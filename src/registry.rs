//! Verify discovered MCP servers against the official MCP Registry
//! (registry.modelcontextprotocol.io). The registry is name/namespace-indexed with a
//! reverse-DNS trust model (e.g. `io.github.<user>/...`) and lists the package
//! identifiers each server ships as. We use it to add a *provenance* layer on top of
//! the threat catalog: is this exact package a registered server, is it deprecated,
//! or is it a near-miss of a registered name (possible typosquat)?
//!
//! Network access is opt-in (`--verify-registry`) and best-effort: a lookup failure
//! never fails the scan. The classifier ([`classify`]) is pure and unit-tested; only
//! [`fetch_candidates`] touches the network.

use crate::models::McpServerDetail;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const REGISTRY_BASE: &str = "https://registry.modelcontextprotocol.io/v0/servers";
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

/// The subset of a registry entry we use.
#[derive(Debug, Clone)]
pub struct RegistryEntry {
    /// Reverse-DNS namespace name, e.g. `io.github.bytedance/mcp-server-filesystem`.
    pub name: String,
    /// (registryType, identifier) for each shipped package, e.g. ("npm", "@a/b").
    pub packages: Vec<(String, String)>,
    /// "active" | "deprecated" | ...
    pub status: String,
}

/// The result of checking one discovered server against the registry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum RegistryVerdict {
    /// Exact package match — registered, with the verified publisher namespace.
    Registered { publisher: String, deprecated: bool },
    /// Package name is within edit-distance 1 of a registered package (possible typo).
    PossibleTyposquat { registered_as: String },
    /// No matching package found (unverified — informational, not inherently bad).
    Unregistered,
    /// The server has no package identity to check (e.g. a bare remote URL).
    NoPackageIdentity,
    /// The registry lookup failed (network/parse) — verdict unknown.
    LookupFailed,
}

/// A per-server verification record stored on the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryCheck {
    pub server_name: String,
    /// e.g. "npm:@modelcontextprotocol/server-filesystem", or "-" if no identity.
    pub package: String,
    pub verdict: RegistryVerdict,
}

/// Verify every package-identified MCP server in the configs against the registry.
/// Returns one [`RegistryCheck`] per server. Network is used here; on failure the
/// verdict is [`RegistryVerdict::LookupFailed`], never a panic.
pub fn verify_servers(configs: &[crate::models::McpConfig]) -> Vec<RegistryCheck> {
    let mut checks = Vec::new();
    for config in configs {
        for server in &config.servers {
            let package = match (&server.package_ecosystem, &server.package_name) {
                (Some(e), Some(n)) => format!("{}:{}", e, n),
                _ => "-".to_string(),
            };
            let verdict = match &server.package_name {
                None => RegistryVerdict::NoPackageIdentity,
                Some(name) => match fetch_candidates(name) {
                    Ok(candidates) => classify(server, &candidates),
                    Err(_) => RegistryVerdict::LookupFailed,
                },
            };
            checks.push(RegistryCheck {
                server_name: server.name.clone(),
                package,
                verdict,
            });
        }
    }
    checks
}

/// Query the registry for candidate entries matching a package-name token.
pub fn fetch_candidates(package_name: &str) -> Result<Vec<RegistryEntry>, String> {
    // Search by the last path segment (drop the npm scope) for a broader match.
    let token = package_name.rsplit('/').next().unwrap_or(package_name);
    let url = format!("{}?search={}&limit=50", REGISTRY_BASE, percent_encode(token));

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(LOOKUP_TIMEOUT))
        .build()
        .into();
    let mut resp = agent.get(&url).call().map_err(|e| e.to_string())?;
    let body = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| e.to_string())?;
    parse_entries(&body)
}

/// Parse the registry `/v0/servers` response into entries.
pub fn parse_entries(body: &str) -> Result<Vec<RegistryEntry>, String> {
    let doc: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("registry parse: {}", e))?;
    let servers = doc
        .get("servers")
        .and_then(|v| v.as_array())
        .ok_or("registry response missing 'servers'")?;

    let mut out = Vec::new();
    for item in servers {
        let Some(s) = item.get("server") else {
            continue;
        };
        let name = s
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let packages = s
            .get("packages")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|p| {
                        let rt = p.get("registryType").and_then(|v| v.as_str())?;
                        let id = p.get("identifier").and_then(|v| v.as_str())?;
                        Some((rt.to_string(), id.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let status = item
            .get("_meta")
            .and_then(|m| m.get("io.modelcontextprotocol.registry/official"))
            .and_then(|o| o.get("status"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        out.push(RegistryEntry {
            name,
            packages,
            status,
        });
    }
    Ok(out)
}

/// Classify a discovered server against registry candidates. Pure and testable.
pub fn classify(server: &McpServerDetail, candidates: &[RegistryEntry]) -> RegistryVerdict {
    let (Some(eco), Some(pkg)) = (
        server.package_ecosystem.as_deref(),
        server.package_name.as_deref(),
    ) else {
        return RegistryVerdict::NoPackageIdentity;
    };

    // Exact (ecosystem, identifier) match → registered, with verified provenance.
    for entry in candidates {
        for (rtype, ident) in &entry.packages {
            if rtype.eq_ignore_ascii_case(eco) && ident.eq_ignore_ascii_case(pkg) {
                return RegistryVerdict::Registered {
                    publisher: publisher_from_name(&entry.name),
                    deprecated: entry.status.eq_ignore_ascii_case("deprecated"),
                };
            }
        }
    }

    // A registered package that is exactly one edit away is a likely typo of the
    // real thing (conservative — different legit servers differ by many chars).
    for entry in candidates {
        for (rtype, ident) in &entry.packages {
            if rtype.eq_ignore_ascii_case(eco) && edit_distance_le1(ident, pkg) {
                return RegistryVerdict::PossibleTyposquat {
                    registered_as: format!("{}:{}", rtype, ident),
                };
            }
        }
    }

    RegistryVerdict::Unregistered
}

/// Turn a reverse-DNS registry name into a human publisher, e.g.
/// `io.github.bytedance/mcp-server-filesystem` -> `github.com/bytedance`.
fn publisher_from_name(name: &str) -> String {
    let ns = name.split('/').next().unwrap_or(name);
    let parts: Vec<&str> = ns.split('.').collect();
    match parts.as_slice() {
        ["io", "github", user, ..] => format!("github.com/{}", user),
        [tld, domain, ..] => format!("{}.{}", domain, tld),
        _ => ns.to_string(),
    }
}

/// True if `a` and `b` differ by at most one single-character edit (insert, delete,
/// or substitute). Cheap early-out on length difference > 1.
fn edit_distance_le1(a: &str, b: &str) -> bool {
    if a == b {
        return false; // exact is handled separately; "typosquat" means near-but-not-equal
    }
    let (ac, bc): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let (la, lb) = (ac.len(), bc.len());
    if la.abs_diff(lb) > 1 {
        return false;
    }
    if la == lb {
        // exactly one substitution
        return ac.iter().zip(&bc).filter(|(x, y)| x != y).count() == 1;
    }
    // lengths differ by 1: one insertion/deletion. Walk the shorter against the longer.
    let (short, long) = if la < lb { (&ac, &bc) } else { (&bc, &ac) };
    let (mut i, mut j, mut skipped) = (0, 0, false);
    while i < short.len() && j < long.len() {
        if short[i] == long[j] {
            i += 1;
            j += 1;
        } else if skipped {
            return false;
        } else {
            skipped = true;
            j += 1; // skip one char in the longer string
        }
    }
    true
}

/// Percent-encode a query-parameter value (encode anything not unreserved).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(eco: &str, name: &str) -> McpServerDetail {
        McpServerDetail {
            name: "s".into(),
            transport: "stdio".into(),
            command: Some("npx".into()),
            args: vec![],
            package_ecosystem: Some(eco.into()),
            package_name: Some(name.into()),
            package_version: None,
            url: None,
        }
    }

    fn entry(name: &str, pkg: &str, status: &str) -> RegistryEntry {
        RegistryEntry {
            name: name.into(),
            packages: vec![("npm".into(), pkg.into())],
            status: status.into(),
        }
    }

    #[test]
    fn classify_exact_match_is_registered_with_publisher() {
        let cands = vec![entry("io.github.bytedance/mcp-server-filesystem", "@agent-infra/fs", "active")];
        let v = classify(&server("npm", "@agent-infra/fs"), &cands);
        assert_eq!(
            v,
            RegistryVerdict::Registered { publisher: "github.com/bytedance".into(), deprecated: false }
        );
    }

    #[test]
    fn classify_deprecated_entry() {
        let cands = vec![entry("com.example/thing", "example-mcp", "deprecated")];
        let v = classify(&server("npm", "example-mcp"), &cands);
        assert_eq!(v, RegistryVerdict::Registered { publisher: "example.com".into(), deprecated: true });
    }

    #[test]
    fn classify_one_edit_off_is_possible_typosquat() {
        // Our package is one deletion away from the registered one.
        let cands = vec![entry("io.github.acme/srv", "server-filesystem", "active")];
        let v = classify(&server("npm", "server-fileystem"), &cands);
        assert!(matches!(v, RegistryVerdict::PossibleTyposquat { .. }));
    }

    #[test]
    fn classify_unrelated_names_are_unregistered_not_typosquat() {
        // Different legit servers differ by many chars — must NOT be flagged typosquat.
        let cands = vec![entry("io.github.a/x", "@modelcontextprotocol/server-filesystem", "active")];
        let v = classify(&server("npm", "@agent-infra/mcp-server-filesystem"), &cands);
        assert_eq!(v, RegistryVerdict::Unregistered);
    }

    #[test]
    fn classify_no_candidates_is_unregistered() {
        assert_eq!(classify(&server("npm", "whatever"), &[]), RegistryVerdict::Unregistered);
    }

    #[test]
    fn classify_no_package_identity() {
        let mut s = server("npm", "x");
        s.package_ecosystem = None;
        s.package_name = None;
        assert_eq!(classify(&s, &[]), RegistryVerdict::NoPackageIdentity);
    }

    #[test]
    fn parse_entries_extracts_real_shape() {
        let body = r#"{"servers":[
            {"server":{"name":"io.github.acme/fs","version":"1.0.0","packages":[{"registryType":"npm","identifier":"@acme/fs"}]},
             "_meta":{"io.modelcontextprotocol.registry/official":{"status":"active","isLatest":true}}},
            {"server":{"name":"com.remote/svc","version":"2.0.0","remotes":[{"type":"streamable-http","url":"https://x"}]},
             "_meta":{"io.modelcontextprotocol.registry/official":{"status":"deprecated"}}}
        ],"metadata":{"count":2}}"#;
        let entries = parse_entries(body).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "io.github.acme/fs");
        assert_eq!(entries[0].packages, vec![("npm".to_string(), "@acme/fs".to_string())]);
        assert_eq!(entries[0].status, "active");
        assert_eq!(entries[1].status, "deprecated");
        assert!(entries[1].packages.is_empty()); // remote-only server
    }

    #[test]
    fn parse_entries_rejects_garbage() {
        assert!(parse_entries("not json").is_err());
        assert!(parse_entries("{}").is_err()); // missing 'servers'
    }

    #[test]
    fn edit_distance_le1_cases() {
        assert!(edit_distance_le1("filesystem", "fileystem")); // deletion
        assert!(edit_distance_le1("abc", "abx")); // substitution
        assert!(edit_distance_le1("abc", "abcd")); // insertion
        assert!(!edit_distance_le1("abc", "abc")); // exact is not a typosquat
        assert!(!edit_distance_le1("abc", "xyz")); // too different
        assert!(!edit_distance_le1("server", "servxr-fs")); // length diff > 1
    }

    #[test]
    fn publisher_from_name_maps_namespaces() {
        assert_eq!(publisher_from_name("io.github.bytedance/mcp-server-filesystem"), "github.com/bytedance");
        assert_eq!(publisher_from_name("com.notion/mcp"), "notion.com");
    }
}
