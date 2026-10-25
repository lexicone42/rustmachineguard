//! The 2026-10-25 threat-catalog refresh: the `@modelcontextprotocol/server-filesystem` and
//! `server-everything` version-scheme reset, the new vulnerable-range and malicious rows,
//! the id corrections, and the optional `advisory_severity` field.
//!
//! On 8e58777 (catalog 2026-10-22) the scheme-reset tests fail (2.0.1, the fixed
//! server-filesystem, matched `<2025.7.1` as Critical; 2.0.0 matched the wrong row), every
//! new-row case fails (no row), and the correction and severity tests fail (no ids, no
//! field). The structural tests (JSON shape, unique rows) pass there too and guard later
//! edits.

use rustmachineguard::catalogs::BUILTIN_CATALOG;
use rustmachineguard::models::{ExposureFinding, McpServerDetail};
use rustmachineguard::scanners::exposure::{ExposureCatalog, pep503_normalize};
use serde_json::Value;
use std::collections::HashMap;

fn catalog() -> ExposureCatalog {
    ExposureCatalog::load_from_str(BUILTIN_CATALOG).expect("built-in catalog loads")
}

fn raw_rows() -> Vec<Value> {
    serde_json::from_str(BUILTIN_CATALOG).expect("built-in catalog is a JSON array")
}

fn server(eco: &str, name: &str, version: &str) -> McpServerDetail {
    McpServerDetail {
        name: "s".into(),
        transport: "stdio".into(),
        command: Some(if eco == "pypi" { "uvx" } else { "npx" }.into()),
        package_ecosystem: Some(eco.into()),
        package_name: Some(name.into()),
        package_version: Some(version.into()),
        ..Default::default()
    }
}

fn matches(cat: &ExposureCatalog, eco: &str, name: &str, version: &str) -> Vec<ExposureFinding> {
    cat.check_mcp_server(&server(eco, name, version), "/t/.mcp.json")
}

/// The `version_range` of every row that matched (None for a malware row).
fn ranges(found: &[ExposureFinding]) -> Vec<Option<String>> {
    found.iter().map(|f| f.matched_range.clone()).collect()
}

// ─── Structure ──────────────────────────────────────────────────────────────

const KEYS: &[&str] = &[
    "ecosystem",
    "name",
    "version",
    "version_range",
    "advisory",
    "advisory_severity",
];
const SEVERITIES: &[&str] = &["critical", "high", "medium", "low"];

#[test]
fn every_row_has_the_documented_shape() {
    for (i, r) in raw_rows().iter().enumerate() {
        let obj = r.as_object().unwrap_or_else(|| panic!("row {i} is not an object"));
        for k in obj.keys() {
            assert!(
                KEYS.contains(&k.as_str()),
                "row {i} ({}) has unknown key {k}",
                r["name"]
            );
        }
        for k in ["ecosystem", "name", "advisory"] {
            assert!(
                obj.get(k).and_then(Value::as_str).is_some_and(|s| !s.trim().is_empty()),
                "row {i} needs a non-empty {k}: {r}"
            );
        }
        assert!(
            !(obj.contains_key("version") && obj.contains_key("version_range")),
            "row {i} ({}) has both version and version_range; version wins and the range is dead",
            r["name"]
        );
        if let Some(rng) = obj.get("version_range") {
            let rng = rng.as_str().expect("version_range is a string");
            assert!(
                semver::VersionReq::parse(rng.trim()).is_ok() && !rng.contains("||"),
                "row {i} ({}) range {rng:?} must parse as a semver::VersionReq without ||",
                r["name"]
            );
        }
    }
}

/// No two rows describe the same thing: (ecosystem, name as the matcher compares it,
/// version, version_range) is unique. A duplicate would report the same install twice.
#[test]
fn rows_are_unique() {
    let mut seen: HashMap<(String, String, String, String), usize> = HashMap::new();
    for (i, r) in raw_rows().iter().enumerate() {
        let eco = r["ecosystem"].as_str().unwrap().to_ascii_lowercase();
        let name = r["name"].as_str().unwrap();
        let name = if eco == "pypi" {
            pep503_normalize(name)
        } else {
            name.to_ascii_lowercase()
        };
        let key = (
            eco,
            name,
            r["version"].as_str().unwrap_or("").to_string(),
            r["version_range"].as_str().unwrap_or("").to_string(),
        );
        if let Some(prev) = seen.insert(key.clone(), i) {
            panic!("rows {prev} and {i} are the same entry: {key:?}");
        }
    }
}

/// Every GHSA, CVE and OSV MAL id cited is well formed, so `advisory_ids` (the finding's
/// evidence) picks each one up whole.
#[test]
fn cited_ids_are_well_formed() {
    // The id after each `prefix`, as the run of characters in `allowed`, trailing dashes trimmed.
    fn ids<'a>(text: &'a str, prefix: &str, allowed: fn(char) -> bool) -> Vec<&'a str> {
        text.match_indices(prefix)
            .map(|(at, _)| {
                let rest = &text[at + prefix.len()..];
                let end = rest.find(|c: char| !allowed(c)).unwrap_or(rest.len());
                rest[..end].trim_end_matches('-')
            })
            .collect()
    }
    let ghsa_part = |p: &str| p.len() == 4 && p.chars().all(|c| c.is_ascii_digit() || c.is_ascii_lowercase());
    for r in raw_rows() {
        let adv = r["advisory"].as_str().unwrap();
        for id in ids(adv, "GHSA-", |c| c.is_ascii_alphanumeric() || c == '-') {
            let parts: Vec<&str> = id.split('-').collect();
            assert!(
                parts.len() == 3 && parts.iter().all(|p| ghsa_part(p)),
                "{}: malformed GHSA id GHSA-{id}",
                r["name"]
            );
        }
        for id in ids(adv, "CVE-", |c| c.is_ascii_alphanumeric() || c == '-') {
            let ok = id.split_once('-').is_some_and(|(y, n)| {
                y.len() == 4 && n.len() >= 4 && y.chars().chain(n.chars()).all(|c| c.is_ascii_digit())
            });
            assert!(ok, "{}: malformed CVE id CVE-{id}", r["name"]);
        }
        for id in ids(adv, "MAL-", |c| c.is_ascii_digit() || c == '-') {
            let ok = id
                .split_once('-')
                .is_some_and(|(y, n)| y.len() == 4 && !n.is_empty() && !n.contains('-'));
            assert!(ok, "{}: malformed OSV id MAL-{id}", r["name"]);
        }
    }
}

/// `advisory_severity` is optional; when present it is one of four lowercase words and
/// sits on a vulnerable-range row (a malware row is Critical by kind). A vulnerable-range
/// match is graded at it (tests/advisory_severity.rs), so a typo here would silently fall
/// back to Critical.
#[test]
fn advisory_severity_values_are_valid() {
    let mut with = 0;
    for r in raw_rows() {
        let Some(sev) = r.get("advisory_severity") else {
            continue;
        };
        with += 1;
        let sev = sev
            .as_str()
            .unwrap_or_else(|| panic!("{}: advisory_severity must be a string", r["name"]));
        assert!(SEVERITIES.contains(&sev), "{}: advisory_severity {sev:?}", r["name"]);
        assert!(
            r.get("version_range").is_some(),
            "{}: advisory_severity belongs on vulnerable-range rows",
            r["name"]
        );
    }
    assert!(
        with >= 22,
        "the 2026-10-25 vulnerable-range rows all carry advisory_severity ({with})"
    );
}

// ─── C1: the version-scheme reset ──────────────────────────────────────────

/// `@modelcontextprotocol/server-filesystem` went 0.x -> date versions (2025.1.14 to
/// 2026.8.31) -> semver again (1.0.0 on 2026-10-11, 2.0.0, 2.0.1 = the fix). Every semver
/// release sorts below the date versions, so the old `<2025.7.1` row flagged the fixed
/// 2.0.1 as Critical. Each line now has its own row.
#[test]
fn server_filesystem_version_scheme_reset() {
    let cat = catalog();
    let sf = "@modelcontextprotocol/server-filesystem";
    assert!(
        matches(&cat, "npm", sf, "2.0.1").is_empty(),
        "the fixed 2.0.1 must match no row"
    );
    assert!(matches(&cat, "npm", sf, "2.0.2").is_empty());
    let cases = [
        ("0.6.2", "<1.0.0"),
        ("0.9.0", "<1.0.0"),
        ("2025.1.14", ">=2025.1.14, <=2026.8.31"),
        ("2025.6.1", ">=2025.1.14, <=2026.8.31"),
        ("2025.7.1", ">=2025.1.14, <=2026.8.31"),
        ("2026.8.31", ">=2025.1.14, <=2026.8.31"),
        ("1.0.0", ">=1.0.0, <2.0.1"),
        ("2.0.0", ">=1.0.0, <2.0.1"),
    ];
    for (ver, want) in cases {
        let found = matches(&cat, "npm", sf, ver);
        assert_eq!(ranges(&found), vec![Some(want.to_string())], "{sf} {ver}");
    }
    // The advisories the semver row cites, so the finding's evidence lists them.
    let adv = &matches(&cat, "npm", sf, "2.0.0")[0].advisory;
    for id in [
        "GHSA-53mr-w429-c597",
        "GHSA-7rgq-gccq-qphx",
        "GHSA-4gxg-m5jx-9j57",
        "GHSA-hhwq-wxfx-cj7g",
    ] {
        assert!(adv.contains(id), "{id} missing from {adv}");
    }
}

/// server-everything restarted the same way; its advisory starts at 2025.9.24.
#[test]
fn server_everything_version_scheme_reset() {
    let cat = catalog();
    let se = "@modelcontextprotocol/server-everything";
    for clean in ["2.0.1", "2025.9.23", "0.6.2"] {
        assert!(matches(&cat, "npm", se, clean).is_empty(), "{se} {clean}");
    }
    for (ver, want) in [
        ("2025.9.24", ">=2025.9.24, <=2026.8.31"),
        ("2026.8.31", ">=2025.9.24, <=2026.8.31"),
        ("1.0.0", ">=1.0.0, <2.0.1"),
        ("2.0.0", ">=1.0.0, <2.0.1"),
    ] {
        assert_eq!(
            ranges(&matches(&cat, "npm", se, ver)),
            vec![Some(want.to_string())],
            "{se} {ver}"
        );
    }
}

// ─── C2 + C4: vulnerable-range rows ─────────────────────────────────────────

/// (ecosystem, package, a vulnerable version, the first fixed version, an id the row
/// must cite). The vulnerable version must match exactly one row of this package and the
/// fixed one none.
const VULNERABLE: &[(&str, &str, &str, &str, &str)] = &[
    ("pypi", "claude-agent-sdk", "0.2.120", "0.2.121", "CVE-2026-96620"),
    (
        "pypi",
        "mcp-server-fetch",
        "2026.10.10",
        "2026.10.24",
        "GHSA-v38p-wf49-hx2j",
    ),
    (
        "pypi",
        "mcp-server-fetch",
        "2026.10.19",
        "2026.10.24",
        "GHSA-66qx-2266-pmj6",
    ),
    (
        "npm",
        "@modelcontextprotocol/server-legacy",
        "2.3.0",
        "2.3.1",
        "CVE-2026-111771",
    ),
    (
        "npm",
        "@modelcontextprotocol/server-legacy",
        "2.0.0-alpha.2",
        "2.4.0",
        "GHSA-rvq5-wwqv-78pq",
    ),
    (
        "npm",
        "@modelcontextprotocol/hono",
        "2.0.0",
        "2.0.1",
        "GHSA-f897-62hf-6gxq",
    ),
    ("pypi", "fastmcp-slim", "3.4.9", "3.4.10", "GHSA-7xgj-8392-5q4r"),
    ("pypi", "fastmcp_slim", "3.3.0b1", "3.4.10", "GHSA-7xgj-8392-5q4r"),
    ("pypi", "fastmcp-slim", "4.1.1", "4.1.2", "GHSA-vqqp-x5qm-5qp4"),
    ("pypi", "fastmcp-slim", "4.0.0a1", "4.1.2", "GHSA-vqqp-x5qm-5qp4"),
    ("npm", "obsidian-tc", "1.31.3", "1.31.4", "CVE-2026-77363"),
    ("npm", "obsidian-tc", "0.0.1", "1.33.1", "CVE-2026-115478"),
    ("npm", "@zenalexa/unicli", "0.225.1", "0.225.2", "CVE-2026-58497"),
    ("pypi", "pydantic-ai", "1.34.0", "1.107.5", "CVE-2026-107295"),
    ("pypi", "pydantic-ai", "1.107.4", "1.107.5", "CVE-2026-107292"),
    ("pypi", "pydantic-ai", "2.0.0b1", "2.30.0", "GHSA-h4xc-3qfq-jf93"),
    ("pypi", "pydantic-ai", "2.29.0", "2.30.0", "GHSA-q2xc-rrxj-58x9"),
    ("pypi", "pydantic-ai-slim", "1.100.0", "1.107.5", "CVE-2026-107295"),
    ("pypi", "pydantic_ai_slim", "2.28.0", "2.30.0", "CVE-2026-107292"),
    ("pypi", "graphifyy", "0.9.69", "0.9.70", "GHSA-pcc4-rvhr-2pr8"),
    ("pypi", "netlicensing-mcp", "0.1.7", "0.1.8", "CVE-2026-57496"),
    ("pypi", "mcp-contextforge-gateway", "1.0.1", "1.0.2", "CVE-2026-53710"),
    (
        "npm",
        "@modelcontextprotocol/inspector-server",
        "1.0.2",
        "1.0.3",
        "GHSA-8qgq-27v6-55w3",
    ),
    (
        "npm",
        "@modelcontextprotocol/inspector-client",
        "0.13.0",
        "1.0.3",
        "GHSA-4fc4-wcmh-4g86",
    ),
    // C4: id corrections on existing rows.
    ("pypi", "mcp", "1.29.0", "1.30.0", "CVE-2026-115563"),
    ("pypi", "mcp", "2.1.0", "2.2.0", "CVE-2026-115563"),
    (
        "npm",
        "@modelcontextprotocol/inspector",
        "1.0.2",
        "1.0.3",
        "GHSA-8qgq-27v6-55w3",
    ),
];

#[test]
fn new_vulnerable_rows_match_their_vulnerable_version_and_not_their_fix() {
    let cat = catalog();
    for &(eco, name, bad, fixed, id) in VULNERABLE {
        let found = matches(&cat, eco, name, bad);
        assert_eq!(
            found.len(),
            1,
            "{eco} {name} {bad} must match exactly one row: {found:?}"
        );
        assert!(
            found[0].matched_range.is_some(),
            "{name} {bad} is a vulnerable-range row"
        );
        assert!(found[0].advisory.contains(id), "{name} {bad}: {id} not cited");
        assert!(
            matches(&cat, eco, name, fixed).is_empty(),
            "{eco} {name} {fixed} is fixed and must not match"
        );
    }
}

/// Below each row's lower bound nothing matches: the advisories name where the flaw
/// starts, and earlier installs are not flagged for it.
#[test]
fn lower_bounds_hold() {
    let cat = catalog();
    for (eco, name, ver) in [
        ("pypi", "mcp-server-fetch", "2026.10.9"),
        ("pypi", "mcp-server-fetch", "2025.4.7"),
        ("npm", "@modelcontextprotocol/server-legacy", "1.9.0"),
        ("npm", "@modelcontextprotocol/hono", "1.0.0"),
        ("pypi", "fastmcp-slim", "2.14.0"),
        ("pypi", "pydantic-ai", "1.33.0"),
        ("pypi", "pydantic-ai-slim", "0.9.0"),
        ("pypi", "graphifyy", "0.7.1"),
        ("npm", "@modelcontextprotocol/inspector-server", "0.14.0"),
        ("npm", "@modelcontextprotocol/inspector-client", "0.12.0"),
    ] {
        assert!(matches(&cat, eco, name, ver).is_empty(), "{eco} {name} {ver}");
    }
}

/// The advisory names `@trigger.dev/cli-v3`, which npm does not have; the mapping to
/// `trigger.dev` is an inference and the catalog has no field to say so, so no row.
#[test]
fn trigger_dev_is_not_catalogued_on_an_inferred_package_name() {
    let cat = catalog();
    assert!(matches(&cat, "npm", "trigger.dev", "4.5.3").is_empty());
}

// ─── C3: malicious rows ────────────────────────────────────────────────────

/// (ecosystem, package, a flagged version, a clean version or "" when every version is
/// bad, an id the row must cite). A match is a malware row (no matched range).
const MALICIOUS: &[(&str, &str, &str, &str, &str)] = &[
    ("npm", "@beloved-lenora/opencode-btw", "1.0.0", "", "MAL-2026-17903"),
    (
        "npm",
        "@beloved-lenora/opencode-goal",
        "1.0.0",
        "",
        "GHSA-c78h-wwhq-g6j8",
    ),
    (
        "npm",
        "@beloved-lenora/opencode-orchestrator",
        "1.0.0",
        "",
        "MAL-2026-17905",
    ),
    (
        "npm",
        "@beloved-lenora/opencode-shared-rpc",
        "1.0.0",
        "",
        "MAL-2026-17906",
    ),
    (
        "npm",
        "@beloved-lenora/opencode-shell-guard",
        "1.0.0",
        "",
        "MAL-2026-17907",
    ),
    (
        "npm",
        "@beloved-lenora/opencode-stats",
        "0.0.1-security",
        "",
        "MAL-2026-17908",
    ),
    (
        "npm",
        "@beloved-lenora/opencode-todo",
        "1.0.0",
        "",
        "GHSA-9rjq-6mhc-46c5",
    ),
    ("npm", "formatting-subtitles", "1.0.2", "", "MAL-2026-18184"),
    ("npm", "formatting-subtitles", "1.0.1", "", "GHSA-2cph-9873-fh57"),
    ("npm", "unicode-title-normalizer", "1.1.0", "", "MAL-2026-18100"),
    ("pypi", "py-worm", "2.0.1", "", "GHSA-483q-j87r-c97c"),
    ("pypi", "py_worm", "0.1.0", "", "MAL-2026-17883"),
    ("npm", "x402-prompt-injection-scan", "0.1.4", "0.1.3", "MAL-2026-18197"),
    ("npm", "skillward", "0.1.2", "", "GHSA-9wgc-5pgr-25p3"),
    ("npm", "@tekmidian/pai", "1.0.8", "1.0.7", "GHSA-xvgg-qjjh-gq34"),
    ("npm", "@tekmidian/pai", "1.0.10", "1.0.11", "MAL-2026-18205"),
    (
        "npm",
        "agentic-awesome-skills",
        "18.9.0",
        "18.8.0",
        "GHSA-rgwm-3jj9-h563",
    ),
    ("npm", "agentic-awesome-skills", "18.14.0", "18.15.0", "MAL-2026-18192"),
    (
        "npm",
        "agentic-awesome-skills",
        "19.7.0",
        "19.8.0",
        "GHSA-rgwm-3jj9-h563",
    ),
    (
        "npm",
        "agentic-awesome-skills",
        "19.10.1",
        "19.11.0",
        "GHSA-rgwm-3jj9-h563",
    ),
    (
        "npm",
        "agentic-awesome-skills",
        "19.13.0",
        "19.14.0",
        "GHSA-rgwm-3jj9-h563",
    ),
    (
        "npm",
        "opencode-skills-collection",
        "4.0.56",
        "4.0.55",
        "GHSA-9855-prwc-mfp2",
    ),
    ("npm", "opencode-skills-collection", "4.1.1", "4.1.2", "MAL-2026-18193"),
    (
        "npm",
        "opencode-skills-collection",
        "4.1.4",
        "4.1.5",
        "GHSA-9855-prwc-mfp2",
    ),
    (
        "npm",
        "opencode-skills-collection",
        "4.1.7",
        "4.1.15",
        "GHSA-9855-prwc-mfp2",
    ),
    (
        "npm",
        "opencode-skills-collection",
        "4.1.20",
        "4.1.22",
        "GHSA-9855-prwc-mfp2",
    ),
];

#[test]
fn malicious_rows_match_flagged_releases_only() {
    let cat = catalog();
    for &(eco, name, bad, clean, id) in MALICIOUS {
        let found = matches(&cat, eco, name, bad);
        assert_eq!(found.len(), 1, "{eco} {name} {bad}: {found:?}");
        assert_eq!(
            found[0].matched_range, None,
            "{name} {bad} must grade as a malicious release"
        );
        assert!(found[0].advisory.contains(id), "{name}: {id} not cited");
        assert!(!found[0].advisory.contains("CVE-"), "{name}: malware rows cite no CVE");
        if !clean.is_empty() {
            assert!(matches(&cat, eco, name, clean).is_empty(), "{name} {clean} is clean");
        }
    }
}

/// The two skills aggregators had clean releases interleaved with flagged ones: every
/// release GitHub's malware advisory lists is caught, no other release is, and each is
/// its own exact-version row (a range row would grade as "Vulnerable", not "Known-bad").
#[test]
fn skills_aggregators_flag_exactly_the_advisory_versions() {
    let cat = catalog();
    let aas_bad = [
        "18.9.0", "18.10.0", "18.11.0", "18.12.0", "18.13.0", "18.14.0", "19.0.0", "19.0.1", "19.1.0", "19.2.0",
        "19.3.0", "19.4.0", "19.5.0", "19.6.0", "19.7.0", "19.9.0", "19.10.1", "19.12.0", "19.12.1", "19.13.0",
    ];
    let aas_clean = ["18.8.0", "18.15.0", "19.8.0", "19.11.0", "19.14.0", "19.15.0"];
    let osc_bad = [
        "4.0.56", "4.0.57", "4.0.77", "4.1.0", "4.1.1", "4.1.3", "4.1.4", "4.1.6", "4.1.7", "4.1.8", "4.1.9", "4.1.10",
        "4.1.11", "4.1.12", "4.1.13", "4.1.14", "4.1.16", "4.1.17", "4.1.18", "4.1.19", "4.1.20",
    ];
    let osc_clean = ["4.0.55", "4.0.58", "4.0.76", "4.1.2", "4.1.5", "4.1.15", "4.1.22"];
    for (name, bad, clean) in [
        ("agentic-awesome-skills", &aas_bad[..], &aas_clean[..]),
        ("opencode-skills-collection", &osc_bad[..], &osc_clean[..]),
    ] {
        for v in bad {
            assert_eq!(ranges(&matches(&cat, "npm", name, v)), vec![None], "{name} {v}");
        }
        for v in clean {
            assert!(matches(&cat, "npm", name, v).is_empty(), "{name} {v}");
        }
        let rows = raw_rows().into_iter().filter(|r| r["name"] == name).count();
        assert_eq!(rows, bad.len(), "{name}: one exact row per flagged release");
    }
}

// ─── C4: id-only corrections on malware rows ─────────────────────────────────

#[test]
fn malware_rows_gain_their_ghsa_ids() {
    let cat = catalog();
    for (eco, name, ver, id) in [
        ("npm", "claude-desktop-setup", "1.0.0", "GHSA-f4mf-vhm8-xxqc"),
        ("npm", "codex-setup", "1.0.0", "GHSA-h8cg-xwfv-9x77"),
        ("npm", "chatgpt-pro-activator", "1.0.0", "GHSA-qp43-mgx6-56x2"),
        ("npm", "formatting-subtitles-for-claude", "1.0.0", "GHSA-xxr7-33gg-pcg6"),
        ("pypi", "litellm", "1.82.7", "GHSA-92x9-889m-jgmw"),
        ("pypi", "litellm", "1.82.8", "GHSA-92x9-889m-jgmw"),
        ("pypi", "litellm", "1.107.0", "GHSA-92x9-889m-jgmw"),
    ] {
        let found = matches(&cat, eco, name, ver);
        assert_eq!(found.len(), 1, "{name} {ver}");
        assert!(found[0].advisory.contains(id), "{name} {ver}: {id}");
    }
}

/// The rows that said a sibling package "shares the bound" or "the same ranges apply"
/// now point at the sibling's own rows, and those rows exist.
#[test]
fn sibling_package_claims_are_backed_by_rows() {
    let rows = raw_rows();
    let text = |name: &str| -> String {
        rows.iter()
            .filter(|r| r["name"] == name)
            .map(|r| r["advisory"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert!(!text("fastmcp").contains("shares the bound"));
    assert!(!text("@modelcontextprotocol/inspector").contains("Same ranges apply"));
    for sibling in [
        "fastmcp-slim",
        "@modelcontextprotocol/inspector-server",
        "@modelcontextprotocol/inspector-client",
        "@modelcontextprotocol/server-legacy",
    ] {
        assert!(rows.iter().any(|r| r["name"] == sibling), "{sibling} has no row");
    }
}

// ─── End to end: installed packages on a fixture machine ─────────────────────

#[cfg(unix)]
mod e2e {
    use serde_json::Value;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    const OTHER_SCANNERS: &str = "ai,aicreds,browser,cloud,containers,envfiles,extensions,frameworks,gitconfig,ide,\
        jbplugins,listeners,liveness,lsp,marketplaces,mcp,node,notebooks,packages,persistence,playwright,rules,\
        settings,shell,skills,ssh,statusline,transcripts,vibe,vscodetasks";

    fn write(path: &Path, text: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    fn npm_global(home: &Path, name: &str, version: &str) {
        write(
            &home
                .join(".npm-global/lib64/node_modules")
                .join(name)
                .join("package.json"),
            &format!(r#"{{"name":"{name}","version":"{version}"}}"#),
        );
    }

    fn uv_tool_dist(home: &Path, tool: &str, name: &str, version: &str) {
        let venv = home.join(".local/share/uv/tools").join(tool);
        let sp = venv.join("lib/python3.13/site-packages");
        write(&venv.join("pyvenv.cfg"), "home = /usr/bin\n");
        write(
            &sp.join(format!("{}-{version}.dist-info", name.replace('-', "_")))
                .join("METADATA"),
            &format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n"),
        );
    }

    /// A temp HOME holding: the fixed server-filesystem 2.0.1 (the 8e58777 false
    /// positive), a vulnerable server-everything 2.0.0, a flagged opencode-skills-collection
    /// release, and a uv tool with vulnerable claude-agent-sdk and pydantic-ai-slim. Run
    /// the real binary with only the package scanners and compare the exposure rows.
    #[test]
    fn installed_packages_are_graded_by_the_refreshed_catalog() {
        let home: PathBuf = std::env::temp_dir().join(format!("rmg-cat1025-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&home).unwrap();
        let home = fs::canonicalize(&home).unwrap();
        npm_global(&home, "@modelcontextprotocol/server-filesystem", "2.0.1");
        npm_global(&home, "@modelcontextprotocol/server-everything", "2.0.0");
        npm_global(&home, "opencode-skills-collection", "4.1.7");
        uv_tool_dist(&home, "agent-app", "claude-agent-sdk", "0.2.120");
        uv_tool_dist(&home, "agent-app", "pydantic-ai-slim", "1.107.4");

        let out = Command::new(env!("CARGO_BIN_EXE_rmguard"))
            .args(["--format", "json", "--skip", OTHER_SCANNERS])
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .env("NO_COLOR", "1")
            .env_remove("UV_TOOL_DIR")
            .env_remove("UV_PYTHON_INSTALL_DIR")
            .env_remove("XDG_DATA_HOME")
            .env_remove("PIPX_HOME")
            .current_dir(&home)
            .output()
            .expect("run rmguard");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let v: Value = serde_json::from_slice(&out.stdout).expect("report json");
        let none = Vec::new();
        let mut got: Vec<(String, String, String)> = v["exposure_findings"]
            .as_array()
            .unwrap_or(&none)
            .iter()
            .filter(|f| {
                f["found_in"]
                    .as_str()
                    .is_some_and(|p| p.starts_with(&*home.to_string_lossy()))
            })
            .map(|f| {
                (
                    f["name"].as_str().unwrap_or("").to_string(),
                    f["version"].as_str().unwrap_or("").to_string(),
                    f["matched_range"].as_str().unwrap_or("(malicious)").to_string(),
                )
            })
            .collect();
        got.sort();
        let want = vec![
            (
                "@modelcontextprotocol/server-everything".to_string(),
                "2.0.0".to_string(),
                ">=1.0.0, <2.0.1".to_string(),
            ),
            ("claude-agent-sdk".into(), "0.2.120".into(), "<0.2.121".into()),
            (
                "opencode-skills-collection".into(),
                "4.1.7".into(),
                "(malicious)".into(),
            ),
            ("pydantic-ai-slim".into(), "1.107.4".into(), ">=1.34.0, <1.107.5".into()),
        ];
        assert_eq!(got, want, "{:#}", v["exposure_findings"]);
        let _ = fs::remove_dir_all(&home);
    }
}
