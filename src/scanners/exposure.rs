use crate::models::{ExposureEntry, ExposureFinding, McpServerDetail};

pub struct ExposureCatalog {
    entries: Vec<ExposureEntry>,
}

impl ExposureCatalog {
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("failed to read catalog {}: {}", path.display(), e))?;
        let entries: Vec<ExposureEntry> =
            serde_json::from_str(&content).map_err(|e| format!("failed to parse catalog {}: {}", path.display(), e))?;
        Ok(Self { entries })
    }

    pub fn load_from_str(content: &str) -> Result<Self, String> {
        let entries: Vec<ExposureEntry> =
            serde_json::from_str(content).map_err(|e| format!("failed to parse catalog: {}", e))?;
        Ok(Self { entries })
    }

    pub fn merge(&mut self, other: Self) {
        self.entries.extend(other.entries);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn check_mcp_server(&self, server: &McpServerDetail, config_path: &str) -> Vec<ExposureFinding> {
        let mut findings = Vec::new();
        // `uvx --with pkg` / `uv run --with pkg` dependencies are PyPI packages the
        // launch installs and imports too.
        for extra in &server.extra_packages {
            let (name, version) = crate::scanners::mcp::split_extra_package(extra);
            if name.is_empty() {
                continue;
            }
            findings.extend(self.check_package("pypi", &name, version.as_deref(), config_path));
        }
        let Some(ref pkg_name) = server.package_name else {
            return findings;
        };
        let Some(ref ecosystem) = server.package_ecosystem else {
            return findings;
        };

        for entry in &self.entries {
            if !eq_case_insensitive(&entry.ecosystem, ecosystem) {
                continue;
            }
            if !names_match(ecosystem, &entry.name, pkg_name) {
                continue;
            }
            if !version_matches(entry, server.package_version.as_deref()) {
                continue;
            }
            findings.push(ExposureFinding {
                ecosystem: ecosystem.clone(),
                name: pkg_name.clone(),
                version: server.package_version.clone().unwrap_or_else(|| "unknown".to_string()),
                advisory: entry.advisory.clone().unwrap_or_default(),
                found_in: config_path.to_string(),
                matched_range: matched_range(entry),
                advisory_severity: matched_severity(entry),
                ..Default::default()
            });
        }

        findings
    }

    /// One package (name, version if known) against every row of `ecosystem`.
    fn check_package(
        &self,
        ecosystem: &str,
        name: &str,
        version: Option<&str>,
        found_in: &str,
    ) -> Vec<ExposureFinding> {
        self.entries
            .iter()
            .filter(|e| eq_case_insensitive(&e.ecosystem, ecosystem))
            .filter(|e| names_match(ecosystem, &e.name, name))
            .filter(|e| version_matches(e, version))
            .map(|entry| ExposureFinding {
                ecosystem: ecosystem.to_string(),
                name: name.to_string(),
                version: version.unwrap_or("unknown").to_string(),
                advisory: entry.advisory.clone().unwrap_or_default(),
                found_in: found_in.to_string(),
                matched_range: matched_range(entry),
                advisory_severity: matched_severity(entry),
                ..Default::default()
            })
            .collect()
    }

    pub fn check_extension(&self, ecosystem: &str, name: &str, version: &str, found_in: &str) -> Vec<ExposureFinding> {
        let mut findings = Vec::new();

        for entry in &self.entries {
            if !eq_case_insensitive(&entry.ecosystem, ecosystem) {
                continue;
            }
            if !names_match(ecosystem, &entry.name, name) {
                continue;
            }
            if !version_matches(entry, Some(version)) {
                continue;
            }
            findings.push(ExposureFinding {
                ecosystem: ecosystem.to_string(),
                name: name.to_string(),
                version: version.to_string(),
                advisory: entry.advisory.clone().unwrap_or_default(),
                found_in: found_in.to_string(),
                matched_range: matched_range(entry),
                advisory_severity: matched_severity(entry),
                ..Default::default()
            });
        }

        findings
    }
}

/// Map a browser's display name to the catalog ecosystem its extensions belong to.
///
/// Chromium-family browsers share the Chrome Web Store extension-ID namespace, so a
/// compromised Chrome extension is the same artifact when installed in Brave or Edge
/// and must match the same catalog row.
pub fn browser_catalog_ecosystem(browser: &str) -> &'static str {
    match browser.trim().to_ascii_lowercase().as_str() {
        "firefox" | "librewolf" | "waterfox" | "zen" => "firefox",
        // Chrome, Chromium, Brave, Edge, Opera, Vivaldi, Arc… all share the namespace.
        _ => "chrome",
    }
}

/// Map a detected AI tool's display name to its key in the `agent-runtime` catalog
/// ecosystem, so an installed agent CLI's own version can be matched against known
/// vulnerable ranges. Agent CLIs are now CVE-bearing packages in their own right.
///
/// Returns `None` for tools we have no stable versioned identity for. Deliberately
/// conservative: a wrong mapping would match one product's CVE ranges against another
/// product's version numbering, which either cries wolf or silently never fires.
/// Every key names exactly one version line:
///
/// - `claude-code` is the CLI (2.x). `claude-desktop` is the desktop app, whose version
///   the scanner reads from the app bundle and reports as "Claude Cowork" (1.x → 3.x,
///   e.g. 1.15962.0, 2.110.0, 3.6556.1). They share a vendor, not a version line, so
///   desktop advisories are keyed to `claude-desktop` and never to the CLI. The bare
///   "Claude Desktop" desktop-app row carries no version and stays unmapped.
/// - `codex` is the Codex CLI (`codex --version` prints `codex-cli X.Y.Z`); Codex
///   Desktop uses 26.5xx.x numbering and is not inventoried.
/// - `kiro-ide` is the Kiro IDE (`kiro` launcher, 0.x/1.x); the Kiro CLI (`kiro-cli`,
///   1.x/2.x) is a different product line and stays unmapped until it has advisories.
/// - `goose` and `ollama` are their CLIs; `ollama` is reached from the frameworks
///   inventory rather than the agents list.
pub fn agent_runtime_key(tool_name: &str) -> Option<&'static str> {
    Some(match tool_name.trim().to_ascii_lowercase().as_str() {
        "claude code" => "claude-code",
        "claude cowork" => "claude-desktop",
        "gemini cli" => "gemini-cli",
        "github copilot cli" | "copilot cli" | "copilot" => "copilot-cli",
        "openai codex cli" | "codex cli" | "codex" => "codex",
        "goose" => "goose",
        "kiro ide" => "kiro-ide",
        "ollama" => "ollama",
        _ => return None,
    })
}

fn eq_case_insensitive(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// The row's `version_range` when it is what matched: a vulnerable-version row, not a
/// malware row (an exact `version`, or no constraint at all, names malicious releases;
/// so does a range row marked `malware`, see [`is_malware_row`]).
fn matched_range(entry: &ExposureEntry) -> Option<String> {
    if entry.version.is_some() || is_malware_row(entry) {
        return None;
    }
    entry.version_range.clone()
}

/// A row that names malicious releases, not a vulnerable version range: an exact
/// `version`, no version constraint at all, `"malware": true`, or (for a user catalog
/// converted from OSV) a range row with no `advisory_severity` whose advisory cites an
/// OpenSSF malicious-packages id (`MAL-YYYY-N`, issued only for malware). Such a match is
/// "Known-bad", Critical by kind, never "Vulnerable ... version".
pub fn is_malware_row(entry: &ExposureEntry) -> bool {
    if entry.malware || entry.version.is_some() || entry.version_range.is_none() {
        return true;
    }
    entry.advisory_severity.is_none() && entry.advisory.as_deref().is_some_and(cites_mal_id)
}

/// The text cites an OpenSSF malicious-packages id: `MAL-` + a 4-digit year + `-` + digits.
fn cites_mal_id(text: &str) -> bool {
    text.match_indices("MAL-").any(|(i, _)| {
        let before_ok = i == 0 || !text.as_bytes()[i - 1].is_ascii_alphanumeric();
        let rest = &text[i + 4..];
        let year = rest.get(..4).is_some_and(|y| y.bytes().all(|b| b.is_ascii_digit()));
        let num = rest.get(4..5) == Some("-") && rest[5..].bytes().next().is_some_and(|b| b.is_ascii_digit());
        before_ok && year && num
    })
}

/// The row's `advisory_severity`, lowercased, when its `version_range` is what matched
/// (see [`matched_range`]); a malware row's is ignored.
fn matched_severity(entry: &ExposureEntry) -> Option<String> {
    matched_range(entry)?;
    entry
        .advisory_severity
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
}

/// The npx cache directory (`<home>/.npm/_npx/<hash>`) holding `found_in`, if any.
pub fn npx_cache_root(found_in: &str) -> Option<std::path::PathBuf> {
    const MARK: &str = "/.npm/_npx/";
    let at = found_in.find(MARK)?;
    let rest = &found_in[at + MARK.len()..];
    let hash = rest
        .split('/')
        .next()
        .filter(|h| !h.is_empty() && *h != "." && *h != "..")?;
    Some(std::path::PathBuf::from(format!("{}{MARK}{hash}", &found_in[..at])))
}

/// Mark a finding inside an npx cache, and name the package(s) the cache was created
/// for from its `package.json` (`_npx.packages`, else `dependencies` keys). Only that
/// one small manifest is read; package code never is.
pub fn annotate_cache(f: &mut ExposureFinding) {
    let Some(root) = npx_cache_root(&f.found_in) else {
        return;
    };
    f.cache = Some("npx cache".to_string());
    let Some(text) = crate::scanners::read_bounded(&root.join("package.json")) else {
        return;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
        return;
    };
    // Each `_npx.packages` spec by its identity (a git spec with a token in its URL is
    // named by its repository path, never copied), and kept as `name@version` (or the
    // bare name when it floats) so the activity check can match the exact launch.
    let ids: Vec<(String, Option<String>)> = json
        .get("_npx")
        .and_then(|n| n.get("packages"))
        .and_then(|p| p.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .filter_map(|spec| crate::scanners::mcp::package_identity_of("npm", spec))
                .take(16)
                .collect()
        })
        .unwrap_or_default();
    let mut specs: Vec<String> = ids
        .iter()
        .map(|(n, v)| match v {
            Some(v) => format!("{n}@{v}"),
            None => n.clone(),
        })
        .collect();
    specs.sort();
    specs.dedup();
    f.cache_specs = specs;
    let mut names: Vec<String> = ids.into_iter().map(|(n, _)| n).collect();
    if names.is_empty()
        && let Some(deps) = json.get("dependencies").and_then(|d| d.as_object())
    {
        names = deps.keys().cloned().collect();
    }
    let mut names: Vec<String> = names
        .iter()
        .filter(|n| !n.is_empty())
        .map(|n| crate::scanners::sanitize_display(n, 128))
        .collect();
    names.sort();
    names.dedup();
    names.truncate(5);
    f.cache_parent = names;
}

/// Decide whether a catalog entry's version constraint matches a candidate version.
/// Precedence: exact `version` (string equality) > `version_range` (semver) > neither
/// (matches all versions). A range against a missing or unparseable version is a
/// non-match (conservative — better to miss than to false-positive).
pub fn version_matches(entry: &crate::models::ExposureEntry, candidate: Option<&str>) -> bool {
    if let Some(ref exact) = entry.version {
        return candidate == Some(exact.as_str());
    }
    if let Some(ref range) = entry.version_range {
        let Some(cand) = candidate else {
            return false;
        };
        let (Ok(req), Some(ver)) = (semver::VersionReq::parse(range.trim()), lenient_version(cand)) else {
            return false;
        };
        // Compare the numeric core only. The semver crate applies Cargo's rule that a
        // pre-release candidate matches a comparator only when it shares the same
        // major.minor.patch, so `<0.1.2` would never match `0.1.1-rc.2` and a row for a
        // package that ships only pre-releases (the @deepseek-ai/dsh line, every
        // `2.0.0a1`-style Python pre-release) would silently never fire. Dropping the
        // pre-release tag gives node-semver's includePrerelease behaviour, with one
        // documented edge: `X.Y.Z-pre` is treated as `X.Y.Z`, so `<X.Y.Z` does not match
        // the pre-release of the fix version itself — a conservative miss, never a
        // false positive.
        let core = semver::Version::new(ver.major, ver.minor, ver.patch);
        return req.matches(&core);
    }
    // No version constraint → applies to all versions.
    true
}

/// Parse a version leniently into semver: accepts "1.2.3", pads "1.2" -> "1.2.0" and
/// "1" -> "1.0.0", and strips a leading "v". Returns None if the numeric core is
/// unparseable.
fn lenient_version(v: &str) -> Option<semver::Version> {
    let v = v.trim().strip_prefix('v').unwrap_or(v.trim());
    if let Ok(parsed) = semver::Version::parse(v) {
        return Some(parsed);
    }
    // Split off any pre-release/build suffix, pad the numeric core to 3 components.
    let core_end = v.find(|c: char| c != '.' && !c.is_ascii_digit()).unwrap_or(v.len());
    let (core, _suffix) = v.split_at(core_end);
    let mut parts: Vec<&str> = core.split('.').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return None;
    }
    while parts.len() < 3 {
        parts.push("0");
    }
    semver::Version::parse(&parts[..3].join(".")).ok()
}

/// PEP 503 name normalisation: lowercase, runs of `-`, `_` and `.` collapse to `-`.
/// PyPI treats `mcp_runcommand_server`, `Mcp.Runcommand.Server` and
/// `mcp-runcommand-server` as the same project, so the catalog must too.
pub fn pep503_normalize(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut dash = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !dash {
                out.push('-');
                dash = true;
            }
        } else {
            out.push(c.to_ascii_lowercase());
            dash = false;
        }
    }
    out
}

/// Ecosystem-aware name equality: PEP 503 for pypi, case-insensitive elsewhere.
pub fn names_match(ecosystem: &str, a: &str, b: &str) -> bool {
    if ecosystem.eq_ignore_ascii_case("pypi") {
        pep503_normalize(a) == pep503_normalize(b)
    } else {
        eq_case_insensitive(a, b)
    }
}
