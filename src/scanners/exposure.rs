use crate::models::{ExposureEntry, ExposureFinding, McpServerDetail};

pub struct ExposureCatalog {
    entries: Vec<ExposureEntry>,
}

impl ExposureCatalog {
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read catalog {}: {}", path.display(), e))?;
        let entries: Vec<ExposureEntry> = serde_json::from_str(&content)
            .map_err(|e| format!("failed to parse catalog {}: {}", path.display(), e))?;
        Ok(Self { entries })
    }

    pub fn load_from_str(content: &str) -> Result<Self, String> {
        let entries: Vec<ExposureEntry> = serde_json::from_str(content)
            .map_err(|e| format!("failed to parse catalog: {}", e))?;
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

    pub fn check_mcp_server(
        &self,
        server: &McpServerDetail,
        config_path: &str,
    ) -> Vec<ExposureFinding> {
        let mut findings = Vec::new();
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
            if !eq_case_insensitive(&entry.name, pkg_name) {
                continue;
            }
            if !version_matches(entry, server.package_version.as_deref()) {
                continue;
            }
            findings.push(ExposureFinding {
                ecosystem: ecosystem.clone(),
                name: pkg_name.clone(),
                version: server
                    .package_version
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                advisory: entry.advisory.clone().unwrap_or_default(),
                found_in: config_path.to_string(),
            });
        }

        findings
    }

    pub fn check_extension(
        &self,
        ecosystem: &str,
        name: &str,
        version: &str,
        found_in: &str,
    ) -> Vec<ExposureFinding> {
        let mut findings = Vec::new();

        for entry in &self.entries {
            if !eq_case_insensitive(&entry.ecosystem, ecosystem) {
                continue;
            }
            if !eq_case_insensitive(&entry.name, name) {
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
            });
        }

        findings
    }
}

fn eq_case_insensitive(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
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
        let (Ok(req), Some(ver)) = (
            semver::VersionReq::parse(range.trim()),
            lenient_version(cand),
        ) else {
            return false;
        };
        return req.matches(&ver);
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
    let core_end = v
        .find(|c: char| c != '.' && !c.is_ascii_digit())
        .unwrap_or(v.len());
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
