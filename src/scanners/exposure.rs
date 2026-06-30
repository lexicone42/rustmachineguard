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
            // If catalog entry specifies a version, match exactly
            if let Some(ref entry_version) = entry.version {
                if let Some(ref server_version) = server.package_version {
                    if entry_version != server_version {
                        continue;
                    }
                } else {
                    // Server has no version info but catalog requires specific version — skip
                    continue;
                }
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
            if let Some(ref entry_version) = entry.version {
                if entry_version != version {
                    continue;
                }
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
