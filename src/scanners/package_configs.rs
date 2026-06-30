use crate::models::{PackageConfigAudit, PackageConfigFinding};
use crate::platform::PlatformInfo;
use crate::scanners::Scanner;
use std::path::PathBuf;

pub struct PackageConfigsScanner;

impl Scanner for PackageConfigsScanner {
    type Output = Vec<PackageConfigAudit>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<PackageConfigAudit> {
        let mut results = Vec::new();
        let home = platform.home_dir();

        // .npmrc locations
        for path in npmrc_paths(&home) {
            if path.is_file() {
                if let Some(content) = crate::scanners::read_bounded(&path) {
                    let findings = audit_npmrc(&content);
                    if !findings.is_empty() {
                        results.push(PackageConfigAudit {
                            manager: "npm".to_string(),
                            config_path: path.display().to_string(),
                            findings,
                        });
                    }
                }
            }
        }

        // pip config
        for path in pip_config_paths(&home) {
            if path.is_file() {
                if let Some(content) = crate::scanners::read_bounded(&path) {
                    let findings = audit_pip_config(&content);
                    if !findings.is_empty() {
                        results.push(PackageConfigAudit {
                            manager: "pip".to_string(),
                            config_path: path.display().to_string(),
                            findings,
                        });
                    }
                }
            }
        }

        // bunfig.toml
        let bunfig = home.join("bunfig.toml");
        if bunfig.is_file() {
            if let Some(content) = crate::scanners::read_bounded(&bunfig) {
                let findings = audit_bunfig(&content);
                if !findings.is_empty() {
                    results.push(PackageConfigAudit {
                        manager: "bun".to_string(),
                        config_path: bunfig.display().to_string(),
                        findings,
                    });
                }
            }
        }

        // .yarnrc / .yarnrc.yml
        for (name, path) in yarn_config_paths(&home) {
            if path.is_file() {
                if let Some(content) = crate::scanners::read_bounded(&path) {
                    let findings = audit_yarn_config(&content, &name);
                    if !findings.is_empty() {
                        results.push(PackageConfigAudit {
                            manager: format!("yarn ({})", name),
                            config_path: path.display().to_string(),
                            findings,
                        });
                    }
                }
            }
        }

        results
    }
}

fn npmrc_paths(home: &PathBuf) -> Vec<PathBuf> {
    vec![
        home.join(".npmrc"),
        PathBuf::from("/etc/npmrc"),
    ]
}

fn pip_config_paths(home: &PathBuf) -> Vec<PathBuf> {
    vec![
        home.join(".config/pip/pip.conf"),
        home.join(".pip/pip.conf"),
        PathBuf::from("/etc/pip.conf"),
    ]
}

fn yarn_config_paths(home: &PathBuf) -> Vec<(String, PathBuf)> {
    vec![
        ("classic".to_string(), home.join(".yarnrc")),
        ("berry".to_string(), home.join(".yarnrc.yml")),
    ]
}

pub fn audit_npmrc(content: &str) -> Vec<PackageConfigFinding> {
    let mut findings = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }

        let lower = line.to_lowercase();

        if lower.starts_with("registry=") || lower.contains(":registry=") {
            let val = line.splitn(2, '=').nth(1).unwrap_or("");
            if !val.contains("registry.npmjs.org") {
                findings.push(PackageConfigFinding {
                    severity: "high".to_string(),
                    description: format!("Custom npm registry: {}", val),
                });
            }
        }

        if lower.starts_with("//") && lower.contains(":_authtoken=") {
            findings.push(PackageConfigFinding {
                severity: "high".to_string(),
                description: "Registry auth token present in config".to_string(),
            });
        }

        if lower.starts_with("//") && lower.contains(":_auth=") {
            findings.push(PackageConfigFinding {
                severity: "high".to_string(),
                description: "Registry basic auth credentials present in config".to_string(),
            });
        }

        if lower == "strict-ssl=false" {
            findings.push(PackageConfigFinding {
                severity: "critical".to_string(),
                description: "SSL verification disabled (strict-ssl=false)".to_string(),
            });
        }

        if lower.starts_with("cafile=") || lower.starts_with("cert=") {
            findings.push(PackageConfigFinding {
                severity: "medium".to_string(),
                description: format!("Custom certificate configuration: {}", line),
            });
        }

        if lower.contains("ignore-scripts=true") {
            findings.push(PackageConfigFinding {
                severity: "info".to_string(),
                description: "Install scripts disabled (ignore-scripts=true)".to_string(),
            });
        }
    }

    findings
}

pub fn audit_pip_config(content: &str) -> Vec<PackageConfigFinding> {
    let mut findings = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        let lower = line.to_lowercase();

        if lower.starts_with("index-url") || lower.starts_with("extra-index-url") {
            let val = line.splitn(2, '=').nth(1).unwrap_or("").trim();
            if !val.contains("pypi.org") {
                findings.push(PackageConfigFinding {
                    severity: "high".to_string(),
                    description: format!("Custom PyPI index: {}", val),
                });
            }
        }

        if lower.starts_with("trusted-host") {
            findings.push(PackageConfigFinding {
                severity: "high".to_string(),
                description: format!("Trusted host (bypasses TLS verification): {}", line),
            });
        }

        if lower.contains("cert") && lower.contains("=") && !lower.starts_with("#") && !lower.starts_with(";") {
            findings.push(PackageConfigFinding {
                severity: "medium".to_string(),
                description: format!("Custom certificate configuration: {}", line),
            });
        }
    }

    findings
}

pub fn audit_bunfig(content: &str) -> Vec<PackageConfigFinding> {
    let mut findings = Vec::new();

    let Ok(table): Result<toml::Table, _> = content.parse() else {
        return findings;
    };

    if let Some(install) = table.get("install").and_then(|v| v.as_table()) {
        if let Some(registry) = install.get("registry").and_then(|v| v.as_str()) {
            if !registry.contains("registry.npmjs.org") {
                findings.push(PackageConfigFinding {
                    severity: "high".to_string(),
                    description: format!("Custom bun registry: {}", registry),
                });
            }
        }
    }

    if let Some(scopes) = table.get("install").and_then(|v| v.as_table()).and_then(|t| t.get("scopes")).and_then(|v| v.as_table()) {
        for (scope, cfg) in scopes {
            if let Some(url) = cfg.as_table().and_then(|t| t.get("url")).and_then(|v| v.as_str()) {
                findings.push(PackageConfigFinding {
                    severity: "medium".to_string(),
                    description: format!("Scoped registry for @{}: {}", scope, url),
                });
            }
        }
    }

    findings
}

pub fn audit_yarn_config(content: &str, variant: &str) -> Vec<PackageConfigFinding> {
    let mut findings = Vec::new();

    if variant == "classic" {
        for line in content.lines() {
            let line = line.trim();
            let lower = line.to_lowercase();

            if lower.starts_with("registry") {
                let val = line.splitn(2, ' ').nth(1).unwrap_or("").trim_matches('"');
                if !val.contains("registry.yarnpkg.com") && !val.contains("registry.npmjs.org") {
                    findings.push(PackageConfigFinding {
                        severity: "high".to_string(),
                        description: format!("Custom yarn classic registry: {}", val),
                    });
                }
            }

            if lower == "strict-ssl false" {
                findings.push(PackageConfigFinding {
                    severity: "critical".to_string(),
                    description: "SSL verification disabled (strict-ssl false)".to_string(),
                });
            }
        }
    } else {
        // Berry (.yarnrc.yml) — simple line scanning for key patterns
        for line in content.lines() {
            let line = line.trim();
            let lower = line.to_lowercase();

            if lower.starts_with("npmregistryserver:") {
                let val = line.splitn(2, ':').nth(1).unwrap_or("").trim().trim_matches('"');
                if !val.contains("registry.yarnpkg.com") && !val.contains("registry.npmjs.org") {
                    findings.push(PackageConfigFinding {
                        severity: "high".to_string(),
                        description: format!("Custom yarn berry registry: {}", val),
                    });
                }
            }

            if lower.starts_with("enablestrictssl:") && lower.contains("false") {
                findings.push(PackageConfigFinding {
                    severity: "critical".to_string(),
                    description: "SSL verification disabled (enableStrictSsl: false)".to_string(),
                });
            }

            if lower.starts_with("unsafehttp") && lower.contains("true") {
                findings.push(PackageConfigFinding {
                    severity: "critical".to_string(),
                    description: "Unsafe HTTP allowed (unsafeHttpWhitelist or similar)".to_string(),
                });
            }
        }
    }

    findings
}
