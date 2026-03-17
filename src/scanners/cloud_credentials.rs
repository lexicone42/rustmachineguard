use crate::models::CloudCredential;
use crate::platform::PlatformInfo;
use crate::scanners::Scanner;

pub struct CloudCredentialsScanner;

impl Scanner for CloudCredentialsScanner {
    type Output = Vec<CloudCredential>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<CloudCredential> {
        let mut results = Vec::new();

        // AWS credentials
        let aws_creds = platform.aws_credentials_path();
        if aws_creds.is_file() {
            let profiles = extract_ini_sections(&aws_creds);
            results.push(CloudCredential {
                provider: "AWS".to_string(),
                credential_type: "credentials file".to_string(),
                config_path: aws_creds.display().to_string(),
                profiles,
            });
        }

        // AWS config (may have SSO profiles)
        let aws_config = aws_creds.parent().map(|p| p.join("config"));
        if let Some(ref cfg) = aws_config {
            if cfg.is_file() {
                let profiles = extract_ini_sections(cfg)
                    .into_iter()
                    .map(|p| p.strip_prefix("profile ").unwrap_or(&p).to_string())
                    .collect();
                results.push(CloudCredential {
                    provider: "AWS".to_string(),
                    credential_type: "config file (SSO/profiles)".to_string(),
                    config_path: cfg.display().to_string(),
                    profiles,
                });
            }
        }

        // GCP
        let gcloud_dir = platform.gcloud_config_dir();
        if gcloud_dir.is_dir() {
            let mut gcp_cred_types = Vec::new();

            // Application default credentials
            let adc = gcloud_dir.join("application_default_credentials.json");
            if adc.is_file() {
                gcp_cred_types.push("application default credentials".to_string());
            }

            // Service account keys in the directory
            let sa_keys: Vec<_> = std::fs::read_dir(&gcloud_dir)
                .into_iter()
                .flatten()
                .flatten()
                .filter(|e| {
                    e.path()
                        .extension()
                        .is_some_and(|ext| ext == "json")
                })
                .filter(|e| {
                    // Check if it looks like a service account key
                    std::fs::read_to_string(e.path())
                        .ok()
                        .is_some_and(|c| c.contains("\"type\": \"service_account\"") || c.contains("\"type\":\"service_account\""))
                })
                .collect();
            if !sa_keys.is_empty() {
                gcp_cred_types
                    .push(format!("{} service account key(s)", sa_keys.len()));
            }

            // Active config
            let properties = gcloud_dir.join("properties");
            let active_account = if properties.is_file() {
                std::fs::read_to_string(&properties)
                    .ok()
                    .and_then(|c| {
                        c.lines()
                            .find(|l| l.starts_with("account"))
                            .map(|l| l.split('=').nth(1).unwrap_or("").trim().to_string())
                    })
            } else {
                None
            };

            if !gcp_cred_types.is_empty() || active_account.is_some() {
                let profiles = active_account.into_iter().collect();
                results.push(CloudCredential {
                    provider: "GCP".to_string(),
                    credential_type: gcp_cred_types.join(", "),
                    config_path: gcloud_dir.display().to_string(),
                    profiles,
                });
            }
        }

        // Azure
        let azure_dir = platform.azure_config_dir();
        if azure_dir.is_dir() {
            let az_profile = azure_dir.join("azureProfile.json");
            let profiles = if az_profile.is_file() {
                std::fs::read_to_string(&az_profile)
                    .ok()
                    .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
                    .and_then(|v| {
                        v["subscriptions"]
                            .as_array()
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|sub| {
                                        sub["name"].as_str().map(|s| s.to_string())
                                    })
                                    .collect()
                            })
                    })
                    .unwrap_or_default()
            } else {
                vec![]
            };

            let has_tokens = azure_dir.join("msal_token_cache.json").is_file()
                || azure_dir.join("accessTokens.json").is_file();

            if has_tokens || !profiles.is_empty() {
                results.push(CloudCredential {
                    provider: "Azure".to_string(),
                    credential_type: if has_tokens {
                        "cached tokens".to_string()
                    } else {
                        "profile".to_string()
                    },
                    config_path: azure_dir.display().to_string(),
                    profiles,
                });
            }
        }

        results
    }
}

/// Extract section names from INI-style files (e.g., [default], [profile foo]).
fn extract_ini_sections(path: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|content| {
            content
                .lines()
                .filter_map(|line| {
                    let trimmed = line.trim();
                    if trimmed.starts_with('[') && trimmed.ends_with(']') {
                        Some(trimmed[1..trimmed.len() - 1].to_string())
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}
