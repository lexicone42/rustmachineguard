use crate::models::AiCredential;
use crate::platform::PlatformInfo;
use crate::scanners::{file_perms, Scanner};
use std::path::PathBuf;

/// Detects at-rest credential files for AI coding tools (OAuth tokens, API-key
/// stores) and flags loose file permissions. These tokens authenticate the agent's
/// identity and billing; a world-readable `~/.claude/.credentials.json` is a concrete,
/// fixable exposure that the cloud-credential scanner (AWS/GCP/Azure) does not cover.
///
/// SECURITY: this scanner reports existence and permissions ONLY — it never reads or
/// stores the secret values.
pub struct AiCredentialsScanner;

impl Scanner for AiCredentialsScanner {
    type Output = Vec<AiCredential>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<AiCredential> {
        // (provider, credential_type, absolute path) — only existing files are reported.
        let candidates: Vec<(&str, &str, PathBuf)> = vec![
            (
                "Claude Code",
                "OAuth token",
                platform.claude_config_dir().join(".credentials.json"),
            ),
            (
                "Codex",
                "auth token",
                platform.codex_config_dir().join("auth.json"),
            ),
            (
                "Gemini CLI",
                "OAuth credentials",
                platform.gemini_config_dir().join("oauth_creds.json"),
            ),
            (
                "GitHub Copilot",
                "app token",
                platform.github_copilot_config_dir().join("apps.json"),
            ),
            (
                "GitHub Copilot",
                "host token",
                platform.github_copilot_config_dir().join("hosts.json"),
            ),
            (
                "OpenCode",
                "auth token",
                platform.opencode_config_dir().join("auth.json"),
            ),
            (
                "Amazon Q",
                "SSO cache",
                platform.aws_q_config_dir().join("cache"),
            ),
        ];

        let mut results = Vec::new();
        for (provider, cred_type, path) in candidates {
            if !path.exists() {
                continue;
            }
            let (permissions, world_readable, group_readable) = match file_perms(&path) {
                Some((p, w, g)) => (Some(p), w, g),
                None => (None, false, false),
            };
            results.push(AiCredential {
                provider: provider.to_string(),
                credential_type: cred_type.to_string(),
                path: path.display().to_string(),
                permissions,
                world_readable,
                group_readable,
            });
        }
        results
    }
}
