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
        let home = platform.home_dir();
        // Hugging Face stores the user access token as a bare file: $HF_TOKEN_PATH, else
        // $HF_HOME/token, else $XDG_CACHE_HOME/huggingface/token, else
        // ~/.cache/huggingface/token (huggingface_hub environment-variable reference).
        let hf_token = std::env::var_os("HF_TOKEN_PATH").map(PathBuf::from).unwrap_or_else(|| {
            let hf_home = std::env::var_os("HF_HOME").map(PathBuf::from).unwrap_or_else(|| {
                std::env::var_os("XDG_CACHE_HOME")
                    .map(|c| PathBuf::from(c).join("huggingface"))
                    .unwrap_or_else(|| home.join(".cache/huggingface"))
            });
            hf_home.join("token")
        });
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
            ("Hugging Face", "user access token", hf_token),
        ];

        let mut results = Vec::new();
        for (provider, cred_type, path) in candidates {
            if !crate::scanners::probe_exists(&path) {
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

        // Inline API keys in agent CONFIG files. Continue and Aider both document -- and
        // advise against -- writing the key into the config itself; the documented forms
        // are `${{ secrets.NAME }}` (Continue) and environment variables / .env (Aider).
        // Only the key NAMES are recorded, never a value.
        let inline: [(&str, PathBuf, fn(&str) -> Vec<String>); 3] = [
            ("Continue", home.join(".continue/config.yaml"), continue_inline_api_keys),
            ("Continue", home.join(".continue/config.json"), continue_inline_api_keys),
            ("Aider", home.join(".aider.conf.yml"), aider_inline_api_keys),
        ];
        for (provider, path, detect) in inline {
            let Some(text) = crate::scanners::read_bounded(&path) else {
                continue;
            };
            let keys = detect(&text);
            if keys.is_empty() {
                continue;
            }
            let (permissions, world_readable, group_readable) = match file_perms(&path) {
                Some((p, w, g)) => (Some(p), w, g),
                None => (None, false, false),
            };
            let file = path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
            results.push(AiCredential {
                provider: provider.to_string(),
                credential_type: format!("inline {} in {file}", keys.join(", ")),
                path: path.display().to_string(),
                permissions,
                world_readable,
                group_readable,
            });
        }
        results
    }
}

/// A value that is a reference, not a secret: Continue's `${{ secrets.X }}` /
/// `${{ env.X }}`, a shell-style `$VAR` / `${VAR}`, or empty.
fn is_reference(value: &str) -> bool {
    let v = value.trim().trim_matches(['"', '\'', ',']);
    v.is_empty() || v.starts_with("${{") || v.starts_with('$') || v.starts_with("localEnv:")
}

/// Continue: `apiKey: <literal>` (config.yaml) or `"apiKey": "<literal>"` (config.json).
/// Returns the key names found with a literal value; never the value.
pub fn continue_inline_api_keys(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim().trim_start_matches("- ");
        let rest = t
            .strip_prefix("apiKey:")
            .or_else(|| t.strip_prefix("\"apiKey\":"))
            .or_else(|| t.strip_prefix("apiKey :"));
        if let Some(v) = rest
            && !is_reference(v)
            && !out.iter().any(|k| k == "apiKey")
        {
            out.push("apiKey".to_string());
        }
    }
    out
}

/// Aider: `openai-api-key: <literal>`, `anthropic-api-key: <literal>`, any `*-api-key:`,
/// or an `api-key:` list with provider=key items. Key names only.
pub fn aider_inline_api_keys(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        let Some((k, v)) = t.split_once(':') else { continue };
        let k = k.trim();
        let literal = if k == "api-key" {
            // list form: the next non-empty line is a `- provider=key` item
            v.trim().is_empty()
                && lines[i + 1..]
                    .iter()
                    .map(|l| l.trim())
                    .find(|l| !l.is_empty())
                    .is_some_and(|l| l.starts_with('-') && l.contains('=') && !is_reference(l.rsplit('=').next().unwrap_or("")))
        } else {
            k.ends_with("-api-key") && !is_reference(v)
        };
        if literal && !out.iter().any(|x| x == k) {
            out.push(k.to_string());
        }
    }
    out
}
