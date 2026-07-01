//! Agent identity posture: *with whose authority does this agent act?*
//!
//! At machine-posture level we can characterize how agents authenticate:
//! - **static, long-lived API keys** — unbound bearer tokens, the anti-pattern the
//!   CoSAI / CNCF guidance warns against (OWASP ASI03).
//! - **OAuth credentials** — refreshable/scoped, better than a static key.
//! - **SPIFFE workload identity** — short-lived SVIDs, the modern target state.
//!
//! This never reads secret *values* — it classifies credential *kinds* from data the
//! scanners already collected (env-var names, credential file types) plus a check for
//! SPIFFE infrastructure on the host.

use crate::models::ScanReport;
use serde::{Deserialize, Serialize};

/// Environment-variable names that hold a static, long-lived AI-service API key.
const STATIC_AI_KEYS: &[&str] = &[
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "CLAUDE_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GROQ_API_KEY",
    "MISTRAL_API_KEY",
    "COHERE_API_KEY",
    "HF_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
    "REPLICATE_API_TOKEN",
    "TOGETHER_API_KEY",
    "PERPLEXITY_API_KEY",
    "DEEPSEEK_API_KEY",
    "XAI_API_KEY",
    "OPENROUTER_API_KEY",
    "FIREWORKS_API_KEY",
];

/// Common SPIFFE Workload API socket locations.
const SPIFFE_SOCKETS: &[&str] = &[
    "/run/spire/sockets/agent.sock",
    "/run/spire/agent-sockets/api.sock",
    "/tmp/spire-agent/public/api.sock",
    "/var/run/spire/sockets/agent.sock",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SpiffeStatus {
    /// SPIFFE workload identity infrastructure is present (short-lived SVIDs available).
    Present { source: String },
    Absent,
}

/// The machine's agent-authentication posture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// Static long-lived API keys in use (env var names — never values).
    pub static_api_keys: Vec<String>,
    /// Providers using OAuth (refreshable/scoped — better than a static key).
    pub oauth_providers: Vec<String>,
    pub spiffe: SpiffeStatus,
}

impl AgentIdentity {
    /// True when agents rely *solely* on static long-lived keys — no OAuth, no SPIFFE.
    pub fn static_only(&self) -> bool {
        !self.static_api_keys.is_empty()
            && self.oauth_providers.is_empty()
            && matches!(self.spiffe, SpiffeStatus::Absent)
    }
}

/// Detect SPIFFE workload-identity infrastructure on the host (env socket, well-known
/// socket paths, or a `spire-agent` binary). Reads the live environment/filesystem.
pub fn detect_spiffe() -> SpiffeStatus {
    if let Ok(sock) = std::env::var("SPIFFE_ENDPOINT_SOCKET") {
        if !sock.is_empty() {
            return SpiffeStatus::Present {
                source: "SPIFFE_ENDPOINT_SOCKET env".into(),
            };
        }
    }
    for path in SPIFFE_SOCKETS {
        if std::path::Path::new(path).exists() {
            return SpiffeStatus::Present {
                source: (*path).to_string(),
            };
        }
    }
    if which::which("spire-agent").is_ok() {
        return SpiffeStatus::Present {
            source: "spire-agent binary".into(),
        };
    }
    SpiffeStatus::Absent
}

/// Compute the agent-identity posture from a scan (classifies credential kinds already
/// collected) plus a live SPIFFE check. Run once at scan time; the result is stored on
/// the report so downstream (findings, fleet) read it without re-probing.
pub fn analyze(report: &ScanReport) -> AgentIdentity {
    let mut static_api_keys: Vec<String> = Vec::new();

    // Static AI keys named in shell configs (values are redacted upstream).
    for sc in &report.shell_configs {
        for entry in &sc.ai_related_entries {
            let name = entry.split(['=', ' ']).next().unwrap_or(entry).trim();
            if is_static_ai_key(name) {
                push_unique(&mut static_api_keys, name);
            }
        }
    }
    // Static AI keys named in .env files (names only).
    for env in &report.env_files {
        for key in &env.secret_keys {
            if is_static_ai_key(key) {
                push_unique(&mut static_api_keys, key);
            }
        }
    }

    // OAuth credentials (refreshable) from the at-rest credential scan.
    let mut oauth_providers: Vec<String> = Vec::new();
    for cred in &report.ai_credentials {
        if cred.credential_type.to_lowercase().contains("oauth") {
            push_unique(&mut oauth_providers, &cred.provider);
        }
    }

    AgentIdentity {
        static_api_keys,
        oauth_providers,
        spiffe: detect_spiffe(),
    }
}

fn is_static_ai_key(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    STATIC_AI_KEYS.iter().any(|k| upper == **k)
}

fn push_unique(v: &mut Vec<String>, s: &str) {
    if !v.iter().any(|x| x == s) {
        v.push(s.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_static_ai_keys_only() {
        assert!(is_static_ai_key("OPENAI_API_KEY"));
        assert!(is_static_ai_key("anthropic_api_key")); // case-insensitive
        assert!(is_static_ai_key("HF_TOKEN"));
        assert!(!is_static_ai_key("PORT"));
        assert!(!is_static_ai_key("DATABASE_URL"));
        assert!(!is_static_ai_key("AWS_SECRET_ACCESS_KEY")); // not an AI-service key
    }

    #[test]
    fn static_only_requires_no_oauth_and_no_spiffe() {
        let base = AgentIdentity {
            static_api_keys: vec!["OPENAI_API_KEY".into()],
            oauth_providers: vec![],
            spiffe: SpiffeStatus::Absent,
        };
        assert!(base.static_only());

        let with_oauth = AgentIdentity {
            oauth_providers: vec!["Claude Code".into()],
            ..base.clone()
        };
        assert!(!with_oauth.static_only(), "OAuth present -> not static-only");

        let with_spiffe = AgentIdentity {
            spiffe: SpiffeStatus::Present { source: "x".into() },
            ..base.clone()
        };
        assert!(!with_spiffe.static_only(), "SPIFFE present -> not static-only");

        let no_static = AgentIdentity {
            static_api_keys: vec![],
            ..base
        };
        assert!(!no_static.static_only(), "no static keys -> not static-only");
    }
}
