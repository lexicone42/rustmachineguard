//! Cross-cutting risk analysis over a completed scan — signals that emerge from the
//! *composition* of findings rather than any single one, plus a single ranked list
//! of the actionable security findings for risk-first reporting.

use crate::models::{PassphraseStatus, ScanReport};
use std::collections::BTreeSet;

/// Severity of a finding, ordered so `Critical` sorts first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }
    fn rank(&self) -> u8 {
        match self {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
        }
    }
}

/// A single actionable security finding, normalized across all scanner categories so
/// reports can lead with what matters instead of a flat inventory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    pub severity: Severity,
    /// Short category, e.g. "Exposure", "Hook", "Credential", "Toxic Flow".
    pub category: String,
    pub title: String,
    /// Where it was found (path / config source), for triage.
    pub location: String,
}

/// Collect and rank the actionable findings in a scan. Highest severity first.
/// This is the risk-first view that HTML/fleet reports lead with.
pub fn collect_findings(report: &ScanReport) -> Vec<Finding> {
    let mut f = Vec::new();

    // Known-malicious / vulnerable package matches — the most actionable signal.
    for e in &report.exposure_findings {
        f.push(Finding {
            severity: Severity::Critical,
            category: "Exposure".into(),
            title: format!("Known-bad {} package: {} {}", e.ecosystem, e.name, e.version),
            location: e.found_in.clone(),
        });
    }

    // MCP server configuration risks (transport encryption, over-broad scope).
    let home = report.device.home_dir.as_str();
    for mcp in &report.mcp_configs {
        for s in &mcp.servers {
            // Plaintext remote transport: credentials/data sent unencrypted.
            if let Some(url) = &s.url
                && url.to_lowercase().starts_with("http://")
            {
                f.push(Finding {
                    severity: Severity::High,
                    category: "MCP transport".into(),
                    title: format!(
                        "MCP server '{}' uses plaintext HTTP ({}) — traffic and tokens are unencrypted",
                        s.name, url
                    ),
                    location: mcp.config_path.clone(),
                });
            }
            // Over-broad filesystem scope: a filesystem server rooted at / or $HOME
            // exposes the whole machine/home to the agent.
            let is_fs = s
                .package_name
                .as_deref()
                .map(|n| n.contains("filesystem"))
                .unwrap_or(false);
            if is_fs {
                for arg in &s.args {
                    if is_broad_root(arg, home) {
                        f.push(Finding {
                            severity: Severity::Medium,
                            category: "MCP scope".into(),
                            title: format!(
                                "MCP filesystem server '{}' is rooted at a broad path ({}) — near-whole-machine access",
                                s.name, arg
                            ),
                            location: mcp.config_path.clone(),
                        });
                    }
                }
            }
            // Credentials hardcoded inline in the config `env` block (names only). A
            // git-tracked config makes this a committed secret — the same escalation
            // as a git-tracked `.env`, so it becomes Critical "Secret leak".
            if !s.inline_secret_env_keys.is_empty() {
                let keys = s.inline_secret_env_keys.join(", ");
                let finding = if mcp.git_tracked {
                    Finding {
                        severity: Severity::Critical,
                        category: "Secret leak".into(),
                        title: format!(
                            "MCP server '{}' has hardcoded credential(s) in a git-tracked config: {} — committed secret",
                            s.name, keys
                        ),
                        location: mcp.config_path.clone(),
                    }
                } else {
                    Finding {
                        severity: Severity::High,
                        category: "MCP secret".into(),
                        title: format!(
                            "MCP server '{}' has hardcoded credential(s) in its config env block: {} — reference ${{ENV_VAR}} instead",
                            s.name, keys
                        ),
                        location: mcp.config_path.clone(),
                    }
                };
                f.push(finding);
            }
            // A launch command that downloads-and-executes (curl|bash, etc.): the
            // server's own bootstrap is a remote-code-execution vector.
            let launch = match &s.command {
                Some(c) => format!("{} {}", c, s.args.join(" ")),
                None => s.args.join(" "),
            };
            if !launch.trim().is_empty()
                && !crate::scanners::rules_files::check_dangerous_patterns(&launch).is_empty()
            {
                f.push(Finding {
                    severity: Severity::High,
                    category: "MCP command".into(),
                    title: format!(
                        "MCP server '{}' launches via a download-and-execute command — remote code on startup",
                        s.name
                    ),
                    location: mcp.config_path.clone(),
                });
            }
        }
    }

    // Settings hooks run shell commands on agent events (silent code execution).
    for s in &report.agent_settings {
        for h in &s.hooks {
            f.push(Finding {
                severity: if h.dangerous { Severity::Critical } else { Severity::Medium },
                category: "Hook".into(),
                title: format!(
                    "{} hook [{}] runs a command{}",
                    h.event,
                    h.matcher.as_deref().unwrap_or("*"),
                    if h.dangerous { " matching a dangerous pattern" } else { "" }
                ),
                location: s.path.clone(),
            });
        }
        if s.auto_approve_mcp {
            f.push(Finding {
                severity: Severity::High,
                category: "MCP auto-approval".into(),
                title: "enableAllProjectMcpServers auto-approves project MCP servers".into(),
                location: s.path.clone(),
            });
        }
        if s.permission_mode.as_deref() == Some("bypassPermissions") {
            f.push(Finding {
                severity: Severity::High,
                category: "Permissions".into(),
                title: "permission mode is bypassPermissions".into(),
                location: s.path.clone(),
            });
        }
        // Credentials hardcoded inline in the settings `env` block (names only).
        // A git-tracked settings file makes this a committed secret.
        if !s.inline_secret_env_keys.is_empty() {
            let keys = s.inline_secret_env_keys.join(", ");
            f.push(if s.git_tracked {
                Finding {
                    severity: Severity::Critical,
                    category: "Secret leak".into(),
                    title: format!(
                        "hardcoded credential(s) in a git-tracked settings env block: {keys} — committed secret"
                    ),
                    location: s.path.clone(),
                }
            } else {
                Finding {
                    severity: Severity::High,
                    category: "Settings secret".into(),
                    title: format!(
                        "hardcoded credential(s) in the settings env block: {keys} — reference ${{ENV_VAR}} instead"
                    ),
                    location: s.path.clone(),
                }
            });
        }
        // EAA-007: an AI base URL pointed at a non-official host routes requests (and
        // the API key) through that host — the CVE-2026-21852 exfil vector. A proxy may
        // be legitimate, so this is advisory-to-review, not automatically critical.
        for g in &s.gateway_overrides {
            if !g.official {
                f.push(Finding {
                    severity: Severity::Medium,
                    category: "Gateway routing".into(),
                    title: format!(
                        "{} points to non-official host {} — verify this gateway is trusted (EAA-007)",
                        g.var, g.host
                    ),
                    location: s.path.clone(),
                });
            }
        }
    }

    // At-rest AI tokens with loose permissions.
    for c in &report.ai_credentials {
        if c.world_readable {
            f.push(Finding {
                severity: Severity::High,
                category: "Credential".into(),
                title: format!("{} {} is world-readable", c.provider, c.credential_type),
                location: c.path.clone(),
            });
        }
    }

    // .env secrets in agent project roots.
    for e in &report.env_files {
        if e.git_tracked {
            f.push(Finding {
                severity: Severity::Critical,
                category: "Secret leak".into(),
                title: format!(".env is git-tracked ({} keys) — committed secrets", e.key_count),
                location: e.path.clone(),
            });
        } else if e.world_readable {
            f.push(Finding {
                severity: Severity::High,
                category: "Secret exposure".into(),
                title: format!(".env is world-readable ({} keys)", e.key_count),
                location: e.path.clone(),
            });
        }
    }

    // World-readable agent transcript/state stores (EAA-005 collection surface):
    // these hold full conversation history — code, prompts, and any secrets discussed —
    // so loose permissions let any local user read the lot.
    for t in &report.transcripts {
        if t.world_readable {
            f.push(Finding {
                severity: Severity::High,
                category: "Transcript exposure".into(),
                title: format!(
                    "{} {} store is world-readable ({} files) — conversation history exposed (EAA-005)",
                    t.framework, t.kind, t.file_count
                ),
                location: t.path.clone(),
            });
        }
    }

    // Auto-updating third-party plugin marketplaces (EAA-009): a non-official source
    // that pulls new remote code automatically hot-loads unreviewed agent code — the
    // rug-pull surface. Installing third-party plugins is normal, so this is advisory:
    // it fires only when auto-update is on AND the source isn't Anthropic-official.
    for m in &report.marketplaces {
        if m.auto_update && !m.official {
            f.push(Finding {
                severity: Severity::Medium,
                category: "Plugin marketplace".into(),
                title: format!(
                    "third-party plugin marketplace '{}' ({}) auto-updates — remote code hot-loads without review (EAA-009)",
                    m.name, m.source_ref
                ),
                location: "~/.claude/plugins/known_marketplaces.json".into(),
            });
        }
    }

    // Unprotected SSH keys.
    for k in &report.ssh_keys {
        if k.has_passphrase == PassphraseStatus::NoPassphrase {
            f.push(Finding {
                severity: Severity::High,
                category: "SSH key".into(),
                title: format!("{} key has no passphrase", k.key_type),
                location: k.path.clone(),
            });
        }
    }

    // Dangerous patterns in agent rules/instruction files.
    for rf in &report.rules_files {
        for finding in &rf.findings {
            let sev = match finding.severity.as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                _ => Severity::Low,
            };
            f.push(Finding {
                severity: sev,
                category: "Rules file".into(),
                title: format!("dangerous pattern: {}", finding.pattern),
                location: rf.path.clone(),
            });
        }
    }

    // MCP registry verification verdicts.
    for check in &report.mcp_registry_checks {
        match &check.verdict {
            crate::registry::RegistryVerdict::PossibleTyposquat { registered_as } => {
                f.push(Finding {
                    severity: Severity::Medium,
                    category: "Registry".into(),
                    title: format!(
                        "'{}' is one edit away from registered {} (possible typosquat)",
                        check.package, registered_as
                    ),
                    location: check.server_name.clone(),
                });
            }
            crate::registry::RegistryVerdict::Registered { deprecated: true, .. } => {
                f.push(Finding {
                    severity: Severity::Medium,
                    category: "Registry".into(),
                    title: format!("{} is deprecated in the official MCP registry", check.package),
                    location: check.server_name.clone(),
                });
            }
            _ => {}
        }
    }

    // Agent identity posture: static long-lived keys are the ASI03 anti-pattern.
    if let Some(id) = &report.agent_identity {
        if !id.static_api_keys.is_empty() {
            let static_only = id.static_only();
            f.push(Finding {
                // Advisory by default; elevated when static keys are the ONLY auth in use.
                severity: if static_only { Severity::Medium } else { Severity::Low },
                category: "Agent identity".into(),
                title: format!(
                    "{} static long-lived AI API key(s) in use ({}unbound bearer tokens, OWASP ASI03){}",
                    id.static_api_keys.len(),
                    if static_only { "sole credential; " } else { "" },
                    if static_only {
                        " — no OAuth/SPIFFE detected; prefer short-lived scoped credentials"
                    } else {
                        ""
                    }
                ),
                location: id.static_api_keys.join(", "),
            });
        }
    }

    // Composition-level toxic-flow surface.
    if let Some(tf) = analyze_toxic_flow(report) {
        f.push(Finding {
            severity: Severity::High,
            category: "Toxic Flow".into(),
            title: format!(
                "sensitive source ({}) + exfil sink ({}) on the agent surface",
                tf.sources.join("/"),
                tf.sinks.join("/")
            ),
            location: report.device.hostname.clone(),
        });
    }

    f.sort_by_key(|x| x.severity.rank());
    f
}

/// Capability categories that read sensitive/private data (a flow "source").
const SOURCES: &[&str] = &["filesystem", "database", "environment", "source_control"];
/// Capability categories that can send data off the host (a flow "sink").
const SINKS: &[&str] = &["network", "communication"];

/// The "lethal trifecta" / toxic-flow surface: when the connected agent surface
/// holds BOTH a sensitive-data source and an exfiltration sink, any prompt injection
/// that reaches the agent can read private data and send it out. Each individual
/// capability is benign and authorized; the *combination across connected servers and
/// skills* is the risk — which a single MCP client never sees.
#[derive(Debug, Clone, PartialEq)]
pub struct ToxicFlowSurface {
    pub sources: Vec<String>,
    pub sinks: Vec<String>,
}

/// True if `arg` is a filesystem root broad enough to expose the whole machine or the
/// user's entire home directory.
pub fn is_broad_root(arg: &str, home: &str) -> bool {
    let a = arg.trim().trim_end_matches('/');
    if a.is_empty() {
        return true; // "/" trimmed to ""
    }
    matches!(a, "~" | "$HOME" | "${HOME}" | "/home" | "/Users" | "/root")
        || (!home.is_empty() && a == home.trim_end_matches('/'))
}

/// Aggregate observed (probed) + declared (skill) capabilities across the whole scan
/// and report a toxic-flow surface when both a source and a sink are present.
pub fn analyze_toxic_flow(report: &ScanReport) -> Option<ToxicFlowSurface> {
    let mut caps: BTreeSet<&str> = BTreeSet::new();
    for probe in &report.mcp_probes {
        if probe.success {
            for c in &probe.observed_capabilities {
                caps.insert(c.as_str());
            }
        }
    }
    for skill in &report.agent_skills {
        for c in &skill.capabilities {
            caps.insert(c.as_str());
        }
    }

    let sources: Vec<String> = SOURCES
        .iter()
        .filter(|s| caps.contains(**s))
        .map(|s| s.to_string())
        .collect();
    let sinks: Vec<String> = SINKS
        .iter()
        .filter(|s| caps.contains(**s))
        .map(|s| s.to_string())
        .collect();

    if !sources.is_empty() && !sinks.is_empty() {
        Some(ToxicFlowSurface { sources, sinks })
    } else {
        None
    }
}
