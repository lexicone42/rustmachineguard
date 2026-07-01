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
