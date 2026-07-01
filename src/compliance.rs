//! Maps rmguard's inventory + findings to the control frameworks that orgs are being
//! asked to satisfy for AI-agent / MCP security, and renders a coverage report.
//!
//! IMPORTANT — honesty: rmguard produces *posture evidence* (inventory + detection),
//! not a compliance attestation. Each control is marked Covered / Partial / Out-of-scope
//! truthfully; runtime controls (invocation logging, network segmentation) are out of
//! scope and say so. The report is evidence you bring to a compliance program, not a
//! claim of compliance.
//!
//! Frameworks referenced (all public):
//! - NSA/CISA "MCP Security" CSI, U/OO/6030316-26 (2026-06-02)
//! - OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10)
//! - OWASP Agentic Skills Top 10 (AST01–AST10)
//! - OWASP MCP Top 10 (MCP01–MCP10)
//! - EU AI Act — AI-system inventory / transparency obligations (enforceable 2026-08-02)
//! - Endpoint AI Agent Abuse (EAA) catalog — github.com/0x4D31/endpoint-ai-agent-abuse (CC0)

use crate::analysis::collect_findings;
use crate::models::ScanReport;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Coverage {
    /// rmguard directly produces the evidence this control asks for.
    Covered,
    /// rmguard covers part of the control; the rest is out of scope.
    Partial,
    /// The control is outside a machine-posture scanner's remit (e.g. runtime).
    OutOfScope,
}

impl Coverage {
    fn label(self) -> &'static str {
        match self {
            Coverage::Covered => "covered",
            Coverage::Partial => "partial",
            Coverage::OutOfScope => "out-of-scope",
        }
    }
}

/// One control from a framework, with rmguard's honest coverage and the finding
/// categories (from `analysis::collect_findings`) that serve as evidence for it.
pub struct Control {
    pub framework: &'static str,
    pub id: &'static str,
    pub title: &'static str,
    pub coverage: Coverage,
    /// How rmguard addresses it — or, for OutOfScope, why not.
    pub how: &'static str,
    /// Finding categories that count as evidence/issues for this control.
    pub finding_categories: &'static [&'static str],
}

/// The control catalog. Deliberately not exhaustive — it covers the controls a
/// machine-posture scanner can speak to, and honestly excludes the rest.
pub const CONTROLS: &[Control] = &[
    // ── NSA/CISA MCP Security CSI ──
    Control {
        framework: "NSA/CISA MCP Security CSI (2026-06)",
        id: "INVENTORY",
        title: "Inventory MCP servers and agent components",
        coverage: Coverage::Covered,
        how: "Scans MCP configs, agents, skills, settings across all known locations; SBOM/Blueprint output.",
        finding_categories: &[],
    },
    Control {
        framework: "NSA/CISA MCP Security CSI (2026-06)",
        id: "UNAUTHORIZED",
        title: "Detect open / unauthorized MCP servers",
        coverage: Coverage::Partial,
        how: "Enumerates configured servers and (opt-in) live-probes them; registry check flags unregistered/shadow. Does not sweep the network for listeners.",
        finding_categories: &["Registry"],
    },
    Control {
        framework: "NSA/CISA MCP Security CSI (2026-06)",
        id: "AUDIT-SERVERS",
        title: "Audit MCP servers for malicious behavior",
        coverage: Coverage::Partial,
        how: "Threat-catalog matching + tool/parameter poisoning + rug-pull detection. Static/behavioral, not a full source audit.",
        finding_categories: &["Exposure", "Toxic Flow"],
    },
    Control {
        framework: "NSA/CISA MCP Security CSI (2026-06)",
        id: "TRUST-BOUNDARIES",
        title: "Define trust boundaries between components",
        coverage: Coverage::Covered,
        how: "Blueprint output models local/remote zones, boundaries, and agent→tool→resource flows.",
        finding_categories: &[],
    },
    Control {
        framework: "NSA/CISA MCP Security CSI (2026-06)",
        id: "SIGN-VERIFY",
        title: "Sign and verify servers / version-pin",
        coverage: Coverage::Partial,
        how: "Verifies servers against the official registry (provenance) and detects unpinned/deprecated packages. Does not itself sign; ingests attestations when available.",
        finding_categories: &["Registry"],
    },
    Control {
        framework: "NSA/CISA MCP Security CSI (2026-06)",
        id: "LOG-INVOCATIONS",
        title: "Log all tool / model invocations",
        coverage: Coverage::OutOfScope,
        how: "Runtime control — an install-time posture scanner cannot log invocations.",
        finding_categories: &[],
    },
    Control {
        framework: "NSA/CISA MCP Security CSI (2026-06)",
        id: "LEAST-PRIV",
        title: "Least-privilege / scoped tokens for agents",
        coverage: Coverage::Partial,
        how: "Flags bypassPermissions and blanket MCP auto-approval; surfaces at-rest credentials. Full agent-identity/scope modeling is not yet implemented.",
        finding_categories: &["Permissions", "MCP auto-approval", "Credential"],
    },
    // ── OWASP Agentic Applications Top 10 (ASI) ──
    Control {
        framework: "OWASP Agentic Applications Top 10 (2026)",
        id: "ASI03",
        title: "Agent Identity & Privilege Abuse",
        coverage: Coverage::Partial,
        how: "Flags permission bypass, MCP auto-approval, hooks (silent exec), at-rest credentials, and static long-lived API keys (anti-pattern) vs OAuth/SPIFFE. Delegation chains not yet modeled.",
        finding_categories: &["Permissions", "MCP auto-approval", "Hook", "Credential", "Agent identity"],
    },
    Control {
        framework: "OWASP Agentic Applications Top 10 (2026)",
        id: "ASI04",
        title: "Agentic Supply Chain",
        coverage: Coverage::Covered,
        how: "Threat catalog (62 entries, exact + version-range), registry provenance verification, exposure matching across MCP/extensions.",
        finding_categories: &["Exposure", "Registry"],
    },
    Control {
        framework: "OWASP Agentic Applications Top 10 (2026)",
        id: "ASI06",
        title: "Memory & Context Poisoning",
        coverage: Coverage::Partial,
        how: "Inventories + hashes rules/memory files (MEMORY.md, SOUL.md, CLAUDE.md), flags dangerous patterns and cross-session tampering via --diff.",
        finding_categories: &["Rules file"],
    },
    Control {
        framework: "OWASP Agentic Applications Top 10 (2026)",
        id: "ASI07",
        title: "Insecure Inter-Agent Communications",
        coverage: Coverage::OutOfScope,
        how: "Agent-to-agent (A2A) traffic is not yet analyzed.",
        finding_categories: &[],
    },
    // ── OWASP Agentic Skills Top 10 (AST) ──
    Control {
        framework: "OWASP Agentic Skills Top 10 (2026)",
        id: "AST02",
        title: "Skill Supply Chain",
        coverage: Coverage::Covered,
        how: "Inventories agent skills, hashes them, infers capabilities across the 8-resource taxonomy.",
        finding_categories: &["Toxic Flow"],
    },
    Control {
        framework: "OWASP Agentic Skills Top 10 (2026)",
        id: "AST07",
        title: "Update Drift",
        coverage: Coverage::Covered,
        how: "--diff detects cross-scan drift in skills, rules files (hash), and probed MCP tool descriptions/schemas (rug-pull).",
        finding_categories: &[],
    },
    Control {
        framework: "OWASP Agentic Skills Top 10 (2026)",
        id: "AST08",
        title: "Poor / Absent Scanning",
        coverage: Coverage::Covered,
        how: "rmguard is the scanning control: risk-first findings across every agent surface.",
        finding_categories: &[],
    },
    // ── OWASP MCP Top 10 (MCP) ──
    Control {
        framework: "OWASP MCP Top 10 (2026)",
        id: "MCP-POISON",
        title: "Tool Poisoning / description injection",
        coverage: Coverage::Covered,
        how: "Scans probed tool + parameter descriptions for injection/line-jumping and invisible-Unicode smuggling.",
        finding_categories: &[],
    },
    Control {
        framework: "OWASP MCP Top 10 (2026)",
        id: "MCP-SHADOW",
        title: "Shadow / cross-server tool conflicts",
        coverage: Coverage::Covered,
        how: "Correlates tool names across probed servers (confused-deputy) and flags unregistered servers via the registry.",
        finding_categories: &["Registry"],
    },
    Control {
        framework: "OWASP MCP Top 10 (2026)",
        id: "MCP-RUGPULL",
        title: "Rug-pull (post-trust mutation)",
        coverage: Coverage::Covered,
        how: "--diff flags a trusted MCP tool whose description or parameter schema changes between scans.",
        finding_categories: &[],
    },
    // ── EU AI Act ──
    Control {
        framework: "EU AI Act (inventory obligations, 2026-08)",
        id: "AI-INVENTORY",
        title: "Catalogue AI systems incl. third-party & embedded components",
        coverage: Coverage::Covered,
        how: "Produces a machine-level inventory of AI tools, MCP servers, skills, and models as JSON / CycloneDX SBOM / Blueprint — an auditable evidence artifact.",
        finding_categories: &[],
    },
    Control {
        framework: "EU AI Act (inventory obligations, 2026-08)",
        id: "AI-TRANSPARENCY",
        title: "Transparency of AI components in use",
        coverage: Coverage::Partial,
        how: "Inventories which AI tools/agents are present and running; does not assess model-level transparency obligations.",
        finding_categories: &[],
    },
    // ── Endpoint AI Agent Abuse (EAA) — the closest-fit framework: endpoint agent
    // abuse specifically. Catalog by 0x4D31 (CC0). ──
    Control {
        framework: "Endpoint AI Agent Abuse (EAA, CC0)",
        id: "EAA-002",
        title: "Permissive or unattended agent execution",
        coverage: Coverage::Partial,
        how: "Flags bypassPermissions mode in settings; runtime invocation flags are out of scope.",
        finding_categories: &["Permissions"],
    },
    Control {
        framework: "Endpoint AI Agent Abuse (EAA, CC0)",
        id: "EAA-003",
        title: "Lifecycle hook persistence",
        coverage: Coverage::Covered,
        how: "Parses settings hooks (shell commands run on agent events) and flags dangerous patterns.",
        finding_categories: &["Hook"],
    },
    Control {
        framework: "Endpoint AI Agent Abuse (EAA, CC0)",
        id: "EAA-004",
        title: "Persistent instruction or memory poisoning",
        coverage: Coverage::Covered,
        how: "Inventories + hashes rules/memory files; flags dangerous patterns; --diff catches cross-session tampering.",
        finding_categories: &["Rules file"],
    },
    Control {
        framework: "Endpoint AI Agent Abuse (EAA, CC0)",
        id: "EAA-005",
        title: "Agent transcript / conversation-state collection",
        coverage: Coverage::Covered,
        how: "Inventories transcript/history/session stores (Claude Code, Codex, Gemini) by existence, file count, size, and permissions — never content — and flags world-readable stores.",
        finding_categories: &["Transcript exposure"],
    },
    Control {
        framework: "Endpoint AI Agent Abuse (EAA, CC0)",
        id: "EAA-006",
        title: "MCP or tool configuration abuse",
        coverage: Coverage::Covered,
        how: "Inventories MCP configs, matches the threat catalog, verifies the registry, and (opt-in) probes servers.",
        finding_categories: &["Exposure", "Registry"],
    },
    Control {
        framework: "Endpoint AI Agent Abuse (EAA, CC0)",
        id: "EAA-007",
        title: "Hostile model/API gateway routing",
        coverage: Coverage::Covered,
        how: "Flags AI base-URL overrides (ANTHROPIC_BASE_URL, ...) in settings env blocks that point at non-official hosts (CVE-2026-21852 vector).",
        finding_categories: &["Gateway routing"],
    },
    Control {
        framework: "Endpoint AI Agent Abuse (EAA, CC0)",
        id: "EAA-009",
        title: "Remote plugin / marketplace hot-load",
        coverage: Coverage::Covered,
        how: "Inventories Claude Code plugin marketplaces (source, official-vs-third-party, plugin counts) and flags auto-updating third-party sources that hot-load unreviewed remote code.",
        finding_categories: &["Plugin marketplace"],
    },
    Control {
        framework: "Endpoint AI Agent Abuse (EAA, CC0)",
        id: "EAA-010",
        title: "MCP dynamic tool mutation / pushed context",
        coverage: Coverage::Covered,
        how: "--diff detects rug-pulls (a trusted tool's description/schema mutating between scans); cross-server shadowing is flagged in the Blueprint.",
        finding_categories: &[],
    },
    Control {
        framework: "Endpoint AI Agent Abuse (EAA, CC0)",
        id: "EAA-011",
        title: "Environment-expanded MCP activation",
        coverage: Coverage::Covered,
        how: "Flags enableAllProjectMcpServers (blanket project-MCP auto-approval).",
        finding_categories: &["MCP auto-approval"],
    },
    Control {
        framework: "Endpoint AI Agent Abuse (EAA, CC0)",
        id: "EAA-015",
        title: "Inherited authority abuse",
        coverage: Coverage::Partial,
        how: "Surfaces at-rest credentials and static-key vs OAuth/SPIFFE identity posture; runtime token use is out of scope.",
        finding_categories: &["Credential", "Agent identity"],
    },
];

/// A control assessed against a specific scan.
pub struct ControlAssessment {
    pub control: &'static Control,
    /// Count of findings (this scan) that relate to the control.
    pub finding_count: usize,
}

pub struct ComplianceReport {
    pub assessments: Vec<ControlAssessment>,
    pub covered: usize,
    pub partial: usize,
    pub out_of_scope: usize,
}

/// Assess every control against a scan.
pub fn assess(report: &ScanReport) -> ComplianceReport {
    let findings = collect_findings(report);
    let mut assessments = Vec::new();
    let (mut covered, mut partial, mut oos) = (0, 0, 0);
    for control in CONTROLS {
        match control.coverage {
            Coverage::Covered => covered += 1,
            Coverage::Partial => partial += 1,
            Coverage::OutOfScope => oos += 1,
        }
        let finding_count = findings
            .iter()
            .filter(|f| control.finding_categories.contains(&f.category.as_str()))
            .count();
        assessments.push(ControlAssessment {
            control,
            finding_count,
        });
    }
    ComplianceReport {
        assessments,
        covered,
        partial,
        out_of_scope: oos,
    }
}

/// Render a plain-text compliance-coverage report.
pub fn render(report: &ScanReport) -> String {
    let assessment = assess(report);
    let mut out = String::new();

    out.push_str("=== rmguard Compliance Coverage ===\n\n");
    out.push_str(&format!(
        "rmguard {} — {} on {}\n",
        report.agent_version, report.device.hostname, report.scan_timestamp_iso
    ));
    out.push_str(&format!(
        "{} covered · {} partial · {} out-of-scope, across {} controls\n\n",
        assessment.covered,
        assessment.partial,
        assessment.out_of_scope,
        CONTROLS.len()
    ));
    out.push_str(
        "NOTE: this is posture EVIDENCE (inventory + detection), not a compliance\n\
         attestation. \"covered\" means rmguard produces the evidence a control asks for;\n\
         it does not by itself make an organization compliant.\n\n",
    );

    // Group by framework, preserving catalog order.
    let mut current_framework = "";
    for a in &assessment.assessments {
        if a.control.framework != current_framework {
            current_framework = a.control.framework;
            out.push_str(&format!("── {} ──\n", current_framework));
        }
        out.push_str(&format!(
            "  [{:>12}] {}  {}\n",
            a.control.coverage.label(),
            a.control.id,
            a.control.title
        ));
        out.push_str(&format!("               {}\n", a.control.how));
        if a.finding_count > 0 {
            out.push_str(&format!(
                "               evidence: {} finding(s) on this machine\n",
                a.finding_count
            ));
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::*;

    /// The finding categories `collect_findings` can emit — control mappings must
    /// reference only these (guards against typos like "Rules File" vs "Rules file").
    const KNOWN_CATEGORIES: &[&str] = &[
        "Exposure", "Hook", "MCP auto-approval", "Permissions", "Credential",
        "Secret leak", "Secret exposure", "SSH key", "Rules file", "Toxic Flow",
        "Registry", "Agent identity", "Gateway routing", "MCP transport",
        "MCP scope", "MCP secret", "MCP command", "Transcript exposure",
        "Plugin marketplace",
    ];

    fn empty_report() -> ScanReport {
        // A minimal report; only the fields findings/assess touch need to be sane.
        serde_json::from_str(
            r#"{"agent_version":"t","scan_timestamp":0,"scan_timestamp_iso":"t",
            "device":{"hostname":"h","os_name":"o","os_version":"v","platform":"p",
            "kernel_version":"k","user_identity":"u","home_dir":"/h"},
            "ai_agents_and_tools":[],"ai_frameworks":[],"ide_installations":[],
            "ide_extensions":[],"mcp_configs":[],"node_package_managers":[],
            "shell_configs":[],"ssh_keys":[],"cloud_credentials":[],"container_tools":[],
            "notebook_servers":[],"browser_extensions":[],"package_config_audits":[],
            "rules_files":[],"agent_skills":[],
            "summary":{"ai_agents_and_tools_count":0,"ai_frameworks_count":0,
            "ide_installations_count":0,"ide_extensions_count":0,"mcp_configs_count":0,
            "mcp_servers_count":0,"node_package_managers_count":0,"shell_configs_count":0,
            "ssh_keys_count":0,"cloud_credentials_count":0,"container_tools_count":0,
            "notebook_servers_count":0,"browser_extensions_count":0,
            "package_config_audits_count":0,"rules_files_count":0,"agent_skills_count":0,
            "agent_settings_count":0,"agent_hooks_count":0,"ai_credentials_count":0,
            "env_files_count":0,"rules_file_findings_count":0,"exposure_findings_count":0,
            "transcript_stores_count":0,"marketplaces_count":0}}"#,
        )
        .unwrap()
    }

    #[test]
    fn every_mapped_category_is_a_real_finding_category() {
        for c in CONTROLS {
            for cat in c.finding_categories {
                assert!(
                    KNOWN_CATEGORIES.contains(cat),
                    "control {} references unknown finding category {:?}",
                    c.id, cat
                );
            }
        }
    }

    #[test]
    fn coverage_counts_sum_to_catalog_size() {
        let a = assess(&empty_report());
        assert_eq!(a.covered + a.partial + a.out_of_scope, CONTROLS.len());
        assert!(a.covered > 0 && a.partial > 0 && a.out_of_scope > 0, "honest mix of coverage");
    }

    #[test]
    fn findings_map_to_the_right_controls() {
        let mut r = empty_report();
        // An exposure -> ASI04 (supply chain); a rules-file finding -> ASI06 (memory).
        r.exposure_findings = vec![ExposureFinding {
            ecosystem: "npm".into(), name: "evil".into(), version: "1".into(),
            advisory: "x".into(), found_in: "/m".into(),
        }];
        r.rules_files = vec![RulesFile {
            path: "/r".into(), file_name: "R".into(), sha256: "h".into(), git_tracked: true,
            size_bytes: 1,
            findings: vec![RulesFileFinding { severity: "critical".into(), pattern: "p".into() }],
        }];
        let a = assess(&r);
        let count = |id: &str| a.assessments.iter().find(|x| x.control.id == id).unwrap().finding_count;
        assert!(count("ASI04") >= 1, "exposure evidences supply-chain");
        assert!(count("ASI06") >= 1, "rules finding evidences memory poisoning");
        assert_eq!(count("ASI07"), 0, "out-of-scope control has no evidence");
    }

    #[test]
    fn render_includes_frameworks_and_honesty_note() {
        let out = render(&empty_report());
        assert!(out.contains("NSA/CISA MCP Security CSI"));
        assert!(out.contains("EU AI Act"));
        assert!(out.contains("OWASP Agentic Applications"));
        assert!(out.contains("not a compliance\nattestation"), "must not overclaim compliance");
        assert!(out.contains("out-of-scope"), "honestly shows uncovered controls");
    }
}
