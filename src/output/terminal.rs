use crate::models::ScanReport;
use colored::Colorize;

pub fn render(report: &ScanReport) -> String {
    let mut out = String::new();

    // Header
    out.push_str(&format!(
        "\n{}\n",
        "╔══════════════════════════════════════════════════════════╗"
            .bold()
            .cyan()
    ));
    out.push_str(&format!(
        "{}\n",
        "║          Dev Machine Guard — Scan Report                ║"
            .bold()
            .cyan()
    ));
    out.push_str(&format!(
        "{}\n\n",
        "╚══════════════════════════════════════════════════════════╝"
            .bold()
            .cyan()
    ));

    // Device info
    section_header(&mut out, "Device Info");
    let d = &report.device;
    kv(&mut out, "Hostname", &d.hostname);
    kv(&mut out, "OS", &format!("{} {}", d.os_name, d.os_version));
    kv(&mut out, "Kernel", &d.kernel_version);
    kv(&mut out, "User", &d.user_identity);
    kv(&mut out, "Home", &d.home_dir);
    kv(&mut out, "Scanned at", &report.scan_timestamp_iso);
    out.push('\n');

    // Summary
    section_header(&mut out, "Summary");
    let s = &report.summary;
    summary_line(&mut out, "AI Agents & Tools", s.ai_agents_and_tools_count);
    summary_line(&mut out, "AI Frameworks", s.ai_frameworks_count);
    summary_line(&mut out, "IDE Installations", s.ide_installations_count);
    summary_line(&mut out, "IDE Extensions", s.ide_extensions_count);
    summary_line(&mut out, "MCP Configurations", s.mcp_configs_count);
    summary_line(&mut out, "Package Managers", s.node_package_managers_count);
    summary_line(&mut out, "Shell Configs (AI-related)", s.shell_configs_count);
    summary_line(&mut out, "SSH Keys", s.ssh_keys_count);
    summary_line(&mut out, "Cloud Credentials", s.cloud_credentials_count);
    summary_line(&mut out, "Container Tools", s.container_tools_count);
    summary_line(&mut out, "Notebook Servers", s.notebook_servers_count);
    summary_line(&mut out, "Browser Extensions", s.browser_extensions_count);
    summary_line(&mut out, "Package Config Audits", s.package_config_audits_count);
    summary_line(&mut out, "Rules Files", s.rules_files_count);
    summary_line(&mut out, "Agent Skills", s.agent_skills_count);
    summary_line(&mut out, "Agent Settings Files", s.agent_settings_count);
    summary_line(&mut out, "Agent Hooks", s.agent_hooks_count);
    summary_line(&mut out, "AI Credentials", s.ai_credentials_count);
    summary_line(&mut out, ".env Files", s.env_files_count);
    summary_line(&mut out, "Transcript Stores", s.transcript_stores_count);
    summary_line(&mut out, "MCP Servers (total)", s.mcp_servers_count);
    if s.rules_file_findings_count > 0 {
        out.push_str(&format!(
            "  {:>35}  {}\n",
            "Rules File Findings",
            s.rules_file_findings_count.to_string().red().bold()
        ));
    }
    if s.exposure_findings_count > 0 {
        out.push_str(&format!(
            "  {:>35}  {}\n",
            "Exposure Findings",
            s.exposure_findings_count.to_string().red().bold()
        ));
    }
    out.push('\n');

    // Risk Analysis — composition-level signals
    if let Some(tf) = crate::analysis::analyze_toxic_flow(report) {
        section_header(&mut out, "Risk Analysis");
        out.push_str(&format!(
            "  {} {}\n",
            "!".red().bold(),
            "Toxic-flow surface (lethal trifecta)".red().bold()
        ));
        out.push_str(&format!(
            "    The agent surface combines a sensitive-data {} with an exfiltration {}.\n",
            "source".yellow(),
            "sink".yellow()
        ));
        out.push_str(&format!(
            "    sources: {}\n",
            tf.sources.join(", ").yellow()
        ));
        out.push_str(&format!("    sinks:   {}\n", tf.sinks.join(", ").yellow()));
        out.push_str(
            "    Any prompt injection reaching the agent could read private data and exfiltrate it.\n",
        );
        out.push('\n');
    }

    // AI Agents & Tools
    if !report.ai_agents_and_tools.is_empty() {
        section_header(&mut out, "AI Agents & Tools");
        for tool in &report.ai_agents_and_tools {
            let status = if tool.is_running {
                " ●".green().to_string()
            } else {
                " ○".dimmed().to_string()
            };
            let version = tool
                .version
                .as_deref()
                .unwrap_or("unknown")
                .dimmed()
                .to_string();
            out.push_str(&format!(
                "  {} {} ({}) [{}]{}\n",
                "→".cyan(),
                tool.name.bold(),
                version,
                tool.vendor.dimmed(),
                status,
            ));
            if let Some(ref path) = tool.binary_path {
                out.push_str(&format!("    {}\n", path.dimmed()));
            }
        }
        out.push('\n');
    }

    // AI Frameworks
    if !report.ai_frameworks.is_empty() {
        section_header(&mut out, "AI Frameworks");
        for fw in &report.ai_frameworks {
            let status = if fw.is_running {
                " ●".green().to_string()
            } else {
                " ○".dimmed().to_string()
            };
            let version = fw
                .version
                .as_deref()
                .unwrap_or("unknown")
                .dimmed()
                .to_string();
            out.push_str(&format!(
                "  {} {} ({}) [{}]{}\n",
                "→".cyan(),
                fw.name.bold(),
                version,
                fw.vendor.dimmed(),
                status,
            ));
        }
        out.push('\n');
    }

    // IDE Installations
    if !report.ide_installations.is_empty() {
        section_header(&mut out, "IDE Installations");
        for ide in &report.ide_installations {
            let version = ide
                .version
                .as_deref()
                .unwrap_or("unknown")
                .dimmed()
                .to_string();
            out.push_str(&format!(
                "  {} {} ({}) [{}]\n",
                "→".cyan(),
                ide.ide_type.bold(),
                version,
                ide.vendor.dimmed(),
            ));
            out.push_str(&format!("    {}\n", ide.install_path.dimmed()));
        }
        out.push('\n');
    }

    // IDE Extensions
    if !report.ide_extensions.is_empty() {
        section_header(&mut out, &format!("IDE Extensions ({})", report.ide_extensions.len()));
        // Group by IDE
        let mut by_ide: std::collections::BTreeMap<&str, Vec<&crate::models::IdeExtension>> =
            std::collections::BTreeMap::new();
        for ext in &report.ide_extensions {
            by_ide.entry(&ext.ide_type).or_default().push(ext);
        }
        for (ide, exts) in &by_ide {
            out.push_str(&format!("  {} ({}):\n", ide.bold(), exts.len()));
            for ext in exts {
                out.push_str(&format!(
                    "    {} {}.{} {}\n",
                    "·".dimmed(),
                    ext.publisher.dimmed(),
                    ext.name,
                    ext.version.dimmed(),
                ));
            }
        }
        out.push('\n');
    }

    // MCP Configs
    if !report.mcp_configs.is_empty() {
        section_header(&mut out, "MCP Configurations");
        for mcp in &report.mcp_configs {
            out.push_str(&format!(
                "  {} {} ({} servers) [{}]\n",
                "→".cyan(),
                mcp.config_source.bold(),
                mcp.server_count.to_string().yellow(),
                mcp.vendor.dimmed(),
            ));
            out.push_str(&format!("    {}\n", mcp.config_path.dimmed()));
            if !mcp.servers.is_empty() {
                for server in &mcp.servers {
                    let pkg_info = match (&server.package_ecosystem, &server.package_name) {
                        (Some(eco), Some(name)) => {
                            let ver = server.package_version.as_deref().unwrap_or("*");
                            format!(" → {}:{} @ {}", eco, name, ver)
                        }
                        _ => String::new(),
                    };
                    out.push_str(&format!(
                        "    {} {} [{}]{}\n",
                        "·".dimmed(),
                        server.name,
                        server.transport.dimmed(),
                        pkg_info.yellow(),
                    ));
                }
            } else {
                for name in &mcp.server_names {
                    out.push_str(&format!("    {} {}\n", "·".dimmed(), name));
                }
            }
        }
        out.push('\n');
    }

    // Package Managers
    if !report.node_package_managers.is_empty() {
        section_header(&mut out, "Node.js / Package Managers");
        for pm in &report.node_package_managers {
            let version = pm
                .version
                .as_deref()
                .unwrap_or("unknown")
                .dimmed()
                .to_string();
            out.push_str(&format!(
                "  {} {} ({})\n",
                "→".cyan(),
                pm.name.bold(),
                version,
            ));
        }
        out.push('\n');
    }

    // Shell Configs
    if !report.shell_configs.is_empty() {
        section_header(&mut out, "Shell Configs (AI-related entries)");
        for cfg in &report.shell_configs {
            out.push_str(&format!(
                "  {} {} ({})\n",
                "→".cyan(),
                cfg.shell.bold(),
                cfg.config_path.dimmed(),
            ));
            for entry in &cfg.ai_related_entries {
                out.push_str(&format!("    {} {}\n", "·".dimmed(), entry.yellow()));
            }
        }
        out.push('\n');
    }

    // SSH Keys
    if !report.ssh_keys.is_empty() {
        section_header(&mut out, "SSH Keys");
        for key in &report.ssh_keys {
            let passphrase = match key.has_passphrase {
                crate::models::PassphraseStatus::Encrypted => "encrypted".green().to_string(),
                crate::models::PassphraseStatus::NoPassphrase => "NO PASSPHRASE".red().bold().to_string(),
                crate::models::PassphraseStatus::Unknown => "unknown".yellow().to_string(),
            };
            let comment = key
                .comment
                .as_deref()
                .map(|c| format!(" ({c})"))
                .unwrap_or_default();
            out.push_str(&format!(
                "  {} {} [{}] {}{}\n",
                "→".cyan(),
                key.path.dimmed(),
                key.key_type,
                passphrase,
                comment,
            ));
        }
        out.push('\n');
    }

    // Cloud Credentials
    if !report.cloud_credentials.is_empty() {
        section_header(&mut out, "Cloud Credentials");
        for cred in &report.cloud_credentials {
            out.push_str(&format!(
                "  {} {} — {}\n",
                "→".cyan(),
                cred.provider.bold(),
                cred.credential_type,
            ));
            out.push_str(&format!("    {}\n", cred.config_path.dimmed()));
            if !cred.profiles.is_empty() {
                out.push_str(&format!(
                    "    profiles: {}\n",
                    cred.profiles.join(", ")
                ));
            }
        }
        out.push('\n');
    }

    // Container Tools
    if !report.container_tools.is_empty() {
        section_header(&mut out, "Container Tools");
        for ct in &report.container_tools {
            let status = if ct.is_running {
                " ●".green().to_string()
            } else {
                " ○".dimmed().to_string()
            };
            let version = ct
                .version
                .as_deref()
                .unwrap_or("unknown")
                .dimmed()
                .to_string();
            out.push_str(&format!(
                "  {} {} ({}){}\n",
                "→".cyan(),
                ct.name.bold(),
                version,
                status,
            ));
        }
        out.push('\n');
    }

    // Notebook Servers
    if !report.notebook_servers.is_empty() {
        section_header(&mut out, "Notebook Servers");
        for ns in &report.notebook_servers {
            let status = if ns.is_running {
                " ●".green().to_string()
            } else {
                " ○".dimmed().to_string()
            };
            let version = ns
                .version
                .as_deref()
                .unwrap_or("unknown")
                .dimmed()
                .to_string();
            out.push_str(&format!(
                "  {} {} ({}){}\n",
                "→".cyan(),
                ns.name.bold(),
                version,
                status,
            ));
        }
        out.push('\n');
    }

    // Browser Extensions
    if !report.browser_extensions.is_empty() {
        section_header(&mut out, &format!("Browser Extensions ({})", report.browser_extensions.len()));
        let mut by_browser: std::collections::BTreeMap<&str, Vec<&crate::models::BrowserExtension>> =
            std::collections::BTreeMap::new();
        for ext in &report.browser_extensions {
            by_browser.entry(&ext.browser).or_default().push(ext);
        }
        for (browser, exts) in &by_browser {
            out.push_str(&format!("  {} ({}):\n", browser.bold(), exts.len()));
            for ext in exts {
                out.push_str(&format!(
                    "    {} {} {} [{}]\n",
                    "·".dimmed(),
                    ext.name,
                    ext.version.dimmed(),
                    ext.profile.dimmed(),
                ));
            }
        }
        out.push('\n');
    }

    // Package Config Audits
    if !report.package_config_audits.is_empty() {
        section_header(&mut out, "Package Config Audits");
        for audit in &report.package_config_audits {
            out.push_str(&format!(
                "  {} {} ({})\n",
                "→".cyan(),
                audit.manager.bold(),
                audit.config_path.dimmed(),
            ));
            for finding in &audit.findings {
                let severity_colored = match finding.severity.as_str() {
                    "critical" => finding.severity.red().bold().to_string(),
                    "high" => finding.severity.red().to_string(),
                    "medium" => finding.severity.yellow().to_string(),
                    _ => finding.severity.dimmed().to_string(),
                };
                out.push_str(&format!(
                    "    {} [{}] {}\n",
                    "!".red(),
                    severity_colored,
                    finding.description,
                ));
            }
        }
        out.push('\n');
    }

    // Rules Files
    if !report.rules_files.is_empty() {
        section_header(&mut out, &format!("Rules Files ({})", report.rules_files.len()));
        for rf in &report.rules_files {
            let git = if rf.git_tracked {
                "git-tracked".green().to_string()
            } else {
                "untracked".yellow().to_string()
            };
            out.push_str(&format!(
                "  {} {} ({} bytes) [{}]\n",
                "→".cyan(),
                rf.file_name.bold(),
                rf.size_bytes,
                git,
            ));
            out.push_str(&format!("    {}\n", rf.path.dimmed()));
            out.push_str(&format!("    sha256: {}\n", rf.sha256.dimmed()));
            for finding in &rf.findings {
                let severity_colored = match finding.severity.as_str() {
                    "critical" => finding.severity.red().bold().to_string(),
                    "high" => finding.severity.red().to_string(),
                    "medium" => finding.severity.yellow().to_string(),
                    _ => finding.severity.dimmed().to_string(),
                };
                out.push_str(&format!(
                    "    {} [{}] {}\n",
                    "!".red(),
                    severity_colored,
                    finding.pattern,
                ));
            }
        }
        out.push('\n');
    }

    // Agent Skills
    if !report.agent_skills.is_empty() {
        section_header(&mut out, &format!("Agent Skills ({})", report.agent_skills.len()));
        let mut by_framework: std::collections::BTreeMap<&str, Vec<&crate::models::AgentSkill>> =
            std::collections::BTreeMap::new();
        for skill in &report.agent_skills {
            by_framework.entry(&skill.framework).or_default().push(skill);
        }
        for (framework, skills) in &by_framework {
            out.push_str(&format!("  {} ({}):\n", framework.bold(), skills.len()));
            for skill in skills {
                let caps = if skill.capabilities.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", skill.capabilities.join(", ").yellow())
                };
                out.push_str(&format!(
                    "    {} {} ({}, {}){}  \n",
                    "·".dimmed(),
                    skill.name,
                    skill.scope.dimmed(),
                    skill.file_type.dimmed(),
                    caps,
                ));
            }
        }
        out.push('\n');
    }

    // Agent Settings (hooks + auto-approval)
    if !report.agent_settings.is_empty() {
        section_header(
            &mut out,
            &format!("Agent Settings ({})", report.agent_settings.len()),
        );
        for s in &report.agent_settings {
            let tracked = if s.git_tracked {
                " [git-tracked]".red().to_string()
            } else {
                String::new()
            };
            out.push_str(&format!(
                "  {} {} ({}){}\n",
                "→".bold(),
                s.path,
                s.source.dimmed(),
                tracked
            ));
            if let Some(ref mode) = s.permission_mode {
                let m = if mode == "bypassPermissions" {
                    mode.red().bold().to_string()
                } else {
                    mode.yellow().to_string()
                };
                out.push_str(&format!("    permission mode: {}\n", m));
            }
            if s.auto_approve_mcp {
                out.push_str(&format!(
                    "    {} enableAllProjectMcpServers (auto-approves project MCP servers)\n",
                    "!".red().bold()
                ));
            }
            for g in &s.gateway_overrides {
                if g.official {
                    out.push_str(&format!(
                        "    {} {} → {} (official)\n",
                        "·".dimmed(),
                        g.var.dimmed(),
                        g.host
                    ));
                } else {
                    out.push_str(&format!(
                        "    {} {} → {} {}\n",
                        "!".red().bold(),
                        g.var,
                        g.host.red(),
                        "(non-official gateway — EAA-007)".red()
                    ));
                }
            }
            for h in &s.hooks {
                let marker = if h.dangerous {
                    "!".red().bold().to_string()
                } else {
                    "·".dimmed().to_string()
                };
                let matcher = h.matcher.as_deref().unwrap_or("*");
                let cmd_preview: String = h.command.chars().take(70).collect();
                out.push_str(&format!(
                    "    {} hook {}[{}]: {}\n",
                    marker,
                    h.event.dimmed(),
                    matcher,
                    if h.dangerous {
                        cmd_preview.red().to_string()
                    } else {
                        cmd_preview
                    }
                ));
            }
        }
        out.push('\n');
    }

    // AI Credentials (at-rest tokens)
    if !report.ai_credentials.is_empty() {
        section_header(
            &mut out,
            &format!("AI Credentials ({})", report.ai_credentials.len()),
        );
        for c in &report.ai_credentials {
            let perm = c.permissions.as_deref().unwrap_or("?");
            let warn = if c.world_readable {
                " WORLD-READABLE".red().bold().to_string()
            } else if c.group_readable {
                " group-readable".yellow().to_string()
            } else {
                String::new()
            };
            out.push_str(&format!(
                "  {} {} — {} [{}]{}\n    {}\n",
                "→".bold(),
                c.provider,
                c.credential_type.dimmed(),
                perm,
                warn,
                c.path.dimmed()
            ));
        }
        out.push('\n');
    }

    // .env Files in agent project roots
    if !report.env_files.is_empty() {
        section_header(&mut out, &format!(".env Files ({})", report.env_files.len()));
        for e in &report.env_files {
            let mut flags = Vec::new();
            if e.git_tracked {
                flags.push("GIT-TRACKED".red().bold().to_string());
            }
            if e.world_readable {
                flags.push("world-readable".red().to_string());
            }
            let flag_str = if flags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", flags.join(", "))
            };
            out.push_str(&format!(
                "  {} {} ({} keys){}\n",
                "→".bold(),
                e.path,
                e.key_count,
                flag_str
            ));
            if !e.secret_keys.is_empty() {
                out.push_str(&format!(
                    "    secret-bearing keys: {}\n",
                    e.secret_keys.join(", ").yellow()
                ));
            }
        }
        out.push('\n');
    }

    // Agent transcript / conversation-state stores (EAA-005 collection surface)
    if !report.transcripts.is_empty() {
        section_header(
            &mut out,
            &format!("Transcript Stores ({})", report.transcripts.len()),
        );
        for t in &report.transcripts {
            let warn = if t.world_readable {
                " WORLD-READABLE".red().bold().to_string()
            } else {
                String::new()
            };
            out.push_str(&format!(
                "  {} {} — {} ({} files, {}){}\n    {}\n",
                "→".bold(),
                t.framework,
                t.kind.dimmed(),
                t.file_count,
                human_bytes(t.total_size_bytes).dimmed(),
                warn,
                t.path.dimmed()
            ));
        }
        out.push('\n');
    }

    // Agent Identity posture
    if let Some(id) = &report.agent_identity {
        use crate::identity::SpiffeStatus;
        // Only show the section if there's something to say.
        let spiffe_present = matches!(id.spiffe, SpiffeStatus::Present { .. });
        if !id.static_api_keys.is_empty() || !id.oauth_providers.is_empty() || spiffe_present {
            section_header(&mut out, "Agent Identity");
            if !id.static_api_keys.is_empty() {
                out.push_str(&format!(
                    "  static API keys:  {}  {}\n",
                    id.static_api_keys.join(", ").yellow(),
                    "(long-lived, unbound)".dimmed()
                ));
            }
            if !id.oauth_providers.is_empty() {
                out.push_str(&format!(
                    "  OAuth (better):   {}\n",
                    id.oauth_providers.join(", ").green()
                ));
            }
            match &id.spiffe {
                SpiffeStatus::Present { source } => out.push_str(&format!(
                    "  workload identity (SPIFFE): {} ({})\n",
                    "present".green(),
                    source.dimmed()
                )),
                SpiffeStatus::Absent => {
                    out.push_str(&format!("  workload identity (SPIFFE): {}\n", "absent".dimmed()))
                }
            }
            if id.static_only() {
                out.push_str(&format!(
                    "  {} Agents rely solely on static long-lived keys (OWASP ASI03).\n",
                    "!".red().bold()
                ));
                out.push_str(
                    "    Prefer short-lived scoped credentials (OAuth token exchange / SPIFFE SVID) where supported.\n",
                );
            }
            out.push('\n');
        }
    }

    // MCP Registry Verification
    if !report.mcp_registry_checks.is_empty() {
        use crate::registry::RegistryVerdict;
        section_header(
            &mut out,
            &format!("MCP Registry Verification ({})", report.mcp_registry_checks.len()),
        );
        for c in &report.mcp_registry_checks {
            let (mark, desc) = match &c.verdict {
                RegistryVerdict::Registered { publisher, deprecated: false } => (
                    "✓".green().to_string(),
                    format!("registered · publisher {}", publisher.dimmed()),
                ),
                RegistryVerdict::Registered { publisher, deprecated: true } => (
                    "!".red().bold().to_string(),
                    format!("{} · publisher {}", "DEPRECATED".red().bold(), publisher.dimmed()),
                ),
                RegistryVerdict::PossibleTyposquat { registered_as } => (
                    "!".red().bold().to_string(),
                    format!("{} of {}", "possible typosquat".red(), registered_as.dimmed()),
                ),
                RegistryVerdict::Unregistered => {
                    ("?".yellow().to_string(), "not in registry (unverified)".dimmed().to_string())
                }
                RegistryVerdict::NoPackageIdentity => {
                    ("·".dimmed().to_string(), "no package identity".dimmed().to_string())
                }
                RegistryVerdict::LookupFailed => {
                    ("·".dimmed().to_string(), "lookup failed".dimmed().to_string())
                }
            };
            out.push_str(&format!("  {} {} — {}\n", mark, c.server_name.bold(), desc));
        }
        out.push('\n');
    }

    // MCP Probe Results
    if !report.mcp_probes.is_empty() {
        section_header(&mut out, &format!("MCP Server Probes ({})", report.mcp_probes.len()));
        for probe in &report.mcp_probes {
            if probe.success {
                let info = probe
                    .server_info
                    .as_ref()
                    .map(|i| {
                        format!(
                            "{} {}",
                            i.name,
                            i.version.as_deref().unwrap_or("?")
                        )
                    })
                    .unwrap_or_else(|| "unknown".to_string());
                out.push_str(&format!(
                    "  {} {} ({})\n",
                    "✓".green().bold(),
                    probe.server_name.bold(),
                    info.dimmed()
                ));
                if !probe.tools.is_empty() {
                    out.push_str(&format!(
                        "    {} tools: {}\n",
                        probe.tools.len().to_string().yellow(),
                        probe
                            .tools
                            .iter()
                            .map(|t| t.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                if !probe.resources.is_empty() {
                    out.push_str(&format!(
                        "    {} resources: {}\n",
                        probe.resources.len().to_string().yellow(),
                        probe
                            .resources
                            .iter()
                            .map(|r| r.uri.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                if !probe.observed_capabilities.is_empty() {
                    out.push_str(&format!(
                        "    observed capabilities: {}\n",
                        probe.observed_capabilities.join(", ").cyan()
                    ));
                }
            } else {
                out.push_str(&format!(
                    "  {} {} — {}\n",
                    "✗".red().bold(),
                    probe.server_name.bold(),
                    probe.error.as_deref().unwrap_or("unknown error").red()
                ));
            }
        }
        out.push('\n');
    }

    // Exposure Findings
    if !report.exposure_findings.is_empty() {
        section_header(&mut out, &format!(
            "⚠ EXPOSURE FINDINGS ({}) ⚠",
            report.exposure_findings.len()
        ));
        for finding in &report.exposure_findings {
            out.push_str(&format!(
                "  {} {}:{} @ {} — {}\n",
                "✗".red().bold(),
                finding.ecosystem.red(),
                finding.name.red().bold(),
                finding.version.red(),
                finding.advisory.yellow(),
            ));
            out.push_str(&format!("    found in: {}\n", finding.found_in.dimmed()));
        }
        out.push('\n');
    }

    // Warnings
    if !report.warnings.is_empty() {
        section_header(&mut out, &format!("Warnings ({})", report.warnings.len()));
        for w in &report.warnings {
            out.push_str(&format!(
                "  {} [{}] {}\n",
                "⚠".yellow(),
                w.scanner.dimmed(),
                w.message.yellow(),
            ));
        }
        out.push('\n');
    }

    out.push_str(&format!(
        "{}\n",
        "Scan complete.".bold().green()
    ));

    out
}

fn section_header(out: &mut String, title: &str) {
    out.push_str(&format!(
        "  {}\n",
        format!("── {title} ──").bold().cyan()
    ));
}

fn kv(out: &mut String, key: &str, value: &str) {
    out.push_str(&format!(
        "  {:>14}  {}\n",
        key.dimmed(),
        value
    ));
}

fn summary_line(out: &mut String, label: &str, count: usize) {
    let count_str = if count > 0 {
        count.to_string().yellow().bold().to_string()
    } else {
        "0".dimmed().to_string()
    };
    out.push_str(&format!("  {:>35}  {}\n", label, count_str));
}

/// Human-readable byte size (e.g. "3.4 MB"). Base-1000 units.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut val = bytes as f64;
    let mut unit = 0;
    while val >= 1000.0 && unit < UNITS.len() - 1 {
        val /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.1} {}", val, UNITS[unit])
    }
}
