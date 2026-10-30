use crate::models::ScanReport;
use colored::Colorize;

/// A copy of the report in which no string can carry a control character: every string
/// value (and object key) has ESC, C0/C1 controls (newline included) and bidi/line
/// separators replaced with `?`. The terminal renderer works from this copy, so the only
/// escape sequences in its output are the colours it adds itself, and
/// [`scrub_terminal`] can tell the two apart. None if the report does not round-trip.
pub fn defanged(report: &ScanReport) -> Option<ScanReport> {
    let mut v = serde_json::to_value(report).ok()?;
    defang_value(&mut v);
    serde_json::from_value(v).ok()
}

fn bad_data_char(c: char) -> bool {
    (c.is_control() && c != '\t') || crate::scanners::is_display_hazard(c)
}

fn defang_str(s: &str) -> String {
    s.chars().map(|c| if bad_data_char(c) { '?' } else { c }).collect()
}

fn defang_value(v: &mut serde_json::Value) {
    use serde_json::Value;
    match v {
        Value::String(s) if s.chars().any(bad_data_char) => *s = defang_str(s),
        Value::Array(a) => a.iter_mut().for_each(defang_value),
        Value::Object(o) => {
            if o.keys().any(|k| k.chars().any(bad_data_char)) {
                let old = std::mem::take(o);
                for (k, val) in old {
                    o.insert(defang_str(&k), val);
                }
            }
            o.values_mut().for_each(defang_value);
        }
        _ => {}
    }
}

pub fn render(report: &ScanReport) -> String {
    match defanged(report) {
        Some(clean) => scrub_terminal(&render_inner(&clean)),
        // Unreachable in practice (the report is plain data); without the defanged copy no
        // escape sequence can be trusted, so colour is dropped with the rest.
        None => scrub_all(&render_inner(report)),
    }
}

fn render_inner(report: &ScanReport) -> String {
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
        "║                  rmguard — Scan Report                   ║"
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

    // Security findings, risk-first — the same ranked list the HTML and fleet reports
    // lead with. Without this the DEFAULT output was a pure inventory, so any finding
    // whose category has no inventory section of its own (Git autorun, Auto-run task,
    // Config integrity, …) was invisible to anyone who just ran `rmguard`: real High
    // findings existed in the analysis and the user was shown a clean report.
    let findings = crate::analysis::collect_findings(report);
    section_header(&mut out, &format!("Security Findings ({})", findings.len()));
    if findings.is_empty() {
        out.push_str(&format!("  {}\n", "✓ No actionable security findings.".green()));
    } else {
        for f in &findings {
            let sev = match f.severity {
                crate::analysis::Severity::Critical => f.severity.label().red().bold(),
                crate::analysis::Severity::High => f.severity.label().red(),
                crate::analysis::Severity::Medium => f.severity.label().yellow(),
                crate::analysis::Severity::Low => f.severity.label().blue(),
            };
            // Titles, locations and evidence carry attacker-chosen text (a skill directory
            // name, an extension id, a settings command). Every scanner is meant to
            // sanitize at extraction; this is the backstop, so a missed field still
            // cannot write ESC/OSC sequences or forge a line in the terminal.
            let clean = |s: &str| crate::scanners::sanitize_display(s, 4000);
            out.push_str(&format!(
                "  {} [{}] {} {}\n      {}\n",
                "!".bold(),
                sev,
                clean(&f.category).dimmed(),
                clean(&f.title),
                clean(&f.location).dimmed()
            ));
            if let Some(ev) = &f.evidence {
                out.push_str(&format!("      {} {}\n", "→".dimmed(), clean(ev).yellow()));
            }
        }
    }
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
    for (framework, n) in &s.agent_hooks_by_framework {
        out.push_str(&format!("  {:>35}  {}\n", format!("{framework} ·").dimmed(), n));
    }
    if s.agent_hooks_inactive_count > 0 {
        out.push_str(&format!(
            "  {:>35}  {}\n",
            "of which inactive (never run) ·".dimmed(),
            s.agent_hooks_inactive_count
        ));
    }
    if s.agent_settings_commands_count > 0 {
        out.push_str(&format!(
            "  {:>35}  {}\n",
            "of which settings commands ·".dimmed(),
            s.agent_settings_commands_count
        ));
    }
    summary_line(&mut out, "AI Credentials", s.ai_credentials_count);
    summary_line(&mut out, ".env Files", s.env_files_count);
    summary_line(&mut out, "Transcript Stores", s.transcript_stores_count);
    summary_line(&mut out, "Plugin Marketplaces", s.marketplaces_count);
    summary_line(&mut out, "Plugin LSP Servers", s.agent_lsp_servers_count);
    summary_line(&mut out, "MCP Servers (total)", s.mcp_servers_count);
    for (label, n) in [
        ("of which plugin servers ·", s.mcp_plugin_servers_count),
        ("of which claude.ai connectors ·", s.mcp_connectors_count),
        ("servers that have run per logs ·", report.mcp_observed_servers.len()),
    ] {
        if n > 0 {
            out.push_str(&format!("  {:>35}  {}\n", label.dimmed(), n));
        }
    }
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
        // Both legs from keywords in skill files only: the finding (when there is one) says
        // "based on skill-file mentions only" (f8aa2a1), and so does this heading.
        let mentions_only = if tf.server_backed() {
            ""
        } else {
            " (skill-file mentions only)"
        };
        out.push_str(&format!(
            "  {} {}{}\n",
            "!".red().bold(),
            "Toxic-flow surface (lethal trifecta)".red().bold(),
            mentions_only.yellow()
        ));
        out.push_str(&format!(
            "    The agent surface combines a sensitive-data {} with an exfiltration {}.\n",
            "source".yellow(),
            "sink".yellow()
        ));
        out.push_str(&format!("    sources: {}\n", tf.sources.join(", ").yellow()));
        out.push_str(&format!("    sinks:   {}\n", tf.sinks.join(", ").yellow()));
        for (cap, who) in &tf.contributors {
            out.push_str(&format!("    {} {}: {}\n", "·".dimmed(), cap, who));
        }
        out.push_str("    Any prompt injection reaching the agent could read private data and exfiltrate it.\n");
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
            let version = tool.version.as_deref().unwrap_or("unknown").dimmed().to_string();
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
            let version = fw.version.as_deref().unwrap_or("unknown").dimmed().to_string();
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
            let version = ide.version.as_deref().unwrap_or("unknown").dimmed().to_string();
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
                let platform = ext
                    .target_platform
                    .as_deref()
                    .map_or(String::new(), |p| format!(" [{p}]"));
                let obsolete = if ext.obsolete { " (obsolete, files on disk)" } else { "" };
                out.push_str(&format!(
                    "    {} {}.{} {}{}{}\n",
                    "·".dimmed(),
                    ext.publisher.dimmed(),
                    ext.name,
                    ext.version.dimmed(),
                    platform.dimmed(),
                    obsolete.dimmed(),
                ));
            }
        }
        out.push('\n');
    }

    // MCP Configs
    if !report.mcp_configs.is_empty() || !report.mcp_observed_servers.is_empty() {
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
                    let mut tags = Vec::new();
                    match server.enabled {
                        Some(true) => tags.push("enabled".to_string()),
                        Some(false) => tags.push("disabled (inactive)".to_string()),
                        None if server.awaits_approval => tags.push("awaits approval (inactive)".to_string()),
                        None => {}
                    }
                    if server.ever_connected {
                        tags.push("ever connected".to_string());
                    }
                    if let Some(u) = &server.unpinned {
                        tags.push(format!("unpinned: {u}"));
                    }
                    let tags = if tags.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", tags.join(", "))
                    };
                    out.push_str(&format!(
                        "    {} {} [{}]{}{}\n",
                        "·".dimmed(),
                        server.name,
                        server.transport.dimmed(),
                        pkg_info.yellow(),
                        tags.dimmed(),
                    ));
                    if let Some(url) = &server.url {
                        out.push_str(&format!("        url: {}\n", url.dimmed()));
                    }
                    for h in &server.headers {
                        out.push_str(&format!("        header {}\n", h.dimmed()));
                    }
                    for e in &server.env {
                        out.push_str(&format!("        env {}\n", e.dimmed()));
                    }
                }
            } else {
                for name in &mcp.server_names {
                    out.push_str(&format!("    {} {}\n", "·".dimmed(), name));
                }
            }
        }
        if !report.mcp_observed_servers.is_empty() {
            out.push_str(&format!(
                "  {} servers that have run per logs: {}\n",
                "→".cyan(),
                report.mcp_observed_servers.len().to_string().yellow()
            ));
            for o in &report.mcp_observed_servers {
                out.push_str(&format!(
                    "    {} {} ({} project(s)){}\n",
                    "·".dimmed(),
                    o.name,
                    o.projects,
                    if o.configured {
                        String::new()
                    } else {
                        " — not in any known config".yellow().to_string()
                    }
                ));
            }
        }
        out.push('\n');
    }

    // Package Managers
    if !report.node_package_managers.is_empty() {
        section_header(&mut out, "Node.js / Package Managers");
        for pm in &report.node_package_managers {
            let version = pm.version.as_deref().unwrap_or("unknown").dimmed().to_string();
            out.push_str(&format!("  {} {} ({})\n", "→".cyan(), pm.name.bold(), version,));
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
            let comment = key.comment.as_deref().map(|c| format!(" ({c})")).unwrap_or_default();
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
                out.push_str(&format!("    profiles: {}\n", cred.profiles.join(", ")));
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
            let version = ct.version.as_deref().unwrap_or("unknown").dimmed().to_string();
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
            let version = ns.version.as_deref().unwrap_or("unknown").dimmed().to_string();
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
        section_header(
            &mut out,
            &format!("Browser Extensions ({})", report.browser_extensions.len()),
        );
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
        // Memory files (Serena memories, Claude Code auto and subagent memory) run to
        // hundreds on a working machine: one line per kind for the clean ones (each is
        // still hashed in the JSON for --diff), in full only when one has a finding.
        let mut quiet: std::collections::BTreeMap<(&str, &str, &str), usize> = std::collections::BTreeMap::new();
        for rf in report
            .rules_files
            .iter()
            .filter(|r| r.kind.is_some() && r.findings.is_empty())
        {
            let key = (
                rf.kind.as_deref().unwrap_or(""),
                rf.framework.as_deref().unwrap_or(""),
                rf.scope.as_deref().unwrap_or(""),
            );
            *quiet.entry(key).or_default() += 1;
        }
        for rf in report
            .rules_files
            .iter()
            .filter(|r| r.kind.is_none() || !r.findings.is_empty())
        {
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
        for ((kind, framework, scope), n) in &quiet {
            out.push_str(&format!(
                "  {} {} {} {} file(s), {} scope, no findings (hashed; listed in --format json)\n",
                "→".cyan(),
                n,
                framework,
                kind,
                scope,
            ));
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
                if !skill.read_by.is_empty() {
                    out.push_str(&format!(
                        "      {} read by: {}\n",
                        "·".dimmed(),
                        skill.read_by.join(", ")
                    ));
                }
                for h in &skill.hooks {
                    let cmd: String = h.command.chars().take(70).collect();
                    out.push_str(&format!(
                        "      {} hook {}[{}]: {}\n",
                        "·".dimmed(),
                        h.event.dimmed(),
                        h.matcher.as_deref().unwrap_or("*"),
                        if h.dangerous { cmd.red().to_string() } else { cmd }
                    ));
                }
            }
        }
        out.push('\n');
    }

    // Agent Settings (hooks + auto-approval)
    if !report.agent_settings.is_empty() {
        section_header(&mut out, &format!("Agent Settings ({})", report.agent_settings.len()));
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
            if let Some(l) = &s.symlink {
                out.push_str(&format!("    {} symlink to {}, not read\n", "·".dimmed(), l.target));
            }
            if !s.read_by.is_empty() {
                out.push_str(&format!(
                    "    {} hooks also run by: {}\n",
                    "·".dimmed(),
                    s.read_by.join(", ")
                ));
            }
            if let Some(ref mode) = s.permission_mode {
                let m = if mode == "bypassPermissions" {
                    mode.red().bold().to_string()
                } else {
                    mode.yellow().to_string()
                };
                out.push_str(&format!("    permission mode: {}\n", m));
            }
            if s.disable_bypass_mode {
                out.push_str(&format!(
                    "    {} disableBypassPermissionsMode (bypass mode is disabled by policy)\n",
                    "✓".green()
                ));
            }
            if s.auto_mode.as_ref().and_then(|a| a.classify_all_shell) == Some(true) {
                out.push_str(&format!(
                    "    {} autoMode.classifyAllShell (in auto mode the classifier reviews every shell command)\n",
                    "✓".green()
                ));
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
                let matcher = match &h.condition {
                    Some(c) => format!("{} if {c}", h.matcher.as_deref().unwrap_or("*")),
                    None => h.matcher.as_deref().unwrap_or("*").to_string(),
                };
                let cmd_preview: String = h.command.chars().take(70).collect();
                let kind = if h.kind.is_empty() || h.kind == "command" {
                    String::new()
                } else {
                    format!(" ({})", h.kind)
                };
                let plugin = match s.provenance.as_ref() {
                    Some(pr) if pr.plugin.is_some() && pr.marketplace.is_some() => {
                        let off = if pr.active { "" } else { ", inactive" };
                        format!(
                            " [plugin {}@{}{off}]",
                            pr.plugin.as_deref().unwrap_or(""),
                            pr.marketplace.as_deref().unwrap_or("")
                        )
                        .dimmed()
                        .to_string()
                    }
                    _ => String::new(),
                };
                let off = match (h.disabled, &h.disabled_reason) {
                    (true, Some(r)) => format!(" (disabled: {r})").dimmed().to_string(),
                    (true, None) => " (disabled)".dimmed().to_string(),
                    _ => String::new(),
                };
                let regs = if h.registers.is_empty() {
                    String::new()
                } else {
                    format!(" registers=[{}]", h.registers.join(", ")).dimmed().to_string()
                };
                out.push_str(&format!(
                    "    {} hook {}[{}]{}{}{}{}: {}\n",
                    marker,
                    h.event.dimmed(),
                    matcher,
                    kind,
                    plugin,
                    off,
                    regs,
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
        section_header(&mut out, &format!("AI Credentials ({})", report.ai_credentials.len()));
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
        section_header(&mut out, &format!("Transcript Stores ({})", report.transcripts.len()));
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
            // Secret-shaped content, by name and label only (never a value).
            let s = &t.secret_shapes;
            if s.files_sampled > 0 {
                let mut line = format!(
                    "mentions {} secret-named key{} ({} file{} sampled{})",
                    s.secret_key_names.len(),
                    if s.secret_key_names.len() == 1 { "" } else { "s" },
                    s.files_sampled,
                    if s.files_sampled == 1 { "" } else { "s" },
                    if s.sampling_truncated { ", sample truncated" } else { "" }
                );
                if !s.secret_key_names.is_empty() {
                    let shown: Vec<&str> = s.secret_key_names.iter().take(8).map(String::as_str).collect();
                    line.push_str(&format!(": {}", shown.join(", ")));
                    if s.secret_key_names.len() > 8 || s.secret_key_names_truncated {
                        line.push_str(" ...");
                    }
                }
                if !s.token_prefix_labels.is_empty() {
                    line.push_str(&format!(
                        "; token-shaped strings: {} ({})",
                        s.token_shaped_strings,
                        s.token_prefix_labels.join(", ")
                    ));
                }
                let line = if s.any() {
                    line.yellow().to_string()
                } else {
                    line.dimmed().to_string()
                };
                out.push_str(&format!("    {line}\n"));
            }
        }
        out.push('\n');
    }

    // Plugin marketplaces (remote code sources feeding the agent)
    if !report.marketplaces.is_empty() {
        section_header(
            &mut out,
            &format!("Plugin Marketplaces ({})", report.marketplaces.len()),
        );
        for m in &report.marketplaces {
            let mut flags = Vec::new();
            if !m.official {
                flags.push("third-party".yellow().to_string());
            }
            if m.auto_update {
                let s = "auto-update";
                flags.push(if m.official {
                    s.dimmed().to_string()
                } else {
                    s.red().to_string()
                });
            }
            let flag_str = if flags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", flags.join(", "))
            };
            out.push_str(&format!(
                "  {} {} — {} ({} plugins){}\n",
                "→".bold(),
                m.name,
                m.source_ref.dimmed(),
                m.installed_plugin_count,
                flag_str
            ));
        }
        out.push('\n');
    }

    out.push_str(&surfaces_section(report));

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
                SpiffeStatus::Absent => out.push_str(&format!("  workload identity (SPIFFE): {}\n", "absent".dimmed())),
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
                RegistryVerdict::Registered {
                    publisher,
                    deprecated: false,
                } => (
                    "✓".green().to_string(),
                    format!("registered · publisher {}", publisher.dimmed()),
                ),
                RegistryVerdict::Registered {
                    publisher,
                    deprecated: true,
                } => (
                    "!".red().bold().to_string(),
                    format!("{} · publisher {}", "DEPRECATED".red().bold(), publisher.dimmed()),
                ),
                RegistryVerdict::PossibleTyposquat { registered_as } => (
                    "!".red().bold().to_string(),
                    format!("{} of {}", "possible typosquat".red(), registered_as.dimmed()),
                ),
                RegistryVerdict::Unregistered => (
                    "?".yellow().to_string(),
                    "not in registry (unverified)".dimmed().to_string(),
                ),
                RegistryVerdict::NoPackageIdentity => {
                    ("·".dimmed().to_string(), "no package identity".dimmed().to_string())
                }
                RegistryVerdict::LookupFailed => ("·".dimmed().to_string(), "lookup failed".dimmed().to_string()),
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
                    .map(|i| format!("{} {}", i.name, i.version.as_deref().unwrap_or("?")))
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
        section_header(
            &mut out,
            &format!("⚠ EXPOSURE FINDINGS ({}) ⚠", report.exposure_findings.len()),
        );
        for finding in &report.exposure_findings {
            out.push_str(&format!(
                "  {} {}:{} @ {} — {}\n",
                "✗".red().bold(),
                finding.ecosystem.red(),
                finding.name.red().bold(),
                finding.version.red(),
                finding.advisory.yellow(),
            ));
            out.push_str(&format!(
                "    found in: {}{}\n",
                finding.found_in.dimmed(),
                root_label(finding).dimmed()
            ));
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

    out.push_str(&format!("{}\n", "Scan complete.".bold().green()));

    out
}

/// SGR parameters this renderer's colours produce (reset, bold, dim, italic, underline,
/// their resets, and the red..white / bright red..white foregrounds). Conceal (8),
/// black (30, 90) and every background are not among them.
fn renderer_sgr(params: &str) -> bool {
    params.split(';').all(|p| {
        p.is_empty()
            || p.parse::<u8>()
                .is_ok_and(|n| matches!(n, 0..=4 | 22..=24 | 31..=37 | 39 | 91..=97))
    })
}

/// The whole-report backstop. The report is rendered from a [`defanged`] copy, so data
/// cannot carry ESC; this still replaces every control character other than newline and
/// tab, every non-SGR escape sequence and every SGR sequence with a parameter the
/// renderer never emits (`ESC[8m` conceal, black on black) with `?`, plus bidi and line
/// separators.
pub fn scrub_terminal(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\u{1b}' && chars.get(i + 1) == Some(&'[') {
            let mut j = i + 2;
            while j < chars.len() && (chars[j].is_ascii_digit() || chars[j] == ';') {
                j += 1;
            }
            let params: String = chars[i + 2..j.min(chars.len())].iter().collect();
            if chars.get(j) == Some(&'m') && renderer_sgr(&params) {
                out.extend(&chars[i..=j]);
                i = j + 1;
                continue;
            }
        }
        let bad = (c.is_control() && c != '\n' && c != '\t') || crate::scanners::is_display_hazard(c);
        out.push(if bad { '?' } else { c });
        i += 1;
    }
    out
}

/// [`scrub_terminal`] with no escape sequence kept at all: for text with no colours
/// (`--diff`) or when the defanged copy could not be made.
pub fn scrub_all(s: &str) -> String {
    s.chars()
        .map(|c| {
            if (c.is_control() && c != '\n' && c != '\t') || (bad_data_char(c) && c != '\n') {
                '?'
            } else {
                c
            }
        })
        .collect()
}

fn section_header(out: &mut String, title: &str) {
    out.push_str(&format!("  {}\n", format!("── {title} ──").bold().cyan()));
}

fn kv(out: &mut String, key: &str, value: &str) {
    out.push_str(&format!("  {:>14}  {}\n", key.dimmed(), value));
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

/// The `--verbose` diagnostics table. Not part of the default report: it is for the
/// person asking "did the scanner actually look?", which is the question every
/// silent-zero bug in this project's history came down to.
pub fn render_diagnostics(report: &ScanReport) -> String {
    match defanged(report) {
        Some(clean) => scrub_terminal(&render_diagnostics_inner(&clean)),
        None => scrub_all(&render_diagnostics_inner(report)),
    }
}

fn render_diagnostics_inner(report: &ScanReport) -> String {
    let mut out = String::new();
    section_header(&mut out, "Scanner Diagnostics");
    out.push_str(&format!(
        "  {:<13} {:>7} {:>6} {:>8} {:>6}  {}\n",
        "scanner", "ms", "read", "missing", "items", "status"
    ));
    for d in &report.diagnostics {
        let status = if d.skipped {
            "skipped"
        } else if matches!(d.scanner.as_str(), "mcp-probe" | "registry") {
            // Process/network phases open no files; "no inputs" would mislead.
            "ran"
        } else if d.files_read == 0 && d.items == 0 {
            "no inputs"
        } else {
            "ok"
        };
        let root = d.root.as_deref().map(|r| format!("  ({r})")).unwrap_or_default();
        let partial = if d.truncated { " partial" } else { "" };
        out.push_str(&format!(
            "  {:<13} {:>7} {:>6} {:>8} {:>6}  {status}{partial}{root}\n",
            d.scanner, d.duration_ms, d.files_read, d.files_missing, d.items
        ));
    }
    out.push_str(
        "\n  \"no inputs\" = opened no files and produced nothing: either this machine has \
         none of what the scanner\n  looks for, or it is looking in the wrong place. Run with \
         --trace to see every path it tried.\n",
    );
    if report.diagnostics.iter().any(|d| d.truncated) {
        out.push_str(
            "  \"partial\" = walk budget reached; results for that scanner may be incomplete \
             (raise with --walk-budget).\n",
        );
    }
    out.push('\n');
    out
}

/// ` (uv-tool mistral-vibe)`: the install root an exposure was found in, when known.
fn root_label(f: &crate::models::ExposureFinding) -> String {
    match (f.root_kind, f.root_name.as_deref()) {
        (Some(k), Some(n)) => format!(" ({} {})", k.label(), crate::scanners::sanitize_display(n, 128)),
        (Some(k), None) => format!(" ({})", k.label()),
        _ => String::new(),
    }
}

/// The round-3b sections: plugin LSP servers, plugin versions and npx caches in use,
/// agent browser profiles and output directories, Mistral Vibe settings and settings
/// scripts. Fields are sanitized at capture.
fn surfaces_section(report: &ScanReport) -> String {
    let mut out = String::new();
    let v = &report.surfaces;
    if !v.agent_lsp_servers.is_empty() {
        section_header(&mut out, &format!("Plugin LSP Servers ({})", v.agent_lsp_servers.len()));
        for l in &v.agent_lsp_servers {
            let state = if l.enabled {
                "enabled".green().to_string()
            } else {
                "disabled".dimmed().to_string()
            };
            let unpinned = l
                .unpinned
                .as_deref()
                .map(|r| format!(" [unpinned: {r}]").yellow().to_string())
                .unwrap_or_default();
            out.push_str(&format!(
                "  {} {} — {} {} [{state}]{unpinned}\n",
                "→".bold(),
                l.plugin,
                l.name,
                format!("({} {})", l.program, l.args.join(" ")).trim_end().dimmed(),
            ));
        }
        out.push('\n');
    }
    if !v.plugin_versions_in_use.is_empty() || !v.npx_caches_running.is_empty() {
        section_header(&mut out, "Loaded By Running Sessions");
        for p in &v.plugin_versions_in_use {
            let stale = if p.stale_version {
                format!(
                    " [older than installed {}]",
                    p.installed_version.as_deref().unwrap_or("?")
                )
                .yellow()
                .to_string()
            } else {
                String::new()
            };
            out.push_str(&format!(
                "  {} {} {} — {} session(s){stale}\n",
                "→".bold(),
                p.plugin,
                p.version.dimmed(),
                p.in_use_by_sessions
            ));
        }
        for c in &v.npx_caches_running {
            out.push_str(&format!(
                "  {} npx cache {} — running ({} process(es))\n",
                "→".bold(),
                c.path.dimmed(),
                c.pids
            ));
        }
        out.push('\n');
    }
    if !v.agent_browser_profiles.is_empty() || !v.agent_output_dirs.is_empty() {
        section_header(&mut out, "Agent Browser State");
        for b in &v.agent_browser_profiles {
            out.push_str(&format!(
                "  {} {} profiles — {} ({} with cookies/logins, {} login file(s) readable by others)\n",
                "→".bold(),
                b.framework,
                b.path.dimmed(),
                b.login_profiles,
                b.readable_login_files
            ));
        }
        for d in &v.agent_output_dirs {
            let ignored = match d.ignored {
                Some(true) => "ignored".to_string(),
                Some(false) => "not ignored".to_string(),
                None if d.git_state_unknown > 0 => format!("git state unknown for {} file(s)", d.git_state_unknown),
                None => "ignore state unknown".to_string(),
            };
            out.push_str(&format!(
                "  {} {} output — {} ({} files, {} tracked, {ignored})\n",
                "→".bold(),
                d.framework,
                d.path.dimmed(),
                d.file_count,
                d.tracked_files
            ));
        }
        out.push('\n');
    }
    for c in &v.vibe_configs {
        section_header(&mut out, "Mistral Vibe");
        let flag = |b: Option<bool>| b.map_or("unset".to_string(), |b| b.to_string());
        out.push_str(&format!(
            "  {} {}\n    auto_approve {} · enable_auto_update {} · enable_telemetry {} · {} MCP server(s) · {} trusted folder(s)\n",
            "→".bold(),
            c.path.dimmed(),
            flag(c.auto_approve),
            flag(c.enable_auto_update),
            flag(c.enable_telemetry),
            c.mcp_server_count,
            c.trusted_folders.len()
        ));
        let always: Vec<&str> = c
            .tool_permissions
            .iter()
            .filter(|(_, p)| p.as_str() == "always")
            .map(|(t, _)| t.as_str())
            .collect();
        if !always.is_empty() {
            out.push_str(&format!("    tools that run without asking: {}\n", always.join(", ")));
        }
        out.push('\n');
    }
    if !v.agent_postures.is_empty() {
        section_header(
            &mut out,
            &format!(
                "Agent Settings: Cline, Roo Code, Continue, Aider, Goose, Zed, Junie, Amp, Warp ({})",
                v.agent_postures.len()
            ),
        );
        for p in &v.agent_postures {
            out.push_str(&format!(
                "  {} {} ({}) {}\n",
                "→".bold(),
                p.agent,
                p.scope,
                p.path.dimmed()
            ));
            for a in &p.auto_approve {
                let default = if a.default { " (default)" } else { "" };
                out.push_str(&format!(
                    "    runs without asking: {} = {} [{}]{default}\n",
                    a.setting, a.value, a.reach
                ));
            }
            if p.mcp_server_count > 0 {
                out.push_str(&format!(
                    "    {} MCP server(s), {} pre-approved tool(s)\n",
                    p.mcp_server_count, p.mcp_auto_approved_tools
                ));
            }
            for c in &p.auto_run_commands {
                out.push_str(&format!("    runs after edits: {c}\n"));
            }
            if !p.hook_files.is_empty() {
                out.push_str(&format!("    hooks: {}\n", p.hook_files.join(", ")));
            }
            for h in &p.hot_load_paths {
                out.push_str(&format!("    loads: {h}\n"));
            }
            for k in &p.key_files {
                out.push_str(&format!("    key file {} ({})\n", k.path, k.mode));
            }
            if let Some(l) = &p.symlink {
                out.push_str(&format!("    symlink, not read: {}\n", l.target));
            }
        }
        out.push('\n');
    }
    if !v.settings_command_scripts.is_empty() {
        section_header(&mut out, "Settings Command Scripts");
        for s in &v.settings_command_scripts {
            out.push_str(&format!(
                "  {} {} — {} ({}, {})\n",
                "→".bold(),
                s.setting,
                s.path.dimmed(),
                s.bin.format,
                s.bin.mode
            ));
        }
        out.push('\n');
    }
    if !v.authorized_keys.is_empty() {
        section_header(&mut out, "SSH Authorized Keys");
        for f in &v.authorized_keys {
            let state = if let Some(t) = &f.symlink {
                format!("symlink to {t}, not read")
            } else if f.unreadable {
                "unreadable".to_string()
            } else {
                format!("{} key(s)", f.key_count)
            };
            let mode = f.mode.as_deref().map_or(String::new(), |m| format!(", mode {m}"));
            out.push_str(&format!("  {} {} ({state}{mode})\n", "→".bold(), f.path.dimmed()));
            for k in &f.keys {
                let opts = if k.options.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", k.options.join(","))
                };
                let flag = if k.known_attacker_key.is_some() {
                    " KNOWN ATTACKER KEY".red().to_string()
                } else if k.backdoor_comment.is_some() {
                    " backdoor comment".red().to_string()
                } else {
                    String::new()
                };
                out.push_str(&format!(
                    "    {} {} {} {}{opts}{flag}\n",
                    "·".dimmed(),
                    k.key_type,
                    k.fingerprint.dimmed(),
                    k.comment.as_deref().unwrap_or("(no comment)"),
                ));
            }
        }
        out.push('\n');
    }
    if !v.network_listeners.is_empty() {
        section_header(&mut out, &format!("Network Listeners ({})", v.network_listeners.len()));
        for l in &v.network_listeners {
            let addr = if l.address.contains(':') {
                format!("[{}]:{}", l.address, l.port)
            } else {
                format!("{}:{}", l.address, l.port)
            };
            let bind = if l.bind.is_network_reachable() {
                l.bind.label().yellow().to_string()
            } else {
                l.bind.label().dimmed().to_string()
            };
            let who = match (&l.program, l.pid) {
                (Some(p), Some(pid)) => format!("{p} (pid {pid})"),
                (None, Some(pid)) => format!("pid {pid}"),
                _ => "no process of yours holds it".to_string(),
            };
            let age = l
                .age_days
                .map(|d| format!(", {d} day{}", if d == 1 { "" } else { "s" }))
                .unwrap_or_default();
            let shell = if l.serves_shell == crate::models::ServesShell::None {
                String::new()
            } else {
                format!(" [serves shell: {}]", l.serves_shell.label()).red().to_string()
            };
            let secrets = if l.readable_secret_files > 0 {
                format!(
                    " [{} world-readable .env with secret-named keys]",
                    l.readable_secret_files
                )
                .red()
                .to_string()
            } else {
                String::new()
            };
            out.push_str(&format!(
                "  {} {addr} {bind} — {who}{age}{shell}{secrets}\n",
                "→".bold()
            ));
            if let Some(p) = &l.project {
                out.push_str(&format!("      project {}\n", p.dimmed()));
            }
        }
        out.push('\n');
    }
    out
}
