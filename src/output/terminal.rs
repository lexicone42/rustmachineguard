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
    out.push('\n');

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
            for name in &mcp.server_names {
                out.push_str(&format!("    {} {}\n", "·".dimmed(), name));
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
            let passphrase = if key.has_passphrase {
                "encrypted".green().to_string()
            } else {
                "NO PASSPHRASE".red().bold().to_string()
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
