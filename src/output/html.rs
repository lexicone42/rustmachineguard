use crate::analysis::{collect_findings, Finding, Severity};
use crate::models::ScanReport;

pub fn render(report: &ScanReport) -> String {
    use base64::Engine;
    let json = serde_json::to_string(report).unwrap_or_default();
    let json_b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

    let findings = collect_findings(report);

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>rmguard — {hostname}</title>
<style>
:root {{
    --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9;
    --heading: #58a6ff; --accent: #f0883e; --green: #3fb950; --dim: #8b949e;
    --critical: #f85149; --high: #f0883e; --medium: #d29922; --low: #58a6ff;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; max-width: 1100px; margin: 0 auto; }}
h1 {{ color: var(--heading); margin-bottom: 0.25rem; font-size: 1.6rem; }}
.subtitle {{ color: var(--dim); margin-bottom: 1.5rem; }}
.card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
.card h2 {{ color: var(--heading); font-size: 1.1rem; margin-bottom: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
table {{ width: 100%; border-collapse: collapse; }}
td, th {{ padding: 0.4rem 0.8rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
th {{ color: var(--dim); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; }}
.running {{ color: var(--green); }} .not-running {{ color: var(--dim); }}
.warn {{ color: var(--critical); font-weight: bold; }} .count {{ color: var(--accent); font-weight: bold; }}
.dim {{ color: var(--dim); word-break: break-all; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; }}
.summary-item {{ text-align: center; }}
.summary-item .value {{ font-size: 1.8rem; color: var(--accent); font-weight: bold; }}
.summary-item .label {{ color: var(--dim); font-size: 0.8rem; }}
/* Risk banner */
.risk-banner {{ display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 1.5rem; }}
.pill {{ padding: 0.5rem 1rem; border-radius: 20px; font-weight: bold; font-size: 0.9rem; }}
.pill.zero {{ background: rgba(63,185,80,0.15); color: var(--green); border: 1px solid var(--green); }}
.pill.critical {{ background: rgba(248,81,73,0.15); color: var(--critical); border: 1px solid var(--critical); }}
.pill.high {{ background: rgba(240,136,62,0.15); color: var(--high); border: 1px solid var(--high); }}
.pill.medium {{ background: rgba(210,153,34,0.15); color: var(--medium); border: 1px solid var(--medium); }}
.pill.low {{ background: rgba(88,166,255,0.15); color: var(--low); border: 1px solid var(--low); }}
.finding {{ padding: 0.75rem 1rem; border-left: 4px solid var(--dim); background: rgba(255,255,255,0.02); margin-bottom: 0.5rem; border-radius: 0 4px 4px 0; }}
.finding.critical {{ border-color: var(--critical); }} .finding.high {{ border-color: var(--high); }}
.finding.medium {{ border-color: var(--medium); }} .finding.low {{ border-color: var(--low); }}
.finding .sev {{ font-size: 0.7rem; text-transform: uppercase; font-weight: bold; letter-spacing: 0.05em; }}
.finding.critical .sev {{ color: var(--critical); }} .finding.high .sev {{ color: var(--high); }}
.finding.medium .sev {{ color: var(--medium); }} .finding.low .sev {{ color: var(--low); }}
.finding .cat {{ color: var(--dim); font-size: 0.75rem; }}
.finding .title {{ margin: 0.15rem 0; }}
.finding .loc {{ color: var(--dim); font-size: 0.8rem; word-break: break-all; }}
.clean {{ padding: 1rem; color: var(--green); font-weight: bold; }}
</style>
</head>
<body>
<h1>rmguard — {hostname}</h1>
<p class="subtitle">{os} &mdash; scanned {timestamp} &mdash; rmguard {version}</p>

<div class="risk-banner">{risk_pills}</div>

<div class="card">
<h2>Security Findings</h2>
{findings}
</div>

<div class="card">
<h2>Inventory Summary</h2>
<div class="summary-grid">
{summary_items}
</div>
</div>

{sections}

<script>
// Full scan data for programmatic access (base64 to prevent injection)
window.__scanReport = JSON.parse(atob("{json_b64}"));
</script>
</body>
</html>"#,
        hostname = html_escape(&report.device.hostname),
        os = html_escape(&format!("{} {}", report.device.os_name, report.device.os_version)),
        timestamp = html_escape(&report.scan_timestamp_iso),
        version = html_escape(&report.agent_version),
        risk_pills = render_risk_pills(&findings),
        findings = render_findings(&findings),
        summary_items = render_summary(&report.summary),
        sections = render_sections(report),
        json_b64 = json_b64,
    )
}

fn count_sev(findings: &[Finding], sev: Severity) -> usize {
    findings.iter().filter(|f| f.severity == sev).count()
}

fn render_risk_pills(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return r#"<span class="pill zero">✓ No security findings</span>"#.to_string();
    }
    let mut pills = String::new();
    for (sev, class) in [
        (Severity::Critical, "critical"),
        (Severity::High, "high"),
        (Severity::Medium, "medium"),
        (Severity::Low, "low"),
    ] {
        let n = count_sev(findings, sev);
        if n > 0 {
            pills.push_str(&format!(
                r#"<span class="pill {class}">{n} {sev}</span>"#,
                sev = sev.label()
            ));
        }
    }
    pills
}

fn render_findings(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return r#"<div class="clean">✓ No actionable security findings on this machine.</div>"#
            .to_string();
    }
    let mut html = String::new();
    for f in findings {
        let class = f.severity.label();
        html.push_str(&format!(
            r#"<div class="finding {class}"><span class="sev">{sev}</span> <span class="cat">· {cat}</span><div class="title">{title}</div><div class="loc">{loc}</div></div>"#,
            sev = f.severity.label(),
            cat = html_escape(&f.category),
            title = html_escape(&f.title),
            loc = html_escape(&f.location),
        ));
    }
    html
}

fn render_summary(s: &crate::models::Summary) -> String {
    let items = [
        ("AI Agents & Tools", s.ai_agents_and_tools_count),
        ("AI Frameworks", s.ai_frameworks_count),
        ("IDE Extensions", s.ide_extensions_count),
        ("MCP Servers", s.mcp_servers_count),
        ("SSH Keys", s.ssh_keys_count),
        ("Cloud Credentials", s.cloud_credentials_count),
        ("Browser Extensions", s.browser_extensions_count),
        ("Rules Files", s.rules_files_count),
        ("Agent Skills", s.agent_skills_count),
        ("Agent Hooks", s.agent_hooks_count),
        ("AI Credentials", s.ai_credentials_count),
        (".env Files", s.env_files_count),
        ("Exposures", s.exposure_findings_count),
    ];
    items
        .iter()
        .map(|(label, count)| {
            format!(
                r#"<div class="summary-item"><div class="value">{count}</div><div class="label">{label}</div></div>"#,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Open a detail card with a header + table header row.
fn card_open(html: &mut String, title: &str, cols: &[&str]) {
    html.push_str(&format!(r#"<div class="card"><h2>{}</h2><table><tr>"#, html_escape(title)));
    for c in cols {
        html.push_str(&format!("<th>{}</th>", html_escape(c)));
    }
    html.push_str("</tr>");
}

fn render_sections(report: &ScanReport) -> String {
    let mut html = String::new();

    // Exposure findings — highest priority detail.
    if !report.exposure_findings.is_empty() {
        card_open(&mut html, "Threat Catalog Matches", &["Package", "Version", "Advisory", "Found In"]);
        for e in &report.exposure_findings {
            html.push_str(&format!(
                "<tr><td class=\"warn\">{}/{}</td><td>{}</td><td>{}</td><td class=\"dim\">{}</td></tr>",
                html_escape(&e.ecosystem), html_escape(&e.name), html_escape(&e.version),
                html_escape(&e.advisory), html_escape(&e.found_in)
            ));
        }
        html.push_str("</table></div>");
    }

    // Agent settings + hooks.
    if !report.agent_settings.is_empty() {
        card_open(&mut html, "Agent Settings & Hooks", &["File", "Source", "Mode", "Auto-approve", "Hooks"]);
        for s in &report.agent_settings {
            let auto = if s.auto_approve_mcp { r#"<span class="warn">yes</span>"# } else { "no" };
            let hooks = if s.hooks.is_empty() {
                "-".to_string()
            } else {
                s.hooks.iter().map(|h| {
                    let d = if h.dangerous { " ⚠" } else { "" };
                    format!("{}[{}]{}", html_escape(&h.event), html_escape(h.matcher.as_deref().unwrap_or("*")), d)
                }).collect::<Vec<_>>().join(", ")
            };
            html.push_str(&format!(
                "<tr><td class=\"dim\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&s.path), html_escape(&s.source),
                html_escape(s.permission_mode.as_deref().unwrap_or("-")), auto, hooks
            ));
        }
        html.push_str("</table></div>");
    }

    // AI credentials.
    if !report.ai_credentials.is_empty() {
        card_open(&mut html, "AI Credentials", &["Provider", "Type", "Perms", "Path"]);
        for c in &report.ai_credentials {
            let perm = if c.world_readable {
                format!(r#"<span class="warn">{} world-readable</span>"#, html_escape(c.permissions.as_deref().unwrap_or("?")))
            } else {
                html_escape(c.permissions.as_deref().unwrap_or("?"))
            };
            html.push_str(&format!(
                "<tr><td>{}</td><td class=\"dim\">{}</td><td>{}</td><td class=\"dim\">{}</td></tr>",
                html_escape(&c.provider), html_escape(&c.credential_type), perm, html_escape(&c.path)
            ));
        }
        html.push_str("</table></div>");
    }

    // .env files.
    if !report.env_files.is_empty() {
        card_open(&mut html, ".env Files", &["Path", "Keys", "Flags", "Secret keys"]);
        for e in &report.env_files {
            let mut flags = Vec::new();
            if e.git_tracked { flags.push(r#"<span class="warn">git-tracked</span>"#.to_string()); }
            if e.world_readable { flags.push(r#"<span class="warn">world-readable</span>"#.to_string()); }
            let flag_str = if flags.is_empty() { "-".to_string() } else { flags.join(", ") };
            html.push_str(&format!(
                "<tr><td class=\"dim\">{}</td><td>{}</td><td>{}</td><td class=\"dim\">{}</td></tr>",
                html_escape(&e.path), e.key_count, flag_str, html_escape(&e.secret_keys.join(", "))
            ));
        }
        html.push_str("</table></div>");
    }

    // Rules / memory files.
    if !report.rules_files.is_empty() {
        card_open(&mut html, "Rules & Memory Files", &["File", "Git", "Findings"]);
        for rf in &report.rules_files {
            let git = if rf.git_tracked { "tracked" } else { "untracked" };
            let findings = if rf.findings.is_empty() {
                "-".to_string()
            } else {
                rf.findings.iter().map(|f| format!("{}: {}", html_escape(&f.severity), html_escape(&f.pattern))).collect::<Vec<_>>().join("; ")
            };
            let cls = if rf.findings.is_empty() { "dim" } else { "warn" };
            html.push_str(&format!(
                "<tr><td class=\"dim\">{}</td><td>{}</td><td class=\"{}\">{}</td></tr>",
                html_escape(&rf.path), git, cls, findings
            ));
        }
        html.push_str("</table></div>");
    }

    // AI Tools.
    if !report.ai_agents_and_tools.is_empty() {
        card_open(&mut html, "AI Agents & Tools", &["Name", "Vendor", "Type", "Version", "Status"]);
        for t in &report.ai_agents_and_tools {
            let status = if t.is_running { r#"<span class="running">● running</span>"# } else { r#"<span class="not-running">○</span>"# };
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td class=\"dim\">{}</td><td>{}</td></tr>",
                html_escape(&t.name), html_escape(&t.vendor), html_escape(&format!("{:?}", t.tool_type)),
                html_escape(t.version.as_deref().unwrap_or("-")), status
            ));
        }
        html.push_str("</table></div>");
    }

    // MCP configs.
    if !report.mcp_configs.is_empty() {
        card_open(&mut html, "MCP Configurations", &["Source", "Vendor", "Servers", "Server Names"]);
        for mcp in &report.mcp_configs {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td class=\"count\">{}</td><td class=\"dim\">{}</td></tr>",
                html_escape(&mcp.config_source), html_escape(&mcp.vendor),
                mcp.server_count, html_escape(&mcp.server_names.join(", "))
            ));
        }
        html.push_str("</table></div>");
    }

    // SSH Keys.
    if !report.ssh_keys.is_empty() {
        card_open(&mut html, "SSH Keys", &["Path", "Type", "Passphrase", "Comment"]);
        for key in &report.ssh_keys {
            let pp = match key.has_passphrase {
                crate::models::PassphraseStatus::Encrypted => r#"<span class="running">encrypted</span>"#,
                crate::models::PassphraseStatus::NoPassphrase => r#"<span class="warn">NO PASSPHRASE</span>"#,
                crate::models::PassphraseStatus::Unknown => r#"<span class="warn">unknown</span>"#,
            };
            html.push_str(&format!(
                "<tr><td class=\"dim\">{}</td><td>{}</td><td>{}</td><td class=\"dim\">{}</td></tr>",
                html_escape(&key.path), html_escape(&key.key_type), pp,
                html_escape(key.comment.as_deref().unwrap_or("-"))
            ));
        }
        html.push_str("</table></div>");
    }

    // Cloud Credentials.
    if !report.cloud_credentials.is_empty() {
        card_open(&mut html, "Cloud Credentials", &["Provider", "Type", "Profiles"]);
        for cred in &report.cloud_credentials {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td class=\"dim\">{}</td></tr>",
                html_escape(&cred.provider), html_escape(&cred.credential_type),
                html_escape(&cred.profiles.join(", "))
            ));
        }
        html.push_str("</table></div>");
    }

    html
}

pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}
