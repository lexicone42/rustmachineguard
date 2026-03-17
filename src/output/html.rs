use crate::models::ScanReport;

pub fn render(report: &ScanReport) -> String {
    use base64::Engine;
    let json = serde_json::to_string(report).unwrap_or_default();
    let json_b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Dev Machine Guard — Scan Report</title>
<style>
:root {{
    --bg: #0d1117;
    --card: #161b22;
    --border: #30363d;
    --text: #c9d1d9;
    --heading: #58a6ff;
    --accent: #f0883e;
    --green: #3fb950;
    --red: #f85149;
    --dim: #8b949e;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }}
h1 {{ color: var(--heading); margin-bottom: 0.5rem; }}
.subtitle {{ color: var(--dim); margin-bottom: 2rem; }}
.card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
.card h2 {{ color: var(--heading); font-size: 1.1rem; margin-bottom: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
table {{ width: 100%; border-collapse: collapse; }}
td, th {{ padding: 0.4rem 0.8rem; text-align: left; border-bottom: 1px solid var(--border); }}
th {{ color: var(--dim); font-weight: 600; font-size: 0.85rem; text-transform: uppercase; }}
.running {{ color: var(--green); }}
.not-running {{ color: var(--dim); }}
.warn {{ color: var(--red); font-weight: bold; }}
.count {{ color: var(--accent); font-weight: bold; }}
.dim {{ color: var(--dim); }}
.summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }}
.summary-item {{ text-align: center; }}
.summary-item .value {{ font-size: 2rem; color: var(--accent); font-weight: bold; }}
.summary-item .label {{ color: var(--dim); font-size: 0.85rem; }}
</style>
</head>
<body>
<h1>Dev Machine Guard</h1>
<p class="subtitle">{hostname} &mdash; {os} &mdash; {timestamp}</p>

<div class="card">
<h2>Summary</h2>
<div class="summary-grid">
{summary_items}
</div>
</div>

{sections}

<script>
// Raw scan data for programmatic access
window.__scanReport = JSON.parse(atob("{json_b64}"));
</script>
</body>
</html>"#,
        hostname = html_escape(&report.device.hostname),
        os = html_escape(&format!("{} {}", report.device.os_name, report.device.os_version)),
        timestamp = html_escape(&report.scan_timestamp_iso),
        summary_items = render_summary(&report.summary),
        sections = render_sections(report),
        json_b64 = json_b64,
    )
}

fn render_summary(s: &crate::models::Summary) -> String {
    let items = [
        ("AI Agents & Tools", s.ai_agents_and_tools_count),
        ("AI Frameworks", s.ai_frameworks_count),
        ("IDE Installations", s.ide_installations_count),
        ("IDE Extensions", s.ide_extensions_count),
        ("MCP Configs", s.mcp_configs_count),
        ("Package Managers", s.node_package_managers_count),
        ("Shell Configs", s.shell_configs_count),
        ("SSH Keys", s.ssh_keys_count),
        ("Cloud Credentials", s.cloud_credentials_count),
        ("Container Tools", s.container_tools_count),
        ("Notebooks", s.notebook_servers_count),
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

fn render_sections(report: &ScanReport) -> String {
    let mut html = String::new();

    // AI Tools
    if !report.ai_agents_and_tools.is_empty() {
        html.push_str(r#"<div class="card"><h2>AI Agents &amp; Tools</h2><table><tr><th>Name</th><th>Vendor</th><th>Type</th><th>Version</th><th>Status</th></tr>"#);
        for t in &report.ai_agents_and_tools {
            let status = if t.is_running { r#"<span class="running">● running</span>"# } else { r#"<span class="not-running">○</span>"# };
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{:?}</td><td class=\"dim\">{}</td><td>{}</td></tr>",
                html_escape(&t.name), html_escape(&t.vendor), t.tool_type,
                html_escape(t.version.as_deref().unwrap_or("-")), status
            ));
        }
        html.push_str("</table></div>");
    }

    // AI Frameworks
    if !report.ai_frameworks.is_empty() {
        html.push_str(r#"<div class="card"><h2>AI Frameworks</h2><table><tr><th>Name</th><th>Vendor</th><th>Version</th><th>Status</th></tr>"#);
        for fw in &report.ai_frameworks {
            let status = if fw.is_running { r#"<span class="running">● running</span>"# } else { r#"<span class="not-running">○</span>"# };
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td class=\"dim\">{}</td><td>{}</td></tr>",
                html_escape(&fw.name), html_escape(&fw.vendor),
                html_escape(fw.version.as_deref().unwrap_or("-")), status
            ));
        }
        html.push_str("</table></div>");
    }

    // IDEs
    if !report.ide_installations.is_empty() {
        html.push_str(r#"<div class="card"><h2>IDE Installations</h2><table><tr><th>IDE</th><th>Vendor</th><th>Version</th><th>Path</th></tr>"#);
        for ide in &report.ide_installations {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td class=\"dim\">{}</td><td class=\"dim\">{}</td></tr>",
                html_escape(&ide.ide_type), html_escape(&ide.vendor),
                html_escape(ide.version.as_deref().unwrap_or("-")), html_escape(&ide.install_path)
            ));
        }
        html.push_str("</table></div>");
    }

    // MCP
    if !report.mcp_configs.is_empty() {
        html.push_str(r#"<div class="card"><h2>MCP Configurations</h2><table><tr><th>Source</th><th>Vendor</th><th>Servers</th><th>Server Names</th></tr>"#);
        for mcp in &report.mcp_configs {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td class=\"count\">{}</td><td class=\"dim\">{}</td></tr>",
                html_escape(&mcp.config_source), html_escape(&mcp.vendor),
                mcp.server_count, html_escape(&mcp.server_names.join(", "))
            ));
        }
        html.push_str("</table></div>");
    }

    // SSH Keys
    if !report.ssh_keys.is_empty() {
        html.push_str(r#"<div class="card"><h2>SSH Keys</h2><table><tr><th>Path</th><th>Type</th><th>Passphrase</th><th>Comment</th></tr>"#);
        for key in &report.ssh_keys {
            let pp = if key.has_passphrase {
                r#"<span class="running">encrypted</span>"#
            } else {
                r#"<span class="warn">NO PASSPHRASE</span>"#
            };
            html.push_str(&format!(
                "<tr><td class=\"dim\">{}</td><td>{}</td><td>{}</td><td class=\"dim\">{}</td></tr>",
                html_escape(&key.path), html_escape(&key.key_type), pp,
                html_escape(key.comment.as_deref().unwrap_or("-"))
            ));
        }
        html.push_str("</table></div>");
    }

    // Cloud Credentials
    if !report.cloud_credentials.is_empty() {
        html.push_str(r#"<div class="card"><h2>Cloud Credentials</h2><table><tr><th>Provider</th><th>Type</th><th>Profiles</th></tr>"#);
        for cred in &report.cloud_credentials {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td class=\"dim\">{}</td></tr>",
                html_escape(&cred.provider), html_escape(&cred.credential_type),
                html_escape(&cred.profiles.join(", "))
            ));
        }
        html.push_str("</table></div>");
    }

    // Container Tools
    if !report.container_tools.is_empty() {
        html.push_str(r#"<div class="card"><h2>Container Tools</h2><table><tr><th>Name</th><th>Version</th><th>Status</th></tr>"#);
        for ct in &report.container_tools {
            let status = if ct.is_running { r#"<span class="running">● running</span>"# } else { r#"<span class="not-running">○</span>"# };
            html.push_str(&format!(
                "<tr><td>{}</td><td class=\"dim\">{}</td><td>{}</td></tr>",
                html_escape(&ct.name), html_escape(ct.version.as_deref().unwrap_or("-")), status
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
