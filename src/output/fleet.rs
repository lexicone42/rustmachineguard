//! Fleet aggregation: combine many per-machine JSON scans into one risk-first HTML
//! dashboard. Reads a directory of `--format json` outputs and ranks machines by the
//! severity of their findings so a team can see, at a glance, where to look first.

use crate::analysis::{collect_findings, Finding, Severity};
use crate::models::ScanReport;
use crate::output::html::html_escape;
use std::path::Path;

/// One machine's contribution to the fleet view.
struct MachineReport {
    hostname: String,
    os: String,
    timestamp: String,
    findings: Vec<Finding>,
}

impl MachineReport {
    fn count(&self, sev: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == sev).count()
    }
    /// Sort key: most critical machines first.
    fn rank(&self) -> (usize, usize, usize, usize) {
        (
            usize::MAX - self.count(Severity::Critical),
            usize::MAX - self.count(Severity::High),
            usize::MAX - self.count(Severity::Medium),
            usize::MAX - self.count(Severity::Low),
        )
    }
}

/// Read every `*.json` scan in `dir`, returning parsed reports and a list of files
/// that failed to parse (so the caller can warn rather than silently drop them).
pub fn load_reports_from_dir(dir: &Path) -> Result<(Vec<ScanReport>, Vec<String>), String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read directory {}: {}", dir.display(), e))?;

    let mut reports = Vec::new();
    let mut skipped = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            skipped.push(path.display().to_string());
            continue;
        };
        match serde_json::from_str::<ScanReport>(&content) {
            Ok(r) => reports.push(r),
            Err(_) => skipped.push(path.display().to_string()),
        }
    }
    Ok((reports, skipped))
}

/// Render a fleet dashboard HTML from a set of parsed scans.
pub fn render_fleet(reports: &[ScanReport]) -> String {
    let mut machines: Vec<MachineReport> = reports
        .iter()
        .map(|r| MachineReport {
            hostname: r.device.hostname.clone(),
            os: format!("{} {}", r.device.os_name, r.device.os_version),
            timestamp: r.scan_timestamp_iso.clone(),
            findings: collect_findings(r),
        })
        .collect();
    machines.sort_by_key(|m| m.rank());

    let total = |sev: Severity| machines.iter().map(|m| m.count(sev)).sum::<usize>();
    let (crit, high, med, low) = (
        total(Severity::Critical),
        total(Severity::High),
        total(Severity::Medium),
        total(Severity::Low),
    );
    let clean_machines = machines.iter().filter(|m| m.findings.is_empty()).count();

    let mut fleet_pills = String::new();
    for (n, class, label) in [
        (crit, "critical", "critical"),
        (high, "high", "high"),
        (med, "medium", "medium"),
        (low, "low", "low"),
    ] {
        if n > 0 {
            fleet_pills.push_str(&format!(r#"<span class="pill {class}">{n} {label}</span>"#));
        }
    }
    if crit + high + med + low == 0 {
        fleet_pills.push_str(r#"<span class="pill zero">✓ No findings across the fleet</span>"#);
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>rmguard — Fleet Report</title>
<style>
:root {{ --bg:#0d1117; --card:#161b22; --border:#30363d; --text:#c9d1d9; --heading:#58a6ff; --dim:#8b949e; --green:#3fb950; --critical:#f85149; --high:#f0883e; --medium:#d29922; --low:#58a6ff; }}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif; background:var(--bg); color:var(--text); padding:2rem; max-width:1100px; margin:0 auto; }}
h1 {{ color:var(--heading); margin-bottom:0.25rem; }} .subtitle {{ color:var(--dim); margin-bottom:1.5rem; }}
.card {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:1.5rem; margin-bottom:1.5rem; }}
.card h2 {{ color:var(--heading); font-size:1.1rem; margin-bottom:1rem; border-bottom:1px solid var(--border); padding-bottom:0.5rem; }}
table {{ width:100%; border-collapse:collapse; }}
td,th {{ padding:0.5rem 0.8rem; text-align:left; border-bottom:1px solid var(--border); font-size:0.9rem; }}
th {{ color:var(--dim); font-weight:600; font-size:0.8rem; text-transform:uppercase; }}
.dim {{ color:var(--dim); }} a {{ color:var(--heading); text-decoration:none; }} a:hover {{ text-decoration:underline; }}
.risk-banner {{ display:flex; gap:0.75rem; flex-wrap:wrap; margin-bottom:1.5rem; }}
.pill {{ padding:0.5rem 1rem; border-radius:20px; font-weight:bold; font-size:0.9rem; }}
.pill.zero {{ background:rgba(63,185,80,0.15); color:var(--green); border:1px solid var(--green); }}
.pill.critical {{ background:rgba(248,81,73,0.15); color:var(--critical); border:1px solid var(--critical); }}
.pill.high {{ background:rgba(240,136,62,0.15); color:var(--high); border:1px solid var(--high); }}
.pill.medium {{ background:rgba(210,153,34,0.15); color:var(--medium); border:1px solid var(--medium); }}
.pill.low {{ background:rgba(88,166,255,0.15); color:var(--low); border:1px solid var(--low); }}
.num {{ font-weight:bold; text-align:center; }} .num.critical {{ color:var(--critical); }} .num.high {{ color:var(--high); }} .num.medium {{ color:var(--medium); }} .num.zero {{ color:var(--green); }}
.finding {{ padding:0.6rem 1rem; border-left:4px solid var(--dim); background:rgba(255,255,255,0.02); margin-bottom:0.4rem; border-radius:0 4px 4px 0; }}
.finding.critical {{ border-color:var(--critical); }} .finding.high {{ border-color:var(--high); }} .finding.medium {{ border-color:var(--medium); }} .finding.low {{ border-color:var(--low); }}
.finding .sev {{ font-size:0.7rem; text-transform:uppercase; font-weight:bold; }} .finding.critical .sev {{ color:var(--critical); }} .finding.high .sev {{ color:var(--high); }} .finding.medium .sev {{ color:var(--medium); }} .finding.low .sev {{ color:var(--low); }}
.finding .loc {{ color:var(--dim); font-size:0.8rem; word-break:break-all; }}
.host {{ scroll-margin-top:1rem; }} .clean {{ color:var(--green); }}
</style></head><body>
<h1>rmguard — Fleet Report</h1>
<p class="subtitle">{n_machines} machines &mdash; {clean} clean &mdash; generated {now}</p>

<div class="risk-banner">{fleet_pills}</div>

<div class="card"><h2>Machines (most at-risk first)</h2>
<table><tr><th>Host</th><th>OS</th><th>Scanned</th><th>Critical</th><th>High</th><th>Medium</th></tr>
{machine_rows}
</table></div>

{machine_details}
</body></html>"#,
        n_machines = machines.len(),
        clean = clean_machines,
        now = html_escape(most_recent_timestamp(&machines)),
        fleet_pills = fleet_pills,
        machine_rows = render_machine_rows(&machines),
        machine_details = render_machine_details(&machines),
    )
}

fn most_recent_timestamp(machines: &[MachineReport]) -> &str {
    machines
        .iter()
        .map(|m| m.timestamp.as_str())
        .max()
        .unwrap_or("-")
}

fn num_cell(n: usize, class: &str) -> String {
    let cls = if n == 0 { "zero" } else { class };
    format!(r#"<td class="num {cls}">{n}</td>"#)
}

fn render_machine_rows(machines: &[MachineReport]) -> String {
    let mut out = String::new();
    for m in machines {
        let anchor = anchor_id(&m.hostname);
        out.push_str(&format!(
            r##"<tr><td><a href="#{anchor}">{host}</a></td><td class="dim">{os}</td><td class="dim">{ts}</td>{c}{h}{md}</tr>"##,
            host = html_escape(&m.hostname),
            os = html_escape(&m.os),
            ts = html_escape(&m.timestamp),
            c = num_cell(m.count(Severity::Critical), "critical"),
            h = num_cell(m.count(Severity::High), "high"),
            md = num_cell(m.count(Severity::Medium), "medium"),
        ));
    }
    out
}

fn render_machine_details(machines: &[MachineReport]) -> String {
    let mut out = String::new();
    for m in machines {
        let anchor = anchor_id(&m.hostname);
        out.push_str(&format!(
            r#"<div class="card host" id="{anchor}"><h2>{host}</h2>"#,
            host = html_escape(&m.hostname)
        ));
        if m.findings.is_empty() {
            out.push_str(r#"<div class="clean">✓ No findings.</div>"#);
        } else {
            for f in &m.findings {
                out.push_str(&format!(
                    r#"<div class="finding {class}"><span class="sev">{sev}</span> · {cat}: {title}<div class="loc">{loc}</div></div>"#,
                    class = f.severity.label(),
                    sev = f.severity.label(),
                    cat = html_escape(&f.category),
                    title = html_escape(&f.title),
                    loc = html_escape(&f.location),
                ));
            }
        }
        out.push_str("</div>");
    }
    out
}

/// Stable, HTML-safe anchor id derived from a hostname.
fn anchor_id(hostname: &str) -> String {
    let s: String = hostname
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect();
    format!("host-{}", s)
}
