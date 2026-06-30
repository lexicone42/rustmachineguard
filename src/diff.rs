use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[derive(Debug)]
pub struct ScanDiff {
    pub sections: Vec<SectionDiff>,
    pub summary_changes: Vec<String>,
}

#[derive(Debug)]
pub struct SectionDiff {
    pub name: String,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<ChangedItem>,
}

#[derive(Debug)]
pub struct ChangedItem {
    pub name: String,
    pub changes: Vec<String>,
}

impl ScanDiff {
    pub fn is_empty(&self) -> bool {
        self.sections.iter().all(|s| s.added.is_empty() && s.removed.is_empty() && s.changed.is_empty())
    }
}

pub fn diff_reports(baseline: &Value, current: &Value) -> ScanDiff {
    let mut sections = Vec::new();

    sections.push(diff_array_section(
        "MCP Servers",
        collect_mcp_servers(baseline),
        collect_mcp_servers(current),
        "name",
        &["transport", "package_name", "package_version", "package_ecosystem"],
    ));

    sections.push(diff_array_section(
        "AI Tools",
        get_array(baseline, "ai_agents_and_tools"),
        get_array(current, "ai_agents_and_tools"),
        "name",
        &["version", "is_running"],
    ));

    sections.push(diff_array_section(
        "IDE Extensions",
        get_array(baseline, "ide_extensions"),
        get_array(current, "ide_extensions"),
        "id",
        &["version"],
    ));

    sections.push(diff_array_section(
        "Browser Extensions",
        get_array(baseline, "browser_extensions"),
        get_array(current, "browser_extensions"),
        "id",
        &["version"],
    ));

    sections.push(diff_rules_files(
        get_array(baseline, "rules_files"),
        get_array(current, "rules_files"),
    ));

    sections.push(diff_skills(
        get_array(baseline, "agent_skills"),
        get_array(current, "agent_skills"),
    ));

    sections.push(diff_array_section(
        "SSH Keys",
        get_array(baseline, "ssh_keys"),
        get_array(current, "ssh_keys"),
        "path",
        &["key_type", "has_passphrase"],
    ));

    sections.push(diff_array_section(
        "Cloud Credentials",
        get_array(baseline, "cloud_credentials"),
        get_array(current, "cloud_credentials"),
        "config_path",
        &["provider", "credential_type"],
    ));

    sections.push(diff_array_section(
        "Exposure Findings",
        get_array(baseline, "exposure_findings"),
        get_array(current, "exposure_findings"),
        "name",
        &["ecosystem", "version", "advisory"],
    ));

    sections.push(diff_mcp_probes(
        get_array(baseline, "mcp_probes"),
        get_array(current, "mcp_probes"),
    ));

    let summary_changes = diff_summary(baseline, current);

    ScanDiff {
        sections,
        summary_changes,
    }
}

pub fn render_diff(diff: &ScanDiff) -> String {
    let mut out = String::new();

    if diff.is_empty() {
        out.push_str("No changes detected between baseline and current scan.\n");
        return out;
    }

    out.push_str("=== Scan Diff Report ===\n\n");

    for section in &diff.sections {
        if section.added.is_empty() && section.removed.is_empty() && section.changed.is_empty() {
            continue;
        }

        out.push_str(&format!("--- {} ---\n", section.name));

        for item in &section.added {
            out.push_str(&format!("  + {}\n", item));
        }
        for item in &section.removed {
            out.push_str(&format!("  - {}\n", item));
        }
        for item in &section.changed {
            out.push_str(&format!("  ~ {}\n", item.name));
            for change in &item.changes {
                out.push_str(&format!("      {}\n", change));
            }
        }

        out.push('\n');
    }

    if !diff.summary_changes.is_empty() {
        out.push_str("--- Summary ---\n");
        for change in &diff.summary_changes {
            out.push_str(&format!("  {}\n", change));
        }
        out.push('\n');
    }

    out
}

fn collect_mcp_servers(report: &Value) -> Vec<Value> {
    let configs = match report.get("mcp_configs").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Vec::new(),
    };

    let mut servers = Vec::new();
    for config in configs {
        let source = config
            .get("config_source")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        if let Some(svrs) = config.get("servers").and_then(|v| v.as_array()) {
            for s in svrs {
                let mut server = s.clone();
                if let Some(obj) = server.as_object_mut() {
                    obj.insert("config_source".into(), Value::String(source.into()));
                }
                servers.push(server);
            }
        }
    }
    servers
}

fn get_array(report: &Value, key: &str) -> Vec<Value> {
    report
        .get(key)
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

fn diff_array_section(
    name: &str,
    baseline: Vec<Value>,
    current: Vec<Value>,
    key_field: &str,
    compare_fields: &[&str],
) -> SectionDiff {
    // Use composite key (key_field + config_source/config_path if present) to
    // avoid collisions when multiple items share the same primary key.
    let composite_key = |v: &Value| -> Option<String> {
        let primary = v.get(key_field)?.as_str()?.to_string();
        let secondary = v
            .get("config_source")
            .or_else(|| v.get("config_path"))
            .and_then(|s| s.as_str());
        match secondary {
            Some(s) => Some(format!("{}|{}", primary, s)),
            None => Some(primary),
        }
    };

    let baseline_map: HashMap<String, &Value> = baseline
        .iter()
        .filter_map(|v| Some((composite_key(v)?, v)))
        .collect();

    let current_map: HashMap<String, &Value> = current
        .iter()
        .filter_map(|v| Some((composite_key(v)?, v)))
        .collect();

    let baseline_keys: HashSet<&String> = baseline_map.keys().collect();
    let current_keys: HashSet<&String> = current_map.keys().collect();

    let added: Vec<String> = current_keys
        .difference(&baseline_keys)
        .map(|k| format_item(current_map[*k], key_field, compare_fields))
        .collect();

    let removed: Vec<String> = baseline_keys
        .difference(&current_keys)
        .map(|k| format_item(baseline_map[*k], key_field, compare_fields))
        .collect();

    let mut changed = Vec::new();
    for key in baseline_keys.intersection(&current_keys) {
        let b = baseline_map[*key];
        let c = current_map[*key];
        let mut changes = Vec::new();

        for field in compare_fields {
            let bv = b.get(*field);
            let cv = c.get(*field);
            if bv != cv {
                changes.push(format!(
                    "{}: {} -> {}",
                    field,
                    display_value(bv),
                    display_value(cv)
                ));
            }
        }

        if !changes.is_empty() {
            changed.push(ChangedItem {
                name: (*key).clone(),
                changes,
            });
        }
    }

    SectionDiff {
        name: name.to_string(),
        added,
        removed,
        changed,
    }
}

fn diff_rules_files(baseline: Vec<Value>, current: Vec<Value>) -> SectionDiff {
    let key_field = "path";

    let baseline_map: HashMap<String, &Value> = baseline
        .iter()
        .filter_map(|v| Some((v.get(key_field)?.as_str()?.to_string(), v)))
        .collect();

    let current_map: HashMap<String, &Value> = current
        .iter()
        .filter_map(|v| Some((v.get(key_field)?.as_str()?.to_string(), v)))
        .collect();

    let baseline_keys: HashSet<&String> = baseline_map.keys().collect();
    let current_keys: HashSet<&String> = current_map.keys().collect();

    let added: Vec<String> = current_keys
        .difference(&baseline_keys)
        .map(|k| {
            let v = current_map[*k];
            let name = v.get("file_name").and_then(|v| v.as_str()).unwrap_or("?");
            format!("{} ({})", k, name)
        })
        .collect();

    let removed: Vec<String> = baseline_keys
        .difference(&current_keys)
        .map(|k| {
            let v = baseline_map[*k];
            let name = v.get("file_name").and_then(|v| v.as_str()).unwrap_or("?");
            format!("{} ({})", k, name)
        })
        .collect();

    let mut changed = Vec::new();
    for key in baseline_keys.intersection(&current_keys) {
        let b = baseline_map[*key];
        let c = current_map[*key];
        let mut changes = Vec::new();

        let b_hash = b.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
        let c_hash = c.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
        if b_hash != c_hash {
            changes.push(format!("CONTENT CHANGED: hash {} -> {}", b_hash, c_hash));
        }

        let b_tracked = b.get("git_tracked").and_then(|v| v.as_bool());
        let c_tracked = c.get("git_tracked").and_then(|v| v.as_bool());
        if b_tracked != c_tracked {
            changes.push(format!(
                "git_tracked: {} -> {}",
                display_value(b.get("git_tracked")),
                display_value(c.get("git_tracked"))
            ));
        }

        let b_findings = count_findings(b);
        let c_findings = count_findings(c);
        if b_findings != c_findings {
            changes.push(format!(
                "dangerous patterns: {} -> {}",
                b_findings, c_findings
            ));
        }

        if !changes.is_empty() {
            let name = c
                .get("file_name")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            changed.push(ChangedItem {
                name: format!("{} ({})", key, name),
                changes,
            });
        }
    }

    SectionDiff {
        name: "Rules Files".to_string(),
        added,
        removed,
        changed,
    }
}

fn diff_skills(baseline: Vec<Value>, current: Vec<Value>) -> SectionDiff {
    let key_field = "path";

    let baseline_map: HashMap<String, &Value> = baseline
        .iter()
        .filter_map(|v| Some((v.get(key_field)?.as_str()?.to_string(), v)))
        .collect();

    let current_map: HashMap<String, &Value> = current
        .iter()
        .filter_map(|v| Some((v.get(key_field)?.as_str()?.to_string(), v)))
        .collect();

    let baseline_keys: HashSet<&String> = baseline_map.keys().collect();
    let current_keys: HashSet<&String> = current_map.keys().collect();

    let added: Vec<String> = current_keys
        .difference(&baseline_keys)
        .map(|k| {
            let v = current_map[*k];
            let name = v.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let fw = v.get("framework").and_then(|v| v.as_str()).unwrap_or("?");
            let caps = get_string_array(v, "capabilities");
            if caps.is_empty() {
                format!("{} ({}/{})", k, fw, name)
            } else {
                format!("{} ({}/{}) [capabilities: {}]", k, fw, name, caps.join(", "))
            }
        })
        .collect();

    let removed: Vec<String> = baseline_keys
        .difference(&current_keys)
        .map(|k| {
            let v = baseline_map[*k];
            let name = v.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            format!("{} ({})", k, name)
        })
        .collect();

    let mut changed = Vec::new();
    for key in baseline_keys.intersection(&current_keys) {
        let b = baseline_map[*key];
        let c = current_map[*key];
        let mut changes = Vec::new();

        let b_hash = b.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
        let c_hash = c.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
        if b_hash != c_hash {
            changes.push(format!("CONTENT CHANGED: hash {} -> {}", b_hash, c_hash));
        }

        let b_caps: HashSet<String> = get_string_array(b, "capabilities").into_iter().collect();
        let c_caps: HashSet<String> = get_string_array(c, "capabilities").into_iter().collect();

        let gained: Vec<&String> = c_caps.difference(&b_caps).collect();
        let lost: Vec<&String> = b_caps.difference(&c_caps).collect();

        if !gained.is_empty() {
            changes.push(format!(
                "CAPABILITIES GAINED: {}",
                gained.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ));
        }
        if !lost.is_empty() {
            changes.push(format!(
                "capabilities lost: {}",
                lost.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ));
        }

        if !changes.is_empty() {
            let name = c.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            changed.push(ChangedItem {
                name: format!("{} ({})", key, name),
                changes,
            });
        }
    }

    SectionDiff {
        name: "Agent Skills".to_string(),
        added,
        removed,
        changed,
    }
}

/// Diff MCP live-probe results across scans. The headline signal is a RUG-PULL: an
/// MCP server that served a benign tool at first connect and later mutates that same
/// tool's description or parameter schema to inject hidden instructions — most clients
/// never re-confirm. Keyed by server_name, then by tool name.
fn diff_mcp_probes(baseline: Vec<Value>, current: Vec<Value>) -> SectionDiff {
    let key_field = "server_name";
    let baseline_map: HashMap<String, &Value> = baseline
        .iter()
        .filter_map(|v| Some((v.get(key_field)?.as_str()?.to_string(), v)))
        .collect();
    let current_map: HashMap<String, &Value> = current
        .iter()
        .filter_map(|v| Some((v.get(key_field)?.as_str()?.to_string(), v)))
        .collect();

    let baseline_keys: HashSet<&String> = baseline_map.keys().collect();
    let current_keys: HashSet<&String> = current_map.keys().collect();

    let added: Vec<String> = current_keys
        .difference(&baseline_keys)
        .map(|k| k.to_string())
        .collect();
    let removed: Vec<String> = baseline_keys
        .difference(&current_keys)
        .map(|k| k.to_string())
        .collect();

    let mut changed = Vec::new();
    for key in baseline_keys.intersection(&current_keys) {
        let b = baseline_map[*key];
        let c = current_map[*key];
        let mut changes = Vec::new();

        // Index tools by name -> fingerprint (description + canonical inputSchema).
        let b_tools = tool_fingerprints(b);
        let c_tools = tool_fingerprints(c);

        let b_names: HashSet<&String> = b_tools.keys().collect();
        let c_names: HashSet<&String> = c_tools.keys().collect();

        for added_tool in c_names.difference(&b_names) {
            changes.push(format!("tool added: {}", added_tool));
        }
        for removed_tool in b_names.difference(&c_names) {
            changes.push(format!("tool removed: {}", removed_tool));
        }
        // The rug-pull: a tool present in both whose fingerprint changed.
        for tool in b_names.intersection(&c_names) {
            let (b_desc, b_schema) = &b_tools[*tool];
            let (c_desc, c_schema) = &c_tools[*tool];
            if b_desc != c_desc {
                changes.push(format!("RUG-PULL: tool '{}' description changed", tool));
            }
            if b_schema != c_schema {
                changes.push(format!("RUG-PULL: tool '{}' parameter schema changed", tool));
            }
        }

        // Observed capability drift.
        let b_caps: HashSet<String> =
            get_string_array(b, "observed_capabilities").into_iter().collect();
        let c_caps: HashSet<String> =
            get_string_array(c, "observed_capabilities").into_iter().collect();
        let gained: Vec<&String> = c_caps.difference(&b_caps).collect();
        if !gained.is_empty() {
            changes.push(format!(
                "CAPABILITIES GAINED: {}",
                gained.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ));
        }

        if !changes.is_empty() {
            changed.push(ChangedItem {
                name: (*key).clone(),
                changes,
            });
        }
    }

    SectionDiff {
        name: "MCP Probes".to_string(),
        added,
        removed,
        changed,
    }
}

/// Map each probed tool's name to (description, canonical-inputSchema-string).
fn tool_fingerprints(probe: &Value) -> HashMap<String, (String, String)> {
    let mut map = HashMap::new();
    if let Some(tools) = probe.get("tools").and_then(|t| t.as_array()) {
        for t in tools {
            let Some(name) = t.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let desc = t
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string();
            // serde_json::to_string of a Value is stable for our purposes (object key
            // order is preserved from parsing); good enough to detect mutation.
            let schema = t
                .get("input_schema")
                .map(|s| s.to_string())
                .unwrap_or_default();
            map.insert(name.to_string(), (desc, schema));
        }
    }
    map
}

fn diff_summary(baseline: &Value, current: &Value) -> Vec<String> {
    let fields = [
        ("ai_agents_and_tools_count", "AI tools"),
        ("mcp_servers_count", "MCP servers"),
        ("ide_extensions_count", "IDE extensions"),
        ("browser_extensions_count", "browser extensions"),
        ("rules_files_count", "rules files"),
        ("agent_skills_count", "agent skills"),
        ("rules_file_findings_count", "dangerous patterns"),
        ("exposure_findings_count", "exposure findings"),
        ("ssh_keys_count", "SSH keys"),
        ("cloud_credentials_count", "cloud credentials"),
    ];

    let b_summary = baseline.get("summary");
    let c_summary = current.get("summary");

    let mut changes = Vec::new();
    for (field, label) in &fields {
        let bv = b_summary.and_then(|s| s.get(*field)).and_then(|v| v.as_i64()).unwrap_or(0);
        let cv = c_summary.and_then(|s| s.get(*field)).and_then(|v| v.as_i64()).unwrap_or(0);
        if bv != cv {
            let delta = cv - bv;
            let sign = if delta > 0 { "+" } else { "" };
            changes.push(format!("{}: {} -> {} ({}{})", label, bv, cv, sign, delta));
        }
    }
    changes
}

fn format_item(v: &Value, key_field: &str, fields: &[&str]) -> String {
    let key = v.get(key_field).and_then(|v| v.as_str()).unwrap_or("?");
    let details: Vec<String> = fields
        .iter()
        .filter_map(|f| {
            let val = v.get(*f)?;
            if val.is_null() {
                return None;
            }
            Some(format!("{}={}", f, display_value(Some(val))))
        })
        .collect();

    if details.is_empty() {
        key.to_string()
    } else {
        format!("{} ({})", key, details.join(", "))
    }
}

fn display_value(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "null".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(v) => v.to_string(),
    }
}

fn count_findings(v: &Value) -> usize {
    v.get("findings")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0)
}

fn get_string_array(v: &Value, field: &str) -> Vec<String> {
    v.get(field)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}
