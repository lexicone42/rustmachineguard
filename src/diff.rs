use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub struct ScanDiff {
    pub sections: Vec<SectionDiff>,
    pub summary_changes: Vec<String>,
    /// One line when the threat catalog the findings were matched against differs from
    /// the baseline's (see [`diff_catalog`]). Not an entry change: [`ScanDiff::is_empty`]
    /// ignores it, so it changes nothing but the output's first line.
    pub catalog_change: Option<String>,
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
        self.sections
            .iter()
            .all(|s| s.added.is_empty() && s.removed.is_empty() && s.changed.is_empty())
    }
}

pub fn diff_reports(baseline: &Value, current: &Value) -> ScanDiff {
    // A baseline written before synced-skill identifiers were masked carries them raw:
    // both sides are compared (and printed) masked, so such a baseline neither leaks
    // them into the diff nor reports every synced skill as removed and re-added.
    let (baseline, current) = (&mask_strings(baseline), &mask_strings(current));
    let sections = vec![
        diff_array_section(
            "MCP Servers",
            collect_mcp_servers(baseline),
            collect_mcp_servers(current),
            "name",
            // `url` distinguishes a plaintext downgrade (https -> http maps to the same
            // `transport`) and a redirect to a new host; `inline_secret_env_keys` and
            // `git_tracked` catch a trusted config gaining a committed credential.
            &[
                "transport",
                "package_name",
                "package_version",
                "package_ecosystem",
                "url",
                "inline_secret_env_keys",
                "git_tracked",
            ],
        ),
        diff_array_section(
            "AI Tools",
            get_array(baseline, "ai_agents_and_tools"),
            get_array(current, "ai_agents_and_tools"),
            "name",
            &["version", "is_running"],
        ),
        diff_array_section(
            "IDE Extensions",
            get_array(baseline, "ide_extensions"),
            get_array(current, "ide_extensions"),
            "id",
            &["version"],
        ),
        diff_array_section(
            "Browser Extensions",
            get_array(baseline, "browser_extensions"),
            get_array(current, "browser_extensions"),
            "id",
            &["version"],
        ),
        diff_rules_files(get_array(baseline, "rules_files"), get_array(current, "rules_files")),
        diff_skills(get_array(baseline, "agent_skills"), get_array(current, "agent_skills")),
        diff_array_section(
            "SSH Keys",
            get_array(baseline, "ssh_keys"),
            get_array(current, "ssh_keys"),
            "path",
            &["key_type", "has_passphrase"],
        ),
        diff_array_section(
            "Cloud Credentials",
            get_array(baseline, "cloud_credentials"),
            get_array(current, "cloud_credentials"),
            "config_path",
            &["provider", "credential_type"],
        ),
        diff_array_section(
            "Exposure Findings",
            get_array(baseline, "exposure_findings"),
            get_array(current, "exposure_findings"),
            "name",
            &["ecosystem", "version", "advisory"],
        ),
        diff_mcp_probes(get_array(baseline, "mcp_probes"), get_array(current, "mcp_probes")),
        // Agent settings are the persistence-tampering surface: a hook, a permission-mode
        // flip, a gateway override, or an inline secret appearing between scans is exactly
        // the kind of quiet change --diff exists to surface.
        diff_array_section(
            "Agent Settings",
            get_array(baseline, "agent_settings"),
            get_array(current, "agent_settings"),
            "path",
            &[
                "permission_mode",
                "auto_approve_mcp",
                "git_tracked",
                "hooks",
                "gateway_overrides",
                "inline_secret_env_keys",
                "helper_commands",
                "login_gateway",
                "provenance",
                // The hook-policy switches silence or unsilence every non-managed Claude
                // Code hook; serde defaults make an older baseline read false / empty.
                "allow_managed_hooks_only",
                "disable_all_hooks",
                "force_enabled_plugins",
            ],
        ),
        // Plugin marketplaces: a source flipping to auto-update, or a new third-party
        // source appearing, is remote-code-hot-load drift (EAA-009).
        diff_array_section(
            "Plugin Marketplaces",
            get_array(baseline, "marketplaces"),
            get_array(current, "marketplaces"),
            "name",
            &[
                "source_ref",
                "source_type",
                "auto_update",
                "official",
                "installed_plugin_count",
                "pin_issues",
            ],
        ),
        // A .env gaining an agent-home relocation or a gateway, and a profile or service
        // unit starting to bind Ollama beyond loopback, are drift like a new hook.
        diff_array_section(
            ".env Files",
            get_array(baseline, "env_files"),
            get_array(current, "env_files"),
            "path",
            &["git_tracked", "agent_overrides"],
        ),
        diff_array_section(
            "Shell Configs",
            get_array(baseline, "shell_configs"),
            get_array(current, "shell_configs"),
            "config_path",
            &["ollama_host"],
        ),
    ];

    let summary_changes = diff_summary(baseline, current);

    ScanDiff {
        sections,
        summary_changes,
        catalog_change: diff_catalog(baseline, current),
    }
}

/// The built-in catalog version of a report's `catalog` block, for display: `None` when
/// the report has no block (written before catalog versioning), else the version, or
/// `not loaded` (`--no-builtin-catalog`).
fn catalog_version(report: &Value) -> Option<String> {
    let block = report.get("catalog")?;
    Some(match block.get("builtin_version") {
        Some(Value::String(v)) => v.clone(),
        None | Some(Value::Null) => "not loaded".to_string(),
        Some(_) => "unrecognized".to_string(),
    })
}

/// One line when the threat catalog changed between the baseline and this scan, since
/// exposure findings can then appear or vanish with nothing changed on the machine.
/// A baseline without a `catalog` block predates catalog versioning; when neither
/// report has one there is nothing to compare.
fn diff_catalog(baseline: &Value, current: &Value) -> Option<String> {
    let cur = catalog_version(current)?;
    match catalog_version(baseline) {
        None => Some("threat catalog: baseline predates catalog versioning".to_string()),
        Some(base) if base != cur => Some(format!(
            "threat catalog: {base} -> {cur} (findings may change without any change on this machine)"
        )),
        Some(_) => None,
    }
}

/// `value` with [`crate::scanners::mask_identifiers`] applied to every string in it
/// (object keys included).
fn mask_strings(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(crate::scanners::mask_identifiers(s).into_owned()),
        Value::Array(a) => Value::Array(a.iter().map(mask_strings).collect()),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, v)| (crate::scanners::mask_identifiers(k).into_owned(), mask_strings(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

pub fn render_diff(diff: &ScanDiff) -> String {
    let mut out = String::new();

    // First, before any entry: the baseline's version string is file text, so it is
    // sanitized like every other line from a baseline.
    if let Some(line) = &diff.catalog_change {
        out.push_str(&crate::scanners::sanitize_display(line, 400));
        out.push_str("\n\n");
    }

    if diff.is_empty() {
        out.push_str("No changes detected between baseline and current scan.\n");
        return crate::output::terminal::scrub_all(&out);
    }

    out.push_str("=== Scan Diff Report ===\n\n");

    for section in &diff.sections {
        if section.added.is_empty() && section.removed.is_empty() && section.changed.is_empty() {
            continue;
        }

        out.push_str(&format!("--- {} ---\n", section.name));

        // Item names and change lines carry report text (paths, names, commands) from
        // the current scan and from a baseline file: each is sanitized so no ESC/OSC
        // sequence or newline reaches the terminal, and the whole output is scrubbed.
        let clean = |s: &str| crate::scanners::sanitize_display(s, 4000);
        for item in &section.added {
            out.push_str(&format!("  + {}\n", clean(item)));
        }
        for item in &section.removed {
            out.push_str(&format!("  - {}\n", clean(item)));
        }
        for item in &section.changed {
            out.push_str(&format!("  ~ {}\n", clean(&item.name)));
            for change in &item.changes {
                out.push_str(&format!("      {}\n", clean(change)));
            }
        }

        out.push('\n');
    }

    if !diff.summary_changes.is_empty() {
        out.push_str("--- Summary ---\n");
        for change in &diff.summary_changes {
            out.push_str(&format!("  {}\n", crate::scanners::sanitize_display(change, 4000)));
        }
        out.push('\n');
    }

    crate::output::terminal::scrub_all(&out)
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

/// Fields that tell apart rows sharing a diff key: one extension id installed for two
/// IDEs or browser profiles, one vulnerable package found in two projects, one MCP
/// server name in two projects of the same client. Used only when keys collide.
const DISAMBIGUATORS: &[&str] = &[
    "ide_type",
    "browser",
    "profile",
    "found_in",
    "config_path",
    "install_path",
    "binary_path",
    "path",
];

/// A row's identity in a --diff section: the row's own key, the disambiguator that
/// tells colliding rows apart, and the copy number. Kept as separate parts, not joined
/// into one string: a natural key can contain `|` or `#` (a composite `primary|source`
/// key, or any text in a hand-edited baseline), so a synthesised `{k}|{d}` or `{k}#2`
/// could equal another row's natural key and overwrite it (review of b21286f).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RowKey {
    key: String,
    disambiguator: String,
    nth: usize,
}

impl std::fmt::Display for RowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.key)?;
        if !self.disambiguator.is_empty() {
            write!(f, "|{}", self.disambiguator)?;
        }
        if self.nth > 1 {
            write!(f, "#{}", self.nth)?;
        }
        Ok(())
    }
}

/// Index rows by `key`, independent of the rows' order. Collecting straight into a map
/// kept the LAST row of a shared key and dropped the others, so the same rows in another
/// order printed a different --diff (and a change to the dropped copy never showed).
/// Colliding rows are told apart by the fewest [`DISAMBIGUATORS`] that make them unique
/// (shown `key|vscode`), and anything still equal by its canonical JSON (`key#2`).
fn index_rows<'a>(rows: &'a [Value], key: impl Fn(&Value) -> Option<String>) -> BTreeMap<RowKey, &'a Value> {
    let mut groups: BTreeMap<String, Vec<&'a Value>> = BTreeMap::new();
    for v in rows {
        if let Some(k) = key(v) {
            groups.entry(k).or_default().push(v);
        }
    }
    let mut out = BTreeMap::new();
    for (k, mut vs) in groups {
        if vs.len() == 1 {
            let rk = RowKey {
                key: k,
                disambiguator: String::new(),
                nth: 1,
            };
            let prev = out.insert(rk, vs[0]);
            debug_assert!(prev.is_none(), "one entry per natural key");
            continue;
        }
        let disc = |v: &Value, n: usize| -> String {
            DISAMBIGUATORS[..n]
                .iter()
                .filter_map(|f| v.get(*f)?.as_str())
                .collect::<Vec<_>>()
                .join("|")
        };
        let n = (1..=DISAMBIGUATORS.len())
            .find(|&n| vs.iter().map(|v| disc(v, n)).collect::<BTreeSet<_>>().len() == vs.len())
            .unwrap_or(DISAMBIGUATORS.len());
        vs.sort_by_cached_key(|v| (disc(v, n), v.to_string()));
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        for v in vs {
            let d = disc(v, n);
            let i = seen.entry(d.clone()).or_default();
            *i += 1;
            let rk = RowKey {
                key: k.clone(),
                disambiguator: d,
                nth: *i,
            };
            let prev = out.insert(rk, v);
            debug_assert!(prev.is_none(), "row keys are unique by construction");
        }
    }
    out
}

fn get_array(report: &Value, key: &str) -> Vec<Value> {
    report.get(key).and_then(|v| v.as_array()).cloned().unwrap_or_default()
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
        // Keyed on config_path itself (Shell Configs), the secondary is the shell: the
        // path again would print `<path>|<path>`.
        let secondary = if key_field == "config_path" {
            v.get("shell")
        } else {
            v.get("config_source").or_else(|| v.get("config_path"))
        }
        .and_then(|s| s.as_str());
        match secondary {
            Some(s) => Some(format!("{}|{}", primary, s)),
            None => Some(primary),
        }
    };

    let baseline_map = index_rows(&baseline, composite_key);
    let current_map = index_rows(&current, composite_key);

    let baseline_keys: BTreeSet<&RowKey> = baseline_map.keys().collect();
    let current_keys: BTreeSet<&RowKey> = current_map.keys().collect();

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
            let (bn, cn);
            let (bv, cv) = if matches!(*field, "hooks" | "helper_commands") {
                bn = normalize_hooks(b.get(*field));
                cn = normalize_hooks(c.get(*field));
                (bn.as_ref(), cn.as_ref())
            } else {
                (b.get(*field), c.get(*field))
            };
            if bv != cv {
                changes.push(format!("{}: {} -> {}", field, display_value(bv), display_value(cv)));
            }
        }

        if !changes.is_empty() {
            changed.push(ChangedItem {
                name: key.to_string(),
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

/// A hook list as drift sees it: what the hook IS (event, matcher, `if`, kind, command,
/// http host, disabled), not how this version grades it (`dangerous`, `risks`,
/// `patterns` are derived from the command and change with the analysis). A command
/// hook's kind is the default and is dropped, so a baseline from before hook kinds
/// existed compares equal. An absent or empty list is None.
fn normalize_hooks(v: Option<&Value>) -> Option<Value> {
    let list = v?.as_array()?;
    if list.is_empty() {
        return None;
    }
    let keep = ["event", "matcher", "if", "command", "url_host", "disabled"];
    Some(Value::Array(
        list.iter()
            .map(|h| {
                let mut m = serde_json::Map::new();
                for k in keep {
                    if let Some(x) = h.get(k).filter(|x| !x.is_null() && **x != Value::Bool(false)) {
                        m.insert(k.to_string(), x.clone());
                    }
                }
                // A settings command is a command whose kind is derived from its key (the
                // event), so it is dropped like `command`: an older baseline compares equal.
                if let Some(kind) = h
                    .get("kind")
                    .and_then(|k| k.as_str())
                    .filter(|k| !crate::scanners::hook_sources::is_command_kind(k))
                {
                    m.insert("kind".to_string(), Value::String(kind.to_string()));
                }
                Value::Object(m)
            })
            .collect(),
    ))
}

fn diff_rules_files(baseline: Vec<Value>, current: Vec<Value>) -> SectionDiff {
    let key_field = "path";

    let key = |v: &Value| Some(v.get(key_field)?.as_str()?.to_string());
    let baseline_map = index_rows(&baseline, key);
    let current_map = index_rows(&current, key);

    let baseline_keys: BTreeSet<&RowKey> = baseline_map.keys().collect();
    let current_keys: BTreeSet<&RowKey> = current_map.keys().collect();

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
            changes.push(format!("dangerous patterns: {} -> {}", b_findings, c_findings));
        }

        if !changes.is_empty() {
            let name = c.get("file_name").and_then(|v| v.as_str()).unwrap_or("?");
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

    let key = |v: &Value| Some(v.get(key_field)?.as_str()?.to_string());
    let baseline_map = index_rows(&baseline, key);
    let current_map = index_rows(&current, key);

    let baseline_keys: BTreeSet<&RowKey> = baseline_map.keys().collect();
    let current_keys: BTreeSet<&RowKey> = current_map.keys().collect();

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

        let b_caps: BTreeSet<String> = get_string_array(b, "capabilities").into_iter().collect();
        let c_caps: BTreeSet<String> = get_string_array(c, "capabilities").into_iter().collect();

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

        // Frontmatter hooks (redacted command text, compared as JSON).
        if normalize_hooks(b.get("hooks")) != normalize_hooks(c.get("hooks")) {
            changes.push("HOOKS CHANGED".to_string());
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
    let key = |v: &Value| Some(v.get(key_field)?.as_str()?.to_string());
    let baseline_map = index_rows(&baseline, key);
    let current_map = index_rows(&current, key);

    let baseline_keys: BTreeSet<&RowKey> = baseline_map.keys().collect();
    let current_keys: BTreeSet<&RowKey> = current_map.keys().collect();

    let added: Vec<String> = current_keys.difference(&baseline_keys).map(|k| k.to_string()).collect();
    let removed: Vec<String> = baseline_keys.difference(&current_keys).map(|k| k.to_string()).collect();

    let mut changed = Vec::new();
    for key in baseline_keys.intersection(&current_keys) {
        let b = baseline_map[*key];
        let c = current_map[*key];
        let mut changes = Vec::new();

        // Index tools by name -> fingerprint (description + canonical inputSchema).
        let b_tools = tool_fingerprints(b);
        let c_tools = tool_fingerprints(c);

        let b_names: BTreeSet<&String> = b_tools.keys().collect();
        let c_names: BTreeSet<&String> = c_tools.keys().collect();

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
        let b_caps: BTreeSet<String> = get_string_array(b, "observed_capabilities").into_iter().collect();
        let c_caps: BTreeSet<String> = get_string_array(c, "observed_capabilities").into_iter().collect();
        let gained: Vec<&String> = c_caps.difference(&b_caps).collect();
        if !gained.is_empty() {
            changes.push(format!(
                "CAPABILITIES GAINED: {}",
                gained.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ));
        }

        if !changes.is_empty() {
            changed.push(ChangedItem {
                name: key.to_string(),
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
fn tool_fingerprints(probe: &Value) -> BTreeMap<String, (String, String)> {
    let mut map = BTreeMap::new();
    if let Some(tools) = probe.get("tools").and_then(|t| t.as_array()) {
        for t in tools {
            let Some(name) = t.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let desc = t.get("description").and_then(|d| d.as_str()).unwrap_or("").to_string();
            // serde_json::to_string of a Value is stable for our purposes (object key
            // order is preserved from parsing); good enough to detect mutation.
            let schema = t.get("input_schema").map(|s| s.to_string()).unwrap_or_default();
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
        let bv = b_summary
            .and_then(|s| s.get(*field))
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let cv = c_summary
            .and_then(|s| s.get(*field))
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
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
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod hook_diff_tests {
    use super::*;

    /// A baseline from before synced-skill identifiers were masked: the same skill
    /// compares equal to the masked row, and the raw UUIDs never reach the diff.
    #[test]
    fn a_raw_synced_baseline_equals_its_masked_rescan() {
        let id = "0e2e0a1b-2c3d-4e5f-8a9b-0c1d2e3f4a5b_1e2e0a1b-2c3d-4e5f-8a9b-0c1d2e3f4a5c";
        let row = |seg: &str, sha: &str| {
            serde_json::json!({"agent_skills": [{
                "path": format!("/h/.claude/skills/synced/{seg}/x/run.py"),
                "name": format!("synced/{seg}/x/run.py"), "framework": "claude-code", "sha256": sha
            }]})
        };
        let d = diff_reports(&row(id, "a"), &row("<org>_<account>", "a"));
        assert!(d.is_empty(), "{}", render_diff(&d));
        let text = render_diff(&diff_reports(&row(id, "a"), &row("<org>_<account>", "b")));
        assert!(text.contains("<org>_<account>") && !text.contains("0e2e0a1b"), "{text}");
    }

    #[test]
    fn skill_frontmatter_hooks_and_settings_provenance_changes_are_drift() {
        let skill =
            |hooks: Value| serde_json::json!({"path": "/p/SKILL.md", "name": "s", "sha256": "a", "hooks": hooks});
        let d = diff_skills(
            vec![skill(Value::Array(Vec::new()))],
            vec![skill(
                serde_json::json!([{"event": "Stop", "command": "x", "dangerous": false}]),
            )],
        );
        assert!(d.changed.iter().any(|c| c.changes.iter().any(|x| x == "HOOKS CHANGED")));
        let same = diff_skills(
            vec![skill(serde_json::json!([]))],
            vec![serde_json::json!({"path": "/p/SKILL.md", "name": "s", "sha256": "a"})],
        );
        assert!(same.changed.is_empty(), "an absent hooks array equals an empty one");
        let base = serde_json::json!({"agent_settings": [{"path": "/h/hooks.json", "provenance": {"plugin": "p", "active": true}}]});
        let cur = serde_json::json!({"agent_settings": [{"path": "/h/hooks.json", "provenance": {"plugin": "p", "active": false}}]});
        let text = render_diff(&diff_reports(&base, &cur));
        assert!(text.contains("provenance"), "{text}");
    }

    /// The hook-policy switches are drift: a managed allowManagedHooksOnly or
    /// disableAllHooks flip, or a plugin newly force-enabled, silences or unsilences
    /// every non-managed Claude Code hook (review of 4e3f8c3). (False and empty are not
    /// serialized, so an older baseline without the fields compares equal.) A settings
    /// command's kind is derived and compares equal to a baseline without it.
    #[test]
    fn hook_policy_switch_flips_are_drift() {
        let row = |extra: Value| {
            let mut m = serde_json::json!({"path": "/etc/claude-code/managed-settings.json", "source": "managed"});
            m.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            serde_json::json!({"agent_settings": [m]})
        };
        for (field, on) in [
            ("allow_managed_hooks_only", serde_json::json!(true)),
            ("disable_all_hooks", serde_json::json!(true)),
            ("force_enabled_plugins", serde_json::json!(["p@m"])),
        ] {
            let text = render_diff(&diff_reports(
                &row(serde_json::json!({})),
                &row(serde_json::json!({field: on})),
            ));
            assert!(text.contains(field), "{field}: {text}");
        }
        let old = row(serde_json::json!({"hooks": [{"event": "statusLine", "command": "~/s.sh"}]}));
        let new = row(
            serde_json::json!({"hooks": [{"event": "statusLine", "command": "~/s.sh", "kind": "settings-command"}]}),
        );
        assert!(render_diff(&diff_reports(&old, &new)).contains("No changes"));
    }

    /// Added and removed rows come out sorted, so two runs of the same `--diff` print the
    /// same text (they came from a HashSet difference before).
    #[test]
    fn added_and_removed_rows_are_sorted() {
        let rows = |paths: &[&str]| serde_json::json!({"agent_settings": paths.iter().map(|p| serde_json::json!({"path": p, "hooks": []})).collect::<Vec<_>>()});
        let names: Vec<String> = (0..40).map(|i| format!("/p/{:02}/hooks.json", (i * 7) % 40)).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let d = diff_reports(&rows(&[]), &rows(&refs));
        let s = d.sections.iter().find(|s| !s.added.is_empty()).expect("added rows");
        let mut sorted = s.added.clone();
        sorted.sort();
        assert_eq!(s.added, sorted);
        let d = diff_reports(&rows(&refs), &rows(&[]));
        let s = d.sections.iter().find(|s| !s.removed.is_empty()).expect("removed rows");
        let mut sorted = s.removed.clone();
        sorted.sort();
        assert_eq!(s.removed, sorted);
    }

    /// The same two reports print the same --diff whatever order their rows arrive in
    /// (C2). Rows sharing a key -- one extension id in two IDEs, one package found in two
    /// projects -- used to collapse to the last one inserted, so a reordering changed the
    /// output and a change to the dropped copy was invisible. On 2ab0c6d the shuffled runs
    /// print different text (and `ext.a|cursor` / `left-pad|/p/b` never appear).
    #[test]
    fn diff_output_is_independent_of_row_order() {
        use serde_json::json;
        let ext = |ide: &str, v: &str| json!({"id": "ext.a", "ide_type": ide, "version": v, "path": format!("/{ide}/ext.a-{v}")});
        let pkg = |at: &str, v: &str| json!({"name": "left-pad", "ecosystem": "npm", "version": v, "advisory": "A-1", "found_in": at});
        let key = |p: &str, t: &str| json!({"path": p, "key_type": t, "has_passphrase": false});
        let base_rows = (
            vec![
                ext("vscode", "1.0"),
                ext("cursor", "1.0"),
                json!({"id": "ext.b", "ide_type": "vscode", "version": "2.0"}),
            ],
            vec![pkg("/p/a", "1.0.0"), pkg("/p/b", "1.0.0")],
            (0..12)
                .map(|i| key(&format!("/k/{i:02}"), "ed25519"))
                .collect::<Vec<_>>(),
        );
        let cur_rows = (
            vec![
                ext("vscode", "1.0"),
                ext("cursor", "1.1"),
                json!({"id": "ext.c", "ide_type": "vscode", "version": "3.0"}),
            ],
            vec![pkg("/p/a", "1.0.0"), pkg("/p/b", "1.0.1")],
            (4..16)
                .map(|i| key(&format!("/k/{i:02}"), if i % 3 == 0 { "rsa" } else { "ed25519" }))
                .collect::<Vec<_>>(),
        );
        // A fixed permutation per run (an LCG), so each run inserts the rows in another order.
        let shuffle = |mut v: Vec<Value>, seed: u64| {
            let mut x = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            for i in (1..v.len()).rev() {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                v.swap(i, (x >> 33) as usize % (i + 1));
            }
            v
        };
        let report = |rows: &(Vec<Value>, Vec<Value>, Vec<Value>), seed: u64| {
            json!({
                "ide_extensions": shuffle(rows.0.clone(), seed),
                "exposure_findings": shuffle(rows.1.clone(), seed + 1),
                "ssh_keys": shuffle(rows.2.clone(), seed + 2),
            })
        };
        let expected = [
            "=== Scan Diff Report ===",
            "",
            "--- IDE Extensions ---",
            "  + ext.c (version=3.0)",
            "  - ext.b (version=2.0)",
            "  ~ ext.a|cursor",
            "      version: 1.0 -> 1.1",
            "",
            "--- SSH Keys ---",
            "  + /k/12 (key_type=rsa, has_passphrase=false)",
            "  + /k/13 (key_type=ed25519, has_passphrase=false)",
            "  + /k/14 (key_type=ed25519, has_passphrase=false)",
            "  + /k/15 (key_type=rsa, has_passphrase=false)",
            "  - /k/00 (key_type=ed25519, has_passphrase=false)",
            "  - /k/01 (key_type=ed25519, has_passphrase=false)",
            "  - /k/02 (key_type=ed25519, has_passphrase=false)",
            "  - /k/03 (key_type=ed25519, has_passphrase=false)",
            "  ~ /k/06",
            "      key_type: ed25519 -> rsa",
            "  ~ /k/09",
            "      key_type: ed25519 -> rsa",
            "",
            "--- Exposure Findings ---",
            "  ~ left-pad|/p/b",
            "      version: 1.0.0 -> 1.0.1",
            "",
            "",
        ]
        .join("\n");
        for run in 0..20u64 {
            let text = render_diff(&diff_reports(
                &report(&base_rows, run * 7),
                &report(&cur_rows, run * 13 + 5),
            ));
            assert_eq!(text, expected, "run {run} printed a different diff");
        }
    }

    /// A baseline written before hook kinds and grading fields existed compares equal to
    /// the same hooks now; a change to what the hook is (its `if`, its command) is drift.
    #[test]
    fn hooks_diff_on_identity_not_grading() {
        let settings = |hooks: Value| serde_json::json!({"agent_settings": [{"path": "/p/.claude/settings.json", "hooks": hooks}]});
        let old = settings(serde_json::json!([
            {"command": "echo user-hook", "dangerous": false, "event": "Stop"},
            {"command": "printenv NODE_ENV", "dangerous": true, "event": "Stop"}
        ]));
        let new = settings(serde_json::json!([
            {"command": "echo user-hook", "dangerous": false, "event": "Stop", "kind": "command"},
            {"command": "printenv NODE_ENV", "dangerous": false, "event": "Stop", "kind": "command",
             "patterns": ["environment variable exfiltration"], "pattern_severity": "medium"}
        ]));
        let d = diff_reports(&old, &new);
        assert!(
            d.sections
                .iter()
                .all(|s| s.changed.is_empty() && s.added.is_empty() && s.removed.is_empty()),
            "{}",
            render_diff(&d)
        );
        let cond = settings(serde_json::json!([
            {"command": "echo user-hook", "dangerous": false, "event": "Stop", "kind": "command", "if": "Bash(git *)"},
            {"command": "printenv NODE_ENV", "event": "Stop"}
        ]));
        assert!(render_diff(&diff_reports(&new, &cond)).contains("Bash(git *)"));
        let http =
            settings(serde_json::json!([{"command": "POST https://a.example", "event": "Stop", "kind": "http"}]));
        let cmd = settings(serde_json::json!([{"command": "POST https://a.example", "event": "Stop"}]));
        assert!(
            render_diff(&diff_reports(&cmd, &http)).contains("http"),
            "a kind change is drift"
        );
    }

    /// A catalog version change is one line at the top of the --diff output and no entry
    /// change; identical versions print nothing about the catalog; a baseline without the
    /// `catalog` block (written before b21286f) says it predates versioning. The
    /// baseline's version is file text and is sanitized. (On 6af8a1e no such line
    /// exists: `ScanDiff` has no `catalog_change`, and the output is "No changes".)
    #[test]
    fn catalog_version_change_is_one_line_at_the_top() {
        use serde_json::json;
        let report = |catalog: Option<Value>| {
            let mut r = json!({
                "agent_settings": [{"path": "/h/.claude/settings.json", "hooks": []}],
                "summary": {"agent_settings_count": 1},
            });
            if let Some(c) = catalog {
                r["catalog"] = c;
            }
            r
        };
        let block = |v: Value| json!({"builtin_version": v, "builtin_entries": 228, "user_entries": 0});
        let cur = report(Some(block(json!("2026-11-03"))));

        let d = diff_reports(&report(Some(block(json!("2026-10-22")))), &cur);
        assert!(d.is_empty(), "a catalog change is not an entry change");
        let text = render_diff(&d);
        assert_eq!(
            text.lines().next(),
            Some("threat catalog: 2026-10-22 -> 2026-11-03 (findings may change without any change on this machine)"),
            "{text}"
        );
        assert!(text.contains("No changes detected"), "{text}");
        assert_eq!(text.matches("threat catalog").count(), 1, "{text}");

        let text = render_diff(&diff_reports(&cur, &cur));
        assert!(!text.contains("threat catalog"), "{text}");
        assert!(text.starts_with("No changes detected"), "{text}");

        let text = render_diff(&diff_reports(&report(None), &cur));
        assert_eq!(
            text.lines().next(),
            Some("threat catalog: baseline predates catalog versioning"),
            "{text}"
        );

        // --no-builtin-catalog on one side.
        let text = render_diff(&diff_reports(&report(Some(block(Value::Null))), &cur));
        assert!(text.starts_with("threat catalog: not loaded -> 2026-11-03 "), "{text}");

        // With entry changes too, the catalog line still comes first.
        let mut moved = cur.clone();
        moved["agent_settings"][0]["path"] = json!("/h/other/settings.json");
        let text = render_diff(&diff_reports(&report(None), &moved));
        assert!(text.starts_with("threat catalog: baseline predates"), "{text}");
        assert!(text.contains("=== Scan Diff Report ==="), "{text}");

        // A hostile baseline version cannot reach the terminal raw.
        let text = render_diff(&diff_reports(
            &report(Some(block(json!("x\u{1b}]0;PWN\u{7}\nforged: line")))),
            &cur,
        ));
        assert!(!text.contains('\u{1b}') && !text.contains('\u{7}'), "{text:?}");
        assert!(!text.lines().any(|l| l.starts_with("forged")), "{text:?}");
    }
}
