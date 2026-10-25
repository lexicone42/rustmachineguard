use crate::models::{
    MCP_SOURCE_CONNECTOR, MCP_SOURCE_PLUGIN, MCP_TRANSPORT_CONNECTOR, McpConfig, McpObservedServer, McpServerDetail,
    ScanReport,
};
use crate::platform::PlatformInfo;
use crate::scanners::{Scanner, is_git_tracked, sanitize_display};
use std::path::{Path, PathBuf};

pub struct McpScanner;

impl Scanner for McpScanner {
    type Output = Vec<McpConfig>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<McpConfig> {
        let mut results = Vec::new();

        for (source, path, vendor) in platform.mcp_config_paths() {
            if !crate::scanners::probe_file(&path) {
                continue;
            }

            let content = match crate::scanners::read_bounded(&path) {
                Some(c) => c,
                None => continue,
            };

            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();

            // Normalize every format to the canonical JSON value so all per-server
            // detections (package identity, inline secrets, transport, launch command)
            // apply uniformly — a hardcoded token in a Codex TOML config is just as
            // committed as one in a Cursor JSON config.
            let canonical = match ext.as_str() {
                "yaml" | "yml" => yaml_to_json(&content),
                "toml" => toml_to_json(&content),
                _ => serde_json::from_str::<serde_json::Value>(&content).ok(),
            };
            let Some(v) = canonical else { continue };
            let server_names = extract_mcp_servers(&v);
            let servers = extract_mcp_server_details(&v);

            if server_names.is_empty() {
                continue;
            }

            let server_count = server_names.len();
            results.push(McpConfig {
                config_source: source,
                config_path: path.display().to_string(),
                vendor,
                server_names,
                server_count,
                git_tracked: is_git_tracked(&path),
                servers,
            });
        }

        let home = platform.home_dir();
        let claude_json = home.join(".claude.json");
        let claude_value = if crate::scanners::probe_file(&claude_json) {
            crate::scanners::read_bounded(&claude_json).and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
        } else {
            None
        };
        // Project-scope servers (`<project>/.mcp.json`) of every project of this pass,
        // built as every other scanner builds its list: registered in `~/.claude.json`,
        // recovered from `~/.claude/projects/<encoded>` names, and (primary pass) the
        // working directory. Another scan home, or an ancestor of one, is not this pass's
        // project (its own pass reads it); this pass's own home stays, as on 4e23ef8, when
        // it is a registered project or the working directory: Claude Code run in `~`
        // loads `~/.mcp.json`. Local-scope servers (`projects.<path>.mcpServers`) are in
        // the `~/.claude.json` row above. `mcpServers` is not a settings-file key
        // (code.claude.com/docs/en/settings-reference), so `.claude/settings*.json` adds none.
        let registered: Vec<PathBuf> = claude_value
            .as_ref()
            .and_then(|v| v.get("projects"))
            .and_then(|p| p.as_object())
            .map(|o| o.keys().map(PathBuf::from).collect())
            .unwrap_or_default();
        for proj in project_dirs(platform.pass_scope(), &home, registered) {
            let mcp_json = proj.join(".mcp.json");
            if !crate::scanners::probe_file(&mcp_json) {
                continue;
            }
            let Some(proj_content) = crate::scanners::read_bounded(&mcp_json) else {
                continue;
            };
            let Ok(pv) = serde_json::from_str::<serde_json::Value>(&proj_content) else {
                continue;
            };
            let server_names = extract_mcp_servers(&pv);
            if server_names.is_empty() {
                continue;
            }
            let servers = extract_mcp_server_details(&pv);
            let server_count = server_names.len();
            results.push(McpConfig {
                config_source: format!("Project MCP ({})", proj.display()),
                config_path: mcp_json.display().to_string(),
                vendor: "Project".to_string(),
                server_names,
                server_count,
                git_tracked: is_git_tracked(&mcp_json),
                servers,
            });
        }

        results.extend(plugin_servers(&home));
        results.extend(connector_servers(&home, &claude_json, claude_value.as_ref()));
        results
    }
}

/// The projects whose `.mcp.json` this pass reads ([`crate::platform::PassScope::with_cwd`]),
/// without another scan home or an ancestor of one, and each directory once (by real
/// path; the working directory is often registered too).
fn project_dirs(scope: &crate::platform::PassScope, home: &Path, registered: Vec<PathBuf>) -> Vec<PathBuf> {
    let real = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let own_home = real(home);
    let mut seen = std::collections::HashSet::new();
    scope
        .with_cwd(registered)
        .into_iter()
        .filter(|d| real(d) == own_home || !scope.is_scan_home_or_ancestor(d))
        .filter(|d| seen.insert(real(d)))
        .collect()
}

/// What the `mcp` job stores: config rows and observed (logged) server names.
pub enum McpOut {
    Config(McpConfig),
    Observed(McpObservedServer),
}

/// The `mcp` job: every config row, then the observed server names of this home.
pub fn scan_home(platform: &dyn PlatformInfo) -> Vec<McpOut> {
    let mut out: Vec<McpOut> = McpScanner.scan(platform).into_iter().map(McpOut::Config).collect();
    out.extend(observed_servers(&platform.home_dir()).into_iter().map(McpOut::Observed));
    out
}

/// Store the `mcp` job's rows.
pub fn store(report: &mut ScanReport, rows: Vec<McpOut>) {
    for r in rows {
        match r {
            McpOut::Config(c) => report.mcp_configs.push(c),
            McpOut::Observed(o) => report.mcp_observed_servers.push(o),
        }
    }
}

// ── Plugin MCP servers ──────────────────────────────────────────────────────────

/// Server entries a plugin may declare: more are not read.
const MAX_PLUGIN_SERVERS: usize = 50;
/// `mcpServers` array entries in a manifest that are followed.
const MAX_MANIFEST_ENTRIES: usize = 20;

/// The MCP servers of every installed Claude Code plugin version, one config row per
/// source file: `<installPath>/.mcp.json`, then each `plugin.json` `mcpServers` entry in
/// order (a `./file.json` reference or an inline map). A server name declared later
/// replaces an earlier one, as Claude Code merges them
/// (code.claude.com/docs/en/plugins-reference#mcpservers). Paths must start with `./`
/// and stay inside the plugin root, and a file is read only when its real path is
/// inside the root's real path, its last component not a symlink (the same containment
/// as plugin hooks). `.mcpb` / `.dxt` bundles are not unpacked.
///
/// Marketplace clones and orphaned cache versions are not installed, so they are not
/// read. A plugin set to false in `enabledPlugins` keeps its rows with
/// `enabled: Some(false)`: inventory only (a managed force-enable is applied after the
/// scan, see [`post_scan`]).
pub fn plugin_servers(home: &Path) -> Vec<McpConfig> {
    let ctx = crate::scanners::skills::PluginContext::load(home);
    let mut ips: Vec<(PathBuf, String, String)> = ctx.install_paths().to_vec();
    ips.sort();
    ips.dedup_by(|a, b| a.0 == b.0);
    let mut out = Vec::new();
    // An install path that is (or sits under) a symlink leaving the plugin cache is not
    // read: containment is judged against the real cache directory.
    let Ok(real_cache) = std::fs::canonicalize(home.join(".claude").join("plugins").join("cache")) else {
        return out;
    };
    for (ip, plugin, market) in &ips {
        if !crate::scanners::probe_dir(ip) {
            continue;
        }
        let Ok(real_root) = std::fs::canonicalize(ip) else {
            continue;
        };
        if !real_root.starts_with(&real_cache) || real_root == real_cache {
            continue;
        }
        let key = format!("{plugin}@{market}");
        let label = sanitize_display(&key, 256);
        let enabled = !ctx.is_disabled(&key);
        out.extend(plugin_root_configs(ip, &real_root, &label, enabled));
    }
    out
}

/// The config rows of one plugin version directory `ip` (real path `real_root`, already
/// checked to lie inside the real plugin cache), in load order (see [`plugin_servers`]).
pub(crate) fn plugin_root_configs(ip: &Path, real_root: &Path, label: &str, enabled: bool) -> Vec<McpConfig> {
    // (source file, server map), in load order.
    let mut sources: Vec<(PathBuf, serde_json::Map<String, serde_json::Value>)> = Vec::new();
    let dot_mcp = ip.join(".mcp.json");
    if let Some(v) = read_plugin_json(real_root, &dot_mcp) {
        sources.push((dot_mcp, server_map(&v)));
    }
    let manifest = ip.join(".claude-plugin").join("plugin.json");
    if let Some(m) = read_plugin_json(real_root, &manifest) {
        let declared: Vec<&serde_json::Value> = match m.get("mcpServers") {
            Some(serde_json::Value::Array(a)) => a.iter().take(MAX_MANIFEST_ENTRIES).collect(),
            Some(v) => vec![v],
            None => Vec::new(),
        };
        let mut inline = serde_json::Map::new();
        for d in declared {
            match d {
                serde_json::Value::String(rel) => {
                    if let Some(p) = manifest_json_path(ip, rel)
                        && let Some(v) = read_plugin_json(real_root, &p)
                    {
                        sources.push((p, server_map(&v)));
                    }
                }
                serde_json::Value::Object(map) => inline.extend(map.clone()),
                _ => {}
            }
        }
        if !inline.is_empty() {
            sources.push((manifest, inline));
        }
    }
    // Later declarations replace earlier ones of the same name.
    let mut taken = std::collections::HashSet::new();
    let mut rows: Vec<McpConfig> = Vec::new();
    for (path, map) in sources.into_iter().rev() {
        let mut kept = serde_json::Map::new();
        for (name, cfg) in map {
            if cfg.is_object() && taken.len() < MAX_PLUGIN_SERVERS && taken.insert(name.clone()) {
                kept.insert(name, cfg);
            }
        }
        if kept.is_empty() {
            continue;
        }
        let wrapped = serde_json::json!({ "mcpServers": kept });
        let server_names: Vec<String> = extract_mcp_servers(&wrapped)
            .iter()
            .map(|n| sanitize_display(n, 128))
            .collect();
        let mut servers = extract_mcp_server_details(&wrapped);
        for s in &mut servers {
            s.plugin = Some(label.to_string());
            s.enabled = Some(enabled);
        }
        rows.push(McpConfig {
            config_source: MCP_SOURCE_PLUGIN.to_string(),
            config_path: sanitize_display(&path.to_string_lossy(), 512),
            vendor: format!("Claude Code plugin {label}"),
            server_count: server_names.len(),
            server_names,
            git_tracked: false,
            servers,
        });
    }
    rows.reverse();
    rows
}

/// A plugin `.mcp.json` (or a file `mcpServers` names) holds either the documented
/// `{"mcpServers": {...}}` wrapper or the bare name -> config map (both shapes ship in
/// Anthropic's own marketplace).
fn server_map(v: &serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    if let Some(m) = v.get("mcpServers").and_then(|m| m.as_object()) {
        return m.clone();
    }
    v.as_object()
        .map(|o| {
            o.iter()
                .filter(|(_, c)| c.is_object())
                .map(|(k, c)| (k.clone(), c.clone()))
                .collect()
        })
        .unwrap_or_default()
}

/// A manifest `mcpServers` path: starts with `./`, ends in `.json`, stays lexically
/// inside `root`. Bundles (`.mcpb`, `.dxt`) and URLs are not followed.
pub(crate) fn manifest_json_path(root: &Path, rel: &str) -> Option<PathBuf> {
    if !rel.starts_with("./") || !rel.ends_with(".json") {
        return None;
    }
    let p = crate::scanners::persistence::lexical_join(root, Path::new(rel));
    (p.starts_with(root) && p != root).then_some(p)
}

/// Read and parse a JSON file of a plugin whose real path lies inside the plugin's real
/// root, its final component not a symlink.
pub(crate) fn read_plugin_json(real_root: &Path, path: &Path) -> Option<serde_json::Value> {
    let present = std::fs::symlink_metadata(path).is_ok();
    crate::scanners::telemetry::note_probe(path, present);
    if !present {
        return None;
    }
    let real = std::fs::canonicalize(path).ok()?;
    if !real.starts_with(real_root) {
        return None;
    }
    let text = crate::scanners::read_bounded_nofollow(path, Some(&real))?;
    serde_json::from_str(&text).ok()
}

// ── claude.ai connectors ────────────────────────────────────────────────────────

/// Connector names read from `claudeAiMcpEverConnected`.
const MAX_CONNECTORS: usize = 200;

/// The claude.ai connectors Claude Code lists in `~/.claude.json`
/// `claudeAiMcpEverConnected` (display names such as `claude.ai Gmail`), as one config
/// row. The key is Claude Code's own state, not a documented setting: it records the
/// connectors that were connected at some point, so each row is `ever_connected`, and
/// whether it is enabled now is unknown (`enabled: None`) unless a user or managed
/// `disableClaudeAiConnectors: true` turns every fetched connector off
/// (code.claude.com/docs/en/mcp, "Disable claude.ai connectors").
pub fn connector_servers(home: &Path, claude_json: &Path, value: Option<&serde_json::Value>) -> Option<McpConfig> {
    let list = value?.get("claudeAiMcpEverConnected")?.as_array()?;
    let mut names: Vec<String> = list
        .iter()
        .filter_map(|v| v.as_str())
        .map(|n| sanitize_display(n, 128))
        .filter(|n| !n.is_empty())
        .collect();
    names.sort();
    names.dedup();
    names.truncate(MAX_CONNECTORS);
    if names.is_empty() {
        return None;
    }
    let off = connectors_disabled(home);
    let servers = names
        .iter()
        .map(|n| McpServerDetail {
            name: n.clone(),
            transport: MCP_TRANSPORT_CONNECTOR.to_string(),
            ever_connected: true,
            enabled: off.then_some(false),
            ..Default::default()
        })
        .collect();
    Some(McpConfig {
        config_source: MCP_SOURCE_CONNECTOR.to_string(),
        // Not the bare `.claude.json` path: that is the user-scope config's row, and rows
        // are deduplicated by path.
        config_path: format!(
            "{} (claudeAiMcpEverConnected)",
            sanitize_display(&claude_json.to_string_lossy(), 512)
        ),
        vendor: "Anthropic (claude.ai)".to_string(),
        server_count: names.len(),
        server_names: names,
        git_tracked: false,
        servers,
    })
}

/// `disableClaudeAiConnectors: true` in the user's settings (any-source-true; managed
/// settings are applied after the scan in [`post_scan`]).
fn connectors_disabled(home: &Path) -> bool {
    let p = home.join(".claude").join("settings.json");
    crate::scanners::read_bounded(&p)
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|v| v.get("disableClaudeAiConnectors").and_then(|b| b.as_bool()))
        .unwrap_or(false)
}

// ── Observed servers (MCP log directory names) ──────────────────────────────────

/// Project directories of the log cache that are listed.
const MAX_LOG_PROJECTS: usize = 2000;
/// Entries of one project directory that are looked at.
const MAX_LOG_ENTRIES: usize = 500;
/// Distinct observed server names kept.
const MAX_OBSERVED: usize = 500;

/// Claude Code's per-project MCP log caches under `home`: Linux
/// `~/.cache/claude-cli-nodejs`, macOS `~/Library/Caches/claude-cli-nodejs`.
fn log_roots(home: &Path) -> [PathBuf; 2] {
    [
        home.join(".cache").join("claude-cli-nodejs"),
        home.join("Library").join("Caches").join("claude-cli-nodejs"),
    ]
}

/// Every `<root>/<project>/mcp-logs-<server>/` directory NAME, aggregated by server:
/// how many projects it appears in and the newest directory mtime. A bounded two-level
/// listing; no log file is opened, and symlinks are not followed.
pub fn observed_servers(home: &Path) -> Vec<McpObservedServer> {
    let mut by_name: std::collections::BTreeMap<String, McpObservedServer> = std::collections::BTreeMap::new();
    for root in log_roots(home) {
        if !crate::scanners::probe_dir(&root) {
            continue;
        }
        let Ok(projects) = crate::scanners::probe_read_dir(&root) else {
            continue;
        };
        let shown_root = sanitize_display(&root.to_string_lossy(), 512);
        for proj in projects.flatten().take(MAX_LOG_PROJECTS) {
            if !proj.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(proj.path()) else {
                continue;
            };
            for e in entries.flatten().take(MAX_LOG_ENTRIES) {
                let file_name = e.file_name();
                let Some(server) = file_name.to_str().and_then(|n| n.strip_prefix("mcp-logs-")) else {
                    continue;
                };
                if server.is_empty() || !e.file_type().is_ok_and(|t| t.is_dir()) {
                    continue;
                }
                let name = sanitize_display(server, 128);
                if !by_name.contains_key(&name) && by_name.len() >= MAX_OBSERVED {
                    continue;
                }
                let mtime = e
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64);
                let row = by_name.entry(name.clone()).or_insert_with(|| McpObservedServer {
                    name,
                    log_root: shown_root.clone(),
                    ..Default::default()
                });
                row.projects += 1;
                row.newest_mtime = row.newest_mtime.max(mtime);
            }
        }
    }
    by_name.into_values().collect()
}

/// A server name as Claude Code's log directory spells it, folded for comparison: every
/// character outside `[A-Za-z0-9]` becomes `-`, lowercased. Observed on disk (the naming
/// is not documented): `plugin:playwright:playwright` -> `plugin-playwright-playwright`,
/// `claude.ai Google Drive` -> `claude-ai-Google-Drive`.
pub fn log_key(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

/// The log key of a server row: plugin servers register as `plugin:<plugin>:<server>`
/// (code.claude.com/docs/en/mcp, "Plugin MCP tool names"), everything else by its name.
pub fn server_log_key(s: &McpServerDetail) -> String {
    match s.plugin.as_deref().and_then(|p| p.rsplit_once('@')).map(|(p, _)| p) {
        Some(plugin) => log_key(&format!("plugin:{plugin}:{}", s.name)),
        None => log_key(&s.name),
    }
}

/// After every home pass: apply managed `enabledPlugins` force-enables to plugin
/// servers, a managed `disableClaudeAiConnectors` to connectors, and mark each observed
/// server whose log name matches a server of the scan.
pub fn post_scan(report: &mut ScanReport) {
    let managed = || {
        report
            .agent_settings
            .iter()
            .filter(|s| s.source == "managed" && s.framework == "claude-code")
    };
    let forced: std::collections::BTreeSet<String> = managed()
        .flat_map(|s| s.force_enabled_plugins.iter().cloned())
        .collect();
    let managed_paths: Vec<String> = managed().map(|s| s.path.clone()).collect();
    let connectors_off = managed_paths.iter().any(|p| managed_disables_connectors(Path::new(p)));
    for cfg in &mut report.mcp_configs {
        for s in &mut cfg.servers {
            if cfg.config_source == MCP_SOURCE_PLUGIN
                && s.enabled == Some(false)
                && s.plugin.as_ref().is_some_and(|p| forced.contains(p))
            {
                s.enabled = Some(true);
            }
            if cfg.config_source == MCP_SOURCE_CONNECTOR && connectors_off {
                s.enabled = Some(false);
            }
        }
    }
    let keys: std::collections::HashSet<String> = report
        .mcp_configs
        .iter()
        .flat_map(|c| c.servers.iter().map(server_log_key))
        .collect();
    for o in &mut report.mcp_observed_servers {
        o.configured = keys.contains(&log_key(&o.name));
    }
    let mut seen = std::collections::HashSet::new();
    report
        .mcp_observed_servers
        .retain(|o| seen.insert((o.log_root.clone(), o.name.clone())));
}

/// A managed settings file sets `disableClaudeAiConnectors: true`.
fn managed_disables_connectors(path: &Path) -> bool {
    crate::scanners::read_bounded(path)
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|v| v.get("disableClaudeAiConnectors").and_then(|b| b.as_bool()))
        .unwrap_or(false)
}

/// Extract MCP server names from JSON config (also the canonical form for TOML/YAML
/// configs, which are converted to JSON before extraction — see `toml_to_json`).
pub fn extract_mcp_servers(json: &serde_json::Value) -> Vec<String> {
    let mut names = Vec::new();

    // "mcpServers" is the JSON convention; "mcp_servers" is the TOML (Codex) one.
    for key in ["mcpServers", "mcp_servers"] {
        if let Some(servers) = json.get(key).and_then(|v| v.as_object()) {
            names.extend(servers.keys().cloned());
        }
    }

    if let Some(servers) = json
        .get("mcp")
        .and_then(|v| v.get("servers"))
        .and_then(|v| v.as_object())
    {
        names.extend(servers.keys().cloned());
    }

    if let Some(servers) = json.get("context_servers").and_then(|v| v.as_object()) {
        names.extend(servers.keys().cloned());
    }

    if let Some(projects) = json.get("projects").and_then(|v| v.as_object()) {
        for (_proj_path, proj_cfg) in projects {
            if let Some(servers) = proj_cfg.get("mcpServers").and_then(|v| v.as_object()) {
                names.extend(servers.keys().cloned());
            }
        }
    }

    names.sort();
    names.dedup();
    names
}

/// Extract detailed server information including package identity from launcher commands.
pub fn extract_mcp_server_details(json: &serde_json::Value) -> Vec<McpServerDetail> {
    let mut details = Vec::new();

    let server_maps: Vec<&serde_json::Map<String, serde_json::Value>> = [
        json.get("mcpServers").and_then(|v| v.as_object()),
        json.get("mcp_servers").and_then(|v| v.as_object()),
        json.get("mcp")
            .and_then(|v| v.get("servers"))
            .and_then(|v| v.as_object()),
        json.get("context_servers").and_then(|v| v.as_object()),
    ]
    .into_iter()
    .flatten()
    .collect();

    // Also collect project-scoped (local-scope) servers. Claude Code records the `/mcp`
    // toggle per project in `~/.claude.json` as `projects.<path>.disabledMcpServers`
    // and does not connect to a server listed there
    // (code.claude.com/docs/en/mcp, "disabledMcpServers"): such a local server is
    // `enabled: false`. A user-scope server disabled in one project still runs in the
    // others, so the list does not mark it.
    if let Some(projects) = json.get("projects").and_then(|v| v.as_object()) {
        for (_, proj_cfg) in projects {
            let disabled: Vec<&str> = proj_cfg
                .get("disabledMcpServers")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|n| n.as_str()).collect())
                .unwrap_or_default();
            if let Some(servers) = proj_cfg.get("mcpServers").and_then(|v| v.as_object()) {
                for (name, cfg) in servers {
                    let mut d = parse_server_detail(name, cfg);
                    if disabled.contains(&name.as_str()) {
                        d.enabled = Some(false);
                    }
                    details.push(d);
                }
            }
        }
    }

    for map in server_maps {
        for (name, cfg) in map {
            details.push(parse_server_detail(name, cfg));
        }
    }

    details
}

/// Redact credential material from a launch argument before it is stored.
///
/// Args are needed for package identity and the download-and-execute check, but they
/// routinely carry secrets: a connection string with userinfo
/// (`postgres://user:pw@host/db`), or a `--token <value>` pair. Storing them verbatim
/// put real passwords into the JSON and Blueprint output, which breaks the
/// no-secret-leakage guarantee, so every arg is filtered on the way in.
///
/// `prev` is the preceding argument, so `--password secret` can be caught as well as
/// `--password=secret`.
pub fn redact_arg(arg: &str, prev: Option<&str>) -> String {
    // A bare value whose FLAG was secret-looking: `--token`, `-p`, `--api-key`. The MCP
    // flag table is wider than the shared helper's (single-letter flags included) because
    // an MCP launch line is a program invocation, not a shell script.
    if let Some(prev) = prev
        && !arg.starts_with('-')
        && flag_names_a_secret(prev)
    {
        return "<redacted>".to_string();
    }
    // Everything else -- `--flag=value`, URLs, `Authorization: Bearer x` inside a single
    // `--header` argument, `Server=db;Password=x;` connection strings -- is the shared
    // helper's job. This used to handle only URL userinfo itself and return anything else
    // untouched, which let header and connection-string credentials into JSON and
    // Blueprint while the canary suite tested a function this path never called.
    crate::scanners::redact_secrets_in_text(arg)
}

/// True if a CLI flag name suggests its value is a secret. Reuses the shared key-name
/// heuristic, so `--api-key`, `--token`, `--password`, `--dsn` are all covered.
fn flag_names_a_secret(flag: &str) -> bool {
    // Only a FLAG can name a secret. Without this, the redacted value itself (`--api-key
    // E2EAPIKEY https://k.internal/`) or a package name containing "key"/"token" made the
    // following URL look like a secret value and blanked it -- the end-to-end canary
    // test's positive control caught the missing host.
    if !flag.starts_with('-') {
        return false;
    }
    let f = flag.trim_start_matches('-').replace('-', "_");
    crate::scanners::env_files::is_secret_key_name(&f)
        || matches!(
            f.to_ascii_lowercase().as_str(),
            "dsn" | "conn" | "connection" | "u" | "p" | "pw"
        )
}

fn parse_server_detail(name: &str, cfg: &serde_json::Value) -> McpServerDetail {
    let command = cfg.get("command").and_then(|v| v.as_str()).map(|s| s.to_string());
    // Raw args are used for package identity, then discarded: only the redacted form
    // is stored, so a credential in a connection string never reaches the report.
    let raw_args: Vec<String> = cfg
        .get("args")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    let args: Vec<String> = raw_args
        .iter()
        .enumerate()
        .map(|(i, a)| redact_arg(a, i.checked_sub(1).and_then(|j| raw_args.get(j)).map(String::as_str)))
        .collect();

    // Determine transport type. Prefer an explicit "type"/"transport" field;
    // fall back to structural inference. The MCP spec replaced standalone SSE
    // with "Streamable HTTP" as the default remote transport in the 2025
    // revision, so a url with no explicit type is classified as "http".
    let url = cfg.get("url").and_then(|v| v.as_str()).map(|s| s.to_string());
    let explicit = cfg
        .get("type")
        .or_else(|| cfg.get("transport"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_ascii_lowercase());
    let transport = match explicit.as_deref() {
        Some("stdio") => "stdio".to_string(),
        Some("sse") => "sse".to_string(),
        Some("http" | "streamable-http" | "streamablehttp" | "streamable_http" | "http-stream") => "http".to_string(),
        _ if url.is_some() => "http".to_string(),
        _ if command.is_some() => "stdio".to_string(),
        _ => "unknown".to_string(),
    };

    // Sanitize URL (strip credentials, paths, query strings)
    let sanitized_url = url.as_deref().map(sanitize_url);

    // Extract package identity from command + args
    let (ecosystem, pkg_name, pkg_version) = if let Some(ref cmd) = command {
        infer_package_from_command(cmd, &raw_args)
    } else {
        (None, None, None)
    };

    let inline_secret_env_keys = extract_inline_secret_env_keys(cfg.get("env"));
    let unpinned = command.as_deref().and_then(|c| unpinned_reason(c, &raw_args));

    McpServerDetail {
        name: crate::scanners::sanitize_display(name, 128),
        transport,
        // Stored redacted: users routinely write the whole launch line into `command`,
        // and this field ships in JSON, Blueprint and SBOM.
        command: command.as_deref().map(crate::scanners::redact_secrets_in_text),
        args,
        package_ecosystem: ecosystem,
        package_name: pkg_name,
        package_version: pkg_version,
        url: sanitized_url,
        inline_secret_env_keys,
        inline_secret_header_keys: inline_secret_header_keys(cfg.get("headers")),
        env: shapes(cfg.get("env"), "="),
        headers: shapes(cfg.get("headers"), ": "),
        unpinned,
        ..Default::default()
    }
}

/// Entries of an `env` / `headers` block that are shown.
const MAX_SHAPES: usize = 50;

/// An `env` or `headers` block as `NAME<sep>SHAPE` lines, sorted: the name and the
/// value's shape (see [`value_shape`]), never the value.
pub fn shapes(block: Option<&serde_json::Value>, sep: &str) -> Vec<String> {
    let Some(obj) = block.and_then(|v| v.as_object()) else {
        return Vec::new();
    };
    let mut out: Vec<String> = obj
        .iter()
        .take(MAX_SHAPES)
        .map(|(k, v)| {
            let shape = v
                .as_str()
                .map(value_shape)
                .unwrap_or_else(|| "<non-string>".to_string());
            format!("{}{sep}{shape}", sanitize_display(k, 128))
        })
        .collect();
    out.sort();
    out
}

/// The shape of a config value, which never contains the value itself: a pure reference
/// as the reference (`${NAME}`, `$NAME`, `%NAME%`, `${user_config.KEY}`), a reference
/// with a default as `${NAME:-<redacted>}` (the default can be a literal credential), an
/// auth scheme word before a reference kept (`Bearer ${NAME}`), `<empty>`, and anything
/// else `<redacted>`.
pub fn value_shape(value: &str) -> String {
    let v = value.trim();
    if v.is_empty() {
        return "<empty>".to_string();
    }
    for scheme in ["Bearer ", "Basic ", "Token ", "bearer ", "basic ", "token "] {
        if let Some(rest) = v.strip_prefix(scheme) {
            let inner = reference_shape(rest.trim());
            return format!("{}{}", scheme, inner.unwrap_or_else(|| "<redacted>".to_string()));
        }
    }
    reference_shape(v).unwrap_or_else(|| "<redacted>".to_string())
}

/// `v` is exactly one environment reference: its shape, else None.
fn reference_shape(v: &str) -> Option<String> {
    let ident = |s: &str| {
        !s.is_empty()
            && s.len() <= 128
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
            && !s.starts_with(|c: char| c.is_ascii_digit())
    };
    if let Some(inner) = v.strip_prefix("${").and_then(|r| r.strip_suffix('}')) {
        if inner.contains(['{', '}', '$']) {
            return None;
        }
        return match inner.split_once(":-") {
            Some((name, default)) if ident(name) => Some(if default.is_empty() {
                format!("${{{name}}}")
            } else {
                format!("${{{name}:-<redacted>}}")
            }),
            None if ident(inner) => Some(format!("${{{inner}}}")),
            _ => None,
        };
    }
    if let Some(name) = v.strip_prefix('$')
        && ident(name)
        && !name.contains('.')
    {
        return Some(format!("${name}"));
    }
    if let Some(name) = v.strip_prefix('%').and_then(|r| r.strip_suffix('%'))
        && ident(name)
    {
        return Some(format!("%{name}%"));
    }
    None
}

/// Header names that carry a credential by convention.
fn header_names_a_secret(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "x-api-key" | "api-key" | "x-auth-token"
    ) || crate::scanners::env_files::is_secret_key_name(&lower.replace('-', "_"))
}

/// From a remote server's `headers`, the NAMES (never values) of credential headers set
/// to a hardcoded literal. `Bearer ${TOKEN}` is a reference; `Bearer abc123` is not.
pub fn inline_secret_header_keys(headers: Option<&serde_json::Value>) -> Vec<String> {
    let Some(obj) = headers.and_then(|v| v.as_object()) else {
        return Vec::new();
    };
    let mut out: Vec<String> = obj
        .iter()
        .filter(|(k, v)| header_names_a_secret(k) && v.as_str().is_some_and(|s| value_shape(s).contains("<redacted>")))
        .map(|(k, _)| sanitize_display(k, 128))
        .collect();
    out.sort();
    out
}

/// Why a stdio launch through a package runner runs whatever version is current, or
/// None when it names a fixed version (or is not a package-runner launch at all: a
/// `node ${CLAUDE_PLUGIN_ROOT}/server.js` ships with, and is pinned by, its plugin).
///
/// The spec is found by [`launch_spec`], which skips each launcher's own options and
/// their values (`uv run --with pkg script.py` runs the local `script.py`; reading `pkg`
/// as the launched package was wrong). Pinned: an exact version, an `@sha256:` digest, a
/// full commit, a local path. Unpinned:
///
/// - `npx` / `bunx` / `pnpx`: no version, `@latest`, another dist-tag or a range, or a
///   git spec (`github:o/r`, `o/r`, `git+https://...`) with no `#<commit>`;
/// - `uvx` / `pipx run` / `uv tool run` / `uv run`: a `git+` source with no commit (`git
///   HEAD`, or a branch/tag ref), `@latest`, a range, or a package with no `==` / `@`
///   version (`uv run` in a `--directory` / `--project` runs that local project);
/// - `docker` / `podman run`: no tag or `:latest`, unless pinned by `@sha256:` digest.
pub fn unpinned_reason(command: &str, raw_args: &[String]) -> Option<String> {
    let launch = launch_spec(command, raw_args)?;
    let spec = launch.spec;
    match launch.kind {
        LaunchKind::Npm => {
            if is_local_path(spec) {
                return None;
            }
            if let Some(r) = npm_git_reason(spec) {
                return r;
            }
            let (_, version) = split_npm_package_version(spec);
            npm_version_reason(version.as_deref())
        }
        LaunchKind::Python => {
            if launch.local_project {
                return None;
            }
            if spec.starts_with("git+") {
                return git_reason(spec);
            }
            // A local script or project path (`uv run server.py`, `uvx ./tool`) is not a
            // registry package.
            if spec.ends_with(".py") || is_local_path(spec) || spec.starts_with('$') || spec.contains('/') {
                return None;
            }
            if spec.split(['@', '=']).any(|p| p == "latest") {
                return Some("@latest".to_string());
            }
            match split_python_spec(spec) {
                (_, Some(_)) => None,
                _ if spec.contains(['<', '>', '~', '!', ',']) => Some("a version range".to_string()),
                _ => Some("no version".to_string()),
            }
        }
        LaunchKind::Docker => {
            if spec.contains("@sha256:") {
                return None;
            }
            match split_image(spec).1.as_deref() {
                None | Some("latest") => Some("docker :latest".to_string()),
                _ => None,
            }
        }
    }
}

/// A local path rather than a registry name: `./x`, `../x`, `/abs`, `~/x`, `file:x`.
fn is_local_path(spec: &str) -> bool {
    spec.starts_with(['.', '/', '~']) || spec.starts_with("file:")
}

/// For an npm git spec (`git+https://...`, `git://...`, `github:o/r`, `gitlab:`,
/// `bitbucket:`, `gist:`, or the `o/r` GitHub shorthand): `Some(None)` when pinned by
/// a full commit after `#`, else `Some(Some(reason))`. None: not a git spec.
fn npm_git_reason(spec: &str) -> Option<Option<String>> {
    let hosted = ["git+", "git://", "github:", "gitlab:", "bitbucket:", "gist:"]
        .iter()
        .any(|p| spec.starts_with(p));
    let shorthand = !spec.starts_with('@') && !spec.contains(':') && spec.contains('/');
    if !hosted && !shorthand {
        return None;
    }
    Some(match spec.split_once('#') {
        None => Some("git HEAD".to_string()),
        Some((_, r)) => {
            let hex = (r.len() == 40 || r.len() == 64) && r.chars().all(|c| c.is_ascii_hexdigit());
            (!hex).then(|| "a git branch or tag (not a commit)".to_string())
        }
    })
}

fn npm_version_reason(version: Option<&str>) -> Option<String> {
    match version {
        None | Some("") => Some("no version".to_string()),
        Some("latest") => Some("@latest".to_string()),
        Some(v)
            if v.chars().next().is_some_and(|c| c.is_ascii_digit())
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
                && !v.split('.').any(|p| p.eq_ignore_ascii_case("x")) =>
        {
            None
        }
        Some(v)
            if v.starts_with(['^', '~', '>', '<', '*', '='])
                || v.chars().next().is_some_and(|c| c.is_ascii_digit()) =>
        {
            Some("a version range".to_string())
        }
        Some(_) => Some("a moving dist-tag".to_string()),
    }
}

/// A `git+` source: pinned only by a full 40- or 64-hex commit after `@`.
fn git_reason(spec: &str) -> Option<String> {
    let after_scheme = spec.split_once("://").map_or(spec, |(_, r)| r);
    // The authority may hold `git@host`; the ref is after the LAST `@` of the path.
    let path = after_scheme.split_once('/').map_or("", |(_, p)| p);
    match path.rsplit_once('@') {
        None => Some("git HEAD".to_string()),
        Some((_, r)) => {
            let r = r.split(['#', '?']).next().unwrap_or(r);
            let hex = (r.len() == 40 || r.len() == 64) && r.chars().all(|c| c.is_ascii_hexdigit());
            (!hex).then(|| "a git branch or tag (not a commit)".to_string())
        }
    }
}

/// From an MCP server's `env` block, return the NAMES (never values) of secret-looking
/// keys whose value is a hardcoded literal — a credential committed into the config
/// rather than referenced from the environment via `${VAR}`/`$VAR`.
///
/// Preserves the no-secret-leakage guarantee: the value is inspected only to decide
/// whether it is a reference or a literal, and is never stored or emitted.
pub fn extract_inline_secret_env_keys(env: Option<&serde_json::Value>) -> Vec<String> {
    let Some(obj) = env.and_then(|v| v.as_object()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (key, val) in obj {
        let Some(value) = val.as_str() else { continue };
        if crate::scanners::env_files::is_secret_key_name(key) && is_inline_literal(value) {
            out.push(key.clone());
        }
    }
    out.sort();
    out
}

/// True if `value` is a hardcoded literal rather than an env reference or placeholder.
/// `${VAR}`, `$VAR`, `%VAR%`, empty, and obvious placeholders don't count as committed
/// secrets. The value is never stored — only classified.
fn is_inline_literal(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return false;
    }
    // Pure environment reference: "${TOKEN}", "$TOKEN", "%TOKEN%".
    let is_ref = (v.starts_with("${") && v.ends_with('}'))
        || (v.starts_with('$') && v[1..].chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        || (v.starts_with('%') && v.ends_with('%'));
    if is_ref {
        return false;
    }
    // Common "fill me in" placeholders aren't real committed secrets.
    let lower = v.to_ascii_lowercase();
    const PLACEHOLDERS: &[&str] = &[
        "your",
        "changeme",
        "change-me",
        "placeholder",
        "example",
        "xxx",
        "todo",
        "<",
        "...",
    ];
    if PLACEHOLDERS.iter().any(|p| lower.starts_with(p)) {
        return false;
    }
    true
}

/// Infer package ecosystem, name, and version from a launcher command and its args.
pub fn infer_package_from_command(command: &str, args: &[String]) -> (Option<String>, Option<String>, Option<String>) {
    let cmd_base = std::path::Path::new(command)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(command);

    match cmd_base {
        "python" | "python3" if args.first().is_some_and(|a| a == "-m") => {
            if let Some(module) = args.get(1) {
                (Some("pypi".to_string()), Some(module.clone()), None)
            } else {
                (None, None, None)
            }
        }
        "node" => {
            if let Some(script) = args.first() {
                (Some("npm".to_string()), Some(script.clone()), None)
            } else {
                (None, None, None)
            }
        }
        _ => match launch_spec(command, args) {
            Some(LaunchSpec {
                kind: LaunchKind::Npm,
                spec,
                ..
            }) => {
                let (name, version) = split_npm_package_version(spec);
                (Some("npm".to_string()), Some(name), version)
            }
            Some(LaunchSpec {
                kind: LaunchKind::Python,
                spec,
                ..
            }) => {
                let (name, version) = split_python_spec(spec);
                (Some("pypi".to_string()), Some(name), version)
            }
            Some(LaunchSpec {
                kind: LaunchKind::Docker,
                spec,
                ..
            }) => {
                let (name, version) = split_image(spec);
                (Some("docker".to_string()), Some(name), version)
            }
            None => (None, None, None),
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaunchKind {
    Npm,
    Python,
    Docker,
}

/// The package (or image) a package-runner launch fetches.
#[derive(Debug)]
struct LaunchSpec<'a> {
    kind: LaunchKind,
    /// The value of the launcher's package option (`npx -p`, `uvx --from`, `pipx run
    /// --spec`) when given, else its first positional argument.
    spec: &'a str,
    /// `uv run` in a `--directory` / `--project`: runs that local project.
    local_project: bool,
}

/// `uv` / `uvx` options that take a value (docs.astral.sh/uv/reference/cli: `uv run`,
/// `uv tool run`, and the global options valid before the subcommand).
const UV_VALUE_FLAGS: &[&str] = &[
    "--with",
    "--with-requirements",
    "--with-editable",
    "--python",
    "-p",
    "--from",
    "--index",
    "--default-index",
    "--index-url",
    "--extra-index-url",
    "--find-links",
    "-f",
    "--directory",
    "--project",
    "--package",
    "--extra",
    "--group",
    "--env-file",
    "--cache-dir",
    "--config-file",
];
/// `pipx run` options that take a value (pipx.pypa.io/stable/docs, `pipx run`).
const PIPX_RUN_VALUE_FLAGS: &[&str] = &["--spec", "--python", "--index-url", "-i", "--pip-args"];
/// `npx` options that take a value other than `-p` / `--package`
/// (docs.npmjs.com/cli/v10/commands/npx, and npm's common config flags).
const NPX_VALUE_FLAGS: &[&str] = &[
    "-c",
    "--call",
    "--registry",
    "--cache",
    "--userconfig",
    "--prefix",
    "-w",
    "--workspace",
];
/// `docker` / `podman` options before the subcommand that take a value.
const DOCKER_GLOBAL_VALUE_FLAGS: &[&str] = &["--context", "-c", "--host", "-H", "--config", "--log-level", "-l"];
/// `docker run` options that take a value (docs.docker.com/reference/cli/docker/container/run).
const DOCKER_RUN_VALUE_FLAGS: &[&str] = &[
    "-e",
    "--env",
    "--env-file",
    "-v",
    "--volume",
    "--mount",
    "-p",
    "--publish",
    "--expose",
    "--name",
    "--network",
    "--net",
    "--network-alias",
    "-w",
    "--workdir",
    "--entrypoint",
    "--platform",
    "-u",
    "--user",
    "--group-add",
    "-l",
    "--label",
    "--label-file",
    "-h",
    "--hostname",
    "--add-host",
    "--dns",
    "--cap-add",
    "--cap-drop",
    "--security-opt",
    "--device",
    "--gpus",
    "-m",
    "--memory",
    "--cpus",
    "--shm-size",
    "--ulimit",
    "--tmpfs",
    "--pull",
    "--restart",
    "--runtime",
    "--ipc",
    "--pid",
    "--userns",
    "--uts",
    "--log-driver",
    "--log-opt",
    "--cidfile",
    "--stop-signal",
    "--volumes-from",
    "-a",
    "--attach",
];

/// A launcher's leading options, read up to its first positional argument.
#[derive(Default)]
struct Options<'a> {
    /// The value of the last `spec_flags` option.
    spec: Option<&'a str>,
    /// Every option name seen (`--name=value` as `--name`).
    flags: Vec<&'a str>,
    /// The index of the first positional argument.
    positional: Option<usize>,
}

/// Read `args` up to the first positional, skipping the value of each option in
/// `value_flags` or `spec_flags` (a `--name=value` option is one argument).
fn read_options<'a>(args: &'a [String], value_flags: &[&str], spec_flags: &[&str]) -> Options<'a> {
    let mut out = Options::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            out.positional = (i + 1 < args.len()).then_some(i + 1);
            break;
        }
        if !a.starts_with('-') || a == "-" {
            out.positional = Some(i);
            break;
        }
        if let Some((flag, value)) = a.split_once('=').filter(|(f, _)| f.starts_with("--")) {
            if spec_flags.contains(&flag) {
                out.spec = Some(value);
            }
            out.flags.push(flag);
            i += 1;
            continue;
        }
        out.flags.push(a);
        if spec_flags.contains(&a) {
            out.spec = args.get(i + 1).map(String::as_str);
            i += 2;
        } else if value_flags.contains(&a) {
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

/// The package spec a package-runner launch fetches, or None for anything else.
fn launch_spec<'a>(command: &str, args: &'a [String]) -> Option<LaunchSpec<'a>> {
    let base = Path::new(command)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(command);
    let spec_or_positional =
        |args: &'a [String], o: &Options<'a>| o.spec.or_else(|| o.positional.map(|i| args[i].as_str()));
    match base {
        "npx" | "bunx" | "pnpx" => {
            let o = read_options(args, NPX_VALUE_FLAGS, &["-p", "--package"]);
            // `npx -c '<cmd>'` with no `-p` runs a command line, not a package.
            if o.spec.is_none() && o.flags.iter().any(|f| *f == "-c" || *f == "--call") {
                return None;
            }
            Some(LaunchSpec {
                kind: LaunchKind::Npm,
                spec: spec_or_positional(args, &o)?,
                local_project: false,
            })
        }
        "uvx" => {
            let o = read_options(args, UV_VALUE_FLAGS, &["--from"]);
            Some(LaunchSpec {
                kind: LaunchKind::Python,
                spec: spec_or_positional(args, &o)?,
                local_project: false,
            })
        }
        "uv" => {
            let global = read_options(args, UV_VALUE_FLAGS, &[]);
            let mut i = global.positional?;
            let (rest, from) = match args[i].as_str() {
                "run" => (&args[i + 1..], &[][..]),
                "tool" if args.get(i + 1).is_some_and(|a| a == "run") => {
                    i += 1;
                    (&args[i + 1..], &["--from"][..])
                }
                _ => return None,
            };
            let o = read_options(rest, UV_VALUE_FLAGS, from);
            let local_project = from.is_empty()
                && global
                    .flags
                    .iter()
                    .chain(&o.flags)
                    .any(|f| *f == "--directory" || *f == "--project");
            Some(LaunchSpec {
                kind: LaunchKind::Python,
                spec: spec_or_positional(rest, &o)?,
                local_project,
            })
        }
        "pipx" => {
            let global = read_options(args, &[], &[]);
            let i = global.positional?;
            if args[i] != "run" {
                return None;
            }
            let rest = &args[i + 1..];
            let o = read_options(rest, PIPX_RUN_VALUE_FLAGS, &["--spec"]);
            Some(LaunchSpec {
                kind: LaunchKind::Python,
                spec: spec_or_positional(rest, &o)?,
                local_project: false,
            })
        }
        "docker" | "podman" => {
            let global = read_options(args, DOCKER_GLOBAL_VALUE_FLAGS, &[]);
            let i = global.positional?;
            if args[i] != "run" {
                return None;
            }
            let rest = &args[i + 1..];
            let o = read_options(rest, DOCKER_RUN_VALUE_FLAGS, &[]);
            Some(LaunchSpec {
                kind: LaunchKind::Docker,
                spec: rest.get(o.positional?)?.as_str(),
                local_project: false,
            })
        }
        _ => None,
    }
}

/// Split a package spec into (name, version). Understands the PEP 440 specifiers and
/// uv's native `pkg@version` pin. A specifier we cannot pin exactly (>=, ~=, …) yields
/// no version, which the matcher treats as a conservative non-match rather than a guess.
fn split_python_spec(spec: &str) -> (String, Option<String>) {
    // uv's pin syntax: ruff@0.5.0
    if let Some((name, ver)) = spec.split_once('@')
        && !name.is_empty()
        && !ver.is_empty()
    {
        return (name.to_string(), Some(ver.to_string()));
    }
    if let Some(idx) = spec.find("==") {
        return (spec[..idx].to_string(), Some(spec[idx + 2..].to_string()));
    }
    // Range specifiers pin a set, not a version: record the name only.
    for op in ["===", ">=", "<=", "~=", "!=", ">", "<"] {
        if let Some(idx) = spec.find(op) {
            return (spec[..idx].to_string(), None);
        }
    }
    (spec.to_string(), None)
}

/// Split an image reference into (name, tag): `ghcr.io/o/mcp:1.4@sha256:..` is
/// (`ghcr.io/o/mcp`, `1.4`); a registry port (`host:5000/img`) is not a tag.
fn split_image(image: &str) -> (String, Option<String>) {
    let reference = image.split_once('@').map_or(image, |(r, _)| r);
    if let Some(idx) = reference.rfind(':') {
        let tag = &reference[idx + 1..];
        if !tag.contains('/') {
            return (reference[..idx].to_string(), Some(tag.to_string()));
        }
    }
    (reference.to_string(), None)
}

/// Split an npm package specifier into (name, optional version).
/// Handles scoped packages: @scope/name@1.2.3
pub fn split_npm_package_version(spec: &str) -> (String, Option<String>) {
    if let Some(rest) = spec.strip_prefix('@') {
        // Scoped: @scope/name@version or @scope/name
        if let Some(slash_idx) = rest.find('/') {
            let after_slash = &rest[slash_idx + 1..];
            if let Some(at_idx) = after_slash.find('@') {
                let name = format!("@{}", &rest[..slash_idx + 1 + at_idx]);
                let version = after_slash[at_idx + 1..].to_string();
                return (name, Some(version));
            }
            return (spec.to_string(), None);
        }
        return (spec.to_string(), None);
    }
    // Unscoped: name@version or name
    if let Some(at_idx) = spec.find('@') {
        let name = spec[..at_idx].to_string();
        let version = spec[at_idx + 1..].to_string();
        (name, Some(version))
    } else {
        (spec.to_string(), None)
    }
}

/// Sanitize a URL down to `scheme://host[:port]`, stripping userinfo, path, query, AND
/// fragment. The scheme is kept (http vs https drives the plaintext-transport finding);
/// everything that can carry a secret is dropped so the stored/displayed value never
/// leaks a token.
///
/// Robust against the same evasions as [`crate::scanners::agent_settings`]'s host
/// parsing: the authority ends at the first `/`, `?`, or `#` (so an `@`, `#`, or `?`
/// in the path/query can't be mistaken for the host), and userinfo is stripped at the
/// LAST `@` within the authority.
fn sanitize_url(url: &str) -> String {
    let (scheme, host_port) = crate::scanners::split_url_authority(url);
    if scheme.is_empty() {
        // No scheme to anchor on (e.g. "stdio://local" has one; "local" does not) —
        // leave it untouched rather than guess at an authority.
        return url.to_string();
    }
    format!("{scheme}://{host_port}")
}

/// Convert a YAML config to the canonical JSON value so ONE parser handles every
/// format — names, package identity, env inline secrets, transport, the lot.
pub fn yaml_to_json(content: &str) -> Option<serde_json::Value> {
    let yaml_value: serde_yaml_ng::Value = serde_yaml_ng::from_str(content).ok()?;
    serde_json::to_value(&yaml_value).ok()
}

/// Convert a TOML config (Codex `~/.codex/config.toml`) to the canonical JSON value.
pub fn toml_to_json(content: &str) -> Option<serde_json::Value> {
    let table: toml::Table = content.parse().ok()?;
    serde_json::to_value(&table).ok()
}

pub fn extract_mcp_servers_yaml(content: &str) -> Vec<String> {
    yaml_to_json(content)
        .map(|v| extract_mcp_servers(&v))
        .unwrap_or_default()
}

pub fn extract_mcp_servers_toml(content: &str) -> Vec<String> {
    toml_to_json(content)
        .map(|v| extract_mcp_servers(&v))
        .unwrap_or_default()
}

#[cfg(test)]
mod inline_secret_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn flags_hardcoded_secret_values_by_name_only() {
        let env = json!({
            "GITHUB_TOKEN": "ghp_realsecretvalue123",
            "API_KEY": "sk-livekey",
            "LOG_LEVEL": "debug"
        });
        let keys = extract_inline_secret_env_keys(Some(&env));
        // Only secret-looking NAMES with literal values; sorted; value never surfaced.
        assert_eq!(keys, vec!["API_KEY".to_string(), "GITHUB_TOKEN".to_string()]);
    }

    #[test]
    fn ignores_env_references_and_placeholders() {
        let env = json!({
            "GITHUB_TOKEN": "${GITHUB_TOKEN}",
            "API_KEY": "$API_KEY",
            "WIN_SECRET": "%WIN_SECRET%",
            "AUTH_TOKEN": "your-token-here",
            "DB_PASSWORD": ""
        });
        assert!(extract_inline_secret_env_keys(Some(&env)).is_empty());
    }

    #[test]
    fn no_env_block_is_clean() {
        assert!(extract_inline_secret_env_keys(None).is_empty());
        assert!(extract_inline_secret_env_keys(Some(&json!("not-an-object"))).is_empty());
    }

    #[test]
    fn parse_server_detail_populates_inline_secrets() {
        let cfg = json!({
            "command": "npx",
            "args": ["-y", "some-mcp"],
            "env": {"SERVICE_SECRET": "hardcoded", "PORT": "8080"}
        });
        let detail = parse_server_detail("s", &cfg);
        assert_eq!(detail.inline_secret_env_keys, vec!["SERVICE_SECRET".to_string()]);
    }

    /// TOML (Codex) configs go through the same canonical parser, so package
    /// identity AND inline env secrets are extracted — previously TOML got
    /// names only and every per-server detection was silently skipped.
    #[test]
    fn toml_config_gets_full_server_details() {
        let toml = r#"
[mcp_servers.leaky]
command = "npx"
args = ["-y", "some-mcp"]

[mcp_servers.leaky.env]
SLACK_TOKEN = "xoxb-hardcoded"
PORT = "8080"
"#;
        let v = toml_to_json(toml).expect("valid toml converts");
        let details = extract_mcp_server_details(&v);
        assert_eq!(details.len(), 1);
        let d = &details[0];
        assert_eq!(d.name, "leaky");
        assert_eq!(d.package_name.as_deref(), Some("some-mcp"));
        assert_eq!(d.inline_secret_env_keys, vec!["SLACK_TOKEN".to_string()]);
    }

    #[test]
    fn sanitize_url_never_leaks_credentials() {
        // Userinfo, query tokens, and fragment tokens must all be stripped; the host
        // must be parsed correctly even when '@'/'?'/'#' appear in path or query.
        let cases = [
            ("https://user:SECRETPASS@host.com/p?token=ABC", "https://host.com"),
            ("https://host.com#token=SECRET", "https://host.com"),
            ("https://host.com?a=1@evil.com/p", "https://host.com"),
            ("http://tok@a/b@c", "http://a"),
            ("https://host.com:8443/path", "https://host.com:8443"),
            ("stdio://local", "stdio://local"),
            ("no-scheme-here", "no-scheme-here"),
        ];
        for (input, expected) in cases {
            assert_eq!(sanitize_url(input), expected, "input: {input}");
        }
        // No secret token should ever survive.
        for leaky in [
            "https://u:SECRETPASS@h/x",
            "https://h#SECRETPASS",
            "https://h?k=SECRETPASS",
        ] {
            assert!(
                !sanitize_url(leaky).contains("SECRETPASS"),
                "leaked secret in: {leaky} -> {}",
                sanitize_url(leaky)
            );
        }
    }

    #[test]
    fn yaml_config_gets_full_server_details() {
        let yaml = r#"
mcpServers:
  fetcher:
    command: uvx
    args: ["mcp-server-fetch"]
    env:
      API_KEY: literal-value
"#;
        let v = yaml_to_json(yaml).expect("valid yaml converts");
        let details = extract_mcp_server_details(&v);
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].inline_secret_env_keys, vec!["API_KEY".to_string()]);
        assert_eq!(details[0].package_name.as_deref(), Some("mcp-server-fetch"));
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    /// Shapes never carry a literal: a reference default and anything that is not a
    /// reference are `<redacted>`.
    #[test]
    fn value_shapes() {
        for (input, want) in [
            ("${KEY}", "${KEY}"),
            ("${KEY:-}", "${KEY}"),
            ("${KEY:-sk-live-SECRET}", "${KEY:-<redacted>}"),
            ("$KEY", "$KEY"),
            ("%KEY%", "%KEY%"),
            ("${user_config.api_token}", "${user_config.api_token}"),
            ("Bearer ${TOKEN}", "Bearer ${TOKEN}"),
            ("Bearer abc123SECRET", "Bearer <redacted>"),
            ("ghp_SECRETVALUE", "<redacted>"),
            ("${A}${B}", "<redacted>"),
            ("prefix-${A}", "<redacted>"),
            ("", "<empty>"),
        ] {
            assert_eq!(value_shape(input), want, "{input}");
            assert!(!value_shape(input).contains("SECRET"), "{input}");
        }
    }

    #[test]
    fn literal_credential_headers_by_name() {
        let h = serde_json::json!({
            "Authorization": "Bearer abc",
            "X-Api-Key": "${KEY}",
            "Accept": "application/json"
        });
        assert_eq!(inline_secret_header_keys(Some(&h)), vec!["Authorization".to_string()]);
    }

    #[test]
    fn unpinned_launches() {
        let r = |c: &str, a: &[&str]| unpinned_reason(c, &args(a));
        assert_eq!(r("npx", &["@playwright/mcp@latest"]).as_deref(), Some("@latest"));
        assert_eq!(r("npx", &["-y", "some-mcp"]).as_deref(), Some("no version"));
        assert_eq!(r("npx", &["-y", "some-mcp@^1.2.0"]).as_deref(), Some("a version range"));
        assert_eq!(r("npx", &["-y", "some-mcp@1.x"]).as_deref(), Some("a version range"));
        assert_eq!(r("npx", &["-y", "some-mcp@next"]).as_deref(), Some("a moving dist-tag"));
        assert_eq!(r("npx", &["-y", "some-mcp@1.2.3"]), None);
        assert_eq!(r("npx", &["-y", "@scope/pkg@2.0.0-beta.1"]), None);
        assert_eq!(
            r("uvx", &["--from", "git+https://github.com/o/serena", "serena"]).as_deref(),
            Some("git HEAD")
        );
        assert_eq!(
            r("uvx", &["--from", "git+ssh://git@github.com/o/serena", "serena"]).as_deref(),
            Some("git HEAD"),
            "the userinfo `git@` is not a ref"
        );
        assert_eq!(
            r("uvx", &["--from", "git+https://github.com/o/serena@main", "serena"]).as_deref(),
            Some("a git branch or tag (not a commit)")
        );
        let sha = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(
            r(
                "uvx",
                &["--from", &format!("git+https://github.com/o/serena@{sha}"), "serena"]
            ),
            None
        );
        assert_eq!(r("uvx", &["mcp-server-fetch"]).as_deref(), Some("no version"));
        assert_eq!(r("uvx", &["mcp-server-fetch==1.0.0"]), None);
        assert_eq!(r("uv", &["run", "server.py"]), None);
        assert_eq!(r("uv", &["tool", "run", "mcp-thing"]).as_deref(), Some("no version"));
        assert_eq!(r("uv", &["pip", "install"]), None);
        assert_eq!(
            r("docker", &["run", "-i", "ghcr.io/o/mcp"]).as_deref(),
            Some("docker :latest")
        );
        assert_eq!(r("docker", &["run", "ghcr.io/o/mcp:1.4"]), None);
        assert_eq!(r("docker", &["run", "ghcr.io/o/mcp@sha256:abcd"]), None);
        // Bundled with the plugin: pinned by the plugin itself.
        assert_eq!(r("node", &["${CLAUDE_PLUGIN_ROOT}/server.js"]), None);
    }

    /// Launcher options and their values are not the package: each launcher's
    /// value-taking flags are skipped, its package option (`npx -p`, `uvx --from`,
    /// `pipx run --spec`) is the spec, and the first positional is the package or image.
    /// On 4e23ef8 `uv run --with pkg script.py` read `pkg` (no version), `docker run -e
    /// TOKEN img:1.4` read the image `TOKEN`, and `uvx --python 3.12 pkg==1.0` read `3.12`.
    #[test]
    fn launcher_flags_are_not_packages() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let git_sha = format!("git+https://github.com/o/serena@{sha}");
        let npm_sha = format!("github:o/r#{sha}");
        // (command, args, unpinned reason, inferred package name)
        type Row<'a> = (&'a str, &'a [&'a str], Option<&'a str>, Option<&'a str>);
        let table: &[Row] = &[
            // uv run / uvx: values of --with, --python, -p, --from, --index, ...
            ("uv", &["run", "--with", "pkg", "script.py"], None, Some("script.py")),
            (
                "uv",
                &["run", "--with", "mcp[cli]", "--with-requirements", "r.txt", "server.py"],
                None,
                Some("server.py"),
            ),
            (
                "uv",
                &["run", "--python", "3.12", "mcp-thing"],
                Some("no version"),
                Some("mcp-thing"),
            ),
            (
                "uv",
                &["--directory", "/srv/weather", "run", "weather"],
                None,
                Some("weather"),
            ),
            ("uv", &["run", "--project", "/srv/w", "weather"], None, Some("weather")),
            (
                "uv",
                &["tool", "run", "--from", "mcp-x==1.0.0", "mcp-x"],
                None,
                Some("mcp-x"),
            ),
            (
                "uvx",
                &["--python", "3.12", "mcp-server-fetch==1.0.0"],
                None,
                Some("mcp-server-fetch"),
            ),
            (
                "uvx",
                &["-p", "3.12", "mcp-server-fetch"],
                Some("no version"),
                Some("mcp-server-fetch"),
            ),
            (
                "uvx",
                &["--index", "https://idx.example/simple", "pkg@1.2.3"],
                None,
                Some("pkg"),
            ),
            (
                "uvx",
                &["--extra-index-url", "https://idx.example/simple", "pkg"],
                Some("no version"),
                Some("pkg"),
            ),
            ("uvx", &["--with", "extra-dep", "pkg==2.0"], None, Some("pkg")),
            ("uvx", &["--from", "mcp-x==1.0.0", "mcp-x"], None, Some("mcp-x")),
            ("uvx", &["--from", "mcp-x", "mcp-x"], Some("no version"), Some("mcp-x")),
            ("uvx", &["--from=mcp-x==1.0.0", "mcp-x"], None, Some("mcp-x")),
            ("uvx", &["--from", "./local/tool", "tool"], None, Some("./local/tool")),
            ("uvx", &["--from", &git_sha, "serena"], None, None),
            (
                "uvx",
                &["--from", "git+https://github.com/o/serena", "serena"],
                Some("git HEAD"),
                None,
            ),
            ("uvx", &["pkg@latest"], Some("@latest"), Some("pkg")),
            ("uvx", &["pkg>=1.0"], Some("a version range"), Some("pkg")),
            ("uvx", &["--directory", "/x", "pkg==1.0"], None, Some("pkg")),
            // npx: -p / --package is the spec; other value flags are skipped.
            (
                "npx",
                &["-y", "-p", "some-mcp@1.2.3", "some-mcp"],
                None,
                Some("some-mcp"),
            ),
            (
                "npx",
                &["-p", "some-mcp", "some-mcp@1.2.3"],
                Some("no version"),
                Some("some-mcp"),
            ),
            (
                "npx",
                &["--package=some-mcp@latest", "bin"],
                Some("@latest"),
                Some("some-mcp"),
            ),
            (
                "npx",
                &["--registry", "https://r.example", "some-mcp@1.2.3"],
                None,
                Some("some-mcp"),
            ),
            (
                "npx",
                &["--registry", "https://r.example", "some-mcp"],
                Some("no version"),
                Some("some-mcp"),
            ),
            ("npx", &["-y", "./local-server"], None, Some("./local-server")),
            ("npx", &["-y", "github:o/r"], Some("git HEAD"), Some("github:o/r")),
            (
                "npx",
                &["-y", "o/r#main"],
                Some("a git branch or tag (not a commit)"),
                Some("o/r#main"),
            ),
            ("npx", &["-y", &npm_sha], None, Some(&npm_sha)),
            ("npx", &["-c", "echo hi"], None, None),
            // pipx run: --spec is the spec, --python skipped.
            ("pipx", &["run", "--spec", "mcp-x==1.0", "mcp-x"], None, Some("mcp-x")),
            (
                "pipx",
                &["run", "--spec", "mcp-x", "mcp-x"],
                Some("no version"),
                Some("mcp-x"),
            ),
            ("pipx", &["run", "--python", "3.12", "mcp-x==1.0"], None, Some("mcp-x")),
            (
                "pipx",
                &["run", "--python", "3.12", "mcp-x"],
                Some("no version"),
                Some("mcp-x"),
            ),
            ("pipx", &["install", "mcp-x"], None, None),
            // docker run: values of -e, -v, -p, --name, --network, -w, --entrypoint, ...
            (
                "docker",
                &[
                    "run",
                    "-i",
                    "--rm",
                    "-e",
                    "GITHUB_TOKEN",
                    "ghcr.io/github/github-mcp-server:1.4",
                ],
                None,
                Some("ghcr.io/github/github-mcp-server"),
            ),
            (
                "docker",
                &[
                    "run",
                    "-i",
                    "--rm",
                    "-e",
                    "GITHUB_TOKEN",
                    "ghcr.io/github/github-mcp-server",
                ],
                Some("docker :latest"),
                Some("ghcr.io/github/github-mcp-server"),
            ),
            (
                "docker",
                &["run", "-v", "/a:/b", "-p", "8080:80", "--name", "m", "img:2"],
                None,
                Some("img"),
            ),
            (
                "docker",
                &["run", "--network", "host", "-w", "/w", "--entrypoint", "sh", "img"],
                Some("docker :latest"),
                Some("img"),
            ),
            (
                "docker",
                &["run", "--platform", "linux/amd64", "--user", "1000", "img:latest"],
                Some("docker :latest"),
                Some("img"),
            ),
            ("docker", &["run", "-e", "A=1", "img@sha256:abcd"], None, Some("img")),
            (
                "docker",
                &["run", "--env=A=1", "localhost:5000/img"],
                Some("docker :latest"),
                Some("localhost:5000/img"),
            ),
            ("podman", &["run", "-e", "K", "img:1.0@sha256:abcd"], None, Some("img")),
            ("docker", &["--context", "remote", "run", "img:3"], None, Some("img")),
            ("docker", &["ps"], None, None),
        ];
        for (cmd, a, reason, name) in table {
            let a = args(a);
            assert_eq!(unpinned_reason(cmd, &a).as_deref(), *reason, "unpinned: {cmd} {a:?}");
            if let Some(name) = name {
                assert_eq!(
                    infer_package_from_command(cmd, &a).1.as_deref(),
                    Some(*name),
                    "package: {cmd} {a:?}"
                );
            } else if !a.iter().any(|x| x.starts_with("git+")) {
                assert_eq!(infer_package_from_command(cmd, &a).1, None, "package: {cmd} {a:?}");
            }
        }
    }

    #[test]
    fn plugin_server_maps_both_shapes() {
        let wrapped = serde_json::json!({"mcpServers": {"a": {"command": "x"}}});
        let bare = serde_json::json!({"a": {"command": "x"}, "note": "not a server"});
        assert_eq!(server_map(&wrapped).keys().collect::<Vec<_>>(), ["a"]);
        assert_eq!(server_map(&bare).keys().collect::<Vec<_>>(), ["a"]);
    }

    #[test]
    fn manifest_paths_stay_inside_the_plugin() {
        let root = Path::new("/p/cache/m/x/1");
        assert!(manifest_json_path(root, "./mcp/a.json").is_some());
        assert!(manifest_json_path(root, "mcp/a.json").is_none());
        assert!(manifest_json_path(root, "./../escape.json").is_none());
        assert!(manifest_json_path(root, "./bundle.mcpb").is_none());
        assert!(manifest_json_path(root, "https://example.com/s.json").is_none());
    }

    #[test]
    fn log_keys_match_claude_code_directory_names() {
        let plugin = McpServerDetail {
            name: "playwright".into(),
            plugin: Some("playwright@claude-plugins-official".into()),
            ..Default::default()
        };
        assert_eq!(server_log_key(&plugin), log_key("plugin-playwright-playwright"));
        let conn = McpServerDetail {
            name: "claude.ai Google Drive".into(),
            ..Default::default()
        };
        assert_eq!(server_log_key(&conn), log_key("claude-ai-Google-Drive"));
    }
}
