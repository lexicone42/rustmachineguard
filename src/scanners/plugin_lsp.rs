//! LSP servers that Claude Code plugins declare. Claude Code starts each one as a
//! process, the way it starts a stdio MCP server, so each one is a launch surface.
//!
//! Source: the Plugin manifest reference (code.claude.com/docs/en/plugins-reference.md,
//! fetched 2026-10-24).
//!
//! - `lspServers` takes "a `.json` file path, an inline map of server name to config, or
//!   an array of either".
//! - "Claude Code loads `.lsp.json` at the plugin root first, then each declared config
//!   in order. A server name declared later replaces an earlier one."
//! - Each config has `command` and `extensionToLanguage`, plus optional `args`,
//!   `transport`, `env`, `initializationOptions`, `settings`, `workspaceFolder`,
//!   `startupTimeout`, `shutdownTimeout`, `requestTimeout`, `restartOnCrash`,
//!   `maxRestarts` and `diagnostics`.
//!
//! The marketplace reference (code.claude.com/docs/en/plugins/marketplace-reference.md)
//! covers plugins without a `plugin.json`: "the entry is the manifest regardless of
//! `strict`. Every manifest field that the entry accepts applies, including
//! `mcpServers`, `lspServers`". When a `plugin.json` is present, "Entry `mcpServers`,
//! `lspServers`, `userConfig`, and `channels` don't apply". Anthropic's official
//! marketplace ships its `*-lsp` plugins this way: the cache directory holds only a
//! README, and the servers are in the `marketplace.json` entry.
//!
//! Containment follows plugin MCP servers ([`crate::scanners::mcp::plugin_servers`]):
//! - only installed versions are read, and only when their real path is inside the real
//!   plugin cache;
//! - a declared file must start with `./`, end in `.json` and stay inside the plugin
//!   root;
//! - files are opened without following a link, at a real path inside the root's real
//!   path.
//!
//! A marketplace manifest is read only from the marketplace clone, as a regular file
//! whose real path stays inside it ([`crate::scanners::marketplaces`]).
//!
//! Nothing is run. Arguments are kept by shape only: flags as written, every other
//! argument as `<arg>`.

use crate::models::AgentLspServer;
use crate::platform::PlatformInfo;
use crate::scanners::{Scanner, sanitize_display};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct PluginLspScanner;

/// Servers one plugin may declare: more are not read.
const MAX_SERVERS_PER_PLUGIN: usize = 50;
/// `lspServers` array entries that are followed.
const MAX_DECLARED_ENTRIES: usize = 20;
/// Arguments and extensions kept per server.
const MAX_ARGS: usize = 64;
const MAX_EXTENSIONS: usize = 64;

impl Scanner for PluginLspScanner {
    type Output = Vec<AgentLspServer>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<AgentLspServer> {
        plugin_lsp_servers(&platform.home_dir())
    }
}

/// The LSP servers of every installed plugin version of `home`, sorted by (plugin, name).
pub fn plugin_lsp_servers(home: &Path) -> Vec<AgentLspServer> {
    let ctx = crate::scanners::skills::PluginContext::load(home);
    let mut ips: Vec<(PathBuf, String, String)> = ctx.install_paths().to_vec();
    ips.sort();
    ips.dedup_by(|a, b| a.0 == b.0);
    let mut out = Vec::new();
    let plugins_dir = home.join(".claude").join("plugins");
    let Ok(real_cache) = std::fs::canonicalize(plugins_dir.join("cache")) else {
        return out;
    };
    let mut manifests = MarketplaceManifests::new(&plugins_dir);
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
        // (source file, server map), in load order.
        let mut sources: Vec<(PathBuf, serde_json::Map<String, serde_json::Value>)> = Vec::new();
        let dot_lsp = ip.join(".lsp.json");
        if let Some(v) = crate::scanners::mcp::read_plugin_json(&real_root, &dot_lsp) {
            sources.push((dot_lsp, lsp_map(&v)));
        }
        let manifest = ip.join(".claude-plugin").join("plugin.json");
        let has_manifest = std::fs::symlink_metadata(&manifest).is_ok();
        // With a plugin.json the manifest declares; without one the marketplace entry is
        // the manifest.
        let (declared, declared_in) = if has_manifest {
            (
                crate::scanners::mcp::read_plugin_json(&real_root, &manifest)
                    .and_then(|m| m.get("lspServers").cloned()),
                manifest,
            )
        } else {
            match manifests.entry(market, plugin) {
                Some((path, entry)) => (entry.get("lspServers").cloned(), path),
                None => (None, manifest),
            }
        };
        if let Some(d) = declared {
            let items: Vec<serde_json::Value> = match d {
                serde_json::Value::Array(a) => a.into_iter().take(MAX_DECLARED_ENTRIES).collect(),
                v => vec![v],
            };
            let mut inline = serde_json::Map::new();
            for item in items {
                match item {
                    serde_json::Value::String(rel) => {
                        if let Some(p) = crate::scanners::mcp::manifest_json_path(ip, &rel)
                            && let Some(v) = crate::scanners::mcp::read_plugin_json(&real_root, &p)
                        {
                            sources.push((p, lsp_map(&v)));
                        }
                    }
                    serde_json::Value::Object(map) => inline.extend(map),
                    _ => {}
                }
            }
            if !inline.is_empty() {
                sources.push((declared_in, inline));
            }
        }
        // Later declarations replace earlier ones of the same name.
        let mut taken = std::collections::HashSet::new();
        for (path, map) in sources.into_iter().rev() {
            for (name, cfg) in map {
                if cfg.is_object() && taken.len() < MAX_SERVERS_PER_PLUGIN && taken.insert(name.clone()) {
                    out.push(server_row(&label, &name, &cfg, &path, enabled));
                }
            }
        }
    }
    out.sort_by(|a, b| (&a.plugin, &a.name).cmp(&(&b.plugin, &b.name)));
    out
}

/// A `.lsp.json` (or a file `lspServers` names): the name -> config map, or the same
/// wrapped in `{"lspServers": {...}}`.
fn lsp_map(v: &serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    if let Some(m) = v.get("lspServers").and_then(|m| m.as_object()) {
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

/// One inventory row from a server config.
fn server_row(label: &str, name: &str, cfg: &serde_json::Value, source: &Path, enabled: bool) -> AgentLspServer {
    let command = cfg.get("command").and_then(|v| v.as_str()).unwrap_or("");
    let raw_args: Vec<String> = cfg
        .get("args")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    // A package-runner launch only: `node <script>` / `python -m <module>` name a local
    // script or module, which is not a fetched package (and is kept by shape).
    let base = program_shape(command);
    let (_, pkg, version) = if command.is_empty() || matches!(base.as_str(), "node" | "python" | "python3") {
        (None, None, None)
    } else {
        crate::scanners::mcp::infer_package_from_command(command, &raw_args)
    };
    let package = pkg.map(|p| match version {
        Some(v) => sanitize_display(&format!("{p}@{v}"), 256),
        None => sanitize_display(&p, 256),
    });
    let unpinned = if command.is_empty() {
        None
    } else {
        crate::scanners::mcp::unpinned_reason(command, &raw_args)
    };
    let mut extensions: Vec<String> = cfg
        .get("extensionToLanguage")
        .and_then(|v| v.as_object())
        .map(|o| o.keys().take(MAX_EXTENSIONS).map(|k| sanitize_display(k, 32)).collect())
        .unwrap_or_default();
    extensions.sort();
    AgentLspServer {
        plugin: label.to_string(),
        name: sanitize_display(name, 128),
        source: sanitize_display(&source.to_string_lossy(), 512),
        program: base,
        args: raw_args.iter().take(MAX_ARGS).map(|a| arg_shape(a)).collect(),
        package,
        unpinned,
        env: crate::scanners::mcp::shapes(cfg.get("env"), "="),
        extensions,
        enabled,
    }
}

/// The program by shape: a plugin-relative path (`${CLAUDE_PLUGIN_ROOT}/bin/server`) as
/// written, anything else by its basename.
pub(crate) fn program_shape(command: &str) -> String {
    let c = command.trim();
    if c.starts_with("${CLAUDE_PLUGIN_ROOT}") || c.starts_with("${CLAUDE_PLUGIN_DATA}") {
        return sanitize_display(&crate::scanners::redact_secrets_in_text(c), 256);
    }
    let base = c.rsplit(['/', '\\']).next().unwrap_or(c);
    sanitize_display(&crate::scanners::redact_secrets_in_text(base), 128)
}

/// Single-dash words an LSP launch uses as option NAMES (Go and Java style): kept as
/// written. Any other single-dash word longer than one letter is a short flag with its
/// value attached (`-pHunter2`, `-HAuthorization: Bearer X`) and shows as `-p<value>`.
const SINGLE_DASH_WORDS: &[&str] = &[
    "stdio",
    "lsp",
    "mode",
    "remote",
    "rpc",
    "debug",
    "verbose",
    "logfile",
    "listen",
    "serve",
    "server",
    "help",
    "version",
    "vv",
    "vvv",
    "trace",
    "pipe",
    "socket",
    "node-ipc",
    "jar",
    "cp",
    "classpath",
    "server-mode",
];

/// One argument by shape: a flag as written (`--stdio`), a flag with an attached value as
/// `--flag=<value>`, a short flag with an attached value as `-p<value>`, a plugin-relative
/// path as written (redacted with the MCP argument rule, [`crate::scanners::mcp::redact_arg`]),
/// anything else `<arg>`. A value never appears.
pub(crate) fn arg_shape(arg: &str) -> String {
    let a = arg.trim();
    if a.starts_with('-') && a.len() > 1 {
        let flag = match a.split_once('=') {
            Some((f, _)) => format!("{f}=<value>"),
            None if !a.starts_with("--") && a.len() > 2 && !SINGLE_DASH_WORDS.contains(&&a[1..]) => {
                let first = a[1..].chars().next().unwrap_or('?');
                format!("-{first}<value>")
            }
            None => a.to_string(),
        };
        return sanitize_display(&flag, 64);
    }
    if a.starts_with("${CLAUDE_PLUGIN_ROOT}") || a.starts_with("${CLAUDE_PLUGIN_DATA}") {
        return sanitize_display(&crate::scanners::mcp::redact_arg(a, None), 256);
    }
    "<arg>".to_string()
}

/// `marketplace.json` plugin entries, read once per marketplace.
struct MarketplaceManifests {
    plugins_dir: PathBuf,
    known: Option<serde_json::Value>,
    read: HashMap<String, Option<(PathBuf, Vec<serde_json::Value>)>>,
}

impl MarketplaceManifests {
    fn new(plugins_dir: &Path) -> Self {
        let known = crate::scanners::read_bounded(&plugins_dir.join("known_marketplaces.json"))
            .and_then(|t| serde_json::from_str(&t).ok());
        MarketplaceManifests {
            plugins_dir: plugins_dir.to_path_buf(),
            known,
            read: HashMap::new(),
        }
    }

    /// The entry named `plugin` in marketplace `market`'s manifest, with the manifest's path.
    fn entry(&mut self, market: &str, plugin: &str) -> Option<(PathBuf, serde_json::Value)> {
        if !self.read.contains_key(market) {
            let loaded = self.load(market);
            self.read.insert(market.to_string(), loaded);
        }
        let (path, list) = self.read.get(market)?.as_ref()?;
        list.iter()
            .find(|p| p.get("name").and_then(|v| v.as_str()) == Some(plugin))
            .map(|p| (path.clone(), p.clone()))
    }

    /// The clone is the default `marketplaces/<name>`, or `installLocation` only when it stays
    /// inside `marketplaces/` (as `scanners::marketplaces` reads it).
    fn load(&self, market: &str) -> Option<(PathBuf, Vec<serde_json::Value>)> {
        let market_root = self.plugins_dir.join("marketplaces");
        let default = market_root.join(market);
        let clone = self
            .known
            .as_ref()
            .and_then(|k| k.get(market))
            .and_then(|e| e.get("installLocation"))
            .and_then(|v| v.as_str())
            .map(PathBuf::from)
            .filter(|p| crate::scanners::marketplaces::lexically_under(p, &market_root))
            .unwrap_or(default);
        if !crate::scanners::marketplaces::lexically_under(&clone, &market_root) {
            return None;
        }
        let manifest = clone.join(".claude-plugin").join("marketplace.json");
        if !crate::scanners::probe_file(&manifest) {
            return None;
        }
        let real = crate::scanners::marketplaces::contained_real_path(&manifest, &clone)?;
        let text = crate::scanners::read_bounded_nofollow(&manifest, Some(&real))?;
        let v: serde_json::Value = serde_json::from_str(&text).ok()?;
        let list = v.get("plugins")?.as_array()?.clone();
        Some((manifest, list))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_are_kept_by_shape() {
        assert_eq!(arg_shape("--stdio"), "--stdio");
        assert_eq!(arg_shape("--token=abc123"), "--token=<value>");
        assert_eq!(arg_shape("s3cr3t"), "<arg>");
        assert_eq!(arg_shape("/home/u/x"), "<arg>");
        assert_eq!(
            arg_shape("${CLAUDE_PLUGIN_ROOT}/bin/ls"),
            "${CLAUDE_PLUGIN_ROOT}/bin/ls"
        );
        assert_eq!(program_shape("/usr/local/bin/rust-analyzer"), "rust-analyzer");
        assert_eq!(program_shape("npx"), "npx");
    }

    #[test]
    fn lsp_map_takes_both_shapes() {
        let bare = serde_json::json!({"go": {"command": "gopls"}, "x": 1});
        assert_eq!(lsp_map(&bare).len(), 1);
        let wrapped = serde_json::json!({"lspServers": {"go": {"command": "gopls"}}});
        assert_eq!(lsp_map(&wrapped).len(), 1);
    }
}
