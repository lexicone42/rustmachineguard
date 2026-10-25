//! Mistral Vibe (`vibe`, `vibe-acp`) as a first-class agent: its configuration, MCP
//! servers, session stores and API-key file.
//!
//! Primary sources, fetched 2026-10-24:
//! - the README at github.com/mistralai/mistral-vibe (raw `README.md`) and its
//!   `docs/acp-setup.md`;
//! - the configuration reference at docs.mistral.ai/vibe/code/cli/configuration-reference.md;
//! - the installed 2.5.0 source (`vibe/core/config/_settings.py`,
//!   `vibe/core/paths/_vibe_home.py`, `vibe/core/trusted_folders.py`,
//!   `vibe/core/tools/base.py`).
//!
//! What each key is and how it is handled:
//!
//! - `[[mcp_servers]]`: "One `[[mcp_servers]]` table per server", with `name`,
//!   `transport` (`http`, `streamable-http`, `stdio`), `url`, `command`, `args` and
//!   `env`. These become `mcp_configs` rows (source "Mistral Vibe"), with `env` and
//!   `headers` by shape only. `command` may be a list (2.5.0: `str | list[str]`).
//! - `tools.<name>.permission`: "`"always"` to auto-allow the tool, `"ask"` to prompt
//!   before use, `"never"` to block it". `tools.bash.permission = "always"` is graded.
//! - `auto_approve` (2.5.0 `auto_approve: bool = False`): when true, `agent_loop`
//!   executes every tool call without asking. It is absent from the current docs,
//!   which have an admin `enable_auto_approve` instead. It is graded where present.
//! - `enable_auto_update` (2.5.0 default true): runs the package manager's upgrade
//!   command when an update is available (`cli/textual_ui/app.py`, `do_update`). The
//!   current docs say it "has no effect either: use `enable_update_checks`". It is
//!   graded Low, and the title says which version was seen acting on it.
//! - `enable_telemetry`, `enable_update_checks` and `bypass_tool_permissions`:
//!   inventory only. `bypass_tool_permissions` is named in the current docs, but its
//!   effect is not confirmed in the 2.5.0 source, so it is not graded.
//! - `tool_paths`, `agent_paths`, `skill_paths`: hot-load directories. They are listed
//!   lexically and NOT walked (a floor). `tool_paths` is 2.5.0 only; the README says
//!   custom tools "will be deprecated".
//! - `~/.vibe/trusted_folders.toml`: the README names the file. The keys `trusted` and
//!   `untrusted` are confirmed from the 2.5.0 source only.
//! - Session stores, graded with the transcript-store rule:
//!   - `session_logging.save_dir` (default `~/.vibe/logs/session`; docs: "Directory
//!     where sessions are saved");
//!   - `~/.vibe/vibehistory` (2.5.0 `HISTORY_FILE`);
//!   - `~/.vibe/plans`.
//! - `~/.vibe/.env`: "Vibe automatically loads API keys from `~/.vibe/.env`". It is
//!   recorded by mode only and never opened.
//!
//! `VIBE_HOME` relocates everything. It is the scanning user's own environment, so it
//! is not applied to a scanned home (a floor).

use crate::models::{AgentTranscriptStore, McpConfig, VibeConfig, VibeEnvFile};
use crate::platform::PlatformInfo;
use crate::scanners::sanitize_display;
use std::path::{Path, PathBuf};

/// What the `vibe` job stores.
pub enum VibeOut {
    Config(VibeConfig),
    Mcp(McpConfig),
    Store(AgentTranscriptStore),
}

/// `config.toml` `mcp_servers` entries read.
const MAX_SERVERS: usize = 50;
/// Entries kept per list (paths, folders, tools).
const MAX_LIST: usize = 200;
/// Files counted per session store, at the base walk budget.
const BASE_STORE_FILES: usize = 20_000;

/// The `vibe` job for one home.
pub fn scan_home(platform: &dyn PlatformInfo) -> Vec<VibeOut> {
    scan_vibe_home(&platform.home_dir())
}

/// Everything under `<home>/.vibe`.
pub fn scan_vibe_home(home: &Path) -> Vec<VibeOut> {
    let dir = home.join(".vibe");
    if !std::fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir()) {
        crate::scanners::telemetry::note_probe(&dir, false);
        return Vec::new();
    }
    let mut out = Vec::new();
    let cfg_path = dir.join("config.toml");
    let parsed = if crate::scanners::probe_file(&cfg_path) {
        crate::scanners::read_bounded_nofollow(&cfg_path, None).and_then(|t| crate::scanners::mcp::toml_to_json(&t))
    } else {
        None
    };
    let mut cfg = VibeConfig {
        path: sanitize_display(&cfg_path.to_string_lossy(), 512),
        ..Default::default()
    };
    let mut session_dir = dir.join("logs").join("session");
    if let Some(v) = &parsed {
        let flag = |k: &str| v.get(k).and_then(|x| x.as_bool());
        cfg.auto_approve = flag("auto_approve");
        cfg.enable_auto_update = flag("enable_auto_update");
        cfg.enable_update_checks = flag("enable_update_checks");
        cfg.enable_telemetry = flag("enable_telemetry");
        cfg.bypass_tool_permissions = flag("bypass_tool_permissions");
        if let Some(tools) = v.get("tools").and_then(|t| t.as_object()) {
            for (name, t) in tools.iter().take(MAX_LIST) {
                if let Some(p) = t.get("permission").and_then(|p| p.as_str()) {
                    cfg.tool_permissions
                        .insert(sanitize_display(name, 64), sanitize_display(p, 32));
                }
            }
        }
        cfg.tool_paths = string_list(v.get("tool_paths"));
        cfg.agent_paths = string_list(v.get("agent_paths"));
        cfg.skill_paths = string_list(v.get("skill_paths"));
        if let Some(save) = v
            .get("session_logging")
            .and_then(|s| s.get("save_dir"))
            .and_then(|s| s.as_str())
            && let Some(p) = expand_home(save, home)
        {
            session_dir = p;
        }
        if let Some(mcp) = mcp_config(v, &cfg_path) {
            cfg.mcp_server_count = mcp.server_count;
            out.push(VibeOut::Mcp(mcp));
        }
    }
    cfg.session_dir = Some(sanitize_display(&session_dir.to_string_lossy(), 512));
    let trusted = dir.join("trusted_folders.toml");
    if crate::scanners::probe_file(&trusted)
        && let Some(t) = crate::scanners::read_bounded_nofollow(&trusted, None)
        && let Some(tv) = crate::scanners::mcp::toml_to_json(&t)
    {
        cfg.trusted_folders = string_list(tv.get("trusted"));
        cfg.untrusted_folders = string_list(tv.get("untrusted"));
    }
    let env = dir.join(".env");
    if let Ok(m) = std::fs::symlink_metadata(&env) {
        crate::scanners::telemetry::note_probe(&env, true);
        if m.is_file()
            && let Some((mode, world, group)) = crate::scanners::file_perms(&env)
        {
            cfg.env_file = Some(VibeEnvFile {
                path: sanitize_display(&env.to_string_lossy(), 512),
                mode,
                world_readable: world,
                group_readable: group,
                unreachable_via: crate::scanners::transcripts::untraversable_ancestor(&env),
            });
        }
    } else {
        crate::scanners::telemetry::note_probe(&env, false);
    }
    // A `save_dir` outside the home is recorded, not walked: the config may point the
    // count at any tree.
    let session_store = crate::scanners::persistence::lexical_join(Path::new("/"), &session_dir)
        .starts_with(home)
        .then_some(session_dir);
    for (path, kind) in [
        (session_store.unwrap_or_default(), "sessions"),
        (dir.join("vibehistory"), "command history"),
        (dir.join("plans"), "plan files"),
    ] {
        if let Some(s) = inspect_store(&path, kind) {
            out.push(VibeOut::Store(s));
        }
    }
    out.push(VibeOut::Config(cfg));
    out
}

/// A TOML array of strings, sanitized, at most [`MAX_LIST`].
fn string_list(v: Option<&serde_json::Value>) -> Vec<String> {
    v.and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .take(MAX_LIST)
                .map(|s| sanitize_display(s, 512))
                .collect()
        })
        .unwrap_or_default()
}

/// `~/x` or an absolute path; anything else (relative, other expansions) is None.
fn expand_home(p: &str, home: &Path) -> Option<PathBuf> {
    if let Some(rest) = p.strip_prefix("~/") {
        return Some(home.join(rest));
    }
    let path = Path::new(p);
    path.is_absolute().then(|| path.to_path_buf())
}

/// `[[mcp_servers]]` as an MCP config row, through the shared server parser.
fn mcp_config(v: &serde_json::Value, path: &Path) -> Option<McpConfig> {
    let list = v.get("mcp_servers")?.as_array()?;
    let mut map = serde_json::Map::new();
    let mut disabled = std::collections::HashSet::new();
    for (i, e) in list.iter().take(MAX_SERVERS).enumerate() {
        let Some(obj) = e.as_object() else { continue };
        let name = obj
            .get("name")
            .and_then(|n| n.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| format!("server-{i}"));
        let mut cfg = obj.clone();
        // `command` may be a list: the program, then arguments before `args`.
        if let Some(serde_json::Value::Array(parts)) = obj.get("command") {
            let mut parts: Vec<serde_json::Value> = parts.clone();
            if parts.is_empty() {
                cfg.remove("command");
            } else {
                let program = parts.remove(0);
                let mut args = parts;
                if let Some(serde_json::Value::Array(more)) = obj.get("args") {
                    args.extend(more.iter().cloned());
                }
                cfg.insert("command".into(), program);
                cfg.insert("args".into(), serde_json::Value::Array(args));
            }
        }
        if obj.get("disabled").and_then(|d| d.as_bool()) == Some(true) {
            disabled.insert(crate::scanners::sanitize_display(&name, 128));
        }
        map.insert(name, serde_json::Value::Object(cfg));
    }
    if map.is_empty() {
        return None;
    }
    let wrapped = serde_json::json!({ "mcpServers": map });
    let server_names: Vec<String> = crate::scanners::mcp::extract_mcp_servers(&wrapped)
        .iter()
        .map(|n| sanitize_display(n, 128))
        .collect();
    let mut servers = crate::scanners::mcp::extract_mcp_server_details(&wrapped);
    for s in &mut servers {
        if disabled.contains(&s.name) {
            s.enabled = Some(false);
        }
    }
    Some(McpConfig {
        config_source: "Mistral Vibe".into(),
        config_path: sanitize_display(&path.to_string_lossy(), 512),
        vendor: "Mistral AI".into(),
        server_count: server_names.len(),
        server_names,
        git_tracked: false,
        servers,
    })
}

#[cfg(unix)]
fn other_bits(meta: &std::fs::Metadata) -> (bool, bool) {
    use std::os::unix::fs::PermissionsExt;
    let m = meta.permissions().mode();
    (m & 0o004 != 0, m & 0o001 != 0)
}
#[cfg(not(unix))]
fn other_bits(_meta: &std::fs::Metadata) -> (bool, bool) {
    (false, false)
}

/// A session store by counts and modes only, as the transcripts scanner records one:
/// files, bytes, files other users can read (o+r reached through o+x directories), the
/// store's own mode and an untraversable ancestor. Empty or missing is None.
fn inspect_store(path: &Path, kind: &str) -> Option<AgentTranscriptStore> {
    if path.as_os_str().is_empty() {
        return None;
    }
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        crate::scanners::telemetry::note_probe(path, false);
        return None;
    };
    crate::scanners::telemetry::note_probe(path, true);
    let (count, bytes, readable) = if meta.is_dir() {
        let cap = crate::scanners::telemetry::walk_cap(BASE_STORE_FILES, crate::scanners::telemetry::walk_budget());
        let (mut c, mut b, mut r) = (0usize, 0u64, 0usize);
        let mut stack = vec![(path.to_path_buf(), other_bits(&meta).1)];
        'walk: while let Some((d, reachable)) = stack.pop() {
            let Ok(rd) = crate::scanners::probe_read_dir(&d) else {
                continue;
            };
            for e in rd.flatten() {
                let Ok(m) = std::fs::symlink_metadata(e.path()) else {
                    continue;
                };
                let (o_read, o_exec) = other_bits(&m);
                if m.is_dir() {
                    stack.push((e.path(), reachable && o_exec));
                } else if m.is_file() {
                    if c >= cap {
                        crate::scanners::telemetry::mark_truncated();
                        break 'walk;
                    }
                    c += 1;
                    b += m.len();
                    if reachable && o_read {
                        r += 1;
                    }
                }
            }
        }
        (c, b, r)
    } else if meta.is_file() {
        (1, meta.len(), usize::from(other_bits(&meta).0))
    } else {
        return None;
    };
    if count == 0 {
        return None;
    }
    let perms = crate::scanners::file_perms(path);
    Some(AgentTranscriptStore {
        framework: "mistral-vibe".into(),
        path: sanitize_display(&path.to_string_lossy(), 512),
        kind: kind.into(),
        file_count: count,
        total_size_bytes: bytes,
        world_readable: perms.as_ref().is_some_and(|(_, w, _)| *w),
        readable_files: Some(readable),
        group_readable: perms.as_ref().is_some_and(|(_, _, g)| *g),
        mode: perms.map(|(m, _, _)| m),
        unreachable_via: crate::scanners::transcripts::untraversable_ancestor(path),
        // Vibe's session logs are not shell-environment stores, so no exported-name
        // sample; the other-login-accounts count is attached by the Claude store pass.
        exported_names: None,
        other_login_accounts: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_command_becomes_program_and_args() {
        let v = serde_json::json!({"mcp_servers": [
            {"name": "fs", "transport": "stdio", "command": ["npx", "-y", "@scope/srv"], "args": ["--root", "/"],
             "env": {"TOKEN": "abc"}},
            {"name": "web", "transport": "http", "url": "http://example.com/mcp", "disabled": true}
        ]});
        let c = mcp_config(&v, Path::new("/h/.vibe/config.toml")).unwrap();
        assert_eq!(c.server_count, 2);
        let fs = c.servers.iter().find(|s| s.name == "fs").unwrap();
        assert_eq!(fs.command.as_deref(), Some("npx"));
        assert_eq!(fs.args, vec!["-y", "@scope/srv", "--root", "/"]);
        assert_eq!(fs.env, vec!["TOKEN=<redacted>"]);
        assert_eq!(fs.unpinned.as_deref(), Some("no version"));
        let web = c.servers.iter().find(|s| s.name == "web").unwrap();
        assert_eq!(web.enabled, Some(false));
        assert_eq!(web.transport, "http");
    }
}
