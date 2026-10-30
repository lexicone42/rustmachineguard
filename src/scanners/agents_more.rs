//! Coding agents rmguard had no reader for: Cline, Roo Code, Continue, Aider, Goose, Zed,
//! JetBrains Junie, Amp and Warp (the `agents` scanner). For each one, what its primary
//! documentation says it loads or writes:
//!
//! - MCP servers become `mcp_configs` rows (source = the agent), through the shared
//!   server parser: `env` and `headers` by shape only, launch packages identified,
//!   unpinned launchers marked.
//! - Rules and instruction files become `rules_files` rows with the shared checks: hash,
//!   git-tracked state, dangerous patterns, invisible Unicode and prompt-injection phrases,
//!   graded by scope (`framework` = the agent, `scope` = user or project).
//! - History and session stores become `transcripts` rows, read by the transcript
//!   scanner's own reader (counts, modes, and for conversation stores the secret-shaped
//!   NAMES and LABELS only).
//! - Approval settings, commands the agent runs by itself, hook executables, hot-load
//!   paths and API-key files (by mode, never opened) become one `AgentPosture` per source.
//!
//! Every configuration file is opened through [`read_hook_file`]: a repository file that
//! is a symlink out of its project is recorded by its target and never opened, and an
//! agent credential name is never opened anywhere. Directory walks are bounded with
//! `walk_cap` and mark the scanner truncated; no symlink is followed. Environment
//! variables that relocate an agent (`CLINE_DIR`, `GOOSE_PATH_ROOT`, `XDG_*`,
//! `CONTINUE_GLOBAL_DIR`, ...) are the scanning user's own and are not applied to a
//! scanned home (a floor, as for `VIBE_HOME`).
//!
//! Primary sources (fetched 2026-10-24/25), cited again where each key is used:
//! - Cline: docs.cline.bot (`getting-started/config.md`, `mcp/configuring-mcp-servers`,
//!   `customization/cline-rules.md`, `features/auto-approve.md`) and github.com/cline/cline
//!   (`apps/vscode/src/shared/AutoApprovalSettings.ts`, `core/storage/disk.ts`,
//!   `shared/storage/storage-context.ts`).
//! - Roo Code: github.com/RooCodeInc/Roo-Code-Docs (`docs/features/custom-instructions.md`,
//!   `custom-modes.mdx`, `mcp/using-mcp-in-roo.mdx`, `auto-approving-actions.mdx`) and
//!   github.com/RooCodeInc/Roo-Code `src/shared/globalFileNames.ts` (archived 2026-05).
//! - Continue: github.com/continuedev/continue `docs/` (`reference.mdx`,
//!   `customize/deep-dives/mcp.mdx`, `cli/tool-permissions.mdx`) and `core/util/paths.ts`.
//! - Aider: aider.chat/docs/config (`aider_conf.md`, `options.md`, `dotenv.md`) and
//!   github.com/Aider-AI/aider `aider/main.py`, `aider/args.py`.
//! - Goose: github.com/aaif-goose/goose (formerly block/goose) `documentation/docs/guides/`
//!   (`config-files.md`, `managing-tools/goose-permissions.md`, `logs.md`,
//!   `context-engineering/using-goosehints.md`) and `crates/goose/src/config/permission.rs`.
//! - Zed: github.com/zed-industries/zed `docs/src/ai/` (`mcp.md`, `tool-permissions.md`,
//!   `instructions.md`), `docs/src/worktree-trust.md`, `crates/agent/src/db.rs`.

mod primary;

use crate::models::{AgentKeyFile, AgentPosture, AgentTranscriptStore, AutoApproveSetting, McpConfig, RulesFile};
use crate::platform::PlatformInfo;
use crate::scanners::agent_settings::{SettingsRead, read_hook_file};
use crate::scanners::sanitize_display;
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

/// What the `agents` job stores.
pub enum AgentsOut {
    Posture(AgentPosture),
    Mcp(McpConfig),
    Store(AgentTranscriptStore),
    Rules(RulesFile),
}

/// Servers read per configuration source.
const MAX_SERVERS: usize = 100;
/// Entries kept per list (paths, commands, hook files).
const MAX_LIST: usize = 100;
/// Rules files read per rules directory, at the base walk budget.
const BASE_RULES_FILES: usize = 200;
/// Subdirectory levels below a rules directory that are listed.
const RULES_DEPTH: usize = 2;
/// Entries of a project root listed for `.roorules-<mode>` files.
const MAX_ROOT_ENTRIES: usize = 5_000;

/// Configuration scope.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    User,
    Project,
}

impl Scope {
    fn label(self) -> &'static str {
        match self {
            Scope::User => "user",
            Scope::Project => "project",
        }
    }
}

/// One scan pass: the home and the projects of this pass.
struct Ctx<'a> {
    home: &'a Path,
    projects: Vec<PathBuf>,
    out: Vec<AgentsOut>,
}

/// The `agents` job for one home.
pub fn scan_home(platform: &dyn PlatformInfo) -> Vec<AgentsOut> {
    let home = platform.home_dir();
    let projects = project_dirs(platform, &home);
    scan_with(&home, projects)
}

fn scan_with(home: &Path, projects: Vec<PathBuf>) -> Vec<AgentsOut> {
    let mut cx = Ctx {
        home,
        projects,
        out: Vec::new(),
    };
    cline(&mut cx);
    roo(&mut cx);
    continue_dev(&mut cx);
    aider(&mut cx);
    goose(&mut cx);
    zed(&mut cx);
    junie(&mut cx);
    amp(&mut cx);
    warp(&mut cx);
    // New configuration surfaces of the agents covered by the other scanners (Cursor,
    // Devin, Copilot, Gemini, Codex, Kiro, OpenCode), kept in their own module.
    primary::scan(&mut cx);
    cx.out
}

/// Every project of this pass, as the rules scanner builds the list: registered in
/// `~/.claude.json`, recovered from `~/.claude/projects/` names, and (primary pass) the
/// working directory; never a scan home or an ancestor of one; each real directory once.
fn project_dirs(platform: &dyn PlatformInfo, home: &Path) -> Vec<PathBuf> {
    let claude_json = home.join(".claude.json");
    let registered: Vec<PathBuf> = if crate::scanners::probe_file(&claude_json) {
        crate::scanners::read_bounded(&claude_json)
            .and_then(|c| serde_json::from_str::<Value>(&c).ok())
            .and_then(|v| v.get("projects").and_then(|p| p.as_object()).cloned())
            .map(|o| o.keys().map(PathBuf::from).collect())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let scope = platform.pass_scope();
    let mut seen = std::collections::HashSet::new();
    scope
        .excluding_scan_homes(scope.with_cwd(registered))
        .into_iter()
        .filter(|d| std::fs::symlink_metadata(d).is_ok_and(|m| m.is_dir()))
        .filter(|d| seen.insert(std::fs::canonicalize(d).unwrap_or_else(|_| d.clone())))
        .collect()
}

// ── Shared readers ─────────────────────────────────────────────────────────────────────

/// Whether `p` exists (not following a link at it), counted as a probe.
fn present(p: &Path) -> bool {
    let ok = std::fs::symlink_metadata(p).is_ok();
    crate::scanners::telemetry::note_probe(p, ok);
    ok
}

/// A directory reached without a symlink in any component of `rel` below `base`.
fn plain_dir(base: &Path, rel: &str) -> Option<PathBuf> {
    let mut at = base.to_path_buf();
    for c in Path::new(rel).components() {
        at.push(c);
        if !std::fs::symlink_metadata(&at).is_ok_and(|m| m.is_dir()) {
            crate::scanners::telemetry::note_probe(&base.join(rel), false);
            return None;
        }
    }
    crate::scanners::telemetry::note_probe(&at, true);
    Some(at)
}

/// What reading one configuration file gave.
enum Read {
    Text(String),
    Link(crate::models::EnvSymlink),
    None,
}

/// Open a configuration file: a project file as repository content (a link out of
/// `proj` is recorded, never followed), a user file with the user ladder (a link into a
/// credential path is never opened).
fn read_cfg(cx: &Ctx, path: &Path, scope: Scope, proj: Option<&Path>) -> Read {
    if !present(path) {
        return Read::None;
    }
    let source = match scope {
        Scope::User => "user-global",
        Scope::Project => "project",
    };
    match read_hook_file(path, source, proj, None, Some(cx.home)) {
        SettingsRead::Content(t) => Read::Text(t),
        SettingsRead::Link(l) => Read::Link(l),
        SettingsRead::Unreadable => Read::None,
    }
}

/// Parse by extension: `.yaml`/`.yml` as YAML, `.toml` as TOML, anything else as JSON
/// with `//` comments and trailing commas allowed (Zed's and VS Code's settings).
fn parse(path: &Path, text: &str) -> Option<Value> {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "yaml" | "yml" => crate::scanners::mcp::yaml_to_json(text),
        "toml" => crate::scanners::mcp::toml_to_json(text),
        _ => serde_json::from_str(&crate::scanners::vscode_tasks::strip_jsonc(text)).ok(),
    }
}

fn shown(p: &Path) -> String {
    sanitize_display(&p.to_string_lossy(), 512)
}

/// A new posture row for `path`.
fn posture(agent: &str, path: &Path, scope: Scope) -> AgentPosture {
    AgentPosture {
        agent: agent.into(),
        path: shown(path),
        scope: scope.label().into(),
        ..Default::default()
    }
}

fn setting(setting: &str, value: &str, reach: &str) -> AutoApproveSetting {
    AutoApproveSetting {
        setting: setting.into(),
        value: sanitize_display(value, 64),
        reach: reach.into(),
        default: false,
    }
}

/// A posture row is kept when it says something: an approval setting, a command, a
/// hook, a hot-load path, a server, a key file or a link.
fn keep(p: &AgentPosture) -> bool {
    !p.auto_approve.is_empty()
        || !p.auto_run_commands.is_empty()
        || !p.hook_files.is_empty()
        || !p.hot_load_paths.is_empty()
        || p.mcp_server_count > 0
        || !p.key_files.is_empty()
        || p.symlink.is_some()
}

/// Push `p` when [`keep`] says so; a kept project file gets its git state then (a
/// `git ls-files` listing is not asked for a file that says nothing). A hook directory's
/// row has its state from its files already.
fn push_posture(cx: &mut Ctx, mut p: AgentPosture) {
    if keep(&p) {
        if p.scope == "project" && p.hook_files.is_empty() && !p.git_tracked {
            p.git_tracked = crate::scanners::is_git_tracked(Path::new(&p.path));
        }
        cx.out.push(AgentsOut::Posture(p));
    }
}

/// An API-key or secret file by mode only: never opened, a link not followed.
fn key_file(path: &Path) -> Option<AgentKeyFile> {
    let meta = std::fs::symlink_metadata(path).ok();
    crate::scanners::telemetry::note_probe(path, meta.is_some());
    if !meta?.is_file() {
        return None;
    }
    let (mode, world, group) = crate::scanners::file_perms(path)?;
    Some(AgentKeyFile {
        path: shown(path),
        mode,
        world_readable: world,
        group_readable: group,
        unreachable_via: crate::scanners::transcripts::untraversable_ancestor(path),
    })
}

/// A history store, read by the transcript scanner's reader; `sample` for a store of
/// conversation text (secret-shaped names and labels only).
fn store(cx: &mut Ctx, framework: &str, path: &Path, kind: &str, sample: bool) {
    let home = cx.home.to_path_buf();
    if let Some(s) =
        crate::scanners::transcripts::inspect_agent_store(framework, path, kind, sample.then_some(home.as_path()))
    {
        cx.out.push(AgentsOut::Store(s));
    }
}

/// One rules or instruction file as a `rules_files` row: hashed, git state, the shared
/// dangerous-pattern and invisible-Unicode checks, and prompt-injection phrases graded by
/// scope. Opened without following a link (`expect`: the real path it must be).
fn rules_row(cx: &mut Ctx, path: &Path, expect: Option<&Path>, label: &str, framework: &str, scope: Scope) {
    let Some(content) = crate::scanners::read_bounded_nofollow(path, expect) else {
        return;
    };
    let user = scope == Scope::User;
    let mut findings = crate::scanners::rules_files::check_dangerous_patterns(&content);
    findings.extend(crate::scanners::rules_files::injection_findings(&content, user));
    cx.out.push(AgentsOut::Rules(RulesFile {
        path: shown(path),
        file_name: sanitize_display(label, 512),
        sha256: crate::scanners::sha256_hex(&content),
        git_tracked: crate::scanners::is_git_tracked(path),
        size_bytes: content.len(),
        findings,
        kind: Some("rules".into()),
        framework: Some(framework.into()),
        scope: Some(scope.label().into()),
    }));
}

/// A rules file at `base/rel`, when it is a regular file reached without a link.
fn rules_file(cx: &mut Ctx, base: &Path, rel: &str, framework: &str, scope: Scope) {
    let path = base.join(rel);
    let parent_ok = Path::new(rel)
        .parent()
        .is_none_or(|p| p.as_os_str().is_empty() || plain_dir(base, &p.to_string_lossy()).is_some());
    if !parent_ok {
        return;
    }
    let meta = std::fs::symlink_metadata(&path).ok();
    crate::scanners::telemetry::note_probe(&path, meta.is_some());
    if meta.is_some_and(|m| m.is_file()) {
        rules_row(cx, &path, None, rel, framework, scope);
    }
}

/// Text files a rules directory holds.
fn is_rules_text(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [".md", ".mdc", ".txt", ".markdown"].iter().any(|e| lower.ends_with(e))
}

/// Every rules text file under `base/rel` (a directory reached without a link), at most
/// [`RULES_DEPTH`] levels down and the scaled [`BASE_RULES_FILES`] files, in name order,
/// no link followed.
fn rules_dir(cx: &mut Ctx, base: &Path, rel: &str, framework: &str, scope: Scope) {
    let Some(root) = plain_dir(base, rel) else { return };
    let Ok(real_root) = std::fs::canonicalize(&root) else {
        return;
    };
    let cap = crate::scanners::telemetry::walk_cap(BASE_RULES_FILES, crate::scanners::telemetry::walk_budget());
    let mut files = Vec::new();
    if walk_level(&root, "", 0, cap, &mut files) {
        crate::scanners::telemetry::mark_truncated();
    }
    for (path, shown_rel) in files {
        let real = real_root.join(&shown_rel);
        rules_row(cx, &path, Some(&real), &format!("{rel}/{shown_rel}"), framework, scope);
    }
}

/// One level of [`rules_dir`]; true when the cap stopped it.
fn walk_level(dir: &Path, prefix: &str, depth: usize, cap: usize, out: &mut Vec<(PathBuf, String)>) -> bool {
    let Ok(rd) = crate::scanners::probe_read_dir(dir) else {
        return false;
    };
    let mut entries: Vec<(String, std::fs::FileType)> = rd
        .flatten()
        .take(MAX_ROOT_ENTRIES)
        .filter_map(|e| Some((e.file_name().into_string().ok()?, e.file_type().ok()?)))
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, ft) in entries {
        let rel = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if ft.is_dir() {
            if depth < RULES_DEPTH && walk_level(&dir.join(&name), &rel, depth + 1, cap, out) {
                return true;
            }
        } else if ft.is_file() && is_rules_text(&name) {
            if out.len() >= cap {
                return true;
            }
            out.push((dir.join(&name), rel));
        }
    }
    false
}

/// `rel` as a file or a directory of rules (Cline's `.clinerules` may be either).
fn rules_file_or_dir(cx: &mut Ctx, base: &Path, rel: &str, framework: &str, scope: Scope) {
    match std::fs::symlink_metadata(base.join(rel)) {
        Ok(m) if m.is_dir() => rules_dir(cx, base, rel, framework, scope),
        _ => rules_file(cx, base, rel, framework, scope),
    }
}

/// An MCP config row from a server map (`name -> {command, args, env, url, headers,
/// type}`), through the shared parser; `disabled` names are `enabled: false`.
fn mcp_row(
    source: &str,
    vendor: &str,
    path: &Path,
    scope: Scope,
    map: Map<String, Value>,
    disabled: &std::collections::HashSet<String>,
) -> Option<McpConfig> {
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
        read_by: Vec::new(),
        inputs: Vec::new(),
        config_source: source.into(),
        config_path: shown(path),
        vendor: vendor.into(),
        server_count: server_names.len(),
        server_names,
        git_tracked: scope == Scope::Project && crate::scanners::is_git_tracked(path),
        servers,
    })
}

/// The `mcpServers` object of a Claude-Desktop-shaped file (Cline, Roo Code, Junie,
/// Continue's JSON drop-ins), normalised: a nested `transport` object (Cline's migrated
/// shape) is lifted, `transportType` becomes `type`. Returns the map, the disabled
/// names, and the count of pre-approved tools (`autoApprove` / `alwaysAllow`).
fn server_map(v: &Value) -> (Map<String, Value>, std::collections::HashSet<String>, usize) {
    let mut map = Map::new();
    let mut disabled = std::collections::HashSet::new();
    let mut approved = 0usize;
    let Some(servers) = v.get("mcpServers").and_then(|s| s.as_object()) else {
        return (map, disabled, approved);
    };
    for (name, cfg) in servers.iter().take(MAX_SERVERS) {
        let Some(obj) = cfg.as_object() else { continue };
        let mut o = obj.clone();
        if let Some(Value::Object(t)) = obj.get("transport") {
            o.remove("transport");
            for (k, val) in t {
                o.entry(k.clone()).or_insert_with(|| val.clone());
            }
        }
        if let Some(tt) = obj.get("transportType").cloned() {
            o.entry("type".to_string()).or_insert(tt);
        }
        if obj.get("disabled").and_then(|d| d.as_bool()) == Some(true) {
            disabled.insert(sanitize_display(name, 128));
        }
        for key in ["autoApprove", "alwaysAllow"] {
            approved += obj.get(key).and_then(|a| a.as_array()).map_or(0, |a| a.len());
        }
        map.insert(name.clone(), Value::Object(o));
    }
    (map, disabled, approved)
}

/// A string or a list of strings, sanitized, at most [`MAX_LIST`].
fn strings(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => vec![sanitize_display(s, 512)],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str())
            .take(MAX_LIST)
            .map(|s| sanitize_display(s, 512))
            .collect(),
        _ => Vec::new(),
    }
}

/// The files (not directories, not links) directly in `dir`, with their names, sorted.
fn files_in(dir: &Path) -> Vec<(PathBuf, String)> {
    let Ok(rd) = crate::scanners::probe_read_dir(dir) else {
        return Vec::new();
    };
    let mut v: Vec<(PathBuf, String)> = Vec::new();
    for e in rd.flatten() {
        if v.len() >= MAX_LIST {
            crate::scanners::telemetry::mark_truncated();
            break;
        }
        let Ok(ft) = e.file_type() else { continue };
        if !ft.is_file() {
            continue;
        }
        if let Ok(n) = e.file_name().into_string() {
            v.push((e.path(), n));
        }
    }
    v.sort();
    v
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}
#[cfg(not(unix))]
fn is_executable(_p: &Path) -> bool {
    false
}

/// `extension.globalStorage` directories of the VS Code family for one extension id
/// (lower-case, as VS Code names the directory).
fn global_storages(home: &Path, ext_id: &str) -> Vec<PathBuf> {
    crate::platform::vscode_user_dirs(home)
        .into_iter()
        .map(|(_, user)| user.join("globalStorage").join(ext_id))
        .filter(|d| std::fs::symlink_metadata(d).is_ok_and(|m| m.is_dir()))
        .collect()
}

// ── Cline ──────────────────────────────────────────────────────────────────────────────

/// Cline (VS Code extension `saoudrizwan.claude-dev`, the `cline` CLI).
///
/// - State: "CLINE_DATA_DIR (trimmed) > CLINE_DIR + "/data" > ~/.cline/data"
///   (cline/cline `apps/vscode/src/shared/storage/storage-context.ts`); the CLI layout
///   `settings/providers.json` ("API keys and provider configuration"),
///   `settings/cline_mcp_settings.json`, `sessions/` ("One folder of messages per
///   session") is docs.cline.bot/getting-started/config.md. `secrets.json` and
///   `providers.json` are key files (mode only).
/// - Auto approve (`globalState.json` `autoApprovalSettings.actions`, shape in
///   `AutoApprovalSettings.ts`): "Execute all commands | Run commands requiring approval
///   (requires base toggle)" (docs.cline.bot/features/auto-approve.md), so
///   `executeAllCommands` with `executeSafeCommands` is graded `shell-commands`; YOLO
///   (`yoloModeToggled`): "Cline executes whatever it decides without asking permission"
///   is `all-actions`. `useMcp`, `editFiles` and `useBrowser` are inventory.
/// - MCP: `cline_mcp_settings.json` in `~/.cline/data/settings/`, the extension's
///   globalStorage `settings/`, and `~/Documents/Cline/MCP/` (the legacy paths
///   `mcp-settings-legacy-migration.ts` imports), `mcpServers` with `command`, `args`,
///   `env`, `url`, `headers`, `disabled`, `autoApprove` (docs.cline.bot
///   mcp/configuring-mcp-servers).
/// - Rules: ".clinerules/ or .cline/rules/ at your project root"; global
///   "~/Documents/Cline/Rules", and "Cline also searches ~/.cline/rules and ~/Cline/Rules"
///   (docs.cline.bot/customization/cline-rules.md).
/// - Hooks: executables named after the event in `.clinerules/hooks/` (workspace),
///   `~/Documents/Cline/Hooks/` (global; `core/storage/disk.ts`), and `.cline/hooks/`,
///   `~/.cline/hooks/` (config.md); `hooksEnabled` defaults to true (`state-keys.ts`).
///   Listed by name; their content is not read (a floor).
/// - History: the extension's globalStorage `tasks/<id>/api_conversation_history.json`
///   (and `ui_messages.json`), the CLI's `~/.cline/data/sessions/`.
fn cline(cx: &mut Ctx) {
    let home = cx.home.to_path_buf();
    let data = home.join(".cline").join("data");
    let gstate = data.join("globalState.json");
    let mut p = posture("cline", &gstate, Scope::User);
    match read_cfg(cx, &gstate, Scope::User, None) {
        Read::Text(t) => {
            if let Some(v) = parse(&gstate, &t) {
                if v.get("yoloModeToggled").and_then(|b| b.as_bool()) == Some(true) {
                    p.auto_approve.push(setting("yoloModeToggled", "true", "all-actions"));
                }
                if let Some(a) = v.get("autoApprovalSettings") {
                    let on = a.get("enabled").and_then(|b| b.as_bool()) != Some(false);
                    let act = |k: &str| a.get("actions").and_then(|x| x.get(k)).and_then(|b| b.as_bool()) == Some(true);
                    if on && act("executeSafeCommands") && act("executeAllCommands") {
                        p.auto_approve.push(setting(
                            "autoApprovalSettings.actions.executeAllCommands",
                            "true",
                            "shell-commands",
                        ));
                    }
                    for (k, reach) in [
                        ("useMcp", "mcp-tools"),
                        ("editFiles", "file-edits"),
                        ("useBrowser", "browser"),
                    ] {
                        if on && act(k) {
                            p.auto_approve
                                .push(setting(&format!("autoApprovalSettings.actions.{k}"), "true", reach));
                        }
                    }
                }
            }
        }
        Read::Link(l) => p.symlink = Some(l),
        Read::None => {}
    }
    for k in [data.join("secrets.json"), data.join("settings").join("providers.json")] {
        p.key_files.extend(key_file(&k));
    }
    push_posture(cx, p);

    let mut mcp_files = vec![data.join("settings").join("cline_mcp_settings.json")];
    let storages = global_storages(&home, "saoudrizwan.claude-dev");
    for gs in &storages {
        mcp_files.push(gs.join("settings").join("cline_mcp_settings.json"));
    }
    mcp_files.push(
        home.join("Documents")
            .join("Cline")
            .join("MCP")
            .join("cline_mcp_settings.json"),
    );
    for f in mcp_files {
        claude_shaped_mcp(cx, "cline", "Cline", "Cline", &f, Scope::User, None);
    }

    for rel in [".clinerules", ".cline/rules", ".cline/workflows"] {
        for proj in cx.projects.clone() {
            rules_file_or_dir(cx, &proj, rel, "cline", Scope::Project);
        }
    }
    for rel in [
        "Documents/Cline/Rules",
        "Documents/Cline/Workflows",
        ".cline/rules",
        "Cline/Rules",
    ] {
        rules_dir(cx, &home, rel, "cline", Scope::User);
    }

    for proj in cx.projects.clone() {
        for rel in [".clinerules/hooks", ".cline/hooks"] {
            hook_dir(cx, "cline", &proj, rel, Scope::Project);
        }
    }
    for rel in ["Documents/Cline/Hooks", ".cline/hooks"] {
        hook_dir(cx, "cline", &home, rel, Scope::User);
    }

    for gs in &storages {
        store(cx, "cline", &gs.join("tasks"), "conversation transcripts", true);
    }
    store(cx, "cline", &data.join("tasks"), "conversation transcripts", true);
    store(cx, "cline", &data.join("sessions"), "sessions", true);
}

/// Hook executables in `base/rel` (reached without a link): one posture row listing them.
fn hook_dir(cx: &mut Ctx, agent: &str, base: &Path, rel: &str, scope: Scope) {
    let Some(dir) = plain_dir(base, rel) else { return };
    let mut p = posture(agent, &dir, scope);
    for (path, name) in files_in(&dir) {
        if is_executable(&path) {
            p.hook_files.push(sanitize_display(&name, 128));
            p.git_tracked |= scope == Scope::Project && crate::scanners::is_git_tracked(&path);
        }
    }
    push_posture(cx, p);
}

/// A Claude-Desktop-shaped MCP file (`mcpServers` map) as an MCP row, with a posture row
/// counting its servers and pre-approved tools (a link out of the project recorded).
fn claude_shaped_mcp(
    cx: &mut Ctx,
    agent: &str,
    source: &str,
    vendor: &str,
    path: &Path,
    scope: Scope,
    proj: Option<&Path>,
) {
    let file = McpFile {
        agent,
        source,
        vendor,
        read_by: &[],
    };
    shaped_mcp(cx, &file, path, scope, proj, |v, _| (v.clone(), Vec::new()));
}

/// Who an MCP file belongs to: the posture `agent`, the row's `config_source` and
/// `vendor`, and (when more than one agent loads the file) `read_by`.
struct McpFile<'a> {
    agent: &'a str,
    source: &'a str,
    vendor: &'a str,
    read_by: &'a [&'a str],
}

/// An MCP file whose own format `shape` turns into the Claude Desktop shape
/// (`{"mcpServers": {name: {command, args, env, url, headers, type, disabled}}}`) plus
/// the file's input ids; `shape` may add approval settings to the posture row. The file
/// is read with [`read_cfg`] (no link followed out of a project) and its servers go
/// through the shared parser, so `env` and `headers` are kept by shape only.
fn shaped_mcp(
    cx: &mut Ctx,
    file: &McpFile,
    path: &Path,
    scope: Scope,
    proj: Option<&Path>,
    shape: impl Fn(&Value, &mut AgentPosture) -> (Value, Vec<String>),
) {
    let mut p = posture(file.agent, path, scope);
    match read_cfg(cx, path, scope, proj) {
        Read::Text(t) => {
            if let Some(v) = parse(path, &t) {
                let (claude_shaped, inputs) = shape(&v, &mut p);
                let (map, disabled, approved) = server_map(&claude_shaped);
                if let Some(mut row) = mcp_row(file.source, file.vendor, path, scope, map, &disabled) {
                    row.read_by = file.read_by.iter().map(|s| s.to_string()).collect();
                    row.inputs = inputs;
                    p.mcp_server_count = row.server_count;
                    p.mcp_auto_approved_tools = approved;
                    cx.out.push(AgentsOut::Mcp(row));
                }
            }
        }
        Read::Link(l) => p.symlink = Some(l),
        Read::None => return,
    }
    push_posture(cx, p);
}

// ── Roo Code ───────────────────────────────────────────────────────────────────────────

/// Roo Code (VS Code extension `RooVeterinaryInc.roo-cline`; repository archived 2026-05,
/// last release 3.53.0).
///
/// - Rules: global "`~/.roo/rules/` and `~/.roo/rules-{modeSlug}/`"; project `.roo/rules/`,
///   `.roo/rules-{modeSlug}/`, and the single-file fallbacks `.roorules` and
///   `.roorules-{modeSlug}` (Roo-Code-Docs `docs/features/custom-instructions.md`).
/// - Modes: `.roomodes` ("can be YAML or JSON"), `customModes` with `roleDefinition`,
///   `customInstructions` and `groups` (`custom-modes.mdx`): its text enters the system
///   prompt, so the file is a rules row. Global `settings/custom_modes.yaml` likewise.
/// - MCP: project `.roo/mcp.json` ("Roo Code automatically detects and loads this file if
///   it exists"), global `settings/mcp_settings.json` in the extension's globalStorage;
///   "`alwaysAllow` (optional): An array of tool names from this server to automatically
///   approve" (`mcp/using-mcp-in-roo.mdx`).
/// - Auto approve: `alwaysAllowExecute`, `allowedCommands`, ... live in VS Code's state
///   database (`state.vscdb`, SQLite), which is not read (a floor); the documented
///   `roo-cline.allowedCommands` user setting is: "Add * to allow all commands (use with
///   caution)" (`auto-approving-actions.mdx`), graded `shell-commands`.
/// - History: globalStorage `tasks/<taskId>/api_conversation_history.json`.
fn roo(cx: &mut Ctx) {
    let home = cx.home.to_path_buf();
    for proj in cx.projects.clone() {
        rules_dir(cx, &proj, ".roo/rules", "roo-code", Scope::Project);
        for rel in mode_rules_dirs(&proj) {
            rules_dir(cx, &proj, &rel, "roo-code", Scope::Project);
        }
        rules_file(cx, &proj, ".roorules", "roo-code", Scope::Project);
        for name in roorules_mode_files(&proj) {
            rules_file(cx, &proj, &name, "roo-code", Scope::Project);
        }
        rules_file(cx, &proj, ".roomodes", "roo-code", Scope::Project);
        let mcp = proj.join(".roo").join("mcp.json");
        if std::fs::symlink_metadata(proj.join(".roo")).is_ok() {
            claude_shaped_mcp(
                cx,
                "roo-code",
                "Roo Code (project)",
                "Roo Code",
                &mcp,
                Scope::Project,
                Some(&proj),
            );
        }
    }
    rules_dir(cx, &home, ".roo/rules", "roo-code", Scope::User);
    for rel in mode_rules_dirs(&home) {
        rules_dir(cx, &home, &rel, "roo-code", Scope::User);
    }
    for gs in global_storages(&home, "rooveterinaryinc.roo-cline") {
        claude_shaped_mcp(
            cx,
            "roo-code",
            "Roo Code",
            "Roo Code",
            &gs.join("settings").join("mcp_settings.json"),
            Scope::User,
            None,
        );
        for name in ["custom_modes.yaml", "custom_modes.json"] {
            let f = gs.join("settings").join(name);
            if present(&f) && std::fs::symlink_metadata(&f).is_ok_and(|m| m.is_file()) {
                rules_row(cx, &f, None, &format!("settings/{name}"), "roo-code", Scope::User);
            }
        }
        store(cx, "roo-code", &gs.join("tasks"), "conversation transcripts", true);
    }
    for (_, user) in crate::platform::vscode_user_dirs(&home) {
        let f = user.join("settings.json");
        let Read::Text(t) = read_cfg(cx, &f, Scope::User, None) else {
            continue;
        };
        let Some(v) = parse(&f, &t) else { continue };
        let all = v
            .get("roo-cline.allowedCommands")
            .and_then(|a| a.as_array())
            .is_some_and(|a| a.iter().any(|c| c.as_str().map(str::trim) == Some("*")));
        if all {
            let mut p = posture("roo-code", &f, Scope::User);
            p.auto_approve
                .push(setting("roo-cline.allowedCommands", "[\"*\"]", "shell-commands"));
            push_posture(cx, p);
        }
    }
}

/// `.roo/rules-<mode>` directories under `base` (listed lexically, no link followed).
fn mode_rules_dirs(base: &Path) -> Vec<String> {
    let Some(roo) = plain_dir(base, ".roo") else {
        return Vec::new();
    };
    let Ok(rd) = crate::scanners::probe_read_dir(&roo) else {
        return Vec::new();
    };
    let mut v: Vec<String> = rd
        .flatten()
        .take(MAX_ROOT_ENTRIES)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with("rules-"))
        .take(MAX_LIST)
        .map(|n| format!(".roo/{n}"))
        .collect();
    v.sort();
    v
}

/// `.roorules-<mode>` files at a project root.
fn roorules_mode_files(proj: &Path) -> Vec<String> {
    let Ok(rd) = crate::scanners::probe_read_dir(proj) else {
        return Vec::new();
    };
    let mut v: Vec<String> = Vec::new();
    for (n, e) in rd.flatten().enumerate() {
        if n >= MAX_ROOT_ENTRIES {
            crate::scanners::telemetry::mark_truncated();
            break;
        }
        if let Ok(name) = e.file_name().into_string()
            && name.starts_with(".roorules-")
            && v.len() < MAX_LIST
        {
            v.push(name);
        }
    }
    v.sort();
    v
}

// ── Continue ───────────────────────────────────────────────────────────────────────────

/// Continue (VS Code extension `Continue.continue`, CLI `cn` from `@continuedev/cli`).
///
/// - `~/.continue/config.yaml` ("`~/.continue/config.yaml` (MacOS / Linux)",
///   `docs/customize/deep-dives/configuration.mdx`): `mcpServers` is a LIST of
///   `{name, command, args, env, type, url, requestOptions.headers}` (`docs/reference.mdx`);
///   legacy `config.json` `experimental.modelContextProtocolServers[].transport`.
/// - Block directories: `mcpServers/`, `rules/`, `prompts/` in both `~/.continue/` and a
///   workspace `.continue/` (`core/config/loadLocalAssistants.ts`); JSON files in
///   `mcpServers/` are Claude Desktop shaped ("copy those JSON config files ... directly
///   into your `.continue/mcpServers/` directory ... Continue will automatically pick them
///   up", `customize/deep-dives/mcp.mdx`).
/// - `cn` permissions: "Persistent permissions are stored in `~/.continue/permissions.yaml`"
///   with `allow`, `ask`, `exclude`; "Write tools (`Edit`, `MultiEdit`, `Write`) and `Bash`
///   default to `ask`" (`docs/cli/tool-permissions.mdx`). `*` or `Bash` in `allow` is
///   graded (`all-actions` / `shell-commands`). `--auto` is a launch flag (a floor).
/// - History: `~/.continue/sessions/` (`core/util/paths.ts`), `logs/prompt.log`.
///   `~/.continue/.env` is a key file (mode only).
fn continue_dev(cx: &mut Ctx) {
    let home = cx.home.to_path_buf();
    let dir = home.join(".continue");
    let dir_present = std::fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir());
    crate::scanners::telemetry::note_probe(&dir, dir_present);
    if dir_present {
        for name in ["config.yaml", "config.json"] {
            continue_config(cx, &dir.join(name));
        }
        continue_mcp_dir(cx, &home, ".continue/mcpServers", Scope::User, None);
        rules_dir(cx, &home, ".continue/rules", "continue", Scope::User);
        rules_dir(cx, &home, ".continue/prompts", "continue", Scope::User);
        let perm = dir.join("permissions.yaml");
        let mut p = posture("continue", &perm, Scope::User);
        match read_cfg(cx, &perm, Scope::User, None) {
            Read::Text(t) => {
                if let Some(v) = parse(&perm, &t) {
                    for rule in strings(v.get("allow")) {
                        let r = rule.trim();
                        if r == "*" {
                            p.auto_approve.push(setting("allow", r, "all-actions"));
                        } else if r == "Bash" || r.starts_with("Bash(") {
                            p.auto_approve.push(setting("allow", r, "shell-commands"));
                        }
                    }
                }
            }
            Read::Link(l) => p.symlink = Some(l),
            Read::None => {}
        }
        p.key_files.extend(key_file(&dir.join(".env")));
        push_posture(cx, p);
        store(cx, "continue", &dir.join("sessions"), "sessions", true);
        store(
            cx,
            "continue",
            &dir.join("logs").join("prompt.log"),
            "conversation transcripts",
            true,
        );
    }
    for proj in cx.projects.clone() {
        if plain_dir(&proj, ".continue").is_none() {
            continue;
        }
        continue_mcp_dir(cx, &proj, ".continue/mcpServers", Scope::Project, Some(&proj));
        rules_dir(cx, &proj, ".continue/rules", "continue", Scope::Project);
        rules_dir(cx, &proj, ".continue/prompts", "continue", Scope::Project);
    }
}

/// `~/.continue/config.yaml` / `config.json`: its MCP servers, and inline `rules` text.
fn continue_config(cx: &mut Ctx, path: &Path) {
    let mut p = posture("continue", path, Scope::User);
    match read_cfg(cx, path, Scope::User, None) {
        Read::Text(t) => {
            if let Some(v) = parse(path, &t) {
                let map = continue_servers(&v);
                if let Some(row) = mcp_row("Continue", "Continue", path, Scope::User, map, &Default::default()) {
                    p.mcp_server_count = row.server_count;
                    cx.out.push(AgentsOut::Mcp(row));
                }
            }
        }
        Read::Link(l) => p.symlink = Some(l),
        Read::None => return,
    }
    push_posture(cx, p);
}

/// Continue's server list (YAML `mcpServers: [{name, ...}]`, or legacy JSON
/// `experimental.modelContextProtocolServers[].transport`) as a name map.
fn continue_servers(v: &Value) -> Map<String, Value> {
    let mut map = Map::new();
    if v.get("mcpServers").is_some_and(Value::is_object) {
        return server_map(v).0;
    }
    let list = v
        .get("mcpServers")
        .and_then(|l| l.as_array())
        .cloned()
        .unwrap_or_default();
    for (i, e) in list.iter().take(MAX_SERVERS).enumerate() {
        let Some(obj) = e.as_object() else { continue };
        let name = obj
            .get("name")
            .and_then(|n| n.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| format!("server-{i}"));
        let mut o = obj.clone();
        o.remove("apiKey");
        if let Some(h) = obj.get("requestOptions").and_then(|r| r.get("headers")) {
            o.insert("headers".into(), h.clone());
        }
        o.remove("requestOptions");
        map.insert(name, Value::Object(o));
    }
    if let Some(list) = v
        .get("experimental")
        .and_then(|e| e.get("modelContextProtocolServers"))
        .and_then(|l| l.as_array())
    {
        for (i, e) in list.iter().take(MAX_SERVERS).enumerate() {
            if let Some(t) = e.get("transport").and_then(|t| t.as_object()) {
                map.insert(format!("server-{i}"), Value::Object(t.clone()));
            }
        }
    }
    map
}

/// `<base>/.continue/mcpServers/*.yaml|*.yml|*.json`: each file one MCP row.
fn continue_mcp_dir(cx: &mut Ctx, base: &Path, rel: &str, scope: Scope, proj: Option<&Path>) {
    let Some(dir) = plain_dir(base, rel) else { return };
    for (path, name) in files_in(&dir) {
        let lower = name.to_ascii_lowercase();
        if !(lower.ends_with(".yaml") || lower.ends_with(".yml") || lower.ends_with(".json")) {
            continue;
        }
        let mut p = posture("continue", &path, scope);
        match read_cfg(cx, &path, scope, proj) {
            Read::Text(t) => {
                if let Some(v) = parse(&path, &t) {
                    let source = match scope {
                        Scope::User => "Continue",
                        Scope::Project => "Continue (project)",
                    };
                    if let Some(row) = mcp_row(
                        source,
                        "Continue",
                        &path,
                        scope,
                        continue_servers(&v),
                        &Default::default(),
                    ) {
                        p.mcp_server_count = row.server_count;
                        cx.out.push(AgentsOut::Mcp(row));
                    }
                }
            }
            Read::Link(l) => p.symlink = Some(l),
            Read::None => continue,
        }
        push_posture(cx, p);
    }
}

// ── Aider ──────────────────────────────────────────────────────────────────────────────

/// Aider (`aider`, PyPI `aider-chat`).
///
/// - `.aider.conf.yml`: "Aider will look for a this file in these locations: - Your home
///   directory. - The root of your git repo. - The current directory." (aider.chat
///   `docs/config/aider_conf.md`); keys are the option names without `--`.
/// - `yes-always`: "Always say yes to every confirmation" (`docs/config/options.md`):
///   `all-actions`, the user ladder for `~`, the repository one for a project file.
/// - `lint-cmd` with `auto-lint` ("Enable/disable automatic linting after changes
///   (default: True)") and `test-cmd` with `auto-test` (default False) run a command after
///   every edit: from a repository file that is a command the repository chose.
/// - `read` ("specify a read-only file") files are loaded into every chat: each one inside
///   the project is a rules row; all are listed. `load` ("Load and execute /commands from a
///   file on launch") is listed.
/// - History: `.aider.chat.history.md` and `.aider.input.history` in the git root
///   (`aider/args.py` defaults; `chat-history-file` / `input-history-file` relocate them,
///   recorded when inside the project); `llm-history-file` when set.
/// - `~/.aider/oauth-keys.env` holds the key the onboarding writes
///   (`aider/onboarding.py`: `OPENROUTER_API_KEY=...`): mode only.
fn aider(cx: &mut Ctx) {
    let home = cx.home.to_path_buf();
    aider_conf(cx, &home.join(".aider.conf.yml"), Scope::User, None);
    if let Some(k) = key_file(&home.join(".aider").join("oauth-keys.env")) {
        let mut p = posture("aider", &home.join(".aider"), Scope::User);
        p.key_files.push(k);
        push_posture(cx, p);
    }
    for proj in cx.projects.clone() {
        let (chat, input, llm) = aider_conf(cx, &proj.join(".aider.conf.yml"), Scope::Project, Some(&proj));
        let chat = chat.unwrap_or_else(|| proj.join(".aider.chat.history.md"));
        let input = input.unwrap_or_else(|| proj.join(".aider.input.history"));
        store(cx, "aider", &chat, "conversation transcripts", true);
        store(cx, "aider", &input, "command history", true);
        if let Some(l) = llm {
            store(cx, "aider", &l, "conversation transcripts", true);
        }
    }
}

/// One `.aider.conf.yml`; returns the project's relocated (chat, input, llm) history
/// files when they stay inside it.
fn aider_conf(
    cx: &mut Ctx,
    path: &Path,
    scope: Scope,
    proj: Option<&Path>,
) -> (Option<PathBuf>, Option<PathBuf>, Option<PathBuf>) {
    let mut p = posture("aider", path, scope);
    let mut hist = (None, None, None);
    match read_cfg(cx, path, scope, proj) {
        Read::Text(t) => {
            if let Some(v) = parse(path, &t) {
                let flag = |k: &str| v.get(k).and_then(|b| b.as_bool());
                if flag("yes-always") == Some(true) {
                    p.auto_approve.push(setting("yes-always", "true", "all-actions"));
                }
                if flag("auto-lint") != Some(false) {
                    p.auto_run_commands.extend(
                        strings(v.get("lint-cmd"))
                            .iter()
                            .map(|c| format!("lint-cmd: {}", crate::scanners::redact_secrets_in_text(c))),
                    );
                }
                if flag("auto-test") == Some(true) {
                    p.auto_run_commands.extend(
                        strings(v.get("test-cmd"))
                            .iter()
                            .map(|c| format!("test-cmd: {}", crate::scanners::redact_secrets_in_text(c))),
                    );
                }
                for (key, prefix) in [("read", "read"), ("load", "load")] {
                    for f in strings(v.get(key)) {
                        p.hot_load_paths.push(format!("{prefix}: {f}"));
                    }
                }
                if let Some(proj) = proj {
                    for f in strings(v.get("read")) {
                        if let Some(rel) = inside(&f) {
                            rules_file(cx, proj, &rel, "aider", scope);
                        }
                    }
                    let in_proj = |k: &str| {
                        v.get(k)
                            .and_then(|x| x.as_str())
                            .and_then(inside)
                            .map(|rel| proj.join(rel))
                    };
                    hist = (
                        in_proj("chat-history-file"),
                        in_proj("input-history-file"),
                        in_proj("llm-history-file"),
                    );
                }
            }
        }
        Read::Link(l) => p.symlink = Some(l),
        Read::None => return hist,
    }
    push_posture(cx, p);
    hist
}

/// A relative path with no `..`, `~` or root: inside the directory it is relative to.
fn inside(p: &str) -> Option<String> {
    use std::path::Component;
    let path = Path::new(p);
    (!p.is_empty()
        && !p.starts_with('~')
        && path
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir)))
    .then(|| p.trim_start_matches("./").to_string())
}

// ── Goose ──────────────────────────────────────────────────────────────────────────────

/// Goose (`goose`; github.com/aaif-goose/goose, formerly block/goose).
///
/// - "macOS/Linux: `~/.config/goose/config.yaml`" (`documentation/docs/guides/config-files.md`;
///   the XDG layout on macOS too, `crates/goose/src/config/paths.rs`).
/// - `extensions:`: "Supported extension types are `builtin`, `platform`, `stdio`, and
///   `streamable_http`" with `cmd`, `args`, `envs`, `env_keys`, `enabled`, `uri`, `headers`
///   (same page): `stdio`, `sse` and `streamable_http` entries are MCP rows (`envs` by
///   shape; `env_keys` names the keyring entries and is not read).
/// - `GOOSE_MODE`: "auto", "approve", "chat", "smart_approve", default "auto"; "Completely
///   Autonomous | goose can modify files, use extensions, and delete files without
///   requiring approval" and "`Autonomous Mode` is applied by default"
///   (`managing-tools/goose-permissions.md`). An explicit `auto` is graded `all-actions`;
///   the unset default is recorded as such (`default: true`).
/// - `permission.yaml` (`config/permission.rs`): `user.always_allow` tool names ("Always
///   Allow | Tool runs without requiring approval"); a shell tool there is
///   `shell-commands`, other tools `listed-tools`.
/// - Hints: "Global hints are stored in `~/.config/goose/.goosehints`"; a project's
///   `.goosehints` (`context-engineering/using-goosehints.md`).
/// - History: "Session Records | `~/.local/share/goose/sessions/sessions.db`" (earlier
///   `.jsonl` files there), "Command History | `~/.config/goose/history.txt`"
///   (`guides/logs.md`). `secrets.yaml` ("secrets are stored in a separate `secrets.yaml`
///   file (in plain text)") is a key file.
fn goose(cx: &mut Ctx) {
    let home = cx.home.to_path_buf();
    let dir = home.join(".config").join("goose");
    let cfg = dir.join("config.yaml");
    let mut p = posture("goose", &cfg, Scope::User);
    match read_cfg(cx, &cfg, Scope::User, None) {
        Read::Text(t) => {
            let v = parse(&cfg, &t).unwrap_or(Value::Null);
            match v.get("GOOSE_MODE").and_then(|m| m.as_str()) {
                Some(m) if m.trim() == "auto" => p.auto_approve.push(setting("GOOSE_MODE", "auto", "all-actions")),
                Some(_) => {}
                None => p.auto_approve.push(AutoApproveSetting {
                    default: true,
                    ..setting("GOOSE_MODE", "auto", "all-actions")
                }),
            }
            let mut map = Map::new();
            let mut disabled = std::collections::HashSet::new();
            if let Some(exts) = v.get("extensions").and_then(|e| e.as_object()) {
                for (key, e) in exts.iter().take(MAX_SERVERS) {
                    let ty = e.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    if !matches!(ty, "stdio" | "sse" | "streamable_http") {
                        continue;
                    }
                    let name = e.get("name").and_then(|n| n.as_str()).unwrap_or(key).to_string();
                    let mut o = Map::new();
                    o.insert("type".into(), Value::String(ty.into()));
                    for (from, to) in [
                        ("cmd", "command"),
                        ("args", "args"),
                        ("envs", "env"),
                        ("uri", "url"),
                        ("headers", "headers"),
                    ] {
                        if let Some(x) = e.get(from) {
                            o.insert(to.into(), x.clone());
                        }
                    }
                    if e.get("enabled").and_then(|b| b.as_bool()) == Some(false) {
                        disabled.insert(sanitize_display(&name, 128));
                    }
                    map.insert(name, Value::Object(o));
                }
            }
            if let Some(row) = mcp_row("Goose", "Block", &cfg, Scope::User, map, &disabled) {
                p.mcp_server_count = row.server_count;
                cx.out.push(AgentsOut::Mcp(row));
            }
        }
        Read::Link(l) => p.symlink = Some(l),
        Read::None => {}
    }
    let perm = dir.join("permission.yaml");
    if let Read::Text(t) = read_cfg(cx, &perm, Scope::User, None)
        && let Some(v) = parse(&perm, &t)
    {
        for tool in strings(v.get("user").and_then(|u| u.get("always_allow"))) {
            let shell = tool == "shell" || tool.ends_with("__shell");
            p.auto_approve.push(setting(
                "permission.yaml user.always_allow",
                &tool,
                if shell { "shell-commands" } else { "listed-tools" },
            ));
        }
    }
    p.key_files.extend(key_file(&dir.join("secrets.yaml")));
    push_posture(cx, p);

    rules_file(cx, &home, ".config/goose/.goosehints", "goose", Scope::User);
    for proj in cx.projects.clone() {
        rules_file(cx, &proj, ".goosehints", "goose", Scope::Project);
    }
    store(cx, "goose", &dir.join("history.txt"), "command history", true);
    store(
        cx,
        "goose",
        &home.join(".local").join("share").join("goose").join("sessions"),
        "sessions",
        true,
    );
}

// ── Zed ────────────────────────────────────────────────────────────────────────────────

/// Zed's agent.
///
/// - Settings: "macOS: `~/.config/zed/settings.json`", "Linux: `~/.config/zed/settings.json`"
///   ("JSON with support for `//` comments", `docs/src/configuring-zed.md`).
/// - `context_servers`: local `command`, `args`, `env`; remote `url`, `headers`
///   (`docs/src/ai/mcp.md`); the older shape nested `command: {path, args, env}`. These
///   are already the `Zed` row of the MCP scanner when the file is plain JSON; the row here
///   (deduplicated by path) also covers a file with comments. Project `.zed/settings.json`
///   `context_servers` are rows too; Zed starts them only in a trusted worktree ("Restricted
///   Mode prevents ... MCP servers from being installed and spawned",
///   `docs/src/worktree-trust.md`).
/// - Approval: "To auto-approve all tool actions: `"agent": { "tool_permissions": {
///   "default": "allow" } }`" (`docs/src/ai/tool-permissions.md`), and before v0.224.0
///   `agent.always_allow_tool_actions`: `all-actions`; `tool_permissions.tools.terminal.default
///   = "allow"`: `shell-commands`. `session.trust_all_worktrees` ("MCP servers are
///   downloaded and started automatically") is `untrusted-projects`.
/// - Rules: "Zed uses the first matching file in this list: `.rules`, `.cursorrules`, ...";
///   personal `~/.config/zed/AGENTS.md` (`docs/src/ai/instructions.md`). Only `.rules`
///   is new here; the others are rules-scanner rows.
/// - Threads: `data_dir()/threads/threads.db` (SQLite; `crates/agent/src/db.rs`).
fn zed(cx: &mut Ctx) {
    let home = cx.home.to_path_buf();
    let settings = home.join(".config").join("zed").join("settings.json");
    let mut p = posture("zed", &settings, Scope::User);
    match read_cfg(cx, &settings, Scope::User, None) {
        Read::Text(t) => {
            if let Some(v) = parse(&settings, &t) {
                let agent = v.get("agent");
                let tp = agent.and_then(|a| a.get("tool_permissions"));
                if tp.and_then(|t| t.get("default")).and_then(|d| d.as_str()) == Some("allow") {
                    p.auto_approve
                        .push(setting("agent.tool_permissions.default", "allow", "all-actions"));
                }
                if agent
                    .and_then(|a| a.get("always_allow_tool_actions"))
                    .and_then(|b| b.as_bool())
                    == Some(true)
                {
                    p.auto_approve
                        .push(setting("agent.always_allow_tool_actions", "true", "all-actions"));
                }
                if tp
                    .and_then(|t| t.get("tools"))
                    .and_then(|t| t.get("terminal"))
                    .and_then(|t| t.get("default"))
                    .and_then(|d| d.as_str())
                    == Some("allow")
                {
                    p.auto_approve.push(setting(
                        "agent.tool_permissions.tools.terminal.default",
                        "allow",
                        "shell-commands",
                    ));
                }
                if v.get("session")
                    .and_then(|s| s.get("trust_all_worktrees"))
                    .and_then(|b| b.as_bool())
                    == Some(true)
                {
                    p.auto_approve
                        .push(setting("session.trust_all_worktrees", "true", "untrusted-projects"));
                }
                if let Some(row) = zed_servers(&v, &settings, Scope::User) {
                    p.mcp_server_count = row.server_count;
                    cx.out.push(AgentsOut::Mcp(row));
                }
            }
        }
        Read::Link(l) => p.symlink = Some(l),
        Read::None => {}
    }
    push_posture(cx, p);
    rules_file(cx, &home, ".config/zed/AGENTS.md", "zed", Scope::User);
    for proj in cx.projects.clone() {
        rules_file(cx, &proj, ".rules", "zed", Scope::Project);
        if plain_dir(&proj, ".zed").is_none() {
            continue;
        }
        let f = proj.join(".zed").join("settings.json");
        let mut p = posture("zed", &f, Scope::Project);
        match read_cfg(cx, &f, Scope::Project, Some(&proj)) {
            Read::Text(t) => {
                if let Some(v) = parse(&f, &t)
                    && let Some(row) = zed_servers(&v, &f, Scope::Project)
                {
                    p.mcp_server_count = row.server_count;
                    cx.out.push(AgentsOut::Mcp(row));
                }
            }
            Read::Link(l) => p.symlink = Some(l),
            Read::None => continue,
        }
        push_posture(cx, p);
    }
    let threads = crate::platform::zed_data_dir(&home).join("threads");
    store(cx, "zed", &threads, "conversation transcripts", true);
}

/// Zed `context_servers` as an MCP row (the old `command: {path, args, env}` lifted).
fn zed_servers(v: &Value, path: &Path, scope: Scope) -> Option<McpConfig> {
    let servers = v.get("context_servers")?.as_object()?;
    let mut map = Map::new();
    let mut disabled = std::collections::HashSet::new();
    for (name, cfg) in servers.iter().take(MAX_SERVERS) {
        let Some(obj) = cfg.as_object() else { continue };
        let mut o = obj.clone();
        if let Some(Value::Object(c)) = obj.get("command") {
            o.remove("command");
            if let Some(p) = c.get("path") {
                o.insert("command".into(), p.clone());
            }
            for k in ["args", "env"] {
                if let Some(x) = c.get(k) {
                    o.insert(k.into(), x.clone());
                }
            }
        }
        if obj.get("enabled").and_then(|b| b.as_bool()) == Some(false) {
            disabled.insert(sanitize_display(name, 128));
        }
        map.insert(name.clone(), Value::Object(o));
    }
    let source = match scope {
        Scope::User => "Zed",
        Scope::Project => "Zed (project)",
    };
    mcp_row(source, "Zed Industries", path, scope, map, &disabled)
}

// ── JetBrains Junie ────────────────────────────────────────────────────────────────────

/// JetBrains Junie (IDE plugin and the `junie` CLI; docs at junie.jetbrains.com/docs, pages
/// dated 23 October 2026).
///
/// - Guidelines: "`.junie/AGENTS.md` file in the project root. `AGENTS.md` file in the
///   project root, combined with `.junie/playbook.md` and every `.junie/rules/*.md` file,
///   if present. `.junie/guidelines.md` file or `.junie/guidelines/` folder – Junie's legacy
///   format"; "global guidelines from `~/.junie/AGENTS.md`" (`guidelines-and-memory.html`).
/// - MCP: "Project scope: `.junie/mcp/mcp.json` at the root of your project. User scope:
///   `~/.junie/mcp/mcp.json`", Claude Desktop shaped (`junie-cli-mcp-configuration.html`).
///   The IDE plugin's global MCP location is not documented (a floor).
/// - Brave mode: "On – Junie CLI executes all potentially sensitive actions without user
///   approval" (`junie-cli.html`); `config.json` `"brave"`: "Enables brave mode by default"
///   (`junie-cli-configuration.html`), in `~/.junie/config.json` and a project's
///   `.junie/config.json` (only project hooks and `sandbox.json` are documented as
///   ignored). `all-actions`. The IDE plugin's Brave Mode is stored in IDE settings whose
///   location is not documented (a floor).
/// - Allowlist: `~/.junie/allowlist.json` (`action-allowlist-junie-cli.html`):
///   `defaultBehavior: "allow"` is `all-actions`; an `executables` rule that allows every
///   command (empty `prefix`, or `pattern` `.*` / `*`) is `shell-commands`; an allowed
///   `mcpTools` rule is `mcp-tools`.
/// - Sessions: "transcript.md file stored next to the session's events.jsonl file"; the
///   sessions directory is not documented (a floor).
fn junie(cx: &mut Ctx) {
    let home = cx.home.to_path_buf();
    let dir = home.join(".junie");
    rules_file(cx, &home, ".junie/AGENTS.md", "junie", Scope::User);
    claude_shaped_mcp(
        cx,
        "junie",
        "Junie",
        "JetBrains",
        &dir.join("mcp").join("mcp.json"),
        Scope::User,
        None,
    );
    for name in ["config.json", "settings.json"] {
        junie_config(cx, &dir.join(name), Scope::User, None);
    }
    let allow = dir.join("allowlist.json");
    let mut p = posture("junie", &allow, Scope::User);
    match read_cfg(cx, &allow, Scope::User, None) {
        Read::Text(t) => {
            if let Some(v) = parse(&allow, &t) {
                if v.get("defaultBehavior").and_then(|d| d.as_str()) == Some("allow") {
                    p.auto_approve.push(setting("defaultBehavior", "allow", "all-actions"));
                }
                let allowed = |kind: &str| -> Vec<Value> {
                    v.get("rules")
                        .and_then(|r| r.get(kind))
                        .and_then(|k| k.get("rules"))
                        .and_then(|r| r.as_array())
                        .map(|a| {
                            a.iter()
                                .take(MAX_LIST)
                                .filter(|r| r.get("action").and_then(|x| x.as_str()) == Some("allow"))
                                .cloned()
                                .collect()
                        })
                        .unwrap_or_default()
                };
                let every = allowed("executables").iter().any(|r| {
                    r.get("prefix")
                        .and_then(|x| x.as_str())
                        .is_some_and(|x| x.trim().is_empty())
                        || r.get("pattern")
                            .and_then(|x| x.as_str())
                            .is_some_and(|x| matches!(x.trim(), ".*" | "*" | "^.*$" | ".+"))
                });
                if every {
                    p.auto_approve
                        .push(setting("rules.executables", "allow *", "shell-commands"));
                }
                if !allowed("mcpTools").is_empty() {
                    p.auto_approve.push(setting("rules.mcpTools", "allow", "mcp-tools"));
                }
            }
        }
        Read::Link(l) => p.symlink = Some(l),
        Read::None => {}
    }
    push_posture(cx, p);
    for proj in cx.projects.clone() {
        for rel in [".junie/AGENTS.md", ".junie/playbook.md", ".junie/guidelines.md"] {
            rules_file(cx, &proj, rel, "junie", Scope::Project);
        }
        if plain_dir(&proj, ".junie").is_none() {
            continue;
        }
        rules_dir(cx, &proj, ".junie/rules", "junie", Scope::Project);
        rules_dir(cx, &proj, ".junie/guidelines", "junie", Scope::Project);
        let mcp = proj.join(".junie").join("mcp").join("mcp.json");
        claude_shaped_mcp(
            cx,
            "junie",
            "Junie (project)",
            "JetBrains",
            &mcp,
            Scope::Project,
            Some(&proj),
        );
        junie_config(
            cx,
            &proj.join(".junie").join("config.json"),
            Scope::Project,
            Some(&proj),
        );
    }
}

/// A Junie `config.json` / `settings.json`: `brave: true`.
fn junie_config(cx: &mut Ctx, path: &Path, scope: Scope, proj: Option<&Path>) {
    let mut p = posture("junie", path, scope);
    match read_cfg(cx, path, scope, proj) {
        Read::Text(t) => {
            if parse(path, &t).and_then(|v| v.get("brave").and_then(|b| b.as_bool())) == Some(true) {
                p.auto_approve.push(setting("brave", "true", "all-actions"));
            }
        }
        Read::Link(l) => p.symlink = Some(l),
        Read::None => return,
    }
    push_posture(cx, p);
}

// ── Amp ────────────────────────────────────────────────────────────────────────────────

/// Amp (`amp`; ampcode.com/docs).
///
/// - Settings: "`~/.config/amp/settings.json` or `~/.config/amp/settings.jsonc`"; workspace
///   "the nearest `.amp/settings.json` or `.amp/settings.jsonc`" (`docs/cli/settings`).
/// - `amp.mcpServers`: stdio `{command, args, env}`, remote `{url, headers, transport}`
///   (`docs/customize/mcp`); "MCP servers in workspace settings require explicit approval
///   before they can run".
/// - Approval: "Amp does not ask for approval before running tools. Use a custom plugin to
///   control tool use." (`docs/tools`): the product default, recorded on the user settings
///   row as `all-actions` with `default: true`. The older `amp.dangerouslyAllowAll` and
///   `amp.permissions` keys are absent from the current schema
///   (ampcode.com/cli-settings.schema.json) and are not read.
/// - Plugins: "`.amp/plugins/`" and "`~/.config/amp/plugins/`", ".ts/.js" files that "run
///   code in your environment" (`docs/customize/plugins`): listed as hot-load paths, not
///   read (a floor: whether a workspace plugin waits for approval is not documented).
/// - Instructions: `AGENTS.md`, falling back to `AGENT.md` and `CLAUDE.md`; user
///   `$HOME/.config/amp/AGENTS.md` and `$HOME/.config/AGENTS.md` (`docs/customize/agents-md`).
/// - Threads are stored by ampcode.com ("Every thread has a URL", `docs/threads`): no local
///   store.
fn amp(cx: &mut Ctx) {
    let home = cx.home.to_path_buf();
    let dir = home.join(".config").join("amp");
    for name in ["settings.json", "settings.jsonc"] {
        amp_settings(cx, &dir.join(name), Scope::User, None);
    }
    amp_plugins(cx, &home, ".config/amp/plugins", Scope::User);
    rules_file(cx, &home, ".config/amp/AGENTS.md", "amp", Scope::User);
    rules_file(cx, &home, ".config/AGENTS.md", "amp", Scope::User);
    for proj in cx.projects.clone() {
        rules_file(cx, &proj, "AGENT.md", "amp", Scope::Project);
        if plain_dir(&proj, ".amp").is_none() {
            continue;
        }
        for name in ["settings.json", "settings.jsonc"] {
            amp_settings(cx, &proj.join(".amp").join(name), Scope::Project, Some(&proj));
        }
        amp_plugins(cx, &proj, ".amp/plugins", Scope::Project);
    }
}

fn amp_settings(cx: &mut Ctx, path: &Path, scope: Scope, proj: Option<&Path>) {
    let mut p = posture("amp", path, scope);
    match read_cfg(cx, path, scope, proj) {
        Read::Text(t) => {
            let v = parse(path, &t).unwrap_or(Value::Null);
            if scope == Scope::User {
                p.auto_approve.push(AutoApproveSetting {
                    default: true,
                    ..setting("tool approval", "none (product behaviour)", "all-actions")
                });
            }
            if let Some(servers) = v.get("amp.mcpServers") {
                let (map, disabled, _) = server_map(&serde_json::json!({ "mcpServers": servers }));
                let source = match scope {
                    Scope::User => "Amp",
                    Scope::Project => "Amp (workspace)",
                };
                if let Some(row) = mcp_row(source, "Amp", path, scope, map, &disabled) {
                    p.mcp_server_count = row.server_count;
                    cx.out.push(AgentsOut::Mcp(row));
                }
            }
        }
        Read::Link(l) => p.symlink = Some(l),
        Read::None => return,
    }
    push_posture(cx, p);
}

/// `.ts` / `.js` plugin files (or `<name>/index.ts`) in an Amp plugin directory, listed.
fn amp_plugins(cx: &mut Ctx, base: &Path, rel: &str, scope: Scope) {
    let Some(dir) = plain_dir(base, rel) else { return };
    let mut p = posture("amp", &dir, scope);
    let Ok(rd) = crate::scanners::probe_read_dir(&dir) else {
        return;
    };
    let mut names: Vec<String> = rd
        .flatten()
        .take(MAX_ROOT_ENTRIES)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file() || t.is_dir()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.starts_with('.'))
        .take(MAX_LIST)
        .collect();
    names.sort();
    p.hot_load_paths = names
        .iter()
        .map(|n| format!("plugin: {}", sanitize_display(n, 128)))
        .collect();
    push_posture(cx, p);
}

// ── Warp ───────────────────────────────────────────────────────────────────────────────

/// Warp's agent (docs.warp.dev).
///
/// - "**MCP server config** - `~/.warp/.mcp.json`" (`terminal/settings/file-locations.md`);
///   project `.warp/.mcp.json`, `mcpServers` with `{command, args, env, working_directory}`
///   or `{url, headers}`; "Project-scoped servers never auto-spawn"
///   (`agents/capabilities/mcp.md`).
/// - Settings: "`~/.warp/settings.toml`" (macOS), "`${XDG_CONFIG_HOME:-$HOME/.config}/warp-terminal/settings.toml`"
///   (Linux) (`file-locations.md`); the Warp Agent CLI's `~/.warp_cli/settings.toml` (macOS)
///   and `~/.config/warp-terminal/cli/settings.toml` (Linux) with
///   `[agents.execution_profiles.<name>]` `execute_commands`, `apply_code_diffs`,
///   `mcp_permissions` = `agent_decides` | `always_ask` | `always_allow`
///   (`agents/cli/configuration.md`). `execute_commands = "always_allow"` is
///   `shell-commands`. The app's own profiles (`[agents.profiles]`, edited "through the UI")
///   are not graded (a floor).
/// - Rules: `WARP.md` ("If both ... exist in the same directory, `WARP.md` takes priority",
///   `agents/capabilities/rules.md`); global rules live in Warp Drive (cloud, a floor).
/// - Conversations: the state database's file name is not documented (a floor).
fn warp(cx: &mut Ctx) {
    let home = cx.home.to_path_buf();
    claude_shaped_mcp(
        cx,
        "warp",
        "Warp",
        "Warp",
        &home.join(".warp").join(".mcp.json"),
        Scope::User,
        None,
    );
    let settings = [
        home.join(".warp").join("settings.toml"),
        home.join(".config").join("warp-terminal").join("settings.toml"),
        home.join(".warp_cli").join("settings.toml"),
        home.join(".config")
            .join("warp-terminal")
            .join("cli")
            .join("settings.toml"),
    ];
    for f in settings {
        let mut p = posture("warp", &f, Scope::User);
        match read_cfg(cx, &f, Scope::User, None) {
            Read::Text(t) => {
                let v = parse(&f, &t).unwrap_or(Value::Null);
                if let Some(profiles) = v
                    .get("agents")
                    .and_then(|a| a.get("execution_profiles"))
                    .and_then(|e| e.as_object())
                {
                    for (name, prof) in profiles.iter().take(MAX_LIST) {
                        for (key, reach) in [
                            ("execute_commands", "shell-commands"),
                            ("apply_code_diffs", "file-edits"),
                            ("mcp_permissions", "mcp-tools"),
                        ] {
                            if prof.get(key).and_then(|x| x.as_str()) == Some("always_allow") {
                                p.auto_approve.push(setting(
                                    &format!("agents.execution_profiles.{}.{key}", sanitize_display(name, 64)),
                                    "always_allow",
                                    reach,
                                ));
                            }
                        }
                    }
                }
            }
            Read::Link(l) => p.symlink = Some(l),
            Read::None => continue,
        }
        push_posture(cx, p);
    }
    for proj in cx.projects.clone() {
        rules_file(cx, &proj, "WARP.md", "warp", Scope::Project);
        if plain_dir(&proj, ".warp").is_some() {
            let f = proj.join(".warp").join(".mcp.json");
            claude_shaped_mcp(cx, "warp", "Warp (project)", "Warp", &f, Scope::Project, Some(&proj));
        }
    }
}
