//! New configuration surfaces of the agents rmguard already covers elsewhere (hooks in
//! `hook_discovery`, MCP in `mcp`): their permission, policy and sandbox files, LSP
//! launch commands, execpolicy rules, custom-agent definitions, and MCP files the other
//! scanners do not read. Same row shapes and readers as the rest of the `agents` scanner
//! (`AgentPosture`, `McpConfig`, `RulesFile`, `AgentTranscriptStore`); skill and subagent
//! directories are walked by the skills scanner (`skills::other_agent_walks`), the shared
//! `.agents/` directory by `scanners::dot_agents`.
//!
//! Every value graded here is one the vendor's own documentation gives a meaning to
//! (fetched 2026-10-30; the URL is next to each reader). An undocumented format is not
//! read, and is a floor in docs/SECURITY.md.

use super::{
    AgentsOut, Ctx, MAX_LIST, Read, Scope, claude_shaped_mcp, files_in, key_file, parse, plain_dir, posture,
    push_posture, read_cfg, rules_dir, rules_row, setting, store,
};
use crate::models::{AgentPosture, AutoApproveSetting};
use crate::scanners::sanitize_display;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Programs that run whatever script or command they are given: approving one of them
/// for every argument approves every command.
const INTERPRETERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "python",
    "python3",
    "node",
    "perl",
    "ruby",
    "php",
    "deno",
    "bun",
    "env",
    "sudo",
    "pwsh",
    "powershell",
    "eval",
    "exec",
    "xargs",
];

fn is_interpreter(word: &str) -> bool {
    let w = word.trim();
    let base = w.rsplit('/').next().unwrap_or(w);
    INTERPRETERS.contains(&base)
}

/// The surfaces of this module, in a fixed order.
pub(super) fn scan(cx: &mut Ctx) {
    cursor(cx);
    devin(cx);
    copilot(cx);
    gemini(cx);
    codex(cx);
    kiro(cx);
    opencode(cx);
    dot_agents_mcp(cx);
}

/// MCP servers a skill in the shared `.agents/skills/` defines in its `mcp.json` (Amp:
/// "Skills can define MCP servers through either an `mcp.json` file or the `mcpServers`
/// field in frontmatter", ampcode.com/docs/customize/skills; the frontmatter field is not
/// read, a floor). Shape only, through the shared server parser.
fn dot_agents_mcp(cx: &mut Ctx) {
    let home = cx.home.to_path_buf();
    let cap = crate::scanners::telemetry::walk_cap(super::BASE_RULES_FILES, crate::scanners::telemetry::walk_budget());
    for (path, proj) in crate::scanners::dot_agents::skill_mcp_files(&home, &cx.projects.clone(), cap) {
        let (scope, source) = match proj {
            Some(_) => (Scope::Project, "Amp skill (project .agents)"),
            None => (Scope::User, "Amp skill (~/.agents)"),
        };
        claude_shaped_mcp(cx, "amp", source, "Amp", &path, scope, proj.as_deref());
    }
}

/// A posture row for `path` whose file was read and parsed, or `None` (absent,
/// unreadable, a link recorded on the row instead).
fn read_json(
    cx: &mut Ctx,
    agent: &str,
    path: &Path,
    scope: Scope,
    proj: Option<&Path>,
) -> Option<(Value, AgentPosture)> {
    let mut p = posture(agent, path, scope);
    match read_cfg(cx, path, scope, proj) {
        Read::Text(t) => {
            let v = parse(path, &t).unwrap_or(Value::Null);
            Some((v, p))
        }
        Read::Link(l) => {
            p.symlink = Some(l);
            push_posture(cx, p);
            None
        }
        Read::None => None,
    }
}

// ── Cursor ─────────────────────────────────────────────────────────────────────────────

/// Cursor (cursor.com/docs, fetched 2026-10-30: `reference/permissions.md`,
/// `reference/sandbox.md`, `hooks.md`, `rules.md`).
///
/// - `permissions.json` ("`~/.cursor/permissions.json` # per-user ...
///   `<workspace>/.cursor/permissions.json` # per-repo"; "When both exist, Cursor
///   **concatenates** the arrays"): `terminalAllowlist` ("Terminal commands that can run
///   without approval", prefix match, `cmd:argsglob`) holding an interpreter (`bash`,
///   `python3:*`) or `*` is `shell-commands`; `mcpAllowlist` holding `*:*` (every tool
///   of every server) is `mcp-tools`. A repository's entries are added to the user's.
/// - `sandbox.json` (`~/.cursor/sandbox.json`, `<workspace>/.cursor/sandbox.json`, the
///   repository's taking precedence): "`"insecure_none"` disables the sandbox entirely"
///   (`type`, `sandbox-off`); `networkPolicy.default: "allow"` ("All outbound network
///   traffic is permitted inside the sandbox", `sandbox-network`).
/// - Team hooks: "The desktop app writes each command hook to
///   `~/.cursor/managed/team_<team ID>/hooks/`": listed by name, an administrator's
///   (managed, inventory).
/// - Rules: `.cursor/rules/` (`.mdc` with `description`, `globs`, `alwaysApply`).
fn cursor(cx: &mut Ctx) {
    let home = cx.home.to_path_buf();
    if plain_dir(&home, ".cursor").is_some() {
        let dir = home.join(".cursor");
        cursor_permissions(cx, &dir.join("permissions.json"), Scope::User, None);
        cursor_sandbox(cx, &dir.join("sandbox.json"), Scope::User, None);
        if let Some(managed) = plain_dir(&home, ".cursor/managed") {
            for d in sub_dirs(&managed) {
                if !d.file_name().is_some_and(|n| n.to_string_lossy().starts_with("team_")) {
                    continue;
                }
                let hooks = d.join("hooks");
                if plain_dir(&d, "hooks").is_none() {
                    continue;
                }
                let mut p = posture("cursor", &hooks, Scope::User);
                p.scope = "managed".into();
                p.hook_files = files_in(&hooks)
                    .into_iter()
                    .map(|(_, n)| sanitize_display(&n, 128))
                    .collect();
                push_posture(cx, p);
            }
        }
    }
    for proj in cx.projects.clone() {
        if plain_dir(&proj, ".cursor").is_none() {
            continue;
        }
        let dir = proj.join(".cursor");
        cursor_permissions(cx, &dir.join("permissions.json"), Scope::Project, Some(&proj));
        cursor_sandbox(cx, &dir.join("sandbox.json"), Scope::Project, Some(&proj));
        rules_dir(cx, &proj, ".cursor/rules", "cursor", Scope::Project);
    }
}

fn cursor_permissions(cx: &mut Ctx, path: &Path, scope: Scope, proj: Option<&Path>) {
    let Some((v, mut p)) = read_json(cx, "cursor", path, scope, proj) else {
        return;
    };
    let every = super::strings(v.get("terminalAllowlist")).into_iter().find(|e| {
        let prog = e.split(':').next().unwrap_or("").trim();
        prog.is_empty() || prog == "*" || is_interpreter(prog.split_whitespace().next().unwrap_or(""))
    });
    if let Some(e) = every {
        p.auto_approve.push(setting("terminalAllowlist", &e, "shell-commands"));
    }
    if super::strings(v.get("mcpAllowlist"))
        .iter()
        .any(|e| matches!(e.trim(), "*:*" | "*"))
    {
        p.auto_approve.push(setting("mcpAllowlist", "*:*", "mcp-tools"));
    }
    push_posture(cx, p);
}

fn cursor_sandbox(cx: &mut Ctx, path: &Path, scope: Scope, proj: Option<&Path>) {
    let Some((v, mut p)) = read_json(cx, "cursor", path, scope, proj) else {
        return;
    };
    if v.get("type").and_then(|t| t.as_str()) == Some("insecure_none") {
        p.auto_approve.push(setting("type", "insecure_none", "sandbox-off"));
    }
    if v.get("networkPolicy")
        .and_then(|n| n.get("default"))
        .and_then(|d| d.as_str())
        == Some("allow")
    {
        p.auto_approve
            .push(setting("networkPolicy.default", "allow", "sandbox-network"));
    }
    push_posture(cx, p);
}

// ── Devin Desktop (formerly Windsurf) and Devin CLI ────────────────────────────────────

/// Devin Desktop, its Devin Local agent ("shares its agent harness with Devin CLI") and
/// Devin CLI (docs.devin.ai, fetched 2026-10-30: `cli/extensibility/mcp/configuration.md`,
/// `cli/reference/configuration/config-file.md`, `cli/reference/permissions.md`,
/// `cli/extensibility/rules.md`, `desktop/devin-desktop-faq.md`, and the vendor's archived
/// `docs.windsurf.com/windsurf/cascade/hooks` page, Wayback 2026-05-13).
///
/// - MCP: "`~/.config/devin/mcp_config.json` ..., `.devin/mcp_config.json`, and
///   `.devin/mcp_config.local.json`" (`mcpServers`, `disabled`; remote `url`/`serverUrl`);
///   the FAQ's "MCP config `~/.codeium/mcp_config.json`"; before v3000.3 `mcpServers` in
///   `~/.config/devin/config.json` (read from that file too).
/// - Permissions (`~/.config/devin/config.json`; `.devin/config.json` and
///   `config.local.json`, where "Only `permissions`, `read_config_from`, and `hooks` are
///   available"): `permission_mode` "`dangerous`" (Bypass: "all tool calls are
///   auto-approved without prompting", `all-actions`, user config only); an
///   `permissions.allow` rule `Exec(<interpreter>)` or `Exec(*)` is `shell-commands`.
/// - Rules: `.devin/rules/`, `.devin/global_rules.md`, `~/.devin/rules/`,
///   `~/.devin/global_rules.md`, `~/.config/devin/AGENTS.md`; legacy `.windsurf/rules/`;
///   workflows `.devin/workflows/`, `.windsurf/workflows/`,
///   `~/.codeium/windsurf/global_workflows/`.
/// - Transcripts: "a JSONL file at `~/.windsurf/transcripts/{trajectory_id}.jsonl`"
///   (written by the `post_cascade_response_with_transcript` hook), a conversation store.
fn devin(cx: &mut Ctx) {
    let home = cx.home.to_path_buf();
    let cfg = home.join(".config").join("devin");
    if plain_dir(&home, ".config/devin").is_some() {
        claude_shaped_mcp(
            cx,
            "devin",
            "Devin",
            "Cognition",
            &cfg.join("mcp_config.json"),
            Scope::User,
            None,
        );
        devin_config(cx, &cfg.join("config.json"), Scope::User, None);
        rules_file_at(cx, &home, ".config/devin/AGENTS.md", Scope::User);
    }
    if plain_dir(&home, ".codeium").is_some() {
        claude_shaped_mcp(
            cx,
            "devin",
            "Devin Desktop",
            "Cognition",
            &home.join(".codeium").join("mcp_config.json"),
            Scope::User,
            None,
        );
        rules_dir(cx, &home, ".codeium/windsurf/global_workflows", "devin", Scope::User);
    }
    if plain_dir(&home, ".devin").is_some() {
        rules_dir(cx, &home, ".devin/rules", "devin", Scope::User);
        rules_file_at(cx, &home, ".devin/global_rules.md", Scope::User);
    }
    store(
        cx,
        "devin",
        &home.join(".windsurf").join("transcripts"),
        "conversation transcripts",
        true,
    );
    for proj in cx.projects.clone() {
        if plain_dir(&proj, ".devin").is_some() {
            let d = proj.join(".devin");
            for name in ["mcp_config.json", "mcp_config.local.json"] {
                claude_shaped_mcp(
                    cx,
                    "devin",
                    "Devin (project)",
                    "Cognition",
                    &d.join(name),
                    Scope::Project,
                    Some(&proj),
                );
            }
            for name in ["config.json", "config.local.json"] {
                devin_config(cx, &d.join(name), Scope::Project, Some(&proj));
            }
            rules_dir(cx, &proj, ".devin/rules", "devin", Scope::Project);
            rules_dir(cx, &proj, ".devin/workflows", "devin", Scope::Project);
            rules_file_at(cx, &proj, ".devin/global_rules.md", Scope::Project);
        }
        if plain_dir(&proj, ".windsurf").is_some() {
            rules_dir(cx, &proj, ".windsurf/rules", "devin", Scope::Project);
            rules_dir(cx, &proj, ".windsurf/workflows", "devin", Scope::Project);
        }
    }
}

fn rules_file_at(cx: &mut Ctx, base: &Path, rel: &str, scope: Scope) {
    super::rules_file(cx, base, rel, "devin", scope);
}

/// A Devin CLI `config.json`: `permission_mode` (user only), `permissions.allow` `Exec`
/// rules, and (before v3000.3) `mcpServers`.
fn devin_config(cx: &mut Ctx, path: &Path, scope: Scope, proj: Option<&Path>) {
    let Some((v, mut p)) = read_json(cx, "devin", path, scope, proj) else {
        return;
    };
    if scope == Scope::User && v.get("permission_mode").and_then(|m| m.as_str()) == Some("dangerous") {
        p.auto_approve
            .push(setting("permission_mode", "dangerous", "all-actions"));
    }
    let allow = v.get("permissions").and_then(|x| x.get("allow"));
    let every = super::strings(allow).into_iter().find(|r| {
        r.strip_prefix("Exec(")
            .and_then(|x| x.strip_suffix(')'))
            .is_some_and(|x| {
                let x = x.trim();
                x.is_empty() || x == "*" || is_interpreter(x.split_whitespace().next().unwrap_or(""))
            })
    });
    if let Some(r) = every {
        p.auto_approve.push(setting("permissions.allow", &r, "shell-commands"));
    }
    if scope == Scope::User && v.get("mcpServers").is_some() {
        let (map, disabled, _) = super::server_map(&v);
        if let Some(row) = super::mcp_row("Devin", "Cognition", path, scope, map, &disabled) {
            p.mcp_server_count = row.server_count;
            cx.out.push(AgentsOut::Mcp(row));
        }
    }
    push_posture(cx, p);
}

// ── GitHub Copilot CLI ─────────────────────────────────────────────────────────────────

/// GitHub Copilot CLI (docs.github.com/en/copilot/reference/copilot-cli-reference/
/// cli-config-dir-reference and cli-command-reference, fetched 2026-10-30).
///
/// - `~/.copilot/settings.json` `defaultPermissionMode`: "`"allow-all"` to grant broad
///   permissions equivalent to `--allow-all`" (`all-actions`). The repository's
///   `.github/copilot/settings*.json` cannot set it ("Only the keys listed ... are
///   supported at the repository level. Any other keys ... are silently ignored"), so it
///   is not read for it.
/// - `~/.copilot/permissions-config.json` ("saved tool and directory permission
///   decisions, organized by project location"): `locations.<path>.tool_approvals[]`;
///   `kind: "commands"` with a `commandIdentifiers` entry `<interpreter>:*` (a trailing
///   `:*` matches as a prefix) approves every command run through that interpreter
///   (`shell-commands`); `kind: "mcp"` with `toolName: null` ("approve every tool on the
///   server") is `mcp-tools`. The user's own decisions: graded on the user ladder.
/// - LSP servers: `~/.copilot/lsp-config.json` and the repository's `.github/lsp.json`,
///   `lspServers.<name>` with `command` / `bash` / `powershell`: "Once the working
///   directory is trusted, Copilot CLI automatically starts any LSP servers that are
///   relevant to your project". Recorded as commands the agent runs on its own.
/// - `~/.copilot/providers.json`: "API keys, bearer tokens, and header values in this
///   file are stored as plain text" — a key file, by mode, never opened.
/// - `~/.copilot/session-state/`: "Each session directory stores an event log
///   (`events.jsonl`) and workspace artifacts" — a transcript store.
fn copilot(cx: &mut Ctx) {
    let home = cx.home.to_path_buf();
    let dir = home.join(".copilot");
    if plain_dir(&home, ".copilot").is_some() {
        let settings = dir.join("settings.json");
        if let Some((v, mut p)) = read_json(cx, "copilot", &settings, Scope::User, None) {
            if v.get("defaultPermissionMode").and_then(|m| m.as_str()) == Some("allow-all") {
                p.auto_approve
                    .push(setting("defaultPermissionMode", "allow-all", "all-actions"));
            }
            push_posture(cx, p);
        }
        let perms = dir.join("permissions-config.json");
        if let Some((v, mut p)) = read_json(cx, "copilot", &perms, Scope::User, None) {
            copilot_approvals(&v, &mut p.auto_approve);
            push_posture(cx, p);
        }
        copilot_lsp(cx, &dir.join("lsp-config.json"), Scope::User, None);
        let mut p = posture("copilot", &dir.join("providers.json"), Scope::User);
        p.key_files.extend(key_file(&dir.join("providers.json")));
        push_posture(cx, p);
        store(cx, "copilot", &dir.join("session-state"), "sessions", true);
    }
    for proj in cx.projects.clone() {
        if plain_dir(&proj, ".github").is_some() {
            copilot_lsp(cx, &proj.join(".github").join("lsp.json"), Scope::Project, Some(&proj));
        }
    }
}

/// `permissions-config.json` approvals that reach every command or every MCP tool.
fn copilot_approvals(v: &Value, out: &mut Vec<AutoApproveSetting>) {
    let Some(locs) = v.get("locations").and_then(|l| l.as_object()) else {
        return;
    };
    let mut every_cmd: Option<String> = None;
    let mut every_mcp = false;
    for loc in locs.values().take(MAX_LIST) {
        let Some(list) = loc.get("tool_approvals").and_then(|a| a.as_array()) else {
            continue;
        };
        for a in list.iter().take(MAX_LIST) {
            match a.get("kind").and_then(|k| k.as_str()) {
                Some("commands") => {
                    for id in super::strings(a.get("commandIdentifiers")) {
                        if let Some(prog) = id.strip_suffix(":*")
                            && is_interpreter(prog)
                            && every_cmd.is_none()
                        {
                            every_cmd = Some(id.clone());
                        }
                    }
                }
                Some("mcp") if a.get("toolName").is_some_and(|t| t.is_null()) => every_mcp = true,
                _ => {}
            }
        }
    }
    if let Some(id) = every_cmd {
        out.push(setting("tool_approvals.commandIdentifiers", &id, "shell-commands"));
    }
    if every_mcp {
        out.push(setting("tool_approvals[kind=mcp].toolName", "null", "mcp-tools"));
    }
}

/// An LSP configuration: the commands of its servers (not disabled), redacted.
fn copilot_lsp(cx: &mut Ctx, path: &Path, scope: Scope, proj: Option<&Path>) {
    let Some((v, mut p)) = read_json(cx, "copilot", path, scope, proj) else {
        return;
    };
    if let Some(servers) = v.get("lspServers").and_then(|s| s.as_object()) {
        for (name, s) in servers.iter().take(MAX_LIST) {
            if s.get("disabled").and_then(|d| d.as_bool()) == Some(true) {
                continue;
            }
            let cmd = ["command", "bash", "powershell"]
                .iter()
                .find_map(|k| s.get(*k).and_then(|c| c.as_str()));
            let Some(cmd) = cmd else { continue };
            let args: Vec<String> = super::strings(s.get("args"));
            let full = if args.is_empty() {
                cmd.to_string()
            } else {
                format!("{cmd} {}", args.join(" "))
            };
            p.auto_run_commands.push(format!(
                "lsp {}: {}",
                sanitize_display(name, 64),
                sanitize_display(&crate::scanners::redact_command_text(&full), 200)
            ));
        }
    }
    push_posture(cx, p);
}

// ── Gemini CLI ─────────────────────────────────────────────────────────────────────────

/// Gemini CLI (github.com/google-gemini/gemini-cli `docs/reference/policy-engine.md`,
/// `docs/core/subagents.md`, `docs/core/remote-agents.md`, fetched 2026-10-30).
///
/// - Policies: user `~/.gemini/policies/*.toml`, `[[rule]]` with `toolName`, `decision`
///   (`allow` | `deny` | `ask_user`), optional `modes`, `commandPrefix`, `commandRegex`,
///   `argsPattern`, `mcpName`. "`*`: Matches **any tool** (built-in or MCP)" and "`allow`:
///   The tool call is executed automatically without user interaction": `toolName = "*"`
///   allowed with no `modes` (the built-in yolo rule is the same rule restricted to
///   `modes = ["yolo"]`) is `all-actions`; `run_shell_command` allowed with no prefix,
///   regex or argument pattern is `shell-commands`; `mcpName = "*"` or `toolName =
///   "mcp_*"` allowed is `mcp-tools`. "The **Workspace** tier (project-level policies) is
///   currently non-functional", so `.gemini/policies/` is not read; the admin directory
///   (`/etc/gemini-cli/policies`) is an administrator's choice and not graded (a floor).
/// - Subagents: `.gemini/agents/*.md` and `~/.gemini/agents/*.md`; a remote agent's
///   `auth` values may be "`!command` | Execute a shell command and use the trimmed
///   output": such a value in a repository's agent file is a command the repository makes
///   the agent run (recorded redacted). The files themselves are inventoried by the skills
///   scanner.
fn gemini(cx: &mut Ctx) {
    let home = cx.home.to_path_buf();
    if let Some(dir) = plain_dir(&home, ".gemini/policies") {
        for (path, name) in files_in(&dir) {
            if !name.ends_with(".toml") {
                continue;
            }
            if let Some((v, mut p)) = read_json(cx, "gemini", &path, Scope::User, None) {
                gemini_rules(&v, &mut p.auto_approve);
                push_posture(cx, p);
            }
        }
    }
    gemini_agents(cx, &home, Scope::User);
    for proj in cx.projects.clone() {
        gemini_agents(cx, &proj, Scope::Project);
    }
}

fn gemini_rules(v: &Value, out: &mut Vec<AutoApproveSetting>) {
    let Some(rules) = v.get("rule").and_then(|r| r.as_array()) else {
        return;
    };
    let mut seen = std::collections::HashSet::new();
    for r in rules.iter().take(MAX_LIST) {
        if r.get("decision").and_then(|d| d.as_str()) != Some("allow") {
            continue;
        }
        if r.get("modes")
            .is_some_and(|m| !m.as_array().is_some_and(|a| a.is_empty()))
        {
            // Restricted to named approval modes (yolo, autoEdit, ...): not every session.
            continue;
        }
        let names = super::strings(r.get("toolName"));
        let narrowed = ["commandPrefix", "commandRegex", "argsPattern"]
            .iter()
            .any(|k| r.get(*k).is_some());
        let mcp_all = r.get("mcpName").and_then(|m| m.as_str()) == Some("*");
        for n in &names {
            let hit = match n.as_str() {
                "*" if !narrowed && r.get("mcpName").is_none() => Some(("toolName", "*", "all-actions")),
                "run_shell_command" if !narrowed => Some(("toolName", "run_shell_command", "shell-commands")),
                "mcp_*" => Some(("toolName", "mcp_*", "mcp-tools")),
                _ => None,
            };
            if let Some((k, val, reach)) = hit
                && seen.insert(reach)
            {
                out.push(setting(&format!("[[rule]] {k} (decision = allow)"), val, reach));
            }
        }
        if mcp_all && seen.insert("mcp-tools") {
            out.push(setting("[[rule]] mcpName (decision = allow)", "*", "mcp-tools"));
        }
    }
}

/// `!command` values in the `auth` block of `<base>/.gemini/agents/*.md` frontmatter.
fn gemini_agents(cx: &mut Ctx, base: &Path, scope: Scope) {
    let Some(dir) = plain_dir(base, ".gemini/agents") else {
        return;
    };
    let proj = (scope == Scope::Project).then_some(base);
    for (path, name) in files_in(&dir) {
        if !name.ends_with(".md") {
            continue;
        }
        let mut p = posture("gemini", &path, scope);
        match read_cfg(cx, &path, scope, proj) {
            Read::Text(t) => {
                let fm = crate::scanners::skills::frontmatter(&t)
                    .and_then(crate::scanners::mcp::yaml_to_json)
                    .unwrap_or(Value::Null);
                if let Some(auth) = fm.get("auth") {
                    let mut cmds = Vec::new();
                    bang_commands(auth, 0, &mut cmds);
                    p.auto_run_commands = cmds
                        .into_iter()
                        .take(MAX_LIST)
                        .map(|c| {
                            format!(
                                "auth: {}",
                                sanitize_display(&crate::scanners::redact_command_text(&c), 200)
                            )
                        })
                        .collect();
                }
            }
            Read::Link(l) => p.symlink = Some(l),
            Read::None => continue,
        }
        push_posture(cx, p);
    }
}

/// String values starting with `!` anywhere in `v` (depth-bounded): Gemini's
/// "Execute a shell command" form.
fn bang_commands(v: &Value, depth: usize, out: &mut Vec<String>) {
    if depth > 4 || out.len() >= MAX_LIST {
        return;
    }
    match v {
        Value::String(s) => {
            if let Some(c) = s.strip_prefix('!')
                && !c.trim().is_empty()
            {
                out.push(c.trim().to_string());
            }
        }
        Value::Object(o) => o.values().for_each(|x| bang_commands(x, depth + 1, out)),
        Value::Array(a) => a.iter().for_each(|x| bang_commands(x, depth + 1, out)),
        _ => {}
    }
}

// ── Codex ──────────────────────────────────────────────────────────────────────────────

/// Codex (learn.chatgpt.com/docs, formerly developers.openai.com/codex; fetched
/// 2026-10-30: `config-file/config-reference.md`, `agent-configuration/rules.md`,
/// `agent-configuration/subagents.md`, `enterprise/managed-configuration.md`).
///
/// - `config.toml` (`~/.codex/config.toml`; a project's `.codex/config.toml`, loaded
///   "only when you trust the project"; `/etc/codex/managed_config.toml`, managed
///   defaults): `sandbox_mode = "danger-full-access"` or `default_permissions =
///   ":danger-full-access"` turns the sandbox off (`sandbox-off`); with `approval_policy =
///   "never"` as well, every command runs unsandboxed and unasked (`all-actions`; "never"
///   alone "prevents approval requests; it doesn't grant unrestricted execution"). The
///   managed file is the administrator's and is inventory.
/// - Execpolicy rules: `~/.codex/rules/*.rules` (the TUI's allow list is written to
///   `default.rules`) and a trusted project's `.codex/rules/*.rules`:
///   `prefix_rule(pattern=[...], decision=...)`, `decision` "(defaults to `"allow"`)",
///   "`allow`: Run the command outside the sandbox without prompting". A one-token
///   pattern naming an interpreter (`["bash"]`, `["python3"]`) allows every script it is
///   given (`shell-commands`). Read lexically (Starlark is not evaluated).
/// - Custom agents: `~/.codex/agents/*.toml`, `.codex/agents/*.toml`, with
///   `developer_instructions` (prompt text): rules rows. "`sandbox_mode`,
///   `approval_policy`, `model_provider`, and `mcp_servers` ... don't override the parent
///   configuration when placed in a custom agent file", so nothing in them is graded as a
///   permission.
/// - `/etc/codex/requirements.toml` only restricts (allowed policies and sandbox modes)
///   and is not graded; its hooks are read by the settings scanner.
fn codex(cx: &mut Ctx) {
    let home = cx.home.to_path_buf();
    let dir = home.join(".codex");
    codex_config(cx, &dir.join("config.toml"), Scope::User, None, false);
    codex_config(
        cx,
        &crate::scanners::system_path("/etc/codex/managed_config.toml"),
        Scope::User,
        None,
        true,
    );
    codex_rules(cx, &home, ".codex/rules", Scope::User);
    codex_agents(cx, &home, Scope::User);
    for proj in cx.projects.clone() {
        if plain_dir(&proj, ".codex").is_none() {
            continue;
        }
        codex_config(
            cx,
            &proj.join(".codex").join("config.toml"),
            Scope::Project,
            Some(&proj),
            false,
        );
        codex_rules(cx, &proj, ".codex/rules", Scope::Project);
        codex_agents(cx, &proj, Scope::Project);
    }
}

fn codex_config(cx: &mut Ctx, path: &Path, scope: Scope, proj: Option<&Path>, managed: bool) {
    let Some((v, mut p)) = read_json(cx, "codex", path, scope, proj) else {
        return;
    };
    if managed {
        p.scope = "managed".into();
    }
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
    let full = match (s("sandbox_mode").as_deref(), s("default_permissions").as_deref()) {
        (Some("danger-full-access"), _) => Some(("sandbox_mode", "danger-full-access")),
        (_, Some(":danger-full-access")) => Some(("default_permissions", ":danger-full-access")),
        _ => None,
    };
    if let Some((k, val)) = full {
        if s("approval_policy").as_deref() == Some("never") {
            p.auto_approve.push(setting(
                &format!("{k} + approval_policy"),
                &format!("{val} + never"),
                "all-actions",
            ));
        } else {
            p.auto_approve.push(setting(k, val, "sandbox-off"));
        }
    }
    push_posture(cx, p);
}

/// `*.rules` files in `base/rel`: one posture row per file.
fn codex_rules(cx: &mut Ctx, base: &Path, rel: &str, scope: Scope) {
    let Some(dir) = plain_dir(base, rel) else { return };
    let proj = (scope == Scope::Project).then_some(base);
    for (path, name) in files_in(&dir) {
        if !name.ends_with(".rules") {
            continue;
        }
        let mut p = posture("codex", &path, scope);
        match read_cfg(cx, &path, scope, proj) {
            Read::Text(t) => {
                if let Some(prog) = codex_interpreter_rule(&t) {
                    p.auto_approve.push(setting(
                        "prefix_rule (decision = allow)",
                        &format!("pattern = [\"{prog}\"]"),
                        "shell-commands",
                    ));
                }
            }
            Read::Link(l) => p.symlink = Some(l),
            Read::None => continue,
        }
        push_posture(cx, p);
    }
}

/// The interpreter of the first allowing `prefix_rule` whose pattern is that one token
/// (or a list of alternatives that names one), optionally followed by option words only,
/// read lexically.
pub(crate) fn codex_interpreter_rule(text: &str) -> Option<String> {
    let text: String = text.lines().map(strip_comment).collect::<Vec<_>>().join("\n");
    let mut rest = text.as_str();
    let mut seen = 0usize;
    while let Some(at) = rest.find("prefix_rule(") {
        seen += 1;
        if seen > 1_000 {
            break;
        }
        let call = &rest[at + "prefix_rule(".len()..];
        let body = balanced(call);
        rest = &call[body.len().min(call.len())..];
        let decision = kwarg_string(body, "decision").unwrap_or_else(|| "allow".into());
        if decision != "allow" {
            continue;
        }
        let Some(pat) = kwarg_list(body, "pattern") else {
            continue;
        };
        let tokens = top_level_items(&pat);
        // `["bash"]`, or an interpreter followed only by option words (`["bash", "-lc"]`,
        // `["python3", "-c"]`): every script it is handed matches.
        let only_flags = tokens.iter().skip(1).all(|t| {
            let t = unquote(t);
            t.starts_with('-') && !t.starts_with("--version") && !t.starts_with("--help")
        });
        if tokens.is_empty() || !only_flags {
            continue;
        }
        let first = tokens[0].trim();
        let alts: Vec<String> = if first.starts_with('[') {
            top_level_items(first.trim_start_matches('[').trim_end_matches(']'))
                .iter()
                .map(|s| unquote(s))
                .collect()
        } else {
            vec![unquote(first)]
        };
        if let Some(p) = alts.iter().find(|a| is_interpreter(a)) {
            return Some(sanitize_display(p, 64));
        }
    }
    None
}

/// The text of a call's arguments up to its closing parenthesis (quotes respected).
fn balanced(s: &str) -> &str {
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut esc = false;
    for (i, c) in s.char_indices() {
        if let Some(q) = quote {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => quote = Some(c),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                if depth == 0 {
                    return &s[..i];
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    s
}

/// A line without its `#` comment (outside quotes).
fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    for (i, c) in line.char_indices() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (None, '"' | '\'') => quote = Some(c),
            (None, '#') => return &line[..i],
            _ => {}
        }
    }
    line
}

/// Items of a comma-separated list at bracket depth zero.
fn top_level_items(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    for c in s.chars() {
        if let Some(q) = quote {
            cur.push(c);
            if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => {
                quote = Some(c);
                cur.push(c);
            }
            '[' | '(' | '{' => {
                depth += 1;
                cur.push(c);
            }
            ']' | ')' | '}' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => {
                if !cur.trim().is_empty() {
                    out.push(cur.trim().to_string());
                }
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches(|c| c == '"' || c == '\'').to_string()
}

/// The keyword argument `name=` among `body`'s top-level items.
fn kwarg<'a>(items: &'a [String], name: &str) -> Option<&'a str> {
    items.iter().find_map(|it| {
        let (k, v) = it.split_once('=')?;
        (k.trim() == name).then_some(v.trim())
    })
}

fn kwarg_string(body: &str, name: &str) -> Option<String> {
    let items = top_level_items(body);
    kwarg(&items, name).map(unquote)
}

fn kwarg_list(body: &str, name: &str) -> Option<String> {
    let items = top_level_items(body);
    let v = kwarg(&items, name)?;
    let inner = v.strip_prefix('[')?.strip_suffix(']')?;
    Some(inner.to_string())
}

/// `*.toml` custom-agent files under `base/.codex/agents` as rules rows.
fn codex_agents(cx: &mut Ctx, base: &Path, scope: Scope) {
    let Some(dir) = plain_dir(base, ".codex/agents") else {
        return;
    };
    for (path, name) in files_in(&dir) {
        if name.ends_with(".toml") {
            rules_row(cx, &path, None, &format!(".codex/agents/{name}"), "codex", scope);
        }
    }
}

// ── Kiro ───────────────────────────────────────────────────────────────────────────────

/// Kiro IDE 1.x / Kiro CLI (kiro.dev/docs, fetched 2026-10-30: `permissions.md`,
/// `sandbox.md`, `mcp/configuration.md`, `powers/create.md`,
/// `custom-agents/configuration-reference.md`, `configuration.md`).
///
/// - Permissions: `~/.kiro/settings/permissions.yaml` and the per-workspace
///   `~/.kiro/workspace-roots/<hash>/permissions.yaml` ("A cloned repo cannot inject
///   permission rules": both are the user's), `rules: [{capability, match?, exclude?,
///   effect}]`. `capability: all, effect: allow` ("equivalent to" the `allow-all`
///   preset, "Every capability except `sandbox_network`") is `all-actions`; `shell`
///   allowed with no `match` is `shell-commands`; `mcp` allowed with no `match` is
///   `mcp-tools`. A custom agent's `permissions` (`~/.kiro/agents/*.json`, a repository's
///   `.kiro/agents/*.json`) is read the same way, the repository's graded as
///   repository content. Markdown agents are not read (a floor).
/// - MCP: `~/.kiro/settings/mcp.json`, `.kiro/settings/mcp.json`; "`autoApprove` ...
///   (use `"*"` to auto-approve all tools)" (counted as pre-approved tools); installed
///   powers' `~/.kiro/powers/installed/<name>/mcp.json` (`mcpServers`).
/// - `sandbox.json` is opt-in (`enabled` is required, the sandbox is off without it) and
///   "a project file can only tighten" an active global policy, and `cli.json` documents
///   no approval key: neither is graded (a floor).
fn kiro(cx: &mut Ctx) {
    let home = cx.home.to_path_buf();
    let kh = home.join(".kiro");
    if plain_dir(&home, ".kiro").is_some() {
        kiro_permissions(cx, &kh.join("settings").join("permissions.yaml"));
        if let Some(roots) = plain_dir(&home, ".kiro/workspace-roots") {
            for d in sub_dirs(&roots) {
                kiro_permissions(cx, &d.join("permissions.yaml"));
            }
        }
        claude_shaped_mcp(
            cx,
            "kiro",
            "Kiro",
            "Amazon",
            &kh.join("settings").join("mcp.json"),
            Scope::User,
            None,
        );
        if let Some(installed) = plain_dir(&home, ".kiro/powers/installed") {
            for d in sub_dirs(&installed) {
                claude_shaped_mcp(
                    cx,
                    "kiro",
                    "Kiro power",
                    "Amazon",
                    &d.join("mcp.json"),
                    Scope::User,
                    None,
                );
            }
        }
        kiro_agents(cx, &home, Scope::User);
    }
    for proj in cx.projects.clone() {
        if plain_dir(&proj, ".kiro").is_none() {
            continue;
        }
        claude_shaped_mcp(
            cx,
            "kiro",
            "Kiro (workspace)",
            "Amazon",
            &proj.join(".kiro").join("settings").join("mcp.json"),
            Scope::Project,
            Some(&proj),
        );
        kiro_agents(cx, &proj, Scope::Project);
    }
}

fn kiro_permissions(cx: &mut Ctx, path: &Path) {
    if let Some((v, mut p)) = read_json(cx, "kiro", path, Scope::User, None) {
        kiro_rules(v.get("rules"), &mut p.auto_approve, "rules");
        push_posture(cx, p);
    }
}

/// Allow rules without a `match` on `all`, `shell` or `mcp`.
fn kiro_rules(rules: Option<&Value>, out: &mut Vec<AutoApproveSetting>, key: &str) {
    let Some(rules) = rules.and_then(|r| r.as_array()) else {
        return;
    };
    let mut seen = std::collections::HashSet::new();
    for r in rules.iter().take(MAX_LIST) {
        if r.get("effect").and_then(|e| e.as_str()) != Some("allow") || r.get("match").is_some() {
            continue;
        }
        let caps = super::strings(r.get("capability"));
        for c in caps {
            let reach = match c.as_str() {
                "all" => "all-actions",
                "shell" => "shell-commands",
                "mcp" => "mcp-tools",
                _ => continue,
            };
            if seen.insert(reach) {
                out.push(setting(&format!("{key}[capability = {c}]"), "allow", reach));
            }
        }
    }
}

/// `<base>/.kiro/agents/*.json` custom agents: their `permissions` rules.
fn kiro_agents(cx: &mut Ctx, base: &Path, scope: Scope) {
    let Some(dir) = plain_dir(base, ".kiro/agents") else {
        return;
    };
    let proj = (scope == Scope::Project).then_some(base);
    for (path, name) in files_in(&dir) {
        if !name.ends_with(".json") {
            continue;
        }
        if let Some((v, mut p)) = read_json(cx, "kiro", &path, scope, proj) {
            let perms = v.get("permissions");
            let rules = perms.and_then(|x| if x.is_array() { Some(x) } else { x.get("rules") });
            kiro_rules(rules, &mut p.auto_approve, "permissions");
            push_posture(cx, p);
        }
    }
}

// ── OpenCode ───────────────────────────────────────────────────────────────────────────

/// OpenCode (opencode.ai/docs; raw at github.com/anomalyco/opencode
/// `packages/web/src/content/docs/{config,permissions,agents,custom-tools,rules}.mdx`,
/// fetched 2026-10-30).
///
/// - Config files: `~/.config/opencode/opencode.json` (global), `opencode.json` /
///   `opencode.jsonc` in a project, and the managed directory ("`/etc/opencode/`" on
///   Linux, "`/Library/Application Support/opencode/`" on macOS; managed: inventory).
///   "Remote config (from `.well-known/opencode`)" is fetched at authentication and has
///   no documented local copy (a floor).
/// - `permission`: values "`allow` — run without approval / `ask` / `deny`"; "You can
///   also set all permissions at once: `"permission": "allow"`" and `"*": "allow"` are
///   `all-actions`; `bash: "allow"` or `bash: {"*": "allow"}` is `shell-commands`.
///   "Most permissions default to `"allow"`": the product default lets shell commands
///   run without asking, recorded on the user config row as `shell-commands` with
///   `default: true` when the file sets no `bash` permission. A per-agent
///   `agent.<name>.permission` is read the same way.
/// - `tools/` ("Tools are defined as TypeScript or JavaScript files", code OpenCode
///   loads) in `.opencode/` and `~/.config/opencode/`: listed as hot-load paths.
/// - `agents/`, `modes/`, `commands/` (and the singular names, "supported for backwards
///   compatibility"): prompt text, rules rows.
fn opencode(cx: &mut Ctx) {
    let home = cx.home.to_path_buf();
    let cfg = home.join(".config").join("opencode");
    for name in ["opencode.json", "opencode.jsonc"] {
        opencode_config(cx, &cfg.join(name), Scope::User, None, false);
    }
    let managed = crate::scanners::system_path(if cfg!(target_os = "macos") {
        "/Library/Application Support/opencode"
    } else {
        "/etc/opencode"
    });
    for name in ["opencode.json", "opencode.jsonc"] {
        opencode_config(cx, &managed.join(name), Scope::User, None, true);
    }
    opencode_dirs(cx, &home, ".config/opencode", Scope::User);
    for proj in cx.projects.clone() {
        for name in ["opencode.json", "opencode.jsonc"] {
            opencode_config(cx, &proj.join(name), Scope::Project, Some(&proj), false);
        }
        opencode_dirs(cx, &proj, ".opencode", Scope::Project);
    }
}

fn opencode_config(cx: &mut Ctx, path: &Path, scope: Scope, proj: Option<&Path>, managed: bool) {
    let Some((v, mut p)) = read_json(cx, "opencode", path, scope, proj) else {
        return;
    };
    if managed {
        p.scope = "managed".into();
    }
    let perm = v.get("permission");
    opencode_permission(perm, "permission", &mut p.auto_approve);
    if let Some(agents) = v.get("agent").and_then(|a| a.as_object()) {
        for (name, a) in agents.iter().take(MAX_LIST) {
            let key = format!("agent.{}.permission", sanitize_display(name, 64));
            opencode_permission(a.get("permission"), &key, &mut p.auto_approve);
        }
    }
    let sets_bash = perm.is_some_and(|x| x.is_string() || x.get("bash").is_some() || x.get("*").is_some());
    if scope == Scope::User && !managed && !sets_bash {
        p.auto_approve.push(AutoApproveSetting {
            default: true,
            ..setting("permission.bash", "allow (product default)", "shell-commands")
        });
    }
    push_posture(cx, p);
}

fn opencode_permission(perm: Option<&Value>, key: &str, out: &mut Vec<AutoApproveSetting>) {
    let allow = |x: Option<&Value>| x.and_then(|v| v.as_str()) == Some("allow");
    match perm {
        Some(Value::String(s)) if s == "allow" => out.push(setting(key, "allow", "all-actions")),
        Some(Value::Object(o)) => {
            if allow(o.get("*")) {
                out.push(setting(&format!("{key}.*"), "allow", "all-actions"));
            } else if let Some(b) = o.get("bash") {
                if allow(Some(b)) {
                    out.push(setting(&format!("{key}.bash"), "allow", "shell-commands"));
                } else if allow(b.get("*")) {
                    out.push(setting(&format!("{key}.bash.*"), "allow", "shell-commands"));
                }
            }
        }
        _ => {}
    }
}

/// `tools/` listed; `agents/`, `modes/`, `commands/` (plural and singular) as rules.
fn opencode_dirs(cx: &mut Ctx, base: &Path, rel: &str, scope: Scope) {
    if plain_dir(base, rel).is_none() {
        return;
    }
    for sub in ["agents", "agent", "modes", "mode", "commands", "command"] {
        rules_dir(cx, base, &format!("{rel}/{sub}"), "opencode", scope);
    }
    for sub in ["tools", "tool"] {
        let Some(dir) = plain_dir(base, &format!("{rel}/{sub}")) else {
            continue;
        };
        let mut p = posture("opencode", &dir, scope);
        p.hot_load_paths = files_in(&dir)
            .into_iter()
            .filter(|(_, n)| {
                crate::scanners::hook_sources::MODULE_EXTS
                    .iter()
                    .any(|e| n.ends_with(&format!(".{e}")))
            })
            .map(|(_, n)| format!("tool: {}", sanitize_display(&n, 128)))
            .collect();
        push_posture(cx, p);
    }
}

/// Real subdirectories (not links) directly in `dir`, sorted, at most [`MAX_LIST`].
fn sub_dirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = crate::scanners::probe_read_dir(dir) else {
        return Vec::new();
    };
    let mut v = Vec::new();
    for e in rd.flatten() {
        if v.len() >= MAX_LIST {
            crate::scanners::telemetry::mark_truncated();
            break;
        }
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            v.push(e.path());
        }
    }
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use super::codex_interpreter_rule as rule;

    #[test]
    fn interpreter_prefix_rules_are_found_lexically() {
        assert_eq!(rule(r#"prefix_rule(pattern=["bash"])"#).as_deref(), Some("bash"));
        assert_eq!(
            rule("prefix_rule(\n  pattern = [[\"zsh\", \"sh\"]], # any shell\n  decision = \"allow\",\n)").as_deref(),
            Some("zsh")
        );
        assert_eq!(
            rule(r#"prefix_rule(pattern=["python3", "-c"], decision="allow")"#).as_deref(),
            Some("python3")
        );
        assert_eq!(
            rule(r#"prefix_rule(pattern=["/usr/bin/env"])"#).as_deref(),
            Some("/usr/bin/env")
        );
    }

    #[test]
    fn narrow_or_non_allowing_rules_are_not() {
        assert_eq!(rule(r#"prefix_rule(pattern=["bash"], decision="prompt")"#), None);
        assert_eq!(rule(r#"prefix_rule(pattern=["bash", "build.sh"])"#), None);
        assert_eq!(rule(r#"prefix_rule(pattern=["git", "status"])"#), None);
        assert_eq!(rule(r#"prefix_rule(pattern=["bash", "--version"])"#), None);
        assert_eq!(
            rule(
                r#"# prefix_rule(pattern=["bash"]) is commented "out"
prefix_rule(pattern=["npm"], justification="x (y)")"#
            ),
            None
        );
        assert_eq!(rule(r#"prefix_rule(pattern=["sh"], decision="forbidden")"#), None);
    }
}
