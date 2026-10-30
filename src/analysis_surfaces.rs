//! Grading of the round-3b surfaces ([`crate::models::SurfaceInventory`]), called once from
//! [`crate::analysis::collect_findings`] after every other finding is collected. Every
//! category used here is in [`crate::analysis::FINDING_CATEGORIES`]; "Network listener"
//! was added for [`listener_findings`].
//!
//! Value-gated throughout: an inventory row with nothing risky in it yields no finding. A
//! disabled plugin's LSP server, an ignored output directory, a browser profile with no
//! saved cookies or logins, and a settings script only its owner can write are inventory.

use crate::analysis::{Finding, Severity};
use crate::models::ScanReport;

/// Push the round-3b findings, and re-grade the npx-cache exposure findings whose cache a
/// running process executes from.
pub fn collect(report: &ScanReport, f: &mut Vec<Finding>) {
    lsp_findings(report, f);
    liveness_findings(report, f);
    running_npx_exposures(report, f);
    browser_profile_findings(report, f);
    output_dir_findings(report, f);
    vibe_findings(report, f);
    agent_posture_findings(report, f);
    settings_script_findings(report, f);
    listener_findings(report, f);
    transcript_content_findings(report, f);
}

/// An enabled plugin's LSP server launched through a package runner with no fixed version
/// fetches new code on each start, the plugin MCP server rule (`unpinned_reason`).
fn lsp_findings(report: &ScanReport, f: &mut Vec<Finding>) {
    for s in report.surfaces.agent_lsp_servers.iter().filter(|s| s.enabled) {
        let Some(reason) = &s.unpinned else { continue };
        let pkg = s.package.as_deref().unwrap_or("its package");
        f.push(Finding {
            severity: Severity::Medium,
            category: "MCP command".into(),
            title: format!(
                "plugin LSP server runs an unpinned package: '{}' from plugin '{}' runs {pkg} ({reason}) — each start can fetch new code",
                s.name, s.plugin
            ),
            location: s.source.clone(),
            evidence: Some(format!("{} {}", s.program, s.args.join(" ")).trim().to_string()),
        });
    }
}

/// Older plugin versions that running sessions still have loaded: one finding per plugin,
/// naming the versions and the sessions (a pid holding two old versions counts once per
/// version, as the markers do).
fn liveness_findings(report: &ScanReport, f: &mut Vec<Finding>) {
    use std::collections::BTreeMap;
    let mut by_plugin: BTreeMap<&str, Vec<&crate::models::PluginVersionInUse>> = BTreeMap::new();
    for v in report
        .surfaces
        .plugin_versions_in_use
        .iter()
        .filter(|v| v.stale_version)
    {
        by_plugin.entry(v.plugin.as_str()).or_default().push(v);
    }
    for (plugin, versions) in by_plugin {
        // Distinct sessions: one session can hold two old versions (it updated mid-run).
        let pids: std::collections::BTreeSet<u32> = versions.iter().flat_map(|v| v.pids.iter().copied()).collect();
        let sessions = if pids.is_empty() {
            versions.iter().map(|v| v.in_use_by_sessions).max().unwrap_or(0)
        } else {
            pids.len()
        };
        let names: Vec<&str> = versions.iter().map(|v| v.version.as_str()).collect();
        let installed = versions
            .iter()
            .find_map(|v| v.installed_version.as_deref())
            .unwrap_or("none");
        let hooks: usize = versions.iter().map(|v| v.hooks.len()).sum();
        let servers: usize = versions.iter().map(|v| v.mcp_servers.len()).sum();
        let (what, its) = if versions.len() == 1 {
            ("an older plugin version is".to_string(), "its")
        } else {
            (format!("{} older plugin versions are", versions.len()), "their")
        };
        f.push(Finding {
            severity: Severity::Low,
            category: "Plugin marketplace".into(),
            title: format!(
                "{what} still loaded by {sessions} running session(s); {its} hooks/MCP servers are the old version's: '{plugin}' {} (installed: {installed})",
                names.join(", ")
            ),
            location: versions[0].path.clone(),
            evidence: Some(format!(
                "{hooks} hook(s) and {servers} MCP server(s) inventoried from the old version(s); restart those sessions to load the installed version (signal: .in_use/<pid> markers, observed, undocumented)"
            )),
        });
    }
}

/// The running npx cache an exposure finding is in: (its path, process count).
fn running_cache<'a>(
    report: &'a ScanReport,
    e: &crate::models::ExposureFinding,
) -> Option<&'a crate::models::NpxCacheRunning> {
    e.cache.as_ref()?;
    report.surfaces.npx_caches_running.iter().find(|c| {
        e.found_in == c.path
            || e.found_in
                .strip_prefix(c.path.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// A vulnerable copy in an npx cache that a process is running from is not dormant: the
/// "dormant unless re-run" High becomes Critical and says it is running, and an active
/// cache's Critical says so too.
fn running_npx_exposures(report: &ScanReport, f: &mut [Finding]) {
    for e in &report.exposure_findings {
        let Some(c) = running_cache(report, e) else { continue };
        let old = crate::analysis::exposure_finding(report, e);
        let Some(slot) = f
            .iter_mut()
            .find(|x| x.category == old.category && x.location == old.location && x.title == old.title)
        else {
            continue;
        };
        let running = format!("running (pid count {})", c.pids);
        if old.title.contains(" in npx cache (dormant unless re-run): ") {
            slot.severity = Severity::Critical;
            slot.title = old.title.replace(
                " in npx cache (dormant unless re-run): ",
                &format!(" in npx cache, {running}: "),
            );
        } else {
            slot.title = format!("{} — npx cache {running}", old.title);
        }
    }
}

fn day(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "unknown date".to_string())
}

/// Agent-driven browser profiles that keep cookies or saved logins: Low as a standing
/// credential store the agent's browser reuses; Medium when other users can read login
/// files (the transcript-store reachability rule; an untraversable ancestor keeps it Low).
fn browser_profile_findings(report: &ScanReport, f: &mut Vec<Finding>) {
    for p in report
        .surfaces
        .agent_browser_profiles
        .iter()
        .filter(|p| p.login_profiles > 0)
    {
        let newest = p.newest_login_mtime.map(day).unwrap_or_else(|| "unknown date".into());
        let base = format!(
            "agent-driven browser profiles with persistent logins ({} profiles, newest login data {newest}) — {} keeps cookies and saved logins between sessions",
            p.profile_count, p.framework
        );
        let (severity, title) = match (&p.unreachable_via, p.readable_login_files) {
            (None, n) if n > 0 => (
                Severity::Medium,
                format!("{base}; {n} cookie/login file(s) readable by other users"),
            ),
            (Some(why), n) if n > 0 => (
                Severity::Low,
                format!("{base}; {n} cookie/login file(s) have o+r — not reachable: {why}"),
            ),
            _ => (Severity::Low, base),
        };
        f.push(Finding {
            severity,
            category: "Transcript exposure".into(),
            title,
            location: p.path.clone(),
            evidence: Some(format!(
                "{} of {} profiles hold Cookies or Login Data (existence, mode and mtime only; never opened)",
                p.login_profiles, p.profile_count
            )),
        });
    }
}

/// An agent output directory in a repository: tracked files are committed page snapshots,
/// console logs and screenshots (Medium); untracked and not ignored, they will be (Low).
/// Ignored, or outside a repository, it is inventory.
fn output_dir_findings(report: &ScanReport, f: &mut Vec<Finding>) {
    for d in report
        .surfaces
        .agent_output_dirs
        .iter()
        .filter(|d| d.in_repo && d.file_count > 0)
    {
        let (severity, title) = if d.tracked_files > 0 {
            (
                Severity::Medium,
                format!(
                    "{} output directory has {} git-tracked file(s) of {} — page snapshots, console logs and screenshots of what the agent browsed are committed",
                    d.framework, d.tracked_files, d.file_count
                ),
            )
        } else if d.ignored == Some(false) {
            let unknown = if d.git_state_unknown > 0 {
                format!(" (git state unknown for {} file(s))", d.git_state_unknown)
            } else {
                String::new()
            };
            (
                Severity::Low,
                format!(
                    "{} output directory ({} file(s)) is not ignored by git — it will be committed by `git add -A`{unknown}",
                    d.framework, d.file_count
                ),
            )
        } else {
            continue;
        };
        f.push(Finding {
            severity,
            category: "Transcript exposure".into(),
            title,
            location: d.path.clone(),
            evidence: Some("add the directory to .gitignore (and `git rm -r --cached` it if tracked)".into()),
        });
    }
}

/// Mistral Vibe settings that remove a prompt or pull code on their own.
fn vibe_findings(report: &ScanReport, f: &mut Vec<Finding>) {
    for c in &report.surfaces.vibe_configs {
        if c.auto_approve == Some(true) {
            f.push(Finding {
                severity: Severity::Medium,
                category: "Permissions".into(),
                title: "Mistral Vibe auto_approve = true: every tool call runs without asking".into(),
                location: c.path.clone(),
                evidence: Some("auto_approve = true".into()),
            });
        }
        if c.tool_permissions.get("bash").map(String::as_str) == Some("always") {
            f.push(Finding {
                severity: Severity::High,
                category: "Permissions".into(),
                title: "Mistral Vibe runs shell commands without asking (tools.bash.permission = \"always\")".into(),
                location: c.path.clone(),
                evidence: Some("[tools.bash] permission = \"always\"".into()),
            });
        }
        if c.enable_auto_update == Some(true) {
            f.push(Finding {
                severity: Severity::Low,
                category: "Plugin marketplace".into(),
                title: "Mistral Vibe auto-updates (enable_auto_update = true) — remote code installs without review (EAA-009; Vibe 2.5.0 acts on the key, current Vibe docs say it no longer has an effect)".into(),
                location: c.path.clone(),
                evidence: Some("enable_auto_update = true".into()),
            });
        }
        if let Some(env) = &c.env_file
            && (env.world_readable || env.group_readable)
        {
            let who = if env.world_readable { "other users" } else { "its group" };
            let (severity, title) = match &env.unreachable_via {
                Some(why) => (
                    Severity::Low,
                    format!(
                        "Mistral Vibe API-key file is readable by {who} (mode {}) — not reachable: {why}",
                        env.mode
                    ),
                ),
                None if env.world_readable => (
                    Severity::High,
                    format!("Mistral Vibe API-key file is readable by {who} (mode {})", env.mode),
                ),
                None => (
                    Severity::Medium,
                    format!("Mistral Vibe API-key file is readable by {who} (mode {})", env.mode),
                ),
            };
            f.push(Finding {
                severity,
                category: "Secret exposure".into(),
                title,
                location: env.path.clone(),
                evidence: None,
            });
        }
    }
}

/// The display name of a round-4 agent label (closed: `AgentPosture::agent`).
fn agent_name(agent: &str) -> &'static str {
    match agent {
        "cline" => "Cline",
        "roo-code" => "Roo Code",
        "continue" => "Continue",
        "aider" => "Aider",
        "goose" => "Goose",
        "zed" => "Zed",
        "junie" => "Junie",
        "amp" => "Amp",
        "warp" => "Warp",
        "cursor" => "Cursor",
        "devin" => "Devin",
        "copilot" => "Copilot CLI",
        "gemini" => "Gemini CLI",
        "codex" => "Codex",
        "kiro" => "Kiro",
        "opencode" => "OpenCode",
        _ => "agent",
    }
}

/// Round-4 agents' settings (`scanners::agents_more`), on the permission-mode ladder:
///
/// - a setting that lets the agent run every action, or every shell command, without asking
///   (`all-actions`, `shell-commands`): Medium in the user's own configuration (as Mistral
///   Vibe's `auto_approve`), High in a repository file (the repository decides it for
///   whoever opens it). A product default the configuration did not write (Goose's
///   `GOOSE_MODE` unset, Amp's tool approval) is Low and says so;
/// - Zed `session.trust_all_worktrees` (`untrusted-projects`: "MCP servers are downloaded
///   and started automatically" for any folder): Medium;
/// - MCP tools pre-approved by a repository file (Roo Code `.roo/mcp.json` `alwaysAllow`):
///   Medium "MCP auto-approval"; in the user's own files, inventory;
/// - commands a repository file makes the agent run after every edit (Aider `lint-cmd`,
///   `test-cmd` with `auto-test`): Medium "Auto-run task";
/// - hook executables a repository ships for Cline (`.clinerules/hooks/`, hooks enabled by
///   default): Medium "Hook"; the user's own hooks are inventory;
/// - an API-key file other users or the group can read: the Mistral Vibe `.env` rule.
///
/// - a sandbox turned off (Codex `danger-full-access`, Cursor `insecure_none`:
///   `sandbox-off`): Low in the user's own configuration (commands still ask unless
///   approved), Medium in a repository file; a sandbox opened to all network traffic
///   (`sandbox-network`): Low from a repository, inventory in the user's own file;
/// - a command a repository file makes the agent start by itself (Copilot CLI
///   `.github/lsp.json` language servers, a Gemini CLI subagent's `!command` auth value):
///   Medium "Auto-run task";
/// - an administrator's file (`scope: managed`: Codex `managed_config.toml`, OpenCode's
///   managed directory, Cursor team hooks): inventory.
///
/// File edits, browser use and per-tool lists are inventory.
fn agent_posture_findings(report: &ScanReport, f: &mut Vec<Finding>) {
    for p in &report.surfaces.agent_postures {
        if p.scope == "managed" {
            continue;
        }
        let name = agent_name(&p.agent);
        let repo = p.scope == "project";
        for a in &p.auto_approve {
            let what = match a.reach.as_str() {
                "all-actions" => "every action runs without asking",
                "shell-commands" => "shell commands run without asking",
                "untrusted-projects" => "every folder is trusted: project MCP servers and settings load without asking",
                "mcp-tools" if repo => "MCP tools run without asking",
                "sandbox-off" => "the sandbox is turned off: approved commands run with full access",
                "sandbox-network" if repo => "the sandbox allows all outbound network traffic",
                _ => continue,
            };
            let mcp = a.reach == "mcp-tools";
            let sandbox = a.reach.starts_with("sandbox-");
            let (severity, note) = if sandbox {
                match (a.reach.as_str(), repo) {
                    ("sandbox-off", true) => (Severity::Medium, " (set by the repository)"),
                    (_, true) => (Severity::Low, " (set by the repository)"),
                    _ => (Severity::Low, ""),
                }
            } else if mcp {
                (Severity::Medium, " (set by the repository)")
            } else if a.default {
                (Severity::Low, " (product default)")
            } else if repo {
                (Severity::High, " (set by the repository)")
            } else {
                (Severity::Medium, "")
            };
            f.push(Finding {
                severity,
                category: if mcp { "MCP auto-approval" } else { "Permissions" }.into(),
                title: format!("{name}: {what}{note} — {} = {}", a.setting, a.value),
                location: p.path.clone(),
                evidence: Some(format!("{} = {}", a.setting, a.value)),
            });
        }
        if repo && p.mcp_auto_approved_tools > 0 {
            f.push(Finding {
                severity: Severity::Medium,
                category: "MCP auto-approval".into(),
                title: format!(
                    "{name}: the repository pre-approves {} MCP tool(s) (they run without asking)",
                    p.mcp_auto_approved_tools
                ),
                location: p.path.clone(),
                evidence: None,
            });
        }
        if repo && !p.auto_run_commands.is_empty() {
            let when = match p.agent.as_str() {
                "copilot" => "starts a language server command once the folder is trusted",
                "gemini" => "makes a subagent run a shell command for its credentials",
                _ => "runs a command after every edit",
            };
            f.push(Finding {
                severity: Severity::Medium,
                category: "Auto-run task".into(),
                title: format!(
                    "{name}: the repository's config {when} ({})",
                    p.auto_run_commands.join("; ")
                ),
                location: p.path.clone(),
                evidence: Some(p.auto_run_commands.join("; ")),
            });
        }
        if repo && p.agent == "cline" && !p.hook_files.is_empty() {
            f.push(Finding {
                severity: Severity::Medium,
                category: "Hook".into(),
                title: format!(
                    "Cline: the repository ships {} hook executable(s) that run on agent events ({})",
                    p.hook_files.len(),
                    p.hook_files.join(", ")
                ),
                location: p.path.clone(),
                evidence: None,
            });
        }
        for k in p.key_files.iter().filter(|k| k.world_readable || k.group_readable) {
            let who = if k.world_readable { "other users" } else { "its group" };
            let (severity, title) = match &k.unreachable_via {
                Some(why) => (
                    Severity::Low,
                    format!(
                        "{name} key file is readable by {who} (mode {}) — not reachable: {why}",
                        k.mode
                    ),
                ),
                None if k.world_readable => (
                    Severity::High,
                    format!("{name} key file is readable by {who} (mode {})", k.mode),
                ),
                None => (
                    Severity::Medium,
                    format!("{name} key file is readable by {who} (mode {})", k.mode),
                ),
            };
            f.push(Finding {
                severity,
                category: "Secret exposure".into(),
                title,
                location: k.path.clone(),
                evidence: None,
            });
        }
    }
}

/// A script a settings command runs that someone other than its owner can change runs
/// their code every time the setting fires (the `~/.claude/bin` rule).
fn settings_script_findings(report: &ScanReport, f: &mut Vec<Finding>) {
    for s in &report.surfaces.settings_command_scripts {
        let why = if s.bin.world_writable {
            "writable by group or other"
        } else if !s.bin.owned_by_user {
            "not owned by you"
        } else {
            continue;
        };
        f.push(Finding {
            severity: Severity::High,
            category: "Persistence".into(),
            title: format!(
                "Script your {} setting runs is {why}: whoever can change it runs code each time it fires ({}, {})",
                s.setting, s.bin.format, s.bin.mode
            ),
            location: s.path.clone(),
            evidence: Some(format!("set in {}", s.settings_path)),
        });
    }
}

/// The directory part of a report path (`/a/b/.env` -> `/a/b`).
fn parent_of(path: &str) -> &str {
    path.rsplit_once('/')
        .map(|(d, _)| if d.is_empty() { "/" } else { d })
        .unwrap_or("")
}

/// The `env_files` rows of this report that are world-readable, hold secret-named keys,
/// sit in the listener's working directory or its project directory, and are reachable
/// by other users (no ancestor without o+x, `EnvFile::unreachable_via`). By reference:
/// the files are not read again.
pub fn readable_secret_env<'a>(
    report: &'a ScanReport,
    l: &crate::models::NetworkListener,
) -> Vec<&'a crate::models::EnvFile> {
    secret_env_by_mode(report, l)
        .into_iter()
        .filter(|e| e.unreachable_via.is_none())
        .collect()
}

/// [`readable_secret_env`] by mode bits alone, reachable or not.
fn secret_env_by_mode<'a>(
    report: &'a ScanReport,
    l: &crate::models::NetworkListener,
) -> Vec<&'a crate::models::EnvFile> {
    let dirs: Vec<&str> = [l.cwd.as_deref(), l.project.as_deref()].into_iter().flatten().collect();
    if dirs.is_empty() {
        return Vec::new();
    }
    report
        .env_files
        .iter()
        .filter(|e| e.world_readable && !e.secret_keys.is_empty())
        .filter(|e| dirs.contains(&parent_of(&e.path)))
        .collect()
}

/// Fill each listener's `readable_secret_files` from the report's `env_files` rows. Run
/// once by `main` after every scanner (the listeners job is global, the env-file job runs
/// per home pass).
pub fn correlate_listeners(report: &mut ScanReport) {
    let counts: Vec<usize> = report
        .surfaces
        .network_listeners
        .iter()
        .map(|l| {
            if l.bind.is_network_reachable() && l.project.is_some() {
                readable_secret_env(report, l).len()
            } else {
                0
            }
        })
        .collect();
    for (l, n) in report.surfaces.network_listeners.iter_mut().zip(counts) {
        l.readable_secret_files = n;
    }
}

/// How a set of bind classes reads in a title.
fn bind_text(classes: &std::collections::BTreeSet<crate::models::BindClass>, addrs: &[&str]) -> String {
    use crate::models::BindClass;
    let mut parts: Vec<String> = Vec::new();
    for c in classes {
        parts.push(match c {
            BindClass::AllInterfaces => "all interfaces".to_string(),
            BindClass::Ipv6Any => "all IPv6 interfaces (::)".to_string(),
            BindClass::SpecificAddress => format!("address {}", addrs.join(", ")),
            BindClass::Loopback => "loopback".to_string(),
        });
    }
    parts.join(" and ")
}

/// A listener in one of the scan's projects, bound beyond loopback, owned by the user (the
/// scanner keeps only the user's sockets): High when it hands out a shell or a terminal
/// (a PTY master, a tmux/screen child, a known bridge name), Critical when its directory
/// also holds a world-readable `.env` with secret-named keys that other users can reach
/// (High, "not reachable", behind a 0700 directory); a shell child alone is Medium "may
/// hand out a shell" (High with such an env file). Low when it hands out nothing and is not a common development server. One finding per
/// process (its ports together). Loopback listeners and listeners outside every project
/// are inventory.
fn listener_findings(report: &ScanReport, f: &mut Vec<Finding>) {
    use crate::models::{NetworkListener, ServesShell};
    use std::collections::{BTreeMap, BTreeSet};
    let mut by_pid: BTreeMap<u32, Vec<&NetworkListener>> = BTreeMap::new();
    for l in &report.surfaces.network_listeners {
        if let (Some(pid), true, true) = (l.pid, l.bind.is_network_reachable(), l.project.is_some()) {
            by_pid.entry(pid).or_default().push(l);
        }
    }
    for (pid, ls) in by_pid {
        let first = ls[0];
        let program = first.program.as_deref().unwrap_or("unknown");
        let project = first.project.as_deref().unwrap_or("");
        let mut ports: Vec<u16> = ls.iter().map(|l| l.port).collect();
        ports.sort_unstable();
        ports.dedup();
        let ports_text = ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ");
        let port_word = if ports.len() == 1 { "port" } else { "ports" };
        let classes: BTreeSet<_> = ls.iter().map(|l| l.bind).collect();
        let specific: Vec<&str> = ls
            .iter()
            .filter(|l| l.bind == crate::models::BindClass::SpecificAddress)
            .map(|l| l.address.as_str())
            .collect();
        let bound = bind_text(&classes, &specific);
        let age = first
            .age_days
            .map(|d| format!(", running {d} day{}", if d == 1 { "" } else { "s" }))
            .unwrap_or_default();
        let location = first.cwd.clone().unwrap_or_else(|| project.to_string());
        if first.serves_shell != ServesShell::None {
            let envs: Vec<&crate::models::EnvFile> = {
                let mut v = Vec::new();
                for l in &ls {
                    for e in readable_secret_env(report, l) {
                        if !v.iter().any(|x: &&crate::models::EnvFile| x.path == e.path) {
                            v.push(e);
                        }
                    }
                }
                v
            };
            let base = format!(
                "a network listener in project {project} hands out a shell/PTY (program {program}, {port_word} {ports_text}, bound to {bound}{age})"
            );
            // World-readable by mode but behind a directory other users cannot traverse:
            // the credentials are not theirs to read, so the grade stays High.
            let mut blocked: Vec<String> = Vec::new();
            if envs.is_empty() {
                for l in &ls {
                    for e in secret_env_by_mode(report, l) {
                        if let Some(why) = &e.unreachable_via
                            && !blocked.contains(why)
                        {
                            blocked.push(why.clone());
                        }
                    }
                }
            }
            let (severity, title) = if envs.is_empty() && !blocked.is_empty() {
                (
                    Severity::High,
                    format!(
                        "{base}; its directory holds an env file with secret-named keys, world-readable by mode (not reachable: {})",
                        blocked.join(", ")
                    ),
                )
            } else if envs.is_empty() && first.serves_shell == ServesShell::ShellChild {
                // A shell child alone (a server that ran `bash` when the scan looked) may
                // be a build step or a hook, not a terminal handed to the network.
                (
                    Severity::Medium,
                    format!(
                        "a network listener in project {project} may hand out a shell: it had a shell child when scanned (program {program}, {port_word} {ports_text}, bound to {bound}{age})"
                    ),
                )
            } else if envs.is_empty() {
                (Severity::High, base)
            } else if first.serves_shell == ServesShell::ShellChild {
                let mut names: Vec<&str> = Vec::new();
                for e in &envs {
                    for k in &e.secret_keys {
                        if !names.contains(&k.as_str()) {
                            names.push(k);
                        }
                    }
                }
                (
                    Severity::High,
                    format!(
                        "a network listener in project {project} may hand out a shell: it had a shell child when scanned (program {program}, {port_word} {ports_text}, bound to {bound}{age}), and its directory holds a world-readable env file with secret-named keys (names only: {})",
                        names.iter().take(8).copied().collect::<Vec<_>>().join(", ")
                    ),
                )
            } else {
                let mut names: Vec<&str> = Vec::new();
                for e in &envs {
                    for k in &e.secret_keys {
                        if !names.contains(&k.as_str()) {
                            names.push(k);
                        }
                    }
                }
                let shown = if names.len() > 8 {
                    format!("{}, ...", names[..8].join(", "))
                } else {
                    names.join(", ")
                };
                (
                    Severity::Critical,
                    format!(
                        "{base} and its directory holds a world-readable env file with secret-named keys (names only: {shown})"
                    ),
                )
            };
            let signal = first.shell_signal.as_deref().unwrap_or(first.serves_shell.label());
            let env_note = if envs.is_empty() {
                String::new()
            } else {
                format!(
                    " · world-readable: {}",
                    envs.iter().map(|e| e.path.as_str()).collect::<Vec<_>>().join(", ")
                )
            };
            f.push(Finding {
                severity,
                category: "Network listener".into(),
                title,
                location,
                evidence: Some(format!(
                    "pid {pid} · shell signal {} ({signal}){env_note} · bind to 127.0.0.1 or a VPN interface, move the credentials out of the world-readable file, run it on its own tmux server (`tmux -L`)",
                    first.serves_shell.label()
                )),
            });
        } else if !crate::scanners::listeners::is_dev_server_listener(first) {
            f.push(Finding {
                severity: Severity::Low,
                category: "Network listener".into(),
                title: format!(
                    "project process listening on {bound}: {program} on {port_word} {ports_text} in project {project}{age}"
                ),
                location,
                evidence: Some(format!(
                    "pid {pid} · no shell or terminal signal · bind to 127.0.0.1 unless other machines must reach it"
                )),
            });
        }
    }
}

/// The `claude_store_finding` group of a Claude Code store path: its directory, and for
/// `~/.claude.json` and its backup the `.claude` directory beside them (as
/// `crate::analysis` keys the rows).
fn claude_group(path: &str) -> String {
    let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
    if name == ".claude.json" || name == ".claude.json.backup" {
        format!("{parent}/.claude")
    } else {
        parent.to_string()
    }
}

/// The "Transcript exposure" finding that reports `t` as readable by other users: the
/// one Claude Code state finding of its home, or the store's own finding.
fn transcript_exposure_slot(f: &[Finding], t: &crate::models::AgentTranscriptStore) -> Option<usize> {
    f.iter().position(|x| {
        x.category == "Transcript exposure"
            && if t.framework == "claude-code" {
                x.title.starts_with("Claude Code state under") && claude_group(&x.location) == claude_group(&t.path)
            } else {
                x.location == t.path
            }
    })
}

/// One step up, at most Critical.
fn raised(s: Severity) -> Severity {
    match s {
        Severity::Low => Severity::Medium,
        Severity::Medium => Severity::High,
        Severity::High | Severity::Critical => Severity::Critical,
    }
}

/// `items` joined with ", ", at most `max` of them and "+N more".
fn capped(items: &[&str], max: usize) -> String {
    let mut s = items.iter().take(max).copied().collect::<Vec<_>>().join(", ");
    if items.len() > max {
        s.push_str(&format!(" +{} more", items.len() - max));
    }
    s
}

/// The token labels then the key names of one sample, names and labels only.
fn shape_labels(s: &crate::models::TranscriptSecretShapes) -> Vec<&str> {
    s.token_prefix_labels
        .iter()
        .chain(s.secret_key_names.iter())
        .map(String::as_str)
        .collect()
}

/// One store's sample for an evidence line: `<path> (<framework> <kind>): K of S sampled
/// files; token labels: ...; key names: ...`. Store path, counts, labels and names only.
fn shape_row(t: &crate::models::AgentTranscriptStore) -> String {
    let s = &t.secret_shapes;
    let mut row = format!(
        "{} ({} {}): {} of {} sampled files{}",
        t.path,
        t.framework,
        t.kind,
        s.files_with_secret_shapes,
        s.files_sampled,
        if s.sampling_truncated {
            " (sample truncated)"
        } else {
            ""
        }
    );
    if !s.token_prefix_labels.is_empty() {
        let l: Vec<&str> = s.token_prefix_labels.iter().map(String::as_str).collect();
        row.push_str(&format!(
            "; token labels: {} ({} strings)",
            l.join(", "),
            s.token_shaped_strings
        ));
    }
    if !s.secret_key_names.is_empty() {
        let n: Vec<&str> = s.secret_key_names.iter().map(String::as_str).collect();
        row.push_str(&format!(
            "; key names: {}{}",
            capped(&n, 12),
            if s.secret_key_names_truncated {
                " (more than 50)"
            } else {
                ""
            }
        ));
    }
    row
}

/// Transcript stores whose sampled content mentions secret-named keys or token-shaped
/// strings (by name and label only: [`crate::models::TranscriptSecretShapes`]). Value-gated
/// on who can read the files that show them:
///
/// - a store other users can read (a shape-bearing file with o+r reached through o+x
///   directories, and no ancestor they cannot traverse) raises its "Transcript exposure"
///   finding one step (at most Critical) and the title says it "contains secret-shaped
///   content (labels: ...)";
/// - otherwise the stores of one home are one Low "Secret hygiene" advisory: the user's
///   own transcripts hold what was pasted into or printed in a conversation.
///
/// Claude Code's session-env and shell-snapshots stores readable by others are graded by
/// their exported NAMES already and are not raised again by their content.
///
/// A store with no shapes yields nothing.
fn transcript_content_findings(report: &ScanReport, f: &mut Vec<Finding>) {
    use crate::scanners::transcripts::{SESSION_ENV, SHELL_SNAPSHOTS};
    use std::collections::{BTreeMap, BTreeSet};
    let mut raise: BTreeMap<usize, Vec<&crate::models::AgentTranscriptStore>> = BTreeMap::new();
    let mut advise: BTreeMap<String, Vec<&crate::models::AgentTranscriptStore>> = BTreeMap::new();
    for t in report.transcripts.iter().filter(|t| t.secret_shapes.any()) {
        let s = &t.secret_shapes;
        let exposed = t.world_readable && t.unreachable_via.is_none() && s.other_readable_files_with_secret_shapes > 0;
        // session-env and shell-snapshots readable by others are already graded by the
        // NAMES they export (High for a secret-named one): the same text does not raise
        // the finding a second time.
        if exposed && t.framework == "claude-code" && matches!(t.kind.as_str(), SHELL_SNAPSHOTS | SESSION_ENV) {
            continue;
        }
        match exposed.then(|| transcript_exposure_slot(f, t)).flatten() {
            Some(i) => raise.entry(i).or_default().push(t),
            None => advise
                .entry(s.scan_home.clone().unwrap_or_default())
                .or_default()
                .push(t),
        }
    }
    for (i, stores) in raise {
        let mut labels: Vec<&str> = Vec::new();
        for t in &stores {
            for l in shape_labels(&t.secret_shapes) {
                if !labels.contains(&l) {
                    labels.push(l);
                }
            }
        }
        let slot = &mut f[i];
        slot.severity = raised(slot.severity);
        slot.title = format!(
            "{} and contains secret-shaped content (labels: {})",
            slot.title,
            capped(&labels, 8)
        );
        let rows: Vec<String> = stores.iter().map(|t| shape_row(t)).collect();
        let shapes = format!("secret-shaped content, names and labels only: {}", rows.join("; "));
        slot.evidence = Some(match slot.evidence.take() {
            Some(e) => format!("{e}; {shapes}"),
            None => shapes,
        });
    }
    for (home, stores) in advise {
        let names: BTreeSet<&str> = stores
            .iter()
            .flat_map(|t| t.secret_shapes.secret_key_names.iter().map(String::as_str))
            .collect();
        let tokens: usize = stores.iter().map(|t| t.secret_shapes.token_shaped_strings).sum();
        let location = if home.is_empty() { stores[0].path.clone() } else { home };
        f.push(Finding {
            severity: Severity::Low,
            category: "Secret hygiene".into(),
            title: format!(
                "agent transcripts mention {} secret-named key{} / {tokens} token-shaped string{}; consider rotating anything pasted into a conversation",
                names.len(),
                if names.len() == 1 { "" } else { "s" },
                if tokens == 1 { "" } else { "s" }
            ),
            location,
            evidence: Some(stores.iter().map(|t| shape_row(t)).collect::<Vec<_>>().join("; ")),
        });
    }
}
