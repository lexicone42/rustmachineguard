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
    settings_script_findings(report, f);
    listener_findings(report, f);
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
