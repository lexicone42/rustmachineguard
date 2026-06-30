use crate::models::{AgentHook, AgentSettings};
use crate::platform::PlatformInfo;
use crate::scanners::{is_git_tracked, read_bounded, Scanner};
use std::path::{Path, PathBuf};

/// Scans Claude Code / Codex settings files for hooks (which run shell commands on
/// agent events) and MCP auto-approval flags (workspace-trust bypass). A hook is
/// silent code execution on the agent host; a project-scoped, git-tracked settings
/// file carrying hooks travels with a cloned repository.
pub struct AgentSettingsScanner;

impl Scanner for AgentSettingsScanner {
    type Output = Vec<AgentSettings>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Self::Output {
        let home = platform.home_dir();
        let mut results = Vec::new();

        // User-global Claude Code settings.
        parse_settings(
            &home.join(".claude").join("settings.json"),
            "user-global",
            "claude-code",
            &mut results,
        );

        // Project-scoped settings from known projects + the current directory.
        let mut project_dirs = extract_project_dirs(&home.join(".claude.json")).unwrap_or_default();
        if let Ok(cwd) = std::env::current_dir() {
            project_dirs.push(cwd);
        }
        for dir in project_dirs {
            parse_settings(
                &dir.join(".claude").join("settings.json"),
                "project",
                "claude-code",
                &mut results,
            );
            parse_settings(
                &dir.join(".claude").join("settings.local.json"),
                "local",
                "claude-code",
                &mut results,
            );
        }

        // Dedupe by path (projects + cwd can overlap).
        let mut seen = std::collections::HashSet::new();
        results.retain(|r| seen.insert(r.path.clone()));
        results
    }
}

fn extract_project_dirs(claude_json: &Path) -> Option<Vec<PathBuf>> {
    let content = read_bounded(claude_json)?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;
    let projects = parsed.get("projects")?.as_object()?;
    Some(
        projects
            .keys()
            .map(PathBuf::from)
            .filter(|p| p.is_dir())
            .collect(),
    )
}

fn parse_settings(path: &Path, source: &str, framework: &str, out: &mut Vec<AgentSettings>) {
    if !path.is_file() {
        return;
    }
    let Some(content) = read_bounded(path) else {
        return;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
        return;
    };

    let hooks = extract_hooks(&json);

    let permissions = json.get("permissions");
    let permission_mode = permissions
        .and_then(|p| p.get("defaultMode"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let allow_rules = permissions
        .and_then(|p| p.get("allow"))
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let deny_rules = permissions
        .and_then(|p| p.get("deny"))
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    let auto_approve_mcp = json
        .get("enableAllProjectMcpServers")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let enabled_mcp_servers = json
        .get("enabledMcpjsonServers")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    out.push(AgentSettings {
        path: path.to_string_lossy().to_string(),
        source: source.to_string(),
        framework: framework.to_string(),
        git_tracked: is_git_tracked(path),
        hooks,
        permission_mode,
        allow_rules,
        deny_rules,
        auto_approve_mcp,
        enabled_mcp_servers,
    });
}

/// Parse the Claude Code `hooks` object:
/// `{ "PreToolUse": [ { "matcher": "Bash", "hooks": [ { "type": "command", "command": "..." } ] } ] }`
pub fn extract_hooks(json: &serde_json::Value) -> Vec<AgentHook> {
    let mut hooks = Vec::new();
    let Some(hooks_obj) = json.get("hooks").and_then(|h| h.as_object()) else {
        return hooks;
    };

    for (event, matchers) in hooks_obj {
        let Some(matcher_arr) = matchers.as_array() else {
            continue;
        };
        for entry in matcher_arr {
            let matcher = entry
                .get("matcher")
                .and_then(|m| m.as_str())
                .filter(|s| !s.is_empty() && *s != "*")
                .map(String::from);
            let Some(inner) = entry.get("hooks").and_then(|h| h.as_array()) else {
                continue;
            };
            for h in inner {
                let Some(command) = h.get("command").and_then(|c| c.as_str()) else {
                    continue;
                };
                let dangerous =
                    !crate::scanners::rules_files::check_dangerous_patterns(command).is_empty();
                hooks.push(AgentHook {
                    event: event.clone(),
                    matcher: matcher.clone(),
                    command: command.to_string(),
                    dangerous,
                });
            }
        }
    }
    hooks
}
