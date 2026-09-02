use crate::models::VsCodeTask;
use crate::platform::PlatformInfo;
use crate::scanners::{is_git_tracked, read_bounded, Scanner};
use std::path::{Path, PathBuf};

/// Scans `.vscode/tasks.json` for tasks that execute automatically when a folder is
/// opened (`runOptions.runOn == "folderOpen"`).
///
/// This is the other half of the 2026 persistence pair. `agent_settings` covers the
/// agent hook that points at a script in `.vscode/`; this covers the VS Code task that
/// points back at a script in `.claude/`. Detecting only one half misses the campaign,
/// because either half alone re-establishes the other.
///
/// VS Code does gate this — `task.allowAutomaticTasks` defaults to "off" with a
/// one-time prompt, and automatic tasks never run in an untrusted workspace — so the
/// finding is graded rather than treated as automatic execution.
pub struct VsCodeTasksScanner;

impl Scanner for VsCodeTasksScanner {
    type Output = Vec<VsCodeTask>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Self::Output {
        let home = platform.home_dir();
        let mut dirs = extract_project_dirs(&home.join(".claude.json")).unwrap_or_default();
        if let Ok(cwd) = std::env::current_dir() {
            dirs.push(cwd);
        }
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for dir in dirs {
            let path = dir.join(".vscode").join("tasks.json");
            if !seen.insert(path.clone()) {
                continue;
            }
            parse_tasks(&path, &mut out);
        }
        out
    }
}

/// Project roots registered with Claude Code — the same set the other project-scoped
/// scanners use, so a repo the agent works in is covered.
fn extract_project_dirs(claude_json: &Path) -> Option<Vec<PathBuf>> {
    let content = read_bounded(claude_json)?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;
    Some(
        parsed
            .get("projects")?
            .as_object()?
            .keys()
            .map(PathBuf::from)
            .filter(|p| crate::scanners::probe_dir(&p))
            .collect(),
    )
}

fn parse_tasks(path: &Path, out: &mut Vec<VsCodeTask>) {
    if !crate::scanners::probe_file(&path) {
        return;
    }
    let Some(content) = read_bounded(path) else {
        return;
    };
    // tasks.json permits comments and trailing commas (JSONC). serde_json rejects both,
    // so strip them first rather than silently skipping every commented config.
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&strip_jsonc(&content)) else {
        return;
    };
    let Some(tasks) = json.get("tasks").and_then(|t| t.as_array()) else {
        return;
    };
    let git_tracked = is_git_tracked(path);
    for task in tasks {
        let run_on_folder_open = task
            .get("runOptions")
            .and_then(|r| r.get("runOn"))
            .and_then(|v| v.as_str())
            .map(|s| s.eq_ignore_ascii_case("folderOpen"))
            .unwrap_or(false);
        if !run_on_folder_open {
            continue;
        }
        let label = task
            .get("label")
            .and_then(|v| v.as_str())
            .unwrap_or("(unlabeled)")
            .to_string();
        // The executed text is `command` plus any args.
        let mut command = task
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if let Some(args) = task.get("args").and_then(|a| a.as_array()) {
            for a in args.iter().filter_map(|v| v.as_str()) {
                command.push(' ');
                command.push_str(a);
            }
        }
        if command.trim().is_empty() {
            continue;
        }
        // Reuse the hook classifier: a folderOpen task pointing into an agent-config
        // directory is the mirror image of an agent hook pointing into .vscode/.
        let risks = crate::scanners::agent_settings::classify_hook_command(&command, path);
        let dangerous =
            !crate::scanners::rules_files::check_dangerous_patterns(&command).is_empty();
        out.push(VsCodeTask {
            path: path.to_string_lossy().to_string(),
            label,
            // Redacted for storage; `dangerous` and `risks` above were computed from
            // the raw command, so detection is unaffected.
            command: crate::scanners::redact_secrets_in_text(&command),
            git_tracked,
            dangerous,
            risks,
        });
    }
}

/// Strip `//` and `/* */` comments and trailing commas so JSONC parses as JSON.
/// String-aware, so a `//` inside a string literal (a URL, a path) is preserved.
pub fn strip_jsonc(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => {
                for n in chars.by_ref() {
                    if n == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut prev = '\0';
                for n in chars.by_ref() {
                    if prev == '*' && n == '/' {
                        break;
                    }
                    prev = n;
                }
            }
            _ => out.push(c),
        }
    }
    // Drop trailing commas before a closing brace/bracket.
    let mut cleaned = String::with_capacity(out.len());
    let bytes: Vec<char> = out.chars().collect();
    for (i, &c) in bytes.iter().enumerate() {
        if c == ',' {
            if let Some(&next) = bytes[i + 1..].iter().find(|c| !c.is_whitespace()) {
                if next == '}' || next == ']' {
                    continue;
                }
            }
        }
        cleaned.push(c);
    }
    cleaned
}
