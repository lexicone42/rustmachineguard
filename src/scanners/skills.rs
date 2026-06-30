use crate::models::AgentSkill;
use crate::platform::PlatformInfo;
use crate::scanners::{read_bounded, Scanner};
use std::path::PathBuf;

pub struct SkillsScanner;

impl Scanner for SkillsScanner {
    type Output = Vec<AgentSkill>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Self::Output {
        let home = platform.home_dir();
        let mut results = Vec::new();

        // Claude Code custom commands: ~/.claude/commands/
        let global_commands = home.join(".claude").join("commands");
        scan_skill_dir(&global_commands, "claude-code", "global", &mut results);

        // Claude Code project commands from known projects
        let claude_json = home.join(".claude.json");
        if let Some(project_dirs) = extract_project_dirs(&claude_json) {
            for dir in project_dirs {
                let project_commands = dir.join(".claude").join("commands");
                scan_skill_dir(
                    &project_commands,
                    "claude-code",
                    "project",
                    &mut results,
                );
            }
        }

        // Current directory project commands
        if let Ok(cwd) = std::env::current_dir() {
            let cwd_commands = cwd.join(".claude").join("commands");
            scan_skill_dir(&cwd_commands, "claude-code", "project", &mut results);
        }

        // Claude Code hooks: ~/.claude/hooks/ and project-level .claude/hooks/
        let global_hooks = home.join(".claude").join("hooks");
        scan_skill_dir(&global_hooks, "claude-code-hook", "global", &mut results);

        // Codex hooks from ~/.codex/
        let codex_dir = home.join(".codex");
        if codex_dir.is_dir() {
            scan_skill_dir(&codex_dir, "codex", "global", &mut results);
        }

        // Dedupe by path
        let mut seen = std::collections::HashSet::new();
        results.retain(|r| seen.insert(r.path.clone()));

        results
    }
}

fn scan_skill_dir(
    dir: &std::path::Path,
    framework: &str,
    scope: &str,
    results: &mut Vec<AgentSkill>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        // Only scan known skill file types
        if !matches!(ext, "md" | "txt" | "yaml" | "yml" | "json" | "sh" | "bash" | "py" | "js" | "ts") {
            continue;
        }

        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        let content = read_bounded(&path);
        let size_bytes = content.as_ref().map(|c| c.len()).unwrap_or(0);
        let sha256 = content
            .as_ref()
            .map(|c| sha256_hex(c))
            .unwrap_or_else(|| "unreadable".to_string());

        let capabilities = content
            .as_ref()
            .map(|c| infer_capabilities(c))
            .unwrap_or_default();

        results.push(AgentSkill {
            name,
            path: path.to_string_lossy().to_string(),
            framework: framework.to_string(),
            scope: scope.to_string(),
            file_type: ext.to_string(),
            size_bytes,
            sha256,
            capabilities,
        });
    }
}

fn extract_project_dirs(claude_json: &std::path::Path) -> Option<Vec<PathBuf>> {
    let content = read_bounded(claude_json)?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;
    let projects = parsed.get("projects")?.as_object()?;
    let dirs: Vec<PathBuf> = projects
        .keys()
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .collect();
    if dirs.is_empty() {
        None
    } else {
        Some(dirs)
    }
}

fn sha256_hex(content: &str) -> String {
    use std::io::Write;
    let output = std::process::Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| {
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(content.as_bytes());
            }
            child.wait_with_output()
        });

    match output {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            text.split_whitespace()
                .next()
                .unwrap_or("unknown")
                .to_string()
        }
        Err(_) => "unknown".to_string(),
    }
}

/// Infer capability categories from skill content.
/// Based on the 8-resource taxonomy from SkillFortify (arXiv:2603.00195).
pub fn infer_capabilities(content: &str) -> Vec<String> {
    let lower = content.to_lowercase();
    let mut caps = Vec::new();

    // filesystem: file operations, path references
    if lower.contains("read_file")
        || lower.contains("write_file")
        || lower.contains("readfile")
        || lower.contains("writefile")
        || lower.contains("fs.")
        || lower.contains("open(")
        || lower.contains("std::fs")
        || lower.contains("pathbuf")
    {
        caps.push("filesystem".to_string());
    }

    // network: HTTP, URLs, fetch, curl
    if lower.contains("http")
        || lower.contains("fetch")
        || lower.contains("curl")
        || lower.contains("wget")
        || lower.contains("request")
        || lower.contains("socket")
        || lower.contains("tcp")
        || lower.contains("udp")
    {
        caps.push("network".to_string());
    }

    // environment: env vars, secrets
    if lower.contains("env.")
        || lower.contains("getenv")
        || lower.contains("process.env")
        || lower.contains("os.environ")
        || lower.contains("env::")
        || lower.contains("api_key")
        || lower.contains("secret")
    {
        caps.push("environment".to_string());
    }

    // shell: command execution
    if lower.contains("bash")
        || lower.contains("subprocess")
        || lower.contains("os.system")
        || lower.contains("child_process")
        || lower.contains("exec(")
        || lower.contains("system(")
        || lower.contains("popen")
        || lower.contains("command::new")
    {
        caps.push("shell".to_string());
    }

    // skill_invoke: calling other skills/tools
    if lower.contains("tool_use")
        || lower.contains("mcp")
        || lower.contains("invoke")
        || lower.contains("call_tool")
        || lower.contains("use_mcp_tool")
    {
        caps.push("skill_invoke".to_string());
    }

    // clipboard: clipboard access
    if lower.contains("clipboard")
        || lower.contains("pbcopy")
        || lower.contains("pbpaste")
        || lower.contains("xclip")
        || lower.contains("xsel")
    {
        caps.push("clipboard".to_string());
    }

    // browser: browser automation
    if lower.contains("playwright")
        || lower.contains("puppeteer")
        || lower.contains("selenium")
        || lower.contains("browser")
        || lower.contains("headless")
    {
        caps.push("browser".to_string());
    }

    // database: DB access
    if lower.contains("database")
        || lower.contains("sqlite")
        || lower.contains("postgres")
        || lower.contains("mysql")
        || lower.contains("mongodb")
        || lower.contains("redis")
        || lower.contains("select ")
        || lower.contains("insert into")
    {
        caps.push("database".to_string());
    }

    caps
}
