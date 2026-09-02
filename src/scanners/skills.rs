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
        if crate::scanners::probe_dir(&codex_dir) {
            scan_skill_dir(&codex_dir, "codex", "global", &mut results);
        }

        // Skill BUNDLES (SKILL.md + sibling scripts), which the flat walk above cannot
        // see. `plugins/` covers the marketplace -> plugin -> skill chain: marketplaces
        // are already inventoried as a remote hot-load surface, but the skills they
        // actually install were never walked.
        scan_skill_bundles(&home.join(".claude").join("skills"), "claude-code", "global", &mut results);
        scan_skill_bundles(&home.join(".claude").join("plugins"), "claude-code-plugin", "global", &mut results);
        if let Some(project_dirs) = extract_project_dirs(&home.join(".claude.json")) {
            for dir in project_dirs {
                scan_skill_bundles(&dir.join(".claude").join("skills"), "claude-code", "project", &mut results);
            }
        }
        if let Ok(cwd) = std::env::current_dir() {
            scan_skill_bundles(&cwd.join(".claude").join("skills"), "claude-code", "project", &mut results);
        }

        // Dedupe by path
        let mut seen = std::collections::HashSet::new();
        results.retain(|r| seen.insert(r.path.clone()));

        results
    }
}

/// Cap the recursive bundle walk so a pathological tree can't hang the scan.
const MAX_BUNDLE_FILES: usize = 5_000;

/// Recursively discover skill BUNDLES: a `SKILL.md` manifest plus the scripts shipped
/// alongside it.
///
/// Modern agent skills are not flat files in `commands/` — they are directories
/// (`skills/<name>/SKILL.md` + `scripts/*.sh|*.py|*.js`), and they arrive through the
/// marketplace -> plugin -> skill chain under `~/.claude/plugins/`. The flat
/// `scan_skill_dir` walk cannot see any of it: it does not recurse, so on a machine with
/// 200 installed `SKILL.md` manifests it happily reports the three (empty) directories
/// it does know about.
///
/// Bundled siblings are inventoried too, not just the manifest: the manifest routinely
/// reads clean while the payload sits in an adjacent script.
fn scan_skill_bundles(
    root: &std::path::Path,
    framework: &str,
    scope: &str,
    results: &mut Vec<AgentSkill>,
) {
    if !crate::scanners::probe_dir(&root) {
        return;
    }
    let mut budget = MAX_BUNDLE_FILES;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = crate::scanners::probe_read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if budget == 0 {
                return;
            }
            let path = entry.path();
            // symlink_metadata: never follow a link out of the tree we were pointed at.
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            budget -= 1;
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            // The manifest, or a script shipped beside it.
            let is_manifest = file_name.eq_ignore_ascii_case("SKILL.md");
            if !is_manifest && !matches!(ext, "sh" | "bash" | "py" | "js" | "ts" | "mjs") {
                continue;
            }
            let content = read_bounded(&path);
            // A manifest is named by its bundle directory (the unit users think in);
            // a bundled script is named by its path relative to the walk root, which
            // stays unambiguous when several bundles each ship a `scripts/run.sh`.
            let name = if is_manifest {
                path.parent()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string()
            } else {
                path.strip_prefix(root)
                    .ok()
                    .and_then(|rel| rel.to_str())
                    .map(String::from)
                    .unwrap_or_else(|| file_name.to_string())
            };
            results.push(AgentSkill {
                name: crate::scanners::sanitize_display(&name, 128),
                path: path.to_string_lossy().to_string(),
                framework: framework.to_string(),
                scope: scope.to_string(),
                file_type: if is_manifest { "skill-manifest".into() } else { ext.to_string() },
                size_bytes: content.as_ref().map(|c| c.len()).unwrap_or(0),
                sha256: content
                    .as_ref()
                    .map(|c| sha256_hex(c))
                    .unwrap_or_else(|| "unreadable".to_string()),
                capabilities: content.as_ref().map(|c| infer_capabilities(c)).unwrap_or_default(),
            });
        }
    }
}

fn scan_skill_dir(
    dir: &std::path::Path,
    framework: &str,
    scope: &str,
    results: &mut Vec<AgentSkill>,
) {
    let Ok(entries) = crate::scanners::probe_read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !crate::scanners::probe_file(&path) {
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
            name: crate::scanners::sanitize_display(&name, 128),
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
        .filter(|p| crate::scanners::probe_dir(&p))
        .collect();
    if dirs.is_empty() {
        None
    } else {
        Some(dirs)
    }
}

fn sha256_hex(content: &str) -> String {
    super::sha256_hex(content)
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
