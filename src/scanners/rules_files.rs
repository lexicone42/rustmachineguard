use crate::models::RulesFile;
use crate::platform::PlatformInfo;
use crate::scanners::{read_bounded, Scanner};
use std::path::PathBuf;

pub struct RulesFilesScanner;

const RULES_FILE_NAMES: &[&str] = &[
    ".cursorrules",
    ".cursorignore",
    "copilot-instructions.md",
    ".github/copilot-instructions.md",
    "CLAUDE.md",
    "CLAUDE.local.md",
    ".claude/CLAUDE.md",
    "AGENTS.md",
    ".windsurfrules",
    ".clinerules",
    ".aiderignore",
    // Agent long-term memory / persona files: malicious postinstall scripts append
    // operating instructions here (e.g. Cisco CVE-2026-21852), which the agent then
    // loads into its system prompt every session. Tamper detection (hash + git_tracked)
    // makes cross-session mutation visible via --diff.
    "MEMORY.md",
    "SOUL.md",
    ".serena/memories",
];

/// Dangerous patterns in rules files.
/// Inspired by SkillFortify (arXiv:2603.00195) phase-2 pattern catalog.
const DANGEROUS_PATTERNS: &[(&str, &str, &str)] = &[
    ("curl|wget piped to shell", "curl ", "critical"),
    ("curl|wget piped to shell", "wget ", "critical"),
    ("base64 decode to shell", "base64 -d", "critical"),
    ("base64 decode to shell", "base64 --decode", "critical"),
    ("dynamic code evaluation", "eval(", "high"),
    ("dynamic code evaluation", "exec(", "high"),
    ("shell command execution", "subprocess", "high"),
    ("shell command execution", "os.system", "high"),
    ("shell command execution", "child_process", "high"),
    ("netcat listener", "nc -l", "critical"),
    ("netcat listener", "ncat -l", "critical"),
    ("environment variable exfiltration", "printenv", "medium"),
    ("disable security controls", "--no-verify", "high"),
    ("disable security controls", "ssl_verify", "medium"),
    ("disable security controls", "strict-ssl=false", "high"),
    ("credential access", "_authToken", "high"),
    ("credential access", "GITHUB_TOKEN", "medium"),
    ("credential access", "API_KEY", "medium"),
    ("data exfiltration pattern", "| curl", "critical"),
    ("data exfiltration pattern", "| wget", "critical"),
];

impl Scanner for RulesFilesScanner {
    type Output = Vec<RulesFile>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Self::Output {
        let home = platform.home_dir();
        let mut results = Vec::new();

        // Scan well-known project directories from ~/.claude.json
        let claude_json = home.join(".claude.json");
        if let Some(project_dirs) = extract_project_dirs(&claude_json) {
            for dir in project_dirs {
                scan_directory_for_rules(&dir, &mut results);
            }
        }

        // Also scan the home directory itself
        scan_directory_for_rules(&home, &mut results);

        // Scan current working directory if different from home
        if let Ok(cwd) = std::env::current_dir() {
            if cwd != home {
                scan_directory_for_rules(&cwd, &mut results);
            }
        }

        // Dedupe by path
        let mut seen = std::collections::HashSet::new();
        results.retain(|r| seen.insert(r.path.clone()));

        results
    }
}

fn scan_directory_for_rules(dir: &std::path::Path, results: &mut Vec<RulesFile>) {
    for name in RULES_FILE_NAMES {
        let path = dir.join(name);
        if path.is_file() {
            if let Some(content) = read_bounded(&path) {
                let hash = sha256_hex(&content);
                let git_tracked = is_git_tracked(&path);
                let findings = check_dangerous_patterns(&content);

                results.push(RulesFile {
                    path: path.to_string_lossy().to_string(),
                    file_name: name.to_string(),
                    sha256: hash,
                    git_tracked,
                    size_bytes: content.len(),
                    findings,
                });
            }
        }
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
    super::sha256_hex(content)
}

fn is_git_tracked(path: &std::path::Path) -> bool {
    super::is_git_tracked(path)
}

pub fn check_dangerous_patterns(content: &str) -> Vec<crate::models::RulesFileFinding> {
    let lower = content.to_lowercase();
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for (description, pattern, severity) in DANGEROUS_PATTERNS {
        if lower.contains(&pattern.to_lowercase()) && seen.insert(*description) {
            findings.push(crate::models::RulesFileFinding {
                severity: severity.to_string(),
                pattern: description.to_string(),
            });
        }
    }

    // Cross-channel detection: encoding + network access (SkillFortify information flow check)
    let has_encoding = lower.contains("base64") || lower.contains("encode");
    let has_network = lower.contains("curl")
        || lower.contains("wget")
        || lower.contains("fetch")
        || lower.contains("http");
    if has_encoding && has_network && seen.insert("cross-channel: encoding + network") {
        findings.push(crate::models::RulesFileFinding {
            severity: "high".to_string(),
            pattern: "cross-channel: encoding + network access (potential exfiltration)"
                .to_string(),
        });
    }

    findings
}
