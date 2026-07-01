use crate::models::EnvFile;
use crate::platform::PlatformInfo;
use crate::scanners::{file_perms, is_git_tracked, read_bounded, Scanner};
use std::path::{Path, PathBuf};

/// Detects `.env` files in agent project roots. Agents routinely read the working
/// directory, so a `.env` full of secrets in a project an agent operates on is an
/// agent-exposure concern; a git-tracked `.env` is a committed-secret leak.
///
/// SECURITY: parses key NAMES only to flag secret-bearing keys and count entries — it
/// never reads, stores, or emits the values.
pub struct EnvFilesScanner;

const ENV_FILENAMES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.test",
];

/// Substrings in a key NAME that suggest it holds a secret.
const SECRET_KEY_HINTS: &[&str] = &[
    "TOKEN", "SECRET", "KEY", "PASSWORD", "PASSWD", "CREDENTIAL", "AUTH", "PRIVATE",
];

/// True if a variable/key NAME looks like it holds a secret (name-only heuristic;
/// never inspects the value). Shared with the MCP scanner's inline-secret check.
pub fn is_secret_key_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    SECRET_KEY_HINTS.iter().any(|h| upper.contains(h))
}

impl Scanner for EnvFilesScanner {
    type Output = Vec<EnvFile>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<EnvFile> {
        let home = platform.home_dir();
        let mut dirs = extract_project_dirs(&home.join(".claude.json")).unwrap_or_default();
        if let Ok(cwd) = std::env::current_dir() {
            dirs.push(cwd);
        }

        let mut results = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for dir in dirs {
            for name in ENV_FILENAMES {
                let path = dir.join(name);
                if !path.is_file() || !seen.insert(path.clone()) {
                    continue;
                }
                results.push(scan_env_file(&path));
            }
        }
        results
    }
}

fn scan_env_file(path: &Path) -> EnvFile {
    let (key_count, secret_keys) = match read_bounded(path) {
        Some(content) => parse_env_keys(&content),
        None => (0, Vec::new()),
    };
    let (_, world_readable, _) = file_perms(path).unwrap_or((String::new(), false, false));
    EnvFile {
        path: path.display().to_string(),
        git_tracked: is_git_tracked(path),
        world_readable,
        key_count,
        secret_keys,
    }
}

/// Parse `KEY=value` lines, returning (total key count, secret-looking key NAMES).
/// Values are never retained.
pub fn parse_env_keys(content: &str) -> (usize, Vec<String>) {
    let mut count = 0;
    let mut secrets = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, _value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        count += 1;
        if is_secret_key_name(key) && !secrets.contains(&key.to_string()) {
            secrets.push(key.to_string());
        }
    }
    (count, secrets)
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
