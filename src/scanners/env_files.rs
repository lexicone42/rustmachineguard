use crate::models::{EnvAgentOverride, EnvFile};
use crate::platform::PlatformInfo;
use crate::scanners::{file_perms, is_git_tracked, read_bounded, redact_secrets_in_text, sanitize_display, Scanner};
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
                if !crate::scanners::probe_file(&path) || !seen.insert(path.clone()) {
                    continue;
                }
                results.push(scan_env_file(&path, &dir, &home));
            }
        }
        results
    }
}

fn scan_env_file(path: &Path, project_dir: &Path, home: &Path) -> EnvFile {
    let content = read_bounded(path);
    let (key_count, secret_keys) = match content.as_deref() {
        Some(content) => parse_env_keys(content),
        None => (0, Vec::new()),
    };
    let agent_overrides = content
        .as_deref()
        .map(|c| build_overrides(&parse_env_overrides(c), project_dir, home))
        .unwrap_or_default();
    let (_, world_readable, _) = file_perms(path).unwrap_or((String::new(), false, false));
    EnvFile {
        path: path.display().to_string(),
        git_tracked: is_git_tracked(path),
        world_readable,
        key_count,
        secret_keys,
        agent_overrides,
    }
}

// Redguard AG (Benjamin Faller): Gemini CLI CVE-2026-13745 — a project .env overriding
// GEMINI_CLI_HOME; EAA-007 (0x4D31) for base URLs.
//
/// Keys that relocate an AI agent's home directory or redirect its traffic, and their
/// kind. These VALUES are not secrets (a path or a host), so they are the one exception
/// to "never read a .env value"; everything else stays unread. Variable names from the
/// vendors' docs: Claude Code env-vars (CLAUDE_CONFIG_DIR, ANTHROPIC_BASE_URL,
/// ANTHROPIC_CUSTOM_HEADERS), Codex config (CODEX_HOME), Gemini CLI configuration
/// (GEMINI_CLI_HOME, GOOGLE_GEMINI_BASE_URL), Cursor CLI configuration
/// (CURSOR_CONFIG_DIR), Kiro settings (KIRO_HOME), Ollama FAQ (OLLAMA_HOST).
pub const AGENT_OVERRIDE_KEYS: &[(&str, &str)] = &[
    ("CLAUDE_CONFIG_DIR", "agent-home"),
    ("CODEX_HOME", "agent-home"),
    ("GEMINI_CLI_HOME", "agent-home"),
    ("CURSOR_CONFIG_DIR", "agent-home"),
    ("KIRO_HOME", "agent-home"),
    ("ANTHROPIC_BASE_URL", "gateway"),
    ("OPENAI_BASE_URL", "gateway"),
    ("OPENAI_API_BASE", "gateway"),
    ("GOOGLE_GEMINI_BASE_URL", "gateway"),
    ("ANTHROPIC_CUSTOM_HEADERS", "headers"),
    ("HTTPS_PROXY", "proxy"),
    ("https_proxy", "proxy"),
    ("OLLAMA_HOST", "ollama-host"),
];

/// The agent an agent-home key belongs to.
pub fn agent_for_home_key(key: &str) -> &'static str {
    match key {
        "CLAUDE_CONFIG_DIR" => "Claude Code",
        "CODEX_HOME" => "Codex",
        "GEMINI_CLI_HOME" => "Gemini CLI",
        "CURSOR_CONFIG_DIR" => "Cursor CLI",
        "KIRO_HOME" => "Kiro",
        _ => "agent",
    }
}

/// `(key, value)` for the AGENT_OVERRIDE_KEYS in a .env, in table order, last
/// assignment winning. Same line grammar as [`parse_env_keys`]. Values of every other
/// key are never sliced out, and ANTHROPIC_CUSTOM_HEADERS (which usually carries a
/// credential) is returned with an EMPTY value: only its presence is recorded.
pub fn parse_env_overrides(content: &str) -> Vec<(String, String)> {
    let mut found: std::collections::HashMap<&'static str, String> = std::collections::HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some(eq) = line.find('=') else { continue };
        let key = line[..eq].trim();
        let Some((k, kind)) = AGENT_OVERRIDE_KEYS.iter().find(|(k, _)| *k == key) else {
            continue;
        };
        if *kind == "headers" {
            found.insert(k, String::new());
            continue;
        }
        found.insert(k, env_value(&line[eq + 1..]));
    }
    AGENT_OVERRIDE_KEYS
        .iter()
        .filter_map(|(k, _)| found.remove(k).map(|v| (k.to_string(), v)))
        .collect()
}

/// A dotenv value: trimmed; one pair of surrounding quotes removed; an unquoted value is
/// cut at ` #`.
fn env_value(raw: &str) -> String {
    let v = raw.trim();
    for q in ['"', '\''] {
        if let Some(rest) = v.strip_prefix(q)
            && let Some(end) = rest.find(q)
        {
            return rest[..end].to_string();
        }
    }
    // `KEY= # note` is an empty value followed by a comment.
    if v.starts_with('#') && raw.starts_with(char::is_whitespace) {
        return String::new();
    }
    let v = match v.find(" #") {
        Some(i) => &v[..i],
        None => v,
    };
    v.trim().to_string()
}

fn expand_home(v: &str, home: &Path) -> Option<PathBuf> {
    for prefix in ["~/", "$HOME/", "${HOME}/"] {
        if let Some(rest) = v.strip_prefix(prefix) {
            return Some(home.join(rest));
        }
    }
    if matches!(v, "~" | "$HOME" | "${HOME}") {
        return Some(home.to_path_buf());
    }
    None
}

fn build_overrides(pairs: &[(String, String)], project_dir: &Path, home: &Path) -> Vec<EnvAgentOverride> {
    let mut out = Vec::new();
    for (key, v) in pairs {
        let kind = AGENT_OVERRIDE_KEYS.iter().find(|(k, _)| k == key).map(|(_, kind)| *kind).unwrap_or("");
        let mut o = EnvAgentOverride { key: key.clone(), kind: kind.to_string(), ..Default::default() };
        match kind {
            "agent-home" => {
                o.value = Some(sanitize_display(&redact_secrets_in_text(v), 256));
                let relative = !v.is_empty() && !v.starts_with(['/', '~', '$']);
                let abs = if v.starts_with('/') { Some(PathBuf::from(v)) } else { expand_home(v, home) };
                let project = crate::scanners::persistence::lexical_join(Path::new("/"), project_dir);
                o.inside_project = relative
                    || abs.is_some_and(|p| {
                        crate::scanners::persistence::lexical_join(Path::new("/"), &p).starts_with(&project)
                    });
            }
            "gateway" => {
                let (host, _) = crate::scanners::host_of(v);
                o.official = crate::scanners::agent_settings::classify_base_url(key, v).is_some_and(|g| g.official);
                o.loopback = crate::scanners::is_loopback_host(&host);
                o.value = Some(sanitize_display(&host, 128));
            }
            "proxy" => {
                let (host, _) = crate::scanners::host_of(v);
                o.loopback = host.is_empty() || crate::scanners::is_loopback_host(&host);
                o.value = Some(sanitize_display(&host, 128));
            }
            "headers" => {}
            "ollama-host" => {
                let (shown, bind) = crate::scanners::shell_configs::classify_ollama_host(v);
                o.loopback = bind == "loopback";
                o.value = Some(shown);
                o.bind = Some(bind.to_string());
            }
            _ => continue,
        }
        out.push(o);
    }
    out
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
            .filter(|p| crate::scanners::probe_dir(&p))
            .collect(),
    )
}
