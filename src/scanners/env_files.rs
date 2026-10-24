use crate::models::{EnvAgentOverride, EnvFile, EnvSymlink};
use crate::platform::PlatformInfo;
use crate::scanners::{Scanner, file_perms, is_git_tracked, read_bounded, redact_secrets_in_text, sanitize_display};
use std::path::{Path, PathBuf};

/// Detects `.env` files in agent project roots. Agents routinely read the working
/// directory, so a `.env` full of secrets in a project an agent operates on is an
/// agent-exposure concern; a git-tracked `.env` is a committed-secret leak.
///
/// SECURITY: parses key NAMES only to flag secret-bearing keys and count entries — it
/// never reads, stores, or emits the values.
pub struct EnvFilesScanner;

const ENV_FILENAMES: &[&str] = &[".env", ".env.local", ".env.development", ".env.production", ".env.test"];

/// Substrings in a key NAME that suggest it holds a secret.
const SECRET_KEY_HINTS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "KEY",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "AUTH",
    "PRIVATE",
];

/// True if a variable/key NAME looks like it holds a secret (name-only heuristic;
/// never inspects the value). Shared with the MCP scanner's inline-secret check.
pub fn is_secret_key_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    SECRET_KEY_HINTS.iter().any(|h| upper.contains(h))
}

/// A .env key NAME that by convention holds a connection string, whose userinfo carries
/// the password: `DATABASE_URL` (the twelve-factor / Heroku Postgres convention, also
/// Prisma's and Rails'), `REDIS_URL`, `MONGODB_URI`, `SENTRY_DSN`, `*_CONNECTION_STRING`.
/// The value is never read, so this is a name rule like [`is_secret_key_name`]; it is
/// kept separate so the MCP inline-secret check keeps its narrower list.
pub fn is_connection_string_key_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    const STORES: &[&str] = &[
        "DATABASE",
        "DB",
        "POSTGRES",
        "PG",
        "MYSQL",
        "MARIADB",
        "MONGO",
        "MONGODB",
        "REDIS",
        "AMQP",
        "RABBITMQ",
        "BROKER",
        "CELERY_BROKER",
        "ELASTICSEARCH",
        "CLICKHOUSE",
        "SUPABASE_DB",
    ];
    upper == "DSN"
        || upper.ends_with("_DSN")
        || upper.contains("CONNECTION_STRING")
        || upper.ends_with("_CONN_STR")
        || ["_URL", "_URI"]
            .iter()
            .filter_map(|s| upper.strip_suffix(s))
            .any(|stem| STORES.iter().any(|st| stem == *st || stem.ends_with(&format!("_{st}"))))
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
                if !crate::scanners::probe_file(&path) || !seen.insert(crate::scanners::skills::dedupe_key(&path)) {
                    continue;
                }
                results.push(scan_env_file(&path, &dir, &home));
            }
        }
        results
    }
}

fn scan_env_file(path: &Path, project_dir: &Path, home: &Path) -> EnvFile {
    // A .env is project content: a link is recorded by its lexical target and never
    // opened (`.env -> ~/.ssh/id_ed25519` or `~/.aws/credentials` would otherwise put that
    // file's key names, and now its values, into the report). The open itself refuses a
    // link at the final component (O_NOFOLLOW) and a FIFO (O_NONBLOCK + fstat), so a
    // swap after this check is refused too.
    let symlink = std::fs::symlink_metadata(path)
        .ok()
        .filter(|m| m.file_type().is_symlink())
        .and_then(|_| std::fs::read_link(path).ok())
        .map(|target| {
            let lexical = crate::scanners::persistence::lexical_join(path.parent().unwrap_or(project_dir), &target);
            EnvSymlink {
                target: sanitize_display(&target.to_string_lossy(), 300),
                sensitive_target: crate::scanners::persistence::is_sensitive_read_target(&lexical, home),
            }
        });
    let content = if symlink.is_some() {
        None
    } else {
        crate::scanners::read_bounded_nofollow(path, None)
    };
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
        // The project directory name is attacker-chosen text (ESC, newlines).
        path: sanitize_display(&path.display().to_string(), 512),
        git_tracked: is_git_tracked(path),
        world_readable,
        key_count,
        secret_keys,
        agent_overrides,
        symlink,
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

/// The agent's own default home for an agent-home key, relative to HOME. Setting the key
/// to this relocates nothing. GEMINI_CLI_HOME names the directory that CONTAINS `.gemini`,
/// so its default is HOME itself.
fn default_agent_home(key: &str) -> Option<&'static str> {
    match key {
        "CLAUDE_CONFIG_DIR" => Some(".claude"),
        "CODEX_HOME" => Some(".codex"),
        "GEMINI_CLI_HOME" => Some(""),
        "CURSOR_CONFIG_DIR" => Some(".cursor"),
        "KIRO_HOME" => Some(".kiro"),
        _ => None,
    }
}

/// A host as it may be shown: a hostname (labels of `[A-Za-z0-9-_]`, dots between) or an
/// IP literal. Anything else -- a key pasted into a *_BASE_URL, free text -- is not
/// echoed; the redirection is still reported, as `<unparseable>`.
fn displayable_host(host: &str) -> String {
    let h = host.trim_end_matches('.');
    let hostname = !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|l| {
            !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        // A credential has no dots and is long; a single-label host (`gateway`) is short.
        && (h.contains('.') || h.len() <= 32);
    if hostname || h.parse::<std::net::IpAddr>().is_ok() {
        sanitize_display(&redact_secrets_in_text(host), 128)
    } else {
        "<unparseable>".to_string()
    }
}

/// Shown in place of a gateway or proxy value that is not a URL yet: a shell or dotenv
/// interpolation (`${OPENAI_BASE_URL}`, `$(cmd)`, backticks) or a template placeholder
/// (`<your-gateway-url>`, `{{GATEWAY}}`). Nothing is routed by the file itself.
pub const UNRESOLVED_VALUE: &str = "<unresolved>";
/// Shown in place of a value with no recognizable host.
pub const UNPARSEABLE_VALUE: &str = "<unparseable>";

/// A value that is an interpolation or a template placeholder, not a literal URL.
fn is_unresolved(v: &str) -> bool {
    v.contains('$') || v.contains('`') || v.contains("{{") || (v.contains('<') && v.contains('>'))
}

/// Key prefixes of common API tokens (`sk-1234`, LiteLLM's master-key form), compared
/// in lower case.
const KEY_PREFIXES: &[&str] = &[
    "sk-",
    "sk_",
    "gsk_",
    "xai-",
    "pplx-",
    "hf_",
    "ghp_",
    "gho_",
    "ghs_",
    "ghu_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "akia",
    "asia",
    "eyj",
    "tok_",
    "key-",
    "api-key",
    "apikey",
];
/// Words a password or token carries (`hunter2-pass`, `my-secret-pw`).
const CREDENTIAL_WORDS: &[&str] = &["pass", "pwd", "token", "secret", "key", "cred"];

/// True when a scheme-less value reads as a credential pasted into the wrong variable: a
/// known key prefix, a JWT, or a label carrying a password/token word.
fn credential_shaped(v: &str, host: &str) -> bool {
    let lower = v.to_ascii_lowercase();
    KEY_PREFIXES.iter().any(|p| lower.starts_with(p))
        || host
            .split('.')
            .any(|l| l.starts_with("eyj") || CREDENTIAL_WORDS.iter().any(|w| l.contains(w)))
}

/// The host of a gateway/proxy value as it may be shown, or a marker. With a scheme
/// (`https://host/...`) the host is shown when it reads as a hostname or an IP (never
/// downgraded by its name: the grading depends on it). A scheme-less value is not a URL
/// a client dials as written, and is the shape of a credential pasted into the wrong
/// variable, so it is shown only when it cannot be one: never with a key prefix
/// (`sk-1234`), a JWT or a password/token word (`hunter2-pass`, `pass.word`); a bare
/// (dotless) name only when it is a common local-stack service name or `name-<digits>`.
pub(crate) fn shown_host(v: &str, host: &str) -> String {
    if is_unresolved(v) {
        return UNRESOLVED_VALUE.to_string();
    }
    let schemeless = !v.contains("://");
    let ip = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .is_ok();
    if schemeless && !ip && credential_shaped(v, &host.to_ascii_lowercase()) {
        return UNPARSEABLE_VALUE.to_string();
    }
    let bare = schemeless && !host.contains('.') && !ip;
    if bare {
        const SERVICE_NAMES: &[&str] = &[
            "localhost",
            "ollama",
            "litellm",
            "gateway",
            "proxy",
            "vllm",
            "llm",
            "openai",
            "router",
            "api",
        ];
        // `ollama-1`, `gpu_2`: a lowercase name and a number.
        let numbered = host.split_once(['-', '_']).is_some_and(|(name, n)| {
            !name.is_empty()
                && name.bytes().all(|b| b.is_ascii_lowercase())
                && !n.is_empty()
                && n.bytes().all(|b| b.is_ascii_digit())
        });
        let service = !v.bytes().any(|b| b.is_ascii_uppercase()) && (SERVICE_NAMES.contains(&host) || numbered);
        if !service {
            return UNPARSEABLE_VALUE.to_string();
        }
    }
    displayable_host(host)
}

/// An agent-home value as it may be shown. `~`, `$HOME` and `${HOME}` prefixes are the
/// one expansion read here (resolved against HOME); any other `$`/backtick expansion is
/// `<unresolved>` (its text, `$(cat ~/.ssh/id_ed25519)`, is not echoed). Only a path is
/// shown: a value with a `/` or a leading `.` (`./.claude-home`, `.codex`), and never
/// one with `://` (a URL with a password in the port position is not a directory);
/// anything else (`a1b2c3...`, `hunter2-pass`) is `<unparseable>`: it could be a
/// credential pasted into the wrong variable.
fn shown_home(v: &str) -> String {
    let home_prefixed = expand_home(v, Path::new("/")).is_some();
    let rest = ["~/", "$HOME/", "${HOME}/"]
        .iter()
        .find_map(|p| v.strip_prefix(p))
        .unwrap_or(v);
    if (!home_prefixed && is_unresolved(v)) || (home_prefixed && is_unresolved(rest)) {
        return UNRESOLVED_VALUE.to_string();
    }
    let plausible_dir =
        !v.contains("://") && (v.contains('/') || v.starts_with('.') || matches!(v, "~" | "$HOME" | "${HOME}"));
    if !plausible_dir {
        return UNPARSEABLE_VALUE.to_string();
    }
    sanitize_display(&redact_secrets_in_text(v), 256)
}

/// A shared temporary location (`/tmp/claude`, `/var/tmp/x`, `/dev/shm/x`), or a path
/// whose nearest existing ancestor is a world-writable directory: another local user
/// can create the directory first. Metadata only (lstat), nothing is opened or followed.
/// A path under HOME is judged by the world-writable rule only (a HOME that itself lives
/// under /tmp is not shared).
fn shared_temp_path(p: &Path, home: &Path) -> bool {
    const SHARED: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/private/tmp", "/private/var/tmp"];
    if !p.starts_with(home) && SHARED.iter().any(|r| p.starts_with(r)) {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for a in p.ancestors() {
            if let Ok(m) = std::fs::symlink_metadata(a) {
                return m.is_dir() && m.permissions().mode() & 0o002 != 0;
            }
        }
    }
    false
}

fn build_overrides(pairs: &[(String, String)], project_dir: &Path, home: &Path) -> Vec<EnvAgentOverride> {
    let mut out = Vec::new();
    for (key, v) in pairs {
        let kind = AGENT_OVERRIDE_KEYS
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, kind)| *kind)
            .unwrap_or("");
        // `KEY=` / `KEY=""` (a template .env) sets nothing: the agent keeps its default
        // home and host. Only ANTHROPIC_CUSTOM_HEADERS is recorded by presence alone.
        if kind != "headers" && v.trim().is_empty() {
            continue;
        }
        let mut o = EnvAgentOverride {
            key: key.clone(),
            kind: kind.to_string(),
            ..Default::default()
        };
        match kind {
            "agent-home" => {
                use crate::scanners::persistence::lexical_join;
                o.value = Some(shown_home(v));
                let relative = !v.is_empty() && !v.starts_with(['/', '~', '$']);
                // A relative value resolves against the project (where the .env is
                // loaded); `../../x` climbs out of it and is not "inside".
                let abs = if v.starts_with('/') {
                    Some(PathBuf::from(v))
                } else if relative {
                    Some(project_dir.join(v))
                } else {
                    expand_home(v, home)
                };
                let abs = abs.map(|p| lexical_join(Path::new("/"), &p));
                // Pointing an agent at its own default home relocates nothing.
                if let (Some(a), Some(d)) = (&abs, default_agent_home(key))
                    && *a == lexical_join(Path::new("/"), &home.join(d))
                {
                    continue;
                }
                // `${PWD}/.claude-cfg`, `$PROJECT_ROOT/.codex`, `~user/x`, `$HOME/$X`: the
                // path is unknown (it may well be the repository itself), so it is neither
                // inside nor outside the project.
                o.unresolved = abs.is_none() || o.value.as_deref() == Some(UNRESOLVED_VALUE);
                let project = lexical_join(Path::new("/"), project_dir);
                o.inside_project = !o.unresolved && abs.as_ref().is_some_and(|p| p.starts_with(&project));
                o.shared_temp =
                    !o.unresolved && !o.inside_project && abs.as_deref().is_some_and(|p| shared_temp_path(p, home));
            }
            "gateway" => {
                let (host, _) = crate::scanners::host_of(v);
                let unresolved = is_unresolved(v);
                o.official = !unresolved
                    && crate::scanners::agent_settings::classify_base_url(key, v).is_some_and(|g| g.official);
                // A client dial: 0.0.0.0 and [::] reach this machine (client-side reading).
                o.loopback = !unresolved && crate::scanners::is_client_loopback_host(&host);
                o.value = Some(shown_host(v, &host));
            }
            "proxy" => {
                let (host, _) = crate::scanners::host_of(v);
                let unresolved = is_unresolved(v);
                o.loopback = !unresolved && (host.is_empty() || crate::scanners::is_client_loopback_host(&host));
                o.value = Some(shown_host(v, &host));
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
        if (is_secret_key_name(key) || is_connection_string_key_name(key)) && !secrets.contains(&key.to_string()) {
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
            .filter(|p| crate::scanners::probe_dir(p))
            .collect(),
    )
}
