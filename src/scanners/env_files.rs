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

/// Substrings in a key NAME that suggest it holds a secret. `AUTH` is not among them: it
/// is matched as a word by [`auth_word_hint`] (`git commit --author=`, `ssh -o
/// PubkeyAuthentication=no` and `WEBAUTHN_RP_ID` are not secrets).
const SECRET_KEY_HINTS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "KEY",
    "PASSWORD",
    "PASSWD",
    "PASSPHRASE",
    "CREDENTIAL",
    "PRIVATE",
];

/// One upper-cased word of a name is an `AUTH` hint: the word `AUTH` (`AUTH_TOKEN`,
/// `NPM_AUTH`, `x-auth-token`, `_authToken`, `AUTH2`), a word ending in it (`OAUTH`,
/// `BASICAUTH`), or one holding `AUTHTOKEN` or `AUTHORIZATION` (`NPMAUTHTOKEN`,
/// `HTTP_AUTHORIZATION`). Not `AUTHOR` (`--author=`, `GIT_AUTHOR_NAME`), not
/// `AUTHENTICATION` (`PubkeyAuthentication=no`, `PasswordAuthentication=yes` are modes,
/// not secrets), not `AUTHORITY`, not `WEBAUTHN`.
fn is_auth_word(w: &str) -> bool {
    let w = w.trim_end_matches(|c: char| c.is_ascii_digit());
    w.ends_with("AUTH") || w.contains("AUTHTOKEN") || w.contains("AUTHORIZATION")
}

/// A NAME whose last word is `AUTHENTICATION`: an authentication-mode switch
/// (ssh_config's `PasswordAuthentication`, `PubkeyAuthentication`,
/// `KbdInteractiveAuthentication`, set to `yes`/`no`), not a secret, though it may
/// contain a hint (`PASSWORD`, a glued `PUBKEY`).
fn is_authentication_mode_name(name: &str) -> bool {
    key_words(name).last().is_some_and(|w| w == "AUTHENTICATION")
}

/// `AUTH` as a word of a NAME ([`is_auth_word`] over its `_`/`-`/`.`/camelCase words).
pub fn auth_word_hint(name: &str) -> bool {
    key_words(name).iter().any(|w| is_auth_word(w))
}

/// A word of a `.env` NAME that is a secret hint: a long hint other than `KEY` as a
/// substring of the word (`GITHUBTOKEN`, `dbPassword`; `TOKEN` not in `TOKENIZER`), `KEY`
/// as a word by [`key_word_hint`]'s rule (`key_hint`: `APIKEY`, `apiKey`, `keyPem`; not
/// `KEYBOARD`, `KEYWORD`, `HOTKEY`, `MONKEY`), the [`is_auth_word`] rule, or a
/// [`SECRET_LAST_WORDS`] word whole.
fn is_env_hint_word(w: &str, key_hint: bool) -> bool {
    let w = w.trim_end_matches(|c: char| c.is_ascii_digit());
    key_hint
        || is_auth_word(w)
        || SECRET_LAST_WORDS.contains(&w)
        || SECRET_KEY_HINTS
            .iter()
            .any(|h| *h != "KEY" && w.contains(h) && !(*h == "TOKEN" && w.contains("TOKENIZ")))
}

/// The `.env` secret-NAME rule: the name has a hint word ([`is_env_hint_word`]) and no
/// word after its last hint word is in [`NON_SECRET_QUALIFIERS`]. `FULL_TOKEN`,
/// `VIEW_PASS`, `SECRET_KEY_BASE`, `GITHUB_TOKEN_B64`, `GITHUB_TOKEN_READONLY` and
/// `API_KEY_2` are secret names (an unknown trailing word fails safe); `VIEW_TOKEN_IPS`,
/// `WEBAUTHN_RP_ID` (no hint: `ID` is not one and `WEBAUTHN` is not `AUTH`),
/// `DB_PASS_FILE`, `API_KEY_ID` and `AWS_ACCESS_KEY_ID` are not. `KEY` counts only as
/// a word ([`key_word_hint`]'s rule, as in the command redactor): `KEYBOARD_LAYOUT`,
/// `KEYWORD`, `HOTKEY`, `MONKEY` and `TURKEY` are not secret names, in a `.env` or in a
/// transcript.
/// The MCP inline-secret check keeps [`is_secret_key_name`]'s substring rule: there a
/// missed name can show a value, while here the record is a NAME and the value is never
/// read.
pub fn is_secret_env_key_name(name: &str) -> bool {
    if name.eq_ignore_ascii_case("PWD") {
        return false;
    }
    let tagged = key_words_with_key_hint(name);
    let words: Vec<String> = tagged.iter().map(|(w, _)| w.clone()).collect();
    let Some(i) = tagged.iter().rposition(|(w, k)| is_env_hint_word(w, *k)) else {
        return false;
    };
    let after = &words[i + 1..];
    // The short hints (PASS, PWD, PAT, JWT, SK) name a secret only as the last word, or
    // before an encoding / environment / version qualifier (`DB_PASS_B64`, `DB_PWD_2`):
    // `JWT_ISSUER`, `PAT_ROW` are not secrets.
    let hint = words[i].trim_end_matches(|c: char| c.is_ascii_digit());
    if SECRET_LAST_WORDS.contains(&hint) && !is_auth_word(hint) {
        return after
            .iter()
            .all(|w| w.bytes().all(|b| b.is_ascii_digit()) || SECRET_VALUE_QUALIFIERS.contains(&w.as_str()));
    }
    // A long hint fails safe: only a word from the closed non-secret list unflags the
    // name, and an unknown qualifier (`GITHUB_TOKEN_READONLY`, `API_KEY_ROTATED`) still
    // names a secret.
    !after
        .iter()
        .any(|w| NON_SECRET_QUALIFIERS.contains(&w.trim_end_matches(|c: char| c.is_ascii_digit())))
}

/// Words that may follow a SHORT secret hint ([`SECRET_LAST_WORDS`]) in a `.env` NAME and
/// still name the secret: its encoding (`DB_PASS_B64`, `_HEX`, `_JSON`, `_PEM`, `_DER`,
/// `_RAW`, `_VALUE`, `_ENC`) or a variant or environment (`DB_PWD_PROD`, `_OLD`).
const SECRET_VALUE_QUALIFIERS: &[&str] = &[
    "B64",
    "BASE64",
    "HEX",
    "JSON",
    "PEM",
    "DER",
    "RAW",
    "VALUE",
    "ENC",
    "ENCRYPTED",
    "BASE",
    "PROD",
    "PRODUCTION",
    "DEV",
    "DEVELOPMENT",
    "STAGING",
    "STAGE",
    "TEST",
    "LIVE",
    "SANDBOX",
    "LOCAL",
    "PRIMARY",
    "SECONDARY",
    "OLD",
    "NEW",
    "CURRENT",
    "PREVIOUS",
    "NEXT",
    "BACKUP",
    "RO",
    "RW",
    "READONLY",
];

/// Words that, after the last secret hint of a `.env` NAME, make it describe the secret
/// rather than hold it: an identifier (`AWS_ACCESS_KEY_ID`, `API_KEY_ID`), a location
/// (`DB_PASS_FILE`, `PRIVATE_KEY_PATH`, `SECRET_DIR`), a lifetime or size
/// (`JWT_SECRET_TTL`, `TOKEN_EXPIRY`, `PASSWORD_LENGTH`, `TOKEN_COUNT`), a switch
/// (`AUTH_ENABLED`), a label or format (`TOKEN_NAME`, `AUTH_HEADER`, `TOKEN_PREFIX`,
/// `KEY_FORMAT`, `TOKEN_TYPE`), an allowlist (`VIEW_TOKEN_IPS`), or a URL (judged by
/// [`is_connection_string_key_name`]). A closed list: any other trailing word keeps the
/// name secret-named.
const NON_SECRET_QUALIFIERS: &[&str] = &[
    "ID", "IDS", "IPS", "FILE", "PATH", "DIR", "TTL", "EXPIRY", "LENGTH", "COUNT", "ENABLED", "NAME", "HEADER",
    "PREFIX", "SUFFIX", "FORMAT", "TYPE", "URL",
];

/// Short secret words that are matched only as the LAST word of a name (or the whole
/// name), never as a substring: `DB_PASS`, `SMTP_PASS`, `DB_PWD`, `GITHUB_PAT`,
/// `STRIPE_SK`, `SUPABASE_JWT`, `dbPass` (review of b21286f: a committed .env of only
/// these was graded clean, and `MY_PASS=x ./notify.sh` was shown verbatim). A substring rule would flag `PASSENGERS`,
/// `COMPASS`, `PATH`, `TASK_ID`, `DISK_SIZE` and `RISK`; a last-word rule also leaves
/// `DB_PASS_FILE` (a path) and `JWT_ISSUER` (a name) alone.
const SECRET_LAST_WORDS: &[&str] = &["PASS", "PWD", "PAT", "JWT", "SK"];

/// The words of a key name, upper-cased: split at `_`, `-`, `.` and every other
/// non-alphanumeric, and at a lower-to-upper camelCase step (`dbPass` -> DB, PASS).
fn key_words(name: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in name.chars() {
        if !c.is_ascii_alphanumeric() {
            if !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
            prev_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && prev_lower && !cur.is_empty() {
            words.push(std::mem::take(&mut cur));
        }
        prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        cur.push(c.to_ascii_uppercase());
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

/// True if a variable/key NAME looks like it holds a secret (name-only heuristic;
/// never inspects the value). Shared with the MCP scanner's inline-secret check and
/// the command redactor. `PWD` on its own is the POSIX working-directory variable, not
/// a password, and is not flagged (`DB_PWD` is).
pub fn is_secret_key_name(name: &str) -> bool {
    if has_secret_key_hint(name) {
        return true;
    }
    let upper = name.to_ascii_uppercase();
    if upper == "PWD" {
        return false;
    }
    key_words(name)
        .last()
        .is_some_and(|w| SECRET_LAST_WORDS.contains(&w.as_str()))
}

/// The substring half of [`is_secret_key_name`] alone: a NAME containing one of the long
/// hint words (`TOKEN`, `SECRET`, `KEY`, `PASSWORD`, ...), without the short last-word
/// rule. The command redactor uses only this for a bare single-dash flag (`-token X`):
/// `-sk` / `-sSk` is curl's silent + insecure cluster, not a name ending in `SK`.
pub fn has_secret_key_hint(name: &str) -> bool {
    if is_authentication_mode_name(name) {
        return false;
    }
    let upper = name.to_ascii_uppercase();
    SECRET_KEY_HINTS.iter().any(|h| upper.contains(h)) || auth_word_hint(name)
}

/// [`is_secret_key_name`] for the command redactor, with the `KEY` hint matched as a
/// word ([`key_word_hint`]) instead of as a substring: `ssh -o StrictHostKeyChecking=no`
/// is an ssh option, not a secret, and `KEYBOARD=us`, `MONKEY=1`, `TURKEY=1` are not
/// secret names. The other hints and the last-word rule are unchanged. The `.env` and
/// transcript name rule ([`is_secret_env_key_name`]) uses the same `KEY` word rule; the
/// MCP inline-secret check keeps the broader substring rule.
pub fn is_secret_command_key_name(name: &str) -> bool {
    if has_secret_command_key_hint(name) {
        return true;
    }
    let upper = name.to_ascii_uppercase();
    if upper == "PWD" {
        return false;
    }
    key_words(name)
        .last()
        .is_some_and(|w| SECRET_LAST_WORDS.contains(&w.as_str()))
}

/// [`has_secret_key_hint`] with `KEY` matched by [`key_word_hint`].
pub fn has_secret_command_key_hint(name: &str) -> bool {
    if is_authentication_mode_name(name) {
        return false;
    }
    let upper = name.to_ascii_uppercase();
    SECRET_KEY_HINTS.iter().any(|h| *h != "KEY" && upper.contains(h)) || key_word_hint(name) || auth_word_hint(name)
}

/// Words that put a following `KEY` in a secret's name though more words come after it
/// (`apiKeyId`, `sshKeyFile`), or that glue onto it (`APIKEYVALUE`).
const KEY_QUALIFIERS: &[&str] = &[
    "API",
    "SECRET",
    "PRIVATE",
    "PRIV",
    "ACCESS",
    "SSH",
    "SIGNING",
    "ENCRYPTION",
    "MASTER",
    "LICENSE",
    "CLIENT",
    "APP",
    "SERVICE",
    "AUTH",
    "ADMIN",
    "DEPLOY",
    "GPG",
    "PGP",
    "HMAC",
    "SESSION",
];

/// Words that, right after `KEY`, make the name the key's own value or encoding
/// (`keyValue`, `keyData`, `keyMaterial`, `keyPem`, `keyB64`, `encKeyHex`, `KEYTEXT`,
/// `keyphrase`): the name holds the key, though `KEY` is not its last word.
/// `StrictHostKeyChecking`, `HostKeyAlgorithms`, `KEYBOARD` and `KEYWORD` are not among them.
const KEY_VALUE_WORDS: &[&str] = &[
    "VALUE", "DATA", "MATERIAL", "PEM", "DER", "B64", "BASE64", "HEX", "STRING", "STR", "TEXT", "PHRASE", "BYTES",
    "BLOB", "SECRET",
];

/// English words ending in `KEY` that are not key names (`MONKEY`, `TURKEY`, `HOTKEY`).
const KEY_WORD_STEMS: &[&str] = &["MON", "TUR", "DON", "HOC", "JOC", "WHIS", "LAC", "HON", "FLUN", "HOT"];

/// `KEY` as a word of a NAME. A name splits into segments at every non-alphanumeric
/// (`API_KEY`, `key=`, `--api-key`) and a segment into camelCase words (`apiKey`). It
/// matches when a segment or word, trailing digits ignored (`API_KEY2`):
/// - is `KEY`/`KEYS` and is the last camelCase word of its segment (`API_KEY`,
///   `KEY_ID`, `apiKey`, `key`), or follows a [`KEY_QUALIFIERS`] word (`apiKeyId`);
/// - ends in `KEY`/`KEYS` glued to a stem that is not an English word
///   (`APIKEY`, `sshkey`, `PRIVKEY`; not `MONKEY`, `TURKEY`, `HOTKEY`);
/// - holds `KEY` mid-word right after a qualifier (`APIKEYVALUE`).
///
/// It does not match `KEY` inside a camelCase name between other words
/// (`StrictHostKeyChecking`, `HostKeyAlgorithms`, and a glued `Pubkey` in
/// `PubkeyAuthentication`) or at the start of a longer word (`KEYBOARD`, `KEYWORD`).
pub fn key_word_hint(name: &str) -> bool {
    key_words_with_key_hint(name).iter().any(|(_, k)| *k)
}

/// The words of a NAME ([`key_words`]), each with whether it is a `KEY` word by
/// [`key_word_hint`]'s rule, judged within its `_`/`-`/`.` segment.
fn key_words_with_key_hint(name: &str) -> Vec<(String, bool)> {
    let value_word = |w: &str| {
        KEY_VALUE_WORDS.contains(&w) || KEY_VALUE_WORDS.contains(&w.trim_end_matches(|c: char| c.is_ascii_digit()))
    };
    let glued = |w: &str| -> bool {
        let stem = w.strip_suffix("KEYS").or_else(|| w.strip_suffix("KEY"));
        if let Some(stem) = stem {
            return stem.is_empty() || !KEY_WORD_STEMS.contains(&stem);
        }
        w.match_indices("KEY").any(|(i, _)| {
            KEY_QUALIFIERS.iter().any(|q| w[..i].ends_with(q))
                || (value_word(&w[i + 3..]) && !KEY_WORD_STEMS.contains(&&w[..i]))
        })
    };
    let mut out = Vec::new();
    for seg in name.split(|c: char| !c.is_ascii_alphanumeric()) {
        let words = key_words(seg);
        for (i, word) in words.iter().enumerate() {
            // A version or index suffix is not part of the word (`API_KEY2`, `apiKey2`).
            let w = word.trim_end_matches(|c: char| c.is_ascii_digit());
            let hint = if !w.contains("KEY") {
                false
            } else if w == "KEY" || w == "KEYS" {
                i + 1 == words.len()
                    || (i > 0 && KEY_QUALIFIERS.contains(&words[i - 1].as_str()))
                    || value_word(&words[i + 1])
            } else if w.ends_with("KEY") || w.ends_with("KEYS") {
                // A glued `...KEY` word inside a longer camelCase name is part of an
                // option name (`PubkeyAuthentication=no`, ssh_config), not a key's name.
                i + 1 == words.len() && glued(w)
            } else {
                glued(w)
            };
            out.push((word.clone(), hint));
        }
    }
    out
}

/// A .env key NAME with `WEBHOOK` as one of its words (`SLACK_WEBHOOK_URL`,
/// `DISCORD_WEBHOOK`): a webhook URL is its own credential. Kept out of
/// [`is_secret_key_name`], like [`is_connection_string_key_name`]: in a command the
/// redactor already cuts a webhook URL to its host by shape (`--webhook
/// https://example.com/<redacted>`), and redacting by name would drop the host too.
pub fn is_webhook_key_name(name: &str) -> bool {
    key_words(name).iter().any(|w| w == "WEBHOOK")
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
        let dirs = {
            // Another scan home, or an ancestor of one, is not this pass's project (its own
            // pass reads it); this pass's own home stays when it is the cwd or registered.
            let scope = platform.pass_scope();
            scope.excluding_other_scan_homes(
                scope.with_cwd(extract_project_dirs(&home.join(".claude.json")).unwrap_or_default()),
                &home,
            )
        };

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
    let read_ok = content.is_some();
    let EnvLines {
        key_count,
        secret_keys,
        unparsed_lines,
    } = content.as_deref().map(parse_env_lines).unwrap_or_default();
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
        read_ok,
        unparsed_lines,
        secret_keys,
        agent_overrides,
        symlink,
        unreachable_via: crate::scanners::transcripts::untraversable_ancestor(path)
            .map(|why| sanitize_display(&why, 512)),
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
    let l = parse_env_lines(content);
    (l.key_count, l.secret_keys)
}

/// What [`parse_env_lines`] found in a `.env`: never a value.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct EnvLines {
    /// `KEY=value` lines parsed (a key name of ASCII letters, digits and `_`).
    pub key_count: usize,
    /// Secret-looking key NAMES, deduplicated, in file order.
    pub secret_keys: Vec<String>,
    /// Non-blank, non-comment lines that are not `KEY=value` (`spring.datasource.password=x`,
    /// YAML-style `OPENAI_API_KEY: sk-...`): rmguard cannot tell what they hold.
    pub unparsed_lines: usize,
}

/// [`parse_env_keys`] that also counts the lines it could not parse. A quoted value that
/// opens on a `KEY=` line and closes on a later one (dotenv's multi-line values, a PEM
/// block) is one entry: its continuation lines are not counted as unparsed. The value is
/// looked at only for its quote characters, never kept.
pub fn parse_env_lines(content: &str) -> EnvLines {
    let mut out = EnvLines::default();
    let mut open_quote: Option<char> = None;
    for line in content.lines() {
        if let Some(q) = open_quote {
            if closes_quote(line, q) {
                open_quote = None;
            }
            continue;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            out.unparsed_lines += 1;
            continue;
        };
        let key = key.trim();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            out.unparsed_lines += 1;
            continue;
        }
        out.key_count += 1;
        if (is_secret_env_key_name(key) || is_connection_string_key_name(key) || is_webhook_key_name(key))
            && !out.secret_keys.iter().any(|k| k == key)
        {
            out.secret_keys.push(key.to_string());
        }
        let value = value.trim_start();
        if let Some(q) = value.chars().next().filter(|c| *c == '"' || *c == '\'')
            && !closes_quote(&value[1..], q)
        {
            open_quote = Some(q);
        }
    }
    out
}

/// `text` holds a closing `q` (for `"`, one not escaped by a backslash).
fn closes_quote(text: &str, q: char) -> bool {
    let mut escaped = false;
    for c in text.chars() {
        if escaped {
            escaped = false;
        } else if c == '\\' && q == '"' {
            escaped = true;
        } else if c == q {
            return true;
        }
    }
    false
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
