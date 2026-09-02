pub mod agent_settings;
pub mod ai_credentials;
pub mod ai_frameworks;
pub mod ai_tools;
pub mod browser_extensions;
pub mod env_files;
pub mod cloud_credentials;
pub mod exposure;
pub mod container_tools;
pub mod extensions;
pub mod git_config;
pub mod ide;
pub mod marketplaces;
pub mod mcp;
pub mod mcp_probe;
pub mod node_packages;
pub mod notebook_servers;
pub mod package_configs;
pub mod npm_packages;
pub mod python_packages;
pub mod rules_files;
pub mod shell_configs;
pub mod skills;
pub mod ssh_keys;
pub mod transcripts;
pub mod vscode_tasks;

use crate::platform::PlatformInfo;
use std::time::Duration;

/// Convenience: check if a process with the given name is running.
/// Falls back to /proc scan on Linux if pgrep is unavailable.
pub fn is_process_running(name: &str) -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // Try pgrep first
        if let Ok(output) = std::process::Command::new("pgrep")
            .arg("-x")
            .arg(name)
            .output()
        {
            return output.status.success();
        }

        // Fallback: scan /proc on Linux
        #[cfg(target_os = "linux")]
        {
            return proc_has_process(name);
        }

        #[cfg(not(target_os = "linux"))]
        {
            return false;
        }
    }
}

/// Scan /proc for a process by comm name (Linux fallback when pgrep is unavailable).
#[cfg(target_os = "linux")]
fn proc_has_process(name: &str) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let fname = entry.file_name();
        let fname = fname.to_string_lossy();
        if !fname.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let comm_path = entry.path().join("comm");
        if let Ok(comm) = std::fs::read_to_string(&comm_path) {
            if comm.trim() == name {
                return true;
            }
        }
    }
    false
}

/// Get version from a binary by running `binary --version` with a 5-second timeout.
pub fn get_binary_version(binary: &str) -> Option<String> {
    let mut child = std::process::Command::new(binary)
        .arg("--version")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;

    let timeout = Duration::from_secs(5);
    let start = std::time::Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }

    let output = child.wait_with_output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let text = if text.is_empty() {
        String::from_utf8_lossy(&output.stderr)
    } else {
        text
    };
    extract_version(&text)
}

/// Extract a semver-like version from text.
pub fn extract_version(text: &str) -> Option<String> {
    // Match patterns like "1.2.3", "v1.2.3", "1.2.3-beta1"
    let re_like = text.split_whitespace().find(|w| {
        let w = w.strip_prefix('v').unwrap_or(w);
        w.chars().next().is_some_and(|c| c.is_ascii_digit()) && w.contains('.')
    })?;
    let v = re_like.strip_prefix('v').unwrap_or(re_like);
    Some(
        v.trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-')
            .to_string(),
    )
}

/// Detect invisible / smuggled Unicode that ASCII pattern-matching is blind to — the
/// dominant 2025-2026 evasion. A "Provides weather forecasts" tool description, or a
/// clean-looking CLAUDE.md, can carry a full invisible instruction payload.
///
/// Returns deduped, stable-ordered category labels. Character-class based, so it is
/// language-agnostic and needs no pattern catalog.
///
/// Coverage note: the bidi class deliberately includes the *marks* U+200E/U+200F, not
/// just the embedding/override controls. The TrapDoor campaign's advisory names LRM
/// (U+200E) among its payload characters, and a detector keyed only on
/// ZWSP/ZWJ/ZWNJ/BOM silently misses it.
pub fn scan_suspicious_unicode(s: &str) -> Vec<&'static str> {
    let mut cats: Vec<&'static str> = Vec::new();
    for ch in s.chars() {
        let label = match ch as u32 {
            0xE0000..=0xE007F => "tag-block",
            0xE0100..=0xE01EF => "variation-selector-smuggler",
            // Zero-width joiners/non-joiners, BOM, and the invisible math operators
            // (U+2060 word joiner .. U+2064) which are equally invisible carriers.
            0x200B | 0x200C | 0x200D | 0xFEFF | 0x2060..=0x2064 => "zero-width",
            0x00AD => "soft-hyphen",
            // Directional marks (200E/200F) as well as embeddings/overrides/isolates.
            0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069 => "bidi-control",
            _ if ch.is_control() && ch != '\t' && ch != '\n' && ch != '\r' => "other-control",
            _ => continue,
        };
        if !cats.contains(&label) {
            cats.push(label);
        }
    }
    cats
}

/// Confusable characters that render like an ASCII letter but are a different
/// codepoint. Cyrillic and Greek lookalikes are the classic trick: `сurl` with a
/// Cyrillic `с` (U+0441) reads as "curl" to a human and to nothing else.
/// Deliberately limited to unambiguous ASCII-lookalikes so folding cannot mangle
/// genuinely non-Latin text into false matches.
const CONFUSABLES: &[(char, char)] = &[
    // Cyrillic
    ('\u{0430}', 'a'), ('\u{0435}', 'e'), ('\u{043e}', 'o'), ('\u{0440}', 'p'),
    ('\u{0441}', 'c'), ('\u{0445}', 'x'), ('\u{0443}', 'y'), ('\u{0456}', 'i'),
    ('\u{0455}', 's'), ('\u{04bb}', 'h'), ('\u{0432}', 'b'), ('\u{043a}', 'k'),
    ('\u{043c}', 'm'), ('\u{0442}', 't'), ('\u{0448}', 'w'),
    // Greek
    ('\u{03bf}', 'o'), ('\u{03c1}', 'p'), ('\u{03b5}', 'e'), ('\u{03b1}', 'a'),
    ('\u{03bd}', 'v'), ('\u{03c5}', 'u'), ('\u{03ba}', 'k'), ('\u{03c4}', 't'),
];

/// Fold text into a canonical form for pattern matching.
///
/// Static instruction scanning is a substring match, which several published techniques
/// defeat without touching the visible text: homoglyph swaps (`сurl` with a Cyrillic
/// `с`), shell quoting that the shell collapses (`c"u"rl`, `c\url`), invisible
/// characters wedged mid-word, and fullwidth forms. This folds all of those to the
/// plain ASCII a shell would actually execute.
///
/// It is deliberately NOT used to replace raw matching — see
/// `rules_files::check_dangerous_patterns`, which matches both and treats a
/// normalization-only hit as its own (stronger) signal, because text that matches only
/// after de-obfuscation was obfuscated on purpose.
pub fn normalize_for_matching(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut escaped = false;
    for ch in input.chars() {
        // A backslash escapes the next character in shell; both vanish on execution.
        if escaped {
            escaped = false;
            out.push(fold_char(ch));
            continue;
        }
        match ch {
            '\\' => escaped = true,
            // Quotes are collapsed by the shell: c"u"rl and 'c'url both run curl.
            '"' | '\'' => {}
            // Invisible/zero-width characters carry no meaning to the shell.
            _ if is_invisible(ch) => {}
            _ => out.push(fold_char(ch)),
        }
    }
    out.to_lowercase()
}

/// Map one character to its ASCII lookalike: confusables, then fullwidth forms.
fn fold_char(ch: char) -> char {
    if let Some((_, ascii)) = CONFUSABLES.iter().find(|(c, _)| *c == ch) {
        return *ascii;
    }
    // Fullwidth ASCII (U+FF01..U+FF5E) maps onto ASCII by a fixed offset.
    let cp = ch as u32;
    if (0xFF01..=0xFF5E).contains(&cp) {
        if let Some(a) = char::from_u32(cp - 0xFEE0) {
            return a;
        }
    }
    ch
}

/// Characters that render as nothing and so cannot change what a shell executes.
fn is_invisible(ch: char) -> bool {
    matches!(ch as u32,
        0x200B..=0x200F | 0x2060..=0x2064 | 0xFEFF | 0x00AD
        | 0x202A..=0x202E | 0x2066..=0x2069 | 0xE0000..=0xE007F)
}

/// Remove credential material from a free-text value that is about to be reported.
///
/// Two shapes cover the realistic cases: userinfo inside a URL
/// (`https://user:pw@host/…`) and a `key=value` assignment whose key names a secret
/// (`password=…`, `token=…`). Everything else is preserved, because the surrounding
/// text is usually the finding itself — a git credential.helper command, a registry
/// URL — and blanking it would destroy the signal.
pub fn redact_secrets_in_text(text: &str) -> String {
    // Tokenise on whitespace, keeping the spans so the original whitespace is copied
    // back verbatim (splitting on ' ' alone once let a tab-separated secret through).
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut idx = 0;
    while idx < text.len() {
        let start = text[idx..]
            .find(|c: char| !c.is_whitespace())
            .map_or(text.len(), |o| idx + o);
        if start == text.len() {
            break;
        }
        let end = text[start..]
            .find(char::is_whitespace)
            .map_or(text.len(), |o| start + o);
        spans.push((start, end));
        idx = end;
    }
    let tok = |i: usize| -> &str { &text[spans[i].0..spans[i].1] };
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    let mut redact_next = false;
    for i in 0..spans.len() {
        out.push_str(&text[last..spans[i].0]);
        let prev = i.checked_sub(1).map(tok);
        let prev2 = i.checked_sub(2).map(tok);
        let next = (i + 1 < spans.len()).then(|| tok(i + 1));
        let (rendered, flag) = redact_token(tok(i), prev, prev2, next, redact_next);
        redact_next = flag;
        out.push_str(&rendered);
        last = spans[i].1;
    }
    out.push_str(&text[last..]);
    out
}

/// Flags whose value is `user:password` (curl, wget, httpie). The user half is kept.
const USER_FLAGS: &[&str] = &["-u", "--user", "--proxy-user", "-U", "--http-user"];

/// HTTP Authorization schemes. In `Authorization: <scheme> <credential>` the scheme is
/// kept -- it says HOW the server authenticates -- and the credential is redacted.
/// Modelling only Bearer/Basic let `Authorization: token ghp_x` (GitHub's documented
/// form) redact the word `token` and pass `ghp_x` through, looking sanitised.
const AUTH_SCHEMES: &[&str] = &[
    "bearer", "basic", "token", "oauth", "oauth2", "ssws", "apikey", "api-key", "negotiate",
    "digest", "ntlm", "hawk", "dpop", "gnap", "hoba", "mutual", "vapid", "signature",
    "privatetoken", "aws4-hmac-sha256", "goog", "splunk", "zoho-oauthtoken",
];

fn is_scheme_word(s: &str) -> bool {
    AUTH_SCHEMES.contains(&s.to_ascii_lowercase().as_str())
}

/// `Authorization:` / `Proxy-Authorization:` / `Authorization=` -- the one header whose
/// value is `<scheme> <credential>` rather than just `<credential>`.
fn is_authorization_marker(s: &str) -> bool {
    (s.ends_with(':') || s.ends_with('='))
        && matches!(
            bare_key(s).to_ascii_lowercase().as_str(),
            "authorization" | "proxy-authorization" | "www-authenticate"
        )
}

fn bare_key(k: &str) -> &str {
    k.trim_start_matches(|c: char| !c.is_ascii_alphanumeric())
        .trim_end_matches(|c: char| !c.is_ascii_alphanumeric())
}

fn is_secret_key(k: &str) -> bool {
    let b = bare_key(k);
    !b.is_empty() && crate::scanners::env_files::is_secret_key_name(b)
}

/// A key with its separator but no value yet: `password:`, `"X-Api-Key:`, `--token=`.
fn is_open_marker(s: &str) -> bool {
    (s.ends_with(':') || s.ends_with('=')) && is_secret_key(s)
}

/// Split a token into `key`, separator and `value`. Both `=` and `:` are tried, in the
/// order they appear, and the first split whose KEY is secret-shaped wins; otherwise the
/// earliest separator. So `//host/:_authToken=X` keys on `_authToken`,
/// `X-Api-Key:abc==` keys on `X-Api-Key` (not on the base64 padding), and
/// `--header=X-Api-Key:X` keys on `X-Api-Key`.
fn split_pair(tok: &str) -> Option<(&str, char, &str)> {
    let mut seps: Vec<(usize, char)> = ['=', ':']
        .iter()
        .filter_map(|&c| tok.find(c).map(|i| (i, c)))
        .collect();
    seps.sort();
    for &(i, c) in &seps {
        if is_secret_key(&tok[..i]) {
            return Some((&tok[..i], c, &tok[i + 1..]));
        }
    }
    seps.first().map(|&(i, c)| (&tok[..i], c, &tok[i + 1..]))
}

/// True when the PRECEDING token(s) mean this token is a secret's value:
/// `Authorization: <tok>`, `Bearer <tok>`, `--token <tok>`, `password: <tok>`,
/// `password = <tok>`, `Authorization=Bearer <tok>`, `--header="X-Api-Key: <tok>`.
///
/// A marker has to LOOK like a key: a flag (`--token`), a key with its separator
/// (`password:`), a scheme word, or a bare key followed by a lone `=`/`:` token (INI
/// style). Bare words are not markers -- `gh auth login` must not redact `login`.
///
/// Single-letter flags are deliberately NOT markers. `-p` is a port (`ssh -p 22`,
/// `-p 3000`) or `mkdir -p /path` at least as often as it is a password, and redacting
/// the argument after it would erase exactly the path or port a finding is about.
fn is_secret_value_position(prev: Option<&str>, prev2: Option<&str>) -> bool {
    let Some(p) = prev else { return false };
    if p == "=" || p == ":" {
        return prev2.is_some_and(is_secret_key);
    }
    // A bare `Bearer`/`Basic` is followed by a credential wherever it appears. The other
    // scheme words (`token`, `key`) are ordinary words -- `vault token lookup` -- and
    // only mark a value when a real Authorization header precedes them, which
    // redact_token handles with its lookahead flag.
    if p.eq_ignore_ascii_case("bearer") || p.eq_ignore_ascii_case("basic") {
        return true;
    }
    if let Some((_, _, v)) = split_pair(p) {
        // `Authorization=Bearer`: the pair's value is the scheme word, so the credential
        // is the NEXT token. `--header="X-Api-Key:`: the value is itself an open marker.
        if is_scheme_word(v) || is_open_marker(v) {
            return true;
        }
        // Any other complete pair already carried its own value; the token after it is
        // the next argument. Redacting it hid the command a hook actually runs.
        if !v.is_empty() {
            return false;
        }
    }
    let flag_shaped = p.starts_with('-') || p.ends_with(':') || p.ends_with('=');
    flag_shaped && is_secret_key(p)
}

/// The authority of `after_scheme` (everything up to the path) and the remainder.
/// A backslash ends the authority too: WHATWG treats `\` as `/` for special schemes,
/// so `https://evil.com\@registry.npmjs.org/` has host evil.com. Splitting only on
/// `/?#` read the host as registry.npmjs.org and called a hostile registry official.
fn split_authority(after_scheme: &str) -> (&str, &str) {
    let end = after_scheme
        .find(['/', '?', '#', '\\'])
        .unwrap_or(after_scheme.len());
    after_scheme.split_at(end)
}

/// Redact a URL: userinfo, and any query parameter whose NAME is secret-shaped.
/// `?a=1&token=X` used to leak because only a leading `key=` was recognised.
fn redact_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let (scheme, after) = (&url[..scheme_end], &url[scheme_end + 3..]);
    let (authority, rest) = split_authority(after);
    let host = match authority.rfind('@') {
        Some(at) => format!("<redacted>@{}", &authority[at + 1..]),
        None => authority.to_string(),
    };
    let rest = match rest.find('?') {
        Some(q) => {
            let (path, query) = (&rest[..q], &rest[q + 1..]);
            let (query, frag) = match query.find('#') {
                Some(h) => (&query[..h], &query[h..]),
                None => (query, ""),
            };
            let query: Vec<String> = query
                .split('&')
                .map(|kv| match kv.split_once('=') {
                    Some((k, v)) if !v.is_empty() && is_secret_key(k) => format!("{k}=<redacted>"),
                    _ => kv.to_string(),
                })
                .collect();
            format!("{path}?{}{frag}", query.join("&"))
        }
        None => rest.to_string(),
    };
    format!("{scheme}://{host}{rest}")
}

/// Strip `user:pass@` from a value, with or without a URL scheme. The HOST is kept --
/// it is the security-relevant half of the finding; the credential is not.
fn redact_userinfo(value: &str) -> String {
    if value.contains("://") {
        return redact_url(value);
    }
    // Scheme-less `user:pass@host`, as pip's `trusted-host` and git remotes write it.
    // Require a non-empty password segment so plain `user@host` and email addresses,
    // which carry no credential, are left intact.
    if let Some(at) = value.rfind('@')
        && at + 1 < value.len()
        && let Some(colon) = value[..at].find(':')
        && colon + 1 < at
        && !value[..at].contains('=')
    {
        return format!("<redacted>@{}", &value[at + 1..]);
    }
    value.to_string()
}

/// Redact a quoted value while keeping the quotes and whatever follows the close, so
/// `'{"token":"X"}'` becomes `'{"token":"<redacted>"}'` rather than losing its tail.
fn redact_value_keeping_quotes(v: &str) -> String {
    let q = v.chars().next().filter(|c| *c == '"' || *c == '\'');
    match q {
        Some(q) if v.len() > 1 => match v[1..].find(q) {
            Some(close) => format!("{q}<redacted>{}", &v[1 + close..]),
            None => format!("{q}<redacted>"),
        },
        _ => "<redacted>".to_string(),
    }
}

/// Redact a whole token that sits in value position, keeping a leading quote pair or
/// trailing closers (`X"`, `X"),`) so the surrounding syntax still reads.
fn redact_bare_value(tok: &str) -> String {
    if tok.starts_with(['"', '\'']) {
        return redact_value_keeping_quotes(tok);
    }
    let core = tok.trim_end_matches(['"', '\'', ')', ']', '}', ',', ';']);
    format!("<redacted>{}", &tok[core.len()..])
}

/// One separator-free segment: a URL, a `user:pass@host`, or a `key=value` pair.
fn redact_segment(seg: &str) -> String {
    if let Some(sc) = seg.find("://")
        && !seg[..sc].contains(['=', ':'])
    {
        return redact_url(seg);
    }
    let userinfo = redact_userinfo(seg);
    if userinfo != seg {
        return userinfo;
    }
    let Some((k, sep, v)) = split_pair(seg) else {
        return seg.to_string();
    };
    if v.is_empty() {
        return seg.to_string();
    }
    if is_secret_key(k) {
        // `Authorization=Bearer`: keep the scheme word so the NEXT token is redacted.
        if is_scheme_word(v) {
            return seg.to_string();
        }
        return format!("{k}{sep}{}", redact_value_keeping_quotes(v));
    }
    // `--user=admin:pw`: keep the user, drop the password.
    if USER_FLAGS.iter().any(|f| f.trim_start_matches('-') == bare_key(k))
        && let Some((u, _)) = v.split_once(':')
    {
        return format!("{k}{sep}{u}:<redacted>");
    }
    format!("{k}{sep}{}", redact_userinfo(v))
}

/// Returns the rendered token and whether the NEXT token must be redacted (set after an
/// `Authorization:` scheme word, whose credential follows).
fn redact_token(
    tok: &str,
    prev: Option<&str>,
    prev2: Option<&str>,
    next: Option<&str>,
    redact_this: bool,
) -> (String, bool) {
    if redact_this {
        return (redact_bare_value(tok), false);
    }
    // `Authorization: token X`: the scheme word stays visible, the credential goes.
    // Only when a real Authorization header precedes it and a value follows; the word
    // `token` in `gh auth token` is just a word.
    if is_scheme_word(tok) {
        let after_auth = prev.is_some_and(is_authorization_marker);
        let has_value = next.is_some_and(|n| !n.starts_with('-') && !n.contains("://"));
        return (tok.to_string(), after_auth && has_value);
    }
    if is_secret_value_position(prev, prev2) {
        return (redact_bare_value(tok), false);
    }
    // curl-style basic auth: `-u admin:pw`. Keep the user, drop the password. The flag
    // alone is not a marker (`python -u script.py`), the `user:pass` shape is.
    if prev.is_some_and(|p| USER_FLAGS.contains(&p))
        && let Some((u, _)) = tok.split_once(':')
    {
        return (format!("{u}:<redacted>"), false);
    }
    // A URL is one unit and must not be split on its query string's '&' or '='.
    if let Some(sc) = tok.find("://")
        && !tok[..sc].contains(['=', ':'])
    {
        return (redact_url(tok), false);
    }
    // Connection strings, query fragments and compact JSON carry several pairs:
    // `Server=db;Password=X;`, `a=1&token=X`, `{"user":"a","password":"X"}`.
    let mut out = String::with_capacity(tok.len());
    let mut start = 0;
    for (i, ch) in tok.char_indices() {
        if ch == ';' || ch == '&' || ch == ',' {
            out.push_str(&redact_segment(&tok[start..i]));
            out.push(ch);
            start = i + 1;
        }
    }
    out.push_str(&redact_segment(&tok[start..]));
    (out, false)
}

/// Trait for all scanners.
pub trait Scanner {
    type Output;
    fn scan(&self, platform: &dyn PlatformInfo) -> Self::Output;
}

/// Split a URL into `(scheme, host_port)`, resolving the authority the way an HTTP
/// client does — the single source of truth for every place that has to decide "where
/// does this request actually go?".
///
/// Security-critical, because both the EAA-007 gateway check and URL sanitization
/// depend on it: the scheme is whatever precedes the first `://`; the authority ends
/// at the first `/`, `?`, or `#` after it (so an `@`/`?`/`#` in the path or query can't
/// masquerade as the host — e.g. `https://evil/?x=https://api.anthropic.com`); and
/// userinfo is stripped at the LAST `@` within the authority. `host_port` keeps any
/// `:port` and the original case; scheme is `""` when the URL has none.
pub fn split_url_authority(url: &str) -> (&str, &str) {
    let (scheme, after_scheme) = match url.find("://") {
        Some(i) => (&url[..i], &url[i + 3..]),
        None => ("", url),
    };
    // A backslash ends the authority (WHATWG special-scheme rule); see split_authority.
    let authority = after_scheme
        .split(['/', '?', '#', '\\'])
        .next()
        .unwrap_or(after_scheme);
    let host_port = match authority.rsplit_once('@') {
        Some((_userinfo, host)) => host,
        None => authority,
    };
    (scheme, host_port)
}

/// Unix permission bits of a file as (octal_string, world_readable, group_readable).
/// Returns None on non-Unix or if the file can't be stat'd. Never reads file content.
pub fn file_perms(path: &std::path::Path) -> Option<(String, bool, bool)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).ok()?;
        let mode = meta.permissions().mode() & 0o777;
        Some((
            format!("{:04o}", mode),
            mode & 0o004 != 0,
            mode & 0o040 != 0,
        ))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// True if `path` is writable by group or other. A config that any local process can
/// modify is a trivial persistence foothold: an attacker appends a hook and the agent
/// runs it. Returns false on non-Unix or if the file can't be stat'd.
pub fn is_world_or_group_writable(path: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let Ok(meta) = std::fs::metadata(path) else {
            return false;
        };
        let mode = meta.permissions().mode();
        mode & 0o022 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

/// Check whether a file is tracked by git (shells out to `git ls-files`).
pub fn is_git_tracked(path: &std::path::Path) -> bool {
    let parent = path.parent().unwrap_or(path);
    std::process::Command::new("git")
        .args(["ls-files", "--error-unmatch", "--"])
        .arg(path)
        .current_dir(parent)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Compute SHA-256 hash of content, returning hex string.
pub fn sha256_hex(content: &str) -> String {
    use sha2::{Sha256, Digest};
    use std::fmt::Write;
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in result {
        let _ = write!(hex, "{:02x}", b);
    }
    hex
}

/// Maximum config file size we'll read (1 MB).
pub const MAX_CONFIG_SIZE: u64 = 1_048_576;

/// Check file size before reading. Returns None if the path is not a regular file,
/// is too large, or is unreadable. Follows symlinks (so dotfile-managed configs work)
/// but rejects non-regular targets — a symlink to `/dev/zero` or a FIFO reports len 0
/// and would otherwise stream infinitely — and bounds the read as a TOCTOU backstop.
pub fn read_bounded(path: &std::path::Path) -> Option<String> {
    use std::io::Read;
    // metadata() follows symlinks: for a symlink→regular file this is the target's
    // metadata (good); for a symlink→device/FIFO, is_file() is false → rejected.
    let Ok(meta) = std::fs::metadata(path) else {
        telemetry::note_read(path, "missing");
        return None;
    };
    if !meta.is_file() {
        telemetry::note_read(path, "not a regular file");
        return None;
    }
    if meta.len() > MAX_CONFIG_SIZE {
        telemetry::note_read(path, "too large");
        eprintln!(
            "warning: skipping {} ({} bytes exceeds {} byte limit)",
            path.display(),
            meta.len(),
            MAX_CONFIG_SIZE
        );
        return None;
    }
    let mut buf = String::new();
    let opened = std::fs::File::open(path)
        .ok()
        .and_then(|f| f.take(MAX_CONFIG_SIZE).read_to_string(&mut buf).ok());
    if opened.is_none() {
        telemetry::note_read(path, "unreadable");
        return None;
    }
    telemetry::note_read(path, "ok");
    Some(buf)
}

/// Read the first N raw BYTES of a file. Unlike [`read_head`], this does not require
/// valid UTF-8, so it works for magic-byte checks on binaries.
pub fn read_head_bytes(path: &std::path::Path, max_bytes: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    // Regular files only. File::open on a FIFO with no writer blocks forever -- one
    // `mkfifo package.json` in any node_modules stalled the whole scan -- and opening a
    // directory succeeds on Linux/macOS, which counted it as a successful read.
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() => {}
        Ok(_) => {
            telemetry::note_read(path, "not a regular file");
            return None;
        }
        Err(_) => {
            telemetry::note_read(path, "missing");
            return None;
        }
    }
    let Ok(mut file) = std::fs::File::open(path) else {
        telemetry::note_read(path, "unreadable");
        return None;
    };
    telemetry::note_read(path, "ok");
    let mut buf = vec![0u8; max_bytes];
    let n = file.read(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

/// Read only the first N bytes of a file (for key header detection).
pub fn read_head(path: &std::path::Path, max_bytes: usize) -> Option<String> {
    use std::io::Read;
    // Regular files only. File::open on a FIFO with no writer blocks forever -- one
    // `mkfifo package.json` in any node_modules stalled the whole scan -- and opening a
    // directory succeeds on Linux/macOS, which counted it as a successful read.
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() => {}
        Ok(_) => {
            telemetry::note_read(path, "not a regular file");
            return None;
        }
        Err(_) => {
            telemetry::note_read(path, "missing");
            return None;
        }
    }
    let Ok(mut file) = std::fs::File::open(path) else {
        telemetry::note_read(path, "unreadable");
        return None;
    };
    telemetry::note_read(path, "ok");
    let mut buf = vec![0u8; max_bytes];
    let n = file.read(&mut buf).ok()?;
    buf.truncate(n);
    String::from_utf8(buf).ok()
}

/// True when a registry URL really points at one of `official` — matched on the parsed
/// HOST, not as a substring.
///
/// `val.contains("registry.npmjs.org")` is true for
/// `https://registry.npmjs.org.evil.example.com/`, so a lookalike registry that
/// exfiltrates every install and every auth token was classified as the official one and
/// never reported. Compares the host exactly, or as a true parent domain.
pub fn is_official_registry(value: &str, official: &[&str]) -> bool {
    let trimmed = value.trim().trim_matches(['"', '\'']);
    // A registry URL with credentials in front of the host is never "just the official
    // registry": npm's parser may read a different host than ours does, and the
    // embedded credential is itself worth a finding.
    let after_scheme = trimmed.find("://").map_or(trimmed, |i| &trimmed[i + 3..]);
    if split_authority(after_scheme).0.contains('@') {
        return false;
    }
    let (_scheme, host_port) = split_url_authority(trimmed);
    let host = host_port
        .rsplit_once(':')
        .map_or(host_port, |(h, port)| {
            if port.chars().all(|c| c.is_ascii_digit()) { h } else { host_port }
        })
        .trim_end_matches('.')
        .to_ascii_lowercase();
    official.iter().any(|o| {
        let o = o.to_ascii_lowercase();
        host == o || host.ends_with(&format!(".{o}"))
    })
}

/// `path.is_file()` that the diagnostics can see. Use this instead of a bare `is_file()`
/// when deciding whether to read a config file, so a wrong path shows up as a miss.
pub fn probe_file(path: &std::path::Path) -> bool {
    let present = path.is_file();
    telemetry::note_probe(path, present);
    present
}

/// Scan telemetry. Answers the one question a silent scanner never could: did it look?
///
/// Counters are process-global because scanners run sequentially; [`timed`] snapshots
/// them around each scanner. If scanning ever goes parallel these must move to
/// per-scanner state, or every attribution here becomes wrong.
pub mod telemetry {
    use crate::models::ScannerStat;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Instant;

    static FILES_READ: AtomicU64 = AtomicU64::new(0);
    static FILES_MISSING: AtomicU64 = AtomicU64::new(0);
    static TRACE: AtomicBool = AtomicBool::new(false);

    /// Turn on per-path tracing to stderr (`--trace`, or RMGUARD_TRACE=1).
    pub fn enable_trace() {
        TRACE.store(true, Ordering::Relaxed);
    }

    pub fn trace_enabled() -> bool {
        TRACE.load(Ordering::Relaxed)
    }

    /// Record one read attempt through a shared reader. `outcome` is "ok" for a
    /// successful open; anything else counts as missing. Only the PATH is ever
    /// traced, never content.
    pub fn note_read(path: &Path, outcome: &str) {
        if outcome == "ok" {
            FILES_READ.fetch_add(1, Ordering::Relaxed);
        } else {
            FILES_MISSING.fetch_add(1, Ordering::Relaxed);
        }
        if trace_enabled() {
            let shown = super::redact_secrets_in_text(&path.display().to_string());
            eprintln!("trace: read {shown} -> {outcome}");
        }
    }

    /// Record an existence check that did not open the file. A `false` counts as a
    /// missing path, so "looked for ~/.bunfig.toml, not there" is visible in the
    /// diagnostics rather than indistinguishable from never having looked.
    pub fn note_probe(path: &Path, present: bool) {
        if !present {
            FILES_MISSING.fetch_add(1, Ordering::Relaxed);
        }
        if trace_enabled() {
            let shown = super::redact_secrets_in_text(&path.display().to_string());
            eprintln!("trace: probe {shown} -> {}", if present { "present" } else { "missing" });
        }
    }

    pub fn snapshot() -> (u64, u64) {
        (
            FILES_READ.load(Ordering::Relaxed),
            FILES_MISSING.load(Ordering::Relaxed),
        )
    }

    /// Run one scanner, attributing wall time and read counters to it.
    pub fn timed<T>(
        diagnostics: &mut Vec<ScannerStat>,
        scanner: &str,
        root: Option<PathBuf>,
        f: impl FnOnce() -> Vec<T>,
    ) -> Vec<T> {
        let (r0, m0) = snapshot();
        let start = Instant::now();
        if trace_enabled() {
            eprintln!("trace: scanner {scanner} start");
        }
        let out = f();
        let (r1, m1) = snapshot();
        let stat = ScannerStat {
            scanner: scanner.to_string(),
            root: root.map(|p| p.display().to_string()),
            duration_ms: start.elapsed().as_millis() as u64,
            files_read: r1 - r0,
            files_missing: m1 - m0,
            items: out.len(),
            skipped: false,
        };
        if trace_enabled() {
            eprintln!(
                "trace: scanner {scanner} done: {}ms, {} read, {} missing, {} items",
                stat.duration_ms, stat.files_read, stat.files_missing, stat.items
            );
        }
        diagnostics.push(stat);
        out
    }

    pub fn skipped(scanner: &str) -> ScannerStat {
        ScannerStat {
            scanner: scanner.to_string(),
            root: None,
            duration_ms: 0,
            files_read: 0,
            files_missing: 0,
            items: 0,
            skipped: true,
        }
    }
}

/// Make attacker-controlled free text safe to print: control characters (including ESC,
/// so no ANSI sequence can forge a green "clean" line), C1 controls and line breaks are
/// replaced, and the result is capped. For names, versions, error messages and paths
/// that a manifest, a package or a probed server gets to choose.
pub fn sanitize_display(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max));
    for c in s.chars() {
        if out.chars().count() >= max {
            out.push('…');
            break;
        }
        let bad = c.is_control() || ('\u{80}'..='\u{9f}').contains(&c) || c == '\u{2028}' || c == '\u{2029}';
        out.push(if bad { '?' } else { c });
    }
    out
}

/// [`sanitize_display`] for multi-line text (tool descriptions, server instructions):
/// line breaks and tabs are kept, every other control character is replaced.
pub fn sanitize_display_multiline(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max));
    for (n, c) in s.chars().enumerate() {
        if n >= max {
            out.push('…');
            break;
        }
        let keep = c == '\n' || c == '\t';
        let bad = !keep && (c.is_control() || ('\u{80}'..='\u{9f}').contains(&c) || c == '\u{2028}' || c == '\u{2029}');
        out.push(if bad { '?' } else { c });
    }
    out
}
