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
mod helper_redact;
pub mod ide;
pub mod marketplaces;
pub mod mcp;
pub mod mcp_probe;
pub mod node_packages;
pub mod notebook_servers;
pub mod package_configs;
pub mod persistence;
pub mod jetbrains_plugins;
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
        let mut x = crate::otel::exec_span("pgrep");
        match child_command("pgrep").arg("-x").arg(name).output() {
            Ok(output) => {
                note_exit(&mut x, &output.status);
                return output.status.success();
            }
            Err(_) => x.outcome("spawn_failed"),
        }
        drop(x);

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

/// Every child process rmguard runs is built here, so none of them inherits the user's
/// OpenTelemetry configuration. `OTEL_EXPORTER_OTLP_HEADERS` is where a hosted backend's
/// API key goes (docs/OPENTELEMETRY.md tells `--otel` users to put it there), and the
/// programs rmguard runs include config-authored, possibly hostile MCP server commands
/// (`--probe-mcp`) and whatever binary sits on PATH under a known tool's name. They get
/// no `OTEL_*` variable at all, whether or not `--otel` was given: the scan never asks
/// a child to report anywhere, and a child that would have reported on its own is
/// better silent than holding a credential it was never meant to see.
/// `tests/otel_export.rs::no_bare_command_new_outside_child_command` keeps every spawn
/// site going through this function.
pub fn child_command(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    let mut cmd = std::process::Command::new(program);
    scrub_otel_env(&mut cmd);
    cmd
}

/// Remove every `OTEL_*` variable (any case) present in this process's environment from
/// `cmd`'s.
///
/// The names are collected once per process and reused for every spawn. std has no
/// names-only environment iterator, so that one pass over `vars_os()` does copy each
/// value into a temporary, which is dropped unused on the spot; only the matching names
/// are kept. rmguard never sets an `OTEL_*` variable itself, so a once-only snapshot
/// cannot go stale. With no `OTEL_*` set the cached list is empty and a spawn does no
/// work and no allocation here. With `OTEL_*` set, each spawn pays one `env_remove` per
/// cached name (a few small allocations and an explicit envp); over 1000 spawns of
/// `/bin/true` the difference was inside the noise. That is the price of keeping a
/// collector credential out of every child, paid per spawn (about 120 per scan), never
/// per file probe.
pub fn scrub_otel_env(cmd: &mut std::process::Command) -> &mut std::process::Command {
    static NAMES: std::sync::OnceLock<Vec<std::ffi::OsString>> = std::sync::OnceLock::new();
    let names = NAMES.get_or_init(|| {
        std::env::vars_os()
            .map(|(name, _)| name)
            .filter(|name| {
                let b = name.as_encoded_bytes();
                b.len() >= 5 && b[..5].eq_ignore_ascii_case(b"OTEL_")
            })
            .collect()
    });
    for name in names {
        cmd.env_remove(name);
    }
    cmd
}

/// Get version from a binary by running `binary --version` with a 5-second timeout.
pub fn get_binary_version(binary: &str) -> Option<String> {
    let mut x = crate::otel::exec_span("version_probe");
    let mut child = match child_command(binary)
        .arg("--version")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => {
            x.outcome("spawn_failed");
            return None;
        }
    };

    let timeout = Duration::from_secs(5);
    let start = std::time::Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                note_exit(&mut x, &status);
                break;
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    x.outcome("timeout");
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                x.outcome("wait_failed");
                return None;
            }
        }
    }
    drop(x);

    let output = child.wait_with_output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let text = if text.is_empty() {
        String::from_utf8_lossy(&output.stderr)
    } else {
        text
    };
    extract_version(&text)
}

/// Record a finished child's exit on its exec span: ok/nonzero plus the code if any.
pub(crate) fn note_exit(x: &mut crate::otel::ExecSpan, status: &std::process::ExitStatus) {
    x.outcome(if status.success() { "ok" } else { "nonzero" });
    if let Some(code) = status.code() {
        x.exit_code(code);
    }
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
    let mut pending = Pending::None;
    for i in 0..spans.len() {
        out.push_str(&text[last..spans[i].0]);
        let prev = i.checked_sub(1).map(tok);
        let prev2 = i.checked_sub(2).map(tok);
        let next = (i + 1 < spans.len()).then(|| tok(i + 1));
        let (rendered, next_state) = redact_token(tok(i), prev, prev2, next, pending);
        pending = next_state;
        out.push_str(&rendered);
        last = spans[i].1;
    }
    out.push_str(&text[last..]);
    redact_token_shapes(&out)
}

/// Vendor credential prefixes and the minimum tail length that makes a match a key
/// rather than a word. The context rules above key on NAMES and positions
/// (`--token X`, `password=X`), so a bare literal such as `echo sk-ant-api03-...` in an
/// apiKeyHelper passed straight through; these shapes are distinctive enough to redact
/// wherever they appear. The prefix is kept (it says WHAT leaked), the tail is not.
const TOKEN_PREFIXES: &[(&str, usize)] = &[
    ("sk-ant-", 16), ("sk-proj-", 16), ("sk-svcacct-", 16), ("sk-or-", 16), ("sk-", 20),
    ("sk_live_", 16), ("sk_test_", 16), ("rk_live_", 16), ("ghp_", 20), ("gho_", 20),
    ("ghu_", 20), ("ghs_", 20), ("ghr_", 20), ("github_pat_", 20), ("glpat-", 20),
    ("xoxb-", 10), ("xoxp-", 10), ("xoxa-", 10), ("xoxr-", 10), ("xoxs-", 10), ("xoxe-", 10),
    ("xapp-", 10), ("AIza", 30), ("npm_", 30), ("hf_", 30), ("pypi-", 32), ("gsk_", 20),
    ("AKIA", 16), ("ASIA", 16),
];

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Redact credential-shaped literals (see TOKEN_PREFIXES) anywhere in `text`.
pub fn redact_token_shapes(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut copied = 0;
    while i < bytes.len() {
        let boundary = i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
        if boundary
            && let Some((prefix, min)) = TOKEN_PREFIXES.iter().find(|(p, _)| bytes[i..].starts_with(p.as_bytes()))
        {
            let start = i + prefix.len();
            let end = start + bytes[start..].iter().take_while(|b| is_token_char(**b)).count();
            if end - start >= *min {
                out.push_str(&text[copied..start]);
                out.push_str("<redacted>");
                copied = end;
                i = end;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&text[copied..]);
    out
}

pub use helper_redact::redact_helper_command;

/// A long run of key-alphabet characters mixing letters and digits that is not a path, a
/// flag or a word-separated identifier: the shape of an API key with no recognisable
/// vendor prefix.
fn looks_high_entropy(tok: &str) -> bool {
    let core = tok.trim_matches(['"', '\'', ';', ',', ')', '(']);
    let core = core.split_once('=').map_or(core, |(_, v)| v);
    core.len() >= 24
        && !core.starts_with(['/', '.', '~', '$', '-'])
        && !core.contains("//")
        && core.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'+' | b'/' | b'=' | b'.'))
        && core.bytes().any(|b| b.is_ascii_digit())
        && core.bytes().filter(|b| b.is_ascii_alphabetic()).count() >= 4
        && core.bytes().filter(|b| *b == b'/').count() <= 2
        && core.bytes().filter(|b| *b == b'.').count() <= 1
        && !identifier_like(core)
}

/// A snake/kebab/CONSTANT-case name (`get_secret_value_for_service_v2`,
/// `MY_VERY_LONG_VARIABLE_NAME_2024`, `fetch-anthropic-key-v2024`): three or more `_`/`-`
/// separated segments, at least half of them plain words, and no non-word segment longer
/// than 6 characters. A UUID or `prefix-<long hex>` key has long non-word segments and
/// does not qualify.
fn identifier_like(s: &str) -> bool {
    if s.bytes().any(|b| !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-')) {
        return false;
    }
    let segs: Vec<&str> = s.split(['_', '-']).collect();
    if segs.len() < 3 || segs.iter().any(|g| g.is_empty()) {
        return false;
    }
    let words = segs.iter().filter(|g| g.bytes().all(|b| b.is_ascii_alphabetic())).count();
    words * 2 >= segs.len() && segs.iter().all(|g| g.bytes().all(|b| b.is_ascii_alphabetic()) || g.len() <= 6)
}

/// Redact key-shaped runs INSIDE a token. [`looks_high_entropy`] judges a whole
/// whitespace token, so an unprefixed key wrapped in interpreter syntax
/// (`print('KEY')`, `console.log('KEY')`, `q(KEY)`, `%q[KEY]`) passed through. The token
/// is split on every character outside `[A-Za-z0-9_+/=-]` and each run is judged by the
/// same rule (identifiers, paths and `$NAME` / `${NAME}` references stay readable); in a
/// `NAME=value` run only the value is redacted.
fn redact_entropy_runs_in_token(tok: &str) -> String {
    let b = tok.as_bytes();
    let in_run = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'+' | b'/' | b'=' | b'-');
    let mut out = String::with_capacity(tok.len());
    let mut copied = 0;
    let mut i = 0;
    while i < b.len() {
        if !in_run(b[i]) {
            i += 1;
            continue;
        }
        let s = i;
        while i < b.len() && in_run(b[i]) {
            i += 1;
        }
        let run = &tok[s..i];
        let var_ref = s > 0 && (b[s - 1] == b'$' || (b[s - 1] == b'{' && s > 1 && b[s - 2] == b'$'));
        if var_ref || !looks_high_entropy(run) {
            continue;
        }
        let keep = match run.split_once('=') {
            Some((k, v)) if !k.is_empty() && !v.is_empty() && k.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') => {
                k.len() + 1
            }
            _ => 0,
        };
        out.push_str(&tok[copied..s + keep]);
        out.push_str("<redacted>");
        copied = i;
    }
    out.push_str(&tok[copied..]);
    out
}

/// [`redact_secrets_in_text`] plus key-shaped runs inside every whitespace token (see
/// [`redact_entropy_runs_in_token`]): for command text that is shown as evidence, such as
/// a skill's dynamic-context command.
pub fn redact_command_text(text: &str) -> String {
    let base = redact_secrets_in_text(text);
    let mut out = String::with_capacity(base.len());
    let mut last = 0;
    for (s, tok) in base.split_whitespace().map(|t| (t.as_ptr() as usize - base.as_ptr() as usize, t)) {
        out.push_str(&base[last..s]);
        out.push_str(&redact_entropy_runs_in_token(tok));
        last = s + tok.len();
    }
    out.push_str(&base[last..]);
    out
}

/// What the tokenizer owes the NEXT token(s): nothing, one redaction (the credential
/// after an Authorization scheme word), or redaction until the quote that opened a
/// value is closed (`--password "first SECOND"` is two tokens; both are the secret).
#[derive(Clone, Copy, PartialEq)]
enum Pending {
    None,
    One,
    Quote(char),
}

/// If `v` opens a quote it does not close, that quote character.
fn unclosed_quote(v: &str) -> Option<char> {
    let q = v.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    (v.len() == 1 || !v[1..].contains(q)).then_some(q)
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
fn is_authorization_key(k: &str) -> bool {
    matches!(
        bare_key(k).to_ascii_lowercase().as_str(),
        "authorization" | "proxy-authorization" | "www-authenticate"
    )
}

fn is_authorization_marker(s: &str) -> bool {
    if (s.ends_with(':') || s.ends_with('=')) && is_authorization_key(s) {
        return true;
    }
    // wget's `--header="Authorization:`, a glued `-H"Authorization:`, HTTPie's quoting:
    // the header name is the TAIL of a k=v or quoted token. bare_key() alone saw
    // `header="Authorization` and never set the scheme lookahead, so the credential
    // after `token`/`SSWS` walked through untouched.
    s.ends_with(':')
        && s.rsplit(['=', '"', '\''])
            .next()
            .is_some_and(is_authorization_key)
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
    if let Some((k, _, v)) = split_pair(p) {
        // `Authorization=Bearer` / `Authorization:"Bearer`: the pair's value is the scheme
        // word, so the credential is the NEXT token -- but only for an Authorization
        // header. For `A_KEY=basic` the word is just the value. `--header="X-Api-Key:`:
        // the value is itself an open marker.
        let v0 = v.trim_start_matches(['"', '\'']);
        if (is_scheme_word(v0) && is_authorization_key(k)) || is_open_marker(v0) {
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
/// Returns the rendering and, if a secret value opened a quote it did not close, that
/// quote (the tokens up to the closing quote are the rest of the secret).
fn redact_segment(seg: &str) -> (String, Option<char>) {
    if let Some(sc) = seg.find("://")
        && !seg[..sc].contains(['=', ':'])
    {
        return (redact_url(seg), None);
    }
    let userinfo = redact_userinfo(seg);
    if userinfo != seg {
        return (userinfo, None);
    }
    let Some((k, sep, v)) = split_pair(seg) else {
        return (seg.to_string(), None);
    };
    if v.is_empty() {
        return (seg.to_string(), None);
    }
    if is_secret_key(k) {
        // `Authorization=Bearer`: keep the scheme word so the NEXT token is redacted.
        // Only for an Authorization header: `A_KEY=basic` is a value like any other.
        if is_authorization_key(k) && is_scheme_word(v.trim_start_matches(['"', '\''])) {
            return (seg.to_string(), None);
        }
        return (format!("{k}{sep}{}", redact_value_keeping_quotes(v)), unclosed_quote(v));
    }
    // `--user=admin:pw`: keep the user, drop the password.
    if USER_FLAGS.iter().any(|f| f.trim_start_matches('-') == bare_key(k))
        && let Some((u, _)) = v.split_once(':')
    {
        return (format!("{k}{sep}{u}:<redacted>"), None);
    }
    (format!("{k}{sep}{}", redact_userinfo(v)), None)
}

/// Returns the rendered token and what the tokenizer owes the next token(s).
fn redact_token(
    tok: &str,
    prev: Option<&str>,
    prev2: Option<&str>,
    next: Option<&str>,
    pending: Pending,
) -> (String, Pending) {
    match pending {
        Pending::One => return (redact_bare_value(tok), Pending::None),
        // Inside a quoted secret: this token is more of it, until the quote closes.
        Pending::Quote(q) => {
            return match tok.find(q) {
                Some(close) => (format!("<redacted>{}", &tok[close..]), Pending::None),
                None => ("<redacted>".to_string(), Pending::Quote(q)),
            };
        }
        Pending::None => {}
    }
    // `Authorization: token X`: the scheme word stays visible, the credential goes.
    // Only when a real Authorization header precedes it and a value follows; the word
    // `token` in `gh auth token` is just a word.
    if is_scheme_word(tok) {
        let after_auth = prev.is_some_and(is_authorization_marker);
        let has_value = next.is_some_and(|n| !n.starts_with('-') && !n.contains("://"));
        return (tok.to_string(), if after_auth && has_value { Pending::One } else { Pending::None });
    }
    // HTTPie / compact JSON: `Authorization:"Bearer X"`, `{"Authorization":"Bearer X"}` --
    // the scheme word is the (quoted) value; keep the token, redact the next.
    if let Some((k, _, v)) = split_pair(tok)
        && is_authorization_key(k)
        && is_scheme_word(v.trim_start_matches(['"', '\'']))
    {
        return (tok.to_string(), Pending::One);
    }
    if is_secret_value_position(prev, prev2) {
        let q = unclosed_quote(tok);
        return (redact_bare_value(tok), q.map_or(Pending::None, Pending::Quote));
    }
    // curl-style basic auth: `-u admin:pw`. Keep the user, drop the password. The flag
    // alone is not a marker (`python -u script.py`), the `user:pass` shape is.
    if prev.is_some_and(|p| USER_FLAGS.contains(&p))
        && let Some((u, _)) = tok.split_once(':')
    {
        return (format!("{u}:<redacted>"), Pending::None);
    }
    // A URL is one unit and must not be split on its query string's '&' or '='.
    if let Some(sc) = tok.find("://")
        && !tok[..sc].contains(['=', ':'])
    {
        return (redact_url(tok), Pending::None);
    }
    // Connection strings, query fragments and compact JSON carry several pairs:
    // `Server=db;Password=X;`, `a=1&token=X`, `{"user":"a","password":"X"}`.
    //
    // A secret can itself contain a separator (`password=ab;cd`). After a segment whose
    // KEY was secret-shaped, following non-empty segments that are not pairs are part of
    // that value and are absorbed -- for ',' and '&' always, for ';' only when the token
    // has two or more pairs (a connection string). In a shell one-liner `TOKEN=x;cmd`
    // the segment after ';' is the COMMAND, and hiding it hid the script a hook runs;
    // an unquoted single-pair password containing ';' keeps its tail (documented floor).
    let mut segs: Vec<(&str, Option<char>)> = Vec::new();
    let mut start = 0;
    for (i, ch) in tok.char_indices() {
        if ch == ';' || ch == '&' || ch == ',' {
            segs.push((&tok[start..i], Some(ch)));
            start = i + 1;
        }
    }
    segs.push((&tok[start..], None));
    let pairs = segs
        .iter()
        .filter(|(sg, _)| split_pair(sg).is_some_and(|(_, _, v)| !v.is_empty()))
        .count();
    let mut out = String::with_capacity(tok.len());
    let mut absorb = false;
    let mut prev_sep: Option<char> = None;
    let mut opened: Option<char> = None;
    for (seg, sep_after) in segs {
        let pair = split_pair(seg);
        // After ';' in a single-pair token, a path-like or command-like segment is the
        // next shell command, not more of the secret.
        let shell_command_position = prev_sep == Some(';') && pairs < 2 && looks_like_command(seg);
        if absorb && pair.is_none() && !seg.is_empty() && !shell_command_position {
            out.push_str("<redacted>");
        } else {
            let (rendered, q) = redact_segment(seg);
            out.push_str(&rendered);
            opened = q;
            absorb = pair.is_some_and(|(k, _, v)| !v.is_empty() && is_secret_key(k));
        }
        if let Some(c) = sep_after {
            out.push(c);
        }
        prev_sep = sep_after;
    }
    // `'password=my secret'`: the quote opened BEFORE the key, so the value's own check
    // never saw it. If this token redacted anything and opens an unclosed quote, the
    // tokens up to the closing quote are the rest of the value.
    if opened.is_none() && out != tok {
        opened = unclosed_quote(tok);
    }
    (out, opened.map_or(Pending::None, Pending::Quote))
}

/// A segment that is plausibly the next command in a shell one-liner: a path, a
/// dot-relative script, or a common command word.
fn looks_like_command(seg: &str) -> bool {
    const COMMANDS: &[&str] = &[
        "echo", "curl", "wget", "sh", "bash", "zsh", "node", "python", "python3", "npm", "npx",
        "uv", "uvx", "pip", "git", "rm", "cd", "ls", "cat", "eval", "exec", "source", "export",
        "chmod", "mkdir", "touch", "nohup", "sudo", "env", "printf", "tee", "true", "false",
    ];
    seg.contains('/') || seg.starts_with(['.', '~']) || COMMANDS.contains(&seg)
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

/// The connection host (lowercased, IPv6 brackets removed) and port of a URL-ish value,
/// built on [`split_url_authority`] so userinfo never survives. `[::1]:4000` gives
/// `("::1", Some(4000))`; a bare IPv6 literal without brackets keeps all its colons.
pub(crate) fn host_of(value: &str) -> (String, Option<u16>) {
    let (_scheme, host_port) = split_url_authority(value.trim());
    let host_port = host_port.trim();
    if let Some(rest) = host_port.strip_prefix('[') {
        let (host, after) = rest.split_once(']').unwrap_or((rest, ""));
        let port = after.strip_prefix(':').and_then(|p| p.parse().ok());
        return (host.to_ascii_lowercase(), port);
    }
    match host_port.rsplit_once(':') {
        // Exactly one colon: host:port. Several colons without brackets is a bare IPv6.
        Some((h, p)) if !h.contains(':') => (h.to_ascii_lowercase(), p.parse().ok()),
        _ => (host_port.to_ascii_lowercase(), None),
    }
}

/// True for `localhost`, 127.0.0.0/8, `::1`, and IPv4-mapped loopback (`::ffff:127.x`).
pub(crate) fn is_loopback_host(host: &str) -> bool {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']').trim_end_matches('.');
    if h.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match h.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.to_canonical().is_loopback(),
        Err(_) => false,
    }
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

/// A `git` command that cannot be turned against the scanner by the repository it runs
/// in. rmguard runs git inside project directories it does not trust — that is the
/// GitSpawn shape it catalogues (Codex CVE-2026-19592, goose CVE-2026-72718, Claude Code
/// <2.1.196): a repo-local `core.fsmonitor`, `core.hooksPath` or a nested bare repo turns
/// the scan's own git call into code execution. Every working-tree git invocation goes
/// through here. `-c` overrides repository config; the environment scrub stops an
/// inherited GIT_DIR/GIT_WORK_TREE from redirecting the command elsewhere. Reading
/// config (`git config --list`) does not go through this, since the `-c` values would
/// appear in its own output.
pub fn hardened_git() -> std::process::Command {
    let mut cmd = child_command("git");
    cmd.args([
        "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null",
        "-c", "safe.bareRepository=explicit",
        "--no-optional-locks",
    ])
    .env_remove("GIT_DIR")
    .env_remove("GIT_WORK_TREE")
    .env_remove("GIT_INDEX_FILE")
    .env_remove("GIT_OBJECT_DIRECTORY")
    .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES");
    cmd
}

/// Wall-clock cap on one repository's `git ls-files` listing.
const GIT_TRACKED_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Wall-clock budget for all tracked-file listings in one scan. Once spent, every
/// repository not yet listed is "unknown": a machine with many cloned repositories, or
/// repositories built to stall git, cannot stretch the scan without bound.
const GIT_TRACKED_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);
/// Output cap for one listing (paths, NUL-separated). A repository whose index lists
/// more than this is "unknown" rather than half-answered.
const GIT_LS_FILES_MAX: usize = 32 * 1024 * 1024;

/// True when `p` is present and is not a regular file (a FIFO, socket, device,
/// directory, or a link to one). A symlink to a regular file is accepted (old git).
fn not_regular(p: &std::path::Path) -> bool {
    let bad = match std::fs::symlink_metadata(p) {
        Err(_) => false,
        Ok(m) if m.is_file() => false,
        Ok(m) if m.file_type().is_symlink() => !std::fs::metadata(p).is_ok_and(|t| t.is_file()),
        Ok(_) => true,
    };
    if bad {
        telemetry::note_read(p, "not a regular file");
    }
    bad
}

/// `[include]` / `[includeIf ...]` `path = X` values in a git config file. Bounded
/// read, no symlink at the final component; values are resolved relative to the
/// config's directory (`~/` against HOME).
fn config_include_paths(config: &std::path::Path) -> Vec<std::path::PathBuf> {
    let Some(text) = read_bounded_nofollow(config, None) else { return Vec::new() };
    let base = config.parent().unwrap_or(std::path::Path::new("/"));
    let mut out = Vec::new();
    let mut in_include = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            let sec = t.trim_start_matches('[').to_ascii_lowercase();
            in_include = sec.starts_with("include]") || sec.starts_with("include ") || sec.starts_with("includeif");
            continue;
        }
        if !in_include {
            continue;
        }
        let Some((k, v)) = t.split_once('=') else { continue };
        if !k.trim().eq_ignore_ascii_case("path") {
            continue;
        }
        let v = v.trim().trim_matches('"');
        let p = if let Some(rest) = v.strip_prefix("~/") {
            std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(rest))
        } else {
            Some(persistence::lexical_join(base, std::path::Path::new(v)))
        };
        out.extend(p);
        if out.len() >= 64 {
            break;
        }
    }
    out
}

/// The git directory a `.git` entry stands for: the directory itself, or the target of
/// a `gitdir: <path>` file (resolved lexically against the file's directory).
fn resolve_git_dir(dot_git: &std::path::Path) -> Option<std::path::PathBuf> {
    let m = std::fs::symlink_metadata(dot_git).ok()?;
    if m.is_dir() {
        return Some(dot_git.to_path_buf());
    }
    if !m.is_file() {
        return None;
    }
    let text = read_bounded_nofollow(dot_git, None)?;
    let target = text.lines().next()?.strip_prefix("gitdir:")?.trim();
    let base = dot_git.parent().unwrap_or(std::path::Path::new("/"));
    Some(persistence::lexical_join(base, std::path::Path::new(target)))
}

/// True when git, started in the repository whose `.git` entry is `dot_git`, would
/// open something that is not a regular file while discovering it: a HEAD, index,
/// config or commondir FIFO/socket/device (opening a FIFO with no writer blocks
/// forever), including behind a `gitdir:` file (worktrees, submodules) and in the
/// common directory a worktree's `commondir` names, or an `[include] path` in either
/// config that is not a regular file.
fn git_dir_unsafe_to_spawn(dot_git: &std::path::Path) -> bool {
    let Some(gd) = resolve_git_dir(dot_git) else {
        // A `.git` that is neither a directory nor a readable gitdir file (a FIFO, a
        // link to one, a gitdir file that is itself unreadable): never spawn git on it.
        return std::fs::symlink_metadata(dot_git).is_ok();
    };
    if !std::fs::symlink_metadata(&gd).is_ok_and(|m| m.is_dir()) {
        return !std::fs::metadata(&gd).is_ok_and(|m| m.is_dir());
    }
    let mut dirs = vec![gd.clone()];
    if !not_regular(&gd.join("commondir"))
        && let Some(text) = read_bounded_nofollow(&gd.join("commondir"), None)
        && let Some(line) = text.lines().next()
    {
        dirs.push(persistence::lexical_join(&gd, std::path::Path::new(line.trim())));
    }
    dirs.iter().any(|d| {
        ["HEAD", "index", "config", "commondir"].iter().any(|f| not_regular(&d.join(f)))
            || config_include_paths(&d.join("config")).iter().any(|p| not_regular(p))
    })
}

/// The repository root governing `path`: the nearest ancestor of its directory holding
/// a `.git` entry (directory or `gitdir:` file).
fn repo_root_of(path: &std::path::Path) -> Option<std::path::PathBuf> {
    let start = path.parent().unwrap_or(path);
    start.ancestors().find(|d| std::fs::symlink_metadata(d.join(".git")).is_ok()).map(|d| d.to_path_buf())
}

/// One repository's tracked paths (root-relative bytes, sorted), or None = unknown.
type TrackedSet = Option<std::collections::BTreeSet<Vec<u8>>>;

struct GitTrackCache {
    repos: std::collections::HashMap<std::path::PathBuf, std::sync::Arc<std::sync::OnceLock<TrackedSet>>>,
    spent: std::time::Duration,
}

static GIT_TRACK_CACHE: std::sync::Mutex<Option<GitTrackCache>> = std::sync::Mutex::new(None);

/// List a repository's index once: `git ls-files -z` through [`hardened_git`], under the
/// per-call timeout and the scan's remaining budget.
fn list_tracked(root: &std::path::Path) -> TrackedSet {
    if git_dir_unsafe_to_spawn(&root.join(".git")) {
        return None;
    }
    let remaining = {
        let guard = GIT_TRACK_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        let spent = guard.as_ref().map_or(std::time::Duration::ZERO, |c| c.spent);
        GIT_TRACKED_BUDGET.saturating_sub(spent)
    };
    if remaining.is_zero() {
        telemetry::note_read(root, "git budget spent");
        return None;
    }
    let started = std::time::Instant::now();
    let mut cmd = hardened_git();
    cmd.args(["ls-files", "-z"]).current_dir(root);
    let out = output_with_timeout_capped(&mut cmd, GIT_TRACKED_TIMEOUT.min(remaining), "git_tracked", GIT_LS_FILES_MAX);
    {
        let mut guard = GIT_TRACK_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = guard.as_mut() {
            c.spent += started.elapsed();
        }
    }
    let out = out.filter(|o| o.status.success())?;
    Some(out.stdout.split(|b| *b == 0).filter(|p| !p.is_empty()).map(<[u8]>::to_vec).collect())
}

/// Whether `path` is tracked by git: `Some(true|false)`, or None when that cannot be
/// answered (no spawn in a repository whose git directory holds a FIFO or other
/// non-file, a listing that timed out or ran past its output cap, or the scan's git
/// budget spent). Each repository is listed once per scan (`git ls-files -z` through
/// [`hardened_git`], stdin closed, killed on timeout) and every later question about
/// it is answered from that listing, so a repository built to stall git costs one
/// timeout, not one per file. A path outside any repository is `Some(false)`. A
/// directory counts as tracked when a file under it is.
pub fn git_tracked_state(path: &std::path::Path) -> Option<bool> {
    let Some(root) = repo_root_of(path) else { return Some(false) };
    let cell = {
        let mut guard = GIT_TRACK_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        let cache = guard.get_or_insert_with(|| GitTrackCache { repos: Default::default(), spent: Default::default() });
        cache.repos.entry(root.clone()).or_default().clone()
    };
    let set = cell.get_or_init(|| list_tracked(&root)).as_ref()?;
    let rel = path.strip_prefix(&root).ok()?;
    #[cfg(unix)]
    let rel_bytes = {
        use std::os::unix::ffi::OsStrExt;
        rel.as_os_str().as_bytes().to_vec()
    };
    #[cfg(not(unix))]
    let rel_bytes = rel.to_string_lossy().replace('\\', "/").into_bytes();
    if set.contains(&rel_bytes) {
        return Some(true);
    }
    let mut prefix = rel_bytes;
    prefix.push(b'/');
    Some(set.range(prefix.clone()..).next().is_some_and(|p| p.starts_with(&prefix)))
}

/// [`git_tracked_state`], with "unknown" answered as not tracked.
pub fn is_git_tracked(path: &std::path::Path) -> bool {
    git_tracked_state(path).unwrap_or(false)
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

/// Open a file for reading only if its FINAL component is not a symlink and it is a
/// regular file: `O_NOFOLLOW | O_NONBLOCK` (a FIFO never blocks the open), then fstat on
/// the opened descriptor, so what is classified is what is read. With `expect`, the
/// descriptor's real path (Linux `/proc/self/fd`, macOS `F_GETPATH`) must equal it: a
/// directory in the chain swapped for a symlink between the caller's canonicalize() and
/// this open is refused instead of read. Returns the file and its length.
pub fn open_regular_nofollow(
    path: &std::path::Path,
    expect: Option<&std::path::Path>,
) -> Option<(std::fs::File, u64)> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .ok()?
    };
    #[cfg(not(unix))]
    let file = {
        if !std::fs::symlink_metadata(path).ok()?.is_file() {
            return None;
        }
        std::fs::File::open(path).ok()?
    };
    let meta = file.metadata().ok()?;
    if !meta.is_file() {
        telemetry::note_read(path, "not a regular file");
        return None;
    }
    if let Some(want) = expect
        && fd_real_path(&file).is_some_and(|got| got != want)
    {
        telemetry::note_read(path, "changed during read");
        return None;
    }
    Some((file, meta.len()))
}

/// The path the kernel holds for an open descriptor, where the platform exposes it.
fn fd_real_path(file: &std::fs::File) -> Option<std::path::PathBuf> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::AsRawFd;
        let mut buf = vec![0u8; libc::PATH_MAX as usize + 1];
        // SAFETY: F_GETPATH writes at most MAXPATHLEN (== PATH_MAX) bytes plus NUL into
        // a buffer of PATH_MAX + 1 bytes owned by this frame.
        let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) };
        if rc == -1 {
            return None;
        }
        let len = buf.iter().position(|b| *b == 0)?;
        Some(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..len])))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = file;
        None
    }
}

/// [`read_bounded`] for a file whose path may be attacker-arranged (a repository's or a
/// marketplace clone's own files): the final component must not be a symlink, the target
/// must be a regular file, and with `expect` the opened file must be exactly that path.
pub fn read_bounded_nofollow(path: &std::path::Path, expect: Option<&std::path::Path>) -> Option<String> {
    use std::io::Read;
    let Some((file, len)) = open_regular_nofollow(path, expect) else {
        telemetry::note_read(path, "refused (symlink or not a regular file)");
        return None;
    };
    if len > MAX_CONFIG_SIZE {
        telemetry::note_read(path, "too large");
        return None;
    }
    let mut buf = String::new();
    file.take(MAX_CONFIG_SIZE).read_to_string(&mut buf).ok()?;
    telemetry::note_read(path, "ok");
    Some(buf)
}

/// [`read_head_bytes`] without following a symlink at the final component.
pub fn read_head_bytes_nofollow(path: &std::path::Path, max_bytes: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let (file, _) = open_regular_nofollow(path, None)?;
    telemetry::note_read(path, "ok");
    let mut buf = Vec::with_capacity(max_bytes.min(64 * 1024));
    file.take(max_bytes as u64).read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// A machine-wide path (managed settings, system service directories). Debug builds
/// honour `RMGUARD_TEST_SYSTEM_ROOT`, which re-roots these under a directory so the
/// end-to-end tests do not read the host's /etc; release builds never do, so the knob
/// cannot hide a real machine's managed settings from a scan.
pub fn system_path(p: impl AsRef<std::path::Path>) -> std::path::PathBuf {
    let p = p.as_ref();
    #[cfg(debug_assertions)]
    if let Some(root) = std::env::var_os("RMGUARD_TEST_SYSTEM_ROOT").filter(|r| !r.is_empty()) {
        let rel = p.strip_prefix("/").unwrap_or(p);
        return std::path::PathBuf::from(root).join(rel);
    }
    p.to_path_buf()
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

/// `path.is_dir()` / `path.exists()` that the diagnostics can see: a `false` counts as a
/// looked-for path that was not there. See [`probe_file`].
pub fn probe_dir(path: &std::path::Path) -> bool {
    let present = path.is_dir();
    telemetry::note_probe(path, present);
    present
}

/// `fs::read_dir` that the diagnostics can see: a directory that exists but cannot be
/// listed (mode 0100, an I/O error) was a silent `return` and read as "no inputs"; it is
/// a miss now, and traced.
pub fn probe_read_dir<P: AsRef<std::path::Path>>(path: P) -> std::io::Result<std::fs::ReadDir> {
    let r = std::fs::read_dir(path.as_ref());
    if let Err(e) = &r {
        telemetry::note_probe(path.as_ref(), false);
        if telemetry::trace_enabled() {
            eprintln!("trace: read_dir {} -> {e}", sanitize_display(&path.as_ref().display().to_string(), 512));
        }
    }
    r
}

pub fn probe_exists(path: &std::path::Path) -> bool {
    let present = path.exists();
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
            // Paths inside a scanned tree are attacker-chosen (a plugin's lib/*.jar name):
            // redact secrets AND neutralise control characters before they hit the terminal.
            let shown = super::sanitize_display(&super::redact_secrets_in_text(&path.display().to_string()), 512);
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
            let shown = super::sanitize_display(&super::redact_secrets_in_text(&path.display().to_string()), 512);
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
        scanner: &'static str,
        root: Option<PathBuf>,
        f: impl FnOnce() -> Vec<T>,
    ) -> Vec<T> {
        use crate::otel::{Attr, Key};
        let (r0, m0) = snapshot();
        // The span starts at the same instant `elapsed` is measured from and is ended at
        // exactly start + elapsed: its duration is the table's, and every child span the
        // scanner opens ends inside it.
        let start = Instant::now();
        let mut span =
            crate::otel::span_with_at("scanner.", scanner, start, || vec![Attr::scanner(scanner)]);
        if trace_enabled() {
            eprintln!("trace: scanner {scanner} start");
        }
        let out = f();
        let elapsed = start.elapsed();
        let (r1, m1) = snapshot();
        let stat = ScannerStat {
            scanner: scanner.to_string(),
            root: root.map(|p| p.display().to_string()),
            duration_ms: elapsed.as_millis() as u64,
            files_read: r1 - r0,
            files_missing: m1 - m0,
            items: out.len(),
            skipped: false,
        };
        // Counts and duration only; `root` (a path) is never exported.
        span.set(|| {
            vec![
                Attr::int(Key::DurationMs, stat.duration_ms as i64),
                Attr::int(Key::FilesRead, stat.files_read as i64),
                Attr::int(Key::FilesMissing, stat.files_missing as i64),
                Attr::int(Key::Items, stat.items as i64),
            ]
        });
        span.finish_after(elapsed);
        crate::otel::record_scanner(scanner, &stat, elapsed);
        if trace_enabled() {
            eprintln!(
                "trace: scanner {scanner} done: {}ms, {} read, {} missing, {} items",
                stat.duration_ms, stat.files_read, stat.files_missing, stat.items
            );
        }
        diagnostics.push(stat);
        out
    }

    pub fn skipped(scanner: &'static str) -> ScannerStat {
        crate::otel::record(crate::otel::Metric::Skipped, 1.0, || vec![crate::otel::Attr::scanner(scanner)]);
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
        // Bidi overrides and isolates (Cf, not is_control) can reverse the visible text
        // of a status line without adding one; they go too.
        let bad = c.is_control()
            || ('\u{80}'..='\u{9f}').contains(&c)
            || matches!(c, '\u{2028}' | '\u{2029}' | '\u{200e}' | '\u{200f}')
            || ('\u{202a}'..='\u{202e}').contains(&c)
            || ('\u{2066}'..='\u{2069}').contains(&c);
        out.push(if bad { '?' } else { c });
    }
    out
}


/// Run a command with a wall-clock cap, stdin closed. `Command::output()` has no timeout,
/// and git will happily open an `[include] path = /dev/tty` (or a FIFO) from an
/// attacker-authored config and block forever, stalling the whole scan. Returns None on
/// timeout or spawn failure.
///
/// stdout is drained on a reader thread while the parent polls, so a child that writes
/// more than the pipe buffer (a `git ls-files` of a large repository) is not deadlocked
/// into the timeout. Output is capped at `MAX_CHILD_OUTPUT` bytes; a child still writing
/// past the cap is killed like a timeout, since nothing is reading any more.
pub fn output_with_timeout(
    cmd: &mut std::process::Command,
    timeout: std::time::Duration,
) -> Option<std::process::Output> {
    output_with_timeout_at(cmd, timeout, "output_with_timeout")
}

/// [`output_with_timeout`] with the exec span's site name.
fn output_with_timeout_at(
    cmd: &mut std::process::Command,
    timeout: std::time::Duration,
    site: &'static str,
) -> Option<std::process::Output> {
    output_with_timeout_capped(cmd, timeout, site, MAX_CHILD_OUTPUT)
}

/// [`output_with_timeout_at`] with an explicit output cap. A child that writes past the
/// cap is killed at once (not left to the timeout) and None is returned: its output is
/// incomplete.
fn output_with_timeout_capped(
    cmd: &mut std::process::Command,
    timeout: std::time::Duration,
    site: &'static str,
    cap: usize,
) -> Option<std::process::Output> {
    use std::io::Read;
    use std::process::Stdio;
    let mut x = crate::otel::exec_span(site);
    let mut child = match cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() {
        Ok(c) => c,
        Err(_) => {
            x.outcome("spawn_failed");
            return None;
        }
    };
    let Some(mut stdout) = child.stdout.take() else {
        x.outcome("spawn_failed");
        return None;
    };
    let over = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let over_r = over.clone();
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut stdout).take(cap as u64 + 1).read_to_end(&mut buf);
        if buf.len() > cap {
            buf.truncate(cap);
            over_r.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        buf
    });
    let start = std::time::Instant::now();
    let capped = cap < MAX_CHILD_OUTPUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = reader.join().unwrap_or_default();
                note_exit(&mut x, &status);
                if capped && over.load(std::sync::atomic::Ordering::SeqCst) {
                    x.outcome("output_cap");
                    return None;
                }
                return Some(std::process::Output { status, stdout, stderr: Vec::new() });
            }
            Ok(None) if capped && over.load(std::sync::atomic::Ordering::SeqCst) => {
                let _ = child.kill();
                let _ = child.wait();
                x.outcome("output_cap");
                return None;
            }
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                x.outcome("timeout");
                return None;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(20)),
            Err(_) => {
                x.outcome("wait_failed");
                return None;
            }
        }
    }
}

/// Upper bound on bytes kept from a child's stdout. 8 MiB is a very large repository's
/// `git ls-files -s`; the callers only ever need a bounded prefix.
pub const MAX_CHILD_OUTPUT: usize = 8 * 1024 * 1024;
