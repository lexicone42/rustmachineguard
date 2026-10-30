pub mod agent_settings;
pub mod agents_more;
pub mod ai_credentials;
pub mod ai_frameworks;
pub mod ai_tools;
pub mod authorized_keys;
pub mod browser_extensions;
pub mod cloud_credentials;
pub mod container_tools;
pub mod dot_agents;
pub mod env_files;
pub mod exposure;
pub mod extensions;
pub mod git_config;
mod helper_redact;
pub(crate) mod hook_discovery;
pub mod hook_sources;
pub mod ide;
pub mod jetbrains_plugins;
pub mod listeners;
pub mod liveness;
pub mod marketplaces;
pub mod mcp;
pub mod mcp_probe;
pub mod node_packages;
pub mod notebook_servers;
pub mod npm_packages;
pub mod package_configs;
pub mod persistence;
pub mod playwright_mcp;
pub mod plugin_lsp;
pub(crate) mod prefetch;
pub mod python_packages;
pub mod rules_files;
pub mod settings_scripts;
pub mod shell_configs;
pub mod skills;
pub mod ssh_keys;
pub mod transcript_content;
pub mod transcripts;
pub mod vibe;
pub mod vscode_tasks;
pub mod walk_index;
pub mod yaml;

use crate::platform::PlatformInfo;
use std::time::Duration;

/// Is a process with exactly this name running?
///
/// This used to spawn `pgrep -x <name>` once per question: ten spawns and about 120 ms a
/// scan (one for `ai`, seven for `frameworks`, two for `containers`). It now asks one
/// process-name snapshot, taken on the first call and kept for the rest of the run
/// ([`process_names`]). The answer is the one `pgrep -x` gave: `-x` anchors the pattern
/// to the whole process NAME (the kernel's 15-byte `comm` on Linux, `p_comm` on macOS),
/// never the command line, case-sensitively. pgrep reads the pattern as a regular
/// expression, so plain string equality is the same match only for names without regex
/// metacharacters; `process_snapshot_tests` checks every name the scanners ask about.
pub fn is_process_running(name: &str) -> bool {
    process_list_has(process_names(), name)
}

/// Exact, case-sensitive name equality: `pgrep -x` for a metacharacter-free name.
pub(crate) fn process_list_has(names: &[String], name: &str) -> bool {
    !name.is_empty() && names.iter().any(|n| n == name)
}

/// The names of every running process, read once per run. A process list cannot be
/// stale in a way that matters within one scan, and nothing rmguard reports depends on
/// a process started or stopped during the two seconds it runs.
fn process_names() -> &'static [String] {
    static SNAPSHOT: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    SNAPSHOT.get_or_init(snapshot_process_names)
}

/// One `ps -A -o ucomm=` through the hardened, time-capped runner: every process, its
/// accounting name only (the field `pgrep -x` matches: `comm` on Linux procps, `p_comm`
/// on macOS), no header. Falls back to reading `/proc/<pid>/comm` on Linux when ps is
/// missing or fails (busybox ps has no `-o ucomm`).
fn snapshot_process_names() -> Vec<String> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let mut cmd = system_command("ps");
        cmd.args(["-A", "-o", "ucomm="]);
        if let Some(out) = output_with_timeout_at(&mut cmd, Duration::from_secs(5), "process_list")
            && out.status.success()
        {
            return parse_process_list(&out.stdout);
        }
    }
    #[cfg(target_os = "linux")]
    {
        proc_process_names()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

/// One name per line. procps appends ` <defunct>` to a zombie's name; `pgrep -x` still
/// matched the bare name, so the suffix is removed.
pub(crate) fn parse_process_list(stdout: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .map(|l| {
            let l = l.trim();
            l.strip_suffix(" <defunct>").unwrap_or(l).to_string()
        })
        .filter(|l| !l.is_empty())
        .collect()
}

/// Every `/proc/<pid>/comm` (Linux fallback when ps is unavailable): the same field
/// pgrep reads.
#[cfg(target_os = "linux")]
fn proc_process_names() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let fname = entry.file_name();
        if !fname.to_string_lossy().chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) {
            out.push(comm.trim().to_string());
        }
    }
    out
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

/// What a waited-on child did. `Exited` hands the child back (its exit status is cached
/// by std, so `wait_with_output` still works) for callers that read its pipes afterwards.
enum ChildWait {
    Exited(std::process::ExitStatus, std::process::Child),
    TimedOut,
    OverCap,
    WaitFailed,
}

/// Events the waiter and reader threads send to the caller's channel.
enum ChildEvent {
    Exited(std::io::Result<std::process::ExitStatus>, std::process::Child),
    OverCap,
}

/// Block until the child exits, `timeout` passes, or (when `strict`) the reader thread
/// reports the output cap hit; never a poll. The child is reaped on a waiter thread
/// that sends its status down `rx` the moment it exits, so a 3 ms `--version` probe
/// costs 3 ms. The old loops slept 50 ms (version probes) and 20 ms (every other
/// child) between `try_wait` calls, which the OpenTelemetry trace exposed as every
/// exec span lasting an exact multiple of the tick: 50, 100 and 300 ms version probes
/// and 20 ms git calls, more than a second of a 3.5 s scan. On timeout or over-cap the
/// child is killed by pid and then reaped, so no zombie and no pid reuse window: the
/// pid stays reserved until the waiter's `wait` returns.
fn wait_child(pid: u32, rx: &std::sync::mpsc::Receiver<ChildEvent>, timeout: Duration, strict: bool) -> ChildWait {
    use std::sync::mpsc::RecvTimeoutError;
    let deadline = std::time::Instant::now() + timeout;
    let reap = |rx: &std::sync::mpsc::Receiver<ChildEvent>| {
        // SAFETY: plain libc call on a pid this process spawned and has not yet reaped.
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        // The waiter thread's `wait` returns once the kill lands; drain to it.
        while let Ok(ev) = rx.recv() {
            if let ChildEvent::Exited(..) = ev {
                break;
            }
        }
    };
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(left) {
            Ok(ChildEvent::Exited(Ok(status), child)) => return ChildWait::Exited(status, child),
            Ok(ChildEvent::Exited(Err(_), _)) => return ChildWait::WaitFailed,
            Ok(ChildEvent::OverCap) if strict => {
                reap(rx);
                return ChildWait::OverCap;
            }
            Ok(ChildEvent::OverCap) => continue,
            Err(RecvTimeoutError::Timeout) => {
                reap(rx);
                return ChildWait::TimedOut;
            }
            Err(RecvTimeoutError::Disconnected) => return ChildWait::WaitFailed,
        }
    }
}

/// Spawn the waiter thread that reaps `child` and reports through `tx`.
fn spawn_waiter(mut child: std::process::Child, tx: std::sync::mpsc::Sender<ChildEvent>) {
    let spawned = std::thread::Builder::new().name("rmguard-wait".into()).spawn(move || {
        let r = child.wait();
        let _ = tx.send(ChildEvent::Exited(r, child));
    });
    // A failed thread spawn drops `tx` with the child; the caller then sees
    // Disconnected and reports wait_failed rather than hanging.
    let _ = spawned;
}

/// Get version from a binary by running `binary --version` with a 5-second timeout.
pub fn get_binary_version(binary: &str) -> Option<String> {
    let mut x = crate::otel::exec_span("version_probe", std::ffi::OsStr::new(binary));
    let child = match child_command(binary)
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

    let pid = child.id();
    let (tx, rx) = std::sync::mpsc::channel();
    spawn_waiter(child, tx);
    let child = match wait_child(pid, &rx, Duration::from_secs(5), false) {
        ChildWait::Exited(status, child) => {
            note_exit(&mut x, &status);
            child
        }
        ChildWait::TimedOut => {
            x.outcome("timeout");
            return None;
        }
        ChildWait::OverCap | ChildWait::WaitFailed => {
            x.outcome("wait_failed");
            return None;
        }
    };
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
            0x061C | 0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069 => "bidi-control",
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
    ('\u{0430}', 'a'),
    ('\u{0435}', 'e'),
    ('\u{043e}', 'o'),
    ('\u{0440}', 'p'),
    ('\u{0441}', 'c'),
    ('\u{0445}', 'x'),
    ('\u{0443}', 'y'),
    ('\u{0456}', 'i'),
    ('\u{0455}', 's'),
    ('\u{04bb}', 'h'),
    ('\u{0432}', 'b'),
    ('\u{043a}', 'k'),
    ('\u{043c}', 'm'),
    ('\u{0442}', 't'),
    ('\u{0448}', 'w'),
    // Greek
    ('\u{03bf}', 'o'),
    ('\u{03c1}', 'p'),
    ('\u{03b5}', 'e'),
    ('\u{03b1}', 'a'),
    ('\u{03bd}', 'v'),
    ('\u{03c5}', 'u'),
    ('\u{03ba}', 'k'),
    ('\u{03c4}', 't'),
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
    if (0xFF01..=0xFF5E).contains(&cp)
        && let Some(a) = char::from_u32(cp - 0xFEE0)
    {
        return a;
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
    // Redaction must be idempotent: a redacted report fed back through the tool must not
    // change again (fuzz_redact_secrets asserts it). The token pass and the pattern passes
    // after it interact -- a marker one inserts changes what another sees on the
    // next run (`:D@auth:/`, `1:D@oauth2=://x`, `':@@:`, a quoted Telegram URL) -- so
    // the pass is repeated until nothing changes. A pass only replaces text with the marker;
    // in practice the second pass is already the fixed point; the bound is a backstop.
    let mut cur = redact_secrets_once(text);
    for _ in 0..8 {
        let next = redact_secrets_once(&cur);
        if next == cur {
            break;
        }
        cur = next;
    }
    cur
}

fn redact_secrets_once(text: &str) -> String {
    // Tokenise into shell words, keeping the spans so the original whitespace is copied
    // back verbatim (splitting on ' ' alone once let a tab-separated secret through).
    let spans = spans_of(text);
    let tok = |i: usize| -> &str { &text[spans[i].0..spans[i].1] };
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    let mut pending = Pending::None;
    // The program of the current simple command takes an attached `-p<password>`
    // (mysql and its tools, sshpass): set by its name, cleared at a command separator.
    let mut attached_p: Option<&str> = None;
    // The shell's quote state at the start of each word, read from the text as written.
    // A value word that redacted something and leaves a quote open (`--api-key "a"' 'X`,
    // `-u "user:a X"`) continues into the next words only when it started at top level:
    // a word that started inside a quote (`bash -c "export TOKEN=X"`) closes one instead.
    let mut qstate: Option<Close> = None;
    // Inside a curl command: its short `-b` (cookies) and `-E` (certificate:passphrase)
    // mean those things only there (`grep -E 'a:b'` is a regex).
    let mut in_curl = false;
    for i in 0..spans.len() {
        let gap = &text[last..spans[i].0];
        // A header value owed to the end of its line (an unquoted `Cookie:`, as an
        // exec-form argv element) ends at the line break.
        if pending == Pending::Line && has_unescaped_newline(gap) {
            pending = Pending::None;
        }
        out.push_str(gap);
        let prev = i.checked_sub(1).map(tok);
        let prev2 = i.checked_sub(2).map(tok);
        let next = (i + 1 < spans.len()).then(|| tok(i + 1));
        let t = tok(i);
        let attached = if pending == Pending::None {
            attached_p.and_then(|prog| redact_attached_password(prog, t, prev))
        } else {
            None
        };
        let was_pending = pending != Pending::None;
        let rendered = match attached {
            Some(shown) => shown,
            None => {
                let (rendered, next_state) = redact_token(t, prev, prev2, next, pending, in_curl);
                pending = next_state;
                rendered
            }
        };
        if pending == Pending::None
            && !was_pending
            && qstate.is_none()
            && rendered != t
            && let Some(q) = quote_state_after(None, &rendered)
        {
            pending = Pending::Quote(q);
        }
        qstate = quote_state_after(qstate, t);
        let word = t.trim_matches(['"', '\'', '(', '`']);
        let base = word.rsplit('/').next().unwrap_or(word);
        if let Some(p) = ATTACHED_PASSWORD_PROGRAMS.iter().find(|p| **p == base) {
            attached_p = Some(p);
        } else if t.ends_with([';', '&', '|']) {
            attached_p = None;
        }
        if base == "curl" {
            in_curl = true;
        } else if separator_token(t) {
            in_curl = false;
        }
        out.push_str(&rendered);
        last = spans[i].1;
    }
    out.push_str(&text[last..]);
    // The program-specific tables too (`redis-cli -a X`, `docker login -p X`,
    // `echo X | gh auth login --with-token`, `--pass X`, `-passin pass:X`): hook, MCP and
    // VS Code task text goes through this function, not only the command redactor.
    let out = redact_config_set_values(&redact_generic_secret_flags(&redact_stdin_password_feeds(
        &redact_program_secret_flags(&out),
    )));
    redact_webhook_urls(&redact_token_shapes(&redact_code_authorization(&out)))
}

/// An `Authorization` header written as code rather than as a shell `-H` word:
/// `fetch(url,{headers:{Authorization:'Bearer X'}})`, `"Authorization": "Bearer X"`,
/// `{'Proxy-Authorization': 'Basic X'}`. After the name, an optional closing quote, `:`,
/// optional space and an optional opening quote, the value is redacted (a known scheme
/// word is kept, as for the header form) up to its closing quote, or without a quote to
/// the next space, `,`, `;`, `}` or `)`. A bare variable reference (`$TOKEN`,
/// `${TOKEN}`) names a value without holding one and is kept; a value that is already
/// `<redacted>` is left alone (review of 4e3f8c3).
fn redact_code_authorization(text: &str) -> String {
    let mut cur = redact_code_header(text, "authorization");
    // The other credential headers written as code (`{"X-API-Key":"X"}`,
    // `headers: {'Private-Token': 'X'}`): the same rule, by name.
    for name in CODE_SECRET_HEADERS {
        if cur.to_ascii_lowercase().contains(name) {
            cur = redact_code_header(&cur, name);
        }
    }
    cur
}

/// Credential header names other than `Authorization` (which keeps its scheme word),
/// matched as a whole name in code: a quote, `{`, `,`, whitespace or the start before it.
const CODE_SECRET_HEADERS: &[&str] = &[
    "x-api-key",
    "x-auth-token",
    "private-token",
    "x-goog-api-key",
    "x-access-token",
    "api-key",
    "apikey",
];

/// [`redact_code_authorization`] for one header name (lower case).
fn redact_code_header(text: &str, header: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    let mut from = 0;
    while let Some(off) = lower[from..].find(header) {
        let name_start = from + off;
        let name_end = name_start + header.len();
        from = name_end;
        if header != "authorization"
            && name_start > 0
            && !matches!(
                b[name_start - 1],
                b'"' | b'\'' | b'`' | b'{' | b',' | b' ' | b'\t' | b'\n'
            )
        {
            continue;
        }
        let mut k = name_end;
        if k < b.len() && matches!(b[k], b'"' | b'\'' | b'`') {
            k += 1;
        }
        // A space, or a backslash-escaped one (`Authorization:\ Bearer\ X` is one word).
        let space_at = |k: usize| match b.get(k) {
            Some(b' ') => 1,
            Some(b'\\') if matches!(b.get(k + 1), Some(b' ' | b'\t')) => 2,
            _ => 0,
        };
        while space_at(k) > 0 {
            k += space_at(k);
        }
        if k >= b.len() || b[k] != b':' {
            continue;
        }
        k += 1;
        while space_at(k) > 0 {
            k += space_at(k);
        }
        let quote = (k < b.len() && matches!(b[k], b'"' | b'\'' | b'`')).then(|| b[k]);
        if quote.is_some() {
            k += 1;
        }
        // A scheme word and its space are kept.
        let word_end = text[k..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .map_or(text.len(), |o| k + o);
        let mut v = k;
        if space_at(word_end) > 0 && is_scheme_word(&text[k..word_end]) {
            v = word_end;
            while space_at(v) > 0 {
                v += space_at(v);
            }
        }
        let end = match quote {
            Some(q) => text[v..].find(q as char).map_or(text.len(), |o| v + o),
            None => {
                // An unquoted value ends at whitespace the shell splits on: not at an
                // escaped space, which is more of the same word.
                let mut e = v;
                while e < b.len() {
                    if b[e] == b'\\' && e + 1 < b.len() {
                        e += 2;
                        continue;
                    }
                    if b[e].is_ascii_whitespace() || matches!(b[e], b',' | b';' | b'}' | b')' | b'"' | b'\'' | b'`') {
                        break;
                    }
                    e += 1;
                }
                // A multi-byte character can follow a backslash; land on a boundary.
                let mut e = e.min(b.len());
                while !text.is_char_boundary(e) {
                    e += 1;
                }
                e
            }
        };
        let value = &text[v..end];
        let var_ref = value.strip_prefix('$').is_some_and(|n| {
            let n = n.strip_prefix('{').and_then(|n| n.strip_suffix('}')).unwrap_or(n);
            !n.is_empty() && n.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
        });
        if value.is_empty() || value.starts_with("<redacted>") || var_ref || v < last {
            continue;
        }
        out.push_str(&text[last..v]);
        out.push_str("<redacted>");
        last = end;
        from = end.max(from);
    }
    out.push_str(&text[last..]);
    out
}

/// Webhook URLs whose path IS the credential: Slack incoming webhooks and workflow
/// triggers, Telegram bot tokens, Microsoft Teams (Office 365) connectors and Zapier
/// catch hooks (Discord is matched separately, for its optional API version). The host
/// and the fixed prefix are kept, so a finding still says where data goes; everything
/// after the prefix is redacted.
const WEBHOOK_SECRET_PREFIXES: &[&str] = &[
    "hooks.slack.com/services/",
    "hooks.slack.com/workflows/",
    "hooks.slack.com/triggers/",
    "api.telegram.org/bot",
    "api.telegram.org/file/bot",
    "webhook.office.com/webhookb2/",
    "hooks.zapier.com/hooks/catch/",
];

/// Characters a webhook URL's secret path runs through (it stops at a quote, space,
/// `?`, `#`, `<` or shell syntax).
fn webhook_path_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':' | b'/' | b'.' | b'%' | b'~' | b'+' | b'=')
}

/// The end of a Discord webhook prefix at `at` (`discord.com/api/[v10/]webhooks/`).
fn discord_webhook_prefix(lower: &str, at: usize) -> Option<usize> {
    let rest = &lower[at..];
    let host = ["discord.com/api/", "discordapp.com/api/"]
        .into_iter()
        .find(|h| rest.starts_with(h))?;
    let b = lower.as_bytes();
    let mut i = at + host.len();
    if b.get(i) == Some(&b'v') {
        let digits = b[i + 1..].iter().take_while(|c| c.is_ascii_digit()).count();
        if digits > 0 && b.get(i + 1 + digits) == Some(&b'/') {
            i += digits + 2;
        }
    }
    lower[i..].starts_with("webhooks/").then_some(i + "webhooks/".len())
}

/// Redact the secret path of the webhook URLs in [`WEBHOOK_SECRET_PREFIXES`] and of
/// Discord webhooks, wherever they appear (a Stop or Notification hook posting to a chat
/// is one of the commonest hooks people write).
pub fn redact_webhook_urls(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut i = 0;
    while i < b.len() {
        if !text.is_char_boundary(i) {
            i += 1;
            continue;
        }
        let prefix_end = WEBHOOK_SECRET_PREFIXES
            .iter()
            .find(|p| lower[i..].starts_with(*p))
            .map(|p| i + p.len())
            .or_else(|| discord_webhook_prefix(&lower, i));
        let Some(start) = prefix_end else {
            i += 1;
            continue;
        };
        let stop = start + b[start..].iter().take_while(|c| webhook_path_byte(**c)).count();
        if stop > start {
            out.push_str(&text[copied..start]);
            out.push_str("<redacted>");
            copied = stop;
        }
        i = stop.max(i + 1);
    }
    out.push_str(&text[copied..]);
    out
}

/// Programs whose `-p` takes the password attached (`mysql -uroot -pHunter2`), or as
/// the next word (`sshpass -p Hunter2 ssh host`).
const ATTACHED_PASSWORD_PROGRAMS: &[&str] = &[
    "mysql",
    "mysqldump",
    "mysqladmin",
    "mysqlimport",
    "mysqlshow",
    "mysqlcheck",
    "mysqlpump",
    "mysqlsh",
    "mariadb",
    "mariadb-dump",
    "mariadb-admin",
    "mariadb-import",
    "mariadb-check",
    "sshpass",
];

/// `-p<value>` after any of [`ATTACHED_PASSWORD_PROGRAMS`], or the word after a bare
/// `-p` for sshpass, redacted. (mysql's bare `-p` prompts; the next word there is the
/// database name.)
fn redact_attached_password(prog: &str, tok: &str, prev: Option<&str>) -> Option<String> {
    // A command separator glued to the value (`-pX;`, `-pX&&`) is the next command's,
    // not the password's.
    let split = |v: &str| v.find([';', '&', '|']).map_or(String::new(), |i| v[i..].to_string());
    if let Some(v) = tok.strip_prefix("-p")
        && !v.is_empty()
        && !tok.starts_with("--")
        && !v.starts_with("<redacted>")
        && !v.starts_with([';', '&', '|'])
    {
        return Some(format!("-p<redacted>{}", split(v)));
    }
    if prog == "sshpass"
        && prev == Some("-p")
        && !tok.starts_with(['-', ';', '&', '|'])
        && !tok.starts_with("<redacted>")
    {
        return Some(format!("<redacted>{}", split(tok)));
    }
    None
}

/// Vendor credential prefixes and the minimum tail length that makes a match a key
/// rather than a word. The context rules above key on NAMES and positions
/// (`--token X`, `password=X`), so a bare literal such as `echo sk-ant-api03-...` in an
/// apiKeyHelper passed straight through; these shapes are distinctive enough to redact
/// wherever they appear. The prefix is kept (it says WHAT leaked), the tail is not.
const TOKEN_PREFIXES: &[(&str, usize)] = &[
    ("sk-ant-", 16),
    ("sk-proj-", 16),
    ("sk-svcacct-", 16),
    ("sk-or-", 16),
    ("sk-", 20),
    ("sk_live_", 16),
    ("sk_test_", 16),
    ("rk_live_", 16),
    ("ghp_", 20),
    ("gho_", 20),
    ("ghu_", 20),
    ("ghs_", 20),
    ("ghr_", 20),
    ("github_pat_", 20),
    ("glpat-", 20),
    ("xoxb-", 10),
    ("xoxp-", 10),
    ("xoxa-", 10),
    ("xoxr-", 10),
    ("xoxs-", 10),
    ("xoxe-", 10),
    ("xapp-", 10),
    ("AIza", 30),
    ("npm_", 30),
    ("hf_", 30),
    ("pypi-", 32),
    ("gsk_", 20),
    ("AKIA", 16),
    ("ASIA", 16),
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
            && let Some((prefix, min)) = TOKEN_PREFIXES
                .iter()
                .find(|(p, _)| bytes[i..].starts_with(p.as_bytes()))
        {
            let start = i + prefix.len();
            let mut end = start + bytes[start..].iter().take_while(|b| is_token_char(**b)).count();
            // A stateless GitHub App installation token is `ghs_<app id>_<JWT>`: the JWT's
            // payload and signature follow dots, and redacting only up to the first dot
            // would print them (transcript_content::stateless_ghs has the sources).
            if *prefix == "ghs_" {
                for _ in 0..2 {
                    let seg = bytes
                        .get(end + 1..)
                        .map_or(0, |r| r.iter().take_while(|b| is_token_char(**b)).count());
                    if bytes.get(end) != Some(&b'.') || seg == 0 {
                        break;
                    }
                    end += 1 + seg;
                }
            }
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

pub use helper_redact::{helper_classification_shape, redact_helper_command};

/// A long run of key-alphabet characters mixing letters and digits that is not a path, a
/// flag or a word-separated identifier: the shape of an API key with no recognisable
/// vendor prefix.
fn looks_high_entropy(tok: &str) -> bool {
    let core = tok.trim_matches(['"', '\'', ';', ',', ')', '(']);
    let core = core.split_once('=').map_or(core, |(_, v)| v);
    core.len() >= 24
        && !core.starts_with(['/', '.', '~', '$', '-'])
        && !core.contains("//")
        && core
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'+' | b'/' | b'=' | b'.'))
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
    if s.bytes()
        .any(|b| !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
    {
        return false;
    }
    let segs: Vec<&str> = s.split(['_', '-']).collect();
    if segs.len() < 3 || segs.iter().any(|g| g.is_empty()) {
        return false;
    }
    let words = segs
        .iter()
        .filter(|g| g.bytes().all(|b| b.is_ascii_alphabetic()))
        .count();
    words * 2 >= segs.len()
        && segs
            .iter()
            .all(|g| g.bytes().all(|b| b.is_ascii_alphabetic()) || g.len() <= 6)
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
            Some((k, v))
                if !k.is_empty() && !v.is_empty() && k.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') =>
            {
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
///
/// Also: the value after a program-agnostic password flag ([`GENERIC_SECRET_FLAGS`]),
/// the path of a URL after a webhook flag ([`WEBHOOK_FLAGS`]), and key-shaped segments of
/// any URL path (`https://example.com/hook/<key>`), judged per segment before the run
/// rule so the host stays readable.
pub fn redact_command_text(text: &str) -> String {
    // Idempotent for the same reason as redact_secrets_in_text: the entropy pass can hide
    // the `=` that kept the userinfo rule from firing (`==a0..user:pw@host`), so a second
    // run would redact more. Repeat to the fixed point; the bound is a backstop.
    let mut cur = redact_command_text_once(text);
    for _ in 0..8 {
        let next = redact_command_text_once(&cur);
        if next == cur {
            break;
        }
        cur = next;
    }
    cur
}

fn redact_command_text_once(text: &str) -> String {
    let base = redact_config_set_values(&redact_generic_secret_flags(&redact_stdin_password_feeds(
        &redact_program_secret_flags(&redact_secrets_in_text(text)),
    )));
    let mut out = String::with_capacity(base.len());
    let mut last = 0;
    for (s, e) in spans_of(&base) {
        out.push_str(&base[last..s]);
        out.push_str(&redact_entropy_runs_in_token(&redact_url_path_keys(&base[s..e])));
        last = e;
    }
    out.push_str(&base[last..]);
    out
}

/// Flags whose value is a credential whatever the program, though their names are not
/// all secret-shaped (`--pass`, `--user-key`): the next word, or the `=` value.
const GENERIC_SECRET_FLAGS: &[&str] = &[
    "-pass",
    "-passin",
    "-passout",
    "--pass",
    "--passwd",
    "--pw",
    "--passphrase",
    "--user-key",
    "--userkey",
    "--app-token",
    "--app-key",
    "--appkey",
    "--bearer",
];

/// Flags whose value is a webhook URL: its path is the credential, its host is kept.
const WEBHOOK_FLAGS: &[&str] = &[
    "--webhook",
    "--webhook-url",
    "--hook-url",
    "--slack-webhook",
    "--discord-webhook",
    "--teams-webhook",
];

/// A webhook URL value with its path (and query) redacted: `https://host/<redacted>`.
/// A value that is not a URL is redacted whole.
fn redact_webhook_value(v: &str) -> String {
    let core = v.trim_matches(['"', '\'']);
    let tail = &v[v.trim_end_matches(['"', '\'']).len()..];
    let head = &v[..v.len() - v.trim_start_matches(['"', '\'']).len()];
    match core.find("://") {
        Some(sc) => {
            let (authority, rest) = split_authority(&core[sc + 3..]);
            let path = if rest.is_empty() || rest.starts_with("/<redacted>") {
                rest.to_string()
            } else {
                "/<redacted>".to_string()
            };
            format!("{head}{}://{authority}{path}{tail}", &core[..sc])
        }
        None if core.is_empty() || core == "<redacted>" => v.to_string(),
        None => format!("{head}<redacted>{tail}"),
    }
}

/// The values of [`GENERIC_SECRET_FLAGS`] and [`WEBHOOK_FLAGS`], as the next word or
/// glued with `=`.
fn redact_generic_secret_flags(text: &str) -> String {
    let spans = spans_of(text);
    let toks: Vec<&str> = spans.iter().map(|&(s, e)| &text[s..e]).collect();
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for (k, &(s, e)) in spans.iter().enumerate() {
        out.push_str(&text[last..s]);
        let t = toks[k];
        let prev = k.checked_sub(1).map(|p| toks[p]);
        let rendered = if let Some((flag, v)) = t.split_once('=')
            && !v.is_empty()
            && (GENERIC_SECRET_FLAGS.contains(&flag) || WEBHOOK_FLAGS.contains(&flag))
        {
            if WEBHOOK_FLAGS.contains(&flag) {
                format!("{flag}={}", redact_webhook_value(v))
            } else if v.starts_with("<redacted>") {
                t.to_string()
            } else {
                format!("{flag}={}", generic_secret_value(flag, v))
            }
        } else if let Some(p) = prev
            && !t.starts_with('-')
            && !separator_token(p)
        {
            if WEBHOOK_FLAGS.contains(&p) {
                redact_webhook_value(t)
            } else if GENERIC_SECRET_FLAGS.contains(&p) && !t.starts_with("<redacted>") {
                generic_secret_value(p, t)
            } else {
                t.to_string()
            }
        } else {
            t.to_string()
        };
        out.push_str(&rendered);
        last = e;
    }
    out.push_str(&text[last..]);
    out
}

/// A [`GENERIC_SECRET_FLAGS`] value redacted. openssl's pass-phrase arguments
/// (`-pass`, `-passin`, `-passout`; openssl-passphrase-options(1)) name where the
/// phrase comes from: `pass:X` holds it (`pass:<redacted>`), while `env:NAME`,
/// `file:PATH`, `fd:N` and `stdin` only point at it and are kept.
fn generic_secret_value(flag: &str, v: &str) -> String {
    if matches!(flag, "-pass" | "-passin" | "-passout") {
        let core = v.trim_start_matches(['"', '\'']);
        let lead = &v[..v.len() - core.len()];
        if let Some(rest) = core.strip_prefix("pass:") {
            if rest.is_empty() || rest.starts_with("<redacted>") {
                return v.to_string();
            }
            return format!("{lead}pass:{}", redact_bare_value(rest));
        }
        if ["env:", "file:", "fd:"].iter().any(|p| core.starts_with(p)) || core == "stdin" {
            return v.to_string();
        }
    }
    redact_bare_value(v)
}

/// Key-shaped segments of a URL's path redacted one by one (see [`looks_high_entropy`]):
/// `https://example.com/hook/<key>` keeps its host and the readable segments.
fn redact_url_path_keys(tok: &str) -> String {
    let Some(sc) = tok.find("://") else {
        return tok.to_string();
    };
    let after = &tok[sc + 3..];
    let (authority, rest) = split_authority(after);
    let end = rest
        .find(['?', '#', '\'', '"', '`', ')', ';', '&', '|'])
        .unwrap_or(rest.len());
    let (path, tail) = rest.split_at(end);
    let path: Vec<String> = path
        .split('/')
        .map(|g| {
            if looks_high_entropy(g) {
                "<redacted>".to_string()
            } else {
                g.to_string()
            }
        })
        .collect();
    format!("{}{authority}{}{tail}", &tok[..sc + 3], path.join("/"))
}

/// Programs whose password flag takes the NEXT word and is not named like a secret
/// (`redis-cli -a PASSWORD`): (program, flags).
// `-p VALUE` after a program not listed here (or in LOGIN_PASSWORD_PROGRAMS) is kept on purpose: a port, path or profile far more often than a password (review of 4e3f8c3).
const PROGRAM_SECRET_FLAGS: &[(&str, &[&str])] = &[
    ("redis-cli", &["-a", "--pass"]),
    ("valkey-cli", &["-a", "--pass"]),
    ("keydb-cli", &["-a", "--pass"]),
    ("redis-benchmark", &["-a"]),
    ("mongosh", &["-p"]),
    ("mongo", &["-p"]),
    ("mongodump", &["-p"]),
    ("mongorestore", &["-p"]),
    ("rabbitmqadmin", &["-p"]),
    ("smbclient", &["-U"]),
];

/// Registry logins whose `-p` is the password, not a port (`docker login -p X`,
/// `podman login -p X`, `helm registry login -p X`): the flag counts only after a
/// `login` word in the same simple command (`docker run -p 8080:80` is a port).
const LOGIN_PASSWORD_PROGRAMS: &[&str] = &["docker", "podman", "helm", "nerdctl", "buildah", "skopeo", "oras"];

/// `config set KEY VALUE` forms whose VALUE is a credential when KEY names one:
/// `npm|yarn|pnpm config set //r.example/:_authToken X`, `yarn config set npmAuthToken X`,
/// `aws configure set aws_secret_access_key X` (and `KEY=VALUE`). The key is kept.
const CONFIG_SET_PROGRAMS: &[&str] = &["npm", "yarn", "pnpm", "aws"];

fn secret_config_key(k: &str) -> bool {
    let l = k.to_ascii_lowercase();
    ["secret", "token", "password", "passwd"].iter().any(|w| l.contains(w)) || l.ends_with("_auth")
}

/// The values of a registry login's `-p` / `--password` ([`LOGIN_PASSWORD_PROGRAMS`]) and
/// of a secret-named `config set` key ([`CONFIG_SET_PROGRAMS`]).
///
/// `-p VALUE` after any OTHER program is left as it is: `-p` is a port, a path or a
/// profile far more often than a password, and redacting it would hide the commands a
/// reviewer needs to read (review of 4e3f8c3 recorded this choice; mysql's attached
/// `-pX` and sshpass are handled by [`redact_attached_password`]).
fn redact_config_set_values(text: &str) -> String {
    let spans = spans_of(text);
    let toks: Vec<&str> = spans.iter().map(|&(s, e)| &text[s..e]).collect();
    let mut redact = vec![false; toks.len()];
    let mut glued: Vec<Option<String>> = vec![None; toks.len()];
    let mut start = 0;
    while start < toks.len() {
        let end = (start..toks.len())
            .find(|&k| separator_token(toks[k]))
            .map_or(toks.len(), |k| k + 1);
        let cmd = &toks[start..end];
        let clean = |t: &str| t.trim_matches(['"', '\'', '(', '`', ';', '&', '|']).to_string();
        let words: Vec<String> = cmd.iter().map(|t| clean(t)).collect();
        if let Some(pi) = words.iter().position(|w| !w.contains('=')) {
            let prog = words[pi].rsplit('/').next().unwrap_or(&words[pi]).to_string();
            if LOGIN_PASSWORD_PROGRAMS.contains(&prog.as_str())
                && let Some(li) = words.iter().position(|w| w == "login")
            {
                for k in li + 1..cmd.len() {
                    let w = &words[k];
                    if (w == "-p" || w == "--password") && k + 1 < cmd.len() && !words[k + 1].starts_with('-') {
                        redact[start + k + 1] = true;
                    } else if let Some((f, v)) = w.split_once('=')
                        && (f == "-p" || f == "--password")
                        && !v.is_empty()
                        && !v.starts_with("<redacted>")
                    {
                        glued[start + k] = Some(format!("{f}=<redacted>"));
                    }
                }
            }
            if CONFIG_SET_PROGRAMS.contains(&prog.as_str())
                && let Some(si) = words.iter().position(|w| w == "set")
                && words[pi + 1..si].iter().any(|w| w == "config" || w == "configure")
                && si + 1 < cmd.len()
            {
                let key = &words[si + 1];
                if let Some((k, v)) = key.split_once('=') {
                    if secret_config_key(k) && !v.is_empty() && !v.starts_with("<redacted>") {
                        glued[start + si + 1] = Some(format!("{k}=<redacted>"));
                    }
                } else if secret_config_key(key) && si + 2 < cmd.len() && !words[si + 2].starts_with('-') {
                    redact[start + si + 2] = true;
                }
            }
        }
        start = end;
    }
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for (k, &(s, e)) in spans.iter().enumerate() {
        out.push_str(&text[last..s]);
        let t = &text[s..e];
        match &glued[k] {
            Some(g) => {
                let keep = t.len() - t.trim_end_matches([';', '&', '|']).len();
                out.push_str(g);
                out.push_str(&t[t.len() - keep..]);
            }
            None if redact[k] && !t.starts_with("<redacted>") => {
                let keep = t.len() - t.trim_end_matches([';', '&', '|']).len();
                out.push_str("<redacted>");
                out.push_str(&t[t.len() - keep..]);
            }
            None => out.push_str(t),
        }
        last = e;
    }
    out.push_str(&text[last..]);
    out
}

/// The words of `text` with their byte spans, split as a POSIX shell splits them on
/// whitespace: a backslash escapes the character after it, so `\ ` (an escaped space or
/// tab) and the `\"`, `\'`, `\\` pairs stay inside the current word. A header value,
/// `--data` body or `NAME=value` written `Authorization:Bearer\ X`, `password=a\ X` or
/// `-u admin:a\ X` is ONE shell word, and splitting at the escaped space showed the
/// credential's tail as the next argument. A backslash-newline that starts a word is a
/// line continuation and belongs to the gap, so the word after it still follows the
/// flag before it (`--token \<newline>  X`). Quoted whitespace still splits, as it
/// always has: the quote-tracking rules carry a quoted value across words.
fn spans_of(text: &str) -> Vec<(usize, usize)> {
    let b = text.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0;
    // Only the shell's own separators split a word: NBSP (U+00A0) and the other Unicode
    // spaces are ordinary characters to sh, so `--token a<NBSP>X` is ONE word whose tail
    // used to show as the next argument.
    let ws_at = |i: usize| b[i].is_ascii_whitespace().then_some(1);
    while i < b.len() {
        if let Some(n) = ws_at(i) {
            i += n;
            continue;
        }
        if b[i] == b'\\' && matches!(b.get(i + 1), Some(b'\n')) {
            i += 2;
            continue;
        }
        if b[i] == b'\\' && b.get(i + 1) == Some(&b'\r') && b.get(i + 2) == Some(&b'\n') {
            i += 3;
            continue;
        }
        let start = i;
        while i < b.len() {
            if b[i] == b'\\' && i + 1 < b.len() {
                // The escaped character, whole (it may be multi-byte).
                i += 1 + text[i + 1..].chars().next().map_or(1, char::len_utf8);
                continue;
            }
            match ws_at(i) {
                Some(_) => break,
                None => i += text[i..].chars().next().map_or(1, char::len_utf8),
            }
        }
        spans.push((start, i));
    }
    spans
}

/// A line break in a gap between words that is not a backslash line continuation.
fn has_unescaped_newline(gap: &str) -> bool {
    gap.match_indices('\n').any(|(i, _)| {
        let before = gap[..i].strip_suffix('\r').unwrap_or(&gap[..i]);
        !before.ends_with('\\')
    })
}

fn separator_token(t: &str) -> bool {
    t.ends_with([';', '&', '|']) || matches!(t, "&&" | "||" | "|" | ";")
}

/// Rebuild `text` with the tokens at `redact` replaced by `<redacted>` (a glued trailing
/// separator, `PW;`, is kept).
fn replace_tokens(text: &str, spans: &[(usize, usize)], redact: &[bool]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for (k, &(s, e)) in spans.iter().enumerate() {
        out.push_str(&text[last..s]);
        let t = &text[s..e];
        if redact[k] && !t.starts_with("<redacted>") {
            let keep = t.len() - t.trim_end_matches([';', '&', '|']).len();
            out.push_str("<redacted>");
            out.push_str(&t[t.len() - keep..]);
        } else {
            out.push_str(t);
        }
        last = e;
    }
    out.push_str(&text[last..]);
    out
}

/// The word after a program's own password flag ([`PROGRAM_SECRET_FLAGS`]).
fn redact_program_secret_flags(text: &str) -> String {
    let spans = spans_of(text);
    let toks: Vec<&str> = spans.iter().map(|&(s, e)| &text[s..e]).collect();
    let mut redact = vec![false; toks.len()];
    let mut glued: Vec<Option<String>> = vec![None; toks.len()];
    let mut prog: Option<&[&str]> = None;
    let mut at_start = true;
    for k in 0..toks.len() {
        let t = toks[k];
        if at_start {
            let w = t.trim_matches(['"', '\'', '(', '`']);
            let base = w.rsplit('/').next().unwrap_or(w);
            if !w.contains('=') {
                prog = PROGRAM_SECRET_FLAGS.iter().find(|(p, _)| *p == base).map(|(_, f)| *f);
                at_start = false;
            }
        } else if let Some(flags) = prog
            && k > 0
            && flags.contains(&toks[k - 1])
            && !t.starts_with('-')
        {
            redact[k] = true;
        } else if let Some(flags) = prog
            && let Some(f) = flags
                .iter()
                .find(|f| f.len() == 2 && t.len() > 2 && t.starts_with(**f) && !t.starts_with("--"))
            && !t[2..].starts_with("<redacted>")
        {
            // A short password flag with its value attached: `redis-cli -aX`.
            glued[k] = Some(format!("{f}<redacted>"));
        }
        if separator_token(t) {
            at_start = true;
            prog = None;
        }
    }
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for (k, &(s, e)) in spans.iter().enumerate() {
        if let Some(g) = &glued[k] {
            out.push_str(&text[last..s]);
            let t = &text[s..e];
            let keep = t.len() - t.trim_end_matches([';', '&', '|']).len();
            out.push_str(g);
            out.push_str(&t[t.len() - keep..]);
            last = e;
        }
    }
    out.push_str(&text[last..]);
    if out == text {
        return replace_tokens(text, &spans, &redact);
    }
    // Rebuild with both kinds of change: re-tokenize the glued result (one span per
    // word is unchanged, since a glued value has no whitespace).
    let spans2 = spans_of(&out);
    replace_tokens(&out, &spans2, &redact)
}

/// `echo PW | docker login -u me --password-stdin`: the arguments of an echo/printf
/// stage piped into a consumer that reads a password or token from stdin
/// (`--password-stdin`, `--with-token`, `--password-file -`) are the credential.
fn redact_stdin_password_feeds(text: &str) -> String {
    let markers = ["--password-stdin", "--with-token", "--password-file", "--token-stdin"];
    if !markers.iter().any(|m| text.contains(m)) {
        return text.to_string();
    }
    // A pipe glued to a word (`echo PW|docker login`) is split out first.
    let text: String = {
        let chars: Vec<char> = text.chars().collect();
        let mut t = String::with_capacity(text.len() + 8);
        for (k, &c) in chars.iter().enumerate() {
            let single = c == '|' && chars.get(k + 1) != Some(&'|') && (k == 0 || chars[k - 1] != '|');
            if single {
                if k > 0 && !chars[k - 1].is_whitespace() {
                    t.push(' ');
                }
                t.push('|');
                if chars.get(k + 1).is_some_and(|n| !n.is_whitespace()) {
                    t.push(' ');
                }
            } else {
                t.push(c);
            }
        }
        t
    };
    let spans = spans_of(&text);
    let toks: Vec<&str> = spans.iter().map(|&(s, e)| &text[s..e]).collect();
    let mut redact = vec![false; toks.len()];
    for p in 0..toks.len() {
        if toks[p] != "|" {
            continue;
        }
        // The consumer: up to the next separator.
        let consumer: Vec<&str> = toks[p + 1..]
            .iter()
            .copied()
            .take_while(|t| !separator_token(t))
            .collect();
        let reads_secret = consumer.iter().enumerate().any(|(k, t)| {
            matches!(
                *t,
                "--password-stdin" | "--with-token" | "--token-stdin" | "--password-file=-"
            ) || (*t == "--password-file" && consumer.get(k + 1) == Some(&"-"))
        });
        if !reads_secret {
            continue;
        }
        // The producer: back to the start of its simple command.
        let start = (0..p).rev().find(|&k| separator_token(toks[k])).map_or(0, |k| k + 1);
        let Some(prog_at) = (start..p).find(|&k| !toks[k].contains('=') || toks[k].starts_with('-')) else {
            continue;
        };
        let w = toks[prog_at].trim_matches(['"', '\'', '(']);
        if !matches!(w.rsplit('/').next().unwrap_or(w), "echo" | "printf" | "print") {
            continue;
        }
        for k in prog_at + 1..p {
            let t = toks[k].trim_matches(['"', '\'']);
            let var = t.strip_prefix('$').is_some_and(|n| {
                n.trim_matches(['{', '}'])
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            });
            if (!toks[k].starts_with('-') || toks[k].len() > 3) && !var {
                redact[k] = true;
            }
        }
    }
    replace_tokens(&text, &spans, &redact)
}

/// What the tokenizer owes the NEXT token(s): nothing, one redaction (the credential
/// after an Authorization scheme word), or redaction until the quote that opened a
/// value is closed (`--password "first SECOND"` is two tokens; both are the secret).
#[derive(Clone, Copy, PartialEq)]
enum Pending {
    None,
    One,
    Quote(Close),
    /// Every token up to the next line break (an unquoted `Cookie:` header value).
    Line,
}

/// A `Cookie:` / `Set-Cookie:` header in a token (`'Cookie:`, `-H"Cookie:`,
/// `--header=Set-Cookie:a=1`): the byte index just past its colon and the quote that
/// opened the header word, if any. Every cookie in the value is a credential.
fn cookie_header(tok: &str) -> Option<(usize, Option<Close>)> {
    let lower = tok.to_ascii_lowercase();
    let at = lower.find("cookie:")?;
    let name_start = if lower[..at].ends_with("set-") { at - 4 } else { at };
    let prefix = &tok[..name_start];
    if !(prefix.is_empty() || prefix.ends_with(['"', '\'', '='])) {
        return None;
    }
    Some((at + "cookie:".len(), quote_state_after(None, prefix)))
}

/// A shell quote that is open: `'...'` (no escapes inside), `"..."` and `$"..."` (a
/// backslash escapes the next character, so `\"` does not close), `$'...'` (ANSI-C: a
/// backslash escapes too, so `\'` does not close).
#[derive(Clone, Copy, PartialEq, Debug)]
enum Close {
    Single,
    Double,
    AnsiC,
}

impl Close {
    fn quote(self) -> u8 {
        match self {
            Close::Double => b'"',
            Close::Single | Close::AnsiC => b'\'',
        }
    }
    fn quote_char(self) -> char {
        self.quote() as char
    }
    fn escapes(self) -> bool {
        self != Close::Single
    }
}

/// The quote `b` opens at its start, and the opener's length (`$'` and `$"` are two).
fn opener(b: &[u8]) -> Option<(Close, usize)> {
    match b {
        [b'$', b'\'', ..] => Some((Close::AnsiC, 2)),
        [b'$', b'"', ..] => Some((Close::Double, 2)),
        [b'"', ..] => Some((Close::Double, 1)),
        [b'\'', ..] => Some((Close::Single, 1)),
        _ => None,
    }
}

/// The byte index of the quote that closes `c` in `s`, which starts inside the quoted
/// text.
fn find_close(s: &str, c: Close) -> Option<usize> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if c.escapes() && b[i] == b'\\' {
            i += 2;
            continue;
        }
        if b[i] == c.quote() {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// The quote state after reading `s` in the shell's quoting rules, starting in `state`.
fn quote_state_after(mut state: Option<Close>, s: &str) -> Option<Close> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match state {
            None => {
                if b[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if let Some((c, n)) = opener(&b[i..]) {
                    state = Some(c);
                    i += n;
                    continue;
                }
            }
            Some(c) => {
                if c.escapes() && b[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if b[i] == c.quote() {
                    state = None;
                }
            }
        }
        i += 1;
    }
    state
}

/// Characters that end a secret's word after a closed quoted part: JSON and
/// connection-string structure (`"X"}`, `"X",`) and shell operators.
fn word_terminator(b: u8) -> bool {
    matches!(b, b'}' | b']' | b')' | b',' | b';' | b'&' | b'|' | b'<' | b'>')
}

/// If `v` opens a quote that the rest of its word does not close, that quote: `"a`,
/// `"a\"`, `$'a`, and `"a"'b` (a closed part, then an open one glued on).
fn unclosed_quote(v: &str) -> Option<Close> {
    opener(v.as_bytes())?;
    redact_value_keeping_quotes(v, None).1
}

/// The rest of a secret's shell word after a closed quoted part (`'a'\ X`, `'a'X`,
/// `"a"'b c'`): the shell glues it onto the same word, so it is more of the secret.
/// Quoted parts keep their quotes and lose their content; an unquoted run becomes one
/// `<redacted>`. The word ends at a [`word_terminator`] or at a quote that closes
/// `outer` (the quote the token opened before the value), which are kept with
/// everything after them. A quote that opens and is not closed before the token ends,
/// with nothing but terminators after it, is read as the closer of a quote opened in an
/// earlier word (`bash -c "export TOKEN=X"`), not as a new one. Returns the rendering
/// and the quote state at the end of the token.
///
/// The kept remainder changes the state only through `outer` (`'{"token":"X"}'` closes
/// the `'` it opened). With no known outer quote, a quote in it is taken to close one
/// opened in an earlier word (`-d '{"token" : "X"}'` arrives as three words), never to
/// open a new one: reading it as an opener redacted every word after the body.
fn redact_word_tail(rest: &str, outer: Option<Close>) -> (String, Option<Close>) {
    let b = rest.as_bytes();
    let mut out = String::with_capacity(rest.len());
    let mut i = 0;
    let verbatim = |out: &mut String, i: usize| {
        out.push_str(&rest[i..]);
        outer.and_then(|_| quote_state_after(outer, &rest[i..]))
    };
    while i < b.len() {
        if word_terminator(b[i]) {
            let st = verbatim(&mut out, i);
            return (out, st);
        }
        if let Some((c, n)) = opener(&b[i..]) {
            if outer.is_some_and(|o| o.quote() == b[i]) {
                let st = verbatim(&mut out, i);
                return (out, st);
            }
            match find_close(&rest[i + n..], c) {
                Some(j) => {
                    out.push_str(&rest[i..i + n]);
                    out.push_str("<redacted>");
                    out.push(c.quote_char());
                    i += n + j + 1;
                }
                None if rest[i + n..].bytes().all(word_terminator) => {
                    let st = verbatim(&mut out, i);
                    return (out, st);
                }
                None => {
                    out.push_str(&rest[i..i + n]);
                    out.push_str("<redacted>");
                    return (out, Some(c));
                }
            }
            continue;
        }
        // An unquoted run, escapes included.
        while i < b.len() && !word_terminator(b[i]) && opener(&b[i..]).is_none() {
            i += if b[i] == b'\\' { 2 } else { 1 };
        }
        i = i.min(b.len());
        out.push_str("<redacted>");
    }
    (out, outer)
}

/// Flags whose value is `user:password` (curl, wget, httpie). The user half is kept.
const USER_FLAGS: &[&str] = &["-u", "--user", "--proxy-user", "-U", "--http-user"];

/// HTTP Authorization schemes. In `Authorization: <scheme> <credential>` the scheme is
/// kept -- it says HOW the server authenticates -- and the credential is redacted.
/// Modelling only Bearer/Basic let `Authorization: token ghp_x` (GitHub's documented
/// form) redact the word `token` and pass `ghp_x` through, looking sanitised.
const AUTH_SCHEMES: &[&str] = &[
    "bearer",
    "basic",
    "token",
    "oauth",
    "oauth2",
    "ssws",
    "apikey",
    "api-key",
    "negotiate",
    "digest",
    "ntlm",
    "hawk",
    "dpop",
    "gnap",
    "hoba",
    "mutual",
    "vapid",
    "signature",
    "privatetoken",
    "aws4-hmac-sha256",
    "goog",
    "splunk",
    "zoho-oauthtoken",
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
    s.ends_with(':') && s.rsplit(['=', '"', '\'']).next().is_some_and(is_authorization_key)
}

fn bare_key(k: &str) -> &str {
    k.trim_start_matches(|c: char| !c.is_ascii_alphanumeric())
        .trim_end_matches(|c: char| !c.is_ascii_alphanumeric())
}

fn is_secret_key(k: &str) -> bool {
    let b = bare_key(k);
    !b.is_empty() && crate::scanners::env_files::is_secret_command_key_name(b)
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
    let mut seps: Vec<(usize, char)> = ['=', ':'].iter().filter_map(|&c| tok.find(c).map(|i| (i, c))).collect();
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
/// Short-flag clusters (`-sk`, `-sSk`) are markers only by a long hint word; see
/// [`is_short_flag_cluster`].
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
    if is_short_flag_cluster(p) {
        // `-sk`, `-sSk`, `-fsSk`: letters that are each their own option. Only a long
        // hint word marks one (`-token X`, `-password X`, `-apiKey X`, Go and openssl
        // style); the short last-word hints (PASS, PWD, PAT, JWT, SK) are word-structured
        // names' rule and here read curl's silent + insecure as a secret key.
        return crate::scanners::env_files::has_secret_command_key_hint(bare_key(p));
    }
    flag_shaped && is_secret_key(p)
}

/// A single-dash flag word with no word structure: one dash, then one run of ASCII
/// letters and digits (`-k`, `-sk`, `-fsSL`, `-token`; trailing punctuation as in `-sk_`
/// or `-sk;` is not structure). Lexically a short-option cluster and a Go style
/// single-dash name are the same thing, so such a word is judged by the long secret-name
/// hints only (see [`is_secret_value_position`]). `--sk` and `-db-pass` have word
/// structure, and `-pass=` / `-sk:` carry their own value: they keep the full rule.
pub(crate) fn is_short_flag_cluster(p: &str) -> bool {
    let b = bare_key(p);
    p.starts_with('-')
        && !p.starts_with("--")
        && !p.ends_with([':', '='])
        && !b.is_empty()
        && b.bytes().all(|c| c.is_ascii_alphanumeric())
}

/// The authority of `after_scheme` (everything up to the path) and the remainder.
/// A backslash ends the authority too: WHATWG treats `\` as `/` for special schemes,
/// so `https://evil.com\@registry.npmjs.org/` has host evil.com. Splitting only on
/// `/?#` read the host as registry.npmjs.org and called a hostile registry official.
fn split_authority(after_scheme: &str) -> (&str, &str) {
    let end = after_scheme.find(['/', '?', '#', '\\']).unwrap_or(after_scheme.len());
    after_scheme.split_at(end)
}

/// Redact a URL: userinfo, and any query parameter whose NAME is secret-shaped.
/// `?a=1&token=X` used to leak because only a leading `key=` was recognised.
fn redact_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let (scheme, after) = (&url[..scheme_end], &url[scheme_end + 3..]);
    // For REDACTION the authority runs on through a backslash-escaped space: in
    // `https://u:a\ X@host/` the shell hands git one word whose password is `a X`, and
    // ending the authority at the backslash (the WHATWG rule split_authority applies, for
    // host decisions) left the userinfo whole.
    let ab = after.as_bytes();
    let end = (0..ab.len())
        .find(|&i| {
            matches!(ab[i], b'/' | b'?' | b'#')
                || (ab[i] == b'\\' && !ab.get(i + 1).is_some_and(|c| c.is_ascii_whitespace()))
        })
        .unwrap_or(ab.len());
    let (authority, rest) = after.split_at(end);
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
                    // A quote or paren closing the surrounding word (`'https://x/?api_key=X'`)
                    // is the shell's, not the value's: it is kept.
                    Some((k, v)) if !v.is_empty() && (is_secret_key(k) || is_query_secret_name(k)) => {
                        let tail = &v[v.trim_end_matches(['\'', '"', ')', '`']).len()..];
                        format!("{k}=<redacted>{tail}")
                    }
                    _ => kv.to_string(),
                })
                .collect();
            format!("{path}?{}{frag}", query.join("&"))
        }
        None => rest.to_string(),
    };
    format!("{scheme}://{host}{rest}")
}

/// Query parameter names that carry a signature or token though they are not
/// secret-shaped words: an Azure SAS `sig` (`?sv=...&sig=X`), `signature`, and the
/// presigned-URL signatures of S3 and GCS.
fn is_query_secret_name(k: &str) -> bool {
    matches!(
        k.to_ascii_lowercase().as_str(),
        "sig" | "signature" | "x-amz-signature" | "x-goog-signature" | "x-amz-security-token" | "code_verifier"
    )
}

/// Strip `user:pass@` from a value, with or without a URL scheme. The HOST is kept --
/// it is the security-relevant half of the finding; the credential is not.
fn redact_userinfo(value: &str) -> String {
    // Only a real scheme (`[A-Za-z][A-Za-z0-9+.-]*`) makes this a URL. `1:D@oauth2=://x`
    // used to be read as a URL with the "scheme" `1:D@oauth2=`, which kept the userinfo;
    // the oauth2 pair rule then removed the `://`, and a second pass found the
    // scheme-less userinfo (fuzz_redact_secrets: redaction was not idempotent).
    if let Some(sc) = value.find("://")
        && value[..sc].chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && value[..sc]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
    {
        return redact_url(value);
    }
    // Scheme-less `user:pass@host`, as pip's `trusted-host` and git remotes write it.
    // Require a non-empty password segment so plain `user@host` and email addresses,
    // which carry no credential, are left intact.
    // A leading quote is the shell's, not the credential's: it is kept, so the quote
    // state a later pass reads from the redacted text is the one this pass acted on.
    let lead = usize::from(value.starts_with(['"', '\'']));
    if let Some(at) = value.rfind('@')
        && at + 1 < value.len()
        && at > lead
        && let Some(colon) = value[lead..at].find(':').map(|c| lead + c)
        && colon + 1 < at
        && !value[..at].contains('=')
    {
        return format!("{}<redacted>@{}", &value[..lead], &value[at + 1..]);
    }
    value.to_string()
}

/// Redact a secret value while keeping its quotes and whatever follows the close, so
/// `'{"token":"X"}'` becomes `'{"token":"<redacted>"}'` rather than losing its tail.
/// The value is read as the shell reads a word: `\"` inside `"..."` and `\'` inside
/// `$'...'` do not close it, and a part glued on after the close (`'a'\ X`, `'a'X`,
/// `"a"'b c'`) is more of the secret (see [`redact_word_tail`]). An escaped-JSON value
/// (`\"X\"`, inside a double-quoted body) closes at the next `\"`.
///
/// `outer` is the quote state at the value's start (`'password=X'` starts inside `'`):
/// an unquoted value then runs to that quote's close, which is kept. Returns the
/// rendering and the quote state at the end of the token.
fn redact_value_keeping_quotes(v: &str, outer: Option<Close>) -> (String, Option<Close>) {
    if let Some(body) = v.strip_prefix("\\\"") {
        return match body.find("\\\"") {
            Some(j) => {
                let rest = &body[j + 2..];
                (format!("\\\"<redacted>\\\"{rest}"), quote_state_after(outer, rest))
            }
            None => ("\\\"<redacted>".to_string(), outer),
        };
    }
    if let Some((c, n)) = opener(v.as_bytes()) {
        return match find_close(&v[n..], c) {
            Some(j) => {
                let (tail, st) = redact_word_tail(&v[n + j + 1..], outer);
                (format!("{}<redacted>{}{tail}", &v[..n], c.quote_char()), st)
            }
            None => (format!("{}<redacted>", &v[..n]), Some(c)),
        };
    }
    match outer {
        // Inside the quote the token opened: the value is its content, up to the close.
        Some(o) => match find_close(v, o) {
            // The close ends the quoted part, not the word: an unquoted run glued on
            // after it (`"Authorization: Bearer"X`) is more of the same shell word.
            Some(j)
                if v[j + 1..]
                    .bytes()
                    .next()
                    .is_some_and(|c| !word_terminator(c) && c != b'"' && c != b'\'') =>
            {
                let (tail, st) = redact_word_tail(&v[j + 1..], None);
                (format!("<redacted>{}{tail}", o.quote_char()), st)
            }
            Some(j) => (format!("<redacted>{}", &v[j..]), quote_state_after(outer, &v[j..])),
            None => ("<redacted>".to_string(), outer),
        },
        None => {
            let b = v.as_bytes();
            let mut i = 0;
            while i < b.len() && opener(&b[i..]).is_none() {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            if i >= b.len() {
                return ("<redacted>".to_string(), None);
            }
            let (tail, st) = redact_word_tail(&v[i..], None);
            (format!("<redacted>{tail}"), st)
        }
    }
}

/// Redact a whole token that sits in value position, keeping a leading quote pair or
/// trailing closers (`X"`, `X"),`) so the surrounding syntax still reads.
fn redact_bare_value(tok: &str) -> String {
    redact_bare_value_quoted(tok).0
}

/// [`redact_bare_value`] and the quote state at the end of the token (`"a b"` opens
/// at `"a`; `X"` closes a quote opened earlier).
fn redact_bare_value_quoted(tok: &str) -> (String, Option<Close>) {
    if opener(tok.as_bytes()).is_some() || tok.starts_with("\\\"") {
        return redact_value_keeping_quotes(tok, None);
    }
    let b = tok.as_bytes();
    let mut i = 0;
    while i < b.len() && opener(&b[i..]).is_none() {
        i += if b[i] == b'\\' { 2 } else { 1 };
    }
    if i < b.len() {
        // `a"b c"` opens a quote; `X")` keeps the closers of an earlier word.
        let (tail, st) = redact_word_tail(&tok[i..], None);
        return (format!("<redacted>{tail}"), st);
    }
    let core = tok.trim_end_matches(['"', '\'', ')', ']', '}', ',', ';']);
    (format!("<redacted>{}", &tok[core.len()..]), None)
}

/// The header name of an Authorization header pair's key, also as the tail of a
/// `--header=` / quoted word (`--header=Authorization`, `-H"Authorization`).
fn is_authorization_pair_key(k: &str) -> bool {
    is_authorization_key(k) || k.rsplit(['=', '"', '\'']).next().is_some_and(is_authorization_key)
}

/// `Bearer\ X`, `\ token\ X`: an Authorization scheme word joined to its credential by
/// escaped whitespace (one shell word). The byte length of the part to keep (leading
/// escaped spaces, the scheme word, the escaped spaces after it) and the scheme word.
fn escaped_scheme_head(v: &str) -> Option<(usize, &str)> {
    let b = v.as_bytes();
    let esc_ws = |i: usize| b.get(i) == Some(&b'\\') && b.get(i + 1).is_some_and(|c| matches!(c, b' ' | b'\t'));
    let mut i = 0;
    while esc_ws(i) {
        i += 2;
    }
    let w = i;
    while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'-') {
        i += 1;
    }
    let scheme = &v[w..i];
    if !is_scheme_word(scheme) || !esc_ws(i) {
        return None;
    }
    while esc_ws(i) {
        i += 2;
    }
    Some((i, scheme))
}

/// One separator-free segment: a URL, a `user:pass@host`, or a `key=value` pair.
/// Returns the rendering and, if a secret value opened a quote it did not close, that
/// quote (the tokens up to the closing quote are the rest of the secret).
fn redact_segment(seg: &str, outer: Option<Close>) -> (String, Option<Close>) {
    if let Some(sc) = seg.find("://")
        && !seg[..sc].contains(['=', ':'])
    {
        return (redact_url(seg), None);
    }
    // Userinfo first; the pair rule below then runs on what is left. It used to return
    // here, so `:D@auth:/` gave `<redacted>@auth:/` and a second pass read that as the
    // secret-named key `<redacted>@auth` and redacted `/` (fuzz_redact_secrets found it:
    // redaction was not idempotent). Running the pair rule on the redacted form gives the
    // fixed point in one pass, and `u:p@token=X` no longer keeps X.
    let userinfo = redact_userinfo(seg);
    let seg = userinfo.as_str();
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
        let outer = quote_state_after(outer, &seg[..k.len() + 1]);
        // `Authorization:Bearer\ X` (one shell word): the scheme stays, the credential goes.
        if is_authorization_pair_key(k)
            && let Some((head, _)) = escaped_scheme_head(v)
        {
            let rest = &v[head..];
            if rest.is_empty() || rest.starts_with("<redacted>") {
                return (seg.to_string(), None);
            }
            let (shown, st) = redact_value_keeping_quotes(rest, outer);
            return (format!("{k}{sep}{}{shown}", &v[..head]), st);
        }
        let (shown, st) = redact_value_keeping_quotes(v, outer);
        return (format!("{k}{sep}{shown}"), st);
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
    in_curl: bool,
) -> (String, Pending) {
    // A redirection between a secret flag and its value (`--with-token <<< TOKEN`,
    // `--password < file`) is the shell's operator, not the credential: it is kept and the
    // redaction owed carries on to the next word.
    let redirection = matches!(tok, "<<<" | "<" | "<<" | "<<-");
    match pending {
        Pending::One if redirection => return (tok.to_string(), Pending::One),
        Pending::One => {
            let (shown, st) = redact_bare_value_quoted(tok);
            return (shown, st.map_or(Pending::None, Pending::Quote));
        }
        // Inside a quoted secret: this token is more of it, until the quote closes (an
        // escaped `\"` does not close a double quote), and a part glued on after the
        // close (`b'\ X`) is more of it too.
        Pending::Quote(q) => {
            return match find_close(tok, q) {
                Some(close) => {
                    let (tail, st) = redact_word_tail(&tok[close + 1..], None);
                    (
                        format!("<redacted>{}{tail}", q.quote_char()),
                        st.map_or(Pending::None, Pending::Quote),
                    )
                }
                None => ("<redacted>".to_string(), Pending::Quote(q)),
            };
        }
        Pending::Line => return (redact_bare_value(tok), Pending::Line),
        Pending::None => {}
    }
    // A Cookie header's whole value: up to the quote that opened the header word, or to
    // the end of the line when nothing quoted it (an exec-form argv element).
    if let Some((end, quote)) = cookie_header(tok) {
        let (head, value) = tok.split_at(end);
        let done = value.is_empty() || value == "<redacted>";
        return match quote {
            Some(q) => match find_close(value, q) {
                Some(0) => (tok.to_string(), Pending::None),
                Some(close) => (format!("{head}<redacted>{}", &value[close..]), Pending::None),
                None if done => (tok.to_string(), Pending::Quote(q)),
                None => (format!("{head}<redacted>"), Pending::Quote(q)),
            },
            None if value.is_empty() => (tok.to_string(), Pending::Line),
            None if value == "<redacted>" => (tok.to_string(), Pending::None),
            // `Cookie:a=1;` continues with the next cookie; `Cookie:a=1` was the whole word.
            None if value.ends_with(';') => (format!("{head}<redacted>"), Pending::Line),
            None => (format!("{head}<redacted>"), Pending::None),
        };
    }
    // `Authorization: token X`: the scheme word stays visible, the credential goes.
    // Only when a real Authorization header precedes it and a value follows; the word
    // `token` in `gh auth token` is just a word. When the header word opened a quote
    // (`-H "Authorization: Bearer a b"`, `"Authorization: Bearer \"a b\""`), the
    // credential is every word up to that quote's close, not just the next one.
    if is_scheme_word(tok) {
        let after_auth = prev.is_some_and(is_authorization_marker);
        let has_value = next.is_some_and(|n| !n.starts_with('-') && !n.contains("://"));
        let owed = match prev.and_then(|p| quote_state_after(None, p)) {
            Some(q) => Pending::Quote(q),
            None => Pending::One,
        };
        return (
            tok.to_string(),
            if after_auth && has_value { owed } else { Pending::None },
        );
    }
    // `Authorization: Bearer\ X` / a bare `Bearer\ X`: one shell word holding the scheme
    // and the credential. The scheme stays, the rest goes.
    if let Some((head, scheme)) = escaped_scheme_head(tok)
        && (prev.is_some_and(is_authorization_marker)
            || scheme.eq_ignore_ascii_case("bearer")
            || scheme.eq_ignore_ascii_case("basic"))
    {
        let rest = &tok[head..];
        if rest.is_empty() || rest.starts_with("<redacted>") {
            return (tok.to_string(), Pending::None);
        }
        let (shown, st) = redact_bare_value_quoted(rest);
        return (
            format!("{}{shown}", &tok[..head]),
            st.map_or(Pending::None, Pending::Quote),
        );
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
        if redirection {
            return (tok.to_string(), Pending::One);
        }
        // A marker word that opened a quote (`-H "X-Api-Key: a\" b"`) puts this value
        // inside it: the value runs to that quote's close, and `\"` does not close it.
        let outer = prev.and_then(|p| quote_state_after(None, p));
        let (shown, q) = match outer {
            Some(_) if opener(tok.as_bytes()).is_none() && !tok.starts_with("\\\"") => {
                redact_value_keeping_quotes(tok, outer)
            }
            _ => redact_bare_value_quoted(tok),
        };
        return (shown, q.map_or(Pending::None, Pending::Quote));
    }
    // A cookie string after curl's `-b` / `--cookie` (`-b session=X`, `--cookie "sid=X;
    // b=Y"`, `--cookie=sid=X`): every cookie value is a credential. A value with no `=`
    // is a cookie FILE (`-b cookies.txt`) and is kept.
    let cookie_value = match prev {
        Some("--cookie") if tok.contains('=') => Some((0, tok)),
        Some("-b") if in_curl && tok.contains('=') => Some((0, tok)),
        _ => tok
            .strip_prefix("--cookie=")
            .filter(|v| v.contains('='))
            .map(|v| (9, v)),
    };
    if let Some((at, value)) = cookie_value {
        let q = opener(value.as_bytes()).map(|(c, _)| c);
        let eq = value.find('=').unwrap_or(0);
        let head = &tok[..at + eq + 1];
        let rest = &value[eq + 1..];
        if rest.is_empty() || rest.starts_with("<redacted>") {
            return (tok.to_string(), Pending::None);
        }
        return match q {
            Some(c) => match find_close(rest, c) {
                Some(j) => (format!("{head}<redacted>{}", &rest[j..]), Pending::None),
                None => (format!("{head}<redacted>"), Pending::Quote(c)),
            },
            None => (format!("{head}<redacted>"), Pending::None),
        };
    }
    // curl's client certificate with its pass phrase: `-E cert.pem:X`, `--cert c:X`
    // (curl: `<certificate[:password]>`). The certificate name stays; a drive letter
    // (`C:\\c.pem`) is not the separator.
    let cert_value = match prev {
        Some("--cert" | "--proxy-cert") => Some((0, tok)),
        Some("-E") if in_curl => Some((0, tok)),
        _ => tok
            .strip_prefix("--cert=")
            .map(|v| (7, v))
            .or_else(|| tok.strip_prefix("--proxy-cert=").map(|v| (13, v))),
    };
    if let Some((at, value)) = cert_value {
        let core = value.trim_start_matches(['"', '\'']);
        let lead = value.len() - core.len();
        let skip = if core.len() > 2 && core.as_bytes()[1] == b':' && core.as_bytes()[0].is_ascii_alphabetic() {
            2
        } else {
            0
        };
        if let Some(c) = core[skip..].find(':') {
            let cut = at + lead + skip + c + 1;
            let rest = &tok[cut..];
            if !rest.is_empty() && !rest.starts_with("<redacted>") {
                let (shown, st) = redact_bare_value_quoted(rest);
                return (
                    format!("{}{shown}", &tok[..cut]),
                    st.map_or(Pending::None, Pending::Quote),
                );
            }
        }
    }
    // curl's `-u` with the credentials attached: `-uuser:pw`, `-Uproxyuser:pw`.
    if (tok.starts_with("-u") || tok.starts_with("-U"))
        && !tok.starts_with("--")
        && let Some((u, pw)) = tok[2..].split_once(':')
        && !u.is_empty()
        && !pw.is_empty()
        && !pw.starts_with("<redacted>")
    {
        return (format!("{}{u}:<redacted>", &tok[..2]), Pending::None);
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
    // Pairs are counted and recognised on the RENDERED segments: the userinfo rule turns
    // the pair `x:y@h` into the non-pair `<redacted>@h`, and judging the raw segment let
    // a second pass absorb what the first had kept (redaction was not idempotent).
    // Each segment starts in the quote state the token reached before it (`'password=X'`
    // starts inside `'`).
    // An ODBC / ADO.NET connection string (`Driver={x};Server=s;Uid=u;Pwd=X;`): `Pwd` is
    // its password key, though alone `PWD` is the working directory and not a secret name.
    let conn = tok.contains(';') && tok.matches('=').count() >= 2;
    let conn_pwd = |k: &str| conn && bare_key(k).eq_ignore_ascii_case("pwd");
    let rendered: Vec<(String, Option<Close>)> = segs
        .iter()
        .map(|(sg, _)| {
            let at = sg.as_ptr() as usize - tok.as_ptr() as usize;
            let outer = quote_state_after(None, &tok[..at]);
            match sg.split_once('=') {
                Some((k, v)) if conn_pwd(k) && !v.is_empty() && !v.starts_with("<redacted>") => {
                    let o = quote_state_after(outer, &sg[..k.len() + 1]);
                    let (shown, st) = redact_value_keeping_quotes(v, o);
                    (format!("{k}={shown}"), st)
                }
                _ => redact_segment(sg, outer),
            }
        })
        .collect();
    let pairs = rendered
        .iter()
        .filter(|(sg, _)| split_pair(sg).is_some_and(|(_, _, v)| !v.is_empty()))
        .count();
    let mut out = String::with_capacity(tok.len());
    let mut absorb = false;
    let mut prev_sep: Option<char> = None;
    let mut opened: Option<Close> = None;
    for ((seg, sep_after), (shown, q)) in segs.into_iter().zip(rendered) {
        let pair = split_pair(&shown);
        // After ';' in a single-pair token, a path-like or command-like segment is the
        // next shell command, not more of the secret.
        let shell_command_position = prev_sep == Some(';') && pairs < 2 && looks_like_command(seg);
        if absorb && pair.is_none() && !seg.is_empty() && !shell_command_position {
            out.push_str("<redacted>");
        } else {
            out.push_str(&shown);
            opened = q;
            absorb = pair.is_some_and(|(k, _, v)| !v.is_empty() && (is_secret_key(k) || conn_pwd(k)));
        }
        if let Some(c) = sep_after {
            out.push(c);
        }
        prev_sep = sep_after;
    }
    // `'password=my secret'`: the quote opened BEFORE the key, so the value's own check
    // never saw it. If this token redacted anything and opens an unclosed quote, the
    // tokens up to the closing quote are the rest of the value.
    // The quote is read from the RENDERED token: reading `tok` let a quote that the
    // userinfo rule removed decide what the tokens after it owed.
    if opened.is_none() && out != tok {
        opened = unclosed_quote(&out);
    }
    (out, opened.map_or(Pending::None, Pending::Quote))
}

/// A segment that is plausibly the next command in a shell one-liner: a path, a
/// dot-relative script, or a common command word.
fn looks_like_command(seg: &str) -> bool {
    const COMMANDS: &[&str] = &[
        "echo", "curl", "wget", "sh", "bash", "zsh", "node", "python", "python3", "npm", "npx", "uv", "uvx", "pip",
        "git", "rm", "cd", "ls", "cat", "eval", "exec", "source", "export", "chmod", "mkdir", "touch", "nohup", "sudo",
        "env", "printf", "tee", "true", "false",
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
    let authority = after_scheme.split(['/', '?', '#', '\\']).next().unwrap_or(after_scheme);
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
    let h = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.');
    if h.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match h.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.to_canonical().is_loopback(),
        Err(_) => false,
    }
}

/// [`is_loopback_host`] for an address a CLIENT dials (a base URL, a proxy): the
/// unspecified addresses `0.0.0.0` and `::` connect to the local machine, so they are
/// loopback here. (LiteLLM's proxy quick start points every client at
/// `http://0.0.0.0:4000`.) Server-bind semantics, where they mean "every interface",
/// apply only to OLLAMA_HOST, which [`shell_configs::classify_ollama_host`] reads.
pub(crate) fn is_client_loopback_host(host: &str) -> bool {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    is_loopback_host(host)
        || h.parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.to_canonical().is_unspecified())
}

/// The account a scan is FOR: the owner of the scanned home directory, so "owned by
/// you" and "a process of yours" mean the scanned user's under `--search-dirs` or
/// `sudo`, not the scanner's. The scanner's effective uid when the home cannot be read
/// (and 0 off Unix, where nothing compares it).
pub fn home_owner_uid(home: &std::path::Path) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions and cannot fail.
        std::fs::metadata(home).map_or_else(|_| unsafe { libc::geteuid() }, |m| m.uid())
    }
    #[cfg(not(unix))]
    {
        let _ = home;
        0
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
        Some((format!("{:04o}", mode), mode & 0o004 != 0, mode & 0o040 != 0))
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

/// PATH with every entry that is not absolute removed: no empty entry, no `.`, no
/// `node_modules/.bin`. None when PATH is unset. A relative entry is resolved against
/// whatever directory the lookup happens in, and rmguard runs git with its working
/// directory inside repositories it is inspecting (on Linux the child chdirs before it
/// searches PATH), so a relative entry would find the repository's own `git`.
pub fn absolute_path_entries() -> Option<std::ffi::OsString> {
    let path = std::env::var_os("PATH")?;
    let kept: Vec<std::path::PathBuf> = std::env::split_paths(&path).filter(|p| p.is_absolute()).collect();
    std::env::join_paths(kept).ok()
}

/// The absolute path of the `git` rmguard runs, found once per process in the absolute
/// PATH entries only ([`absolute_path_entries`]). None when no absolute entry holds an
/// executable `git`; every git spawn then fails and its answer is "unknown".
pub fn git_program() -> Option<&'static std::path::Path> {
    static GIT: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();
    GIT.get_or_init(|| {
        let path = absolute_path_entries()?;
        let names: &[&str] = if cfg!(windows) {
            &["git.exe", "git.cmd", "git.bat"]
        } else {
            &["git"]
        };
        std::env::split_paths(&path).find_map(|dir| names.iter().map(|n| dir.join(n)).find(|c| is_executable_file(c)))
    })
    .as_deref()
}

#[cfg(unix)]
fn is_executable_file(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable_file(p: &std::path::Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.is_file())
}

/// A `git` command by absolute path ([`git_program`]) whose PATH holds only absolute
/// entries, so neither rmguard's own lookup nor any program git (or a git wrapper)
/// starts in turn can resolve to a binary in the directory it runs in. With no git
/// found the program is a path that cannot exist, so the spawn fails cleanly.
pub fn git_command() -> std::process::Command {
    let program = git_program().map_or_else(
        || std::path::PathBuf::from("/nonexistent/rmguard-no-git"),
        std::path::Path::to_path_buf,
    );
    let mut cmd = child_command(program);
    match absolute_path_entries() {
        Some(p) => cmd.env("PATH", p),
        None => cmd.env_remove("PATH"),
    };
    cmd
}

/// The only directories a system tool (`ps`, `ssh-keygen`, `sw_vers`, `defaults`) is run
/// from, in this order. They are root-owned on every supported system (SIP-protected on
/// macOS; `/run/current-system/sw/bin` is NixOS's system profile), so neither the
/// user's PATH nor the directory a scan runs in can put a program of that name in front
/// of the real one. `hostname` and `uname` are not run at all: `uname(2)` answers both.
pub const SYSTEM_TOOL_DIRS: &[&str] = &["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/run/current-system/sw/bin"];

/// The absolute path of system tool `name` in [`SYSTEM_TOOL_DIRS`], or None. Debug
/// builds first try `RMGUARD_TEST_SYSTEM_TOOL_DIR` (like `RMGUARD_TEST_SYSTEM_ROOT`), so
/// the end-to-end tests can stand a recording `ps` in for the real one; release builds
/// never read it.
pub fn system_tool_path(name: &str) -> Option<std::path::PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(dir) = std::env::var_os("RMGUARD_TEST_SYSTEM_TOOL_DIR").filter(|d| !d.is_empty()) {
        let p = std::path::PathBuf::from(dir).join(name);
        if is_executable_file(&p) {
            return Some(p);
        }
    }
    SYSTEM_TOOL_DIRS
        .iter()
        .map(|d| std::path::Path::new(d).join(name))
        .find(|p| is_executable_file(p))
}

/// A [`child_command`] for system tool `name` by absolute path ([`system_tool_path`]),
/// whose own PATH is [`SYSTEM_TOOL_DIRS`]. With no such tool the program is a path that
/// cannot exist, so the spawn fails cleanly and the answer is "unknown". Run it through
/// [`output_with_timeout`] (or the crate-internal variant with a site name) so it has a
/// deadline and an exec span.
pub fn system_command(name: &str) -> std::process::Command {
    let program =
        system_tool_path(name).unwrap_or_else(|| std::path::PathBuf::from(format!("/nonexistent/rmguard-no-{name}")));
    let mut cmd = child_command(program);
    cmd.env("PATH", SYSTEM_TOOL_DIRS.join(":"));
    cmd
}

/// A `git` command that cannot be turned against the scanner by the repository it runs
/// in. rmguard runs git inside project directories it does not trust — that is the
/// GitSpawn shape it catalogues (Codex CVE-2026-19592, goose CVE-2026-72718, Claude Code
/// <2.1.196): a repo-local `core.fsmonitor`, `core.hooksPath` or a nested bare repo turns
/// the scan's own git call into code execution. Every working-tree git invocation goes
/// through here. `-c` overrides repository config; the environment scrub stops an
/// inherited GIT_DIR/GIT_WORK_TREE from redirecting the command elsewhere. Reading
/// config (`git config --list`) does not go through this, since the `-c` values would
/// appear in its own output. The program is [`git_command`]'s absolute path: `-c`
/// overrides are no help when the binary itself is the repository's (`PATH=.:...`).
pub fn hardened_git() -> std::process::Command {
    let mut cmd = git_command();
    cmd.args([
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "safe.bareRepository=explicit",
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

/// Every file a git config pulls in through `[include]` / `[includeIf]`, followed
/// transitively the way git does (each path relative to the file that names it), at
/// most 8 levels and 64 files. A nested include of a FIFO blocks git like a direct one.
fn config_include_closure(config: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out: Vec<std::path::PathBuf> = Vec::new();
    let mut frontier = vec![config.to_path_buf()];
    for _ in 0..8 {
        let mut next = Vec::new();
        for f in &frontier {
            // A non-regular include is reported by the caller; it is never opened here.
            if not_regular_quiet(f) {
                continue;
            }
            for p in config_include_paths(f) {
                if out.len() >= 64 {
                    return out;
                }
                if !out.contains(&p) && p != config {
                    out.push(p.clone());
                    next.push(p);
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    out
}

/// [`not_regular`] without the telemetry note (the closure walk checks before reading).
fn not_regular_quiet(p: &std::path::Path) -> bool {
    match std::fs::symlink_metadata(p) {
        Err(_) => false,
        Ok(m) if m.is_file() => false,
        Ok(m) if m.file_type().is_symlink() => !std::fs::metadata(p).is_ok_and(|t| t.is_file()),
        Ok(_) => true,
    }
}

/// `[include]` / `[includeIf ...]` `path = X` values in a git config file. Bounded
/// read, no symlink at the final component; values are resolved relative to the
/// config's directory (`~/` against HOME).
fn config_include_paths(config: &std::path::Path) -> Vec<std::path::PathBuf> {
    let Some(text) = read_bounded_nofollow(config, None) else {
        return Vec::new();
    };
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
        ["HEAD", "index", "config", "commondir", "config.worktree"]
            .iter()
            .any(|f| not_regular(&d.join(f)))
            || ["config", "config.worktree"]
                .iter()
                .any(|c| config_include_closure(&d.join(c)).iter().any(|p| not_regular(p)))
            || shared_index_unsafe(d)
    })
}

/// A split index (`core.splitIndex`) names a `sharedindex.<sha>` file that git opens
/// beside the index; one that is not a regular file blocks it the same way.
fn shared_index_unsafe(git_dir: &std::path::Path) -> bool {
    let Ok(entries) = std::fs::read_dir(git_dir) else {
        return false;
    };
    entries
        .flatten()
        .take(4096)
        .filter(|e| e.file_name().to_str().is_some_and(|n| n.starts_with("sharedindex.")))
        .any(|e| not_regular(&e.path()))
}

/// The repository root governing `path`: the nearest ancestor of its directory holding
/// a `.git` entry (directory or `gitdir:` file).
fn repo_root_of(path: &std::path::Path) -> Option<std::path::PathBuf> {
    let start = path.parent().unwrap_or(path);
    start
        .ancestors()
        .find(|d| std::fs::symlink_metadata(d.join(".git")).is_ok())
        .map(|d| d.to_path_buf())
}

/// One repository's tracked paths (root-relative bytes, sorted), or None = unknown.
type TrackedSet = Option<std::collections::BTreeSet<Vec<u8>>>;

/// One repository's listing, filled once, with what filling it read
/// ([`telemetry::SharedCost`]), charged to the first scanner in the fixed order that asked.
type TrackedCell = std::sync::Arc<std::sync::OnceLock<(TrackedSet, std::sync::Arc<telemetry::SharedCost>)>>;

struct GitTrackCache {
    repos: std::collections::HashMap<std::path::PathBuf, TrackedCell>,
    /// Time taken by finished listings.
    spent: std::time::Duration,
    /// Allowances of listings running now.
    reserved: std::time::Duration,
}

static GIT_TRACK_CACHE: std::sync::Mutex<Option<GitTrackCache>> = std::sync::Mutex::new(None);
/// Signalled when a running listing gives its allowance back.
static GIT_TRACK_RELEASED: std::sync::Condvar = std::sync::Condvar::new();

/// List a repository's index once: `git ls-files -z` through [`hardened_git`], under the
/// per-call timeout and the scan's remaining budget.
fn list_tracked(root: &std::path::Path) -> TrackedSet {
    if git_dir_unsafe_to_spawn(&root.join(".git")) {
        return None;
    }
    // The listing's whole allowance is reserved from the budget before the spawn and
    // the time actually taken charged after it, so listings of different repositories
    // running at the same time (`--jobs`) cannot together run past the budget. A listing
    // whose allowance does not fit beside the running ones WAITS for one to finish rather
    // than being refused: refused, its repository was "unknown" for the whole scan only
    // because five listings happened to overlap (every row of it reported untracked at
    // --jobs 6, tracked at --jobs 1). Only time actually spent ends the budget, so the
    // answer is the one the one-at-a-time loop gives.
    let allowed = {
        let mut guard = GIT_TRACK_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            let cache = guard.get_or_insert_with(|| GitTrackCache {
                repos: Default::default(),
                spent: Default::default(),
                reserved: Default::default(),
            });
            let want = GIT_TRACKED_TIMEOUT.min(GIT_TRACKED_BUDGET.saturating_sub(cache.spent));
            if want.is_zero() || cache.spent + cache.reserved + want <= GIT_TRACKED_BUDGET {
                cache.reserved += want;
                break want;
            }
            guard = GIT_TRACK_RELEASED.wait(guard).unwrap_or_else(|e| e.into_inner());
        }
    };
    if allowed.is_zero() {
        telemetry::note_read(root, "git budget spent");
        return None;
    }
    let started = std::time::Instant::now();
    let mut cmd = hardened_git();
    cmd.args(["ls-files", "-z"]).current_dir(root);
    let out = output_with_timeout_capped(&mut cmd, allowed, "git_tracked", GIT_LS_FILES_MAX);
    {
        let mut guard = GIT_TRACK_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = guard.as_mut() {
            c.reserved = c.reserved.saturating_sub(allowed);
            c.spent += started.elapsed();
        }
        GIT_TRACK_RELEASED.notify_all();
    }
    let out = out.filter(|o| o.status.success())?;
    Some(
        out.stdout
            .split(|b| *b == 0)
            .filter(|p| !p.is_empty())
            .map(<[u8]>::to_vec)
            .collect(),
    )
}

/// Whether `path` is tracked by git: `Some(true|false)`, or None when that cannot be
/// answered (no spawn in a repository whose git directory holds a FIFO or other
/// non-file, a listing that timed out or ran past its output cap, or the scan's git
/// budget spent). Each repository is listed once per scan (`git ls-files -z` through
/// [`hardened_git`], stdin closed, killed on timeout) and every later question about
/// it is answered from that listing, so a repository built to stall git costs one
/// timeout, not one per file. A path outside any repository is `Some(false)`. A
/// directory counts as tracked when a file under it is.
///
/// Safe to call from scanners running at the same time: the map is behind a mutex and
/// each repository's listing is a `OnceLock`, so a second scanner asking about a
/// repository being listed waits for that one listing and gets the same answer. The
/// reads the listing makes are charged to the first scanner in the fixed order that
/// asked ([`telemetry::SharedCost`]).
pub fn git_tracked_state(path: &std::path::Path) -> Option<bool> {
    let Some(root) = repo_root_of(path) else {
        return Some(false);
    };
    let cell = {
        let mut guard = GIT_TRACK_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        let cache = guard.get_or_insert_with(|| GitTrackCache {
            repos: Default::default(),
            spent: Default::default(),
            reserved: Default::default(),
        });
        cache.repos.entry(root.clone()).or_default().clone()
    };
    let (set, cost) = cell.get_or_init(|| telemetry::shared_fill(|| list_tracked(&root)));
    telemetry::touch_shared(cost);
    let set = set.as_ref()?;
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
    Some(
        set.range(prefix.clone()..)
            .next()
            .is_some_and(|p| p.starts_with(&prefix)),
    )
}

/// [`git_tracked_state`], with "unknown" answered as not tracked.
pub fn is_git_tracked(path: &std::path::Path) -> bool {
    git_tracked_state(path).unwrap_or(false)
}

/// The root of the git work tree governing `path` (the nearest ancestor of its directory
/// holding a `.git` entry), or None outside any repository. Lexical: nothing is spawned.
pub(crate) fn git_work_tree_of(path: &std::path::Path) -> Option<std::path::PathBuf> {
    repo_root_of(path)
}

/// Whether git ignores `path` (a file inside a work tree): `git check-ignore -q -- <path>`
/// through [`hardened_git`] in the work tree root, stdin closed, output capped, killed after
/// [`GIT_TRACKED_TIMEOUT`]. Exit 0 is ignored, 1 is not; anything else (a timeout, a
/// repository whose git directory is unsafe to spawn in, an error) is None. git answers
/// for every ignore source (`.gitignore` files, `.git/info/exclude`, `core.excludesFile`).
pub(crate) fn git_check_ignored(path: &std::path::Path) -> Option<bool> {
    let root = repo_root_of(path)?;
    if git_dir_unsafe_to_spawn(&root.join(".git")) {
        return None;
    }
    let rel = path.strip_prefix(&root).ok()?;
    let mut cmd = hardened_git();
    cmd.args(["check-ignore", "-q", "--"]).arg(rel).current_dir(&root);
    let out = output_with_timeout_capped(&mut cmd, GIT_TRACKED_TIMEOUT, "git_check_ignore", 4096)?;
    match out.status.code() {
        Some(0) => Some(true),
        Some(1) => Some(false),
        _ => None,
    }
}

/// Compute SHA-256 hash of content, returning hex string.
pub fn sha256_hex(content: &str) -> String {
    use sha2::{Digest, Sha256};
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
            sanitize_display(&path.display().to_string(), 512),
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
pub fn open_regular_nofollow(path: &std::path::Path, expect: Option<&std::path::Path>) -> Option<(std::fs::File, u64)> {
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

/// The real path of a repository file whose real path stays inside its project.
/// `root` is the project's containment root
/// ([`crate::scanners::skills::project_containment_root`]: the enclosing work tree, never
/// HOME or above it). A file reached through a committed symlink, at the file or at any
/// directory below `root`, whose real path leaves `root` is refused: never opened, never
/// parsed into the report. A link that stays in the project (`CLAUDE.md -> AGENTS.md`, a
/// pnpm `node_modules/x -> .pnpm/x@1/node_modules/x`) is followed, unless it lands on a
/// credential, key or agent-config path (a project that is the home itself).
pub fn contained_real_path(path: &std::path::Path, root: &std::path::Path) -> Option<std::path::PathBuf> {
    let Ok(real) = std::fs::canonicalize(path) else {
        telemetry::note_read(path, "missing");
        return None;
    };
    let real_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    if !real.starts_with(&real_root) {
        telemetry::note_read(path, "refused (real path leaves the project)");
        return None;
    }
    let lexical = path.strip_prefix(root).ok().map(|rel| real_root.join(rel));
    if lexical.as_deref() != Some(real.as_path()) && redirected_to_sensitive(&real) {
        telemetry::note_read(path, "refused (link to a sensitive path)");
        return None;
    }
    Some(real)
}

/// A link's resolved target is a credential, key or agent-config file of this user.
fn redirected_to_sensitive(real: &std::path::Path) -> bool {
    use crate::scanners::persistence::{is_agent_credential_path, is_sensitive_read_name, is_sensitive_read_target};
    if is_sensitive_read_name(real) || is_agent_credential_path(real, None) {
        return true;
    }
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .map(|h| std::fs::canonicalize(&h).unwrap_or(h))
        .is_some_and(|h| real.starts_with(&h) && is_sensitive_read_target(real, &h))
}

/// [`read_bounded`] for a repository file: read only when its real path stays inside the
/// project ([`contained_real_path`]), opened by that real path without following a link.
pub fn read_bounded_within(path: &std::path::Path, root: &std::path::Path) -> Option<String> {
    use std::io::Read;
    let real = contained_real_path(path, root)?;
    let Some((file, len)) = open_regular_nofollow(&real, Some(&real)) else {
        telemetry::note_read(path, "refused (symlink or not a regular file)");
        return None;
    };
    if len > MAX_CONFIG_SIZE {
        telemetry::note_read(path, "too large");
        eprintln!(
            "warning: skipping {} ({} bytes exceeds {} byte limit)",
            sanitize_display(&path.display().to_string(), 512),
            len,
            MAX_CONFIG_SIZE
        );
        return None;
    }
    let mut buf = String::new();
    if file.take(MAX_CONFIG_SIZE).read_to_string(&mut buf).is_err() {
        telemetry::note_read(path, "unreadable");
        return None;
    }
    telemetry::note_read(path, "ok");
    Some(buf)
}

/// [`read_head_bytes`] for a repository file ([`contained_real_path`]).
pub fn read_head_bytes_within(path: &std::path::Path, root: &std::path::Path, max_bytes: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let real = contained_real_path(path, root)?;
    let Some((file, _)) = open_regular_nofollow(&real, Some(&real)) else {
        telemetry::note_read(path, "refused (symlink or not a regular file)");
        return None;
    };
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
            if port.chars().all(|c| c.is_ascii_digit()) {
                h
            } else {
                host_port
            }
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
///
/// A path that exists but is not a regular file (a directory met while listing a
/// directory's entries, a socket) is traced as "not a regular file" and NOT counted as
/// missing: it was there, it is just not what a file probe reads. Counting it as missing
/// inflated `files_missing` (every subdirectory of `~/.claude` — `paste-cache`,
/// `shell-snapshots`, `plans`, ... — was a "missing file" of the persistence scanner's
/// loader-staging listing).
pub fn probe_file(path: &std::path::Path) -> bool {
    probe_kind(path, std::fs::Metadata::is_file, "not a regular file")
}

/// `path.is_dir()` that the diagnostics can see: a `false` counts as a looked-for path
/// that was not there, unless something else (a file) is there, which is traced as "not a
/// directory" and not counted. See [`probe_file`].
pub fn probe_dir(path: &std::path::Path) -> bool {
    probe_kind(path, std::fs::Metadata::is_dir, "not a directory")
}

/// One stat (following symlinks, like `is_file`/`is_dir`): present when `want` holds,
/// missing when nothing (or a dangling link) is there, and neither when something of
/// another type is there.
fn probe_kind(path: &std::path::Path, want: fn(&std::fs::Metadata) -> bool, other: &str) -> bool {
    match std::fs::metadata(path) {
        Ok(m) if want(&m) => {
            telemetry::note_probe(path, true);
            true
        }
        Ok(_) => {
            telemetry::note_probe_other(path, other);
            false
        }
        Err(_) => {
            telemetry::note_probe(path, false);
            false
        }
    }
}

/// `fs::read_dir` that the diagnostics can see: a directory that exists but cannot be
/// listed (mode 0100, an I/O error) was a silent `return` and read as "no inputs"; it is
/// a miss now, and traced.
pub fn probe_read_dir<P: AsRef<std::path::Path>>(path: P) -> std::io::Result<std::fs::ReadDir> {
    let r = std::fs::read_dir(path.as_ref());
    if let Err(e) = &r {
        note_read_dir_error(path.as_ref(), e);
    }
    r
}

/// What [`probe_read_dir`] notes for a directory that could not be listed: a missing
/// path, and the error under `--trace`. For a walk whose listings were read by a
/// [`prefetch`] helper, noted when the walk consumes the listing.
pub(crate) fn note_read_dir_error(path: &std::path::Path, e: &std::io::Error) {
    telemetry::note_probe(path, false);
    if telemetry::trace_enabled() {
        eprintln!(
            "trace: read_dir {} -> {e}",
            sanitize_display(&path.display().to_string(), 512)
        );
    }
}

pub fn probe_exists(path: &std::path::Path) -> bool {
    let present = path.exists();
    telemetry::note_probe(path, present);
    present
}

/// Scan telemetry. Answers the one question a silent scanner never could: did it look?
///
/// Counters are per scanner run, not process-global: [`timed`] gives each scanner its own
/// [`ScannerScope`] on the thread it runs on (scanners run side by side under `--jobs`),
/// and helper threads carry it ([`par_map`], [`ScopeHandle::enter`]), so attribution
/// stays right when scanning is parallel. Only the trace switch is process-wide.
pub mod telemetry {
    use crate::models::ScannerStat;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::time::Instant;

    static TRACE: AtomicBool = AtomicBool::new(false);

    /// The state one scanner run owns: its read counters, whether it stopped at a
    /// budget, and its hook and probe budget. [`timed`] gives every scanner a fresh one
    /// on the thread it runs on, so scanners running side by side on worker threads
    /// (`--jobs`) never count each other's reads or spend each other's budget. A thread
    /// outside any [`timed`] call (a unit test calling a scanner directly) has its own.
    ///
    /// The counters are atomics behind an `Arc` so that a scanner that hands work to a
    /// helper thread carries its scope there ([`current_scope`], [`ScopeHandle::enter`];
    /// [`par_map`] does it for every helper): the gitconfig project walks and the skills
    /// file reads.
    #[derive(Debug)]
    pub struct ScannerScope {
        read: AtomicU64,
        missing: AtomicU64,
        truncated: AtomicBool,
        hooks_left: AtomicUsize,
        probes_left: AtomicUsize,
        /// Shared-cache fills this scanner asked for ([`touch_shared`]); their reads are
        /// charged to it at [`Pending::finalize`] unless an earlier scanner claimed them.
        touched: std::sync::Mutex<Vec<Arc<SharedCost>>>,
    }

    impl Default for ScannerScope {
        fn default() -> Self {
            use super::hook_sources::{MAX_HOOKS_PER_SCAN, MAX_PROBED_PER_SCAN};
            ScannerScope {
                read: AtomicU64::new(0),
                missing: AtomicU64::new(0),
                truncated: AtomicBool::new(false),
                hooks_left: AtomicUsize::new(MAX_HOOKS_PER_SCAN),
                probes_left: AtomicUsize::new(MAX_PROBED_PER_SCAN),
                touched: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl ScannerScope {
        /// Restart the hook and probe budget (the counters are untouched).
        pub(crate) fn reset_budget(&self) {
            let fresh = ScannerScope::default();
            self.hooks_left.store(fresh.hooks_left.into_inner(), Ordering::Relaxed);
            self.probes_left
                .store(fresh.probes_left.into_inner(), Ordering::Relaxed);
        }

        /// Take one from `which` (hooks or probes); false once it is spent.
        fn take(slot: &AtomicUsize) -> bool {
            slot.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_ok()
        }
        pub(crate) fn take_hook(&self) -> bool {
            Self::take(&self.hooks_left)
        }
        pub(crate) fn take_probe(&self) -> bool {
            Self::take(&self.probes_left)
        }
        pub(crate) fn hooks_left(&self) -> usize {
            self.hooks_left.load(Ordering::Relaxed)
        }
    }

    thread_local! {
        static SCOPE: std::cell::RefCell<Arc<ScannerScope>> = std::cell::RefCell::new(Arc::new(ScannerScope::default()));
    }

    /// Run `f` with the current thread's scanner scope.
    pub(crate) fn with_scope<R>(f: impl FnOnce(&ScannerScope) -> R) -> R {
        SCOPE.with(|s| f(&s.borrow()))
    }

    /// A handle on the running scanner's scope, for a helper thread that does part of
    /// that scanner's work: reads and budget spent there count for the scanner.
    #[derive(Clone)]
    pub struct ScopeHandle(Arc<ScannerScope>);

    /// The scope of the scanner running on this thread.
    pub fn current_scope() -> ScopeHandle {
        SCOPE.with(|s| ScopeHandle(s.borrow().clone()))
    }

    impl ScopeHandle {
        /// Make this the current thread's scope until the guard drops.
        pub fn enter(&self) -> ScopeGuard {
            let prev = SCOPE.with(|s| std::mem::replace(&mut *s.borrow_mut(), self.0.clone()));
            ScopeGuard { prev: Some(prev) }
        }
    }

    /// Restores the thread's previous scope on drop.
    #[must_use = "the scope is current only while the guard lives"]
    pub struct ScopeGuard {
        prev: Option<Arc<ScannerScope>>,
    }

    impl Drop for ScopeGuard {
        fn drop(&mut self) {
            if let Some(prev) = self.prev.take() {
                SCOPE.with(|s| *s.borrow_mut() = prev);
            }
        }
    }

    /// The reads one fill of a cache shared by several scanners made (the git-tracked
    /// listing of one repository). Sequentially, they were counted for whichever scanner
    /// asked first, in the fixed scanner order. Scanners running side by side ask in
    /// whatever order the threads take, so the fill's reads are counted apart
    /// ([`shared_fill`]) and charged, when rows are finalized in the fixed order, to the
    /// first scanner that asked for it ([`touch_shared`]): the row is the one the
    /// sequential run gave, whichever thread did the fill.
    #[derive(Debug, Default)]
    pub struct SharedCost {
        read: u64,
        missing: u64,
        claimed: AtomicBool,
    }

    /// Run a shared cache's fill under a scope of its own and return what it read.
    pub(crate) fn shared_fill<R>(f: impl FnOnce() -> R) -> (R, Arc<SharedCost>) {
        let scope = ScopeHandle(Arc::new(ScannerScope::default()));
        let out = {
            let _g = scope.enter();
            f()
        };
        let cost = SharedCost {
            read: scope.0.read.load(Ordering::Relaxed),
            missing: scope.0.missing.load(Ordering::Relaxed),
            claimed: AtomicBool::new(false),
        };
        (out, Arc::new(cost))
    }

    /// The running scanner used a shared cache entry filled by [`shared_fill`].
    pub(crate) fn touch_shared(cost: &Arc<SharedCost>) {
        with_scope(|s| {
            let mut t = s.touched.lock().unwrap_or_else(|e| e.into_inner());
            if !t.iter().any(|c| Arc::ptr_eq(c, cost)) {
                t.push(cost.clone());
            }
        });
    }

    /// The running scanner stopped at a walk budget: its results may be incomplete.
    /// Shown as `truncated` in its diagnostics row and on its span.
    pub fn mark_truncated() {
        with_scope(|s| s.truncated.store(true, Ordering::Relaxed));
    }

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
        with_scope(|s| if outcome == "ok" { &s.read } else { &s.missing }.fetch_add(1, Ordering::Relaxed));
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
            with_scope(|s| s.missing.fetch_add(1, Ordering::Relaxed));
        }
        if trace_enabled() {
            let shown = super::sanitize_display(&super::redact_secrets_in_text(&path.display().to_string()), 512);
            eprintln!(
                "trace: probe {shown} -> {}",
                if present { "present" } else { "missing" }
            );
        }
    }

    /// Record an existence check that found something of another type than the probe
    /// looks for (a directory where a file was probed): traced with `what`, counted as
    /// neither read nor missing.
    pub fn note_probe_other(path: &Path, what: &str) {
        if trace_enabled() {
            let shown = super::sanitize_display(&super::redact_secrets_in_text(&path.display().to_string()), 512);
            eprintln!("trace: probe {shown} -> {what}");
        }
    }

    /// (files read, files missing) so far by the scanner running on this thread (its
    /// scope's counters; a thread outside any scanner has its own). Callers take
    /// differences, as `skills.walk` does for one walk.
    pub fn snapshot() -> (u64, u64) {
        with_scope(|s| (s.read.load(Ordering::Relaxed), s.missing.load(Ordering::Relaxed)))
    }

    /// Run one scanner, attributing wall time and read counters to it.
    ///
    /// The scanner gets a fresh [`ScannerScope`] on this thread for the duration of `f`
    /// (read counters, `truncated` flag, hook and probe budget), so its row counts what
    /// it did and nothing a scanner running at the same time on another thread did.
    /// [`run`] then [`Pending::finalize`], on this thread.
    pub fn timed<T>(
        diagnostics: &mut Vec<ScannerStat>,
        scanner: &'static str,
        root: Option<PathBuf>,
        f: impl FnOnce() -> Vec<T>,
    ) -> Vec<T> {
        let (out, pending) = run(scanner, root, f);
        diagnostics.push(pending.finalize());
        out
    }

    /// Run one scanner on this thread under its own [`ScannerScope`] and `scanner.*`
    /// span (a child of this thread's current span). The span is detached when `f`
    /// returns, so the thread's context is back to what it was; its counts are set, and
    /// it is ended, by [`Pending::finalize`], which may run on another thread.
    pub fn run<T>(scanner: &'static str, root: Option<PathBuf>, f: impl FnOnce() -> Vec<T>) -> (Vec<T>, Pending) {
        use crate::otel::Attr;
        let scope = ScopeHandle(Arc::new(ScannerScope::default()));
        let entered = scope.enter();
        // The span starts at the same instant `elapsed` is measured from and is ended at
        // exactly start + elapsed: its duration is the table's, and every child span the
        // scanner opens ends inside it.
        let start = Instant::now();
        let span = crate::otel::span_with_at("scanner.", scanner, start, || vec![Attr::scanner(scanner)]);
        if trace_enabled() {
            eprintln!("trace: scanner {scanner} start");
        }
        let out = f();
        let elapsed = start.elapsed();
        let span = span.detach();
        drop(entered);
        let items = out.len();
        (
            out,
            Pending {
                scanner,
                root,
                elapsed,
                items,
                scope: scope.0,
                span,
            },
        )
    }

    /// A scanner that has run ([`run`]) whose row is not final yet: the shared-cache
    /// reads it may be charged with ([`SharedCost`]) depend on the scanners before it in
    /// the fixed order. Finalize rows in that order.
    #[must_use = "a scanner's row and span are produced by finalize"]
    pub struct Pending {
        scanner: &'static str,
        root: Option<PathBuf>,
        elapsed: std::time::Duration,
        items: usize,
        scope: Arc<ScannerScope>,
        span: crate::otel::DetachedSpan,
    }

    impl Pending {
        /// The scanner's diagnostics row: its own reads plus every shared-cache fill it
        /// asked for that no scanner finalized before it claimed. Sets the span's counts
        /// and ends it, records the scanner metrics, and prints the `--trace` done line.
        pub fn finalize(self) -> ScannerStat {
            use crate::otel::{Attr, Key};
            let Pending {
                scanner,
                root,
                elapsed,
                items,
                scope,
                mut span,
            } = self;
            let (mut read, mut missing) = (
                scope.read.load(Ordering::Relaxed),
                scope.missing.load(Ordering::Relaxed),
            );
            for c in scope.touched.lock().unwrap_or_else(|e| e.into_inner()).iter() {
                if !c.claimed.swap(true, Ordering::Relaxed) {
                    read += c.read;
                    missing += c.missing;
                }
            }
            let stat = ScannerStat {
                scanner: scanner.to_string(),
                root: root.map(|p| p.display().to_string()),
                duration_ms: elapsed.as_millis() as u64,
                files_read: read,
                files_missing: missing,
                items,
                skipped: false,
                truncated: scope.truncated.load(Ordering::Relaxed),
            };
            // Counts and duration only; `root` (a path) is never exported.
            span.set(|| {
                vec![
                    Attr::int(Key::DurationMs, stat.duration_ms as i64),
                    Attr::int(Key::FilesRead, stat.files_read as i64),
                    Attr::int(Key::FilesMissing, stat.files_missing as i64),
                    Attr::int(Key::Items, stat.items as i64),
                    Attr::bool(Key::ScannerTruncated, stat.truncated),
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
            stat
        }
    }

    /// Threads a scanner may use for its own work, counting the one it runs on: the
    /// scan's `--jobs` ([`set_helper_jobs`]). 1 (the default, and what a unit test calling
    /// a scanner directly gets) keeps every scanner single-threaded.
    static HELPER_JOBS: AtomicUsize = AtomicUsize::new(1);

    /// Set the scan's `--jobs` for [`helper_jobs`] (main, once, before scanning).
    pub fn set_helper_jobs(jobs: usize) {
        HELPER_JOBS.store(jobs.max(1), Ordering::Relaxed);
    }

    /// The scan's `--jobs`: the most threads one scanner's [`par_map`] uses.
    pub fn helper_jobs() -> usize {
        HELPER_JOBS.load(Ordering::Relaxed).max(1)
    }

    /// The default `--walk-budget`: directories listed per project by the gitconfig
    /// nested-repo walk. Coverage over speed: a project with a 25,000-directory data tree
    /// costs about 200 ms on one thread, and the walk is still a hard cap.
    pub const DEFAULT_WALK_BUDGET: usize = 25_000;

    /// The `--walk-budget` every other walk cap is written against: at this value each
    /// cap is the one rmguard shipped before the flag existed (the nested-repo walk's
    /// 4,000 directories), and every cap scales with the flag in the same ratio
    /// ([`walk_cap`]).
    pub const BASE_WALK_BUDGET: usize = 4_000;

    /// The scan's `--walk-budget` ([`set_walk_budget`]). A unit test calling a scanner
    /// directly gets [`DEFAULT_WALK_BUDGET`].
    static WALK_BUDGET: AtomicUsize = AtomicUsize::new(DEFAULT_WALK_BUDGET);

    /// Set the scan's `--walk-budget` (main, once, before scanning). 0 is raised to 1:
    /// the CLI rejects 0, and a budget is never "unlimited".
    pub fn set_walk_budget(budget: usize) {
        WALK_BUDGET.store(budget.max(1), Ordering::Relaxed);
    }

    /// The scan's `--walk-budget`.
    pub fn walk_budget() -> usize {
        WALK_BUDGET.load(Ordering::Relaxed).max(1)
    }

    /// A walk cap written as `base` at [`BASE_WALK_BUDGET`], scaled to `budget` in the
    /// same ratio (rounded down, at least 1, saturating): `walk_cap(5_000, 25_000)` is
    /// 31,250.
    pub fn walk_cap(base: usize, budget: usize) -> usize {
        let scaled = base as u128 * budget as u128 / BASE_WALK_BUDGET as u128;
        usize::try_from(scaled).unwrap_or(usize::MAX).max(1)
    }

    /// `items.map(f)` on up to `jobs` threads (this one and `jobs - 1` helpers), results
    /// in the items' order whichever thread finished first. `jobs <= 1`, or fewer than
    /// two items, is the plain loop on this thread.
    ///
    /// Every helper enters the running scanner's [`ScannerScope`] (its reads, `truncated`
    /// flag and hook and probe budget are the scanner's) and attaches this thread's span
    /// context (a span or exec span opened in `f` nests where it would sequentially). `f`
    /// must not spend an order-dependent budget (hooks, probes): which item gets the last
    /// unit would depend on thread timing. A helper that cannot be spawned is not an
    /// error: the others, this thread included, take its items.
    pub fn par_map<T: Send, R: Send>(items: Vec<T>, jobs: usize, f: impl Fn(T) -> R + Sync) -> Vec<R> {
        use std::sync::Mutex;
        let n = items.len();
        if jobs <= 1 || n <= 1 {
            return items.into_iter().map(f).collect();
        }
        let scope = current_scope();
        let cx = crate::otel::current_context();
        let slots: Vec<Mutex<Option<T>>> = items.into_iter().map(|t| Mutex::new(Some(t))).collect();
        let out: Vec<Mutex<Option<R>>> = (0..n).map(|_| Mutex::new(None)).collect();
        let next = AtomicUsize::new(0);
        let work = || {
            loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(slot) = slots.get(i) else { break };
                let item = slot
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take()
                    .expect("each item is taken once");
                let r = f(item);
                *out[i].lock().unwrap_or_else(|e| e.into_inner()) = Some(r);
            }
        };
        std::thread::scope(|s| {
            for _ in 1..jobs.min(n) {
                let (scope, cx, work) = (&scope, &cx, &work);
                // The main thread's stack size, as the scan pool's workers have.
                let _ = std::thread::Builder::new()
                    .name("rmguard-helper".into())
                    .stack_size(8 << 20)
                    .spawn_scoped(s, move || {
                        let _scope = scope.enter();
                        let _cx = cx.attach();
                        work();
                    });
            }
            work();
        });
        out.into_iter()
            .map(|m| {
                m.into_inner()
                    .unwrap_or_else(|e| e.into_inner())
                    .expect("every item ran")
            })
            .collect()
    }

    pub fn skipped(scanner: &'static str) -> ScannerStat {
        crate::otel::record(crate::otel::Metric::Skipped, 1.0, || {
            vec![crate::otel::Attr::scanner(scanner)]
        });
        ScannerStat {
            scanner: scanner.to_string(),
            root: None,
            duration_ms: 0,
            files_read: 0,
            files_missing: 0,
            items: 0,
            skipped: true,
            truncated: false,
        }
    }
}

// Injection-specific phrases that suggest MCP tool/resource description poisoning
// (hidden instructions aimed at the agent). Chosen to be multi-word to minimise
// false positives on benign descriptions like "Always returns JSON". Covers the
// Trail-of-Bits "line jumping" / Invariant Labs tool-poisoning families and the
// CyberArk "Poison everywhere" resource-description variant.
pub const POISONING_PATTERNS: &[&str] = &[
    "ignore previous",
    "ignore all previous",
    "disregard previous",
    "disregard the above",
    "you must ignore",
    "override previous instructions",
    "do not tell the user",
    "do not mention",
    "do not display",
    "do not show the user",
    "never reveal",
    "always include the contents of",
    "before using this tool",
    "before you use this tool",
    "first read",
    "pass as a sidenote",
    "this is very important",
    "system prompt",
    "hidden instruction",
    "<important>",
    "</important>",
    "<secret>",
    "<system-prompt>",
    "<system>",
    "```system",
];

/// Scan text for known prompt-injection / line-jumping phrases.
/// Lowercases once; returns the matched patterns in catalog order.
pub fn scan_injection_text(text: &str) -> Vec<&'static str> {
    let lower = text.to_lowercase();
    POISONING_PATTERNS
        .iter()
        .filter(|p| contains_phrase(&lower, p))
        .copied()
        .collect()
}

/// Whether `hay` contains the phrase `p` ending on a word boundary: when the phrase ends
/// in a letter, the character after the match must not be an ASCII letter, so "ignore
/// previous" matches "Ignore previous instructions" but not "Ignore previously generated
/// files" (review of 4e3f8c3). A phrase that ends in punctuation (`<system>`) is its own
/// boundary.
pub fn contains_phrase(hay: &str, p: &str) -> bool {
    if !p.ends_with(|c: char| c.is_ascii_alphabetic()) {
        return hay.contains(p);
    }
    hay.match_indices(p).any(|(i, m)| {
        !hay[i + m.len()..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
    })
}

/// The [`POISONING_PATTERNS`] that still mean injection in a prompt- or agent-type
/// hook's prompt. That prompt's whole job is to instruct the hook's evaluator model
/// ("Claude Code sends your prompt and the hook's input data to a Claude model ... The
/// model's only job is to return its decision as JSON", code.claude.com/docs/en/hooks-guide,
/// fetched 2026-10-23), so the tool-description phrases an ordinary evaluator prompt
/// uses are left out: "first read", "system prompt", "do not mention", "do not display",
/// "this is very important", "before using/you use this tool".
pub const HOOK_PROMPT_POISONING_PATTERNS: &[&str] = &[
    "ignore previous",
    "ignore all previous",
    "disregard previous",
    "disregard the above",
    "you must ignore",
    "override previous instructions",
    "do not tell the user",
    "do not show the user",
    "always include the contents of",
    "pass as a sidenote",
    "hidden instruction",
    "```system",
];

/// [`scan_injection_text`] with [`HOOK_PROMPT_POISONING_PATTERNS`], for the prompts of
/// hooks whose text goes to a separate evaluator model (Claude Code, Cursor).
///
/// "never reveal" and the XML-tag rows (`<important>`, `<system>`, ...) are left out of
/// the hook subset: "the agent must never reveal API keys" and
/// `<important>Be strict about rm -rf.</important>` are ordinary guard wording, and the
/// hook's author already writes the evaluator's instructions (review of f6f7df7).
///
/// Matched three ways: on the lowercased text, on the text folded by
/// [`normalize_for_matching`] with every Unicode space (NBSP, ideographic space) read as
/// one ASCII space (so a soft hyphen, a zero-width character or fullwidth letters inside
/// a phrase do not hide it), and on the ASCII that Unicode tag characters (U+E0020 to
/// U+E007E) spell, which a model reads and a reviewer does not see.
pub fn scan_hook_prompt_text(text: &str) -> Vec<&'static str> {
    scan_prompt_phrases(text, HOOK_PROMPT_POISONING_PATTERNS)
}

/// [`scan_hook_prompt_text`] with the whole [`POISONING_PATTERNS`] list, for a prompt the
/// agent itself reads: a Copilot CLI prompt hook ("Prompt hooks auto-submit text as if
/// the user typed it", docs.github.com/en/copilot/reference/hooks-configuration) and a
/// Kiro agent action ("the prompt specified in the hook is appended to the user prompt",
/// kiro.dev/docs/hooks/actions, both fetched 2026-10-23) are text in the agent's own
/// context, as an MCP tool description is, so no evaluator wording is exempt.
pub fn scan_context_prompt_text(text: &str) -> Vec<&'static str> {
    scan_prompt_phrases(text, POISONING_PATTERNS)
}

/// The [`POISONING_PATTERNS`] rows that ordinary instructions also use ("First read
/// CONTRIBUTING.md", "This is very important"): in a prompt the agent reads they are
/// graded one step below the concealment and override rows.
pub const WEAK_CONTEXT_PHRASES: &[&str] = &[
    "first read",
    "this is very important",
    "system prompt",
    "before using this tool",
    "before you use this tool",
    "<important>",
    "</important>",
];

/// The three readings a prompt is matched on: lowercased, folded by
/// [`normalize_for_matching`] with whitespace runs read as one space, and the ASCII that
/// Unicode tag characters spell.
fn prompt_readings(text: &str) -> [String; 3] {
    let lower = text.to_lowercase();
    let spaced = |s: &str| {
        s.split(char::is_whitespace)
            .filter(|w| !w.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    };
    let folded = spaced(&normalize_for_matching(text));
    let tags: String = text
        .chars()
        .filter_map(|c| {
            (0xE0020..=0xE007E)
                .contains(&(c as u32))
                .then(|| char::from_u32(c as u32 - 0xE0000))
                .flatten()
        })
        .collect();
    let tags = spaced(&tags.to_lowercase());
    [lower, folded, tags]
}

fn scan_prompt_phrases(text: &str, list: &[&'static str]) -> Vec<&'static str> {
    let readings = prompt_readings(text);
    list.iter()
        .filter(|p| readings.iter().any(|r| contains_phrase(r, p)))
        .copied()
        .collect()
}

/// Concealment phrases that ordinary guard wording also uses ("Never reveal any secret
/// values you find", "Do not mention internal ticket numbers"): in a prompt the agent
/// reads they are weak unless the same sentence aims the concealment at the user
/// ([`concealment_aimed_at_user`]), review of 4e3f8c3.
pub const SOFT_CONCEALMENT_PHRASES: &[&str] = &["never reveal", "do not display", "do not mention"];

/// The label a [`SOFT_CONCEALMENT_PHRASES`] row gets when its sentence names the user as
/// the one kept in the dark; it is graded as a strong phrase.
pub const AIMED_AT_USER_SUFFIX: &str = " (aimed at the user)";

/// Whether a sentence holding the phrase `p` also names "the user" (`from the user`, `to
/// the user`, `the user`): the concealment is then aimed at the person, not at output
/// hygiene. Sentences end at `.`, `!`, `?` or a line break; every reading of
/// [`prompt_readings`] is checked.
pub fn concealment_aimed_at_user(text: &str, p: &str) -> bool {
    prompt_readings(text).iter().any(|r| {
        r.split(['.', '!', '?', '\n'])
            .any(|sentence| contains_phrase(sentence, p) && contains_phrase(sentence, "the user"))
    })
}

/// Emoji and pictographic code points a ZWJ sequence joins (with skin-tone modifiers and
/// the emoji variation selectors that may sit before the joiner).
fn is_emoji_part(c: char) -> bool {
    matches!(c as u32,
        0x1F000..=0x1FAFF | 0x2600..=0x27BF | 0x2300..=0x23FF | 0x2B00..=0x2BFF | 0x2190..=0x21FF
        | 0x2900..=0x297F | 0x3030 | 0x303D | 0x3297 | 0x3299 | 0x00A9 | 0x00AE | 0x203C | 0x2049
        | 0x2122 | 0x2139 | 0x24C2 | 0x25A0..=0x25FF | 0xFE0E | 0xFE0F | 0x20E3)
}

/// Right-to-left letters (Hebrew, Arabic, Syriac, Thaana, NKo and their presentation
/// forms): a text with any of them has a use for directional marks.
fn is_rtl_letter(c: char) -> bool {
    matches!(c as u32, 0x0590..=0x08FF | 0xFB1D..=0xFDFF | 0xFE70..=0xFEFF) && c.is_alphabetic()
}

/// The [`scan_suspicious_unicode`] classes that make a hook prompt a hiding place: the
/// model reads tag characters, variation-selector payloads, zero-width characters and
/// bidi controls that render as nothing (or reorder what renders) for the person
/// reviewing the hook. Soft hyphens and other controls are left to
/// [`scan_hook_prompt_text`]'s folding.
///
/// Ordinary text is not a hiding place (review of b9cda85): a zero-width joiner between
/// two emoji parts (the ZWJ of 🧑‍💻, 👨‍👩‍👧, ❤️‍🔥) and a ZWSP, ZWNJ or ZWJ between two
/// non-ASCII letters (Persian ZWNJ, Thai ZWSP line breaks) are not counted; one that is
/// isolated, at either end, next to another invisible character or next to ASCII is. A
/// directional mark (LRM, RLM, ALM) counts only when the text has no right-to-left
/// letter or the mark sits between two ASCII letters or digits (`ig\u{200f}nore`); the
/// embedding, override and isolate controls always count. A run of two or more BMP
/// variation selectors with no emoji base ([`bmp_selector_runs`]) counts as the
/// supplementary ones do.
pub fn hook_prompt_hidden_unicode(text: &str) -> Vec<&'static str> {
    let chars: Vec<char> = text.chars().collect();
    let rtl = chars.iter().any(|c| is_rtl_letter(*c));
    let mut cats: Vec<&'static str> = Vec::new();
    if bmp_selector_runs(&chars).contains(&true) {
        cats.push("variation-selector-smuggler");
    }
    for (i, &c) in chars.iter().enumerate() {
        let prev = i.checked_sub(1).map(|j| chars[j]);
        let next = chars.get(i + 1).copied();
        let both = |f: fn(char) -> bool| prev.is_some_and(f) && next.is_some_and(f);
        let label = match c as u32 {
            0xE0000..=0xE007F => "tag-block",
            0xE0100..=0xE01EF => "variation-selector-smuggler",
            0x200B | 0x200C | 0x200D | 0xFEFF | 0x2060..=0x2064 => {
                let emoji_join = c == '\u{200d}' && both(is_emoji_part);
                let script_join =
                    matches!(c, '\u{200b}' | '\u{200c}' | '\u{200d}') && both(|x| !x.is_ascii() && x.is_alphabetic());
                if emoji_join || script_join {
                    continue;
                }
                "zero-width"
            }
            0x061C | 0x200E | 0x200F => {
                if rtl && !both(|x| x.is_ascii_alphanumeric()) {
                    continue;
                }
                "bidi-control"
            }
            0x202A..=0x202E | 0x2066..=0x2069 => "bidi-control",
            _ => continue,
        };
        if !cats.contains(&label) {
            cats.push(label);
        }
    }
    cats
}

/// The credential paths a prompt names, as written (`~/.aws/credentials`,
/// `$HOME/.ssh/id_ed25519`, `.env`, `id_rsa`): each whitespace-separated word, trimmed of
/// quotes, brackets and sentence punctuation, judged lexically by
/// [`persistence::sensitive_read_kind`] against a placeholder home (`~/`, `$HOME/`,
/// `${HOME}/`) or by its file name alone ([`persistence::is_sensitive_read_name`]).
/// Nothing is opened or probed. At most 8, deduped, sanitized.
pub fn prompt_credential_paths(text: &str) -> Vec<String> {
    const TEMPLATE_SUFFIXES: &[&str] = &[".example", ".sample", ".template", ".dist"];
    let mut out: Vec<String> = Vec::new();
    for w in text.split_whitespace() {
        let w = w.trim_matches(|c: char| {
            matches!(
                c,
                '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '<' | '>' | ',' | ';' | ':' | '!' | '?' | '*' | '{' | '}'
            )
        });
        let w = w.trim_end_matches('.');
        if w.len() < 2 || w.contains("://") {
            continue;
        }
        // A template names variables, not values (`.env.example`, `secrets.json.sample`),
        // so it is not a credential path.
        let lw = w.to_ascii_lowercase();
        if TEMPLATE_SUFFIXES.iter().any(|t| lw.ends_with(t)) {
            continue;
        }
        let rel = w
            .strip_prefix("~/")
            .or_else(|| w.strip_prefix("$HOME/"))
            .or_else(|| w.strip_prefix("${HOME}/"));
        let hit = match rel {
            Some(r) => {
                persistence::sensitive_read_kind(&std::path::Path::new("/h").join(r), std::path::Path::new("/h"))
                    == Some("credential")
            }
            // A bare word is a file name only when it is shaped like one (`.env`, `id_rsa`,
            // `credentials.json`, `secrets/.netrc`), not the English word "credentials".
            None => {
                (w.contains('/') || w.contains('.') || w.starts_with("id_"))
                    && persistence::is_sensitive_read_name(std::path::Path::new(w))
            }
        };
        if hit {
            let shown = sanitize_display(w, 120);
            if !out.contains(&shown) && out.len() < 8 {
                out.push(shown);
            }
        }
    }
    out
}

/// Mask the account identifiers Claude Code puts in synced-skill directory names.
///
/// Synced skills live under `~/.claude/skills/synced/<organizationUuid>_<accountUuid>/`
/// (observed 2026-10-24): the same organization and account UUIDs `~/.claude.json`'s
/// `oauthAccount` holds, which no report prints. A path segment directly under a
/// `skills/synced/` component (or under a leading `synced/`, a skill's name relative to
/// its skills directory) that is `<uuid>_<uuid>` becomes `<org>_<account>`, and a bare
/// `<uuid>` becomes `<account>` (8-4-4-4-12 hex, either case). Display and serialization
/// only: dedupe keys and content hashes are computed on the real path before this runs,
/// and the masked text is deterministic, so a `--diff` of two scans keys on the same
/// string.
pub fn mask_identifiers(s: &str) -> std::borrow::Cow<'_, str> {
    const MARK: &str = "synced";
    if !s.contains(MARK) {
        return std::borrow::Cow::Borrowed(s);
    }
    match mask_encoded_identifiers(s) {
        std::borrow::Cow::Owned(o) => std::borrow::Cow::Owned(mask_path_identifiers(&o).into_owned()),
        std::borrow::Cow::Borrowed(_) => mask_path_identifiers(s),
    }
}

/// The ENCODED spelling of a synced-skill directory, as Claude Code names a project
/// directory under `~/.claude/projects/` (every `/`, `.` and `_` becomes `-`):
/// `...-skills-synced-<uuid>-<uuid>...` becomes `...-skills-synced-<org>-<account>...`
/// and `...-synced-<uuid>...` becomes `...-synced-<account>...`. `synced` must start
/// the text or follow a `-` or a path separator, and the UUID run must end the text or
/// be followed by a byte that is not a hex digit or letter.
fn mask_encoded_identifiers(s: &str) -> std::borrow::Cow<'_, str> {
    const MARK: &str = "synced-";
    let b = s.as_bytes();
    let mut out = String::new();
    let mut copied = 0;
    let mut from = 0;
    while let Some(off) = s[from..].find(MARK) {
        let at = from + off;
        from = at + MARK.len();
        if at > 0 && !matches!(b[at - 1], b'-' | b'/' | b'\\') {
            continue;
        }
        let start = from;
        let uuid_at = |i: usize| s.get(i..i + 36).is_some_and(is_uuid);
        if !uuid_at(start) {
            continue;
        }
        let mut end = start + 36;
        let pair = b.get(end) == Some(&b'-') && uuid_at(end + 1);
        if pair {
            end += 37;
        }
        if b.get(end).is_some_and(|c| c.is_ascii_alphanumeric()) {
            continue;
        }
        out.push_str(&s[copied..start]);
        out.push_str(if pair { "<org>-<account>" } else { "<account>" });
        copied = end;
        from = end;
    }
    if copied == 0 {
        return std::borrow::Cow::Borrowed(s);
    }
    out.push_str(&s[copied..]);
    std::borrow::Cow::Owned(out)
}

/// [`mask_identifiers`] for the path spelling (`skills/synced/<uuid>_<uuid>/`).
fn mask_path_identifiers(s: &str) -> std::borrow::Cow<'_, str> {
    const MARK: &str = "synced";
    let b = s.as_bytes();
    let sep = |c: u8| c == b'/' || c == b'\\';
    let mut out = String::with_capacity(s.len());
    let mut copied = 0;
    let mut from = 0;
    while let Some(off) = s[from..].find(MARK) {
        let at = from + off;
        from = at + MARK.len();
        // `synced` must be a whole component followed by a separator: after `skills/`,
        // or a relative path's first component (`synced/<id>/x/SKILL.md`, a skill's name
        // relative to its skills directory, alone or inside a line or a reference).
        let name_byte = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.';
        let under_skills = at >= 7 && sep(b[at - 1]) && s[..at - 1].ends_with("skills") && {
            let k = at - 7;
            k == 0 || !name_byte(b[k - 1])
        };
        let leading = at == 0 || !(name_byte(b[at - 1]) || sep(b[at - 1]));
        if !(under_skills || leading) || !b.get(from).copied().is_some_and(sep) {
            continue;
        }
        let seg_start = from + 1;
        let seg_end = s[seg_start..]
            .find(|c: char| !(c.is_ascii_hexdigit() || c == '-' || c == '_'))
            .map_or(s.len(), |o| seg_start + o);
        let seg = &s[seg_start..seg_end];
        // The segment must end the component: a separator, the end, or a non-name byte.
        let ends = seg_end == s.len() || !(b[seg_end].is_ascii_alphanumeric() || b[seg_end] == b'.');
        if !ends {
            continue;
        }
        let mask = match seg.split_once('_') {
            Some((o, a)) if is_uuid(o) && is_uuid(a) => "<org>_<account>",
            None if is_uuid(seg) => "<account>",
            _ => continue,
        };
        out.push_str(&s[copied..seg_start]);
        out.push_str(mask);
        copied = seg_end;
        from = seg_end;
    }
    if copied == 0 {
        return std::borrow::Cow::Borrowed(s);
    }
    out.push_str(&s[copied..]);
    std::borrow::Cow::Owned(out)
}

/// `8-4-4-4-12` hex digits, either case.
fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

/// Make attacker-controlled free text safe to print: control characters (including ESC,
/// so no ANSI sequence can forge a green "clean" line), C1 controls and line breaks are
/// replaced, and the result is capped. For names, versions, error messages and paths
/// that a manifest, a package or a probed server gets to choose.
///
/// Account identifiers in synced-skill paths are masked first ([`mask_identifiers`]), so
/// the cap never cuts a UUID into a prefix that escapes the mask.
pub fn sanitize_display(s: &str, max: usize) -> String {
    let s = mask_identifiers(s);
    let mut out = String::with_capacity(s.len().min(max));
    let chars: Vec<char> = s.chars().collect();
    let smuggled = bmp_selector_runs(&chars);
    for (i, &c) in chars.iter().enumerate() {
        if out.chars().count() >= max {
            out.push('…');
            break;
        }
        // Bidi overrides and isolates (Cf, not is_control) can reverse the visible text
        // of a status line without adding one; they go too. So does a BMP
        // variation-selector run with no emoji base ([`bmp_selector_runs`]).
        let bad = c.is_control() || ('\u{80}'..='\u{9f}').contains(&c) || is_display_hazard(c) || smuggled[i];
        out.push(if bad { '?' } else { c });
    }
    out
}

/// For each char, whether it is in a run of two or more BMP variation selectors
/// (U+FE00-FE0F) that no emoji base precedes (the run starts the text or follows an
/// ASCII character). One selector after an emoji or another non-ASCII character
/// (`❤️`) is ordinary text; a run after ASCII is the variation-selector smuggling
/// encoding, which carries one nibble per selector (review of 4e3f8c3).
pub(crate) fn bmp_selector_runs(chars: &[char]) -> Vec<bool> {
    let sel = |c: char| ('\u{fe00}'..='\u{fe0f}').contains(&c);
    let mut out = vec![false; chars.len()];
    let mut i = 0;
    while i < chars.len() {
        if !sel(chars[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && sel(chars[i]) {
            i += 1;
        }
        let based = start > 0 && !chars[start - 1].is_ascii();
        if i - start >= 2 && !based {
            out[start..i].iter_mut().for_each(|b| *b = true);
        }
    }
    out
}

/// Format characters that change how surrounding text renders without showing
/// themselves: the line and paragraph separators, every Unicode Bidi_Control character
/// (U+061C ARABIC LETTER MARK, U+200E/F, U+202A-E, U+2066-9), and the invisible
/// zero-width space, word joiner and invisible operators (U+200B, U+2060-4) and BOM
/// (U+FEFF). ZWNJ and ZWJ (U+200C/D) are kept: Persian text and emoji sequences need
/// them. Shared by [`sanitize_display`] and the terminal renderer's backstops.
pub fn is_display_hazard(c: char) -> bool {
    matches!(
        c,
        '\u{2028}' | '\u{2029}' | '\u{061c}' | '\u{200b}' | '\u{200e}' | '\u{200f}' | '\u{feff}'
    ) || ('\u{202a}'..='\u{202e}').contains(&c)
        || ('\u{2060}'..='\u{2064}').contains(&c)
        || ('\u{2066}'..='\u{2069}').contains(&c)
        || is_invisible_carrier(c)
}

/// Characters that render as nothing (or as blank space) and carry hidden text: the
/// Unicode tag block (U+E0000-E007F, which spells ASCII a model reads), the
/// supplementary variation selectors (U+E0100-E01EF), the soft hyphen (U+00AD), the
/// Mongolian vowel separator (U+180E) and the Hangul fillers (U+115F, U+1160, U+3164,
/// U+FFA0). [`scan_suspicious_unicode`] treats them as smuggling carriers; no display
/// field needs them.
fn is_invisible_carrier(c: char) -> bool {
    matches!(c as u32, 0xE0000..=0xE007F | 0xE0100..=0xE01EF | 0x00AD | 0x180E | 0x115F | 0x1160 | 0x3164 | 0xFFA0)
}

/// Run a command with a wall-clock cap, stdin closed. `Command::output()` has no timeout,
/// and git will happily open an `[include] path = /dev/tty` (or a FIFO) from an
/// attacker-authored config and block forever, stalling the whole scan. Returns None on
/// timeout or spawn failure.
///
/// stdout is drained on a reader thread while the parent blocks on the exit event, so a child that writes
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
    output_with_cap(cmd, timeout, site, MAX_CHILD_OUTPUT, false)
}

/// [`output_with_timeout_at`] with an explicit output cap that is ENFORCED, whatever its
/// size: a child that writes past the cap is killed at once (not left to the timeout)
/// and None is returned, since its output is incomplete. A cut-off listing is never
/// returned as complete (review round 6: the old `cap < MAX_CHILD_OUTPUT` test made the
/// 32 MiB `git ls-files` cap a no-op).
fn output_with_timeout_capped(
    cmd: &mut std::process::Command,
    timeout: std::time::Duration,
    site: &'static str,
    cap: usize,
) -> Option<std::process::Output> {
    output_with_cap(cmd, timeout, site, cap, true)
}

/// The shared runner. `strict`: output past `cap` is an incomplete answer (None); without
/// it the first `cap` bytes are returned (callers that only read a bounded prefix).
fn output_with_cap(
    cmd: &mut std::process::Command,
    timeout: std::time::Duration,
    site: &'static str,
    cap: usize,
    strict: bool,
) -> Option<std::process::Output> {
    use std::io::Read;
    use std::process::Stdio;
    let mut x = crate::otel::exec_span(site, cmd.get_program());
    let mut child = match cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
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
    let (tx, rx) = std::sync::mpsc::channel();
    let tx_r = tx.clone();
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut stdout).take(cap as u64 + 1).read_to_end(&mut buf);
        if buf.len() > cap {
            buf.truncate(cap);
            over_r.store(true, std::sync::atomic::Ordering::SeqCst);
            // Wake the waiting caller at once; it decides whether the cap is fatal.
            let _ = tx_r.send(ChildEvent::OverCap);
        }
        buf
    });
    let pid = child.id();
    spawn_waiter(child, tx);
    match wait_child(pid, &rx, timeout, strict) {
        ChildWait::Exited(status, _child) => {
            let stdout = reader.join().unwrap_or_default();
            note_exit(&mut x, &status);
            if strict && over.load(std::sync::atomic::Ordering::SeqCst) {
                x.outcome("output_cap");
                return None;
            }
            Some(std::process::Output {
                status,
                stdout,
                stderr: Vec::new(),
            })
        }
        // On timeout or over-cap the reader is NOT joined: the kill reaches the child
        // only, and a grandchild (`sh -c 'a; sleep 30'` under dash, which does not exec
        // its last command) can keep the pipe open; the reader thread ends by itself
        // when the pipe finally closes. Joining it here stalled a 200 ms timeout for the
        // grandchild's full 30 s on the Linux CI runner.
        ChildWait::OverCap => {
            x.outcome("output_cap");
            None
        }
        ChildWait::TimedOut => {
            x.outcome("timeout");
            None
        }
        ChildWait::WaitFailed => {
            x.outcome("wait_failed");
            None
        }
    }
}

/// Upper bound on bytes kept from a child's stdout. 8 MiB is a very large repository's
/// `git ls-files -s`; the callers only ever need a bounded prefix.
pub const MAX_CHILD_OUTPUT: usize = 8 * 1024 * 1024;

#[cfg(all(test, unix))]
mod capped_output_tests {
    use super::*;

    /// The child wait is event-driven, not polled. The fastest of ten `/bin/true` runs
    /// through the shared runner, and through the version probe, finishes well under the
    /// old ticks (20 ms and 50 ms); the bounds leave room for a loaded CI runner but not
    /// for a poll loop. (Found by the OpenTelemetry trace: every exec
    /// span lasted an exact multiple of its tick.)
    #[test]
    fn child_waits_do_not_poll() {
        // macOS ships /usr/bin/true, Linux /bin/true.
        let truth = ["/bin/true", "/usr/bin/true"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists())
            .expect("a true binary");
        // A polled wait never returns before its first tick, so even its FASTEST run is
        // at least the tick; an event-driven one returns in a few ms. Bounding the fastest
        // of ten runs, rather than their total, still fails a poll loop every time but no
        // longer fails a loaded machine where a few spawns are slow.
        let t = std::time::Duration::from_secs(5);
        let fastest = |f: &mut dyn FnMut()| {
            (0..10)
                .map(|_| {
                    let start = std::time::Instant::now();
                    f();
                    start.elapsed()
                })
                .min()
                .unwrap()
        };
        let runner = fastest(&mut || {
            let mut c = child_command(truth);
            assert!(output_with_timeout(&mut c, t).is_some());
        });
        let probe = fastest(&mut || {
            let _ = get_binary_version(truth);
        });
        assert!(
            runner < std::time::Duration::from_millis(15),
            "runner polled (20 ms tick): fastest of 10 runs took {runner:?}"
        );
        assert!(
            probe < std::time::Duration::from_millis(40),
            "version probe polled (50 ms tick): fastest of 10 runs took {probe:?}"
        );
    }

    /// Timeouts and the output cap still kill and reap the child under the new waiter.
    #[test]
    fn child_timeout_kills_and_reaps() {
        let mut c = child_command("/bin/sh");
        c.args(["-c", "sleep 30"]);
        let start = std::time::Instant::now();
        assert!(output_with_timeout(&mut c, std::time::Duration::from_millis(200)).is_none());
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "timeout did not fire promptly"
        );
        // Over-cap in strict mode is also event-driven: the reader wakes the waiter.
        let mut c = child_command("/bin/sh");
        c.args(["-c", "head -c 200000 /dev/zero; sleep 30"]);
        let start = std::time::Instant::now();
        assert!(output_with_timeout_capped(&mut c, std::time::Duration::from_secs(10), "test", 1000).is_none());
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "over-cap kill was not prompt"
        );
    }

    /// Review round 6: a cap above MAX_CHILD_OUTPUT (the 32 MiB `git ls-files` cap) is
    /// enforced: a child that writes past it is an incomplete answer (None), never a
    /// silently cut-off listing returned as complete.
    #[test]
    fn explicit_caps_above_the_default_are_enforced() {
        let cap = MAX_CHILD_OUTPUT + 100;
        let t = std::time::Duration::from_secs(20);
        let mut over = child_command("/bin/sh");
        over.args(["-c", &format!("head -c {} /dev/zero", cap + 1000)]);
        assert!(
            output_with_timeout_capped(&mut over, t, "test", cap).is_none(),
            "a cut-off listing was returned as complete"
        );
        let mut under = child_command("/bin/sh");
        under.args(["-c", &format!("head -c {} /dev/zero", cap - 1000)]);
        let out = output_with_timeout_capped(&mut under, t, "test", cap).expect("complete output under the cap");
        assert_eq!(out.stdout.len(), cap - 1000);
        let mut small = child_command("/bin/sh");
        small.args(["-c", "head -c 5000 /dev/zero"]);
        assert!(output_with_timeout_capped(&mut small, t, "test", 1000).is_none());
    }
}

#[cfg(test)]
mod process_snapshot_tests {
    use super::*;

    /// Every process name a detector asks about, with the scanner that asks.
    fn asked() -> Vec<(&'static str, &'static str)> {
        let mut v = Vec::new();
        v.extend(ai_tools::spawn_and_process_names().1.into_iter().map(|n| ("ai", n)));
        v.extend(
            ai_frameworks::spawn_and_process_names()
                .1
                .into_iter()
                .map(|n| ("frameworks", n)),
        );
        v.extend(
            container_tools::spawn_and_process_names()
                .1
                .into_iter()
                .map(|n| ("containers", n)),
        );
        v.extend(
            notebook_servers::spawn_and_process_names()
                .1
                .into_iter()
                .map(|n| ("notebooks", n)),
        );
        // `ai` also asks about each desktop app by its file stem (both platforms' lists).
        for stem in ["Claude", "GitHub Copilot", "claude-desktop", "github-copilot"] {
            v.push(("ai", stem));
        }
        v
    }

    /// What `pgrep -x <pattern>` matched: the pattern as an extended regex anchored at
    /// both ends, against the process name. Implemented for the subset the detectors
    /// use (literal text, `.` as any byte), which `names_are_regex_literals` pins.
    fn old_pgrep_x(names: &[String], pattern: &str) -> bool {
        names
            .iter()
            .any(|n| n.len() == pattern.len() && n.bytes().zip(pattern.bytes()).all(|(a, p)| p == b'.' || a == p))
    }

    /// pgrep read its argument as a regex. String equality equals that match only
    /// when no name holds a metacharacter; one that did (`.`, `+`, `[`...) would need
    /// escaping to keep its old meaning, or a regex here.
    #[test]
    fn names_are_regex_literals() {
        for (scanner, n) in asked() {
            assert!(
                !n.chars().any(|c| ".[]()*+?{}|^$\\".contains(c)),
                "{scanner}: process name {n:?} has a regex metacharacter"
            );
            // Linux pgrep: "pattern ... longer than 15 characters will result in zero
            // matches". A name past 15 bytes was never matched there, and is not now.
            assert!(n.len() <= 16, "{scanner}: {n:?} can never match a process name");
        }
    }

    /// A canned `ps -A -o ucomm=` listing: the new in-process match gives, for every
    /// detector's name, the answer the old per-name `pgrep -x` call gave.
    #[test]
    fn snapshot_match_equals_old_pgrep_per_detector() {
        let listing = b"systemd\n  kthreadd\nollama\ntext-generation\ndockerd\ncontainerd-shim\n\
podman <defunct>\njupyter-noteboo\nClaude\nGitHub Copilot\nlimactlx\nCOLIMA\nvllm \nps\n\n";
        let names = parse_process_list(listing);
        assert!(
            names.contains(&"podman".to_string()),
            "zombie suffix not removed: {names:?}"
        );
        assert!(names.contains(&"kthreadd".to_string()), "leading padding not trimmed");
        let mut hits = Vec::new();
        for (scanner, n) in asked() {
            // The zombie: pgrep matched it by name, so must we.
            let old = old_pgrep_x(&names, n);
            assert_eq!(process_list_has(&names, n), old, "{scanner}: {n}");
            if old {
                hits.push(n);
            }
        }
        hits.sort();
        hits.dedup();
        // Exact, anchored, case-sensitive: `containerd-shim` is not `containerd`,
        // `limactlx` is not `limactl`, `COLIMA` is not `colima`; the 15-byte truncated
        // comm `text-generation` is what the frameworks entry asks for.
        assert_eq!(
            hits,
            [
                "Claude",
                "GitHub Copilot",
                "dockerd",
                "jupyter-noteboo",
                "ollama",
                "podman",
                "text-generation",
                "vllm"
            ]
        );
        assert!(
            !process_list_has(&names, ""),
            "an empty name (no file stem) matches nothing"
        );
        assert!(!process_list_has(&names, "containerd"));
        assert!(!process_list_has(&names, "colima"));
    }

    /// On this machine, one snapshot answers like the pgrep it replaced, for the
    /// current process (whose name the test harness knows) and a name nobody runs.
    #[cfg(target_os = "linux")]
    #[test]
    fn live_snapshot_sees_this_process() {
        let me = std::fs::read_to_string("/proc/self/comm").unwrap();
        let me = me.trim();
        assert!(is_process_running(me), "{me} not in the snapshot");
        assert!(!is_process_running("rmguard-no-such-process"));
        let names = proc_process_names();
        assert!(process_list_has(&names, me));
    }

    /// Every program a scanner may `--version` probe or verify is in the closed
    /// `rmguard.exec.program` table, so the trace names it rather than `other`.
    #[test]
    fn every_spawned_program_is_in_the_exec_program_table() {
        let mut programs: Vec<&str> = vec!["git", "ps", "ssh-keygen", "claude-desktop"];
        programs.extend(ai_tools::spawn_and_process_names().0);
        programs.extend(ai_frameworks::spawn_and_process_names().0);
        programs.extend(container_tools::spawn_and_process_names().0);
        programs.extend(notebook_servers::spawn_and_process_names().0);
        programs.extend(node_packages::spawned_binaries());
        programs.extend(crate::platform::Ide::ALL.iter().map(|&i| ide::ide_bin_name(i)));
        for p in programs {
            assert_eq!(
                crate::otel::exec_program(std::ffi::OsStr::new(p)),
                p,
                "{p} missing from EXEC_PROGRAMS"
            );
        }
    }
}

#[cfg(test)]
mod scanner_scope_tests {
    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("rmg-scope-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The hook and probe budget is the scanner's own: a scanner run on a thread where
    /// an earlier scanner spent the budget starts with all of it. (On f613c78 the
    /// budget was a thread-local that only `skills` and `settings` reset, so any other
    /// scanner, or those two run on a reused worker thread mid-scan, inherited what the
    /// previous scanner on that thread left.)
    #[test]
    fn hook_budget_is_per_scanner_not_per_thread() {
        std::thread::spawn(|| {
            let mut diag = Vec::new();
            telemetry::timed(&mut diag, "first", None, || {
                while hook_sources::take_probe() {}
                assert!(!hook_sources::take_probe());
                Vec::<()>::new()
            });
            let left = telemetry::timed(&mut diag, "second", None, || {
                vec![(hook_sources::hooks_left(), hook_sources::take_probe())]
            });
            assert_eq!(
                left,
                vec![(hook_sources::MAX_HOOKS_PER_SCAN, true)],
                "the second scanner inherited a spent budget"
            );
        })
        .join()
        .unwrap();
    }

    /// A shared cache's fill (the git-tracked listing of one repository) is charged to
    /// the first scanner in the fixed order that asked, whichever thread filled it: here
    /// the later scanner `b` fills it, and `a`, finalized first, is charged, as it would
    /// have been had `a` run first. `b` is charged nothing.
    #[test]
    fn shared_cache_reads_go_to_the_first_scanner_in_order() {
        let repo = scratch("shared");
        std::fs::create_dir_all(repo.join(".git/objects")).unwrap();
        std::fs::write(repo.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(repo.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
        std::fs::write(repo.join(".git/commondir"), ".\n").unwrap();
        let file = repo.join("a.txt");
        std::fs::write(&file, "x").unwrap();
        let (_, b) = std::thread::scope(|s| {
            s.spawn(|| telemetry::run("b", None, || vec![is_git_tracked(&file)]))
                .join()
                .unwrap()
        });
        let (_, a) = telemetry::run("a", None, || vec![is_git_tracked(&file)]);
        let (a, b) = (a.finalize(), b.finalize());
        let _ = std::fs::remove_dir_all(&repo);
        assert!(
            a.files_read + a.files_missing > 0,
            "the fill's reads were not charged to a: {a:?}"
        );
        assert_eq!(
            (b.files_read, b.files_missing),
            (0, 0),
            "b was charged for a fill a claimed: {b:?}"
        );
    }

    /// `mark_truncated` marks the running scanner's row only.
    #[test]
    fn truncated_is_per_scanner() {
        let mut diag = Vec::new();
        telemetry::timed(&mut diag, "walk", None, || {
            telemetry::mark_truncated();
            Vec::<()>::new()
        });
        telemetry::timed(&mut diag, "next", None, Vec::<()>::new);
        assert!(diag[0].truncated);
        assert!(!diag[1].truncated, "truncated leaked into the next scanner");
        let json = serde_json::to_value(&diag[1]).unwrap();
        assert!(json.get("truncated").is_none(), "false is not serialized: {json}");
        assert_eq!(serde_json::to_value(&diag[0]).unwrap()["truncated"], true);
    }
}

#[cfg(test)]
mod par_map_tests {
    use super::telemetry::{self, par_map};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    /// At `jobs` 4 the items run on more than one thread at once, every helper counts its
    /// reads and its `truncated` for the scanner whose scope the caller is in, and the
    /// results come back in the items' order; at `jobs` 1 everything runs on this thread.
    #[test]
    fn helpers_run_concurrently_inside_the_callers_scope_and_keep_order() {
        for jobs in [1usize, 4] {
            let (out, pending) = telemetry::run("par_map_test", None, || {
                let in_flight = AtomicUsize::new(0);
                let peak = AtomicUsize::new(0);
                let me = std::thread::current().id();
                let r = par_map((0..16u64).collect(), jobs, |i| {
                    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    // Wait (bounded) for a second item to be in flight, so concurrency is
                    // observed rather than hoped for.
                    let t = Instant::now();
                    while jobs > 1 && peak.load(Ordering::SeqCst) < 2 && t.elapsed() < Duration::from_secs(5) {
                        std::hint::spin_loop();
                    }
                    telemetry::note_read(std::path::Path::new("/par-map-test"), "ok");
                    if i == 13 {
                        telemetry::mark_truncated();
                    }
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    (i * 10, std::thread::current().id() == me)
                });
                let all_here = r.iter().all(|(_, here)| *here);
                assert_eq!(
                    all_here,
                    jobs == 1,
                    "jobs {jobs}: items ran on this thread only = {all_here}"
                );
                assert_eq!(
                    peak.load(Ordering::SeqCst) >= 2,
                    jobs > 1,
                    "jobs {jobs}: peak in flight"
                );
                r.into_iter().map(|(v, _)| v).collect::<Vec<_>>()
            });
            let stat = pending.finalize();
            assert_eq!(
                out,
                (0..16u64).map(|i| i * 10).collect::<Vec<_>>(),
                "jobs {jobs}: order"
            );
            assert_eq!(stat.files_read, 16, "jobs {jobs}: helper reads count for the scanner");
            assert!(
                stat.truncated,
                "jobs {jobs}: a helper's mark_truncated reaches the scanner row"
            );
        }
    }
}

#[cfg(test)]
mod mask_identifiers_tests {
    use super::{mask_identifiers, sanitize_display};

    const O: &str = "0e2e0a1b-2c3d-4e5f-8a9b-0c1d2e3f4a5b";
    const A: &str = "1E2E0A1B-2C3D-4E5F-8A9B-0C1D2E3F4A5C";

    #[test]
    fn synced_segments_are_masked() {
        let m = |s: &str| mask_identifiers(s).into_owned();
        assert_eq!(
            m(&format!("/h/.claude/skills/synced/{O}_{A}/x/SKILL.md")),
            "/h/.claude/skills/synced/<org>_<account>/x/SKILL.md"
        );
        assert_eq!(
            m(&format!("/h/.claude/skills/synced/{A}/x")),
            "/h/.claude/skills/synced/<account>/x"
        );
        assert_eq!(
            m(&format!("/h/.claude/skills/synced/{O}_{A}")),
            "/h/.claude/skills/synced/<org>_<account>"
        );
        // A skill's name, relative to its skills directory, and inside a bom-ref.
        assert_eq!(
            m(&format!("synced/{O}_{A}/x/run.py")),
            "synced/<org>_<account>/x/run.py"
        );
        assert_eq!(
            m(&format!("a skills/synced/{O}_{A}/x and skills/synced/{A}/y")),
            "a skills/synced/<org>_<account>/x and skills/synced/<account>/y"
        );
        assert_eq!(
            m(&format!("/p (synced/{O}_{A}/x) skill:claude-code:synced/{A}/y")),
            "/p (synced/<org>_<account>/x) skill:claude-code:synced/<account>/y"
        );
        assert_eq!(
            m(&format!(r"C:\u\.claude\skills\synced\{O}_{A}\x")),
            r"C:\u\.claude\skills\synced\<org>_<account>\x"
        );
        // The cap applies after the mask: no UUID prefix survives a truncation.
        let long = format!("/{}/.claude/skills/synced/{O}_{A}/x", "d".repeat(60));
        assert!(!sanitize_display(&long, 100).contains(&O[..8]));
    }

    #[test]
    fn other_text_is_left_alone() {
        for s in [
            format!("/h/.claude/skills/{O}_{A}/x"),
            format!("/h/notskills/synced/{O}_{A}/x"),
            format!("/h/.claude/skills/synced2/{A}/x"),
            format!("/h/.claude/skills/synced/{A}x/y"),
            format!("/h/.claude/skills/synced/{A}.bak/y"),
            format!("/h/.claude/skills/synced/{O}_{A}_{A}/y"),
            format!("/h/.claude/skills/synced/x/{A}/y"),
            "/h/.claude/skills/synced/0e2e0a1b-2c3d/y".to_string(),
            "/h/.claude/skills/synced".to_string(),
            format!("/h/x/synced/{A}/y"),
            format!("prefix.synced/{A}/y"),
            "plain text".to_string(),
        ] {
            assert_eq!(mask_identifiers(&s), s.as_str(), "{s}");
        }
        // Idempotent.
        let once = mask_identifiers(&format!("skills/synced/{O}_{A}/x")).into_owned();
        assert_eq!(mask_identifiers(&once), once.as_str());
    }
}
