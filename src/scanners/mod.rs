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
    text.split(' ')
        .map(|tok| {
            // URL userinfo.
            if let Some(scheme_end) = tok.find("://") {
                let after = &tok[scheme_end + 3..];
                let authority_end = after.find(['/', '?', '#']).unwrap_or(after.len());
                if let Some(at) = after[..authority_end].rfind('@') {
                    return format!(
                        "{}://<redacted>@{}",
                        &tok[..scheme_end],
                        &after[at + 1..]
                    );
                }
            }
            // key=value where the key names a secret. Split on the FIRST '=' so a
            // base64 value containing '=' is still fully covered.
            if let Some((k, v)) = tok.split_once('=')
                && !v.is_empty()
            {
                let bare = k.trim_start_matches(|c: char| !c.is_ascii_alphanumeric());
                if crate::scanners::env_files::is_secret_key_name(bare) {
                    return format!("{k}=<redacted>");
                }
            }
            tok.to_string()
        })
        .collect::<Vec<_>>()
        .join(" ")
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
    let authority = after_scheme
        .split(['/', '?', '#'])
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
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    if meta.len() > MAX_CONFIG_SIZE {
        eprintln!(
            "warning: skipping {} ({} bytes exceeds {} byte limit)",
            path.display(),
            meta.len(),
            MAX_CONFIG_SIZE
        );
        return None;
    }
    let mut buf = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_CONFIG_SIZE)
        .read_to_string(&mut buf)
        .ok()?;
    Some(buf)
}

/// Read the first N raw BYTES of a file. Unlike [`read_head`], this does not require
/// valid UTF-8, so it works for magic-byte checks on binaries.
pub fn read_head_bytes(path: &std::path::Path, max_bytes: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; max_bytes];
    let n = file.read(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

/// Read only the first N bytes of a file (for key header detection).
pub fn read_head(path: &std::path::Path, max_bytes: usize) -> Option<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; max_bytes];
    let n = file.read(&mut buf).ok()?;
    buf.truncate(n);
    String::from_utf8(buf).ok()
}
