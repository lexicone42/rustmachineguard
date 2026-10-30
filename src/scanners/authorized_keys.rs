//! `~/.ssh/authorized_keys`: who can log in as this user with a key.
//!
//! The 2026-10-29 trojanized Claude Code extension (`anthropic.claude-code` 2.1.313,
//! served only by the Cursor Marketplace) appended an ssh-ed25519 key commented
//! `svc-telemetry` to `~/.ssh/authorized_keys` and opened a reverse tunnel to its own
//! host, so the key gave the attacker a shell on the developer's machine. It changed no
//! `sshd_config`. Sources:
//! - Cursor, "Claude Code extension security notice", 2026-10-29,
//!   <https://cursor.com/blog/claude-code-extension-security-notice> (IOCs: the key
//!   fingerprint `SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk`, the comment
//!   `svc-telemetry`; "Check for the svc-telemetry key in SSH authorized_keys").
//! - OpenSourceMalware, "Trojanized Claude Code extension plants persistent SSH
//!   backdoor", 2026-10-30,
//!   <https://opensourcemalware.com/blog/trojanized-claude-code-extension-plants-persistent-ssh-backdoor>
//!   (the same fingerprint and comment; the key is an Ed25519 key; no sshd_config change).
//!
//! What is read: `~/.ssh/authorized_keys` and `~/.ssh/authorized_keys2` (sshd's default
//! `AuthorizedKeysFile`), and any other file a readable `/etc/ssh/sshd_config` (and the
//! files its top-level `Include` lines name) sets as `AuthorizedKeysFile`. The usual
//! sshd_config is root-only (0600): then only the defaults are read, and every row says
//! `sshd_config: "unreadable"` (a documented floor). Each file is opened without following
//! a symlink at its final component and bounded at 1 MiB; a symlinked file is listed by
//! its link text and not read.
//!
//! These files hold PUBLIC keys. Each key line is parsed for its options, key type,
//! base64 key blob and comment; the blob is decoded only to compute its OpenSSH
//! fingerprint (`SHA256:` + unpadded base64 of the SHA-256 of the blob, as `ssh-keygen -l`
//! prints it) in-process, and is never stored or printed. Option VALUES (`command="..."`,
//! `from="..."`, `environment="..."`) are not kept, only the option names.
//! Nothing is spawned.

use crate::models::{AuthorizedKey, AuthorizedKeysFile};
use crate::platform::PlatformInfo;
use crate::scanners::sanitize_display;
use base64::Engine as _;
use sha2::Digest as _;
use std::path::{Path, PathBuf};

/// SSH public keys published as attacker keys: `(fingerprint, campaign)`. A key with
/// one of these fingerprints in an authorized_keys file is a backdoor login.
pub const KNOWN_ATTACKER_KEYS: &[(&str, &str)] = &[(
    // Cursor (cursor.com/blog/claude-code-extension-security-notice, 2026-10-29) and
    // OpenSourceMalware (opensourcemalware.com/blog/trojanized-claude-code-extension-
    // plants-persistent-ssh-backdoor, 2026-10-30).
    "SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk",
    "trojanized Claude Code extension 2.1.313 (Cursor Marketplace, 2026-10-29)",
)];

/// Key comments a campaign wrote with its key: `(comment, campaign)`. Matched exactly. The
/// comment is attacker-chosen and a variant build may carry another key, so a matching
/// comment with an unknown fingerprint is still reported (High, not Critical).
pub const BACKDOOR_KEY_COMMENTS: &[(&str, &str)] = &[(
    "svc-telemetry",
    "trojanized Claude Code extension 2.1.313 (Cursor Marketplace, 2026-10-29)",
)];

/// sshd's key types (sshd(8) "AUTHORIZED_KEYS FILE FORMAT"), certificates included.
const KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "sk-ssh-ed25519@openssh.com",
    "ssh-ed25519-cert-v01@openssh.com",
    "ssh-rsa-cert-v01@openssh.com",
    "ssh-dss-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "sk-ssh-ed25519-cert-v01@openssh.com",
];

/// sshd's authorized_keys options (sshd(8)). Any other name is reported as `<other>`.
const OPTION_NAMES: &[&str] = &[
    "agent-forwarding",
    "cert-authority",
    "command",
    "environment",
    "expiry-time",
    "from",
    "no-agent-forwarding",
    "no-port-forwarding",
    "no-pty",
    "no-user-rc",
    "no-x11-forwarding",
    "permitlisten",
    "permitopen",
    "port-forwarding",
    "principals",
    "pty",
    "no-touch-required",
    "verify-required",
    "restrict",
    "tunnel",
    "user-rc",
    "x11-forwarding",
];

/// Keys kept per file (the rest are counted in `key_count`).
const MAX_KEYS_PER_FILE: usize = 500;
/// `AuthorizedKeysFile` paths taken from sshd_config.
const MAX_CONFIG_PATHS: usize = 16;
/// sshd_config files read (the main file plus its `Include`s).
const MAX_CONFIG_FILES: usize = 32;

/// Every authorized_keys file of this home that exists.
pub fn scan(platform: &dyn PlatformInfo) -> Vec<AuthorizedKeysFile> {
    let home = platform.home_dir();
    let ssh_dir = platform.ssh_dir();
    let uid = crate::scanners::home_owner_uid(&home);
    let user = user_name(uid).unwrap_or_else(|| {
        home.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    });
    let (sshd_state, configured) = sshd_authorized_keys_files(&home, &user, uid);
    let mut paths: Vec<(PathBuf, &'static str)> = vec![
        (ssh_dir.join("authorized_keys"), "default"),
        (ssh_dir.join("authorized_keys2"), "default"),
    ];
    for p in configured {
        if !paths.iter().any(|(q, _)| *q == p) {
            paths.push((p, "sshd_config"));
        }
    }
    let mut out = Vec::new();
    for (path, source) in paths {
        if let Some(row) = read_file(&path, source, sshd_state) {
            out.push(row);
        }
    }
    out
}

/// One authorized_keys file, or None when nothing is at the path.
fn read_file(path: &Path, source: &str, sshd_state: &str) -> Option<AuthorizedKeysFile> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    let mut row = AuthorizedKeysFile {
        path: sanitize_display(&path.to_string_lossy(), 512),
        source: source.to_string(),
        sshd_config: sshd_state.to_string(),
        ..Default::default()
    };
    if meta.file_type().is_symlink() {
        // Listed by its link text; not followed (a link into a private key is not opened).
        let target = std::fs::read_link(path)
            .map(|t| t.to_string_lossy().into_owned())
            .unwrap_or_default();
        row.symlink = Some(sanitize_display(&target, 512));
        crate::scanners::telemetry::note_read(path, "refused (symlink)");
        return Some(row);
    }
    if !meta.is_file() {
        return None;
    }
    row.mode = crate::scanners::file_perms(path).map(|(m, _, _)| m);
    row.writable_by = writable_by(path);
    let Some(text) = crate::scanners::read_bounded_nofollow(path, None) else {
        row.unreadable = true;
        return Some(row);
    };
    let mut keys = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        match parse_key_line(t) {
            Some(mut k) => {
                k.line = i + 1;
                row.key_count += 1;
                // An IOC match is never dropped by the per-file cap.
                if keys.len() < MAX_KEYS_PER_FILE || k.known_attacker_key.is_some() || k.backdoor_comment.is_some() {
                    keys.push(k);
                }
            }
            None => row.unparsed_lines += 1,
        }
    }
    row.keys = keys;
    Some(row)
}

/// "file" when the file is writable by group or other, "directory" when its directory
/// is (either lets another local user add a login key). None otherwise.
fn writable_by(path: &Path) -> Option<String> {
    if crate::scanners::is_world_or_group_writable(path) {
        return Some("file".into());
    }
    let dir = path.parent()?;
    if std::fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir()) && crate::scanners::is_world_or_group_writable(dir) {
        return Some("directory".into());
    }
    None
}

/// Parse one authorized_keys line (`[options] keytype base64 [comment]`). None for a
/// line that is not a key line (an SSH1 key, a truncated line, a blob that is not
/// base64).
pub fn parse_key_line(line: &str) -> Option<AuthorizedKey> {
    let line = line.trim();
    let first_end = token_end(line);
    let (options, rest) = if KEY_TYPES.contains(&&line[..first_end]) {
        (Vec::new(), line)
    } else {
        (option_names(&line[..first_end]), line[first_end..].trim_start())
    };
    let type_end = rest.find(char::is_whitespace)?;
    let key_type = &rest[..type_end];
    if !KEY_TYPES.contains(&key_type) {
        return None;
    }
    let rest = rest[type_end..].trim_start();
    let blob_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let blob = base64::engine::general_purpose::STANDARD
        .decode(&rest[..blob_end])
        .ok()?;
    if blob.is_empty() {
        return None;
    }
    let comment = rest[blob_end..].trim();
    let fingerprint = fingerprint_of(&blob);
    let known_attacker_key = KNOWN_ATTACKER_KEYS
        .iter()
        .find(|(f, _)| *f == fingerprint)
        .map(|(_, c)| c.to_string());
    let backdoor_comment = BACKDOOR_KEY_COMMENTS
        .iter()
        .find(|(c, _)| *c == comment)
        .map(|(_, c)| c.to_string());
    Some(AuthorizedKey {
        line: 0,
        key_type: key_type.to_string(),
        fingerprint,
        comment: (!comment.is_empty()).then(|| sanitize_display(&crate::scanners::redact_token_shapes(comment), 128)),
        options,
        known_attacker_key,
        backdoor_comment,
    })
}

/// The OpenSSH SHA-256 fingerprint of a decoded public key blob, as `ssh-keygen -l`
/// prints it: `SHA256:` + base64 without padding.
pub fn fingerprint_of(blob: &[u8]) -> String {
    let digest = sha2::Sha256::digest(blob);
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    )
}

/// Where the first token ends: at whitespace outside double quotes (an option value may
/// be quoted and hold spaces; `\"` inside quotes is an escaped quote).
fn token_end(s: &str) -> usize {
    let mut in_quote = false;
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quote => escaped = true,
            '"' => in_quote = !in_quote,
            c if c.is_whitespace() && !in_quote => return i,
            _ => {}
        }
    }
    s.len()
}

/// The option NAMES of an options field (`no-pty,command="..."` -> `no-pty`, `command`),
/// from the closed [`OPTION_NAMES`] (`<other>` for anything else), in order, once each.
fn option_names(field: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut in_quote = false;
    let mut escaped = false;
    let mut start = 0;
    let push = |opt: &str, out: &mut Vec<String>| {
        let name = opt.split('=').next().unwrap_or("").trim().to_ascii_lowercase();
        if name.is_empty() {
            return;
        }
        let label = OPTION_NAMES
            .iter()
            .find(|n| **n == name)
            .map_or("<other>".to_string(), |n| n.to_string());
        if !out.contains(&label) {
            out.push(label);
        }
    };
    for (i, c) in field.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quote => escaped = true,
            '"' => in_quote = !in_quote,
            ',' if !in_quote => {
                push(&field[start..i], &mut out);
                start = i + 1;
            }
            _ => {}
        }
    }
    push(&field[start..], &mut out);
    out
}

/// The name of the account with this uid, from the passwd database.
pub fn user_name(uid: u32) -> Option<String> {
    #[cfg(unix)]
    {
        let mut buf = vec![0 as libc::c_char; 16 * 1024];
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `pwd`, `buf` and `result` are valid for the call; getpwuid_r writes the
        // entry's strings into `buf` (its length is passed) and sets `result` to `&pwd` on
        // success or to null.
        let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
        if rc != 0 || result.is_null() || pwd.pw_name.is_null() {
            return None;
        }
        // SAFETY: on success `pw_name` points at a NUL-terminated string inside `buf`.
        let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) };
        Some(name.to_string_lossy().into_owned())
    }
    #[cfg(not(unix))]
    {
        let _ = uid;
        None
    }
}

/// `AuthorizedKeysFile` from sshd_config: ("read" | "unreadable" | "absent", the files
/// it names other than nothing). A value inside a `Match` block is not evaluated (sshd
/// applies it only to matching connections): the rest of a file after its first `Match`
/// is skipped.
fn sshd_authorized_keys_files(home: &Path, user: &str, uid: u32) -> (&'static str, Vec<PathBuf>) {
    let main = crate::scanners::system_path("/etc/ssh/sshd_config");
    if std::fs::symlink_metadata(&main).is_err() {
        return ("absent", Vec::new());
    }
    let mut files_read = 0usize;
    let mut value: Option<String> = None;
    let state = match read_config(&main) {
        Some(text) => {
            files_read += 1;
            collect_authorized_keys_value(&text, &mut value, &mut files_read, 0);
            "read"
        }
        None => "unreadable",
    };
    let paths = value
        .map(|v| expand_authorized_keys_files(&v, home, user, uid))
        .unwrap_or_default();
    (state, paths)
}

fn read_config(path: &Path) -> Option<String> {
    // sshd_config may legitimately be a link (configuration management): follow it,
    // bounded, regular files only.
    crate::scanners::read_bounded(path)
}

/// The first `AuthorizedKeysFile` value (sshd keeps the first one it reads), following
/// top-level `Include` lines in order (globs in the final component only; relative paths
/// are under /etc/ssh, as sshd resolves them).
fn collect_authorized_keys_value(text: &str, value: &mut Option<String>, files_read: &mut usize, depth: usize) {
    for line in text.lines() {
        if value.is_some() {
            return;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, rest) = split_keyword(line);
        if key.eq_ignore_ascii_case("match") {
            return;
        }
        if key.eq_ignore_ascii_case("authorizedkeysfile") {
            *value = Some(rest.to_string());
            return;
        }
        if key.eq_ignore_ascii_case("include") && depth < 4 {
            for pat in rest.split_whitespace() {
                for f in expand_include(pat) {
                    if *files_read >= MAX_CONFIG_FILES || value.is_some() {
                        return;
                    }
                    if let Some(t) = read_config(&f) {
                        *files_read += 1;
                        collect_authorized_keys_value(&t, value, files_read, depth + 1);
                    }
                }
            }
        }
    }
}

/// `Keyword value` or `Keyword=value`.
fn split_keyword(line: &str) -> (&str, &str) {
    let end = line.find(|c: char| c.is_whitespace() || c == '=').unwrap_or(line.len());
    let rest = line[end..].trim_start();
    let rest = rest.strip_prefix('=').unwrap_or(rest).trim();
    (&line[..end], rest)
}

/// The files one `Include` argument names, sorted (sshd expands globs with glob(3)).
fn expand_include(pat: &str) -> Vec<PathBuf> {
    let p = if pat.starts_with('/') {
        crate::scanners::system_path(pat)
    } else {
        crate::scanners::system_path("/etc/ssh").join(pat)
    };
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !name.contains(['*', '?']) {
        return vec![p];
    }
    let Some(dir) = p.parent() else { return Vec::new() };
    let Ok(entries) = std::fs::read_dir(dir) else {
        crate::scanners::telemetry::note_read(dir, "unreadable");
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| glob_match(&name, &e.file_name().to_string_lossy()))
        .map(|e| e.path())
        .take(MAX_CONFIG_FILES)
        .collect();
    out.sort();
    out
}

/// `*` and `?` glob over one path component (no character classes).
fn glob_match(pat: &str, name: &str) -> bool {
    fn go(p: &[u8], n: &[u8]) -> bool {
        match (p.first(), n.first()) {
            (None, None) => true,
            (Some(b'*'), _) => go(&p[1..], n) || (!n.is_empty() && go(p, &n[1..])),
            (Some(b'?'), Some(_)) => go(&p[1..], &n[1..]),
            (Some(a), Some(b)) if a == b => go(&p[1..], &n[1..]),
            _ => false,
        }
    }
    // A leading dot is matched only by a literal dot, as glob(3) does.
    if name.starts_with('.') && !pat.starts_with('.') {
        return false;
    }
    go(pat.as_bytes(), name.as_bytes())
}

/// The paths an `AuthorizedKeysFile` value names, after sshd's token expansion (`%%`,
/// `%h` home, `%u` user, `%U` uid; a token with any other `%` escape is skipped) with
/// relative paths under the home. `none` names nothing.
pub fn expand_authorized_keys_files(value: &str, home: &Path, user: &str, uid: u32) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for tok in value.split_whitespace().take(MAX_CONFIG_PATHS) {
        let tok = tok.trim_matches('"');
        if tok.eq_ignore_ascii_case("none") || tok.is_empty() {
            continue;
        }
        let mut s = String::new();
        let mut chars = tok.chars();
        let mut ok = true;
        while let Some(c) = chars.next() {
            if c != '%' {
                s.push(c);
                continue;
            }
            match chars.next() {
                Some('%') => s.push('%'),
                Some('h') => s.push_str(&home.to_string_lossy()),
                Some('u') => s.push_str(user),
                Some('U') => s.push_str(&uid.to_string()),
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            continue;
        }
        let p = if let Some(rest) = s.strip_prefix("~/") {
            home.join(rest)
        } else if s.starts_with('/') {
            PathBuf::from(&s)
        } else {
            home.join(&s)
        };
        out.push(p);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_are_named_never_valued() {
        assert_eq!(
            option_names(r#"no-pty,command="echo a,b \"c\" d",from="10.0.0.1",bogus"#),
            vec!["no-pty", "command", "from", "<other>"]
        );
    }

    #[test]
    fn a_line_with_quoted_spaces_in_options_parses() {
        // A synthetic blob: the fingerprint is whatever its bytes hash to.
        let blob = base64::engine::general_purpose::STANDARD.encode(b"\0\0\0\x0bssh-ed25519synthetic");
        let line = format!(r#"command="echo hi there",no-pty ssh-ed25519 {blob} me@host"#);
        let k = parse_key_line(&line).unwrap();
        assert_eq!(k.key_type, "ssh-ed25519");
        assert_eq!(k.options, vec!["command", "no-pty"]);
        assert_eq!(k.comment.as_deref(), Some("me@host"));
        assert!(k.fingerprint.starts_with("SHA256:") && !k.fingerprint.ends_with('='));
        assert!(!format!("{k:?}").contains(&blob), "the blob is never kept");
    }

    #[test]
    fn non_key_lines_do_not_parse() {
        assert!(parse_key_line("1024 35 1234567 old-ssh1-key").is_none());
        assert!(parse_key_line("ssh-ed25519 !!notbase64!! x").is_none());
        assert!(parse_key_line("ssh-ed25519").is_none());
    }

    #[test]
    fn authorized_keys_file_tokens_expand_like_sshd() {
        let home = Path::new("/home/u");
        let got = expand_authorized_keys_files(
            ".ssh/authorized_keys /etc/ssh/keys/%u %h/.ssh/k_%U none /x/%i",
            home,
            "u",
            1000,
        );
        assert_eq!(
            got,
            vec![
                PathBuf::from("/home/u/.ssh/authorized_keys"),
                PathBuf::from("/etc/ssh/keys/u"),
                PathBuf::from("/home/u/.ssh/k_1000"),
            ]
        );
    }

    #[test]
    fn first_value_wins_and_match_blocks_are_not_evaluated() {
        let mut v = None;
        let mut n = 0;
        collect_authorized_keys_value(
            "# c\nPort 22\nAuthorizedKeysFile=.ssh/a .ssh/b\nAuthorizedKeysFile .ssh/c\n",
            &mut v,
            &mut n,
            0,
        );
        assert_eq!(v.as_deref(), Some(".ssh/a .ssh/b"));
        let mut v = None;
        collect_authorized_keys_value("Match User x\n  AuthorizedKeysFile /k\n", &mut v, &mut n, 0);
        assert_eq!(v, None);
    }

    #[test]
    fn globs_match_one_component() {
        assert!(glob_match("*.conf", "50-cloud.conf"));
        assert!(!glob_match("*.conf", "50-cloud.conf.bak"));
        assert!(!glob_match("*.conf", ".hidden.conf"));
        assert!(glob_match("a?c", "abc"));
    }
}
