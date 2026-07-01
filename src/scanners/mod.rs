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
pub mod ide;
pub mod marketplaces;
pub mod mcp;
pub mod mcp_probe;
pub mod node_packages;
pub mod notebook_servers;
pub mod package_configs;
pub mod rules_files;
pub mod shell_configs;
pub mod skills;
pub mod ssh_keys;
pub mod transcripts;

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

/// Read only the first N bytes of a file (for key header detection).
pub fn read_head(path: &std::path::Path, max_bytes: usize) -> Option<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; max_bytes];
    let n = file.read(&mut buf).ok()?;
    buf.truncate(n);
    String::from_utf8(buf).ok()
}
