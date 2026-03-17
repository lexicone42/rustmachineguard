pub mod ai_frameworks;
pub mod ai_tools;
pub mod cloud_credentials;
pub mod container_tools;
pub mod extensions;
pub mod ide;
pub mod mcp;
pub mod node_packages;
pub mod notebook_servers;
pub mod shell_configs;
pub mod ssh_keys;

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

/// Maximum config file size we'll read (1 MB).
pub const MAX_CONFIG_SIZE: u64 = 1_048_576;

/// Check file size before reading. Returns None if file is too large.
pub fn read_bounded(path: &std::path::Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_CONFIG_SIZE {
        return None;
    }
    std::fs::read_to_string(path).ok()
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
