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

/// Convenience: check if a process with the given name is running.
pub fn is_process_running(name: &str) -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        std::process::Command::new("pgrep")
            .arg("-x")
            .arg(name)
            .output()
            .is_ok_and(|o| o.status.success())
    }
}

/// Get version from a binary by running `binary --version` and extracting the first version-like string.
pub fn get_binary_version(binary: &str) -> Option<String> {
    let output = std::process::Command::new(binary)
        .arg("--version")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let text = if text.is_empty() {
        String::from_utf8_lossy(&output.stderr)
    } else {
        text
    };
    extract_version(&text)
}

/// Extract a semver-like version from text.
fn extract_version(text: &str) -> Option<String> {
    // Match patterns like "1.2.3", "v1.2.3", "1.2.3-beta1"
    let re_like = text
        .split_whitespace()
        .find(|w| {
            let w = w.strip_prefix('v').unwrap_or(w);
            w.chars().next().is_some_and(|c| c.is_ascii_digit())
                && w.contains('.')
        })?;
    let v = re_like.strip_prefix('v').unwrap_or(re_like);
    Some(v.trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-').to_string())
}

/// Trait for all scanners.
pub trait Scanner {
    type Output;
    fn scan(&self, platform: &dyn PlatformInfo) -> Self::Output;
}
