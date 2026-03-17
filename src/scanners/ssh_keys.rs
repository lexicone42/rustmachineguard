use crate::models::SshKey;
use crate::platform::PlatformInfo;
use crate::scanners::Scanner;

pub struct SshKeysScanner;

impl Scanner for SshKeysScanner {
    type Output = Vec<SshKey>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<SshKey> {
        let mut results = Vec::new();
        let ssh_dir = platform.ssh_dir();

        if !ssh_dir.is_dir() {
            return results;
        }

        let Ok(entries) = std::fs::read_dir(&ssh_dir) else {
            return results;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let fname = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };

            // Only look at private key files (skip .pub, known_hosts, config, etc.)
            if fname.ends_with(".pub")
                || fname == "known_hosts"
                || fname == "known_hosts.old"
                || fname == "config"
                || fname == "authorized_keys"
            {
                continue;
            }

            // Read first line to detect key type
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let first_line = content.lines().next().unwrap_or("");

            let (is_key, key_type, has_passphrase) = classify_key(first_line, &content, &path);
            if !is_key {
                continue;
            }

            // Try to read the comment from the corresponding .pub file
            let pub_path = path.with_extension(format!(
                "{}.pub",
                path.extension().and_then(|e| e.to_str()).unwrap_or("")
            ));
            let pub_path = if pub_path == path {
                PathBuf::from(format!("{}.pub", path.display()))
            } else {
                pub_path
            };
            let comment = std::fs::read_to_string(&pub_path)
                .ok()
                .and_then(|c| {
                    // Public key format: type base64 comment
                    let parts: Vec<&str> = c.trim().splitn(3, ' ').collect();
                    parts.get(2).map(|s| s.to_string())
                });

            results.push(SshKey {
                path: path.display().to_string(),
                key_type,
                has_passphrase,
                comment,
            });
        }

        results
    }
}

use std::path::PathBuf;

/// Classify a potential SSH key file by its header.
fn classify_key(first_line: &str, content: &str, path: &std::path::Path) -> (bool, String, bool) {
    let pem_encrypted = content.contains("ENCRYPTED");

    if first_line.contains("RSA PRIVATE KEY") {
        (true, "rsa".to_string(), pem_encrypted)
    } else if first_line.contains("EC PRIVATE KEY") || first_line.contains("ECDSA") {
        (true, "ecdsa".to_string(), pem_encrypted)
    } else if first_line.contains("OPENSSH PRIVATE KEY") {
        // OpenSSH format: "ENCRYPTED" marker does NOT appear in the PEM text
        // for bcrypt-protected keys. Probe with ssh-keygen instead.
        let has_passphrase = probe_passphrase(path);
        (true, "openssh".to_string(), has_passphrase)
    } else if first_line.contains("DSA PRIVATE KEY") {
        (true, "dsa".to_string(), pem_encrypted)
    } else if first_line.contains("PRIVATE KEY") {
        (true, "unknown".to_string(), pem_encrypted)
    } else {
        (false, String::new(), false)
    }
}

/// Use ssh-keygen to probe whether a key file is passphrase-protected.
/// Returns true if the key has a passphrase, false if it doesn't,
/// and defaults to false (unknown) if ssh-keygen fails.
fn probe_passphrase(path: &std::path::Path) -> bool {
    // `ssh-keygen -y -P "" -f <path>` tries to extract the public key
    // with an empty passphrase. Exit 0 = no passphrase, non-zero = has one.
    let result = std::process::Command::new("ssh-keygen")
        .args(["-y", "-P", "", "-f"])
        .arg(path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match result {
        Ok(status) => !status.success(), // non-zero = has passphrase
        Err(_) => false,                 // ssh-keygen unavailable
    }
}
