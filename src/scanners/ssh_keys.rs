use crate::models::{PassphraseStatus, SshKey};
use crate::platform::PlatformInfo;
use crate::scanners::Scanner;

pub struct SshKeysScanner;

impl Scanner for SshKeysScanner {
    type Output = Vec<SshKey>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<SshKey> {
        let mut results = Vec::new();
        let ssh_dir = platform.ssh_dir();

        if !crate::scanners::probe_dir(&ssh_dir) {
            return results;
        }

        let Ok(entries) = crate::scanners::probe_read_dir(&ssh_dir) else {
            return results;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !crate::scanners::probe_file(&path) {
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

            // The first line and at most 32 characters after it: enough to name the
            // format and its encryption header, and short of any key material.
            let Some(head) = read_key_head(&path) else {
                continue;
            };
            let (is_key, key_type, has_passphrase) = classify_key(&head.first_line, &head.next);
            if !is_key {
                continue;
            }

            // The comment, from the public half ssh-keygen writes next to the key:
            // `<key file name>.pub`, whatever the key file's own extension. (Before
            // 2026-11-14 an extension-less key such as `id_ed25519` was looked up as
            // `id_ed25519..pub`, so its comment was never found.)
            let pub_path = PathBuf::from(format!("{}.pub", path.display()));
            let comment = crate::scanners::read_bounded(&pub_path).and_then(|c| {
                // Public key format: type base64 comment
                let line = c.lines().next().unwrap_or("");
                let parts: Vec<&str> = line.trim().splitn(3, ' ').collect();
                parts
                    .get(2)
                    .map(|s| crate::scanners::sanitize_display(&crate::scanners::redact_token_shapes(s.trim()), 128))
                    .filter(|s| !s.is_empty())
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

use base64::Engine as _;

/// The longest first line read: `-----BEGIN ENCRYPTED PRIVATE KEY-----` is 37 bytes.
const MAX_FIRST_LINE: usize = 64;

/// What is read of a candidate private key file: its first line and the few characters
/// after it that say whether the key is encrypted ([`tail_len`]).
pub struct KeyHead {
    pub first_line: String,
    pub next: String,
}

/// How many characters after the first line decide the passphrase state, by format.
/// Every count stops inside the format's own header, before any key material:
///
/// - OpenSSH (`openssh-key-v1`): 32 base64 characters = 24 bytes = the 15-byte magic,
///   the cipher name's 4-byte length and its first 5 bytes. An unencrypted key's cipher
///   is `none`; the private section starts far later, after the KDF fields and the
///   public key.
/// - Traditional PEM (`RSA`/`EC`/`DSA PRIVATE KEY`): 4 characters. An encrypted key's
///   second line is `Proc-Type: 4,ENCRYPTED`; an unencrypted one starts its DER there,
///   and 4 base64 characters are the 3 bytes of the outer SEQUENCE header (in an EC key
///   the private scalar starts at the eighth byte, so the old 1 KiB read held all of it).
/// - PKCS#8: none; the first line itself says `ENCRYPTED PRIVATE KEY` or not.
pub fn tail_len(first_line: &str) -> usize {
    if first_line.contains("OPENSSH PRIVATE KEY") {
        32
    } else if ["RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY"]
        .iter()
        .any(|m| first_line.contains(m))
    {
        4
    } else {
        0
    }
}

/// Read a candidate key's head from a regular file. Nothing past it is read.
fn read_key_head(path: &std::path::Path) -> Option<KeyHead> {
    use crate::scanners::telemetry;
    // Regular files only: opening a FIFO with no writer blocks forever.
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
    let Ok(file) = std::fs::File::open(path) else {
        telemetry::note_read(path, "unreadable");
        return None;
    };
    telemetry::note_read(path, "ok");
    read_key_head_from(file)
}

/// [`read_key_head`] over any reader, one byte at a time for the first line (so a short
/// first line never drags the bytes after it into memory), then exactly [`tail_len`]
/// more. `None` when the first line is longer than [`MAX_FIRST_LINE`] or not UTF-8: not
/// a key file.
pub fn read_key_head_from(mut r: impl std::io::Read) -> Option<KeyHead> {
    let mut line = Vec::with_capacity(MAX_FIRST_LINE);
    let mut byte = [0u8; 1];
    loop {
        match r.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                if line.len() == MAX_FIRST_LINE {
                    return None;
                }
                line.push(byte[0]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    let first_line = String::from_utf8(line).ok()?.trim_end_matches('\r').to_string();
    let want = if first_line.contains("PRIVATE KEY") {
        tail_len(&first_line)
    } else {
        0
    };
    let mut next = Vec::with_capacity(want);
    while next.len() < want {
        match r.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => next.push(byte[0]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    Some(KeyHead {
        first_line,
        next: String::from_utf8(next).unwrap_or_default(),
    })
}

/// Classify a potential SSH key file by its first line and the [`tail_len`] characters
/// after it. No program is run and no key material is looked at: before 2026-11-14 an
/// OpenSSH-format key was handed to `ssh-keygen -y -P ""`, which read and tried to
/// decrypt the whole key.
pub fn classify_key(first_line: &str, next: &str) -> (bool, String, PassphraseStatus) {
    // Traditional PEM: an encrypted key's second line is its `Proc-Type` header.
    let pem_status = if next.starts_with("Proc") {
        PassphraseStatus::Encrypted
    } else if next.len() >= 4 {
        PassphraseStatus::NoPassphrase
    } else {
        PassphraseStatus::Unknown
    };

    if first_line.contains("RSA PRIVATE KEY") {
        (true, "rsa".to_string(), pem_status)
    } else if first_line.contains("EC PRIVATE KEY") {
        (true, "ecdsa".to_string(), pem_status)
    } else if first_line.contains("OPENSSH PRIVATE KEY") {
        (true, "openssh".to_string(), openssh_status(next))
    } else if first_line.contains("DSA PRIVATE KEY") {
        (true, "dsa".to_string(), pem_status)
    } else if first_line.contains("ENCRYPTED PRIVATE KEY") {
        // PKCS#8 says it in the label.
        (true, "unknown".to_string(), PassphraseStatus::Encrypted)
    } else if first_line.contains("PRIVATE KEY") {
        (true, "unknown".to_string(), PassphraseStatus::NoPassphrase)
    } else {
        (false, String::new(), PassphraseStatus::Unknown)
    }
}

/// The passphrase state of an `openssh-key-v1` key from the first 32 base64 characters
/// of its body (OpenSSH `PROTOCOL.key`: `"openssh-key-v1\0"`, then `string ciphername`).
/// `none` is an unencrypted key; any other cipher name is an encrypted one. Anything
/// that does not parse is `Unknown`, never "no passphrase".
fn openssh_status(next: &str) -> PassphraseStatus {
    const MAGIC: &[u8] = b"openssh-key-v1\0";
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(next.trim_end()) else {
        return PassphraseStatus::Unknown;
    };
    if bytes.len() < 24 || &bytes[..15] != MAGIC {
        return PassphraseStatus::Unknown;
    }
    let len = u32::from_be_bytes([bytes[15], bytes[16], bytes[17], bytes[18]]);
    match len {
        4 if &bytes[19..23] == b"none" => PassphraseStatus::NoPassphrase,
        // Real cipher names are 10 to 29 characters (`aes256-ctr`,
        // `chacha20-poly1305@openssh.com`) and start with a lowercase letter or digit.
        3..=64 if bytes[19].is_ascii_lowercase() || bytes[19].is_ascii_digit() => PassphraseStatus::Encrypted,
        _ => PassphraseStatus::Unknown,
    }
}
