use crate::models::CloudCredential;
use crate::platform::PlatformInfo;
use crate::scanners::Scanner;

pub struct CloudCredentialsScanner;

impl Scanner for CloudCredentialsScanner {
    type Output = Vec<CloudCredential>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<CloudCredential> {
        let mut results = Vec::new();

        // AWS credentials
        let aws_creds = platform.aws_credentials_path();
        if crate::scanners::probe_file(&aws_creds) {
            let profiles = extract_ini_sections(&aws_creds);
            results.push(CloudCredential {
                provider: "AWS".to_string(),
                credential_type: "credentials file".to_string(),
                config_path: aws_creds.display().to_string(),
                profiles,
            });
        }

        // AWS config (may have SSO profiles)
        let aws_config = aws_creds.parent().map(|p| p.join("config"));
        if let Some(ref cfg) = aws_config
            && crate::scanners::probe_file(cfg)
        {
            let profiles = extract_ini_sections(cfg)
                .into_iter()
                .map(|p| p.strip_prefix("profile ").unwrap_or(&p).to_string())
                .collect();
            results.push(CloudCredential {
                provider: "AWS".to_string(),
                credential_type: "config file (SSO/profiles)".to_string(),
                config_path: cfg.display().to_string(),
                profiles,
            });
        }

        // GCP
        let gcloud_dir = platform.gcloud_config_dir();
        if crate::scanners::probe_dir(&gcloud_dir) {
            let mut gcp_cred_types = Vec::new();

            // Application default credentials
            let adc = gcloud_dir.join("application_default_credentials.json");
            if crate::scanners::probe_file(&adc) {
                gcp_cred_types.push("application default credentials".to_string());
            }

            // Service account keys in the directory. A key file holds `private_key`, so
            // each `.json` is classified from its first [`GCLOUD_HEAD_BYTES`] only, read
            // without following a link ([`gcloud_json_kind`]): Google writes `"type"` as
            // the first member, ahead of the key. ADC is reported above by name and never
            // opened here.
            let mut sa_keys = 0usize;
            let mut unknown = 0usize;
            for e in crate::scanners::probe_read_dir(&gcloud_dir)
                .into_iter()
                .flatten()
                .flatten()
            {
                let path = e.path();
                if path.extension().is_none_or(|ext| ext != "json")
                    || path
                        .file_name()
                        .is_some_and(|n| n == "application_default_credentials.json")
                {
                    continue;
                }
                match gcloud_json_kind(&path) {
                    GcloudJsonKind::ServiceAccount => sa_keys += 1,
                    GcloudJsonKind::Unknown => unknown += 1,
                    GcloudJsonKind::Other => {}
                }
            }
            if sa_keys > 0 {
                gcp_cred_types.push(format!("{sa_keys} service account key(s)"));
            }
            if unknown > 0 {
                gcp_cred_types.push(format!("{unknown} unclassified JSON file(s)"));
            }

            // Active config
            let properties = gcloud_dir.join("properties");
            let active_account = if crate::scanners::probe_file(&properties) {
                crate::scanners::read_bounded(&properties).and_then(|c| {
                    c.lines()
                        .find(|l| l.starts_with("account"))
                        .map(|l| l.split('=').nth(1).unwrap_or("").trim().to_string())
                })
            } else {
                None
            };

            if !gcp_cred_types.is_empty() || active_account.is_some() {
                let profiles = active_account.into_iter().collect();
                results.push(CloudCredential {
                    provider: "GCP".to_string(),
                    credential_type: gcp_cred_types.join(", "),
                    config_path: gcloud_dir.display().to_string(),
                    profiles,
                });
            }
        }

        // Azure
        let azure_dir = platform.azure_config_dir();
        if crate::scanners::probe_dir(&azure_dir) {
            let az_profile = azure_dir.join("azureProfile.json");
            let profiles = if crate::scanners::probe_file(&az_profile) {
                crate::scanners::read_bounded(&az_profile)
                    .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
                    .and_then(|v| {
                        v["subscriptions"].as_array().map(|arr| {
                            arr.iter()
                                .filter_map(|sub| sub["name"].as_str().map(|s| s.to_string()))
                                .collect()
                        })
                    })
                    .unwrap_or_default()
            } else {
                vec![]
            };

            let has_tokens = crate::scanners::probe_file(&azure_dir.join("msal_token_cache.json"))
                || crate::scanners::probe_file(&azure_dir.join("accessTokens.json"));

            if has_tokens || !profiles.is_empty() {
                results.push(CloudCredential {
                    provider: "Azure".to_string(),
                    credential_type: if has_tokens {
                        "cached tokens".to_string()
                    } else {
                        "profile".to_string()
                    },
                    config_path: azure_dir.display().to_string(),
                    profiles,
                });
            }
        }

        results
    }
}

/// Section names of an INI file that holds secrets (`~/.aws/credentials` holds
/// `aws_secret_access_key`, and `~/.aws/config` may). The file is streamed one line at a
/// time through a fixed window that is overwritten by the next line: only `[section]`
/// lines are kept, and a key line is never copied out of the window, so no secret value
/// is retained or returned. A user-scope file: a dotfile-manager link is followed, as
/// [`crate::scanners::read_bounded`] does, but only to a regular file, and at most
/// [`crate::scanners::MAX_CONFIG_SIZE`] bytes are streamed.
fn extract_ini_sections(path: &std::path::Path) -> Vec<String> {
    use std::io::{BufRead, Read};
    let Ok(meta) = std::fs::metadata(path) else {
        crate::scanners::telemetry::note_read(path, "missing");
        return Vec::new();
    };
    if !meta.is_file() {
        crate::scanners::telemetry::note_read(path, "not a regular file");
        return Vec::new();
    }
    let Ok(file) = std::fs::File::open(path) else {
        crate::scanners::telemetry::note_read(path, "unreadable");
        return Vec::new();
    };
    crate::scanners::telemetry::note_read(path, "ok");
    let mut reader = std::io::BufReader::with_capacity(4096, file.take(crate::scanners::MAX_CONFIG_SIZE));
    let mut line = Vec::with_capacity(256);
    let mut out = Vec::new();
    loop {
        line.clear();
        // A line longer than the window is read in pieces; only a piece that starts a
        // line can be a header, and a header longer than 256 bytes is not a profile name.
        match reader.by_ref().take(256).read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let complete = line.ends_with(b"\n");
        let trimmed = line.trim_ascii();
        if complete && trimmed.starts_with(b"[") && trimmed.ends_with(b"]") && trimmed.len() > 2 {
            out.push(String::from_utf8_lossy(&trimmed[1..trimmed.len() - 1]).into_owned());
        }
        if !complete {
            // Drain the rest of an over-long line without keeping it.
            let _ = reader.skip_until(b'\n');
        }
        line.fill(0);
    }
    out
}

/// Bytes of a gcloud `.json` read to classify it. A service-account key file is ~2.3 KiB
/// and opens with `"type": "service_account"`; its `private_key` comes after
/// `private_key_id`, so the head is enough for the type and nothing past it is read.
pub const GCLOUD_HEAD_BYTES: usize = 4096;

/// What a gcloud `.json` is, judged from its head only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcloudJsonKind {
    /// Top-level `"type": "service_account"`.
    ServiceAccount,
    /// Not JSON, or JSON whose top-level `"type"` is something else or absent within a
    /// file that fit in the head.
    Other,
    /// The head ended before a top-level `"type"` was seen: more would have to be read
    /// to tell, and rmguard does not read more.
    Unknown,
}

#[cfg(debug_assertions)]
static HEAD_BYTES_READ: std::sync::Mutex<Vec<(std::path::PathBuf, usize)>> = std::sync::Mutex::new(Vec::new());

/// Debug builds: how many bytes [`gcloud_json_kind`] read from `path` (the last time it
/// classified it). Tests use it to prove a key file's `private_key` region is never read.
#[cfg(debug_assertions)]
pub fn debug_head_bytes_read(path: &std::path::Path) -> Option<usize> {
    let v = HEAD_BYTES_READ.lock().unwrap_or_else(|e| e.into_inner());
    v.iter().rev().find(|(p, _)| p == path).map(|(_, n)| *n)
}

/// Classify a gcloud `.json` from its first [`GCLOUD_HEAD_BYTES`] bytes (no-follow).
pub fn gcloud_json_kind(path: &std::path::Path) -> GcloudJsonKind {
    let Some(mut head) = crate::scanners::read_head_bytes_nofollow(path, GCLOUD_HEAD_BYTES) else {
        // A link (to a key kept elsewhere) is not followed; it is still a JSON file in
        // the credentials directory whose kind rmguard did not establish.
        return if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
            GcloudJsonKind::Unknown
        } else {
            GcloudJsonKind::Other
        };
    };
    #[cfg(debug_assertions)]
    HEAD_BYTES_READ
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((path.to_path_buf(), head.len()));
    let whole = head.len() < GCLOUD_HEAD_BYTES;
    let kind = match json_top_level_type(&head) {
        TypeScan::Found(true) => GcloudJsonKind::ServiceAccount,
        TypeScan::Found(false) | TypeScan::Absent | TypeScan::NotJson => GcloudJsonKind::Other,
        TypeScan::Truncated if whole => GcloudJsonKind::Other,
        TypeScan::Truncated => GcloudJsonKind::Unknown,
    };
    head.fill(0);
    kind
}

/// Result of [`json_top_level_type`].
#[derive(Debug, PartialEq, Eq)]
pub enum TypeScan {
    /// A top-level `"type"` string was found; true when it is `service_account`.
    Found(bool),
    /// The top-level object closed with no `"type"` member.
    Absent,
    /// The input ended inside the object before a `"type"` member.
    Truncated,
    /// Not a JSON object.
    NotJson,
}

/// Find the top-level `"type"` member of a JSON object in `b` (a head of the file) and
/// compare its string value with `service_account`, stopping there. Other members'
/// values are skipped without being decoded or copied. A tiny tokenizer, not a parser:
/// it only needs to find member boundaries, so it tracks strings (with escapes) and
/// nesting depth.
pub fn json_top_level_type(b: &[u8]) -> TypeScan {
    let mut i = 0usize;
    if b.starts_with(&[0xEF, 0xBB, 0xBF]) {
        i = 3;
    }
    let ws = |b: &[u8], mut i: usize| {
        while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\r') {
            i += 1;
        }
        i
    };
    // End of a string starting at `i` (on the opening quote): index after the closing
    // quote, or None when the input ends first.
    let str_end = |b: &[u8], mut i: usize| -> Option<usize> {
        i += 1;
        while i < b.len() {
            match b[i] {
                b'\\' => i += 2,
                b'"' => return Some(i + 1),
                _ => i += 1,
            }
        }
        None
    };
    i = ws(b, i);
    if i >= b.len() {
        return TypeScan::Truncated;
    }
    if b[i] != b'{' {
        return TypeScan::NotJson;
    }
    i += 1;
    loop {
        i = ws(b, i);
        if i >= b.len() {
            return TypeScan::Truncated;
        }
        match b[i] {
            b'}' => return TypeScan::Absent,
            b',' => {
                i += 1;
                continue;
            }
            b'"' => {}
            _ => return TypeScan::NotJson,
        }
        let Some(kend) = str_end(b, i) else {
            return TypeScan::Truncated;
        };
        let key = &b[i + 1..kend - 1];
        i = ws(b, kend);
        if i >= b.len() {
            return TypeScan::Truncated;
        }
        if b[i] != b':' {
            return TypeScan::NotJson;
        }
        i = ws(b, i + 1);
        if i >= b.len() {
            return TypeScan::Truncated;
        }
        if key == b"type" {
            if b[i] != b'"' {
                return TypeScan::Found(false);
            }
            let Some(vend) = str_end(b, i) else {
                return TypeScan::Truncated;
            };
            return TypeScan::Found(&b[i + 1..vend - 1] == b"service_account");
        }
        // Skip the value: a string, or a run up to the next top-level `,` / `}` that
        // tracks nested brackets and strings.
        let mut depth = 0usize;
        loop {
            if i >= b.len() {
                return TypeScan::Truncated;
            }
            match b[i] {
                b'"' => match str_end(b, i) {
                    Some(e) => i = e,
                    None => return TypeScan::Truncated,
                },
                b'{' | b'[' => {
                    depth += 1;
                    i += 1;
                }
                b'}' | b']' if depth > 0 => {
                    depth -= 1;
                    i += 1;
                }
                b',' | b'}' if depth == 0 => break,
                b']' => return TypeScan::NotJson,
                _ => i += 1,
            }
        }
    }
}

/// Parse section headers from INI content (pure function, testable).
pub fn parse_ini_sections(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.len() > 2 {
                Some(trimmed[1..trimmed.len() - 1].to_string())
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("rmg-gcloud-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A service-account key whose `private_key` sits after 4 KiB of padding: the type
    /// (first, as Google writes it) classifies the file, and no byte at or past the key
    /// is read. Fails on the base, which read the whole file (and had no counter).
    #[test]
    fn service_account_key_is_classified_from_the_head_only() {
        let d = scratch("sa");
        let canary = format!("{}{}", "-----BEGIN PRIVATE", " KEY-----\\nPKCANARYBODY");
        let pad = "a".repeat(5000);
        let text = format!(
            "{{\n  \"type\": \"service_account\",\n  \"project_id\": \"p\",\n  \"private_key_id\": \"k\",\n  \"pad\": \"{pad}\",\n  \"private_key\": \"{canary}\"\n}}\n"
        );
        let key_at = text.find("\"private_key\":").unwrap();
        assert!(key_at > GCLOUD_HEAD_BYTES);
        let p = d.join("sa.json");
        std::fs::write(&p, &text).unwrap();
        assert_eq!(gcloud_json_kind(&p), GcloudJsonKind::ServiceAccount);
        let read = debug_head_bytes_read(&p).expect("the classifier recorded its read");
        assert!(read <= GCLOUD_HEAD_BYTES, "read {read} bytes");
        assert!(
            read < key_at,
            "the private_key region (at {key_at}) was read ({read} bytes)"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// `"type"` past the head is not looked for: the file is "unknown", never read further.
    #[test]
    fn type_past_the_head_is_unknown() {
        let d = scratch("late");
        let text = format!("{{\"pad\": \"{}\", \"type\": \"service_account\"}}", "b".repeat(6000));
        let p = d.join("late.json");
        std::fs::write(&p, &text).unwrap();
        assert_eq!(gcloud_json_kind(&p), GcloudJsonKind::Unknown);
        assert!(debug_head_bytes_read(&p).unwrap() <= GCLOUD_HEAD_BYTES);
        // A small file with no top-level type is simply something else.
        let q = d.join("small.json");
        std::fs::write(&q, "{\"last_update_check\": 1}").unwrap();
        assert_eq!(gcloud_json_kind(&q), GcloudJsonKind::Other);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn linked_json_is_unknown_and_not_followed() {
        let d = scratch("link");
        let target = d.join("elsewhere.json");
        std::fs::write(&target, "{\"type\": \"service_account\"}").unwrap();
        let link = d.join("key.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(gcloud_json_kind(&link), GcloudJsonKind::Unknown);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn top_level_type_tokenizer() {
        assert_eq!(
            json_top_level_type(br#"{"type":"service_account"}"#),
            TypeScan::Found(true)
        );
        assert_eq!(
            json_top_level_type(b"\xEF\xBB\xBF {\n \"type\" : \"authorized_user\"}"),
            TypeScan::Found(false)
        );
        // A nested "type" and a "type" inside a string value are not the member.
        assert_eq!(
            json_top_level_type(
                br#"{"a":{"type":"service_account"},"b":"\"type\": \"service_account\"","c":[1,{"type":"x"}]}"#
            ),
            TypeScan::Absent
        );
        assert_eq!(
            json_top_level_type(br#"{"a":[1,2],"type":"service_account"}"#),
            TypeScan::Found(true)
        );
        assert_eq!(json_top_level_type(br#"{"a":"unterminated"#), TypeScan::Truncated);
        assert_eq!(json_top_level_type(br#"{"type":"service_acc"#), TypeScan::Truncated);
        assert_eq!(json_top_level_type(b"[1]"), TypeScan::NotJson);
        assert_eq!(json_top_level_type(br#"{"type":1}"#), TypeScan::Found(false));
    }

    /// `~/.aws/credentials` is streamed: section names come back, and no key line does.
    #[test]
    fn ini_sections_are_streamed_without_values() {
        let d = scratch("ini");
        let secret = format!("{}{}", "AWSCANARY", "SECRETVALUE");
        let long = "x".repeat(10_000);
        let text = format!(
            "[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = {secret}\n\
             note = {long}[notasection]\n[profile work]\naws_secret_access_key={secret}\n  [indented]  \n"
        );
        let p = d.join("credentials");
        std::fs::write(&p, &text).unwrap();
        let got = extract_ini_sections(&p);
        assert_eq!(got, vec!["default", "profile work", "indented"]);
        assert!(!got.iter().any(|s| s.contains(&secret)));
        let _ = std::fs::remove_dir_all(&d);
    }
}
