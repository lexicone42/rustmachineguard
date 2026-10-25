//! End-to-end tests for the round-3c follow-ups:
//! - T1: Mistral Vibe's version is read from its venv's `dist-info`, not `vibe --version`;
//! - T2: SSH keys without a passphrase are one finding per home;
//! - T3: a toxic-flow High needs a leg a connected server supplies;
//! - T4: MCP server args keep a short-flag cluster's value (`-sk https://x`).
//!
//! Each test builds a temp HOME, runs the real binary with only the scanners it needs and
//! checks positive fixtures next to negative controls.
//!
//! `RMGUARD_TEST_BIN` runs another binary in place of the one under test. Severity and
//! title checks are made on the binary's own HTML report ([`binary_findings`]), not only
//! on this crate's `collect_findings`, so they hold for that binary. Pointed at a build
//! of bb1fc66, the four behaviour tests fail (vibe 9.9.9 from a spawn; three per-key SSH
//! Highs; a mentions-only toxic flow graded High; `-sk <redacted>`). The two
//! server-backed toxic-flow tests and the Vibe fallback controls pass there by design:
//! they pin behaviour that must not change.
#![cfg(unix)]

use rustmachineguard::analysis::{Finding, Severity, collect_findings};
use rustmachineguard::models::{PassphraseStatus, ScanReport, SshKey};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
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
];

/// A fresh temp directory (mode 0755), canonicalized.
fn temp_home(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rmg-r3c-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    chmod(&d, 0o755);
    fs::canonicalize(&d).unwrap()
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn bin() -> String {
    std::env::var("RMGUARD_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_rmguard").to_string())
}

/// Run rmguard against `home` with only `keep` scanners and `PATH` = `path`, from `home`.
fn run(home: &Path, keep: &[&str], path: &str) -> String {
    run_format(home, keep, path, "json")
}

fn run_format(home: &Path, keep: &[&str], path: &str, format: &str) -> String {
    let skip: Vec<&str> = ALL_LABELS.iter().copied().filter(|l| !keep.contains(l)).collect();
    let out = Command::new(bin())
        .args(["--skip", &skip.join(","), "--format", format])
        .env("HOME", home)
        .env("PATH", path)
        .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
        .env("NO_COLOR", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("RMGUARD_TRACE")
        .env_remove("VIBE_HOME")
        .env_remove("UV_TOOL_DIR")
        .env_remove("PIPX_HOME")
        .env_remove("XDG_DATA_HOME")
        .current_dir(home)
        .output()
        .expect("run rmguard");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn scan(home: &Path, keep: &[&str]) -> (String, Value, ScanReport, Vec<Finding>) {
    let text = run(home, keep, "/usr/bin:/bin");
    let v: Value = serde_json::from_str(&text).expect("report json");
    let report: ScanReport = serde_json::from_str(&text).expect("report json");
    let findings = collect_findings(&report);
    (text, v, report, findings)
}

/// The findings the BINARY grades, as (severity label, category, title), read back from
/// its HTML report: `collect_findings` in this test is the library under test, so only
/// this shows what a `RMGUARD_TEST_BIN` build reports. Titles are unescaped.
fn binary_findings(home: &Path, keep: &[&str]) -> Vec<(String, String, String)> {
    let html = run_format(home, keep, "/usr/bin:/bin", "html");
    let unescape = |s: &str| {
        s.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#x27;", "'")
            .replace("&amp;", "&")
    };
    let span = |part: &str, class: &str| -> String {
        let open = format!("<span class=\"{class}\">");
        part.split_once(&open)
            .and_then(|(_, r)| r.split_once("</span>"))
            .map(|(v, _)| unescape(v))
            .unwrap_or_default()
    };
    html.split("<details class=\"finding ")
        .skip(1)
        .map(|part| {
            let cat = span(part, "cat");
            (
                span(part, "sev"),
                cat.trim_start_matches("· ").to_string(),
                span(part, "title"),
            )
        })
        .collect()
}

fn dump(findings: &[Finding]) -> String {
    findings
        .iter()
        .map(|f| {
            format!(
                "[{}] {} | {} | {} | {}\n",
                f.severity.label(),
                f.category,
                f.title,
                f.location,
                f.evidence.as_deref().unwrap_or("")
            )
        })
        .collect()
}

// ── T1: Mistral Vibe version from dist-info ─────────────────────────────────────────────

/// A uv tool venv for `mistral-vibe` under `home`, with `vibe` linked from
/// `~/.local/bin`. The `vibe` script is executable (so PATH lookup finds it) but must
/// never run: it prints a different version and leaves a marker file.
fn vibe_tool(home: &Path, dist_dir: &str, metadata: &str, venv_marker: bool) -> (PathBuf, PathBuf) {
    let venv = home.join(".local/share/uv/tools/mistral-vibe");
    let marker = home.join("vibe-was-spawned");
    let script = venv.join("bin/vibe");
    write(
        &script,
        &format!("#!/bin/sh\ntouch '{}'\necho 'vibe 9.9.9'\n", marker.display()),
    );
    chmod(&script, 0o755);
    if venv_marker {
        write(&venv.join("pyvenv.cfg"), "home = /usr/bin\nversion_info = 3.13.0\n");
    }
    let site = venv.join("lib/python3.13/site-packages");
    write(&site.join(dist_dir).join("METADATA"), metadata);
    write(
        &site.join("mistralai-2.0.0.dist-info/METADATA"),
        "Name: mistralai\nVersion: 2.0.0\n",
    );
    let link_dir = home.join(".local/bin");
    fs::create_dir_all(&link_dir).unwrap();
    std::os::unix::fs::symlink(&script, link_dir.join("vibe")).unwrap();
    (link_dir, marker)
}

fn vibe_version(home: &Path, link_dir: &Path) -> Value {
    let text = run(home, &["ai"], &format!("{}:/usr/bin:/bin", link_dir.display()));
    let v: Value = serde_json::from_str(&text).unwrap();
    v["ai_agents_and_tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "Mistral Vibe")
        .unwrap_or_else(|| panic!("no vibe row: {text}"))["version"]
        .clone()
}

/// Fails on bb1fc66: it runs `vibe --version`, so the row says 9.9.9 and the marker file
/// exists.
#[test]
fn vibe_version_comes_from_the_uv_tool_dist_info_without_a_spawn() {
    let home = temp_home("vibe-dist");
    let meta = "Metadata-Version: 2.4\nName: mistral-vibe\nVersion: 2.5.0\n\nVersion: 6.6.6 in the README\n";
    let (links, marker) = vibe_tool(&home, "mistral_vibe-2.5.0.dist-info", meta, true);
    assert_eq!(vibe_version(&home, &links), "2.5.0");
    assert!(!marker.exists(), "vibe --version was run");
    // The library entry point too: the PATH link resolves into the venv.
    assert_eq!(
        rustmachineguard::scanners::ai_tools::venv_dist_version(&links.join("vibe"), "mistral-vibe").as_deref(),
        Some("2.5.0")
    );
    let _ = fs::remove_dir_all(&home);
}

/// Negative controls: each falls back to the spawn (9.9.9, marker written): METADATA
/// naming another project, a version that disagrees with the directory name, no
/// `pyvenv.cfg` (not a venv).
#[test]
fn vibe_version_falls_back_to_the_spawn_when_the_dist_info_does_not_answer() {
    for (tag, dir, meta, venv) in [
        (
            "other-name",
            "mistral_vibe-2.5.0.dist-info",
            "Name: not-vibe\nVersion: 2.5.0\n",
            true,
        ),
        (
            "mismatch",
            "mistral_vibe-2.5.0.dist-info",
            "Name: mistral-vibe\nVersion: 2.6.0\n",
            true,
        ),
        (
            "no-venv",
            "mistral_vibe-2.5.0.dist-info",
            "Name: mistral-vibe\nVersion: 2.5.0\n",
            false,
        ),
    ] {
        let home = temp_home(&format!("vibe-{tag}"));
        let (links, marker) = vibe_tool(&home, dir, meta, venv);
        assert_eq!(vibe_version(&home, &links), "9.9.9", "{tag}");
        assert!(marker.exists(), "{tag}: the fallback spawn did not run");
        let _ = fs::remove_dir_all(&home);
    }
}

// ── T2: SSH keys without a passphrase, one finding per home ─────────────────────────────

fn key(path: &Path, header: &str) {
    write(path, &format!("-----BEGIN {header}-----\nFAKEKEYBODY\n"));
    chmod(path, 0o600);
}

/// Three unprotected keys and one encrypted key in one home: one High listing the three
/// (relative to `~/.ssh`, in path order), every key still a row. A second home's keys
/// are their own finding; a single key keeps the per-key title. Fails on bb1fc66, which
/// reports three "rsa key has no passphrase" Highs for the first home.
#[test]
fn ssh_keys_without_a_passphrase_are_one_finding_per_home() {
    let home = temp_home("ssh");
    let ssh = home.join(".ssh");
    key(&ssh.join("id_rsa"), "RSA PRIVATE KEY");
    key(&ssh.join("deploy_ecdsa"), "EC PRIVATE KEY");
    key(&ssh.join("legacy_dsa"), "DSA PRIVATE KEY");
    write(
        &ssh.join("id_rsa_locked"),
        "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nFAKE\n",
    );
    chmod(&ssh.join("id_rsa_locked"), 0o600);
    let (_, _, mut report, findings) = scan(&home, &["ssh"]);
    let d = dump(&findings);
    assert_eq!(report.ssh_keys.len(), 4, "{:?}", report.ssh_keys);
    let ssh_f: Vec<&Finding> = findings.iter().filter(|f| f.category == "SSH key").collect();
    assert_eq!(ssh_f.len(), 1, "{d}");
    let f = ssh_f[0];
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.title, "3 SSH private keys without a passphrase");
    assert_eq!(f.location, ssh.display().to_string());
    assert_eq!(
        f.evidence.as_deref(),
        Some("deploy_ecdsa (ecdsa), id_rsa (rsa), legacy_dsa (dsa)"),
        "{d}"
    );

    // What the binary reports (fails on bb1fc66: three "rsa/ecdsa/dsa key has no
    // passphrase" Highs).
    let bin_ssh: Vec<_> = binary_findings(&home, &["ssh"])
        .into_iter()
        .filter(|(_, c, _)| c == "SSH key")
        .collect();
    assert_eq!(
        bin_ssh,
        vec![(
            "high".to_string(),
            "SSH key".to_string(),
            "3 SSH private keys without a passphrase".to_string()
        )]
    );

    // A second home, and order independence: the same keys in reverse order.
    let other = |p: &str, t: &str| SshKey {
        path: p.into(),
        key_type: t.into(),
        has_passphrase: PassphraseStatus::NoPassphrase,
        comment: None,
    };
    report.ssh_keys.push(other("/srv/u2/.ssh/id_ed", "openssh"));
    report.ssh_keys.reverse();
    let f2 = collect_findings(&report);
    let ssh_f: Vec<&Finding> = f2.iter().filter(|f| f.category == "SSH key").collect();
    assert_eq!(ssh_f.len(), 2, "{}", dump(&f2));
    assert!(
        ssh_f
            .iter()
            .any(|f| f.title == "3 SSH private keys without a passphrase"
                && f.evidence.as_deref() == Some("deploy_ecdsa (ecdsa), id_rsa (rsa), legacy_dsa (dsa)"))
    );
    assert!(
        ssh_f
            .iter()
            .any(|f| f.title == "openssh key has no passphrase" && f.location == "/srv/u2/.ssh/id_ed"),
        "{}",
        dump(&f2)
    );
    let _ = fs::remove_dir_all(&home);
}

// ── T3: toxic-flow High needs a server-backed leg ───────────────────────────────────────

fn skill(home: &Path, name: &str, body: &str) {
    write(
        &home.join(format!(".claude/skills/{name}/SKILL.md")),
        &format!("---\nname: {name}\ndescription: {name}\n---\n{body}\n"),
    );
}

fn toxic(findings: &[Finding]) -> Vec<&Finding> {
    findings.iter().filter(|f| f.category == "Toxic Flow").collect()
}

fn assert_binary_toxic_high(home: &Path) {
    let bin: Vec<_> = binary_findings(home, &["mcp", "skills"])
        .into_iter()
        .filter(|(_, c, _)| c == "Toxic Flow")
        .collect();
    assert_eq!(bin.len(), 1, "{bin:?}");
    assert_eq!(bin[0].0, "high", "{bin:?}");
}

/// An active MCP server (fetch: network) plus one skill that mentions read_file: High,
/// as before (the guard that the gate does not demote a server-backed flow).
#[test]
fn toxic_flow_with_a_server_leg_is_high() {
    let home = temp_home("tf-server");
    write(
        &home.join(".claude.json"),
        r#"{"mcpServers":{"fetch":{"command":"uvx","args":["mcp-server-fetch==2025.4.7"]}}}"#,
    );
    skill(&home, "reader", "Use read_file on the notes.");
    let (_, _, _, findings) = scan(&home, &["mcp", "skills"]);
    let tf = toxic(&findings);
    assert_eq!(tf.len(), 1, "{}", dump(&findings));
    assert_eq!(tf[0].severity, Severity::High);
    assert!(!tf[0].title.contains("mentions only"), "{}", tf[0].title);
    assert!(tf[0].title.contains("fetch: network"), "{}", tf[0].title);
    assert_binary_toxic_high(&home);
    let _ = fs::remove_dir_all(&home);
}

/// This machine's shape: a claude.ai Gmail connector (private data) and an enabled
/// Playwright plugin server (network): High.
#[test]
fn toxic_flow_connector_and_playwright_is_high() {
    let home = temp_home("tf-connector");
    let ip = home.join(".claude/plugins/cache/mkt/playwright/1.0.0");
    write(
        &ip.join(".mcp.json"),
        r#"{"playwright":{"command":"npx","args":["@playwright/mcp@1.0.0"]}}"#,
    );
    write(
        &home.join(".claude/plugins/installed_plugins.json"),
        &format!(
            "{{\"version\":2,\"plugins\":{{\"playwright@mkt\":[{{\"scope\":\"user\",\"installPath\":\"{}\",\"version\":\"1.0.0\"}}]}}}}",
            ip.display()
        ),
    );
    write(
        &home.join(".claude.json"),
        r#"{"claudeAiMcpEverConnected":["claude.ai Gmail"]}"#,
    );
    let (_, _, _, findings) = scan(&home, &["mcp", "skills"]);
    let tf = toxic(&findings);
    assert_eq!(tf.len(), 1, "{}", dump(&findings));
    assert_eq!(tf[0].severity, Severity::High);
    assert_binary_toxic_high(&home);
    let _ = fs::remove_dir_all(&home);
}

/// Skill-file mentions alone: three skills that read files and three that call out is
/// Medium "based on skill-file mentions only"; one skill that mentions both is no
/// finding. Fails on bb1fc66, where both are High.
#[test]
fn toxic_flow_from_skill_mentions_only_is_medium_or_nothing() {
    let home = temp_home("tf-mentions");
    for i in 0..3 {
        skill(&home, &format!("reader{i}"), "Use read_file on the notes.");
        skill(&home, &format!("poster{i}"), "Run curl to send the summary.");
    }
    let (_, _, _, findings) = scan(&home, &["mcp", "skills"]);
    let tf = toxic(&findings);
    assert_eq!(tf.len(), 1, "{}", dump(&findings));
    assert_eq!(tf[0].severity, Severity::Medium, "{}", dump(&findings));
    assert!(
        tf[0]
            .title
            .ends_with("on the agent surface, based on skill-file mentions only"),
        "{}",
        tf[0].title
    );
    let ev = tf[0].evidence.as_deref().unwrap_or("");
    assert!(ev.contains("(+3 loading skill(s) mention filesystem)"), "{ev}");
    let bin_tf: Vec<_> = binary_findings(&home, &["mcp", "skills"])
        .into_iter()
        .filter(|(_, c, _)| c == "Toxic Flow")
        .collect();
    assert_eq!(bin_tf.len(), 1, "{bin_tf:?}");
    assert_eq!(bin_tf[0].0, "medium", "{bin_tf:?}");
    assert!(bin_tf[0].2.ends_with("based on skill-file mentions only"), "{bin_tf:?}");
    let _ = fs::remove_dir_all(&home);

    let home = temp_home("tf-one-skill");
    skill(
        &home,
        "both",
        "Use read_file to load the notes, then curl to send them.",
    );
    let (_, _, _, findings) = scan(&home, &["mcp", "skills"]);
    assert!(toxic(&findings).is_empty(), "{}", dump(&findings));
    let bin = binary_findings(&home, &["mcp", "skills"]);
    assert!(!bin.iter().any(|(_, c, _)| c == "Toxic Flow"), "{bin:?}");
    let _ = fs::remove_dir_all(&home);
}

// ── T4: MCP args keep short-flag clusters ───────────────────────────────────────────────

/// `-sk https://x` (curl's silent + insecure) keeps the URL; `--api-key X` and Go style
/// `-token X` still redact. Fails on bb1fc66, where `-sk` read as a secret-key flag
/// (last word `SK`) and the URL became `<redacted>`.
#[test]
fn mcp_args_keep_the_value_after_a_short_flag_cluster() {
    let home = temp_home("mcp-sk");
    write(
        &home.join(".claude.json"),
        r#"{"mcpServers":{
            "curlish":{"command":"curl-mcp","args":["-sk","https://x.example/mcp","-fsSL","https://y.example/i"]},
            "keyed":{"command":"keyed-mcp","args":["--api-key","APIKEYCANARY1","-token","GOTOKCANARY2"]}
        }}"#,
    );
    let (text, v, _, _) = scan(&home, &["mcp"]);
    assert!(
        !text.contains("APIKEYCANARY1") && !text.contains("GOTOKCANARY2"),
        "{text}"
    );
    let servers: Vec<&Value> = v["mcp_configs"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|c| c["servers"].as_array().unwrap())
        .collect();
    let args = |name: &str| servers.iter().find(|s| s["name"] == name).unwrap()["args"].clone();
    assert_eq!(
        args("curlish"),
        serde_json::json!(["-sk", "https://x.example/mcp", "-fsSL", "https://y.example/i"]),
        "{text}"
    );
    assert_eq!(
        args("keyed"),
        serde_json::json!(["--api-key", "<redacted>", "-token", "<redacted>"]),
        "{text}"
    );
    use rustmachineguard::scanners::mcp::redact_arg;
    assert_eq!(redact_arg("https://x", Some("-sk")), "https://x");
    assert_eq!(redact_arg("X", Some("--api-key")), "<redacted>");
    assert_eq!(
        redact_arg("X", Some("-p")),
        "<redacted>",
        "explicit short flags unchanged"
    );
    let _ = fs::remove_dir_all(&home);
}
