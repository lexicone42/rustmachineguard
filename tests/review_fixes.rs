//! Regression tests for the independent review of 8e58777 (findings R3, R5..R16; the
//! R1/R2/R4/R6 canaries are in `no_secret_leakage.rs`, the listener cases of R3/R16 in
//! `listeners.rs`). Each test states how it fails on 8e58777. Fixtures are built under the
//! temp directory and never assume its ancestors are traversable by other users.

use rustmachineguard::analysis::{Finding, Severity, collect_findings};
use rustmachineguard::models::ScanReport;
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
    "listeners",
];

fn temp_home(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rmg-rvfix-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
    fs::canonicalize(&d).unwrap()
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn run(home: &Path, keep: &[&str], args: &[&str], env: &[(&str, &Path)]) -> (String, String) {
    let skip: Vec<&str> = ALL_LABELS.iter().copied().filter(|l| !keep.contains(l)).collect();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rmguard"));
    cmd.args(args)
        .args(["--skip", &skip.join(",")])
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
        .env("NO_COLOR", "1")
        .env_remove("RMGUARD_TEST_PROC_ROOT")
        .current_dir(home);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run rmguard");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn scan(home: &Path, keep: &[&str]) -> (String, Value, Vec<Finding>) {
    let (text, _) = run(home, keep, &["--format", "json"], &[]);
    let v: Value = serde_json::from_str(&text).expect("report json");
    let report: ScanReport = serde_json::from_str(&text).expect("report json");
    let findings = collect_findings(&report);
    (text, v, findings)
}

fn dump(findings: &[Finding]) -> String {
    findings
        .iter()
        .map(|f| {
            format!(
                "[{}] {} | {} | {}\n",
                f.severity.label(),
                f.category,
                f.title,
                f.location
            )
        })
        .collect()
}

// ── R5: KEY followed by a value word ────────────────────────────────────────────────────

/// `KEY` names a key's value when it is the last word or is followed by a value word
/// (`keyValue`, `keyData`, `keyMaterial`, `keyB64`, `keyString`, `keyPem`, `KEYTEXT`,
/// `encKeyHex`, `KEYPHRASE`, `keyphrase`); ssh options and English words stay unflagged.
/// Fails on 8e58777 (b44ed97's whole-word rule): every "yes" row but the first is false,
/// and `keyPem=X cmd` shows X in both redactors.
#[test]
fn r5_key_followed_by_a_value_word_is_a_secret_name() {
    use rustmachineguard::scanners::env_files::key_word_hint;
    use rustmachineguard::scanners::{redact_command_text, redact_secrets_in_text};
    for yes in [
        "API_KEY",
        "keyValue",
        "keyData",
        "keyMaterial",
        "keyB64",
        "keyString",
        "keyPem",
        "KEYTEXT",
        "encKeyHex",
        "KEYPHRASE",
        "keyphrase",
        "signingKeyBase64",
        "key_value",
    ] {
        assert!(key_word_hint(yes), "{yes} should be a key name");
    }
    for no in [
        "StrictHostKeyChecking",
        "PubkeyAuthentication",
        "HostKeyAlgorithms",
        "KEYBOARD",
        "MONKEY",
        "TURKEY",
        "HOTKEY",
        "KEYWORD",
        "keyboardLayout",
    ] {
        assert!(!key_word_hint(no), "{no} should not be a key name");
    }
    for r in [redact_secrets_in_text, redact_command_text] {
        let out = r("keyPem=RVKEYPEM cmd");
        assert_eq!(out, "keyPem=<redacted> cmd");
        assert_eq!(
            r("ssh -o StrictHostKeyChecking=no host"),
            "ssh -o StrictHostKeyChecking=no host"
        );
    }
}

// ── R6: one argv element is one word ────────────────────────────────────────────────────

/// Fails on 8e58777: each value after the first space (or a value starting with `-`)
/// was shown.
#[test]
fn r6_mcp_argv_elements_redact_to_their_end() {
    use rustmachineguard::scanners::mcp::redact_arg;
    let cases: &[(&str, Option<&str>, &str)] = &[
        (
            "--header=Authorization:Bearer RVARGX",
            None,
            "--header=Authorization:Bearer <redacted>",
        ),
        ("--password=a b RVARGX", None, "--password=<redacted>"),
        ("API_KEY=a RVARGX", Some("-e"), "API_KEY=<redacted>"),
        ("-RVARGX", Some("--token"), "<redacted>"),
        (
            "Authorization: Bearer a RVARGX",
            Some("--header"),
            "Authorization: Bearer <redacted>",
        ),
        ("X-Api-Key: a RVARGX", Some("-H"), "X-Api-Key: <redacted>"),
        ("API_KEY=${KEY}", Some("-e"), "API_KEY=${KEY}"),
    ];
    for (arg, prev, want) in cases {
        assert_eq!(redact_arg(arg, *prev), *want, "{arg} after {prev:?}");
    }
    // Unchanged: no secret, or a flag that carried its own value.
    assert_eq!(redact_arg("--verbose", Some("--token=abc")), "--verbose");
    assert_eq!(
        redact_arg("Content-Type: application/json", Some("-H")),
        "Content-Type: application/json"
    );
}

// ── R7: strict decoding of ~/.claude/projects names ─────────────────────────────────────

/// `shared/a-b` and `shared/a/b` both encode to the same name: neither is recovered, and
/// `--trace` says the name was skipped; a name only one directory encodes to is still
/// recovered; a symlinked directory is never followed while decoding. Fails on 8e58777:
/// both `a-b` and `a/b` are recovered (and the link is followed).
#[test]
fn r7_ambiguous_or_linked_encoded_names_are_not_recovered() {
    use rustmachineguard::platform::encode_project_path;
    let home = temp_home("decode-home");
    let outside = temp_home("decode-out");
    let shared = outside.join("shared");
    for d in ["a-b", "a/b", "uniq_x", "target/sub"] {
        write(
            &shared.join(d).join(".claude/settings.local.json"),
            r#"{"permissions":{"allow":["Bash(ls)"]}}"#,
        );
    }
    std::os::unix::fs::symlink(shared.join("target"), shared.join("link")).unwrap();
    let projects = home.join(".claude/projects");
    for p in [shared.join("a-b"), shared.join("uniq_x"), shared.join("link/sub")] {
        fs::create_dir_all(projects.join(encode_project_path(&p))).unwrap();
    }
    assert_eq!(
        encode_project_path(&shared.join("a-b")),
        encode_project_path(&shared.join("a/b"))
    );
    write(&home.join(".claude.json"), "{}");
    let (_, trace) = run(&home, &["settings"], &["--format", "json", "--trace"], &[]);
    let recovered: Vec<&str> = trace
        .lines()
        .filter(|l| l.contains("source claude-projects-dir"))
        .collect();
    assert_eq!(recovered.len(), 1, "{recovered:?}");
    assert!(recovered[0].contains("shared/uniq_x"), "{recovered:?}");
    assert!(
        trace.contains("trace: ambiguous encoded project name, skipped"),
        "{trace}"
    );
    let _ = fs::remove_dir_all(&home);
    let _ = fs::remove_dir_all(&outside);
}

// ── R8: .mcp.json approval decides activity ─────────────────────────────────────────────

fn mcpjson_project(tag: &str) -> (PathBuf, PathBuf) {
    let home = temp_home(tag);
    let proj = home.join("proj");
    write(
        &proj.join(".mcp.json"),
        r#"{"mcpServers":{"gmail":{"command":"npx","args":["-y","gmail-mcp@1.0.0"]},"playwright":{"command":"npx","args":["@playwright/mcp@1.0.0"]}}}"#,
    );
    (home, proj)
}

fn toxic(findings: &[Finding]) -> Vec<&Finding> {
    findings.iter().filter(|f| f.category == "Toxic Flow").collect()
}

/// The reviewer's fixture: both project servers (Gmail, a private-data source, and
/// Playwright, a network sink) are disabled where Claude Code records the approval
/// dialog's answers, `~/.claude.json` `projects.<path>.disabledMcpjsonServers`: no
/// server-backed toxic flow. With neither list naming them they await approval (inactive,
/// `awaits_approval`); approved by `enableAllProjectMcpServers` they are a toxic flow
/// (the control). Fails on 8e58777: the first two cases raise the High toxic flow.
#[test]
fn r8_disabled_or_unapproved_project_servers_are_not_active() {
    let (home, proj) = mcpjson_project("mcpjson-off");
    write(
        &home.join(".claude.json"),
        &serde_json::json!({"projects": {proj.to_str().unwrap(): {"disabledMcpjsonServers": ["gmail", "playwright"]}}})
            .to_string(),
    );
    let (text, v, findings) = scan(&home, &["mcp"]);
    assert!(toxic(&findings).is_empty(), "{}", dump(&findings));
    let rows: Vec<&Value> = v["mcp_configs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["vendor"] == "Project")
        .flat_map(|c| c["servers"].as_array().unwrap())
        .collect();
    assert_eq!(rows.len(), 2, "{text}");
    assert!(rows.iter().all(|r| r["enabled"] == false), "{text}");
    let _ = fs::remove_dir_all(&home);

    let (home, proj) = mcpjson_project("mcpjson-pending");
    write(
        &home.join(".claude.json"),
        &serde_json::json!({"projects": {proj.to_str().unwrap(): {}}}).to_string(),
    );
    let (text, _, findings) = scan(&home, &["mcp"]);
    assert!(toxic(&findings).is_empty(), "{}", dump(&findings));
    assert_eq!(text.matches("\"awaits_approval\": true").count(), 2, "{text}");
    let _ = fs::remove_dir_all(&home);

    let (home, proj) = mcpjson_project("mcpjson-on");
    write(
        &home.join(".claude.json"),
        &serde_json::json!({"projects": {proj.to_str().unwrap(): {}}}).to_string(),
    );
    write(
        &proj.join(".claude/settings.local.json"),
        r#"{"enableAllProjectMcpServers":true}"#,
    );
    let (_, _, findings) = scan(&home, &["mcp"]);
    let tf = toxic(&findings);
    assert_eq!(tf.len(), 1, "{}", dump(&findings));
    assert_eq!(tf[0].severity, Severity::High);
    let _ = fs::remove_dir_all(&home);
}

// ── R9: an npx cache is active only for the same launch spec ────────────────────────────

fn npx_cache_home(tag: &str, cache_spec: &str, server_spec: &str) -> PathBuf {
    let home = temp_home(tag);
    let root = home.join(".npm/_npx/0123456789abcdef");
    write(
        &root.join("package.json"),
        &format!(r#"{{"_npx":{{"packages":["{cache_spec}"]}}}}"#),
    );
    write(
        &root.join("node_modules/@modelcontextprotocol/server/package.json"),
        r#"{"name":"@modelcontextprotocol/server","version":"2.0.0"}"#,
    );
    write(
        &home.join(".claude.json"),
        &format!(r#"{{"mcpServers":{{"foo":{{"command":"npx","args":["-y","{server_spec}"]}}}}}}"#),
    );
    home
}

fn sdk_hit(findings: &[Finding]) -> &Finding {
    let hits: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.category == "Exposure" && f.title.contains("@modelcontextprotocol/server"))
        .collect();
    assert_eq!(hits.len(), 1, "{}", dump(findings));
    hits[0]
}

/// A vulnerable SDK in the npx cache fetched for `foo-mcp@1.0.0` is dormant while the
/// active server launches `foo-mcp@2.0.0` (npx keys its cache by the spec), and active
/// when the server launches `foo-mcp@1.0.0`. Fails on 8e58777: the first case is Critical
/// (any version of the same NAME counted as re-running the cache).
#[test]
fn r9_npx_cache_matches_the_launch_spec_not_the_name() {
    let home = npx_cache_home("npx-other", "foo-mcp@1.0.0", "foo-mcp@2.0.0");
    let (_, _, findings) = scan(&home, &["mcp", "npmpkgs"]);
    let f = sdk_hit(&findings);
    // The row's advisory_severity is high (catalog 2026-10-25.3): active is High and
    // dormant one below.
    assert_eq!(f.severity, Severity::Medium, "{}", f.title);
    assert!(f.title.contains("dormant unless re-run"), "{}", f.title);
    let _ = fs::remove_dir_all(&home);

    let home = npx_cache_home("npx-same", "foo-mcp@1.0.0", "foo-mcp@1.0.0");
    let (_, _, findings) = scan(&home, &["mcp", "npmpkgs"]);
    assert_eq!(sdk_hit(&findings).severity, Severity::High);
    let _ = fs::remove_dir_all(&home);

    // An unpinned launch re-runs an unpinned cache, not a pinned one.
    let home = npx_cache_home("npx-float", "foo-mcp", "foo-mcp@latest");
    let (_, _, findings) = scan(&home, &["mcp", "npmpkgs"]);
    assert_eq!(sdk_hit(&findings).severity, Severity::High);
    let _ = fs::remove_dir_all(&home);
    let home = npx_cache_home("npx-float-pinned", "foo-mcp@1.0.0", "foo-mcp");
    let (_, _, findings) = scan(&home, &["mcp", "npmpkgs"]);
    assert_eq!(sdk_hit(&findings).severity, Severity::Medium);
    let _ = fs::remove_dir_all(&home);
}

// ── R10: disableBypassPermissionsMode, and bypass from project scope ────────────────────

fn bypass_findings(findings: &[Finding]) -> Vec<&Finding> {
    findings
        .iter()
        .filter(|f| f.category == "Permissions" && f.title.contains("bypassPermissions"))
        .collect()
}

/// User settings that start sessions in bypassPermissions AND set
/// `permissions.disableBypassPermissionsMode: "disable"`: bypass is off, so no High (the
/// terminal says "bypass mode is disabled by policy"). A project file's
/// `bypassPermissions` has no effect there (code.claude.com/docs/en/settings.md): Low
/// "ignored". The control, user bypass without the policy, stays High. Fails on 8e58777:
/// the first two cases are High.
#[test]
fn r10_bypass_disabled_by_policy_and_project_scope_bypass_are_not_high() {
    let home = temp_home("bypass-off");
    write(
        &home.join(".claude/settings.json"),
        r#"{"permissions":{"defaultMode":"bypassPermissions","disableBypassPermissionsMode":"disable"}}"#,
    );
    let (_, _, findings) = scan(&home, &["settings"]);
    assert!(
        !findings
            .iter()
            .any(|f| f.title.contains("runs without approval prompts")),
        "{}",
        dump(&findings)
    );
    let (term, _) = run(&home, &["settings"], &["--format", "terminal", "--verbose"], &[]);
    assert!(term.contains("bypass mode is disabled by policy"), "{term}");
    let _ = fs::remove_dir_all(&home);

    let home = temp_home("bypass-project");
    let proj = home.join("proj");
    write(
        &proj.join(".claude/settings.json"),
        r#"{"permissions":{"defaultMode":"bypassPermissions"}}"#,
    );
    write(
        &home.join(".claude.json"),
        &serde_json::json!({"projects": {proj.to_str().unwrap(): {}}}).to_string(),
    );
    let (_, _, findings) = scan(&home, &["settings"]);
    let b = bypass_findings(&findings);
    assert_eq!(b.len(), 1, "{}", dump(&findings));
    assert_eq!(b[0].severity, Severity::Low, "{}", dump(&findings));
    assert!(
        b[0].title.contains("ignored by Claude Code in this scope"),
        "{}",
        b[0].title
    );
    let _ = fs::remove_dir_all(&home);

    let home = temp_home("bypass-on");
    write(
        &home.join(".claude/settings.json"),
        r#"{"permissions":{"defaultMode":"bypassPermissions"}}"#,
    );
    let (_, _, findings) = scan(&home, &["settings"]);
    assert!(
        findings
            .iter()
            .any(|f| f.severity == Severity::High && f.title.contains("runs without approval prompts")),
        "{}",
        dump(&findings)
    );
    let _ = fs::remove_dir_all(&home);
}

// ── R11: names exported at shell top level only ─────────────────────────────────────────

/// A world-readable session-env file whose quoted value spans lines (with an `IDENT=` at
/// the start of a continuation line) and a here-document: only the real exports are
/// names. Fails on 8e58777: `sslpasswordRvcanary` (a fragment of the URL's query) and
/// `HEREDOCRVNAME` are listed. Skipped when the temp directory's ancestors stop other
/// users (the store is then not graded by names at all).
#[test]
fn r11_multi_line_values_and_heredocs_yield_no_names() {
    use rustmachineguard::scanners::transcripts::untraversable_ancestor;
    let home = temp_home("sessenv");
    let claude = home.join(".claude");
    let f = claude.join("session-env/s1/sessionstart-hook-0.sh");
    write(
        &f,
        "export DB_URL=\"postgres://db/app?sslmode=require&\nsslpasswordRvcanary=x\n\"\nexport OK_NAME=1\ncat > /tmp/x <<'EOF'\nHEREDOCRVNAME=1\nEOF\nexport AFTER_DOC=1\n",
    );
    fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();
    for d in [
        claude.clone(),
        claude.join("session-env"),
        claude.join("session-env/s1"),
    ] {
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
    }
    if let Some(why) = untraversable_ancestor(&f) {
        eprintln!("store not reachable ({why}); the names are not read: skipping");
        let _ = fs::remove_dir_all(&home);
        return;
    }
    let (text, _, _) = scan(&home, &["transcripts"]);
    for name in ["DB_URL", "OK_NAME", "AFTER_DOC"] {
        assert!(text.contains(&format!("\"{name}\"")), "{name} missing: {text}");
    }
    for frag in ["sslpasswordRvcanary", "HEREDOCRVNAME", "<key-shaped name>"] {
        assert!(!text.contains(frag), "{frag} reached the report: {text}");
    }
    let _ = fs::remove_dir_all(&home);
}

// ── R12..R14: redactor batch ────────────────────────────────────────────────────────────

/// One canary per reviewer shape, through both redactors, idempotently. Fails on
/// 8e58777: every row but the `-passin pass:` one shows its canary in at least one
/// redactor.
#[test]
fn r12_r14_redactor_canaries() {
    use rustmachineguard::scanners::{redact_command_text, redact_secrets_in_text};
    let cases: &[(&str, &str)] = &[
        // R12: openssl's pass-phrase flags.
        ("openssl x -pass RVCANA", "RVCANA"),
        ("openssl rsa -passin pass:RVCANB -passout pass:RVCANC", "RVCANB"),
        // R13: adjacent quoted and unquoted parts are one word.
        ("curl -H \"Authorization: Bearer\"RVCAND https://h", "RVCAND"),
        ("curl --api-key \"a\"' 'RVCANE https://h", "RVCANE"),
        ("curl -u \"user:a RVCANF\" https://h", "RVCANF"),
        // R14.
        ("curl -uuser:RVCANG https://h", "RVCANG"),
        ("redis-cli -aRVCANH ping", "RVCANH"),
        ("redis-cli -a RVCANI ping", "RVCANI"),
        ("curl -b session=RVCANJ https://h", "RVCANJ"),
        ("curl --cookie \"sid=RVCANK; b=RVCANL\" https://h", "RVCANL"),
        ("curl -E cert.pem:RVCANM https://h", "RVCANM"),
        ("deploy --token a\u{a0}RVCANN https://h", "RVCANN"),
        ("Driver={ODBC};Server=s;Uid=u;Pwd=RVCANO;", "RVCANO"),
        ("\"Server=s;Uid=u;Password=a RVCANP;\"", "RVCANP"),
        ("fetch(u,{headers:{\"X-API-Key\":\"RVCANQ\"}})", "RVCANQ"),
        ("fetch(u,{headers:{Authorization:\"Bearer RVCANR\"}})", "RVCANR"),
        ("curl 'https://a.blob.core.windows.net/c?sv=2020&sig=RVCANS'", "RVCANS"),
        ("curl 'https://h/x?access_token=RVCANT'", "RVCANT"),
        ("docker login -u me -p RVCANU r.io", "RVCANU"),
        ("echo RVCANV | gh auth login --with-token", "RVCANV"),
    ];
    for (text, canary) in cases {
        for (label, r) in [
            ("text", redact_secrets_in_text as fn(&str) -> String),
            ("command", redact_command_text),
        ] {
            let once = r(text);
            assert!(!once.contains(canary), "{label}: {text} -> {once}");
            assert!(!once.contains("RVCAN"), "{label}: {text} -> {once}");
            assert_eq!(r(&once), once, "{label}: not idempotent on {text}");
        }
    }
    // What a reader needs stays: the program, the flag, the host, the cookie name.
    let r = redact_secrets_in_text;
    assert_eq!(r("curl -b session=X https://h"), "curl -b session=<redacted> https://h");
    assert_eq!(r("openssl x -passin env:PASSVAR"), "openssl x -passin env:PASSVAR");
    assert_eq!(r("curl -b cookies.txt https://h"), "curl -b cookies.txt https://h");
    assert_eq!(r("redis-cli -h db -p 6379 ping"), "redis-cli -h db -p 6379 ping");
    // curl's `-E` / `-b` mean a certificate and cookies only in a curl command.
    for keep in [
        "cargo test 2>&1 | grep -E \"merge:|panicked|FAILED\"",
        "git checkout -b feature=x",
        "curl -s https://h | grep -E 'a:b'",
    ] {
        assert_eq!(r(keep), keep);
        assert_eq!(redact_command_text(keep), keep);
    }
}

// ── R15: an .in_use pid counts only if it started before its marker ─────────────────────

/// Two `.in_use` markers of an older plugin version, written now: pid 4242 started 500 s
/// before (a live session) and pid 4243 500 s after (the kernel reused a dead session's
/// pid). Only 4242 counts. The fixture `/proc` has `stat` files (btime and starttime).
/// Fails on 8e58777: both pids are counted.
#[cfg(target_os = "linux")]
#[test]
fn r15_a_reused_pid_is_not_a_live_session() {
    let home = temp_home("inuse-reuse");
    let cache = home.join(".claude/plugins/cache/mk/pl");
    let new = cache.join("2.0.0");
    let old = cache.join("1.0.0");
    fs::create_dir_all(&new).unwrap();
    write(
        &home.join(".claude/plugins/installed_plugins.json"),
        &format!(
            r#"{{"version":2,"plugins":{{"pl@mk":[{{"scope":"user","installPath":"{}","version":"2.0.0"}}]}}}}"#,
            new.display()
        ),
    );
    for pid in ["4242", "4243"] {
        write(&old.join(".in_use").join(pid), "");
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // SAFETY: sysconf has no preconditions.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
    let btime = now - 1000;
    let proc_root = home.join("fakeproc");
    write(&proc_root.join("stat"), &format!("cpu 1 2 3\nbtime {btime}\n"));
    for (pid, after_boot) in [(4242u32, 500u64), (4243, 1500)] {
        let ticks = after_boot * hz;
        write(
            &proc_root.join(pid.to_string()).join("stat"),
            &format!("{pid} (claude) S 1 {pid} {pid} 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 {ticks} 1 1 0"),
        );
    }
    let (text, _) = run(
        &home,
        &["liveness"],
        &["--format", "json"],
        &[("RMGUARD_TEST_PROC_ROOT", proc_root.as_path())],
    );
    let v: Value = serde_json::from_str(&text).unwrap();
    let rows = v["plugin_versions_in_use"].as_array().cloned().unwrap_or_default();
    let o = rows
        .iter()
        .find(|r| r["version"] == "1.0.0")
        .unwrap_or_else(|| panic!("{text}"));
    assert_eq!(o["pids"], serde_json::json!([4242]), "{text}");
    assert_eq!(o["in_use_by_sessions"], 1, "{text}");
    let _ = fs::remove_dir_all(&home);
}

// ── R16 ─────────────────────────────────────────────────────────────────────────────────

/// `Bash(git push --force:*)` changes remote state (a force push rewrites history):
/// graded with the state-changing rules; `Bash(git push:*)` stays a scoped rule. Fails on
/// 8e58777: no finding for the force-push rule.
#[test]
fn r16_force_push_rule_is_state_changing() {
    let home = temp_home("forcepush");
    write(
        &home.join(".claude/settings.json"),
        r#"{"permissions":{"allow":["Bash(git push --force:*)","Bash(git push:*)"]}}"#,
    );
    let (_, v, findings) = scan(&home, &["settings"]);
    assert!(
        findings
            .iter()
            .any(|f| f.category == "Permissions" && f.title.contains("change remote or privileged state")),
        "{}",
        dump(&findings)
    );
    let rules: Vec<&Value> = v["agent_settings"][0]["permission_rules"]
        .as_array()
        .unwrap()
        .iter()
        .collect();
    let class = |r: &str| {
        rules
            .iter()
            .find(|x| x["rule"] == r)
            .and_then(|x| x["class"].as_str().map(str::to_string))
    };
    assert_eq!(class("Bash(git push --force:*)").as_deref(), Some("destructive"));
    assert_eq!(class("Bash(git push:*)"), None);
    let _ = fs::remove_dir_all(&home);
}

/// The `.env` secret-name rule fails safe: an unknown word after a long hint keeps the
/// name secret-named (`GITHUB_TOKEN_READONLY`, `API_KEY_ROTATED`); only the closed
/// non-secret list unflags (`AWS_ACCESS_KEY_ID`, `TOKEN_HEADER`). Fails on 8e58777:
/// `API_KEY_ROTATED`, `SECRET_KEY_SALTED` and `DB_PASSWORD_ALT` are not secret names.
#[test]
fn r16_env_secret_names_fail_safe() {
    use rustmachineguard::scanners::env_files::is_secret_env_key_name as s;
    for yes in [
        "GITHUB_TOKEN_READONLY",
        "API_KEY_ROTATED",
        "SECRET_KEY_SALTED",
        "DB_PASSWORD_ALT",
        "GITHUB_TOKEN",
        "DB_PASS_B64",
    ] {
        assert!(s(yes), "{yes} should be a secret name");
    }
    for no in [
        "AWS_ACCESS_KEY_ID",
        "TOKEN_HEADER",
        "API_KEY_PREFIX",
        "JWT_ISSUER",
        "TOKEN_TYPE",
        "KEY_FORMAT",
    ] {
        assert!(!s(no), "{no} should not be a secret name");
    }
}
