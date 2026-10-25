//! End-to-end tests for the quality of Claude Code posture findings: every allow rule is
//! classified whatever its index (Q1); interpreter rules are graded by whether sessions
//! start in auto mode, which drops them (Q2); code-running, state-changing and wrapper
//! rules, Claude Code's state stores and ~/.claude/bin executables are one finding per
//! machine (Q3); session-env and shell-snapshots are graded by the variable NAMES they
//! export, never a value (Q4); MCP, credential-read and inert-rule wording (Q5); the
//! toxic-flow wording (Q6); the destructive and wrapper rule classes (Q7); and the
//! `autoMode` settings block (Q8).
//!
//! Each test builds a temp HOME and runs the real binary with only the scanners it
//! needs, with positive fixtures next to negative controls. Assertions read the JSON
//! report as plain JSON and through `collect_findings`, so the file compiles against
//! 837d9aa and each test fails there on its assertions (the comment on each test says
//! how).
#![cfg(unix)]

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
];

/// A fresh temp directory (mode 0755), canonicalized (macOS temp_dir() is under /var).
fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rmg-ccq-{tag}-{}", std::process::id()));
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

fn managed_dir(sysroot: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        sysroot.join("Library/Application Support/ClaudeCode")
    } else {
        sysroot.join("etc/claude-code")
    }
}

/// Run rmguard against `home` with only `keep` scanners, in `format`.
fn run(home: &Path, keep: &[&str], format: &str) -> String {
    let skip: Vec<&str> = ALL_LABELS.iter().copied().filter(|l| !keep.contains(l)).collect();
    let out = Command::new(env!("CARGO_BIN_EXE_rmguard"))
        .args(["--skip", &skip.join(","), "--format", format])
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
        .env("NO_COLOR", "1")
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("RMGUARD_TRACE")
        .current_dir(home)
        .output()
        .expect("run rmguard");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// JSON text, the report as a Value, and the findings.
fn scan(home: &Path, keep: &[&str]) -> (String, Value, Vec<Finding>) {
    let text = run(home, keep, "json");
    let value: Value = serde_json::from_str(&text).expect("report json");
    let report: ScanReport = serde_json::from_str(&text).expect("report json");
    (text, value, collect_findings(&report))
}

fn perms(findings: &[Finding]) -> Vec<&Finding> {
    findings.iter().filter(|f| f.category == "Permissions").collect()
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

/// The finding whose title contains `needle`, or a panic listing them all.
fn find<'a>(findings: &'a [Finding], needle: &str) -> &'a Finding {
    findings
        .iter()
        .find(|f| f.title.contains(needle))
        .unwrap_or_else(|| panic!("no finding with {needle:?}:\n{}", dump(findings)))
}

/// Register `projects` in ~/.claude.json so the settings scanner reads their files.
fn register(home: &Path, projects: &[&Path]) {
    let map: serde_json::Map<String, Value> = projects
        .iter()
        .map(|p| (p.display().to_string(), serde_json::json!({})))
        .collect();
    write(
        &home.join(".claude.json"),
        &serde_json::json!({ "projects": map }).to_string(),
    );
}

/// True when a directory above `p` is not traversable by other users (macOS `$TMPDIR`,
/// or CI's re-run under a 0700 parent): reachability-graded findings honestly drop to
/// Low there.
fn blocked_above(p: &Path) -> bool {
    p.ancestors().skip(1).any(|a| {
        fs::metadata(a)
            .map(|m| m.permissions().mode() & 0o001 == 0)
            .unwrap_or(false)
    })
}

// ── Q1: every allow rule is classified ─────────────────────────────────────────────────

/// A code-execution rule at index 201 and a credential read at index 250 are graded and
/// kept in the stored list (capped at 200); a scoped rule past the cap is not graded.
/// Fails on 837d9aa, which took the first 200 rules BEFORE classifying, so neither rule
/// produced a finding.
#[test]
fn q1_every_allow_rule_is_classified_past_the_stored_cap() {
    let home = temp_dir("q1");
    let mut allow: Vec<String> = (0..260).map(|i| format!("Bash(tool{i} --flag:*)")).collect();
    allow[201] = "Bash(python3:*)".into();
    allow[250] = "Read(~/.ssh/**)".into();
    allow[255] = "Bash(git status:*)".into();
    write(
        &home.join(".claude/settings.json"),
        &serde_json::json!({"permissions": {"allow": allow}}).to_string(),
    );
    let (text, v, findings) = scan(&home, &["settings"]);
    let user = v["agent_settings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["source"] == "user-global")
        .unwrap_or_else(|| panic!("{text}"));
    assert_eq!(user["allow_rules"], 260, "the count is the file's");
    let rules = user["permission_rules"].as_array().unwrap();
    assert_eq!(rules.len(), 200, "the stored list stays capped");
    for r in ["Bash(python3:*)", "Read(~/.ssh/**)"] {
        assert!(
            rules.iter().any(|x| x["rule"] == r && x["class"].is_string()),
            "{r} is kept: {rules:?}"
        );
    }
    let d = dump(&findings);
    let exec = find(&findings, "Code-execution allow rules in 1 settings file");
    assert_eq!(exec.severity, Severity::Medium, "{d}");
    assert!(exec.evidence.as_deref().unwrap().contains("Bash(python3:*)"), "{d}");
    let read = find(&findings, "Read(~/.ssh/**) pre-approves reading ~/.ssh");
    assert_eq!(read.severity, Severity::High, "{d}");
    assert_eq!(
        perms(&findings).len(),
        2,
        "the scoped rule past the cap is not graded: {d}"
    );

    let _ = fs::remove_dir_all(&home);
}

// ── Q2: auto mode drops interpreter rules ────────────────────────────────────────────────

/// A project's local settings with interpreter, package-runner and curl rules.
fn exec_project(home: &Path, name: &str, extra: &str) -> PathBuf {
    let proj = home.join(name);
    write(
        &proj.join(".claude/settings.local.json"),
        &format!(
            r#"{{"permissions":{{"allow":["Bash(python3:*)","Bash(uv run:*)","Bash(npx:*)","Bash(curl:*)","Bash(git status:*)"]{extra}}}}}"#
        ),
    );
    proj
}

/// User settings start sessions in auto mode, so the interpreter / package-runner rules
/// are suspended (Low) and curl, which auto mode keeps, stays Medium. Fails on 837d9aa,
/// which graded every one of them as one Medium with no auto-mode awareness.
#[test]
fn q2_interpreter_rules_are_suspended_where_sessions_start_in_auto() {
    let home = temp_dir("q2-auto");
    write(
        &home.join(".claude/settings.json"),
        r#"{"permissions":{"defaultMode":"auto"}}"#,
    );
    let proj = exec_project(&home, "p", "");
    register(&home, &[&proj]);
    let (_, _, findings) = scan(&home, &["settings"]);
    let d = dump(&findings);
    let low = find(
        &findings,
        "Code-execution allow rules in 1 project settings file: suspended while auto mode is active; sessions here start in auto",
    );
    assert_eq!(low.severity, Severity::Low, "{d}");
    let ev = low.evidence.as_deref().unwrap();
    for r in ["Bash(python3:*)", "Bash(uv run:*)", "Bash(npx:*)"] {
        assert!(ev.contains(r), "{r}: {d}");
    }
    assert!(!ev.contains("curl") && !ev.contains("git status"), "{d}");
    let net = find(
        &findings,
        "Network-transfer allow rules (curl, wget) in 1 project settings file",
    );
    assert_eq!(net.severity, Severity::Medium, "{d}");
    assert!(net.title.contains("stay active in auto mode"), "{d}");
    assert!(
        !findings
            .iter()
            .any(|f| f.severity == Severity::Medium && f.title.starts_with("Code-execution")),
        "{d}"
    );
    let _ = fs::remove_dir_all(&home);
}

/// The other branch: where sessions do NOT start in auto mode the interpreter rules stay
/// Medium. A project's own `defaultMode` outranks the user's auto (settings precedence),
/// a managed `defaultMode` outranks both, and `disableAutoMode` removes auto mode. A
/// project whose files set nothing inherits the user's auto (control). Fails on 837d9aa,
/// whose titles carry neither wording.
#[test]
fn q2_interpreter_rules_stay_medium_where_sessions_do_not_start_in_auto() {
    let home = temp_dir("q2-manual");
    write(
        &home.join(".claude/settings.json"),
        r#"{"permissions":{"defaultMode":"auto"}}"#,
    );
    let own_mode = exec_project(&home, "own-mode", r#","defaultMode":"acceptEdits""#);
    let disabled = exec_project(&home, "disabled", r#","disableAutoMode":"disable""#);
    let inherits = exec_project(&home, "inherits", "");
    register(&home, &[&own_mode, &disabled, &inherits]);
    let (_, _, findings) = scan(&home, &["settings"]);
    let d = dump(&findings);
    let live = find(
        &findings,
        "Code-execution allow rules in 2 project settings files: arbitrary code runs without a prompt",
    );
    assert_eq!(live.severity, Severity::Medium, "{d}");
    let ev = live.evidence.as_deref().unwrap();
    assert!(
        ev.contains("/own-mode/") && ev.contains("/disabled/") && !ev.contains("/inherits/"),
        "{d}"
    );
    let suspended = find(
        &findings,
        "Code-execution allow rules in 1 project settings file: suspended",
    );
    assert!(suspended.evidence.as_deref().unwrap().contains("/inherits/"), "{d}");

    // A managed defaultMode outranks the user's auto everywhere.
    write(
        &managed_dir(&home.join("sysroot")).join("managed-settings.json"),
        r#"{"permissions":{"defaultMode":"default"}}"#,
    );
    let (_, _, findings) = scan(&home, &["settings"]);
    let d = dump(&findings);
    find(
        &findings,
        "Code-execution allow rules in 3 project settings files: arbitrary code runs without a prompt",
    );
    assert!(!findings.iter().any(|f| f.title.contains("suspended")), "{d}");
    let _ = fs::remove_dir_all(&home);
}

// ── Q3: one finding per machine per class ───────────────────────────────────────────────

/// Code-running rules in two project files and in user settings are one finding listing
/// every file; per-file rows stay in `permission_rules`. Fails on 837d9aa, which emitted
/// one finding per file.
#[test]
fn q3_code_execution_rules_across_files_are_one_finding() {
    let home = temp_dir("q3-exec");
    write(
        &home.join(".claude/settings.json"),
        r#"{"permissions":{"allow":["Bash(node:*)"]}}"#,
    );
    let a = home.join("a");
    let b = home.join("b");
    write(
        &a.join(".claude/settings.local.json"),
        r#"{"permissions":{"allow":["Bash(bash:*)"]}}"#,
    );
    write(
        &b.join(".claude/settings.local.json"),
        r#"{"permissions":{"allow":["Bash(uv run python:*)","Bash(cargo test:*)"]}}"#,
    );
    register(&home, &[&a, &b]);
    let (_, v, findings) = scan(&home, &["settings"]);
    let d = dump(&findings);
    let exec: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.title.starts_with("Code-execution allow rules"))
        .collect();
    assert_eq!(exec.len(), 1, "{d}");
    assert!(exec[0].title.contains("in 3 settings files"), "{d}");
    assert!(exec[0].location.contains("3 Claude Code settings files"), "{d}");
    let ev = exec[0].evidence.as_deref().unwrap();
    for r in ["Bash(node:*)", "Bash(bash:*)", "Bash(uv run python:*)"] {
        assert!(ev.contains(r), "{r}: {ev}");
    }
    assert!(!ev.contains("cargo test"), "{ev}");
    let rows: usize = v["agent_settings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            s["permission_rules"]
                .as_array()
                .map(|r| r.iter().filter(|x| x["class"] == "code-execution").count())
                .unwrap_or(0)
        })
        .sum();
    assert_eq!(rows, 3, "per-file rows stay in the inventory");
    let _ = fs::remove_dir_all(&home);
}

/// Low executables in ~/.claude/bin are one finding, naming the plugin they are named
/// after. Fails on 837d9aa, which emitted one Low per file.
#[test]
fn q3_agent_bin_executables_are_one_finding_naming_the_plugin() {
    let home = temp_dir("q3-bin");
    let ip = home.join(".claude/plugins/cache/mkt/toolkit/1.0.0");
    fs::create_dir_all(ip.join("skills/use")).unwrap();
    write(
        &ip.join("skills/use/SKILL.md"),
        "---\nname: use\ndescription: d\n---\nbody\n",
    );
    write(
        &home.join(".claude/plugins/installed_plugins.json"),
        &format!(
            "{{\"version\":2,\"plugins\":{{\"toolkit@mkt\":[{{\"scope\":\"user\",\"installPath\":\"{}\",\"version\":\"1.0.0\"}}]}}}}",
            ip.display()
        ),
    );
    write(
        &home.join(".claude/settings.json"),
        r#"{"enabledPlugins":{"toolkit@mkt":true}}"#,
    );
    let bin = home.join(".claude/bin");
    for n in ["toolkit", "toolkit-linux-x64"] {
        write(&bin.join(n), "#!/bin/sh\n");
        chmod(&bin.join(n), 0o755);
    }
    let (_, _, findings) = scan(&home, &["persistence", "settings", "skills"]);
    let d = dump(&findings);
    let bins: Vec<&Finding> = findings.iter().filter(|f| f.title.contains("~/.claude/bin")).collect();
    assert_eq!(bins.len(), 1, "{d}");
    assert_eq!(bins[0].severity, Severity::Low);
    assert_eq!(
        bins[0].title, "2 executables in ~/.claude/bin (plugin toolkit@mkt, by name) survive uninstall",
        "{d}"
    );
    assert!(bins[0].location.ends_with("/.claude/bin"), "{d}");

    // An unrelated name is counted as named after no installed plugin.
    write(&bin.join("other"), "#!/bin/sh\n");
    chmod(&bin.join("other"), 0o755);
    let (_, _, findings) = scan(&home, &["persistence", "settings", "skills"]);
    let f = find(&findings, "3 executables in ~/.claude/bin survive plugin uninstall");
    assert!(
        f.title
            .contains("(2 named after plugin toolkit@mkt; 1 named after no installed plugin)"),
        "{}",
        dump(&findings)
    );
    let _ = fs::remove_dir_all(&home);
}

// ── Q4: session-env / shell-snapshots graded by exported NAMES ─────────────────────────

const VALUE_CANARY: &str = "Qz8ExportedValueCanary";
const KEY_CANARY: &str = "sk-proj-Zx9SessionEnvKeyCanaryAbCdEfGhIjKlMn";

/// A HOME whose session-env and shell-snapshots files are world-readable, with a
/// `/etc/passwd` under the test system root.
fn names_home(tag: &str, session_env: &[(&str, &str)], snapshot: &str) -> PathBuf {
    let home = temp_dir(tag);
    let claude = home.join(".claude");
    for (rel, body) in session_env {
        let p = claude.join("session-env").join(rel);
        write(&p, body);
        chmod(&p, 0o644);
        chmod(p.parent().unwrap(), 0o755);
    }
    let snap = claude.join("shell-snapshots/snapshot-bash-1-x.sh");
    write(&snap, snapshot);
    chmod(&snap, 0o644);
    for d in ["", "session-env", "shell-snapshots"] {
        chmod(&claude.join(d), 0o755);
    }
    write(
        &home.join("sysroot/etc/passwd"),
        "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\nsync:x:5:0:sync:/sbin:/bin/sync\nalice:x:1500:1500::/home/alice:/bin/zsh\nsvc:x:990:990::/var/lib/svc:/bin/false\n",
    );
    home
}

/// The row of `store` in the Claude Code store finding's evidence table.
fn store_row<'a>(f: &'a Finding, store: &str) -> &'a str {
    let ev = f.evidence.as_deref().unwrap_or("");
    ev.split("; ")
        .find(|r| r.starts_with(&format!("{store} (")))
        .unwrap_or_else(|| panic!("no row {store}: {ev}"))
}

/// PATH-only session-env and a snapshot exporting PATH (plus a bare assignment and a
/// base64 line, neither an export) are Low "PATH/shell state only"; a secret-named
/// export is High naming the variable; another name is Medium. The exported VALUES never
/// appear in any output. Fails on 837d9aa, which graded both stores High "may contain
/// exported environment variables" without reading names.
#[test]
fn q4_session_env_and_snapshots_are_graded_by_exported_names() {
    let snapshot = format!(
        "# Snapshot file\nexport PATH=/usr/bin:{VALUE_CANARY}\nFAKE_TOKEN={VALUE_CANARY}\nZm9vYmFy=\n  __rvm() {{\n    local x={VALUE_CANARY}\n  }}\n"
    );
    let home = names_home(
        "q4-low",
        &[
            (
                "s1/sessionstart-hook-0.sh",
                &format!("export PATH=/opt/{VALUE_CANARY}:$PATH\n"),
            ),
            (
                "s2/sessionstart-hook-0.sh",
                "export LANG=C\nexport XDG_RUNTIME_DIR=/run/x\n",
            ),
        ],
        &snapshot,
    );
    let (text, v, findings) = scan(&home, &["transcripts"]);
    let d = dump(&findings);
    let t: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.category == "Transcript exposure")
        .collect();
    assert_eq!(t.len(), 1, "{d}");
    let f = t[0];
    let env_row = store_row(f, "session-env");
    let snap_row = store_row(f, "shell-snapshots");
    if blocked_above(&home) {
        assert_eq!(f.severity, Severity::Low, "{d}");
        assert!(f.title.contains("not reachable:"), "{d}");
    } else {
        assert_eq!(f.severity, Severity::Low, "PATH/shell state only: {d}");
        assert!(env_row.contains("low: contains PATH/shell state only"), "{env_row}");
        assert!(snap_row.contains("low: contains PATH/shell state only"), "{snap_row}");
        assert!(
            env_row.contains("2 of 2 readable files sampled, first 64 KiB each, in path order"),
            "{env_row}"
        );
    }
    let stores = v["transcripts"].as_array().unwrap();
    let names = |kind: &str| -> Vec<String> {
        stores.iter().find(|s| s["kind"] == kind).unwrap()["exported_names"]["names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(names("session environment"), ["LANG", "PATH", "XDG_RUNTIME_DIR"]);
    assert_eq!(
        names("shell snapshots"),
        ["PATH"],
        "a bare X= or base64 line in a snapshot is not an export"
    );
    // The other login accounts (Linux): root and alice, not nologin/false/sync.
    if cfg!(target_os = "linux") {
        assert!(
            f.evidence
                .as_deref()
                .unwrap()
                .contains("other accounts with a login shell on this machine: 2 (from /etc/passwd)"),
            "{d}"
        );
    }
    let terminal = run(&home, &["transcripts"], "terminal");
    let html = run(&home, &["transcripts"], "html");
    for out in [&text, &terminal, &html, &d] {
        assert!(!out.contains(VALUE_CANARY), "an exported value leaked");
    }
    let _ = fs::remove_dir_all(&home);

    // A secret-named export is High, by name only.
    let home = names_home(
        "q4-high",
        &[(
            "s1/sessionstart-hook-0.sh",
            &format!("export OPENAI_API_KEY={KEY_CANARY}\nexport PATH=/x\nMY_SETTING={VALUE_CANARY}\n"),
        )],
        "export PATH=/usr/bin\n",
    );
    let (text, _, findings) = scan(&home, &["transcripts"]);
    let d = dump(&findings);
    let f = find(&findings, "Claude Code state under ~/.claude");
    let env_row = store_row(f, "session-env");
    if !blocked_above(&home) {
        assert_eq!(f.severity, Severity::High, "{d}");
        assert!(
            env_row.contains("high: exports a secret-named variable (name only): OPENAI_API_KEY"),
            "{env_row}"
        );
    }
    let terminal = run(&home, &["transcripts"], "terminal");
    for out in [&text, &terminal, &d] {
        assert!(
            !out.contains(VALUE_CANARY) && !out.contains(KEY_CANARY),
            "an exported value leaked"
        );
    }
    let _ = fs::remove_dir_all(&home);

    // Another name is Medium.
    let home = names_home(
        "q4-medium",
        &[(
            "s1/sessionstart-hook-0.sh",
            "export NODE_OPTIONS=--max-old-space-size=4096\n",
        )],
        "export PATH=/usr/bin\n",
    );
    let (_, _, findings) = scan(&home, &["transcripts"]);
    let f = find(&findings, "Claude Code state under ~/.claude");
    if !blocked_above(&home) {
        assert_eq!(f.severity, Severity::Medium, "{}", dump(&findings));
        assert!(
            store_row(f, "session-env")
                .contains("medium: exports variables beyond shell state (names only): NODE_OPTIONS"),
            "{}",
            dump(&findings)
        );
    }
    let _ = fs::remove_dir_all(&home);
}

// ── Q5: MCP, credential-read and inert-rule wording ─────────────────────────────────────

/// A whole-server wildcard on a disabled plugin's server is noted as disabled (and alone
/// it is Low); a phantom server name says what it is; a credential read names what it
/// reaches; inert rules are counted. Fails on 837d9aa, whose titles carry none of this.
#[test]
fn q5_mcp_credential_and_inert_wording() {
    let home = temp_dir("q5");
    let mut entries = Vec::new();
    for p in ["live", "off"] {
        let ip = home.join(".claude/plugins/cache/mkt").join(p).join("1.0.0");
        write(
            &ip.join(".mcp.json"),
            &format!(r#"{{"{p}":{{"command":"echo","args":["x"]}}}}"#),
        );
        entries.push(format!(
            "\"{p}@mkt\":[{{\"scope\":\"user\",\"installPath\":\"{}\",\"version\":\"1.0.0\"}}]",
            ip.display()
        ));
    }
    write(
        &home.join(".claude/plugins/installed_plugins.json"),
        &format!("{{\"version\":2,\"plugins\":{{{}}}}}", entries.join(",")),
    );
    let h = home.display().to_string();
    write(
        &home.join(".claude/settings.json"),
        &serde_json::json!({
            "enabledPlugins": {"live@mkt": true, "off@mkt": false},
            "permissions": {"allow": [
                "mcp__plugin_live_live__*",
                "mcp__plugin_off_off__*",
                "mcp__ghost__*",
                format!("Read(//{}/**)", h.trim_start_matches('/')),
                "Read(~/.claude/plans/**)",
                format!("Read({h}/x/**)"),
                "Write(~/notes/**)"
            ]}
        })
        .to_string(),
    );
    let (_, _, findings) = scan(&home, &["settings", "mcp"]);
    let d = dump(&findings);
    let mcp = find(&findings, "every tool of MCP server(s) plugin_live_live");
    assert_eq!(mcp.severity, Severity::Medium, "{d}");
    assert!(mcp.title.contains("(1 currently disabled: plugin_off_off)"), "{d}");
    let phantom = find(&findings, "Allow rules pre-approve 1 MCP server name(s)");
    assert!(
        phantom.title.contains("that no installed plugin or configured server provides; a server later added under that name is trusted without a prompt: ghost"),
        "{d}"
    );
    let read = find(&findings, "pre-approves reading");
    assert!(
        read.title.starts_with(&format!(
            "Read(//{}/**) pre-approves reading ~/.ssh, ~/.aws/credentials, ~/.claude/.credentials.json and ",
            h.trim_start_matches('/')
        )),
        "{d}"
    );
    assert!(
        !read.title.contains("plans"),
        "a scoped agent-state read is not graded: {d}"
    );
    let inert = find(&findings, "allow rule(s) never match what they name");
    assert!(
        inert.title.starts_with("2 allow rule(s) never match what they name"),
        "{d}"
    );

    // Only the disabled server: Low.
    write(
        &home.join(".claude/settings.json"),
        r#"{"enabledPlugins":{"live@mkt":true,"off@mkt":false},"permissions":{"allow":["mcp__plugin_off_off__*"]}}"#,
    );
    let (_, _, findings) = scan(&home, &["settings", "mcp"]);
    let off = find(&findings, "every tool of MCP server(s) plugin_off_off");
    assert_eq!(off.severity, Severity::Low, "{}", dump(&findings));
    assert!(off.title.contains("currently disabled"));
    let _ = fs::remove_dir_all(&home);
}

// ── Q6: toxic-flow wording ───────────────────────────────────────────────────────────────

/// Sources and sinks name servers first; a claude.ai connector says when it was last
/// used (its newest `mcp-logs-*` mtime); skill files are "mention" counts, never a
/// source. Fails on 837d9aa, whose title listed capabilities only and whose evidence
/// called skill counts "filesystem from 1 skill file(s)".
#[test]
fn q6_toxic_flow_names_servers_first_and_skills_as_mentions() {
    let home = temp_dir("q6");
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
    write(
        &home.join(".claude/skills/reader/SKILL.md"),
        "---\nname: reader\ndescription: reads notes\n---\nUse read_file on the notes.\n",
    );
    let log = home.join(".cache/claude-cli-nodejs/-p-a/mcp-logs-claude-ai-Gmail");
    write(&log.join("2026-05-28.jsonl"), "x");
    let when = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_780_000_000);
    fs::File::open(&log).unwrap().set_modified(when).unwrap();

    let (_, _, findings) = scan(&home, &["mcp", "skills"]);
    let d = dump(&findings);
    let tf = find(&findings, "on the agent surface");
    assert_eq!(tf.category, "Toxic Flow");
    assert!(
        tf.title.starts_with(
            "sensitive source (claude.ai Gmail: private_data; loading skills mention filesystem) + exfil sink (playwright: network)"
        ),
        "{d}"
    );
    let ev = tf.evidence.as_deref().unwrap();
    assert!(
        ev.contains("claude.ai Gmail (claude.ai connector, ever connected, last used 2026-05-28): private_data"),
        "{ev}"
    );
    assert!(ev.contains("(+1 loading skill(s) mention filesystem)"), "{ev}");
    assert!(
        !ev.contains("filesystem from"),
        "a skill mention is never a source: {ev}"
    );
    let _ = fs::remove_dir_all(&home);
}

// ── Q7: destructive and wrapper rules ───────────────────────────────────────────────────

/// Rules that change remote or privileged state are one Medium; wrapper rules one Low
/// that says what is documented; read-only, stripped-wrapper and scoped rules are
/// inventory. Fails on 837d9aa, which had neither class.
#[test]
fn q7_destructive_and_wrapper_rules() {
    let home = temp_dir("q7");
    write(
        &home.join(".claude/settings.json"),
        r#"{"permissions":{"allow":[
            "Bash(ssh:*)","Bash(sudo chown:*)","Bash(gh repo delete:*)","Bash(aws s3 rm:*)",
            "Bash(rm -rf:*)","Bash(kubectl delete:*)","Bash(terraform apply:*)","Bash(gh api:*)",
            "Bash(aws iam list-roles:*)","Bash(git push:*)","Bash(gh pr view:*)",
            "Bash(xargs:*)","Bash(env:*)","Bash(make:*)",
            "Bash(xargs grep:*)","Bash(timeout:*)","Bash(find:*)","Bash(make test)"
        ]}}"#,
    );
    let (_, _, findings) = scan(&home, &["settings"]);
    let d = dump(&findings);
    let destructive = find(&findings, "pre-approve commands that change remote or privileged state");
    assert_eq!(destructive.severity, Severity::Medium, "{d}");
    let ev = destructive.evidence.as_deref().unwrap();
    for r in [
        "Bash(ssh:*)",
        "Bash(sudo chown:*)",
        "Bash(gh repo delete:*)",
        "Bash(aws s3 rm:*)",
        "Bash(rm -rf:*)",
        "Bash(kubectl delete:*)",
        "Bash(terraform apply:*)",
        "Bash(gh api:*)",
    ] {
        assert!(ev.contains(r), "{r}: {ev}");
    }
    for r in ["list-roles", "git push", "gh pr view"] {
        assert!(!ev.contains(r), "{r} is inventory: {ev}");
    }
    let wrapper = find(&findings, "may run arbitrary commands through a wrapper");
    assert_eq!(wrapper.severity, Severity::Low, "{d}");
    assert!(wrapper.title.starts_with("3 allow rule(s) in 1 settings file"), "{d}");
    let ev = wrapper.evidence.as_deref().unwrap();
    for r in ["Bash(xargs:*)", "Bash(env:*)", "Bash(make:*)"] {
        assert!(ev.contains(r), "{r}: {ev}");
    }
    assert!(ev.contains("not documented"), "the uncertainty is stated: {ev}");
    for r in ["xargs grep", "timeout", "find", "make test"] {
        assert!(!ev.contains(&format!("Bash({r}")), "{r} is not a wrapper rule: {ev}");
    }
    let _ = fs::remove_dir_all(&home);
}

// ── Q8: the autoMode block ───────────────────────────────────────────────────────────────

/// `hard_deny` without `"$defaults"` is High; a `soft_deny` keeping it is not; custom
/// `allow` entries are Medium with the entries redacted by shape; trusted environment
/// slots are Medium by slot name only; `classifyAllShell` is inventory, and with auto
/// mode it suspends curl rules too; `autoMode` in project settings is a Low inert note.
/// Fails on 837d9aa, which did not read `autoMode`.
#[test]
fn q8_auto_mode_block() {
    const TOKEN: &str = "ghp_Zq9AutoModeAllowCanaryAbCdEfGhIjKlMnOp12";
    let home = temp_dir("q8");
    write(
        &home.join(".claude/settings.json"),
        &serde_json::json!({
            "permissions": {"defaultMode": "auto", "allow": ["Bash(curl:*)"]},
            "autoMode": {
                "hard_deny": ["Never touch prod"],
                "soft_deny": ["$defaults", "Never run migrations"],
                "allow": ["$defaults", format!("Deploying with token {TOKEN} is allowed")],
                "environment": ["$defaults", "Trusted internal domains: *.corp-secret.example.com", "Organization: Acme"],
                "classifyAllShell": true
            }
        })
        .to_string(),
    );
    let proj = home.join("p");
    write(
        &proj.join(".claude/settings.local.json"),
        r#"{"autoMode":{"allow":["anything goes"]}}"#,
    );
    register(&home, &[&proj]);
    let (text, v, findings) = scan(&home, &["settings"]);
    let d = dump(&findings);
    let hard = find(&findings, "built-in auto-mode denials are discarded");
    assert_eq!(hard.severity, Severity::High, "{d}");
    assert!(
        hard.title.contains("autoMode.hard_deny is set without \"$defaults\"")
            && hard.title.contains("the built-in data-exfiltration hard-deny")
            && !hard.title.contains("soft_deny"),
        "{d}"
    );
    let allow = find(&findings, "autoMode.allow adds 1 custom exception(s)");
    assert_eq!(allow.severity, Severity::Medium, "{d}");
    assert!(
        allow.evidence.as_deref().unwrap().contains("Deploying with token"),
        "{d}"
    );
    let env = find(
        &findings,
        "autoMode.environment widens what the auto-mode classifier trusts",
    );
    assert_eq!(env.severity, Severity::Medium, "{d}");
    assert!(
        env.title.contains("Trusted internal domains (1)") && !env.title.contains("Organization"),
        "{d}"
    );
    let ignored = find(&findings, "autoMode in project settings is ignored by Claude Code");
    assert_eq!(ignored.severity, Severity::Low, "{d}");
    assert!(ignored.location.ends_with("/p/.claude/settings.local.json"), "{d}");
    // classifyAllShell + auto: the curl rule is suspended too.
    let curl = find(&findings, "Code-execution allow rules in 1 settings file: suspended");
    assert_eq!(curl.severity, Severity::Low, "{d}");
    assert!(curl.evidence.as_deref().unwrap().contains("Bash(curl:*)"), "{d}");
    let user = v["agent_settings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["source"] == "user-global")
        .unwrap();
    assert_eq!(user["auto_mode"]["classify_all_shell"], true, "{text}");
    let terminal = run(&home, &["settings"], "terminal");
    assert!(
        terminal.contains("autoMode.classifyAllShell (in auto mode the classifier reviews every shell command)"),
        "a positive note in the inventory: {terminal}"
    );
    assert!(!terminal.contains(TOKEN));
    for out in [&text, &d] {
        assert!(!out.contains(TOKEN), "a token in an autoMode entry is redacted");
        assert!(
            !out.contains("corp-secret"),
            "environment entries are shown by slot name only"
        );
    }

    // Defaults kept everywhere and nothing custom: no autoMode finding.
    write(
        &home.join(".claude/settings.json"),
        r#"{"autoMode":{"hard_deny":["$defaults"],"soft_deny":["$defaults"],"allow":["$defaults"],"environment":["$defaults","Organization: Acme"]}}"#,
    );
    fs::remove_file(proj.join(".claude/settings.local.json")).unwrap();
    let (_, _, findings) = scan(&home, &["settings"]);
    assert!(
        !findings.iter().any(|f| f.title.contains("autoMode")),
        "{}",
        dump(&findings)
    );
    let _ = fs::remove_dir_all(&home);
}
