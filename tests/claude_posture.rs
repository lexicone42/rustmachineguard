//! End-to-end tests for Claude Code posture: permission modes and the dangerous-mode
//! confirmation, allow rules graded by class (whole MCP servers, code-running shells,
//! credential reads and edits, rules that do not match the path they name), world-
//! readable ~/.claude stores and ~/.claude.json, agent URL scheme handlers, executables
//! in ~/.claude/bin, and plugin records whose install is missing. Each test builds a temp
//! HOME, runs the real binary with only the scanners it needs, and checks positive
//! fixtures next to negative controls. The assertions read the JSON report and the
//! findings only, so they run (and fail) against a build that predates these checks.
#![cfg(unix)]

use rustmachineguard::analysis::{Finding, Severity, collect_findings};
use rustmachineguard::models::ScanReport;
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
    let d = std::env::temp_dir().join(format!("rmg-ccp-{tag}-{}", std::process::id()));
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

/// Run rmguard against `home` with only `keep` scanners; the JSON report as text.
fn run_json(home: &Path, keep: &[&str]) -> String {
    let skip: Vec<&str> = ALL_LABELS.iter().copied().filter(|l| !keep.contains(l)).collect();
    let out = Command::new(env!("CARGO_BIN_EXE_rmguard"))
        .args(["--skip", &skip.join(","), "--format", "json"])
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

fn scan(home: &Path, keep: &[&str]) -> (ScanReport, Vec<Finding>, String) {
    let text = run_json(home, keep);
    let report: ScanReport = serde_json::from_str(&text).expect("report json");
    let findings = collect_findings(&report);
    (report, findings, text)
}

fn of<'a>(findings: &'a [Finding], category: &str) -> Vec<&'a Finding> {
    findings.iter().filter(|f| f.category == category).collect()
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

// ── W1: permission mode and the dangerous-mode confirmation ─────────────────────────

#[test]
fn auto_mode_and_skipped_dangerous_confirmation_are_graded_in_user_settings() {
    let home = temp_dir("mode-user");
    write(
        &home.join(".claude/settings.json"),
        r#"{"permissions":{"defaultMode":"auto"},"skipDangerousModePermissionPrompt":true}"#,
    );
    let (_, findings, _) = scan(&home, &["settings"]);
    let perms = of(&findings, "Permissions");
    let d = dump(&findings);
    assert!(
        perms
            .iter()
            .any(|f| f.severity == Severity::Low && f.title.contains("auto mode") && f.title.contains("classifier")),
        "{d}"
    );
    assert!(
        perms.iter().any(|f| f.severity == Severity::Medium
            && f.title.contains("dangerous-mode confirmation is disabled")
            && f.evidence.as_deref() == Some("skipDangerousModePermissionPrompt: true")),
        "{d}"
    );
    assert_eq!(perms.len(), 2, "{d}");
}

#[test]
fn skipped_confirmation_with_bypass_default_is_critical() {
    let home = temp_dir("mode-critical");
    write(
        &home.join(".claude/settings.json"),
        r#"{"permissions":{"defaultMode":"bypassPermissions"},"skipDangerousModePermissionPrompt":true}"#,
    );
    let (_, findings, _) = scan(&home, &["settings"]);
    let d = dump(&findings);
    assert!(
        findings.iter().any(|f| f.severity == Severity::Critical
            && f.category == "Permissions"
            && f.title.contains("sessions start in bypassPermissions")),
        "{d}"
    );
    // The existing bypassPermissions finding is unchanged.
    assert!(
        findings
            .iter()
            .any(|f| f.severity == Severity::High
                && f.title.contains("runs without approval prompts (bypassPermissions)")),
        "{d}"
    );
}

#[test]
fn restrictive_modes_and_project_scoped_mode_keys_are_not_graded() {
    let home = temp_dir("mode-negative");
    write(
        &home.join(".claude/settings.json"),
        r#"{"permissions":{"defaultMode":"plan"}}"#,
    );
    // auto and skipDangerousModePermissionPrompt do not take effect from project
    // settings (code.claude.com/docs/en/settings-reference); dontAsk denies what would
    // prompt.
    let proj = home.join("proj");
    write(
        &proj.join(".claude/settings.json"),
        r#"{"permissions":{"defaultMode":"auto"},"skipDangerousModePermissionPrompt":true}"#,
    );
    write(
        &proj.join(".claude/settings.local.json"),
        r#"{"permissions":{"defaultMode":"dontAsk"}}"#,
    );
    write(
        &home.join(".claude.json"),
        &format!("{{\"projects\":{{\"{}\":{{}}}}}}", proj.display()),
    );
    let (report, findings, _) = scan(&home, &["settings"]);
    assert!(
        report.agent_settings.iter().any(|s| s.source == "project"),
        "the project file was read"
    );
    assert!(of(&findings, "Permissions").is_empty(), "{}", dump(&findings));
}

// ── W2: allow rules ──────────────────────────────────────────────────────────────────

const TOKEN: &str = "ghp_Zq9CanaryRuleTokenAbCdEfGhIjKlMnOpQr12";

fn rules_home(tag: &str) -> PathBuf {
    let home = temp_dir(tag);
    let h = home.display().to_string();
    write(
        &home.join(".claude/settings.json"),
        &serde_json::json!({
            "permissions": {
                "allow": [
                    "mcp__cfg__*",
                    "mcp__ghost__*",
                    "mcp__cfg__get_issue",
                    "Bash(curl:*)",
                    "Bash(python3:*)",
                    "Bash(uv run:*)",
                    "Bash(git status:*)",
                    "Bash(git push:*)",
                    "Bash(npm test)",
                    format!("Bash(curl -H 'Authorization: Bearer {TOKEN}' https://api.example.com:*)"),
                    "Read(~/.claude/**)",
                    "Read(src/**)",
                    format!("Read({h}/.claude/**)"),
                    "Edit(~/.ssh/**)",
                    "Edit(~/.claude/**)",
                    "Write(~/notes/**)"
                ],
                "deny": ["Bash(rm -rf:*)"]
            }
        })
        .to_string(),
    );
    write(
        &home.join(".claude.json"),
        r#"{"mcpServers":{"cfg":{"command":"echo","args":["hi"]}}}"#,
    );
    home
}

#[test]
fn allow_rules_are_kept_and_graded_per_class_in_user_settings() {
    let home = rules_home("rules-user");
    let (_, findings, text) = scan(&home, &["settings", "mcp"]);
    let d = dump(&findings);
    let perms = of(&findings, "Permissions");
    let find = |needle: &str| {
        perms
            .iter()
            .find(|f| f.title.contains(needle))
            .unwrap_or_else(|| panic!("no finding with {needle:?}:\n{d}"))
    };

    // (a) A configured server's wildcard is Medium; an unconfigured one is a Low phantom.
    let mcp = find("every tool of MCP server(s)");
    assert_eq!(mcp.severity, Severity::Medium, "{d}");
    assert!(mcp.title.contains("cfg") && !mcp.title.contains("ghost"), "{d}");
    let phantom = find("that no installed plugin or configured server provides");
    assert_eq!(phantom.severity, Severity::Low, "{d}");
    assert!(phantom.title.contains("ghost") && !phantom.title.contains("cfg"), "{d}");

    // (b) Code-running shells: no session starts in auto mode here, so the interpreter
    // rules are one Medium and the network-transfer rule another; scoped rules are in
    // neither.
    let exec = find("Code-execution allow rules in 1 settings file: arbitrary code runs without a prompt");
    assert_eq!(exec.severity, Severity::Medium, "{d}");
    let ev = exec.evidence.as_deref().unwrap_or("");
    for r in ["Bash(python3:*)", "Bash(uv run:*)"] {
        assert!(ev.contains(r), "{r}: {d}");
    }
    let net = find("Network-transfer allow rules (curl, wget) in 1 settings file");
    assert_eq!(net.severity, Severity::Medium, "{d}");
    assert!(net.evidence.as_deref().unwrap_or("").contains("Bash(curl:*)"), "{d}");
    for f in [exec, net] {
        let ev = f.evidence.as_deref().unwrap_or("");
        for r in ["git status", "git push", "npm test", "api.example.com"] {
            assert!(!ev.contains(r), "{r} is scoped: {d}");
        }
    }

    // (c) Read of agent state: High, naming what it reaches. (d) Edit of ~/.ssh: High;
    // Edit(~/.claude/**) is a protected-path write no allow rule pre-approves, so it is
    // not listed.
    let read = find("pre-approves reading");
    assert_eq!(read.severity, Severity::High, "{d}");
    assert!(
        read.title
            .starts_with("Read(~/.claude/**) pre-approves reading ~/.claude/.credentials.json")
            && !read.title.contains("src/**"),
        "{d}"
    );
    let edit = find("pre-approves editing");
    assert_eq!(edit.severity, Severity::High, "{d}");
    assert!(
        edit.title.starts_with("Edit(~/.ssh/**) pre-approves editing ~/.ssh") && !edit.title.contains(".claude"),
        "{d}"
    );

    // A single-slash absolute home path anchors at ~/.claude/, and Write(path) never
    // matches: one Low note.
    let inert = find("allow rule(s) never match what they name");
    assert_eq!(inert.severity, Severity::Low, "{d}");
    assert!(
        inert.title.starts_with("2 allow rule(s)") && inert.title.contains("Write(~/notes/**)"),
        "{d}"
    );
    assert!(inert.evidence.as_deref().unwrap_or("").contains("anchors at"), "{d}");

    assert_eq!(perms.len(), 7, "one finding per class and grade: {d}");

    // The rules themselves are in the report, the deny rule as inventory, and a token
    // pasted into a rule is redacted.
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let user = json["agent_settings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["source"] == "user-global")
        .unwrap();
    let rules = user["permission_rules"].as_array().expect("permission_rules");
    assert_eq!(rules.len(), 17, "{rules:?}");
    assert!(
        rules
            .iter()
            .any(|r| r["list"] == "deny" && r["rule"] == "Bash(rm -rf:*)")
    );
    assert!(
        rules
            .iter()
            .any(|r| r["rule"] == "mcp__ghost__*" && r["class"] == "mcp-server-wildcard"),
        "a server name is not mistaken for a key: {rules:?}"
    );
    assert!(!text.contains(TOKEN), "a token in an allow rule must never be printed");
}

#[test]
fn allow_rules_from_a_repository_settings_file_are_high() {
    let home = temp_dir("rules-repo");
    let proj = home.join("proj");
    write(
        &proj.join(".claude/settings.json"),
        r#"{"permissions":{"allow":["Bash(bash:*)","mcp__cfg__*","Bash(git status:*)"]}}"#,
    );
    write(
        &home.join(".claude.json"),
        &format!(
            "{{\"projects\":{{\"{}\":{{}}}},\"mcpServers\":{{\"cfg\":{{\"command\":\"echo\"}}}}}}",
            proj.display()
        ),
    );
    let (_, findings, _) = scan(&home, &["settings", "mcp"]);
    let d = dump(&findings);
    let perms = of(&findings, "Permissions");
    assert!(
        perms.iter().any(|f| f.severity == Severity::High
            && f.title
                .contains("Code-execution allow rules in 1 project settings file")
            && f.title.ends_with("— from project settings")
            && f.evidence.as_deref().unwrap_or("").contains("Bash(bash:*)")),
        "{d}"
    );
    assert!(
        perms
            .iter()
            .any(|f| f.severity == Severity::High && f.title.contains("every tool of MCP server(s) cfg")),
        "{d}"
    );
    assert_eq!(perms.len(), 2, "{d}");
}

#[test]
fn scoped_rules_alone_raise_nothing() {
    let home = temp_dir("rules-negative");
    write(
        &home.join(".claude/settings.json"),
        r#"{"permissions":{"allow":["Bash(git status:*)","Bash(git push:*)","Bash(cargo test:*)","mcp__cfg__get_issue","Read(./docs/**)","WebFetch(domain:docs.rs)"]}}"#,
    );
    let (_, findings, _) = scan(&home, &["settings", "mcp"]);
    assert!(of(&findings, "Permissions").is_empty(), "{}", dump(&findings));
}

// ── W3: stores and ~/.claude.json ─────────────────────────────────────────────────────

fn stores_home(tag: &str) -> PathBuf {
    let home = temp_dir(tag);
    let claude = home.join(".claude");
    write(&claude.join("shell-snapshots/snapshot-bash-1.sh"), "# shape only");
    write(&claude.join("backups/.claude.json.backup.1"), "{}");
    write(&claude.join("statsig/statsig.cached.evaluations.1"), "{}");
    // paste-cache files are 0600: only names are visible, so no finding.
    write(&claude.join("paste-cache/p1.txt"), "x");
    chmod(&claude.join("paste-cache/p1.txt"), 0o600);
    // Transcripts written 0600 under a 0755 projects/ were reported before; the files
    // are not readable by others, so they are not now.
    write(&claude.join("projects/-w-p/s.jsonl"), "{}");
    chmod(&claude.join("projects/-w-p/s.jsonl"), 0o600);
    chmod(&claude.join("projects/-w-p"), 0o755);
    chmod(&claude.join("projects"), 0o755);
    for d in ["", "shell-snapshots", "backups", "statsig", "paste-cache"] {
        chmod(&claude.join(d), 0o755);
    }
    for f in [
        "shell-snapshots/snapshot-bash-1.sh",
        "backups/.claude.json.backup.1",
        "statsig/statsig.cached.evaluations.1",
    ] {
        chmod(&claude.join(f), 0o644);
    }
    write(&home.join(".claude.json"), r#"{"projects":{}}"#);
    chmod(&home.join(".claude.json"), 0o644);
    write(&home.join(".claude.json.backup"), r#"{"projects":{}}"#);
    chmod(&home.join(".claude.json.backup"), 0o640);
    home
}

#[test]
fn world_readable_stores_and_account_file_are_graded_by_what_others_can_open() {
    let home = stores_home("stores");
    let (_, findings, _) = scan(&home, &["transcripts"]);
    let d = dump(&findings);
    let t = of(&findings, "Transcript exposure");
    // The grade counts what OTHER users can open, so every ancestor must be traversable.
    // macOS keeps `$TMPDIR` under a user-private `/private/var/folders/...` directory, and
    // there the same fixture is honestly downgraded to Low "not reachable" (the path the
    // 0700 test below exercises on purpose). Assert that path instead of faking a High.
    let blocked_above = home.ancestors().skip(1).any(|a| {
        std::fs::metadata(a)
            .map(|m| m.permissions().mode() & 0o001 == 0)
            .unwrap_or(false)
    });
    // Claude Code's stores are ONE finding with a table of stores in the evidence.
    assert_eq!(t.len(), 1, "{d}");
    let f = t[0];
    let ev = f.evidence.as_deref().unwrap_or("");
    if blocked_above {
        assert_eq!(
            f.severity,
            Severity::Low,
            "ancestor above the fixture is not traversable: {d}"
        );
        assert!(f.title.contains("not reachable:"), "{d}");
        return;
    }
    assert_eq!(f.severity, Severity::High, "{d}\n{ev}");
    assert!(
        f.title.starts_with(
            "Claude Code state under ~/.claude and ~/.claude.json is readable by other local accounts (5 stores, about 5 files)"
        ),
        "{d}"
    );
    for row in [
        // A snapshot exporting nothing beyond shell state is Low on its own.
        "shell-snapshots (shell snapshots): file, low: contains PATH/shell state only",
        "backups (settings backups): file, high: copies of ~/.claude.json",
        "statsig (feature-flag cache): file, medium",
        ".claude.json (account state file): file, high: account identifier and project list",
        ".claude.json.backup (account state backup): file, medium",
    ] {
        assert!(ev.contains(row), "{row}: {ev}");
    }
    assert!(
        !ev.contains("paste-cache"),
        "0600 files under a 0755 directory are not readable: {ev}"
    );
    assert!(!ev.contains("projects ("), "{ev}");
    assert!(
        ev.contains("other accounts with a login shell on this machine: not determined"),
        "no /etc/passwd under the test system root: {ev}"
    );
}

#[test]
fn a_home_others_cannot_traverse_downgrades_store_findings_to_low() {
    let home = stores_home("stores-0700");
    chmod(&home, 0o700);
    let (_, findings, _) = scan(&home, &["transcripts"]);
    chmod(&home, 0o755);
    let d = dump(&findings);
    let t = of(&findings, "Transcript exposure");
    assert_eq!(t.len(), 1, "{d}");
    assert_eq!(t[0].severity, Severity::Low, "{d}");
    assert!(
        t[0].title.contains("(5 stores, about 5 files)")
            && t[0].title.contains("not reachable:")
            && t[0].title.contains("is 0700"),
        "{d}"
    );
}

// ── W4: URL scheme handlers ────────────────────────────────────────────────────────────

#[test]
fn an_agent_url_scheme_handler_is_inventoried_with_a_low_advisory() {
    let home = temp_dir("urlhandler");
    let apps = home.join(".local/share/applications");
    write(
        &apps.join("claude-code-url-handler.desktop"),
        "[Desktop Entry]\nName=Claude Code URL Handler\nExec=\"~/.local/bin/claude\" --handle-uri %u\nType=Application\nNoDisplay=true\nMimeType=x-scheme-handler/claude-cli;\n",
    );
    // A browser's own handler is not an agent's.
    write(
        &apps.join("firefox.desktop"),
        "[Desktop Entry]\nName=Firefox\nExec=firefox %u\nMimeType=text/html;x-scheme-handler/http;x-scheme-handler/https;\n",
    );
    // A system-wide handler whose program is a known agent, under any scheme.
    write(
        &home.join("sysroot/usr/share/applications/cursor-url.desktop"),
        "[Desktop Entry]\nName=Cursor\nExec=/usr/share/cursor/cursor --open-url %U\nMimeType=x-scheme-handler/cursor;\n",
    );
    write(
        &home.join(".config/mimeapps.list"),
        "[Default Applications]\nx-scheme-handler/claude-cli=claude-code-url-handler.desktop\n",
    );
    let (report, findings, _) = scan(&home, &["persistence"]);
    let d = dump(&findings);
    let rows: Vec<_> = report
        .persistence_artifacts
        .iter()
        .filter(|a| a.kind == "url-handler")
        .collect();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(
        rows.iter()
            .any(|a| a.detail == "claude-cli:// opens claude (the default handler in mimeapps.list)")
    );
    assert!(rows.iter().any(|a| a.detail == "cursor:// opens cursor"));
    let low: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.title
                .starts_with("URL scheme handler: a browser link can launch the agent")
        })
        .collect();
    assert_eq!(low.len(), 2, "{d}");
    assert!(
        low.iter()
            .all(|f| f.severity == Severity::Low && f.category == "Persistence")
    );
}

// ── W5: executables in ~/.claude/bin ───────────────────────────────────────────────────

#[test]
fn agent_bin_executables_are_inventoried_and_graded() {
    let home = temp_dir("agentbin");
    let bin = home.join(".claude/bin");
    write(&bin.join("helper"), "#!/bin/sh\necho hi\n");
    chmod(&bin.join("helper"), 0o755);
    fs::write(bin.join("native"), b"\x7fELF\x02\x01\x01\x00rest").unwrap();
    chmod(&bin.join("native"), 0o755);
    write(&bin.join("open"), "#!/bin/sh\n");
    chmod(&bin.join("open"), 0o777);
    write(&bin.join("README"), "not executable");
    chmod(&bin.join("README"), 0o644);
    write(
        &home.join(".claude/settings.json"),
        r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"~/.claude/bin/helper --stop"}]}]}}"#,
    );
    let (_, findings, text) = scan(&home, &["persistence", "settings"]);
    let d = dump(&findings);
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let rows: Vec<&serde_json::Value> = json["persistence_artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["kind"] == "agent-bin")
        .collect();
    assert_eq!(rows.len(), 3, "the 0644 README is not an executable: {rows:?}");
    let row = |name: &str| {
        *rows
            .iter()
            .find(|a| a["path"].as_str().unwrap().ends_with(&format!("/.claude/bin/{name}")))
            .unwrap()
    };
    assert_eq!(row("native")["bin"]["format"], "elf");
    assert_eq!(row("helper")["bin"]["format"], "script");
    assert_eq!(row("helper")["bin"]["mode"], "0755");
    assert_eq!(row("helper")["bin"]["owned_by_user"], true);
    assert_eq!(row("helper")["bin"]["sha256"].as_str().unwrap().len(), 64, "hex sha256");

    // The world-writable one is its own High; the two Lows are one finding per machine.
    let open = findings
        .iter()
        .find(|f| f.location.ends_with("/bin/open"))
        .unwrap_or_else(|| panic!("{d}"));
    assert_eq!(open.severity, Severity::High, "world-writable: {d}");
    assert!(open.title.starts_with("Executable in the agent's bin directory"), "{d}");
    let lows: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("in ~/.claude/bin") && f.title.contains("survive"))
        .collect();
    assert_eq!(lows.len(), 1, "{d}");
    assert_eq!(lows[0].severity, Severity::Low, "{d}");
    assert!(lows[0].title.starts_with("2 executables in ~/.claude/bin"), "{d}");
    let ev = lows[0].evidence.as_deref().unwrap_or("");
    assert!(ev.contains("native (elf, 0755)"), "{ev}");
    assert!(
        ev.contains("helper (script, 0755) — a hook runs it"),
        "hooked, but owned by the user: {ev}"
    );

    // The same hooked file owned by someone else is High.
    let mut json = json;
    for a in json["persistence_artifacts"].as_array_mut().unwrap() {
        if a["path"].as_str().unwrap().ends_with("/bin/helper") {
            a["bin"]["owned_by_user"] = serde_json::Value::Bool(false);
        }
    }
    let report: ScanReport = serde_json::from_value(json).unwrap();
    let f2 = collect_findings(&report);
    assert!(
        f2.iter().any(|f| f.severity == Severity::High
            && f.location.ends_with("/bin/helper")
            && f.title.contains("not owned by you")),
        "{}",
        dump(&f2)
    );
}

// ── W6: dangling plugin records ─────────────────────────────────────────────────────────

#[test]
fn a_plugin_record_whose_install_is_missing_is_a_low_advisory() {
    let home = temp_dir("dangling");
    let plugins = home.join(".claude/plugins");
    let present = plugins.join("cache/m/present/1.0.0");
    fs::create_dir_all(&present).unwrap();
    let missing = plugins.join("cache/local/gone/1.0.0");
    let enabled_missing = plugins.join("cache/local/live/2.0.0");
    write(
        &plugins.join("installed_plugins.json"),
        &serde_json::json!({
            "version": 2,
            "plugins": {
                "present@m": [{"scope": "user", "installPath": present}],
                "gone@local": [{"scope": "user", "installPath": missing}],
                "live@local": [{"scope": "user", "installPath": enabled_missing}]
            }
        })
        .to_string(),
    );
    write(
        &home.join(".claude/settings.json"),
        r#"{"enabledPlugins":{"live@local":true,"present@m":true}}"#,
    );
    let (report, findings, _) = scan(&home, &["persistence"]);
    let d = dump(&findings);
    let rows: Vec<_> = report
        .persistence_artifacts
        .iter()
        .filter(|a| a.kind == "dangling-plugin-record")
        .collect();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows.iter().any(|a| a.detail == "gone@local; not enabled"));
    assert!(rows.iter().any(|a| a.detail == "live@local; enabled in user settings"));
    let low: Vec<_> = findings
        .iter()
        .filter(|f| f.title.starts_with("Plugin record points at a missing install"))
        .collect();
    assert_eq!(low.len(), 2, "{d}");
    assert!(
        low.iter()
            .all(|f| f.severity == Severity::Low && f.title.contains("may load it"))
    );
}
