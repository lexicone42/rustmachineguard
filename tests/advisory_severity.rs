//! Exposure grades follow the catalog row's `advisory_severity`; malware rows are exact
//! versions; the `destructive_command_guard` fail-open safety hook is recognised.
//!
//! Each end-to-end test builds a temp HOME and runs the real binary, then grades the
//! report with `collect_findings`, so the file compiles against b7747e9 and fails there
//! on its assertions: every vulnerable-range match was Critical (High in a dormant npx
//! cache) whatever its advisory said, `agentwork-cli` 0.1.4 in an npx cache was a High
//! "dormant vulnerable" finding, and no hook finding named CVE-2026-77474.
//!
//! Severity scale: GitHub Advisory Database "About CVSS levels" (critical 9.0-10.0, high
//! 7.0-8.9, medium 4.0-6.9, low 0.1-3.9),
//! https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database#about-cvss-levels
#![cfg(unix)]

use rustmachineguard::analysis::{Finding, Severity, collect_findings};
use rustmachineguard::catalogs::BUILTIN_CATALOG;
use rustmachineguard::models::ScanReport;
use rustmachineguard::scanners::exposure::{ExposureCatalog, browser_catalog_ecosystem};
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

fn temp_home(tag: &str) -> PathBuf {
    let home = std::env::temp_dir().join(format!("rmg-advsev-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).unwrap();
    fs::canonicalize(&home).unwrap()
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

/// Run the scanner on `home` with only `keep` enabled; `extra` are further flags.
fn scan(home: &Path, keep: &[&str], extra: &[&str]) -> Vec<Finding> {
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
    let report: ScanReport = serde_json::from_slice(&out.stdout).expect("report json");
    collect_findings(&report)
}

fn dump(findings: &[Finding]) -> String {
    findings
        .iter()
        .map(|f| format!("[{}] {} {}", f.severity.label(), f.category, f.title))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The single Exposure finding whose title names `name` (followed by a space).
fn exposure<'a>(findings: &'a [Finding], name: &str) -> &'a Finding {
    let hits: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.category == "Exposure" && f.title.contains(&format!("{name} ")))
        .collect();
    assert_eq!(hits.len(), 1, "{name}:\n{}", dump(findings));
    hits[0]
}

/// (package, advisory_severity) fixture rows, each `<2.0.0`, plus one malware row whose
/// stray `advisory_severity` must be ignored.
const ROWS: &[(&str, Option<&str>)] = &[
    ("rmg-fixture-crit", Some("critical")),
    ("rmg-fixture-high", Some("high")),
    ("rmg-fixture-med", Some("medium")),
    ("rmg-fixture-low", Some("low")),
    ("rmg-fixture-none", None),
];

fn fixture_catalog(home: &Path) -> PathBuf {
    let mut rows: Vec<serde_json::Value> = ROWS
        .iter()
        .map(|(n, sev)| {
            let mut r = serde_json::json!({
                "ecosystem": "npm",
                "name": n,
                "version_range": "<2.0.0",
                "advisory": format!("GHSA-xxxx-yyyy-zzzz: fixture for {n}. Fixed: 2.0.0."),
            });
            if let Some(s) = sev {
                r["advisory_severity"] = (*s).into();
            }
            r
        })
        .collect();
    rows.push(serde_json::json!({
        "ecosystem": "npm",
        "name": "rmg-fixture-malware",
        "version": "1.0.0",
        "advisory": "MAL-2026-0: fixture malicious release.",
        "advisory_severity": "low",
    }));
    let path = home.join("catalog.json");
    write(&path, &serde_json::to_string(&rows).unwrap());
    path
}

fn install(node_modules: &Path, names: &[&str], version: &str) {
    for n in names {
        write(
            &node_modules.join(n).join("package.json"),
            &format!(r#"{{"name":"{n}","version":"{version}"}}"#),
        );
    }
}

fn all_names() -> Vec<&'static str> {
    ROWS.iter().map(|(n, _)| *n).chain(["rmg-fixture-malware"]).collect()
}

/// An active install (a registered project's node_modules): each vulnerable range is
/// graded at its advisory severity, a row without one stays Critical, and the malware row
/// stays Critical "Known-bad" despite its `advisory_severity`. Fails on b7747e9: every
/// range was Critical and no title stated the severity.
#[test]
fn active_vulnerable_range_is_graded_by_advisory_severity() {
    let home = temp_home("active");
    let cat = fixture_catalog(&home);
    let proj = home.join("proj");
    install(&proj.join("node_modules"), &all_names(), "1.0.0");
    write(
        &home.join(".claude.json"),
        &format!(r#"{{"projects":{{"{}":{{}}}}}}"#, proj.display()),
    );
    let findings = scan(
        &home,
        &["npmpkgs"],
        &["--no-builtin-catalog", "--threat-catalog", cat.to_str().unwrap()],
    );
    let expect = [
        ("rmg-fixture-crit", Severity::Critical, Some("critical")),
        ("rmg-fixture-high", Severity::High, Some("high")),
        ("rmg-fixture-med", Severity::Medium, Some("medium")),
        ("rmg-fixture-low", Severity::Low, Some("low")),
        ("rmg-fixture-none", Severity::Critical, None),
    ];
    for (name, sev, word) in expect {
        let f = exposure(&findings, name);
        assert_eq!(f.severity, sev, "{name}: {}", f.title);
        let lead = match word {
            Some(w) => format!("Vulnerable npm package version (advisory severity: {w}): {name} 1.0.0"),
            None => format!("Vulnerable npm package version: {name} 1.0.0"),
        };
        assert!(f.title.starts_with(&lead), "{name}: {}", f.title);
    }
    let mal = exposure(&findings, "rmg-fixture-malware");
    assert_eq!(mal.severity, Severity::Critical, "{}", mal.title);
    assert!(
        mal.title
            .starts_with("Known-bad npm package: rmg-fixture-malware 1.0.0"),
        "{}",
        mal.title
    );
    assert!(!mal.title.contains("advisory severity"), "{}", mal.title);
    let _ = fs::remove_dir_all(&home);
}

/// A dormant npx cache (nothing launches it) is one step below the advisory grade, never
/// below Low: critical -> High, high -> Medium, medium -> Low, low -> Low, no field ->
/// High (today's grade). The malware row is Critical in a cache too. Fails on b7747e9:
/// every dormant range was High.
#[test]
fn dormant_npx_cache_is_one_step_below_the_advisory_grade() {
    let home = temp_home("dormant");
    let cat = fixture_catalog(&home);
    let root = home.join(".npm/_npx/0123456789abcdef");
    write(
        &root.join("package.json"),
        r#"{"_npx":{"packages":["rmg-fixture-parent"]},"dependencies":{"rmg-fixture-parent":"^1.0.0"}}"#,
    );
    install(&root.join("node_modules"), &all_names(), "1.0.0");
    let findings = scan(
        &home,
        &["npmpkgs"],
        &["--no-builtin-catalog", "--threat-catalog", cat.to_str().unwrap()],
    );
    let expect = [
        ("rmg-fixture-crit", Severity::High),
        ("rmg-fixture-high", Severity::Medium),
        ("rmg-fixture-med", Severity::Low),
        ("rmg-fixture-low", Severity::Low),
        ("rmg-fixture-none", Severity::High),
    ];
    for (name, sev) in expect {
        let f = exposure(&findings, name);
        assert_eq!(f.severity, sev, "{name}: {}", f.title);
        assert!(f.title.contains("in npx cache (dormant unless re-run)"), "{}", f.title);
    }
    assert!(
        exposure(&findings, "rmg-fixture-high")
            .title
            .starts_with("Vulnerable npm package version (advisory severity: high) in npx cache"),
        "{}",
        dump(&findings)
    );
    let mal = exposure(&findings, "rmg-fixture-malware");
    assert_eq!(mal.severity, Severity::Critical, "{}", mal.title);
    let _ = fs::remove_dir_all(&home);
}

/// The built-in `claude-agent-sdk <0.2.121` row (CVE-2026-96620) carries
/// `advisory_severity: critical`, so an installed 0.2.87 stays Critical and says so.
/// Fails on b7747e9 (no severity in the title).
#[test]
fn builtin_critical_row_states_its_severity() {
    let cat = ExposureCatalog::load_from_str(BUILTIN_CATALOG).unwrap();
    let server = rustmachineguard::models::McpServerDetail {
        name: "s".into(),
        transport: "stdio".into(),
        command: Some("uvx".into()),
        package_ecosystem: Some("pypi".into()),
        package_name: Some("claude-agent-sdk".into()),
        package_version: Some("0.2.87".into()),
        ..Default::default()
    };
    let hits = cat.check_mcp_server(&server, "/t/.mcp.json");
    assert_eq!(hits.len(), 1, "{hits:#?}");
    // A minimal report (no npx cache in play), the shape src/compliance.rs tests use.
    let report: ScanReport = serde_json::from_str(
        r#"{"agent_version":"t","scan_timestamp":0,"scan_timestamp_iso":"t",
            "device":{"hostname":"h","os_name":"o","os_version":"v","platform":"p",
            "kernel_version":"k","user_identity":"u","home_dir":"/h"},
            "ai_agents_and_tools":[],"ai_frameworks":[],"ide_installations":[],
            "ide_extensions":[],"mcp_configs":[],"node_package_managers":[],
            "shell_configs":[],"ssh_keys":[],"cloud_credentials":[],"container_tools":[],
            "notebook_servers":[],"browser_extensions":[],"package_config_audits":[],
            "rules_files":[],"agent_skills":[],
            "summary":{"ai_agents_and_tools_count":0,"ai_frameworks_count":0,
            "ide_installations_count":0,"ide_extensions_count":0,"mcp_configs_count":0,
            "mcp_servers_count":0,"node_package_managers_count":0,"shell_configs_count":0,
            "ssh_keys_count":0,"cloud_credentials_count":0,"container_tools_count":0,
            "notebook_servers_count":0,"browser_extensions_count":0,
            "package_config_audits_count":0,"rules_files_count":0,"agent_skills_count":0,
            "agent_settings_count":0,"agent_hooks_count":0,"ai_credentials_count":0,
            "env_files_count":0,"rules_file_findings_count":0,"exposure_findings_count":0,
            "transcript_stores_count":0,"marketplaces_count":0,
            "vscode_autorun_tasks_count":0,"git_autorun_configs_count":0,"python_packages_count":0}}"#,
    )
    .unwrap();
    let f = rustmachineguard::analysis::exposure_finding(&report, &hits[0]);
    assert_eq!(f.severity, Severity::Critical);
    assert!(
        f.title
            .starts_with("Vulnerable pypi package version (advisory severity: critical): claude-agent-sdk 0.2.87"),
        "{}",
        f.title
    );
}

// ─── A2: malware rows are exact versions ─────────────────────────────────────

/// `agentwork-cli` 0.1.4 (a Mini Shai-Hulud worm node) in an npx cache nothing launches is
/// Critical "Known-bad", never a High "dormant vulnerable" finding. Fails on b7747e9,
/// whose `>=0.1.4, <=0.1.5` range row graded it High dormant.
#[test]
fn agentwork_cli_in_npx_cache_is_critical_malware() {
    let home = temp_home("agentwork");
    let root = home.join(".npm/_npx/fedcba9876543210");
    write(
        &root.join("package.json"),
        r#"{"_npx":{"packages":["agentwork-cli"]},"dependencies":{"agentwork-cli":"^0.1.0"}}"#,
    );
    install(&root.join("node_modules"), &["agentwork-cli"], "0.1.4");
    let findings = scan(&home, &["npmpkgs"], &[]);
    let f = exposure(&findings, "agentwork-cli");
    assert_eq!(f.severity, Severity::Critical, "{}", f.title);
    assert!(
        f.title.starts_with("Known-bad npm package: agentwork-cli 0.1.4"),
        "{}",
        f.title
    );
    assert!(!f.title.contains("dormant"), "{}", f.title);
    let _ = fs::remove_dir_all(&home);
}

/// Every compromised-release row that was a range is now one exact row per malicious
/// version: matched as malware (no `matched_range`), and the clean neighbours still do
/// not match. Fails on b7747e9 (each matched through its `version_range`).
#[test]
fn compromised_release_rows_match_as_malware() {
    let cat = ExposureCatalog::load_from_str(BUILTIN_CATALOG).unwrap();
    let ext = |eco: &str, name: &str, v: &str| cat.check_extension(eco, name, v, "/t");
    let chrome = browser_catalog_ecosystem("Chrome");
    let cyber = "pajkjnmeojmbapicmbpliphjmcekeaac";
    let trivy = "aquasecurityofficial.trivy-vulnerability-scanner";
    for (eco, name, bad, clean) in [
        (chrome, cyber, &["24.10.4"][..], &["24.10.3", "24.10.5"][..]),
        ("vscode", trivy, &["1.8.12", "1.8.13"][..], &["1.8.11", "1.8.14"][..]),
    ] {
        for v in bad {
            let hits = ext(eco, name, v);
            assert_eq!(hits.len(), 1, "{name} {v}: {hits:#?}");
            assert!(hits[0].matched_range.is_none(), "{name} {v} must match as malware");
        }
        for v in clean {
            assert!(ext(eco, name, v).is_empty(), "{name} {v} is clean");
        }
    }
}

// ─── A3: the fail-open safety hook ───────────────────────────────────────────

const FAIL_OPEN: &str = "CVE-2026-77474";

fn fail_open_findings(findings: &[Finding]) -> Vec<&Finding> {
    findings
        .iter()
        .filter(|f| f.category == "Hook" && f.title.contains(FAIL_OPEN))
        .collect()
}

fn hooks_json(commands: &[&str]) -> String {
    let hooks: Vec<serde_json::Value> = commands
        .iter()
        .map(|c| serde_json::json!({"type": "command", "command": c}))
        .collect();
    serde_json::json!({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": hooks}]}}).to_string()
}

/// User settings hooks: `dcg` from a Homebrew Cellar 0.6.5 path is Medium (affected
/// version stated), at 0.6.6 nothing, a bare `~/.local/bin/dcg` Low (version unknown), a
/// script named `destructive_command_guard.py` Low, and an unrelated hook nothing.
/// Fails on b7747e9: no hook finding names CVE-2026-77474.
#[test]
fn destructive_command_guard_hook_is_recognised() {
    let home = temp_home("dcg");
    let affected = "/opt/homebrew/Cellar/dcg/0.6.5/bin/dcg";
    let fixed = "/opt/homebrew/Cellar/dcg/0.6.6/bin/dcg";
    let bare = format!("{}/.local/bin/dcg", home.display());
    let script = "python3 ~/.claude/hooks/destructive_command_guard.py";
    write(
        &home.join(".claude/settings.json"),
        &hooks_json(&[affected, fixed, &bare, script, "dcgx --check", "echo dcg"]),
    );
    let findings = scan(&home, &["settings"], &[]);
    let hits = fail_open_findings(&findings);
    let d = dump(&findings);
    assert_eq!(hits.len(), 3, "{d}");
    let by = |cmd: &str| {
        hits.iter()
            .find(|f| f.evidence.as_deref().is_some_and(|e| e.starts_with(&format!("{cmd};"))))
            .unwrap_or_else(|| panic!("no finding for {cmd}:\n{d}"))
    };
    let a = by(affected);
    assert_eq!(a.severity, Severity::Medium, "{}", a.title);
    assert!(
        a.title.starts_with(
            "Safety hook with a known fail-open bug (CVE-2026-77474): a hanging guard lets the command through"
        ),
        "{}",
        a.title
    );
    assert!(
        a.title.contains("0.6.5") && a.title.contains("update to 0.6.6"),
        "{}",
        a.title
    );
    assert!(a.evidence.as_deref().unwrap().contains("GHSA-4cfr-w3v5-w5j5"));
    for cmd in [bare.as_str(), script] {
        let f = by(cmd);
        assert_eq!(f.severity, Severity::Low, "{}", f.title);
        assert!(f.title.contains("version unknown"), "{}", f.title);
    }
    let _ = fs::remove_dir_all(&home);
}

/// An enabled third-party plugin named `destructive-command-guard` at 0.6.5 (its cache
/// install path) whose hook runs `${CLAUDE_PLUGIN_ROOT}/bin/dcg` is Medium; the same
/// plugin disabled runs nothing and has no finding. Fails on b7747e9 (no finding).
#[test]
fn destructive_command_guard_plugin_version_comes_from_the_install_path() {
    for enabled in [true, false] {
        let home = temp_home(if enabled { "dcg-plugin-on" } else { "dcg-plugin-off" });
        let ip = home.join(".claude/plugins/cache/mkt/destructive-command-guard/0.6.5");
        write(
            &ip.join(".claude-plugin/plugin.json"),
            r#"{"name":"destructive-command-guard","version":"0.6.5"}"#,
        );
        write(
            &ip.join("hooks/hooks.json"),
            &hooks_json(&["${CLAUDE_PLUGIN_ROOT}/bin/dcg"]),
        );
        write(
            &home.join(".claude/plugins/installed_plugins.json"),
            &format!(
                "{{\"version\":2,\"plugins\":{{\"destructive-command-guard@mkt\":[{{\"scope\":\"user\",\"installPath\":\"{}\",\"version\":\"0.6.5\"}}]}}}}",
                ip.display()
            ),
        );
        write(
            &home.join(".claude/settings.json"),
            &format!(r#"{{"enabledPlugins":{{"destructive-command-guard@mkt":{enabled}}}}}"#),
        );
        let findings = scan(&home, &["settings", "skills"], &[]);
        let hits = fail_open_findings(&findings);
        if enabled {
            assert_eq!(hits.len(), 1, "{}", dump(&findings));
            assert_eq!(hits[0].severity, Severity::Medium, "{}", hits[0].title);
            assert!(
                hits[0].title.contains("destructive_command_guard 0.6.5"),
                "{}",
                hits[0].title
            );
        } else {
            assert!(hits.is_empty(), "{}", dump(&findings));
        }
        let _ = fs::remove_dir_all(&home);
    }
}

/// The lexical recogniser, path by path: where a version is read from, and what is not
/// the guard. Fails to compile on b7747e9 (no `fail_open_guard`).
#[test]
fn fail_open_guard_reads_the_version_from_the_path_only() {
    use rustmachineguard::models::AgentHook;
    use rustmachineguard::scanners::hook_sources::{FailOpenGuard, fail_open_guard};
    let hook = |cmd: &str| AgentHook {
        event: "PreToolUse".into(),
        command: cmd.into(),
        kind: "command".into(),
        ..Default::default()
    };
    let affected = |v: &str| Some(FailOpenGuard::Affected(v.into()));
    let cases: &[(&str, &str, bool, Option<FailOpenGuard>)] = &[
        (
            "/nix/store/abc123-destructive_command_guard-0.6.5/bin/dcg",
            "/s",
            false,
            affected("0.6.5"),
        ),
        (
            "/nix/store/abc123-destructive_command_guard-0.15.3/bin/dcg",
            "/s",
            false,
            None,
        ),
        ("/opt/tools/dcg/v0.5.0/dcg", "/s", false, affected("0.5.0")),
        ("DCG_LOG=debug dcg", "/s", false, Some(FailOpenGuard::Unknown)),
        ("dcg.exe", "/s", false, Some(FailOpenGuard::Unknown)),
        ("/opt/abcdcg-0.1.0/bin/abcdcg", "/s", false, None),
        ("echo destructive_command_guard", "/s", false, None),
        // A plugin's hook: the install path names the plugin and its version.
        (
            "node ${CLAUDE_PLUGIN_ROOT}/run.js",
            "/h/.claude/plugins/cache/m/destructive-command-guard/0.6.4/hooks/hooks.json",
            true,
            affected("0.6.4"),
        ),
        // The same path outside a plugin scope is not evidence.
        (
            "node run.js",
            "/h/.claude/plugins/cache/m/destructive-command-guard/0.6.4/hooks/hooks.json",
            false,
            None,
        ),
    ];
    for (cmd, loc, plugin, want) in cases {
        assert_eq!(&fail_open_guard(&hook(cmd), loc, *plugin), want, "{cmd} @ {loc}");
    }
    let mut http = hook("dcg");
    http.kind = "http".into();
    assert_eq!(
        fail_open_guard(&http, "/s", false),
        None,
        "only command hooks run a program"
    );
}
