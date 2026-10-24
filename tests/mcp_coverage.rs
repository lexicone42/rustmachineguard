//! End-to-end tests for MCP coverage beyond the user's own config files: Claude Code
//! plugin servers (`.mcp.json` and `plugin.json` `mcpServers`), claude.ai connectors
//! (`claudeAiMcpEverConnected`), servers observed in Claude Code's MCP log directory
//! names, the toxic-flow surface built from what is actually connected, and the grade of
//! a vulnerable MCP SDK version found only in an npx cache.
//!
//! Each test builds a temp HOME and runs the real binary. Assertions read the report as
//! plain JSON and through `collect_findings`, so the file compiles against older
//! releases and each test fails there on its assertions.
#![cfg(unix)]

use rustmachineguard::analysis::{Finding, Severity, collect_findings};
use rustmachineguard::models::ScanReport;
use serde_json::Value;
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
    let home = std::env::temp_dir().join(format!("rmg-mcpcov-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).unwrap();
    fs::canonicalize(&home).unwrap()
}

fn managed_dir(sysroot: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        sysroot.join("Library/Application Support/ClaudeCode")
    } else {
        sysroot.join("etc/claude-code")
    }
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn scan_format(home: &Path, keep: &[&str], format: &str) -> String {
    let skip: Vec<&str> = ALL_LABELS.iter().copied().filter(|l| !keep.contains(l)).collect();
    let out = Command::new(env!("CARGO_BIN_EXE_rmguard"))
        .args(["--format", format, "--skip", &skip.join(",")])
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
        .env("NO_COLOR", "1")
        .current_dir(home)
        .output()
        .expect("run rmguard");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// JSON text, the report as a Value, and the findings.
fn scan(home: &Path, keep: &[&str]) -> (String, Value, Vec<Finding>) {
    let text = scan_format(home, keep, "json");
    let value: Value = serde_json::from_str(&text).expect("report json");
    let report: ScanReport = serde_json::from_str(&text).expect("report json");
    let findings = collect_findings(&report);
    (text, value, findings)
}

/// Every server row of the report whose config row has `config_source == source`.
fn servers<'a>(v: &'a Value, source: &str) -> Vec<&'a Value> {
    v["mcp_configs"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| c["config_source"] == source)
        .flat_map(|c| c["servers"].as_array().into_iter().flatten())
        .collect()
}

fn named<'a>(rows: &[&'a Value], name: &str) -> Option<&'a Value> {
    rows.iter().copied().find(|s| s["name"] == name)
}

/// One installed plugin version: an `installed_plugins.json` entry (merged into the
/// file) and its cache directory.
fn install_plugin(home: &Path, plugin: &str, market: &str, entries: &mut Vec<String>) -> PathBuf {
    let ip = home
        .join(".claude/plugins/cache")
        .join(market)
        .join(plugin)
        .join("1.0.0");
    fs::create_dir_all(&ip).unwrap();
    entries.push(format!(
        "\"{plugin}@{market}\":[{{\"scope\":\"user\",\"installPath\":\"{}\",\"version\":\"1.0.0\"}}]",
        ip.display()
    ));
    ip
}

fn write_installed(home: &Path, entries: &[String]) {
    write(
        &home.join(".claude/plugins/installed_plugins.json"),
        &format!("{{\"version\":2,\"plugins\":{{{}}}}}", entries.join(",")),
    );
}

/// A plugin fixture: an enabled unpinned npx server (bare-map `.mcp.json`, the shape
/// Anthropic's playwright plugin ships), an http server with a header that references an
/// env var with a literal default (wrapped `.mcp.json`), a disabled plugin's git-HEAD
/// uvx server, and a plugin whose manifest declares a `./file.json`, an inline map, a
/// `../` escape and a symlink that leaves the plugin, an installed version whose
/// directory is a symlink out of the cache, and a marketplace clone of a plugin that is
/// not installed.
fn plugin_fixture(home: &Path) {
    let mut entries = Vec::new();
    let pw = install_plugin(home, "pw", "mkt", &mut entries);
    write(
        &pw.join(".mcp.json"),
        r#"{"playwright":{"command":"npx","args":["@playwright/mcp@latest"]}}"#,
    );
    let ctx = install_plugin(home, "ctx", "mkt", &mut entries);
    write(
        &ctx.join(".mcp.json"),
        r#"{"mcpServers":{"context7":{"type":"http","url":"https://mcp.example.com/mcp?key=QUERYCANARY","headers":{"Authorization":"Bearer ${CTX_KEY:-HDRDEFAULTCANARY}","X-Plain":"PLAINCANARY"}}}}"#,
    );
    let ser = install_plugin(home, "ser", "mkt", &mut entries);
    write(
        &ser.join(".mcp.json"),
        r#"{"serena":{"command":"uvx","args":["--from","git+https://github.com/example/serena","serena","start-mcp-server"],"env":{"SERENA_TOKEN":"ENVCANARYVALUE"}}}"#,
    );
    let inl = install_plugin(home, "inl", "mkt", &mut entries);
    write(
        &inl.join(".claude-plugin/plugin.json"),
        r#"{"name":"inl","mcpServers":["./mcp/extra.json",{"inline-srv":{"command":"npx","args":["-y","pinned-mcp@1.2.3"]}},"../escape.json","./mcp/link.json"]}"#,
    );
    write(
        &inl.join("mcp/extra.json"),
        r#"{"mcpServers":{"extra-srv":{"command":"node","args":["${CLAUDE_PLUGIN_ROOT}/server.js"]}}}"#,
    );
    write(
        &inl.join("../escape.json"),
        r#"{"mcpServers":{"escape-srv":{"command":"npx","args":["evil"]}}}"#,
    );
    write(
        &home.join("outside.json"),
        r#"{"mcpServers":{"link-srv":{"command":"npx","args":["evil"]}}}"#,
    );
    std::os::unix::fs::symlink(home.join("outside.json"), inl.join("mcp/link.json")).unwrap();
    // An installed version whose directory is a symlink out of the plugin cache.
    let away = install_plugin(home, "away", "mkt", &mut entries);
    fs::remove_dir_all(&away).unwrap();
    write(
        &home.join("elsewhere/.mcp.json"),
        r#"{"away-srv":{"command":"npx","args":["away-mcp"]}}"#,
    );
    std::os::unix::fs::symlink(home.join("elsewhere"), &away).unwrap();
    write_installed(home, &entries);
    write(
        &home.join(".claude/plugins/marketplaces/mkt/plugins/clone/.mcp.json"),
        r#"{"clone-srv":{"command":"npx","args":["clone-mcp"]}}"#,
    );
    write(
        &home.join(".claude/settings.json"),
        r#"{"enabledPlugins":{"pw@mkt":true,"ctx@mkt":true,"ser@mkt":false,"inl@mkt":true}}"#,
    );
}

/// Y1: plugin servers are inventoried with their plugin and state; an enabled plugin's
/// unpinned launch is a Medium "plugin MCP server runs an unpinned package"; a disabled
/// plugin's is inventory only; manifest paths that escape the plugin are not read; the
/// marketplace clone is not inventoried; header and env values appear by shape only.
/// Fails on f91d034, which read no plugin `.mcp.json` at all.
#[test]
fn plugin_mcp_servers_are_inventoried_and_graded() {
    let home = temp_home("plugins");
    plugin_fixture(&home);
    let (text, v, findings) = scan(&home, &["mcp"]);

    let rows = servers(&v, "plugin");
    let mut names: Vec<&str> = rows.iter().filter_map(|s| s["name"].as_str()).collect();
    names.sort();
    assert_eq!(
        names,
        ["context7", "extra-srv", "inline-srv", "playwright", "serena"],
        "{text}"
    );
    let pw = named(&rows, "playwright").unwrap();
    assert_eq!(pw["plugin"], "pw@mkt");
    assert_eq!(pw["enabled"], true);
    assert_eq!(pw["unpinned"], "@latest");
    let ser = named(&rows, "serena").unwrap();
    assert_eq!(ser["enabled"], false);
    assert_eq!(ser["unpinned"], "git HEAD");
    assert!(named(&rows, "inline-srv").unwrap()["unpinned"].is_null());
    assert!(named(&rows, "extra-srv").unwrap()["unpinned"].is_null());
    let ctx = named(&rows, "context7").unwrap();
    assert_eq!(ctx["url"], "https://mcp.example.com");
    let headers: Vec<&str> = ctx["headers"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|h| h.as_str())
        .collect();
    assert_eq!(
        headers,
        ["Authorization: Bearer ${CTX_KEY:-<redacted>}", "X-Plain: <redacted>"]
    );
    assert_eq!(v["summary"]["mcp_plugin_servers_count"], 5);
    assert_eq!(v["summary"]["mcp_servers_count"], 5);

    let unpinned: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.title.starts_with("plugin MCP server runs an unpinned package"))
        .collect();
    assert_eq!(unpinned.len(), 1, "{findings:#?}");
    assert_eq!(unpinned[0].severity, Severity::Medium);
    assert_eq!(unpinned[0].category, "MCP command");
    assert!(unpinned[0].title.contains("'playwright'") && unpinned[0].title.contains("pw@mkt"));
    // The disabled plugin's server is inventory only.
    assert!(!findings.iter().any(|f| f.title.contains("serena")), "{findings:#?}");

    let terminal = scan_format(&home, &["mcp"], "terminal");
    let html = scan_format(&home, &["mcp"], "html");
    for out in [&text, &terminal, &html] {
        for canary in [
            "HDRDEFAULTCANARY",
            "PLAINCANARY",
            "ENVCANARYVALUE",
            "QUERYCANARY",
            "escape-srv",
            "link-srv",
            "clone-srv",
            "away-srv",
        ] {
            assert!(!out.contains(canary), "{canary} leaked");
        }
    }
    let _ = fs::remove_dir_all(&home);
}

/// A managed `enabledPlugins` force-enable makes a user-disabled plugin's server active,
/// so its git-HEAD launch is graded. Fails on f91d034 (no plugin servers).
#[test]
fn managed_force_enable_activates_a_disabled_plugin_server() {
    let home = temp_home("forced");
    plugin_fixture(&home);
    write(
        &managed_dir(&home.join("sysroot")).join("managed-settings.json"),
        r#"{"enabledPlugins":{"ser@mkt":true}}"#,
    );
    let (_, v, findings) = scan(&home, &["mcp", "settings"]);
    let rows = servers(&v, "plugin");
    assert_eq!(named(&rows, "serena").unwrap()["enabled"], true);
    assert!(
        findings
            .iter()
            .any(|f| f.title.starts_with("plugin MCP server runs an unpinned package") && f.title.contains("git HEAD")),
        "{findings:#?}"
    );
    let _ = fs::remove_dir_all(&home);
}

/// Y2 + Y3: connectors from `claudeAiMcpEverConnected` are rows marked ever connected
/// (never "enabled"); log directory names are observed servers, matched to the plugin
/// and connector rows; a logged server no config defines is one Low advisory; no log
/// file is read. Fails on f91d034.
#[test]
fn connectors_and_observed_servers() {
    let home = temp_home("connectors");
    let mut entries = Vec::new();
    let pw = install_plugin(&home, "pw", "mkt", &mut entries);
    write(
        &pw.join(".mcp.json"),
        r#"{"playwright":{"command":"npx","args":["@playwright/mcp@1.0.0"]}}"#,
    );
    write_installed(&home, &entries);
    write(
        &home.join(".claude.json"),
        r#"{"claudeAiMcpEverConnected":["claude.ai Gmail","claude.ai Google Drive"]}"#,
    );
    let logs = home.join(".cache/claude-cli-nodejs");
    for (proj, server) in [
        ("-p-a", "claude-ai-Gmail"),
        ("-p-a", "plugin-pw-playwright"),
        ("-p-a", "mystery"),
        ("-p-b", "mystery"),
    ] {
        write(
            &logs
                .join(proj)
                .join(format!("mcp-logs-{server}"))
                .join("2026-10-01.jsonl"),
            "LOGCONTENTCANARY",
        );
    }
    let (text, v, findings) = scan(&home, &["mcp"]);

    let conns = servers(&v, "claude.ai connector");
    assert_eq!(conns.len(), 2, "{text}");
    let gmail = named(&conns, "claude.ai Gmail").unwrap();
    assert_eq!(gmail["transport"], "remote (vendor-hosted)");
    assert_eq!(gmail["ever_connected"], true);
    assert!(gmail["enabled"].is_null(), "enabled is unknown for a connector");
    assert_eq!(v["summary"]["mcp_connectors_count"], 2);
    assert_eq!(v["summary"]["mcp_servers_count"], 3);

    let observed = v["mcp_observed_servers"].as_array().expect("observed servers");
    let get = |n: &str| {
        observed
            .iter()
            .find(|o| o["name"] == n)
            .unwrap_or_else(|| panic!("{n}: {text}"))
    };
    assert_eq!(get("claude-ai-Gmail")["configured"], true);
    assert_eq!(get("plugin-pw-playwright")["configured"], true);
    assert_eq!(get("mystery")["configured"], false);
    assert_eq!(get("mystery")["projects"], 2);

    let unknown: Vec<&Finding> = findings.iter().filter(|f| f.category == "MCP inventory").collect();
    assert_eq!(unknown.len(), 1, "{findings:#?}");
    assert_eq!(unknown[0].severity, Severity::Low);
    assert!(unknown[0].title.contains("'mystery'") && unknown[0].title.contains("not in any known config"));
    // Connectors are inventory only: no finding names them.
    assert!(!findings.iter().any(|f| f.title.contains("Gmail")), "{findings:#?}");

    let terminal = scan_format(&home, &["mcp"], "terminal");
    assert!(terminal.contains("servers that have run per logs: 3"), "{terminal}");
    assert!(terminal.contains("ever connected"));
    for out in [&text, &terminal] {
        assert!(!out.contains("LOGCONTENTCANARY"));
    }
    let _ = fs::remove_dir_all(&home);
}

/// Y4 true path: an enabled playwright plugin server (network sink, untrusted content)
/// and a Gmail connector (private data) are a toxic flow, and the evidence names both.
/// Fails on f91d034, which took capabilities only from probes and skills.
#[test]
fn toxic_flow_from_plugin_server_and_connector() {
    let home = temp_home("tf-true");
    let mut entries = Vec::new();
    let pw = install_plugin(&home, "playwright", "mkt", &mut entries);
    write(
        &pw.join(".mcp.json"),
        r#"{"playwright":{"command":"npx","args":["@playwright/mcp@latest"]}}"#,
    );
    write_installed(&home, &entries);
    write(
        &home.join(".claude.json"),
        r#"{"claudeAiMcpEverConnected":["claude.ai Gmail"]}"#,
    );
    let (_, _, findings) = scan(&home, &["mcp"]);
    let tf: Vec<&Finding> = findings.iter().filter(|f| f.category == "Toxic Flow").collect();
    assert_eq!(tf.len(), 1, "{findings:#?}");
    assert_eq!(tf[0].severity, Severity::High);
    let ev = tf[0].evidence.as_deref().unwrap_or("");
    assert!(ev.contains("claude.ai Gmail") && ev.contains("playwright"), "{ev}");
    assert!(tf[0].title.contains("private_data") && tf[0].title.contains("network"));
    let _ = fs::remove_dir_all(&home);
}

/// Y4 false path: a disabled plugin's server and a marketplace clone of a plugin that is
/// not installed supply nothing, so a user skill that reads files and a clone skill that
/// fetches over the network are not a toxic flow. Fails on f91d034, which unioned the
/// clone's capabilities into the surface.
#[test]
fn uninstalled_clone_and_disabled_plugin_are_not_a_toxic_flow() {
    let home = temp_home("tf-false");
    let mut entries = Vec::new();
    let pw = install_plugin(&home, "playwright", "mkt", &mut entries);
    write(
        &pw.join(".mcp.json"),
        r#"{"playwright":{"command":"npx","args":["@playwright/mcp@latest"]}}"#,
    );
    write_installed(&home, &entries);
    write(
        &home.join(".claude/settings.json"),
        r#"{"enabledPlugins":{"playwright@mkt":false}}"#,
    );
    write(
        &home.join(".claude/skills/reader/SKILL.md"),
        "---\nname: reader\ndescription: reads notes\n---\nUse read_file on the notes.\n",
    );
    write(
        &home.join(".claude/plugins/marketplaces/mkt/plugins/poster/skills/post/SKILL.md"),
        "---\nname: post\ndescription: posts\n---\nRun curl https://example.com/upload with the data.\n",
    );
    let (text, v, findings) = scan(&home, &["mcp", "skills"]);
    // The clone stays in the inventory.
    assert!(
        v["agent_skills"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["name"] == "post"),
        "{text}"
    );
    assert!(!findings.iter().any(|f| f.category == "Toxic Flow"), "{findings:#?}");
    let _ = fs::remove_dir_all(&home);
}

/// An npx cache holding a vulnerable MCP SDK version.
fn npx_cache(home: &Path) {
    let root = home.join(".npm/_npx/abc123def4567890");
    write(
        &root.join("package.json"),
        r#"{"_npx":{"packages":["@upstash/context7-mcp"]},"dependencies":{"@upstash/context7-mcp":"^1.0.0"}}"#,
    );
    write(
        &root.join("node_modules/@modelcontextprotocol/server/package.json"),
        r#"{"name":"@modelcontextprotocol/server","version":"2.0.0"}"#,
    );
}

/// Y5: a vulnerable version range matched only in an npx cache nothing launches is High,
/// titled as dormant, names the package the cache was fetched for, and keeps the
/// advisory IDs. Fails on f91d034 (Critical "Known-bad npm package").
#[test]
fn vulnerable_sdk_in_npx_cache_is_high_and_dormant() {
    let home = temp_home("npx");
    npx_cache(&home);
    let (_, _, findings) = scan(&home, &["npmpkgs"]);
    let hit: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.category == "Exposure" && f.title.contains("@modelcontextprotocol/server"))
        .collect();
    assert_eq!(hit.len(), 1, "{findings:#?}");
    assert_eq!(hit[0].severity, Severity::High);
    assert!(
        hit[0]
            .title
            .starts_with("Vulnerable MCP SDK version in npx cache (dormant unless re-run)"),
        "{}",
        hit[0].title
    );
    assert!(hit[0].title.contains("@upstash/context7-mcp"), "{}", hit[0].title);
    let ev = hit[0].evidence.as_deref().unwrap_or("");
    assert!(
        ev.contains(">=2.0.0, <2.3.0") && ev.contains("GHSA-jm63-cq47-j5jp"),
        "{ev}"
    );
    let _ = fs::remove_dir_all(&home);
}

/// The Exposure findings for `@modelcontextprotocol/server`.
fn sdk_hits(findings: &[Finding]) -> Vec<&Finding> {
    findings
        .iter()
        .filter(|f| f.category == "Exposure" && f.title.contains("@modelcontextprotocol/server"))
        .collect()
}

fn assert_active_critical(hits: &[&Finding]) {
    assert_eq!(hits.len(), 1, "{hits:#?}");
    let f = hits[0];
    assert_eq!(f.severity, Severity::Critical, "{}", f.title);
    assert!(f.title.starts_with("Vulnerable npm package version"), "{}", f.title);
    assert!(!f.title.contains("dormant"));
}

/// Y5: the same version is Critical in an active install, a registered project's
/// node_modules. Fails on f91d034, whose title called a vulnerable version "Known-bad".
#[test]
fn vulnerable_sdk_in_a_project_install_stays_critical() {
    let home = temp_home("active-proj");
    let proj = home.join("proj");
    write(
        &proj.join("node_modules/@modelcontextprotocol/server/package.json"),
        r#"{"name":"@modelcontextprotocol/server","version":"2.0.0"}"#,
    );
    write(
        &home.join(".claude.json"),
        &format!(r#"{{"projects":{{"{}":{{}}}}}}"#, proj.display()),
    );
    let (_, _, findings) = scan(&home, &["npmpkgs"]);
    assert_active_critical(&sdk_hits(&findings));
    let _ = fs::remove_dir_all(&home);
}

/// Y5: an npx cache that a configured MCP server launches (`npx -y
/// @upstash/context7-mcp`, the package the cache was fetched for) is active: Critical.
/// Fails on f91d034 (title "Known-bad").
#[test]
fn vulnerable_sdk_in_an_npx_cache_a_server_launches_stays_critical() {
    let home = temp_home("active-npx");
    npx_cache(&home);
    write(
        &home.join(".claude.json"),
        r#"{"mcpServers":{"context7":{"command":"npx","args":["-y","@upstash/context7-mcp"]}}}"#,
    );
    let (_, _, findings) = scan(&home, &["mcp", "npmpkgs"]);
    assert_active_critical(&sdk_hits(&findings));
    let _ = fs::remove_dir_all(&home);
}
