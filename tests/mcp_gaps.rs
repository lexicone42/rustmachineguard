//! MCP configuration files and extension directories 12c1f7f did not read:
//!
//! - M1: a Cursor project's `.cursor/mcp.json` (cursor.com/docs/context/mcp); GitHub
//!   Copilot CLI's `~/.copilot/mcp-config.json` and a repository's `.github/mcp.json`
//!   (docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers);
//!   VS Code's `.vscode/mcp.json` and user-profile `mcp.json` with their `inputs`
//!   (code.visualstudio.com/docs/agents/reference/mcp-configuration); Gemini CLI's
//!   `mcpServers` in `~/.gemini/settings.json` and `.gemini/settings.json`
//!   (github.com/google-gemini/gemini-cli `docs/tools/mcp-server.md`); and `read_by` on
//!   files more than one agent loads.
//! - M2: the extension directories of a VS Code-family remote server (`~/.vscode-server`,
//!   `~/.cursor-server`, ...), parsed and catalog-matched like local ones.
//! - M3: the `ai` scanner's extension agents honour VS Code's root `.obsolete` file, not a
//!   per-extension `.obsolete` VS Code never writes.
//!
//! The file compiles against 12c1f7f (it reads the report as JSON and grades it with
//! `collect_findings`); with `RMGUARD_TEST_BIN` pointing at a 12c1f7f build every test
//! fails on its assertions: none of these files is read there, no row carries `read_by`
//! or `inputs`, no remote-server extension is inventoried, and the extension-agent rows
//! follow the per-extension `.obsolete` probe. Token-shaped canaries are built from parts
//! at run time and must never reach the output.
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
    let d = std::env::temp_dir().join(format!("rmg-mg-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    fs::canonicalize(&d).unwrap()
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn bin() -> String {
    std::env::var("RMGUARD_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_rmguard").to_string())
}

/// A home with one project, `<home>/proj`, registered in `~/.claude.json`.
fn home_and_project(tag: &str) -> (PathBuf, PathBuf) {
    let home = temp_home(tag);
    let proj = home.join("proj");
    fs::create_dir_all(&proj).unwrap();
    write(
        &home.join(".claude.json"),
        &format!("{{\"projects\":{{\"{}\":{{}}}}}}", proj.display()),
    );
    (home, proj)
}

/// Run rmguard on `home` with only `keep`, in `cwd`, `PATH` = an empty directory (no
/// tool is found or run); returns (raw stdout, JSON, findings).
fn scan(home: &Path, cwd: &Path, keep: &[&str]) -> (String, Value, Vec<Finding>) {
    let skip: Vec<&str> = ALL_LABELS.iter().copied().filter(|l| !keep.contains(l)).collect();
    let empty = home.join("empty-path");
    fs::create_dir_all(&empty).unwrap();
    let out = Command::new(bin())
        .args(["--skip", &skip.join(","), "--format", "json"])
        .env("HOME", home)
        .env("PATH", &empty)
        .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
        .env("NO_COLOR", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("COPILOT_HOME")
        .env_remove("RMGUARD_TRACE")
        .current_dir(cwd)
        .output()
        .expect("run rmguard");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let v: Value = serde_json::from_str(&text).expect("report json");
    let report: ScanReport = serde_json::from_str(&text).expect("report");
    let f = collect_findings(&report);
    (text, v, f)
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

fn mcp<'a>(v: &'a Value, source: &str) -> &'a Value {
    v["mcp_configs"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|c| c["config_source"] == source)
        .unwrap_or_else(|| panic!("no MCP row from {source}: {}", v["mcp_configs"]))
}

fn server<'a>(row: &'a Value, name: &str) -> &'a Value {
    row["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| panic!("no server {name}: {row}"))
}

fn has(findings: &[Finding], sev: Severity, cat: &str, needle: &str) -> bool {
    findings
        .iter()
        .any(|f| f.severity == sev && f.category == cat && f.title.contains(needle))
}

/// A GitHub-token-shaped canary, assembled at run time.
fn canary(tag: &str) -> String {
    format!("{}{}{}{}", "gh", "p_", tag, "Q7wZ3kV9".repeat(4))
}

// ── M1: Cursor project ──────────────────────────────────────────────────────────────

/// A Cursor project's `.cursor/mcp.json` is an MCP row: an unpinned launcher marked, an
/// inline credential graded by name with its value never shown. 12c1f7f read only
/// `~/.cursor/mcp.json`.
#[test]
fn cursor_project_mcp_json_is_read_and_graded() {
    let (home, proj) = home_and_project("cursor");
    let secret = canary("CUR");
    write(
        &proj.join(".cursor/mcp.json"),
        &format!(
            r#"{{"mcpServers":{{"db":{{"command":"npx","args":["-y","some-db-mcp"],"env":{{"DB_TOKEN":"{secret}","HOME_DIR":"${{env:HOME}}"}}}}}}}}"#
        ),
    );
    let (text, v, f) = scan(&home, &home, &["agents"]);
    let row = mcp(&v, "Cursor (project)");
    assert_eq!(
        Path::new(row["config_path"].as_str().unwrap()),
        proj.join(".cursor/mcp.json")
    );
    let s = server(row, "db");
    assert_eq!(s["package_name"], "some-db-mcp");
    assert!(s["unpinned"].is_string(), "{s}");
    assert_eq!(s["inline_secret_env_keys"][0], "DB_TOKEN");
    let env: Vec<&str> = s["env"].as_array().unwrap().iter().filter_map(|e| e.as_str()).collect();
    assert!(env.contains(&"HOME_DIR=${env:HOME}"), "{env:?}");
    assert!(
        has(&f, Severity::High, "MCP secret", "'db' has hardcoded credential(s)"),
        "{}",
        dump(&f)
    );
    assert!(!text.contains(&secret), "the credential value reached the report");
    let _ = fs::remove_dir_all(&home);
}

/// The project list is the pass's: a project recovered only from its
/// `~/.claude/projects/<encoded>` name has its `.cursor/mcp.json`, `.github/mcp.json`,
/// `.vscode/mcp.json` and `.gemini/settings.json` read too.
#[test]
fn recovered_project_mcp_files_are_read() {
    let home = temp_home("recovered");
    let proj = home.join("work").join("app_v3");
    let one = |n: &str| format!(r#"{{"command":"uvx","args":["{n}==1.0"]}}"#);
    write(
        &proj.join(".cursor/mcp.json"),
        &format!(r#"{{"mcpServers":{{"c":{}}}}}"#, one("c-mcp")),
    );
    write(&proj.join(".github/mcp.json"), &format!(r#"{{"g":{}}}"#, one("g-mcp")));
    write(
        &proj.join(".vscode/mcp.json"),
        &format!(r#"{{"servers":{{"v":{}}}}}"#, one("v-mcp")),
    );
    write(
        &proj.join(".gemini/settings.json"),
        &format!(r#"{{"mcpServers":{{"m":{}}}}}"#, one("m-mcp")),
    );
    fs::create_dir_all(
        home.join(".claude/projects")
            .join(rustmachineguard::platform::encode_project_path(&proj)),
    )
    .unwrap();
    let (_, v, _) = scan(&home, &home, &["agents"]);
    for (source, name) in [
        ("Cursor (project)", "c"),
        ("Copilot CLI (repository)", "g"),
        ("VS Code (workspace)", "v"),
        ("Gemini CLI (project)", "m"),
    ] {
        let row = mcp(&v, source);
        assert!(
            row["config_path"]
                .as_str()
                .unwrap()
                .starts_with(&proj.display().to_string()),
            "{row}"
        );
        assert_eq!(server(row, name)["package_name"], format!("{name}-mcp"));
    }
    let _ = fs::remove_dir_all(&home);
}

// ── M1: Copilot CLI ─────────────────────────────────────────────────────────────────

/// `~/.copilot/mcp-config.json` (read by Copilot CLI and, through its default-on
/// discovery, VS Code) and the repository's `.github/mcp.json` in the bare format. A
/// remote server's host is inventoried (path and query dropped), a plaintext one is
/// High, a literal credential header is graded by name only.
#[test]
fn copilot_user_and_repository_mcp_files() {
    let (home, proj) = home_and_project("copilot");
    let secret = canary("COP");
    write(
        &home.join(".copilot/mcp-config.json"),
        r#"{"mcpServers":{
            "context7":{"type":"http","url":"https://mcp.context7.example/mcp?k=1","headers":{"CONTEXT7_API_KEY":"${CONTEXT7_API_KEY}"},"tools":["*"]},
            "pw":{"type":"local","command":"npx","args":["@playwright/mcp@latest"],"tools":["*"]}}}"#,
    );
    write(
        &proj.join(".github/mcp.json"),
        &format!(
            r#"{{"internal":{{"type":"http","url":"http://mcp.internal.example/mcp","headers":{{"Authorization":"Bearer {secret}"}}}},"notes":"not a server"}}"#
        ),
    );
    let (text, v, f) = scan(&home, &home, &["agents"]);
    let user = mcp(&v, "Copilot CLI");
    assert_eq!(user["read_by"], serde_json::json!(["Copilot CLI", "VS Code"]));
    let c7 = server(user, "context7");
    assert_eq!(c7["transport"], "http");
    assert_eq!(c7["url"], "https://mcp.context7.example");
    assert_eq!(server(user, "pw")["transport"], "stdio");
    assert!(server(user, "pw")["unpinned"].is_string());
    let repo = mcp(&v, "Copilot CLI (repository)");
    assert_eq!(
        repo["server_count"], 1,
        "the bare format's non-server key is not a server: {repo}"
    );
    assert_eq!(
        server(repo, "internal")["inline_secret_header_keys"][0],
        "Authorization"
    );
    assert!(
        has(&f, Severity::High, "MCP transport", "'internal' uses plaintext HTTP"),
        "{}",
        dump(&f)
    );
    assert!(
        has(
            &f,
            Severity::High,
            "MCP secret",
            "'internal' has hardcoded credential(s)"
        ),
        "{}",
        dump(&f)
    );
    assert!(!text.contains(&secret));
    let _ = fs::remove_dir_all(&home);
}

/// A project's `.mcp.json` is loaded by Claude Code, Copilot CLI and VS Code: its row says
/// so. 12c1f7f had no `read_by` on MCP rows.
#[test]
fn project_mcp_json_names_every_reader() {
    let (home, proj) = home_and_project("mcpjson");
    write(
        &proj.join(".mcp.json"),
        r#"{"mcpServers":{"s":{"command":"uvx","args":["s-mcp==1.0"]}}}"#,
    );
    let (_, v, _) = scan(&home, &home, &["mcp"]);
    let row = v["mcp_configs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["config_path"].as_str().is_some_and(|p| p.ends_with("proj/.mcp.json")))
        .unwrap_or_else(|| panic!("{}", v["mcp_configs"]));
    assert_eq!(
        row["read_by"],
        serde_json::json!(["Claude Code", "Copilot CLI", "VS Code"])
    );
    let _ = fs::remove_dir_all(&home);
}

// ── M1: VS Code ─────────────────────────────────────────────────────────────────────

fn vscode_user_dir(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Code/User")
    } else {
        home.join(".config/Code/User")
    }
}

/// VS Code's `servers` + `inputs` format, workspace and user profile (with comments, as
/// VS Code allows). Inputs are inventoried by id, type and password flag; a default value
/// is never read; `${input:...}` is a reference, not a hardcoded credential.
#[test]
fn vscode_workspace_and_user_mcp_json() {
    let (home, proj) = home_and_project("vscode");
    let default = canary("VSD");
    write(
        &proj.join(".vscode/mcp.json"),
        &format!(
            r#"{{
  // prompted secrets
  "inputs": [
    {{"type":"promptString","id":"perplexity-key","description":"Perplexity API Key","password":true}},
    {{"type":"pickString","id":"env","description":"Env","options":["dev","prod"],"default":"{default}"}}
  ],
  "servers": {{
    "perplexity": {{"type":"stdio","command":"npx","args":["-y","server-perplexity-ask"],
                   "env":{{"PERPLEXITY_API_KEY":"${{input:perplexity-key}}"}}}},
  }}
}}"#
        ),
    );
    write(
        &vscode_user_dir(&home).join("mcp.json"),
        r#"{"servers":{"gh":{"type":"http","url":"https://api.githubcopilot.example/mcp/"}}}"#,
    );
    let (text, v, f) = scan(&home, &home, &["agents"]);
    let ws = mcp(&v, "VS Code (workspace)");
    assert_eq!(ws["vendor"], "Microsoft");
    assert_eq!(
        ws["inputs"],
        serde_json::json!(["perplexity-key (promptString, password)", "env (pickString)"])
    );
    let s = server(ws, "perplexity");
    assert_eq!(s["env"][0], "PERPLEXITY_API_KEY=${input:perplexity-key}");
    assert!(
        s["inline_secret_env_keys"].as_array().is_none_or(|a| a.is_empty()),
        "{s}"
    );
    assert!(s["unpinned"].is_string());
    assert!(!f.iter().any(|x| x.category == "MCP secret"), "{}", dump(&f));
    let user = mcp(&v, "VS Code (user)");
    assert_eq!(server(user, "gh")["url"], "https://api.githubcopilot.example");
    assert!(!text.contains(&default), "an input's default value reached the report");
    let _ = fs::remove_dir_all(&home);
}

/// A workspace `.vscode/mcp.json` that is a link out of the project is recorded by its
/// target and never opened.
#[test]
fn vscode_workspace_mcp_json_link_out_of_project_is_not_opened() {
    let (home, proj) = home_and_project("vslink");
    let outside = home.join("outside.json");
    write(&outside, r#"{"servers":{"leak":{"command":"uvx","args":["x==1"]}}}"#);
    fs::create_dir_all(proj.join(".vscode")).unwrap();
    std::os::unix::fs::symlink(&outside, proj.join(".vscode/mcp.json")).unwrap();
    let (_, v, _) = scan(&home, &home, &["agents"]);
    assert!(
        !v["mcp_configs"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|c| c["config_source"] == "VS Code (workspace)"),
        "{}",
        v["mcp_configs"]
    );
    let p = v["agent_postures"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| p["agent"] == "vscode")
        .unwrap_or_else(|| panic!("{}", v["agent_postures"]));
    assert!(p["symlink"].is_object(), "{p}");
    let _ = fs::remove_dir_all(&home);
}

// ── M1: Gemini CLI ──────────────────────────────────────────────────────────────────

/// Gemini CLI `mcpServers`: `httpUrl` is an http server, `url` an SSE one; a repository
/// server with `trust: true` ("bypasses all tool call confirmations") is a Medium MCP
/// auto-approval; the user's own `trust` is inventory; `mcp.excluded` turns a server off.
#[test]
fn gemini_user_and_project_settings_mcp_servers() {
    let (home, proj) = home_and_project("gemini");
    write(
        &home.join(".gemini/settings.json"),
        r#"{"mcp":{"excluded":["old"]},"mcpServers":{
            "run":{"httpUrl":"https://run.example/mcp","trust":true},
            "sse":{"url":"https://sse.example/sse"}}}"#,
    );
    write(
        &proj.join(".gemini/settings.json"),
        r#"{"mcpServers":{
            "repo-tool":{"command":"npx","args":["-y","repo-tool-mcp@1.2.3"],"trust":true},
            "old":{"command":"npx","args":["-y","old-mcp@1.0.0"]}}}"#,
    );
    let (_, v, f) = scan(&home, &home, &["agents"]);
    let user = mcp(&v, "Gemini CLI");
    assert_eq!(server(user, "run")["transport"], "http");
    assert_eq!(server(user, "run")["url"], "https://run.example");
    assert_eq!(server(user, "sse")["transport"], "sse");
    let repo = mcp(&v, "Gemini CLI (project)");
    assert_eq!(server(repo, "old")["enabled"], false);
    assert!(
        has(
            &f,
            Severity::Medium,
            "MCP auto-approval",
            "Gemini CLI: MCP tools run without asking (set by the repository) — mcpServers.repo-tool.trust = true"
        ),
        "{}",
        dump(&f)
    );
    assert!(
        !f.iter().any(|x| x.title.contains("mcpServers.run.trust")),
        "{}",
        dump(&f)
    );
    let _ = fs::remove_dir_all(&home);
}

// ── M2: remote-server extension directories ─────────────────────────────────────────

fn extension(dir: &Path, version: &str) {
    write(
        &dir.join("package.json"),
        &format!(r#"{{"name":"claude-code","publisher":"Anthropic","version":"{version}","main":"./extension.js"}}"#),
    );
    write(&dir.join("extension.js"), "// inert test fixture\n");
}

/// The trojanized `anthropic.claude-code` 2.1.313 installed by a Cursor remote server is
/// the same Critical finding as a local install, located at the remote-server label; a
/// VS Code server's root `.obsolete` marks its listed version. 12c1f7f did not look in
/// any remote-server directory.
#[test]
fn trojanized_extension_under_cursor_server_is_critical() {
    let home = temp_home("remote");
    extension(
        &home.join(".cursor-server/extensions/anthropic.claude-code-2.1.313"),
        "2.1.313",
    );
    let vs = home.join(".vscode-server/extensions");
    extension(&vs.join("anthropic.claude-code-2.1.313-linux-x64"), "2.1.313");
    write(
        &vs.join(".obsolete"),
        r#"{"anthropic.claude-code-2.1.313-linux-x64":true}"#,
    );
    let (_, v, f) = scan(&home, &home, &["extensions"]);
    let rows: Vec<&Value> = v["ide_extensions"].as_array().unwrap().iter().collect();
    let cursor = rows
        .iter()
        .find(|r| r["ide_type"] == "Cursor (remote server)")
        .unwrap_or_else(|| panic!("{rows:?}"));
    assert_eq!(cursor["version"], "2.1.313");
    let vsrow = rows
        .iter()
        .find(|r| r["ide_type"] == "Visual Studio Code (remote server)")
        .unwrap_or_else(|| panic!("{rows:?}"));
    assert_eq!(vsrow["target_platform"], "linux-x64");
    assert_eq!(vsrow["obsolete"], true);
    let hits: Vec<&Finding> = f
        .iter()
        .filter(|x| x.category == "Exposure" && x.location == "Cursor (remote server)")
        .collect();
    assert_eq!(hits.len(), 1, "{}", dump(&f));
    assert_eq!(hits[0].severity, Severity::Critical);
    assert_eq!(hits[0].title, "Known-bad vscode package: anthropic.claude-code 2.1.313");
    let _ = fs::remove_dir_all(&home);
}

// ── M3: extension agents and the root .obsolete ─────────────────────────────────────

/// Cline installed in VS Code: the version the root `.obsolete` lists is not an installed
/// agent; a per-extension `.obsolete` file (VS Code never writes one) does not hide the
/// installed version; a remote server's Cline is an agent too. 12c1f7f probed the
/// per-extension file only, so it listed the obsolete version, hid the installed one and
/// never looked at a remote server.
#[test]
fn extension_agents_follow_the_root_obsolete_file() {
    let home = temp_home("obsolete");
    let ext = home.join(".vscode/extensions");
    fs::create_dir_all(ext.join("saoudrizwan.claude-dev-3.0.0")).unwrap();
    fs::create_dir_all(ext.join("saoudrizwan.claude-dev-3.1.0")).unwrap();
    write(&ext.join("saoudrizwan.claude-dev-3.1.0/.obsolete"), "{}");
    write(&ext.join(".obsolete"), r#"{"saoudrizwan.claude-dev-3.0.0":true}"#);
    fs::create_dir_all(home.join(".cursor-server/extensions/saoudrizwan.claude-dev-3.2.0")).unwrap();
    let (_, v, _) = scan(&home, &home, &["ai"]);
    let cline: Vec<(String, String)> = v["ai_agents_and_tools"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|t| t["name"].as_str().is_some_and(|n| n.starts_with("Cline (")))
        .map(|t| {
            (
                t["name"].as_str().unwrap().to_string(),
                t["version"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(
        cline,
        vec![
            ("Cline (Visual Studio Code)".to_string(), "3.1.0".to_string()),
            ("Cline (Cursor (remote server))".to_string(), "3.2.0".to_string()),
        ],
        "{}",
        v["ai_agents_and_tools"]
    );
    let _ = fs::remove_dir_all(&home);
}
