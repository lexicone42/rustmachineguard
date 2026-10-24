//! Install roots the package scanners read beyond system, user and project
//! site-packages: uv tool environments, pipx venvs, agent-private venvs, uv-managed
//! interpreters, and npm's `lib64/node_modules` prefix (Gentoo multilib). Each test
//! builds a temp HOME holding a package whose name and version match a built-in
//! catalog row, runs the real binary with every other scanner skipped, and asserts the
//! exposure finding (or persistence artifact) appears with the right root. On f91d034
//! none of these roots was read, so every positive assertion here fails there.
#![cfg(unix)]

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

/// A fresh, canonical temp HOME (macOS temp_dir() is behind a /var symlink).
fn temp_home(tag: &str) -> PathBuf {
    let home = std::env::temp_dir().join(format!("rmg-roots-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).unwrap();
    fs::canonicalize(&home).unwrap()
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

/// A `Name-Version.dist-info` with its METADATA in `site_packages`.
fn dist(site_packages: &Path, name: &str, version: &str) {
    let dir = site_packages.join(format!("{}-{version}.dist-info", name.replace('-', "_")));
    write(
        &dir.join("METADATA"),
        &format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n"),
    );
}

/// A venv at `venv`: `lib/python3.13/site-packages` with a `lib64 -> lib` link, the
/// layout `uv venv` and `python -m venv` write on Linux. Returns its site-packages.
fn venv(venv: &Path) -> PathBuf {
    let sp = venv.join("lib/python3.13/site-packages");
    fs::create_dir_all(&sp).unwrap();
    let _ = std::os::unix::fs::symlink("lib", venv.join("lib64"));
    write(&venv.join("pyvenv.cfg"), "home = /usr/bin\n");
    sp
}

/// Run rmguard against `home` with only `keep` enabled; JSON and terminal outputs.
/// The install-root environment variables are cleared so the host's own cannot leak in;
/// `env` sets the ones a test wants.
fn run(home: &Path, keep: &[&str], extra_args: &[&str], env: &[(&str, &Path)], format: &str) -> String {
    let skip: Vec<&str> = ALL_LABELS.iter().copied().filter(|l| !keep.contains(l)).collect();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rmguard"));
    cmd.args(["--format", format, "--skip", &skip.join(",")])
        .args(extra_args)
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("NO_COLOR", "1")
        .env_remove("UV_TOOL_DIR")
        .env_remove("UV_PYTHON_INSTALL_DIR")
        .env_remove("XDG_DATA_HOME")
        .env_remove("PIPX_HOME")
        .current_dir(home);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run rmguard");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn json(home: &Path, keep: &[&str], extra_args: &[&str], env: &[(&str, &Path)]) -> Value {
    serde_json::from_str(&run(home, keep, extra_args, env, "json")).expect("report json")
}

/// (ecosystem, name, version, root_kind, root_name) of each exposure finding located
/// under `home` (the host's own /usr/lib site-packages are read too and are not this
/// test's business).
fn exposures_under(v: &Value, home: &Path) -> Vec<(String, String, String, String, String)> {
    let s = |x: &Value| x.as_str().unwrap_or("").to_string();
    // Absent from the JSON when empty.
    let none = Vec::new();
    let mut rows: Vec<_> = v["exposure_findings"]
        .as_array()
        .unwrap_or(&none)
        .iter()
        .filter(|f| {
            f["found_in"]
                .as_str()
                .is_some_and(|p| p.starts_with(&*home.to_string_lossy()))
        })
        .map(|f| {
            (
                s(&f["ecosystem"]),
                s(&f["name"]),
                s(&f["version"]),
                s(&f["root_kind"]),
                s(&f["root_name"]),
            )
        })
        .collect();
    rows.sort();
    rows
}

fn row(eco: &str, name: &str, ver: &str, kind: &str, root: &str) -> (String, String, String, String, String) {
    (eco.into(), name.into(), ver.into(), kind.into(), root.into())
}

/// Every Python root kind the scanner learned, each holding a catalogued version
/// (pypi `mcp` <1.30.0, pypi `mistral-vibe` >=1.3.4,<2.25.4 — MAI-2026-003), plus the
/// negative controls: an unrelated uv tool, a venv reached only through a symlink in
/// `~/.claude`, and a venv deeper than the walk looks.
#[test]
fn python_roots_uv_tools_pipx_agent_venvs_and_uv_pythons_are_matched() {
    let home = temp_home("py");
    let tools = home.join(".local/share/uv/tools");
    let vibe = venv(&tools.join("mistral-vibe"));
    dist(&vibe, "mistral-vibe", "2.5.0");
    dist(&vibe, "mcp", "1.26.0");
    // Negative control: a uv tool with nothing catalogued.
    let ruff = venv(&tools.join("ruff"));
    dist(&ruff, "ruff", "0.6.9");
    // A uv tool under $UV_TOOL_DIR (an absolute override).
    let alt_tools = home.join("alt-uv-tools");
    dist(&venv(&alt_tools.join("semgrep")), "mcp", "1.23.3");
    // pipx (current default PIPX_HOME) and the legacy location.
    dist(&venv(&home.join(".local/share/pipx/venvs/some-cli")), "mcp", "1.20.0");
    dist(&venv(&home.join(".local/pipx/venvs/old-cli")), "mcp", "1.19.0");
    // An agent-private venv, depth 2 under ~/.claude.
    dist(&venv(&home.join(".claude/security/agent-sdk-venv")), "mcp", "1.27.1");
    // A uv-managed interpreter's base site-packages (no pyvenv.cfg there).
    let interp = home.join(".local/share/uv/python/cpython-3.13.1-linux-x86_64-gnu/lib/python3.13/site-packages");
    fs::create_dir_all(&interp).unwrap();
    dist(&interp, "mcp", "1.22.0");
    // Not followed: a venv reachable from ~/.claude only through a symlink.
    let outside = home.join("elsewhere/linked-venv");
    dist(&venv(&outside), "mcp", "1.18.0");
    std::os::unix::fs::symlink(&outside, home.join(".claude/linked-venv")).unwrap();
    // Not reached: a venv at depth 4 under ~/.codex.
    dist(&venv(&home.join(".codex/a/b/c/deep-venv")), "mcp", "1.17.0");

    let v = json(&home, &["pypkgs"], &[], &[("UV_TOOL_DIR", &alt_tools)]);
    let got = exposures_under(&v, &home);
    let mut want = vec![
        row("pypi", "mistral-vibe", "2.5.0", "uv-tool", "mistral-vibe"),
        row("pypi", "mcp", "1.26.0", "uv-tool", "mistral-vibe"),
        row("pypi", "mcp", "1.23.3", "uv-tool", "semgrep"),
        row("pypi", "mcp", "1.20.0", "pipx", "some-cli"),
        row("pypi", "mcp", "1.19.0", "pipx", "old-cli"),
        row("pypi", "mcp", "1.27.1", "agent-venv", "agent-sdk-venv"),
        row("pypi", "mcp", "1.22.0", "uv-python", ""),
    ];
    want.sort();
    // Exactly these: the lib64 -> lib link does not double a row, ruff matches nothing,
    // the symlinked and the too-deep venvs are not read.
    assert_eq!(got, want, "{:#}", v["exposure_findings"]);

    // The terminal says where each one lives.
    let text = run(&home, &["pypkgs"], &[], &[("UV_TOOL_DIR", &alt_tools)], "terminal");
    assert!(text.contains("(uv-tool mistral-vibe)"), "{text}");
    assert!(text.contains("(agent-venv agent-sdk-venv)"), "{text}");
    assert!(text.contains("(uv-python)"), "{text}");

    // Without the variable the override tree is not a root: it is read because
    // $UV_TOOL_DIR names it, not because it sits under HOME.
    let without = json(&home, &["pypkgs"], &[], &[]);
    assert!(
        !exposures_under(&without, &home).iter().any(|r| r.4 == "semgrep"),
        "UV_TOOL_DIR unset: the override tree is not a default root"
    );
    let _ = fs::remove_dir_all(&home);
}

/// The `.pth` / `sitecustomize.py` check runs over the same roots: an import `.pth`
/// in a uv tool and a `sitecustomize.py` in an agent venv are reported, uv's own
/// `_virtualenv.pth` is not.
#[test]
fn persistence_startup_hooks_in_uv_tool_and_agent_venv_roots() {
    let home = temp_home("pth");
    let sp = venv(&home.join(".local/share/uv/tools/some-tool"));
    write(&sp.join("_virtualenv.pth"), "import _virtualenv\n"); // uv writes this
    write(&sp.join("zz-hook.pth"), "import os; os.getcwd()\n");
    let agent = venv(&home.join(".claude/plugins/mcp-venv"));
    write(&agent.join("sitecustomize.py"), "pass\n");
    write(&home.join(".claude.json"), r#"{"projects":{}}"#);

    let v = json(&home, &["persistence"], &[], &[]);
    let none = Vec::new();
    let names: Vec<(String, String)> = v["persistence_artifacts"]
        .as_array()
        .unwrap_or(&none)
        .iter()
        .map(|a| {
            (
                a["kind"].as_str().unwrap().to_string(),
                a["path"].as_str().unwrap().rsplit('/').next().unwrap().to_string(),
            )
        })
        .collect();
    let has = |f: &str| names.iter().any(|(k, n)| k == "python-startup-hook" && n == f);
    assert!(has("zz-hook.pth"), "uv tool .pth missing: {names:?}");
    assert!(has("sitecustomize.py"), "agent venv sitecustomize missing: {names:?}");
    assert!(!has("_virtualenv.pth"), "uv's own .pth is allowlisted: {names:?}");
    // One row per hook although the venv is reachable as lib/ and lib64/.
    assert_eq!(names.iter().filter(|(_, n)| n == "zz-hook.pth").count(), 1, "{names:?}");
    let _ = fs::remove_dir_all(&home);
}

/// npm's global prefix on a multilib Gentoo box is `<prefix>/lib64/node_modules`
/// (@modelcontextprotocol/sdk 1.20.0 matches the catalog's <1.32.0 row).
#[test]
fn npm_global_lib64_prefix_is_read() {
    let home = temp_home("npm");
    let pkg = home.join(".npm-global/lib64/node_modules/@modelcontextprotocol/sdk");
    write(
        &pkg.join("package.json"),
        r#"{"name":"@modelcontextprotocol/sdk","version":"1.20.0"}"#,
    );
    let v = json(&home, &["npmpkgs"], &[], &[]);
    let got = exposures_under(&v, &home);
    assert_eq!(
        got,
        vec![row("npm", "@modelcontextprotocol/sdk", "1.20.0", "", "")],
        "{:#}",
        v["exposure_findings"]
    );
    let _ = fs::remove_dir_all(&home);
}

/// The environment-root walk is bounded by `--walk-budget` and says so. At budget 8 the
/// cap is 2 directories: the tools dir and the first tool's `lib` (name order, so the
/// survivor does not depend on listing order); the rest is dropped and the pypkgs row
/// is marked truncated. At the default budget the same tree is complete and unmarked.
#[test]
fn environment_root_walk_is_capped_and_marked_truncated() {
    let home = temp_home("cap");
    let tools = home.join(".local/share/uv/tools");
    for t in ["a-tool", "b-tool", "c-tool"] {
        dist(&venv(&tools.join(t)), "mcp", "1.26.0");
    }
    let pypkgs_row = |v: &Value| {
        v["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["scanner"] == "pypkgs")
            .cloned()
            .unwrap()
    };
    let capped = json(&home, &["pypkgs"], &["--walk-budget", "8"], &[]);
    let roots: Vec<String> = exposures_under(&capped, &home).into_iter().map(|r| r.4).collect();
    assert_eq!(roots, vec!["a-tool".to_string()], "{:#}", capped["exposure_findings"]);
    assert_eq!(pypkgs_row(&capped)["truncated"], true, "{:#}", pypkgs_row(&capped));

    let full = json(&home, &["pypkgs"], &[], &[]);
    let roots: Vec<String> = exposures_under(&full, &home).into_iter().map(|r| r.4).collect();
    assert_eq!(roots, vec!["a-tool", "b-tool", "c-tool"]);
    assert!(pypkgs_row(&full).get("truncated").is_none(), "{:#}", pypkgs_row(&full));
    let _ = fs::remove_dir_all(&home);
}
