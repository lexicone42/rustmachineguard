//! Perf round 6c regression tests.
//!
//! * The gitconfig nested-repository walk is breadth-first with listings read ahead on
//!   helper threads (`scanners::prefetch`, as the rules walk since 6b; depth-first
//!   before). Its findings within a project are sorted by path, so their order no longer
//!   follows the walk's (or the file system's listing order), and the report is the same
//!   at `--jobs 1` and `--jobs 4`.
//! * Under an exhausted `--walk-budget` the walk lists the shallowest directories first:
//!   a git dir two levels down is found, and the ones 43 levels down, which the
//!   depth-first walk spent its budget reaching, are not (the one intended difference).

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rmg-perf6c-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::canonicalize(&dir).unwrap()
}

fn write(p: &Path, text: &str) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

/// A buried bare git dir whose `core.fsmonitor` runs a script inside the repository.
fn plant(dir: &Path, tag: &str) {
    std::fs::create_dir_all(dir.join("objects")).unwrap();
    std::fs::create_dir_all(dir.join("refs")).unwrap();
    write(&dir.join("HEAD"), "ref: refs/heads/main\n");
    write(&dir.join("config"), &format!("[core]\n\tfsmonitor = \"./{tag}.sh\"\n"));
}

fn register(home: &Path, project: &Path) {
    write(
        &home.join(".claude.json"),
        &format!("{{\"projects\":{{\"{}\":{{}}}}}}", project.display()),
    );
}

fn rmguard(home: &Path, args: &[&str]) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_rmguard"))
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
        .current_dir(home)
        .args(["--format", "json"])
        .args(args)
        .output()
        .expect("run rmguard");
    assert!(
        out.status.success(),
        "exit {:?}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let mut v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    for k in ["scan_timestamp", "scan_timestamp_iso"] {
        v.as_object_mut().unwrap().remove(k);
    }
    if let Some(d) = v.get_mut("diagnostics").and_then(|d| d.as_array_mut()) {
        for row in d {
            row.as_object_mut().unwrap().remove("duration_ms");
        }
    }
    v
}

/// The nested-repo findings' paths, relative to `project`.
fn nested(report: &serde_json::Value, project: &Path) -> Vec<String> {
    let prefix = format!("{}/", project.display());
    report["git_autorun_configs"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|c| c["nested"] == true)
                .map(|c| c["path"].as_str().unwrap().trim_start_matches(&prefix).to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn gitconfig_truncated(report: &serde_json::Value) -> bool {
    report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["scanner"] == "gitconfig")
        .and_then(|r| r["truncated"].as_bool())
        .unwrap_or(false)
}

/// Eight buried git dirs in one project, among 40 other directories: reported sorted by
/// path, and the whole report is the same at `--jobs 1` and `--jobs 4` (the walk reads
/// ahead at 4). The depth-first walk reported them in reverse listing order.
#[test]
fn nested_findings_are_sorted_by_path_at_any_jobs() {
    let root = temp_dir("order");
    let home = root.join("home");
    let project = home.join("proj");
    for i in 0..40 {
        std::fs::create_dir_all(project.join(format!("src/m{i:02}"))).unwrap();
    }
    let planted = [
        "src/m31/pay",
        "vendor/z",
        "src/m03/pay",
        "a/b/c/pay",
        "src/m17/x/pay",
        "lib",
        "src/m09/pay",
        "tools/t",
    ];
    for (k, rel) in planted.iter().enumerate() {
        plant(&project.join(rel), &format!("p{k}"));
    }
    register(&home, &project);
    let one = rmguard(&home, &["--jobs", "1"]);
    let four = rmguard(&home, &["--jobs", "4"]);
    let _ = std::fs::remove_dir_all(&root);
    let mut want: Vec<String> = planted.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(nested(&one, &project), want);
    assert_eq!(one, four, "--jobs 1 and --jobs 4 reports differ");
    assert!(!gitconfig_truncated(&one));
}

/// A project over a 60-directory `--walk-budget`: ten 45-deep chains, each with a git dir
/// 43 levels down, and one git dir 2 levels down. The breadth-first walk lists the 60
/// shallowest directories: it finds the shallow one and none of the deep ones, the same at
/// `--jobs 1` and `--jobs 4`, and the row is truncated. The depth-first walk always went
/// down a chain first and reported a deep one (pinned: the order change is intended).
#[test]
fn an_exhausted_budget_lists_the_shallowest_directories() {
    let root = temp_dir("budget");
    let home = root.join("home");
    let project = home.join("proj");
    for c in 0..10 {
        let mut d = project.join(format!("c{c}"));
        for l in 0..45 {
            d = d.join(format!("l{l}"));
            if l == 40 {
                plant(&d.join("pay"), &format!("deep{c}"));
            }
        }
        std::fs::create_dir_all(&d).unwrap();
    }
    plant(&project.join("s/pay"), "shallow");
    register(&home, &project);
    let one = rmguard(&home, &["--jobs", "1", "--walk-budget", "60"]);
    let four = rmguard(&home, &["--jobs", "4", "--walk-budget", "60"]);
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(nested(&one, &project), vec!["s/pay".to_string()]);
    assert!(gitconfig_truncated(&one));
    assert_eq!(one, four, "--jobs 1 and --jobs 4 reports differ");
}
