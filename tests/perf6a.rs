//! Perf round 6a regression tests: each optimisation keeps the report as it was.
//!
//! * The persistence scanner reads a repository's git index before spawning
//!   `git ls-files -s`, and spawns only when the index lists a symlink or the parser is
//!   unsure. [`index_symlink_free`] is checked against git itself on every index layout
//!   git writes (versions 2, 3 and 4, split, sparse, untracked cache, SHA-256), and the
//!   end-to-end report still finds an escaping committed symlink in each layout.
//! * Settings permission rules are classified after every file is read and each distinct
//!   rule text rendered once on the helper threads; the gitconfig nested walk starts the
//!   project holding the most other projects first. Neither may change a report: the
//!   same fixture scanned at `--jobs 1` and `--jobs 4` gives the same JSON.

#![cfg(unix)]

use rustmachineguard::scanners::persistence::index_symlink_free;
use std::path::{Path, PathBuf};
use std::process::Command;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rmg-perf6a-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(p: &Path, text: &str) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

/// git with no user or system config; None when git is unavailable or fails.
fn git(dir: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", dir)
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_DIR")
        .output()
        .ok()?;
    out.status.success().then_some(out.stdout)
}

fn ok(dir: &Path, args: &[&str]) -> bool {
    git(dir, args).is_some()
}

/// A repository with tracked files, a gitlink-free tree, and optionally one tracked
/// symlink. None when git is unavailable.
fn repo(dir: &Path, init: &[&str], symlink: bool) -> Option<()> {
    std::fs::create_dir_all(dir).unwrap();
    let mut args = vec!["init", "-q"];
    args.extend_from_slice(init);
    git(dir, &args)?;
    git(dir, &["config", "user.email", "t@example.com"])?;
    git(dir, &["config", "user.name", "t"])?;
    write(&dir.join("a.txt"), "a\n");
    write(&dir.join("sub/b.txt"), "b\n");
    // A long name (over 0xFFF bytes would need deep trees; this exercises long paths).
    let long = format!("deep/{}/c.txt", "d".repeat(200));
    write(&dir.join(long), "c\n");
    if symlink {
        std::os::unix::fs::symlink("../../outside", dir.join("sub/link")).unwrap();
    }
    git(dir, &["add", "-A"])?;
    git(dir, &["commit", "-q", "-m", "init"])?;
    Some(())
}

/// What git says: does `git ls-files -s` list a mode-120000 entry?
fn git_lists_symlink(dir: &Path) -> Option<bool> {
    let out = git(dir, &["ls-files", "-s", "-z"])?;
    Some(out.split(|b| *b == 0).any(|r| r.starts_with(b"120000 ")))
}

fn index(dir: &Path) -> Vec<u8> {
    std::fs::read(dir.join(".git/index")).unwrap()
}

/// The pre-check agrees with git on every layout git writes: never "no symlink" when git
/// lists one, and unsure (None) for the layouts it does not read itself.
#[test]
fn index_precheck_agrees_with_git_on_every_layout() {
    let base = temp_dir("layouts");
    if !ok(&base, &["--version"]) {
        eprintln!("git unavailable: skipped");
        return;
    }
    // (name, init args, post-commit commands, expected verdict without / with a symlink)
    type Case<'a> = (&'a str, &'a [&'a str], &'a [&'a [&'a str]], Option<bool>);
    let cases: &[Case] = &[
        ("v2", &[], &[&["update-index", "--index-version", "2"]], Some(true)),
        ("v3", &[], &[&["update-index", "--index-version", "3"]], Some(true)),
        ("v4", &[], &[&["update-index", "--index-version", "4"]], Some(true)),
        // Intent-to-add sets the extended flag (a v3 entry with two more flag bytes).
        ("ita", &[], &[], Some(true)),
        (
            "untracked-cache",
            &[],
            &[&["update-index", "--untracked-cache"]],
            Some(true),
        ),
        // Split index: the entries live in sharedindex.*; the parser must not claim none.
        ("split", &[], &[&["update-index", "--split-index"]], None),
        ("sha256", &["--object-format=sha256"], &[], None),
    ];
    for (name, init, post, want_clean) in cases {
        for symlink in [false, true] {
            let dir = base.join(format!("{name}-{symlink}"));
            if repo(&dir, init, symlink).is_none() {
                eprintln!("{name}: git could not build this layout here: skipped");
                continue;
            }
            if *name == "ita" {
                write(&dir.join("new.txt"), "n\n");
                assert!(ok(&dir, &["add", "-N", "new.txt"]));
            }
            let mut skipped = false;
            for cmd in *post {
                if !ok(&dir, cmd) {
                    skipped = true;
                }
            }
            if skipped {
                eprintln!("{name}: git refused {post:?}: skipped");
                continue;
            }
            let truth = git_lists_symlink(&dir).expect("git ls-files");
            assert_eq!(truth, symlink, "{name}: fixture");
            let verdict = index_symlink_free(&index(&dir));
            match want_clean {
                Some(_) => assert_eq!(verdict, Some(!symlink), "{name} symlink={symlink}"),
                None => assert_eq!(verdict, None, "{name} symlink={symlink}: must defer to git"),
            }
        }
    }
    // A sparse index (directory entries stand for whole trees) is deferred to git.
    let dir = base.join("sparse");
    if repo(&dir, &[], true).is_some()
        && ok(&dir, &["sparse-checkout", "init", "--cone", "--sparse-index"])
        && ok(&dir, &["sparse-checkout", "set", "deep"])
    {
        let raw = index(&dir);
        if raw.windows(4).any(|w| w == b"sdir") {
            assert_eq!(index_symlink_free(&raw), None, "sparse index");
        }
    }
    // A gitlink (submodule entry, mode 160000) is an ordinary entry.
    let dir = base.join("gitlink");
    if repo(&dir, &[], false).is_some() {
        let oid = String::from_utf8(git(&dir, &["rev-parse", "HEAD"]).unwrap()).unwrap();
        let info = format!("160000,{},vendored", oid.trim());
        if ok(&dir, &["update-index", "--add", "--cacheinfo", &info]) {
            assert_eq!(git_lists_symlink(&dir), Some(false));
            assert_eq!(index_symlink_free(&index(&dir)), Some(true), "gitlink");
        }
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// Damaged input never panics and never turns a symlink into "none": every truncation
/// and every single-byte change of a real index with a symlink entry is either still a
/// symlink or unsure, or (when the damage removed the symlink entry from what parses) a
/// verdict git would not contradict for an index it refuses to read.
#[test]
fn index_precheck_is_conservative_on_damaged_input() {
    let base = temp_dir("damaged");
    let dir = base.join("r");
    if repo(&dir, &[], true).is_none() {
        eprintln!("git unavailable: skipped");
        return;
    }
    let raw = index(&dir);
    assert_eq!(index_symlink_free(&raw), Some(false));
    for len in 0..raw.len() {
        let cut = &raw[..len];
        // Every entry comes before the extensions: a prefix that still parses holds all of
        // them, so it still holds the symlink.
        assert_ne!(index_symlink_free(cut), Some(true), "truncated to {len}");
    }
    for at in 0..raw.len() {
        for flip in [0x01u8, 0x80, 0xff] {
            let mut m = raw.clone();
            m[at] ^= flip;
            // No panic, whatever the verdict. A flip in the symlink entry's mode word can
            // make it a regular file; git would then list no symlink either.
            let _ = index_symlink_free(&m);
        }
    }
    for junk in [&b""[..], b"DIRC", b"DIRC\0\0\0\x02\xff\xff\xff\xff", &[0u8; 64][..]] {
        assert_eq!(index_symlink_free(junk), None);
    }
    let _ = std::fs::remove_dir_all(&base);
}

fn rmguard(home: &Path, args: &[&str]) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_rmguard"))
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
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
    // Timing is not content.
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

/// The pre-check skips git only where it would have found nothing: an escaping committed
/// symlink is still reported from a v2, v4 and split-index repository, and a repository
/// without one reports nothing.
#[test]
fn escaping_symlinks_still_found_in_every_index_layout() {
    let home = temp_dir("e2e");
    let mut projects = Vec::new();
    let mut want = Vec::new();
    for (name, post, symlink) in [
        ("plain", &[][..], true),
        ("v4", &[&["update-index", "--index-version", "4"][..]][..], true),
        ("split", &[&["update-index", "--split-index"][..]][..], true),
        ("clean", &[][..], false),
    ] {
        let dir = home.join("work").join(name);
        if repo(&dir, &[], symlink).is_none() {
            eprintln!("git unavailable: skipped");
            return;
        }
        if !post.iter().all(|c| ok(&dir, c)) {
            continue;
        }
        if symlink {
            want.push(dir.join("sub/link").display().to_string());
        }
        projects.push(dir);
    }
    let reg: serde_json::Map<String, serde_json::Value> = projects
        .iter()
        .map(|p| (p.display().to_string(), serde_json::json!({})))
        .collect();
    write(
        &home.join(".claude.json"),
        &serde_json::json!({ "projects": reg }).to_string(),
    );
    let report = rmguard(&home, &[]);
    let mut got: Vec<String> = report["persistence_artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["kind"] == "escaping-symlink")
        .map(|a| a["path"].as_str().unwrap().to_string())
        .collect();
    got.sort();
    want.sort();
    assert_eq!(got, want);
    let _ = std::fs::remove_dir_all(&home);
}

/// The settings rules (classified after every file is read, each distinct text rendered
/// once, on helper threads) and the gitconfig walk (biggest project first) give the same
/// report at `--jobs 1` and `--jobs 4`, and the same as the rules each file yields alone.
#[test]
fn jobs_do_not_change_settings_rules_or_nested_walk() {
    let home = temp_dir("jobs");
    let ws = home.join("ws");
    let mut projects = vec![ws.clone()];
    // Shared rules across projects (rendered once), per-project ones, graded ones and a
    // secret-shaped one the redactor must still hide.
    let shared: Vec<String> = (0..40).map(|i| format!("Bash(cargo test -p crate{i}:*)")).collect();
    for p in 0..6 {
        let proj = ws.join(format!("p{p}"));
        let mut allow = shared.clone();
        allow.extend((0..30).map(|i| format!("Bash(make target{p}_{i}:*)")));
        allow.push("Bash(python3:*)".into());
        allow.push("Read(~/.ssh/**)".into());
        allow.push("mcp__github".into());
        allow.push("Bash(curl -H 'Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789' :*)".into());
        write(
            &proj.join(".claude/settings.local.json"),
            &serde_json::json!({ "permissions": { "allow": allow, "deny": ["Bash(rm -rf /:*)"] } }).to_string(),
        );
        // A buried git dir in each project, and generated trees to prune.
        let nested = proj.join("vendor/payload");
        write(&nested.join("HEAD"), "ref: refs/heads/main\n");
        write(&nested.join("config"), "[core]\n\tfsmonitor = \"./payload.sh\"\n");
        std::fs::create_dir_all(nested.join("objects")).unwrap();
        std::fs::create_dir_all(nested.join("refs")).unwrap();
        for d in 0..20 {
            std::fs::create_dir_all(proj.join(format!("data/d{d}/e"))).unwrap();
        }
        projects.push(proj);
    }
    // The workspace itself (registered LAST, holding every other project) is the
    // biggest walk: it is started first and its findings still come last.
    projects.rotate_left(1);
    let reg: serde_json::Map<String, serde_json::Value> = projects
        .iter()
        .map(|p| (p.display().to_string(), serde_json::json!({})))
        .collect();
    write(
        &home.join(".claude.json"),
        &serde_json::json!({ "projects": reg }).to_string(),
    );
    let one = rmguard(&home, &["--jobs", "1"]);
    let four = rmguard(&home, &["--jobs", "4"]);
    assert_eq!(one, four, "--jobs changed the report");
    let rows = one["agent_settings"].as_array().unwrap();
    let local: Vec<_> = rows.iter().filter(|r| r["source"] == "local").collect();
    assert_eq!(local.len(), 6);
    for r in &local {
        let rules = r["permission_rules"].as_array().unwrap();
        assert_eq!(rules.len(), 40 + 30 + 4 + 1, "every allow and deny rule kept");
        let text = serde_json::to_string(rules).unwrap();
        assert!(!text.contains("ghp_abcdefghijklmnopqrstuvwxyz0123456789"), "redacted");
        assert!(rules.iter().any(|x| x["class"].is_string()), "graded rules");
    }
    let nested: Vec<_> = one["git_autorun_configs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c.to_string().contains("payload"))
        .collect();
    assert_eq!(nested.len(), 6, "each project's buried git dir, found once");
    let _ = std::fs::remove_dir_all(&home);
}
