//! The Junie CLI build is read from the `~/.local/share/junie/current` symlink (the tree
//! the vendor's installer and npm launchers write), `junie` is never run, and the catalog's
//! `junie-cli` row (in build numbers) matches it. Every case fails on the code before this
//! file: Junie had no version and no `agent-runtime` key.
#![cfg(unix)]

use rustmachineguard::catalogs::BUILTIN_CATALOG;
use rustmachineguard::scanners::ai_tools::junie_current_build;
use rustmachineguard::scanners::exposure::{ExposureCatalog, agent_runtime_key};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

fn home(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rmg-junie-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::canonicalize(&dir).unwrap()
}

/// `<home>/.local/share/junie/current` -> `target`, with the versions directory present.
fn install(home: &Path, target: &Path) {
    let data = home.join(".local/share/junie");
    std::fs::create_dir_all(data.join("versions")).unwrap();
    symlink(target, data.join("current")).unwrap();
}

#[test]
fn build_is_the_name_of_the_directory_current_points_at() {
    for build in ["2470.4", "888.26", "4020.10", "2548.5.1"] {
        let h = home(&format!("ok-{build}"));
        let dir = h.join(".local/share/junie/versions").join(build);
        install(&h, &dir);
        assert_eq!(junie_current_build(&h).as_deref(), Some(build), "absolute target");
        let _ = std::fs::remove_dir_all(&h);
    }
    // A relative target, and one whose directory is gone (a dangling link still names it).
    let h = home("rel");
    install(&h, Path::new("versions/3110.7"));
    assert_eq!(junie_current_build(&h).as_deref(), Some("3110.7"));
    let _ = std::fs::remove_dir_all(&h);
}

#[test]
fn anything_that_is_not_a_versions_build_link_gives_no_version() {
    // Not under `versions/`, not a build number, text where a number belongs, too long.
    for (tag, target) in [
        ("elsewhere", "/opt/junie/2470.4"),
        ("word", "versions/latest"),
        ("single", "versions/2470"),
        ("four", "versions/1.2.3.4"),
        ("alpha", "versions/2470.4-beta"),
        ("empty-part", "versions/2470."),
        ("long", "versions/12345678.1"),
        ("escape", "versions/\u{1b}[31m1.2"),
        ("up", "versions/.."),
    ] {
        let h = home(tag);
        install(&h, Path::new(target));
        assert_eq!(junie_current_build(&h), None, "{target}");
        let _ = std::fs::remove_dir_all(&h);
    }
    // `current` as a real directory (the shim tolerates it; it names no build), and absent.
    let h = home("dir");
    std::fs::create_dir_all(h.join(".local/share/junie/current")).unwrap();
    assert_eq!(junie_current_build(&h), None);
    assert_eq!(junie_current_build(&h.join("nowhere")), None);
    let _ = std::fs::remove_dir_all(&h);
}

#[test]
fn catalog_row_is_in_build_numbers_and_ends_at_the_first_26_8_24_build() {
    let cat = ExposureCatalog::load_from_str(BUILTIN_CATALOG).unwrap();
    let hits = |v: &str| cat.check_extension("agent-runtime", "junie-cli", v, "/t").len();
    assert_eq!(agent_runtime_key("Junie CLI"), Some("junie-cli"));
    // update-info.jsonl: 2777.8 = 26.8.17, 2470.4 = 26.7.27, 888.x and 1468.30 unnumbered.
    for vulnerable in ["888.26", "1468.30", "2470.4", "2548.5", "2777.8", "2929.4"] {
        assert_eq!(hits(vulnerable), 1, "{vulnerable}");
    }
    // 2929.5 = 26.8.24 (the fix), then later builds.
    for fixed in ["2929.5", "3013.3", "3110.7", "4020.10"] {
        assert_eq!(hits(fixed), 0, "{fixed}");
    }
    // A 26.x release number is not a build number and must never be read as one by a
    // caller: the scanner only ever supplies builds, and this row would call it old.
    assert_eq!(hits("26.11.3"), 1, "documented: the row compares build numbers only");
}

#[test]
fn scan_reports_the_build_and_the_advisory_without_running_junie() {
    let h = home("e2e");
    std::fs::create_dir_all(h.join(".junie")).unwrap();
    let dir = h.join(".local/share/junie/versions/2470.4");
    std::fs::create_dir_all(&dir).unwrap();
    install(&h, &dir);
    // A `junie` on PATH that leaves a marker if anything starts it.
    let bin = h.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let marker = h.join("junie-was-run");
    let shim = bin.join("junie");
    std::fs::write(&shim, format!("#!/bin/sh\ntouch '{}'\necho 9999.1\n", marker.display())).unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_rmguard"))
        .args(["--format", "json"])
        .env("HOME", &h)
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("RMGUARD_TEST_SYSTEM_ROOT", h.join("sysroot"))
        .env("NO_COLOR", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env_remove("CLAUDE_CONFIG_DIR")
        .current_dir(&h)
        .output()
        .expect("rmguard runs");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("report json");
    let tool = v["ai_agents_and_tools"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|t| t["name"] == "Junie CLI")
        .unwrap_or_else(|| panic!("no Junie CLI row: {}", v["ai_agents_and_tools"]));
    assert_eq!(tool["version"], "2470.4", "{tool}");
    let hit = v["exposure_findings"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|f| f["name"] == "junie-cli")
        .unwrap_or_else(|| panic!("no junie-cli exposure: {}", v["exposure_findings"]));
    assert_eq!(hit["version"], "2470.4");
    assert!(hit["advisory"].as_str().unwrap().contains("CVE-2026-111091"), "{hit}");
    assert!(!marker.exists(), "junie was started");
    let _ = std::fs::remove_dir_all(&h);
}
