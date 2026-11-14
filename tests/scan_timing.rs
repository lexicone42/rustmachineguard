//! The report's `timing` block: phase rows that tile the run, so a slow run is always
//! attributable. Fails on a0588ce (no `timing`).
#![cfg(unix)]

use std::process::Command;

fn scan(extra: &[&str]) -> (serde_json::Value, String) {
    let home = std::env::temp_dir().join(format!("rmg-timing-{}-{}", std::process::id(), extra.len()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let json = Command::new(env!("CARGO_BIN_EXE_rmguard"))
        .args(["--format", "json"])
        .args(extra)
        .env("HOME", &home)
        .env("PATH", &home)
        .env("NO_COLOR", "1")
        .current_dir(&home)
        .output()
        .expect("run rmguard");
    assert!(json.status.success(), "{}", String::from_utf8_lossy(&json.stderr));
    let verbose = Command::new(env!("CARGO_BIN_EXE_rmguard"))
        .args(["--verbose"])
        .args(extra)
        .env("HOME", &home)
        .env("PATH", &home)
        .env("NO_COLOR", "1")
        .current_dir(&home)
        .output()
        .expect("run rmguard");
    let _ = std::fs::remove_dir_all(&home);
    (
        serde_json::from_slice(&json.stdout).expect("report json"),
        String::from_utf8_lossy(&verbose.stdout).to_string(),
    )
}

#[test]
fn phases_are_the_closed_set_in_order_and_sum_to_the_wall_time() {
    let (v, verbose) = scan(&[]);
    let t = &v["timing"];
    let phases: Vec<(&str, u64)> = t["phases"]
        .as_array()
        .expect("phases")
        .iter()
        .map(|p| (p["phase"].as_str().unwrap(), p["duration_ms"].as_u64().unwrap()))
        .collect();
    let names: Vec<&str> = phases.iter().map(|p| p.0).collect();
    assert_eq!(
        names,
        [
            "setup",
            "device_info",
            "scan",
            "post_scan",
            "catalog_load",
            "exposure",
            "finalize"
        ]
    );
    let wall = t["wall_ms"].as_u64().expect("wall_ms");
    let sum: u64 = phases.iter().map(|p| p.1).sum();
    // Each row is truncated to whole milliseconds, so the sum trails by under 1 ms a row.
    assert!(
        sum <= wall && wall - sum <= phases.len() as u64,
        "sum {sum} wall {wall}"
    );
    #[cfg(target_os = "linux")]
    assert!(t["startup_ms"].as_u64().is_some_and(|ms| ms < 60_000), "{t}");
    // The same rows close the --verbose table.
    assert!(verbose.contains("phase") && verbose.contains("catalog_load") && verbose.contains("total"));
}

#[test]
fn an_extra_search_dir_adds_its_own_phase_row() {
    let extra = std::env::temp_dir().join(format!("rmg-timing-extra-{}", std::process::id()));
    std::fs::create_dir_all(&extra).unwrap();
    let (v, _) = scan(&["--search-dirs", extra.to_str().unwrap()]);
    let _ = std::fs::remove_dir_all(&extra);
    let names: Vec<&str> = v["timing"]["phases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["phase"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"search_dirs"), "{names:?}");
}

#[test]
fn a_report_without_timing_still_loads() {
    let (mut v, _) = scan(&[]);
    v.as_object_mut().unwrap().remove("timing");
    let r: rustmachineguard::models::ScanReport = serde_json::from_value(v).expect("older report loads");
    assert!(r.timing.is_empty());
    // And an empty timing is not written back.
    assert!(serde_json::to_value(&r).unwrap().get("timing").is_none());
}
