#![no_main]
//! Fuzzes the untrusted-input surface opened by `--report`: an attacker who can drop
//! a file into the scans directory controls this JSON. Exercise the full path —
//! deserialize a ScanReport, compute findings, and render the fleet HTML — so any
//! panic or hang on adversarial scan files is caught.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(report) = serde_json::from_str::<rustmachineguard::models::ScanReport>(s) {
            let _ = rustmachineguard::analysis::collect_findings(&report);
            let _ = rustmachineguard::output::fleet::render_fleet(&[report]);
        }
    }
});
