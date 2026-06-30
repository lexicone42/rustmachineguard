#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
            let _ = rustmachineguard::diff::diff_reports(&v, &v);
            let empty = serde_json::json!({});
            let _ = rustmachineguard::diff::diff_reports(&empty, &v);
            let _ = rustmachineguard::diff::diff_reports(&v, &empty);
        }
    }
});
