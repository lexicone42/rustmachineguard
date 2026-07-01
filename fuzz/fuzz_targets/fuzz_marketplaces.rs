#![no_main]
//! Fuzzes the plugin-marketplace parsers, which navigate untrusted
//! `known_marketplaces.json` / `installed_plugins.json` structures.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
            let counts = rustmachineguard::scanners::marketplaces::plugin_counts(&v);
            let _ = rustmachineguard::scanners::marketplaces::parse_marketplaces(&v, &counts);
        }
    }
});
