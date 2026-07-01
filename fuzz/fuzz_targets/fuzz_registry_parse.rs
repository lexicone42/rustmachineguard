#![no_main]
//! The MCP registry response is remote JSON (a MITM or compromised registry controls
//! it). parse_entries must never panic on malformed input — only Err.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = rustmachineguard::registry::parse_entries(s);
    }
});
