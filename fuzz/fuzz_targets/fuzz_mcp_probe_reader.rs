#![no_main]
//! Fuzzes the MCP probe's response reader against adversarial server stdout. A
//! malicious/buggy MCP server controls exactly these bytes; the reader must never
//! panic or hang (it's bounded by MAX_INTERLEAVED, a per-line size cap, and EOF).
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use std::time::{Duration, Instant};

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let deadline = Instant::now() + Duration::from_secs(5);
    let _ = rustmachineguard::scanners::mcp_probe::await_response(&mut cursor, 1, deadline);
});
