#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let first_line = s.lines().next().unwrap_or("");
        let _ = rustmachineguard::scanners::ssh_keys::classify_key(
            first_line,
            s,
            std::path::Path::new("/dev/null"),
        );
    }
});
