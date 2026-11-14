#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(head) = rustmachineguard::scanners::ssh_keys::read_key_head_from(data) {
        let _ = rustmachineguard::scanners::ssh_keys::classify_key(&head.first_line, &head.next);
    }
    if let Ok(s) = std::str::from_utf8(data) {
        let (first, next) = s.split_once('\n').unwrap_or((s, ""));
        let _ = rustmachineguard::scanners::ssh_keys::classify_key(first, next);
    }
});
