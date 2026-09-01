#![no_main]
use libfuzzer_sys::fuzz_target;

// redact_secrets_in_text runs over every command line, registry URL and config value
// that reaches a report. It must be total on arbitrary text, and idempotent: a redacted
// report fed back through the tool must not change again.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let once = rustmachineguard::scanners::redact_secrets_in_text(s);
        let twice = rustmachineguard::scanners::redact_secrets_in_text(&once);
        assert_eq!(once, twice, "redaction not idempotent");
    }
});
