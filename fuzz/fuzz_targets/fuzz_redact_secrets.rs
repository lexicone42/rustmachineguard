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
        // The credential-helper redactor (literal echo/printf/heredoc arguments) must be
        // total too, and never let a vendor-shaped key through that the base pass caught.
        let helper = rustmachineguard::scanners::redact_helper_command(s);
        assert_eq!(rustmachineguard::scanners::redact_token_shapes(&helper), helper, "a key shape survived");
    }
});
