#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = rustmachineguard::scanners::rules_files::check_dangerous_patterns(s);
        // Skill dynamic-context extraction and allowed-tools parsing read the same
        // untrusted skill text.
        let _ = rustmachineguard::scanners::skills::extract_dynamic_commands(s);
        let _ = rustmachineguard::scanners::skills::parse_allowed_tools(s);
        if let Some(fm) = rustmachineguard::scanners::skills::frontmatter(s) {
            let _ = rustmachineguard::scanners::skills::parse_allowed_tools(fm);
        }
    }
});
