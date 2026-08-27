#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
            let _ = rustmachineguard::scanners::agent_settings::extract_hooks(
                &v,
                std::path::Path::new("/p/.claude/settings.json"),
            );
        }
        // The hook-command classifier walks arbitrary command text and resolves
        // referenced paths; it must be total on junk input.
        let _ = rustmachineguard::scanners::agent_settings::classify_hook_command(
            s,
            std::path::Path::new("/p/.claude/settings.json"),
        );
    }
});
