#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = rustmachineguard::scanners::env_files::parse_env_keys(s);
        for (_, v) in rustmachineguard::scanners::env_files::parse_env_overrides(s) {
            let _ = rustmachineguard::scanners::shell_configs::classify_ollama_host(&v);
        }
        // OLLAMA_HOST readers for shell profiles, systemd units and launchd plists.
        for line in s.lines() {
            let _ = rustmachineguard::scanners::shell_configs::ollama_host_assignment(line);
        }
        let _ = rustmachineguard::scanners::shell_configs::systemd_ollama_host(s);
        let _ = rustmachineguard::scanners::shell_configs::launchd_ollama_host(s);
    }
});
