#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
            let _ = rustmachineguard::scanners::mcp::extract_mcp_servers(&v);
            let _ = rustmachineguard::scanners::mcp::extract_mcp_server_details(&v);
        }
        // TOML/YAML now normalize to JSON and run the FULL detail parser (package
        // identity, env inline secrets) — fuzz the whole path, including TOML-only
        // types (datetimes) that have unusual JSON serializations.
        if let Some(v) = rustmachineguard::scanners::mcp::yaml_to_json(s) {
            let _ = rustmachineguard::scanners::mcp::extract_mcp_servers(&v);
            let _ = rustmachineguard::scanners::mcp::extract_mcp_server_details(&v);
        }
        if let Some(v) = rustmachineguard::scanners::mcp::toml_to_json(s) {
            let _ = rustmachineguard::scanners::mcp::extract_mcp_servers(&v);
            let _ = rustmachineguard::scanners::mcp::extract_mcp_server_details(&v);
        }
    }
});
