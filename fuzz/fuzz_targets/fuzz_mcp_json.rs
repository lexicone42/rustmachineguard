#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
            let _ = rustmachineguard::scanners::mcp::extract_mcp_servers(&v);
            let _ = rustmachineguard::scanners::mcp::extract_mcp_server_details(&v);
        }
        let _ = rustmachineguard::scanners::mcp::extract_mcp_servers_yaml(s);
        let _ = rustmachineguard::scanners::mcp::extract_mcp_servers_toml(s);
    }
});
