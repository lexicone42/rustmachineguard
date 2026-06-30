#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(catalog) = rustmachineguard::scanners::exposure::ExposureCatalog::load_from_str(s) {
            let server = rustmachineguard::models::McpServerDetail {
                name: "test".into(),
                transport: "stdio".into(),
                command: Some("npx".into()),
                args: vec![],
                package_ecosystem: Some("npm".into()),
                package_name: Some("test-pkg".into()),
                package_version: Some("1.0.0".into()),
                url: None,
            };
            let _ = catalog.check_mcp_server(&server, "/test");
            let _ = catalog.check_extension("vscode", "pub.ext", "1.0.0", "vscode");
        }
    }
});
