use crate::models::McpConfig;
use crate::platform::PlatformInfo;
use crate::scanners::Scanner;

pub struct McpScanner;

impl Scanner for McpScanner {
    type Output = Vec<McpConfig>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<McpConfig> {
        let mut results = Vec::new();

        for (source, path, vendor) in platform.mcp_config_paths() {
            if !path.is_file() {
                continue;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let json: serde_json::Value = match serde_json::from_str(&content) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Extract MCP server names from various config formats
            let server_names = extract_mcp_servers(&json);
            if server_names.is_empty() {
                continue;
            }

            let server_count = server_names.len();
            results.push(McpConfig {
                config_source: source,
                config_path: path.display().to_string(),
                vendor,
                server_names,
                server_count,
            });
        }

        results
    }
}

/// Extract MCP server names from config JSON.
/// Handles multiple formats:
/// - Claude Desktop: { "mcpServers": { "name": {...} } }
/// - Cursor: { "mcpServers": { "name": {...} } }
/// - VS Code: { "mcp": { "servers": { "name": {...} } } }  (or mcpServers at top level)
/// - Claude Code: { "mcpServers": { ... } } or projects with mcpServers
fn extract_mcp_servers(json: &serde_json::Value) -> Vec<String> {
    let mut names = Vec::new();

    // Direct mcpServers key
    if let Some(servers) = json.get("mcpServers").and_then(|v| v.as_object()) {
        names.extend(servers.keys().cloned());
    }

    // VS Code style: mcp.servers
    if let Some(servers) = json
        .get("mcp")
        .and_then(|v| v.get("servers"))
        .and_then(|v| v.as_object())
    {
        names.extend(servers.keys().cloned());
    }

    // Zed style: nested in context_servers or language_models
    if let Some(servers) = json.get("context_servers").and_then(|v| v.as_object()) {
        names.extend(servers.keys().cloned());
    }

    names.sort();
    names.dedup();
    names
}
