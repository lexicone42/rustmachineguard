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

            let content = match crate::scanners::read_bounded(&path) {
                Some(c) => c,
                None => continue,
            };

            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();

            let server_names = match ext.as_str() {
                "yaml" | "yml" => extract_mcp_servers_yaml(&content),
                "toml" => extract_mcp_servers_toml(&content),
                _ => {
                    // Default to JSON
                    match serde_json::from_str::<serde_json::Value>(&content) {
                        Ok(v) => extract_mcp_servers(&v),
                        Err(_) => continue,
                    }
                }
            };

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

/// Extract MCP server names from JSON config.
/// Handles multiple formats:
/// - Claude Desktop / Cursor / Claude Code: { "mcpServers": { "name": {...} } }
/// - VS Code: { "mcp": { "servers": { "name": {...} } } }
/// - Zed: { "context_servers": { "name": {...} } }
/// - Claude Code `.claude.json`: { "projects": { path: { "mcpServers": {...} } } }
pub fn extract_mcp_servers(json: &serde_json::Value) -> Vec<String> {
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

    // Zed style: context_servers
    if let Some(servers) = json.get("context_servers").and_then(|v| v.as_object()) {
        names.extend(servers.keys().cloned());
    }

    // Claude Code `~/.claude.json`: projects.{path}.mcpServers
    if let Some(projects) = json.get("projects").and_then(|v| v.as_object()) {
        for (_proj_path, proj_cfg) in projects {
            if let Some(servers) = proj_cfg.get("mcpServers").and_then(|v| v.as_object()) {
                names.extend(servers.keys().cloned());
            }
        }
    }

    names.sort();
    names.dedup();
    names
}

/// Extract MCP server names from YAML config.
/// Open Interpreter format: `mcpServers: { name: {...} }` or `mcp: { servers: {...} }`.
pub fn extract_mcp_servers_yaml(content: &str) -> Vec<String> {
    // Parse YAML into serde_json::Value for unified handling
    let yaml_value: Result<serde_yaml::Value, _> = serde_yaml::from_str(content);
    let Ok(yaml_value) = yaml_value else {
        return Vec::new();
    };
    // Convert to JSON for shared extraction logic
    let json_value: Result<serde_json::Value, _> = serde_json::to_value(&yaml_value);
    match json_value {
        Ok(v) => extract_mcp_servers(&v),
        Err(_) => Vec::new(),
    }
}

/// Extract MCP server names from TOML config (Codex format).
/// Codex uses `[mcp_servers.{name}]` tables or `[mcpServers.{name}]`.
pub fn extract_mcp_servers_toml(content: &str) -> Vec<String> {
    let parsed: Result<toml::Table, _> = content.parse();
    let Ok(table) = parsed else {
        return Vec::new();
    };

    let mut names = Vec::new();

    // Check common top-level keys (both snake_case and camelCase)
    for key in &["mcp_servers", "mcpServers"] {
        if let Some(sub) = table.get(*key).and_then(|v| v.as_table()) {
            names.extend(sub.keys().cloned());
        }
    }

    // Nested under [mcp.servers]
    if let Some(sub) = table
        .get("mcp")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("servers"))
        .and_then(|v| v.as_table())
    {
        names.extend(sub.keys().cloned());
    }

    names.sort();
    names.dedup();
    names
}
