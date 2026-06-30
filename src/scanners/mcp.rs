use crate::models::{McpConfig, McpServerDetail};
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

            let (server_names, servers) = match ext.as_str() {
                "yaml" | "yml" => {
                    let names = extract_mcp_servers_yaml(&content);
                    (names, Vec::new())
                }
                "toml" => {
                    let names = extract_mcp_servers_toml(&content);
                    (names, Vec::new())
                }
                _ => {
                    match serde_json::from_str::<serde_json::Value>(&content) {
                        Ok(v) => {
                            let names = extract_mcp_servers(&v);
                            let details = extract_mcp_server_details(&v);
                            (names, details)
                        }
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
                servers,
            });
        }

        let claude_json = platform.home_dir().join(".claude.json");
        if claude_json.is_file() {
            if let Some(content) = crate::scanners::read_bounded(&claude_json) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(projects) = v.get("projects").and_then(|v| v.as_object()) {
                        for (proj_path, _) in projects {
                            let mcp_json = std::path::PathBuf::from(proj_path).join(".mcp.json");
                            if !mcp_json.is_file() {
                                continue;
                            }
                            let proj_content = match crate::scanners::read_bounded(&mcp_json) {
                                Some(c) => c,
                                None => continue,
                            };
                            let (server_names, servers) = match serde_json::from_str::<serde_json::Value>(&proj_content) {
                                Ok(pv) => {
                                    let names = extract_mcp_servers(&pv);
                                    let details = extract_mcp_server_details(&pv);
                                    (names, details)
                                }
                                Err(_) => continue,
                            };
                            if server_names.is_empty() {
                                continue;
                            }
                            let server_count = server_names.len();
                            results.push(McpConfig {
                                config_source: format!("Project MCP ({})", proj_path),
                                config_path: mcp_json.display().to_string(),
                                vendor: "Project".to_string(),
                                server_names,
                                server_count,
                                servers,
                            });
                        }
                    }
                }
            }
        }

        results
    }
}

/// Extract MCP server names from JSON config.
pub fn extract_mcp_servers(json: &serde_json::Value) -> Vec<String> {
    let mut names = Vec::new();

    if let Some(servers) = json.get("mcpServers").and_then(|v| v.as_object()) {
        names.extend(servers.keys().cloned());
    }

    if let Some(servers) = json
        .get("mcp")
        .and_then(|v| v.get("servers"))
        .and_then(|v| v.as_object())
    {
        names.extend(servers.keys().cloned());
    }

    if let Some(servers) = json.get("context_servers").and_then(|v| v.as_object()) {
        names.extend(servers.keys().cloned());
    }

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

/// Extract detailed server information including package identity from launcher commands.
pub fn extract_mcp_server_details(json: &serde_json::Value) -> Vec<McpServerDetail> {
    let mut details = Vec::new();

    let server_maps: Vec<&serde_json::Map<String, serde_json::Value>> = [
        json.get("mcpServers").and_then(|v| v.as_object()),
        json.get("mcp").and_then(|v| v.get("servers")).and_then(|v| v.as_object()),
        json.get("context_servers").and_then(|v| v.as_object()),
    ]
    .into_iter()
    .flatten()
    .collect();

    // Also collect project-scoped servers
    if let Some(projects) = json.get("projects").and_then(|v| v.as_object()) {
        for (_, proj_cfg) in projects {
            if let Some(servers) = proj_cfg.get("mcpServers").and_then(|v| v.as_object()) {
                for (name, cfg) in servers {
                    details.push(parse_server_detail(name, cfg));
                }
            }
        }
    }

    for map in server_maps {
        for (name, cfg) in map {
            details.push(parse_server_detail(name, cfg));
        }
    }

    details
}

fn parse_server_detail(name: &str, cfg: &serde_json::Value) -> McpServerDetail {
    let command = cfg.get("command").and_then(|v| v.as_str()).map(|s| s.to_string());
    let args: Vec<String> = cfg
        .get("args")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    // Determine transport type. Prefer an explicit "type"/"transport" field;
    // fall back to structural inference. The MCP spec replaced standalone SSE
    // with "Streamable HTTP" as the default remote transport in the 2025
    // revision, so a url with no explicit type is classified as "http".
    let url = cfg.get("url").and_then(|v| v.as_str()).map(|s| s.to_string());
    let explicit = cfg
        .get("type")
        .or_else(|| cfg.get("transport"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_ascii_lowercase());
    let transport = match explicit.as_deref() {
        Some("stdio") => "stdio".to_string(),
        Some("sse") => "sse".to_string(),
        Some("http" | "streamable-http" | "streamablehttp" | "streamable_http" | "http-stream") => {
            "http".to_string()
        }
        _ if url.is_some() => "http".to_string(),
        _ if command.is_some() => "stdio".to_string(),
        _ => "unknown".to_string(),
    };

    // Sanitize URL (strip credentials, paths, query strings)
    let sanitized_url = url.as_deref().map(sanitize_url);

    // Extract package identity from command + args
    let (ecosystem, pkg_name, pkg_version) = if let Some(ref cmd) = command {
        infer_package_from_command(cmd, &args)
    } else {
        (None, None, None)
    };

    McpServerDetail {
        name: name.to_string(),
        transport,
        command,
        args,
        package_ecosystem: ecosystem,
        package_name: pkg_name,
        package_version: pkg_version,
        url: sanitized_url,
    }
}

/// Infer package ecosystem, name, and version from a launcher command and its args.
pub fn infer_package_from_command(
    command: &str,
    args: &[String],
) -> (Option<String>, Option<String>, Option<String>) {
    let cmd_base = std::path::Path::new(command)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(command);

    match cmd_base {
        "npx" | "bunx" | "pnpx" => parse_npm_launcher(args),
        "uvx" | "pipx" => parse_python_launcher(args),
        "uv" if args.first().is_some_and(|a| a == "run" || a == "tool") => {
            parse_python_launcher(&args[1..])
        }
        "python" | "python3" if args.first().is_some_and(|a| a == "-m") => {
            if let Some(module) = args.get(1) {
                (Some("pypi".to_string()), Some(module.clone()), None)
            } else {
                (None, None, None)
            }
        }
        "docker" | "podman" => parse_docker_launcher(args),
        "node" => {
            if let Some(script) = args.first() {
                (Some("npm".to_string()), Some(script.clone()), None)
            } else {
                (None, None, None)
            }
        }
        _ => (None, None, None),
    }
}

fn parse_npm_launcher(args: &[String]) -> (Option<String>, Option<String>, Option<String>) {
    let mut pkg_arg: Option<&str> = None;
    let mut skip_next = false;
    let mut use_package_flag = false;

    for (i, arg) in args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }

        if arg == "-y" || arg == "--yes" || arg == "-q" || arg == "--quiet" {
            continue;
        }

        if arg == "-p" || arg == "--package" {
            if let Some(next) = args.get(i + 1) {
                pkg_arg = Some(next.as_str());
                use_package_flag = true;
                skip_next = true;
            }
            continue;
        }

        if let Some(val) = arg.strip_prefix("--package=") {
            pkg_arg = Some(val);
            use_package_flag = true;
            continue;
        }

        if arg.starts_with('-') {
            continue;
        }

        if !use_package_flag {
            pkg_arg = Some(arg.as_str());
        }
        break;
    }

    if let Some(pkg) = pkg_arg {
        let (name, version) = split_npm_package_version(pkg);
        (Some("npm".to_string()), Some(name), version)
    } else {
        (None, None, None)
    }
}

fn parse_python_launcher(args: &[String]) -> (Option<String>, Option<String>, Option<String>) {
    for arg in args {
        if arg.starts_with('-') {
            continue;
        }
        // Python package with optional version: package==1.0.0 or package>=1.0
        if let Some(idx) = arg.find("==") {
            return (
                Some("pypi".to_string()),
                Some(arg[..idx].to_string()),
                Some(arg[idx + 2..].to_string()),
            );
        }
        return (Some("pypi".to_string()), Some(arg.clone()), None);
    }
    (None, None, None)
}

fn parse_docker_launcher(args: &[String]) -> (Option<String>, Option<String>, Option<String>) {
    let mut found_run = false;
    for arg in args {
        if arg == "run" {
            found_run = true;
            continue;
        }
        if !found_run {
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        // docker image: registry/name:tag
        let (name, version) = if let Some(idx) = arg.rfind(':') {
            let tag = &arg[idx + 1..];
            if tag.contains('/') {
                (arg.clone(), None)
            } else {
                (arg[..idx].to_string(), Some(tag.to_string()))
            }
        } else {
            (arg.clone(), None)
        };
        return (Some("docker".to_string()), Some(name), version);
    }
    (None, None, None)
}

/// Split an npm package specifier into (name, optional version).
/// Handles scoped packages: @scope/name@1.2.3
pub fn split_npm_package_version(spec: &str) -> (String, Option<String>) {
    if let Some(rest) = spec.strip_prefix('@') {
        // Scoped: @scope/name@version or @scope/name
        if let Some(slash_idx) = rest.find('/') {
            let after_slash = &rest[slash_idx + 1..];
            if let Some(at_idx) = after_slash.find('@') {
                let name = format!("@{}", &rest[..slash_idx + 1 + at_idx]);
                let version = after_slash[at_idx + 1..].to_string();
                return (name, Some(version));
            }
            return (spec.to_string(), None);
        }
        return (spec.to_string(), None);
    }
    // Unscoped: name@version or name
    if let Some(at_idx) = spec.find('@') {
        let name = spec[..at_idx].to_string();
        let version = spec[at_idx + 1..].to_string();
        (name, Some(version))
    } else {
        (spec.to_string(), None)
    }
}

/// Sanitize a URL by stripping credentials, paths beyond the host, and query strings.
fn sanitize_url(url: &str) -> String {
    // Strip userinfo
    if let Some(scheme_end) = url.find("://") {
        let after_scheme = &url[scheme_end + 3..];
        let host_part = if let Some(at_idx) = after_scheme.find('@') {
            &after_scheme[at_idx + 1..]
        } else {
            after_scheme
        };
        // Strip path and query
        let host = host_part
            .split('/')
            .next()
            .unwrap_or(host_part)
            .split('?')
            .next()
            .unwrap_or(host_part);
        format!("{}://{}", &url[..scheme_end], host)
    } else {
        url.to_string()
    }
}

pub fn extract_mcp_servers_yaml(content: &str) -> Vec<String> {
    let yaml_value: Result<serde_yaml_ng::Value, _> = serde_yaml_ng::from_str(content);
    let Ok(yaml_value) = yaml_value else {
        return Vec::new();
    };
    let json_value: Result<serde_json::Value, _> = serde_json::to_value(&yaml_value);
    match json_value {
        Ok(v) => extract_mcp_servers(&v),
        Err(_) => Vec::new(),
    }
}

pub fn extract_mcp_servers_toml(content: &str) -> Vec<String> {
    let parsed: Result<toml::Table, _> = content.parse();
    let Ok(table) = parsed else {
        return Vec::new();
    };

    let mut names = Vec::new();

    for key in &["mcp_servers", "mcpServers"] {
        if let Some(sub) = table.get(*key).and_then(|v| v.as_table()) {
            names.extend(sub.keys().cloned());
        }
    }

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
