use crate::models::{McpConfig, McpServerDetail};
use crate::platform::PlatformInfo;
use crate::scanners::{is_git_tracked, Scanner};

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

            // Normalize every format to the canonical JSON value so all per-server
            // detections (package identity, inline secrets, transport, launch command)
            // apply uniformly — a hardcoded token in a Codex TOML config is just as
            // committed as one in a Cursor JSON config.
            let canonical = match ext.as_str() {
                "yaml" | "yml" => yaml_to_json(&content),
                "toml" => toml_to_json(&content),
                _ => serde_json::from_str::<serde_json::Value>(&content).ok(),
            };
            let Some(v) = canonical else { continue };
            let server_names = extract_mcp_servers(&v);
            let servers = extract_mcp_server_details(&v);

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
                git_tracked: is_git_tracked(&path),
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
                                git_tracked: is_git_tracked(&mcp_json),
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

/// Extract MCP server names from JSON config (also the canonical form for TOML/YAML
/// configs, which are converted to JSON before extraction — see `toml_to_json`).
pub fn extract_mcp_servers(json: &serde_json::Value) -> Vec<String> {
    let mut names = Vec::new();

    // "mcpServers" is the JSON convention; "mcp_servers" is the TOML (Codex) one.
    for key in ["mcpServers", "mcp_servers"] {
        if let Some(servers) = json.get(key).and_then(|v| v.as_object()) {
            names.extend(servers.keys().cloned());
        }
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
        json.get("mcp_servers").and_then(|v| v.as_object()),
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

    let inline_secret_env_keys = extract_inline_secret_env_keys(cfg.get("env"));

    McpServerDetail {
        name: name.to_string(),
        transport,
        command,
        args,
        package_ecosystem: ecosystem,
        package_name: pkg_name,
        package_version: pkg_version,
        url: sanitized_url,
        inline_secret_env_keys,
    }
}

/// From an MCP server's `env` block, return the NAMES (never values) of secret-looking
/// keys whose value is a hardcoded literal — a credential committed into the config
/// rather than referenced from the environment via `${VAR}`/`$VAR`.
///
/// Preserves the no-secret-leakage guarantee: the value is inspected only to decide
/// whether it is a reference or a literal, and is never stored or emitted.
pub fn extract_inline_secret_env_keys(env: Option<&serde_json::Value>) -> Vec<String> {
    let Some(obj) = env.and_then(|v| v.as_object()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (key, val) in obj {
        let Some(value) = val.as_str() else { continue };
        if crate::scanners::env_files::is_secret_key_name(key) && is_inline_literal(value) {
            out.push(key.clone());
        }
    }
    out.sort();
    out
}

/// True if `value` is a hardcoded literal rather than an env reference or placeholder.
/// `${VAR}`, `$VAR`, `%VAR%`, empty, and obvious placeholders don't count as committed
/// secrets. The value is never stored — only classified.
fn is_inline_literal(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return false;
    }
    // Pure environment reference: "${TOKEN}", "$TOKEN", "%TOKEN%".
    let is_ref = (v.starts_with("${") && v.ends_with('}'))
        || (v.starts_with('$') && v[1..].chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        || (v.starts_with('%') && v.ends_with('%'));
    if is_ref {
        return false;
    }
    // Common "fill me in" placeholders aren't real committed secrets.
    let lower = v.to_ascii_lowercase();
    const PLACEHOLDERS: &[&str] = &[
        "your", "changeme", "change-me", "placeholder", "example", "xxx", "todo", "<", "...",
    ];
    if PLACEHOLDERS.iter().any(|p| lower.starts_with(p)) {
        return false;
    }
    true
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

/// Convert a YAML config to the canonical JSON value so ONE parser handles every
/// format — names, package identity, env inline secrets, transport, the lot.
pub fn yaml_to_json(content: &str) -> Option<serde_json::Value> {
    let yaml_value: serde_yaml_ng::Value = serde_yaml_ng::from_str(content).ok()?;
    serde_json::to_value(&yaml_value).ok()
}

/// Convert a TOML config (Codex `~/.codex/config.toml`) to the canonical JSON value.
pub fn toml_to_json(content: &str) -> Option<serde_json::Value> {
    let table: toml::Table = content.parse().ok()?;
    serde_json::to_value(&table).ok()
}

pub fn extract_mcp_servers_yaml(content: &str) -> Vec<String> {
    yaml_to_json(content)
        .map(|v| extract_mcp_servers(&v))
        .unwrap_or_default()
}

pub fn extract_mcp_servers_toml(content: &str) -> Vec<String> {
    toml_to_json(content)
        .map(|v| extract_mcp_servers(&v))
        .unwrap_or_default()
}

#[cfg(test)]
mod inline_secret_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn flags_hardcoded_secret_values_by_name_only() {
        let env = json!({
            "GITHUB_TOKEN": "ghp_realsecretvalue123",
            "API_KEY": "sk-livekey",
            "LOG_LEVEL": "debug"
        });
        let keys = extract_inline_secret_env_keys(Some(&env));
        // Only secret-looking NAMES with literal values; sorted; value never surfaced.
        assert_eq!(keys, vec!["API_KEY".to_string(), "GITHUB_TOKEN".to_string()]);
    }

    #[test]
    fn ignores_env_references_and_placeholders() {
        let env = json!({
            "GITHUB_TOKEN": "${GITHUB_TOKEN}",
            "API_KEY": "$API_KEY",
            "WIN_SECRET": "%WIN_SECRET%",
            "AUTH_TOKEN": "your-token-here",
            "DB_PASSWORD": ""
        });
        assert!(extract_inline_secret_env_keys(Some(&env)).is_empty());
    }

    #[test]
    fn no_env_block_is_clean() {
        assert!(extract_inline_secret_env_keys(None).is_empty());
        assert!(extract_inline_secret_env_keys(Some(&json!("not-an-object"))).is_empty());
    }

    #[test]
    fn parse_server_detail_populates_inline_secrets() {
        let cfg = json!({
            "command": "npx",
            "args": ["-y", "some-mcp"],
            "env": {"SERVICE_SECRET": "hardcoded", "PORT": "8080"}
        });
        let detail = parse_server_detail("s", &cfg);
        assert_eq!(detail.inline_secret_env_keys, vec!["SERVICE_SECRET".to_string()]);
    }

    /// TOML (Codex) configs go through the same canonical parser, so package
    /// identity AND inline env secrets are extracted — previously TOML got
    /// names only and every per-server detection was silently skipped.
    #[test]
    fn toml_config_gets_full_server_details() {
        let toml = r#"
[mcp_servers.leaky]
command = "npx"
args = ["-y", "some-mcp"]

[mcp_servers.leaky.env]
SLACK_TOKEN = "xoxb-hardcoded"
PORT = "8080"
"#;
        let v = toml_to_json(toml).expect("valid toml converts");
        let details = extract_mcp_server_details(&v);
        assert_eq!(details.len(), 1);
        let d = &details[0];
        assert_eq!(d.name, "leaky");
        assert_eq!(d.package_name.as_deref(), Some("some-mcp"));
        assert_eq!(d.inline_secret_env_keys, vec!["SLACK_TOKEN".to_string()]);
    }

    #[test]
    fn yaml_config_gets_full_server_details() {
        let yaml = r#"
mcpServers:
  fetcher:
    command: uvx
    args: ["mcp-server-fetch"]
    env:
      API_KEY: literal-value
"#;
        let v = yaml_to_json(yaml).expect("valid yaml converts");
        let details = extract_mcp_server_details(&v);
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].inline_secret_env_keys, vec!["API_KEY".to_string()]);
        assert_eq!(details[0].package_name.as_deref(), Some("mcp-server-fetch"));
    }
}
