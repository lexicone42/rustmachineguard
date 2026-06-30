use crate::models::{McpConfig, McpProbeResult, McpResourceInfo, McpServerInfo, McpToolInfo};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Probe all stdio MCP servers in the given configs.
pub fn probe_mcp_servers(configs: &[McpConfig]) -> Vec<McpProbeResult> {
    let mut results = Vec::new();

    for config in configs {
        for server in &config.servers {
            if server.transport != "stdio" {
                continue;
            }

            let Some(ref cmd) = server.command else {
                continue;
            };

            eprintln!(
                "info: probing MCP server '{}' ({})",
                server.name, cmd
            );

            let result = probe_stdio_server(
                &server.name,
                &config.config_source,
                cmd,
                &server.args,
            );
            results.push(result);
        }
    }

    results
}

fn probe_stdio_server(name: &str, config_source: &str, command: &str, args: &[String]) -> McpProbeResult {
    if command.is_empty() {
        return error_result(name, config_source, "empty command");
    }

    eprintln!(
        "warning: probing MCP server '{}' — this executes: {} {}",
        name,
        command,
        args.join(" ")
    );

    let mut child = match Command::new(command)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return error_result(name, config_source, &format!("spawn failed: {}", e)),
    };

    // Watchdog: kill child if it outlives the probe timeout.
    // Uses AtomicBool to cancel after reap, avoiding PID-reuse races.
    let cancelled = Arc::new(AtomicBool::new(false));
    let child_id = child.id();
    let cancel_flag = cancelled.clone();
    let watchdog = std::thread::spawn(move || {
        std::thread::sleep(PROBE_TIMEOUT);
        if !cancel_flag.load(Ordering::Acquire) {
            #[cfg(unix)]
            unsafe {
                libc::kill(child_id as i32, libc::SIGKILL);
            }
        }
    });

    let mut stdin = match child.stdin.take() {
        Some(s) => s,
        None => {
            let _ = child.kill();
            return error_result(name, config_source, "no stdin");
        }
    };

    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            let _ = child.kill();
            return error_result(name, config_source, "no stdout");
        }
    };

    let mut reader = BufReader::new(stdout);

    // Send initialize
    let init_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "rustmachineguard-probe",
                "version": "0.1.0"
            }
        }
    });

    if let Err(e) = send_message(&mut stdin, &init_req) {
        let _ = child.kill();
        return error_result(name, config_source, &format!("send init failed: {}", e));
    }

    let init_response = match read_response(&mut reader) {
        Ok(r) => r,
        Err(e) => {
            let _ = child.kill();
            return error_result(name, config_source, &format!("init response: {}", e));
        }
    };

    let server_info = extract_server_info(&init_response);

    // Send initialized notification
    let initialized = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    let _ = send_message(&mut stdin, &initialized);

    // Request tools/list
    let tools_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    let _ = send_message(&mut stdin, &tools_req);
    let tools = match read_response(&mut reader) {
        Ok(r) => extract_tools(&r),
        Err(_) => Vec::new(),
    };

    // Request resources/list
    let resources_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "resources/list",
        "params": {}
    });
    let _ = send_message(&mut stdin, &resources_req);
    let resources = match read_response(&mut reader) {
        Ok(r) => extract_resources(&r),
        Err(_) => Vec::new(),
    };

    // Shut down: kill, reap, then cancel watchdog to prevent PID-reuse signal
    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    cancelled.store(true, Ordering::Release);
    let _ = watchdog.join();

    let observed_capabilities = infer_capabilities_from_tools(&tools, &resources);

    McpProbeResult {
        server_name: name.to_string(),
        config_source: config_source.to_string(),
        success: true,
        server_info,
        tools,
        resources,
        error: None,
        observed_capabilities,
    }
}

fn send_message(stdin: &mut impl Write, msg: &serde_json::Value) -> std::io::Result<()> {
    let body = serde_json::to_string(msg)?;
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    stdin.write_all(header.as_bytes())?;
    stdin.write_all(body.as_bytes())?;
    stdin.flush()?;
    Ok(())
}

fn read_response(reader: &mut BufReader<impl std::io::Read>) -> Result<serde_json::Value, String> {
    let start = Instant::now();

    // Read headers to find Content-Length
    let mut content_length: Option<usize> = None;
    loop {
        if start.elapsed() > PROBE_TIMEOUT {
            return Err("timeout reading headers".into());
        }
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => return Err("EOF".into()),
            Ok(_) => {}
            Err(e) => return Err(format!("read error: {}", e)),
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("Content-Length:") {
            if let Ok(len) = rest.trim().parse::<usize>() {
                content_length = Some(len);
            }
        }
    }

    let len = content_length.ok_or("no Content-Length header")?;
    if len > 1_048_576 {
        return Err("response too large".into());
    }

    let mut body = vec![0u8; len];
    let mut read = 0;
    while read < len {
        if start.elapsed() > PROBE_TIMEOUT {
            return Err("timeout reading body".into());
        }
        match std::io::Read::read(reader, &mut body[read..]) {
            Ok(0) => return Err("EOF during body".into()),
            Ok(n) => read += n,
            Err(e) => return Err(format!("read error: {}", e)),
        }
    }

    serde_json::from_slice(&body).map_err(|e| format!("parse error: {}", e))
}

fn extract_server_info(response: &serde_json::Value) -> Option<McpServerInfo> {
    let result = response.get("result")?;
    let info = result.get("serverInfo")?;
    Some(McpServerInfo {
        name: info.get("name")?.as_str()?.to_string(),
        version: info.get("version").and_then(|v| v.as_str()).map(String::from),
    })
}

fn extract_tools(response: &serde_json::Value) -> Vec<McpToolInfo> {
    let tools = response
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array());

    match tools {
        Some(arr) => arr
            .iter()
            .filter_map(|t| {
                Some(McpToolInfo {
                    name: t.get("name")?.as_str()?.to_string(),
                    description: t
                        .get("description")
                        .and_then(|d| d.as_str())
                        .map(String::from),
                })
            })
            .collect(),
        None => Vec::new(),
    }
}

fn extract_resources(response: &serde_json::Value) -> Vec<McpResourceInfo> {
    let resources = response
        .get("result")
        .and_then(|r| r.get("resources"))
        .and_then(|t| t.as_array());

    match resources {
        Some(arr) => arr
            .iter()
            .filter_map(|r| {
                Some(McpResourceInfo {
                    uri: r.get("uri")?.as_str()?.to_string(),
                    name: r.get("name").and_then(|n| n.as_str()).map(String::from),
                    description: r
                        .get("description")
                        .and_then(|d| d.as_str())
                        .map(String::from),
                })
            })
            .collect(),
        None => Vec::new(),
    }
}

fn infer_capabilities_from_tools(
    tools: &[McpToolInfo],
    resources: &[McpResourceInfo],
) -> Vec<String> {
    let mut caps = Vec::new();
    let all_text: String = tools
        .iter()
        .map(|t| {
            format!(
                "{} {}",
                t.name,
                t.description.as_deref().unwrap_or("")
            )
        })
        .chain(resources.iter().map(|r| {
            format!(
                "{} {} {}",
                r.uri,
                r.name.as_deref().unwrap_or(""),
                r.description.as_deref().unwrap_or("")
            )
        }))
        .collect::<Vec<_>>()
        .join(" ");

    let lower = all_text.to_lowercase();

    if lower.contains("file")
        || lower.contains("read")
        || lower.contains("write")
        || lower.contains("directory")
        || lower.contains("path")
    {
        caps.push("filesystem".to_string());
    }

    if lower.contains("http")
        || lower.contains("fetch")
        || lower.contains("request")
        || lower.contains("url")
        || lower.contains("api")
        || lower.contains("webhook")
    {
        caps.push("network".to_string());
    }

    if lower.contains("exec")
        || lower.contains("run")
        || lower.contains("shell")
        || lower.contains("command")
        || lower.contains("terminal")
        || lower.contains("bash")
    {
        caps.push("shell".to_string());
    }

    if lower.contains("env") || lower.contains("secret") || lower.contains("credential") {
        caps.push("environment".to_string());
    }

    if lower.contains("database")
        || lower.contains("query")
        || lower.contains("sql")
        || lower.contains("table")
        || lower.contains("schema")
    {
        caps.push("database".to_string());
    }

    if lower.contains("browser")
        || lower.contains("screenshot")
        || lower.contains("navigate")
        || lower.contains("click")
    {
        caps.push("browser".to_string());
    }

    if lower.contains("git")
        || lower.contains("commit")
        || lower.contains("branch")
        || lower.contains("repository")
    {
        caps.push("source_control".to_string());
    }

    if lower.contains("email")
        || lower.contains("send")
        || lower.contains("message")
        || lower.contains("notification")
    {
        caps.push("communication".to_string());
    }

    caps
}

fn error_result(name: &str, config_source: &str, error: &str) -> McpProbeResult {
    McpProbeResult {
        server_name: name.to_string(),
        config_source: config_source.to_string(),
        success: false,
        server_info: None,
        tools: Vec::new(),
        resources: Vec::new(),
        error: Some(error.to_string()),
        observed_capabilities: Vec::new(),
    }
}
