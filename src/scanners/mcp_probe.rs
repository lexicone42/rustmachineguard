use crate::models::{McpConfig, McpProbeResult, McpResourceInfo, McpServerInfo, McpToolInfo};
use std::io::{BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

// JSON-RPC request ids for each phase of the handshake.
const ID_DISCOVER: u64 = 0;
const ID_INITIALIZE: u64 = 1;
const ID_TOOLS: u64 = 2;
const ID_RESOURCES: u64 = 3;

/// The modern protocol revision we announce. MCP revision 2026-07-28 removed the
/// `initialize` handshake: version, identity and capabilities are now per-request
/// `_meta` instead of session state.
const MODERN_PROTOCOL_VERSION: &str = "2026-07-28";

/// How long to wait for the `server/discover` probe before concluding the server is
/// legacy. Deliberately a fraction of PROBE_TIMEOUT: the spec says a silent server is
/// legacy, and we must leave budget for the `initialize` fallback that follows.
const DISCOVER_TIMEOUT: Duration = Duration::from_secs(3);

/// MCP error codes reserved by the spec (-32020..-32099). Receiving ANY of these
/// identifies a modern server, so we must not fall back to `initialize`.
fn is_modern_error_code(code: i64) -> bool {
    (-32099..=-32020).contains(&code)
}

/// Which protocol era a server speaks. Determined by probing, never assumed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ServerEra {
    /// Revision 2026-07-28+: per-request `_meta`, no handshake.
    Modern,
    /// Revision 2025-11-25 and earlier: requires the `initialize` handshake.
    Legacy,
}

/// The `_meta` block every modern request must carry. `protocolVersion` and
/// `clientCapabilities` are REQUIRED — a request missing either is malformed and the
/// server must reject it with -32602.
fn modern_meta() -> serde_json::Value {
    serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {
            "name": "rustmachineguard-probe", "version": "0.1.0"
        }
    })
}

/// Classify the `server/discover` probe result into a protocol era.
///
/// Per the stdio binding's backward-compatibility rules, the fallback MUST NOT be
/// keyed to one specific error code: legacy servers answer an unknown pre-`initialize`
/// method with implementation-defined errors (commonly -32601 or -32602) or not at all.
/// So: a result means modern; a spec-reserved error code means modern (do not fall
/// back); anything else means legacy.
pub fn classify_discover_response(response: &serde_json::Value) -> ServerEra {
    if response.get("result").is_some() {
        return ServerEra::Modern;
    }
    if let Some(code) = response.get("error").and_then(|e| e.get("code")).and_then(|c| c.as_i64())
        && is_modern_error_code(code)
    {
        return ServerEra::Modern;
    }
    ServerEra::Legacy
}

/// Max size of a single newline-delimited message (a hostile server could otherwise
/// send an unbounded line and OOM the probe).
const MAX_MESSAGE_BYTES: usize = 1_048_576;
/// Max messages to read while waiting for one response — bounds a server that spams
/// notifications instead of answering.
const MAX_INTERLEAVED: usize = 64;

/// Interruptible watchdog that SIGKILLs a child process if the probe outlives
/// PROBE_TIMEOUT. Cancellation is signalled via a Condvar so the watchdog thread
/// wakes immediately on the success path instead of sleeping the full timeout.
/// RAII: Drop cancels and joins, so every early-return path cleans up.
struct Watchdog {
    // (cancelled, child-already-reaped) guarded together; Condvar wakes the thread.
    state: Arc<(Mutex<bool>, Condvar)>,
    handle: Option<JoinHandle<()>>,
}

impl Watchdog {
    fn spawn(child: &Child) -> Self {
        let state = Arc::new((Mutex::new(false), Condvar::new()));
        let child_id = child.id();
        let thread_state = state.clone();
        let handle = std::thread::spawn(move || {
            let (lock, cvar) = &*thread_state;
            let guard = lock.lock().unwrap();
            // Wait until cancelled or the timeout elapses.
            let (guard, timed_out) = cvar
                .wait_timeout_while(guard, PROBE_TIMEOUT, |cancelled| !*cancelled)
                .unwrap();
            // Only kill if we genuinely timed out (still not cancelled). The lock is
            // held across the kill so the reaper cannot mark-reaped concurrently —
            // this serializes the check-and-kill against the cancel path.
            if timed_out.timed_out() && !*guard {
                #[cfg(unix)]
                unsafe {
                    libc::kill(child_id as i32, libc::SIGKILL);
                }
            }
        });
        Watchdog {
            state,
            handle: Some(handle),
        }
    }

    /// Cancel the watchdog (after the child has been reaped) and join its thread.
    fn cancel(&mut self) {
        let (lock, cvar) = &*self.state;
        {
            let mut cancelled = lock.lock().unwrap();
            *cancelled = true;
        }
        cvar.notify_all();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.cancel();
    }
}

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

/// Successful probe payload (server info + enumerated tools/resources).
struct ProbeData {
    server_info: Option<McpServerInfo>,
    tools: Vec<McpToolInfo>,
    resources: Vec<McpResourceInfo>,
    /// The server's free-text `instructions`, which the host splices into the model's
    /// system prompt — the highest-leverage injection carrier MCP offers, and one we
    /// previously never read.
    instructions: Option<String>,
    era: ServerEra,
}

/// Probe one stdio server directly. Exposed so tests can point the real probe at a
/// fake server and assert end-to-end behaviour (era detection, instructions capture)
/// rather than only unit-testing the pure classifier.
pub fn probe_server_for_test(
    name: &str,
    config_source: &str,
    command: &str,
    args: &[String],
) -> McpProbeResult {
    probe_stdio_server(name, config_source, command, args)
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

    // Watchdog kills the child if the protocol exchange exceeds PROBE_TIMEOUT.
    let mut watchdog = Watchdog::spawn(&child);

    // Run the protocol exchange; cleanup happens exactly once below regardless of outcome.
    let outcome = run_probe_protocol(&mut child);

    // Cancel the watchdog (sets flag + joins) BEFORE reaping the child, so the
    // watchdog can never signal a PID that has been reaped and possibly reused.
    watchdog.cancel();
    let _ = child.kill();
    let _ = child.wait();

    match outcome {
        Ok(data) => {
            let observed_capabilities =
                infer_capabilities_from_tools(&data.tools, &data.resources);
            McpProbeResult {
                server_name: name.to_string(),
                config_source: config_source.to_string(),
                success: true,
                server_info: data.server_info,
                tools: data.tools,
                resources: data.resources,
                error: None,
                observed_capabilities,
                instructions: data.instructions,
                protocol_era: Some(
                    match data.era {
                        ServerEra::Modern => "modern",
                        ServerEra::Legacy => "legacy",
                    }
                    .to_string(),
                ),
            }
        }
        Err(e) => error_result(name, config_source, &e),
    }
}

/// Perform the MCP JSON-RPC handshake and enumerate tools/resources.
/// Returns an error string if the handshake fails; tools/resources are
/// best-effort (an empty list on per-request failure, not a hard error).
fn run_probe_protocol(child: &mut Child) -> Result<ProbeData, String> {
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let mut reader = BufReader::new(stdout);

    // The stdio probe is a small state machine over newline-delimited JSON-RPC
    // (per the MCP spec, stdio messages are newline-delimited, NOT Content-Length
    // framed). Phases: Initialize -> (initialized notification) -> ListTools ->
    // ListResources. `await_response` matches replies by JSON-RPC id and skips any
    // interleaved notifications / log lines a server may emit, so the reader can't
    // desync if a response doesn't arrive as the very next message.
    let deadline = Instant::now() + PROBE_TIMEOUT;

    // Phase 0: era detection. MCP revision 2026-07-28 REMOVED the `initialize`
    // handshake, and servers must implement `server/discover`. Sending `initialize`
    // first to a modern server gets an implementation-defined rejection, which used to
    // abort the probe and report the server as clean — the worst outcome for a posture
    // tool. So probe with `server/discover` first and fall back only on a non-modern
    // error or silence, exactly as the stdio binding prescribes.
    let discover_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": ID_DISCOVER,
        "method": "server/discover",
        "params": { "_meta": modern_meta() }
    });
    send_message(&mut stdin, &discover_req)
        .map_err(|e| format!("send server/discover failed: {}", e))?;
    let discover_deadline = Instant::now() + DISCOVER_TIMEOUT.min(PROBE_TIMEOUT);
    let discover = await_response(&mut reader, ID_DISCOVER, discover_deadline);
    // No response at all (or a read error) means legacy, per the spec's timeout rule.
    let era = discover
        .as_ref()
        .map(classify_discover_response)
        .unwrap_or(ServerEra::Legacy);

    let mut server_info = discover.as_ref().ok().and_then(extract_server_info);
    let mut instructions = discover.as_ref().ok().and_then(extract_instructions);

    if era == ServerEra::Legacy {
        // Phase 1 (legacy only): initialize handshake.
        let init_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": ID_INITIALIZE,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "rustmachineguard-probe", "version": "0.1.0" }
            }
        });
        send_message(&mut stdin, &init_req).map_err(|e| format!("send init failed: {}", e))?;
        let init_response = await_response(&mut reader, ID_INITIALIZE, deadline)
            .map_err(|e| format!("init response: {}", e))?;
        server_info = extract_server_info(&init_response);
        instructions = extract_instructions(&init_response);

        // The client must acknowledge initialization before issuing requests.
        let initialized = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        let _ = send_message(&mut stdin, &initialized);
    }

    // Modern requests must carry `_meta`; legacy ones must not (it would be ignored,
    // but keeping them clean avoids confusing older servers).
    let params = |era: ServerEra| -> serde_json::Value {
        match era {
            ServerEra::Modern => serde_json::json!({ "_meta": modern_meta() }),
            ServerEra::Legacy => serde_json::json!({}),
        }
    };

    // Phase 2: tools/list (best-effort — a missing/failed list yields none).
    let tools_req = serde_json::json!({
        "jsonrpc": "2.0", "id": ID_TOOLS, "method": "tools/list", "params": params(era)
    });
    let _ = send_message(&mut stdin, &tools_req);
    let tools = await_response(&mut reader, ID_TOOLS, deadline)
        .map(|r| extract_tools(&r))
        .unwrap_or_default();

    // Phase 3: resources/list (best-effort).
    let resources_req = serde_json::json!({
        "jsonrpc": "2.0", "id": ID_RESOURCES, "method": "resources/list", "params": params(era)
    });
    let _ = send_message(&mut stdin, &resources_req);
    let resources = await_response(&mut reader, ID_RESOURCES, deadline)
        .map(|r| extract_resources(&r))
        .unwrap_or_default();

    drop(stdin);

    Ok(ProbeData {
        server_info,
        tools,
        resources,
        instructions,
        era,
    })
}

/// Send one MCP message as newline-delimited JSON (the stdio transport framing).
fn send_message(stdin: &mut impl Write, msg: &serde_json::Value) -> std::io::Result<()> {
    let body = serde_json::to_string(msg)?;
    stdin.write_all(body.as_bytes())?;
    stdin.write_all(b"\n")?;
    stdin.flush()?;
    Ok(())
}

/// Read messages until the JSON-RPC response with `expected_id` arrives, skipping
/// interleaved notifications, server->client requests, and unrelated/unparseable
/// lines. Bounded by `deadline` and `MAX_INTERLEAVED`. Reads adversarial MCP-server
/// stdout, so it's exposed for fuzzing.
pub fn await_response(
    reader: &mut impl Read,
    expected_id: u64,
    deadline: Instant,
) -> Result<serde_json::Value, String> {
    for _ in 0..MAX_INTERLEAVED {
        if Instant::now() >= deadline {
            return Err("timeout".into());
        }
        let line = match read_line_bounded(reader, MAX_MESSAGE_BYTES)? {
            Some(bytes) => bytes,
            None => return Err("connection closed".into()),
        };
        // Skip blank / non-JSON lines (a spec-violating server logging to stdout).
        let Ok(msg) = serde_json::from_slice::<serde_json::Value>(&line) else {
            continue;
        };
        // A response carries result|error and the id we asked for. Everything else
        // (notifications, server requests, other ids) is skipped — this is what keeps
        // the reader from desyncing on interleaved traffic.
        let is_response = msg.get("result").is_some() || msg.get("error").is_some();
        if is_response && msg.get("id").and_then(|v| v.as_u64()) == Some(expected_id) {
            return Ok(msg);
        }
    }
    Err(format!(
        "no response to request {} within {} messages",
        expected_id, MAX_INTERLEAVED
    ))
}

/// Read one newline-delimited line (without the trailing newline), bounded to `max`
/// bytes. Returns `Ok(None)` on EOF with no data. Strips a trailing `\r` so CRLF is
/// tolerated even though MCP uses `\n`.
fn read_line_bounded(reader: &mut impl Read, max: usize) -> Result<Option<Vec<u8>>, String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => {
                return Ok(if buf.is_empty() { None } else { Some(buf) });
            }
            Ok(_) => {
                if byte[0] == b'\n' {
                    if buf.last() == Some(&b'\r') {
                        buf.pop();
                    }
                    return Ok(Some(buf));
                }
                buf.push(byte[0]);
                if buf.len() > max {
                    return Err("message exceeds size limit".into());
                }
            }
            Err(e) => return Err(format!("read error: {}", e)),
        }
    }
}

/// Pull the server's `instructions` string out of a discover/initialize result.
fn extract_instructions(response: &serde_json::Value) -> Option<String> {
    response
        .get("result")?
        .get("instructions")?
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .map(String::from)
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
                    // Capture the parameter schema so rug-pull diffing can detect
                    // mutated parameters and injection hidden in param descriptions.
                    input_schema: t.get("inputSchema").cloned(),
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
        instructions: None,
        protocol_era: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn far_deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    #[test]
    fn await_response_matches_by_id() {
        let stream = "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}\n";
        let mut r = Cursor::new(stream.as_bytes());
        let resp = await_response(&mut r, ID_TOOLS, far_deadline()).unwrap();
        assert!(resp.get("result").is_some());
    }

    #[test]
    fn await_response_skips_interleaved_notification() {
        // A server logs a notification BEFORE answering — the old linear reader would
        // have mistaken this for the response and returned nothing useful.
        let stream = concat!(
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"info\"}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"serverInfo\":{\"name\":\"srv\"}}}\n"
        );
        let mut r = Cursor::new(stream.as_bytes());
        let resp = await_response(&mut r, ID_INITIALIZE, far_deadline()).unwrap();
        assert_eq!(resp["result"]["serverInfo"]["name"], "srv");
    }

    #[test]
    fn await_response_skips_wrong_id_and_noise() {
        // A stray non-JSON log line + a response to a different id, then ours.
        let stream = concat!(
            "not json at all\n",
            "{\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"resources\":[]}}\n"
        );
        let mut r = Cursor::new(stream.as_bytes());
        let resp = await_response(&mut r, ID_RESOURCES, far_deadline()).unwrap();
        assert!(resp.get("result").is_some());
        assert_eq!(resp["id"], 3);
    }

    #[test]
    fn await_response_errors_on_eof() {
        let mut r = Cursor::new(&b""[..]);
        assert!(await_response(&mut r, ID_TOOLS, far_deadline()).is_err());
    }

    #[test]
    fn await_response_bounded_against_notification_flood() {
        // A server that only ever sends notifications must not hang the reader forever.
        let flood = "{\"jsonrpc\":\"2.0\",\"method\":\"x\"}\n".repeat(1000);
        let mut r = Cursor::new(flood.into_bytes());
        assert!(await_response(&mut r, ID_TOOLS, far_deadline()).is_err());
    }

    #[test]
    fn read_line_bounded_handles_crlf_and_eof() {
        let mut r = Cursor::new(&b"hello\r\nworld"[..]);
        assert_eq!(read_line_bounded(&mut r, 1024).unwrap(), Some(b"hello".to_vec()));
        assert_eq!(read_line_bounded(&mut r, 1024).unwrap(), Some(b"world".to_vec()));
        assert_eq!(read_line_bounded(&mut r, 1024).unwrap(), None);
    }

    #[test]
    fn read_line_bounded_rejects_oversized_line() {
        let huge = vec![b'a'; 2048];
        let mut r = Cursor::new(huge);
        assert!(read_line_bounded(&mut r, 1024).is_err());
    }
}
