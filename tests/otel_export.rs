//! End-to-end proof of the OpenTelemetry contract (docs/OPENTELEMETRY.md):
//!
//! * a default run opens no socket, even with every OTEL_* endpoint variable set;
//! * `--otel` exports spans and metrics whose numbers equal the JSON diagnostics;
//! * nothing scan-derived (names, commands, args, env values, paths) is exported;
//! * a dead or black-holed collector costs at most ~2 s and never changes the report
//!   or the exit code;
//! * OTEL_SDK_DISABLED wins over the flag, and `--fail-on` still flushes first;
//! * no child process rmguard runs (probed MCP servers, `--version` probes, pgrep, git)
//!   inherits an `OTEL_*` variable, so a collector API key in OTEL_EXPORTER_OTLP_HEADERS
//!   never reaches a config-authored command;
//! * a loopback collector is reached directly even when a proxy variable is set.
//!
//! Every child gets a cleared environment (HOME = a temp dir, PATH=/usr/bin:/bin) so no
//! tool it runs can talk to the test port and nothing from the developer's own shell
//! (OTEL_* variables included) leaks in.

#![cfg(unix)]

use std::io::ErrorKind;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

/// A fresh, empty HOME. The name carries the E2EOTEL marker, so a leaked path is caught
/// by the same substring check as every other canary.
fn temp_home(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rmg-E2EOTELDIR-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Scanners that run `--version` on whatever is on PATH. Skipped in the timing tests so
/// the wall-time comparison measures export cost, not the host's toolchain.
const SLOW_SKIP: &str = "ai,frameworks,ide,node,containers,notebooks";

fn rmguard(home: &Path, endpoint_port: Option<u16>, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rmguard"));
    cmd.env_clear().env("HOME", home).env("PATH", "/usr/bin:/bin").args(args);
    if let Some(port) = endpoint_port {
        let base = format!("http://127.0.0.1:{port}");
        cmd.env("OTEL_EXPORTER_OTLP_ENDPOINT", &base)
            .env("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", format!("{base}/v1/traces"))
            .env("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", format!("{base}/v1/metrics"));
    }
    cmd
}

fn run(mut cmd: Command) -> (Output, Duration) {
    let t = Instant::now();
    let out = cmd.output().expect("run rmguard");
    (out, t.elapsed())
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!("stdout is not JSON ({e}); stderr:\n{}", stderr(out))
    })
}

/// Nothing connected, not even a completed handshake waiting in the backlog.
fn assert_never_connected(listener: &TcpListener) {
    listener.set_nonblocking(true).unwrap();
    match listener.accept() {
        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
        Ok((_, peer)) => panic!("something connected to the collector port from {peer}"),
        Err(e) => panic!("unexpected accept error: {e}"),
    }
}

#[test]
fn help_documents_otel_flag() {
    let out = Command::new(env!("CARGO_BIN_EXE_rmguard")).arg("--help").output().unwrap();
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("--otel"), "{help}");
    assert!(help.contains("OTEL_EXPORTER_OTLP_ENDPOINT"), "{help}");
    assert!(
        help.contains("OTEL_EXPORTER_OTLP_ENDPOINT alone never enables export"),
        "--help must say the env var alone never enables export:\n{help}"
    );
}

#[test]
fn default_run_never_connects_even_with_otel_env() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let home = temp_home("default");
    let (out, _) = run(rmguard(&home, Some(port), &["--format", "json"]));
    assert!(out.status.success(), "exit {:?}; stderr:\n{}", out.status, stderr(&out));
    json(&out);
    assert!(
        !stderr(&out).lines().any(|l| l.contains("OpenTelemetry")),
        "a default run said something about OpenTelemetry:\n{}",
        stderr(&out)
    );
    assert_never_connected(&listener);
    let _ = std::fs::remove_dir_all(&home);
}

/// The reviewer's reproduction, generalized: a hostile MCP server command plus a fake
/// tool on PATH under the names rmguard runs (`ghcs` for the Copilot CLI's verify and
/// `--version` probes, `tabby` to trigger `pgrep`, `pgrep` and `git` themselves). Each
/// one dumps its environment. With OTEL_EXPORTER_OTLP_HEADERS holding a canary API key,
/// no dump may contain any OTEL_ variable, with or without `--otel`.
#[test]
fn children_never_inherit_otel_env() {
    use std::os::unix::fs::PermissionsExt;
    for (tag, with_otel) in [("childenv-default", false), ("childenv-otel", true)] {
        let home = temp_home(tag);
        let bin = home.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let dump = home.join("child_env.txt");
        let probe_dump = home.join("probe_env.txt");
        let recorder = format!(
            "#!/bin/sh\n{{ echo \"ARGV0=$(basename \"$0\")\"; env; }} >> '{}'\necho \"$(basename \"$0\") 1.2.3\"\nexit 0\n",
            dump.display()
        );
        for name in ["ghcs", "tabby", "pgrep", "git"] {
            let f = bin.join(name);
            std::fs::write(&f, &recorder).unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let claude = serde_json::json!({
            "mcpServers": {
                "leak": {
                    "command": "/bin/sh",
                    "args": ["-c", format!("env > '{}'", probe_dump.display())]
                }
            }
        });
        std::fs::write(home.join(".claude.json"), claude.to_string()).unwrap();
        std::fs::write(home.join(".gitconfig"), "[user]\n\tname = x\n").unwrap();

        let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let mut args = vec!["--probe-mcp", "--format", "json"];
        if with_otel {
            args.insert(0, "--otel");
        }
        let mut cmd = rmguard(&home, Some(closed), &args);
        cmd.env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("OTEL_EXPORTER_OTLP_HEADERS", "authorization=Bearer E2EOTELHEADERKEY")
            .env("OTEL_EXPORTER_OTLP_TRACES_HEADERS", "x-api-key=E2EOTELHEADERKEY")
            .env("OTEL_RESOURCE_ATTRIBUTES", "team=E2EOTELHEADERKEY")
            .env("otel_lowercase_too", "E2EOTELHEADERKEY");
        let (out, _) = run(cmd);
        assert!(out.status.success(), "{tag}: exit {:?}; stderr:\n{}", out.status, stderr(&out));
        json(&out);

        let probe_env = std::fs::read_to_string(&probe_dump)
            .unwrap_or_else(|e| panic!("{tag}: the probed server did not run ({e}); stderr:\n{}", stderr(&out)));
        let child_env = std::fs::read_to_string(&dump)
            .unwrap_or_else(|e| panic!("{tag}: no fake tool ran ({e}); stderr:\n{}", stderr(&out)));
        // Positive controls: the dumps are real environments from the sites under test.
        assert!(probe_env.contains("HOME="), "{tag}: {probe_env}");
        for site in ["ARGV0=ghcs", "ARGV0=pgrep"] {
            assert!(child_env.contains(site), "{tag}: {site} never ran:\n{child_env}");
        }
        for (what, text) in [("probed MCP server", &probe_env), ("--version/pgrep/git child", &child_env)] {
            assert!(!text.contains("E2EOTELHEADERKEY"), "{tag}: the collector key reached a {what}:\n{text}");
            assert!(
                !text.lines().any(|l| l.to_ascii_uppercase().starts_with("OTEL_")),
                "{tag}: an OTEL_ variable reached a {what}:\n{text}"
            );
        }
        let _ = std::fs::remove_dir_all(&home);
    }
}

/// Every child process goes through `scanners::child_command`, which scrubs `OTEL_*`.
/// A new `Command::new` anywhere else in src/ would bypass it.
#[test]
fn no_bare_command_new_outside_child_command() {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
    assert!(files.len() > 20, "src/ not found");
    let mut allowed = 0;
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        for (i, line) in text.lines().enumerate() {
            if !line.contains("Command::new(") {
                continue;
            }
            if f.ends_with("src/scanners/mod.rs") && line.trim() == "let mut cmd = std::process::Command::new(program);" {
                allowed += 1;
                continue;
            }
            panic!(
                "{}:{}: spawn through crate::scanners::child_command, not Command::new: {line}",
                f.display(),
                i + 1
            );
        }
    }
    assert_eq!(allowed, 1, "child_command itself not found");
}

#[cfg(not(feature = "otel"))]
#[test]
fn otel_flag_without_feature_warns() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let home = temp_home("nofeature");
    let (out, _) = run(rmguard(&home, Some(port), &["--otel", "--format", "json", "--skip", SLOW_SKIP]));
    assert!(out.status.success(), "exit {:?}", out.status);
    json(&out);
    let n = stderr(&out).lines().filter(|l| l.contains("built without the `otel` feature")).count();
    assert_eq!(n, 1, "{}", stderr(&out));
    assert_never_connected(&listener);
    let _ = std::fs::remove_dir_all(&home);
}

#[cfg(feature = "otel")]
mod enabled {
    use super::*;
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
    use opentelemetry_proto::tonic::trace::v1::{Span, status::StatusCode};
    use prost::Message;
    use std::collections::{BTreeSet, HashMap};
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// Received (request path, body) pairs.
    type Bodies = Vec<(String, Vec<u8>)>;

    /// A minimal OTLP/HTTP collector: HTTP/1.1 with keep-alive and several requests per
    /// connection; answers 200 with an empty body; keeps (path, body).
    struct Collector {
        port: u16,
        got: Arc<Mutex<Bodies>>,
        /// The User-Agent header of every request.
        agents: Arc<Mutex<Vec<String>>>,
        stop: Arc<AtomicBool>,
        live: Arc<AtomicUsize>,
        accept: Option<std::thread::JoinHandle<()>>,
    }

    impl Collector {
        fn start() -> Collector {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            listener.set_nonblocking(true).unwrap();
            let got = Arc::new(Mutex::new(Vec::new()));
            let agents = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let live = Arc::new(AtomicUsize::new(0));
            let (g, a, s, l) = (got.clone(), agents.clone(), stop.clone(), live.clone());
            let accept = std::thread::spawn(move || {
                while !s.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let (g, a, l) = (g.clone(), a.clone(), l.clone());
                            l.fetch_add(1, Ordering::SeqCst);
                            std::thread::spawn(move || {
                                serve(stream, &g, &a);
                                l.fetch_sub(1, Ordering::SeqCst);
                            });
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(5)),
                    }
                }
            });
            Collector { port, got, agents, stop, live, accept: Some(accept) }
        }

        /// Stop accepting and wait (at most 5 s) for open connections to drain.
        fn finish(mut self) -> Vec<(String, Vec<u8>)> {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(h) = self.accept.take() {
                let _ = h.join();
            }
            let t = Instant::now();
            while self.live.load(Ordering::SeqCst) > 0 && t.elapsed() < Duration::from_secs(5) {
                std::thread::sleep(Duration::from_millis(10));
            }
            std::mem::take(&mut *self.got.lock().unwrap())
        }
    }

    fn serve(mut s: std::net::TcpStream, got: &Mutex<Bodies>, agents: &Mutex<Vec<String>>) {
        let _ = s.set_nonblocking(false);
        let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
        let mut buf: Vec<u8> = Vec::new();
        let mut tmp = [0u8; 16384];
        loop {
            let head_end = loop {
                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break p;
                }
                match s.read(&mut tmp) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
            let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
            let len: usize = head
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.trim().eq_ignore_ascii_case("content-length").then(|| v.trim().parse().ok())?
                })
                .unwrap_or(0);
            let ua = head.lines().find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim().eq_ignore_ascii_case("user-agent").then(|| v.trim().to_string())
            });
            agents.lock().unwrap().push(ua.unwrap_or_default());
            let total = head_end + 4 + len;
            while buf.len() < total {
                match s.read(&mut tmp) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            }
            got.lock().unwrap().push((path, buf[head_end + 4..total].to_vec()));
            buf.drain(..total);
            if s
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/x-protobuf\r\ncontent-length: 0\r\n\r\n")
                .is_err()
            {
                return;
            }
        }
    }

    fn traces(bodies: &[(String, Vec<u8>)]) -> Vec<ExportTraceServiceRequest> {
        bodies
            .iter()
            .filter(|(p, _)| p == "/v1/traces")
            .map(|(_, b)| ExportTraceServiceRequest::decode(b.as_slice()).expect("decode traces"))
            .collect()
    }

    fn metrics(bodies: &[(String, Vec<u8>)]) -> Vec<ExportMetricsServiceRequest> {
        bodies
            .iter()
            .filter(|(p, _)| p == "/v1/metrics")
            .map(|(_, b)| ExportMetricsServiceRequest::decode(b.as_slice()).expect("decode metrics"))
            .collect()
    }

    fn spans(reqs: &[ExportTraceServiceRequest]) -> Vec<Span> {
        reqs.iter()
            .flat_map(|r| &r.resource_spans)
            .flat_map(|rs| &rs.scope_spans)
            .flat_map(|ss| ss.spans.clone())
            .collect()
    }

    fn attr<'a>(kvs: &'a [KeyValue], key: &str) -> Option<&'a any_value::Value> {
        kvs.iter().find(|kv| kv.key == key).and_then(|kv| kv.value.as_ref()).and_then(|v| v.value.as_ref())
    }

    fn attr_str(kvs: &[KeyValue], key: &str) -> Option<String> {
        match attr(kvs, key)? {
            any_value::Value::StringValue(s) => Some(s.clone()),
            _ => None,
        }
    }

    fn attr_int(kvs: &[KeyValue], key: &str) -> Option<i64> {
        match attr(kvs, key)? {
            any_value::Value::IntValue(i) => Some(*i),
            _ => None,
        }
    }

    /// Every string value anywhere in the export: span names, attribute values,
    /// resource attributes, metric names and data-point attributes.
    fn all_strings(tr: &[ExportTraceServiceRequest], mr: &[ExportMetricsServiceRequest]) -> Vec<String> {
        fn kv_strings(kvs: &[KeyValue], out: &mut Vec<String>) {
            for kv in kvs {
                out.push(kv.key.clone());
                if let Some(AnyValue { value: Some(any_value::Value::StringValue(s)) }) = &kv.value {
                    out.push(s.clone());
                }
            }
        }
        let mut out = Vec::new();
        for r in tr {
            for rs in &r.resource_spans {
                if let Some(res) = &rs.resource {
                    kv_strings(&res.attributes, &mut out);
                }
                for ss in &rs.scope_spans {
                    for s in &ss.spans {
                        out.push(s.name.clone());
                        kv_strings(&s.attributes, &mut out);
                        if let Some(st) = &s.status {
                            out.push(st.message.clone());
                        }
                        for e in &s.events {
                            out.push(e.name.clone());
                            kv_strings(&e.attributes, &mut out);
                        }
                    }
                }
            }
        }
        for r in mr {
            for rm in &r.resource_metrics {
                if let Some(res) = &rm.resource {
                    kv_strings(&res.attributes, &mut out);
                }
                for sm in &rm.scope_metrics {
                    for m in &sm.metrics {
                        out.push(m.name.clone());
                        use opentelemetry_proto::tonic::metrics::v1::metric::Data;
                        match &m.data {
                            Some(Data::Sum(s)) => s.data_points.iter().for_each(|p| kv_strings(&p.attributes, &mut out)),
                            Some(Data::Histogram(h)) => {
                                h.data_points.iter().for_each(|p| kv_strings(&p.attributes, &mut out))
                            }
                            Some(Data::Gauge(g)) => g.data_points.iter().for_each(|p| kv_strings(&p.attributes, &mut out)),
                            _ => {}
                        }
                    }
                }
            }
        }
        out
    }

    fn metric_names(reqs: &[ExportMetricsServiceRequest]) -> BTreeSet<String> {
        reqs.iter()
            .flat_map(|r| &r.resource_metrics)
            .flat_map(|rm| &rm.scope_metrics)
            .flat_map(|sm| sm.metrics.iter().map(|m| m.name.clone()))
            .collect()
    }

    fn warning_lines(out: &Output) -> usize {
        stderr(out).lines().filter(|l| l.starts_with("warning: OpenTelemetry export")).count()
    }

    #[test]
    fn otel_run_exports_spans_and_metrics() {
        let home = temp_home("positive");
        let collector = Collector::start();
        let agents = collector.agents.clone();
        let (out, _) = run(rmguard(&home, Some(collector.port), &["--otel", "--format", "json"]));
        let bodies = collector.finish();
        let agents = agents.lock().unwrap().clone();
        assert!(!agents.is_empty());
        for ua in &agents {
            assert_eq!(ua, concat!("rmguard/", env!("CARGO_PKG_VERSION")), "documented user agent");
        }
        assert!(out.status.success(), "exit {:?}; stderr:\n{}", out.status, stderr(&out));
        let report = json(&out);
        assert!(stderr(&out).contains("info: OpenTelemetry export enabled"), "{}", stderr(&out));
        assert_eq!(warning_lines(&out), 0, "{}", stderr(&out));

        let tr = traces(&bodies);
        let mr = metrics(&bodies);
        assert!(!tr.is_empty(), "no /v1/traces request; got paths {:?}", bodies.iter().map(|b| &b.0).collect::<Vec<_>>());
        assert!(!mr.is_empty(), "no /v1/metrics request");

        // Resource.
        let res = tr[0].resource_spans[0].resource.as_ref().expect("resource");
        assert_eq!(attr_str(&res.attributes, "service.name").as_deref(), Some("rmguard"));
        assert_eq!(attr_str(&res.attributes, "service.version").as_deref(), Some(env!("CARGO_PKG_VERSION")));
        assert!(attr_str(&res.attributes, "os.type").is_some());
        assert!(attr_str(&res.attributes, "host.name").is_none(), "host.name must not be exported");

        // One trace, one root.
        let all = spans(&tr);
        let roots: Vec<&Span> = all.iter().filter(|s| s.name == "rmguard.scan").collect();
        assert_eq!(roots.len(), 1, "expected exactly one root span");
        let root = roots[0];
        assert!(root.parent_span_id.is_empty(), "root span has a parent");
        assert!(all.iter().all(|s| s.trace_id == root.trace_id), "spans span several traces");
        assert_eq!(
            all.iter().filter(|s| s.parent_span_id.is_empty()).count(),
            1,
            "only the root may be parentless"
        );
        let by_id: HashMap<&[u8], &Span> = all.iter().map(|s| (s.span_id.as_slice(), s)).collect();
        let reaches_root = |s: &Span| {
            let mut cur = s;
            for _ in 0..16 {
                if cur.span_id == root.span_id {
                    return true;
                }
                match by_id.get(cur.parent_span_id.as_slice()) {
                    Some(p) => cur = p,
                    None => return false,
                }
            }
            false
        };

        // Each scanner that ran has exactly one span whose numbers equal the JSON row.
        let rows = report["diagnostics"].as_array().expect("diagnostics");
        let mut checked = 0;
        for row in rows.iter().filter(|r| r["skipped"] == false) {
            let label = row["scanner"].as_str().unwrap();
            let name = format!("scanner.{label}");
            let matching: Vec<&Span> = all.iter().filter(|s| s.name == name).collect();
            assert_eq!(matching.len(), 1, "spans named {name}");
            let s = matching[0];
            let a = &s.attributes;
            assert_eq!(attr_str(a, "rmguard.scanner").as_deref(), Some(label));
            assert_eq!(attr_int(a, "rmguard.files.read"), row["files_read"].as_i64(), "{name}");
            assert_eq!(attr_int(a, "rmguard.files.missing"), row["files_missing"].as_i64(), "{name}");
            assert_eq!(attr_int(a, "rmguard.items"), row["items"].as_i64(), "{name}");
            assert_eq!(attr_int(a, "rmguard.duration_ms"), row["duration_ms"].as_i64(), "{name}");
            let span_ms = (s.end_time_unix_nano - s.start_time_unix_nano) / 1_000_000;
            assert_eq!(Some(span_ms as i64), row["duration_ms"].as_i64(), "{name} span duration");
            assert!(reaches_root(s), "{name} does not reach the root span");
            checked += 1;
        }
        assert!(checked >= 10, "only {checked} scanner rows checked");
        assert!(all.iter().any(|s| s.name == "phase.home_pass"));
        assert!(all.iter().all(reaches_root), "a span is detached from the root");

        let names = metric_names(&mr);
        for m in ["rmguard.scanner.duration", "rmguard.scanner.files_read", "rmguard.scan.duration"] {
            assert!(names.contains(m), "metric {m} missing; got {names:?}");
        }

        // The report itself is unchanged in shape by --otel.
        let (plain, _) = run(rmguard(&home, None, &["--format", "json"]));
        let plain = json(&plain);
        let keys = |v: &serde_json::Value| v.as_object().unwrap().keys().cloned().collect::<BTreeSet<_>>();
        assert_eq!(keys(&report), keys(&plain));
        let _ = std::fs::remove_dir_all(&home);
    }

    /// A HOME full of E2E-prefixed canaries in every place the scanners read.
    fn canary_home(tag: &str) -> PathBuf {
        let home = temp_home(tag);
        let proj = home.join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        let claude = serde_json::json!({
            "mcpServers": {
                "E2EOTELNAME\u{1b}[32m": {
                    "command": "/nonexistent/E2EOTELCMD",
                    "args": ["--token=E2EOTELARG"],
                    "env": {"API_KEY": "E2EOTELENV"}
                }
            },
            "projects": { proj.to_string_lossy(): {} }
        });
        std::fs::write(home.join(".claude.json"), claude.to_string()).unwrap();
        std::fs::write(proj.join(".env"), "SECRET_TOKEN=E2EOTELDOTENV\n").unwrap();
        std::fs::write(home.join(".aider.conf.yml"), "openai-api-key: E2EOTELAIDER\n").unwrap();
        home
    }

    #[test]
    fn otel_never_exports_secrets_paths_or_names() {
        let home = canary_home("secrecy");
        let collector = Collector::start();
        let (out, _) = run(rmguard(&home, Some(collector.port), &["--otel", "--probe-mcp", "--format", "json"]));
        let bodies = collector.finish();
        assert!(out.status.success(), "exit {:?}; stderr:\n{}", out.status, stderr(&out));
        let report = json(&out);

        // Positive control: the scan saw the fixture.
        let text = report.to_string();
        assert!(text.contains("E2EOTELNAME"), "the MCP server was not reported");
        assert!(text.contains(".aider.conf.yml"), "the Aider config was not reported");
        assert!(!bodies.is_empty(), "nothing exported");

        let raw: Vec<u8> = bodies.iter().flat_map(|(_, b)| b.iter().copied()).collect();
        let contains = |needle: &[u8]| raw.windows(needle.len()).any(|w| w == needle);
        assert!(!contains(b"E2EOTEL"), "a canary reached the collector");
        assert!(!contains(home.to_string_lossy().as_bytes()), "the HOME path reached the collector");

        let tr = traces(&bodies);
        let mr = metrics(&bodies);
        // Raw protobuf holds random IDs and fixed64 timestamps, so ESC is checked on the
        // decoded strings, not the bytes.
        for s in all_strings(&tr, &mr) {
            assert!(!s.contains('\u{1b}'), "control character exported: {s:?}");
            assert!(!s.contains("E2EOTEL"), "canary exported: {s:?}");
        }

        let all = spans(&tr);
        // Program names are an inventory of installed tools: not exported.
        assert!(
            all.iter().all(|s| attr(&s.attributes, "process.executable.name").is_none()),
            "process.executable.name exported"
        );
        let probes: Vec<&Span> = all.iter().filter(|s| s.name == "mcp.probe").collect();
        assert_eq!(probes.len(), 1, "expected one mcp.probe span");
        let p = probes[0];
        assert_eq!(attr_str(&p.attributes, "rmguard.mcp.outcome").as_deref(), Some("spawn_failed"));
        assert_eq!(attr_int(&p.attributes, "rmguard.mcp.server_index"), Some(0));
        let status = p.status.as_ref().expect("status");
        assert_eq!(status.code, StatusCode::Error as i32);
        assert_eq!(status.message, "spawn_failed");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn otel_dead_collector_closed_port() {
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let home = temp_home("dead");
        let args = ["--format", "json", "--skip", SLOW_SKIP];
        let (base, base_wall) = run(rmguard(&home, Some(port), &args));
        assert!(base.status.success());
        let mut with = args.to_vec();
        with.insert(0, "--otel");
        let (out, wall) = run(rmguard(&home, Some(port), &with));
        assert!(out.status.success(), "exit {:?}; stderr:\n{}", out.status, stderr(&out));
        json(&out);
        assert_eq!(warning_lines(&out), 1, "{}", stderr(&out));
        assert!(stderr(&out).contains("export failed (could not connect)"), "{}", stderr(&out));
        assert!(!stderr(&out).contains("panicked"), "{}", stderr(&out));
        assert!(!stderr(&out).contains(&format!(":{port}")), "the endpoint was echoed: {}", stderr(&out));
        // A refused port costs about a millisecond; 2.5 s still catches a deadline loop
        // that stopped working (the sequential-shutdown regression cost 3.03 s).
        assert!(
            wall.saturating_sub(base_wall) < Duration::from_millis(2500),
            "dead collector cost {wall:?} vs {base_wall:?}"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn otel_blackhole_collector_is_bounded() {
        // Bound but never accepted: the kernel completes the handshake, the request is
        // written, and no response ever comes.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let home = temp_home("blackhole");
        let args = ["--format", "json", "--skip", SLOW_SKIP];
        let (base, base_wall) = run(rmguard(&home, None, &args));
        assert!(base.status.success());
        let mut with = args.to_vec();
        with.insert(0, "--otel");
        let (out, wall) = run(rmguard(&home, Some(port), &with));
        drop(listener);
        assert!(out.status.success(), "exit {:?}; stderr:\n{}", out.status, stderr(&out));
        json(&out);
        assert_eq!(warning_lines(&out), 1, "{}", stderr(&out));
        assert!(!stderr(&out).contains("panicked"), "{}", stderr(&out));
        // Measured ~1.03 s; the hard bound in code is 2 s; 0.5 s of slack for loaded CI.
        assert!(
            wall.saturating_sub(base_wall) < Duration::from_millis(2500),
            "black-holed collector cost {wall:?} vs {base_wall:?}"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// The report is complete on stdout before the OpenTelemetry shutdown starts, not when
    /// the process exits. JSON ends without a newline, so without an explicit flush its
    /// last line sat in std's line buffer for the whole (black-holed: ~1 s) shutdown, and
    /// a pipeline that killed rmguard in that window got a truncated document. Here the
    /// test waits until stdout goes quiet while rmguard is still running (stuck on the
    /// collector), kills it, and requires what it already wrote to be the whole report.
    #[test]
    fn report_is_flushed_before_otel_shutdown() {
        use std::process::Stdio;
        use std::sync::mpsc;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let home = temp_home("flush");
        let mut cmd = rmguard(&home, Some(port), &["--otel", "--format", "json", "--skip", SLOW_SKIP]);
        let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("spawn rmguard");
        let mut stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 65536];
            while let Ok(n) = stdout.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        let mut got = Vec::new();
        let mut killed_while_running = false;
        let give_up = Instant::now() + Duration::from_secs(60);
        loop {
            match rx.recv_timeout(Duration::from_millis(300)) {
                Ok(chunk) => got.extend_from_slice(&chunk),
                // Output has started and then stopped while the process lives on: it is
                // in the export shutdown (the collector never answers). Kill it now.
                Err(mpsc::RecvTimeoutError::Timeout) if !got.is_empty() => {
                    if child.try_wait().unwrap().is_none() {
                        child.kill().unwrap();
                        killed_while_running = true;
                    }
                    break;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    assert!(Instant::now() < give_up, "no report within 60 s");
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        let _ = child.wait();
        let _ = reader.join();
        // Bytes still in the pipe when the kill landed were written before it.
        while let Ok(chunk) = rx.try_recv() {
            got.extend_from_slice(&chunk);
        }
        drop(listener);
        assert!(
            killed_while_running,
            "rmguard exited before stdout went quiet, so this run did not exercise the shutdown window"
        );
        serde_json::from_slice::<serde_json::Value>(&got).unwrap_or_else(|e| {
            panic!("report on stdout was incomplete when the OpenTelemetry shutdown began ({e}); {} bytes", got.len())
        });
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn otel_sdk_disabled_env_wins() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let home = temp_home("sdkdisabled");
        let mut cmd = rmguard(&home, Some(port), &["--otel", "--format", "json", "--skip", SLOW_SKIP]);
        cmd.env("OTEL_SDK_DISABLED", "TRUE");
        let (out, _) = run(cmd);
        assert!(out.status.success(), "exit {:?}", out.status);
        json(&out);
        assert!(stderr(&out).contains("OpenTelemetry export off"), "{}", stderr(&out));
        assert_never_connected(&listener);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn otel_flushes_before_fail_on_exit() {
        let home = canary_home("failon");
        let collector = Collector::start();
        let (out, _) = run(rmguard(
            &home,
            Some(collector.port),
            &["--otel", "--fail-on", "low", "--format", "json", "--skip", SLOW_SKIP],
        ));
        let bodies = collector.finish();
        assert_eq!(out.status.code(), Some(2), "stderr:\n{}", stderr(&out));
        json(&out);
        let all = spans(&traces(&bodies));
        assert!(all.iter().any(|s| s.name == "rmguard.scan"), "root span not flushed before exit 2");
        let _ = std::fs::remove_dir_all(&home);
    }

    /// The protocol notice is a start-up line of its own; it must not use up the single
    /// end-of-run warning. A gRPC setup on :4317 is common, and there every export fails.
    #[test]
    fn protocol_notice_does_not_swallow_export_warning() {
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let home = temp_home("protocol");
        let mut cmd = rmguard(&home, Some(port), &["--otel", "--format", "json", "--skip", SLOW_SKIP]);
        cmd.env("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc");
        let (out, _) = run(cmd);
        assert!(out.status.success(), "exit {:?}; stderr:\n{}", out.status, stderr(&out));
        json(&out);
        let err = stderr(&out);
        assert_eq!(err.lines().filter(|l| l.contains("OTEL_EXPORTER_OTLP_PROTOCOL is ignored")).count(), 1, "{err}");
        assert_eq!(warning_lines(&out), 1, "{err}");
        assert!(err.contains("export failed (could not connect)"), "{err}");
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Every proxy variable ureq reads is set and points at a listener; the loopback
    /// collector must still get the export directly and the proxy nothing.
    #[test]
    fn loopback_collector_bypasses_proxy_env() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_url = format!("http://127.0.0.1:{}", proxy.local_addr().unwrap().port());
        let home = temp_home("proxy");
        let collector = Collector::start();
        let mut cmd = rmguard(&home, Some(collector.port), &["--otel", "--format", "json", "--skip", SLOW_SKIP]);
        for var in ["ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
            cmd.env(var, &proxy_url);
        }
        let (out, _) = run(cmd);
        let bodies = collector.finish();
        assert!(out.status.success(), "exit {:?}; stderr:\n{}", out.status, stderr(&out));
        json(&out);
        assert_eq!(warning_lines(&out), 0, "{}", stderr(&out));
        assert!(bodies.iter().any(|(p, _)| p == "/v1/traces"), "no direct export; stderr:\n{}", stderr(&out));
        assert!(bodies.iter().any(|(p, _)| p == "/v1/metrics"), "no direct export");
        assert_never_connected(&proxy);
        let _ = std::fs::remove_dir_all(&home);
    }

    /// A real TLS failure (https:// endpoint, plain-HTTP server) is reported as `tls`,
    /// not `other`.
    #[test]
    fn tls_failure_is_categorized() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let s2 = stop.clone();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            while !s2.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n");
                        // Hold the socket briefly, as the unit-test twin does, so the
                        // client reads the plaintext reply (a TLS error) rather than
                        // racing an RST (which would categorize as "could not connect").
                        std::thread::spawn(move || {
                            std::thread::sleep(Duration::from_millis(200));
                            drop(s);
                        });
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        let home = temp_home("tls");
        let mut cmd = rmguard(&home, None, &["--otel", "--format", "json", "--skip", SLOW_SKIP]);
        cmd.env("OTEL_EXPORTER_OTLP_ENDPOINT", format!("https://127.0.0.1:{port}"));
        let (out, _) = run(cmd);
        stop.store(true, Ordering::SeqCst);
        let _ = server.join();
        assert!(out.status.success(), "exit {:?}; stderr:\n{}", out.status, stderr(&out));
        json(&out);
        assert_eq!(warning_lines(&out), 1, "{}", stderr(&out));
        assert!(stderr(&out).contains("export failed (tls)"), "{}", stderr(&out));
        let _ = std::fs::remove_dir_all(&home);
    }
}
