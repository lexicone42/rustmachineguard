//! The real OpenTelemetry pipeline, compiled with the `otel` feature and built only by
//! [`init`] (i.e. only under `--otel`).
//!
//! Shape: `opentelemetry` API used directly (no `tracing` bridge), `opentelemetry_sdk`'s
//! thread-based BatchSpanProcessor and PeriodicReader (no async runtime: the SDK drives
//! the exporters with `futures_executor::block_on` on its own std threads), and
//! `opentelemetry-otlp` over http/protobuf through a ureq client we supply, so the TLS
//! stack stays the rustls one rmguard already ships and no tokio/hyper/reqwest is pulled.
//! Builder usage follows the opentelemetry-rust 0.33 docs for `BatchSpanProcessor`,
//! `BatchConfigBuilder` and `PeriodicReader`.

use super::{Attr, InitError, Metric, V};
use crate::models::ScannerStat;
use opentelemetry::metrics::{Counter, Histogram, MeterProvider as _};
use opentelemetry::trace::{SpanKind, Status, TraceContextExt, Tracer as _, TracerProvider as _};
use opentelemetry::{Context, ContextGuard, KeyValue, Value};
use opentelemetry_http::{Bytes, HttpClient, HttpError, Request, Response};
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::{BatchConfigBuilder, BatchSpanProcessor, SdkTracer, SdkTracerProvider};
use std::borrow::Cow;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

static ENABLED: AtomicBool = AtomicBool::new(false);
static STATE: OnceLock<State> = OnceLock::new();
/// The first export failure seen by the HTTP client. Only the first is kept: one
/// warning line per run, and the first failure is the informative one.
static EXPORT_ERR: OnceLock<ExportErr> = OnceLock::new();
/// At most one end-of-run `warning: OpenTelemetry export ...` line per run. Start-up
/// configuration notices are printed directly and do not use this slot: sharing it once
/// let an OTEL_EXPORTER_OTLP_PROTOCOL notice swallow the export-failure warning.
static WARNED: AtomicBool = AtomicBool::new(false);

/// Per-request cap for an export (HTTP client and OTLP exporter both).
const EXPORT_TIMEOUT: Duration = Duration::from_secs(1);
/// The span pipeline's own shutdown cap. A little above EXPORT_TIMEOUT so that a request
/// that times out is reported by the HTTP client as `timeout`, not cut off first by the
/// processor (which only says "failed"), and still well inside SHUTDOWN_DEADLINE.
const SPAN_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(1500);
/// Sent on every export request, replacing opentelemetry-otlp's own
/// `OTel-OTLP-Exporter-Rust/<version>`, which overrides the agent's default.
const USER_AGENT: &str = concat!("rmguard/", env!("CARGO_PKG_VERSION"));
/// Hard cap on the whole shutdown/flush, however the collector behaves.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(2);
/// Histogram buckets in seconds: a scanner is milliseconds, a `--version` probe tens of
/// milliseconds, an MCP probe or registry lookup up to its 10-30 s timeout.
const BUCKETS: &[f64] = &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0];

struct State {
    tracer: Option<SdkTracer>,
    tp: Option<SdkTracerProvider>,
    mp: Option<SdkMeterProvider>,
    inst: Option<Instruments>,
}

struct Instruments {
    scan_duration: Histogram<f64>,
    scanner_duration: Histogram<f64>,
    files_read: Counter<u64>,
    files_missing: Counter<u64>,
    items: Counter<u64>,
    skipped: Counter<u64>,
    exec_duration: Histogram<f64>,
    mcp_probe_duration: Histogram<f64>,
    registry_lookup_duration: Histogram<f64>,
}

/// A failed export, as a fixed category. Never the error text: ureq's messages carry
/// the endpoint URL, and endpoint userinfo or OTEL_EXPORTER_OTLP_HEADERS can hold
/// credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExportErr {
    Refused,
    Dns,
    Timeout,
    Tls,
    Status(u16),
    Other,
}

impl std::fmt::Display for ExportErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportErr::Refused => f.write_str("could not connect"),
            ExportErr::Dns => f.write_str("could not resolve host"),
            ExportErr::Timeout => f.write_str("timeout"),
            ExportErr::Tls => f.write_str("tls"),
            ExportErr::Status(c) => write!(f, "HTTP {c}"),
            ExportErr::Other => f.write_str("other"),
        }
    }
}

fn categorize(e: &ureq::Error) -> ExportErr {
    use std::io::ErrorKind;
    match e {
        ureq::Error::ConnectionFailed => ExportErr::Refused,
        ureq::Error::HostNotFound => ExportErr::Dns,
        ureq::Error::Io(io)
            if matches!(
                io.kind(),
                ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
            ) =>
        {
            ExportErr::Refused
        }
        ureq::Error::Io(io) if io.kind() == ErrorKind::TimedOut => ExportErr::Timeout,
        // ureq 3.5's resolver hands back std's `to_socket_addrs` error unchanged
        // (resolver.rs), and std gives a getaddrinfo failure no stable ErrorKind, only
        // this fixed message prefix. Matching std's own text, never anything remote.
        ureq::Error::Io(io)
            if io.raw_os_error().is_none() && io.to_string().starts_with("failed to lookup address information") =>
        {
            ExportErr::Dns
        }
        // ureq's rustls connector runs the handshake through rustls' `complete_io`, which
        // reports a protocol failure (e.g. a plain-HTTP server on an https:// endpoint)
        // as an io::Error of kind InvalidData wrapping the rustls error.
        ureq::Error::Io(io) if io.kind() == ErrorKind::InvalidData => ExportErr::Tls,
        ureq::Error::Timeout(_) => ExportErr::Timeout,
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) => ExportErr::Tls,
        ureq::Error::StatusCode(c) => ExportErr::Status(*c),
        _ => ExportErr::Other,
    }
}

/// Keep the first failure only.
fn note_export_err(slot: &OnceLock<ExportErr>, e: ExportErr) {
    let _ = slot.set(e);
}

/// The single end-of-run warning, if any. Deadline first: it says the most.
fn shutdown_warning(deadline_passed: bool, err: Option<ExportErr>) -> Option<String> {
    if deadline_passed {
        Some(format!(
            "warning: OpenTelemetry export did not finish within {}s; abandoned (telemetry only; the report and exit code are not affected by this)",
            SHUTDOWN_DEADLINE.as_secs()
        ))
    } else {
        err.map(|e| {
            format!("warning: OpenTelemetry export failed ({e}); telemetry only, the report and exit code are not affected by this")
        })
    }
}

fn warn_once(line: &str) {
    if !WARNED.swap(true, Ordering::Relaxed) {
        eprintln!("{line}");
    }
}

/// OTLP over our ureq agents. Pattern from the opentelemetry-http 0.33 crate docs' custom
/// HttpClient example, adapted to ureq 3: status codes come back as responses (not
/// errors) so the exporter sees them, the body read is capped, and failures are
/// recorded as a category before being handed back unchanged.
///
/// Two agents, one proxy policy: a loopback collector (the default `localhost:4318`) is
/// always reached directly, because ureq's environment proxy (ALL_PROXY, HTTPS_PROXY,
/// HTTP_PROXY, lowercase too; the first one set wins for http:// and https:// alike)
/// has no loopback exemption. Without this, a corporate proxy variable sent telemetry
/// meant for this machine, with any OTEL_EXPORTER_OTLP_HEADERS credential, in cleartext
/// to the proxy. Any other endpoint uses the environment proxy, with NO_PROXY honored.
#[derive(Debug, Clone)]
struct UreqClient {
    direct: ureq::Agent,
    proxied: ureq::Agent,
}

/// `localhost`, `*.localhost`, 127.0.0.0/8 or ::1 (RFC 6761 reserves `localhost` names
/// for loopback).
fn is_loopback_host(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    let lower = h.to_ascii_lowercase();
    let lower = lower.trim_end_matches('.');
    lower == "localhost"
        || lower.ends_with(".localhost")
        || h.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

#[async_trait::async_trait]
impl HttpClient for UreqClient {
    async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let (mut parts, body) = request.into_parts();
        if let Ok(ua) = USER_AGENT.parse() {
            parts.headers.insert("user-agent", ua);
        }
        let agent = if parts.uri.host().is_some_and(is_loopback_host) { &self.direct } else { &self.proxied };
        let req = Request::from_parts(parts, body.to_vec());
        let mut resp = match agent.run(req) {
            Ok(r) => r,
            Err(e) => {
                note_export_err(&EXPORT_ERR, categorize(&e));
                return Err(Box::new(e));
            }
        };
        let status = resp.status();
        if status.as_u16() >= 400 {
            note_export_err(&EXPORT_ERR, ExportErr::Status(status.as_u16()));
        }
        let body = match resp.body_mut().with_config().limit(64 * 1024).read_to_vec() {
            Ok(b) => b,
            Err(e) => {
                note_export_err(&EXPORT_ERR, categorize(&e));
                return Err(Box::new(e));
            }
        };
        Ok(Response::builder().status(status).body(Bytes::from(body))?)
    }
}

fn os_type(os: &str) -> &str {
    match os {
        "macos" => "darwin",
        other => other,
    }
}

fn host_arch(arch: &str) -> &str {
    match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

fn env_is(name: &str, value: &str) -> bool {
    std::env::var(name).is_ok_and(|v| v.trim().eq_ignore_ascii_case(value))
}

#[inline(always)]
pub(super) fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

pub(super) fn init() -> Result<(), InitError> {
    if STATE.get().is_some() {
        return Ok(());
    }
    if env_is("OTEL_SDK_DISABLED", "true") {
        return Err(InitError::Disabled);
    }
    // Start-up notices print directly; WARNED is kept for the end-of-run export warning.
    // Values are not echoed: they are the user's, but nothing here needs them.
    if let Ok(p) = std::env::var("OTEL_EXPORTER_OTLP_PROTOCOL")
        && !p.trim().is_empty()
        && p.trim() != "http/protobuf"
    {
        eprintln!("warning: OTEL_EXPORTER_OTLP_PROTOCOL is ignored; rmguard exports OTLP over http/protobuf only");
    }
    for var in ["OTEL_TRACES_EXPORTER", "OTEL_METRICS_EXPORTER"] {
        if let Ok(v) = std::env::var(var)
            && !matches!(v.trim().to_ascii_lowercase().as_str(), "" | "otlp" | "none")
        {
            eprintln!("warning: {var} supports only `otlp` and `none` here; exporting OTLP");
        }
    }
    let want_traces = !env_is("OTEL_TRACES_EXPORTER", "none");
    let want_metrics = !env_is("OTEL_METRICS_EXPORTER", "none");
    if !want_traces && !want_metrics {
        return Err(InitError::Disabled);
    }

    // Resource: the SDK's detectors (telemetry.sdk.*, OTEL_SERVICE_NAME,
    // OTEL_RESOURCE_ATTRIBUTES) plus fixed facts. No host name, no user.
    let mut rb = Resource::builder();
    if std::env::var("OTEL_SERVICE_NAME").map_or(true, |v| v.trim().is_empty()) {
        rb = rb.with_service_name("rmguard");
    }
    let res = rb
        .with_attributes([
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            KeyValue::new("os.type", os_type(std::env::consts::OS)),
            KeyValue::new("host.arch", host_arch(std::env::consts::ARCH)),
        ])
        .build();

    let agent = |proxy: Option<ureq::Proxy>| -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_global(Some(EXPORT_TIMEOUT))
            .http_status_as_error(false)
            .max_redirects(0)
            .user_agent(USER_AGENT)
            .proxy(proxy)
            .build()
            .into()
    };
    let client = UreqClient { direct: agent(None), proxied: agent(ureq::Proxy::try_from_env()) };

    // No with_endpoint(): the standard OTEL_EXPORTER_OTLP_{TRACES,METRICS}_ENDPOINT /
    // OTEL_EXPORTER_OTLP_ENDPOINT / default resolution applies. Protocol and timeout are
    // forced (programmatic config wins over env). Build errors are mapped to a category
    // without formatting: their text echoes the endpoint.
    let tp = if want_traces {
        let exp = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_http_client(client.clone())
            .with_protocol(Protocol::HttpBinary)
            .with_timeout(EXPORT_TIMEOUT)
            .with_retry_policy(opentelemetry_otlp::RetryPolicy::disabled())
            .build()
            .map_err(|_| InitError::Config)?;
        let processor = BatchSpanProcessor::builder(exp)
            .with_batch_config(
                BatchConfigBuilder::default()
                    .with_max_queue_size(8192)
                    .with_max_export_batch_size(512)
                    .with_scheduled_delay(Duration::from_secs(5))
                    .build(),
            )
            .build();
        Some(
            SdkTracerProvider::builder()
                .with_span_processor(processor)
                .with_resource(res.clone())
                .build(),
        )
    } else {
        None
    };

    let mp = if want_metrics {
        let mexp = match opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_http_client(client)
            .with_protocol(Protocol::HttpBinary)
            .with_timeout(EXPORT_TIMEOUT)
            .with_retry_policy(opentelemetry_otlp::RetryPolicy::disabled())
            .build()
        {
            Ok(m) => m,
            Err(_) => {
                // The span pipeline already started its worker; stop it quietly.
                if let Some(tp) = tp {
                    let _ = tp.shutdown_with_timeout(Duration::from_millis(100));
                }
                return Err(InitError::Config);
            }
        };
        // One cumulative snapshot, at shutdown: a scan is short, and periodic export
        // would only add requests.
        let reader = PeriodicReader::builder(mexp).with_interval(Duration::from_secs(3600)).build();
        Some(SdkMeterProvider::builder().with_reader(reader).with_resource(res).build())
    } else {
        None
    };

    let tracer = tp.as_ref().map(|tp| tp.tracer("rmguard"));
    let inst = mp.as_ref().map(|mp| {
        let meter = mp.meter("rmguard");
        let hist = |name: &'static str, desc: &'static str| {
            meter
                .f64_histogram(name)
                .with_unit("s")
                .with_description(desc)
                .with_boundaries(BUCKETS.to_vec())
                .build()
        };
        Instruments {
            scan_duration: hist("rmguard.scan.duration", "Wall time of one rmguard scan"),
            scanner_duration: hist("rmguard.scanner.duration", "Wall time of one scanner run"),
            files_read: meter
                .u64_counter("rmguard.scanner.files_read")
                .with_unit("{file}")
                .with_description("Files a scanner opened")
                .build(),
            files_missing: meter
                .u64_counter("rmguard.scanner.files_missing")
                .with_unit("{file}")
                .with_description("Paths a scanner looked for that were absent or rejected")
                .build(),
            items: meter
                .u64_counter("rmguard.scanner.items")
                .with_unit("{item}")
                .with_description("Items a scanner reported")
                .build(),
            skipped: meter
                .u64_counter("rmguard.scanner.skipped")
                .with_unit("{scanner}")
                .with_description("Scanners that did not run")
                .build(),
            exec_duration: hist("rmguard.exec.duration", "Wall time of one subprocess rmguard ran"),
            mcp_probe_duration: hist("rmguard.mcp.probe.duration", "Wall time of one MCP server probe"),
            registry_lookup_duration: hist(
                "rmguard.registry.lookup.duration",
                "Wall time of one MCP registry lookup",
            ),
        }
    });

    if STATE.set(State { tracer, tp, mp, inst }).is_err() {
        return Ok(());
    }
    ENABLED.store(true, Ordering::SeqCst);
    Ok(())
}

fn value(v: V) -> Value {
    match v {
        V::S(s) => Value::from(s),
        V::I(i) => Value::I64(i),
        V::B(b) => Value::Bool(b),
    }
}

fn conv(attrs: Vec<Attr>) -> Vec<KeyValue> {
    attrs.into_iter().map(|Attr(k, v)| KeyValue::new(k.as_str(), value(v))).collect()
}

/// A started span, attached as the current context on this thread.
pub(super) struct Live {
    cx: Context,
    // Dropped after `Drop::drop` ends the span: restores the parent context.
    _attach: ContextGuard,
    start: SystemTime,
    /// Monotonic twin of `start`. Every end time is `start + <Instant elapsed>`, so a wall
    /// clock step mid-scan cannot put a child span outside its parent.
    t0: Instant,
    finished: bool,
}

impl Live {
    pub(super) fn set(&mut self, attrs: Vec<Attr>) {
        self.cx.span().set_attributes(conv(attrs));
    }

    pub(super) fn error(&mut self, category: &'static str) {
        self.cx.span().set_status(Status::error(category));
    }

    pub(super) fn finish_after(mut self, elapsed: Duration) {
        self.cx.span().end_with_timestamp(self.start + elapsed);
        self.finished = true;
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        if !self.finished {
            self.cx.span().end_with_timestamp(self.start + self.t0.elapsed());
        }
    }
}

pub(super) fn start(name: Cow<'static, str>, client: bool, attrs: Vec<Attr>) -> Option<Live> {
    let tracer = STATE.get()?.tracer.as_ref()?;
    let start = SystemTime::now();
    let t0 = Instant::now();
    let span = tracer
        .span_builder(name)
        .with_kind(if client { SpanKind::Client } else { SpanKind::Internal })
        .with_start_time(start)
        .with_attributes(conv(attrs))
        .start(tracer);
    let cx = Context::current_with_span(span);
    let attach = cx.clone().attach();
    Some(Live { cx, _attach: attach, start, t0, finished: false })
}

pub(super) fn annotate_current(attrs: Vec<Attr>) {
    Context::current().span().set_attributes(conv(attrs));
}

pub(super) fn record(metric: Metric, v: f64, attrs: Vec<Attr>) {
    let Some(inst) = STATE.get().and_then(|s| s.inst.as_ref()) else { return };
    let kv = conv(attrs);
    let n = v.max(0.0) as u64;
    match metric {
        Metric::ScanDuration => inst.scan_duration.record(v, &kv),
        Metric::ScannerDuration => inst.scanner_duration.record(v, &kv),
        Metric::FilesRead => inst.files_read.add(n, &kv),
        Metric::FilesMissing => inst.files_missing.add(n, &kv),
        Metric::Items => inst.items.add(n, &kv),
        Metric::Skipped => inst.skipped.add(n, &kv),
        Metric::ExecDuration => inst.exec_duration.record(v, &kv),
        Metric::McpProbeDuration => inst.mcp_probe_duration.record(v, &kv),
        Metric::RegistryLookupDuration => inst.registry_lookup_duration.record(v, &kv),
    }
}

pub(super) fn record_scanner(label: &'static str, stat: &ScannerStat, elapsed: Duration) {
    let Some(inst) = STATE.get().and_then(|s| s.inst.as_ref()) else { return };
    let kv = conv(vec![Attr::scanner(label)]);
    inst.scanner_duration.record(elapsed.as_secs_f64(), &kv);
    inst.files_read.add(stat.files_read, &kv);
    inst.files_missing.add(stat.files_missing, &kv);
    inst.items.add(stat.items as u64, &kv);
}

/// Flush both pipelines concurrently under one deadline, then return whatever happened.
///
/// Concurrent because opentelemetry_sdk 0.33.1's `SdkMeterProvider::shutdown_with_timeout`
/// ignores its argument (a hardcoded 5 s): run in sequence against a collector that
/// accepts and never answers, the two shutdowns took 3.03 s; side by side, 1.02 s.
/// A thread still stuck at the deadline is abandoned and dies with the process.
pub(super) fn shutdown() {
    if !ENABLED.swap(false, Ordering::SeqCst) {
        return;
    }
    let Some(state) = STATE.get() else { return };
    let start = Instant::now();
    let deadline = start + SHUTDOWN_DEADLINE;
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    let mut pending = 0usize;
    let mut spawn_failed = false;
    if let Some(tp) = state.tp.clone() {
        let tx = tx.clone();
        match std::thread::Builder::new()
            .name("rmguard-otel-trace".into())
            .spawn(move || {
                let _ = tx.send(tp.shutdown_with_timeout(SPAN_SHUTDOWN_TIMEOUT).is_ok());
            }) {
            Ok(_) => pending += 1,
            Err(_) => spawn_failed = true,
        }
    }
    if let Some(mp) = state.mp.clone() {
        let tx = tx.clone();
        match std::thread::Builder::new()
            .name("rmguard-otel-metrics".into())
            .spawn(move || {
                let _ = tx.send(mp.shutdown().is_ok());
            }) {
            Ok(_) => pending += 1,
            Err(_) => spawn_failed = true,
        }
    }
    drop(tx);
    let mut timed_out = spawn_failed;
    let mut any_failed = false;
    while pending > 0 {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(ok) => {
                pending -= 1;
                any_failed |= !ok;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                timed_out = true;
                break;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let mut err = EXPORT_ERR.get().copied();
    if err.is_none() && any_failed {
        // A pipeline reported failure without the HTTP client seeing one (e.g. the
        // span processor's own timeout); still say export did not complete.
        err = Some(ExportErr::Other);
    }
    if let Some(line) = shutdown_warning(timed_out, err) {
        warn_once(&line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_type_and_arch_mapping() {
        assert_eq!(os_type("macos"), "darwin");
        assert_eq!(os_type("linux"), "linux");
        assert_eq!(host_arch("aarch64"), "arm64");
        assert_eq!(host_arch("x86_64"), "amd64");
        assert_eq!(host_arch("riscv64"), "riscv64");
    }

    #[test]
    fn export_error_records_first_only() {
        let slot = OnceLock::new();
        note_export_err(&slot, categorize(&ureq::Error::ConnectionFailed));
        note_export_err(&slot, ExportErr::Status(503));
        assert_eq!(slot.get().copied(), Some(ExportErr::Refused));

        let line = shutdown_warning(false, slot.get().copied()).expect("a warning");
        assert!(line.starts_with("warning: OpenTelemetry export failed ("), "{line}");
        assert!(!line.contains("http://") && !line.contains("https://") && !line.contains('@'), "{line}");

        assert_eq!(
            shutdown_warning(false, Some(ExportErr::Status(401))).unwrap(),
            "warning: OpenTelemetry export failed (HTTP 401); telemetry only, the report and exit code are not affected by this"
        );
        assert!(shutdown_warning(true, Some(ExportErr::Timeout)).unwrap().contains("did not finish within 2s"));
        assert_eq!(shutdown_warning(false, None), None);
    }

    #[test]
    fn ureq_errors_map_to_categories() {
        use std::io::{Error, ErrorKind};
        assert_eq!(categorize(&ureq::Error::Io(Error::from(ErrorKind::ConnectionRefused))), ExportErr::Refused);
        assert_eq!(categorize(&ureq::Error::HostNotFound), ExportErr::Dns);
        assert_eq!(categorize(&ureq::Error::Io(Error::from(ErrorKind::InvalidData))), ExportErr::Tls);
        assert_eq!(categorize(&ureq::Error::StatusCode(500)), ExportErr::Status(500));
        assert_eq!(categorize(&ureq::Error::Tls("x")), ExportErr::Tls);
        assert_eq!(categorize(&ureq::Error::BadUri("http://u:pw@h".into())), ExportErr::Other);
    }

    /// Errors from real requests, not hand-built variants: a refused loopback port, and
    /// an https:// endpoint answered in plain HTTP. Local sockets only.
    #[test]
    fn real_request_errors_map_to_categories() {
        use std::io::Write;
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(5)))
            .proxy(None)
            .build()
            .into();

        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let e = agent.get(format!("http://127.0.0.1:{closed}/v1/traces")).call().unwrap_err();
        assert_eq!(categorize(&e), ExportErr::Refused, "{e:?}");

        let plain = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = plain.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            if let Ok((mut s, _)) = plain.accept() {
                let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n");
                std::thread::sleep(Duration::from_millis(200));
            }
        });
        let e = agent.get(format!("https://127.0.0.1:{port}/v1/traces")).call().unwrap_err();
        let _ = server.join();
        assert_eq!(categorize(&e), ExportErr::Tls, "{e:?}");
    }

    #[test]
    fn loopback_hosts_bypass_the_proxy() {
        for h in ["localhost", "LOCALHOST", "localhost.", "collector.localhost", "127.0.0.1", "127.8.9.10", "[::1]", "::1"] {
            assert!(is_loopback_host(h), "{h}");
        }
        for h in ["otel.example.com", "localhost.example.com", "10.0.0.1", "[2001:db8::1]", "0.0.0.0", ""] {
            assert!(!is_loopback_host(h), "{h}");
        }
    }
}
