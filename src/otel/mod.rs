//! OpenTelemetry export of scan timing: OFF unless the user passes `--otel`.
//!
//! This module is the only door between the scanner and the OpenTelemetry SDK, and it is
//! shaped so that the door cannot carry scan content:
//!
//! * Attribute keys are a closed enum ([`Key`]); there is no free-form key.
//! * Attribute values are built only through [`Attr`]'s constructors. Compile-time
//!   strings, integers and booleans go in as they are; the only two constructors that
//!   accept runtime text ([`Attr::scanner`] and [`Attr::exec_name`]) run it through the
//!   report's own redaction and display sanitizers and cap it at 64 characters.
//!   (Allow-list attribute construction; the pattern is ours, the sanitizers are the
//!   existing report helpers in `crate::scanners`.)
//! * Span names are `&'static str`, or `scanner.<label>` / `exec.<site>` built from a
//!   scanner label and a static call-site name.
//!
//! Nothing here reads paths, server or package names, commands, arguments, environment
//! values, URLs or error text into telemetry. See docs/OPENTELEMETRY.md.
//!
//! Disabled cost: every entry point checks one `Relaxed` atomic (a constant `false` in a
//! build without the `otel` feature) and returns before evaluating any closure, reading
//! a clock or allocating.

use crate::models::ScannerStat;
use std::ffi::OsStr;
use std::time::{Duration, Instant};

#[cfg(feature = "otel")]
mod sdk;

/// Stand-ins for a build without the `otel` feature. Nothing here is ever constructed:
/// [`enabled`] is a constant `false`, so every caller returns before reaching them.
#[cfg(not(feature = "otel"))]
mod sdk {
    use super::{Attr, InitError, Metric};
    use crate::models::ScannerStat;
    use std::time::Duration;

    pub enum Live {}

    impl Live {
        pub fn set(&mut self, _: Vec<Attr>) {
            match *self {}
        }
        pub fn error(&mut self, _: &'static str) {
            match *self {}
        }
        pub fn finish_after(self, _: Duration) {
            match self {}
        }
    }

    #[inline(always)]
    pub fn enabled() -> bool {
        false
    }
    #[inline(always)]
    pub fn start(_: std::borrow::Cow<'static, str>, _: bool, _: Vec<Attr>) -> Option<Live> {
        None
    }
    #[inline(always)]
    pub fn annotate_current(_: Vec<Attr>) {}
    #[inline(always)]
    pub fn record(_: Metric, _: f64, _: Vec<Attr>) {}
    #[inline(always)]
    pub fn record_scanner(_: &ScannerStat, _: Duration) {}
    pub fn init() -> Result<(), InitError> {
        Err(InitError::NotCompiled)
    }
    #[inline(always)]
    pub fn shutdown() {}
}

/// Attribute keys. A closed set: nothing else can become a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Key {
    Scanner,
    Phase,
    RootIndex,
    RootKind,
    FilesRead,
    FilesMissing,
    Items,
    DurationMs,
    McpServerIndex,
    McpOutcome,
    McpTools,
    McpResources,
    RegistryIndex,
    RegistryVerdict,
    HttpMethod,
    ServerAddress,
    HttpStatus,
    ErrorType,
    ExecSite,
    ExecName,
    ExecOutcome,
    ExitCode,
    Format,
    SkipCount,
    SearchDirs,
    ProbeMcp,
    VerifyRegistry,
    Diff,
    ExposureFindings,
    ScannersRun,
}

impl Key {
    pub const ALL: &[Key] = &[
        Key::Scanner,
        Key::Phase,
        Key::RootIndex,
        Key::RootKind,
        Key::FilesRead,
        Key::FilesMissing,
        Key::Items,
        Key::DurationMs,
        Key::McpServerIndex,
        Key::McpOutcome,
        Key::McpTools,
        Key::McpResources,
        Key::RegistryIndex,
        Key::RegistryVerdict,
        Key::HttpMethod,
        Key::ServerAddress,
        Key::HttpStatus,
        Key::ErrorType,
        Key::ExecSite,
        Key::ExecName,
        Key::ExecOutcome,
        Key::ExitCode,
        Key::Format,
        Key::SkipCount,
        Key::SearchDirs,
        Key::ProbeMcp,
        Key::VerifyRegistry,
        Key::Diff,
        Key::ExposureFindings,
        Key::ScannersRun,
    ];

    /// The exported key. Generic concepts use the OpenTelemetry semantic-convention
    /// names (`error.type`, `http.response.status_code`, `process.executable.name`, ...);
    /// rmguard-specific ones live under `rmguard.`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Key::Scanner => "rmguard.scanner",
            Key::Phase => "rmguard.phase",
            Key::RootIndex => "rmguard.root.index",
            Key::RootKind => "rmguard.root.kind",
            Key::FilesRead => "rmguard.files.read",
            Key::FilesMissing => "rmguard.files.missing",
            Key::Items => "rmguard.items",
            Key::DurationMs => "rmguard.duration_ms",
            Key::McpServerIndex => "rmguard.mcp.server_index",
            Key::McpOutcome => "rmguard.mcp.outcome",
            Key::McpTools => "rmguard.mcp.tools",
            Key::McpResources => "rmguard.mcp.resources",
            Key::RegistryIndex => "rmguard.registry.index",
            Key::RegistryVerdict => "rmguard.registry.verdict",
            Key::HttpMethod => "http.request.method",
            Key::ServerAddress => "server.address",
            Key::HttpStatus => "http.response.status_code",
            Key::ErrorType => "error.type",
            Key::ExecSite => "rmguard.exec.site",
            Key::ExecName => "process.executable.name",
            Key::ExecOutcome => "rmguard.exec.outcome",
            Key::ExitCode => "process.exit.code",
            Key::Format => "rmguard.format",
            Key::SkipCount => "rmguard.skip.count",
            Key::SearchDirs => "rmguard.search_dirs.count",
            Key::ProbeMcp => "rmguard.probe_mcp",
            Key::VerifyRegistry => "rmguard.verify_registry",
            Key::Diff => "rmguard.diff",
            Key::ExposureFindings => "rmguard.exposure_findings",
            Key::ScannersRun => "rmguard.scanners_run",
        }
    }
}

/// One attribute. The value enum is private: the constructors below are the only way
/// to make one, and only two of them accept runtime text, both sanitized.
#[cfg_attr(not(feature = "otel"), allow(dead_code))]
pub struct Attr(Key, V);

#[cfg_attr(not(feature = "otel"), allow(dead_code))]
enum V {
    S(&'static str),
    Owned(String),
    I(i64),
    B(bool),
}

/// Maximum characters of runtime text in one attribute value.
const MAX_ATTR_CHARS: usize = 64;

/// Token prefixes of widely used credentials, from each vendor's published token format
/// (GitHub ghp_/gho_/ghu_/ghs_/ghr_/github_pat_, Anthropic sk-ant-, OpenAI sk-, GitLab
/// glpat-, Slack xox?-, Hugging Face hf_, AWS AKIA/ASIA, Google AIza).
/// `redact_secrets_in_text` keys on *context* (`token=`, URL userinfo, Authorization);
/// a bare token has none, so attribute text also drops any word that starts like one.
/// Nothing legitimate in a scanner label or a program basename looks like this.
const CREDENTIAL_PREFIXES: &[&str] = &[
    "sk-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "xoxa-", "xoxb-",
    "xoxp-", "xoxs-", "hf_", "AKIA", "ASIA", "AIza",
];

fn is_word_sep(c: char) -> bool {
    c.is_whitespace() || matches!(c, '/' | '=' | ':' | ',' | '"' | '\'')
}

fn clean(s: &str) -> String {
    let redacted = crate::scanners::redact_secrets_in_text(s);
    let mut out = String::with_capacity(redacted.len());
    for piece in redacted.split_inclusive(is_word_sep) {
        let word = piece.trim_end_matches(is_word_sep);
        let sep = &piece[word.len()..];
        let bare = word.trim_start_matches(|c: char| !c.is_ascii_alphanumeric());
        if CREDENTIAL_PREFIXES.iter().any(|p| bare.starts_with(p)) {
            out.push_str("[redacted]");
        } else {
            out.push_str(word);
        }
        out.push_str(sep);
    }
    crate::scanners::sanitize_display(&out, MAX_ATTR_CHARS)
}

impl Attr {
    /// A compile-time string: a fixed category, phase name or outcome.
    pub fn str(key: Key, value: &'static str) -> Attr {
        Attr(key, V::S(value))
    }
    pub fn int(key: Key, value: i64) -> Attr {
        Attr(key, V::I(value))
    }
    pub fn bool(key: Key, value: bool) -> Attr {
        Attr(key, V::B(value))
    }
    /// A scanner label (`mcp`, `packages`, ...). Labels are ours, but the value is
    /// sanitized anyway so this constructor cannot become a side door.
    pub fn scanner(label: &str) -> Attr {
        Attr(Key::Scanner, V::Owned(clean(label)))
    }
    /// The basename of an executed program (`git`, `ssh-keygen`). The directory is
    /// dropped: it can be the user's home or a project path.
    pub fn exec_name(program: &OsStr) -> Attr {
        let base = std::path::Path::new(program)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Attr(Key::ExecName, V::Owned(clean(&base)))
    }

    pub fn key(&self) -> Key {
        self.0
    }
}

/// Metric instruments. Names and units are listed in docs/OPENTELEMETRY.md.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Metric {
    ScanDuration,
    ScannerDuration,
    FilesRead,
    FilesMissing,
    Items,
    Skipped,
    ExecDuration,
    McpProbeDuration,
    RegistryLookupDuration,
}

/// Why `--otel` did not turn export on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitError {
    /// This binary was built without the `otel` cargo feature.
    NotCompiled,
    /// `OTEL_SDK_DISABLED=true`, or both `OTEL_TRACES_EXPORTER` and
    /// `OTEL_METRICS_EXPORTER` are `none`.
    Disabled,
    /// The OTLP exporter rejected the `OTEL_EXPORTER_OTLP_*` configuration. The inner
    /// error is deliberately not kept: it echoes the endpoint, which may hold userinfo.
    Config,
}

/// Is export on? One relaxed atomic load; constant `false` without the feature.
#[inline(always)]
pub fn enabled() -> bool {
    sdk::enabled()
}

/// An open span, attached as the current context until dropped. `None` when disabled.
/// Guards must be dropped in reverse order of creation; block scoping does that.
#[must_use = "a span ends when its guard is dropped"]
pub struct SpanGuard(Option<sdk::Live>);

impl SpanGuard {
    /// A guard that records nothing.
    pub const fn none() -> SpanGuard {
        SpanGuard(None)
    }

    /// Add attributes. The closure is not called when export is off.
    #[inline]
    pub fn set(&mut self, attrs: impl FnOnce() -> Vec<Attr>) {
        if let Some(live) = &mut self.0 {
            live.set(attrs());
        }
    }

    /// Mark the span failed with a fixed category (never free text).
    #[inline]
    pub fn error(&mut self, category: &'static str) {
        if let Some(live) = &mut self.0 {
            live.error(category);
        }
    }

    /// End the span exactly `elapsed` after its start, so its duration agrees with a
    /// duration the caller measured with `Instant` and reported elsewhere.
    #[inline]
    pub fn finish_after(mut self, elapsed: Duration) {
        if let Some(live) = self.0.take() {
            live.finish_after(elapsed);
        }
    }
}

/// Open a span named `name` as a child of the current span.
#[inline]
pub fn span(name: &'static str, attrs: impl FnOnce() -> Vec<Attr>) -> SpanGuard {
    if !enabled() {
        return SpanGuard(None);
    }
    SpanGuard(sdk::start(name.into(), false, attrs()))
}

/// Like [`span`], with a name computed only when export is on.
#[inline]
pub fn span_with(name: impl FnOnce() -> String, attrs: impl FnOnce() -> Vec<Attr>) -> SpanGuard {
    if !enabled() {
        return SpanGuard(None);
    }
    SpanGuard(sdk::start(name().into(), false, attrs()))
}

/// Like [`span`], with SpanKind::Client: an outbound call (MCP probe, registry lookup).
#[inline]
pub fn client_span(name: &'static str, attrs: impl FnOnce() -> Vec<Attr>) -> SpanGuard {
    if !enabled() {
        return SpanGuard(None);
    }
    SpanGuard(sdk::start(name.into(), true, attrs()))
}

/// Add attributes to whatever span is current (used where the span is opened by a caller).
#[inline]
pub fn annotate_current(attrs: impl FnOnce() -> Vec<Attr>) {
    if enabled() {
        sdk::annotate_current(attrs());
    }
}

/// Record one metric value. Durations are seconds; counters are cast to u64.
#[inline]
pub fn record(metric: Metric, value: f64, attrs: impl FnOnce() -> Vec<Attr>) {
    if enabled() {
        sdk::record(metric, value, attrs());
    }
}

/// The per-scanner metrics for one finished scanner: duration plus the three counts.
#[inline]
pub fn record_scanner(stat: &ScannerStat, elapsed: Duration) {
    if enabled() {
        sdk::record_scanner(stat, elapsed);
    }
}

/// A subprocess span: `exec.<site>`, with the program's basename. Set the outcome before
/// it drops; its duration is recorded as `rmguard.exec.duration` on drop.
#[inline]
pub fn exec_span(site: &'static str, program: &OsStr) -> ExecSpan {
    if !enabled() {
        return ExecSpan(None);
    }
    let guard = span_with(
        || format!("exec.{site}"),
        || vec![Attr::str(Key::ExecSite, site), Attr::exec_name(program)],
    );
    ExecSpan(Some(ExecInner { guard, start: Instant::now(), site, outcome: None }))
}

#[must_use = "an exec span ends when dropped"]
pub struct ExecSpan(Option<ExecInner>);

struct ExecInner {
    guard: SpanGuard,
    start: Instant,
    site: &'static str,
    outcome: Option<&'static str>,
}

impl ExecSpan {
    /// A fixed outcome category: ok, nonzero, spawn_failed, timeout, wait_failed.
    #[inline]
    pub fn outcome(&mut self, outcome: &'static str) {
        if let Some(inner) = &mut self.0 {
            inner.outcome = Some(outcome);
        }
    }

    #[inline]
    pub fn exit_code(&mut self, code: i32) {
        if let Some(inner) = &mut self.0 {
            inner.guard.set(|| vec![Attr::int(Key::ExitCode, i64::from(code))]);
        }
    }
}

impl Drop for ExecSpan {
    fn drop(&mut self) {
        let Some(inner) = self.0.take() else { return };
        let ExecInner { mut guard, start, site, outcome } = inner;
        let elapsed = start.elapsed();
        let outcome = outcome.unwrap_or("unknown");
        guard.set(|| vec![Attr::str(Key::ExecOutcome, outcome)]);
        // A non-zero exit is an answer (git: "not tracked"), not a failure of the call.
        if matches!(outcome, "spawn_failed" | "timeout" | "wait_failed") {
            guard.error(outcome);
        }
        guard.finish_after(elapsed);
        record(Metric::ExecDuration, elapsed.as_secs_f64(), || {
            vec![Attr::str(Key::ExecSite, site), Attr::str(Key::ExecOutcome, outcome)]
        });
    }
}

/// Start export. Called once, only when `--otel` was given. Builds the exporters,
/// providers and their background threads; until this returns `Ok`, nothing exists.
pub fn init() -> Result<(), InitError> {
    sdk::init()
}

/// Flush and stop export, bounded at 2 s. Safe to call more than once and when off.
/// Prints at most one warning line to stderr; never touches stdout.
pub fn shutdown() {
    sdk::shutdown()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(a: &Attr) -> String {
        match &a.1 {
            V::S(s) => s.to_string(),
            V::Owned(s) => s.clone(),
            V::I(i) => i.to_string(),
            V::B(b) => b.to_string(),
        }
    }

    /// Lib unit tests never call init(), so export is off in-process; every entry point
    /// must then return without evaluating its closures.
    #[test]
    fn disabled_path_never_evaluates_closures() {
        assert!(!enabled());
        let mut s = span("x", || panic!("attrs evaluated while disabled"));
        s.set(|| panic!("set evaluated while disabled"));
        s.error("timeout");
        drop(s);
        let s = span_with(|| panic!("name evaluated while disabled"), || panic!("attrs evaluated"));
        s.finish_after(Duration::from_millis(1));
        let c = client_span("x", || panic!("client attrs evaluated while disabled"));
        drop(c);
        annotate_current(|| panic!("annotate evaluated while disabled"));
        record(Metric::Skipped, 1.0, || panic!("record attrs evaluated while disabled"));
        let mut x = exec_span("site", OsStr::new("/usr/bin/git"));
        assert!(x.0.is_none(), "exec span allocated state while disabled");
        x.outcome("ok");
        x.exit_code(0);
        drop(x);
        record_scanner(
            &ScannerStat {
                scanner: "mcp".into(),
                root: None,
                duration_ms: 0,
                files_read: 0,
                files_missing: 0,
                items: 0,
                skipped: false,
            },
            Duration::ZERO,
        );
    }

    #[test]
    fn attr_scanner_and_exec_name_sanitize() {
        for evil in [
            "a\x1b[32mb",
            "a\u{9b}31mb",
            "a\r\nb",
            "a\u{2028}b",
            "a\u{202e}b",
            "a\u{2066}b",
        ] {
            let v = text(&Attr::scanner(evil));
            assert!(
                !v.chars().any(|c| c.is_control()
                    || ('\u{80}'..='\u{9f}').contains(&c)
                    || matches!(c, '\u{2028}' | '\u{202e}' | '\u{2066}')),
                "unsanitized: {v:?}"
            );
            assert!(v.starts_with('a') && v.ends_with('b'), "{v:?}");
        }
        let long = "x".repeat(200);
        let v = text(&Attr::scanner(&long));
        assert_eq!(v.chars().count(), MAX_ATTR_CHARS + 1);
        assert!(v.ends_with('…'));

        for (canary, secret) in [
            ("key sk-ant-api03-E2EOTELCANARY", "E2EOTELCANARY"),
            ("tok ghp_E2EOTELCANARY0000000000000000000000", "E2EOTELCANARY"),
            ("url https://u:E2EOTELPW@h/", "E2EOTELPW"),
        ] {
            let v = text(&Attr::scanner(canary));
            assert!(!v.contains(secret), "secret survived: {v:?}");
        }

        let a = Attr::exec_name(OsStr::new("/home/x/E2EDIR/bin/git"));
        assert_eq!(a.key(), Key::ExecName);
        assert_eq!(text(&a), "git");
        assert_eq!(text(&Attr::exec_name(OsStr::new("ssh-keygen"))), "ssh-keygen");
        let v = text(&Attr::exec_name(OsStr::new("/tmp/ghp_E2EOTELCANARY0000000000000000000000")));
        assert!(!v.contains("E2EOTELCANARY"), "{v:?}");
        let v = text(&Attr::exec_name(OsStr::new("/tmp/evil\x1b[2Jname")));
        assert!(!v.contains('\x1b'), "{v:?}");
    }

    #[test]
    fn keys_are_unique_and_well_formed() {
        let mut seen = std::collections::HashSet::new();
        for k in Key::ALL {
            let s = k.as_str();
            assert!(seen.insert(s), "duplicate key {s}");
            let mut chars = s.chars();
            assert!(chars.next().is_some_and(|c| c.is_ascii_lowercase()), "{s}");
            assert!(
                chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.'),
                "{s}"
            );
        }
        assert_eq!(Key::ALL.len(), 30, "a Key variant is missing from Key::ALL");
        assert_eq!(Key::ExecName.as_str(), "process.executable.name");
        assert_eq!(Key::HttpStatus.as_str(), "http.response.status_code");
        assert_eq!(Key::ErrorType.as_str(), "error.type");
    }
}
