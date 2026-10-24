//! OpenTelemetry export of scan timing: OFF unless the user passes `--otel`.
//!
//! This module is the only door between the scanner and the OpenTelemetry SDK, and it is
//! shaped so that the door cannot carry scan content:
//!
//! * Attribute keys are a closed enum ([`Key`]); there is no free-form key.
//! * Attribute values are built only through [`Attr`]'s constructors, and none of them
//!   accepts runtime text: strings are `&'static str` (a scanner label, a phase name, an
//!   outcome category), everything else is an integer or a boolean. There is nothing to
//!   sanitize because nothing a scan read can be passed in; a `String` does not
//!   compile:
//!
//! ```compile_fail,E0597
//! let label = String::from("read from disk");
//! let _ = rustmachineguard::otel::Attr::scanner(&label);
//! ```
//! * Span names are `&'static str`, or a static prefix joined to a static label
//!   (`scanner.<label>`, `exec.<site>`) by [`span_with`] itself, which accepts no
//!   runtime text either:
//!
//! ```compile_fail,E0597
//! let root = String::from("/home/u/.cursor/mcp.json");
//! let _g = rustmachineguard::otel::span_with("scanner.", &root, Vec::new);
//! ```
//!
//! (The same call with two literals compiles; see [`span_with`].) The one way around
//! both checks is to leak a `String` into a `&'static str` (`String::leak`,
//! `Box::leak`); `src/otel/` and the call sites contain none, and a reviewer should
//! treat one near an `Attr` or span name as a finding.
//!
//! Nothing here reads paths, server or package names, commands, arguments,
//! environment values, URLs or error text into telemetry. The one runtime-text input is
//! [`exec_program`], which maps a spawned program to an entry of the fixed
//! [`EXEC_PROGRAMS`] table or the literal `other`; the value exported is always the
//! table's own `&'static str`. See docs/OPENTELEMETRY.md.
//!
//! Disabled cost: every entry point checks one `Relaxed` atomic (a constant `false` in a
//! build without the `otel` feature) and returns before evaluating any closure or
//! allocating. Call sites that time something read `Instant::now()` only when
//! [`enabled`] says so.

use crate::models::ScannerStat;
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
    pub fn start(
        _: std::borrow::Cow<'static, str>,
        _: bool,
        _: Vec<Attr>,
        _: Option<std::time::Instant>,
    ) -> Option<Live> {
        None
    }
    #[inline(always)]
    pub fn annotate_current(_: Vec<Attr>) {}
    #[inline(always)]
    pub fn record(_: Metric, _: f64, _: Vec<Attr>) {}
    #[inline(always)]
    pub fn record_scanner(_: &'static str, _: &ScannerStat, _: Duration) {}
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
    ExecProgram,
    WalkKind,
    WalkScope,
    WalkRootLink,
    WalkEntries,
    WalkDirs,
    WalkFiles,
    WalkBytes,
    WalkBytesHashed,
    WalkHooks,
    WalkBudgetExhausted,
    Repos,
    SkillsProjects,
    TranscriptsFramework,
    TranscriptsKind,
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
        Key::ExecProgram,
        Key::WalkKind,
        Key::WalkScope,
        Key::WalkRootLink,
        Key::WalkEntries,
        Key::WalkDirs,
        Key::WalkFiles,
        Key::WalkBytes,
        Key::WalkBytesHashed,
        Key::WalkHooks,
        Key::WalkBudgetExhausted,
        Key::Repos,
        Key::SkillsProjects,
        Key::TranscriptsFramework,
        Key::TranscriptsKind,
    ];

    /// The exported key. Generic concepts use the OpenTelemetry semantic-convention
    /// names (`error.type`, `http.response.status_code`, `process.exit.code`, ...);
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
            Key::ExecProgram => "rmguard.exec.program",
            Key::WalkKind => "rmguard.walk.kind",
            Key::WalkScope => "rmguard.walk.scope",
            Key::WalkRootLink => "rmguard.walk.root_link",
            Key::WalkEntries => "rmguard.walk.entries",
            Key::WalkDirs => "rmguard.walk.dirs",
            Key::WalkFiles => "rmguard.walk.files",
            Key::WalkBytes => "rmguard.walk.bytes",
            Key::WalkBytesHashed => "rmguard.walk.bytes_hashed",
            Key::WalkHooks => "rmguard.walk.hooks",
            Key::WalkBudgetExhausted => "rmguard.walk.budget_exhausted",
            Key::Repos => "rmguard.repos",
            Key::SkillsProjects => "rmguard.skills.projects",
            Key::TranscriptsFramework => "rmguard.transcripts.framework",
            Key::TranscriptsKind => "rmguard.transcripts.kind",
        }
    }
}

/// One attribute. The value enum is private: the constructors below are the only way
/// to make one, and none of them accepts runtime text.
#[cfg_attr(not(feature = "otel"), allow(dead_code))]
pub struct Attr(Key, V);

#[cfg_attr(not(feature = "otel"), allow(dead_code))]
enum V {
    S(&'static str),
    I(i64),
    B(bool),
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
    /// A scanner label (`mcp`, `packages`, ...): a string literal at every call site.
    pub fn scanner(label: &'static str) -> Attr {
        Attr(Key::Scanner, V::S(label))
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
    SpanGuard(sdk::start(name.into(), false, attrs(), None))
}

/// Like [`span`], named `<prefix><label>`. Both parts are `&'static str`, so a name can
/// only be assembled from compile-time text; it is formatted only when export is on.
///
/// ```
/// let _g = rustmachineguard::otel::span_with("scanner.", "mcp", Vec::new);
/// ```
#[inline]
pub fn span_with(prefix: &'static str, label: &'static str, attrs: impl FnOnce() -> Vec<Attr>) -> SpanGuard {
    if !enabled() {
        return SpanGuard(None);
    }
    SpanGuard(sdk::start(format!("{prefix}{label}").into(), false, attrs(), None))
}

/// Like [`span_with`], but the span starts at `at`, an `Instant` the caller already read
/// to time the same work. Ended with [`SpanGuard::finish_after`] and the elapsed time
/// measured from that same instant, the span is exactly the measured interval, so every
/// child opened during the work ends inside it. (Opening the span first and reading the
/// clock second left the parent ending a few microseconds before its last child.)
#[inline]
pub fn span_with_at(
    prefix: &'static str,
    label: &'static str,
    at: Instant,
    attrs: impl FnOnce() -> Vec<Attr>,
) -> SpanGuard {
    if !enabled() {
        return SpanGuard(None);
    }
    SpanGuard(sdk::start(format!("{prefix}{label}").into(), false, attrs(), Some(at)))
}

/// Like [`span`], with SpanKind::Client: an outbound call (MCP probe, registry lookup).
#[inline]
pub fn client_span(name: &'static str, attrs: impl FnOnce() -> Vec<Attr>) -> SpanGuard {
    if !enabled() {
        return SpanGuard(None);
    }
    SpanGuard(sdk::start(name.into(), true, attrs(), None))
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
/// `label` is the same static label as `stat.scanner`.
#[inline]
pub fn record_scanner(label: &'static str, stat: &ScannerStat, elapsed: Duration) {
    if enabled() {
        sdk::record_scanner(label, stat, elapsed);
    }
}

/// The programs rmguard itself chooses to run, by basename: the value set of
/// `rmguard.exec.program`. Every `--version` probe, verification run, `git`, the
/// process-list snapshot and `ssh-keygen`; `tests` in `crate::scanners` keep it in step
/// with the scanners' binary tables. Anything else (a renamed binary, a desktop app's
/// own executable name, an MCP server command, which never reaches [`exec_span`]) is
/// exported as `other`.
pub const EXEC_PROGRAMS: &[&str] = &[
    // rmguard's own helpers
    "git", "ps", "ssh-keygen",
    // node toolchain (scanner.node)
    "node", "npm", "yarn", "pnpm", "bun",
    // AI CLIs and agents (scanner.ai)
    "claude", "claude-desktop", "copilot", "gh-copilot", "github-copilot-cli", "ghcs", "codex",
    "gemini", "amazon-q", "cursor-agent", "kiro-cli", "kiro", "aish", "opencode", "aider",
    "continue", "cody", "openclaw", "clawdbot", "moltbot", "moldbot", "gpt-engineer", "gpte",
    "interpreter", "goose", "tabby",
    // local model servers (scanner.frameworks)
    "ollama", "local-ai", "localai", "lms", "llama-server", "llama-cli", "vllm",
    "text-generation-launcher", "textgen",
    // container runtimes (scanner.containers)
    "docker", "podman", "nerdctl", "limactl", "colima", "rdctl", "finch",
    // notebook servers (scanner.notebooks)
    "jupyter-notebook", "jupyter-lab", "jupyter", "marimo",
    // IDE launchers (scanner.ide)
    "code", "cursor", "windsurf", "zed", "antigravity",
];

/// `program`'s basename if it is one of [`EXEC_PROGRAMS`], else `other`. The input is
/// runtime text (a resolved path such as `/home/u/.local/bin/claude`), but the output
/// is always one of the table's own `&'static str` entries or the literal `other`: the
/// path, and any name outside the table, cannot come back out.
pub fn exec_program(program: &std::ffi::OsStr) -> &'static str {
    let base = std::path::Path::new(program).file_name().unwrap_or(program);
    EXEC_PROGRAMS.iter().copied().find(|p| std::ffi::OsStr::new(p) == base).unwrap_or("other")
}

/// A subprocess span: `exec.<site>`, with `rmguard.exec.program` set to
/// [`exec_program`]`(program)`: a basename from the fixed table, or `other`. The
/// program is classified only when export is on. Set the outcome before it drops; its
/// duration is recorded as `rmguard.exec.duration` on drop.
#[inline]
pub fn exec_span(site: &'static str, program: &std::ffi::OsStr) -> ExecSpan {
    if !enabled() {
        return ExecSpan(None);
    }
    let program = exec_program(program);
    let guard = span_with("exec.", site, || {
        vec![Attr::str(Key::ExecSite, site), Attr::str(Key::ExecProgram, program)]
    });
    ExecSpan(Some(ExecInner { guard, start: Instant::now(), site, program, outcome: None }))
}

#[must_use = "an exec span ends when dropped"]
pub struct ExecSpan(Option<ExecInner>);

struct ExecInner {
    guard: SpanGuard,
    start: Instant,
    site: &'static str,
    program: &'static str,
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
        let ExecInner { mut guard, start, site, program, outcome } = inner;
        let elapsed = start.elapsed();
        let outcome = outcome.unwrap_or("unknown");
        guard.set(|| vec![Attr::str(Key::ExecOutcome, outcome)]);
        // A non-zero exit is an answer (git: "not tracked"), not a failure of the call.
        if matches!(outcome, "spawn_failed" | "timeout" | "wait_failed") {
            guard.error(outcome);
        }
        guard.finish_after(elapsed);
        record(Metric::ExecDuration, elapsed.as_secs_f64(), || {
            vec![
                Attr::str(Key::ExecSite, site),
                Attr::str(Key::ExecProgram, program),
                Attr::str(Key::ExecOutcome, outcome),
            ]
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
        let s = span_with("scanner.", "mcp", || panic!("attrs evaluated while disabled"));
        s.finish_after(Duration::from_millis(1));
        let c = client_span("x", || panic!("client attrs evaluated while disabled"));
        drop(c);
        annotate_current(|| panic!("annotate evaluated while disabled"));
        record(Metric::Skipped, 1.0, || panic!("record attrs evaluated while disabled"));
        let mut x = exec_span("site", std::ffi::OsStr::new("git"));
        assert!(x.0.is_none(), "exec span allocated state while disabled");
        x.outcome("ok");
        x.exit_code(0);
        drop(x);
        record_scanner(
            "mcp",
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

    /// Every attribute value is static text, an integer or a boolean: what goes in is
    /// exactly what is exported, with no runtime text to clean. (That `Attr::scanner`
    /// rejects a `String` is the module doc's compile_fail example.)
    #[test]
    fn attr_values_are_static_or_numeric() {
        let a = Attr::scanner("mcp");
        assert_eq!(a.key(), Key::Scanner);
        assert_eq!(text(&a), "mcp");
        assert_eq!(text(&Attr::str(Key::McpOutcome, "timeout")), "timeout");
        assert_eq!(text(&Attr::int(Key::Items, -3)), "-3");
        assert_eq!(text(&Attr::bool(Key::Diff, true)), "true");
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
        assert_eq!(Key::ALL.len(), 44, "a Key variant is missing from Key::ALL");
        assert!(
            !Key::ALL.iter().any(|k| k.as_str() == "process.executable.name"),
            "program names are a tool inventory and are not exported"
        );
        assert_eq!(Key::ExecProgram.as_str(), "rmguard.exec.program");
        assert_eq!(Key::HttpStatus.as_str(), "http.response.status_code");
        assert_eq!(Key::ErrorType.as_str(), "error.type");
    }

    /// `rmguard.exec.program` is a closed set: a listed basename, or `other`. Paths are
    /// reduced to the basename; nothing outside the table comes back, whatever the input.
    #[test]
    fn exec_program_is_a_closed_set() {
        use std::ffi::OsStr;
        assert_eq!(exec_program(OsStr::new("git")), "git");
        assert_eq!(exec_program(OsStr::new("/usr/bin/git")), "git");
        assert_eq!(exec_program(OsStr::new("/home/u/.local/bin/claude")), "claude");
        assert_eq!(exec_program(OsStr::new("/home/u/E2EOTEL/evil-server")), "other");
        assert_eq!(exec_program(OsStr::new("node --inspect")), "other");
        assert_eq!(exec_program(OsStr::new("Claude")), "other", "case-sensitive, like the spawn");
        assert_eq!(exec_program(OsStr::new("")), "other");
        assert_eq!(exec_program(OsStr::new("/nonexistent/rmguard-no-git")), "other");
        let mut seen = std::collections::HashSet::new();
        for p in EXEC_PROGRAMS {
            assert!(seen.insert(p), "duplicate {p}");
            assert!(!p.contains('/') && !p.contains(' ') && !p.is_empty(), "{p:?} is not a basename");
            assert_eq!(exec_program(OsStr::new(p)), *p);
        }
        assert!(!EXEC_PROGRAMS.contains(&"other"));
    }
}
