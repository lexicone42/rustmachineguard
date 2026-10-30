use clap::{Parser, ValueEnum};
use rustmachineguard::models::{self, ScanReport};
use rustmachineguard::otel::{self, Attr, Key, Metric};
use rustmachineguard::output::{self, OutputFormat};
use rustmachineguard::platform::{self, PlatformInfo};
use rustmachineguard::scanners::telemetry::{self, timed};
use rustmachineguard::scanners::{self, Scanner};
use std::path::PathBuf;
use std::time::Instant;

/// AI-agent posture scanner for developer machines.
///
/// Inventories coding agents, MCP servers, IDE/browser extensions, agent skills and
/// hooks, at-rest credentials, registry configs and git auto-execution settings; matches
/// them against a sourced threat catalog; probes MCP servers live; diffs scans over time;
/// emits a CycloneDX 2.0 Blueprint and compliance evidence. Runs locally; sends nothing
/// unless --verify-registry or --otel is given.
///
/// Began as a Rust rewrite of step-security/dev-machine-guard (Apache-2.0); see NOTICE.
#[derive(Parser)]
#[command(
    name = "rmguard",
    version = concat!(env!("CARGO_PKG_VERSION"), " (threat catalog ", rustmachineguard::builtin_catalog_version!(), ")"),
    about
)]
struct Cli {
    /// Output format
    #[arg(short, long, default_value = "terminal")]
    format: Format,

    /// Write output to a file instead of stdout
    #[arg(short, long)]
    output: Option<String>,

    /// Skip specific scanner categories (comma-separated)
    #[arg(long, value_delimiter = ',')]
    skip: Vec<String>,

    /// Search additional directories as alternate home roots (comma-separated).
    /// When set, home-rooted scanners (mcp, ssh, cloud, extensions, shell)
    /// run once per directory and merge results.
    #[arg(long, value_delimiter = ',')]
    search_dirs: Vec<PathBuf>,

    /// Path to additional JSON threat catalog for exposure matching (merged with built-in catalog).
    /// Format: array of {"ecosystem":"npm","name":"pkg","version":"1.0","advisory":"..."}
    #[arg(long)]
    threat_catalog: Option<PathBuf>,

    /// Disable the built-in threat catalog (only use --threat-catalog if provided)
    #[arg(long)]
    no_builtin_catalog: bool,

    /// Compare against a baseline scan (JSON format from a previous --format json run).
    /// Shows added, removed, and changed items across all categories. With --diff,
    /// stdout is the diff; -o receives the scan (in --format); --fail-on still applies.
    #[arg(long)]
    diff: Option<PathBuf>,

    /// Live-probe local (stdio) MCP servers to enumerate their tools and resources.
    /// WARNING: This spawns each MCP server process. Only use on trusted configurations.
    #[arg(long)]
    probe_mcp: bool,

    /// Aggregate a directory of `--format json` scans into one fleet HTML dashboard.
    /// Does not scan the local machine; reads existing scan files instead.
    #[arg(long, value_name = "DIR")]
    report: Option<PathBuf>,

    /// Verify discovered MCP servers against the official MCP registry
    /// (registry.modelcontextprotocol.io). NETWORK: sends server package names to the
    /// registry. Flags deprecated servers and possible typosquats; notes provenance.
    #[arg(long)]
    verify_registry: bool,

    /// Exit with code 3 if any finding at or above this severity is present, after
    /// printing the report as usual (with --diff too: the gate is on the current scan).
    /// For CI / fleet-onboarding gates (e.g. fail a machine's check on any Critical).
    /// Operational errors exit 1, command-line usage errors 2.
    #[arg(long, value_name = "SEVERITY")]
    fail_on: Option<FailOn>,

    /// Append a per-scanner diagnostics table to the terminal report: duration, files
    /// read, files missing, items. Tells "clean machine" apart from "looked in the
    /// wrong place". Always present in JSON output as `diagnostics`.
    #[arg(long)]
    verbose: bool,

    /// Print every file the scanners open or find missing to stderr, as it happens.
    /// Paths only, never contents. Same as RMGUARD_TRACE=1.
    #[arg(long)]
    trace: bool,

    /// Export OpenTelemetry traces and metrics for this scan (time per scanner, MCP probe,
    /// registry lookup and instrumented subprocess) over OTLP http/protobuf. NETWORK, off by default:
    /// setting OTEL_EXPORTER_OTLP_ENDPOINT alone never enables export; it only picks where
    /// --otel sends (default http://localhost:4318; OTEL_EXPORTER_OTLP_{TRACES,METRICS}_ENDPOINT
    /// and OTEL_EXPORTER_OTLP_HEADERS honored). Exports labels, counts and durations only —
    /// never paths, server or package names, or secret values. OTEL_SDK_DISABLED=true wins.
    #[arg(long)]
    otel: bool,

    /// Name this machine in the OpenTelemetry export: sets the resource's
    /// `service.instance.id` to ID (an asset tag, an inventory number), so a fleet's
    /// series do not all land on the same labels. Exported exactly as typed (surrounding
    /// whitespace removed; at most 128 characters, no control characters). rmguard never
    /// derives it from the host name, the user or any file. Requires --otel.
    #[arg(long, value_name = "ID", requires = "otel", value_parser = parse_otel_instance)]
    otel_instance: Option<String>,

    /// Scanners run side by side within each scan phase, on at most N threads
    /// (default: the machine's available parallelism, at most 8). 1 runs them one after
    /// another on the main thread. The report is the same whatever N is: results and
    /// diagnostics rows keep the fixed scanner order.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u16).range(1..=64))]
    jobs: Option<u16>,

    /// Directories listed per project by the gitconfig nested-repository walk (default
    /// 25,000); the other walk caps (the skills bundle walk's files and entries, the
    /// transcript file counts) scale in the same ratio. Coverage over speed: a larger
    /// budget walks bigger untagged data trees to the end at the order of 10 ms per
    /// thousand directories on one thread; a walk that still reaches it stops and is marked `partial`
    /// (`truncated` in JSON). Must be at least 1.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u64).range(1..))]
    walk_budget: Option<u64>,
}

/// Exit status when `--fail-on` trips. Not 2: that is the argument parser's usage-error
/// status, and a scheduled job with a typo must not look like a machine with findings.
/// Operational errors exit 1.
const FINDINGS_GATE_EXIT: i32 = 3;

/// Severity threshold for `--fail-on`, ordered most- to least-severe.
#[derive(Clone, Copy, ValueEnum)]
enum FailOn {
    Critical,
    High,
    Medium,
    Low,
}

impl FailOn {
    /// The analysis severity this threshold corresponds to.
    fn as_severity(self) -> rustmachineguard::analysis::Severity {
        use rustmachineguard::analysis::Severity;
        match self {
            FailOn::Critical => Severity::Critical,
            FailOn::High => Severity::High,
            FailOn::Medium => Severity::Medium,
            FailOn::Low => Severity::Low,
        }
    }
}

#[derive(Clone, ValueEnum)]
enum Format {
    Terminal,
    Json,
    Html,
    Sbom,
    /// CycloneDX 2.0 Blueprint (draft) — agent posture with assets, behaviors, flows
    Blueprint,
    /// Compliance coverage: maps findings/inventory to NSA-CISA / OWASP / EU AI Act controls
    Compliance,
}

const VALID_SKIP: &[&str] = &[
    "ai",
    "frameworks",
    "ide",
    "extensions",
    "mcp",
    "node",
    "shell",
    "ssh",
    "authkeys",
    "cloud",
    "containers",
    "notebooks",
    "browser",
    "packages",
    "rules",
    "skills",
    "settings",
    "aicreds",
    "envfiles",
    "transcripts",
    "marketplaces",
    "vscodetasks",
    "gitconfig",
    "pypkgs",
    "npmpkgs",
    "jbplugins",
    "persistence",
    "lsp",
    "liveness",
    "playwright",
    "vibe",
    "statusline",
    "listeners",
    "agents",
];

/// One scanner of a phase, ready to run on any thread: it returns its diagnostics row
/// and a closure that stores its results in the report. Results are stored, and rows
/// pushed, in the phase's fixed scanner order after every job has finished
/// ([`run_jobs`]), so nothing in the report depends on which job finished first.
struct Job<'a> {
    label: &'static str,
    run: Box<dyn FnOnce() -> Done<'a> + Send + 'a>,
}

/// A finished [`Job`]: its row-to-be and the store of its results.
struct Done<'a> {
    pending: telemetry::Pending,
    store: Box<dyn FnOnce(&mut ScanReport) + Send + 'a>,
}

impl Done<'_> {
    /// Finalize the row (in the fixed order: see [`telemetry::Pending`]), push it, and
    /// store the results.
    fn apply(self, report: &mut ScanReport) {
        report.diagnostics.push(self.pending.finalize());
        (self.store)(report);
    }
}

/// A [`Job`] that runs `scan` under [`telemetry::run`] (its own span, read counters and
/// budgets on the thread it runs on) and hands the results to `store`.
fn job<'a, T: Send + 'a>(
    label: &'static str,
    root: Option<PathBuf>,
    scan: impl FnOnce() -> Vec<T> + Send + 'a,
    store: fn(&mut ScanReport, Vec<T>),
) -> Job<'a> {
    Job {
        label,
        run: Box::new(move || {
            let (out, pending) = telemetry::run(label, root, scan);
            Done {
                pending,
                store: Box::new(move |r: &mut ScanReport| store(r, out)),
            }
        }),
    }
}

/// Labels dispatched before the rest of a pool, whatever phase they belong to: the
/// scanners that, on a developer machine, take longest (the gitconfig project walk, the
/// skills plugin walk, the node toolchain probes). Started first, they overlap with all the
/// short ones instead of waiting behind them. Only the order jobs are TAKEN in depends on
/// this; results and rows are stored in the fixed scanner order whatever it says.
const DISPATCH_FIRST: &[&str] = &["gitconfig", "skills", "node"];

/// One phase of a pool: its jobs, in the fixed order their results are stored in, and the
/// span context (`phase.*`) their `scanner.*` spans nest under.
struct Phase<'a> {
    cx: otel::ParentContext,
    list: Vec<Job<'a>>,
}

/// Run every job of `phases` on up to `jobs` threads (this one and `jobs - 1` workers)
/// sharing one queue, and hand back each phase's finished jobs in that phase's order with
/// the instant each one finished. `jobs <= 1` is the plain sequential loop, on this
/// thread, phase after phase, each in order.
///
/// Before it runs a job, a thread makes that job's phase context current, so a
/// `scanner.*` span is a child of its own `phase.*` span whichever thread runs it, and
/// every span the scanner opens nests under it on that thread. Jobs are taken in the
/// [`DISPATCH_FIRST`] order, then in phase order. A worker that cannot be spawned is not an
/// error: the jobs it would have taken are run by the others, this thread included.
fn run_pool<'a>(phases: Vec<Phase<'a>>, jobs: usize) -> Vec<Vec<(Done<'a>, Instant)>> {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let total: usize = phases.iter().map(|p| p.list.len()).sum();
    let mut cxs = Vec::with_capacity(phases.len());
    let mut slots: Vec<(usize, &'static str, Mutex<Option<Job<'a>>>)> = Vec::with_capacity(total);
    for (pi, p) in phases.into_iter().enumerate() {
        cxs.push(p.cx);
        slots.extend(p.list.into_iter().map(|j| (pi, j.label, Mutex::new(Some(j)))));
    }
    let done: Vec<Mutex<Option<(Done<'a>, Instant)>>> = slots.iter().map(|_| Mutex::new(None)).collect();
    let run_one = |i: usize| {
        let (pi, _, slot) = &slots[i];
        let j = slot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .expect("each job is taken once");
        let d = {
            let _cx = cxs[*pi].attach();
            (j.run)()
        };
        *done[i].lock().unwrap_or_else(|e| e.into_inner()) = Some((d, Instant::now()));
    };
    if jobs <= 1 || total <= 1 {
        (0..total).for_each(run_one);
    } else {
        let mut order: Vec<usize> = (0..total).collect();
        // A stable sort: past the DISPATCH_FIRST labels, phase order then scanner order.
        order.sort_by_key(|&i| {
            DISPATCH_FIRST
                .iter()
                .position(|f| *f == slots[i].1)
                .unwrap_or(DISPATCH_FIRST.len())
        });
        let next = AtomicUsize::new(0);
        let work = || {
            while let Some(&i) = order.get(next.fetch_add(1, Ordering::Relaxed)) {
                run_one(i);
            }
        };
        std::thread::scope(|s| {
            for _ in 1..jobs.min(total) {
                // The main thread's stack size: a scanner's parse or walk must not get less
                // room on a worker than it had when the phase ran sequentially.
                let _ = std::thread::Builder::new()
                    .name("rmguard-scan".into())
                    .stack_size(8 << 20)
                    .spawn_scoped(s, work);
            }
            work();
        });
    }
    let mut out: Vec<Vec<(Done<'a>, Instant)>> = cxs.iter().map(|_| Vec::new()).collect();
    for ((pi, _, _), d) in slots.iter().zip(done) {
        out[*pi].push(
            d.into_inner()
                .unwrap_or_else(|e| e.into_inner())
                .expect("every job ran"),
        );
    }
    out
}

/// Run one phase's jobs ([`run_pool`]) under the span that is current here, then store
/// every result and push every diagnostics row in the jobs' order.
fn run_jobs(list: Vec<Job<'_>>, jobs: usize, report: &mut ScanReport) {
    for phase in run_pool(
        vec![Phase {
            cx: otel::current_context(),
            list,
        }],
        jobs,
    ) {
        for (d, _) in phase {
            d.apply(report);
        }
    }
}

/// The primary scan's two phases, `phase.global_scanners` and the first
/// `phase.home_pass`, run side by side in one pool of `jobs` threads ([`run_pool`]).
///
/// They are independent: the global scanners store only `ai_agents_and_tools`,
/// `ai_frameworks`, `ide_installations`, `node_package_managers`, `container_tools`,
/// `notebook_servers` and `surfaces.network_listeners`; the home scanners only `ide_extensions`, `mcp_configs`,
/// `shell_configs`, `ssh_keys`, `cloud_credentials`, `browser_extensions`,
/// `package_config_audits`, `rules_files`, `agent_skills`, `agent_settings`,
/// `ai_credentials`, `env_files`, `persistence_artifacts`, `transcripts`, `marketplaces`,
/// `vscode_tasks` and `git_autorun_configs`; every store runs here, after both phases.
/// Both push diagnostics rows, global rows first, then home rows, each in scanner order,
/// as when the phases ran one after the other. The shared caches they could both touch
/// are not shared in practice (the process-list snapshot is asked for only by global
/// scanners, the git-tracked listings only by home scanners) and are race-safe anyway.
///
/// Each phase span is a child of the span current here (`rmguard.scan`), starts when the
/// pool starts and ends when the last of its scanners finished. `jobs <= 1` runs the two
/// phases one after the other, each span ending before the next starts, as before.
fn run_primary_phases(plat: &dyn PlatformInfo, skip: &[&str], jobs: usize, report: &mut ScanReport) {
    let global_attrs = || vec![Attr::str(Key::Phase, "global_scanners")];
    let home_attrs = || {
        vec![
            Attr::str(Key::Phase, "home_pass"),
            Attr::int(Key::RootIndex, 0),
            Attr::str(Key::RootKind, "home"),
        ]
    };
    if jobs <= 1 {
        {
            let _p = otel::span("phase.global_scanners", global_attrs);
            run_jobs(global_jobs(plat, skip), jobs, report);
        }
        let _p = otel::span("phase.home_pass", home_attrs);
        run_jobs(home_jobs(plat, skip), jobs, report);
        return;
    }
    let start = Instant::now();
    // Open each phase span, capture it as the parent of its scanners, and detach it, so
    // the second is a sibling of the first under the root span, not its child.
    let open = |label: &'static str, attrs: &dyn Fn() -> Vec<Attr>| {
        let g = otel::span_with_at("phase.", label, start, attrs);
        let cx = otel::current_context();
        (g.detach(), cx)
    };
    let (global_span, global_cx) = open("global_scanners", &global_attrs);
    let (home_span, home_cx) = open("home_pass", &home_attrs);
    let phases = vec![
        Phase {
            cx: global_cx,
            list: global_jobs(plat, skip),
        },
        Phase {
            cx: home_cx,
            list: home_jobs(plat, skip),
        },
    ];
    for (span, done) in [global_span, home_span].into_iter().zip(run_pool(phases, jobs)) {
        let end = done.iter().map(|(_, t)| *t).max().unwrap_or(start);
        for (d, _) in done {
            d.apply(report);
        }
        span.finish_after(end.saturating_duration_since(start));
    }
}

/// Scanners that operate from a home directory (re-run per --search-dirs entry).
fn home_jobs<'a>(plat: &'a dyn PlatformInfo, skip: &[&str]) -> Vec<Job<'a>> {
    let mut list = Vec::new();
    if !skip.contains(&"extensions") {
        list.push(job(
            "extensions",
            Some(plat.home_dir()),
            move || scanners::extensions::ExtensionsScanner.scan(plat),
            |r, v| r.ide_extensions.extend(v),
        ));
    }
    if !skip.contains(&"mcp") {
        list.push(job(
            "mcp",
            Some(plat.home_dir()),
            move || scanners::mcp::scan_home(plat),
            scanners::mcp::store,
        ));
    }
    if !skip.contains(&"shell") {
        list.push(job(
            "shell",
            Some(plat.home_dir()),
            move || scanners::shell_configs::ShellConfigsScanner.scan(plat),
            |r, v| r.shell_configs.extend(v),
        ));
    }
    if !skip.contains(&"ssh") {
        list.push(job(
            "ssh",
            Some(plat.home_dir()),
            move || scanners::ssh_keys::SshKeysScanner.scan(plat),
            |r, v| r.ssh_keys.extend(v),
        ));
    }
    if !skip.contains(&"authkeys") {
        list.push(job(
            "authkeys",
            Some(plat.home_dir()),
            move || scanners::authorized_keys::scan(plat),
            |r, v| r.surfaces.authorized_keys.extend(v),
        ));
    }
    if !skip.contains(&"cloud") {
        list.push(job(
            "cloud",
            Some(plat.home_dir()),
            move || scanners::cloud_credentials::CloudCredentialsScanner.scan(plat),
            |r, v| r.cloud_credentials.extend(v),
        ));
    }
    if !skip.contains(&"browser") {
        list.push(job(
            "browser",
            Some(plat.home_dir()),
            move || scanners::browser_extensions::BrowserExtensionsScanner.scan(plat),
            |r, v| r.browser_extensions.extend(v),
        ));
    }
    if !skip.contains(&"packages") {
        list.push(job(
            "packages",
            Some(plat.home_dir()),
            move || scanners::package_configs::PackageConfigsScanner.scan(plat),
            |r, v| r.package_config_audits.extend(v),
        ));
    }
    if !skip.contains(&"rules") {
        list.push(job(
            "rules",
            Some(plat.home_dir()),
            move || scanners::rules_files::RulesFilesScanner.scan(plat),
            |r, v| r.rules_files.extend(v),
        ));
    }
    if !skip.contains(&"skills") {
        list.push(job(
            "skills",
            Some(plat.home_dir()),
            move || scanners::skills::SkillsScanner.scan(plat),
            |r, v| r.agent_skills.extend(v),
        ));
    }
    if !skip.contains(&"settings") {
        list.push(job(
            "settings",
            Some(plat.home_dir()),
            move || scanners::agent_settings::AgentSettingsScanner.scan(plat),
            |r, v| r.agent_settings.extend(v),
        ));
    }
    if !skip.contains(&"aicreds") {
        list.push(job(
            "aicreds",
            Some(plat.home_dir()),
            move || scanners::ai_credentials::AiCredentialsScanner.scan(plat),
            |r, v| r.ai_credentials.extend(v),
        ));
    }
    if !skip.contains(&"envfiles") {
        list.push(job(
            "envfiles",
            Some(plat.home_dir()),
            move || scanners::env_files::EnvFilesScanner.scan(plat),
            |r, v| r.env_files.extend(v),
        ));
    }
    if !skip.contains(&"persistence") {
        list.push(job(
            "persistence",
            Some(plat.home_dir()),
            move || scanners::persistence::PersistenceScanner.scan(plat),
            |r, v| r.persistence_artifacts.extend(v),
        ));
    }
    if !skip.contains(&"transcripts") {
        list.push(job(
            "transcripts",
            Some(plat.home_dir()),
            move || scanners::transcripts::TranscriptsScanner.scan(plat),
            |r, v| r.transcripts.extend(v),
        ));
    }
    if !skip.contains(&"marketplaces") {
        list.push(job(
            "marketplaces",
            Some(plat.home_dir()),
            move || scanners::marketplaces::MarketplacesScanner.scan(plat),
            |r, v| r.marketplaces.extend(v),
        ));
    }
    if !skip.contains(&"vscodetasks") {
        list.push(job(
            "vscodetasks",
            Some(plat.home_dir()),
            move || scanners::vscode_tasks::VsCodeTasksScanner.scan(plat),
            |r, v| r.vscode_tasks.extend(v),
        ));
    }
    if !skip.contains(&"gitconfig") {
        list.push(job(
            "gitconfig",
            Some(plat.home_dir()),
            move || scanners::git_config::GitConfigScanner.scan(plat),
            |r, v| r.git_autorun_configs.extend(v),
        ));
    }
    if !skip.contains(&"lsp") {
        list.push(job(
            "lsp",
            Some(plat.home_dir()),
            move || scanners::plugin_lsp::PluginLspScanner.scan(plat),
            |r, v| r.surfaces.agent_lsp_servers.extend(v),
        ));
    }
    if !skip.contains(&"liveness") {
        list.push(job(
            "liveness",
            Some(plat.home_dir()),
            move || scanners::liveness::scan_home(plat),
            |r, v| {
                for o in v {
                    match o {
                        scanners::liveness::LivenessOut::InUse(x) => r.surfaces.plugin_versions_in_use.push(x),
                        scanners::liveness::LivenessOut::Npx(x) => r.surfaces.npx_caches_running.push(x),
                    }
                }
            },
        ));
    }
    if !skip.contains(&"playwright") {
        list.push(job(
            "playwright",
            Some(plat.home_dir()),
            move || scanners::playwright_mcp::scan_home(plat),
            |r, v| {
                for o in v {
                    match o {
                        scanners::playwright_mcp::PlaywrightOut::Profiles(x) => {
                            r.surfaces.agent_browser_profiles.push(x)
                        }
                        scanners::playwright_mcp::PlaywrightOut::OutputDir(x) => r.surfaces.agent_output_dirs.push(x),
                    }
                }
            },
        ));
    }
    if !skip.contains(&"vibe") {
        list.push(job(
            "vibe",
            Some(plat.home_dir()),
            move || scanners::vibe::scan_home(plat),
            |r, v| {
                for o in v {
                    match o {
                        scanners::vibe::VibeOut::Config(x) => r.surfaces.vibe_configs.push(x),
                        scanners::vibe::VibeOut::Mcp(x) => r.mcp_configs.push(x),
                        scanners::vibe::VibeOut::Store(x) => r.transcripts.push(x),
                    }
                }
            },
        ));
    }
    if !skip.contains(&"agents") {
        list.push(job(
            "agents",
            Some(plat.home_dir()),
            move || scanners::agents_more::scan_home(plat),
            |r, v| {
                for o in v {
                    match o {
                        scanners::agents_more::AgentsOut::Posture(x) => r.surfaces.agent_postures.push(x),
                        scanners::agents_more::AgentsOut::Mcp(x) => r.mcp_configs.push(x),
                        scanners::agents_more::AgentsOut::Store(x) => r.transcripts.push(x),
                        scanners::agents_more::AgentsOut::Rules(x) => r.rules_files.push(x),
                    }
                }
            },
        ));
    }
    if !skip.contains(&"statusline") {
        list.push(job(
            "statusline",
            Some(plat.home_dir()),
            move || scanners::settings_scripts::scan_home(plat),
            |r, v| r.surfaces.settings_command_scripts.extend(v),
        ));
    }
    list
}

/// Scanners that don't depend on home dir (run once).
fn global_jobs<'a>(plat: &'a dyn PlatformInfo, skip: &[&str]) -> Vec<Job<'a>> {
    let mut list = Vec::new();
    if !skip.contains(&"ai") {
        list.push(job(
            "ai",
            None,
            move || scanners::ai_tools::AiToolsScanner.scan(plat),
            |r, v| r.ai_agents_and_tools = v,
        ));
    }
    if !skip.contains(&"frameworks") {
        list.push(job(
            "frameworks",
            None,
            move || scanners::ai_frameworks::AiFrameworksScanner.scan(plat),
            |r, v| r.ai_frameworks = v,
        ));
    }
    if !skip.contains(&"ide") {
        list.push(job(
            "ide",
            None,
            move || scanners::ide::IdeScanner.scan(plat),
            |r, v| r.ide_installations = v,
        ));
    }
    if !skip.contains(&"node") {
        list.push(job(
            "node",
            None,
            move || scanners::node_packages::NodePackagesScanner.scan(plat),
            |r, v| r.node_package_managers = v,
        ));
    }
    if !skip.contains(&"containers") {
        list.push(job(
            "containers",
            None,
            move || scanners::container_tools::ContainerToolsScanner.scan(plat),
            |r, v| r.container_tools = v,
        ));
    }
    if !skip.contains(&"notebooks") {
        list.push(job(
            "notebooks",
            None,
            move || scanners::notebook_servers::NotebookServersScanner.scan(plat),
            |r, v| r.notebook_servers = v,
        ));
    }
    // Listening sockets from /proc (Linux only; elsewhere a skipped row with its floor).
    #[cfg(target_os = "linux")]
    if !skip.contains(&"listeners") {
        list.push(job(
            "listeners",
            None,
            move || scanners::listeners::scan(plat),
            |r, v| r.surfaces.network_listeners = v,
        ));
    }
    list
}

/// `--otel-instance`: the operator's text, trimmed, non-empty, at most 128 characters
/// and unchanged by [`scanners::sanitize_display`] (it ends up in dashboards and terminal
/// output): control characters, bidi overrides and isolates, zero-width and other
/// invisible format characters are refused, not silently rewritten.
fn parse_otel_instance(s: &str) -> Result<String, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("must not be empty".into());
    }
    if t.chars().count() > 128 {
        return Err("at most 128 characters".into());
    }
    if scanners::sanitize_display(t, 128) != t {
        return Err("must not contain control, bidi, zero-width or other invisible formatting characters".into());
    }
    Ok(t.to_string())
}

/// `--jobs`, or the machine's parallelism clamped to 1..=8.
fn scan_jobs(flag: Option<usize>) -> usize {
    flag.unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()).clamp(1, 8))
}

fn main() {
    let cli = Cli::parse();

    // Fleet report mode: aggregate a directory of JSON scans, don't scan locally.
    if let Some(ref dir) = cli.report {
        if cli.otel {
            eprintln!("warning: --otel is ignored with --report");
        }
        run_fleet_report(dir, cli.output.as_deref());
        return;
    }

    let format = match cli.format {
        Format::Terminal => OutputFormat::Terminal,
        Format::Json => OutputFormat::Json,
        Format::Html => OutputFormat::Html,
        Format::Sbom => OutputFormat::Sbom,
        Format::Blueprint => OutputFormat::Blueprint,
        Format::Compliance => OutputFormat::Compliance,
    };

    // RMGUARD_TRACE is a boolean: "1"/"true"/"yes". An exported-but-disabled `=0` must
    // not turn on a channel that prints every path the scanners touch.
    let env_trace = std::env::var("RMGUARD_TRACE")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    if cli.trace || env_trace {
        rustmachineguard::scanners::telemetry::enable_trace();
    }

    // OpenTelemetry export: only ever started by the explicit flag. Ambient OTEL_* env
    // (common on developer machines, set up for other tools) never turns it on; it only
    // chooses where --otel sends. Without the flag nothing below is built or read.
    //
    // Machine identity is the operator's to give (`--otel-instance`, or
    // service.instance.id in OTEL_RESOURCE_ATTRIBUTES); without it one info line says
    // so and export goes ahead. Nothing is derived from the host.
    let mut otel_instance_set = false;
    if cli.otel {
        match otel::init(cli.otel_instance.as_deref()) {
            Ok(()) => {
                eprintln!(
                    "info: OpenTelemetry export enabled (OTLP http/protobuf; endpoint from OTEL_EXPORTER_OTLP_*, default http://localhost:4318)"
                );
                otel_instance_set = cli.otel_instance.is_some() || otel::env_has_instance_id();
                if !otel_instance_set {
                    eprintln!("{}", otel::NO_INSTANCE_NOTICE);
                }
            }
            Err(otel::InitError::NotCompiled) => {
                eprintln!("warning: --otel ignored: this rmguard was built without the `otel` feature")
            }
            Err(otel::InitError::Disabled) => {
                eprintln!("info: OTEL_SDK_DISABLED/OTEL_*_EXPORTER=none set; OpenTelemetry export off")
            }
            Err(otel::InitError::Config) => {
                eprintln!("warning: OpenTelemetry disabled: invalid OTEL_EXPORTER_OTLP_* configuration")
            }
        }
    }

    // Mapped onto VALID_SKIP's own static strings, so a label that reaches telemetry is
    // one of ours and never the user's text.
    let skip: Vec<&'static str> = cli
        .skip
        .iter()
        .map(|s| s.trim())
        .filter_map(|s| {
            let known = VALID_SKIP.iter().copied().find(|v| *v == s);
            if known.is_none() {
                eprintln!(
                    "warning: unknown --skip category '{}' (valid: {})",
                    s,
                    VALID_SKIP.join(", ")
                );
            }
            known
        })
        .collect();

    // Validate --search-dirs entries
    let search_dirs: Vec<PathBuf> = cli
        .search_dirs
        .into_iter()
        .filter(|d| {
            if !d.is_dir() {
                eprintln!(
                    "warning: --search-dirs entry '{}' is not a directory, skipping",
                    d.display()
                );
                false
            } else {
                true
            }
        })
        .collect();

    let format_name: &'static str = match cli.format {
        Format::Terminal => "terminal",
        Format::Json => "json",
        Format::Html => "html",
        Format::Sbom => "sbom",
        Format::Blueprint => "blueprint",
        Format::Compliance => "compliance",
    };
    let jobs = scan_jobs(cli.jobs.map(usize::from));
    // The same setting bounds the threads one scanner uses for its own work (the
    // gitconfig project walks, the skills file reads): `--jobs 1` keeps every scanner
    // single-threaded.
    telemetry::set_helper_jobs(jobs);
    telemetry::set_walk_budget(cli.walk_budget.map_or(telemetry::DEFAULT_WALK_BUDGET, |b| {
        usize::try_from(b).unwrap_or(usize::MAX)
    }));
    // Only for the rmguard.scan.duration metric: no clock read unless exporting.
    let scan_start = otel::enabled().then(Instant::now);
    // Root span of the whole scan; every phase and scanner span nests under it. Options
    // are exported as flags and counts, never as the paths or names they carry.
    let root = otel::span("rmguard.scan", || {
        vec![
            Attr::str(Key::Format, format_name),
            Attr::int(Key::SkipCount, skip.len() as i64),
            Attr::int(Key::SearchDirs, search_dirs.len() as i64),
            Attr::bool(Key::ProbeMcp, cli.probe_mcp),
            Attr::bool(Key::VerifyRegistry, cli.verify_registry),
            Attr::bool(Key::Diff, cli.diff.is_some()),
            Attr::int(Key::Jobs, jobs as i64),
            Attr::bool(Key::OtelInstanceIdSet, otel_instance_set),
        ]
    });

    let (primary_plat, device) = {
        let _p = otel::span("phase.device_info", || vec![Attr::str(Key::Phase, "device_info")]);
        // The working directory is a project of this pass only; every scan home (this one
        // and each --search-dirs entry) is kept out of every pass's project walks.
        let plat = platform::primary_platform(&search_dirs);
        let device = plat.device_info();
        (plat, device)
    };

    let now = chrono::Utc::now();

    let mut report = ScanReport {
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        scan_timestamp: now.timestamp(),
        scan_timestamp_iso: now.to_rfc3339(),
        device,
        ai_agents_and_tools: Vec::new(),
        ai_frameworks: Vec::new(),
        ide_installations: Vec::new(),
        ide_extensions: Vec::new(),
        mcp_configs: Vec::new(),
        mcp_observed_servers: Vec::new(),
        node_package_managers: Vec::new(),
        shell_configs: Vec::new(),
        ssh_keys: Vec::new(),
        cloud_credentials: Vec::new(),
        container_tools: Vec::new(),
        notebook_servers: Vec::new(),
        browser_extensions: Vec::new(),
        package_config_audits: Vec::new(),
        rules_files: Vec::new(),
        agent_skills: Vec::new(),
        agent_settings: Vec::new(),
        ai_credentials: Vec::new(),
        env_files: Vec::new(),
        exposure_findings: Vec::new(),
        mcp_probes: Vec::new(),
        mcp_registry_checks: Vec::new(),
        agent_identity: None,
        transcripts: Vec::new(),
        marketplaces: Vec::new(),
        vscode_tasks: Vec::new(),
        git_autorun_configs: Vec::new(),
        jetbrains_plugins: Vec::new(),
        persistence_artifacts: Vec::new(),
        warnings: Vec::new(),
        diagnostics: Vec::new(),
        catalog: Default::default(),
        surfaces: Default::default(),
        summary: models::Summary {
            ai_agents_and_tools_count: 0,
            ai_frameworks_count: 0,
            ide_installations_count: 0,
            ide_extensions_count: 0,
            mcp_configs_count: 0,
            node_package_managers_count: 0,
            shell_configs_count: 0,
            ssh_keys_count: 0,
            cloud_credentials_count: 0,
            container_tools_count: 0,
            notebook_servers_count: 0,
            browser_extensions_count: 0,
            package_config_audits_count: 0,
            rules_files_count: 0,
            agent_skills_count: 0,
            agent_settings_count: 0,
            agent_hooks_count: 0,
            ai_credentials_count: 0,
            env_files_count: 0,
            rules_file_findings_count: 0,
            mcp_servers_count: 0,
            mcp_plugin_servers_count: 0,
            mcp_connectors_count: 0,
            exposure_findings_count: 0,
            transcript_stores_count: 0,
            marketplaces_count: 0,
            vscode_autorun_tasks_count: 0,
            git_autorun_configs_count: 0,
            python_packages_count: 0,
            npm_packages_count: 0,
            jetbrains_plugins_count: 0,
            persistence_artifacts_count: 0,
            agent_hooks_by_framework: Default::default(),
            agent_hooks_inactive_count: 0,
            agent_settings_commands_count: 0,
            agent_lsp_servers_count: 0,
        },
    };

    // Global scanners (PATH-based, platform-level) and the primary home pass, side by
    // side: see run_primary_phases for why they are independent.
    run_primary_phases(primary_plat.as_ref(), &skip, jobs, &mut report);

    // Extra home passes, one per --search-dirs entry, after the primary pair.
    for (i, extra_home) in search_dirs.iter().enumerate() {
        let _p = otel::span("phase.home_pass", || {
            vec![
                Attr::str(Key::Phase, "home_pass"),
                Attr::int(Key::RootIndex, i as i64 + 1),
                Attr::str(Key::RootKind, "search_dir"),
            ]
        });
        let alt_plat = platform::search_dir_platform(extra_home.clone(), primary_plat.as_ref());
        run_jobs(home_jobs(alt_plat.as_ref(), &skip), jobs, &mut report);
    }

    // Deduplicate results that might appear from overlapping roots
    {
        let _p = otel::span("phase.dedupe", || vec![Attr::str(Key::Phase, "dedupe")]);
        dedupe_report(&mut report);
    }
    rustmachineguard::analysis::apply_managed_hook_policy(&mut report);
    scanners::mcp::post_scan(&mut report);
    // Listeners (global) meet the env files (per home pass): see correlate_listeners.
    rustmachineguard::analysis_surfaces::correlate_listeners(&mut report);

    // Exposure catalog matching — built-in catalog + optional user catalog
    let catalog_phase = otel::span("phase.catalog_load", || vec![Attr::str(Key::Phase, "catalog_load")]);
    let mut catalog = if cli.no_builtin_catalog {
        None
    } else {
        match scanners::exposure::ExposureCatalog::load_from_str(rustmachineguard::catalogs::BUILTIN_CATALOG) {
            Ok(c) => {
                eprintln!(
                    "info: loaded built-in threat catalog {} ({} entries)",
                    rustmachineguard::catalogs::BUILTIN_CATALOG_VERSION,
                    c.len()
                );
                report.catalog.builtin_version = Some(rustmachineguard::catalogs::BUILTIN_CATALOG_VERSION.to_string());
                report.catalog.builtin_entries = c.len();
                Some(c)
            }
            Err(e) => {
                eprintln!("warning: failed to load built-in catalog: {}", e);
                None
            }
        }
    };

    if let Some(ref catalog_path) = cli.threat_catalog {
        match scanners::exposure::ExposureCatalog::load_from_file(catalog_path) {
            Ok(user_catalog) => {
                eprintln!(
                    "info: loaded user threat catalog ({} entries from {})",
                    user_catalog.len(),
                    catalog_path.display()
                );
                report.catalog.user_entries = user_catalog.len();
                if let Some(ref mut c) = catalog {
                    c.merge(user_catalog);
                } else {
                    catalog = Some(user_catalog);
                }
            }
            Err(e) => {
                eprintln!("warning: {}", e);
            }
        }
    }

    drop(catalog_phase);

    // Without a catalog the package scanners never run; say so in the table rather
    // than leaving two labels with no row at all, which reads as "never existed".
    if catalog.is_none() {
        for label in ["pypkgs", "npmpkgs", "jbplugins"] {
            if !skip.contains(&label) {
                report
                    .diagnostics
                    .push(rustmachineguard::scanners::telemetry::skipped(label));
            }
        }
    }
    if let Some(ref catalog) = catalog {
        let _p = otel::span("phase.exposure", || vec![Attr::str(Key::Phase, "exposure")]);
        for mcp in &report.mcp_configs {
            // A disabled plugin's server and a claude.ai connector are inventory only.
            for server in mcp.servers.iter().filter(|s| s.is_active() && !s.ever_connected) {
                report
                    .exposure_findings
                    .extend(catalog.check_mcp_server(server, &mcp.config_path));
            }
        }
        for ext in &report.ide_extensions {
            let id = format!("{}.{}", ext.publisher, ext.name);
            report.exposure_findings.extend(
                catalog
                    .check_extension("vscode", &id, &ext.version, &ext.ide_type)
                    .into_iter()
                    .map(|mut f| {
                        f.obsolete = ext.obsolete;
                        f
                    }),
            );
        }
        for ext in &report.browser_extensions {
            report.exposure_findings.extend(
                // The catalog keys browser rows by store namespace (chrome/firefox),
                // NOT by the literal string "browser" — passing that matched nothing,
                // silently disabling every browser-extension detection.
                catalog.check_extension(
                    scanners::exposure::browser_catalog_ecosystem(&ext.browser),
                    &ext.id,
                    &ext.version,
                    &ext.browser,
                ),
            );
        }
        // Installed Python distributions. Until this existed, the only path to a pypi
        // catalog row was an MCP server whose launch command pinned a version, so a
        // compromised package merely installed on the machine was invisible.
        if !skip.contains(&"pypkgs") {
            let pkgs = timed(&mut report.diagnostics, "pypkgs", None, || {
                scanners::python_packages::PythonPackagesScanner.scan(primary_plat.as_ref())
            });
            report.summary.python_packages_count = pkgs.len();
            for pkg in &pkgs {
                // Where it lives decides how it is fixed (`uv tool upgrade`, `pipx
                // upgrade`, a project lock file, the system package manager).
                report.exposure_findings.extend(
                    catalog
                        .check_extension("pypi", &pkg.name, &pkg.version, &pkg.location)
                        .into_iter()
                        .map(|mut f| {
                            f.root_kind = Some(pkg.root_kind);
                            f.root_name = pkg.root_name.clone();
                            f
                        }),
                );
            }
        }

        // Installed npm packages. The npm catalog rows are mostly typosquats of agent
        // CLIs, which are installed by mistyping `npm i -g` and never appear as MCP
        // servers -- so without this enumeration they were unreachable.
        if !skip.contains(&"npmpkgs") {
            let pkgs = timed(&mut report.diagnostics, "npmpkgs", None, || {
                scanners::npm_packages::NpmPackagesScanner.scan(primary_plat.as_ref())
            });
            report.summary.npm_packages_count = pkgs.len();
            for pkg in &pkgs {
                for mut f in catalog.check_extension("npm", &pkg.name, &pkg.version, &pkg.location) {
                    // A match inside ~/.npm/_npx/<hash>/ is dormant code; name what it came with.
                    scanners::exposure::annotate_cache(&mut f);
                    report.exposure_findings.push(f);
                }
            }
        }

        // JetBrains IDE plugins. Fifteen Marketplace plugins posing as AI dev tools
        // exfiltrated users' AI API keys in 2025-26; the catalog keys them by plugin ID.
        if !skip.contains(&"jbplugins") {
            let plugins = timed(
                &mut report.diagnostics,
                "jbplugins",
                Some(primary_plat.home_dir()),
                || scanners::jetbrains_plugins::JetBrainsPluginsScanner.scan(primary_plat.as_ref()),
            );
            report.summary.jetbrains_plugins_count = plugins.len();
            for p in &plugins {
                report
                    .exposure_findings
                    .extend(catalog.check_extension("jetbrains", &p.id, &p.version, &p.location));
            }
            report.jetbrains_plugins = plugins
                .into_iter()
                .map(|p| rustmachineguard::models::JetBrainsPlugin {
                    id: p.id,
                    name: p.name,
                    version: p.version,
                    vendor: p.vendor,
                    ide: p.ide,
                    location: p.location,
                })
                .collect();
        }

        // Agent CLIs are CVE-bearing packages themselves. We already resolve each
        // tool's version; match it against the `agent-runtime` catalog ecosystem.
        // Tools with no version (not on PATH, or --version unparseable) are skipped:
        // a range against an unknown version is a conservative non-match anyway.
        for tool in &report.ai_agents_and_tools {
            let (Some(key), Some(version)) = (
                scanners::exposure::agent_runtime_key(&tool.name),
                tool.version.as_deref(),
            ) else {
                continue;
            };
            let found_in = tool.binary_path.as_deref().unwrap_or(tool.name.as_str());
            report
                .exposure_findings
                .extend(catalog.check_extension("agent-runtime", key, version, found_in));
        }
        // Local inference servers grew agent modes of their own (Ollama's Bash tool,
        // CVE-2026-102697), so the frameworks inventory feeds the same ecosystem.
        for fw in &report.ai_frameworks {
            let (Some(key), Some(version)) = (scanners::exposure::agent_runtime_key(&fw.name), fw.version.as_deref())
            else {
                continue;
            };
            let found_in = fw.binary_path.as_deref().unwrap_or(fw.name.as_str());
            report
                .exposure_findings
                .extend(catalog.check_extension("agent-runtime", key, version, found_in));
        }
    }

    // MCP live probing (opt-in)
    // The two opt-in phases are the slowest and the only network-touching things this
    // tool does; they belong in the table like any scanner, and appear as skipped when
    // their flag is off.
    if cli.probe_mcp {
        report.mcp_probes = timed(&mut report.diagnostics, "mcp-probe", None, || {
            scanners::mcp_probe::probe_mcp_servers(&report.mcp_configs)
        });
    }

    // MCP registry verification (opt-in, network)
    if cli.verify_registry {
        eprintln!("info: verifying MCP servers against the official registry (network)");
        report.mcp_registry_checks = timed(&mut report.diagnostics, "registry", None, || {
            rustmachineguard::registry::verify_servers(&report.mcp_configs)
        });
    }

    // Agent identity posture (static keys vs OAuth vs SPIFFE) — derived from the scan.
    {
        let _p = otel::span("phase.identity", || vec![Attr::str(Key::Phase, "identity")]);
        report.agent_identity = Some(rustmachineguard::identity::analyze(&report));
        report.compute_summary();
    }

    // Skipped scanners appear in diagnostics too, so the table answers "did it run?"
    // for every scanner, not just the ones that did.
    let mut skipped: std::collections::BTreeSet<&str> = skip.iter().copied().collect();
    if !cli.probe_mcp {
        skipped.insert("mcp-probe");
    }
    if !cli.verify_registry {
        skipped.insert("registry");
    }
    // No /proc: the listener inventory is a documented floor off Linux.
    #[cfg(not(target_os = "linux"))]
    if skipped.insert("listeners") {
        report.warnings.push(rustmachineguard::models::ScanWarning {
            scanner: "listeners".into(),
            message: scanners::listeners::FLOOR_REASON.into(),
        });
    }
    for label in skipped {
        report
            .diagnostics
            .push(rustmachineguard::scanners::telemetry::skipped(label));
    }

    // Diff mode: compare against a baseline scan. With --diff, stdout is the diff and `-o`
    // receives this scan in `--format`; `--fail-on` gates on this scan below, as in any run.
    let diff_output = cli.diff.as_ref().map(|baseline_path| {
        let _p = otel::span("phase.diff", || vec![Attr::str(Key::Phase, "diff")]);
        let baseline_str = std::fs::read_to_string(baseline_path).unwrap_or_else(|e| {
            eprintln!("Error reading baseline {}: {}", baseline_path.display(), e);
            otel::shutdown();
            std::process::exit(1);
        });
        let baseline: serde_json::Value = serde_json::from_str(&baseline_str).unwrap_or_else(|e| {
            eprintln!("Error parsing baseline JSON: {}", e);
            otel::shutdown();
            std::process::exit(1);
        });
        let current_json = serde_json::to_value(&report).unwrap_or_default();
        let diff = rustmachineguard::diff::diff_reports(&baseline, &current_json);
        rustmachineguard::diff::render_diff(&diff)
    });

    // The scan itself is rendered unless the diff takes stdout and there is no `-o`.
    let rendered = (diff_output.is_none() || cli.output.is_some()).then(|| {
        let _p = otel::span("phase.render", || vec![Attr::str(Key::Phase, "render")]);
        let mut rendered = output::render(&report, format);
        if cli.verbose && format == OutputFormat::Terminal {
            rendered.push_str(&output::terminal::render_diagnostics(&report));
        }
        rendered
    });

    {
        let _p = otel::span("phase.write", || vec![Attr::str(Key::Phase, "write")]);
        if let (Some(path), Some(rendered)) = (cli.output.as_ref(), rendered.as_ref()) {
            std::fs::write(path, rendered).unwrap_or_else(|e| {
                eprintln!("Error writing to {path}: {e}");
                otel::shutdown();
                std::process::exit(1);
            });
            if format == OutputFormat::Terminal {
                eprintln!("Report written to {path}");
            }
        }
        match (&diff_output, &rendered) {
            (Some(diff), _) => write_report_to_stdout(diff),
            (None, Some(rendered)) if cli.output.is_none() => write_report_to_stdout(rendered),
            _ => {}
        }
    }

    // The report is out (and flushed); end the root span and flush telemetry (bounded at
    // 2 s) before the fail-on gate can exit the process.
    finish_scan(root, scan_start, &report);

    // CI / fleet-onboarding gate: fail the process when findings breach the threshold.
    // The report has already been emitted, so this only changes the exit status.
    if let Some(threshold) = cli.fail_on.map(FailOn::as_severity) {
        let findings = rustmachineguard::analysis::collect_findings(&report);
        // Severity is ordered most-severe-first, so "at or above" is `<= threshold`.
        let breaching = findings.iter().filter(|f| f.severity <= threshold).count();
        if breaching > 0 {
            let worst = findings
                .iter()
                .map(|f| f.severity)
                .min()
                .expect("non-empty since breaching > 0");
            eprintln!(
                "fail-on: {breaching} finding(s) at or above {} (most severe: {}) — exiting {FINDINGS_GATE_EXIT}",
                threshold.label(),
                worst.label()
            );
            std::process::exit(FINDINGS_GATE_EXIT);
        }
    }
}

/// Write the report to stdout and flush it before returning. std's stdout is
/// line-buffered, and the json/sbom/blueprint/html outputs end without a newline, so
/// without the flush their last line would sit in the buffer until process exit, i.e.
/// for the whole (up to 2 s) OpenTelemetry shutdown that follows: a pipeline that read
/// or killed rmguard in that window would see a truncated document.
fn write_report_to_stdout(text: &str) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    if let Err(e) = out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        drop(out);
        eprintln!("Error writing report to stdout: {e}");
        otel::shutdown();
        std::process::exit(1);
    }
}

/// End the root span with the scan's totals, record its duration, and flush/stop
/// OpenTelemetry export. Nothing happens here unless `--otel` started export.
///
/// Posture (findings by severity and category, the summary's inventory counts) is
/// computed here, from the finished report, only when export is on: a plain run does
/// not run the finding analysis an extra time.
fn finish_scan(mut root: otel::SpanGuard, scan_start: Option<Instant>, report: &ScanReport) {
    if otel::enabled() {
        let findings = rustmachineguard::analysis::collect_findings(report);
        let [critical, high, medium, low] = otel::severity_totals(&findings);
        root.set(|| {
            vec![
                Attr::int(Key::ExposureFindings, report.exposure_findings.len() as i64),
                Attr::int(
                    Key::ScannersRun,
                    report.diagnostics.iter().filter(|d| !d.skipped).count() as i64,
                ),
                Attr::int(Key::FindingsCritical, critical),
                Attr::int(Key::FindingsHigh, high),
                Attr::int(Key::FindingsMedium, medium),
                Attr::int(Key::FindingsLow, low),
            ]
        });
        // The catalog the exposure findings were matched against: a constant of this
        // binary, present only when the built-in catalog was used.
        if report.catalog.builtin_version.is_some() {
            root.set(|| {
                vec![Attr::str(
                    Key::CatalogVersion,
                    rustmachineguard::catalogs::BUILTIN_CATALOG_VERSION,
                )]
            });
        }
        otel::record_posture(&findings, &report.summary);
    }
    if let Some(t) = scan_start {
        otel::record(Metric::ScanDuration, t.elapsed().as_secs_f64(), Vec::new);
    }
    drop(root);
    otel::shutdown();
}

/// Aggregate a directory of `--format json` scans into one fleet HTML dashboard.
fn run_fleet_report(dir: &std::path::Path, output_path: Option<&str>) {
    let (reports, skipped) = output::fleet::load_reports_from_dir(dir).unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        std::process::exit(1);
    });

    for s in &skipped {
        eprintln!("warning: skipping {} (not a valid rmguard JSON scan)", s);
    }
    if reports.is_empty() {
        eprintln!(
            "Error: no valid JSON scans found in {} (run `rmguard --format json --output <host>.json` on each machine first)",
            dir.display()
        );
        std::process::exit(1);
    }
    eprintln!("info: aggregating {} machine scan(s)", reports.len());

    let html = output::fleet::render_fleet(&reports);
    if let Some(path) = output_path {
        std::fs::write(path, &html).unwrap_or_else(|e| {
            eprintln!("Error writing to {path}: {e}");
            std::process::exit(1);
        });
        eprintln!("Fleet report written to {path}");
    } else {
        print!("{html}");
    }
}

/// Remove duplicate entries that may arise from overlapping search dirs.
fn dedupe_report(report: &mut ScanReport) {
    // Dedupe by primary identifying field(s) for each category.
    use std::collections::HashSet;

    let mut seen = HashSet::new();
    report
        .ide_extensions
        .retain(|x| seen.insert((x.id.clone(), x.version.clone(), x.ide_type.clone())));

    let mut seen = HashSet::new();
    report.mcp_configs.retain(|x| seen.insert(x.config_path.clone()));

    let mut seen = HashSet::new();
    report.shell_configs.retain(|x| seen.insert(x.config_path.clone()));

    let mut seen = HashSet::new();
    report.ssh_keys.retain(|x| seen.insert(x.path.clone()));

    let mut seen = HashSet::new();
    report.cloud_credentials.retain(|x| seen.insert(x.config_path.clone()));

    let mut seen = HashSet::new();
    report
        .browser_extensions
        .retain(|x| seen.insert((x.browser.clone(), x.id.clone(), x.profile.clone())));

    let mut seen = HashSet::new();
    report
        .package_config_audits
        .retain(|x| seen.insert(x.config_path.clone()));

    // One file can be read by two scanners: Cline's `.clinerules` as a single file is a
    // `rules` row (an instruction-file name) and an `agents` row (Cline's rules, which also
    // get the prompt-injection phrases). The first row is kept and the others' findings and
    // agent metadata are merged into it, so which checks a file gets does not depend on
    // which scanner's row comes first.
    let mut first: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut kept: Vec<models::RulesFile> = Vec::with_capacity(report.rules_files.len());
    for row in std::mem::take(&mut report.rules_files) {
        let Some(&i) = first.get(&row.path) else {
            first.insert(row.path.clone(), kept.len());
            kept.push(row);
            continue;
        };
        let k = &mut kept[i];
        for f in row.findings {
            if !k
                .findings
                .iter()
                .any(|x| x.severity == f.severity && x.pattern == f.pattern)
            {
                k.findings.push(f);
            }
        }
        k.kind = k.kind.take().or(row.kind);
        k.framework = k.framework.take().or(row.framework);
        k.scope = k.scope.take().or(row.scope);
    }
    report.rules_files = kept;

    let mut seen = HashSet::new();
    report.agent_skills.retain(|x| seen.insert(x.path.clone()));

    // Managed settings and the systemd/launchd service paths are system-wide, so every
    // --search-dirs home pass finds them again.
    let mut seen = HashSet::new();
    report.agent_settings.retain(|x| seen.insert(x.path.clone()));

    // A project registered in two homes is a project of both passes, and the /tmp worm
    // paths are the same for every pass. The working directory is a project of the
    // primary pass only and no pass walks a scan home as a project, so these keys only
    // ever meet a project two homes share.
    let mut seen = HashSet::new();
    report.git_autorun_configs.retain(|x| {
        seen.insert((
            x.path.clone(),
            x.origin.clone(),
            x.key.clone(),
            x.value.clone(),
            x.scope.clone(),
        ))
    });

    let mut seen = HashSet::new();
    report.env_files.retain(|x| seen.insert(x.path.clone()));

    let mut seen = HashSet::new();
    report
        .vscode_tasks
        .retain(|x| seen.insert((x.path.clone(), x.label.clone(), x.command.clone())));

    let mut seen = HashSet::new();
    report
        .persistence_artifacts
        .retain(|x| seen.insert((x.kind.clone(), x.path.clone(), x.detail.clone())));
}
