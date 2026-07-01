use clap::{Parser, ValueEnum};
use rustmachineguard::models::{self, ScanReport};
use rustmachineguard::output::{self, OutputFormat};
use rustmachineguard::platform::{self, PlatformInfo};
use rustmachineguard::scanners::{self, Scanner};
use std::path::PathBuf;

/// Scan your dev machine for AI agents, MCP servers, IDE extensions, and more.
///
/// Rust rewrite of https://github.com/step-security/dev-machine-guard (Apache-2.0).
/// Extended with Linux support, cloud credential detection, container tools,
/// SSH key auditing, shell config scanning, and notebook server detection.
#[derive(Parser)]
#[command(name = "rmguard", version, about)]
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
    /// Shows added, removed, and changed items across all categories.
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

    /// Exit with code 2 if any finding at or above this severity is present, after
    /// printing the report as usual. For CI / fleet-onboarding gates (e.g. fail a
    /// machine's check on any Critical). Operational errors still exit 1.
    #[arg(long, value_name = "SEVERITY")]
    fail_on: Option<FailOn>,
}

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
    "ai", "frameworks", "ide", "extensions", "mcp", "node", "shell", "ssh",
    "cloud", "containers", "notebooks", "browser", "packages", "rules", "skills",
    "settings", "aicreds", "envfiles", "transcripts", "marketplaces",
];

/// Scanners that operate from a home directory (re-run per --search-dirs entry).
fn run_home_rooted_scanners(plat: &dyn PlatformInfo, skip: &[&str], report: &mut ScanReport) {
    if !skip.contains(&"extensions") {
        report
            .ide_extensions
            .extend(scanners::extensions::ExtensionsScanner.scan(plat));
    }
    if !skip.contains(&"mcp") {
        report
            .mcp_configs
            .extend(scanners::mcp::McpScanner.scan(plat));
    }
    if !skip.contains(&"shell") {
        report
            .shell_configs
            .extend(scanners::shell_configs::ShellConfigsScanner.scan(plat));
    }
    if !skip.contains(&"ssh") {
        report
            .ssh_keys
            .extend(scanners::ssh_keys::SshKeysScanner.scan(plat));
    }
    if !skip.contains(&"cloud") {
        report
            .cloud_credentials
            .extend(scanners::cloud_credentials::CloudCredentialsScanner.scan(plat));
    }
    if !skip.contains(&"browser") {
        report
            .browser_extensions
            .extend(scanners::browser_extensions::BrowserExtensionsScanner.scan(plat));
    }
    if !skip.contains(&"packages") {
        report
            .package_config_audits
            .extend(scanners::package_configs::PackageConfigsScanner.scan(plat));
    }
    if !skip.contains(&"rules") {
        report
            .rules_files
            .extend(scanners::rules_files::RulesFilesScanner.scan(plat));
    }
    if !skip.contains(&"skills") {
        report
            .agent_skills
            .extend(scanners::skills::SkillsScanner.scan(plat));
    }
    if !skip.contains(&"settings") {
        report
            .agent_settings
            .extend(scanners::agent_settings::AgentSettingsScanner.scan(plat));
    }
    if !skip.contains(&"aicreds") {
        report
            .ai_credentials
            .extend(scanners::ai_credentials::AiCredentialsScanner.scan(plat));
    }
    if !skip.contains(&"envfiles") {
        report
            .env_files
            .extend(scanners::env_files::EnvFilesScanner.scan(plat));
    }
    if !skip.contains(&"transcripts") {
        report
            .transcripts
            .extend(scanners::transcripts::TranscriptsScanner.scan(plat));
    }
    if !skip.contains(&"marketplaces") {
        report
            .marketplaces
            .extend(scanners::marketplaces::MarketplacesScanner.scan(plat));
    }
}

/// Scanners that don't depend on home dir (run once).
fn run_global_scanners(plat: &dyn PlatformInfo, skip: &[&str], report: &mut ScanReport) {
    if !skip.contains(&"ai") {
        report.ai_agents_and_tools = scanners::ai_tools::AiToolsScanner.scan(plat);
    }
    if !skip.contains(&"frameworks") {
        report.ai_frameworks = scanners::ai_frameworks::AiFrameworksScanner.scan(plat);
    }
    if !skip.contains(&"ide") {
        report.ide_installations = scanners::ide::IdeScanner.scan(plat);
    }
    if !skip.contains(&"node") {
        report.node_package_managers =
            scanners::node_packages::NodePackagesScanner.scan(plat);
    }
    if !skip.contains(&"containers") {
        report.container_tools =
            scanners::container_tools::ContainerToolsScanner.scan(plat);
    }
    if !skip.contains(&"notebooks") {
        report.notebook_servers =
            scanners::notebook_servers::NotebookServersScanner.scan(plat);
    }
}

fn main() {
    let cli = Cli::parse();

    // Fleet report mode: aggregate a directory of JSON scans, don't scan locally.
    if let Some(ref dir) = cli.report {
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

    let skip: Vec<&str> = cli
        .skip
        .iter()
        .map(|s| s.trim())
        .filter(|s| {
            if !VALID_SKIP.contains(s) {
                eprintln!(
                    "warning: unknown --skip category '{}' (valid: {})",
                    s,
                    VALID_SKIP.join(", ")
                );
                false
            } else {
                true
            }
        })
        .collect();

    // Validate --search-dirs entries
    let search_dirs: Vec<PathBuf> = cli
        .search_dirs
        .into_iter()
        .filter(|d| {
            if !d.is_dir() {
                eprintln!("warning: --search-dirs entry '{}' is not a directory, skipping", d.display());
                false
            } else {
                true
            }
        })
        .collect();

    let primary_plat = platform::current_platform();
    let device = primary_plat.device_info();

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
        warnings: Vec::new(),
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
            exposure_findings_count: 0,
            transcript_stores_count: 0,
            marketplaces_count: 0,
        },
    };

    // Global scanners (PATH-based, platform-level): run once
    run_global_scanners(primary_plat.as_ref(), &skip, &mut report);

    // Home-rooted scanners: run for primary home + each --search-dirs entry
    run_home_rooted_scanners(primary_plat.as_ref(), &skip, &mut report);
    for extra_home in &search_dirs {
        let alt_plat = platform::platform_for_home(extra_home.clone());
        run_home_rooted_scanners(alt_plat.as_ref(), &skip, &mut report);
    }

    // Deduplicate results that might appear from overlapping roots
    dedupe_report(&mut report);

    // Exposure catalog matching — built-in catalog + optional user catalog
    let mut catalog = if cli.no_builtin_catalog {
        None
    } else {
        match scanners::exposure::ExposureCatalog::load_from_str(
            rustmachineguard::catalogs::BUILTIN_CATALOG,
        ) {
            Ok(c) => {
                eprintln!(
                    "info: loaded built-in threat catalog ({} entries)",
                    c.len()
                );
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

    if let Some(ref catalog) = catalog {
        for mcp in &report.mcp_configs {
            for server in &mcp.servers {
                report
                    .exposure_findings
                    .extend(catalog.check_mcp_server(server, &mcp.config_path));
            }
        }
        for ext in &report.ide_extensions {
            let id = format!("{}.{}", ext.publisher, ext.name);
            report.exposure_findings.extend(
                catalog.check_extension("vscode", &id, &ext.version, &ext.ide_type),
            );
        }
        for ext in &report.browser_extensions {
            report.exposure_findings.extend(
                catalog.check_extension("browser", &ext.id, &ext.version, &ext.browser),
            );
        }
    }

    // MCP live probing (opt-in)
    if cli.probe_mcp {
        report.mcp_probes = scanners::mcp_probe::probe_mcp_servers(&report.mcp_configs);
    }

    // MCP registry verification (opt-in, network)
    if cli.verify_registry {
        eprintln!("info: verifying MCP servers against the official registry (network)");
        report.mcp_registry_checks =
            rustmachineguard::registry::verify_servers(&report.mcp_configs);
    }

    // Agent identity posture (static keys vs OAuth vs SPIFFE) — derived from the scan.
    report.agent_identity = Some(rustmachineguard::identity::analyze(&report));

    report.compute_summary();

    // Diff mode: compare against a baseline scan
    if let Some(ref baseline_path) = cli.diff {
        let baseline_str = std::fs::read_to_string(baseline_path).unwrap_or_else(|e| {
            eprintln!("Error reading baseline {}: {}", baseline_path.display(), e);
            std::process::exit(1);
        });
        let baseline: serde_json::Value = serde_json::from_str(&baseline_str).unwrap_or_else(|e| {
            eprintln!("Error parsing baseline JSON: {}", e);
            std::process::exit(1);
        });

        let current_json = serde_json::to_value(&report).unwrap_or_default();
        let diff = rustmachineguard::diff::diff_reports(&baseline, &current_json);
        let diff_output = rustmachineguard::diff::render_diff(&diff);

        if let Some(ref path) = cli.output {
            std::fs::write(path, &diff_output).unwrap_or_else(|e| {
                eprintln!("Error writing to {path}: {e}");
                std::process::exit(1);
            });
        } else {
            print!("{diff_output}");
        }
        return;
    }

    let rendered = output::render(&report, format);

    if let Some(ref path) = cli.output {
        std::fs::write(path, &rendered).unwrap_or_else(|e| {
            eprintln!("Error writing to {path}: {e}");
            std::process::exit(1);
        });
        if format == OutputFormat::Terminal {
            eprintln!("Report written to {path}");
        }
    } else {
        print!("{rendered}");
    }

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
                "fail-on: {breaching} finding(s) at or above {} (most severe: {}) — exiting 2",
                threshold.label(),
                worst.label()
            );
            std::process::exit(2);
        }
    }
}

/// Aggregate a directory of `--format json` scans into one fleet HTML dashboard.
fn run_fleet_report(dir: &std::path::Path, output_path: Option<&str>) {
    let (reports, skipped) =
        output::fleet::load_reports_from_dir(dir).unwrap_or_else(|e| {
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
    report
        .mcp_configs
        .retain(|x| seen.insert(x.config_path.clone()));

    let mut seen = HashSet::new();
    report
        .shell_configs
        .retain(|x| seen.insert(x.config_path.clone()));

    let mut seen = HashSet::new();
    report.ssh_keys.retain(|x| seen.insert(x.path.clone()));

    let mut seen = HashSet::new();
    report
        .cloud_credentials
        .retain(|x| seen.insert(x.config_path.clone()));

    let mut seen = HashSet::new();
    report
        .browser_extensions
        .retain(|x| seen.insert((x.browser.clone(), x.id.clone(), x.profile.clone())));

    let mut seen = HashSet::new();
    report
        .package_config_audits
        .retain(|x| seen.insert(x.config_path.clone()));

    let mut seen = HashSet::new();
    report
        .rules_files
        .retain(|x| seen.insert(x.path.clone()));

    let mut seen = HashSet::new();
    report
        .agent_skills
        .retain(|x| seen.insert(x.path.clone()));
}
