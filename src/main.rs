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
#[command(name = "dev-machine-guard", version, about)]
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
}

#[derive(Clone, ValueEnum)]
enum Format {
    Terminal,
    Json,
    Html,
}

const VALID_SKIP: &[&str] = &[
    "ai", "frameworks", "ide", "extensions", "mcp", "node", "shell", "ssh",
    "cloud", "containers", "notebooks",
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

    let format = match cli.format {
        Format::Terminal => OutputFormat::Terminal,
        Format::Json => OutputFormat::Json,
        Format::Html => OutputFormat::Html,
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

    report.compute_summary();

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
}
