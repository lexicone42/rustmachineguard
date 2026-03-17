use clap::{Parser, ValueEnum};
use rustmachineguard::models::{self, ScanReport};
use rustmachineguard::output::{self, OutputFormat};
use rustmachineguard::platform;
use rustmachineguard::scanners::{self, Scanner};

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

    let plat = platform::current_platform();
    let device = plat.device_info();

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

    // Run scanners (skip if requested)
    if !skip.contains(&"ai") {
        report.ai_agents_and_tools = scanners::ai_tools::AiToolsScanner.scan(plat.as_ref());
    }
    if !skip.contains(&"frameworks") {
        report.ai_frameworks = scanners::ai_frameworks::AiFrameworksScanner.scan(plat.as_ref());
    }
    if !skip.contains(&"ide") {
        report.ide_installations = scanners::ide::IdeScanner.scan(plat.as_ref());
    }
    if !skip.contains(&"extensions") {
        report.ide_extensions = scanners::extensions::ExtensionsScanner.scan(plat.as_ref());
    }
    if !skip.contains(&"mcp") {
        report.mcp_configs = scanners::mcp::McpScanner.scan(plat.as_ref());
    }
    if !skip.contains(&"node") {
        report.node_package_managers =
            scanners::node_packages::NodePackagesScanner.scan(plat.as_ref());
    }
    if !skip.contains(&"shell") {
        report.shell_configs = scanners::shell_configs::ShellConfigsScanner.scan(plat.as_ref());
    }
    if !skip.contains(&"ssh") {
        report.ssh_keys = scanners::ssh_keys::SshKeysScanner.scan(plat.as_ref());
    }
    if !skip.contains(&"cloud") {
        report.cloud_credentials =
            scanners::cloud_credentials::CloudCredentialsScanner.scan(plat.as_ref());
    }
    if !skip.contains(&"containers") {
        report.container_tools =
            scanners::container_tools::ContainerToolsScanner.scan(plat.as_ref());
    }
    if !skip.contains(&"notebooks") {
        report.notebook_servers =
            scanners::notebook_servers::NotebookServersScanner.scan(plat.as_ref());
    }

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
