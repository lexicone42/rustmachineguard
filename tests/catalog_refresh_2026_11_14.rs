//! The 2026-11-14 threat-catalog refresh (window 2026-10-25 to 2026-11-14): the Miasma
//! "testmetest" packages, malicious MCP and agent-named packages, new advisories on the
//! MCP reference servers and the Inspector, and two new `agent-runtime` keys (`vscode`,
//! `kiro-cli`). Every case fails on the 2026-10-30 catalog (no such row).

use rustmachineguard::catalogs::BUILTIN_CATALOG;
use rustmachineguard::models::{ExposureFinding, McpServerDetail};
use rustmachineguard::scanners::exposure::ExposureCatalog;

fn catalog() -> ExposureCatalog {
    ExposureCatalog::load_from_str(BUILTIN_CATALOG).expect("built-in catalog loads")
}

fn matches(cat: &ExposureCatalog, eco: &str, name: &str, version: &str) -> Vec<ExposureFinding> {
    let server = McpServerDetail {
        name: "s".into(),
        transport: "stdio".into(),
        command: Some(if eco == "pypi" { "uvx" } else { "npx" }.into()),
        package_ecosystem: Some(eco.into()),
        package_name: Some(name.into()),
        package_version: Some(version.into()),
        ..Default::default()
    };
    cat.check_mcp_server(&server, "/t/.mcp.json")
}

fn runtime(cat: &ExposureCatalog, key: &str, version: &str) -> usize {
    cat.check_extension("agent-runtime", key, version, "/t").len()
}

#[test]
fn malicious_packages_of_the_window_match_at_any_version() {
    let cat = catalog();
    for (eco, name) in [
        ("npm", "@iobandamwer/cache-helper"),
        ("npm", "@iobandamwer/native-helper"),
        ("npm", "path-stream-utils-testmetest"),
        ("npm", "event-bus-lite-testmetest"),
        ("npm", "data-pipeline-testmetest"),
        ("npm", "event-emitter-testmetest"),
        ("npm", "test-brotli-testmetest"),
        ("npm", "pixel-map-testmetest"),
        ("npm", "net-codec-testmetest"),
        ("npm", "log-rotate-testmetest"),
        ("pypi", "pystr-codec"),
        ("pypi", "is-it-ai"),
        ("pypi", "skills-analyzer"),
        ("pypi", "nebulallm"),
        ("npm", "@ifasn/mdd-doc-mcp"),
        ("npm", "@ifasn/mmd-doc-mcp"),
        ("npm", "@ifasn/md-doc-mcp"),
        ("npm", "@rfewqa-fes/mnm-doc-mcp"),
        ("npm", "@claudecode/cli"),
        ("npm", "@bestcoolman/dev-mcp"),
        ("npm", "mcp-contract-tester"),
        ("npm", "agent-trace-kit"),
        ("npm", "depfix-ai"),
        ("npm", "monitoring-agent"),
    ] {
        assert_eq!(matches(&cat, eco, name, "9.9.9").len(), 1, "{eco}:{name}");
    }
    // Anthropic's own CLI is a different package and stays clean.
    assert!(matches(&cat, "npm", "@anthropic-ai/claude-code", "9.9.9").is_empty());
}

#[test]
fn dsh_blender_plugin_matches_only_the_malicious_release() {
    let cat = catalog();
    assert_eq!(matches(&cat, "npm", "dsh-plugin-blender-3d", "0.2.1").len(), 1);
    assert!(matches(&cat, "npm", "dsh-plugin-blender-3d", "0.2.0").is_empty());
}

#[test]
fn reference_server_rows_end_at_the_new_fixed_releases() {
    let cat = catalog();
    for (eco, name, bad, fixed) in [
        ("pypi", "mcp-server-git", "2026.10.28", "2026.11.11"),
        ("pypi", "mcp-server-git", "2025.9.25", "2026.11.11"),
        ("pypi", "mcp-server-fetch", "2026.10.24", "2026.11.11"),
        ("npm", "@modelcontextprotocol/server-filesystem", "2.0.1", "2.3.0"),
        ("npm", "@modelcontextprotocol/server-filesystem", "2.2.0", "2.3.0"),
        ("npm", "@modelcontextprotocol/inspector", "2.12.0", "2.15.0"),
        ("npm", "@modelcontextprotocol/inspector", "2.14.0", "2.15.0"),
        ("npm", "@modelcontextprotocol/inspector", "1.0.3", "1.0.5"),
        ("npm", "@modelcontextprotocol/inspector-server", "1.0.4", "1.0.5"),
    ] {
        assert_eq!(matches(&cat, eco, name, bad).len(), 1, "{name} {bad} matches one row");
        assert!(matches(&cat, eco, name, fixed).is_empty(), "{name} {fixed} is clean");
    }
}

#[test]
fn vscode_and_kiro_cli_are_matched_by_their_own_version_lines() {
    let cat = catalog();
    assert_eq!(runtime(&cat, "vscode", "1.145.2"), 1);
    assert_eq!(runtime(&cat, "vscode", "1.145.3"), 0);
    assert_eq!(runtime(&cat, "kiro-cli", "1.16.0"), 1);
    assert_eq!(runtime(&cat, "kiro-cli", "2.26.9"), 1);
    assert_eq!(runtime(&cat, "kiro-cli", "2.27.0"), 0);
    assert_eq!(runtime(&cat, "kiro-cli", "1.15.0"), 0);
    // The IDE's row (`<0.8.135`) must not match a CLI version, nor the reverse.
    assert_eq!(runtime(&cat, "kiro-ide", "2.0.0"), 0);
}
