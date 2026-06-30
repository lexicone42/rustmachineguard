use serde::Serialize;

/// Top-level scan report matching the upstream JSON schema,
/// extended with new detection categories.
#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub agent_version: String,
    pub scan_timestamp: i64,
    pub scan_timestamp_iso: String,
    pub device: DeviceInfo,
    pub ai_agents_and_tools: Vec<AiTool>,
    pub ai_frameworks: Vec<AiFramework>,
    pub ide_installations: Vec<IdeInstallation>,
    pub ide_extensions: Vec<IdeExtension>,
    pub mcp_configs: Vec<McpConfig>,
    pub node_package_managers: Vec<NodePackageManager>,
    pub shell_configs: Vec<ShellConfig>,
    pub ssh_keys: Vec<SshKey>,
    pub cloud_credentials: Vec<CloudCredential>,
    pub container_tools: Vec<ContainerTool>,
    pub notebook_servers: Vec<NotebookServer>,
    pub browser_extensions: Vec<BrowserExtension>,
    pub package_config_audits: Vec<PackageConfigAudit>,
    pub rules_files: Vec<RulesFile>,
    pub agent_skills: Vec<AgentSkill>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub agent_settings: Vec<AgentSettings>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ai_credentials: Vec<AiCredential>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env_files: Vec<EnvFile>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exposure_findings: Vec<ExposureFinding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mcp_probes: Vec<McpProbeResult>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<ScanWarning>,
    pub summary: Summary,
}

/// A non-fatal issue encountered during scanning.
#[derive(Debug, Serialize, Clone)]
pub struct ScanWarning {
    pub scanner: String,
    pub message: String,
}

/// Results from live-probing an MCP server via JSON-RPC.
#[derive(Debug, Serialize, Clone)]
pub struct McpProbeResult {
    pub server_name: String,
    pub config_source: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_info: Option<McpServerInfo>,
    pub tools: Vec<McpToolInfo>,
    pub resources: Vec<McpResourceInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub observed_capabilities: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct McpServerInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct McpToolInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The tool's JSON-Schema parameter definition (MCP `inputSchema`), captured so
    /// rug-pull diffing can detect parameter mutations and injection hidden in
    /// parameter descriptions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Clone)]
pub struct McpResourceInfo {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeviceInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub platform: String,
    pub kernel_version: String,
    pub user_identity: String,
    pub home_dir: String,
}

#[derive(Debug, Serialize)]
pub struct AiTool {
    pub name: String,
    pub vendor: String,
    #[serde(rename = "type")]
    pub tool_type: AiToolType,
    pub version: Option<String>,
    pub binary_path: Option<String>,
    pub config_dir: Option<String>,
    pub install_path: Option<String>,
    pub is_running: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AiToolType {
    CliTool,
    DesktopApp,
    Agent,
}

#[derive(Debug, Serialize)]
pub struct AiFramework {
    pub name: String,
    pub vendor: String,
    pub version: Option<String>,
    pub binary_path: Option<String>,
    pub is_running: bool,
}

#[derive(Debug, Serialize)]
pub struct IdeInstallation {
    pub ide_type: String,
    pub version: Option<String>,
    pub install_path: String,
    pub vendor: String,
    pub is_installed: bool,
}

#[derive(Debug, Serialize)]
pub struct IdeExtension {
    pub id: String,
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub ide_type: String,
}

#[derive(Debug, Serialize)]
pub struct McpConfig {
    pub config_source: String,
    pub config_path: String,
    pub vendor: String,
    pub server_names: Vec<String>,
    pub server_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<McpServerDetail>,
}

#[derive(Debug, Serialize, Clone)]
pub struct McpServerDetail {
    pub name: String,
    pub transport: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_ecosystem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct NodePackageManager {
    pub name: String,
    pub version: Option<String>,
    pub path: Option<String>,
}

// --- New detection categories ---

#[derive(Debug, Serialize)]
pub struct ShellConfig {
    pub shell: String,
    pub config_path: String,
    /// AI-related environment variables or aliases found
    pub ai_related_entries: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SshKey {
    pub path: String,
    pub key_type: String,
    pub has_passphrase: PassphraseStatus,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PassphraseStatus {
    Encrypted,
    NoPassphrase,
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct CloudCredential {
    pub provider: String,
    pub credential_type: String,
    pub config_path: String,
    pub profiles: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ContainerTool {
    pub name: String,
    pub version: Option<String>,
    pub binary_path: Option<String>,
    pub is_running: bool,
}

#[derive(Debug, Serialize)]
pub struct NotebookServer {
    pub name: String,
    pub version: Option<String>,
    pub binary_path: Option<String>,
    pub is_running: bool,
}

#[derive(Debug, Serialize)]
pub struct BrowserExtension {
    pub browser: String,
    pub name: String,
    pub id: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub profile: String,
}

#[derive(Debug, Serialize)]
pub struct PackageConfigAudit {
    pub manager: String,
    pub config_path: String,
    pub findings: Vec<PackageConfigFinding>,
}

#[derive(Debug, Serialize)]
pub struct PackageConfigFinding {
    pub severity: String,
    pub description: String,
}

/// A rules/instruction file that controls agent behavior.
#[derive(Debug, Serialize)]
pub struct RulesFile {
    pub path: String,
    pub file_name: String,
    pub sha256: String,
    pub git_tracked: bool,
    pub size_bytes: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<RulesFileFinding>,
}

/// A dangerous pattern found in a rules file.
#[derive(Debug, Serialize, Clone)]
pub struct RulesFileFinding {
    pub severity: String,
    pub pattern: String,
}

/// An agent skill (custom command, hook, or plugin).
#[derive(Debug, Serialize)]
pub struct AgentSkill {
    pub name: String,
    pub path: String,
    pub framework: String,
    pub scope: String,
    pub file_type: String,
    pub size_bytes: usize,
    pub sha256: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

/// An agent settings file (Claude Code / Codex), which can register hooks that run
/// shell commands on agent events and auto-approve MCP servers.
#[derive(Debug, Serialize)]
pub struct AgentSettings {
    pub path: String,
    /// "user-global" | "local" | "project"
    pub source: String,
    pub framework: String,
    /// Project-scoped settings from a cloned repo are higher risk; git_tracked tells
    /// whether this file travels with a repository.
    pub git_tracked: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hooks: Vec<AgentHook>,
    /// `permissions.defaultMode` (e.g. "acceptEdits", "bypassPermissions").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_mode: Option<String>,
    pub allow_rules: usize,
    pub deny_rules: usize,
    /// `enableAllProjectMcpServers` — auto-approves all project MCP servers (a
    /// workspace-trust bypass).
    pub auto_approve_mcp: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub enabled_mcp_servers: Vec<String>,
}

/// A hook that runs a command on an agent lifecycle event.
#[derive(Debug, Serialize, Clone)]
pub struct AgentHook {
    /// Event name, e.g. "PreToolUse", "PostToolUse", "Stop".
    pub event: String,
    /// Tool matcher, e.g. "Bash", "*". None or "*" means it runs for every tool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matcher: Option<String>,
    pub command: String,
    /// True if the command matches a dangerous pattern (curl|bash, base64 decode, …).
    pub dangerous: bool,
}

/// At-rest AI-service credential file (existence + permissions only; values never read).
#[derive(Debug, Serialize)]
pub struct AiCredential {
    pub provider: String,
    pub credential_type: String,
    pub path: String,
    /// Octal permission bits, e.g. "0600". None on non-Unix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<String>,
    pub world_readable: bool,
    pub group_readable: bool,
}

/// A `.env` file in an agent project root (agents read the working directory).
#[derive(Debug, Serialize)]
pub struct EnvFile {
    pub path: String,
    /// A git-tracked .env is a committed secret.
    pub git_tracked: bool,
    pub world_readable: bool,
    /// Count of `KEY=value` lines (names parsed, values never stored).
    pub key_count: usize,
    /// NAMES (never values) of keys that look secret-bearing (TOKEN/SECRET/KEY/...).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub secret_keys: Vec<String>,
}

/// Exposure catalog entry for known-bad packages.
#[derive(Debug, Serialize, serde::Deserialize, Clone)]
pub struct ExposureEntry {
    pub ecosystem: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Semver range of affected versions, e.g. "< 2.0.0" or ">=1.0,<1.5". When set,
    /// matches any version satisfying the range (for "vulnerable below X" cases).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_range: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory: Option<String>,
}

/// A matched exposure finding.
#[derive(Debug, Serialize)]
pub struct ExposureFinding {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub advisory: String,
    pub found_in: String,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub ai_agents_and_tools_count: usize,
    pub ai_frameworks_count: usize,
    pub ide_installations_count: usize,
    pub ide_extensions_count: usize,
    pub mcp_configs_count: usize,
    pub mcp_servers_count: usize,
    pub node_package_managers_count: usize,
    pub shell_configs_count: usize,
    pub ssh_keys_count: usize,
    pub cloud_credentials_count: usize,
    pub container_tools_count: usize,
    pub notebook_servers_count: usize,
    pub browser_extensions_count: usize,
    pub package_config_audits_count: usize,
    pub rules_files_count: usize,
    pub agent_skills_count: usize,
    pub agent_settings_count: usize,
    pub agent_hooks_count: usize,
    pub ai_credentials_count: usize,
    pub env_files_count: usize,
    pub rules_file_findings_count: usize,
    pub exposure_findings_count: usize,
}

impl ScanReport {
    pub fn compute_summary(&mut self) {
        self.summary = Summary {
            ai_agents_and_tools_count: self.ai_agents_and_tools.len(),
            ai_frameworks_count: self.ai_frameworks.len(),
            ide_installations_count: self.ide_installations.len(),
            ide_extensions_count: self.ide_extensions.len(),
            mcp_configs_count: self.mcp_configs.len(),
            mcp_servers_count: self.mcp_configs.iter().map(|c| c.server_count).sum(),
            node_package_managers_count: self.node_package_managers.len(),
            shell_configs_count: self.shell_configs.len(),
            ssh_keys_count: self.ssh_keys.len(),
            cloud_credentials_count: self.cloud_credentials.len(),
            container_tools_count: self.container_tools.len(),
            notebook_servers_count: self.notebook_servers.len(),
            browser_extensions_count: self.browser_extensions.len(),
            package_config_audits_count: self.package_config_audits.len(),
            rules_files_count: self.rules_files.len(),
            agent_skills_count: self.agent_skills.len(),
            agent_settings_count: self.agent_settings.len(),
            agent_hooks_count: self.agent_settings.iter().map(|s| s.hooks.len()).sum(),
            ai_credentials_count: self.ai_credentials.len(),
            env_files_count: self.env_files.len(),
            rules_file_findings_count: self.rules_files.iter().map(|r| r.findings.len()).sum(),
            exposure_findings_count: self.exposure_findings.len(),
        };
    }
}
