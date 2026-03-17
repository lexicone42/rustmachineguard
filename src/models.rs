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
    // New detection categories beyond upstream
    pub shell_configs: Vec<ShellConfig>,
    pub ssh_keys: Vec<SshKey>,
    pub cloud_credentials: Vec<CloudCredential>,
    pub container_tools: Vec<ContainerTool>,
    pub notebook_servers: Vec<NotebookServer>,
    pub summary: Summary,
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
    /// Server names found in the config (keys of "mcpServers")
    pub server_names: Vec<String>,
    /// Number of servers configured
    pub server_count: usize,
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
    pub has_passphrase: bool,
    pub comment: Option<String>,
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
pub struct Summary {
    pub ai_agents_and_tools_count: usize,
    pub ai_frameworks_count: usize,
    pub ide_installations_count: usize,
    pub ide_extensions_count: usize,
    pub mcp_configs_count: usize,
    pub node_package_managers_count: usize,
    pub shell_configs_count: usize,
    pub ssh_keys_count: usize,
    pub cloud_credentials_count: usize,
    pub container_tools_count: usize,
    pub notebook_servers_count: usize,
}

impl ScanReport {
    pub fn compute_summary(&mut self) {
        self.summary = Summary {
            ai_agents_and_tools_count: self.ai_agents_and_tools.len(),
            ai_frameworks_count: self.ai_frameworks.len(),
            ide_installations_count: self.ide_installations.len(),
            ide_extensions_count: self.ide_extensions.len(),
            mcp_configs_count: self.mcp_configs.len(),
            node_package_managers_count: self.node_package_managers.len(),
            shell_configs_count: self.shell_configs.len(),
            ssh_keys_count: self.ssh_keys.len(),
            cloud_credentials_count: self.cloud_credentials.len(),
            container_tools_count: self.container_tools.len(),
            notebook_servers_count: self.notebook_servers.len(),
        };
    }
}
