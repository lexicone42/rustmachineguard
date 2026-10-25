use serde::{Deserialize, Serialize};

/// Top-level scan report matching the upstream JSON schema,
/// extended with new detection categories.
#[derive(Debug, Serialize, Deserialize)]
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
    /// MCP servers that have run, per Claude Code's MCP log directories
    /// (`~/.cache/claude-cli-nodejs/<project>/mcp-logs-<server>/`): directory NAMES only,
    /// never a log file's contents.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mcp_observed_servers: Vec<McpObservedServer>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_settings: Vec<AgentSettings>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ai_credentials: Vec<AiCredential>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_files: Vec<EnvFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exposure_findings: Vec<ExposureFinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mcp_probes: Vec<McpProbeResult>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mcp_registry_checks: Vec<crate::registry::RegistryCheck>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_identity: Option<crate::identity::AgentIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transcripts: Vec<AgentTranscriptStore>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub marketplaces: Vec<AgentMarketplace>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vscode_tasks: Vec<VsCodeTask>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub git_autorun_configs: Vec<GitAutorunConfig>,
    /// User-installed JetBrains IDE plugins (identity only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jetbrains_plugins: Vec<JetBrainsPlugin>,
    #[serde(default)]
    pub persistence_artifacts: Vec<PersistenceArtifact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<ScanWarning>,
    /// Per-scanner telemetry: how long it ran, how many files it opened or found
    /// missing, how many items it produced. This exists to make "clean machine"
    /// distinguishable from "looked in the wrong place" -- every silent-zero bug in the
    /// project's history (bunfig at the wrong path, 31 unreachable catalog rows, a
    /// budget exhausted before the walk reached anything) would have shown here as
    /// files_read=0.
    #[serde(default)]
    pub diagnostics: Vec<ScannerStat>,
    /// Which threat catalog the exposure findings were matched against. Absent in
    /// reports from older versions (read back as the default: no version, 0 entries).
    #[serde(default)]
    pub catalog: CatalogInfo,
    /// Round-3b sections (LSP servers, liveness, browser profiles, ...), flattened.
    #[serde(flatten, default)]
    pub surfaces: SurfaceInventory,
    pub summary: Summary,
}

/// The threat catalog a scan used: rmguard's own data, never anything read from the
/// machine (a `--threat-catalog` file contributes only its entry count).
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct CatalogInfo {
    /// `catalogs::BUILTIN_CATALOG_VERSION` when the built-in catalog was loaded; `None`
    /// with `--no-builtin-catalog`.
    pub builtin_version: Option<String>,
    /// Entries of the built-in catalog that were loaded (0 when it was not).
    pub builtin_entries: usize,
    /// Entries loaded from `--threat-catalog` (0 without it).
    pub user_entries: usize,
}

/// A non-fatal issue encountered during scanning.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanWarning {
    pub scanner: String,
    pub message: String,
}

/// Results from live-probing an MCP server via JSON-RPC.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct McpProbeResult {
    pub server_name: String,
    pub config_source: String,
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_info: Option<McpServerInfo>,
    pub tools: Vec<McpToolInfo>,
    pub resources: Vec<McpResourceInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub observed_capabilities: Vec<String>,
    /// The server's free-text `instructions`, which the host splices into the model's
    /// system prompt. Scanned for injection like any tool description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    /// Which protocol era the server actually spoke: "modern" (2026-07-28+, no
    /// handshake) or "legacy" (initialize). Determined by probing, never assumed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_era: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct McpServerInfo {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct McpToolInfo {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The tool's JSON-Schema parameter definition (MCP `inputSchema`), captured so
    /// rug-pull diffing can detect parameter mutations and injection hidden in
    /// parameter descriptions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct McpResourceInfo {
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub platform: String,
    pub kernel_version: String,
    pub user_identity: String,
    pub home_dir: String,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiToolType {
    CliTool,
    DesktopApp,
    Agent,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AiFramework {
    pub name: String,
    pub vendor: String,
    pub version: Option<String>,
    pub binary_path: Option<String>,
    pub is_running: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdeInstallation {
    pub ide_type: String,
    pub version: Option<String>,
    pub install_path: String,
    pub vendor: String,
    pub is_installed: bool,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct IdeExtension {
    pub id: String,
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub ide_type: String,
    /// `package.json` `categories` (sanitized, at most 10). Attacker-authored.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    /// Which code entry points the manifest declares: static labels from
    /// {"main", "browser", "activationEvents"}.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code_entry_points: Vec<String>,
    /// `contributes` has themes, iconThemes or productIconThemes.
    #[serde(default)]
    pub contributes_theme: bool,
    /// `contributes` declares commands or configuration: the extension says what its
    /// code is for (an icon theme with a "toggle folder icons" command).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub contributes_commands: bool,
    /// The extension presents itself as declarative (themes, snippets, keymaps,
    /// language packs): such an extension has no reason to run code.
    #[serde(default)]
    pub declarative_claim: bool,
    /// Native `.node` addons (ELF/Mach-O/PE by magic bytes) inside the extension
    /// directory, relative paths, at most 5. ONLY inspected when `declarative_claim`
    /// is true: ordinary extensions (Pylance, Jupyter) legitimately ship native addons,
    /// so the walk never runs for them and this stays empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub native_addons: Vec<String>,
    /// The extension's directory (sanitized). The same id can be installed for several
    /// IDEs or in several versions; this says which copy a finding is about.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct McpConfig {
    pub config_source: String,
    pub config_path: String,
    pub vendor: String,
    pub server_names: Vec<String>,
    pub server_count: usize,
    /// True if this config file is tracked by git — a git-tracked config carrying an
    /// inline credential is a committed secret (parallels a git-tracked `.env`).
    #[serde(default)]
    pub git_tracked: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<McpServerDetail>,
}

/// Where a server's definition came from when no config file of the user's holds it:
/// `McpConfig::config_source` for a Claude Code plugin's `.mcp.json` / `plugin.json`
/// `mcpServers` (code.claude.com/docs/en/plugins-reference#mcpservers).
pub const MCP_SOURCE_PLUGIN: &str = "plugin";
/// `McpConfig::config_source` for the claude.ai connectors Claude Code lists as ever
/// connected (`claudeAiMcpEverConnected` in `~/.claude.json`; code.claude.com/docs/en/mcp,
/// "Use MCP servers from claude.ai").
pub const MCP_SOURCE_CONNECTOR: &str = "claude.ai connector";
/// The transport of a claude.ai connector: Anthropic connects to it, not this machine.
pub const MCP_TRANSPORT_CONNECTOR: &str = "remote (vendor-hosted)";

/// One `mcp-logs-<server>` directory name seen under Claude Code's per-project log cache.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct McpObservedServer {
    /// The directory name after `mcp-logs-` (sanitized). Claude Code writes plugin
    /// servers as `plugin-<plugin>-<server>` and connectors as `claude-ai-<Name>`.
    pub name: String,
    /// Project log directories it appears in.
    pub projects: usize,
    /// Newest modification time of those log directories (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub newest_mtime: Option<i64>,
    /// The log cache it was found in (sanitized).
    pub log_root: String,
    /// A configured, plugin or connector server of this scan has this log name.
    #[serde(default)]
    pub configured: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct McpServerDetail {
    pub name: String,
    pub transport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_ecosystem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// NAMES (never values) of secret-looking env vars set to a hardcoded literal in
    /// this server's config `env` block — i.e. a credential committed inline rather
    /// than referenced via `${VAR}`. Empty when the env block is absent or clean.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inline_secret_env_keys: Vec<String>,
    /// NAMES of secret-looking `headers` set to a hardcoded literal (never values).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inline_secret_header_keys: Vec<String>,
    /// The `env` block by SHAPE: `NAME=${REF}`, `NAME=$REF` or `NAME=<redacted>`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// The `headers` block by SHAPE: `Name: Bearer ${REF}` or `Name: <redacted>`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<String>,
    /// Plugin servers: the plugin that ships it, `plugin@marketplace` (sanitized).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,
    /// Plugin servers: whether the plugin is enabled (`enabledPlugins`, managed
    /// force-enables applied). Connectors: `Some(false)` under `disableClaudeAiConnectors`,
    /// else unknown (`None`). Configured servers: `None` (loaded as configured).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// claude.ai connectors: Claude Code lists it in `claudeAiMcpEverConnected`. This
    /// says the connector was connected at some point, not that it is enabled now.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ever_connected: bool,
    /// Why the launch runs whatever version is current: "@latest", "no version",
    /// "git HEAD", "docker :latest". Only stdio launchers through a package runner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unpinned: Option<String>,
    /// Packages the launch installs next to the one it runs: `uvx` / `uv run` /
    /// `uv tool run` `--with` requirements (name and version spec, redacted and
    /// sanitized), in order. Matched against the catalog and graded by the unpinned rule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_packages: Vec<String>,
    /// Project `.mcp.json` servers: listed in `enabledMcpjsonServers` of that project's
    /// `.claude/settings.json` or `settings.local.json` (approved by the user;
    /// code.claude.com/docs/en/settings.md, /mcp.md). A server listed in
    /// `disabledMcpjsonServers` there is `enabled: false` instead.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub approved: bool,
}

impl McpServerDetail {
    /// Nothing marks this server off: not a disabled plugin's, not under
    /// `disableClaudeAiConnectors`.
    pub fn is_active(&self) -> bool {
        self.enabled != Some(false)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodePackageManager {
    pub name: String,
    pub version: Option<String>,
    pub path: Option<String>,
}

// --- New detection categories ---

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ShellConfig {
    /// "bash" | "zsh" | ... for rc files; "systemd-user" | "systemd-system" | "launchd"
    /// for service definitions that set OLLAMA_HOST.
    pub shell: String,
    pub config_path: String,
    /// AI-related environment variables or aliases found
    pub ai_related_entries: Vec<String>,
    /// The last OLLAMA_HOST assignment in this file, classified the way Ollama parses it.
    /// Not a secret: a bind address. Userinfo is stripped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ollama_host: Option<OllamaHostSetting>,
}

/// An OLLAMA_HOST value and where it makes the Ollama server listen.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct OllamaHostSetting {
    /// Sanitized host[:port] as written (userinfo stripped).
    pub value: String,
    /// "wildcard" | "non-loopback-ip" | "hostname" | "loopback" | "unresolved"
    pub bind: String,
    /// True when the source is the Ollama server's own service definition (a unit or
    /// launchd job for ollama), so the value is a server bind, not a client target.
    #[serde(default)]
    pub service: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SshKey {
    pub path: String,
    pub key_type: String,
    pub has_passphrase: PassphraseStatus,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PassphraseStatus {
    Encrypted,
    NoPassphrase,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CloudCredential {
    pub provider: String,
    pub credential_type: String,
    pub config_path: String,
    pub profiles: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContainerTool {
    pub name: String,
    pub version: Option<String>,
    pub binary_path: Option<String>,
    pub is_running: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NotebookServer {
    pub name: String,
    pub version: Option<String>,
    pub binary_path: Option<String>,
    pub is_running: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BrowserExtension {
    pub browser: String,
    pub name: String,
    pub id: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub profile: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PackageConfigAudit {
    pub manager: String,
    pub config_path: String,
    pub findings: Vec<PackageConfigFinding>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PackageConfigFinding {
    pub severity: String,
    pub description: String,
}

/// A rules/instruction file that controls agent behavior.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct RulesFile {
    pub path: String,
    pub file_name: String,
    pub sha256: String,
    pub git_tracked: bool,
    pub size_bytes: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<RulesFileFinding>,
    /// Absent for an instruction file (CLAUDE.md, .cursorrules, ...). "memory" (a Serena
    /// memory), "auto-memory" (Claude Code's `~/.claude/projects/<project>/memory/`),
    /// "agent-memory" (a Claude Code subagent's `agent-memory/<name>/`) or
    /// "prompt-config" (Serena `project.yml` `initial_prompt`): text an agent loads or
    /// reads on its own, found by walking a directory rather than by a fixed name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The agent that loads it, for a `kind` row: "serena" or "claude-code".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    /// For a `kind` row: "user" (under a scan home), "project" or "local".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// A dangerous pattern found in a rules file.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RulesFileFinding {
    pub severity: String,
    pub pattern: String,
}

/// An agent skill (custom command, hook, or plugin).
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AgentSkill {
    pub name: String,
    pub path: String,
    pub framework: String,
    pub scope: String,
    /// "skill-manifest", "command" (a `commands/*.md` inside a bundle walk), or the
    /// file extension.
    pub file_type: String,
    pub size_bytes: usize,
    /// sha256 of the content, "unreadable", or "symlink-not-followed" for a symlink
    /// into a sensitive path (never read).
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// Set when the skill file is a symbolic link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symlink: Option<SkillSymlink>,
    /// Dynamic context injection: commands Claude Code runs when the skill loads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dynamic_commands: Vec<SkillDynamicCommand>,
    /// `allowed-tools` pre-approves unrestricted Bash (Bash, Bash(*), PowerShell).
    #[serde(default)]
    pub unrestricted_bash: bool,
    /// Where the skill came from, used to grade the two fields above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<SkillProvenance>,
    /// Frontmatter `hooks:` (skills, commands and subagent files).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hooks: Vec<AgentHook>,
}

/// A skill file that is a symbolic link, or a regular file reached through a symlinked
/// directory. `target` is the link text (sanitized); for `through_directory`, the real
/// path. The verdict is made on the fully resolved real path and on the lexical target.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SkillSymlink {
    pub target: String,
    /// The real path lies outside the skill's directory (for a project: its repository).
    pub escapes: bool,
    /// The real or lexical target is a credential, key, shell-rc/history, agent-config
    /// or system path. Such a target is never read.
    pub sensitive_target: bool,
    /// Why a sensitive target was refused: "credential" (a credential, key, `.env` or
    /// shell-rc path), "agent-config", "other-home" or "system". Absent when not sensitive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive_kind: Option<String>,
    /// True when the target was read.
    pub followed: bool,
    /// The real path is in a read-only content-addressed store (/nix/store).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub store: bool,
    /// The file itself is not a link; a directory above it is.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub through_directory: bool,
    /// The link resolves to nothing (dangling or looping); `escapes` is judged on the
    /// lexical target.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dangling: bool,
}

/// One dynamic-context command (`!`cmd`` or a ```! block) in a skill or command file.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SkillDynamicCommand {
    /// Redacted and sanitized command text.
    pub command: String,
    /// Matches the dangerous-pattern set used for hooks.
    pub dangerous: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<String>,
    /// From a ```! fenced block rather than an inline placeholder.
    #[serde(default)]
    pub block: bool,
}

/// Provenance of a skill file: plugin marketplace, activation and git status.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SkillProvenance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marketplace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,
    /// The marketplace is listed in known_marketplaces.json and is not Anthropic's.
    #[serde(default)]
    pub third_party: bool,
    /// The file lies under an installed plugin's installPath and the plugin is not
    /// disabled in enabledPlugins. Marketplace clones and orphaned versions never are.
    #[serde(default)]
    pub active: bool,
    /// Project skills inside a git work tree: "tracked" | "untracked".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<String>,
    /// Under ~/.claude/skills/synced/ (dynamic context does not run locally for these).
    #[serde(default)]
    pub synced: bool,
}

/// An agent settings file (Claude Code / Codex), which can register hooks that run
/// shell commands on agent events and auto-approve MCP servers.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AgentSettings {
    pub path: String,
    /// "user-global" | "user-local" (~/.claude/settings.local.json, seen when the scan
    /// runs from HOME) | "local" | "project" | "managed" | "plugin" (a plugin- or
    /// extension-bundled hook file of any framework)
    pub source: String,
    pub framework: String,
    /// Project-scoped settings from a cloned repo are higher risk; git_tracked tells
    /// whether this file travels with a repository.
    pub git_tracked: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hooks: Vec<AgentHook>,
    /// `permissions.defaultMode` (e.g. "acceptEdits", "bypassPermissions").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_mode: Option<String>,
    pub allow_rules: usize,
    pub deny_rules: usize,
    /// `enableAllProjectMcpServers` — auto-approves all project MCP servers (a
    /// workspace-trust bypass).
    pub auto_approve_mcp: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enabled_mcp_servers: Vec<String>,
    /// AI provider base-URL / gateway overrides set in the settings `env` block.
    /// A non-official host is the EAA-007 "hostile gateway routing" surface — the
    /// vector behind Claude Code CVE-2026-21852 (API-key exfil via a malicious proxy).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gateway_overrides: Vec<GatewayOverride>,
    /// NAMES (never values) of secret-looking env vars set to a hardcoded literal in
    /// the settings `env` block — a credential committed inline rather than referenced.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inline_secret_env_keys: Vec<String>,
    /// True if the config file is writable by group or other — any local process can
    /// append a hook, which the agent then runs.
    #[serde(default)]
    pub world_writable: bool,
    /// Credential and telemetry helpers (apiKeyHelper, awsAuthRefresh, ...): shell
    /// commands Claude Code runs on its own. Recorded like hooks (redacted); `event` is
    /// the settings key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub helper_commands: Vec<AgentHook>,
    /// forceLoginMethod / forceLoginGatewayUrl.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_gateway: Option<LoginGateway>,
    /// `disableSkillShellExecution`: skills and commands may not run inline shell.
    #[serde(default)]
    pub disable_skill_shell_execution: bool,
    /// A project or local settings file that is a symlink (or sits under a symlinked
    /// agent directory) leaving its repository: recorded by its lexical target and never
    /// opened, so every other field is empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symlink: Option<EnvSymlink>,
    /// Plugin-bundled hook files (source "plugin"): which plugin shipped them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<SkillProvenance>,
    /// Claude Code `allowManagedHooksOnly` (honoured in managed settings only).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_managed_hooks_only: bool,
    /// Claude Code `disableAllHooks`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_all_hooks: bool,
    /// Managed settings only: the `enabledPlugins` keys (`plugin@marketplace`) set to
    /// true. Their hooks run even under `allowManagedHooksOnly`. Sorted, at most 200.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub force_enabled_plugins: Vec<String>,
    /// Claude Code `skipDangerousModePermissionPrompt`: the confirmation dialog before a
    /// session enters `bypassPermissions` mode is skipped. Honoured in user, local and
    /// managed settings only (code.claude.com/docs/en/settings-reference).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub skip_dangerous_mode_prompt: bool,
    /// The `permissions.allow`, `ask` and `deny` rules themselves (counts above): each
    /// redacted and sanitized to at most 200 characters, at most 200 per list. Every
    /// allow rule is classified; the stored list always keeps the classified ones and
    /// fills the rest of the 200 with unclassified rules in file order. An allow rule
    /// carries the class rmguard grades it by, if any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permission_rules: Vec<PermissionRule>,
    /// Claude Code `permissions.disableAutoMode: "disable"` (auto mode removed).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_auto_mode: bool,
    /// Claude Code `autoMode` block (code.claude.com/docs/en/auto-mode-config.md), by
    /// shape: which lists are set, whether each keeps `"$defaults"`, and what the
    /// custom entries are (see [`AutoModeList`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_mode: Option<AutoModeSettings>,
}

/// A settings file's `autoMode` block. Only the keys the auto-mode-config page documents
/// are read: `environment`, `allow`, `soft_deny`, `hard_deny`, `classifyAllShell`.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct AutoModeSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<AutoModeList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<AutoModeList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soft_deny: Option<AutoModeList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard_deny: Option<AutoModeList>,
    /// `autoMode.classifyAllShell`: every Bash and PowerShell allow rule is suspended
    /// while auto mode is active, so the classifier sees every shell command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classify_all_shell: Option<bool>,
}

/// One `autoMode` list (an array of prose rules).
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct AutoModeList {
    /// The list contains the literal `"$defaults"`, which splices the built-in entries in.
    pub has_defaults: bool,
    /// String entries other than `"$defaults"`.
    pub entries: usize,
    /// `allow`: the custom entries, redacted by shape and sanitized (at most 20 of 200
    /// characters). `environment`: the slot label of each custom entry (the text before
    /// its first `:` when that is a documented slot name, else `custom entry`), never
    /// the entry's text. Empty for `soft_deny` and `hard_deny`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shown: Vec<String>,
}

/// One Claude Code permission rule (code.claude.com/docs/en/permissions.md).
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct PermissionRule {
    /// "allow" | "ask" | "deny"
    pub list: String,
    /// The rule text, redacted and sanitized (at most 200 characters).
    pub rule: String,
    /// Allow rules only: "mcp-server-wildcard" | "code-execution" | "credential-read" |
    /// "credential-edit" | "inert-path" (see `scanners::agent_settings`). None: a scoped
    /// rule that is inventoried, not graded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    /// mcp-server-wildcard: the server segment of the tool name. inert-path: what the
    /// rule matches instead of the path it names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Claude Code's forced login method / Claude apps gateway URL.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct LoginGateway {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// Claude Code honours forceLoginGatewayUrl only in user or managed settings.
    #[serde(default)]
    pub effective: bool,
}

/// An AI provider base-URL override (e.g. ANTHROPIC_BASE_URL) found in a settings
/// `env` block. `official` is true only when the host matches the provider's known
/// endpoint; a non-official host warrants review (a proxy may be legitimate or hostile).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GatewayOverride {
    pub var: String,
    pub host: String,
    pub official: bool,
}

/// A hook that runs on an agent lifecycle event: a shell command, an HTTP endpoint, a
/// model prompt, an MCP tool call or an in-process module.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AgentHook {
    /// Event name, e.g. "PreToolUse", "PostToolUse", "Stop".
    pub event: String,
    /// Tool matcher, e.g. "Bash", "*". None or "*" means it runs for every tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matcher: Option<String>,
    pub command: String,
    /// True if the command matches a dangerous pattern (curl|bash, base64 decode, …).
    pub dangerous: bool,
    /// What the command *references*, as distinct from what it pattern-matches — e.g.
    /// a script stored in an agent-config directory, or a native binary. Empty for an
    /// ordinary inline command. See `agent_settings::classify_hook_command`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub risks: Vec<String>,
    /// "command" | "settings-command" (statusLine, subagentStatusLine, fileSuggestion) |
    /// "http" | "prompt" | "agent" | "mcp_tool" | "module" | "unknown".
    /// Empty means command (older reports, credential helpers).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    /// Exec-form argv (Claude Code `args`, Copilot `exec` + `args`): each element
    /// redacted and sanitized, at most 64.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Dangerous-pattern descriptions the command matched, medium-only ones included.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<String>,
    /// The highest severity among `patterns` ("critical" | "high" | "medium" | "low");
    /// empty when nothing matched.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pattern_severity: String,
    /// Patterns the text matched only where they cannot run: inside a guard's test
    /// argument (`grep -q 'curl .* | sh' && exit 2`), as data sent to a loopback host
    /// (`jq . | curl -d @- http://localhost:8080/log`), or (modules) in a string or
    /// comment that no shell-execution call receives. Advisory, never dangerous.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advisory_patterns: Vec<String>,
    /// Claude Code's `if` handler field (permission-rule syntax, `Bash(git *)`): the hook
    /// runs only for tool calls that match it. Redacted and sanitized.
    #[serde(default, rename = "if", skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    /// http hooks: the URL host only (never path, query, userinfo or headers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_host: Option<String>,
    /// http hooks: "http" | "https" | "<other>".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_scheme: Option<String>,
    /// http hooks: the host is an AI provider's own API (the official-host model).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub first_party_host: bool,
    /// prompt/agent hooks: prompt-injection phrases matched in the prompt text, hidden
    /// characters (`invisible Unicode (...)`) and, for a prompt the agent itself reads,
    /// the credential paths it names (`credential path ~/.aws/credentials`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub poisoning: Vec<String>,
    /// prompt/agent hooks: where the prompt goes. "evaluator": a separate model that
    /// returns a decision (Claude Code, Cursor); "conversation": submitted into the
    /// agent's own conversation (Copilot CLI prompt hooks, Kiro agent actions);
    /// "undocumented": the vendor does not say (Devin CLI and others), graded as
    /// "conversation". Empty for other kinds and in older reports (read as "evaluator").
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prompt_target: String,
    /// module hooks: event names the module registers (lexical, sorted, deduped).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub registers: Vec<String>,
    /// command hooks: the host a notification hook sends fields of its own event to
    /// (`jq -r .message | curl -d @- ntfy.sh/topic`, see
    /// `hook_sources::event_push_host`). Host only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_host: Option<String>,
    /// The source marks the hook off (Kiro `enabled: false`, Copilot file-level
    /// `disableAllHooks: true`): inventoried, not graded.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    /// Why a hook is `disabled` when its own source does not say so (the managed Claude
    /// Code `allowManagedHooksOnly` / `disableAllHooks` silencing it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<String>,
}

/// An agent transcript / conversation-state store (EAA-005 collection surface).
/// Records existence, size, and permissions only — content is never read.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AgentTranscriptStore {
    pub framework: String,
    pub path: String,
    /// e.g. "conversation transcripts", "command history", "sessions".
    pub kind: String,
    pub file_count: usize,
    pub total_size_bytes: u64,
    pub world_readable: bool,
    /// Files in the store other users can read: mode o+r on the file and o+x on every
    /// directory between it and the store root. None in reports from older versions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readable_files: Option<usize>,
    /// The store's own mode (`0644`), and whether it is group-readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub group_readable: bool,
    /// An ancestor directory other users cannot traverse (no o+x), e.g. a HOME of 0700:
    /// `"/home/u is 0700"`. Set means the store is not reachable by other users whatever
    /// its own mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreachable_via: Option<String>,
    /// Claude Code `session-env` and `shell-snapshots` stores with files other users can
    /// read: the variable NAMES their files export, never a value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exported_names: Option<ExportedNames>,
    /// Claude Code stores: other accounts on this machine with a login shell (Linux:
    /// `/etc/passwd` entries whose shell is not `nologin`/`false`/`sync`/`shutdown`/`halt`,
    /// the scanning user excluded). None when not determined (macOS, unreadable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other_login_accounts: Option<usize>,
}

/// The variable names a store's files export, read by name only: `export NAME=`,
/// `declare -x NAME=`, and in `session-env` files a line-start `NAME=` (the right-hand
/// side is never kept). Bounded: the first 64 KiB of at most 50 files other users can
/// read, sampled in path order.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct ExportedNames {
    /// Files read.
    pub sampled_files: usize,
    /// Files other users can read in the store (the population the sample is drawn from;
    /// at most the walk bound).
    pub readable_files: usize,
    /// Bytes read from the head of each file.
    pub bytes_per_file: usize,
    /// The distinct names, sorted (at most 100).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
    /// More than 100 distinct names were seen.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// A configured plugin marketplace — a remote source whose skills/plugins run as
/// agent code (EAA-009 remote hot-load surface). Records provenance and whether it
/// auto-updates; never fetches or executes anything.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AgentMarketplace {
    pub name: String,
    /// "git", "github", "local", etc.
    pub source_type: String,
    /// The remote reference: a git URL or an `owner/repo` slug.
    pub source_ref: String,
    /// True if the marketplace pulls new remote code automatically (no review gate).
    pub auto_update: bool,
    /// True if published by Anthropic (an official marketplace).
    pub official: bool,
    pub installed_plugin_count: usize,
    /// Plugin4Shell-shaped pins: commit-shaped refs in the clone, HEAD/FETCH_HEAD on such
    /// a branch, and manifest pins that are not commits. Sorted by (kind, path, plugin).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pin_issues: Vec<PluginPinIssue>,
}

/// One pin that is not a commit (see `scanners::marketplaces`).
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PluginPinIssue {
    /// head-on-sha-branch | sha-shaped-ref | fetch-head-sha-branch | manifest-ref-is-sha |
    /// manifest-sha-{not-commit,abbreviated,empty} | installed-sha-{not-commit,abbreviated,empty}
    pub kind: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,
    /// Fixed words plus hex prefixes or a sanitized manifest value; never a URL.
    pub detail: String,
    /// The commit-shaped name resolves to a different object than the one it names.
    #[serde(default)]
    pub mismatch: bool,
}

/// Git configuration whose value git executes as a command, found in a scope an
/// untrusted repository can control. Value-gated: ordinary settings like
/// `core.fsmonitor=true` or a git-lfs filter are deliberately NOT recorded.
#[derive(Debug, Serialize, Deserialize)]
pub struct GitAutorunConfig {
    /// The repository or git directory this was found in.
    pub path: String,
    /// The config file git attributed the setting to. Differs from `path/config` when
    /// an `include.path` was used to hide it.
    pub origin: String,
    pub key: String,
    /// The command git would run. Not a secret: these are program invocations.
    pub value: String,
    /// "repo-local" or "nested-repo".
    pub scope: String,
    /// True when found in a git directory BURIED inside the project rather than the
    /// project's own .git — the CVE-2026-45033 shape.
    pub nested: bool,
    /// Why the value was judged attack-shaped.
    pub reason: String,
}

/// A VS Code task that runs automatically when a folder is opened
/// (`runOptions.runOn == "folderOpen"`) — an auto-execution surface that travels with
/// a repository. Gated by `task.allowAutomaticTasks` and workspace trust, so it is
/// reported as a risk to review rather than as confirmed execution.
#[derive(Debug, Serialize, Deserialize)]
pub struct VsCodeTask {
    pub path: String,
    pub label: String,
    /// The command plus its args, as executed.
    pub command: String,
    /// A git-tracked auto-run task travels with the repo: clone, open, it runs.
    pub git_tracked: bool,
    /// True if the command matches a dangerous pattern (curl|bash, base64 decode, …).
    pub dangerous: bool,
    /// What the command references — see `agent_settings::classify_hook_command`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub risks: Vec<String>,
}

/// At-rest AI-service credential file (existence + permissions only; values never read).
#[derive(Debug, Serialize, Deserialize)]
pub struct AiCredential {
    pub provider: String,
    pub credential_type: String,
    pub path: String,
    /// Octal permission bits, e.g. "0600". None on non-Unix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<String>,
    pub world_readable: bool,
    pub group_readable: bool,
}

/// A `.env` file in an agent project root (agents read the working directory).
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct EnvFile {
    pub path: String,
    /// A git-tracked .env is a committed secret.
    pub git_tracked: bool,
    pub world_readable: bool,
    /// Count of `KEY=value` lines (names parsed, values never stored).
    pub key_count: usize,
    /// The file was opened and parsed (key_count is then the real count, possibly 0).
    /// False for a symlink (never opened) and for a file that could not be read; absent
    /// in reports from before this field existed, which reads as false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub read_ok: bool,
    /// Non-blank, non-comment lines that are not `KEY=value` (`spring.datasource.password=x`,
    /// `OPENAI_API_KEY: sk-...`). rmguard cannot tell what they hold, so a file with any is
    /// never graded clean. Absent when 0.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub unparsed_lines: usize,
    /// NAMES (never values) of keys that look secret-bearing (TOKEN/SECRET/KEY/...).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_keys: Vec<String>,
    /// Keys that relocate an agent's home or redirect its traffic. These values are not
    /// secrets, so the path or host is kept (sanitized); every other value is never read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_overrides: Vec<EnvAgentOverride>,
    /// The .env is a symbolic link: it is inventoried by its link text and never read
    /// (key_count, secret_keys and agent_overrides stay empty).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symlink: Option<EnvSymlink>,
}

/// A symlinked `.env` or project settings file, recorded without opening it.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct EnvSymlink {
    /// The link text, sanitized.
    pub target: String,
    /// The lexical target is a credential, key, shell-rc, agent-config or system path.
    #[serde(default)]
    pub sensitive_target: bool,
}

/// An agent-home or traffic override in a `.env` file.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct EnvAgentOverride {
    pub key: String,
    /// agent-home | gateway | headers | proxy | ollama-host
    pub kind: String,
    /// Path (agent-home) or host (gateway, proxy, ollama-host). None for headers, whose
    /// value is never read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default)]
    pub official: bool,
    #[serde(default)]
    pub loopback: bool,
    /// agent-home: the relocated home is inside the project.
    #[serde(default)]
    pub inside_project: bool,
    /// agent-home: the value could not be resolved to a path (an expansion other than a
    /// leading `~`/`$HOME`, such as `${PWD}/.claude-cfg` or `~user/x`), so whether it is
    /// inside the project is unknown. `inside_project` is false and means nothing then.
    #[serde(default)]
    pub unresolved: bool,
    /// agent-home: the resolved home is in a shared temporary location (/tmp, /var/tmp,
    /// /dev/shm) or under a world-writable directory, where another local user can
    /// create it first.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub shared_temp: bool,
    /// ollama-host only: the bind classification (see OllamaHostSetting).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<String>,
}

/// A persistence or planting artifact: a Python startup hook, a tool-shadowing binary in
/// a project root, a committed symlink that escapes its repository, a JavaScript loader
/// staged in an agent directory, or a known worm persistence path. See
/// `scanners::persistence`.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PersistenceArtifact {
    /// "python-startup-hook" | "planted-binary" | "escaping-symlink" | "loader-script" |
    /// "worm-ioc" | "url-handler" | "agent-bin" | "dangling-plugin-record"
    pub kind: String,
    pub path: String,
    /// The site-packages root, project root, or home the artifact was found under.
    pub scope: String,
    /// Shape detail: the `.pth` import line, the shadowed tool, the symlink target, or
    /// the campaign name. Sanitised; never a secret value.
    pub detail: String,
    pub git_tracked: bool,
    /// Startup hooks: true if an installed distribution's RECORD lists the file (or the
    /// manifests could not all be read, so "unclaimed" cannot be asserted).
    pub claimed: bool,
    /// The high-confidence variant of each kind: a published IOC file name, a symlink
    /// into a credential/agent-config path, a PATH that searches the working directory,
    /// or a known loader name.
    pub sensitive_target: bool,
    /// agent-bin only: what the file is, from its mode, owner and first four bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bin: Option<AgentBinInfo>,
}

/// An executable in the agent's own bin directory (`~/.claude/bin/`), outside any plugin
/// cache. Identity only: a 4-byte magic read and a SHA-256 of the file.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct AgentBinInfo {
    /// "elf" | "mach-o" | "script" | "other" (from the first four bytes).
    pub format: String,
    /// Permission bits, e.g. "0755".
    pub mode: String,
    /// Modification time, seconds since the epoch.
    pub mtime: i64,
    pub size: u64,
    /// Hex SHA-256 of the contents; None when the file could not be read or exceeds the
    /// hashing bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Owned by the user running the scan.
    pub owned_by_user: bool,
    /// Writable by group or other.
    pub world_writable: bool,
}

/// Exposure catalog entry for known-bad packages.
#[derive(Debug, Serialize, serde::Deserialize, Clone)]
pub struct ExposureEntry {
    pub ecosystem: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Semver range of affected versions, e.g. "< 2.0.0" or ">=1.0,<1.5". When set,
    /// matches any version satisfying the range (for "vulnerable below X" cases).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_range: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory: Option<String>,
}

/// A matched exposure finding.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ExposureFinding {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub advisory: String,
    pub found_in: String,
    /// Which kind of install root the package was found in (installed Python
    /// distributions only), so the report says whether to fix it with `uv tool
    /// upgrade`, `pipx upgrade`, a project lock file or the system package manager.
    /// Absent for every other source and in reports that predate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_kind: Option<PackageRootKind>,
    /// The uv tool, pipx venv or agent-private venv the package belongs to: the
    /// directory name, sanitized. Absent for system, user, project and uv-python roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_name: Option<String>,
    /// The catalog row's `version_range` when the match is a vulnerable version range
    /// (not a malware row that names an exact version or every version).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_range: Option<String>,
    /// "npx cache" when `found_in` is inside `~/.npm/_npx/<hash>/`: code npx fetched
    /// once, which runs again only when the same `npx` line is re-run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<String>,
    /// The package(s) the npx cache was created for (its `package.json` `_npx.packages`
    /// or `dependencies`), names only, sanitized.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cache_parent: Vec<String>,
}

/// The kind of Python install root a distribution was found in. A closed set: the
/// report, the terminal and the HTML show these labels verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageRootKind {
    /// An interpreter's site-packages under /usr/lib, /usr/local/lib, /opt/homebrew/lib.
    System,
    /// `~/.local/lib/python*/site-packages` (pip `--user`).
    User,
    /// A virtualenv in a registered project root or the working directory.
    Project,
    /// A `uv tool install` environment.
    UvTool,
    /// A `pipx install` environment.
    Pipx,
    /// A virtualenv inside an agent's own directory (`~/.claude`, `~/.codex`, ...).
    AgentVenv,
    /// A uv-managed interpreter's own site-packages.
    UvPython,
}

impl PackageRootKind {
    /// The label as serialized.
    pub fn label(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Project => "project",
            Self::UvTool => "uv-tool",
            Self::Pipx => "pipx",
            Self::AgentVenv => "agent-venv",
            Self::UvPython => "uv-python",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Summary {
    pub ai_agents_and_tools_count: usize,
    pub ai_frameworks_count: usize,
    pub ide_installations_count: usize,
    pub ide_extensions_count: usize,
    pub mcp_configs_count: usize,
    pub mcp_servers_count: usize,
    /// Of `mcp_servers_count`, servers shipped by Claude Code plugins.
    #[serde(default)]
    pub mcp_plugin_servers_count: usize,
    /// Of `mcp_servers_count`, claude.ai connectors Claude Code lists as ever connected.
    #[serde(default)]
    pub mcp_connectors_count: usize,
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
    pub transcript_stores_count: usize,
    pub marketplaces_count: usize,
    pub vscode_autorun_tasks_count: usize,
    pub git_autorun_configs_count: usize,
    /// Installed Python distributions examined for catalog matches.
    #[serde(default)]
    pub python_packages_count: usize,
    #[serde(default)]
    pub npm_packages_count: usize,
    #[serde(default)]
    pub jetbrains_plugins_count: usize,
    #[serde(default)]
    pub persistence_artifacts_count: usize,
    /// Hooks per framework (settings, plugin and frontmatter hooks; helpers not counted).
    #[serde(default)]
    pub agent_hooks_by_framework: std::collections::BTreeMap<String, usize>,
    /// Of `agent_hooks_count`, the hooks nothing runs: marked off by their source
    /// (Kiro `enabled: false`, `disableAllHooks`) or shipped by a disabled plugin or a
    /// synced skill copy. They are inventoried, never graded.
    #[serde(default)]
    pub agent_hooks_inactive_count: usize,
    /// Of `agent_hooks_count`, the settings commands Claude Code runs that are not hooks
    /// (`statusLine`, `subagentStatusLine`, `fileSuggestion`; code.claude.com/docs/en/statusline):
    /// inventoried and graded with the hooks, counted apart.
    #[serde(default)]
    pub agent_settings_commands_count: usize,
    /// LSP servers declared by installed Claude Code plugins (`agent_lsp_servers`).
    #[serde(default)]
    pub agent_lsp_servers_count: usize,
}

impl Summary {
    /// Every count in the summary, as (`rmguard.inventory.kind`, count): the field name
    /// without `_count`. A closed set of `&'static str` kinds, in field order, each
    /// number the summary's own; `agent_hooks_by_framework` (keyed by framework names)
    /// is the one summary field not here. `summary_inventory_tests::inventory_is_every_summary_count`
    /// fails when a `_count` field is added without a row.
    pub fn inventory(&self) -> [(&'static str, usize); 35] {
        [
            ("ai_agents_and_tools", self.ai_agents_and_tools_count),
            ("ai_frameworks", self.ai_frameworks_count),
            ("ide_installations", self.ide_installations_count),
            ("ide_extensions", self.ide_extensions_count),
            ("mcp_configs", self.mcp_configs_count),
            ("mcp_servers", self.mcp_servers_count),
            ("mcp_plugin_servers", self.mcp_plugin_servers_count),
            ("mcp_connectors", self.mcp_connectors_count),
            ("node_package_managers", self.node_package_managers_count),
            ("shell_configs", self.shell_configs_count),
            ("ssh_keys", self.ssh_keys_count),
            ("cloud_credentials", self.cloud_credentials_count),
            ("container_tools", self.container_tools_count),
            ("notebook_servers", self.notebook_servers_count),
            ("browser_extensions", self.browser_extensions_count),
            ("package_config_audits", self.package_config_audits_count),
            ("rules_files", self.rules_files_count),
            ("agent_skills", self.agent_skills_count),
            ("agent_settings", self.agent_settings_count),
            ("agent_hooks", self.agent_hooks_count),
            ("ai_credentials", self.ai_credentials_count),
            ("env_files", self.env_files_count),
            ("rules_file_findings", self.rules_file_findings_count),
            ("exposure_findings", self.exposure_findings_count),
            ("transcript_stores", self.transcript_stores_count),
            ("marketplaces", self.marketplaces_count),
            ("vscode_autorun_tasks", self.vscode_autorun_tasks_count),
            ("git_autorun_configs", self.git_autorun_configs_count),
            ("python_packages", self.python_packages_count),
            ("npm_packages", self.npm_packages_count),
            ("jetbrains_plugins", self.jetbrains_plugins_count),
            ("persistence_artifacts", self.persistence_artifacts_count),
            ("agent_hooks_inactive", self.agent_hooks_inactive_count),
            ("agent_settings_commands", self.agent_settings_commands_count),
            ("agent_lsp_servers", self.agent_lsp_servers_count),
        ]
    }
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
            mcp_plugin_servers_count: self.mcp_servers_from(MCP_SOURCE_PLUGIN),
            mcp_connectors_count: self.mcp_servers_from(MCP_SOURCE_CONNECTOR),
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
            agent_hooks_count: self.agent_settings.iter().map(|s| s.hooks.len()).sum::<usize>()
                + self.agent_skills.iter().map(|k| k.hooks.len()).sum::<usize>(),
            ai_credentials_count: self.ai_credentials.len(),
            env_files_count: self.env_files.len(),
            rules_file_findings_count: self.rules_files.iter().map(|r| r.findings.len()).sum(),
            exposure_findings_count: self.exposure_findings.len(),
            transcript_stores_count: self.transcripts.len(),
            marketplaces_count: self.marketplaces.len(),
            vscode_autorun_tasks_count: self.vscode_tasks.len(),
            git_autorun_configs_count: self.git_autorun_configs.len(),
            python_packages_count: self.summary.python_packages_count,
            npm_packages_count: self.summary.npm_packages_count,
            jetbrains_plugins_count: self.summary.jetbrains_plugins_count,
            persistence_artifacts_count: self.persistence_artifacts.len(),
            agent_hooks_by_framework: self.hooks_by_framework(),
            agent_hooks_inactive_count: self.inactive_hooks(),
            agent_settings_commands_count: self
                .agent_settings
                .iter()
                .flat_map(|s| &s.hooks)
                .filter(|h| h.kind == crate::scanners::hook_sources::SETTINGS_COMMAND_KIND)
                .count(),
            agent_lsp_servers_count: self.surfaces.agent_lsp_servers.len(),
        };
    }

    /// Servers of the configs whose `config_source` is `source`.
    fn mcp_servers_from(&self, source: &str) -> usize {
        self.mcp_configs
            .iter()
            .filter(|c| c.config_source == source)
            .map(|c| c.server_count)
            .sum()
    }

    /// Hooks that never run (see [`Summary::agent_hooks_inactive_count`]).
    fn inactive_hooks(&self) -> usize {
        let off = |p: Option<&SkillProvenance>| p.is_some_and(|p| !p.active || p.synced);
        self.agent_settings
            .iter()
            .map(|s| {
                if off(s.provenance.as_ref()) {
                    s.hooks.len()
                } else {
                    s.hooks.iter().filter(|h| h.disabled).count()
                }
            })
            .sum::<usize>()
            + self
                .agent_skills
                .iter()
                .map(|k| {
                    if off(k.provenance.as_ref()) {
                        k.hooks.len()
                    } else {
                        k.hooks.iter().filter(|h| h.disabled).count()
                    }
                })
                .sum::<usize>()
    }

    /// Hook counts keyed by framework. Skill frameworks (`claude-code`,
    /// `claude-code-agent`, ...) all count as `claude-code`.
    fn hooks_by_framework(&self) -> std::collections::BTreeMap<String, usize> {
        let mut m = std::collections::BTreeMap::new();
        for s in &self.agent_settings {
            if !s.hooks.is_empty() {
                *m.entry(s.framework.clone()).or_insert(0) += s.hooks.len();
            }
        }
        for k in &self.agent_skills {
            if !k.hooks.is_empty() {
                let fw = if k.framework.starts_with("claude-code") {
                    "claude-code".to_string()
                } else {
                    k.framework.clone()
                };
                *m.entry(fw).or_insert(0) += k.hooks.len();
            }
        }
        m
    }
}

/// One scanner's run. See [`ScanReport::diagnostics`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScannerStat {
    /// The `--skip` label of the scanner, e.g. "mcp", "packages".
    pub scanner: String,
    /// Home root the scanner ran against, for home-rooted scanners under --search-dirs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    pub duration_ms: u64,
    /// Files successfully opened through the shared bounded readers. Scanners that only
    /// probe binaries on PATH or list directories legitimately read zero files.
    pub files_read: u64,
    /// Paths the scanner tried to read that did not exist or were rejected. A scanner
    /// with files_missing > 0 and files_read == 0 LOOKED and found nothing there.
    pub files_missing: u64,
    /// Items the scanner returned.
    pub items: usize,
    /// Excluded via --skip; the other counters are zero.
    pub skipped: bool,
    /// The scanner stopped at a walk budget (`telemetry::mark_truncated`): its results
    /// may be incomplete. Absent from the JSON when false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// A user-installed JetBrains IDE plugin. Identity only; the descriptor fields are
/// attacker-authored and sanitized at capture.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JetBrainsPlugin {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    pub ide: String,
    pub location: String,
}

/// serde `skip_serializing_if` for a count that is absent when 0.
fn is_zero(n: &usize) -> bool {
    *n == 0
}

#[cfg(test)]
mod summary_inventory_tests {
    use super::Summary;

    /// Every `*_count` key the JSON summary has is an inventory kind with the same value.
    /// Each field gets a distinct number, so a row reading the wrong field is caught too.
    #[test]
    fn inventory_is_every_summary_count() {
        let mut v = serde_json::to_value(Summary::default()).unwrap();
        let obj = v.as_object_mut().unwrap();
        let keys: Vec<String> = obj.keys().filter(|k| k.ends_with("_count")).cloned().collect();
        for (i, k) in keys.iter().enumerate() {
            obj.insert(k.clone(), serde_json::json!(i + 1));
        }
        let s: Summary = serde_json::from_value(v.clone()).unwrap();
        let inv = s.inventory();
        assert_eq!(inv.len(), keys.len(), "summary counts vs inventory rows");
        for (kind, n) in inv {
            let key = format!("{kind}_count");
            assert_eq!(v[&key].as_u64(), Some(n as u64), "{kind}");
            assert!(
                kind.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{kind} is not a snake_case label"
            );
        }
    }
}

// ── Round-3b coverage surfaces ─────────────────────────────────────────────────────────
// New report sections, kept together at the end of the file: plugin LSP servers, plugin
// and npx-cache liveness, agent-driven browser profiles and output directories, Mistral
// Vibe settings and settings-command scripts. `ScanReport::surfaces` flattens them into
// the report's top level. Graded in `crate::analysis_surfaces`.

/// The round-3b report sections, flattened into [`ScanReport`]'s top-level JSON keys.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SurfaceInventory {
    /// LSP servers Claude Code plugins declare (see `scanners::plugin_lsp`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_lsp_servers: Vec<AgentLspServer>,
    /// Plugin cache versions that live Claude Code sessions mark as loaded
    /// (`scanners::liveness`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plugin_versions_in_use: Vec<PluginVersionInUse>,
    /// npx caches a running process executes from (`scanners::liveness`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub npx_caches_running: Vec<NpxCacheRunning>,
    /// Persistent browser profiles kept by an agent-driven browser (`scanners::playwright_mcp`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_browser_profiles: Vec<AgentBrowserProfiles>,
    /// Agent tool output directories inside projects (`scanners::playwright_mcp`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_output_dirs: Vec<AgentOutputDir>,
    /// Mistral Vibe configuration (`scanners::vibe`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vibe_configs: Vec<VibeConfig>,
    /// Scripts the user's settings commands (`statusLine`, ...) run (`scanners::settings_scripts`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub settings_command_scripts: Vec<SettingsCommandScript>,
    /// TCP sockets in LISTEN state owned by the scanning user (`scanners::listeners`,
    /// Linux `/proc` only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_listeners: Vec<NetworkListener>,
}

/// One LSP server a Claude Code plugin declares (`.lsp.json`, `plugin.json` `lspServers`, or
/// the marketplace entry of a plugin with no `plugin.json`;
/// code.claude.com/docs/en/plugins-reference#lsp-servers). Claude Code starts it as a
/// process, like a stdio MCP server.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct AgentLspServer {
    /// `plugin@marketplace`, sanitized.
    pub plugin: String,
    /// The server name (the config map key), sanitized.
    pub name: String,
    /// The file the declaration came from: `<root>/.lsp.json`, `<root>/.claude-plugin/plugin.json`,
    /// a manifest-named `.json`, or the marketplace's `marketplace.json`.
    pub source: String,
    /// The program's basename (`rust-analyzer`, `npx`), or `${CLAUDE_PLUGIN_ROOT}/...` for a
    /// program the plugin bundles. Sanitized.
    pub program: String,
    /// The arguments by SHAPE: flags kept (`--stdio`, `--log=<value>`), every other
    /// argument as `<arg>`; the launched package is in `package`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// The package a package-runner launch fetches (`npx`, `uvx`, ...), when one is named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    /// Why the launch runs whatever version is current (`scanners::mcp::unpinned_reason`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unpinned: Option<String>,
    /// The `env` block by shape (`NAME=${REF}` / `NAME=<redacted>`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// File extensions the server is registered for (`extensionToLanguage` keys), sanitized.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<String>,
    /// The plugin is enabled (`enabledPlugins`); a disabled plugin's servers are inventory.
    pub enabled: bool,
}

/// A plugin cache version (`~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/`) that
/// running Claude Code sessions mark as loaded: `.in_use/<pid>` entries whose process exists.
/// An observed, undocumented signal (Claude Code's docs describe only `.orphaned_at`,
/// code.claude.com/docs/en/plugins/loading); entry NAMES only.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PluginVersionInUse {
    /// `plugin@marketplace`, sanitized.
    pub plugin: String,
    /// The cache directory name (a version or a commit prefix), sanitized.
    pub version: String,
    pub path: String,
    /// Live processes among the `.in_use` entries (Linux `/proc/<pid>`, owned by this user).
    pub in_use_by_sessions: usize,
    /// Their pids, sorted (which sessions to restart).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pids: Vec<u32>,
    /// The version `installed_plugins.json` records, when it is not this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_version: Option<String>,
    /// Not the installed version: its hooks and MCP servers are the old version's.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stale_version: bool,
    /// A stale version's hooks (`hooks/hooks.json` and manifest hooks): inventory only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hooks: Vec<AgentHook>,
    /// A stale version's MCP servers (`.mcp.json` and manifest `mcpServers`): inventory only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mcp_servers: Vec<McpServerDetail>,
}

/// An npx cache (`~/.npm/_npx/<hash>/`) that a running process executes from: some argument
/// of its command line is a path inside the cache. Linux only (`/proc/<pid>/cmdline`, this
/// user's processes); the command line is matched and dropped, never stored.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct NpxCacheRunning {
    pub path: String,
    /// Processes running from it.
    pub pids: usize,
}

/// The persistent browser profiles one agent-driven browser keeps
/// (`~/.cache/ms-playwright-mcp/mcp-<channel>-<hash>/`): their cookie and saved-login stores
/// by existence, mode, size and modification time only. Nothing in a profile is opened.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct AgentBrowserProfiles {
    /// "playwright-mcp".
    pub framework: String,
    /// The directory holding the profiles.
    pub path: String,
    pub profile_count: usize,
    /// Profiles holding a `Cookies` or `Login Data` file.
    pub login_profiles: usize,
    /// Cookie and login-data files found (each counted once).
    pub login_files: usize,
    /// Of `login_files`, those other users can read: o+r on the file and o+x on every
    /// directory from `path` down to it.
    pub readable_login_files: usize,
    /// Newest modification time of a login file (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub newest_login_mtime: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// An ancestor other users cannot traverse (`"/home/u is 0700"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreachable_via: Option<String>,
}

/// An agent tool's output directory inside a project (Playwright MCP's `.playwright-mcp/`:
/// page snapshots, console logs, screenshots).
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct AgentOutputDir {
    /// "playwright-mcp".
    pub framework: String,
    pub path: String,
    pub file_count: usize,
    /// Files git tracks (the scan's once-per-repository listing).
    pub tracked_files: usize,
    /// The project is a git work tree.
    pub in_repo: bool,
    /// An untracked file of the directory is ignored by git (`git check-ignore`, hardened);
    /// None when not asked or unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ignored: Option<bool>,
}

/// `~/.vibe/config.toml` and its neighbours (Mistral Vibe; github.com/mistralai/mistral-vibe,
/// docs.mistral.ai/vibe). Values that are not secrets are kept; `.env` by mode only.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct VibeConfig {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_approve: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_auto_update: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_update_checks: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_telemetry: Option<bool>,
    /// Inventoried, not graded (current docs name it; its effect is not confirmed here).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bypass_tool_permissions: Option<bool>,
    /// `tools.<name>.permission` ("always" | "ask" | "never"), by tool name, sanitized.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub tool_permissions: std::collections::BTreeMap<String, String>,
    /// `[[mcp_servers]]` entries (rows of `mcp_configs`).
    pub mcp_server_count: usize,
    /// Hot-load lists, lexical (not walked).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skill_paths: Vec<String>,
    /// `trusted_folders.toml` `trusted` / `untrusted`, sanitized.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_folders: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub untrusted_folders: Vec<String>,
    /// `session_logging.save_dir` (default `~/.vibe/logs/session`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_dir: Option<String>,
    /// `~/.vibe/.env` (API keys): mode only, never opened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_file: Option<VibeEnvFile>,
}

/// `~/.vibe/.env` by mode only.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct VibeEnvFile {
    pub path: String,
    pub mode: String,
    pub world_readable: bool,
    pub group_readable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreachable_via: Option<String>,
}

/// A script under the agent's own directory that a user settings command runs
/// (`statusLine: ~/.claude/statusline.sh`): identity only, as for `~/.claude/bin`.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct SettingsCommandScript {
    /// "statusLine" | "subagentStatusLine" | "fileSuggestion".
    pub setting: String,
    pub settings_path: String,
    pub path: String,
    pub bin: AgentBinInfo,
}

// ── Network listeners (`scanners::listeners`) ──────────────────────────────────────────

/// Where a listening socket accepts connections from. A closed set.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum BindClass {
    /// 127.0.0.0/8, `::1`, or an IPv4-mapped loopback address: this machine only.
    #[default]
    Loopback,
    /// `0.0.0.0` (or `::ffff:0.0.0.0`): every IPv4 interface.
    AllInterfaces,
    /// One non-loopback address (a LAN, VPN or link-local address).
    SpecificAddress,
    /// `::`: every IPv6 interface, and every IPv4 one too unless the socket is v6-only.
    Ipv6Any,
}

impl BindClass {
    pub fn label(self) -> &'static str {
        match self {
            BindClass::Loopback => "loopback",
            BindClass::AllInterfaces => "all-interfaces",
            BindClass::SpecificAddress => "specific-address",
            BindClass::Ipv6Any => "ipv6-any",
        }
    }

    /// Reachable from another machine (anything but loopback).
    pub fn is_network_reachable(self) -> bool {
        self != BindClass::Loopback
    }
}

/// Why rmguard thinks a listener hands out a shell or a terminal. A closed set, checked
/// in this order; the first that holds is recorded.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum ServesShell {
    /// A child process is tmux or screen.
    TmuxChild,
    /// The process holds a PTY master (`/dev/ptmx`): it allocates terminals.
    PtyChild,
    /// A child process is a shell (bash, zsh, sh, fish, dash).
    ShellChild,
    /// The program is a known web-terminal bridge (ttyd, gotty, ...).
    KnownBridgeName,
    #[default]
    None,
}

impl ServesShell {
    pub fn label(self) -> &'static str {
        match self {
            ServesShell::TmuxChild => "tmux-child",
            ServesShell::PtyChild => "pty-child",
            ServesShell::ShellChild => "shell-child",
            ServesShell::KnownBridgeName => "known-bridge-name",
            ServesShell::None => "none",
        }
    }
}

/// One TCP socket in LISTEN state that the scanning user owns, from `/proc/net/tcp{,6}`,
/// mapped to its process through `/proc/<pid>/fd` (the user's own processes only). The
/// process is identified by `comm` and the `exe` link; its command line and environment
/// are never read.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct NetworkListener {
    pub bind: BindClass,
    /// The bound address as text (`0.0.0.0`, `127.0.0.1`, `::`, `192.168.1.5`).
    pub address: String,
    pub port: u16,
    /// The lowest pid holding the socket; None when no process of the user's holds it
    /// (another pid namespace, or the fd walk stopped at its cap).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// `/proc/<pid>/comm` (at most 15 bytes, set by the program), sanitized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    /// The `/proc/<pid>/exe` link, sanitized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// The `/proc/<pid>/cwd` link, sanitized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Whole days since the process started (`/proc/<pid>/stat` starttime and `btime`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_days: Option<u64>,
    /// The scanned project the working directory is in (the most specific one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    pub serves_shell: ServesShell,
    /// What showed it (`child 'tmux: client'`, `holds /dev/ptmx`, `program terminal-bridge`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell_signal: Option<String>,
    /// World-readable `.env` files with secret-named keys in the working directory or its
    /// project, counted from this report's `env_files` rows after the scan
    /// (`analysis_surfaces::correlate_listeners`); the files are not read again.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub readable_secret_files: usize,
}
