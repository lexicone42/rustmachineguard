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
    pub summary: Summary,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
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
#[derive(Debug, Serialize, Deserialize)]
pub struct RulesFile {
    pub path: String,
    pub file_name: String,
    pub sha256: String,
    pub git_tracked: bool,
    pub size_bytes: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<RulesFileFinding>,
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
    /// runs from HOME) | "local" | "project" | "managed"
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

/// A hook that runs a command on an agent lifecycle event.
#[derive(Debug, Serialize, Deserialize, Clone)]
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
}

/// An agent transcript / conversation-state store (EAA-005 collection surface).
/// Records existence, size, and permissions only — content is never read.
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentTranscriptStore {
    pub framework: String,
    pub path: String,
    /// e.g. "conversation transcripts", "command history", "sessions".
    pub kind: String,
    pub file_count: usize,
    pub total_size_bytes: u64,
    pub world_readable: bool,
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
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PersistenceArtifact {
    /// "python-startup-hook" | "planted-binary" | "escaping-symlink" | "loader-script" | "worm-ioc"
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
#[derive(Debug, Serialize, Deserialize)]
pub struct ExposureFinding {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub advisory: String,
    pub found_in: String,
}

#[derive(Debug, Serialize, Deserialize)]
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
            transcript_stores_count: self.transcripts.len(),
            marketplaces_count: self.marketplaces.len(),
            vscode_autorun_tasks_count: self.vscode_tasks.len(),
            git_autorun_configs_count: self.git_autorun_configs.len(),
            python_packages_count: self.summary.python_packages_count,
            npm_packages_count: self.summary.npm_packages_count,
            jetbrains_plugins_count: self.summary.jetbrains_plugins_count,
            persistence_artifacts_count: self.persistence_artifacts.len(),
        };
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
