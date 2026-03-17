use crate::models::{AiTool, AiToolType};
use crate::platform::PlatformInfo;
use crate::scanners::{get_binary_version, is_process_running, Scanner};

pub struct AiToolsScanner;

struct ToolDef {
    name: &'static str,
    vendor: &'static str,
    tool_type: AiToolType,
    binary_names: &'static [&'static str],
    process_name: Option<&'static str>,
    /// Check for config dir existence as a signal (even if binary not found)
    config_dir_check: Option<fn(&dyn PlatformInfo) -> std::path::PathBuf>,
}

const TOOLS: &[ToolDef] = &[
    ToolDef {
        name: "Claude Code",
        vendor: "Anthropic",
        tool_type: AiToolType::CliTool,
        binary_names: &["claude"],
        process_name: Some("claude"),
        config_dir_check: Some(|p| p.claude_config_dir()),
    },
    ToolDef {
        name: "GitHub Copilot CLI",
        vendor: "GitHub",
        tool_type: AiToolType::CliTool,
        binary_names: &["github-copilot-cli", "ghcs"],
        process_name: None,
        config_dir_check: None,
    },
    ToolDef {
        name: "OpenAI Codex CLI",
        vendor: "OpenAI",
        tool_type: AiToolType::CliTool,
        binary_names: &["codex"],
        process_name: None,
        config_dir_check: None,
    },
    ToolDef {
        name: "Gemini CLI",
        vendor: "Google",
        tool_type: AiToolType::CliTool,
        binary_names: &["gemini"],
        process_name: None,
        config_dir_check: Some(|p| p.gemini_config_dir()),
    },
    ToolDef {
        name: "Amazon Q CLI",
        vendor: "Amazon",
        tool_type: AiToolType::CliTool,
        binary_names: &["amazon-q"],
        process_name: None,
        config_dir_check: Some(|p| p.aws_q_config_dir()),
    },
    ToolDef {
        name: "Aider",
        vendor: "Aider",
        tool_type: AiToolType::CliTool,
        binary_names: &["aider"],
        process_name: None,
        config_dir_check: None,
    },
    ToolDef {
        name: "Continue",
        vendor: "Continue",
        tool_type: AiToolType::CliTool,
        binary_names: &["continue"],
        process_name: None,
        config_dir_check: None,
    },
    ToolDef {
        name: "Cody CLI",
        vendor: "Sourcegraph",
        tool_type: AiToolType::CliTool,
        binary_names: &["cody"],
        process_name: None,
        config_dir_check: None,
    },
    // Agents from the original script
    ToolDef {
        name: "OpenClaw",
        vendor: "OpenClaw",
        tool_type: AiToolType::Agent,
        binary_names: &["openclaw"],
        process_name: None,
        config_dir_check: None,
    },
    ToolDef {
        name: "GPT Engineer",
        vendor: "GPT Engineer",
        tool_type: AiToolType::Agent,
        binary_names: &["gpt-engineer", "gpte"],
        process_name: None,
        config_dir_check: None,
    },
    // New detections beyond upstream
    ToolDef {
        name: "Open Interpreter",
        vendor: "Open Interpreter",
        tool_type: AiToolType::Agent,
        binary_names: &["interpreter"],
        process_name: None,
        config_dir_check: None,
    },
    ToolDef {
        name: "Goose",
        vendor: "Block",
        tool_type: AiToolType::Agent,
        binary_names: &["goose"],
        process_name: None,
        config_dir_check: None,
    },
    ToolDef {
        name: "Tabby",
        vendor: "TabbyML",
        tool_type: AiToolType::CliTool,
        binary_names: &["tabby"],
        process_name: Some("tabby"),
        config_dir_check: None,
    },
];

impl Scanner for AiToolsScanner {
    type Output = Vec<AiTool>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<AiTool> {
        let mut results = Vec::new();

        // Check CLI tools via PATH
        for def in TOOLS {
            let mut found_binary: Option<std::path::PathBuf> = None;

            for bin_name in def.binary_names {
                if let Ok(path) = which::which(bin_name) {
                    found_binary = Some(path);
                    break;
                }
            }

            let has_config = def
                .config_dir_check
                .map(|f| f(platform).is_dir())
                .unwrap_or(false);

            if found_binary.is_some() || has_config {
                let version = found_binary
                    .as_ref()
                    .and_then(|p| get_binary_version(p.to_str().unwrap_or("")));

                let is_running = def
                    .process_name
                    .map(is_process_running)
                    .unwrap_or(false);

                let config_dir = def
                    .config_dir_check
                    .map(|f| f(platform))
                    .filter(|p| p.is_dir())
                    .map(|p| p.display().to_string());

                results.push(AiTool {
                    name: def.name.to_string(),
                    vendor: def.vendor.to_string(),
                    tool_type: match def.tool_type {
                        AiToolType::CliTool => AiToolType::CliTool,
                        AiToolType::DesktopApp => AiToolType::DesktopApp,
                        AiToolType::Agent => AiToolType::Agent,
                    },
                    version,
                    binary_path: found_binary.map(|p| p.display().to_string()),
                    config_dir,
                    install_path: None,
                    is_running,
                });
            }
        }

        // Check desktop apps from platform-specific paths
        for (name, vendor, path) in platform.ai_desktop_app_paths() {
            if path.exists() {
                let is_running = is_process_running(
                    path.file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or(""),
                );
                results.push(AiTool {
                    name,
                    vendor,
                    tool_type: AiToolType::DesktopApp,
                    version: None,
                    binary_path: None,
                    config_dir: None,
                    install_path: Some(path.display().to_string()),
                    is_running,
                });
            }
        }

        results
    }
}
