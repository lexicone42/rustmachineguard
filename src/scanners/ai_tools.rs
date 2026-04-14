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
        vendor: "Microsoft",
        tool_type: AiToolType::CliTool,
        // Upstream naming: `copilot` (new) and `gh-copilot` (gh extension)
        binary_names: &["copilot", "gh-copilot", "github-copilot-cli", "ghcs"],
        process_name: None,
        config_dir_check: Some(|p| p.github_copilot_config_dir()),
    },
    ToolDef {
        name: "OpenAI Codex CLI",
        vendor: "OpenAI",
        tool_type: AiToolType::CliTool,
        binary_names: &["codex"],
        process_name: None,
        config_dir_check: Some(|p| p.codex_config_dir()),
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
        name: "Kiro",
        vendor: "Amazon",
        tool_type: AiToolType::CliTool,
        binary_names: &["kiro-cli", "kiro"],
        process_name: None,
        config_dir_check: Some(|p| p.kiro_config_dir()),
    },
    ToolDef {
        name: "Microsoft AI Shell",
        vendor: "Microsoft",
        tool_type: AiToolType::CliTool,
        binary_names: &["aish"],
        process_name: None,
        config_dir_check: Some(|p| p.aish_config_dir()),
    },
    ToolDef {
        name: "OpenCode",
        vendor: "OpenCode",
        tool_type: AiToolType::CliTool,
        binary_names: &["opencode"],
        process_name: None,
        config_dir_check: Some(|p| p.opencode_config_dir()),
    },
    ToolDef {
        name: "Aider",
        vendor: "Aider",
        tool_type: AiToolType::CliTool,
        binary_names: &["aider"],
        process_name: None,
        config_dir_check: Some(|p| p.aider_config_dir()),
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
    // AI agents
    ToolDef {
        name: "OpenClaw",
        vendor: "OpenClaw",
        tool_type: AiToolType::Agent,
        binary_names: &["openclaw"],
        process_name: None,
        config_dir_check: None,
    },
    ToolDef {
        name: "ClawdBot",
        vendor: "OpenSource",
        tool_type: AiToolType::Agent,
        binary_names: &["clawdbot"],
        process_name: None,
        config_dir_check: None,
    },
    ToolDef {
        name: "MoltBot",
        vendor: "OpenSource",
        tool_type: AiToolType::Agent,
        binary_names: &["moltbot"],
        process_name: None,
        config_dir_check: None,
    },
    ToolDef {
        name: "MoldBot",
        vendor: "OpenSource",
        tool_type: AiToolType::Agent,
        binary_names: &["moldbot"],
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
    // Detections beyond upstream
    ToolDef {
        name: "Open Interpreter",
        vendor: "Open Interpreter",
        tool_type: AiToolType::Agent,
        binary_names: &["interpreter"],
        process_name: None,
        config_dir_check: Some(|p| p.open_interpreter_config_dir()),
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

        // Known fallback binary paths (absolute paths to check if `which` fails).
        // Format: (tool_name, [candidate paths relative to home])
        let home = platform.home_dir();
        let fallback_paths: &[(&str, &[std::path::PathBuf])] = &[
            (
                "Claude Code",
                &[
                    home.join(".claude/local/claude"),
                    home.join(".local/bin/claude"),
                ],
            ),
            (
                "OpenCode",
                &[home.join(".opencode/bin/opencode")],
            ),
        ];

        // Check CLI tools via PATH, with fallback to known install locations.
        for def in TOOLS {
            let mut found_binary: Option<std::path::PathBuf> = None;

            for bin_name in def.binary_names {
                if let Ok(path) = which::which(bin_name) {
                    found_binary = Some(path);
                    break;
                }
            }

            // Fallback: check known absolute paths
            if found_binary.is_none() {
                for (name, paths) in fallback_paths {
                    if *name == def.name {
                        for p in *paths {
                            if p.is_file() {
                                found_binary = Some(p.clone());
                                break;
                            }
                        }
                    }
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

        // Claude Cowork: a feature inside Claude Desktop v0.7+.
        // Detected by presence of Claude.app/claude-desktop binary AND version >= 0.7.
        if let Some(app_path) = platform.claude_desktop_app() {
            if let Some(version) = read_claude_desktop_version(&app_path) {
                if version_gte(&version, (0, 7)) {
                    results.push(AiTool {
                        name: "Claude Cowork".to_string(),
                        vendor: "Anthropic".to_string(),
                        tool_type: AiToolType::Agent,
                        version: Some(version),
                        binary_path: None,
                        config_dir: None,
                        install_path: Some(app_path.display().to_string()),
                        is_running: false,
                    });
                }
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

/// Try to read the Claude Desktop version from the app bundle (macOS) or binary (Linux).
fn read_claude_desktop_version(app_path: &std::path::Path) -> Option<String> {
    // macOS: read Info.plist
    #[cfg(target_os = "macos")]
    {
        let plist = app_path.join("Contents/Info.plist");
        if plist.is_file() {
            if let Ok(output) = std::process::Command::new("defaults")
                .args(["read", plist.to_str().unwrap_or(""), "CFBundleShortVersionString"])
                .output()
            {
                let v = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    // Linux: run binary with --version
    #[cfg(target_os = "linux")]
    {
        if app_path.is_file() {
            return crate::scanners::get_binary_version(app_path.to_str().unwrap_or(""));
        }
    }
    let _ = app_path;
    None
}

/// Compare a version string against a (major, minor) tuple. Returns true if version >= target.
pub fn version_gte(version: &str, target: (u32, u32)) -> bool {
    let parts: Vec<u32> = version
        .trim_start_matches('v')
        .split('.')
        .take(2)
        .map(|p| {
            p.chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse::<u32>()
                .unwrap_or(0)
        })
        .collect();
    if parts.is_empty() {
        return false;
    }
    let major = parts[0];
    let minor = parts.get(1).copied().unwrap_or(0);
    (major, minor) >= target
}
