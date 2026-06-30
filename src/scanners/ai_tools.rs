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
    config_dir_check: Option<fn(&dyn PlatformInfo) -> std::path::PathBuf>,
    verify_binary: bool,
}

const TOOLS: &[ToolDef] = &[
    ToolDef {
        name: "Claude Code",
        vendor: "Anthropic",
        tool_type: AiToolType::CliTool,
        binary_names: &["claude"],
        process_name: Some("claude"),
        config_dir_check: Some(|p| p.claude_config_dir()),
        verify_binary: false,
    },
    ToolDef {
        name: "GitHub Copilot CLI",
        vendor: "Microsoft",
        tool_type: AiToolType::CliTool,
        binary_names: &["copilot", "gh-copilot", "github-copilot-cli", "ghcs"],
        process_name: None,
        config_dir_check: Some(|p| p.github_copilot_config_dir()),
        verify_binary: true,
    },
    ToolDef {
        name: "OpenAI Codex CLI",
        vendor: "OpenAI",
        tool_type: AiToolType::CliTool,
        binary_names: &["codex"],
        process_name: None,
        config_dir_check: Some(|p| p.codex_config_dir()),
        verify_binary: false,
    },
    ToolDef {
        name: "Gemini CLI",
        vendor: "Google",
        tool_type: AiToolType::CliTool,
        binary_names: &["gemini"],
        process_name: None,
        config_dir_check: Some(|p| p.gemini_config_dir()),
        verify_binary: false,
    },
    ToolDef {
        name: "Amazon Q CLI",
        vendor: "Amazon",
        tool_type: AiToolType::CliTool,
        binary_names: &["amazon-q"],
        process_name: None,
        config_dir_check: Some(|p| p.aws_q_config_dir()),
        verify_binary: false,
    },
    ToolDef {
        name: "Cursor Agent",
        vendor: "Anysphere",
        tool_type: AiToolType::Agent,
        binary_names: &["cursor-agent"],
        process_name: None,
        config_dir_check: None,
        verify_binary: false,
    },
    ToolDef {
        name: "Kiro",
        vendor: "Amazon",
        tool_type: AiToolType::CliTool,
        binary_names: &["kiro-cli", "kiro"],
        process_name: None,
        config_dir_check: Some(|p| p.kiro_config_dir()),
        verify_binary: false,
    },
    ToolDef {
        name: "Microsoft AI Shell",
        vendor: "Microsoft",
        tool_type: AiToolType::CliTool,
        binary_names: &["aish"],
        process_name: None,
        config_dir_check: Some(|p| p.aish_config_dir()),
        verify_binary: false,
    },
    ToolDef {
        name: "OpenCode",
        vendor: "OpenCode",
        tool_type: AiToolType::CliTool,
        binary_names: &["opencode"],
        process_name: None,
        config_dir_check: Some(|p| p.opencode_config_dir()),
        verify_binary: false,
    },
    ToolDef {
        name: "Aider",
        vendor: "Aider",
        tool_type: AiToolType::CliTool,
        binary_names: &["aider"],
        process_name: None,
        config_dir_check: Some(|p| p.aider_config_dir()),
        verify_binary: false,
    },
    ToolDef {
        name: "Continue",
        vendor: "Continue",
        tool_type: AiToolType::CliTool,
        binary_names: &["continue"],
        process_name: None,
        config_dir_check: None,
        verify_binary: false,
    },
    ToolDef {
        name: "Cody CLI",
        vendor: "Sourcegraph",
        tool_type: AiToolType::CliTool,
        binary_names: &["cody"],
        process_name: None,
        config_dir_check: None,
        verify_binary: false,
    },
    ToolDef {
        name: "OpenClaw",
        vendor: "OpenClaw",
        tool_type: AiToolType::Agent,
        binary_names: &["openclaw"],
        process_name: None,
        config_dir_check: None,
        verify_binary: false,
    },
    ToolDef {
        name: "ClawdBot",
        vendor: "OpenSource",
        tool_type: AiToolType::Agent,
        binary_names: &["clawdbot"],
        process_name: None,
        config_dir_check: None,
        verify_binary: false,
    },
    ToolDef {
        name: "MoltBot",
        vendor: "OpenSource",
        tool_type: AiToolType::Agent,
        binary_names: &["moltbot"],
        process_name: None,
        config_dir_check: None,
        verify_binary: false,
    },
    ToolDef {
        name: "MoldBot",
        vendor: "OpenSource",
        tool_type: AiToolType::Agent,
        binary_names: &["moldbot"],
        process_name: None,
        config_dir_check: None,
        verify_binary: false,
    },
    ToolDef {
        name: "GPT Engineer",
        vendor: "GPT Engineer",
        tool_type: AiToolType::Agent,
        binary_names: &["gpt-engineer", "gpte"],
        process_name: None,
        config_dir_check: None,
        verify_binary: false,
    },
    ToolDef {
        name: "Open Interpreter",
        vendor: "Open Interpreter",
        tool_type: AiToolType::Agent,
        binary_names: &["interpreter"],
        process_name: None,
        config_dir_check: Some(|p| p.open_interpreter_config_dir()),
        verify_binary: false,
    },
    ToolDef {
        name: "Goose",
        vendor: "Block",
        tool_type: AiToolType::Agent,
        binary_names: &["goose"],
        process_name: None,
        config_dir_check: None,
        verify_binary: false,
    },
    ToolDef {
        name: "Tabby",
        vendor: "TabbyML",
        tool_type: AiToolType::CliTool,
        binary_names: &["tabby"],
        process_name: Some("tabby"),
        config_dir_check: None,
        verify_binary: false,
    },
];

/// Verify a binary is real (not a shim that says "not installed").
fn verify_binary_works(path: &std::path::Path) -> bool {
    let output = std::process::Command::new(path)
        .arg("--version")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();
    match output {
        Ok(o) => {
            if !o.status.success() {
                return false;
            }
            let text = String::from_utf8_lossy(&o.stdout).to_lowercase()
                + &String::from_utf8_lossy(&o.stderr).to_lowercase();
            !text.contains("not installed") && !text.contains("command not found")
        }
        Err(_) => false,
    }
}

impl Scanner for AiToolsScanner {
    type Output = Vec<AiTool>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<AiTool> {
        let mut results = Vec::new();

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

        for def in TOOLS {
            let mut found_binary: Option<std::path::PathBuf> = None;

            for bin_name in def.binary_names {
                if let Ok(path) = which::which(bin_name) {
                    found_binary = Some(path);
                    break;
                }
            }

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

            // Reject shims that aren't actually installed
            if def.verify_binary {
                if let Some(ref path) = found_binary {
                    if !verify_binary_works(path) {
                        found_binary = None;
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

fn read_claude_desktop_version(app_path: &std::path::Path) -> Option<String> {
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
    #[cfg(target_os = "linux")]
    {
        if app_path.is_file() {
            return crate::scanners::get_binary_version(app_path.to_str().unwrap_or(""));
        }
    }
    let _ = app_path;
    None
}

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
