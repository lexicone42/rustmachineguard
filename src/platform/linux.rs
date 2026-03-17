use super::{Ide, PlatformInfo};
use crate::models::DeviceInfo;
use std::path::PathBuf;
use std::process::Command;

pub struct LinuxPlatform {
    home: PathBuf,
}

impl LinuxPlatform {
    pub fn new() -> Self {
        Self {
            home: dirs::home_dir().expect("cannot determine home directory — set $HOME"),
        }
    }

    fn read_os_release_field(field: &str) -> Option<String> {
        let content = std::fs::read_to_string("/etc/os-release").ok()?;
        for line in content.lines() {
            if let Some(val) = line.strip_prefix(&format!("{field}=")) {
                return Some(val.trim_matches(|c| c == '"' || c == '\'').to_string());
            }
        }
        None
    }
}

impl PlatformInfo for LinuxPlatform {
    fn device_info(&self) -> DeviceInfo {
        let hostname = hostname();
        let os_name = Self::read_os_release_field("PRETTY_NAME")
            .or_else(|| Self::read_os_release_field("NAME"))
            .unwrap_or_else(|| "Linux".to_string());
        let os_version = Self::read_os_release_field("VERSION_ID").unwrap_or_default();
        let kernel_version = Command::new("uname")
            .arg("-r")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let user_identity =
            std::env::var("USER").unwrap_or_else(|_| whoami::username());

        DeviceInfo {
            hostname,
            os_name: os_name.clone(),
            os_version,
            platform: "linux".to_string(),
            kernel_version,
            user_identity,
            home_dir: self.home.display().to_string(),
        }
    }

    fn home_dir(&self) -> PathBuf {
        self.home.clone()
    }

    fn ide_install_path(&self, ide: Ide) -> Option<PathBuf> {
        // On Linux, IDEs are typically binaries on PATH or in known locations
        let bin_name = match ide {
            Ide::VsCode => "code",
            Ide::Cursor => "cursor",
            Ide::Windsurf => "windsurf",
            Ide::Zed => "zed",
            Ide::Antigravity => "antigravity",
        };
        which::which(bin_name).ok()
    }

    fn ide_extension_dir(&self, ide: Ide) -> Option<PathBuf> {
        let dir = match ide {
            Ide::VsCode => self.home.join(".vscode/extensions"),
            Ide::Cursor => self.home.join(".cursor/extensions"),
            Ide::Windsurf => self.home.join(".windsurf/extensions"),
            Ide::Zed => self.home.join(".config/zed/extensions/installed"),
            Ide::Antigravity => self.home.join(".antigravity/extensions"),
        };
        if dir.is_dir() {
            Some(dir)
        } else {
            None
        }
    }

    fn mcp_config_paths(&self) -> Vec<(String, PathBuf, String)> {
        vec![
            (
                "Claude Desktop".to_string(),
                self.home.join(".config/Claude/claude_desktop_config.json"),
                "Anthropic".to_string(),
            ),
            (
                "Claude Code".to_string(),
                self.home.join(".claude/settings.json"),
                "Anthropic".to_string(),
            ),
            (
                "Cursor".to_string(),
                self.home.join(".cursor/mcp.json"),
                "Anysphere".to_string(),
            ),
            (
                "Windsurf".to_string(),
                self.home.join(".codeium/windsurf/mcp_config.json"),
                "Codeium".to_string(),
            ),
            (
                "Zed".to_string(),
                self.home.join(".config/zed/settings.json"),
                "Zed Industries".to_string(),
            ),
            (
                "VS Code".to_string(),
                self.home.join(".config/Code/User/settings.json"),
                "Microsoft".to_string(),
            ),
        ]
    }

    fn ai_desktop_app_paths(&self) -> Vec<(String, String, PathBuf)> {
        // On Linux, desktop apps are found via .desktop files or PATH
        vec![
            (
                "Claude Desktop".to_string(),
                "Anthropic".to_string(),
                PathBuf::from("/usr/bin/claude-desktop"),
            ),
            (
                "GitHub Copilot".to_string(),
                "GitHub".to_string(),
                PathBuf::from("/usr/bin/github-copilot"),
            ),
        ]
    }

    fn claude_config_dir(&self) -> PathBuf {
        self.home.join(".claude")
    }

    fn gemini_config_dir(&self) -> PathBuf {
        self.home.join(".gemini")
    }

    fn aws_q_config_dir(&self) -> PathBuf {
        self.home.join(".aws/q")
    }

    fn shell_config_paths(&self) -> Vec<(String, PathBuf)> {
        vec![
            ("bash".to_string(), self.home.join(".bashrc")),
            ("bash_profile".to_string(), self.home.join(".bash_profile")),
            ("zsh".to_string(), self.home.join(".zshrc")),
            ("fish".to_string(), self.home.join(".config/fish/config.fish")),
            ("profile".to_string(), self.home.join(".profile")),
        ]
    }

    fn ssh_dir(&self) -> PathBuf {
        self.home.join(".ssh")
    }

    fn aws_credentials_path(&self) -> PathBuf {
        self.home.join(".aws/credentials")
    }

    fn gcloud_config_dir(&self) -> PathBuf {
        self.home.join(".config/gcloud")
    }

    fn azure_config_dir(&self) -> PathBuf {
        self.home.join(".azure")
    }
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| {
            Command::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        })
}
