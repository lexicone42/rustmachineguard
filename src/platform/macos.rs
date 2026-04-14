use super::{Ide, PlatformInfo};
use crate::models::DeviceInfo;
use std::path::PathBuf;
use std::process::Command;

pub struct MacOsPlatform {
    home: PathBuf,
}

impl MacOsPlatform {
    pub fn new() -> Self {
        Self {
            home: dirs::home_dir().expect("cannot determine home directory — set $HOME"),
        }
    }

    /// Create a macOS platform rooted at a specific home directory (for --search-dirs).
    pub fn with_home(home: PathBuf) -> Self {
        Self { home }
    }
}

impl PlatformInfo for MacOsPlatform {
    fn device_info(&self) -> DeviceInfo {
        let hostname = Command::new("hostname")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let os_version = Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        let kernel_version = Command::new("uname")
            .arg("-r")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        let user_identity =
            std::env::var("USER").unwrap_or_else(|_| {
                whoami::username().unwrap_or_else(|_| "unknown".to_string())
            });

        DeviceInfo {
            hostname,
            os_name: "macOS".to_string(),
            os_version,
            platform: "macos".to_string(),
            kernel_version,
            user_identity,
            home_dir: self.home.display().to_string(),
        }
    }

    fn home_dir(&self) -> PathBuf {
        self.home.clone()
    }

    fn ide_install_path(&self, ide: Ide) -> Option<PathBuf> {
        let app_path = match ide {
            Ide::VsCode => "/Applications/Visual Studio Code.app",
            Ide::Cursor => "/Applications/Cursor.app",
            Ide::Windsurf => "/Applications/Windsurf.app",
            Ide::Zed => "/Applications/Zed.app",
            Ide::Antigravity => "/Applications/Antigravity.app",
        };
        let p = PathBuf::from(app_path);
        if p.exists() {
            Some(p)
        } else {
            None
        }
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
                self.home.join("Library/Application Support/Claude/claude_desktop_config.json"),
                "Anthropic".to_string(),
            ),
            (
                "Claude Code".to_string(),
                self.home.join(".claude/settings.json"),
                "Anthropic".to_string(),
            ),
            (
                "Claude Code (home)".to_string(),
                self.home.join(".claude.json"),
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
                "Antigravity".to_string(),
                self.home.join(".gemini/antigravity/mcp_config.json"),
                "Google".to_string(),
            ),
            (
                "Zed".to_string(),
                self.home.join(".config/zed/settings.json"),
                "Zed Industries".to_string(),
            ),
            (
                "VS Code".to_string(),
                self.home.join("Library/Application Support/Code/User/settings.json"),
                "Microsoft".to_string(),
            ),
            (
                "Open Interpreter".to_string(),
                self.home.join(".config/open-interpreter/config.yaml"),
                "Open Interpreter".to_string(),
            ),
            (
                "Codex".to_string(),
                self.home.join(".codex/config.toml"),
                "OpenAI".to_string(),
            ),
        ]
    }

    fn ai_desktop_app_paths(&self) -> Vec<(String, String, PathBuf)> {
        vec![
            (
                "Claude Desktop".to_string(),
                "Anthropic".to_string(),
                PathBuf::from("/Applications/Claude.app"),
            ),
            (
                "GitHub Copilot".to_string(),
                "GitHub".to_string(),
                PathBuf::from("/Applications/GitHub Copilot.app"),
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

    fn codex_config_dir(&self) -> PathBuf {
        self.home.join(".codex")
    }

    fn kiro_config_dir(&self) -> PathBuf {
        self.home.join(".kiro")
    }

    fn aish_config_dir(&self) -> PathBuf {
        self.home.join(".aish")
    }

    fn opencode_config_dir(&self) -> PathBuf {
        self.home.join(".config/opencode")
    }

    fn github_copilot_config_dir(&self) -> PathBuf {
        self.home.join(".config/github-copilot")
    }

    fn aider_config_dir(&self) -> PathBuf {
        self.home.join(".aider")
    }

    fn open_interpreter_config_dir(&self) -> PathBuf {
        self.home.join(".config/open-interpreter")
    }

    fn claude_desktop_app(&self) -> Option<PathBuf> {
        let p = PathBuf::from("/Applications/Claude.app");
        if p.exists() { Some(p) } else { None }
    }

    fn shell_config_paths(&self) -> Vec<(String, PathBuf)> {
        vec![
            ("bash".to_string(), self.home.join(".bashrc")),
            ("bash_profile".to_string(), self.home.join(".bash_profile")),
            ("zsh".to_string(), self.home.join(".zshrc")),
            ("zprofile".to_string(), self.home.join(".zprofile")),
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
