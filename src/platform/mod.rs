#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "linux")]
mod linux;

use crate::models::DeviceInfo;
use std::path::PathBuf;

/// IDE identifiers used across the platform layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ide {
    VsCode,
    Cursor,
    Windsurf,
    Zed,
    Antigravity,
}

impl Ide {
    pub const ALL: &[Ide] = &[
        Ide::VsCode,
        Ide::Cursor,
        Ide::Windsurf,
        Ide::Zed,
        Ide::Antigravity,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Ide::VsCode => "Visual Studio Code",
            Ide::Cursor => "Cursor",
            Ide::Windsurf => "Windsurf",
            Ide::Zed => "Zed",
            Ide::Antigravity => "Antigravity",
        }
    }

    pub fn vendor(self) -> &'static str {
        match self {
            Ide::VsCode => "Microsoft",
            Ide::Cursor => "Anysphere",
            Ide::Windsurf => "Codeium",
            Ide::Zed => "Zed Industries",
            Ide::Antigravity => "Antigravity",
        }
    }
}

/// Platform-specific path and device info resolution.
#[allow(dead_code)]
pub trait PlatformInfo {
    fn device_info(&self) -> DeviceInfo;
    fn home_dir(&self) -> PathBuf;

    // IDE install locations
    fn ide_install_path(&self, ide: Ide) -> Option<PathBuf>;
    fn ide_extension_dir(&self, ide: Ide) -> Option<PathBuf>;

    // MCP config paths for each vendor
    fn mcp_config_paths(&self) -> Vec<(String, PathBuf, String)>;

    // AI desktop app paths
    fn ai_desktop_app_paths(&self) -> Vec<(String, String, PathBuf)>;

    // AI CLI config directories
    fn claude_config_dir(&self) -> PathBuf;
    fn gemini_config_dir(&self) -> PathBuf;
    fn aws_q_config_dir(&self) -> PathBuf;

    // Shell config files
    fn shell_config_paths(&self) -> Vec<(String, PathBuf)>;

    // SSH directory
    fn ssh_dir(&self) -> PathBuf;

    // Cloud credential paths
    fn aws_credentials_path(&self) -> PathBuf;
    fn gcloud_config_dir(&self) -> PathBuf;
    fn azure_config_dir(&self) -> PathBuf;
}

/// Get the platform implementation for the current OS.
pub fn current_platform() -> Box<dyn PlatformInfo> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsPlatform::new())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxPlatform::new())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        compile_error!("Only macOS and Linux are supported");
    }
}
