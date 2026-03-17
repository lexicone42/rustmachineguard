use crate::models::IdeInstallation;
use crate::platform::{Ide, PlatformInfo};
use crate::scanners::{get_binary_version, Scanner};

pub struct IdeScanner;

impl Scanner for IdeScanner {
    type Output = Vec<IdeInstallation>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<IdeInstallation> {
        let mut results = Vec::new();

        for &ide in Ide::ALL {
            if let Some(install_path) = platform.ide_install_path(ide) {
                let version = get_ide_version(ide, &install_path);
                results.push(IdeInstallation {
                    ide_type: ide.name().to_string(),
                    version,
                    install_path: install_path.display().to_string(),
                    vendor: ide.vendor().to_string(),
                    is_installed: true,
                });
            }
        }

        results
    }
}

fn get_ide_version(ide: Ide, install_path: &std::path::Path) -> Option<String> {
    // On macOS, try reading version from Info.plist
    #[cfg(target_os = "macos")]
    {
        let plist = install_path.join("Contents/Info.plist");
        if plist.exists() {
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

    // On Linux, try running the binary with --version
    let bin_name = match ide {
        Ide::VsCode => "code",
        Ide::Cursor => "cursor",
        Ide::Windsurf => "windsurf",
        Ide::Zed => "zed",
        Ide::Antigravity => "antigravity",
    };

    // If install_path is a binary (Linux), use it directly
    if install_path.is_file() {
        return get_binary_version(install_path.to_str().unwrap_or(bin_name));
    }

    get_binary_version(bin_name)
}
