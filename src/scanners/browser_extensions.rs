use crate::models::BrowserExtension;
use crate::platform::PlatformInfo;
use crate::scanners::Scanner;
use std::path::PathBuf;

pub struct BrowserExtensionsScanner;

impl Scanner for BrowserExtensionsScanner {
    type Output = Vec<BrowserExtension>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<BrowserExtension> {
        let mut results = Vec::new();
        let home = platform.home_dir();

        for (browser, profiles_dir) in chromium_profile_dirs(&home) {
            if !profiles_dir.is_dir() {
                continue;
            }
            scan_chromium_profiles(&profiles_dir, &browser, &mut results);
        }

        let firefox_dir = home.join(".mozilla/firefox");
        if firefox_dir.is_dir() {
            scan_firefox_profiles(&firefox_dir, &mut results);
        }

        #[cfg(target_os = "macos")]
        {
            let ff_mac = home.join("Library/Application Support/Firefox/Profiles");
            if ff_mac.is_dir() {
                scan_firefox_profiles(&ff_mac, &mut results);
            }
        }

        results
    }
}

fn chromium_profile_dirs(home: &PathBuf) -> Vec<(String, PathBuf)> {
    #[allow(unused_mut)]
    let mut dirs = vec![
        ("Chrome".to_string(), home.join(".config/google-chrome")),
        ("Chromium".to_string(), home.join(".config/chromium")),
        ("Edge".to_string(), home.join(".config/microsoft-edge")),
        ("Brave".to_string(), home.join(".config/BraveSoftware/Brave-Browser")),
        ("Vivaldi".to_string(), home.join(".config/vivaldi")),
    ];

    #[cfg(target_os = "macos")]
    {
        dirs.push(("Chrome".to_string(), home.join("Library/Application Support/Google/Chrome")));
        dirs.push(("Edge".to_string(), home.join("Library/Application Support/Microsoft Edge")));
        dirs.push(("Brave".to_string(), home.join("Library/Application Support/BraveSoftware/Brave-Browser")));
        dirs.push(("Vivaldi".to_string(), home.join("Library/Application Support/Vivaldi")));
    }

    dirs
}

fn scan_chromium_profiles(base: &PathBuf, browser: &str, results: &mut Vec<BrowserExtension>) {
    let profile_dirs: Vec<PathBuf> = std::fs::read_dir(base)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            (name == "Default" || name.starts_with("Profile ")) && e.path().is_dir()
        })
        .map(|e| e.path())
        .collect();

    for profile_dir in profile_dirs {
        let profile_name = profile_dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Default".to_string());

        let extensions_dir = profile_dir.join("Extensions");
        if !extensions_dir.is_dir() {
            continue;
        }

        let Ok(ext_entries) = std::fs::read_dir(&extensions_dir) else {
            continue;
        };

        for ext_entry in ext_entries.flatten() {
            let ext_id = ext_entry.file_name().to_string_lossy().to_string();
            if !ext_entry.path().is_dir() {
                continue;
            }

            // Each extension ID dir contains version dirs; pick the latest
            let version_dirs: Vec<_> = std::fs::read_dir(ext_entry.path())
                .into_iter()
                .flatten()
                .flatten()
                .filter(|e| e.path().is_dir())
                .collect();

            let Some(latest) = version_dirs.into_iter().max_by_key(|e| {
                e.file_name().to_string_lossy().to_string()
            }) else {
                continue;
            };

            let manifest_path = latest.path().join("manifest.json");
            if !manifest_path.is_file() {
                continue;
            }

            let content = match crate::scanners::read_bounded(&manifest_path) {
                Some(c) => c,
                None => continue,
            };

            let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&content) else {
                continue;
            };

            let name = manifest
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(&ext_id)
                .to_string();
            let version = manifest
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let description = manifest
                .get("description")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            // Skip Chrome built-in extensions
            if name.starts_with("__MSG_") || ext_id == "nmmhkkegccagdldgiimedpiccmgmieda" {
                continue;
            }

            results.push(BrowserExtension {
                browser: browser.to_string(),
                name,
                id: ext_id,
                version,
                description,
                profile: profile_name.clone(),
            });
        }
    }
}

fn scan_firefox_profiles(profiles_dir: &PathBuf, results: &mut Vec<BrowserExtension>) {
    let Ok(entries) = std::fs::read_dir(profiles_dir) else {
        return;
    };

    for entry in entries.flatten() {
        if !entry.path().is_dir() {
            continue;
        }

        let profile_name = entry.file_name().to_string_lossy().to_string();
        let extensions_json = entry.path().join("extensions.json");

        if !extensions_json.is_file() {
            continue;
        }

        let content = match crate::scanners::read_bounded(&extensions_json) {
            Some(c) => c,
            None => continue,
        };

        let Ok(data) = serde_json::from_str::<serde_json::Value>(&content) else {
            continue;
        };

        let Some(addons) = data.get("addons").and_then(|v| v.as_array()) else {
            continue;
        };

        for addon in addons {
            let addon_type = addon.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if addon_type != "extension" {
                continue;
            }

            let id = addon
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let name = addon
                .get("defaultLocale")
                .and_then(|v| v.get("name"))
                .and_then(|v| v.as_str())
                .or_else(|| addon.get("name").and_then(|v| v.as_str()))
                .unwrap_or(&id)
                .to_string();
            let version = addon
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let description = addon
                .get("defaultLocale")
                .and_then(|v| v.get("description"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            // Skip built-in/system extensions
            if id.ends_with("@mozilla.org") || id.ends_with("@shield.mozilla.org") {
                continue;
            }

            results.push(BrowserExtension {
                browser: "Firefox".to_string(),
                name,
                id,
                version,
                description,
                profile: profile_name.clone(),
            });
        }
    }
}
