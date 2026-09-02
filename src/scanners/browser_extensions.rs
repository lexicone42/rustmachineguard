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
            if !crate::scanners::probe_dir(&profiles_dir) {
                continue;
            }
            scan_chromium_profiles(&profiles_dir, &browser, &mut results);
        }

        let firefox_dir = home.join(".mozilla/firefox");
        if crate::scanners::probe_dir(&firefox_dir) {
            scan_firefox_profiles(&firefox_dir, &mut results);
        }

        #[cfg(target_os = "macos")]
        {
            let ff_mac = home.join("Library/Application Support/Firefox/Profiles");
            if crate::scanners::probe_dir(&ff_mac) {
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
            (name == "Default" || name.starts_with("Profile ")) && crate::scanners::probe_dir(&e.path())
        })
        .map(|e| e.path())
        .collect();

    for profile_dir in profile_dirs {
        let profile_name = profile_dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Default".to_string());

        let extensions_dir = profile_dir.join("Extensions");
        if !crate::scanners::probe_dir(&extensions_dir) {
            continue;
        }

        let Ok(ext_entries) = std::fs::read_dir(&extensions_dir) else {
            continue;
        };

        for ext_entry in ext_entries.flatten() {
            let ext_id = ext_entry.file_name().to_string_lossy().to_string();
            if !crate::scanners::probe_dir(&ext_entry.path()) {
                continue;
            }

            // Each extension ID dir contains version dirs; pick the latest
            let version_dirs: Vec<_> = std::fs::read_dir(ext_entry.path())
                .into_iter()
                .flatten()
                .flatten()
                .filter(|e| crate::scanners::probe_dir(&e.path()))
                .collect();

            // Chrome names version dirs `<version>_<n>` and may hold two across an
            // update. Compare numerically: as strings, "24.10.4_0" sorts above
            // "24.10.10_0", which mis-reported the live version and broke range rows.
            let Some(latest) = version_dirs.into_iter().max_by_key(|e| {
                version_dir_key(&e.file_name().to_string_lossy())
            }) else {
                continue;
            };

            let manifest_path = latest.path().join("manifest.json");
            if !crate::scanners::probe_file(&manifest_path) {
                continue;
            }

            let content = match crate::scanners::read_bounded(&manifest_path) {
                Some(c) => c,
                None => continue,
            };

            let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&content) else {
                continue;
            };

            // A localized manifest has "name": "__MSG_appName__". That is not a built-in
            // marker -- most store extensions localize -- and skipping on it dropped every
            // such extension from the inventory, so no catalog row could ever match it.
            // Resolve the key from _locales/, and fall back to the ID rather than drop.
            let raw_name = manifest.get("name").and_then(|v| v.as_str()).unwrap_or(&ext_id);
            // Name, version and description are attacker-authored (the manifest and the
            // locale file are the extension's own). Sanitize and validate them here so
            // no control character or forged "clean" line can reach the terminal.
            let name = resolve_i18n_name(raw_name, &latest.path(), &manifest).unwrap_or_else(|| {
                if raw_name.starts_with("__MSG_") { ext_id.clone() } else { raw_name.to_string() }
            });
            let name = crate::scanners::sanitize_display(&name, 128);
            let version = manifest
                .get("version")
                .and_then(|v| v.as_str())
                .filter(|v| crate::scanners::npm_packages::is_valid_version(v))
                .unwrap_or("unknown")
                .to_string();
            let description = manifest
                .get("description")
                .and_then(|v| v.as_str())
                .map(|s| crate::scanners::sanitize_display(s, 256));

            // Skip Chrome's own built-in component extension (Chrome Web Store), by ID.
            if ext_id == "nmmhkkegccagdldgiimedpiccmgmieda" {
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
        if !crate::scanners::probe_dir(&entry.path()) {
            continue;
        }

        let profile_name = entry.file_name().to_string_lossy().to_string();
        let extensions_json = entry.path().join("extensions.json");

        if !crate::scanners::probe_file(&extensions_json) {
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

/// Numeric sort key for a Chrome extension version directory (`24.10.4_0`).
fn version_dir_key(dir_name: &str) -> (Vec<u64>, u64) {
    let (version, counter) = dir_name.split_once('_').unwrap_or((dir_name, "0"));
    // The `_N` install counter breaks ties between two dirs of the same version: `_1`
    // is the reinstall, `_0` the stale copy. Without it max_by_key fell back to
    // read_dir order, which is filesystem-dependent.
    (
        version.split('.').map(|part| part.parse::<u64>().unwrap_or(0)).collect(),
        counter.parse::<u64>().unwrap_or(0),
    )
}

/// Resolve a `__MSG_key__` manifest name via `_locales/<default_locale>/messages.json`.
fn resolve_i18n_name(raw: &str, ext_dir: &std::path::Path, manifest: &serde_json::Value) -> Option<String> {
    let key = raw.strip_prefix("__MSG_")?.strip_suffix("__")?;
    let mut locales: Vec<String> = Vec::new();
    // `default_locale` is attacker-controlled and is joined into a path: only a Chrome
    // locale code may pass, never `..` or an absolute path.
    if let Some(d) = manifest.get("default_locale").and_then(|v| v.as_str())
        && is_locale_code(d)
    {
        locales.push(d.to_string());
    }
    for fallback in ["en", "en_US", "en_GB"] {
        if !locales.iter().any(|l| l == fallback) {
            locales.push(fallback.to_string());
        }
    }
    for locale in locales {
        let path = ext_dir.join("_locales").join(&locale).join("messages.json");
        let Some(text) = crate::scanners::read_bounded(&path) else {
            continue;
        };
        let Ok(messages) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        // Keys are case-insensitive in Chrome's i18n.
        let found = messages.as_object().and_then(|m| {
            m.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .and_then(|(_, v)| v.get("message").and_then(|s| s.as_str()))
        });
        if let Some(name) = found.map(str::trim).filter(|n| !n.is_empty()) {
            return Some(name.to_string());
        }
    }
    None
}

/// `en`, `pt_BR`, `zh_CN`, `es_419`: letters, optionally `_` and 2-8 alphanumerics.
fn is_locale_code(s: &str) -> bool {
    let (lang, region) = s.split_once('_').unwrap_or((s, ""));
    (2..=3).contains(&lang.len())
        && lang.chars().all(|c| c.is_ascii_alphabetic())
        && (region.is_empty()
            || ((2..=8).contains(&region.len()) && region.chars().all(|c| c.is_ascii_alphanumeric())))
}
