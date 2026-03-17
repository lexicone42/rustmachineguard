use crate::models::IdeExtension;
use crate::platform::{Ide, PlatformInfo};
use crate::scanners::Scanner;

pub struct ExtensionsScanner;

impl Scanner for ExtensionsScanner {
    type Output = Vec<IdeExtension>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<IdeExtension> {
        let mut results = Vec::new();

        for &ide in Ide::ALL {
            if ide == Ide::Zed {
                // Zed has a different extension format
                if let Some(ext_dir) = platform.ide_extension_dir(ide) {
                    results.extend(scan_zed_extensions(&ext_dir, ide));
                }
                continue;
            }

            if let Some(ext_dir) = platform.ide_extension_dir(ide) {
                results.extend(scan_vscode_style_extensions(&ext_dir, ide));
            }
        }

        results
    }
}

/// Scan VS Code-style extensions (publisher.name-version directory format).
fn scan_vscode_style_extensions(
    ext_dir: &std::path::Path,
    ide: Ide,
) -> Vec<IdeExtension> {
    let mut results = Vec::new();

    let Ok(entries) = std::fs::read_dir(ext_dir) else {
        return results;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        // Skip obsolete extensions
        if path.join(".obsolete").exists() {
            continue;
        }

        let dir_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        // Format: publisher.name-version
        if let Some((id, version)) = parse_extension_dir_name(dir_name) {
            let (publisher, name) = match id.split_once('.') {
                Some((p, n)) => (p.to_string(), n.to_string()),
                None => ("unknown".to_string(), id.clone()),
            };

            results.push(IdeExtension {
                id: id.clone(),
                name,
                version,
                publisher,
                ide_type: ide.name().to_string(),
            });
        }
    }

    results
}

/// Parse "publisher.name-1.2.3" into ("publisher.name", "1.2.3").
pub fn parse_extension_dir_name(name: &str) -> Option<(String, String)> {
    // Find the last hyphen followed by a digit (start of version)
    let mut split_pos = None;
    for (i, _) in name.match_indices('-') {
        if name[i + 1..].starts_with(|c: char| c.is_ascii_digit()) {
            split_pos = Some(i);
        }
    }

    let pos = split_pos?;
    let id = &name[..pos];
    let version = &name[pos + 1..];
    Some((id.to_string(), version.to_string()))
}

/// Scan Zed extensions (different structure).
fn scan_zed_extensions(
    ext_dir: &std::path::Path,
    ide: Ide,
) -> Vec<IdeExtension> {
    let mut results = Vec::new();

    let Ok(entries) = std::fs::read_dir(ext_dir) else {
        return results;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        // Try to read extension.json for version info
        let version = std::fs::read_to_string(path.join("extension.json"))
            .ok()
            .and_then(|content| {
                serde_json::from_str::<serde_json::Value>(&content).ok()
            })
            .and_then(|v| v["version"].as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "unknown".to_string());

        results.push(IdeExtension {
            id: name.clone(),
            name: name.clone(),
            version,
            publisher: "zed-extensions".to_string(),
            ide_type: ide.name().to_string(),
        });
    }

    results
}
