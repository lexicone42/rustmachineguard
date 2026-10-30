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
fn scan_vscode_style_extensions(ext_dir: &std::path::Path, ide: Ide) -> Vec<IdeExtension> {
    let mut results = Vec::new();

    let Ok(entries) = crate::scanners::probe_read_dir(ext_dir) else {
        return results;
    };
    // VS Code keeps ONE `.obsolete` file at the extensions root (not one per extension):
    // a JSON object keyed by `ExtensionKey.toString()` of each superseded or uninstalled
    // version whose directory has not been deleted yet. Its rows stay in the inventory,
    // marked, because a leftover directory still proves the code was installed and ran.
    let obsolete = read_obsolete_keys(ext_dir);

    for entry in entries.flatten() {
        let path = entry.path();
        if !crate::scanners::probe_dir(&path) {
            continue;
        }

        let dir_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        // Format: publisher.name-version[-targetPlatform]
        if let Some((id, dir_version, target_platform)) = parse_extension_dir_name_platform(dir_name) {
            let (publisher, name) = match id.split_once('.') {
                Some((p, n)) => (p.to_string(), n.to_string()),
                None => ("unknown".to_string(), id.clone()),
            };

            let manifest = read_manifest_claims(&path);
            // The manifest's version when it is well-formed (VS Code names the directory
            // from it: `ExtensionKey.create` takes `manifest.version`), else the one in
            // the directory name with its platform suffix removed.
            let version = manifest.version.clone().unwrap_or(dir_version);
            let is_obsolete = obsolete.contains(&dir_name.to_ascii_lowercase());
            let native_addons = if manifest.declarative_claim {
                find_native_addons(&path)
            } else {
                Vec::new()
            };
            // The directory name is attacker-chosen text that reaches the terminal.
            let clean = |s: &str| crate::scanners::sanitize_display(s, 200);
            results.push(IdeExtension {
                id: clean(&id),
                name: clean(&name),
                version: clean(&version),
                publisher: clean(&publisher),
                ide_type: ide.name().to_string(),
                categories: manifest.categories,
                code_entry_points: manifest.code_entry_points,
                contributes_theme: manifest.contributes_theme,
                contributes_commands: manifest.contributes_commands,
                declarative_claim: manifest.declarative_claim,
                native_addons,
                path: crate::scanners::sanitize_display(&path.display().to_string(), 512),
                target_platform: target_platform.map(str::to_string),
                obsolete: is_obsolete,
            });
        }
    }

    results
}

// GlassWorm-linked theme loaders (Socket Threat Research, Kirill Boychenko) and the
// GlassWorm Zig dropper's native addon (Aikido Security, Ilyas Makari).

/// Marketplace categories that describe an extension with no reason to run code.
const DECLARATIVE_CATEGORIES: &[&str] = &["themes", "snippets", "keymaps", "language packs"];
/// `contributes` keys that are pure data (JSON grammars, colour tables, snippets).
const DECLARATIVE_CONTRIBUTES: &[&str] = &[
    "themes",
    "iconThemes",
    "productIconThemes",
    "snippets",
    "keybindings",
    "grammars",
    "languages",
    "localizations",
];
const MAX_ADDON_WALK: usize = 20_000;

/// What an extension's package.json claims about itself.
#[derive(Debug, Default, PartialEq)]
pub struct ManifestClaims {
    pub categories: Vec<String>,
    pub code_entry_points: Vec<String>,
    pub contributes_theme: bool,
    pub contributes_commands: bool,
    pub declarative_claim: bool,
    /// `version`, when it is a well-formed `X.Y.Z` version (an optional `-pre`/`+build`
    /// tail), at most 64 bytes.
    pub version: Option<String>,
}

/// The extension's package.json, read only when it is a regular file (not a symlink) whose
/// real path stays inside the extension directory. The directory itself may be a link (a
/// development install); a manifest linked elsewhere, such as into ~/.ssh, is not read.
fn read_manifest_claims(dir: &std::path::Path) -> ManifestClaims {
    let manifest = dir.join("package.json");
    if !std::fs::symlink_metadata(&manifest).is_ok_and(|m| m.is_file()) {
        crate::scanners::telemetry::note_read(&manifest, "refused (symlink or not a regular file)");
        return ManifestClaims::default();
    }
    let (Ok(real), Ok(real_dir)) = (std::fs::canonicalize(&manifest), std::fs::canonicalize(dir)) else {
        return ManifestClaims::default();
    };
    if !real.starts_with(&real_dir) {
        return ManifestClaims::default();
    }
    crate::scanners::read_bounded_nofollow(&manifest, Some(&real))
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .map(|v| manifest_claims(&v))
        .unwrap_or_default()
}

/// Classify a VS Code `package.json`. `declarative_claim` is true when every category
/// is a declarative one (Themes, Snippets, Keymaps, Language Packs), or, with no
/// categories, when every `contributes` key is pure data.
pub fn manifest_claims(pkg: &serde_json::Value) -> ManifestClaims {
    let categories: Vec<String> = pkg
        .get("categories")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|c| c.as_str())
                .take(10)
                .map(|c| crate::scanners::sanitize_display(c, 64))
                .collect()
        })
        .unwrap_or_default();
    let mut code_entry_points = Vec::new();
    for key in ["main", "browser"] {
        if pkg
            .get(key)
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.trim().is_empty())
        {
            code_entry_points.push(key.to_string());
        }
    }
    if pkg
        .get("activationEvents")
        .and_then(|v| v.as_array())
        .is_some_and(|a| !a.is_empty())
    {
        code_entry_points.push("activationEvents".to_string());
    }
    let contributes = pkg.get("contributes").and_then(|v| v.as_object());
    let contributes_theme = contributes.is_some_and(|c| {
        ["themes", "iconThemes", "productIconThemes"]
            .iter()
            .any(|k| c.contains_key(*k))
    });
    let contributes_commands =
        contributes.is_some_and(|c| c.contains_key("commands") || c.contains_key("configuration"));
    // Deliberately stricter than "contributes a theme": the extension must present ITSELF
    // as declarative (every category declarative, or with no categories only data
    // contributions). A theme filed under "Themes" and "Other" makes no such claim, and
    // flagging every extension that happens to bundle a theme would cry wolf.
    let declarative_claim = if !categories.is_empty() {
        categories
            .iter()
            .all(|c| DECLARATIVE_CATEGORIES.contains(&c.to_ascii_lowercase().as_str()))
    } else {
        contributes.is_some_and(|c| !c.is_empty() && c.keys().all(|k| DECLARATIVE_CONTRIBUTES.contains(&k.as_str())))
    };
    let version = pkg
        .get("version")
        .and_then(|v| v.as_str())
        .filter(|v| is_well_formed_version(v))
        .map(str::to_string);
    ManifestClaims {
        categories,
        code_entry_points,
        contributes_theme,
        contributes_commands,
        declarative_claim,
        version,
    }
}

/// `X.Y.Z` (digits), optionally followed by a `-` or `+` tail of ASCII letters, digits,
/// `.` and `-`; at most 64 bytes. Anything else in a manifest's `version` is ignored and
/// the directory name's version is used.
pub fn is_well_formed_version(v: &str) -> bool {
    if v.is_empty() || v.len() > 64 {
        return false;
    }
    let core_end = v.find(['-', '+']).unwrap_or(v.len());
    let (core, tail) = v.split_at(core_end);
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        && tail
            .chars()
            .skip(1)
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && tail.len() != 1
}

/// VS Code's target platforms, the closed `TargetPlatform` enum in
/// `src/vs/platform/extensions/common/extensions.ts`
/// (<https://github.com/microsoft/vscode/blob/2780fc5eac21547e7342a172d7fcd557fc8ef05a/src/vs/platform/extensions/common/extensions.ts#L394-L413>).
/// `unknown` and `undefined` are never written into a directory name.
pub const VSCODE_TARGET_PLATFORMS: &[&str] = &[
    "win32-x64",
    "win32-arm64",
    "linux-x64",
    "linux-arm64",
    "linux-armhf",
    "alpine-x64",
    "alpine-arm64",
    "darwin-x64",
    "darwin-arm64",
    "web",
    "universal",
];

/// Most `.obsolete` keys read from one extensions root.
const MAX_OBSOLETE_KEYS: usize = 10_000;

/// The extension directory names (lowercased) VS Code's root `.obsolete` file marks as
/// removed: keys whose value is `true`. VS Code reads and rewrites this one file at
/// `<extensions root>/.obsolete` (`withRemovedExtensions` in
/// `src/vs/platform/extensionManagement/node/extensionManagementService.ts`,
/// <https://github.com/microsoft/vscode/blob/2780fc5eac21547e7342a172d7fcd557fc8ef05a/src/vs/platform/extensionManagement/node/extensionManagementService.ts#L822-L855>),
/// keyed by `ExtensionKey.toString()`, which is the directory name. Read bounded and
/// without following a symlink; a missing or malformed file marks nothing.
pub fn read_obsolete_keys(ext_dir: &std::path::Path) -> std::collections::HashSet<String> {
    let path = ext_dir.join(".obsolete");
    if !crate::scanners::probe_exists(&path) {
        return Default::default();
    }
    crate::scanners::read_bounded_nofollow(&path, None)
        .map(|t| parse_obsolete(&t))
        .unwrap_or_default()
}

/// The keys of a `.obsolete` JSON object whose value is `true`, lowercased.
pub fn parse_obsolete(text: &str) -> std::collections::HashSet<String> {
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(text) else {
        return Default::default();
    };
    map.into_iter()
        .filter(|(_, v)| v.as_bool() == Some(true))
        .map(|(k, _)| k.to_ascii_lowercase())
        .take(MAX_OBSOLETE_KEYS)
        .collect()
}

/// Native `.node` addons (by magic bytes, not just extension) inside an extension
/// directory: up to 5 relative paths, sorted. No symlink is followed; the walk is
/// bounded. Only called for extensions that claim to be declarative.
pub fn find_native_addons(dir: &std::path::Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut budget = MAX_ADDON_WALK;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        for e in entries.flatten() {
            if budget == 0 {
                break;
            }
            budget -= 1;
            let p = e.path();
            let Ok(meta) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if meta.is_dir() {
                stack.push(p);
            } else if meta.is_file()
                && p.extension().is_some_and(|x| x == "node")
                // Opened O_NOFOLLOW|O_NONBLOCK with an fstat check: a .node swapped for a
                // link or a FIFO after the symlink_metadata check is refused, not followed.
                && crate::scanners::read_head_bytes_nofollow(&p, 64)
                    .is_some_and(|b| crate::scanners::agent_settings::is_native_head(&b))
                && let Ok(rel) = p.strip_prefix(dir)
            {
                found.push(crate::scanners::sanitize_display(&rel.to_string_lossy(), 200));
            }
        }
    }
    found.sort();
    found.truncate(5);
    found
}

/// Parse "publisher.name-1.2.3" into ("publisher.name", "1.2.3"). A platform-specific
/// install, "publisher.name-1.2.3-darwin-arm64", parses to the same pair: the version
/// never carries the target platform (see [`parse_extension_dir_name_platform`]).
pub fn parse_extension_dir_name(name: &str) -> Option<(String, String)> {
    parse_extension_dir_name_platform(name).map(|(id, version, _)| (id, version))
}

/// Parse a VS Code-family extension directory name into (id, version, target platform).
///
/// VS Code names an installed extension's directory `ExtensionKey.toString()`:
/// `${id}-${version}` plus `-${targetPlatform}` for a platform-specific build
/// (`src/vs/platform/extensionManagement/common/extensionManagementUtil.ts`,
/// <https://github.com/microsoft/vscode/blob/2780fc5eac21547e7342a172d7fcd557fc8ef05a/src/vs/platform/extensionManagement/common/extensionManagementUtil.ts#L30-L57>).
/// The suffix is split off only when it is one of the closed [`VSCODE_TARGET_PLATFORMS`],
/// so a pre-release tail (`1.2.3-beta`) stays part of the version. Before this, the
/// version of `anthropic.claude-code-2.1.313-linux-x64` read `2.1.313-linux-x64`, and no
/// exact-version catalog row could match a platform-specific build.
pub fn parse_extension_dir_name_platform(name: &str) -> Option<(String, String, Option<&'static str>)> {
    let (id, version) = split_id_version(name)?;
    for p in VSCODE_TARGET_PLATFORMS {
        if let Some(v) = version.strip_suffix(p).and_then(|v| v.strip_suffix('-'))
            && !v.is_empty()
        {
            return Some((id, v.to_string(), Some(p)));
        }
    }
    Some((id, version, None))
}

fn split_id_version(name: &str) -> Option<(String, String)> {
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
fn scan_zed_extensions(ext_dir: &std::path::Path, ide: Ide) -> Vec<IdeExtension> {
    let mut results = Vec::new();

    let Ok(entries) = crate::scanners::probe_read_dir(ext_dir) else {
        return results;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !crate::scanners::probe_dir(&path) {
            continue;
        }

        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        // Try to read extension.json for version info
        let version = crate::scanners::read_bounded(&path.join("extension.json"))
            .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
            .and_then(|v| v["version"].as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "unknown".to_string());

        results.push(IdeExtension {
            id: name.clone(),
            name: name.clone(),
            version,
            publisher: "zed-extensions".to_string(),
            ide_type: ide.name().to_string(),
            ..Default::default()
        });
    }

    results
}
