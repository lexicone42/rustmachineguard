use crate::platform::PlatformInfo;
use crate::scanners::Scanner;
use std::io::Read;
use std::path::{Path, PathBuf};

/// User-installed JetBrains IDE plugins, identified by the plugin ID in the jar's
/// `META-INF/plugin.xml` -- the key the Marketplace and the IDE use.
///
/// Why this scanner exists: in June 2026 JetBrains removed 15 Marketplace plugins from 7
/// vendor accounts (about 70,000 installs) that posed as DeepSeek/OpenAI developer tools
/// and posted the AI API keys users typed into their settings to a C2 over plaintext
/// HTTP. The remote kill-switch disables them on relaunch, but the jars stay on disk and
/// the catalog had no ecosystem for them at all. Sources: JetBrains Marketplace security
/// update (2026-06), StepSecurity.
///
/// Identities only: id, name, version, vendor, location. Plugin CODE is never read, and
/// the descriptor read is bounded.
pub struct JetBrainsPluginsScanner;

const MAX_PLUGINS_PER_ROOT: usize = 500;
/// Jars considered per plugin folder. Bounded by count only as a runtime guard; every
/// jar's central directory is cheap to read, and the folder-named jar is tried first, so
/// a legitimately large plugin is found and padding lib/ with dummy jars does not hide it.
const MAX_JARS_PER_PLUGIN: usize = 500;
const MAX_DESCRIPTOR_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct JetBrainsPluginRecord {
    pub id: String,
    pub name: String,
    pub version: String,
    pub vendor: Option<String>,
    /// Product-version directory the plugin was found under, e.g. `IntelliJIdea2026.2`.
    pub ide: String,
    pub location: String,
}

impl Scanner for JetBrainsPluginsScanner {
    type Output = Vec<JetBrainsPluginRecord>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<JetBrainsPluginRecord> {
        let home = platform.home_dir();
        let mut out = Vec::new();
        for base in plugin_bases(&home) {
            let Ok(products) = crate::scanners::probe_read_dir(&base) else {
                continue;
            };
            for product in products.flatten() {
                let ide = product.file_name().to_string_lossy().to_string();
                // Linux keeps plugins directly under the product dir; macOS under plugins/.
                // Both candidates are scanned: stopping at the first meant a plugin folder
                // literally named `plugins` hid every sibling on Linux. Duplicates are
                // removed below.
                for plugins_dir in [product.path().join("plugins"), product.path()] {
                    if crate::scanners::probe_dir(&plugins_dir) {
                        scan_plugins_dir(&plugins_dir, &ide, &mut out);
                    }
                }
            }
        }
        let mut seen = std::collections::HashSet::new();
        out.retain(|p| seen.insert((p.id.clone(), p.version.clone(), p.ide.clone())));
        out
    }
}

/// Per JetBrains' "Directories used by the IDE": Linux `~/.local/share/JetBrains/<product>`,
/// macOS `~/Library/Application Support/JetBrains/<product>/plugins`. Toolbox installs
/// use the same locations.
fn plugin_bases(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join(".local/share/JetBrains"),
        home.join("Library/Application Support/JetBrains"),
    ]
}

fn scan_plugins_dir(dir: &Path, ide: &str, out: &mut Vec<JetBrainsPluginRecord>) {
    let Ok(entries) = crate::scanners::probe_read_dir(dir) else {
        return;
    };
    let mut budget = MAX_PLUGINS_PER_ROOT;
    for entry in entries.flatten() {
        if budget == 0 {
            return;
        }
        budget -= 1;
        let p = entry.path();
        // Follow symlinks for the dir-vs-jar decision (a plugin installed as a symlink is
        // still installed); read_descriptor re-checks for a regular file at open time.
        let Ok(meta) = std::fs::metadata(&p) else {
            continue;
        };
        let descriptor = if meta.is_file() && has_ext(&p, "jar") {
            read_descriptor(&p)
        } else if meta.is_dir() {
            plugin_folder_descriptor(&p)
        } else {
            None
        };
        if let Some(xml) = descriptor
            && let Some(rec) = parse_plugin_xml(&xml, ide, &p)
        {
            out.push(rec);
        }
    }
}

/// The descriptor of a plugin FOLDER: in one of lib/*.jar (or *.jar). Jars are sorted,
/// the one named after the folder is tried first, and all are tried up to the cap --
/// readdir order is filesystem-dependent, and a first-N cut made a catalogued plugin
/// visible on one filesystem and invisible on another.
fn plugin_folder_descriptor(folder: &Path) -> Option<String> {
    let folder_name = folder.file_name()?.to_string_lossy().to_ascii_lowercase();
    let mut jars: Vec<PathBuf> = Vec::new();
    for jar_dir in [folder.join("lib"), folder.to_path_buf()] {
        let Ok(it) = crate::scanners::probe_read_dir(&jar_dir) else {
            continue;
        };
        for j in it.flatten() {
            let jp = j.path();
            if has_ext(&jp, "jar") && std::fs::metadata(&jp).is_ok_and(|m| m.is_file()) {
                jars.push(jp);
            }
            if jars.len() >= MAX_JARS_PER_PLUGIN {
                break;
            }
        }
    }
    jars.sort();
    jars.sort_by_key(|j| {
        let stem = j.file_stem().map(|s| s.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
        !(stem == folder_name || folder_name.starts_with(&stem) || stem.starts_with(&folder_name))
    });
    jars.iter().find_map(|j| read_descriptor(j))
}

fn has_ext(p: &Path, ext: &str) -> bool {
    p.extension().and_then(|e| e.to_str()).is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

/// The `META-INF/plugin.xml` text from a jar, bounded. Only regular files are opened.
fn read_descriptor(jar: &Path) -> Option<String> {
    match std::fs::metadata(jar) {
        Ok(m) if m.is_file() => {}
        _ => return None,
    }
    let file = std::fs::File::open(jar).ok()?;
    crate::scanners::telemetry::note_read(jar, "ok");
    let mut archive = zip::ZipArchive::new(file).ok()?;
    let entry = archive.by_name("META-INF/plugin.xml").ok()?;
    let mut text = String::new();
    entry.take(MAX_DESCRIPTOR_BYTES).read_to_string(&mut text).ok()?;
    Some(text)
}

/// Remove XML comments and neutralise CDATA sections (their `<` becomes `&lt;`) so a
/// `<id>` inside a comment or a CDATA description cannot be mistaken for the real one.
fn neutralise_markup(xml: &str) -> String {
    enum Next {
        Comment(usize),
        Cdata(usize),
    }
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    loop {
        let next = match (rest.find("<!--"), rest.find("<![CDATA[")) {
            (None, None) => {
                out.push_str(rest);
                return out;
            }
            (Some(ci), None) => Next::Comment(ci),
            (None, Some(di)) => Next::Cdata(di),
            (Some(ci), Some(di)) => {
                if ci < di {
                    Next::Comment(ci)
                } else {
                    Next::Cdata(di)
                }
            }
        };
        match next {
            Next::Comment(ci) => {
                out.push_str(&rest[..ci]);
                rest = match rest[ci..].find("-->") {
                    Some(e) => &rest[ci + e + 3..],
                    None => "",
                };
            }
            Next::Cdata(di) => {
                out.push_str(&rest[..di]);
                let body = &rest[di + 9..];
                let (inner, after) = match body.find("]]>") {
                    Some(e) => (&body[..e], &body[e + 3..]),
                    None => (body, ""),
                };
                out.push_str(&inner.replace('<', "&lt;"));
                rest = after;
            }
        }
    }
}

/// Decode the five predefined entities and numeric character references.
fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let Some(semi) = tail.find(';').filter(|&n| n <= 10) else {
            out.push('&');
            rest = &tail[1..];
            continue;
        };
        let ent = &tail[1..semi];
        let decoded = match ent {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => ent
                .strip_prefix('#')
                .and_then(|n| match n.strip_prefix(['x', 'X']) {
                    Some(h) => u32::from_str_radix(h, 16).ok(),
                    None => n.parse::<u32>().ok(),
                })
                .and_then(char::from_u32),
        };
        match decoded {
            Some(c) => out.push(c),
            None => out.push_str(&tail[..=semi]),
        }
        rest = &tail[semi + 1..];
    }
    out.push_str(rest);
    out
}

/// Text of the FIRST `<tag>…</tag>` at any depth. `<idea-version since-build=…/>` has
/// attributes and so does not match `<version>`.
fn xml_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    // `<tag>` or `<tag attr="…">`; `<idea-version …>` never matches `<version`.
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut from = 0;
    let start = loop {
        let i = xml[from..].find(&open)? + from;
        let after = &xml[i + open.len()..];
        if after.starts_with('>') {
            break i + open.len() + 1;
        }
        if after.starts_with(char::is_whitespace)
            && let Some(gt) = after.find('>')
        {
            break i + open.len() + gt + 1;
        }
        from = i + open.len();
    };
    let end = xml[start..].find(&close)? + start;
    let inner = xml[start..end].trim();
    let inner = inner.strip_prefix("<![CDATA[").and_then(|s| s.strip_suffix("]]>")).unwrap_or(inner);
    Some(inner.trim())
}

/// A plugin ID is an opaque string to the platform: JetBrains only RECOMMENDS the
/// Java-package charset, and widely installed plugins use `Key Promoter X` (8M installs)
/// and `Lombook Plugin` (27M). Restricting to `[A-Za-z0-9._-]` silently dropped them from
/// the inventory. Reject only what cannot be an ID or is unsafe to print: empty,
/// oversized, control characters, path separators. Catalog matching is exact.
pub fn is_valid_plugin_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 200
        && !id.chars().any(|c| c.is_control() || matches!(c, '/' | '\\'))
        && id.trim() == id
}

/// Identity from a plugin.xml. A legacy descriptor without `<id>` is identified by its
/// `<name>`, as the platform does. Every field is attacker-authored and sanitized.
pub fn parse_plugin_xml(xml: &str, ide: &str, location: &Path) -> Option<JetBrainsPluginRecord> {
    let xml = neutralise_markup(xml);
    let xml = xml.as_str();
    let name_raw = xml_text(xml, "name").map(decode_entities).unwrap_or_default();
    let id_owned = xml_text(xml, "id").map(decode_entities).unwrap_or_else(|| name_raw.clone());
    let id_raw = id_owned.trim();
    let name_raw = name_raw.as_str();
    if !is_valid_plugin_id(id_raw) {
        return None;
    }
    let version = xml_text(xml, "version")
        .filter(|v| crate::scanners::npm_packages::is_valid_version(v))
        .unwrap_or("unknown")
        .to_string();
    Some(JetBrainsPluginRecord {
        id: id_raw.to_string(),
        name: crate::scanners::sanitize_display(if name_raw.is_empty() { id_raw } else { name_raw }, 128),
        version,
        vendor: xml_text(xml, "vendor").map(|v| crate::scanners::sanitize_display(v, 128)),
        ide: crate::scanners::sanitize_display(ide, 64),
        location: crate::scanners::sanitize_display(&location.to_string_lossy(), 512),
    })
}
