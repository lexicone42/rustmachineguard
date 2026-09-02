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
const MAX_JARS_PER_PLUGIN: usize = 40;
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
                for plugins_dir in [product.path().join("plugins"), product.path()] {
                    if !crate::scanners::probe_dir(&plugins_dir) {
                        continue;
                    }
                    scan_plugins_dir(&plugins_dir, &ide, &mut out);
                    break;
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
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let descriptor = if kind.is_file() && has_ext(&p, "jar") {
            read_descriptor(&p)
        } else if kind.is_dir() {
            // A plugin folder: the descriptor is in one of lib/*.jar (or *.jar).
            let mut found = None;
            let mut jars = 0;
            for jar_dir in [p.join("lib"), p.clone()] {
                let Ok(jars_iter) = crate::scanners::probe_read_dir(&jar_dir) else {
                    continue;
                };
                for j in jars_iter.flatten() {
                    if jars >= MAX_JARS_PER_PLUGIN {
                        break;
                    }
                    let jp = j.path();
                    if has_ext(&jp, "jar") && j.file_type().is_ok_and(|k| k.is_file()) {
                        jars += 1;
                        if let Some(d) = read_descriptor(&jp) {
                            found = Some(d);
                            break;
                        }
                    }
                }
                if found.is_some() {
                    break;
                }
            }
            found
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

/// Plugin IDs are Java-package-like: letters, digits, `.`, `_`, `-`; bounded.
pub fn is_valid_plugin_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 200
        && id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Identity from a plugin.xml. A legacy descriptor without `<id>` is identified by its
/// `<name>`, as the platform does. Every field is attacker-authored and sanitized.
pub fn parse_plugin_xml(xml: &str, ide: &str, location: &Path) -> Option<JetBrainsPluginRecord> {
    let name_raw = xml_text(xml, "name").unwrap_or("");
    let id_raw = xml_text(xml, "id").unwrap_or(name_raw).trim();
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
