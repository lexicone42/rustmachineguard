use crate::models::AgentMarketplace;
use crate::platform::PlatformInfo;
use crate::scanners::{read_bounded, Scanner};
use std::collections::HashMap;

/// Inventories Claude Code plugin marketplaces — remote git sources whose plugins and
/// skills run as agent code (the EAA-009 remote hot-load surface). Records provenance
/// (source, official-vs-third-party) and whether each auto-updates. Reads config JSON
/// only; never fetches, clones, or executes a marketplace.
pub struct MarketplacesScanner;

impl Scanner for MarketplacesScanner {
    type Output = Vec<AgentMarketplace>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<AgentMarketplace> {
        let dir = platform.claude_config_dir().join("plugins");
        let Some(content) = read_bounded(&dir.join("known_marketplaces.json")) else {
            return Vec::new();
        };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
            return Vec::new();
        };
        let counts = read_bounded(&dir.join("installed_plugins.json"))
            .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
            .map(|v| plugin_counts(&v))
            .unwrap_or_default();
        parse_marketplaces(&json, &counts)
    }
}

/// Count installed plugins per marketplace from `installed_plugins.json`. Plugin keys
/// are namespaced `plugin@marketplace`, so the count per marketplace is the number of
/// keys ending in `@<name>`.
pub fn plugin_counts(json: &serde_json::Value) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    if let Some(plugins) = json.get("plugins").and_then(|v| v.as_object()) {
        for key in plugins.keys() {
            if let Some((_, market)) = key.rsplit_once('@') {
                *counts.entry(market.to_string()).or_insert(0) += 1;
            }
        }
    }
    counts
}

/// Parse the `known_marketplaces.json` object into structured marketplace records.
pub fn parse_marketplaces(
    json: &serde_json::Value,
    counts: &HashMap<String, usize>,
) -> Vec<AgentMarketplace> {
    let Some(obj) = json.as_object() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, entry) in obj {
        let source = entry.get("source");
        let source_type = source
            .and_then(|s| s.get("source"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        // A github source carries `repo: owner/name`; a git source carries `url`.
        let source_ref = source
            .and_then(|s| s.get("repo").or_else(|| s.get("url")).or_else(|| s.get("path")))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let auto_update = entry
            .get("autoUpdate")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let official = is_official(&source_type, &source_ref);
        let installed_plugin_count = counts.get(name).copied().unwrap_or(0);
        out.push(AgentMarketplace {
            name: name.clone(),
            source_type,
            source_ref,
            auto_update,
            official,
            installed_plugin_count,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// True if a marketplace is published by Anthropic (an official source).
fn is_official(source_type: &str, source_ref: &str) -> bool {
    let r = source_ref.to_ascii_lowercase();
    match source_type {
        "github" => r.starts_with("anthropics/"),
        "git" => r.contains("github.com/anthropics/") || r.contains("github.com:anthropics/"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_github_and_git_sources() {
        let j = json!({
            "official-mp": {"source": {"source": "github", "repo": "anthropics/claude-plugins-official"}},
            "vendor-mp": {"source": {"source": "github", "repo": "trailofbits/skills"}, "autoUpdate": true},
            "raw-git": {"source": {"source": "git", "url": "https://github.com/someone/x.git"}}
        });
        let counts = HashMap::new();
        let mps = parse_marketplaces(&j, &counts);
        assert_eq!(mps.len(), 3);
        let official = mps.iter().find(|m| m.name == "official-mp").unwrap();
        assert!(official.official);
        assert!(!official.auto_update);
        let vendor = mps.iter().find(|m| m.name == "vendor-mp").unwrap();
        assert!(!vendor.official);
        assert!(vendor.auto_update);
        assert_eq!(vendor.source_ref, "trailofbits/skills");
        let raw = mps.iter().find(|m| m.name == "raw-git").unwrap();
        assert!(!raw.official);
        assert_eq!(raw.source_type, "git");
    }

    #[test]
    fn official_anthropic_git_url_is_recognized() {
        assert!(is_official("git", "https://github.com/anthropics/claude-code.git"));
        assert!(is_official("github", "anthropics/claude-plugins-official"));
        assert!(!is_official("github", "evil/anthropics-lookalike"));
        assert!(!is_official("git", "https://gitlab.com/x/y.git"));
    }

    #[test]
    fn counts_plugins_per_marketplace() {
        let installed = json!({
            "version": 2,
            "plugins": {
                "a@official-mp": [{}],
                "b@official-mp": [{}],
                "c@vendor-mp": [{}]
            }
        });
        let counts = plugin_counts(&installed);
        assert_eq!(counts.get("official-mp"), Some(&2));
        assert_eq!(counts.get("vendor-mp"), Some(&1));
    }

    #[test]
    fn empty_or_malformed_is_empty() {
        assert!(parse_marketplaces(&json!("nope"), &HashMap::new()).is_empty());
        assert!(plugin_counts(&json!({})).is_empty());
    }
}
