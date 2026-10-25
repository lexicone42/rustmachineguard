//! Scripts that the user's Claude Code settings commands run (`statusLine`,
//! `subagentStatusLine`, `fileSuggestion`; code.claude.com/docs/en/statusline.md, fetched
//! 2026-10-24: the status line "runs any shell script you configure", and `/statusline`
//! "generates a script file in `~/.claude/`"). The
//! commands themselves are already inventoried and graded as hooks of kind
//! `settings-command`, through the same `hook_severity` ladder as command hooks. What a
//! command line cannot show is the script it names. `"command": "~/.claude/statusline.sh"`
//! runs whatever that file holds every time the status line renders. A script under the
//! agent's own directory is therefore recorded with the same identity as `~/.claude/bin`
//! executables: format, mode, owner, mtime, size and SHA-256
//! ([`crate::scanners::persistence::agent_bin_info`]), so `--diff` shows it changing.
//!
//! Only the user's `~/.claude/settings.json` is read. Only a program, or the script
//! given to an interpreter (`bash ~/.claude/x.sh`), that resolves under the Claude
//! config directory is recorded, and only as a regular file (a link is not followed) that
//! is not a credential or agent-state file.

use crate::models::SettingsCommandScript;
use crate::platform::PlatformInfo;
use crate::scanners::sanitize_display;
use std::path::{Path, PathBuf};

/// Interpreters whose first argument is the script that runs.
const INTERPRETERS: &[&str] = &[
    "bash", "sh", "zsh", "dash", "fish", "python", "python3", "node", "bun", "deno", "perl", "ruby",
];

/// The `statusline` job for one home.
pub fn scan_home(platform: &dyn PlatformInfo) -> Vec<SettingsCommandScript> {
    settings_command_scripts(&platform.home_dir(), &platform.claude_config_dir())
}

/// The scripts under `claude_dir` that `claude_dir/settings.json` settings commands run.
pub fn settings_command_scripts(home: &Path, claude_dir: &Path) -> Vec<SettingsCommandScript> {
    let settings = claude_dir.join("settings.json");
    if !crate::scanners::probe_file(&settings) {
        return Vec::new();
    }
    let Some(json) =
        crate::scanners::read_bounded(&settings).and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for key in crate::scanners::hook_sources::SETTINGS_COMMAND_KEYS {
        let cmd = match json.get(*key) {
            Some(serde_json::Value::String(s)) => s.as_str(),
            Some(v) => match v.get("command").and_then(|c| c.as_str()) {
                Some(c) => c,
                None => continue,
            },
            None => continue,
        };
        let Some(script) = script_of(cmd, home, claude_dir) else {
            continue;
        };
        // A command naming a credential or state file (`~/.claude/.credentials.json`) is not
        // hashed: the identity read would read the secret.
        if crate::scanners::persistence::is_sensitive_read_name(&script)
            || crate::scanners::persistence::is_agent_credential_path(&script, Some(claude_dir))
        {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(&script) else {
            crate::scanners::telemetry::note_probe(&script, false);
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        out.push(SettingsCommandScript {
            setting: (*key).to_string(),
            settings_path: sanitize_display(&settings.to_string_lossy(), 512),
            path: sanitize_display(&script.to_string_lossy(), 512),
            bin: crate::scanners::persistence::agent_bin_info(&script, &meta, crate::scanners::home_owner_uid(home)),
        });
    }
    out
}

/// The script a settings command runs, when it lies (lexically) under `claude_dir`: the
/// program, or an interpreter's first non-flag argument. `~/`, `$HOME/` and `${HOME}/`
/// are resolved against `home`; other expansions are not followed.
pub fn script_of(cmd: &str, home: &Path, claude_dir: &Path) -> Option<PathBuf> {
    let tokens: Vec<&str> = cmd
        .split_whitespace()
        .map(|t| t.trim_matches(|c| c == '"' || c == '\''))
        .collect();
    let first = *tokens.first()?;
    let base = first.rsplit('/').next().unwrap_or(first);
    let candidate = if INTERPRETERS.contains(&base) {
        *tokens.iter().skip(1).find(|t| !t.starts_with('-'))?
    } else {
        first
    };
    let path = ["~/", "$HOME/", "${HOME}/"]
        .iter()
        .find_map(|p| candidate.strip_prefix(p).map(|rest| home.join(rest)))
        .or_else(|| Path::new(candidate).is_absolute().then(|| PathBuf::from(candidate)))?;
    let lexical = crate::scanners::persistence::lexical_join(Path::new("/"), &path);
    let root = crate::scanners::persistence::lexical_join(Path::new("/"), claude_dir);
    (lexical.starts_with(&root) && lexical != root).then_some(lexical)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_paths_resolve_under_the_agent_dir_only() {
        let h = Path::new("/h");
        let c = Path::new("/h/.claude");
        assert_eq!(
            script_of("~/.claude/statusline.sh", h, c),
            Some(PathBuf::from("/h/.claude/statusline.sh"))
        );
        assert_eq!(
            script_of("bash \"$HOME/.claude/s.sh\" --x", h, c),
            Some(PathBuf::from("/h/.claude/s.sh"))
        );
        assert_eq!(script_of("/h/.claude/../bin/x", h, c), None);
        assert_eq!(script_of("~/bin/statusline", h, c), None);
        assert_eq!(script_of("jq -r .model", h, c), None);
    }
}
