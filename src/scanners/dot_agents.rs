//! The shared `.agents/` directory, and the Claude Code settings files other agents
//! read: one place for which agent loads what, so the skills, settings and `agents`
//! scanners attribute a file to every agent that runs it rather than keeping one copy
//! per agent.
//!
//! The `.agents/` directory belongs to no single agent. Skills in `.agents/skills/` (a
//! project's) and `~/.agents/skills/` are walked once (`framework: "agents"`), and each
//! row lists in `read_by` the agents whose documentation says they load that directory
//! AND that have a configuration home on this machine (`~/.codex`, `~/.gemini`, ...:
//! existence of the directory, not a link, not its contents). An agent installed
//! without ever writing its configuration home is not listed (a floor). Sources
//! (fetched 2026-10-30):
//!
//! - Codex: "For repositories, Codex scans `.agents/skills` in every directory from your
//!   current working directory up to the repository root"; `$HOME/.agents/skills` (USER)
//!   (learn.chatgpt.com/docs/build-skills.md).
//! - Gemini CLI: "**Workspace skills**: Located in `.gemini/skills/` or the
//!   `.agents/skills/` alias"; user `~/.agents/skills/`
//!   (github.com/google-gemini/gemini-cli `docs/cli/skills.md`).
//! - GitHub Copilot CLI: skills from `.github/skills/`, `.agents/skills/`, ...,
//!   `~/.agents/skills/` (docs.github.com/en/copilot/reference/copilot-cli-reference/
//!   cli-command-reference).
//! - Cursor: "`.agents/skills/`, `.cursor/skills/`, `~/.agents/skills/`"
//!   (cursor.com/docs/skills.md).
//! - OpenCode: "Project agent-compatible: `.agents/skills/<name>/SKILL.md`", "Global
//!   agent-compatible: `~/.agents/skills/<name>/SKILL.md`" (opencode.ai/docs/skills).
//! - Amp: `~/.agents/skills/` and "`.agents/skills/` in the project and searched parent
//!   directories"; a skill may define MCP servers in "an `mcp.json` file or the
//!   `mcpServers` field in frontmatter" (ampcode.com/docs/customize/skills).
//! - Goose: "`~/.agents/skills/` — Global skills", "`.agents/skills/` — Project-level
//!   skills", "`~/.agents/plugins/<plugin-name>/` — Skills provided by installed plugins"
//!   (github.com/aaif-goose/goose `documentation/docs/guides/context-engineering/
//!   using-skills.md`).
//! - Devin CLI / Devin Local: "`.agents/skills/<name>/SKILL.md` | Project-specific",
//!   `~/.agents/skills/`, subagents in `.agents/agents/` (docs.devin.ai
//!   `cli/extensibility/skills/overview.md`, `desktop/devin-local/customizations.md`).
//!
//! Kiro documents `.kiro/skills` only; Claude Code does not read `.agents/`. Codex's
//! `.agents/plugins/marketplace.json` lists plugin sources; installed Codex plugins are
//! read where Codex keeps them (`~/.codex/plugins`, the settings scanner), so the
//! marketplace file is not read (a floor).
//!
//! Claude Code settings: "The CLI also reads `.claude/settings.json` and
//! `.claude/settings.local.json` for the shared cross-tool subset of repository settings
//! (such as ... `hooks`)" (Copilot CLI, docs.github.com cli-config-dir-reference);
//! "Claude Code hooks load when **Include Third-Party Plugins, Skills, and Other
//! Configs** is enabled ... The setting is on by default", from `.claude/settings.local.json`,
//! `.claude/settings.json` and `~/.claude/settings.json` (Cursor,
//! cursor.com/docs/reference/third-party-hooks.md); "`.claude/settings.json` | `"hooks"`
//! key (Claude Code format)", "`~/.claude/settings.json` | `"hooks"` key" and
//! `~/.claude/settings.local.json` (Devin CLI, docs.devin.ai
//! `cli/extensibility/hooks/overview.md`). A `.claude` hook is therefore run by each of
//! those agents too, not only by Claude Code.

use std::path::{Path, PathBuf};

/// An agent that reads part of `.agents/` or `.claude/`: its closed label and its
/// configuration home under HOME.
struct Reader {
    label: &'static str,
    home: &'static [&'static str],
}

const CODEX: Reader = Reader {
    label: "codex",
    home: &[".codex"],
};
const GEMINI: Reader = Reader {
    label: "gemini-cli",
    home: &[".gemini"],
};
const COPILOT: Reader = Reader {
    label: "copilot-cli",
    home: &[".copilot"],
};
const CURSOR: Reader = Reader {
    label: "cursor",
    home: &[".cursor"],
};
const OPENCODE: Reader = Reader {
    label: "opencode",
    home: &[".config/opencode"],
};
const AMP: Reader = Reader {
    label: "amp",
    home: &[".config/amp"],
};
const GOOSE: Reader = Reader {
    label: "goose",
    home: &[".config/goose"],
};
const DEVIN: Reader = Reader {
    label: "devin",
    home: &[".config/devin", ".devin"],
};

/// What is read, and who reads it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Surface {
    /// `.agents/skills/` in a project.
    ProjectSkills,
    /// `~/.agents/skills/`.
    UserSkills,
    /// `~/.agents/plugins/<plugin>/` (skills of installed plugins).
    UserPlugins,
    /// `.agents/agents/` in a project, `~/.agents/agents/` (subagents).
    Subagents,
    /// A repository's `.claude/settings.json` / `settings.local.json` hooks.
    ClaudeProjectSettings,
    /// `~/.claude/settings.json` hooks.
    ClaudeUserSettings,
    /// `~/.claude/settings.local.json` hooks.
    ClaudeUserLocalSettings,
}

fn documented(s: Surface) -> &'static [Reader] {
    match s {
        Surface::ProjectSkills | Surface::UserSkills => &[CODEX, GEMINI, COPILOT, CURSOR, OPENCODE, AMP, GOOSE, DEVIN],
        Surface::UserPlugins => &[GOOSE],
        Surface::Subagents => &[DEVIN],
        Surface::ClaudeProjectSettings => &[CURSOR, COPILOT, DEVIN],
        Surface::ClaudeUserSettings => &[CURSOR, DEVIN],
        Surface::ClaudeUserLocalSettings => &[DEVIN],
    }
}

/// The documented readers of `s` that have a configuration home in `home` (a real
/// directory, judged without following a link), in a fixed order.
pub fn readers(home: &Path, s: Surface) -> Vec<String> {
    documented(s)
        .iter()
        .filter(|r| {
            r.home.iter().any(|h| {
                let p = home.join(h);
                let ok = std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_dir());
                crate::scanners::telemetry::note_probe(&p, ok);
                ok
            })
        })
        .map(|r| r.label.to_string())
        .collect()
}

/// The other agents that run the hooks of a Claude Code settings file with `source`
/// (`project`, `local`, `user-global`, `user-local`); empty for other sources.
pub fn claude_settings_readers(home: &Path, source: &str) -> Vec<String> {
    let s = match source {
        "project" | "local" => Surface::ClaudeProjectSettings,
        "user-global" => Surface::ClaudeUserSettings,
        "user-local" => Surface::ClaudeUserLocalSettings,
        _ => return Vec::new(),
    };
    readers(home, s)
}

/// The skill walks of `.agents/`: (root, framework, scope, surface). `projects` are
/// the pass's project directories.
pub fn skill_roots(home: &Path, projects: &[PathBuf]) -> Vec<(PathBuf, &'static str, &'static str, Surface)> {
    let mut v = vec![
        (
            home.join(".agents").join("skills"),
            "agents",
            "global",
            Surface::UserSkills,
        ),
        (
            home.join(".agents").join("plugins"),
            "agents-plugin",
            "global",
            Surface::UserPlugins,
        ),
    ];
    for p in projects {
        v.push((
            p.join(".agents").join("skills"),
            "agents",
            "project",
            Surface::ProjectSkills,
        ));
    }
    v
}

/// Subagent directories of `.agents/` (`~/.agents/agents`, `<project>/.agents/agents`).
pub fn subagent_roots(home: &Path, projects: &[PathBuf]) -> Vec<(PathBuf, &'static str)> {
    let mut v = vec![(home.join(".agents").join("agents"), "global")];
    for p in projects {
        v.push((p.join(".agents").join("agents"), "project"));
    }
    v
}

/// Skill `mcp.json` files (Amp: "Skills can define MCP servers through ... an `mcp.json`
/// file"): `<root>/<skill>/mcp.json` for each `.agents/skills` root, real directories
/// only, at most `cap` skills per root. `(path, project root or None)`.
pub fn skill_mcp_files(home: &Path, projects: &[PathBuf], cap: usize) -> Vec<(PathBuf, Option<PathBuf>)> {
    let mut out = Vec::new();
    let mut roots: Vec<(PathBuf, Option<PathBuf>)> = vec![(home.join(".agents").join("skills"), None)];
    for p in projects {
        roots.push((p.join(".agents").join("skills"), Some(p.clone())));
    }
    for (root, proj) in roots {
        if !plain(&root, proj.as_deref().unwrap_or(home)) {
            continue;
        }
        let Ok(rd) = crate::scanners::probe_read_dir(&root) else {
            continue;
        };
        let mut dirs: Vec<PathBuf> = Vec::new();
        for e in rd.flatten() {
            if dirs.len() >= cap {
                crate::scanners::telemetry::mark_truncated();
                break;
            }
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                dirs.push(e.path());
            }
        }
        dirs.sort();
        for d in dirs {
            let f = d.join("mcp.json");
            if std::fs::symlink_metadata(&f).is_ok() {
                out.push((f, proj.clone()));
            }
        }
    }
    out
}

/// `dir` is a real directory reached from `base` without a link in any component.
fn plain(dir: &Path, base: &Path) -> bool {
    let Ok(rel) = dir.strip_prefix(base) else {
        return false;
    };
    let mut at = base.to_path_buf();
    for c in rel.components() {
        at.push(c);
        if !std::fs::symlink_metadata(&at).is_ok_and(|m| m.is_dir()) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readers_are_the_documented_agents_with_a_home() {
        let d = std::env::temp_dir().join(format!("rmg-dotagents-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(".codex")).unwrap();
        std::fs::create_dir_all(d.join(".config/goose")).unwrap();
        std::fs::create_dir_all(d.join(".cursor")).unwrap();
        assert_eq!(readers(&d, Surface::ProjectSkills), vec!["codex", "cursor", "goose"]);
        assert_eq!(readers(&d, Surface::UserPlugins), vec!["goose"]);
        assert_eq!(claude_settings_readers(&d, "project"), vec!["cursor"]);
        assert!(claude_settings_readers(&d, "managed").is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }
}
