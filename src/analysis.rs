//! Cross-cutting risk analysis over a completed scan — signals that emerge from the
//! *composition* of findings rather than any single one, plus a single ranked list
//! of the actionable security findings for risk-first reporting.

use crate::models::{PassphraseStatus, ScanReport};
use std::collections::BTreeSet;

/// Severity of a finding, ordered so `Critical` sorts first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }
    fn rank(&self) -> u8 {
        match self {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
        }
    }
}

/// A single actionable security finding, normalized across all scanner categories so
/// reports can lead with what matters instead of a flat inventory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    pub severity: Severity,
    /// Short category, e.g. "Exposure", "Hook", "Credential", "Toxic Flow".
    pub category: String,
    pub title: String,
    /// Where it was found (path / config source), for triage.
    pub location: String,
    /// The concrete offending artifact when it isn't already in the title — e.g. the
    /// actual shell command a hook runs. NEVER a secret value (the no-leak guarantee).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

/// Every `category` [`collect_findings`] can emit: a closed set. It is the value set of
/// the `rmguard.finding.category` OpenTelemetry attribute (docs/OPENTELEMETRY.md), which
/// exports [`category_label`]'s `&'static str`, never the finding's own `String`.
/// `finding_category_tests::finding_categories_match_the_source` walks this file for category literals and
/// fails when one is missing here, and a debug build asserts every emitted category is
/// listed, so a new category cannot be added silently.
pub const FINDING_CATEGORIES: &[&str] = &[
    "Exposure",
    "Hook",
    "MCP auto-approval",
    "Permissions",
    "Credential",
    "Secret leak",
    "Secret exposure",
    "SSH key",
    "Rules file",
    "Toxic Flow",
    "Registry",
    "Agent identity",
    "Gateway routing",
    "MCP transport",
    "MCP scope",
    "MCP secret",
    "MCP command",
    "Transcript exposure",
    "Plugin marketplace",
    "Settings secret",
    "Auto-run task",
    "Config integrity",
    "Git autorun",
    "Persistence",
    "Binary planting",
    "Repo symlink",
    "Plugin pin",
    "Skill symlink",
    "Skill command",
    "Skill grant",
    "Agent redirection",
    "Helper command",
    "Login gateway",
    "Extension code",
    "Ollama exposure",
    "Secret hygiene",
    "MCP inventory",
    "Network listener",
];

/// `category` as its [`FINDING_CATEGORIES`] entry, or `other` for a string outside the
/// table. The input is runtime text; the output is always a `&'static str` of the table
/// or the literal `other`, never the input.
pub fn category_label(category: &str) -> &'static str {
    FINDING_CATEGORIES
        .iter()
        .copied()
        .find(|c| *c == category)
        .unwrap_or("other")
}

/// Human-facing explanation for a finding category — the "click to learn more" detail:
/// what was found, why it matters, how to fix it, and the framework it maps to.
pub struct Guidance {
    pub what: &'static str,
    pub why: &'static str,
    pub fix: &'static str,
    /// Standard / catalog reference, or "" when none applies.
    pub reference: &'static str,
}

/// Guidance for a finding category. Every category `collect_findings` can emit has an
/// entry; the fallback keeps the report honest if a new category is added.
pub fn guidance(category: &str) -> Guidance {
    match category {
        "Exposure" => Guidance {
            what: "This package matches rmguard's threat catalog of known-malicious or known-vulnerable releases (compromised npm/PyPI packages, malicious MCP servers, and the like).",
            why: "Installing or running a known-bad package executes attacker-controlled code with your privileges — the most direct compromise path on the machine.",
            fix: "Remove or downgrade the package to a known-good version, rotate any credentials it could have touched, and check the linked advisory for indicators of compromise.",
            reference: "rmguard threat catalog · see docs/THREAT-CATALOG.md",
        },
        "MCP transport" => Guidance {
            what: "This MCP server is reached over plaintext http://, so the connection is unencrypted.",
            why: "Any token in the request and all tool traffic travel in the clear — readable and modifiable by anyone on the network path (a coffee-shop Wi-Fi or a compromised proxy).",
            fix: "Switch the server URL to https://. If the server only offers http, run it over a local loopback or a tunnel, and treat any bearer token it used as exposed.",
            reference: "OWASP MCP Top 10",
        },
        "MCP scope" => Guidance {
            what: "A filesystem MCP server is rooted at a very broad path (/, $HOME, or the home directory), granting the agent read/write across nearly the whole machine.",
            why: "A prompt injection that reaches this agent can read or modify anything under that root — SSH keys, browser profiles, other projects — not just the intended workspace.",
            fix: "Re-root the server at the specific project directory it needs. Filesystem servers should be scoped as narrowly as the task allows.",
            reference: "OWASP Agentic Apps Top 10 (excessive agency)",
        },
        "MCP secret" | "Settings secret" => Guidance {
            what: "A credential is hardcoded as a literal value in a config `env` block (rmguard reports the key NAME only, never the value).",
            why: "Secrets in config get copied, synced, screen-shared, and backed up far more widely than a proper secret store — each copy is a place they can leak from.",
            fix: "Replace the literal with an environment reference (e.g. \"${API_KEY}\") and move the real value into your OS keychain or a secrets manager. Rotate the exposed credential.",
            reference: "OWASP MCP Top 10 · EAA-006",
        },
        "MCP command" => Guidance {
            what: "This MCP server's launch command fetches code at startup: a curl|bash-style bootstrap, or (for an enabled plugin's server) a package runner with no fixed version (`npx pkg@latest`, `npx pkg`, `uvx --from git+https://...` at the branch HEAD, `docker run image:latest`).",
            why: "Every launch fetches and runs whatever the remote endpoint or registry currently serves. A plugin pinned to a reviewed commit still runs new, unreviewed server code when its MCP launch line floats, so whoever publishes the next release (or compromises the publisher) runs code on this machine.",
            fix: "Pin the server to a vetted, versioned package (`npx pkg@1.2.3`, `uvx --from git+https://...@<commit>`, an image digest). For a plugin, ask the plugin's maintainer to pin it, or disable the plugin's server in /mcp until it is pinned; review the launch command shown below before trusting it.",
            reference: "EAA-006 · supply-chain · code.claude.com/docs/en/plugins-reference#mcpservers",
        },
        "MCP inventory" => Guidance {
            what: "Claude Code's MCP log cache (`~/.cache/claude-cli-nodejs/<project>/mcp-logs-<server>/`) shows that a server ran, but no config, enabled or disabled plugin, or claude.ai connector this scan read defines a server of that name. Only directory names are read, never the logs.",
            why: "Often benign: the server may come from a claude.ai connector Claude Code no longer lists, a plugin that was since uninstalled, a project `.mcp.json` outside the registered projects, or `--mcp-config`. It is worth knowing what code has run with agent access.",
            fix: "Run `claude mcp list` (and `/mcp` inside a session) in the projects listed to see where the server comes from. Remove its config or the plugin if it is no longer wanted; the log directory itself can be deleted.",
            reference: "code.claude.com/docs/en/mcp",
        },
        "Secret leak" => Guidance {
            what: "A secret-bearing file (a .env or a config with an inline credential) is tracked by git — i.e. committed into a repository. A tracked .env whose keys could not be read (unreadable, or a symlink rmguard does not open) is treated the same way, since nothing shows it is clean.",
            why: "A committed secret is in the repo's history for every clone, fork, and CI run; deleting it later does not remove it from history. This is the highest-confidence credential exposure.",
            fix: "Remove the file from tracking (git rm --cached), add it to .gitignore, ROTATE the credential immediately (assume it is public), and scrub history if the repo was shared.",
            reference: "committed secret",
        },
        "Secret hygiene" => Guidance {
            what: "A .env file is tracked by git or world-readable, but rmguard read it and none of its key names looks like a credential (only settings such as PORT, NODE_ENV or LOG_LEVEL, or no keys at all). rmguard reads key names only, never values.",
            why: "Nothing secret-named is committed or exposed, so this is not a leak. A tracked or world-readable .env is still where a credential tends to get added later, or hides under a neutral name.",
            fix: "Confirm no value is a credential. For a tracked .env, consider committing a .env.example with the settings and adding .env to .gitignore so a later secret is not committed by habit; for a world-readable one, chmod 600 it.",
            reference: "tracked or world-readable .env without secret-named keys",
        },
        "Git autorun" => Guidance {
            what: "A git configuration setting whose value git executes as a command — for example core.fsmonitor, which git runs every time it refreshes the index, so an ordinary `git status` or `git add` triggers it.",
            why: "It turns routine git use into code execution, with no prompt and no vulnerability required. The dangerous case is a repository you did not write supplying the config: a git directory buried inside a project is auto-discovered by git and its config is honoured, which is the class behind CVE-2026-45033.",
            fix: "Inspect the command shown below before running any git command in this directory. Remove the setting (git config --unset <key>), and consider `git config --global safe.bareRepository explicit` — noting that this blocks bare-repo auto-discovery only, not the nested non-bare case.",
            reference: "CVE-2026-45033 · git config autorun",
        },
        "Auto-run task" => Guidance {
            what: "A VS Code task in .vscode/tasks.json is configured with runOptions.runOn = \"folderOpen\", so it executes automatically when the folder is opened.",
            why: "Opening a project becomes code execution. Combined with an agent hook pointing the other way, it is the 2026 persistence pattern: removing one half leaves the other to re-establish it. A git-tracked auto-run task ships with the repository, so cloning and opening it is enough.",
            fix: "Review the exact command below. Remove the runOn setting if the task should not auto-start, and keep VS Code's task.allowAutomaticTasks at its default (off) so automatic tasks require an explicit prompt.",
            reference: "workspace auto-execution · EAA-003 (lifecycle persistence)",
        },
        "Config integrity" => Guidance {
            what: "An agent configuration file (settings.json, hooks.json, …) is writable by group or other, not just by you.",
            why: "Agent configs are executable surface: a hook entry is a shell command the agent runs on its own events. Anything on the machine that can write this file gets silent code execution as you, with no vulnerability required — just the loose permission.",
            fix: "Restrict the file to owner-only (chmod 600, or 644 if it must be world-readable but not writable), and check the parent directory's permissions too. Review the current contents for hooks you did not add.",
            reference: "least privilege · EAA-003 (lifecycle persistence)",
        },
        "Hook" => Guidance {
            what: "A hook — a shell command, HTTP endpoint, model prompt, MCP tool call or in-process module — registered in an agent's settings, a plugin, a skill or subagent file, or a status-line or file-suggestion command.",
            why: "Hooks execute silently with your privileges on every triggering event — a powerful persistence and code-execution mechanism if the settings file is tampered with or shared. Cursor, GitHub Copilot CLI and Devin CLI also run the hooks in a repository's .claude/settings.json and settings.local.json by default, and Cursor and Devin CLI those in ~/.claude/settings.json, whatever Claude Code's managed policy says.",
            fix: "Review the exact command below. Remove it if unexpected; if intended, confirm the settings file isn't world-writable or attacker-modifiable.",
            reference: "EAA-003 (lifecycle hook persistence)",
        },
        "MCP auto-approval" => Guidance {
            what: "`enableAllProjectMcpServers` is set, which auto-approves every MCP server a project defines — no per-server trust prompt.",
            why: "Opening any project then silently trusts whatever MCP servers it ships, turning a cloned repo into arbitrary tool access (a workspace-trust bypass).",
            fix: "Disable enableAllProjectMcpServers and approve project MCP servers individually.",
            reference: "EAA-011 (environment-expanded MCP activation)",
        },
        "Permissions" => Guidance {
            what: "How much the agent may do without asking: a permission mode of `bypassPermissions` (Cursor: `unrestricted`) or `auto`, `skipDangerousModePermissionPrompt` (the confirmation before bypassPermissions mode), Claude Code allow rules that pre-approve every tool of an MCP server, a shell, interpreter or package runner (`Bash(python3:*)`, `Bash(uv run:*)`), network transfer (`Bash(curl:*)`), commands that change remote or privileged state (`Bash(ssh:*)`, `Bash(sudo:*)`, `Bash(gh api:*)`, `Bash(aws iam:*)`, `Bash(rm -rf:*)`), or reads of credential and agent-state paths (the finding names what the rule reaches), and the `autoMode` block (built-in denials discarded, custom allow exceptions, trusted environment entries). Code-running, state-changing and wrapper rules are one finding per machine listing every settings file. A rule pre-approving a server no installed plugin provides, a path rule that never matches what it names, a wrapper rule (`Bash(xargs:*)`, `Bash(env:*)`, `Bash(make:*)`), and an `autoMode` block in project settings (which Claude Code ignores) are Low notes.",
            why: "Each one removes a prompt a person would otherwise answer, so the agent, or a prompt injection steering it, acts on that surface unreviewed. Claude Code's docs: in bypassPermissions mode it \"runs everything without asking\"; in auto mode \"a background classifier checks\" shell commands and network requests instead of you, and \"On entering auto mode, broad allow rules that grant arbitrary code execution are dropped: Blanket Bash(*) or PowerShell(*), Wildcarded interpreters like Bash(python*), Package-manager run commands, Agent allow rules, Monitor allow rules\". So where sessions start in auto mode (user or managed `defaultMode: auto`, not overridden by the project), interpreter and package-runner rules are suspended (Low), while `Bash(curl:*)` and state-changing rules \"stay in effect\" and are resolved \"before the classifier runs\" (Medium). In other modes `Bash(python3:*)` matches every python3 command, which is any code. Allow rules \"accept tool-name globs only after a literal mcp__<server>__ prefix\", so `mcp__x__*` approves whatever tools server x has, including one configured later under that name. A single leading slash in a path rule \"anchors at the settings source, not the filesystem root\" (in ~/.claude/settings.json, at ~/.claude/), and `Write(path)` rules never match. Setting `autoMode.soft_deny` or `hard_deny` without the `$defaults` entry discards the built-in rules, for hard_deny \"the built-in data exfiltration rule\". Rules in a repository's .claude/settings.json apply to everyone who opens it.",
            fix: "Remove the rules you do not rely on (`/permissions`, or edit the settings files listed) and prefer scoped rules such as `Bash(npm test)` or `mcp__github__get_*`. Set `autoMode.classifyAllShell: true` in ~/.claude/settings.json to have the classifier review every shell command in auto mode. Keep `\"$defaults\"` in every `autoMode` list you set. Remove `skipDangerousModePermissionPrompt` to get the bypassPermissions confirmation back. To stop the modes being used, set `permissions.disableBypassPermissionsMode` or `permissions.disableAutoMode` to \"disable\". Write absolute paths in path rules as `//path` and home paths as `~/path`.",
            reference: "code.claude.com/docs/en/permissions · /permission-modes · /auto-mode-config · OWASP Agentic Apps Top 10 (excessive agency)",
        },
        "Gateway routing" => Guidance {
            what: "An AI provider base-URL override (in agent settings or a project .env) points at a host that is not any AI provider's own API, so requests (and the API key) route through it. A provider's own API host counts as official under every base-URL variable (api.anthropic.com, api.openai.com and its regional hosts such as eu.api.openai.com, and named OpenAI- or Anthropic-compatible providers: Groq, Azure OpenAI and AI Foundry, Mistral, Gemini, NVIDIA NIM, Bedrock, DeepSeek, Z.ai, Moonshot, ...), and loopback proxies (including a client dial to 0.0.0.0 or [::], which reaches this machine) are not reported.",
            why: "Whoever controls that host sees every prompt and can capture the API key. In Claude Code project settings this is the exfiltration vector behind CVE-2026-21852. A .env applies only to tools that load it (Gemini CLI loads project .env files itself; other agents need direnv, an IDE or a dotenv loader), and a git-tracked .env is the repository choosing the host for everyone. A committed per-mode file (.env.development, .env.production) is the application's own build config, which no coding agent loads by default, so it is advisory. A legitimate proxy looks identical, so this needs a human check.",
            fix: "Confirm the host is a gateway you deliberately configured and trust. If it is not, remove the override, and rotate the API key if a tool already sent requests there.",
            reference: "EAA-007 · CVE-2026-21852",
        },
        "Credential" => Guidance {
            what: "An at-rest AI-service credential file is world-readable, or an agent config file stores an API key inline (rmguard checks names and permissions only, never the values).",
            why: "Any local user or process can read a world-readable token; an inline key travels with the config into backups, sync and version control.",
            fix: "Tighten permissions to owner-only (chmod 600). Move inline keys to the tool's secrets mechanism (Continue: ${{ secrets.NAME }}; Aider: environment variables or .env) and rotate them.",
            reference: "least privilege",
        },
        "Secret exposure" => Guidance {
            what: "A .env file in an agent project root is world-readable and holds a secret-named key, or its keys could not be read (unreadable, or a symlink rmguard does not open), so nothing shows it is clean.",
            why: ".env files hold API keys and DB credentials; world-readable means any local user or process can read them.",
            fix: "chmod 600 the file. Rotate anything in it if the machine is multi-user.",
            reference: "least privilege",
        },
        "Transcript exposure" => Guidance {
            what: "An agent transcript or state store has files other users can read (mode o+r, reached through directories with o+x): conversation transcripts, command history, shell snapshots and session environment, backups of ~/.claude.json, file-edit history, plans, tasks, paste cache, agent memory, or metadata (telemetry, feature flags, usage data). Or ~/.claude.json itself, which holds the account identifier and the list of every project path, is readable by other users or by its group. Claude Code's stores are one finding with a table of stores, graded by the most sensitive one; the evidence also counts the other accounts with a login shell. rmguard opens none of these files except session-env and shell-snapshots, whose exported variable NAMES it reads (the first 64 KiB of at most 50 readable files, never a value): PATH and shell state only is Low, other names Medium, a secret-shaped name High. When a directory above the store (usually HOME at 0700) cannot be traversed by others, the finding is Low.",
            why: "Transcripts and snapshots routinely contain pasted credentials, source code, environment values and internal details, a rich target that any local user can read; the account file maps the machine's projects and identifies the account.",
            fix: "Restrict the store's permissions to owner-only (chmod -R go-rwx ~/.claude, chmod 600 ~/.claude.json*), or make HOME 0700 so nothing under it is reachable. Consider pruning old transcripts and snapshots you no longer need.",
            reference: "EAA-005 (agent-state collection)",
        },
        "Plugin marketplace" => Guidance {
            what: "A third-party plugin marketplace is configured with auto-update on, so it pulls new remote code automatically.",
            why: "Auto-update means today's vetted plugin can become tomorrow's malicious one with no review step — the rug-pull surface for hot-loaded agent code.",
            fix: "Turn off auto-update for third-party sources and update deliberately after reviewing changes, or remove the marketplace if unused.",
            reference: "EAA-009 (remote plugin hot-load)",
        },
        "SSH key" => Guidance {
            what: "Private SSH keys on disk have no passphrase (one finding per home, listing every such key; each key is still its own row in ssh_keys).",
            why: "If the key file is copied or the machine is compromised, the key is immediately usable — there's no second factor protecting it.",
            fix: "Add a passphrase (ssh-keygen -p -f <key>) and use an agent to cache it. Prefer hardware-backed keys where possible.",
            reference: "defense in depth",
        },
        "Rules file" => Guidance {
            what: "An agent instruction/memory file (CLAUDE.md, .cursorrules, and similar) contains a pattern that could steer the agent into dangerous behavior — e.g. an instruction to pipe a download into a shell.",
            why: "Agents follow these files as authoritative instructions, so a poisoned rules file is prompt injection that persists across every session.",
            fix: "Review the matched pattern shown below and the surrounding instruction; remove anything that directs the agent to run untrusted code or exfiltrate data.",
            reference: "EAA-004 (instruction/memory poisoning)",
        },
        "Registry" => Guidance {
            what: "An MCP server package is either one edit away from a registered name (possible typosquat) or is deprecated in the official MCP registry.",
            why: "A typosquat can substitute malicious code for the package you meant; a deprecated package no longer receives security fixes.",
            fix: "Verify you have the exact intended package name from the official registry, and replace deprecated servers with maintained alternatives.",
            reference: "official MCP registry",
        },
        "Agent identity" => Guidance {
            what: "Agents authenticate with static, long-lived API keys — unbound bearer tokens rather than short-lived, scoped credentials.",
            why: "A leaked static key is valid until someone notices and rotates it, and carries the full scope of the account. It's the weakest link if any of the above exposures hit.",
            fix: "Move toward OAuth (refreshable/scoped) or SPIFFE workload identity (short-lived SVIDs) where the tooling supports it; at minimum rotate keys regularly and scope them tightly.",
            reference: "OWASP ASI03 (identity & authentication)",
        },
        "Persistence" => Guidance {
            what: "A file that runs code without being invoked: a Python `.pth` whose line begins with `import` or a `sitecustomize.py` in site-packages (executed on every interpreter start), a JavaScript loader staged inside a project's .vscode/ or .claude/ directory, or a path a known worm leaves behind (the tensorlake hostage-token monitor, the EtherDuck launch agents).",
            why: "This is how the 2026 package compromises survive remediation: litellm 1.107.0's implant kept running after `pip uninstall` and inside every MCP server launched with that interpreter, and the ChainDrop loader is re-planted by the hook/task pair whenever one half is removed. The tensorlake monitor wipes the home directory if the stolen GitHub token is revoked, so order of cleanup matters.",
            fix: "Read the file shown below before touching anything. A startup hook no installed distribution claims should be removed along with whatever dropped it; for the gh-token-monitor artifacts, remove the monitor service BEFORE rotating the GitHub token. Reinstall the interpreter environment if an unclaimed hook ran.",
            reference: "EAA-003 (lifecycle persistence) · litellm 1.107.0 · tensorlake 0.5.144",
        },
        "Binary planting" => Guidance {
            what: "A regular executable named like a tool agents spawn by bare name (git, npx, node, python, ...) sits in a project root or an IDE/agent directory.",
            why: "Agents and IDEs resolve such tools through the search path; on Windows the working directory comes first, and on POSIX a PATH containing `.` does the same. A git.exe committed into a repository ran on project open in Claude Desktop (CVE-2026-88066), Cursor (CVE-2026-63093) and Kiro — no prompt injection or model involved. No legitimate repository ships git.exe at its root.",
            fix: "Inspect and remove the file. If the repository is shared, treat the commit that added it as hostile. Keep `.` out of PATH.",
            reference: "CVE-2026-88066 · CVE-2026-63093 · uncontrolled search path",
        },
        "Repo symlink" => Guidance {
            what: "A git-tracked symbolic link in a project resolves to a path outside that repository (a shell rc file, ~/.ssh, an agent config directory, /etc).",
            why: "An agent asked to write a project file follows the link, so an approval that looked like an in-project edit lands in authorized_keys or a shell profile instead. Wiz's GhostApproval showed the shape across six agents; Claude Code's write-time re-resolution gap is CVE-2026-103435.",
            fix: "Replace the symlink with a real file or remove it, and review who committed it. Do not let an agent write through it in the meantime.",
            reference: "CVE-2026-103435 · GhostApproval · write-time symlink following",
        },
        "Plugin pin" => Guidance {
            what: "A Claude Code plugin marketplace clone or plugin manifest holds a \"pin\" that is not a commit: a git ref whose name is a full 40- or 64-character hex string (a branch or tag impersonating a commit ID), HEAD checked out on such a branch, FETCH_HEAD recording a fetched branch with a commit-shaped name, or a manifest whose sha or gitCommitSha field holds a branch or tag name, an abbreviated commit ID (resolved by name, so a same-named branch wins) or nothing at all, or whose ref field holds a commit ID with no sha.",
            why: "Plugin4Shell (CVE-2026-86063): plugin install and update checked out the pinned commit by name, and a branch named with the same hex string won. So whoever controlled the plugin's upstream repository could swap reviewed code for their own while the pin still read intact. Git never creates a ref named like a commit, so one on disk is either an exploitation attempt or a pin that floats with a branch.",
            fix: "Update Claude Code to 2.1.179 or later (Codex to 0.146.0 or later). Remove and reinstall the affected marketplace or plugin, and compare the installed files against the pinned commit before trusting them. In a plugin entry, put the 40-hex commit in `sha` and keep branch names in `ref`. A marketplace source has no `sha` field (its `ref` takes a branch or tag), so pin a marketplace by a tag you control.",
            reference: "CVE-2026-86063 · Plugin4Shell (Air Security) · EAA-009",
        },
        "Skill symlink" => Guidance {
            what: "A skill manifest (SKILL.md), command file or bundled script is a symbolic link (or sits under a symlinked directory) whose real path is outside its skill directory, project or plugin. rmguard resolves every hop and never reads a target that is a credential, key, .env, shell-rc or history, agent-config or system path, or a file that is not a skill-file type; a repository's or plugin's link that leaves it is inventoried without being read. Links that are read (inside the repository or plugin, into your own skill areas including other agents' skills/ and commands/ directories, or your own links into a dotfiles checkout) stay in the inventory and are not reported. Your own link (outside a repository or plugin) to a skill directory or a .md file under a system path or agent config is Low; a target named like a credential, key, .env or shell-rc file is High.",
            why: "Claude Code loads the link's target as the skill. A SKILL.md that points at ~/.ssh or a settings file puts that file into the model's context. An edit the agent makes to the skill writes through the link: the write-time symlink-following class behind CVE-2026-103435. A link into a dotfiles checkout is common and benign.",
            fix: "If you did not create the link, replace it with a regular file or remove the skill. Keep skill bundles self-contained; dotfile managers can copy instead of linking.",
            reference: "CVE-2026-103435 · write-time symlink following · AST02",
        },
        "Skill command" => Guidance {
            what: "A skill or custom command contains dynamic context injection: an inline !`command` placeholder or a ```! block. Claude Code runs it in your shell before the skill text reaches the model, every time the skill is invoked.",
            why: "The command runs with your privileges on invocation, and Claude can invoke a skill on its own unless the skill sets disable-model-invocation. So a third-party plugin or a repository can ship code that runs when its skill loads, with no tool-approval prompt. Read-only context commands (git status, gh pr view) are the documented use; a committed project skill whose commands are all of that kind stays in the inventory and is not reported. That list is strict: git with the subcommand first and no option before it, git branch with list-only flags, no --no-index, --output, --ext-diff or --textconv, no path argument outside the repository, date with at most a +FORMAT, and no pipes, redirection, quoting or substitution. Any dangerous-pattern match is named, as it is for a hook: data sent to the network (printenv | nc, an encoded upload) is High wherever the skill comes from, and a medium-only match (printenv NODE_ENV) in your own skills is a Low advisory.",
            fix: "Read the command shown below. Remove the skill if you did not expect it. To stop all skills running inline shell, set \"disableSkillShellExecution\": true in user or managed settings (a project's own .claude/settings.json or settings.local.json setting it silences that project's skills).",
            reference: "Claude Code skills: dynamic context injection · AST02 · EAA-003",
        },
        "Skill grant" => Guidance {
            what: "A skill's or command's allowed-tools frontmatter pre-approves unrestricted Bash (Bash or Bash(*)). Every shell command Claude runs during the invoking turn then executes without a permission prompt.",
            why: "The grant opts the skill out of human review of the shell. Claude Code does not gate this field on workspace trust, so the third-party plugin that ships the skill decides it for you. A project skill is reported only when it is not committed (untracked or ignored): it was put there locally, by you or by a tool, and nobody reviewed it with the repository. Scoped grants such as Bash(git diff:*) are the documented alternative.",
            fix: "Confirm you meant to pre-approve every shell command for this skill. Narrow the grant to the commands the skill needs, or remove the skill. Organizations can set allowManagedPermissionRulesOnly so allowed-tools is ignored.",
            reference: "Claude Code skills: allowed-tools · AST02 · EAA-002 (permissive execution)",
        },
        "Agent redirection" => Guidance {
            what: "A project .env file sets a variable that relocates an AI agent's home directory (CLAUDE_CONFIG_DIR, CODEX_HOME, GEMINI_CLI_HOME, CURSOR_CONFIG_DIR, KIRO_HOME) or reroutes its traffic (HTTPS_PROXY to a non-loopback host, ANTHROPIC_CUSTOM_HEADERS).",
            why: "An agent started with a relocated home loads settings, hooks and MCP servers from that directory. When the directory sits inside the repository, the repository author controls them (Gemini CLI CVE-2026-13745: an untrusted .env overrode GEMINI_CLI_HOME past the folder-trust prompt). A home outside the repository (a devcontainer home such as /home/node/.claude) loads nothing the repository controls and is inventory only, unless it is a shared temporary directory (/tmp, /var/tmp, /dev/shm) that another local user could create first (Low). A home that could not be resolved (`${PWD}/.claude-cfg`, `$PWD`) may be the repository itself, so a committed one is Medium. A proxy sees all traffic. Gemini CLI and aider load a project's .env themselves; other agents only see these values when something exports them (direnv, an IDE, a dotenv loader). Per-mode files (.env.local, .env.development, .env.production, .env.test) are application config that no coding agent loads by default, so they are advisory even when committed.",
            fix: "Remove the variable unless you put it there. Never commit agent-home or proxy overrides; set them in your own shell profile. Upgrade Gemini CLI to 0.39.1 or later.",
            reference: "CVE-2026-13745 · EAA-006 · EAA-007",
        },
        "Helper command" => Guidance {
            what: "A Claude Code settings file names a credential or telemetry helper (apiKeyHelper, awsAuthRefresh, awsCredentialExport, gcpAuthRefresh, otelHeadersHelper). This is a shell command Claude Code runs on its own to fetch credentials or headers.",
            why: "Like a hook, it runs silently with your privileges, and its output becomes the agent's credential. In a repository's settings file the repository author chooses the command. In your own or managed settings it is a normal enterprise setup and is only reported when the command matches a dangerous pattern. Printing a variable or decoding a stored key is what a helper does; piping or substituting data into a network sender (nc, curl, wget, a python/node/ruby HTTP request) is not, and is dangerous from every scope.",
            fix: "Review the command below (only its shape is shown: program, flags, paths and hosts; every other argument is redacted). Remove a helper that arrived with a repository; keep credential helpers in user or managed settings, and have them read the key from a secret store rather than echo it.",
            reference: "EAA-003 (lifecycle hook persistence) · OWASP ASI03",
        },
        "Login gateway" => Guidance {
            what: "forceLoginGatewayUrl in your user settings sends Claude Code's /login to the Claude apps gateway at the host shown.",
            why: "A gateway you sign in to holds the upstream credential, sees every prompt, and can push managed settings (including hooks and env) that run commands on this machine. Anthropic documents user-settings gateways for machines without managed settings, so this is expected where your organization runs one.",
            fix: "Confirm your organization operates this gateway. If not, remove forceLoginGatewayUrl and forceLoginMethod from ~/.claude/settings.json and sign in again.",
            reference: "Claude apps gateway · EAA-007",
        },
        "Extension code" => Guidance {
            what: "An IDE extension that presents itself as declarative carries code: a theme (colour or icon theme) with a main/browser entry point and no contributed commands or settings to explain it, or a declarative extension (themes, snippets, keymaps, a language pack) that ships a native .node addon. The entry-point check applies to theme extensions only.",
            why: "Pure themes are JSON and run nothing. GlassWorm-linked \"theme\" extensions shipped encrypted JavaScript, and the GlassWorm Zig dropper loaded a native addon to install a second-stage extension into every IDE. Some popular themes legitimately add commands or settings code, so this is advisory.",
            fix: "Check the publisher and the marketplace page, and uninstall the extension if the code is not explained. Prefer themes with no entry point.",
            reference: "GlassWorm theme loaders (Socket) · GlassWorm Zig dropper (Aikido) · OWASP ASI04",
        },
        "Ollama exposure" => Guidance {
            what: "OLLAMA_HOST tells the Ollama server where to listen (and clients where to connect). It is set to every interface (0.0.0.0, [::], or a bare :port) in a shell profile, .env, systemd unit or launchd job, or to a non-loopback address in the Ollama server's own unit or job. A remote address in a profile or .env is a client target and is not reported. A wildcard in a unit or job that does not itself run ollama (an Open WebUI container, a client agent) reaches only that unit's processes, so it is Low: it matters only if the unit starts `ollama serve` some way the scanner cannot see.",
            why: "Ollama's API has no authentication. Bound beyond 127.0.0.1, anyone who can reach the port can run, pull, push and delete models.",
            fix: "Bind to 127.0.0.1 (the default) and reach it remotely through an authenticating reverse proxy or an SSH tunnel. Inside a container, publish the port on 127.0.0.1 only.",
            reference: "Ollama FAQ (OLLAMA_HOST) · unauthenticated local API",
        },
        "Network listener" => Guidance {
            what: "A process started from one of your projects listens on a non-loopback address (every interface, `::`, or one LAN/VPN address). High when it hands out a shell or a terminal: a tmux or screen child, a shell child, a PTY master it holds, or a known web-terminal program (ttyd, gotty, wetty, shellinabox, webssh, sshwifty). Critical when the same directory also holds a world-readable .env with secret-named keys, which is where such a bridge keeps its logins. Low for any other program but a common development server. Listeners on loopback, and listeners outside your projects, are inventory only.",
            why: "Anyone on the network who gets past the listener's login gets a shell as you: your files, your keys, and the tmux server your coding agents run in (a client of the default tmux server can attach to every agent session, read it and type into it). A token in a world-readable file can be read by every local user and process, so the login is only as strong as that file's mode.",
            fix: "Bind the listener to 127.0.0.1 or a VPN interface (Tailscale, WireGuard) and reach it through SSH or the VPN. Move its credentials out of the world-readable file (chmod 600, or a secret store) and rotate them. Run the bridge on its own tmux server (`tmux -L bridge new -A -s <name>`) so it cannot attach to the agents' sessions, and stop it when you are not using it.",
            reference: "rmguard listeners scanner (Linux /proc) · docs/THREAT-CATALOG.md",
        },
        "Toxic Flow" => Guidance {
            what: "The connected agent surface holds BOTH a sensitive-data source (filesystem/database/environment/source-control) and an exfiltration sink (network/communication) at the same time. High when an active MCP server, a successful probe or a claude.ai connector supplies at least one of the two; Medium (\"based on skill-file mentions only\") when both rest on keywords in loading skill files, each mentioned by at least 3 skills; below that, no finding.",
            why: "Each capability is individually authorized and benign, but together they complete the \"lethal trifecta\": one prompt injection can read private data and send it out. No single MCP client sees this composition.",
            fix: "Separate the source and sink so no single agent context has both, or add human approval on the sink. Review why this agent needs both at once.",
            reference: "lethal trifecta / toxic flow",
        },
        _ => Guidance {
            what: "An actionable security finding on this machine.",
            why: "See the title and location for specifics.",
            fix: "Review the offending item and remediate per your team's policy.",
            reference: "",
        },
    }
}

/// A path argument that may leave the repository: absolute (`/etc/passwd`, `/dev/null`),
/// home-relative (`~/.ssh/id_rsa`, `~user`), or with a `..` path component (`../x`,
/// `a/../../b`). A revision is not a path: `HEAD~3`, `main..HEAD` and
/// `origin/main...HEAD` keep their `~` and `..` inside a component.
fn leaves_repository(arg: &str) -> bool {
    arg.starts_with('/') || arg.starts_with('~') || arg.contains("~/") || arg.split('/').any(|c| c == "..")
}

/// Flags of `git branch` that only list. Anything else (-d/-D/--delete, -m/-M/--move,
/// -c/-C/--copy, -f/--force, -u/--set-upstream-to, --unset-upstream, --edit-description,
/// -t/--track) changes refs.
const GIT_BRANCH_LIST_FLAGS: &[&str] = &[
    "-a",
    "--all",
    "-r",
    "--remotes",
    "-l",
    "--list",
    "-v",
    "-vv",
    "--verbose",
    "--show-current",
    "--contains",
    "--no-contains",
    "--merged",
    "--no-merged",
    "--points-at",
    "--sort",
    "--format",
    "--color",
    "--no-color",
    "--column",
    "--no-column",
    "-i",
    "--ignore-case",
    "--abbrev",
    "--no-abbrev",
    "--omit-empty",
];
/// `git branch` flags whose (separate) next word is their value, not a branch to create.
const GIT_BRANCH_VALUE_FLAGS: &[&str] = &["--contains", "--no-contains", "--merged", "--no-merged", "--points-at"];
/// Flags that make a reading git subcommand write a file, read one outside the
/// repository, or run a configured program: `--no-index` (diff two arbitrary files:
/// `git diff --no-index ~/.ssh/id_rsa /dev/null` prints the key), `--output` (writes),
/// `--ext-diff` / `--textconv` (run configured drivers), `-O<orderfile>` (reads a file).
const GIT_READ_DENIED_FLAGS: &[&str] = &["--no-index", "--output", "--ext-diff", "--textconv", "-O"];

fn git_read_only(sub: &str, args: &[&str]) -> bool {
    let flag_name = |a: &str| a.split_once('=').map_or(a, |(n, _)| n).to_string();
    // Every argument: a path that leaves the repository, as a word or a flag's value.
    if args
        .iter()
        .any(|a| leaves_repository(a) || a.split_once('=').is_some_and(|(_, v)| leaves_repository(v)))
    {
        return false;
    }
    match sub {
        "status" | "diff" | "log" | "show" | "rev-parse" | "describe" | "ls-files" | "shortlog" => !args
            .iter()
            .any(|a| GIT_READ_DENIED_FLAGS.iter().any(|d| flag_name(a).starts_with(d))),
        // List-only flags; a positional word is a branch to create unless --list is
        // given or it is the value of --contains and the like.
        "branch" => {
            let listing = args.iter().any(|a| matches!(*a, "-l" | "--list"));
            let mut value_next = false;
            for a in args {
                if value_next && !a.starts_with('-') {
                    value_next = false;
                    continue;
                }
                value_next = false;
                if a.starts_with('-') {
                    let name = flag_name(a);
                    if !GIT_BRANCH_LIST_FLAGS.contains(&name.as_str()) {
                        return false;
                    }
                    value_next = !a.contains('=') && GIT_BRANCH_VALUE_FLAGS.contains(&name.as_str());
                } else if !listing {
                    return false;
                }
            }
            true
        }
        _ => false,
    }
}

/// A read-only context command, the documented use of dynamic context. Strict: one
/// simple command (no pipe, redirection, separator, substitution, quoting, glob or
/// escape), whose program and arguments only read inside the repository:
/// - `git status|diff|log|show|rev-parse|describe|ls-files|shortlog` with the subcommand
///   first (no `-C`, `-c`, `--git-dir`, `--work-tree`, `--exec-path`, `--config-env`,
///   `-p`/`--paginate`/`--no-pager` or any other option before it) and without
///   `--no-index`, `--output`, `--ext-diff` or `--textconv`; `git branch` with list-only
///   flags (see [`GIT_BRANCH_LIST_FLAGS`]);
/// - `gh pr|issue|repo|run view|list|diff|status|checks`;
/// - `date` with no argument or a single `+FORMAT`, `ls`, `pwd` and `whoami` with no
///   arguments, `uname` with short flags only;
/// - and no path argument that leaves the repository (see [`leaves_repository`]).
pub fn is_read_only_context_command(cmd: &str) -> bool {
    if cmd.contains([
        '|', '>', '<', ';', '&', '$', '`', '(', ')', '\n', '\r', '\\', '"', '\'', '*', '?', '[', ']', '{', '}', '!',
        '#',
    ]) {
        return false;
    }
    let words: Vec<&str> = cmd.split_whitespace().collect();
    let Some((prog, args)) = words.split_first() else {
        return false;
    };
    match *prog {
        "git" => {
            // The subcommand must come first: any option before it can redirect git to
            // another repository or work tree, set config (and with it a program to run),
            // or start a pager.
            let Some((sub, rest)) = args.split_first() else {
                return false;
            };
            !sub.starts_with('-') && git_read_only(sub, rest)
        }
        "gh" => {
            let (Some(sub), Some(verb)) = (args.first(), args.get(1)) else {
                return false;
            };
            matches!(*sub, "pr" | "issue" | "repo" | "run")
                && matches!(*verb, "view" | "list" | "diff" | "status" | "checks")
                && !args
                    .iter()
                    .any(|a| leaves_repository(a) || a.split_once('=').is_some_and(|(_, v)| leaves_repository(v)))
        }
        // `date -s` sets the clock; `+FORMAT` only formats.
        "date" => args.is_empty() || (args.len() == 1 && args[0].starts_with('+')),
        "ls" | "pwd" | "whoami" => args.is_empty(),
        "uname" => args
            .iter()
            .all(|a| a.len() >= 2 && a.starts_with('-') && a[1..].chars().all(|c| "asnrvmpio".contains(c))),
        _ => false,
    }
}

/// Collect and rank the actionable findings in a scan. Highest severity first.
/// This is the risk-first view that HTML/fleet reports lead with.
/// True when hook `command` names the agent-bin file at `path` (`/home/u/.claude/bin/x`)
/// by its full path or as `~/.claude/bin/x`, `$HOME/.claude/bin/x`, `${HOME}/.claude/bin/x`.
fn references_bin(command: &str, path: &str) -> bool {
    let Some(idx) = path.rfind("/.claude/bin/") else {
        return command.contains(path);
    };
    let tail = &path[idx..];
    let boundary = |s: &str, needle: &str| {
        s.match_indices(needle).any(|(i, _)| {
            s[i + needle.len()..]
                .chars()
                .next()
                .is_none_or(|c| !(c.is_alphanumeric() || matches!(c, '-' | '_' | '.')))
        })
    };
    boundary(command, path)
        || ["~", "$HOME", "${HOME}"]
            .iter()
            .any(|h| boundary(command, &format!("{h}{tail}")))
}

/// A Claude Code MCP server name as it appears in a tool name (`mcp__<server>__<tool>`),
/// folded for comparison: lowercase, every character other than a letter or digit as
/// `_`. Claude Code writes plugin servers as `plugin_<plugin>_<server>` and claude.ai
/// connectors as `claude_ai_<Name>`; its MCP log directories use `-` for the same.
fn mcp_tool_segment(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// Every server name the report's MCP inventory knows, folded by [`mcp_tool_segment`]:
/// configured servers (plugin servers also as `plugin_<plugin>_<server>`) and the servers
/// Claude Code's MCP logs show have run. None when the MCP scanner was skipped, so no
/// server can be called unconfigured.
fn known_mcp_segments(report: &ScanReport) -> Option<BTreeSet<String>> {
    if report.diagnostics.iter().any(|d| d.scanner == "mcp" && d.skipped) {
        return None;
    }
    let mut out = BTreeSet::new();
    for c in &report.mcp_configs {
        for n in &c.server_names {
            out.insert(mcp_tool_segment(n));
        }
        for s in &c.servers {
            out.insert(mcp_tool_segment(&s.name));
            if let Some(p) = &s.plugin {
                let plugin = p.rsplit_once('@').map(|(n, _)| n).unwrap_or(p);
                out.insert(mcp_tool_segment(&format!("plugin_{plugin}_{}", s.name)));
            }
        }
    }
    for o in &report.mcp_observed_servers {
        out.insert(mcp_tool_segment(&o.name));
    }
    Some(out)
}

/// Rules listed in a title or evidence: the first `cap`, then a count.
/// The directory an SSH key finding is grouped under: the `.ssh` directory of the home
/// the key lives in (`<home>/.ssh`, the directory above the last `/.ssh/` component of
/// the path), else the key's own directory. Keys under `~/.ssh/work/` group with `~/.ssh`.
fn ssh_key_group(path: &str) -> &str {
    match path.rfind("/.ssh/") {
        Some(i) => &path[..i + "/.ssh".len()],
        None => path
            .rsplit_once('/')
            .map(|(d, _)| d)
            .filter(|d| !d.is_empty())
            .unwrap_or(path),
    }
}

/// The SSH-key findings: one per (class, home), so N keys without a passphrase in one
/// home are one High that names them all, never N Highs. A single key keeps the old
/// shape (title names its type, location is the key). Keys are listed in path order,
/// relative to the group's directory, at most 20 (`(+N more)` after), so the finding is
/// independent of the order the scanner found the keys in. No-passphrase is the only
/// per-key SSH class today; another class (a key other users can read, say) would be
/// one more entry in `classes` and merge the same way.
fn ssh_key_findings(keys: &[crate::models::SshKey]) -> Vec<Finding> {
    type Pick = fn(&crate::models::SshKey) -> bool;
    let classes: [(Pick, Severity, &str, &str); 1] = [(
        |k| k.has_passphrase == PassphraseStatus::NoPassphrase,
        Severity::High,
        "key has no passphrase",
        "SSH private keys without a passphrase",
    )];
    let mut out = Vec::new();
    for (pick, severity, one, many) in classes {
        let mut groups: std::collections::BTreeMap<&str, Vec<&crate::models::SshKey>> = Default::default();
        for k in keys.iter().filter(|k| pick(k)) {
            groups.entry(ssh_key_group(&k.path)).or_default().push(k);
        }
        for (dir, mut ks) in groups {
            ks.sort_by(|a, b| a.path.cmp(&b.path));
            ks.dedup_by(|a, b| a.path == b.path);
            if let [k] = ks.as_slice() {
                out.push(Finding {
                    severity,
                    category: "SSH key".into(),
                    title: format!("{} {one}", k.key_type),
                    location: k.path.clone(),
                    evidence: None,
                });
                continue;
            }
            let listed: Vec<String> = ks
                .iter()
                .map(|k| {
                    let rel = k
                        .path
                        .strip_prefix(dir)
                        .and_then(|r| r.strip_prefix('/'))
                        .unwrap_or(&k.path);
                    format!("{rel} ({})", k.key_type)
                })
                .collect();
            out.push(Finding {
                severity,
                category: "SSH key".into(),
                title: format!("{} {many}", ks.len()),
                location: dir.to_string(),
                evidence: Some(list_rules(&listed.iter().map(String::as_str).collect::<Vec<_>>(), 20)),
            });
        }
    }
    out
}

fn list_rules(rules: &[&str], cap: usize) -> String {
    let mut s = rules.iter().take(cap).copied().collect::<Vec<_>>().join(", ");
    if rules.len() > cap {
        s.push_str(&format!(" (+{} more)", rules.len() - cap));
    }
    s
}

/// The project directory of a project or local Claude Code settings file
/// (`<dir>/.claude/settings.json`, `<dir>/.claude/settings.local.json`).
fn settings_project_dir(path: &str) -> Option<&str> {
    path.strip_suffix("/.claude/settings.local.json")
        .or_else(|| path.strip_suffix("/.claude/settings.json"))
}

/// A user or managed Claude Code settings file sets
/// `permissions.disableBypassPermissionsMode: "disable"` ("To prevent `bypassPermissions`
/// ... mode from being used ... in any settings file", code.claude.com/docs/en/permissions.md):
/// bypass mode is off in every project. A project or local file's value applies to that
/// project only and is not counted here.
pub fn bypass_disabled_by_policy(report: &ScanReport) -> bool {
    report.agent_settings.iter().any(|s| {
        s.framework == "claude-code" && matches!(s.source.as_str(), "user-global" | "managed") && s.disable_bypass_mode
    })
}

/// Whether sessions that read settings file `s` start in auto mode, from the settings
/// files this scan read, as code.claude.com/docs/en/permission-modes.md (fetched
/// 2026-10-24) describes it: "When more than one settings file sets
/// `permissions.defaultMode`, settings precedence decides, so a project or managed value
/// outranks `~/.claude/settings.json`", and "If you set `"auto"` in
/// `.claude/settings.json` or `.claude/settings.local.json`, the value doesn't take
/// effect, and Claude Code then uses the built-in default rather than a `defaultMode`
/// from `~/.claude/settings.json`. If you set `"bypassPermissions"` in those two files,
/// it doesn't take effect either, and the session starts in Manual mode." The order is
/// therefore managed, then the project's local file, then its shared file, then user
/// settings. Auto counts only when a managed or user file selects it: the built-in
/// default depends on the Claude Code version and how it is run ("`claude -p` or the
/// Agent SDK" start in `default`), so it is not assumed. "Any settings file sets
/// `disableAutoMode` to `"disable"`" removes auto mode.
fn starts_in_auto(report: &ScanReport, s: &crate::models::AgentSettings) -> bool {
    let claude: Vec<&crate::models::AgentSettings> = report
        .agent_settings
        .iter()
        .filter(|x| x.framework == "claude-code")
        .collect();
    let project = matches!(s.source.as_str(), "local" | "project")
        .then(|| settings_project_dir(&s.path))
        .flatten();
    let same_project = |x: &&&crate::models::AgentSettings| {
        project.is_some()
            && matches!(x.source.as_str(), "local" | "project")
            && settings_project_dir(&x.path) == project
    };
    let applies =
        |x: &&&crate::models::AgentSettings| matches!(x.source.as_str(), "managed" | "user-global") || same_project(x);
    if claude.iter().filter(applies).any(|x| x.disable_auto_mode) {
        return false;
    }
    if let Some(m) = claude
        .iter()
        .find(|x| x.source == "managed" && x.permission_mode.is_some())
    {
        return m.permission_mode.as_deref() == Some("auto");
    }
    // A project or local value decides the mode; there `auto` falls to the built-in
    // default and `bypassPermissions` to Manual, neither of which is counted as auto.
    if claude.iter().filter(same_project).any(|x| x.permission_mode.is_some()) {
        return false;
    }
    claude
        .iter()
        .find(|x| x.source == "user-global")
        .and_then(|x| x.permission_mode.as_deref())
        == Some("auto")
}

/// `autoMode.classifyAllShell: true` in user or managed settings, the scopes the
/// classifier reads `autoMode` from: "suspend every Bash and PowerShell allow rule while
/// auto mode is active" (code.claude.com/docs/en/auto-mode-config.md, fetched 2026-10-24).
fn classify_all_shell(report: &ScanReport) -> bool {
    report.agent_settings.iter().any(|s| {
        s.framework == "claude-code"
            && matches!(s.source.as_str(), "managed" | "user-global")
            && s.auto_mode.as_ref().and_then(|a| a.classify_all_shell) == Some(true)
    })
}

/// `a, b and c`.
fn and_list(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// One machine-level group of allow rules of one grade: the files and their rules.
#[derive(Default)]
struct RuleGroup<'a> {
    files: Vec<(&'a str, &'a str, Vec<&'a str>)>,
}

impl<'a> RuleGroup<'a> {
    fn add(&mut self, path: &'a str, source: &'a str, rule: &'a str) {
        match self.files.iter_mut().find(|(p, _, _)| *p == path) {
            Some((_, _, rules)) => rules.push(rule),
            None => self.files.push((path, source, vec![rule])),
        }
    }
    fn rules(&self) -> usize {
        self.files.iter().map(|(_, _, r)| r.len()).sum()
    }
    /// "3 project settings files", "1 settings file", "user settings and 2 project
    /// settings files".
    fn files_noun(&self) -> String {
        let n = self.files.len();
        let project = self
            .files
            .iter()
            .filter(|(_, s, _)| matches!(*s, "local" | "project"))
            .count();
        let s = if n == 1 { "" } else { "s" };
        if project == n {
            format!("{n} project settings file{s}")
        } else {
            format!("{n} settings file{s}")
        }
    }
    fn location(&self) -> String {
        match self.files.as_slice() {
            [(p, _, _)] => p.to_string(),
            _ => format!(
                "{} Claude Code settings files (listed in the evidence)",
                self.files.len()
            ),
        }
    }
    /// `path: r1, r2; path2: r3`, at most 30 files and 8 rules per file.
    fn evidence(&self) -> String {
        let mut s = self
            .files
            .iter()
            .take(30)
            .map(|(p, _, r)| format!("{p}: {}", list_rules(r, 8)))
            .collect::<Vec<_>>()
            .join("; ");
        if self.files.len() > 30 {
            s.push_str(&format!(" (+{} more files)", self.files.len() - 30));
        }
        s
    }
}

/// Claude Code permission posture (code.claude.com/docs/en/permissions.md,
/// /permission-modes.md, /auto-mode-config.md and /settings-reference.md, fetched
/// 2026-10-24):
///
/// - `permissions.defaultMode: "auto"` in user settings: Low. Auto mode has a background
///   classifier review shell commands and network requests instead of a prompt, and it
///   is the built-in starting mode from v2.1.283, so it is reported as the posture it
///   is, not as an alarm. `auto` (like `bypassPermissions`) does not take effect from
///   project or local settings, and `dontAsk` denies whatever would prompt: neither is
///   graded.
/// - `skipDangerousModePermissionPrompt: true` (honoured in user, local and managed
///   settings; "An untrusted repository can't skip the dialog for you"): Medium, the
///   confirmation before `bypassPermissions` is off; Critical when user or managed
///   settings also start sessions in `bypassPermissions`. Managed files are the
///   organization's policy and stay inventory.
/// - Allow rules (see `scanners::agent_settings::classify_allow_rule`), per file: a whole
///   MCP server pre-approved (Medium; High from a repository's file; Low when every such
///   server is a disabled plugin's or none is installed), reads of credential or
///   agent-state paths and edits of credential paths (High, naming what the rule
///   reaches), and path rules that never match what they name (Low).
/// - Allow rules, one finding per machine per grade, listing the files: code-running
///   rules ([`code_exec_findings`]), rules that change remote or privileged state
///   (Medium; High from a repository's file), and wrapper rules (Low).
/// - The `autoMode` block ([`auto_mode_findings`]).
fn collect_permission_findings(report: &ScanReport, f: &mut Vec<Finding>) {
    use crate::scanners::agent_settings::{
        CODE_EXEC_NETWORK, RULE_CODE_EXEC, RULE_CREDENTIAL_EDIT, RULE_CREDENTIAL_READ, RULE_DESTRUCTIVE,
        RULE_INERT_PATH, RULE_MCP_SERVER, RULE_WRAPPER,
    };
    use std::collections::BTreeMap;
    let claude = || report.agent_settings.iter().filter(|s| s.framework == "claude-code");
    let bypass_default = claude().find(|s| {
        matches!(s.source.as_str(), "user-global" | "managed")
            && s.permission_mode.as_deref() == Some("bypassPermissions")
    });
    let bypass_disabled = bypass_disabled_by_policy(report);
    let bypass_default = bypass_default.filter(|_| !bypass_disabled);
    let known_servers = known_mcp_segments(report);
    // Servers marked off: a disabled plugin's, or a connector under
    // disableClaudeAiConnectors (by folded tool segment).
    let mut inactive: BTreeSet<String> = BTreeSet::new();
    let mut active: BTreeSet<String> = BTreeSet::new();
    for c in &report.mcp_configs {
        for s in &c.servers {
            let mut segs = vec![mcp_tool_segment(&s.name)];
            if let Some(p) = &s.plugin {
                let plugin = p.rsplit_once('@').map(|(n, _)| n).unwrap_or(p);
                segs.push(mcp_tool_segment(&format!("plugin_{plugin}_{}", s.name)));
            }
            for seg in segs {
                if s.is_active() {
                    active.insert(seg);
                } else {
                    inactive.insert(seg);
                }
            }
        }
    }
    let shell_all = classify_all_shell(report);

    // Machine-level groups: (severity, title) -> files and rules.
    let mut groups: BTreeMap<(Severity, String), RuleGroup> = BTreeMap::new();

    for s in claude() {
        let user_scoped = matches!(s.source.as_str(), "user-global" | "user-local" | "local");
        let repository = !matches!(s.source.as_str(), "managed" | "plugin") && (s.source == "project" || s.git_tracked);
        let origin = if !repository {
            ""
        } else if s.git_tracked {
            " — from a git-tracked project settings file"
        } else {
            " — from project settings"
        };

        if s.source == "user-global" && s.permission_mode.as_deref() == Some("auto") {
            f.push(Finding {
                severity: Severity::Low,
                category: "Permissions".into(),
                title: "Claude Code sessions start in auto mode: a background classifier, not a prompt, reviews shell commands and network requests".into(),
                location: s.path.clone(),
                evidence: Some("permissions.defaultMode: auto".into()),
            });
        }
        // Under disableBypassPermissionsMode there is no bypass mode to confirm: inventory.
        if s.skip_dangerous_mode_prompt && user_scoped && !s.git_tracked && !bypass_disabled {
            let (severity, title) = match bypass_default {
                Some(b) => (
                    Severity::Critical,
                    format!(
                        "the bypassPermissions confirmation is disabled and sessions start in bypassPermissions ({}): every tool call runs without a prompt or a confirmation",
                        b.path
                    ),
                ),
                None => (
                    Severity::Medium,
                    "the dangerous-mode confirmation is disabled: a session launched with --dangerously-skip-permissions or into bypassPermissions enters it without asking".into(),
                ),
            };
            f.push(Finding {
                severity,
                category: "Permissions".into(),
                title,
                location: s.path.clone(),
                evidence: Some("skipDangerousModePermissionPrompt: true".into()),
            });
        }
        auto_mode_findings(report, s, f);

        if !(user_scoped || repository) {
            continue; // managed policy and plugin files: inventory
        }
        let allow = || s.permission_rules.iter().filter(|r| r.list == "allow");
        let of = |class: &str| -> Vec<&crate::models::PermissionRule> {
            allow().filter(|r| r.class.as_deref() == Some(class)).collect()
        };
        let scoped_sev = if repository { Severity::High } else { Severity::Medium };

        let (mut live, mut disabled, mut phantom) = (Vec::new(), Vec::new(), Vec::new());
        for r in of(RULE_MCP_SERVER) {
            let server = r.detail.as_deref().unwrap_or("");
            let seg = mcp_tool_segment(server);
            match &known_servers {
                Some(k) if !k.contains(&seg) => phantom.push(r),
                _ if inactive.contains(&seg) && !active.contains(&seg) => disabled.push(r),
                _ => live.push(r),
            }
        }
        let names = |rs: &[&crate::models::PermissionRule]| -> Vec<String> {
            rs.iter()
                .filter_map(|r| r.detail.clone())
                .collect::<BTreeSet<String>>()
                .into_iter()
                .collect()
        };
        if !live.is_empty() || !disabled.is_empty() {
            let rules: Vec<&str> = live.iter().chain(&disabled).map(|r| r.rule.as_str()).collect();
            let off = names(&disabled);
            let (severity, title) = if live.is_empty() {
                (
                    Severity::Low,
                    format!(
                        "every tool of MCP server(s) {} is pre-approved by an allow rule, but the server(s) are currently disabled{origin}",
                        off.join(", ")
                    ),
                )
            } else {
                let off_note = if off.is_empty() {
                    String::new()
                } else {
                    format!(" ({} currently disabled: {})", off.len(), off.join(", "))
                };
                (
                    scoped_sev,
                    format!(
                        "every tool of MCP server(s) {} is pre-approved by an allow rule{off_note}{origin}",
                        names(&live).join(", ")
                    ),
                )
            };
            f.push(Finding {
                severity,
                category: "Permissions".into(),
                title,
                location: s.path.clone(),
                evidence: Some(list_rules(&rules, 20)),
            });
        }
        if !phantom.is_empty() {
            let servers = names(&phantom);
            let rules: Vec<&str> = phantom.iter().map(|r| r.rule.as_str()).collect();
            f.push(Finding {
                severity: Severity::Low,
                category: "Permissions".into(),
                title: format!(
                    "Allow rules pre-approve {} MCP server name(s) that no installed plugin or configured server provides; a server later added under that name is trusted without a prompt: {}",
                    servers.len(),
                    list_rules(&servers.iter().map(String::as_str).collect::<Vec<_>>(), 20)
                ),
                location: s.path.clone(),
                evidence: Some(list_rules(&rules, 20)),
            });
        }
        for (class, verb) in [(RULE_CREDENTIAL_READ, "reading"), (RULE_CREDENTIAL_EDIT, "editing")] {
            let mut rules = of(class);
            if rules.is_empty() {
                continue;
            }
            // The broadest rule (the one reaching the most paths) leads the title.
            let reach =
                |r: &crate::models::PermissionRule| r.detail.as_deref().map(|d| d.split(", ").count()).unwrap_or(0);
            rules.sort_by_key(|r| std::cmp::Reverse(reach(r)));
            let lead = rules[0];
            let mut labels: Vec<&str> = lead
                .detail
                .as_deref()
                .map(|d| d.split(", ").collect())
                .unwrap_or_else(|| vec!["credential paths"]);
            let extra = labels.len().saturating_sub(3);
            labels.truncate(3);
            let more_paths = if extra > 0 {
                format!(" and {extra} more credential path(s)")
            } else {
                String::new()
            };
            let more = if rules.len() > 1 {
                format!(" (+{} more rule(s))", rules.len() - 1)
            } else {
                String::new()
            };
            f.push(Finding {
                severity: Severity::High,
                category: "Permissions".into(),
                title: format!(
                    "{} pre-approves {verb} {}{more_paths}{more}{origin}",
                    lead.rule,
                    if extra > 0 {
                        labels.join(", ")
                    } else {
                        and_list(&labels)
                    }
                ),
                location: s.path.clone(),
                evidence: Some(
                    rules
                        .iter()
                        .take(20)
                        .map(|r| format!("{} → {}", r.rule, r.detail.as_deref().unwrap_or("credential paths")))
                        .collect::<Vec<_>>()
                        .join("; "),
                ),
            });
        }
        let inert = of(RULE_INERT_PATH);
        if !inert.is_empty() {
            let names: Vec<&str> = inert.iter().map(|r| r.rule.as_str()).collect();
            f.push(Finding {
                severity: Severity::Low,
                category: "Permissions".into(),
                title: format!(
                    "{} allow rule(s) never match what they name: {}{origin}",
                    inert.len(),
                    list_rules(&names, 8)
                ),
                location: s.path.clone(),
                evidence: Some(
                    inert
                        .iter()
                        .take(8)
                        .map(|r| {
                            format!("{} {}", r.rule, r.detail.as_deref().unwrap_or(""))
                                .trim()
                                .to_string()
                        })
                        .collect::<Vec<_>>()
                        .join("; "),
                ),
            });
        }

        // Machine-level classes: grade each rule, group by grade.
        let auto = starts_in_auto(report, s);
        let from = if repository { " — from project settings" } else { "" };
        for r in of(RULE_CODE_EXEC) {
            let network = r.detail.as_deref() == Some(CODE_EXEC_NETWORK);
            let suspended = auto && (!network || shell_all);
            let (severity, title) = if suspended {
                (
                    if repository { Severity::Medium } else { Severity::Low },
                    format!(
                        "Code-execution allow rules in {{files}}: suspended while auto mode is active; sessions here start in auto{from}"
                    ),
                )
            } else if network && auto {
                (
                    scoped_sev,
                    format!(
                        "Network-transfer allow rules (curl, wget) in {{files}}: they stay active in auto mode, so these commands run without a prompt or a classifier check{from}"
                    ),
                )
            } else if network {
                (
                    scoped_sev,
                    format!(
                        "Network-transfer allow rules (curl, wget) in {{files}}: any download or upload runs without a prompt{from}"
                    ),
                )
            } else {
                (
                    scoped_sev,
                    format!("Code-execution allow rules in {{files}}: arbitrary code runs without a prompt{from}"),
                )
            };
            groups
                .entry((severity, title))
                .or_default()
                .add(&s.path, &s.source, &r.rule);
        }
        for r in of(RULE_DESTRUCTIVE) {
            let suspended = auto && shell_all;
            let (severity, title) = if suspended {
                (
                    Severity::Low,
                    format!(
                        "Allow rules in {{files}} pre-approve commands that change remote or privileged state (ssh, sudo, cloud and GitHub mutations, recursive rm); suspended while auto mode is active (classifyAllShell){from}"
                    ),
                )
            } else {
                (
                    scoped_sev,
                    format!(
                        "Allow rules in {{files}} pre-approve commands that change remote or privileged state (ssh, sudo, cloud and GitHub mutations, recursive rm){from}"
                    ),
                )
            };
            groups
                .entry((severity, title))
                .or_default()
                .add(&s.path, &s.source, &r.rule);
        }
        for r in of(RULE_WRAPPER) {
            let title =
                "{rules} allow rule(s) in {files} may run arbitrary commands through a wrapper or environment runner"
                    .to_string();
            let shown: &str = &r.rule;
            groups
                .entry((Severity::Low, title))
                .or_default()
                .add(&s.path, &s.source, shown);
        }
    }

    // Wrapper rules carry what is known about each wrapper in their detail.
    let wrapper_detail: BTreeMap<&str, &str> = claude()
        .flat_map(|s| s.permission_rules.iter())
        .filter(|r| r.class.as_deref() == Some(RULE_WRAPPER))
        .filter_map(|r| r.detail.as_deref().map(|d| (r.rule.as_str(), d)))
        .collect();
    for ((severity, title), g) in groups {
        let title = title
            .replace("{files}", &g.files_noun())
            .replace("{rules}", &g.rules().to_string());
        let mut evidence = g.evidence();
        if title.contains("through a wrapper") {
            let notes: Vec<String> = wrapper_detail
                .iter()
                .take(8)
                .map(|(r, d)| format!("{r}: {d}"))
                .collect();
            evidence.push_str(&format!(" | {}", notes.join("; ")));
        }
        f.push(Finding {
            severity,
            category: "Permissions".into(),
            title,
            location: g.location(),
            evidence: Some(evidence),
        });
    }
}

/// The `autoMode` block (code.claude.com/docs/en/auto-mode-config.md, fetched
/// 2026-10-24). The classifier reads it from user and managed settings only: "The
/// classifier doesn't read `autoMode` from project settings in `.claude/settings.json`
/// or `.claude/settings.local.json`", so a block there is a Low inert note. In user and
/// managed settings:
///
/// - `soft_deny` / `hard_deny` set without `"$defaults"`: High. "If you set an array
///   without `"$defaults"`, you discard the built-in rules for that section: `soft_deny`:
///   every built-in soft block rule, including force push, `curl | bash`, production
///   deploys, and auto-mode bypass; `hard_deny`: the built-in data exfiltration rule".
///   Medium when another scope's list of that name keeps `"$defaults"`: "Entries from
///   each scope are combined", and whether that restores the defaults is not documented.
/// - Custom `allow` entries: Medium, the entries (redacted by shape) as evidence: allow
///   rules "override matching `soft_deny` rules as exceptions".
/// - `environment` entries in a trust slot: Medium, the slot names as evidence: "any
///   destination not listed is a potential exfiltration target", so a listed one is not.
///   `environment` without `"$defaults"` is not graded: `/auto-mode-setup` "writes the
///   `environment` list without `"$defaults"`" by design.
/// - `classifyAllShell: true` is inventory (it narrows what allow rules approve).
fn auto_mode_findings(report: &ScanReport, s: &crate::models::AgentSettings, f: &mut Vec<Finding>) {
    use crate::scanners::agent_settings::AUTO_MODE_TRUST_SLOTS;
    let Some(a) = &s.auto_mode else { return };
    if !matches!(s.source.as_str(), "user-global" | "managed") {
        let keys: Vec<&str> = [
            ("environment", a.environment.is_some()),
            ("allow", a.allow.is_some()),
            ("soft_deny", a.soft_deny.is_some()),
            ("hard_deny", a.hard_deny.is_some()),
            ("classifyAllShell", a.classify_all_shell.is_some()),
        ]
        .iter()
        .filter(|(_, on)| *on)
        .map(|(k, _)| *k)
        .collect();
        f.push(Finding {
            severity: Severity::Low,
            category: "Permissions".into(),
            title: "autoMode in project settings is ignored by Claude Code: the auto-mode classifier reads it only from user and managed settings".into(),
            location: s.path.clone(),
            evidence: Some(format!("autoMode keys: {}", keys.join(", "))),
        });
        return;
    }
    let other_keeps = |pick: fn(&crate::models::AutoModeSettings) -> Option<&crate::models::AutoModeList>| {
        report.agent_settings.iter().any(|o| {
            !std::ptr::eq(o, s)
                && o.framework == "claude-code"
                && matches!(o.source.as_str(), "user-global" | "managed")
                && o.auto_mode.as_ref().and_then(pick).is_some_and(|l| l.has_defaults)
        })
    };
    let mut discarded: Vec<(&str, &str, bool)> = Vec::new();
    if a.hard_deny.as_ref().is_some_and(|l| !l.has_defaults) {
        discarded.push((
            "hard_deny",
            "the built-in data-exfiltration hard-deny",
            other_keeps(|m| m.hard_deny.as_ref()),
        ));
    }
    if a.soft_deny.as_ref().is_some_and(|l| !l.has_defaults) {
        discarded.push((
            "soft_deny",
            "every built-in soft block (force push, curl | bash, production deploys, auto-mode bypass)",
            other_keeps(|m| m.soft_deny.as_ref()),
        ));
    }
    if !discarded.is_empty() {
        let kept_elsewhere = discarded.iter().all(|(_, _, k)| *k);
        let lists: Vec<&str> = discarded.iter().map(|(k, _, _)| *k).collect();
        let what: Vec<&str> = discarded.iter().map(|(_, w, _)| *w).collect();
        f.push(Finding {
            severity: if kept_elsewhere { Severity::Medium } else { Severity::High },
            category: "Permissions".into(),
            title: format!(
                "built-in auto-mode denials are discarded: autoMode.{} is set without \"$defaults\", which drops {}{}",
                lists.join(" and autoMode."),
                and_list(&what),
                if kept_elsewhere {
                    " (another settings scope's list keeps \"$defaults\"; how the scopes combine for the built-in rules is not documented)"
                } else {
                    ""
                }
            ),
            location: s.path.clone(),
            evidence: Some(
                discarded
                    .iter()
                    .map(|(k, _, _)| {
                        let n = match *k {
                            "hard_deny" => a.hard_deny.as_ref(),
                            _ => a.soft_deny.as_ref(),
                        }
                        .map(|l| l.entries)
                        .unwrap_or(0);
                        format!("autoMode.{k}: {n} custom entr{}, no \"$defaults\"", if n == 1 { "y" } else { "ies" })
                    })
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
        });
    }
    if let Some(l) = a.allow.as_ref().filter(|l| l.entries > 0) {
        f.push(Finding {
            severity: Severity::Medium,
            category: "Permissions".into(),
            title: format!(
                "autoMode.allow adds {} custom exception(s) that override the auto-mode classifier's soft blocks",
                l.entries
            ),
            location: s.path.clone(),
            evidence: Some(l.shown.join("; ")),
        });
    }
    if let Some(l) = &a.environment {
        let mut slots: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
        for e in &l.shown {
            if AUTO_MODE_TRUST_SLOTS.contains(&e.as_str()) {
                *slots.entry(e.as_str()).or_default() += 1;
            }
        }
        if !slots.is_empty() {
            let shown: Vec<String> = slots.iter().map(|(k, n)| format!("{k} ({n})")).collect();
            f.push(Finding {
                severity: Severity::Medium,
                category: "Permissions".into(),
                title: format!(
                    "autoMode.environment widens what the auto-mode classifier trusts: {}",
                    shown.join(", ")
                ),
                location: s.path.clone(),
                evidence: Some(format!(
                    "trust-slot entries by slot name (their text is not shown): {}",
                    shown.join(", ")
                )),
            });
        }
    }
}

/// One Claude Code store others can read, graded: (severity before reachability, what
/// it exposes, readable files). None when other users can open nothing in it.
struct StoreRow {
    severity: Severity,
    what: String,
    readable: usize,
}

/// Shell state an exported NAME may carry without being a credential: a closed list
/// (prefixes end in `_`).
const SHELL_STATE_NAMES: &[&str] = &[
    "PATH",
    "SHELL",
    "TERM",
    "LANG",
    "LC_",
    "PWD",
    "OLDPWD",
    "SHLVL",
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "XDG_",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "DBUS_SESSION_BUS_ADDRESS",
    "SSH_AUTH_SOCK",
];

fn is_shell_state_name(n: &str) -> bool {
    SHELL_STATE_NAMES
        .iter()
        .any(|s| if s.ends_with('_') { n.starts_with(s) } else { n == *s })
}

/// The grade of a `session-env` / `shell-snapshots` store by the NAMES its sampled files
/// export (values are never read): a secret-shaped name is High, any name outside
/// [`SHELL_STATE_NAMES`] Medium, shell state only Low.
fn exported_names_grade(n: &crate::models::ExportedNames) -> (Severity, String) {
    let sample = format!(
        "{} of {} readable files sampled, first {} KiB each, in path order",
        n.sampled_files,
        n.readable_files,
        n.bytes_per_file / 1024
    );
    if n.sampled_files == 0 {
        return (Severity::Medium, format!("exported names could not be read ({sample})"));
    }
    let secret: Vec<&str> = n
        .names
        .iter()
        .map(String::as_str)
        .filter(|x| crate::scanners::env_files::is_secret_key_name(x) || *x == "<key-shaped name>")
        .collect();
    let other: Vec<&str> = n
        .names
        .iter()
        .map(String::as_str)
        .filter(|x| !is_shell_state_name(x))
        .collect();
    if !secret.is_empty() {
        (
            Severity::High,
            format!(
                "exports a secret-named variable (name only): {} ({sample})",
                list_rules(&secret, 8)
            ),
        )
    } else if !other.is_empty() || n.truncated {
        (
            Severity::Medium,
            format!(
                "exports variables beyond shell state (names only): {} ({sample})",
                list_rules(&other, 8)
            ),
        )
    } else {
        (Severity::Low, format!("contains PATH/shell state only ({sample})"))
    }
}

/// What other users can open in one Claude Code store, graded. Content-bearing stores
/// (transcripts, command history, ~/.claude.json and its backups, agent memory and
/// journals, paste cache, file-edit history) are High; metadata stores (todos, tasks,
/// plans, telemetry, feature flags, usage data, plugin logs) Medium; session-env and
/// shell-snapshots by the names they export ([`exported_names_grade`]).
fn claude_store_row(t: &crate::models::AgentTranscriptStore) -> Option<StoreRow> {
    use crate::scanners::transcripts::{ACCOUNT_STATE, ACCOUNT_STATE_BACKUP, store_exposure};
    let (what, content) = store_exposure(&t.kind);
    let readable = t.readable_files.unwrap_or(t.file_count);
    if matches!(t.kind.as_str(), ACCOUNT_STATE | ACCOUNT_STATE_BACKUP) {
        return if t.world_readable {
            Some(StoreRow {
                severity: Severity::High,
                what: what.to_string(),
                readable: 1,
            })
        } else if t.group_readable {
            Some(StoreRow {
                severity: Severity::Medium,
                what: format!("{what}; readable by its group only"),
                readable: 1,
            })
        } else {
            None
        };
    }
    if !(t.world_readable && readable > 0) {
        return None;
    }
    let (severity, what) = match &t.exported_names {
        Some(n) => exported_names_grade(n),
        None if content => (Severity::High, what.to_string()),
        None => (Severity::Medium, what.to_string()),
    };
    Some(StoreRow {
        severity,
        what,
        readable,
    })
}

/// The Claude Code store finding of one home: every store under ~/.claude and
/// ~/.claude.json other local accounts can read, as a table in the evidence, graded by the most
/// sensitive reachable store. A store behind an ancestor others cannot traverse is a
/// Low row; when every store is, the finding is Low "not reachable".
fn claude_store_finding(rows: &[(&crate::models::AgentTranscriptStore, StoreRow)]) -> Option<Finding> {
    if rows.is_empty() {
        return None;
    }
    let reachable: Vec<&(&crate::models::AgentTranscriptStore, StoreRow)> =
        rows.iter().filter(|(t, _)| t.unreachable_via.is_none()).collect();
    let files: usize = reachable.iter().map(|(_, r)| r.readable).sum();
    let (severity, lead) = match reachable.iter().min_by_key(|(_, r)| r.severity.rank()) {
        Some((t, r)) => (r.severity, *t),
        None => (Severity::Low, rows[0].0),
    };
    let name = |t: &crate::models::AgentTranscriptStore| t.path.rsplit('/').next().unwrap_or(&t.path).to_string();
    let title = if reachable.is_empty() {
        let all: usize = rows.iter().map(|(_, r)| r.readable).sum();
        format!(
            "Claude Code state under ~/.claude and ~/.claude.json has files other local accounts could read ({} stores, about {all} files) — not reachable: {}",
            rows.len(),
            rows[0].0.unreachable_via.as_deref().unwrap_or("")
        )
    } else {
        format!(
            "Claude Code state under ~/.claude and ~/.claude.json is readable by other local accounts ({} store{}, about {files} files)",
            reachable.len(),
            if reachable.len() == 1 { "" } else { "s" }
        )
    };
    let mut table: Vec<String> = rows
        .iter()
        .map(|(t, r)| {
            let grade = if t.unreachable_via.is_some() {
                format!("low (not reachable: {})", t.unreachable_via.as_deref().unwrap_or(""))
            } else {
                r.severity.label().to_string()
            };
            let total = if t.file_count > 1 {
                format!("{} of {} files", r.readable, t.file_count)
            } else {
                "file".to_string()
            };
            format!("{} ({}): {total}, {grade}: {}", name(t), t.kind, r.what)
        })
        .collect();
    table.push(match rows[0].0.other_login_accounts {
        Some(n) => format!("other accounts with a login shell on this machine: {n} (from /etc/passwd)"),
        None => "other accounts with a login shell on this machine: not determined".to_string(),
    });
    Some(Finding {
        severity,
        category: "Transcript exposure".into(),
        title,
        location: lead.path.clone(),
        evidence: Some(table.join("; ")),
    })
}

/// Installed plugins this scan knows by name, as `(name, plugin@marketplace)`: from
/// plugin hook files, skill provenance and plugin MCP servers.
fn installed_plugins(report: &ScanReport) -> Vec<(String, String)> {
    let mut out: BTreeSet<(String, String)> = BTreeSet::new();
    let mut add = |id: &str| {
        let name = id.split_once('@').map(|(n, _)| n).unwrap_or(id);
        if !name.is_empty() {
            out.insert((name.to_string(), id.to_string()));
        }
    };
    for s in &report.agent_settings {
        if let Some(p) = s.provenance.as_ref().and_then(|p| p.plugin.as_deref()) {
            add(p);
        }
    }
    for k in &report.agent_skills {
        if let Some(p) = k.provenance.as_ref().filter(|p| p.active) {
            match (p.plugin.as_deref(), p.marketplace.as_deref()) {
                (Some(n), Some(m)) if !n.contains('@') => add(&format!("{n}@{m}")),
                (Some(n), _) => add(n),
                _ => {}
            }
        }
    }
    for c in &report.mcp_configs {
        for s in &c.servers {
            if let Some(p) = &s.plugin {
                add(p);
            }
        }
    }
    out.into_iter().collect()
}

/// The Low executables in `~/.claude/bin` (outside any plugin cache, owned by the user,
/// not writable by others) as one finding: the count, the plugin each is named after
/// (its file name is the plugin's name or starts with `<name>-`), and each file as
/// evidence. rmguard does not know which plugin installed a file; the name is the only
/// link it draws, and says so.
fn agent_bin_finding(report: &ScanReport, bins: &[(&crate::models::PersistenceArtifact, bool)]) -> Option<Finding> {
    let first = bins.first()?;
    let plugins = installed_plugins(report);
    let file_name = |p: &str| p.rsplit('/').next().unwrap_or(p).to_string();
    let mut by_plugin: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
    let mut unattributed = 0usize;
    for (a, _) in bins {
        let n = file_name(&a.path);
        // A `plugin@marketplace` id is preferred over a bare name for the same plugin.
        match plugins
            .iter()
            .filter(|(name, _)| n == *name || n.starts_with(&format!("{name}-")))
            .max_by_key(|(name, id)| (name.len(), id.contains('@')))
        {
            Some((_, id)) => by_plugin.entry(id.clone()).or_default().push(n),
            None => unattributed += 1,
        }
    }
    let count = bins.len();
    let s = if count == 1 { "" } else { "s" };
    let title = match (by_plugin.len(), unattributed) {
        (0, _) => format!("{count} executable{s} in ~/.claude/bin survive plugin uninstall"),
        (1, 0) => format!(
            "{count} executable{s} in ~/.claude/bin (plugin {}, by name) survive uninstall",
            by_plugin.keys().next().map(String::as_str).unwrap_or("")
        ),
        _ => format!(
            "{count} executable{s} in ~/.claude/bin survive plugin uninstall ({}{})",
            by_plugin
                .iter()
                .map(|(id, v)| format!("{} named after plugin {id}", v.len()))
                .collect::<Vec<_>>()
                .join(", "),
            if unattributed > 0 {
                format!("; {unattributed} named after no installed plugin")
            } else {
                String::new()
            }
        ),
    };
    let dir = first.0.path.rsplit_once('/').map(|(d, _)| d).unwrap_or(&first.0.path);
    Some(Finding {
        severity: Severity::Low,
        category: "Persistence".into(),
        title,
        location: dir.to_string(),
        evidence: Some(
            bins.iter()
                .take(30)
                .map(|(a, hooked)| format!("{}{}", a.detail, if *hooked { " — a hook runs it" } else { "" }))
                .collect::<Vec<_>>()
                .join("; "),
        ),
    })
}

pub fn collect_findings(report: &ScanReport) -> Vec<Finding> {
    let mut f = Vec::new();

    // Known-malicious / vulnerable package matches — the most actionable signal.
    for e in &report.exposure_findings {
        f.push(exposure_finding(report, e));
    }

    // MCP server configuration risks (transport encryption, over-broad scope). A disabled
    // plugin's servers and the claude.ai connectors are inventory only.
    let home = report.device.home_dir.as_str();
    for mcp in &report.mcp_configs {
        for s in mcp.servers.iter().filter(|s| s.is_active() && !s.ever_connected) {
            if mcp.config_source == crate::models::MCP_SOURCE_PLUGIN
                && let Some(reason) = &s.unpinned
            {
                let pkg = s.package_name.as_deref().unwrap_or("its package");
                f.push(Finding {
                    severity: Severity::Medium,
                    category: "MCP command".into(),
                    title: format!(
                        "plugin MCP server runs an unpinned package: '{}' from plugin '{}' runs {} ({reason}) — each start can fetch new code",
                        s.name,
                        s.plugin.as_deref().unwrap_or("?"),
                        pkg
                    ),
                    location: mcp.config_path.clone(),
                    evidence: Some(crate::scanners::redact_secrets_in_text(
                        format!("{} {}", s.command.as_deref().unwrap_or(""), s.args.join(" ")).trim(),
                    )),
                });
            }
            // `--with` dependencies of a plugin server's uv launch: the same rule, one
            // grade lower (the launched package is what the plugin chose to run).
            if mcp.config_source == crate::models::MCP_SOURCE_PLUGIN {
                let floating: Vec<String> = s
                    .extra_packages
                    .iter()
                    .filter_map(|p| crate::scanners::mcp::extra_package_unpinned(p).map(|r| format!("{p} ({r})")))
                    .collect();
                if !floating.is_empty() {
                    f.push(Finding {
                        severity: Severity::Low,
                        category: "MCP command".into(),
                        title: format!(
                            "plugin MCP server runs an extra unpinned package: '{}' from plugin '{}' installs {} with --with — each start can fetch new code",
                            s.name,
                            s.plugin.as_deref().unwrap_or("?"),
                            floating.join(", ")
                        ),
                        location: mcp.config_path.clone(),
                        evidence: Some(crate::scanners::redact_secrets_in_text(
                            format!("{} {}", s.command.as_deref().unwrap_or(""), s.args.join(" ")).trim(),
                        )),
                    });
                }
            }
            // Plaintext remote transport: credentials/data sent unencrypted.
            if let Some(url) = &s.url
                && url.to_lowercase().starts_with("http://")
            {
                f.push(Finding {
                    severity: Severity::High,
                    category: "MCP transport".into(),
                    title: format!(
                        "MCP server '{}' uses plaintext HTTP ({}) — traffic and tokens are unencrypted",
                        s.name, url
                    ),
                    location: mcp.config_path.clone(),
                    evidence: None,
                });
            }
            // Over-broad filesystem scope: a filesystem server rooted at / or $HOME
            // exposes the whole machine/home to the agent.
            let is_fs = s
                .package_name
                .as_deref()
                .map(|n| n.contains("filesystem"))
                .unwrap_or(false);
            if is_fs {
                for arg in &s.args {
                    if is_broad_root(arg, home) {
                        f.push(Finding {
                            severity: Severity::Medium,
                            category: "MCP scope".into(),
                            title: format!(
                                "MCP filesystem server '{}' is rooted at a broad path ({}) — near-whole-machine access",
                                s.name, arg
                            ),
                            location: mcp.config_path.clone(),
                            evidence: None,
                        });
                    }
                }
            }
            // Credentials hardcoded inline in the config `env` block (names only). A
            // git-tracked config makes this a committed secret — the same escalation
            // as a git-tracked `.env`, so it becomes Critical "Secret leak".
            if !s.inline_secret_env_keys.is_empty() || !s.inline_secret_header_keys.is_empty() {
                let keys = s
                    .inline_secret_env_keys
                    .iter()
                    .chain(&s.inline_secret_header_keys)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                let finding = if mcp.git_tracked {
                    Finding {
                        severity: Severity::Critical,
                        category: "Secret leak".into(),
                        title: format!(
                            "MCP server '{}' has hardcoded credential(s) in a git-tracked config: {} — committed secret",
                            s.name, keys
                        ),
                        location: mcp.config_path.clone(),
                        evidence: None,
                    }
                } else {
                    Finding {
                        severity: Severity::High,
                        category: "MCP secret".into(),
                        title: format!(
                            "MCP server '{}' has hardcoded credential(s) in its config env block: {} — reference ${{ENV_VAR}} instead",
                            s.name, keys
                        ),
                        location: mcp.config_path.clone(),
                        evidence: None,
                    }
                };
                f.push(finding);
            }
            // A launch command that downloads-and-executes (curl|bash, etc.): the
            // server's own bootstrap is a remote-code-execution vector.
            let launch = match &s.command {
                Some(c) => format!("{} {}", c, s.args.join(" ")),
                None => s.args.join(" "),
            };
            if !launch.trim().is_empty() && !crate::scanners::rules_files::check_dangerous_patterns(&launch).is_empty()
            {
                f.push(Finding {
                    severity: Severity::High,
                    category: "MCP command".into(),
                    title: format!(
                        "MCP server '{}' launches via a download-and-execute command — remote code on startup",
                        s.name
                    ),
                    location: mcp.config_path.clone(),
                    evidence: Some(crate::scanners::redact_secrets_in_text(launch.trim())),
                });
            }
        }
    }

    // Hooks of every agent and every scope: settings, plugin files and skill frontmatter.
    collect_hook_findings(report, &mut f);

    // Claude Code permission modes, the dangerous-mode confirmation, and allow rules.
    collect_permission_findings(report, &mut f);

    for s in &report.agent_settings {
        // Credential/telemetry helpers: commands Claude Code runs on its own. In the
        // user's own or managed settings they are normal enterprise plumbing and are
        // reported only when dangerous; from a project file the repository chose them.
        let project_scoped = matches!(s.source.as_str(), "project" | "local");
        for h in &s.helper_commands {
            // The cross-directory escalation is for a repository's helper; a user or
            // managed helper is reported only when dangerous, as the guidance says.
            let cross_dir = project_scoped && h.risks.iter().any(|r| r.starts_with("cross-references"));
            let severity = if h.dangerous {
                Severity::Critical
            } else if cross_dir {
                Severity::High
            } else if project_scoped {
                // settings.local.json is created and gitignored by Claude Code, so an
                // untracked one is normally the user's own; untracked settings.json is not.
                if s.git_tracked {
                    Severity::High
                } else if s.source == "local" {
                    Severity::Low
                } else {
                    Severity::Medium
                }
            } else {
                continue;
            };
            let origin = if !project_scoped {
                ""
            } else if s.git_tracked {
                " — from a git-tracked project settings file"
            } else {
                " — from project settings"
            };
            let detail = if h.risks.is_empty() {
                String::new()
            } else {
                format!(" — {}", h.risks.join("; "))
            };
            f.push(Finding {
                severity,
                category: "Helper command".into(),
                title: format!(
                    "{} runs a command{}{}{}",
                    h.event,
                    if h.dangerous {
                        " matching a dangerous pattern"
                    } else {
                        ""
                    },
                    origin,
                    detail
                ),
                location: s.path.clone(),
                evidence: Some(h.command.clone()),
            });
        }
        // A login gateway in user settings is surfaced for review; managed settings are
        // the organization's own, and project/local files are ignored by Claude Code.
        // A gateway on this machine (`http://localhost:8443`) is silent, like a loopback
        // ANTHROPIC_BASE_URL in the same file.
        if let Some(lg) = &s.login_gateway
            && lg.effective
            && s.source == "user-global"
            && let Some(host) = &lg.host
            && !crate::scanners::is_client_loopback_host(host)
        {
            f.push(Finding {
                severity: Severity::Low,
                category: "Login gateway".into(),
                title: format!(
                    "Claude Code login is forced to the gateway at {host} from user settings — confirm your organization runs it"
                ),
                location: s.path.clone(),
                evidence: None,
            });
        }
        if s.auto_approve_mcp {
            f.push(Finding {
                severity: Severity::High,
                category: "MCP auto-approval".into(),
                title: "enableAllProjectMcpServers auto-approves project MCP servers".into(),
                location: s.path.clone(),
                evidence: None,
            });
        }
        // A config any local process can write is a persistence foothold: append a
        // hook and the agent runs it on the next event. This is the cheapest possible
        // implant, and it needs no vulnerability — just a loose mode bit.
        if s.world_writable {
            f.push(Finding {
                severity: Severity::High,
                category: "Config integrity".into(),
                title: format!(
                    "{} config is writable by group/other — any local process can inject a hook",
                    s.framework
                ),
                location: s.path.clone(),
                evidence: None,
            });
        }

        // The same "act without asking" setting under two names: Claude Code calls it
        // permissions.defaultMode = bypassPermissions, Cursor calls it
        // approvalMode = unrestricted.
        //
        // Claude Code: `bypassPermissions` "doesn't take effect from project or local
        // settings" (code.claude.com/docs/en/settings.md, from v2.1.257), so there it is a
        // Low note; from user or managed settings it is High, unless any user or managed
        // file sets `permissions.disableBypassPermissionsMode: "disable"`, which removes
        // the mode: inventory (the terminal shows "bypass mode is disabled by policy").
        if let Some(mode) = s.permission_mode.as_deref()
            && matches!(mode, "bypassPermissions" | "unrestricted")
        {
            let claude_scope = s.framework == "claude-code" && mode == "bypassPermissions";
            if claude_scope && matches!(s.source.as_str(), "project" | "local" | "user-local") {
                f.push(Finding {
                    severity: Severity::Low,
                    category: "Permissions".into(),
                    title: format!(
                        "{} defaultMode bypassPermissions is ignored by Claude Code in this scope ({} settings start sessions in Manual mode); set it in user or managed settings only if you mean it",
                        s.framework, s.source
                    ),
                    location: s.path.clone(),
                    evidence: Some("permissions.defaultMode: bypassPermissions".into()),
                });
            } else if !(claude_scope && bypass_disabled_by_policy(report)) {
                f.push(Finding {
                    severity: Severity::High,
                    category: "Permissions".into(),
                    title: format!("{} runs without approval prompts ({})", s.framework, mode),
                    location: s.path.clone(),
                    evidence: None,
                });
            }
        }
        // Credentials hardcoded inline in the settings `env` block (names only).
        // A git-tracked settings file makes this a committed secret.
        if !s.inline_secret_env_keys.is_empty() {
            let keys = s.inline_secret_env_keys.join(", ");
            f.push(if s.git_tracked {
                Finding {
                    severity: Severity::Critical,
                    category: "Secret leak".into(),
                    title: format!(
                        "hardcoded credential(s) in a git-tracked settings env block: {keys} — committed secret"
                    ),
                    location: s.path.clone(),
                    evidence: None,
                }
            } else {
                Finding {
                    severity: Severity::High,
                    category: "Settings secret".into(),
                    title: format!(
                        "hardcoded credential(s) in the settings env block: {keys} — reference ${{ENV_VAR}} instead"
                    ),
                    location: s.path.clone(),
                    evidence: None,
                }
            });
        }
        // EAA-007: an AI base URL pointed at a non-official host routes requests (and
        // the API key) through that host — the CVE-2026-21852 exfil vector. A proxy may
        // be legitimate, so this is advisory-to-review, not automatically critical.
        for g in &s.gateway_overrides {
            // A loopback or unspecified dial address (localhost, 127.0.0.1, 0.0.0.0, [::])
            // is a proxy on this machine: not reported, as the guidance says.
            if !g.official && !crate::scanners::is_client_loopback_host(&g.host) {
                f.push(Finding {
                    severity: Severity::Medium,
                    category: "Gateway routing".into(),
                    title: format!(
                        "{} points to non-official host {} — verify this gateway is trusted (EAA-007)",
                        g.var, g.host
                    ),
                    location: s.path.clone(),
                    evidence: None,
                });
            }
        }
    }

    // VS Code tasks that auto-run on folder open — the other half of the 2026
    // persistence pair (an agent hook pointing into .vscode/, and a folderOpen task
    // pointing back into .claude/). VS Code gates this behind allowAutomaticTasks and
    // workspace trust, so a plain auto-run task is a Medium to review; it escalates
    // when the task is git-tracked (clone the repo, open it, it runs) or when it
    // references another tool's config directory.
    for t in &report.vscode_tasks {
        let cross_dir = t.risks.iter().any(|r| r.starts_with("cross-references"));
        let severity = if t.dangerous {
            Severity::Critical
        } else if cross_dir || t.git_tracked {
            Severity::High
        } else {
            Severity::Medium
        };
        let mut why = Vec::new();
        if t.git_tracked {
            why.push("git-tracked, so it travels with the repository".to_string());
        }
        why.extend(t.risks.iter().cloned());
        f.push(Finding {
            severity,
            category: "Auto-run task".into(),
            title: format!(
                "VS Code task '{}' runs automatically when the folder is opened{}",
                t.label,
                if why.is_empty() {
                    String::new()
                } else {
                    format!(" — {}", why.join("; "))
                }
            ),
            location: t.path.clone(),
            evidence: Some(t.command.clone()),
        });
    }

    // Persistence and planting artifacts: Python startup hooks, tool-shadowing
    // binaries, committed symlinks that escape the repo, staged loaders, worm IOCs,
    // agent URL handlers, executables in ~/.claude/bin, dangling plugin records.
    let hook_commands: Vec<&str> = report
        .agent_settings
        .iter()
        .flat_map(|s| s.hooks.iter().chain(&s.helper_commands))
        .map(|h| h.command.as_str())
        .collect();
    // Low agent-bin executables are one finding per machine (agent_bin_finding).
    let mut bin_lows: Vec<(&crate::models::PersistenceArtifact, bool)> = Vec::new();
    for a in &report.persistence_artifacts {
        let (severity, category, title) = match a.kind.as_str() {
            "python-startup-hook" => {
                let sev = if a.sensitive_target {
                    Severity::Critical
                } else if !a.claimed {
                    Severity::High
                } else {
                    Severity::Medium
                };
                let claim = if a.sensitive_target {
                    "published indicator of the litellm 1.107.0 implant"
                } else if a.claimed {
                    "listed by an installed distribution's RECORD"
                } else {
                    "claimed by no installed distribution"
                };
                (
                    sev,
                    "Persistence",
                    format!("Python startup hook runs on every interpreter start — {claim}"),
                )
            }
            "planted-binary" => {
                let sev = match (a.git_tracked, a.sensitive_target) {
                    (true, true) => Severity::Critical,
                    (true, false) | (false, true) => Severity::High,
                    (false, false) => Severity::Medium,
                };
                let carrier = if a.git_tracked {
                    " — git-tracked, so every clone carries it"
                } else {
                    ""
                };
                (
                    sev,
                    "Binary planting",
                    format!("Executable in a project root {}{carrier}", a.detail),
                )
            }
            "escaping-symlink" => {
                let sev = if a.sensitive_target {
                    Severity::Critical
                } else {
                    Severity::High
                };
                let target = if a.sensitive_target {
                    "a credential, shell-rc or agent-config path"
                } else {
                    "outside the repository"
                };
                (
                    sev,
                    "Repo symlink",
                    format!("Committed symlink resolves {target}; an approved in-project write lands there"),
                )
            }
            "loader-script" => {
                let sev = if a.sensitive_target || a.git_tracked {
                    Severity::High
                } else {
                    Severity::Medium
                };
                (
                    sev,
                    "Persistence",
                    format!("Loader staged in an agent directory: {}", a.detail),
                )
            }
            "url-handler" => (
                Severity::Low,
                "Persistence",
                format!("URL scheme handler: a browser link can launch the agent — {}", a.detail),
            ),
            "agent-bin" => {
                let info = a.bin.clone().unwrap_or_default();
                let hooked = hook_commands.iter().any(|c| references_bin(c, &a.path));
                let sev = if info.world_writable || (hooked && !info.owned_by_user) {
                    Severity::High
                } else {
                    Severity::Low
                };
                let why = if info.world_writable {
                    " — writable by group or other"
                } else if hooked && !info.owned_by_user {
                    " — a hook runs it and it is not owned by you"
                } else if hooked {
                    " — a hook runs it"
                } else {
                    ""
                };
                (
                    sev,
                    "Persistence",
                    format!(
                        "Executable in the agent's bin directory, outside any plugin cache; survives plugin uninstall: {}{why}",
                        a.detail
                    ),
                )
            }
            "dangling-plugin-record" => (
                Severity::Low,
                "Persistence",
                format!(
                    "Plugin record points at a missing install ({}); recreating the path may load it without a new install prompt",
                    a.detail
                ),
            ),
            _ => (
                Severity::Critical,
                "Persistence",
                format!("Known worm persistence artifact: {}", a.detail),
            ),
        };
        if a.kind == "agent-bin" && severity == Severity::Low {
            let hooked = hook_commands.iter().any(|c| references_bin(c, &a.path));
            bin_lows.push((a, hooked));
            continue;
        }
        f.push(Finding {
            severity,
            category: category.into(),
            title,
            location: a.path.clone(),
            evidence: Some(a.detail.clone()),
        });
    }
    if let Some(finding) = agent_bin_finding(report, &bin_lows) {
        f.push(finding);
    }

    // Git configuration that turns an ordinary git command into code execution.
    // Value-gated and scope-gated, so reaching here already means the value chains
    // shell commands / matches a dangerous pattern / runs a script the repo ships,
    // in a scope an untrusted repository controls.
    for g in &report.git_autorun_configs {
        f.push(Finding {
            // A BURIED git dir is attacker-authored by construction — a project's own
            // .git/config is at least something the developer may have written.
            severity: if g.nested { Severity::Critical } else { Severity::High },
            category: "Git autorun".into(),
            title: format!(
                "git {} in {} runs a command on ordinary git operations — {}{}",
                g.key,
                if g.nested {
                    "a nested git directory"
                } else {
                    "this repository"
                },
                g.reason,
                if g.origin.ends_with("/config") {
                    String::new()
                } else {
                    format!(" (hidden via include: {})", g.origin)
                }
            ),
            location: g.path.clone(),
            evidence: Some(format!("{} = {}", g.key, g.value)),
        });
    }

    // At-rest AI tokens with loose permissions, and API keys written into configs.
    for c in &report.ai_credentials {
        if c.world_readable {
            f.push(Finding {
                severity: Severity::High,
                category: "Credential".into(),
                title: format!("{} {} is world-readable", c.provider, c.credential_type),
                location: c.path.clone(),
                evidence: None,
            });
        } else if c.credential_type.starts_with("inline ") {
            // A key in a config file gets synced, backed up and committed with it; the
            // tools' own docs say to use their secrets mechanism instead.
            f.push(Finding {
                severity: Severity::Medium,
                category: "Credential".into(),
                title: format!("{} config stores an API key inline ({})", c.provider, c.credential_type),
                location: c.path.clone(),
                evidence: None,
            });
        }
    }

    // .env secrets in agent project roots.
    for e in &report.env_files {
        // A .env is graded by what was actually read. The values are never read, so a
        // secret is judged by the key NAMES (secret-named or a connection string, plus
        // ANTHROPIC_CUSTOM_HEADERS). When the file was opened, EVERY content line parsed as
        // `KEY=value`, and no name is credential-shaped (only PORT / NODE_ENV / LOG_LEVEL,
        // or no content at all), a committed or world-readable .env is a Low advisory. A
        // file whose keys were not read (a symlink, never opened, or a file that could not
        // be read), or that has lines rmguard could not parse (`spring.datasource.password=x`,
        // `OPENAI_API_KEY: sk-...`), keeps the Critical / High grade, since nothing shows
        // it is clean. `key_count > 0` also proves a read, so a report from before
        // `read_ok` existed grades as it did.
        let credential_named = !e.secret_keys.is_empty() || e.agent_overrides.iter().any(|o| o.kind == "headers");
        let keys_read = e.symlink.is_none() && (e.read_ok || e.key_count > 0);
        let clean = keys_read && !credential_named && e.unparsed_lines == 0;
        let unparsed = |what: &str| {
            format!(
                ".env is {what} and has {} line{} rmguard could not parse as KEY=value",
                e.unparsed_lines,
                if e.unparsed_lines == 1 { "" } else { "s" }
            )
        };
        if e.git_tracked && clean {
            let title = if e.key_count == 0 {
                ".env is git-tracked and empty — check that no credential is added to it later".to_string()
            } else {
                format!(
                    ".env is git-tracked ({} keys, no secret-named keys) — check that no credential is committed under another name",
                    e.key_count
                )
            };
            f.push(Finding {
                severity: Severity::Low,
                category: "Secret hygiene".into(),
                title,
                location: e.path.clone(),
                evidence: None,
            });
        } else if e.git_tracked {
            let title = if !keys_read {
                ".env is git-tracked and its keys could not be read (unreadable, or a symlink rmguard does not open); treated as committed secrets".to_string()
            } else if !credential_named {
                format!("{}; treated as committed secrets", unparsed("git-tracked"))
            } else {
                format!(".env is git-tracked ({} keys) — committed secrets", e.key_count)
            };
            f.push(Finding {
                severity: Severity::Critical,
                category: "Secret leak".into(),
                title,
                location: e.path.clone(),
                evidence: None,
            });
        } else if e.world_readable && clean {
            f.push(Finding {
                severity: Severity::Low,
                category: "Secret hygiene".into(),
                title: format!(
                    ".env is world-readable ({} keys, no secret-named keys) — check that no credential is stored under another name",
                    e.key_count
                ),
                location: e.path.clone(),
                evidence: None,
            });
        } else if e.world_readable
            && let Some(why) = &e.unreachable_via
        {
            // Mode bits alone: a directory between it and `/` stops other users (a 0700
            // HOME or project parent), as for transcript stores.
            f.push(Finding {
                severity: Severity::Low,
                category: "Secret exposure".into(),
                title: format!(
                    ".env is world-readable by mode ({} keys) — not reachable: {why}; tighten it to 0600 before that directory opens up",
                    e.key_count
                ),
                location: e.path.clone(),
                evidence: None,
            });
        } else if e.world_readable {
            let title = if keys_read && !credential_named {
                format!("{}; treated as exposed secrets", unparsed("world-readable"))
            } else {
                format!(".env is world-readable ({} keys)", e.key_count)
            };
            f.push(Finding {
                severity: Severity::High,
                category: "Secret exposure".into(),
                title,
                location: e.path.clone(),
                evidence: None,
            });
        }
    }

    // Agent transcript/state stores others can read (EAA-005 collection surface).
    // Value-gated on what other users can actually open: files with o+r reached through
    // directories with o+x (a store of 0600 files under a 0755 directory exposes names
    // only). An ancestor others cannot traverse (HOME 0700) makes it Low. Reports from
    // older versions carry no per-file count and are graded on the store's own mode.
    // Claude Code's stores are one finding per Claude Code config directory, i.e. per
    // scanned home ([`claude_store_finding`]); other agents' stores are one finding each.
    let mut claude_rows: Vec<(String, Vec<(&crate::models::AgentTranscriptStore, StoreRow)>)> = Vec::new();
    for t in &report.transcripts {
        use crate::scanners::transcripts::{ACCOUNT_STATE, ACCOUNT_STATE_BACKUP, store_exposure};
        if t.framework == "claude-code" {
            if let Some(row) = claude_store_row(t) {
                let parent = t.path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
                let key = if matches!(t.kind.as_str(), ACCOUNT_STATE | ACCOUNT_STATE_BACKUP) {
                    format!("{parent}/.claude")
                } else {
                    parent.to_string()
                };
                match claude_rows.iter_mut().find(|(k, _)| *k == key) {
                    Some((_, rows)) => rows.push((t, row)),
                    None => claude_rows.push((key, vec![(t, row)])),
                }
            }
            continue;
        }
        let (what, content) = store_exposure(&t.kind);
        let readable = t.readable_files.unwrap_or(t.file_count);
        let account = matches!(t.kind.as_str(), ACCOUNT_STATE | ACCOUNT_STATE_BACKUP);
        let (base, title) = if account && t.world_readable {
            (
                Severity::High,
                format!("{} {} ({what}) readable by other users", t.framework, t.kind),
            )
        } else if account && t.group_readable {
            (
                Severity::Medium,
                format!("{} {} ({what}) readable by its group", t.framework, t.kind),
            )
        } else if !account && t.world_readable && readable > 0 {
            (
                if content { Severity::High } else { Severity::Medium },
                format!(
                    "{} {} store is world-readable ({readable} of {} files readable by other users) — {what} (EAA-005)",
                    t.framework, t.kind, t.file_count
                ),
            )
        } else {
            continue;
        };
        let (severity, title) = match &t.unreachable_via {
            Some(why) => (Severity::Low, format!("{title} — not reachable: {why}")),
            None => (base, title),
        };
        f.push(Finding {
            severity,
            category: "Transcript exposure".into(),
            title,
            location: t.path.clone(),
            evidence: None,
        });
    }
    for (_, rows) in &claude_rows {
        if let Some(finding) = claude_store_finding(rows) {
            f.push(finding);
        }
    }

    // Auto-updating third-party plugin marketplaces (EAA-009): a non-official source
    // that pulls new remote code automatically hot-loads unreviewed agent code — the
    // rug-pull surface. Installing third-party plugins is normal, so this is advisory:
    // it fires only when auto-update is on AND the source isn't Anthropic-official.
    for m in &report.marketplaces {
        if m.auto_update && !m.official {
            f.push(Finding {
                severity: Severity::Medium,
                category: "Plugin marketplace".into(),
                title: format!(
                    "third-party plugin marketplace '{}' ({}) auto-updates — remote code hot-loads without review (EAA-009)",
                    m.name, m.source_ref
                ),
                location: "~/.claude/plugins/known_marketplaces.json".into(),
                evidence: None,
            });
        }
    }

    // Unprotected SSH keys: one finding per home, not one per key (nine identical Highs
    // on one machine said the same thing nine times). Every key stays its own row in
    // `ssh_keys[]`; the finding lists them.
    f.extend(ssh_key_findings(&report.ssh_keys));

    // Dangerous patterns in agent rules/instruction files.
    for rf in &report.rules_files {
        for finding in &rf.findings {
            let sev = match finding.severity.as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                _ => Severity::Low,
            };
            f.push(Finding {
                severity: sev,
                category: "Rules file".into(),
                title: format!("dangerous pattern: {}", finding.pattern),
                location: rf.path.clone(),
                evidence: None,
            });
        }
    }

    // MCP registry verification verdicts.
    for check in &report.mcp_registry_checks {
        match &check.verdict {
            crate::registry::RegistryVerdict::PossibleTyposquat { registered_as } => {
                f.push(Finding {
                    severity: Severity::Medium,
                    category: "Registry".into(),
                    title: format!(
                        "'{}' is one edit away from registered {} (possible typosquat)",
                        check.package, registered_as
                    ),
                    location: check.server_name.clone(),
                    evidence: None,
                });
            }
            crate::registry::RegistryVerdict::Registered { deprecated: true, .. } => {
                f.push(Finding {
                    severity: Severity::Medium,
                    category: "Registry".into(),
                    title: format!("{} is deprecated in the official MCP registry", check.package),
                    location: check.server_name.clone(),
                    evidence: None,
                });
            }
            _ => {}
        }
    }

    // Agent identity posture: static long-lived keys are the ASI03 anti-pattern.
    if let Some(id) = &report.agent_identity
        && !id.static_api_keys.is_empty()
    {
        let static_only = id.static_only();
        f.push(Finding {
            // Advisory by default; elevated when static keys are the ONLY auth in use.
            severity: if static_only { Severity::Medium } else { Severity::Low },
            category: "Agent identity".into(),
            title: format!(
                "{} static long-lived AI API key(s) in use ({}unbound bearer tokens, OWASP ASI03){}",
                id.static_api_keys.len(),
                if static_only { "sole credential; " } else { "" },
                if static_only {
                    " — no OAuth/SPIFFE detected; prefer short-lived scoped credentials"
                } else {
                    ""
                }
            ),
            location: id.static_api_keys.join(", "),
            evidence: None,
        });
    }

    // Servers that ran (per Claude Code's MCP log directory names) but that no config,
    // plugin or connector of this scan defines.
    for o in report.mcp_observed_servers.iter().filter(|o| !o.configured) {
        f.push(Finding {
            severity: Severity::Low,
            category: "MCP inventory".into(),
            title: format!(
                "MCP server '{}' ran but is not in any known config (logs in {} project(s); it may be a claude.ai connector or a removed plugin)",
                o.name, o.projects
            ),
            location: o.log_root.clone(),
            evidence: None,
        });
    }

    // Composition-level toxic-flow surface. High needs a leg that something connected
    // supplies (an active MCP server, a successful probe, a claude.ai connector); a
    // surface built only from keywords in skill files is Medium, and only when each leg
    // is mentioned by at least TOXIC_FLOW_MIN_MENTIONS skills (one skill that says
    // "curl" and "read_file" is not a flow).
    if let Some(tf) = analyze_toxic_flow(report) {
        let legs = format!(
            "sensitive source ({}) + exfil sink ({}) on the agent surface",
            tf.leg_title(&tf.sources),
            tf.leg_title(&tf.sinks)
        );
        let graded = if tf.server_backed() {
            Some((Severity::High, legs))
        } else if tf.leg_mentions(&tf.sources) >= TOXIC_FLOW_MIN_MENTIONS
            && tf.leg_mentions(&tf.sinks) >= TOXIC_FLOW_MIN_MENTIONS
        {
            Some((Severity::Medium, format!("{legs}, based on skill-file mentions only")))
        } else {
            None
        };
        if let Some((severity, title)) = graded {
            f.push(Finding {
                severity,
                category: "Toxic Flow".into(),
                title,
                location: report.device.hostname.clone(),
                evidence: Some(tf.evidence()),
            });
        }
    }

    collect_agent_surface_findings(report, &mut f);
    crate::analysis_surfaces::collect(report, &mut f);

    debug_assert!(
        f.iter().all(|x| FINDING_CATEGORIES.contains(&x.category.as_str())),
        "a finding category is missing from FINDING_CATEGORIES: {:?}",
        f.iter()
            .map(|x| x.category.as_str())
            .find(|c| !FINDING_CATEGORIES.contains(c))
    );
    f.sort_by_key(|x| x.severity.rank());
    f
}

/// A host that only resolves on the local network: a single-label name (a docker-compose
/// service such as `ollama` or `litellm`), `host.docker.internal`, a `.local` mDNS name,
/// or a private, link-local or shared-address IP literal. `<unparseable>` is not.
pub fn is_local_network_host(host: &str) -> bool {
    let h = host
        .trim_end_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if h.is_empty() || h.starts_with('<') {
        return false;
    }
    match h.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let o = v4.octets();
            v4.is_private() || v4.is_link_local() || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            let s = v6.segments()[0];
            (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80
        }
        Err(_) => {
            !h.contains('.')
                || matches!(
                    h.as_str(),
                    "host.docker.internal" | "gateway.docker.internal" | "host.containers.internal"
                )
                || h.ends_with(".local")
        }
    }
}

/// Where a hook came from, for grading. The ladder is the settings-hook policy per scope.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HookScope {
    /// A repository's file (project or local settings, `.github/hooks`, `.kiro/hooks`, a
    /// project skill or subagent).
    Repository { tracked: bool },
    /// The user's own file (user settings, `~/.claude/skills`, a local plugin).
    UserOwn,
    /// Machine policy.
    Managed,
    /// An active plugin from Anthropic's official marketplace.
    PluginOfficial,
    /// An active plugin from any other marketplace (every non-Claude-Code plugin).
    PluginThirdParty { key: (String, String), root: String },
    /// A disabled plugin, a marketplace clone, a synced skill: nothing loads it.
    Inactive,
}

/// The plugin root of a plugin hook file: the directory above `hooks/` or the manifest
/// directory, else the file's own directory.
fn plugin_root_of(path: &str) -> String {
    // A Claude Code plugin cache version is the root of every file in it
    // (`./config/hooks.json` too, now its own entry).
    let cached = plugin_install_root(path);
    if cached != path {
        return cached;
    }
    let p = std::path::Path::new(path);
    let parent = p.parent().unwrap_or(p);
    let up = matches!(
        parent.file_name().and_then(|n| n.to_str()),
        Some("hooks" | ".claude-plugin" | ".codex-plugin" | ".cursor-plugin")
    );
    let root = if up { parent.parent().unwrap_or(parent) } else { parent };
    root.to_string_lossy().to_string()
}

fn plugin_scope(prov: Option<&crate::models::SkillProvenance>, root: String) -> HookScope {
    match prov {
        Some(p) if !p.active => HookScope::Inactive,
        Some(p) if !p.third_party => HookScope::PluginOfficial,
        p => HookScope::PluginThirdParty {
            key: (
                p.and_then(|p| p.marketplace.clone()).unwrap_or_default(),
                p.and_then(|p| p.plugin.clone()).unwrap_or_default(),
            ),
            root,
        },
    }
}

fn hook_scope_for_settings(s: &crate::models::AgentSettings) -> HookScope {
    match s.source.as_str() {
        "project" | "local" => HookScope::Repository { tracked: s.git_tracked },
        "managed" => HookScope::Managed,
        "plugin" => plugin_scope(s.provenance.as_ref(), plugin_root_of(&s.path)),
        _ => HookScope::UserOwn,
    }
}

fn hook_scope_for_skill(k: &crate::models::AgentSkill) -> HookScope {
    let prov = k.provenance.as_ref();
    if k.scope == "project" {
        return HookScope::Repository {
            tracked: prov.and_then(|p| p.git.as_deref()) == Some("tracked"),
        };
    }
    if prov.is_some_and(|p| p.marketplace.is_some()) {
        return plugin_scope(prov, plugin_install_root(&k.path));
    }
    if prov.is_some_and(|p| p.synced) {
        return HookScope::Inactive;
    }
    HookScope::UserOwn
}

/// A hook's grade: its own finding, or one line in its third-party plugin's aggregated
/// Low finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HookGrade {
    Finding(Severity),
    Aggregate,
}

/// Where an http hook sends its events, for grading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpReach {
    /// Loopback, or the AI provider's own API (the official-host model).
    Local,
    /// A private, link-local or single-label host: the local network (graded as a LAN
    /// gateway in `.env` is, [`is_local_network_host`]).
    Lan,
    /// Anything else: off the machine and its network.
    Far,
}

fn http_reach(h: &crate::models::AgentHook) -> HttpReach {
    let host = h.url_host.as_deref().unwrap_or("");
    if crate::scanners::is_client_loopback_host(host) || h.first_party_host {
        HttpReach::Local
    } else if is_local_network_host(host) {
        HttpReach::Lan
    } else {
        HttpReach::Far
    }
}

/// The hook ladder (first matching row wins; `kind` "" is a command). Pure.
///
/// Command hooks keep main's settings-hook policy per scope. In a repository and in the
/// user's own settings: any dangerous-pattern hit is Critical (main graded every
/// pattern-matching settings hook Critical, whatever its scope); a cross-directory
/// reference is High. A repository's other hooks are Medium; the user's own are
/// inventory. In managed settings (machine policy, graded like managed credential
/// helpers: reported only when dangerous): a critical- or high-pattern hit is Critical,
/// a cross-directory reference High, anything else inventory.
///
/// Two user-scope rows are graded by what the hook does rather than by the substring:
/// a reference to another agent's config directory under the user's own HOME
/// (`~/.claude/hooks/fmt.sh` from `~/.codex/hooks.json`, one personal script shared by
/// several agents) is a Low advisory, and a notification hook that only pipes fields of
/// its own event to a web host (`jq -r .message | curl -d @- ntfy.sh/topic`,
/// [`crate::scanners::hook_sources::event_push_host`]) is graded as the http hook to that
/// host is (Low, naming it). Hits that are only inside a guard's test argument or a
/// loopback send (`advisory_patterns`) are not hits in any scope: such a hook is graded
/// as a plain one.
fn hook_severity(scope: &HookScope, h: &crate::models::AgentHook) -> Option<HookGrade> {
    use HookGrade::{Aggregate, Finding};
    use HookScope::*;
    use Severity::*;
    if h.disabled || h.kind == "unknown" || *scope == Inactive {
        return None;
    }
    let kind = if crate::scanners::hook_sources::is_command_kind(&h.kind) {
        "command"
    } else {
        h.kind.as_str()
    };
    let by =
        |repo: Option<Severity>, user: Option<Severity>, official: Option<Severity>, tp: Option<HookGrade>| match scope
        {
            Repository { .. } => repo.map(Finding),
            UserOwn => user.map(Finding),
            Managed | Inactive => None,
            PluginOfficial => official.map(Finding),
            PluginThirdParty { .. } => tp,
        };
    let code = matches!(kind, "command" | "module");
    if *scope == UserOwn && kind == "command" && user_event_push(h) {
        return Some(Finding(Low));
    }
    if code && h.dangerous {
        return Some(Finding(Critical));
    }
    if kind == "command" && !h.patterns.is_empty() && matches!(scope, Repository { .. } | UserOwn) {
        return Some(Finding(Critical));
    }
    let cross = |r: &String| r.starts_with("cross-references");
    if kind == "command" && h.risks.iter().any(cross) {
        if *scope == UserOwn
            && h.risks
                .iter()
                .filter(|r| cross(r))
                .all(|r| r.starts_with(crate::scanners::agent_settings::CROSS_HOME_RISK))
        {
            return Some(Finding(Low));
        }
        return match scope {
            Managed => Some(Finding(High)),
            _ => by(Some(High), Some(High), None, Some(Finding(High))),
        };
    }
    if kind == "http" {
        match http_reach(h) {
            HttpReach::Far => return by(Some(High), Some(Low), None, Some(Finding(Medium))),
            HttpReach::Lan | HttpReach::Local => return by(Some(Medium), None, None, Some(Aggregate)),
        }
    }
    if matches!(kind, "prompt" | "agent") && in_conversation(h) {
        // Text the agent itself reads (a Copilot CLI prompt hook, a Kiro agent action):
        // graded as an instruction file's text, not with the evaluator cap. A credential
        // path together with an injection phrase or hidden text is what a dangerous
        // command is (Critical in every scope); either alone, or a concealment or
        // override phrase, is High in a repository; phrases ordinary instructions also
        // use ("first read", "this is very important") are the plain repository row.
        // A credential path alone, and a concealment phrase guard wording also uses
        // ("never reveal any secret values you find") unless it is aimed at the user,
        // are one step lower: the repository's plain-command row (review of 4e3f8c3).
        let PromptSignals {
            cred,
            weak,
            soft,
            strong,
        } = prompt_signals(h);
        return if cred && (weak || strong) {
            match scope {
                Inactive => None,
                _ => Some(Finding(Critical)),
            }
        } else if strong {
            by(Some(High), Some(Low), Some(Low), Some(Finding(Medium)))
        } else if cred || weak || soft {
            by(Some(Medium), None, None, Some(Aggregate))
        } else {
            by(Some(Low), None, None, Some(Aggregate))
        };
    }
    if matches!(kind, "prompt" | "agent") {
        return if h.poisoning.is_empty() {
            by(Some(Low), None, None, Some(Aggregate))
        } else {
            // Capped at the plain repository command level: the text goes to the hook's
            // evaluator model, not into the agent's context (only its `reason` does).
            by(Some(Medium), Some(Low), Some(Low), Some(Finding(Low)))
        };
    }
    if kind == "mcp_tool" {
        return by(Some(Medium), None, None, Some(Aggregate));
    }
    if code && !h.patterns.is_empty() {
        return by(Some(Medium), Some(Low), None, Some(Aggregate));
    }
    by(Some(Medium), None, None, Some(Aggregate))
}

/// A prompt the agent itself reads ([`crate::models::AgentHook::prompt_target`]
/// "conversation" or "undocumented"); an evaluator prompt and an older report's
/// prompt (no target) are not.
fn in_conversation(h: &crate::models::AgentHook) -> bool {
    matches!(h.prompt_target.as_str(), "conversation" | "undocumented")
}

/// The signals of a prompt the agent reads, by kind.
struct PromptSignals {
    /// It names a credential path.
    cred: bool,
    /// A phrase ordinary instructions also use ([`crate::scanners::WEAK_CONTEXT_PHRASES`]).
    weak: bool,
    /// A concealment phrase not aimed at the user ([`crate::scanners::SOFT_CONCEALMENT_PHRASES`]).
    soft: bool,
    /// A concealment or override phrase, or hidden text.
    strong: bool,
}

fn prompt_signals(h: &crate::models::AgentHook) -> PromptSignals {
    let cred_sig = crate::scanners::hook_sources::CREDENTIAL_PATH_SIGNAL;
    let mut sig = PromptSignals {
        cred: false,
        weak: false,
        soft: false,
        strong: false,
    };
    for p in &h.poisoning {
        if p.starts_with(cred_sig) {
            sig.cred = true;
        } else if crate::scanners::WEAK_CONTEXT_PHRASES.contains(&p.as_str()) {
            sig.weak = true;
        } else if crate::scanners::SOFT_CONCEALMENT_PHRASES.contains(&p.as_str()) {
            sig.soft = true;
        } else {
            sig.strong = true;
        }
    }
    sig
}

/// The user's own notification hook: its only hit is the `| curl` / `| wget` row, and the
/// command is exactly a jq of its own event piped to a sender with a parseable host
/// (`push_host`), with no other risk.
fn user_event_push(h: &crate::models::AgentHook) -> bool {
    crate::scanners::hook_sources::is_event_push(h)
}

/// The finding title for one hook (see [`hook_severity`] for the grade).
fn hook_title(h: &crate::models::AgentHook, framework: &str, scope: &HookScope) -> String {
    let event = if framework.starts_with("claude-code") || framework.is_empty() {
        h.event.clone()
    } else {
        format!("{framework} {}", h.event)
    };
    let m = match (&h.matcher, &h.condition) {
        (m, Some(c)) => format!("{} if {c}", m.as_deref().unwrap_or("*")),
        (m, None) => m.as_deref().unwrap_or("*").to_string(),
    };
    let kind = if crate::scanners::hook_sources::is_command_kind(&h.kind) {
        "command"
    } else {
        h.kind.as_str()
    };
    let advisory = if h.advisory_patterns.is_empty() {
        String::new()
    } else {
        format!(
            "; matches {} only where it cannot run: a guard's test, a loopback send or the argument of a program that runs none (advisory)",
            h.advisory_patterns.join(", ")
        )
    };
    match kind {
        "http" => {
            let host = h.url_host.as_deref().unwrap_or("?");
            let plain = if h.url_scheme.as_deref() == Some("http") {
                " over plaintext http"
            } else {
                ""
            };
            let lan = if http_reach(h) == HttpReach::Lan {
                " (a local-network host)"
            } else {
                ""
            };
            format!("{event} hook [{m}] sends each event's JSON to {host}{lan}{plain}")
        }
        "prompt" | "agent" if in_conversation(h) => {
            let into = if h.prompt_target == "conversation" {
                "submits a prompt into the agent's conversation".to_string()
            } else {
                let who = if framework.is_empty() { "the agent" } else { framework };
                format!(
                    "sends a prompt that {who} does not document the handling of (graded as text in the agent's conversation)"
                )
            };
            let sig = prompt_signals(h);
            if h.poisoning.is_empty() {
                format!("{event} {kind} hook [{m}] {into} on each event (advisory)")
            } else if sig.strong || sig.weak {
                format!(
                    "{event} {kind} hook [{m}] {into} with prompt-injection signals ({})",
                    h.poisoning.join(", ")
                )
            } else {
                // Only a credential path and/or guard-style concealment wording: say what
                // it is, not "prompt injection".
                let cred_sig = crate::scanners::hook_sources::CREDENTIAL_PATH_SIGNAL;
                let paths: Vec<&str> = h.poisoning.iter().filter_map(|p| p.strip_prefix(cred_sig)).collect();
                let soft: Vec<&str> = h
                    .poisoning
                    .iter()
                    .filter(|p| !p.starts_with(cred_sig))
                    .map(String::as_str)
                    .collect();
                let mut parts = Vec::new();
                if !soft.is_empty() {
                    parts.push(format!("with concealment wording ({})", soft.join(", ")));
                }
                if !paths.is_empty() {
                    parts.push(format!("that names a credential path ({})", paths.join(", ")));
                }
                format!("{event} {kind} hook [{m}] {into} {}", parts.join(" and "))
            }
        }
        "prompt" | "agent" if !h.poisoning.is_empty() => format!(
            "{event} {kind} hook [{m}] gives its {} a prompt containing prompt-injection phrases ({})",
            if kind == "agent" {
                "hook subagent"
            } else {
                "hook evaluator model"
            },
            h.poisoning.join(", ")
        ),
        "prompt" | "agent" => format!("{event} {kind} hook [{m}] sends a model prompt on each event (advisory)"),
        "mcp_tool" => format!("{event} hook [{m}] calls MCP tool {}", h.command),
        "module" => {
            let regs = if h.registers.is_empty() {
                String::new()
            } else {
                format!(": registers {}", h.registers.join(", "))
            };
            let bad = if h.dangerous {
                format!(
                    " and a shell command it runs matches a dangerous pattern ({})",
                    h.patterns.join("; ")
                )
            } else if !h.patterns.is_empty() {
                format!("; a shell command it runs matches {}", h.patterns.join(", "))
            } else if !h.advisory_patterns.is_empty() {
                format!(
                    "; its code names a dangerous pattern outside any shell-execution call ({}) (advisory)",
                    h.advisory_patterns.join("; ")
                )
            } else {
                String::new()
            };
            // Framework-labelled like every other agent's hook (review of 4e3f8c3).
            let label = if framework.starts_with("claude-code") || framework.is_empty() {
                "claude-code mod"
            } else {
                framework
            };
            format!(
                "{label} hooks module {} runs inside the agent on its events{regs}{bad}",
                h.command
            )
        }
        _ => {
            let detail = if h.risks.is_empty() {
                String::new()
            } else {
                format!(" — {}", h.risks.join("; "))
            };
            let graded_as_match = h.dangerous
                || matches!(
                    scope,
                    HookScope::Repository { .. } | HookScope::Managed | HookScope::UserOwn
                );
            if *scope == HookScope::UserOwn && user_event_push(h) {
                let host = h.push_host.as_deref().unwrap_or("?");
                format!(
                    "{event} hook [{m}] runs a command that sends fields of its event to {host} (a notification hook)"
                )
            } else if !h.patterns.is_empty() && graded_as_match {
                format!(
                    "{event} hook [{m}] runs a command matching a dangerous pattern ({}){detail}{advisory}",
                    h.patterns.join(", ")
                )
            } else if !h.patterns.is_empty() {
                format!(
                    "{event} hook [{m}] runs a command{detail}; matches {}{advisory}",
                    h.patterns.join(", ")
                )
            } else if *scope == HookScope::UserOwn
                && h.risks
                    .iter()
                    .any(|r| r.starts_with(crate::scanners::agent_settings::CROSS_HOME_RISK))
            {
                format!("{event} hook [{m}] runs a command{detail} (advisory)")
            } else {
                format!("{event} hook [{m}] runs a command{detail}{advisory}")
            }
        }
    }
}

/// Settings commands Claude Code alone runs (not hooks other agents import).
fn claude_only_setting(h: &crate::models::AgentHook) -> bool {
    h.kind == crate::scanners::hook_sources::SETTINGS_COMMAND_KIND
}

/// Agents other than Claude Code that run the hooks of a Claude Code settings file, by
/// default (fetched 2026-10-23): Cursor reads `~/.claude/settings.json`,
/// `.claude/settings.json` and `.claude/settings.local.json`
/// (cursor.com/docs/reference/third-party-hooks, "on by default"); GitHub Copilot CLI the
/// repository's two (docs.github.com/en/copilot/reference/hooks-configuration); Devin CLI
/// all of them (docs.devin.ai/cli/extensibility/hooks/overview, `read_config_from.claude`
/// default). None of them is bound by Claude Code's managed policy.
fn claude_settings_importers(s: &crate::models::AgentSettings) -> Option<&'static str> {
    let p = std::path::Path::new(&s.path);
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let in_claude_dir = p.parent().and_then(|d| d.file_name()).is_some_and(|d| d == ".claude");
    if s.framework != "claude-code" || !in_claude_dir || !matches!(name, "settings.json" | "settings.local.json") {
        return None;
    }
    match s.source.as_str() {
        "project" | "local" => Some("Cursor, GitHub Copilot CLI and Devin CLI"),
        "user-global" => Some("Cursor and Devin CLI"),
        // Cursor documents no user-level settings.local.json
        // (cursor.com/docs/reference/third-party-hooks, fetched 2026-10-23); Devin CLI
        // reads it (docs.devin.ai/cli/extensibility/hooks/overview).
        "user-local" => Some("Devin CLI"),
        _ => None,
    }
}

/// Claude Code's managed hook policy, from the managed settings files.
struct ManagedPolicy {
    /// A managed `allowManagedHooksOnly` or `disableAllHooks`.
    managed_only: bool,
    /// A managed `disableAllHooks` (managed hooks are off too).
    managed_off: bool,
    /// Plugins the managed `enabledPlugins` force-enables (`plugin@marketplace`).
    forced: BTreeSet<String>,
}

impl ManagedPolicy {
    fn of(settings: &[crate::models::AgentSettings]) -> Self {
        let managed = || {
            settings
                .iter()
                .filter(|s| s.source == "managed" && s.framework == "claude-code")
        };
        ManagedPolicy {
            managed_only: managed().any(|s| s.allow_managed_hooks_only || s.disable_all_hooks),
            managed_off: managed().any(|s| s.disable_all_hooks),
            forced: managed()
                .flat_map(|s| s.force_enabled_plugins.iter().cloned())
                .collect(),
        }
    }

    fn policy(&self) -> &'static str {
        if self.managed_off {
            "disableAllHooks"
        } else {
            "allowManagedHooksOnly"
        }
    }

    /// Whether Claude Code skips a hook of `framework` in `scope` under this policy
    /// (before the other-agents exemption of [`claude_settings_importers`]).
    fn silences(&self, framework: &str, scope: &HookScope, prov: Option<&crate::models::SkillProvenance>) -> bool {
        let plugin_key = prov.and_then(|p| Some(format!("{}@{}", p.plugin.as_deref()?, p.marketplace.as_deref()?)));
        framework.starts_with("claude-code")
            && self.managed_only
            && (*scope != HookScope::Managed || self.managed_off)
            && !plugin_key.is_some_and(|k| self.forced.contains(&k))
    }
}

/// Mark every hook the managed Claude Code policy silences as disabled, with the policy
/// as its reason, so the inactive count, the terminal, HTML and Blueprint agree with the
/// grading ([`collect_hook_findings`] skips the same hooks). A hook another agent also
/// runs ([`claude_settings_importers`]) stays active. Run once on a fresh scan, before
/// the summary.
pub fn apply_managed_hook_policy(report: &mut ScanReport) {
    let mp = ManagedPolicy::of(&report.agent_settings);
    if !mp.managed_only {
        return;
    }
    let reason = format!("managed {}", mp.policy());
    let mut off = |h: &mut crate::models::AgentHook| {
        if !h.disabled {
            h.disabled = true;
            h.disabled_reason = Some(reason.clone());
        }
    };
    for s in &mut report.agent_settings {
        let scope = hook_scope_for_settings(s);
        if !mp.silences(&s.framework, &scope, s.provenance.as_ref()) {
            continue;
        }
        let others = claude_settings_importers(s).is_some();
        for h in s.hooks.iter_mut().filter(|h| !others || claude_only_setting(h)) {
            off(h);
        }
    }
    for k in &mut report.agent_skills {
        let scope = hook_scope_for_skill(k);
        if !k.hooks.is_empty() && mp.silences("claude-code", &scope, k.provenance.as_ref()) {
            k.hooks.iter_mut().for_each(&mut off);
        }
    }
}

/// Grade every hook: settings and plugin files (agent_settings) and skill, command and
/// subagent frontmatter (agent_skills). A managed Claude Code `allowManagedHooksOnly` or
/// `disableAllHooks` silences the non-managed Claude Code hooks only Claude Code runs
/// (inventory kept), and a managed `disableAllHooks` silences managed hooks too. Not
/// silenced: hooks of a plugin the managed `enabledPlugins` force-enables (exempt, per
/// code.claude.com/docs/en/hooks), and the `hooks` of a `.claude/settings*.json`, which
/// other agents also run ([`claude_settings_importers`]); those keep their grade with a
/// note.
fn collect_hook_findings(report: &ScanReport, f: &mut Vec<Finding>) {
    use std::collections::BTreeMap;
    let mp = ManagedPolicy::of(&report.agent_settings);
    let policy = mp.policy();
    // (marketplace, plugin) -> (framework, plugin root, events, hook count, first (path, command))
    type Agg = (String, String, BTreeSet<String>, usize, Option<(String, String)>);
    let mut agg: BTreeMap<(String, String), Agg> = BTreeMap::new();
    // `note`: set when the hook is kept despite a managed policy, because other agents run it.
    let mut grade = |h: &crate::models::AgentHook,
                     framework: &str,
                     scope: HookScope,
                     location: &str,
                     prefix: &str,
                     note: Option<&str>,
                     f: &mut Vec<Finding>| {
        if let Some(g) = fail_open_guard_finding(h, &scope, location, prefix) {
            f.push(g);
        }
        match hook_severity(&scope, h) {
            None => {}
            Some(HookGrade::Finding(severity)) => {
                let mut title = format!("{prefix}{}", hook_title(h, framework, &scope));
                if let HookScope::PluginThirdParty { key: (m, p), .. } = &scope {
                    title.push_str(&format!(" ({} '{p}@{m}')", plugin_label(framework)));
                }
                if let Some(others) = note {
                    title.push_str(&format!(
                        " (Claude Code skips it under the managed {policy}; {others} still run this file's hooks)"
                    ));
                }
                f.push(Finding {
                    severity,
                    category: "Hook".into(),
                    title,
                    location: location.to_string(),
                    evidence: Some(h.command.clone()),
                })
            }
            Some(HookGrade::Aggregate) => {
                if let HookScope::PluginThirdParty { key, root } = scope {
                    let e = agg
                        .entry(key)
                        .or_insert_with(|| (framework.to_string(), root, BTreeSet::new(), 0, None));
                    if h.kind == "module" {
                        if h.registers.is_empty() {
                            e.2.insert("a hooks module".to_string());
                        } else {
                            e.2.extend(h.registers.iter().cloned());
                        }
                    } else {
                        e.2.insert(h.event.clone());
                    }
                    e.3 += 1;
                    let cand = (location.to_string(), h.command.clone());
                    if e.4.as_ref().is_none_or(|(p, _)| cand.0 < *p) {
                        e.4 = Some(cand);
                    }
                }
            }
        }
    };
    let silenced = |framework: &str, scope: &HookScope, prov: Option<&crate::models::SkillProvenance>| {
        mp.silences(framework, scope, prov)
    };
    for s in &report.agent_settings {
        let scope = hook_scope_for_settings(s);
        let others = claude_settings_importers(s);
        for h in &s.hooks {
            let mut note = None;
            if silenced(&s.framework, &scope, s.provenance.as_ref()) {
                match others {
                    Some(o) if !claude_only_setting(h) => note = Some(o),
                    _ => continue,
                }
            }
            grade(h, &s.framework, scope.clone(), &s.path, "", note, f);
        }
    }
    for k in &report.agent_skills {
        if k.hooks.is_empty() {
            continue;
        }
        let scope = hook_scope_for_skill(k);
        if silenced("claude-code", &scope, k.provenance.as_ref()) {
            continue;
        }
        let loc = crate::scanners::sanitize_display(&k.path, 512);
        let what = if k.framework == "claude-code-agent" || k.file_type == "agent" {
            "subagent"
        } else {
            "skill"
        };
        let prefix = format!("{what} '{}': ", k.name);
        for h in &k.hooks {
            grade(h, "claude-code", scope.clone(), &loc, &prefix, None, f);
        }
    }
    for s in &report.agent_settings {
        if let Some(f0) = cross_agent_link(s) {
            f.push(f0);
        }
    }
    for ((m, p), (framework, root, events, n, first)) in agg {
        f.push(Finding {
            severity: Severity::Low,
            category: "Hook".into(),
            title: format!(
                "{} '{p}@{m}' registers {n} hook(s) that run on agent events: {}",
                plugin_label(&framework),
                first_names(&events)
            ),
            location: crate::scanners::sanitize_display(&root, 512),
            evidence: first.map(|(_, c)| c),
        });
    }
}

/// A hook that runs `destructive_command_guard` (dcg) below 0.6.6, a PreToolUse safety
/// hook with a known fail-open bug: CVE-2026-77474 / GHSA-4cfr-w3v5-w5j5 (GitHub CNA,
/// CVSS 3.1 7.1; NVD affected "< 0.6.6", fixed in v0.6.6). A crafted command (a
/// destructive command followed by nested or unclosed `$(`) hangs the guard, the agent
/// treats the hung hook as allow, and the command runs. Medium when the install path
/// states an affected version (the guard still blocks ordinary commands; the bypass
/// needs a crafted one), Low when no version is stated, none at or above the fix or when
/// nothing runs the hook. Separate from the hook ladder, which grades what the hook can
/// do, not whether a guard can be bypassed.
fn fail_open_guard_finding(
    h: &crate::models::AgentHook,
    scope: &HookScope,
    location: &str,
    prefix: &str,
) -> Option<Finding> {
    use crate::scanners::hook_sources::{FAIL_OPEN_GUARD_FIX, FailOpenGuard, fail_open_guard};
    if *scope == HookScope::Inactive {
        return None;
    }
    let plugin = matches!(scope, HookScope::PluginOfficial | HookScope::PluginThirdParty { .. });
    let (major, minor, patch) = FAIL_OPEN_GUARD_FIX;
    let fix = format!("{major}.{minor}.{patch}");
    let (severity, title, how) = match fail_open_guard(h, location, plugin)? {
        FailOpenGuard::Affected(v) => (
            Severity::Medium,
            format!(
                "{prefix}Safety hook with a known fail-open bug (CVE-2026-77474): a hanging guard lets the command through — destructive_command_guard {v}; update to {fix} or later (`dcg update`)"
            ),
            format!("version {v} read from the install path"),
        ),
        FailOpenGuard::Unknown => (
            Severity::Low,
            format!(
                "{prefix}Safety hook of a known fail-open class (CVE-2026-77474), version unknown: destructive_command_guard below {fix} lets a command through when the guard hangs; check `dcg --version` and update to {fix} or later"
            ),
            "the install path states no version (the binary is not run)".to_string(),
        ),
    };
    Some(Finding {
        severity,
        category: "Hook".into(),
        title,
        location: location.to_string(),
        evidence: Some(format!(
            "{}; advisories: CVE-2026-77474, GHSA-4cfr-w3v5-w5j5 (fixed in {fix}); {how}",
            h.command
        )),
    })
}

/// The user's own hook or settings file that is a symlink into another agent's
/// directory in the same home (`~/.codex/hooks.json -> ../.claude/codex-hooks.json`):
/// one hook setup shared across agents, the ordinary multi-agent case. It is not read
/// (agent configuration is never followed), so it is a Low advisory naming the link,
/// not a skill-symlink finding (review of 4e3f8c3). Judged lexically; a target named
/// like a credential is left to the inventory row.
fn cross_agent_link(s: &crate::models::AgentSettings) -> Option<Finding> {
    use crate::scanners::agent_settings::AGENT_CONFIG_DIRS;
    use crate::scanners::persistence::{is_agent_credential_path, is_sensitive_read_name, lexical_join};
    use std::path::{Component, Path, PathBuf};
    let l = s.symlink.as_ref()?;
    if !matches!(s.source.as_str(), "user-global" | "user-local") {
        return None;
    }
    let path = Path::new(&s.path);
    let comps: Vec<Component> = path.components().collect();
    let own_at = comps
        .iter()
        .position(|c| c.as_os_str().to_str().is_some_and(|c| AGENT_CONFIG_DIRS.contains(&c)))?;
    let home: PathBuf = comps[..own_at].iter().collect();
    let own = comps[own_at].as_os_str();
    let target = lexical_join(path.parent()?, Path::new(&l.target));
    let rel = target.strip_prefix(&home).ok()?;
    let other = rel.components().next()?.as_os_str();
    if other == own || !other.to_str().is_some_and(|o| AGENT_CONFIG_DIRS.contains(&o)) {
        return None;
    }
    if is_sensitive_read_name(&target) || is_agent_credential_path(&target, None) {
        return None;
    }
    Some(Finding {
        severity: Severity::Low,
        category: "Hook".into(),
        title: format!(
            "{} hook file is a symlink into another agent's directory in your home ({}) — not read (advisory)",
            s.framework, l.target
        ),
        location: crate::scanners::sanitize_display(&s.path, 512),
        evidence: Some(l.target.clone()),
    })
}

/// How a non-official plugin is named in a title: Claude Code has an official-marketplace
/// model, so its other plugins are third-party; other agents' plugins are graded the same
/// way, but nothing verified says who published them.
fn plugin_label(framework: &str) -> &'static str {
    if framework.starts_with("claude-code") {
        "third-party plugin"
    } else {
        "plugin (provenance not verified)"
    }
}

/// `~/.claude/plugins/cache/<m>/<p>/<v>` for a path inside a plugin cache version.
fn plugin_install_root(path: &str) -> String {
    let p = std::path::Path::new(path);
    let comps: Vec<_> = p.components().collect();
    for (i, c) in comps.iter().enumerate() {
        if c.as_os_str() == "cache" && i > 0 && comps[i - 1].as_os_str() == "plugins" && comps.len() > i + 3 {
            return comps[..=i + 3]
                .iter()
                .collect::<std::path::PathBuf>()
                .to_string_lossy()
                .to_string();
        }
    }
    path.to_string()
}

/// How a plugin's skill is named in an aggregated finding: a manifest by its bundle
/// name, a command or script by its path inside the plugin version (`commands/x.md`).
fn plugin_skill_label(skill: &crate::models::AgentSkill, root: &str) -> String {
    if skill.file_type == "skill-manifest" {
        return skill.name.clone();
    }
    match std::path::Path::new(&skill.path).strip_prefix(root) {
        Ok(rel) => crate::scanners::sanitize_display(&rel.to_string_lossy(), 128),
        Err(_) => skill.name.clone(),
    }
}

fn first_names(names: &BTreeSet<String>) -> String {
    let shown: Vec<&str> = names.iter().take(5).map(String::as_str).collect();
    let more = names.len().saturating_sub(5);
    if more > 0 {
        format!("{} (+{more} more)", shown.join(", "))
    } else {
        shown.join(", ")
    }
}

/// Plugin pins, skills, .env agent overrides, extensions and OLLAMA_HOST binds.
fn collect_agent_surface_findings(report: &ScanReport, f: &mut Vec<Finding>) {
    use std::collections::BTreeMap;

    // ── A. Plugin4Shell pins ──
    for m in &report.marketplaces {
        for i in &m.pin_issues {
            let p = i.plugin.as_deref().unwrap_or("");
            let (severity, title) = match i.kind.as_str() {
                // Graded like the other ref kinds: a commit-named branch whose tip is the
                // commit it is named after is a pin that floats with a branch (Medium);
                // one that points elsewhere, or cannot be resolved, is the exploit shape.
                "head-on-sha-branch" => (
                    if i.mismatch {
                        Severity::Critical
                    } else {
                        Severity::Medium
                    },
                    format!(
                        "marketplace '{}' is checked out on a branch named like a commit{} — Plugin4Shell shape (CVE-2026-86063)",
                        m.name,
                        if i.mismatch {
                            " that points at a different commit"
                        } else {
                            ""
                        }
                    ),
                ),
                "sha-shaped-ref" => (
                    if i.mismatch {
                        Severity::Critical
                    } else {
                        Severity::Medium
                    },
                    format!(
                        "marketplace '{}' has a ref named like a commit{}",
                        m.name,
                        if i.mismatch {
                            " that points at a different commit"
                        } else {
                            ""
                        }
                    ),
                ),
                "fetch-head-sha-branch" => (
                    if i.mismatch {
                        Severity::Critical
                    } else {
                        Severity::Medium
                    },
                    format!(
                        "marketplace '{}' last fetched a branch named like a commit{}",
                        m.name,
                        if i.mismatch {
                            ", which resolved to a different commit"
                        } else {
                            ""
                        }
                    ),
                ),
                // Three different things a non-commit sha can be; each gets its own words.
                k @ ("manifest-sha-not-commit" | "manifest-sha-abbreviated" | "manifest-sha-empty") => {
                    let who = if i.plugin.is_some() {
                        format!("plugin '{p}' from '{}'", m.name)
                    } else {
                        format!("marketplace '{}'", m.name)
                    };
                    match k {
                        "manifest-sha-abbreviated" => (
                            Severity::Medium,
                            format!(
                                "{who} is pinned to an abbreviated commit ID — it is resolved by name, so a branch of that name would win; use the full 40-hex ID"
                            ),
                        ),
                        "manifest-sha-empty" => (
                            Severity::Low,
                            format!("{who} has an empty sha — no commit pin is recorded, so it follows its ref"),
                        ),
                        _ => (
                            Severity::Medium,
                            format!(
                                "{who} is pinned to a branch or tag name, not a commit — the pin moves with the branch"
                            ),
                        ),
                    }
                }
                "manifest-ref-is-sha" if i.plugin.is_some() => (
                    Severity::Medium,
                    format!(
                        "plugin '{p}' from '{}' gives a commit ID as its ref with no sha pin — a branch of that name would win",
                        m.name
                    ),
                ),
                // A marketplace source has no `sha` field (github: repo/ref/path/sparsePaths;
                // git: url/ref/path/sparsePaths), so a commit ID in `ref` is the only way to
                // ask for one. The on-disk ref checks above already report a shadowing
                // branch if one exists; this is the residual advisory.
                "manifest-ref-is-sha" => (
                    Severity::Low,
                    format!(
                        "marketplace '{}' gives a commit ID as its ref — marketplace sources cannot pin a commit (ref is resolved as a branch or tag name, so a branch of that name would win); pin a tag you control instead",
                        m.name
                    ),
                ),
                "installed-sha-not-commit" => (
                    Severity::Medium,
                    format!(
                        "installed plugin '{p}@{}' records a gitCommitSha that is a name, not a commit ID",
                        m.name
                    ),
                ),
                "installed-sha-abbreviated" => (
                    Severity::Medium,
                    format!(
                        "installed plugin '{p}@{}' records an abbreviated gitCommitSha — a branch of that name would win; a full 40-hex ID cannot be shadowed",
                        m.name
                    ),
                ),
                "installed-sha-empty" => (
                    Severity::Low,
                    format!(
                        "installed plugin '{p}@{}' records an empty gitCommitSha — no commit pin is recorded",
                        m.name
                    ),
                ),
                _ => continue,
            };
            f.push(Finding {
                severity,
                category: "Plugin pin".into(),
                title,
                location: i.path.clone(),
                evidence: Some(i.detail.clone()),
            });
        }
    }

    // ── B. Skills: escaping symlinks, dynamic context, unrestricted Bash grants ──
    let shell_disabled = report
        .agent_settings
        .iter()
        .any(|s| matches!(s.source.as_str(), "user-global" | "managed") && s.disable_skill_shell_execution);
    // disableSkillShellExecution is honoured from any settings file (settings-reference
    // scope "Any file"), and a project can only make itself safer, so a project's own
    // .claude/settings.json or settings.local.json setting it silences that project's
    // skills: `<proj>/.claude/` for each such file.
    let shell_disabled_projects: Vec<String> = report
        .agent_settings
        .iter()
        .filter(|s| matches!(s.source.as_str(), "project" | "local") && s.disable_skill_shell_execution)
        .filter_map(|s| {
            let p = std::path::Path::new(&s.path);
            let agent_dir = p.parent()?;
            (agent_dir.file_name()? == ".claude").then(|| format!("{}/", agent_dir.to_string_lossy()))
        })
        .collect();
    // (marketplace, plugin) -> (install root, skill names, (path, first command))
    type PluginKey = (String, String);
    type CmdAgg = (String, BTreeSet<String>, Option<(String, String)>);
    type GrantAgg = (String, BTreeSet<String>, BTreeSet<String>);
    let mut plugin_cmds: BTreeMap<PluginKey, CmdAgg> = BTreeMap::new();
    // (marketplace, plugin) -> (install root, skill names, file paths)
    let mut plugin_grants: BTreeMap<PluginKey, GrantAgg> = BTreeMap::new();
    for skill in &report.agent_skills {
        // AgentSkill.path is the raw path (a directory name is attacker-chosen text).
        let loc = crate::scanners::sanitize_display(&skill.path, 512);
        // A /nix/store target (home-manager) is read-only and content-addressed: inventory.
        // Reported: a link refused as sensitive, or one that leaves its skill directory /
        // repository / plugin and was therefore not read. A link that was followed (your
        // own link into your own skill areas or files, a plugin's link inside the plugin)
        // stays in the inventory (agent_skills[].symlink): the guidance calls those benign.
        if let Some(l) = &skill.symlink
            && !l.store
            && (l.sensitive_target || (l.escapes && !l.followed))
            // The user's own broken link loads nothing and exposes nothing: inventory
            // only. A repository's or plugin's dangling link out of its tree is reported
            // (it goes live the moment its target appears).
            && (!l.dangling
                || skill.scope == "project"
                || skill.provenance.as_ref().is_some_and(|p| p.marketplace.is_some()))
        {
            let via = if l.through_directory {
                "is reached through a symlinked directory"
            } else {
                "is a symlink"
            };
            let within = if skill.scope == "project" {
                "its project"
            } else if skill.provenance.as_ref().is_some_and(|p| p.marketplace.is_some()) {
                "its plugin"
            } else {
                "its skill directory"
            };
            let directory = skill.file_type == "directory";
            // What the refused target is, in words that are true of it: a /var/tmp
            // SKILL.md is "a system path", not "a credential, key or shell-rc path".
            let into = match l.sensitive_kind.as_deref() {
                Some("credential") => "a credential, key, .env or shell-rc path",
                Some("agent-config") => "agent config",
                Some("other-home") => "another user's home",
                Some("system") => "a system path",
                // Reports written before sensitive_kind existed.
                _ => "a credential, key, shell-rc, agent-config or system path",
            };
            let credential = l.sensitive_kind.as_deref().is_none_or(|k| k == "credential");
            // The user's own global-scope link to a skill (a directory, or a SKILL.md / *.md
            // file) under /var, /run or ~/.claude is how people keep skills elsewhere
            // (/var/home on Silverblue, a skills-archive). Nothing is read, so Low; High
            // stays for credential-named targets and for repository and plugin links.
            let own_global =
                skill.scope != "project" && skill.provenance.as_ref().is_none_or(|p| p.marketplace.is_none());
            let md_target = l
                .target
                .rsplit('/')
                .next()
                .is_some_and(|n| n.to_ascii_lowercase().ends_with(".md"));
            // A link reached through a symlinked directory names that directory.
            let skill_shaped = directory || l.through_directory || md_target;
            let (severity, title) = if directory && l.sensitive_target && own_global && skill_shaped && !credential {
                (
                    Severity::Low,
                    format!(
                        "skill directory '{}' points outside the skills directory (into {into}) — not listed or read",
                        skill.name
                    ),
                )
            } else if directory && l.sensitive_target {
                (
                    Severity::High,
                    format!(
                        "skill directory '{}' is a symlink into {into} — not listed or read",
                        skill.name
                    ),
                )
            } else if directory {
                (
                    Severity::Low,
                    format!(
                        "skill directory '{}' is a symlink that resolves outside {within} — not listed or read",
                        skill.name
                    ),
                )
            } else if l.sensitive_target && own_global && skill_shaped && !credential {
                (
                    Severity::Low,
                    format!(
                        "skill file '{}' points outside the skills directory (into {into}) — not read",
                        skill.name
                    ),
                )
            } else if l.sensitive_target {
                (
                    Severity::High,
                    format!("skill file '{}' {via} into {into} — not read", skill.name),
                )
            } else if l.dangling {
                (
                    Severity::Low,
                    format!(
                        "skill file '{}' is a dangling symlink that points outside {within} — nothing to read",
                        skill.name
                    ),
                )
            } else {
                (
                    Severity::Low,
                    format!(
                        "skill file '{}' {via} that resolves outside {within} — not read",
                        skill.name
                    ),
                )
            };
            f.push(Finding {
                severity,
                category: "Skill symlink".into(),
                title,
                location: loc.clone(),
                // The bare target: the renderers draw their own arrow.
                evidence: Some(l.target.clone()),
            });
        }
        let prov = skill.provenance.as_ref();
        let synced = prov.is_some_and(|p| p.synced);
        let is_plugin = prov.is_some_and(|p| p.marketplace.is_some());
        let active = prov.is_some_and(|p| p.active);
        let loadable = !synced && (!is_plugin || active);
        let third_active = prov.is_some_and(|p| p.third_party && p.active);
        let project = skill.scope == "project";
        let git = prov.and_then(|p| p.git.as_deref());
        let plugin_key = || {
            (
                prov.and_then(|p| p.marketplace.clone()).unwrap_or_default(),
                prov.and_then(|p| p.plugin.clone()).unwrap_or_default(),
            )
        };

        let project_shell_disabled = project
            && shell_disabled_projects
                .iter()
                .any(|p| skill.path.starts_with(p.as_str()));
        if loadable && !shell_disabled && !project_shell_disabled && !skill.dynamic_commands.is_empty() {
            let matched = || -> BTreeSet<&str> {
                skill
                    .dynamic_commands
                    .iter()
                    .flat_map(|d| d.patterns.iter().map(String::as_str))
                    .collect()
            };
            if let Some(d) = skill.dynamic_commands.iter().find(|d| d.dangerous) {
                f.push(Finding {
                    severity: Severity::High,
                    category: "Skill command".into(),
                    title: format!(
                        "skill '{}' runs a shell command matching a dangerous pattern when it loads ({})",
                        skill.name,
                        d.patterns.join("; ")
                    ),
                    location: loc.clone(),
                    evidence: Some(d.command.clone()),
                });
            } else if third_active {
                let e = plugin_cmds
                    .entry(plugin_key())
                    .or_insert_with(|| (plugin_install_root(&skill.path), BTreeSet::new(), None));
                e.1.insert(plugin_skill_label(skill, &e.0));
                let cand = (skill.path.clone(), skill.dynamic_commands[0].command.clone());
                if e.2.as_ref().is_none_or(|(p, _)| cand.0 < *p) {
                    e.2 = Some(cand);
                }
            } else if project
                && !(git == Some("tracked")
                    && skill
                        .dynamic_commands
                        .iter()
                        .all(|d| d.patterns.is_empty() && is_read_only_context_command(&d.command)))
            {
                // A committed skill whose every command is a read-only context command
                // (git status, gh pr view: the documented use) stays in the inventory.
                let origin = match git {
                    Some("tracked") => "project (git-tracked)",
                    Some(_) => "project (not committed to its git repository)",
                    None => "project",
                };
                // Medium-only pattern hits (printenv, an API_KEY name) are named but do not
                // raise the grade.
                let matched = matched();
                let note = if matched.is_empty() {
                    String::new()
                } else {
                    format!("; matches {}", matched.into_iter().collect::<Vec<_>>().join(", "))
                };
                f.push(Finding {
                    severity: Severity::Low,
                    category: "Skill command".into(),
                    title: format!(
                        "{origin} skill '{}' runs {} shell command(s) when it loads (dynamic context{note})",
                        skill.name,
                        skill.dynamic_commands.len()
                    ),
                    location: loc.clone(),
                    evidence: Some(skill.dynamic_commands[0].command.clone()),
                });
            } else if !project
                && !is_plugin
                && let Some(d) = skill.dynamic_commands.iter().find(|d| !d.patterns.is_empty())
            {
                // The user's own skill: any dangerous-pattern match is named, as it would be
                // for a hook. Only medium rows matched (a critical or high one, or data sent
                // to the network, is the High branch above), so it is advisory.
                f.push(Finding {
                    severity: Severity::Low,
                    category: "Skill command".into(),
                    title: format!(
                        "skill '{}' runs a shell command matching {} when it loads (dynamic context; advisory)",
                        skill.name,
                        matched().into_iter().collect::<Vec<_>>().join(", ")
                    ),
                    location: loc.clone(),
                    evidence: Some(d.command.clone()),
                });
            }
        }

        if skill.unrestricted_bash {
            if third_active {
                let e = plugin_grants
                    .entry(plugin_key())
                    .or_insert_with(|| (plugin_install_root(&skill.path), BTreeSet::new(), BTreeSet::new()));
                e.1.insert(plugin_skill_label(skill, &e.0));
                e.2.insert(skill.path.clone());
            } else if project && git == Some("untracked") {
                // A git-tracked grant is the repository's reviewable, documented choice and
                // stays in the inventory (agent_skills[].unrestricted_bash). An untracked
                // one in a repository arrived some other way (a tool, a script, an
                // unreviewed drop) and is worth a look.
                f.push(Finding {
                    severity: Severity::Low,
                    category: "Skill grant".into(),
                    title: format!(
                        "project skill '{}' pre-approves unrestricted Bash and is not committed to its git repository (added locally, by you or a tool)",
                        skill.name
                    ),
                    location: loc.clone(),
                    evidence: None,
                });
            }
        }
    }
    for ((m, p), (root, names, first)) in &plugin_cmds {
        f.push(Finding {
            severity: Severity::Low,
            category: "Skill command".into(),
            title: format!(
                "third-party plugin '{p}@{m}' runs shell commands when its skills load: {}",
                first_names(names)
            ),
            location: crate::scanners::sanitize_display(root, 512),
            evidence: first.as_ref().map(|(_, c)| c.clone()),
        });
    }
    for ((m, p), (root, names, files)) in &plugin_grants {
        f.push(Finding {
            severity: Severity::Low,
            category: "Skill grant".into(),
            title: format!(
                "third-party plugin '{p}@{m}' pre-approves unrestricted Bash in {} skill(s)/command(s): {}",
                files.len(),
                first_names(names)
            ),
            location: crate::scanners::sanitize_display(root, 512),
            evidence: None,
        });
    }

    // ── C. .env agent-home / gateway / proxy / headers / OLLAMA_HOST ──
    for e in &report.env_files {
        // Coding agents load a project's `.env` (Gemini CLI, aider) and nothing else:
        // `.env.local`, `.env.development`, `.env.production` and `.env.test` are an
        // application framework's per-mode config (Next.js, Vite, dotenv-flow). A
        // committed one is the app's build config, not repository-controlled agent
        // redirection, so it is advisory and worded as such.
        let file_name = e.path.rsplit(['/', '\\']).next().unwrap_or("");
        let mode_file = file_name != ".env";
        let t = e.git_tracked && !mode_file;
        let tracked = if e.git_tracked { " git-tracked" } else { "" };
        let app_note = if mode_file {
            format!(" ({file_name} is application config; coding agents do not load it by default)")
        } else {
            String::new()
        };
        for o in &e.agent_overrides {
            let value = o.value.as_deref().unwrap_or("");
            let gemini = o.key.starts_with("GEMINI") || o.key.starts_with("GOOGLE_GEMINI");
            let gemini_note = if mode_file {
                app_note.clone()
            } else if gemini {
                " (Gemini CLI loads project .env files itself)".to_string()
            } else {
                String::new()
            };
            let finding = match o.kind.as_str() {
                // Graded by where the home points. Inside the repository, the repository
                // author writes the settings, hooks and MCP servers the agent loads
                // (CVE-2026-13745). Outside it (a devcontainer home such as
                // /home/node/.claude, the user's own directory) nothing the repository
                // controls is loaded from it, committed or not: inventory only. The one
                // outside home that carries risk is a shared temporary directory
                // (/tmp/claude): another local user can create it first and plant the
                // settings, hooks and MCP servers the agent loads.
                // A value that could not be resolved (`${PWD}/.claude-cfg`,
                // `GEMINI_CLI_HOME=$PWD`) may point at the repository itself, so it is not
                // given the "outside" reassurance: Medium in a committed .env, Low otherwise.
                "agent-home" if o.unresolved => Some((
                    if t { Severity::Medium } else { Severity::Low },
                    "Agent redirection",
                    format!(
                        "{} in a{tracked} .env relocates the {} home to a value that could not be resolved ({value}); check where it points (inside the repository, the repository controls the agent's settings, hooks and MCP servers){gemini_note}",
                        o.key,
                        crate::scanners::env_files::agent_for_home_key(&o.key),
                    ),
                )),
                "agent-home" if !o.inside_project && !o.shared_temp => None,
                "agent-home" if !o.inside_project => Some((
                    Severity::Low,
                    "Agent redirection",
                    format!(
                        "{} in a{tracked} .env relocates the {} home to {value}, a shared temporary directory outside the project — another local user can create it first and plant the settings, hooks and MCP servers the agent loads{gemini_note}",
                        o.key,
                        crate::scanners::env_files::agent_for_home_key(&o.key),
                    ),
                )),
                "agent-home" => Some((
                    if t && o.inside_project {
                        Severity::High
                    } else if o.inside_project && !mode_file {
                        Severity::Medium
                    } else {
                        Severity::Low
                    },
                    "Agent redirection",
                    format!(
                        "{} in a{tracked} .env relocates the {} home to {value}{}{gemini_note}",
                        o.key,
                        crate::scanners::env_files::agent_for_home_key(&o.key),
                        " inside the project",
                    ),
                )),
                // A tracked .env is repository-controlled redirection. An untracked one is
                // usually the user's own app config (an OpenAI-compatible SDK pointed at a
                // provider) and reaches a coding agent only when something loads it, so
                // it is advisory.
                // A docker-compose service name (`http://ollama:11434/v1`),
                // host.docker.internal or a private/link-local address is the local-stack
                // setup, not an internet third party: advisory, worded as such.
                // A template placeholder (`<your-gateway-url>`), an interpolation
                // (`${OPENAI_BASE_URL}`, re-exporting the user's own environment) or text
                // with no host routes nothing by itself, tracked or not: advisory.
                "gateway" | "proxy"
                    if !o.official
                        && !o.loopback
                        && matches!(
                            value,
                            crate::scanners::env_files::UNRESOLVED_VALUE | crate::scanners::env_files::UNPARSEABLE_VALUE
                        ) =>
                {
                    Some((
                        Severity::Low,
                        if o.kind == "gateway" { "Gateway routing" } else { "Agent redirection" },
                        format!(
                            "{} in a{tracked} .env is not a recognizable URL ({}) — it routes nothing until it is filled in or expanded; check the host it ends up with{gemini_note}",
                            o.key,
                            if value == crate::scanners::env_files::UNRESOLVED_VALUE {
                                "a placeholder or interpolation"
                            } else {
                                "no parseable host"
                            }
                        ),
                    ))
                }
                "gateway" if !o.official && !o.loopback && is_local_network_host(value) => Some((
                    Severity::Low,
                    "Gateway routing",
                    format!(
                        "{} points to local-network host {value} in a{tracked} .env (a container service name or LAN address) — when the .env is loaded, requests and the API key go there; confirm it is your own service{gemini_note}",
                        o.key
                    ),
                )),
                "gateway" if !o.official && !o.loopback => Some((
                    if t { Severity::High } else { Severity::Low },
                    "Gateway routing",
                    // Starts with the key: Blueprint matches .env gateways by location.
                    if t {
                        format!(
                            "{} points to non-official host {value} in a git-tracked .env — every clone routes requests (and the API key) there when the .env is loaded (EAA-007){gemini_note}",
                            o.key
                        )
                    } else if mode_file {
                        format!(
                            "{} points to non-official host {value} in a{tracked} {file_name} — when the app (or anything exporting this file) loads it, requests and the API key go there; verify the host (EAA-007){gemini_note}",
                            o.key
                        )
                    } else {
                        format!(
                            "{} points to non-official host {value} in a .env — when the .env is loaded, requests and the API key go there; verify the host (EAA-007){gemini_note}",
                            o.key
                        )
                    },
                )),
                "headers" if t => Some((
                    Severity::Medium,
                    "Agent redirection",
                    "ANTHROPIC_CUSTOM_HEADERS is set in a git-tracked .env — adds request headers (often a credential) to every Claude Code request when loaded".to_string(),
                )),
                "headers" if e.git_tracked => Some((
                    Severity::Low,
                    "Agent redirection",
                    format!(
                        "ANTHROPIC_CUSTOM_HEADERS is set in a git-tracked {file_name} — adds request headers to Claude Code requests if something exports this file{app_note}"
                    ),
                )),
                "proxy" if !o.loopback => Some((
                    if t { Severity::Medium } else { Severity::Low },
                    "Agent redirection",
                    format!("{} in a{tracked} .env sends agent traffic through proxy {value}", o.key),
                )),
                // Only a wildcard means the same thing read by the server or a client. A
                // specific remote address or host is how clients point at another machine.
                "ollama-host" => match o.bind.as_deref() {
                    Some("wildcard") => Some((
                        Severity::Low,
                        "Ollama exposure",
                        format!(
                            "OLLAMA_HOST={value} in a .env would make Ollama listen on every interface if the server starts from this environment (normal inside a container; check the published port)"
                        ),
                    )),
                    _ => None,
                },
                _ => None,
            };
            if let Some((severity, category, title)) = finding {
                f.push(Finding {
                    severity,
                    category: category.into(),
                    title,
                    location: e.path.clone(),
                    evidence: None,
                });
            }
        }
    }

    // ── E. Declarative extensions that carry code ──
    for x in &report.ide_extensions {
        if !x.declarative_claim {
            continue;
        }
        // The id is the extension's directory name: attacker-chosen text.
        let id = crate::scanners::sanitize_display(&x.id, 200);
        // Located by its directory: one id can sit in ~/.vscode and ~/.vscode-oss.
        let loc = if x.path.is_empty() {
            id.clone()
        } else {
            crate::scanners::sanitize_display(&x.path, 512)
        };
        let runs: Vec<&str> = x
            .code_entry_points
            .iter()
            .map(String::as_str)
            .filter(|e| matches!(*e, "main" | "browser"))
            .collect();
        // A theme that also contributes commands or settings (Material Icon Theme,
        // vscode-icons, One Dark Pro) declares what its code is for; that stays in the
        // inventory. Code with no declared purpose is the GlassWorm loader shape.
        if x.contributes_theme && !runs.is_empty() && !x.contributes_commands {
            f.push(Finding {
                severity: Severity::Low,
                category: "Extension code".into(),
                title: format!(
                    "theme extension '{id}' ({}) runs code ({}) but contributes no commands or settings — pure themes are JSON only",
                    x.ide_type,
                    x.code_entry_points.join(", ")
                ),
                location: loc.clone(),
                evidence: None,
            });
        }
        if !x.native_addons.is_empty() {
            let claim = if x.categories.is_empty() {
                "declarative".to_string()
            } else {
                x.categories.join(", ")
            };
            f.push(Finding {
                severity: Severity::Low,
                category: "Extension code".into(),
                title: format!(
                    "extension '{id}' ({}) declares itself {claim} but ships native addon(s): {}",
                    x.ide_type,
                    x.native_addons.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
                ),
                location: loc.clone(),
                evidence: None,
            });
        }
    }

    // ── F. OLLAMA_HOST binds in profiles, systemd units and launchd jobs ──
    for c in &report.shell_configs {
        let Some(o) = &c.ollama_host else { continue };
        // OLLAMA_HOST is read by the server (where to listen) AND by clients (where to
        // connect). A wildcard means "listen everywhere" either way. A specific address
        // or host is a server bind only in the server's own unit or job; in a shell
        // profile it is how a client reaches a remote GPU box, and stays quiet.
        //
        // A systemd unit's Environment= and a launchd job's EnvironmentVariables reach only
        // that unit's or job's own process tree. When it does not run Ollama (service=false:
        // an open-webui container, a client agent), a wildcard there is a client dial to
        // this machine unless the unit starts `ollama serve` some way the scanner cannot
        // see, so it is Low and says so (review round 7). A shell profile is where the user
        // runs `ollama serve` by hand: Medium.
        let unit = c.shell.starts_with("systemd") || c.shell == "launchd";
        let unit_word = if c.shell == "launchd" { "job" } else { "unit" };
        let (severity, title) = match (o.bind.as_str(), o.service) {
            ("wildcard", true) => (
                Severity::Medium,
                format!(
                    "OLLAMA_HOST={} in {} config makes the Ollama server listen on every interface — the Ollama API has no authentication",
                    o.value, c.shell
                ),
            ),
            ("wildcard", false) if unit => (
                Severity::Low,
                format!(
                    "OLLAMA_HOST={} in a {} {unit_word} that does not run ollama: if this {unit_word} starts `ollama serve` (directly or through a script) it will listen on every interface — the Ollama API has no authentication",
                    o.value, c.shell
                ),
            ),
            ("wildcard", false) => (
                Severity::Medium,
                format!(
                    "OLLAMA_HOST={} in {} config makes `ollama serve` started from this environment listen on every interface — the Ollama API has no authentication",
                    o.value, c.shell
                ),
            ),
            ("non-loopback-ip" | "hostname", true) => (
                Severity::Medium,
                format!(
                    "OLLAMA_HOST={} in {} config makes the Ollama server listen on a non-loopback address — the Ollama API has no authentication",
                    o.value, c.shell
                ),
            ),
            _ => continue,
        };
        f.push(Finding {
            severity,
            category: "Ollama exposure".into(),
            title,
            location: c.config_path.clone(),
            evidence: None,
        });
    }
}

/// Capability categories that read sensitive/private data (a flow "source").
const SOURCES: &[&str] = &[
    "filesystem",
    "database",
    "environment",
    "source_control",
    "private_data",
];
/// Capability categories that can send data off the host (a flow "sink").
const SINKS: &[&str] = &["network", "communication", "code_exec"];
/// The third leg of the trifecta: content an attacker can write (web pages).
const UNTRUSTED: &str = "untrusted_content";

/// The "lethal trifecta" / toxic-flow surface: when the connected agent surface
/// holds BOTH a sensitive-data source and an exfiltration sink, any prompt injection
/// that reaches the agent can read private data and send it out. Each individual
/// capability is benign and authorized; the *combination across connected servers and
/// skills* is the risk — which a single MCP client never sees.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ToxicFlowSurface {
    pub sources: Vec<String>,
    pub sinks: Vec<String>,
    /// Untrusted-content capabilities present (`untrusted_content`), the third leg.
    pub untrusted: Vec<String>,
    /// What supplies each leg, as `(capability, contributor)`: MCP servers by name and
    /// origin first, then skill files as one count per capability ("N loading skill(s)
    /// mention it": a keyword in a skill file is a mention, not a source).
    pub contributors: Vec<(String, String)>,
    /// The servers among the contributors, as `(capability, server name)`.
    pub servers: Vec<(String, String)>,
}

/// Loading skills that must mention a capability of EACH leg (source and sink) before a
/// toxic-flow surface built from skill-file mentions alone, with no connected server
/// behind either leg, becomes a finding (Medium). Below it the surface is still
/// computed (terminal, blueprint) but is not a finding: a keyword in one or two skill
/// files is too weak a signal to grade.
pub const TOXIC_FLOW_MIN_MENTIONS: usize = 3;

/// The contributor label of skill files ([`analyze_toxic_flow`]).
const SKILL_COUNT_SUFFIX: &str = " loading skill(s) mention it";

fn is_skill_count(who: &str) -> bool {
    who.ends_with(SKILL_COUNT_SUFFIX)
}

impl ToxicFlowSurface {
    /// Whether a source or sink capability is supplied by something connected (an active
    /// MCP server or connector, a successful probe), not only by skill-file mentions.
    /// The untrusted-content leg does not count.
    pub fn server_backed(&self) -> bool {
        self.contributors
            .iter()
            .any(|(c, w)| !is_skill_count(w) && (self.sources.contains(c) || self.sinks.contains(c)))
    }

    /// The most loading skills that mention any one capability of the leg `caps`.
    pub fn leg_mentions(&self, caps: &[String]) -> usize {
        self.contributors
            .iter()
            .filter(|(c, w)| is_skill_count(w) && caps.contains(c))
            .filter_map(|(_, w)| w.trim_end_matches(SKILL_COUNT_SUFFIX).parse::<usize>().ok())
            .max()
            .unwrap_or(0)
    }

    /// One leg for a title: the servers that supply it first, with their capabilities,
    /// then the capabilities only skill files mention: `claude.ai Gmail, claude.ai Google
    /// Drive: private_data; skills mention filesystem/environment`.
    pub fn leg_title(&self, caps: &[String]) -> String {
        let mut names: Vec<&str> = Vec::new();
        let mut served: Vec<&str> = Vec::new();
        for c in caps {
            for (k, n) in self.servers.iter().filter(|(k, _)| k == c) {
                if !names.contains(&n.as_str()) {
                    names.push(n);
                }
                if !served.contains(&k.as_str()) {
                    served.push(k);
                }
            }
        }
        let mentioned: Vec<&str> = caps
            .iter()
            .map(String::as_str)
            .filter(|c| !served.contains(c))
            .collect();
        let mut parts = Vec::new();
        if !names.is_empty() {
            parts.push(format!("{}: {}", list_rules(&names, 3), served.join("/")));
        }
        if !mentioned.is_empty() {
            parts.push(format!("loading skills mention {}", mentioned.join("/")));
        }
        parts.join("; ")
    }

    /// One line naming what supplies each leg: MCP servers first (a server pair is the
    /// concrete flow), each with its origin, then skill files as counts labelled
    /// "mention", never "source".
    pub fn evidence(&self) -> String {
        let servers: Vec<&(String, String)> = self.contributors.iter().filter(|(_, w)| !is_skill_count(w)).collect();
        let skills: Vec<&(String, String)> = self.contributors.iter().filter(|(_, w)| is_skill_count(w)).collect();
        let mut parts = Vec::new();
        for (label, caps) in [
            ("sources", &self.sources),
            ("sinks", &self.sinks),
            ("untrusted content", &self.untrusted),
        ] {
            // Server -> the capabilities of this leg it supplies, in contributor order.
            let mut rows: Vec<(&str, Vec<&str>)> = Vec::new();
            for (c, who) in servers.iter().filter(|(c, _)| caps.contains(c)) {
                match rows.iter_mut().find(|(w, _)| w == who) {
                    Some((_, cs)) => cs.push(c),
                    None => rows.push((who, vec![c])),
                }
            }
            let mut leg: Vec<String> = rows.iter().map(|(w, cs)| format!("{w}: {}", cs.join("/"))).collect();
            for (c, who) in skills.iter().filter(|(c, _)| caps.contains(c)) {
                let n = who.trim_end_matches(SKILL_COUNT_SUFFIX);
                leg.push(format!("(+{n} loading skill(s) mention {c})"));
            }
            if !leg.is_empty() {
                parts.push(format!("{label}: {}", leg.join("; ")));
            }
        }
        parts.join(" | ")
    }
}

/// Capabilities of an MCP server judged by its name and package name alone: a small,
/// closed table of well-known servers (the server is never contacted). Words are the
/// lowercase runs of letters and digits.
pub fn mcp_server_capabilities(s: &crate::models::McpServerDetail) -> Vec<&'static str> {
    let text = format!("{} {}", s.name, s.package_name.as_deref().unwrap_or("")).to_ascii_lowercase();
    let words: BTreeSet<&str> = text
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    let any = |ws: &[&str]| ws.iter().any(|w| words.contains(w));
    let mut caps = Vec::new();
    if any(&["gmail", "drive", "gdrive", "calendar", "docs", "outlook"]) {
        caps.push("private_data");
    }
    if any(&[
        "playwright",
        "puppeteer",
        "browser",
        "browserbase",
        "chrome",
        "fetch",
        "curl",
    ]) {
        caps.push("network");
        caps.push(UNTRUSTED);
    }
    if any(&["filesystem"]) {
        caps.push("filesystem");
    }
    if any(&["shell", "exec", "terminal"]) {
        caps.push("code_exec");
    }
    caps
}

/// A server row's origin, for evidence. A claude.ai connector also says when it was last
/// used: the newest modification time of its `mcp-logs-<server>` directories, when the
/// MCP scanner saw any.
fn server_origin(report: &ScanReport, cfg: &crate::models::McpConfig, s: &crate::models::McpServerDetail) -> String {
    if cfg.config_source == crate::models::MCP_SOURCE_PLUGIN {
        format!("plugin MCP server of {}", s.plugin.as_deref().unwrap_or("?"))
    } else if cfg.config_source == crate::models::MCP_SOURCE_CONNECTOR {
        let seg = mcp_tool_segment(&s.name);
        let last = report
            .mcp_observed_servers
            .iter()
            .filter(|o| mcp_tool_segment(&o.name) == seg)
            .filter_map(|o| o.newest_mtime)
            .max()
            .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
            .map(|d| format!(", last used {}", d.format("%Y-%m-%d")))
            .unwrap_or_default();
        format!("claude.ai connector, ever connected{last}")
    } else {
        format!("MCP server in {}", cfg.config_source)
    }
}

/// A skill counts toward the surface when it loads: the user's own and a project's
/// (no plugin provenance), synced skills, and skills of an installed, enabled plugin
/// version. Marketplace clones and orphaned versions of plugins that are not installed
/// stay in the inventory but do not load, so they supply no capability.
fn skill_loads(skill: &crate::models::AgentSkill) -> bool {
    match &skill.provenance {
        None => true,
        Some(p) => p.marketplace.is_none() || p.active || p.synced,
    }
}

/// Aggregate the capabilities of what is actually connected and report a toxic-flow
/// surface when both a source and a sink are present: successful probes; MCP servers
/// that are not marked off (an enabled plugin's, a configured one, a claude.ai connector
/// Claude Code lists as ever connected) through [`mcp_server_capabilities`]; and the
/// declared capabilities of skills that load ([`skill_loads`]).
pub fn analyze_toxic_flow(report: &ScanReport) -> Option<ToxicFlowSurface> {
    use std::collections::BTreeMap;
    // capability -> contributors, in insertion order of kind (servers, then skills).
    let mut by_cap: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut add = |cap: &str, who: String| {
        let key: &str = [SOURCES, SINKS, &[UNTRUSTED]]
            .iter()
            .flat_map(|t| t.iter())
            .find(|c| **c == cap)
            .copied()
            .unwrap_or("");
        if key.is_empty() {
            return;
        }
        let list = by_cap.entry(key).or_default();
        if !list.contains(&who) {
            list.push(who);
        }
    };
    let mut probed: Vec<(String, String)> = Vec::new();
    for probe in &report.mcp_probes {
        if probe.success {
            for c in &probe.observed_capabilities {
                add(c, format!("probed MCP server '{}'", probe.server_name));
                probed.push((c.clone(), probe.server_name.clone()));
            }
        }
    }
    let mut servers: Vec<(String, String)> = Vec::new();
    for cfg in &report.mcp_configs {
        for s in cfg.servers.iter().filter(|s| s.is_active()) {
            for c in mcp_server_capabilities(s) {
                add(c, format!("{} ({})", s.name, server_origin(report, cfg, s)));
                servers.push((c.to_string(), s.name.clone()));
            }
        }
    }
    let mut skill_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for skill in report.agent_skills.iter().filter(|k| skill_loads(k)) {
        for c in &skill.capabilities {
            if let Some(k) = SOURCES.iter().chain(SINKS).find(|k| **k == c.as_str()) {
                *skill_counts.entry(k).or_default() += 1;
            }
        }
    }
    for (c, n) in skill_counts {
        add(c, format!("{n}{SKILL_COUNT_SUFFIX}"));
    }

    // Capabilities a named server supplies come first, so the title leads with the
    // concrete pair rather than with keyword counts over skill files.
    let present = |table: &[&str]| -> Vec<String> {
        let mut v: Vec<&str> = table.iter().copied().filter(|c| by_cap.contains_key(c)).collect();
        v.sort_by_key(|c| by_cap[c].iter().all(|w| is_skill_count(w)));
        v.into_iter().map(str::to_string).collect()
    };
    let sources = present(SOURCES);
    let sinks = present(SINKS);
    if sources.is_empty() || sinks.is_empty() {
        return None;
    }
    let untrusted = present(&[UNTRUSTED]);
    let contributors = by_cap
        .iter()
        .flat_map(|(c, who)| who.iter().map(move |w| (c.to_string(), w.clone())))
        .collect();
    probed.extend(servers);
    Some(ToxicFlowSurface {
        sources,
        sinks,
        untrusted,
        contributors,
        servers: probed,
    })
}

/// Advisory IDs (CVE-..., GHSA-...) named in a catalog advisory, in order, deduplicated.
fn advisory_ids(advisory: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in advisory.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')) {
        let ok = (raw.starts_with("CVE-") && raw.len() >= 13) || (raw.starts_with("GHSA-") && raw.len() == 19);
        if ok && !out.iter().any(|x| x == raw) {
            out.push(raw.to_string());
        }
    }
    out
}

/// The npx cache a finding is in runs again only when the same `npx` line does: it is
/// active when an active configured or plugin MCP server launches one of the packages
/// the cache was created for.
///
/// npx keys its cache by the spec it was given, so the server must launch that spec: the
/// same name at the same exact version, or (an unpinned launch: no version, `@latest`, a
/// range or a dist-tag) a cache whose spec is unpinned too. A server launching
/// `foo-mcp@2.0.0` does not re-run a `foo-mcp@1.0.0` cache. A cache whose specs were not
/// recorded (only `dependencies`, or an older report) falls back to the name.
fn npx_cache_is_active(report: &ScanReport, e: &crate::models::ExposureFinding) -> bool {
    let floats = |v: Option<&str>| match v {
        None => true,
        Some(v) => crate::scanners::mcp::npm_version_floats(v),
    };
    let cache: Vec<(&str, Option<&str>)> = e
        .cache_specs
        .iter()
        .map(|spec| match crate::scanners::mcp::split_npm_package_version(spec) {
            (_, None) => (spec.as_str(), None),
            (n, Some(_)) => (&spec[..n.len()], Some(&spec[n.len() + 1..])),
        })
        .collect();
    report.mcp_configs.iter().flat_map(|c| &c.servers).any(|s| {
        if !(s.is_active() && !s.ever_connected && s.package_ecosystem.as_deref() == Some("npm")) {
            return false;
        }
        let Some(name) = s.package_name.as_deref() else {
            return false;
        };
        if cache.is_empty() {
            return e.cache_parent.iter().any(|n| n == name);
        }
        let sv = s.package_version.as_deref();
        cache.iter().any(|(cn, cv)| {
            *cn == name
                && match (floats(sv), floats(*cv)) {
                    (true, true) => true,
                    (false, false) => sv == *cv,
                    _ => false,
                }
        })
    })
}

/// The finding for one catalog match. A malware row (an exact version, or every version)
/// and a vulnerable version in an active install are Critical. A vulnerable-version-range
/// match found only in an npx cache that no active server launches is High: the code is
/// on disk but runs only if that `npx` line is run again. The evidence keeps the catalog
/// row's range and advisory IDs.
pub fn exposure_finding(report: &ScanReport, e: &crate::models::ExposureFinding) -> Finding {
    let ids = advisory_ids(&e.advisory);
    let mut evidence = match &e.matched_range {
        Some(r) => format!("catalog row: {} {} {r}", e.ecosystem, e.name),
        None => format!("catalog row: {} {} (malicious release)", e.ecosystem, e.name),
    };
    if !ids.is_empty() {
        evidence.push_str(&format!("; advisories: {}", ids.join(", ")));
    }
    let parent = if e.cache_parent.is_empty() {
        String::new()
    } else {
        format!(" (fetched with {})", e.cache_parent.join(", "))
    };
    let dormant = e.cache.is_some() && !npx_cache_is_active(report, e);
    // A vulnerable range is graded at its advisory's severity (GitHub's scale, from the
    // CVSS score: critical 9.0-10.0, high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9); a row
    // without one keeps Critical. A dormant npx cache is one step below that, never below
    // Low. A malware row is Critical by kind.
    let advisory = e.matched_range.as_ref().and_then(|_| advisory_severity_of(e));
    let base = advisory.unwrap_or(Severity::Critical);
    let stated = advisory.map_or(String::new(), |s| format!(" (advisory severity: {})", s.label()));
    let (severity, title) = match (&e.matched_range, dormant) {
        (Some(_), true) => {
            let what = if e.name.starts_with("@modelcontextprotocol/") {
                "Vulnerable MCP SDK version".to_string()
            } else {
                format!("Vulnerable {} package version", e.ecosystem)
            };
            (
                one_step_below(base),
                format!(
                    "{what}{stated} in npx cache (dormant unless re-run): {} {}{parent}",
                    e.name, e.version
                ),
            )
        }
        (Some(_), false) => (
            base,
            format!(
                "Vulnerable {} package version{stated}: {} {}{parent}",
                e.ecosystem, e.name, e.version
            ),
        ),
        (None, _) => (
            Severity::Critical,
            format!("Known-bad {} package: {} {}{parent}", e.ecosystem, e.name, e.version),
        ),
    };
    Finding {
        severity,
        category: "Exposure".into(),
        title,
        location: e.found_in.clone(),
        evidence: Some(evidence),
    }
}

/// The severity a vulnerable-range finding's catalog row states (`advisory_severity`),
/// or None when the row has none or an unknown word. GitHub's API spells medium
/// "moderate", so a user catalog copied from it is read the same way.
fn advisory_severity_of(e: &crate::models::ExposureFinding) -> Option<Severity> {
    match e.advisory_severity.as_deref()?.trim().to_ascii_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" | "moderate" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        _ => None,
    }
}

/// One grade lower, never below Low.
fn one_step_below(s: Severity) -> Severity {
    match s {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium | Severity::Low => Severity::Low,
    }
}

/// True if `arg` is a filesystem root broad enough to expose the whole machine or the
/// user's entire home directory.
pub fn is_broad_root(arg: &str, home: &str) -> bool {
    let a = arg.trim().trim_end_matches('/');
    if a.is_empty() {
        return true; // "/" trimmed to ""
    }
    matches!(a, "~" | "$HOME" | "${HOME}" | "/home" | "/Users" | "/root")
        || (!home.is_empty() && a == home.trim_end_matches('/'))
}

#[cfg(test)]
mod hook_ladder_tests {
    use super::*;
    use crate::models::AgentHook;

    fn hook(kind: &str) -> AgentHook {
        AgentHook {
            event: "Stop".into(),
            command: "x".into(),
            kind: kind.into(),
            ..Default::default()
        }
    }

    /// Every (scope x kind x condition) cell of the hook ladder.
    #[test]
    fn hook_severity_table() {
        use HookGrade::{Aggregate as A, Finding as F};
        use Severity::*;
        let tp = HookScope::PluginThirdParty {
            key: ("m".into(), "p".into()),
            root: "/r".into(),
        };
        let scopes = [
            HookScope::Repository { tracked: true },
            HookScope::Repository { tracked: false },
            HookScope::UserOwn,
            HookScope::Managed,
            HookScope::PluginOfficial,
            tp,
            HookScope::Inactive,
        ];
        let crit = |k: &str| AgentHook {
            dangerous: true,
            pattern_severity: "critical".into(),
            patterns: vec!["curl|wget piped to shell".into()],
            ..hook(k)
        };
        let dangerous = crit("command");
        let high_only = AgentHook {
            dangerous: true,
            pattern_severity: "high".into(),
            patterns: vec!["shell command execution".into()],
            ..hook("command")
        };
        // A report from before pattern_severity existed: dangerous means critical.
        let legacy = AgentHook {
            dangerous: true,
            ..hook("command")
        };
        let dangerous_module = crit("module");
        let cross = AgentHook {
            risks: vec!["cross-references another tool's config directory (.vscode/x)".into()],
            ..hook("")
        };
        let http_far = AgentHook {
            url_host: Some("collector.evil.example".into()),
            ..hook("http")
        };
        let http_lan = AgentHook {
            url_host: Some("10.1.2.3".into()),
            ..hook("http")
        };
        let http_local = AgentHook {
            url_host: Some("localhost".into()),
            ..hook("http")
        };
        let http_first = AgentHook {
            url_host: Some("api.anthropic.com".into()),
            first_party_host: true,
            ..hook("http")
        };
        let poison = AgentHook {
            poisoning: vec!["ignore previous".into()],
            ..hook("prompt")
        };
        let agent_plain = hook("agent");
        let mcp = hook("mcp_tool");
        let medium = AgentHook {
            patterns: vec!["environment variable exfiltration".into()],
            pattern_severity: "medium".into(),
            ..hook("command")
        };
        let guarded = AgentHook {
            advisory_patterns: vec!["disable security controls".into()],
            ..hook("command")
        };
        let cross_home = AgentHook {
            risks: vec![format!(
                "{} (~/.claude/hooks/fmt.sh)",
                crate::scanners::agent_settings::CROSS_HOME_RISK
            )],
            ..hook("")
        };
        let cross_both = AgentHook {
            risks: vec![cross_home.risks[0].clone(), cross.risks[0].clone()],
            ..hook("")
        };
        let exfil = |p: &str| AgentHook {
            dangerous: true,
            pattern_severity: "critical".into(),
            patterns: vec![p.into()],
            push_host: Some("ntfy.sh".into()),
            ..hook("command")
        };
        let push = exfil("data exfiltration pattern");
        let push_cred = AgentHook {
            patterns: vec![
                "data exfiltration pattern".into(),
                "data exfiltration pattern (a credential file sent by a network client)".into(),
            ],
            ..exfil("data exfiltration pattern")
        };
        let plain = hook("");
        let module = hook("module");
        let module_medium = AgentHook {
            patterns: vec!["environment variable exfiltration".into()],
            pattern_severity: "medium".into(),
            ..hook("module")
        };
        let module_advisory = AgentHook {
            advisory_patterns: vec!["curl|wget piped to shell".into()],
            ..hook("module")
        };
        // Prompts the agent itself reads (Copilot CLI, Kiro; review of b9cda85).
        let conv = |sig: &[&str]| AgentHook {
            poisoning: sig.iter().map(|s| s.to_string()).collect(),
            prompt_target: "conversation".into(),
            ..hook("prompt")
        };
        let conv_plain = conv(&[]);
        let conv_weak = conv(&["first read"]);
        let conv_strong = conv(&["do not mention (aimed at the user)"]);
        // Guard wording and a credential path alone are one step lower (review of 4e3f8c3).
        let conv_soft = conv(&["never reveal", "do not display"]);
        let conv_cred_soft = conv(&["never reveal", "credential path .env"]);
        let conv_cred = conv(&["credential path ~/.aws/credentials"]);
        let conv_cred_phrase = conv(&["first read", "credential path ~/.aws/credentials"]);
        let undocumented = AgentHook {
            prompt_target: "undocumented".into(),
            ..conv(&["<system>"])
        };
        // Columns: repo tracked, repo untracked, user, managed, official, third-party, inactive.
        let table: Vec<(&AgentHook, [Option<HookGrade>; 7])> = vec![
            (
                &dangerous,
                [
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    None,
                ],
            ),
            (
                &high_only,
                [
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    None,
                ],
            ),
            (
                &legacy,
                [
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    None,
                ],
            ),
            (
                &dangerous_module,
                [
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    None,
                ],
            ),
            (
                &medium,
                [
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    None,
                    None,
                    Some(A),
                    None,
                ],
            ),
            (
                &guarded,
                [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None],
            ),
            (
                &cross,
                [
                    Some(F(High)),
                    Some(F(High)),
                    Some(F(High)),
                    Some(F(High)),
                    None,
                    Some(F(High)),
                    None,
                ],
            ),
            (
                &cross_home,
                [
                    Some(F(High)),
                    Some(F(High)),
                    Some(F(Low)),
                    Some(F(High)),
                    None,
                    Some(F(High)),
                    None,
                ],
            ),
            (
                &cross_both,
                [
                    Some(F(High)),
                    Some(F(High)),
                    Some(F(High)),
                    Some(F(High)),
                    None,
                    Some(F(High)),
                    None,
                ],
            ),
            (
                &push,
                [
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Low)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    None,
                ],
            ),
            (
                &push_cred,
                [
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    None,
                ],
            ),
            (
                &http_far,
                [
                    Some(F(High)),
                    Some(F(High)),
                    Some(F(Low)),
                    None,
                    None,
                    Some(F(Medium)),
                    None,
                ],
            ),
            (
                &http_lan,
                [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None],
            ),
            (
                &http_local,
                [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None],
            ),
            (
                &http_first,
                [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None],
            ),
            (
                &poison,
                [
                    Some(F(Medium)),
                    Some(F(Medium)),
                    Some(F(Low)),
                    None,
                    Some(F(Low)),
                    Some(F(Low)),
                    None,
                ],
            ),
            (
                &agent_plain,
                [Some(F(Low)), Some(F(Low)), None, None, None, Some(A), None],
            ),
            (
                &mcp,
                [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None],
            ),
            (
                &plain,
                [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None],
            ),
            (
                &module,
                [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None],
            ),
            (
                &module_medium,
                [
                    Some(F(Medium)),
                    Some(F(Medium)),
                    Some(F(Low)),
                    None,
                    None,
                    Some(A),
                    None,
                ],
            ),
            (
                &module_advisory,
                [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None],
            ),
            (
                &conv_plain,
                [Some(F(Low)), Some(F(Low)), None, None, None, Some(A), None],
            ),
            (
                &conv_weak,
                [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None],
            ),
            (
                &conv_strong,
                [
                    Some(F(High)),
                    Some(F(High)),
                    Some(F(Low)),
                    None,
                    Some(F(Low)),
                    Some(F(Medium)),
                    None,
                ],
            ),
            (
                &conv_soft,
                [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None],
            ),
            (
                &conv_cred,
                [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None],
            ),
            (
                &conv_cred_soft,
                [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None],
            ),
            (
                &conv_cred_phrase,
                [
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    Some(F(Critical)),
                    None,
                ],
            ),
            (
                &undocumented,
                [
                    Some(F(High)),
                    Some(F(High)),
                    Some(F(Low)),
                    None,
                    Some(F(Low)),
                    Some(F(Medium)),
                    None,
                ],
            ),
        ];
        for (h, row) in &table {
            for (scope, want) in scopes.iter().zip(row.iter()) {
                assert_eq!(hook_severity(scope, h), *want, "{scope:?} x {h:?}");
            }
        }
        // Disabled and unknown-type hooks are never graded.
        for scope in &scopes {
            assert_eq!(
                hook_severity(
                    scope,
                    &AgentHook {
                        disabled: true,
                        ..dangerous.clone()
                    }
                ),
                None
            );
            assert_eq!(
                hook_severity(
                    scope,
                    &AgentHook {
                        dangerous: true,
                        ..hook("unknown")
                    }
                ),
                None
            );
        }
    }

    #[test]
    fn plugin_root_of_strips_hook_and_manifest_dirs() {
        assert_eq!(plugin_root_of("/c/m/p/1.0/hooks/hooks.json"), "/c/m/p/1.0");
        assert_eq!(plugin_root_of("/c/m/p/1.0/.codex-plugin/plugin.json"), "/c/m/p/1.0");
        assert_eq!(plugin_root_of("/c/m/p/hooks.json"), "/c/m/p");
    }
}

#[cfg(test)]
mod finding_category_tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The production part of this file (everything before the first `#[cfg(test)]`), then
    /// that of `analysis_surfaces.rs`.
    fn source() -> &'static str {
        // The round-3b grading module emits findings too; its categories are this table's.
        static SRC: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        SRC.get_or_init(|| {
            let src = include_str!("analysis.rs");
            let mut s = src[..src.find("#[cfg(test)]").expect("test module")].to_string();
            let surfaces = include_str!("analysis_surfaces.rs");
            s.push_str(&surfaces[..surfaces.find("#[cfg(test)]").unwrap_or(surfaces.len())]);
            s
        })
    }

    /// Every category literal in the source is in [`FINDING_CATEGORIES`], and every
    /// table entry is emitted somewhere. Two shapes exist: `category: "X".into()` on a
    /// `Finding`, and a `(severity, "X", title)` tuple whose second element is a line
    /// of its own; a `Finding` built from a variable (`category: category.into()`) is
    /// only fed by those tuples, and a new variable-fed site fails the count below so
    /// its literals get looked at.
    #[test]
    fn finding_categories_match_the_source() {
        let src = source();
        let mut found = BTreeSet::new();
        for (at, _) in src.match_indices("category: \"") {
            let rest = &src[at + "category: \"".len()..];
            found.insert(&rest[..rest.find('"').unwrap()]);
        }
        let literal_sites = found.len();
        assert!(literal_sites >= 30, "only {literal_sites} category literals found");
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            // A tuple's category: a capitalised string literal alone on its line, right
            // after the severity expression.
            if t.starts_with('"') && t.ends_with("\",") && t.chars().nth(1).is_some_and(|c| c.is_ascii_uppercase()) {
                let prev = lines[i - 1].trim();
                if prev.contains("Severity::") || prev == "sev," {
                    found.insert(&t[1..t.len() - 2]);
                }
            }
        }
        let variable_sites = src.matches("category: category.into()").count();
        assert_eq!(
            variable_sites, 2,
            "a new Finding takes its category from a variable: make sure the literals feeding it are \
             in FINDING_CATEGORIES, then update this count"
        );
        let table: BTreeSet<&str> = FINDING_CATEGORIES.iter().copied().collect();
        assert_eq!(table.len(), FINDING_CATEGORIES.len(), "duplicate in FINDING_CATEGORIES");
        let missing: Vec<_> = found.difference(&table).collect();
        assert!(
            missing.is_empty(),
            "categories emitted but not in FINDING_CATEGORIES: {missing:?}"
        );
        let unused: Vec<_> = table.difference(&found).collect();
        assert!(
            unused.is_empty(),
            "FINDING_CATEGORIES entries never emitted: {unused:?}"
        );
    }

    /// `guidance` has a bespoke arm for exactly the table's categories.
    #[test]
    fn guidance_arms_are_the_category_table() {
        let src = source();
        let body = &src[src.find("pub fn guidance(").unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap()];
        let mut arms = BTreeSet::new();
        for line in body.lines() {
            let t = line.trim();
            if t.starts_with('"') && t.ends_with("=> Guidance {") {
                for alt in t.trim_end_matches("=> Guidance {").split('|') {
                    arms.insert(alt.trim().trim_matches('"'));
                }
            }
        }
        let table: BTreeSet<&str> = FINDING_CATEGORIES.iter().copied().collect();
        assert_eq!(arms, table);
    }

    #[test]
    fn category_label_is_closed() {
        for c in FINDING_CATEGORIES {
            assert_eq!(category_label(c), *c);
        }
        assert_eq!(category_label("hook"), "other", "case-sensitive");
        assert_eq!(category_label("/home/u/.env"), "other");
        assert_eq!(category_label(""), "other");
        assert!(!FINDING_CATEGORIES.contains(&"other"));
    }
}
