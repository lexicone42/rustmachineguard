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
            what: "This MCP server's launch command downloads and executes code at startup (a curl|bash-style bootstrap).",
            why: "Every launch fetches and runs whatever the remote endpoint currently serves — a supply-chain foothold the server author (or anyone who compromises that endpoint) can weaponize silently.",
            fix: "Pin the server to a vetted, versioned package instead of a fetch-and-run bootstrap; review the launch command shown below before trusting it.",
            reference: "EAA-006 · supply-chain",
        },
        "Secret leak" => Guidance {
            what: "A secret-bearing file (a .env or a config with an inline credential) is tracked by git — i.e. committed into a repository.",
            why: "A committed secret is in the repo's history for every clone, fork, and CI run; deleting it later does not remove it from history. This is the highest-confidence credential exposure.",
            fix: "Remove the file from tracking (git rm --cached), add it to .gitignore, ROTATE the credential immediately (assume it is public), and scrub history if the repo was shared.",
            reference: "committed secret",
        },
        "Secret hygiene" => Guidance {
            what: "A .env file is tracked by git, but none of its key names looks like a credential (only settings such as PORT, NODE_ENV or LOG_LEVEL). rmguard reads key names only, never values.",
            why: "Nothing secret-named is committed, so this is not a leak. A tracked .env is still where a credential tends to get added later, or hides under a neutral name.",
            fix: "Confirm no value is a credential. Consider committing a .env.example with the settings and adding .env to .gitignore so a later secret is not committed by habit.",
            reference: "tracked .env without secret-named keys",
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
            what: "The agent's permission mode is `bypassPermissions`, so it acts without the usual approval prompts.",
            why: "The human-in-the-loop guardrail is off — the agent (or a prompt injection steering it) can run tools and edits with no confirmation.",
            fix: "Set the permission mode back to a prompting mode (e.g. acceptEdits or default). Reserve bypass modes for disposable sandboxes.",
            reference: "OWASP Agentic Apps Top 10 (excessive agency)",
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
            what: "A .env file in an agent project root is world-readable.",
            why: ".env files hold API keys and DB credentials; world-readable means any local user or process can read them.",
            fix: "chmod 600 the file. Rotate anything in it if the machine is multi-user.",
            reference: "least privilege",
        },
        "Transcript exposure" => Guidance {
            what: "An agent transcript / conversation-state store (full chat history, prompts, and any secrets discussed) is world-readable.",
            why: "Transcripts routinely contain pasted credentials, source code, and internal details — a rich target that any local user can read.",
            fix: "Restrict the store's permissions to owner-only. Consider pruning old transcripts you no longer need.",
            reference: "EAA-005 (agent-state collection)",
        },
        "Plugin marketplace" => Guidance {
            what: "A third-party plugin marketplace is configured with auto-update on, so it pulls new remote code automatically.",
            why: "Auto-update means today's vetted plugin can become tomorrow's malicious one with no review step — the rug-pull surface for hot-loaded agent code.",
            fix: "Turn off auto-update for third-party sources and update deliberately after reviewing changes, or remove the marketplace if unused.",
            reference: "EAA-009 (remote plugin hot-load)",
        },
        "SSH key" => Guidance {
            what: "A private SSH key on disk has no passphrase.",
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
        "Toxic Flow" => Guidance {
            what: "The connected agent surface holds BOTH a sensitive-data source (filesystem/database/environment/source-control) and an exfiltration sink (network/communication) at the same time.",
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
    "-a", "--all", "-r", "--remotes", "-l", "--list", "-v", "-vv", "--verbose", "--show-current", "--contains",
    "--no-contains", "--merged", "--no-merged", "--points-at", "--sort", "--format", "--color", "--no-color",
    "--column", "--no-column", "-i", "--ignore-case", "--abbrev", "--no-abbrev", "--omit-empty",
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
    if args.iter().any(|a| leaves_repository(a) || a.split_once('=').is_some_and(|(_, v)| leaves_repository(v))) {
        return false;
    }
    match sub {
        "status" | "diff" | "log" | "show" | "rev-parse" | "describe" | "ls-files" | "shortlog" => {
            !args.iter().any(|a| GIT_READ_DENIED_FLAGS.iter().any(|d| flag_name(a).starts_with(d)))
        }
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
        '|', '>', '<', ';', '&', '$', '`', '(', ')', '\n', '\r', '\\', '"', '\'', '*', '?', '[', ']', '{', '}', '!', '#',
    ]) {
        return false;
    }
    let words: Vec<&str> = cmd.split_whitespace().collect();
    let Some((prog, args)) = words.split_first() else { return false };
    match *prog {
        "git" => {
            // The subcommand must come first: any option before it can redirect git to
            // another repository or work tree, set config (and with it a program to run),
            // or start a pager.
            let Some((sub, rest)) = args.split_first() else { return false };
            !sub.starts_with('-') && git_read_only(sub, rest)
        }
        "gh" => {
            let (Some(sub), Some(verb)) = (args.first(), args.get(1)) else { return false };
            matches!(*sub, "pr" | "issue" | "repo" | "run")
                && matches!(*verb, "view" | "list" | "diff" | "status" | "checks")
                && !args.iter().any(|a| leaves_repository(a) || a.split_once('=').is_some_and(|(_, v)| leaves_repository(v)))
        }
        // `date -s` sets the clock; `+FORMAT` only formats.
        "date" => args.is_empty() || (args.len() == 1 && args[0].starts_with('+')),
        "ls" | "pwd" | "whoami" => args.is_empty(),
        "uname" => args.iter().all(|a| {
            a.len() >= 2 && a.starts_with('-') && a[1..].chars().all(|c| "asnrvmpio".contains(c))
        }),
        _ => false,
    }
}

/// Collect and rank the actionable findings in a scan. Highest severity first.
/// This is the risk-first view that HTML/fleet reports lead with.
pub fn collect_findings(report: &ScanReport) -> Vec<Finding> {
    let mut f = Vec::new();

    // Known-malicious / vulnerable package matches — the most actionable signal.
    for e in &report.exposure_findings {
        f.push(Finding {
            severity: Severity::Critical,
            category: "Exposure".into(),
            title: format!("Known-bad {} package: {} {}", e.ecosystem, e.name, e.version),
            location: e.found_in.clone(),
            evidence: None,
        });
    }

    // MCP server configuration risks (transport encryption, over-broad scope).
    let home = report.device.home_dir.as_str();
    for mcp in &report.mcp_configs {
        for s in &mcp.servers {
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
            if !s.inline_secret_env_keys.is_empty() {
                let keys = s.inline_secret_env_keys.join(", ");
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
            if !launch.trim().is_empty()
                && !crate::scanners::rules_files::check_dangerous_patterns(&launch).is_empty()
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
            let detail = if h.risks.is_empty() { String::new() } else { format!(" — {}", h.risks.join("; ")) };
            f.push(Finding {
                severity,
                category: "Helper command".into(),
                title: format!(
                    "{} runs a command{}{}{}",
                    h.event,
                    if h.dangerous { " matching a dangerous pattern" } else { "" },
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
        if let Some(mode) = s.permission_mode.as_deref()
            && matches!(mode, "bypassPermissions" | "unrestricted")
        {
            f.push(Finding {
                severity: Severity::High,
                category: "Permissions".into(),
                title: format!(
                    "{} runs without approval prompts ({})",
                    s.framework, mode
                ),
                location: s.path.clone(),
                evidence: None,
            });
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
                if why.is_empty() { String::new() } else { format!(" — {}", why.join("; ")) }
            ),
            location: t.path.clone(),
            evidence: Some(t.command.clone()),
        });
    }

    // Persistence and planting artifacts: Python startup hooks, tool-shadowing
    // binaries, committed symlinks that escape the repo, staged loaders, worm IOCs.
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
                (sev, "Persistence", format!("Python startup hook runs on every interpreter start — {claim}"))
            }
            "planted-binary" => {
                let sev = match (a.git_tracked, a.sensitive_target) {
                    (true, true) => Severity::Critical,
                    (true, false) | (false, true) => Severity::High,
                    (false, false) => Severity::Medium,
                };
                let carrier = if a.git_tracked { " — git-tracked, so every clone carries it" } else { "" };
                (sev, "Binary planting", format!("Executable in a project root {}{carrier}", a.detail))
            }
            "escaping-symlink" => {
                let sev = if a.sensitive_target { Severity::Critical } else { Severity::High };
                let target = if a.sensitive_target { "a credential, shell-rc or agent-config path" } else { "outside the repository" };
                (sev, "Repo symlink", format!("Committed symlink resolves {target}; an approved in-project write lands there"))
            }
            "loader-script" => {
                let sev = if a.sensitive_target || a.git_tracked { Severity::High } else { Severity::Medium };
                (sev, "Persistence", format!("Loader staged in an agent directory: {}", a.detail))
            }
            _ => (Severity::Critical, "Persistence", format!("Known worm persistence artifact: {}", a.detail)),
        };
        f.push(Finding {
            severity,
            category: category.into(),
            title,
            location: a.path.clone(),
            evidence: Some(a.detail.clone()),
        });
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
                if g.nested { "a nested git directory" } else { "this repository" },
                g.reason,
                if g.origin.ends_with("/config") { String::new() }
                else { format!(" (hidden via include: {})", g.origin) }
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
        // A committed .env is a committed secret only if it holds one. The values are
        // never read, so that is judged by the key NAMES (secret-named or a connection
        // string, plus ANTHROPIC_CUSTOM_HEADERS); a .env of only PORT / NODE_ENV /
        // LOG_LEVEL is a Low advisory. A file whose keys were not read (a symlink, an
        // empty or unreadable file: key_count 0) keeps the Critical grade, since nothing
        // says it is clean.
        let credential_named = !e.secret_keys.is_empty() || e.agent_overrides.iter().any(|o| o.kind == "headers");
        if e.git_tracked && !credential_named && e.key_count > 0 && e.symlink.is_none() {
            f.push(Finding {
                severity: Severity::Low,
                category: "Secret hygiene".into(),
                title: format!(
                    ".env is git-tracked ({} keys, no secret-named keys) — check that no credential is committed under another name",
                    e.key_count
                ),
                location: e.path.clone(),
                evidence: None,
            });
        } else if e.git_tracked {
            f.push(Finding {
                severity: Severity::Critical,
                category: "Secret leak".into(),
                title: format!(".env is git-tracked ({} keys) — committed secrets", e.key_count),
                location: e.path.clone(),
                evidence: None,
            });
        } else if e.world_readable {
            f.push(Finding {
                severity: Severity::High,
                category: "Secret exposure".into(),
                title: format!(".env is world-readable ({} keys)", e.key_count),
                location: e.path.clone(),
                evidence: None,
            });
        }
    }

    // World-readable agent transcript/state stores (EAA-005 collection surface):
    // these hold full conversation history — code, prompts, and any secrets discussed —
    // so loose permissions let any local user read the lot.
    for t in &report.transcripts {
        if t.world_readable {
            f.push(Finding {
                severity: Severity::High,
                category: "Transcript exposure".into(),
                title: format!(
                    "{} {} store is world-readable ({} files) — conversation history exposed (EAA-005)",
                    t.framework, t.kind, t.file_count
                ),
                location: t.path.clone(),
                evidence: None,
            });
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

    // Unprotected SSH keys.
    for k in &report.ssh_keys {
        if k.has_passphrase == PassphraseStatus::NoPassphrase {
            f.push(Finding {
                severity: Severity::High,
                category: "SSH key".into(),
                title: format!("{} key has no passphrase", k.key_type),
                location: k.path.clone(),
                evidence: None,
            });
        }
    }

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
    if let Some(id) = &report.agent_identity {
        if !id.static_api_keys.is_empty() {
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
    }

    // Composition-level toxic-flow surface.
    if let Some(tf) = analyze_toxic_flow(report) {
        f.push(Finding {
            severity: Severity::High,
            category: "Toxic Flow".into(),
            title: format!(
                "sensitive source ({}) + exfil sink ({}) on the agent surface",
                tf.sources.join("/"),
                tf.sinks.join("/")
            ),
            location: report.device.hostname.clone(),
            evidence: None,
        });
    }

    collect_agent_surface_findings(report, &mut f);

    f.sort_by_key(|x| x.severity.rank());
    f
}

/// A host that only resolves on the local network: a single-label name (a docker-compose
/// service such as `ollama` or `litellm`), `host.docker.internal`, a `.local` mDNS name,
/// or a private, link-local or shared-address IP literal. `<unparseable>` is not.
pub fn is_local_network_host(host: &str) -> bool {
    let h = host.trim_end_matches('.').trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
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
                || matches!(h.as_str(), "host.docker.internal" | "gateway.docker.internal" | "host.containers.internal")
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
        return HookScope::Repository { tracked: prov.and_then(|p| p.git.as_deref()) == Some("tracked") };
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
    let kind = if crate::scanners::hook_sources::is_command_kind(&h.kind) { "command" } else { h.kind.as_str() };
    let by = |repo: Option<Severity>, user: Option<Severity>, official: Option<Severity>, tp: Option<HookGrade>| match scope {
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
        if *scope == UserOwn && h.risks.iter().filter(|r| cross(r)).all(|r| r.starts_with(crate::scanners::agent_settings::CROSS_HOME_RISK)) {
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
        let PromptSignals { cred, weak, soft, strong } = prompt_signals(h);
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
    let mut sig = PromptSignals { cred: false, weak: false, soft: false, strong: false };
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
    let kind = if crate::scanners::hook_sources::is_command_kind(&h.kind) { "command" } else { h.kind.as_str() };
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
            let plain = if h.url_scheme.as_deref() == Some("http") { " over plaintext http" } else { "" };
            let lan = if http_reach(h) == HttpReach::Lan { " (a local-network host)" } else { "" };
            format!("{event} hook [{m}] sends each event's JSON to {host}{lan}{plain}")
        }
        "prompt" | "agent" if in_conversation(h) => {
            let into = if h.prompt_target == "conversation" {
                "submits a prompt into the agent's conversation".to_string()
            } else {
                let who = if framework.is_empty() { "the agent" } else { framework };
                format!("sends a prompt that {who} does not document the handling of (graded as text in the agent's conversation)")
            };
            let sig = prompt_signals(h);
            if h.poisoning.is_empty() {
                format!("{event} {kind} hook [{m}] {into} on each event (advisory)")
            } else if sig.strong || sig.weak {
                format!("{event} {kind} hook [{m}] {into} with prompt-injection signals ({})", h.poisoning.join(", "))
            } else {
                // Only a credential path and/or guard-style concealment wording: say what
                // it is, not "prompt injection".
                let cred_sig = crate::scanners::hook_sources::CREDENTIAL_PATH_SIGNAL;
                let paths: Vec<&str> = h.poisoning.iter().filter_map(|p| p.strip_prefix(cred_sig)).collect();
                let soft: Vec<&str> = h.poisoning.iter().filter(|p| !p.starts_with(cred_sig)).map(String::as_str).collect();
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
            if kind == "agent" { "hook subagent" } else { "hook evaluator model" },
            h.poisoning.join(", ")
        ),
        "prompt" | "agent" => format!("{event} {kind} hook [{m}] sends a model prompt on each event (advisory)"),
        "mcp_tool" => format!("{event} hook [{m}] calls MCP tool {}", h.command),
        "module" => {
            let regs = if h.registers.is_empty() { String::new() } else { format!(": registers {}", h.registers.join(", ")) };
            let bad = if h.dangerous {
                format!(" and a shell command it runs matches a dangerous pattern ({})", h.patterns.join("; "))
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
            let label = if framework.starts_with("claude-code") || framework.is_empty() { "claude-code mod" } else { framework };
            format!("{label} hooks module {} runs inside the agent on its events{regs}{bad}", h.command)
        }
        _ => {
            let detail = if h.risks.is_empty() { String::new() } else { format!(" — {}", h.risks.join("; ")) };
            let graded_as_match = h.dangerous || matches!(scope, HookScope::Repository { .. } | HookScope::Managed | HookScope::UserOwn);
            if *scope == HookScope::UserOwn && user_event_push(h) {
                let host = h.push_host.as_deref().unwrap_or("?");
                format!("{event} hook [{m}] runs a command that sends fields of its event to {host} (a notification hook)")
            } else if !h.patterns.is_empty() && graded_as_match {
                format!("{event} hook [{m}] runs a command matching a dangerous pattern ({}){detail}{advisory}", h.patterns.join(", "))
            } else if !h.patterns.is_empty() {
                format!("{event} hook [{m}] runs a command{detail}; matches {}{advisory}", h.patterns.join(", "))
            } else if *scope == HookScope::UserOwn && h.risks.iter().any(|r| r.starts_with(crate::scanners::agent_settings::CROSS_HOME_RISK)) {
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
        let managed = || settings.iter().filter(|s| s.source == "managed" && s.framework == "claude-code");
        ManagedPolicy {
            managed_only: managed().any(|s| s.allow_managed_hooks_only || s.disable_all_hooks),
            managed_off: managed().any(|s| s.disable_all_hooks),
            forced: managed().flat_map(|s| s.force_enabled_plugins.iter().cloned()).collect(),
        }
    }

    fn policy(&self) -> &'static str {
        if self.managed_off { "disableAllHooks" } else { "allowManagedHooksOnly" }
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
    let mut grade = |h: &crate::models::AgentHook, framework: &str, scope: HookScope, location: &str, prefix: &str, note: Option<&str>, f: &mut Vec<Finding>| {
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
                f.push(Finding { severity, category: "Hook".into(), title, location: location.to_string(), evidence: Some(h.command.clone()) })
            }
            Some(HookGrade::Aggregate) => {
                if let HookScope::PluginThirdParty { key, root } = scope {
                    let e = agg.entry(key).or_insert_with(|| (framework.to_string(), root, BTreeSet::new(), 0, None));
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
    let silenced = |framework: &str, scope: &HookScope, prov: Option<&crate::models::SkillProvenance>| mp.silences(framework, scope, prov);
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
        let what = if k.framework == "claude-code-agent" || k.file_type == "agent" { "subagent" } else { "skill" };
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
    let own_at = comps.iter().position(|c| c.as_os_str().to_str().is_some_and(|c| AGENT_CONFIG_DIRS.contains(&c)))?;
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
    if framework.starts_with("claude-code") { "third-party plugin" } else { "plugin (provenance not verified)" }
}

/// `~/.claude/plugins/cache/<m>/<p>/<v>` for a path inside a plugin cache version.
fn plugin_install_root(path: &str) -> String {
    let p = std::path::Path::new(path);
    let comps: Vec<_> = p.components().collect();
    for (i, c) in comps.iter().enumerate() {
        if c.as_os_str() == "cache" && i > 0 && comps[i - 1].as_os_str() == "plugins" && comps.len() > i + 3 {
            return comps[..=i + 3].iter().collect::<std::path::PathBuf>().to_string_lossy().to_string();
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
                    if i.mismatch { Severity::Critical } else { Severity::Medium },
                    format!(
                        "marketplace '{}' is checked out on a branch named like a commit{} — Plugin4Shell shape (CVE-2026-86063)",
                        m.name,
                        if i.mismatch { " that points at a different commit" } else { "" }
                    ),
                ),
                "sha-shaped-ref" => (
                    if i.mismatch { Severity::Critical } else { Severity::Medium },
                    format!(
                        "marketplace '{}' has a ref named like a commit{}",
                        m.name,
                        if i.mismatch { " that points at a different commit" } else { "" }
                    ),
                ),
                "fetch-head-sha-branch" => (
                    if i.mismatch { Severity::Critical } else { Severity::Medium },
                    format!(
                        "marketplace '{}' last fetched a branch named like a commit{}",
                        m.name,
                        if i.mismatch { ", which resolved to a different commit" } else { "" }
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
                            format!("{who} is pinned to an abbreviated commit ID — it is resolved by name, so a branch of that name would win; use the full 40-hex ID"),
                        ),
                        "manifest-sha-empty" => (
                            Severity::Low,
                            format!("{who} has an empty sha — no commit pin is recorded, so it follows its ref"),
                        ),
                        _ => (
                            Severity::Medium,
                            format!("{who} is pinned to a branch or tag name, not a commit — the pin moves with the branch"),
                        ),
                    }
                }
                "manifest-ref-is-sha" if i.plugin.is_some() => (
                    Severity::Medium,
                    format!("plugin '{p}' from '{}' gives a commit ID as its ref with no sha pin — a branch of that name would win", m.name),
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
                    format!("installed plugin '{p}@{}' records a gitCommitSha that is a name, not a commit ID", m.name),
                ),
                "installed-sha-abbreviated" => (
                    Severity::Medium,
                    format!("installed plugin '{p}@{}' records an abbreviated gitCommitSha — a branch of that name would win; a full 40-hex ID cannot be shadowed", m.name),
                ),
                "installed-sha-empty" => (
                    Severity::Low,
                    format!("installed plugin '{p}@{}' records an empty gitCommitSha — no commit pin is recorded", m.name),
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
    let mut plugin_cmds: BTreeMap<PluginKey, CmdAgg> =
        BTreeMap::new();
    // (marketplace, plugin) -> (install root, skill names, file paths)
    let mut plugin_grants: BTreeMap<PluginKey, GrantAgg> =
        BTreeMap::new();
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
            let via = if l.through_directory { "is reached through a symlinked directory" } else { "is a symlink" };
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
            let own_global = skill.scope != "project" && skill.provenance.as_ref().is_none_or(|p| p.marketplace.is_none());
            let md_target = l
                .target
                .rsplit('/')
                .next()
                .is_some_and(|n| n.to_ascii_lowercase().ends_with(".md"));
            // A link reached through a symlinked directory names that directory.
            let skill_shaped = directory || l.through_directory || md_target;
            let (severity, title) = if directory && l.sensitive_target && own_global && skill_shaped && !credential {
                (Severity::Low, format!("skill directory '{}' points outside the skills directory (into {into}) — not listed or read", skill.name))
            } else if directory && l.sensitive_target {
                (Severity::High, format!("skill directory '{}' is a symlink into {into} — not listed or read", skill.name))
            } else if directory {
                (Severity::Low, format!("skill directory '{}' is a symlink that resolves outside {within} — not listed or read", skill.name))
            } else if l.sensitive_target && own_global && skill_shaped && !credential {
                (Severity::Low, format!("skill file '{}' points outside the skills directory (into {into}) — not read", skill.name))
            } else if l.sensitive_target {
                (Severity::High, format!("skill file '{}' {via} into {into} — not read", skill.name))
            } else if l.dangling {
                (Severity::Low, format!("skill file '{}' is a dangling symlink that points outside {within} — nothing to read", skill.name))
            } else {
                (Severity::Low, format!("skill file '{}' {via} that resolves outside {within} — not read", skill.name))
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

        let project_shell_disabled = project && shell_disabled_projects.iter().any(|p| skill.path.starts_with(p.as_str()));
        if loadable && !shell_disabled && !project_shell_disabled && !skill.dynamic_commands.is_empty() {
            let matched = || -> BTreeSet<&str> {
                skill.dynamic_commands.iter().flat_map(|d| d.patterns.iter().map(String::as_str)).collect()
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
                    && skill.dynamic_commands.iter().all(|d| d.patterns.is_empty() && is_read_only_context_command(&d.command)))
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
            } else if !project && !is_plugin && let Some(d) = skill.dynamic_commands.iter().find(|d| !d.patterns.is_empty()) {
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
            title: format!("third-party plugin '{p}@{m}' runs shell commands when its skills load: {}", first_names(names)),
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
                f.push(Finding { severity, category: category.into(), title, location: e.path.clone(), evidence: None });
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
        let loc = if x.path.is_empty() { id.clone() } else { crate::scanners::sanitize_display(&x.path, 512) };
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
            let claim = if x.categories.is_empty() { "declarative".to_string() } else { x.categories.join(", ") };
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
            ("wildcard", true) => (Severity::Medium, format!(
                "OLLAMA_HOST={} in {} config makes the Ollama server listen on every interface — the Ollama API has no authentication",
                o.value, c.shell
            )),
            ("wildcard", false) if unit => (Severity::Low, format!(
                "OLLAMA_HOST={} in a {} {unit_word} that does not run ollama: if this {unit_word} starts `ollama serve` (directly or through a script) it will listen on every interface — the Ollama API has no authentication",
                o.value, c.shell
            )),
            ("wildcard", false) => (Severity::Medium, format!(
                "OLLAMA_HOST={} in {} config makes `ollama serve` started from this environment listen on every interface — the Ollama API has no authentication",
                o.value, c.shell
            )),
            ("non-loopback-ip" | "hostname", true) => (Severity::Medium, format!(
                "OLLAMA_HOST={} in {} config makes the Ollama server listen on a non-loopback address — the Ollama API has no authentication",
                o.value, c.shell
            )),
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
const SOURCES: &[&str] = &["filesystem", "database", "environment", "source_control"];
/// Capability categories that can send data off the host (a flow "sink").
const SINKS: &[&str] = &["network", "communication"];

/// The "lethal trifecta" / toxic-flow surface: when the connected agent surface
/// holds BOTH a sensitive-data source and an exfiltration sink, any prompt injection
/// that reaches the agent can read private data and send it out. Each individual
/// capability is benign and authorized; the *combination across connected servers and
/// skills* is the risk — which a single MCP client never sees.
#[derive(Debug, Clone, PartialEq)]
pub struct ToxicFlowSurface {
    pub sources: Vec<String>,
    pub sinks: Vec<String>,
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

/// Aggregate observed (probed) + declared (skill) capabilities across the whole scan
/// and report a toxic-flow surface when both a source and a sink are present.
pub fn analyze_toxic_flow(report: &ScanReport) -> Option<ToxicFlowSurface> {
    let mut caps: BTreeSet<&str> = BTreeSet::new();
    for probe in &report.mcp_probes {
        if probe.success {
            for c in &probe.observed_capabilities {
                caps.insert(c.as_str());
            }
        }
    }
    for skill in &report.agent_skills {
        for c in &skill.capabilities {
            caps.insert(c.as_str());
        }
    }

    let sources: Vec<String> = SOURCES
        .iter()
        .filter(|s| caps.contains(**s))
        .map(|s| s.to_string())
        .collect();
    let sinks: Vec<String> = SINKS
        .iter()
        .filter(|s| caps.contains(**s))
        .map(|s| s.to_string())
        .collect();

    if !sources.is_empty() && !sinks.is_empty() {
        Some(ToxicFlowSurface { sources, sinks })
    } else {
        None
    }
}

#[cfg(test)]
mod hook_ladder_tests {
    use super::*;
    use crate::models::AgentHook;

    fn hook(kind: &str) -> AgentHook {
        AgentHook { event: "Stop".into(), command: "x".into(), kind: kind.into(), ..Default::default() }
    }

    /// Every (scope x kind x condition) cell of the hook ladder.
    #[test]
    fn hook_severity_table() {
        use HookGrade::{Aggregate as A, Finding as F};
        use Severity::*;
        let tp = HookScope::PluginThirdParty { key: ("m".into(), "p".into()), root: "/r".into() };
        let scopes = [
            HookScope::Repository { tracked: true },
            HookScope::Repository { tracked: false },
            HookScope::UserOwn,
            HookScope::Managed,
            HookScope::PluginOfficial,
            tp,
            HookScope::Inactive,
        ];
        let crit = |k: &str| AgentHook { dangerous: true, pattern_severity: "critical".into(), patterns: vec!["curl|wget piped to shell".into()], ..hook(k) };
        let dangerous = crit("command");
        let high_only = AgentHook { dangerous: true, pattern_severity: "high".into(), patterns: vec!["shell command execution".into()], ..hook("command") };
        // A report from before pattern_severity existed: dangerous means critical.
        let legacy = AgentHook { dangerous: true, ..hook("command") };
        let dangerous_module = crit("module");
        let cross = AgentHook { risks: vec!["cross-references another tool's config directory (.vscode/x)".into()], ..hook("") };
        let http_far = AgentHook { url_host: Some("collector.evil.example".into()), ..hook("http") };
        let http_lan = AgentHook { url_host: Some("10.1.2.3".into()), ..hook("http") };
        let http_local = AgentHook { url_host: Some("localhost".into()), ..hook("http") };
        let http_first = AgentHook { url_host: Some("api.anthropic.com".into()), first_party_host: true, ..hook("http") };
        let poison = AgentHook { poisoning: vec!["ignore previous".into()], ..hook("prompt") };
        let agent_plain = hook("agent");
        let mcp = hook("mcp_tool");
        let medium = AgentHook { patterns: vec!["environment variable exfiltration".into()], pattern_severity: "medium".into(), ..hook("command") };
        let guarded = AgentHook { advisory_patterns: vec!["disable security controls".into()], ..hook("command") };
        let cross_home = AgentHook {
            risks: vec![format!("{} (~/.claude/hooks/fmt.sh)", crate::scanners::agent_settings::CROSS_HOME_RISK)],
            ..hook("")
        };
        let cross_both = AgentHook { risks: vec![cross_home.risks[0].clone(), cross.risks[0].clone()], ..hook("") };
        let exfil = |p: &str| AgentHook {
            dangerous: true,
            pattern_severity: "critical".into(),
            patterns: vec![p.into()],
            push_host: Some("ntfy.sh".into()),
            ..hook("command")
        };
        let push = exfil("data exfiltration pattern");
        let push_cred = AgentHook {
            patterns: vec!["data exfiltration pattern".into(), "data exfiltration pattern (a credential file sent by a network client)".into()],
            ..exfil("data exfiltration pattern")
        };
        let plain = hook("");
        let module = hook("module");
        let module_medium = AgentHook { patterns: vec!["environment variable exfiltration".into()], pattern_severity: "medium".into(), ..hook("module") };
        let module_advisory = AgentHook { advisory_patterns: vec!["curl|wget piped to shell".into()], ..hook("module") };
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
        let undocumented = AgentHook { prompt_target: "undocumented".into(), ..conv(&["<system>"]) };
        // Columns: repo tracked, repo untracked, user, managed, official, third-party, inactive.
        let table: Vec<(&AgentHook, [Option<HookGrade>; 7])> = vec![
            (&dangerous, [Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), None]),
            (&high_only, [Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), None]),
            (&legacy, [Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), None]),
            (&dangerous_module, [Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), None]),
            (&medium, [Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), None, None, Some(A), None]),
            (&guarded, [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None]),
            (&cross, [Some(F(High)), Some(F(High)), Some(F(High)), Some(F(High)), None, Some(F(High)), None]),
            (&cross_home, [Some(F(High)), Some(F(High)), Some(F(Low)), Some(F(High)), None, Some(F(High)), None]),
            (&cross_both, [Some(F(High)), Some(F(High)), Some(F(High)), Some(F(High)), None, Some(F(High)), None]),
            (&push, [Some(F(Critical)), Some(F(Critical)), Some(F(Low)), Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), None]),
            (&push_cred, [Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), None]),
            (&http_far, [Some(F(High)), Some(F(High)), Some(F(Low)), None, None, Some(F(Medium)), None]),
            (&http_lan, [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None]),
            (&http_local, [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None]),
            (&http_first, [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None]),
            (&poison, [Some(F(Medium)), Some(F(Medium)), Some(F(Low)), None, Some(F(Low)), Some(F(Low)), None]),
            (&agent_plain, [Some(F(Low)), Some(F(Low)), None, None, None, Some(A), None]),
            (&mcp, [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None]),
            (&plain, [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None]),
            (&module, [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None]),
            (&module_medium, [Some(F(Medium)), Some(F(Medium)), Some(F(Low)), None, None, Some(A), None]),
            (&module_advisory, [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None]),
            (&conv_plain, [Some(F(Low)), Some(F(Low)), None, None, None, Some(A), None]),
            (&conv_weak, [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None]),
            (&conv_strong, [Some(F(High)), Some(F(High)), Some(F(Low)), None, Some(F(Low)), Some(F(Medium)), None]),
            (&conv_soft, [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None]),
            (&conv_cred, [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None]),
            (&conv_cred_soft, [Some(F(Medium)), Some(F(Medium)), None, None, None, Some(A), None]),
            (&conv_cred_phrase, [Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), Some(F(Critical)), None]),
            (&undocumented, [Some(F(High)), Some(F(High)), Some(F(Low)), None, Some(F(Low)), Some(F(Medium)), None]),
        ];
        for (h, row) in &table {
            for (scope, want) in scopes.iter().zip(row.iter()) {
                assert_eq!(hook_severity(scope, h), *want, "{scope:?} x {h:?}");
            }
        }
        // Disabled and unknown-type hooks are never graded.
        for scope in &scopes {
            assert_eq!(hook_severity(scope, &AgentHook { disabled: true, ..dangerous.clone() }), None);
            assert_eq!(hook_severity(scope, &AgentHook { dangerous: true, ..hook("unknown") }), None);
        }
    }

    #[test]
    fn plugin_root_of_strips_hook_and_manifest_dirs() {
        assert_eq!(plugin_root_of("/c/m/p/1.0/hooks/hooks.json"), "/c/m/p/1.0");
        assert_eq!(plugin_root_of("/c/m/p/1.0/.codex-plugin/plugin.json"), "/c/m/p/1.0");
        assert_eq!(plugin_root_of("/c/m/p/hooks.json"), "/c/m/p");
    }
}
