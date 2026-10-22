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
            what: "An agent settings file registers a hook that runs a shell command automatically on an agent event (e.g. before every tool use).",
            why: "Hooks execute silently with your privileges on every triggering event — a powerful persistence and code-execution mechanism if the settings file is tampered with or shared.",
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
            what: "An AI provider base-URL override (in agent settings or a project .env) points at a host that is not the provider's own API, so requests (and the API key) route through it. Named OpenAI-compatible providers (Groq, Azure OpenAI, Mistral, Gemini, ...) and loopback proxies are not reported.",
            why: "Whoever controls that host sees every prompt and can capture the API key. In Claude Code project settings this is the exfiltration vector behind CVE-2026-21852. A .env applies only to tools that load it (Gemini CLI loads project .env files itself; other agents need direnv, an IDE or a dotenv loader), and a git-tracked one is the repository choosing the host for everyone. A legitimate proxy looks identical, so this needs a human check.",
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
            fix: "Update Claude Code to 2.1.179 or later (Codex to 0.146.0 or later). Remove and reinstall the affected marketplace or plugin, and compare the installed files against the pinned commit before trusting them. In a manifest, put the 40-hex commit in `sha` and keep branch names in `ref`.",
            reference: "CVE-2026-86063 · Plugin4Shell (Air Security) · EAA-009",
        },
        "Skill symlink" => Guidance {
            what: "A skill manifest (SKILL.md), command file or bundled script is a symbolic link (or sits under a symlinked directory) whose real path is outside its skill directory, project or plugin. rmguard resolves every hop and never reads a target that is a credential, key, shell-rc or history, agent-config or system path; a repository's or plugin's link that leaves it is inventoried without being read, and only your own links into your own files (a dotfiles checkout) are read.",
            why: "Claude Code loads the link's target as the skill. A SKILL.md that points at ~/.ssh or a settings file puts that file into the model's context. An edit the agent makes to the skill writes through the link: the write-time symlink-following class behind CVE-2026-103435. A link into a dotfiles checkout is common and benign.",
            fix: "If you did not create the link, replace it with a regular file or remove the skill. Keep skill bundles self-contained; dotfile managers can copy instead of linking.",
            reference: "CVE-2026-103435 · write-time symlink following · AST02",
        },
        "Skill command" => Guidance {
            what: "A skill or custom command contains dynamic context injection: an inline !`command` placeholder or a ```! block. Claude Code runs it in your shell before the skill text reaches the model, every time the skill is invoked.",
            why: "The command runs with your privileges on invocation, and Claude can invoke a skill on its own unless the skill sets disable-model-invocation. So a third-party plugin or a repository can ship code that runs when its skill loads, with no tool-approval prompt. Read-only context commands (git status, gh pr view) are the documented use.",
            fix: "Read the command shown below. Remove the skill if you did not expect it. To stop all skills running inline shell, set \"disableSkillShellExecution\": true in user or managed settings.",
            reference: "Claude Code skills: dynamic context injection · AST02 · EAA-003",
        },
        "Skill grant" => Guidance {
            what: "A skill's or command's allowed-tools frontmatter pre-approves unrestricted Bash (Bash or Bash(*)). Every shell command Claude runs during the invoking turn then executes without a permission prompt.",
            why: "The grant opts the skill out of human review of the shell. Claude Code does not gate this field on workspace trust, so the repository or third-party plugin that ships the skill decides it for you. Scoped grants such as Bash(git diff:*) are the documented alternative.",
            fix: "Narrow the grant to the commands the skill needs, or remove the skill. Organizations can set allowManagedPermissionRulesOnly so allowed-tools is ignored.",
            reference: "Claude Code skills: allowed-tools · AST02 · EAA-002 (permissive execution)",
        },
        "Agent redirection" => Guidance {
            what: "A project .env file sets a variable that relocates an AI agent's home directory (CLAUDE_CONFIG_DIR, CODEX_HOME, GEMINI_CLI_HOME, CURSOR_CONFIG_DIR, KIRO_HOME) or reroutes its traffic (HTTPS_PROXY to a non-loopback host, ANTHROPIC_CUSTOM_HEADERS).",
            why: "An agent started with a relocated home loads settings, hooks and MCP servers from that directory. When the directory sits inside the repository, the repository author controls them (Gemini CLI CVE-2026-13745: an untrusted .env overrode GEMINI_CLI_HOME past the folder-trust prompt). A proxy sees all traffic. Gemini CLI loads project .env files itself; other agents only see these values when something exports them (direnv, an IDE, a dotenv loader).",
            fix: "Remove the variable unless you put it there. Never commit agent-home or proxy overrides; set them in your own shell profile. Upgrade Gemini CLI to 0.39.1 or later.",
            reference: "CVE-2026-13745 · EAA-006 · EAA-007",
        },
        "Helper command" => Guidance {
            what: "A Claude Code settings file names a credential or telemetry helper (apiKeyHelper, awsAuthRefresh, awsCredentialExport, gcpAuthRefresh, otelHeadersHelper). This is a shell command Claude Code runs on its own to fetch credentials or headers.",
            why: "Like a hook, it runs silently with your privileges, and its output becomes the agent's credential. In a repository's settings file the repository author chooses the command. In your own or managed settings it is a normal enterprise setup and is only reported when the command matches a dangerous pattern.",
            fix: "Review the command below (literal arguments are redacted). Remove a helper that arrived with a repository; keep credential helpers in user or managed settings, and have them read the key from a secret store rather than echo it.",
            reference: "EAA-003 (lifecycle hook persistence) · OWASP ASI03",
        },
        "Login gateway" => Guidance {
            what: "forceLoginGatewayUrl in your user settings sends Claude Code's /login to the Claude apps gateway at the host shown.",
            why: "A gateway you sign in to holds the upstream credential, sees every prompt, and can push managed settings (including hooks and env) that run commands on this machine. Anthropic documents user-settings gateways for machines without managed settings, so this is expected where your organization runs one.",
            fix: "Confirm your organization operates this gateway. If not, remove forceLoginGatewayUrl and forceLoginMethod from ~/.claude/settings.json and sign in again.",
            reference: "Claude apps gateway · EAA-007",
        },
        "Extension code" => Guidance {
            what: "An IDE extension that presents itself as declarative (a colour or icon theme, snippets, keymaps, a language pack) carries code: a main/browser entry point with no contributed commands or settings to explain it, or a native .node addon.",
            why: "Pure themes are JSON and run nothing. GlassWorm-linked \"theme\" extensions shipped encrypted JavaScript, and the GlassWorm Zig dropper loaded a native addon to install a second-stage extension into every IDE. Some popular themes legitimately add commands or settings code, so this is advisory.",
            fix: "Check the publisher and the marketplace page, and uninstall the extension if the code is not explained. Prefer themes with no entry point.",
            reference: "GlassWorm theme loaders (Socket) · GlassWorm Zig dropper (Aikido) · OWASP ASI04",
        },
        "Ollama exposure" => Guidance {
            what: "OLLAMA_HOST tells the Ollama server where to listen (and clients where to connect). It is set to every interface (0.0.0.0, [::], or a bare :port) in a shell profile, .env, systemd unit or launchd job, or to a non-loopback address in the Ollama server's own unit or job. A remote address in a profile or .env is a client target and is not reported.",
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

    // Settings hooks run shell commands on agent events (silent code execution).
    for s in &report.agent_settings {
        for h in &s.hooks {
            // A hook that points at a script in ANOTHER tool's config directory is the
            // 2026 persistence fingerprint (a Claude hook running .vscode/setup.mjs and
            // vice versa). The command itself looks mundane, so it would otherwise score
            // as an ordinary hook — elevate it on the reference, not the text.
            let cross_dir = h.risks.iter().any(|r| r.starts_with("cross-references"));
            let severity = if h.dangerous {
                Severity::Critical
            } else if cross_dir {
                Severity::High
            } else {
                Severity::Medium
            };
            let detail = if h.risks.is_empty() {
                String::new()
            } else {
                format!(" — {}", h.risks.join("; "))
            };
            f.push(Finding {
                severity,
                category: "Hook".into(),
                title: format!(
                    "{} hook [{}] runs a command{}{}",
                    h.event,
                    h.matcher.as_deref().unwrap_or("*"),
                    if h.dangerous { " matching a dangerous pattern" } else { "" },
                    detail
                ),
                location: s.path.clone(),
                // The actual command is the offending artifact — surface it verbatim.
                evidence: Some(h.command.clone()),
            });
        }
        // Credential/telemetry helpers: commands Claude Code runs on its own. In the
        // user's own or managed settings they are normal enterprise plumbing and are
        // reported only when dangerous; from a project file the repository chose them.
        let project_scoped = matches!(s.source.as_str(), "project" | "local");
        for h in &s.helper_commands {
            let cross_dir = h.risks.iter().any(|r| r.starts_with("cross-references"));
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
        if let Some(lg) = &s.login_gateway
            && lg.effective
            && s.source == "user-global"
            && let Some(host) = &lg.host
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
            if !g.official {
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
        if e.git_tracked {
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
                "head-on-sha-branch" => (
                    Severity::Critical,
                    format!("marketplace '{}' is checked out on a branch named like a commit — Plugin4Shell shape (CVE-2026-86063)", m.name),
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
                "manifest-ref-is-sha" => (
                    Severity::Medium,
                    format!("marketplace '{}' gives a commit ID as its ref with no sha pin — a branch of that name would win", m.name),
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
        if let Some(l) = &skill.symlink
            && l.escapes
            && !l.store
        {
            let via = if l.through_directory { "is reached through a symlinked directory" } else { "is a symlink" };
            let within = if skill.scope == "project" {
                "its project"
            } else if skill.provenance.as_ref().is_some_and(|p| p.marketplace.is_some()) {
                "its plugin"
            } else {
                "its skill directory"
            };
            let (severity, title) = if l.sensitive_target {
                (
                    Severity::High,
                    format!("skill file '{}' {via} into a credential, key, shell-rc or agent-config path — not read", skill.name),
                )
            } else if !l.followed {
                (Severity::Low, format!("skill file '{}' {via} that resolves outside {within} — not read", skill.name))
            } else {
                (Severity::Low, format!("skill file '{}' {via} that resolves outside its skill directory", skill.name))
            };
            f.push(Finding {
                severity,
                category: "Skill symlink".into(),
                title,
                location: loc.clone(),
                evidence: Some(format!("-> {}", l.target)),
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

        if loadable && !shell_disabled && !skill.dynamic_commands.is_empty() {
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
            } else if project {
                let origin = match git {
                    Some("tracked") => "project (git-tracked)",
                    Some(_) => "project (untracked in a git repository)",
                    None => "project",
                };
                f.push(Finding {
                    severity: Severity::Low,
                    category: "Skill command".into(),
                    title: format!(
                        "{origin} skill '{}' runs {} shell command(s) when it loads (dynamic context)",
                        skill.name,
                        skill.dynamic_commands.len()
                    ),
                    location: loc.clone(),
                    evidence: Some(skill.dynamic_commands[0].command.clone()),
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
                        "project skill '{}' pre-approves unrestricted Bash (untracked in a git repository)",
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
        let t = e.git_tracked;
        let tracked = if t { " git-tracked" } else { "" };
        for o in &e.agent_overrides {
            let value = o.value.as_deref().unwrap_or("");
            let gemini = o.key.starts_with("GEMINI") || o.key.starts_with("GOOGLE_GEMINI");
            let gemini_note = if gemini { " (Gemini CLI loads project .env files itself)" } else { "" };
            let finding = match o.kind.as_str() {
                "agent-home" => Some((
                    if t { Severity::High } else if o.inside_project { Severity::Medium } else { Severity::Low },
                    "Agent redirection",
                    format!(
                        "{} in a{tracked} .env relocates the {} home to {value}{}{gemini_note}",
                        o.key,
                        crate::scanners::env_files::agent_for_home_key(&o.key),
                        if o.inside_project { " inside the project" } else { "" },
                    ),
                )),
                // A tracked .env is repository-controlled redirection. An untracked one is
                // usually the user's own app config (an OpenAI-compatible SDK pointed at a
                // provider) and reaches a coding agent only when something loads it, so
                // it is advisory.
                "gateway" if !o.official && !o.loopback => Some((
                    if t { Severity::High } else { Severity::Low },
                    "Gateway routing",
                    // Starts with the key: Blueprint matches .env gateways by location.
                    if t {
                        format!(
                            "{} points to non-official host {value} in a git-tracked .env — every clone routes requests (and the API key) there when the .env is loaded (EAA-007){gemini_note}",
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
                location: id.clone(),
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
                location: id.clone(),
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
        let title = match (o.bind.as_str(), o.service) {
            ("wildcard", true) => format!(
                "OLLAMA_HOST={} in {} config makes the Ollama server listen on every interface — the Ollama API has no authentication",
                o.value, c.shell
            ),
            ("wildcard", false) => format!(
                "OLLAMA_HOST={} in {} config makes `ollama serve` started from this environment listen on every interface — the Ollama API has no authentication",
                o.value, c.shell
            ),
            ("non-loopback-ip" | "hostname", true) => format!(
                "OLLAMA_HOST={} in {} config makes the Ollama server listen on a non-loopback address — the Ollama API has no authentication",
                o.value, c.shell
            ),
            _ => continue,
        };
        f.push(Finding {
            severity: Severity::Medium,
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
