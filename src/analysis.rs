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
            what: "An AI provider base-URL override points at a non-official host, so requests (and the API key) route through a third party.",
            why: "Whoever controls that host sees every prompt and can capture the API key — the exfiltration vector behind CVE-2026-21852. A legitimate proxy looks identical, so this needs a human check.",
            fix: "Confirm the host is a gateway you deliberately configured and trust. If not, remove the override and rotate the API key.",
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

    f.sort_by_key(|x| x.severity.rank());
    f
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
