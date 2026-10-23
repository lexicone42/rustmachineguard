# Built-in Threat Catalog

rustmachineguard ships a built-in catalog of known-malicious and known-vulnerable packages
that is automatically checked during every scan. The catalog currently contains 228 entries
covering malicious npm/PyPI packages, CVEs in MCP infrastructure, compromised VS Code
extensions, malicious browser extensions, and — in the `agent-runtime` ecosystem — CVEs
in the agent runtimes themselves (Claude Code, Claude Desktop/Cowork, Codex CLI, Copilot
CLI, Gemini CLI, Goose, Kiro IDE, Ollama), matched against the installed tool's own
version. Each `agent-runtime` key names exactly one product version line; the mapping
lives in `agent_runtime_key()` and is tested.

### A note on legitimate-but-compromised packages

Some entries pin a **specific version** (e.g. `litellm@1.82.7`, `durabletask@1.4.1-1.4.3`,
`telnyx@4.87.1`). These are otherwise-legitimate, widely-used packages that were briefly
compromised via a stolen publisher token or supply-chain attack. We match the exact
affected versions so we do **not** false-positive on the clean releases.

For "vulnerable below version X" cases — legitimate, ubiquitous packages with a CVE fixed
in a known release — entries carry a **`version_range`** (semver) instead: e.g.
`@modelcontextprotocol/server-filesystem` (`<2025.7.1`, the EscapeRoute CVEs),
`mcp-remote` (`>=0.0.5, <0.1.16` and `>=0.1.32, <0.1.39`), `@modelcontextprotocol/inspector`
(`<1.0.3` and `>=2.0.0, <2.12.0`, one row per release line), the MCP Python SDK `mcp`
(`<1.30.0` and `>=2.0.0, <2.2.0`), the TypeScript SDK `@modelcontextprotocol/sdk` (`<1.32.0`)
and its v2 split packages, `fastmcp` (`>=2.10.0, <3.4.10` and `>=4.0.0, <4.1.2`),
`mcp-server-git` (`<2025.9.25`), and `@cyanheads/git-mcp-server` (`<2.1.5`, `<2.15.2`). A
patched install isn't flagged — and because a range treats an *unknown* version as a
conservative non-match, an unpinned `npx -y …` (which fetches the latest, patched release)
isn't flagged either, while a pinned vulnerable version still is. Pre-release versions are
compared by their numeric core (`0.1.1-rc.2` is read as `0.1.1`, `2.0.0a1` as `2.0.0`), so a
package that only ships pre-releases still matches; the one edge is that `X.Y.Z-pre` is
treated as the fix version `X.Y.Z` itself, a conservative miss.

A package compromised at several non-adjacent releases gets one exact-version row per
release (`@memtensor/memos-cloud-openclaw-plugin` 0.1.21 / 0.1.23 / 0.1.25): the matcher
has no `||` alternation, and the clean releases in between must not match.

A test (`cve_citing_catalog_entries_must_be_version_bounded`) enforces the rule that any
entry citing a CVE must carry a version bound — an unbounded CVE entry flags every
install, including patched ones.

Use `--no-builtin-catalog` to disable it, or `--threat-catalog <file>` to add your own
entries (merged with the built-in catalog by default).

### Deliberately not catalogued

Verified during the 2026-10-22 refresh and left out on purpose, so the next sweep does
not re-propose them:

- **Windows-only advisories** (Claude Desktop CVE-2026-88066 `git.exe` search-path, the
  OpenCode and MCP Inspector 2.x PowerShell `open` injection as a standalone row): the
  catalog has no platform field and rmguard runs on macOS and Linux, so the row would flag
  a stale macOS build for a bug it cannot have. The Inspector 2.x row is kept because its
  other advisories apply everywhere.
- **`fa-mcp-sdk@0.12.72`** (GHSA-h524-rpj8-rm5j): a composition-based automated
  malware flag on a legitimate, actively developed SDK; the cited file is byte-identical
  in unflagged releases. Standing rule: an OSSF MAL record with no human analysis and no
  registry removal is not enough on its own.
- **`langgraph-sdk`** CVE-2026-104873: a server-side authorization bypass in a hosted
  framework, not endpoint posture.
- **`cursor-always-local` and siblings** (2025-01): dependency-confusion test packages
  published by a security vendor's research team and unpublished a day later.
- **`mcp-remote` as an unbounded range**: the researcher reports the SSRF code path still
  present in 0.15.x, but the CVE records name 0.1.32 through 0.1.38 and no vendor fix
  exists to bound against; the row uses the official range and says so in its text.
- **Hermes Agent as a git checkout**: the PyPI `hermes-agent` row covers the stale PyPI
  releases; the documented install is a clone under `~/.hermes/hermes-agent`, which only
  commit ancestry can classify.

## How It Works

The catalog is compiled into the binary at build time from
`src/catalogs/builtin_catalog.json`. Each entry specifies an ecosystem, package name,
optional version constraint, and an advisory string citing the source.

During scanning, every discovered MCP server, IDE extension, and browser extension is
checked against the catalog. Matches appear as exposure findings in all output formats.

## Sources and Attribution

This catalog is compiled from public security advisories, CVE databases, and researcher
disclosures. We credit the organizations and individuals whose work makes this possible:

### Security Research Organizations

| Organization | Contribution | License/Terms |
|---|---|---|
| **JFrog Security Research** | Discovered mcp-runcmd-server reverse shell campaign (XRAY-734538/39/40), CVE-2025-6514 in mcp-remote | Public advisories |
| **Socket.dev** | Discovered SANDWORM_MODE npm typosquatting campaign (19 packages targeting AI toolchains) | Public blog post |
| **Snyk** | First public disclosure of postmark-mcp malicious package | Public advisory |
| **ReversingLabs** | Extended postmark-mcp analysis and timeline | Public blog post |
| **Oligo Security** | Discovered CVE-2025-49596 in MCP Inspector | Public advisory, GHSA-7f8r-222p-6f5g |
| **Cymulate** | Discovered CVE-2025-53109 + CVE-2025-53110 (EscapeRoute) in MCP filesystem server | Public advisory |
| **Koi Security** | Discovered ClawHavoc campaign (341+ malicious skills) and MaliciousCorgi VS Code extensions | Public blog posts |
| **Datadog Security Labs** | Discovered Clawsights malicious Claude Code skill | Public blog post |
| **Kaspersky GERT** | Published devtools-assistant PoC demonstrating MCP credential harvesting | Public advisory (Securelist) |
| **Invariant Labs** | Coined "Tool Poisoning Attacks", disclosed github-mcp-server prompt injection | Public blog posts |
| **Trail of Bits** | Identified Line Jumping, Conversation History Theft, ANSI Terminal Deception attacks | Public blog post |
| **Endor Labs** | Analyzed 2,614 MCP servers: 82% prone to path traversal, 67% code injection | Public blog post |
| **Cloud Security Alliance** | "MCP Security Crisis" report (May 2026) with aggregate statistics | Public research note |
| **Wiz** | Discovered 550+ leaked secrets across 500+ VS Code extensions | Public blog post |
| **Cyata** | Discovered CVE-2025-68143/68144/68145 triple chain in mcp-server-git | Public advisories |
| **Check Point** | Discovered CVE-2025-54136 (MCPoison) in Cursor IDE | Public advisory |
| **Aikido** | Detailed Nx Console supply chain compromise analysis | Public blog post |
| **ExtensionTotal** | MaliciousCorgi campaign analysis, VS Code extension security research | Public blog posts |
| **Cyberhaven** | Disclosure of compromised Cyberhaven Chrome extension incident (2024-12) | Public disclosure |
| **Guardio Labs** | Discovered trojanized ChatGPT browser extensions stealing session cookies | Public blog posts |
| **Sekoia.io TDR** | Enumerated the December 2024 Chrome extension supply-chain campaign, including the compromised Cyberhaven extension ID | Public blog posts |
| **eSentire TRU** | Independent confirmation of the compromised Cyberhaven extension ID and affected versions | Public security advisories |
| **JetBrains Marketplace team** | Identified and removed 15 malicious AI-themed plugins (2026-06) and published their IDs | Public security update |
| **StepSecurity** | Independent analysis of the 15 malicious JetBrains plugins: vendors, install counts, exfiltration endpoint | Public blog posts |
| **SafeDep** | Discovered the `durabletask` PyPI hijack (Microsoft SDK, multi-cloud cred stealer) | Public blog post |
| **StepSecurity** | Discovered the `easy-day-js` typosquat across 140+ @mastra AI-framework packages | Public blog post |
| **Datadog Security Labs** | Discovered the TeamPCP `litellm`/`telnyx` PyPI compromises | Public blog post |
| **Tenable** | Mini Shai-Hulud worm (CVE-2026-45321) analysis and FAQ | Public blog post |
| **OX Security** | SANDWORM_MODE 19-package re-analysis; AI-chat Chrome extension stealers | Public blog posts |
| **OSV.dev / PyPA Advisory DB** | MAL-/PYSEC records for the 2026 MCP-named PyPI typosquat wave (`openai-mcp`, `langchain-core-mcp`, `instructor-mcp`, `tiktoken-mcp`, `ray-mcp-server`) | OSV (CC-BY-4.0) |
| **GitHub Advisory Database** | GHSA records for `@mcpjam/inspector` (CVE-2026-23744), `@cyanheads/git-mcp-server` (CVE-2025-53107) | GHSA (CC-BY-4.0) |

| **LayerX Security / Akamai** | AiFrame: 32 fake AI-assistant Chrome extensions (260K+ users) with injected-iframe credential and Gmail theft; IDs verified against the original post | Public blog post |
| **Air Security** | Plugin4Shell: SHA-shaped-branch plugin pin bypass in Claude Code (CVE-2026-86063), Codex, Copilot CLI and Gemini CLI; inspired the plugin-pin check | Public blog post, GHSA credit |
| **Manifold Security** | GitSpawn: repo-local `core.fsmonitor` executed by agents' background git calls (Claude Code, Goose CVE-2026-72718, Hermes CVE-2026-71963); Open VSX evil-twin extension research | Public blog posts |
| **Pluto Research** | EtherDuck / SleepyDuck Open VSX Solidity extensions (mp4-steganographed payload, Ethereum-contract C2), both waves | Public blog post |
| **Yeeth Security** | Operation Solidity Pro (WhiteCobra-attributed) Open VSX stealer identifiers | Public blog post |
| **Socket Threat Research** | keyv/cacheable ChainDrop wave, tensorlake and litellm 1.107.0 detections, GlassWorm-linked VS Code theme loaders (Kirill Boychenko); inspired the theme-with-code detection | Public blog posts |
| **StepSecurity** | ChainDrop naming and keyv timeline, tensorlake hostage-token worm (Ashish Kurmi), litellm 1.107.0 analysis, MemTensor sckit corroboration | Public blog posts |
| **Aikido Security** | Shai-Hulud 2026-09-07 redeployment (Charlie Eriksen), GlassWorm Zig dropper and its second-stage extension (Ilyas Makari), MemTensor PyPI side (Oliver Smith); inspired the native-addon detection | Public blog posts |
| **SafeDep** | MemTensor sckit worm (npm + PyPI), Apex Foundation macOS infostealer (Kunal Singh), keyv/cacheable corroboration | Public blog posts |
| **Elastic Security Labs** | REF8801 Apex Accelerator: backdoored coding-agent fork relaying OpenRouter traffic and planting an attacker MCP server (Jia Yu Chan, Daniel Stepanic) | Public blog post |
| **CloudSEK** | NEBULA fake AI SDK npm packages dropping the KNTRAT Windows RAT (Vikas Kundu) | Public blog post |
| **codelake Research** | imjustbetterxd campaign: five AI coding-agent CLI impersonations relaying provider keys | OpenSSF malicious-packages |
| **Datadog Security Labs** | litellm 1.107.0 compromise analysis (Ian Kretz); OpenCode `/global/upgrade` cross-site install (Christophe Tafani-Dereeper) | Public blog posts, GHSA credit |
| **Wiz Research, Upwind Security, OX Security** | Independent litellm 1.107.0 analyses; OX Research reported CVE-2026-82533 in the DeepSeek dsh harness (Nir Zadok, Moshe Siman Tov Bustan) | Public blog posts |
| **Pillar Security** | MCP OAuth authorization URL to PowerShell in OpenCode and MCP Inspector 2.x (GHSA-q978-78c7-phqw); Deadbugz runtime-gated MCP metadata poisoning | Public blog posts, GHSA credit |
| **Cycode** | MCP Python SDK OAuth authorization-server misdirection (GHSA-qx49-fqc8-xw99, Yuval Elbar) | Public blog post, GHSA credit |
| **Compass Security** | Codex CVE-2026-19591 PowerShell stop-parsing token bypass | CNA credit |
| **Fudan University SSSL and Doyensec via ZDI** | Codex CVE-2026-19592 repo-local fsmonitor execution | CNA credit |
| **Redguard AG** | Gemini CLI CVE-2026-13745 `.env` overriding `GEMINI_CLI_HOME` (Benjamin Faller); inspired the .env agent-home override detection | Public advisory |
| **Cyera Research** | Claude Desktop Cowork shared-folder file execution (GHSA-v234-4jrq-mgg6, Vladimir Tokarev) | Vendor advisory credit |
| **NVIDIA AI Red Team** | Claude Code CVE-2026-103012 managed settings not applied (Tamas Voros) | Vendor advisory credit |
| **HiddenLayer SAI** | Mistral Vibe shell-permission bypasses CVE-2026-87983 to -87988 (Esteban Tonglet) | CNA |
| **Checkmarx Zero** | ViteVenom `@vite-mcp/vite-type` impersonation (Pavan Gudimalla) | Public blog post |
| **pkgwarden** | `faiss-cpu-avx512` PyPI impersonation | OpenSSF malicious-packages |
| **Amazon Inspector** | Automated finder credited on most 2026 OSSF MAL records in this refresh (Shai-Hulud nodes, NEBULA, Apex, agentaix, openaii wave) | OpenSSF malicious-packages |
| **OpenSSF malicious-packages / Kamil Mańkowski (kam193)** | MAL records and campaign analysis for the 2026-09-openaii, 2026-10-agentaix and 2026-10-semvver PyPI waves | OSV (CC-BY-4.0) |
| **Eclipse Foundation Open VSX, Microsoft VS Marketplace** | Registry-operator blocklists (`extension-control/extensions.json`, `RemovedPackages.md`) used to corroborate extension identifiers | Public repositories |
| **Aqua Security** | Trivy extension compromise advisory GHSA-8mr6-gf9x-j8qg / CVE-2026-28353 | Vendor advisory |
| **AWS Security** | Kiro IDE CVE-2026-89332 (bulletin 2026-111) | Vendor bulletin |
| **Anthropic, OpenAI, Google, Block (goose), Ollama, Anomaly (OpenCode), PrefectHQ (FastMCP), MCP SDK and Inspector maintainers** | Vendor security advisories that supply the agent-runtime and SDK version bounds | GHSA / CNA records |

### Individual Researchers

| Researcher | Contribution |
|---|---|
| **Or Peles** (JFrog) | CVE-2025-6514 (mcp-remote command injection) |
| **Oren Yomtov** (Koi Security) | ClawHavoc campaign discovery |
| **RyotaK** | Claude Code GitHub Action bot trust bypass |
| **Inga Cherny** (Cato CTRL) | GIF Creator skill weaponization PoC |
| **Natalie Zargarov, Dar Kahllon** (LayerX / Akamai) | AiFrame Chrome extension campaign |
| **Or Nevo Michrowski, Dor Granat, Niv Hoffman** (Air Security) | Plugin4Shell |
| **Francisco Rosales, Ax Sharma** (Manifold Security) | GitSpawn |
| **Eitan Chassid, Yotam Perkal** (Pluto Research) | EtherDuck Open VSX extensions |
| **Lidor Machluf** (Upwind Security) | First public report of litellm 1.107.0 (BerriAI/litellm#47826); keyv payload analysis |
| **Alex Gercog** (playb0t) | mcp-remote OAuth discovery SSRF, CVE-2026-51994/51995 |
| **George Chen, Jashn Wahi** | `@cyanheads/git-mcp-server` CVE-2026-85626 |
| **c_h4ck_0, edbr** (HackerOne) | Claude Code CVE-2026-103435, CVE-2026-25725 |
| **Akıner Kısa** | Ollama agent-mode CVE-2026-102697 |
| **bhavya32, Lemohang Khaile, sondt99, CloneOfAlex, 0xParth, hackyhunter, eilonc-pillar** | MCP Inspector 2026-10-21 advisories |
| **jlmitra-ampl, 0xParth, rishid, LHMisme420, GEONWOOHAN** | FastMCP October 2026 advisories |
| **Grg0rry, rainfantry, EQSTLab** | langgraph-sdk, mcp-atlassian, meta-ads-mcp advisories |

### Databases and Trackers

| Resource | URL | Use |
|---|---|---|
| **vulnerablemcp.info** | https://vulnerablemcp.info/ | Comprehensive MCP vulnerability database (50+ CVEs) |
| **OWASP MCP Top 10** | https://owasp.org/www-project-mcp-top-10/ | Risk taxonomy |
| **NVD** | https://nvd.nist.gov/ | CVE details and CVSS scores |
| **GitHub Advisory Database** | https://github.com/advisories | GHSA identifiers |
| **Endpoint AI Agent Abuse (EAA)** | https://github.com/0x4D31/endpoint-ai-agent-abuse | Technique taxonomy (EAA-001…016) for local-agent abuse; informs our detection coverage mapping. Licensed CC0-1.0 (0x4D31). Inspired the EAA-007 hostile-gateway-routing, EAA-005 agent-transcript-collection, and EAA-009 remote-plugin-marketplace detections. |

### Academic Papers

| Paper | ID | Relevance |
|---|---|---|
| SkillFortify | arXiv:2603.00195 | 8-resource capability taxonomy, trust score algebra |
| MCPTox | arXiv:2508.14925 | 72.8% attack success rate across 45 MCP servers |
| MCP-ITP | arXiv:2601.07395 | Implicit tool poisoning, 84.2% ASR |
| ETDI | arXiv:2506.01333 | Tool squatting and rug pull attack models |
| MCP-38 | arXiv:2603.18063 | 38 threat categories mapped to STRIDE/OWASP |

## Detection techniques and their sources

Detections that are not catalog rows but follow a researcher's or vendor's published
technique. Each detection also names its source in a comment at the code.

| Detection | Where | Source |
|---|---|---|
| Plugin pin | `marketplaces` | Air Security (Or Nevo Michrowski, Dor Granat, Niv Hoffman): Plugin4Shell, CVE-2026-86063 / GHSA-pq7j-f95f-qfcv; Codex fix openai/codex PR #34644 |
| Skill symlink | `skills` | CVE-2026-103435 write-time symlink following (c_h4ck_0, edbr); real-path (multi-hop, symlinked-directory) resolution added after an internal review showed the lexical first-hop check could be walked past |
| Skill command, Skill grant | `skills` | Anthropic Claude Code docs: skills (dynamic context injection, `allowed-tools`, `disableSkillShellExecution`, synced skills) and permissions (`Bash(*)` is equivalent to `Bash`) |
| Agent redirection, .env Gateway routing | `envfiles` | Redguard AG (Benjamin Faller): Gemini CLI CVE-2026-13745; EAA-007 hostile gateway routing (0x4D31); CVE-2026-21852; vendor variable docs (Claude Code env-vars, Gemini CLI configuration, Codex config, Cursor CLI configuration, Kiro settings); OpenAI data-residency docs (`<region>.api.openai.com`); LiteLLM proxy quick start (clients dial `0.0.0.0:4000`) |
| Helper command, Login gateway | `settings` | Anthropic Claude Code settings reference and Claude apps gateway docs |
| Extension code | `extensions` | Socket Threat Research (Kirill Boychenko): GlassWorm-linked theme loaders; Aikido Security (Ilyas Makari): GlassWorm Zig dropper native addon. The entry-point check applies to theme extensions only (the GlassWorm shape); native addons are checked in every declarative extension |
| Hook (Claude Code settings, statusLine, plugins, mods, frontmatter) | `settings`, `skills` | Anthropic Claude Code docs, fetched 2026-10-23: code.claude.com/docs/en/hooks (handler types, exec-form `args`, http/mcp_tool fields, hooks in skills and agents, `disableAllHooks`, `allowManagedHooksOnly`), /settings-reference and /statusline (statusLine, subagentStatusLine, fileSuggestion), /permissions, /plugins-reference, /plugins/mods/reference and /plugins/mods/create (`modules`), /plugins/mods/api.md ("The hooks module itself has no Node.js APIs"; `$.process.run` "takes an argument list and uses no shell", so it is graded as a shell-execution call), /plugins/loading (skills-dir plugins, path escapes), /skills and /sub-agents (plugin subagent hooks are ignored; "Claude Code scans `.claude/agents/` and `~/.claude/agents/` recursively"), all fetched 2026-10-23. Technique: EAA-003 lifecycle hook persistence (Endpoint AI Agent Abuse catalog, 0x4D31, CC0); repository hooks that run before trust: Check Point Research (Aviv Donenfeld, Oded Vanunu), "Caught in the Hook: RCE and API Token Exfiltration Through Claude Code Project Files", CVE-2025-59536 / CVE-2026-21852 (2026-02-25, fetched 2026-10-23); the cross-directory script reference is the Shai-Hulud persistence pattern (in a repository; one personal script under HOME shared by several agents is a Low advisory, since Cursor and Devin CLI import `~/.claude` configuration, and a repository sharing one script between its own `.claude`, `.cursor`, `.codex` and `.gemini` directories is its plain hook, since Cursor runs a repository's `.claude` hooks itself; `.vscode/` keeps the pattern); hidden text in a prompt/agent hook's prompt is ASCII smuggling: Unicode tag characters "remain unnoticable to users… but LLMs interpret such text" (Johann Rehberger, "ASCII Smuggler Tool: Crafting Invisible Text and Decoding Hidden Codes", embracethered.com, 2024-01-14, fetched 2026-10-23), so tag, variation-selector, zero-width and bidi characters in a hook prompt are graded like an injection phrase; Claude Code's (and Cursor's) prompt/agent hooks are matched with a narrower subset of the MCP tool-poisoning phrase families of Invariant Labs (tool poisoning), Trail of Bits (line jumping) and CyberArk ("Poison everywhere"), because the prompt goes to the hook's evaluator model and only its decision's `reason` reaches the agent (code.claude.com/docs/en/hooks-guide, fetched 2026-10-23), while prompts the agent itself reads (Copilot CLI, Kiro, rows below) get the whole list; an emoji ZWJ sequence or right-to-left prose is not hidden text (review of b9cda85); managed `enabledPlugins` force-enabled plugins are exempt from `allowManagedHooksOnly` (/hooks); http hooks for "a shared audit service" are the documented use (/hooks-guide), so the user's own are graded by host reach |
| Hook (Claude Code files other agents run) | `settings` | Cursor runs `~/.claude/settings.json`, `.claude/settings.json` and `.claude/settings.local.json` hooks, "on by default" (cursor.com/docs/reference/third-party-hooks); Copilot CLI reads the repository's `.claude/settings.json` and `settings.local.json` (docs.github.com/en/copilot/reference/hooks-configuration); Devin CLI reads all of them while `read_config_from.claude` is on, the default (docs.devin.ai/cli/extensibility/hooks/overview); all fetched 2026-10-23. So a Claude Code managed `allowManagedHooksOnly`/`disableAllHooks` does not silence these files' hooks |
| Hook command redaction | `settings`, `skills` | Webhook URLs whose path is the credential: Slack incoming webhooks ("Your webhook URL contains a secret", docs.slack.dev/messaging/sending-messages-using-incoming-webhooks, formerly api.slack.com/messaging/webhooks), Discord `POST /api/v10/webhooks/{id}/{token}` ("the secure token of the webhook", docs.discord.com/developers/resources/webhook), Telegram `https://api.telegram.org/bot<token>/METHOD_NAME` (core.telegram.org/bots/api), all fetched 2026-10-23; shapes found in the review of f4dbf35 |
| Hook (Cursor) | `settings` | cursor.com/docs/hooks (events incl. `workspaceOpen`, enterprise paths, prompt hooks), cursor.com/docs/reference/plugins and cursor.com/docs/plugins (local plugins, `CURSOR_PLUGIN_ROOT`), cursor.com/docs/reference/third-party-hooks (Cursor runs a repository's `.claude/settings.json` hooks), fetched 2026-10-23 |
| Hook (Codex) | `settings` | learn.chatgpt.com/docs/hooks.md (formerly developers.openai.com/codex/hooks.md, which now 308-redirects there; handler types; prompt/agent "parsed but skipped"; manifest hooks used instead of the default `hooks/hooks.json`, re-fetched 2026-10-23), /codex/config-basic.md, /codex/enterprise/managed-configuration.md (`requirements.toml` `[hooks]`), developers.openai.com/plugins/build/plugins.md (`.codex-plugin/plugin.json` `hooks`; the cache `~/.codex/plugins/cache/$MARKETPLACE_NAME/$PLUGIN_NAME/$VERSION/`, `$VERSION` `local` for local plugins, so the plugin identity is marketplace and plugin), fetched 2026-10-23; `[features] hooks = false` turns hooks off ("The deprecated alias codex_hooks still works"), and "Admins can force hooks off the same way in `requirements.toml`" (learn.chatgpt.com/docs/hooks.md, fetched 2026-10-23) |
| Hook (Copilot CLI) | `settings` | docs.github.com/en/copilot/reference/hooks-configuration (file locations, `version: 1` for "Hook configuration files", the settings files' "Inline `hooks` block" with no version stated, `disableAllHooks`, `bash`/`command`/`exec`+`args`, http and prompt hooks, `policy.d`; "Prompt hooks auto-submit text as if the user typed it. They are only supported on `sessionStart`", so a prompt hook is graded as text in the agent's conversation with the whole MCP tool-poisoning list and its credential paths, not as an evaluator prompt) and /copilot/reference/copilot-cli-reference/cli-config-dir-reference (installed plugins), fetched 2026-10-23 |
| Hook (Gemini CLI) | `settings` | github.com/google-gemini/gemini-cli docs/hooks/index.md and docs/hooks/reference.md (command hooks, `GEMINI_PROJECT_DIR`), docs/extensions/reference.md (`hooks/hooks.json`, `${extensionPath}`), docs/reference/configuration.md (system settings paths; `hooksConfig.enabled`: "When disabled, no hooks will be executed", also at geminicli.com/docs/reference/configuration), fetched 2026-10-23 |
| Hook (Devin Desktop / Windsurf) | `settings` | docs.windsurf.com/windsurf/cascade/hooks, now served at docs.devin.ai/desktop/cascade/hooks (system, user and workspace paths, events, the legacy `.windsurf` fallback), fetched 2026-10-23 |
| Hook (Devin CLI) | `settings` | docs.devin.ai/cli/extensibility/hooks/overview.md (`.devin/hooks.v1.json`, `config.json` `hooks`, `~/.claude.json` hooks read in Claude Code format; a prompt hook is only "to evaluate an LLM prompt", where its text goes is not stated, so it is graded as conversation text: a README floor) and /cli/extensibility/plugins/overview.md, fetched 2026-10-23 |
| Hook (OpenCode) | `settings` | opencode.ai/docs/plugins/ (plugin directories, `opencode.json` `plugin`, the documented hook keys), fetched 2026-10-23 |
| Hook (Kiro) | `settings` | kiro.dev/docs/hooks/ (`.kiro/hooks/*.json`, `version: "v1"`, `trigger`, `action` command/agent, `enabled`, `confirm.confirmCommand`, `~/.kiro/hooks` for CLI V3) and kiro.dev/docs/hooks/actions/ (an agent action's prompt "is appended to the user prompt, and the combined prompt is sent to the agent": graded as conversation text), fetched 2026-10-23 |
| Ollama exposure | `shell`, `envfiles` | Ollama FAQ (`OLLAMA_HOST`, default 127.0.0.1:11434) and `envconfig.Host()` in ollama/ollama. Accepted deviation from the detection spec: a wildcard `OLLAMA_HOST` in a project `.env` is Low, not a warning (it binds only a server started from that environment, normally a container); profiles, systemd units and launchd jobs are Medium |

## Updating the Catalog

To add entries, edit `src/catalogs/builtin_catalog.json`. Each entry is:

```json
{
  "ecosystem": "npm",
  "name": "package-name",
  "version": "1.0.0",
  "advisory": "Short description with source attribution"
}
```

- Omit both `version` and `version_range` to match all versions — **only** for fully
  malicious packages, where every release is bad
- Include `version` for exact matching (a single compromised release, e.g. Nx Console
  `18.95.0`)
- Include `version_range` (semver, e.g. `<1.30.0` or `>=0.0.5, <0.1.16`) for a
  legitimate package with a CVE fixed in a known release
- **Any entry citing a CVE must carry a bound** — an unbounded CVE entry flags every
  install including patched ones. This is enforced by a test
- Always include the source in the advisory string

To contribute additional entries, please open a PR with:
1. The JSON entry in `builtin_catalog.json`
2. A link to the public advisory or CVE in the PR description
3. A test in `tests/property_tests.rs` verifying the match

## License

The catalog data (advisory descriptions, CVE identifiers, package names) is compiled from
publicly available security advisories. CVE identifiers are public domain. Advisory
descriptions are original text summarizing public disclosures. The catalog itself is
distributed under Apache 2.0 as part of rustmachineguard.
