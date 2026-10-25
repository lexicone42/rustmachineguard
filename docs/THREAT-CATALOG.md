# Built-in Threat Catalog

rustmachineguard ships a built-in catalog of known-malicious and known-vulnerable packages
that is automatically checked during every scan. The catalog (version `2026-10-25.3`) currently contains 307 entries
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
`@modelcontextprotocol/server-filesystem` (`<1.0.0`, `>=2025.1.14, <=2026.8.31` and `>=1.0.0, <2.0.1`,
one row per version scheme; see "Version-scheme resets" below),
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
has no `||` alternation, and the clean releases in between must not match. Malicious
releases stay exact-version rows even when they are consecutive (`agentic-awesome-skills`,
20 rows; `opencode-skills-collection`, 21 rows; `agentwork-cli` 0.1.4 and 0.1.5; the Trivy
extension 1.8.12 and 1.8.13; Cyberhaven 24.10.4): a row's kind is read from its shape, so a
`version_range` row would be reported as a "Vulnerable ... package version" (and downgraded
in a dormant npx cache) instead of "Known-bad".

### Version-scheme resets

A range compares numbers, not release dates, so a package that changes its versioning
scheme can turn a correct row into a false positive overnight.
`@modelcontextprotocol/server-filesystem` went from 0.x (0.2.0 to 0.6.2) to date versions
(2025.1.14 to 2026.8.31) and then restarted on semver: 1.0.0 (2026-10-11), 2.0.0
(2026-10-19) and 2.0.1 (2026-10-25, the fix for four new advisories). Every semver release
sorts below 2025.7.1, so the 2026-10-22 row `<2025.7.1` reported the fixed 2.0.1 as a
Critical vulnerable install. The 2026-10-25 catalog gives each scheme its own row (`<1.0.0`,
`>=2025.1.14, <=2026.8.31`, `>=1.0.0, <2.0.1`); the date line has no fixed release, so its
row is closed at the last date release rather than open-ended. `server-everything` restarted
the same way and has the same two-row shape. Rules that follow:

- A range on a date-versioned package names both ends (`>=first, <=last`), never just `<fix`.
- When a date-versioned package publishes a version that looks like semver, re-check every
  row for it. `mcp-server-git` (PyPI, still date-versioned at 2026.10.19) is the next one to
  watch.
- `scripts/catalog-latest-check.py` (see "Updating the Catalog") flags a row whose range
  contains the registry's current release, which is how a reset shows up.

### Malicious rows backed only by an advisory

The 2026-10-22 bar for a malicious row was a GitHub malware advisory plus registry removal
(an OSSF MAL record alone, with no human analysis and no removal, is not enough). Some rows
meet that bar with no published cause: `@tekmidian/pai` 1.0.8 to 1.0.10, `skillward`,
`x402-prompt-injection-scan` 0.1.4, the `agentic-awesome-skills` and
`opencode-skills-collection` releases, the seven `@beloved-lenora/opencode-*` packages, and
the 2026-10-19 lure cluster (`claude-desktop-setup` and siblings). Their advisory text says
so ("flagged by GitHub malware advisory ...; npm removed the versions; cause not
published"). An automated false positive, an account takeover and a malicious bundled skill
all fit the registry evidence; if a maintainer disclosure or a retraction appears, revisit
these rows first. Two `opencode-skills-collection` releases the advisory lists (4.1.7 and
4.1.16) were still downloadable on 2026-10-25; they are catalogued because the advisory
names them.

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

Left out during the 2026-10-25 refresh:

- **`trigger.dev`** CVE-2026-114090 / GHSA-pqmg-rq46-vm4m (`trigger dev --mcp` binds all
  interfaces with no auth): the advisory names `@trigger.dev/cli-v3`, which npm does not
  have; mapping it to the `trigger.dev` CLI package is an inference, and a row has no field
  to say so. Add it once the advisory names the published package.
- **vLLM** (about 20 advisories in the window, including GHSA-h3rc-j82p-2c3h and
  GHSA-6757-hggm-hp2w RCEs and the permissive default CORS GHSA-vvpg-rrww-wpmh), the
  litellm proxy, LMCache, mem0ai, MLflow, Langflow, langgraph-checkpoint, open-webui,
  strands-agents A2A, crewai-tools and pydantic-ai's server-side set: inference servers and
  server-side frameworks, the langgraph-sdk precedent.
- **`fastmcp` below 2.10.0**: the row's lower bound comes from the client RCE
  GHSA-gpgx-58w2-xwwf; older installs are affected only by server-side advisories
  (GHSA-99xm-8q53-5c8p, GHSA-qvjc-pw7p-hvg5, GHSA-63pr-7fpf-v477, GHSA-m2xc-hx3h-rjf6,
  GHSA-p8g9-xjch-9mxg) and the Windows-only GHSA-57vm-5fr9-3r5x, which this catalog does not
  count as endpoint posture. The bound stays at 2.10.0, and the `fastmcp-slim` rows mirror
  the fastmcp ones, citing only the advisories that name `fastmcp-slim`.
- **Goose** CVE-2026-111079 (terminal integration sends shell history to the LLM provider):
  the Red Hat record names no affected or fixed version, and an unbounded CVE row is
  forbidden by test.
- **JetBrains Junie CLI** CVE-2026-111091 (fixed 26.8.3): there is no `agent-runtime` key
  for Junie, and the npm packages (`@jetbrains/junie-cli` 1468.x, `@jetbrains/junie`
  3110.x) do not use the vendor's 26.x numbering, so no bound can be stated.
- **Z.ai ZCode** CVE-2026-88755 and **DeepSeek Harness (dsh)** CVE-2026-95183: a CNA
  record and a researcher gist only, no vendor source; dsh is identified by commit, not
  version.
- **`mcp-ripgrep`** CVE-2026-113378: the CNA marks its existence as disputed and no fixed
  release exists.
- **Optional rows not taken**: `mcp-server-fetch` GHSA-3jqg-r5pp-rmp2 (low: robots.txt not
  rechecked after redirects; deferred), `mcp-contextforge-gateway` CVE-2026-8355 (authenticated SSRF,
  server-side), `@aborruso/ckan-mcp-server` CVE-2026-76894 (low), `@lumen-labs-dev/whisper-node`
  0.5.1 (speech bindings, not an agent surface), and the kam193 `2026-10-voice-synthesis-profiles`
  and `2026-10-emberlytts` PyPI loader campaigns (about 45 AI-audio-themed names with an
  unknown payload; weak tie to agent posture, deferred).
- **`netbox-mcp-server`** CVE-2026-57207: not published on PyPI, so there is no name to match.

## How It Works

The catalog is compiled into the binary at build time from
`src/catalogs/builtin_catalog.json`. Each entry specifies an ecosystem, package name,
optional version constraint, and an advisory string citing the source.

A vulnerable-range row may also carry `advisory_severity` (`critical`, `high`, `medium` or
`low`): the highest severity among the advisories the row cites, as the advisory states it,
on the GitHub Advisory Database scale (from the CVSS score: critical 9.0-10.0, high
7.0-8.9, medium 4.0-6.9, low 0.1-3.9; [About CVSS
levels](https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database#about-cvss-levels)).
A match is graded at that severity (see below); a user catalog may also write GitHub's API
spelling `moderate` for medium. Malware rows do not carry it, and it is ignored there:
GitHub stamps every malware record critical, and a malicious release is Critical by kind. A row spanning
versions where only some advisories apply still carries the highest (the
server-filesystem date row is `high` for its EscapeRoute part, though 2025.7.1 and later
releases have only medium and low advisories).

During scanning, every discovered MCP server (configured, and an enabled Claude Code
plugin's own `.mcp.json` / `plugin.json` `mcpServers`; a disabled plugin's servers and
claude.ai connectors are inventory only), IDE extension, and browser extension is checked
against the catalog, and so is every installed npm and PyPI package. Matches appear as
exposure findings in all output formats.

A row that names an exact version, or no version, is a malicious release: its match is
Critical ("Known-bad"). A row with a `version_range` is a vulnerable version, and its
match in an active install is graded at the row's `advisory_severity` (Critical, High,
Medium or Low, with the title saying so: "Vulnerable npm package version (advisory
severity: high)"), or Critical, as before, for a row without one. When it is
found only in an npx cache (`~/.npm/_npx/<hash>/`, code `npx` fetched once and runs again
only when the same `npx` line is re-run) and no enabled configured or plugin MCP server
launches the package the cache was fetched for, it is one step lower (never below Low; High
for a row without a severity), titled "Vulnerable MCP SDK
version in npx cache (dormant unless re-run)" for the `@modelcontextprotocol/*` SDK
packages, and names that package (from the cache's `package.json` `_npx.packages`, else its
`dependencies`). The finding's evidence keeps the catalog row's range and the advisory IDs.

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
| **GitHub Advisory Database / npm Security** | 2026-10-25 refresh: the malware records behind the `@beloved-lenora/opencode-*`, `skillward`, `x402-prompt-injection-scan`, `@tekmidian/pai`, `agentic-awesome-skills`, `opencode-skills-collection`, `unicode-title-normalizer` and `formatting-subtitles` rows, and the reviewed records for `obsidian-tc`, `graphifyy`, `netlicensing-mcp`, `mcp-contextforge-gateway` and `pydantic-ai` (https://github.com/advisories) | GHSA (CC-BY-4.0) |

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
| **moamenmahmood** (HackerOne) | Claude Agent SDK for Python CVE-2026-96620 (`resume` flag injection) |
| **ehudmelzer** | `server-everything` GHSA-mvf5-2qqv-rg3c (cross-origin environment read) |
| **gdegrange** | MCP TypeScript SDK CVE-2026-111771 (bearer tokens for another service; `express`, `server-legacy`) |
| **Kamil Mańkowski (kam193)** | Human analysis of `py-worm` (campaign 2026-10-agentaix, MAL-2026-17883) |

### Databases and Trackers

| Resource | URL | Use |
|---|---|---|
| **Claude Code documentation** (Anthropic) | https://code.claude.com/docs/en/permissions.md, /permission-modes.md, /auto-mode-config.md, /settings-reference.md (fetched 2026-10-24) | Permission-rule grammar, path anchors, protected paths, wrapper stripping, `defaultMode` values, where each takes effect and their precedence, the allow rules auto mode drops ("On entering auto mode, broad allow rules that grant arbitrary code execution are dropped"), `skipDangerousModePermissionPrompt`, and the `autoMode` block (`environment`, `allow`, `soft_deny`, `hard_deny`, `"$defaults"`, `classifyAllShell`, scopes it is read from): the source for grading permission modes, allow rules and auto-mode configuration (not catalog rows) |
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
| Hook (Devin CLI) | `settings` | docs.devin.ai/cli/extensibility/hooks/overview.md (`.devin/hooks.v1.json`, `config.json` `hooks`, `~/.claude.json` hooks read in Claude Code format; the user-level files include `~/.claude/settings.local.json`, so it is read as `user-local` wherever the scan runs (review of 4e3f8c3); a prompt hook is only "to evaluate an LLM prompt", where its text goes is not stated, so it is graded as conversation text: a README floor) and /cli/extensibility/plugins/overview.md, fetched 2026-10-23 |
| Hook (OpenCode) | `settings` | opencode.ai/docs/plugins/ (plugin directories, `opencode.json` `plugin`, the documented hook keys), fetched 2026-10-23 |
| Hook (Kiro) | `settings` | kiro.dev/docs/hooks/ (`.kiro/hooks/*.json`, `version: "v1"`, `trigger`, `action` command/agent, `enabled`, `confirm.confirmCommand`, `~/.kiro/hooks` for CLI V3) and kiro.dev/docs/hooks/actions/ (an agent action's prompt "is appended to the user prompt, and the combined prompt is sent to the agent": graded as conversation text), fetched 2026-10-23 |
| Ollama exposure | `shell`, `envfiles` | Ollama FAQ (`OLLAMA_HOST`, default 127.0.0.1:11434) and `envconfig.Host()` in ollama/ollama. Accepted deviation from the detection spec: a wildcard `OLLAMA_HOST` in a project `.env` is Low, not a warning (it binds only a server started from that environment, normally a container); profiles, systemd units and launchd jobs are Medium |
| MCP command (plugin LSP servers) | `lsp` | Anthropic Claude Code docs, fetched 2026-10-24: code.claude.com/docs/en/plugins-reference.md (`lspServers`: "a `.json` file path, an inline map of server name to config, or an array of either"; "loads `.lsp.json` at the plugin root first, then each declared config in order"; fields `command`, `args`, `env`, `extensionToLanguage`, `transport`, ...) and /plugins/marketplace-reference.md (with no `plugin.json` "the entry is the manifest regardless of `strict`", including `lspServers`; with one, entry `lspServers` "don't apply"). Unpinned launches use the plugin MCP rule (`unpinned_reason`) |
| Plugin marketplace (old plugin versions still loaded) | `liveness` | Observed, undocumented: `~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/.in_use/<pid>` entries for live sessions (entry names only; `/proc/<pid>` owned by the user, Linux). The documented marker is `.orphaned_at` with cleanup "14 days later" (code.claude.com/docs/en/plugins/loading.md, fetched 2026-10-24). Running npx caches: `/proc/<pid>/cmdline` paths under `~/.npm/_npx/<hash>/` (matched, never stored) turn a "dormant unless re-run" Exposure into a Critical "running" one |
| Transcript exposure (agent browser profiles, output directories) | `playwright` | microsoft/playwright-mcp README, fetched 2026-10-24: persistent profile "(default)" at `~/.cache/ms-playwright/mcp-{channel}-{workspace-hash}` (macOS `~/Library/Caches/...`), `--isolated` "keep the browser profile in memory", `--user-data-dir`, `--output-dir`; @playwright/mcp 0.0.83 writes `~/.cache/ms-playwright-mcp/` and defaults its output to `<cwd>/.playwright-mcp` (installed code; the README states neither). Cookie and Login Data files: existence, mode and mtime only |
| Transcript exposure, Secret hygiene (secret-shaped content in agent transcripts) | `transcripts`, `vibe` | Token prefixes, each source page fetched 2026-10-25 (cited at the table in `src/scanners/transcript_content.rs`). Index: GitHub's supported secret-scanning patterns (docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns), which is also the cited source where a vendor publishes no format: OpenAI (`sk-proj-`/`sk-svcacct-`/`sk-admin-`/`sk-`; its API reference at developers.openai.com/api/reference/overview documents bearer auth only, and the old platform.openai.com page answers 403) and the lengths of Hugging Face `hf_` (huggingface.co/docs/hub/security-tokens shows only `hf_...`). Vendor pages: Anthropic `sk-ant-api03-` (`partial_key_hint` example, platform.claude.com/docs/en/api/beta/organization/api_keys/retrieve, formerly docs.anthropic.com/en/api/admin-api/apikeys/get-api-key) and `sk-ant-admin` (platform.claude.com/docs/en/manage-claude/admin-api); GitHub `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/`github_pat_` (docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github; base62 with a CRC32 checksum, github.blog "Behind GitHub's new authentication token formats"; neither states a length, and the first says new App installation tokens have a stateless `ghs_APPID_JWT` form since 2026-04-27, which the 36-character `ghs_` shape does not match); AWS `AKIA`/`ASIA` (IAM User Guide, reference_identifiers.html#identifiers-prefixes, corrected from #identifiers-unique-ids; the API reference gives the id only as 16 to 128 `[\w]` characters); Slack `xoxb-`/`xoxp-` (docs.slack.dev/authentication/tokens, formerly api.slack.com/concepts/token-types); GitLab `glpat-` (docs.gitlab.com/security/tokens/#token-prefixes, no length); npm `npm_` (GitHub changelog 2021-09-23: prefix and base62 CRC32 checksum, no length; its "36 characters" is the old UUID format); Google `AIza` (docs.cloud.google.com/docs/authentication/api-keys, formerly cloud.google.com: an example key of `AIza` and 35 characters, no stated length); PEM private keys (RFC 7468 `PRIVATE KEY` and `ENCRYPTED PRIVATE KEY`; the `RSA`/`EC`/`OPENSSH` labels also matched are not in it). Prefix plus a plausible length and charset; only the LABEL and a count are recorded, never the match. Key names use the `.env` classifier, with `KEY` as a whole word (the command redactor's rule): `KEYBOARD`, `KEYWORD`, `HOTKEY`, `MONKEY` are not secret names |
| Rules file (nested instruction files) | `rules` | code.claude.com/docs/en/memory.md, fetched 2026-10-24 (subdirectory `CLAUDE.md`/`CLAUDE.local.md` load "once Claude reads, writes, or edits another file in that subdirectory"; a subdirectory's `AGENTS.md` when it has no `CLAUDE.md`); google-gemini/gemini-cli docs/cli/gemini-md.md (JIT `GEMINI.md` "in that directory and its ancestors up to a trusted root", and workspace `GEMINI.md`) |
| Permissions, Plugin marketplace, Secret exposure (Mistral Vibe) | `vibe`, `ai` | mistralai/mistral-vibe README and docs/acp-setup.md; docs.mistral.ai/vibe/code/cli/configuration-reference.md (`[[mcp_servers]]`, `tools.<name>.permission` "always"/"ask"/"never", `enable_telemetry`, `session_logging.save_dir`, `~/.vibe/.env`, `enable_auto_update` "has no effect" in current versions); installed 2.5.0 source for `auto_approve` (every tool call executes without asking), `enable_auto_update` (runs the upgrade command), `trusted_folders.toml` keys and `vibehistory`, all fetched 2026-10-24. `bypass_tool_permissions` is inventoried, not graded |
| Persistence (settings-command scripts) | `statusline` | code.claude.com/docs/en/statusline.md, fetched 2026-10-24 ("runs any shell script you configure"; `/statusline` "generates a script file in `~/.claude/`"): the script it names under `~/.claude/` is identified like `~/.claude/bin` executables and graded High only when group/other-writable or not owned by the user |
| Network listener (shell bridges beyond loopback) | `listeners`, `envfiles` | Linux procfs, proc_net_tcp(5)/proc(5) man pages (LISTEN is state `0A`; addresses are `%08X` words in host byte order; `/proc/<pid>/fd` links read `socket:[<inode>]`; `task/<tid>/children` needs `CONFIG_PROC_CHILDREN`, so the parent pid in `stat` is the fallback). Web-terminal programs by name, from each project's README: ttyd (github.com/tsl0922/ttyd), gotty (github.com/yudai/gotty, github.com/sorenisanerd/gotty), wetty (github.com/butlerx/wetty), shellinabox (github.com/shellinabox/shellinabox, daemon `shellinaboxd`), webssh (github.com/huashengdun/webssh, `wssh`), sshwifty (github.com/nirui/sshwifty); terminal-bridge is the project-local PTY bridge (`tmux new -A -s <name>` behind token/passkey auth) this surface was written against. Floors: a bridge that runs under an interpreter (wetty under `node`, webssh under `python3`) is seen by name only through a child or a PTY master, since the command line is never read; a socket in another network namespace (a container) is not in this namespace's `/proc/net/tcp` |
| Permissions, MCP auto-approval, Auto-run task, Hook, Secret exposure, Rules file, Transcript exposure (Cline, Roo Code, Continue, Aider, Goose, Zed, Junie, Amp, Warp) | `agents`, `ai` | Vendor docs fetched 2026-10-24/25. Cline: docs.cline.bot (`getting-started/config.md`, `mcp/configuring-mcp-servers`, `customization/cline-rules.md`, `features/auto-approve.md`: "Execute all commands: Run commands requiring approval (requires base toggle)", YOLO "executes whatever it decides without asking permission") and github.com/cline/cline (`AutoApprovalSettings.ts`, `core/storage/disk.ts` hook directories, `state-keys.ts` `hooksEnabled` default true). Roo Code: github.com/RooCodeInc/Roo-Code-Docs (`custom-instructions.md`, `custom-modes.mdx`, `mcp/using-mcp-in-roo.mdx` `alwaysAllow`, `auto-approving-actions.mdx` "Add * to allow all commands") and Roo-Code `globalFileNames.ts` (archived 2026-05). Continue: github.com/continuedev/continue `docs/reference.mdx`, `docs/customize/deep-dives/mcp.mdx`, `docs/cli/tool-permissions.mdx` (`~/.continue/permissions.yaml`), `core/util/paths.ts`. Aider: aider.chat/docs/config (`aider_conf.md`, `options.md`: `yes-always` "Always say yes to every confirmation", `auto-lint` default True) and Aider-AI/aider `aider/args.py`, `aider/onboarding.py` (`~/.aider/oauth-keys.env`). Goose: github.com/aaif-goose/goose (formerly block/goose) `documentation/docs/guides/config-files.md`, `managing-tools/goose-permissions.md` ("`Autonomous Mode` is applied by default"), `logs.md`, `using-goosehints.md`, `crates/goose/src/config/permission.rs`. Zed: zed-industries/zed `docs/src/ai/{mcp,tool-permissions,instructions}.md`, `docs/src/worktree-trust.md`, `crates/agent/src/db.rs`, `crates/paths/src/paths.rs`. Junie: junie.jetbrains.com/docs (`guidelines-and-memory.html`, `junie-cli-mcp-configuration.html`, `junie-cli.html` Brave Mode, `junie-cli-configuration.html`, `action-allowlist-junie-cli.html`). Amp: ampcode.com/docs (`cli/settings`, `customize/mcp`, `tools`: "Amp does not ask for approval before running tools", `customize/plugins`, `customize/agents-md`) and ampcode.com/cli-settings.schema.json. Warp: docs.warp.dev (`terminal/settings/file-locations.md`, `agents/capabilities/mcp.md`, `agents/cli/configuration.md`, `agents/capabilities/rules.md`). VS Code user directories: microsoft/vscode-docs `docs/configure/settings.md`. npm package names and bins: registry.npmjs.org (`cline`, `@continuedev/cli`, `@sourcegraph/amp`) |

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

or, for a vulnerable range, with the optional severity:

```json
{
  "ecosystem": "pypi",
  "name": "package-name",
  "version_range": ">=1.0.0, <1.2.3",
  "advisory": "CVE-... / GHSA-...: what goes wrong. Fixed: 1.2.3. Source: ...",
  "advisory_severity": "high"
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
- Always include the source in the advisory string, and write ids in full
  (`GHSA-xxxx-xxxx-xxxx`, never a short `GHSA-xxxx`), so the finding's evidence lists them
- `advisory_severity` (optional, vulnerable-range rows only): `critical`, `high`, `medium`
  or `low`, the highest the cited advisories state
- A date-versioned package gets a closed range (`>=first, <=last`), and one row per version
  scheme if it ever changes scheme (see "Version-scheme resets")
- Bump the catalog version in the same change: `builtin_catalog_version!()` in
  `src/catalogs/builtin.rs` is the date of the last edit (`YYYY-MM-DD`, `.2`, `.3`, ...
  for further edits that day), and `catalog_version_is_bumped_with_the_catalog` pins the
  file's sha256 to it, so an edit without a bump fails the tests. The version is shown by
  `rmguard --version`, in the JSON report's `catalog.builtin_version`, and under `--otel`
  as `rmguard.catalog.version`, which is how a fleet tells a catalog update from a change
  on its machines
- Update the version and the entry count in this document's intro in the same change:
  `catalog_doc_states_the_current_version_and_count` fails until they match

### Refresh procedure

1. Sweep the sources for the window: the GitHub advisory API
   (`https://api.github.com/advisories?type=reviewed` and `type=malware`, with `published=`
   and `updated=` set to the window), the vendor repositories' security advisories, OSV
   (`https://api.osv.dev/v1/query` per package name), NVD keyword search
   (`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=...`), the CISA KEV
   feed, and the registries (`registry.npmjs.org`, `pypi.org/pypi/<name>/json`) for
   version history and removals.
2. Read each candidate's primary source; take ranges from the advisory, and runs of
   malicious releases from the registry `time` map (every version ever published).
3. Edit the JSON, bump the version and the doc intro, and add a table test that each new
   row matches a sample vulnerable version and not its fix
   (`tests/catalog_refresh_2026_10_25.rs` is the pattern).
4. Run the registry check, read-only and rate-limited:

   ```sh
   uv run --script scripts/catalog-latest-check.py [--catalog FILE] [--delay 0.3]
   ```

   It fetches each npm/PyPI vulnerable-range row's current release (npm
   `dist-tags.latest`, PyPI `info.version`) and lists rows whose range contains it
   (`LATEST MATCHES`: a probable false positive for upgraded installs, a version-scheme
   reset, or an advisory with no fix yet) and packages the registry no longer has
   (`MISSING`). It compares versions the way the matcher does (numeric core, pre-release
   ignored) and exits 1 when anything is listed. On the 2026-10-25 catalog it lists
   `hermes-agent` (PyPI is stale at 0.19.0 below the git-only fix 0.21.1, as the row says)
   and `agentwork-cli` (unpublished by npm, a worm node; from 2026-10-25.2 its rows are
   exact versions, which the check skips); on the 2026-10-22 catalog it also
   listed `@modelcontextprotocol/server-filesystem` `<2025.7.1` against latest 2.0.1.
5. Run the advisory-id check, read-only and rate-limited (set `GITHUB_TOKEN`, e.g.
   `GITHUB_TOKEN=$(gh auth token)`; unauthenticated GitHub calls stop at 60 an hour):

   ```sh
   uv run --script scripts/catalog-id-check.py [--catalog FILE] [--delay 0.5]
   ```

   It resolves every id the rows cite: GHSA ids in GitHub's advisory database, then (for
   a maintainer-published advisory not reviewed into it) in the row's repository's
   security advisories, the repository taken from the registry or the row; CVE ids in
   OSV, NVD and CVE.org, then as the `cve_id` of a published repository advisory (listed
   as `CVE UNPUBLISHED`: assigned, record not yet public); MAL and PYSEC ids in OSV.
   Vendor ids with no public resolver (JFrog `XRAY-`, codelake `CLR-`, Mistral `MAI-`)
   are listed `NOT CHECKED` unless the row cites a URL, which must answer 200. It exits 1
   when an id is `UNRESOLVED` or `WITHDRAWN`. On the 2026-10-25.3 catalog (265 distinct ids in 307 rows) every
   GHSA, MAL and PYSEC id resolves (32 GHSA ids only as repository advisories); six CVEs
   are `CVE UNPUBLISHED` (CVE-2026-111768 to -111771 in
   `modelcontextprotocol/typescript-sdk`, CVE-2026-115563 in
   `modelcontextprotocol/python-sdk`, CVE-2026-88066 in `anthropics/claude-code`); nine
   vendor ids are `NOT CHECKED`; and GHSA-7x36-8jrh-v4pw is `NOTED` (the `hermes-agent`
   row names it as the wrong id it replaced).

To contribute additional entries, please open a PR with:
1. The JSON entry in `builtin_catalog.json`
2. A link to the public advisory or CVE in the PR description
3. A test in `tests/property_tests.rs` verifying the match

## Refresh history

- **2026-10-22** (99 to 228 rows): five research sweeps (packages, extensions, runtimes,
  techniques, spec) with one verifier per candidate reading the primary source; 129 rows
  added, 4 widened.
- **2026-10-25** (228 to 305 rows; 78 added, 1 removed, 11 changed). Window 2026-10-15 to
  2026-10-25.
  - Replaced: `@modelcontextprotocol/server-filesystem` `<2025.7.1` by three rows, one per
    version scheme (see "Version-scheme resets"), carrying GHSA-53mr-w429-c597,
    GHSA-7rgq-gccq-qphx, GHSA-4gxg-m5jx-9j57 and GHSA-hhwq-wxfx-cj7g.
  - 19 further vulnerable-range rows: `server-everything` (two schemes, GHSA-mvf5-2qqv-rg3c),
    `claude-agent-sdk` (CVE-2026-96620), `mcp-server-fetch` (GHSA-v38p-wf49-hx2j,
    GHSA-66qx-2266-pmj6), `@modelcontextprotocol/server-legacy`, `@modelcontextprotocol/hono`,
    `fastmcp-slim` (3.x, 4.x), `obsidian-tc`, `@zenalexa/unicli`, `pydantic-ai` and
    `pydantic-ai-slim` (1.x, 2.x each), `graphifyy`, `netlicensing-mcp`,
    `mcp-contextforge-gateway`, and the Inspector split packages `inspector-server` and
    `inspector-client` (the Inspector row's text claimed they were covered; they had no
    rows). Every one carries `advisory_severity`.
  - 56 malicious rows: seven `@beloved-lenora/opencode-*` packages, `formatting-subtitles`
    (tarball inspected), `unicode-title-normalizer`, `py-worm` (campaign
    2026-10-agentaix), `skillward`, `x402-prompt-injection-scan` 0.1.4, `@tekmidian/pai`
    (3 releases), `agentic-awesome-skills` (20) and `opencode-skills-collection` (21). The
    last five are advisory-backed only (see above).
  - Changed: both `mcp` rows gain CVE-2026-115563 (GHSA-qx49-fqc8-xw99); the Inspector
    `<1.0.3` row gains GHSA-8qgq-27v6-55w3; `claude-desktop-setup`, `codex-setup`,
    `chatgpt-pro-activator` and `formatting-subtitles-for-claude` gain their GHSA ids; the
    three `litellm` rows gain GHSA-92x9-889m-jgmw; the `fastmcp` 3.x row points at the new
    `fastmcp-slim` rows.
  - Sources swept: GitHub advisory API (871 reviewed and malware records published or
    updated in the window, https://api.github.com/advisories), about 55 vendor repository
    advisory pages (among them https://github.com/modelcontextprotocol/servers/security/advisories,
    https://github.com/modelcontextprotocol/typescript-sdk/security/advisories,
    https://github.com/modelcontextprotocol/python-sdk/security/advisories,
    https://github.com/modelcontextprotocol/inspector/security/advisories,
    https://github.com/PrefectHQ/fastmcp/security/advisories,
    https://github.com/anthropics/claude-code/security/advisories), OSV
    (https://api.osv.dev/v1/query, about 100 package names, and the MAL records cited), NVD
    (https://services.nvd.nist.gov/rest/json/cves/2.0, 17 keywords), the CISA KEV feed
    (catalog 2026.10.23, nothing agent-related), vendor pages (https://access.redhat.com/security/cve/CVE-2026-111079,
    https://www.jetbrains.com/privacy-security/issues-fixed/,
    https://docs.mistral.ai/resources/security-advisories,
    https://www.ibm.com/support/pages/node/7285723), and the npm and PyPI registries.
    Third-party research blogs (Socket, Phylum, ReversingLabs, Snyk, Sonatype) were not
    swept this round, which is why no cause is known for the advisory-backed malicious rows.
  - Left out, with reasons: see "Deliberately not catalogued" (vLLM and other server-side
    frameworks, Goose with no fixed version, Junie with no runtime key, ZCode and dsh with no
    primary source, the disputed mcp-ripgrep record, the inferred trigger.dev mapping).
- **2026-10-25.2** (305 to 307 rows; no advisory added). The three compromised-release rows
  that were ranges become one exact-version row per malicious release, so they match as
  malware (Critical "Known-bad", never downgraded as a dormant vulnerable version):
  `agentwork-cli` 0.1.4 and 0.1.5, the Trivy VS Code extension 1.8.12 and 1.8.13, and the
  Cyberhaven Chrome extension 24.10.4. Grading now reads `advisory_severity`.

- **2026-10-25.3** (307 rows; no row added or removed). `advisory_severity` backfilled on
  twelve older vulnerable-range rows, each the highest severity GitHub states for the
  advisories the row cites (GitHub advisory API, global and repository advisories, read
  2026-10-25): critical for `@modelcontextprotocol/inspector` `<1.0.3` (GHSA-4fc4-wcmh-4g86,
  GHSA-6x67-4w4w-9f3w, CVE-2025-49596), `@mcpjam/inspector` (GHSA-232v-j27c-5pp6, CVSS
  9.8), both `fastmcp` rows (GHSA-gpgx-58w2-xwwf) and `mistral-vibe` (all six MAI-2026-003
  CVEs, CVSS 4.0 9.2 to 10); high for `@modelcontextprotocol/sdk` 1.x, both `mcp` rows
  (GHSA-qx49-fqc8-xw99, GHSA-fmmv-w9g8-j3gc, CVE-2025-66416 and others, none above high),
  `@modelcontextprotocol/server` 2.x (GHSA-jm63-cq47-j5jp, CVSS 7.7),
  `@modelcontextprotocol/node` 2.x (GHSA-f897-62hf-6gxq, CVSS 7.5), the Inspector 2.x row
  (GHSA-q978-78c7-phqw, CVSS 8.8; CVE-2025-49596 is named there only as the fix it
  completes) and `hermes-agent` (CVE-2026-71963, CVSS 8.8). The `hermes-agent` row's
  advisory id is corrected to GHSA-cc88-9pxf-j2wv, GitHub's record for CVE-2026-71963
  (GHSA-7x36-8jrh-v4pw resolves in neither GitHub nor OSV). The `litellm` rows are
  exact-version malware rows and carry no severity by design.

## License

The catalog data (advisory descriptions, CVE identifiers, package names) is compiled from
publicly available security advisories. CVE identifiers are public domain. Advisory
descriptions are original text summarizing public disclosures. The catalog itself is
distributed under Apache 2.0 as part of rustmachineguard.
