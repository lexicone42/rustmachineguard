# rmguard

[![CI](https://github.com/lexicone42/rustmachineguard/actions/workflows/ci.yml/badge.svg)](https://github.com/lexicone42/rustmachineguard/actions/workflows/ci.yml)

**An AI-agent posture scanner for developer machines.**

rmguard inventories the agent layer of a workstation — coding agents, MCP servers, IDE
and browser extensions, agent skills and hooks, at-rest credentials, package-registry
configuration, git auto-execution settings — and reports what on that machine could be
used against you. It matches what it finds against a curated threat catalog, probes MCP
servers live, diffs scans over time to catch rug-pulls, emits a CycloneDX 2.0 Blueprint of
the agent posture, and maps its findings to the control frameworks organizations are being
asked to satisfy. Everything runs locally; nothing is sent anywhere unless you pass a flag
that says so.

Traditional endpoint protection has no visibility into this layer. An EDR sees a `node`
process; it does not see that the process is an MCP server whose config was shipped by a
cloned repository, that it was auto-approved by a workspace-trust bypass, and that its
tool descriptions carry an instruction to read `~/.ssh`. rmguard does.

## Quick Start

```bash
# Build from source
cargo build --release

# Run a scan (findings first, then inventory)
./target/release/rmguard

# JSON output (round-trippable; feeds --diff and --report)
./target/release/rmguard --format json

# HTML report
./target/release/rmguard --format html --output report.html

# CycloneDX 2.0 Blueprint (agent posture as assets/behaviors/flows)
./target/release/rmguard --format blueprint

# Detect drift since a baseline (incl. MCP rug-pulls)
./target/release/rmguard --format json --output baseline.json
./target/release/rmguard --diff baseline.json

# Live-probe local MCP servers (opt-in; spawns the server processes)
./target/release/rmguard --probe-mcp

# Show what each scanner actually looked at
./target/release/rmguard --verbose

# Skip specific categories, or scan additional home roots
./target/release/rmguard --skip ssh,cloud
./target/release/rmguard --search-dirs /home/alice,/home/bob
```

## What It Scans

| Category | What's Detected | Examples |
|---|---|---|
| **AI Agents & Tools** | CLI tools and desktop apps | Claude Code, Claude Cowork, GitHub Copilot (`copilot`, `gh-copilot`), Codex, Gemini, Amazon Q, Kiro, Microsoft AI Shell (`aish`), OpenCode, Aider, Goose, Open Interpreter, Tabby, and agents (ClawdBot, MoltBot, MoldBot, OpenClaw, GPT-Engineer) |
| **AI Frameworks** | Local inference servers | Ollama, LocalAI, LM Studio, llama.cpp, vLLM, HuggingFace TGI, oobabooga text-generation-webui |
| **IDE Installations** | Developer editors | VS Code, Cursor, Windsurf, Zed, Antigravity |
| **IDE Extensions** | Installed extensions | VS Code-style and Zed format parsing with version info |
| **JetBrains Plugins** | User-installed IDE plugins, by plugin ID | Reads `META-INF/plugin.xml` from each plugin jar under the JetBrains plugin directories (Linux, macOS, Toolbox installs) — identity only, plugin code never read. Catalogs the 15 Marketplace plugins that exfiltrated AI API keys in 2025–26 |
| **MCP Configurations** | Model Context Protocol servers | Claude Desktop, Claude Code (`settings.json` + `~/.claude.json` project scope), Cursor, Windsurf, Antigravity, Zed, VS Code, Open Interpreter (YAML), Codex (TOML) |
| **Package Managers** | Node.js ecosystem | npm, yarn, pnpm, bun, Node.js |
| **Shell Configs** | AI-related env vars | API keys (redacted), tool aliases |
| **SSH Keys** | Key inventory with passphrase audit | RSA, ECDSA, Ed25519/OpenSSH with passphrase detection |
| **Cloud Credentials** | Cloud provider credentials | AWS (profiles, SSO), GCP (ADC, service accounts), Azure (tokens, subscriptions) |
| **Container Tools** | Container runtimes | Docker, Podman, nerdctl, Lima, Colima, Finch |
| **Notebook Servers** | Computational notebooks | Jupyter, JupyterLab, Marimo |
| **Browser Extensions** | AI-related browser add-ons | Chrome/Firefox extension inventory with known-malicious matching; localized (`__MSG_`) names resolved, live version chosen numerically |
| **Package Config Audits** | Registry/install hijacks | `.npmrc`, pip, bun, yarn config — custom and lookalike registries (matched on the parsed host, not a substring), disabled SSL, auth tokens |
| **Rules Files** | Agent instruction files | `CLAUDE.md` and similar, with dangerous-pattern + tamper (hash) detection, **invisible-Unicode** detection (zero-width, bidi marks, tag blocks, variation-selector smuggling), and an **evasion-resistant normalization pass** — homoglyphs (Cyrillic/Greek/fullwidth), shell quote-splitting (`c"u"rl`) and backslash escapes are folded to what a shell would actually execute, so obfuscated payloads still match. A pattern that matches *only* after folding is reported as **obfuscated** and escalated, since hiding it was deliberate |
| **Agent Skills** | Custom commands / hooks / plugins / **skill bundles** | Recursively walks skill bundles (`skills/<name>/SKILL.md` + shipped `scripts/*`), including the marketplace → plugin → skill chain under `~/.claude/plugins/`. Inventories bundled scripts as well as manifests — the manifest often reads clean while the payload sits in a sibling script. Capability inference across the SkillFortify 8-resource taxonomy |
| **Agent Settings** | Claude Code **and Cursor** control planes | Hooks that run shell commands on tool-use events (silent code exec), `enableAllProjectMcpServers` workspace-trust bypass, permission modes. Cursor is covered too — `.cursor/hooks.json` (a different schema, so the Claude parser reads nothing from it) and `cli-config.json` `approvalMode: unrestricted`, which is Cursor's exact analogue of `bypassPermissions`. Hook commands are resolved the way the hook runner resolves them (`$CLAUDE_PROJECT_DIR`, `~/`, project root) so a shipped native binary is recognized |
| **AI Credentials** | At-rest agent tokens + permissions | `~/.claude/.credentials.json`, Codex/Gemini/Copilot/OpenCode/Amazon Q token files, the Hugging Face token file (`$HF_HOME/token`), and inline API keys in Continue (`~/.continue/config.yaml`) and Aider (`~/.aider.conf.yml`) configs — existence, loose permissions and key NAMES only (values never read or reported) |
| **`.env` Files** | Secrets in agent project roots | `.env`/`.env.local`/… in project roots agents operate on — git-tracked (committed-secret) and world-readable flags, secret-bearing key **names** (never values) |
| **Transcript Stores** | Agent conversation-state collection (EAA-005) | Claude Code (`projects/`, `history.jsonl`, `todos/`), Codex (`sessions/`, `history.jsonl`), Gemini (`tmp/`) — existence, file count, size, and permissions only (content never read); world-readable stores flagged |
| **Python Packages** | Installed distributions matched to the catalog | Reads `*.dist-info` / `*.egg-info` in system, user and project-venv site-packages to resolve name + version — identities only, never package code, PEP 503-normalized on both sides of the match. This is what makes the catalog's PyPI rows reachable for a package that is merely *installed*, rather than only one launched as an MCP server |
| **npm Packages** | Installed packages matched to the catalog | Walks global roots and project `node_modules` including pnpm's virtual store and nested installs; the installed directory name is the identity (a padded or garbled `package.json` cannot hide a typosquat), alias installs are matched under both names, versions validated. Identities only |
| **Git Autorun Config** | git settings that execute a command | Keys git runs as commands (`core.fsmonitor`, `diff.external`, `filter.*`, …) — but **value-gated, not key-gated**: only reported when the value chains shell commands, matches a dangerous pattern, or runs a script the repo ships, and only in a scope an untrusted repo controls. `core.fsmonitor=true`, husky's `core.hooksPath`, git-lfs filters and your keychain helper stay silent. A git directory **buried** inside a project (the CVE-2026-45033 shape) is Critical, detected with git's own criterion (HEAD + `objects/` + `refs/`, symlinks and HEAD content handled as git handles them); a project that *is* a bare git directory is checked too. Resolves `include.path`, so a payload hidden in an included file is still found |
| **VS Code Auto-run Tasks** | Tasks that execute on folder open | `.vscode/tasks.json` entries with `runOptions.runOn: folderOpen` — opening a project becomes code execution. Escalated when git-tracked (ships with the repo) or when the task reaches into an agent-config directory: that plus an agent hook pointing the other way is the 2026 persistence pair, where removing one half leaves the other to restore it |
| **Plugin Marketplaces** | Remote plugin/skill hot-load sources (EAA-009) | Claude Code plugin marketplaces — source (git/github), official-vs-third-party, installed-plugin counts; auto-updating third-party sources (unreviewed remote code) flagged |

MCP server and `settings.json` configs are additionally checked for **plaintext HTTP transport** (tokens/traffic sent unencrypted), **over-broad filesystem scope** (a `server-filesystem` rooted at `/` or `$HOME` — near-whole-machine access), **hardcoded credentials in an `env` block** (a secret-looking key set to a literal instead of `${VAR}` — reported by **name** only, never value; escalated to a **committed-secret Critical** when the config is git-tracked, mirroring a git-tracked `.env`), and **download-and-execute launch commands** (a server that boots via `curl … | bash`). AI base-URL overrides are checked for **hostile gateway routing** (EAA-007).

A built-in **threat catalog** (99 entries) flags known-malicious or known-vulnerable
packages, MCP servers, IDE plugins and browser extensions during the scan — and, via the
`agent-runtime` ecosystem, checks the **agent CLI's own version** (Claude Code, Copilot
CLI, Gemini CLI) against known-vulnerable ranges, since agent CLIs are now CVE-bearing
packages in their own right. Every entry cites its source; every ecosystem in the catalog
is guaranteed by test to be reachable from a scanner, so a row can never sit unmatchable
while reading as coverage. See [docs/THREAT-CATALOG.md](docs/THREAT-CATALOG.md) for
sources and attribution.

## Output Formats

- **`terminal`** (default) — Risk-first: a ranked Security Findings section, then the inventory with status indicators (● running, ○ stopped)
- **`json`** — Structured data for programmatic consumption, CI pipelines, or SIEM ingestion (round-trippable — it deserializes back into a scan report). Includes per-scanner `diagnostics`
- **`html`** — **Risk-first** dark-themed report: severity pills, a ranked Security Findings section, then inventory + detail. Meant to be shared/archived. Each finding is **click-to-expand**: it reveals what it means, why it matters, how to fix it, the framework it maps to (EAA / OWASP / etc.), and — where relevant — the exact offending artifact (e.g. the actual shell command a hook runs, with any credential in it redacted). Self-contained (no external assets), so it renders offline and travels as a single file
- **`sbom`** — CycloneDX 1.6 SBOM
- **`blueprint`** — CycloneDX 2.0 Blueprint (draft) — agent posture as assets/behaviors/flows plus a native risk layer: threats (with CVE `vulnerabilities` and CAPEC `attackPatterns`), a scored toxic-flow risk, and compliance controls, schema-validated in CI. New to Blueprints? [docs/BLUEPRINT-WALKTHROUGH.md](docs/BLUEPRINT-WALKTHROUGH.md) explains the output field by field
- **`compliance`** — control-coverage report (see below)

## Compliance evidence

`--format compliance` maps rmguard's inventory and findings to the control frameworks
organizations are being asked to satisfy for AI-agent / MCP security, and reports honest
coverage (Covered / Partial / Out-of-scope) per control:

- **NSA/CISA "MCP Security" CSI** (U/OO/6030316-26, 2026-06)
- **OWASP Top 10 for Agentic Applications** (ASI01–ASI10) and **Agentic Skills Top 10** (AST)
- **OWASP MCP Top 10** (MCP)
- **EU AI Act** AI-component inventory / transparency obligations (applicable since 2026-08-02). The Chapter III *high-risk* obligations were deferred by the Digital Omnibus (Regulation (EU) 2026/1744) to 2027-12-02 / 2028-08-02 — this mapping covers the inventory/transparency bucket only.
- **[Endpoint AI Agent Abuse (EAA)](https://github.com/0x4D31/endpoint-ai-agent-abuse)** — the closest-fit framework (endpoint agent abuse specifically); rmguard covers 8 of its 16 techniques outright and partials several more. CC0, by 0x4D31.

This is posture **evidence** (inventory + detection), **not a compliance attestation** —
runtime controls (invocation logging, network segmentation) are explicitly marked
out-of-scope. Every finding category the tool emits maps to at least one control, and
every mapped category is a real finding category; both directions are tested. It's the
artifact you bring to a compliance program to demonstrate agent/MCP inventory and
detection coverage, with each finding tied to the control it evidences.

## Team / fleet reporting

Run per-machine scans, collect the JSON however your team already moves files (MDM,
a shared drive, CI artifact, S3, a git repo), then aggregate into one dashboard:

```bash
# On each machine (cron, MDM, or manual):
rmguard --format json --output /shared/scans/$(hostname).json

# Anywhere the JSONs are collected:
rmguard --report /shared/scans/ --output fleet.html
```

`fleet.html` ranks machines by the severity of their findings (most at-risk first),
shows fleet-wide critical/high/medium totals, and links to each machine's findings.
The aggregator only reads the JSON files — it's agnostic about how they got there.

To **gate** on posture instead of just reporting it — a pre-commit hook, an onboarding
check, or a CI step that must fail a machine with serious findings — use `--fail-on`:

```bash
# Exits 2 (report still prints) if any Critical finding is present; else 0.
rmguard --fail-on critical || echo "machine failed its security gate"
```

Operational errors exit 1, findings-at-threshold exit 2, clean exits 0 — so scripts can
tell "the scan couldn't run" from "the scan found something."

### Debugging a scan

A scanner that finds nothing looks the same whether the machine is clean or the scanner
looked in the wrong place. `--verbose` appends a diagnostics table that tells them apart:

```
  ── Scanner Diagnostics ──
  scanner            ms   read  missing  items  status
  packages            0      1        8      0  ok  (/home/me)
  gitconfig         332     44        0      0  ok  (/home/me)
  notebooks           0      0        0      0  no inputs
  mcp-probe           0      0        0      0  skipped
```

`read` and `missing` count the files and directories a scanner opened or looked for
(a directory that exists but cannot be listed is a miss, not silence); the opt-in phases
(`mcp-probe`, `registry`) show as `skipped` unless their flag was passed; `no inputs`
means it opened nothing and produced nothing — either this machine has none of what it
looks for, or it is looking in the wrong place. `--trace` (or `RMGUARD_TRACE=1`) then
prints every path as it is tried, redacted and sanitized. The same numbers are in
`--format json` under `diagnostics`, so a fleet aggregator can spot a scanner that
silently stopped working across machines.

## Validating detection

Two end-to-end suites run the shipped binary against planted fixtures:

- `tests/vulnerable_range.rs` builds a deliberately-vulnerable "machine" (a threat-catalog
  MCP server, a `curl | bash` hook, MCP auto-approval, a poisoned rules file, a toxic-flow
  skill, a world-readable `.env`, a world-readable agent transcript store) and asserts the
  binary catches every planted issue. It's both a regression guard and a reference for
  "what a compromised machine looks like."
- `tests/no_secret_leakage.rs` plants a distinct credential in every surface that echoes
  user-controlled text — MCP launch args and commands, hook and task commands, every
  package-registry config, agent configs, marketplace URLs, a token file — renders every
  output format, and asserts none of them survives. Each fixture also carries a positive
  control (its host or provider name) that must appear, so a fixture the scanner never
  read cannot pass as "clean."

To generate a shareable demo report from the vulnerable fixtures, point `--search-dirs`
at a scratch copy and render HTML — the planted issues surface at the top of the report
(plus anything real on the host, since your own home directory is scanned too).

## Temporal & cross-server analysis

Capabilities that no MCP client performs at install time:

- **Rug-pull detection** (`--diff baseline.json`) — flags an MCP server that mutates an already-trusted tool's description or parameter schema between scans (the canonical rug-pull); also surfaces tool add/remove and capability drift per server.
- **Cross-server tool shadowing** — when two probed MCP servers offer the same tool name (a confused-deputy risk), the Blueprint emits a shadowing finding naming the colliding servers.
- **Toxic-flow surface (lethal trifecta)** — flags when the aggregate agent surface (probed servers + skills) combines a sensitive-data *source* (filesystem, database, environment, source-control) with an exfiltration *sink* (network, communication). Each capability is individually authorized; the composition across connected servers is the risk. Surfaced in the default terminal report and the Blueprint.
- **Live MCP probing** (`--probe-mcp`) — enumerates each stdio server's tools/resources and scans tool **and parameter** descriptions, plus the server's `instructions` (which the host splices into the model's system prompt), for prompt-injection / line-jumping and invisible-Unicode smuggling. Detects the server's **protocol era**: MCP revision 2026-07-28 removed the `initialize` handshake, so the probe leads with `server/discover` and falls back to `initialize` only on a non-spec error or silence — and a server that rejects the handshake, answers with nothing, or stalls mid-enumeration is reported as a failed probe, never as a clean server with no tools. Servers run in their own process group under a watchdog and are killed with their children when the probe ends or on Ctrl-C.
- **Official registry verification** (`--verify-registry`) — checks each discovered MCP server against the official [MCP registry](https://registry.modelcontextprotocol.io): confirms verified publisher provenance (reverse-DNS namespace), flags packages **deprecated** in the registry, and flags names one edit away from a registered package (**possible typosquat**). Opt-in because it makes a network call. A signature/attestation slot is reserved for when the registry/Sigstore adds one.
- **Agent identity posture** (*with whose authority does this agent act?*) — characterizes how agents authenticate: **static long-lived API keys** (unbound bearer tokens — the OWASP ASI03 anti-pattern), **OAuth credentials** (refreshable/scoped — better), and **SPIFFE workload identity** (short-lived SVIDs — the modern target). Advisory when static keys are present; elevated when they're the *sole* credential (no OAuth/SPIFFE). Classifies credential *kinds* only — never reads secret values.

## Platform Support

| Platform | Status |
|---|---|
| Linux | Supported (XDG paths, `/etc/os-release`, `pgrep`) |
| macOS | Supported (`/Applications/`, `sw_vers`, `defaults read`) |

CI runs the full test suite on both.

## Security Considerations

This tool is itself a security-sensitive program. Design decisions:

- **No secret leakage**: Scanners report key *names*, file existence and permissions — never values. Anything that echoes user-controlled text into a finding (a hook command, an MCP launch line, a registry URL, a git config value) passes through one redaction helper that understands URL userinfo and query parameters, `key=value` and `key: value` pairs, HTTP `Authorization` schemes, curl/wget basic-auth and header forms, connection strings, compact JSON bodies and quoted values with whitespace — and keeps the parts a finding needs (the host, the binary, `| bash`). The guarantee is tested end to end, one canary per surface, with positive controls.
- **Attacker text cannot forge the report**: every string an attacker chooses — a package version, an extension name, a plugin ID, a probed server's error message — is sanitized before it can reach the terminal, so no ANSI sequence or line break can draw a green "clean" line. Text the tool *scans* for injection (tool descriptions, server instructions) is kept raw for the scanner and never printed.
- **Adversarially reviewed**: the redaction, the git walk, the probe and the diagnostics have each been through multiple rounds of multi-agent adversarial review in which every finding was independently reproduced by a second agent before being accepted. Several of those rounds found that a fix had introduced a second edge; each is documented in the commit history along with the floors that remain by design.
- **SSH passphrase detection**: Uses `ssh-keygen` probing for OpenSSH-format keys (the PEM `ENCRYPTED` marker is unreliable for modern key formats); reports a tri-state (encrypted / no-passphrase / unknown) so a missing `ssh-keygen` is never reported as "unprotected".
- **MCP probing is opt-in**: `--probe-mcp` spawns local MCP servers and is gated behind an explicit flag with a runtime warning; each server runs in its own process group under a watchdog, its output is read with enforced deadlines, and the whole group is killed when the probe ends or the user interrupts.
- **HTML XSS prevention**: Report data is base64-encoded in script tags to prevent injection; all user content is HTML-escaped including single quotes.
- **Input validation**: `--format` and `--skip` flags are validated at parse time with clear error messages.
- **No `/tmp` fallback**: Fails fast if `$HOME` cannot be determined rather than scanning a shared directory.
- **Bounded, regular-file-only reads**: Config files are read up to 1 MiB; identity files (`package.json`, `METADATA`, `plugin.xml`) are read as a bounded head so padding cannot hide a package; readers refuse FIFOs and devices so a planted named pipe cannot stall the scan; subprocesses (`git config`, `--version` probes) run under timeouts. Directory walks are budgeted, and budgets are spent on directories rather than files so junk files cannot exhaust them.
- **Fuzzed & schema-validated**: Untrusted-input parsers (MCP config, threat catalog, `.env`, settings hooks, diff, the redaction helper) have `cargo-fuzz` targets; Blueprint output is validated against the vendored CycloneDX 2.0 schema in CI.
- **CI-gated**: every push runs the full suite on Linux **and** macOS, denies clippy correctness lints, keeps the fuzz targets compiling, and audits the dependency tree against RustSec advisories (`cargo audit`) — a supply-chain scanner should hold its own dependencies to the standard it scans for.

## Origins

rmguard started in March 2026 as a Rust rewrite of
[Dev Machine Guard](https://github.com/step-security/dev-machine-guard) by
[StepSecurity](https://www.stepsecurity.io/), which at the time was a bash script under
Apache-2.0. That project deserves the credit for the idea — inventory the developer
tooling layer that endpoint security cannot see — and for the first list of what to look
for. rmguard is not affiliated with StepSecurity, and the two have since gone their own
ways: StepSecurity has rewritten Dev Machine Guard in Go and grown it into part of their
platform, and rmguard has grown into a different tool with a different shape — a scanner
trait with per-scanner diagnostics, a sourced threat catalog with reachability
guarantees, live MCP probing with protocol-era detection, scan diffing and rug-pull
detection, a CycloneDX 2.0 Blueprint output, compliance mapping, and a redaction layer
that has been adversarially tested. If you want a vendor-supported product with a fleet
console, theirs is a good choice. If you want a local, auditable, standards-oriented
scanner you can read end to end, this is that.

The derivation is acknowledged in [NOTICE](NOTICE), as Apache-2.0 asks; StepSecurity's
research is also credited in the threat catalog where their findings are used.

## CLI Reference

Abridged — `rmguard --help` is authoritative.

```
Usage: rmguard [OPTIONS]

Options:
  -f, --format <FORMAT>              Output format [default: terminal]
                                     [values: terminal, json, html, sbom,
                                     blueprint, compliance]
  -o, --output <OUTPUT>              Write output to a file instead of stdout
      --skip <SKIP>                  Skip scanner categories (comma-separated):
                                     ai, frameworks, ide, extensions, mcp, node,
                                     shell, ssh, cloud, containers, notebooks,
                                     browser, packages, rules, skills, settings,
                                     aicreds, envfiles, transcripts,
                                     marketplaces, vscodetasks, gitconfig,
                                     pypkgs, npmpkgs, jbplugins
      --search-dirs <SEARCH_DIRS>    Additional home roots (comma-separated).
                                     Home-rooted scanners run once per directory
                                     and merge results.
      --threat-catalog <FILE>        Additional JSON threat catalog, merged with
                                     the built-in catalog.
      --no-builtin-catalog           Disable the built-in threat catalog.
      --diff <BASELINE.json>         Compare against a previous --format json scan
                                     and report drift (incl. MCP rug-pulls).
      --probe-mcp                    Live-probe local stdio MCP servers to
                                     enumerate tools/resources (opt-in; spawns the
                                     server processes).
      --verify-registry              Verify MCP servers against the official MCP
                                     registry (opt-in; NETWORK — sends server
                                     package names to registry.modelcontextprotocol.io).
      --verbose                      Append a per-scanner diagnostics table to the
                                     terminal report (duration, files read/missing,
                                     items). Always present in JSON as `diagnostics`.
      --trace                        Print every path the scanners open or probe to
                                     stderr as it happens (paths only, redacted and
                                     sanitized). Same as RMGUARD_TRACE=1.
      --fail-on <SEVERITY>           Exit 2 if any finding is at or above this
                                     severity [values: critical, high, medium,
                                     low]. The report still prints; only the exit
                                     status changes. For CI / fleet-onboarding gates.
      --report <DIR>                 Aggregate a directory of --format json scans
                                     into one fleet HTML dashboard (does not scan
                                     the local machine).
  -h, --help                         Print help
  -V, --version                      Print version
```

## Building

Requires Rust 2024 edition (1.85+):

```bash
cargo build --release
```

The resulting binary at `target/release/rmguard` is self-contained with no runtime dependencies.

## License

Apache-2.0 — see [LICENSE](LICENSE).

rmguard began as a derivative work of [step-security/dev-machine-guard](https://github.com/step-security/dev-machine-guard)
by StepSecurity Inc.; see [NOTICE](NOTICE) for attribution and [Origins](#origins) for how the
projects relate today.
