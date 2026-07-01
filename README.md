# Dev Machine Guard (Rust)

> **This is an independent Rust rewrite of [step-security/dev-machine-guard](https://github.com/step-security/dev-machine-guard), not the original project.**
> The original is a bash script by [StepSecurity](https://www.stepsecurity.io/) licensed under Apache-2.0.
> This rewrite extends it with Linux support, additional detection categories, and security hardening.

Scan your developer machine for AI agents, MCP servers, IDE extensions, cloud credentials, SSH keys, and more — in seconds.

Traditional endpoint protection (EDR, MDM) has no visibility into developer-specific tooling layers: AI coding assistants, Model Context Protocol servers, IDE extensions with broad permissions, and locally-running inference frameworks. This tool fills that gap.

## Quick Start

```bash
# Build from source
cargo build --release

# Run a scan
./target/release/rmguard

# JSON output
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

# Skip specific categories
./target/release/rmguard --skip ssh,cloud

# Scan additional home roots (e.g. another user's profile on the same machine)
./target/release/rmguard --search-dirs /home/alice,/home/bob
```

## What It Scans

| Category | What's Detected | Examples |
|---|---|---|
| **AI Agents & Tools** | CLI tools and desktop apps | Claude Code, Claude Cowork, GitHub Copilot (`copilot`, `gh-copilot`), Codex, Gemini, Amazon Q, Kiro, Microsoft AI Shell (`aish`), OpenCode, Aider, Goose, Open Interpreter, Tabby, and agents (ClawdBot, MoltBot, MoldBot, OpenClaw, GPT-Engineer) |
| **AI Frameworks** | Local inference servers | Ollama, LocalAI, LM Studio, llama.cpp, vLLM, HuggingFace TGI, oobabooga text-generation-webui |
| **IDE Installations** | Developer editors | VS Code, Cursor, Windsurf, Zed, Antigravity |
| **IDE Extensions** | Installed extensions | VS Code-style and Zed format parsing with version info |
| **MCP Configurations** | Model Context Protocol servers | Claude Desktop, Claude Code (`settings.json` + `~/.claude.json` project scope), Cursor, Windsurf, Antigravity, Zed, VS Code, Open Interpreter (YAML), Codex (TOML) |
| **Package Managers** | Node.js ecosystem | npm, yarn, pnpm, bun, Node.js |
| **Shell Configs**\* | AI-related env vars | API keys (redacted), tool aliases |
| **SSH Keys**\* | Key inventory with passphrase audit | RSA, ECDSA, Ed25519/OpenSSH with passphrase detection |
| **Cloud Credentials**\* | Cloud provider credentials | AWS (profiles, SSO), GCP (ADC, service accounts), Azure (tokens, subscriptions) |
| **Container Tools**\* | Container runtimes | Docker, Podman, nerdctl, Lima, Colima, Finch |
| **Notebook Servers**\* | Computational notebooks | Jupyter, JupyterLab, Marimo |
| **Browser Extensions**\* | AI-related browser add-ons | Chrome/Firefox extension inventory with known-malicious matching |
| **Package Config Audits**\* | Registry/install hijacks | `.npmrc`, pip, bun config — custom registries, disabled SSL, auth tokens |
| **Rules Files**\* | Agent instruction files | `CLAUDE.md` and similar, with dangerous-pattern + tamper (hash) detection |
| **Agent Skills**\* | Custom commands / hooks / plugins | Capability inference across the SkillFortify 8-resource taxonomy |
| **Agent Settings**\* | `settings.json` hooks + MCP auto-approval | Hooks that run shell commands on tool-use events (silent code exec), `enableAllProjectMcpServers` workspace-trust bypass, permission modes |
| **AI Credentials**\* | At-rest agent tokens + permissions | `~/.claude/.credentials.json`, Codex/Gemini/Copilot/OpenCode token files — existence and loose permissions only (values never read) |
| **`.env` Files**\* | Secrets in agent project roots | `.env`/`.env.local`/… in project roots agents operate on — git-tracked (committed-secret) and world-readable flags, secret-bearing key **names** (never values) |

\* New detection categories not in the original bash tool.

A built-in **threat catalog** (62 entries) flags known-malicious or known-vulnerable
packages, MCP servers, and IDE/browser extensions during the scan. See
[docs/THREAT-CATALOG.md](docs/THREAT-CATALOG.md) for sources and attribution.

## Output Formats

- **`terminal`** (default) — Colored, human-readable report with status indicators (● running, ○ stopped)
- **`json`** — Structured data for programmatic consumption, CI pipelines, or SIEM ingestion (round-trippable — it deserializes back into a scan report)
- **`html`** — **Risk-first** dark-themed report: severity pills, a ranked Security Findings section, then inventory + detail. Meant to be shared/archived.
- **`sbom`** — CycloneDX 1.6 SBOM
- **`blueprint`** — CycloneDX 2.0 Blueprint (draft) — agent posture as assets/behaviors/flows, schema-validated in CI

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

## Temporal & cross-server analysis

Capabilities that no MCP client performs at install time:

- **Rug-pull detection** (`--diff baseline.json`) — flags an MCP server that mutates an already-trusted tool's description or parameter schema between scans (the canonical rug-pull); also surfaces tool add/remove and capability drift per server.
- **Cross-server tool shadowing** — when two probed MCP servers offer the same tool name (a confused-deputy risk), the Blueprint emits a shadowing finding naming the colliding servers.
- **Toxic-flow surface (lethal trifecta)** — flags when the aggregate agent surface (probed servers + skills) combines a sensitive-data *source* (filesystem, database, environment, source-control) with an exfiltration *sink* (network, communication). Each capability is individually authorized; the composition across connected servers is the risk. Surfaced in the default terminal report and the Blueprint.
- **Live MCP probing** (`--probe-mcp`) — enumerates each stdio server's tools/resources and scans tool **and parameter** descriptions for prompt-injection / line-jumping and invisible-Unicode smuggling.

## Platform Support

| Platform | Status |
|---|---|
| Linux | Supported (XDG paths, `/etc/os-release`, `pgrep`) |
| macOS | Supported (`/Applications/`, `sw_vers`, `defaults read`) |

## Security Considerations

This tool is itself a security-sensitive program. Design decisions:

- **No secret leakage**: Scanners report variable/key *names* and file existence only, never values. Shell configs redact values (`OPENAI_API_KEY=<redacted>`); the AI-credential and `.env` scanners report permissions and key names but never read the secret material.
- **SSH passphrase detection**: Uses `ssh-keygen` probing for OpenSSH-format keys (the PEM `ENCRYPTED` marker is unreliable for modern key formats); reports a tri-state (encrypted / no-passphrase / unknown) so a missing `ssh-keygen` is never reported as "unprotected".
- **MCP probing is opt-in**: `--probe-mcp` spawns local MCP servers and is gated behind an explicit flag with a runtime warning; an interruptible watchdog kills any server that exceeds the probe timeout.
- **HTML XSS prevention**: Report data is base64-encoded in script tags to prevent injection; all user content is HTML-escaped including single quotes.
- **Input validation**: `--format` and `--skip` flags are validated at parse time with clear error messages.
- **No `/tmp` fallback**: Fails fast if `$HOME` cannot be determined rather than scanning a shared directory.
- **Bounded reads**: Files over 1MB are skipped (with a warning), and SHA-256 hashing uses the native `sha2` crate (no subprocess).
- **Fuzzed & schema-validated**: Untrusted-input parsers (MCP config, threat catalog, `.env`, settings hooks, diff) have `cargo-fuzz` targets; Blueprint output is validated against the vendored CycloneDX 2.0 schema in CI.

## Differences from Upstream

| Feature | Original (bash) | This Rewrite (Rust) |
|---|---|---|
| Platform | macOS only | macOS + Linux |
| Language | Shell script | Compiled Rust binary |
| New scanners | — | Shell configs, SSH keys, cloud credentials, containers, notebooks, rules/memory files, agent skills, agent settings/hooks, AI credentials, `.env` files |
| Threat intelligence | — | Built-in 62-entry catalog (exact + semver-range matching), live MCP probing |
| Temporal analysis | — | Scan diffing, MCP rug-pull detection, cross-server tool shadowing, toxic-flow surface |
| Standards output | — | CycloneDX 1.6 SBOM + 2.0 Blueprint (schema-validated in CI) |
| SSH detection | — | `ssh-keygen` probe for accurate passphrase detection |
| Secret handling | — | Names/existence/permissions only, never values |
| Output validation | Silent fallback | Strict format/skip validation |
| Dependencies | bash, curl, base64 | Zero runtime dependencies (static binary) |

## CLI Reference

```
Usage: rmguard [OPTIONS]

Options:
  -f, --format <FORMAT>              Output format [default: terminal]
                                     [values: terminal, json, html, sbom, blueprint]
  -o, --output <OUTPUT>              Write output to a file instead of stdout
      --skip <SKIP>                  Skip scanner categories (comma-separated):
                                     ai, frameworks, ide, extensions, mcp, node,
                                     shell, ssh, cloud, containers, notebooks,
                                     browser, packages, rules, skills, settings,
                                     aicreds, envfiles
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

This is a derivative work of [step-security/dev-machine-guard](https://github.com/step-security/dev-machine-guard) by StepSecurity Inc.
See [NOTICE](NOTICE) for attribution details.
