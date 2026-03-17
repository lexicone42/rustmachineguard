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
./target/release/dev-machine-guard

# JSON output
./target/release/dev-machine-guard --format json

# HTML report
./target/release/dev-machine-guard --format html --output report.html

# Skip specific categories
./target/release/dev-machine-guard --skip ssh,cloud
```

## What It Scans

| Category | What's Detected | Examples |
|---|---|---|
| **AI Agents & Tools** | CLI tools and desktop apps | Claude Code, GitHub Copilot, Codex, Gemini, Aider, Goose, Open Interpreter |
| **AI Frameworks** | Local inference servers | Ollama, LocalAI, LM Studio, llama.cpp, vLLM, TGI |
| **IDE Installations** | Developer editors | VS Code, Cursor, Windsurf, Zed, Antigravity |
| **IDE Extensions** | Installed extensions | VS Code-style and Zed format parsing with version info |
| **MCP Configurations** | Model Context Protocol servers | Claude Desktop, Claude Code, Cursor, Windsurf, Zed, VS Code |
| **Package Managers** | Node.js ecosystem | npm, yarn, pnpm, bun, Node.js |
| **Shell Configs**\* | AI-related env vars | API keys (redacted), tool aliases |
| **SSH Keys**\* | Key inventory with passphrase audit | RSA, ECDSA, Ed25519/OpenSSH with passphrase detection |
| **Cloud Credentials**\* | Cloud provider credentials | AWS (profiles, SSO), GCP (ADC, service accounts), Azure (tokens, subscriptions) |
| **Container Tools**\* | Container runtimes | Docker, Podman, nerdctl, Lima, Colima, Finch |
| **Notebook Servers**\* | Computational notebooks | Jupyter, JupyterLab, Marimo |

\* New detection categories not in the original bash tool.

## Output Formats

- **`terminal`** (default) — Colored, human-readable report with status indicators (● running, ○ stopped)
- **`json`** — Structured data for programmatic consumption, CI pipelines, or SIEM ingestion
- **`html`** — Dark-themed report for sharing or archiving

## Platform Support

| Platform | Status |
|---|---|
| Linux | Supported (XDG paths, `/etc/os-release`, `pgrep`) |
| macOS | Supported (`/Applications/`, `sw_vers`, `defaults read`) |

## Security Considerations

This tool is itself a security-sensitive program. Design decisions:

- **No secret leakage**: Shell config scanning reports only variable *names* (e.g., `OPENAI_API_KEY=<redacted>`), never values
- **SSH passphrase detection**: Uses `ssh-keygen` probing for OpenSSH-format keys (the PEM `ENCRYPTED` marker is unreliable for modern key formats)
- **HTML XSS prevention**: Report data is base64-encoded in script tags to prevent injection; all user content is HTML-escaped including single quotes
- **Input validation**: `--format` and `--skip` flags are validated at parse time with clear error messages
- **No `/tmp` fallback**: Fails fast if `$HOME` cannot be determined rather than scanning a shared directory
- **Bounded reads**: Shell config files over 1MB are skipped

## Differences from Upstream

| Feature | Original (bash) | This Rewrite (Rust) |
|---|---|---|
| Platform | macOS only | macOS + Linux |
| Language | Shell script | Compiled Rust binary |
| New scanners | — | Shell configs, SSH keys, cloud credentials, containers, notebooks |
| SSH detection | — | `ssh-keygen` probe for accurate passphrase detection |
| Secret handling | — | Variable names only, never values |
| Output validation | Silent fallback | Strict format/skip validation |
| Dependencies | bash, curl, base64 | Zero runtime dependencies (static binary) |

## CLI Reference

```
Usage: dev-machine-guard [OPTIONS]

Options:
  -f, --format <FORMAT>   Output format [default: terminal] [possible values: terminal, json, html]
  -o, --output <OUTPUT>   Write output to a file instead of stdout
      --skip <SKIP>       Skip scanner categories (comma-separated):
                          ai, frameworks, ide, extensions, mcp, node,
                          shell, ssh, cloud, containers, notebooks
  -h, --help              Print help
  -V, --version           Print version
```

## Building

Requires Rust 2024 edition (1.85+):

```bash
cargo build --release
```

The resulting binary at `target/release/dev-machine-guard` is self-contained with no runtime dependencies.

## License

Apache-2.0 — see [LICENSE](LICENSE).

This is a derivative work of [step-security/dev-machine-guard](https://github.com/step-security/dev-machine-guard) by StepSecurity Inc.
See [NOTICE](NOTICE) for attribution details.
