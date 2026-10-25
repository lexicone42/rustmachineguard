# rmguard

[![CI](https://github.com/lexicone42/rustmachineguard/actions/workflows/ci.yml/badge.svg)](https://github.com/lexicone42/rustmachineguard/actions/workflows/ci.yml)

**An AI-agent posture scanner for developer machines.**

rmguard inventories the agent layer of a workstation: coding agents, MCP servers, IDE and
browser extensions, agent skills and hooks, at-rest credentials, package-registry
configuration and git auto-execution settings. It reports what on that machine could be
used against you, matches what it finds against a sourced threat catalog, diffs scans over
time to catch rug-pulls, and emits a CycloneDX 2.0 Blueprint and compliance evidence.

What it never does: it never reads or prints a secret value (key names, existence and
permissions only), and it never runs a command a config file names (hooks, MCP launch
lines), except MCP servers under the opt-in `--probe-mcp`. The programs it does run are
installed tools for `--version`, `git` (hardened) and a few system tools from fixed paths.
It is report-only: it changes no configuration, and it sends nothing over the network
unless you pass `--verify-registry` or `--otel`.

Traditional endpoint protection has no visibility into this layer. An EDR sees a `node`
process; it does not see that the process is an MCP server whose config was shipped by a
cloned repository, that it was auto-approved by a workspace-trust bypass, and that its
tool descriptions carry an instruction to read `~/.ssh`.

## Quick start

```bash
cargo build --release
./target/release/rmguard                                    # findings first, then inventory
./target/release/rmguard --format json -o baseline.json     # round-trippable; feeds --diff and --report
./target/release/rmguard --format html -o report.html       # self-contained, risk-first report
./target/release/rmguard --format blueprint                 # CycloneDX 2.0 Blueprint
./target/release/rmguard --diff baseline.json --fail-on high # drift since baseline; exit 3 on High+
./target/release/rmguard --probe-mcp                        # opt-in: spawns local stdio MCP servers
./target/release/rmguard --verbose                          # what each scanner actually looked at
./target/release/rmguard --skip ssh,cloud --search-dirs /home/alice,/home/bob
```

## What it scans

One row per area. The per-surface detail (paths, grading ladders, sources) is in
[docs/COVERAGE.md](docs/COVERAGE.md).

| Area | Inventoried | Graded |
|---|---|---|
| [**Agents & runtimes**](docs/COVERAGE.md#ai-agents--tools) | CLI agents and desktop apps (Claude Code, Copilot, Codex, Gemini, Kiro, Cline, Continue, Aider, Goose, Amp, Junie, Warp, Mistral Vibe, ...), local inference servers, IDEs, IDE/JetBrains/browser extensions, notebooks, containers, Node package managers | Agent runtime versions against known-vulnerable ranges; malicious extensions and plugins; declarative-looking extensions that ship native code |
| [**MCP**](docs/COVERAGE.md#mcp-configurations) | Servers from every agent's config, Claude Code plugin servers, claude.ai connectors, servers seen in Claude Code's MCP logs; live tool lists under `--probe-mcp` | Catalogued servers, plaintext HTTP, whole-machine filesystem scope, inline secrets (by name), download-and-execute and unpinned launches, tool poisoning and rug-pulls, toxic flows, registry typosquats (`--verify-registry`) |
| [**Hooks & settings**](docs/COVERAGE.md#hook-surfaces) | Hooks of every kind from Claude Code, Cursor, Codex, Copilot CLI, Gemini CLI, Devin, OpenCode and Kiro; permission rules and modes; credential helpers (by shape); auto-approve settings of nine more agents | Dangerous commands, cross-agent script references, off-network http hooks, poisoned prompt hooks, broad allow rules, bypass and auto-mode guards, workspace-trust bypass |
| [**Skills, rules & memory**](docs/COVERAGE.md#agent-skills) | Skill bundles and their scripts, commands, subagents, plugin marketplaces, rules files, agent memory | Dangerous and obfuscated patterns, invisible Unicode, injection phrases, dynamic context and unrestricted-Bash grants by provenance, unpinned marketplaces (Plugin4Shell) |
| [**Packages & exposure**](docs/COVERAGE.md#npm-packages) | Installed npm and Python packages (every root, npx caches, uv tools, pipx, agent venvs), registry configs, git autorun config, VS Code folder-open tasks | Threat-catalog matches, lookalike registries, disabled TLS, value-gated git autorun, buried git directories, auto-run tasks |
| [**Credentials & stores**](docs/COVERAGE.md#ai-credentials) | SSH keys, cloud credentials, agent token files, `.env` files, shell configs, agent transcripts and state stores | Keys without a passphrase, loose permissions, committed or world-readable secrets (names only), gateway and agent-home redirection, readable transcripts with secret-shaped content |
| [**Persistence**](docs/COVERAGE.md#persistence-artifacts) | Python startup hooks, planted tool-named executables, escaping symlinks, staged loaders, URL scheme handlers, `~/.claude/bin` | Known worm and CVE persistence shapes; leftovers that survive uninstall |
| [**Network listeners**](docs/COVERAGE.md#network-listeners-linux) (Linux) | Your own TCP listeners via `/proc`, with program, project and shell signal | Shell bridges bound beyond loopback in a project; Critical next to a world-readable `.env` |

## Output and exit codes

`--format` takes `terminal` (default, risk-first, ● running / ○ stopped), `json`
(round-trippable, with per-scanner `diagnostics`), `html` (self-contained, click-to-expand
findings with meaning, fix and mapped control), `sbom` (CycloneDX 1.6), `blueprint`
(CycloneDX 2.0 draft, schema-validated in CI; see
[docs/BLUEPRINT-WALKTHROUGH.md](docs/BLUEPRINT-WALKTHROUGH.md)) and `compliance`
(coverage against NSA/CISA MCP Security, OWASP agentic, skills and MCP Top 10s, the EU AI
Act inventory bucket, and EAA; posture evidence, not an attestation; see
[Compliance evidence](docs/COVERAGE.md#compliance-evidence)). Each format in detail:
[Output formats](docs/COVERAGE.md#output-formats).

| 0 clean, or below the `--fail-on` threshold | 1 operational error (scan, baseline or write failed) | 2 usage error (bad flag or value) | 3 `--fail-on` threshold breached (report still written) |
|---|---|---|---|

The findings gate moved from 2 to 3 on 2026-10-25, so a usage error no longer looks like
findings. With `--diff`, stdout is the diff, `-o` receives the scan in `--format`, and
`--fail-on` gates on that scan. What a diff compares is in
[What a diff shows](docs/COVERAGE.md#what-a-diff-shows); `--verbose` and `--trace` are
explained in [Debugging a scan](docs/COVERAGE.md#debugging-a-scan).

## Running it on a schedule or across a fleet

[docs/OPERATIONS.md](docs/OPERATIONS.md) covers a reviewed baseline plus a daily
`--fail-on` gate and `--diff` in one invocation,
[`scripts/rmguard-baseline.sh`](scripts/rmguard-baseline.sh) to create or rotate the
baseline, [`scripts/rmguard-notify.sh`](scripts/rmguard-notify.sh) to log and notify
(desktop by default; a webhook only if you set one, and then counts only), systemd,
launchd and cron examples under [`contrib/`](contrib/), and fleet export with a Grafana
dashboard and Prometheus alert rules. For a fleet without a collector, gather each
machine's `--format json` scan however you already move files, then
`rmguard --report /shared/scans/ --output fleet.html` ranks the machines by severity. The
aggregator only reads the JSON files.

## Telemetry

`--otel` exports the scan's timing and posture counts as OpenTelemetry traces and metrics
over OTLP http/protobuf. It is off unless you pass the flag: `OTEL_*` variables only say
where it sends, and `OTEL_SDK_DISABLED=true` wins. Only closed labels, counts, durations
and fixed outcome categories leave the machine, never a path, name, command, finding title
or secret. Child processes start with every `OTEL_*` variable removed, so a collector key
never reaches a probed server. `--otel-instance <ID>` is the only free-text value, and
rmguard never derives one. A dead collector costs at most 2 s and never changes the report
or exit code. Every span, attribute and metric is in
[docs/OPENTELEMETRY.md](docs/OPENTELEMETRY.md); the exporter is the default `otel` cargo
feature.

## Security and privacy model

Short version; the full design, the test-only knobs and every known limit are in
[docs/SECURITY.md](docs/SECURITY.md).

- **Read:** config, settings, manifest and identity files, bounded in size, regular files
  only (FIFOs and devices refused), symlinks judged before they are followed; directory
  walks are budgeted (`--walk-budget`) and marked `partial` when they stop early.
- **Never read:** secret values. Scanners report key names, existence and permissions.
  Credential files reached through a link are not opened. The one deliberate exception:
  the host or path of agent-home, base-URL and proxy variables is shown, sanitized.
- **`/proc` (Linux):** only your own processes; `cmdline` is read in memory only to spot
  npx-cache processes and never stored; `environ` is never opened; nothing is spawned.
- **Redaction:** every echoed command, URL or config value passes one redaction helper;
  attacker text is sanitized so it cannot forge the terminal report; synced-skill account
  identifiers are masked as `<org>_<account>`.
- **Spawning:** `git` runs hardened (fsmonitor and hooks off, absolute path, no relative
  PATH entries); system tools come from fixed system directories, never PATH; MCP servers
  run only under `--probe-mcp`, in their own process group under a watchdog.
- **Tested:** one canary per surface with positive controls, fuzzed parsers, CI on Linux
  and macOS, and a RustSec audit of rmguard's own dependencies.

## Validating detection and the threat catalog

Two end-to-end suites run the shipped binary against planted fixtures:
`tests/vulnerable_range.rs` (a deliberately vulnerable machine; every planted issue must
be caught) and `tests/no_secret_leakage.rs` (a distinct credential in every surface that
echoes user text; none may survive in any output format). Details are in
[docs/SECURITY.md](docs/SECURITY.md#how-the-guarantees-are-tested).

The built-in threat catalog covers malicious and vulnerable packages, MCP servers, IDE
plugins, browser extensions and agent runtimes. Every entry cites its source, and every
ecosystem is tested to be reachable from a scanner. Its version is in `rmguard --version`
and the JSON report's `catalog` block; sources, attribution, entry count and refresh
procedure are in [docs/THREAT-CATALOG.md](docs/THREAT-CATALOG.md). `--threat-catalog`
adds your own entries; `--no-builtin-catalog` turns the built-in one off.

## Platform support

| Platform | Status |
|---|---|
| Linux | Supported (XDG paths, `/etc/os-release`, `ps`) |
| macOS | Supported (`/Applications/`, `sw_vers`, `defaults read`); no network-listener inventory (no `/proc`; the `listeners` row is skipped with a warning) |

CI runs the full test suite on both. Windows paths are not read.

## Building

Requires Rust 1.99 or later (2024 edition, `rust-version` in `Cargo.toml`):

```bash
cargo build --release                         # target/release/rmguard, no runtime dependencies
cargo build --release --no-default-features   # without the OpenTelemetry exporter
cargo test                                    # debug build, as CI runs it (see docs/SECURITY.md)
```

## CLI reference

`rmguard --help` is authoritative; `rmguard -h` gives the summary.

| Flag | What it does |
|---|---|
| `-f, --format <FORMAT>` | `terminal` (default), `json`, `html`, `sbom`, `blueprint`, `compliance` |
| `-o, --output <FILE>` | Write output to a file instead of stdout |
| `--skip <LIST>` | Skip scanner categories (comma-separated; an unknown name is a warning listing the valid ones): `ai`, `frameworks`, `ide`, `extensions`, `mcp`, `node`, `shell`, `ssh`, `cloud`, `containers`, `notebooks`, `browser`, `packages`, `rules`, `skills`, `settings`, `aicreds`, `envfiles`, `transcripts`, `marketplaces`, `vscodetasks`, `gitconfig`, `pypkgs`, `npmpkgs`, `jbplugins`, `persistence`, `lsp`, `liveness`, `playwright`, `vibe`, `statusline`, `listeners`, `agents` |
| `--search-dirs <LIST>` | Additional home roots (comma-separated); home-rooted scanners run once per directory |
| `--threat-catalog <FILE>` | Additional JSON threat catalog, merged with the built-in one |
| `--no-builtin-catalog` | Disable the built-in threat catalog |
| `--diff <BASELINE.json>` | Compare against a previous `--format json` scan; stdout is the diff, `-o` receives the scan |
| `--fail-on <SEVERITY>` | Exit 3 if any finding is at or above `critical`, `high`, `medium` or `low` |
| `--probe-mcp` | Live-probe local stdio MCP servers (spawns them) |
| `--verify-registry` | Check MCP servers against registry.modelcontextprotocol.io (network) |
| `--report <DIR>` | Aggregate a directory of JSON scans into one fleet HTML dashboard (no local scan) |
| `--verbose` | Append the per-scanner diagnostics table |
| `--trace` | Print every path tried to stderr (same as `RMGUARD_TRACE=1`) |
| `--otel`, `--otel-instance <ID>` | OpenTelemetry export (network, opt-in) and the machine name it carries |
| `--jobs <N>` | Scanner threads per phase (default: available parallelism, at most 8) |
| `--walk-budget <N>` | Directories per project for the nested-repo walk (default 25,000); other caps scale |
| `-h, --help`, `-V, --version` | Help; version with the threat catalog version |

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

## License

Apache-2.0 — see [LICENSE](LICENSE).

rmguard began as a derivative work of [step-security/dev-machine-guard](https://github.com/step-security/dev-machine-guard)
by StepSecurity Inc.; see [NOTICE](NOTICE) for attribution and [Origins](#origins) for how the
projects relate today.
