# Security and privacy model

rmguard is itself a security-sensitive program: it reads credential-adjacent files, runs
`git` inside repositories it does not trust, and can spawn MCP servers. This file is the
full design (what it reads, what it never reads, how output is redacted), the test-only
knobs, and every documented floor: a limit that is known and kept by design. The
[README](../README.md#security-and-privacy-model) has the short version.

## Design decisions

- **No secret leakage**: Scanners report key *names*, file existence and permissions — never values. The one deliberate exception is variables that relocate an agent's home or redirect its traffic (`CLAUDE_CONFIG_DIR`, `*_BASE_URL`, `HTTPS_PROXY`, `OLLAMA_HOST`, ...): their path or host is not a secret and is shown after sanitization, with URL userinfo dropped; `ANTHROPIC_CUSTOM_HEADERS` is recorded by presence only. Anything that echoes user-controlled text into a finding (a hook command, an MCP launch line, a registry URL, a git config value) passes through one redaction helper that understands URL userinfo and query parameters, `key=value` and `key: value` pairs, HTTP `Authorization` schemes, curl/wget basic-auth and header forms, connection strings, compact JSON bodies and quoted values with whitespace — and keeps the parts a finding needs (the host, the binary, `| bash`). The guarantee is tested end to end, one canary per surface, with positive controls. The account and organization identifiers Claude Code puts in synced-skill directory names (`~/.claude/skills/synced/<org>_<account>/`) are masked as `<org>_<account>` in every output and in `--diff`, including against a baseline written before the mask.
- **Attacker text cannot forge the report**: every string an attacker chooses (a package version, an extension name, a plugin ID, a probed server's error message, hook and helper commands, skill paths, extension directory names) is sanitized when it is extracted, every finding's title, location and evidence is sanitized again in the terminal renderer, and the whole terminal report is rendered from a copy in which no string can carry a control character. The terminal output keeps only the SGR codes the renderer itself emits (no conceal, black or background codes), so no ANSI sequence or line break can draw a green "clean" line. `--diff` output is sanitized per line and keeps no escape sequence at all. Text the tool *scans* for injection (tool descriptions, server instructions) is kept raw for the scanner and never printed.
- **Adversarially reviewed**: the redaction, the git walk, the probe and the diagnostics have each been through multiple rounds of multi-agent adversarial review in which every finding was independently reproduced by a second agent before being accepted. Several of those rounds found that a fix had introduced a second edge; each is documented in the commit history along with the floors that remain by design.
- **authorized_keys is read, public material only**: `~/.ssh/authorized_keys` (and `authorized_keys2`, and any file a readable sshd_config names) holds public keys. Each key's blob is base64-decoded in memory only to compute its SHA-256 fingerprint; the report keeps the fingerprint, key type, comment (token shapes redacted) and option NAMES, never the blob or an option value (`command="..."`, `from="..."`). A symlinked authorized_keys is not followed. The user's crontab is read, when readable, only to classify `@reboot` lines; only the verdict and line number are reported.
- **SSH passphrase detection**: Uses `ssh-keygen` probing for OpenSSH-format keys (the PEM `ENCRYPTED` marker is unreliable for modern key formats); reports a tri-state (encrypted / no-passphrase / unknown) so a missing `ssh-keygen` is never reported as "unprotected".
- **MCP probing is opt-in**: `--probe-mcp` spawns local MCP servers and is gated behind an explicit flag with a runtime warning; each server runs in its own process group under a watchdog, its output is read with enforced deadlines, and the whole group is killed when the probe ends or the user interrupts.
- **Telemetry export is opt-in and content-free**: `--otel` exports OTLP traces/metrics of scan timing; ambient `OTEL_*` env never enables it; only labels, counts, durations and fixed outcome categories are exported (attribute keys are a closed enum, attribute values are `&'static str`, integers or booleans, and span names are joined from `&'static str` parts, so no runtime text can become an attribute or a span name; `compile_fail` doc tests, run in CI, check both); child processes never inherit `OTEL_*` variables, so a collector API key never reaches a probed server; a dead collector costs ≤2 s and never changes the report or exit code. Tested end to end with canaries in every scanned surface, a fake-tool canary for child environments, and a check that a default run with every `OTEL_*` endpoint variable set never connects to the collector port they name (rmguard's own process; tools it runs for `--version` are not covered).
- **HTML XSS prevention**: Report data is base64-encoded in script tags to prevent injection; all user content is HTML-escaped including single quotes.
- **Input validation**: `--format`, `--fail-on`, `--walk-budget`, `--otel-instance` and the other flag values are validated at parse time with clear error messages (a usage error exits 2). An unknown `--skip` category is a `warning:` line that lists the valid names; it is ignored and the scan goes on.
- **No `/tmp` fallback**: Fails fast if `$HOME` cannot be determined rather than scanning a shared directory.
- **What is read from `/proc` (Linux), and why**: only the scanning user's own processes (`stat(2)` of `/proc/<pid>`, owner = euid) are looked into, and nothing is spawned. The `liveness` scanner checks that a `.in_use/<pid>` marker under `~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/` names a live process (that `stat` only; the marker is an OBSERVED Claude Code signal, not documented: the plugin docs describe only `.orphaned_at`), and reads `/proc/<pid>/cmdline` (at most 16 KiB, at most 8,192 processes scaled by `--walk-budget`) to see whether a process runs from an npx cache: each argument is compared in memory by path prefix against `~/.npm/_npx/`, only the hex `<hash>` directory name and a process count are kept, the buffer is zeroed before the next process, and no argv text is stored, logged, traced or printed (a test plants canary arguments and checks every output format and `--trace`). The command line is read because nothing else finds these processes: the npx-launched `playwright-mcp` servers this was written against run as the system `node` with their `cwd` in a project and no open descriptor or mapping under the cache, so `exe`, `cwd`, `fd/*` and `maps` miss all of them (checked 2026-10-24). The `listeners` scanner reads `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/stat`, and per own process `comm`, `stat`, the `exe` and `cwd` links, `fd/*` link targets and `task/<tid>/children`; it never opens `cmdline` or `environ`. No scanner opens `/proc/<pid>/environ`. Floors: off Linux there is no `/proc` and neither signal is reported; an npx cache moved by `npm_config_cache` is not followed.
- **Bounded, regular-file-only reads**: Config files are read up to 1 MiB; identity files (`package.json`, `METADATA`, `plugin.xml`) are read as a bounded head so padding cannot hide a package; readers refuse FIFOs and devices so a planted named pipe cannot stall the scan; subprocesses (`git config`, `git ls-files`, `--version` probes) run under timeouts with stdin closed, and the git-tracked check refuses, without spawning git, a repository whose HEAD, index, config or commondir is not a regular file (behind a `gitdir:` file too) or whose config includes a non-regular file. Each repository is listed once per scan (`git ls-files -z`), and all tracked-file listings share a 20 s budget, so a repository built to stall git costs one timeout, not one per file. Directory walks are budgeted, and budgets are spent on directories rather than files so junk files cannot exhaust them.
- **The scanner cannot be turned against itself by a repository**: rmguard runs `git` inside project directories it does not trust, which is the GitSpawn shape it catalogues (a repo-local `core.fsmonitor` or `core.hooksPath` turning any git call into code execution). Every working-tree git invocation goes through one hardened command (`-c core.fsmonitor=false -c core.hooksPath=/dev/null -c safe.bareRepository=explicit`, with `GIT_DIR`-style environment scrubbed). The `git` program itself is resolved once, by absolute path, from the absolute PATH entries only, and the child's PATH keeps only those: git runs with its working directory inside the repository, and a relative entry (`.`, `node_modules/.bin`, an empty entry) would otherwise find a `git` the repository ships (a canary test plants one and runs with `PATH=.:/usr/bin:/bin`), and a canary test commits a repo whose fsmonitor would create a file and asserts the scan leaves it uncreated. This was found by automated review after the fact: an earlier `git ls-files` check was exploitable, which is exactly why the catalogue entry exists.
- **System tools never come from PATH**: the hostname and kernel version are read with `uname(2)` (no `hostname` or `uname` process at all), and the system tools rmguard does run (`ps`, `ssh-keygen`, and on macOS `sw_vers` and `defaults`) are taken by absolute path from `/usr/bin`, `/bin`, `/usr/sbin`, `/sbin` or NixOS's `/run/current-system/sw/bin` only, with that as their PATH, under a timeout and an exec span; a missing tool is an "unknown" answer, never a PATH lookup. A canary test puts a fake of each tool first on PATH and asserts none runs. (The AI tools whose `--version` is read are found on PATH by design: that is how they are installed.)
- **YAML is parsed in safe Rust, on a budget**: skill, command and subagent frontmatter, YAML MCP and agent configs and Serena's `project.yml` come from repositories rmguard does not trust, so the parser is attack surface. It is `serde-saphyr` (`#![forbid(unsafe_code)]`; it replaced `serde_yaml_ng`, whose C-to-Rust libyaml translation is unmaintained, RUSTSEC-2024-0449), and every document goes through one entry point (`src/scanners/yaml.rs`) with explicit limits: 1 MiB of input, nesting depth 128, one document, 10,000 aliases, 1,000 expansions of any one anchor, 20,000 recorded or replayed alias events, 256 merge keys, and 2 MiB of scalar text counting what aliases replay. An alias bomb, a large scalar repeated through aliases (which the previous parser expanded in full) or 100,000 nested brackets is refused in milliseconds (`tests/yaml_hostile.rs`); a document under the size cap that uses no anchors never reaches a counting limit. A document that is refused or malformed yields nothing from that file, as before.
- **Fuzzed & schema-validated**: Untrusted-input parsers (MCP config, threat catalog, `.env` and its agent overrides, settings hooks and helpers, skill dynamic context and `allowed-tools`, marketplace git files, `OLLAMA_HOST` readers, diff, the redaction helper) have `cargo-fuzz` targets; Blueprint output is validated against the vendored CycloneDX 2.0 schema in CI.
- **CI-gated**: every push runs the full suite on Linux **and** macOS, denies clippy correctness lints, keeps the fuzz targets compiling, and audits the dependency tree against RustSec advisories (`cargo audit`) — a supply-chain scanner should hold its own dependencies to the standard it scans for.

## How the guarantees are tested

Two end-to-end suites run the shipped binary against planted fixtures:

- `tests/vulnerable_range.rs` builds a deliberately-vulnerable "machine" (a threat-catalog
  MCP server, a `curl | bash` hook, MCP auto-approval, a poisoned rules file, a toxic-flow
  skill, a world-readable `.env`, a world-readable agent transcript store) and asserts the
  binary catches every planted issue. It's both a regression guard and a reference for
  "what a compromised machine looks like."
- `tests/no_secret_leakage.rs` plants a distinct credential in every surface that echoes
  user-controlled text — MCP launch args and commands, hook and task commands, every
  package-registry config, agent configs, marketplace URLs, a token file, agent transcripts
  (key names and token labels only) — renders every
  output format, and asserts none of them survives. Each fixture also carries a positive
  control (its host or provider name) that must appear, so a fixture the scanner never
  read cannot pass as "clean."

To generate a shareable demo report from the vulnerable fixtures, point `--search-dirs`
at a scratch copy and render HTML — the planted issues surface at the top of the report
(plus anything real on the host, since your own home directory is scanned too).

## Test-only knobs

The end-to-end tests run the debug binary with `HOME` and `RMGUARD_TEST_SYSTEM_ROOT` pointed at temp directories; the latter re-roots the machine-wide paths (`/etc/claude-code`, `/etc/systemd/system`, `/Library/...`) so a developer machine's own managed settings or Ollama unit cannot change a test's result. Release builds ignore it, so run the suite in debug (`cargo test`, as CI does): under `cargo test --release` those tests would read the host's real system paths.

## Floors

A floor is something rmguard knowingly does not read or does not grade. Most are stated
next to the behaviour they limit in [COVERAGE.md](COVERAGE.md); the longer lists are here.

### Hook surfaces

Floors (documented but not read):
- Claude Code: inline hooks in a marketplace entry (`marketplace.json` `plugins[].hooks`), link-mode and local-path plugins (an `installPath` outside the cache), `~/.claude/dev-mods` session mods, `CLAUDE_CODE_PLUGIN_CACHE_DIR` relocation, plugin monitors, and data flows inside a mod that use no process call (`$.fs.read` of a credential then `$.http.fetch`).
- Cursor: team hooks are listed by file name from `~/.cursor/managed/team_<id>/hooks/` (the desktop app's local copy) and not parsed; installed marketplace plugins (their on-disk location is not documented).
- Codex: intermediate project config layers between the repository root and the cwd, `commandWindows` (not pattern-checked), and plugin activation in `config.toml` `[plugins."p@m"] enabled` (every cached plugin's graded version is treated as active).
- Copilot CLI: `COPILOT_HOME` relocation, Windows registry policies, and agent-scoped hooks in custom-agent frontmatter.
- Gemini CLI: `GEMINI_CLI_SYSTEM_SETTINGS_PATH` and the `hooksConfig.disabled` per-hook list.
- Devin: plugin hooks (install location undocumented), ancestor-directory discovery between the repository root and the cwd, and dashboard-distributed enterprise hooks.
- OpenCode: npm plugin package sources (installed by Bun into `~/.cache/opencode`).
- Kiro: legacy IDE `*.kiro.hook` files and CLI 2.x profile-scoped hooks.
- Claude Code: an `asyncRewake` hook's `rewakeMessage` and `rewakeSummary` text (used by the official security-guidance plugin; code.claude.com/docs/en/hooks documents `asyncRewake` but not these fields, fetched 2026-10-23) is not read or graded; if they are documented as text put in the agent's context, they will be graded as conversation text.
- Everywhere: Windows paths (`%APPDATA%`, `ProgramData`).
- Budgets: at most 500 hooks per file entry and per plugin (a plugin manifest's list of hook files is read once per path and only until the plugin's cap) and 10,000 per scan; hooks past either are not parsed (the file is counted as a miss in the diagnostics and traced as "hook budget spent" under `--trace`). The on-disk checks of one command (native-binary probe, symlink check) stop after 16 path words, program words first, and after 20,000 per scan; the lexical agent-directory check still sees every word.

### More agents

Floors: what is inventoried but not graded, or not read:

- **Roo Code:** approval toggles (`alwaysAllowExecute`, ...) live in VS Code's SQLite
  `state.vscdb` and are not read. Custom modes' `groups` are not graded; the files are rules
  rows.
- **Cline:** hook contents are not read; hooks are listed by name. The VS Code state that
  predates `~/.cline/data` is not read.
- **Continue:** `cn --auto` and `--allow` are launch flags and leave nothing on disk. The
  `.continueignore` file is not read.
- **Aider:** a `read` or `load` path outside the project, and `.aider.tags.cache.v*`, are
  listed or ignored, not read. `env-file` is not read.
- **Goose:** `GOOSE_MODE` from the environment, `GOOSE_PATH_ROOT`, recipes, plugin
  hooks under `.agents/` (plugin skills are walked, see `.agents/` above), and `~/.local/state/goose/logs` (LLM request logs) are not read.
- **Zed:** the Rules Library (an LMDB file) is not read. The threads database is counted
  and sampled as bytes.
- **Junie:** the IDE plugin's Brave Mode, allowlist and global MCP live in IDE settings
  whose location is not documented. The CLI's sessions directory is not documented.
  Project hooks are documented as ignored.
- **Amp:** threads are stored on ampcode.com. The removed `amp.permissions` and
  `amp.dangerouslyAllowAll` keys are not read. Plugins are listed, not read or graded,
  because whether a workspace plugin waits for approval is not documented.
- **Warp:** app execution profiles (`[agents.profiles]`, edited in the UI), Warp Drive
  rules and MCP servers, and the state database are not read.
- **All agents:** environment-variable relocations (`CLINE_DIR`, `CONTINUE_GLOBAL_DIR`,
  `JUNIE_HOME`, `XDG_*`) are the scanning user's own and are not applied.

### New surfaces of covered agents

Floors of [the new surfaces](COVERAGE.md#new-surfaces-of-covered-agents-and-the-shared-agents-directory)
(documented but not read, or read but not graded):

- **Cursor:** Run Modes chosen in the UI ("Run Everything") and the team dashboard's
  Auto-review configuration are not on disk as documented files. `permissions.json`
  `autoRun` steering text is not read. `sandbox.json` path lists are not graded.
- **Devin:** where Devin Desktop stores its Allow/Deny/Ask lists and the legacy Cascade
  auto-execution level (`~/.codeium/user_settings.pb`, a binary protobuf) is not
  documented; neither is read. `local_tools_bypass_permissions` is not graded (its reach
  is not documented). `~/.codeium/windsurf/memories/global_rules.md` is not in current
  documentation and is not read. Ancestor `.devin/` directories between the repository
  root and the cwd are not walked.
- **Copilot CLI:** `allowedUrls`, `askUser`, `sandbox.*` and `statusLine.command` in
  `settings.json`, `localModel.args` in `providers.json` (never opened), plugin LSP files,
  and custom-agent `mcp-servers` frontmatter are not read. The repository settings files
  document no permission key, so only their hooks are read (settings scanner).
- **Gemini CLI:** the administrator's policy directory (`/etc/gemini-cli/policies`) and
  `policyPaths` are not graded; workspace `.gemini/policies/` is documented as
  non-functional and is not read; `tools.allowed` and `general.defaultApprovalMode` in
  `settings.json` are not graded here.
- **Codex:** `/etc/codex/requirements.toml` only restricts and is not graded (its hooks
  are read); execpolicy rules are read lexically, not evaluated as Starlark, and only a
  one-token interpreter pattern is graded; `.agents/plugins/marketplace.json` lists
  plugin sources and is not read (installed plugins are read under `~/.codex/plugins`);
  `/etc/codex/skills` is not walked; nested `.agents/skills` between the cwd and the
  repository root are not walked.
- **Kiro:** `sandbox.json` is opt-in (off without it) and a project file "can only
  tighten" the global one, and `cli.json` documents no approval key: neither is read.
  Markdown custom agents, `/etc/kiro/managed-settings.json` (deny and ask only) and the
  IDE's `kiroAgent.agentAutonomy` are not read. Hooks or steering inside a power are not
  documented.
- **OpenCode:** the remote `.well-known/opencode` configuration has no documented local
  copy; `OPENCODE_CONFIG`, `OPENCODE_CONFIG_DIR` and `OPENCODE_CONFIG_CONTENT` are the
  scanning user's environment and are not applied; macOS MDM plists are not read;
  `external_directory` and `doom_loop` permissions are not graded; tool files are listed,
  not read.
- **`.agents/`:** an agent counts as a reader only when its configuration home exists
  (an agent installed but never run is not listed). Skill frontmatter `mcpServers` (Amp)
  is not parsed. AGENTS.md is read by the rules scanner and is not attributed (nearly
  every agent reads it).
- **Other agents' skills:** Claude Code's dynamic context, `allowed-tools` grants and
  frontmatter hooks are not graded for them (Copilot CLI documents `allowed-tools: "*"`;
  not graded).

### Floors stated elsewhere

- Agent skills: plugins installed in link mode are not walked ([Agent Skills](COVERAGE.md#agent-skills)).
- Persistence: macOS URL handlers (LaunchServices database, app bundles' `Info.plist`) are not parsed ([Persistence Artifacts](COVERAGE.md#persistence-artifacts)).
- Network listeners: macOS has no `/proc`, so the scanner is skipped with a warning ([Network Listeners](COVERAGE.md#network-listeners-linux)).
- SSH authorized keys: a root-only `/etc/ssh/sshd_config` (the usual mode) is not read, so a non-default `AuthorizedKeysFile` is missed for an unprivileged scan (rows say `sshd_config: unreadable`); `AuthorizedKeysFile` inside a `Match` block is not evaluated; a symlinked authorized_keys is listed, not read; the attacker-key list holds only published fingerprints ([SSH Authorized Keys](COVERAGE.md#ssh-authorized-keys)).
- Persistence (October 2026 extension backdoor): the user's crontab spool is usually root-only, so the Linux `@reboot` entry is seen only when rmguard runs with access to it (`crontab -l` is not run); a live reverse SSH tunnel (`ssh -N -R` to the attacker host) is not detected, since process arguments are never read and the tunnel's remote listener is not visible locally; `$TMPDIR/.stk_*` and the Windows scheduled task and Startup entry are not checked ([Persistence Artifacts](COVERAGE.md#persistence-artifacts)).
- IDE extensions: the `~/.vscode-server` and `~/.cursor-server` remote-extension directories are not scanned.
- Hooks: prose redaction of prompt text is a heuristic; short passwords after a flag with no secret-shaped name are not recognised; Devin CLI, Devin Desktop and Gemini CLI prompts are `undocumented` and graded as conversation text; a command built in a variable and passed to an exec call is advisory ([Hook surfaces](COVERAGE.md#hook-surfaces)).
- `/proc` signals: off Linux neither signal is reported; an npx cache moved by `npm_config_cache` is not followed ([Design decisions](#design-decisions)).
- OpenTelemetry: see [OPENTELEMETRY.md](OPENTELEMETRY.md#known-limits).
- Scheduled runs: see [OPERATIONS.md](OPERATIONS.md#caveats).
