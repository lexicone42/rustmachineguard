# OpenTelemetry export

rmguard can export the timing of a scan as OpenTelemetry traces and metrics, so you can
see where a slow scan spends its time, or watch scanner health across a fleet in the
observability stack you already run, and, through the [posture metrics](#posture-metrics),
how many findings of each severity and category, and how many items of each inventory
kind, each machine has. Export is off by default. It sends **labels, counts and
durations only**, and never the content of anything the scan found: no finding title,
evidence, path, name or value.

## Turning it on

| Condition | Export? |
|---|---|
| no `--otel` (whatever `OTEL_*` variables are set) | **no**: no `OTEL_*` value is used, nothing is built, rmguard opens no socket |
| `--otel` | yes |
| `--otel` with no `--otel-instance` and no `service.instance.id` in `OTEL_RESOURCE_ATTRIBUTES` | yes, with one `info:` line saying the export carries no machine identity ([Machine identity](#machine-identity)) |
| `--otel` + `OTEL_SDK_DISABLED=true` (any case) | no (`info:` line) |
| `--otel` + `OTEL_TRACES_EXPORTER=none` | metrics only |
| `--otel` + `OTEL_METRICS_EXPORTER=none` | traces only |
| `--otel` + both `=none` | no (`info:` line) |
| `--otel` + `--report <DIR>` (fleet mode) | no (`warning:` line): fleet mode aggregates other machines' JSON reports into one dashboard and scans nothing, so there is no scan of this machine to time or report posture for, and exporting the aggregated reports as this process's telemetry would attribute every machine's posture to one resource |
| `--otel` on a binary built with `--no-default-features` | no (`warning:` line, exit code unchanged) |

Why the flag and not the environment: `OTEL_EXPORTER_OTLP_ENDPOINT` is common on
developer machines, because other tools ask you to export it in your shell profile
(Claude Code's monitoring setup is one example). A scanner that "runs locally, sends
nothing" must not start shipping data because some other tool configured a collector.
The variables only choose **where** `--otel` sends:

- Endpoint: `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` / `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`,
  then `OTEL_EXPORTER_OTLP_ENDPOINT` + `/v1/traces` or `/v1/metrics`, then
  `http://localhost:4318`. https works (rustls, the same TLS stack as `--verify-registry`).
- `OTEL_EXPORTER_OTLP_HEADERS` (e.g. an API key for a hosted backend) is honored. It is
  never handed on: every process rmguard starts (a probed MCP server, a `--version`
  probe, `git`, `ps`, `ssh-keygen`) gets an environment with **every** `OTEL_*`
  variable removed, with or without `--otel`. A probed server command is written by
  whoever wrote the MCP config, and must not be able to read your collector key.
- `OTEL_SERVICE_NAME` and `OTEL_RESOURCE_ATTRIBUTES` are honored. What you add there is
  your choice and your data. `--otel-instance <ID>` sets `service.instance.id` and wins
  over one in `OTEL_RESOURCE_ATTRIBUTES`.
- Proxies: a **loopback** endpoint (`localhost`, `*.localhost`, `127.0.0.0/8`, `::1`,
  which includes the default) is always reached directly. For any other endpoint, ureq's
  environment proxy applies: the first of `ALL_PROXY`, `all_proxy`, `HTTPS_PROXY`,
  `https_proxy`, `HTTP_PROXY`, `http_proxy` that is set is used for http:// and https://
  endpoints alike, and `NO_PROXY`/`no_proxy` exempts hosts. A plain http:// export
  through a proxy is cleartext to that proxy, headers included; use https:// or
  `NO_PROXY` for a collector you reach without one.
- The protocol is always http/protobuf. A different `OTEL_EXPORTER_OTLP_PROTOCOL` gets
  one start-up `warning:` line and is ignored. For `OTEL_TRACES_EXPORTER` /
  `OTEL_METRICS_EXPORTER`, only `none` (turn that signal off) and `otlp` are recognized;
  any other value (`console`, `zipkin`, ...) gets one start-up `warning:` line and turns
  that signal off, the same as `none`: a value rmguard cannot honour never falls back to
  an OTLP push you did not ask for. Timeouts are fixed in code (below), and env values
  do not lengthen them.

## Machine identity

rmguard does not name the machine it runs on: there is no `host.name`, no user and no
id derived from either (see [What is never exported](#what-is-never-exported-and-why)).
Without an identity of your choosing, every machine's series carry the same labels and
a fleet dashboard sees one machine. Give each one an id with

```bash
rmguard --otel --otel-instance "$ASSET_TAG"
# or
OTEL_RESOURCE_ATTRIBUTES=service.instance.id=$ASSET_TAG rmguard --otel
```

`--otel-instance <ID>` sets the resource attribute `service.instance.id` (the
[resource semantic convention](https://opentelemetry.io/docs/specs/semconv/resource/service/)
for telling instances of one service apart; the collector's Prometheus exporter turns it
into the `instance` label). It is **the one exported value that is not a closed set**:
it is your text, typed on the command line (or by your fleet tooling), exported as given
(surrounding whitespace removed; empty, longer than 128 characters or containing a
control, bidi, zero-width or other invisible formatting character, anything the
display sanitizer would rewrite, is a usage error). rmguard never fills it in itself: not from the host
name, the user, a machine id file or anything it scanned. Pick something that means
something to you and nothing to an outsider, such as an asset tag, rather than the host
name. `--otel-instance` without `--otel` is a usage error.

When `--otel` starts export and neither `--otel-instance` nor a non-empty
`service.instance.id` in `OTEL_RESOURCE_ATTRIBUTES` is given, stderr gets one line, and
export goes ahead without an id:

```
info: OpenTelemetry export carries no machine identity (no service.instance.id), so every machine's series share labels; add one with --otel-instance <id> or OTEL_RESOURCE_ATTRIBUTES=service.instance.id=<id> (rmguard never derives it from the host)
```

The root span's `rmguard.otel.instance_id_set` (bool) says whether an id was supplied,
so a trace shows it without the resource at hand.

## Quickstart

```bash
# A local collector that prints what it receives
docker run --rm -p 4318:4318 otel/opentelemetry-collector

# or Jaeger all-in-one, with its OTLP/HTTP receiver, UI on :16686
docker run --rm -p 4318:4318 -p 16686:16686 jaegertracing/all-in-one

rmguard --otel
rmguard --otel --probe-mcp --verbose
OTEL_EXPORTER_OTLP_ENDPOINT=https://otel.example.internal:4318 rmguard --otel --format json -o scan.json
```

On stderr you get one `info: OpenTelemetry export enabled ...` line. If the collector
cannot be reached you also get exactly one `warning: OpenTelemetry export ...` line,
whatever configuration notices were printed at start-up. The report on stdout or in
`-o` is the same either way.

## Span tree

```
rmguard.scan                                   (root; one trace per run)
├── phase.device_info
│   └── exec.output_with_timeout               (macOS only: `sw_vers -productVersion`; Linux uses libc uname, no spawn)
├── phase.global_scanners
│   ├── scanner.ai
│   │   ├── version.read                       (Mistral Vibe: version from its venv's dist-info METADATA)
│   │   ├── exec.version_probe                 (`<tool> --version`)
│   │   ├── exec.verify_binary
│   │   └── exec.process_list                  (`ps -A -o ucomm=`, once per scan)
│   ├── scanner.node
│   │   ├── version.read                       (npm, yarn, pnpm: version from package.json)
│   │   └── exec.version_probe                 (node, bun; a JS tool whose package.json did not answer)
│   └── scanner.listeners                      (Linux: /proc/net/tcp{,6} and the user's own /proc/<pid>; nothing is run;
│                                               macOS: a `skipped` row, no span)
├── phase.home_pass                            (rmguard.root.index=0, root.kind=home)
│   ├── scanner.mcp
│   ├── scanner.envfiles
│   │   └── exec.git_tracked                   (`git ls-files --error-unmatch`)
│   ├── scanner.ssh
│   │   └── exec.ssh_keygen
│   ├── scanner.skills
│   │   └── skills.walk                        (one per walk: commands, agents, hooks,
│   │                                           codex, skills, plugins; global and per project)
│   ├── scanner.transcripts
│   │   └── transcripts.store                  (one per store, present or not)
│   ├── scanner.lsp                            (plugin LSP servers; nothing is run)
│   ├── scanner.liveness                       (plugin `.in_use` markers, /proc on Linux)
│   ├── scanner.playwright
│   │   └── exec.git_check_ignore              (`git check-ignore -q`, one per `.playwright-mcp/` with untracked files)
│   ├── scanner.vibe
│   ├── scanner.statusline
│   └── scanner.gitconfig
│       ├── gitconfig.repos                    (every project's own .git/config)
│       │   └── exec.output_with_timeout       (`git config --list`)
│       └── gitconfig.nested_walk              (buried-git-dir walk; every project but HOME)
│           └── exec.output_with_timeout
├── phase.home_pass                            (index=1.., root.kind=search_dir; one per --search-dirs)
├── phase.dedupe
├── phase.catalog_load
├── phase.exposure
│   ├── scanner.pypkgs
│   ├── scanner.npmpkgs
│   └── scanner.jbplugins
├── scanner.mcp-probe                          (--probe-mcp)
│   └── mcp.probe                              (SpanKind=Client, one per stdio server)
├── scanner.registry                           (--verify-registry)
│   └── registry.lookup                        (SpanKind=Client, one per package)
├── phase.identity
├── phase.diff                                 (--diff)
├── phase.render
└── phase.write
```

A `scanner.<label>` span's duration equals that scanner's `duration_ms` in the JSON
`diagnostics` (the span is ended at exactly start + the measured elapsed time), and its
attributes carry the same counts.

Within `phase.global_scanners` and each `phase.home_pass` the scanners run side by side
on up to `--jobs` threads (default: the machine's available parallelism, at most 8), so
their spans overlap in time; with `--jobs 1` they run one after another on the main
thread and never overlap. `phase.global_scanners` and the primary `phase.home_pass`
(index 0) share one pool of `--jobs` threads, so those two phase spans overlap too: both
are children of `rmguard.scan`, both start when the pool starts, and each ends when the
last of its own scanners finished. (They are independent: the two phases store disjoint
report fields, and rows are pushed after both, global rows first.) With `--jobs 1` they
run one after the other, as before; `--search-dirs` passes always follow the pair, one
at a time. The tree is the same either way: a thread makes the scanner's own phase span
context current before it runs a scanner, so every `scanner.*` span is a child of its
`phase.*` span, and every span a scanner opens (`exec.*`, `skills.walk`,
...) is a child of that scanner. The one `exec.*` span outside a scanner is the macOS
device-info probe under `phase.device_info`, a phase with no scanners. A scanner span's counts are set, and the span ended
at start + its measured duration, once the phase has joined and the rows are final, in
the fixed scanner order (the reads of a cache shared by several scanners, a
repository's `git ls-files` listing, are charged to the first scanner in that order
that asked for it, as when the scanners ran one at a time). The `exec.git_tracked` or
`exec.process_list` span that fills such a cache sits under whichever scanner thread
got there first.

The process list is read once per scan, by whichever scanner asks first (normally
`ai`); `frameworks`, `containers` and `notebooks` answer from the same snapshot and
open no span for it. It replaced one `pgrep -x <name>` per question (ten spawns and
about 120 ms a scan on the machine it was measured on; the snapshot is one spawn of
about 9 ms). The match is the one `pgrep -x` made: the whole process name, exactly,
case-sensitively.

`scanner.node` reads the version of npm, yarn and pnpm from disk when it can: the PATH
entry is resolved through its symlinks, and when it lands in `node_modules/<tool>/` whose
`package.json` names the tool and holds a plain semver version, that is the version, and
nothing is spawned (pnpm's `--version` cost 262 ms and npm's 79 ms on the machine this
was measured on; the read costs well under a millisecond). Each attempt is a
`version.read` span with `rmguard.exec.program` (the tool, from the same closed table)
and `rmguard.version.source`: `package_json` when the file answered, `spawn` when it did
not, in which case the `exec.version_probe` that follows, a sibling under
`scanner.node`, is the answer. node and bun are native binaries and only get the
`exec.version_probe`.

`scanner.ai` does the same for Mistral Vibe, a Python console script (`vibe --version`
starts an interpreter: about 1.2 s of a 1.3 s scan on the machine this was measured on).
When the resolved `vibe` sits in `<venv>/bin/` of a virtual environment with a
`pyvenv.cfg` (a uv tool under `~/.local/share/uv/tools/<name>/`, a pipx venv), the
version is the `Version:` header of that environment's single `mistral_vibe-*.dist-info/METADATA`
(64 KiB head, no-follow; `Name:` must be `mistral-vibe` and the version must match the
directory name). Its `version.read` span carries `rmguard.version.source` = `dist_info`
or `spawn`.

`gitconfig` runs in two passes so the trace can tell its two costs apart: every
project's own `.git/config` (`gitconfig.repos`), then the walk for git directories
buried inside each project (`gitconfig.nested_walk`). The findings are joined back in
the old per-project order, so the report is unchanged. The projects are walked side by
side on up to `--jobs` threads, each with its own directory budget (`--walk-budget`,
default 25,000 directories listed per project) and counts; the span's counts are the
per-project counts summed in project order, and `rmguard.walk.budget_exhausted` is true
when any project's walk stopped at its budget. The skills bundle walk's file and entry
budgets scale with the same flag (31,250 files and 312,500 entries at the default).
Raising `--walk-budget` trades scan time for coverage; a walk that still reaches it sets
`rmguard.walk.budget_exhausted` and its scanner's `rmguard.scanner.truncated`.
An `exec.*` span a helper thread opens (a nested repo's `git config`) is a child of
`gitconfig.nested_walk`, as it was sequentially.

A `skills.walk` reads, hashes and analyses the files it judged on up to `--jobs`
threads, after the walk; the walk (its entries, budgets and symlink judgement), the
frontmatter hooks (which spend the scan's hook budget) and its counts stay on the
scanner's thread, in walk order, so `rmguard.walk.files`, `rmguard.walk.bytes_hashed`
and `rmguard.walk.hooks` are the same at any `--jobs`. With `--jobs 1` neither scanner
starts a thread.

## Attributes

| Key | On | Value |
|---|---|---|
| `rmguard.format` | root | `terminal` \| `json` \| `html` \| `sbom` \| `blueprint` \| `compliance` |
| `rmguard.skip.count` | root | number of valid `--skip` labels |
| `rmguard.search_dirs.count` | root | number of `--search-dirs` entries |
| `rmguard.probe_mcp`, `rmguard.verify_registry`, `rmguard.diff` | root | bool |
| `rmguard.exposure_findings` | root | count |
| `rmguard.findings.critical`, `rmguard.findings.high`, `rmguard.findings.medium`, `rmguard.findings.low` | root | findings of that severity (the same findings `--fail-on` and the report's risk summary count) |
| `rmguard.scanners_run` | root | count of non-skipped diagnostics rows |
| `rmguard.jobs` | root | threads a scan phase may use (`--jobs`, or the default) |
| `rmguard.otel.instance_id_set` | root | bool: `--otel-instance` or a `service.instance.id` in `OTEL_RESOURCE_ATTRIBUTES` was given ([Machine identity](#machine-identity)) |
| `rmguard.catalog.version` | root, resource | the built-in threat catalog's version (`2026-10-22`: the date of its last change, a constant compiled into the binary, also in `rmguard --version` and the JSON report's `catalog.builtin_version`). On the root span only when the built-in catalog was used (absent with `--no-builtin-catalog`); on the resource always, as a fact of the binary |
| `rmguard.phase` | phase.* | the phase name |
| `rmguard.root.index` | phase.home_pass | 0 = your home, 1.. = `--search-dirs` position |
| `rmguard.root.kind` | phase.home_pass | `home` \| `search_dir` |
| `rmguard.scanner` | scanner.*, metrics | scanner label: a closed set, the `--skip` labels (`VALID_SKIP` in src/main.rs: `mcp`, `packages`, ..., `statusline`, `listeners`) plus `mcp-probe` and `registry` |
| `rmguard.finding.severity` | `rmguard.findings` | `critical` \| `high` \| `medium` \| `low` |
| `rmguard.finding.category` | `rmguard.findings` | one of the 38 entries of `analysis::FINDING_CATEGORIES` (`Exposure`, `Hook`, `Secret leak`, `SSH key`, ...: the report's own `category` strings), else `other` |
| `rmguard.inventory.kind` | `rmguard.inventory` | one of the 35 report summary counts, named without `_count` (`mcp_servers`, `mcp_plugin_servers`, `mcp_connectors`, `agent_hooks`, `agent_hooks_inactive`, `agent_skills`, `ssh_keys`, `env_files`, ...; `Summary::inventory`) |
| `rmguard.duration_ms` | scanner.* | as in diagnostics |
| `rmguard.files.read`, `rmguard.files.missing`, `rmguard.items` | scanner.* | as in diagnostics |
| `rmguard.scanner.truncated` | scanner.* | bool: the scanner stopped at a walk budget (the gitconfig nested walk, the skills bundle walk); `truncated` in diagnostics |
| `rmguard.exec.site` | exec.*, metric | `version_probe` \| `verify_binary` \| `git_tracked` \| `output_with_timeout` \| `process_list` \| `ssh_keygen` \| `git_check_ignore` |
| `rmguard.exec.program` | exec.*, version.read, metric | the program's basename if it is one rmguard itself runs (`otel::EXEC_PROGRAMS`: `git`, `ps`, `ssh-keygen`, `sw_vers`, `defaults`, `node`, `npm`, `yarn`, `pnpm`, `bun`, the AI CLIs, model servers, container runtimes, notebook servers and IDE launchers the scanners probe), else `other` |
| `rmguard.exec.outcome` | exec.*, metric | `ok` \| `nonzero` \| `spawn_failed` \| `timeout` \| `wait_failed` \| `unknown` |
| `process.exit.code` | exec.* | exit code, when the child exited normally |
| `rmguard.skills.projects` | scanner.skills | number of project directories walked (no path, no index) |
| `rmguard.walk.kind` | skills.walk | `commands` \| `agents` \| `hooks` \| `codex` \| `skills` \| `plugins` |
| `rmguard.walk.scope` | skills.walk | `global` \| `project` |
| `rmguard.walk.root_link` | skills.walk | `plain` (no symlink to the root, or no root) \| `followed` (a linked root that is walked) \| `refused` (a linked root that is inventoried unread) |
| `rmguard.walk.entries` | skills.walk, gitconfig.nested_walk, transcripts.store | directory entries visited |
| `rmguard.walk.files` | skills.walk, transcripts.store | skills: files read through the shared reader; transcripts: regular files counted (opened only for two bounded samples: the head of at most 50 session-env / shell-snapshots files read for exported variable names, and the first 1 MiB of at most 200 files of each conversation, history, session and shell-state store read for secret-shaped key names and token-prefix labels) |
| `rmguard.walk.bytes_hashed` | skills.walk | bytes of file content hashed for the inventory's sha256 |
| `rmguard.walk.hooks` | skills.walk | frontmatter hooks found |
| `rmguard.walk.budget_exhausted` | skills.walk, gitconfig.nested_walk | bool: a file, entry or directory budget stopped the walk (budgets set by `--walk-budget`) |
| `rmguard.items` | skills.walk | inventory entries the walk produced (before the scanner's dedupe) |
| `rmguard.walk.dirs` | gitconfig.nested_walk | directories listed, summed over projects |
| `rmguard.walk.pruned` | gitconfig.nested_walk | directories not descended into as generated content, summed over projects: skipped by name (`node_modules`, ...) or holding a `CACHEDIR.TAG` ([Cache Directory Tagging Specification](https://bford.info/cachedir/)) or `pyvenv.cfg`. HOME registered as a project is not walked at all and adds nothing |
| `rmguard.version.source` | version.read | `package_json` (the version came from the tool's own package.json) \| `dist_info` (from the `METADATA` of the tool's Python distribution in its venv) \| `spawn` (it did not; `<tool> --version` is run) |
| `rmguard.walk.bytes` | transcripts.store | summed size of the counted files |
| `rmguard.repos` | gitconfig.repos, gitconfig.nested_walk | projects whose own config was checked; nested git directories found |
| `rmguard.transcripts.framework` | transcripts.store | `claude-code` \| `codex` \| `gemini-cli` |
| `rmguard.transcripts.kind` | transcripts.store | `conversation transcripts` \| `command history` \| `todo state` \| `shell snapshots` \| `session environment` \| `task lists` \| `plan files` \| `settings backups` \| `telemetry queue` \| `security plugin state` \| `exo-self plugin state` \| `feature-flag cache` \| `paste cache` \| `usage data` \| `agent memory` \| `file edit history` \| `account state file` \| `account state backup` \| `sessions` \| `session state` |
| `rmguard.mcp.server_index` | mcp.probe | position among probed servers (not the name) |
| `rmguard.mcp.outcome` | mcp.probe, metric | `ok` \| `empty_command` \| `spawn_failed` \| `timeout` (deadline or watchdog) \| `closed` (server exited: EOF or broken pipe) \| `error` (anything else, including every server-reported error) |
| `rmguard.mcp.tools`, `rmguard.mcp.resources` | mcp.probe | counts |
| `rmguard.registry.index` | registry.lookup | position among lookups (not the package) |
| `rmguard.registry.verdict` | registry.lookup, metric | `registered` \| `possible_typosquat` \| `unregistered` \| `no_package_identity` \| `lookup_failed` |
| `http.request.method`, `server.address` | registry.lookup | `GET`, `registry.modelcontextprotocol.io` |
| `error.type` | registry.lookup | `status` \| `timeout` \| `connect` \| `tls` \| `body` \| `parse` \| `other` |
| `http.response.status_code` | registry.lookup | the HTTP status, when the registry answered with an error |

Failed spans carry `Status::Error` with a fixed category as the description, such as
`spawn_failed`, `timeout` or `lookup_failed`. A non-zero exit is not an error: for
`git ls-files` it means "not tracked".

Subprocess spans name the call site and, since the trace could not otherwise say
which of three `version_probe` spans took 250 ms, the program, as a closed value:
`rmguard.exec.program` is the basename only when it is in the fixed table of programs
rmguard chooses to run, and `other` for anything else (a renamed binary, a path outside
the table). It is never a path, an argument or an MCP server command; `mcp.probe` spans
still do not name the server. `process.executable.name` (free text) is not exported.

This is a deliberate change from earlier versions, and it is posture metadata of the
same kind as the counts below: rmguard runs `<tool> --version` only for tools it found,
so the programs on a trace's `version_probe` spans say which of the table's AI tools,
model servers, container runtimes and IDEs are installed. They never say where, which
version, or anything outside the table.

Resource attributes: `service.name=rmguard` (unless `OTEL_SERVICE_NAME` is set),
`service.version`, `os.type` (`linux` \| `darwin`), `host.arch` (`amd64` \| `arm64` \| raw),
`rmguard.catalog.version`, the SDK's `telemetry.sdk.*`, and `service.instance.id` when you
give one ([Machine identity](#machine-identity)). There is no `host.name` and no user.

`rmguard.catalog.version` is there so a fleet can tell a catalog update from a posture
change: when `rmguard.findings{rmguard.finding.category="Exposure"}` jumps on many
machines at once, a new catalog version on the same day says the catalog learned about
packages that were already installed, not that the machines changed.

## Metrics

Exported once, when the scan ends (cumulative temporality: the one snapshot covers the
whole run).

| Name | Instrument | Unit | Attributes |
|---|---|---|---|
| `rmguard.scan.duration` | histogram | s | none |
| `rmguard.scanner.duration` | histogram | s | `rmguard.scanner` |
| `rmguard.scanner.files_read` | counter | `{file}` | `rmguard.scanner` |
| `rmguard.scanner.files_missing` | counter | `{file}` | `rmguard.scanner` |
| `rmguard.scanner.items` | counter | `{item}` | `rmguard.scanner` |
| `rmguard.scanner.skipped` | counter | `{scanner}` | `rmguard.scanner` |
| `rmguard.exec.duration` | histogram | s | `rmguard.exec.site`, `rmguard.exec.program`, `rmguard.exec.outcome` |
| `rmguard.mcp.probe.duration` | histogram | s | `rmguard.mcp.outcome` |
| `rmguard.registry.lookup.duration` | histogram | s | `rmguard.registry.verdict` |
| `rmguard.findings` | gauge | `{finding}` | `rmguard.finding.severity`, `rmguard.finding.category` |
| `rmguard.inventory` | gauge | `{item}` | `rmguard.inventory.kind` |
| `rmguard.scan.truncated_scanners` | gauge | `{scanner}` | `rmguard.scanner` |

That is twelve names, but a plain scan exports ten: `rmguard.mcp.probe.duration` appears
only with `--probe-mcp` (and at least one stdio server probed), and
`rmguard.registry.lookup.duration` only with `--verify-registry` (and at least one
lookup). An instrument with no recorded value is not exported. (`rmguard.findings`
always has a value on a machine with at least one finding; on a machine with none it is
absent, which is the answer "no findings".)

Histogram buckets (s): 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30.

Counts are posture metadata. `rmguard.scanner.items` labelled `aicreds` or `ssh`,
`rmguard.exposure_findings` and the severity totals on the root span, and the posture
metrics below tell a collector how many credentials or findings of each kind a machine
has, never which ones or where. Choose the collector with that in mind.

### Posture metrics

`rmguard.findings` and `rmguard.inventory` are recorded once per scan from the finished
report, after analysis and before the export shutdown (and only under `--otel`: a plain
run does not compute them); `rmguard.scan.truncated_scanners` is recorded with the other
per-scanner metrics as each diagnostics row is final (a scanner with one row per home
pass records the running sum, so the exported value is the scan's total). All three are
exported in the one snapshot at the end of the scan.

They are **gauges** (the synchronous `u64_gauge` of opentelemetry 0.33), not counters.
One rmguard process exports one scan and exits, so each value is the machine's state at
that scan, replaced by the next run's, never added to. As counters (before this
version) each run started a new cumulative stream, which a backend reads as a counter
reset per run: `rate()`/`increase()` over them were meaningless, and `_total` names
suggested a running count that was not there. The metrics API's
[Gauge](https://opentelemetry.io/docs/specs/otel/metrics/api/#gauge) records a current
value "when changes occur", and the
[Prometheus compatibility spec](https://opentelemetry.io/docs/specs/otel/compatibility/prometheus_and_openmetrics/#gauges)
maps an OTLP Gauge to a Prometheus gauge with no `_total` suffix. (The
[instrument-selection guidelines](https://opentelemetry.io/docs/specs/otel/metrics/supplementary-guidelines/#instrument-selection)
put a non-additive absolute value on a gauge; these counts are additive across their
labels, which is the case for an UpDownCounter. That would export as a non-monotonic
cumulative Sum, which the same compatibility spec also maps to a Prometheus gauge; the
gauge was chosen because each value is a replacement, not a delta. Summing them across
labels and machines is still meaningful, and the queries below do it.) The performance
metrics are unchanged: durations are histograms, and the per-scanner
`files_read`/`files_missing`/`items`/`skipped` stay counters.

| Name | Data points | Equals |
|---|---|---|
| `rmguard.findings` | one per (severity, category) pair with at least one finding; pairs with none are not exported | the report's findings grouped by severity and `category` (`analysis::collect_findings`, the list the terminal and HTML risk summary and `--fail-on` use) |
| `rmguard.inventory` | one per kind, all 32, zeros included | the JSON report's `summary.<kind>_count` |
| `rmguard.scan.truncated_scanners` | one per scanner that ran: 0, or the number of its rows (one per home pass) that stopped early | diagnostics rows with `truncated: true` |

The severity totals are also on the root span as ints (`rmguard.findings.critical`,
`.high`, `.medium`, `.low`), so a trace on its own shows the machine's posture.

The labels are closed sets defined in code, each pinned by a test:
`rmguard.finding.severity` is the `Severity` enum's lowercase label;
`rmguard.finding.category` is `analysis::FINDING_CATEGORIES` (38 entries), the
category strings exactly as the terminal, HTML and compliance reports show them. A unit test walks `src/analysis.rs`
for every `category: "..."` literal and every `(severity, "...", title)` tuple and fails
if one is not in the table (or a table entry is never emitted), a second checks the
table against the categories `guidance` explains, and a debug build asserts every
emitted category is listed. The exported value is the table's own `&'static str`
(`analysis::category_label`, which returns `other` for anything else, never its input).
`rmguard.inventory.kind` is `Summary::inventory`, whose test fails when a `_count` field
is added to the summary without a row. `agent_hooks_by_framework`, keyed by framework
names, is the one summary field not exported.

**Not exported**, here or anywhere: finding titles, evidence (the hook command, the git
config value, ...), locations and paths, server, package, extension, skill or key
names, versions, hosts and users. A dashboard can say "this machine has 2 critical
`Exposure` findings"; only the machine's own report says which packages.

The names follow the OpenTelemetry metric naming guidance
([semantic conventions: metrics](https://opentelemetry.io/docs/specs/semconv/general/metrics/)):
lowercase dot-separated namespaces under `rmguard.`, a count's unit an annotation in
braces (`{finding}`, `{item}`, `{scanner}`), and no unit or `_total` in the name.

Each run is its own process and exports its scan once, so a backend holds one sample
per machine per scan: read a posture gauge as "the value at the latest scan", with
`last_over_time` over a window at least as long as the scan interval. Every machine
needs an id of its own ([Machine identity](#machine-identity)), or their series land on
the same labels.

Names in Prometheus, from the collector's `prometheus` exporter (verified against
otelcol-contrib 0.163.2, [below](#verified-against)). Under the
[Prometheus compatibility rules](https://opentelemetry.io/docs/specs/otel/compatibility/prometheus_and_openmetrics/#metric-metadata),
dots become underscores, a brace unit such as `{finding}` is dropped, a monotonic Sum
gets `_total` and a Gauge gets no suffix:

| OTLP name | default (`translation_strategy: UnderscoreEscapingWithSuffixes`) | `NoUTF8EscapingWithSuffixes`, scraped with UTF-8 escaping allowed |
|---|---|---|
| `rmguard.findings` (gauge) | `rmguard_findings` | `rmguard.findings` |
| `rmguard.inventory` (gauge) | `rmguard_inventory` | `rmguard.inventory` |
| `rmguard.scan.truncated_scanners` (gauge) | `rmguard_scan_truncated_scanners` | `rmguard.scan.truncated_scanners` |
| `rmguard.scanner.files_read` (counter) | `rmguard_scanner_files_read_total` | `rmguard.scanner.files_read_total` |

Labels follow the same rule (`rmguard_finding_severity`, or `"rmguard.finding.severity"`
with UTF-8 names); `service.instance.id` becomes `instance` and `service.name` becomes
`job` either way. A UTF-8 name is kept only when the exporter is configured for it
**and** the scraper asks for it (Prometheus 3 does; a plain `curl` without an
`escaping=allow-utf-8` Accept header still gets underscores). The
[exporter's `translation_strategy`](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/exporter/prometheusexporter/README.md)
replaces the deprecated `add_metric_suffixes`. With the default translation:

```promql
# Fleet findings by severity, from each machine's latest scan in the last day
sum by (rmguard_finding_severity) (last_over_time(rmguard_findings[1d]))

# Critical and high findings by category across the fleet (a Grafana bar chart)
sum by (rmguard_finding_category) (
  last_over_time(rmguard_findings{rmguard_finding_severity=~"critical|high"}[1d])
)

# Machines with at least one critical finding
count(sum by (instance) (last_over_time(rmguard_findings{rmguard_finding_severity="critical"}[1d])) > 0)

# Machines whose last scan stopped a walk early (results may be incomplete)
count(sum by (instance) (last_over_time(rmguard_scan_truncated_scanners[1d])) > 0)

# The same first query with UTF-8 names
sum by ("rmguard.finding.severity") (last_over_time({"rmguard.findings"}[1d]))
```

`sum by` over `last_over_time` is right for these gauges: within one machine the points
of one scan are disjoint label sets, so summing them is a count of that scan's
findings, and summing across `instance` adds machines.

### Consuming the metrics

[docs/OPERATIONS.md](OPERATIONS.md#fleet) has a collector and Prometheus configuration
for these gauges (scrape with `honor_labels: true`, so `instance` stays the machine's
id), a Grafana dashboard built on the queries above
([`contrib/grafana/rmguard-posture.json`](../contrib/grafana/rmguard-posture.json)) and
two alert rules, a new critical finding on any machine and a threat-catalog version skew
across the fleet
([`contrib/prometheus/rmguard-alerts.yaml`](../contrib/prometheus/rmguard-alerts.yaml),
with a `promtool test rules` file). The collector's `prometheus` exporter puts resource
attributes on `target_info`, so `rmguard.catalog.version` is queried there as
`target_info{rmguard_catalog_version=...}`.

## What is never exported, and why

The collector may be remote, shared, or run by someone else, and OTLP backends keep
data for a long time. A posture scan is a map of where the credentials on a machine are,
so none of that map goes out:

- file paths, including diagnostics `root` and your home directory;
- MCP server names, commands, arguments and environment;
- names of programs rmguard ran, except a basename from the fixed
  `rmguard.exec.program` table (see above); everything else is `other`;
- package names and versions, registry URLs and response bodies;
- error message text from servers, ureq or the OS (only the fixed categories above);
- host names, user names, file contents, secret values (and no machine id derived from
  any of them: `service.instance.id` is exported only when you supply it, as you typed
  it);
- finding titles, evidence and locations (only the closed severity and category
  labels, and counts);
- `--trace` / `RMGUARD_TRACE` lines. They are per-path and are fine on your own terminal,
  but they are not shipped. Per-scanner counts already answer the performance question.

Some exported **integers** are chosen by programs rmguard runs, not by rmguard:
`process.exit.code` on `exec.*` spans is whatever the child returned (a binary planted on
`PATH` under a known tool name controls about 8 bits per run), and
`rmguard.mcp.tools` / `rmguard.mcp.resources` are whatever a probed MCP server listed
(`--probe-mcp` only). They are not secrets, and a program able to choose them already
runs with your privileges and network access, so this opens no new channel; it does
mean those numbers are untrusted input to your backend, not facts about rmguard.

This is enforced by construction rather than by review. (The one exception is the
operator's `--otel-instance` text, which `otel::init` puts on the resource as
`service.instance.id`; it is command-line input, never scan output, and is the only
runtime text that reaches the export.) In `src/otel/mod.rs`, attribute
keys are a closed enum. Attribute values can be built only from `&'static str`,
integers and booleans; there is no constructor that takes runtime text, so nothing a
scan read can be passed in (the one function that looks at runtime text,
`otel::exec_program`, returns an entry of its own fixed table or `other`, never its
input) (a `compile_fail` doc test in that module checks that a
`String` label does not compile). Span names are static, or a static prefix and a static
label (`scanner.<label>`, `exec.<site>`) that `otel::span_with` joins itself; it takes
two `&'static str` and nothing else, and a second `compile_fail` doc test checks that a
runtime path cannot be passed. CI runs these doc tests (`cargo test --doc`; `cargo test
--all-targets` alone skips them). The one hole the type system leaves is deliberately
leaking a `String` into a `&'static str` (`String::leak`, `Box::leak`); nothing in
rmguard does, and one near an `Attr` or a span name is a review finding. No context is propagated: there is no
`traceparent` on the registry request, nothing is injected into spawned processes, and
`OTEL_*` variables are removed from them.
`tests/otel_export.rs::otel_never_exports_secrets_paths_or_names` plants canaries in a
server name (with an ANSI escape), a command, an argument, an env value, a `.env` file
and an Aider config. It then asserts that none of them, and not the HOME path, appears
anywhere in the raw OTLP bodies.

## Looking at your own trace

`scripts/otel-tree.py` is a self-contained receiver for reading one scan's trace
without a collector. It needs only `uv` (its dependencies, `opentelemetry-proto` and
`protobuf`, are declared inline):

```bash
cargo build --release
uv run scripts/otel-tree.py --port 0 -- target/release/rmguard --otel --format json -o /dev/null
# or listen, and run rmguard yourself:
uv run scripts/otel-tree.py --port 4318 &
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 rmguard --otel
```

It listens on 127.0.0.1 only, waits for the `rmguard.scan` span, and prints the span
tree with durations and attributes (runs of identical leaf spans, such as one walk per
project, are folded into one `xN` line), totals by span name, exec time by program and
site, and for each phase and scanner the time no child span covers: the part of the
scan the trace does not yet explain, then every metric's data points with their
attributes (the posture gauges first; histograms as count and sum). A `resource:` line
comes first, with `service.instance.id` when `--otel-instance` gave one (the script
removes every `OTEL_*` variable from the command it runs, so pass the flag, not
`OTEL_RESOURCE_ATTRIBUTES`). `--save FILE` writes the decoded resource, spans and metric
points as JSON.

## Failure behavior

- Nothing from telemetry is written to stdout. The SDK's internal logging is compiled
  out (`internal-logs` off), so it cannot print either.
- stderr gets one `info:` line at start (two when no machine identity was given; see
  [Machine identity](#machine-identity)), a start-up `warning:` line per unsupported
  setting (`OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_*_EXPORTER`), and at most one
  `warning: OpenTelemetry export ...` line at the end. The end-of-run warning names a
  category (`could not connect`, `could not resolve host`, `timeout`, `tls`, `HTTP 503`,
  `other`) and never the endpoint or headers, because those can carry credentials. It
  says "telemetry only": the report and the exit code do not depend on it (on an
  operational error the exit code is 1 for that error, not for telemetry).
- Each export request times out after 1 s, with retries off. Trace and metric shutdown
  run side by side under a 2 s overall deadline (the span processor's own cap is 1.5 s,
  so a request timeout is reported as `timeout`). Whatever is still pending at the
  deadline is abandoned. The report is written and flushed to stdout (or written to
  `-o`) before shutdown starts, so a consumer that reads or kills rmguard during the
  shutdown already has the whole document
  (`tests/otel_export.rs::report_is_flushed_before_otel_shutdown`); the exit code
  (including `--fail-on`'s 2) is unchanged. Measured costs: a refused port adds a few
  ms (about 2.5 ms, including start-up of the exporter threads). A collector that
  accepts connections but never answers adds about 1.0 s, and up to 1.5 s (the span
  processor's cap) when a scheduled export (every 5 s, so in any scan longer than that)
  is still in flight at shutdown; 2 s is the hard cap either way.
- When export is off, every instrumentation point is one relaxed atomic load and a
  branch. No closure runs, nothing is allocated, and no thread or socket exists. (The
  `gitconfig` and `transcripts` walks also bump a few local integer counters per
  directory entry either way; the skills walk's counters are behind the same check.) (The
  one exception is the child-environment scrub, which is on whether or not export is:
  the names of any `OTEL_*` variables are collected once per run, on the first spawn,
  and reused. std has no names-only iterator, so that single pass copies each
  environment value into a temporary that is dropped unused.) The
  call sites that time something for telemetry (the scan, each MCP probe, each registry
  lookup) read `Instant::now()` only when export is on. The per-scanner diagnostics
  table reads the clock either way; it is part of the report.

## Known limits

- The span queue holds 8192 spans. Past that, spans are dropped, for example on a
  machine with tens of thousands of `.env` candidates, each with a `git ls-files` check.
  Scanner spans and metrics are unaffected in practice, because they are few.
- An operational error that exits 1 (an unreadable `--diff` baseline, an unwritable
  `-o`) flushes what has ended, but the root span is still open and is lost.
- Child processes inherit your environment **minus every `OTEL_*` variable** (see
  above). Everything else is inherited as before; in particular a probed MCP server
  still sees the rest of your shell environment, as it would when your agent host
  starts it. A child that is itself instrumented may still find a collector through its
  own configuration files.
- "rmguard opens no socket" is about rmguard's own process. Programs it runs in a default
  scan are their own programs: `ollama --version`, for example, connects to its local
  server on 127.0.0.1:11434. That predates `--otel` and is unrelated to it.
- Spans opened on a thread nobody handed the context to would start a new trace. The
  scan-phase workers are handed it (`otel::current_context`, `ParentContext::attach`);
  the reader and waiter threads of a spawned child open no span.
- Span timestamps come from one wall-clock reading taken when export starts, plus
  monotonic time since. A clock step during the run (NTP, a manual change) cannot put
  a child span outside its parent or change any duration; the price is that every span
  is off from the wall clock by however far it was stepped during the run.

## Verified against

The OpenTelemetry Collector Contrib distribution, image
`docker.io/otel/opentelemetry-collector-contrib:latest` = 0.163.2 (image id
`a64fa52ad3b5`, digest `sha256:989669581ee1f89184f3fd9dd5adfc6615ed6c9692c026aaea89e07a20dfb177`,
built 2026-10-21; from `podman image inspect`), run under podman on 2026-10-24 with its
OTLP/HTTP receiver behind the `bearertokenauth` extension, published on a 127.0.0.1 port
only:

```yaml
extensions:
  bearertokenauth:
    token: "<random 48 hex chars>"
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
        auth:
          authenticator: bearertokenauth
exporters:
  debug:
    verbosity: detailed
service:
  extensions: [bearertokenauth]
  telemetry:
    logs:
      level: debug
  pipelines:
    traces:   { receivers: [otlp], exporters: [debug] }
    metrics:  { receivers: [otlp], exporters: [debug] }
```

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:<port> \
OTEL_EXPORTER_OTLP_HEADERS="Authorization=Bearer <token>" \
  rmguard --otel --format json -o scan.json
```

- **Right token: accepted.** Exit 0, no warning line. The collector's debug exporter
  logged one traces batch of 217 spans and one metrics batch of 10 metrics and 183 data
  points, including `rmguard.findings` (8 points on that machine), `rmguard.inventory`
  (32), `rmguard.scan.truncated_scanners` and the root span's
  `rmguard.findings.critical/high/medium/low` ints.
- **Wrong token: rejected.** The collector answered 401 (confirmed with `curl` against
  the same receiver: wrong and missing tokens both get `HTTP 401`) and logged nothing
  for the rejected requests, not even at debug level: the 401 is visible on the client
  side only. rmguard printed its one line,
  `warning: OpenTelemetry export failed (HTTP 401); telemetry only, the report and exit code are not affected by this`,
  exited 0, and wrote a report identical (bar timestamps and durations) to a run
  without `--otel`; with `--fail-on high` it exited 2, the same as without `--otel`.
- **Nothing identifying arrived.** The accepted batch's log holds no home directory,
  user name, host name, `/datar` path, `CLAUDE.md` or key file name; the only `.ssh` /
  `.env` substrings are the fixed span names `exec.ssh_keygen`, `scanner.ssh` and
  `scanner.envfiles`, and every string value in it is a closed label or a
  version (`service.version`, the SDK's).

### Gauges, machine identity and catalog version (2026-10-24)

The same image (otelcol-contrib 0.163.2, image id `a64fa52ad3b5`), run under podman with
a plain OTLP/HTTP receiver (no auth), the `debug` exporter at `verbosity: detailed`, and
two `prometheus` exporters on the metrics pipeline, one with the default translation and
one with `translation_strategy: NoUTF8EscapingWithSuffixes`, every port published on
127.0.0.1 only. One real scan of the development machine:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:<port> \
  rmguard --otel --otel-instance test-box-1 --format json -o scan.json
```

- Exit 0, no warning, and no machine-identity `info:` line (an id was given). The debug
  exporter logged one traces batch of 217 spans and one metrics batch of 10 metrics and
  183 data points.
- `rmguard.findings`, `rmguard.inventory` and `rmguard.scan.truncated_scanners` arrived
  as `DataType: Gauge`; `rmguard.scanner.files_read` as `Sum` and `rmguard.scan.duration`
  as `Histogram`, as before.
- Both resources (traces and metrics) carried `service.instance.id: Str(test-box-1)` and
  `rmguard.catalog.version: Str(2026-10-22)`; the root span carried
  `rmguard.otel.instance_id_set: Bool(true)` and `rmguard.catalog.version`.
- The default Prometheus exporter served `# TYPE rmguard_findings gauge`,
  `rmguard_inventory gauge`, `rmguard_scan_truncated_scanners gauge` and
  `rmguard_scanner_files_read_total counter`, with `instance="test-box-1"` and
  `job="rmguard"` on every series. The UTF-8 exporter served the same underscore names
  to a plain `curl`, and `"rmguard.findings"`, `"rmguard.inventory"`,
  `"rmguard.scan.truncated_scanners"` and `"rmguard.scanner.files_read_total"` (with
  `"rmguard.finding.severity"` labels) to a scrape sending
  `Accept: text/plain;version=1.0.0;escaping=allow-utf-8`.
- Nothing identifying arrived: with the collector's own log lines removed, the log holds
  no host name, user name, home directory, `/datar` or `/home` path, `CLAUDE.md`, `.claude`
  or key file name; the `.ssh` / `.env` substrings are the fixed span names
  `exec.ssh_keygen`, `scanner.ssh` and `scanner.envfiles`, and every string value is a
  closed label, a version, the catalog version or `test-box-1`.

## Implementation and credits

- `opentelemetry`, `opentelemetry_sdk` and `opentelemetry-otlp` 0.33 (Apache-2.0), all with
  `default-features = false`. That leaves out tokio, hyper, tonic, reqwest and `tracing`.
  The SDK's batch span processor and periodic metric reader run on their own std
  threads, and only after `--otel`. Builder usage follows the opentelemetry-rust 0.33
  docs for `BatchSpanProcessor`, `BatchConfigBuilder` and `PeriodicReader`.
- The HTTP transport is a small `opentelemetry_http::HttpClient` over the ureq 3 + rustls
  agent rmguard already ships (pattern from the opentelemetry-http crate docs' custom
  client example). Status codes come back as responses, bodies are capped at 64 KiB,
  redirects are off, and the user agent is `rmguard/<version>` (set on each request:
  opentelemetry-otlp's own `OTel-OTLP-Exporter-Rust/<version>` header would otherwise
  override the agent's default).
- `opentelemetry_sdk` 0.33.1's `SdkMeterProvider::shutdown_with_timeout` ignores its
  argument (a hardcoded 5 s), which is why the two shutdowns run on separate threads
  under rmguard's own deadline.
- The feature is `otel`, on by default. `cargo build --no-default-features` builds the
  same CLI with no OpenTelemetry code; `--otel` then prints one warning. The feature adds
  about 1.6 MB (21%) to the release binary (7.66 MB without, 9.27 MB with, measured on
  linux x86_64) and no measurable start-up time; packagers who do not want it can build
  without it.
