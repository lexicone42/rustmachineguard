# OpenTelemetry export

rmguard can export the timing of a scan as OpenTelemetry traces and metrics, so you can
see where a slow scan spends its time, or watch scanner health across a fleet in the
observability stack you already run. Export is off by default. It sends **labels,
counts and durations only**, and never anything the scan found.

## Turning it on

| Condition | Export? |
|---|---|
| no `--otel` (whatever `OTEL_*` variables are set) | **no**: no `OTEL_*` value is used, nothing is built, rmguard opens no socket |
| `--otel` | yes |
| `--otel` + `OTEL_SDK_DISABLED=true` (any case) | no (`info:` line) |
| `--otel` + `OTEL_TRACES_EXPORTER=none` | metrics only |
| `--otel` + `OTEL_METRICS_EXPORTER=none` | traces only |
| `--otel` + both `=none` | no (`info:` line) |
| `--otel` + `--report <DIR>` (fleet mode) | no (`warning:` line) |
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
  your choice and your data.
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
│   │   ├── exec.version_probe                 (`<tool> --version`)
│   │   ├── exec.verify_binary
│   │   └── exec.process_list                  (`ps -A -o ucomm=`, once per scan)
│   └── scanner.node
│       ├── version.read                       (npm, yarn, pnpm: version from package.json)
│       └── exec.version_probe                 (node, bun; a JS tool whose package.json did not answer)
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

`gitconfig` runs in two passes so the trace can tell its two costs apart: every
project's own `.git/config` (`gitconfig.repos`), then the walk for git directories
buried inside each project (`gitconfig.nested_walk`). The findings are joined back in
the old per-project order, so the report is unchanged. The projects are walked side by
side on up to `--jobs` threads, each with its own directory budget and counts; the
span's counts are the per-project counts summed in project order, and
`rmguard.walk.budget_exhausted` is true when any project's walk stopped at its budget.
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
| `rmguard.scanners_run` | root | count of non-skipped diagnostics rows |
| `rmguard.jobs` | root | threads a scan phase may use (`--jobs`, or the default) |
| `rmguard.phase` | phase.* | the phase name |
| `rmguard.root.index` | phase.home_pass | 0 = your home, 1.. = `--search-dirs` position |
| `rmguard.root.kind` | phase.home_pass | `home` \| `search_dir` |
| `rmguard.scanner` | scanner.*, metrics | scanner label (`mcp`, `packages`, ...) |
| `rmguard.duration_ms` | scanner.* | as in diagnostics |
| `rmguard.files.read`, `rmguard.files.missing`, `rmguard.items` | scanner.* | as in diagnostics |
| `rmguard.scanner.truncated` | scanner.* | bool: the scanner stopped at a walk budget (the gitconfig nested walk, the skills bundle walk); `truncated` in diagnostics |
| `rmguard.exec.site` | exec.*, metric | `version_probe` \| `verify_binary` \| `git_tracked` \| `output_with_timeout` \| `process_list` \| `ssh_keygen` |
| `rmguard.exec.program` | exec.*, version.read, metric | the program's basename if it is one rmguard itself runs (`otel::EXEC_PROGRAMS`: `git`, `ps`, `ssh-keygen`, `sw_vers`, `defaults`, `node`, `npm`, `yarn`, `pnpm`, `bun`, the AI CLIs, model servers, container runtimes, notebook servers and IDE launchers the scanners probe), else `other` |
| `rmguard.exec.outcome` | exec.*, metric | `ok` \| `nonzero` \| `spawn_failed` \| `timeout` \| `wait_failed` \| `unknown` |
| `process.exit.code` | exec.* | exit code, when the child exited normally |
| `rmguard.skills.projects` | scanner.skills | number of project directories walked (no path, no index) |
| `rmguard.walk.kind` | skills.walk | `commands` \| `agents` \| `hooks` \| `codex` \| `skills` \| `plugins` |
| `rmguard.walk.scope` | skills.walk | `global` \| `project` |
| `rmguard.walk.root_link` | skills.walk | `plain` (no symlink to the root, or no root) \| `followed` (a linked root that is walked) \| `refused` (a linked root that is inventoried unread) |
| `rmguard.walk.entries` | skills.walk, gitconfig.nested_walk, transcripts.store | directory entries visited |
| `rmguard.walk.files` | skills.walk, transcripts.store | skills: files read through the shared reader; transcripts: regular files counted (never opened) |
| `rmguard.walk.bytes_hashed` | skills.walk | bytes of file content hashed for the inventory's sha256 |
| `rmguard.walk.hooks` | skills.walk | frontmatter hooks found |
| `rmguard.walk.budget_exhausted` | skills.walk, gitconfig.nested_walk | bool: a file, entry or directory budget stopped the walk |
| `rmguard.items` | skills.walk | inventory entries the walk produced (before the scanner's dedupe) |
| `rmguard.walk.dirs` | gitconfig.nested_walk | directories listed, summed over projects |
| `rmguard.walk.pruned` | gitconfig.nested_walk | directories not descended into as generated content, summed over projects: skipped by name (`node_modules`, ...) or holding a `CACHEDIR.TAG` ([Cache Directory Tagging Specification](https://bford.info/cachedir/)) or `pyvenv.cfg`. HOME registered as a project is not walked at all and adds nothing |
| `rmguard.version.source` | version.read | `package_json` (the version came from the tool's own package.json) \| `spawn` (it did not; `<tool> --version` is run) |
| `rmguard.walk.bytes` | transcripts.store | summed size of the counted files |
| `rmguard.repos` | gitconfig.repos, gitconfig.nested_walk | projects whose own config was checked; nested git directories found |
| `rmguard.transcripts.framework` | transcripts.store | `claude-code` \| `codex` \| `gemini-cli` |
| `rmguard.transcripts.kind` | transcripts.store | `conversation transcripts` \| `command history` \| `todo state` \| `sessions` \| `session state` |
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
and the SDK's `telemetry.sdk.*`. There is no `host.name` and no user.

## Metrics

Exported once, as a cumulative snapshot when the scan ends.

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

That is nine names, but a plain scan exports seven: `rmguard.mcp.probe.duration` appears
only with `--probe-mcp` (and at least one stdio server probed), and
`rmguard.registry.lookup.duration` only with `--verify-registry` (and at least one
lookup). An instrument with no recorded value is not exported.

Histogram buckets (s): 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30.

Counts are posture metadata. `rmguard.scanner.items` labelled `aicreds` or `ssh`, and
`rmguard.exposure_findings` on the root span, tell a collector how many credentials or
exposure findings a machine has, never which ones or where. Choose the collector with
that in mind.

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
- host names, user names, file contents, secret values;
- `--trace` / `RMGUARD_TRACE` lines. They are per-path and are fine on your own terminal,
  but they are not shipped. Per-scanner counts already answer the performance question.

Some exported **integers** are chosen by programs rmguard runs, not by rmguard:
`process.exit.code` on `exec.*` spans is whatever the child returned (a binary planted on
`PATH` under a known tool name controls about 8 bits per run), and
`rmguard.mcp.tools` / `rmguard.mcp.resources` are whatever a probed MCP server listed
(`--probe-mcp` only). They are not secrets, and a program able to choose them already
runs with your privileges and network access, so this opens no new channel; it does
mean those numbers are untrusted input to your backend, not facts about rmguard.

This is enforced by construction rather than by review. In `src/otel/mod.rs`, attribute
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
scan the trace does not yet explain. `--save FILE` writes the decoded spans as JSON.

## Failure behavior

- Nothing from telemetry is written to stdout. The SDK's internal logging is compiled
  out (`internal-logs` off), so it cannot print either.
- stderr gets one `info:` line at start, a start-up `warning:` line per unsupported
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
