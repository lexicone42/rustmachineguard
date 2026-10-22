# OpenTelemetry export

rmguard can export the timing of a scan as OpenTelemetry traces and metrics, so you can
see where a slow scan spends its time, or watch scanner health across a fleet in the
observability stack you already run. Export is off by default. It sends **labels,
counts and durations only**, and never anything the scan found.

## Turning it on

| Condition | Export? |
|---|---|
| no `--otel` (whatever `OTEL_*` variables are set) | **no**: no `OTEL_*` variable is read, nothing is built, no socket is opened |
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
- `OTEL_EXPORTER_OTLP_HEADERS` (e.g. an API key for a hosted backend) is honored.
- `OTEL_SERVICE_NAME` and `OTEL_RESOURCE_ATTRIBUTES` are honored. What you add there is
  your choice and your data.
- `HTTPS_PROXY`/`ALL_PROXY` are honored the same way as for registry lookups.
- The protocol is always http/protobuf. A different `OTEL_EXPORTER_OTLP_PROTOCOL` gets
  one `warning:` line and is ignored. Timeouts are fixed in code (below), and env values
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
cannot be reached you also get exactly one `warning: OpenTelemetry export ...` line. The
report on stdout or in `-o` is the same either way.

## Span tree

```
rmguard.scan                                   (root; one trace per run)
├── phase.device_info
├── phase.global_scanners
│   ├── scanner.ai
│   │   ├── exec.version_probe                 (`<tool> --version`)
│   │   └── exec.verify_binary
│   └── scanner.node ...
├── phase.home_pass                            (rmguard.root.index=0, root.kind=home)
│   ├── scanner.mcp
│   ├── scanner.envfiles
│   │   └── exec.git_tracked                   (`git ls-files --error-unmatch`)
│   ├── scanner.ssh
│   │   └── exec.ssh_keygen
│   └── scanner.gitconfig
│       └── exec.output_with_timeout           (`git config --list`, ...)
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

## Attributes

| Key | On | Value |
|---|---|---|
| `rmguard.format` | root | `terminal` \| `json` \| `html` \| `sbom` \| `blueprint` \| `compliance` |
| `rmguard.skip.count` | root | number of valid `--skip` labels |
| `rmguard.search_dirs.count` | root | number of `--search-dirs` entries |
| `rmguard.probe_mcp`, `rmguard.verify_registry`, `rmguard.diff` | root | bool |
| `rmguard.exposure_findings` | root | count |
| `rmguard.scanners_run` | root | count of non-skipped diagnostics rows |
| `rmguard.phase` | phase.* | the phase name |
| `rmguard.root.index` | phase.home_pass | 0 = your home, 1.. = `--search-dirs` position |
| `rmguard.root.kind` | phase.home_pass | `home` \| `search_dir` |
| `rmguard.scanner` | scanner.*, metrics | scanner label (`mcp`, `packages`, ...) |
| `rmguard.duration_ms` | scanner.* | as in diagnostics |
| `rmguard.files.read`, `rmguard.files.missing`, `rmguard.items` | scanner.* | as in diagnostics |
| `rmguard.exec.site` | exec.*, metric | `version_probe` \| `verify_binary` \| `git_tracked` \| `output_with_timeout` \| `pgrep` \| `ssh_keygen` |
| `process.executable.name` | exec.* | program **basename** only (`git`), directory dropped |
| `rmguard.exec.outcome` | exec.*, metric | `ok` \| `nonzero` \| `spawn_failed` \| `timeout` \| `wait_failed` \| `unknown` |
| `process.exit.code` | exec.* | exit code, when the child exited normally |
| `rmguard.mcp.server_index` | mcp.probe | position among probed servers (not the name) |
| `rmguard.mcp.outcome` | mcp.probe, metric | `ok` \| `empty_command` \| `spawn_failed` \| `timeout` \| `closed` \| `error` |
| `rmguard.mcp.tools`, `rmguard.mcp.resources` | mcp.probe | counts |
| `rmguard.registry.index` | registry.lookup | position among lookups (not the package) |
| `rmguard.registry.verdict` | registry.lookup, metric | `registered` \| `possible_typosquat` \| `unregistered` \| `no_package_identity` \| `lookup_failed` |
| `http.request.method`, `server.address` | registry.lookup | `GET`, `registry.modelcontextprotocol.io` |
| `error.type` | registry.lookup | `status` \| `timeout` \| `connect` \| `tls` \| `body` \| `parse` \| `other` |
| `http.response.status_code` | registry.lookup | the HTTP status, when the registry answered with an error |

Failed spans carry `Status::Error` with a fixed category as the description, such as
`spawn_failed`, `timeout` or `lookup_failed`. A non-zero exit is not an error: for
`git ls-files` it means "not tracked".

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
| `rmguard.exec.duration` | histogram | s | `rmguard.exec.site`, `rmguard.exec.outcome` |
| `rmguard.mcp.probe.duration` | histogram | s | `rmguard.mcp.outcome` |
| `rmguard.registry.lookup.duration` | histogram | s | `rmguard.registry.verdict` |

Histogram buckets (s): 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30.

## What is never exported, and why

The collector may be remote, shared, or run by someone else, and OTLP backends keep
data for a long time. A posture scan is a map of where the credentials on a machine are,
so none of that map goes out:

- file paths, including diagnostics `root` and your home directory;
- MCP server names, commands, arguments and environment;
- package names and versions, registry URLs and response bodies;
- error message text from servers, ureq or the OS (only the fixed categories above);
- host names, user names, file contents, secret values;
- `--trace` / `RMGUARD_TRACE` lines. They are per-path and are fine on your own terminal,
  but they are not shipped. Per-scanner counts already answer the performance question.

This is enforced by construction rather than by review. In `src/otel/mod.rs`, attribute
keys are a closed enum. Attribute values can be built only from compile-time strings,
integers and booleans. The two exceptions, the scanner label and the program basename,
go through the report's redaction and display sanitizers and a credential-prefix
filter, and are capped at 64 characters. Span names are static or `scanner.<label>` /
`exec.<site>`. No context is propagated: there is no `traceparent` on the registry
request, and nothing is injected into spawned processes.
`tests/otel_export.rs::otel_never_exports_secrets_paths_or_names` plants canaries in a
server name (with an ANSI escape), a command, an argument, an env value, a `.env` file
and an Aider config. It then asserts that none of them, and not the HOME path, appears
anywhere in the raw OTLP bodies.

## Failure behavior

- Nothing from telemetry is written to stdout. The SDK's internal logging is compiled
  out (`internal-logs` off), so it cannot print either.
- stderr gets at most one `info:` line at start and at most one `warning:` line per run.
  The warning names a category (`could not connect`, `timeout`, `tls`, `HTTP 503`, ...)
  and never the endpoint or headers, because those can carry credentials.
- Each export request times out after 1 s, with retries off. Trace and metric shutdown
  run side by side under a 2 s overall deadline. Whatever is still pending at the
  deadline is abandoned. The report has already been written by then, and the exit code
  (including `--fail-on`'s 2) is unchanged. Measured costs: a refused port adds under
  1 ms, and a collector that accepts connections but never answers adds about 1.0 s.
- When export is off, every instrumentation point is one relaxed atomic load and a
  branch. No closure runs, no clock is read, nothing is allocated, and no thread or
  socket exists.

## Known limits

- The span queue holds 8192 spans. Past that, spans are dropped, for example on a
  machine with tens of thousands of `.env` candidates, each with a `git ls-files` check.
  Scanner spans and metrics are unaffected in practice, because they are few.
- An operational error that exits 1 (an unreadable `--diff` baseline, an unwritable
  `-o`) flushes what has ended, but the root span is still open and is lost.
- Child processes inherit your environment, `OTEL_*` included. A probed MCP server or a
  tool run for `--version` that is itself instrumented may send its own telemetry to
  your collector, independent of `--otel`. rmguard does not add or remove `OTEL_*`
  variables for children.
- Spans opened on another thread would start a new trace. All instrumented work runs on
  the main thread today.

## Implementation and credits

- `opentelemetry`, `opentelemetry_sdk` and `opentelemetry-otlp` 0.33 (Apache-2.0), all with
  `default-features = false`. That leaves out tokio, hyper, tonic, reqwest and `tracing`.
  The SDK's batch span processor and periodic metric reader run on their own std
  threads, and only after `--otel`. Builder usage follows the opentelemetry-rust 0.33
  docs for `BatchSpanProcessor`, `BatchConfigBuilder` and `PeriodicReader`.
- The HTTP transport is a small `opentelemetry_http::HttpClient` over the ureq 3 + rustls
  agent rmguard already ships (pattern from the opentelemetry-http crate docs' custom
  client example). Status codes come back as responses, bodies are capped at 64 KiB,
  redirects are off, and the user agent is `rmguard/<version>`.
- `opentelemetry_sdk` 0.33.1's `SdkMeterProvider::shutdown_with_timeout` ignores its
  argument (a hardcoded 5 s), which is why the two shutdowns run on separate threads
  under rmguard's own deadline.
- The feature is `otel`, on by default. `cargo build --no-default-features` builds the
  same CLI with no OpenTelemetry code; `--otel` then prints one warning.
