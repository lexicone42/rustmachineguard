# Operations: rmguard on a schedule

How to run rmguard regularly on one machine or a small fleet, and act on what changes:
a baseline and a daily diff, a severity gate, local notifications, OpenTelemetry export
to a collector, a Grafana dashboard and two Prometheus alert rules.

Everything here uses the CLI as it ships; the helper scripts are POSIX `sh`. Every
command below was run against a release build on Linux x86_64 on 2026-10-25, with outputs
pasted as they came, home directory shortened to `~`: the one-machine and notification
commands against `rmguard 0.1.0 (threat catalog 2026-10-25.3)`, after the exit-code
change below; the fleet commands against the 2026-10-25.2 build before it. Where
something could not be run here, it says so
([What was and was not verified](#what-was-and-was-not-verified)).

- [One machine](#one-machine)
  - [Baseline, gate, diff](#baseline-gate-diff)
  - [Exit codes](#exit-codes)
  - [When to rotate the baseline](#when-to-rotate-the-baseline)
  - [Caveats](#caveats)
- [Scheduling](#scheduling): [systemd (Linux)](#systemd-linux), [launchd (macOS)](#launchd-macos), [cron](#cron)
- [Notifications](#notifications)
- [Fleet](#fleet): [OpenTelemetry to a collector](#opentelemetry-to-a-collector), [JSON reports and `--report`](#json-reports-and---report)
- [Grafana dashboard](#grafana-dashboard)
- [Alert rules](#alert-rules)
- [What was and was not verified](#what-was-and-was-not-verified)

## One machine

### Baseline, gate, diff

State lives in `${XDG_STATE_HOME:-~/.local/state}/rmguard/`. A scan report holds no
secret values, but it is a map of where the machine's credentials and agent
configuration are, so keep the directory owner-only.

**First run: write the baseline.** Run from your home directory (see
[the working-directory rule](#caveats)):

```console
$ STATE=${XDG_STATE_HOME:-$HOME/.local/state}/rmguard; mkdir -p "$STATE" && chmod 700 "$STATE"; cd ~ && rmguard --format json -o "$STATE/baseline.json"
info: loaded built-in threat catalog 2026-10-25.3 (307 entries)
[exit 0]
```

**Every later run: one invocation** writes the current JSON, diffs against the baseline
and gates on severity. With `--diff`, stdout is the diff; `-o` receives the scan, in
`--format`; `--fail-on` is evaluated on that scan exactly as in a run without `--diff`:

```console
$ cd ~ && rmguard --format json -o ~/.local/state/rmguard/latest.json --diff ~/.local/state/rmguard/baseline.json --fail-on high
info: loaded built-in threat catalog 2026-10-25.3 (307 entries)
=== Scan Diff Report ===

--- MCP Servers ---
  + fetcher (transport=stdio, package_name=mcp-server-fetch, package_ecosystem=pypi, unpinned=no version)
  ~ notes|Claude Code (home)
      package_version: 0.6.0 -> 0.6.2

--- Summary ---
  MCP servers: 1 -> 2 (+1)

fail-on: 1 finding(s) at or above high (most severe: high) — exiting 3
[exit 3]
```

(That is a scratch home in which, after the baseline, one MCP server was added, another
moved from `server-memory@0.6.0` to `@0.6.2`, and `~/.claude.json` was made
world-readable, which is the one high finding. With nothing changed the diff prints
`No changes detected between baseline and current scan.`
[`scripts/rmguard-notify.sh`](../scripts/rmguard-notify.sh) runs this and decides
whether to tell you.)

This changed on 2026-10-25: before it, a `--diff` run wrote the diff text into `-o`,
ignored `--format`, never evaluated `--fail-on` (exit 0 on a machine with high
findings), and the gate exited 2.

**What `--diff` compares.** Inventory, not findings: MCP servers (by name, comparing
transport, package identity and version, URL, inline secret env key names and whether
the config is git-tracked), AI tools, extensions, agent settings and hooks, skills,
probe results and summary counts. A finding that comes from something the diff does not
track does not appear in it: making `~/.claude.json` world-readable above raised a high
finding, which the gate reported, and added no diff line. An MCP server's `command` and
`args` are not compared beyond the package identity derived from them. Run the gate and
the diff together; neither covers the other.

### Exit codes

| Invocation | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| `rmguard ... --fail-on <sev>` (with or without `--diff`) | no finding at or above `<sev>` | the scan could not run or write (missing HOME, unreadable or non-JSON `--diff` baseline, write error) | usage error | at least one finding at or above `<sev>`; the report (and diff) was still written, and stderr has the `fail-on:` line |
| `rmguard --diff <baseline>` without `--fail-on` | diff written, **whether or not anything changed** | baseline unreadable or not JSON, write error | usage error | never |
| `rmguard --report <dir>` | fleet HTML written | no valid scan in `<dir>`, write error | usage error | never |
| `scripts/rmguard-notify.sh` | nothing to report | error (no baseline, scan failed, rmguard usage error, another run holds the lock) | never | reported: gate tripped or the diff has entries |
| `scripts/rmguard-baseline.sh` | baseline written or rotated | error, nothing changed | never | a baseline exists and `--force` was not given; the drift was printed |

**A command-line usage error exits 2** (an unknown flag, `--fail-on severe`): the
argument parser's convention; it prints usage instead of a report. The findings gate
exits 3, so a scheduled job with a typo does not look like a machine with findings (until
2026-10-25 both were 2).

A diff's first line can be `threat catalog: <old> -> <new> (findings may change without
any change on this machine)`: the binary's built-in catalog changed since the baseline.
It is not an entry and does not count as drift.

### When to rotate the baseline

The baseline is "the state I have reviewed and accept". Rotate it **after** you have read
a diff and decided every entry in it is expected (you installed that server, you upgraded
that extension), and not before: rotating without reading turns a rug-pull into the new
normal. Also rotate after upgrading rmguard if the first diff lists surfaces the new
version inventories for the first time (COVERAGE.md's
[Temporal analysis](COVERAGE.md#temporal--cross-server-analysis) section describes this).

[`scripts/rmguard-baseline.sh`](../scripts/rmguard-baseline.sh) does this safely:
without `--force` it prints the drift and changes nothing; with `--force` it keeps the
previous baseline as `baseline.<UTC timestamp>.json` and replaces it. `--from <file>`
promotes a scan you already have (the `latest.json` whose diff you just read) instead of
the one the printed drift came from, so what becomes the baseline is exactly what you
reviewed (without `--from`, the new baseline is the scan the printed drift was computed
from: one scan per run); the file is
checked with rmguard's own report loader first (a file that is not an rmguard JSON scan
is refused).

```console
$ rmguard-baseline.sh
info: loaded built-in threat catalog 2026-10-25.3 (307 entries)
=== Scan Diff Report ===

--- MCP Servers ---
  + fetcher (transport=stdio, package_name=mcp-server-fetch, package_ecosystem=pypi, unpinned=no version)
  ~ notes|Claude Code (home)
      package_version: 0.6.0 -> 0.6.2

--- Summary ---
  MCP servers: 1 -> 2 (+1)

drift since baseline: 1 added, 0 removed, 1 changed
baseline unchanged: review the drift above, then re-run with --force to rotate
[exit 3]

$ rmguard-baseline.sh --force --from ~/.local/state/rmguard/latest.json
info: loaded built-in threat catalog 2026-10-25.3 (307 entries)
=== Scan Diff Report ===
...
drift since baseline: 1 added, 0 removed, 1 changed
previous baseline kept: ~/.local/state/rmguard/baseline.20261025T080113Z.json
baseline rotated: ~/.local/state/rmguard/baseline.json
[exit 0]
```

The printed drift comes from a fresh scan, so with `--from` it can differ from
`latest.json` if something changed between the two; read `diff.txt` from the run that
produced that `latest.json` if it matters. The first run (no baseline yet) writes one and
exits 0. Old timestamped baselines are never deleted by the script.

### Caveats

- **The working directory is a project.** The directory rmguard runs in is scanned as a
  project of the primary home, unless it is a scanned home or an ancestor of one. Run
  scheduled scans from `$HOME` (the scripts `cd` there; the unit files set it), and make
  the baseline from the same place, or the diff reports the difference between two
  directories.
- **PATH is part of the scan.** rmguard finds AI tools on `PATH`, and schedulers start
  jobs with a short one (cron: `/usr/bin:/bin`). On the development machine, a scan with
  `PATH=/usr/bin:/bin` against a baseline made from a login shell reported
  `- Mistral Vibe ACP server` and `~ Mistral Vibe  version: 2.5.0 -> null`, a tool
  installed in `~/.local/bin`; the same scan with the shell's PATH reported no changes.
  Set the scheduled job's PATH to the one the baseline was made with (the unit files and
  the cron line below do).
- **Truncated rows.** A scanner that stopped at its walk budget (the gitconfig
  nested-repository walk, the skills bundle walk, transcript counts) is marked `partial`
  in `--verbose` and `"truncated": true` in the JSON's `diagnostics`: its results may be
  incomplete, and what it missed is not in the diff either. Check after the first scan:
  `jq -r '.diagnostics[] | select(.truncated) | .scanner' latest.json` (on the
  development machine: `rules` and `gitconfig`). Raise `--walk-budget` (default 25,000
  directories per project for the gitconfig walk, other caps scale with it) if the time
  is acceptable, and pass the same value to the baseline and to every scheduled run
  (both scripts forward arguments after `--`).
- **Which homes.** The primary pass scans `$HOME`; `--search-dirs` adds more homes, each
  with its own projects. A scheduled run as one user sees that user's home only (and only
  that user's processes). Give the baseline and the scheduled run the same
  `--search-dirs` and `--skip`.
- **Keep arguments identical.** `--skip`, `--search-dirs`, `--walk-budget`,
  `--probe-mcp`, `--threat-catalog` all change what is in the report; a baseline made
  with different ones produces drift that is not drift.
- **`--probe-mcp` on a timer** spawns every configured stdio MCP server, unattended. It is
  the only way to see a tool-description rug-pull, and it runs code a config file
  names; leave it to deliberate runs unless you accept that.
- **The gate repeats.** `--fail-on high` trips on every run while a high finding exists,
  not only when it is new. When you have reviewed and accepted the current findings, set
  `RMGUARD_FAIL_ON=critical` (or `none`) for the scheduled run and rely on the diff for
  change.

## Scheduling

Install the binary and the scripts where the units expect them:

```sh
install -m 755 target/release/rmguard scripts/rmguard-notify.sh scripts/rmguard-baseline.sh ~/.local/bin/
rmguard-baseline.sh            # first baseline, from the shell whose PATH the timer will use
```

### systemd (Linux)

[`contrib/systemd/rmguard.service`](../contrib/systemd/rmguard.service) and
[`rmguard.timer`](../contrib/systemd/rmguard.timer) are **user** units: the scan runs as
you and reads your home, which is what it is for. Do not run it as a system service as
root; root's home is not yours.

```sh
mkdir -p ~/.config/systemd/user
cp contrib/systemd/rmguard.service contrib/systemd/rmguard.timer ~/.config/systemd/user/
# edit Environment=PATH= in rmguard.service to your login shell's $PATH
systemctl --user daemon-reload
systemctl --user start rmguard.service      # one run now; check it
journalctl --user -u rmguard.service -n 20
systemctl --user enable --now rmguard.timer # daily, RandomizedDelaySec=1h, Persistent=true
loginctl enable-linger "$USER"              # optional: run while you are logged out
```

Exit 3 (gate tripped or drift) leaves the unit `failed` until the next clean run, so
`systemctl --user --failed` doubles as a reminder; uncomment `SuccessExitStatus=3` if you
would rather it did not.

#### Hardening

The scanner's job is to read your home directory, `/proc` entries of your own processes,
`/etc` and some system paths, and to run `--version` on the tools it finds. Directives
that hide any of that do not make the scan safer; they make it **wrong**, and wrong in
the dangerous direction: an empty-looking home scans clean.

In the unit, enabled (seccomp and personality restrictions, which a user unit can apply
without a user namespace):

| Directive | Why it is safe |
|---|---|
| `NoNewPrivileges=yes` | rmguard and the tools it runs need no setuid. |
| `LockPersonality=yes`, `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, `SystemCallArchitectures=native` | none of these is used by the scan or its `--version` probes. |
| `UMask=0077` | the state files are owner-only (the scripts also set `umask 077`). |
| `Nice=10`, `IOSchedulingClass=idle` | a scan is a burst of directory walks; let interactive work win. |

Optional, commented out in the unit: `ProtectSystem=strict` with
`ReadWritePaths=%S/rmguard`. **`strict` makes the file system read-only, not
unreadable**, and a scanner only reads; the state directory is the one path it writes.
In a user unit it implies `PrivateUsers=yes` and needs unprivileged user namespaces
(systemd.exec(5)); other users' files then appear owned by `nobody`, which no rmguard
check depends on (permission checks use mode bits; process checks are limited to your
own UID). This combination was not run under a live systemd here.

Do not add:

| Directive | What breaks |
|---|---|
| `ProtectHome=yes` / `tmpfs`, `InaccessiblePaths=` on the home | the scan sees an empty home and reports nothing: a clean-looking scan of nothing (the next diff lists everything as removed) |
| `MemoryDenyWriteExecute=yes` | inherited by children: systemd.exec(5) notes it is incompatible with JIT compilers, so `node` and other JIT runtimes rmguard starts for `--version` (and MCP servers under `--probe-mcp`) can fail, and a failed probe reads as an unknown version |
| `PrivateNetwork=yes`, `IPAddressDeny=any` | `--otel`, `--verify-registry` and the notification webhook |
| `ProcSubset=pid` | hides `/proc/stat`, which the listeners scanner reads |

`systemd-analyze --user security rmguard.service` rates the shipped unit 8.5 and the
optional variant 8.4 ("EXPOSED"): expected for a job whose purpose is to read the home
directory.

### launchd (macOS)

[`contrib/launchd/io.github.lexicone42.rmguard.plist`](../contrib/launchd/io.github.lexicone42.rmguard.plist)
is a user agent, daily at 10:17. launchd expands neither `~` nor `$HOME`: replace every
`/Users/YOU`, and set `PATH` to your login shell's.

```sh
sed "s#/Users/YOU#$HOME#g" contrib/launchd/io.github.lexicone42.rmguard.plist \
  > ~/Library/LaunchAgents/io.github.lexicone42.rmguard.plist
plutil -lint ~/Library/LaunchAgents/io.github.lexicone42.rmguard.plist
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/io.github.lexicone42.rmguard.plist
launchctl kickstart -k "gui/$(id -u)/io.github.lexicone42.rmguard"   # one run now
```

A run missed while the Mac was asleep runs when it wakes (one missed while it was off
does not). As a `gui/` agent, `osascript`
notifications appear in your session.

### cron

The fallback where neither is available. cron gives jobs `PATH=/usr/bin:/bin` and no
desktop session, so set PATH and do not expect a notification (the log still gets it):

```crontab
17 10 * * * PATH=$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin RMGUARD_DESKTOP=0 $HOME/.local/bin/rmguard-notify.sh >>$HOME/.local/state/rmguard/cron.out 2>&1
```

Run in a cron-like environment (`env -i HOME=... LOGNAME=... SHELL=/bin/sh
PATH=/usr/bin:/bin /bin/sh -c '<the line's command>'`), after the baseline was rotated
and with `RMGUARD_FAIL_ON=critical`, it exited 0 and wrote nothing. The script takes a
lock in the state directory, so a slow scan does not overlap the next one.

## Notifications

[`scripts/rmguard-notify.sh`](../scripts/rmguard-notify.sh) runs the one scan above, and
when the gate trips (rmguard exit 3) or the diff has any entry it:

1. appends a summary and the diff to `rmguard.log` in the state directory (owner-only;
   the diff names items, with the redaction rmguard applies to every output);
2. shows a desktop notification with `notify-send` (when a session bus or display is
   reachable) or `osascript` (macOS), holding **counts and diff section titles only**;
   `RMGUARD_DESKTOP=0` turns it off;
3. only if you set `RMGUARD_WEBHOOK_URL` (unset by default; `https://` only), POSTs
   `{"text": "<the same headline>"}`: counts and section titles, optionally prefixed by
   `RMGUARD_INSTANCE`, a label you choose. Never finding text, paths, names, commands,
   evidence, or the host name. The URL is handed to `curl` on stdin, not on its command
   line, so other local users cannot read it from the process list.

Nothing leaves the machine unless that variable is set.

```console
$ RMGUARD_DESKTOP=0 rmguard-notify.sh
rmguard: 1 finding(s) at or above high (worst: high); drift since baseline: 1 added, 0 removed, 1 changed (MCP Servers)
[exit 3]

$ cat ~/.local/state/rmguard/rmguard.log
== 2026-10-25T08:01:13Z ==
rmguard: 1 finding(s) at or above high (worst: high); drift since baseline: 1 added, 0 removed, 1 changed (MCP Servers)
  === Scan Diff Report ===

  --- MCP Servers ---
    + fetcher (transport=stdio, package_name=mcp-server-fetch, package_ecosystem=pypi, unpinned=no version)
    ~ notes|Claude Code (home)
        package_version: 0.6.0 -> 0.6.2

  --- Summary ---
    MCP servers: 1 -> 2 (+1)

report: ~/.local/state/rmguard/latest.json  diff: ~/.local/state/rmguard/diff.txt
after review: rmguard-baseline.sh --force --from ~/.local/state/rmguard/latest.json
```

With a local HTTPS receiver standing in for the webhook (`RMGUARD_INSTANCE=box-7`, an MCP
argument carrying a canary token in the scanned config), the receiver got exactly
`{"text":"[box-7] rmguard: drift since baseline: 0 added, 1 removed, 1 changed (MCP Servers)"}`
with `Content-Type: application/json`; the canary was in none of the webhook body, the
`notify-send` arguments, `diff.txt` or the log.

Environment: `RMGUARD` (binary), `RMGUARD_STATE_DIR`, `RMGUARD_FAIL_ON`
(`critical|high|medium|low|none`, default `high`), `RMGUARD_DESKTOP`,
`RMGUARD_WEBHOOK_URL`, `RMGUARD_INSTANCE`. `--help` prints them.

## Fleet

Two independent routes; use either or both.

### OpenTelemetry to a collector

Each machine exports its posture as counts with closed labels ([what is and is never
exported](OPENTELEMETRY.md#what-is-never-exported-and-why)). Give every machine an id of
its own, or their series collide:

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=https://collector.example:4318 \
OTEL_EXPORTER_OTLP_HEADERS="Authorization=Bearer $RMGUARD_COLLECTOR_TOKEN" \
OTEL_TRACES_EXPORTER=none \
  rmguard --otel --otel-instance "$ASSET_TAG" --format json -o latest.json --fail-on high
```

- `--otel-instance` becomes `service.instance.id` (in Prometheus, `instance`). Use an
  asset tag, not something that identifies a person; rmguard exports it as typed and never
  derives one.
- `OTEL_EXPORTER_OTLP_HEADERS` carries the collector credential; rmguard strips every
  `OTEL_*` variable from the processes it starts, so the token never reaches a probed
  server or a `--version` probe. Keep it out of shell history (an environment file
  readable only by you, e.g. a systemd `EnvironmentFile=`). The bearer-token setup was
  verified against otelcol-contrib in [OPENTELEMETRY.md](OPENTELEMETRY.md#verified-against).
- `OTEL_TRACES_EXPORTER=none` sends metrics only: the dashboard and alerts need nothing
  else. Without it, a collector that has no traces pipeline answers 404 to the trace
  export, and rmguard prints
  `warning: OpenTelemetry export failed (HTTP 404); telemetry only, the report and exit code are not affected by this`
  (seen here with a metrics-only collector; the metrics arrived regardless).
- The notify script runs one scan per run, so `rmguard-notify.sh -- --otel
  --otel-instance "$ASSET_TAG"` exports once per run (the posture metrics describe the
  scan, not the diff).

On the collector, the `prometheus` exporter with default translation produces the names
the dashboard and rules use. Scrape it with `honor_labels: true`, or Prometheus renames
the exporter's `job`/`instance` to `exported_job`/`exported_instance` and every machine
appears as the collector:

```yaml
# collector
receivers:
  otlp:
    protocols:
      http: { endpoint: 0.0.0.0:4318 }   # add auth: see OPENTELEMETRY.md
exporters:
  prometheus:
    endpoint: 0.0.0.0:8889
    metric_expiration: 30m               # each scan is one export; default is 5m
service:
  pipelines:
    metrics: { receivers: [otlp], exporters: [prometheus] }

# prometheus.yml
scrape_configs:
  - job_name: otelcol
    honor_labels: true
    static_configs: [{ targets: ["collector:8889"] }]
rule_files: [rmguard-alerts.yaml]
```

Real run (collector, Prometheus and Grafana on 127.0.0.1, configured as above):

```console
$ OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:14318 OTEL_TRACES_EXPORTER=none rmguard --otel --otel-instance box-0042 --format json -o ~/box-0042.json
info: OpenTelemetry export enabled (OTLP http/protobuf; endpoint from OTEL_EXPORTER_OTLP_*, default http://localhost:4318)
info: loaded built-in threat catalog 2026-10-25.2 (307 entries)
[exit 0]
```

after which Prometheus held `target_info{instance="box-0042", job="rmguard",
rmguard_catalog_version="2026-10-25.2", ...}` and the `rmguard_inventory` series for it.
The catalog version is a resource attribute, so it is on `target_info`, not on the
posture series.

### JSON reports and `--report`

No collector needed: collect each machine's `latest.json` however you already move files
(MDM, a shared drive, a CI artifact, S3, a git repo), named by asset tag, and aggregate:

```console
$ mkdir -p ~/scans && cp ~/box-0042.json ~/scans/ && rmguard --report ~/scans -o ~/fleet.html
info: aggregating 1 machine scan(s)
Fleet report written to ~/fleet.html
[exit 0]
```

A file in the directory that is not an rmguard scan is skipped with
`warning: skipping <path> (not a valid rmguard JSON scan)`; a directory with none exits 1.
Unlike the metrics, these files contain the full report (paths, names, redacted
commands): store and move them like the sensitive inventory they are.

`fleet.html` ranks machines by the severity of their findings (most at-risk first),
shows fleet-wide critical/high/medium totals, and links to each machine's findings.
The aggregator only reads the JSON files — it's agnostic about how they got there:

```bash
# On each machine (cron, MDM, or manual):
rmguard --format json --output /shared/scans/$(hostname).json

# Anywhere the JSONs are collected:
rmguard --report /shared/scans/ --output fleet.html
```

To **gate** on posture instead of just reporting it — a pre-commit hook, an onboarding
check, or a CI step that must fail a machine with serious findings — use `--fail-on`:

```bash
# Exits 3 (report still prints) if any Critical finding is present; else 0.
rmguard --fail-on critical || echo "machine failed its security gate"
```

## Grafana dashboard

[`contrib/grafana/rmguard-posture.json`](../contrib/grafana/rmguard-posture.json)
(Dashboards → New → Import, or file provisioning). It asks for a Prometheus data source
and has three variables: data source, machine (`instance`, multi-select), and "latest
scan within" (the `last_over_time` window, default `1d`: at least one scan interval).

| Panel | Query (default translation) |
|---|---|
| Machines | `count(sum by (instance) (last_over_time(rmguard_inventory[$lookback])))` |
| With critical / With high | machines whose latest scan has a finding of that severity |
| With truncated scans | machines with `rmguard_scan_truncated_scanners > 0` |
| Threat catalog versions | `count by (rmguard_catalog_version) (last_over_time(target_info{job="rmguard"}[$lookback]))`, one value per version |
| Fleet findings by severity | `sum by (rmguard_finding_severity) (last_over_time(rmguard_findings[$lookback]))` over time |
| Critical and high findings by category | by `rmguard_finding_category` |
| Findings per machine | a machine × severity table |
| Truncated scanners | machine and `rmguard_scanner` for each walk that stopped early |
| Inventory by kind | `sum by (rmguard_inventory_kind) (...)`, one row per kind |

Every query also filters `job="rmguard", instance=~"$instance"`. The posture gauges hold
one sample per scan, so every panel reads the latest scan with `last_over_time`, never
`rate`. A machine with no findings has no `rmguard_findings` series at all (a severity
and category pair with no findings is not exported), so it is counted by "Machines" and
missing from "Findings per machine".

Checked here against Grafana 13.2.4 with Prometheus 3.15.1 and otelcol-contrib 0.163.2
(podman, 127.0.0.1 only): the dashboard provisioned from the file, every panel's query
returned data through Grafana's query API with three machines exporting, and the
rendered page showed every panel populated. Grafana migrates the file's `schemaVersion`
39 on load.

## Alert rules

[`contrib/prometheus/rmguard-alerts.yaml`](../contrib/prometheus/rmguard-alerts.yaml):

- **`RmguardNewCriticalFinding`**: a machine's latest scan has more critical findings than
  its previous scan, including a first critical finding and a machine seen for the first
  time with one. It fires for 2 h after that scan (set the `2h` between "one scan plus a
  scrape" and your scan interval), then resolves; the alert carries the count, the
  machine's own report says what and where.
- **`RmguardCatalogVersionSkew`**: more than one `rmguard.catalog.version` among the
  machines that scanned in the last day, for 2 days. Exposure findings follow the
  catalog, so a fleet on mixed versions is not comparable.

[`rmguard-alerts.test.yaml`](../contrib/prometheus/rmguard-alerts.test.yaml) is a
`promtool test rules` file with synthetic daily scans (new critical, unchanged critical,
a new machine, a version skew):

```console
$ promtool check rules rmguard-alerts.yaml
Checking rmguard-alerts.yaml
  SUCCESS: 2 rules found

$ promtool test rules rmguard-alerts.test.yaml
  SUCCESS
```

Removing the "no previous series counts as 0" clause makes the test fail, as it should.
Loaded into the live Prometheus above, both rules evaluated with `health: ok`; the new-
critical rule fired for the one machine whose first scan had a critical finding, and the
skew rule stayed inactive with every machine on 2026-10-25.2.

## What was and was not verified

Run here (Linux, 2026-10-25): every `rmguard` command and both scripts as shown, including
the cron line in a cron-like environment; the webhook path against a local HTTPS receiver
and `notify-send` through a stand-in that recorded its arguments; `shellcheck --shell=sh`
(0.11.0) on both scripts, clean; `systemd-analyze --user verify` (systemd 262, in a
container) on both units, with and without the optional directives, clean; the plist
parsed with Python's `plistlib`; the collector → Prometheus → Grafana path and the alert
rules as described above.

Re-run after the single-scan change (2026-10-25, catalog 2026-10-25.3), in an `env -i`
environment with a scratch home: the one-machine commands as shown; both scripts (first
baseline, drift without `--force`, `--force`, `--force --from`; notify with the gate
tripped and drift, with `RMGUARD_FAIL_ON=critical` and no drift, and with an rmguard
usage error after `--`, which it reports as an error, exit 1); `sh -n` on both scripts.
Not re-run after that change: `shellcheck` (not installed on the machine), the webhook
receiver and the `notify-send` stand-in (their code did not change).

Not run here:

- **The units under a live systemd and the plist under launchd.** This machine has no
  systemd and is not a Mac. The hardening table is reasoning from systemd.exec(5) and
  from what rmguard reads, not a test of each directive.
- **A real desktop notification.** `notify-send` was a stand-in; `osascript` was not run.
- **A webhook service.** The body is a minimal `{"text": ...}`, which Slack-style incoming
  webhooks accept; other services may want a different shape.
- **`honor_labels: false`.** The `exported_instance` renaming is Prometheus's documented
  behavior, not something re-tested here.
