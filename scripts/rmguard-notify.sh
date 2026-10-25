#!/bin/sh
# Scheduled rmguard run: scan, gate on severity, diff against the baseline, and tell you
# when there is something to look at.
#
#   rmguard-notify.sh [-- extra rmguard args]
#
# Each run does two scans (rmguard's --diff mode writes the diff instead of the JSON and
# ignores --fail-on, so one invocation cannot do both):
#   1. rmguard --format json -o latest.json --fail-on $RMGUARD_FAIL_ON
#   2. rmguard --diff baseline.json -o diff.txt
# When the gate trips (exit 2) or the diff has any entry, it appends a summary to
# rmguard.log and, if a desktop is reachable, shows a notification. Anything after `--`
# goes to both scans (keep it the same as the baseline's).
#
# Environment (all optional):
#   RMGUARD               the rmguard binary (default: rmguard on PATH)
#   RMGUARD_STATE_DIR     state directory (default: ${XDG_STATE_HOME:-$HOME/.local/state}/rmguard)
#   RMGUARD_FAIL_ON       critical | high | medium | low | none (default: high)
#   RMGUARD_DESKTOP       1 = notify-send / osascript when available (default), 0 = log only
#   RMGUARD_WEBHOOK_URL   unset by default. When set (https:// only), POST a JSON
#                         {"text": ...} holding counts and diff section titles only: no
#                         finding text, path, name, command or evidence, and no host name
#   RMGUARD_INSTANCE      a label of your choosing for the webhook text (never derived
#                         from the host)
#
# Files in the state directory: baseline.json (written by rmguard-baseline.sh),
# latest.json, diff.txt, rmguard.log. Created with umask 077.
#
# Exit codes: 0 nothing to report; 2 reported (gate tripped or drift); 1 error.

set -eu
umask 077

RMGUARD=${RMGUARD:-rmguard}
STATE_DIR=${RMGUARD_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/rmguard}
FAIL_ON=${RMGUARD_FAIL_ON:-high}
DESKTOP=${RMGUARD_DESKTOP:-1}
WEBHOOK=${RMGUARD_WEBHOOK_URL:-}
INSTANCE=${RMGUARD_INSTANCE:-}

case ${1:-} in
    -h | --help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --) shift ;;
    '') ;;
    *) echo "error: unknown option: $1 (extra rmguard arguments go after --)" >&2; exit 1 ;;
esac
case $FAIL_ON in
    critical | high | medium | low | none) ;;
    *) echo "error: RMGUARD_FAIL_ON must be critical, high, medium, low or none" >&2; exit 1 ;;
esac
nl='
'
case $WEBHOOK in
    *"$nl"*) echo "error: RMGUARD_WEBHOOK_URL contains a newline" >&2; exit 1 ;;
    *'"'* | *\\* | *' '*) echo "error: RMGUARD_WEBHOOK_URL contains a quote, backslash or space" >&2; exit 1 ;;
    '' | https://*) ;;
    *) echo "error: RMGUARD_WEBHOOK_URL must be an https:// URL" >&2; exit 1 ;;
esac

command -v "$RMGUARD" >/dev/null 2>&1 || { echo "error: rmguard not found: $RMGUARD (set RMGUARD)" >&2; exit 1; }
baseline=$STATE_DIR/baseline.json
[ -f "$baseline" ] || { echo "error: no baseline at $baseline; run rmguard-baseline.sh first" >&2; exit 1; }
log=$STATE_DIR/rmguard.log

# One run at a time (cron can overlap a slow scan; systemd does not start a running unit).
lock=$STATE_DIR/.notify.lock
mkdir "$lock" 2>/dev/null || { echo "error: another run holds $lock (remove it if no run is active)" >&2; exit 1; }
trap 'rm -rf "$lock"' EXIT
trap 'exit 130' INT TERM

# Run from $HOME: the working directory is scanned as a project unless it is a scanned
# home or an ancestor of one, and a timer's working directory should add nothing.
cd "$HOME"

# 1. The JSON scan and the severity gate.
gate=0
if [ "$FAIL_ON" = none ]; then
    "$RMGUARD" --format json -o "$STATE_DIR/latest.json.tmp" "$@" 2>"$STATE_DIR/scan.err" || gate=$?
else
    "$RMGUARD" --format json -o "$STATE_DIR/latest.json.tmp" --fail-on "$FAIL_ON" "$@" 2>"$STATE_DIR/scan.err" || gate=$?
fi
# Exit 2 is also what a command-line usage error returns (the argument parser's
# convention), so a 2 counts as the gate only with rmguard's own fail-on line.
rc=$gate
if [ "$gate" -eq 2 ] && ! grep -q '^fail-on: ' "$STATE_DIR/scan.err"; then
    gate=1
fi
case $gate in
    0 | 2) mv "$STATE_DIR/latest.json.tmp" "$STATE_DIR/latest.json" ;;
    *)
        echo "error: scan failed (exit $rc):" >&2
        cat "$STATE_DIR/scan.err" >&2
        rm -f "$STATE_DIR/latest.json.tmp"
        exit 1
        ;;
esac
# rmguard's own line, e.g. "fail-on: 3 finding(s) at or above high (most severe: critical) — exiting 2"
gate_line=$(grep '^fail-on: ' "$STATE_DIR/scan.err" || true)
gate_count=$(printf '%s\n' "$gate_line" | sed -n 's/^fail-on: \([0-9][0-9]*\) finding.*/\1/p')
gate_worst=$(printf '%s\n' "$gate_line" | sed -n 's/.*(most severe: \([a-z]*\)).*/\1/p')

# 2. The drift.
"$RMGUARD" --diff "$baseline" -o "$STATE_DIR/diff.txt" "$@" 2>>"$STATE_DIR/scan.err" || {
    echo "error: diff against $baseline failed:" >&2
    cat "$STATE_DIR/scan.err" >&2
    exit 1
}
added=$(grep -c '^  + ' "$STATE_DIR/diff.txt" || true)
removed=$(grep -c '^  - ' "$STATE_DIR/diff.txt" || true)
changed=$(grep -c '^  ~ ' "$STATE_DIR/diff.txt" || true)
drift=1
grep -q '^No changes detected between baseline and current scan\.$' "$STATE_DIR/diff.txt" && drift=0
# Section titles are fixed strings in rmguard ("MCP Servers", "Agent Settings", ...); they
# name what kind of thing changed, never which one.
sections=$(sed -n 's/^--- \(.*\) ---$/\1/p' "$STATE_DIR/diff.txt" | grep -vx 'Summary' | paste -s -d, - | sed 's/,/, /g' || true)
catalog_line=$(grep '^threat catalog: ' "$STATE_DIR/diff.txt" || true)

if [ "$gate" -ne 2 ] && [ "$drift" -eq 0 ]; then
    exit 0
fi

# 3. Report. The headline holds counts and section titles only: it is what leaves this
# file (desktop notification, webhook).
headline="rmguard:"
if [ "$gate" -eq 2 ]; then
    headline="$headline ${gate_count:-?} finding(s) at or above $FAIL_ON (worst: ${gate_worst:-?});"
fi
if [ "$drift" -eq 1 ]; then
    headline="$headline drift since baseline: $added added, $removed removed, $changed changed ($sections)"
else
    headline="$headline no drift since baseline"
fi

{
    echo "== $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
    echo "$headline"
    # (The diff's own first line when the drift is printed below.)
    [ -z "$catalog_line" ] || [ "$drift" -eq 1 ] || echo "$catalog_line"
    # The diff itself (item names, redacted fields) stays in this local, owner-only log.
    [ "$drift" -eq 0 ] || sed 's/^/  /' "$STATE_DIR/diff.txt"
    echo "report: $STATE_DIR/latest.json  diff: $STATE_DIR/diff.txt"
    echo "after review: rmguard-baseline.sh --force --from $STATE_DIR/latest.json"
} >>"$log"

if [ "$DESKTOP" = 1 ]; then
    if command -v notify-send >/dev/null 2>&1 && { [ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ] || [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; }; then
        notify-send --app-name=rmguard "rmguard" "$headline" 2>/dev/null || true
    elif command -v osascript >/dev/null 2>&1; then
        # The text goes in as an argument, never spliced into the AppleScript source.
        osascript -e 'on run argv' -e 'display notification (item 1 of argv) with title "rmguard"' -e 'end run' "$headline" >/dev/null 2>&1 || true
    fi
fi

if [ -n "$WEBHOOK" ]; then
    if command -v curl >/dev/null 2>&1; then
        text=$headline
        [ -z "$INSTANCE" ] || text="[$INSTANCE] $text"
        # JSON-escape: backslash and double quote (the headline has no control characters).
        esc=$(printf '%s' "$text" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
        printf '{"text":"%s"}' "$esc" >"$STATE_DIR/.webhook.json"
        # The URL goes to curl on stdin (-K -), not argv, so other local users cannot read it
        # from the process list.
        printf 'url = "%s"\n' "$WEBHOOK" | curl -K - -fsS --max-time 10 --proto '=https' \
            -H 'Content-Type: application/json' --data-binary "@$STATE_DIR/.webhook.json" \
            -o /dev/null || echo "warning: webhook post failed" >&2
        rm -f "$STATE_DIR/.webhook.json"
    else
        echo "warning: RMGUARD_WEBHOOK_URL is set but curl is not installed" >&2
    fi
fi

echo "$headline"
exit 2
