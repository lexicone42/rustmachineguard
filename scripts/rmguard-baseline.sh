#!/bin/sh
# Create or rotate the rmguard baseline that scheduled runs diff against.
#
#   rmguard-baseline.sh                  first run: scan and write the baseline
#   rmguard-baseline.sh                  later: print the drift since the baseline, change nothing
#   rmguard-baseline.sh --force          print the drift, then rotate (old one kept, timestamped)
#   rmguard-baseline.sh --force --from latest.json
#                                        rotate to a scan you already reviewed instead of a new one
#
# Anything after `--` is passed to every rmguard run (e.g. `-- --walk-budget 100000`); give
# the scheduled runs the same arguments, or the diff compares different scans.
#
# Environment:
#   RMGUARD            the rmguard binary (default: rmguard on PATH)
#   RMGUARD_STATE_DIR  where the baseline lives (default: ${XDG_STATE_HOME:-$HOME/.local/state}/rmguard)
#
# Exit codes: 0 baseline written or rotated; 1 error (nothing changed); 3 a baseline exists
# and --force was not given (the drift was printed, nothing changed).
#
# Files are created with umask 077: a scan report is a map of where this machine's
# credentials and agent configuration are, even though it holds no secret values.

set -eu
umask 077

RMGUARD=${RMGUARD:-rmguard}
STATE_DIR=${RMGUARD_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/rmguard}
force=0
from=

usage() {
    sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case $1 in
        --force) force=1 ;;
        --from)
            [ $# -ge 2 ] || { echo "error: --from needs a file" >&2; exit 1; }
            from=$2
            shift
            ;;
        -h | --help) usage; exit 0 ;;
        --) shift; break ;;
        *) echo "error: unknown option: $1 (see --help)" >&2; exit 1 ;;
    esac
    shift
done

command -v "$RMGUARD" >/dev/null 2>&1 || { echo "error: rmguard not found: $RMGUARD (set RMGUARD)" >&2; exit 1; }
mkdir -p "$STATE_DIR"
baseline=$STATE_DIR/baseline.json

# A scratch directory inside the state dir, so the final mv is a same-filesystem rename.
work=$(mktemp -d "$STATE_DIR/.baseline.XXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 130' INT TERM

# Is this file an rmguard JSON scan? Ask rmguard: --report loads a directory of scans with
# the same deserializer the report uses and exits 1 when none of them parses.
is_scan() {
    mkdir "$work/check"
    cp "$1" "$work/check/scan.json"
    if "$RMGUARD" --report "$work/check" -o "$work/check.html" >/dev/null 2>&1; then
        rm -rf "$work/check" "$work/check.html"
        return 0
    fi
    rm -rf "$work/check" "$work/check.html"
    return 1
}

# The new baseline: the --from file, or a fresh scan. rmguard runs from $HOME so the
# working directory adds no project (a scanned home is never a project), the same as a
# scheduled run.
new_scan() {
    if [ -n "$from" ]; then
        [ -f "$from" ] || { echo "error: --from: no such file: $from" >&2; return 1; }
        is_scan "$from" || { echo "error: --from: not an rmguard --format json scan: $from" >&2; return 1; }
        cp "$from" "$work/new.json"
    elif [ -s "$work/fresh.json" ]; then
        # The scan the drift above was computed from: what becomes the baseline is what
        # was printed.
        mv "$work/fresh.json" "$work/new.json"
    else
        (cd "$HOME" && "$RMGUARD" --format json -o "$work/new.json" "$@") || {
            echo "error: scan failed; baseline unchanged" >&2
            return 1
        }
        [ -s "$work/new.json" ] || { echo "error: scan wrote nothing; baseline unchanged" >&2; return 1; }
    fi
}

if [ ! -e "$baseline" ]; then
    new_scan "$@"
    mv "$work/new.json" "$baseline"
    echo "baseline written: $baseline"
    exit 0
fi

# A baseline exists: show what changed since it, before anything is replaced. One scan:
# the diff on stdout, the scan itself in fresh.json (rmguard 2026-10-25 or later).
(cd "$HOME" && "$RMGUARD" --format json -o "$work/fresh.json" --diff "$baseline" "$@" >"$work/diff.txt") || {
    echo "error: diff against $baseline failed; baseline unchanged" >&2
    exit 1
}
added=$(grep -c '^  + ' "$work/diff.txt" || true)
removed=$(grep -c '^  - ' "$work/diff.txt" || true)
changed=$(grep -c '^  ~ ' "$work/diff.txt" || true)
cat "$work/diff.txt"
echo "drift since baseline: $added added, $removed removed, $changed changed"

if [ "$force" -ne 1 ]; then
    echo "baseline unchanged: review the drift above, then re-run with --force to rotate"
    exit 3
fi

new_scan "$@"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
kept=$STATE_DIR/baseline.$stamp.json
[ ! -e "$kept" ] || { echo "error: $kept already exists; baseline unchanged" >&2; exit 1; }
# Copy, then rename over: at every moment $baseline is a complete scan.
cp -p "$baseline" "$kept"
mv "$work/new.json" "$baseline"
echo "previous baseline kept: $kept"
echo "baseline rotated: $baseline"
