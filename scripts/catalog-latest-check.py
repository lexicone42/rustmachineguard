#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Check the threat catalog's vulnerable-range rows against the registries' latest releases.

For every npm and PyPI row with a `version_range`, fetch the package's current release
(npm `https://registry.npmjs.org/<name>` -> `dist-tags.latest`; PyPI
`https://pypi.org/pypi/<name>/json` -> `info.version`) and report:

  * LATEST MATCHES: the registry's latest release falls inside the row's range. Either the
    row is a false positive for anyone who upgraded (a fix exists outside the range, or the
    package restarted its version scheme, as `@modelcontextprotocol/server-filesystem` did
    in 2026-10), or the advisory genuinely has no fix yet. Read the row before changing it.
  * MISSING: the registry no longer has the package (HTTP 404, or an npm document whose
    every version is unpublished, as after an npm security removal).
  * ERROR: any other failure (network, unparseable version).

Versions are compared the way rmguard's `version_matches` does: a leading `v` is dropped,
the numeric core is padded to three parts, and pre-release / build suffixes are ignored
(`2.0.0a1` reads as `2.0.0`). Ranges are the catalog's semver comparator lists
(`>=1.0.0, <2.0.1`, no `||`).

Read-only: it sends GET requests and never writes anything. Requests are spaced by
`--delay` seconds (default 0.3) and each package is fetched once.

    uv run --script scripts/catalog-latest-check.py [--catalog FILE] [--delay SECONDS]

Exit status: 0 when no row is flagged, 1 when some row is LATEST MATCHES or MISSING,
2 on usage errors.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_CATALOG = Path(__file__).resolve().parent.parent / "src" / "catalogs" / "builtin_catalog.json"
USER_AGENT = "rmguard-catalog-latest-check/1 (read-only)"
COMPARATOR = re.compile(r"^\s*(>=|<=|>|<|=)?\s*v?(\d+(?:\.\d+){0,2})\S*\s*$")


def core(version: str) -> tuple[int, int, int] | None:
    """The numeric core of a version, padded to three parts; None if there is none."""
    m = re.match(r"\s*v?(\d+(?:\.\d+)*)", version)
    if not m:
        return None
    parts = [int(p) for p in m.group(1).split(".")][:3]
    while len(parts) < 3:
        parts.append(0)
    return parts[0], parts[1], parts[2]


def range_matches(rng: str, version: str) -> bool:
    """True when `version`'s numeric core satisfies every comparator in `rng`."""
    ver = core(version)
    if ver is None:
        raise ValueError(f"unparseable version {version!r}")
    for part in rng.split(","):
        m = COMPARATOR.match(part)
        if not m:
            raise ValueError(f"unsupported comparator {part!r} in {rng!r}")
        op, bound = m.group(1) or "=", core(m.group(2))
        assert bound is not None
        ok = {
            ">=": ver >= bound,
            "<=": ver <= bound,
            ">": ver > bound,
            "<": ver < bound,
            "=": ver == bound,
        }[op]
        if not ok:
            return False
    return True


def fetch_latest(ecosystem: str, name: str) -> tuple[str | None, str | None]:
    """(latest version, None) or (None, "missing" | error text)."""
    if ecosystem == "npm":
        url = "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@")
    else:
        url = "https://pypi.org/pypi/" + urllib.parse.quote(name) + "/json"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            doc = json.load(resp)
    except urllib.error.HTTPError as e:
        return (None, "missing") if e.code == 404 else (None, f"HTTP {e.code}")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        return None, str(e)
    if ecosystem == "npm":
        # A fully unpublished package (npm security removal included) still answers 200,
        # with no dist-tags and a `time.unpublished` record.
        if not doc.get("dist-tags") and (doc.get("time") or {}).get("unpublished"):
            return None, "missing"
        latest = (doc.get("dist-tags") or {}).get("latest")
    else:
        latest = (doc.get("info") or {}).get("version")
    return (latest, None) if latest else (None, "no latest version in registry response")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG, help="catalog JSON (default: the built-in one)")
    ap.add_argument("--delay", type=float, default=0.3, help="seconds between registry requests (default 0.3)")
    args = ap.parse_args()
    try:
        rows = json.loads(args.catalog.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"cannot read {args.catalog}: {e}", file=sys.stderr)
        return 2

    ranged = [r for r in rows if r.get("version_range") and not r.get("version")]
    checked = [r for r in ranged if r["ecosystem"] in ("npm", "pypi")]
    skipped = len(ranged) - len(checked)
    cache: dict[tuple[str, str], tuple[str | None, str | None]] = {}
    flagged, missing, errors, clean = [], [], [], 0
    for r in checked:
        key = (r["ecosystem"], r["name"])
        if key not in cache:
            if cache:
                time.sleep(args.delay)
            cache[key] = fetch_latest(*key)
        latest, err = cache[key]
        label = f'{r["ecosystem"]} {r["name"]} [{r["version_range"]}]'
        if err == "missing":
            missing.append(label)
            continue
        if err:
            errors.append(f"{label}: {err}")
            continue
        try:
            hit = range_matches(r["version_range"], latest)
        except ValueError as e:
            errors.append(f"{label}: {e}")
            continue
        if hit:
            flagged.append(f"{label} matches latest {latest}")
        else:
            clean += 1

    print(f"catalog: {args.catalog}")
    print(
        f"vulnerable-range rows: {len(ranged)} ({len(checked)} npm/PyPI checked against {len(cache)} packages, "
        f"{skipped} in other ecosystems skipped)"
    )
    for title, items in (("LATEST MATCHES", flagged), ("MISSING", missing), ("ERROR", errors)):
        print(f"{title}: {len(items)}")
        for item in items:
            print(f"  {item}")
    print(f"clean (latest outside the range): {clean}")
    return 1 if flagged or missing else 0


if __name__ == "__main__":
    sys.exit(main())
