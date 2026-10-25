#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Check that every advisory id the threat catalog cites resolves to a published record.

Ids are taken from each row's `advisory` text:

  * GHSA-xxxx-xxxx-xxxx: `https://api.github.com/advisories/<id>` (GitHub's global
    advisory database). Unauthenticated calls are limited to 60 an hour; set
    `GITHUB_TOKEN` to raise that. When GitHub refuses with a rate limit (403/429), the
    id is looked up in OSV instead (`https://api.osv.dev/v1/vulns/<id>`; OSV imports the
    GitHub database). An id the global database does not have may be a repository
    advisory (published by the maintainer, not reviewed into the database):
    `https://api.github.com/repos/<owner>/<repo>/security-advisories/<id>` is tried for
    the row's repository, taken from the registry (npm `repository.url`, PyPI
    `project_urls`), a `github.com/<owner>/<repo>` URL or an `<owner>/<repo> PR|commit`
    mention in the row, or `KNOWN_REPOS` (agent runtimes, extensions, and packages whose
    registry entry names no repository).
  * CVE-YYYY-N: OSV, then NVD
    (`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<id>`; at most 5 requests per
    30 s without a key, so NVD calls are spaced 6.5 s apart; `NVD_API_KEY` is sent when
    set), then CVE.org (`https://cveawg.mitre.org/api/cve/<id>`). A CVE none of them has
    but that a published repository advisory names as its `cve_id` (in the row's
    repositories, as above) is reported as CVE UNPUBLISHED with that advisory (assigned
    by GitHub's CNA, CVE record not public yet), not as unresolved. An abbreviated list (`CVE-2026-87983 (...), -87984 (...)`) is expanded
    with the year of the CVE before it.
  * MAL-YYYY-N, PYSEC-YYYY-N: OSV.
  * Vendor ids (JFrog `XRAY-`, codelake `CLR-`, Mistral `MAI-`): no public resolver by id.
    When the row cites an http(s) URL, the URL must answer 200; otherwise the id is listed
    as NOT CHECKED with the reason.

A record that resolves but is marked withdrawn (GitHub `withdrawn_at`, OSV `withdrawn`) is
reported as WITHDRAWN.

Read-only: GET requests only, nothing is written. Each id is fetched once, requests are
spaced by `--delay` seconds (default 0.5).

    uv run --script scripts/catalog-id-check.py [--catalog FILE] [--delay SECONDS]

Exit status: 0 when every checked id resolves and none is withdrawn, 1 when some id is
UNRESOLVED or WITHDRAWN (or a lookup errored), 2 on usage errors. CVE UNPUBLISHED and
NOT CHECKED (and NOTED, an id a row names as one that does not resolve) are listed but
do not fail the run.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_CATALOG = Path(__file__).resolve().parent.parent / "src" / "catalogs" / "builtin_catalog.json"
USER_AGENT = "rmguard-catalog-id-check/1 (read-only)"

GHSA = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b")
CVE = re.compile(r"\bCVE-(\d{4})-(\d{4,})\b")
# `, -87984` / `and -87988` after a CVE: the same year, abbreviated.
CVE_TAIL = re.compile(r"(?:,|\band|\bto)\s+-(\d{4,})\b")
OSV_ONLY = re.compile(r"\b(?:MAL|PYSEC)-\d{4}-\d+\b")
VENDOR = re.compile(r"\b(?:XRAY-\d+|CLR-\d{4}-\d+|MAI-\d{4}-\d+)\b")
URL = re.compile(r"https?://[^\s)\],;]+")
GH_URL = re.compile(r"github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/#?\s)\]]|$)")
REPO_MENTION = re.compile(r"\b([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+) (?:PR|commit|#)")

# Ids a row cites on purpose as NOT resolving (a correction note naming the id it
# replaced): listed as NOTED, never looked up, never a failure.
CITED_AS_DEAD = {
    "GHSA-7x36-8jrh-v4pw": "the hermes-agent row names it as the wrong id it replaced (13dcc64)",
}

# Rows with no registry repository (agent runtimes, editor extensions, packages whose
# registry entry names none): the GitHub repository their maintainers publish advisories in.
KNOWN_REPOS = {
    "npm:opencode-ai": "anomalyco/opencode",
    "agent-runtime:claude-code": "anthropics/claude-code",
    "agent-runtime:claude-desktop": "anthropics/claude-code",
    "agent-runtime:goose": "block/goose",
    "agent-runtime:ollama": "ollama/ollama",
    "vscode:aquasecurityofficial.trivy-vulnerability-scanner": "aquasecurity/trivy-vscode-extension",
}


class RateLimited(Exception):
    pass


def get(url: str, headers: dict[str, str] | None = None) -> tuple[int, dict | None]:
    """GET `url`: (status, parsed JSON or None). 404 is a status, not an exception."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
            try:
                return resp.status, json.loads(body)
            except ValueError:
                return resp.status, None
    except urllib.error.HTTPError as e:
        if e.code in (403, 429):
            raise RateLimited(f"HTTP {e.code}") from e
        return e.code, None


class Checker:
    def __init__(self, delay: float) -> None:
        self.delay = delay
        self.repo_cves: dict[str, str] = {}
        self.repo_cache: dict[str, list[str]] = {}
        self.repo_lists: dict[str, list[dict]] = {}
        self.last_nvd = 0.0
        self.github_limited = False
        self.gh_headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if os.environ.get("GITHUB_TOKEN"):
            self.gh_headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
        self.nvd_headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {}

    def pause(self) -> None:
        time.sleep(self.delay)

    def osv(self, ident: str) -> tuple[str, str]:
        self.pause()
        status, doc = get(f"https://api.osv.dev/v1/vulns/{ident}")
        if status == 200 and doc is not None:
            if doc.get("withdrawn"):
                return "WITHDRAWN", f"osv withdrawn {doc['withdrawn']}"
            return "OK", "osv"
        return "UNRESOLVED", f"osv HTTP {status}"

    def repos_of(self, row: dict) -> list[str]:
        """Candidate `owner/repo` for a row, most specific first."""
        key = f"{row.get('ecosystem')}:{row.get('name')}"
        if key in self.repo_cache:
            return self.repo_cache[key]
        out: list[str] = []
        text = row.get("advisory", "")
        for m in GH_URL.finditer(text):
            out.append(f"{m.group(1)}/{m.group(2)}")
        for m in REPO_MENTION.finditer(text):
            out.append(f"{m.group(1)}/{m.group(2)}")
        if key in KNOWN_REPOS:
            out.append(KNOWN_REPOS[key])
        eco, name = row.get("ecosystem"), row.get("name", "")
        try:
            if eco == "npm":
                self.pause()
                _, doc = get(f"https://registry.npmjs.org/{name.replace('/', '%2F')}")
                repo = (doc or {}).get("repository") or {}
                url = repo.get("url", "") if isinstance(repo, dict) else str(repo)
                out += [f"{m.group(1)}/{m.group(2)}" for m in GH_URL.finditer(url + " ")]
            elif eco == "pypi":
                self.pause()
                _, doc = get(f"https://pypi.org/pypi/{name}/json")
                info = (doc or {}).get("info") or {}
                urls = " ".join((info.get("project_urls") or {}).values()) + " " + (info.get("home_page") or "")
                out += [f"{m.group(1)}/{m.group(2)}" for m in GH_URL.finditer(urls + " ")]
        except (urllib.error.URLError, TimeoutError, RateLimited):
            pass
        seen: list[str] = []
        for r in out:
            if r.lower() not in [x.lower() for x in seen]:
                seen.append(r)
        self.repo_cache[key] = seen
        return seen

    def repo_advisory(self, ident: str, rows: list[dict]) -> tuple[str, str] | None:
        for row in rows:
            for repo in self.repos_of(row):
                self.pause()
                try:
                    status, doc = get(f"https://api.github.com/repos/{repo}/security-advisories/{ident}", self.gh_headers)
                except RateLimited:
                    return None
                if status == 200 and doc is not None:
                    if doc.get("cve_id"):
                        self.repo_cves[doc["cve_id"]] = f"{ident} in {repo}"
                    if doc.get("withdrawn_at"):
                        return "WITHDRAWN", f"repository advisory {repo}, withdrawn {doc['withdrawn_at']}"
                    return "OK", f"repository advisory {repo}"
        return None

    def repo_cve(self, ident: str, rows: list[dict]) -> str | None:
        """The published repository advisory (GHSA id) in one of the rows' repositories
        whose `cve_id` is `ident`."""
        for row in rows:
            for repo in self.repos_of(row):
                if repo not in self.repo_lists:
                    self.pause()
                    try:
                        status, doc = get(
                            f"https://api.github.com/repos/{repo}/security-advisories?per_page=100&state=published",
                            self.gh_headers,
                        )
                    except RateLimited:
                        return None
                    self.repo_lists[repo] = doc if status == 200 and isinstance(doc, list) else []
                for adv in self.repo_lists[repo]:
                    if adv.get("cve_id") == ident:
                        return f"{adv.get('ghsa_id')} in {repo}"
        return None

    def ghsa(self, ident: str, rows: list[dict]) -> tuple[str, str]:
        verdict, how = self.ghsa_global(ident)
        if verdict == "UNRESOLVED":
            found = self.repo_advisory(ident, rows)
            if found:
                return found
            how += "; no repository advisory in " + (", ".join(r for row in rows for r in self.repos_of(row)) or "no known repository")
        return verdict, how

    def ghsa_global(self, ident: str) -> tuple[str, str]:
        if not self.github_limited:
            self.pause()
            try:
                status, doc = get(f"https://api.github.com/advisories/{ident}", self.gh_headers)
            except RateLimited as e:
                print(f"note: GitHub API {e}; falling back to OSV for GHSA ids", file=sys.stderr)
                self.github_limited = True
            else:
                if status == 200 and doc is not None:
                    if doc.get("withdrawn_at"):
                        return "WITHDRAWN", f"github withdrawn {doc['withdrawn_at']}"
                    return "OK", "github"
                return "UNRESOLVED", f"github HTTP {status}"
        return self.osv(ident)

    def cve_org(self, ident: str) -> tuple[str, str]:
        self.pause()
        status, doc = get(f"https://cveawg.mitre.org/api/cve/{ident}")
        if status == 200 and doc is not None:
            state = (doc.get("cveMetadata") or {}).get("state")
            return ("WITHDRAWN", "cve.org REJECTED") if state == "REJECTED" else ("OK", "cve.org")
        return "UNRESOLVED", f"cve.org HTTP {status}"

    def nvd(self, ident: str) -> tuple[str, str]:
        wait = (0.7 if self.nvd_headers else 6.5) - (time.monotonic() - self.last_nvd)
        if wait > 0:
            time.sleep(wait)
        self.last_nvd = time.monotonic()
        try:
            status, doc = get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={ident}", self.nvd_headers)
        except RateLimited as e:
            return "ERROR", f"nvd {e}"
        if status == 200 and doc is not None and doc.get("totalResults", 0) > 0:
            vuln = doc["vulnerabilities"][0]["cve"]
            if vuln.get("vulnStatus") == "Rejected":
                return "WITHDRAWN", "nvd Rejected"
            return "OK", "nvd"
        return "UNRESOLVED", f"nvd HTTP {status}, {0 if doc is None else doc.get('totalResults', 0)} results"

    def cve(self, ident: str, rows: list[dict]) -> tuple[str, str]:
        verdict, how = self.osv(ident)
        if verdict != "UNRESOLVED":
            return verdict, how
        v2, how2 = self.nvd(ident)
        if v2 != "UNRESOLVED":
            return v2, how2
        v3, how3 = self.cve_org(ident)
        if v3 != "UNRESOLVED":
            return v3, how3
        trail = f"{how}; {how2}; {how3}"
        named = self.repo_cves.get(ident) or self.repo_cve(ident, rows)
        if named:
            return "CVE UNPUBLISHED", f"named by repository advisory {named}; {trail}"
        return "UNRESOLVED", trail

    def url(self, url: str) -> tuple[str, str]:
        self.pause()
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return ("OK", f"url 200 {url}") if resp.status == 200 else ("UNRESOLVED", f"url {resp.status} {url}")
        except urllib.error.HTTPError as e:
            return "UNRESOLVED", f"url HTTP {e.code} {url}"


def ids_of(advisory: str) -> list[tuple[str, str]]:
    """(kind, id) for every id in one advisory text, in order of appearance."""
    out: list[tuple[str, str]] = []
    for m in GHSA.finditer(advisory):
        out.append(("ghsa", m.group(0)))
    year = None
    pos = 0
    for m in CVE.finditer(advisory):
        year = m.group(1)
        out.append(("cve", m.group(0)))
        pos = m.end()
        # Abbreviated followers up to the next full CVE id.
        nxt = CVE.search(advisory, pos)
        segment = advisory[pos : nxt.start() if nxt else len(advisory)]
        for t in CVE_TAIL.finditer(segment):
            out.append(("cve", f"CVE-{year}-{t.group(1)}"))
    for m in OSV_ONLY.finditer(advisory):
        out.append(("osv", m.group(0)))
    for m in VENDOR.finditer(advisory):
        out.append(("vendor", m.group(0)))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    ap.add_argument("--delay", type=float, default=0.5)
    args = ap.parse_args()
    try:
        rows = json.loads(args.catalog.read_text())
    except (OSError, ValueError) as e:
        print(f"error: {args.catalog}: {e}", file=sys.stderr)
        return 2

    where: dict[tuple[str, str], list[str]] = {}
    cited_rows: dict[tuple[str, str], list[dict]] = {}
    urls: dict[str, list[str]] = {}
    for r in rows:
        name = f"{r.get('ecosystem')}:{r.get('name')}"
        text = r.get("advisory", "")
        for key in ids_of(text):
            where.setdefault(key, []).append(name)
            cited_rows.setdefault(key, []).append(r)
        if any(k == "vendor" for k, _ in ids_of(text)):
            urls[name] = URL.findall(text)
    # GHSA first: a repository advisory's `cve_id` explains a CVE whose record is not public.
    order = {"ghsa": 0, "osv": 1, "cve": 2, "vendor": 3}

    chk = Checker(args.delay)
    bad = 0
    counts: dict[str, int] = {}
    for (kind, ident), names in sorted(where.items(), key=lambda kv: (order[kv[0][0]], kv[0][1])):
        try:
            if ident in CITED_AS_DEAD:
                verdict, how = "NOTED", CITED_AS_DEAD[ident]
            elif kind == "ghsa":
                verdict, how = chk.ghsa(ident, cited_rows[(kind, ident)])
            elif kind == "cve":
                verdict, how = chk.cve(ident, cited_rows[(kind, ident)])
            elif kind == "osv":
                verdict, how = chk.osv(ident)
            else:
                cited = [u for n in names for u in urls.get(n, [])]
                if cited:
                    verdict, how = chk.url(cited[0])
                else:
                    verdict, how = "NOT CHECKED", "vendor id with no resolver; the row cites no URL"
        except (urllib.error.URLError, TimeoutError, RateLimited) as e:
            verdict, how = "ERROR", str(e)
        counts[verdict] = counts.get(verdict, 0) + 1
        if verdict != "OK":
            print(f"{verdict:<12} {ident:<22} ({how}) rows: {', '.join(sorted(set(names)))}")
        if verdict in ("UNRESOLVED", "WITHDRAWN", "ERROR"):
            bad += 1
    summary = ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))
    print(f"{len(where)} distinct ids in {len(rows)} rows: {summary}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
