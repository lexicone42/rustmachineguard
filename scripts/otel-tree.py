#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "opentelemetry-proto>=1.20",
#     "protobuf>=4.21",
# ]
# ///
"""Print the span tree of one rmguard --otel scan.

Runs a minimal OTLP/HTTP (http/protobuf) receiver on 127.0.0.1, waits for one scan's
export, and prints:

  * the span tree, children in start order, with durations and attributes;
  * totals by span name (count, total and max duration);
  * exec spans by program and site (`rmguard.exec.program`, `rmguard.exec.site`);
  * per phase and per scanner, the time no child span covers ("uncovered"): work the
    trace does not yet explain;
  * every counter's data points with their attributes (the posture metrics
    `rmguard.findings`, `rmguard.inventory`, `rmguard.scan.truncated_scanners` first),
    and each histogram's per-attribute-set count and sum.

Either start the scan yourself:

    uv run scripts/otel-tree.py --port 4318 &
    OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 rmguard --otel

or let the script run it, with the endpoint set for you:

    uv run scripts/otel-tree.py -- target/release/rmguard --otel --format json -o /dev/null

Nothing is sent anywhere: the receiver listens on loopback and answers 200 to every
request. `--save FILE` also writes the decoded spans and metric points as JSON.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import subprocess
import sys
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from opentelemetry.proto.collector.metrics.v1 import metrics_service_pb2
from opentelemetry.proto.collector.trace.v1 import trace_service_pb2


def any_value(v):
    """Decode an AnyValue by the oneof field actually set: an int 0 is 0, not false."""
    kind = v.WhichOneof("value")
    if kind is None:
        return None
    if kind == "string_value":
        return v.string_value
    if kind == "bool_value":
        return v.bool_value
    if kind == "int_value":
        return v.int_value
    if kind == "double_value":
        return v.double_value
    if kind == "bytes_value":
        return v.bytes_value.hex()
    if kind == "array_value":
        return [any_value(x) for x in v.array_value.values]
    if kind == "kvlist_value":
        return {kv.key: any_value(kv.value) for kv in v.kvlist_value.values}
    return None


def attrs(kvs):
    return {kv.key: any_value(kv.value) for kv in kvs}


class Store:
    def __init__(self):
        self.lock = threading.Lock()
        self.spans = []
        self.metrics = set()
        # name -> {"kind", "unit", "points": [{"attrs", "value"} | {"attrs", "count", "sum"}]},
        # the last export of each (export is cumulative: the last is the scan's total).
        self.points = {}
        self.root_seen = threading.Event()
        self.last = time.monotonic()

    def add_traces(self, body):
        req = trace_service_pb2.ExportTraceServiceRequest()
        req.ParseFromString(body)
        with self.lock:
            for rs in req.resource_spans:
                for ss in rs.scope_spans:
                    for s in ss.spans:
                        span = {
                            "name": s.name,
                            "id": s.span_id.hex(),
                            "parent": s.parent_span_id.hex(),
                            "start": s.start_time_unix_nano,
                            "end": s.end_time_unix_nano,
                            "attrs": attrs(s.attributes),
                            "status": s.status.code,
                        }
                        self.spans.append(span)
                        if s.name == "rmguard.scan":
                            self.root_seen.set()
            self.last = time.monotonic()

    def add_metrics(self, body):
        req = metrics_service_pb2.ExportMetricsServiceRequest()
        req.ParseFromString(body)
        with self.lock:
            for rm in req.resource_metrics:
                for sm in rm.scope_metrics:
                    for m in sm.metrics:
                        self.metrics.add(m.name)
                        kind = m.WhichOneof("data")
                        pts = []
                        if kind == "sum":
                            for p in m.sum.data_points:
                                v = p.as_int if p.WhichOneof("value") == "as_int" else p.as_double
                                pts.append({"attrs": attrs(p.attributes), "value": v})
                        elif kind == "histogram":
                            for p in m.histogram.data_points:
                                pts.append({"attrs": attrs(p.attributes), "count": p.count, "sum": p.sum})
                        self.points[m.name] = {"kind": kind, "unit": m.unit, "points": pts}
            self.last = time.monotonic()


def make_handler(store):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            n = int(self.headers.get("content-length") or 0)
            body = self.rfile.read(n)
            if (self.headers.get("content-encoding") or "").lower() == "gzip":
                body = gzip.decompress(body)
            try:
                if self.path.endswith("/v1/traces"):
                    store.add_traces(body)
                elif self.path.endswith("/v1/metrics"):
                    store.add_metrics(body)
            except Exception as e:  # a malformed body is reported, not fatal
                print(f"otel-tree: could not decode {self.path}: {e}", file=sys.stderr)
            self.send_response(200)
            self.send_header("content-type", "application/x-protobuf")
            self.send_header("content-length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    return Handler


def ms(ns):
    return ns / 1e6


def union_ns(intervals):
    """Total length covered by a set of [start, end) intervals."""
    total = 0
    cur_s = cur_e = None
    for s, e in sorted(intervals):
        if cur_e is None or s > cur_e:
            if cur_e is not None:
                total += cur_e - cur_s
            cur_s, cur_e = s, e
        else:
            cur_e = max(cur_e, e)
    if cur_e is not None:
        total += cur_e - cur_s
    return total


HIDDEN = {"rmguard.phase", "rmguard.scanner", "rmguard.duration_ms", "rmguard.exec.site"}


def label(span):
    a = {k: v for k, v in span["attrs"].items() if k not in HIDDEN}
    short = " ".join(f"{k.removeprefix('rmguard.')}={v}" for k, v in sorted(a.items()))
    return short


POSTURE = ("rmguard.findings", "rmguard.inventory", "rmguard.scan.truncated_scanners")


def print_points(points, out):
    names = [n for n in POSTURE if n in points] + sorted(n for n in points if n not in POSTURE)
    print("\nmetric data points (last export):", file=out)
    for name in names:
        m = points[name]
        print(f"  {name} [{m['kind']}, {m['unit']}] {len(m['points'])} point(s)", file=out)
        rows = []
        for p in m["points"]:
            a = ", ".join(f"{k}={v}" for k, v in sorted(p["attrs"].items())) or "(no attributes)"
            if "value" in p:
                rows.append((a, f"{p['value']}"))
            else:
                rows.append((a, f"count={p['count']} sum={p['sum']:.4f}s"))
        for a, v in sorted(rows):
            print(f"    {a:<72} {v}", file=out)


def print_report(spans, metrics, max_depth, min_ms, out):
    by_id = {s["id"]: s for s in spans}
    children = defaultdict(list)
    roots = []
    for s in spans:
        if s["parent"] and s["parent"] in by_id:
            children[s["parent"]].append(s)
        else:
            roots.append(s)
    for c in children.values():
        c.sort(key=lambda s: s["start"])
    roots.sort(key=lambda s: s["start"])

    print("== span tree (ms) ==", file=out)

    def walk(s, depth):
        d = ms(s["end"] - s["start"])
        if depth > 0 and d < min_ms and not children.get(s["id"]):
            return
        err = "  [error]" if s["status"] == 2 else ""
        print(f"{'  ' * depth}{s['name']:<{max(1, 44 - 2 * depth)}} {d:9.1f}  {label(s)}{err}", file=out)
        if depth + 1 > max_depth:
            return
        kids = children.get(s["id"], [])
        # Collapse runs of small, identical leaf spans (one per project walk, say).
        i = 0
        while i < len(kids):
            k = kids[i]
            j = i
            while (
                j + 1 < len(kids)
                and kids[j + 1]["name"] == k["name"]
                and not children.get(kids[j + 1]["id"])
                and not children.get(k["id"])
                and label(kids[j + 1]) == label(k)
            ):
                j += 1
            if j > i:
                tot = sum(ms(x["end"] - x["start"]) for x in kids[i : j + 1])
                print(
                    f"{'  ' * (depth + 1)}{k['name'] + f' x{j - i + 1}':<{max(1, 42 - 2 * depth)}} {tot:9.1f}  {label(k)}",
                    file=out,
                )
            else:
                walk(k, depth + 1)
            i = j + 1

    for r in roots:
        walk(r, 0)

    print("\n== totals by span name ==", file=out)
    agg = defaultdict(lambda: [0, 0.0, 0.0])
    for s in spans:
        d = ms(s["end"] - s["start"])
        a = agg[s["name"]]
        a[0] += 1
        a[1] += d
        a[2] = max(a[2], d)
    print(f"{'name':<34} {'count':>6} {'total':>10} {'max':>9}", file=out)
    for name, (n, tot, mx) in sorted(agg.items(), key=lambda kv: -kv[1][1]):
        print(f"{name:<34} {n:>6} {tot:>10.1f} {mx:>9.1f}", file=out)

    print("\n== exec by program ==", file=out)
    ex = defaultdict(lambda: [0, 0.0])
    for s in spans:
        if s["name"].startswith("exec."):
            key = (s["attrs"].get("rmguard.exec.program", "?"), s["attrs"].get("rmguard.exec.site", "?"))
            ex[key][0] += 1
            ex[key][1] += ms(s["end"] - s["start"])
    print(f"{'program':<26} {'site':<20} {'count':>6} {'total':>10}", file=out)
    for (prog, site), (n, tot) in sorted(ex.items(), key=lambda kv: -kv[1][1]):
        print(f"{prog:<26} {site:<20} {n:>6} {tot:>10.1f}", file=out)

    print("\n== uncovered time (no child span) ==", file=out)
    print(f"{'span':<34} {'duration':>10} {'covered':>10} {'uncovered':>10}", file=out)
    for s in sorted(spans, key=lambda s: s["start"]):
        if not (s["name"].startswith("phase.") or s["name"].startswith("scanner.") or s["name"] == "rmguard.scan"):
            continue
        d = s["end"] - s["start"]
        kids = children.get(s["id"], [])
        if not kids and not s["name"].startswith("phase."):
            continue
        cov = union_ns([(max(k["start"], s["start"]), min(k["end"], s["end"])) for k in kids])
        print(f"{s['name']:<34} {ms(d):>10.1f} {ms(cov):>10.1f} {ms(d - cov):>10.1f}", file=out)

    print(f"\nmetric names ({len(metrics)}): {', '.join(sorted(metrics))}", file=out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=4318, help="port to listen on (0: any free port)")
    ap.add_argument("--timeout", type=float, default=120, help="seconds to wait for the root span")
    ap.add_argument("--settle", type=float, default=1.0, help="seconds of quiet after the root span")
    ap.add_argument("--depth", type=int, default=6, help="tree depth to print")
    ap.add_argument("--min-ms", type=float, default=0.0, help="hide leaf spans shorter than this")
    ap.add_argument("--save", help="also write the decoded spans as JSON here")
    ap.add_argument("command", nargs=argparse.REMAINDER, help="-- rmguard --otel ... (optional)")
    args = ap.parse_args()

    store = Store()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(store))
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    endpoint = f"http://127.0.0.1:{port}"

    cmd = args.command[1:] if args.command[:1] == ["--"] else args.command
    proc = None
    if cmd:
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("OTEL_")}
        env["OTEL_EXPORTER_OTLP_ENDPOINT"] = endpoint
        t0 = time.monotonic()
        proc = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL)
        rc = proc.wait()
        print(f"otel-tree: command exited {rc} after {time.monotonic() - t0:.2f} s", file=sys.stderr)
    else:
        print(f"otel-tree: listening on {endpoint}; run rmguard --otel with "
              f"OTEL_EXPORTER_OTLP_ENDPOINT={endpoint}", file=sys.stderr)

    if not store.root_seen.wait(args.timeout):
        print("otel-tree: no rmguard.scan span arrived", file=sys.stderr)
        server.shutdown()
        return 1
    while time.monotonic() - store.last < args.settle:
        time.sleep(0.05)
    server.shutdown()

    with store.lock:
        spans = list(store.spans)
        metrics = set(store.metrics)
        points = dict(store.points)
    if args.save:
        with open(args.save, "w") as f:
            json.dump({"spans": spans, "metrics": sorted(metrics), "points": points}, f, indent=1)
    print_report(spans, metrics, args.depth, args.min_ms, sys.stdout)
    print_points(points, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
