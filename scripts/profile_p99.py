#!/usr/bin/env python3
"""
Run load against a live SOTH proxy and generate a p99-focused profiling report.

Capabilities:
- Concurrent real HTTP(S) requests through proxy
- Optional CPU sampling (macOS `sample`, Linux `perf`)
- Pipeline trace analysis from SOTH_PIPELINE_TRACE ndjson
- Intercept DB latency summary from intercept_records

Example:
  scripts/profile_p99.py \
    --proxy-port 5074 \
    --target-url https://api.openai.com/v1/chat/completions \
    --method POST \
    --header "content-type: application/json" \
    --body-file /tmp/request.json \
    --workers 200 \
    --duration 60 \
    --trace-file /tmp/soth-pipeline.ndjson
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import dataclasses
import datetime as dt
import http.client
import json
import math
import os
import pathlib
import shutil
import sqlite3
import ssl
import statistics
import subprocess
import sys
import threading
import time
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclasses.dataclass
class RequestSpec:
    proxy_host: str
    proxy_port: int
    target_url: str
    method: str
    headers: Dict[str, str]
    body: bytes
    timeout_ms: int
    reconnect_each_request: bool


@dataclasses.dataclass
class LoadResult:
    start_epoch_ms: int
    end_epoch_ms: int
    elapsed_sec: float
    workers: int
    total: int
    ok: int
    failed: int
    ok_rps: float
    latency_ms: Dict[str, float]
    status_counts: Dict[str, int]
    error_counts: Dict[str, int]


@dataclasses.dataclass
class ProfilerHandle:
    kind: str
    output_file: pathlib.Path
    process: subprocess.Popen[Any]


def now_ms() -> int:
    return int(time.time() * 1000)


def percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    if p <= 0:
        return float(min(values))
    if p >= 100:
        return float(max(values))
    sorted_values = sorted(values)
    rank = (len(sorted_values) - 1) * (p / 100.0)
    low = int(math.floor(rank))
    high = int(math.ceil(rank))
    if low == high:
        return float(sorted_values[low])
    weight = rank - low
    return float(sorted_values[low] * (1.0 - weight) + sorted_values[high] * weight)


def stats_from_values(values: List[float]) -> Dict[str, float]:
    if not values:
        return {
            "min": 0.0,
            "mean": 0.0,
            "p50": 0.0,
            "p95": 0.0,
            "p99": 0.0,
            "p999": 0.0,
            "max": 0.0,
        }
    return {
        "min": float(min(values)),
        "mean": float(statistics.fmean(values)),
        "p50": percentile(values, 50),
        "p95": percentile(values, 95),
        "p99": percentile(values, 99),
        "p999": percentile(values, 99.9),
        "max": float(max(values)),
    }


def parse_headers(headers: Iterable[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for raw in headers:
        if ":" not in raw:
            raise ValueError(f"invalid header format (expected 'name: value'): {raw!r}")
        name, value = raw.split(":", 1)
        out[name.strip()] = value.strip()
    return out


def default_body() -> bytes:
    payload = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "profile this request path for latency"}],
        "max_tokens": 64,
    }
    return json.dumps(payload).encode("utf-8")


def make_connection(
    spec: RequestSpec, parsed_target: urllib.parse.ParseResult
) -> http.client.HTTPConnection:
    timeout = spec.timeout_ms / 1000.0
    if parsed_target.scheme == "https":
        context = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(
            host=spec.proxy_host,
            port=spec.proxy_port,
            timeout=timeout,
            context=context,
        )
        target_port = parsed_target.port or 443
        conn.set_tunnel(parsed_target.hostname, target_port)
        return conn
    if parsed_target.scheme == "http":
        return http.client.HTTPConnection(
            host=spec.proxy_host,
            port=spec.proxy_port,
            timeout=timeout,
        )
    raise ValueError(f"unsupported URL scheme: {parsed_target.scheme!r}")


def request_path(parsed_target: urllib.parse.ParseResult) -> str:
    path = parsed_target.path or "/"
    if parsed_target.query:
        path = f"{path}?{parsed_target.query}"
    return path


def worker_loop(
    worker_id: int,
    spec: RequestSpec,
    stop_at_monotonic: float,
    shared_lock: threading.Lock,
    all_latencies: List[float],
    status_counts: collections.Counter[str],
    error_counts: collections.Counter[str],
) -> None:
    del worker_id
    parsed_target = urllib.parse.urlparse(spec.target_url)
    if not parsed_target.hostname:
        raise ValueError(f"target URL missing hostname: {spec.target_url!r}")

    conn: Optional[http.client.HTTPConnection] = None
    local_latencies: List[float] = []
    local_status_counts: collections.Counter[str] = collections.Counter()
    local_error_counts: collections.Counter[str] = collections.Counter()

    try:
        while time.perf_counter() < stop_at_monotonic:
            start = time.perf_counter()
            try:
                if conn is None:
                    conn = make_connection(spec, parsed_target)

                if parsed_target.scheme == "http":
                    # HTTP proxy requests use absolute URI form.
                    req_target = spec.target_url
                else:
                    req_target = request_path(parsed_target)

                conn.request(
                    method=spec.method,
                    url=req_target,
                    body=spec.body,
                    headers=spec.headers,
                )
                resp = conn.getresponse()
                _ = resp.read()

                elapsed_ms = (time.perf_counter() - start) * 1000.0
                local_latencies.append(elapsed_ms)
                local_status_counts[str(resp.status)] += 1

                if spec.reconnect_each_request:
                    conn.close()
                    conn = None
            except Exception as exc:  # noqa: BLE001
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                local_latencies.append(elapsed_ms)
                local_error_counts[type(exc).__name__] += 1
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:  # noqa: BLE001
                        pass
                    conn = None
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
        with shared_lock:
            all_latencies.extend(local_latencies)
            status_counts.update(local_status_counts)
            error_counts.update(local_error_counts)


def run_load(spec: RequestSpec, workers: int, duration_sec: float) -> LoadResult:
    start_epoch_ms = now_ms()
    start_mono = time.perf_counter()
    stop_at = start_mono + duration_sec

    lock = threading.Lock()
    all_latencies: List[float] = []
    status_counts: collections.Counter[str] = collections.Counter()
    error_counts: collections.Counter[str] = collections.Counter()

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(
                worker_loop,
                idx,
                spec,
                stop_at,
                lock,
                all_latencies,
                status_counts,
                error_counts,
            )
            for idx in range(workers)
        ]
        for fut in futures:
            fut.result()

    end_epoch_ms = now_ms()
    elapsed = max((time.perf_counter() - start_mono), 1e-9)
    total = sum(status_counts.values()) + sum(error_counts.values())
    ok = sum(count for code, count in status_counts.items() if code.startswith("2"))
    failed = total - ok

    return LoadResult(
        start_epoch_ms=start_epoch_ms,
        end_epoch_ms=end_epoch_ms,
        elapsed_sec=elapsed,
        workers=workers,
        total=total,
        ok=ok,
        failed=failed,
        ok_rps=ok / elapsed,
        latency_ms=stats_from_values(all_latencies),
        status_counts=dict(status_counts),
        error_counts=dict(error_counts),
    )


def find_listener_pid(proxy_port: int) -> Optional[int]:
    lsof = shutil.which("lsof")
    if not lsof:
        return None
    cmd = [lsof, "-nP", f"-iTCP:{proxy_port}", "-sTCP:LISTEN", "-t"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return None
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.isdigit():
            return int(line)
    return None


def start_cpu_profiler(
    pid: Optional[int],
    duration_sec: float,
    output_dir: pathlib.Path,
    mode: str,
) -> Tuple[Optional[ProfilerHandle], str]:
    if mode == "off":
        return None, "disabled"
    if pid is None:
        return None, "skipped (proxy pid not found on port)"

    rounded = max(1, int(math.ceil(duration_sec)))

    if sys.platform == "darwin":
        sample_bin = shutil.which("sample")
        if not sample_bin:
            return None, "skipped (macOS `sample` not found)"
        output_file = output_dir / "cpu.sample.txt"
        cmd = [sample_bin, str(pid), str(rounded), "-file", str(output_file)]
        proc = subprocess.Popen(  # noqa: S603
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return ProfilerHandle("sample", output_file, proc), "running (sample)"

    if sys.platform.startswith("linux"):
        perf_bin = shutil.which("perf")
        if not perf_bin:
            return None, "skipped (linux `perf` not found)"
        output_file = output_dir / "cpu.perf.data"
        cmd = [
            perf_bin,
            "record",
            "-F",
            "99",
            "-g",
            "-p",
            str(pid),
            "-o",
            str(output_file),
            "--",
            "sleep",
            str(rounded),
        ]
        proc = subprocess.Popen(  # noqa: S603
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return ProfilerHandle("perf", output_file, proc), "running (perf record)"

    return None, f"skipped (unsupported platform: {sys.platform})"


def finalize_cpu_profiler(handle: Optional[ProfilerHandle], timeout_sec: float) -> str:
    if handle is None:
        return "none"
    try:
        handle.process.wait(timeout=max(2.0, timeout_sec))
    except subprocess.TimeoutExpired:
        handle.process.kill()
        return f"{handle.kind} timed out and was killed"
    code = handle.process.returncode
    if code == 0:
        return f"{handle.kind} complete: {handle.output_file}"
    return f"{handle.kind} exited non-zero ({code}): {handle.output_file}"


def analyze_trace_file(
    trace_file: pathlib.Path,
    start_epoch_ms: int,
    end_epoch_ms: int,
) -> Dict[str, Any]:
    if not trace_file.exists():
        return {"available": False, "reason": f"trace file not found: {trace_file}"}

    event_counts: collections.Counter[str] = collections.Counter()
    by_conn: Dict[str, Dict[str, int]] = {}
    read_lines = 0
    parse_errors = 0

    with trace_file.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            read_lines += 1
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue

            ts = int(obj.get("ts_epoch_ms", 0))
            if ts and (ts < start_epoch_ms - 2000 or ts > end_epoch_ms + 2000):
                continue

            event = str(obj.get("event", "unknown"))
            event_counts[event] += 1
            conn_id = obj.get("connection_id")
            if not conn_id:
                continue
            conn = by_conn.setdefault(str(conn_id), {})
            if event == "http_gate_outcome":
                conn.setdefault("http_gate_outcome", ts)
            elif event == "handler_decision":
                conn.setdefault("handler_decision", ts)
            elif event == "classify_started":
                conn.setdefault("classify_started", ts)
            elif event == "classify_result":
                conn.setdefault("classify_result", ts)
            elif event == "db_write" and obj.get("status") == "ok":
                conn.setdefault("db_write_ok", ts)

    gate_to_decision_ms: List[float] = []
    classify_ms: List[float] = []
    classify_to_db_ms: List[float] = []

    for conn in by_conn.values():
        if "http_gate_outcome" in conn and "handler_decision" in conn:
            delta = conn["handler_decision"] - conn["http_gate_outcome"]
            if delta >= 0:
                gate_to_decision_ms.append(float(delta))
        if "classify_started" in conn and "classify_result" in conn:
            delta = conn["classify_result"] - conn["classify_started"]
            if delta >= 0:
                classify_ms.append(float(delta))
        if "classify_result" in conn and "db_write_ok" in conn:
            delta = conn["db_write_ok"] - conn["classify_result"]
            if delta >= 0:
                classify_to_db_ms.append(float(delta))

    return {
        "available": True,
        "file": str(trace_file),
        "read_lines": read_lines,
        "parse_errors": parse_errors,
        "event_counts": dict(event_counts),
        "connections_seen": len(by_conn),
        "timings_ms": {
            "gate_to_handler_decision": stats_from_values(gate_to_decision_ms),
            "classify_started_to_result": stats_from_values(classify_ms),
            "classify_result_to_db_write_ok": stats_from_values(classify_to_db_ms),
        },
    }


def analyze_db_window(db_path: pathlib.Path, start_epoch_ms: int, end_epoch_ms: int) -> Dict[str, Any]:
    if not db_path.exists():
        return {"available": False, "reason": f"db not found: {db_path}"}
    try:
        conn = sqlite3.connect(str(db_path))
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"sqlite open failed: {exc}"}

    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT latency_ms, policy_enforced
            FROM intercept_records
            WHERE timestamp_utc >= ? AND timestamp_utc <= ? AND latency_ms IS NOT NULL
            """,
            (start_epoch_ms, end_epoch_ms),
        )
        rows = cur.fetchall()
    except Exception as exc:  # noqa: BLE001
        conn.close()
        return {"available": False, "reason": f"query failed: {exc}"}

    conn.close()
    latencies = [float(row[0]) for row in rows if row[0] is not None]
    policy_enforced_false = sum(1 for _, enforced in rows if enforced == 0)
    return {
        "available": True,
        "db_path": str(db_path),
        "rows_in_window": len(rows),
        "latency_ms": stats_from_values(latencies),
        "policy_enforced_false_rows": policy_enforced_false,
    }


def write_markdown_report(
    path: pathlib.Path,
    args: argparse.Namespace,
    pid: Optional[int],
    profiler_status_start: str,
    profiler_status_end: str,
    load: LoadResult,
    trace_summary: Dict[str, Any],
    db_summary: Dict[str, Any],
) -> None:
    lines: List[str] = []
    lines.append("# SOTH p99 Profiling Report")
    lines.append("")
    lines.append(f"- Generated: {dt.datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"- Proxy endpoint: {args.proxy_host}:{args.proxy_port}")
    lines.append(f"- Proxy pid: {pid if pid is not None else 'not found'}")
    lines.append(f"- Target URL: {args.target_url}")
    lines.append(f"- Method: {args.method}")
    lines.append(f"- Workers: {args.workers}")
    lines.append(f"- Duration (s): {args.duration}")
    lines.append(f"- CPU profiler start: {profiler_status_start}")
    lines.append(f"- CPU profiler end: {profiler_status_end}")
    lines.append("")

    lines.append("## Load Summary")
    lines.append("")
    lines.append(f"- Total requests: {load.total}")
    lines.append(f"- 2xx responses: {load.ok}")
    lines.append(f"- Failed requests: {load.failed}")
    lines.append(f"- 2xx RPS: {load.ok_rps:.2f}")
    lines.append(
        "- Latency ms: "
        f"p50={load.latency_ms['p50']:.2f}, "
        f"p95={load.latency_ms['p95']:.2f}, "
        f"p99={load.latency_ms['p99']:.2f}, "
        f"p999={load.latency_ms['p999']:.2f}, "
        f"max={load.latency_ms['max']:.2f}"
    )
    lines.append(f"- Status counts: {json.dumps(load.status_counts, sort_keys=True)}")
    lines.append(f"- Error counts: {json.dumps(load.error_counts, sort_keys=True)}")
    lines.append("")

    lines.append("## Trace Correlation")
    lines.append("")
    if not trace_summary.get("available"):
        lines.append(f"- Unavailable: {trace_summary.get('reason', 'unknown')}")
        lines.append("- Enable with: SOTH_PIPELINE_TRACE=1 and dev-pipeline-trace build.")
    else:
        timings = trace_summary.get("timings_ms", {})
        cls = timings.get("classify_started_to_result", {})
        c2d = timings.get("classify_result_to_db_write_ok", {})
        g2h = timings.get("gate_to_handler_decision", {})
        lines.append(f"- Trace file: {trace_summary.get('file')}")
        lines.append(f"- Event counts: {json.dumps(trace_summary.get('event_counts', {}), sort_keys=True)}")
        lines.append(
            "- classify_started->classify_result ms: "
            f"p50={cls.get('p50', 0.0):.2f}, p95={cls.get('p95', 0.0):.2f}, p99={cls.get('p99', 0.0):.2f}"
        )
        lines.append(
            "- classify_result->db_write_ok ms: "
            f"p50={c2d.get('p50', 0.0):.2f}, p95={c2d.get('p95', 0.0):.2f}, p99={c2d.get('p99', 0.0):.2f}"
        )
        lines.append(
            "- gate_outcome->handler_decision ms: "
            f"p50={g2h.get('p50', 0.0):.2f}, p95={g2h.get('p95', 0.0):.2f}, p99={g2h.get('p99', 0.0):.2f}"
        )
    lines.append("")

    lines.append("## DB Window Summary")
    lines.append("")
    if not db_summary.get("available"):
        lines.append(f"- Unavailable: {db_summary.get('reason', 'unknown')}")
    else:
        l = db_summary["latency_ms"]
        lines.append(f"- DB path: {db_summary.get('db_path')}")
        lines.append(f"- Rows in window: {db_summary.get('rows_in_window')}")
        lines.append(
            "- intercept_records.latency_ms: "
            f"p50={l['p50']:.2f}, p95={l['p95']:.2f}, p99={l['p99']:.2f}, max={l['max']:.2f}"
        )
        lines.append(
            f"- policy_enforced=false rows: {db_summary.get('policy_enforced_false_rows', 0)}"
        )
    lines.append("")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SOTH proxy p99 profiling runner")
    parser.add_argument("--proxy-host", default="127.0.0.1")
    parser.add_argument("--proxy-port", type=int, default=5074)
    parser.add_argument("--target-url", required=True)
    parser.add_argument("--method", default="POST")
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        help="HTTP header in 'name: value' form; can be repeated",
    )
    parser.add_argument("--body-file", default=None)
    parser.add_argument("--body", default=None)
    parser.add_argument("--workers", type=int, default=200)
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument("--timeout-ms", type=int, default=15000)
    parser.add_argument("--reconnect-each-request", action="store_true")
    parser.add_argument("--trace-file", default="/tmp/soth-pipeline.ndjson")
    parser.add_argument(
        "--db-path",
        default=os.path.expanduser("~/.soth/logs/events.db"),
    )
    parser.add_argument(
        "--cpu-profiler",
        choices=["auto", "off"],
        default="auto",
        help="attach sample/perf while load runs",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="output directory; default /tmp/soth-p99-<timestamp>",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = pathlib.Path(args.output_dir or f"/tmp/soth-p99-{ts}").resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        headers = parse_headers(args.header)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.body_file:
        body = pathlib.Path(args.body_file).read_bytes()
    elif args.body is not None:
        body = args.body.encode("utf-8")
    else:
        body = default_body()

    headers.setdefault("content-type", "application/json")
    headers.setdefault("accept", "application/json")
    headers.setdefault("connection", "keep-alive")

    spec = RequestSpec(
        proxy_host=args.proxy_host,
        proxy_port=args.proxy_port,
        target_url=args.target_url,
        method=args.method.upper(),
        headers=headers,
        body=body,
        timeout_ms=max(1, int(args.timeout_ms)),
        reconnect_each_request=bool(args.reconnect_each_request),
    )

    pid = find_listener_pid(args.proxy_port)
    profiler_handle, profiler_status_start = start_cpu_profiler(
        pid=pid,
        duration_sec=float(args.duration),
        output_dir=output_dir,
        mode=args.cpu_profiler,
    )

    load = run_load(spec, workers=max(1, int(args.workers)), duration_sec=max(0.1, float(args.duration)))

    profiler_status_end = finalize_cpu_profiler(
        profiler_handle, timeout_sec=float(args.duration) + 20.0
    )

    trace_summary = analyze_trace_file(
        pathlib.Path(args.trace_file),
        start_epoch_ms=load.start_epoch_ms,
        end_epoch_ms=load.end_epoch_ms,
    )
    db_summary = analyze_db_window(
        pathlib.Path(args.db_path),
        start_epoch_ms=load.start_epoch_ms,
        end_epoch_ms=load.end_epoch_ms,
    )

    summary = {
        "load": dataclasses.asdict(load),
        "trace": trace_summary,
        "db": db_summary,
        "meta": {
            "proxy_pid": pid,
            "output_dir": str(output_dir),
            "cpu_profiler_start": profiler_status_start,
            "cpu_profiler_end": profiler_status_end,
        },
    }

    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report_path = output_dir / "report.md"
    write_markdown_report(
        report_path,
        args=args,
        pid=pid,
        profiler_status_start=profiler_status_start,
        profiler_status_end=profiler_status_end,
        load=load,
        trace_summary=trace_summary,
        db_summary=db_summary,
    )

    print(f"output_dir={output_dir}")
    print(f"summary={summary_path}")
    print(f"report={report_path}")
    print(
        "load: "
        f"ok={load.ok} fail={load.failed} ok_rps={load.ok_rps:.2f} "
        f"p50={load.latency_ms['p50']:.2f}ms "
        f"p95={load.latency_ms['p95']:.2f}ms "
        f"p99={load.latency_ms['p99']:.2f}ms"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
