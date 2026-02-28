#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROFILES_DIR = ROOT / "qa" / "profiles"


def load_profile(name: str) -> dict[str, Any]:
    path = PROFILES_DIR / f"{name}.json"
    if not path.is_file():
        raise FileNotFoundError(f"profile not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def summarize_proxy_rows(path: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return {
            "rows": 0,
            "gate_passed": 0,
            "gate_failed": 0,
            "parse_expected": 0,
            "parse_matched": 0,
            "classify_expected": 0,
            "classify_matched": 0,
            "telemetry_expected": 0,
            "telemetry_matched": 0,
            "overall_passed": 0,
            "overall_failed": 0,
            "missing_output": str(path),
        }

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                rows.append(value)

    def b(row: dict[str, Any], key: str) -> bool:
        return bool(row.get(key))

    parse_expected = [r for r in rows if b(r, "parse_expected")]
    classify_expected = [r for r in rows if b(r, "classify_expected")]
    telemetry_expected = [r for r in rows if b(r, "telemetry_expected")]

    return {
        "rows": len(rows),
        "gate_passed": sum(1 for r in rows if b(r, "gate_pass")),
        "gate_failed": sum(1 for r in rows if not b(r, "gate_pass")),
        "parse_expected": len(parse_expected),
        "parse_matched": sum(1 for r in parse_expected if b(r, "parse_pass")),
        "classify_expected": len(classify_expected),
        "classify_matched": sum(1 for r in classify_expected if b(r, "classify_pass")),
        "telemetry_expected": len(telemetry_expected),
        "telemetry_matched": sum(1 for r in telemetry_expected if b(r, "telemetry_pass")),
        "overall_passed": sum(1 for r in rows if b(r, "overall_pass")),
        "overall_failed": sum(1 for r in rows if not b(r, "overall_pass")),
    }


def run_step(step: dict[str, Any]) -> dict[str, Any]:
    step_id = str(step.get("id") or "unnamed")
    target = str(step.get("target") or "unknown")
    cmd = step.get("cmd")
    if not isinstance(cmd, list) or not cmd:
        raise ValueError(f"step {step_id} has invalid cmd")

    cwd = ROOT / str(step.get("cwd") or ".")
    env = os.environ.copy()
    for key, value in (step.get("env") or {}).items():
        env[str(key)] = str(value)

    started = time.time()
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    duration_ms = int((time.time() - started) * 1000)

    result: dict[str, Any] = {
        "id": step_id,
        "target": target,
        "ok": proc.returncode == 0,
        "return_code": proc.returncode,
        "duration_ms": duration_ms,
        "cmd": cmd,
        "cwd": str(cwd),
        "stdout_tail": "\n".join(proc.stdout.splitlines()[-60:]),
        "stderr_tail": "\n".join(proc.stderr.splitlines()[-60:]),
    }

    kind = str(step.get("result_kind") or "")
    if kind == "proxy_ndjson":
        out_path_raw = (step.get("env") or {}).get("SOTH_GATING_CORPUS_OUT")
        if out_path_raw:
            summary = summarize_proxy_rows(Path(str(out_path_raw)))
            result["proxy_summary"] = summary
            if summary.get("rows", 0) <= 0 or summary.get("overall_failed", 0) > 0:
                result["ok"] = False

    return result


def select_steps(profile: dict[str, Any], targets: set[str]) -> list[dict[str, Any]]:
    steps = profile.get("steps")
    if not isinstance(steps, list):
        return []

    out: list[dict[str, Any]] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        target = str(step.get("target") or "")
        if "all" not in targets and target not in targets:
            continue
        out.append(step)
    return out


def print_step_result(result: dict[str, Any]) -> None:
    status = "PASS" if result.get("ok") else "FAIL"
    print(f"[{status}] {result['id']} ({result['target']}) {result['duration_ms']}ms")
    summary = result.get("proxy_summary")
    if isinstance(summary, dict):
        print(
            "  proxy rows={rows} gate={gate_passed}/{rows} parse={parse_matched}/{parse_expected} "
            "classify={classify_matched}/{classify_expected} telemetry={telemetry_matched}/{telemetry_expected}".format(
                **summary
            )
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Workspace-level reusable corpus suite runner")
    parser.add_argument(
        "--profile",
        default="smoke",
        help="profile name from qa/profiles/*.json (default: smoke)",
    )
    parser.add_argument(
        "--target",
        action="append",
        choices=["all", "proxy_e2e", "classify", "policy", "detect"],
        help="target(s) to run; can be repeated; default: all",
    )
    parser.add_argument(
        "--output-json",
        default="",
        help="optional path to write suite results json",
    )
    parser.add_argument("--list", action="store_true", help="list available profiles")
    return parser.parse_args()


def list_profiles() -> int:
    print("Available profiles:")
    for path in sorted(PROFILES_DIR.glob("*.json")):
        try:
            profile = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            print(f"  {path.stem}: <invalid json>")
            continue
        description = str(profile.get("description") or "")
        steps = profile.get("steps") if isinstance(profile.get("steps"), list) else []
        print(f"  {path.stem}: {description} ({len(steps)} steps)")
    return 0


def main() -> int:
    args = parse_args()
    if args.list:
        return list_profiles()

    targets = set(args.target or ["all"])
    try:
        profile = load_profile(args.profile)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 2

    steps = select_steps(profile, targets)
    if not steps:
        print("no steps selected", file=sys.stderr)
        return 2

    print(f"Profile: {args.profile}")
    print(f"Steps: {len(steps)}")

    results: list[dict[str, Any]] = []
    for step in steps:
        result = run_step(step)
        results.append(result)
        print_step_result(result)

    failures = [r for r in results if not r.get("ok")]
    suite = {
        "profile": args.profile,
        "targets": sorted(targets),
        "total_steps": len(results),
        "failed_steps": len(failures),
        "results": results,
        "generated_at_epoch_ms": int(time.time() * 1000),
    }

    if args.output_json:
        out = Path(args.output_json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(suite, indent=2, ensure_ascii=True), encoding="utf-8")
        print(f"Wrote suite json: {out}")

    if failures:
        print("Failed steps:")
        for item in failures:
            print(f"  - {item['id']} (rc={item['return_code']})")
        return 1

    print("All steps passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
