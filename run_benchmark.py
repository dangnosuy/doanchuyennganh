#!/usr/bin/env python3
"""
Benchmark runner for marl3 — supports repeated runs (R=N) across multiple configs.

Usage:
    python3 run_benchmark.py                          # R=5, all 5 configs, VulnShop
    python3 run_benchmark.py --repeats 3 --configs full,no-debate
    python3 run_benchmark.py --target vulnshop --repeats 5

Output structure:
    benchmark_results/
      {config}/
        run_0/   → workspace symlink + run_metadata.json + findings.json + usage.json
        run_1/
        ...
      summary.json  → per-config aggregate (for analyze_benchmark.py)
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# ── Ground truth ─────────────────────────────────────────────────────────────

# Ground truth cho VulnShop v2 — mapping endpoint → bug thực sự
# Dùng endpoint matching để đánh giá TP/FP thay vì pattern_id
# (Hunt có thể label sai pattern nhưng tìm đúng endpoint = vẫn là TP)
VULNSHOP_GROUND_TRUTH = {
    "BUG-001": {"pattern_id": "BAC-01", "endpoint": "/api/v2/roster",                    "method": "GET"},
    "BUG-002": {"pattern_id": "BAC-02", "endpoint": "/control-panel",                    "method": "GET"},
    "BUG-003": {"pattern_id": "BAC-03", "endpoint": "/api/v2/purchases",                 "method": "GET"},
    "BUG-004": {"pattern_id": "BAC-03", "endpoint": "/api/v2/members",                   "method": "GET"},
    "BUG-005": {"pattern_id": "BAC-06", "endpoint": "/api/v2/members/grant",             "method": "POST"},
    "BUG-006": {"pattern_id": "BLF-01", "endpoint": "/finance/send",                     "method": "POST"},
    "BUG-007": {"pattern_id": "BLF-06", "endpoint": "/shop/item/add",                    "method": "POST"},
    "BUG-008": {"pattern_id": "Chain",  "endpoint": "/orders",                           "method": "POST"},
    "BUG-009": {"pattern_id": "Chain",  "endpoint": "/shop/checkout/confirm",            "method": "POST"},
    "BUG-010": {"pattern_id": "Chain",  "endpoint": "/orders",                           "method": "POST"},
}

# Endpoint fragments đủ để nhận dạng một TP (dùng substring match)
GT_ENDPOINT_FRAGMENTS = [
    "/api/v2/roster",
    "/control-panel",
    "/api/v2/purchases",
    "/api/v2/members",
    "/api/v2/members/grant",
    "/finance/send",
    "/shop/item/add",
    "/promo/redeem",
    "/shop/checkout/confirm",
    "/orders",
]

TARGETS = {
    "vulnshop": {
        "url": "http://localhost:5002",
        "credentials": "user:alice pass:Alice@123 user:bob pass:Bob@123",
        "ground_truth": VULNSHOP_GROUND_TRUTH,
        "total_bugs": 10,
    },
}

CONFIGS = {
    "full":         None,                                    # default config
    "no-debate":    "config/ablations/no_debate.yaml",
    "no-seeder":    "config/ablations/no_seeder.yaml",
    "no-memory":    "config/ablations/no_memory.yaml",
    "no-proofgate": "config/ablations/no_proofgate.yaml",
}


def _check_target_alive(url: str) -> bool:
    """Quick check if the target is responding."""
    import urllib.request
    try:
        urllib.request.urlopen(url, timeout=5)
        return True
    except Exception:
        return False


def _reset_vulnshop() -> None:
    """Reset VulnShop DB to clean state between runs."""
    # The VulnShop container auto-inits DB on restart
    compose_dir = Path(__file__).parent.parent / "vulnshop"
    if not compose_dir.exists():
        compose_dir = Path("/home/dangnosuy/Documents/UIT/doanchuyennganh/vulnshop")
    if compose_dir.exists():
        subprocess.run(
            ["docker", "compose", "restart"],
            cwd=str(compose_dir),
            capture_output=True,
            timeout=30,
        )
        time.sleep(5)  # wait for DB re-init


def _clear_longterm_memory() -> None:
    """Clear longterm memory DB between runs for fair/independent evaluation."""
    db_path = Path.home() / ".local/share/marl3/memory.db"
    if db_path.exists():
        try:
            import sqlite3
            conn = sqlite3.connect(str(db_path))
            conn.executescript("DELETE FROM episodes; DELETE FROM rules;")
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"  [WARN] Could not clear memory DB: {e}", file=sys.stderr)


def _run_single(target_url: str, credentials: str, config_file: str | None,
                workspace_dir: str) -> tuple[Path | None, float]:
    """Run marl3 once. Returns (workspace_path, elapsed_seconds)."""
    prompt = f"{target_url} {credentials}"
    cmd = ["marl3", "run", prompt, "--workspace", workspace_dir]
    if config_file:
        cmd.extend(["--config", config_file])

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=5400,  # 90 min max per run (= 9 bugs × 10 min wall-clock each)
            cwd=str(Path(__file__).parent),
        )
        elapsed = round(time.monotonic() - start, 2)

        # Find the workspace directory created by this run
        ws_base = Path(workspace_dir)
        if ws_base.exists():
            dirs = sorted(ws_base.iterdir(), key=lambda d: d.stat().st_mtime, reverse=True)
            for d in dirs:
                if d.is_dir() and (d / "findings.json").exists():
                    return d, elapsed

        print(f"  [WARN] No findings.json found. stdout: {result.stdout[-500:]}", file=sys.stderr)
        print(f"  [WARN] stderr: {result.stderr[-500:]}", file=sys.stderr)
        return None, elapsed

    except subprocess.TimeoutExpired:
        elapsed = round(time.monotonic() - start, 2)
        print(f"  [WARN] Run timed out after 1800s", file=sys.stderr)
        return None, elapsed


def _evaluate_run(workspace: Path, ground_truth: dict, total_bugs: int) -> dict:
    """Evaluate a single run against ground truth. Returns structured result."""
    findings_path = workspace / "findings.json"
    metadata_path = workspace / "run_metadata.json"
    usage_path = workspace / "usage.json"

    findings = []
    if findings_path.exists():
        findings = json.loads(findings_path.read_text(encoding="utf-8"))

    metadata = {}
    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

    usage = {}
    if usage_path.exists():
        usage = json.loads(usage_path.read_text(encoding="utf-8"))

    # Classify each finding as TP or FP
    # TP = EXPLOITED + endpoint khớp với một trong 10 lỗ hổng ground truth
    # Dùng endpoint matching (substring) vì Hunt có thể label pattern sai
    exploited = [f for f in findings if f.get("status") == "EXPLOITED"]
    tp_findings = []
    fp_findings = []

    # Mỗi GT endpoint chỉ được claim 1 lần (tránh double-count)
    claimed_gt = set()

    for f in exploited:
        endpoint = (f.get("endpoint") or "").lower().rstrip("/")
        is_tp = False
        matched_gt = None

        for gt_key, gt_bug in ground_truth.items():
            if gt_key in claimed_gt:
                continue
            gt_ep = gt_bug["endpoint"].lower().rstrip("/").split("<")[0].rstrip("/")
            # Substring match: finding endpoint chứa gt fragment
            if gt_ep in endpoint or endpoint in gt_ep:
                is_tp = True
                matched_gt = gt_key
                break

        if is_tp and matched_gt:
            tp_findings.append(f)
            claimed_gt.add(matched_gt)
        else:
            fp_findings.append(f)

    # Failure mode analysis for non-exploited
    failure_modes = {}
    for f in findings:
        if f.get("status") != "EXPLOITED":
            mode = f.get("failure_mode", "UNKNOWN")
            failure_modes[mode] = failure_modes.get(mode, 0) + 1

    tp = len(tp_findings)
    fp = len(fp_findings)
    fn = total_bugs - tp
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / total_bugs if total_bugs > 0 else 0.0
    fpr = fp / (fp + fn) if (fp + fn) > 0 else 0.0

    return {
        "workspace": str(workspace),
        "total_findings": len(findings),
        "exploited": len(exploited),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall_tpr": round(recall, 4),
        "fpr": round(fpr, 4),
        "total_tokens": usage.get("summary", {}).get("total_tokens", metadata.get("total_tokens", 0)),
        "total_llm_calls": usage.get("summary", {}).get("calls", metadata.get("total_llm_calls", 0)),
        "elapsed_s": metadata.get("elapsed_s", 0),
        "tp_patterns": [f.get("pattern_id") for f in tp_findings],
        "fp_patterns": [f.get("pattern_id") for f in fp_findings],
        "failure_modes": failure_modes,
        "per_bug_metrics": [
            {
                "bug_id": f.get("bug_id"),
                "pattern_id": f.get("pattern_id"),
                "status": f.get("status"),
                "debate_rounds": f.get("debate_rounds", 0),
                "verify_retries": f.get("verify_retries", 0),
                "exec_retries": f.get("exec_retries", 0),
                "elapsed_s": f.get("elapsed_s", 0),
                "failure_mode": f.get("failure_mode", ""),
            }
            for f in findings
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="marl3 benchmark runner")
    parser.add_argument("--target", default="vulnshop", choices=list(TARGETS.keys()))
    parser.add_argument("--repeats", "-R", type=int, default=5,
                        help="Number of repeated runs per config (default: 5)")
    parser.add_argument("--configs", default="full,no-debate,no-seeder,no-memory,no-proofgate",
                        help="Comma-separated config names (default: all)")
    parser.add_argument("--output", default="benchmark_results",
                        help="Output directory (default: benchmark_results)")
    parser.add_argument("--no-reset", action="store_true",
                        help="Skip VulnShop DB reset between runs")
    args = parser.parse_args()

    target = TARGETS[args.target]
    config_names = [c.strip() for c in args.configs.split(",")]
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Pre-flight check
    if not _check_target_alive(target["url"]):
        print(f"[ERROR] Target {target['url']} is not responding. Start VulnShop first.", file=sys.stderr)
        sys.exit(1)

    print(f"=== marl3 Benchmark ===")
    print(f"Target: {args.target} ({target['url']})")
    print(f"Repeats: {args.repeats}")
    print(f"Configs: {config_names}")
    print(f"Output: {output_dir}")
    print()

    all_results = {}

    for config_name in config_names:
        if config_name not in CONFIGS:
            print(f"[WARN] Unknown config '{config_name}', skipping", file=sys.stderr)
            continue

        config_file = CONFIGS[config_name]
        config_dir = output_dir / config_name
        config_dir.mkdir(parents=True, exist_ok=True)

        runs = []
        print(f"── Config: {config_name} ──")

        for run_i in range(args.repeats):
            run_dir = config_dir / f"run_{run_i}"
            run_dir.mkdir(parents=True, exist_ok=True)

            # Skip if already completed successfully (check any workspace subdir has findings.json)
            ws_base = run_dir / "workspace"
            ws_with_results = None
            if ws_base.exists():
                for ws in sorted(ws_base.iterdir(), key=lambda d: d.stat().st_mtime, reverse=True):
                    if ws.is_dir() and (ws / "findings.json").exists():
                        ws_with_results = ws
                        break
            if ws_with_results:
                result = _evaluate_run(ws_with_results, VULNSHOP_GROUND_TRUTH, 10)
                runs.append(result)
                print(f"  [{config_name}] run {run_i}/{args.repeats} — SKIP (TP={result['tp']} FP={result['fp']})")
                continue

            # Reset target between runs (clean state)
            if not args.no_reset and args.target == "vulnshop":
                print(f"  [{config_name}] run {run_i}/{args.repeats} — resetting VulnShop + memory...")
                _reset_vulnshop()
                _clear_longterm_memory()

            print(f"  [{config_name}] run {run_i}/{args.repeats} — starting...")
            ws_dir = str(run_dir / "workspace")
            workspace, elapsed = _run_single(
                target["url"], target["credentials"],
                config_file, ws_dir,
            )

            if workspace is None:
                print(f"  [{config_name}] run {run_i} — FAILED (no workspace)")
                runs.append({
                    "run_index": run_i,
                    "status": "FAILED",
                    "elapsed_s": elapsed,
                    "tp": 0, "fp": 0, "fn": target["total_bugs"],
                    "precision": 0, "recall_tpr": 0, "fpr": 0,
                    "total_tokens": 0, "total_llm_calls": 0,
                })
                continue

            # Evaluate
            result = _evaluate_run(workspace, target["ground_truth"], target["total_bugs"])
            result["run_index"] = run_i
            result["status"] = "OK"
            runs.append(result)

            # Save per-run result
            (run_dir / "eval_result.json").write_text(
                json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
            )

            print(f"  [{config_name}] run {run_i} — TP={result['tp']} FP={result['fp']} "
                  f"TPR={result['recall_tpr']:.2f} FPR={result['fpr']:.2f} "
                  f"tokens={result['total_tokens']} time={result['elapsed_s']:.0f}s")

        # Aggregate stats for this config
        ok_runs = [r for r in runs if r.get("status") == "OK"]
        if ok_runs:
            import statistics
            tps = [r["tp"] for r in ok_runs]
            fps = [r["fp"] for r in ok_runs]
            tprs = [r["recall_tpr"] for r in ok_runs]
            fprs = [r["fpr"] for r in ok_runs]
            precisions = [r["precision"] for r in ok_runs]
            tokens = [r["total_tokens"] for r in ok_runs]
            times = [r["elapsed_s"] for r in ok_runs]

            summary = {
                "config": config_name,
                "config_file": config_file,
                "repeats": args.repeats,
                "successful_runs": len(ok_runs),
                "tp":        {"mean": statistics.mean(tps), "std": statistics.stdev(tps) if len(tps) > 1 else 0, "values": tps},
                "fp":        {"mean": statistics.mean(fps), "std": statistics.stdev(fps) if len(fps) > 1 else 0, "values": fps},
                "tpr":       {"mean": statistics.mean(tprs), "std": statistics.stdev(tprs) if len(tprs) > 1 else 0, "values": tprs},
                "fpr":       {"mean": statistics.mean(fprs), "std": statistics.stdev(fprs) if len(fprs) > 1 else 0, "values": fprs},
                "precision": {"mean": statistics.mean(precisions), "std": statistics.stdev(precisions) if len(precisions) > 1 else 0, "values": precisions},
                "tokens":    {"mean": statistics.mean(tokens), "std": statistics.stdev(tokens) if len(tokens) > 1 else 0, "values": tokens},
                "elapsed_s": {"mean": statistics.mean(times), "std": statistics.stdev(times) if len(times) > 1 else 0, "values": times},
                "runs": runs,
            }
        else:
            summary = {"config": config_name, "repeats": args.repeats, "successful_runs": 0, "runs": runs}

        (config_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        all_results[config_name] = summary

        if summary.get("successful_runs", 0) > 0:
            tp = summary.get("tp", {}); fp = summary.get("fp", {})
            tpr = summary.get("tpr", {})
            print(f"  [{config_name}] aggregate: "
                  f"TP={tp.get('mean', 0):.1f}±{tp.get('std', 0):.1f} "
                  f"FP={fp.get('mean', 0):.1f}±{fp.get('std', 0):.1f} "
                  f"TPR={tpr.get('mean', 0):.2f}±{tpr.get('std', 0):.2f}")
        else:
            print(f"  [{config_name}] aggregate: 0 runs completed")
        print()

    # Save master summary
    master = {
        "target": args.target,
        "target_url": target["url"],
        "repeats": args.repeats,
        "configs": all_results,
    }
    (output_dir / "benchmark_master.json").write_text(
        json.dumps(master, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"=== Benchmark complete. Results in {output_dir}/ ===")


if __name__ == "__main__":
    main()
