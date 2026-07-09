#!/usr/bin/env python3
"""
Statistical analysis of marl3 benchmark results.

Reads benchmark_results/ produced by run_benchmark.py and generates:
- Per-config: TPR/FPR/precision, mean ± std, bootstrap 95% CI
- Pairwise: McNemar test (full vs each ablation)
- Cost analysis: tokens, cost-per-success, time
- Failure mode breakdown
- LaTeX-ready tables

Usage:
    python3 analyze_benchmark.py                              # default dir
    python3 analyze_benchmark.py --input benchmark_results    # explicit dir
    python3 analyze_benchmark.py --latex                      # output LaTeX tables
    python3 analyze_benchmark.py --reeval                     # re-evaluate từ raw findings.json
    python3 analyze_benchmark.py --partial                    # chạy dù chưa đủ R=5
"""
from __future__ import annotations

import argparse
import json
import sys
import statistics
from pathlib import Path

import numpy as np


# ── Ground truth VulnShop v2 (endpoint-based matching) ───────────────────────

GT_VULNSHOP = {
    "BUG-001": "/api/v2/roster",
    "BUG-002": "/control-panel",
    "BUG-003": "/api/v2/purchases",
    "BUG-004": "/api/v2/members",
    "BUG-005": "/api/v2/members/grant",
    "BUG-006": "/finance/send",
    "BUG-007": "/shop/item/add",
    "BUG-008": "/promo/redeem",
    "BUG-009": "/shop/checkout/confirm",
    "BUG-010": "/orders",
}
TOTAL_BUGS = 10


def _is_tp(endpoint: str) -> bool:
    """Endpoint substring match against VulnShop v2 ground truth."""
    ep = (endpoint or "").lower().rstrip("/")
    for gt_ep in GT_VULNSHOP.values():
        gt = gt_ep.lower().rstrip("/").split("<")[0].rstrip("/")
        if gt in ep or ep in gt:
            return True
    return False


def _eval_findings_file(findings_path: Path, usage_path: Path, meta_path: Path) -> dict:
    """Re-evaluate a single run from raw findings.json."""
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    usage = json.loads(usage_path.read_text(encoding="utf-8")) if usage_path.exists() else {}
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}

    exploited = [f for f in findings if f.get("status") == "EXPLOITED"]

    # Deduplicated TP matching
    claimed = set()
    tp_list, fp_list = [], []
    for f in exploited:
        ep = (f.get("endpoint") or "").lower().rstrip("/")
        matched = None
        for gt_key, gt_ep in GT_VULNSHOP.items():
            if gt_key in claimed:
                continue
            gt = gt_ep.lower().rstrip("/").split("<")[0].rstrip("/")
            if gt in ep or ep in gt:
                matched = gt_key
                break
        if matched:
            tp_list.append(f)
            claimed.add(matched)
        else:
            fp_list.append(f)

    tp = len(tp_list)
    fp = len(fp_list)
    fn = TOTAL_BUGS - tp
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    tpr = tp / TOTAL_BUGS
    fpr = fp / (fp + fn) if (fp + fn) > 0 else 0.0

    failure_modes: dict[str, int] = {}
    for f in findings:
        if f.get("status") != "EXPLOITED":
            mode = f.get("failure_mode") or "UNKNOWN"
            failure_modes[mode] = failure_modes.get(mode, 0) + 1

    total_tokens = usage.get("summary", {}).get("total_tokens", meta.get("total_tokens", 0))
    total_calls = usage.get("summary", {}).get("calls", meta.get("total_llm_calls", 0))

    return {
        "status": "OK",
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(precision, 4),
        "recall_tpr": round(tpr, 4),
        "fpr": round(fpr, 4),
        "total_tokens": total_tokens,
        "total_llm_calls": total_calls,
        "elapsed_s": meta.get("elapsed_s", 0),
        "tp_patterns": [f.get("pattern_id") for f in tp_list],
        "fp_patterns": [f.get("pattern_id") for f in fp_list],
        "failure_modes": failure_modes,
        "total_findings": len(findings),
        "exploited_count": len(exploited),
    }


def reeval_from_raw(input_dir: Path) -> dict:
    """Scan benchmark_results/ and re-evaluate every run from raw findings.json."""
    configs = {}
    for config_dir in sorted(input_dir.iterdir()):
        if not config_dir.is_dir() or config_dir.name.startswith("."):
            continue
        runs = []
        for run_dir in sorted(config_dir.iterdir()):
            if not run_dir.is_dir() or not run_dir.name.startswith("run_"):
                continue
            ws_base = run_dir / "workspace"
            if not ws_base.exists():
                continue
            # Find workspace subdirectory that has findings.json
            ws_dirs = [d for d in ws_base.iterdir() if d.is_dir() and (d / "findings.json").exists()]
            if not ws_dirs:
                continue
            ws = sorted(ws_dirs, key=lambda d: d.stat().st_mtime)[-1]  # latest with findings
            findings_path = ws / "findings.json"
            result = _eval_findings_file(
                findings_path,
                ws / "usage.json",
                ws / "run_metadata.json",
            )
            result["run_index"] = int(run_dir.name.split("_")[1])
            runs.append(result)

        if not runs:
            continue

        ok_runs = [r for r in runs if r.get("status") == "OK"]
        if not ok_runs:
            configs[config_dir.name] = {"config": config_dir.name, "successful_runs": 0, "runs": runs}
            continue

        def _agg(key):
            vals = [r[key] for r in ok_runs]
            return {
                "mean": statistics.mean(vals),
                "std": statistics.stdev(vals) if len(vals) > 1 else 0.0,
                "values": vals,
            }

        configs[config_dir.name] = {
            "config": config_dir.name,
            "successful_runs": len(ok_runs),
            "tp": _agg("tp"),
            "fp": _agg("fp"),
            "tpr": _agg("recall_tpr"),
            "fpr": _agg("fpr"),
            "precision": _agg("precision"),
            "tokens": _agg("total_tokens"),
            "elapsed_s": _agg("elapsed_s"),
            "runs": ok_runs,
        }

    return configs


# ── Bootstrap 95% CI ─────────────────────────────────────────────────────────

def bootstrap_ci(values: list[float], n_bootstrap: int = 10000, ci: float = 0.95) -> tuple[float, float]:
    """Compute bootstrap confidence interval for the mean."""
    if len(values) < 2:
        return (values[0] if values else 0.0, values[0] if values else 0.0)
    arr = np.array(values)
    rng = np.random.default_rng(42)  # deterministic seed for reproducibility
    boot_means = np.array([
        rng.choice(arr, size=len(arr), replace=True).mean()
        for _ in range(n_bootstrap)
    ])
    alpha = (1 - ci) / 2
    lo = float(np.percentile(boot_means, alpha * 100))
    hi = float(np.percentile(boot_means, (1 - alpha) * 100))
    return (lo, hi)


# ── McNemar's Test ───────────────────────────────────────────────────────────

def mcnemar_test(full_results: list[list[str]], ablation_results: list[list[str]],
                 ground_truth_count: int) -> dict:
    """McNemar's test comparing full vs ablation on paired per-bug outcomes.

    full_results: list of runs, each run is list of pattern_ids that were TP.
    ablation_results: same structure.

    We aggregate across runs (majority vote per bug pattern) and then build
    the 2x2 contingency table.
    """
    # Get all patterns from ground truth
    from run_benchmark import VULNSHOP_GROUND_TRUTH
    all_patterns = list({v["pattern_id"] for v in VULNSHOP_GROUND_TRUTH.values()})

    def _majority_hit(runs_patterns: list[list[str]], pattern: str) -> bool:
        """Pattern was found in >50% of runs."""
        hits = sum(1 for run_pats in runs_patterns if pattern in run_pats)
        return hits > len(runs_patterns) / 2

    # Build 2x2 table
    b = 0  # full correct, ablation wrong
    c = 0  # full wrong, ablation correct

    for pat in all_patterns:
        full_hit = _majority_hit(full_results, pat)
        abl_hit = _majority_hit(ablation_results, pat)
        if full_hit and not abl_hit:
            b += 1
        elif not full_hit and abl_hit:
            c += 1

    # McNemar statistic (with continuity correction for small samples)
    if b + c == 0:
        return {"b": b, "c": c, "statistic": 0.0, "p_value": 1.0, "significant": False}

    statistic = (abs(b - c) - 1) ** 2 / (b + c) if (b + c) > 0 else 0.0

    # Chi-squared p-value (1 df)
    try:
        from scipy.stats import chi2
        p_value = 1 - chi2.cdf(statistic, df=1)
    except ImportError:
        # Fallback: approximate p-value
        import math
        # Using complementary error function approximation
        z = math.sqrt(statistic) if statistic > 0 else 0
        p_value = 2 * (1 - _norm_cdf(z))

    return {
        "b": b, "c": c,
        "statistic": round(statistic, 4),
        "p_value": round(p_value, 4),
        "significant": p_value < 0.05,
    }


def _norm_cdf(x: float) -> float:
    """Standard normal CDF approximation."""
    import math
    return 0.5 * (1 + math.erf(x / math.sqrt(2)))


# ── Cost Analysis ────────────────────────────────────────────────────────────

# Approximate cost per 1M tokens (minimax-m2.5:cloud via proxy)
COST_PER_M_TOKENS = 0.50  # $0.50 per 1M tokens (estimate for minimax)


def cost_per_success(tokens: float, tp: float) -> float:
    """Dollar cost per true positive found."""
    cost = tokens * COST_PER_M_TOKENS / 1_000_000
    return cost / tp if tp > 0 else float("inf")


# ── Main Analysis ────────────────────────────────────────────────────────────

def analyze(input_dir: Path, latex: bool = False):
    master_path = input_dir / "benchmark_master.json"
    if not master_path.exists():
        # Try reading individual config summaries
        configs = {}
        for config_dir in sorted(input_dir.iterdir()):
            if config_dir.is_dir() and (config_dir / "summary.json").exists():
                summary = json.loads((config_dir / "summary.json").read_text())
                configs[config_dir.name] = summary
        if not configs:
            print(f"[ERROR] No benchmark results found in {input_dir}", file=sys.stderr)
            sys.exit(1)
    else:
        master = json.loads(master_path.read_text())
        configs = master.get("configs", {})

    print("=" * 80)
    print(f"BENCHMARK ANALYSIS — {len(configs)} configurations")
    print("=" * 80)
    print()

    # ── Per-config statistics ────────────────────────────────────────────────
    print("## Per-Configuration Results (mean ± std, [95% CI])")
    print()
    header = f"{'Config':<15} {'R':>3} {'TP':>10} {'FP':>10} {'TPR':>16} {'FPR':>16} {'Precision':>16} {'Tokens':>15} {'Time(s)':>12}"
    print(header)
    print("-" * len(header))

    config_data = {}
    for name, summary in configs.items():
        if summary.get("successful_runs", 0) == 0:
            print(f"{name:<15} {'0':>3} {'N/A':>10} {'N/A':>10}")
            continue

        r = summary["successful_runs"]
        tp = summary["tp"]
        fp = summary["fp"]
        tpr = summary["tpr"]
        fpr = summary["fpr"]
        prec = summary["precision"]
        tok = summary["tokens"]
        time_s = summary["elapsed_s"]

        tp_ci = bootstrap_ci(tp["values"])
        tpr_ci = bootstrap_ci(tpr["values"])

        print(f"{name:<15} {r:>3} "
              f"{tp['mean']:>4.1f}±{tp['std']:.1f}  "
              f"{fp['mean']:>4.1f}±{fp['std']:.1f}  "
              f"{tpr['mean']:>5.2f}±{tpr['std']:.2f} [{tpr_ci[0]:.2f},{tpr_ci[1]:.2f}] "
              f"{fpr['mean']:>5.2f}±{fpr['std']:.2f}  "
              f"{prec['mean']:>5.2f}±{prec['std']:.2f}  "
              f"{tok['mean']:>10.0f}±{tok['std']:.0f} "
              f"{time_s['mean']:>6.0f}±{time_s['std']:.0f}")

        config_data[name] = summary

    print()

    # ── Cost per success ─────────────────────────────────────────────────────
    print("## Cost Analysis")
    print()
    print(f"{'Config':<15} {'Tokens/run':>12} {'$/run':>8} {'$/TP':>8}")
    print("-" * 50)
    for name, s in config_data.items():
        if s.get("successful_runs", 0) == 0:
            continue
        tok_mean = s["tokens"]["mean"]
        tp_mean = s["tp"]["mean"]
        run_cost = tok_mean * COST_PER_M_TOKENS / 1_000_000
        tp_cost = cost_per_success(tok_mean, tp_mean)
        print(f"{name:<15} {tok_mean:>12.0f} {run_cost:>8.4f} {tp_cost:>8.4f}")
    print()

    # ── McNemar pairwise tests ───────────────────────────────────────────────
    if "full" in config_data and len(config_data) > 1:
        print("## McNemar Test: full vs each ablation")
        print()
        print(f"{'Comparison':<25} {'b':>3} {'c':>3} {'χ²':>8} {'p-value':>8} {'Significant':>12}")
        print("-" * 65)

        full_runs_patterns = []
        full_summary = config_data["full"]
        for run in full_summary.get("runs", []):
            if run.get("status") == "OK":
                full_runs_patterns.append(run.get("tp_patterns", []))

        for name, s in config_data.items():
            if name == "full":
                continue
            abl_runs_patterns = []
            for run in s.get("runs", []):
                if run.get("status") == "OK":
                    abl_runs_patterns.append(run.get("tp_patterns", []))

            if full_runs_patterns and abl_runs_patterns:
                result = mcnemar_test(full_runs_patterns, abl_runs_patterns, 10)
                sig = "YES (p<0.05)" if result["significant"] else "no"
                print(f"full vs {name:<17} {result['b']:>3} {result['c']:>3} "
                      f"{result['statistic']:>8.4f} {result['p_value']:>8.4f} {sig:>12}")
        print()

    # ── Failure mode analysis ────────────────────────────────────────────────
    print("## Failure Mode Breakdown")
    print()
    all_modes = set()
    for s in config_data.values():
        for run in s.get("runs", []):
            if run.get("status") == "OK":
                for mode in run.get("failure_modes", {}).keys():
                    all_modes.add(mode)

    if all_modes:
        modes_sorted = sorted(all_modes)
        header = f"{'Config':<15}" + "".join(f"{m:>20}" for m in modes_sorted)
        print(header)
        print("-" * len(header))
        for name, s in config_data.items():
            mode_counts: dict[str, list[int]] = {m: [] for m in modes_sorted}
            for run in s.get("runs", []):
                if run.get("status") == "OK":
                    fm = run.get("failure_modes", {})
                    for m in modes_sorted:
                        mode_counts[m].append(fm.get(m, 0))
            vals = ""
            for m in modes_sorted:
                if mode_counts[m]:
                    mean = np.mean(mode_counts[m])
                    vals += f"{mean:>20.1f}"
                else:
                    vals += f"{'—':>20}"
            print(f"{name:<15}{vals}")
    print()

    # ── LaTeX output ─────────────────────────────────────────────────────────
    if latex:
        print("## LaTeX Table")
        print()
        print(r"\begin{table}[htbp]")
        print(r"\centering")
        print(r"\caption{Kết quả benchmark VulnShop (R=5, 10 lỗ hổng)}")
        print(r"\label{tab:benchmark_vulnshop}")
        print(r"\begin{tabular}{lcccccc}")
        print(r"\toprule")
        print(r"Cấu hình & R & TP & FP & TPR & FPR & Precision \\")
        print(r"\midrule")
        for name, s in config_data.items():
            if s.get("successful_runs", 0) == 0:
                continue
            tp = s["tp"]
            fp = s["fp"]
            tpr = s["tpr"]
            fpr = s["fpr"]
            prec = s["precision"]
            tpr_ci = bootstrap_ci(tpr["values"])
            escaped_name = name.replace("_", r"\_").replace("-", r"-")
            print(f"{escaped_name} & {s['successful_runs']} & "
                  f"${tp['mean']:.1f} \\pm {tp['std']:.1f}$ & "
                  f"${fp['mean']:.1f} \\pm {fp['std']:.1f}$ & "
                  f"${tpr['mean']:.2f} \\pm {tpr['std']:.2f}$ & "
                  f"${fpr['mean']:.2f} \\pm {fpr['std']:.2f}$ & "
                  f"${prec['mean']:.2f} \\pm {prec['std']:.2f}$ \\\\")
        print(r"\bottomrule")
        print(r"\end{tabular}")
        print(r"\end{table}")
        print()

        # McNemar table
        if "full" in config_data:
            print(r"\begin{table}[htbp]")
            print(r"\centering")
            print(r"\caption{McNemar test: full vs từng ablation}")
            print(r"\label{tab:mcnemar}")
            print(r"\begin{tabular}{lcccc}")
            print(r"\toprule")
            print(r"So sánh & $b$ & $c$ & $\chi^2$ & $p$ \\")
            print(r"\midrule")
            for name, s in config_data.items():
                if name == "full":
                    continue
                abl_runs_patterns = []
                for run in s.get("runs", []):
                    if run.get("status") == "OK":
                        abl_runs_patterns.append(run.get("tp_patterns", []))
                if full_runs_patterns and abl_runs_patterns:
                    result = mcnemar_test(full_runs_patterns, abl_runs_patterns, 10)
                    escaped = name.replace("_", r"\_").replace("-", r"-")
                    sig = r"\textbf{*}" if result["significant"] else ""
                    print(f"full vs {escaped} & {result['b']} & {result['c']} & "
                          f"{result['statistic']:.4f} & {result['p_value']:.4f}{sig} \\\\")
            print(r"\bottomrule")
            print(r"\end{tabular}")
            print(r"\end{table}")


def main():
    parser = argparse.ArgumentParser(description="Analyze marl3 benchmark results")
    parser.add_argument("--input", default="benchmark_results",
                        help="Input directory containing benchmark results")
    parser.add_argument("--latex", action="store_true",
                        help="Output LaTeX-formatted tables")
    parser.add_argument("--reeval", action="store_true",
                        help="Re-evaluate từ raw findings.json (bỏ qua summary.json cũ)")
    parser.add_argument("--partial", action="store_true",
                        help="Chạy analysis dù chưa đủ R=5 runs")
    args = parser.parse_args()

    input_dir = Path(args.input)

    if args.reeval:
        print(f"[re-eval] Đọc raw findings.json từ {input_dir}/...")
        configs = reeval_from_raw(input_dir)
        if not configs:
            print(f"[ERROR] Không có findings.json nào trong {input_dir}", file=sys.stderr)
            sys.exit(1)
        # Tạo structure giống master.json để analyze() dùng được
        analyze_configs(configs, latex=args.latex, partial=args.partial)
    else:
        analyze(input_dir, latex=args.latex)


def analyze_configs(configs: dict, latex: bool = False, partial: bool = False):
    """Analyze và in report từ configs dict (output của reeval_from_raw hoặc summary.json)."""
    print("=" * 90)
    print(f"BENCHMARK ANALYSIS — marl3 vs ablations (VulnShop v2, N=10 bugs)")
    print("=" * 90)
    print()

    # Cảnh báo nếu partial
    for name, s in configs.items():
        r = s.get("successful_runs", 0)
        if r < 5:
            print(f"  [PARTIAL] {name}: chỉ có {r}/5 runs xong{' (--partial mode)' if partial else ''}")
    print()

    # ── Bảng kết quả chính ───────────────────────────────────────────────────
    print("## Kết quả tổng hợp (mean ± std, [95% Bootstrap CI])")
    print()
    hdr = f"{'Config':<16} {'R':>2}  {'TP':>12}  {'FP':>12}  {'TPR':>18}  {'FPR':>12}  {'Precision':>12}  {'Tokens':>14}  {'Time(s)':>10}"
    print(hdr)
    print("-" * len(hdr))

    config_data = {}
    CONFIG_ORDER = ["full", "no-debate", "no-seeder", "no-memory", "no-proofgate"]
    ordered = [(k, configs[k]) for k in CONFIG_ORDER if k in configs]
    ordered += [(k, v) for k, v in configs.items() if k not in CONFIG_ORDER]

    for name, s in ordered:
        if s.get("successful_runs", 0) == 0:
            print(f"{name:<16}  0  {'N/A':>12}  {'N/A':>12}  {'N/A':>18}  {'N/A':>12}  {'N/A':>12}")
            continue
        r = s["successful_runs"]
        tp = s["tp"]; fp = s["fp"]; tpr = s["tpr"]; fpr = s["fpr"]; prec = s["precision"]
        tok = s["tokens"]; t = s["elapsed_s"]

        tpr_ci = bootstrap_ci(tpr["values"])
        print(f"{name:<16} {r:>2}  "
              f"{tp['mean']:>5.1f}±{tp['std']:.1f}  "
              f"{fp['mean']:>5.1f}±{fp['std']:.1f}  "
              f"{tpr['mean']:>5.2f}±{tpr['std']:.2f} [{tpr_ci[0]:.2f},{tpr_ci[1]:.2f}]  "
              f"{fpr['mean']:>5.2f}±{fpr['std']:.2f}  "
              f"{prec['mean']:>5.2f}±{prec['std']:.2f}  "
              f"{tok['mean']:>10.0f}±{tok['std']:.0f}  "
              f"{t['mean']:>6.0f}±{t['std']:.0f}")
        config_data[name] = s
    print()

    # ── Cost per success ─────────────────────────────────────────────────────
    COST_PER_M = 0.50
    print("## Chi phí per-success")
    print(f"  (giả sử $0.50/1M tokens — minimax-m2.5:cloud proxy)")
    print()
    print(f"{'Config':<16} {'Tokens/run':>12}  {'$/run':>8}  {'$/TP':>10}")
    print("-" * 52)
    for name, s in ordered:
        if s.get("successful_runs", 0) == 0:
            continue
        tok_mean = s["tokens"]["mean"]
        tp_mean = s["tp"]["mean"]
        run_cost = tok_mean * COST_PER_M / 1_000_000
        tp_cost = run_cost / tp_mean if tp_mean > 0 else float("inf")
        tp_cost_str = f"${tp_cost:.3f}" if tp_cost < 1000 else "∞"
        print(f"{name:<16} {tok_mean:>12.0f}  ${run_cost:>7.4f}  {tp_cost_str:>10}")
    print()

    # ── Failure mode breakdown ────────────────────────────────────────────────
    print("## Failure mode breakdown (mean bugs/run)")
    print()
    all_modes = set()
    for s in config_data.values():
        for run in s.get("runs", []):
            all_modes.update(run.get("failure_modes", {}).keys())

    if all_modes:
        modes = sorted(all_modes)
        print(f"{'Config':<16}" + "".join(f"{m:>24}" for m in modes))
        print("-" * (16 + 24 * len(modes)))
        for name, s in ordered:
            if name not in config_data:
                continue
            row = f"{name:<16}"
            for m in modes:
                vals = [r.get("failure_modes", {}).get(m, 0) for r in s.get("runs", [])]
                mean = statistics.mean(vals) if vals else 0
                row += f"{mean:>24.1f}"
            print(row)
    print()

    # ── McNemar test ─────────────────────────────────────────────────────────
    if "full" in config_data and len(config_data) > 1:
        print("## McNemar test: full vs mỗi ablation")
        print("   (H0: không có sự khác biệt về khả năng phát hiện bug)")
        print()
        print(f"{'So sánh':<25}  {'b':>3}  {'c':>3}  {'χ²':>8}  {'p-value':>8}  {'Ý nghĩa':>12}")
        print("-" * 68)

        full_runs_eps = []
        for run in config_data["full"].get("runs", []):
            full_runs_eps.append(run.get("tp_patterns", []))

        for name, s in ordered:
            if name == "full" or name not in config_data:
                continue
            abl_runs_eps = [r.get("tp_patterns", []) for r in s.get("runs", [])]
            if full_runs_eps and abl_runs_eps:
                res = _mcnemar(full_runs_eps, abl_runs_eps)
                sig = "✓ p<0.05" if res["significant"] else "n.s."
                print(f"full vs {name:<17}  {res['b']:>3}  {res['c']:>3}  "
                      f"{res['statistic']:>8.4f}  {res['p_value']:>8.4f}  {sig:>12}")
        print()

    # ── LaTeX ────────────────────────────────────────────────────────────────
    if latex:
        print("%" + "=" * 80)
        print("% LaTeX Tables")
        print("%" + "=" * 80)
        print()
        print(r"\begin{table}[htbp]")
        print(r"\centering")
        print(r"\caption{Kết quả thực nghiệm trên VulnShop (R=5, 10 lỗ hổng). TPR = True Positive Rate, FPR = False Positive Rate.}")
        print(r"\label{tab:benchmark_main}")
        print(r"\begin{tabular}{lrcccc}")
        print(r"\toprule")
        print(r"Cấu hình & R & TP ($\bar{x} \pm \sigma$) & FP ($\bar{x} \pm \sigma$) & TPR ($\bar{x} \pm \sigma$) & FPR ($\bar{x} \pm \sigma$) \\")
        print(r"\midrule")
        for name, s in ordered:
            if name not in config_data or s.get("successful_runs", 0) == 0:
                continue
            tp = s["tp"]; fp = s["fp"]; tpr = s["tpr"]; fpr = s["fpr"]
            r = s["successful_runs"]
            esc = name.replace("-", r"\text{-}")
            print(f"\\texttt{{{esc}}} & {r} & "
                  f"${tp['mean']:.1f} \\pm {tp['std']:.1f}$ & "
                  f"${fp['mean']:.1f} \\pm {fp['std']:.1f}$ & "
                  f"${tpr['mean']:.2f} \\pm {tpr['std']:.2f}$ & "
                  f"${fpr['mean']:.2f} \\pm {fpr['std']:.2f}$ \\\\")
        print(r"\bottomrule")
        print(r"\end{tabular}")
        print(r"\end{table}")
        print()


def _mcnemar(full_runs: list[list], abl_runs: list[list]) -> dict:
    """McNemar test — so sánh endpoint-level hits giữa full vs ablation."""
    all_eps = set(GT_VULNSHOP.values())
    b = c = 0
    for ep in all_eps:
        full_hits = sum(1 for run in full_runs if any(ep in (p or "") for p in run))
        abl_hits  = sum(1 for run in abl_runs  if any(ep in (p or "") for p in run))
        full_majority = full_hits > len(full_runs) / 2
        abl_majority  = abl_hits  > len(abl_runs)  / 2
        if full_majority and not abl_majority:
            b += 1
        elif not full_majority and abl_majority:
            c += 1

    if b + c == 0:
        return {"b": 0, "c": 0, "statistic": 0.0, "p_value": 1.0, "significant": False}

    stat = (abs(b - c) - 1) ** 2 / (b + c)
    try:
        from scipy.stats import chi2
        p = float(1 - chi2.cdf(stat, df=1))
    except ImportError:
        import math
        z = math.sqrt(stat)
        p = 2 * (1 - 0.5 * (1 + math.erf(z / math.sqrt(2))))

    return {"b": b, "c": c, "statistic": round(stat, 4), "p_value": round(p, 4), "significant": p < 0.05}


def analyze(input_dir: Path, latex: bool = False):
    """Đọc từ benchmark_master.json hoặc config summary.json."""
    master_path = input_dir / "benchmark_master.json"
    configs = {}
    if master_path.exists():
        master = json.loads(master_path.read_text())
        configs = master.get("configs", {})
    else:
        for config_dir in sorted(input_dir.iterdir()):
            if config_dir.is_dir() and (config_dir / "summary.json").exists():
                s = json.loads((config_dir / "summary.json").read_text())
                configs[config_dir.name] = s
    if not configs:
        print(f"[ERROR] Không có benchmark results trong {input_dir}", file=sys.stderr)
        sys.exit(1)
    analyze_configs(configs, latex=latex)


def main():
    parser = argparse.ArgumentParser(description="Analyze marl3 benchmark results")
    parser.add_argument("--input", default="benchmark_results",
                        help="Input directory containing benchmark results")
    parser.add_argument("--latex", action="store_true",
                        help="Output LaTeX-formatted tables")
    parser.add_argument("--reeval", action="store_true",
                        help="Re-evaluate từ raw findings.json (bỏ qua summary.json cũ)")
    parser.add_argument("--partial", action="store_true",
                        help="Chạy dù chưa đủ R=5 runs")
    args = parser.parse_args()

    input_dir = Path(args.input)
    if args.reeval:
        print(f"[re-eval] Đọc raw findings.json từ {input_dir}/...")
        configs = reeval_from_raw(input_dir)
        if not configs:
            print(f"[ERROR] Không có findings.json nào trong {input_dir}", file=sys.stderr)
            sys.exit(1)
        analyze_configs(configs, latex=args.latex, partial=args.partial)
    else:
        analyze(input_dir, latex=args.latex)


if __name__ == "__main__":
    main()
