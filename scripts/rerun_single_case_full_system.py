#!/usr/bin/env python3
"""
仅重跑「完整系统」单案例，并合并回 comparative_results_*.json（重算 methods 汇总）。

示例:
  python scripts/rerun_single_case_full_system.py \\
    --case-name "Benign control — Cloudflare DNS" \\
    --report report/evaluation/comparative_results_real.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from comparative_experiment import ComparativeExperiment, load_test_cases_from_events  # noqa: E402
from tools.project_paths import EVENTS_DIR  # noqa: E402


def _case_matches(name: str, needle: str) -> bool:
    return needle.strip().lower() in (name or "").lower()


async def main_async(args) -> int:
    cases = load_test_cases_from_events(
        events_root=args.events_dir,
        limit=None,
        top_k_per_event=args.top_k or None,
        prefer_eval_file=not args.no_prefer_eval,
        pad_top_k=not args.no_pad,
        realistic_input=not args.oracle_expected_origin,
    )
    needle = args.case_name
    case = next((c for c in cases if _case_matches(c.get("name", ""), needle)), None)
    if not case:
        print(f"❌ 未找到案例（子串匹配）: {needle!r}")
        return 1

    print(f"🔁 重跑完整系统: {case.get('name')!r}")
    exp = ComparativeExperiment(
        output_file=args.report,
        realistic_input=not args.oracle_expected_origin,
    )
    result = await exp.method1_full_system(case)

    case_type = case.get("type", "MALICIOUS")
    expected = exp._normalize_asn(case.get("expected_attacker"))
    predicted = result["attacker"]
    status = result.get("status", "UNKNOWN")
    if case_type == "BENIGN":
        is_correct = predicted == "None" and status != "MALICIOUS"
    else:
        is_correct = predicted == expected
    result["is_correct"] = is_correct
    print(f"   预测 AS{predicted} status={status} correct={is_correct}")

    report_path = Path(args.report)
    if not report_path.is_file():
        print(f"❌ 报告不存在: {report_path}")
        return 1

    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    detailed = data.get("detailed_results") or []
    updated = False
    target_name = case.get("name", "")
    for row in detailed:
        if row.get("case_name") == target_name:
            method_key = "完整系统(RAG+LLM+Tools)"
            # 深拷贝，避免后续改动污染内存中的其他结构
            row["methods"][method_key] = json.loads(json.dumps(result, default=str))
            updated = True
            break

    if not updated:
        print(f"❌ 报告中未找到同名案例: {target_name!r}")
        return 1

    data["methods"] = exp.calculate_metrics(detailed)
    data["summary"] = {
        "total_cases": len(detailed),
        "best_method": max(data["methods"].items(), key=lambda x: x[1]["accuracy"])[0],
        "fastest_method": min(data["methods"].items(), key=lambda x: x[1]["avg_latency"])[0],
    }
    meta = data.get("experiment_meta")
    if not isinstance(meta, dict):
        meta = {}
    meta["partial_rerun"] = {
        "at": datetime.now().isoformat(),
        "method": "完整系统(RAG+LLM+Tools)",
        "case_name": target_name,
    }
    data["experiment_meta"] = meta
    data["experiment_time"] = datetime.now().isoformat()

    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"✅ 已更新: {report_path}")
    m = data["methods"]["完整系统(RAG+LLM+Tools)"]
    print(f"   完整系统 准确率: {m['correct']}/{m['total']} = {m['accuracy']:.1f}%")
    return 0


def main():
    p = argparse.ArgumentParser(description="重跑单案例完整系统并写回报告")
    p.add_argument("--case-name", default="Cloudflare", help="案例名称子串（匹配 load_test_cases_from_events 的 name）")
    p.add_argument("--report", default="report/evaluation/comparative_results_real.json")
    p.add_argument("--events-dir", default=str(EVENTS_DIR))
    p.add_argument("--events-top-k", type=int, default=10)
    p.add_argument("--no-prefer-eval", action="store_true")
    p.add_argument("--no-pad", action="store_true")
    p.add_argument(
        "--oracle-expected-origin",
        action="store_true",
        help="与 comparative_experiment 一致：输入中含 expected_origin",
    )
    args = p.parse_args()
    args.top_k = args.events_top_k
    sys.exit(asyncio.run(main_async(args)))


if __name__ == "__main__":
    main()
