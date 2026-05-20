#!/usr/bin/env python3
"""
一键：真实 BGP 数据抓取 → 从事件构建 RAG 语料 → 向量库 → 对比实验。

示例:
  export HF_ENDPOINT=https://hf-mirror.com   # 若 huggingface.co 不可达
  python scripts/run_comparative_real_pipeline.py
  # 使用 JSON 内完整时间窗（不截断为 30 分钟）:
  python scripts/run_comparative_real_pipeline.py --step1-window-minutes 0
  python scripts/run_comparative_real_pipeline.py --step1-force   # Step1 全部重下，不跳过已有目录
  python scripts/run_comparative_real_pipeline.py --skip-step1 --skip-rag-jsonl --skip-vector-db
  # 仅重跑四方法（保留已有 rag_db 与 events）:
  python comparative_experiment.py --source events --output report/evaluation/comparative_results_real.json
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(cmd: list[str]) -> None:
    print("+", " ".join(cmd), flush=True)
    r = subprocess.run(cmd, cwd=str(ROOT))
    if r.returncode != 0:
        sys.exit(r.returncode)


def main():
    p = argparse.ArgumentParser(description="真实数据对比实验流水线")
    p.add_argument("--input-events", default="data/famous_bgp_events.json", help="Step1 事件列表")
    p.add_argument("--step1-source", default="auto", help="传给 step1_collect_events 的 --source")
    p.add_argument(
        "--step1-window-minutes",
        type=int,
        default=30,
        metavar="N",
        help="Step1 每事件抓取窗口（分钟），从 start_time 起；0 表示不截断，沿用 JSON 的 end_time 或默认 24h",
    )
    p.add_argument(
        "--step1-force",
        action="store_true",
        help="传给 step1 的 --force（不跳过已存在事件目录）",
    )
    p.add_argument("--skip-step1", action="store_true")
    p.add_argument("--skip-rag-jsonl", action="store_true", help="跳过 scripts/build_rag_from_events.py")
    p.add_argument("--skip-vector-db", action="store_true")
    p.add_argument("--skip-experiment", action="store_true")
    p.add_argument(
        "--prepare-top10",
        action="store_true",
        help="Step1 后运行 prepare_top10_high_risk_eval.py（每事件 10 条高危 updates）",
    )
    p.add_argument("--top-k", type=int, default=10, help="--prepare-top10 时每事件条数")
    p.add_argument(
        "--experiment-output",
        default="report/evaluation/comparative_results_real.json",
        help="四方法对比结果 JSON（默认与合成实验路径区分）",
    )
    args = p.parse_args()

    py = sys.executable

    if not args.skip_step1:
        step1_cmd = [
            py,
            "scripts/step1_collect_events.py",
            "--input",
            args.input_events,
            "--source",
            args.step1_source,
        ]
        if args.step1_window_minutes and args.step1_window_minutes > 0:
            step1_cmd.extend(["--window-minutes", str(args.step1_window_minutes)])
        if args.step1_force:
            step1_cmd.append("--force")
        run(step1_cmd)

    if args.prepare_top10:
        run([py, "scripts/prepare_top10_high_risk_eval.py", "--k", str(args.top_k)])

    if not args.skip_rag_jsonl:
        run([py, "scripts/build_rag_from_events.py"])

    if not args.skip_vector_db:
        run([py, "build_vector_db.py", "--input", "data/rag_cases_from_events.jsonl"])

    if not args.skip_experiment:
        run(
            [
                py,
                "comparative_experiment.py",
                "--source",
                "events",
                "--output",
                args.experiment_output,
            ]
            + (["--events-top-k", str(args.top_k)] if args.prepare_top10 else [])
        )


if __name__ == "__main__":
    main()
