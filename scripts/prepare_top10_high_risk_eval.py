#!/usr/bin/env python3
"""
为 data/events 下每个已抓取事件生成 eval_updates.json：默认 Top-10 高危 suspicious updates。

前置:
  python scripts/step1_collect_events.py --input data/famous_bgp_events.json --source auto

用法:
  python scripts/prepare_top10_high_risk_eval.py
  python scripts/prepare_top10_high_risk_eval.py --k 10 --events-dir data/events
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.project_paths import EVENTS_DIR
from tools.eval_updates_sample import write_eval_batch_for_event_dir


def main():
    p = argparse.ArgumentParser(description="为每事件写入 eval_updates.json（Top-K 高危）")
    p.add_argument("--events-dir", default=str(EVENTS_DIR))
    p.add_argument("--k", type=int, default=10, help="每事件选取条数")
    p.add_argument("--no-pad", action="store_true", help="不足 K 条时不循环补齐")
    args = p.parse_args()

    root = Path(args.events_dir)
    if not root.is_dir():
        print(f"❌ 目录不存在: {root}")
        sys.exit(1)

    ok = 0
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        if not (d / "suspicious_updates.json").is_file():
            continue
        if write_eval_batch_for_event_dir(d, k=args.k, pad_to_k=not args.no_pad):
            print(f"✅ {d.name} -> eval_updates.json ({args.k} 条)")
            ok += 1
        else:
            print(f"⚠️ 跳过 {d.name}")

    print(f"\n共处理 {ok} 个事件目录")
    if ok == 0:
        print("💡 请先运行 Step1 生成 suspicious_updates.json")
        sys.exit(1)


if __name__ == "__main__":
    main()
