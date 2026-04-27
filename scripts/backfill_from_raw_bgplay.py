#!/usr/bin/env python3
"""
对仅有 raw_bgplay.json（无 meta/suspicious）的事件目录，用 famous_bgp_events.json 对齐案例并生成
meta.json + suspicious_updates.json（与 Step1 逻辑一致：filter + 空则 fallback）。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.project_paths import COMPARATIVE_EVENTS_FILE, EVENTS_DIR
from tools.update_fetcher import filter_suspicious_updates
from tools.config_loader import get_known_prefix_origin


def _safe_event_id(e):
    s = f"{e.get('prefix', '')}_{e.get('attacker', '')}_{e.get('start_time', '')}"
    return re.sub(r"[^\w\-.]", "_", s)[:80]


def _to_iso8601(t):
    if not t:
        return None
    s = str(t).strip()
    if "T" in s or "-" in s:
        return s[:19].replace(" ", "T")
    return s[:19] if s else None


def main():
    p = argparse.ArgumentParser(description="从 raw_bgplay.json 回填 meta + suspicious")
    p.add_argument(
        "--events",
        default=str(COMPARATIVE_EVENTS_FILE),
        help="案例列表 JSON（默认 famous_bgp_events.json）",
    )
    p.add_argument("--events-dir", default=str(EVENTS_DIR))
    p.add_argument("--overwrite", action="store_true", help="已存在 meta/suspicious 时也重写")
    args = p.parse_args()

    with open(args.events, "r", encoding="utf-8") as f:
        raw_list = json.load(f)
    by_id = {_safe_event_id(e): e for e in raw_list}

    root = Path(args.events_dir)
    known = get_known_prefix_origin()
    n = 0

    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        if not (d / "raw_bgplay.json").is_file():
            continue
        if (d / "meta.json").is_file() and (d / "suspicious_updates.json").is_file() and not args.overwrite:
            continue

        ev = by_id.get(d.name)
        if not ev:
            print(f"⚠️ 无匹配案例，跳过: {d.name}")
            continue

        with open(d / "raw_bgplay.json", "r", encoding="utf-8") as f:
            bg = json.load(f)
        if not isinstance(bg, dict):
            print(f"⚠️ raw_bgplay 非对象: {d.name}")
            continue

        prefix = ev.get("prefix")
        victim = str(ev.get("victim", "")).strip()
        attacker_raw = ev.get("attacker")
        attacker = str(attacker_raw).strip() if attacker_raw else ""
        st = bg.get("query_starttime") or _to_iso8601(ev.get("start_time"))
        et = bg.get("query_endtime") or _to_iso8601(ev.get("end_time"))
        if not st or not et:
            st = _to_iso8601(ev.get("start_time"))
            et = _to_iso8601(ev.get("end_time"))

        suspicious = filter_suspicious_updates(
            bg, prefix, victim, known_prefix_origin=known
        )

        is_benign = not attacker or attacker.lower() == "none"
        used_fallback = False
        if not suspicious:
            used_fallback = True
            if is_benign:
                suspicious = [
                    {
                        "prefix": prefix,
                        "as_path": f"3356 {victim}",
                        "detected_origin": victim,
                        "expected_origin": victim,
                        "timestamp": st,
                        "reason": "BENIGN_FALLBACK",
                    }
                ]
            elif attacker:
                suspicious = [
                    {
                        "prefix": prefix,
                        "as_path": f"3356 {attacker}",
                        "detected_origin": attacker,
                        "expected_origin": victim,
                        "timestamp": st,
                        "reason": "FALLBACK",
                    }
                ]

        label = ev.get("source", "local")
        meta = {
            "event_id": d.name,
            "prefix": prefix,
            "victim": victim,
            "attacker": attacker if attacker else "None",
            "start_time": st,
            "end_time": et,
            "source": label,
            "fetch_source": "ripestat",
            "data_source": "fallback" if used_fallback else "ripestat",
            "suspicious_count": len(suspicious),
            "backfilled_from": "raw_bgplay.json",
        }
        for opt_key in ("event_type", "reference", "is_real", "case_name", "note", "description"):
            if opt_key in ev:
                meta[opt_key] = ev.get(opt_key)

        with open(d / "meta.json", "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)
        with open(d / "suspicious_updates.json", "w", encoding="utf-8") as f:
            json.dump(suspicious, f, indent=2, ensure_ascii=False)
        print(f"✅ {d.name} -> suspicious={len(suspicious)} fallback={used_fallback}")
        n += 1

    print(f"\n共回填 {n} 个目录")
    if n == 0:
        print("（无需回填或目录名与 famous_bgp_events 不一致）")


if __name__ == "__main__":
    main()
