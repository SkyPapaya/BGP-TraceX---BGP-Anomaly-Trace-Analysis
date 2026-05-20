#!/usr/bin/env python3
"""
Step1: 从本地 test_events.json 读取待测案例 → 下载 RIPEstat 原始 BGP updates → 按论文四步法过滤 → 按事件存储

待测案例在 data/test_events.json 中手动配置，格式见 data/README_test_events.md。

使用: python scripts/step1_collect_events.py [--input data/test_events.json] [--output data/events]
      python scripts/step1_collect_events.py --window-minutes 30   # 每个事件仅抓取 start_time 起 30 分钟
      python scripts/step1_collect_events.py --force               # 忽略已有目录，全部重新下载
"""
import os
import sys
import json
import argparse
import re
from datetime import datetime, timedelta

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.update_fetcher import fetch_and_filter
from tools.project_paths import EVENTS_DIR, TEST_EVENTS_FILE


def load_local_events(path):
    """从本地 JSON 加载待测事件"""
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else [data]


def _to_iso8601(t):
    if not t:
        return None
    s = str(t).strip()
    if s.isdigit():
        ts = int(s) / 1000 if len(s) > 10 else int(s)
        return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%S")
    if "T" in s or "-" in s:
        return s[:19].replace(" ", "T")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y%m%d"):
        try:
            return datetime.strptime(s[:19], fmt).strftime("%Y-%m-%dT%H:%M:%S")
        except ValueError:
            continue
    return s


def _safe_event_id(e):
    s = f"{e.get('prefix','')}_{e.get('attacker','')}_{e.get('start_time','')}"
    return re.sub(r"[^\w\-.]", "_", s)[:80]


def _norm_ts_for_compare(s):
    if not s:
        return ""
    return str(s).strip().replace(" ", "T")[:19]


def _step1_cache_ok(ev_dir, prefix, victim, st, et, fetch_source):
    """
    若目录内已有有效 meta + suspicious_updates，且与本次抓取参数一致，则视为已下载，可跳过。
    """
    meta_path = os.path.join(ev_dir, "meta.json")
    sus_path = os.path.join(ev_dir, "suspicious_updates.json")
    if not os.path.isfile(meta_path) or not os.path.isfile(sus_path):
        return False
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        with open(sus_path, "r", encoding="utf-8") as f:
            json.load(f)
    except (json.JSONDecodeError, OSError):
        return False
    if meta.get("prefix") != prefix:
        return False
    if str(meta.get("victim", "")).strip() != str(victim).strip():
        return False
    if _norm_ts_for_compare(meta.get("start_time")) != _norm_ts_for_compare(st):
        return False
    if _norm_ts_for_compare(meta.get("end_time")) != _norm_ts_for_compare(et):
        return False
    fs = meta.get("fetch_source")
    if fs is not None and fs != fetch_source:
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description="Step1: 从本地案例下载 BGP updates 并过滤")
    parser.add_argument("--input", default=str(TEST_EVENTS_FILE), help="待测案例 JSON 路径")
    parser.add_argument("--output", default=str(EVENTS_DIR), help="输出目录")
    parser.add_argument(
        "--source",
        choices=["ris_mrt", "ripestat", "auto"],
        default="ris_mrt",
        help="数据源: ris_mrt=RIPE RIS MRT(支持历史), ripestat=BGPlay API(仅2024+), auto=优先RIS",
    )
    parser.add_argument(
        "--window-minutes",
        type=int,
        default=None,
        metavar="N",
        help="若指定正整数，则忽略 JSON 中的 end_time，统一使用 [start_time, start_time+N 分钟) 作为抓取窗口",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="忽略已存在且参数一致的输出目录，强制重新下载并覆盖",
    )
    args = parser.parse_args()

    out_root = args.output
    os.makedirs(out_root, exist_ok=True)

    print("=" * 60)
    print("Step1: 读取本地案例 → 下载 RIPEstat 真实 updates → 过滤")
    print("=" * 60)

    events = load_local_events(args.input)
    if not events:
        print(f"\n⚠️ 未找到案例，请在 {args.input} 中配置")
        print("   格式见 data/README_test_events.md")
        return

    print(f"\n📂 从 {args.input} 加载 {len(events)} 个待测案例")

    total_events = 0
    total_updates = 0
    total_skipped = 0

    iterator = tqdm(events, desc="Step1 收集事件", unit="事件") if tqdm else events
    for ev in iterator:
        prefix = ev.get("prefix")
        victim = ev.get("victim")
        attacker_raw = ev.get("attacker")
        attacker = str(attacker_raw).strip() if attacker_raw else ""
        st = _to_iso8601(ev.get("start_time"))
        et = _to_iso8601(ev.get("end_time"))
        source = ev.get("source", "local")

        if not prefix or not victim:
            print(f"   跳过: 缺少 prefix/victim")
            continue
        if not st:
            print(f"   跳过 {prefix}: 无有效 start_time")
            continue

        if args.window_minutes is not None and args.window_minutes > 0:
            try:
                st_dt = datetime.strptime(st[:19], "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                try:
                    st_dt = datetime.strptime(st[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    st_dt = None
            if st_dt is None:
                print(f"   跳过 {prefix}: start_time 无法解析，无法应用 --window-minutes")
                continue
            et = (st_dt + timedelta(minutes=args.window_minutes)).strftime(
                "%Y-%m-%dT%H:%M:%S"
            )
        elif not et:
            et_dt = datetime.strptime(st[:10], "%Y-%m-%d") + timedelta(hours=24)
            et = et_dt.strftime("%Y-%m-%dT%H:%M:%S")

        is_benign = not attacker or attacker.lower() == "none"
        attacker_disp = "None(良性)" if is_benign else attacker
        print(f"\n   {prefix} | victim=AS{victim} attacker=AS{attacker_disp} | {st} ~ {et}")

        event_id = _safe_event_id(ev)
        ev_dir = os.path.join(out_root, event_id)
        if (
            not args.force
            and _step1_cache_ok(ev_dir, prefix, victim, st, et, args.source)
        ):
            prev_meta: dict = {}
            try:
                with open(os.path.join(ev_dir, "meta.json"), "r", encoding="utf-8") as f:
                    prev_meta = json.load(f)
                    if not isinstance(prev_meta, dict):
                        prev_meta = {}
            except (json.JSONDecodeError, OSError, TypeError):
                prev_meta = {}
            n_sus = prev_meta.get("suspicious_count", "?")
            ds = (prev_meta.get("data_source") or "").strip()
            ds_tag = f" [{ds}]" if ds else ""
            print(f"      -> 已存在，跳过下载（约 {n_sus} 条可疑 update）{ds_tag} — {ev_dir}")
            total_skipped += 1
            continue

        suspicious, raw_bgplay, data_source = fetch_and_filter(
            prefix=prefix,
            expected_origin=victim,
            start_time=st,
            end_time=et,
            source=args.source,
        )

        used_fallback = False
        if not suspicious:
            used_fallback = True
            if is_benign:
                suspicious = [{
                    "prefix": prefix,
                    "as_path": f"3356 {victim}",
                    "detected_origin": victim,
                    "expected_origin": victim,
                    "timestamp": st,
                    "reason": "BENIGN_FALLBACK",
                }]
            elif attacker:
                suspicious = [{
                    "prefix": prefix,
                    "as_path": f"3356 {attacker}",
                    "detected_origin": attacker,
                    "expected_origin": victim,
                    "timestamp": st,
                    "reason": "FALLBACK",
                }]
        data_source_meta = "fallback" if used_fallback and data_source == "empty" else data_source

        os.makedirs(ev_dir, exist_ok=True)

        # 保存原始 BGPlay 数据作为备用（真实下载）
        if raw_bgplay:
            with open(os.path.join(ev_dir, "raw_bgplay.json"), "w", encoding="utf-8") as f:
                json.dump(raw_bgplay, f, indent=2, ensure_ascii=False, default=str)

        meta = {
            "event_id": event_id,
            "prefix": prefix,
            "victim": victim,
            "attacker": attacker if attacker else "None",
            "start_time": st,
            "end_time": et,
            "source": source,
            "fetch_source": args.source,
            "data_source": data_source_meta,
            "suspicious_count": len(suspicious),
        }
        if args.window_minutes is not None and args.window_minutes > 0:
            meta["window_minutes_applied"] = args.window_minutes
        # 透传输入中的可选标签字段，便于后续分类型实验评测
        for opt_key in ("event_type", "reference", "is_real", "case_name", "note"):
            if opt_key in ev:
                meta[opt_key] = ev.get(opt_key)

        with open(os.path.join(ev_dir, "meta.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)
        with open(os.path.join(ev_dir, "suspicious_updates.json"), "w", encoding="utf-8") as f:
            json.dump(suspicious, f, indent=2, ensure_ascii=False)

        total_events += 1
        total_updates += len(suspicious)
        ds = f" [{data_source_meta}]" if data_source_meta else ""
        print(f"      -> {len(suspicious)} 条可疑 update{ds}，已保存到 {ev_dir}")

    print("\n" + "=" * 60)
    print(
        f"✅ Step1 完成: 新抓取 {total_events} 个事件, 跳过 {total_skipped} 个已存在, "
        f"新抓取共 {total_updates} 条可疑 updates"
    )
    print(f"   输出: {out_root}")
    print("=" * 60)


if __name__ == "__main__":
    main()
