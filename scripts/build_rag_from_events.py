#!/usr/bin/env python3
"""
从 Step1 输出目录 data/events/<event_id>/ 构建 RAG 知识库语料（JSONL）。

每条记录符合 tools/rag_manager.py::load_knowledge_base 所期望的结构，
内容来自真实 meta.json + suspicious_updates.json（非 LLM 臆造）。

用法:
  python scripts/step1_collect_events.py --input data/famous_bgp_events.json --source auto
  python scripts/build_rag_from_events.py
  python build_vector_db.py --input data/rag_cases_from_events.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.project_paths import EVENTS_DIR, RAG_CASES_FROM_EVENTS_FILE


def _is_benign_attacker(attacker) -> bool:
    if attacker is None:
        return True
    s = str(attacker).strip().lower()
    return not s or s == "none"


def _infer_type(updates: list, is_benign: bool) -> str:
    if is_benign:
        return "Benign observation"
    for u in updates[:5]:
        det = str(u.get("detected_origin", "")).strip()
        exp = str(u.get("expected_origin", "")).strip()
        if det and exp and det != exp:
            return "Origin Hijack"
    return "Route Leak"


def event_dir_to_case(ev_dir: Path) -> dict | None:
    meta_path = ev_dir / "meta.json"
    sus_path = ev_dir / "suspicious_updates.json"
    if not meta_path.is_file() or not sus_path.is_file():
        return None

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    with open(sus_path, "r", encoding="utf-8") as f:
        updates = json.load(f)
    if not isinstance(updates, list) or not updates:
        return None

    event_id = meta.get("event_id") or ev_dir.name
    prefix = meta.get("prefix", "")
    victim = str(meta.get("victim", "")).strip()
    attacker_raw = meta.get("attacker")
    is_benign = _is_benign_attacker(attacker_raw)
    source = meta.get("source", meta.get("case_name", "unknown"))
    data_source = meta.get("data_source", "")

    # 规范单条 evidence（取第一条非空 path）
    first = updates[0]
    ev = {
        "prefix": first.get("prefix", prefix),
        "as_path": str(first.get("as_path", "") or ""),
        "detected_origin": str(first.get("detected_origin", "") or ""),
        "expected_origin": str(first.get("expected_origin", "") or victim),
    }

    paths_preview = []
    for u in updates[:3]:
        p = u.get("as_path")
        if p:
            paths_preview.append(str(p))
    paths_note = "; ".join(paths_preview) if paths_preview else "(no path)"

    scenario_desc = (
        f"Real BGP observations for incident '{source}'. "
        f"Prefix {prefix}, legitimate origin AS{victim}. "
        f"Data source: {data_source}. "
        f"Collected {len(updates)} suspicious/filtered update(s). "
        f"Sample AS_PATH(s): {paths_note}."
    )

    if is_benign:
        analysis_logic = (
            f"Control window: observed origin matches expected AS{victim}. "
            f"No unauthorized origin in the filtered updates; treat as benign unless tools show contradiction."
        )
        conclusion = {"attacker_as": "None", "confidence": "n/a"}
    else:
        att = str(attacker_raw).strip()
        analysis_logic = (
            f"Per event annotation, the suspected attacker AS is {att}. "
            f"Compare detected_origin vs expected_origin across updates and use path forensics to confirm."
        )
        conclusion = {"attacker_as": att, "confidence": "High"}

    return {
        "id": f"real_{event_id}"[:120],
        "type": _infer_type(updates, is_benign),
        "scenario_desc": scenario_desc,
        "evidence": ev,
        "analysis_logic": analysis_logic,
        "conclusion": conclusion,
    }


def main():
    parser = argparse.ArgumentParser(description="从 data/events 生成 RAG 用 JSONL")
    parser.add_argument(
        "--events-root",
        default=str(EVENTS_DIR),
        help="Step1 输出根目录（默认 data/events）",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=str(RAG_CASES_FROM_EVENTS_FILE),
        help="输出 JSONL 路径",
    )
    args = parser.parse_args()

    root = Path(args.events_root)
    if not root.is_dir():
        print(f"❌ 目录不存在: {root}")
        print("   请先运行: python scripts/step1_collect_events.py --input data/famous_bgp_events.json --source auto")
        sys.exit(1)

    subdirs = sorted([p for p in root.iterdir() if p.is_dir()])
    cases: list[dict] = []
    for d in subdirs:
        c = event_dir_to_case(d)
        if c:
            cases.append(c)

    if not cases:
        print(f"❌ 在 {root} 下未找到任何含 meta.json + 非空 suspicious_updates.json 的事件目录")
        sys.exit(1)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for c in cases:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    print(f"✅ 已写入 {len(cases)} 条 RAG 语料到 {out}")


if __name__ == "__main__":
    main()
