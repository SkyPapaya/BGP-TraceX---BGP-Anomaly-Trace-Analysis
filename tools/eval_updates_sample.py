"""
为对比评测从 Step1 的 suspicious_updates 中抽取 Top-K 条「高危」更新。

高危启发式（与 update_fetcher / RIS 的 reason 字段对齐）：
- ORIGIN_MISMATCH：Origin 与合法 owner 不一致（劫持类优先）
- VALLEY_FREE_VIOLATION：路径商业关系异常（泄露类）
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


REASON_SCORE: Dict[str, float] = {
    "ORIGIN_MISMATCH": 100.0,
    "VALLEY_FREE_VIOLATION": 78.0,
    "FALLBACK": 42.0,
    "BENIGN_FALLBACK": 12.0,
}


def _path_len(as_path: str) -> int:
    return len([p for p in str(as_path or "").replace(",", " ").split() if p.strip().isdigit()])


def risk_score(update: Dict[str, Any]) -> float:
    reason = str(update.get("reason", "") or "").upper()
    base = REASON_SCORE.get(reason, 55.0)
    pl = _path_len(update.get("as_path", ""))
    # 同 reason 下略偏短路径（更「干净」的劫持宣告）分值略高
    if reason == "ORIGIN_MISMATCH":
        base += max(0.0, 15.0 - min(pl, 15))
    elif reason == "VALLEY_FREE_VIOLATION":
        base += max(0.0, 10.0 - min(abs(pl - 4), 10))
    return base


def _dedupe_key(u: Dict[str, Any]) -> Tuple:
    return (
        str(u.get("prefix", "")),
        str(u.get("detected_origin", "")),
        str(u.get("expected_origin", "")),
        str(u.get("as_path", "")),
    )


def select_top_high_risk_updates(
    updates: List[Dict[str, Any]],
    k: int = 10,
    pad_to_k: bool = True,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    去重后按 risk_score 降序取前 k 条；不足 k 条时在排序结果上循环补齐（保证批量输入规模一致）。

    Returns:
        (selected_updates, meta)  meta 含 padded, unique_before_pad, total_raw
    """
    if k < 1:
        k = 1
    meta: Dict[str, Any] = {"k": k, "total_raw": len(updates), "padded": False}

    if not updates:
        return [], {**meta, "unique_before_pad": 0, "padded": False}

    best: Dict[Tuple, Tuple[float, Dict[str, Any]]] = {}
    for u in updates:
        key = _dedupe_key(u)
        sc = risk_score(u)
        if key not in best or sc > best[key][0]:
            best[key] = (sc, u)

    ranked = sorted(best.values(), key=lambda x: -x[0])
    unique_list = [u for _, u in ranked]
    meta["unique_before_pad"] = len(unique_list)

    if len(unique_list) >= k:
        out = unique_list[:k]
        return out, meta

    if not pad_to_k:
        return unique_list, meta

    meta["padded"] = True
    out: List[Dict[str, Any]] = []
    i = 0
    while len(out) < k:
        out.append(dict(unique_list[i % len(unique_list)]))
        i += 1
    return out, meta


def write_eval_batch_for_event_dir(
    event_dir: Path,
    k: int = 10,
    pad_to_k: bool = True,
) -> bool:
    """读取 suspicious_updates.json，写入 eval_updates.json 与 eval_batch_meta.json。"""
    sus_path = event_dir / "suspicious_updates.json"
    if not sus_path.is_file():
        return False
    with open(sus_path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    if not isinstance(raw, list):
        return False

    selected, meta = select_top_high_risk_updates(raw, k=k, pad_to_k=pad_to_k)
    meta["event_dir"] = event_dir.name

    eval_path = event_dir / "eval_updates.json"
    with open(eval_path, "w", encoding="utf-8") as f:
        json.dump(selected, f, indent=2, ensure_ascii=False)

    meta_path = event_dir / "eval_batch_meta.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    return True
