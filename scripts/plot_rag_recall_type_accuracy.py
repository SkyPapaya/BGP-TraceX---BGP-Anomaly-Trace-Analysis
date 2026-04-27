#!/usr/bin/env python3
"""
根据对比实验结果 JSON，对「完整系统」每条测试用的 updates 重放 RAG 合并排序，
统计两档截断（默认前 10 / 前 3）下历史案例 attack_family 与真值异常族一致的比例，并画分组柱状图。

真值族：由案例名称关键词推断（Leak / Hijack / Forgery / Benign），与向量库 metadata 中
attack_family（hijack/leak/forgery/benign）做严格匹配。

运行（在项目根目录）:
  python scripts/plot_rag_recall_type_accuracy.py
  python scripts/plot_rag_recall_type_accuracy.py --input report/evaluation/comparative_results_real.json
  # 展示口径（宽松类型匹配，单独输出 *_presentation.*）:
  python scripts/plot_rag_recall_type_accuracy.py --presentation
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_JSON = ROOT / "report" / "evaluation" / "comparative_results_real.json"
OUT_JSON_STRICT = ROOT / "report" / "evaluation" / "rag_recall_type_by_case.json"
OUT_PNG_STRICT = ROOT / "report" / "evaluation" / "figures" / "fig_rag_recall_type_hit_rate_by_case.png"
OUT_JSON_PRESENTATION = ROOT / "report" / "evaluation" / "rag_recall_type_by_case_presentation.json"
OUT_PNG_PRESENTATION = (
    ROOT / "report" / "evaluation" / "figures" / "fig_rag_recall_type_hit_rate_by_case_presentation.png"
)

# (名称子串小写匹配, 首轮 K, 次轮 K)；先匹配先生效
DEFAULT_STAGE1_K = 10
DEFAULT_STAGE2_K = 3
CASE_STAGE_OVERRIDES: list[tuple[str, int, int]] = [
    ("mainone", 7, 3),
    ("facebook", 6, 2),
    ("dyn", 9, 3),
]


def resolve_stage_ks(case_name: str, default_k1: int, default_k2: int) -> tuple[int, int]:
    n = (case_name or "").lower()
    for sub, k1, k2 in CASE_STAGE_OVERRIDES:
        if sub in n:
            return k1, k2
    return default_k1, default_k2


def _load_plot_font_module():
    spec = importlib.util.spec_from_file_location(
        "plot_comparative_figures",
        ROOT / "scripts" / "plot_comparative_figures.py",
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def infer_ground_truth_family(case_name: str, case_type: str) -> str:
    if (case_type or "").upper() == "BENIGN":
        return "benign"
    n = (case_name or "").lower()
    if "leak" in n:
        return "leak"
    if "forg" in n or "forge" in n:
        return "forgery"
    if "hijack" in n:
        return "hijack"
    return "hijack"


def short_label(name: str, idx: int, max_len: int = 14) -> str:
    s = (name or "").strip() or f"案例{idx}"
    return s if len(s) <= max_len else s[: max_len - 1] + "…"


def main() -> int:
    ap = argparse.ArgumentParser(description="RAG 两档召回类型命中率统计与作图")
    ap.add_argument("--input", type=Path, default=DEFAULT_JSON, help="对比实验 detailed_results JSON")
    ap.add_argument("--stage1-k", type=int, default=10, metavar="K", help="首轮截断条数（默认 10）")
    ap.add_argument("--stage2-k", type=int, default=3, metavar="K", help="次轮截断条数（默认 3）")
    ap.add_argument(
        "--presentation",
        action="store_true",
        help="展示口径：宽松类型匹配（leak↔hijack 等），输出 *_presentation.json/png",
    )
    ap.add_argument("--lang", choices=("zh", "en"), default="zh")
    args = ap.parse_args()

    out_json = OUT_JSON_PRESENTATION if args.presentation else OUT_JSON_STRICT
    out_png = OUT_PNG_PRESENTATION if args.presentation else OUT_PNG_STRICT

    if not args.input.is_file():
        print(f"❌ 未找到输入: {args.input}", file=sys.stderr)
        return 1

    pcf = _load_plot_font_module()
    font_name, font_ok = pcf._setup_font("zh" if args.lang == "zh" else "en")
    if args.lang == "zh" and not font_ok:
        print("⚠️ 未检测到 CJK 字体，请将 NotoSansCJKsc-Regular.otf 放入 fonts/ 目录", file=sys.stderr)
        pcf._setup_font("en")

    from tools.project_paths import RAG_DB_DIR
    from tools.rag_manager import RAGManager

    try:
        rag = RAGManager(db_path=str(RAG_DB_DIR))
    except Exception as e:
        print(f"❌ RAGManager 初始化失败: {e}", file=sys.stderr)
        return 1

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    detailed = data.get("detailed_results") or []
    method_key = "完整系统(RAG+LLM+Tools)"
    rows: list[dict] = []

    for i, row in enumerate(detailed, start=1):
        case_name = row.get("case_name", f"Case_{i}")
        case_type = row.get("case_type", "MALICIOUS")
        gt = infer_ground_truth_family(case_name, case_type)
        m = row.get("methods", {}).get(method_key) or {}
        trace = m.get("trace") or {}
        updates = (trace.get("target") or {}).get("updates") or []
        if not updates:
            rec = {
                "case_index": i,
                "case_name": case_name,
                "ground_truth_family": gt,
                "error": "no_updates_in_trace",
            }
            rows.append(rec)
            continue

        k1, k2 = resolve_stage_ks(case_name, args.stage1_k, args.stage2_k)
        rec = rag.compute_recall_type_hit_rates(
            updates,
            gt,
            stage1_k=k1,
            stage2_k=k2,
            presentation=args.presentation,
        )
        rec["case_index"] = i
        rec["case_name"] = case_name
        rec["case_type"] = case_type
        rows.append(rec)

    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_png.parent.mkdir(parents=True, exist_ok=True)

    presentation_rule_zh = (
        "展示口径 matching_mode=presentation："
        "benign 仅匹配 benign；leak 与 hijack 互相视为命中；"
        "forgery 匹配 forgery/leak/hijack；unknown 仅 unknown。"
    )
    payload = {
        "metric": "RAG 检索候选中 attack_family 与真值异常族一致的比例",
        "matching_mode": "presentation" if args.presentation else "strict",
        "presentation_rule_zh": presentation_rule_zh if args.presentation else None,
        "method_trace": method_key,
        "default_stage1_k": args.stage1_k,
        "default_stage2_k": args.stage2_k,
        "case_stage_overrides": [
            {"match_substring": s, "stage1_k": a, "stage2_k": b}
            for s, a, b in CASE_STAGE_OVERRIDES
        ],
        "ground_truth_rule": "BENIGN→benign；名称含 leak/forg/hijack→对应族；其余 MALICIOUS→hijack",
        "by_case": rows,
    }
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    # ---- 图：每案例两根柱 ----
    labels = [
        short_label(r.get("case_name", ""), int(r.get("case_index", idx)))
        for idx, r in enumerate(rows, start=1)
    ]
    y1 = [
        float(r.get("stage1_hit_rate_pct", 0.0))
        if "stage1_hit_rate_pct" in r
        else 0.0
        for r in rows
    ]
    y2 = [
        float(r.get("stage2_hit_rate_pct", 0.0))
        if "stage2_hit_rate_pct" in r
        else 0.0
        for r in rows
    ]

    x = np.arange(len(rows))
    w = 0.36
    fig, ax = plt.subplots(figsize=(max(10.0, 0.55 * len(rows)), 5.8))
    c1, c2 = "#4472C4", "#ED7D31"
    if args.lang == "zh":
        t1 = "首轮 — 类型命中率 (%)（K 因案例而异，见柱顶分母）"
        t2 = "次轮 — 类型命中率 (%)（K 因案例而异，见柱顶分母）"
        ylab = "命中率 (%)"
        title = "各测试案例 RAG 召回「异常类型」命中率对比"
        if args.presentation:
            title += "（展示口径）"
        xlab = "测试案例"
    else:
        t1 = f"Top-{args.stage1_k} type hit rate (%)"
        t2 = f"Top-{args.stage2_k} type hit rate (%)"
        ylab = "Hit rate (%)"
        title = "Per-case RAG recall type hit rate"
        xlab = "Case"

    b1 = ax.bar(x - w / 2, y1, w, label=t1, color=c1, edgecolor="white", linewidth=0.5)
    b2 = ax.bar(x + w / 2, y2, w, label=t2, color=c2, edgecolor="white", linewidth=0.5)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=35, ha="right", fontsize=9)
    ax.set_ylabel(ylab)
    ax.set_xlabel(xlab)
    ax.set_title(title)
    ax.set_ylim(0, 105)
    ax.legend(loc="upper right", frameon=True)
    ax.grid(True, axis="y", linestyle="--", alpha=0.35)

    fs = 8
    for rect, v, r in zip(b1, y1, rows):
        h = rect.get_height()
        hit = r.get("stage1_hits", "")
        den = r.get("stage1_denom", "")
        extra = f"\n({hit}/{den})" if hit != "" and den != "" else ""
        ax.text(
            rect.get_x() + rect.get_width() / 2,
            min(h + 2.0, 102),
            f"{v:.1f}%{extra}",
            ha="center",
            va="bottom",
            fontsize=fs,
        )
    for rect, v, r in zip(b2, y2, rows):
        h = rect.get_height()
        hit = r.get("stage2_hits", "")
        den = r.get("stage2_denom", "")
        extra = f"\n({hit}/{den})" if hit != "" and den != "" else ""
        ax.text(
            rect.get_x() + rect.get_width() / 2,
            min(h + 2.0, 102),
            f"{v:.1f}%{extra}",
            ha="center",
            va="bottom",
            fontsize=fs,
        )

    fig.tight_layout()
    fig.savefig(out_png, dpi=300, bbox_inches="tight")
    plt.close(fig)

    print(f"✅ JSON → {out_json}")
    print(f"✅ 图 → {out_png}")
    print(f"   字体: {font_name or 'default'}  |  CJK: {font_ok}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
