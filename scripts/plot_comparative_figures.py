#!/usr/bin/env python3
"""
根据 comparative_results_real.json / 对比实验报告 生成论文用图（高分辨率 PNG）：
图 5.2 为四种方法可解释性对比；另含 5.3、5.4。
运行: python scripts/plot_comparative_figures.py [--lang auto|zh|en] [--ref-four]
加 --ref-four 时额外输出四张参考风格独立图（准确率柱、双轴置信度/准确率×2、时延散点）。
输出: report/evaluation/figures/（fig5_2：四方法可解释性对比、fig5_3、fig5_4）
无 CJK 字体时 auto 会改用英文标签；将 NotoSansCJKsc-Regular.otf 放入仓库根目录 fonts/ 后
可用 --lang zh（脚本会优先 addfont 该目录）。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from glob import glob
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import ListedColormap

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "report" / "evaluation" / "figures"
JSON_PATH = ROOT / "report" / "evaluation" / "comparative_results_real.json"

# 与论文配色统一：M1 深蓝 · M2 红 · M3 绿 · M4 橙
METHOD_COLORS = {
    "M1": "#1f4e79",
    "M2": "#c55a11",
    "M3": "#548235",
    "M4": "#ed7d31",
}

METHOD_ORDER = ["M1", "M2", "M3", "M4"]
METHOD_LABELS_ZH = [
    "M1 完整系统",
    "M2 仅 LLM",
    "M3 规则检测",
    "M4 RAG+LLM",
]
METHOD_LABELS_EN = [
    "M1 (full system)",
    "M2 (LLM only)",
    "M3 (rule-based)",
    "M4 (RAG+LLM)",
]

# 常见 Linux/WSL 路径：先 addfont 再选用（含 WSL 下 Windows 字体）
_FONT_FILE_GLOBS = [
    "/usr/share/fonts/opentype/noto/NotoSansCJK-*.ttc",
    "/usr/share/fonts/opentype/noto-sans-cjk/NotoSansCJK-*.ttc",
    "/usr/share/fonts/noto-cjk/NotoSansCJK-*.ttc",
    "/usr/share/fonts/truetype/noto/NotoSansCJK-*.ttc",
    "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
    "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
    "/mnt/c/Windows/Fonts/msyh.ttc",
    "/mnt/c/Windows/Fonts/msyhbd.ttc",
    "/mnt/c/Windows/Fonts/simhei.ttf",
    "/mnt/c/Windows/Fonts/simsun.ttc",
]


def _register_font_files() -> None:
    from matplotlib import font_manager

    seen: set[str] = set()
    # 优先：仓库内 fonts/（随项目下载的 Noto CJK SC 等）
    bundled = ROOT / "fonts"
    if bundled.is_dir():
        for fp in sorted(bundled.glob("*.otf")) + sorted(bundled.glob("*.ttf")) + sorted(
            bundled.glob("*.ttc")
        ):
            p = str(fp.resolve())
            if p in seen or not fp.is_file():
                continue
            seen.add(p)
            try:
                font_manager.fontManager.addfont(p)
            except OSError:
                pass
    for pattern in _FONT_FILE_GLOBS:
        for fp in glob(pattern):
            if fp in seen or not os.path.isfile(fp):
                continue
            seen.add(fp)
            try:
                font_manager.fontManager.addfont(fp)
            except OSError:
                pass


def _setup_font(lang: str) -> tuple[str | None, bool]:
    """返回 (matplotlib 选用的字体名, 是否适合中文). lang=='zh' 时尽力加载 CJK。"""
    matplotlib.rcParams["axes.unicode_minus"] = False
    from matplotlib import font_manager

    _register_font_files()

    cjk_candidates = [
        "Noto Sans CJK SC",
        "Noto Sans SC",
        "Noto Sans CJK JP",
        "Noto Serif CJK SC",
        "WenQuanYi Micro Hei",
        "WenQuanYi Zen Hei",
        "Source Han Sans SC",
        "SimHei",
        "Microsoft YaHei",
        "PingFang SC",
        "STHeiti",
        "Arial Unicode MS",
    ]
    fallback = ["DejaVu Sans"]

    available = {f.name for f in font_manager.fontManager.ttflist}
    if lang == "zh":
        for name in cjk_candidates:
            if name in available:
                matplotlib.rcParams["font.sans-serif"] = [name] + list(
                    matplotlib.rcParams.get("font.sans-serif", [])
                )
                return name, True
        for name in fallback:
            if name in available:
                matplotlib.rcParams["font.sans-serif"] = [name] + list(
                    matplotlib.rcParams.get("font.sans-serif", [])
                )
                return name, False
        return None, False

    # English labels: prefer DejaVu / Liberation
    for name in ["DejaVu Sans", "Liberation Sans", "Arial", "Helvetica"]:
        if name in available:
            matplotlib.rcParams["font.sans-serif"] = [name] + list(
                matplotlib.rcParams.get("font.sans-serif", [])
            )
            return name, False
    return None, False


def _resolve_lang(cli_lang: str | None, font_has_cjk: bool) -> str:
    if cli_lang in ("zh", "en"):
        return cli_lang
    return "zh" if font_has_cjk else "en"


def _strings(lang: str) -> dict:
    if lang == "zh":
        return {
            "m_labels": METHOD_LABELS_ZH,
            "acc_pct": "准确率 (%)",
            "exp_score": "可解释性评分 (0–100)",
            "exp_ylabel": "可解释性评分",
            "5_3_x": "平均处理时延 (秒)",
            "5_3_y": "溯源准确率 (%)",
            "5_4_x": "方法",
            "5_4_y": "测试案例",
            "5_5_ylabel": "数值 (%)",
            "5_5_acc": "准确率 (%)",
            "5_5_conf": "平均置信度 (×100)",
            "triple_ylabel": "得分 / 百分比（0–100）",
            "triple_acc": "准确率",
            "triple_exp": "可解释性",
            "triple_conf": "平均置信度×100",
            "ref_acc_only_legend": "准确率",
            "ref_model_axis": "模型",
            "ref_title_A": "准确率对比 (%)",
            "ref_mean_conf": "平均置信度",
            "ref_ylabel_conf": "平均置信度",
            "ref_acc_pct_label": "准确率 (%)",
            "ref_acc_trend": "准确率趋势",
            "ref_latency_short": "平均时延",
            "ref_sec": " s",
            "ref_linear_trend": "线性趋势线",
            "ref_title_C": "处理时延 (s) 与准确率 (%) 权衡",
            "ref_title_B1": "平均置信度 vs. 准确率 (%)（全模型）",
            "ref_title_B2": "平均置信度 vs. 准确率 (%)（M1 / M2）",
        }
    return {
        "m_labels": METHOD_LABELS_EN,
        "acc_pct": "Accuracy (%)",
        "exp_score": "Explainability (0–100)",
        "exp_ylabel": "Explainability",
        "5_3_x": "Mean latency (s)",
        "5_3_y": "Trace accuracy (%)",
        "5_4_x": "Method",
        "5_4_y": "Test case",
        "5_5_ylabel": "Value (%)",
        "5_5_acc": "Accuracy (%)",
        "5_5_conf": "Mean confidence ×100",
        "triple_ylabel": "Score / percent (0–100)",
        "triple_acc": "Accuracy",
        "triple_exp": "Explainability",
        "triple_conf": "Mean confidence ×100",
        "ref_acc_only_legend": "Accuracy",
        "ref_model_axis": "Model",
        "ref_title_A": "Accuracy comparison (%)",
        "ref_mean_conf": "Mean confidence",
        "ref_ylabel_conf": "Mean confidence",
        "ref_acc_pct_label": "Accuracy (%)",
        "ref_acc_trend": "Accuracy trend",
        "ref_latency_short": "Latency",
        "ref_sec": " s",
        "ref_linear_trend": "Linear trend",
        "ref_title_C": "Latency vs. accuracy trade-off",
        "ref_title_B1": "Mean confidence vs. accuracy (all)",
        "ref_title_B2": "Mean confidence vs. accuracy (M1 / M2)",
    }


def load_metrics(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    m = data["methods"]
    keys = [
        "完整系统(RAG+LLM+Tools)",
        "仅LLM",
        "规则检测",
        "RAG+LLM(无工具)",
    ]
    out = []
    for k in keys:
        row = m[k]
        out.append(
            {
                "accuracy": row["accuracy"],
                "explainability": row["avg_explainability"],
                "latency": row["avg_latency"],
                "confidence": row["avg_confidence"],
            }
        )
    return {
        "rows": out,
        "detailed": data.get("detailed_results", []),
    }


def build_correctness_matrix(detailed: list) -> tuple[np.ndarray, list[str]]:
    order_m = [
        "完整系统(RAG+LLM+Tools)",
        "仅LLM",
        "规则检测",
        "RAG+LLM(无工具)",
    ]
    mat = []
    names = []
    for row in detailed:
        short = row.get("case_name", "")[:32]
        names.append(short)
        r = []
        for mk in order_m:
            ok = row["methods"][mk].get("is_correct", False)
            r.append(1 if ok else 0)
        mat.append(r)
    return np.array(mat, dtype=float), names


def fig5_2_explainability_four_methods(rows: list, s: dict) -> None:
    """图 5.2：四种方法的可解释性评分对比；无图题；图例为中文方法说明。"""
    from matplotlib.patches import Patch

    explainability = [r["explainability"] for r in rows]
    x = np.arange(len(METHOD_ORDER))
    colors = [METHOD_COLORS[m] for m in METHOD_ORDER]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(
        x,
        explainability,
        color=colors,
        edgecolor="white",
        linewidth=0.5,
    )

    ax.set_xticks(x)
    ax.set_xticklabels(METHOD_ORDER)
    ax.set_ylim(0, 110)
    ax.set_ylabel(s["exp_score"])
    ax.grid(True, axis="y", linestyle="--", alpha=0.35)

    # 图 5.2 图例固定中文（与论文一致）
    handles = [
        Patch(facecolor=METHOD_COLORS[m], edgecolor="white", label=lab)
        for m, lab in zip(METHOD_ORDER, METHOD_LABELS_ZH)
    ]
    ax.legend(handles=handles, loc="upper right", frameon=True)

    label_fs = 10
    t_exp = "#5d4e37"
    for rect, v in zip(bars, explainability):
        h = rect.get_height()
        ax.text(
            rect.get_x() + rect.get_width() / 2,
            h + 1.2,
            f"{v:.1f}",
            ha="center",
            va="bottom",
            fontsize=label_fs,
            color=t_exp,
        )

    fig.tight_layout()
    fig.savefig(OUT_DIR / "fig5_2_performance_multimetric.png", dpi=300, bbox_inches="tight")
    plt.close(fig)


def fig_5_3(rows: list, s: dict) -> None:
    latency = [r["latency"] for r in rows]
    accuracy = [r["accuracy"] for r in rows]
    colors = [METHOD_COLORS[m] for m in METHOD_ORDER]

    # M2/M4 数据点几乎重合，用不同 offset 错开文字
    annotate_xytext = {
        "M1": (8, 6),
        "M2": (6, 16),
        "M3": (8, 6),
        "M4": (6, -22),
    }

    fig, ax = plt.subplots(figsize=(8, 5.5))
    ax.scatter(latency, accuracy, s=160, c=colors, edgecolors="white", linewidths=1.2, zorder=3)
    for i, m in enumerate(METHOD_ORDER):
        ox, oy = annotate_xytext[m]
        ax.annotate(
            m,
            (latency[i], accuracy[i]),
            xytext=(ox, oy),
            textcoords="offset points",
            fontsize=11,
            fontweight="bold",
            color=colors[i],
        )
    ax.set_xlabel(s["5_3_x"])
    ax.set_ylabel(s["5_3_y"])
    ax.grid(True, linestyle="--", alpha=0.45)
    ax.set_xlim(left=0)
    ax.set_ylim(0, 105)
    fig.tight_layout()
    fig.savefig(OUT_DIR / "fig5_3_latency_accuracy_tradeoff.png", dpi=300, bbox_inches="tight")
    plt.close(fig)


# 参考示意图 A/C：按模型区分配色（与 METHOD_COLORS 论文配色区分，便于对照示例图）
REF_MODEL_BAR_COLORS = ["#4472C4", "#70AD47", "#ED7D31", "#C00000"]


def fig_ref_A_accuracy_only(rows: list, s: dict, out_dir: Path) -> None:
    """图 A：四方法准确率柱状图，柱顶标注具体百分比。"""
    acc = [r["accuracy"] for r in rows]
    x = np.arange(len(METHOD_ORDER))
    fig, ax = plt.subplots(figsize=(7, 5))
    bars = ax.bar(
        x,
        acc,
        color=REF_MODEL_BAR_COLORS,
        edgecolor="white",
        linewidth=0.6,
        label=s.get("ref_acc_only_legend", "准确率"),
    )
    ax.set_xticks(x)
    ax.set_xticklabels(METHOD_ORDER)
    ax.set_ylabel(s["acc_pct"])
    ax.set_xlabel(s.get("ref_model_axis", "模型"))
    ax.set_title(s.get("ref_title_A", "准确率对比 (%)"))
    ax.set_ylim(0, 110)
    ax.grid(True, axis="y", linestyle="--", alpha=0.4)
    ax.legend(loc="upper right", frameon=True)
    for rect, v in zip(bars, acc):
        h = rect.get_height()
        ax.text(
            rect.get_x() + rect.get_width() / 2,
            h + 1.5,
            f"{v:.1f}%",
            ha="center",
            va="bottom",
            fontsize=10,
            fontweight="bold",
        )
    fig.tight_layout()
    fig.savefig(out_dir / "fig_ref_A_准确率对比.png", dpi=300, bbox_inches="tight")
    plt.close(fig)


def fig_ref_B_dual_axis(
    rows: list,
    s: dict,
    out_dir: Path,
    *,
    indices: list[int],
    suffix: str,
    title: str,
) -> None:
    """图 B：分组柱 — 左轴平均置信度 [0,1]，右轴准确率 [%]；柱顶标注数值。"""
    sub = [rows[i] for i in indices]
    labels = [METHOD_ORDER[i] for i in indices]
    conf = [r["confidence"] for r in sub]
    acc = [r["accuracy"] for r in sub]

    x = np.arange(len(labels))
    w = 0.36
    fig, ax1 = plt.subplots(figsize=(max(5.0, 1.2 + 1.8 * len(labels)), 5.2))
    c_conf, c_acc = "#ED7D31", "#4472C4"

    b1 = ax1.bar(
        x - w / 2,
        conf,
        w,
        color=c_conf,
        edgecolor="white",
        linewidth=0.5,
        label=s.get("ref_mean_conf", "平均置信度"),
        zorder=2,
    )
    ax1.set_xlabel(s.get("ref_model_axis", "模型"))
    ax1.set_ylabel(s.get("ref_ylabel_conf", "平均置信度"))
    ax1.set_ylim(0, 1.08)
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels)
    ax1.grid(True, axis="y", linestyle="--", alpha=0.35)

    ax2 = ax1.twinx()
    b2 = ax2.bar(
        x + w / 2,
        acc,
        w,
        color=c_acc,
        edgecolor="white",
        linewidth=0.5,
        label=s.get("ref_acc_pct_label", "准确率 (%)"),
        zorder=2,
    )
    ax2.set_ylabel(s["acc_pct"])
    ax2.set_ylim(0, 110)

    # 折线：连接各方法「准确率」中点，便于观察趋势（与参考图风格一致）
    ax2.plot(
        x,
        acc,
        color="#1f375e",
        linestyle="-",
        linewidth=1.8,
        marker="o",
        markersize=6,
        zorder=3,
        label=s.get("ref_acc_trend", "准确率趋势"),
    )

    ax1.set_title(title)
    h1, l1 = ax1.get_legend_handles_labels()
    h2, l2 = ax2.get_legend_handles_labels()
    ax1.legend(h1 + h2, l1 + l2, loc="upper right", frameon=True)

    for rect, v in zip(b1, conf):
        h = rect.get_height()
        ax1.text(
            rect.get_x() + rect.get_width() / 2,
            h + 0.02,
            f"{v:.3f}",
            ha="center",
            va="bottom",
            fontsize=9,
        )
    for rect, v in zip(b2, acc):
        h = rect.get_height()
        ax2.text(
            rect.get_x() + rect.get_width() / 2,
            h + 2.0,
            f"{v:.1f}%",
            ha="center",
            va="bottom",
            fontsize=9,
        )

    fig.tight_layout()
    fig.savefig(out_dir / suffix, dpi=300, bbox_inches="tight")
    plt.close(fig)


def fig_ref_C_latency_accuracy(rows: list, s: dict, out_dir: Path) -> None:
    """图 C：平均时延–准确率散点，带线性趋势线；点旁标注模型与数值。"""
    latency = [r["latency"] for r in rows]
    accuracy = [r["accuracy"] for r in rows]
    markers = ["o", "s", "D", "P"]
    fig, ax = plt.subplots(figsize=(8, 5.5))

    for i, m in enumerate(METHOD_ORDER):
        ax.scatter(
            latency[i],
            accuracy[i],
            s=180,
            c=REF_MODEL_BAR_COLORS[i],
            marker=markers[i],
            edgecolors="white",
            linewidths=1.1,
            label=f"{m}",
            zorder=4,
        )
        ax.annotate(
            f"{m}\n{s.get('ref_latency_short', '时延')} {latency[i]:.1f}{s.get('ref_sec', 's')}\n{accuracy[i]:.1f}%",
            (latency[i], accuracy[i]),
            xytext=(10, 8),
            textcoords="offset points",
            fontsize=8,
            bbox=dict(boxstyle="round,pad=0.25", facecolor="white", edgecolor="#cccccc", alpha=0.92),
            zorder=5,
        )

    xs = np.array(latency, dtype=float)
    ys = np.array(accuracy, dtype=float)
    if len(xs) >= 2 and np.std(xs) > 1e-9:
        coef = np.polyfit(xs, ys, 1)
        x_line = np.linspace(max(0, xs.min() - 2), xs.max() + 5, 80)
        y_line = coef[0] * x_line + coef[1]
        ax.plot(
            x_line,
            y_line,
            color="#1f375e",
            linestyle="--",
            linewidth=2.0,
            label=s.get("ref_linear_trend", "线性趋势线"),
            zorder=2,
        )

    ax.set_xlabel(s["5_3_x"])
    ax.set_ylabel(s["5_3_y"])
    ax.set_title(s.get("ref_title_C", "处理时延 (s) 与准确率 (%) 权衡"))
    ax.grid(True, linestyle="--", alpha=0.4)
    ax.set_xlim(left=0)
    ax.set_ylim(0, 105)
    ax.legend(loc="best", frameon=True)
    fig.tight_layout()
    fig.savefig(out_dir / "fig_ref_C_时延准确率权衡.png", dpi=300, bbox_inches="tight")
    plt.close(fig)


def fig_5_4(matrix: np.ndarray, case_names: list[str], s: dict) -> None:
    fig, ax = plt.subplots(figsize=(9, 10))
    # 错误格为白底（便于红叉对比），正确格为绿
    cmap = ListedColormap(["#FFFFFF", "#4CAF50"])
    im = ax.imshow(matrix, aspect="auto", cmap=cmap, vmin=0, vmax=1)
    ax.set_xticks(np.arange(4))
    ax.set_xticklabels(["M1", "M2", "M3", "M4"])
    ax.set_yticks(np.arange(len(case_names)))
    ax.set_yticklabels(case_names, fontsize=8)
    ax.set_xlabel(s["5_4_x"])
    ax.set_ylabel(s["5_4_y"])

    # 白底错误格之间用浅线分隔，避免连成一片
    ax.set_xticks(np.arange(matrix.shape[1] + 1) - 0.5, minor=True)
    ax.set_yticks(np.arange(matrix.shape[0] + 1) - 0.5, minor=True)
    ax.grid(which="minor", color="#e0e0e0", linestyle="-", linewidth=0.55)
    ax.tick_params(which="minor", bottom=False, left=False)

    mark_fs = 18  # 相对原 9pt 约翻倍
    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            ok = matrix[i, j] >= 0.5
            # Noto CJK SC 不含 U+2717「✗」，用 ASCII 避免缺字形警告
            txt = "✓" if ok else "X"
            color = "#333333" if ok else "#c62828"
            ax.text(j, i, txt, ha="center", va="center", color=color, fontsize=mark_fs)

    fig.tight_layout()
    fig.savefig(OUT_DIR / "fig5_4_case_heatmap.png", dpi=300, bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    ap = argparse.ArgumentParser(description="生成对比实验论文用图（5.2 可解释性四方法，5.3，5.4）")
    ap.add_argument(
        "--lang",
        choices=("auto", "zh", "en"),
        default="auto",
        help="标签语言：auto 在有 CJK 字体时用中文，否则英文",
    )
    ap.add_argument(
        "--ref-four",
        action="store_true",
        help="额外生成参考风格四张独立图：准确率柱、双轴分组柱（全模型+M1/M2）、时延-准确率散点",
    )
    args = ap.parse_args()

    want_zh = args.lang != "en"
    font_name, font_has_cjk = _setup_font("zh" if want_zh else "en")
    lang = _resolve_lang(None if args.lang == "auto" else args.lang, font_has_cjk)
    if args.lang == "zh" and not font_has_cjk:
        print(
            "⚠️ 未找到 CJK 字体，中文将显示为方块；已改用英文标签。请安装 fonts-noto-cjk 或文泉驿。",
            file=sys.stderr,
        )
        lang = "en"
        _setup_font("en")

    s = _strings(lang)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    if not JSON_PATH.is_file():
        print(f"❌ 未找到 {JSON_PATH}", file=sys.stderr)
        return 1

    pack = load_metrics(JSON_PATH)
    rows = pack["rows"]
    mat, case_names = build_correctness_matrix(pack["detailed"])

    fig5_2_explainability_four_methods(rows, s)
    fig_5_3(rows, s)
    fig_5_4(mat, case_names, s)

    n_extra = 0
    if args.ref_four:
        fig_ref_A_accuracy_only(rows, s, OUT_DIR)
        fig_ref_B_dual_axis(
            rows,
            s,
            OUT_DIR,
            indices=[0, 1, 2, 3],
            suffix="fig_ref_B1_置信度与准确率_全模型.png",
            title=s["ref_title_B1"],
        )
        fig_ref_B_dual_axis(
            rows,
            s,
            OUT_DIR,
            indices=[0, 1],
            suffix="fig_ref_B2_置信度与准确率_M1M2.png",
            title=s["ref_title_B2"],
        )
        fig_ref_C_latency_accuracy(rows, s, OUT_DIR)
        n_extra = 4

    print(f"✅ 已生成 {3 + n_extra} 张图 → {OUT_DIR}")
    print(f"   标签语言: {lang}  |  字体: {font_name or 'default'}")
    if lang == "zh":
        print("   （CJK 字体已启用）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
