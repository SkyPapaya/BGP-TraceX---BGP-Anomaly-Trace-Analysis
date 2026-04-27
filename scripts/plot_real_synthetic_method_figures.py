#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "report" / "evaluation" / "figures"
REAL_JSON = ROOT / "report" / "evaluation" / "comparative_results_real.json"
SYN_JSON = ROOT / "report" / "evaluation" / "comparative_results_synthetic.json"

METHODS = [
    ("完整系统(RAG+LLM+Tools)", "M1"),
    ("仅LLM", "M2"),
    ("规则检测", "M3"),
    ("RAG+LLM(无工具)", "M4"),
]
METHOD_ORDER = [m[0] for m in METHODS]
METHOD_SHORT = [m[1] for m in METHODS]
METHOD_COLORS = {
    "M1": "#1f4e79",
    "M2": "#c55a11",
    "M3": "#548235",
    "M4": "#7f6000",
}


def setup_style() -> None:
    plt.rcParams["font.sans-serif"] = ["DejaVu Sans"]
    plt.rcParams["axes.unicode_minus"] = False
    plt.rcParams["font.size"] = 10


def parse_path(as_path: str) -> List[str]:
    return [p.strip() for p in str(as_path or "").replace(",", " ").split() if p.strip().isdigit()]


def normalize_asn(val: Any) -> str:
    if val is None:
        return "None"
    s = str(val).strip().upper()
    if s in ("", "NONE", "UNKNOWN", "NULL"):
        return "None"
    if s.startswith("AS"):
        s = s[2:]
    digits = "".join(ch for ch in s if ch.isdigit())
    return digits if digits else "None"


def infer_case_noise_level(case: Dict[str, Any]) -> str:
    event_type = str(case.get("event_type", "")).upper().strip()
    updates = (case.get("context") or {}).get("updates") or []
    expected_attacker = normalize_asn(case.get("expected_attacker"))

    candidates: List[str] = []
    if event_type == "HIJACK":
        for u in updates:
            candidates.append(normalize_asn(u.get("detected_origin")))
    elif event_type == "LEAK":
        for u in updates:
            path = parse_path(u.get("as_path", ""))
            candidates.append(path[-2] if len(path) >= 2 else "None")
    elif event_type == "FORGERY":
        for u in updates:
            path = parse_path(u.get("as_path", ""))
            if expected_attacker != "None" and expected_attacker in path:
                candidates.append(expected_attacker)
            else:
                candidates.append("None")

    counts = Counter(candidates)
    total = sum(counts.values()) or 1
    dominant = counts.most_common(1)[0][1] if counts else 0
    ratio = dominant / total

    if len(counts) <= 1 and ratio >= 1.0:
        return "low"
    if ratio >= 0.75:
        return "medium"
    return "high"


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def extract_updates_from_case_result(case_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    trace = ((case_result.get("methods") or {}).get("完整系统(RAG+LLM+Tools)") or {}).get("trace") or {}
    target = trace.get("target") or {}
    return target.get("updates") or []


def infer_real_case_noise_level(case_result: Dict[str, Any]) -> str:
    updates = extract_updates_from_case_result(case_result)
    expected_attacker = str(case_result.get("expected_attacker", "None"))
    case_type = str(case_result.get("case_type", "MALICIOUS")).upper()
    pseudo_event_type = "BENIGN" if case_type == "BENIGN" else "HIJACK"
    pseudo_case = {
        "event_type": pseudo_event_type,
        "expected_attacker": expected_attacker,
        "context": {"updates": updates},
    }
    return infer_case_noise_level(pseudo_case)


def infer_synthetic_case_noise_level(case_result: Dict[str, Any]) -> str:
    if case_result.get("noise_level"):
        return str(case_result["noise_level"]).lower().strip()
    event_type = str(case_result.get("event_type", "UNKNOWN")).upper()
    expected_attacker = str(case_result.get("expected_attacker", "None"))
    pseudo_case = {
        "event_type": event_type,
        "expected_attacker": expected_attacker,
        "context": {"updates": case_result.get("context_updates", [])},
    }
    return infer_case_noise_level(pseudo_case)


def normalize_dataset(data: Dict[str, Any], dataset: str) -> Dict[str, Any]:
    methods = data["methods"]
    detailed = data["detailed_results"]
    rows = []

    if dataset == "real":
        for item in detailed:
            noise = infer_real_case_noise_level(item)
            expected_attacker = str(item.get("expected_attacker", "None"))
            case_type = str(item.get("case_type", "MALICIOUS")).upper()
            row = {
                "case_name": item.get("case_name", ""),
                "event_type": "BENIGN" if case_type == "BENIGN" else "MALICIOUS",
                "expected_attacker": expected_attacker,
                "noise_level": noise,
                "methods": item.get("methods", {}),
            }
            rows.append(row)
    else:
        for item in detailed:
            noise = infer_synthetic_case_noise_level(item)
            row = {
                "case_name": item.get("case_name", ""),
                "event_type": str(item.get("event_type", "UNKNOWN")).upper(),
                "expected_attacker": str(item.get("expected_attacker", "None")),
                "noise_level": noise,
                "methods": item.get("methods", {}),
            }
            rows.append(row)

    return {"methods": methods, "cases": rows}


def compute_robustness(dataset_rows: List[Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, float]], Dict[str, Dict[str, float]]]:
    acc = defaultdict(dict)
    fpr = defaultdict(dict)
    levels = ["low", "medium", "high"]

    for method_name, short in METHODS:
        for level in levels:
            subset = [r for r in dataset_rows if r["noise_level"] == level]
            if subset:
                hit = sum(1 for r in subset if r["methods"][method_name].get("is_correct"))
                acc[short][level] = round(hit / len(subset) * 100.0, 1)
            else:
                acc[short][level] = math.nan

            benign_subset = [r for r in subset if r["event_type"] == "BENIGN"]
            if benign_subset:
                fp = 0
                for r in benign_subset:
                    res = r["methods"][method_name]
                    if res.get("attacker") != "None" or str(res.get("status", "")).upper() in ("MALICIOUS", "LEAK", "FORGERY"):
                        fp += 1
                fpr[short][level] = round(fp / len(benign_subset) * 100.0, 1)
            else:
                fpr[short][level] = math.nan
    return acc, fpr


def annotate_bars(ax, bars, values, fmt: str, offset: float) -> None:
    for bar, v in zip(bars, values):
        y = bar.get_height()
        text = fmt.format(v)
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            y + offset,
            text,
            ha="center",
            va="bottom",
            fontsize=9,
        )


def plot_accuracy_fpr(methods: Dict[str, Any], out_path: Path) -> None:
    x = np.arange(len(METHODS))
    width = 0.34
    acc = [methods[name]["accuracy"] for name, _ in METHODS]
    fpr = [methods[name]["false_positive_rate"] or 0.0 for name, _ in METHODS]

    fig, ax = plt.subplots(figsize=(8.6, 5.2))
    bars1 = ax.bar(x - width / 2, acc, width, color=[METHOD_COLORS[s] for _, s in METHODS], alpha=0.9)
    bars2 = ax.bar(x + width / 2, fpr, width, color="#b7b7b7", alpha=0.95)
    ax.set_xticks(x)
    ax.set_xticklabels(METHOD_SHORT)
    ax.set_ylabel("Value (%)")
    ax.set_xlabel("Method")
    ax.set_ylim(0, max(max(acc), max(fpr) + 5, 110))
    ax.grid(True, axis="y", linestyle="--", alpha=0.35)
    annotate_bars(ax, bars1, acc, "{:.1f}", 1.2)
    annotate_bars(ax, bars2, fpr, "{:.1f}", 1.2)
    ax.legend(["Accuracy", "FPR"], loc="upper right", frameon=True)
    fig.tight_layout()
    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)


def plot_latency(methods: Dict[str, Any], out_path: Path) -> None:
    x = np.arange(len(METHODS))
    vals = [methods[name]["avg_latency"] for name, _ in METHODS]
    fig, ax = plt.subplots(figsize=(8.2, 5.0))
    bars = ax.bar(x, vals, color=[METHOD_COLORS[s] for _, s in METHODS], width=0.55)
    ax.set_xticks(x)
    ax.set_xticklabels(METHOD_SHORT)
    ax.set_ylabel("Mean latency (s)")
    ax.set_xlabel("Method")
    ax.grid(True, axis="y", linestyle="--", alpha=0.35)
    annotate_bars(ax, bars, vals, "{:.2f}", max(vals) * 0.015 + 0.2)
    fig.tight_layout()
    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)


def plot_conf_accuracy(methods: Dict[str, Any], out_path: Path) -> None:
    acc = [methods[name]["accuracy"] for name, _ in METHODS]
    conf = [methods[name]["avg_confidence"] * 100.0 for name, _ in METHODS]
    fig, ax = plt.subplots(figsize=(7.8, 5.4))
    offsets = {"M1": (10, 8), "M2": (10, -18), "M3": (-54, 10), "M4": (-54, -18)}
    for (name, short), x, y in zip(METHODS, conf, acc):
        ax.scatter(x, y, s=180, color=METHOD_COLORS[short], edgecolors="white", linewidths=1.2, zorder=3)
        ox, oy = offsets[short]
        ax.annotate(
            f"{short}\n({x:.1f}, {y:.1f})",
            (x, y),
            xytext=(ox, oy),
            textcoords="offset points",
            fontsize=9,
            bbox=dict(boxstyle="round,pad=0.2", facecolor="white", edgecolor="#cccccc", alpha=0.95),
        )
    ax.set_xlabel("Mean confidence (%)")
    ax.set_ylabel("Accuracy (%)")
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 105)
    ax.grid(True, linestyle="--", alpha=0.35)
    fig.tight_layout()
    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)


def plot_robustness_heatmaps(acc: Dict[str, Dict[str, float]], fpr: Dict[str, Dict[str, float]], out_path: Path) -> None:
    levels = ["low", "medium", "high"]
    methods = METHOD_SHORT
    acc_mat = np.array([[acc[m][lv] for lv in levels] for m in methods], dtype=float)
    fpr_mat = np.array([[fpr[m][lv] for lv in levels] for m in methods], dtype=float)

    fig, axes = plt.subplots(1, 2, figsize=(11.2, 5.6))
    for ax, mat, cmap, label in [
        (axes[0], acc_mat, "YlGn", "Accuracy (%)"),
        (axes[1], fpr_mat, "OrRd", "FPR (%)"),
    ]:
        show = np.nan_to_num(mat, nan=-1.0)
        im = ax.imshow(show, aspect="auto", cmap=cmap, vmin=0, vmax=100)
        ax.set_xticks(np.arange(len(levels)))
        ax.set_xticklabels([lv.capitalize() for lv in levels])
        ax.set_yticks(np.arange(len(methods)))
        ax.set_yticklabels(methods)
        ax.set_xlabel("Noise level")
        ax.set_ylabel("Method")
        for i in range(mat.shape[0]):
            for j in range(mat.shape[1]):
                val = mat[i, j]
                txt = "N/A" if math.isnan(val) else f"{val:.1f}"
                color = "black" if math.isnan(val) or val < 65 else "white"
                ax.text(j, i, txt, ha="center", va="center", fontsize=9, color=color)
        cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
        cbar.set_label(label)
    fig.tight_layout()
    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description="Plot separate real/synthetic method comparison figures")
    parser.add_argument("--real-json", default=str(REAL_JSON))
    parser.add_argument("--synthetic-json", default=str(SYN_JSON))
    args = parser.parse_args()

    setup_style()
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    real_raw = load_json(Path(args.real_json))
    syn_raw = load_json(Path(args.synthetic_json))
    real = normalize_dataset(real_raw, "real")
    syn = normalize_dataset(syn_raw, "synthetic")

    for prefix, pack in [("real", real), ("synthetic", syn)]:
        methods = pack["methods"]
        rows = pack["cases"]
        acc_heat, fpr_heat = compute_robustness(rows)

        plot_accuracy_fpr(methods, OUT_DIR / f"{prefix}_accuracy_fpr_bar.png")
        plot_latency(methods, OUT_DIR / f"{prefix}_latency_bar.png")
        plot_conf_accuracy(methods, OUT_DIR / f"{prefix}_confidence_accuracy_scatter.png")
        plot_robustness_heatmaps(acc_heat, fpr_heat, OUT_DIR / f"{prefix}_robustness_heatmap.png")

    print(f"Saved figures to: {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
