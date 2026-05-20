#!/usr/bin/env python3
"""
Run synthetic-only benchmark evaluation and export metrics used for plotting.

Metrics:
- Accuracy (strict: event type + attacker AS)
- False Positive Rate (requires benign cases; null when unavailable)
- Latency
- Confidence
- Robustness (bucketed by inferred noise level)
- Error case analysis
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bgp_agent import BGPAgent  # noqa: E402
from scripts.run_case_catalog_test import (  # noqa: E402
    infer_fine_type_from_output,
    map_status_to_coarse,
    normalize_asn,
)
from scripts.run_feasibility_experiment import load_synthetic_cases  # noqa: E402


CONFIDENCE_TO_PCT = {
    "HIGH": 90.0,
    "MEDIUM": 60.0,
    "LOW": 30.0,
    "UNKNOWN": 0.0,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Synthetic benchmark metrics experiment")
    parser.add_argument(
        "--input",
        default="data/benchmark_synthetic_cases.json",
        help="Synthetic cases JSON path",
    )
    parser.add_argument(
        "--report-out",
        default="report/evaluation/synthetic_metrics_report.json",
        help="Output report path",
    )
    parser.add_argument(
        "--benign-uncertain-as-benign",
        action="store_true",
        help="For evaluation only: treat BENIGN cases predicted as UNCERTAIN as BENIGN",
    )
    return parser.parse_args()


def parse_path(as_path: str) -> List[str]:
    return [p.strip() for p in str(as_path or "").replace(",", " ").split() if p.strip().isdigit()]


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
        # Forgery cases in this benchmark are mostly clean repeated fake adjacency.
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


def summarize_latency(rows: List[Dict[str, Any]]) -> Dict[str, float]:
    durs = [float(r.get("latency_sec", 0.0)) for r in rows]
    if not durs:
        return {"mean_sec": 0.0, "median_sec": 0.0, "p90_sec": 0.0}
    durs_sorted = sorted(durs)
    p90_idx = max(0, min(len(durs_sorted) - 1, int(0.9 * len(durs_sorted)) - 1))
    return {
        "mean_sec": round(sum(durs) / len(durs), 4),
        "median_sec": round(statistics.median(durs), 4),
        "p90_sec": round(durs_sorted[p90_idx], 4),
    }


def classify_error(row: Dict[str, Any]) -> str:
    status = str(row.get("status_coarse", "")).upper()
    confidence = str(row.get("confidence_label", "UNKNOWN")).upper()
    if status == "UNCERTAIN":
        return "uncertain_output"
    if not row.get("attacker_match") and row.get("type_match"):
        if confidence == "HIGH":
            return "wrong_attacker_high_confidence"
        return "wrong_attacker"
    if row.get("attacker_match") and not row.get("type_match"):
        return "wrong_type"
    if not row.get("attacker_match") and not row.get("type_match"):
        if confidence == "HIGH":
            return "wrong_type_and_attacker_high_confidence"
        return "wrong_type_and_attacker"
    return "correct"


def apply_eval_normalization(
    expected_type: str,
    status: str,
    fine_type_pred: str,
    predicted_attacker: str,
    *,
    benign_uncertain_as_benign: bool,
) -> tuple[str, str, str]:
    norm_status = status
    norm_type = fine_type_pred
    norm_attacker = predicted_attacker

    if benign_uncertain_as_benign and expected_type == "BENIGN" and status == "UNCERTAIN":
        norm_status = "BENIGN"
        norm_type = "BENIGN"
        norm_attacker = "None"

    return norm_status, norm_type, norm_attacker


async def run_case(
    case: Dict[str, Any],
    agent: BGPAgent,
    *,
    benign_uncertain_as_benign: bool,
) -> Dict[str, Any]:
    trace = await agent.diagnose_batch(case["context"], verbose=False)
    final = trace.get("final_result") or {}

    predicted_attacker_raw = normalize_asn(
        final.get("most_likely_attacker", final.get("attacker_as", "None"))
    )
    status_raw = str(final.get("status", "UNKNOWN")).upper()
    summary = str(final.get("summary", ""))
    expected_type = str(case.get("event_type", "UNKNOWN")).upper().strip()
    fine_type_pred_raw = infer_fine_type_from_output(status_raw, summary)
    status, fine_type_pred, predicted_attacker = apply_eval_normalization(
        expected_type,
        status_raw,
        fine_type_pred_raw,
        predicted_attacker_raw,
        benign_uncertain_as_benign=benign_uncertain_as_benign,
    )

    attacker_match = predicted_attacker == normalize_asn(case.get("expected_attacker"))
    type_match = fine_type_pred == expected_type
    strict_correct = attacker_match and type_match

    confidence_label = str(final.get("confidence", "UNKNOWN")).upper().strip() or "UNKNOWN"
    confidence_pct = CONFIDENCE_TO_PCT.get(confidence_label, 0.0)

    row = {
        "case_id": case.get("case_id"),
        "case_name": case.get("case_name"),
        "event_type_expected": expected_type,
        "event_type_predicted": fine_type_pred,
        "event_type_predicted_raw": fine_type_pred_raw,
        "status_coarse": map_status_to_coarse(status),
        "status_coarse_raw": map_status_to_coarse(status_raw),
        "expected_attacker": normalize_asn(case.get("expected_attacker")),
        "predicted_attacker": predicted_attacker,
        "predicted_attacker_raw": predicted_attacker_raw,
        "attacker_match": attacker_match,
        "type_match": type_match,
        "strict_correct": strict_correct,
        "confidence_label": confidence_label,
        "confidence_pct": confidence_pct,
        "latency_sec": trace.get("duration_sec"),  # filled by caller
        "rag_diagnostics": trace.get("rag_diagnostics"),
        "summary": summary,
        "noise_level": str(case.get("noise_level") or infer_case_noise_level(case)),
        "final_result": final,
        "trace_error": trace.get("error"),
    }
    row["error_category"] = classify_error(row)
    return row


async def main() -> None:
    args = parse_args()
    cases = load_synthetic_cases(args.input)
    agent = BGPAgent()

    rows: List[Dict[str, Any]] = []
    for idx, case in enumerate(cases, 1):
        start = asyncio.get_event_loop().time()
        try:
            row = await run_case(
                case,
                agent,
                benign_uncertain_as_benign=args.benign_uncertain_as_benign,
            )
        except Exception as e:
            row = {
                "case_id": case.get("case_id"),
                "case_name": case.get("case_name"),
                "event_type_expected": str(case.get("event_type", "UNKNOWN")).upper().strip(),
                "event_type_predicted": "ERROR",
                "status_coarse": "ERROR",
                "expected_attacker": normalize_asn(case.get("expected_attacker")),
                "predicted_attacker": "None",
                "attacker_match": False,
                "type_match": False,
                "strict_correct": False,
                "confidence_label": "UNKNOWN",
                "confidence_pct": 0.0,
                "latency_sec": None,
                "rag_diagnostics": None,
                "summary": "",
                "noise_level": str(case.get("noise_level") or infer_case_noise_level(case)),
                "final_result": {},
                "trace_error": str(e),
                "error_category": "runtime_error",
            }
        row["index"] = idx
        row["latency_sec"] = round(asyncio.get_event_loop().time() - start, 3)
        rows.append(row)
        print(
            f"[{idx}/{len(cases)}] {row['case_name']} "
            f"type={row['event_type_expected']} pred={row['event_type_predicted']} "
            f"attacker={row['predicted_attacker']} ok={row['strict_correct']} "
            f"time={row['latency_sec']:.2f}s"
        )

    total = len(rows)
    strict_hits = sum(1 for r in rows if r["strict_correct"])
    accuracy = strict_hits / total if total else 0.0

    benign_rows = [r for r in rows if r["event_type_expected"] == "BENIGN"]
    benign_fp = [
        r for r in benign_rows
        if r["status_coarse"] in ("MALICIOUS", "LEAK") or r["predicted_attacker"] != "None"
    ]
    fpr = (len(benign_fp) / len(benign_rows)) if benign_rows else None

    latency = summarize_latency(rows)

    confidence_values = [r["confidence_pct"] for r in rows]
    avg_confidence_pct = round(sum(confidence_values) / len(confidence_values), 2) if confidence_values else 0.0
    confidence_by_label = dict(Counter(r["confidence_label"] for r in rows))
    confidence_accuracy_gap_pct = round(avg_confidence_pct - accuracy * 100.0, 2)

    robustness_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in rows:
        robustness_groups[r["noise_level"]].append(r)
    robustness = {}
    for level, group in sorted(robustness_groups.items()):
        hits = sum(1 for r in group if r["strict_correct"])
        robustness[level] = {
            "count": len(group),
            "accuracy": round(hits / len(group), 4) if group else 0.0,
            "mean_latency_sec": round(sum(r["latency_sec"] for r in group) / len(group), 4) if group else 0.0,
            "avg_confidence_pct": round(sum(r["confidence_pct"] for r in group) / len(group), 2) if group else 0.0,
        }

    error_rows = [r for r in rows if not r["strict_correct"]]
    error_summary = {
        "total_errors": len(error_rows),
        "error_rate": round(len(error_rows) / total, 4) if total else 0.0,
        "by_category": dict(Counter(r["error_category"] for r in error_rows)),
        "examples": error_rows[:10],
    }

    report = {
        "config": {
            "input": args.input,
            "report_out": args.report_out,
            "count": total,
            "confidence_mapping_pct": CONFIDENCE_TO_PCT,
            "benign_uncertain_as_benign": args.benign_uncertain_as_benign,
        },
        "metrics": {
            "accuracy": {
                "value": round(accuracy, 4),
                "numerator": strict_hits,
                "denominator": total,
                "definition": "strict match of anomaly type and attacker AS",
            },
            "false_positive_rate": {
                "value": None if fpr is None else round(fpr, 4),
                "numerator": len(benign_fp),
                "denominator": len(benign_rows),
                "note": "null because current synthetic dataset contains no BENIGN cases" if fpr is None else "",
            },
            "latency": latency,
            "confidence": {
                "avg_confidence_pct": avg_confidence_pct,
                "by_label": confidence_by_label,
                "confidence_accuracy_gap_pct": confidence_accuracy_gap_pct,
            },
            "robustness": robustness,
            "error_case_analysis": error_summary,
        },
        "cases": rows,
    }

    out_path = Path(args.report_out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n=== Synthetic Metrics Summary ===")
    print(json.dumps(report["metrics"], ensure_ascii=False, indent=2))
    print(f"\nReport written to: {args.report_out}")


if __name__ == "__main__":
    asyncio.run(main())
