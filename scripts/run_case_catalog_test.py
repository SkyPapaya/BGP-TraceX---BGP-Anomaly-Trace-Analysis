#!/usr/bin/env python3
"""
分类案例测试脚本：
1) 运行 case_catalog 案例并统计输入/输出攻击者与类型对照
2) 检查 simulation_reason 是否在模型输出中泄露

说明：
- 对于含 context.updates 的案例，直接调用 diagnose_batch。
- 对于仅含 event 的真实案例，优先尝试从本地缓存目录还原 updates；
  若未命中缓存，可通过 --fetch-missing-real 调用 Step1 在线抓取。
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from bgp_agent import BGPAgent  # noqa: E402
from tools.project_paths import (
    CASE_CATALOG_DIR,
    CASE_CATALOG_EVAL_REPORT,
    EVENTS_DIR,
    EXPERIMENT_REAL_EVENTS_DIR,
    REPORT_FORENSICS_DIR,
)  # noqa: E402


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


def map_expected_to_coarse(event_type: str) -> str:
    t = str(event_type or "").strip().upper()
    if t in ("HIJACK", "FORGERY", "MALICIOUS"):
        return "MALICIOUS"
    if t in ("LEAK", "BENIGN", "UNCERTAIN"):
        return t
    return "UNKNOWN"


def map_status_to_coarse(status: str) -> str:
    s = str(status or "").strip().upper()
    if s == "FORGERY":
        return "MALICIOUS"
    if s in ("MALICIOUS", "LEAK", "BENIGN", "UNCERTAIN"):
        return s
    return "UNKNOWN"


def infer_fine_type_from_output(status: str, summary: str) -> str:
    s = str(status or "").strip().upper()
    text = str(summary or "").lower()

    if s == "LEAK":
        return "LEAK"
    if s == "FORGERY":
        return "FORGERY"
    if s == "BENIGN":
        return "BENIGN"
    if s == "UNCERTAIN":
        return "UNCERTAIN"

    # MALICIOUS 细分：通过结论文本关键词进行弱推断
    if any(k in text for k in ("forgery", "伪造", "fake adjacency", "path spoof")):
        return "FORGERY"
    if any(k in text for k in ("hijack", "劫持", "子前缀")):
        return "HIJACK"
    if any(k in text for k in ("leak", "泄露")):
        return "LEAK"
    return "MALICIOUS"


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def build_updates_from_event_dir(event_dir: Path, fallback_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    meta_path = event_dir / "meta.json"
    updates_path = event_dir / "suspicious_updates.json"
    if not (meta_path.exists() and updates_path.exists()):
        return None

    try:
        meta = load_json(meta_path)
        updates = load_json(updates_path)
    except Exception:
        return None

    if not updates:
        return None

    model_updates = []
    for u in updates:
        model_updates.append(
            {
                "prefix": u.get("prefix", meta.get("prefix", fallback_event.get("prefix"))),
                "as_path": u.get("as_path", ""),
                "detected_origin": u.get("detected_origin", u.get("suspicious_as", "")),
                "expected_origin": u.get("expected_origin", meta.get("victim", fallback_event.get("victim", ""))),
            }
        )

    return {
        "time_window": {
            "start": meta.get("start_time", fallback_event.get("start_time")),
            "end": meta.get("end_time", fallback_event.get("end_time")),
        },
        "updates": model_updates,
    }


def event_match_score(event: Dict[str, Any], meta: Dict[str, Any]) -> int:
    score = 0
    if str(event.get("prefix")) == str(meta.get("prefix")):
        score += 2
    if normalize_asn(event.get("victim")) == normalize_asn(meta.get("victim")):
        score += 2
    if normalize_asn(event.get("attacker")) == normalize_asn(meta.get("attacker")):
        score += 2
    if str(event.get("start_time")) == str(meta.get("start_time")):
        score += 2
    if str(event.get("end_time")) == str(meta.get("end_time")):
        score += 1
    return score


def resolve_context_from_cache(
    event: Dict[str, Any], cache_dirs: List[Path]
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    candidates: List[Tuple[int, Path]] = []
    for cache_dir in cache_dirs:
        if not cache_dir.exists() or not cache_dir.is_dir():
            continue
        for child in cache_dir.iterdir():
            if not child.is_dir():
                continue
            meta_path = child / "meta.json"
            if not meta_path.exists():
                continue
            try:
                meta = load_json(meta_path)
            except Exception:
                continue
            score = event_match_score(event, meta)
            if score >= 6:
                candidates.append((score, child))

    if not candidates:
        return None, None

    candidates.sort(key=lambda x: x[0], reverse=True)
    for _, event_dir in candidates:
        context = build_updates_from_event_dir(event_dir, event)
        if context and context.get("updates"):
            return context, f"cache:{event_dir}"
    return None, None


def fetch_context_via_step1(
    event: Dict[str, Any], source: str, project_root: Path
) -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[str]]:
    temp_root = Path(tempfile.mkdtemp(prefix="case_catalog_eval_"))
    try:
        input_path = temp_root / "event.json"
        output_dir = temp_root / "events"
        with input_path.open("w", encoding="utf-8") as f:
            json.dump([event], f, ensure_ascii=False, indent=2)

        cmd = [
            sys.executable,
            "scripts/step1_collect_events.py",
            "--input",
            str(input_path),
            "--output",
            str(output_dir),
            "--source",
            source,
        ]
        subprocess.run(cmd, cwd=str(project_root), check=True, capture_output=True, text=True)

        if not output_dir.exists():
            return None, None, "Step1 输出目录不存在"

        for child in output_dir.iterdir():
            if child.is_dir():
                context = build_updates_from_event_dir(child, event)
                if context and context.get("updates"):
                    return context, f"fetched:{child}", None
        return None, None, "Step1 未生成可用 suspicious_updates"
    except subprocess.CalledProcessError as e:
        err = e.stderr.strip() if e.stderr else str(e)
        return None, None, f"Step1 执行失败: {err}"
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def load_cases(catalog_root: Path, types: List[str]) -> List[Dict[str, Any]]:
    all_cases: List[Dict[str, Any]] = []
    for t in types:
        p = catalog_root / t / "cases_10.json"
        if not p.exists():
            continue
        data = load_json(p)
        for item in data:
            c = dict(item)
            c["_catalog_type"] = t
            all_cases.append(c)
    return all_cases


def check_reason_leak(simulation_reason: str, trace_obj: Dict[str, Any]) -> Dict[str, Any]:
    trace_text = json.dumps(trace_obj, ensure_ascii=False)
    reason = str(simulation_reason or "").strip()
    return {
        "field_name_leak": "simulation_reason" in trace_text,
        "exact_text_leak": bool(reason and reason in trace_text),
    }


def bool_rate(rows: List[Dict[str, Any]], key: str) -> float:
    if not rows:
        return 0.0
    hit = sum(1 for r in rows if r.get(key))
    return round(hit / len(rows), 4)


async def run_eval(args: argparse.Namespace) -> Dict[str, Any]:
    project_root = Path(__file__).resolve().parents[1]
    catalog_root = project_root / args.catalog_root
    types = [t.strip() for t in args.types.split(",") if t.strip()]
    cache_dirs = [project_root / p.strip() for p in args.cache_dirs.split(",") if p.strip()]

    cases = load_cases(catalog_root, types)
    if args.max_cases > 0:
        cases = cases[: args.max_cases]

    agent = BGPAgent(report_dir=args.trace_report_dir)

    results: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    for idx, case in enumerate(cases, 1):
        case_id = case.get("case_id", f"CASE-{idx:03d}")
        event_type = str(case.get("event_type", "UNKNOWN")).upper().strip()
        source_type = case.get("source_type", "unknown")
        expected_attacker = normalize_asn(case.get("expected_attacker"))
        if expected_attacker == "None" and isinstance(case.get("event"), dict):
            expected_attacker = normalize_asn(case["event"].get("attacker"))

        context = case.get("context")
        context_source = "embedded"
        fetch_error = None

        if not (isinstance(context, dict) and isinstance(context.get("updates"), list) and context.get("updates")):
            event = case.get("event") if isinstance(case.get("event"), dict) else None
            if event:
                context, context_source = resolve_context_from_cache(event, cache_dirs)
                if context is None and args.fetch_missing_real:
                    context, context_source, fetch_error = fetch_context_via_step1(
                        event=event,
                        source=args.source,
                        project_root=project_root,
                    )
            else:
                context = None

        if context is None:
            skipped.append(
                {
                    "case_id": case_id,
                    "case_name": case.get("case_name"),
                    "event_type": event_type,
                    "source_type": source_type,
                    "reason": fetch_error or "案例缺少可用 context.updates，且未能从缓存/抓取恢复。",
                }
            )
            continue

        start = time.time()
        trace: Dict[str, Any] = {}
        error = None
        try:
            trace = await agent.diagnose_batch(context, verbose=args.verbose)
        except Exception as e:
            error = str(e)
            trace = {"final_result": None, "error": error}
        latency = round(time.time() - start, 3)

        final = trace.get("final_result") if isinstance(trace, dict) else None
        final = final if isinstance(final, dict) else {}
        status = str(final.get("status", "UNKNOWN")).upper()
        pred_attacker = normalize_asn(
            final.get("most_likely_attacker", final.get("attacker_as", "None"))
        )
        output_summary = str(final.get("summary", ""))
        output_type_fine = infer_fine_type_from_output(status, output_summary)
        expected_type_coarse = map_expected_to_coarse(event_type)
        output_type_coarse = map_status_to_coarse(status)

        accept_uncertain = bool(case.get("accept_uncertain", False))
        if expected_attacker == "None":
            attacker_match = (pred_attacker == "None") or (accept_uncertain and status == "UNCERTAIN")
        else:
            attacker_match = pred_attacker == expected_attacker

        type_match_coarse = output_type_coarse == expected_type_coarse
        type_match_fine = output_type_fine == event_type

        leak_check = check_reason_leak(case.get("simulation_reason", ""), trace if isinstance(trace, dict) else {})
        reason_leaked = leak_check["field_name_leak"] or leak_check["exact_text_leak"]

        results.append(
            {
                "index": idx,
                "case_id": case_id,
                "case_name": case.get("case_name"),
                "source_type": source_type,
                "event_type_input": event_type,
                "event_type_input_coarse": expected_type_coarse,
                "attacker_input": expected_attacker,
                "event_type_output_raw": status,
                "event_type_output_coarse": output_type_coarse,
                "event_type_output_fine_inferred": output_type_fine,
                "attacker_output": pred_attacker,
                "attacker_match": attacker_match,
                "type_match_coarse": type_match_coarse,
                "type_match_fine_inferred": type_match_fine,
                "both_match_coarse": attacker_match and type_match_coarse,
                "accept_uncertain": accept_uncertain,
                "simulation_reason_leak": reason_leaked,
                "simulation_reason_leak_detail": leak_check,
                "context_source": context_source,
                "updates_count": len(context.get("updates", [])),
                "latency_sec": latency,
                "error": error,
            }
        )

    valid_rows = [r for r in results if not r.get("error")]
    by_type: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in valid_rows:
        by_type[r["event_type_input"]].append(r)

    by_type_summary = {}
    for t, rows in sorted(by_type.items()):
        by_type_summary[t] = {
            "count": len(rows),
            "attacker_accuracy": bool_rate(rows, "attacker_match"),
            "type_accuracy_coarse": bool_rate(rows, "type_match_coarse"),
            "type_accuracy_fine_inferred": bool_rate(rows, "type_match_fine_inferred"),
            "both_accuracy_coarse": bool_rate(rows, "both_match_coarse"),
            "reason_leak_rate": bool_rate(rows, "simulation_reason_leak"),
            "mean_latency_sec": round(statistics.mean([r["latency_sec"] for r in rows]), 4),
        }

    summary = {
        "total_cases_loaded": len(cases),
        "total_cases_ran": len(results),
        "total_cases_skipped": len(skipped),
        "total_cases_error": sum(1 for r in results if r.get("error")),
        "attacker_accuracy": bool_rate(valid_rows, "attacker_match"),
        "type_accuracy_coarse": bool_rate(valid_rows, "type_match_coarse"),
        "type_accuracy_fine_inferred": bool_rate(valid_rows, "type_match_fine_inferred"),
        "both_accuracy_coarse": bool_rate(valid_rows, "both_match_coarse"),
        "simulation_reason_leak_count": sum(1 for r in valid_rows if r.get("simulation_reason_leak")),
        "simulation_reason_leak_rate": bool_rate(valid_rows, "simulation_reason_leak"),
        "mean_latency_sec": round(statistics.mean([r["latency_sec"] for r in valid_rows]), 4) if valid_rows else 0.0,
    }

    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "config": {
            "catalog_root": str(args.catalog_root),
            "types": types,
            "cache_dirs": args.cache_dirs.split(","),
            "fetch_missing_real": args.fetch_missing_real,
            "source": args.source,
        },
        "summary": summary,
        "by_type_summary": by_type_summary,
        "results": results,
        "skipped": skipped,
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="运行 case_catalog 分类案例测试并输出对照统计报告")
    p.add_argument("--catalog-root", default=str(CASE_CATALOG_DIR), help="案例库根目录")
    p.add_argument("--types", default="hijack,leak,forgery", help="测试类型列表，逗号分隔")
    p.add_argument(
        "--cache-dirs",
        default=f"{EVENTS_DIR},{EXPERIMENT_REAL_EVENTS_DIR}",
        help="真实案例缓存目录，逗号分隔",
    )
    p.add_argument("--fetch-missing-real", action="store_true", help="缓存缺失时调用 Step1 在线抓取真实案例")
    p.add_argument("--source", choices=["ris_mrt", "ripestat", "auto"], default="auto", help="抓取真实案例时数据源")
    p.add_argument("--report-out", default=str(CASE_CATALOG_EVAL_REPORT), help="评估报告输出路径")
    p.add_argument("--trace-report-dir", default=str(REPORT_FORENSICS_DIR), help="Agent trace 报告目录")
    p.add_argument("--max-cases", type=int, default=0, help="仅运行前 N 条案例（0 表示全部）")
    p.add_argument("--verbose", action="store_true", help="打印 Agent 详细过程")
    return p.parse_args()


async def main() -> None:
    args = parse_args()
    report = await run_eval(args)

    out_path = Path(args.report_out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
        f.write("\n")

    summary = report["summary"]
    print("=" * 96)
    print("Case Catalog Evaluation Summary")
    print("=" * 96)
    print(
        f"loaded={summary['total_cases_loaded']} | "
        f"ran={summary['total_cases_ran']} | "
        f"skipped={summary['total_cases_skipped']} | "
        f"errors={summary['total_cases_error']}"
    )
    print(
        f"attacker_acc={summary['attacker_accuracy']:.2%} | "
        f"type_acc_coarse={summary['type_accuracy_coarse']:.2%} | "
        f"type_acc_fine_inferred={summary['type_accuracy_fine_inferred']:.2%} | "
        f"both_acc_coarse={summary['both_accuracy_coarse']:.2%}"
    )
    print(
        f"simulation_reason_leak={summary['simulation_reason_leak_count']} "
        f"({summary['simulation_reason_leak_rate']:.2%}) | "
        f"mean_latency={summary['mean_latency_sec']:.2f}s"
    )
    print(f"report: {out_path}")

    if report["by_type_summary"]:
        print("-- By Type --")
        for t, s in report["by_type_summary"].items():
            print(
                f"{t:8s} count={s['count']:2d} "
                f"attacker={s['attacker_accuracy']:.2%} "
                f"type_coarse={s['type_accuracy_coarse']:.2%} "
                f"leak={s['reason_leak_rate']:.2%}"
            )

    if report["skipped"]:
        print("-- Skipped Cases --")
        for item in report["skipped"][:10]:
            print(f"{item['case_id']}: {item['reason']}")
        if len(report["skipped"]) > 10:
            print(f"... and {len(report['skipped']) - 10} more.")


if __name__ == "__main__":
    asyncio.run(main())
