#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from comparative_experiment import _run_main_async  # noqa: E402


def load_synthetic_cases(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    cases: List[Dict[str, Any]] = []
    for item in data:
        event_type = str(item.get("event_type", "UNKNOWN")).upper().strip()
        expected_attacker = item.get("expected_attacker", "None")
        cases.append(
            {
                "name": item.get("case_name", item.get("case_id", "synthetic_case")),
                "type": "BENIGN" if event_type == "BENIGN" else "MALICIOUS",
                "event_type": event_type,
                "context": item.get("context", {}),
                "expected_attacker": None if event_type == "BENIGN" else expected_attacker,
                "source": "synthetic",
                "case_id": item.get("case_id"),
                "noise_level": item.get("noise_level"),
                "simulation_reason": item.get("simulation_reason", ""),
            }
        )
    return cases


def main() -> None:
    parser = argparse.ArgumentParser(description="Run M1-M4 comparative experiment on synthetic benchmark")
    parser.add_argument("--input", default="data/benchmark_synthetic_cases.json", help="Synthetic benchmark JSON")
    parser.add_argument(
        "--output",
        default="report/evaluation/comparative_results_synthetic.json",
        help="Output comparative report JSON",
    )
    args = parser.parse_args()

    cases = load_synthetic_cases(args.input)
    experiment_meta = {
        "source": "synthetic_benchmark",
        "input": args.input,
        "realistic_input": True,
        "count": len(cases),
    }
    asyncio.run(_run_main_async(cases, args.output, experiment_meta=experiment_meta))


if __name__ == "__main__":
    main()
