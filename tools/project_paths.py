"""
Project-wide input/output path conventions.

Use these constants instead of scattering hardcoded "data/..." and "report/..." strings.
"""
from __future__ import annotations

from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]

# Core directories
DATA_DIR = ROOT_DIR / "data"
REPORT_DIR = ROOT_DIR / "report"
RAG_DB_DIR = ROOT_DIR / "rag_db"

# Input files
TEST_EVENTS_FILE = DATA_DIR / "test_events.json"
TEST_CASES_FILE = DATA_DIR / "test_cases.json"
BENCHMARK_REAL_FILE = DATA_DIR / "benchmark_events_real.json"
BENCHMARK_SYNTHETIC_FILE = DATA_DIR / "benchmark_synthetic_cases.json"
FULL_ATTACK_CASES_FILE = DATA_DIR / "full_attack_cases.jsonl"
FORENSICS_CASES_FILE = DATA_DIR / "forensics_cases.jsonl"
# 从 Step1 输出目录生成的 RAG 语料（真实观测摘要）
RAG_CASES_FROM_EVENTS_FILE = DATA_DIR / "rag_cases_from_events.jsonl"
# 对比实验默认事件列表（与 famous_bgp_events.json 对齐时可复制或共用）
COMPARATIVE_EVENTS_FILE = DATA_DIR / "famous_bgp_events.json"

# Input directories
CASE_CATALOG_DIR = DATA_DIR / "case_catalog"

# Generated data/cache directories
EVENTS_DIR = DATA_DIR / "events"
EXPERIMENT_REAL_EVENTS_DIR = DATA_DIR / "experiments" / "real_events"

# Report directories/files
REPORT_FORENSICS_DIR = REPORT_DIR / "forensics"
REPORT_EVAL_DIR = REPORT_DIR / "evaluation"
CASE_CATALOG_EVAL_REPORT = REPORT_EVAL_DIR / "case_catalog_eval_report.json"
FEASIBILITY_REPORT = REPORT_EVAL_DIR / "feasibility_report.json"
TRACE_ACCURACY_REPORT = REPORT_EVAL_DIR / "trace_accuracy_eval.json"


def ensure_standard_layout() -> None:
    """Create standard output directories if missing."""
    EVENTS_DIR.mkdir(parents=True, exist_ok=True)
    EXPERIMENT_REAL_EVENTS_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_FORENSICS_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_EVAL_DIR.mkdir(parents=True, exist_ok=True)
