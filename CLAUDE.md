# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

BGP-TraceX 3.0 is a research system for BGP anomaly attribution. The core goal is not just detecting anomalies, but outputting:
- Anomaly type: `HIJACK` / `LEAK` / `FORGERY` / `BENIGN`
- Most likely attacker AS
- Reasoning chain with tool evidence and batch alert consistency

Current version: **3.0** (推荐分支: `haomin`)

## Environment Setup

### Prerequisites
- Python 3.10+
- DeepSeek API key (uses OpenAI-compatible interface)
- Neo4j (optional, for graph analysis enhancement)

### Installation
```bash
# Install dependencies
pip install openai chromadb sentence-transformers neo4j requests aiofiles tqdm tabulate mrtparse python-dotenv

# Configure environment
cp .env.example .env
# Edit .env and set:
#   DEEPSEEK_API_KEY=your_key
#   NEO4J_PASSWORD=neo4j  # optional
```

### Hugging Face Mirror (if needed)
```bash
export HF_ENDPOINT=https://hf-mirror.com
```

## Core Architecture

### 1. Agent Layer (`bgp_agent.py`)
The main forensics agent that orchestrates:
- Single/batch alert analysis
- RAG retrieval for historical cases
- Tool invocation (path forensics, authority check, etc.)
- Three-round review process
- Batch correction gate for noise filtering
- Fast-path detection for `FORGERY` and `BENIGN`

Key methods:
- `diagnose_batch()`: Primary entry point for batch forensics
- `diagnose()`: Single alert analysis

### 2. Tool Layer (`tools/bgp_toolkit.py`)
Provides forensics tools:
- `path_forensics`: Parse AS_PATH, extract Origin, identify suspects
- `authority_check`: Query RPKI authorization
- `forgery_check`: Detect forged paths
- `graph_analysis`: Query Neo4j topology (requires Neo4j running)
- `topology_check`, `geo_check`, `neighbor_check`: Additional validation

### 3. RAG System (`tools/rag_manager.py`)
Vector database using ChromaDB + `all-MiniLM-L6-v2` embeddings:
- Historical case retrieval
- Batch update denoising
- Consistency/dominant ratio statistics
- Retrieval reranking

Parameters:
- `recall_k=15`: Initial retrieval count
- `reject_distance=0.75`: Distance threshold
- `noise_singleton_ratio=0.10`: Noise filtering threshold

### 4. Comparative Experiments (`comparative_experiment.py`)
Evaluates four methods:
- **M1**: Full system (RAG + LLM + Tools)
- **M2**: LLM only
- **M3**: Rule-based detection
- **M4**: RAG + LLM (no tools)

Metrics: Accuracy, FPR, Latency, Confidence, Robustness

## Common Workflows

### Build RAG Database
```bash
# Generate synthetic cases
python auto_generator/auto_generator.py

# Build vector database
python build_vector_db.py

# Or use real event summaries
python scripts/build_rag_from_events.py
python build_vector_db.py --input data/rag_cases_from_events.jsonl
```

### Collect Real BGP Events
```bash
python scripts/step1_collect_events.py \
  --input data/famous_bgp_events.json \
  --source auto
```

Output structure:
- `data/events/<event_id>/meta.json`
- `data/events/<event_id>/suspicious_updates.json`
- `data/events/<event_id>/eval_updates.json`

### Run Real Event Experiments
```bash
# Full pipeline: collect events → build RAG → run comparison
python scripts/run_comparative_real_pipeline.py --prepare-top10

# Skip steps if data already exists
python scripts/run_comparative_real_pipeline.py --skip-step1 --skip-rag-jsonl --skip-vector-db
```

### Generate Synthetic Benchmark
```bash
python scripts/generate_benchmark_synthetic_cases.py \
  --count 50 \
  --benign-count 15 \
  --seed 20260427
```

Generates 50 synthetic cases with three noise levels: `low`, `medium`, `high`

### Run Synthetic Experiments
```bash
# Four-method comparison
python scripts/run_comparative_synthetic.py

# Detailed metrics experiment
python scripts/run_synthetic_metrics_experiment.py \
  --input data/benchmark_synthetic_cases.json \
  --report-out report/evaluation/synthetic_metrics_report.json
```

### Generate Figures
```bash
python scripts/plot_real_synthetic_method_figures.py \
  --real-json report/evaluation/comparative_results_real.json \
  --synthetic-json report/evaluation/comparative_results_synthetic.json
```

Output: `report/evaluation/figures/`

## Project Structure

### Key Directories
- `tools/`: Core utilities (toolkit, RAG, data providers, path helpers)
- `scripts/`: Experiment runners and data collection scripts
- `data/`: Input files and event cache (mostly gitignored)
- `report/`: Evaluation results and forensics reports (gitignored)
- `rag_db/`: Vector database (gitignored)
- `auto_generator/`: Synthetic case generator

### Path Management
Use `tools/project_paths.py` constants instead of hardcoded paths:
- `DATA_DIR`, `REPORT_DIR`, `RAG_DB_DIR`
- `EVENTS_DIR`, `CASE_CATALOG_DIR`
- `BENCHMARK_REAL_FILE`, `BENCHMARK_SYNTHETIC_FILE`

Call `ensure_standard_layout()` to create output directories.

## Important Constraints

### Neo4j Dependency
- If Neo4j is not running, `graph_analysis` tool will degrade gracefully
- The system can still function without graph analysis

### FORGERY vs LEAK Ambiguity
- `FORGERY` detection is more stable for long-tail forged paths
- Short-tail `FORGERY/LEAK` cases may still have ambiguity

### Research Prototype
This is a research system, not a production monitoring platform. Performance and reliability are optimized for experimental evaluation, not 24/7 operation.

## Version Control

The following are gitignored (do not commit):
- `.env` and local credentials
- `rag_db/` (vector database)
- `report/evaluation/` and `report/forensics/`
- Generated figures
- Local font files
- `data/events/` (event cache)
- `data/rag_cases_from_events.jsonl`

To share experimental results, commit:
- Generation scripts
- Input JSON files
- Final conclusion summaries

Not the raw cache or large resource files.

## API Configuration

Default: DeepSeek API with OpenAI-compatible interface
- Base URL: `https://api.deepseek.com`
- Model: `deepseek-chat` via async OpenAI client (`AsyncOpenAI`)
- Temperature: `0.0` (zero-temperature for deterministic reasoning)
- Response format: `{"type": "json_object"}` — all LLM calls expect structured JSON output
- Fallback: Can use `OPENAI_API_KEY` if `DEEPSEEK_API_KEY` not set

## Testing

No formal test suite currently exists. Validation is done through:
- Case catalog tests: `python scripts/run_case_catalog_test.py`
- Case catalog validation: `python scripts/validate_case_catalog.py`
- Comparative experiments (see workflows above)
- Individual case reruns: `python scripts/rerun_single_case_full_system.py`
- Feasibility experiments: `python scripts/run_feasibility_experiment.py`
- Trace accuracy comparison: `python scripts/compare_trace_accuracy.py`

## Runtime Notes

### Script Execution
All scripts must be run from the **project root directory** (not from `scripts/` or `tools/`). The codebase uses `sys.path.append(os.path.dirname(...))` patterns that assume the repo root as working directory.

### HuggingFace Model Download
`RAGManager` uses `SentenceTransformer("all-MiniLM-L6-v2")`, which triggers a ~90MB model download on first run. If behind a firewall, set the mirror first:
```bash
export HF_ENDPOINT=https://hf-mirror.com
```

### build_vector_db.py is Destructive
This script **deletes and rebuilds** the entire ChromaDB directory from scratch. It does not do incremental updates. Make sure existing RAG data is backed up if needed.

### Concurrency
`auto_generator/auto_generator.py` uses `asyncio.Semaphore(CONCURRENCY)` with `CONCURRENCY=10` — generating many cases in parallel against the LLM API. Adjust for API rate limits.

### Error Handling Pattern
The codebase uses broad `except Exception` in many places (RAG retrieval, tool calls, LLM API calls) with silent degradation. When a tool fails, it returns a fallback result rather than raising. This means debugging requires checking verbose output, not just exit codes.

### Batch Correction Gate (5 gates)
The `_batch_correction_gate()` in `bgp_agent.py` enforces evidence consistency:
1. Low-consensus + weak tool evidence → downgrade to BENIGN
2. Tool/LLM direct conflict → reject LLM result
3. RAG-overweighting detected → correction
4. BENIGN + strong contradictory evidence → override
5. High-confidence conclusion without tool evidence → flag uncertain
