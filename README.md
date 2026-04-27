# BGP-TraceX 3.0

BGP-TraceX 3.0 是一个面向 BGP 异常归因的研究型系统，核心目标不是只判断“有没有异常”，而是输出：

- 异常类型：`HIJACK` / `LEAK` / `FORGERY` / `BENIGN`
- 最可能攻击者 AS
- 推理链、工具证据和批量告警一致性信息

当前版本把系统主线收敛为四部分：

1. 真实事件抓取与过滤
2. RAG 知识库构建
3. Agent 溯源
4. 真实 / 模拟实验与绘图

## 1. 版本说明

- 当前版本：`3.0`
- 版本文件：[`VERSION`](/home/haomin_wang/code/BGP-TraceX---BGP-Anomaly-Trace-Analysis/VERSION)
- 推荐分支：`haomin`

3.0 的主要变化：

- 批量溯源流程稳定化，默认以 `diagnose_batch()` 为主
- 新增 `FORGERY` 识别链路
- 新增模拟基准生成、四方法对比和指标绘图脚本
- 将生成型资源从版本控制中剥离，统一走 `.gitignore`

## 2. 目录结构

```text
.
├── bgp_agent.py                         # 核心溯源 Agent
├── comparative_experiment.py           # M1/M2/M3/M4 对比实验主程序
├── build_vector_db.py                  # 构建 Chroma 向量库
├── auto_generator/auto_generator.py    # 生成合成 RAG 案例
├── scripts/
│   ├── step1_collect_events.py         # 真实事件抓取与过滤
│   ├── build_rag_from_events.py        # 从 Step1 输出构建真实事件 RAG 语料
│   ├── run_comparative_real_pipeline.py
│   ├── run_comparative_synthetic.py
│   ├── run_synthetic_metrics_experiment.py
│   ├── generate_benchmark_synthetic_cases.py
│   ├── plot_real_synthetic_method_figures.py
│   ├── prepare_top10_high_risk_eval.py
│   └── run_case_catalog_test.py
├── tools/
│   ├── bgp_toolkit.py                  # path_forensics / authority / forgery / graph 等工具
│   ├── rag_manager.py
│   ├── update_fetcher.py
│   ├── ris_mrt_fetcher.py
│   ├── authority.py
│   ├── eval_updates_sample.py
│   └── project_paths.py
├── data/
│   ├── test_events.json
│   ├── benchmark_events_real.json
│   ├── benchmark_synthetic_cases.json
│   ├── famous_bgp_events.json
│   └── case_catalog/
└── report/
```

## 3. 环境要求

### 3.1 Python

- Python `3.10+`

### 3.2 依赖

```bash
pip install openai chromadb sentence-transformers neo4j requests aiofiles tqdm tabulate mrtparse python-dotenv
```

### 3.3 环境变量

复制一份模板：

```bash
cp .env.example .env
```

最少需要：

```bash
DEEPSEEK_API_KEY=...
NEO4J_PASSWORD=neo4j
```

说明：

- 默认使用 `DeepSeek` 的 OpenAI 兼容接口
- `Neo4j` 是可选增强，不启动时 `graph_analysis` 会退化

## 4. 核心能力

### 4.1 Agent

[`bgp_agent.py`](/home/haomin_wang/code/BGP-TraceX---BGP-Anomaly-Trace-Analysis/bgp_agent.py)

当前支持：

- 单条 / 批量告警分析
- RAG 检索
- 工具调用
- 三轮复核
- 批量纠偏 gate
- `FORGERY` 与 `BENIGN` 快速判定

### 4.2 工具层

[`tools/bgp_toolkit.py`](/home/haomin_wang/code/BGP-TraceX---BGP-Anomaly-Trace-Analysis/tools/bgp_toolkit.py)

主要工具：

- `path_forensics`
- `authority_check`
- `forgery_check`
- `graph_analysis`
- `topology_check`
- `geo_check`
- `neighbor_check`

### 4.3 RAG

[`tools/rag_manager.py`](/home/haomin_wang/code/BGP-TraceX---BGP-Anomaly-Trace-Analysis/tools/rag_manager.py)

当前用于：

- 历史案例召回
- 批量更新去噪
- 一致性 / dominant ratio 统计
- 检索重排

## 5. 典型工作流

### 5.1 构建默认 RAG 库

```bash
python auto_generator/auto_generator.py
python build_vector_db.py
```

如果要用真实事件摘要重建 RAG：

```bash
python scripts/build_rag_from_events.py
python build_vector_db.py --input data/rag_cases_from_events.jsonl
```

### 5.2 抓取真实事件

```bash
python scripts/step1_collect_events.py \
  --input data/famous_bgp_events.json \
  --source auto
```

输出落在：

- `data/events/<event_id>/meta.json`
- `data/events/<event_id>/suspicious_updates.json`
- `data/events/<event_id>/eval_updates.json`

### 5.3 一键跑真实对比实验

```bash
python scripts/run_comparative_real_pipeline.py --prepare-top10
```

### 5.4 生成模拟基准

```bash
python scripts/generate_benchmark_synthetic_cases.py \
  --count 50 \
  --benign-count 15 \
  --seed 20260427
```

当前默认生成：

- `50` 条模拟案例
- 含 `BENIGN` 控制样本
- `low / medium / high` 三档噪声

### 5.5 跑模拟四方法对比

```bash
python scripts/run_comparative_synthetic.py
```

输出：

- `report/evaluation/comparative_results_synthetic.json`

### 5.6 跑模拟指标实验

```bash
python scripts/run_synthetic_metrics_experiment.py \
  --input data/benchmark_synthetic_cases.json \
  --report-out report/evaluation/synthetic_metrics_report.json
```

输出指标：

- Accuracy
- FPR
- Latency
- Confidence
- Robustness
- Error Case Analysis

### 5.7 绘图

```bash
python scripts/plot_real_synthetic_method_figures.py \
  --real-json report/evaluation/comparative_results_real.json \
  --synthetic-json report/evaluation/comparative_results_synthetic.json
```

输出到：

- `report/evaluation/figures/`

## 6. 当前评测方法

四方法定义：

- `M1`: 完整系统（RAG + LLM + Tools）
- `M2`: 仅 LLM
- `M3`: 规则检测
- `M4`: RAG + LLM（无工具）

模拟实验当前关注：

- 严格准确率：类型 + 攻击者都正确
- 攻击者归因准确率
- 误报率 `FPR`
- 平均时延
- 置信度与准确率偏差
- 不同噪声级别下的鲁棒性

## 7. 需要注意的边界

- `Neo4j` 未启动时，图分析不会参与真实推断
- `FORGERY` 对长尾伪造路径识别更稳定；短尾 `FORGERY/LEAK` 仍可能歧义
- 本项目是研究原型，不是生产级监控平台

## 8. 版本控制约定

以下内容默认不纳入版本控制：

- `.env` / 本地密钥
- `rag_db/`
- `report/evaluation/` 与 `report/forensics/`
- 生成图片
- 本地字体文件
- `data/events/` 抓取缓存
- `data/rag_cases_from_events.jsonl`

如果需要共享实验结果，建议共享：

- 生成脚本
- 输入 JSON
- 最终结论摘要

而不是直接提交本地缓存和大体积资源文件。
