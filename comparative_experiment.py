"""
BGP 溯源系统对比实验
对比四种方法：
1. 完整系统 (RAG + LLM + Tools)
2. 仅 LLM (无 RAG，无工具)
3. 传统规则检测 (Rule-based)
4. RAG + LLM (有 RAG，无工具)

评估指标：
1. 准确率 (Accuracy)
2. 时间消耗 (Latency)
3. 置信度得分 (Confidence Score)
4. 误报率 (False Positive Rate)
5. 可解释性得分 (Explainability Score)
"""
import asyncio
import argparse
import time
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from openai import AsyncOpenAI
from tabulate import tabulate
from dotenv import load_dotenv

# 加载 .env 文件
load_dotenv()

# 导入现有组件
from bgp_agent import BGPAgent
from tools.rag_manager import RAGManager
from tools.bgp_toolkit import BGPToolKit
from tools.project_paths import EVENTS_DIR, RAG_DB_DIR, COMPARATIVE_EVENTS_FILE
from tools.eval_updates_sample import select_top_high_risk_updates

# API 配置
API_KEY = os.getenv("DEEPSEEK_API_KEY") or os.getenv("OPENAI_API_KEY", "")
BASE_URL = "https://api.deepseek.com"


class ComparativeExperiment:
    """对比实验管理器"""

    def __init__(
        self,
        output_file="report/evaluation/comparative_results.json",
        realistic_input: bool = True,
    ):
        self.output_file = output_file
        self.realistic_input = realistic_input
        self.client = AsyncOpenAI(api_key=API_KEY, base_url=BASE_URL)

        # 初始化各个方法所需的组件
        self.full_agent = BGPAgent()  # 方法1: 完整系统
        self.rag_manager = RAGManager(db_path=str(RAG_DB_DIR))  # 方法4用
        self.toolkit = BGPToolKit()  # 规则检测用

        self.results = {
            "experiment_time": datetime.now().isoformat(),
            "methods": {},
            "summary": {}
        }

    def _normalize_asn(self, val):
        """清洗 AS 号"""
        if val is None:
            return "None"
        s = str(val).strip()
        if s.lower() in ("none", "unknown", ""):
            return "None"
        digits = "".join(filter(str.isdigit, s))
        return digits if digits else "None"

    def _calculate_explainability_score(self, trace: Dict) -> float:
        """
        计算可解释性得分 (0-100)
        基于：推理步骤数、工具调用次数、思维链完整性
        """
        score = 0.0

        # 1. 思维链完整性 (40分)
        cot = trace.get("chain_of_thought") or []
        if cot:
            score += min(len(cot) * 15, 40)  # 每轮推理15分，最多40分

        # 2. 工具调用证据 (30分)
        tool_calls = 0
        for step in cot:
            if step.get("tool_request"):
                tool_calls += 1
        score += min(tool_calls * 10, 30)  # 每次工具调用10分，最多30分

        # 3. 最终结论完整性 (30分)
        final = trace.get("final_result") or {}
        if final.get("status"):
            score += 10
        if final.get("attacker_as") or final.get("most_likely_attacker"):
            score += 10
        if final.get("summary") or final.get("confidence"):
            score += 10

        return min(score, 100.0)

    async def _method3_rule_based_async(self, case: Dict) -> Dict:
        """在线程池中执行同步规则检测，避免阻塞事件循环且兼容各 Python 版本。"""
        return await asyncio.to_thread(self.method3_rule_based, case)

    def _extract_confidence(self, trace: Dict) -> float:
        """提取置信度 (0-1)"""
        final = trace.get("final_result") or {}

        # 尝试从多个字段提取置信度
        if "confidence" in final:
            conf = final["confidence"]
            if isinstance(conf, (int, float)):
                return min(max(conf, 0), 1)
            elif isinstance(conf, str):
                # 尝试解析百分比或小数
                match = re.search(r'(\d+\.?\d*)%?', conf)
                if match:
                    val = float(match.group(1))
                    return val / 100 if val > 1 else val

        # 根据状态推断置信度
        status = final.get("status", "UNKNOWN")
        if status == "UNCERTAIN":
            return 0.3
        elif status in ["MALICIOUS", "BENIGN"]:
            return 0.8
        else:
            return 0.5

    async def method1_full_system(self, case: Dict) -> Dict:
        """方法1: 完整系统 (RAG + LLM + Tools)"""
        start_time = time.time()

        try:
            context = case.get("context", case)
            if isinstance(context, list) or "updates" in context:
                trace = await self.full_agent.diagnose_batch(context, verbose=False)
                is_batch = True
            else:
                trace = await self.full_agent.diagnose(context, verbose=False)
                is_batch = False

            final = trace.get("final_result") or {}
            attacker = final.get("most_likely_attacker" if is_batch else "attacker_as", "None")
            status = final.get("status", "UNKNOWN")
            confidence = self._extract_confidence(trace)
            explainability = self._calculate_explainability_score(trace)

            return {
                "attacker": self._normalize_asn(attacker),
                "status": status,
                "confidence": confidence,
                "explainability": explainability,
                "latency": time.time() - start_time,
                "trace": trace
            }
        except Exception as e:
            return {
                "attacker": "ERROR",
                "status": "ERROR",
                "confidence": 0.0,
                "explainability": 0.0,
                "latency": time.time() - start_time,
                "error": str(e)
            }

    async def method2_llm_only(self, case: Dict) -> Dict:
        """方法2: 仅 LLM (无 RAG，无工具)"""
        start_time = time.time()

        # 构造简单的 prompt
        context = case.get("context", case)
        updates = context.get("updates", []) if isinstance(context, dict) else []

        hint = ""
        if getattr(self, "realistic_input", True):
            hint = (
                "\n说明：以下为被动观测到的更新字段（通常**不含**事先给定的「合法起源」），"
                "请勿假设存在 expected_origin；请根据 as_path 末跳与前缀常识推断，无法确定时 attacker_as 填 None。\n"
            )

        prompt = f"""你是 BGP 安全专家。分析以下 BGP 更新，判断是否存在攻击者。
{hint}
更新信息：
{json.dumps(updates, indent=2, ensure_ascii=False)}

请以 JSON 格式回复：
{{
    "attacker_as": "ASxxxx 或 None",
    "status": "MALICIOUS/BENIGN/UNCERTAIN",
    "confidence": 0.0-1.0,
    "reasoning": "你的推理过程"
}}
"""

        try:
            response = await self.client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": "你是 BGP 安全专家，擅长分析路由异常。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )

            content = response.choices[0].message.content
            # 尝试解析 JSON
            result = self._parse_json_response(content)

            attacker = result.get("attacker_as", "None")
            status = result.get("status", "UNCERTAIN")
            confidence = float(result.get("confidence", 0.5))
            reasoning = result.get("reasoning", "")

            # 可解释性得分：仅基于推理文本长度
            explainability = min(len(reasoning) / 10, 50.0)  # 最多50分

            return {
                "attacker": self._normalize_asn(attacker),
                "status": status,
                "confidence": confidence,
                "explainability": explainability,
                "latency": time.time() - start_time,
                "reasoning": reasoning
            }
        except Exception as e:
            return {
                "attacker": "ERROR",
                "status": "ERROR",
                "confidence": 0.0,
                "explainability": 0.0,
                "latency": time.time() - start_time,
                "error": str(e)
            }

    def _origin_from_as_path(self, as_path: str) -> str:
        parts = (as_path or "").replace(",", " ").split()
        digits = [p.strip() for p in parts if p.strip().isdigit()]
        if not digits:
            return "None"
        return self._normalize_asn(digits[-1])

    def _moas_minority_attacker(self, updates: List[Dict]) -> Optional[str]:
        """同一前缀出现多个不同起源时，取出现次数最少的 AS 作为 MOAS 嫌疑（无外部先验时）。"""
        from collections import defaultdict

        by_pfx: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for u in updates:
            p = (u.get("prefix") or "").strip()
            o = self._origin_from_as_path(str(u.get("as_path", "") or ""))
            if not p or o == "None":
                continue
            by_pfx[p][o] += 1
        for _pfx, oc in by_pfx.items():
            if len(oc) < 2:
                continue
            attacker, _cnt = min(oc.items(), key=lambda x: x[1])
            return self._normalize_asn(attacker)
        return None

    def method3_rule_based(self, case: Dict) -> Dict:
        """方法3: 传统规则检测"""
        start_time = time.time()

        context = case.get("context", case)
        updates = context.get("updates", []) if isinstance(context, dict) else []

        if not updates:
            return {
                "attacker": "None",
                "status": "BENIGN",
                "confidence": 0.5,
                "explainability": 20.0,
                "latency": time.time() - start_time,
                "reasoning": "无更新数据",
            }

        # 真实输入：不向规则泄露 expected_origin，用 RPKI/API+知识库 + MOAS 启发式
        if getattr(self, "realistic_input", True):
            from tools.authority import AuthorityValidator

            validator = AuthorityValidator()
            invalid_asns: Dict[str, int] = {}
            lines: List[str] = []
            for i, u in enumerate(updates):
                ctx = {
                    "prefix": u.get("prefix"),
                    "as_path": str(u.get("as_path", "") or ""),
                }
                try:
                    res = validator.run(ctx)
                except Exception as e:
                    res = f"ERROR: {e}"
                lines.append(f"[{i+1}] {res}")
                if "INVALID" in res:
                    o = self._origin_from_as_path(ctx["as_path"])
                    if o != "None":
                        invalid_asns[o] = invalid_asns.get(o, 0) + 1

            if invalid_asns:
                attacker, count = max(invalid_asns.items(), key=lambda x: x[1])
                sample = lines[0] if lines else ""
                reasoning_txt = (
                    f"RPKI/权威核查: {count}/{len(updates)} 条报 INVALID，主嫌疑 AS{attacker}。"
                    f" 示例: {sample[:200]}"
                )
                return {
                    "attacker": attacker,
                    "status": "MALICIOUS",
                    "confidence": min(0.55 + (count / len(updates)) * 0.35, 0.95),
                    "explainability": 40.0,
                    "latency": time.time() - start_time,
                    "reasoning": reasoning_txt,
                }

            moas = self._moas_minority_attacker(updates)
            if moas and moas != "None":
                rs = f"同前缀多起源(MOAS): 少数派 AS{moas} 作为嫌疑"
                return {
                    "attacker": moas,
                    "status": "MALICIOUS",
                    "confidence": 0.65,
                    "explainability": 40.0,
                    "latency": time.time() - start_time,
                    "reasoning": rs,
                }

            return {
                "attacker": "None",
                "status": "BENIGN",
                "confidence": 0.55,
                "explainability": 40.0,
                "latency": time.time() - start_time,
                "reasoning": "RPKI/权威未报 INVALID 且无同前缀 MOAS；判良性/无确定攻击者",
            }

        # 旧版「标签泄露」规则：观测起源 vs 给定 expected_origin
        origin_count = {}
        expected_origin = None

        for u in updates:
            detected = self._normalize_asn(u.get("detected_origin"))
            expected = self._normalize_asn(u.get("expected_origin"))

            if detected != "None":
                origin_count[detected] = origin_count.get(detected, 0) + 1
            if expected and expected != "None":
                expected_origin = expected

        attacker = "None"
        status = "BENIGN"
        confidence = 0.5
        reasoning = []

        if origin_count:
            most_common = max(origin_count.items(), key=lambda x: x[1])
            candidate_as = most_common[0]
            count = most_common[1]

            if expected_origin and candidate_as != expected_origin:
                attacker = candidate_as
                status = "MALICIOUS"
                confidence = min(0.6 + (count / len(updates)) * 0.3, 0.95)
                reasoning.append(
                    f"检测到 AS{candidate_as} 在 {count}/{len(updates)} 条更新中作为异常 Origin"
                )
                reasoning.append(f"预期 Origin 为 AS{expected_origin}")
            else:
                reasoning.append("所有更新的 Origin 与预期一致")

        explainability = 40.0

        return {
            "attacker": attacker,
            "status": status,
            "confidence": confidence,
            "explainability": explainability,
            "latency": time.time() - start_time,
            "reasoning": " | ".join(reasoning),
        }

    async def method4_rag_llm_no_tools(self, case: Dict) -> Dict:
        """方法4: RAG + LLM (有 RAG，无工具)"""
        start_time = time.time()

        context = case.get("context", case)
        updates = context.get("updates", []) if isinstance(context, dict) else []

        # 1. RAG 检索相似案例
        rag_context = ""
        if updates:
            query_text = f"prefix: {updates[0].get('prefix', '')} origin: {updates[0].get('detected_origin', '')}"
            try:
                rag_results = self.rag_manager.retrieve(query_text, top_k=3)
                if rag_results:
                    rag_context = "\n\n参考案例：\n"
                    for i, r in enumerate(rag_results, 1):
                        rag_context += f"{i}. {r.get('text', '')}\n"
            except:
                pass

        # 2. 构造 prompt（包含 RAG 上下文）
        hint = ""
        if getattr(self, "realistic_input", True):
            hint = (
                "\n说明：观测更新**不含**事先给定的合法起源 AS，请勿依赖 expected_origin；"
                "结合参考案例与 as_path 判断，不确定则 attacker_as=None。\n"
            )

        prompt = f"""你是 BGP 安全专家。分析以下 BGP 更新，判断是否存在攻击者。
{hint}
{rag_context}

当前更新信息：
{json.dumps(updates, indent=2, ensure_ascii=False)}

请以 JSON 格式回复：
{{
    "attacker_as": "ASxxxx 或 None",
    "status": "MALICIOUS/BENIGN/UNCERTAIN",
    "confidence": 0.0-1.0,
    "reasoning": "你的推理过程"
}}
"""

        try:
            response = await self.client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": "你是 BGP 安全专家，擅长分析路由异常。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )

            content = response.choices[0].message.content
            result = self._parse_json_response(content)

            attacker = result.get("attacker_as", "None")
            status = result.get("status", "UNCERTAIN")
            confidence = float(result.get("confidence", 0.5))
            reasoning = result.get("reasoning", "")

            # 可解释性：有 RAG 上下文，得分稍高
            explainability = min(len(reasoning) / 8, 60.0)  # 最多60分

            return {
                "attacker": self._normalize_asn(attacker),
                "status": status,
                "confidence": confidence,
                "explainability": explainability,
                "latency": time.time() - start_time,
                "reasoning": reasoning,
                "rag_used": bool(rag_context)
            }
        except Exception as e:
            return {
                "attacker": "ERROR",
                "status": "ERROR",
                "confidence": 0.0,
                "explainability": 0.0,
                "latency": time.time() - start_time,
                "error": str(e)
            }

    def _parse_json_response(self, content: str) -> Dict:
        """从 LLM 响应中解析 JSON"""
        # 尝试直接解析
        try:
            return json.loads(content)
        except:
            pass

        # 尝试提取 JSON 代码块
        match = re.search(r'```json\s*(\{.*?\})\s*```', content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except:
                pass

        # 尝试提取任意 JSON 对象
        match = re.search(r'\{.*\}', content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except:
                pass

        return {}

    async def run_single_case(self, case: Dict, case_idx: int) -> Dict:
        """对单个案例运行所有方法"""
        case_name = case.get("name", f"Case_{case_idx}")
        expected = self._normalize_asn(case.get("expected_attacker"))
        case_type = case.get("type", "MALICIOUS")

        n_up = len(case.get("context", {}).get("updates", []))
        eb = case.get("eval_batch", "")
        extra = f", {n_up} 条 updates" + (f" ({eb})" if eb else "")
        print(f"\n[{case_idx}] 测试案例: {case_name} (预期: AS{expected}, 类型: {case_type}{extra})")

        results = {
            "case_name": case_name,
            "expected_attacker": expected,
            "case_type": case_type,
            "methods": {},
        }
        if case.get("event_type"):
            results["event_type"] = case.get("event_type")
        if case.get("noise_level"):
            results["noise_level"] = case.get("noise_level")
        if case.get("context", {}).get("updates"):
            results["context_updates"] = case.get("context", {}).get("updates")
        if case.get("eval_batch"):
            results["eval_batch"] = case["eval_batch"]
            results["eval_update_count"] = case.get("eval_update_count")

        # 运行四种方法
        methods = [
            ("完整系统(RAG+LLM+Tools)", self.method1_full_system(case)),
            ("仅LLM", self.method2_llm_only(case)),
            ("规则检测", self._method3_rule_based_async(case)),
            ("RAG+LLM(无工具)", self.method4_rag_llm_no_tools(case))
        ]

        for method_name, method_coro in methods:
            print(f"  - 运行 {method_name}...", end=" ", flush=True)
            result = await method_coro

            # 判断是否正确
            predicted = result["attacker"]
            status = result.get("status", "UNKNOWN")
            if case_type == "BENIGN":
                # 良性：不应断言攻击者；标为 MALICIOUS 视为错误
                is_correct = predicted == "None" and status != "MALICIOUS"
            else:
                is_correct = predicted == expected

            result["is_correct"] = is_correct
            results["methods"][method_name] = result

            status_icon = "✅" if is_correct else "❌"
            print(f"{status_icon} AS{predicted} ({result['latency']:.2f}s)")

        return results

    def calculate_metrics(self, all_results: List[Dict]) -> Dict:
        """计算各方法的综合指标"""
        methods = ["完整系统(RAG+LLM+Tools)", "仅LLM", "规则检测", "RAG+LLM(无工具)"]
        metrics = {}

        for method in methods:
            correct = 0
            total = 0
            latencies = []
            confidences = []
            explainabilities = []

            # 误报率统计
            benign_cases = 0
            false_positives = 0

            for case_result in all_results:
                if method not in case_result["methods"]:
                    continue

                result = case_result["methods"][method]
                total += 1

                if result["is_correct"]:
                    correct += 1

                latencies.append(result["latency"])
                confidences.append(result["confidence"])
                explainabilities.append(result["explainability"])

                # 误报率：良性案例被误判为存在攻击（宣称攻击者或标为 MALICIOUS）
                if case_result["case_type"] == "BENIGN":
                    benign_cases += 1
                    if result["attacker"] != "None" or result.get("status") == "MALICIOUS":
                        false_positives += 1

            accuracy = (correct / total * 100) if total > 0 else 0
            avg_latency = sum(latencies) / len(latencies) if latencies else 0
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0
            avg_explainability = sum(explainabilities) / len(explainabilities) if explainabilities else 0
            false_positive_rate = (
                (false_positives / benign_cases * 100) if benign_cases > 0 else None
            )

            metrics[method] = {
                "accuracy": accuracy,
                "correct": correct,
                "total": total,
                "avg_latency": avg_latency,
                "avg_confidence": avg_confidence,
                "avg_explainability": avg_explainability,
                "false_positive_rate": false_positive_rate,
                "false_positives": false_positives,
                "benign_cases": benign_cases,
            }

        return metrics

    def print_summary_table(self, metrics: Dict):
        """打印汇总表格"""
        table_data = []
        for method, m in metrics.items():
            fpr = m["false_positive_rate"]
            fpr_s = "N/A" if fpr is None else f"{fpr:.1f}%"
            table_data.append([
                method,
                f"{m['accuracy']:.1f}%",
                f"{m['correct']}/{m['total']}",
                f"{m['avg_latency']:.2f}s",
                f"{m['avg_confidence']:.2f}",
                f"{m['avg_explainability']:.1f}",
                fpr_s,
            ])

        headers = ["方法", "准确率", "正确/总数", "平均时延", "平均置信度", "可解释性", "误报率"]
        print("\n" + "=" * 120)
        print("📊 对比实验汇总")
        print("=" * 120)
        print(tabulate(table_data, headers=headers, tablefmt="grid"))

    async def run_experiment(self, cases: List[Dict], experiment_meta: Optional[Dict] = None):
        """运行完整实验"""
        print(f"\n🚀 开始对比实验，共 {len(cases)} 个案例")
        print("=" * 80)

        all_results = []
        for i, case in enumerate(cases, 1):
            result = await self.run_single_case(case, i)
            all_results.append(result)

        # 计算指标
        metrics = self.calculate_metrics(all_results)

        # 保存结果
        self.results["methods"] = metrics
        self.results["detailed_results"] = all_results
        self.results["experiment_meta"] = experiment_meta or {}
        self.results["summary"] = {
            "total_cases": len(cases),
            "best_method": max(metrics.items(), key=lambda x: x[1]["accuracy"])[0],
            "fastest_method": min(metrics.items(), key=lambda x: x[1]["avg_latency"])[0]
        }

        # 输出汇总
        self.print_summary_table(metrics)

        # 保存到文件
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        print(f"\n✅ 实验完成！结果已保存到: {self.output_file}")
        print(f"🏆 最佳方法: {self.results['summary']['best_method']}")
        print(f"⚡ 最快方法: {self.results['summary']['fastest_method']}")


def load_test_cases(
    limit: Optional[int] = 10,
    json_file: Optional[str] = None,
    realistic_input: bool = True,
):
    """加载测试案例（从 JSON 列表构造合成 snapshots，用于快速对照）"""
    test_file = json_file or str(COMPARATIVE_EVENTS_FILE)

    if not os.path.exists(test_file):
        print(f"⚠️ 测试文件不存在: {test_file}")
        return []

    try:
        with open(test_file, "r", encoding="utf-8") as f:
            events = json.load(f)
    except Exception as e:
        print(f"❌ 读取测试文件失败: {e}")
        return []

    if limit is not None:
        events = events[:limit]

    cases = []
    for event in events:
        prefix = event.get("prefix", "")
        victim = event.get("victim", "")
        attacker = event.get("attacker", "")
        start_time = event.get("start_time", "")
        end_time = event.get("end_time", "")
        source = event.get("source", "anomaly")

        # 构造模拟的 BGP 更新数据
        our_updates = []

        is_benign = not attacker or str(attacker).lower() == "none"

        if not is_benign:
            # 恶意案例：生成异常更新
            our_updates.append({
                "prefix": prefix,
                "as_path": f"1234 5678 {attacker}",
                "detected_origin": attacker,
                "expected_origin": victim,
            })
            our_updates.append({
                "prefix": prefix,
                "as_path": f"9999 {attacker}",
                "detected_origin": attacker,
                "expected_origin": victim,
            })
        else:
            # 良性案例：生成正常更新
            our_updates.append({
                "prefix": prefix,
                "as_path": f"1234 5678 {victim}",
                "detected_origin": victim,
                "expected_origin": victim,
            })

        norm_updates = _normalize_updates_for_agent(
            our_updates, include_expected_origin=not realistic_input
        )
        context = {
            "time_window": {"start": start_time, "end": end_time},
            "updates": norm_updates,
        }

        label = source if source else event.get("description", "")
        cases.append({
            "name": (label or f"{prefix}_{attacker or 'benign'}")[:80],
            "type": "BENIGN" if is_benign else "MALICIOUS",
            "context": context,
            "expected_attacker": None if is_benign else attacker,
            "source": source,
            "realistic_input": realistic_input,
        })

    print(f"📂 加载了 {len(cases)} 个测试案例")
    return cases


def _normalize_updates_for_agent(
    updates: List[Dict],
    *,
    include_expected_origin: bool = False,
) -> List[Dict]:
    """
    只保留观测侧字段。默认 **不包含 expected_origin**（真实场景通常不随 update 提供合法起源标签）。
    设 include_expected_origin=True 可恢复旧评测（oracle 泄露）。
    """
    out: List[Dict] = []
    for u in updates:
        row = {
            "prefix": u.get("prefix", ""),
            "as_path": str(u.get("as_path", "") or ""),
            "detected_origin": str(u.get("detected_origin", "") or ""),
        }
        if include_expected_origin:
            row["expected_origin"] = str(u.get("expected_origin", "") or "")
        out.append(row)
    return out


def load_test_cases_from_events(
    events_root: Optional[str] = None,
    limit: Optional[int] = None,
    top_k_per_event: Optional[int] = None,
    prefer_eval_file: bool = True,
    pad_top_k: bool = True,
    realistic_input: bool = True,
) -> List[Dict]:
    """
    从 Step1 输出目录加载真实 updates（每个子目录一则事件）。

    优先级:
    1) 若存在 eval_updates.json（由 scripts/prepare_top10_high_risk_eval.py 生成）且非空，则使用；
    2) 否则若指定 top_k_per_event，则对 suspicious_updates 做 Top-K 高危抽样；
    3) 否则使用全部 suspicious_updates。
    """
    root = Path(events_root or EVENTS_DIR)
    if not root.is_dir():
        print(f"⚠️ 事件目录不存在: {root}")
        return []

    subdirs = sorted([p for p in root.iterdir() if p.is_dir()])
    cases: List[Dict] = []

    for ev_dir in subdirs:
        meta_path = ev_dir / "meta.json"
        sus_path = ev_dir / "suspicious_updates.json"
        eval_path = ev_dir / "eval_updates.json"
        if not meta_path.is_file() or not sus_path.is_file():
            continue
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            with open(sus_path, "r", encoding="utf-8") as f:
                suspicious = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"⚠️ 跳过 {ev_dir.name}: 读取失败 ({e})")
            continue

        if not isinstance(suspicious, list):
            continue

        updates: List[Dict] = []
        batch_note = ""

        if prefer_eval_file and eval_path.is_file():
            try:
                with open(eval_path, "r", encoding="utf-8") as f:
                    updates = json.load(f)
            except (json.JSONDecodeError, OSError):
                updates = []
            if isinstance(updates, list) and updates:
                batch_note = "eval_updates.json"
            else:
                updates = []

        if not updates:
            if not suspicious:
                print(f"⚠️ 跳过 {ev_dir.name}: suspicious_updates 为空且无可用 eval_updates")
                continue
            if top_k_per_event is not None and top_k_per_event > 0:
                updates, _meta = select_top_high_risk_updates(
                    suspicious, k=top_k_per_event, pad_to_k=pad_top_k
                )
                batch_note = f"top_{top_k_per_event}_high_risk"
            else:
                updates = suspicious
                batch_note = "full_suspicious"

        if not updates:
            print(f"⚠️ 跳过 {ev_dir.name}: 无有效 updates")
            continue

        attacker_raw = meta.get("attacker")
        is_benign = not attacker_raw or str(attacker_raw).strip().lower() == "none"
        prefix = meta.get("prefix", "")
        victim = str(meta.get("victim", "")).strip()
        st = meta.get("start_time", "")
        et = meta.get("end_time", "")
        label = meta.get("source", meta.get("case_name", ev_dir.name))

        context: Dict[str, Any] = {
            "time_window": {"start": st, "end": et},
            "updates": _normalize_updates_for_agent(
                updates, include_expected_origin=not realistic_input
            ),
        }

        cases.append({
            "name": (label or ev_dir.name)[:80],
            "type": "BENIGN" if is_benign else "MALICIOUS",
            "context": context,
            "expected_attacker": None if is_benign else str(attacker_raw).strip(),
            "source": label,
            "event_id": meta.get("event_id", ev_dir.name),
            "data_source": meta.get("data_source", ""),
            "eval_batch": batch_note,
            "eval_update_count": len(updates),
            "realistic_input": realistic_input,
        })

        if limit is not None and len(cases) >= limit:
            break

    mode = "真实输入(无 expected_origin)" if realistic_input else "Oracle(含 expected_origin)"
    print(f"📂 从 {root} 加载了 {len(cases)} 个真实事件案例 [{mode}]")
    return cases


async def _run_main_async(
    cases: List[Dict],
    output_file: str,
    experiment_meta: Optional[Dict] = None,
):
    if not cases:
        print("❌ 没有可用的测试案例")
        print(
            "💡 真实数据流程:\n"
            "   1) python scripts/step1_collect_events.py --input data/famous_bgp_events.json --source auto\n"
            "   2) python scripts/prepare_top10_high_risk_eval.py\n"
            "   3) python comparative_experiment.py --source events --events-top-k 10\n"
            "   （可选）重建事件 RAG: scripts/build_rag_from_events.py + build_vector_db.py --input data/rag_cases_from_events.jsonl\n"
            "   一键: python scripts/run_comparative_real_pipeline.py --prepare-top10"
        )
        return

    if not API_KEY:
        print("❌ 未设置 DEEPSEEK_API_KEY 或 OPENAI_API_KEY，无法调用模型")
        sys.exit(1)

    realistic_input = True
    if experiment_meta and "realistic_input" in experiment_meta:
        realistic_input = bool(experiment_meta["realistic_input"])

    experiment = ComparativeExperiment(
        output_file=output_file,
        realistic_input=realistic_input,
    )
    await experiment.run_experiment(cases, experiment_meta=experiment_meta)


def main():
    parser = argparse.ArgumentParser(description="BGP 溯源对比实验")
    parser.add_argument(
        "--source",
        choices=["events", "json"],
        default="events",
        help="events=使用 Step1 目录下的真实 suspicious_updates；json=使用 famous_bgp_events 合成快照",
    )
    parser.add_argument("--events-dir", default=str(EVENTS_DIR), help="Step1 输出根目录")
    parser.add_argument(
        "--json-file",
        default=str(COMPARATIVE_EVENTS_FILE),
        help="--source json 时的事件列表 JSON",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="最多评测前 N 个案例（默认不截断 events；json 模式默认 10）",
    )
    parser.add_argument(
        "--output",
        default="report/evaluation/comparative_results.json",
        help="结果 JSON 路径",
    )
    parser.add_argument(
        "--events-top-k",
        type=int,
        default=None,
        help="每事件使用 Top-K 条高危 updates（无 eval_updates.json 时从 suspicious 抽样；建议先运行 prepare_top10_high_risk_eval.py）",
    )
    parser.add_argument(
        "--events-no-prefer-eval",
        action="store_true",
        help="忽略 eval_updates.json，仅用 suspicious + --events-top-k 或全量",
    )
    parser.add_argument(
        "--events-no-pad",
        action="store_true",
        help="Top-K 抽样时不足 K 条不循环补齐",
    )
    parser.add_argument(
        "--oracle-expected-origin",
        action="store_true",
        help="在输入 updates 中包含 expected_origin（旧评测：泄露合法起源标签）",
    )
    args = parser.parse_args()

    realistic_input = not args.oracle_expected_origin

    experiment_meta: Dict[str, Any] = {
        "source": args.source,
        "json_file": args.json_file if args.source == "json" else None,
        "events_dir": args.events_dir if args.source == "events" else None,
        "events_top_k": args.events_top_k,
        "prefer_eval_file": not args.events_no_prefer_eval,
        "pad_top_k": not args.events_no_pad,
        "realistic_input": realistic_input,
    }

    if args.source == "events":
        cases = load_test_cases_from_events(
            args.events_dir,
            limit=args.limit,
            top_k_per_event=args.events_top_k,
            prefer_eval_file=not args.events_no_prefer_eval,
            pad_top_k=not args.events_no_pad,
            realistic_input=realistic_input,
        )
    else:
        json_path = Path(args.json_file)
        if not json_path.is_file():
            print(f"❌ 找不到 {json_path}")
            sys.exit(1)
        lim = 10 if args.limit is None else args.limit
        cases = load_test_cases(
            limit=lim,
            json_file=str(json_path.resolve()),
            realistic_input=realistic_input,
        )

    asyncio.run(_run_main_async(cases, args.output, experiment_meta=experiment_meta))


if __name__ == "__main__":
    main()
