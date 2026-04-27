import asyncio
import json
import os
import ast
import re
import traceback
from datetime import datetime
from openai import AsyncOpenAI
from tools.bgp_toolkit import BGPToolKit
from tools.rag_manager import RAGManager
from tools.project_paths import RAG_DB_DIR, REPORT_FORENSICS_DIR

# --- 配置 ---
API_KEY = os.getenv("DEEPSEEK_API_KEY") or os.getenv("OPENAI_API_KEY", "")
BASE_URL = "https://api.deepseek.com"

class BGPAgent:
    def __init__(self, report_dir=None):
        """
        初始化 BGP 溯源 Agent
        """
        if not API_KEY:
            raise ValueError("缺少 API Key，请设置环境变量 DEEPSEEK_API_KEY 或 OPENAI_API_KEY。")
        self.client = AsyncOpenAI(api_key=API_KEY, base_url=BASE_URL)
        
        # 1. 初始化工具箱
        self.toolkit = BGPToolKit()
        
        # 2. 初始化 RAG (指向溯源专用数据库)
        # 注意: 请确保你运行了 gen_forensics_data.py 并构建了此数据库
        db_path = str(RAG_DB_DIR)
        
        # 为了防止目录不存在报错，加个判断，如果新库不存在则回退到默认
        if not os.path.exists(db_path):
            print(f"⚠️ [Warning] 溯源数据库 {db_path} 未找到。")
            
        self.rag = RAGManager(db_path=db_path)
        self.report_dir = report_dir or str(REPORT_FORENSICS_DIR)

        # ==========================================
        # 🎯 System Prompt: 溯源专家设定（单条）
        # ==========================================
        self.base_system_prompt = """
你是一个 BGP 安全溯源专家 (Digital Forensics Expert)。
你的核心任务是分析 BGP 路由更新，并**找出攻击者 (Attacker AS)**。

**溯源分析方法论 (Methodology):**
1. **Path Forensics (路径取证)**:
   - 检查 `AS_PATH` 属性。
   - 路径最右侧的 AS (Last Hop) 是 **Origin AS**。
   - 如果 Origin AS != Expected Owner，且无合法授权，则该 Origin AS 是**首要嫌疑人 (Primary Suspect)**。

2. **Route Leak (路由泄露)**:
   - 如果 Origin 正确，但路径违反商业关系 (例如 Tier-1 互联出现异常)，攻击者可能是路径中间的 AS。

**可用工具:**
- `path_forensics`: 专门用于解析 AS Path，提取 Origin 并自动判定嫌疑人。
- `graph_analysis`: 查询图谱，验证嫌疑人与 Owner 是否有真实连接。
- `authority_check`: 查询 RPKI 授权。

**⚠️ 严格输出格式 (JSON):**
每一次回复必须是标准 JSON，格式如下：
{
    "thought_process": "你的详细推理过程 (思维链)...",
    "tool_request": "工具名称字符串" OR null,
    "final_decision": null OR {
        "status": "MALICIOUS" | "LEAK" | "BENIGN",
        "attacker_as": "ASxxxx" (必须明确指出，如果是误判则填 'None'),
        "summary": "简短的结案陈词"
    }
}

**禁忌:**
- `tool_request` 必须是字符串，严禁返回字典/对象。
- 只有在证据确凿（已锁定 Attacker AS 或排除攻击）时，才返回 `final_decision`。
"""

        # ==========================================
        # 🎯 Batch System Prompt: 批量告警综合溯源
        # ==========================================
        self.batch_system_prompt = """
你是一个 BGP 安全溯源专家 (Digital Forensics Expert)。
你收到**一个时间窗口内的多条告警消息**，每条告警包含可疑的 BGP Update。

**重要前提：**
- 告警消息不一定 100% 准确，可能存在误报或噪声。
- 你需要**汇总所有 updates**，综合进行异常溯源分析。
- 输出**基于目前异常告警消息、最有可能是攻击者的 AS 号**，并给出置信度。

**溯源分析方法论:**
1. **Path Forensics**: 对每条 update 提取 Origin，统计哪些 AS 作为可疑 Origin 出现最频繁。
2. **交叉验证**: 若多条 update 指向同一 AS，则该 AS 嫌疑更大；若相互矛盾，需权衡证据强度。
3. **Route Leak**: 若 Origin 正确但路径异常，攻击者可能是路径中间的 Leaker。
4. **Path Forgery / Fake Adjacency**: 若 Origin 正确，但合法 Owner 前反复出现稳定的异常跳点或伪造邻接，应优先考虑 FORGERY。

**可用工具:**
- `path_forensics`: 对批量 updates 做路径取证，返回每条的分析 + 汇总统计。
- `graph_analysis`: 查询图谱验证嫌疑人与 Owner 的拓扑关系（可指定某条 update）。
- `authority_check`: 查询 RPKI 授权（可指定某条 update）。
- `forgery_check`: 检查 origin 正常场景下是否存在稳定的伪造邻接 / 路径伪造。

**⚠️ 严格输出格式 (JSON):**
{
    "thought_process": "你的详细推理过程，需考虑多条告警的综合证据...",
    "tool_request": "工具名称字符串" OR null,
    "final_decision": null OR {
        "status": "MALICIOUS" | "LEAK" | "FORGERY" | "BENIGN" | "UNCERTAIN",
        "most_likely_attacker": "ASxxxx" (基于目前告警最可能的攻击者，若无则填 'None'),
        "confidence": "High" | "Medium" | "Low",
        "summary": "综合 X 条告警消息的分析结论，说明为何该 AS 最有可能是攻击者"
    }
}
"""

    async def _call_llm(self, messages):
        """调用 DeepSeek API (JSON 模式)"""
        try:
            response = await self.client.chat.completions.create(
                model="deepseek-chat",
                messages=messages,
                response_format={'type': 'json_object'}, # 强制 JSON
                temperature=0.0 # 零温度，确保逻辑严谨
            )
            content = response.choices[0].message.content
            return json.loads(content)
        except Exception as e:
            print(f"❌ API 调用失败: {e}")
            return {"thought_process": f"API Error: {str(e)}", "tool_request": None}

    def _save_report(self, trace_data, is_batch=False):
        """归档分析报告"""
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir, exist_ok=True)

        if is_batch:
            target = trace_data.get("target", {})
            updates = target.get("updates", [])
            prefix = updates[0].get("prefix", "unknown").replace("/", "_") if updates else "batch"
            timestamp = datetime.now().strftime("%H%M%S")
            filename = f"forensics_batch_{prefix}_{len(updates)}updates_{timestamp}.json"
        else:
            prefix = trace_data.get("target", {}).get("prefix", "unknown").replace("/", "_")
            timestamp = datetime.now().strftime("%H%M%S")
            filename = f"forensics_{prefix}_{timestamp}.json"
        
        try:
            with open(os.path.join(self.report_dir, filename), 'w', encoding='utf-8') as f:
                json.dump(trace_data, f, indent=4, ensure_ascii=False)
        except Exception:
            pass

    @staticmethod
    def _normalize_asn(asn):
        if asn is None:
            return "None"
        s = str(asn).strip().upper()
        if s in ("", "NONE", "UNKNOWN"):
            return "None"
        if s.startswith("AS"):
            s = s[2:]
        digits = "".join(ch for ch in s if ch.isdigit())
        return digits if digits else "None"

    def _extract_batch_attacker(self, final_decision):
        if not isinstance(final_decision, dict):
            return "None"
        return self._normalize_asn(
            final_decision.get("most_likely_attacker", final_decision.get("attacker_as", "None"))
        )

    @staticmethod
    def _parse_path_forensics_batch_output(text):
        counts = {}
        total = 0
        if not text:
            return counts, total

        m_total = re.search(r"良性 update 数量:\s*(\d+)\s*/\s*(\d+)", str(text))
        if m_total:
            try:
                total = int(m_total.group(2))
            except ValueError:
                total = 0

        for asn, cnt in re.findall(r"AS(\d+):\s*出现\s*(\d+)\s*次", str(text)):
            counts[asn] = counts.get(asn, 0) + int(cnt)

        return counts, total

    @staticmethod
    def _parse_authority_batch_output(text):
        counts = {}
        if not text:
            return counts

        # 样例: 汇总: 非法 Origin AS 出现频次: {'9498': 20}
        m = re.search(r"非法 Origin AS 出现频次:\s*(\{.*\})", str(text))
        if not m:
            return counts
        try:
            obj = ast.literal_eval(m.group(1))
            if isinstance(obj, dict):
                for k, v in obj.items():
                    asn = "".join(ch for ch in str(k) if ch.isdigit())
                    if not asn:
                        continue
                    try:
                        counts[asn] = counts.get(asn, 0) + int(v)
                    except (TypeError, ValueError):
                        continue
        except Exception:
            return counts
        return counts

    @staticmethod
    def _parse_forgery_batch_output(text):
        if not text:
            return {"suspect": "None", "count": 0, "ratio": 0.0, "strong": 0, "verdict": ""}
        m = re.search(
            r"forgery_candidate=AS(\d+); count=(\d+); ratio=([0-9.]+); strong=(\d+); .* verdict=([A-Z_]+)",
            str(text),
        )
        if not m:
            return {"suspect": "None", "count": 0, "ratio": 0.0, "strong": 0, "verdict": ""}
        return {
            "suspect": m.group(1),
            "count": int(m.group(2)),
            "ratio": float(m.group(3)),
            "strong": int(m.group(4)),
            "verdict": m.group(5),
        }

    @staticmethod
    def _detect_clean_benign_batch(alert_batch):
        updates = (alert_batch or {}).get("updates", [])
        if not updates:
            return False
        for u in updates:
            path = [p for p in str(u.get("as_path", "")).replace(",", " ").split() if p.isdigit()]
            expected = str(u.get("expected_origin", "")).strip()
            detected = str(u.get("detected_origin") or (path[-1] if path else "")).strip()
            if not path or not expected:
                return False
            if detected != expected:
                return False
            if len(path) > 2:
                return False
        return True

    @staticmethod
    def _likely_forgery_candidate_batch(alert_batch):
        updates = (alert_batch or {}).get("updates", [])
        if not updates:
            return False
        has_long_tail = False
        for u in updates:
            path = [p for p in str(u.get("as_path", "")).replace(",", " ").split() if p.isdigit()]
            expected = str(u.get("expected_origin", "")).strip()
            detected = str(u.get("detected_origin") or (path[-1] if path else "")).strip()
            if not path or not expected or detected != expected:
                return False
            if len(path) >= 4:
                has_long_tail = True
        return has_long_tail

    def _update_tool_evidence(self, evidence, tool_name, tool_output):
        tname = str(tool_name or "").strip().lower()
        evidence["called_tools"].add(tname)

        if tname == "path_forensics":
            path_counts, parsed_total = self._parse_path_forensics_batch_output(tool_output)
            for asn, cnt in path_counts.items():
                evidence["path_suspects"][asn] = evidence["path_suspects"].get(asn, 0) + cnt
            if parsed_total:
                evidence["parsed_total_updates"] = max(evidence.get("parsed_total_updates", 0), parsed_total)

        if tname == "authority_check":
            invalid_counts = self._parse_authority_batch_output(tool_output)
            for asn, cnt in invalid_counts.items():
                evidence["rpki_invalid"][asn] = evidence["rpki_invalid"].get(asn, 0) + cnt

        if tname == "forgery_check":
            fg = self._parse_forgery_batch_output(tool_output)
            if fg["suspect"] != "None":
                evidence["forgery_suspect"] = fg["suspect"]
                evidence["forgery_count"] = fg["count"]
                evidence["forgery_ratio"] = fg["ratio"]
                evidence["forgery_strong"] = fg["strong"]
                evidence["forgery_verdict"] = fg["verdict"]

    @staticmethod
    def _dominant_from_counter(counter):
        if not counter:
            return ("None", 0, 0.0)
        asn, cnt = max(counter.items(), key=lambda x: x[1])
        total = sum(counter.values())
        ratio = cnt / total if total else 0.0
        return asn, cnt, ratio

    def _build_uncertain_decision(self, reason):
        return {
            "status": "UNCERTAIN",
            "most_likely_attacker": "None",
            "confidence": "Low",
            "summary": f"证据存在冲突或一致性不足，暂不输出确定攻击者。原因: {reason}",
        }

    def _batch_correction_gate(self, final_decision, rag_meta, evidence, total_updates):
        """
        批量纠偏闸门：
        1) 一致性不足时，要求补充工具证据或降级 UNCERTAIN
        2) RAG 与工具证据冲突时，拒绝被 RAG 误导的结论
        """
        if not isinstance(final_decision, dict):
            return {"action": "revise", "reason": "final_decision 为空或格式错误。"}

        pred_asn = self._extract_batch_attacker(final_decision)
        status = str(final_decision.get("status", "UNKNOWN")).upper()
        confidence = str(final_decision.get("confidence", "Low")).upper()
        rag_top = self._normalize_asn(rag_meta.get("rag_top_attacker"))
        rag_top_score = float(rag_meta.get("rag_top_attacker_score", 0.0) or 0.0)
        low_consensus = bool(rag_meta.get("low_consensus", False))

        tool_asn_path, tool_cnt_path, tool_ratio_path = self._dominant_from_counter(evidence["path_suspects"])
        tool_asn_rpki, tool_cnt_rpki, tool_ratio_rpki = self._dominant_from_counter(evidence["rpki_invalid"])
        forgery_asn = evidence.get("forgery_suspect", "None")
        forgery_cnt = int(evidence.get("forgery_count", 0) or 0)
        forgery_ratio = float(evidence.get("forgery_ratio", 0.0) or 0.0)
        forgery_strong_cnt = int(evidence.get("forgery_strong", 0) or 0)
        forgery_verdict = str(evidence.get("forgery_verdict", ""))

        strong_path = tool_asn_path != "None" and (tool_cnt_path >= 2 or tool_ratio_path >= 0.60)
        strong_rpki = tool_asn_rpki != "None" and (tool_cnt_rpki >= 2 or tool_ratio_rpki >= 0.60)
        strong_forgery = (
            forgery_asn != "None"
            and ((forgery_cnt >= 2 and forgery_ratio >= 0.60) or forgery_strong_cnt >= 2 or forgery_verdict == "FORGERY_STRONG")
        )
        tools_ready = ("path_forensics" in evidence["called_tools"]) and ("authority_check" in evidence["called_tools"])
        strong_tools = strong_path or strong_rpki or strong_forgery

        if (
            pred_asn == "None"
            and status == "UNCERTAIN"
            and evidence.get("direct_benign", False)
            and not strong_path
            and not strong_rpki
            and not strong_forgery
        ):
            return {
                "action": "accept",
                "decision": {
                    "status": "BENIGN",
                    "most_likely_attacker": "None",
                    "confidence": "Medium",
                    "summary": "所有 updates 的 origin 与合法 owner 一致，且仅表现为直连上游传播，未见稳定攻击证据，按良性处理。",
                },
            }

        # Gate-1: 一致性不足，且工具证据薄弱 -> 不给确定归因
        if low_consensus and not strong_tools:
            if not tools_ready:
                return {
                    "action": "revise",
                    "reason": "当前告警一致性不足，且缺少 path_forensics + authority_check 的交叉证据，请先补证后再结案。",
                }
            return {
                "action": "accept",
                "decision": self._build_uncertain_decision(
                    f"输入一致性低(dominant_ratio={rag_meta.get('dominant_ratio', 0):.2f})且工具证据不充分"
                ),
            }

        # Gate-2: 工具证据强且结论与工具主证据冲突 -> 要求重判
        if strong_path and pred_asn not in ("None", tool_asn_path):
            return {
                "action": "revise",
                "reason": f"path_forensics 主证据指向 AS{tool_asn_path}，当前结论为 AS{pred_asn}，请解释冲突并重判。",
            }
        if strong_rpki and pred_asn not in ("None", tool_asn_rpki):
            return {
                "action": "revise",
                "reason": f"authority_check 主证据指向 AS{tool_asn_rpki}，当前结论为 AS{pred_asn}，请解释冲突并重判。",
            }
        if strong_forgery:
            if pred_asn not in ("None", forgery_asn):
                return {
                    "action": "revise",
                    "reason": f"forgery_check 主证据指向 AS{forgery_asn}，当前结论为 AS{pred_asn}，请解释冲突并重判。",
                }
            if status == "LEAK":
                fixed = dict(final_decision)
                fixed["status"] = "FORGERY"
                fixed["most_likely_attacker"] = f"AS{forgery_asn}"
                fixed["summary"] = (
                    f"{fixed.get('summary', '')} 工具证据显示为稳定伪造邻接，按 FORGERY 结案。"
                ).strip()
                return {"action": "accept", "decision": fixed}

        # Gate-3: 高置信度但只被 RAG 牵引，且与工具主证据冲突
        if (
            rag_top not in ("", "None")
            and rag_top_score >= 0.60
            and pred_asn == rag_top
            and strong_tools
        ):
            tool_major = tool_asn_path if strong_path else tool_asn_rpki
            if tool_major not in ("None", rag_top):
                return {
                    "action": "revise",
                    "reason": f"RAG 倾向 AS{rag_top}，但工具主证据指向 AS{tool_major}。请降低 RAG 权重并以工具证据重判。",
                }

        # Gate-4: 明显矛盾的 BENIGN 结论
        if status == "BENIGN" and strong_tools:
            return {
                "action": "revise",
                "reason": "当前为 BENIGN，但工具证据已出现强异常指向，请重新评估。",
            }

        # Gate-5: 高置信度结案但证据基础薄弱
        if confidence == "HIGH" and not strong_tools and total_updates >= 5:
            return {
                "action": "revise",
                "reason": "当前给出 High 置信度，但缺少足够强的工具证据，请补充交叉验证后再结案。",
            }

        return {"action": "accept", "decision": final_decision}

    async def diagnose(self, alert_context, verbose=False):
        """
        执行诊断流程
        """
        if verbose: 
            print(f"\n🕵️‍♂️ [Agent] 开始溯源取证: {alert_context.get('prefix')} ...")

        # --- Phase 1: RAG 知识检索 ---
        try:
            # 搜索相似的溯源案例
            rag_knowledge = self.rag.search_similar_cases(alert_context, k=2)
            if verbose and "未找到" not in str(rag_knowledge):
                print(f"📚 [RAG] 已加载历史溯源档案...")
        except Exception:
            rag_knowledge = "(RAG Database Unavailable)"

        # --- Phase 2: 构造动态 Prompt ---
        dynamic_prompt = f"""
{self.base_system_prompt}

【📂 历史溯源档案 (RAG Reference)】
{rag_knowledge}

【RAG 使用约束】
- RAG 案例仅作为辅助参考，不能直接当作当前事件事实。
- 若 RAG 与工具输出（path_forensics / authority_check / graph_analysis）冲突，必须以工具证据为准。

【🚨 当前案情证据 (Evidence)】
- Target Prefix: {alert_context.get('prefix')}
- Suspicious AS_PATH: {alert_context.get('as_path')}
- Detected Origin: {alert_context.get('detected_origin')}
- Legitimate Owner: {(alert_context.get('expected_origin') or '（观测未提供，请通过 authority_check / RPKI 推断）')}
"""
        messages = [
            {"role": "system", "content": dynamic_prompt},
            {"role": "user", "content": "请分析上述证据，使用工具拆解路径，并锁定攻击者 (Attacker AS)。"}
        ]
        
        trace = {
            "target": alert_context,
            "start_time": datetime.now().isoformat(),
            "rag_context": rag_knowledge,
            "chain_of_thought": [],
            "final_result": None
        }
        final_candidate = None

        # --- Phase 3: 推理循环 (Max 3 Rounds) ---
        for round_idx in range(1, 4):
            if verbose: print(f"--- Round {round_idx} ---")
            
            # 1. AI 思考
            resp_json = await self._call_llm(messages)
            if not resp_json: break
            
            # 2. 解析输出
            tool_req = resp_json.get("tool_request")
            final_decision = resp_json.get("final_decision")

            # === 🛡️ 鲁棒性防御: 清洗工具名 ===
            if tool_req:
                if isinstance(tool_req, dict):
                    # 如果 AI 还是返回了字典，提取第一个值
                    tool_req = list(tool_req.values())[0]
                tool_req = str(tool_req).strip()
                if tool_req.lower() == "none": tool_req = None
            # ==============================

            step_record = {
                "round": round_idx,
                "thought": resp_json.get("thought_process"),
                "ai_full_response": resp_json,
                "tool_used": tool_req,
                "tool_output": None
            }

            # 3. 分支处理
            # 优先执行工具
            if tool_req:
                if verbose: print(f"🛠️  Agent 调用工具: {tool_req}")
                
                tool_output = self.toolkit.call_tool(tool_req, alert_context)
                step_record["tool_output"] = tool_output
                trace["chain_of_thought"].append(step_record)
                
                # 将工具结果喂回给 AI
                messages.append({"role": "assistant", "content": json.dumps(resp_json)})
                messages.append({"role": "user", "content": f"【工具结果】\n{tool_output}\n\n请根据结果判断：能否锁定 Attacker AS？如果能，请输出 final_decision。"})
                continue
            
            # 如果没有工具，检查是否结案
            if final_decision:
                final_candidate = final_decision
                trace["chain_of_thought"].append(step_record)
                if round_idx < 3:
                    # 固定三轮复核：即使已初步结案，也继续让模型做后续复核并保留思考链
                    messages.append({"role": "assistant", "content": json.dumps(resp_json)})
                    messages.append({
                        "role": "user",
                        "content": (
                            f"你已给出阶段性结论（第{round_idx}轮）。"
                            "请继续下一轮复核：可补充工具验证或指出证据冲突，"
                            "并继续按JSON格式输出。"
                        ),
                    })
                    continue

                trace["final_result"] = final_candidate
                if verbose:
                    attacker = final_candidate.get('attacker_as', 'Unknown')
                    print(f"✅ 结案! 锁定攻击者: {attacker}")

                self._save_report(trace)
                return trace

            # 既没工具也没结论 (罕见情况)
            trace["chain_of_thought"].append(step_record)
            messages.append({"role": "assistant", "content": json.dumps(resp_json)})
            messages.append({"role": "user", "content": "请继续分析。"})

        if trace["final_result"] is None and final_candidate is not None:
            trace["final_result"] = final_candidate
            self._save_report(trace)
            return trace

        # --- Phase 4: 强制结算 ---
        if trace["final_result"] is None:
            if verbose: print("⚠️ 强制结案...")
            messages.append({"role": "user", "content": "分析结束。请忽略未完成步骤，立即输出 JSON，必须包含 'attacker_as'。"})
            final_resp = await self._call_llm(messages)
            if final_resp and final_resp.get("final_decision"):
                trace["final_result"] = final_resp.get("final_decision")
                trace["chain_of_thought"].append({
                    "round": "force",
                    "thought": final_resp.get("thought_process"),
                    "ai_full_response": final_resp,
                    "tool_used": None,
                    "tool_output": None,
                })

        self._save_report(trace)
        return trace

    async def diagnose_batch(self, alert_batch, verbose=False):
        """
        批量告警综合溯源：汇总时间窗口内多条 updates，综合分析，输出最有可能是攻击者的 AS。

        输入格式:
        {
            "time_window": {"start": "...", "end": "..."},  # 可选
            "updates": [
                {"prefix": "8.8.8.0/24", "as_path": "701 174", "detected_origin": "174", "expected_origin": "15169"},
                {"prefix": "8.8.8.0/24", "as_path": "701 4761", "detected_origin": "4761", "expected_origin": "15169"},
                ...
            ]
        }
        """
        updates = alert_batch.get("updates", [])
        if not updates:
            return {"error": "updates 不能为空", "final_result": None}

        if self._detect_clean_benign_batch(alert_batch):
            trace = {
                "target": alert_batch,
                "start_time": datetime.now().isoformat(),
                "rag_context": "（直连良性快速判定，未进入 RAG/LLM）",
                "rag_diagnostics": {
                    "low_consensus": False,
                    "dominant_ratio": 1.0,
                    "total_updates": len(updates),
                    "kept_updates": len(updates),
                    "dropped_updates": 0,
                    "rag_top_attacker": "",
                    "rag_top_attacker_score": 0.0,
                },
                "chain_of_thought": [
                    {
                        "round": "precheck",
                        "thought": "所有 updates 均为合法 origin 且路径长度不超过 2，命中良性快速判定。",
                        "ai_full_response": None,
                        "tool_used": "precheck",
                        "tool_output": "BENIGN_PRECHECK: all updates are direct upstream propagation with valid origin.",
                    }
                ],
                "final_result": {
                    "status": "BENIGN",
                    "most_likely_attacker": "None",
                    "confidence": "Medium",
                    "summary": "所有 updates 的 origin 与 expected_origin 一致，且仅存在直连上游传播，未发现伪造或泄露迹象。",
                },
            }
            self._save_report(trace, is_batch=True)
            return trace

        if verbose:
            print(f"\n🕵️‍♂️ [Agent] 批量溯源: 共 {len(updates)} 条告警 updates ...")

        # --- Phase 1: RAG 知识检索（含批量输入去噪与一致性诊断）---
        try:
            rag_payload = self.rag.search_similar_cases_batch_with_meta(updates, k=2)
            if not isinstance(rag_payload, dict):
                rag_payload = {}
            rag_knowledge = rag_payload.get("text", "（未找到相似历史案例）")
            rag_meta = rag_payload.get("meta") or {}
            if verbose and "未找到" not in str(rag_knowledge):
                print(f"📚 [RAG] 已加载历史溯源档案（汇总 {len(updates)} 条 updates 检索）...")
            if verbose:
                print(
                    "🧪 [RAG-纠偏] "
                    f"total={rag_meta.get('total_updates', len(updates))}, "
                    f"kept={rag_meta.get('kept_updates', len(updates))}, "
                    f"dropped={rag_meta.get('dropped_updates', 0)}, "
                    f"dominant_ratio={rag_meta.get('dominant_ratio', 1.0):.2f}, "
                    f"low_consensus={rag_meta.get('low_consensus', False)}"
                )
        except Exception:
            rag_knowledge = "(RAG Database Unavailable)"
            rag_meta = {
                "low_consensus": False,
                "dominant_ratio": 1.0,
                "total_updates": len(updates),
                "kept_updates": len(updates),
                "dropped_updates": 0,
                "rag_top_attacker": "",
                "rag_top_attacker_score": 0.0,
            }

        # --- Phase 2: 构造批量 Prompt ---
        time_info = alert_batch.get("time_window", {})
        tw_str = f"时间窗口: {time_info.get('start', 'N/A')} ~ {time_info.get('end', 'N/A')}\n" if time_info else ""

        updates_text = "\n".join([
            f"  [{i+1}] prefix={u.get('prefix')} | as_path={u.get('as_path')} | "
            f"detected_origin={u.get('detected_origin')} | expected_origin={u.get('expected_origin')}"
            for i, u in enumerate(updates)
        ])

        dynamic_prompt = f"""
{self.batch_system_prompt}

【📂 历史溯源档案 (RAG Reference)】
{rag_knowledge}

【RAG 使用约束】
- RAG 案例仅作为辅助参考，不能直接当作当前事件事实。
- 若 RAG 与工具输出（path_forensics / authority_check / forgery_check / graph_analysis）冲突，必须以工具证据为准。
- RAG 批量纠偏统计: total={rag_meta.get('total_updates', len(updates))}, kept={rag_meta.get('kept_updates', len(updates))}, dropped={rag_meta.get('dropped_updates', 0)}, dominant_ratio={rag_meta.get('dominant_ratio', 1.0):.2f}。
- 若一致性不足（low_consensus=True），在工具证据不足时应输出 UNCERTAIN，而非强行锁定攻击者。

【🚨 批量告警证据 (Batch Evidence)】
{tw_str}
共 {len(updates)} 条可疑 Update 消息:
{updates_text}

请汇总以上所有 updates，综合判断：**基于目前异常告警消息，最有可能是攻击者的 AS 号**。
"""
        messages = [
            {"role": "system", "content": dynamic_prompt},
            {"role": "user", "content": "请分析上述批量告警，优先调用 path_forensics、authority_check 与 forgery_check 进行交叉验证，再输出 most_likely_attacker 与 confidence。"}
        ]

        trace = {
            "target": alert_batch,
            "start_time": datetime.now().isoformat(),
            "rag_context": rag_knowledge,
            "rag_diagnostics": rag_meta,
            "chain_of_thought": [],
            "final_result": None
        }
        final_candidate = None

        tool_evidence = {
            "called_tools": set(),
            "path_suspects": {},
            "rpki_invalid": {},
            "parsed_total_updates": 0,
            "direct_benign": self._detect_clean_benign_batch(alert_batch),
        }

        if self._likely_forgery_candidate_batch(alert_batch):
            pre_tool = "forgery_check"
            pre_output = self.toolkit.call_tool(pre_tool, alert_batch, is_batch=True)
            self._update_tool_evidence(tool_evidence, pre_tool, pre_output)
            trace["chain_of_thought"].append({
                "round": "precheck",
                "thought": "输入满足合法 origin + 长尾异常路径特征，预先执行 forgery_check。",
                "ai_full_response": None,
                "tool_used": pre_tool,
                "tool_output": pre_output,
            })
            messages.append({
                "role": "user",
                "content": f"【预加载工具结果：forgery_check】\n{pre_output}\n\n请在后续推理中优先判断是否属于 FORGERY，而不是泛化为 LEAK。"
            })

        # --- Phase 3: 推理循环 ---
        for round_idx in range(1, 4):
            if verbose:
                print(f"--- Round {round_idx} ---")

            resp_json = await self._call_llm(messages)
            if not resp_json:
                break

            tool_req = resp_json.get("tool_request")
            final_decision = resp_json.get("final_decision")

            if tool_req:
                if isinstance(tool_req, dict):
                    tool_req = list(tool_req.values())[0]
                tool_req = str(tool_req).strip()
                if tool_req.lower() == "none":
                    tool_req = None

            step_record = {
                "round": round_idx,
                "thought": resp_json.get("thought_process"),
                "ai_full_response": resp_json,
                "tool_used": tool_req,
                "tool_output": None
            }

            if tool_req:
                if verbose:
                    print(f"🛠️  Agent 调用工具: {tool_req}")
                tool_output = self.toolkit.call_tool(tool_req, alert_batch, is_batch=True)
                self._update_tool_evidence(tool_evidence, tool_req, tool_output)
                step_record["tool_output"] = tool_output
                trace["chain_of_thought"].append(step_record)

                messages.append({"role": "assistant", "content": json.dumps(resp_json)})
                messages.append({"role": "user", "content": f"【工具结果】\n{tool_output}\n\n请综合以上结果判断：最有可能是攻击者的 AS？若能确定，请输出 final_decision（含 most_likely_attacker 与 confidence）。"})
                continue

            if final_decision:
                gate = self._batch_correction_gate(
                    final_decision=final_decision,
                    rag_meta=rag_meta,
                    evidence=tool_evidence,
                    total_updates=len(updates),
                )
                if gate.get("action") == "revise":
                    trace["chain_of_thought"].append(step_record)
                    messages.append({"role": "assistant", "content": json.dumps(resp_json)})
                    messages.append({
                        "role": "user",
                        "content": f"【纠偏闸门提示】{gate.get('reason')}\n请补充工具证据并重新给出 final_decision。"
                    })
                    continue

                final_fixed = gate.get("decision", final_decision)
                final_candidate = final_fixed
                trace["chain_of_thought"].append(step_record)
                if round_idx < 3:
                    messages.append({"role": "assistant", "content": json.dumps(resp_json)})
                    messages.append({
                        "role": "user",
                        "content": (
                            f"你已给出阶段性结论（第{round_idx}轮）。"
                            "请继续下一轮复核：检查是否与工具证据冲突，"
                            "必要时调整结论，继续按JSON格式输出。"
                        ),
                    })
                    continue

                trace["final_result"] = final_candidate
                if verbose:
                    attacker = final_candidate.get("most_likely_attacker", final_candidate.get("attacker_as", "Unknown"))
                    conf = final_candidate.get("confidence", "")
                    print(f"✅ 结案! 最可能攻击者: {attacker} (置信度: {conf})")
                self._save_report(trace, is_batch=True)
                return trace

            trace["chain_of_thought"].append(step_record)
            messages.append({"role": "assistant", "content": json.dumps(resp_json)})
            messages.append({"role": "user", "content": "请继续分析。"})

        if trace["final_result"] is None and final_candidate is not None:
            trace["final_result"] = final_candidate
            self._save_report(trace, is_batch=True)
            return trace

        # --- Phase 4: 强制结算 ---
        if trace["final_result"] is None:
            if verbose:
                print("⚠️ 强制结案...")
            messages.append({"role": "user", "content": "分析结束。请立即输出 JSON，必须包含 most_likely_attacker 和 confidence。"})
            final_resp = await self._call_llm(messages)
            if final_resp and final_resp.get("final_decision"):
                final_decision = final_resp.get("final_decision")
                gate = self._batch_correction_gate(
                    final_decision=final_decision,
                    rag_meta=rag_meta,
                    evidence=tool_evidence,
                    total_updates=len(updates),
                )
                if gate.get("action") == "accept":
                    trace["final_result"] = gate.get("decision", final_decision)
                else:
                    trace["final_result"] = self._build_uncertain_decision("强制结算阶段仍未通过纠偏闸门")
                trace["chain_of_thought"].append({
                    "round": "force",
                    "thought": final_resp.get("thought_process"),
                    "ai_full_response": final_resp,
                    "tool_used": None,
                    "tool_output": None,
                })

        if trace["final_result"] is None:
            trace["final_result"] = self._build_uncertain_decision(
                "未在限定轮次内形成可靠 final_decision，已降级输出"
            )

        self._save_report(trace, is_batch=True)
        return trace

if __name__ == "__main__":
    import sys
    agent = BGPAgent()

    # 批量模式：多条告警综合溯源
    if len(sys.argv) > 1 and sys.argv[1] == "batch":
        batch_case = {
            "time_window": {"start": "2024-01-15T10:00:00", "end": "2024-01-15T10:30:00"},
            "updates": [
                {"prefix": "8.8.8.0/24", "as_path": "701 174", "detected_origin": "174", "expected_origin": "15169"},
                {"prefix": "8.8.8.0/24", "as_path": "701 174", "detected_origin": "174", "expected_origin": "15169"},
                {"prefix": "8.8.8.0/24", "as_path": "3356 4761", "detected_origin": "4761", "expected_origin": "15169"},
            ]
        }
        asyncio.run(agent.diagnose_batch(batch_case, verbose=True))
    else:
        # 单条模式：模拟 Google 2005 真实劫持案
        test_case = {
            "prefix": "64.233.161.0/24",
            "as_path": "701 174",
            "detected_origin": "174",
            "expected_origin": "15169"
        }
        asyncio.run(agent.diagnose(test_case, verbose=True))
