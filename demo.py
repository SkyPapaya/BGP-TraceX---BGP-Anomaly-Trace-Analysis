#!/usr/bin/env python3
"""
BGP-TraceX 3.0 现场演示脚本
演示内容：经典 BGP 劫持事件溯源 + 批量告警交叉验证
"""
import asyncio
import sys
import os
import json
import time

# 必须在其他 import 之前禁用代理并加载 .env
for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy'):
    os.environ.pop(key, None)
os.environ['HF_HUB_OFFLINE'] = '1'

from dotenv import load_dotenv
load_dotenv()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bgp_agent import BGPAgent
from tools.project_paths import ensure_standard_layout, EVENTS_DIR
from tools.rag_manager import RAGManager
from tools.bgp_toolkit import BGPToolKit


def divider(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def check_env():
    """检查运行环境"""
    divider("环境检查")
    ok = True
    for key in ['DEEPSEEK_API_KEY', 'OPENAI_API_KEY']:
        if os.getenv(key):
            print(f"  ✓ {key} 已配置")
            ok = True
            break
    else:
        print("  ✗ 请配置 DEEPSEEK_API_KEY 或 OPENAI_API_KEY")
        return False

    try:
        RAGManager(db_path='./rag_db')
        print(f"  ✓ RAG 向量库可用")
    except Exception as e:
        print(f"  ✗ RAG 向量库不可用: {e}")
        ok = False

    print(f"  ✓ Python {sys.version.split()[0]}")
    return ok


async def demo_single_alert(agent):
    """演示1：单条告警溯源 —— 2014年 Indosat 劫持 Google DNS"""
    divider("演示1: 单条告警溯源 — 2014 Indosat 劫持 8.8.8.0/24")

    alert = {
        "prefix": "8.8.8.0/24",
        "as_path": "3356 4761",
        "detected_origin": "4761",
        "expected_origin": "15169"
    }

    print(f"  告警: prefix={alert['prefix']}")
    print(f"  AS_PATH: {alert['as_path']}")
    print(f"  检测到的 Origin: AS{alert['detected_origin']} (Indosat)")
    print(f"  预期合法持有者: AS{alert['expected_origin']} (Google)")
    print(f"\n  ▸ 正在分析...")

    t0 = time.time()
    trace = await agent.diagnose(alert, verbose=False)
    elapsed = time.time() - t0

    result = trace.get('final_result', {})
    attacker = result.get('most_likely_attacker', '?')
    if attacker and attacker != '?' and not str(attacker).startswith('AS'):
        attacker = f'AS{attacker}'
    print(f"\n  ┌─ 溯源结论")
    print(f"  ├─ 判定: {result.get('status', '?')}")
    print(f"  ├─ 攻击者: {attacker}")
    print(f"  ├─ 置信度: {result.get('confidence', '?')}")
    print(f"  ├─ 推理轮次: {len(trace.get('chain_of_thought', []))}")
    print(f"  └─ 耗时: {elapsed:.1f}s")

    if result.get('summary'):
        print(f"\n  摘要: {result['summary']}")

    return trace


async def demo_batch_forensics(agent):
    """演示2：批量溯源 —— 同一时间窗口多条告警交叉验证"""
    divider("演示2: 批量溯源 — 时间窗口内交叉验证")

    # 从已有事件中加载一个真实案例
    event_dirs = sorted(os.listdir(EVENTS_DIR)) if os.path.exists(EVENTS_DIR) else []
    if not event_dirs:
        print("  无可用事件数据，使用合成案例演示")
        batch = {
            "time_window": {"start": "2014-04-01T08:00:00", "end": "2014-04-01T18:00:00"},
            "updates": [
                {
                    "prefix": "8.8.8.0/24",
                    "as_path": "3356 4761",
                    "detected_origin": "4761",
                    "expected_origin": "15169"
                },
                {
                    "prefix": "8.8.4.0/24",
                    "as_path": "3356 15169",
                    "detected_origin": "15169",
                    "expected_origin": "15169"
                },
            ]
        }
    else:
        # 加载第一个可用事件
        event_id = event_dirs[0]
        meta_path = os.path.join(EVENTS_DIR, event_id, 'meta.json')
        suspicious_path = os.path.join(EVENTS_DIR, event_id, 'suspicious_updates.json')

        with open(meta_path) as f:
            meta = json.load(f)
        with open(suspicious_path) as f:
            updates = json.load(f)

        batch = {
            "time_window": {
                "start": meta.get('start_time', ''),
                "end": meta.get('end_time', ''),
            },
            "updates": updates[:10]
        }
        print(f"  使用事件: {event_id}")
        print(f"  prefix={meta['prefix']}, victim=AS{meta['victim']}")

    print(f"  告警数量: {len(batch['updates'])} 条")
    print(f"  时间窗口: {batch['time_window']['start']} ~ {batch['time_window']['end']}")
    print(f"\n  ▸ 正在执行批量溯源...")

    t0 = time.time()
    trace = await agent.diagnose_batch(batch, verbose=False)
    elapsed = time.time() - t0

    result = trace.get('final_result', {})
    rag_diag = trace.get('rag_diagnostics', {})
    attacker = result.get('most_likely_attacker', '?')
    if attacker and attacker != '?' and not str(attacker).startswith('AS'):
        attacker = f'AS{attacker}'

    print(f"\n  ┌─ 批量溯源结论")
    print(f"  ├─ 判定: {result.get('status', '?')}")
    print(f"  ├─ 攻击者: {attacker}")
    print(f"  ├─ 置信度: {result.get('confidence', '?')}")
    if rag_diag.get('consensus_ratio') is not None:
        print(f"  ├─ RAG 共识率: {rag_diag.get('consensus_ratio')}")
    if rag_diag.get('dominant_type') is not None:
        print(f"  ├─ RAG 主导类型: {rag_diag.get('dominant_type')}")
    print(f"  ├─ 推理轮次: {len(trace.get('chain_of_thought', []))}")
    print(f"  └─ 耗时: {elapsed:.1f}s")

    if result.get('summary'):
        print(f"\n  摘要: {result['summary']}")

    return trace


async def demo_tools(agent):
    """演示3：工具链独立演示"""
    divider("演示3: 工具链展示")

    toolkit = BGPToolKit()
    context = {
        "prefix": "8.8.8.0/24",
        "as_path": "3356 4761",
        "detected_origin": "4761",
        "expected_origin": "15169"
    }

    tools = ['path_forensics', 'authority_check', 'forgery_check']
    for tool_name in tools:
        print(f"\n  ▸ {tool_name}:")
        try:
            result = toolkit.call_tool(tool_name, context, is_batch=False)
            # 截取前200字符
            display = result[:300].replace('\n', '\n    ')
            print(f"    {display}")
            if len(result) > 300:
                print(f"    ... (共 {len(result)} 字符)")
        except Exception as e:
            print(f"    ✗ 调用失败: {e}")


async def demo_summary():
    """总结"""
    divider("BGP-TraceX 3.0 核心能力总结")
    print("""
  ┌────────────────────────────────────────────┐
  │  异常类型:  HIJACK / LEAK / FORGERY / BENIGN  │
  │  攻击者归因: 定位到具体 AS 号                  │
  │  置信度评估: High / Medium / Low / Uncertain  │
  │  推理链:     多轮 CoT + 工具调用完整记录       │
  │  批量纠偏:   5 道 Gate 保证结论一致性          │
  │  七种工具:   path_forensics / authority_check │
  │              forgery_check / graph_analysis   │
  │              topology_check / geo_check       │
  │              neighbor_check                   │
  └────────────────────────────────────────────┘
""")


async def main():
    ensure_standard_layout()

    if not check_env():
        print("\n环境检查未通过，请先配置环境变量。")
        return

    agent = BGPAgent()

    await demo_single_alert(agent)

    await demo_batch_forensics(agent)

    await demo_tools(agent)

    await demo_summary()

    print("演示完成！\n")


if __name__ == '__main__':
    asyncio.run(main())
