import argparse
import asyncio
import json
import random
import os
import sys
import aiofiles
from dotenv import load_dotenv
from openai import AsyncOpenAI
from tqdm.asyncio import tqdm

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.config_loader import get_entities
from tools.project_paths import FULL_ATTACK_CASES_FILE

load_dotenv()

# --- 1. Configuration ---
API_KEY = os.getenv("DEEPSEEK_API_KEY") or os.getenv("OPENAI_API_KEY", "")
BASE_URL = "https://api.deepseek.com"
OUTPUT_FILE = str(FULL_ATTACK_CASES_FILE)
CONCURRENCY = 10

# --- 3. Core System Prompt (English) ---
SYSTEM_PROMPT = """
You are a BGP Security Forensics Data Generator.
Your task is to generate a synthetic BGP incident case in JSON format based on the specified [Attack Type].

**Core Requirements:**
1. Technical Accuracy: Ensure AS relationships and BGP attributes make sense.
2. **Analysis Logic (Chain of Thought)**: You must clearly explain how to identify the attacker by analyzing the AS_PATH.
3. Output strictly in valid JSON format.

**Attack Type Definitions:**
1. **[Direct Hijack]**: The attacker places itself at the very end of the AS_PATH (Origin).
   - Attribution: Observed Origin != Expected Origin.
2. **[Path Forgery]**: The attacker claims to be connected to the legitimate victim (Fake Adjacency).
   - Attribution: The Origin AS is correct (Victim), but the link between the Attacker (second to last) and the Victim (last) does not physically exist. The Attacker is the second-to-last AS.
3. **[Route Leak]**: The path is valid, Origin is correct, but an AS violated commercial rules (Valley-Free Principle).
   - Attribution: Identify the "Leaker" AS that exported a Peer/Provider route to another Provider or Peer illegally.
"""

class AttackDataGenerator:
    def __init__(self):
        if not API_KEY:
            raise ValueError("缺少 API Key，请设置环境变量 DEEPSEEK_API_KEY 或 OPENAI_API_KEY。")
        self.client = AsyncOpenAI(api_key=API_KEY, base_url=BASE_URL)
        self.sem = asyncio.Semaphore(CONCURRENCY)

    async def generate_case(self):
        entities = get_entities()
        victims = entities.get("VICTIMS", [])
        attackers = entities.get("ATTACKERS", [])
        transit_list = entities.get("TRANSIT", [])
        if not victims:
            victims = [{"asn": "15169", "name": "Google", "prefix": "8.8.8.0/24"}]
        if not attackers:
            attackers = [{"asn": "12389", "name": "Rostelecom", "desc": "ISP"}]
        if not transit_list:
            transit_list = [{"asn": "3356", "name": "Level3"}, {"asn": "174", "name": "Cogent"}]

        scenario_type = random.choice(["Direct Hijack", "Path Forgery", "Route Leak"])
        victim = random.choice(victims)
        attacker = random.choice([a for a in attackers if a.get("asn") != victim.get("asn")] or attackers)
        transit = random.choice(transit_list)

        # 2. Construct Prompt based on Scenario
        if scenario_type == "Direct Hijack":
            # Path: Transit -> Attacker (Origin)
            path_str = f"{transit['asn']} {attacker['asn']}"
            detected_origin = attacker['asn']
            user_prompt = f"""
            Generate a [Direct Origin Hijack] case.
            - Victim: {victim['name']} (AS{victim['asn']})
            - Attacker: {attacker['name']} (AS{attacker['asn']})
            - Anomalous Path: "{path_str}"
            - Attribution Logic: Highlight that the Origin changed to AS{attacker['asn']}, which is unauthorized.
            """

        elif scenario_type == "Path Forgery":
            # Path: Transit -> Attacker -> Victim (Fake Link)
            path_str = f"{transit['asn']} {attacker['asn']} {victim['asn']}"
            detected_origin = victim['asn'] # Origin looks correct!
            user_prompt = f"""
            Generate a [Path Forgery / Fake Adjacency] case.
            - Victim: {victim['name']} (AS{victim['asn']})
            - Attacker: {attacker['name']} (AS{attacker['asn']})
            - Anomalous Path: "{path_str}"
            - Attribution Logic: The Origin AS{victim['asn']} is correct, making it look legitimate.
              However, the critical flaw is the Fake Adjacency: AS{attacker['asn']} is NOT a legitimate upstream of AS{victim['asn']}.
              Therefore, the Attacker is AS{attacker['asn']} (the AS announcing the fake link).
            """

        else: # Route Leak
            # Path: Transit(Provider) <- Attacker(Leaker) <- Victim(Peer)
            path_str = f"{transit['asn']} {attacker['asn']} {victim['asn']}"
            detected_origin = victim['asn']
            user_prompt = f"""
            Generate a [Route Leak] case.
            - Victim (Peer): {victim['name']} (AS{victim['asn']})
            - Leaker (Attacker): {attacker['name']} (AS{attacker['asn']})
            - Receiver (Provider): {transit['name']} (AS{transit['asn']})
            - Anomalous Path: "{path_str}"
            - Attribution Logic: The Origin is correct and the link exists.
              However, AS{attacker['asn']} violated the Valley-Free Principle (e.g., leaking a Peer route to a Provider).
              Identify AS{attacker['asn']} as the Leaker responsible for the incident.
            """

        full_prompt = f"""
        {user_prompt}
        
        Please output JSON:
        {{
            "case_id": "gen_xxxx",
            "type": "{scenario_type}",
            "scenario_desc": "Detailed description of the incident context (English)...",
            "evidence": {{
                "prefix": "{victim['prefix']}",
                "as_path": "{path_str}",
                "detected_origin": "{detected_origin}",
                "expected_origin": "{victim['asn']}"
            }},
            "analysis_logic": "Step-by-step forensic reasoning to identify the attacker...",
            "conclusion": {{
                "status": "MALICIOUS" or "LEAK",
                "attacker_as": "{attacker['asn']}",
                "confidence": "High"
            }}
        }}
        """

        async with self.sem:
            try:
                response = await self.client.chat.completions.create(
                    model="deepseek-chat",
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": full_prompt}
                    ],
                    temperature=0.8,
                    response_format={'type': 'json_object'}
                )
                return json.loads(response.choices[0].message.content)
            except Exception:
                return None

    async def run(self, count=100):
        print(f"🚀 Starting generation of {count} Forensic Cases (English)...")
        tasks = [self.generate_case() for _ in range(count)]
        
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        
        valid_count = 0
        async with aiofiles.open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            for future in tqdm(asyncio.as_completed(tasks), total=count):
                res = await future
                if res:
                    res['id'] = f"full_attack_{random.randint(100000, 999999)}"
                    await f.write(json.dumps(res, ensure_ascii=False) + "\n")
                    valid_count += 1
        
        print(f"✅ Completed! Generated {valid_count} cases. Saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="生成 full_attack_cases.jsonl 供 build_vector_db 使用")
    parser.add_argument(
        "--count",
        type=int,
        default=500,
        help="生成条数（默认 500，可先 100～200 试跑）",
    )
    args = parser.parse_args()
    generator = AttackDataGenerator()
    asyncio.run(generator.run(count=args.count))
