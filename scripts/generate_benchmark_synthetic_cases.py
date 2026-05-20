#!/usr/bin/env python3
"""
Generate synthetic benchmark attack cases for batch diagnosis experiments.

Output format matches data/benchmark_synthetic_cases.json and can be consumed by
scripts/run_feasibility_experiment.py directly.
"""
from __future__ import annotations

import argparse
import json
import random
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.project_paths import BENCHMARK_SYNTHETIC_FILE


UPSTREAMS = ["174", "209", "286", "701", "1239", "1299", "2914", "3257", "3320", "3356", "6453", "6939"]

VICTIMS = [
    {"asn": "15169", "prefix": "8.8.8.0/24", "label": "Google DNS"},
    {"asn": "13335", "prefix": "1.1.1.0/24", "label": "Cloudflare DNS"},
    {"asn": "16509", "prefix": "52.94.11.0/24", "label": "Amazon"},
    {"asn": "19281", "prefix": "9.9.9.0/24", "label": "Quad9"},
    {"asn": "13414", "prefix": "104.244.42.0/24", "label": "Twitter"},
    {"asn": "64496", "prefix": "203.0.113.0/24", "label": "LabNet-A"},
    {"asn": "64497", "prefix": "198.51.100.0/24", "label": "LabNet-B"},
    {"asn": "64498", "prefix": "203.0.114.0/24", "label": "LabNet-C"},
    {"asn": "64499", "prefix": "203.0.115.0/24", "label": "LabNet-D"},
    {"asn": "64520", "prefix": "198.51.120.0/24", "label": "LabNet-E"},
    {"asn": "64530", "prefix": "203.0.121.0/24", "label": "LabNet-F"},
    {"asn": "64540", "prefix": "203.0.122.0/24", "label": "LabNet-G"},
    {"asn": "64550", "prefix": "203.0.123.0/24", "label": "LabNet-H"},
]

BENIGN_VICTIMS = [v for v in VICTIMS if v["asn"].startswith("64")]


def cycle_pick(items: list[str], start: int, count: int) -> list[str]:
    return [items[(start + i) % len(items)] for i in range(count)]


def build_time_window(index: int) -> dict:
    start_dt = datetime(2026, 3, 1, 0, 0, 0) + timedelta(hours=index * 3)
    end_dt = start_dt + timedelta(minutes=30)
    return {
        "start": start_dt.strftime("%Y-%m-%dT%H:%M:%S"),
        "end": end_dt.strftime("%Y-%m-%dT%H:%M:%S"),
    }


def make_hijack_case(index: int, victim: dict, noise_level: str) -> dict:
    attacker = str(65000 + index)
    count_by_noise = {"low": 4, "medium": 4, "high": 5}
    viewpoints = cycle_pick(UPSTREAMS, index, count_by_noise[noise_level])
    updates = []
    dominant_count = {"low": len(viewpoints), "medium": 3, "high": 3}[noise_level]

    for up in viewpoints[:dominant_count]:
        updates.append(
            {
                "prefix": victim["prefix"],
                "as_path": f"{up} {attacker}",
                "detected_origin": attacker,
                "expected_origin": victim["asn"],
            }
        )

    for pos, up in enumerate(viewpoints[dominant_count:]):
        noise_asn = str(65100 + index + pos)
        updates.append(
            {
                "prefix": victim["prefix"],
                "as_path": f"{up} {noise_asn}",
                "detected_origin": noise_asn,
                "expected_origin": victim["asn"],
            }
        )

    return {
        "case_id": f"HIJACK-GEN-{index:03d}",
        "case_name": f"Synthetic Hijack #{index:02d}",
        "event_type": "HIJACK",
        "source_type": "synthetic",
        "noise_level": noise_level,
        "simulation_reason": (
            f"{len(updates)} 条 updates 中主导异常 origin 为 AS{attacker}，"
            f"其宣告前缀 {victim['prefix']} 时与 expected_origin=AS{victim['asn']} 不一致；"
            f"{'多视角均一致指向同一异常 origin。' if noise_level == 'low' else ('含 1 条少数噪声 origin，用于中等噪声测试。' if noise_level == 'medium' else '含 2 条少数派 origin，用于高噪声测试。')}"
        ),
        "expected_attacker": attacker,
        "accept_uncertain": False,
        "context": {
            "time_window": build_time_window(index),
            "updates": updates,
        },
    }


def make_leak_case(index: int, victim: dict, noise_level: str) -> dict:
    leaker = str(66000 + index)
    count_by_noise = {"low": 4, "medium": 4, "high": 5}
    viewpoints = cycle_pick(UPSTREAMS, index + 2, count_by_noise[noise_level])
    updates = []
    dominant_count = {"low": len(viewpoints), "medium": 3, "high": 3}[noise_level]

    for up in viewpoints[:dominant_count]:
        updates.append(
            {
                "prefix": victim["prefix"],
                "as_path": f"{up} {leaker} {victim['asn']}",
                "detected_origin": victim["asn"],
                "expected_origin": victim["asn"],
            }
        )

    for pos, up in enumerate(viewpoints[dominant_count:]):
        alt = str(66100 + index + pos)
        updates.append(
            {
                "prefix": victim["prefix"],
                "as_path": f"{up} {alt} {victim['asn']}",
                "detected_origin": victim["asn"],
                "expected_origin": victim["asn"],
            }
        )

    return {
        "case_id": f"LEAK-GEN-{index:03d}",
        "case_name": f"Synthetic Leak #{index:02d}",
        "event_type": "LEAK",
        "source_type": "synthetic",
        "noise_level": noise_level,
        "simulation_reason": (
            f"origin 始终保持合法 AS{victim['asn']}，但多条路径稳定出现中间 AS{leaker}，"
            f"符合路由泄露的“合法 origin + 异常中转”模式；"
            f"{'多观测点对泄露节点形成一致共识。' if noise_level == 'low' else ('另含 1 条少数中转噪声。' if noise_level == 'medium' else '另含 2 条少数中转噪声，用于高噪声测试。')}"
        ),
        "expected_attacker": leaker,
        "accept_uncertain": False,
        "context": {
            "time_window": build_time_window(100 + index),
            "updates": updates,
        },
    }


def make_forgery_case(index: int, victim: dict, noise_level: str) -> dict:
    attacker = str(67000 + index)
    anchor = cycle_pick(UPSTREAMS, index + 4, 1)[0]
    count_by_noise = {"low": 4, "medium": 4, "high": 5}
    viewpoints = cycle_pick(UPSTREAMS, index + 5, count_by_noise[noise_level])
    pattern = index % 3
    updates = []
    dominant_count = {"low": len(viewpoints), "medium": 3, "high": 3}[noise_level]

    for pos, up in enumerate(viewpoints[:dominant_count]):
        if pattern == 0:
            as_path = f"{up} {attacker} {victim['asn']}"
        elif pattern == 1:
            as_path = f"{up} {attacker} {anchor} {victim['asn']}"
        else:
            as_path = f"{up} {anchor} {attacker} {victim['asn']}"
        updates.append(
            {
                "prefix": victim["prefix"],
                "as_path": as_path,
                "detected_origin": victim["asn"],
                "expected_origin": victim["asn"],
            }
        )

    for pos, up in enumerate(viewpoints[dominant_count:]):
        alt = str(67100 + index + pos)
        if pattern == 0:
            as_path = f"{up} {alt} {victim['asn']}"
        elif pattern == 1:
            as_path = f"{up} {alt} {anchor} {victim['asn']}"
        else:
            as_path = f"{up} {anchor} {alt} {victim['asn']}"
        updates.append(
            {
                "prefix": victim["prefix"],
                "as_path": as_path,
                "detected_origin": victim["asn"],
                "expected_origin": victim["asn"],
            }
        )

    return {
        "case_id": f"FORGERY-GEN-{index:03d}",
        "case_name": f"Synthetic Forgery #{index:02d}",
        "event_type": "FORGERY",
        "source_type": "synthetic",
        "noise_level": noise_level,
        "simulation_reason": (
            f"origin 维持合法 AS{victim['asn']}，但多视角路径稳定插入 AS{attacker}，"
            f"形成重复的异常邻接/伪造跳点；该模式更符合路径伪造而非 origin hijack。"
            f"{' 全部观测一致。' if noise_level == 'low' else ('另含 1 条少数派伪造路径。' if noise_level == 'medium' else '另含 2 条少数派伪造路径，用于高噪声测试。')}"
        ),
        "expected_attacker": attacker,
        "accept_uncertain": False,
        "context": {
            "time_window": build_time_window(200 + index),
            "updates": updates,
        },
    }


def make_benign_case(index: int, victim: dict, noise_level: str) -> dict:
    count_by_noise = {"low": 3, "medium": 4, "high": 5}
    viewpoints = cycle_pick(UPSTREAMS, index + 7, count_by_noise[noise_level])
    updates = []

    # 为了让 FPR 更有区分度，良性样本不再全部是“完美直连 + 完整先验”。
    # 对部分控制样本，移除 expected_origin，并引入 benign MOAS / 长路径传播，
    # 让弱方法在不完整观测下出现自然误报，而完整系统可退回 BENIGN/UNCERTAIN。
    variant = index % 3
    use_observation_only = noise_level != "low" or variant != 0

    moas_case = noise_level in ("medium", "high") and ((index + (1 if noise_level == "high" else 0)) % 2 == 0)
    if use_observation_only and moas_case:
        alt_origin = str(64600 + index)
        dominant_count = 3 if noise_level == "medium" else 3
        for pos, up in enumerate(viewpoints):
            origin = victim["asn"] if pos < dominant_count else alt_origin
            updates.append(
                {
                    "prefix": victim["prefix"],
                    "as_path": f"{up} {origin}",
                    "detected_origin": origin,
                }
            )
        reason_tail = (
            "良性 MOAS 控制样本：观测中出现少数派第二起源，但不提供 expected_origin，"
            "用于测试弱方法在不完整先验下的误报。"
        )
    else:
        for pos, up in enumerate(viewpoints):
            if use_observation_only and pos > 0:
                relay = str(64560 + index + pos)
                update = {
                    "prefix": victim["prefix"],
                    "as_path": f"{up} {relay} {victim['asn']}",
                    "detected_origin": victim["asn"],
                }
            else:
                update = {
                    "prefix": victim["prefix"],
                    "as_path": f"{up} {victim['asn']}",
                    "detected_origin": victim["asn"],
                }
            if not use_observation_only:
                update["expected_origin"] = victim["asn"]
            updates.append(update)
        reason_tail = (
            "观测缺少 expected_origin，且混入合法长路径传播。"
            if use_observation_only
            else "保留 expected_origin 的直连良性传播。"
        )

    return {
        "case_id": f"BENIGN-GEN-{index:03d}",
        "case_name": f"Synthetic Benign #{index:02d}",
        "event_type": "BENIGN",
        "source_type": "synthetic",
        "noise_level": noise_level,
        "simulation_reason": (
            f"良性控制样本基于前缀 {victim['prefix']} / AS{victim['asn']} 构造，"
            f"{reason_tail}"
            f"{' 低噪声：以一致直连为主。' if noise_level == 'low' else (' 中噪声：引入少量观测歧义。' if noise_level == 'medium' else ' 高噪声：进一步增加路径或起源层面的观测歧义。')}"
        ),
        "expected_attacker": "None",
        "accept_uncertain": False,
        "context": {
            "time_window": build_time_window(300 + index),
            "updates": updates,
        },
    }


def generate_cases(count: int, seed: int, benign_count: int) -> list[dict]:
    if count <= 0:
        return []
    benign_count = max(0, min(benign_count, count))
    attack_count = count - benign_count

    random.seed(seed)
    victim_pool = VICTIMS[:]
    random.shuffle(victim_pool)

    attack_type_order = ["HIJACK", "LEAK", "FORGERY"]
    counters = {"HIJACK": 0, "LEAK": 0, "FORGERY": 0, "BENIGN": 0}
    cases = []
    noise_cycle = ["low", "medium", "high"]

    for idx in range(attack_count):
        event_type = attack_type_order[idx % len(attack_type_order)]
        counters[event_type] += 1
        victim = victim_pool[idx % len(victim_pool)]
        noise_level = noise_cycle[(idx // len(attack_type_order)) % len(noise_cycle)]

        if event_type == "HIJACK":
            case = make_hijack_case(counters[event_type], victim, noise_level)
        elif event_type == "LEAK":
            case = make_leak_case(counters[event_type], victim, noise_level)
        else:
            case = make_forgery_case(counters[event_type], victim, noise_level)
        cases.append(case)

    for idx in range(benign_count):
        counters["BENIGN"] += 1
        victim = BENIGN_VICTIMS[idx % len(BENIGN_VICTIMS)]
        noise_level = noise_cycle[idx % len(noise_cycle)]
        cases.append(make_benign_case(counters["BENIGN"], victim, noise_level))

    random.shuffle(cases)

    return cases


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic benchmark attack cases")
    parser.add_argument("--count", type=int, default=50, help="Number of synthetic attack cases")
    parser.add_argument("--benign-count", type=int, default=15, help="Number of benign cases included in the synthetic benchmark")
    parser.add_argument("--seed", type=int, default=20260427, help="Random seed")
    parser.add_argument(
        "--output",
        default=str(BENCHMARK_SYNTHETIC_FILE),
        help="Output JSON path",
    )
    args = parser.parse_args()

    cases = generate_cases(args.count, args.seed, args.benign_count)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(cases, f, indent=2, ensure_ascii=False)

    counts = {"HIJACK": 0, "LEAK": 0, "FORGERY": 0, "BENIGN": 0}
    for case in cases:
        counts[case["event_type"]] += 1

    print(f"Generated {len(cases)} synthetic attack cases -> {args.output}")
    print(
        "Breakdown: "
        f"HIJACK={counts['HIJACK']}, "
        f"LEAK={counts['LEAK']}, "
        f"FORGERY={counts['FORGERY']}, "
        f"BENIGN={counts['BENIGN']}"
    )


if __name__ == "__main__":
    main()
