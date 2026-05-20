"""
BGP Updates 抓取与观测过滤模块
从 RIPEstat BGPlay API 下载目标前缀在指定时间窗口内的原始 BGP updates，
并按论文四步法筛选可疑 updates。
参考: https://stat.ripe.net/docs/02.data-api/bgplay.html
"""
import json
import logging
from typing import List, Dict, Optional
from urllib.parse import urlencode

from .config_loader import get_known_prefix_origin, get_tier1_asns
from .curl_fetch import curl_available, curl_download

logger = logging.getLogger("UpdateFetcher")

RIPESTAT_BGPLAY = "https://stat.ripe.net/data/bgplay/data.json"
SOURCE_APP = "bgp-anomaly-analysis-tool"


def _ipv4_prefix_mask_len(prefix: str) -> Optional[int]:
    """返回 IPv4 CIDR 掩码长度；非 IPv4 CIDR 返回 None。"""
    p = (prefix or "").strip()
    if not p or "/" not in p or ":" in p:
        return None
    try:
        return int(p.split("/", 1)[1].strip())
    except ValueError:
        return None


def _prefix_too_broad_for_ris_mrt(prefix: str, min_len: int = 24) -> bool:
    """
    掩码长度 < min_len 的前缀（如 /8、/18）在 RIS MRT 全文件解析中命中面大，
    易长时间阻塞、占大量内存或异常退出；auto 模式下应改用 RIPEstat。
    """
    ln = _ipv4_prefix_mask_len(prefix)
    return ln is not None and ln < min_len


def fetch_bgp_updates(prefix: str, start_time: str, end_time: str) -> Dict:
    """
    从 RIPEstat BGPlay 获取指定前缀在时间窗口内的 BGP updates。
    :param prefix: 目标前缀，如 8.8.8.0/24
    :param start_time: 开始时间 ISO8601，如 2024-01-15T00:00:00
    :param end_time: 结束时间 ISO8601
    :return: BGPlay API 返回的 data 部分，含 initial_state, events, nodes 等
    """
    query = urlencode(
        {
            "resource": prefix,
            "starttime": start_time,
            "endtime": end_time,
            "sourceapp": SOURCE_APP,
        }
    )
    url = f"{RIPESTAT_BGPLAY}?{query}"
    if not curl_available():
        logger.error("未找到 curl，无法请求 BGPlay（请安装 curl 并加入 PATH）")
        return {}
    ok, _rc, body, _err = curl_download(
        url, max_time_sec=90, connect_timeout_sec=20
    )
    if not ok or not body:
        return {}
    try:
        data = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as e:
        logger.error("BGPlay 响应非 JSON: %s", e)
        return {}
    if data.get("status") != "ok":
        logger.warning("BGPlay 返回非 ok: %s", data.get("message"))
        return {}
    return data.get("data", {}) or {}


def _parse_path(path) -> List[str]:
    """解析 AS path，返回 AS 号列表"""
    if isinstance(path, list):
        return [str(p).strip() for p in path if str(p).strip().replace(",", "").isdigit()]
    if isinstance(path, str):
        return [p.strip() for p in path.replace(",", " ").split() if p.strip().isdigit()]
    return []


def _extract_origin(path) -> Optional[str]:
    """从 path 提取 Origin（最右侧 AS）"""
    parsed = _parse_path(path)
    return parsed[-1] if parsed else None


def _path_to_str(path) -> str:
    """将 path 转为空格分隔字符串"""
    parsed = _parse_path(path)
    return " ".join(parsed) if parsed else ""


def filter_suspicious_updates(
    bgplay_data: Dict,
    prefix: str,
    expected_origin: str,
    use_valley_free: bool = True,
    known_prefix_origin: Optional[Dict[str, str]] = None,
) -> List[Dict]:
    """
    按论文四步法筛选可疑 updates。

    1. 前缀过滤：BGPlay 已按 prefix 查询，天然满足
    2. Origin 校验：Detected Origin != Expected Owner -> 异常
    3. 时间相关：已限定时间窗口
    4. Valley-Free（可选）：路径违反 Tier1->非Tier1->Tier1 视为泄露

    :return: list of {prefix, as_path, detected_origin, expected_origin, timestamp, reason}
    """
    result = []
    expected = str(expected_origin).strip()

    # 确定 expected_origin：优先参数，其次知识库
    if not expected and known_prefix_origin:
        expected = known_prefix_origin.get(prefix, "")

    if not expected:
        logger.warning(f"无法确定 prefix {prefix} 的合法 Owner，跳过筛选")
        return result

    tier1 = get_tier1_asns() if use_valley_free else set()
    events = bgplay_data.get("events", [])
    initial_state = bgplay_data.get("initial_state", [])

    def check_update(entry, ts=None):
        # BGPlay: initial_state 用 path, events 用 attrs.path
        attrs = entry.get("attrs", entry)
        path = attrs.get("path", entry.get("path", entry.get("as_path", [])))
        origin = _extract_origin(path)
        if not origin:
            return
        as_path_str = _path_to_str(path)
        target = attrs.get("target_prefix", entry.get("target_prefix", entry.get("target", prefix)))
        pfx = target if "/" in str(target) else prefix

        # 2. Origin 校验：MOAS 冲突
        if str(origin) != str(expected):
            result.append({
                "prefix": pfx,
                "as_path": as_path_str,
                "detected_origin": origin,
                "expected_origin": expected,
                "timestamp": ts,
                "reason": "ORIGIN_MISMATCH",
            })
            return


        #Tier1 集合来自 config/knowledge_base.json 的 ，已知的骨干网络as号# 4. Valley-Free：路径中间违反商业关系
        if use_valley_free and tier1 and len(_parse_path(path)) >= 3:
            for i in range(1, len(_parse_path(path)) - 1):
                prev = _parse_path(path)[i - 1]
                curr = _parse_path(path)[i]
                nxt = _parse_path(path)[i + 1]
                if prev in tier1 and nxt in tier1 and curr not in tier1:
                    result.append({
                        "prefix": pfx,
                        "as_path": as_path_str,
                        "detected_origin": origin,
                        "expected_origin": expected,
                        "timestamp": ts,
                        "reason": "VALLEY_FREE_VIOLATION",
                        "suspicious_as": curr,
                    })
                    return

    # 处理 initial_state
    for entry in initial_state:
        if isinstance(entry, dict):
            check_update(entry, bgplay_data.get("query_starttime"))

    # 处理 events（BGPlay 格式：{ timestamp, type, attrs: { path, target_prefix } }）
    def process_entry(e, ts=None):
        if not isinstance(e, dict):
            return
        attrs = e.get("attrs", e)
        path = attrs.get("path", e.get("path", e.get("as_path", e.get("path_attr", []))))
        if path:
            check_update(e, ts)
        else:
            for sub in e.get("updates", e.get("entries", [])):
                process_entry(sub, ts or e.get("timestamp"))

    for ev in events:
        if isinstance(ev, dict):
            ts = ev.get("timestamp", ev.get("time"))
            if ev.get("path") or ev.get("as_path"):
                process_entry(ev, ts)
            else:
                for e in ev.get("updates", ev.get("entries", [ev])):
                    process_entry(e, ts)
        elif isinstance(ev, list):
            for e in ev:
                process_entry(e)

    return result


def fetch_and_filter(
    prefix: str,
    expected_origin: str,
    start_time: str,
    end_time: str,
    use_valley_free: bool = True,
    source: str = "ris_mrt",
) -> tuple[List[Dict], Dict, str]:
    """
    一站式：下载真实 BGP updates + 按论文四步法筛选。
    :param source: "ris_mrt" | "ripestat" | "auto"
      - ris_mrt: RIPE RIS MRT 文件 (https://data.ris.ripe.net/...)，支持历史数据
      - ripestat: RIPEstat BGPlay API，仅 2024-01+
      - auto: 优先 RIS MRT，失败则 RIPEstat
    :return: (suspicious_updates, raw_data, data_source)
    """
    known = get_known_prefix_origin()

    def _try_ris():
        try:
            from .ris_mrt_fetcher import fetch_and_parse, filter_suspicious_from_ris
            raw_updates, ds = fetch_and_parse(prefix, start_time, end_time)
            if ds != "ris_mrt" or not raw_updates:
                return [], {}, ds
            suspicious = filter_suspicious_from_ris(
                raw_updates, prefix, expected_origin,
                use_valley_free=use_valley_free,
                known_prefix_origin=known,
            )
            raw_data = {"source": "ris_mrt", "updates": raw_updates}
            return suspicious, raw_data, "ris_mrt"
        except Exception as e:
            logger.warning(f"RIS MRT 抓取失败: {e}")
            return None, None, None

    def _try_ripestat():
        data = fetch_bgp_updates(prefix, start_time, end_time)
        if not data:
            return [], {}, "empty"
        suspicious = filter_suspicious_updates(
            data, prefix, expected_origin,
            use_valley_free=use_valley_free,
            known_prefix_origin=known,
        )
        return suspicious, data, "ripestat"

    if source == "ris_mrt":
        susp, raw, ds = _try_ris()
        if susp is not None:
            return susp, raw or {}, ds
        return [], {}, "empty"

    if source == "ripestat":
        return _try_ripestat()

    # auto: 优先 RIS，失败则 RIPEstat；过宽 IPv4 前缀跳过 RIS（见 _prefix_too_broad_for_ris_mrt）
    if _prefix_too_broad_for_ris_mrt(prefix):
        logger.info("前缀较宽，auto 跳过 RIS MRT，使用 RIPEstat: %s", prefix)
        return _try_ripestat()
    susp, raw, ds = _try_ris()
    if susp is not None and ds == "ris_mrt":
        return susp, raw or {}, ds
    return _try_ripestat()
