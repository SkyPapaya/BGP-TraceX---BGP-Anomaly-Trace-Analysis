"""
RIPE RIS MRT Updates 抓取模块
从 https://data.ris.ripe.net/rrcXX/YYYY.MM/updates.YYYYMMDD.HHmm.gz 下载原始 BGP updates，
解析 MRT 并按前缀过滤。
参考: https://ris.ripe.net/docs/mrt/#name-and-location
- Updates 每 5 分钟一个文件
- RRC00/RRC24/RRC25 为 multi-hop，覆盖全球
"""
import os
import re
import tempfile
import ipaddress
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Generator

from .curl_fetch import curl_available, curl_download

logger = logging.getLogger("RISMRTFetcher")

RIS_BASE = "https://data.ris.ripe.net"
# Multi-hop collectors: 覆盖全球，首选
DEFAULT_RRC = "rrc00"
# 单次最多下载文件数，避免长时间窗口请求过多
MAX_FILES = 24  # 约 2 小时


def _to_datetime(s: str) -> Optional[datetime]:
    """ISO8601 或常见格式转 datetime"""
    if not s:
        return None
    s = str(s).strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y%m%d"):
        try:
            return datetime.strptime(s[:19].replace("T", " "), fmt.replace("T", " "))
        except ValueError:
            continue
    return None


def _prefix_matches(announced: str, target: str) -> bool:
    """检查宣告前缀是否与目标前缀匹配（精确或包含）"""
    try:
        a = ipaddress.ip_network(announced, strict=False)
        t = ipaddress.ip_network(target, strict=False)
        return a == t or a.subnet_of(t) or t.subnet_of(a)
    except Exception:
        return False


def _normalize_prefix(p: str, length: int) -> str:
    if "/" in str(p):
        return str(p)
    return f"{p}/{length}"


def _generate_mrt_urls(
    start: datetime, end: datetime, rrc: str = DEFAULT_RRC, max_files: int = MAX_FILES
) -> List[str]:
    """生成时间窗口内所有 5 分钟间隔的 MRT 文件 URL"""
    urls = []
    cur = datetime(start.year, start.month, start.day, start.hour, (start.minute // 5) * 5, 0)
    end_ts = end
    while cur < end_ts and len(urls) < max_files:
        yy = cur.strftime("%Y")
        mm = cur.strftime("%m")
        dd = cur.strftime("%d")
        hh = cur.strftime("%H")
        mi = cur.strftime("%M")
        # 官方文档写 update，实测 updates 可用
        path = f"{rrc}/{yy}.{mm}/updates.{yy}{mm}{dd}.{hh}{mi}.gz"
        urls.append(f"{RIS_BASE}/{path}")
        cur += timedelta(minutes=5)
    return urls


def _parse_as_path(bgp_message: dict) -> List[str]:
    """从 BGP message 提取 AS_PATH"""
    attrs = bgp_message.get("path_attributes", [])
    for a in attrs:
        t = a.get("type")
        if isinstance(t, dict) and 2 in t:  # AS_PATH
            v = a.get("value", [])
            if v and isinstance(v[0], dict):
                return [str(x) for x in v[0].get("value", [])]
    return []


def _parse_mrt_file(filepath: str, target_prefix: str) -> List[Dict]:
    """解析单个 MRT 文件，提取匹配 target_prefix 的 BGP updates"""
    try:
        from mrtparse import Reader
    except ImportError:
        logger.error("请安装 mrtparse: pip install mrtparse")
        return []

    result = []
    target_net = None
    try:
        target_net = ipaddress.ip_network(target_prefix, strict=False)
    except Exception:
        pass

    reader = Reader(filepath)
    for entry in reader:
            try:
                d = entry.data
                if not isinstance(d, dict):
                    continue
                mrt_type = d.get("type")
                if isinstance(mrt_type, dict):
                    mrt_type = list(mrt_type.keys())[0] if mrt_type else 0
                subtype = d.get("subtype")
                if isinstance(subtype, dict):
                    subtype = list(subtype.keys())[0] if subtype else 0
                # BGP4MP MESSAGE (1/4/6/7/8/9/10/11)
                if mrt_type not in (16, 17):
                    continue
                if subtype not in (1, 4, 6, 7, 8, 9, 10, 11):
                    continue

                bmsg = d.get("bgp_message", {})
                nlri = bmsg.get("nlri", [])
                ts_dict = d.get("timestamp", {})
                ts = list(ts_dict.keys())[0] if ts_dict else 0
                ts_str = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%S") if ts else ""

                for n in nlri:
                    pfx = n.get("prefix", "")
                    ln = n.get("length", 32)
                    full_pfx = _normalize_prefix(pfx, ln)
                    if not _prefix_matches(full_pfx, target_prefix):
                        continue
                    path = _parse_as_path(bmsg)
                    path_str = " ".join(path) if path else ""
                    origin = path[-1] if path else ""
                    result.append({
                        "prefix": full_pfx,
                        "as_path": path_str,
                        "detected_origin": origin,
                        "timestamp": ts_str,
                        "raw_timestamp": ts,
                    })
            except Exception as e:
                logger.debug(f"解析 MRT entry 失败: {e}")
                continue

    return result


def fetch_and_parse(
    prefix: str,
    start_time: str,
    end_time: str,
    rrc: str = DEFAULT_RRC,
    max_files: int = MAX_FILES,
) -> tuple[List[Dict], str]:
    """
    从 RIPE RIS 下载 MRT 并解析，按前缀过滤。
    :return: (updates_list, data_source)
      data_source: "ris_mrt" 成功, "empty" 无数据
    """
    st = _to_datetime(start_time)
    et = _to_datetime(end_time)
    if not st or not et:
        logger.warning("无效时间范围")
        return [], "empty"

    urls = _generate_mrt_urls(st, et, rrc, max_files)
    if not urls:
        return [], "empty"

    if not curl_available():
        logger.error("未找到 curl，无法下载 RIS MRT（请安装 curl 并加入 PATH）")
        return [], "empty"

    all_updates = []
    seen = set()

    for url in urls:
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".gz", delete=False) as tmp:
                tmp_path = tmp.name
            ok, _rc, _body, _err = curl_download(
                url,
                output_path=tmp_path,
                max_time_sec=120,
                connect_timeout_sec=30,
            )
            if not ok:
                logger.debug("跳过或失败: %s", url)
                continue
            if os.path.getsize(tmp_path) == 0:
                logger.debug("空文件: %s", url)
                continue
            updates = _parse_mrt_file(tmp_path, prefix)
            for u in updates:
                key = (u.get("prefix"), u.get("as_path"), u.get("raw_timestamp", 0))
                if key not in seen:
                    seen.add(key)
                    all_updates.append(u)
        except Exception as e:
            logger.warning("下载/解析 %s 失败: %s", url, e)
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    return all_updates, "ris_mrt" if all_updates else "empty"


def filter_suspicious_from_ris(
    updates: List[Dict],
    prefix: str,
    expected_origin: str,
    use_valley_free: bool = True,
    known_prefix_origin: Optional[Dict[str, str]] = None,
) -> List[Dict]:
    """
    对 RIS 解析出的 updates 按论文四步法筛选可疑项。
    :return: list of {prefix, as_path, detected_origin, expected_origin, timestamp, reason}
    """
    from .config_loader import get_tier1_asns
    from .update_fetcher import _parse_path, _path_to_str

    result = []
    expected = str(expected_origin).strip()
    if not expected and known_prefix_origin:
        expected = known_prefix_origin.get(prefix, "")
    if not expected:
        return result

    tier1 = get_tier1_asns() if use_valley_free else set()

    for u in updates:
        origin = u.get("detected_origin", "")
        if not origin:
            continue
        as_path = u.get("as_path", "")
        path_list = _parse_path(as_path)
        ts = u.get("timestamp", "")

        # 2. Origin 校验
        if str(origin) != str(expected):
            result.append({
                "prefix": u.get("prefix", prefix),
                "as_path": as_path,
                "detected_origin": origin,
                "expected_origin": expected,
                "timestamp": ts,
                "reason": "ORIGIN_MISMATCH",
            })
            continue

        # 4. Valley-Free
        if use_valley_free and tier1 and len(path_list) >= 3:
            for i in range(1, len(path_list) - 1):
                prev, curr, nxt = path_list[i - 1], path_list[i], path_list[i + 1]
                if prev in tier1 and nxt in tier1 and curr not in tier1:
                    result.append({
                        "prefix": u.get("prefix", prefix),
                        "as_path": as_path,
                        "detected_origin": origin,
                        "expected_origin": expected,
                        "timestamp": ts,
                        "reason": "VALLEY_FREE_VIOLATION",
                        "suspicious_as": curr,
                    })
                    break

    return result
