"""
使用系统 curl 下载 HTTP(S) 资源，依靠 curl 的 --max-time / --connect-timeout
硬性掐断，避免 Python requests 在部分网络环境下长时间阻塞。
"""
import logging
import shutil
import subprocess
from typing import Optional, Tuple

logger = logging.getLogger("CurlFetch")


def curl_available() -> bool:
    return shutil.which("curl") is not None


def curl_download(
    url: str,
    *,
    output_path: Optional[str] = None,
    max_time_sec: int = 120,
    connect_timeout_sec: int = 30,
) -> Tuple[bool, int, bytes, str]:
    """
    执行 curl（非 shell）。
    :param output_path: 若给定则写入该文件；否则正文从 stdout 读取。
    :return: (成功, curl 退出码, 正文 bytes（仅无 output_path 时有内容）, stderr 文本)
    """
    if not curl_available():
        return False, 127, b"", "curl 未安装或不在 PATH"

    cmd = [
        "curl",
        "-sS",
        "-L",
        "--connect-timeout",
        str(connect_timeout_sec),
        "--max-time",
        str(max_time_sec),
        "-f",
    ]
    if output_path:
        cmd.extend(["-o", output_path, url])
    else:
        cmd.append(url)

    # 略大于 curl 的 max-time，防止极端情况下子进程挂死
    proc_timeout = max_time_sec + connect_timeout_sec + 15
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            timeout=proc_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.error("curl 子进程超时: %s", url[:120])
        return False, -1, b"", "subprocess.TimeoutExpired"

    err = (r.stderr or b"").decode("utf-8", errors="replace").strip()
    body = r.stdout if isinstance(r.stdout, bytes) else b""

    if r.returncode != 0:
        if err:
            logger.warning("curl 失败 rc=%s: %s", r.returncode, err[:500])
        else:
            logger.warning("curl 失败 rc=%s url=%s", r.returncode, url[:120])

    ok = r.returncode == 0
    if output_path and ok:
        body = b""
    return ok, r.returncode, body, err
