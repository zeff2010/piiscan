#!/usr/bin/env python3
"""平台启动入口。

用法：
  python run_platform.py                    # 默认 http://127.0.0.1:8760
  python run_platform.py --port 9000 --host 0.0.0.0
  python run_platform.py --workdir D:/piiscan_out
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from webapp.server import serve        # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="App 个人信息保护合规检测平台")
    ap.add_argument("--host", default="127.0.0.1", help="监听地址（0.0.0.0 表示允许局域网访问）")
    ap.add_argument("--port", type=int, default=8760, help="监听端口")
    ap.add_argument("--workdir", default="out/platform",
                    help="任务工作目录（APK 副本、报告、数据库都放在这里）")
    ap.add_argument("--db", default="", help="数据库路径，默认 <workdir>/jobs.db")
    ap.add_argument("--no-device", action="store_true",
                    help="本机没有接入检测设备（服务器部署）：默认不跑动态采集，"
                         "且拒绝要求动态采集的请求")
    ap.add_argument("--quiet", action="store_true", help="不打印每个 HTTP 请求")
    args = ap.parse_args()

    wd = Path(args.workdir)
    if not wd.is_absolute():
        wd = Path(__file__).resolve().parent / wd
    return serve(host=args.host, port=args.port, workdir=wd,
                 db_path=args.db or None, quiet=args.quiet,
                 device=not args.no_device)


if __name__ == "__main__":
    raise SystemExit(main())
