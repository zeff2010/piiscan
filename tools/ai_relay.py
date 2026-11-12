#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Agent 中继值守工具 —— 给「对话里的 AI」用的命令行接口。

配合 ai.provider = agent 使用。检测工具把每个 AI 请求落盘后会阻塞等待回答，
这个脚本负责把请求读出来给人（或对话里的 AI）看，再把回答写回去。

典型用法（对话里的 AI 每次循环做三步）：
    python tools/ai_relay.py list              # 有没有待处理的请求
    python tools/ai_relay.py show 3            # 看第 3 个请求的提示词，并拿到截图路径
    #（用 Read 工具看那张图，按提示词里的 schema 写出答案 tmp/a3.json）
    python tools/ai_relay.py answer 3 --file tmp/a3.json
    python tools/ai_relay.py wait --timeout 120   # 等下一个请求

命令：
    status                    会话概览（计数、超时、日志尾部）
    list                      列出未回答的请求
    show <id>                 打印某个请求的 system 与完整提示词，给出截图绝对路径
    answer <id> --file X.json 写回回答（X.json 是你要返回的 JSON 或纯文本）
    answer <id> --text "..."  写回回答（直接把一段文本当答案）
    wait [--timeout N]        阻塞等待下一个未回答的请求（有则打印摘要后返回）
    log [-n 20]               看往返日志

选项：
    --base <dir>              中继根目录（默认 out/ai_relay）
    --session <name>          指定会话目录（默认取最新的一个）
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

try:      # Windows 控制台默认可能是 GBK，中文提示词会打不出来
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BASE = ROOT / "out" / "ai_relay"


# ---------------------------------------------------------------- 会话定位

def find_session(base: Path, name: str = "") -> Optional[Path]:
    if name:
        p = base / name
        return p if p.is_dir() else None
    if not base.is_dir():
        return None
    cands = [d for d in base.iterdir() if d.is_dir() and (d / "req").is_dir()]
    if not cands:
        return None
    return max(cands, key=lambda d: d.stat().st_mtime)


def load_session_json(sess: Path) -> Dict[str, Any]:
    p = sess / "session.json"
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def all_ids(sess: Path) -> List[int]:
    ids: List[int] = []
    for p in sorted((sess / "req").glob("*.json")):
        try:
            ids.append(int(p.stem))
        except ValueError:
            continue
    return ids


def is_answered(sess: Path, rid: int) -> bool:
    return (sess / "resp" / ("%04d.json" % rid)).is_file()


def pending(sess: Path) -> List[int]:
    return [i for i in all_ids(sess) if not is_answered(sess, i)]


def load_req(sess: Path, rid: int) -> Dict[str, Any]:
    p = sess / "req" / ("%04d.json" % rid)
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


# ---------------------------------------------------------------- 命令

def cmd_status(sess: Path, args) -> int:
    meta = load_session_json(sess)
    ids = all_ids(sess)
    pend = pending(sess)
    print("会话目录：%s" % sess)
    print("创建时间：%s" % (time.strftime("%Y-%m-%d %H:%M:%S",
                                     time.localtime(meta.get("created", 0)))
                        if meta.get("created") else "未知"))
    print("等一次回答的上限：%s 秒" % meta.get("timeout", "?"))
    print("请求总数：%d    已回答：%d    未回答：%d"
          % (len(ids), len(ids) - len(pend), len(pend)))
    if pend:
        print("未回答的 id：%s" % ", ".join(str(i) for i in pend))
    log = sess / "log.txt"
    if log.is_file():
        lines = log.read_text(encoding="utf-8", errors="replace").strip().splitlines()
        print("最近日志：")
        for l in lines[-6:]:
            print("  " + l)
    return 0


def cmd_list(sess: Path, args) -> int:
    ids = all_ids(sess)
    if not ids:
        print("（本会话还没有任何请求）")
        return 0
    pend = pending(sess)
    for rid in ids:
        req = load_req(sess, rid)
        mark = "✅ 已答" if is_answered(sess, rid) else "⏳ 待答"
        imgs = req.get("images") or []
        head = " ".join(str(req.get("prompt") or "").split())[:80]
        print("%s  #%-4d %-6s 图 %d  提示词 %d 字  %s"
              % (mark, rid, req.get("kind") or "?", len(imgs),
                 len(str(req.get("prompt") or "")), head))
    print("\n未回答：%s" % (", ".join(str(i) for i in pend) if pend else "无"))
    return 0


def cmd_show(sess: Path, args) -> int:
    rid = int(args.id)
    req = load_req(sess, rid)
    if not req:
        print("找不到请求 #%d（目录 %s）" % (rid, sess))
        return 2
    if getattr(args, "brief", False):
        # 精简模式：只给「任务/目标/界面文字/候选列表」——
        # schema 与 system 每次都一样，值守时逐条重读纯属浪费。
        prompt = req.get("prompt") or ""
        cut = prompt.find("只输出如下 JSON：")
        seg = (prompt[:cut] if cut > 0 else prompt).strip()
        print("=== 请求 #%d  %s ===" % (rid, req.get("kind")))
        print(seg)
        for n in (req.get("images") or []):
            p = (sess / "img" / n).resolve()
            size = p.stat().st_size / 1024.0 if p.is_file() else 0
            print("--- 截图：%s  (%.1f KB) ---" % (p, size))
        print("--- (提示词共 %d 字；回答：answer %d --file tmp/ans.json) ---"
              % (len(prompt), rid))
        return 0
    print("=" * 72)
    print("请求 #%d   kind=%s   回答状态=%s"
          % (rid, req.get("kind"), "已答" if is_answered(sess, rid) else "待答"))
    print("=" * 72)
    if req.get("system"):
        print("--- system ---")
        print(req["system"])
    print("--- 提示词 ---")
    print(req.get("prompt") or "")
    imgs = req.get("images") or []
    if imgs:
        print("--- 截图（用 Read 工具打开下面这个绝对路径看图）---")
        for n in imgs:
            p = (sess / "img" / n).resolve()
            size = p.stat().st_size / 1024.0 if p.is_file() else 0
            print("  %s   (%.1f KB)" % (p, size))
    print("--- 回答方式 ---")
    print("  把答案写成 JSON 文件（例：tmp/a%d.json），然后：" % rid)
    print("  python tools/ai_relay.py answer %d --file tmp/a%d.json" % (rid, rid))
    print("=" * 72)
    return 0


def _raw_from_file(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    stripped = text.strip()
    try:
        obj = json.loads(stripped)
    except Exception:
        return text                       # 不是 JSON，就原样当文本
    if isinstance(obj, dict) and len(obj) == 1 and "raw" in obj \
            and isinstance(obj["raw"], str):
        return obj["raw"]                 # 已经包成 {"raw": ...}
    return json.dumps(obj, ensure_ascii=False)    # 再把 JSON 序列化回文本


def cmd_answer(sess: Path, args) -> int:
    rid = int(args.id)
    if not (sess / "req" / ("%04d.json" % rid)).is_file():
        print("找不到请求 #%d" % rid)
        return 2
    if args.file:
        p = Path(args.file)
        if not p.is_file():
            p2 = ROOT / args.file
            if p2.is_file():
                p = p2
            else:
                print("答案文件不存在：%s" % args.file)
                return 2
        try:
            raw = _raw_from_file(p)
        except Exception as e:
            print("读取答案文件失败：%s" % e)
            return 2
    elif args.text is not None:
        raw = args.text
    else:
        print("需要 --file 或 --text")
        return 2

    out = sess / "resp" / ("%04d.json" % rid)
    tmp = out.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"raw": raw, "by": "agent", "ts": time.time()},
                              ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(out)
    print("已写回回答：#%d（%d 字符）→ %s" % (rid, len(raw), out))
    return 0


def cmd_wait(sess: Path, args) -> int:
    deadline = time.time() + max(1, int(args.timeout))
    while time.time() < deadline:
        pend = pending(sess)
        if pend:
            rid = pend[0]
            req = load_req(sess, rid)
            print("有新请求：#%d  kind=%s  图 %d 张  提示词 %d 字"
                  % (rid, req.get("kind"), len(req.get("images") or []),
                     len(str(req.get("prompt") or ""))))
            print("运行 show 看详情：python tools/ai_relay.py show %d" % rid)
            return 0
        time.sleep(0.5)
    print("等待 %ss 内没有新请求。" % args.timeout)
    return 3


def cmd_log(sess: Path, args) -> int:
    p = sess / "log.txt"
    if not p.is_file():
        print("（还没有日志）")
        return 0
    lines = p.read_text(encoding="utf-8", errors="replace").strip().splitlines()
    for l in lines[-max(1, int(args.n)):]:
        print(l)
    return 0


# ---------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description="Agent 中继值守工具")
    ap.add_argument("--base", default=str(DEFAULT_BASE), help="中继根目录")
    ap.add_argument("--session", default="", help="指定会话目录名")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("status")
    sub.add_parser("list")
    sp = sub.add_parser("show")
    sp.add_argument("id")
    sp.add_argument("--brief", action="store_true",
                    help="只打印任务/目标/界面文字/候选列表（跳过重复的 schema 说明）")
    sp = sub.add_parser("answer")
    sp.add_argument("id")
    sp.add_argument("--file", default="")
    sp.add_argument("--text", default=None)
    sp = sub.add_parser("wait"); sp.add_argument("--timeout", type=int, default=120)
    sp = sub.add_parser("log"); sp.add_argument("-n", type=int, default=20)

    args = ap.parse_args()
    if not args.cmd:
        args.cmd = "status"

    base = Path(args.base)
    sess = find_session(base, args.session)
    if sess is None:
        print("找不到中继会话目录。检测工具是否以 ai.provider = agent 启动过？")
        print("查找位置：%s" % base)
        return 2

    fn = {"status": cmd_status, "list": cmd_list, "show": cmd_show,
          "answer": cmd_answer, "wait": cmd_wait, "log": cmd_log}[args.cmd]
    return fn(sess, args)


if __name__ == "__main__":
    sys.exit(main())
