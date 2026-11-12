"""把遍历的每一步决策交给外部（人工或更强的模型）。

为什么要有这个东西
------------------
本地模型（qwen3.8-fast）在**自绘界面、密集菜单、长列表**上判断不出"该点哪个"。
而"点哪里才算真把这屏翻完"恰恰决定遍历质量：点错一屏十几次，
预算就没了。想搞清"到底哪一步点错了"，只靠事后看日志是不够的 ——
日志里只有结果，没有"当时屏幕长什么样、有哪些候选、为什么选它"。

这里开一条旁路：把**现场**（界面摘要 + 候选元素 + 截图）落盘，等外部写回决策。
外部可以是人，也可以是比本地模型强得多的模型。检测程序照常跑，
只是"选哪个"这一步换人。

协议
----
全部 JSON、UTF-8，序号自增，一问一答：

    <dir>/req-<seq>.json    检测程序写：现场
    <dir>/req-<seq>.png     检测程序写：同刻截图（可能缺失，看设备）
    <dir>/res-<seq>.json    外部写：决策

req 字段：
    seq       序号（与文件名一致）
    activity  当前 Activity
    fp        界面指纹（同一屏内不变）
    states    已到达过的界面数
    taps      已发生的点击次数
    steps     已走步数
    prev      最近若干步动作（用于判"是不是在绕圈"）
    cands     候选元素：i / uid / label / cls / b(bounds) / c(center) / tapped(已点次数) / note
    blocked   本屏已被判定无效的动作（如 ["swipe:left"]）
    allow_back 现在按返回是否会退出 App
    shot      截图文件名（相对 dir），没有则空串

res 字段：
    seq       必须与 req 的 seq 一致（不一致按未应答处理，防止串号）
    action    tap（配 uid）| back | swipe（配 dir）| done
    uid       action=tap 时必填，取 cands 里的 uid
    dir       action=swipe 时用：up / down / left / right
    why       一句话理由，会进日志与报告（写不出理由的点击通常就是错的那一步）

超时没等到就把 `res` 当不存在，返回 None —— 调用方退回本地 AI，
**绝不把检测卡在这里**。这是硬要求：外部掉线不能变成"任务挂死"。
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional

ENV_DIR = "PIISCAN_ORACLE_DIR"
ENV_TIMEOUT = "PIISCAN_ORACLE_TIMEOUT"

DEFAULT_TIMEOUT = 150.0        # 秒。外部一次决策给足思考时间，但不能无限等
POLL = 0.4


def root() -> str:
    return (os.environ.get(ENV_DIR) or "").strip()


def enabled() -> bool:
    d = root()
    return bool(d) and os.path.isdir(d)


def timeout() -> float:
    try:
        v = float(os.environ.get(ENV_TIMEOUT) or DEFAULT_TIMEOUT)
    except Exception:
        v = DEFAULT_TIMEOUT
    return max(5.0, min(900.0, v))


def _write_json(path: str, obj: Dict[str, Any]) -> None:
    """原子写：先落 .tmp 再 rename。

    外部可能正好在读到一半，半截 JSON 会让人以为"程序崩了"。
    """
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _read_json(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


class Oracle:
    """一问一答的决策通道。实例持有序号，跨步骤连续。"""

    def __init__(self, base: Optional[str] = None) -> None:
        self.base = base or root()
        self.seq = 0
        self.asked = 0
        self.answered = 0
        self.timeouts = 0
        self.rejected = 0
        self.last_why = ""

    # -- 对外 ---------------------------------------------------------
    def ask(self, payload: Dict[str, Any], shot_png: Optional[bytes] = None,
            log: Any = None) -> Optional[Dict[str, Any]]:
        """把一个决策请求交出去并等回答。超时/非法一律返回 None。"""
        if not self.base or not os.path.isdir(self.base):
            return None
        self.seq += 1
        seq = self.seq
        req_path = os.path.join(self.base, "req-%03d.json" % seq)
        res_path = os.path.join(self.base, "res-%03d.json" % seq)
        shot_name = "req-%03d.png" % seq
        if shot_png:
            try:
                with open(os.path.join(self.base, shot_name), "wb") as f:
                    f.write(shot_png)
            except Exception:
                shot_name = ""

        body = dict(payload)
        body["seq"] = seq
        body["shot"] = shot_name
        _write_json(req_path, body)
        # 旧回答先清掉：同一序号曾被回答过（极少见，比如外部手滑重放）不能直接信。
        try:
            if os.path.exists(res_path):
                os.remove(res_path)
        except Exception:
            pass

        self.asked += 1
        t0 = time.time()
        if log:
            log("    [接管] 第 %d 问已发出（%s），等待外部决策…"
                % (seq, body.get("activity") or "界面"))

        ans: Optional[Dict[str, Any]] = None
        while time.time() - t0 < timeout():
            ans = _read_json(res_path)
            if ans is not None:
                break
            time.sleep(POLL)

        if ans is None:
            self.timeouts += 1
            if log:
                log("    [接管] 第 %d 问 %.0fs 内没有回答，退回本地 AI"
                    % (seq, timeout()))
            return None
        if int(ans.get("seq", -1)) != seq:
            # 序号对不上 = 回答是上一问的。照它执行会点错界面，
            # 宁可退回本地 AI 也不能"大概齐"。
            self.rejected += 1
            if log:
                log("    [接管] 第 %d 问的回答序号不符（%s），丢弃"
                    % (seq, ans.get("seq")))
            return None
        self.answered += 1
        self.last_why = str(ans.get("why") or "")
        if log:
            log("    [接管] 第 %d 问 → %s %s（%s）"
                % (seq, ans.get("action"), ans.get("uid") or ans.get("dir") or "",
                   self.last_why[:50]))
        return ans

    def stats(self) -> Dict[str, Any]:
        return {"asked": self.asked, "answered": self.answered,
                "timeouts": self.timeouts, "rejected": self.rejected}


def build_payload(activity: str, fp: str, cands: List[Dict[str, Any]],
                  prev: List[Dict[str, Any]], states: int, taps: int, steps: int,
                  blocked: List[str], allow_back: bool, hint: str = "") -> Dict[str, Any]:
    """把现场整理成 req 的正文。候选的顺序就是程序化探测给出的优先级，别打乱。"""
    return {
        "activity": activity or "",
        "fp": fp or "",
        "states": states,
        "taps": taps,
        "steps": steps,
        "prev": prev[-10:],
        "cands": cands,
        "blocked": sorted(blocked),
        "allow_back": bool(allow_back),
        "hint": hint,
    }
