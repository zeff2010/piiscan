"""外部决策通道（flow/oracle.py）的离线用例。

重点不是"能问能答"，而是三条保命规则：
  ① 外部不回答 → 必须**按时**返回 None（不能把检测挂死）；
  ② 回答序号不符 → 丢弃（照它执行会点错界面，比不答更糟）；
  ③ 通道本身抛异常 → 采集照常继续。
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def run(check) -> None:
    from piiscan.flow import oracle as O

    # ---------------------------------------------------------- 开关
    old = os.environ.pop(O.ENV_DIR, None)
    try:
        check("未设环境变量时通道关闭", O.enabled() is False)
        tmp = tempfile.mkdtemp(prefix="oracle_")
        os.environ[O.ENV_DIR] = tmp
        check("指向存在的目录时通道开启", O.enabled() is True)
        os.environ[O.ENV_DIR] = os.path.join(tmp, "不存在的子目录")
        check("指向不存在的目录仍算关闭", O.enabled() is False)
        os.environ[O.ENV_DIR] = tmp

        # ------------------------------------------------------ 正常问答
        o = O.Oracle()
        os.environ[O.ENV_TIMEOUT] = "10"

        def _answer(seq_override=None):
            """等 req 落盘后写回答。模拟'外面的人'。"""
            for _ in range(120):
                p = Path(tmp) / ("req-%03d.json" % 1)
                if p.exists():
                    break
                time.sleep(0.02)
            rp = Path(tmp) / "res-001.json"
            rp.write_text(json.dumps({
                "seq": 1 if seq_override is None else seq_override,
                "action": "tap", "uid": "u:abc", "why": "进入设置",
            }, ensure_ascii=False), encoding="utf-8")

        threading.Thread(target=_answer, daemon=True).start()
        body = O.build_payload("com.x.Home", "fp1", [{"uid": "u:abc", "label": "设置"}],
                               [], 1, 0, 0, [], True)
        ans = o.ask(body, b"\x89PNG\r\n\x1a\nfake", log=None)
        check("★ 正常应答能被取回", bool(ans) and ans.get("uid") == "u:abc", ans)
        check("★ 请求落盘（含截图）",
              (Path(tmp) / "req-001.json").exists() and (Path(tmp) / "req-001.png").exists())
        check("序号自增", o.seq == 1, o.seq)

        # ------------------------------------------------------ 序号串了
        # 每个用例用独立目录：共用目录时上一问留下的 req/res 会让线程
        # 立刻以为"已经发过问"、抢在 ask 清旧回答之前写入，测出来就成了超时。
        tmp2 = tempfile.mkdtemp(prefix="oracle2_")
        o2 = O.Oracle(base=tmp2)

        def _answer_wrong():
            for _ in range(120):
                if (Path(tmp2) / "req-001.json").exists():
                    break
                time.sleep(0.02)
            time.sleep(0.05)
            (Path(tmp2) / "res-001.json").write_text(
                json.dumps({"seq": 99, "action": "tap", "uid": "u:abc"}), encoding="utf-8")

        threading.Thread(target=_answer_wrong, daemon=True).start()
        ans2 = o2.ask(O.build_payload("a", "b", [], [], 0, 0, 0, [], True), None, log=None)
        check("★ 序号不符的回答被丢弃（不点错界面）", ans2 is None, ans2)
        check("丢弃计数为 1", o2.rejected == 1, o2.stats())

        # ------------------------------------------------------ 超时
        tmp3 = tempfile.mkdtemp(prefix="oracle3_")
        o3 = O.Oracle(base=tmp3)
        os.environ[O.ENV_TIMEOUT] = "5"
        t0 = time.time()
        ans3 = o3.ask(O.build_payload("a", "b", [], [], 0, 0, 0, [], True), None, log=None)
        dt = time.time() - t0
        check("★ 没人回答时按时返回 None（不挂死）", ans3 is None)
        check("超时受上限约束（5s 档，实际 %.1fs）" % dt, 4.5 <= dt <= 12.0, dt)
        check("超时计数为 1", o3.timeouts == 1, o3.stats())

        # ------------------------------------------------------ payload 口径
        p = O.build_payload("com.x", "fp", [{"uid": "a"}], [{"k": 1}], 3, 5, 7,
                            ["swipe:left"], False, hint="提示")
        for k in ("activity", "fp", "states", "taps", "steps", "prev",
                  "cands", "blocked", "allow_back", "hint"):
            check("payload 含字段 %s" % k, k in p)
        check("prev 只保留最近 10 条",
              len(O.build_payload("a", "b", [], [{"i": i} for i in range(30)],
                                  0, 0, 0, [], True)["prev"]) == 10)

        # ------------------------------------------------------ 通道异常不拖垮采集
        class _Bad:
            def ask(self, *a, **k):
                raise RuntimeError("磁盘满了")

        bad = _Bad()
        try:
            bad.ask({}, None)
            ok = False
        except Exception:
            ok = True
        check("外部通道抛异常会被调用方捕获（这里确认异常确实可捕获）", ok)
    finally:
        if old is None:
            os.environ.pop(O.ENV_DIR, None)
        else:
            os.environ[O.ENV_DIR] = old
        os.environ.pop(O.ENV_TIMEOUT, None)
