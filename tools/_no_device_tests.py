"""服务器部署形态（本机无检测设备）的自测。

背景：平台既要能跑在接了测试机的 PC 上，也要能跑在**没有 USB、手机也不在
同一网段**的服务器上。后者必须满足两条：

  1. 默认不跑动态采集（否则每个任务都在环境自检处硬失败）；
  2. 调用方**显式**要求动态采集时报错，而不是悄悄降级成静态。

第 2 条是安全底线：静态-only 的报告里，所有采集类结论都是「跳过未测」，
而提交者以为跑过动态，就会把"没测"读成"没问题"。
"""
from __future__ import annotations

import json
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path


def _json(url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"},
                                 method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"raw": body}


def run(check):
    from webapp import server as S
    from webapp.db import JobDB

    # ---- 纯函数：requested=None 按本机能力给默认 ----
    check("未提交 run_dynamic + 有设备 → 默认动态",
          S.resolve_dynamic(None, True) is True, S.resolve_dynamic(None, True))
    check("未提交 run_dynamic + 无设备 → 默认静态",
          S.resolve_dynamic(None, False) is False, S.resolve_dynamic(None, False))
    check("显式静态 + 无设备 → 静态",
          S.resolve_dynamic(False, False) is False)
    try:
        S.resolve_dynamic(True, False)
        check("显式动态 + 无设备 → 报错", False, "没有抛异常")
    except ValueError as e:
        check("显式动态 + 无设备 → 报错", "未接入检测设备" in str(e), str(e)[:80])

    # ---- 真起一个 HTTP 服务（device=False），走完整提交路径 ----
    tmp = Path(tempfile.mkdtemp(prefix="piiscan_nodev_"))
    S.Handler.db = JobDB(tmp / "jobs.db")
    S.Handler.workdir = tmp
    S.Handler.device_enabled = False
    httpd = S.ThreadingHTTPServer(("127.0.0.1", 0), S.Handler)
    httpd.quiet = True
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        st, body = _json(base + "/api/env")
        check("/api/env 报告无设备",
              st == 200 and body.get("device_enabled") is False, body)

        # 显式要求动态 → 400，且说清怎么办
        st, body = _json(base + "/api/jobs",
                         {"apk_url": "http://example.com/a.apk", "run_dynamic": True})
        check("显式动态提交被拒（400）", st == 400, (st, body))
        check("拒绝原因写明怎么办",
              "run_dynamic=0" in json.dumps(body, ensure_ascii=False),
              json.dumps(body, ensure_ascii=False)[:120])

        # 没提交 run_dynamic → 按本机能力落成静态
        st, body = _json(base + "/api/jobs", {"apk_url": "http://example.com/a.apk"})
        check("默认提交成功（201）", st == 201, (st, body))
        job = S.Handler.db.get(body.get("job_id", ""))
        check("落库 run_dynamic=0", bool(job) and int(job.get("run_dynamic") or 0) == 0,
              job.get("run_dynamic") if job else None)

        # 有设备时同一路径必须仍然是"默认动态"（别把 PC 上的行为改坏）
        S.Handler.device_enabled = True
        # ★ 必须把设备清单钉死成"恰好一台"：这段是离线用例，而
        #   `_resolve_device` 会去读真实 adb —— 开发机上正好插了两台时，
        #   本来测"默认动态"的用例会被"必须选机"拦成 400，失败结果取决于
        #   手边插了几台手机，这种用例比没有还糟。
        # ★ 2026-11-11 起还要**登记**：能不能用由登记簿决定，不再看 adb 有几台。
        #   用完的临时库也要清干净，否则同一进程里后续用例会看到残留设备。
        real_list = S.list_test_devices
        for _s in ("SELFTEST01", "SELFTEST02"):
            S.Handler.db.device_save(
                serial=_s, root_ok=True, frida_ver="16.7.18",
                info={"model": "自检机", "android": "10", "abi": "arm64-v8a"})

        def _dev(s, model, root=True, managed=True):
            return {"serial": s, "state": "device", "model": model, "brand": "",
                    "android": "10", "sdk": "29", "abi": "arm64-v8a",
                    "root": root, "frida": "", "frida_ok": True, "busy": False,
                    "busy_job": "", "note": "", "label": model, "tags": [],
                    "managed": managed, "alias": "", "registered_root_ok": root,
                    "degraded": False, "verified_at": 0, "usable": root and managed}

        S.list_test_devices = lambda *a, **k: [_dev("SELFTEST01", "自检机")]
        try:
            # 现在设备必须显式指定（2026-11-11 用户口径），所以这里带上它；
            # 这条用例要守的是"不勾选时默认仍跑动态"，不是"替人选设备"。
            st, body = _json(base + "/api/jobs", {"apk_url": "http://example.com/b.apk",
                                                  "device": "SELFTEST01"})
            job2 = S.Handler.db.get(body.get("job_id", ""))
            check("有设备时默认仍跑动态",
                  st == 201 and int(job2.get("run_dynamic") or 0) == 1,
                  (st, job2.get("run_dynamic") if job2 else None))
            check("指定的序列号原样写进任务",
                  bool(job2) and job2.get("device") == "SELFTEST01",
                  job2.get("device") if job2 else None)

            # 不指定 → 400（哪怕只有一台）。设备是报告里的证据，不能程序替。
            st, body = _json(base + "/api/jobs", {"apk_url": "http://example.com/b2.apk"})
            txt = json.dumps(body, ensure_ascii=False)
            check("只有一台也不替用户选（400）", st == 400, (st, txt[:120]))
            check("拒绝时告诉用户去选哪台", "SELFTEST01" in txt and "选" in txt, txt[:160])

            # 两台在线却没指定 → 当场 400，且把机器列出来（不是排队后才失败）
            S.list_test_devices = lambda *a, **k: [_dev("SELFTEST01", "自检机A"),
                                                   _dev("SELFTEST02", "自检机B")]
            st, body = _json(base + "/api/jobs", {"apk_url": "http://example.com/c.apk",
                                                  "run_dynamic": True})
            txt = json.dumps(body, ensure_ascii=False)
            check("两台在线不选机 → 400", st == 400, (st, txt[:120]))
            check("拒绝时点名两台机器",
                  "SELFTEST01" in txt and "SELFTEST02" in txt, txt[:160])

            # 指定其中一台 → 放行，且落库带 device
            st, body = _json(base + "/api/jobs", {"apk_url": "http://example.com/d.apk",
                                                  "run_dynamic": True,
                                                  "device": "SELFTEST02"})
            job3 = S.Handler.db.get(body.get("job_id", ""))
            check("指定测试机后放行（201）", st == 201, (st, body))
            check("落库记住指定设备",
                  bool(job3) and job3.get("device") == "SELFTEST02",
                  job3.get("device") if job3 else None)

            # 只接一台也必须人选（2026-11-11 用户口径）：不选 → 400 并点名那台，
            # 而不是替他把那台写进任务。设备是报告里的一条证据，得由人点出来。
            S.list_test_devices = lambda *a, **k: [_dev("SELFTEST01", "自检机")]
            st, body = _json(base + "/api/jobs", {"apk_url": "http://example.com/e.apk",
                                                  "run_dynamic": True})
            txt = json.dumps(body, ensure_ascii=False)
            check("单台不选机 → 400（不再替用户定）", st == 400, (st, txt[:120]))
            check("单台不选时点名那一台", "SELFTEST01" in txt, txt[:160])
            check("单台不选时不落库", not body.get("job_id"), body.get("job_id"))

            st, body = _json(base + "/api/jobs", {"apk_url": "http://example.com/e2.apk",
                                                  "run_dynamic": True,
                                                  "device": "SELFTEST01"})
            job4 = S.Handler.db.get(body.get("job_id", ""))
            check("单台选定后放行（201）", st == 201, (st, body))
            check("选定后落库带那一台",
                  bool(job4) and job4.get("device") == "SELFTEST01",
                  job4.get("device") if job4 else None)

            # ---- 登记簿口径（2026-11-11）----
            # 指定一台**没登记**的序列号 → 400。它可能刚被用户从平台移除，
            # 这时候还拿它跑任务，报告上的设备指纹跟实际执行的对不上。
            st, body = _json(base + "/api/jobs", {"apk_url": "http://example.com/f.apk",
                                                  "run_dynamic": True,
                                                  "device": "GHOST999"})
            txt = json.dumps(body, ensure_ascii=False)
            check("指定未登记设备 → 400", st == 400, (st, txt[:120]))
            check("拒绝时说明去手机管理重新添加",
                  "手机管理" in txt, txt[:160])

            # 一台都没登记 → 动态任务拒绝，且告诉人去哪儿添加
            S.Handler.db.device_delete("SELFTEST01")
            S.Handler.db.device_delete("SELFTEST02")
            # 手机还插着（managed 由登记簿算出来是 False），这正是用户当时的情形
            S.list_test_devices = lambda *a, **k: [_dev("SELFTEST01", "自检机", managed=False)]
            st, body = _json(base + "/api/jobs", {"apk_url": "http://example.com/g.apk",
                                                  "run_dynamic": True})
            txt = json.dumps(body, ensure_ascii=False)
            check("登记簿为空 → 动态任务 400", st == 400, (st, txt[:120]))
            check("提示去「手机管理」添加手机",
                  "添加手机" in txt and "手机管理" in txt, txt[:160])

            # 设备插着但没登记 → 依然拒绝：能不能用由登记簿决定，不看 adb 有几台。
            # 这正是"两台都移除了，状态页还写 2 台可用"那个 bug 的根。
            S.list_test_devices = lambda *a, **k: [_dev("SELFTEST01", "自检机A", managed=False),
                                                   _dev("SELFTEST02", "自检机B", managed=False)]
            st, body = _json(base + "/api/jobs", {"apk_url": "http://example.com/h.apk",
                                                  "run_dynamic": True})
            check("两台都插着但都没登记 → 仍然拒（不看 adb 数量）",
                  st == 400, (st, json.dumps(body, ensure_ascii=False)[:120]))
        finally:
            S.list_test_devices = real_list
    finally:
        httpd.shutdown()
        httpd.server_close()
