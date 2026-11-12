"""测试机 → 手机号的联动（离线，不碰真机）。

守的是两条：
1. 选哪台机，默认号就是那台的号 —— 每台机插自己的卡，用错号登录只会"超时"，
   而超时不会告诉你是号码错，很容易被当成 App 的问题写进报告。
2. **显式传空串仍然是"不登录"**，不能被设备默认号覆盖 —— 那会让用户关不掉。

第 2 条是回归项：给"缺字段"加默认值时，最容易顺手把"空串"也一起兜住。
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


def _fake_dev(serial, model="M2004J19C", state="device", phone="13900000000"):
    return {
        "serial": serial, "state": state, "model": model, "android": "10",
        "sdk": "29", "abi": "arm64-v8a", "root": True, "frida": "16.7.18",
        "frida_ok": True, "busy": False, "busy_job": "", "tags": [], "note": "",
        "label": model, "phone": phone,
        # 2026-11-11：能不能用由登记簿决定，假设备也得说清自己是登记的
        "managed": True, "alias": "", "registered_root_ok": True,
        "degraded": False, "verified_at": 0, "usable": True,
    }


def run(check):
    import webapp.server as S

    # ---------- 1. 配置映射（历史兜底路径）----------
    # 自己造一份临时配置显式传进去：发布出去的干净树里没有 config.yaml，
    # 用例不能依赖开发机上恰好有一份带真实号码的配置。
    import tempfile as _tf
    _cfg = Path(_tf.mkdtemp(prefix="piiscan_cfg_")) / "config.yaml"
    _cfg.write_text("device:\n  phones:\n"
                    "    \"f6e5d4c3b2a1\": \"13900000000\"\n"
                    "    \"a1b2c3d4\": \"13800000000\"\n"
                    "scan:\n  login_phone: \"13800000000\"\n", encoding="utf-8")
    phones = S._device_phones(str(_cfg))
    check("config 里两台机都登记了号码",
          phones.get("f6e5d4c3b2a1") == "13900000000"
          and phones.get("a1b2c3d4") == "13800000000", phones)

    check("按 Android 10 那台取号",
          S._default_login_phone_for("f6e5d4c3b2a1", str(_cfg)) == "13900000000",
          S._default_login_phone_for("f6e5d4c3b2a1", str(_cfg)))
    check("按 Redmi K30 取号",
          S._default_login_phone_for("a1b2c3d4", str(_cfg)) == "13800000000",
          S._default_login_phone_for("a1b2c3d4", str(_cfg)))
    # 没登记的机器不能瞎猜一个号 —— 回落到全局默认，由前端提示"请手填"
    check("未登记的机器回落全局默认号",
          S._default_login_phone_for("deadbeef00", str(_cfg)) == S._default_login_phone(str(_cfg)),
          S._default_login_phone_for("deadbeef00", str(_cfg)))
    check("不指定设备时用全局默认号",
          S._default_login_phone_for("", str(_cfg)) == S._default_login_phone(str(_cfg)),
          S._default_login_phone_for("", str(_cfg)))

    # ---------- 2. /api/devices 带出号码 ----------
    from webapp.db import JobDB
    tmp = Path(tempfile.mkdtemp(prefix="piiscan_phone_"))
    db = JobDB(tmp / "jobs.db")
    S.Handler.db = db
    S.Handler.workdir = tmp
    S.Handler.device_enabled = False
    # 2026-11-11 起"这台能不能用"由登记簿决定：先把下面要用的两台登记进去，
    # 否则指定序列号会被判"没在平台登记"。
    # 号码也**登记在簿子里**（主口径）—— 这样用例不依赖 config.yaml 是否存在。
    for _s, _ph in (("f6e5d4c3b2a1", "13900000000"), ("a1b2c3d4", "13800000000")):
        db.device_save(serial=_s, root_ok=True, frida_ver="16.7.18", phone=_ph)
    real_list = S.list_test_devices

    httpd = S.ThreadingHTTPServer(("127.0.0.1", 0), S.Handler)
    httpd.quiet = True
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        # 真实 list_test_devices 会把 phone 填进来；这里用假设备是因为开发机
        # 插不插手机不该决定用例过不过（上一轮已经吃过这个亏）。
        _, body = _json(base + "/api/devices")
        real = {d["serial"]: d.get("phone") for d in body["devices"]}
        # 只有当开发机真接着这两台时才断言，否则跳过（离线机器上没设备）
        if real:
            check("/api/devices 每台都带 phone 字段",
                  all("phone" in d for d in body["devices"]),
                  [d.get("serial") for d in body["devices"]])
        else:
            check("/api/devices 无设备时返回空清单（跳过 phone 断言）", body["devices"] == [], real)

        # ---------- 3. 建任务时按设备取默认号 ----------
        S.list_test_devices = lambda *a, **k: [_fake_dev("f6e5d4c3b2a1"), _fake_dev("a1b2c3d4")]
        S.Handler.device_enabled = True

        st, body = _json(base + "/api/jobs", {
            "apk_url": "http://example.com/a.apk", "device": "f6e5d4c3b2a1"})
        jid = body.get("job_id", "")
        job = db.get(jid) if jid else None
        check("不带 login_phone + 指定 Android 10 → 用该机号码",
              st == 201 and job and job.get("login_phone") == "13900000000",
              (st, job.get("login_phone") if job else body))

        st, body = _json(base + "/api/jobs", {
            "apk_url": "http://example.com/b.apk", "device": "a1b2c3d4"})
        jid = body.get("job_id", "")
        job = db.get(jid) if jid else None
        check("不带 login_phone + 指定 Redmi K30 → 用该机号码",
              st == 201 and job and job.get("login_phone") == "13800000000",
              (st, job.get("login_phone") if job else body))

        # ★ 显式空串 = 用户主动关，绝不能被设备默认号"兜"回来
        st, body = _json(base + "/api/jobs", {
            "apk_url": "http://example.com/c.apk", "device": "f6e5d4c3b2a1",
            "login_phone": ""})
        jid = body.get("job_id", "")
        job = db.get(jid) if jid else None
        check("显式传空串 → 不登录（设备默认号不覆盖）",
              st == 201 and job and job.get("login_phone") == "",
              (st, job.get("login_phone") if job else body))

        # 显式传别的号 → 用传的（用户可能故意用另一张卡）
        st, body = _json(base + "/api/jobs", {
            "apk_url": "http://example.com/d.apk", "device": "f6e5d4c3b2a1",
            "login_phone": "13800000000"})
        jid = body.get("job_id", "")
        job = db.get(jid) if jid else None
        check("显式传号码 → 用传的，不换成设备号",
              st == 201 and job and job.get("login_phone") == "13800000000",
              (st, job.get("login_phone") if job else body))

        # 只接着一台也不替用户选（2026-11-11 口径）：不指定 → 400；
        # 指定之后，默认号必须按**那台机的卡**取 —— 若还按"没选机"取全局默认号，
        # 就是拿另一张卡的号去登录这台机上的 App，验证码永远收不到。
        S.list_test_devices = lambda *a, **k: [_fake_dev("f6e5d4c3b2a1")]
        st, body = _json(base + "/api/jobs", {"apk_url": "http://example.com/e.apk"})
        check("单台在线 + 不指定设备 → 400（必须人选）", st == 400, (st, str(body)[:120]))

        st, body = _json(base + "/api/jobs", {"apk_url": "http://example.com/e2.apk",
                                              "device": "f6e5d4c3b2a1"})
        jid = body.get("job_id", "")
        job = db.get(jid) if jid else None
        check("指定设备 → 用那台机自己的号（不是全局默认号）",
              st == 201 and job and job.get("login_phone") == "13900000000",
              (st, job.get("login_phone") if job else body))
    finally:
        S.list_test_devices = real_list
        httpd.shutdown()
