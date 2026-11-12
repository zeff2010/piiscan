"""测试机管理（增删手机）用例，2026-11-11。

用户要求："目前真实手机是直接相对固化写在平台上的……增加手机的时候需要自动配置
手机的能力，点击增加手机后，能自动识别插在电脑上的手机，让用户选择需要增加的
是哪一台，然后能自动检查是否可调试和 root 状态，然后自动帮手机部署 frida-server
和自检，并且在增加的过程中提供必要的提示和引导。"

这套用例守的是**几件说错就会误导人的事**：

1. **登记簿只存"接入那一刻的事实"**。
   `root_ok` / `verified_at` 是历史记录，不能当"现在是否已 root"。现状由实时探测回答
   （`devices.usable` 三条件：接入时达标 + 此刻插着 + su 还在）。
2. **接入是显式动作，允许执行 su**；而前端每 10 秒一次的轮询探测**绝不允许**
   （那是"另一台手机被点亮"的根因）。两条口径必须分开守。
3. **失败要停在正确的步骤上**，后面的步骤标 `skip` 而不是留着 `pending`
   —— `pending` 在前端看起来像"还在跑"，人会一直等下去。
4. **`ok` 字段不能一物两用**：接口顶层 `ok` 是"请求成功"，接入是否成功是
   `succeeded`。混用过一次，结果是"点了开始接入，界面立刻说无法开始接入"。
5. **ABI 必须匹配**：推错 ABI 的二进制，表现是"启动后没有进程"，与"su 没授权"
   长得一模一样，事后极难分辨。
"""
from __future__ import annotations

import json
import re
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "webapp" / "static" / "index.html"
SERVER = ROOT / "webapp" / "server.py"


class _R:
    def __init__(self, out=b"", rc=0):
        self.returncode = rc
        self.stdout = out
        self.stderr = b""


def _fake_run(args, timeout: int = 30):
    s = " ".join(str(a) for a in args)
    if "version" in s:
        return _R(b"Android Debug Bridge version 1.0.41")
    if "piiscan-enroll" in s:
        return _R(b"piiscan-enroll")
    return _R(b"")


def _patch(obj, **kv):
    """临时替换若干属性，返回恢复函数。"""
    old = {k: getattr(obj, k) for k in kv}
    for k, v in kv.items():
        setattr(obj, k, v)

    def restore():
        for k, v in old.items():
            setattr(obj, k, v)
    return restore


def run(check):
    _t_fridabin(check)
    _t_registry(check)
    _t_usable(check)
    _t_enroll_fail_root(check)
    _t_enroll_ok(check)
    _t_enroll_unauthorized(check)
    _t_snapshot_fields(check)
    _t_consistency(check)
    _t_frontend(check)


# ---------------------------------------------------------------- frida 二进制
def _t_fridabin(check):
    from piiscan import fridabin as F

    check("ABI 归一到 frida 的发布名",
          F.norm_abi("arm64-v8a") == "arm64"
          and F.norm_abi("armeabi-v7a") == "arm"
          and F.norm_abi("x86_64") == "x86_64",
          [F.norm_abi(x) for x in ("arm64-v8a", "armeabi-v7a", "x86_64")])
    check("认不出的 ABI 原样返回（不猜成 arm64）",
          F.norm_abi("mips") == "mips", F.norm_abi("mips"))

    check("从文件名解析出版本与 ABI",
          F.parse_name("frida-server-16.7.18-android-arm64") == ("16.7.18", "arm64"),
          F.parse_name("frida-server-16.7.18-android-arm64"))
    check("带 .xz/.bak 后缀也能解析",
          F.parse_name("frida-server-16.7.18-android-arm64.xz")[0] == "16.7.18",
          F.parse_name("frida-server-16.7.18-android-arm64.xz"))
    check("不认识的文件名返回空串（不臆造版本）",
          F.parse_name("not-a-frida") == ("", ""), F.parse_name("not-a-frida"))

    # ★ 这条是本次最实质的修复：旧实现只按文件名找、不看 ABI。
    #   一台 32 位 arm 的手机拿到 arm64 的二进制，push 会成功、启动会失败，
    #   而错误看起来像"su 没授权"。
    ok, why = F.find(abi="armeabi-v7a", version="16.7.18")
    check("本机没有该 ABI 的二进制时**拒绝**返回 arm64 的文件",
          ok is None or F.parse_name(str(ok))[1] == "arm",
          str(ok))
    check("拒绝时说明差在哪（版本/ABI 都要写出来）",
          "ABI" in why and "arm" in why, why[:160])
    check("拒绝时给出可执行的下一步（放哪、或设环境变量）",
          "FRIDA_SERVER" in why or "tools/frida" in why, why[:200])

    # 备份文件不该被当成候选（`.bak` 名字里带版本号，很容易被误推）
    cands = F.search()
    check("搜索时排除 .bak/.old 备份文件",
          all(".bak" not in p.name for p, _v, _a in cands),
          [p.name for p, _v, _a in cands])


# ---------------------------------------------------------------- 登记簿
def _t_registry(check):
    from webapp.db import JobDB

    db = JobDB(Path(tempfile.mkdtemp(prefix="reg_")) / "t.db")
    check("空库时登记簿为 0", db.device_count() == 0, db.device_count())

    e = db.device_save(serial="AAA", alias="一号机", phone="13800000000",
                       note="备注", root_ok=True,
                       info={"model": "M1", "brand": "B", "android": "12",
                             "sdk": "31", "abi": "arm64-v8a"},
                       frida_ver="16.7.18", steps="[]")
    check("新增登记成功", e.get("serial") == "AAA" and e.get("alias") == "一号机", e)
    check("root_ok 落成布尔", e.get("root_ok") is True, e.get("root_ok"))
    check("verified_at 在 root 通过时写入", bool(e.get("verified_at")), e.get("verified_at"))

    # 改信息**不能**刷新 verified_at —— 那是"上次验证时间"，改个备注就变今天
    # 等于伪造成"今天验证过"。
    v1 = e["verified_at"]
    db.device_meta("AAA", alias="改名后", note="新备注")
    e2 = db.device_get("AAA")
    check("改别名/备注不刷新验证时间",
          abs(float(e2["verified_at"]) - float(v1)) < 0.001,
          (v1, e2.get("verified_at")))
    check("改别名生效", e2["alias"] == "改名后", e2["alias"])
    check("只传一个字段不会把其它字段清空",
          e2["phone"] == "13800000000", e2["phone"])

    # 重复添加同一台：不产生第二条，也不把 added_at 改成现在
    a1 = e2["added_at"]
    db.device_save(serial="AAA", alias="再添一次", root_ok=True)
    check("重复添加不产生第二条记录", db.device_count() == 1, db.device_count())
    check("重复添加不改加入时间（列表顺序不会乱跳）",
          abs(float(db.device_get("AAA")["added_at"]) - float(a1)) < 0.001,
          (a1, db.device_get("AAA")["added_at"]))

    # 号码表
    db.device_save(serial="BBB", alias="二号机", phone="13900000000", root_ok=True)
    phones = db.device_phones()
    check("号码表按序列号返回", phones.get("BBB") == "13900000000", phones)
    # 上面那条"再添一次"把 AAA 的号覆盖成了空 —— 这是 db 层的 UPSERT 语义，
    # 而真正要守的是**接口层**：重新接入时表单没填的项要沿用旧值
    # （见 _t_snapshot_wiring 里的源码断言）。这里把它补回去，后面的删除用例要用。

    # 删除
    r = db.device_delete("BBB")
    check("删除已登记设备成功", r.get("ok") is True, r)
    check("删除后计数下降", db.device_count() == 1, db.device_count())
    check("重复删除要说清「没登记过」而不是静默成功",
          db.device_delete("BBB").get("ok") is False, db.device_delete("BBB"))
    check("删除不存在的设备也不抛异常", True)

    # 降级登记：root 没通过但用户坚持登记
    db.device_save(serial="CCC", alias="无root", root_ok=False, degraded=True)
    c = db.device_get("CCC")
    check("降级登记的 root_ok 为假", c["root_ok"] is False, c["root_ok"])
    check("降级登记要带 degraded 标记（界面上必须看得出来）",
          c["degraded"] is True, c["degraded"])
    check("降级登记不写 verified_at（没验证过就不能有验证时间）",
          not c.get("verified_at"), c.get("verified_at"))


# ---------------------------------------------------------------- 可用性判定
def _t_usable(check):
    from piiscan.devices import usable

    entry = {"root_ok": True}
    dev_ok = {"state": "device", "root": True}
    check("接入达标 + 此刻在线 + su 还在 → 可用", usable(entry, dev_ok) is True)
    check("拔了线 → 不可用", usable(entry, {"state": "absent", "root": True}) is False)
    check("没接入过 → 不可用", usable(None, dev_ok) is False)
    check("接入时 root 没通过 → 不可用", usable({"root_ok": False}, dev_ok) is False)
    # 这一条是"历史事实 vs 现状"的分界线：接入时通过过，后来 root 被撤了
    check("root 后来失效 → 不可用（不能拿历史结论当现状）",
          usable(entry, {"state": "device", "root": False}) is False)

    from piiscan.devices import STEP_TITLES
    check("步骤数 ≥ 8 且首尾正确",
          len(STEP_TITLES) >= 8 and STEP_TITLES[0][0] == "adb"
          and STEP_TITLES[-1][0] == "ui_dump",
          [k for k, _t in STEP_TITLES])
    check("步骤里有 root 检查与 frida 部署",
          any(k == "root" for k, _ in STEP_TITLES)
          and any(k == "frida_server" for k, _ in STEP_TITLES))


# ---------------------------------------------------------------- 接入：失败路径
def _t_enroll_fail_root(check):
    """root 拿不到 → 流程停在 root，后面的步骤标 skip（不是 pending）。"""
    from piiscan import devices as D
    from piiscan import preflight as PF

    undo = [
        _patch(D, _run=_fake_run),
        _patch(PF, list_devices=lambda: [PF.DeviceEntry("FAKE1", "device", "T")],
               _device_prop=lambda s, n: {"ro.product.model": "测试机",
                                          "ro.product.brand": "Test",
                                          "ro.build.version.release": "12",
                                          "ro.build.version.sdk": "31",
                                          "ro.product.cpu.abi": "arm64-v8a"}.get(n, "")),
        _patch(D, _probe_root=lambda *a, **k: (False, "su -c id 连续 3 次都没有 uid=0",
                                               "在 Magisk 里给 Shell 放行")),
    ]
    try:
        res = D.enroll("FAKE1", wait_s=1.0)
    finally:
        for f in reversed(undo):
            f()

    check("root 不可用 → 整体失败", res.ok is False, res.ok)
    r = res.step("root")
    check("root 步骤标 fail", r is not None and r.state == "fail", r.state if r else None)
    check("root 失败带「怎么办」（Magisk 授权指引）",
          "Magisk" in (r.fix or ""), r.fix if r else "")
    later = [s for s in res.steps if s.key in ("frida_bin", "frida_server",
                                               "frida_conn", "screen", "ui_dump")]
    check("root 之后的步骤全部标 skip（不能留着 pending 让人一直等）",
          all(s.state == "skip" for s in later),
          [(s.key, s.state) for s in later])
    check("失败时一个 pending 都不剩",
          not any(s.state == "pending" for s in res.steps),
          [(s.key, s.state) for s in res.steps])
    check("失败原因写在 error 里（给上层判断用）", bool(res.error), res.error)
    check("root 失败时不产生登记记录（错误在流程侧，不在库侧）",
          res.degraded is False, res.degraded)


def _t_enroll_ok(check):
    """全绿路径：步骤依序走完，root 通过时不算降级。"""
    from piiscan import devices as D
    from piiscan import preflight as PF
    from piiscan import uiwalk as UW

    from piiscan import fridabin as FB
    undo = [
        # 用例不能依赖"跑自检的这台机器装了 frida"：服务端自检跑在内置 Python 上，
        # 那里通常没有 frida 运行库，真去 import 会把整条路径判成"本机没有运行库"。
        _patch(FB, local_version=lambda: "16.7.18"),
        _patch(D, _run=_fake_run),
        _patch(PF, list_devices=lambda: [PF.DeviceEntry("FAKE2", "device", "T")],
               _device_prop=lambda s, n: {"ro.product.model": "测试机2",
                                          "ro.product.brand": "Test",
                                          "ro.build.version.release": "12",
                                          "ro.build.version.sdk": "31",
                                          "ro.product.cpu.abi": "arm64-v8a"}.get(n, ""),
               _remote_frida_names=lambda s: ["frida-server-16.7.18-android-arm64"],
               _local_frida_version=lambda: "16.7.18",
               ensure_frida_server=lambda *a, **k: PF.Check(
                   "frida_server", "frida-server 运行中", True, "进程在跑"),
               _frida_connect=lambda s: PF.Check(
                   "frida_conn", "frida 可连接设备", True, "已连接")),
        _patch(D, _probe_root=lambda *a, **k: (True, "su -c id → uid=0(root)", "")),
        _patch(UW, keep_screen_on=lambda s: None, wake=lambda s: None,
               is_locked=lambda s: False, try_unlock=lambda s, log=None: True,
               reset_dump_health=lambda s: None,
               kill_stale_uiautomator=lambda s: (0, []),
               home=lambda s: None,
               dump=lambda s, force=False: "<hierarchy></hierarchy>",
               parse_all=lambda x: [1, 2, 3]),
    ]
    try:
        res = D.enroll("FAKE2", wait_s=1.0)
    finally:
        for f in reversed(undo):
            f()

    check("全绿路径 → 接入成功", res.ok is True, res.error or res.ok)
    check("成功时所有步骤都是 ok",
          all(s.state == "ok" for s in res.steps),
          [(s.key, s.state) for s in res.steps])
    check("成功时不算降级", res.degraded is False)
    check("读到设备信息（型号/ABI 要能用于选二进制）",
          res.info.get("model") == "测试机2" and res.info.get("abi") == "arm64-v8a",
          res.info)
    check("root 成功时不留 fix（失败建议不该挂在成功项上）",
          not (res.step("root").fix or ""), res.step("root").fix)

    # 降级：force=True 时 root 失败仍然继续
    undo = [
        _patch(FB, local_version=lambda: "16.7.18"),
        _patch(D, _run=_fake_run),
        _patch(PF, list_devices=lambda: [PF.DeviceEntry("FAKE3", "device", "T")],
               _device_prop=lambda s, n: {"ro.product.model": "测试机3",
                                          "ro.product.cpu.abi": "arm64-v8a"}.get(n, ""),
               _remote_frida_names=lambda s: ["frida-server-16.7.18-android-arm64"],
               _local_frida_version=lambda: "16.7.18",
               ensure_frida_server=lambda *a, **k: PF.Check(
                   "frida_server", "frida-server 运行中", True, "进程在跑"),
               _frida_connect=lambda s: PF.Check(
                   "frida_conn", "frida 可连接设备", True, "已连接")),
        _patch(D, _probe_root=lambda *a, **k: (False, "没有 uid=0", "去授权")),
        _patch(UW, keep_screen_on=lambda s: None, wake=lambda s: None,
               is_locked=lambda s: False, try_unlock=lambda s, log=None: True,
               reset_dump_health=lambda s: None,
               kill_stale_uiautomator=lambda s: (0, []),
               home=lambda s: None,
               dump=lambda s, force=False: "<hierarchy></hierarchy>",
               parse_all=lambda x: [1]),
    ]
    try:
        res = D.enroll("FAKE3", wait_s=1.0, force=True)
    finally:
        for f in reversed(undo):
            f()
    check("force=True 时 root 失败仍会走完流程（供「仅登记信息」用）",
          res.ok is True and res.degraded is True, (res.ok, res.degraded))
    check("降级时 root 步骤的说明里写明功能受限",
          "仅登记" in (res.step("root").detail or ""), res.step("root").detail)


def _t_enroll_unauthorized(check):
    """一直未授权：online 失败，且提示必须在手机上点「允许」。"""
    from piiscan import devices as D
    from piiscan import preflight as PF

    undo = [
        _patch(D, _run=_fake_run),
        _patch(PF, list_devices=lambda: [PF.DeviceEntry("FAKE4", "unauthorized", "T")]),
    ]
    try:
        res = D.enroll("FAKE4", wait_s=0)
    finally:
        for f in reversed(undo):
            f()
    st = res.step("online")
    check("未授权 → 接入失败", res.ok is False, res.ok)
    check("未授权时说明要在手机上点「允许 USB 调试」",
          "允许" in (st.detail or ""), st.detail)
    check("未授权时不把后面步骤留在 pending",
          not any(s.state == "pending" for s in res.steps),
          [(s.key, s.state) for s in res.steps])
    check("未授权时 fix 提到 USB / 无线调试", "USB" in (st.fix or ""), st.fix)


# ---------------------------------------------------------------- 接口字段
def _t_snapshot_fields(check):
    src = SERVER.read_text(encoding="utf-8")
    # ★ 这条是踩过的坑：snapshot 里用 `ok` 表示"接入成功"，而所有接口顶层
    #   也用 `ok` 表示"请求成功"。前端判定 `r.ok === false` 后立刻报
    #   "无法开始接入"，而实际上流程刚刚开始跑。
    check("接入会话的成功标志用 succeeded，不叫 ok",
          '"succeeded": (sess.get("state") == "ok")' in src
          and '"ok": (sess.get("state") == "ok")' not in src, "")
    check("接入/轮询接口的顶层 ok 恒为请求成功",
          'self._json(dict(snap, ok=True)' in src, "")
    check("接入会话不落盘（重启后如实说进度丢失）",
          "接入会话不存在或已过期" in src, "")
    check("删除接口明确写「不动设备本身」",
          "设备本身未做任何改动" in src, "")
    check("删除/接入前检查设备是否被任务占用",
          src.count("正被任务") >= 2, src.count("正被任务"))
    check("手机号在设备管理里也走同一套校验",
          "_norm_phone(phone)" in src, "")
    check("登记簿号码优先于 config.yaml（人在界面上改过就该生效）",
          "登记簿优先" in src, "")
    # 重新接入一台已登记的机器时，表单里没填的项要沿用旧值 —— 否则
    # "再添加一次"会把之前填好的号码悄悄清空，症状只是"登录超时"。
    check("重新接入时表单没填的别名/号码/备注沿用旧值",
          'if not phone:' in src and 'old.get("phone")' in src
          and 'old.get("alias")' in src, "")


# ------------------------------------------------- 一处操作、处处一致（2026-11-11）
def _t_consistency(check):
    """用户报障：两台手机都移除了，状态页仍写"2 台可用 / 2 台已连接"。

    根因有两层，两层都要守：
      ① 前端把"一台都没登记"当成"退回旧行为：列出全部已连接设备"，
         于是移除之后下拉框和设备卡又冒出来了；
      ② 状态页按 adb 里有几台统计"已连接/就绪"，而不是按登记簿。

    这里跑一遍真实 HTTP 路径：登记两台 → 全删 → 看接口和口径还说不说真话。
    """
    import webapp.server as S
    from webapp.db import JobDB

    src = SERVER.read_text(encoding="utf-8")

    # ---- 口径只算一次 ----
    check("「能不能用」只在 list_test_devices 里算一次（两页共用）",
          src.count('d["usable"] = bool(') == 1 and 'can = bool(d.get("usable"))' in src,
          src.count('d["usable"] = bool('))
    check("登记簿接口直接取算好的 usable（不再自己算一遍）",
          'can = bool(d.get("usable"))' in src and "_dev.usable(e, d)) and not busy" not in src, "")
    check("移除设备的兜底回退已删除（不再「空了就列全部」）",
          "regN > 0 ? DEVICES.filter" not in src
          and "regN > 0 ? DEVICES.filter" not in HTML.read_text(encoding="utf-8"), "")
    check("提交任务时把设备解析成 _resolve_device（登记簿是唯一口径）",
          "def _resolve_device" in src and "_require_device_choice" not in src, "")

    # ---- 设备必须人选（2026-11-11 用户口径）----
    hsrc = HTML.read_text(encoding="utf-8")
    check("前端不再有「自动挑一台」的函数", "devPickDefault" not in hsrc, "")
    check("下拉框不再给某台标「（默认）」",
          '"（默认）"' not in hsrc and "（默认）</span>" not in hsrc, "")
    check("下拉框首项是占位「（请选择测试机）」",
          "（请选择测试机）" in hsrc, "")
    check("不再把选择记进 localStorage（记了就是隐性默认）",
          "DEV_STORE" not in hsrc and "piiscan.device" not in hsrc, "")
    check("未选设备时提示「请先在…选一台」，不是「—」",
          "请先在「测试机」里选一台" in hsrc, "")
    check("静态任务不因未选设备被拦（只拦动态）",
          '$("#run_dynamic").checked && !_devSel.value' in hsrc, "")
    # 标签函数必须是页面级的：下拉框 change 只改 value、不会重跑 loadDevices，
    # 定义在 loadDevices 内部的话"选完标签还写着必须选"（CDP 真抓到过）。
    _fn_at = hsrc.find("function setDevLabel(pick)")
    _load_at = hsrc.find("async function loadDevices(force)")
    check("setDevLabel 是页面级函数（在 loadDevices 之前定义）",
          0 <= _fn_at < _load_at, (_fn_at, _load_at))
    check("切换测试机时刷新标签与错误提示",
          'setDevLabel($("#device").value);' in hsrc
          and "if (typeof hideErr" in hsrc, "")
    # 2026-11-11 踩过：改 if/else 时留下一截旧 else，root 明明是 true，
    # 提示行却拼出"未 root（动态采集不可用）"（截图上一眼可见，自检全绿）。
    check("root 结论只有一条 if(!d.root) 分支（没有多余的 else 尾巴）",
          hsrc.count('bits.push("未 root') == 1
          and 'else bits.push("未 root' not in hsrc,
          hsrc.count('bits.push("未 root'))

    tmp = Path(tempfile.mkdtemp(prefix="consist_"))
    db = JobDB(tmp / "jobs.db")
    S.Handler.db = db
    S.Handler.workdir = tmp
    S.Handler.device_enabled = True

    # 假设备清单**按登记簿算 managed**，与 list_test_devices 的真实逻辑一致
    # （否则用例本身就在撒谎，测不出问题）。
    def _fake_list(*a, **k):
        reg = {e["serial"]: e for e in db.devices_list()}
        out = []
        for s, model in (("f6e5d4c3b2a1", "M2004J19C"), ("a1b2c3d4", "Redmi K30")):
            e = reg.get(s) or {}
            out.append({
                "serial": s, "state": "device", "model": model, "brand": "Redmi",
                "android": "10", "sdk": "29", "abi": "arm64-v8a", "root": True,
                "frida": "16.7.18", "frida_ok": True, "busy": False, "busy_job": "",
                "note": "", "label": model, "tags": [], "managed": bool(e),
                "alias": e.get("alias") or "", "registered_root_ok": bool(e.get("root_ok")),
                "degraded": False, "verified_at": 0,
                "usable": bool(e.get("root_ok"))})
        return out

    real_list = S.list_test_devices
    S.list_test_devices = _fake_list
    httpd = S.ThreadingHTTPServer(("127.0.0.1", 0), S.Handler)
    httpd.quiet = True
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]

    def _get(p):
        with urllib.request.urlopen(base + p, timeout=10) as r:
            return r.status, json.loads(r.read().decode())

    def _post(p, payload):
        req = urllib.request.Request(base + p, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def _del(p):
        req = urllib.request.Request(base + p, method="DELETE")
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())

    try:
        db.device_save(serial="f6e5d4c3b2a1", root_ok=True, frida_ver="16.7.18")
        db.device_save(serial="a1b2c3d4", root_ok=True, frida_ver="16.7.18")
        st, body = _get("/api/devices")
        check("登记两台之后 /api/devices 报 registry_count=2",
              st == 200 and body.get("registry_count") == 2, body.get("registry_count"))
        check("登记过的设备 managed=True 且 usable=True",
              all(d.get("managed") and d.get("usable") for d in body["devices"]),
              [(d["serial"], d.get("managed"), d.get("usable")) for d in body["devices"]])

        # ---- 只登记一台、不指定设备 → 也必须拒绝 ----
        # 设备是报告里的一条证据。"只有一台所以替你选"等于替用户签字，
        # 而猜错的后果是"在 A 机上测完、报告写 B 机的环境"，从报告上看不出来。
        db.device_delete("a1b2c3d4")
        st, r = _post("/api/jobs", {"apk_url": "http://example.com/solo.apk",
                                    "run_dynamic": True})
        txt = json.dumps(r, ensure_ascii=False)
        check("只登记一台、不选机 → 400", st == 400, (st, txt[:120]))
        check("拒绝时点名那台已登记的机器", "f6e5d4c3b2a1" in txt, txt[:200])
        check("拒绝时不给 job_id", not r.get("job_id"), r.get("job_id"))
        db.device_save(serial="a1b2c3d4", root_ok=True, frida_ver="16.7.18")

        # ---- 两台都移除（用户在界面上做的那一步）----
        for s in ("f6e5d4c3b2a1", "a1b2c3d4"):
            st, r = _del("/api/devices/" + s)
            check("移除 %s 成功" % s, st == 200 and r.get("ok") is True, (st, r.get("error")))

        st, body = _get("/api/devices")
        check("移除后 registry_count=0", body.get("registry_count") == 0, body.get("registry_count"))
        check("移除后所有设备 managed=False（否则下拉框还会列它）",
              all(d.get("managed") is False for d in body["devices"]),
              [(d["serial"], d.get("managed")) for d in body["devices"]])
        check("移除后所有设备 usable=False（否则状态页还会说「可用」）",
              all(d.get("usable") is False for d in body["devices"]),
              [(d["serial"], d.get("usable")) for d in body["devices"]])

        st, reg = _get("/api/devices/registry")
        check("登记簿为空时 devices 为空、unmanaged 有 2 台",
              reg.get("devices") == [] and len(reg.get("unmanaged") or []) == 2,
              (len(reg.get("devices") or []), len(reg.get("unmanaged") or [])))

        # 动态任务：没有已登记的测试机 → 当场拒绝，不排队
        st, r = _post("/api/jobs", {"apk_url": "http://example.com/a.apk",
                                    "run_dynamic": True})
        txt = json.dumps(r, ensure_ascii=False)
        check("移除两台后提交动态任务 → 400", st == 400, (st, txt[:120]))
        check("拒绝理由指向「手机管理 → 添加手机」",
              "手机管理" in txt and "添加手机" in txt, txt[:160])

        # 再移除一次 → 404（不是 200，也不是 500）
        try:
            _del("/api/devices/f6e5d4c3b2a1")
            check("重复移除 → 404", False, "没有报错")
        except urllib.error.HTTPError as e:
            check("重复移除 → 404", e.code == 404, e.code)
    finally:
        S.list_test_devices = real_list
        httpd.shutdown()
        httpd.server_close()


# ---------------------------------------------------------------- 前端
def _t_frontend(check):
    h = HTML.read_text(encoding="utf-8")

    check("手机管理页容器存在", 'id="page-devices"' in h, "")
    check("侧栏有手机管理菜单", 'href="#/devices" data-page="devices"' in h, "")
    m = re.search(r'<nav class="nav" id="nav">([\s\S]*?)</nav>', h)
    order = re.findall(r'data-page="([a-z]+)"', m.group(1)) if m else []
    check("菜单顺序：状态 → 新建 → 列表 → 手机管理",
          order == ["status", "new", "jobs", "devices"], order)

    check("路由表包含 devices", "const PAGES = {status: 1, devices: 1, new: 1, jobs: 1};" in h
          or re.search(r"const PAGES = \{[^}]*devices: 1", h) is not None, "")
    check("切到手机管理页会强制刷新登记簿", 'loadRegistry(true)' in h, "")

    # 下拉框过滤：**登记簿是唯一口径**（2026-11-11 用户报障后又改过一次）。
    # 早先是 `regN > 0 ? 只列登记的 : 列全部`，那个回落让"两台都移除"之后
    # 下拉框里又冒出两台、状态页仍写"2 台可用" —— 移除看起来没生效。
    check("任务下拉只列已登记的机器（不再回落列全部）",
          "const shown = DEVICES.filter(d => d.managed);" in h
          and "regN > 0 ? DEVICES.filter" not in h, "")
    check("登记了但一台都没在线时给出明确提示（不是空下拉）",
          "没有已登记的测试机在线" in h, "")
    check("一台都没登记时提示去添加（不是列出全部可用）",
          "还没有添加测试机" in h, "")

    # 向导
    for eid in ("dev-add", "reg-list", "unmanaged-card", "wiz", "wiz-body", "wiz-foot"):
        check("向导元素存在：%s" % eid, ('id="%s"' % eid) in h, "")
    check("向导有备注名与手机号输入", 'id="wiz-alias"' in h and 'id="wiz-phone"' in h, "")
    check("向导有「允许联网下载 frida-server」开关", 'id="wiz-dl"' in h, "")
    check("向导说明「关闭窗口不会中断接入」", "不会中断" in h, "")
    check("向导在运行中提示「在手机上点允许」", "请在手机上点允许" in h, "")
    check("失败步骤会显示建议（.sf）", 'class="sf"' in h, "")
    check("结果页区分「已登记但受限」与「接入成功」",
          "已登记（功能受限）" in h and "接入成功" in h, "")

    # 四个动作
    for attr in ("data-enroll", "data-edit", "data-del", "data-check"):
        check("管理页动作：%s" % attr, attr in h, "")
    check("移除前的确认框写明「不会改动手机」", "不会改动手机" in h, "")
    check("移除确认框写清「移除后不再用它跑任务」，不留「除非清空」的回退口子",
          "平台不再用它跑任务" in h and "除非登记簿被清空" not in h, "")
    check("事件用委托绑定（列表每次刷新都重建，逐行绑会累积监听器）",
          '#"page-devices").addEventListener("click"' in h
          or '"#page-devices").addEventListener("click"' in h, "")
    check("状态页的未登记设备给「添加到平台」入口", "添加到平台" in h, "")

    # 状态页汇总也必须按登记簿算 —— 用户看到的就是这行字："2 台已连接 · 2 台就绪"。
    check("状态页汇总只统计已登记的设备",
          "const managed = DEVICES.filter(d => d.managed);" in h
          and "DEVICES.filter(d => d.state === \"device\")" not in h.split("function renderDevCards")[1][:900],
          "")
    check("没有登记时汇总直接说「还没有添加测试机」",
          '"还没有添加测试机（检测到 "' in h, "")
    check("未登记设备单独一段并写明「不参与任务」",
          "不参与任务" in h and ".devcard.unreg" in h, "")
    check("未登记的设备卡不用红色（红=这台机坏了，那是另一回事）",
          '" unreg"' in h and "const bad = d.managed && (!online || !d.root);" in h, "")
    check("未登记那组的说明条单独一个类（不复用 .devcard，否则会被算成一张卡）",
          'class="devsep"' in h and ".devsep{" in h, "")
    check("「全部自检」只跑已登记的（否则就绪台数会虚高）",
          "DEVICES.filter(d => d.managed && d.state === \"device\")" in h, "")

    # 细节：轮询用 succeeded/state，不看 HTTP 层 ok 判业务成败
    check("轮询不会把「正在跑」当成失败",
          "r.ok === false && r.error" not in h, "")
