"""sop_job 编排层的离线自测（由 tools/platform_selftest.py 调用）。

单独成一个文件是为了让桩代码集中、不干扰状态机与自检的用例。
所有外部动作（预检、采集、卸载、判定、渲染）都换成桩，
但**编排顺序与失败处理完全走真实代码** —— 要验的正是顺序。
"""
from __future__ import annotations

import tempfile
import time
from pathlib import Path


def _patch_job_deps(scan_factory, teardown_calls, pf_ok=True):
    from piiscan import collector, preflight, teardown
    import piiscan.flow as flow_pkg
    from piiscan.report import sop_report

    saved = {}

    def fake_pf_run(cfg, log=None, **kw):
        ok = pf_ok

        class R:
            serial = "fake-serial"
            device = {"model": "FakePhone"}

            def to_dict(self):
                return {"ok": ok, "serial": self.serial}

            def brief(self):
                return ["[OK ] fake"]

            def summary(self):
                return "环境自检通过（fake）" if ok else "环境自检未通过：设备未连接"

        R.ok = ok
        return R()

    saved["pf"] = preflight.run
    preflight.run = fake_pf_run

    saved["scan"] = collector.run_scan
    collector.run_scan = scan_factory

    saved["td"] = teardown.uninstall

    def fake_td(serial, package, log=None):
        teardown_calls.append((serial, package))
        return {"ok": True, "note": "已从设备卸载，复查确认不存在",
                "package": package, "before": {"installed": True}}

    teardown.uninstall = fake_td

    class FakeFlow:
        def __init__(self):
            self.teardown = {}
            self.source_market = ""
            self.operator = ""
            self.published_at = ""

        def stats(self):
            return {"fail": 1, "suspect": 2, "pass": 4, "not_tested": 15, "total": 22}

        def to_dict(self):
            return {"items": {}, "phases": []}

    saved["flow"] = flow_pkg.run_flow
    flow_pkg.run_flow = lambda **kw: FakeFlow()

    saved["render"] = sop_report.render
    sop_report.render = lambda fr, **kw: "<html>fake report</html>"

    def restore():
        preflight.run = saved["pf"]
        collector.run_scan = saved["scan"]
        teardown.uninstall = saved["td"]
        flow_pkg.run_flow = saved["flow"]
        sop_report.render = saved["render"]

    return restore


def _fake_scan(package="com.demo.app", aborted=False, raise_exc=None):
    from piiscan.collector import ScanResult

    def factory(cfg, log=None, **kw):
        if raise_exc:
            raise raise_exc
        r = ScanResult(package=package)
        r.device_serial = "fake-serial"
        r.aborted = aborted
        r.abort_reason = "UI 遍历阶段被中断" if aborted else ""
        r.started_at = time.time()
        r.ended_at = time.time()
        r.ui_taps = 3
        r.screenshots = [{"label": "x"}]
        return r

    return factory


def _run_job(opts, stop=None):
    from piiscan.sop_job import run_job
    from piiscan.config import AppConfig

    with tempfile.TemporaryDirectory() as td:
        out = run_job("JTEST", td, opts, AppConfig(), log=lambda *_a: None,
                      should_stop=stop)
        files = sorted(p.name for p in Path(td).iterdir())
    return out, files


def run(check) -> None:
    from piiscan.sop_job import JobOptions

    # ---------------- 正常路径 ----------------
    calls = []
    restore = _patch_job_deps(_fake_scan(), calls)
    try:
        out, files = _run_job(JobOptions(package="com.demo.app", dynamic=True,
                                         duration=10))
    finally:
        restore()
    check("正常任务返回成功", out.ok is True, out.error)
    check("正常任务生成报告", out.report_path.endswith("report.html"), out.report_path)
    check("正常任务生成流程存档", out.flow_path.endswith("flow.json"), out.flow_path)
    check("正常任务保存采集存档", out.scan_path.endswith("scan.result.json"), out.scan_path)
    check("正常任务完成卸载", len(calls) == 1, calls)
    check("结论统计透传", out.stats.get("fail") == 1 and out.stats.get("not_tested") == 15,
          out.stats)
    check("阶段耗时有记录", len(out.phases) >= 4, [p.get("phase") for p in out.phases])
    check("报告与存档都落在工作目录", "report.html" in files and "flow.json" in files, files)

    # ---------------- 环境不过：不许碰设备 ----------------
    calls = []
    restore = _patch_job_deps(_fake_scan(), calls, pf_ok=False)
    try:
        out, _ = _run_job(JobOptions(package="com.demo.app", dynamic=True))
    finally:
        restore()
    check("环境不通过时任务失败", out.ok is False)
    check("失败原因写明是环境自检", "环境自检未通过" in out.error, out.error)
    # ★ 无人值守最关键的一条：环境没好就不许装。
    #   否则会装上去、跑一轮空采集、再卸掉，最后出一份"看起来没问题"的报告。
    check("环境不通过时不安装也不卸载", calls == [], calls)

    # ---------------- 采集中断：仍要恢复环境 ----------------
    calls = []
    restore = _patch_job_deps(_fake_scan(aborted=True), calls)
    try:
        out, files = _run_job(JobOptions(package="com.demo.app", dynamic=True))
    finally:
        restore()
    check("被取消的任务标记 canceled", out.canceled is True, out.error)
    check("被取消的任务标记为数据不完整", out.aborted is True)
    check("被取消时仍然卸载应用", len(calls) == 1, calls)
    check("被取消时不出具报告", out.report_path == "", out.report_path)
    check("被取消时保留采集存档", out.scan_path != "", out.scan_path)
    check("被取消时不写 flow.json", "flow.json" not in files, files)

    # ---------------- 采集异常：仍要恢复环境 ----------------
    calls = []
    restore = _patch_job_deps(_fake_scan(raise_exc=RuntimeError("frida 掉了")), calls)
    try:
        out, _ = _run_job(JobOptions(package="com.demo.app", dynamic=True))
    finally:
        restore()
    check("采集异常 → 任务失败", out.ok is False)
    check("异常原因被记录", "frida 掉了" in out.error, out.error)
    # ★ 失败也要卸：不卸的话下一轮"首启"判定直接被残留数据污染。
    check("异常时也会卸载应用", len(calls) == 1, calls)

    # ---------------- keep_app ----------------
    calls = []
    restore = _patch_job_deps(_fake_scan(), calls)
    try:
        out, _ = _run_job(JobOptions(package="com.demo.app", dynamic=True, keep_app=True))
    finally:
        restore()
    check("keep_app 时不卸载", calls == [], calls)
    check("keep_app 时注明跳过", out.teardown.get("skipped") is True, out.teardown)

    # ---------------- 阶段边界取消 ----------------
    calls = []
    restore = _patch_job_deps(_fake_scan(), calls)
    try:
        n = {"i": 0}

        def should_stop():
            # 第 1 次在静态分析后（放行），第 2 次在环境自检后（要求停）
            # → 应该还没碰设备就退出
            n["i"] += 1
            return n["i"] > 1

        out, _ = _run_job(JobOptions(package="com.demo.app", dynamic=True),
                          stop=should_stop)
    finally:
        restore()
    check("阶段边界能响应取消", out.canceled is True, out.error)
    check("阶段边界取消时未进入采集", calls == [], calls)
    check("阶段边界取消时不出报告", out.report_path == "")

    # ---------------- 取消不得重复卸载 ----------------
    calls = []
    restore = _patch_job_deps(_fake_scan(), calls)
    try:
        n = {"i": 0}

        def should_stop():
            # 第 3 次（采集后）才要求停：此时正常路径已卸过一次，
            # except 分支不能再卸第二次
            n["i"] += 1
            return n["i"] > 2

        out, _ = _run_job(JobOptions(package="com.demo.app", dynamic=True),
                          stop=should_stop)
    finally:
        restore()
    check("采集后取消仍算取消", out.canceled is True, out.error)
    check("只卸载一次（不重复卸载覆盖证据）", len(calls) == 1, calls)

    # ---------------- 外部采集结果：不碰设备也能出报告 ----------------
    # 场景：手机接在另一台机器上（或本机 USB 直通不通），采集端跑出
    # scan.result.json，拿到这台机器上做判定与报告。
    # 要验的是：**这台机器一条设备命令都不发**，而不是"发一遍失败了再兜底"。
    import json as _json
    import tempfile as _tf

    with _tf.TemporaryDirectory() as sdir:
        scan_file = Path(sdir) / "scan.result.json"
        scan_file.write_text(_json.dumps({
            "package": "com.demo.app",
            "device_serial": "ext-serial",
            "device_model": "ExternalPhone",
            "android_version": "12",
            "consent_given": True,
            "events": [],
            "teardown": {"ok": True, "note": "采集端已卸载"},
        }, ensure_ascii=False), encoding="utf-8")
        calls = []
        restore = _patch_job_deps(_fake_scan(), calls)
        try:
            # dynamic=True 是刻意的：调用方写了要动态采集，但给了存档，
            # 就必须以存档为准，不能"顺手跑一下"去连一台不存在的设备。
            out, files = _run_job(JobOptions(
                scan_result_path=str(scan_file), dynamic=True, duration=10))
        finally:
            restore()
    check("外部存档：任务成功", out.ok is True, out.error)
    check("外部存档：不执行环境自检", out.preflight == {}, out.preflight)
    check("外部存档：不碰设备（无卸载调用）", calls == [], calls)
    check("外部存档：报告已生成", out.report_path.endswith("report.html"),
          out.report_path)
    check("外部存档：存档复制进工作目录", "scan.result.json" in files, files)
    check("外部存档：阶段里有导入记录",
          any(p.get("phase") == "导入采集结果" for p in out.phases),
          [p.get("phase") for p in out.phases])
    check("外部存档：沿用存档里的包名", out.package == "com.demo.app", out.package)
    check("外部存档：保留采集端写下的收尾记录",
          "采集端已卸载" in str(out.teardown.get("note") or ""), out.teardown)

    # 存档不存在 → 明确失败，不许"照常出报告"
    out2, _ = _run_job(JobOptions(scan_result_path="/nonexistent/scan.result.json"))
    check("外部存档：文件不存在时明确失败",
          out2.ok is False and "找不到采集结果" in (out2.error or ""), out2.error)

    # 存档没有包名、也没给 APK → 明确失败（缺包名的报告无法关联到被测对象）
    with _tf.TemporaryDirectory() as sdir:
        np_file = Path(sdir) / "scan.result.json"
        np_file.write_text(_json.dumps({"events": []}), encoding="utf-8")
        out3, _ = _run_job(JobOptions(scan_result_path=str(np_file)))
    check("外部存档：缺包名时明确失败",
          out3.ok is False and "包名" in (out3.error or ""), out3.error)

    # ---------------- 存档必须能独立支撑离线重跑 ----------------
    _archive_roundtrip(check)


def _archive_roundtrip(check) -> None:
    """采集存档要带 static / teardown，否则离线重跑等于换了一份报告。

    实测教训（以观书法 5.4.2，2026-10-20）：存档里没有 `static`，
    `run_flow.py --from-result` 渲染时 P0 整段空掉 —— 22 项里丢掉 10 项判定，
    剩下的也退化成"跳过未测"；同一份采集、同一台机器，结论却和原始作业对不上。
    存档不能自证，复核就无从谈起。
    """
    import json as _json
    from dataclasses import dataclass, field as _field
    from piiscan import apkstatic
    from piiscan.config import AppConfig
    from piiscan.sop_job import JobOptions, run_job

    # 用 dataclass 造桩：真实的 apkstatic.StaticResult 就是 dataclass，**没有 to_dict**。
    # 早先这里写成"有 to_dict 就调"，存档里于是静默没有 P0 —— 测试必须踩同一条路径。
    @dataclass
    class _St:
        package: str = "com.demo.app"
        app_label: str = "测试App"
        version_name: str = "1.0"
        permissions: list = _field(default_factory=lambda: ["android.permission.CAMERA"])
        sdks: list = _field(default_factory=list)
        jiagu: list = _field(default_factory=list)
        policy_assets: list = _field(default_factory=list)

    calls = []
    _saved_an = apkstatic.analyze
    apkstatic.analyze = lambda *a, **k: _St()
    restore = _patch_job_deps(_fake_scan(), calls)
    data = {}
    try:
        with tempfile.TemporaryDirectory() as td:
            apk = Path(td) / "demo.apk"
            apk.write_bytes(b"PK\x03\x04fake")
            run_job("JARC", td, JobOptions(package="com.demo.app", apk_path=str(apk),
                                           dynamic=True, duration=10),
                    AppConfig(), log=lambda *_a: None)
            p = Path(td) / "scan.result.json"
            if p.exists():
                data = _json.loads(p.read_text(encoding="utf-8"))
    finally:
        restore()
        apkstatic.analyze = _saved_an

    check("存档存在", bool(data), data and list(data.keys())[:6])
    check("存档含静态分析", bool(data.get("static")), list(data.keys())[:8])
    check("存档含收尾卸载记录", bool(data.get("teardown")), data.get("teardown"))
    check("存档里的静态分析带包名",
          (data.get("static") or {}).get("package") == "com.demo.app",
          (data.get("static") or {}).get("package"))

    # 能被离线入口原样读回来（这是 --from-result 的第一步）
    from piiscan.collector import ScanResult
    _ok = True
    try:
        sr = ScanResult.from_dict(data)
        _ok = sr.package == "com.demo.app"
    except Exception as e:      # noqa: BLE001
        _ok = False
        check("存档可被离线入口反序列化", False, str(e))
    if _ok:
        check("存档可被离线入口反序列化", True)
