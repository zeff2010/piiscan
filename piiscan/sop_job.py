"""一条完整的检测作业：环境 → 安装 → 采集 → 卸载 → 判定 → 报告。

**为什么要从 run_flow.py 里抽出来**

    此前"跑一次检测"这件事有两套实现：
      · 命令行 run_flow.py  —— 走 SOP 九阶段，出模板化报告，结束会卸载
      · 平台 webapp/server  —— 调 piiscan/pipeline.py 的旧流水线，出另一套报告，不卸载
    两套并行最要命的不是重复代码，而是**同一个 APK 会得到两份不一样的结论**。
    使用者看到平台报告时会以为那就是 SOP 的结果，实际上不是 ——
    这种"看起来对、其实换了流程"的问题，比报错难发现得多。

    所以这里只留一条链，CLI 与平台都调它。要改流程就改这里，改一处两边同时生效。

**收尾一定要执行**

    无论成功、失败还是被取消，只要动过设备，就必须把被测应用卸掉
    （`keep_app=True` 除外）。理由不是洁癖：下一轮检测的"首启"判定
    前提就是设备上没有这个 App 的残留。中途崩了不卸，下一轮就会
    因为"App 已存在、数据不是空的"而采不到弹窗，然后被误判成"未公开收集规则"。
"""
from __future__ import annotations

import dataclasses
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

Log = Callable[[str], None]
_NOP: Log = lambda *_a, **_k: None
# 阶段进度回调：(中文阶段名, 0~100)
StageFn = Callable[[str, int], None]
# 取消回调：返回 True 表示要求停止
StopFn = Callable[[], bool]


@dataclass
class JobOptions:
    """一次检测的全部外部输入。字段与平台表单一一对应。"""
    package: str = ""
    apk_path: str = ""
    dynamic: bool = True
    duration: int = 90
    policy_wait: int = 22
    reset_app: bool = True
    keep_app: bool = False          # True = 测完不卸载（人工要接着复现时用）
    mode: str = "expert"
    do_repro: bool = False
    # ---- 登录辅助 ----
    # 测试手机号由检测人员提供（平台表单里填）。给了就在遍历遇到登录页时代填，
    # 短信验证码由人在平台上回填（写进工作目录的 sms.txt，脚本轮询读取）。
    # 空字符串 = 不做登录，遍历只覆盖游客可见的界面。
    login_phone: str = ""
    login_timeout: int = 180
    # 检测档位：pre（1 档仅同意前，约 7 分钟）/ light（2 档 15 分钟、不登录、只到二级）
    # / deep（3 档 60 分钟、可登录、层级不限）。
    # normal 是历史档（约 1.5 分钟），保留只为读得懂旧任务与旧存档。
    # 旧写法 "4" / "extreme" 仍可传入，归一为 deep（见 config._DEPTH_ALIASES）。
    depth: str = "normal"
    # 提交时直接给的政策正文 / 链接。平台表单里这两项一直存在（而且文案写着
    # "优先级最高"），但 JobOptions 里没有对应字段、链路也没接 —— 用户粘了
    # 一整篇政策，实际走的还是空正文，报告写成"未能取得隐私政策正文"。
    # 服务器部署（无设备、抓不到首启弹窗）时这是**唯一**的政策来源。
    policy_url: str = ""
    policy_text: str = ""
    # 外部采集结果（scan.result.json）。给了就不做设备采集 —— 采集在接了
    # 测试机的那台机器上跑，判定与出报告在这台机器上跑。
    #
    # ★ 为什么需要这条：手机能不能被这台机器枚举，取决于 USB 直通/驱动，
    #   而判定与报告只依赖采集存档。把两者绑死会让"采集不可用"直接等于
    #   "平台不可用"；拆开后，服务器就算一台设备都没有，也能出具完整报告
    #   （报告里的事实来自存档，而不是来自这台机器的设备）。
    scan_result_path: str = ""
    report_name: str = "report.html"    # 报告文件名（在 workdir 下）
    flow_name: str = "flow.json"        # 流程存档文件名
    # 报告头信息（模板里要填的应用软件信息）
    app_name: str = ""
    version: str = ""
    market: str = ""
    operator: str = ""
    published: str = ""


@dataclass
class JobOutcome:
    ok: bool = False
    canceled: bool = False
    error: str = ""
    package: str = ""
    app_name: str = ""
    version: str = ""
    report_path: str = ""
    flow_path: str = ""             # 流程存档（*.json，供 --from-result 重渲染）
    scan_path: str = ""             # 采集存档（*.result.json）
    # 这一轮**实际**用的设备序列号（auto 选机时由采集层回填）。
    # ★ 平台要拿它做两件事：标"这台机已 root（验证过）"、查设备是否还在线。
    #   2026-11-11 之前平台读的是 `res.device_serial`，而 JobOutcome 根本没这个字段
    #   → getattr 拿到空串 → "跑完就记下已 root"这段从来没执行过，
    #   设备卡永远显示「su 可用（未验证）」，把验证过的结论说成没验证。
    device_serial: str = ""
    stats: Dict[str, int] = field(default_factory=dict)
    phases: List[Dict[str, Any]] = field(default_factory=list)
    teardown: Dict[str, Any] = field(default_factory=dict)
    preflight: Dict[str, Any] = field(default_factory=dict)
    aborted: bool = False           # 采集被中断（数据不完整）
    # 「App 是否真的跑起来了」：state=ok/no_ui/no_app，带屏数与原因。
    # run_failed=True 时平台应把任务记为失败而不是完成。
    run_health: Dict[str, Any] = field(default_factory=dict)
    run_failed: bool = False
    started_at: float = 0.0
    ended_at: float = 0.0

    @property
    def elapsed(self) -> float:
        return max(0.0, (self.ended_at or time.time()) - (self.started_at or time.time()))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok, "canceled": self.canceled, "error": self.error,
            "package": self.package, "app_name": self.app_name, "version": self.version,
            "report_path": self.report_path, "flow_path": self.flow_path,
            "scan_path": self.scan_path, "stats": dict(self.stats),
            "device_serial": self.device_serial,
            "phases": list(self.phases), "teardown": dict(self.teardown),
            "preflight": dict(self.preflight), "aborted": self.aborted,
            "run_health": dict(self.run_health), "run_failed": self.run_failed,
            "elapsed": round(self.elapsed, 1),
        }


class _Stopped(Exception):
    """内部用：在阶段边界检测到停止请求。"""


def _check(stop: Optional[StopFn], what: str) -> None:
    if stop is None:
        return
    try:
        if stop():
            raise _Stopped(what)
    except _Stopped:
        raise
    except Exception:
        pass


def _phase(out: JobOutcome, name: str, t0: float, ok: bool = True, note: str = "") -> None:
    out.phases.append({
        "phase": name, "ok": ok, "seconds": round(time.time() - t0, 1), "note": note,
    })


# 4~8 位连续数字，两侧不能再接数字 —— 11 位手机号因此不会被误当成验证码。
_SMS_CODE_RE = re.compile(r"(?<!\d)(\d{4,8})(?!\d)")


def _parse_sms(raw: str) -> str:
    """从 sms.txt 的内容里取出验证码。

    检测人员可能只贴一串数字，也可能把整条短信原文粘进来（"【XX】您的验证码
    是 382910，5 分钟内有效"）。两种都要认，但**优先认"验证码"字样后面的数字**，
    因为整条短信里常常还有发送方号码、时间、金额等其它数字。
    """
    txt = (raw or "").strip()
    if not txt:
        return ""
    if re.fullmatch(r"\d{4,8}", txt):
        return txt
    # 整段只有数字和空白（常见于从短信里复制时带上了换行/空格）：
    # 先把空白去掉再认，否则 "3829 10" 会被切成 "3829" 交上去。
    if re.fullmatch(r"[\d\s]{4,12}", txt):
        flat = re.sub(r"\s", "", txt)
        if re.fullmatch(r"\d{4,8}", flat):
            return flat
    for m in re.finditer(r"(?:验证码|校验码|动态码|激活码|code)[^0-9]{0,16}(\d{4,8})",
                         txt, re.I):
        return m.group(1)
    m = _SMS_CODE_RE.search(txt)
    return m.group(1) if m else ""


def _sms_getter(wd: Path, should_stop: Optional[StopFn] = None,
                log: Log = _NOP) -> Callable[[], str]:
    """返回"取短信验证码"的回调，供采集侧登录辅助轮询。

    ★ 为什么走文件而不是查库
      验证码由检测人员在平台页面上回填，平台把它写进本任务工作目录的
      sms.txt；采集线程隔几秒读一次，取到就删。走数据库得把这次读取塞进
      SQLite 的写事务，一轮几十次轮询会把库打成热表，还会和任务状态更新
      抢锁；而这条链路失败的代价只是"这一次没登上"，不值得。

    ★ 用过即删
      验证码一次性。文件留着，下一次登录辅助（遍历中途掉登录再登）会读到
      同一条已失效的码，然后失败并在报告里写成"登录失败"——把环境问题写成
      了 App 问题。删掉才能区分"没给我码"和"给我的码过期了"。

    ★ 取不到不算错
      超时返回空串，调用方按"未完成登录"处理，报告写"未能登录，遍历仅覆盖
      游客可见界面"。绝不因为拿不到验证码就中断整轮采集。
    """
    path = Path(wd) / "sms.txt"
    state = {"asked": False}

    def _get() -> str:
        try:
            if should_stop is not None and should_stop():
                return ""
        except Exception:
            pass
        if not state["asked"]:
            state["asked"] = True
            log("[*] 需要短信验证码：请把收到的验证码写入 %s" % path)
        try:
            if not path.exists():
                return ""
            raw = path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            log("[!] 读取验证码文件失败：%s" % e)
            return ""
        code = _parse_sms(raw)
        if not code:
            return ""
        try:
            path.unlink()
        except Exception:
            pass
        log("[+] 已取到短信验证码，继续登录")
        return code

    return _get


def apply_depth_budget(scan_cfg: Any, depth: str = "", duration: int = 0,
                       log: Log = _NOP) -> str:
    """按检测深度档设定采集预算，返回实际生效的档位。

    ★ 深度档（light / deep）**不用**调用方给的时长
      否则会出现最难解释的一种结果：用户选了"3 档"、表单里还留着默认 90 秒，
      最后按 90 秒跑完，报告却写着全功能 —— 看起来测过，其实只点了首屏。
      常规档保留"手填时长覆盖档位"的自由度（临时想跑 5 分钟时用得上）。

    ★ 三档（2026-11-19）：pre / light / deep。
      1 档只测同意前（7 分钟），2 档同意后 15 分钟且不登录、只点二级，
      3 档 60 分钟尽量走全功能（可登录）。原 3 档（15 分钟）取消，
      原 4 档改为新的 3 档；旧写法 4 / extreme 由别名表归一。
    """
    from .config import DEPTH_LABELS as _LABELS

    _d = scan_cfg.apply_depth(depth or getattr(scan_cfg, "depth", "normal"))
    _name = _LABELS.get(_d, _d)
    if _d == "normal":
        scan_cfg.duration = int(duration or scan_cfg.duration)
        log("[*] 检测深度：%s（采集 %d 秒、最多 %d 张遍历截图，权限弹窗截图另计）"
            % (_name, int(scan_cfg.duration), int(scan_cfg.max_shots)))
        return _d
    _tail = []
    if getattr(scan_cfg, "consent_only", False):
        _tail.append("取到政策正文即收工，不点同意")
    if getattr(scan_cfg, "max_depth", 0):
        _tail.append("最深只到第 %d 层" % int(scan_cfg.max_depth))
    if not getattr(scan_cfg, "login_enabled", True):
        _tail.append("不做登录")
    log("[*] 检测深度：%s（采集 %d 秒、首启观测 %d 秒、单 hook 上限 %d 条、"
        "最多 %d 张遍历截图，权限弹窗截图另计；表单里的采集时长本档不生效%s）"
        % (_name, int(scan_cfg.duration), int(scan_cfg.policy_wait),
           int(scan_cfg.max_events_per_hook), int(scan_cfg.max_shots),
           ("；" + "、".join(_tail)) if _tail else ""))
    return _d


def run_job(job_id: str, workdir: str | Path, opts: JobOptions, cfg: Any, *,
            log: Log = _NOP, on_stage: Optional[StageFn] = None,
            should_stop: Optional[StopFn] = None,
            ai_tasks: Any = None, ai: Any = None,
            on_package: Optional[Any] = None) -> JobOutcome:
    """执行一次完整检测。

    参数
    ----
    workdir   本任务的独立工作目录（报告、存档都写在这里）
    cfg       AppConfig（device / scan / ai 都在里面；调用方已按任务选项覆盖过）
    ai_tasks  AI 任务封装（可为 None —— 纯规则也能跑完，这是刻意的设计）
    ai        底层 provider（flow 层用）
    should_stop 取消回调。每个阶段边界 + 采集循环内部都会检查。
    on_stage  进度回调，用于任务看板显示真实阶段。

    返回的 JobOutcome 已经把"成功/失败/被取消"分清楚，调用方不需要再猜。
    """
    out = JobOutcome(started_at=time.time())
    # 设备序列号先按配置兜底（auto 选机时配置里是空的，等采集层回填真实值）。
    # 只认真正的序列号：`auto` / 空串都不算"这一次用了哪台机"。
    _cfg_serial = str(getattr(getattr(cfg, "device", None), "serial", "") or "").strip()
    if _cfg_serial and _cfg_serial.lower() != "auto":
        out.device_serial = _cfg_serial
    wd = Path(workdir)
    wd.mkdir(parents=True, exist_ok=True)
    log = log or _NOP

    def stage(name: str, pct: int) -> None:
        if on_stage is not None:
            try:
                on_stage(name, pct)
            except Exception:
                pass

    scan_result = None
    static_result = None
    teardown_info: Dict[str, Any] = {}
    touched_device = False
    # 是否真的去碰设备。给了外部采集存档就不碰 —— 哪怕调用方写了 dynamic=True，
    # 也不能因为"顺手跑一下"去连一台可能不存在的手机。
    do_device = bool(opts.dynamic) and not opts.scan_result_path
    if opts.dynamic and opts.scan_result_path:
        log("[*] 已提供外部采集结果，本轮跳过设备采集（run_dynamic 不生效）")

    def _restore_device(reason: str) -> None:
        """恢复测试环境：卸载被测应用。失败也要留下证据，不静默。

        ★ 幂等：取消路径会在"采集后"正常收尾里卸一次，随后 except 分支
          又会再调一次。重复卸载虽然不会出错（第二次会看到"未安装"），
          但会把第一次的真实证据（卸载前版本、设备返回原文）覆盖成
          "卸载前设备上未安装"——报告里就变成"这次没装过"，与事实相反。
        """
        nonlocal teardown_info
        if teardown_info:
            return
        if opts.keep_app:
            teardown_info = {"ok": True, "skipped": True,
                             "note": "任务配置为保留被测应用（keep_app）"}
            return
        if not touched_device or not out.package:
            return
        try:
            from . import teardown as TD
            log("[*] 收尾：卸载被测应用（%s）" % reason)
            teardown_info = TD.uninstall(
                getattr(scan_result, "device_serial", "") if scan_result else "",
                out.package, log=log)
            log("[+] 收尾：%s" % (teardown_info.get("note") or "已处理"))
        except Exception as e:
            # 卸载失败不掩盖：它直接影响下一轮能否采到"首启"
            teardown_info = {"ok": False, "note": "卸载步骤异常：%s" % e}
            log("[!] 收尾卸载失败：%s" % e)

    _screen_reset_done = False

    def _reset_screen() -> None:
        """收尾第二件事：把界面起点复位到桌面。

        ★ 卸载只解决"应用还在不在"，不解决"屏幕停在哪"。
          2026-10-26 实测：复现轮重放点了首页页脚的「备案号:皖ICP备…」，
          系统浏览器被拉起，两次返回退不掉 → 复现中止，但任务照样判成功，
          **设备就那样留在浏览器里交给下一个任务**。下一个任务的首启观测会
          拍到上一个 App 的浏览器页面，而人看到的现象是"卡着浏览器不走了"，
          很容易被当成 USB / adb 故障（那次自检失败确实另有原因）。
        ★ 判据用包名分类，不用"看起来像不像桌面"：前台是桌面就不动，
          是被测应用也不动（keep_app 时要留在原地），其余一律按 HOME。
        """
        nonlocal _screen_reset_done
        if _screen_reset_done:
            return
        _screen_reset_done = True
        # 纯离线重渲染（--from-result）不碰设备：存档里带着 serial，
        # 但此刻那台手机可能压根没连，不能因为"顺手"去 home 一下。
        if not do_device:
            return
        try:
            from . import uiwalk as UW
            serial = getattr(scan_result, "device_serial", "") or ""
            if not serial:
                return
            fg = UW.current_package(serial) or ""
            if not fg or fg == (out.package or ""):
                return
            kind = ""
            try:
                from .flow import foreign as _F
                kind = _F.classify(fg, app_package=out.package or "").get("kind") or ""
            except Exception:
                kind = ""
            if kind == "launcher":
                return
            UW.home(serial)
            time.sleep(1.0)
            if teardown_info:
                # 只在已有收尾记录上加字段，不凭空造一个"收尾成功"的对象
                teardown_info["screen_reset"] = fg
            log("[*] 收尾：界面原停在 %s，已按 HOME 复位到桌面"
                "（下一个任务从干净界面开始）" % fg)
        except Exception as e:
            log("[!] 收尾复位界面失败（不影响结论）：%s" % e)

    try:
        # ---------------- 0. APK 与静态分析 ----------------
        stage("静态分析", 3)
        t = time.time()
        if opts.apk_path:
            from . import apkstatic
            static_result = apkstatic.analyze(opts.apk_path, log=log)
            out.package = getattr(static_result, "package", "") or opts.package
            out.app_name = opts.app_name or getattr(static_result, "app_label", "") or ""
            out.version = opts.version or getattr(static_result, "version_name", "") or ""
            _phase(out, "静态分析", t)
            log("[*] 静态分析：%s %s（%s）"
                % (out.app_name or "(未知名)", out.version or "?",
                   out.package or "(未取到包名)"))
        else:
            out.package = opts.package
            _phase(out, "静态分析", t, ok=False, note="未提供 APK，跳过")
            log("[*] 未提供 APK，跳过静态分析（仅做动态采集）")

        # 把包名尽早交给调用方：看门狗"强制停止"要靠它 `am force-stop` ——
        # 卡死的进程只能靠杀进程解开（frida 同步调用没有超时，见 frida_guard）。
        if on_package is not None and out.package:
            try:
                on_package(out.package)
            except Exception:
                pass

        _check(should_stop, "静态分析后")

        # ---------------- 0.5 外部采集结果 ----------------
        # 采集端（接了测试机的那台机器）跑 run_scan 产出 scan.result.json，
        # 拷到这台机器上，这里直接载入 —— 不做预检、不碰设备。
        if opts.scan_result_path:
            t = time.time()
            stage("载入采集结果", 14)
            sp = Path(opts.scan_result_path)
            if not sp.exists():
                raise RuntimeError("找不到采集结果：%s" % sp)
            try:
                data = json.loads(sp.read_text(encoding="utf-8"))
            except Exception as e:
                raise RuntimeError("采集结果不是合法 JSON：%s（%s）" % (sp.name, e))
            from .collector import ScanResult

            # ★ 包名必须在建对象之前就查。ScanResult 的 package 是必填位置参数，
            #   缺了会抛一句 "missing 1 required positional argument" —— 那是对着
            #   代码结构说的话，不是对着人说的话，看到的人只会去翻源码。
            if not (data.get("package") or "").strip():
                raise RuntimeError(
                    "采集结果缺少 package 字段（%s）：取不到被测 App 的包名，"
                    "无法确定被测对象。"
                    "请用采集端的 run_scan / run_flow 产出完整存档，"
                    "或同时提供 APK 与 --package" % sp.name)
            try:
                scan_result = ScanResult.from_dict(data)
            except Exception as e:
                # 存档字段对不上就不要硬跑：判定层拿不到事件只会全部"跳过未测"，
                # 报告看起来像"这个 App 很干净"，是最危险的假阴性。
                raise RuntimeError("采集结果结构不符（%s）：%s" % (sp.name, e))
            teardown_info = data.get("teardown") or {}
            if not static_result:
                static_result = data.get("static") or None
            out.package = out.package or (data.get("package")
                                          or getattr(scan_result, "package", "") or "")
            if not out.app_name:
                out.app_name = ((static_result or {}).get("app_label") or "")
            # 存档复制进工作目录：报告目录必须自洽，不能只指着一个外部路径 ——
            # 底稿归档后外部路径很可能已经不在了。
            try:
                dst = wd / "scan.result.json"
                if sp.resolve() != dst.resolve():
                    dst.write_text(json.dumps(data, ensure_ascii=False, indent=1),
                                   encoding="utf-8")
                out.scan_path = str(dst)
            except Exception as e:
                log("[!] 采集存档复制失败（不影响判定）：%s" % e)
            _evs = list(getattr(scan_result, "events", None) or [])
            _post = [e for e in _evs if not getattr(e, "before_consent", False)]
            _phase(out, "导入采集结果", t,
                   note="事件 %d 条（同意后 %d）%s"
                        % (len(_evs), len(_post),
                           "；存档标记为中断，数据不完整"
                           if getattr(scan_result, "aborted", False) else ""))
            log("[*] 已载入采集结果：事件 %d 条（同意后 %d），采集设备 %s"
                % (len(_evs), len(_post),
                   getattr(scan_result, "device_serial", "") or "(存档未记录)"))
            if getattr(scan_result, "aborted", False):
                log("[!] 该存档标记为「采集中断」，数据不完整；"
                    "结论只能用于初筛，不能作为认定依据")
            if not teardown_info:
                teardown_info = {"ok": True, "skipped": True,
                                 "note": "本轮未在本机执行采集，收尾卸载由采集端完成"}
            out.teardown = teardown_info

        if not out.package and (do_device or opts.scan_result_path):
            raise RuntimeError("取不到目标包名：请提供 APK、显式指定包名，"
                               "或提供带 package 字段的采集结果")

        # ---------------- 1. 环境自检 ----------------
        t = time.time()
        if do_device:
            stage("环境自检", 6)
            from . import preflight as PF
            pf = PF.run(cfg, log=log, apk_path=opts.apk_path, auto_fix=True,
                        need_device=True)
            out.preflight = pf.to_dict()
            for line in pf.brief():
                log("[自检] " + line)
            if not pf.ok:
                # ★ 这里必须硬失败。环境没准备好就开跑，结果会是一条事件都没有，
                #   而报告上看起来像"这个 App 很干净"—— 是最危险的假阴性。
                raise RuntimeError("环境自检未通过：%s" % pf.summary())
            log("[+] %s" % pf.summary())
            _phase(out, "环境自检", t)
        else:
            _phase(out, "环境自检", t, ok=False, note="未启用动态采集")

        # ---------------- 2. 设备动态采集 ----------------
        if do_device:
            _check(should_stop, "环境自检后")
            stage("设备动态采集", 20)
            t = time.time()
            from . import collector
            cfg.scan.package = out.package
            apply_depth_budget(cfg.scan, opts.depth, int(opts.duration or 0), log)
            cfg.scan.reset_app = bool(opts.reset_app)
            touched_device = True

            def _scan_stage(name: str, pct: int) -> None:
                # 采集内部进度映射到 20~80，避免跳回前面
                stage(name, 20 + int(pct * 0.6))

            # ★ 静态分析挑出来的政策链接先交给采集端。
            #   有 URL 就能一次 HTTP 拿到完整全文，省掉"点入口 → 下钻 →
            #   一屏屏上滑读"这整段最贵的开销（用户 2026-10-21 的第一条意见）。
            #   抓不到会自动退回界面采集，不影响既有行为。
            _static_urls: List[str] = []
            _builtin: Dict[str, Any] = {}
            try:
                if static_result is not None:
                    from . import policy as _P
                    _static_urls = list(_P.candidate_urls(static_result) or [])
                    # ★ 安装包里已有一份像样的政策全文时，交给采集端：
                    #   界面侧就不必再一屏屏滑动去"读"同一份文档了
                    #   （金考典 2026-10-28：界面上滑出 844 字，包里是 8422 字）。
                    for _a in (getattr(static_result, "policy_assets", None) or []):
                        if not isinstance(_a, dict) or _a.get("role") == "prompt_config":
                            continue
                        _t = str(_a.get("text") or "").strip()
                        if len(_t) < 300 or _P._text_quality(_t) < 0.98:
                            continue
                        if not _P.looks_like_privacy_policy(_t):
                            continue
                        if len(_t) > len(_builtin.get("text") or ""):
                            _builtin = {"path": str(_a.get("path") or ""), "text": _t}
            except Exception:
                _static_urls = _builtin = {}
            if _static_urls:
                log("[*] 静态分析给出 %d 个政策候选链接，采集端将优先按链接取全文"
                    % len(_static_urls))
            if _builtin:
                log("[*] 安装包内含政策全文 %d 字（%s），界面侧将只取证据、不滑动通读"
                    % (len(_builtin["text"]), _builtin["path"]))

            scan_result = collector.run_scan(
                cfg, log=log,
                apk_path=opts.apk_path,
                reset_app=bool(opts.reset_app),
                policy_urls=_static_urls,
                builtin_policy=_builtin or None,
                policy_wait=int(opts.policy_wait or cfg.scan.policy_wait),
                ai_tasks=ai_tasks,
                should_stop=should_stop,
                on_stage=_scan_stage,
                login_phone=str(opts.login_phone or ""),
                get_sms_code=_sms_getter(wd, should_stop, log),
                login_timeout=int(opts.login_timeout or cfg.scan.login_timeout),
            )
            post = [e for e in (scan_result.events or [])
                    if not getattr(e, "before_consent", False)]
            # 采集层才知道 auto 最终选了哪台：以它为准，覆盖配置里的兜底值。
            if getattr(scan_result, "device_serial", ""):
                out.device_serial = scan_result.device_serial
            _phase(out, "设备动态采集", t,
                   note="事件 %d 条（同意后 %d）%s"
                        % (len(scan_result.events or []), len(post),
                           "；本轮被中断，数据不完整" if scan_result.aborted else ""))
            log("[*] 采集完成：事件 %d 条，截图 %d 张，点击 %d 次"
                % (len(scan_result.events or []),
                   len(scan_result.screenshots or []), scan_result.ui_taps or 0))

            # ★ 存档要在卸载之前落盘：卸载只影响设备，不影响这份样本。
            #   若放在卸载之后，卸载一旦抛异常，十几分钟的采集就白丢了。
            try:
                sp = wd / "scan.result.json"
                sp.write_text(json.dumps(scan_result.to_dict(), ensure_ascii=False,
                                         indent=1), encoding="utf-8")
                out.scan_path = str(sp)
                log("[*] 采集存档：%s" % sp.name)
            except Exception as e:
                log("[!] 采集存档失败（不影响后续判定）：%s" % e)

            # ---------------- 3. 收尾：恢复测试环境 ----------------
            stage("收尾卸载", 82)
            t = time.time()
            _restore_device("采集完成")
            _reset_screen()
            out.teardown = teardown_info or {}
            _phase(out, "收尾卸载", t, ok=bool(out.teardown.get("ok", True)),
                   note=out.teardown.get("note", ""))

            # ★ 静态分析与卸载结果也要落到存档里。
            #   离线重跑（`run_flow.py --from-result`）只认存档里的 `static`/`teardown`：
            #   缺 static 就等于丢掉 P0 的全部结论（权限、SDK、加固、内置政策文档），
            #   实测少 10 项判定、剩下的也多半退化成"跳过未测"。
            #   必须写在 teardown 之后 —— 卸载结果此刻才确定。
            try:
                _d = scan_result.to_dict()
                _sr = static_result
                # StaticResult 是 dataclass（没有 to_dict），与 flow 层保持同一套转换，
                # 否则存档里会静默缺掉 P0 —— 那正是这次要修的问题。
                if _sr is not None and dataclasses.is_dataclass(_sr):
                    _sr = dataclasses.asdict(_sr)
                elif hasattr(_sr, "to_dict"):
                    _sr = _sr.to_dict()
                if isinstance(_sr, dict) and _sr:
                    _d["static"] = json.loads(json.dumps(_sr, ensure_ascii=False,
                                                         default=str))
                if teardown_info:
                    _d["teardown"] = teardown_info
                (wd / "scan.result.json").write_text(
                    json.dumps(_d, ensure_ascii=False, indent=1), encoding="utf-8")
                log("[*] 存档已补入静态分析与收尾信息（离线重跑不会丢结论）")
            except Exception as e:
                log("[!] 存档补写失败（不影响后续判定）：%s" % e)

            if scan_result.aborted:
                out.canceled = True
                out.aborted = True
                out.error = scan_result.abort_reason or "任务被取消"
                out.ended_at = time.time()
                log("[*] 本轮采集被中断，不出具报告（已采数据已存档，可用于排查）")
                return out

        # ---------------- 4. 判定与报告 ----------------
        _check(should_stop, "采集后")
        stage("合规判定", 88)
        t = time.time()
        from .flow import run_flow
        from .report import sop_report

        # ---- 复现采集能力（P7 用）----
        # 流层负责判定，不碰 adb；这里把"清数据重跑一轮"包成回调交给它。
        # 拿不到设备（离线出报告 / 平台无设备）就传 None —— P7 会如实写
        # "本轮未执行自动复现"，绝不假装跑过。
        repro_runner = None
        if opts.do_repro and do_device and scan_result is not None:
            def repro_runner() -> Dict[str, Any]:     # type: ignore[misc]
                """清除应用数据 → 按首轮点击路径重放一轮 → 再次卸载。

                ★ 重跑前必须是"初始安装状态"
                  首轮结束时已卸载，这里由 run_scan 重新安装并清数据，
                  等价于"新装一台机器上的首次启动" —— 这正是问题该被复现的状态。
                ★ 走**路径重放**，不是"重新遍历"
                  首轮的 `ui_path` 记着每一步点了什么（`flow/replay.py`）。
                  复现轮照这条路径执行：不调模型、不做新决策，因此
                  ① 快（首轮每步等模型 2~3 秒，回放不花这钱）；
                  ② 可比（两轮走同一批界面，"判据没再出现"才算真未复现）。
                  首轮存档里没有路径（老版本存档 / 遍历被关掉）时退回整轮遍历，
                  并在日志里明说 —— 不能让人以为"按路径重放过了"。
                ★ 这一轮的采集存档单独落盘
                  复现轮如果采不到数据，报告要能说清"是没跑成还是没复现"，
                  存档是唯一能复查的东西。
                """
                stage("复现采集", 89)
                _path = [s for s in (getattr(scan_result, "ui_path", None) or [])
                         if isinstance(s, dict)]
                if _path:
                    log("[*] 复现：按首轮点击路径重放 %d 步（不调用模型，最多 %d 秒）"
                        % (len(_path), int(getattr(cfg.scan, "repro_duration", 120))))
                else:
                    log("[*] 复现：首轮未记录点击路径（旧存档或未启用界面遍历），"
                        "本轮退回整轮重新遍历（最多 %d 秒）"
                        % int(getattr(cfg.scan, "repro_duration", 120)))
                td: Dict[str, Any] = {}
                _dur = int(getattr(cfg.scan, "repro_duration", 120))
                _old_dur = int(getattr(cfg.scan, "duration", 90) or 90)
                try:
                    from . import collector
                    # 采集器从 cfg.scan.duration 读时长，这里临时换掉、跑完还原 ——
                    # 别把复现轮的短时长留在配置里影响下一次首轮采集。
                    cfg.scan.duration = _dur
                    sc2 = collector.run_scan(
                        cfg, log=log, apk_path=opts.apk_path,
                        reset_app=True,
                        policy_wait=int(getattr(cfg.scan, "repro_policy_wait", 20)),
                        ai_tasks=ai_tasks, should_stop=should_stop,
                        login_phone=str(opts.login_phone or ""),
                        get_sms_code=_sms_getter(wd, should_stop, log),
                        login_timeout=int(opts.login_timeout
                                          or cfg.scan.login_timeout),
                        replay_path=(_path or None),
                        # ★ 复现轮必须带首轮的政策链接。
                        #   不带的话它会退回"在界面上找政策入口"：真机实测
                        #   （mbsf15）点了 13 个采样点、花 203 秒仍没打开，
                        #   政策结论从首轮的"按链接直取 9219 字"变成
                        #   "仅取得弹窗摘要 97 字" —— 两轮条件不同，判据自然
                        #   对不上，Q007 会被误判成"未复现"而降级。
                        policy_urls=list(getattr(scan_result, "policy_urls", None)
                                         or []),
                    )
                except Exception as e:
                    return {"scan": None, "teardown": {},
                            "error": "%s: %s" % (type(e).__name__, e)}
                finally:
                    cfg.scan.duration = _old_dur
                try:
                    sp2 = wd / "scan.repro.json"
                    sp2.write_text(json.dumps(sc2.to_dict(), ensure_ascii=False,
                                              indent=1), encoding="utf-8")
                    log("[*] 复现轮采集存档：%s" % sp2.name)
                except Exception as e:
                    log("[!] 复现轮存档失败（不影响判定）：%s" % e)
                # 复现轮也装了一次应用，就必须再卸一次 —— 否则留给下一轮的
                # 就是"App 已安装、数据非空"，下一轮采不到首启弹窗。
                if not opts.keep_app:
                    try:
                        from . import teardown as TD
                        td = TD.uninstall(getattr(sc2, "device_serial", ""),
                                          out.package, log=log)
                        log("[+] 复现收尾：%s" % (td.get("note") or "已处理"))
                    except Exception as e:
                        td = {"ok": False, "note": "复现轮卸载失败：%s" % e}
                        log("[!] 复现收尾失败：%s" % e)
                return {"scan": sc2, "teardown": td, "error": ""}

        fr = run_flow(package=out.package, apk=opts.apk_path,
                      scan_result=scan_result, static_result=static_result,
                      cfg=cfg, ai=ai, ai_tasks=ai_tasks,
                      mode=opts.mode, do_repro=opts.do_repro,
                      policy_url=opts.policy_url, policy_text=opts.policy_text,
                      log=log, app_name=out.app_name, version=out.version,
                      repro_runner=repro_runner)
        fr.teardown = out.teardown
        fr.source_market = opts.market or fr.source_market
        fr.operator = opts.operator or fr.operator
        fr.published_at = opts.published or fr.published_at

        # ★ 把"判定实际使用的那份政策正文"写回采集存档。
        #   为什么（以观书法 5.4.2，2026-10-20）：界面入口点不开，政策正文是按
        #   APK 内链接在线抓的（9219 字）。若存档里没有这份正文，下次离线重渲染
        #   就得重新联网；政策页一改版，同一份底稿就复现不出同样的结论了。
        #   检验检测底稿必须能自证，所以正文要随存档一起留。
        try:
            _sp = wd / "scan.result.json"
            if _sp.exists() and getattr(fr, "policy_text", ""):
                _d = json.loads(_sp.read_text(encoding="utf-8"))
                _cap = _d.setdefault("policy_capture", {})
                _cap["bestText"] = fr.policy_text
                _cap["bestTextUrl"] = getattr(fr, "policy_url", "") or ""
                _cap["policySource"] = getattr(fr, "policy_source", "") or ""
                _cap["bestTextFrom"] = "报告判定所用（可能来自 APK 链接抓取/提交正文）"
                _sp.write_text(json.dumps(_d, ensure_ascii=False, indent=1),
                               encoding="utf-8")
                log("[*] 存档已写入判定所用的政策正文（%d 字）" % len(fr.policy_text))
        except Exception as e:
            log("[!] 政策正文补写存档失败（不影响报告）：%s" % e)

        out.stats = dict(fr.stats())
        # 把"App 到底跑起来没有"带到任务状态层：跑不起来就不算完成
        # （用户 2026-10-27 明确要求，见 models.assess_run_health）。
        out.run_health = dict(getattr(fr, "run_health", None) or {})
        out.run_failed = bool(getattr(fr, "run_failed", False))
        if out.run_failed:
            _st = out.run_health.get("state") or ""
            _probe = out.run_health.get("app_start_probe") or {}
            # ★ 顺序有讲究：先认"应用自己起不来"，再认"注入被拦"。
            #   反过来写会把小盒课堂（爱加密）那种"注入失败 + 应用本身也起不来"
            #   说成"检测手段受限"，把责任从应用挪到工具身上。
            if _st == "no_app" and _probe.get("started") is False:
                _head = "被测应用在本机无法启动"
            elif out.run_health.get("hook_blocked"):
                _head = "注入被加固拦截，动态检测未能开展"
            elif _st == "no_ui":
                _head = "应用已启动但界面无法读取"
            elif _st == "no_dump":
                _head = "应用已启动但界面结构未能导出"
            else:
                _head = "被测应用未能正常运行"
            log("[!] %s：%s —— 本轮动态检测无法开展，"
                "任务将记为失败（报告保留，用于复核原因）"
                % (_head, out.run_health.get("why") or "未取得被测应用界面内容"))
        _phase(out, "合规判定", t)

        stage("报告生成", 96)
        t = time.time()
        html = sop_report.render(fr, app_name=out.app_name, version=out.version,
                                 source_market=opts.market, operator=opts.operator,
                                 published_at=opts.published)
        rp = wd / (opts.report_name or "report.html")
        rp.parent.mkdir(parents=True, exist_ok=True)
        rp.write_text(html, encoding="utf-8")
        out.report_path = str(rp)

        # ---- 简版报告 ----
        # 与详细报告同源（都是 fr.to_dict()），只换选取哪些字段：
        # 详细版回答"结论怎么来的"，简版只给"发现 / 判定 / 截图"。
        # 失败**不影响任务**：简版是给外部看的那一份，底稿是详细报告；
        # 而且历史任务可以由服务端按 flow.json 现补，所以这里坏掉不是致命的。
        try:
            from .report import sop_brief
            bhtml = sop_brief.render_brief(
                fr.to_dict(), app_name=out.app_name, version=out.version,
                source_market=opts.market, operator=opts.operator,
                published_at=opts.published, date=time.time())
            bp = rp.with_name("report_brief.html")
            bp.write_text(bhtml, encoding="utf-8")
            log("[+] 简版报告：%s（%.0f KB）"
                % (bp.name, len(bhtml.encode("utf-8")) / 1024.0))
        except Exception as e:
            log("[!] 简版报告生成失败（不影响详细报告）：%s" % e)

        fp = wd / (opts.flow_name or "flow.json")
        fp.write_text(json.dumps(fr.to_dict(), ensure_ascii=False, indent=1),
                      encoding="utf-8")
        out.flow_path = str(fp)
        _phase(out, "报告生成", t)

        out.ok = True
        out.ended_at = time.time()
        log("[+] 报告：%s（%.0f KB）" % (rp, len(html.encode("utf-8")) / 1024.0))
        log("[+] 结论：发现问题 %d / 疑似 %d / 未发现问题 %d / 跳过未测 %d"
            % (out.stats.get("fail", 0), out.stats.get("suspect", 0),
               out.stats.get("pass", 0), out.stats.get("not_tested", 0)))
        return out

    except _Stopped as e:
        out.canceled = True
        out.error = "任务在「%s」后被取消" % str(e)
        log("[*] %s，正在恢复测试环境…" % out.error)
        _restore_device("任务取消")
        _reset_screen()
        out.teardown = teardown_info or {}
        out.ended_at = time.time()
        return out
    except Exception as e:
        out.ok = False
        out.error = "%s: %s" % (type(e).__name__, e)
        log("[!] 检测失败：%s" % out.error)
        # 失败也要把环境恢复掉 —— 否则下一轮采集会被残留数据污染
        _restore_device("任务失败")
        _reset_screen()
        out.teardown = teardown_info or {}
        out.ended_at = time.time()
        return out
