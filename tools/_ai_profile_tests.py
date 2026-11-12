"""AI 模型服务配置档案 + 「停止」打断模型调用 的用例（2026-11-12）。

用户原话两段：
  · "运行过程中 AI 的 api 突然断了，我一开始点了几次停止没反应……
    你要么强化一下『停止』功能，让停止响应更加及时。"
  · "本地 ai 的 api 不要写死在配置里，这个允许用户自定义 api 的配置……
    增加一项使用 deepseek API 的选项……把 AI 的 API 配置调整到『系统状态』页面。"

这里守的是几件"说错就会误导人"的事：

1. **密钥不回传**。列表接口只给 `has_key` 与末四位，完整密钥不出服务端。
   把密钥回传给浏览器，等于让任何能打开这个页面的人都拿到它。
2. **留空 ≠ 清空**。编辑时留空表示"不修改已保存的密钥"；只有显式传空串才清掉。
   这两者混了，改个名字就会把密钥删掉，下次调用才报 401。
3. **删掉正在用的那份 = AI 关闭**，必须如实告知（而不是静默变成"没配置"）。
4. **停止要能打断在途的模型调用**。这是本轮报障的根因：`should_stop()` 只在
   两次调用之间检查，而单次调用最长 180 秒、分段还会并发 4 路。
5. **视觉能力按模型区分，不按厂商**。初版我写死"DeepSeek 不支持图片"，是错的：
   官方文档里 `deepseek-flash` 有 Vision、`deepseek-v4-pro` 没有。整家标成 False
   会让能看图的模型白白用不上；整家标成 True 又会让 v4-pro 每次带图 400 再静默
   回退。所以这里守的是"带图调用一定落到 deepseek-flash"。
"""
from __future__ import annotations

import re
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "webapp" / "static" / "index.html"
SERVER = ROOT / "webapp" / "server.py"


def _html() -> str:
    return HTML.read_text(encoding="utf-8")


def _src() -> str:
    return SERVER.read_text(encoding="utf-8")


def _db():
    from webapp.db import JobDB
    return JobDB(Path(tempfile.mkdtemp(prefix="ai_pf_")) / "jobs.db")


# ------------------------------------------------------------------ 档案增删改
def _t_profiles_db(check):
    db = _db()
    pid = db.ai_profile_save(name="本机 Ollama", provider="ollama",
                             base_url="http://127.0.0.1:11434",
                             model="qwen2.5:7b", api_key="sk-1234567890")
    check("新建档案返回 id", bool(pid) and pid.startswith("ai"), pid)
    items = db.ai_profiles()
    check("档案能列出来", len(items) == 1 and items[0]["name"] == "本机 Ollama", items)
    check("密钥存在库里（服务端可用）",
          items[0]["api_key"] == "sk-1234567890", items[0].get("api_key"))

    # 改个名字，不传 api_key → 密钥必须还在
    db.ai_profile_save(pid=pid, name="本机 Ollama（改）", provider="ollama",
                       base_url="http://127.0.0.1:11434", model="qwen2.5:7b")
    p = db.ai_profile(pid)
    check("编辑时不传 api_key → 保留旧密钥（留空≠清空）",
          p["api_key"] == "sk-1234567890", p.get("api_key"))
    check("编辑生效", p["name"] == "本机 Ollama（改）", p.get("name"))

    # 显式传空串 → 清掉
    db.ai_profile_save(pid=pid, name="本机 Ollama（改）", provider="ollama",
                       base_url="", model="qwen2.5:7b", api_key="")
    p = db.ai_profile(pid)
    check("显式传空串 → 清空密钥", p["api_key"] == "", repr(p.get("api_key")))

    # last_used_at 只由 ai_touch 写
    check("新建档案 last_used_at 为空（没跑过就是没跑过）",
          not db.ai_profile(pid).get("last_used_at"),
          db.ai_profile(pid).get("last_used_at"))
    db.ai_touch(pid)
    check("ai_touch 会写 last_used_at", bool(db.ai_profile(pid).get("last_used_at")), "")

    # 启用 / 停用
    db.ai_set_active(pid)
    check("启用后 ai_active_id 指向它", db.ai_active_id() == pid, db.ai_active_id())
    db.ai_set_active("")
    check("传空串＝停用全部", db.ai_active_id() == "", db.ai_active_id())
    try:
        db.ai_set_active("nope")
        check("启用不存在的档案要报错", False, "没有抛异常")
    except ValueError as e:
        check("启用不存在的档案要报错", "不存在" in str(e), str(e))

    # 删除正在用的那份
    db.ai_set_active(pid)
    r = db.ai_profile_delete(pid)
    check("删除返回 ok 并标记 was_active", r.get("ok") and r.get("was_active"), r)
    check("删掉正在用的那份后 active 变空（AI 关闭，不是静默降级）",
          db.ai_active_id() == "", db.ai_active_id())
    r2 = db.ai_profile_delete(pid)
    check("删已删除的档案 → 明确报错（不是静默成功）",
          not r2.get("ok") and "不存在" in (r2.get("error") or ""), r2)


# ------------------------------------------------------- 档案 → AIConfig 覆盖
def _t_apply_profile(check):
    import webapp.server as S
    from piiscan.config import AppConfig

    db = _db()
    # 没有启用任何档案 → 一点都不能改
    cfg = AppConfig()
    cfg.ai.provider = "ollama"
    cfg.ai.model = "keep-me"
    name = S.apply_ai_profile(db, cfg)
    check("未启用档案时不改配置", name == "" and cfg.ai.model == "keep-me",
          (name, cfg.ai.model))

    pid = db.ai_profile_save(name="DeepSeek", provider="deepseek",
                             base_url="", model="deepseek-flash", api_key="sk-x")
    db.ai_set_active(pid)
    cfg2 = AppConfig()
    cfg2.ai.provider = "ollama"
    cfg2.ai.model = "qwen2.5:7b"
    name = S.apply_ai_profile(db, cfg2)
    check("启用后 provider 被档案覆盖", cfg2.ai.provider == "deepseek", cfg2.ai.provider)
    check("启用后 model 被档案覆盖", cfg2.ai.model == "deepseek-flash", cfg2.ai.model)
    check("启用后 api_key 被档案覆盖", cfg2.ai.api_key == "sk-x", cfg2.ai.api_key)
    check("返回档案名（写进任务日志）", name == "DeepSeek", name)

    # ollama 空地址要回填默认端口：报告/日志里不能显示空地址
    db2 = _db()
    pid2 = db2.ai_profile_save(name="本机", provider="ollama", base_url="",
                               model="qwen2.5:7b")
    db2.ai_set_active(pid2)
    cfg3 = AppConfig()
    S.apply_ai_profile(db2, cfg3)
    check("ollama 空地址回填默认端口",
          cfg3.ai.base_url == "http://127.0.0.1:11434", cfg3.ai.base_url)

    # 顺序：apply_ai_profile 必须在 apply_ai_opts 之后调用
    src = _src()
    i_opts = src.find("apply_ai_opts(cfg, job, log)")
    i_prof = src.find("apply_ai_profile(self.db, cfg, log)", i_opts)
    check("AI 档案在任务级选项之后应用（档案优先，老任务里的旧地址不生效）",
          i_opts > 0 and i_prof > i_opts, (i_opts, i_prof))


def _t_seed(check):
    import webapp.server as S
    db = _db()
    # 自己造一份临时配置，显式传给迁移函数 —— 不读仓库里的 config.yaml。
    # （发布出去的干净树里没有 config.yaml，用例不能依赖开发机恰好有一份。）
    tmp = Path(tempfile.mkdtemp(prefix="piiscan_seed_"))
    cfg_none = tmp / "config_none.yaml"
    cfg_none.write_text("ai:\n  provider: none\n", encoding="utf-8")
    check("provider=none 时不迁移（发布后的初始状态就该是空的）",
          S.seed_ai_profiles(db, str(cfg_none)) == "", "")

    cfg = tmp / "config.yaml"
    cfg.write_text("ai:\n  provider: ollama\n  base_url: http://127.0.0.1:11434\n"
                   "  model: qwen2.5:7b\n", encoding="utf-8")
    pid = S.seed_ai_profiles(db, str(cfg))
    check("首次启动把配置里的连接参数迁进档案表", bool(pid), pid)
    p = db.ai_profile(pid) or {}
    check("迁移后的档案是启用状态",
          db.ai_active_id() == pid, db.ai_active_id())
    check("迁移写明来源（不是凭空多出一条配置）",
          "config.yaml" in (p.get("name") or ""), p.get("name"))
    check("迁移后的连接参数与配置一致",
          p.get("provider") == "ollama" and p.get("model") == "qwen2.5:7b",
          (p.get("provider"), p.get("model")))
    again = S.seed_ai_profiles(db, str(cfg))
    check("第二次启动不重复迁移", again == "", again)


# ------------------------------------------------------------ 密钥不外泄
def _t_masking(check):
    import webapp.server as S
    p = {"id": "x1", "name": "DeepSeek", "provider": "deepseek",
         "base_url": "https://api.deepseek.com", "model": "deepseek-flash",
         "api_key": "sk-abcdefghijklmn", "created_at": 1, "updated_at": 2}
    out = S.ai_profile_out(p, "x1")
    check("视图里没有 api_key 原文字段", "api_key" not in out, sorted(out))
    check("只回传 has_key", out.get("has_key") is True, out.get("has_key"))
    check("密钥提示只露末四位",
          out.get("key_hint") == "…klmn", out.get("key_hint"))
    check("deepseek 视图标为具备视觉能力", out.get("vision") is True, out.get("vision"))
    check("active 标记正确", out.get("active") is True, out.get("active"))


# ------------------------------------------------------- 取消令牌 / 打断请求
def _t_cancel(check):
    from piiscan.ai import cancel
    from piiscan.ai.base import AIError

    cancel.disarm()
    cancel.check("测试")          # 不该抛
    check("未置位时 check 不抛", True, "")
    cancel.arm("用户请求停止")
    check("arm 后 is_set 为真", cancel.is_set(), "")
    try:
        cancel.check("AI 请求")
        check("arm 后 check 必须抛错", False, "没有抛")
    except AIError as e:
        check("arm 后 check 必须抛错", "中断" in str(e), str(e))
        check("错误里带上原因", "用户请求停止" in str(e), str(e))
    cancel.disarm()
    check("disarm 后恢复", not cancel.is_set(), "")


def _t_post_json_interrupt(check):
    """在途请求必须能被"停止"打断，而不是等满 timeout。"""
    import piiscan.ai.providers as P
    from piiscan.ai import cancel
    from piiscan.ai.base import AIError

    real = P._post_json_blocking
    P._post_json_blocking = lambda *a, **k: time.sleep(30) or {}
    try:
        cancel.disarm()
        # ① 已经置位 → 连请求都不发
        cancel.arm("用户请求停止")
        t0 = time.time()
        try:
            P._post_json("http://127.0.0.1:1/x", {}, timeout=30)
            check("已置位时立刻拒绝发起请求", False, "没有抛")
        except AIError as e:
            dt = time.time() - t0
            check("已置位时立刻拒绝发起请求", dt < 1.0, round(dt, 2))
            check("拒绝原因写明是中断", "中断" in str(e), str(e))

        # ② 请求发出后再置位 → 0.25 秒级返回
        cancel.disarm()
        threading.Timer(0.3, lambda: cancel.arm("用户请求停止")).start()
        t0 = time.time()
        try:
            P._post_json("http://127.0.0.1:1/x", {}, timeout=30)
            check("在途请求能被停止打断", False, "没有抛")
        except AIError:
            dt = time.time() - t0
            # 30 秒的 timeout 说明"没打断就会等 30 秒"
            check("在途请求能被停止打断（不等满 timeout）", dt < 2.0, round(dt, 2))

        # ③ 正常路径不受影响
        cancel.disarm()
        P._post_json_blocking = lambda *a, **k: {"ok": 1}
        check("未置位时正常返回",
              P._post_json("http://x/y", {}, timeout=5).get("ok") == 1, "")
    finally:
        P._post_json_blocking = real
        cancel.disarm()


def _t_worker_cancel_scope(check):
    """取消只能落在"当前任务"上，否则会误伤队列里的下一个任务。"""
    import webapp.server as S
    w = S.Worker.__new__(S.Worker)          # 不跑 __init__，避免起线程
    w.current_job = "J1"
    from piiscan.ai import cancel
    cancel.disarm()
    check("对非当前任务的取消不置位", w.request_cancel("J2") is False, "")
    check("非当前任务的取消没有动令牌", not cancel.is_set(), "")
    check("对当前任务的取消会置位", w.request_cancel("J1") is True, "")
    check("置位后 token 为真", cancel.is_set(), "")
    cancel.disarm()
    check("空 job_id 不置位", w.request_cancel("") is False, "")


# --------------------------------------------------------------- DeepSeek
def _t_deepseek(check):
    from piiscan.ai import factory
    from piiscan.ai.base import AIError
    from piiscan.ai.providers import DeepSeekProvider
    from piiscan.config import AIConfig

    check("factory 认得 deepseek", factory._REGISTRY.get("deepseek") is DeepSeekProvider,
          factory._REGISTRY.get("deepseek"))
    # 2026-11-12 修正：官方 FEATURES 表里 deepseek-flash 有 Vision ✓。
    # 之前写成 False 是我记错了 —— 用户当场指出来的。
    check("DeepSeek 被标为具备视觉能力（deepseek-flash 能看图）",
          DeepSeekProvider.vision is True, DeepSeekProvider.vision)

    ai = AIConfig(provider="deepseek", base_url="", model="deepseek-flash")
    p = DeepSeekProvider(ai)
    check("留空地址使用官方域名", p._base() == "https://api.deepseek.com", p._base())
    check("端点拼成 /v1/chat/completions",
          p._endpoint() == "https://api.deepseek.com/v1/chat/completions", p._endpoint())
    try:
        p._headers()
        check("没有密钥时立刻报错（而不是等 401）", False, "没有抛")
    except AIError as e:
        check("没有密钥时立刻报错（而不是等 401）",
              "密钥" in str(e) and "系统状态" in str(e), str(e))

    # ---- 带图调用必须落到 deepseek-flash ----
    from piiscan.ai.providers import OpenAICompatProvider
    check("视觉调用不再覆写（继承父类的 image_url 实现）",
          DeepSeekProvider._chat_vision is OpenAICompatProvider._chat_vision,
          DeepSeekProvider._chat_vision)
    check("默认文本模型是 deepseek-flash", p._model() == "deepseek-flash", p._model())
    check("视觉模型默认也是 deepseek-flash（能看图的那个）",
          p._model(vision=True) == "deepseek-flash", p._model(vision=True))

    # 文本用 v4-pro（推理更强）、视觉自动借 flash —— 这是最正当的配法
    ai2 = AIConfig(provider="deepseek", base_url="", model="deepseek-v4-pro",
                   vision_model="")
    p2 = DeepSeekProvider(ai2)
    check("文本模型可用 deepseek-v4-pro", p2._model() == "deepseek-v4-pro", p2._model())
    check("没填视觉模型时自动回落 deepseek-flash（否则每个带图调用都 400）",
          p2._model(vision=True) == "deepseek-flash", p2._model(vision=True))

    # 视觉模型被误填成 v4-pro：拦下来，而不是让它 400
    ai3 = AIConfig(provider="deepseek", base_url="", model="deepseek-v4-pro",
                   vision_model="deepseek-v4-pro")
    p3 = DeepSeekProvider(ai3)
    check("视觉模型误填 deepseek-v4-pro 时改用 flash",
          p3._model(vision=True) == "deepseek-flash", p3._model(vision=True))
    check("但文本调用仍尊重使用者填的 v4-pro", p3._model() == "deepseek-v4-pro", p3._model())

    # 已从官方模型表退场的旧名，改写成现名，避免撞 400
    ai4 = AIConfig(provider="deepseek", base_url="", model="deepseek-chat",
                   vision_model="deepseek-v4-flash-vision-exp")
    p4 = DeepSeekProvider(ai4)
    check("旧名 deepseek-chat 改写成 deepseek-flash",
          p4._model() == "deepseek-flash", p4._model())
    check("旧名 deepseek-v4-flash-vision-exp 改写成 deepseek-flash",
          p4._model(vision=True) == "deepseek-flash", p4._model(vision=True))

    check("provider.label 用于报告标注", p.label == "DeepSeek", p.label)
    # can_vision 是平台决定"要不要走看图环节"的闸门，必须与 provider 一致
    check("provider.vision 决定 AITasks 走不走看图环节",
          hasattr(DeepSeekProvider, "vision") and DeepSeekProvider.vision is True, "")

    # ---- 线上格式：起一个假服务，看真正发出去的报文长什么样 ----
    # 光断言 `_model(vision=True)` 不够 —— 参数对了但 content 拼错，DeepSeek 照样 400。
    _t_deepseek_wire(check)


def _t_deepseek_wire(check):
    """把请求发给本机假服务，检查 content 块、模型名、鉴权头。"""
    import base64
    import json as _json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from piiscan.ai.providers import DeepSeekProvider
    from piiscan.config import AIConfig

    got = {}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            got["path"] = self.path
            got["auth"] = self.headers.get("Authorization") or ""
            try:
                got["body"] = _json.loads(self.rfile.read(n).decode("utf-8"))
            except Exception:
                got["body"] = {}
            b = _json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ai = AIConfig(provider="deepseek", base_url="http://127.0.0.1:%d" % port,
                      model="deepseek-v4-pro", vision_model="", api_key="sk-wire")
        out = DeepSeekProvider(ai).chat_vision("这屏有没有政策链接", [b"\xff\xd8jpeg"], timeout=10)
    except Exception as e:
        srv.shutdown()
        check("视觉请求能发出去（假服务）", False, "%s: %s" % (type(e).__name__, e))
        return
    srv.shutdown()

    body = got.get("body") or {}
    check("视觉请求回得出内容", out == "ok", out)
    check("请求打到 /v1/chat/completions", got.get("path") == "/v1/chat/completions",
          got.get("path"))
    check("带 Bearer 鉴权", got.get("auth") == "Bearer sk-wire", got.get("auth"))
    check("带图的调用自动改用 deepseek-flash（文本模型是 v4-pro）",
          body.get("model") == "deepseek-flash", body.get("model"))
    content = (body.get("messages") or [{}])[-1].get("content")
    check("content 是块数组（不是纯字符串）", isinstance(content, list), type(content))
    kinds = [seg.get("type") for seg in (content or []) if isinstance(seg, dict)]
    check("有 text 与 image_url 两种块", kinds == ["text", "image_url"], kinds)
    url = ""
    for seg in content or []:
        if isinstance(seg, dict) and seg.get("type") == "image_url":
            url = (seg.get("image_url") or {}).get("url") or ""
    check("图片用 data URL 内联", url.startswith("data:image/jpeg;base64,"), url[:40])
    try:
        raw = base64.b64decode(url.split(",", 1)[1])
        check("base64 能解回原字节", raw.startswith(b"\xff\xd8"), raw[:4])
    except Exception as e:
        check("base64 能解回原字节", False, e)


# ------------------------------------------------------------ 服务端接口
def _t_endpoints(check):
    src = _src()
    check("GET /api/ai/profiles 存在", '"/api/ai/profiles"' in src, "")
    check("POST /api/ai/active 存在（启用/停用同一入口）", '"/api/ai/active"' in src, "")
    check("删除路由存在",
          "/api/ai/profiles/([A-Za-z0-9_\\-]+)$" in src, "")
    check("测试路由存在", "/(activate|test)$" in src, "")
    check("DeepSeek 没有密钥时拒绝保存",
          "DeepSeek 需要 API 密钥" in src, "")
    check("地址必须带 http(s)（防手滑写成 localhost:11434）",
          "需以 http:// 或 https:// 开头" in src, "")
    check("删掉正在用的配置要说明 AI 会关闭",
          "AI 环节全部回退到确定性策略" in src, "")
    check("服务启动时会迁移 config.yaml 的连接配置",
          "seed_ai_profiles(db)" in src, "")


def _t_stop_wiring(check):
    src = _src()
    check("停止接口返回 interrupted_ai（前端据此说『已打断模型调用』）",
          '"interrupted_ai": hit' in src, "")
    check("停止时立刻置位取消令牌（不等 worker 下一轮读库）",
          "self.worker.request_cancel(job_id)" in src, "")
    check("新任务开局复位取消令牌（上一条的停止不能连坐）",
          src.count("_ai_cancel.disarm()") >= 2, src.count("_ai_cancel.disarm()"))
    check("看门狗强制收工也会打断模型调用",
          "强制收工也意味着" in src, "")
    check("关服务时会打断在途调用（不然退出要等 90 秒）",
          'cancel.arm("服务正在停止")' in src, "")


# ------------------------------------------------------------------ 前端
def _t_frontend(check):
    h = _html()
    check("系统状态页有 AI 模型服务卡片", 'id="aiwrap"' in h and 'id="ailist"' in h, "")
    check("有「+ 添加配置」按钮", 'id="aiadd"' in h, "")
    check("有配置表单（名称/类型/地址/模型/密钥）",
          all('id="%s"' % x in h for x in
              ("f_name", "f_provider", "f_base_url", "f_model", "f_api_key")), "")
    check("接口类型里有 DeepSeek", 'value="deepseek"' in h, "")
    # 2026-11-12 修正：DeepSeek 的视觉模型框不能再藏起来。
    # 它按模型分档，正当配法是"文本 v4-pro + 视觉 flash"，藏掉就没处填。
    check("视觉模型输入框仍存在（DeepSeek 也要能填）",
          'id="f_vision_model"' in h, "")
    check("不再按接口类型隐藏视觉模型框",
          '$("#f_vision_model").closest("div")' not in h, "")
    check("预填 deepseek-flash 而不是已退场的 deepseek-chat",
          '"deepseek-flash"' in h and '"deepseek-chat"' not in h, "")
    check("界面说明里写明 v4-pro 只读文本",
          "deepseek-v4-pro" in h and "只读文本" in h, "")
    # 提示是 innerHTML 直出的，写进去的 ** 会原样显示成星号（截图里抓到过）
    check("提示文案里不留 markdown 星号",
          "图片能力**" not in _src() and "**按模型区分**" not in _src()
          and "**可能不支持图片输入**" not in _src(), "")
    check("视觉模型的括注按接口类型变（DeepSeek 不再是「沿用文本模型」）",
          'id="f_vision_opt"' in h and "能看图的只有 deepseek-flash" in h, "")

    # 新建任务页不能再有模型连接字段（否则两份配置各说各话）
    nw = h[h.find('id="page-new"'):h.find('id="page-jobs"')]
    check("新建任务页不再有接口类型下拉", 'id="ai_provider"' not in nw, "")
    check("新建任务页不再有模型地址/模型名/密钥",
          all(('id="%s"' % x) not in nw for x in
              ("ai_base_url", "ai_model", "ai_vision_model", "ai_api_key")), "")
    check("新建任务页指向系统状态页",
          "系统状态 → AI 模型服务" in nw, "")
    check("新建任务页保留 AI 环节开关",
          all(('id="%s"' % x) in nw for x in
              ("ai_policy_vision", "ai_policy_analyze", "ai_ui_agent")), "")
    check("提交时不再发送模型连接参数",
          'for (const id of ["ai_provider"' not in h, "")

    # 停止中的标记必须落在**状态列**：上一版写进了结论列，
    # 整表文本照样包含"停止中"（断言全绿），截图上一眼看出位置错了。
    check("任务行的停止标记写在状态列",
          "+stBadge+timeLines(j)+qp+stopInfo+" in h, "")
    check("停止中时徽标也换成「停止中」（不同时显示检测中）",
          'badge b-canceled">停止中' in h, "")
    check("停止中时写出「正在收尾（模型调用已打断）」",
          "正在收尾（模型调用已打断）" in h, "")
    check("停止后把按钮换成不可点的文字",
          'a === "cancel" && j.req === "cancel"' in h, "")
    check("停止后有更快的轮询（FAST_POLL）", "FAST_POLL" in h, "")
    check("停止确认框说明会打断模型调用", "模型调用会立即打断" in h, "")
    check("档案列表用事件委托（不逐行绑监听器）",
          '$("#aiwrap").addEventListener("click"' in h, "")
    check("停用全部时给出说明（AI 回退，报告照常）",
          "已停用全部 AI 配置" in _src(), "")


def run(check):
    _t_profiles_db(check)
    _t_apply_profile(check)
    _t_seed(check)
    _t_masking(check)
    _t_cancel(check)
    _t_post_json_interrupt(check)
    _t_worker_cancel_scope(check)
    _t_deepseek(check)
    _t_endpoints(check)
    _t_stop_wiring(check)
    _t_frontend(check)
