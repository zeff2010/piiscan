# -*- coding: utf-8 -*-
"""对外报告（`report_brief.html`）的回归测试。

口径（2026-10-26 定稿）：这份报告**不自称"简版"**，正文不出现「简版」
「报告类型」这类字样；必须留下的是——静态档案里的基本信息、**加固**、
**签名**，以及每个检测项的**调用栈**与**截图**。

所以测试的重点**不是好看**，而是三件事：

  ① **该有的都在**：基本信息（含加固/签名）、隐私政策链接、每个检测项的
     判定、调用栈、截图；
  ② **不该有的都没有**：复现步骤、遍历覆盖、AI 参与、法规依据句、阶段号
     —— 这些是内部底稿的内容，漏进来就等于"暴露测试过程"；
  ③ **口径变了要能重出**：老任务目录里的旧文件不能被当成新口径递给用户
     （靠文件头的口径标记判断）。

第 ② 类只能靠"断言不含某些关键词"来测，所以文案规则（`_clean`）写在
`piiscan/report/sop_brief.py` 里并单独测，避免渲染逻辑和清洗规则互相掩盖。

渲染素材直接用真实存档（`out/mbsf20/flow.json`）：它含 22 个检测项、
5 个问题项、13 张内联截图、5 条调用栈，是最能暴露"漏字段/漏清洗"的样本。
"""
from __future__ import annotations

import io
import json
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from piiscan.report.sop_brief import (BRIEF_MARKER, _clean, _first_sentence,  # noqa: E402
                                      _reason, _static_pairs, render_brief)
from webapp.db import JobDB                                                        # noqa: E402

_ok = 0
_bad = 0


def check(name: str, cond: bool, detail=""):
    global _ok, _bad
    if cond:
        _ok += 1
    else:
        _bad += 1
        print("  [FAIL] %s  %s" % (name, str(detail)[:300]))


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _http(url: str):
    try:
        with urllib.request.urlopen(url, timeout=120) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def _cd_name(headers: dict) -> str:
    cd = headers.get("Content-Disposition") or headers.get("content-disposition") or ""
    for part in cd.split(";"):
        part = part.strip()
        if part.lower().startswith("filename*=utf-8''"):
            return urllib.parse.unquote(part[len("filename*=UTF-8''"):])
    return cd


def _text(html: str) -> str:
    """HTML → 纯文本（去掉样式与 base64），用于"该不该出现"的断言。"""
    t = re.sub(r"data:image/[^\"']+", "[IMG]", html)
    t = re.sub(r"<style>.*?</style>", "", t, flags=re.S)
    t = re.sub(r"<[^>]+>", " ", t)
    t = re.sub(r"[ \t]+", " ", t)
    return t


def _sample() -> Path:
    for d in ("mbsf20", "mbsf19", "mbsf18"):
        p = ROOT / "out" / d / "flow.json"
        if p.exists():
            return p
    raise RuntimeError("找不到可用的 flow.json 素材（out/mbsf2x）")


# ------------------------------------------------------------ 单元：清洗规则
def test_clean():
    src = ("经隐私政策文本核查：政策中未见相关说明。"
           "依据《GB/T 42582-2023 信息安全技术 移动互联网应用程序(App)个人信息安全测评规范》"
           "中6.1.4.4 测评单元（PIC-22），疑似存在该情形，需人工复核确认。"
           "如需认定，应以抓包方式复核。")
    out = _clean(src)
    check("删掉法规依据句", "依据《" not in out, out)
    check("删掉复核方法建议", "如需认定" not in out, out)
    check("删掉「经…核查：」前缀", "经隐私政策文本核查" not in out, out)
    check("保留事实陈述", "政策中未见相关说明" in out, out)

    # 阶段号要删，但括号里的证据必须留下 —— 那是判定所依据的界面文字
    s2 = _clean("本次在 1 个场景中申请了权限（第 P4 阶段，弹窗前界面为「客服」）。")
    check("删掉「第 P4 阶段」", "P4" not in s2 and "第 P" not in s2, s2)
    check("保留弹窗前界面这条证据", "弹窗前界面为「客服」" in s2, s2)

    # 讲"我们做了什么"的句子删掉，App 做了什么要留
    s3 = _clean("本轮执行了设备侧首启观测（同意动作已采集），未在弹窗上点开政策页。")
    check("删掉检测动作句", "首启观测" not in s3, s3)
    check("保留结论性事实", "未在弹窗上点开政策页" in s3, s3)

    # 越界检查：不该误伤正常句子
    s4 = _clean("应用在后台读取了设备标识符 12 次，用户未被告知。")
    check("普通事实句不被误删", "读取了设备标识符 12 次" in s4, s4)

    check("首句提取", _first_sentence("第一句。第二句。") == "第一句。",
          _first_sentence("第一句。第二句。"))
    check("超长首句被截断", _first_sentence("啊" * 300, 50).endswith("…"),
          _first_sentence("啊" * 300, 50)[-6:])
    check("「跳过未测。」开头被去掉",
          _reason("跳过未测。本轮未部署流量监测。") == "本轮未部署流量监测。",
          _reason("跳过未测。本轮未部署流量监测。"))


# ------------------------------------------------------------ 渲染：内容口径
def test_render():
    data = json.loads(_sample().read_text(encoding="utf-8"))
    html = render_brief(data, date="2026-10-23")
    text = _text(html)

    # ① 基本信息和政策链接
    check("含 App 名称", "以观书法" in text, text[:200])
    check("含版本号", "5.4.2" in text)
    check("含包名", "com.ltzk.mbsf" in text)
    check("含检测日期", "2026-10-23" in text)
    check("含隐私政策链接", "https://app.ygsf.com/privacy.html" in html)
    check("政策链接可点（<a href>）",
          'href=\'https://app.ygsf.com/privacy.html\'' in html
          or 'href="https://app.ygsf.com/privacy.html"' in html)

    # ② 静态档案必留的三组：基本信息 / 加固 / 签名（2026-10-26 用户指定）
    st = data.get("static") or {}
    pairs = dict(_static_pairs(st))
    check("含 minSdk / targetSdk 行", "minSdkVersion" in text and "targetSdkVersion" in text)
    check("含权限声明规模", "权限声明" in text and "项（其中危险权限" in text)
    check("含加固信息", "加固" in text and pairs.get("加固", "")[:2] in text,
          pairs.get("加固"))
    check("含签名主体", "签名主体" in text and (pairs.get("签名主体") or "x") in text,
          pairs.get("签名主体"))
    check("含签名证书指纹", "签名证书 SHA-256" in text
          and (st.get("signature") or {}).get("sha256", "x") in text)
    check("含可调试 / 明文流量 / 允许备份",
          all(k in text for k in ("可调试", "明文流量", "允许备份")))

    # ③ 检测项：堆栈与截图都要在（用户 2026-10-26 指定）
    n_img = html.count("data:image/jpeg;base64,")
    check("截图已内嵌（>0）", n_img > 0, n_img)
    check("截图带说明文字", "附图" in text)
    n_stack = sum(1 for r in (data.get("rows") or []) if r.get("stacks"))
    check("有堆栈的检测项 > 0", n_stack > 0, n_stack)
    check("调用栈写进了正文", "调用栈 1" in text, text[:200])
    check("每条栈都给出发起点", "直接发起点" in text)
    check("每条栈都标注主体", "主体：" in text)
    # 跳过的项只在"有该项专属截图"时才挂图（阶段兜底图不算，见 2026-10-29 意见）
    def _has_own_shot(r: dict) -> bool:
        return any(str(s.get("kind") or "") != "phase" for s in (r.get("shots") or []))
    n_with_shots = sum(1 for r in (data.get("rows") or [])
                       if r.get("shots") and r.get("state") in ("fail", "suspect"))
    check("该挂图的检测项都挂上了图",
          html.count("<figure>") >= n_with_shots, html.count("<figure>"))
    check("阶段图如实标注（不等于该项专属证据）",
          "所处阶段的界面截图" in text)

    # 跳过未测项一张图都不贴（用户 2026-10-29 与 2026-10-30 两次意见）
    # 上一版只挡阶段兜底图，权限项那张 kind=perm 还留着；用户复核时仍然认为
    # "跳过未测"下面挂图是无关信息 —— 现在整段关掉，任何 kind 都不放过。
    _cards = re.split(r"<div class='item ", html)
    _skip_leak = []
    for _r in (data.get("rows") or []):
        if _r.get("state") in ("fail", "suspect") or not _r.get("shots"):
            continue
        _key = "%s. %s" % (_r.get("num"), _r.get("title"))
        for _c in _cards:
            if _key in _c[:400] and "<figure>" in _c:
                _skip_leak.append(_key)
    check("跳过项不贴任何截图（含权限弹窗图）", not _skip_leak, _skip_leak)
    check("跳过项无图时不再写「未采集到截图」",
          _text(html).count("本次自动化未采集到该项的界面截图") <=
          sum(1 for r in (data.get("rows") or [])
              if r.get("state") in ("fail", "suspect") and not r.get("shots")),
          _text(html).count("本次自动化未采集到该项的界面截图"))

    # ④ 不能出现的「简版」痕迹（用户 2026-10-26 第一条）
    for kw in ("简版", "报告类型", "详细报告", "本节从略", "为控制篇幅",
               "见同一批次的", "证据链"):
        check("正文不含「%s」" % kw, kw not in text, text[:200])
    check("标题区不含「（简版）」", "（简版）" not in html)
    check("写了口径标记（供服务端判断是否重出）", BRIEF_MARKER in html[:400], html[:80])

    # ⑤ 每类检测项都在，且带判定
    stats = data.get("stats") or {}
    check("含问题项章节", "检测发现问题" in text)
    check("含未发现问题章节", "未发现问题的检测项" in text)
    check("含跳过未测章节", "跳过未测项" in text)
    check("判定标签「发现问题」出现", "发现问题" in text)
    check("判定标签「疑似」出现", "疑似" in text)
    check("跳过项写明不作结论", "不作合规结论" in text)
    check("跳过项逐条给出未测原因", text.count("未测原因：") >= 3,
          text.count("未测原因："))

    # ⑥ 不该出现的东西（属于内部底稿）
    banned = ["复现步骤", "遍历覆盖", "AI 参与", "证据链附录",
              "依据《", "第 P4 阶段", "政策正文摘录", "行为主体归因"]
    for kw in banned:
        check("正文不含「%s」" % kw, kw not in text, text[:200])

    # ⑦ 体量与详细版对比（同一份数据）
    detail = ROOT / "out" / _sample().parent.name / "report.html"
    if detail.exists():
        check("小于详细版",
              len(html.encode()) < detail.stat().st_size,
              "%d vs %d" % (len(html.encode()), detail.stat().st_size))
    check("正文不超过 12000 字（仍远比详细版短）",
          len(re.sub(r"<details>.*?</details>", "", text, flags=re.S)) < 12000,
          len(text))

    # ⑧ 空数据不能崩
    empty = render_brief({"rows": [], "stats": {}}, app_name="空样本")
    check("空数据也能出报告", "空样本" in empty and len(empty) > 500, len(empty))
    check("空数据时如实说未发现",
          "未发现明确问题" in _text(empty), _text(empty)[:200])
    check("无静态档案时如实说明加固/签名未取得",
          "未取得" in _text(empty), _text(empty)[:300])


# ------------------------------------------------- 隐私政策一节（包内政策给全文）
def test_policy_section():
    """内置政策没有网址，简版必须把全文摆出来（用户 2026-10-29 意见）。

    用户原话：Hi投屏「简版报告说没获取隐私政策链接，不过详细版报告有内置隐私
    政策的全文」——同一次检测两份报告两种说法，交出去那份等于说"没有政策"。
    """
    from piiscan.report.sop_brief import _pick_policy_url

    body = ("【隐私政策】\n开发者：某某科技有限公司\n\n"
            "本政策仅适用于某某App提供的服务。我们如何收集您的个人信息："
            "为向您提供服务，我们会收集您的设备标识符、手机号码。\n" * 6)

    # ① 新存档：policy_refs 里有包内政策（带 path + 全文）
    d1 = {"rows": [], "stats": {},
          "policy_refs": [{"kind": "隐私政策", "path": "assets/privacy.htm",
                           "url": "", "chars": len(body), "text": body}]}
    h1 = render_brief(d1, app_name="样本A")
    t1 = _text(h1)
    check("包内政策：给出全文", "开发者：某某科技有限公司" in t1, t1[:150])
    check("包内政策：注明包内路径", "assets/privacy.htm" in t1, t1[:150])
    check("包内政策：给出字数", ("%d 字" % len(body.strip())) in t1, t1[:150])
    check("包内政策：不再说没链接", "本次未取得隐私政策链接" not in t1, t1[:200])
    check("包内政策：正文内嵌可展开", h1.count("<pre class='doc'>") == 1,
          h1.count("<pre class='doc'>"))

    # ② 旧存档：没有 policy_refs，回落到 static.policy_assets（简版是事后现渲染的）
    d2 = {"rows": [], "stats": {},
          "static": {"policy_assets": [
              {"path": "assets/vivo_private.html", "role": "policy_text", "text": body},
              {"path": "assets/lenovo_private.html", "role": "policy_text",
               "text": body.replace("某某", "另一")}]}}
    h2 = render_brief(d2, app_name="样本B")
    t2 = _text(h2)
    check("旧存档回落：仍能给出全文", "开发者：某某科技有限公司" in t2, t2[:150])
    check("旧存档回落：同类只留最长一份，不刷屏",
          h2.count("<pre class='doc'>") == 1, h2.count("<pre class='doc'>"))

    # ③ rows.links 里的来源标签不是网址，绝不能渲染成链接
    d3 = {"rows": [{"num": "1", "title": "未公开收集使用规则", "state": "pass",
                    "links": ["政策页面文本（滚动后）"]}], "stats": {}}
    check("来源标签不被当成政策地址", _pick_policy_url(d3) == "", _pick_policy_url(d3))
    h3 = render_brief(d3, app_name="样本C")
    check("渲染出的政策段不含相对链接", "href='政策页面文本" not in h3)

    # ④ 有真网址时照旧只给链接，不塞全文（读者点开就是最新版）
    d4 = {"rows": [], "stats": {}, "policy_url": "https://a.example.com/private.html"}
    h4 = render_brief(d4, app_name="样本D")
    check("有网址时给可点链接", "href='https://a.example.com/private.html'" in h4)
    check("有网址时不重复内嵌全文", h4.count("<pre class='doc'>") == 0)

    # ⑤ 一条都没有时仍如实说没取到（不许用空白糊过去）
    h5 = render_brief({"rows": [], "stats": {}}, app_name="样本E")
    check("什么都没有时如实说明", "本次未取得隐私政策链接" in _text(h5))

    # ⑥ 正文在手、但既没有包内路径也没有 http 地址（看个比赛 2026-10-29）
    #    uni-app 壳应用政策是本地页面（file:///…/__uniappview.html），
    #    上一版只收 path 非空的，这条被整条跳过 → 简版又退回"没找到政策文档"。
    d6 = {"rows": [], "stats": {},
          "policy_refs": [{"title": "隐私政策（正文）", "kind": "隐私政策",
                           "path": "", "url": "", "chars": len(body),
                           "text": body,
                           "how": "首启弹窗内《隐私政策》入口点开后从 WebView 读取"}]}
    h6 = render_brief(d6, app_name="样本F")
    t6 = _text(h6)
    check("设备侧正文：无地址也要给全文", "开发者：某某科技有限公司" in t6, t6[:150])
    check("设备侧正文：不再说没取得链接", "本次未取得隐私政策链接" not in t6, t6[:200])
    check("设备侧正文：来源不说成安装包内",
          "安装包内" not in t6 and "设备侧读取" in t6, t6[:300])
    check("设备侧正文：内嵌可展开", h6.count("<pre class='doc'>") == 1,
          h6.count("<pre class='doc'>"))

    # ⑦ 同一地址抓了两次，正文长度不同 → 只留最长的一份
    #    （国铁吉讯：P2 主政策 11935 字 + collect_documents 同链接 11212 字，
    #     开头排版不同，只按"开头 60 字"去重认不出，简版并列两条几乎一样的政策）
    d7 = {"rows": [], "stats": {},
          "policy_refs": [
              {"title": "隐私政策（正文）", "kind": "隐私政策", "url": "https://x.example.com/p.html",
               "chars": len(body), "text": body},
              {"title": "隐私政策", "kind": "隐私政策", "url": "https://x.example.com/p.html",
               "chars": len(body) - 40, "text": "另一段开头排版不同。" + body[10:]}]}
    h7 = render_brief(d7, app_name="样本G")
    check("同一地址只留一份", h7.count("<pre class='doc'>") == 1, h7.count("<pre class='doc'>"))
    check("同一地址留最长的一份", ("%d 字" % len(body.strip())) in _text(h7), _text(h7)[:300])

    # ⑧ JSON 配置接口不算政策文档（看个比赛：QQ 互联 policy_conf 返回 SDK 配置）
    from piiscan import policy as _P
    jbody = '{"Agent_ReportBatchCount":5,"Agent_ReportTimeInterval":5000,"policy":"隐私政策"}'
    check("JSON 配置不判成隐私政策",
          _P.classify_doc(jbody, "隐私政策", "https://cgi.connect.qq.com/x/policy_conf") == "other",
          _P.classify_doc(jbody, "隐私政策", "https://cgi.connect.qq.com/x/policy_conf"))
    d8 = {"rows": [], "stats": {},
          "policy_refs": [{"title": "隐私政策", "kind": "隐私政策",
                           "url": "https://cgi.connect.qq.com/x/policy_conf",
                           "chars": len(jbody), "text": jbody}]}
    h8 = render_brief(d8, app_name="样本H")
    check("JSON 配置不进简版政策表", "Agent_ReportBatchCount" not in _text(h8), _text(h8)[:200])


def test_http():
    tmp = Path(tempfile.mkdtemp(prefix="piiscanbrief-"))
    work = tmp / "plat"
    work.mkdir(parents=True, exist_ok=True)
    db = JobDB(work / "jobs.db")
    src_flow = _sample()
    src_html = src_flow.with_name("report.html")

    def make(label: str, pkg: str, *, report=True, flow=True, brief=False,
             status="done") -> str:
        jid = db.create(source="upload", apk_name=pkg + ".apk",
                        apk_path=str(work / "x.apk"), run_dynamic=False)
        wd = work / jid
        wd.mkdir(parents=True, exist_ok=True)
        rp, fp = "", ""
        if report:
            rp = str(wd / "report.html")
            if src_html.exists():
                (wd / "report.html").write_bytes(src_html.read_bytes())
            else:
                (wd / "report.html").write_text("<html><body>demo</body></html>",
                                                encoding="utf-8")
        if flow:
            fp = str(wd / "flow.json")
            (wd / "flow.json").write_bytes(src_flow.read_bytes())
        if brief and report:
            (wd / "report_brief.html").write_text("<html>预生成简版</html>",
                                                  encoding="utf-8")
        db.update(jid, status=status, app_label=label, package=pkg,
                  version_name="5.4.2", workdir=str(wd), report_path=rp,
                  result_path=fp, checked=22)
        return jid

    a = make("以观书法", "com.ltzk.mbsf")                      # 有详细缺简版 → 现补
    b = make("以观书法二号", "com.ltzk.demo", flow=False)       # 无 flow.json
    c = make("还在跑", "com.ltzk.run", report=False, flow=False, status="running")
    d = make("旧口径报告", "com.ltzk.done", brief=True)         # 有文件但缺口径标记
    e = make("现行报告", "com.ltzk.cur", brief=True)            # 有文件且口径标记一致
    (work / e / "report_brief.html").write_text(
        "<!DOCTYPE html>\n" + BRIEF_MARKER + "\n<html><body>现行口径报告</body></html>",
        encoding="utf-8")

    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "run_platform.py"), "--port", str(port),
         "--workdir", str(work), "--no-device", "--quiet"],
        cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    base = "http://127.0.0.1:%d" % port
    try:
        for _ in range(120):
            try:
                if _http(base + "/api/health")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.25)
        else:
            raise RuntimeError("测试服务未能启动：%s"
                               % proc.stderr.read().decode("utf-8", "replace")[:400])

        # ① 下载：历史任务应"现补"出来
        brief_a = work / a / "report_brief.html"
        check("任务目录初始没有报告文件", not brief_a.exists())
        st, hd, body = _http(base + "/api/jobs/%s/download?fmt=brief" % a)
        check("下载返回 200", st == 200, st)
        check("下载后文件已落盘", brief_a.exists())
        txt = body.decode("utf-8", "replace")
        check("内容含 App 名称", "以观书法" in txt)
        check("现补的那份带口径标记", BRIEF_MARKER in txt[:400], txt[:80])
        check("现补的那份不含「（简版）」", "（简版）" not in txt)
        name = _cd_name(hd)
        check("文件名含 App 名称", "以观书法" in name, name)
        # 2026-10-26：后缀改挂在详细版上，对外这份一个字都不带
        check("文件名不带「简版」", "简版" not in name, name)
        check("文件名不带任何版本后缀",
              re.search(r"_\d{8}-\d{4}\.html$", name) is not None, name)
        check("文件名以 .html 结尾", name.endswith(".html"), name)

        # ② 二次请求走已落盘的文件（不应重复渲染出错）
        st2, _h2, body2 = _http(base + "/api/jobs/%s/download?fmt=brief" % a)
        check("再次下载仍 200", st2 == 200 and len(body2) == len(body), st2)

        # ③ 预览（不触发下载）
        st3, hd3, body3 = _http(base + "/api/jobs/%s/report?brief=1" % a)
        check("预览返回 200", st3 == 200, st3)
        check("预览不带 Content-Disposition",
              not (hd3.get("Content-Disposition") or hd3.get("content-disposition")))
        check("预览内容与下载一致", body3 == body)

        # ④ 详细报告不受影响
        st4, hd4, body4 = _http(base + "/api/jobs/%s/download" % a)
        check("详细报告仍可下载", st4 == 200, st4)
        check("详细报告比这份大", len(body4) > len(body), "%d vs %d" % (len(body4), len(body)))
        check("详细报告里含调用栈等内容（两版确实不同源裁剪）",
              "调用栈" in body4.decode("utf-8", "replace"))
        name4 = _cd_name(hd4)
        check("详细版文件名带「详细版」", "详细版" in name4, name4)
        check("两版文件名不撞（一个带后缀、一个不带）", name4 != name,
              "%s / %s" % (name4, name))

        # ⑤ 缺 flow.json 又缺文件 → 409 且说清缺什么
        st5, _h5, body5 = _http(base + "/api/jobs/%s/download?fmt=brief" % b)
        check("缺流程存档时 409", st5 == 409, st5)
        msg5 = body5.decode("utf-8", "replace")
        check("提示点明缺流程存档", "流程存档" in msg5, msg5[:200])

        # ⑥ 还没跑完 → 409
        st6, _h6, _b6 = _http(base + "/api/jobs/%s/download?fmt=brief" % c)
        check("未完成的任务下载 409", st6 == 409, st6)

        # ⑦ 旧口径文件（无标记）→ 重出，不能把旧内容递给用户
        st7, _h7, body7 = _http(base + "/api/jobs/%s/download?fmt=brief" % d)
        t7 = body7.decode("utf-8", "replace")
        check("旧口径文件返回 200", st7 == 200, st7)
        check("旧口径文件被重出（旧内容不再出现）", "预生成简版" not in t7, t7[:120])
        check("重出后带现行口径标记", BRIEF_MARKER in t7[:400], t7[:80])

        # ⑧ 口径一致的文件原样用，不做无谓重渲染
        st8, _h8, body8 = _http(base + "/api/jobs/%s/download?fmt=brief" % e)
        check("现行文件直接返回", st8 == 200 and "现行口径报告" in body8.decode("utf-8", "replace"))

        # ⑨ 列表接口如实给出 has_brief
        _st, _h, lb = _http(base + "/api/jobs")
        jobs = {j["id"]: j for j in json.loads(lb)["jobs"]}
        check("列表 has_brief：现行文件为 True", jobs[e].get("has_brief") is True,
              jobs[e].get("has_brief"))
        check("列表 has_brief：现补后的为 True", jobs[a].get("has_brief") is True,
              jobs[a].get("has_brief"))
        check("列表 has_brief：缺 flow 的为 False", jobs[b].get("has_brief") is False,
              jobs[b].get("has_brief"))

        # ⑩ 批量下载
        st9, h9, zbody = _http(base + "/api/reports/zip?ids=%s,%s&fmt=brief" % (a, e))
        check("批量下载返回 200", st9 == 200, st9)
        z = zipfile.ZipFile(io.BytesIO(zbody))
        names = z.namelist()
        check("zip 里有两个报告", len([n for n in names if n.endswith(".html")]) == 2, names)
        check("包内文件名不带「简版」",
              all("简版" not in n for n in names if n.endswith(".html")), names)
        check("包内文件名含 App 名称",
              any("以观书法" in n for n in names), names)
        zname = _cd_name(h9)
        check("压缩包名不带「简版」", "简版" not in zname, zname)
        check("压缩包名是 .zip", zname.endswith(".zip"), zname)
        check("zip 里的报告可正常打开（含 html 结构）",
              z.read([n for n in names if "以观书法_" in n][0])[:60].decode(
                  "utf-8", "replace").lstrip().lower().startswith("<!doctype"))

        # ⑩b 详细版批量：包内带「详细版」、包名带「详细报告」
        st9b, h9b, zb = _http(base + "/api/reports/zip?ids=%s&fmt=html" % a)
        check("详细版批量返回 200", st9b == 200, st9b)
        names_b = zipfile.ZipFile(io.BytesIO(zb)).namelist()
        check("详细版包内文件名带「详细版」",
              all("详细版" in n for n in names_b if n.endswith(".html")), names_b)
        zname_b = _cd_name(h9b)
        check("详细版压缩包名带「详细报告」", "详细报告" in zname_b, zname_b)

        # ⑪ 批量里夹一个没有该报告的任务 → 仍 200，缺的写进说明文件
        st10, _h10, zbody10 = _http(
            base + "/api/reports/zip?ids=%s,%s&fmt=brief" % (a, b))
        check("部分缺件时整单不失败", st10 == 200, st10)
        z10 = zipfile.ZipFile(io.BytesIO(zbody10))
        note = [n for n in z10.namelist() if n.startswith("_未打包")]
        check("缺的项写进说明文件", bool(note), z10.namelist())
        if note:
            check("说明里点明缺的是哪一份",
                  "简版" in z10.read(note[0]).decode("utf-8", "replace"),
                  z10.read(note[0]).decode("utf-8", "replace")[:200])

        # ⑫ 非法 fmt 仍是 400
        st11, _h11, _b11 = _http(base + "/api/reports/zip?ids=%s&fmt=nope" % a)
        check("非法 fmt 返回 400", st11 == 400, st11)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


def main() -> int:
    test_clean()
    test_render()
    test_policy_section()
    test_http()
    total = _ok + _bad
    print("\n  简版报告：%d 项通过 / %d 项失败（共 %d）" % (_ok, _bad, total))
    return 1 if _bad else 0


if __name__ == "__main__":
    sys.exit(main())
