# -*- coding: utf-8 -*-
"""对外报告：基本信息（含加固、签名）、隐私政策链接，以及每个检测项的
「检测发现 / 检测判定 / 调用栈 / 截图」。

★ 这份报告**不自称"简版"**。正文、标题、页脚都不出现「简版」「报告类型」
  这类字样 —— 交出去的那一份就是一份报告，不必向读者交代"还有一份更全的"。
  差别只在**选取哪些字段**：不含检测过程（阶段耗时、政策取证路径、声明矩阵、
  遍历覆盖、AI 参与、复现步骤），因为这些回答的是"结论怎么来的"，
  属于内部底稿。

为什么要单独一个渲染器，而不是给详细模板加个 `brief=True` 开关：
详细报告的每一节都在回答同一个问题——**这个结论是怎么来的**。用开关控制
它们显隐，等于让两套口径挤在一个模板里，迟早会出现"某个开关忘了关、
对外版里漏出一段取证日志"这类事故。所以这里是**独立的字段选取**。

★ 哪些必须留（用户 2026-10-26 明确）：静态档案里的基本信息、加固信息、
  签名信息；以及每个检测项的**调用栈**与**截图**。前一组是"这份报告说的是
  哪个包"的锚点，后一组是判定能不能被复核的唯一凭据 —— 都不能因为"求简"
  就丢掉。

★ 入参是 **dict**（就是 flow.json 的内容），不是 FlowResult：
  这样历史任务（本报告上线前跑的那批）只要 flow.json 还在，就能补出一份，
  不需要重跑一遍检测。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .sop_report import STATE_LABELS
from .sop_report import _is_perm_row
from .sop_report import _item_shots as _detail_shots
from .sop_report import _jiagu_text, _stack_block

_TPL = Path(__file__).with_name("sop_template.html")

# 渲染口径版本。服务端据它判断"已落盘的那份是不是旧口径"——
# 老任务目录里的文件不会自动更新，而口径改过（2026-10-26 去掉"简版"字样、
# 补静态档案与调用栈；2026-10-29 v4 政策一节改为"正文在手就给全文"，
# 不再只认安装包内路径；v5 跳过未测项不再贴阶段兜底截图；v6 跳过未测项
# 整段不贴图；v7 结论区加一行「本轮检测范围」，写明未同意状态下点了几次、
# 经过几屏、是否因「拒绝」退出）之后，
# 旧文件必须重出，否则用户点下载拿到的还是旧版本。
BRIEF_VERSION = "7"
BRIEF_MARKER = "<!-- piiscan-brief:%s -->" % BRIEF_VERSION

# 要剔除的四类内容（都属于"怎么得到的 / 依据什么判"，属于内部底稿）：
#   ① 「依据《XX》…。」—— 法条与标准引用，判定标签已经表达结论；
#   ② 「（来源：…）」—— 正文是从哪抓的、走的哪条路径；
#   ③ 「如需认定，应以…」—— 复核方法建议；
#   ④ 「第 P4 阶段」「经隐私政策文本核查：」—— 阶段号与取证手段。
# 只删这几类，其余事实陈述一律保留：删多了会变成"没说"，比"啰嗦"更糟。
_RE_BASIS = re.compile(r"依据《[^》]*》[^。]*。")
_RE_SOURCE = re.compile(r"[（(]\s*来源[：:][^）)]*[）)]")
_RE_ADVICE = re.compile(r"如需(?:认定|核实|确认|判断)[^。]*。")
# 「（第 P4 阶段，弹窗前界面为「…」）」→ 保留后半截证据，去掉阶段号。
# 阶段号是"我们怎么跑的"，而"弹窗前那一屏是什么"是复核要看的证据，不能一起删。
_RE_PHASE = re.compile(r"[（(]\s*第\s*P\d+[^，,）)]*[，,]\s*")
_RE_METHOD = re.compile(r"^(?:经[^：:，。]{0,24}(?:核查|检索|分析)[：:]\s*)+")
# 「本轮执行了设备侧首启观测（同意动作与界面序列已采集），」这类句子讲的是
# **我们做了什么**，不是 App 做了什么 —— 读者关心后者。
# 只删"执行/开展/完成 + 观测/采集/遍历"这种检测动作句，纯事实句不动。
_RE_OUR_STEP = re.compile(r"本轮(?:执行|开展|完成)了?[^。；]*?(?:观测|采集|遍历)[^。；]*?[，,；;]\s*")


def _clean(text: str) -> str:
    """去掉依据句 / 来源括号 / 复核建议 / 阶段号与取证手段，压掉多余空白。"""
    s = str(text or "")
    for rx in (_RE_BASIS, _RE_SOURCE, _RE_ADVICE):
        s = rx.sub("", s)
    s = _RE_PHASE.sub("（", s)
    s = re.sub(r"[（(]\s*[）)]", "", s)          # 清理"()"空括号
    s = _RE_METHOD.sub("", s)
    s = _RE_OUR_STEP.sub("", s)
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n{2,}", "\n", s)
    return s.strip()


def _first_sentence(text: str, limit: int = 110) -> str:
    """取首句，过长则截断。用于表格里的"一句话发现"。"""
    s = _clean(text)
    if not s:
        return ""
    m = re.match(r"[^。！？]*[。！？]", s)
    head = m.group(0) if m else s
    if len(head) > limit:
        head = head[:limit].rstrip("，、；：,;:") + "…"
    return head


def _reason(text: str, limit: int = 160) -> str:
    """「未测原因」：跳过未测项的 desc 常以"跳过未测。"开头，那半句没有信息量。

    只删这个开头，不取"首句"——因为原因往往就在后面那几句里。
    """
    s = _clean(text)
    s = re.sub(r"^(?:跳过未测|未测|未检测)[。；;：:]\s*", "", s)
    if limit and len(s) > limit:
        s = s[:limit].rstrip("，、；：,;:") + "…"
    return s


def _shared_css() -> str:
    """把详细模板的 `<style>` 整块拿过来。

    两版共用同一份样式表，是为了避免"两份报告配色不一致"这种无谓差异;
    配色/字体要改时只改一处。额外需要的那点样式在下面单独追加。
    """
    try:
        html = _TPL.read_text(encoding="utf-8")
    except Exception:
        return ""
    m = re.search(r"<style>(.*?)</style>", html, re.S)
    return m.group(1) if m else ""


def _fmt_date(value: Any) -> str:
    """时间戳 / 字符串 → YYYY-MM-DD；取不到就空着（不写"未知"来占位）。"""
    import time as _t
    if isinstance(value, (int, float)) and value:
        try:
            return _t.strftime("%Y-%m-%d", _t.localtime(value))
        except Exception:
            return ""
    s = str(value or "").strip()
    if not s:
        return ""
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", s)
    return m.group(0) if m else s[:32]


_RE_HTTP = re.compile(r"^https?://", re.I)


def _pick_policy_url(data: Dict[str, Any]) -> str:
    """找隐私政策**网址**。

    优先取存档顶层字段；老存档没有这个字段时，从各检测项的核对链接里挑
    —— 政策类检测项的 links 就是那份政策本身。挑不到就返回空（不猜）。

    ★ 只认 `http(s)`（2026-10-29 金考典简版实测）：
      `links` 里混着界面收割时的**来源标签**（「政策页面文本（滚动后）」），
      它不是地址。照抄会渲染成 `<a href="政策页面文本（滚动后）">` 这种
      点不开的相对链接 —— 详细版 2026-10-28 出过一次 `file:///C:` 死链，
      同一个污染源在简版又中了一次。
    """
    direct = str(data.get("policy_url") or "").strip()
    if _RE_HTTP.match(direct):
        return direct
    urls: List[str] = []
    for row in (data.get("rows") or []):
        for u in (row.get("links") or []):
            u = str(u or "").strip()
            if _RE_HTTP.match(u) and u not in urls:
                urls.append(u)
    for u in urls:
        if re.search(r"priv|policy|agreement|protocol|隐私|协议", u, re.I):
            return u
    return urls[0] if urls else ""


def _policy_docs(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """本次检测**正文在手**的政策文档（不管有没有可点链接）。

    ★ 用户 2026-10-29 意见（Hi投屏）：详细版有内置隐私政策全文，简版却写
      「本次未取得隐私政策链接」——同一次检测，两份报告对同一件事两种说法。
      内置政策本来就没有网址，只写"没链接"等于告诉读者"没有"，正文必须摆出来。

    ★ 再修一次（看个比赛 2026-10-29）：上一版只收 `path` 非空的
      （= 安装包内提取的文档）。可 uni-app / H5 壳应用的政策是**本地页面**
      （`file:///…/__uniappview.html`），正文 16411 字已经读到，却没有
      `path` 也没有 `http` 地址 —— 上一版把它整条跳过，简版又退回到
      「安装包内也未找到政策文档」。真实情况是"读到了但没记下地址"，
      这三类都得收：包内路径 / 在线地址 / **设备侧读到的正文**。

    两个来源，按可靠度排序：
      ① `policy_refs`（本次渲染写入 flow.json，带 path/url 与全文）；
      ② 旧存档回落到 `static.policy_assets`（解包时提取的包内文档，也有全文）——
         简版是事后按 flow.json 现补的，历史任务没有 ① 也得能出全文。

    只取**隐私政策**（含未成年人隐私政策这类专门分册）：清单/用户协议在详细版里
    逐份展开，简版读者要核的是"这个 App 公开了什么样的收集规则"。
    类型一律走 `policy.classify_doc` 判定，不按标题字面猜。
    """
    from .. import policy as _POL           # 延迟导入：避免 report ↔ flow 循环
    out: List[Dict[str, Any]] = []
    # 采集侧记下来的"这份正文到底从哪儿来的"（inline_html / local_file / …）
    src_cap: Dict[str, Any] = dict(data.get("policy_capture") or {})
    if not src_cap and isinstance(data.get("scan"), dict):
        src_cap = dict((data.get("scan") or {}).get("policy_capture") or {})

    def _push(title: str, path: str, url: str, text: str, note: str = "") -> None:
        body = (text or "").strip()
        if len(body) < 200:
            return
        kind = _POL.classify_doc(body, "", url)
        if not _POL.is_policy_kind(kind):
            return
        _norm = re.sub(r"\s+", "", body)
        for it in out:
            # 同一份只留一次，两种判据：
            #   ① 开头 60 字相同（包内文档与界面文本那种"同文不同源"）；
            #   ② 同一地址（国铁吉讯 2026-10-29：P2 主政策 11935 字与
            #      collect_documents 抓的同一链接 11212 字，开头排版不同，
            #      ① 认不出，简版会并列显示两份"几乎一样"的政策）。
            if (re.sub(r"\s+", "", it["text"])[:60] == _norm[:60]
                    or (url and it["url"] == url)):
                if len(body) > len(it["text"]):
                    it.update(text=body, chars=len(body))
                return
        # 来源如实写：没有地址就写清**为什么没有**，不能含糊成"随安装包提供"
        # —— 那会把"本地页面读到的正文"说成"包里有这个文件"。
        # ★ 2026-11-09 用户第 1 条（Q船）：只说"本次未记录到可访问地址"，
        #   读的人会以为采集器漏了地址。真正的原因有两类，必须分开写：
        #     ① 应用把 HTML 直接交给 WebView（about:blank），本来就没有地址；
        #     ② 注入受限，WebView 地址通道不可用。
        if path:
            src, src_kind = "安装包内 %s" % path, "apk"
        elif url:
            src, src_kind = "在线读取", "web"
        else:
            src = "设备侧读取的页面正文（%s）" % (
                note or _POL.no_url_reason(src_cap) or "本次未记录到可访问地址")
            src_kind = "device"
        out.append({"title": (title or _POL.doc_kind_label(kind)).strip(),
                    "kind": _POL.doc_kind_label(kind),
                    "path": path, "url": url, "src": src, "src_kind": src_kind,
                    "text": body, "chars": len(body)})

    for r in (data.get("policy_refs") or []):
        if not isinstance(r, dict):
            continue
        _push(str(r.get("title") or ""), str(r.get("path") or ""),
              str(r.get("url") or ""), str(r.get("text") or ""),
              note=str(r.get("url_note") or ""))
    if not out:
        # 旧存档：policy_assets 里每类可能有七八份厂商定制副本，
        # 直接全渲染会把简版撑成图鉴 —— 每类只取最长的一份。
        by_kind: Dict[str, str] = {}
        best: Dict[str, Dict[str, Any]] = {}
        for a in ((data.get("static") or {}).get("policy_assets") or []):
            if not isinstance(a, dict) or a.get("role") == "prompt_config":
                continue
            t = str(a.get("text") or "").strip()
            if len(t) < 300:
                continue
            k = _POL.classify_doc(t, "", "")
            if not _POL.is_policy_kind(k):
                continue
            if len(t) > len(by_kind.get(k, "")):
                by_kind[k] = t
                best[k] = a
        for k, t in by_kind.items():
            _push(str(best[k].get("title") or ""), str(best[k].get("path") or ""), "", t)
    out.sort(key=lambda it: -it["chars"])
    return out


def _policy_section(data: Dict[str, Any], policy_url: str) -> str:
    """「隐私政策」一节：有网址给网址，正文在手就给全文。

    这一段是简版里唯一"举证"性质的内容 —— 判定写着"未发现未公开收集使用规则"，
    读者得能当场把那份政策读一遍才算数。
    """
    docs = _policy_docs(data)
    blocks: List[str] = []
    if policy_url:
        blocks.append("<p class='mono'><a href='%s' target='_blank'>%s</a></p>"
                      % (_esc(policy_url), _esc(policy_url)))
    if docs:
        rows = "".join(
            "<tr><td>%s</td><td>%s</td><td style='width:82px'>%d 字</td></tr>"
            % (_esc(it["kind"]),
               # 名称与类型相同时只留来源，避免出现"— 在线读取"这种空壳
               (_esc(it["title"]) + "<div class='sub'>%s</div>" % _esc(it["src"]))
               if it["title"] and it["title"] != it["kind"] else _esc(it["src"]),
               it["chars"])
            for it in docs)
        # 引导语按**正文实际来源**说：包内提取 / 设备上读到的页面，措辞不能通用。
        # ★ "政策以应用内页面展示"这类推断不写：我们只掌握"没记录到 http 地址"，
        #   不掌握它一定没有官网地址（可能只是这次没取到）。
        _kinds = {it["src_kind"] for it in docs}
        if policy_url:
            _lead = "政策全文如下，可直接核对。"
        elif _kinds == {"apk"}:
            _lead = ("本次未取得可访问的在线政策地址；政策文本随安装包提供，"
                     "全文如下（无需联网即可核对）。")
        else:
            _lead = ("本次未取得可访问的在线政策地址；正文为本次检测在设备上读取，"
                     "全文留存如下，可直接核对。")
        blocks.append("<p class='muted'>%s</p>" % _esc(_lead))
        blocks.append("<table class='bief'><tr><th>文档</th><th>名称与来源</th>"
                      "<th>字数</th></tr>%s</table>" % rows)
        for it in docs:
            full = it["text"]
            tail = ""
            cap = 30000
            if len(full) > cap:
                tail = ("\n\n……（全文 %d 字，此处显示前 %d 字）" % (len(full), cap))
                full = full[:cap]
            blocks.append(
                "<details><summary>%s 全文（%d 字）</summary>"
                "<pre class='doc'>%s%s</pre></details>"
                % (_esc(it["kind"]), it["chars"], _esc(full), _esc(tail)))
    if not blocks:
        blocks.append("<p class='muted'>本次未取得隐私政策链接，安装包内也未找到政策文档。</p>")
    return "<h2 class='sec'>隐私政策</h2>" + "".join(blocks)


def _session_date(data: Dict[str, Any], given: Any = "") -> str:
    if given:
        return _fmt_date(given)
    if data.get("started_at"):
        return _fmt_date(data.get("started_at"))
    starts = [p.get("started_at") for p in (data.get("phases") or [])
              if isinstance(p, dict) and p.get("started_at")]
    return _fmt_date(min(starts)) if starts else ""


def _esc(s: Any) -> str:
    return (str(s if s is not None else "")
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _rich(s: Any) -> str:
    """转义后保留换行。本报告不渲染任何 HTML 标记 —— 存档字段是纯文本。"""
    return _esc(s).replace("\n", "<br/>")


# ---------------------------------------------------------------- 静态档案
def _static_pairs(s: Dict[str, Any]) -> List[Tuple[str, str]]:
    """静态档案里要在正文出现的那几行。

    只挑"这份报告说的是哪个包、包怎么被处理过"的字段：
    版本与 SDK 级别、权限声明规模、加固、签名。其余（组件清单、域名、native 库）
    属于取证细节，留在详细报告。

    ★ 加固与签名是用户点名要留的：加固决定"动态行为能不能采到、采到的是不是
      加固壳自己的行为"，签名决定"这份结论对应的是不是同一个发行包"——
      换过签名的包等于另一个样本，不写就无从对照。
    """
    perms = s.get("permissions") or []
    sdks = s.get("sdks") or []
    try:
        from ..flow.compare import dangerous_permissions
        risky = dangerous_permissions(perms)
    except Exception:
        risky = []

    pairs: List[Tuple[str, str]] = []

    def add(k: str, v: Any) -> None:
        v = str(v if v is not None else "").strip()
        if v:
            pairs.append((k, v))

    add("minSdkVersion", s.get("min_sdk"))
    add("targetSdkVersion", s.get("target_sdk"))
    add("DEX 数量", s.get("dex_count"))
    if perms:
        add("权限声明", "%d 项（其中危险权限 %d 项）" % (len(perms), len(risky)))
    if sdks:
        add("第三方 SDK", "%d 个" % len(sdks))
    # 加固：无文件级命中时 `_jiagu_text` 也会给一句"未识别（…）"，
    # 比留空更能说明"查过、结论是没有"，所以照收。
    add("加固", _jiagu_text(s))

    sig = s.get("signature") or {}
    subj = str(sig.get("subject") or sig.get("cn") or "").strip()
    fp = str(sig.get("sha256") or "").strip()
    if subj or fp:
        add("签名主体", subj or "（未解析出证书主体）")
        if fp:
            add("签名证书 SHA-256", fp)
        add("签名方案", sig.get("schemes"))
        ver = str(sig.get("verified") or "").strip()
        if ver:
            add("签名校验", "通过" if ver in ("是", "True", "true", "1") else "未通过")
    else:
        add("签名", "未取得证书信息（未安装 apksigner 且 APK 内无签名块）")

    add("可调试", "是" if s.get("debuggable") else "否")
    add("明文流量", "允许" if s.get("cleartext") else "否")
    add("允许备份", "是" if s.get("allow_backup") else "否")
    return pairs


def _static_html(s: Dict[str, Any]) -> str:
    if not s:
        return ("<p class='muted'>本次未提供 APK，未执行静态分析，"
                "基本信息、加固与签名信息未取得。</p>")
    rows = _static_pairs(s)
    if not rows:
        return "<p class='muted'>静态分析未取得可用字段。</p>"
    body = "".join("<tr><th>%s</th><td>%s</td></tr>" % (_esc(k), _esc(v))
                   for k, v in rows)
    return "<table class='meta'>%s</table>" % body


# ---------------------------------------------------------------- 检测项
def _item_card(row: Dict[str, Any], shot_map: Dict[int, Dict[str, Any]],
               app_package: str = "") -> str:
    """一个检测项：发现（或未测原因）+ 判定 + 调用栈 + 截图。

    问题项与跳过未测项用同一张卡片：跳过未测同样要给得出"为什么没测"，
    只写一句"跳过未测"等于让人无从判断该不该补测。

    ★ 跳过项一律不贴截图（用户 2026-10-29 / 2026-10-30 两次意见）：
      那类图只是该项恰好触发时屏幕上的样子，跟"这一项为什么没测"毫无关系，
      放进对外版只会让读者以为"看，有图，就是它没测出来"。上一版还给
      "该项专属截图"（如权限弹窗）开了口子，用户复核时仍然认为无关 —— 这次
      整段关掉。简版要把体积与注意力留给真问题；图在详细版里一张不少。
    """
    state = row.get("state") or "not_tested"
    label = STATE_LABELS.get(state, row.get("state_label") or state)
    skipped = state not in ("fail", "suspect")

    if skipped:
        text = _reason(row.get("desc"), 0)     # 不截断：原因写不全就等于没写
        head = "未测原因"
    else:
        text = _clean(row.get("desc"))
        head = "检测发现"

    body: List[str] = ["<p class='desc'><span class='label'>%s：</span>%s</p>"
                       % (head, _rich(text) or "—")]

    # ---- 调用栈：判定能不能被复核，全看这一段 ----
    stacks = _stack_block(row.get("stacks") or [], app_package,
                           row.get("stack_meta"))
    if stacks:
        body.append(stacks)
    elif row.get("needs_stack"):
        # 采集类结论却没有栈 —— 必须说出来，静默略过会被读成"这条不需要栈"。
        body.append("<p class='evidence'>调用栈：<b>本次未捕获到该行为的调用栈</b>，"
                    "无法据此区分是应用自身还是第三方 SDK 发起，需结合沙箱精检复核。</p>")

    shots = row.get("shots") or []
    # 跳过项一律不贴图（用户 2026-10-30 二次意见：连"该项专属截图"也不要）。
    # 上一版只挡了阶段兜底图（`kind=phase`），权限项那张 `kind=perm` 还留着 ——
    # 复核员看到"跳过未测"下面挂着一张权限弹窗，只会问"那到底测没测"。
    # 跳过项本来就没有结论要交代，配图反而制造歧义；图在详细版里都在。
    if not skipped:
        body.append(_detail_shots(row, shot_map or {}))
        # 兜底挂在"阶段"上的截图 ≠ 该项的专属证据。必须当场说清，
        # 否则读者会把这些界面图当成"这一项就是这么判的"。
        if shots and str(shots[0].get("kind") or "") == "phase" and not _is_perm_row(row):
            body.append("<p class='muted'>以上为该检测项所处阶段的界面截图，"
                        "用于说明当时的界面状态；该项判定未依赖其中的界面文字。</p>")
    return ("<div class='item %s'><div class='hd'><span>%s. %s</span>"
            "<span class='tag'>%s</span></div><div class='bd'>%s</div></div>"
            % (_esc(state), _esc(row.get("num")), _esc(row.get("title")),
               _esc(label), "".join(body)))


_CN = ["一", "二", "三", "四", "五", "六"]


def _scope_line(data: Dict[str, Any]) -> str:
    """一行写清「这一轮到底做了什么」。

    ★ 2026-11-17 使用者质疑："跑了十几个 App 的 1 档，一个同意前实锤都没有"。
      查下来，报告里既没写这一档点了几次、也没写"点了「拒绝使用」就退回桌面"——
      复核的人只看到"跳过未测"，无法判断是 App 干净、还是我们压根没测到。
      所以简版（对外那份）也要有这一行：它不谈合规结论，只交代检测动作。
    """
    pe = data.get("pre_explore") or {}
    depth = str(data.get("depth") or "")
    label = {"pre": "1 档（仅同意前）", "light": "2 档", "deep": "3 档",
             "extreme": "4 档", "normal": "自定义"}.get(depth, "")
    bits: List[str] = []
    if label:
        bits.append("检测档位：%s" % label)
    if pe:
        taps = int(pe.get("taps") or 0)
        screens = int(pe.get("screens") or 0)
        if taps:
            bits.append("未同意状态下点击 %d 次、经过 %d 屏" % (taps, screens))
        else:
            bits.append("未同意状态下未执行界面点击（%s）"
                        % (pe.get("why") or "原因未记录"))
        rx = pe.get("refused_exit") or []
        if rx:
            names = "、".join("「%s」" % str(r.get("label") or "") for r in rx[:3])
            bits.append("点击%s后应用退回桌面，未同意状态下没有第二个可用界面"
                        % names)
        rs = int(pe.get("respawns") or 0)
        if rs:
            bits.append("期间重新拉起 %d 次" % rs)
        esc = int(pe.get("escapes") or 0)
        if esc:
            bits.append("有 %d 次界面已不属于被测应用（已退回、不计入触发）" % esc)
    if not bits:
        return ""
    return "".join(["<p class='muted'>本轮检测范围：", _esc("；".join(bits)), "。</p>"])


def render_brief(data: Dict[str, Any], *, app_name: str = "", version: str = "",
                 source_market: str = "", operator: str = "",
                 published_at: str = "", date: Any = "") -> str:
    """渲染对外报告。data 为 `FlowResult.to_dict()`（即 flow.json 的内容）。"""
    data = data or {}
    name = app_name or str(data.get("app_name") or "") or str(data.get("package") or "") or "XXX"
    ver = version or str(data.get("version") or "")
    pkg = str(data.get("package") or "")
    market = source_market or str(data.get("source_market") or "")
    org = operator or str(data.get("operator") or "")
    day = _session_date(data, date)
    policy_url = _pick_policy_url(data)
    static = data.get("static") or {}

    rows = list(data.get("rows") or [])
    shot_map: Dict[int, Dict[str, Any]] = {
        int(it.get("index")): it for it in (data.get("shots") or [])
        if isinstance(it, dict) and it.get("index") is not None
    }
    problems = [r for r in rows if r.get("state") in ("fail", "suspect")]
    passed = [r for r in rows if r.get("state") == "pass"]
    skipped = [r for r in rows if r.get("state") not in ("fail", "suspect", "pass")]
    stats = data.get("stats") or {}
    n_fail = int(stats.get("fail") or 0)
    n_susp = int(stats.get("suspect") or 0)

    parts: List[str] = []
    idx = 0

    # ---- 问题项：逐项展开（发现 + 判定 + 调用栈 + 截图）----
    idx += 1
    parts.append("<h2 class='sec'>%s、检测发现问题（%d 项）</h2>"
                 % (_CN[idx - 1], len(problems)))
    if problems:
        if n_fail and n_susp:
            parts.append("<p class='muted'>其中认定为发现问题 %d 项、疑似需人工复核 %d 项。</p>"
                         % (n_fail, n_susp))
        parts.extend(_item_card(r, shot_map, pkg) for r in problems)
    else:
        parts.append("<p class='muted'>本次未发现明确问题。</p>")

    # ---- 跳过未测：同样逐项写清"为什么没测"，不做合规结论 ----
    if skipped:
        idx += 1
        parts.append("<h2 class='sec'>%s、跳过未测项（%d 项）</h2>"
                     % (_CN[idx - 1], len(skipped)))
        parts.append("<p class='muted'>以下检测项本次未取得判定所需的证据，"
                     "<b>不作合规结论</b>，需人工补充检测。</p>")
        parts.extend(_item_card(r, shot_map, pkg) for r in skipped)

    # ---- 未发现问题：一句话表格（这类项没有需要逐条看的证据）----
    if passed:
        idx += 1
        parts.append("<h2 class='sec'>%s、未发现问题的检测项（%d 项）</h2>"
                     % (_CN[idx - 1], len(passed)))
        parts.append(
            "<table class='bief'><tr><th style='width:42px'>#</th>"
            "<th style='width:36%%'>检测项</th><th>检测发现</th>"
            "<th style='width:92px'>检测判定</th></tr>%s</table>"
            % "".join(
                "<tr><td>%s</td><td>%s</td><td>%s</td><td>未发现问题</td></tr>"
                % (_esc(r.get("num")), _esc(r.get("title")),
                   _rich(_first_sentence(r.get("desc"))) or "—")
                for r in passed))

    summary = ("本次共检测 %d 个检测项：发现问题 %d 项、疑似 %d 项、"
               "未发现问题 %d 项、跳过未测 %d 项。"
               % (int(stats.get("total") or len(rows)), n_fail, n_susp,
                  int(stats.get("pass") or 0), int(stats.get("not_tested") or 0)))

    meta_rows = [
        ("应用软件名称", name),
        ("应用软件版本", ver or "—"),
        ("应用包名", pkg or "—"),
        ("来源应用市场", market or "—"),
        ("检测日期", day or "—"),
    ]
    if org:
        meta_rows.append(("送检单位", org))
    if published_at:
        meta_rows.append(("发布日期", _fmt_date(published_at) or str(published_at)))
    meta_html = "".join("<tr><th>%s</th><td>%s</td></tr>" % (_esc(k), _rich(v))
                        for k, v in meta_rows)

    policy_html = _policy_section(data, policy_url)

    extra_css = """
  table.bief { width: 100%; border-collapse: collapse; margin: 10px 0 4px; font-size: 13.5px; }
  table.bief th, table.bief td { border-bottom: 1px solid var(--line); padding: 7px 8px;
    text-align: left; vertical-align: top; line-height: 1.65; }
  table.bief th { color: var(--ink2); font-weight: 500; background: #fafbfc; }
  table.bief td:last-child { color: var(--ink2); white-space: nowrap; }
  table.bief td div.sub { font-size: 12.5px; color: var(--ink2); margin-top: 2px; }
  p.mono { font-size: 13.5px; word-break: break-all; margin: 6px 0 0; }
  table.meta td { word-break: break-all; }
"""

    return """<!DOCTYPE html>
""" + BRIEF_MARKER + """
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>%(title)s</title>
<style>%(css)s%(extra)s</style>
</head>
<body>
<div class="wrap"><div class="doc">
<h1 class="title">%(name)s App 个人信息保护合规检测报告</h1>
<h2 class="sec">应用软件信息</h2>
<table class="meta">%(meta)s</table>
<h2 class="sec">基本信息</h2>
%(static)s
%(policy)s
<h2 class="sec">检测结论</h2>
<p class="lead">%(summary)s</p>
%(scope)s
%(items)s
</div></div>
</body>
</html>
""" % {
        "title": _esc("%s App 个人信息保护合规检测报告" % name),
        "css": _shared_css(),
        "extra": extra_css,
        "name": _esc(name),
        "meta": meta_html,
        "static": _static_html(static),
        "policy": policy_html,
        "summary": _esc(summary),
        "scope": _scope_line(data),
        "items": "".join(parts),
    }


__all__ = ["render_brief", "BRIEF_VERSION", "BRIEF_MARKER"]
