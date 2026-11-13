"""政策取证相关用例（2026-11-08）。

起因：岛 / 小包搜题 / 快搜搜题三个 App 都"没拿到隐私政策"，
但首启弹窗上确实有政策入口。三种病因各不相同：

  ① 岛：入口是正文里的一段普通文字 —— 与正文同色、结构树里没有独立节点、
     也不带 ClickableSpan。关键词匹配找不到，AI 视觉也只会说"仅有一段告知文本"。
     但真机上按文字位置点下去**能打开政策页**（实测切到 BrowserActivity，
     正文《隐私政策》全屏可读，URL 在 Activity intent 的 extra 里）。
  ② 小包搜题 / 快搜搜题：加固壳冷启动，首启观测窗口里 App 还没到前台，
     窗口结束后遍历才开始，同意页那时才第一次出现。
  ③ 三家共同：政策没取到就点了「同意」，之后十几项条款比对全部落空。

所以这里守三条：
  · 内联链接候选的排序与去重（弹窗内的优先，因为模态弹窗会吃掉下面的触摸）；
  · "已取得政策"的判据（★ 只有 URL 不算 —— 用户要求"通过应用页面访问到"）；
  · 注入脚本确实具备"按文字布局算坐标"和"从 Activity intent 取 URL"的能力。
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(check):
    from piiscan import collector as C

    # ---------------------------------------------------------------- 候选排序
    links = [
        {"text": "《隐私政策》", "xy": [600, 1731], "src": "anchor", "win": "activity"},
        {"text": "《隐私协议》", "xy": [841, 1164], "src": "anchor", "win": "dialog"},
        {"text": "用户协议", "xy": [481, 1731], "src": "keyword", "win": "activity"},
        {"text": "隐私政策", "xy": [446, 999], "src": "keyword", "win": "dialog"},
    ]
    ranked = C._rank_inline_links(links)
    check("内联候选：弹窗内的排在页面之前（模态弹窗会吃掉下面的触摸）",
          ranked[0].get("win") == "dialog",
          "实际排第一的是 %s" % (ranked[0],))
    check("内联候选：同为弹窗内时「隐私」优先于「用户协议」",
          "隐私" in ranked[0]["text"],
          "实际 %s" % ranked[0]["text"])
    check("内联候选：带 URL 的排最前",
          C._rank_inline_links([
              {"text": "《隐私政策》", "xy": [1, 1], "src": "anchor", "win": "activity"},
              {"text": "《隐私政策》", "xy": [2, 2], "src": "span", "win": "activity",
               "url": "https://x/y"},
          ])[0].get("url") == "https://x/y", "")
    check("内联候选：没有坐标的条目被丢掉（不能点一个不知道在哪的点）",
          all(ln.get("xy") for ln in C._rank_inline_links(
              [{"text": "《隐私政策》", "xy": None}, {"text": "《隐私政策》", "xy": [3, 4]}])),
          "")

    # ---------------------------------------------------------------- 去重键
    k1 = C._link_tried_key({"text": "《隐私政策》", "xy": [10, 20]})
    k2 = C._link_tried_key({"text": "《隐私政策》", "xy": [10, 20]})
    k3 = C._link_tried_key({"text": "《隐私政策》", "xy": [10, 21]})
    check("内联候选：同一位置算同一个点（避免反复点同一处）", k1 == k2 and k1 != k3, "")

    # ---------------------------------------------------------------- 取证判据
    class _R:
        def __init__(self, cap):
            self.policy_capture = cap

    check("★ 只有链接、页面从未打开 → 不算「已访问到政策」",
          not C._policy_evidence_ok(_R({
              "urls": [{"url": "https://www.iiisland.com/privacy?show=app"}],
              "bestText": "", "documents": [], "openSnapshot": {},
          })), "抓 URL 不等于通过应用页面读到政策")
    check("政策页确实打开过 → 算已取得",
          C._policy_evidence_ok(_R({
              "urls": [], "bestText": "", "documents": [],
              "openSnapshot": {"entered": True},
          })), "")
    check("正文够长（可做条款比对）→ 算已取得",
          C._policy_evidence_ok(_R({
              "urls": [], "bestText": "隐" * (C.INLINE_POLICY_MIN + 10),
              "documents": [], "openSnapshot": {},
          })), "")
    check("只有几百字的弹窗摘要 → 不算（那是告知语，不是政策正文）",
          not C._policy_evidence_ok(_R({
              "urls": [], "bestText": "隐" * 300,
              "documents": [], "openSnapshot": {},
          })), "")
    check("有文档入库 → 算已取得",
          C._policy_evidence_ok(_R({
              "urls": [], "bestText": "", "openSnapshot": {},
              "documents": [{"url": "u", "chars": 9000}],
          })), "")

    # ---------------------------------------------------------------- 逐轮换点
    tries = []

    class _FakeExports:
        def policy_links(self, n):
            return [{"text": "《隐私协议》", "xy": [100, 200], "src": "anchor", "win": "dialog"},
                    {"text": "《用户协议》", "xy": [300, 200], "src": "anchor", "win": "dialog"}]

    class _FakeScript:
        exports_sync = _FakeExports()

    cap = {"inlineTried": []}
    got = []
    for _ in range(4):
        node = C._inline_policy_entry("s", None, cap, lambda *a: None, lambda: _FakeScript())
        got.append(node)
    real = [n for n in got if n is not None]
    check("内联候选：一次只给一个点，且逐个换（不反复点同一处）",
          len(real) == 2, "实际拿到 %d 个" % len(real))
    check("内联候选：试完所有点后不再返回（由调用方如实收工）",
          len(real) == 2 and got[-1] is None, "")
    check("内联候选：返回的节点坐标就是精确点击点（框只有 ±2px）",
          all((n.bounds[2] - n.bounds[0]) <= 4 for n in real), "")

    cap2 = {"inlineTried": []}
    n1 = C._inline_policy_entry("s", None, cap2, lambda *a: None, lambda: _FakeScript())
    check("内联候选：弹窗内的点优先被先试（岛弹窗正文 y≈1164 那一条）",
          n1 is not None and n1.center == (100, 200),
          "实际 %s" % (str(n1.center) if n1 else "None"))

    # ---------------------------------------------------------------- 注入脚本
    js = (ROOT / "piiscan" / "hooks" / "collector.js").read_text(encoding="utf-8")
    check("★ 注入脚本导出 policyLinks（按文字布局算政策链接坐标）",
          "policyLinks: function" in js and "collectPolicyLinks" in js, "")
    check("★ 注入脚本导出 activityUrl（政策页在自家 Activity 里时 URL 在 intent 里）",
          "activityUrl: function" in js, "")
    check("★ 遍历窗口要包含 Dialog 与 PopupWindow（首启隐私弹窗多是 Dialog，"
          "不在 Activity 的视图树里）",
          "Java.choose('android.app.Dialog'" in js
          and "Java.choose('android.widget.PopupWindow'" in js, "")
    check("★ TextView 判定必须用 cast（instanceof 按声明类型判，永远是 false）",
          "Java.cast(v, TVCls)" in js, "")
    check("★ 子节点遍历要 cast 到 ViewGroup（View 上没有 getChildCount）",
          "Java.cast(v, VGCls)" in js, "")
    check("按书名号切分正文里的链接文字",
          "《[^》]{2,40}》" in js, "")

    # ---------------------------------------------------------------- 同意闸门
    src = (ROOT / "piiscan" / "collector.py").read_text(encoding="utf-8")
    check("★ 同意之前有强制取证闸门（政策没取到时先打开政策再同意）",
          "grab_policy_once" in src and "_policy_evidence_ok" in src, "")
    check("★ 着陆阶段点「同意」前也过闸门（岛就是被模型直接点了同意）",
          '"着陆阶段点同意前"' in src, "")
    check("★ 政策采集窗口结束前也补做一次（不放任「没取到就直接同意」）",
          '"首启观测窗口结束前"' in src, "")
    check("★ 首启观测窗口以档位声明值为下限（表单不能把它压到 25 秒）",
          "_pw_cfg" in src and "首启观测窗口按档位校正" in src, "")
    check("★ 前台迟迟不来时窗口顺延（加固壳冷启动 50 秒才起来的场景）",
          "首启观测窗口顺延" in src, "")

    # ------------------------------------------------- 着陆阶段的分水岭登记
    # 岛 land31 暴露的旧缺口：着陆第 1 步模型点了「同 意」，P3 却报
    # "未捕获到同意事件" —— 之后每一条事件都被划进"同意前"。
    check("★ 着陆阶段点击同意要登记分水岭（此前一处都没有）",
          'pending_consent = {"node": node' in src, "")
    check("★ 着陆的同意登记只看下一屏指纹（没换屏不算已同意）",
          '_csig = "ui" if (fp and fp != str(_pc_c.get("fp") or "")) else ""' in src, "")
    check("★ 着陆同意登记走唯一入口 _mark_consent_after_tap",
          '"首启着陆点击"' in src, "")

    # ------------------------------------------------- 注入被壳拦死时的自救
    # 小包搜题 1.9.5 实测：冷启动注入成功、hook 回执 70 个，随后进程消失；
    # 首启观测在桌面上空转 66 秒，政策 0 字。不注入时它能正常跑到协议页。
    check("★ 首启观测要能区分「启动慢」与「已被注入弄死」（看进程在不在）",
          "abandon_inject" in src and "_alive = find_running_pid(serial, _pkg)" in src, "")
    check("★ 判定死亡后要放弃注入、不注入重新拉起（不是继续干等）",
          "改为不注入重新拉起" in src, "")
    check("★ 放弃注入要把 live.hooked 置 False（后续 respawn 才会只拉起）",
          "live.hooked = False" in src and "live.script = _NoScript()" in src, "")
    check("★ 判死要两个条件同时成立（pidof 取不到 + 前台也不在应用内），"
          "只看 pidof 会误伤多进程 App",
          "_alive is None and not _now_fg.startswith(_pkg)" in src, "")
    check("★ 这条检查不能只在「前台没来」时做（land35：活动页短暂到过前台就崩了）",
          "_now_fg = uiwalk.current_focus(serial) or \"\"" in src, "")

    # ------------------------------------------------- WebView 正文读不出来
    # 不注入时政策页开在 WebActivity 的 WebView 里，结构树只有一个空节点；
    # 点一下页面后无障碍树才建立（实测 164 节点 / 7136 字）。
    # 夹具按真机 dump 的属性顺序写：`parse_all` 只认标准格式，
    # 属性顺序不对会一个节点都解析不出来（自己踩过）。
    _NODE = ('<hierarchy><node index="0" text="%s" resource-id="" class="%s"'
             ' package="p" content-desc="" checkable="false" checked="false"'
             ' clickable="true" enabled="true" focusable="true" focused="false"'
             ' scrollable="false" long-clickable="false" password="false"'
             ' selected="false" bounds="[0,233][1080,2261]" /></hierarchy>')
    _wv_empty = _NODE % ("", "android.webkit.WebView")
    _wv_full = _NODE % ("隐私政策正文" * 30, "android.webkit.WebView")
    _no_wv = _NODE % ("同意", "android.widget.TextView")
    check("空 WebView 判定为「读不出正文」", C.webview_text_blind(_wv_empty) is True, "")
    check("有正文的 WebView 不算读不出（不能白点一下把人点走）",
          C.webview_text_blind(_wv_full) is False, "")
    check("没有 WebView 的界面一律不碰", C.webview_text_blind(_no_wv) is False, "")
    check("空 xml 不判为 WebView 盲区", C.webview_text_blind("") is False, "")
    check("★ 政策页要接入 WebView 唤醒（点一下再读）",
          'cap["webviewWake"]' in src and "wake_webview_text(" in src, "")
    check("★ 唤醒只点一处、且要核对前台没被点走",
          "唤醒 WebView 时前台被切到" in src, "")

    # --------------------------------------------- WebView 政策页取文方式
    # 真机根因：政策页被拆成上百个短节点，"取最长的三段"拿到的是正文中段，
    # 开头「隐私政策/本政策仅适用于…」丢了 → 类型闸门 False → 整页 6624 字全废。
    _PN = ('<node index="%d" text="%s" resource-id="" class="android.view.View"'
           ' package="p" content-desc="" checkable="false" checked="false"'
           ' clickable="false" enabled="true" focusable="false" focused="false"'
           ' scrollable="false" long-clickable="false" password="false"'
           ' selected="false" bounds="[0,%d][1080,%d]" />')
    _head = "隐私政策 本政策仅适用于广州小宇宙科技有限公司的小包搜题产品与服务。"
    _p = ["设备品牌、型号、软件系统版本、存储信息、运营商信息、网络信号强度"
          "与地址、语言等基础信息，用于保障服务正常运行与安全风控。" * 3,
          "我们如何使用Cookie和同类技术，以及我们如何共享、转让、公开披露"
          "相关信息，并在法律允许范围内进行必要说明。" * 3,
          "账号的管理方式，包括注册、登录、注销与找回，以及更新方式和联系"
          "方式等说明内容。" * 3]
    _page = "<hierarchy>" + "".join(
        _PN % (i, t, i * 10, i * 10 + 10)
        for i, t in enumerate([_head] + _p)) + "</hierarchy>"
    _h = C._harvest_ui_text(_page)
    _ppt = C.policy_page_text(_page)
    check("复现：只取最长三段 → 开头那句「隐私政策」不在里面",
          _h and not _h.startswith("隐私政策"),
          "harvest=%d" % len(_h))
    check("复现：因此过不了类型闸门（整页正文会被丢掉）",
          C._POL.looks_like_privacy_policy(_h) is False, "")
    check("★ 政策页取不到或被闸门否掉时，按文档顺序拼全页",
          _ppt.startswith("隐私政策") and len(_ppt) > len(_h),
          "ppt=%d" % len(_ppt))
    check("★ 拼全页后通过类型闸门（这是政策全文能进报告的前提）",
          C._POL.looks_like_privacy_policy(_ppt) is True, "")
    check("全页拼接会把 &#10; 当空白、并去掉相邻重复节点",
          C.page_full_text("<hierarchy>" + _PN % (0, "&#10;", 0, 1)
                           + _PN % (1, "甲", 1, 2) + _PN % (2, "甲", 2, 3)
                           + "</hierarchy>") == "甲", "")
    check("★ 政策页一律按文档顺序取（快搜搜题那轮拿到的是服务协议中段，"
          "开头「本政策…」根本不在里面）",
          C.policy_page_text(_page) == C.page_full_text(_page), "")

    # ------------------------------------------- 按钮文字里夹空格（岛 2.2.0）
    # 岛的同意按钮写成「同  意」，子串匹配整场落空 → 点了不算同意 →
    # 133 条事件全落"同意前"、P3 报"未捕获到同意事件"。
    check("★ 「同  意」（字间夹空格）要认成明示同意",
          C._consent_label_kind("同  意")[0] == "explicit", "")
    check("★ 「同 意 并 继 续」同样认成明示同意",
          C._consent_label_kind("同 意 并 继 续")[0] == "explicit", "")
    check("★ 「不同意并退出App」仍是否定（抹空格不能把否定抹掉）",
          C._consent_label_kind("不同意并退出App")[0] == "", "")
    check("★ 夹空格的勾选文案仍判为 checkbox",
          C._consent_label_kind("我 已 阅 读 并 同 意")[0] == "checkbox", "")

    # ------------------------------------- 弹窗标题 ≠ 入口（学习通 7.0.6，2026-11-11）
    # 真机现场：首启弹窗上「隐私政策」四个字出现两次 ——
    #   ① 弹窗标题，bounds [440,502][640,569]，clickable=false；
    #   ② 正文首句「亲爱的用户，请仔细阅读《隐私政策》和《用户协议》…」，
    #      整句一个 TextView，clickable=true，句子折成两行。
    # 旧排序是「含隐私 → 文字越短越靠前」，于是第一个候选＝标题中心 (540,535)。
    # 点标题什么都不会发生，程序就写"点击后前台未切换；正文 0 字"，然后去点同意。
    # 而按颜色实测，蓝字《隐私政策》在 x 581..760 / y 632..665，
    # 点 (670,648) 立刻打开 WebAppViewerActivity，页面就是完整隐私政策。
    _fix = ROOT / "tools" / "fixtures" / "chaoxing_706_popup.xml"
    if _fix.exists():
        import io as _io
        from PIL import Image, ImageDraw as _ID

        _xml = _fix.read_text(encoding="utf-8")
        # 合成一张同尺寸截图：只在链接的真实像素区画蓝字（不引入 300KB 图）
        _im = Image.new("RGB", (1080, 2340), (255, 255, 255))
        _d = _ID.Draw(_im)
        _d.rectangle([581, 632, 760, 665], fill=(47, 107, 176))    # 《隐私政策》
        _d.rectangle([850, 632, 881, 665], fill=(47, 107, 176))    # 《用（换行截断）
        _d.rectangle([167, 684, 290, 717], fill=(47, 107, 176))    # 户协议》
        _buf = _io.BytesIO()
        _im.save(_buf, format="PNG")
        _png = _buf.getvalue()

        _old_dump, _old_shot = C.uiwalk.dump_retry, C.capture_screenshot
        C.uiwalk.dump_retry = lambda *a, **k: _xml
        C.capture_screenshot = lambda *a, **k: _png
        try:
            _cands = C._policy_link_points_from_tree("FAKE", log=lambda *_a: None)
        finally:
            C.uiwalk.dump_retry, C.capture_screenshot = _old_dump, _old_shot

        _xy = [c["xy"] for c in _cands]
        check("★ 学习通：算出了候选点", bool(_cands), _xy[:3])
        check("★ 弹窗标题（不可点的「隐私政策」）不再作为候选",
              all(abs(x - 540) > 8 or abs(y - 535) > 8 for x, y in _xy), _xy[:3])
        check("★ 第一个候选是正文那句，不是标题",
              bool(_cands) and _cands[0]["text"].startswith("亲爱的用户"),
              _cands[0]["text"][:30] if _cands else "")
        check("★ 首选坐标落在彩色链接文字上（像素校准，y=632..665）",
              bool(_cands) and 560 <= _cands[0]["xy"][0] <= 890
              and 620 <= _cands[0]["xy"][1] <= 680,
              _cands[0]["xy"] if _cands else "")

        # 逐个重试：3 个候选要能都排进去（旧实现只点第一个）
        import inspect
        _src = inspect.getsource(C.grab_policy_once)
        check("★ 点空一个候选后会换下一个（不再只点一次就收工）",
              "_attempts" in _src and "for _idx, _cand in enumerate(_attempts)" in _src,
              "")

    # -------------------------- 1 档：点开了 ≠ 拿到正文（学习通，2026-11-11）
    # 现场：`grab_policy_once` 在"点开政策页"时返回 True → policy_resolved=True，
    # 1 档收尾却写"已取得政策正文"，同一份日志上一行是"正文 0 字"。
    import inspect as _insp
    _src1 = _insp.getsource(C._probe_first_launch)
    check("★ 1 档收尾不再把「点开页面」写成「已取得正文」",
          "政策页已打开但正文读不到" in _src1
          and "1 档：已取得政策正文，按要求不点同意" not in _src1, "")
    check("★ 1 档也要走「同意前补做政策访问」（不点同意，故无替用户同意风险）",
          "not consent_done and not policy_resolved" in _src1, "")

    # -------------------- 「没走完」不能读成「应用没有」（2026-11-13）
    # 起因：对着 40 份人工检测报告复核 84 轮自动化结论，发现 84 轮里只有两轮判了
    # 「未公开收集使用规则（发现问题）」—— 船务通与健康深圳。而这两轮的
    # scan_errors 里都写着"未覆盖部分按「跳过未测」计，不代表应用没有该功能"；
    # 人工报告里**船务通是有隐私政策的**（还引用了其中"更正 30 天"的承诺）。
    # 采集侧已经诚实地说"我没走完"，判据层却把"没走完"读成了"不存在"。
    from types import SimpleNamespace as _NS
    from piiscan.flow.sop import FlowRunner as _SOP

    class _Stub:            # 只需要 `.fr.scan_errors`
        pass

    _s = _Stub()
    _s.fr = _NS(scan_errors=[
        "连续 8 轮停在「x/.MainActivity」没有任何动作发生……因此在此收工。"
        "未覆盖部分按「跳过未测」计，不代表应用没有该功能"])
    check("★ 能识别「本轮没走完」的自述（降级依据）",
          bool(_SOP._coverage_caveat(_s)), _SOP._coverage_caveat(_s)[:40])
    _s.fr = _NS(scan_errors=["界面布局中有 9 个可点入口被其它控件遮挡"])
    check("没有这类自述时不许降级（正常收工仍可认定）",
          _SOP._coverage_caveat(_s) == "", "")
    _s.fr = _NS(scan_errors=[])
    check("scan_errors 为空时安全返回", _SOP._coverage_caveat(_s) == "", "")

    _sop_src = (ROOT / "piiscan" / "flow" / "sop.py").read_text(encoding="utf-8")
    check("首启无提示这条路会先问覆盖度",
          "_nonotice" in _sop_src and "_coverage_caveat()" in _sop_src, "")
    check("★ 覆盖不足时降为「疑似」而不是「发现问题」",
          "首启未见政策提示，但本轮覆盖不全，按疑似处理" in _sop_src, "")

    # 描述拼接：正文自带句号时不能再叠一个
    from piiscan.flow.checklist import _desc_for as _DF
    from piiscan.flow.models import ItemState as _IS, SUSPECT as _SUSPECT
    _row = {"standard": "某标准", "clause": "", "unit": "",
            "conclusion": "未公开收集使用规则"}
    _txt = _DF(_row, _IS(state=_SUSPECT, desc="正文自己带句号。"))
    check("★ 疑似/问题的描述不会拼出连续句号", "。。" not in _txt, _txt[:50])
