"""界面分页相关用例（2026-11-11）。

起因：用户提的两个功能问题修完之后，界面本身还是「统计 + 设备 + 表单 +
任务列表」全挤在一张长页上 —— 交任务要滚到中段，盯进度要滚到底部。
按用户要求改成侧边栏 + 三页：系统状态（默认）/ 新建任务 / 任务列表，
提交成功后自动跳到任务列表。

这里守的是**结构约定**，不是像素：
  · 三个页容器与三个菜单项一一对应，缺一个就等于有一页点不到；
  · 默认落地页必须是系统状态（用户明确指定）；
  · 统计/设备/表单/列表各自归属正确的页 —— 搬错页不会报错，只会"点了没反应"；
  · JS 里 `$("#xxx")` 引用的元素必须真的存在：拆页时最容易漏掉某个 id，
    而漏掉的表现是整段脚本在那一行抛异常、后面的绑定全部失效；
  · 提交流程里"成功才跳转"，失败留在表单页看错误；
  · 窄屏下侧栏必须退出 flex 行（实测过一次：只改 .sidebar 不改 .shell，
    侧栏会变成挤掉正文的左列，且菜单条飘到页面中间）。
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "webapp" / "static" / "index.html"

PAGES = ("status", "new", "jobs", "devices")


def _html() -> str:
    return HTML.read_text(encoding="utf-8")


def _page_slice(h: str, name: str) -> str:
    """取某个页 section 的片段。

    不能用 `<section ...>(.*?)</section>`：表单页里还嵌着
    `<section class="sect">`（高级选项），非贪婪匹配会提前收尾，
    把「开始检测」按钮截在外面。
    """
    i = h.find('id="page-%s"' % name)
    if i < 0:
        return ""
    j = h.find('<section class="page"', i + 10)
    k = h.find("</main>", i)
    ends = [x for x in (j, k) if x > 0]
    return h[i:min(ends)] if ends else h[i:]


def run(check):
    _t_pages(check)
    _t_default_page(check)
    _t_ownership(check)
    _t_ids(check)
    _t_submit_jump(check)
    _t_report_preview(check)
    _t_narrow(check)


def _t_pages(check):
    h = _html()
    for name in PAGES:
        check("页面容器存在：page-%s" % name, 'id="page-%s"' % name in h, "")
    pos = [h.find('id="page-%s"' % n) for n in PAGES]
    # 顺序：系统状态 → 新建任务 → 任务列表 → 手机管理。
    # 「手机管理」放最后而不是插在中间：用户的三个主流程（看状态/交任务/盯任务）
    # 顺序不该被一个新功能打乱，管理类功能放末尾更像"设置"。
    check("四页按「状态 → 新建 → 列表 → 手机管理」排列",
          all(p > 0 for p in pos) and pos == sorted(pos), pos)

    # 菜单项：三个、且 data-page 与页容器一一对应。
    # 注意分页按钮也用 data-page（按页码），所以只找 nav 里的 <a>。
    for name in PAGES:
        check("菜单项 data-page=%s 存在" % name,
              'href="#/%s" data-page="%s"' % (name, name) in h, "")
    m = re.search(r'<nav class="nav" id="nav">([\s\S]*?)</nav>', h)
    navbody = m.group(1) if m else ""
    check("侧栏菜单恰为 4 项", navbody.count("<a ") == 4, navbody.count("<a "))


def _t_default_page(check):
    h = _html()
    # 用户要求：进入后默认页是系统状态
    check("无 hash 时默认落到系统状态",
          'return PAGES[h] ? h : "status";' in h, "")
    check("启动时按 hash 落地（首屏即默认页）",
          "go(hashPage(), true);" in h, "")
    check("菜单点击不新增浏览历史（replaceState）",
          "history.replaceState(null, \"\", \"#/\" + name)" in h, "")


def _t_ownership(check):
    """每个区块必须在它该在的那一页。搬错页不会报错，只会"点了没反应"。"""
    h = _html()
    st, nw, jb = _page_slice(h, "status"), _page_slice(h, "new"), _page_slice(h, "jobs")
    check("能切出三个页的片段", all((st, nw, jb)), [len(st), len(nw), len(jb)])
    check("统计卡在系统状态页", 'id="stats"' in st, "")
    check("检测环境/设备卡在系统状态页", 'id="devgrid"' in st and 'id="envcheck"' in st, "")
    check("测试机下拉与档位在新建任务页", 'id="device"' in nw and 'id="depth"' in nw, "")
    check("「开始检测」按钮在新建任务页", 'id="submit"' in nw, "")
    check("任务列表在任务列表页", 'id="list"' in jb, "")
    check("报告预览容器在任务列表页", 'id="preview"' in jb and 'id="frame"' in jb, "")
    # 报告预览会把页面标题改成"检测报告预览"，标题必须在这一页里
    check("页面标题（#panel-title）在任务列表页 —— 预览复用这个标题",
          'id="panel-title"' in jb, "")


def _t_ids(check):
    """JS 引用的 id 必须都存在。拆页时最容易漏掉某个 id，
    而漏掉的表现是脚本在那行抛异常、后面的绑定全部失效（页面"看着正常、点着不动"）。"""
    h = _html()
    js = h.split("<script>", 1)[1]
    used = set(re.findall(r'\$\("#([\w\-]+)"\)', js))
    used |= set(re.findall(r'getElementById\("([\w\-]+)"\)', js))
    have = set(re.findall(r'id="([\w\-]+)"', h))
    # 运行时才创建的：toast（轻提示）、back（报告预览的返回按钮），
    # 以及「添加手机」向导里的那些 —— 它们由 wizPick / wizRenderRun 用
    # innerHTML 生成，静态页里不存在，但脚本会去 $() 取。
    runtime = {"back", "toast", "wiz-alias", "wiz-phone", "wiz-dl", "wiz-go",
               "wiz-done", "wiz-new", "wiz-retry", "wiz-rescan", "wiz-close2"}
    miss = sorted(used - have - runtime)
    check("JS 引用的元素 id 都真实存在（%d 个）" % len(used), not miss, miss)

    # 这几个是 $("#" + id) 动态拼出来的，静态正则抓不到，单独查。
    # 模型连接相关的四个 id（ai_provider / ai_base_url / ai_model / ai_vision_model）
    # 已随「模型服务搬到系统状态页」移除（2026-11-12）—— 留在这里的只有
    # 任务级的节流参数，它们仍然是动态拼的。
    for cid in ("ai_ui_agent_every", "ai_ui_agent_max_calls"):
        check("动态拼接的 id 存在：%s" % cid, 'id="%s"' % cid in h, "")

    # 重复 id 只在**静态 HTML** 里查：向导那几个按钮的 id 出现在 JS 字符串里
    # （if/else 两个分支各写一个 `id="wiz-done"`，同一时刻只会存在一个），
    # 拿整份文件数会把它们误报成重复。
    static_h = re.sub(r"<script[\s\S]*?</script>", "", h)
    dup = sorted(k for k in have
                 if len(re.findall(r'id="%s"' % re.escape(k), static_h)) > 1)
    check("没有重复 id", not dup, dup)


def _t_submit_jump(check):
    h = _html()
    check("提交成功后自动跳到任务列表", 'if (created > 0) go("jobs");' in h, "")
    i = h.find("if (xhr.status === 201 && r.ok)")
    j = h.find('if (created > 0) go("jobs");')
    k = h.find("xhr.onerror")
    check("跳转写在提交成功分支内（失败留在表单页看错误）",
          i > 0 and j > i and (k < 0 or j < k), [i, j, k])
    # 跳走以后红框看不见，被跳过的链接要用轻提示说
    check("跳页同时用轻提示说明被跳过的链接",
          'if (created > 0) toast(_msg); else showErr(_msg);' in h, "")


def _t_report_preview(check):
    h = _html()
    check("点「查看」会先确保在任务列表页",
          'if (CUR_PAGE !== "jobs") go("jobs", false);' in h, "")
    check("预览态再点「任务列表」菜单＝回到列表",
          'a.dataset.page === "jobs" && lastReport && $("#back")' in h, "")
    check("返回列表时标题恢复为「任务列表」",
          '"任务列表"' in h and 'id="panel-title">任务列表<' in h, "")


def _t_narrow(check):
    """窄屏下侧栏要退出 flex 行。

    实测踩过一次：媒体查询里只写了 .sidebar{position:sticky;width:auto;
    flex-direction:row}，没管 .shell{display:flex} —— 侧栏仍然作为
    flex 子项占住左侧一列（760px 屏吃掉一半宽度），菜单条还飘到页面中间。
    """
    h = _html()
    m = re.search(r"@media\(max-width:900px\)\{([\s\S]*?)\n\}", h)
    check("存在窄屏媒体查询", bool(m), "")
    body = m.group(1) if m else ""
    check("窄屏下 .shell 回到 block（侧栏不再占一列）",
          re.search(r"\.shell\{display:block;\}", body) is not None, "")
    check("窄屏下侧栏改为 sticky 横条",
          "position:sticky" in body and "flex-direction:row" in body, "")
    check("窄屏下正文取消左侧留白", re.search(r"\.main\{margin-left:0", body) is not None, "")
