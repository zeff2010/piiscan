"""应用商店链接批量提交的自测（由 tools/platform_selftest.py 调用）。

要守住的三件事：

1. **一行一个链接，按提交顺序排队** —— 顺序错了用户无法预判"先测哪个"；
2. **下不到就跳过，且继续跑后面的** —— 批量 20 个链接里坏一个就整批停住，
   等于把工具变成"必须全程盯人"；
3. **跳过必须与"测出问题"分得开** —— 都记成 failed 的话，"8 个里 3 个失败"
   会被读成"3 个 App 有问题"。这是最容易被忽略、后果最严重的一条。
"""
from __future__ import annotations

import json
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path


def _post_multipart(url: str, fields: dict):
    """不引 requests，手搓 multipart —— 平台本身只依赖标准库。"""
    b = "----piiscanBoundary7d1a3f"
    chunks = []
    for k, v in fields.items():
        chunks.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
                       % (b, k, v)).encode("utf-8"))
    body = b"".join(chunks) + ("--%s--\r\n" % b).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "multipart/form-data; boundary=%s" % b})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw}


_MULTI = """# 这行是注释，应被忽略
https://sj.qq.com/appdetail/com.tencent.mm
https://app.mi.com/details?id=com.tencent.mm

https://sj.qq.com/appdetail/com.tencent.mm
https://example.com/app-release.apk
随便写的一行
https://appgallery.huawei.com/app/C100404489
"""


def run(check) -> None:
    from piiscan import storefetch as SF
    from webapp import server as S
    from webapp.db import ALLOWED_ACTIONS, JobDB

    # ---------------- 纯函数：链接列表解析 ----------------
    ok, skipped = SF.parse_url_list(_MULTI)
    check("多行输入只保留受支持的商店链接", len(ok) == 3, ok)
    check("按输入顺序保留", ok[0].startswith("https://sj.qq.com")
          and ok[-1].startswith("https://appgallery"), ok)
    check("注释行不算跳过项", not any(s["url"].startswith("#") for s in skipped),
          skipped)
    reasons = {s["url"]: s["reason"] for s in skipped}
    check("重复链接被合并并说明原因",
          "重复" in reasons.get("https://sj.qq.com/appdetail/com.tencent.mm", ""),
          reasons)
    check("APK 直链提示改用直链入口",
          "直链" in reasons.get("https://example.com/app-release.apk", ""), reasons)
    check("非 http 行被拒绝",
          "http" in reasons.get("随便写的一行", ""), reasons)

    # 七个市场都要能认出来（认不出就等于这个市场没接）
    for url, market in [
        ("https://sj.qq.com/appdetail/com.a.b", "应用宝"),
        ("https://appgallery.huawei.com/app/C100404489", "华为应用市场"),
        ("https://h5.appstore.vivo.com.cn/#/details?app_id=123", "vivo 应用商店"),
        ("https://app.mi.com/details?id=com.a.b", "小米应用商店"),
        ("https://shouji.baidu.com/item?docid=123", "百度手机助手"),
        ("https://www.wandoujia.com/apps/com.a.b", "豌豆荚"),
        ("https://zhushou.360.cn/detail?id=123", "360手机助手"),
    ]:
        try:
            got = SF.pick_adapter(url)[0]
        except SF.StoreError as e:
            got = "ERR:%s" % e
        check("识别市场：%s" % market, got == market, got)

    try:
        SF.pick_adapter("https://play.google.com/store/apps/details?id=com.a.b")
        check("不支持的市场要报错", False, "没有抛异常")
    except SF.StoreError as e:
        check("不支持的市场要报错", "不支持" in str(e), str(e)[:60])

    over, over_sk = SF.parse_url_list(
        "\n".join("https://sj.qq.com/appdetail/com.x%d" % i for i in range(SF.MAX_BATCH_URLS + 3)))
    check("超过单次上限的部分被挡下", len(over) == SF.MAX_BATCH_URLS, len(over))
    check("超限原因写清楚", any("上限" in s["reason"] for s in over_sk), over_sk[:1])

    # ---------------- 任务库：store_url 与「已跳过」 ----------------
    tmp = Path(tempfile.mkdtemp(prefix="piiscan_store_"))
    db = JobDB(tmp / "jobs.db")
    jid = db.create(source="store", store_url="https://sj.qq.com/appdetail/com.a.b",
                    apk_name="https://sj.qq.com/appdetail/com.a.b")
    row = db.get(jid) or {}
    check("store_url 落库", row.get("store_url", "").startswith("https://sj.qq.com"), row)
    check("新建任务是排队中", row.get("status") == "queued", row.get("status"))
    check("已跳过可重试、可删除",
          set(ALLOWED_ACTIONS.get("skipped", ())) == {"retry", "delete"},
          ALLOWED_ACTIONS.get("skipped"))
    check("列表接口带出 store_url",
          any(j.get("store_url") for j in db.list()), [j.get("store_url") for j in db.list()])

    # ---------------- 端到端：提交多行 → 两条任务 → 下不到就跳过 ----------------
    S.Handler.db = db
    S.Handler.workdir = tmp
    S.Handler.device_enabled = True
    httpd = S.ThreadingHTTPServer(("127.0.0.1", 0), S.Handler)
    httpd.quiet = True
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]

    orig_fetch = SF.fetch
    # 桩：模拟"市场不提供下载" —— 这是最常见的一种失败，必须整批继续往下跑。
    SF.fetch = lambda url, dest, **kw: SF.FetchResult(
        ok=False, source="store", url=url, error="测试桩：该应用网页端不提供下载")

    worker = S.Worker(db, tmp)
    worker.start()
    try:
        st, body = _post_multipart(base + "/api/jobs",
                                   {"store_urls": _MULTI, "run_dynamic": "0"})
        ids = body.get("job_ids") or []
        check("多行提交返回 201", st == 201 and body.get("ok") is True, body)
        check("一条链接建一个任务", len(ids) == 3, body)
        check("非法行在提交时就挡下并说明原因",
              len(body.get("skipped") or []) == 3, body.get("skipped"))

        deadline = time.time() + 25
        while time.time() < deadline:
            rows = [db.get(i) for i in ids]
            if all(r and r["status"] in ("skipped", "failed", "done") for r in rows):
                break
            time.sleep(0.2)
        rows = [db.get(i) for i in ids]
        check("下不到的三条都收尾（不会一直卡在排队）",
              all(r["status"] in ("skipped", "failed", "done") for r in rows),
              [(r["status"], r.get("stage")) for r in rows])
        check("下不到记为「已跳过」而不是「失败」",
              all(r["status"] == "skipped" for r in rows),
              [r["status"] for r in rows])
        check("跳过原因写进任务记录",
              all("不提供下载" in (r.get("error") or "") for r in rows),
              [r.get("error") for r in rows])
        check("跳过的任务不产出报告",
              all(not r.get("report_path") for r in rows),
              [r.get("report_path") for r in rows])
        check("跳过也记进了任务日志",
              any("已跳过" in (r.get("log") or "") for r in rows),
              [((r.get("log") or "")[-80:]) for r in rows])

        # 队列继续：再投一条纯邮件地址行 → 直接 400 说清楚，不建任务
        st2, body2 = _post_multipart(base + "/api/jobs",
                                     {"store_urls": "这不是链接\n# 注释", "run_dynamic": "0"})
        check("一条可用链接都没有时直接报错",
              st2 == 400 and "没有可提交" in (body2.get("error") or ""), body2)
    finally:
        SF.fetch = orig_fetch
        worker.stop()
        httpd.shutdown()
