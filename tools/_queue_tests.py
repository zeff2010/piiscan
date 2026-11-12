"""排队顺序与「置顶到队头」的自测（离线，不碰真机）。

这一组用例守的是一句话：
**置顶只改一条任务的顺序，其它任务的相对先后一动不动。**

为什么要专门测：置顶如果做成"把别人往后推"，出错时不会报错，
只会让队列悄悄乱掉 —— 而队列乱掉的表现是"我明明置顶了，跑的却是另一条"，
下一次就没人敢用这个按钮了。
"""
from __future__ import annotations

import json
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path


def _order(db):
    """当前排队顺序（按 next_queued 的同一口径，不真的改状态）。"""
    with db._c() as c:
        rows = c.execute(
            "SELECT id FROM jobs WHERE status='queued' "
            "ORDER BY COALESCE(queue_seq, created_at) ASC, created_at ASC, id ASC"
        ).fetchall()
    return [r["id"] for r in rows]


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


def run(check):
    from webapp.db import JobDB

    tmp = Path(tempfile.mkdtemp(prefix="piiscan_queue_"))
    db = JobDB(tmp / "jobs.db")

    def mk(n=1, tag=""):
        return [db.create(source="test", apk_name="%s%d.apk" % (tag, i),
                          apk_url="http://example.com/%s%d.apk" % (tag, i))
                for i in range(n)]

    # ---------- 1. 基础顺序 = 先来先跑 ----------
    a, b, c = mk(3, "a")
    check("三条新任务按提交先后排队", _order(db) == [a, b, c], _order(db))
    pos = {j["id"]: j["queue_pos"] for j in db.list()}
    check("列表里的队列名次 1/2/3",
          (pos.get(a), pos.get(b), pos.get(c)) == (1, 2, 3),
          (pos.get(a), pos.get(b), pos.get(c)))

    # ---------- 2. 置顶：只动一条 ----------
    r = db.bump_queue(c)
    check("置顶成功并给了说明", r.get("ok") and "下一个" in (r.get("note") or ""), r)
    check("置顶后排到第一个", _order(db) == [c, a, b], _order(db))
    check("其它两条的相对顺序没变（a 仍在 b 前）",
          _order(db).index(a) < _order(db).index(b), _order(db))

    # 再置顶 a：连续置顶时"最后指的那条先跑"
    db.bump_queue(a)
    check("连续置顶：后置顶的排更前", _order(db) == [a, c, b], _order(db))
    check("连续置顶后排尾次序仍稳定", _order(db)[-1] == b, _order(db))

    # 队列名次跟着变
    pos = {j["id"]: j["queue_pos"] for j in db.list()}
    check("名次随置顶一起变（a=1, c=2, b=3）",
          (pos.get(a), pos.get(c), pos.get(b)) == (1, 2, 3),
          (pos.get(a), pos.get(c), pos.get(b)))

    # ---------- 3. 不该能置顶的状态要明确拒绝 ----------
    db.update(b, status="running")
    r = db.bump_queue(b)
    check("运行中的任务不能置顶", not r.get("ok") and "排队中" in (r.get("error") or ""), r)
    db.update(b, status="queued")

    r = db.bump_queue("NOT-EXIST")
    check("不存在的任务置顶报错", not r.get("ok") and "不存在" in (r.get("error") or ""), r)

    # ---------- 4. 重新入队排到队尾（不能借"暂停/重试"插队）----------
    # 先把上一节剩下的排队任务清空：留着的话它们会混进下面的顺序断言里，
    # 失败信息看起来像"队列乱了"，实际是用例自己没收拾干净。
    for jid in _order(db):
        db.update(jid, status="done")
    a, b, c = mk(3, "b")
    db.request(a, "pause")
    check("暂停后不在排队序列里", a not in _order(db), _order(db))
    db.request(a, "resume")
    check("恢复后排到队尾，而不是插回原位", _order(db) == [b, c, a], _order(db))

    db.update(b, status="done")          # 假装跑完了
    db.request(b, "retry")
    check("重试旧任务排到队尾，不占队头", _order(db) == [c, a, b], _order(db))

    # ---------- 5. 只有一条时置顶不报错、也不改动 ----------
    d1 = db.create(source="test", apk_name="only.apk", apk_url="http://example.com/o.apk")
    for jid in _order(db):
        if jid != d1:
            db.update(jid, status="done")
    r = db.bump_queue(d1)
    check("队列里只有一条时置顶是空操作", r.get("ok") and "只有这一条" in (r.get("note") or ""), r)
    check("空操作后它仍然是第一个", _order(db) == [d1], _order(db))

    # ---------- 6. HTTP 端口径一致 ----------
    from webapp import server as S
    S.Handler.db = db
    S.Handler.workdir = tmp
    S.Handler.device_enabled = False
    httpd = S.ThreadingHTTPServer(("127.0.0.1", 0), S.Handler)
    httpd.quiet = True
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        x, y = mk(2, "h")
        st, body = _json(base + "/api/jobs/" + y + "/front", {})
        check("POST /front 返回 200", st == 200 and body.get("ok"), (st, body))
        check("接口置顶后 y 排第一", _order(db).index(y) == 0, _order(db))

        st, body = _json(base + "/api/jobs/NOT-EXIST/front", {})
        check("不存在的任务 → 404", st == 404, (st, body))

        db.update(x, status="running")
        st, body = _json(base + "/api/jobs/" + x + "/front", {})
        check("运行中置顶 → 409 并写原因",
              st == 409 and "排队中" in json.dumps(body, ensure_ascii=False), (st, body))
        # 跑完的任务不该有名次：名次是"排队里第几位"，不在队列里的必须是 0，
        # 否则界面上会给已完成的任务也写一句"队列第 3 位"。
        db.update(x, status="done")

        # 列表接口必须带上 queue_pos，否则界面写不出"第几位"
        st, body = _json(base + "/api/jobs")
        jobs = {j["id"]: j for j in (body.get("jobs") or [])}
        check("列表带 queue_pos", bool(jobs.get(y)) and jobs[y].get("queue_pos") == 1,
              jobs.get(y, {}).get("queue_pos"))
        check("非排队任务 queue_pos 为 0",
              bool(jobs.get(x)) and jobs[x].get("queue_pos", -1) == 0,
              jobs.get(x, {}).get("queue_pos"))
    finally:
        httpd.shutdown()
        httpd.server_close()
