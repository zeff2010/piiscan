#!/usr/bin/env python3
"""批量删除任务用例（离线，无需设备）。

批量删除的风险不在"能不能删"，而在**删一半之后界面说得清吗**：
运行中的任务必须拒删、单条失败不能连坐、文件清理失败时记录不能先消失
（那会变成"报告还躺在盘上，任务列表里却查不到它"）。

跑法：python tools/_batch_delete_tests.py
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from webapp.db import MAX_BATCH_DELETE, JobDB


def _mk(db: JobDB, name: str, status: str = "done", with_dir: bool = True) -> str:
    """建一条任务，必要时给它一个真实工作目录（含报告文件）。"""
    jid = db.create(source="upload", apk_name=name)
    fields = {"status": status}
    if with_dir:
        wd = Path(db.path).parent / ("wd_" + jid)
        wd.mkdir(parents=True, exist_ok=True)
        (wd / "report.html").write_text("<html>x</html>", encoding="utf-8")
        fields["workdir"] = str(wd)
    db.update(jid, **fields)
    return jid


def run(check) -> None:
    print("— 批量删除任务")
    with tempfile.TemporaryDirectory() as td:
        db = JobDB(Path(td) / "jobs.db")

        # ---- ① 全部可删：记录 + 工作目录一起清 ----
        ids = [_mk(db, "a%d.apk" % i) for i in range(3)]
        dirs = [Path(db.get(i)["workdir"]) for i in ids]
        r = db.delete_many(ids)
        check("三条全部删除成功", r["ok"] and len(r["deleted"]) == 3, r)
        check("无跳过项", not r["skipped"], r["skipped"])
        check("记录真的没了", all(db.get(i) is None for i in ids))
        check("工作目录一并清理", not any(d.exists() for d in dirs))
        check("回报清理的文件/目录数", r["files"] >= 3, r["files"])

        # ---- ② 混合：运行中的跳过，其余照删（不连坐）----
        ok1, ok2 = _mk(db, "ok1.apk"), _mk(db, "ok2.apk")
        run_id = _mk(db, "running.apk", status="running")
        r = db.delete_many([ok1, run_id, ok2])
        check("部分成功仍算成功", r["ok"] is True, r)
        check("删掉的是两条可删任务", sorted(r["deleted"]) == sorted([ok1, ok2]), r["deleted"])
        check("运行中的进跳过清单", [x["id"] for x in r["skipped"]] == [run_id], r["skipped"])
        check("跳过原因说清要先停止", "先停止" in r["skipped"][0]["reason"], r["skipped"])
        check("运行中的任务仍在库里", db.get(run_id) is not None)

        # ---- ③ 全部不可删：整体失败，且原因可读 ----
        run2 = _mk(db, "running2.apk", status="running")
        r = db.delete_many([run_id, run2])
        check("一条都没删时 ok=False", r["ok"] is False, r)
        check("两条都在跳过清单里", len(r["skipped"]) == 2, r["skipped"])
        check("记录未被误删", db.get(run_id) and db.get(run2))
        db.update(run_id, status="canceled")
        db.update(run2, status="canceled")

        # ---- ④ 不存在的 id：跳过但不影响其他条 ----
        live = _mk(db, "live.apk")
        r = db.delete_many(["J-not-exist", live])
        check("不存在的 id 只进跳过清单",
              [x["id"] for x in r["skipped"]] == ["J-not-exist"], r["skipped"])
        check("同批里的有效任务照删", r["deleted"] == [live], r["deleted"])

        # ---- ⑤ 重复 / 空白 id：去重后只处理一次 ----
        d1 = _mk(db, "dup.apk")
        r = db.delete_many([d1, d1, "", "   ", d1])
        check("重复 id 只删一次", r["deleted"] == [d1], r["deleted"])
        check("requested 计数按去重后算", r["requested"] == 1, r.get("requested"))

        # ---- ⑥ 文件清理失败：记录必须保留（否则等于把报告弄丢）----
        keep_id = _mk(db, "keep.apk")
        real_rmtree = shutil.rmtree

        def boom(*_a, **_k):
            raise PermissionError("文件被占用")

        shutil.rmtree = boom
        try:
            r = db.delete_many([keep_id])
        finally:
            shutil.rmtree = real_rmtree
        check("清理失败时该条进跳过清单",
              [x["id"] for x in r["skipped"]] == [keep_id], r["skipped"])
        check("清理失败时 ok=False", r["ok"] is False, r)
        check("★ 清理失败时记录仍在（报告不会变成孤儿文件）",
              db.get(keep_id) is not None)

        # ---- ⑦ drop_files=False：只删记录，留文件 ----
        db.update(keep_id, status="done")
        wd = Path(db.get(keep_id)["workdir"])
        r = db.delete_many([keep_id], drop_files=False)
        check("只删记录成功", r["ok"] and r["deleted"] == [keep_id], r)
        check("文件按参数保留", wd.exists())
        check("记录已移除", db.get(keep_id) is None)

        # ---- ⑧ 上限保护：防止一次误传清空全部历史 ----
        many = [_mk(db, "m%d.apk" % i, with_dir=False) for i in range(MAX_BATCH_DELETE + 4)]
        r = db.delete_many(many)
        check("单次不超过上限", len(r["deleted"]) == MAX_BATCH_DELETE, len(r["deleted"]))
        check("超出部分有汇总提示",
              any("最多" in (x.get("reason") or "") for x in r["skipped"]),
              r["skipped"][-1:])


if __name__ == "__main__":
    OK = FAIL = 0

    def check(name, cond, got=""):
        global OK, FAIL
        if cond:
            OK += 1
            print("  PASS", name)
        else:
            FAIL += 1
            print("  FAIL", name, "实际：%r" % (got,))

    run(check)
    print("结果：%d 项通过，%d 项失败" % (OK, FAIL))
    raise SystemExit(1 if FAIL else 0)
