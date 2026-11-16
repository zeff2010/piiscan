#!/usr/bin/env python3
"""APK 共享存储用例（离线，无需设备、无需网络）。

这块的风险不在"能不能存"，而在**删不删得对**：
  · 同一个包被三条任务共用时，删掉第一条不能把文件带走；
  · 最后一个引用走了，文件必须真的消失（否则"删任务省空间"是空话）；
  · 使用者可以把根目录指到已有内容的盘（D:\\我的资料），那里面的东西一个都不能碰 ——
    所以护栏是"路径在根内" + "文件名符合本层命名"两条同时成立。

跑法：python tools/_apk_store_tests.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from piiscan import apkstore
from webapp.db import JobDB

SHA_A = "a" * 64
SHA_B = "b" * 64


def _mkfile(p: Path, size: int = 1024) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"PK\x03\x04" + b"x" * (size - 4))
    return p


def _job(db: JobDB, apk_path: str = "", apk_store: str = "", name="a.apk") -> str:
    jid = db.create(source="upload", apk_name=name,
                    apk_path=apk_path, apk_store=apk_store,
                    apk_size=os.path.getsize(apk_path) if apk_path and Path(apk_path).exists() else 0)
    db.update(jid, status="done")
    return jid


def run(check) -> None:
    print("— APK 共享存储")

    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        work = base / "out" / "platform"
        work.mkdir(parents=True)
        db = JobDB(base / "jobs.db")

        # ---- ① 根目录：默认 / 自定义 / 恢复默认 ----
        check("默认根目录在工作目录下的 apk/",
              apkstore.root(db, work) == work / apkstore.DEFAULT_DIRNAME,
              apkstore.root(db, work))
        custom = base / "另一个盘" / "apk"
        v = apkstore.validate_dir(str(custom))
        check("自定义目录校验通过并创建", v["ok"] and custom.is_dir(), v)
        db.meta_set(apkstore.META_KEY, v["path"])
        check("配置后 root 生效", str(apkstore.root(db, work)) == str(custom),
              apkstore.root(db, work))
        db.meta_set(apkstore.META_KEY, "")
        check("清空配置回到默认", apkstore.root(db, work) == work / "apk",
              apkstore.root(db, work))

        # ---- ② 目录校验的拒绝路径 ----
        check("相对路径被拒绝", not apkstore.validate_dir("apk")["ok"])
        root_drive = Path(os.path.abspath(os.sep))
        check("磁盘根目录被拒绝", not apkstore.validate_dir(str(root_drive))["ok"],
              str(root_drive))
        afile = _mkfile(base / "not_a_dir.apk", 64)
        r = apkstore.validate_dir(str(afile))
        check("指向一个文件时拒绝", not r["ok"] and "文件" in r["error"], r)

        # ---- ③ 落盘命名与去重 ----
        store = base / "store"
        apkstore.ensure(store)
        inc = apkstore.incoming_dir(store)
        inc.mkdir(parents=True, exist_ok=True)

        src1 = _mkfile(inc / "first.apk", 2048)
        r1 = apkstore.adopt(src1, store, key=SHA_A, filename="微信 8.0.apk")
        check("落盘成功", r1["ok"] and Path(r1["path"]).exists(), r1)
        check("首次落盘不标记复用", r1["reused"] is False, r1)
        p1 = Path(r1["path"])
        check("目录是哈希前两位", p1.parent.name == SHA_A[:2], p1.parent.name)
        check("文件名校验：12 位哈希 + ASCII 原名",
              p1.name.startswith(SHA_A[:12] + "_") and p1.name.endswith(".apk"), p1.name)
        check("中文原名被转成 ASCII", "微信" not in p1.name, p1.name)
        check("临时文件已从 .incoming 移走", not src1.exists(), src1)

        src2 = _mkfile(inc / "second.apk", 2048)
        r2 = apkstore.adopt(src2, store, key=SHA_A, filename="微信-again.apk")
        check("同内容第二次落盘标记复用", r2["ok"] and r2["reused"] is True, r2)
        check("复用返回同一个路径", r2["path"] == r1["path"], (r1["path"], r2["path"]))
        check("同内容只留一份（临时文件被丢弃）", not src2.exists(), src2)
        apks = [p for p in store.rglob("*.apk") if p.is_file()]
        check("磁盘上只有一个包文件", len(apks) == 1, apks)

        # ---- ④ 护栏：哪些路径允许删 ----
        check("托管文件可识别", apkstore.is_managed_path(p1, store), p1)
        outside = _mkfile(base / "我的资料" / "重要.apk", 128)
        check("根目录之外的文件不算托管",
              not apkstore.is_managed_path(outside, store), outside)
        # 使用者把根设成"我的资料"时，目录里原本的文件仍然不能被当成托管文件
        r = apkstore.validate_dir(str(base / "我的资料"))
        check("非空目录也允许作为根（只有本层命名的文件才归它管）", r["ok"], r)
        check("同目录里的既有文件不在保护区外",
              not apkstore.is_managed_path(outside, base / "我的资料"), outside)

        # ---- ⑤ 引用计数：三条任务共用一个包 ----
        # 走真实的 db.delete（先按引用判断、再删记录），不直接调 release：
        # 直接调 release 时任务记录还在库里，计数不会变，测出来的东西不对。
        j1 = _job(db, r1["path"], str(store))
        j2 = _job(db, r1["path"], str(store))
        j3 = _job(db, r1["path"], str(store))
        check("三条任务指向同一路径", db.apk_refs(r1["path"]) == 3, db.apk_refs(r1["path"]))

        o1 = db.delete(j1)
        check("还有别人在用时不删文件", p1.exists() and not o1["removed"], o1)
        check("并回报被几个任务留着", o1["apk_kept_by"] == 2, o1)
        check("原因写明保留", "保留" in (o1.get("apk_note") or ""), o1.get("apk_note"))

        o2 = db.delete(j2)
        check("删到还剩一个时仍保留", p1.exists() and o2["apk_kept_by"] == 1, o2)

        o3 = db.delete(j3)
        check("最后一个引用离开才真删", any(str(p1) == x for x in (o3.get("removed") or [])), o3)
        check("文件确实不在了", not p1.exists(), p1)

        # ---- ⑥ 不该删的情况 ----
        keep = _mkfile(base / "用户自己的.apk", 64)
        rel = apkstore.release(db, "J-x", str(keep), str(store))
        check("路径不在托管根内 → 一律不删", keep.exists(), rel)
        rel = apkstore.release(db, "J-x", str(keep), "")
        check("没有托管根（历史任务）→ 不删", keep.exists(), rel)
        check("（历史任务不要假装删了）", rel["removed"] == "", rel)

        # ---- ⑦ 删任务真的会把包删掉（走 db.delete）----
        src3 = _mkfile(inc / "third.apk", 4096)
        r3 = apkstore.adopt(src3, store, key=SHA_B, filename="独立.apk")
        j4 = _job(db, r3["path"], str(store), name="独立.apk")
        p4 = Path(r3["path"])
        out = db.delete(j4)
        check("删任务连带删掉包", out["ok"] and not p4.exists(), out)
        check("删除回报里列出被删的文件",
              any(str(p4) == x for x in (out.get("removed") or [])), out.get("removed"))

        # ---- ⑧ 占用统计与孤儿 ----
        u = apkstore.usage(store)
        check("统计能跑通且形式正确", isinstance(u["files"], int) and isinstance(u["bytes"], int), u)
        orphan = _mkfile(store / SHA_B[:2] / ("%s_%s.apk" % (SHA_B[:12], "orphan")), 128)
        orph = apkstore.orphans(db, store)
        check("无主文件被识别", any(o["path"] == str(orphan) for o in orph), orph)
        sw = apkstore.sweep(db, store)
        check("清理掉无主文件", not orphan.exists(), sw)
        check("清理有数量回报", sw["count"] >= 1 and sw["bytes"] > 0, sw)

        # ---- ⑨ .incoming：新的不动，老的清 ----
        fresh = _mkfile(apkstore.incoming_dir(store) / "downloading.apk", 256)
        old = _mkfile(apkstore.incoming_dir(store) / "stale.apk", 256)
        past = time.time() - 48 * 3600
        os.utime(old, (past, past))
        apkstore.sweep(db, store)
        check("正在下载的残片不能被清掉", fresh.exists(), fresh)
        check("两天前的残片会被清掉", not old.exists(), old)

        # ---- ⑩ 目录不可用时给出可读原因 ----
        r = apkstore.adopt(inc / "不存在.apk", store, key=SHA_A)
        check("源文件不存在时返回失败而不是抛异常",
              r["ok"] is False and r["error"], r)
        r = apkstore.adopt(_mkfile(inc / "tmp.apk", 32), store, key="不合法")
        check("哈希不合法时拒绝改名", r["ok"] is False and "哈希" in r["error"], r)

    # ---- ⑪ 端到端：真走一次 HTTP 上传，确认落在哪、删任务是否带走 ----
    _e2e_upload(check)


def _post_file(url: str, fields: dict, filename: str, content: bytes):
    """不引 requests：平台本身只依赖标准库，测试也照做。"""
    b = "----piiscanBoundaryApk01"
    parts = []
    for k, v in fields.items():
        parts.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
                      % (b, k, v)).encode("utf-8"))
    parts.append(("--%s\r\nContent-Disposition: form-data; name=\"apk_file\"; "
                  "filename=\"%s\"\r\nContent-Type: application/vnd.android."
                  "package-archive\r\n\r\n" % (b, filename)).encode("utf-8")
                 + content + b"\r\n")
    parts.append(("--%s--\r\n" % b).encode("utf-8"))
    body = b"".join(parts)
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "multipart/form-data; boundary=%s" % b})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw}


def _e2e_upload(check) -> None:
    """端到端：上传 → 落进共享目录 → 删任务 → 文件随之消失。

    不启 worker：这里要验的是"建任务这一侧"的记账，跑起来反而会去连设备。
    """
    from webapp import server as S
    from webapp.db import JobDB

    tmp = Path(tempfile.mkdtemp(prefix="piiscan_apkstore_"))
    try:
        db = JobDB(tmp / "jobs.db")
        S.Handler.db = db
        S.Handler.workdir = tmp
        S.Handler.device_enabled = True
        httpd = S.ThreadingHTTPServer(("127.0.0.1", 0), S.Handler)
        httpd.quiet = True
        httpd.daemon_threads = True
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = "http://127.0.0.1:%d" % httpd.server_address[1]
        apk_bytes = b"PK\x03\x04" + b"payload" * 200

        try:
            st, body = _post_file(base + "/api/jobs",
                                  {"run_dynamic": "0", "policy_wait": "5"},
                                  "端到端测试包.apk", apk_bytes)
            check("上传建任务成功", st == 201 and body.get("ok") is True, body)
            jid = body.get("job_id") or ""
            row = db.get(jid) or {}
            check("任务里记录了 APK 绝对路径", bool(row.get("apk_path")), row.get("apk_path"))
            check("任务里记录了托管根目录", bool(row.get("apk_store")), row.get("apk_store"))
            check("上传也算出了内容哈希（用于去重）",
                  bool(row.get("sha256")) and bool(row.get("md5")), row.get("sha256"))
            p = Path(row.get("apk_path") or "")
            check("文件真的在那个路径上", p.exists(), p)
            # 落在 <root>/<hash前2位>/ 下，而不是任务目录里
            check("文件落在共享目录里", str(p.parent.parent) == str(apkstore.root(db, tmp)),
                  (p.parent.parent, apkstore.root(db, tmp)))
            check("任务目录里没有第二份副本",
                  not (tmp / jid / "input").exists(), tmp / jid / "input")
            check("旧的 _uploads 不再产生文件",
                  not (tmp / "_uploads").exists()
                  or not any((tmp / "_uploads").iterdir()), tmp / "_uploads")

            # 同内容再传一次：应该复用同一个文件
            st2, body2 = _post_file(base + "/api/jobs",
                                    {"run_dynamic": "0", "policy_wait": "5"},
                                    "同一个包换个名字.apk", apk_bytes)
            jid2 = body2.get("job_id") or ""
            row2 = db.get(jid2) or {}
            check("第二条任务建成", st2 == 201 and bool(jid2), body2)
            check("同内容复用同一个文件", row2.get("apk_path") == row.get("apk_path"),
                  (row.get("apk_path"), row2.get("apk_path")))
            apks = [x for x in apkstore.root(db, tmp).rglob("*.apk") if x.is_file()]
            check("盘上只有一个包文件", len(apks) == 1, apks)

            # 删第一条：文件必须留下（第二条还在用）
            req = urllib.request.Request(base + "/api/jobs/" + jid, method="DELETE")
            with urllib.request.urlopen(req, timeout=15) as r:
                d1 = json.loads(r.read().decode())
            check("删第一条时文件保留", d1.get("ok") and p.exists(), d1)
            check("并告知还有几个任务在用", d1.get("apk_kept_by") == 1, d1)

            req = urllib.request.Request(base + "/api/jobs/" + jid2, method="DELETE")
            with urllib.request.urlopen(req, timeout=15) as r:
                d2 = json.loads(r.read().decode())
            check("最后一条删掉后文件消失", not p.exists(), p)
            check("删除回报里带上了这个文件", bool(d2.get("removed")), d2)

            # ---- 存储配置接口：看 / 换 / 非法 / 清理 / 回默认 ----
            # 先留一个包在默认目录里：换目录时的提示要能说清"旧文件不搬"，
            # 目录空着走的是另一条文案，测不出来。
            stk, bodyk = _post_file(base + "/api/jobs",
                                    {"run_dynamic": "0", "policy_wait": "5"},
                                    "留在原处的包.apk", b"PK\x03\x04" + b"k" * 250)
            keep_path = Path((db.get(bodyk.get("job_id") or "") or {}).get("apk_path") or "")
            check("准备：默认目录里有一个包", stk == 201 and keep_path.exists(), keep_path)

            with urllib.request.urlopen(base + "/api/storage", timeout=15) as r:
                s0 = json.loads(r.read().decode())
            check("/api/storage 报出当前位置", s0.get("ok") and bool(s0.get("dir")), s0)
            check("没配过时标为默认位置", s0.get("is_default") is True, s0)
            check("报出占用与孤儿数",
                  isinstance(s0.get("files"), int) and isinstance(s0.get("orphans"), int), s0)

            def _setdir(v):
                rq = urllib.request.Request(
                    base + "/api/storage", method="POST",
                    data=json.dumps({"dir": v}).encode("utf-8"),
                    headers={"Content-Type": "application/json"})
                try:
                    with urllib.request.urlopen(rq, timeout=30) as r:
                        return r.status, json.loads(r.read().decode())
                except urllib.error.HTTPError as e:
                    return e.code, json.loads(e.read().decode())

            newdir = tmp / "另一个位置"
            st1, s1 = _setdir(str(newdir))
            check("切换到新目录", st1 == 200 and s1.get("ok") is True, s1)
            check("校验后路径指向新目录",
                  str(Path(s1.get("dir") or "").resolve()).lower()
                  == str(newdir.resolve()).lower(), s1)
            check("换目录时说明旧文件不搬移",
                  "保留" in (s1.get("note") or ""), s1.get("note"))

            st3, body3 = _post_file(base + "/api/jobs",
                                    {"run_dynamic": "0", "policy_wait": "5"},
                                    "另一个包.apk", b"PK\x03\x04" + b"x" * 300)
            row3 = db.get(body3.get("job_id") or "") or {}
            check("新上传落到新目录",
                  str(Path(row3.get("apk_path") or "").parent.parent).lower()
                  == str(newdir).lower(), row3.get("apk_path"))

            stx, sx = _setdir("相对路径")
            check("相对路径被接口挡下", stx == 400 and not sx.get("ok"), sx)

            rq = urllib.request.Request(base + "/api/storage/sweep", method="POST",
                                        data=b"{}",
                                        headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(rq, timeout=30) as r:
                sw = json.loads(r.read().decode())
            check("清理接口可用", sw.get("ok") is True, sw)

            sty, sy = _setdir("")
            check("空值＝恢复默认位置",
                  sty == 200
                  and str(sy.get("dir") or "").lower()
                  == str(apkstore.default_root(tmp)).lower(), sy)
        finally:
            httpd.shutdown()
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


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
