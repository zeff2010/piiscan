# -*- coding: utf-8 -*-
"""批量下载（zip 打包）与"文件名带 App 名称"的回归测试。

为什么要真起 HTTP 服务、真发请求、真解压，而不是只调函数：
文件名这件事的正确性一半在服务端（怎么拼名字），另一半在协议层
（`Content-Disposition` 里 `filename` 与 `filename*` 两个字段怎么写）。
只测前者，等于没测"浏览器会不会把它显示成一长串 %E7%B1%B3"。

用独立临时 workdir 起服务，不碰 out/platform 里的真实任务。
"""
from __future__ import annotations

import io
import json
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

from webapp.db import JobDB                          # noqa: E402
from webapp.server import (_app_label, _ascii_fallback,   # noqa: E402
                           _disposition, _report_filename, _safe_name)

_ok = 0
_bad = 0


def check(name: str, cond: bool, detail=""):
    global _ok, _bad
    if cond:
        _ok += 1
    else:
        _bad += 1
        print("  [FAIL] %s  %s" % (name, detail))


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _http(url: str, method: str = "GET"):
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def _cd_name(headers: dict) -> str:
    """从 Content-Disposition 里取出真正该用的文件名（优先 filename*）。"""
    cd = headers.get("Content-Disposition") or headers.get("content-disposition") or ""
    for part in cd.split(";"):
        part = part.strip()
        if part.lower().startswith("filename*=utf-8''"):
            return urllib.parse.unquote(part[len("filename*=UTF-8''"):])
    for part in cd.split(";"):
        part = part.strip()
        if part.lower().startswith("filename="):
            return part[len("filename="):].strip('"')
    return ""


# ---------------------------------------------------------------- 纯函数
def test_names():
    job = {"app_label": "米兔", "package": "com.xiaomi.mitu", "created_at": 1761000000,
           "apk_name": "mitu.apk", "id": "J1"}
    n = _report_filename(job)
    check("文件名含 App 名称", "米兔" in n, n)
    check("文件名含包名", "com.xiaomi.mitu" in n, n)
    check("扩展名是 .html", n.endswith(".html"), n)
    check("时间戳在文件名里", "2025" in n or "2026" in n, n)

    # 名称里混进非法字符（APK 的 android:label 什么都可能有）
    bad = dict(job, app_label="米兔/测试:版*本", package="a<b>c")
    nb = _report_filename(bad)
    check("非法字符被清洗", "/" not in nb and ":" not in nb and "*" not in nb
          and "<" not in nb, nb)
    check("清洗后仍保留可读部分", "米兔" in nb, nb)

    # 没装包、也没有 app_label → 退到 APK 文件名
    no_label = {"apk_name": "米兔_v5.4.2.apk", "package": "", "id": "J2",
                "created_at": 1761000000}
    check("无 app_label 时用 APK 文件名", "米兔_v5.4.2" in _report_filename(no_label),
          _report_filename(no_label))

    # 什么都没有 → 用任务号，不能生成 ".html" 这种隐藏文件
    empty = {"id": "J9", "created_at": 1761000000}
    check("全空时退回任务号", _report_filename(empty).startswith("J9"),
          _report_filename(empty))

    check("超长名称被截断", len(_safe_name("あ" * 200, 30)) == 30)
    check("后缀能拼进去", _report_filename(job, "流程存档", ".json").endswith("_流程存档.json"))

    # 响应头：两个 filename 都要有，且 ASCII 那个不能含中文
    cd = _disposition("米兔_com.x_20260101-0000.html", _ascii_fallback(job))
    check("Content-Disposition 含 filename*=UTF-8", "filename*=UTF-8''" in cd, cd)
    check("Content-Disposition 含 ASCII 兜底", 'filename="' in cd, cd)
    check("兜底名是纯 ASCII", cd.split('filename="')[1].split('"')[0].isascii(), cd)
    check("中文名被百分号编码", "%E7%B1%B3" in cd, cd)


# ---------------------------------------------------------------- HTTP
def test_http():
    tmp = Path(tempfile.mkdtemp(prefix="piiscanzip-"))
    work = tmp / "plat"
    work.mkdir(parents=True, exist_ok=True)
    db = JobDB(work / "jobs.db")

    def make(label, pkg, apk_name, status="done", report=True):
        jid = db.create(source="upload", apk_name=apk_name,
                        apk_path=str(work / "x.apk"), run_dynamic=False)
        wd = work / jid
        wd.mkdir(parents=True, exist_ok=True)
        rp = ""
        if report:
            rp = str(wd / "report.html")
            Path(rp).write_text("<html><body>%s</body></html>" % (label or pkg),
                                encoding="utf-8")
            (wd / "flow.json").write_text('{"ok":1}', encoding="utf-8")
        db.update(jid, status=status, app_label=label, package=pkg,
                  version_name="5.4.2", workdir=str(wd),
                  report_path=rp,
                  result_path=str(wd / "flow.json") if report else "")
        return jid

    a = make("米兔", "com.xiaomi.mitu", "mitu.apk")
    b = make("以观书法", "com.yg.sf", "yg.apk")
    # 同名任务（同一 App 跑了两轮）→ 压缩包里必须自动改名，不能互相覆盖
    c = make("米兔", "com.xiaomi.mitu", "mitu.apk")
    # done 但产物被清掉 → 不该进包，但要写进说明文件
    d = make("已清理", "com.gone.app", "gone.apk", report=False)
    # 还在跑 → 没有报告
    e = make("在跑的", "com.running.app", "run.apk", status="running", report=False)

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
                               % (proc.stderr.read().decode("utf-8", "replace")[:400]))

        # ① 列表接口要如实给出 has_report
        st, _h, body = _http(base + "/api/jobs")
        check("列表接口可用", st == 200, st)
        jobs = {j["id"]: j for j in json.loads(body)["jobs"]}
        check("list 返回 has_report=True（有报告的）", jobs[a].get("has_report") is True,
              jobs[a].get("has_report"))
        check("list 返回 has_report=False（产物已清理）", jobs[d].get("has_report") is False,
              jobs[d].get("has_report"))

        # ② 正常打包
        ids = ",".join([a, b, c])
        st, h, data = _http(base + "/api/reports/zip?ids=" + urllib.parse.quote(ids))
        check("打包返回 200", st == 200, st)
        check("Content-Type 是 zip", "zip" in (h.get("Content-Type") or "").lower(),
              h.get("Content-Type"))
        zname = _cd_name(h)
        check("zip 文件名含份数", "3份" in zname, zname)
        check("zip 文件名是 .zip", zname.endswith(".zip"), zname)

        z = zipfile.ZipFile(io.BytesIO(data))
        names = z.namelist()
        check("包里有 3 个报告", len([n for n in names if n.endswith(".html")]) == 3, names)
        check("包内文件名含 App 名称", any("米兔" in n for n in names), names)
        check("包内文件名含另一 App 名称", any("以观书法" in n for n in names), names)
        check("同名任务不互相覆盖", len({n for n in names}) == len(names), names)
        # 同名的第二份应有 (2) 之类的区分
        mt = [n for n in names if "米兔" in n]
        check("同名任务被加了后缀区分", len(set(mt)) == 2 and any("(2)" in n for n in mt), mt)
        check("没有说明文件（全部成功时）", not any(n.startswith("_未打包") for n in names), names)
        check("报告内容正确", b"<html>" in z.read(names[0]))

        # ③ 部分缺产物 → 仍 200，并附说明文件
        st, h, data = _http(base + "/api/reports/zip?ids=" + urllib.parse.quote(
            ",".join([a, d, e])))
        check("部分缺产物仍返回 200", st == 200, st)
        z = zipfile.ZipFile(io.BytesIO(data))
        names = z.namelist()
        check("只打包有报告的那份", len([n for n in names if n.endswith(".html")]) == 1, names)
        check("附了未打包说明", any(n.startswith("_未打包") for n in names), names)
        note = z.read([n for n in names if n.startswith("_未打包")][0]).decode("utf-8")
        # 只断言"点到了具体是哪两项、缺什么"，不断言状态字符串：
        # 服务重启时平台会把遗留的 running 任务收成 failed，状态本来就可能变。
        # 缺件措辞跟着内容走（2026-10-26 起详细版带「详细版」后缀，说明里也写「详细报告」）。
        check("说明里点明缺的是哪项", d in note and e in note and "没有详细报告" in note,
              note[:200])

        # ④ 参数错误 / 无可用产物
        st, _h, _b = _http(base + "/api/reports/zip")
        check("缺 ids 返回 400", st == 400, st)
        st, _h, _b = _http(base + "/api/reports/zip?ids=" + e)
        check("全无报告返回 409", st == 409, st)
        st, _h, _b = _http(base + "/api/reports/zip?ids=" + a + "&fmt=docx")
        check("非法 fmt 返回 400", st == 400, st)

        # ⑤ 单份下载的文件名也要带 App 名称
        st, h, data = _http(base + "/api/jobs/%s/download" % a)
        check("单份下载 200", st == 200, st)
        fn = _cd_name(h)
        check("单份下载文件名含 App 名称", "米兔" in fn, fn)
        check("单份下载文件名含包名", "com.xiaomi.mitu" in fn, fn)

        # ⑥ 流程存档（fmt=json）走同一套命名
        st, _h, data = _http(base + "/api/reports/zip?ids=%s&fmt=json" % a)
        check("流程存档可打包", st == 200, st)
        z = zipfile.ZipFile(io.BytesIO(data))
        check("流程存档名含后缀", any("流程存档" in n for n in z.namelist()), z.namelist())
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    test_names()
    test_http()
    print("=" * 60)
    print("批量下载回归：通过 %d 项，失败 %d 项" % (_ok, _bad))
    sys.exit(1 if _bad else 0)
