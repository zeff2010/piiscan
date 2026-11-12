"""端到端：商店链接 → 排队 → 下载 → 检测 → 报告；下不到的自动跳过。

会真装真测（用的是连接的测试机），跑一次约 3~5 分钟。

用法（开发机）：
    python -u tools/_e2e_store.py                # 真机动态采集
    python -u tools/_e2e_store.py --no-dynamic   # 只做静态 + 政策，不碰设备
"""
import json
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from webapp import server as S            # noqa: E402
from webapp.db import JobDB               # noqa: E402

URLS = """https://sj.qq.com/appdetail/com.tencent.qqpinyin
https://app.mi.com/details?id=com.tencent.qqpinyin
https://example.com/whatever.apk
"""


def main() -> int:
    dyn = "1" if "--no-dynamic" not in sys.argv else "0"
    tmp = Path(tempfile.mkdtemp(prefix="piiscan_e2e_store_", dir=str(ROOT / "out")))
    db = JobDB(tmp / "jobs.db")
    S.Handler.db = db
    S.Handler.workdir = tmp
    S.Handler.device_enabled = True
    httpd = S.ThreadingHTTPServer(("127.0.0.1", 0), S.Handler)
    httpd.quiet = True
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]

    b = "----e2eboundary9f"
    body = b"".join([
        ("--%s\r\nContent-Disposition: form-data; name=\"store_urls\"\r\n\r\n%s\r\n"
         % (b, URLS)).encode(),
        ("--%s\r\nContent-Disposition: form-data; name=\"run_dynamic\"\r\n\r\n%s\r\n"
         % (b, dyn)).encode(),
        ("--%s\r\nContent-Disposition: form-data; name=\"duration\"\r\n\r\n90\r\n"
         % b).encode(),
        ("--%s--\r\n" % b).encode(),
    ])
    req = urllib.request.Request(base + "/api/jobs", data=body, method="POST",
                                 headers={"Content-Type":
                                          "multipart/form-data; boundary=%s" % b})
    with urllib.request.urlopen(req, timeout=30) as r:
        out = json.loads(r.read().decode())
    print("提交结果:", json.dumps({k: out.get(k) for k in ("created", "skipped")},
                                   ensure_ascii=False))
    ids = out.get("job_ids") or []
    for s in out.get("skipped") or []:
        print("  未提交:", s["url"], "->", s["reason"])

    w = S.Worker(db, tmp)
    w.start()
    seen = {}
    deadline = time.time() + 900
    try:
        while time.time() < deadline:
            rows = [db.get(i) for i in ids]
            for r in rows:
                key = (r["id"], r["status"], r.get("stage"))
                if seen.get(r["id"]) != key:
                    seen[r["id"]] = key
                    print("[%s] %s / %s" % (r["id"][-6:], r["status"], r.get("stage")))
            if all(r["status"] in ("done", "failed", "skipped", "canceled")
                   for r in rows):
                break
            time.sleep(2)
    finally:
        w.stop()
        httpd.shutdown()

    print("\n=== 最终 ===")
    for r in [db.get(i) for i in ids]:
        print("%s  %s" % (r["id"], r["status"]))
        print("   应用=%s 包名=%s 版本=%s" % (r.get("app_label"), r.get("package"),
                                            r.get("version_name")))
        if r.get("error"):
            print("   原因=%s" % r["error"][:160])
        if r.get("report_path"):
            print("   报告=%s" % r["report_path"])
        if r.get("scan_path"):
            print("   采集存档=%s" % r["scan_path"])
    print("\n工作目录:", tmp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
