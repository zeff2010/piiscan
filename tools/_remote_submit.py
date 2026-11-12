#!/usr/bin/env python3
"""在服务器本机提交一个作业（流式 multipart，不把 140MB APK 读进内存）。

用途：服务器上验收一次端到端。为什么不从开发机 curl：被测 APK 已经在
服务器 `out/platform/_uploads/` 里，再经内网上传一遍纯属浪费；而平台只
接受 multipart 文件或 apk_url，没有"用服务器上已有文件"的入口。

用法：
  python3 tools/_remote_submit.py <apk路径> [policy_url]
"""
from __future__ import annotations

import http.client
import json
import os
import sys
import time
import uuid

HOST, PORT = "127.0.0.1", 8760


def submit(apk: str, policy_url: str, fields: dict) -> str:
    boundary = "----piiscan" + uuid.uuid4().hex
    parts = []
    for k, v in fields.items():
        parts.append(
            ("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
             % (boundary, k, v)).encode("utf-8"))
    name = os.path.basename(apk)
    parts.append(
        ("--%s\r\nContent-Disposition: form-data; name=\"apk_file\"; filename=\"%s\"\r\n"
         "Content-Type: application/vnd.android.package-archive\r\n\r\n"
         % (boundary, name)).encode("utf-8"))
    head = b"".join(parts)
    tail = ("\r\n--%s--\r\n" % boundary).encode("utf-8")
    size = len(head) + os.path.getsize(apk) + len(tail)

    c = http.client.HTTPConnection(HOST, PORT, timeout=1800)
    c.putrequest("POST", "/api/jobs")
    c.putheader("Content-Type", "multipart/form-data; boundary=" + boundary)
    c.putheader("Content-Length", str(size))
    c.endheaders()
    c.send(head)
    with open(apk, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            c.send(b)
    c.send(tail)
    r = c.getresponse()
    body = r.read().decode("utf-8", "replace")
    c.close()
    if r.status not in (200, 201):
        raise SystemExit("提交失败 %s: %s" % (r.status, body[:400]))
    d = json.loads(body)
    return d.get("job_id") or (d.get("job") or {}).get("id")


def poll(job_id: str, limit: float = 900) -> dict:
    t0 = time.time()
    last = ""
    while time.time() - t0 < limit:
        c = http.client.HTTPConnection(HOST, PORT, timeout=60)
        c.request("GET", "/api/jobs/" + job_id)
        r = c.getresponse()
        job = json.loads(r.read().decode("utf-8")).get("job") or {}
        c.close()
        st = "%s %s%% %s" % (job.get("status"), job.get("progress"), job.get("stage"))
        if st != last:
            print("  … " + st, flush=True)
            last = st
        if job.get("status") in ("done", "failed", "canceled", "cancelled"):
            return job
        time.sleep(3)
    raise SystemExit("等待超时")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    apk = sys.argv[1]
    url = sys.argv[2] if len(sys.argv) > 2 else ""
    f = {"run_dynamic": "0", "duration": "90", "policy_wait": "22"}
    if url:
        f["policy_url"] = url
    jid = submit(apk, url, f)
    print("job:", jid, flush=True)
    job = poll(jid)
    keep = {k: job.get(k) for k in
            ("status", "findings", "high", "mid", "low", "checked", "skipped",
             "report_path", "result_path", "duration", "error")}
    print(json.dumps(keep, ensure_ascii=False, indent=2))
