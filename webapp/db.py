"""平台数据层：SQLite 任务表。

只依赖标准库。所有写操作走同一把锁，读操作独立连接，够单机多任务用。

## 任务状态机

    queued ──pause──▶ paused ──resume──▶ queued
      │                 │
      │                 └──cancel──▶ canceled
      ├──cancel──▶ canceled
      └──(worker 取走)──▶ running
                            ├──完成──▶ done
                            ├──异常──▶ failed
                            ├──cancel 请求──▶ canceled
                            └──pause 请求──▶ paused

`req` 列是**运行中任务的请求信箱**：worker 在采集循环里轮询它，
看到非空就把当前阶段收尾、按请求落到 canceled / paused。

为什么要用轮询而不是直接杀线程：采集过程中持有 frida 会话、adb 管道、
设备上的 hook，硬杀线程会把这些全留在中间态（设备上还开着 hook、
进程还在被 spawn 挂起），下一轮检测直接受影响。协作式收尾慢 1~2 秒，
但设备状态是干净的。
"""
from __future__ import annotations

import json
import shutil
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Sequence

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id            TEXT PRIMARY KEY,
    created_at    REAL NOT NULL,
    started_at    REAL,
    finished_at   REAL,
    status        TEXT NOT NULL DEFAULT 'queued',
    stage         TEXT DEFAULT '',
    progress      INTEGER DEFAULT 0,

    source        TEXT DEFAULT 'upload',
    apk_name      TEXT DEFAULT '',
    apk_path      TEXT DEFAULT '',
    apk_url       TEXT DEFAULT '',
    -- 应用商店详情页链接（应用宝/华为/vivo/小米/百度/豌豆荚/360）。
    -- 与 apk_url 分开存：apk_url 是"能直接下到 APK 的直链"，
    -- 这个是"要先去页面里解析出直链"的商店链接，两者的失败模式完全不同。
    store_url     TEXT DEFAULT '',
    apk_size      INTEGER DEFAULT 0,
    md5           TEXT DEFAULT '',
    sha256        TEXT DEFAULT '',

    package       TEXT DEFAULT '',
    app_label     TEXT DEFAULT '',
    version_name  TEXT DEFAULT '',

    policy_url    TEXT DEFAULT '',
    policy_text   TEXT DEFAULT '',
    run_dynamic   INTEGER DEFAULT 1,
    duration      INTEGER DEFAULT 90,
    reset_app     INTEGER DEFAULT 1,
    policy_wait   INTEGER DEFAULT 22,
    -- 登录辅助：测试手机号。给了就在遍历遇到登录页时代填，
    -- 验证码由检测人员通过 POST /api/jobs/<id>/sms 回填到工作目录的 sms.txt。
    login_phone   TEXT DEFAULT '',
    -- 发现问题后是否清数据重跑一轮做复现（会多用一轮采集时间）
    repro         INTEGER DEFAULT 1,
    -- 检测深度：normal / deep。存字符串而不是布尔，将来加"极深"档不用改表。
    depth         TEXT DEFAULT 'normal',
    -- 指定在哪台测试机上跑（adb 序列号）。空串 = 沿用 config.yaml 的 device.serial，
    -- 也就是"自动"：只有一台在线时用它，多台时明确拒绝（不替用户猜）。
    -- 必须落在任务行里而不是只放内存：任务排队时选的是 A 机，执行时插着 A、B 两台，
    -- 若这时再按"当前唯一在线设备"去推，装包与截图就会跑到 B 机上。
    device        TEXT DEFAULT '',

    findings      INTEGER DEFAULT 0,
    high          INTEGER DEFAULT 0,
    mid           INTEGER DEFAULT 0,
    low           INTEGER DEFAULT 0,
    checked       INTEGER DEFAULT 0,
    skipped       INTEGER DEFAULT 0,

    report_path   TEXT DEFAULT '',
    result_path   TEXT DEFAULT '',
    scan_path     TEXT DEFAULT '',
    workdir       TEXT DEFAULT '',

    -- AI 选项按 JSON 整体存一列。
    -- 为什么不再拆成一堆列：AI 的选项会随功能演进不断增加（模型地址、模型名、
    -- 视觉模型、各类开关、超时…），每加一个选项就改一次表结构既啰嗦又容易漏迁移。
    -- 整块 JSON 存下来，读取端做默认值合并即可，扩展成本接近零。
    ai_opts       TEXT DEFAULT '',

    -- 运行中任务的请求信箱：'' / 'pause' / 'cancel'
    req           TEXT DEFAULT '',
    -- 最近一次"进度有变化"的时刻。stage/progress 每更新一次就刷新一次。
    -- 无人值守时最危险的不是报错，而是"看起来还在跑"：进度条停在 74%、
    -- 状态仍是 running、日志也停在一小时前 —— 没有这个字段就无法把
    -- "正在慢慢跑"和"已经卡死"区分开。
    heartbeat_at  REAL,
    paused_at     REAL,
    error         TEXT DEFAULT '',
    log           TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);

-- 测试机登记簿（2026-11-11 用户要求"能增删手机"）。
--
-- 在此之前设备是隐式的：adb 里有什么，平台就显示什么，没有"这台机属于
-- 这个平台"的概念 —— 于是没法记别名、没法记号码、更没法表达
-- "这台机我不在平台上用了"。
--
-- ★ 这里只存**接入那一刻的事实**，不存"现在是否已 root"：
--   `verified_at` / `root_ok` 写的是"某时刻验证通过过"，
--   而"此刻能不能用"必须由实时探测判断（见 piiscan/devices.py::usable）。
--   把历史事实当现状用，就会在手机被取消 root 之后继续断言"已 root"。
CREATE TABLE IF NOT EXISTS devices (
    serial       TEXT PRIMARY KEY,
    alias        TEXT DEFAULT '',
    phone        TEXT DEFAULT '',
    note         TEXT DEFAULT '',
    added_at     REAL NOT NULL,
    verified_at  REAL,
    -- 接入时是否真的拿到过 uid=0（不是"看到了 su 文件"）
    root_ok      INTEGER DEFAULT 0,
    degraded     INTEGER DEFAULT 0,
    model        TEXT DEFAULT '',
    brand        TEXT DEFAULT '',
    android      TEXT DEFAULT '',
    sdk          TEXT DEFAULT '',
    abi          TEXT DEFAULT '',
    frida_ver    TEXT DEFAULT '',
    -- 上次接入的步骤摘要。删掉设备就一起删掉：它描述的是那台机。
    last_steps   TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_devices_added ON devices(added_at ASC);

-- AI 模型服务的配置档案（2026-11-12 用户要求）。
--
-- 在此之前模型地址/模型名/密钥只写在 config.yaml 里：换一台机器、换一个
-- 模型服务都要改文件并重启，而使用者未必碰得到那个文件。现在改成
-- "一份档案一条记录"，界面上可以保存多套（本机 Ollama / DeepSeek / 内网 vLLM），
-- 用哪一套由 app_meta.ai_active 指定 —— 比改文件可查、可回退、可删除。
--
-- ★ api_key 只存在本机 SQLite 里，接口一律不回传明文（只回 has_key）。
--   这不是加密存储（本地平台没有可以安全存放主密钥的地方），
--   但至少不会出现在浏览器、日志、报告里。
CREATE TABLE IF NOT EXISTS ai_profiles (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    provider     TEXT NOT NULL DEFAULT 'ollama',
    base_url     TEXT DEFAULT '',
    model        TEXT DEFAULT '',
    vision_model TEXT DEFAULT '',
    api_key      TEXT DEFAULT '',
    note         TEXT DEFAULT '',
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL,
    last_used_at REAL
);
CREATE INDEX IF NOT EXISTS idx_ai_profiles_created ON ai_profiles(created_at ASC);

-- 平台级的小配置（当前只有 ai_active：当前启用的档案 id）。
-- 单独一张 K/V 表而不是塞进 config.yaml：这是"运行时选择"，
-- 改它不该需要重启服务，也不该和部署配置混在一起。
CREATE TABLE IF NOT EXISTS app_meta (
    k TEXT PRIMARY KEY,
    v TEXT DEFAULT ''
);
"""

ACTIVE = ("queued", "running")

# 追加列迁移：老库（CREATE TABLE IF NOT EXISTS 不会补列）需要手工 ALTER
_MIGRATIONS = {
    "reset_app": "ALTER TABLE jobs ADD COLUMN reset_app INTEGER DEFAULT 1",
    "policy_wait": "ALTER TABLE jobs ADD COLUMN policy_wait INTEGER DEFAULT 22",
    "ai_opts": "ALTER TABLE jobs ADD COLUMN ai_opts TEXT DEFAULT ''",
    "req": "ALTER TABLE jobs ADD COLUMN req TEXT DEFAULT ''",
    "paused_at": "ALTER TABLE jobs ADD COLUMN paused_at REAL",
    "scan_path": "ALTER TABLE jobs ADD COLUMN scan_path TEXT DEFAULT ''",
    "heartbeat_at": "ALTER TABLE jobs ADD COLUMN heartbeat_at REAL",
    "store_url": "ALTER TABLE jobs ADD COLUMN store_url TEXT DEFAULT ''",
    "login_phone": "ALTER TABLE jobs ADD COLUMN login_phone TEXT DEFAULT ''",
    "repro": "ALTER TABLE jobs ADD COLUMN repro INTEGER DEFAULT 1",
    "depth": "ALTER TABLE jobs ADD COLUMN depth TEXT DEFAULT 'normal'",
    "device": "ALTER TABLE jobs ADD COLUMN device TEXT DEFAULT ''",
    # 排队序（不是 created_at）。置顶＝把这个值改到比队头更小，
    # 这样"其它任务的相对顺序保持不变"是天然的：只动一行。
    "queue_seq": "ALTER TABLE jobs ADD COLUMN queue_seq REAL",
}

# 状态中文名。前端也有一份，这里是给日志和 API 用的权威版本。
STATUS_LABELS = {
    "queued": "排队中", "running": "检测中", "paused": "已暂停",
    "canceled": "已停止", "done": "已完成", "failed": "失败",
    # skipped：这一条根本没测（链接解析不出直链 / 应用下架 / 市场不提供网页下载）。
    # ★ 不能记成 failed 也不能记成 done：failed 会让人以为是"测了但有问题"，
    #   而 done 更糟 —— 批量提交时那等于把"没测"混进"测过"里。
    "skipped": "已跳过",
}

# 这些状态下允许的操作。UI 与 API 都以它为准，避免前端硬编码判断漂移。
ALLOWED_ACTIONS = {
    # front＝置顶到队头。只在排队中才有意义：跑着的任务没法"提前"，
    # 已暂停的也不在队列里（要先把 state 推回 queued）。
    "queued": ("front", "pause", "cancel", "delete"),
    "paused": ("resume", "cancel", "delete"),
    "running": ("pause", "cancel"),
    "canceled": ("retry", "delete"),
    "failed": ("retry", "delete"),
    "skipped": ("retry", "delete"),
    "done": ("retry", "delete"),
}

# 单次批量删除上限。不是性能考虑（几十条也只是几秒的 rmtree），
# 而是防误操作：一个 URL 传错把所有历史作业清空，报告无法重建。
MAX_BATCH_DELETE = 200


class JobDB:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._c() as c:
            c.executescript(SCHEMA)
            self._migrate(c)

    @staticmethod
    def _migrate(c: sqlite3.Connection) -> None:
        have = {r["name"] for r in c.execute("PRAGMA table_info(jobs)").fetchall()}
        for col, ddl in _MIGRATIONS.items():
            if col not in have:
                try:
                    c.execute(ddl)
                except sqlite3.OperationalError:
                    pass
        # queue_seq 的口径必须与"没有它"时的行为完全一致：老任务的排队序就是
        # 创建时间。不补这一次，历史任务全是 NULL —— 在 ORDER BY 里 NULL 排最前，
        # 于是随便一条几周前的旧任务都会插到新任务前面，队列看起来像被随机打乱。
        c.execute("UPDATE jobs SET queue_seq=created_at "
                  "WHERE queue_seq IS NULL")

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    @contextmanager
    def _c(self):
        """一次用完就关的连接。

        ★ 不能用 `with sqlite3.connect(...) as c:` —— 那个上下文只管
          提交/回滚，**不关连接**。此前所有方法都那么写，于是每次请求都留下
          一个没关的句柄：跑久了文件句柄耗尽；Windows 上更直接的后果是
          删任务目录时报 WinError 32（数据库文件还被自己占着），
          "删除任务"就永远失败。
        """
        c = self._conn()
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    # ------------------------------------------------------------ 写
    def create(self, *, source: str, apk_name: str = "", apk_url: str = "",
               store_url: str = "",
               apk_path: str = "", apk_size: int = 0,
               policy_url: str = "", policy_text: str = "",
               run_dynamic: bool = True, duration: int = 90,
               reset_app: bool = True, policy_wait: int = 22,
               login_phone: str = "", repro: bool = True, depth: str = "normal",
               device: str = "",
               ai_opts: str = "", workdir: str = "") -> str:
        """建任务。

        `apk_path` / `apk_size` 必须在**同一条 INSERT** 里写进去：
        拆成 create + update 两步会留下一个竞态窗口 —— 任务已进入 queued，
        但 apk_path 还是空的，worker 此刻取走就会判定「没有 APK」而失败。

        `store_url` 同理：它决定了 worker 走哪条获取 APK 的路径，
        不能等建完任务再补写（补写之前那一瞬 worker 可能已经取走了）。
        """
        job_id = "J" + time.strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:6]
        now = time.time()
        with self._lock, self._c() as c:
            c.execute(
                "INSERT INTO jobs(id,created_at,status,source,apk_name,apk_url,"
                "store_url,apk_path,apk_size,"
                "policy_url,policy_text,run_dynamic,duration,reset_app,policy_wait,"
                "login_phone,repro,depth,device,ai_opts,workdir,queue_seq) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (job_id, now, "queued", source, apk_name, apk_url,
                 store_url or "", apk_path or "", int(apk_size or 0),
                 policy_url, policy_text, 1 if run_dynamic else 0, int(duration),
                 1 if reset_app else 0, int(policy_wait), login_phone or "",
                 1 if repro else 0, (depth or "normal"), (device or "").strip(),
                 ai_opts or "", workdir, now))
        return job_id

    def update(self, job_id: str, **fields: Any) -> None:
        if not fields:
            return
        # 任何一次阶段/进度更新都算"还活着"。由这里统一打点，
        # 而不是让调用方各自记得传 —— 漏一处心跳就会误报卡死。
        # （日志行同样算活着，见 append_log —— 遍历阶段主要靠日志刷心跳。）
        if "stage" in fields or "progress" in fields:
            fields.setdefault("heartbeat_at", time.time())
        cols = ", ".join("%s=?" % k for k in fields)
        vals = list(fields.values()) + [job_id]
        with self._lock, self._c() as c:
            c.execute("UPDATE jobs SET %s WHERE id=?" % cols, vals)

    def append_log(self, job_id: str, line: str, live: bool = True) -> None:
        """追加一行日志。`live=True` 时同时刷新"还活着"的时间戳。

        ★ 为什么把"存活"挂在日志上（用户 2026-10-21 提的第二条）：
          以前只有 stage/progress 变化才刷新心跳，于是**正在一步步遍历**的任务
          —— 百分比停在 53% 不动、但每几秒就打一行「点击」「AI 决策」——
          被看门狗判成"20 分钟没有变化"，还劝人去查设备连接。
          遍历本来就是"百分比慢慢爬、日志一直在刷"的形态，
          判断死活要看**有没有在干活**，不是看数字有没有变。

          `live=False` 留给看门狗自己写提醒用 —— 否则它每提醒一次就把
          心跳刷新一次，从此再也提醒不了第二次。
        """
        with self._lock, self._c() as c:
            row = c.execute("SELECT log FROM jobs WHERE id=?", (job_id,)).fetchone()
            cur = (row["log"] if row else "") or ""
            cur = (cur + line + "\n")[-60000:]     # 只保留尾部，避免无限增长
            if live:
                c.execute("UPDATE jobs SET log=?, heartbeat_at=? WHERE id=?",
                          (cur, time.time(), job_id))
            else:
                c.execute("UPDATE jobs SET log=? WHERE id=?", (cur, job_id))

    # ------------------------------------------------------------ 状态机
    def request(self, job_id: str, kind: str) -> Dict[str, Any]:
        """给任务投递一个请求（pause / cancel）。返回 (ok, msg, job)。

        · 排队中/已暂停的任务不需要请求信箱，直接改状态即可；
        · 运行中的任务只写 `req`，由 worker 在采集循环里看到后协作收尾。
        """
        job = self.get(job_id)
        if not job:
            return {"ok": False, "error": "任务不存在"}
        st = job["status"]

        if kind == "pause":
            if st == "queued":
                self.update(job_id, status="paused", req="",
                            paused_at=time.time(), stage="已暂停")
                return {"ok": True, "status": "paused",
                        "note": "任务未开始，已暂停"}
            if st == "running":
                self.update(job_id, req="pause")
                return {"ok": True, "status": "running",
                        "note": "已发出暂停请求，将在当前阶段收尾后停下"
                                "（采集过程不可续，恢复时会重新执行本轮）"}
            return {"ok": False, "error": "当前状态（%s）不能暂停"
                                          % STATUS_LABELS.get(st, st), "status": st}

        if kind == "cancel":
            if st in ("queued", "paused"):
                self.update(job_id, status="canceled", req="", finished_at=time.time(),
                            stage="已停止", error=job.get("error") or "")
                return {"ok": True, "status": "canceled", "note": "任务已停止"}
            if st == "running":
                self.update(job_id, req="cancel")
                return {"ok": True, "status": "running",
                        # 不再承诺"1~2 秒"：注入调用卡在设备上时（应用黑屏/无响应），
                        # frida 的同步调用本身没有超时，得等看门狗强制收工。
                        # 宁可说清"可能需要一分钟"，也不要让人以为按钮没反应。
                        # 2026-11-12：模型调用改为可中断（0.25 秒内抛错），
                        # 所以"AI 卡住"这一种不再需要等超时。
                        "note": "已发出停止请求：正在进行的模型调用会立即中断；"
                                "若注入调用卡在设备上，会在 1 分钟内强制收工，"
                                "随后自动卸载被测应用"}
            return {"ok": False, "error": "当前状态（%s）不能停止"
                                          % STATUS_LABELS.get(st, st), "status": st}

        if kind == "resume":
            if st != "paused":
                return {"ok": False, "error": "只有已暂停的任务可以恢复", "status": st}
            self.update(job_id, status="queued", req="", paused_at=None,
                        stage="排队中", progress=0,
                        # 重新入队排到**队尾**（queue_seq 取当前时刻）：暂停一会儿再恢复
                        # 却插回原位，会让"暂停"变成插队手段，对后面排着的人不公平。
                        queue_seq=time.time(),
                        # 上一轮的失败/中断原因必须清掉：不清的话界面会一直挂着
                        # "UI 遍历阶段被中断"这类旧原因，和当前状态对不上。
                        error="", finished_at=None)
            return {"ok": True, "status": "queued", "note": "已重新排队（排到队尾）"}

        if kind == "retry":
            if st in ("queued", "running", "paused"):
                return {"ok": False, "error": "任务尚未结束，无需重试", "status": st}
            # 重试 = 同参数重新排队；上一轮的产物保留在 workdir 里，
            # 新一轮会覆盖同名报告，所以先把旧的挪开（不删，留作对比）。
            self._archive_products(job_id)
            self.update(job_id, status="queued", req="", stage="排队中", progress=0,
                        started_at=None, finished_at=None, error="",
                        # 同 resume：重试是"现在"入队，不该顶到几周前那条任务的位置上。
                        queue_seq=time.time(),
                        report_path="", result_path="", scan_path="")
            return {"ok": True, "status": "queued", "note": "已重新排队（排到队尾）"}

        return {"ok": False, "error": "未知操作：%s" % kind}

    def _archive_products(self, job_id: str) -> None:
        """把上一轮的报告/存档改名留档，避免被新一轮覆盖掉。"""
        job = self.get(job_id) or {}
        wd = job.get("workdir") or ""
        if not wd:
            return
        d = Path(wd)
        if not d.exists():
            return
        ts = time.strftime("%Y%m%d-%H%M%S")
        for name in ("report.html", "report_brief.html", "flow.json",
                     "scan.result.json"):
            p = d / name
            if p.exists():
                try:
                    p.rename(d / ("%s.prev-%s" % (name, ts)))
                except Exception:
                    pass

    def take_request(self, job_id: str) -> str:
        with self._c() as c:
            row = c.execute("SELECT req FROM jobs WHERE id=?", (job_id,)).fetchone()
        return (row["req"] if row else "") or ""

    def clear_request(self, job_id: str, **extra: Any) -> None:
        self.update(job_id, req="", **extra)

    # ------------------------------------------------------------ 读
    def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._c() as c:
            row = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return dict(row) if row else None

    def list(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._c() as c:
            rows = c.execute(
                "SELECT id,created_at,started_at,finished_at,status,stage,progress,"
                "source,apk_name,apk_url,store_url,apk_size,package,app_label,version_name,"
                "findings,high,mid,low,checked,skipped,error,req,run_dynamic,"
                "report_path,heartbeat_at,device "
                "FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
            # 队列名次（1 = 下一个开跑）。★ 按与 next_queued 完全相同的排序算，
            # 否则界面写"第 1 位"而实际跑的是另一条 —— 置顶这个功能一旦显示不准，
            # 就没人敢用它。
            qrows = c.execute(
                "SELECT id FROM jobs WHERE status='queued' "
                "ORDER BY COALESCE(queue_seq, created_at) ASC, created_at ASC, id ASC"
            ).fetchall()
        qpos = {r["id"]: i + 1 for i, r in enumerate(qrows)}
        now = time.time()
        out = []
        for r in rows:
            d = dict(r)
            d["actions"] = list(ALLOWED_ACTIONS.get(d["status"], ()))
            # 报告真的存在才置 True —— 前端据此决定「下载」「批量下载」是否可用。
            # 只看 status=="done" 是不够的：产物可能被清过（删了 workdir、
            # 迁移过目录），此时点下载会得到 409，人却不知道是为什么。
            # 只对 done 的任务做 stat：其余状态本来就不该有报告，
            # 200 条列表每行一次磁盘检查在机械盘上会明显拖慢轮询。
            rp = d.pop("report_path", "") or ""
            d["has_report"] = bool(rp) and d["status"] == "done" and Path(rp).exists()
            # 简版报告与详细报告同目录（`report_brief.html`）。它**不是**下载入口的
            # 前提：历史任务没有这个文件，服务端可以按 flow.json 现补一份。
            # 这里只如实说明"文件是否已存在"，前端不要拿它决定能不能点。
            d["has_brief"] = (bool(d["has_report"])
                              and Path(rp).with_name("report_brief.html").exists())
            # 距上次进度变化过去了多久（秒）。前端据此在进度条旁标黄，
            # 让"卡住了"这件事在界面上是可见的，而不是靠人盯着时钟猜。
            hb = d.pop("heartbeat_at", None)
            d["stall"] = int(now - hb) if (d["status"] == "running" and hb) else 0
            d["queue_pos"] = qpos.get(d["id"], 0)
            out.append(d)
        return out

    def next_queued(self) -> Optional[Dict[str, Any]]:
        """取一条待执行任务，并**原子地**置为 running。

        ★ 为什么不是「先 SELECT 再 UPDATE」：
          两个执行者（两个服务进程，或以后可能的多进程执行器）会同时
          SELECT 到同一条，然后各自 UPDATE 成功 —— 于是**同一个任务被跑两遍**。
          这比两个不同任务同时跑更糟：两个进程同时装同一个包、抢同一个
          frida 端口，报告还会互相覆盖。
          条件更新（`AND status='queued'`）由 SQLite 保证只有一个能成功，
          抢输的一方返回 None，等下一轮再取。
        """
        with self._lock, self._c() as c:
            # 排队序用 queue_seq 而不是 created_at：置顶时只改一行的 queue_seq，
            # 其它任务的相对顺序一动不动（这正是用户要的语义）。
            # created_at 作为并列时的兜底，保证同一时刻创建的两条也有稳定次序。
            row = c.execute(
                "SELECT id FROM jobs WHERE status='queued' "
                "ORDER BY COALESCE(queue_seq, created_at) ASC, created_at ASC, id ASC "
                "LIMIT 1").fetchone()
            if not row:
                return None
            now = time.time()
            cur = c.execute(
                "UPDATE jobs SET status='running', started_at=?, req='', "
                "stage='启动中', progress=1, heartbeat_at=? "
                "WHERE id=? AND status='queued'", (now, now, row["id"]))
            if cur.rowcount != 1:
                return None      # 被另一个执行者抢走了
            fresh = c.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone()
            if not fresh:
                return None
            d = dict(fresh)
        d["status"] = "running"
        d["req"] = ""
        return d

    def bump_queue(self, job_id: str) -> Dict[str, Any]:
        """把一条排队中的任务挪到队头：**下一个**就是它。

        ★ 为什么是"改排序值"而不是"把别人的 created_at 往后推"：
          后者要动 N 行，中途出错就是一个半乱序的队列，而且"其它任务的相对顺序
          保持不变"这件事会变成需要证明的性质。改一行 queue_seq 到 `MIN-1`，
          相对顺序在数学上就不可能被破坏。

        ★ 连续置顶的语义：每一次都取当时的 `MIN-1`，所以"先置顶 A、再置顶 B"
          的结果是 B 在 A 前面 —— 与"我最后指的那条马上跑"的直觉一致。

        ★ 只在 queued 上生效：跑着的没法提前（采集已经开始了），
          已暂停的不在队列里（它连队都没排）。
        """
        with self._lock, self._c() as c:
            row = c.execute("SELECT id,status FROM jobs WHERE id=?",
                            (job_id,)).fetchone()
            if not row:
                return {"ok": False, "error": "任务不存在"}
            if row["status"] != "queued":
                return {"ok": False, "status": row["status"],
                        "error": "只有排队中的任务可以置顶（当前：%s）"
                                 % STATUS_LABELS.get(row["status"], row["status"])}
            mn = c.execute(
                "SELECT MIN(COALESCE(queue_seq, created_at)) AS m FROM jobs "
                "WHERE status='queued' AND id<>?", (job_id,)).fetchone()
            head = mn["m"] if mn else None
            if head is None:                   # 队列里只有它自己
                return {"ok": True, "status": "queued",
                        "note": "队列里只有这一条，无需置顶"}
            c.execute("UPDATE jobs SET queue_seq=? WHERE id=? AND status='queued'",
                      (float(head) - 1.0, job_id))
            if c.execute("SELECT changes() AS n").fetchone()["n"] != 1:
                return {"ok": False, "error": "任务状态已变化，请刷新后重试"}
        return {"ok": True, "status": "queued", "note": "已置顶，下一个就轮到它"}

    def cleanup_stale(self) -> int:
        """进程重启后把卡在 running 的任务标记为失败。

        ★ 这里不只是改状态：上一轮进程可能是被强杀的，设备上还装着被测 App、
           frida 会话也还挂着。所以启动时把这件事写进 error，提醒操作者
           下一轮检测前先手动确认设备状态（无法自动卸载是因为此时不知道包名
           是否装成功，卸载反而可能删掉不该删的东西）。
        """
        with self._lock, self._c() as c:
            cur = c.execute(
                "UPDATE jobs SET status='failed', req='', "
                "error='服务重启导致任务中断（上一轮可能未完成卸载，下一轮检测前请确认设备状态）', "
                "finished_at=? WHERE status='running'", (time.time(),))
            return cur.rowcount

    def delete(self, job_id: str, drop_files: bool = True) -> Dict[str, Any]:
        """删除任务记录；默认连工作目录（报告、存档、APK 副本）一起清理。

        为什么默认连文件一起删：报告里含被测 App 的采集数据（含设备标识符原值），
        留着不管等同于把样本永久留在服务器上。使用者点"删除"的预期就是"清掉"。
        """
        job = self.get(job_id)
        if not job:
            return {"ok": False, "error": "任务不存在"}
        if job["status"] == "running":
            return {"ok": False, "error": "任务正在执行，请先停止再删除"}
        removed = []
        wd = job.get("workdir") or ""
        if drop_files and wd:
            d = Path(wd)
            if d.exists() and d.is_dir():
                try:
                    shutil.rmtree(d)
                    removed.append(str(d))
                except Exception as e:
                    return {"ok": False, "error": "删除工作目录失败：%s" % e}
        # 上传的 APK 副本在 <workdir>/_uploads 下，记录里存的是绝对路径
        apk = job.get("apk_path") or ""
        if drop_files and apk and job.get("source") == "upload":
            p = Path(apk)
            if p.exists() and "_uploads" in str(p):
                try:
                    p.unlink()
                    removed.append(str(p))
                except Exception:
                    pass
        with self._lock, self._c() as c:
            c.execute("DELETE FROM jobs WHERE id=?", (job_id,))
        return {"ok": True, "removed": removed}

    def delete_many(self, job_ids: Sequence[str],
                    drop_files: bool = True) -> Dict[str, Any]:
        """批量删除，逐条处理、单条失败不连坐。

        为什么不做成一个 `DELETE ... WHERE id IN (...)`：
        每条任务背后有一个工作目录（报告 + 采集存档 + APK 副本），文件清理
        可能失败，运行中的任务必须拒删。一条 SQL 删完记录、文件留下一地，
        比不删更糟 —— 报告里有设备标识符原值，用户以为清了其实还在盘上。
        所以逐条走 `delete()`，把每一侧的成败都如实回报给界面。

        返回值里 `deleted` 与 `skipped` 分开，前端据此说清"删了哪些、哪些没删、
        为什么"（一律成功或一律失败的二元反馈会让用户以为全删干净了）。
        """
        deleted: List[str] = []
        skipped: List[Dict[str, str]] = []
        files = 0
        seen = set()
        for raw in job_ids or ():
            jid = str(raw or "").strip()
            if not jid or jid in seen:
                continue
            seen.add(jid)
            if len(seen) > MAX_BATCH_DELETE:
                # 超出部分不再逐条列举，否则一次误传几千个 id 会生成
                # 一个几 MB 的错误清单，页面直接卡在渲染上。
                skipped.append({"id": "*",
                                "reason": "单次最多删除 %d 项，其余请求已忽略"
                                          % MAX_BATCH_DELETE})
                break
            try:
                r = self.delete(jid, drop_files=drop_files)
            except Exception as e:                       # 单条异常不中断整批
                skipped.append({"id": jid, "reason": "%s: %s" % (type(e).__name__, e)})
                continue
            if r.get("ok"):
                deleted.append(jid)
                files += len(r.get("removed") or [])
            else:
                skipped.append({"id": jid, "reason": r.get("error") or "删除失败"})
        return {
            "ok": bool(deleted),
            "deleted": deleted,
            "skipped": skipped,
            "files": files,
            "requested": len(seen),
        }

    def stats(self) -> Dict[str, int]:
        with self._c() as c:
            rows = c.execute("SELECT status, COUNT(*) n FROM jobs GROUP BY status").fetchall()
        out = {r["status"]: r["n"] for r in rows}
        out["total"] = sum(out.values())
        return out

    # ------------------------------------------------------------ 测试机登记簿
    #
    # 与 jobs 同一把写锁：设备登记簿的写入频率极低（一个人点"添加手机"），
    # 但"设备清单"会被每 10 秒一次的轮询读取，两者共用一条 SQLite 连接池，
    # 分开加锁反而容易在 Windows 上撞到 database is locked。
    def devices_list(self) -> List[Dict[str, Any]]:
        """全部已登记测试机，按加入时间升序（界面上的顺序应该稳定）。"""
        with self._c() as c:
            rows = c.execute("SELECT * FROM devices ORDER BY added_at ASC, serial ASC"
                             ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["root_ok"] = bool(d.get("root_ok"))
            d["degraded"] = bool(d.get("degraded"))
            out.append(d)
        return out

    def device_get(self, serial: str) -> Optional[Dict[str, Any]]:
        s = (serial or "").strip()
        if not s:
            return None
        with self._c() as c:
            row = c.execute("SELECT * FROM devices WHERE serial=?", (s,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["root_ok"] = bool(d.get("root_ok"))
        d["degraded"] = bool(d.get("degraded"))
        return d

    def device_save(self, *, serial: str, alias: str = "", phone: str = "",
                    note: str = "", root_ok: bool = False, degraded: bool = False,
                    info: Optional[Dict[str, str]] = None,
                    frida_ver: str = "", steps: str = "") -> Dict[str, Any]:
        """新增或更新一条登记记录。

        用 UPSERT 而不是"先查再决定 insert/update"：
        重复点「添加手机」不该产生两条记录，也不该把 `added_at` 覆盖成新时间
        （那会让列表顺序在每次重试后被重排，看起来像"多了一台机器"）。
        """
        s = (serial or "").strip()
        if not s:
            raise ValueError("设备序列号不能为空")
        now = time.time()
        info = info or {}
        with self._lock, self._c() as c:
            c.execute(
                "INSERT INTO devices(serial,alias,phone,note,added_at,verified_at,"
                "root_ok,degraded,model,brand,android,sdk,abi,frida_ver,last_steps) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(serial) DO UPDATE SET "
                "alias=excluded.alias, phone=excluded.phone, note=excluded.note, "
                "verified_at=excluded.verified_at, root_ok=excluded.root_ok, "
                "degraded=excluded.degraded, model=excluded.model, "
                "brand=excluded.brand, android=excluded.android, sdk=excluded.sdk, "
                "abi=excluded.abi, frida_ver=excluded.frida_ver, "
                "last_steps=excluded.last_steps",
                (s, (alias or "").strip(), (phone or "").strip(), (note or "").strip(),
                 now, now if root_ok else None,
                 1 if root_ok else 0, 1 if degraded else 0,
                 info.get("model") or "", info.get("brand") or "",
                 info.get("android") or "", info.get("sdk") or "",
                 info.get("abi") or "", frida_ver or "", steps or ""))
        return self.device_get(s) or {}

    def device_meta(self, serial: str, *, alias: Optional[str] = None,
                    phone: Optional[str] = None,
                    note: Optional[str] = None) -> Dict[str, Any]:
        """只改人填的三项（别名 / 号码 / 备注）。

        ★ 为什么不直接复用 `device_save`：那个方法会顺手刷新 `verified_at`
          并重写 `root_ok`。改个备注就把"上次验证时间"改成今天，等于伪造成
          "今天验证过" —— 而人只是想给手机改个名字。
        """
        s = (serial or "").strip()
        if not s:
            return {"ok": False, "error": "设备序列号不能为空"}
        sets, vals = [], []
        if alias is not None:
            sets.append("alias=?")
            vals.append(str(alias).strip()[:40])
        if phone is not None:
            sets.append("phone=?")
            vals.append(str(phone).strip()[:20])
        if note is not None:
            sets.append("note=?")
            vals.append(str(note).strip()[:200])
        if not sets:
            return {"ok": False, "error": "没有要修改的字段"}
        with self._lock, self._c() as c:
            cur = c.execute("UPDATE devices SET %s WHERE serial=?" % ", ".join(sets),
                            vals + [s])
            n = cur.rowcount
        if not n:
            return {"ok": False, "error": "这台设备没有登记过"}
        return {"ok": True, "device": self.device_get(s)}

    def device_delete(self, serial: str) -> Dict[str, Any]:
        """从平台移除一台测试机。

        ★ 只删平台上的登记记录，**不动设备本身**：
          不卸载 frida-server、不改 USB 调试授权、不清设备上的任何文件。
          "在平台里不用它了"和"把手机清空"是两件事，代码里混在一起做，
          迟早会在别人电脑上删掉不该动的东西。
        """
        s = (serial or "").strip()
        if not s:
            return {"ok": False, "error": "设备序列号不能为空"}
        with self._lock, self._c() as c:
            cur = c.execute("DELETE FROM devices WHERE serial=?", (s,))
            n = cur.rowcount
        if not n:
            return {"ok": False, "error": "这台设备没有登记过"}
        return {"ok": True, "serial": s}

    def device_phones(self) -> Dict[str, str]:
        """登记簿里记了号码的设备 → serial: phone。

        号码随设备记，而不是全局一个：每台机插的是自己的卡，
        拿 A 机的号去登录 B 机上的 App，验证码根本收不到。
        """
        with self._c() as c:
            rows = c.execute("SELECT serial,phone FROM devices "
                             "WHERE phone IS NOT NULL AND phone<>''").fetchall()
        return {r["serial"]: r["phone"] for r in rows}

    def device_count(self) -> int:
        with self._c() as c:
            return int(c.execute("SELECT COUNT(*) n FROM devices").fetchone()["n"])

    # ------------------------------------------------------------ AI 档案
    def ai_profiles(self) -> List[Dict[str, Any]]:
        """全部 AI 配置档案（按创建时间，先建的在前）。含 api_key 原文 —— 只给服务端用。"""
        with self._c() as c:
            rows = c.execute(
                "SELECT * FROM ai_profiles ORDER BY created_at ASC").fetchall()
        return [dict(r) for r in rows]

    def ai_profile(self, pid: str) -> Optional[Dict[str, Any]]:
        with self._c() as c:
            row = c.execute("SELECT * FROM ai_profiles WHERE id=?", (pid,)).fetchone()
        return dict(row) if row else None

    def ai_profile_save(self, *, pid: str = "", name: str, provider: str,
                        base_url: str = "", model: str = "",
                        vision_model: str = "", note: str = "",
                        api_key: Optional[str] = None) -> str:
        """新增或更新一份档案。返回 id。

        `api_key=None` 表示"不改动"（界面上留空＝沿用已存的那串）。
        传空串才是"清掉密钥"，两者的语义必须分开：否则编辑时只要不重填密钥
        就会把它悄悄删掉，下次调用才报 401 —— 而使用者明明只是改了个名字。
        """
        now = time.time()
        if pid:
            old = self.ai_profile(pid)
            if not old:
                raise ValueError("AI 配置不存在（可能已被删除）：%s" % pid)
        else:
            pid = "ai" + uuid.uuid4().hex[:10]
            old = None
        key = (old or {}).get("api_key", "") if api_key is None else str(api_key or "")
        with self._lock, self._c() as c:
            if old:
                c.execute(
                    "UPDATE ai_profiles SET name=?,provider=?,base_url=?,model=?,"
                    "vision_model=?,api_key=?,note=?,updated_at=? WHERE id=?",
                    (name, provider, (base_url or "").strip(), (model or "").strip(),
                     (vision_model or "").strip(), key, note or "", now, pid))
            else:
                c.execute(
                    "INSERT INTO ai_profiles(id,name,provider,base_url,model,"
                    "vision_model,api_key,note,created_at,updated_at,last_used_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,NULL)",
                    (pid, name, provider, (base_url or "").strip(),
                     (model or "").strip(), (vision_model or "").strip(), key,
                     note or "", now, now))
        return pid

    def ai_profile_delete(self, pid: str) -> Dict[str, Any]:
        """删除档案。若删的正是当前启用的一份，把 active 一并清空并如实告知。"""
        with self._lock, self._c() as c:
            row = c.execute("SELECT id,name FROM ai_profiles WHERE id=?", (pid,)).fetchone()
            if not row:
                return {"ok": False, "error": "这条 AI 配置不存在（可能已被删除）"}
            c.execute("DELETE FROM ai_profiles WHERE id=?", (pid,))
            active = c.execute(
                "SELECT v FROM app_meta WHERE k='ai_active'").fetchone()
            was_active = bool(active and (active["v"] or "") == pid)
            if was_active:
                c.execute("DELETE FROM app_meta WHERE k='ai_active'")
        return {"ok": True, "was_active": was_active, "name": row["name"]}

    def ai_touch(self, pid: str) -> None:
        """记一次"真的用它跑过"。
        与 device 的 `verified_at` 同一态度：只有实际调用过才写，
        单纯"选中"不算（选中一个连不通的地址不该看起来像验证通过）。
        """
        with self._c() as c:
            c.execute("UPDATE ai_profiles SET last_used_at=? WHERE id=?",
                      (time.time(), pid))

    def meta_get(self, k: str, default: str = "") -> str:
        with self._c() as c:
            row = c.execute("SELECT v FROM app_meta WHERE k=?", (k,)).fetchone()
        return (row["v"] if row else default) or default

    def meta_set(self, k: str, v: str) -> None:
        with self._lock, self._c() as c:
            c.execute("INSERT INTO app_meta(k,v) VALUES(?,?) "
                      "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v or ""))

    def ai_active_id(self) -> str:
        return self.meta_get("ai_active", "")

    def ai_set_active(self, pid: str) -> None:
        """启用某一套。空串＝停用全部（AI 完全关闭）。"""
        if pid and not self.ai_profile(pid):
            raise ValueError("这条 AI 配置不存在（可能已被删除）：%s" % pid)
        self.meta_set("ai_active", pid or "")
