"""测试账号台账：注册过谁、密码是什么、哪一轮注的。

★ 为什么必须有这个模块（2026-11-06 用户要求）：
  春雨诊所、万步健康这类 App 只给「手机号 + 密码」，没有短信验证码登录，
  也没有游客入口 —— 手里只有测试手机号时，唯一能进去的路是**注册一个账号**。
  而注册不是无成本动作：
    · 同一台测试机反复注册会在厂商侧堆一串废号，同号注册还可能触发风控；
    · 密码如果每轮随机生成，下一轮就再也登不进去（等于花钱买一次登录）；
    · 台账丢了之后，人只知道"这个号注册过"，但不知道密码。
  所以密码用**固定规则**生成（见 `make_password`），并把结果落盘。
  规则固定 + 台账落盘是两道保险：文件丢了能重算，平台换机器也能接着用。

★ 这不是用户凭据，是**检测用测试账号**：
  · 号码来自 config.yaml 的测试机号码；
  · 密码按规则从号码推导，不涉及任何真实用户的密码；
  · 报告里只写脱敏账号（133****0822）与"密码见本地台账"，
    不把密码写进会被分发出去的 HTML。
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

NAME = "accounts.json"


def default_path() -> Path:
    """台账默认位置：项目根目录（与 config.yaml 同级）。

    刻意**不放进 out/**：out/ 是按任务清空的产物目录，
    台账跨任务、跨轮次有效，放进去等于每轮都从零开始注册。
    """
    return Path(__file__).resolve().parent.parent.parent / NAME


def make_password(phone: str) -> str:
    """按固定规则生成测试账号密码。

    为什么固定：台账文件丢了下轮还能算出同一个密码，不用去走「忘记密码」。
    为什么长这样：`Pii@20822Aa` 同时含字母、数字、符号，长度 10 位，
    满足最常见的强度校验（春雨诊所的提示就是「8-20 位，须同时包含
    英文字母、数字、符号」）。不做"随机更安全"的取舍 ——
    这个密码保护的是一个测试账号，能被重新算出来比"猜不到"重要得多。
    """
    digits = "".join(ch for ch in str(phone or "") if ch.isdigit())
    tail = digits[-6:] or "000000"
    return "Pii@%sAa" % tail


def masked(phone: str) -> str:
    s = str(phone or "")
    if len(s) >= 7:
        return s[:3] + "****" + s[-4:]
    return s


def load(path: Optional[Path] = None) -> Dict[str, Any]:
    p = Path(path) if path else default_path()
    if not p.exists():
        return {"version": 1, "accounts": []}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        # 文件坏了不能把整轮任务带崩：当作空台账，下一次写入会重建。
        return {"version": 1, "accounts": []}
    if not isinstance(data, dict):
        return {"version": 1, "accounts": []}
    data.setdefault("version", 1)
    if not isinstance(data.get("accounts"), list):
        data["accounts"] = []
    return data


def save(data: Dict[str, Any], path: Optional[Path] = None) -> bool:
    """原子写：先写临时文件再替换。

    平台可能同时跑多个任务（虽然设备串行），两个进程同读同写时
    直接覆盖会写出半截 JSON —— 那比不写更糟（下次读出来是空的，
    于是又注册一遍，正是台账要防的事）。
    """
    p = Path(path) if path else default_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        os.replace(str(tmp), str(p))
        return True
    except Exception:
        return False


def find(package: str, phone: str = "", path: Optional[Path] = None
         ) -> Optional[Dict[str, Any]]:
    """按包名（+ 手机号）查已注册账号。不传号表示"这个包任意一个号"。"""
    pkg = str(package or "").strip()
    ph = str(phone or "").strip()
    for it in load(path).get("accounts") or []:
        if str(it.get("package") or "") != pkg:
            continue
        if ph and str(it.get("phone") or "") != ph:
            continue
        return it
    return None


def upsert(package: str, phone: str, *, password: str = "", app: str = "",
           ok: Optional[bool] = None, note: str = "",
           path: Optional[Path] = None) -> Dict[str, Any]:
    """记一条账号：已有就更新（保留 created_at），没有就新建。

    只更新"这次真的发生了什么"的字段 —— 登录失败不该把上次的成功记录抹掉，
    否则台账读起来像"从没登上过"，人会再去注册一遍。
    """
    data = load(path)
    pkg = str(package or "").strip()
    ph = str(phone or "").strip()
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    item = None
    for it in data.get("accounts") or []:
        if (str(it.get("package") or "") == pkg
                and str(it.get("phone") or "") == ph):
            item = it
            break
    if item is None:
        item = {"package": pkg, "phone": ph, "created_at": now,
                "password": "", "app": "", "ok": None, "note": ""}
        data.setdefault("accounts", []).append(item)
    if password:
        item["password"] = password
    if app:
        item["app"] = app
    if ok is not None:
        item["ok"] = bool(ok)
        if ok:
            item["last_ok_at"] = now
    if note:
        item["note"] = str(note)[:200]
    item["updated_at"] = now
    save(data, path)
    return item


def summary_text(path: Optional[Path] = None) -> str:
    """给报告用的一句话：这个包里有没有我们注册过的账号。"""
    rows: List[Dict[str, Any]] = load(path).get("accounts") or []
    if not rows:
        return "本地台账里没有该应用的测试账号"
    pkg = str(rows[0].get("package") or "")
    return "本地台账共 %d 个测试账号（最近：%s %s）" % (
        len(rows), pkg, masked(rows[0].get("phone") or ""))
