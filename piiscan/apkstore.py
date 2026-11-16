"""APK 存储层：统一存放、按内容去重、删除任务时按引用清理。

为什么单独做一层：
    APK 是这个平台上最占磁盘的东西（带 native 库的包动辄上百 MB），而同一份
    包经常被反复用：同一个 App 隔一周复测、批量提交里重复的链接、同一个文件
    传两遍。此前每个任务各存一份（上传还额外在 `_uploads` 留一份原件），
    84 轮任务就把 `out/` 撑到 12 GB —— 其中大半是同一个包的副本。

三条规矩：
  1. **一个可配置的根目录**。使用者可以把它指到别的分区/别的盘（`app_meta` 的
     `apk_store_dir`），不填就用 `<工作目录>/apk`。目录是平台配置，不是任务参数：
     同一台机器上的所有任务共用一个位置。
  2. **按内容哈希去重**。落盘名是 `<hash前12位>_<原名>`，同内容只落一份，
     多个任务共享同一个绝对路径 —— 任务行里记的就是这个路径。
  3. **删除任务时按引用清理**。只有最后一个引用该文件的任务离开才真正 unlink；
     还有别的任务在用就保留，并如实回报"被几个任务留着"。

安全边界（比"追求彻底清理"更重要）：
  删文件是不可逆动作，所以删除前要过两道闸 ——
  ① 路径必须位于**该任务自己记录的托管根**之内；
  ② 文件名必须符合本层生成的命名规则（`<12位hex>_<...>.apk`）。
  使用者完全可能把根目录选在 `D:\\我的资料` 这种已有内容的地方，只有这两道
  闸同时成立，才可能删到本层自己写进去的那个文件。

进程崩溃留下的半截文件在 `.incoming/` 下，不参与去重、也不算占用统计里的
"已归档"，由 `sweep()` 按龄清理。
"""
from __future__ import annotations

import os
import re
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List

from .apkfetch import safe_ascii_filename

# 使用者没指定目录时用这个子目录名（相对工作目录）。
DEFAULT_DIRNAME = "apk"

# 平台级配置的键名（JSON 形状是纯字符串，存绝对路径）。
META_KEY = "apk_store_dir"

# 下载/上传先落到这里，算完哈希再改名进正式目录。
# 固定名字的好处：商店下载的断点续传（同名同大小就跳过）仍然有效。
INCOMING = ".incoming"

# 落盘命名：<hash 前 12 位>_<ascii 原名>.apk
# ★ 这条正则同时是删除时的护栏，改它等于改删除的行为，务必同步自检。
_HASH_NAME = re.compile(r"^[0-9a-f]{12}_[A-Za-z0-9._-]+\.apk$", re.I)


# ---------------------------------------------------------------- 根目录

def default_root(workdir: str | os.PathLike) -> Path:
    return Path(workdir) / DEFAULT_DIRNAME


def configured(db: Any) -> str:
    """使用者指定的根目录；空串＝用默认位置。"""
    try:
        return (db.meta_get(META_KEY, "") or "").strip()
    except Exception:
        return ""


def root(db: Any, workdir: str | os.PathLike) -> Path:
    """当前生效的根目录（只解析，不创建）。"""
    raw = configured(db)
    return Path(raw).expanduser() if raw else default_root(workdir)


def normalize(raw: str) -> Path:
    """把用户输入规整成可比较的绝对路径。"""
    s = (raw or "").strip().strip('"').strip("'")
    if not s:
        raise ValueError("目录不能为空")
    p = Path(s).expanduser()
    if not p.is_absolute():
        # 相对路径在服务的工作目录变化后会指向别处，配置项不接受它。
        raise ValueError("必须填绝对路径（例如 D:\\apk 或 /data/apk）")
    return Path(os.path.abspath(str(p)))


def validate_dir(raw: str) -> Dict[str, Any]:
    """校验并试探可写，返回 {ok, path, error, created}。

    只做"能不能往这里写"的判断，不对目录里的既有内容做任何假设 ——
    使用者完全可以把根目录指到一个已经有别的东西的地方。
    """
    try:
        p = normalize(raw)
    except ValueError as e:
        return {"ok": False, "path": "", "error": str(e), "created": False}

    if p.exists() and not p.is_dir():
        return {"ok": False, "path": str(p), "error": "这个路径是一个文件，不是目录",
                "created": False}
    # 盘根会被"扫描占用"和"清理"变成全盘遍历，也会让人误以为整个盘都归平台管。
    if p.parent == p:
        return {"ok": False, "path": str(p), "error": "不能直接用磁盘根目录，请在其下建一个子目录",
                "created": False}

    created = False
    try:
        if not p.exists():
            p.mkdir(parents=True, exist_ok=True)
            created = True
    except OSError as e:
        return {"ok": False, "path": str(p), "error": "目录不可创建：%s" % e,
                "created": created}

    probe = p / (".piiscan-write-test-%d.tmp" % os.getpid())
    try:
        probe.write_bytes(b"ok")
        probe.unlink()
    except OSError as e:
        try:
            probe.unlink()
        except OSError:
            pass
        return {"ok": False, "path": str(p), "error": "目录不可写：%s" % e,
                "created": created}
    return {"ok": True, "path": str(p), "error": "", "created": created}


def ensure(root_dir: str | os.PathLike) -> Path:
    d = Path(root_dir)
    d.mkdir(parents=True, exist_ok=True)
    return d


def incoming_dir(root_dir: str | os.PathLike) -> Path:
    return Path(root_dir) / INCOMING


# ---------------------------------------------------------------- 落盘

def target_for(root_dir: str | os.PathLike, key: str, filename: str = "") -> Path:
    """按内容哈希算出最终路径（不创建也不移动）。"""
    k = (key or "").lower()
    if not re.match(r"^[0-9a-f]{32,64}$", k):
        raise ValueError("内容哈希不合法：%r" % key)
    name = safe_ascii_filename(filename or "target.apk")
    return Path(root_dir) / k[:2] / ("%s_%s" % (k[:12], name))


def adopt(src: str | os.PathLike, root_dir: str | os.PathLike, *,
          key: str, filename: str = "",
          log=None) -> Dict[str, Any]:
    """把一个临时文件收进存储目录，同内容已存在时直接复用。

    返回 {ok, path, reused, size, error}。`reused=True` 表示这个包之前就收过，
    src 已被丢弃（同内容没必要留两份）。

    ★ 用 move 而不是 copy：临时文件与正式目录默认在同一个根下，
      rename 是原子的、不需要再搬一次几百 MB。跨盘时才退回复制。
    """
    log = log or (lambda *_: None)
    src = Path(src)
    if not src.exists():
        return {"ok": False, "path": "", "reused": False, "size": 0,
                "error": "文件不存在：%s" % src}
    try:
        dest = target_for(root_dir, key, filename or src.name)
    except ValueError as e:
        return {"ok": False, "path": "", "reused": False, "size": 0, "error": str(e)}

    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        return {"ok": False, "path": "", "reused": False, "size": 0,
                "error": "无法创建存储子目录：%s" % e}

    size = src.stat().st_size

    # ★ 去重必须按**内容哈希**，不能按最终文件名：
    #   同一个包换个名字再传一次（"微信 8.0.apk" / "weixin.apk"）会算出不同的
    #   目标路径，于是同内容各存一份 —— 去重就白做了。这里先在该哈希前缀下
    #   找有没有同哈希的文件，有就直接复用（名字沿用第一次落盘时那个）。
    for e in sorted(dest.parent.glob("%s_*.apk" % dest.name[:12])):
        try:
            if not e.is_file() or e.stat().st_size != size:
                continue
            if src.resolve() != e.resolve():
                try:
                    src.unlink()
                except OSError:
                    pass
            log("[*] 存储去重：这个包已经收过，直接复用（省 %.1f MB）" % (size / 1048576.0))
            return {"ok": True, "path": str(e), "reused": True, "size": size, "error": ""}
        except OSError:
            continue

    if dest.exists() and dest.stat().st_size == size:
        if src.resolve() != dest.resolve():
            try:
                src.unlink()
            except OSError:
                pass
        log("[*] 存储去重：这个包已经收过，直接复用（省 %.1f MB）" % (size / 1048576.0))
        return {"ok": True, "path": str(dest), "reused": True, "size": size, "error": ""}

    if src.resolve() == dest.resolve():          # 已经在位（重复提交同一路径）
        return {"ok": True, "path": str(dest), "reused": True, "size": size, "error": ""}

    try:
        shutil.move(str(src), str(dest))
    except OSError as e:
        # 跨盘 move 会被 shutil 拆成 copy+unlink，仍然失败通常是占用/权限。
        try:
            shutil.copy2(str(src), str(dest))
            os.unlink(str(src))
        except OSError as e2:
            try:
                if dest.exists() and dest.stat().st_size != size:
                    dest.unlink()
            except OSError:
                pass
            return {"ok": False, "path": "", "reused": False, "size": size,
                    "error": "归档失败（先试移动后试复制）：%s / %s" % (e, e2)}
    return {"ok": True, "path": str(dest), "reused": False, "size": size, "error": ""}


# ---------------------------------------------------------------- 删除

def is_managed_path(path: str | os.PathLike, root_dir: str | os.PathLike) -> bool:
    """这个文件是不是本层自己写进去的那一个（两道闸）。"""
    if not str(path or "").strip() or not str(root_dir or "").strip():
        return False
    p, r = Path(path), Path(root_dir)
    try:
        rel = p.resolve().relative_to(r.resolve())
    except (ValueError, OSError):
        return False
    # 结构必须是 <root>/<hash前2位>/<hash前12位>_<名>.apk
    if len(rel.parts) != 2:
        return False
    return bool(_HASH_NAME.match(p.name))


def release(db: Any, job_id: str, apk_path: str, apk_root: str) -> Dict[str, Any]:
    """删除一个任务时，处理它引用的 APK。

    返回 {removed, kept, reason}：
      · removed 非空 = 真的删了；
      · kept > 0    = 还有别的任务在用，保留（这是正常结果，不是失败）；
      · 两者都空    = 没动（没记录 / 不是托管文件 / 已经不在）。

    不抛异常：删任务的主流程不该因为一个文件删不掉就整体失败。文件删不掉时
    `reason` 会写清原因，界面能如实告诉使用者"这条记录删了，但这个文件还留着"。
    """
    path = (apk_path or "").strip()
    holder = (apk_root or "").strip()
    if not path:
        return {"removed": "", "kept": 0, "reason": "任务没有记录 APK 路径"}
    if not holder:
        # 加这一列之前的老任务：文件在任务目录或 _uploads 下，由调用方的旧逻辑清理。
        return {"removed": "", "kept": 0, "reason": "历史任务，未按共享存储管理"}
    if not is_managed_path(path, holder):
        return {"removed": "", "kept": 0,
                "reason": "文件不在本任务记录的存储目录内，未删除"}
    p = Path(path)
    if not p.exists():
        return {"removed": "", "kept": 0, "reason": "文件已不存在"}

    try:
        others = db.apk_refs(path, exclude=job_id)
    except Exception:
        # 查不到引用就不删 —— 宁可留下一个文件，也不能删掉别人还要用的包。
        return {"removed": "", "kept": 0, "reason": "无法确认其它任务是否还在用，已保留"}
    if others > 0:
        return {"removed": "", "kept": int(others),
                "reason": "还有 %d 个任务在用这个包，文件已保留" % others}

    try:
        p.unlink()
    except OSError as e:
        return {"removed": "", "kept": 0, "reason": "删除文件失败：%s" % e}
    # 顺手收掉空的哈希前缀目录；非空说明还有别的包，不能动。
    try:
        p.parent.rmdir()
    except OSError:
        pass
    return {"removed": str(p), "kept": 0, "reason": ""}


# ---------------------------------------------------------------- 统计与清理

def usage(root_dir: str | os.PathLike) -> Dict[str, Any]:
    """占用统计。只统计本层自己写的文件（命名规则），临时目录单独算。

    不做递归求和之外的事，也不修复任何东西 —— 这是个只读动作，
    界面每打开一次都会调它。
    """
    r = Path(root_dir)
    files = 0
    total = 0
    inc_files = 0
    inc_bytes = 0
    newest = 0.0
    if not r.exists():
        return {"exists": False, "files": 0, "bytes": 0,
                "incoming_files": 0, "incoming_bytes": 0, "newest": 0.0}
    try:
        for d in r.iterdir():
            if d.is_dir() and d.name == INCOMING:
                for f in d.iterdir():
                    try:
                        if f.is_file():
                            inc_files += 1
                            inc_bytes += f.stat().st_size
                    except OSError:
                        continue
                continue
            if not d.is_dir():
                continue
            for f in d.iterdir():
                try:
                    if not f.is_file() or not _HASH_NAME.match(f.name):
                        continue
                    st = f.stat()
                except OSError:
                    continue
                files += 1
                total += st.st_size
                newest = max(newest, st.st_mtime)
    except OSError:
        pass
    return {"exists": True, "files": files, "bytes": total,
            "incoming_files": inc_files, "incoming_bytes": inc_bytes,
            "newest": newest}


def orphans(db: Any, root_dir: str | os.PathLike) -> List[Dict[str, Any]]:
    """存储里有、但没有任何任务引用的文件。

    产生原因：任务记录被外部工具直接删掉、库被重建、或者删库时进程刚好退出。
    正常删任务不会留下孤儿（`release` 会删掉最后一个引用）。
    """
    r = Path(root_dir)
    if not r.exists():
        return []
    try:
        referenced = db.apk_paths()
    except Exception:
        return []
    out: List[Dict[str, Any]] = []
    for d in r.iterdir():
        if not d.is_dir() or d.name == INCOMING:
            continue
        for f in d.iterdir():
            try:
                if not f.is_file() or not _HASH_NAME.match(f.name):
                    continue
                if str(f) in referenced:
                    continue
                st = f.stat()
            except OSError:
                continue
            out.append({"path": str(f), "size": st.st_size, "mtime": st.st_mtime})
    out.sort(key=lambda x: x["mtime"])
    return out


def sweep(db: Any, root_dir: str | os.PathLike, *,
          max_age: float = 24 * 3600, log=None) -> Dict[str, Any]:
    """清掉孤儿文件与过期的半截下载。

    `max_age` 只作用于 `.incoming`：那里的东西可能是**正在下载**的文件，
    太新的绝对不能碰（一个 2 GB 的包下半小时，清理不能把它删了）。
    """
    log = log or (lambda *_: None)
    r = Path(root_dir)
    removed: List[Dict[str, Any]] = []
    freed = 0
    errors: List[str] = []

    for f in orphans(db, r):
        try:
            Path(f["path"]).unlink()
            removed.append(f)
            freed += f["size"]
        except OSError as e:
            errors.append("%s: %s" % (f["path"], e))

    inc = incoming_dir(r)
    now = time.time()
    if inc.exists():
        for f in inc.iterdir():
            try:
                if not f.is_file():
                    continue
                st = f.stat()
                if now - st.st_mtime < max_age:
                    continue
                f.unlink()
                removed.append({"path": str(f), "size": st.st_size, "mtime": st.st_mtime})
                freed += st.st_size
            except OSError as e:
                errors.append("%s: %s" % (f, e))

    if removed:
        log("[*] 已清理 %d 个文件，释放 %.1f MB" % (len(removed), freed / 1048576.0))
    return {"ok": not errors, "count": len(removed), "bytes": freed,
            "items": removed[:50], "errors": errors[:20]}


def describe(root_dir: str | os.PathLike) -> Dict[str, Any]:
    """给界面用的一段状态：路径、是否默认位置、占用、孤儿数。"""
    r = Path(root_dir)
    u = usage(r)
    return {"dir": str(r), "exists": u["exists"],
            "files": u["files"], "bytes": u["bytes"],
            "incoming_files": u["incoming_files"],
            "incoming_bytes": u["incoming_bytes"]}


def fmt_size(n: float) -> str:
    """人类可读的体积。界面与日志共用一份，避免两处四舍五入不一致。"""
    v = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024 or unit == "TB":
            return ("%d %s" % (v, unit)) if unit == "B" else ("%.1f %s" % (v, unit))
        v /= 1024.0
    return "%.1f TB" % v
