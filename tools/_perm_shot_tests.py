"""权限弹窗截图的回归测试（不连真机）。

守的是用户明确提的第一条要求：**涉及权限获取，必截图**。

真机撞到的问题（以观书法 mbsf5）：
    截图配额 14 张在遍历途中就用完了，两次「照片」权限申请全部 shot=-1，
    报告里 Q026 写着"弹窗前界面与弹窗中均未见用途说明"，
    却连一张弹窗截图都拿不出来 —— 复核员无法验证这句话。

这里的用例直接替换 adb / uiautomator 的边界函数，验证：
  ① 配额已满时，权限弹窗**仍然截图**；
  ② 普通截图不再占用权限弹窗的配额；
  ③ 权限弹窗标签能被 shot_phase 认出阶段（P2/P3 也认）；
  ④ 截图失败时如实留空并写日志，不假装拍到了。
"""
from __future__ import annotations

import base64
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from piiscan import collector as C            # noqa: E402
from piiscan.flow.sop import shot_phase       # noqa: E402

OK = BAD_C = 0
BAD: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    global OK, BAD_C
    if cond:
        OK += 1
    else:
        BAD_C += 1
        BAD.append("%s%s" % (name, ("　→ " + detail) if detail else ""))
        print("  ✗ %s%s" % (name, ("　→ " + detail) if detail else ""))


# 一张 1×1 的合法 PNG（能被 base64 编码、能进报告；渲染时会被压缩跳过，
# 但这里只验证"有没有留图"，不验证图像质量）。
_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")

_DIALOG = {
    "perm": "照片", "perm_raw": "READ_MEDIA_IMAGES",
    "dialog_text": "允许「以观书法」访问照片和视频吗？",
    "options": ["拒绝", "允许"], "has_purpose": False, "purpose_quote": "",
    "allow_label": "允许", "pkg": "com.android.permissioncontroller",
}


def _res(n_ordinary: int, max_shots: int = 14):
    """造一个已有 n_ordinary 张普通截图的采集结果。"""
    shots = [{"label": "UI 遍历第 %d 步" % i, "activity": "a", "b64": "x"}
             for i in range(n_ordinary)]
    return SimpleNamespace(
        screenshots=shots, max_shots=max_shots, perm_scenes=[], ui_steps=[],
        started_at=1.0, events=[], marks={}, screens=[],
    )


def _patch(shot=..., allow_label="允许"):
    """替换 adb / uiautomator 边界；返回 restore 函数。"""
    saved = {}
    dlg = dict(_DIALOG)
    dlg["allow_label"] = allow_label

    def _set(obj, name, val):
        saved[(obj, name)] = getattr(obj, name)
        setattr(obj, name, val)

    _set(C.uiwalk, "perm_dialog", lambda xml: dict(dlg) if dlg.get("perm") else None)
    _set(C.uiwalk, "screen_fingerprint", lambda xml: "fp1")
    _set(C.uiwalk, "top_activity", lambda serial: "com.ltzk.mbsf/.MainActivity")
    _set(C.uiwalk, "clickable", lambda xml: [])
    _set(C.uiwalk, "tap", lambda *a, **k: None)
    _set(C.uiwalk, "dump_retry", lambda *a, **k: "<hierarchy/>")
    _set(C.uiwalk, "screen_texts", lambda xml: [])
    _set(C.uiwalk, "parse_all", lambda xml: [])
    _set(C, "capture_screenshot",
         (lambda serial: _PNG) if shot is ... else (lambda serial: shot))
    _set(C.time, "sleep", lambda s: None)

    def restore():
        for (obj, name), val in saved.items():
            setattr(obj, name, val)
    return restore


def t_quota_full_still_shoots():
    print("① 配额已满时权限弹窗仍截图")
    restore = _patch()
    try:
        res = _res(14)            # 14/14，配额已满
        ok = C._capture_perm_dialog(res, "<xml/>", "dev", lambda m: None, "P4")
        check("识别为权限弹窗并处理", ok is True, str(ok))
        check("配额满时仍留下了截图", len(res.screenshots) == 15,
              "实际 %d 张" % len(res.screenshots))
        check("截图标签带阶段与权限名",
              res.screenshots[-1]["label"] == "权限申请·P4·照片",
              res.screenshots[-1]["label"])
        check("权限场景记录了截图编号", res.perm_scenes[0]["shot"] == 14,
              str(res.perm_scenes[0]["shot"]))
    finally:
        restore()


def t_ordinary_does_not_eat_perm_quota():
    print("② 普通截图不占权限配额")
    restore = _patch()
    try:
        res = _res(0)
        # 灌满普通配额（模拟遍历一路截图）
        for i in range(14):
            res.screenshots.append({"label": "UI 遍历第 %d 步" % i, "b64": "x"})
        check("普通计数 = 14", C._ordinary_shot_count(res) == 14,
              str(C._ordinary_shot_count(res)))
        # 普通截图点：配额满 → 不再加图
        C.observe_screen(res, "UI 遍历第 99 步", "dev", take_shot=True)
        check("普通截图点配额满后不再加图", len(res.screenshots) == 14,
              str(len(res.screenshots)))
        # 权限弹窗：照样拍
        C._capture_perm_dialog(res, "<xml/>", "dev", lambda m: None, "P4")
        check("权限弹窗不受普通配额影响", len(res.screenshots) == 15,
              str(len(res.screenshots)))
        check("普通计数仍为 14（权限图不计入）",
              C._ordinary_shot_count(res) == 14, str(C._ordinary_shot_count(res)))
    finally:
        restore()


def t_shot_failure_is_honest():
    print("③ 截图失败要如实留空")
    restore = _patch(shot=b"")
    try:
        res = _res(14)
        logs: list[str] = []
        C._capture_perm_dialog(res, "<xml/>", "dev", logs.append, "P1")
        check("截图失败时不写截图", len(res.screenshots) == 14, str(len(res.screenshots)))
        check("shot 记 -1", res.perm_scenes[0]["shot"] == -1,
              str(res.perm_scenes[0]["shot"]))
        check("日志明确写了需要人工补充",
              any("需人工补充" in x for x in logs), str(logs[:2]))
        check("权限场景本身仍然记录（事实不丢）",
              res.perm_scenes[0]["dialog_text"].startswith("允许"),
              res.perm_scenes[0].get("dialog_text", "")[:20])
    finally:
        restore()


def t_perm_label_phase():
    print("④ 权限标签能归到阶段")
    for lab, want in (("权限申请·P1·相机", "P1"), ("权限申请·P2·存储", "P2"),
                      ("权限申请·P3·位置", "P3"), ("权限申请·P4·照片", "P4"),
                      ("首启界面 1", "P1"), ("UI 遍历第 3 步", "P4"),
                      ("完全认不出的标签", "")):
        check("「%s」→ %s" % (lab, want or "（不挂）"), shot_phase(lab) == want,
              shot_phase(lab))


def main() -> int:
    print("权限弹窗截图回归")
    print("=" * 62)
    t_quota_full_still_shoots()
    t_ordinary_does_not_eat_perm_quota()
    t_shot_failure_is_honest()
    t_perm_label_phase()
    print("=" * 62)
    if BAD_C:
        print("失败 %d 项：" % BAD_C)
        for b in BAD:
            print("  -", b)
        return 1
    print("全部通过（%d 项）" % OK)
    return 0


if __name__ == "__main__":
    sys.exit(main())
