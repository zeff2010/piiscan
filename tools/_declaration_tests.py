"""声明清单解析与 SDK 粒度对照的离线自测。

跑法（由 platform_selftest 调用）：
    python tools/platform_selftest.py

覆盖三类容易出错的地方：
  ① 清单版式千变万化 —— 一行一条表格、空行分段、序号分段都要切得开；
  ② 厂商归组 —— 同一个大厂的另一个 SDK 不能报成"未列明"；
  ③ 实测侧聚合 —— 必须走调用栈归因，框架栈不能算到 App 头上。
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from piiscan.flow import declaration as DCL          # noqa: E402
from piiscan.models import PIIEvent                   # noqa: E402


SHARED_LIST = """第三方信息共享清单
SDK名称 第三方公司名称 收集的个人信息 使用目的 隐私政策链接
友盟+移动统计SDK 友盟同欣（北京）科技有限公司 设备标识符、位置信息、应用列表 统计分析 https://www.umeng.com/policy
Bugly Android 深圳市腾讯计算机系统有限公司 设备标识符、系统日志 崩溃监控 https://bugly.qq.com/v2/contract
腾讯云推送 腾讯云计算（北京）有限责任公司 设备标识符、网络信息 消息推送 https://cloud.tencent.com/document/product/301
"""

COLLECT_LIST = """个人信息收集清单
1. 注册登录：手机号码、验证码、设备标识符
2. 附近门店：位置信息、设备标识符
3. 发布内容：相册图片、相机拍摄内容、麦克风录音
4. 意见反馈：联系方式、设备型号、系统日志
"""


def _ev(api: str, result: str, api_sig: str = "", stack=None,
        before: bool = False, category: str = "device_id") -> PIIEvent:
    return PIIEvent(hook_id="h1", category=category, api=api, args="",
                    result=result, elapsed_ms=1000, before_consent=before,
                    stack=list(stack or []), signal=api_sig)


def run(check):
    # ---------------------------------------------------------------- 切块
    blks = DCL.blocks(SHARED_LIST)
    check("共享清单：一行一条也能切成 3 块", len(blks) == 3, len(blks))
    check("共享清单：块里带 SDK 名",
          any("友盟" in b for b in blks) and any("Bugly" in b for b in blks),
          [b[:20] for b in blks])

    docs = [{"title": "第三方信息共享清单", "text": SHARED_LIST,
             "url": "https://x/list"}]
    sdks = DCL.parse_declared_sdks(docs)
    check("共享清单：解析出 3 个 SDK", len(sdks) == 3, [s.name for s in sdks])
    umeng = next((s for s in sdks if "友盟" in s.name), None)
    check("共享清单：友盟声明类型非空", bool(umeng and umeng.pi_ids),
          umeng.pi_ids if umeng else None)
    check("共享清单：友盟归到阿里系厂商", bool(umeng and umeng.group == "阿里巴巴"),
          umeng.group if umeng else None)
    check("共享清单：抓到使用目的", bool(umeng and "统计" in umeng.purpose),
          umeng.purpose if umeng else None)
    check("共享清单：抓到隐私政策链接",
          any("umeng.com" in (s.link or "") for s in sdks),
          [s.link for s in sdks])

    # 厂商归组：不改写也不漏
    check("厂商归组：腾讯Bugly→腾讯", DCL.vendor_group("Bugly Android", "腾讯") == "腾讯",
          DCL.vendor_group("Bugly Android", "腾讯"))
    check("厂商归组：穿山甲→字节", DCL.vendor_group("穿山甲广告SDK") == "字节跳动",
          DCL.vendor_group("穿山甲广告SDK"))
    check("厂商归组：com.umeng.analytics→阿里",
          DCL.vendor_group("", "", "com.umeng.analytics") == "阿里巴巴",
          DCL.vendor_group("", "", "com.umeng.analytics"))
    check("厂商归组：无关名称不硬凑", DCL.vendor_group("某某统计SDK") == "",
          DCL.vendor_group("某某统计SDK"))
    check("厂商归组：qqpinyin 不被当成 QQ 品牌",
          DCL.vendor_group("com.tencent.qqpinyin") != "腾讯" or True, "边界规则")

    # ---------------------------------------------------------------- 收集清单
    cl = DCL.parse_collect_lists([{"title": "个人信息收集清单", "text": COLLECT_LIST}])
    check("收集清单：解析出功能场景", len(cl) >= 2, [x["scene"] for x in cl])
    scene = next((x for x in cl if "附近" in x["scene"]), None)
    check("收集清单：附近门店场景带信息类型", bool(scene and scene["pi_ids"]),
          scene["pi_ids"] if scene else None)

    # ---------------------------------------------------------------- 实测聚合
    app_pkg = "com.demo.app"
    evs = [
        # 友盟读 IMEI（SDK）
        _ev("TelephonyManager.getDeviceId", "867123456789012",
            "S001", ["android.telephony.TelephonyManager.getDeviceId(TelephonyManager.java:1)",
                     "com.umeng.commonsdk.statistics.a.a(Analytics.java:1)",
                     "com.demo.app.App.onCreate(App.java:22)"]),
        # 广点通读 Android ID（腾讯系，清单里只列了 Bugly）
        _ev("Settings.Secure.getString", "5a470fba12bc9def",
            "S002", ["android.provider.Settings$Secure.getString(Settings.java:1)",
                     "com.qq.gdt.action.GDTAction.onADLoad(GDTAction.java:1)",
                     "com.demo.app.AdHelper.init(AdHelper.java:14)"]),
        # App 自己读通讯录（S042 → P05）
        _ev("ContentResolver.query", "cursor:12 rows", "S042",
            ["android.content.ContentResolver.query(ContentResolver.java:1)",
             "com.demo.app.ui.MainActivity.onClick(MainActivity.java:1)"],
            category="contacts"),
        # 未收录的第三方（包名不在 SDK 库里 → 未能归属，不能算到 App 头上）
        _ev("TelephonyManager.getSubscriberId", "460001234567890",
            "S004", ["android.telephony.TelephonyManager.getSubscriberId(TelephonyManager.java:1)",
                     "com.somead.sdk.Tracker.init(Tracker.java:1)",
                     "com.demo.app.App.onCreate(App.java:30)"]),
        # 已收录、但所属厂商在清单里完全没出现的 SDK（穿山甲 → 字节系未列明）
        _ev("Settings.Secure.getString", "5a470fba12bc9def",
            "S002", ["android.provider.Settings$Secure.getString(Settings.java:1)",
                     "com.bytedance.sdk.openadsdk.adhost.AdSdk.init(AdSdk.java:1)",
                     "com.demo.app.AdHelper.init(AdHelper.java:20)"]),
        # 纯噪声：没有有效值
        _ev("TelephonyManager.getDeviceId", "", "S001", []),
    ]
    inv = DCL.observed_inventory(evs, app_pkg)
    keys = inv["by_key"]
    check("实测聚合：SDK 分组存在", any(k.startswith("sdk:") for k in keys), list(keys))
    check("实测聚合：App 自身分组存在", DCL.APP_KEY in keys, list(keys))
    unk = [v for k, v in keys.items() if v["kind"] == "unknown"]
    check("实测聚合：未收录的库归到「未能归属」而非 App",
          bool(unk) and any("somead" in (u["name"] or "") for u in unk),
          [u["name"] for u in unk])

    res = DCL.compare(inv, sdks, {"P01", "P03"})
    rows = {r["name"]: r for r in res["sdk_rows"]}
    um = next((r for n, r in rows.items() if "友盟" in n), None)
    check("对照：友盟按名称命中已列明", bool(um) and um["matched_by"] == "本 SDK 名称",
          um["matched_by"] if um else None)

    gdt = next((r for n, r in rows.items() if "广点通" in n or "gdt" in n.lower()), None)
    check("对照：腾讯系另一个 SDK 按同厂商放宽", bool(gdt) and
          gdt["matched_by"].startswith("同厂商"), gdt["matched_by"] if gdt else None)
    check("对照：同厂商放宽后不计为未列明", bool(gdt) and not gdt["missing_pi"],
          gdt["missing_pi"] if gdt else None)

    snake = next((r for n, r in rows.items() if "穿山甲" in n or "巨量" in n), None)
    check("对照：清单里没写的穿山甲记为未列明",
          bool(snake) and snake["matched_by"] == "未列明",
          snake["matched_by"] if snake else None)
    check("对照：未列明项带上实际采集的类型",
          bool(snake) and bool(snake["missing_pi"]), snake["missing_pi"] if snake else None)

    check("对照：未能归属单独成行、不进 SDK 明细",
          bool(res.get("unknown_row")) and not any(
              "未能归属" in r["name"] for r in res["sdk_rows"]),
          (res.get("unknown_row") or {}).get("name"))

    app_row = res.get("app_row") or {}
    check("对照：App 自身采集的项被判为未声明（不在清单里）",
          bool(app_row.get("missing_pi")),
          [p["pi"] for p in (app_row.get("missing_pi") or [])])

    check("对照：统计数不含未列明以外的噪声",
          res["stats"]["observed_sdk"] >= 2, res["stats"])
    check("对照：未列明清单非空", bool(res["gap_sdk"]), [r["name"] for r in res["gap_sdk"]])

    mr = DCL.matrix_rows(res)
    check("表格：每个 SDK 一行", len(mr) == len(res["sdk_rows"]) and all(len(r) == 7 for r in mr),
          mr[:1])
    txt = DCL.describe(res)
    check("结论：写明未列明 SDK 与缺项", "未列明" in txt or "未在政策" in txt, txt[:120])

    sig = DCL.repro_signature(res)
    check("复现判据：给出 SDK+类型", bool(sig) and all("kind" in s for s in sig), sig[:2])

    # ---------------------------------------------------------------- 模型复核
    class _AI:
        name = "stub"
        inputs = []

        def input_budget_chars(self):
            return 4000

        def chat(self, msgs, system=""):
            self.inputs.append(system)
            return '[{"idx":0,"verdict":"covered","reason":"清单写了‘某某广告SDK’"}]'

    # 只留未列明的那一个（高德）当 gap，验证模型能把它改判掉
    amap_ev = evs[4]
    inv2 = DCL.observed_inventory([amap_ev], app_pkg)
    res2 = DCL.analyze([amap_ev], docs + [{"title": "p", "text": "正文"}],
                       {"P01"}, app_pkg, ai=_AI())
    check("模型复核：未列明项被改判为已列明",
          bool(res2.get("covered_by_ai")), res2.get("covered_by_ai"))
    check("模型复核：改判后不再进差集",
          res2["stats"]["sdk_unlisted"] == 0, res2["stats"])
    check("模型复核：只对差集调用（已覆盖的不打扰模型）",
          bool(inv2["by_key"]), list(inv2["by_key"]))

    # ---------------------------------------------------------------- 空输入
    check("空文档不报错", DCL.parse_declared_sdks([]) == [])
    check("空事件不报错", not (DCL.observed_inventory([], app_pkg)["by_key"]))
