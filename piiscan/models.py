"""采集事件的数据模型。"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

_HOST_IN_ARGS = re.compile(r"https?://([^/\s]+)")
# 本地持久化的"目标"：表名 / 键名 / 文件名
_TARGET_IN_ARGS = re.compile(r"(?:table|key|file|name|db)=([^\s,;]+)")
# 直接写在 SQL 里的表名（execSQL 的 args 形如 "table=create table if not exists __sd(...)"）
_SQL_TABLE = re.compile(
    r"(?:create\s+table(?:\s+if\s+not\s+exists)?|insert\s+into|update|delete\s+from|"
    r"alter\s+table|drop\s+table(?:\s+if\s+exists)?)\s+[`\"\[]?([A-Za-z0-9_]+)")
_VALID_HOST = re.compile(r"[a-z0-9][a-z0-9.\-]*")


def clean_host(host: str) -> str:
    """规范化主机名，供去重使用。

    ★ 两个真机上真实出现过的坑：
      1) 采集侧会把过长的 URL 截断、末尾补一个 `…`（U+2026）。截断点如果落在域名里，
         同一台主机会变成两个 key —— 实测 `license.vod2.myqcloud.com` 被拆成
         `…myqcloud.com`（args 完整）和 `…myqcl…`（result 被截断）两条。
      2) 极光推送同一主机有 v4/v6 两个域名（`ce3e75d5.jpush.cn` 与
         `ce3e75d5-ipv6.jpush.cn`），实际是同一次上报的双栈连接。
    """
    h = (host or "").strip().lower()
    h = h.replace("…", "").replace("。", "")
    m = _VALID_HOST.search(h)
    h = m.group(0) if m else ""
    h = h.rstrip(".-")
    if "-ipv6." in h:
        h = h.replace("-ipv6.", ".")
    return h

# 个人信息类别 -> 中文名（报告展示用）
CATEGORY_LABELS: Dict[str, str] = {
    "device_id": "设备标识符",
    "subscriber_id": "用户身份标识（IMSI / 手机号）",
    "location": "位置信息",
    "contacts": "通讯录",
    "sms": "短信",
    "call_log": "通话记录",
    "media": "相册 / 媒体文件",
    "calendar": "日历",
    "app_list": "已安装应用列表",
    "network": "网络标识（MAC / SSID / BSSID）",
    "network_sink": "数据外发（网络上报）",
    "storage_sink": "本地持久化（数据留存）",
    "log_sink": "日志输出",
    "clipboard": "剪贴板内容",
    "account": "账号信息",
    "sensor": "传感器数据",
    "storage": "外部存储",
    "camera": "相机",
    "microphone": "麦克风",
    "permission": "权限申请 / 检查",
    "other": "其他",
}

# 属于"个人敏感信息"的类别（用于报告中的风险标注）
SENSITIVE_CATEGORIES = {
    "subscriber_id",
    "location",
    "contacts",
    "sms",
    "call_log",
    "media",
    "clipboard",
    "account",
    "camera",
    "microphone",
}

# 证据分级说明（对应误报漏斗）
EVIDENCE_LABELS: Dict[str, str] = {
    "A": "取到有效值，可独立支撑结论",
    "B": "API 命中但取值需人工确认",
    "C": "纯行为记录，需结合界面上下文判断",
    "D": "噪声线索，仅作参考",
}

SINK_LABELS: Dict[str, str] = {
    "K1": "网络上报",
    "K2": "本地持久化",
    "K3": "日志输出",
}


@dataclass
class PIIEvent:
    hook_id: str
    category: str
    api: str
    args: str = ""
    result: str = ""
    thread: str = ""
    ts: int = 0
    elapsed_ms: int = 0
    before_consent: bool = True
    stack: List[str] = field(default_factory=list)
    # 新增：与 signal_map.yaml 对齐的指纹与证据等级
    signal: str = ""
    group: str = ""
    pi: str = ""
    evidence: str = "B"
    sink: str = ""
    activity: str = ""
    ui_action: str = ""
    screenshot_idx: int = -1
    # 误报漏斗第 5 级：**框架/系统自己**的行为（不是 App 在收集）。
    # 前四级解决的是"值是不是真的个人信息"，这一级解决"是不是 App 收集的"。
    # 非空 = 排除原因，报告与规则层都不再计入，但仍留在存档里可审计。
    noise: str = ""

    @classmethod
    def from_msg(cls, m: Dict[str, Any]) -> "PIIEvent":
        return cls(
            hook_id=str(m.get("hookId") or ""),
            category=str(m.get("category") or "other"),
            api=str(m.get("api") or ""),
            args=str(m.get("args") or ""),
            result=str(m.get("result") or ""),
            thread=str(m.get("thread") or ""),
            ts=int(m.get("ts") or 0),
            elapsed_ms=int(m.get("elapsedMs") or 0),
            before_consent=bool(m.get("beforeConsent", True)),
            stack=[str(x) for x in (m.get("stack") or [])],
            signal=str(m.get("signal") or ""),
            group=str(m.get("group") or ""),
            pi=str(m.get("pi") or ""),
            evidence=str(m.get("evidence") or "B"),
            sink=str(m.get("sink") or ""),
            activity=str(m.get("activity") or ""),
            ui_action=str(m.get("uiAction") or ""),
            screenshot_idx=int(m.get("screenshotIdx", -1)),
        )

    @property
    def category_label(self) -> str:
        return CATEGORY_LABELS.get(self.category, self.category)

    @property
    def evidence_label(self) -> str:
        return EVIDENCE_LABELS.get(self.evidence, self.evidence)

    @property
    def sink_label(self) -> str:
        return SINK_LABELS.get(self.sink, self.sink)

    @property
    def is_valid_value(self) -> bool:
        """漏斗第 2 级：是否取到有效值（A 级即视为有效）。"""
        return self.evidence == "A"

    @property
    def group_key(self) -> str:
        """报告分组键。

        ★ 去向类事件（网络上报 / 本地持久化）必须按**目标**分组，而不是按实现类。
          同一次网络请求会被多条 hook 分别捕获 —— `java.net.URL.openConnection`（抽象层）
          与 `com.android.okhttp…HttpURLConnectionImpl` / `HttpsURLConnectionImpl`（真实实现）。
          按 api 分组会把**一次**请求拆成 2~3 条"不符合项"，报告看着问题很多，
          人工复核还得自己合并。简小知 jxz3 实测 15 组里有 4 组是这种重复
          （腾讯云许可、Sentry 上报各被拆成两条 HTTP/HTTPS）。
        """
        if self.category.endswith("_sink"):
            # ★ URL 不一定在 args 里：`URL.openConnection` 的 args 是空的，
            #   目标地址在**返回值**里（返回的是真实实现对象，toString 带 URL）。
            #   只在 args 里找，12 条 jpush 上报会全部落到 target:?，白做了按目标归并。
            blob = (self.args or "") + " " + (self.result or "")
            target = ""
            truncated = False
            m = _HOST_IN_ARGS.search(blob)
            if m:
                raw = m.group(1)
                # 采集侧对过长的 URL 会截断并补 `…`。截断点落在域名里时，
                # 这里拼不出完整主机名 —— 打个 `~` 标记，交给 group_events
                # 按前缀并回完整的那一组，否则一次连接会变成两条问题项。
                truncated = "…" in raw
                target = clean_host(raw)
            elif "host=" in blob:
                target = clean_host(blob.split("host=", 1)[1].split()[0])
            else:
                # 本地持久化：SQL 里写死的表名优先，其次 table=/key= 参数
                m3 = _SQL_TABLE.search(blob)
                if m3:
                    target = m3.group(1)[:48]
                else:
                    m2 = _TARGET_IN_ARGS.search(self.args or "")
                    target = (m2.group(1) if m2 else "")[:48]
            mark = "~" if truncated else ""
            return "%s|target:%s%s" % (self.category, mark, target or "?")
        return "%s|%s|%s" % (self.category, self.hook_id, self.api)
