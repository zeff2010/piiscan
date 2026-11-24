"""配置加载。

设计要点：所有需要调用大模型（AI）的地方都由 ai: 段落驱动；
换环境时可改 yaml，也可用环境变量覆盖（便于容器化/内网部署）。
"""
from __future__ import annotations

import dataclasses
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict

import yaml


# 各 AI 环节的默认开关。与 config.yaml 的 ai.features 一一对应。
#
# 这里的默认值刻意**全部为 False**：AI 是能力增强，不是运行前提。
# 没配模型 / 模型挂了 / 内网拉不到服务时，整条链路必须仍能跑出报告，
# 只是回到「关键词 + 结构树」的确定性策略。把 AI 设为默认必开启，
# 会让平台在换环境时直接不可用 —— 那是设计事故，不是特性。
DEFAULT_AI_FEATURES: Dict[str, bool] = {
    "report_narrative": True,    # 把采集事件写成自然语言「问题描述」
    "policy_parse": False,       # 政策结构化解析（AI）
    "policy_vision": False,      # 用视觉模型看截图定位政策入口 / 判断页面类型
    "policy_analyze": False,     # 政策全文深读 + 第三方共享清单追链
    "ui_agent": False,           # 用视觉模型指挥 UI 遍历
    "risk_classify": False,      # 风险等级辅助判定
}


@dataclass
class AIConfig:
    provider: str = "none"
    base_url: str = "http://127.0.0.1:11434"
    model: str = "qwen2.5:7b"
    api_key: str = ""
    timeout: int = 90
    temperature: float = 0.2

    # ---- 视觉（多模态）相关 ----
    # 视觉模型单独配置：文本任务用便宜的小模型跑，视觉任务才吃大模型，
    # 是本地部署里最省钱也最稳的组合。留空则沿用 model。
    vision_model: str = ""
    vision_max_width: int = 720    # 截图送模型前的目标宽度（见 ai/vision.py 的说明）
    vision_quality: int = 72       # JPEG 质量
    vision_timeout: int = 180      # 视觉推理慢，单独给超时

    # ---- 上下文预算（对接小上下文模型的关键）----
    # 服务端 Modelfile：PARAMETER num_ctx 8192（2026-10-25 用 /api/show 核对）。
    # ★ 实测行为（同一模型，不传 options.num_ctx，走 Modelfile）：
    #     正文 4000 字 → prompt_eval_count 2037   完整
    #     正文 12000 字 → 6073                    完整
    #     正文 16000 字 → 8092                    完整（已贴近 8192 顶）
    #     正文 20000 字 → 4098                    **被截尾**
    #   两点很关键：
    #   ① 截尾后 count 会掉到 4098 左右（不是停在 8192），早先那个
    #      "只有 4096 可用"的结论正是把这个截断后的数字当成了上限，属于误读；
    #   ② 超限不报错、不提示，模型只看到一部分，报告却会写"已分析全文"。
    #   所以预算写进配置，所有 AI 调用点都按它裁剪/分段（见 ai/chunker.py、
    #   ai/base.py）。真实上限 8192，配置也写 8192，再由 max_output_tokens
    #   与 SYSTEM_RESERVE_TOKENS 扣掉输出和模板占位。
    context_tokens: int = 8192     # 服务端单次可用的输入预算（token）= num_ctx
    max_output_tokens: int = 1536  # 预留给回答的额度（分段抽取的 JSON 常 800~1200 token）

    # ---- 推理模型（qwen3.8 / QwQ / R1 这类带思考链的）----
    # 实测 qwen3.8-fast：开思考 2.0s/次、关思考 0.5s/次（4 倍差）。
    # 更麻烦的是**思考会吃掉 num_predict 预算**——120 的上限下思考写了 200 字，
    # content 直接是空的。我们这些任务是"按给定 JSON 骨架抽取"，
    # 不需要长链推理，关掉思考又快又稳。
    think: bool = False

    # 分段抽取的并发度。ollama 会自行排队，4 路实测约 2.3 倍吞吐。
    chunk_workers: int = 4

    # ---- 遍历环节的节流 ----
    # 遍历时「每一步都问一次模型」在真实环境里代价很高：本地 CPU 推理每步几十秒，
    # 云端 API 按量计费，中继模式下更会产生上百次人工往返。所以给两个闸门：
    #   ui_agent_every     —— 每 N 步问一次（中间步骤走规则遍历）
    #   ui_agent_max_calls —— 总调用上限，用完自动转规则遍历（0 = 不限）
    ui_agent_every: int = 1
    # 同一个界面最多问几次模型（0 = 不限）。默认 1：
    # 界面上"该点哪个入口"是节点级决策，问过一次就够，后续按图谱排序执行。
    ui_agent_per_node: int = 1
    ui_agent_max_calls: int = 0

    # ---- Agent 中继（provider = agent 时生效）----
    # 本机开发测试用：请求落盘、由对话里的 AI 看图和回答，不连任何模型服务。
    relay_dir: str = ""            # 留空 = out/ai_relay
    relay_timeout: int = 900       # 等一次回答的上限（秒），超时回退确定性策略

    features: Dict[str, bool] = field(default_factory=dict)

    def feature(self, name: str) -> bool:
        """环节开关。未显式配置时回落到默认表。"""
        if name in self.features:
            return bool(self.features[name])
        return bool(DEFAULT_AI_FEATURES.get(name, False))

    def vision_ready(self) -> bool:
        """是否具备「看截图」的条件：既开了开关，也配了服务。

        与 `AITasks.can_vision()` 同一口径：政策视觉或 UI 遍历任一开启即算，
        因为它们都要看图。两处口径不一致时，启动日志说"有视觉"、实际却回退，
        排查时会被误导。
        """
        return ((self.provider or "none") != "none"
                and (self.feature("policy_vision") or self.feature("ui_agent")))

    def apply_env_overrides(self) -> "AIConfig":
        """环境变量覆盖，优先级高于 yaml。便于在别的环境里不改文件直接切模型。"""
        env_map = {
            "PII_AI_PROVIDER": "provider",
            "PII_AI_BASE_URL": "base_url",
            "PII_AI_MODEL": "model",
            "PII_AI_API_KEY": "api_key",
            "PII_AI_VISION_MODEL": "vision_model",
            "PII_AI_RELAY_DIR": "relay_dir",
        }
        for env_key, attr in env_map.items():
            val = os.environ.get(env_key)
            if val:
                setattr(self, attr, val)
        return self


@dataclass
class DeviceConfig:
    serial: str = ""        # 留空 = 自动发现（恰好一台时自动选中）
    # 界面上"测试机"下拉框的默认选中项。只是默认值，不限制选择；
    # 该序列号不在线时由界面退回到第一台在线设备。
    preferred: str = ""
    port: int = 27042
    # frida-server 可执行文件在本机的位置。留空则按 search path 自动找。
    frida_server: str = ""
    # 每台测试机自带 SIM 的手机号（serial → 号码）。界面选机时用它自动切号码。
    # 用映射表而不是给每台写死字段：设备是插拔的，加一台不用改代码。
    phones: Dict[str, str] = field(default_factory=dict)


@dataclass
class ScanConfig:
    package: str = ""
    duration: int = 90
    spawn: bool = True
    max_events_per_hook: int = 12
    global_event_cap: int = 2500
    capture_screenshot: bool = True
    ui_walk: bool = True          # 是否自动遍历界面以触发行为
    ui_tap_interval: float = 1.2  # 每次点击后的等待间隔（秒）
    # ---- 页面图观测（P4 遍历轨迹）----
    # 只记录"走到了哪些界面、点了谁、落点如何"，**不参与决策**，打开它遍历
    # 行为与关闭时完全一致；关掉可一键回到旧行为（出问题时的止损开关）。
    crawl_observe: bool = True
    # ---- 遍历调度（P4 决策）----
    #   graph  = 页面图调度：DFS 栈 + tab 铺开 + 价值表 + 死点（Step 2 起的默认）
    #   legacy = 旧的逐屏贪心：按关键词排序取第一个没点过的
    # ★ 回退开关。调度出问题时改成 legacy 即可回到 Step 1 的行为，
    #   观测数据仍然照记 —— 两者是独立的开关，可以只关决策不关观测。
    crawl_mode: str = "graph"
    max_taps_per_state: int = 30   # 单屏最多尝试点击次数（防止某个列表页吃掉预算）
    # ---- 遍历台账 / 循环防护（2026-11-01）----
    # 两个 1 小时档任务（川剧迷/冰纷万象）90% 的预算耗在 A↔B 两屏来回：
    # 同一屏的「檢舉」被点 206~224 次、另一屏返回 225 次。每一步"界面都变了"，
    # 所以只看"界面没变"的熔断一次都没触发。这四档是替代判据：
    #   walk_tap_limit      —— 同一界面同一元素最多点几次（1 次探索 + 1 次复查）
    #   walk_freeze_sec     —— 判定循环后冻结该界面多久（秒）
    #   walk_sat_actions    —— 连续多少个动作没有新界面就判定遍历已完结
    #   walk_sat_min_actions—— 最少走够多少动作才允许判完结（防止刚起步就收工）
    walk_tap_limit: int = 2
    walk_freeze_sec: int = 180
    walk_sat_actions: int = 30
    walk_sat_min_actions: int = 45
    # 列表页滚到底后最多再上拉几次。上拉是"已到底还要再拉一下才加载下一页"
    # 这类列表的唯一触发手段；给 0 等于关掉上拉（退回 Step 2 的行为）。
    list_pull_max: int = 2
    # ---- 图引导遍历（P4 决策的第二层：AI 只在当前节点做选择）----
    #   guided = 先由本地图算出"当前界面还能做什么"，让模型只选编号；
    #            没有可用选项（WebView/自绘界面）时才回到"看截图自由规划"
    #   rule   = 完全不用图引导，回到"规则调度 + 自由规划"
    # ★ 与 crawl_mode 正交：crawl_mode 决定**规则调度器**用哪种算法，
    #   crawl_strategy 决定**AI** 有没有图素材。两个都关就是最早的逐屏贪心。
    crawl_strategy: str = "guided"
    shot_every_taps: int = 4      # 每点击多少次留一张截图（证据链）
    policy_wait: int = 22         # 首启观测阶段时长：等隐私政策弹窗（秒）
    reset_app: bool = True        # 检测前清除应用数据（必须，否则不出现首启弹窗）
    reinstall: bool = True        # 检测前安装待测 APK
    # ---- 登录辅助（很多功能页在登录态后面）----
    # 留空 = 不做登录，遍历只覆盖游客可见的界面。填了就用这个手机号代填，
    # 短信验证码由检测人员在平台上回填（脚本轮询等待，超时即如实记未完成）。
    login_phone: str = ""
    login_timeout: int = 180      # 等待验证码回填的秒数
    # ---- 复现轮（P7）----
    # 判定出问题项后，清除应用数据回到初始安装状态，然后**按首轮的点击路径重放**
    # （见 flow/replay.py）：首启 → 政策 → 同意 → 登录照旧重做，进入 UI 阶段后
    # 照抄首轮记下的 tap/back/swipe/pull 顺序，不调模型、不做新决策。
    # 这样两轮走的是同一批界面，"判据没再出现"才是真的未复现。
    repro_duration: int = 120     # 这一轮的总时长上限（含首启与登录）
    repro_policy_wait: int = 20
    # 重放每步之间的等待（秒）。首轮那 1.2 秒里有一部分是留给模型看下一张
    # 截图的，回放只看动作结果，可以更短；但太快会在界面还没加载完时 dump。
    replay_interval: float = 0.8
    # ---- 检测深度（三档，2026-11-19 用户重定的口径）----
    #   pre   1 档：只测「同意隐私政策之前」的行为，不点同意、不遍历（约 7 分钟）
    #   light 2 档：同意后约 15 分钟，不登录，只点到二级目录
    #   deep  3 档：全功能遍历（约 60 分钟），可登录，层级不限
    # normal 是历史档位（约 1.5 分钟），保留只为读得懂旧存档；表单不再提供。
    #
    # ★ 2026-11-19 由四档减为三档：原来的 3 档（15 分钟 / 可登录）取消 ——
    #   它和 2 档只差"能不能登录"，而 15 分钟在电商/生活服务类 App 上连主导航
    #   都铺不满，登录了也走不了几个页面，属于"看着比 2 档深、实际覆盖差不多"。
    #   原 4 档（60 分钟）直接改名为 3 档；原 2 档的时长提到 15 分钟
    #   （5 分钟只够点完首屏 icon，二级菜单一个都进不去，等于白跑一档）。
    # 为什么要有档位而不是让人手调六个数：这六个参数彼此耦合 ——
    # 只加时长不加上限，事件会先被 global_event_cap 截断；
    # 只加上限不加时长，遍历根本走不到深层的界面。
    # 档位一次把它们调配到同一水平，避免"以为测深了，其实只是等得更久"。
    depth: str = "normal"
    max_shots: int = 14           # 单轮最多保留多少张截图（证据图集与报告体积的平衡）
    # 遍历的界面层级上限（0 = 不限）。2 档「只点二级目录」用它。
    # 层级由页面图按"从入口点了几跳"记，不是猜 Activity 名字。
    max_depth: int = 0
    # 是否尝试登录（微信快捷登录 / 手机号验证码）。1、2 档显式关掉 ——
    # 登录会把界面推进到"登录后"，覆盖掉"游客可见"的取证口径。
    login_enabled: bool = True
    # 拿到政策正文后**不点同意**就收工（1 档的语义）。
    # 注意不能复用 ui_walk=False 代替：那个开关会连首启观测一起关掉，
    # 而 1 档的全部证据恰恰来自首启观测。
    consent_only: bool = False
    # 内部标记：这一份配置是否被套过档位表。
    # 用来区分"从没套过档"（此时套常规档应当保留配置文件里的现值）和
    # "套过别的档又退回常规"（此时必须把预算还原）。
    _depth_deep: bool = False
    _depth_applied: str = ""

    def apply_depth(self, name: str = "") -> str:
        """按档位调整采集预算，返回实际生效的档位名。

        ★ 常规档（normal）**不动**任何值
          配置文件里可能已经把 duration 改成 150（临时想跑久一点），
          如果常规档再用档位表里的 90 覆盖一遍，等于把使用者的设置悄悄改回去。
          常规档 = 保持配置现值；其余档 = 一次把整套预算同时调到位。
          档位表里的 normal 一栏仍然保留，它是对照基准（测试据此校验倍差）。

        未知档位名按 normal 处理而不是报错：表单/配置里写错一个词不该让整轮
        检测起不来；但也别静默成 deep（那会把 1 小时当 90 秒用，
        结果是一份"看起来测过"的报告）。返回生效档位，日志里打出来即可。
        """
        want = (name or self.depth or "normal").strip().lower()
        if want in _DEPTH_ALIASES:
            want = _DEPTH_ALIASES[want]
        if want not in DEPTH_PROFILES:
            want = "normal"
        prev = getattr(self, "_depth_applied", "")
        self.depth = want
        # 常规档：只有"刚刚套过别的档"时才还原（那说明这份配置被动过）。
        # 否则一律保留现值（可能是配置文件里特意改过的时长）。
        if want == "normal" and not prev:
            self._depth_deep = False
            return want
        for k, v in DEPTH_PROFILES[want].items():
            setattr(self, k, v)
        self._depth_applied = want
        self._depth_deep = want != "normal"
        return want


# 检测深度档位（2026-11-19 三档）。数值不是拍脑袋定的，每条都对应一次实测教训：
#   · duration       2 档 15 分钟：5 分钟只够点完首屏 icon，进不到二级菜单；
#                    3 档 60 分钟是"尽可能走全功能"的档，实测 15 分钟在
#                    电商/生活服务类 App 上只够铺开主导航 + 两三层菜单。
#   · policy_wait    加固/大型 App 冷启动要 30 秒以上才弹隐私框，22 秒会漏；
#                    高档位给得更宽，因为解壳时间随包体增大而变长。
#   · ui_tap_interval 深度模式下反而要慢一点：点太快容易被判成机器操作，
#                    也来不及观察加载中的界面。
#   · max_shots      报告体积与证据量的平衡：14 张只够"关键节点"，高阶档要够翻页；
#   · max_events_per_hook / global_event_cap
#                    单 hook 只留 12 条时，某个 SDK 的高频调用会把其他 SDK 挤掉，
#                    差集里就凭空少几个 SDK —— 这是最隐蔽的假阴性。
#   · max_depth      2 档「只点二级」：层级按页面图从入口点了几跳记，0 = 不限。
#   · login_enabled  1、2 档不做登录（口径是"游客可见"）；3 档才尝试登录。
#   · consent_only   1 档：不点同意；政策取到之后**继续在未同意状态下点**
#                    （除了同意，弹窗上的政策链接/设置/关闭、「不同意」「仅浏览」
#                    之后仍能进的主界面都算），因为只有动起来才会触发 SDK 初始化。
#   · consent_only   1 档：不点同意；政策取到之后**继续在未同意状态下点**
#                    （除了同意，弹窗上的政策链接/设置/关闭、「不同意」「仅浏览」
#                    之后仍能进的主界面都算），因为只有动起来才会触发 SDK 初始化。
DEPTH_PROFILES: Dict[str, Dict[str, Any]] = {
    "pre": {
        # ★ 2026-11-17 由 150 → 420：1 档从"取到政策就收工"改成
        #   "在未同意状态下尽量点多几个界面"。150 秒里政策观测就占 45 秒，
        #   剩下 100 秒只够点十下左右（每次 dump 要 2~8 秒），
        #   而那些只在二级界面才初始化的 SDK 一个都碰不到 —— 这正是
        #   "跑了十几个 App、一个同意前实锤都没有"的直接原因。
        # ★ 2026-11-18 45 → 60：与 4 档对齐。真机对照（同一批 App 跑 1 档
        #   与 4 档）量出来的采集点在**冷启动后 23~48 秒**：驿站助手 23.0s
        #   读 Android ID，贝利自动点击器 48.2s 读。45 秒的窗口对前者勉强、
        #   对后者差 3 秒 —— 而这段静置时间本来就是 1 档最该拿到的东西。
        "duration": 420, "policy_wait": 60, "ui_tap_interval": 1.4,
        "shot_every_taps": 3, "max_shots": 20,
        "max_events_per_hook": 20, "global_event_cap": 4000,
        "repro_duration": 120,
        "max_depth": 0, "login_enabled": False, "consent_only": True,
        "max_taps_per_state": 20, "list_pull_max": 1, "max_relaunch": 3,
    },
    "light": {
        # ★ 2026-11-19 300 → 900 秒（用户口径：1 档 7 分钟、2 档 15 分钟）。
        #   原来的 5 分钟只够"点完首屏 + 进一两个二级页"，报告里的
        #   "入口探索比例"长期停在 20%~30% —— 这一档的名字（浅测）于是
        #   成了自我实现的预言。max_depth 仍为 2：用途是"快速过一遍主流程"。
        "duration": 900, "policy_wait": 30, "ui_tap_interval": 1.4,
        "shot_every_taps": 4, "max_shots": 36,
        "max_events_per_hook": 24, "global_event_cap": 9000,
        "repro_duration": 180,
        "max_depth": 2, "login_enabled": False, "consent_only": False,
        "max_taps_per_state": 30, "list_pull_max": 2, "max_relaunch": 4,
    },
    "normal": {
        "duration": 90, "policy_wait": 22, "ui_tap_interval": 1.2,
        "shot_every_taps": 4, "max_shots": 14,
        "max_events_per_hook": 12, "global_event_cap": 2500,
        "repro_duration": 120,
        "max_depth": 0, "login_enabled": True, "consent_only": False,
        "max_taps_per_state": 30, "list_pull_max": 2, "max_relaunch": 4,
    },
    "deep": {
        # ★ 2026-11-19：原 4 档（extreme）整体改名为 3 档，参数原样沿用 ——
        #   这组值是唯一经过真机整轮验证的"走全功能"预算：1 小时里铺开主导航、
        #   逐层下钻、列表上拉到底、可登录。原 3 档（900 秒 / 可登录）取消，
        #   因为它与 2 档只差"能不能登录"，15 分钟连主导航都铺不满。
        "duration": 3600, "policy_wait": 60, "ui_tap_interval": 1.8,
        "shot_every_taps": 2, "max_shots": 160,
        "max_events_per_hook": 80, "global_event_cap": 40000,
        "repro_duration": 600,
        "max_depth": 0, "login_enabled": True, "consent_only": False,
        "max_taps_per_state": 60, "list_pull_max": 5, "max_relaunch": 10,
    },
}

# 档位别名：老表单/老配置里的写法不能直接失效。
# 「standard / quick」在早期文档里出现过；normal 保留为历史档（1.5 分钟）。
# ★ 2026-11-19 减为三档后，原来的 "4"/"extreme"（60 分钟）与 "3"
#   （15 分钟深度档）都指向现在的 3 档 —— 旧调用方按老习惯填 4，
#   拿到的是"尽量走全功能"，正是它本来想要的那一档，不会悄悄降级。
_DEPTH_ALIASES: Dict[str, str] = {
    "standard": "normal", "quick": "normal", "fast": "normal",
    "1": "pre", "2": "light", "3": "deep", "4": "deep",
    "extreme": "deep", "shallow": "light", "full": "deep", "max": "deep",
}

# 表单/日志里用的档位中文名（一处定义，平台与报告都从这里取）。
# ★ extreme 已不再是合法档位，但**报告层仍要能读旧存档**：
#   历史任务存档里的 depth 是 "extreme"，查不到标签就会把英文露在报告里。
#   兼容映射写在 sop_report._DEPTH_NAME 与 sop_brief._scope_line。
DEPTH_LABELS: Dict[str, str] = {
    "pre": "1 档 · 仅同意前（含未同意状态探索，约 7 分钟）",
    "light": "2 档 · 二级菜单（约 15 分钟 / 不登录 / 只到二级）",
    "normal": "常规（历史档，约 1.5 分钟）",
    "deep": "3 档 · 全功能（约 60 分钟 / 可登录 / 层级不限）",
}


@dataclass
class ReportConfig:
    title: str = "App 个人信息保护合规检测报告"
    out: str = "report.html"


@dataclass
class AppConfig:
    device: DeviceConfig = field(default_factory=DeviceConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    root: Path = field(default_factory=Path.cwd)

    @classmethod
    def load(cls, path: str | os.PathLike) -> "AppConfig":
        p = Path(path).resolve()
        raw: Dict[str, Any] = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return cls(
            device=_fill(DeviceConfig, raw.get("device")),
            scan=_fill(ScanConfig, raw.get("scan")),
            ai=_fill(AIConfig, raw.get("ai")).apply_env_overrides(),
            report=_fill(ReportConfig, raw.get("report")),
            root=p.parent,
        )

    def out_path(self) -> Path:
        out = Path(self.report.out)
        return out if out.is_absolute() else (self.root / out)


def _fill(cls, data):
    """只取 dataclass 已声明的字段，忽略 yaml 里多写的键。"""
    data = data or {}
    allowed = {f.name for f in dataclasses.fields(cls)}
    return cls(**{k: v for k, v in data.items() if k in allowed})
