"""视觉任务的基础设施 —— 把「截图交给大模型看」这件事里容易踩的坑集中在这里。

为什么单独一个模块：截图给模型看，看起来只是把图塞进请求，实际上有四个坑，
每一个都足以让整条链路废掉：

1. **体积**。真机截图是 1080×2400 的 PNG，动辄 2~4 MB，base64 之后更大。
   直接丢给多模态模型会撞上下文上限或超时。必须先等比缩小、转 JPEG 重编码。
   实测缩到宽 720、质量 72，一张首启弹窗约 60~120 KB —— 认字、认按钮、
   认「同意」和「不同意」的区别都够用，再大收益极小、代价很高。

2. **坐标系**。多模态模型给不出可靠的原图像素坐标（经常整张图差几百像素），
   但**归一化坐标（0~1）**很稳。因此所有 AI 返回的框一律按「相对所给图片」
   的归一化值解释，由这里换算回原图像素，业务层不必关心缩放比例。

3. **可点元素的语义**。这里有个关键取舍：
     · uiautomator 结构树 → bounds 精确到像素，但语义判断不可靠
       （标题「隐私政策」常是 clickable=false；「同意」是「不同意」的子串）
     · 视觉模型        → 语义判断可靠，但坐标不准
   于是把两者结合：把结构树里的候选**画成带编号的框**贴在图上，
   让模型只回答「哪个编号」，坐标仍取结构树的原始值。这条路还顺手解决了
   可审计性 —— 标注图会存进证据目录，人工复核时一眼能看出模型当时看到了什么。

4. **输出解析**。模型经常把 JSON 包在 ```json 里，或者前后加一段解释文字，
   甚至用全角引号。解析必须容错，否则一个格式抖动就让整条链路降级。
"""
from __future__ import annotations

import base64
import io
import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

try:  # Pillow 仅在启用视觉功能时才是硬依赖
    from PIL import Image, ImageDraw, ImageFont
    PIL_OK = True
    PIL_ERR = ""
except Exception as e:  # pragma: no cover - 取决于环境
    Image = ImageDraw = ImageFont = None  # type: ignore
    PIL_OK = False
    PIL_ERR = str(e)

# 一张截图缩放后的目标宽度。720 是实测的平衡点：
#   1080 → 720 后，正文小字（约 12~14pt）在多数多模态模型上仍可读；
#   再降到 540 就开始出现「认不出按钮文字」的漏判。
DEFAULT_MAX_WIDTH = 720
DEFAULT_QUALITY = 72

# 标注框的配色（RGB）。用高对比色，避免和 App 自己的主题色撞在一起。
BOX_COLOR = (255, 64, 64)
BOX_COLOR_ALT = (32, 144, 255)
LABEL_BG = (255, 64, 64)
LABEL_FG = (255, 255, 255)


@dataclass
class PreparedImage:
    """一张准备好送进模型的图。"""

    jpeg: bytes
    orig_w: int
    orig_h: int
    sent_w: int
    sent_h: int

    @property
    def scale(self) -> float:
        """原图 / 发送图 的比例。归一化坐标 → 原图坐标时乘它。"""
        return (self.orig_w / self.sent_w) if self.sent_w else 1.0

    @property
    def size_kb(self) -> float:
        return len(self.jpeg) / 1024.0

    def to_b64(self) -> str:
        return base64.b64encode(self.jpeg).decode("ascii")


@dataclass
class CandidateBox:
    """画在图上、供模型按编号选择的一个候选控件。"""

    index: int
    label: str                      # 界面上显示的文字/描述（给模型读的）
    bounds: Tuple[int, int, int, int]   # **原图**像素坐标
    tag: str = ""                   # 附带线索，如 "clickable" / "text"

    def to_prompt_line(self) -> str:
        x1, y1, x2, y2 = self.bounds
        extra = ("，%s" % self.tag) if self.tag else ""
        return "%d. %s%s" % (self.index, self.label, extra)


# ---------------------------------------------------------------- 图片处理

def _find_font(size: int):
    """找一个能画数字的字体。

    只用来画编号（纯数字），不需要中文字形，所以优先用系统里的西文字体，
    加载失败就退回 Pillow 内置位图字体 —— 编号画得丑总比画不出来强。
    """
    if ImageFont is None:
        return None
    for path in (
        r"C:\Windows\Fonts\arialbd.ttf",
        r"C:\Windows\Fonts\arial.ttf",
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    ):
        try:
            if os.path.isfile(path):
                return ImageFont.truetype(path, size)
        except Exception:
            continue
    try:
        return ImageFont.load_default(size)  # Pillow >= 10.1 支持 size 参数
    except Exception:
        try:
            return ImageFont.load_default()
        except Exception:
            return None


def prepare(png_bytes: bytes, max_width: int = DEFAULT_MAX_WIDTH,
            quality: int = DEFAULT_QUALITY) -> PreparedImage:
    """PNG 截图 → 等比缩放 → JPEG 重编码。

    竖屏截图只按宽度缩放（高度等比），保证不拉伸变形；
    如果原图本来就不宽（如平板横屏），则不做放大，避免糊掉。
    """
    if not PIL_OK:
        raise RuntimeError("缺少 Pillow，无法处理截图（pip install pillow）：%s" % PIL_ERR)
    img = Image.open(io.BytesIO(png_bytes))
    img = img.convert("RGB")
    orig_w, orig_h = img.size

    sent_w = min(orig_w, max_width)
    scale = sent_w / float(orig_w) if orig_w else 1.0
    sent_h = max(1, int(round(orig_h * scale)))
    if scale < 1.0:
        img = img.resize((sent_w, sent_h), Image.LANCZOS)

    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=quality, optimize=True)
    data = buf.getvalue()
    # 低熵截图（纯白页、只有几个字的弹窗）用 PNG 无损压反而更小：
    # 实测一张 12.9 KB 的合成图重编码成 JPEG q72 变成 20.5 KB。
    # 这时保留原图 —— 多传 60% 字节换不来任何清晰度收益。
    if scale >= 1.0 and len(png_bytes) < len(data):
        data = png_bytes
    return PreparedImage(jpeg=data, orig_w=orig_w, orig_h=orig_h,
                         sent_w=sent_w, sent_h=sent_h)


def annotate(png_bytes: bytes, candidates: Sequence[CandidateBox],
             max_width: int = DEFAULT_MAX_WIDTH, quality: int = DEFAULT_QUALITY,
             columns: int = 1) -> Tuple[PreparedImage, List[CandidateBox]]:
    """把候选控件画成带编号的框，贴在截图上。

    编号是模型与我们之间的唯一约定：模型只需要回答「3」，
    我们就能从候选表里取出**精确到像素**的 bounds。

    返回 (处理后的图, 实际画上去的候选列表)。
    只画落在图内的候选，且跳过面积过大的框 —— 整屏容器（如 FrameLayout）
    会盖住其它所有框，把图糊成一片，反而让模型看不清。
    """
    if not PIL_OK:
        raise RuntimeError("缺少 Pillow，无法标注截图：%s" % PIL_ERR)

    img = Image.open(io.BytesIO(png_bytes)).convert("RGB")
    orig_w, orig_h = img.size
    sent_w = min(orig_w, max_width)
    scale = sent_w / float(orig_w) if orig_w else 1.0
    sent_h = max(1, int(round(orig_h * scale)))
    if scale < 1.0:
        img = img.resize((sent_w, sent_h), Image.LANCZOS)

    draw = ImageDraw.Draw(img)
    font = _find_font(max(14, int(sent_w / 34)))
    full_area = sent_w * sent_h

    drawn: List[CandidateBox] = []
    for c in candidates:
        x1, y1, x2, y2 = c.bounds
        sx1, sy1 = int(x1 * scale), int(y1 * scale)
        sx2, sy2 = int(x2 * scale), int(y2 * scale)
        w, h = sx2 - sx1, sy2 - sy1
        if w <= 0 or h <= 0:
            continue
        if w * h > full_area * 0.85:        # 整屏容器，画上去只会糊住别的框
            continue
        color = BOX_COLOR if len(drawn) % 2 == 0 else BOX_COLOR_ALT
        draw.rectangle([sx1, sy1, sx2, sy2], outline=color, width=3)
        tag = str(len(drawn) + 1)
        if font is not None:
            try:
                tb = draw.textbbox((0, 0), tag, font=font)
                tw, th = tb[2] - tb[0], tb[3] - tb[1]
            except Exception:
                tw, th = 8 * len(tag), 14
            pad = 3
            bx1 = max(0, sx1)
            by1 = max(0, sy1 - th - 2 * pad)
            draw.rectangle([bx1, by1, bx1 + tw + 2 * pad, by1 + th + 2 * pad],
                           fill=LABEL_BG)
            draw.text((bx1 + pad, by1 + pad - (tb[1] if 'tb' in dir() else 0)),
                      tag, fill=LABEL_FG, font=font)
        drawn.append(CandidateBox(index=len(drawn) + 1, label=c.label,
                                  bounds=c.bounds, tag=c.tag))

    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=quality, optimize=True)
    return (PreparedImage(jpeg=buf.getvalue(), orig_w=orig_w, orig_h=orig_h,
                          sent_w=sent_w, sent_h=sent_h),
            drawn)


def norm_to_px(bbox: Sequence[float], orig_w: int, orig_h: int,
               clamp: bool = True) -> Optional[Tuple[int, int, int, int]]:
    """归一化坐标（0~1，相对所给图片）→ 原图像素坐标。

    模型偶尔不听提示词，给出 0~1000 这种刻度（把坐标当成了千分比）。
    这里做一次启发式归一，但**判据收得很紧**：只有四个值全部非负、
    且明显超出 1 时才按 0~1000 解释。

    为什么收紧：猜错的代价极不对称。猜对只是省一次回退，猜错会让点击落到
    完全无关的位置（甚至触发危险按钮）。所以宁可放弃猜测、交给调用方回退到
    候选框策略 —— 那条路的坐标来自 uiautomator，是精确的。
    """
    try:
        vals = [float(v) for v in bbox[:4]]
    except Exception:
        return None
    if len(vals) != 4:
        return None
    if max(vals) > 1.5 and min(vals) >= 0:
        vals = [v / 1000.0 for v in vals]
    x1, y1, x2, y2 = vals
    if x2 < x1:
        x1, x2 = x2, x1
    if y2 < y1:
        y1, y2 = y2, y1
    px = (int(round(x1 * orig_w)), int(round(y1 * orig_h)),
          int(round(x2 * orig_w)), int(round(y2 * orig_h)))
    if clamp:
        px = (max(0, min(px[0], orig_w)), max(0, min(px[1], orig_h)),
              max(0, min(px[2], orig_w)), max(0, min(px[3], orig_h)))
    return px


def plausible_box(px: Optional[Tuple[int, int, int, int]],
                  orig_w: int, orig_h: int,
                  min_side: int = 8, max_area_ratio: float = 0.9) -> bool:
    """换算出来的框是否**值得照着点**。

    这是防「模型坐标不可靠」的最后一道闸：过小的框（几个像素，多半是解析噪声）
    和过大的框（几乎整屏，多半是把容器或整张图当成了目标）都不能用。
    宁可放弃这个坐标、退回候选框，也不要往一个说不清的地方点下去。
    """
    if not px or orig_w <= 0 or orig_h <= 0:
        return False
    x1, y1, x2, y2 = px
    w, h = x2 - x1, y2 - y1
    if w < min_side or h < min_side:
        return False
    if (w * h) > (orig_w * orig_h) * max_area_ratio:
        return False
    return True


def center_of(px: Tuple[int, int, int, int]) -> Tuple[int, int]:
    x1, y1, x2, y2 = px
    return (x1 + x2) // 2, (y1 + y2) // 2


# ------------------------------------------------- 彩色文字带精定位（AI 粗 + 像素精）

def find_colored_text_run(png_bytes: bytes, box: Tuple[int, int, int, int],
                          band_ratio: float = 1.6,
                          chroma: int = 40) -> Optional[Tuple[int, int, int, int]]:
    """在 AI 给的框附近，用「彩色文字」这一视觉特征把目标行精确定位出来。

    ★ 为什么需要这一步（真机实测踩到的坑）：
      AI（人也好、模型也好）给的框只能保证"大致在这一带"。
      赣警办首启弹窗每次启动的**竖直位置会浮动**（同一台机、同一个 App，
      上一轮链接文字在 y 875..914，这一轮在 843..873，差了约 30px）。
      直接照搬上一次的坐标 → 点击落在两行文字之间的空白上 → 弹窗纹丝不动，
      报告于是写成「点击入口后界面未跳转」，把"链接打不开"这件事漏过去。
      框内按比例取采样点也救不了：采样点都落在同一个错误的带里。

      而链接文字有个稳定得多的特征 —— **它是彩色的**（通常是蓝色、带下划线），
      周围正文都是黑/深灰。于是：AI 负责"大概在哪一块"，像素负责"到底是哪一行"。

    box 用**原图像素**坐标。搜索范围向上下各扩 band_ratio × 框高，
    并保证至少扩 80px（约等于 1080p 上一行正文的高度）——
    实测的偏差量级正好是"偏了一行"这个级别，窗口小于一行就会把目标带裁掉。
    返回彩色文字带的像素框；找不到（附近没有彩色文字）返回 None，
    调用方据此回退到普通采样点 —— 不强求，能识别才精定位。
    """
    try:
        from PIL import Image
    except Exception:                       # 没装 Pillow 就退回原路径
        return None
    try:
        im = Image.open(io.BytesIO(png_bytes)).convert("RGB")
    except Exception:
        return None
    W, H = im.size
    x1, y1, x2, y2 = (int(v) for v in box)
    h = max(1, y2 - y1)
    pad = int(max(h * max(0.0, band_ratio), 80))
    # 搜索区：横向略放宽（链接可能比模型给的框宽），纵向上下各扩一个多行高
    sx1 = max(0, min(x1, x2) - int(h * 1.2))
    sx2 = min(W, max(x1, x2) + int(h * 1.2))
    sy1 = max(0, min(y1, y2) - pad)
    sy2 = min(H, max(y1, y2) + pad)
    if sx2 - sx1 < 4 or sy2 - sy1 < 4:
        return None

    px = im.load()
    rows: Dict[int, List[int]] = {}
    for y in range(sy1, sy2):
        for x in range(sx1, sx2):
            r, g, b = px[x, y]
            mx, mn = max(r, g, b), min(r, g, b)
            # 彩色 = 通道差异明显；同时排除接近纯白/纯黑的背景与正文。
            # ★ 上界不能用 `mx < 250`（2026-11-06 万步健康 land29 实测）：
            #   该弹窗的链接色是 (92, 92, 255) —— B 通道满值 255，被判据直接排除，
            #   于是"附近没有彩色文字"，像素校准整条失效。
            #   而真正被认成"彩色文字"的是弹窗外面一块橙色 (245,140,40)：
            #   校准点跑到别处 → 偏移过大被拒 → 等于没校准，
            #   16 个采样点全落在链接下方一行，点了 16 次一次没中。
            #   正确的排除条件是"接近白"（三个通道都高），而不是"某个通道高"：
            #   饱和蓝 (92,92,255) 的 mn=92 明显不是白，浅蓝 (175,175,255) 也不是。
            if mx - mn >= chroma and mx >= 40 and mn <= 235:
                rows.setdefault(y, []).append(x)
    if not rows:
        return None

    # 找**连续的行带**：彩色文字每行有几十个像素，图标/分隔线只有零星几个点。
    #
    # ★ 收集「全部」行带再挑，不能只留最长的（2026-11-06 万步健康）：
    #   那一屏的搜索区里同时有蓝色链接（38 行）和弹窗外的橙色块（37 行），
    #   按"最长"选只差一行，等于抛硬币；选错的那一次会被偏移检查拒掉，
    #   校准静默失效，而日志里一句解释都没有。
    #   改按"离 AI 框中心最近"选 —— AI 的框只错一行是常态，
    #   真正要修的就是这一行的偏差，隔得远的彩色元素不是我们的目标。
    runs: List[List[int]] = []
    cur: List[int] = []
    for y in range(sy1, sy2):
        if rows.get(y):
            cur.append(y)
        else:
            if cur:
                runs.append(cur)
            cur = []
    if cur:
        runs.append(cur)
    runs = [r for r in runs if len(r) >= 4]      # 行高不足 4px，多半是噪声
    if not runs:
        return None
    cy_box = (y1 + y2) / 2.0
    x_lo, x_hi = min(x1, x2), max(x1, x2)

    # ★ 先在"与框横向有重叠"的候选里挑，再按离框中心最近排序（2026-11-06 万步健康）。
    #   那条弹窗的链接「《隐私政策》」跨行折到了下一行开头，于是搜索区里有两段蓝字：
    #     ① x 440..649, y 1338..1375  与框 (370..860) 重叠 ← 我们要的
    #     ② x 212..314, y 1409..1446  在框左边外面 ← 折行的后半截
    #   只按"就近"选会挑到②（离框中心 37px，比①的 108px 近），
    #   而②通不过横向重叠检查 → refine 直接返回 None，校准又白做一次。
    #   横向重叠说明"这段彩色文字确实在 AI 框覆盖的那一列里"，
    #   是判断"同一元素"比纵向距离更硬的依据。
    best: List[int] = []
    best_key: Optional[tuple] = None
    for r in runs:
        xs_r = [x for y in r for x in rows.get(y, [])]
        if not xs_r:
            continue
        if max(xs_r) < x_lo or min(xs_r) > x_hi:
            continue                     # 在这一列之外，不是本框的目标
        key = (abs((r[0] + r[-1]) / 2.0 - cy_box), -len(r))
        if best_key is None or key < best_key:
            best, best_key = r, key
    if not best:
        # 框这一列附近没有任何彩色文字 —— 返回 None，让上层走普通采样点，
        # 不拿别处的彩色元素冒充（学丞事故就是"拿别处的彩色元素当目标"）。
        return None

    ys = [y for y in best]
    xs = [x for y in best for x in rows.get(y, [])]
    if not xs:
        return None
    # 取该带内彩色像素的**横向主区间**（去掉个别偏远的点）
    xs.sort()
    lo = xs[int(len(xs) * 0.02)]
    hi = xs[int(len(xs) * 0.98) - 1] if len(xs) > 2 else xs[-1]
    return (lo, min(ys), hi, max(ys))


def refine_click_point(png_bytes: bytes, box: Tuple[int, int, int, int],
                       band_ratio: float = 1.6,
                       ) -> Optional[Tuple[int, int, int, int]]:
    """给「AI 给的框」返回一个更贴合彩色文字行的框；无法精定位时返回 None。

    只在框**明显偏离**彩色文字带时才替换（偏移超过框高的一半），
    否则保留原框 —— AI 若已经给准了，就没有理由再动它。
    """
    got = find_colored_text_run(png_bytes, box, band_ratio=band_ratio)
    if not got:
        return None
    x1, y1, x2, y2 = box
    h = max(1, abs(y2 - y1))
    # ★ 纵向偏移超过一个框高 → 认错元素了，必须放弃。
    #   真实事故（学丞 v1.5.6）：AI 框 (362,1367,718,1419) 指向弹窗里的
    #   《隐私协议》，「彩色文字带」却找到了下方 85px 处的另一行彩色文字
    #   （实测点下去直接触发了「同意」，页面跳到 GuideActivity，政策正文 0 字，
    #   整轮检测从 5 项判定退化到 1 项）。横向重叠检查拦不住这种错误：
    #   两行文字本来就在同一条竖直带上，横向当然重叠。
    #   refine 的职责是"在同一个按钮内部微调行高"，不是"换到另一个按钮"。
    cy_ai = (y1 + y2) / 2.0
    cy_got = (got[1] + got[3]) / 2.0
    # ★ 容差取 1.5 个框高，不是 1.0（2026-11-06 万步健康 land29 实测）：
    #   AI 框 (370,1414,860,1514) 高 100，框住的是链接**下面那一行**正文；
    #   真实链接在 y 1338..1375，中心距框中心 108px = 1.08 个框高 ——
    #   旧判据 1.0 正好把它拒掉，校准返回 None，16 个采样点全落在错行上。
    #   而"偏一行"恰恰是 AI 看图定位最常见的误差量级，不是认错元素。
    #   学丞事故那种"点到了下面的「同意」按钮"偏移 85px / 框高 52 = 1.63 倍，
    #   仍会被这道闸门挡住 —— 放宽到 1.5 不推翻原来的教训。
    if abs(cy_got - cy_ai) > h * 1.5:
        return None
    # 框与彩色带基本重合 → 不需要修正
    if abs(got[1] - min(y1, y2)) <= h * 0.5 and abs(got[3] - max(y1, y2)) <= h * 0.5:
        return None
    # 精定位结果必须与原框横向有明显重叠，否则可能是认错了别的彩色元素
    if got[2] < min(x1, x2) or got[0] > max(x1, x2):
        return None
    return got


# ---------------------------------------------------------------- 输出解析

_FENCE = re.compile(r"```(?:json|JSON)?\s*(.*?)```", re.S)


def parse_json(text: str) -> Optional[dict]:
    """从模型输出里抠出 JSON 对象。

    依次尝试：
      1. 整段就是 JSON
      2. ```json ... ``` 代码块里的内容
      3. 第一个 `{` 到最后一个 `}` 之间的内容（模型常前后加解释）
    另外顺手把全角引号/括号换成半角 —— 中文模型偶尔会输出全角标点，
    这会让 json.loads 直接失败，属于纯粹的形式问题，值得在解析层兜掉。
    """
    if not text:
        return None
    s = text.strip()
    for cand in [s] + _FENCE.findall(s):
        got = _try_load(cand)
        if got is not None:
            return got
    i, j = s.find("{"), s.rfind("}")
    if 0 <= i < j:
        got = _try_load(s[i:j + 1])
        if got is not None:
            return got
    return None


def _try_load(s: str) -> Optional[dict]:
    s = (s or "").strip()
    if not s:
        return None
    for cand in (s, _normalize_punct(s)):
        try:
            obj = json.loads(cand)
        except Exception:
            continue
        if isinstance(obj, dict):
            return obj
        if isinstance(obj, list) and obj and isinstance(obj[0], dict):
            return {"items": obj}
    return None


def _normalize_punct(s: str) -> str:
    """全角标点 → 半角。仅处理结构符号，不动字符串里的中文内容。"""
    table = {"“": '"', "”": '"', "‘": "'", "’": "'",
             "：": ":", "，": ",", "｛": "{", "｝": "}",
             "［": "[", "］": "]", "（": "(", "）": ")"}
    out = s
    for k, v in table.items():
        out = out.replace(k, v)
    return out


def as_bool(v, default: bool = False) -> bool:
    """模型返回的布尔值可能是 "true" / "是" / 1，统一收敛。"""
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        t = v.strip().lower()
        if t in ("true", "yes", "1", "是", "有", "命中", "存在"):
            return True
        if t in ("false", "no", "0", "否", "没有", "不存在", ""):
            return False
    return default


def as_float(v, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return default


def as_list(v) -> List:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    if isinstance(v, str):
        return [v] if v.strip() else []
    return [v]
