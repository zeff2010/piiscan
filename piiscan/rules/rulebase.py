"""规则库加载：checkitems.yaml（测评项）+ signal_map.yaml（采集信号）。

两者都是「与模板无关」的知识资产：
  · checkitems 决定「检测什么、依据什么条款、要什么证据」
  · signal_map 决定「什么 API 调用对应什么个人信息类型」
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

ROOT = Path(__file__).resolve().parent.parent.parent      # .../piiscan/
ANALYSIS = ROOT / "analysis"


def _load(path: Path) -> Dict[str, Any]:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


class CheckItems:
    """测评项知识库。"""

    def __init__(self, data: Dict[str, Any]):
        self.raw = data
        self.items: Dict[str, Dict[str, Any]] = {}
        for it in (data.get("items") or []):
            if it.get("id"):
                self.items[it["id"]] = it
        self.categories: Dict[str, Dict[str, Any]] = {}
        for c in (data.get("categories") or []):
            if c.get("id"):
                self.categories[c["id"]] = c
        self.templates: List[Dict[str, Any]] = list(data.get("templates") or [])

    def get(self, qid: str) -> Dict[str, Any]:
        return self.items.get(qid, {})

    def title(self, qid: str) -> str:
        return (self.get(qid) or {}).get("title", qid)

    def category_name(self, qid: str) -> str:
        cid = (self.get(qid) or {}).get("category", "")
        c = self.categories.get(cid, {})
        num = c.get("num", "")
        name = c.get("name", "")
        return ("%s、%s" % (num, name)) if num else name

    def basis(self, qid: str) -> str:
        return (self.get(qid) or {}).get("basis", "")

    def unit(self, qid: str) -> str:
        """从 basis 里抽出测评单元编号，如 PIC-19 / RPI-24。"""
        b = self.basis(qid)
        import re
        m = re.search(r"[（(]([A-Z]{3}-\d{1,3})[）)]", b)
        return m.group(1) if m else ""

    def freq(self, qid: str) -> int:
        try:
            return int((self.get(qid) or {}).get("freq", 0) or 0)
        except Exception:
            return 0

    def automation(self, qid: str) -> str:
        return (self.get(qid) or {}).get("automation", "")

    def pain(self, qid: str) -> str:
        return (self.get(qid) or {}).get("pain", "")

    def all_ids(self) -> List[str]:
        return list(self.items.keys())


class SignalMap:
    """采集信号映射表：API → 信号 → 个人信息类型。"""

    def __init__(self, data: Dict[str, Any]):
        self.raw = data
        self.signals: List[Dict[str, Any]] = list(data.get("signals") or [])
        self.by_id: Dict[str, Dict[str, Any]] = {s["id"]: s for s in self.signals if s.get("id")}
        self.pi: Dict[str, Dict[str, Any]] = {}
        for p in (data.get("pi_vocab") or []):
            if p.get("id"):
                self.pi[p["id"]] = p
        self.feeds: Dict[str, Dict[str, Any]] = dict(data.get("feeds") or {})
        self.sinks: List[Dict[str, Any]] = list(data.get("sinks") or [])
        self.dedup: List[Dict[str, Any]] = list(data.get("dedup_rules") or [])
        self._api_index: Dict[str, Dict[str, Any]] = {}
        for s in self.signals:
            for api in (s.get("api") or []):
                self._api_index[self._norm(api)] = s

    @staticmethod
    def _norm(api: str) -> str:
        """把 `类#方法()` 归一化成 `类#方法`（去掉括号与参数）。"""
        api = (api or "").strip()
        if "#" in api:
            cls, _, meth = api.partition("#")
            meth = meth.split("(")[0].strip()
            return "%s#%s" % (cls.strip(), meth)
        return api

    def match_api(self, api: str) -> Optional[Dict[str, Any]]:
        n = self._norm(api)
        s = self._api_index.get(n)
        if s:
            return s
        # 退化匹配：只按方法名（部分 hook 上报的是简写形式）
        if "#" in n:
            _, _, meth = n.partition("#")
            for key, item in self._api_index.items():
                if key.endswith("#" + meth):
                    return item
        return None

    def pi_of(self, signal: Dict[str, Any]) -> Dict[str, Any]:
        return self.pi.get((signal or {}).get("pi", ""), {})

    def pi_name(self, pi_id: str) -> str:
        return (self.pi.get(pi_id) or {}).get("name", pi_id)

    def feeds_for(self, qid: str) -> List[str]:
        return list((self.feeds.get(qid) or {}).get("signals") or [])

    def dedup_group(self, sid: str) -> List[str]:
        for r in self.dedup:
            if sid in (r.get("members") or []):
                return list(r["members"])
        return [sid]


@lru_cache(maxsize=1)
def checkitems() -> CheckItems:
    return CheckItems(_load(ANALYSIS / "checkitems.yaml"))


@lru_cache(maxsize=1)
def signal_map() -> SignalMap:
    return SignalMap(_load(ANALYSIS / "signal_map.yaml"))
