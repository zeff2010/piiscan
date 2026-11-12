"""纯 Python 的 Android 二进制 XML（AXML）解析器。

用途：在没有 aapt / 无法调用外部工具的环境下，直接从 APK 的
AndroidManifest.xml 中解析出包名、版本、权限、组件等关键信息。

实现依据 AOSP 的 ResXMLTree 二进制格式（resources.arsc 的 chunk 结构）。
只做读取，不做校验，遇到异常 chunk 会跳过而不是抛错。
"""
from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional

# ---- chunk 类型 ----
RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_TYPE = 0x0002
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

# ---- attribute typedValue 的 dataType ----
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

# android 命名空间下常用属性的资源 ID -> 名称
# （AXML 里属性名以资源 ID 存储，需要反查）
ANDROID_ATTRS: Dict[int, str] = {
    0x01010000: "theme",
    0x01010001: "label",
    0x01010002: "icon",
    0x01010003: "name",
    0x01010004: "permission",
    0x01010005: "process",
    0x01010006: "exported",
    0x01010007: "taskAffinity",
    0x01010008: "enabled",
    0x0101000E: "authorities",
    0x01010010: "exported",
    0x01010018: "authorities",
    0x0101001E: "grantUriPermissions",
    0x01010020: "protectionLevel",
    0x01010021: "permissionGroup",
    0x01010022: "description",
    0x0101020C: "minSdkVersion",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x0101021E: "permission",
    0x01010270: "targetSdkVersion",
    0x01010271: "maxSdkVersion",
    0x01010280: "allowBackup",
    0x010102B7: "installLocation",
    0x010102D9: "required",
    0x0101035F: "debuggable",
    0x010103F6: "hardwareAccelerated",
    0x010104EA: "usesCleartextTraffic",
    0x010104EC: "networkSecurityConfig",
    0x0101051A: "requestLegacyExternalStorage",
    0x0101055C: "roundIcon",
    0x01010572: "appComponentFactory",
}


class _ResStringPool:
    """字符串池。flags 的 bit8 表示 UTF-8 编码，否则为 UTF-16LE。"""

    UTF8_FLAG = 1 << 8

    def __init__(self, data: bytes):
        self.strings: List[str] = []
        if len(data) < 28:
            return
        (_type, _hsize, _size, string_count, _style_count,
         flags, strings_start, _styles_start) = struct.unpack_from("<HHIIIIII", data, 0)
        self.utf8 = bool(flags & self.UTF8_FLAG)
        offsets = struct.unpack_from("<%dI" % string_count, data, 28)
        base = strings_start
        for off in offsets:
            pos = base + off
            if pos >= len(data):
                self.strings.append("")
                continue
            try:
                self.strings.append(self._read_string(data, pos))
            except Exception:
                self.strings.append("")

    def _read_string(self, data: bytes, pos: int) -> str:
        if self.utf8:
            # u16 len（字符数的高位标记） -> u8 字节数 -> 字节
            n = data[pos]
            pos += 1
            if n & 0x80:
                n = ((n & 0x7F) << 8) | data[pos]
                pos += 1
            blen = data[pos]
            pos += 1
            if blen & 0x80:
                blen = ((blen & 0x7F) << 8) | data[pos]
                pos += 1
            return data[pos:pos + blen].decode("utf-8", errors="replace")
        # UTF-16LE：u16 字符数（高字节可能带 0x80 标记）
        n = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        if n & 0x8000:
            n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, pos)[0]
            pos += 2
        return data[pos:pos + n * 2].decode("utf-16-le", errors="replace")

    def get(self, idx: int) -> str:
        if 0 <= idx < len(self.strings):
            return self.strings[idx]
        return ""


class AXMLParser:
    """解析 AndroidManifest.xml，产出结构化 dict。"""

    def __init__(self, data: bytes):
        self.data = data
        self.strings = _ResStringPool(b"")
        self.res_map: List[int] = []
        self.elements: List[Dict[str, Any]] = []
        self._parse()

    # -------------------------------------------------- 内部
    def _parse(self) -> None:
        data = self.data
        if len(data) < 8:
            return
        ctype, _hsize, _size = struct.unpack_from("<HHI", data, 0)
        if ctype != RES_XML_TYPE:
            # 不是 AXML（有些包会把 manifest 存为明文 XML）
            return

        pos = 8
        stack: List[Dict[str, Any]] = []
        while pos + 8 <= len(data):
            chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, pos)
            if chunk_size < 8 or pos + chunk_size > len(data):
                break
            body = data[pos:pos + chunk_size]

            if chunk_type == RES_STRING_POOL_TYPE:
                self.strings = _ResStringPool(body)
            elif chunk_type == RES_XML_RESOURCE_MAP_TYPE:
                n = (chunk_size - header_size) // 4
                if n > 0:
                    self.res_map = list(struct.unpack_from("<%dI" % n, body, header_size))
            elif chunk_type == RES_XML_START_ELEMENT_TYPE:
                el = self._read_element(body, header_size)
                if el:
                    el["parent"] = stack[-1]["tag"] if stack else None
                    self.elements.append(el)
                    stack.append(el)
            elif chunk_type == RES_XML_END_ELEMENT_TYPE:
                if stack:
                    stack.pop()

            pos += chunk_size

    def _read_element(self, body: bytes, header_size: int) -> Optional[Dict[str, Any]]:
        # START_ELEMENT 结构：
        #   0..7   ResChunk_header
        #   8      lineNumber
        #   12     comment
        #   16     ns            (ResXMLTree_attrExt 起点)
        #   20     name
        #   24     attributeStart / attributeSize / attributeCount
        #   30     idIndex / classIndex / styleIndex
        # 注意：attributeStart 是相对于 attrExt 起点（offset 16）的偏移，
        # 典型值为 20，因此第一个属性落在 16 + 20 = 36 处。
        try:
            name_idx = struct.unpack_from("<I", body, 20)[0]
            attr_start = struct.unpack_from("<H", body, 24)[0]
            attr_size = struct.unpack_from("<H", body, 26)[0]
            attr_count = struct.unpack_from("<H", body, 28)[0]
        except struct.error:
            return None

        if attr_size < 20:
            attr_size = 20
        attrs: Dict[str, str] = {}
        raw_attrs: List[Dict[str, Any]] = []
        for i in range(attr_count):
            off = 16 + attr_start + i * attr_size
            if off + 20 > len(body):
                break
            a_ns, a_name, a_raw = struct.unpack_from("<III", body, off)
            v_type = body[off + 15]
            v_data = struct.unpack_from("<I", body, off + 16)[0]

            key = self._attr_name(a_name)
            val = self._attr_value(a_raw, v_type, v_data)
            attrs[key] = val
            raw_attrs.append({"name": key, "value": val,
                              "ns": self.strings.get(a_ns) if a_ns != 0xFFFFFFFF else ""})

        return {
            "tag": self.strings.get(name_idx),
            "attrs": attrs,
            "raw": raw_attrs,
        }

    def _attr_name(self, idx: int) -> str:
        # 属性名本来就存在于字符串池中（如 versionCode / package）。
        name = self.strings.get(idx)
        if name:
            return name
        # 若索引落在资源映射区内，用资源 ID 反查已知的 android: 属性名。
        if 0 <= idx < len(self.res_map):
            rid = self.res_map[idx]
            return ANDROID_ATTRS.get(rid, "0x%08x" % rid)
        return "attr_%d" % idx

    def _attr_value(self, raw_idx: int, v_type: int, v_data: int) -> str:
        if raw_idx != 0xFFFFFFFF:
            s = self.strings.get(raw_idx)
            if s:
                return s
        if v_type == TYPE_STRING:
            return self.strings.get(v_data)
        if v_type == TYPE_INT_BOOLEAN:
            return "true" if v_data else "false"
        if v_type == TYPE_INT_DEC:
            return str(v_data)
        if v_type == TYPE_INT_HEX:
            return "0x%x" % v_data
        if v_type == TYPE_REFERENCE:
            return "@0x%08x" % v_data
        if v_type == TYPE_NULL:
            return ""
        return str(v_data)

    # -------------------------------------------------- 对外
    def manifest(self) -> Dict[str, Any]:
        """把元素序列整理成便于消费的结构。"""
        out: Dict[str, Any] = {
            "package": "", "versionName": "", "versionCode": "",
            "minSdkVersion": "", "targetSdkVersion": "", "label": "",
            "application": {}, "permissions": [], "declared_permissions": [],
            "activities": [], "services": [], "receivers": [], "providers": [],
            "features": [], "libraries": [], "activities_count": 0,
            "usesCleartextTraffic": "", "debuggable": "", "allowBackup": "",
        }
        for el in self.elements:
            tag = el["tag"]
            a = el["attrs"]
            if tag == "manifest":
                out["package"] = a.get("package", "")
                out["versionName"] = a.get("versionName", "")
                out["versionCode"] = a.get("versionCode", "")
            elif tag == "uses-sdk":
                out["minSdkVersion"] = a.get("minSdkVersion", "")
                out["targetSdkVersion"] = a.get("targetSdkVersion", "")
            elif tag == "uses-permission" or tag == "uses-permission-sdk-23":
                n = a.get("name", "")
                if n:
                    out["permissions"].append(n)
            elif tag == "permission":
                n = a.get("name", "")
                if n:
                    out["declared_permissions"].append(n)
            elif tag == "uses-feature":
                n = a.get("name", "")
                if n:
                    out["features"].append(n)
            elif tag == "uses-library":
                n = a.get("name", "")
                if n:
                    out["libraries"].append(n)
            elif tag == "application":
                out["application"] = dict(a)
                out["label"] = a.get("label", "")
                for k in ("usesCleartextTraffic", "debuggable", "allowBackup"):
                    if k in a:
                        out[k] = a[k]
            elif tag in ("activity", "activity-alias", "service", "receiver", "provider"):
                key = {"activity": "activities", "activity-alias": "activities",
                       "service": "services", "receiver": "receivers",
                       "provider": "providers"}[tag]
                out[key].append(dict(a))

        out["activities_count"] = len(out["activities"])
        # 去重保持顺序
        out["permissions"] = list(dict.fromkeys(out["permissions"]))
        return out


def parse_manifest_bytes(data: bytes) -> Dict[str, Any]:
    return AXMLParser(data).manifest()


def is_binary_xml(data: bytes) -> bool:
    return len(data) >= 4 and data[:2] == b"\x03\x00"
