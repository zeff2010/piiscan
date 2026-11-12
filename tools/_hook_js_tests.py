#!/usr/bin/env python3
"""hook 脚本（collector.js）的行为自测 —— 用 Node 跑，不需要真机。

为什么值得单独有这一层
----------------------
`install()` 是整个采集脚本唯一的 hook 安装器，里面有两件事**只能靠代码本身
保证**、真机很难"恰好"复现：

  ① **调用被系统拒绝时也要留痕**（2026-11-10 Android 10）。
     Android 10 起 IMEI / MEID / 序列号对普通应用一律抛 SecurityException。
     旧实现在 `ov.apply()` 处让异常直接穿透，于是"App 尝试读取 IMEI、被系统
     拒绝"在报告里表现成**一条事件都没有**。要真机复现这一点，得正好有一个
     应用调用了会抛异常的 API，且调用栈里带业务帧 —— 而栈里没有业务帧的调用
     本来就会被 `stackExcluded()` 正确剔除（这是防误报的核心规则）。
     两件事混在一起，真机现象无法判别是"没调用"还是"被过滤"。
     所以这里用假 Java 环境直接调用被替换后的 `implementation`，
     把"抛异常 → 记一条 denied 事件 → 异常原样再抛出"钉死。

  ② **正常取值仍然是 A 级**（改了 catch 分支不能顺手把正常路径改坏）。

跑法：python tools/_hook_js_tests.py
没有 node 时不做失败判定（部署机上可能没装），会明确写"跳过"。
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "piiscan" / "hooks" / "collector.js"

_PRELUDE = r"""
var SENT = [];
function send(o) { SENT.push(o); }
var FAKE_STACK = [
  'java.lang.Throwable',
  '\tat android.telephony.TelephonyManager.getDeviceId(Native Method)',
  '\tat com.example.app.MainActivity.onCreate(MainActivity.java:42)'
].join('\n');

function mkMethod(impl) {
  var f = function () { return impl.apply(null, arguments); };
  f.overloads = [f];
  return f;
}
var TARGET = {
  boom: mkMethod(function () {
    var e = new Error('java.lang.SecurityException: getDeviceId');
    e.name = 'SecurityException';
    throw e;
  }),
  ok: mkMethod(function () { return '9893a5aebfd56f37'; })
};
var Java = {
  available: true,
  perform: function () {},
  array: function (t, a) { return a; },
  use: function (name) {
    if (name === 'com.test.App') return TARGET;
    if (name === 'android.util.Log') return { getStackTraceString: function () { return FAKE_STACK; } };
    if (name === 'java.lang.Throwable') return { $new: function () { return {}; } };
    if (name === 'java.lang.Thread') return { currentThread: function () { return { getName: function () { return 'main'; } }; } };
    return {};
  }
};
var rpc = { exports: {} };
"""

_CASES = r"""
var RESULT = [];

// ---- ① 抛异常：必须记一条 denied 事件，且异常原样抛出 ----
install('t_boom', 'com.test.App', 'boom', 'device_id',
        { signal: 'S001', group: '硬件标识', pi: '设备标识', evidence: 'A' });
var threw = false;
SENT.length = 0;
try { TARGET.boom.implementation.call(null, 0); } catch (e) { threw = true; }
var ev = SENT[0] || {};
RESULT.push({
  case: 'throw',
  sent: SENT.length,
  threw: threw,
  denied: ev.denied,
  evidence: ev.evidence,
  result: String(ev.result || ''),
  signal: ev.signal
});

// ---- ② 正常返回：一条事件、非 denied、A 级 ----
install('t_ok', 'com.test.App', 'ok', 'device_id',
        { signal: 'S001', group: '硬件标识', pi: '设备标识', evidence: 'A' });
SENT.length = 0;
var ret = TARGET.ok.implementation.call(null);
var ev2 = SENT[0] || {};
RESULT.push({
  case: 'ok',
  sent: SENT.length,
  denied: !!ev2.denied,
  evidence: ev2.evidence,
  result: String(ev2.result || ''),
  ret: ret
});

// ---- ③ 栈里全是框架帧：不得上报（否则框架自己的调用会被算成 App 行为）----
FAKE_STACK = ['java.lang.Throwable',
              '\tat android.telephony.TelephonyManager.getDeviceId(Native Method)',
              '\tat android.app.Instrumentation.callApplicationOnCreate(Instrumentation.java:1154)'
             ].join('\n');
SENT.length = 0;
TARGET.ok.implementation.call(null);
RESULT.push({ case: 'framework_stack', sent: SENT.length });

console.log('###RESULT###' + JSON.stringify(RESULT));
"""


def _node() -> str:
    return shutil.which("node") or shutil.which("node.exe") or ""


def _run_node(src: str) -> list:
    node = _node()
    if not node:
        return []
    with tempfile.TemporaryDirectory(prefix="hookjs_") as td:
        f = Path(td) / "harness.js"
        f.write_text(src, encoding="utf-8")
        p = subprocess.run([node, str(f)], capture_output=True, timeout=120)
        out = (p.stdout or b"").decode("utf-8", "replace")
        err = (p.stderr or b"").decode("utf-8", "replace")
        for ln in out.splitlines():
            if ln.startswith("###RESULT###"):
                return json.loads(ln[len("###RESULT###"):])
        return [{"case": "__error__", "stdout": out[-800:], "stderr": err[-800:]}]


def run(check) -> None:
    src = (HOOK.read_text(encoding="utf-8")
           .replace("__MAX_EVENTS__", "50")
           .replace("__GLOBAL_CAP__", "200"))
    results = _run_node(_PRELUDE + "\n" + src + "\n" + _CASES)

    if not results:
        # 没有 node：只做源码级兜底，明确标注"未执行"
        check("hook 脚本：调用被拒时有 catch 分支记录（Node 不可用，仅源码核对）",
              "调用被拒绝" in src and "throw err;" in src,
              "未找到 catch 分支")
        return

    by = {r.get("case"): r for r in results}
    if "__error__" in by:
        check("hook 脚本自测可执行（Node 跑通）", False, by["__error__"])
        return

    t = by.get("throw") or {}
    check("hook：被系统拒绝的调用仍记一条事件", t.get("sent") == 1, t)
    check("hook：该事件标记 denied=true", t.get("denied") is True, t)
    check("hook：被拒事件降为 B 级（没取到值不能单独支撑结论）",
          t.get("evidence") == "B", t.get("evidence"))
    check("hook：被拒结果写成「调用被拒绝：…」而不是当成取值",
          str(t.get("result", "")).startswith("调用被拒绝"), t.get("result"))
    check("hook：异常原样抛给应用（行为与不注入时一致）", t.get("threw") is True, t)

    o = by.get("ok") or {}
    check("hook：正常取值仍记一条事件", o.get("sent") == 1, o)
    check("hook：正常取值不标 denied", o.get("denied") is False, o)
    check("hook：正常取有效值仍为 A 级", o.get("evidence") == "A", o.get("evidence"))
    check("hook：正常路径返回值不被改写", o.get("ret") == "9893a5aebfd56f37", o.get("ret"))

    f = by.get("framework_stack") or {}
    check("hook：栈里全是框架帧时不上报（防框架自调用误报）",
          f.get("sent") == 0, f)


if __name__ == "__main__":
    OK = []
    BAD = []

    def _check(name, cond, got=""):
        (OK if cond else BAD).append(name if cond else "%s（%r）" % (name, got))

    run(_check)
    print("通过 %d 项，失败 %d 项" % (len(OK), len(BAD)))
    for b in BAD:
        print("  ·", b)
    sys.exit(1 if BAD else 0)
