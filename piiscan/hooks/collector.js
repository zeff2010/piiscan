'use strict';
/*
 * App 个人信息保护合规检测 —— 采集脚本
 *
 * 职责：
 *   A. hook 敏感 API，把每一次「读取/外发个人信息」的行为记为一条事件，
 *      附时间戳、参数、返回值、调用栈、线程、所在界面，以及是否发生在同意之前；
 *   B. 捕获「隐私政策」的真实来源 —— 首启弹窗里的链接、WebView 加载的地址、
 *      以及 WebView 渲染后的正文（JS 渲染的页面也能拿到）；
 *   C. 记录「数据去向」—— 网络上报 / 本地持久化 / 日志输出，用于误报漏斗第 4 级。
 *
 * 事件分级（对应 analysis/signal_map.yaml 的 evidence_levels）：
 *   A 级：取到有效值 —— 可独立支撑结论
 *   B 级：命中但值需另行确认
 *   C 级：纯行为（如申请权限），需结合界面上下文
 *   D 级：噪声（日志、Socket 创建），仅作线索
 *
 * 与 Python 侧约定：
 *   send({type:'event'|'hooks'|'consent'|'policy'|'webview'|'activity', ...})
 *   rpc.exports: summary / setConsent / getPolicy / dumpWebView / markUiAction
 */

/* 这两个占位符由 Python 侧（collector.py）在加载前替换成数字。
   ★ 兜底：如果谁直接加载本文件而没做替换，原先会抛
   "ReferenceError: '__MAX_EVENTS__' is not defined" —— 而这发生在**脚本顶层**，
   会终止整个脚本的后续执行（文件末尾的 rpc.exports 永远设不上），
   表现却是"hook 部分装上了、某些功能静默失效"，极难排查（简小知实测踩到）。
   所以这里用 typeof 兜一层：未替换时退回默认值，脚本照样能跑完。
   注意 typeof 对未声明的标识符是安全的（不会抛错）。 */
var MAX_EVENTS = (typeof __MAX_EVENTS__ === 'number') ? __MAX_EVENTS__ : 200;
var GLOBAL_CAP = (typeof __GLOBAL_CAP__ === 'number') ? __GLOBAL_CAP__ : 2000;
/* 单个信号最多占用全局额度的 1/3。见 shouldReport 里的说明：
   一个持续轮询的 API（wifi 状态、网络信息）能把总额度吃光，
   让后面真正有价值的采集全被丢弃，而报告里只看到"事件很多"。 */
var PER_SIGNAL_CAP = Math.max(30, Math.floor(GLOBAL_CAP / 3));

var CONSENT_KEYWORDS = ['同意并继续', '同意并接受', '同意并登录', '同意', '接受',
                        '允许', '我知道了', '知道了', '好的', '确定'];

// 「同意」是「不同意」的子串。不做否定式排除的话，「不同意」会被记成"已同意"，
// 于是同意之后本来正常的行为全被算进"同意前收集" —— 这是最危险的误报方向。
var CONSENT_REJECT = ['不同意', '不接受', '不认可', '拒绝', '暂不', '以后再说',
                      '残忍', '放弃', '退出', '取消', '关闭'];

var state = {
  consent: false,
  consentAt: null,
  consentSource: '',
  startTs: Date.now(),
  counts: {},
  reported: {},
  sigReported: {},
  sigSkipped: {},
  total: 0,
  curActivity: '',
  curActivityAt: 0,
  uiAction: '',
  screens: []
};

/* ================================================================
 * 工具
 * ================================================================ */

function truncate(s, n) {
  s = String(s);
  n = n || 80;
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function sanitize(v) {
  try {
    if (v === null || v === undefined) return 'null';
    if (typeof v === 'string') return truncate(v);
    if (typeof v === 'number' || typeof v === 'boolean') return String(v);
    if (v.$className) {
      try { return truncate(v.toString()); } catch (e) { return '<' + v.$className + '>'; }
    }
    return truncate(String(v));
  } catch (e) {
    return '<unreadable>';
  }
}

function formatArgs(args) {
  var out = [];
  for (var i = 0; i < args.length; i++) out.push(sanitize(args[i]));
  return truncate(out.join(', '), 160);
}

function javaStack(depth) {
  try {
    var Log = Java.use('android.util.Log');
    var Throwable = Java.use('java.lang.Throwable');
    var s = Log.getStackTraceString(Throwable.$new());
    var lines = s.split('\n');
    var out = [];
    for (var i = 0; i < lines.length; i++) {
      var ln = lines[i].replace(/^\s+/, '');
      if (ln.indexOf('at ') !== 0) continue;
      out.push(truncate(ln.slice(3), 160));
      if (out.length >= (depth || 14)) break;
    }
    return out;
  } catch (e) {
    return ['<调用栈获取失败: ' + e + '>'];
  }
}

function currentThread() {
  try {
    return Java.use('java.lang.Thread').currentThread().getName();
  } catch (e) {
    return '?';
  }
}

/* 堆栈级误报排除 —— 借鉴沙箱 action.json 的 exclude / excludeStack 机制。
 * 逻辑：向下找「第一条业务方帧」。
 *   · 全是框架帧  → 框架/WebView 自己触发的读取，不是 App 主动收集 → 剔除
 *   · 第一条业务帧本身是框架代读方法（getPackageInfo 等）→ 剔除
 * 被剔除的命中仍计入 counts，报告里会说明「过滤掉多少条」。 */
var FRAMEWORK_RE = /^(android\.|androidx?\.|com\.android\.|java\.|javax\.|kotlin\.|kotlinx\.|org\.chromium|com\.android\.webkit|dalvik\.|libcore\.|sun\.|org\.json|com\.google\.android\.gms\.common)/;

/* 框架自己代读、不代表 App 有收集意图的方法名 */
var STACK_METHOD_EXCLUDE = [
  'queryIntentActivities', 'getInstallerPackageName', 'getPackageInfo',
  'getApplicationInfo', 'checkPermission', 'getCallingPackage',
  'getPackagesForUid', 'getSharedPreferences', 'createPackageContext',
];

function stackExcluded(stack) {
  if (!stack || !stack.length) return false;
  var firstBiz = -1, firstBizFrame = '';
  for (var i = 0; i < stack.length; i++) {
    var cls = stack[i].split('(')[0];
    if (!FRAMEWORK_RE.test(cls)) { firstBiz = i; firstBizFrame = cls; break; }
  }
  if (firstBiz < 0) return true;                       // 全是框架帧
  for (var j = 0; j < STACK_METHOD_EXCLUDE.length; j++) {
    if (firstBizFrame.indexOf('.' + STACK_METHOD_EXCLUDE[j]) >= 0) return true;
  }
  return false;
}

function shouldReport(id, signal) {
  state.counts[id] = (state.counts[id] || 0) + 1;
  if (state.total >= GLOBAL_CAP) return false;
  var r = state.reported[id] || 0;
  if (r >= MAX_EVENTS) return false;
  /* ---- 单信号限流（2026-11-05，万步健康实测）----
   * 该应用在后台**持续轮询 wifi 状态**：一轮采集 41656 条事件里有 24114 条是
   * `WifiManager.getWifiState`（占 58%）。事件总额 40000 条被它一个人吃光，
   * 之后真正有价值的事件（读通讯录、取设备标识、定位）**一条都进不来** ——
   * 报告上写着"事件 41656 条"，看起来很多，实际上后半段全是同一条轮的重复。
   * 这不是"应用调用频繁"的证据（频率另有 `state.counts` 记全量），
   * 而是**预算分配问题**。所以给每个信号设上限：单个信号最多占 1/3 总额，
   * 超出部分只记数不上报，并在 summary 里交代被限流多少条。
   */
  var sig = signal || id;
  var used = state.sigReported[sig] || 0;
  if (used >= PER_SIGNAL_CAP) {
    state.sigSkipped[sig] = (state.sigSkipped[sig] || 0) + 1;
    return false;
  }
  state.sigReported[sig] = used + 1;
  state.reported[id] = r + 1;
  state.total++;
  return true;
}

/**
 * 上报一条行为事件。
 * opts: { signal, group, pi, evidence, sink, ok(值是否有效), filter }
 */
function emit(hookId, category, api, args, result, opts) {
  opts = opts || {};
  if (!hookId) return;
  if (opts.filter) { return; }
  var stack = javaStack(opts.depth || 14);
  if (opts.stackGuard !== false && stackExcluded(stack)) {
    // 命中但被堆栈排除规则剔除 —— 计入 counts 便于报告里说明过滤量
    state.counts[hookId] = (state.counts[hookId] || 0) + 1;
    return;
  }
  if (!shouldReport(hookId, opts.signal || '')) return;
  send({
    type: 'event',
    hookId: hookId,
    signal: opts.signal || '',
    category: category,
    api: api,
    args: args || '',
    result: result || '',
    thread: currentThread(),
    ts: Date.now(),
    elapsedMs: Date.now() - state.startTs,
    beforeConsent: !state.consent,
    screenshotIdx: state.screens.length,
    activity: state.curActivity,
    uiAction: state.uiAction,
    group: opts.group || '',
    pi: opts.pi || '',
    evidence: opts.evidence || 'B',
    sink: opts.sink || '',
    /* 调用被系统拒绝（SecurityException 等）：调用事实确凿、但没取到值。
       单独标出来，报告才能区分「读了但被拒」与「根本没读」（2026-11-10）。 */
    denied: !!opts.denied,
    stack: stack
  });
}

/** 值有效性：null / 空 / 全零占位 / "unknown" 一律不算「收集到」 */
function validValue(v) {
  if (v === null || v === undefined) return false;
  var s = String(v).trim();
  if (!s) return false;
  if (s === 'null' || s === 'undefined' || s === 'unknown' || s === '0') return false;
  if (/^0{2}(:0{2}){5}$/.test(s)) return false;          // 02:00:00:00:00:00
  if (/^0{8}-?0{4}-?0{4}-?0{4}-?0{12}$/.test(s)) return false;
  if (/^0+$/.test(s)) return false;
  return true;
}

/* ================================================================
 * hook 安装器
 * ================================================================ */

var installed = [];
var failed = [];

function shortName(cls) {
  var parts = cls.split('.');
  return parts[parts.length - 1];
}

/**
 * 安装一个 hook。自动覆盖该方法的全部重载（只 hook 一个重载会漏事件）。
 * opts.onReturn(args, ret) 可自定义上报内容。
 */
function install(id, className, methodName, category, opts) {
  opts = opts || {};
  try {
    var clazz = Java.use(className);
    var target = clazz[methodName];
    if (!target) { failed.push(id + ' — 方法不存在'); return; }
    var overloads = target.overloads;
    if (!overloads || overloads.length === 0) { failed.push(id + ' — 无可用重载'); return; }
    var apiName = shortName(className) + '.' + methodName;
    for (var i = 0; i < overloads.length; i++) {
      (function (ov) {
        ov.implementation = function () {
          var args = Array.prototype.slice.call(arguments);
          var ret;
          try {
            ret = ov.apply(this, args);
          } catch (err) {
            /* ★ 抛异常也是一次真实调用，必须记下来（2026-11-10 Android 10 实测）。
             *
             * Android 10（API 29）起，IMEI / MEID / 序列号这类"不可重置标识符"
             * 对普通应用**一律抛 SecurityException**。旧实现在这里让异常直接穿透，
             * 于是「App 尝试读取 IMEI、被系统拒绝」在报告里表现成**一条事件都没有** ——
             * 结论会写成"未见读取设备标识"，而它明明读了。
             * 「尝试但被拒」和「根本没读」是两件事，前者恰恰是设备标识类违规里
             * 最常见的一种（应用在低版本上一直这么干）。
             *
             * 只记 B 级：没有取到值，不能单独支撑"已收集"。
             * 值字段写异常类型，报告与人工复核都能一眼看出"是被拒不是没调"。
             * 异常**原样再抛出**，应用看到的行为与不注入时完全一致。 */
            try {
              var ev2 = 'B';
              emit(id, category, apiName, formatArgs(args),
                   sanitize('调用被拒绝：' + err),
                   { signal: opts.signal, group: opts.group, pi: opts.pi,
                     evidence: ev2, sink: opts.sink, depth: opts.depth,
                     denied: true });
            } catch (e2) { /* 采集失败不影响 App 运行 */ }
            throw err;
          }
          try {
            if (opts.onReturn) {
              opts.onReturn(args, ret, id, category, apiName);
            } else {
              /* 有效性规则：声明 A 级但取到的值无效（null/占位值）→ 降为 B 级。
                 对应误报漏斗第 2 级「取到有效值」。 */
              var ev = opts.evidence || 'B';
              if (ev === 'A' && !validValue(ret)) ev = 'B';
              emit(id, category, apiName, formatArgs(args), sanitize(ret), {
                signal: opts.signal, group: opts.group, pi: opts.pi,
                evidence: ev, sink: opts.sink, depth: opts.depth
              });
            }
          } catch (e) { /* 采集失败不影响 App 运行 */ }
          return ret;
        };
      })(overloads[i]);
    }
    installed.push(id + ' — ' + apiName);
  } catch (e) {
    failed.push(id + ' — ' + e);
  }
}

/* ================================================================
 * 政策捕获
 * ================================================================ */

var policy = {
  urls: [],          // 捕获到的候选政策链接（带来源）
  webviews: [],      // WebView 实例
  texts: {},         // url -> 渲染后正文
  entryTexts: [],    // 首启弹窗里出现的政策入口文字
  entryClicked: '',
  activityTexts: []
};

function noteUrl(url, from) {
  try {
    url = String(url || '');
    if (!url) return;
    var low = url.toLowerCase();
    if (low.indexOf('http') !== 0 && low.indexOf('file:') !== 0 && low.indexOf('javascript:') !== 0) return;
    if (low.indexOf('javascript:') === 0) return;
    for (var i = 0; i < policy.urls.length; i++) {
      if (policy.urls[i].url === url) return;
    }
    var isPolicy = /privacy|policy|agreement|statement|protocol|terms|隐私|协议|polic|yszc/i.test(url);
    policy.urls.push({
      url: url, from: from, ts: Date.now(),
      policyLikely: isPolicy,
      elapsedMs: Date.now() - state.startTs
    });
    send({ type: 'policy', kind: 'url', url: url, from: from, policyLikely: isPolicy,
           ts: Date.now(), elapsedMs: Date.now() - state.startTs });
  } catch (e) {}
}

/* WebView 实例只做计数 —— **绝不缓存实例对象**。
   ★ 真机教训（简小知，2026-10-16 定位）：把 WebView 对象存在数组里留到以后用，
   一旦它对应的页面关掉（政策页返回、H5 finish），再去调它的方法会让 ART
   直接空指针崩溃：
     signal 11 (SIGSEGV) Cause: null pointer dereference, fault addr 0x68
     #00 art::mirror::Class::FindVirtualMethodForVirtualOrInterface
     #03 art::JNI<false>::CallObjectMethod
     后面一路是 /memfd:frida-agent-64.so 的帧
   App 进程当场消失，日志里**没有** Java 崩溃（不是 FATAL/AndroidRuntime），
   只有 tombstone 里的 SIGSEGV。而且这种 native 崩溃 JS 的 try/catch 拦不住。
   现象极具误导性：注入后一点开政策页就崩（t+1s 打开、t+3s 页面前台变 null、
   t+4s 退回弹窗、Frida 报 "script has been destroyed"），
   而**空脚本对照实验**下政策页能稳定存活 10 秒以上 —— 说明不是 Frida 被检测，
   就是这条"缓存实例 + 事后调用"的链路干的。
   所以：要读正文时现场 Java.choose 重新枚举，retain 到主线程、用完立刻 release。 */
var _webviewSeen = 0;
function registerWebView(wv) {
  try { _webviewSeen += 1; } catch (e) {}
}

var _cbSeq = 0;
var _cbClassByUrl = {};
var _lastCurrentUrls = [];   // currentUrls() 的异步结果缓存

/* 取渲染后正文的 JS 片段（在 WebView 里跑）。
   ★ 只取 document.body.innerText 是不够的：真机实测（简小知）政策页是 H5/SPA，
   body.innerText 只有标题那十几字，正文要么在 iframe 里、要么只在 textContent 里
   （innerText 受 CSS 可见性影响，未展开的折叠区、transition 中的元素都可能拿不到）。
   所以：body.innerText → body.textContent → 所有 iframe 的同样两样，逐个收集后拼接。
   textContent 会把隐藏文字也带出来 —— 对"有没有写到规则"这类判定反而更有利。 */
var WV_INNER_TEXT_JS =
  '(function(){try{'
  + 'var p=[];'
  + 'var g=function(d){try{if(!d||!d.body)return;'
  + 'var a=d.body.innerText||"";var b=d.body.textContent||"";'
  + 'var t=(a.length>=b.length)?a:b;if(t)p.push(t);}catch(e){}};'
  + 'g(document);'
  + 'var f=document.querySelectorAll("iframe,frame");'
  + 'for(var i=0;i<f.length;i++){try{g(f[i].contentDocument);}catch(e){}}'
  + 'return p.join("\\n");'
  + '}catch(e){return "";}})()';

/* 国内 App 未必用系统 WebView：腾讯 X5 / UC 内核的类名都不一样。
   挨个试，不存在的类会抛，忽略即可。 */
var WEBVIEW_CLASSES = ['android.webkit.WebView',
                       'com.tencent.smtt.sdk.WebView',
                       'com.uc.webview.export.WebView'];

/* 把 HTML 源码转成纯文本（2026-11-09 Q船 4.4.2）。
   为什么要在脚本侧就转：
     · 有的 App 用 loadDataWithBaseURL 把**HTML 源码**塞给 WebView，我们 hook 到的
       是 args[1]（源码）。原样当正文记下来，报告里的"政策正文"就是一堆 <div>，
       读起来像代码，关键词与声明抽取也全被标签污染。
     · innerText 走的是渲染后文字，没有这个问题；只有 loadData 这条路需要转。
   只求"读得懂、能检索"，不追求版式。 */
function htmlToText(h) {
  var s = String(h || '');
  if (!s) return '';
  s = s.replace(/<script[\s\S]*?<\/script>/gi, ' ')
       .replace(/<style[\s\S]*?<\/style>/gi, ' ')
       .replace(/<head[\s\S]*?<\/head>/gi, ' ')
       .replace(/<!--[\s\S]*?-->/g, ' ')
       .replace(/<br\s*\/?>/gi, '\n')
       .replace(/<\/(p|div|li|tr|h[1-6]|section|article|ul|ol|table)\s*>/gi, '\n')
       .replace(/<[^>]{1,400}>/g, '')
       .replace(/&nbsp;/gi, ' ')
       .replace(/&emsp;|&ensp;/gi, ' ')
       .replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
       .replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'")
       .replace(/&amp;/gi, '&')
       .replace(/&#(\d{2,5});/g, function (m, d) { try { return String.fromCharCode(parseInt(d, 10)); } catch (e) { return ' '; } })
       .replace(/[ \t]+/g, ' ')
       .replace(/\n[ \t]+/g, '\n')
       .replace(/\n{3,}/g, '\n\n');
  return s.trim();
}

/* 为某个 URL 拿（必要时注册）一个 ValueCallback 实现类。
   同一个 URL 复用同一个类，避免反复 registerClass 撑爆方法数。
   url 被闭包捕获，回调里据此归类正文。 */
function _cbFor(url) {
  if (!_cbClassByUrl[url]) {
    var CB = Java.use('android.webkit.ValueCallback');
    _cbSeq += 1;
    _cbClassByUrl[url] = Java.registerClass({
      name: 'com.piiscan.PolicyCb' + _cbSeq,
      implements: [CB],
      methods: {
        onReceiveValue: function (v) {
          try {
            var s = (v === null || v === undefined) ? '' : String(v);
            s = s.replace(/\\n/g, '\n');
            if (s && (!policy.texts[url] || s.length > policy.texts[url].length)) {
              policy.texts[url] = s;
              send({ type: 'policy', kind: 'text', url: url, len: s.length,
                     text: truncate(s, 200000), ts: Date.now() });
            }
          } catch (e) {}
        }
      }
    });
  }
  return _cbClassByUrl[url].$new();
}

/* 在主线程里对一个 WebView 做一件事，做完无条件释放。
   retain 是必须的：scheduleOnMainThread 是排期，等它执行时
   Java.choose 的回调早已返回，对象不 retain 就可能已经失效。 */
function _onMainWithWebView(wv, fn) {
  try {
    Java.retain(wv);
  } catch (e) {
    return;
  }
  Java.scheduleOnMainThread(function () {
    try {
      fn(wv);
    } catch (e) {
      try { send({ type: 'debug', msg: 'WebView 操作失败：' + e }); } catch (e2) {}
    } finally {
      try { Java.release(wv); } catch (e3) {}
    }
  });
}

/* 枚举所有存活的 WebView，逐个交给 fn（都在主线程里执行） */
function _eachWebView(fn) {
  Java.perform(function () {
    WEBVIEW_CLASSES.forEach(function (cn) {
      try {
        Java.choose(cn, {
          onMatch: function (wv) { _onMainWithWebView(wv, fn); },
          onComplete: function () {}
        });
      } catch (e) { /* 该内核不存在，正常 */ }
    });
  });
}

var _lastReadCount = 0;

/**
 * 把当前所有 WebView 的渲染后 innerText 读回 policy.texts。
 *
 * 三层约束叠在一起，缺一条就静默失败或直接崩（都是真机踩出来的）：
 *  ① Java 调用必须在 Java.perform 里 —— setTimeout / RPC 回调跑在 Frida 的
 *     JS 线程上，裸调 Java 会让 ART 空指针崩溃（native，JS 拦不住）。
 *  ② WebView 的方法只能在主线程调 —— 否则抛
 *     "A WebView method was called on thread 'Thread-10'"，一个字都读不到。
 *  ③ Java.choose 回调里的对象离开回调不保证有效 —— 所以 retain + 用完 release。
 *
 * 正文是异步回调写入的，调用方稍后读 getPolicy() 才是准的；
 * 返回值只是"本轮排期的读取数"。
 */
function readAllWebViews() {
  _lastReadCount = 0;
  _eachWebView(function (wv) {
    var url = String(wv.getUrl() || '');
    if (!url || url.indexOf('about:blank') === 0) return;
    wv.evaluateJavascript(WV_INNER_TEXT_JS, _cbFor(url));
    _lastReadCount += 1;
  });
  return _lastReadCount;
}

/* ================================================================
 * 安装
 * ================================================================ */

Java.perform(function () {

  /* ---------------- 0. 界面上下文（用于「无关场景」归因） ---------------- */
  var ACT_HOOKS = [['onCreate', 'onResume', 'onNewIntent']];
  try {
    var Activity = Java.use('android.app.Activity');
    ['onCreate', 'onResume', 'onNewIntent'].forEach(function (m) {
      if (!Activity[m]) return;
      Activity[m].overloads.forEach(function (ov) {
        ov.implementation = function () {
          try {
            var name = this.getClass().getName();
            state.curActivity = String(name);
            state.curActivityAt = Date.now();
            if (m === 'onResume' || m === 'onCreate') {
              send({ type: 'activity', name: state.curActivity, via: m, ts: Date.now(),
                     elapsedMs: Date.now() - state.startTs });
            }
          } catch (e) {}
          return ov.apply(this, arguments);
        };
      });
    });
    installed.push('ui_activity — Activity.onCreate/onResume/onNewIntent（界面归因）');
  } catch (e) {
    failed.push('ui_activity — ' + e);
  }

  /* ---------------- 1. 设备标识符 ---------------- */
  install('dev_tm_getDeviceId', 'android.telephony.TelephonyManager', 'getDeviceId', 'device_id',
          { signal: 'S001', group: '硬件标识', pi: '设备标识', evidence: 'A' });
  install('dev_tm_getImei', 'android.telephony.TelephonyManager', 'getImei', 'device_id',
          { signal: 'S001', group: '硬件标识', pi: '设备标识', evidence: 'A' });
  install('dev_tm_getMeid', 'android.telephony.TelephonyManager', 'getMeid', 'device_id',
          { signal: 'S003', group: '硬件标识', pi: '设备标识', evidence: 'A' });
  install('dev_build_getSerial', 'android.os.Build', 'getSerial', 'device_id',
          { signal: 'S005', group: '硬件标识', pi: '设备标识', evidence: 'A' });

  /* -------- 1b. DRM 设备唯一标识（2026-11-10，Android 10 起的主要替代路径） --------
   * Android 10 对普通应用封掉了 IMEI / MEID / Build.getSerial（一律 SecurityException），
   * 于是 SDK 转向 **Widevine 的 deviceUniqueId**：无需任何权限、每机唯一、
   * 恢复出厂也可能不变 —— 实质就是一个持久设备指纹。
   * 不挂它的话，在这类 App 上"读设备标识"会表现为一条事件都没有。
   * 参数必过滤：getPropertyByteArray 还用于 version / vendor 等，全记会把
   * 每次视频播放都算成读标识（误报）。 */
  try {
    var MDrm = Java.use('android.media.MediaDrm');
    MDrm.getPropertyByteArray.overloads.forEach(function (ov) {
      ov.implementation = function () {
        var args = Array.prototype.slice.call(arguments);
        var ret;
        try {
          ret = ov.apply(this, args);
        } catch (err) {
          try {
            if (String(args[0] || '') === 'deviceUniqueId') {
              emit('dev_drm_id', 'device_id', 'MediaDrm.getPropertyByteArray',
                   'property=deviceUniqueId', sanitize('调用被拒绝：' + err),
                   { signal: 'S097', group: '硬件标识', pi: '设备标识',
                     evidence: 'B', denied: true });
            }
          } catch (e2) {}
          throw err;
        }
        try {
          if (String(args[0] || '') === 'deviceUniqueId') {
            var n = 0;
            try { n = Java.array('byte', ret).length; } catch (e3) { n = 0; }
            /* 字节数组不能当字符串比值：只说"取到 N 字节"，有效性看长度。 */
            emit('dev_drm_id', 'device_id', 'MediaDrm.getPropertyByteArray',
                 'property=deviceUniqueId', 'byte[' + n + ']',
                 { signal: 'S097', group: '硬件标识', pi: '设备标识',
                   evidence: n > 0 ? 'A' : 'B' });
          }
        } catch (e) {}
        return ret;
      };
    });
    installed.push('dev_drm_id — MediaDrm.getPropertyByteArray(deviceUniqueId)');
  } catch (e) { failed.push('dev_drm_id — ' + e); }

  /* OAID / 匿名设备标识 —— 现在的重心，由 SDK 动态发现统一处理（见文末 discoverSdks） */

  /* Settings.Secure / Global —— 必须按 key 精确匹配，是最常见的误报源 */
  try {
    var Secure = Java.use('android.provider.Settings$Secure');
    /* getString 与 getStringForUser 都要挂（2026-11-10 Android 10）。
     * 前者是应用代码最常用的写法，后者是**第三方 SDK 的常用写法**
     * （多用户 API，能拿到"当前用户"下的值）。只挂 getString 时，
     * 同一份 android_id 在走 SDK 的 App 上一条都看不到，
     * 报告却会写"未读取 Android ID" —— 漏报比误报更难被发现。 */
    [['getString', ['android.content.ContentResolver', 'java.lang.String']],
     ['getStringForUser',
      ['android.content.ContentResolver', 'java.lang.String', 'int']]
    ].forEach(function (spec) {
      var mname = spec[0], types = spec[1];
      try {
        var ov = Secure[mname].overload.apply(Secure[mname], types);
        ov.implementation = function () {
          var args = Array.prototype.slice.call(arguments);
          var ret;
          try {
            ret = ov.apply(this, args);
          } catch (err) {
            /* 与 install() 同一口径：被系统拒绝也要留痕（见 install 的注释）。
             * Settings 读取一般不会抛，但个别 ROM / 受限用户下会，留一手。 */
            try {
              var kerr = String(args[1] || '');
              if (kerr.indexOf('android_id') >= 0) {
                emit('dev_android_id', 'device_id', 'Settings.Secure.' + mname,
                     'name=' + kerr, sanitize('调用被拒绝：' + err),
                     { signal: 'S006', group: '硬件标识', pi: '设备标识',
                       evidence: 'B', denied: true });
              }
            } catch (e2) {}
            throw err;
          }
          try {
            var k = String(args[1] || '');
            if (k.indexOf('android_id') >= 0) {
              emit('dev_android_id', 'device_id', 'Settings.Secure.' + mname,
                   'name=' + k, sanitize(ret),
                   { signal: 'S006', group: '硬件标识', pi: '设备标识',
                     evidence: validValue(ret) ? 'A' : 'B' });
            }
          } catch (e) {}
          return ret;
        };
        installed.push('dev_android_id — Settings.Secure.' + mname + '(android_id)');
      } catch (e) {
        failed.push('dev_android_id_' + mname + ' — ' + e);
      }
    });
  } catch (e) { failed.push('dev_android_id — ' + e); }

  try {
    var SysProp = Java.use('android.os.SystemProperties');
    if (SysProp.get) {
      SysProp.get.overloads.forEach(function (ov) {
        ov.implementation = function () {
          var args = Array.prototype.slice.call(arguments);
          var ret = ov.apply(this, args);
          try {
            var k = String(args[0] || '');
            if (/^(ro\.serialno|ro\.boot_id|gsm\.version\.baseband|persist\.sys\.|ro\.product)/.test(k)) {
              emit('dev_sysprop', 'device_id', 'SystemProperties.get', 'key=' + k, sanitize(ret),
                   { signal: 'S055', group: '硬件标识', pi: '系统属性', evidence: 'B' });
            }
          } catch (e) {}
          return ret;
        };
      });
      installed.push('dev_sysprop — SystemProperties.get（按 key 白名单）');
    }
  } catch (e) { failed.push('dev_sysprop — ' + e); }

  /* ---------------- 2. 用户身份标识 ---------------- */
  install('dev_tm_getSubscriberId', 'android.telephony.TelephonyManager', 'getSubscriberId', 'subscriber_id',
          { signal: 'S002', group: '用户信息', pi: 'SIM 标识', evidence: 'A' });
  install('dev_tm_getSimSerialNumber', 'android.telephony.TelephonyManager', 'getSimSerialNumber', 'subscriber_id',
          { signal: 'S004', group: '用户信息', pi: 'SIM 标识', evidence: 'A' });
  install('dev_tm_getLine1Number', 'android.telephony.TelephonyManager', 'getLine1Number', 'subscriber_id',
          { signal: 'S035', group: '用户信息', pi: '手机号', evidence: 'A' });
  install('dev_tm_getSimOperatorName', 'android.telephony.TelephonyManager', 'getSimOperatorName', 'subscriber_id',
          { signal: 'S025', group: '用户信息', pi: '运营商', evidence: 'B' });

  /* ---------------- 3. 位置信息 ---------------- */
  install('loc_getLastKnownLocation', 'android.location.LocationManager', 'getLastKnownLocation', 'location',
          { signal: 'S043', group: '操作手机', pi: '位置', evidence: 'A' });
  install('loc_requestLocationUpdates', 'android.location.LocationManager', 'requestLocationUpdates', 'location',
          { signal: 'S043', group: '操作手机', pi: '位置', evidence: 'C' });
  install('loc_getLatitude', 'android.location.Location', 'getLatitude', 'location',
          { signal: 'S043', group: '操作手机', pi: '位置', evidence: 'B' });
  install('loc_getLongitude', 'android.location.Location', 'getLongitude', 'location',
          { signal: 'S043', group: '操作手机', pi: '位置', evidence: 'B' });

  /* ---------------- 4. 通讯录 / 短信 / 通话 / 媒体（按 URI 精确过滤） ---------------- */
  try {
    var CR = Java.use('android.content.ContentResolver');
    CR.query.overloads.forEach(function (ov) {
      ov.implementation = function () {
        var args = Array.prototype.slice.call(arguments);
        var ret = ov.apply(this, args);
        try {
          var uri = args[0] ? String(args[0].toString()) : '';
          var cat = null, sig = '', pi = '';
          if (/contacts|com\.android\.contacts/i.test(uri)) { cat = 'contacts'; sig = 'S030'; pi = '通讯录'; }
          else if (/\/sms|content:\/\/sms|content:\/\/mms/i.test(uri)) { cat = 'sms'; sig = 'S031'; pi = '短信'; }
          else if (/call_log|calllog/i.test(uri)) { cat = 'call_log'; sig = 'S032'; pi = '通话记录'; }
          else if (/images|video|audio|external\/media/i.test(uri)) { cat = 'media'; sig = 'S033'; pi = '相册'; }
          else if (/calendar/i.test(uri)) { cat = 'calendar'; sig = 'S034'; pi = '日历'; }
          else if (/user_dictionary/i.test(uri)) { cat = 'other'; sig = 'S035'; pi = '用户词典'; }
          if (cat) {
            emit('res_query_' + cat, cat, 'ContentResolver.query',
                 'uri=' + truncate(uri, 120), '<' + (ret ? ret.getClass().getName() : 'null') + '>',
                 { signal: sig, group: '操作手机', pi: pi, evidence: 'A' });
          }
        } catch (e) {}
        return ret;
      };
    });
    installed.push('res_query — ContentResolver.query（按 URI 精确分类）');
  } catch (e) { failed.push('res_query — ' + e); }

  /* -------- 4b. 剪贴板 / 传感器 / WIFI / 运行列表 / 系统设置（2026-10-31 补） --------
   * 这几项在 `reference/sensitive_api_table.md` 里都有、采集侧却一直没 hook。
   * 补它们不是为了"多抓几条"，而是让**静态表与运行期能对上**：
   * 静态分析说用了 ClipboardManager / SensorManager，运行期一条都没有，
   * 报告只能写"未见读取"，而那句"未见"在复核时会被读成"没做过"。
   * 每一个都是独立的 try：加固包常常只让其中一两个类加载失败，
   * 用一个 try 包住整段会让后面的全部装不上。
   */
  try {
    install('dev_clip_read', 'android.content.ClipboardManager', 'getPrimaryClip', 'clipboard',
            { signal: 'S046', group: '操作手机', pi: '剪贴板', evidence: 'A' });
  } catch (e) { failed.push('dev_clip_read — ' + e); }
  try {
    /* hasPrimaryClip / getPrimaryClipDescription 只探测"有没有"，不取内容。
     * 单独记为 B 级：它是"想知道剪贴板里有没有东西"，不等于读到了剪贴板内容。 */
    install('dev_clip_probe', 'android.content.ClipboardManager', 'hasPrimaryClip', 'clipboard',
            { signal: 'S048', group: '操作手机', pi: '剪贴板', evidence: 'B' });
  } catch (e) { failed.push('dev_clip_probe — ' + e); }
  try {
    /* 传感器：getSensorList 只枚举元数据（B 级线索），registerListener 才是真的开始采
     * （C 级：注册成功 ≠ 已产生用户数据，判定层还会再校一道，见 compare.py 的 P13 备注）。 */
    install('dev_sensor_list', 'android.hardware.SensorManager', 'getSensorList', 'sensor',
            { signal: 'S036', group: '操作手机', pi: '传感器', evidence: 'B' });
  } catch (e) { failed.push('dev_sensor_list — ' + e); }
  try {
    install('dev_sensor_reg', 'android.hardware.SystemSensorManager', 'registerListenerImpl',
            'sensor',
            { signal: 'S036', group: '操作手机', pi: '传感器', evidence: 'C' });
  } catch (e) { failed.push('dev_sensor_reg — ' + e); }
  try {
    install('dev_wifi_ssid', 'android.net.wifi.WifiInfo', 'getSSID', 'network',
            { signal: 'S013', group: '操作手机', pi: 'WIFI 名称', evidence: 'A' });
  } catch (e) { failed.push('dev_wifi_ssid — ' + e); }
  try {
    install('dev_wifi_bssid', 'android.net.wifi.WifiInfo', 'getBSSID', 'network',
            { signal: 'S012', group: '操作手机', pi: 'WIFI 接入点', evidence: 'A' });
  } catch (e) { failed.push('dev_wifi_bssid — ' + e); }
  try {
    /* Android 6 以后 getMacAddress 返回 02:00:00:00:00:00，本身拿不到真 MAC；
     * 但"调用了它"仍是 App 想要 MAC 的证据，所以记 B 级（调用事实确凿、取值无效）。 */
    install('dev_wifi_mac', 'android.net.wifi.WifiInfo', 'getMacAddress', 'network',
            { signal: 'S011', group: '硬件标识', pi: 'MAC 地址', evidence: 'B' });
  } catch (e) { failed.push('dev_wifi_mac — ' + e); }
  try {
    install('dev_running_apps', 'android.app.ActivityManager', 'getRunningAppProcesses',
            'app_list', { signal: 'S054', group: '操作手机', pi: '运行中的应用', evidence: 'A' });
  } catch (e) { failed.push('dev_running_apps — ' + e); }
  try {
    /* AudioRecord 是另一条录音通路：MediaRecorder 只能录文件，
     * 语音识别 / 声纹 SDK 走的是 AudioRecord 流式读取。
     * 只 hook MediaRecorder 时，这类 SDK 一条录音行为都采不到。 */
    install('mic_audiorecord', 'android.media.AudioRecord', 'startRecording', 'microphone',
            { signal: 'S065', group: '操作手机', pi: '麦克风', evidence: 'A' });
  } catch (e) { failed.push('mic_audiorecord — ' + e); }
  try {
    /* 发短信：报告里"读取短信"和"发送短信"是两件性质不同的事（后者可能产生费用），
     * 以前只有 ContentResolver.query 覆盖读取，发送完全没有 hook。 */
    install('sms_send', 'android.telephony.SmsManager', 'sendTextMessage', 'sms',
            { signal: 'S033', group: '操作手机', pi: '发送短信', evidence: 'A' });
  } catch (e) { failed.push('sms_send — ' + e); }
  try {
    /* Settings$System / $Global 的 getString 被调得非常频繁（屏幕亮度、字体大小…），
     * 全量上报会把事件上限吃光、把真正的设备号读取挤掉。
     * 所以只在 key 命中敏感词时才记 —— 白名单在闭包里，不上报 key 本身的内容。 */
    var SYS_KEY_RE = /android_id|device_name|bluetooth|serial|imei|meid|mac|ssid|bssid|advertising/i;
    ['System', 'Global'].forEach(function (tab) {
      /* getString 与 getStringForUser 都挂：SDK 走后者（多用户 API）的比例不低，
       * 只挂前者会让"读蓝牙名/序列号"这类行为在 SDK 路径上一条都不出现。 */
      ['getString', 'getStringForUser'].forEach(function (mname) {
        try {
          install('dev_settings_' + tab.toLowerCase() + (mname === 'getStringForUser' ? '_user' : ''),
                  'android.provider.Settings$' + tab, mname, 'device_id', {
                    onReturn: function (args, ret, id, category, apiName) {
                      var k = String(args.length > 1 ? args[1] : '');
                      if (!SYS_KEY_RE.test(k)) return;
                      emit(id, category, apiName, 'key=' + k, sanitize(ret), {
                        signal: 'S074',
                        group: '硬件标识', pi: '系统设置', evidence: 'B'
                      });
                    }
                  });
        } catch (e) { failed.push('dev_settings_' + tab.toLowerCase() + ' — ' + e); }
      });
    });
  } catch (e) { failed.push('dev_settings — ' + e); }

  /* ---------------- 5. 已安装应用列表 ---------------- */
  /* PackageManager / ActivityManager 是抽象类，必须 hook 实现类 */
  install('app_getInstalledPackages', 'android.app.ApplicationPackageManager', 'getInstalledPackages', 'app_list',
          { signal: 'S052', group: '操作手机', pi: '应用列表', evidence: 'A' });
  install('app_getInstalledApplications', 'android.app.ApplicationPackageManager', 'getInstalledApplications', 'app_list',
          { signal: 'S052', group: '操作手机', pi: '应用列表', evidence: 'A' });
  install('app_getPackagesForUid', 'android.app.ApplicationPackageManager', 'getPackagesForUid', 'app_list',
          { signal: 'S052', group: '操作手机', pi: '应用列表', evidence: 'B' });
  install('app_getRunningAppProcesses', 'android.app.ActivityManager', 'getRunningAppProcesses', 'app_list',
          { signal: 'S054', group: '操作手机', pi: '运行中应用', evidence: 'A' });
  install('app_getRunningServices', 'android.app.ActivityManager', 'getRunningServices', 'app_list',
          { signal: 'S054', group: '操作手机', pi: '运行中应用', evidence: 'A' });
  install('app_getRunningTasks', 'android.app.ActivityManager', 'getRunningTasks', 'app_list',
          { signal: 'S054', group: '操作手机', pi: '运行中应用', evidence: 'B' });

  /* ---------------- 6. 网络标识 ---------------- */
  install('net_wifi_getMacAddress', 'android.net.wifi.WifiInfo', 'getMacAddress', 'network',
          { signal: 'S011', group: '网络信息', pi: 'MAC', evidence: 'A' });
  /* WifiManager 是抽象类 -> 实现类 */
  install('net_wifi_getConnectionInfo', 'android.net.wifi.WifiManager', 'getConnectionInfo', 'network',
          { signal: 'S089', group: '网络信息', pi: 'WiFi 信息', evidence: 'B' });
  install('net_wifi_getScanResults', 'android.net.wifi.WifiManager', 'getScanResults', 'network',
          { signal: 'S087', group: '网络信息', pi: '周边 WiFi', evidence: 'A' });
  install('net_ni_getHardwareAddress', 'java.net.NetworkInterface', 'getHardwareAddress', 'network',
          { signal: 'S011', group: '网络信息', pi: 'MAC', evidence: 'A' });
  install('net_tm_getNetworkOperator', 'android.telephony.TelephonyManager', 'getNetworkOperator', 'network',
          { signal: 'S020', group: '网络信息', pi: '运营商网络', evidence: 'B' });

  /* ---------------- 7. 剪贴板 / 账号 / 传感器 / 外部存储 ---------------- */
  install('clip_getPrimaryClip', 'android.content.ClipboardManager', 'getPrimaryClip', 'clipboard',
          { signal: 'S046', group: '操作手机', pi: '剪贴板', evidence: 'B' });
  install('clip_getText', 'android.content.ClipboardManager', 'getText', 'clipboard',
          { signal: 'S046', group: '操作手机', pi: '剪贴板', evidence: 'A' });
  install('acct_getAccounts', 'android.accounts.AccountManager', 'getAccounts', 'account',
          { signal: 'S049', group: '用户信息', pi: '账号列表', evidence: 'A' });
  install('acct_getAccountsByType', 'android.accounts.AccountManager', 'getAccountsByType', 'account',
          { signal: 'S049', group: '用户信息', pi: '账号列表', evidence: 'A' });
  /* SensorManager 是抽象类 -> 实现类
   * ★ signal 必须与 signal_map.yaml 里的「读取传感器」一致（S036 → P13 传感器信息）。
   *   这里曾写成 S060（写SDCard → P12 存储文件），于是所有传感器监听都被算成
   *   「收集了存储文件」：免费手机投屏神器那轮，"实际收集了存储文件（一般个人信息）"
   *   这条认定项下面挂的栈全是 SystemSensorManager.registerListener，
   *   描述与证据对不上，复核员第一眼就会怀疑整份报告。
   *   pi 字段只在 signal 匹配不到时兜底，不能拿它当分类依据。 */
  install('sensor_registerListener', 'android.hardware.SystemSensorManager', 'registerListener', 'sensor',
          { signal: 'S036', group: '模组信息', pi: '传感器', evidence: 'C' });
  install('storage_getExternalStorageDirectory', 'android.os.Environment', 'getExternalStorageDirectory', 'storage',
          { signal: 'S061', group: '操作手机', pi: '外部存储', evidence: 'B' });
  install('storage_getExternalStoragePublicDirectory', 'android.os.Environment', 'getExternalStoragePublicDirectory', 'storage',
          { signal: 'S061', group: '操作手机', pi: '外部存储', evidence: 'B' });

  /* ---------------- 8. 相机 / 麦克风 ---------------- */
  install('cam_open', 'android.hardware.Camera', 'open', 'camera',
          { signal: 'S066', group: '操作手机', pi: '相机', evidence: 'C' });
  try {
    var MR = Java.use('android.media.MediaRecorder');
    ['start', 'setAudioSource'].forEach(function (m) {
      if (!MR[m]) return;
      MR[m].overloads.forEach(function (ov) {
        ov.implementation = function () {
          var args = Array.prototype.slice.call(arguments);
          var ret = ov.apply(this, args);
          try {
            emit('mic_mediarecorder_' + m, 'microphone', 'MediaRecorder.' + m, formatArgs(args),
                 sanitize(ret), { signal: 'S081', group: '操作手机', pi: '麦克风', evidence: 'C' });
          } catch (e) {}
          return ret;
        };
      });
    });
    installed.push('mic_mediarecorder — MediaRecorder.start/setAudioSource');
  } catch (e) { failed.push('mic_mediarecorder — ' + e); }
  install('mic_audiorecord_init', 'android.media.AudioRecord', '$init', 'microphone',
          { signal: 'S065', group: '操作手机', pi: '麦克风', evidence: 'C' });

  /* ---------------- 9. 权限申请（用于「提前索要非必要权限」归因） ---------------- */
  try {
    var PM = Java.use('android.content.pm.PackageManager');
    PM.checkPermission.overloads.forEach(function (ov) {
      ov.implementation = function () {
        var args = Array.prototype.slice.call(arguments);
        var ret = ov.apply(this, args);
        try {
          emit('perm_checkPermission', 'permission', 'PackageManager.checkPermission',
               formatArgs(args), sanitize(ret),
               { signal: 'S069', group: '权限', pi: '权限检查', evidence: 'C', stackGuard: false });
        } catch (e) {}
        return ret;
      };
    });
    installed.push('perm_checkPermission — PackageManager.checkPermission');
  } catch (e) { failed.push('perm_checkPermission — ' + e); }

  ['android.app.Activity', 'androidx.core.app.ActivityCompat',
   'android.support.v4.app.ActivityCompat'].forEach(function (cn) {
    try {
      var C = Java.use(cn);
      if (!C.requestPermissions) return;
      C.requestPermissions.overloads.forEach(function (ov) {
        ov.implementation = function () {
          var args = Array.prototype.slice.call(arguments);
          var ret = ov.apply(this, args);
          try {
            var perms = '';
            for (var i = 0; i < args.length; i++) {
              var a = args[i];
              if (a && a.$className && a.$className.indexOf('[') >= 0) {
                try {
                  var n = a.length;
                  var arr = [];
                  for (var j = 0; j < n; j++) arr.push(String(a[j]));
                  perms = arr.join('|');
                } catch (e2) {}
              }
            }
            emit('perm_request', 'permission', shortName(cn) + '.requestPermissions',
                 perms || formatArgs(args), sanitize(ret),
                 { signal: 'S069', group: '权限', pi: '权限申请', evidence: 'C', stackGuard: false });
          } catch (e) {}
          return ret;
        };
      });
      installed.push('perm_request_' + shortName(cn) + ' — requestPermissions');
    } catch (e) { /* 类不存在属正常（不同 support 库版本） */ }
  });

  /* ---------------- 10. 数据去向：网络上报（漏斗第 4 级） ---------------- */
  var SINK_NET = { group: '网络信息', pi: '外发数据', sink: 'K1', evidence: 'C' };

  /* ★ URL.openConnection / openStream 必须按协议过滤（简小知真机，2026-10-16）。
     这两个方法不只服务 HTTP：`classpath:` / `jar:file:` 协议的 URL 也走它们 ——
     那是框架在打开 APK 自带的打包资源。日志里的表现是
         URL.openStream → libcore.io.ClassPathURLStreamHandler$ClassPathURLConnection
     把它当"数据外发"就是纯误报（本次检测吃到 2 条，JDK 的 ClassPathURLStreamHandler
     从来不会联网）。只放行 http / https。 */
  function _urlScheme(u) {
    try { return String(u.getProtocol() || '').toLowerCase(); } catch (e) {}
    try {
      var s = String(u).toLowerCase();
      var i = s.indexOf(':');
      return i > 0 ? s.substring(0, i) : '';
    } catch (e2) {}
    return '';
  }
  ['openConnection', 'openStream'].forEach(function (m) {
    try {
      var U = Java.use('java.net.URL');
      if (!U[m]) { failed.push('sink_url_' + m + ' — 方法不存在'); return; }
      U[m].overloads.forEach(function (ov) {
        ov.implementation = function () {
          var ret = ov.apply(this, arguments);
          try {
            var sch = _urlScheme(this);
            if (sch === 'http' || sch === 'https') {
              emit('sink_url_' + m, 'network_sink', 'java.net.URL.' + m,
                   'url=' + truncate(String(this), 130), sanitize(ret),
                   { signal: 'S090', group: '网络信息', pi: '外发数据',
                     sink: 'K1', evidence: 'C', depth: 10 });
            }
            /* 非 http(s)：classpath/jar/file 等本地协议，不算外发，直接丢弃 */
          } catch (e) {}
          return ret;
        };
      });
      installed.push('sink_url_' + m + ' — java.net.URL.' + m);
    } catch (e) { failed.push('sink_url_' + m + ' — ' + e); }
  });
  try {
    var HUC = Java.use('java.net.HttpURLConnection');
    ['connect', 'getInputStream', 'getOutputStream', 'getResponseCode'].forEach(function (m) {
      if (!HUC[m]) return;
      HUC[m].overloads.forEach(function (ov) {
        ov.implementation = function () {
          var ret = ov.apply(this, arguments);
          try {
            var url = '';
            try { url = String(this.getURL()); } catch (e) {}
            emit('sink_http_' + m, 'network_sink', 'HttpURLConnection.' + m, 'url=' + truncate(url, 130),
                 sanitize(ret), { signal: 'S090', group: '网络信息', pi: '外发数据',
                                  sink: 'K1', evidence: 'C', depth: 10 });
          } catch (e) {}
          return ret;
        };
      });
    });
    installed.push('sink_http — HttpURLConnection.connect/getInputStream/getOutputStream');
  } catch (e) { failed.push('sink_http — ' + e); }

  /* 真实实现类：Android 内置 OkHttp（只 hook java.net 会漏大量真实上报） */
  [['com.android.okhttp.internal.huc.HttpURLConnectionImpl', ['connect', 'getInputStream']],
   ['com.android.okhttp.internal.huc.HttpsURLConnectionImpl', ['connect', 'getInputStream']],
   ['com.android.okhttp.internal.http.HttpURLConnectionImpl', ['connect', 'getInputStream']]
  ].forEach(function (pair) {
    pair[1].forEach(function (m) {
      try {
        var K = Java.use(pair[0]);
        if (!K[m]) return;
        K[m].overloads.forEach(function (ov) {
          ov.implementation = function () {
            var ret = ov.apply(this, arguments);
            try {
              var url = '';
              try { url = String(this.getURL()); } catch (e) {}
              emit('sink_okhttp_plat', 'network_sink', shortName(pair[0]) + '.' + m,
                   'url=' + truncate(url, 130), sanitize(ret),
                   { signal: 'S090', group: '网络信息', pi: '外发数据',
                     sink: 'K1', evidence: 'C', depth: 10 });
            } catch (e) {}
            return ret;
          };
        });
        installed.push('sink_okhttp_plat — ' + shortName(pair[0]) + '.' + m);
      } catch (e) { /* 该设备无此类，正常 */ }
    });
  });

  /* OkHttp3 / Okio —— 仅当 App 集成了才存在，属正常缺失 */
  [['okhttp3.internal.connection.RealCall', ['execute', 'enqueue']],
   ['okhttp3.RealCall', ['execute', 'enqueue']]
  ].forEach(function (pair) {
    try {
      var OC = Java.use(pair[0]);
      pair[1].forEach(function (m) {
        if (!OC[m]) return;
        OC[m].overloads.forEach(function (ov) {
          ov.implementation = function () {
            var ret = ov.apply(this, arguments);
            try {
              var u = '';
              try { u = String(this.request().url().toString()); } catch (e) {}
              emit('sink_okhttp3', 'network_sink', shortName(pair[0]) + '.' + m,
                   'url=' + truncate(u, 130), sanitize(ret),
                   { signal: 'S090', group: '网络信息', pi: '外发数据',
                     sink: 'K1', evidence: 'C', depth: 10 });
            } catch (e) {}
            return ret;
          };
        });
      });
      installed.push('sink_okhttp3 — ' + shortName(pair[0]));
    } catch (e) { /* 未集成 okhttp3，正常 */ }
  });

  /* Socket 建连（噪声大，只留线索） */
  try {
    var Sock = Java.use('java.net.Socket');
    Sock.$init.overloads.forEach(function (ov) {
      ov.implementation = function () {
        var args = Array.prototype.slice.call(arguments);
        var ret = ov.apply(this, args);
        try {
          var host = args[0] ? String(args[0]) : '';
          if (host && !/^127\.|^0\.0\.0|^10\.|^192\.168\./.test(host)) {
            emit('sink_socket', 'network_sink', 'Socket.<init>', 'host=' + truncate(host, 80),
                 sanitize(args[1]), { signal: 'S091', group: '网络信息', pi: '外发数据',
                                      sink: 'K1', evidence: 'D', depth: 8 });
          }
        } catch (e) {}
        return ret;
      };
    });
    installed.push('sink_socket — Socket.<init>');
  } catch (e) { failed.push('sink_socket — ' + e); }

  /* ---------------- 11. 数据去向：本地持久化 / 日志 ---------------- */
  try {
    var SP = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    ['putString', 'putInt', 'putLong', 'putBoolean', 'putStringSet'].forEach(function (m) {
      if (!SP[m]) return;
      SP[m].overloads.forEach(function (ov) {
        ov.implementation = function () {
          var args = Array.prototype.slice.call(arguments);
          var ret = ov.apply(this, args);
          try {
            var key = String(args[0] || '');
            if (/imei|imsi|mac|androidid|android_id|oaid|uuid|device|token|phone|mobile|lat|lon|location|idfa|vaid/i.test(key)) {
              emit('sink_sp_' + m, 'storage_sink', 'SharedPreferences.Editor.' + m,
                   'key=' + truncate(key, 60), sanitize(args[1]),
                   { signal: 'S064', group: '操作手机', pi: '本地留存',
                     sink: 'K2', evidence: 'B', depth: 10 });
            }
          } catch (e) {}
          return ret;
        };
      });
    });
    installed.push('sink_sharedprefs — SharedPreferences.Editor 敏感 key');
  } catch (e) { failed.push('sink_sharedprefs — ' + e); }

  try {
    var DB = Java.use('android.database.sqlite.SQLiteDatabase');
    ['insert', 'execSQL', 'insertOrThrow', 'replace'].forEach(function (m) {
      if (!DB[m]) return;
      DB[m].overloads.forEach(function (ov) {
        ov.implementation = function () {
          var args = Array.prototype.slice.call(arguments);
          var ret = ov.apply(this, args);
          try {
            var tbl = String(args[0] || '');
            if (tbl && !/^\s*(android_|sqlite_|cache)/i.test(tbl)) {
              emit('sink_sqlite_' + m, 'storage_sink', 'SQLiteDatabase.' + m,
                   'table=' + truncate(tbl, 50), sanitize(ret),
                   { signal: 'S063', group: '操作手机', pi: '本地留存',
                     sink: 'K2', evidence: 'C', depth: 10 });
            }
          } catch (e) {}
          return ret;
        };
      });
    });
    installed.push('sink_sqlite — SQLiteDatabase.insert/execSQL');
  } catch (e) { failed.push('sink_sqlite — ' + e); }

  try {
    var Log = Java.use('android.util.Log');
    ['d', 'i', 'w', 'e', 'v'].forEach(function (m) {
      if (!Log[m]) return;
      Log[m].overloads.forEach(function (ov) {
        ov.implementation = function () {
          var args = Array.prototype.slice.call(arguments);
          var ret = ov.apply(this, args);
          try {
            var body = args.length > 1 ? String(args[1] || '') : '';
            if (/\b(imei|imsi|mac|android[_-]?id|oaid|idfa|vaid|uuid|lat|lon|lng|token|phone)\b\s*[:=]/i.test(body)) {
              emit('sink_log_' + m, 'log_sink', 'Log.' + m, 'tag=' + truncate(args[0], 30),
                   truncate(body, 120), { signal: 'S094', group: '操作手机', pi: '日志泄露',
                                          sink: 'K3', evidence: 'C', depth: 8 });
            }
          } catch (e) {}
          return ret;
        };
      });
    });
    installed.push('sink_log — Log.d/i/w/e/v（仅含敏感字段名）');
  } catch (e) { failed.push('sink_log — ' + e); }

  /* ---------------- 12. 隐私政策捕获 ---------------- */
  try {
    var WV = Java.use('android.webkit.WebView');
    if (WV.$init) {
      WV.$init.overloads.forEach(function (ov) {
        ov.implementation = function () {
          var ret = ov.apply(this, arguments);
          try { registerWebView(this); } catch (e) {}
          return ret;
        };
      });
    }
    if (WV.loadUrl) {
      WV.loadUrl.overloads.forEach(function (ov) {
        ov.implementation = function () {
          var args = Array.prototype.slice.call(arguments);
          try {
            registerWebView(this);
            noteUrl(String(args[0] || ''), 'WebView.loadUrl');
          } catch (e) {}
          return ov.apply(this, args);
        };
      });
    }
    if (WV.loadDataWithBaseURL) {
      WV.loadDataWithBaseURL.overloads.forEach(function (ov) {
        ov.implementation = function () {
          var args = Array.prototype.slice.call(arguments);
          try {
            var baseUrl = String(args[0] || '');
            var body = String(args[1] || '');
            var isHttp = /^https?:/i.test(baseUrl);
            noteUrl(baseUrl, 'WebView.loadDataWithBaseURL');
            if (body.length > 400) {
              // ★ 存**纯文本**，不存源码（见 htmlToText 的说明）。
              //   是 http 地址就用它当 key（那样的正文确实有可访问地址）；
              //   否则用 about:blank#inline —— 报告据此写"应用内置内容，
              //   没有网络地址"，而不是含糊一句"未记录到可访问地址"。
              var txt = htmlToText(body);
              if (txt.length > 200) {
                var key = isHttp ? baseUrl : 'about:blank#inline';
                if (!policy.texts[key] || txt.length > policy.texts[key].length) {
                  policy.texts[key] = txt;
                }
                send({ type: 'policy', kind: 'text', url: key, len: txt.length,
                       text: truncate(txt, 200000), ts: Date.now(),
                       inline: !isHttp, baseUrl: baseUrl.slice(0, 200) });
              }
            }
          } catch (e) {}
          return ov.apply(this, args);
        };
      });
    }
    if (WV.loadData) {
      WV.loadData.overloads.forEach(function (ov) {
        ov.implementation = function () {
          var args = Array.prototype.slice.call(arguments);
          try {
            var body = String(args[0] || '');
            if (body.length > 400) {
              var txt2 = htmlToText(body);
              if (txt2.length > 200 && !policy.texts['about:blank#inline']) {
                policy.texts['about:blank#inline'] = txt2;
              }
              send({ type: 'policy', kind: 'text', url: 'about:blank#inline',
                     len: txt2.length, text: truncate(txt2, 200000),
                     ts: Date.now(), inline: true });
            }
          } catch (e) {}
          return ov.apply(this, args);
        };
      });
    }
    installed.push('policy_webview — WebView.loadUrl/loadDataWithBaseURL/$init');
  } catch (e) { failed.push('policy_webview — ' + e); }

  ['android.webkit.WebViewClient', 'android.webkit.WebChromeClient'].forEach(function (cn) {
    try {
      var WC = Java.use(cn);
      ['shouldOverrideUrlLoading', 'onPageStarted', 'onPageFinished'].forEach(function (m) {
        if (!WC[m]) return;
        WC[m].overloads.forEach(function (ov) {
          ov.implementation = function () {
            var args = Array.prototype.slice.call(arguments);
            try {
              for (var i = 0; i < args.length; i++) {
                if (args[i] && args[i].$className && String(args[i].$className).indexOf('WebView') >= 0) {
                  registerWebView(args[i]);
                } else if (typeof args[i] === 'string' && args[i].indexOf('http') === 0) {
                  noteUrl(args[i], cn.split('.').pop() + '.' + m);
                } else if (args[i] && args[i].$className && ('' + args[i].$className).indexOf('WebResourceRequest') >= 0) {
                  try { noteUrl(String(args[i].getUrl()), cn.split('.').pop() + '.' + m); } catch (e) {}
                }
              }
              if (m === 'onPageFinished') {
                var self = this;
                setTimeout(function () { try { readAllWebViews(); } catch (e) {} }, 900);
              }
            } catch (e) {}
            return ov.apply(this, args);
          };
        });
      });
      installed.push('policy_webclient — ' + cn.split('.').pop());
    } catch (e) { /* 不同版本差异，正常 */ }
  });

  /* 通过 Intent 打开外链（很多 App 用系统浏览器打开隐私政策） */
  ['android.app.Activity', 'android.content.ContextWrapper'].forEach(function (cn) {
    try {
      var C = Java.use(cn);
      if (!C.startActivity) return;
      C.startActivity.overloads.forEach(function (ov) {
        ov.implementation = function () {
          var args = Array.prototype.slice.call(arguments);
          try {
            var it = args[0];
            if (it && it.$className && String(it.$className).indexOf('Intent') >= 0) {
              var act = String(it.getAction() || '');
              var data = String(it.getData() || '');
              if (data && data.indexOf('http') === 0) noteUrl(data, 'Intent:' + act);
              /* 有些 App 把 URL 放在 extra 里 */
              try {
                var b = it.getExtras();
                if (b) {
                  var keys = b.keySet().toArray();
                  for (var i = 0; i < keys.length; i++) {
                    var k = String(keys[i]);
                    if (/url|link|redirect|target/i.test(k)) {
                      var v = String(b.getString(k) || '');
                      if (v.indexOf('http') === 0) noteUrl(v, 'Intent.extra:' + k);
                    }
                  }
                }
              } catch (e2) {}
            }
          } catch (e) {}
          return ov.apply(this, args);
        };
      });
      installed.push('policy_intent_' + shortName(cn) + ' — startActivity');
    } catch (e) { /* 正常 */ }
  });

  /* 弹窗里的政策入口文字：TextView.setText 含政策关键词即记录（不点击也能留证） */
  try {
    var TV = Java.use('android.widget.TextView');
    TV.setText.overloads.forEach(function (ov) {
      ov.implementation = function () {
        var args = Array.prototype.slice.call(arguments);
        var ret = ov.apply(this, args);
        try {
          var s = String(args[0] || '');
          if (s.length > 4 && s.length < 4000 &&
              /隐私政策|个人信息保护政策|隐私权政策|用户协议|隐私权声明|个人信息保护指引|隐私协议/.test(s)) {
            if (policy.entryTexts.length < 40 && policy.entryTexts.indexOf(s) < 0) {
              policy.entryTexts.push(s);
              send({ type: 'policy', kind: 'entry', text: truncate(s, 400), ts: Date.now(),
                     elapsedMs: Date.now() - state.startTs });
            }
          }
        } catch (e) {}
        return ret;
      };
    });
    installed.push('policy_textview — TextView.setText（政策入口文字）');
  } catch (e) { failed.push('policy_textview — ' + e); }

  /* ---------------- 13. 同意状态（辅助信号） ----------------
   * 主判定由 Python 侧依据 UI 点击文字显式调用 setConsent()。
   * 这里的 hook 只作为补充：捕获 App 自身的隐私弹窗消失 / 同意类点击。 */
  try {
    var Btn = Java.use('android.widget.Button');
    Btn.performClick.implementation = function () {
      var ret = this.performClick();
      try { tryMarkConsent(String(this.getText() || ''), 'Button.performClick'); } catch (e) {}
      return ret;
    };
    installed.push('consent_button_click — Button.performClick（辅助）');
  } catch (e) { failed.push('consent_button_click — ' + e); }

  try {
    var TV2 = Java.use('android.widget.TextView');
    TV2.performClick.implementation = function () {
      var ret = this.performClick();
      try { tryMarkConsent(String(this.getText() || ''), 'TextView.performClick'); } catch (e) {}
      return ret;
    };
    installed.push('consent_textview_click — TextView.performClick（辅助）');
  } catch (e) { failed.push('consent_textview_click — ' + e); }

  /* ---------------- 14. SDK 动态发现（按包名前缀，换 App 不失效） ---------------- */
  setTimeout(function () {
    try { discoverSdks(); } catch (e) {}
  }, 3500);

  send({ type: 'hooks', installed: installed, failed: failed, total: installed.length + failed.length });
});

/* ================================================================
 * 同意标记
 * ================================================================ */

function tryMarkConsent(text, via) {
  if (state.consent) return;
  if (!text) return;
  // 先排除否定式（「不同意」「拒绝」「暂不」…），再匹配同意词
  for (var r = 0; r < CONSENT_REJECT.length; r++) {
    if (text.indexOf(CONSENT_REJECT[r]) >= 0) {
      send({ type: 'consent_rejected', text: truncate(text, 40), via: via });
      return;
    }
  }
  for (var i = 0; i < CONSENT_KEYWORDS.length; i++) {
    if (text.indexOf(CONSENT_KEYWORDS[i]) >= 0) {
      state.consent = true;
      state.consentAt = Date.now();
      state.consentSource = via + ':' + truncate(text, 30);
      send({ type: 'consent', text: truncate(text, 40), via: via,
             ts: state.consentAt, elapsedMs: state.consentAt - state.startTs });
      return;
    }
  }
}

/* ================================================================
 * SDK 动态发现
 * ================================================================ */

var SDK_PREFIXES = [
  ['com.bun.miitmdid', 'MSA OAID SDK'],
  ['com.asus.msa', '华硕 MSA SDK'],
  ['com.huawei.hms.ads.identifier', '华为 OAID'],
  ['com.heytap.openid', 'OPPO OAID'],
  ['com.vivo.identifier', 'vivo OAID'],
  ['com.coolpad.deviceidsupport', '酷派 OAID'],
  ['com.android.id', '设备标识库'],
  ['com.umeng', '友盟'],
  ['com.tencent', '腾讯'],
  ['com.bytedance', '字节'],
  ['com.alibaba', '阿里'],
  ['com.baidu', '百度'],
  ['com.kwad', '快手广告'],
  ['com.qq.e', '优量汇广告'],
  ['com.pangle', '穿山甲广告'],
  ['okhttp3', 'OkHttp3'],
  ['com.squareup.okhttp', 'OkHttp2'],
  ['com.google.android.gms', 'GMS']
];

/* OAID 取值方法名（各厂商 SDK 命名不一，用方法名匹配） */
var OAID_METHODS = ['getOAID', 'getOaid', 'getOAIDAsync', 'getVAID', 'getAAID',
                    'getClientId', 'getDevId', 'getSerial', 'getUDID',
                    'getId', 'getDeviceId', 'getImei', 'getMac', 'getAndroidId'];

function discoverSdks() {
  try {
    var all = Java.enumerateLoadedClassesSync();
    var totals = {};
    var seen = {};
    for (var i = 0; i < all.length; i++) {
      var cn = all[i];
      for (var p = 0; p < SDK_PREFIXES.length; p++) {
        if (cn.indexOf(SDK_PREFIXES[p][0]) === 0) {
          totals[SDK_PREFIXES[p][1]] = (totals[SDK_PREFIXES[p][1]] || 0) + 1;
          seen[cn] = SDK_PREFIXES[p][1];
          break;
        }
      }
    }
    var found = [];
    for (var name in totals) found.push({ sdk: name, classes: totals[name] });

    /* 对命中的 SDK 类尝试挂 OAID 取值方法（只挂叶子类，控制开销） */
    var hooked = 0;
    var count = 0;
    for (var cls in seen) {
      if (count >= 60) break;
      if (!/\.(impl|internal|provider|util|core|api)\./i.test(cls) &&
          !/(oaid|id|device|identifier|support|sdk)/i.test(cls)) {
        continue;
      }
      count++;
      (function (klass) {
        try {
          var C = Java.use(klass);
          for (var mi = 0; mi < OAID_METHODS.length; mi++) {
            var m = OAID_METHODS[mi];
            if (!C[m]) continue;
            (function (meth) {
              C[meth].overloads.forEach(function (ov) {
                ov.implementation = function () {
                  var args = Array.prototype.slice.call(arguments);
                  var ret = ov.apply(this, args);
                  try {
                    emit('sdk_' + String(klass).split('.').pop() + '_' + meth, 'device_id',
                         String(klass).split('.').pop() + '.' + meth, formatArgs(args), sanitize(ret),
                         { signal: 'S007', group: '硬件标识', pi: '设备标识（OAID）',
                           evidence: validValue(ret) ? 'A' : 'B', depth: 12 });
                  } catch (e) {}
                  return ret;
                };
                hooked++;
              });
            })(m);
          }
        } catch (e) {}
      })(cls);
    }
    send({ type: 'sdks', sdks: found, hookedMethods: hooked,
           totalClasses: all.length });
  } catch (e) {
    send({ type: 'sdks', sdks: [], hookedMethods: 0, error: String(e) });
  }
}

/* ================================================================
 * 政策链接定位（按文字布局算坐标）
 * ================================================================
 *
 * ★ 为什么需要（2026-11-08，岛 2.2.0 真机实测）：
 *   首启弹窗里的《用户协议》《隐私协议》是**正文里的一段普通文字**：
 *     · 与正文同色、无下划线 —— 视觉上完全看不出可点（截图肉眼无法分辨）；
 *     · 结构树里没有独立节点：整段正文只有 1 个 TextView，
 *       《隐私协议》不是子节点，也不带 ClickableSpan；
 *     · 所以关键词匹配找不到入口，AI 视觉也只能说"仅有一段告知文本"。
 *   结果政策一次都没打开，报告写"未观测到政策入口"。
 *   而在真机上按文字位置点下去 —— **确实能打开政策页**
 *   （实测前台切到 BrowserActivity，显示《隐私政策》全文，URL 在
 *    Activity intent 的 extra 里）。
 *
 *   关键点：**没有 span 也能量出坐标**。TextView 有 Layout，
 *   给定字符下标就能算出该字符在屏幕上的位置
 *   （getPrimaryHorizontal + getLineTop/Bottom），
 *   于是"书名号片段"与"政策关键词"都能变成可点坐标。
 *
 * 优先级：span 自带 URL（最可靠，连点都不用点） > 书名号片段 > 裸关键词。
 */
function _spanUrl(o, URLSpanCls) {
  try {
    return String(Java.cast(o, URLSpanCls).getURL() || '');
  } catch (e) {
    return '';
  }
}

function collectPolicyLinks(maxItems) {
  var out = [];
  var limit = maxItems || 24;
  Java.perform(function () {
    var ViewCls = Java.use('android.view.View');
    var VGCls = Java.use('android.view.ViewGroup');
    var TVCls = Java.use('android.widget.TextView');
    var SpanCls = Java.use('android.text.Spanned');
    var URLSpanCls = Java.use('android.text.style.URLSpan');
    var ObjCls = Java.use('java.lang.Object').class;
    var intArr = Java.array('int', [0, 0]);

    function loc(v) {
      try { v.getLocationOnScreen(intArr); return [intArr[0], intArr[1]]; }
      catch (e) { return null; }
    }

    /* 字符下标 → 屏幕坐标（落在该字符所在行的中线上） */
    function pointAt(tv, v, off) {
      try {
        var lay = tv.getLayout();
        if (lay === null) return null;
        var line = lay.getLineForOffset(off);
        var x = lay.getPrimaryHorizontal(off);
        var y = (lay.getLineTop(line) + lay.getLineBottom(line)) / 2;
        var sc = loc(v);
        if (sc === null) return null;
        var padL = 0, padT = 0;
        try { padL = tv.getTotalPaddingLeft(); padT = tv.getTotalPaddingTop(); } catch (e) {}
        // 长正文会在框内滚动，要把 scrollX/scrollY 抵掉，否则点到的不是那一行
        var sx = 0, sy = 0;
        try { sx = tv.getScrollX(); sy = tv.getScrollY(); } catch (e) {}
        return [Math.round(sc[0] + padL - sx + x), Math.round(sc[1] + padT - sy + y)];
      } catch (e) {
        return null;
      }
    }

    function push(text, xy, url, src, v) {
      if (!xy || !text) return;
      if (out.length >= limit) return;
      for (var i = 0; i < out.length; i++) {
        if (Math.abs(out[i].xy[0] - xy[0]) < 8 && Math.abs(out[i].xy[1] - xy[1]) < 8) {
          if (url && !out[i].url) out[i].url = url;
          return;
        }
      }
      out.push({text: String(text).slice(0, 60), xy: xy, url: url || '',
                src: src, cls: String(v.$className), win: _curWin});
    }

    var KW = ['隐私政策', '隐私协议', '隐私权政策', '用户协议', '服务协议',
              '个人信息保护指引', '个人信息保护政策', '个人信息保护规则'];

    // 当前正在遍历的窗口类型：dialog / popup 在最上层，能收到触摸；
    // activity 的控件可能被模态弹窗盖住 —— 点了没反应（岛实测）。
    var _curWin = '';

    function dumpTv(v, tv) {
      var txt = null;
      try { txt = tv.getText(); } catch (e) { return; }
      if (txt === null) return;
      var s = String(txt);
      if (!s || s.length > 12000) return;

      /* ① 真正的 span：带 URL 的直接拿到链接 */
      var spanned = null;
      try { spanned = Java.cast(txt, SpanCls); } catch (e) { spanned = null; }
      if (spanned !== null) {
        try {
          var all = spanned.getSpans(0, spanned.length(), ObjCls);
          for (var i = 0; i < all.length; i++) {
            var o = all[i];
            var st = spanned.getSpanStart(o), en = spanned.getSpanEnd(o);
            if (st < 0 || en <= st) continue;
            var piece = '';
            try { piece = s.substring(st, en); } catch (e2) {}
            var u = _spanUrl(o, URLSpanCls);
            push(piece || u, pointAt(tv, v, st), u, 'span', v);
          }
        } catch (e3) {}
      }

      /* ② 书名号片段：这类文字即使没有 span，也常被 App 自己接管点击 */
      var re = /《[^》]{2,40}》/g, m;
      while ((m = re.exec(s)) !== null) {
        push(m[0], pointAt(tv, v, m.index), '', 'anchor', v);
        if (out.length >= limit) break;
      }

      /* ③ 裸关键词（没有书名号的写法） */
      for (var k = 0; k < KW.length && out.length < limit; k++) {
        var idx = s.indexOf(KW[k]);
        var guard = 0;
        while (idx >= 0 && guard < 4) {
          push(KW[k], pointAt(tv, v, idx), '', 'keyword', v);
          idx = s.indexOf(KW[k], idx + KW[k].length);
          guard++;
        }
      }
    }

    function walk(v, d) {
      if (v === null || d > 40) return;
      try {
        // ★ 必须用 cast 判断 TextView：`v instanceof TextView` 按**声明类型**
        //   （android.view.View）判断，永远 false —— 界面上实际是
        //   androidx.appcompat.widget.AppCompatTextView。
        var tv = null;
        try { tv = Java.cast(v, TVCls); } catch (eCast) { tv = null; }
        if (tv !== null) dumpTv(v, tv);
        var n = 0, vg = null;
        // ★ getChildCount/getChildAt 是 ViewGroup 的方法，View 上调用抛
        //   "TypeError: not a function"，整棵树到根节点就停 —— 先 cast。
        try { vg = Java.cast(v, VGCls); n = vg.getChildCount(); } catch (e8) { n = 0; }
        for (var i = 0; i < n; i++) walk(vg.getChildAt(i), d + 1);
      } catch (e7) {}
    }

    try {
      // ★ 不用 WindowManagerGlobal.getRootViews()：这台 MIUI(Android 12) 上
      //   它只剩 .overload('android.os.IBinder')，无参版本被厂商改掉了。
      //
      // ★ 必须同时遍历 Activity / Dialog / PopupWindow 三类窗口（2026-11-08）：
      //   首启隐私弹窗几乎都是 Dialog（或 PopupWindow），它有自己的 Window，
      //   **不在 Activity 的 decorView 树里**。
      //   只遍历 Activity 的后果（岛实测）：拿到的全是弹窗底下那个登录页上的
      //   《用户协议》《隐私政策》（y=1731），点下去毫无反应 —— 因为它们被
      //   模态弹窗盖住，触摸事件被弹窗吃掉；
      //   真正能点的是弹窗正文里那一行文字（y≈1233）。
      function visit(dv, win) {
        if (dv === null || dv === undefined) return;
        _curWin = win || '';
        walk(Java.cast(dv, ViewCls), 0);
      }
      Java.choose('android.app.Activity', {
        onMatch: function (act) {
          try { visit(act.getWindow().peekDecorView(), 'activity'); } catch (e9) {}
        },
        onComplete: function () {}
      });
      Java.choose('android.app.Dialog', {
        onMatch: function (dlg) {
          try { visit(dlg.getWindow().peekDecorView(), 'dialog'); } catch (e10) {}
        },
        onComplete: function () {}
      });
      Java.choose('android.widget.PopupWindow', {
        onMatch: function (pw) {
          try {
            var cv = pw.getContentView();
            if (cv !== null) visit(cv.getRootView(), 'popup');
          } catch (e11) {}
        },
        onComplete: function () {}
      });
    } catch (e) {}
  });
  return out;
}

/* ================================================================
 * RPC
 * ================================================================ */

rpc.exports = {
  summary: function () {    return {
      consent: state.consent,
      consentAt: state.consentAt,
      // startTs 必须一起给出去：Python 侧用 consentAt - startTs 算"冷启动后多久同意"。
      // 早先漏了这个字段，差值就成了 epoch 毫秒（1792074259594），
      // 报告里会写成"冷启动后 1792074259.6 秒同意"。
      startTs: state.startTs,
      consentSource: state.consentSource,
      counts: state.counts,
      reportedCount: Object.keys(state.reported).length,
      totalEvents: state.total,
      // 被单信号限流丢掉的条数（按信号汇总）。报告要能说清
      // "某信号发生了 N 次，只上报了 M 条"，而不是让读者以为只发生了 M 次。
      signalSkipped: state.sigSkipped,
      elapsedMs: Date.now() - state.startTs,
      activity: state.curActivity,
      installedCount: installed.length,
      failedCount: failed.length
    };
  },
  // silent=true 只用于「App 进程重启后恢复同意状态」，它不是一次新的同意动作。
  // ★ 真机教训（自设捏脸，2026-10-16 第 4 轮）：早先恢复状态也走同一条分支，
  //   于是新进程会发出 elapsedMs = 300ms 的 consent 事件（新进程的 startTs
  //   是从 0 算起的），把真实的同意时刻（第 178 秒）覆盖成第 0.3 秒。
  //   后果：44 条真实的同意前事件全部落进"同意后"，
  //   「未经同意收集」这项直接从可判定退化为"跳过未测"，且理由与事实相反。
  //   —— 覆盖"同意时刻"是误报/漏报里最危险的一类，因为它同时污染
  //      同意前与同意后两侧的统计。恢复状态只能恢复布尔位，绝不能记时间戳。
  setConsent: function (v, text, silent) {
    state.consent = !!v;
    if (silent) {
      if (state.consent && !state.consentSource) {
        state.consentSource = 'ui:' + (text || '');
      }
      return state.consent;
    }
    if (state.consent && !state.consentAt) {
      state.consentAt = Date.now();
      state.consentSource = 'ui:' + (text || '');
      send({ type: 'consent', text: truncate(text || '', 40), via: 'ui-driven',
             ts: state.consentAt, elapsedMs: state.consentAt - state.startTs });
    }
    return state.consent;
  },
  markUiAction: function (desc) {
    state.uiAction = truncate(desc || '', 80);
    return state.uiAction;
  },
  getPolicy: function () {
    return {
      urls: policy.urls,
      entryTexts: policy.entryTexts,
      entryClicked: policy.entryClicked,
      texts: policy.texts,
      webviewCount: _webviewSeen,
      bestText: (function () {
        var best = '', bestUrl = '';
        for (var u in policy.texts) {
          if (policy.texts[u] && policy.texts[u].length > best.length) {
            best = policy.texts[u]; bestUrl = u;
          }
        }
        return { url: bestUrl, text: best, len: best.length };
      })()
    };
  },
  /** Python 侧点击政策入口后调用：尝试读取当前所有 WebView 的渲染正文 */
  readWebViews: function () {
    var n = 0;
    Java.perform(function () { n = readAllWebViews(); });
    return n;
  },
  /* ★ 别名：Frida 会把 JS 的 readWebViews 规范化成 Python 侧的 read_web_views
     （在 Web 与 Views 各插一个下划线），而 Python 代码历史上一直调 read_webviews
     （把 webviews 当成一个词）—— 两者不匹配，这条调用每次抛异常后被 except 吞掉，
     表现是"看起来读了、其实什么都没读"。真机实测（简小知）才暴露。
     两个名字都导出，避免再踩。 */
  read_webviews: function () {
    var n = 0;
    Java.perform(function () { n = readAllWebViews(); });
    return n;
  },
  notePolicyClick: function (text) {
    policy.entryClicked = truncate(text || '', 120);
    return policy.entryClicked;
  },
  /** 当前所有存活 WebView 的 URL（辅助判断政策页是否已打开）。
      与读正文同一套策略：现场枚举 + 主线程 + retain/release，
      **不缓存实例**（缓存实例事后调用会让 ART 空指针崩溃，见 registerWebView 上的说明）。
      排期是异步的，所以函数同步返回上一次的结果；Python 侧调用两次即可拿到。 */
  currentUrls: function (reset) {
    if (reset) _lastCurrentUrls = [];
    _eachWebView(function (wv) {
      var u = String(wv.getUrl() || '');
      if (u && _lastCurrentUrls.indexOf(u) < 0) _lastCurrentUrls.push(u);
    });
    return _lastCurrentUrls;
  },
  /* 政策链接候选点：按 TextView 的文字布局算出坐标（见 collectPolicyLinks）。
     返回 [{text, xy, url, src}]，src = span / anchor / keyword。
     结构树和 AI 都找不到入口时用它 —— 岛这类"正文里内联链接、无 span、
     无独立节点"的弹窗，只有这条路能真的把政策页点开。 */
  policyLinks: function (maxItems) {
    try {
      return collectPolicyLinks(maxItems);
    } catch (e) {
      return [];
    }
  },
  /* 当前前台 Activity 的 intent 里带的 URL —— 政策页由 App 自己的
     BrowserActivity 承载时，URL 不在 WebView.getUrl()，而是在这里
     （岛实测：extra "url" = https://www.iiisland.com/privacy?show=app&t=...）。 */
  activityUrl: function () {
    var found = [];
    Java.perform(function () {
      try {
        Java.choose('android.app.Activity', {
          onMatch: function (a) {
            try {
              var it = a.getIntent();
              if (it === null) return;
              var d = null;
              try { d = it.getData(); } catch (e) {}
              if (d !== null) {
                var s = String(d.toString() || '');
                if (s.indexOf('http') === 0 && found.indexOf(s) < 0) found.push(s);
              }
              var b = null;
              try { b = it.getExtras(); } catch (e) {}
              if (b !== null) {
                try {
                  var ks = b.keySet().toArray();
                  for (var i = 0; i < ks.length; i++) {
                    var v = b.get(String(ks[i]));
                    if (v === null) continue;
                    var sv = String(v);
                    if (sv.indexOf('http') === 0 && found.indexOf(sv) < 0) found.push(sv);
                  }
                } catch (e2) {}
              }
            } catch (e3) {}
          },
          onComplete: function () {}
        });
      } catch (e) {}
    });
    return found;
  }
};
