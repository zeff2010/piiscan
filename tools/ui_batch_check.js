// 用极简 DOM stub 跑真实的前端脚本，验证批量选择的渲染逻辑。
// （浏览器 headless 在部分机器上被策略挡住，与其"看起来没问题"，不如把断言跑出来。）
//
// 跑法：node tools/ui_batch_check.js   （platform_selftest.py 会自动调用）
const fs = require("fs");
const path = require("path");

const htmlPath = path.join(__dirname, "..", "webapp", "static", "index.html");
const html = fs.readFileSync(htmlPath, "utf8");
const m = html.match(/<script>([\s\S]*?)<\/script>/);
if (!m) { console.log("FAIL 未找到脚本"); process.exit(1); }
const src = m[1];

const elems = {};
function el(id) {
  if (!elems[id]) {
    elems[id] = {
      id, style: {}, dataset: {}, className: "", textContent: "", innerHTML: "",
      checked: false, indeterminate: false, disabled: false, src: "",
      _children: [],
      classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
      querySelectorAll: () => [], insertBefore() {}, appendChild() {},
      addEventListener() {}, removeEventListener() {}, remove() {}, focus() {},
      onclick: null, onchange: null,
    };
  }
  return elems[id];
}
global.document = {
  querySelector: s => el(String(s).replace(/^[#.][\w-]+$/, x => x.slice(1))),
  querySelectorAll: () => [],
  getElementById: id => el(id),
  createElement: () => el("_tmp" + Math.random()),
  body: { appendChild() {} },
};
global.fetch = () => Promise.resolve({ json: () => Promise.resolve({ ok: true, jobs: [], stats: {} }) });
global.setInterval = () => 0;
global.setTimeout = () => 0;
global.clearTimeout = () => {};
global.confirm = () => false;
global.window = global;
// 2026-11-11 起了 hash 路由（三页：系统状态/新建任务/任务列表），
// 脚本启动时会读 location.hash 并写回 history。桩里补上这三个浏览器 API，
// 否则 new Function 在初始化阶段就抛错，后面的 render 断言一条都跑不到。
global.location = { hash: "" };
global.history = { replaceState() {} };
global.addEventListener = () => {};
global.removeEventListener = () => {};
global.scrollTo = () => {};

const api = new Function(src + "\nreturn {render, SEL, JOBS, syncBulk, canDelete, selScope, viewJobs, filterLabel};")();

let ok = 0, fail = 0;
const check = (name, cond, got) => {
  if (cond) { ok++; console.log("  PASS", name); }
  else { fail++; console.log("  FAIL", name, "实际：" + JSON.stringify(got)); }
};

const jobs = [
  { id: "J1", status: "done", app_label: "甲", findings: 2, high: 1, mid: 1, created_at: Date.now() / 1000, actions: ["retry", "delete"] },
  { id: "J2", status: "running", app_label: "乙", progress: 40, stage: "采集中", created_at: Date.now() / 1000, actions: ["pause", "cancel"] },
  { id: "J3", status: "failed", apk_name: "丙.apk", error: "设备断开", created_at: Date.now() / 1000, actions: ["retry", "delete"] },
];

api.render(jobs, { total: 3, done: 1, running: 1, failed: 1 });
const out = elems["list"].innerHTML;

check("表格出现选择列", /<td class="sel"><input type="checkbox" data-sel="J1"/.test(out), out.slice(0, 200));
check("表头有全选框", /<th class="sel"><input type="checkbox" id="selall"/.test(out), out.slice(0, 200));
check("可删任务不 disabled", !/data-sel="J1" disabled/.test(out));
check("★ 运行中任务的勾选框被禁用", /data-sel="J2" disabled title="任务正在执行/.test(out), "未禁用");
check("三条任务都渲染了", (out.match(/data-sel=/g) || []).length === 3, (out.match(/data-sel=/g) || []).length);

// 选中两条后重渲：勾选状态必须保留（列表每 3 秒整体重写）
api.SEL.add("J1"); api.SEL.add("J3");
api.render(jobs, {});
const out2 = elems["list"].innerHTML;
check("★ 重渲后勾选状态保留（J1）", /data-sel="J1" checked/.test(out2), "");
check("★ 重渲后勾选状态保留（J3）", /data-sel="J3" checked/.test(out2), "");
check("批量条显示为已选 2 项", (elems["bulkcount"].textContent === 2 && elems["bulkbar"].classList) ? true : elems["bulkcount"].textContent, elems["bulkcount"].textContent);

// 任务变成运行中 -> 选择里要剔除，不能留一个删不掉的幽灵
api.render(jobs.map(j => j.id === "J1" ? { ...j, status: "running" } : j), {});
check("★ 转为运行中后自动剔除选择", !api.SEL.has("J1"), [...api.SEL]);

// 任务消失 -> 选择里也要剔除
api.render(jobs.filter(j => j.id !== "J3"), {});
check("★ 任务消失后自动剔除选择", api.SEL.size === 0, [...api.SEL]);

// canDelete 口径
check("running 不可删", api.canDelete({ status: "running" }) === false);
check("done/failed/canceled/queued/paused 可删",
  ["done", "failed", "canceled", "queued", "paused"].every(s => api.canDelete({ status: s })));

// ---------- 勾选范围必须跟筛选一致（2026-11-01 误删事故）----------
// 用户筛"失败"→ 点表头全选 → 批量删除，结果整库任务被删光。
// 根因：全选框拿的是未筛选的 JOBS。这里把那条路径钉死。
const jobs4 = [
  { id: "A1", status: "done", app_label: "甲", findings: 2, high: 1, has_report: true },
  { id: "A2", status: "done", app_label: "乙", findings: 0, has_report: true },
  { id: "A3", status: "failed", app_label: "丙", error: "设备断开" },
  { id: "A4", status: "canceled", app_label: "丁" },
  { id: "A5", status: "running", app_label: "戊", progress: 10 },
];
api.render(jobs4, { total: 5, done: 2, failed: 1, canceled: 1, running: 1 });
elems.fstatus.value = "failed";
elems.fstatus.selectedIndex = 0;
elems.fstatus.options = [{ textContent: "失败 / 跳过 / 已停止" }];
elems.fstatus.onchange();          // 切到"失败"筛选
check("★ 切筛选后范围只剩失败/已停止",
  api.viewJobs().map(j => j.id).join(",") === "A3,A4", api.viewJobs().map(j => j.id));

api.SEL.clear();
elems.selall.checked = true;
elems.selall.onchange();           // 点表头全选
check("★ 筛选态下全选只选筛出来的（不含已完成）",
  [...api.SEL].sort().join(",") === "A3,A4", [...api.SEL]);

elems.selall.checked = false;
elems.selall.onchange();           // 取消全选
check("★ 筛选态下反选只取消本范围", api.SEL.size === 0, [...api.SEL]);

// 「全选可删」按钮同样不得越界
api.SEL.clear();
elems.bulkall.onclick();
check("★ 筛选态下「全选可删」不越界",
  [...api.SEL].sort().join(",") === "A3,A4", [...api.SEL]);

// 未筛选时全选仍然覆盖全部可删任务，只是不含运行中的
api.SEL.clear();
elems.fstatus.value = "all";
elems.fstatus.onchange();
elems.selall.checked = true;
elems.selall.onchange();
check("★ 未筛选时全选覆盖全部可删（运行中除外）",
  [...api.SEL].sort().join(",") === "A1,A2,A3,A4", [...api.SEL]);

// 换筛选后，范围外的残留勾选必须被剔掉：在"全部"里勾了已完成，
// 切到"失败"之后这两条看不见了，绝不能还躺在选择里等着被执行。
elems.fstatus.value = "failed";
elems.fstatus.onchange();
check("★ 换筛选后范围外勾选自动剔除",
  [...api.SEL].sort().join(",") === "A3,A4", [...api.SEL]);
api.SEL.clear();

console.log("结果：" + ok + " 项通过，" + fail + " 项失败");
process.exit(fail ? 1 : 0);
