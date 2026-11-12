# 测试机准备（root + frida-server + adb）

平台只做「检查」，不做「刷机」。这份文档说明一台手机要满足什么条件，
以及每一步失败时怎么判断问题在哪。

---

## 1. adb

安好 Android SDK Platform-Tools，确认：

```bash
adb version
adb devices
```

`adb devices` 至少要看到一行 `<serial>  device`。
`unauthorized` 表示手机还没允许这台电脑调试：在手机上点「允许」，
弹窗不出来就先 `adb kill-server` 再插一次。

> Windows 上常见坑：官方 adb 与手机助手自带的 adb 版本不同、抢同一个 5037 端口。
> 只留一套，或在 PATH 里让它优先。

### 平台怎么找 adb（换机器部署时优先看这节）

平台按这个顺序找，找到第一个就用：

1. 环境变量 `ADB` 或 `ADB_PATH`（指向 `adb` / `adb.exe` 本身）
2. 环境变量 `ANDROID_HOME` / `ANDROID_SDK_ROOT` 下的 `platform-tools/`
3. `PATH` 里的 `adb`
4. 各平台默认安装位置，例如 Windows 的
   `%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe`、
   macOS 的 `~/Library/Android/sdk/platform-tools/adb`

**它用的是哪一个，界面上会写出来。** 设备列表为空时，提示的第二行就是
「当前使用的 adb：<完整路径>（来源：PATH / 环境变量 ADB / 默认安装路径）」。

### 插上手机却显示「未检测到测试机」

先看提示区分是哪一类，不要凭猜：

| 界面写的是 | 含义 | 怎么办 |
|---|---|---|
| **未找到 adb，无法检测设备** | 平台没找到 adb（不是手机的问题） | 装 platform-tools；把 `platform-tools` 加进 PATH，或设 `ADB` 指向 `adb.exe`；**重启平台服务**（环境变量只对新进程生效） |
| 未找到 adb … 但命令行里 `adb devices` 正常 | 平台用的 adb 与你命令行里的不是同一个 | 按提示里显示的路径核对；设 `ADB` 指向你在用的那一个，重启服务 |
| **未检测到测试机** + 「设备列表是空的」 | adb 能用，但一台都没看到 | ① 手机「开发者选项 → USB 调试」是否打开；② 插上后手机上的「允许 USB 调试」是否点了允许；③ 换数据线/换 USB 口（有些线只能充电）；④ Windows 设备管理器里是否出现 Android ADB Interface（没有就是驱动没装）；⑤ `adb kill-server` 后重试（可能是别的 adb 抢了 5037） |
| 提示里出现 `unauthorized` | 手机连上了但没授权这台电脑 | 在手机上点「允许 USB 调试」；没弹窗就先「撤销 USB 调试授权」再插 |
| 提示里出现 `offline` | adb 服务与设备状态不同步 | `adb kill-server` → 重插 → `adb devices` |

另外注意：**`adb devices` 里能看到 ≠ 平台能拿它跑任务**。还要在
「手机管理」里「添加手机」登记一次（见第 4 节）。未登记的设备会显示成
「未登记 · 不参与任务」的卡片，下拉框里不会出现。

---

## 2. root

平台用 `su -c` 做这些事：启动 frida-server、读 `dumpsys`、清应用数据、抓截图。
**没有 root 就跑不了动态采集**。

验证：

```bash
adb shell su -c id
# 期望：uid=0(root) gid=0(root) ...
```

用 Magisk 的话，第一次 `su` 请求会在手机上弹授权框，记得**永久允许**
（否则每次调用都要人工点，遍历过程中会卡住）。

平台侧判据：接入手机时会真的执行一次 `su -c` 并看返回，不是读某个配置项。
之后每次列设备也会重新确认 —— 手机上把 root 关了，这台就会从「可用」里掉出去。

---

## 3. frida-server

### 版本必须严格一致

| 本机 pip | 设备上 frida-server |
|---|---|
| `frida==16.7.18`（`requirements.txt` 锁定） | `frida-server-16.7.18-android-<abi>` |

不一致时接入向导会直接失败并打印两边的版本号。**不要「先跑起来再说」**：
版本错着采到的调用栈是不可信的，而报告上不会体现这个差异。

### 拿到二进制

三条路，任选：

1. **让平台下载**：手机管理 → 添加手机，检测到本机没有二进制时会尝试
   下载到 `tools/frida/`（需要能访问 GitHub）。
2. **手动放**：从 [frida releases](https://github.com/frida/frida/releases)
   下对应 ABI 的 `frida-server-16.7.18-android-arm64.xz`，解压后放到
   `tools/frida/frida-server-16.7.18-android-arm64`。
3. **环境变量**：`FRIDA_SERVER=/path/to/frida-server`。

ABI 怎么确定：`adb shell getprop ro.product.cpu.abi`。
`arm64-v8a` 用 `android-arm64`，`armeabi-v7a` 用 `android-arm`。
**64 位系统上装 32 位 App 时，注入需要 32 位的 frida-server** ——
本仓库只自动下载当前设备主 ABI 的那一份，混合场景要两份都备。

### 手动启动（排错用）

平台会自动推送并启动，但排查时手动跑一遍最快：

```bash
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c '/data/local/tmp/frida-server -D &'"
adb shell "ps -A | grep frida"          # 应能看到进程

# 本机验证注入链路（这一步通了，平台侧就基本能通）
frida-ps -U
```

`frida-ps -U` 能列出进程名 = 注入链路正常。

### 常见错误

| 现象 | 原因 |
|---|---|
| `Failed to spawn: unable to find process with name` | 包名错，或 App 不允许被 spawn |
| `unable to connect to remote frida-server` | 没启动 / 端口被占（默认 27042）/ 只监听了 localhost |
| 进程秒退、注入后应用消失 | 有反调试或加固壳，见 README「边界」一节 |
| `permission denied` | 忘了 `chmod 755`，或没走 `su` |

---

## 4. 平台里的设备登记

「手机管理」→「+ 添加手机」，向导 10 步，约 10 秒：

```
adb 可见 → 设备信息（型号/系统/ABI）→ root 验证 → 选 frida 二进制
→ 推送 → 启动 → 注入自检 → 记录（root_ok + frida 版本 + 验证时间）
```

成功后会写一条记录，界面上显示「已登记」。四条语义要知道：

1. **登记簿是唯一口径**。没登记的设备，即使 `adb devices` 能看到，
   也只显示、不参与统计、不能被选来跑任务。
2. **登记 ≠ 现在可用**。`可用 = 接入时验过 root + 此刻在 adb 里 + 此刻 root 还在`。
   手机拔了、root 关了，这台就从可用里掉出去。
3. **删除只删记录，不动设备**。
4. 接入失败时可以「降级登记」（功能受限），界面会标出来 ——
   这种设备能跑不依赖注入的部分，报告里会写明。

### 为什么要给每台机配手机号

登录辅助要发短信。每台机插的是自己的卡，**用 A 机的号登录 B 机上的 App，
验证码根本到不了**，而现象只是「登录超时」—— 很容易被误当成 App 的问题。
所以号码是跟设备绑的，切设备时表单会跟着换，没登记的机器会清空让你手填。

---

## 5. 稳定性建议

- 用**原装或质量好的数据线**，遍历过程中掉线会中断采集（重连后任务会等，但时间预算照走）。
- 关掉手机的自动锁屏 / 省电策略 / 自动清理后台，否则长跑（`extreme` 档 1 小时）
  会在中途被系统杀掉。
- 关闭系统「自动更新」和厂商的「应用行为管控」，它们会拦截 `su` 或注入。
- 采集期间别在同一台机上手动操作 —— 界面状态会被你的点击带偏，证据链就对不上了。
