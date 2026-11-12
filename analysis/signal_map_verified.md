# 采集信号映射表 · 真机验证报告

> 生成时间：2026-10-15 16:08:09  ｜  验证设备：Redmi K30（Android 12 / SDK 31）
> 靶子 App：`bin.mt.plus`

## 一、验证结论

| 项目 | 数值 |
|---|---|
| 映射表信号总数 | 85（5 列 × 17） |
| 声明的 hook 点 | 139 |
| **框架级 hook 点真机确认存在** | **126** |
| 未解析（全部为第三方 SDK 类） | 13 |
| 需包名前缀兜底的信号 | 9 |

**核心结论：所有框架级 hook 点在 Android 12 真机上 100% 存在**，并已取得精确重载签名。
13 个未解析项全部是第三方 SDK 类（OAID / GMS / AndroidX / OkHttp / 友盟等），其存在与否取决于目标 App 集成了哪个 SDK —— 这是预期行为，不是映射表错误。

## 二、关键发现：网络 hook 点必须修正

真机发现 `com.android.okhttp` 包下存在 **134 个类**，其中包括：

```
com.android.okhttp.internal.huc.HttpURLConnectionImpl#connect   ← 真实实现
com.android.okhttp.internal.huc.HttpsURLConnectionImpl#connect  ← HTTPS 真实实现
com.android.okhttp.internal.http.HttpEngine#connect
com.android.okhttp.internal.io.RealConnection#connect
```

**`java.net.HttpURLConnection` 只是抽象层**。只 hook 它，会漏掉大量真实网络请求，
直接影响「第三方共享 / 数据出境」类判定的召回率。已在映射表 S081/S086 中补入这两个类。

## 三、SDK 依赖信号（需包名前缀兜底匹配）

写死类名在换 App 后会失效。以下信号改为「枚举已加载类 → 按包名前缀筛选 → 找目标方法」：

| 信号 | 名称 | 前缀 |
|---|---|---|
| S007 | OAID | `com.bun.miitmdid`, `com.heytap.openid`, `com.huawei.hms.ads`, `com.bun.lib` |
| S008 | VAID | `com.bun.miitmdid`, `com.vivo.identifier` |
| S009 | AAID | `com.bun.miitmdid`, `com.asus.msa` |
| S010 | GAID | `com.google.android.gms.ads` |
| S043 | 定位信息 | `com.google.android.gms.location` |
| S069 | 申请敏感权限 | `androidx.core.app` |
| S070 | 检查权限状态 | `androidx.core.content` |
| S081 | HTTP访问 | `com.android.okhttp`, `okhttp3`, `com.android.volley` |
| S086 | 发敏感词 | `com.android.okhttp.okio`, `okio` |

靶子 App 实测已加载类总数：**23059**。命中情况：

| 包名前缀 | 命中类数 | 说明 |
|---|---|---|
| `com.android.okhttp` | 134 | 已集成 |
| `okhttp3` | 0 | 未集成 |
| `com.bun.miitmdid` | 0 | 未集成 |
| `com.vivo.identifier` | 0 | 未集成 |
| `com.google.android.gms.ads` | 0 | 未集成 |
| `androidx.core.app` | 0 | 未集成 |
| `com.android.volley` | 0 | 未集成 |
| `com.tencent` | 0 | 未集成 |
| `com.umeng` | 235 | 已集成 |
| `com.alibaba` | 0 | 未集成 |
| `com.bytedance` | 0 | 未集成 |

## 四、证据分级与误报风险分布

| 等级 | 含义 | 信号数 |
|---|---|---|
| A | 直接证据 —— API 语义唯一，返回值即目标数据 | 47 |
| B | 条件证据 —— 语义宽泛，须按参数/返回值判定 | 29 |
| C | 间接证据 —— 只能推断，须叠加落地或上报 | 9 |

| 误报风险 | 信号数 |
|---|---|
| 低 | 47 |
| 中 | 27 |
| 高 | 11 |

## 五、分组明细

| 分组 | 信号数 | 证据 A | 证据 B | 证据 C | 高风险 |
|---|---|---|---|---|---|
| 硬件标识 | 17 | 11 | 4 | 2 | 1 |
| 模组信息 | 17 | 14 | 3 | 0 | 0 |
| 用户信息 | 17 | 8 | 8 | 1 | 2 |
| 操作手机 | 17 | 8 | 8 | 1 | 3 |
| 网络信息 | 17 | 6 | 6 | 5 | 5 |

## 六、逐项验证状态

| 信号 | 名称 | 分组 | 证据 | 误报 | 框架 hook 点验证 |
|---|---|---|---|---|---|
| S001 | IMEI | 硬件标识 | A | 低 | ✔ TelephonyManager<br>✔ TelephonyManager |
| S002 | IMSI | 硬件标识 | A | 低 | ✔ TelephonyManager |
| S003 | MEID | 硬件标识 | A | 低 | ✔ TelephonyManager |
| S004 | ICCID | 硬件标识 | A | 低 | ✔ TelephonyManager |
| S005 | 硬件序列号 | 硬件标识 | B | 中 | ✔ Build<br>✔ SystemProperties |
| S006 | Android ID | 硬件标识 | B | 中 | ✔ Settings$Secure |
| S007 | OAID | 硬件标识 | A | 低 | ○ SDK 前缀兜底<br>○ SDK 前缀兜底 |
| S008 | VAID | 硬件标识 | A | 低 | ○ SDK 前缀兜底<br>○ SDK 前缀兜底 |
| S009 | AAID | 硬件标识 | A | 低 | ○ SDK 前缀兜底<br>○ SDK 前缀兜底 |
| S010 | GAID | 硬件标识 | A | 低 | ○ SDK 前缀兜底 |
| S011 | MAC地址 | 硬件标识 | B | 中 | ✔ WifiInfo<br>✔ NetworkInterface |
| S012 | BSSID | 硬件标识 | A | 低 | ✔ WifiInfo |
| S013 | SSID | 硬件标识 | A | 低 | ✔ WifiInfo |
| S014 | CPU序列号 | 硬件标识 | C | 高 | native（未验证）<br>native（未验证） |
| S015 | 手机Boot ID | 硬件标识 | C | 中 | native（未验证）<br>native（未验证） |
| S016 | 本机IP地址 | 硬件标识 | B | 中 | ✔ WifiInfo<br>✔ NetworkInterface<br>✔ InetAddress |
| S017 | 蓝牙名称 | 硬件标识 | A | 低 | ✔ BluetoothAdapter<br>✔ BluetoothAdapter |
| S020 | 运营商信息 | 模组信息 | A | 低 | ✔ TelephonyManager<br>✔ TelephonyManager<br>✔ TelephonyManager |
| S021 | 手机硬件类型 | 模组信息 | A | 低 | ✔ Build<br>✔ Build<br>✔ Build<br>✔ Build |
| S022 | 手机网络类型 | 模组信息 | A | 低 | ✔ TelephonyManager<br>✔ ConnectivityManager |
| S023 | 手机服务状态 | 模组信息 | A | 低 | ✔ TelephonyManager |
| S024 | 手机模版版本 | 模组信息 | A | 低 | ✔ Build$VERSION<br>✔ Build<br>✔ Build |
| S025 | SIM卡状态 | 模组信息 | A | 低 | ✔ TelephonyManager<br>✔ TelephonyManager |
| S026 | SIM国家代码 | 模组信息 | A | 低 | ✔ TelephonyManager<br>✔ TelephonyManager |
| S027 | 移动网参数 | 模组信息 | A | 低 | ✔ TelephonyManager<br>✔ TelephonyManager<br>✔ TelephonyManager |
| S028 | 网络接入标识 | 模组信息 | B | 中 | ✔ TelephonyManager<br>✔ NetworkCapabilities |
| S029 | 语音信箱信息 | 模组信息 | A | 低 | ✔ TelephonyManager<br>✔ TelephonyManager |
| S030 | 手机漫游标识 | 模组信息 | A | 低 | ✔ TelephonyManager |
| S031 | 监听电话状态 | 模组信息 | A | 低 | ✔ TelephonyManager |
| S032 | 拨打电话 | 模组信息 | B | 中 | ✔ Context |
| S033 | 发送短信 | 模组信息 | A | 低 | ✔ SmsManager<br>✔ SmsManager |
| S034 | 接收短信 | 模组信息 | B | 中 | ✔ ContextWrapper |
| S035 | 电话号码 | 模组信息 | A | 低 | ✔ TelephonyManager |
| S036 | 读取传感器 | 模组信息 | A | 低 | ✔ SystemSensorManager<br>✔ SystemSensorManager |
| S040 | 短信记录 | 用户信息 | B | 中 | ✔ ContentResolver |
| S041 | 通话记录 | 用户信息 | B | 中 | ✔ ContentResolver |
| S042 | 通讯录 | 用户信息 | B | 中 | ✔ ContentResolver |
| S043 | 定位信息 | 用户信息 | A | 低 | ✔ LocationManager<br>✔ LocationManager<br>✔ LocationManager<br>○ SDK 前缀兜底 |
| S044 | 图片位置信息 | 用户信息 | A | 低 | ✔ ExifInterface<br>✔ ExifInterface |
| S045 | 解析位置参数 | 用户信息 | A | 低 | ✔ Geocoder<br>✔ Geocoder |
| S046 | 读取剪切板 | 用户信息 | A | 低 | ✔ ClipboardManager<br>✔ ClipboardManager |
| S047 | 写入剪切板 | 用户信息 | A | 低 | ✔ ClipboardManager |
| S048 | 检测剪切板 | 用户信息 | B | 中 | ✔ ClipboardManager<br>✔ ClipboardManager |
| S049 | Android账户 | 用户信息 | A | 低 | ✔ AccountManager<br>✔ AccountManager |
| S050 | 读取日历 | 用户信息 | B | 中 | ✔ ContentResolver |
| S051 | 监听媒体库 | 用户信息 | B | 中 | ✔ ContentResolver<br>✔ ContentResolver |
| S052 | 应用列表 | 用户信息 | A | 低 | ✔ ApplicationPackageManager<br>✔ ApplicationPackageManager |
| S053 | 读指定包名 | 用户信息 | B | 中 | ✔ ApplicationPackageManager<br>✔ ApplicationPackageManager |
| S054 | 读取运行列表 | 用户信息 | A | 低 | ✔ ActivityManager<br>✔ ActivityManager<br>✔ ActivityManager |
| S055 | 读系统属性 | 用户信息 | B | 高 | ✔ SystemProperties<br>✔ SystemProperties<br>✔ Settings$System<br>✔ Settings$Global |
| S056 | 读其他内容库 | 用户信息 | C | 高 | ✔ ContentResolver |
| S060 | 写SDCard | 操作手机 | C | 高 | ✔ FileOutputStream<br>✔ FileWriter |
| S061 | 读SDCard | 操作手机 | B | 中 | ✔ Environment<br>✔ FileInputStream |
| S062 | 数据加解密 | 操作手机 | A | 低 | ✔ Cipher<br>✔ Cipher<br>✔ MessageDigest |
| S063 | SQLite数据库 | 操作手机 | B | 中 | ✔ SQLiteDatabase<br>✔ SQLiteDatabase<br>✔ SQLiteDatabase |
| S064 | SharedPrefs | 操作手机 | B | 中 | ✔ SharedPreferencesImpl$EditorImpl<br>✔ SharedPreferencesImpl |
| S065 | 录音 | 操作手机 | A | 低 | ✔ MediaRecorder<br>✔ AudioRecord |
| S066 | 拍照 | 操作手机 | A | 低 | ✔ Camera<br>✔ CameraCaptureSession |
| S067 | 执行Shell命令 | 操作手机 | B | 中 | ✔ Runtime<br>✔ ProcessBuilder |
| S068 | 创建通知渠道 | 操作手机 | A | 低 | ✔ NotificationManager |
| S069 | 申请敏感权限 | 操作手机 | A | 低 | ✔ Activity<br>○ SDK 前缀兜底 |
| S070 | 检查权限状态 | 操作手机 | B | 中 | ✔ Context<br>○ SDK 前缀兜底 |
| S071 | 加载应用插件 | 操作手机 | A | 低 | ✔ DexClassLoader<br>✔ PathClassLoader |
| S072 | 获取Root权限 | 操作手机 | A | 低 | ✔ Runtime |
| S073 | 安装应用 | 操作手机 | B | 中 | ✔ PackageInstaller<br>✔ Context |
| S074 | 读系统设置 | 操作手机 | B | 高 | ✔ Settings$System<br>✔ Settings$Secure<br>✔ Settings$Global |
| S075 | 收发系统广播 | 操作手机 | B | 高 | ✔ ContextWrapper<br>✔ ContextWrapper |
| S076 | 中断系统广播 | 操作手机 | A | 低 | ✔ BroadcastReceiver |
| S080 | 原始网络包 | 网络信息 | C | 高 | ✔ Socket<br>✔ DatagramSocket |
| S081 | HTTP访问 | 网络信息 | C | 高 | ✔ HttpURLConnection<br>✔ HttpURLConnectionImpl<br>✔ HttpsURLConnectionImpl<br>○ SDK 前缀兜底<br>○ SDK 前缀兜底 |
| S082 | 网络调用 | 网络信息 | C | 高 | ✔ URL<br>✔ URL |
| S083 | 浏览器访问 | 网络信息 | B | 中 | ✔ Context |
| S084 | 读取上网记录 | 网络信息 | B | 中 | ✔ ContentResolver |
| S085 | DNS解析 | 网络信息 | C | 高 | ✔ InetAddress<br>✔ InetAddress |
| S086 | 发敏感词 | 网络信息 | C | 高 | ✔ HttpURLConnection<br>✔ Buffer<br>○ SDK 前缀兜底 |
| S087 | 扫描WiFi列表 | 网络信息 | A | 低 | ✔ WifiManager<br>✔ WifiManager |
| S088 | 改变WiFi状态 | 网络信息 | A | 低 | ✔ WifiManager |
| S089 | 读取WiFi参数 | 网络信息 | B | 中 | ✔ WifiManager |
| S090 | 读取WiFi状态 | 网络信息 | B | 中 | ✔ WifiManager<br>✔ WifiManager |
| S091 | DHCP信息 | 网络信息 | A | 低 | ✔ WifiManager |
| S092 | 改变网络类型 | 网络信息 | A | 低 | ✔ ConnectivityManager<br>✔ ConnectivityManager |
| S093 | 发送邮件 | 网络信息 | B | 中 | ✔ Context |
| S094 | 读取邮件 | 网络信息 | B | 中 | ✔ ContentResolver |
| S095 | 使用蓝牙 | 网络信息 | A | 低 | ✔ BluetoothAdapter<br>✔ BluetoothAdapter |
| S096 | 开启NFC | 网络信息 | A | 低 | ✔ NfcAdapter<br>✔ NfcAdapter |

> 图例：✔ 真机确认存在 ｜ ○ 依赖目标 App 集成的 SDK，按包名前缀动态发现 ｜ ✘ 未解析