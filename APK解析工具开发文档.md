# APK 信息解析工具（aapt 版 GUI）开发文档

> 版本：v12（截至 2026-11-20，对应 GitHub Release `v1.2.0`；仓库根目录可移植 spec 构建产出 `apk_info_aapt.exe` 与 `apk_info_cli.exe`）
> 源码：`apk_tools/apk_info_aapt_gui.py`（GUI）、`apk_info_cli.py`（CLI，复用前者解析核心）
> 作者：han（WorkBuddy 协助开发）

---

## 一、项目简介

这是一款**图形化 APK 分析工具**，核心能力是：把一个 `.apk` 文件拖进窗口，自动解析出

- 文件信息：MD5、大小、路径
- 包基本信息：包名、应用名、版本名/版本码、最低/目标/编译 SDK、入口 Activity、原生代码、支持屏幕等
- **应用图标**：在内容区顶部展示 APK 启动图标（位图）、图标文件 **MD5**、格式/尺寸与来源路径
- 权限与特性：所有 `uses-permission`、特性、uses-library，并附带常见权限的中文说明
- 签名信息：从 META-INF 证书（v1）或 APK Signing Block（v2/v3/v4）中提取 X.509 证书的
  主题、颁发者、序列号、有效期、算法、公钥类型

### 设计取舍：为什么用 aapt 而不是 aapt2 / androguard？
- **aapt**（Android Asset Packaging Tool）有 `aapt dump badging` 这个"一站式"命令，
  一条命令就能吐出包名、版本、权限、启动 Activity、特性等全部信息，且它是 Android
  官方打包/安装器的同源工具，**对损坏、加壳、清单被改写的样本容错极强**。
- **aapt2** 设计定位是"增量资源编译器"，它的 `dump` 子命令只支持
  `resources` / `packages` / `configurations` / `xmltree` 这类底层项，**没有
  `dump badging`**，要拿到同样的信息得重写大量解析逻辑。
- **androguard** 纯 Python、依赖重，对"清单被加固抹掉"的样本经常直接抛异常。
- 权衡之下，本工具选 aapt 做"基本信息"主力，再用 Python + `cryptography` 库独立解析
  签名，**不依赖任何第三方 APK 框架**，因此体积小便携、对恶意/加固样本稳定。

---

## 二、整体技术架构

```
┌──────────────────────────────────────────────────────────┐
│                       Tkinter GUI 层                       │
│   ApkInfoApp  (UI 构建 / 主题字体 / 拖拽 / 复制 / 日志)      │
└───────────┬───────────────────────────┬──────────────────┘
            │ 调用                       │ 调用
            ▼                           ▼
   ┌─────────────────┐         ┌──────────────────────────┐
   │  run_aapt()     │         │  parse_signatures()       │
   │  (subprocess 跑 │         │  (cryptography 解析证书)   │
   │   aapt.exe)     │         └──────────────────────────┘
   └────────┬────────┘                      │
            │ 失败且是 zip 结构损坏          │ 容器内嵌证书扫描
            ▼                               ▼
   ┌─────────────────────────┐    ┌────────────────────────┐
   │ repair_apk_central_dir  │    │ _find_apk_signing_block │
   │ (从 local header 重建)  │    │ + _parse_v2_certs       │
   └─────────────────────────┘    │ + _scan_x509_in_blob    │
                                   └────────────────────────┘
            │
            ▼
   ┌─────────────────────────┐
   │   find_aapt()           │  ← 自动发现本机 aapt.exe
   └─────────────────────────┘
```

**依赖库**
- 标准库：`tkinter`/`ttk`、`subprocess`、`zipfile`、`struct`、`zlib`、`hashlib`、`re`、`ctypes`（仅 Windows 拖拽）
- 第三方：`cryptography`（解析 X.509 / PKCS#7 证书）

---

## 三、核心功能实现原理

### 3.1 aapt 自动发现（`find_aapt`）
程序不要求用户手动配环境，启动时会按下列**优先级**自动找 `aapt.exe`：

1. PyInstaller 打包后（`_MEIPASS` 临时目录）—— 用于 exe 内置 aapt 的场景
2. 脚本**同级目录**下的 `aapt.exe`/`aapt` —— 便于随工具一起分发
3. 环境变量 `AAPT_PATH`
4. `ANDROID_HOME` / `ANDROID_SDK_ROOT` 及常见 SDK 路径下的 `build-tools`（**取版本号最高的**）
5. 系统 `PATH`

> 版本号比较：`vkey()` 把 `"37.0.0"` 拆成 `[37,0,0]` 再排序，保证选中最新 build-tools。

若全部找不到，程序不会崩溃，只是提示"未找到 aapt"，包名/权限等无法解析，但**文件 MD5/签名信息仍可正常解析**（这两块不依赖 aapt）。

---

### 3.2 包基本信息解析（`aapt dump badging` → `parse_badging`）
1. `_aapt_dump_once()` 用 `subprocess.run([aapt, "dump", "badging", target])` 抓标准输出。
2. `parse_badging(text)` 对每一行做**前缀匹配 + 正则提取**：
   - `package:` → 正则 `(\w+)='([^']*)'` 提取 `name`/`versionCode`/`versionName`/`compileSdkVersion`/`platformBuildVersionName`
   - `sdkVersion:` / `targetSdkVersion:` → 最低/目标 SDK
   - `application-label:` → 应用名（只取无语言后缀的基础标签）
   - `launchable-activity:` → 入口 Activity
   - `uses-permission:` / `uses-feature:` / `uses-library:` / `supports-screens:` / `native-code:` / `locales:` 等逐项收集
3. 最后对数组类字段（权限、特性等）做**去重**——aapt 偶尔会重复同一条。

SDK 版本号通过 `SDK_API_NAMES` 字典转成可读名（如 `33 → "13"`、`28 → "9 (Pie)"`）。

---

### 3.3 签名解析（`parse_signatures`）
签名是本项目最复杂、也最折腾的一块。Android 有三种签名方案：

| 方案 | 证书位置 | 说明 |
|------|----------|------|
| v1 | `META-INF/*.RSA/.DSA/.EC` | JAR 签名，证书是 PKCS#7/PEM 或裸 X.509 |
| v2 / v3 / v4 | APK Signing Block（文件尾部） | 全文件签名，证书内嵌在签名块里 |

解析流程：

**① v1（META-INF）**
- `_read_meta_certs()` 用 `zipfile` 读取所有 `META-INF/*.RSA/.DSA/.EC` 的原始字节。
- `_extract(data)` 用**回退链**尝试四种解析方式，命中即返回：
  `PKCS#7(DER)` → `PKCS#7(PEM)` → `裸 X.509(DER)` → `裸 X.509(PEM)`。
- 如果四种都失败，再用 `_scan_asn1()` 在字节里扫描第一个 `0x30 0x82/0x83/0x81`
  开头的 DER `SEQUENCE`，截出来再试一次（兜底加固样本）。

**② v2 / v3（APK Signing Block）**
- `_find_apk_signing_block(raw)`：在文件里 `rfind(b"APK Sig Block 42")` 找到签名块魔数，
  魔数前 8 字节是 size，据此定位整个 block；遍历内部 `(8字节长度 + 4字节 scheme ID + value)`
  段，取出所有 scheme ID。
- 标准 scheme ID 常量（**曾写错过，见第五章**）：
  - `0x7109871a` → v2
  - `0xf05368c0` → v3
  - `0x1b93d61a` → v3.1
  - `0x42726577` → v4
- `_parse_v2_certs(value)`：按"signer（uint32 长度）→ signedData（uint32 长度）→
  跳过 digests → certificates（uint32 长度）→ 逐个证书（uint32 长度）"的层级，
  把内嵌 DER 证书字节抠出来。
- **扫描回退 `_scan_x509_in_blob()`**：不少加固/重打包样本**不遵循标准层级**，
  只是把证书直接塞在块里（NP 管理器也是这么干的），所以 strict 解析失败时会退化为
  在整块 value 里扫描 `0x30 0x82/0x83` 开头的 DER SEQUENCE，尝试解析为 X.509。
- 证书解析成功后 `_append_cert()` 提取主题/颁发者/序列号/有效期/算法/公钥，
  并按 `(主题, 序列号)` 去重，避免重复显示同一张证书。

**证书指纹（MD5 / SHA1 / SHA256）**
- 在 `_append_cert()` 中对每张证书调用
  `cert.fingerprint(hashes.MD5() / SHA1() / SHA256())`（即**对证书 DER 编码取摘要**），
  再格式化为**大写冒号分隔**字符串（如 `9D:7A:DC:D3:...`），与
  `keytool -printcert` / `apksigner verify --print-certs` 展示的"应用签名"指纹完全一致。
- 三个算法各自独立 `try/except`：某一算法因样本证书字段不规范失败，不影响其它算法。
- 三个字段在"证书 #N"卡片中独立成行（等宽字体，**带逐项复制按钮**），
  并纳入顶部"复制全部信息"的输出文本。

---

### 3.4 加固样本 Central Directory 缺失自动修复（`repair_apk_central_dir`）
部分加固/加壳 APK 会**删除 central directory 和 EOCD**（文件尾部索引区），导致 aapt、
zipfile、甚至系统资源管理器都报 "Invalid file" / "no AndroidManifest.xml"。

但**本地文件头（local file header）链通常是完整的**，数据还在。修复算法：
1. 从文件头开始，循环 `data.find(b"PK\x03\x04", off)` 找到所有 local file header。
2. 对每个 header，按 `<IHHHHHIIIHH>` 解包出 flag/method/crc/comp/uncomp/名称长度/附加长度。
3. 数据区边界用"下一个 local header 的位置"界定。
4. CRC/大小优先用 header 原值（非延迟写入且非零）；若被抹掉（flag `0x0008` 延迟写入），
   则**现解压计算**（`zlib.decompressobj(-15)` 处理 deflate 流）。
5. 用收集到的条目**重新生成 central directory + EOCD**，写出临时 `.apk` 返回路径。
6. `run_aapt()` 检测到 aapt 首次因结构损坏失败时，自动用修复后的临时文件重试一次，
   用完即删。

---

### 3.5 拖拽支持（`_install_dragdrop`）
无需任何第三方库，基于 **Windows 原生 `WM_DROPFILES`** 消息：
- 用 `ctypes` 拿到 `shell32.DragQueryFileW / DragFinish / DragAcceptFiles` 和
  `user32.SetWindowLongPtrW / CallWindowProcW`。
- 自写窗口过程 `_wndproc`，收到 `WM_DROPFILES (0x0233)` 时枚举拖入的文件，
  取第一个交给 `callback`（即 `on_drop`）。
- **关键坑**：回调对象必须保活（`_DRAG_KEEPALIVE.append(cb)`），否则被 GC 后
  窗口过程指针变野指针，进程直接崩溃。
- 递归 `_register_drops()` 给所有子控件注册拖拽，保证拖到窗口任意位置都生效。

---

### 3.6 主题 / 字体切换（`_apply_theme` / `_apply_font`）
- 用 `ttk.Style().theme_use("clam")` 作为基底，再用 `s.configure(...)` 统一设置
  深色（`#1e1e1e`）/浅色（`#f2f2f2`）配色。
- 字体族（微软雅黑/等线…）和字号（8~22）通过 Combobox 选择，实时 `configure` 应用到
  所有控件；等宽字体（Consolas）单独应用到"值/日志"类标签和日志框。
- 主题切换按钮文案随之变化（☀ 浅色 / 🌙 深色）。

---

### 3.7 复制功能 & 滚轮滚动
- 每行右侧"复制"按钮、顶部"复制全部信息""复制全部权限"，统一走 `clipboard_append`。
- 内容区是 `Canvas + Scrollbar`，`_bind_mousewheel()` 把鼠标滚轮事件绑定到画布，
  溢出内容可用滚轮滚动（Windows `event.delta` 每格 120）。

---

### 3.8 加固 manifest 容错解析 + arsc 应用名还原（`parse_manifest_axml` / `_resolve_arsc_string`）

**为什么需要这套兜底**：`aapt dump badging` 对"清单被加固改写"的样本经常**中途放弃**——
例如样本 `71F985ADF1C92A2007AB6B8D79543CA0.apk` 的 `AndroidManifest.xml` 被膨胀到 **213MB**、
注入了非法 chunk（type `0x017e/0x017f/0x0180` 等）、字符串池被写成巨型零填充、且
`attributeStart` 字段被写错。aapt 跑到一半抛 `Unknown XML block` /
`failed to read attribute 'android:required'`，只吐出 package/version/sdk，
**应用名、入口 Activity、权限全丢**，返回码还是 1（被当成失败）。

为此新增一套**纯 Python 的二进制 AXML 解析器**作为兜底，挂载在 `run_aapt()` 末尾：
只要 aapt 结果里缺应用名/入口/权限三者之一（或应用名是未解析的 `@0x…` 资源引用），
就直接读 `AndroidManifest.xml` 自己解。

**二进制 AXML 结构（关键常量）**
- 文件头 `0x0003 0x0008 0x00080000`（`type=u16 headerSize=u16 size=u32`），`size` 可能
  被写成天文数字，需 `min(size, len)` 截断。
- chunk 类型：`0x0001` StringPool / `0x0002` ResourceMap / `0x0100` StartNamespace /
  `0x0101` EndNamespace / `0x0102` StartElement / `0x0103` EndElement / `0x0104` CData。
- **元素头 36 字节**；其后的属性数组标准格式为 `<IIIHBBI>`
  （ns, name, rawValue, valueSize, res0, dataType, data = 7 字段），
  属性名 `0x80000000` 高位表示 resource ID（查 `_ATTR_ID_NAMES` 映射表）。
- 属性 `dataType`：`0x03` STRING（引用字符串池）/`0x01` REFERENCE（资源引用）/
  `0x10` INT_DEC / `0x11` INT_HEX / `0x12` INT_BOOL。

**三个容错要点（缺一不可）**
1. **跳过损坏区**：遇到 size 非法或越界时，用 `_scan_next_known()` 扫描到下一个合法
   chunk 起点继续，而不是整体崩溃。
2. **属性起点固定为 `pos+36`**：加固样本把 `attributeStart` 写成 20（标准是 36 之后），
   若按字段值偏移会整体错位；故直接以 `pos+36` 为基准，仅当越界时回退 `pos+astart`。
3. **应用名是资源引用时，从 `resources.arsc` 还原真名**：
   加固样本的 `android:label` 往往是 `REFERENCE` 类型，值形如 `0x7f1000ee`
   （`@0xPPTTEEEE`：PP=包ID, TT=类型ID, EEEE=条目ID）。这时再调 `_resolve_arsc_string()`
   去 `resources.arsc` 里查全局字符串池——**包内嵌套块从 `pstart + headerSize` 开始**
   （不是 `pstart+8`），类型块里 `entryCount` 在 `tp+12`、`entriesStart` 在 `tp+16`
   （不是 `+20/+24`，那会读进 config 区）。

**arsc 字符串池自适应解码（关键坑）**
标准 Android `resources.arsc` 全局字符串池 UTF-8 用 `[u16 字符数][u16 字节数]` 前缀，
但**部分加固/重打包样本压成了 `[u8][u8]` 紧凑前缀**——用标准格式去解会把长度读成
巨大值（如 `0x1708`）、一口气吞掉整段 3MB 数据。新增 `_decode_arsc_string()` 自适应：
先按标准 `u16` 算字节长度，**若该长度明显超出到下一个字符串的间隔（gap），则回退 u8 紧凑格式**，
两种都取不到合理长度时以 gap 为界尽力解码。这样标准 APK 与加固样本都能正确还原应用名。

**验证**：样本 `71F985ADF1C92A2007AB6B8D79543CA0.apk` 经兜底成功解出
- 应用名：**我的世界·极速版**（arsc 还原，原 aapt 只给 `@0x7f1000ee`）
- 入口 Activity：`world.videocouponec.routeshop09.CoreTrackerHolder0e940`
- 权限：**38 项**（含 `CAMERA`、`INTERNET`、各厂商私有权限等）
- 解析耗时约 1~2 秒。普通 APK（多彩、008智选、ＡＩ 等）回归测试应用名均正常，无副作用。

---

### 3.9 应用图标提取与展示（`_extract_apk_icon` / `_render_icon`）

**需求**：在界面"找个空闲位置"展示 APK 的启动图标（矢量图 → 实际是位图 PNG/WebP/JPEG），
并尽可能展示**图标文件的 MD5**。

> 说明：APK 启动图标本质是 **res/drawable*/ 或 res/mipmap*/ 下的位图（PNG/WebP/JPEG）**，
> 并非真正的矢量 SVG；少数现代应用用 `res/mipmap-anydpi-v26/ic_launcher.xml` 自适应矢量图标
> （无法直接以位图渲染）。本工具渲染的是图标位图，并给出其文件 MD5。

**提取来源优先级**（均在 `_extract_apk_icon()` 内，按序尝试，命中即返回）：

1. **aapt `application-icon-<密度>:'res/.../icon.png'`**（最可靠，覆盖绝大多数普通 APK）
   - `parse_badging()` 新增解析这些行，存进 `info["app_icons"]`（密度→路径字典），
     取**密度最高者**作为首选路径；`application:` 行的 `icon='...'` 也一并记录到 `info["icon_ref"]`。
2. **manifest 的 `android:icon` 引用**（aapt 失败时的兜底，由 `parse_manifest_axml()` 捕获）
   - `@drawable/xxx` / `@mipmap/xxx` → 按 `*/drawable|mipmap*/xxx.png` 在 zip 里匹配文件；
   - `@0xPPTTEEEE` 资源引用 → 先经 `_resolve_arsc_drawable_name()` 从 `resources.arsc`
     还原资源名（见 3.8 同款 arsc 解析思路），再按文件名匹配。
3. **自适应 XML 图标跟随**：若 aapt 给出的图标是 `res/BW.xml` 这类 **自适应 XML**，
   读取该 XML 并正则提取内部 `@drawable/...` / `@mipmap/...` 前景引用，作为额外候选。
4. **常见启动图标名兜底扫描（`_scan_launcher_icon`）**：当上述引用都无法解析时
   （加固样本 arsc 解析失败等），直接扫描 zip 全部条目，按 `ic_launcher`/`ic_launcher_round`/
   `app_icon`/`logo`/`icon`/`ic_launcher_foreground` 等常见名挑最佳候选——
   **不依赖 arsc**，纯文件名启发式。

**读取方式（兼容 hjsq 类篡改）**：所有条目读取走 `_read_zip_entry_match()`——
直接扫 **local file header**，按名称匹配后做 `_decode_payload()`（stored 原样返回；
deflate/method 被篡改则 raw inflate；条目数据区间以"下一个 local header"为界，
对 `csize` 声明错误免疫），完全绕开可能被篡改/删除的 central directory。

**展示（`_make_icon_section` + `_render_icon`）**：在内容区顶部新增"应用图标"卡片。
- 图标渲染：优先用 **Pillow**（支持 WebP/JPEG 缩放，需运行环境装了 Pillow）；
  缺失时退回 **tkinter 原生 `PhotoImage`**（仅支持 PNG/GIF，绝大多数启动图标是 PNG 够用）。
- 图像统一缩放到 **96×96** 内（保持纵横比），保活 `PhotoImage` 引用防止被 GC 后图像消失。
- 同步展示 **图标MD5**（对图标字节 `hashlib.md5` 取大写十六进制）、**格式/尺寸**
  （`_image_info` 从字节流识别 PNG/GIF/JPEG/WebP 及其宽高）、**来源路径**。
- 图标 MD5 纳入顶部"复制全部信息"输出。

**已知局限（v9 改进区分）**：
- 自适应 XML 图标（无可用栅格前景）、arsc 解析失败且文件名不在常见名单里的加固样本，
  界面显示"（无图标）"，不影响其它信息解析。
- **资源已加密/加壳的样本**（如 `org.apk`）：其 `resources.arsc` 的 drawable 分支被混淆
  （`ResTable_type` 的 entry 偏移数组被改写，标准 arsc 解析越界失效），且 zip 内大量
  `*.png` 条目解压后是加密乱码、并非合法位图（stored 首字节 `edd3…`、inflate 后为 ASCII
  乱码）。此类样本图标运行时才由壳解密，**静态工具（aapt / apkanalyzer / 本工具）均无法还原**。
  为不与"真 bug"混淆，v9 做了状态区分：
  - `_extract_apk_icon()` 返回 7 元组，末位 `status` ∈ `{'ok','guess','encrypted','none'}`；
  - `status='encrypted'` 时界面显示"**（资源已加密/加壳，无法提取图标）**"并附说明，
    而非笼统的"（无图标）"。
  - 另新增 `_scan_raster_candidates()` 作为最后兜底：扫描全部可解码位图，仅接受
    "正方形 且 边长为标准启动密度尺寸"的强信号候选（避免误把普通图片当图标），命中则
    `status='guess'` 并标注"按图形特征推测"。
- Pillow 已打包进 exe（v8 起），故 WebP/JPEG 也能预览；仅当运行环境缺 Pillow 时退回
  tkinter 原生（仅 PNG/GIF）。

**验证**：
- 普通 APK（`128_17tk_16.apk`、`488c1e_sn.apk` 等）经 aapt 路径直接命中，正常显示 48×48 PNG + MD5。
- 加固样本 `hjsq.apk`（aapt 整段失败、图标藏在 `8/drawable/icon.png` 随机前缀路径下）
  经"常见名兜底扫描"恢复出 **144×144 PNG + MD5**（诱饵的 `8/5/6/.../6/icon.png` 单字符目录
  因父目录名不以 `drawable/mipmap` 开头被正确排除）。
- 加壳样本 `org.apk`（包名 `net.y0swud.xkw33sx3bs`）：arsc 解析越界、34 个图片名条目均不可解码，
  正确返回 `status='encrypted'`，界面给出"资源已加密/加壳"明确提示，无崩溃、不影响其它信息。

---

## 四、代码结构总览

| 模块/函数 | 行数区间 | 职责 |
|-----------|---------|------|
| `find_aapt()` | 62–136 | 自动发现 aapt 路径 |
| `sdk_name()` / `SDK_API_NAMES` | 142–161 | SDK 版本号转可读名 |
| `PERMISSION_DESC` / `perm_desc()` | 167–224 | 常见权限中文说明 |
| `parse_badging()` | 248–320 | 解析 aapt 文本输出 |
| `_scheme_name()` / `_vnum()` | 323–334 | 签名方案 ID 映射 |
| `_find_apk_signing_block()` | 337–365 | 定位 APK 签名块 |
| `_parse_v2_certs()` | 382–438 | 标准 v2/v3 证书提取 |
| `_read_meta_certs()` | 441–466 | 读取 META-INF 证书（含修复兜底） |
| `parse_signatures()` | 486–660 | 签名解析总入口（v1 + v2/v3 + 扫描回退） |
| `_aapt_dump_once()` | 1051–1074 | 单次调用 aapt（隐藏子进程窗口） |
| `repair_apk_central_dir()` | 1090–1184 | 重建 central directory |
| `_decode_axml_string()` | 362–398 | AXML 字符串池解码（UTF-8/UTF-16） |
| `_decode_arsc_string()` | 400–468 | arsc 字符串池**自适应**解码（u16/u8 前缀） |
| `parse_manifest_axml()` | 470–637 | 加固 manifest 容错 AXML 解析（兜底补全） |
| `_resolve_arsc_string()` | 670–715 | 从 `@0x…` 引用查 resources.arsc 还原真名 |
| `_is_raster_magic()` / `_image_info()` | 新增 | 位图格式魔数识别 / 宽高解析 |
| `_read_zip_entry_match()` | 新增 | 扫 local header 按名取条目（兼容篡改） |
| `_resolve_arsc_drawable_name()` | 新增 | `@0x…` 图标引用 → 资源名（arsc） |
| `_extract_apk_icon()` / `_scan_launcher_icon()` | 新增 | 图标提取（aapt→manifest→XML→常见名兜底） |
| `_scan_raster_candidates()` | 新增 | 全量位图扫描兜底（正方形+标准启动尺寸强信号，`guess`） |
| `_make_icon_section()` / `_render_icon()` | 新增 | 图标展示卡片 + 图标MD5/格式/尺寸（按 status 区分提示） |
| `run_aapt()` | 1252–1386 | aapt 解析总入口（含中文路径/加固修复/arsc 兜底） |
| `_install_dragdrop()` | 861–925 | Windows 原生拖拽 |
| `ApkInfoApp` 类 | 931–1564 | GUI 主类（UI/解析/交互/主题/字体/日志） |
| `main()` | 1570–1584 | 程序入口 |

---

## 五、遇到的问题与解决方案

### 问题 1：深色主题下界面"黑屏"/控件错位
**现象**：切换深色主题后，大片内容区域变成纯黑，部分控件位置错乱。
**根因**：
1. `_build_ui()` 被**重复调用**，内容区/日志区被创建了两次，布局冲突。
2. 给 `ttk.LabelFrame` 设置样式时用了错误的样式名 `TLabelFrame`，
   正确名称是 **`TLabelframe`**（首字母大写规则不同），导致样式不生效。

**解决方案**：
- 删除重复构建 UI 的代码，保证只建一次。
- 所有样式名改为 `TLabelframe`、`TLabelframe.Label`，与 ttk 命名规范一致。

---

### 问题 2：证书文件存在但解析失败，却误报"未检测到证书"
**现象**：样本含 `META-INF/RUNKEY.RSA`，但工具显示"未检测到证书"，把证书弄"丢"了。
**根因**：原逻辑只要解析失败就走"无证书"分支，没区分"文件不存在"和"文件存在但解析失败"。

**解决方案**：
- 重构 `_render_signatures()` 的判断层级：
  - 有证书文件**且**解析成功 → 显示证书明细；
  - 有证书文件**但**解析失败 → 明确显示"发现 N 个证书文件但均解析失败"，并列出每个文件
    的失败原因（如"非标准签名块"），**绝不谎称未检测**；
  - 无 META-INF 证书但有 APK Signing Block → 提示"检测到签名块，证书内嵌于签名块"；
  - 两者皆无 → 才提示"可能未签名"。

---

### 问题 3：加固样本 `aasy7b_7284.apk` 跑不出信息（Invalid file）
**现象**：aapt 报 `Invalid file`、`no AndroidManifest.xml found`，且"该 APK 无 META-INF 证书"。
**诊断**：文件头 `PK\x03\x04` 正常，有 **810 个 local file header，但 0 个 central directory、
0 个 EOCD**——典型加固样本抹掉索引区；本样本确实也无 META-INF 证书（"无证书"是真现象，非 bug）。

**解决方案**：
- 新增 `repair_apk_central_dir()`（原理见 3.4），从 local header 重建 central directory + EOCD。
- `run_aapt()` 升级为返回三元组 `(info, err, repaired)`：首次失败且错误含
  `invalid file` / `no androidmanifest.xml` / `not a zip` 等**结构错误**时，自动修复后重试。
- 验证：该样本修复后成功解析出包名、版本、40 项权限、入口 Activity、应用名（"美色"）。

---

### 问题 4：拖入 APK 时弹出 PowerShell / 黑窗口
**现象**：双击运行 exe 后，每次拖入 apk 解析，都会闪出一个控制台/powershell 窗口。
**根因**：exe 本身是 `--windowed`（无控制台），但内部 `_aapt_dump_once()` 调用
`subprocess.run([aapt.exe,...])` 时**未隐藏子进程窗口**，Windows 给 aapt（控制台程序）
开了一个控制台窗口。

**解决方案**：在 `subprocess.run` 加上
```python
if hasattr(subprocess, "CREATE_NO_WINDOW"):
    kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
else:  # 兜底
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE
    kwargs["startupinfo"] = si
```
模块内仅此一处子进程调用（aapt），确认无遗漏。

---

### 问题 5：有签名却显示"该 APK 无 META-INF 证书（可能未签名）"——且签名块被误判"非标准加固"
**现象**：样本 `159_0722100007.apk`（81MB）明明有签名，手机 NP 管理器能看 V2+V3，
本工具却显示"无 META-INF 证书"，签名块还被标成"0x7109871a (非标准…)"。
**诊断**：
1. **scheme ID 常量写错**：原本错误地按 `0x0101`/`0x0102` 当 v1/v2，而真实的
   v2 = `0x7109871a`、v3 = `0xf05368c0`、v4 = `0x42726577`。
2. `_parse_v2_certs()` 只按**标准 signer → signedData → certificates 层级**解析，
   但该样本（以及很多加固/重打包样本）把证书直接内嵌在块里，strict 结构匹配不到。
3. 本样本 META-INF 里**确实没有** `.RSA/.DSA/.EC`（只有垃圾 `.xml/.png`），
   所以 v1 不存在，全靠 v2/v3 块里的证书——之前没解析这块，自然"无证书"。

**解决方案**：
1. 把 `_scheme_name` / `_vnum` / 判断逻辑里的常量修正为真实 V2/V3/V3.1/V4 ID。
2. 新增 `_scan_x509_in_blob(value)` 扫描回退：在签名块 value 中扫描
   `0x30 0x82/0x83` 开头的 DER SEQUENCE，尝试解析为 X.509（与 NP 管理器思路一致）。
3. `parse_signatures()` 对每种方案**先 strict 解析，失败再扫描**，去重后返回。

**验证**：该样本成功提取 1 张证书——
主题 `CN=GunatetoEnterprises, OU=Gunateto Enterprises Ltd, …`、`C=MY`、
序列号 `37ACFE5B`、有效期至 2036-07-19、RSA 2048、SHA256，**与 NP 管理器完全一致**。

---

### 问题 6：加固样本 `71F985ADF1C92A2007AB6B8D79543CA0.apk` 解析不出应用名/入口 Activity
**现象**：用户拖入该 APK，工具只显示包名/版本/SDK，**应用名为空、入口 Activity 空、权限空**。
**诊断**：
1. `aapt dump badging` 对该样本**中途放弃**（加固 manifest 见 3.8）：213MB 的
   `AndroidManifest.xml`、注入非法 chunk、字符串池零填充、`attributeStart` 写错，
   aapt 报 `Unknown XML block` 后只输出基本信息，应用名/入口/权限全丢，RC=1。
2. 应用名即便能解出来，也常是**资源引用** `0x7f1000ee`（`@0x…`）而非真名——aapt 把
   `android:label` 的 REFERENCE 原样吐出，不查 `resources.arsc`。
3. 早期 `_resolve_arsc_string()` 有 **3 处字段错位**：包内嵌套块起点写成 `pstart+8`
   （应为 `pstart+headerSize`）、`entryCount/entriesStart` 写成 `tp+20/tp+24`
   （应为 `tp+12/tp+16`）；且 arsc 字符串池用**标准 u16 前缀**去解，遇加固样本的
   **u8 紧凑前缀**时长度读成巨大值，直接吞掉整段数据。
4. arsc 兜底分支的 `int(_lbl[2:], 16)` 是 **off-by-one**：`@0x` 是 3 个字符，
   `_lbl[2:]` 得到 `x7f1000ee`（`x` 未被剥掉），`int()` 抛 `ValueError` 被静默吞掉，
   导致 arsc 还原根本没执行。

**解决方案**（对应 3.8）：
1. 新增 `parse_manifest_axml()` 容错 AXML 解析器，挂在 `run_aapt()` 末尾兜底补全
   应用名/入口/权限；属性起点固定 `pos+36`、损坏区用 `_scan_next_known()` 跳过。
2. `_resolve_arsc_string()` 修正包嵌套起点与类型块字段偏移；
   新增 `_decode_arsc_string()` **自适应 u16/u8 前缀**解码，避免吞数据。
3. `run_aapt()` 的 `need` 判定把"应用名是 `@0x…` 资源引用"也视为缺失，确保走到 arsc 还原；
   arsc 调用改 `int(_lbl[3:], 16)` 正确剥掉 `@0x`。

**验证**：该样本成功解析出应用名 **我的世界·极速版**、入口 Activity、
**38 项权限**，耗时约 1~2 秒；多款普通 APK 回归测试应用名正常（多彩 / 008智选 / ＡＩ 等）。

---

### 问题 7：Win11 120% 缩放下界面字体模糊
**现象**：用户系统缩放 120%，双击打开程序后界面文字/控件发虚、不清晰。
**根因**：程序未声明 DPI 感知，Windows 在 120% 缩放下对**整个窗口做位图拉伸**
（GDI DPI 虚拟化），把 96 DPI 的渲染结果拉大到 120%，文字自然模糊。
**解决方案**（`apk_info_aapt_gui.py`），双保险：
1. 入口 `main()` 在创建 `tk.Tk()` **之前**调用 `_enable_high_dpi()`：依次尝试
   `SetProcessDpiAwarenessContext(-4)`（每显示器 v2）/ `shcore.SetProcessDpiAwareness(2)`
   （每显示器）/ `SetProcessDPIAware()`（系统级），让进程以**原生分辨率**渲染，文字即刻清晰。
2. 在 `apk_info_aapt_v6.spec` 的 EXE 里内嵌 **高 DPI manifest**
   （`dpiAware=true/pm` + `dpiAwareness=PerMonitorV2,PerMonitor`），从进程启动起即声明感知，
   比运行时调用更彻底。
3. 开启 DPI 感知后，窗口像素 = 设备像素，默认 `780x720` 会比未感知时（被拉伸前）显得更小，
   故在 `ApkInfoApp.__init__` 按缩放比放大窗口：
   `scale = root.winfo_fpixels("1i") / 96.0`（120% → 1.25），几何尺寸与 minsize 乘 `scale`。
   字体**物理大小**由 Tk 按真实 DPI 自动保持（1pt 始终是 1/72 英寸），因此只变清晰、不会变小。

**验证**：重新打包为 `apk_info_aapt_v6.exe`（已校验 MZ 头 + manifest 内嵌）。
用户在 120% 缩放下打开即为原生分辨率清晰渲染；窗口尺寸按 1.25 倍放大保持原有屏幕占比。
（注：sandbox 无法启动 windowed GUI，界面清晰度需用户本机实测。）

### 问题 8：加固样本 `hjsq.apk` 解析失败（AndroidManifest.xml is corrupt / size mismatch）
**现象**：aapt 直接报错退出
`Zip: size mismatch on inflated file (0 vs 23544)` / `ERROR: AndroidManifest.xml is corrupt`，
解析不出任何信息（包名/应用名/入口 Activity/权限全空）。

**根因（两层损坏，叠加反分析诱饵）**：
1. **zip 条目元数据被篡改**：`AndroidManifest.xml` 条目的 `compression method` 字段
   被写成非法值 `12783`（本应是 `8`=deflate），且 `compressed size` 字段被写成 `8240`
   （实际 23544 字节的未压缩 AXML 明文直接内嵌在文件里，即本质是 stored）。
   因此 aapt 与 Python `zipfile` 都拒绝读取（`NotImplementedError: compression method not supported`）。
2. **属性名被清空**：该混淆 APK 把 `uses-permission` / `activity` / `manifest` 等元素的
   `name`、`versionName`、`minSdkVersion` 等**属性名**在字符串池里写成**空串**（长度 0），
   导致按名字取值时 `aname=""`、整条属性被丢弃（属性值本身解码正常）。
3. **大量诱饵条目**：zip 内塞了 `AndroidManifest.xml/xxx`、`/AndroidManifest.xml/xxx`、
   `resources.arsc/xxx` 等垃圾条目，需按**精确名称**匹配才能避开。

**解决方案**（均在 `apk_info_aapt_gui.py`）：
- 新增 `_read_zip_entry_raw()`：绕过 zip 元数据，直接扫 local file header + `zlib` 实 inflate 读取条目。
  - 数据区间优先用条目声明 `csize` 界定；当 `method` 被篡改（≠0/8）且 deflate 失败时，
    回退用声明 `uncomp`（23544）界定，直接拿到完整未压缩 AXML 明文（经 AXML 魔数 `03000800` 校验）。
  - 对 `method` 字段被篡改（如 12783）免疫：除 stored 外一律先试 raw deflate，失败再回退 stored。
- `parse_manifest_axml()` 增强容错：
  - 新增 `_pick_name()`：属性名被清空时，从元素的**字符串类型属性值**里按模式兜底识别
    （权限挑含 `permission` 的字符串；Activity 挑含 `.` 的类名）。
  - 新增 `_pick_manifest_meta()`：manifest 元素无名值时，从无名字符串/整数里恢复
    `versionName`（形如 `x.y.z`）、`minSdk`/`targetSdk`/`compileSdk`（1~99 的整数，最小者作 minSdk）。
  - 属性循环同时收集无名 `str_values` 与 `int_values` 传入 `handle_start`。
- `run_aapt()` 兜底重构：**aapt 整段失败（`info=None`）时也跑 AXML 兜底**，并把 `info` 初始化为
  `_blank_info()`（与 `parse_badging` 同构的空白字典）避免 GUI 缺键 KeyError；恢复成功后把 aapt 原始
  报错降级为温和提示（不再当硬失败）。

**验证**：`hjsq.apk` 完整恢复——应用名 **海角**、入口 `io.dcloud.PandoraEntry`、版本 `3.1.5`、
`minSdk=16 / targetSdk=36`、`37 项权限`；另一混淆样本 `apkfix_*.apk` 也恢复出应用名/入口/40 权限。
普通 APK 回归正常（应用名/入口/权限不受影响，因兜底仅在名字为空时触发）。

---

### 问题 9：应用图标展示 + 图标 MD5（v8 新需求）
**现象/需求**：用户希望在界面展示 APK 启动图标，并尽量展示图标文件的 MD5。

**实现要点**（见 3.9）：
1. `parse_badging()` 新增解析 `application-icon-<密度>:'res/.../icon.png'` 与 `application:` 行的
   `icon='...'`，分别存入 `info["app_icons"]`（密度→路径）与 `info["icon_ref"]`；
   `parse_manifest_axml()` 在解析 `application` 元素时同步捕获 `icon` 属性（加固样本 aapt 失败时的兜底来源）。
2. `_extract_apk_icon()` 按"aapt 图标路径 → manifest `@drawable/@mipmap/@0x` 引用 →
   自适应 XML 前景跟随 → 常见启动图标名扫描兜底"四级优先级提取图标字节。
3. `_read_zip_entry_match()` / `_decode_payload()` 直接扫 local header + zlib 实解压，
   对 hjsq 这类 `csize` 被篡改的条目同样免疫。
4. GUI 在内容区顶部新增"应用图标"卡片，`_render_icon()` 用 Pillow（或 tkinter 原生）渲染
   位图并展示 **图标MD5 / 格式尺寸 / 来源**；该 MD5 纳入"复制全部信息"。

**关键坑**：
- 加固样本把图标藏在前缀路径下（如 `8/drawable/icon.png`），且塞了大量
  `8/5/6/…/6/icon.png` 这类**单字符诱饵目录**。兜底扫描必须要求"父目录名以 `drawable`/`mipmap` 开头"，
  才能选中真图标、排除诱饵。
- 部分 app（如 `17cg.apk`、`6vPro.apk`）的图标是自适应 XML / 纯 WebView 资源，zip 内**根本无栅格启动图标**，
  这类提取不到，界面显示"（无图标）"，属已知局限而非 bug。

**验证**：普通 APK 经 aapt 路径命中；`hjsq.apk` 经常见名兜底恢复出 144×144 PNG + MD5；
`17cg`/`6vPro`/`ff4fc` 等极端加固样本因无可用栅格图标显示"（无图标）"，其余信息解析不受影响。

---

### 问题 10：加壳样本图标提取失败（`org.apk`，v9 修复区分）
**现象**：`org.apk`（包名 `net.y0swud.xkw33sx3bs`）界面"应用图标"区为空，用户反馈"解析不出来图标"。

**根因（并非代码 bug，而是加壳硬限制）**：
1. manifest 的 `android:icon` 为 `@0x7f0c0000`。`resources.arsc` 仅一个 package（0x7f），
   但 drawable(`0x0c`) 类型的 `ResTable_type` 中 entry 偏移数组被改写——`entriesStart=88` 处
   实际是 `ResTable_config`（其 `size` 字段被误读成 entry 偏移，得 `131080`），导致标准 arsc
   解析越界返回 `None`，无法把 `@0x7f0c0000` 还原成资源名。
2. 即使忽略 arsc，zip 内 34 个图片名条目（`*.png`，多位于 `resources.arsc/<随机>/...` 与
   `res/<随机>/...`）解压后**均不是合法位图**：stored 首字节 `edd3…`、inflate 后为 ASCII 乱码。
   说明这些条目是**加壳加密的 payload 伪装成 png**，真正的图标（含全部资源）运行时由壳解密，
   静态分析（aapt / apkanalyzer / 本工具）都无法还原像素。

**修复（v9，改进区分与提示，而非"修好提取"）**：
- `_extract_apk_icon()` 返回值由 6 元组扩为 **7 元组**，末位 `status`：
  `'ok'`（正常命中）/ `'guess'`（按图形特征推测）/ `'encrypted'`（资源加密）/ `'none'`（确无图标）。
- 新增 `_scan_raster_candidates()` 最后兜底：扫描全部可解码位图，仅接受"**正方形 且 边长为
  标准启动密度尺寸**（36/48/72/96/108/144/192/216/432/512）"的强信号候选，命中 `status='guess'`
  并标注"按图形特征推测"，避免误把普通图片当图标。
- `_render_icon()` 据 `status` 给出准确文案：`encrypted` → "**（资源已加密/加壳，无法提取图标）**"
  并附说明；`none` → "（无图标）"。`parse()` 日志同步区分，便于排查。
- 该样本同时验证：除图标外，包名/权限/版本等其它信息解析不受影响。

**结论**：对加壳加密样本，图标无法静态提取是客观限制；v9 的价值是**准确识别并说明原因**，
  避免被误判为解析 bug。要拿到这类图标，需对样本**真机/模拟器运行后抓取**或逆向壳的解密逻辑。

---

### 问题 10：UTF-8 字符串池解码错位致包名/应用名全空（v10）

**现象**：`U-VIP.apk`（路径含中文目录 `特殊APK\`）经工具解析后**包名、应用名、版本、权限全部为空**；
  但 `aapt dump badging` 直接对该路径报 `Illegal byte sequence`（中文路径无法打开）。

**根因（两层）**：

1. **`_decode_axml_string()` 的 UTF-8 分支读错长度字段**。
   Android 的 **UTF-8 字符串池**用 **uleb128 变长** 编码两个长度（u16 字符数、u8 字节数），
   而原代码按**定长 2 字节**读取。对短字符串（如 `package`：u16len=7、u8len=7，各只占 1 字节），
   多读的 1~2 字节使后续所有字符串整体错位——`package` 被读成 `ckage`，元素名 `manifest` 也读错。
   结果是：元素名匹配失败 → `handle_start("manifest")` 永不触发 → 包名等全部落空。
   （UTF-16 池走 `else` 分支、长度本就是 2 字节，此前样本多为 UTF-16 故未暴露。）

2. **应用名混淆**：该样本把 `android:label` 用零宽连接符包裹（`\u200dU\u200d.\u200dV\u200dI\u200dP\u200d`），
   即使解码正确，界面也会显示成一串不可见字符。

**修复**：

- 新增 `_read_uleb128()`，UTF-8 分支改用 uleb128 解析两个长度字段（UTF-16 分支保持 2 字节不变）。
- 新增 `_clean_label()` 剥离零宽连接符 / 方向格式字符（U+200B/200C/200D/FEFF/2060~2064/202A~202E
  等），`ord(ch) not in _INVISIBLE` 比对（注意键是整数码位），让 `U.VIP` 正确显示。
- `_ATTR_ID_NAMES` 补 `0x01010000→package` 等若干资源 ID 作兜底（该样本属性名其实是字符串索引，
  主路径靠字符串解析，补 ID 仅为双保险）。
- 中文路径已由 `run_aapt()` 的 ASCII 临时副本机制覆盖（`tempfile.mkstemp` + `shutil.copy2`），
  无需改动；本例真正卡住的是上面第 1 点的解码 bug。

**验证**：

- `U-VIP.apk` → 包名 `com.crscg.cib1255.rcdezfj`、应用名 `U.VIP`、版本 `1.1.51`(code 12)、
  minSdk 14 / targetSdk 34 / compileSdk 34、入口 `com.speed.client.CCMainActivity`、25 项权限。
- 回归：批量扫描 19 个样本 APK，包名解析 19/19 成功，0 失败；`hjsq.apk` 等 UTF-16 池样本应用名正常。

---

### 问题 11："填充炸弹"manifest 致 GUI 解析卡死（`ag209.apk`，v11）

**现象**：拖入 `ag209.apk`（57MB）后 GUI 长时间无响应（卡死数分钟），无法得出结果。

**定位（分阶段计时）**：`aapt dump badging` 本身仅 1s 且输出正常，
  卡点在 `run_aapt()` 的容错兜底链路——`parse_manifest_axml()` 解析
  `_read_zip_entry_raw()` 取出的 manifest 时超时（>60s）。

**根因**：该样本是反分析构造的"填充炸弹"：
- `AndroidManifest.xml` 压缩后仅 112KB，解压后达 **109MB**（压缩比约 973:1），
  aapt 报错 `ResXMLTree_node data size 0x20202020 extends beyond resource end`。
- 合法 AXML 结构仅在前 **68508 字节**（261 个 chunk：105 START_ELEM + 105 END_ELEM +
  字符串池等，信息完整）；其后是 **109,051,922 字节的 0x20 空格填充**（占 99.9%）。
- 填充区被当作 chunk 读出的 `size=0x20202020`(538MB) `> end`，主循环进入
  `_scan_next_known()`。该函数从 `pos+1` 起**逐字节**扫描剩余 109MB，
  每次做 2 次 `struct.unpack_from`——约 2 亿次 Python 层循环，耗时数十秒~数分钟，
  且发生在 GUI 主线程，直接冻结窗口。

**修复**：
- `_scan_next_known()` 增加 `max_scan=65536`(64KB) 重同步窗口上限：合法 chunk 通常紧跟
  损坏区，64KB 内足以重新同步；超限即判定为尾部填充垃圾，返回 None 让主循环终止。
- `parse_manifest_axml()` 主循环增加迭代上限 `_MAX_STEPS=50000`：正常 manifest chunk 数
  在数千以内，超限即终止并保留已解析信息，防止其他畸形构造反复重同步占用主线程。

**验证**：
- 完整 109MB manifest 解析：`>60s（卡死）→ 0.085s`，信息完整
  （包名 `co.zh9feqyc1.jfg04z`、入口 `vip.zpiln9.nx9lxdale.MainActivity`、
  版本 `6.3.383`、21 项权限；label 为资源引用 `@0x7f0f001e`，由 aapt 还原真实应用名）。
- 全链路计时：compute_file_info 0.17s / run_aapt 1.01s / 图标提取 1.25s（提示 `encrypted`）/ 签名 0.13s。
- 回归：普通样本的合法 chunk 均在 64KB 窗口与 50000 步内完成，行为不变。

---

### 附：技术问答——为什么用 aapt 不用 aapt2
见第一章设计取舍。`aapt2` 没有 `dump badging` 子命令，且 `dump` 输出结构不同，
要拿到包名/权限/启动 Activity 得重写整套解析。选 aapt 不是因为它"旧"，而是因为只有它
有最省事的查包信息命令。

---

## 六、exe 打包说明（PyInstaller）

### 6.1 打包命令
```bat
PyInstaller --onefile --windowed --name apk_info_aapt
  --add-binary "E:/repo/android/Sdk/build-tools/37.0.0/aapt.exe;."
  --add-binary "D:/ProgramData/miniconda3/Library/bin/tcl86t.dll;."
  --add-binary "D:/ProgramData/miniconda3/Library/bin/tk86t.dll;."
  --add-binary "D:/ProgramData/miniconda3/Library/bin/ffi.dll;."
  --add-binary "D:/ProgramData/miniconda3/Library/bin/libbz2.dll;."
  --add-data "D:/ProgramData/miniconda3/Library/lib/tcl8.6;tcl8.6"
  --add-data "D:/ProgramData/miniconda3/Library/lib/tk8.6;tk8.6"
  --hidden-import=cryptography
  --distpath=apk_tools/dist_exe --workpath=apk_tools/build_pkg --specpath=apk_tools
  apk_info_aapt_gui.py
```
- `--onefile` 单文件；`--windowed` 无控制台。
- 必须**手动内嵌** aapt.exe 与 tcl/tk 运行时（见下），否则 exe 在本机以外环境会
  报 `Can't find a usable init.tcl`。
- 脚本顶部已处理打包后路径：
  ```python
  _mp = getattr(sys, "_MEIPASS", None)
  if _mp:
      os.environ.setdefault("TCL_LIBRARY", os.path.join(_mp, "tcl8.6"))
      os.environ.setdefault("TK_LIBRARY", os.path.join(_mp, "tk8.6"))
  ```

### 6.2 打包踩坑实录（重打包必看）
1. **tcl/tk 找不到**：conda 环境下 PyInstaller 默认不打包 tcl/tk DLL，
   必须手动 `--add-binary`（tcl86t.dll/tk86t.dll/ffi.dll/libbz2.dll）+ `--add-data`（tcl8.6/tk8.6）。
2. **旧 exe 被占用 → PermissionError**：若旧 exe 正在运行，覆盖同名文件会
   构建失败（RC=1）。解法：用新文件名（如 `apk_info_aapt_v4`）或新 dist 目录，
   让用户先关掉旧 exe。
3. **spec 复用漏打依赖**：若 spec 已存在，PyInstaller 会复用旧 spec、忽略命令行新参数，
   可能漏打 tcl/tk。重打包前 `rm -f *.spec` 或加 `--clean`。
4. **sandbox 偶发 segfault（0xC0000005 / RC=139）**：本构建环境对 PyInstaller 构建与
   启动 GUI 进程偶发崩溃，用重试循环顶过；验证依赖改查 spec/构建日志
   （grep `tcl86t`/`tk86t`/`tcl8.6`/`tk8.6`）而非启动 exe。

---

## 七、使用说明（快速开始）

1. **源码运行**：
   ```bat
   pip install cryptography
   python apk_info_aapt_gui.py
   ```
   确保本机有 Android SDK build-tools 下的 `aapt.exe`（或设置 `AAPT_PATH` 环境变量）。

2. **exe 运行**：双击 `apk_tools/dist_exe/apk_info_aapt_v8.exe` 即可，
   自带 aapt 与 tcl/tk，无需安装环境。

3. **解析 APK**：把 `.apk` 拖到窗口任意位置，或点"选择 APK 文件"。
   结果区会显示文件信息 / 基本信息 / 签名信息 / 权限，可逐项复制或"复制全部信息"。

4. **界面设置**：右上角可切换字体、字号、深浅主题。

---

## 八、CLI 命令行版（供其它程序调用）

### 8.1 定位与设计

`apk_info_cli.py` / `apk_info_cli.exe` 是同一解析核心的命令行入口，供脚本或其它程序集成。

- **复用而非重写**：CLI 直接 `import apk_info_aapt_gui as core`，调用
  `find_aapt / compute_file_info / run_aapt / parse_signatures / _extract_apk_icon /
  sdk_name / _clean_label` 等函数。GUI 源码零改动，两者解析结果始终一致，无重复维护。
- **import 安全性**：GUI 模块末尾有 `if __name__ == "__main__"` 保护，import 时不会启动窗口。
- **流分离**：stdout 只输出数据，stderr 只输出提示/错误；程序可放心解析 stdout。
- **编码**：启动时强制 `sys.stdout/stderr` 为 UTF-8，中文应用名在管道/重定向下不乱码。
- **打包**：`apk_info_cli.spec` 以 console 模式构建（保证 stdout 可用），内嵌 aapt，
  独立运行无需 Python / SDK。

### 8.2 用法

```bat
apk_info_cli.exe app.apk                                   :: 默认每行「字段=值」
apk_info_cli.exe --fields package,app_label,version_name app.apk
apk_info_cli.exe --json app.apk                            :: 结构化 JSON（推荐程序解析）
apk_info_cli.exe --tsv --out result.tsv a.apk b.apk         :: TSV 写入文件 + 批量
apk_info_cli.exe --list-fields                             :: 列出全部字段
```

参数：

| 参数 | 说明 |
| --- | --- |
| `apks...` | 一个或多个 APK 路径（位置参数） |
| `--json` | 输出 JSON（单 APK 为对象，多 APK 为数组；列表字段保留为数组） |
| `--tsv` | 输出两列 TSV：`字段<TAB>值` |
| `--fields LIST` | 只输出指定字段，逗号分隔 |
| `--list-fields` | 打印全部字段名与中文说明后退出 |
| `--aapt PATH` | 指定 aapt.exe（默认自动查找 / 用 exe 内嵌的） |
| `--out FILE` | 输出写入文件（UTF-8），stdout 保持为空 |
| `--no-icon` / `--no-sign` | 跳过图标提取 / 签名解析（批量提速） |
| `--quiet` | 不向 stderr 输出非致命提示 |

### 8.3 默认输出字段（顺序即输出顺序）

| 字段 | 含义 | 字段 | 含义 |
| --- | --- | --- | --- |
| `file_path` / `file_name` | 路径 / 文件名 | `package` / `app_label` | 包名 / 应用名 |
| `file_md5` | 文件 MD5 | `version_name` / `version_code` | 版本名 / 版本码 |
| `file_size_bytes` / `file_size_mb` | 大小 | `min_sdk` / `target_sdk` | 最低 / 目标 SDK 数值 |
| `min_sdk_name` / `target_sdk_name` | 系统可读名 | `compile_sdk` | 编译 SDK |
| `launchable` | 入口 Activity | `install_location` | 安装位置 |
| `native_code` | ABI（逗号连接） | `supports_screens` | 支持屏幕（逗号连接） |
| `icon_status` | ok/guess/encrypted/missing | `icon_path` / `icon_format` / `icon_size` | 图标路径 / 格式 / 尺寸 |
| `icon_md5` | 图标 MD5 | `sign_schemes` | 签名方案（逗号连接） |
| `sign_count` | 证书数 | `permission_count` / `permissions` | 权限数 / 权限列表 |
| `feature_count` / `features` | 特性数 / 列表 | `certs` | 证书明细（kv/tsv 下展开为 `certN_*` 行） |

多值时：`kv` / `tsv` 模式把列表用逗号连接成单行，证书展开为 `cert1_subject=`、`cert1_sha256=` 等；
`--json` 模式保留原生数组/对象，最适合程序消费。

### 8.4 退出码与错误约定

| 退出码 | 含义 |
| --- | --- |
| `0` | 全部 APK 解析成功 |
| `1` | 部分 APK 失败（成功项照常输出，失败原因见 stderr） |
| `2` | 参数错误 / 文件不存在 / 全部失败 / 无可用 aapt |

典型调用（Python 子进程示例）：

```python
import subprocess, json
r = subprocess.run(["apk_info_cli.exe", "--json", "app.apk"],
                   capture_output=True, text=True, encoding="utf-8")
if r.returncode == 0:
    info = json.loads(r.stdout)
    print(info["package"], info["app_label"])
else:
    print("解析失败:", r.stderr)
```

### 8.5 验证记录（v1.2.0）

- 普通样本：全字段输出正常，包名/应用名/版本/图标MD5/签名/权限齐全。
- 加固样本（central directory 损坏）：自动从本地文件头重建后解析，提示走 stderr。
- 填充炸弹样本 `ag209.apk`（109MB manifest）：约 7 秒完成，不卡死（复用 GUI 版修复）。
- 批量 + 部分失败：成功项输出、失败原因进 stderr、退出码 `1`。
- 打包 exe：内嵌 aapt、`--list-fields` 冒烟通过、中文应用名不乱码。

---

## 九、已知局限与后续可改进

- **v4 签名**：当前只从签名块识别 v4 方案 ID，不校验 v4 依赖的 `.idsig` 文件。
- **证书链**：目前只展示直接解析出的证书，未显式构建"证书链/是否被系统信任"关系。
- **aapt 版本差异**：不同 build-tools 的 `dump badging` 输出格式偶有细微差别，
  极端样本可能需要补充正则。
- **跨平台**：拖拽仅实现 Windows；macOS/Linux 可改用 TkDnD 或文件选择按钮兜底。
- **批量解析**：当前单次单文件，后续可加"批量拖入目录 → 导出 CSV/Excel"。

---

*文档生成时间：2026-07-27；最近更新 2026-11-20（v12，新增 CLI 命令行版）— 基于源码 `apk_info_aapt_gui.py` 与 `apk_info_cli.py` 及开发记录整理。*
