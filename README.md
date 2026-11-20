# APK 信息解析工具 (apk_info_aapt)

一个 Windows 下的图形化 APK 解析工具，基于 `aapt` + 自研二进制解析，可提取：

- 包名 (package)
- 应用名 (label)
- 版本号 / 版本名
- 最低 / 目标 SDK
- 入口 Activity
- 权限列表
- **应用图标**（矢量图展示 + 图标文件 MD5）
- 对加壳/加密/混淆 APK 给出明确的“无法提取”原因提示

## 下载

到 [Releases](../../releases) 页面下载 `apk_info_aapt.exe` 即可直接运行（已内嵌 aapt，无需安装 Android SDK）。

> 首次运行若被系统拦截，属正常 Windows SmartScreen 提示，选择“仍要运行”即可。

## 使用

1. 启动 `apk_info_aapt.exe`
2. 选择或拖入一个 `.apk` 文件
3. 工具会展示解析出的全部信息，并在右上角展示应用图标及其 MD5

## 命令行版 (CLI) — 供其它程序调用

同一个仓库另提供 `apk_info_cli.exe`：解析逻辑与 GUI 版完全一致，但通过命令行调用、
按行输出结果，方便被脚本 / 其它程序集成。同样已内嵌 aapt，独立运行无需 Python 或 SDK。

```powershell
# 默认：每行一个「字段=值」
apk_info_cli.exe app.apk

# 只取需要的字段（最常用）
apk_info_cli.exe --fields package,app_label,version_name,icon_md5 app.apk

# 结构化 JSON（推荐程序解析）
apk_info_cli.exe --json app.apk

# TSV / 写入文件 / 一次处理多个 APK
apk_info_cli.exe --tsv --out result.tsv a.apk b.apk

# 查看全部字段名
apk_info_cli.exe --list-fields
```

约定：

- **stdout 只输出数据**，stderr 只输出提示/错误；程序可放心解析 stdout。
- **退出码**：`0` 全部成功，`1` 部分失败，`2` 参数错误/全部失败/无 aapt。
- 多 APK 时每组前有一行 `### <路径>` 分隔；JSON 模式输出数组。
- 批量提速可加 `--no-icon` / `--no-sign` 跳过较耗时的步骤。
- 完整参数与字段说明见开发文档「CLI 命令行版」章节。

## 本地构建

需要 Windows + Python 3.11，并预先将 `aapt.exe` 放在仓库根目录（已自带）。

```powershell
python -m pip install pyinstaller pillow
pyinstaller apk_info_aapt.spec --noconfirm --clean   # GUI 版
pyinstaller apk_info_cli.spec --noconfirm --clean    # CLI 版
# 产物：dist/apk_info_aapt.exe 与 dist/apk_info_cli.exe
```

`apk_info_aapt.spec` 会自动定位当前 Python 环境下的 `aapt.exe` 与 `tcl/tk`，因此在本机 (miniconda) 与 CI (python.org) 均可构建。

## 自动打包 (CI)

仓库配置了 GitHub Actions（`.github/workflows/build.yml`）：

- 推送 `main` 分支：自动构建并将 exe 作为 artifact 上传（便于验证）。
- 推送 `v*` 标签（如 `v1.0.0`）：自动构建并发布到 GitHub Release。

```powershell
git tag v1.0.0
git push origin v1.0.0
```

## 目录说明

| 文件 | 说明 |
| --- | --- |
| `apk_info_aapt_gui.py` | GUI 版主程序源码（同时是 CLI 版共用的解析核心） |
| `apk_info_cli.py` | CLI 版源码（复用 GUI 解析核心，负责命令行与按行输出） |
| `apk_info_aapt.spec` | GUI 版 PyInstaller 可移植构建配置 |
| `apk_info_cli.spec` | CLI 版 PyInstaller 可移植构建配置 |
| `aapt.exe` | Android Asset Packaging Tool（构建时嵌入两个 exe） |
| `APK解析工具开发文档.md` | 开发文档与问题排查记录 |
| `.github/workflows/build.yml` | 自动构建/发布工作流 |
