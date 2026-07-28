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

## 本地构建

需要 Windows + Python 3.11，并预先将 `aapt.exe` 放在仓库根目录（已自带）。

```powershell
python -m pip install pyinstaller pillow
pyinstaller apk_info_aapt.spec --noconfirm --clean
# 产物：dist/apk_info_aapt.exe
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
| `apk_info_aapt_gui.py` | 主程序源码 |
| `apk_info_aapt.spec` | PyInstaller 可移植构建配置 |
| `aapt.exe` | Android Asset Packaging Tool（构建时嵌入 exe） |
| `APK解析工具开发文档.md` | 开发文档与问题排查记录 |
| `.github/workflows/build.yml` | 自动构建/发布工作流 |
