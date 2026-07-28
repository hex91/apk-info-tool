# -*- coding: utf-8 -*-
"""
APK 信息解析工具 (aapt 版 GUI)
================================

基于 Android 官方 aapt 解析 APK 的包名 / 版本 / 最低·目标系统 / 权限 / 特性等，
再从 META-INF 证书用 cryptography 解析签名信息。
不依赖 androguard，因此对「清单被加壳/破坏」的恶意样本也能稳定出数据
(系统安装器与 aapt 同源，对损坏的 AXML 容错更强)。

特性:
  - 拖入 APK 自动解析 (基于 Windows 原生 WM_DROPFILES, 无需第三方包)
  - 每项信息右侧「复制」按钮, 顶部「复制全部信息」
  - 底部日志区
  - 权限信息可折叠 (默认折叠), 含常见权限中文说明, 支持「复制全部权限」
  - 签名信息 (自 META-INF 证书解析)

运行:
  python apk_info_aapt_gui.py
  (本机需有 Android SDK build-tools 下的 aapt.exe, 工具会自动查找; 也可用
   环境变量 AAPT_PATH 指定, 例如 AAPT_PATH="E:/repo/android/Sdk/build-tools/37.0.0/aapt.exe")
"""

import sys
import os
import re
import io
import struct
import zipfile
import hashlib
import warnings

# 打包后 (PyInstaller onefile): 需显式告知 tkinter 去 _MEIPASS 临时目录
# 找 tcl/tk 运行时库, 否则 Tk() 初始化会报 "Can't find a usable init.tcl"
_mp = getattr(sys, "_MEIPASS", None)
if _mp:
    os.environ.setdefault("TCL_LIBRARY", os.path.join(_mp, "tcl8.6"))
    os.environ.setdefault("TK_LIBRARY", os.path.join(_mp, "tk8.6"))

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# 屏蔽 cryptography 对证书属性长度异常的告警 (某些样本证书字段不规范)
warnings.filterwarnings("ignore", message=".*Attribute.*length.*")

try:
    import ctypes
    from ctypes import windll, wintypes, WINFUNCTYPE, c_void_p, c_longlong, c_int
except Exception:  # pragma: no cover
    ctypes = None

# 图标渲染: 优先用 Pillow (支持 WebP/JPEG 缩放), 缺失时退回 tkinter 原生
# PhotoImage (仅支持 PNG/GIF)。绝大多数启动图标是 PNG, 原生路径即可覆盖。
try:
    from PIL import Image, ImageTk
except Exception:  # pragma: no cover
    Image = None
    ImageTk = None

try:
    from cryptography.hazmat.primitives.serialization import pkcs7 as _pkcs7
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes as _hashes
except Exception:  # pragma: no cover
    _pkcs7 = None
    _x509 = None
    _hashes = None


def _hex(b):
    """字节序列格式化为冒号分隔的大写十六进制 (Android 证书指纹常用形式)。"""
    return ':'.join('%02X' % x for x in b)


# --------------------------------------------------------------------------- #
# 1. aapt 自动发现
# --------------------------------------------------------------------------- #
def find_aapt():
    """返回 aapt 可执行文件路径, 找不到返回 None。

    查找优先级:
      0) PyInstaller 打包后的 _MEIPASS 临时目录 (onefile 模式通过 --add-binary 内置 aapt)
      1) 脚本同级目录下的 aapt(.exe)        —— 便于随工具一起分发
      2) 环境变量 AAPT_PATH
      3) ANDROID_HOME / ANDROID_SDK_ROOT 及常见 SDK 路径下的 build-tools (取最高版本)
      4) 系统 PATH
    """
    import shutil, sys
    here = os.path.dirname(os.path.abspath(__file__))

    # 0) PyInstaller 打包 (onefile) 运行时的临时解压目录, aapt 由此注入
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        for name in ("aapt.exe", "aapt"):
            p = os.path.join(meipass, name)
            if os.path.isfile(p):
                return p

    # 1) 同级目录
    for name in ("aapt.exe", "aapt"):
        p = os.path.join(here, name)
        if os.path.isfile(p):
            return p

    # 2) 环境变量 AAPT_PATH
    env = os.environ.get("AAPT_PATH")
    if env and os.path.isfile(env):
        return env

    # 3) 常见 SDK 路径
    roots = []
    for e in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        v = os.environ.get(e)
        if v and os.path.isdir(v):
            roots.append(v)
    for d in ("E:/repo/android/Sdk", "E:/Android/Sdk",
              "C:/Android/Sdk", "D:/Android/Sdk", "C:/Users/han/AppData/Local/Android/Sdk"):
        if os.path.isdir(d):
            roots.append(d)

    candidates = []
    for r in roots:
        bt = os.path.join(r, "build-tools")
        if not os.path.isdir(bt):
            continue
        for ver in os.listdir(bt):
            p = os.path.join(bt, ver, "aapt.exe")
            if os.path.isfile(p):
                candidates.append((ver, p))
            # 也兼容非 Windows 的 aapt (无后缀)
            p2 = os.path.join(bt, ver, "aapt")
            if os.path.isfile(p2):
                candidates.append((ver, p2))

    if candidates:
        def vkey(v):
            out = []
            for x in v.split("."):
                try:
                    out.append(int(x))
                except ValueError:
                    out.append(0)
            return out
        candidates.sort(key=lambda c: vkey(c[0]))
        return candidates[-1][1]  # 取版本号最高的

    # 4) PATH
    for name in ("aapt.exe", "aapt"):
        found = shutil.which(name)
        if found:
            return found
    return None


# --------------------------------------------------------------------------- #
# 2. SDK 版本号 -> 可读名称
# --------------------------------------------------------------------------- #
SDK_API_NAMES = {
    1: "1.0", 2: "1.1", 3: "1.5 (Cupcake)", 4: "1.6 (Donut)",
    5: "2.0 (Eclair)", 6: "2.0.1", 7: "2.1",
    8: "2.2 (Froyo)", 9: "2.3 (Gingerbread)", 10: "2.3.3",
    11: "3.0 (Honeycomb)", 12: "3.1", 13: "3.2",
    14: "4.0 (ICS)", 15: "4.0.3", 16: "4.1 (JellyBean)",
    17: "4.2", 18: "4.3", 19: "4.4 (KitKat)", 20: "4.4W",
    21: "5.0 (Lollipop)", 22: "5.1", 23: "6.0 (Marshmallow)",
    24: "7.0 (Nougat)", 25: "7.1", 26: "8.0 (Oreo)", 27: "8.1",
    28: "9 (Pie)", 29: "10", 30: "11", 31: "12", 32: "12L",
    33: "13", 34: "14", 35: "15", 36: "16",
}


def sdk_name(api):
    try:
        api = int(api)
    except (TypeError, ValueError):
        return str(api) if api else "未知"
    return "%d (%s)" % (api, SDK_API_NAMES.get(api, "Android %d" % api))


# --------------------------------------------------------------------------- #
# 3. 常见权限中文说明
# --------------------------------------------------------------------------- #
PERMISSION_DESC = {
    "android.permission.INTERNET": "访问网络",
    "android.permission.ACCESS_NETWORK_STATE": "获取网络状态",
    "android.permission.ACCESS_WIFI_STATE": "获取 WiFi 状态",
    "android.permission.CHANGE_NETWORK_STATE": "改变网络状态",
    "android.permission.WAKE_LOCK": "唤醒锁 (保持 CPU 运行)",
    "android.permission.RECEIVE_BOOT_COMPLETED": "开机自启",
    "android.permission.FOREGROUND_SERVICE": "前台服务",
    "android.permission.VIBRATE": "振动",
    "android.permission.CAMERA": "使用摄像头",
    "android.permission.RECORD_AUDIO": "录音",
    "android.permission.READ_EXTERNAL_STORAGE": "读取外部存储",
    "android.permission.WRITE_EXTERNAL_STORAGE": "写入外部存储",
    "android.permission.READ_PHONE_STATE": "读取手机状态/IMEI",
    "android.permission.READ_PRIVILEGED_PHONE_STATE": "读取特权手机状态 (系统级)",
    "android.permission.CALL_PHONE": "直接拨打电话",
    "android.permission.PROCESS_OUTGOING_CALLS": "监听/处理去电",
    "android.permission.MODIFY_PHONE_STATE": "修改手机状态 (系统级)",
    "android.permission.READ_SMS": "读取短信",
    "android.permission.SEND_SMS": "发送短信",
    "android.permission.RECEIVE_SMS": "接收短信",
    "android.permission.RECEIVE_MMS": "接收彩信",
    "android.permission.READ_CONTACTS": "读取联系人",
    "android.permission.WRITE_CONTACTS": "写入联系人",
    "android.permission.GET_ACCOUNTS": "获取账户列表",
    "android.permission.MANAGE_ACCOUNTS": "管理账户 (系统级)",
    "android.permission.AUTHENTICATE_ACCOUNTS": "认证账户",
    "android.permission.READ_SYNC_SETTINGS": "读取同步设置",
    "android.permission.WRITE_SYNC_SETTINGS": "写入同步设置",
    "android.permission.READ_PROFILE": "读取用户资料 (系统级)",
    "android.permission.ACCESS_FINE_LOCATION": "精确位置 (GPS)",
    "android.permission.ACCESS_COARSE_LOCATION": "粗略位置",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "后台位置",
    "android.permission.SYSTEM_ALERT_WINDOW": "悬浮窗 (可覆盖其他应用)",
    "android.permission.REQUEST_INSTALL_PACKAGES": "请求安装未知来源应用",
    "android.permission.WRITE_SECURE_SETTINGS": "写入安全设置 (系统级)",
    "android.permission.CHANGE_CONFIGURATION": "修改系统配置 (系统级)",
    "android.permission.PACKAGE_USAGE_STATS": "使用情况统计 (系统级)",
    "android.permission.BLUETOOTH": "蓝牙",
    "android.permission.BLUETOOTH_ADMIN": "蓝牙管理",
    "android.permission.MODIFY_AUDIO_SETTINGS": "修改音频设置",
    "android.permission.USE_FINGERPRINT": "使用指纹",
    "android.permission.USE_BIOMETRIC": "使用生物识别",
    "android.permission.READ_LOGS": "读取系统日志 (系统级)",
    "android.permission.REORDER_TASKS": "重排任务",
    "android.permission.KILL_BACKGROUND_PROCESSES": "杀死后台进程",
    "android.permission.RECEIVE_USER_PRESENT": "监听屏幕解锁",
    "android.permission.EXPAND_STATUS_BAR": "展开状态栏",
    "android.permission.INSTALL_SHORTCUT": "创建桌面快捷方式",
    "android.permission.ACCESS_NOTIFICATION_POLICY": "免打扰策略 (系统级)",
    "android.permission.REQUEST_DELETE_PACKAGES": "请求卸载应用",
    "android.permission.DISABLE_KEYGUARD": "禁用锁屏",
    "android.permission.WRITE_SETTINGS": "修改系统设置 (需用户授权)",
}


def perm_desc(name):
    return PERMISSION_DESC.get(name, "")


# --------------------------------------------------------------------------- #
# 4. 解析逻辑
# --------------------------------------------------------------------------- #
def compute_file_info(path):
    size = os.path.getsize(path)
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper(), size


def _quoted_list(s):
    return re.findall(r"'([^']*)'", s)


def _quoted_value(s):
    m = re.search(r"'([^']*)'", s)
    return m.group(1) if m else ""


def parse_badging(text):
    info = {
        "package": "", "versionName": "", "versionCode": "",
        "minSdk": "", "targetSdk": "", "compileSdk": "", "platformVersion": "",
        "app_label": "", "launchable": "", "install_location": "",
        "permissions": [], "features": [], "features_notreq": [],
        "libraries": [], "supports_screens": [], "densities": [],
        "native_code": [], "locales": [],
        "app_icons": {}, "icon_ref": "",
    }
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("package:") and False:
            pass
        if line.startswith("package:"):
            for k, v in re.findall(r"(\w+)='([^']*)'", line):
                if k == "name":
                    info["package"] = v
                elif k == "versionCode":
                    info["versionCode"] = v
                elif k == "versionName":
                    info["versionName"] = v
                elif k == "compileSdkVersion":
                    info["compileSdk"] = v
                elif k == "platformBuildVersionName":
                    info["platformVersion"] = v
        elif line.startswith("sdkVersion:"):
            info["minSdk"] = _quoted_value(line)
        elif line.startswith("targetSdkVersion:"):
            info["targetSdk"] = _quoted_value(line)
        elif line.startswith("application-label:") and line[len("application-label:"):].startswith("'"):
            # 仅取无 locale 后缀的基础标签
            info["app_label"] = _quoted_value(line)
        elif line.startswith("launchable-activity:"):
            m = re.search(r"name='([^']*)'", line)
            if m:
                info["launchable"] = m.group(1)
        elif line.startswith("application-icon-"):
            # aapt 为每个密度输出一行: application-icon-160:'res/.../icon.png'
            # 选取密度最高者作为图标来源 (见 _extract_apk_icon)。
            m = re.search(r"^application-icon-(\d+):'([^']*)'", line)
            if m:
                try:
                    info["app_icons"][int(m.group(1))] = m.group(2)
                except ValueError:
                    pass
        elif line.startswith("application:"):
            # application: label='...' icon='@drawable/ic_launcher'
            m = re.search(r"icon='([^']*)'", line)
            if m:
                info["icon_ref"] = m.group(1)
        elif line.startswith("uses-permission:"):
            m = re.search(r"name='([^']*)'", line)
            if m:
                info["permissions"].append(m.group(1))
        elif line.startswith("uses-feature-not-required:"):
            m = re.search(r"name='([^']*)'", line)
            if m:
                info["features_notreq"].append(m.group(1))
        elif line.startswith("uses-feature:"):
            m = re.search(r"name='([^']*)'", line)
            if m:
                info["features"].append(m.group(1))
        elif line.startswith("uses-library"):
            m = re.search(r"name='([^']*)'", line)
            if m:
                info["libraries"].append(m.group(1))
        elif line.startswith("supports-screens:"):
            info["supports_screens"] = _quoted_list(line)
        elif line.startswith("supports-any-density:"):
            info["any_density"] = _quoted_value(line)
        elif line.startswith("densities:"):
            info["densities"] = _quoted_list(line)
        elif line.startswith("native-code:"):
            info["native_code"] = _quoted_list(line)
        elif line.startswith("locales:"):
            info["locales"] = _quoted_list(line)
        elif line.startswith("install-location:"):
            info["install_location"] = _quoted_value(line)
    # 去重 (aapt 偶尔重复)
    for k in ("permissions", "features", "features_notreq", "libraries",
              "supports_screens", "densities", "native_code", "locales"):
        seen = []
        for x in info[k]:
            if x not in seen:
                seen.append(x)
        info[k] = seen
    return info


# --------------------------------------------------------------------------- #
# 2b. 容错 AXML 解析 (AndroidManifest.xml)
# --------------------------------------------------------------------------- #
# 部分加固/混淆 APK 会在二进制 AXML 里注入非法 chunk 类型 (如 0x017e/0x017f/
# 0x0180 等) 或塞入巨型字符串池, 导致 aapt `dump badging` 中途放弃, 只吐出
# 包名/版本/SDK, 应用名、入口 Activity、权限全部丢失。本解析器按 chunk size
# 跳过非法块、按需懒加载字符串, 仍能从剩下的合法节点里取出这些信息。
_CHUNK_STRING_POOL = 0x0001
_CHUNK_RESMAP = 0x0002
_CHUNK_START_NS = 0x0100
_CHUNK_END_NS = 0x0101
_CHUNK_START_ELEM = 0x0102
_CHUNK_END_ELEM = 0x0103
_CHUNK_CDATA = 0x0104
_AXML_KNOWN = {_CHUNK_STRING_POOL, _CHUNK_RESMAP, _CHUNK_START_NS,
               _CHUNK_END_NS, _CHUNK_START_ELEM, _CHUNK_END_ELEM, _CHUNK_CDATA}

# 常用 Android 属性 resource ID -> 名称 (用于解析带高位的属性名)
_ATTR_ID_NAMES = {
    0x01010000: "package",
    0x01010003: "name",
    0x01010001: "versionCode",
    0x0101021b: "label",
    0x0101021c: "icon",
    0x0101021a: "versionCode",
    0x0101021d: "versionName",
    0x0101020c: "minSdkVersion",
    0x01010270: "targetSdkVersion",
    0x010102a3: "maxSdkVersion",
    0x01010572: "compileSdkVersion",
    0x01010573: "compileSdkVersionCodename",
}


def _read_uleb128(raw, p):
    """从 p 处读取一个 uleb128 变长整数, 返回 (value, new_pos)。"""
    result = 0
    shift = 0
    total = len(raw)
    while p < total:
        b = raw[p]
        p += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, p


def _decode_axml_string(raw, p, utf8):
    """从 AXML 字符串池里解码第 p 字节处的字符串 (UTF-8 或 UTF-16)。

    UTF-8 池的长度字段是 uleb128 变长 (u16len 与 u8len 各一个), 不能用定长
    2 字节读取, 否则小长度值会被多读 1~2 字节导致整段错位 (如 'package' 被
    读成 'ckage')。UTF-16 池仍是定长 2 字节, 保持原逻辑。
    """
    total = len(raw)
    if p < 0 or p + 2 > total:
        return ""
    if utf8:
        u16len, p = _read_uleb128(raw, p)
        u8len, p = _read_uleb128(raw, p)
        nbytes = u8len
        if p + nbytes > total:
            nbytes = total - p
        try:
            return raw[p:p + nbytes].decode("utf-8", "replace")
        except Exception:
            return ""
    else:
        len16 = struct.unpack_from("<H", raw, p)[0]
        p += 2
        if len16 & 0x8000:
            len16 = ((len16 & 0x7FFF) << 16) | struct.unpack_from("<H", raw, p)[0]
            p += 2
        nbytes = len16 * 2
        if p + nbytes > total:
            nbytes = total - p
        try:
            return raw[p:p + nbytes].decode("utf-16-le", "replace")
        except Exception:
            return ""


# 零宽/不可见格式字符 (部分加固 APK 会把应用名用这些字符包裹做混淆)
_INVISIBLE = dict.fromkeys(
    c for c in range(0x110000)
    if c in (0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060, 0x2061, 0x2062,
             0x2063, 0x2064, 0x00AD, 0x034F, 0x061C, 0x180E)
    or (0x202A <= c <= 0x202E) or (0x2066 <= c <= 0x2069)
    or (0xE0000 <= c <= 0xE0FFF))


def _clean_label(s):
    """剥离零宽连接符/方向格式字符等不可见字符, 还原被混淆的应用名。

    部分加固/重打包样本会把 label 用 \\u200d 等零宽字符包裹 (如 'U\\u200dV\\u200dI\\u200dP'),
    直接显示会变成一串不可见乱码。这里仅做显示清洗, 不改变其它字段。"""
    if not s:
        return s
    return "".join(ch for ch in s if ord(ch) not in _INVISIBLE).strip()


def _decode_arsc_string(raw, p, utf8, gap):
    """从 resources.arsc 字符串池解码第 p 字节处的字符串。

    arsc 全局字符串池绝大多数是标准 Android 格式 (UTF-8 时用 [u16 字符数][u16
    字节数] 前缀, UTF-16 时用 [u16 长度] 前缀)。但部分加固/重打包样本会把前缀
    压成 [u8][u8] 紧凑格式, 用标准解析会把长度读成巨大值并吞掉整段数据。
    这里自适应: 先按标准格式算字节长度, 若该长度明显超出到下一个字符串的间隔
    (gap), 则回退到 u8 紧凑格式。两种都取不到合理长度时, 以间隔为界尽力解码。
    """
    total = len(raw)
    if p + 2 > total:
        return ""
    if not utf8:
        len16 = struct.unpack_from("<H", raw, p)[0]
        p += 2
        if len16 & 0x8000:
            len16 = ((len16 & 0x7fff) << 16) | struct.unpack_from("<H", raw, p)[0]
            p += 2
        nbytes = len16 * 2
        if p + nbytes > total:
            nbytes = total - p
        try:
            return raw[p:p + nbytes].decode("utf-16-le", "replace")
        except Exception:
            return ""
    # UTF-8: 标准 u16 字符数 + u16 字节数 (高位 0x8000 表示长度 >=0x8000 时用 4 字节)
    def _rd_u16ext(b, q):
        v = struct.unpack_from("<H", b, q)[0]
        if v & 0x8000:
            v = ((v & 0x7fff) << 16) | struct.unpack_from("<H", b, q + 2)[0]
            return v, q + 4
        return v, q + 2
    q = p
    _cc, q = _rd_u16ext(raw, q)
    bc, q = _rd_u16ext(raw, q)
    std_prefix = q - p
    std_ok = (0 < bc <= gap - std_prefix <= gap) and std_prefix <= 8
    if std_ok:
        start = q
        nbytes = bc
    else:
        # 回退到 u8 紧凑格式: [u8 字符数][u8 字节数]
        bc2 = raw[p + 1]
        start = p + 2
        nbytes = bc2 if (0 < bc2 <= gap - 2) else max(0, gap - 2)
    if nbytes <= 0:
        return ""
    if start + nbytes > total:
        nbytes = total - start
    try:
        return raw[start:start + nbytes].decode("utf-8", "replace")
    except Exception:
        return ""


def _scan_next_known(raw, start, end):
    """从 start 起扫描, 跳过损坏区, 找到下一个合法 chunk 的起始偏移。"""
    p = start
    while p + 8 <= end:
        t = struct.unpack_from("<H", raw, p)[0]
        if t in _AXML_KNOWN:
            return p
        s = struct.unpack_from("<I", raw, p + 4)[0]
        if s >= 8 and p + s <= end:
            p += s
        else:
            p += 1
    return None


def _pick_name(attrs, str_values, kind):
    """属性名被混淆成空串时的兜底识别。

    部分加固/混淆 APK 会把 uses-permission / activity 等元素的 'name' 属性名
    在字符串池里写成空串, 导致无法按名字取值。此时从该元素的字符串类型属性值
    中挑选:
      - kind=='permission': 含 'permission' 的字符串 (如 android.permission.CAMERA)
      - kind=='activity'  : 像类名的值 (含 '.' 且非权限引用)
    优先仍用属性名 'name' 取到的值。"""
    v = attrs.get("name", "")
    if v:
        return v
    cands = [x for x in str_values if x and not x.startswith("@0x")]
    if kind == "permission":
        for x in cands:
            if "permission" in x.lower():
                return x
        return cands[0] if cands else ""
    if kind == "activity":
        for x in cands:
            if "." in x and not x.lower().startswith("android.permission"):
                return x
        return cands[0] if cands else ""
    return ""


def _pick_manifest_meta(str_values, int_values):
    """manifest 元素属性名被混淆成空串时的兜底: 从无名值恢复
    versionName / minSdk / targetSdk / compileSdk。
      - versionName: 形如 'x.y.z' 的无名字符串
      - SDK: 1~99 的整数(含以字符串形式存的, 如 '16'), 最小者作 minSdk,
        最大者作 targetSdk/compileSdk(二者常相等)。"""
    import re
    version_name = ""
    for x in str_values:
        xs = x.strip()
        if re.match(r"^\d+(\.\d+){1,3}$", xs):
            version_name = xs
            break
    sdk = []
    for v in int_values:
        try:
            if isinstance(v, int) and 1 <= v <= 99:
                sdk.append(v)
        except Exception:
            pass
    for x in str_values:
        xs = x.strip()
        if xs.isdigit():
            iv = int(xs)
            if 1 <= iv <= 99:
                sdk.append(iv)
    sdk = sorted(set(sdk))
    min_sdk = str(sdk[0]) if sdk else ""
    max_sdk = str(sdk[-1]) if sdk else ""
    return version_name, min_sdk, max_sdk, max_sdk


def parse_manifest_axml(raw):
    """容错解析二进制 AndroidManifest.xml。

    返回 dict, 尽力填充: app_label / launchable / permissions / package /
    versionName / versionCode / minSdk / targetSdk / compileSdk / platformVersion。
    缺失字段为 '' 或 []。遇到非法 chunk 不崩溃, 按 size 跳过或扫描到下一个合法块。
    """
    res = {"app_label": "", "launchable": "", "permissions": [],
           "package": "", "versionName": "", "versionCode": "",
           "minSdk": "", "targetSdk": "", "compileSdk": "", "platformVersion": "",
           "icon_ref": ""}
    if not raw:
        return res
    # 明文 XML 兜底 (极少出现, 但更稳)
    if raw[:5] == b"<?xml" or raw[:8] == b"<manifest":
        return _parse_manifest_text(raw, res)
    if raw[:4] != b"\x03\x00\x08\x00":
        return res
    total = len(raw)
    try:
        _t, _h, size = struct.unpack_from("<HHI", raw, 0)
    except Exception:
        return res
    if size <= 0 or size > total:
        size = total
    pos = _h
    end = min(pos + size, total)

    pool = {"count": 0, "utf8": False, "offtab": 0, "strdata": 0}

    def get_string(idx):
        if idx < 0 or idx >= pool["count"]:
            return ""
        try:
            off = struct.unpack_from("<I", raw, pool["offtab"] + idx * 4)[0]
            return _decode_axml_string(raw, pool["strdata"] + off, pool["utf8"])
        except Exception:
            return ""

    stack = []          # [(name, attrs), ...] 当前未闭合元素栈
    cur_activity = [""]  # 最近未闭合的 activity/activity-alias 的 name
    filter_state = [None]  # 当前 intent-filter 状态 {main, launcher}

    def handle_start(name, attrs, str_values=None, int_values=None):
        if str_values is None:
            str_values = []
        if int_values is None:
            int_values = []
        stack.append((name, attrs))
        if name in ("activity", "activity-alias"):
            cur_activity[0] = _pick_name(attrs, str_values, "activity")
        elif name == "intent-filter":
            filter_state[0] = {"main": False, "launcher": False}
        elif name == "action":
            if attrs.get("name") == "android.intent.action.MAIN" \
                    and filter_state[0] is not None:
                filter_state[0]["main"] = True
        elif name == "category":
            if attrs.get("name") == "android.intent.category.LAUNCHER" \
                    and filter_state[0] is not None:
                filter_state[0]["launcher"] = True
        elif name == "application":
            lbl = attrs.get("label", "")
            if lbl:
                res["app_label"] = _clean_label(lbl)
            ico = attrs.get("icon", "")
            if ico:
                res["icon_ref"] = ico
        elif name == "uses-permission":
            pm = _pick_name(attrs, str_values, "permission")
            if pm:
                res["permissions"].append(pm)
        elif name == "manifest":
            if attrs.get("package"):
                res["package"] = attrs["package"]
            if attrs.get("versionName"):
                res["versionName"] = attrs["versionName"]
            if attrs.get("versionCode"):
                res["versionCode"] = attrs["versionCode"]
            if attrs.get("compileSdkVersion"):
                res["compileSdk"] = attrs["compileSdkVersion"]
            if attrs.get("platformBuildVersionName"):
                res["platformVersion"] = attrs["platformBuildVersionName"]
            # 兜底: 属性名被混淆为空时, 从无名值恢复版本/SDK
            if not res["versionName"] or not res["minSdk"] \
                    or not res["targetSdk"]:
                vn, ms, ts, cs = _pick_manifest_meta(
                    str_values, int_values)
                if not res["versionName"] and vn:
                    res["versionName"] = vn
                if not res["minSdk"] and ms:
                    res["minSdk"] = ms
                if not res["targetSdk"] and ts:
                    res["targetSdk"] = ts
                if not res["compileSdk"] and cs:
                    res["compileSdk"] = cs
        elif name == "uses-sdk":
            if attrs.get("minSdkVersion"):
                res["minSdk"] = attrs["minSdkVersion"]
            if attrs.get("targetSdkVersion"):
                res["targetSdk"] = attrs["targetSdkVersion"]

    def handle_end(name):
        if name == "intent-filter" and filter_state[0] is not None:
            if filter_state[0]["main"] and filter_state[0]["launcher"] \
                    and cur_activity[0] and not res["launchable"]:
                res["launchable"] = cur_activity[0]
            filter_state[0] = None
        if name in ("activity", "activity-alias"):
            cur_activity[0] = ""
        if stack:
            stack.pop()

    while pos + 8 <= end:
        t, h, s = struct.unpack_from("<HHI", raw, pos)
        if s < 8 or pos + s > end:
            nxt = _scan_next_known(raw, pos + 1, end)
            if nxt is None:
                break
            pos = nxt
            continue
        if t == _CHUNK_STRING_POOL:
            try:
                cnt = struct.unpack_from("<I", raw, pos + 8)[0]
                flags = struct.unpack_from("<I", raw, pos + 16)[0]
                str_start = struct.unpack_from("<I", raw, pos + 20)[0]
                pool["count"] = cnt
                pool["utf8"] = bool(flags & 0x100)
                pool["offtab"] = pos + 28
                pool["strdata"] = pos + str_start
            except Exception:
                pass
        elif t == _CHUNK_START_ELEM:
            try:
                _ln, _cm, _ns, name_idx = struct.unpack_from("<IIII", raw, pos + 8)
                astart, asize, acnt, _id, _cl, _st = struct.unpack_from(
                    "<HHHHHH", raw, pos + 24)
                elem_name = get_string(name_idx)
                attrs = {}
                str_values = []   # 属性名为空(被混淆)时的字符串值兜底候选
                int_values = []   # 属性名为空时的整数值兜底候选
                # 属性数组起点: 标准 AOSP 中紧跟在 36 字节元素头之后。
                # 部分加固样本会把 attributeStart 字段写错(如写成 20), 故以固定
                # 偏移 pos+36 为准, 仅当越界时才回退到字段值。
                if asize < 8:
                    asize = 20
                apos = pos + 36
                if apos + acnt * asize > pos + s:
                    apos = pos + astart
                for i in range(acnt):
                    aoff = apos + i * asize
                    a_ns, a_name, a_raw, a_vsize, a_res0, a_dtype, a_data = \
                        struct.unpack_from("<IIIHBBI", raw, aoff)
                    if a_name & 0x80000000:
                        rid = a_name & 0x7fffffff
                        aname = _ATTR_ID_NAMES.get(rid, "attr_0x%08x" % rid)
                    else:
                        aname = get_string(a_name)
                    if a_dtype == 0x03:          # STRING
                        aval = get_string(a_raw)
                        if not aname:
                            str_values.append(aval)
                    elif a_dtype == 0x01:        # REFERENCE
                        aval = "@0x%08x" % a_data
                    elif a_dtype == 0x10:        # INT_DEC
                        aval = str(a_data)
                        if not aname:
                            try:
                                int_values.append(int(a_data))
                            except Exception:
                                pass
                    elif a_dtype == 0x11:        # INT_HEX
                        aval = "0x%x" % a_data
                    elif a_dtype == 0x12:        # INT_BOOL
                        aval = "true" if a_data else "false"
                    else:
                        aval = ""
                    if aname:
                        attrs[aname] = aval
                handle_start(elem_name, attrs, str_values, int_values)
            except Exception:
                pass
        elif t == _CHUNK_END_ELEM:
            try:
                _ln, _cm, _ns, name_idx = struct.unpack_from("<IIII", raw, pos + 8)
                handle_end(get_string(name_idx))
            except Exception:
                pass
        # 其余 (命名空间 / RESMAP / CDATA / 加固注入的非法块) 一律按 size 跳过
        pos += s
    # 权限去重
    seen = []
    for x in res["permissions"]:
        if x and x not in seen:
            seen.append(x)
    res["permissions"] = seen
    return res


def _parse_manifest_text(raw, res):
    """明文 XML 形式的 manifest 兜底解析 (极简正则)。"""
    try:
        txt = raw.decode("utf-8", "replace")
    except Exception:
        return res
    import re
    m = re.search(r"<manifest\b[^>]*\bpackage\s*=\s*[\"']([^\"']+)[\"']", txt)
    if m:
        res["package"] = m.group(1)
    m = re.search(r"android:label\s*=\s*[\"']([^\"']+)[\"']", txt)
    if m:
        res["app_label"] = m.group(1)
    for m in re.finditer(
            r"android:name\s*=\s*[\"']([^\"']+)[\"']", txt):
        nm = m.group(1)
        if nm == "android.intent.action.MAIN":
            # 往前找最近的 activity 名 (粗略: 取该行附近)
            pass
    # 入口 Activity: 匹配带 MAIN/LAUNCHER 的 intent-filter 内的 activity
    act = re.search(
        r"<activity\b[^>]*android:name\s*=\s*[\"']([^\"']+)[\"']", txt)
    if act:
        res["launchable"] = act.group(1)
    for m in re.finditer(
            r"<uses-permission\b[^>]*android:name\s*=\s*[\"']([^\"']+)[\"']",
            txt):
        res["permissions"].append(m.group(1))
    return res


def _resolve_arsc_string(arsc, ref):
    """尽力从 resources.arsc 解析一个 @0xPPTTEEEE 资源引用为字符串。

    支持最常见的 string 资源: value 的 dataType==0x03(STRING) 时, data 为
    全局字符串池下标。找不到/解析失败返回 None。
    """
    import struct
    if not arsc or len(arsc) < 12:
        return None
    try:
        tt, _th, tsize = struct.unpack_from("<HHI", arsc, 0)
        if tt != 0x0002:  # RES_TABLE_TYPE
            return None
        pkg_id = (ref >> 24) & 0xff
        type_id = (ref >> 16) & 0xff
        entry_id = ref & 0xffff
        end = min(tsize, len(arsc))
        pos = 12  # 跳过 table header(8) + packageCount(4)
        global_pool = None
        packages = []
        while pos + 8 <= end:
            t, _h, s = struct.unpack_from("<HHI", arsc, pos)
            if s < 8 or pos + s > end:
                break
            if t == 0x0001 and global_pool is None:  # 全局字符串池
                cnt = struct.unpack_from("<I", arsc, pos + 8)[0]
                flags = struct.unpack_from("<I", arsc, pos + 16)[0]
                ss = struct.unpack_from("<I", arsc, pos + 20)[0]
                global_pool = {"count": cnt, "utf8": bool(flags & 0x100),
                               "offtab": pos + 28, "strdata": pos + ss}
            elif t == 0x0200:  # RES_TABLE_PACKAGE_TYPE
                pid = struct.unpack_from("<I", arsc, pos + 8)[0]
                packages.append((pid, pos))
            pos += s
        if global_pool is None:
            return None

        def pool_get(pool, idx):
            if idx < 0 or idx >= pool["count"]:
                return ""
            offtab = pool["offtab"]
            strdata = pool["strdata"]
            off = struct.unpack_from("<I", arsc, offtab + idx * 4)[0]
            if idx + 1 < pool["count"]:
                nxt = struct.unpack_from("<I", arsc, offtab + (idx + 1) * 4)[0]
                gap = nxt - off
            else:
                gap = len(arsc) - strdata - off
            return _decode_arsc_string(arsc, strdata + off, pool["utf8"], gap)

        for pid, pstart in packages:
            if pid != pkg_id:
                continue
            pend = min(pstart + struct.unpack_from("<I", arsc, pstart + 4)[0],
                       len(arsc))
            # 包内嵌套块 (类型名池 / 键名池 / type spec / type chunk) 紧跟在
            # 包的 header 之后, 起点 = 包起始 + 包头 headerSize, 而非固定 +8。
            phsize = struct.unpack_from("<H", arsc, pstart + 2)[0]
            tp = pstart + phsize
            while tp + 8 <= pend:
                t2, _h2, s2 = struct.unpack_from("<HHI", arsc, tp)
                if s2 < 8 or tp + s2 > pend:
                    break
                if t2 == 0x0201:  # RES_TABLE_TYPE_TYPE
                    tid = struct.unpack_from("<I", arsc, tp + 8)[0]
                    if (tid & 0xff) == type_id:
                        entry_count = struct.unpack_from("<I", arsc, tp + 12)[0]
                        entries_start = struct.unpack_from("<I", arsc, tp + 16)[0]
                        if 0 <= entry_id < entry_count:
                            off_arr = tp + entries_start - entry_count * 4
                            eoff = struct.unpack_from(
                                "<I", arsc, off_arr + entry_id * 4)[0]
                            epos = tp + entries_start + eoff
                            _esz, _eflags, _ekey = struct.unpack_from(
                                "<HHI", arsc, epos)
                            vsize, _vres0, vdtype, vdata = struct.unpack_from(
                                "<HBBI", arsc, epos + 8)
                            if vdtype == 0x03:
                                return pool_get(global_pool, vdata)
                            return None
                        break
                tp += s2
        return None
    except Exception:
        return None


def _scheme_name(sid):
    # Android 标准 APK Signing Block ID (非 0x0101/0x0102 旧假设)
    return {
        0x7109871a: "v2 (APK Signature Scheme v2)",
        0xf05368c0: "v3 (APK Signature Scheme v3)",
        0x1b93d61a: "v3.1 (APK Signature Scheme v3.1)",
        0x42726577: "v4 (APK Signature Scheme v4)",
    }.get(sid, "v? (ID=0x%x)" % sid)


def _vnum(sid):
    return {0x7109871a: 2, 0xf05368c0: 3, 0x1b93d61a: 3, 0x42726577: 4}.get(sid, 0)


def _find_apk_signing_block(raw):
    """定位 APK Signing Block (v2/v3 共用)。

    返回 (scheme_ids: list[int], pairs: bytes) 或 None。
    pairs 是每个 scheme 的 '8字节长度 + 4字节ID + value' 拼接段,
    便于用 _scheme_value 取出某个 scheme 的 value。
    """
    magic = b"APK Sig Block 42"
    idx = raw.rfind(magic)
    if idx == -1:
        return None
    block_end = idx + 16  # 魔数 16 字节
    if idx - 8 < 0:
        return None
    (size,) = struct.unpack("<Q", raw[idx - 8:idx])
    block_start = block_end - 8 - size
    if block_start < 0 or block_start + 8 > len(raw):
        return None
    pairs = raw[block_start + 8:idx]
    scheme_ids = []
    p = 0
    while p + 8 <= len(pairs):
        (plen,) = struct.unpack("<Q", pairs[p:p + 8])
        if plen < 4 or p + 8 + plen > len(pairs):
            break
        sid = struct.unpack("<I", pairs[p + 8:p + 12])[0]
        scheme_ids.append(sid)
        p += 8 + plen
    return scheme_ids, pairs


def _scheme_value(pairs, sid):
    """从 pairs 段取出指定 scheme ID 的 value 字节(不含长度/ID 前缀)。"""
    p = 0
    while p + 8 <= len(pairs):
        (plen,) = struct.unpack("<Q", pairs[p:p + 8])
        if plen < 4:
            break
        cur = struct.unpack("<I", pairs[p + 8:p + 12])[0]
        if cur == sid:
            return pairs[p + 12:p + 8 + plen]
        p += 8 + plen
    return None


def _parse_v2_certs(value):
    """从 v2/v3 scheme value 中提取内嵌的 DER X.509 证书字节列表。

    v2/v3 scheme value 结构:
      sequence of signer (每个 signer 长度前缀 uint32)
        signer:
          length-prefixed signedData
          length-prefixed signatures
          length-prefixed publicKey

    signedData:
      digests      (length-prefixed sequence)
      certificates (length-prefixed sequence of length-prefixed DER certs)
      additionalAttributes (length-prefixed sequence)
    """
    der_list = []
    p = 0
    n = len(value)
    # 外层: 遍历所有 signer
    while p + 4 <= n:
        (signer_len,) = struct.unpack("<I", value[p:p + 4])
        if signer_len == 0 or p + 4 + signer_len > n:
            break
        signer = value[p + 4:p + 4 + signer_len]
        p += 4 + signer_len

        # signer 内部: 先读 signedData 长度
        if len(signer) < 4:
            continue
        (sd_len,) = struct.unpack("<I", signer[0:4])
        if sd_len == 0 or 4 + sd_len > len(signer):
            continue
        sd = signer[4:4 + sd_len]
        sp = 0

        # 跳过 digests
        if sp + 4 > len(sd):
            continue
        (dl,) = struct.unpack("<I", sd[sp:sp + 4])
        sp += 4 + dl
        # 读取 certificates
        if sp + 4 > len(sd):
            continue
        (clen,) = struct.unpack("<I", sd[sp:sp + 4])
        sp += 4
        blob = sd[sp:sp + clen]
        cp = 0
        while cp + 4 <= len(blob):
            (cert_len,) = struct.unpack("<I", blob[cp:cp + 4])
            cp += 4
            if cp + cert_len > len(blob):
                break
            der = blob[cp:cp + cert_len]
            cp += cert_len
            if der:
                der_list.append(der)
    return der_list


def _read_meta_certs(path):
    """返回 {证书文件名: 原始字节}, 处理加固(无 central directory)样本。"""
    def _inner(p):
        out = {}
        with zipfile.ZipFile(p) as z:
            for n in z.namelist():
                if n.startswith("META-INF/") and \
                   n.endswith((".RSA", ".DSA", ".EC")):
                    out[n] = z.read(n)
        return out
    try:
        return _inner(path)
    except Exception:
        pass
    fixed = repair_apk_central_dir(path)
    if fixed is None:
        return {}
    try:
        return _inner(fixed)
    except Exception:
        return {}
    finally:
        try:
            os.remove(fixed)
        except Exception:
            pass


def detect_sign_schemes(path, cert_files):
    """返回签名方案名列表 (v1 来自 META-INF, v2/v3 来自 APK Signing Block)。"""
    schemes = []
    try:
        with open(path, "rb") as f:
            raw = f.read()
        parsed = _find_apk_signing_block(raw)
        if parsed:
            for sid in parsed[0]:
                schemes.append(_scheme_name(sid))
    except Exception:
        pass
    if cert_files:
        schemes.append("v1 (JAR 签名 / META-INF)")
    return schemes or ["签名方案未知"]


def parse_signatures(path):
    """返回 (certs, errors, schemes)。

    certs: 成功解析的证书字典列表
    errors: {来源: 解析失败的简短原因}
    schemes: 检测到的签名方案名列表

    证书来源:
      - v1: META-INF/*.RSA|.DSA|.EC 中的 PKCS#7 / 裸 X509
      - v2/v3: APK Signing Block 内嵌的签名者证书
    """
    if _pkcs7 is None or _x509 is None:
        return [], {}, []
    certs = []
    errors = {}
    seen_serials = set()

    def _extract(data):
        """对一段字节尝试多种解析, 成功返回证书列表, 失败抛出最后一个异常。"""
        last_exc = None
        try:
            return _pkcs7.load_der_pkcs7_certificates(data)
        except Exception as e:
            last_exc = e
        try:
            return _pkcs7.load_pem_pkcs7_certificates(data)
        except Exception as e:
            last_exc = e
        try:
            return [_x509.load_der_x509_certificate(data)]
        except Exception as e:
            last_exc = e
        try:
            return [_x509.load_pem_x509_certificate(data)]
        except Exception as e:
            last_exc = e
        raise last_exc

    def _scan_asn1(data):
        """在大块二进制里找到第一个 SEQUENCE 起始 (0x30 0x82), 截取一段再试。"""
        i = 0
        n = len(data)
        while i < n - 4:
            if data[i] == 0x30 and data[i + 1] in (0x82, 0x83, 0x81):
                if data[i + 1] == 0x82:
                    length = (data[i + 2] << 8) | data[i + 3]
                    end = i + 4 + length
                elif data[i + 1] == 0x83:
                    length = (data[i + 2] << 16) | (data[i + 3] << 8) | data[i + 4]
                    end = i + 5 + length
                else:
                    length = data[i + 2]
                    end = i + 3 + length
                if 0 < length < n:
                    return data[i:end]
            i += 1
        return None

    def _scan_x509_in_blob(blob, min_len=200, max_len=8000):
        """在字节块中扫描内嵌的 DER X.509 证书(不依赖 strict v2/v3 结构)。

        部分加固/重打包样本的签名块并不遵循标准 signer/signedData 层级,
        只是把证书塞在块里; NP 管理器等工具采用扫描方式, 我们也扫描。
        """
        found = []
        p = 0
        n = len(blob)
        while p < n - 4:
            if blob[p] == 0x30 and blob[p + 1] in (0x82, 0x83):
                if blob[p + 1] == 0x82:
                    length = (blob[p + 2] << 8) | blob[p + 3]
                    end = p + 4 + length
                else:
                    length = (blob[p + 2] << 16) | (blob[p + 3] << 8) | blob[p + 4]
                    end = p + 5 + length
                if min_len < length < max_len and end <= n:
                    try:
                        c = _x509.load_der_x509_certificate(blob[p:end])
                        found.append(c)
                        p = end
                        continue
                    except Exception:
                        pass
            p += 1
        return found

    def _append_cert(chain, source):
        for cert in chain:
            try:
                spki = cert.public_key()
                key_type = spki.__class__.__name__
                key_size = getattr(spki, "key_size", None)
                subj = cert.subject.rfc4514_string()
                iss = cert.issuer.rfc4514_string()
                serial = format(cert.serial_number, "X")
                key = (subj, serial)
                if key in seen_serials:
                    continue
                seen_serials.add(key)
                # 证书指纹: Android 标准展示为 MD5/SHA1/SHA256, 即对证书 DER 取摘要,
                # 大写冒号分隔。部分样本证书字段不规范, 单个算法失败不影响其它算法。
                fp_md5 = fp_sha1 = fp_sha256 = ""
                if _hashes is not None:
                    try:
                        fp_md5 = _hex(cert.fingerprint(_hashes.MD5()))
                    except Exception:
                        pass
                    try:
                        fp_sha1 = _hex(cert.fingerprint(_hashes.SHA1()))
                    except Exception:
                        pass
                    try:
                        fp_sha256 = _hex(cert.fingerprint(_hashes.SHA256()))
                    except Exception:
                        pass
                certs.append({
                    "file": source,
                    "subject": subj,
                    "issuer": iss,
                    "serial": serial,
                    "not_before": str(cert.not_valid_before_utc),
                    "not_after": str(cert.not_valid_after_utc),
                    "sig_alg": cert.signature_hash_algorithm.name
                    if cert.signature_hash_algorithm else "未知",
                    "key_type": key_type,
                    "key_size": key_size,
                    "self_signed": (subj == iss),
                    "md5": fp_md5,
                    "sha1": fp_sha1,
                    "sha256": fp_sha256,
                })
            except Exception:
                continue

    # ---- v1: META-INF ----
    schemes = []
    meta = _read_meta_certs(path)
    if meta:
        schemes.append("v1 (JAR 签名 / META-INF)")
    for cf, data in meta.items():
        try:
            chain = _extract(data)
        except Exception as e1:
            seg = _scan_asn1(data)
            if seg is not None:
                try:
                    chain = _extract(seg)
                except Exception:
                    errors[cf] = "非标准签名块 (%d字节): %s" % (
                        len(data), str(e1)[:100])
                    chain = None
            else:
                errors[cf] = "无法识别的签名块 (%d字节): %s" % (
                    len(data), str(e1)[:100])
                chain = None
        if chain:
            _append_cert(chain, cf)

    # ---- v2/v3 及自定义签名块: APK Signing Block ----
    try:
        with open(path, "rb") as f:
            raw = f.read()
        parsed = _find_apk_signing_block(raw)
        if parsed:
            scheme_ids, pairs = parsed
            for sid in scheme_ids:
                if sid in (0x7109871a, 0xf05368c0, 0x1b93d61a, 0x42726577):
                    label = _scheme_name(sid)
                else:
                    label = "签名块方案 0x%x (非标准, 可能为加固/加壳)" % sid
                schemes.append(label)
                val = _scheme_value(pairs, sid)
                if not val:
                    continue
                # 1) 标准 v2/v3 strict 解析
                strict_ders = _parse_v2_certs(val)
                parsed_any = False
                for der in strict_ders:
                    try:
                        c = _x509.load_der_x509_certificate(der)
                    except Exception:
                        continue
                    _append_cert([c], "APK Signing Block (%s)" % label)
                    parsed_any = True
                # 2) 扫描回退: 部分加固/重打包样本把证书直接塞块里,
                #    不遵循 strict 结构, NP 管理器也是扫描找的
                if not parsed_any:
                    scanned = _scan_x509_in_blob(val)
                    if scanned:
                        _append_cert(scanned, "APK Signing Block (%s)" % label)
    except Exception:
        pass

    return certs, errors, schemes


def _aapt_dump_once(aapt_path, target):
    """单次调用 aapt dump badging, 返回 (info_dict_or_None, err_or_None)"""
    import subprocess
    # 隐藏子进程控制台窗口: aapt 是命令行程序, 不设置时 Windows 会为它
    # 弹出一个控制台(你看到的 powershell/黑窗口)。CREATE_NO_WINDOW 在
    # Python 3.7+ 可用; 同时用 startupinfo 兜底, 确保窗口绝不闪出。
    kwargs = dict(
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=120,
    )
    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    else:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE
        kwargs["startupinfo"] = si
    proc = subprocess.run(
        [aapt_path, "dump", "badging", target], **kwargs
    )
    if proc.returncode != 0 and not proc.stdout.strip():
        return None, "aapt 返回错误 (code=%s): %s" % (
            proc.returncode, proc.stderr.strip()[:300])
    return parse_badging(proc.stdout), None


def _is_zip_struct_error(err):
    """判断错误是否由 zip 结构损坏(central directory 缺失/损坏, 或条目尺寸
    声明错乱)引起。后者如 Android 报 'size mismatch on inflated file' /
    'ERROR: AndroidManifest.xml is corrupt' —— 这类需要从 local file header
    重建 central directory(并现算正确 uncompressed_size)后重试。"""
    if not err:
        return False
    e = err.lower()
    return ("invalid file" in e
            or "no androidmanifest.xml" in e
            or "not a zip" in e
            or "badzipfile" in e
            or "error opening archive" in e
            or "invalid offset" in e
            or "is corrupt" in e
            or "size mismatch" in e
            or "inflated file" in e)


def repair_apk_central_dir(src):
    """从 local file headers 重建缺失/损坏的 central directory。

    某些加固/加壳 APK 会删除 central directory 与 EOCD, 导致 aapt、
    zipfile 等标准解析器报 "Invalid file" / "no AndroidManifest.xml"。
    但 local file header 链通常完整, 数据仍在。本函数扫描所有
    PK\\x03\\x04 local header, 重建 central directory + EOCD, 写出一个
    临时 apk 并返回其路径; 失败返回 None。
    """
    import struct, zlib, tempfile, os
    try:
        with open(src, "rb") as f:
            data = f.read()
    except Exception:
        return None
    n = len(data)
    if n < 30 or data[:4] != b"PK\x03\x04":
        return None
    LFH = b"PK\x03\x04"
    entries = []
    off = 0
    while True:
        i = data.find(LFH, off)
        if i == -1:
            break
        if i + 30 > n:
            break
        (sig, ver, flag, method, mt, md, crc, comp, uncomp,
         nlen, elen) = struct.unpack("<IHHHHHIIIHH", data[i:i+30])
        name = data[i+30:i+30+nlen]
        extra = data[i+30+nlen:i+30+nlen+elen]
        data_start = i + 30 + nlen + elen
        next_i = data.find(LFH, data_start)
        data_end = next_i if next_i != -1 else n
        if data_end <= data_start:
            off = i + 4
            continue
        raw = data[data_start:data_end]
        delayed = bool(flag & 0x0008)
        # 优先用 local header 原值(非延迟且非零); 否则现算
        if (not delayed) and crc and uncomp and comp:
            calc_crc, calc_uncomp, calc_comp = crc, uncomp, comp
        else:
            try:
                if method == 0:
                    calc_uncomp = len(raw)
                    calc_crc = zlib.crc32(raw) & 0xffffffff
                elif method == 8:
                    d = zlib.decompressobj(-15)
                    out = d.decompress(raw)
                    out += d.flush()
                    calc_uncomp = len(out)
                    calc_crc = zlib.crc32(out) & 0xffffffff
                else:
                    calc_uncomp = uncomp
                    calc_crc = crc
                calc_comp = data_end - data_start
            except Exception:
                calc_uncomp = uncomp if uncomp else 0
                calc_crc = crc
                calc_comp = data_end - data_start
        entries.append({
            "ver": ver, "flag": flag, "method": method,
            "crc": calc_crc, "comp": calc_comp, "uncomp": calc_uncomp,
            "nlen": nlen, "elen": elen, "name": name, "extra": extra,
            "lfh_off": i, "data_end": data_end,
        })
        off = data_end
    if not entries:
        return None
    local_region = data[: entries[-1]["data_end"]]
    central = b""
    for e in entries:
        nm = e["name"]
        ex = e["extra"]
        central += struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014b50, 20, e["ver"], e["flag"], e["method"],
            0, 0, e["crc"], e["comp"], e["uncomp"],
            len(nm), len(ex), 0, 0, 0, 0, e["lfh_off"])
        central += nm + ex
    cd_offset = len(local_region)
    cd_size = len(central)
    eocd = struct.pack("<IHHHHIIH", 0x06054b50, 0, 0,
                       len(entries), len(entries), cd_size, cd_offset, 0)
    try:
        fd, out_path = tempfile.mkstemp(suffix=".apk", prefix="apkfix_")
        os.close(fd)
        with open(out_path, "wb") as f:
            f.write(local_region)
            f.write(central)
            f.write(eocd)
        return out_path
    except Exception:
        return None


def _blank_info():
    """返回与 parse_badging 同构的空白信息字典, 供 aapt 整段失败时由
    parse_manifest_axml 兜底填充, 避免 GUI 访问缺失键 KeyError。"""
    return {
        "package": "", "versionName": "", "versionCode": "",
        "minSdk": "", "targetSdk": "", "compileSdk": "", "platformVersion": "",
        "app_label": "", "launchable": "", "install_location": "",
        "permissions": [], "features": [], "features_notreq": [],
        "libraries": [], "supports_screens": [], "densities": [],
        "native_code": [], "locales": [], "any_density": "",
        "app_icons": {}, "icon_ref": "",
    }


def _read_zip_entry_raw(path, name):
    """绕过 zip 元数据, 直接扫描 local file header 读取某条目解压后的内容。
    要点:
      - 不依赖声明大小(csize/usize), 用 zlib 实际解压, 对
        'uncompressed_size 声明为 0 / 与实 inflate 不符' 这类损坏免疫;
      - 对 '压缩方法字段被篡改'(如 method=12783 实为 deflate) 也免疫:
        除 stored(method==0) 外, 一律尝试 raw deflate, 失败再回退 stored;
      - 条目名按精确匹配(剥离路径), 规避反分析中大量同前缀诱饵条目
        (如 'AndroidManifest.xml/xxx'、'/AndroidManifest.xml/xxx')。
    返回 bytes; 找不到/解压失败返回 b''。"""
    import struct, zlib
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception:
        return b""
    n = len(data)
    LFH = b"PK\x03\x04"
    target_b = name.encode("utf-8") if isinstance(name, str) else name
    off = 0
    while True:
        i = data.find(LFH, off)
        if i == -1:
            break
        if i + 30 > n:
            break
        (_sig, _ver, flag, method, mt, md, crc, comp, uncomp,
         nlen, elen) = struct.unpack("<IHHHHHIIIHH", data[i:i + 30])
        name_b = data[i + 30:i + 30 + nlen]
        data_start = i + 30 + nlen + elen
        # 数据区间: 优先用条目声明 csize(更精确), 否则回退到下一个 local header
        if 0 < comp <= (n - data_start):
            data_end = data_start + comp
        else:
            nxt = data.find(LFH, data_start)
            data_end = nxt if nxt != -1 else n
        if data_end <= data_start:
            off = i + 4
            continue
        if name_b == target_b:
            # comp 界定的压缩数据; uncomp 界定的是"若实为 stored 时的明文区间"。
            # 该样本 method/comp 字段均被篡改(method=12783, comp=8240),
            # 但数据实为 stored 的 23544 字节 AXML 明文, 故当 deflate 失败时
            # 用 uncomp 区间兜底, 拿到完整未压缩内容。
            cand_comp = (data[data_start:data_start + comp]
                         if 0 < comp <= (n - data_start) else b"")
            cand_uncomp = b""
            if 0 < uncomp <= (n - data_start) and uncomp >= comp:
                cand_uncomp = data[data_start:data_start + uncomp]
            # 1) stored 直接返回
            if method == 0 and cand_comp:
                return cand_comp
            # 2) 尝试 raw deflate (method==8 或 method 被篡改但实为 deflate)
            if cand_comp:
                try:
                    d = zlib.decompressobj(-15)
                    out = d.decompress(cand_comp)
                    out += d.flush()
                    if out:
                        return out
                except Exception:
                    pass
            # 3) 兜底: 若 uncomp 区间看起来是合法未压缩内容(如 AXML 魔数 03000800),
            #    直接返回完整明文; 否则回退到 comp 区间。
            if cand_uncomp and cand_uncomp[:4] == b"\x03\x00\x08\x00":
                return cand_uncomp
            if cand_uncomp:
                return cand_uncomp
            if cand_comp:
                return cand_comp
            return b""
        off = data_end
    return b""


# --------------------------------------------------------------------------- #
# 4b. APK 图标提取
# --------------------------------------------------------------------------- #
# 启动图标通常是 res/drawable*/ 或 res/mipmap*/ 下的 PNG/WebP/JPEG, 部分现代
# 应用用 res/mipmap-anydpi-v26/ic_launcher.xml (自适应矢量, 无法以位图直接渲染)。
# 解析来源优先级:
#   1) aapt `application-icon-<密度>:'res/.../icon.png'` (最可靠, 覆盖绝大多数 APK)
#   2) manifest 的 android:icon:
#        - @drawable/xxx / @mipmap/xxx  -> 按 'res/{drawable|mipmap}*/xxx.png' 匹配
#        - @0xPPTTEEEE 资源引用        -> 经 resources.arsc 还原资源名后再匹配
# 读取时绕过 zip 中央目录, 直接扫 local file header + zlib 实解压 (兼容 hjsq 类
# 元数据被篡改样本); 条目数据区间以"下一个 local header"为界, 对 csize 声明错误
# 免疫。
def _is_raster_magic(b):
    """判断字节流开头是否为常见位图格式 (PNG/GIF/JPEG/WebP)。"""
    if not b or len(b) < 12:
        return False
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return True
    if b[:6] in (b"GIF87a", b"GIF89a"):
        return True
    if b[:3] == b"\xff\xd8\xff":
        return True
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
        return True
    return False


def _decode_payload(method, raw):
    """把 zip 条目原始数据解成"明文/位图"字节。

    - 若本身已是位图魔数 (stored 明文) 直接返回;
    - method==0 (stored) 返回原样;
    - 其它 (deflate 或 method 被篡改实为 deflate) 尝试 raw inflate,
      失败再退回原样 (最坏情况交给上层按魔数判定)。
    """
    if _is_raster_magic(raw):
        return raw
    if method == 0:
        return raw
    try:
        d = zlib.decompressobj(-15)
        out = d.decompress(raw)
        out += d.flush()
        if out:
            return out
    except Exception:
        pass
    return raw


def _read_zip_entry_match(path, matcher):
    """扫描 local file headers, 返回首个名称匹配 matcher 的 (name_str, payload)。

    matcher(name_bytes) -> bool。仅对匹配条目做解压, 不遍历解压全部, 性能可控。
    找不到返回 None。"""
    import zlib
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception:
        return None
    n = len(data)
    LFH = b"PK\x03\x04"
    off = 0
    while True:
        i = data.find(LFH, off)
        if i == -1:
            break
        if i + 30 > n:
            break
        (_sig, _ver, flag, method, mt, md, crc, comp, uncomp,
         nlen, elen) = struct.unpack("<IHHHHHIIIHH", data[i:i + 30])
        name_b = data[i + 30:i + 30 + nlen]
        data_start = i + 30 + nlen + elen
        if 0 < comp <= (n - data_start):
            data_end = data_start + comp
        else:
            nxt = data.find(LFH, data_start)
            data_end = nxt if nxt != -1 else n
        if data_end <= data_start:
            off = i + 4
            continue
        if matcher(name_b):
            raw = data[data_start:data_end]
            payload = _decode_payload(method, raw)
            return name_b.decode("utf-8", "replace"), payload
        off = data_end
    return None


def _image_info(b):
    """从位图字节流识别 (格式名, 宽, 高); 无法识别返回 ('?', 0, 0)。"""
    if not b:
        return ("?", 0, 0)
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        try:
            w, h = struct.unpack(">II", b[16:24])
            return ("PNG", w, h)
        except Exception:
            return ("PNG", 0, 0)
    if b[:6] in (b"GIF87a", b"GIF89a"):
        try:
            w, h = struct.unpack("<HH", b[6:10])
            return ("GIF", w, h)
        except Exception:
            return ("GIF", 0, 0)
    if b[:3] == b"\xff\xd8\xff":
        i = 2
        n = len(b)
        while i + 9 < n:
            if b[i] != 0xFF:
                i += 1
                continue
            m = b[i + 1]
            if m in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
                     0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                try:
                    h, w = struct.unpack(">HH", b[i + 5:i + 9])
                    return ("JPEG", w, h)
                except Exception:
                    break
            if m in (0xD9, 0xDA):
                break
            seg = struct.unpack(">H", b[i + 2:i + 4])[0]
            i += 2 + seg
        return ("JPEG", 0, 0)
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
        fmt = b[12:16]
        try:
            if fmt == b"VP8 ":
                w = struct.unpack("<H", b[26:28])[0] + 1
                h = struct.unpack("<H", b[28:30])[0] + 1
                return ("WebP", w, h)
            if fmt == b"VP8L":
                b0, b1, b2, b3 = b[21], b[22], b[23], b[24]
                w = ((b1 & 0x3F) << 8 | b0) + 1
                h = ((b3 & 0x0F) << 10 | b2 << 2 | (b1 & 0xC0) >> 6) + 1
                return ("WebP", w, h)
            if fmt == b"VP8X":
                w = struct.unpack("<I", b[24:27] + b"\x00")[0] + 1
                h = struct.unpack("<I", b[27:30] + b"\x00")[0] + 1
                return ("WebP", w, h)
        except Exception:
            pass
        return ("WebP", 0, 0)
    return ("?", 0, 0)


def _resolve_arsc_drawable_name(arsc, ref):
    """从 resources.arsc 把 @0xPPTTEEEE 资源引用还原成资源名 (如 'ic_launcher')。

    仅解析最常见的 RES_TABLE_TYPE 结构: 定位目标 package 块, 取其 key 字符串池,
    再在匹配 type_id 的 type chunk 中按 entry_id 取出条目的 key 索引, 映射到名字。
    任何异常一律返回 None (图标解析为尽力而为, 失败不应影响主流程)。"""
    if not arsc or len(arsc) < 12:
        return None
    try:
        tt, _th, tsize = struct.unpack_from("<HHI", arsc, 0)
        if tt != 0x0002:  # RES_TABLE_TYPE
            return None
        pkg_id = (ref >> 24) & 0xff
        type_id = (ref >> 16) & 0xff
        entry_id = ref & 0xffff
        end = min(tsize, len(arsc))
        pos = 12
        pkg = None
        while pos + 8 <= end:
            t, _h, s = struct.unpack_from("<HHI", arsc, pos)
            if s < 8 or pos + s > end:
                break
            if t == 0x0200:  # RES_TABLE_PACKAGE_TYPE
                pid = struct.unpack_from("<I", arsc, pos + 8)[0]
                if pid == pkg_id:
                    pkg = (pos, s)
                    break
            pos += s
        if pkg is None:
            return None
        pstart, psize = pkg
        pend = min(pstart + psize, len(arsc))
        # 包头字段偏移 (相对包起始): id@8, keyStrings@276
        key_strings_off = struct.unpack_from("<I", arsc, pstart + 276)[0]

        def get_pool(pool_off):
            pp = pstart + pool_off
            cnt = struct.unpack_from("<I", arsc, pp + 8)[0]
            flags = struct.unpack_from("<I", arsc, pp + 16)[0]
            ss = struct.unpack_from("<I", arsc, pp + 20)[0]
            return {"count": cnt, "utf8": bool(flags & 0x100),
                    "offtab": pp + 28, "strdata": pp + ss}

        key_pool = get_pool(key_strings_off)

        def pool_get(pool, idx):
            if idx < 0 or idx >= pool["count"]:
                return ""
            offtab = pool["offtab"]
            strdata = pool["strdata"]
            off = struct.unpack_from("<I", arsc, offtab + idx * 4)[0]
            if idx + 1 < pool["count"]:
                nxt = struct.unpack_from("<I", arsc, offtab + (idx + 1) * 4)[0]
                gap = nxt - off
            else:
                gap = len(arsc) - strdata - off
            return _decode_arsc_string(arsc, strdata + off, pool["utf8"], gap)

        # 包内嵌套块起点 = 包起始 + 包头 headerSize
        phsize = struct.unpack_from("<H", arsc, pstart + 2)[0]
        tp = pstart + phsize
        while tp + 8 <= pend:
            t2, _h2, s2 = struct.unpack_from("<HHI", arsc, tp)
            if s2 < 8 or tp + s2 > pend:
                break
            if t2 == 0x0201:  # RES_TABLE_TYPE_TYPE
                tid = struct.unpack_from("<I", arsc, tp + 8)[0] & 0xff
                if tid == type_id:
                    entry_count = struct.unpack_from("<I", arsc, tp + 12)[0]
                    entries_start = struct.unpack_from("<I", arsc, tp + 16)[0]
                    if 0 <= entry_id < entry_count:
                        base = tp + entries_start
                        eoff = struct.unpack_from("<I", arsc, base + entry_id * 4)[0]
                        if eoff == 0xffffffff:  # 该 entry 不存在
                            break
                        epos = base + eoff
                        if epos + 8 > len(arsc):
                            break
                        _esz, _eflags = struct.unpack_from("<HH", arsc, epos)
                        key_idx = struct.unpack_from("<I", arsc, epos + 4)[0]
                        name = pool_get(key_pool, key_idx)
                        return name
                    break
            tp += s2
        return None
    except Exception:
        return None


def _extract_apk_icon(apk_path, info):
    """提取 APK 启动图标, 返回 (bytes, md5_upper, entry_path, fmt, w, h, status)。

    status: 'ok'          已找到并解出图标位图;
            'guess'       资源名/arsc 均失效, 仅按"正方形+标准密度尺寸"几何特征
                          从可解码位图中猜测的候选 (仅供参考);
            'encrypted'   存在大量图片名条目但无一能解出合法位图 —— 资源被加壳加密,
                          图标运行时才解密, 静态工具无法还原;
            'none'        APK 中没有任何图片条目 (确无图标)。
    找不到/解析失败返回 (None, None, None, None, None, None, status)。
    info: aapt badging 字典 (可能含 app_icons / icon_ref); 缺失时回退解析 manifest。
    """
    def ref_to_name(ref):
        if not ref:
            return None
        if ref.startswith("@drawable/") or ref.startswith("@mipmap/"):
            return ref.split("/", 1)[1]
        if ref.startswith("@0x"):
            try:
                arsc = _read_zip_entry_raw(apk_path, "resources.arsc")
                if arsc:
                    return _resolve_arsc_drawable_name(
                        arsc, int(ref[3:], 16))
            except Exception:
                pass
        return None

    # ---- 收集候选资源名 (来自 @drawable/@mipmap/@0x 解析) ----
    names = []
    ref = (info.get("icon_ref") or "")
    n0 = ref_to_name(ref)
    if n0:
        names.append(n0)

    # aapt 失败时 (info 来自 _blank_info) 没有 icon_ref, 再从 manifest 兜底
    if not names and not info.get("app_icons"):
        try:
            mraw = _read_zip_entry_raw(apk_path, "AndroidManifest.xml")
            if mraw:
                fb = parse_manifest_axml(mraw)
                n0 = ref_to_name(fb.get("icon_ref") or "")
                if n0:
                    names.append(n0)
        except Exception:
            pass

    # aapt application-icon 最高密度路径 (可能是 .png, 也可能是自适应 .xml)
    icons = info.get("app_icons") or {}
    best_path = icons[max(icons.keys())] if icons else None

    # 自适应 XML 图标: 解析内部 @drawable/@mipmap 前景引用作为额外候选
    xml_paths = set()
    if best_path and best_path.lower().endswith(".xml"):
        xml_paths.add(best_path)
    if ref.lower().endswith(".xml"):
        xml_paths.add(ref)
    for xp in xml_paths:
        entry = _read_zip_entry_match(
            apk_path, lambda nb, xp=xp: nb == xp.encode("utf-8", "replace"))
        if entry:
            try:
                txt = entry[1].decode("utf-8", "replace")
                for m in re.finditer(r"@(?:drawable|mipmap)/([\w.\-]+)", txt):
                    names.append(m.group(1))
            except Exception:
                pass

    # ---- 构建匹配器 (按优先级) ----
    candidates = []
    if best_path:
        candidates.append(
            (lambda nb, p=best_path: nb == p.encode("utf-8", "replace"),
             "aapt:%s" % best_path))
    for nm in names:
        pat = re.compile(
            r"(?:drawable|mipmap)[^/]*/%s\.(?:png|webp|jpg|jpeg)$"
            % re.escape(nm), re.I)
        candidates.append(
            (lambda nb, pat=pat: bool(
                pat.search(nb.decode("utf-8", "replace"))),
             "name:%s" % nm))

    for matcher, desc in candidates:
        res = _read_zip_entry_match(apk_path, matcher)
        if res and _is_raster_magic(res[1]):
            icon_bytes = res[1]
            md5 = hashlib.md5(icon_bytes).hexdigest().upper()
            fmt, w, h = _image_info(icon_bytes)
            return icon_bytes, md5, res[0], fmt, w, h, "ok"

    # ---- 兜底 A: 按常见启动图标文件名扫描 drawable/mipmap (不依赖 arsc) ----
    scan = _scan_launcher_icon(apk_path)
    if scan and _is_raster_magic(scan[1]):
        icon_bytes = scan[1]
        md5 = hashlib.md5(icon_bytes).hexdigest().upper()
        fmt, w, h = _image_info(icon_bytes)
        return icon_bytes, md5, scan[0], fmt, w, h, "ok"

    # ---- 兜底 B: 资源名/arsc 都失效时, 扫描全部可解码位图, 仅接受"正方形 +
    #            标准启动密度尺寸"的强信号候选 (避免误把普通图片当图标); 同时统计
    #            图片名条目数, 用于区分"资源加密"与"确无图标"。 ----
    rc = _scan_raster_candidates(apk_path)
    best_name, best_payload, img_named, valid_count = rc
    if best_payload is not None and _is_raster_magic(best_payload):
        icon_bytes = best_payload
        md5 = hashlib.md5(icon_bytes).hexdigest().upper()
        fmt, w, h = _image_info(icon_bytes)
        return icon_bytes, md5, best_name.decode("utf-8", "replace"), fmt, w, h, "guess"

    # 没有可解码位图: 若 APK 中存在图片名条目却被全部加密/混淆, 判定为加密。
    status = "encrypted" if img_named > 0 else "none"
    return None, None, None, None, None, None, status


def _scan_launcher_icon(apk_path):
    """扫描全部 drawable/mipmap 位图条目, 按常见启动图标名挑出最佳候选。

    当 aapt/manifest 给出的图标引用无法解析 (如 @0x 资源在加固样本中解析失败,
    或自适应 XML 无可用栅格) 时, 作为最后兜底。不依赖 arsc, 直接按文件名启发式
    匹配 ic_launcher / app_icon / logo / icon 等。返回 (name_bytes, payload) 或 None。
    """
    PRIORITY = ["ic_launcher_round", "ic_launcher", "launcher",
                "app_icon", "logo", "icon", "ic_launcher_foreground"]
    DENS = {"xxxhdpi": 6, "xxhdpi": 5, "xhdpi": 4, "hdpi": 3,
            "tvdpi": 2, "mdpi": 1, "ldpi": 0, "anydpi": -1}
    # 不强制 'res/' 前缀: 部分加固样本把图标藏在 '8/drawable/icon.png' 这类
    # 带随机前缀的路径下; 只要求"父目录"是 drawable/mipmap(含 -hdpi 等后缀),
    # 以此排除 '.../6/icon.png' 这类单字符诱饵目录。
    pat = re.compile(
        r"(?:^|/)([^/]+)/([\w.\-]+)\.(png|webp|jpg|jpeg)$", re.I)
    try:
        with open(apk_path, "rb") as f:
            data = f.read()
    except Exception:
        return None
    n = len(data)
    LFH = b"PK\x03\x04"
    off = 0
    best = None  # ((score, fscore, dscore), name_b, payload)
    while True:
        i = data.find(LFH, off)
        if i == -1:
            break
        if i + 30 > n:
            break
        (_sig, _ver, flag, method, mt, md, crc, comp, uncomp,
         nlen, elen) = struct.unpack("<IHHHHHIIIHH", data[i:i + 30])
        name_b = data[i + 30:i + 30 + nlen]
        data_start = i + 30 + nlen + elen
        if 0 < comp <= (n - data_start):
            data_end = data_start + comp
        else:
            nxt = data.find(LFH, data_start)
            data_end = nxt if nxt != -1 else n
        if data_end <= data_start:
            off = i + 4
            continue
        nm = name_b.decode("utf-8", "replace")
        m = pat.search(nm)
        if m:
            parent = m.group(1).lower()
            if not (parent.startswith("drawable")
                    or parent.startswith("mipmap")):
                off = data_end
                continue
            base = m.group(2).lower()
            if base in PRIORITY:
                score = PRIORITY.index(base)
                folder = 1 if parent.startswith("mipmap") else 0
                dm = re.search(
                    r"-(xxxhdpi|xxhdpi|xhdpi|hdpi|tvdpi|mdpi|ldpi|anydpi)",
                    parent)
                dscore = DENS.get(dm.group(1), 1) if dm else 1
                key = (score, folder, dscore)
                if best is None or key < best[0]:
                    payload = _decode_payload(method, data[data_start:data_end])
                    best = (key, name_b, payload)
        off = data_end
    if best and _is_raster_magic(best[2]):
        return best[1], best[2]
    return None


def _scan_raster_candidates(apk_path):
    """扫描全部位图条目, 返回 (best_name_bytes, best_payload, img_named, valid_count)。

    仅接受"正方形 且 边长为标准启动密度尺寸(36/48/72/96/108/144/192/216/432/512)"
    的强信号候选, 避免把普通图片误判为启动图标。找不到返回 (None, None, img_named, 0)。

    img_named : 文件名像图片的条目数 (用于判断"资源加密" vs "确无图标");
    valid_count: 实际能解出合法位图(尺寸合理)的条目数。
    """
    STD = {36, 48, 72, 96, 108, 144, 192, 216, 432, 512}
    try:
        with open(apk_path, "rb") as f:
            data = f.read()
    except Exception:
        return (None, None, 0, 0)
    n = len(data)
    LFH = b"PK\x03\x04"
    off = 0
    img_named = 0
    valid_count = 0
    best = None  # (key, name_b, payload)
    while True:
        i = data.find(LFH, off)
        if i == -1:
            break
        if i + 30 > n:
            break
        (_sig, _ver, flag, method, mt, md, crc, comp, uncomp,
         nlen, elen) = struct.unpack("<IHHHHHIIIHH", data[i:i + 30])
        name_b = data[i + 30:i + 30 + nlen]
        data_start = i + 30 + nlen + elen
        if 0 < comp <= (n - data_start):
            data_end = data_start + comp
        else:
            nxt = data.find(LFH, data_start)
            data_end = nxt if nxt != -1 else n
        if data_end <= data_start:
            off = i + 4
            continue
        nm = name_b.decode("utf-8", "replace")
        if re.search(r"\.(png|webp|jpg|jpeg|gif)$", nm, re.I):
            img_named += 1
            raw = data[data_start:data_end]
            payload = _decode_payload(method, raw)
            if _is_raster_magic(payload):
                fmt, w, h = _image_info(payload)
                if fmt != "?" and 1 <= w <= 2000 and 1 <= h <= 2000:
                    valid_count += 1
                    # 仅强信号: 正方形 + 标准启动尺寸
                    if w == h and w in STD:
                        png_bonus = 1 if fmt == "PNG" else 0
                        key = (-png_bonus, -w)  # PNG 优先, 大优先
                        if best is None or key < best[0]:
                            best = (key, name_b, payload)
        off = data_end
    if best is not None:
        return (best[1], best[2], img_named, valid_count)
    return (None, None, img_named, valid_count)


def run_aapt(aapt_path, apk_path):
    """返回 (badging_info_dict, error_or_None, repaired_flag)

    注意: aapt.exe 以 ANSI 命令行读取参数, 路径含非 ASCII(如中文)时
    会找不到文件导致基本信息全部解析为空。此时先把 APK 复制到不含
    非 ASCII 的临时路径再解析, 用完即删。

    当 aapt 因 zip 结构损坏(central directory 缺失/损坏, 常见于加固
    样本)而失败时, 会自动从 local file headers 重建 central directory
    后重试一次。
    """
    import tempfile, shutil, os
    target = apk_path
    tmp_paths = []
    repaired = False
    fixed = None
    # 1) 中文/非 ASCII 路径 -> 复制到 ASCII 临时路径
    if any(ord(c) > 127 for c in apk_path):
        for d in (tempfile.gettempdir(), "C:/Windows/Temp", None):
            if d is None:
                break
            if any(ord(c) > 127 for c in d):
                continue
            try:
                fd, tmp_path = tempfile.mkstemp(suffix=".apk", dir=d)
                os.close(fd)
                shutil.copy2(apk_path, tmp_path)
                target = tmp_path
                tmp_paths.append(tmp_path)
                break
            except Exception:
                continue
    try:
        # 2) 首次尝试
        info, err = _aapt_dump_once(aapt_path, target)
        # 3) 结构损坏 -> 重建 central directory 重试
        if info is None and _is_zip_struct_error(err):
            fixed = repair_apk_central_dir(target)
            if fixed:
                tmp_paths.append(fixed)
                repaired = True
                info, err = _aapt_dump_once(aapt_path, fixed)
                if info is None and err:
                    err = "%s (已从本地文件头重建 central directory, 仍失败)" % err
        # 4) 兜底: 无论 aapt 成功与否, 都尝试用容错 AXML 解析补全/重建基本信息。
        #    覆盖两类失败:
        #      a) 加固/混淆 manifest 致 dump badging 截断 (信息缺失);
        #      b) zip 条目尺寸声明损坏(如 'size mismatch on inflated file' /
        #         'AndroidManifest.xml is corrupt')致 aapt 整段失败(info 为 None)。
        #    读取 manifest 时绕过 zip 元数据, 直接扫 local header + zlib 实 inflate,
        #    对 uncompressed_size 声明错乱的损坏免疫; 读不到再退回标准 zipfile。
        _fb_target = fixed if (repaired and fixed) else target
        try:
            _manifest_raw = _read_zip_entry_raw(_fb_target, "AndroidManifest.xml")
        except Exception:
            _manifest_raw = b""
        if not _manifest_raw:
            try:
                import zipfile as _zf
                with _zf.ZipFile(_fb_target) as _z:
                    if "AndroidManifest.xml" in _z.namelist():
                        _manifest_raw = _z.read("AndroidManifest.xml")
            except Exception:
                _manifest_raw = b""
        if _manifest_raw:
            try:
                _fb = parse_manifest_axml(_manifest_raw)
                if info is None:
                    # aapt 整段失败 -> 用 AXML 兜底重建基本信息
                    info = _blank_info()
                # 应用名若为 @0x... 资源引用, 视为缺失 (需再从 resources.arsc 还原真名)
                _lbl_missing = (not info.get("app_label")
                                or (isinstance(info.get("app_label"), str)
                                    and info["app_label"].startswith("@0x")))
                need = (_lbl_missing
                        or not info.get("launchable")
                        or not info.get("permissions"))
                if need:
                    for _k in ("app_label", "launchable", "permissions",
                               "package", "versionName", "versionCode",
                               "minSdk", "targetSdk", "compileSdk",
                               "platformVersion"):
                        if not info.get(_k):
                            info[_k] = _fb.get(_k, "")
                    # 应用名若为 @0x... 资源引用, 尝试从 resources.arsc 解析真名
                    _lbl = info.get("app_label", "")
                    if isinstance(_lbl, str) and _lbl.startswith("@0x"):
                        try:
                            _arsc_raw = _read_zip_entry_raw(_fb_target,
                                                            "resources.arsc")
                            if _arsc_raw:
                                _resolved = _resolve_arsc_string(
                                    _arsc_raw, int(_lbl[3:], 16))
                                if _resolved:
                                    info["app_label"] = _clean_label(_resolved)
                        except Exception:
                            pass
            except Exception:
                pass
        # aapt 原始报错但容错兜底已恢复出有效信息 -> 降级为温和提示,
        # 避免把加固/损坏 APK 的 aapt 报错当成硬失败吓到用户。
        if err and info:
            _recovered = (info.get("package")
                          or info.get("app_label")
                          or info.get("launchable")
                          or (isinstance(info.get("permissions"), list)
                              and info["permissions"]))
            if _recovered:
                err = ("（已从受损/加固 APK 容错提取基本信息；"
                       "aapt 原始报错已忽略）")
        # 统一清洗应用名: 剥离加固样本用零宽字符包裹的混淆 (如 'U\\u200dV\\u200dI\\u200dP')
        if info:
            info["app_label"] = _clean_label(info.get("app_label", ""))
        return info, err, repaired
    finally:
        for p in tmp_paths:
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# 5. 可滚动帧 (用于权限列表)
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# 6. 拖拽支持 (Windows 原生 WM_DROPFILES, 带回调保活)
# --------------------------------------------------------------------------- #
_DRAG_KEEPALIVE = []


def _install_dragdrop():
    if sys.platform != "win32" or ctypes is None:
        return None
    try:
        drag_query_file = windll.shell32.DragQueryFileW
        drag_finish = windll.shell32.DragFinish
        drag_accept = windll.shell32.DragAcceptFiles
        set_window_long = windll.user32.SetWindowLongPtrW
        call_window_proc = windll.user32.CallWindowProcW

        GWL_WNDPROC = -4
        WM_DROPFILES = 0x0233

        WNDPROC = WINFUNCTYPE(c_longlong, wintypes.HWND, wintypes.UINT,
                              wintypes.WPARAM, wintypes.LPARAM)

        drag_query_file.argtypes = (wintypes.HANDLE, wintypes.UINT,
                                    wintypes.LPWSTR, wintypes.UINT)
        drag_query_file.restype = wintypes.UINT
        set_window_long.argtypes = (wintypes.HWND, c_int, c_longlong)
        set_window_long.restype = c_longlong
        call_window_proc.argtypes = (c_void_p, wintypes.HWND, wintypes.UINT,
                                     wintypes.WPARAM, wintypes.LPARAM)
        call_window_proc.restype = c_longlong
    except Exception:
        return None

    drops = {}

    def _wndproc(hwnd, msg, wparam, lparam):
        entry = drops.get(hwnd)
        if entry is None:
            return 0
        old_proc, callback = entry
        if msg == WM_DROPFILES:
            hdrop = wintypes.HANDLE(wparam)
            count = drag_query_file(hdrop, 0xFFFFFFFF, None, 0)
            files = []
            for i in range(count):
                length = drag_query_file(hdrop, i, None, 0)
                buf = ctypes.create_unicode_buffer(length + 1)
                drag_query_file(hdrop, i, buf, length + 1)
                files.append(buf.value)
            drag_finish(hdrop)
            if files and callback:
                try:
                    callback(files[0])
                except Exception as exc:  # pragma: no cover
                    print("drop callback error:", exc)
            return 0
        return call_window_proc(old_proc, hwnd, msg, wparam, lparam)

    cb = WNDPROC(_wndproc)
    cb_ptr = ctypes.cast(cb, c_void_p).value
    # 关键: 保活回调对象, 否则被 GC 后窗口过程指针变野指针 -> 进程崩溃
    _DRAG_KEEPALIVE.append(cb)

    def enable_drop(hwnd, callback):
        if hwnd in drops:
            return
        drag_accept(hwnd, True)
        old = set_window_long(hwnd, GWL_WNDPROC, cb_ptr)
        drops[hwnd] = (old, callback)

    return enable_drop


# --------------------------------------------------------------------------- #
# 7. 主界面
# --------------------------------------------------------------------------- #
class ApkInfoApp:
    def __init__(self, root):
        self.root = root
        root.title("APK 信息解析工具 (aapt)")
        # 高 DPI 适配: 进程已声明 DPI 感知(见 main()), 此时窗口像素 = 设备像素,
        # 默认 780x720 会比未感知时(Windows 位图拉伸)显得更小, 故按系统缩放比放大,
        # 既保证文字清晰, 又保持原有屏幕占比。winfo_fpixels('1i') = 每英寸设备像素
        # (96=100%, 120%=120), 缩放比 = 该值 / 96。
        try:
            _dpi = root.winfo_fpixels("1i")
            self.scale = _dpi / 96.0 if _dpi > 0 else 1.0
        except Exception:
            self.scale = 1.0
        if self.scale < 1.0:
            self.scale = 1.0
        root.geometry("%dx%d" % (int(780 * self.scale),
                                 int(720 * self.scale)))
        root.minsize(int(680 * self.scale), int(560 * self.scale))

        self.aapt_path = find_aapt()
        self.current = {}        # 全部字段 (用于复制全部)
        self.perms = []          # 权限列表
        self.features = []       # 特性列表
        self.sigs = []           # 签名证书
        self.perm_expanded = False

        # 字体 / 主题状态
        self.font_name = "Microsoft YaHei"   # UI 字体族
        self.mono_name = "Consolas"          # 等宽字体族 (值/日志)
        self.font_size = 11                   # 字号
        self.dark = True                      # 默认深色主题白字
        self.style = ttk.Style()

        self._build_ui()

        self.enable_drop = _install_dragdrop()
        if self.enable_drop:
            self.root.after(80, self._register_drops)
        else:
            self.log("提示: 当前非 Windows 或缺少 ctypes, 拖拽不可用, 请用「选择 APK」按钮。")

        if not self.aapt_path:
            self.log("⚠ 未找到 aapt.exe! 将无法解析包名/版本/权限等信息。")
            self.log("   请把 Android SDK build-tools 加入路径, 或设置环境变量 AAPT_PATH。")
            messagebox.showwarning(
                "未找到 aapt",
                "未能自动发现 aapt.exe。\n请安装 Android SDK build-tools, 或在运行前设置环境变量:\n"
                "  AAPT_PATH=\"你的路径\\build-tools\\版本\\aapt.exe\"\n\n"
                "文件 MD5/大小/签名信息仍可正常解析。")
        else:
            self.log("aapt 已就绪: %s" % self.aapt_path)

    # ----------------------------- UI 构建 ----------------------------- #
    def _build_ui(self):
        # 字体候选 (仅保留系统实际存在的)
        import tkinter.font as tkfont
        fams = set(tkfont.families())
        candidates = ["Microsoft YaHei", "微软雅黑", "等线", "DengXian",
                      "Segoe UI", "宋体", "SimSun", "黑体", "SimHei",
                      "Tahoma", "Arial", "Consolas", "Courier New"]
        font_choices = [f for f in candidates if f in fams]
        if not font_choices:
            font_choices = ["Microsoft YaHei"]
        if self.font_name not in font_choices:
            font_choices.insert(0, self.font_name)
        size_choices = [str(s) for s in
                        (8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22)]

        top = ttk.Frame(self.root, padding=8)
        top.pack(fill="x")

        title = ttk.Label(top, text="APK 信息解析工具 (aapt)")
        title._weight = "bold"
        self.title_label = title
        title.pack(side="left")

        # 右: 设置控件
        self.theme_btn = ttk.Button(top, text="☀ 浅色", command=self._toggle_theme)
        self.theme_btn.pack(side="right", padx=(8, 2))
        ttk.Label(top, text="字号:").pack(side="right", padx=(8, 2))
        self.size_combo = ttk.Combobox(top, values=size_choices, width=4,
                                       state="readonly")
        self.size_combo.set(str(self.font_size))
        self.size_combo.pack(side="right")
        self.size_combo.bind(
            "<<ComboboxSelected>>",
            lambda e: self._set_font_size(int(self.size_combo.get())))
        ttk.Label(top, text="字体:").pack(side="right", padx=(6, 2))
        self.font_combo = ttk.Combobox(top, values=font_choices, width=14,
                                       state="readonly")
        self.font_combo.set(self.font_name)
        self.font_combo.pack(side="right")
        self.font_combo.bind(
            "<<ComboboxSelected>>",
            lambda e: self._set_font_name(self.font_combo.get()))

        ttk.Button(top, text="复制全部信息",
                   command=self.copy_all).pack(side="right", padx=4)
        ttk.Button(top, text="选择 APK 文件",
                   command=self._choose).pack(side="right")

        hint = ttk.Label(self.root,
                         text="👉 把 .apk 文件拖到窗口任意位置即可自动解析",
                         padding=(8, 0, 8, 4))
        self.hint_label = hint
        hint.pack(fill="x")

        # 可滚动内容区 (Canvas + 右侧竖向滚动条)
        content_frame = ttk.Frame(self.root)
        content_frame.pack(fill="both", expand=True)
        self.body_canvas = tk.Canvas(content_frame, borderwidth=0,
                                     highlightthickness=0)
        self.body_scroll = ttk.Scrollbar(content_frame, orient="vertical",
                                         command=self.body_canvas.yview)
        self.body = ttk.Frame(self.body_canvas, padding=(8, 0, 4, 0))
        self._body_win = self.body_canvas.create_window(
            (0, 0), window=self.body, anchor="nw")
        self.body_canvas.configure(yscrollcommand=self.body_scroll.set)
        self.body_canvas.bind(
            "<Configure>",
            lambda e: self.body_canvas.itemconfigure(self._body_win, width=e.width))
        self.body.bind(
            "<Configure>",
            lambda e: self.body_canvas.configure(
                scrollregion=self.body_canvas.bbox("all")))
        self.body_canvas.pack(side="left", fill="both", expand=True)
        self.body_scroll.pack(side="right", fill="y")

        self._make_section("文件信息", "file")
        self._make_icon_section()
        self._make_section("基本信息", "basic")
        self._make_section("签名信息", "sig")
        self._make_perm_section()
        self._bind_mousewheel()

        # 日志
        log_frame = ttk.LabelFrame(self.root, text="日志", padding=6)
        log_frame.pack(fill="both", expand=False, padx=8, pady=6)
        self.log_text = scrolledtext.ScrolledText(
            log_frame, height=8, state="disabled",
            font=("Consolas", 9))

        self.log_text.pack(fill="both", expand=True)

        # 应用主题与字体 (一次性)
        self._apply_theme()
        self._apply_font()

    def _make_section(self, title, key):
        lf = ttk.LabelFrame(self.body, text=title, padding=6)
        lf.pack(fill="x", pady=4)
        setattr(self, key + "_frame", lf)
        inner = ttk.Frame(lf)
        inner.pack(fill="x")
        setattr(self, key + "_inner", inner)

    def _make_icon_section(self):
        lf = ttk.LabelFrame(self.body, text="应用图标", padding=6)
        lf.pack(fill="x", pady=4)
        self.icon_frame = lf
        inner = ttk.Frame(lf)
        inner.pack(fill="x")
        # 左: 图标图像 (固定尺寸凹槽框, 避免布局跳动)
        self.icon_img_label = ttk.Label(
            inner, text="（无图标）", anchor="center", width=14,
            relief="groove")
        self.icon_img_label.pack(side="left", padx=4, pady=4)
        # 右: 图标元信息
        info = ttk.Frame(inner)
        info.pack(side="left", fill="x", expand=True, padx=6)
        self.icon_md5_lbl = ttk.Label(info, text="图标MD5: —", anchor="w")
        self.icon_md5_lbl.pack(fill="x", pady=1)
        self.icon_fmt_lbl = ttk.Label(info, text="格式/尺寸: —", anchor="w")
        self.icon_fmt_lbl.pack(fill="x", pady=1)
        self.icon_path_lbl = ttk.Label(info, text="来源: —", anchor="w")
        self.icon_path_lbl.pack(fill="x", pady=1)
        self._icon_photo = None  # 保活 PhotoImage 引用, 防止被 GC 后图像消失

    def _render_icon(self, icon_bytes, md5, path, fmt, w, h, status=None):
        """渲染图标图像并显示 MD5 / 格式尺寸 / 来源。

        优先用 Pillow (支持 WebP/JPEG 且可缩放); 缺失 Pillow 时退回 tkinter 原生
        PhotoImage (仅 PNG/GIF)。其它格式或解析失败显示占位文字, 不报错中断。
        status: 见 _extract_apk_icon —— 用于在无图标时给出准确原因(加密/混淆/确无)。"""
        self._icon_photo = None
        if icon_bytes is None:
            if status == "encrypted":
                tip = "（资源已加密/加壳，无法提取图标）"
                note = "APK 资源被加壳加密，图标运行时才解密，静态工具无法还原。"
            elif status == "guess":
                tip = "（无明确图标）"
                note = "未找到命名图标，按图形特征也未匹配到启动图标。"
            else:
                tip = "（无图标）"
                note = "该 APK 不含可识别的启动图标资源。"
            self.icon_img_label.configure(image="", text=tip)
            self.icon_md5_lbl.configure(text="图标MD5: —")
            self.icon_fmt_lbl.configure(text="格式/尺寸: —")
            self.icon_path_lbl.configure(text=note)
            self.current.pop("图标MD5", None)
            return
        img = None
        try:
            if Image is not None:
                im = Image.open(io.BytesIO(icon_bytes)).convert("RGBA")
                maxsz = 96
                if w and h:
                    scale = min(maxsz / float(w), maxsz / float(h))
                    nw, nh = max(1, int(w * scale)), max(1, int(h * scale))
                else:
                    nw = nh = maxsz
                im = im.resize((nw, nh), Image.LANCZOS)
                img = ImageTk.PhotoImage(im)
            else:
                # 原生 tk 只支持 PNG/GIF
                if fmt in ("PNG", "GIF"):
                    import base64
                    photo = tk.PhotoImage(
                        data=base64.b64encode(icon_bytes).decode("ascii"))
                    if w and h:
                        maxsz = 96
                        f = max(1, max(w, h) // maxsz)
                        if f > 1:
                            photo = photo.subsample(f, f)
                    img = photo
        except Exception as exc:
            self.log("图标预览失败: %s" % exc)
        if img is not None:
            self.icon_img_label.configure(image=img, text="", width=14)
            self._icon_photo = img  # 保活
        else:
            self.icon_img_label.configure(image="", text="（无法预览）")
        self.icon_md5_lbl.configure(text="图标MD5: %s" % (md5 or "—"))
        self.icon_fmt_lbl.configure(
            text="格式/尺寸: %s (%dx%d)" % (fmt or "?", w or 0, h or 0))
        self.icon_path_lbl.configure(text="来源: %s" % (path or "—"))
        if md5:
            self.current["图标MD5"] = md5

    def _make_perm_section(self):
        lf = ttk.LabelFrame(self.body, text="权限信息", padding=6)
        lf.pack(fill="x", pady=4)
        self.perm_frame = lf

        self.perm_toggle = ttk.Button(
            lf, text="展开权限 (0)", command=self.toggle_perm)
        self.perm_toggle.pack(fill="x")

        self.perm_ctrl = ttk.Frame(lf)
        ttk.Button(self.perm_ctrl, text="复制全部权限",
                   command=self.copy_perms).pack(side="right", padx=2)
        self.perm_ctrl.pack_forget()

        self.perm_inner = ttk.Frame(lf)
        self.perm_inner.pack_forget()

    # ----------------------------- 通用行 ----------------------------- #
    def _add_row(self, parent, label, value, copy_key=None, mono=False):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=1)
        ttk.Label(row, text=label, width=14, anchor="e").pack(side="left")
        display = value if value else "—"
        lbl = ttk.Label(row, text=display, anchor="w", wraplength=520,
                        justify="left")
        lbl._mono = mono
        lbl.pack(side="left", fill="x", expand=True, padx=4)
        if copy_key is not None:
            ttk.Button(row, text="复制", width=5,
                       command=lambda: self.copy(value)).pack(side="right")
            if copy_key:
                self.current[copy_key] = value
        return lbl

    # ----------------------------- 解析 ----------------------------- #
    def parse(self, path):
        if not path or not os.path.isfile(path):
            self.log("文件不存在: %s" % path)
            return
        if not path.lower().endswith(".apk"):
            self.log("忽略非 APK 文件: %s" % path)
            return

        self.log("━" * 30)
        self.log("开始解析: %s" % os.path.basename(path))

        # 清空旧数据
        self.current = {}
        self.perms = []
        self.features = []
        self.sigs = []
        for key in ("file", "basic", "sig"):
            inner = getattr(self, key + "_inner")
            for w in inner.winfo_children():
                w.destroy()
        for w in self.perm_inner.winfo_children():
            w.destroy()
        if self.perm_expanded:
            self.toggle_perm()  # 收起

        # 文件信息
        if any(ord(c) > 127 for c in path):
            self.log("提示: 路径含中文/非 ASCII 字符, 已复制到临时路径交由 aapt 解析以确保兼容。")
        try:
            md5, size = compute_file_info(path)
            self._add_row(self.file_inner, "MD5", md5, "MD5", mono=True)
            self._add_row(self.file_inner, "文件大小",
                          "%s 字节 (%.2f MB)" % (size, size / 1024 / 1024),
                          "文件大小")
            self._add_row(self.file_inner, "路径", path, "路径", mono=True)
        except Exception as exc:
            self.log("计算文件信息失败: %s" % exc)

        # aapt 解析
        info = None
        if self.aapt_path:
            info, err, repaired = run_aapt(self.aapt_path, path)
            if repaired:
                self.log("提示: 检测到 APK 的 central directory 缺失/损坏"
                         "(常见于加固样本), 已自动从本地文件头重建后解析。")
            recovered = False
            if err and info:
                self.log("⚠ aapt 直接解析失败(%s), 已尝试从 AndroidManifest.xml "
                         "容错解析恢复。"
                         % (err.splitlines()[0] if err else ""))
                recovered = True
            elif err:
                self.log("⚠ %s" % err)
            if info:
                self._render_basic(info)
                self.perms = info["permissions"]
                self.features = info["features"] + [
                    "(非必需) " + f for f in info["features_notreq"]]
                self._render_permissions(info)
                if recovered:
                    self.log("容错解析恢复完成: 包名=%s, 权限 %d 项"
                             % (info["package"] or "?", len(self.perms)))
                else:
                    self.log("aapt 解析完成: 包名=%s, 权限 %d 项, 特性 %d 项"
                             % (info["package"] or "?", len(self.perms),
                                len(info["features"]) + len(info["features_notreq"])))
        else:
            self._add_row(self.basic_inner, "包名",
                          "(未找到 aapt)", None)
            self.log("跳过 aapt 解析 (未找到 aapt)。")

        # 应用图标 (不依赖 aapt 是否成功; aapt 失败时从 manifest 兜底解析)
        try:
            _info_for_icon = info if isinstance(info, dict) else {}
            (icon_bytes, icon_md5, icon_path, icon_fmt, icon_w,
             icon_h, icon_status) = _extract_apk_icon(path, _info_for_icon)
            self._render_icon(icon_bytes, icon_md5, icon_path,
                              icon_fmt, icon_w, icon_h, icon_status)
            if icon_bytes:
                tag = "（按图形特征推测）" if icon_status == "guess" else ""
                self.log("图标提取成功%s: %s, %s (%dx%d), MD5=%s"
                         % (tag, icon_path, icon_fmt, icon_w or 0, icon_h or 0,
                            icon_md5))
            elif icon_status == "encrypted":
                self.log("提示: 该 APK 资源被加壳加密, 启动图标无法静态提取"
                         "(存在图片名条目但均不可解码)。")
            else:
                self.log("提示: 未能从 APK 提取启动图标 (确无图标或资源引用无法解析)。")
        except Exception as exc:
            self.log("图标提取异常: %s" % exc)

        # 签名信息 (不依赖 aapt)
        cert_files = self._meta_cert_files(path)
        self.sigs, self.sig_errors, schemes = parse_signatures(path)
        self._render_signatures(cert_files, schemes)

        # 内容变化后重新绑定滚轮并刷新滚动区域
        self._bind_mousewheel()
        self.root.after(50, lambda: self.body_canvas.configure(
            scrollregion=self.body_canvas.bbox("all")))

        # 让新生成的行应用当前字体/字号
        self._apply_font()

        self.log("解析结束 ✓")

    def _meta_cert_files(self, path):
        try:
            return list(_read_meta_certs(path).keys())
        except Exception:
            return []

    def _render_basic(self, info):
        self._add_row(self.basic_inner, "包名", info["package"], "包名", mono=True)
        self._add_row(self.basic_inner, "应用名",
                      info["app_label"] or "—", "应用名")
        self._add_row(self.basic_inner, "版本名",
                      info["versionName"] or "—", "版本名")
        self._add_row(self.basic_inner, "版本码",
                      info["versionCode"] or "—", "版本码")
        self._add_row(self.basic_inner, "最低系统",
                      sdk_name(info["minSdk"]), "最低系统")
        self._add_row(self.basic_inner, "目标系统",
                      sdk_name(info["targetSdk"]), "目标系统")
        self._add_row(self.basic_inner, "编译 SDK",
                      info["compileSdk"] or "—", "编译SDK")
        self._add_row(self.basic_inner, "入口 Activity",
                      info["launchable"] or "—", "入口Activity", mono=True)
        if info["native_code"]:
            self._add_row(self.basic_inner, "原生代码",
                          ", ".join(info["native_code"]), "原生代码", mono=True)
        if info["supports_screens"]:
            self._add_row(self.basic_inner, "支持屏幕",
                          ", ".join(info["supports_screens"]), "支持屏幕")
        if info["install_location"]:
            self._add_row(self.basic_inner, "安装位置",
                          info["install_location"], "安装位置")

    def _render_permissions(self, info):
        self.perm_toggle.configure(
            text="展开权限 (%d)" % len(self.perms))
        # 预先填充折叠区内容 (隐藏状态)
        for name in self.perms:
            self._add_perm_row(name)
        # 特性也放入权限区
        for f in self.features:
            self._add_perm_row(f, is_feature=True)
        if info["libraries"]:
            for lib in info["libraries"]:
                self._add_perm_row("uses-library: " + lib, is_feature=True)

    def _add_perm_row(self, name, is_feature=False):
        row = ttk.Frame(self.perm_inner)
        row.pack(fill="x", pady=1)
        if is_feature:
            tag = "〔特性〕"
            desc = ""
        else:
            tag = ""
            desc = perm_desc(name)
        tag_lbl = ttk.Label(row, text=tag, width=8)
        if getattr(self, "_accent", None):
            tag_lbl.configure(foreground=self._accent)
        tag_lbl._accent_tag = True
        tag_lbl.pack(side="left")
        txt = name + (("  —  " + desc) if desc else "")
        txt_lbl = ttk.Label(row, text=txt, wraplength=560,
                            justify="left")
        txt_lbl._mono = True
        txt_lbl.pack(side="left", fill="x", expand=True, padx=2)
        ttk.Button(row, text="复制", width=5,
                   command=lambda n=name: self.copy(n)).pack(side="right")

    def _render_signatures(self, cert_files, schemes):
        if not self.sigs:
            if cert_files:
                # 文件存在但没解析出证书 —— 明确告诉用户, 不要谎称"无证书"
                msg = ("发现 %d 个证书文件但均解析失败 (可能为非标准/加壳签名)"
                       % len(cert_files))
                self._add_row(self.sig_inner, "签名", msg, None)
                self._add_row(self.sig_inner, "证书文件",
                              ", ".join(cert_files), None, mono=True)
                for cf, why in (getattr(self, "sig_errors", {}) or {}).items():
                    self._add_row(self.sig_inner, "解析失败",
                                  "%s: %s" % (cf, why), None, mono=True)
                self.log("⚠ %s: %s" % (msg, ", ".join(cert_files)))
                if self.sig_errors:
                    for cf, why in self.sig_errors.items():
                        self.log("   ↳ %s" % why)
            else:
                # 无 META-INF 证书: 判断是否检测到签名块 (而非真未签名)
                vtags = [s for s in schemes
                         if (("v2" in s or "v3" in s or "v4" in s
                              or "签名块" in s) and s != "签名方案未知")]
                if vtags:
                    msg = ("该 APK 检测到 APK Signing Block (签名块), 但 "
                           "META-INF 中无标准 v1 证书。签名方案: %s。"
                           "若是现代 Android 应用 (Play 商店发布) 此为正常情况,"
                           "证书内嵌于签名块; 若方案 ID 非标准 (含 '加固/加壳' 字样),"
                           "则可能是加固样本自定义签名块, 无法提取标准 X.509 证书。"
                           % " / ".join(vtags))
                    self._add_row(self.sig_inner, "签名", msg, None)
                    if self.sig_errors:
                        for src, why in self.sig_errors.items():
                            self._add_row(self.sig_inner, "解析提示",
                                          "%s: %s" % (src, why), None, mono=True)
                        self.log("⚠ 检测到签名块, 但未能从中提取证书明细: %s"
                                 % "; ".join(self.sig_errors.values()))
                    else:
                        self.log("ℹ 检测到签名块 (无 META-INF v1 证书): %s"
                                 % " / ".join(vtags))
                else:
                    self._add_row(self.sig_inner, "签名",
                                  "(未检测到 META-INF 证书, 可能未签名)", None)
                    self.log("该 APK 无 META-INF 证书 (可能未签名)。")
            return
        self._add_row(self.sig_inner, "签名方案",
                      "; ".join(schemes), "签名方案")
        for i, c in enumerate(self.sigs, 1):
            sub = ttk.LabelFrame(self.sig_inner,
                                 text="证书 #%d (%s)" % (i, c["file"]),
                                 padding=4)
            sub.pack(fill="x", pady=3)
            self._add_row(sub, "主题", c["subject"], "签名主题%d" % i, mono=True)
            self._add_row(sub, "颁发者", c["issuer"], "签名颁发者%d" % i, mono=True)
            self._add_row(sub, "序列号", c["serial"], "签名序列号%d" % i, mono=True)
            self._add_row(sub, "有效期",
                          "%s  →  %s" % (c["not_before"], c["not_after"]),
                          "签名有效期%d" % i)
            self._add_row(sub, "签名算法", c["sig_alg"], "签名算法%d" % i)
            keyinfo = c["key_type"].replace("PublicKey", "") + \
                ((" %d位" % c["key_size"]) if c["key_size"] else "")
            self._add_row(sub, "公钥", keyinfo, "签名公钥%d" % i)
            self._add_row(sub, "自签名",
                          "是 (subject == issuer)" if c["self_signed"] else "否",
                          "自签名%d" % i)
            self._add_row(sub, "签名MD5", c.get("md5", ""),
                          "签名MD5%d" % i, mono=True)
            self._add_row(sub, "签名SHA1", c.get("sha1", ""),
                          "签名SHA1%d" % i, mono=True)
            self._add_row(sub, "签名SHA256", c.get("sha256", ""),
                          "签名SHA256%d" % i, mono=True)
            self.log("证书 #%d: %s | %s | 有效期至 %s"
                     % (i, c["subject"], c["sig_alg"], c["not_after"][:10]))

    # ----------------------------- 交互 ----------------------------- #
    def toggle_perm(self):
        if self.perm_expanded:
            self.perm_expanded = False
            self.perm_inner.pack_forget()
            self.perm_ctrl.pack_forget()
            self.perm_toggle.configure(
                text="展开权限 (%d)" % len(self.perms))
        else:
            self.perm_expanded = True
            self.perm_inner.pack(fill="both", expand=True, pady=2)
            self.perm_ctrl.pack(fill="x", pady=2)
            self.perm_toggle.configure(text="收起权限 (%d)" % len(self.perms))
            if self.enable_drop:
                self.root.after(60, self._register_drops)
            self.root.after(60, self._bind_mousewheel)
            self.root.after(60, lambda: self.body_canvas.configure(
                scrollregion=self.body_canvas.bbox("all")))

    def copy(self, text):
        if text is None:
            text = ""
        text = str(text)
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.log("已复制: %s%s" % (text[:40], "…" if len(text) > 40 else ""))
        except Exception as exc:
            self.log("复制失败: %s" % exc)

    def copy_all(self):
        lines = []
        order = ["MD5", "文件大小", "路径", "包名", "应用名", "版本名",
                 "版本码", "最低系统", "目标系统", "编译SDK", "入口Activity",
                 "原生代码", "支持屏幕", "安装位置", "图标MD5", "签名方案"]
        for k in order:
            if k in self.current and self.current[k]:
                lines.append("%s: %s" % (k, self.current[k]))
        if self.perms:
            lines.append("")
            lines.append("权限 (%d):" % len(self.perms))
            for p in self.perms:
                d = perm_desc(p)
                lines.append("  %s%s" % (p, ("  — " + d) if d else ""))
        if self.sigs:
            lines.append("")
            lines.append("签名信息:")
            for i, c in enumerate(self.sigs, 1):
                lines.append("  证书 #%d: %s" % (i, c["subject"]))
                lines.append("    颁发者: %s" % c["issuer"])
                lines.append("    序列号: %s" % c["serial"])
                lines.append("    有效期: %s → %s" % (c["not_before"], c["not_after"]))
                lines.append("    算法: %s / %s" % (c["sig_alg"], c["key_type"]))
                if c.get("md5"):
                    lines.append("    签名MD5: %s" % c["md5"])
                if c.get("sha1"):
                    lines.append("    签名SHA1: %s" % c["sha1"])
                if c.get("sha256"):
                    lines.append("    签名SHA256: %s" % c["sha256"])
        self.copy("\n".join(lines))

    def copy_perms(self):
        lines = []
        for p in self.perms:
            d = perm_desc(p)
            lines.append("%s%s" % (p, ("  — " + d) if d else ""))
        for f in self.features:
            lines.append(f)
        self.copy("\n".join(lines))

    def _choose(self):
        p = filedialog.askopenfilename(
            title="选择 APK 文件",
            filetypes=[("APK 文件", "*.apk"), ("所有文件", "*.*")])
        if p:
            self.parse(p)

    def on_drop(self, path):
        self.parse(path)

    # ----------------------------- 拖拽注册 ----------------------------- #
    def _register_drops(self):
        if not self.enable_drop:
            return

        def walk(w):
            try:
                self.enable_drop(w.winfo_id(), self.on_drop)
            except Exception:
                pass
            for c in w.winfo_children():
                walk(c)

        walk(self.root)

    # ----------------------------- 鼠标滚轮滚动内容区 ----------------------------- #
    def _bind_mousewheel(self):
        """把鼠标滚轮绑定到内容区画布, 让窗口溢出的内容可用滚轮滚动。"""
        def on_wheel(event):
            # Windows: event.delta 向上为正; 每格 120
            self.body_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def walk(w):
            try:
                w.bind("<MouseWheel>", on_wheel)
            except Exception:
                pass
            for c in w.winfo_children():
                walk(c)

        walk(self.body_canvas)

    # ----------------------------- 主题 / 字体 ----------------------------- #
    def _apply_theme(self, dark=None):
        """应用深色/浅色主题。dark=None 时沿用当前 self.dark。"""
        if dark is None:
            dark = self.dark
        self.dark = dark

        if dark:
            BG = "#1e1e1e"; PANEL = "#252526"; FIELD = "#2d2d30"
            FG = "#e8e8e8"; TITLE = "#ffffff"; BORDER = "#3c3c3c"
            BTN = "#3c3c3c"; BTN_ACTIVE = "#525252"
            ACCENT = "#4ec9b0"; MUTED = "#9aa0a6"
            LOG_BG = "#1e1e1e"; LOG_FG = "#d4d4d4"
        else:
            BG = "#f2f2f2"; PANEL = "#ffffff"; FIELD = "#ffffff"
            FG = "#222222"; TITLE = "#000000"; BORDER = "#cfcfcf"
            BTN = "#e8e8e8"; BTN_ACTIVE = "#cfcfcf"
            ACCENT = "#0a7"; MUTED = "#666666"
            LOG_BG = "#ffffff"; LOG_FG = "#222222"

        self._accent = ACCENT
        self._muted = MUTED

        self.root.configure(bg=BG)
        self.body_canvas.configure(bg=BG)

        s = self.style
        try:
            s.theme_use("clam")
        except Exception:
            pass
        s.configure("TFrame", background=PANEL)
        s.configure("TLabel", background=PANEL, foreground=FG)
        s.configure("TButton", background=BTN, foreground=FG,
                    bordercolor=BORDER, lightcolor=BTN, darkcolor=BTN,
                    relief="flat")
        s.configure("TLabelframe", background=PANEL, foreground=TITLE,
                    bordercolor=BORDER)
        s.configure("TLabelframe.Label", background=PANEL, foreground=TITLE)
        s.configure("TCombobox", background=FIELD, foreground=FG,
                    fieldbackground=FIELD, bordercolor=BORDER)
        s.configure("Vertical.TScrollbar", background=BTN, troughcolor=PANEL,
                    bordercolor=BORDER, lightcolor=BTN, darkcolor=BTN)
        s.map("TButton",
              background=[("active", BTN_ACTIVE), ("pressed", BTN_ACTIVE)])
        s.map("TCombobox",
              fieldbackground=[("readonly", FIELD), ("disabled", FIELD)],
              background=[("readonly", FIELD)],
              foreground=[("readonly", FG)])

        # tk 原生控件 (日志)
        try:
            self.log_text.configure(
                bg=LOG_BG, fg=LOG_FG, insertbackground=FG,
                selectbackground=BTN_ACTIVE, selectforeground=LOG_FG)
        except Exception:
            pass

        # 提示文字 / 强调标签跟随主题
        try:
            self.hint_label.configure(foreground=MUTED)
        except Exception:
            pass

        # 遍历: 把带 _accent_tag 的权限标签刷成强调色
        def walk(w):
            for c in w.winfo_children():
                if getattr(c, "_accent_tag", False):
                    try:
                        c.configure(foreground=ACCENT)
                    except Exception:
                        pass
                walk(c)
        walk(self.root)

        # 主题按钮文案
        try:
            self.theme_btn.configure(text="☀ 浅色" if dark else "🌙 深色")
        except Exception:
            pass

        self._apply_font()

    def _apply_font(self):
        """把当前字体族/字号应用到所有控件。

        普通 TLabel / TButton / TCombobox 通过 ttk 样式统一设置;
        等宽(mono)标签与日志(Text)逐个单独设置以覆盖样式。
        """
        ui = (self.font_name, self.font_size)
        mono = (self.mono_name, self.font_size)

        # 统一通过样式设置 (TButton 不支持实例级 font, 只能走样式)
        try:
            self.style.configure("TLabel", font=ui)
            self.style.configure("TButton", font=ui)
            self.style.configure("TCombobox", font=ui)
        except Exception:
            pass

        def walk(w):
            for c in w.winfo_children():
                cls = c.winfo_class()
                try:
                    if cls == "TLabel" and getattr(c, "_mono", False):
                        c.configure(font=mono)
                    elif cls == "TLabel" and getattr(c, "_weight", None):
                        c.configure(font=(self.font_name, self.font_size,
                                         c._weight))
                    elif cls == "Text":
                        c.configure(font=mono)
                    elif cls in ("Label", "Button", "Entry"):  # tk 原生
                        fnt = mono if getattr(c, "_mono", False) else ui
                        c.configure(font=fnt)
                except Exception:
                    pass
                walk(c)
        walk(self.root)

    def _set_font_name(self, name):
        if name:
            self.font_name = name
            self._apply_font()

    def _set_font_size(self, size):
        self.font_size = size
        self._apply_font()

    def _toggle_theme(self):
        self._apply_theme(not self.dark)

    # ----------------------------- 日志 ----------------------------- #
    def log(self, msg):
        try:
            import datetime
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            self.log_text.configure(state="normal")
            self.log_text.insert("end", "[%s] %s\n" % (ts, msg))
            self.log_text.configure(state="disabled")
            self.log_text.see("end")
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# 8. 入口
# --------------------------------------------------------------------------- #
def _enable_high_dpi():
    """声明进程为 DPI 感知, 避免 Windows 对窗口做位图拉伸导致字体模糊。

    必须在创建 Tk 根窗口之前调用。Win10/11 上优先用「每显示器 DPI 感知 v2」,
    多显示器不同缩放下最准确; 不支持时回退到每显示器/系统级感知。
    字体物理大小由 Tk 依据真实 DPI 自动保持 (1pt 始终是 1/72 英寸), 因此开启后
    文字只是从「被拉伸的虚像」变为「原生分辨率清晰渲染」, 不会变小。
    """
    if ctypes is None:
        return
    PMV2 = -4  # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
    try:
        # 每显示器 v2 (Win10 1703+), 支持子窗口/对话框独立缩放
        ctypes.windll.user32.SetProcessDpiAwarenessContext(PMV2)
    except Exception:
        pass
    try:
        # 每显示器感知 (Win8.1+), 失败时回退
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        pass
    try:
        # 系统级感知 (最兜底)
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def main():
    if sys.version_info[0] < 3:
        print("需要 Python 3")
        sys.exit(1)
    _enable_high_dpi()  # 必须早于 tk.Tk(), 否则窗口已被位图缩放
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print("无法启动 GUI (缺少 Tk/tkinter?):", exc)
        sys.exit(1)
    app = ApkInfoApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
