# -*- coding: utf-8 -*-
"""
APK 信息解析工具 —— 命令行版 (CLI)
====================================

与 apk_info_aapt_gui.py (GUI 版) 共用同一套解析函数, 解析结果完全一致;
本文件只负责「命令行参数 + 按行输出」, 便于被其它程序 / 脚本调用。

设计目标:
  - stdout 只输出数据, stderr 只输出诊断/错误, 退出码可判成功失败
  - 默认每行一个「字段=值」, 稳定顺序, 便于逐行 split
  - 可选 JSON / TSV 输出, 可选字段筛选, 支持一次传入多个 APK
  - 内嵌 aapt (打包后) 或自动查找, 中文/加固/填充炸弹样本与 GUI 版同样稳健

用法示例:
  apk_info_cli.exe app.apk
  apk_info_cli.exe --json app.apk
  apk_info_cli.exe --fields package,app_label,version_name app.apk
  apk_info_cli.exe --list-fields
  apk_info_cli.exe --tsv --out result.tsv a.apk b.apk

退出码:
  0  全部 APK 解析成功
  1  部分 APK 解析失败 (成功项照常输出, 失败原因见 stderr)
  2  参数错误 / 文件不存在 / 全部失败 / 无可用 aapt
"""
import sys
import os
import argparse
import json

# ---- Windows 控制台强制 UTF-8, 避免中文应用名乱码 / 管道被 GBK 破坏 ----
def _force_utf8():
    for stream in (getattr(sys, "stdout", None), getattr(sys, "stderr", None)):
        if stream is None:
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
_force_utf8()

# 复用 GUI 模块的解析函数 (import 安全: 模块末尾有 if __name__ == "__main__" 保护)
try:
    import apk_info_aapt_gui as core
except Exception as exc:  # pragma: no cover
    sys.stderr.write("无法加载解析核心 apk_info_aapt_gui.py: %s\n" % exc)
    sys.exit(2)


# --------------------------------------------------------------------------- #
# 字段定义: (输出键, 中文说明) —— 顺序即默认输出顺序
# --------------------------------------------------------------------------- #
FIELDS = [
    ("file_path",        "APK 文件路径"),
    ("file_name",        "文件名"),
    ("file_md5",         "文件 MD5 (大写)"),
    ("file_size_bytes",  "文件大小 (字节)"),
    ("file_size_mb",     "文件大小 (MB, 两位小数)"),
    ("package",          "包名"),
    ("app_label",        "应用名"),
    ("version_name",     "版本名 (versionName)"),
    ("version_code",     "版本码 (versionCode)"),
    ("min_sdk",          "最低 SDK 数值"),
    ("min_sdk_name",     "最低系统 (数值+Android版本)"),
    ("target_sdk",       "目标 SDK 数值"),
    ("target_sdk_name",  "目标系统 (数值+Android版本)"),
    ("compile_sdk",      "编译 SDK"),
    ("launchable",       "入口 Activity"),
    ("install_location", "安装位置"),
    ("native_code",      "原生代码 ABI (逗号连接)"),
    ("supports_screens", "支持屏幕 (逗号连接)"),
    ("icon_status",      "图标状态 (ok/guess/encrypted/missing)"),
    ("icon_path",        "图标在 APK 内路径"),
    ("icon_format",      "图标格式"),
    ("icon_size",        "图标尺寸 (宽x高)"),
    ("icon_md5",         "图标 MD5 (大写)"),
    ("sign_schemes",     "签名方案 (逗号连接)"),
    ("sign_count",       "成功解析的证书数量"),
    ("permission_count", "权限数量"),
    ("permissions",      "权限列表 (逗号连接, 完整限定名)"),
    ("feature_count",    "特性数量 (必需+非必需)"),
    ("features",         "特性列表 (逗号连接)"),
    ("certs",            "证书明细 (JSON 格式; kv/tsv 模式下展开为 certN_* 行)"),
]
FIELD_KEYS = [k for k, _ in FIELDS]
FIELD_DESC = dict(FIELDS)


def _to_text(value):
    """递归把 bytes 解成文本 (icon_path 等来自 ZIP 的字段可能是 bytes)。"""
    if isinstance(value, bytes):
        for enc in ("utf-8", "gbk", "latin-1"):
            try:
                return value.decode(enc)
            except Exception:
                continue
        return value.decode("utf-8", "replace")
    if isinstance(value, (list, tuple)):
        return [_to_text(x) for x in value]
    if isinstance(value, dict):
        return {(_to_text(k) if isinstance(k, bytes) else k): _to_text(v)
                for k, v in value.items()}
    return value


def _esc(value):
    """把任意值转成适合单行输出的安全字符串 (转义换行/制表/反斜杠)。"""
    if value is None:
        return ""
    value = _to_text(value)
    if isinstance(value, (list, tuple)):
        value = ", ".join(str(x) for x in value)
    elif isinstance(value, dict):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    s = str(value)
    return (s.replace("\\", "\\\\")
             .replace("\n", "\\n")
             .replace("\r", "\\r")
             .replace("\t", "\\t"))


# --------------------------------------------------------------------------- #
# 采集: 对单个 APK 调用核心函数, 组装成有序记录
# --------------------------------------------------------------------------- #
def collect(path, aapt_path=None, want_icon=True, want_sign=True, warnings=None):
    """返回 (record_dict, ok_bool)。warnings 为列表, 追加非致命提示。"""
    warnings = warnings if warnings is not None else []
    path = os.path.abspath(path)
    rec = {k: "" for k in FIELD_KEYS}
    rec["file_path"] = path
    rec["file_name"] = os.path.basename(path)
    rec["permissions"] = []
    rec["features"] = []
    rec["native_code"] = []
    rec["supports_screens"] = []
    rec["sign_schemes"] = []
    rec["certs"] = []

    if not os.path.isfile(path):
        warnings.append("文件不存在: %s" % path)
        return rec, False

    # 1) 文件信息
    try:
        md5, size = core.compute_file_info(path)
        rec["file_md5"] = md5
        rec["file_size_bytes"] = size
        rec["file_size_mb"] = "%.2f" % (size / 1024.0 / 1024.0)
    except Exception as exc:
        warnings.append("文件信息计算失败: %s" % exc)

    # 2) aapt / manifest 解析基本信息
    info = None
    if aapt_path:
        try:
            info, err, repaired = core.run_aapt(aapt_path, path)
            if repaired:
                warnings.append("central directory 损坏, 已从本地文件头重建后解析")
            if err and info:
                warnings.append("aapt 部分失败, 已用容错 AXML 补全: %s" %
                                err.splitlines()[0])
            elif err:
                warnings.append("aapt 解析提示: %s" % err.splitlines()[0])
        except Exception as exc:
            warnings.append("aapt 解析异常: %s" % exc)
    else:
        warnings.append("未找到 aapt, 基本字段将为空 (可用 --aapt 指定)")

    if isinstance(info, dict):
        rec["package"]          = info.get("package", "") or ""
        rec["app_label"]        = core._clean_label(info.get("app_label", "") or "")
        rec["version_name"]     = info.get("versionName", "") or ""
        rec["version_code"]     = info.get("versionCode", "") or ""
        rec["min_sdk"]          = info.get("minSdk", "") or ""
        rec["min_sdk_name"]     = core.sdk_name(info.get("minSdk"))
        rec["target_sdk"]       = info.get("targetSdk", "") or ""
        rec["target_sdk_name"]  = core.sdk_name(info.get("targetSdk"))
        rec["compile_sdk"]      = info.get("compileSdk", "") or ""
        rec["launchable"]       = info.get("launchable", "") or ""
        rec["install_location"] = info.get("install_location", "") or ""
        rec["native_code"]      = list(info.get("native_code") or [])
        rec["supports_screens"] = list(info.get("supports_screens") or [])
        perms = [p for p in (info.get("permissions") or []) if p]
        feats = [f for f in (info.get("features") or []) if f]
        feats += ["(非必需) " + f for f in (info.get("features_notreq") or []) if f]
        rec["permissions"] = perms
        rec["permission_count"] = len(perms)
        rec["features"] = feats
        rec["feature_count"] = len(feats)

    # 3) 图标 (失败不影响其它字段)
    if want_icon:
        try:
            (ib, imd5, ipath, ifmt, iw, ih, istatus) = core._extract_apk_icon(
                path, info if isinstance(info, dict) else {})
            rec["icon_status"] = istatus or ("ok" if ib else "missing")
            rec["icon_path"] = _to_text(ipath) if ipath else ""
            rec["icon_format"] = _to_text(ifmt) if ifmt else ""
            rec["icon_size"] = ("%dx%d" % (iw, ih)) if (iw and ih) else ""
            rec["icon_md5"] = imd5 or ""
        except Exception as exc:
            rec["icon_status"] = "error"
            warnings.append("图标提取异常: %s" % exc)

    # 4) 签名 (失败不影响其它字段)
    if want_sign:
        try:
            certs, cert_errs, schemes = core.parse_signatures(path)
            rec["sign_schemes"] = list(schemes or [])
            rec["certs"] = list(certs or [])
            rec["sign_count"] = len(certs or [])
            if cert_errs and not certs:
                warnings.append("签名解析失败: %s" %
                                "; ".join("%s: %s" % (k, v)
                                          for k, v in cert_errs.items()))
        except Exception as exc:
            warnings.append("签名解析异常: %s" % exc)

    ok = bool(info) or bool(rec["file_md5"])
    return rec, ok


# --------------------------------------------------------------------------- #
# 渲染
# --------------------------------------------------------------------------- #
def render_kv(records, fields):
    """每行「字段=值」; 证书展开为 certN_* 行; 多 APK 用分隔行区分。"""
    out = []
    multi = len(records) > 1
    for idx, rec in enumerate(records):
        if multi:
            if idx:
                out.append("")
            out.append("### %s" % rec.get("file_path", ""))
        for key in fields:
            if key == "certs":
                for i, cert in enumerate(rec.get("certs") or [], 1):
                    for ck in ("subject", "issuer", "serial", "not_before",
                               "not_after", "sig_alg", "key_type", "key_size",
                               "self_signed", "md5", "sha1", "sha256"):
                        if ck in cert:
                            out.append("cert%d_%s=%s" % (i, ck, _esc(cert[ck])))
                continue
            out.append("%s=%s" % (key, _esc(rec.get(key, ""))))
    return "\n".join(out)


def render_tsv(records, fields):
    """两列 TSV: 字段<TAB>值; 多 APK 时第一列为 file_path 值区分。"""
    out = []
    for rec in records:
        for key in fields:
            if key == "certs":
                for i, cert in enumerate(rec.get("certs") or [], 1):
                    for ck in ("subject", "issuer", "serial", "sig_alg",
                               "md5", "sha1", "sha256"):
                        if ck in cert:
                            out.append("cert%d_%s\t%s" % (i, ck, _esc(cert[ck])))
                continue
            out.append("%s\t%s" % (key, _esc(rec.get(key, ""))))
    return "\n".join(out)


def render_json(records, fields):
    sel = []
    for rec in records:
        sel.append({k: _to_text(rec.get(k, "")) for k in fields})
    if len(sel) == 1:
        return json.dumps(sel[0], ensure_ascii=False, indent=2)
    return json.dumps(sel, ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------- #
# 命令行入口
# --------------------------------------------------------------------------- #
def build_parser():
    p = argparse.ArgumentParser(
        prog="apk_info_cli",
        description="解析 APK 信息并按行输出 (默认 每行 字段=值), 供其它程序调用。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  apk_info_cli app.apk\n"
               "  apk_info_cli --json app.apk\n"
               "  apk_info_cli --fields package,app_label,version_name app.apk\n"
               "  apk_info_cli --list-fields\n"
               "  apk_info_cli --tsv --out result.tsv a.apk b.apk\n")
    p.add_argument("apks", nargs="*", help="一个或多个 APK 文件路径")
    fmt = p.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="输出 JSON (结构化, 推荐程序调用)")
    fmt.add_argument("--tsv", action="store_true", help="输出制表符分隔 (字段<TAB>值)")
    p.add_argument("--fields", metavar="LIST",
                   help="只输出指定字段, 逗号分隔, 如 package,app_label,icon_md5")
    p.add_argument("--list-fields", action="store_true", help="列出所有可用字段后退出")
    p.add_argument("--aapt", metavar="PATH", help="指定 aapt.exe 路径 (默认自动查找/内嵌)")
    p.add_argument("--out", metavar="FILE", help="把输出写入文件 (UTF-8) 而非 stdout")
    p.add_argument("--no-icon", action="store_true", help="跳过图标提取 (批量提速)")
    p.add_argument("--no-sign", action="store_true", help="跳过签名解析 (批量提速)")
    p.add_argument("--quiet", action="store_true", help="不向 stderr 输出非致命提示")
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_fields:
        for key, desc in FIELDS:
            sys.stdout.write("%-18s %s\n" % (key, desc))
        return 0

    if not args.apks:
        parser.print_usage(sys.stderr)
        sys.stderr.write("错误: 请至少提供一个 APK 路径 (或用 --list-fields)\n")
        return 2

    # 字段筛选
    if args.fields:
        fields = [f.strip() for f in args.fields.split(",") if f.strip()]
        unknown = [f for f in fields if f not in FIELD_KEYS]
        if unknown:
            sys.stderr.write("错误: 未知字段 %s (用 --list-fields 查看)\n" %
                             ", ".join(unknown))
            return 2
    else:
        fields = list(FIELD_KEYS)

    aapt_path = args.aapt or core.find_aapt()
    if not aapt_path and not args.quiet:
        sys.stderr.write("提示: 未找到 aapt, 基本字段可能为空; 可用 --aapt 指定。\n")

    records = []
    fail_count = 0
    for apk in args.apks:
        warns = []
        try:
            rec, ok = collect(apk, aapt_path,
                              want_icon=not args.no_icon,
                              want_sign=not args.no_sign,
                              warnings=warns)
        except Exception as exc:
            sys.stderr.write("错误: 解析 %s 时异常: %s\n" % (apk, exc))
            fail_count += 1
            continue
        records.append(rec)
        if not ok:
            fail_count += 1
        if not args.quiet:
            for w in warns:
                sys.stderr.write("[提示] %s: %s\n" % (os.path.basename(apk), w))

    if not records:
        sys.stderr.write("错误: 没有任何 APK 被成功处理。\n")
        return 2

    if args.json:
        text = render_json(records, fields)
    elif args.tsv:
        text = render_tsv(records, fields)
    else:
        text = render_kv(records, fields)

    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8", newline="\n") as f:
                f.write(text + "\n")
        except Exception as exc:
            sys.stderr.write("错误: 写入 %s 失败: %s\n" % (args.out, exc))
            return 2
    else:
        sys.stdout.write(text + "\n")

    if fail_count and fail_count == len(args.apks):
        return 2
    if fail_count:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
