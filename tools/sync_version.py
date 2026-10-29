#!/usr/bin/env python3
"""把版本号从唯一来源同步到应用包元数据。

唯一来源：dwm/__init__.py 的 __version__
同步目标：fpk-src/manifest 的 version 与 changelog（取 CHANGELOG.md 最新一节）

用法：
    python3 tools/sync_version.py           # 同步并打印
    python3 tools/sync_version.py --check   # 只校验，不一致则退出码 1
    python3 tools/sync_version.py --name    # 打印产物文件名并校验，供构建脚本使用

设计原则：脚本只做「读取 + 覆写这两行」，不重排 manifest 其余内容，
避免 diff 噪音；任何解析失败都直接报错退出，绝不带着错的版本号打包。

产物文件名遵循 fnOS 官方规范 {appname}_{version}_{platform}.fpk，
由本脚本统一派生，构建脚本不自行拼接，避免版本号在文件名里漂移。
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INIT_FILE = ROOT / "dwm" / "__init__.py"
CHANGELOG = ROOT / "CHANGELOG.md"
MANIFEST = ROOT / "fpk-src" / "manifest"

_VERSION_RE = re.compile(r"""^__version__\s*=\s*["']([^"']+)["']""", re.M)


def read_version() -> str:
    text = INIT_FILE.read_text(encoding="utf-8")
    match = _VERSION_RE.search(text)
    if not match:
        raise SystemExit(f"错误：{INIT_FILE} 里找不到 __version__")
    return match.group(1)


def read_latest_changelog() -> tuple[str, list[str]]:
    """返回 (最新小节标题, 条目列表)。标题形如 '1.1.0（2026-10-27）'。"""
    if not CHANGELOG.is_file():
        raise SystemExit(f"错误：缺少 {CHANGELOG}")
    lines = CHANGELOG.read_text(encoding="utf-8").splitlines()

    title = ""
    items: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not title:
            if line.startswith("## "):
                title = line[3:].strip()
            continue
        if line.startswith("## "):
            break
        if line.startswith("- "):
            items.append(line[2:].strip())
    if not title:
        raise SystemExit("错误：CHANGELOG.md 里没有 '## 版本号' 小节")
    return title, items


def read_manifest_field(name: str) -> str:
    """从 manifest 里取单个字段值（`key = value` 或 `key= value` 都能认）。"""
    if not MANIFEST.is_file():
        raise SystemExit(f"错误：缺少 {MANIFEST}")
    for raw in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip() == name:
            return value.strip()
    raise SystemExit(f"错误：manifest 缺少 {name}")


def artifact_name(version: str) -> str:
    """按 fnOS 规范生成产物文件名：{appname}_{version}_{platform}.fpk。"""
    appname = read_manifest_field("appname")
    platform = read_manifest_field("platform") or "x86"
    for label, value in (("appname", appname), ("platform", platform)):
        if not re.fullmatch(r"[A-Za-z0-9._-]+", value):
            raise SystemExit(f"错误：manifest 的 {label}={value!r} 含非法字符，无法用于文件名")
    return f"{appname}_{version}_{platform}.fpk"


def changelog_version(title: str) -> str:
    """从 '1.1.0（2026-10-27）' 里取出 '1.1.0'。"""
    match = re.match(r"([0-9][0-9A-Za-z.\-+]*)", title)
    return match.group(1) if match else ""


def compress_changelog(items: list[str], limit: int = 2, max_chars: int = 120) -> str:
    """把条目压成 manifest 用的单行（fnOS 应用中心按一行显示）。

    应用中心那一格很窄，塞四条长条目会被截成半句话，所以只取前两条并限长。
    """
    picked = items[:limit]
    text = "；".join(picked)
    if len(items) > limit:
        text += f" 等 {len(items)} 项"
    text = text.replace("\n", " ").replace("|", "／")
    if len(text) > max_chars:
        text = text[: max_chars - 1].rstrip("；，、 ") + "…"
    return text


def patch_manifest(version: str, changelog: str) -> list[str]:
    if not MANIFEST.is_file():
        raise SystemExit(f"错误：缺少 {MANIFEST}")
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    changes: list[str] = []
    seen = {"version": False, "changelog": False}

    out: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("version") and "=" in stripped and not seen["version"]:
            key, _, old = stripped.partition("=")
            if key.strip() == "version":
                out.append(f"{key}= {version}")
                if old.strip() != version:
                    changes.append(f"version: {old.strip()} → {version}")
                seen["version"] = True
                continue
        if stripped.startswith("changelog") and "=" in stripped and not seen["changelog"]:
            key, _, old = stripped.partition("=")
            if key.strip() == "changelog":
                out.append(f"{key}= {changelog}")
                if old.strip() != changelog:
                    changes.append("changelog: 已按 CHANGELOG.md 更新")
                seen["changelog"] = True
                continue
        out.append(line)

    missing = [name for name, ok in seen.items() if not ok]
    if missing:
        raise SystemExit(f"错误：manifest 缺少字段 {', '.join(missing)}")

    # 必须显式 LF：Windows 默认行尾会让 manifest 的 version 带上 \r，
    # fnOS 做版本比较时会出现看不见的尾巴
    with open(MANIFEST, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(out) + "\n")
    return changes


def main() -> int:
    parser = argparse.ArgumentParser(description="同步版本号到 fpk manifest")
    parser.add_argument("--check", action="store_true", help="只校验不写入")
    parser.add_argument(
        "--name", action="store_true", help="打印产物文件名并校验 manifest 版本，不写入"
    )
    args = parser.parse_args()

    version = read_version()
    title, items = read_latest_changelog()
    doc_version = changelog_version(title)

    if doc_version != version:
        print(
            f"错误：版本不一致 —— dwm/__init__.py 是 {version}，"
            f"CHANGELOG.md 最新一节是 {doc_version or title!r}。\n"
            f"      请用 python3 tools/bump_version.py 统一修改，或手工同步这两处。",
            file=sys.stderr,
        )
        return 1

    changelog = compress_changelog(items)
    if not changelog:
        print("错误：最新版本小节里没有任何 '- ' 条目", file=sys.stderr)
        return 1

    def manifest_version() -> str:
        actual = read_manifest_field("version")
        if actual != version:
            print(f"错误：manifest version={actual!r}，应为 {version!r}", file=sys.stderr)
            raise SystemExit(1)
        return actual

    if args.check:
        manifest_version()
        print(f"版本校验通过：v{version}")
        return 0

    if args.name:
        # 先确认 manifest 已是目标版本，否则文件名会带错误的版本号
        manifest_version()
        print(artifact_name(version))
        return 0

    changes = patch_manifest(version, changelog)
    print(f"版本同步完成：v{version}")
    for change in changes:
        print(f"  - {change}")
    if not changes:
        print("  - manifest 已是目标版本，无需改动")
    print(f"  - changelog 摘要：{changelog}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
