#!/usr/bin/env python3
"""升级版本号：同时改唯一来源与变更日志，避免两处不一致。

用法：
    python3 tools/bump_version.py 1.2.0 "一句话概述本次发布"
    python3 tools/bump_version.py --show          # 只看当前版本

做的事：
    1. 校验新版本号格式（X.Y.Z）且必须大于当前版本
    2. 改写 dwm/__init__.py 的 __version__
    3. 在 CHANGELOG.md 顶部插入新小节（日期取今天），并把概述写成第一条
    4. 调用 tools/sync_version.py 把版本写进 fpk manifest

之后运行 bash tools/build_fpk.sh 出包。
"""

from __future__ import annotations

import argparse
import datetime as _dt
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INIT_FILE = ROOT / "dwm" / "__init__.py"
CHANGELOG = ROOT / "CHANGELOG.md"

semver_re = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_version_re = re.compile(r"""^__version__\s*=\s*["']([^"']+)["']""", re.M)


def parse(version: str) -> tuple[int, int, int]:
    match = semver_re.match(version)
    if not match:
        raise SystemExit(f"错误：版本号必须形如 1.2.3，收到 {version!r}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def current() -> str:
    match = _version_re.search(INIT_FILE.read_text(encoding="utf-8"))
    if not match:
        raise SystemExit(f"错误：{INIT_FILE} 里找不到 __version__")
    return match.group(1)


def write_version(version: str) -> None:
    text = INIT_FILE.read_text(encoding="utf-8")
    INIT_FILE.write_text(_version_re.sub(f'__version__ = "{version}"', text), encoding="utf-8")


def prepend_changelog(version: str, summary: str) -> None:
    today = _dt.date.today().isoformat()
    section = f"## {version}（{today}）\n\n- {summary}\n\n"
    text = CHANGELOG.read_text(encoding="utf-8")
    # 必须锚定「行首的 ## 标题」：文档说明行里的反引号内也可能出现 "## "，
    # 用普通 find 会插进句子中间，把 CHANGELOG 截断（1.2.0 发布时踩过）。
    match = re.search(r"^## ", text, re.M)
    if not match:
        raise SystemExit("错误：CHANGELOG.md 里没有 '## ' 小节，无法插入")
    index = match.start()
    CHANGELOG.write_text(text[:index] + section + text[index:], encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="升级版本号")
    parser.add_argument("version", nargs="?", help="新版本号，如 1.2.0")
    parser.add_argument("summary", nargs="?", default="", help="一句话概述（写入变更日志）")
    parser.add_argument("--show", action="store_true", help="只显示当前版本")
    args = parser.parse_args()

    old = current()
    if args.show or not args.version:
        print(f"当前版本：v{old}")
        return 0

    new = args.version.lstrip("v")
    if parse(new) <= parse(old):
        raise SystemExit(f"错误：新版本 {new} 必须大于当前 {old}")

    write_version(new)
    prepend_changelog(new, args.summary or "（待补充）")
    print(f"版本：v{old} → v{new}")

    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "sync_version.py")],
        cwd=str(ROOT),
    )
    if result.returncode != 0:
        print("警告：manifest 同步失败，请手动运行 tools/sync_version.py", file=sys.stderr)
        return result.returncode
    print("下一步：补充 CHANGELOG.md 条目后运行 bash tools/build_fpk.sh")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
