#!/usr/bin/env python3
"""修正 .fpk 内的文件权限与行尾（跨平台可靠，不依赖 MSYS chmod）。

Windows 上打出来的包有两个坑，都会在 fnOS 上出真实故障：

1. 脚本一律是 0666 —— 缺执行位直接启动失败，这是 fpk 安装故障的头号原因
2. 文本文件是 CRLF —— manifest 的 `version = 1.3.0\\r` 会让版本比较出现
   看不见的尾巴，sh 脚本带 CR 则会报 bad interpreter

本脚本在 fnpack build 之后跑一遍：
  - 外层 cmd/* 与 cmd 子目录          → 0755
  - app.tgz 内部 bin/* 可执行文件     → 0755
  - 文本文件（manifest/cmd/config/wizard、代码与文档）→ 统一为 LF

用法：python tools/fix_fpk_perm.py <path.fpk>
"""

from __future__ import annotations

import gzip
import io
import sys
import tarfile

EXEC_FILES = {"bin/dwmctl"}

TEXT_SUFFIXES = (
    ".py",
    ".md",
    ".txt",
    ".json",
    ".js",
    ".css",
    ".html",
    ".sh",
    ".cfg",
    ".conf",
)
TEXT_NAMES = {"manifest", "bin/dwmctl"}


def _is_text(name: str) -> bool:
    base = name.rsplit("/", 1)[-1]
    if base in TEXT_NAMES:
        return True
    return name.endswith(TEXT_SUFFIXES)


def _to_lf(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


def fix_inner_app(app_bytes: bytes) -> bytes:
    inner = tarfile.open(fileobj=io.BytesIO(app_bytes), mode="r:*")
    buf = io.BytesIO()
    # app.tgz 在包内是 gzip 压缩的 tar，重写时必须保持，否则体积和安装器预期都会变
    out = tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.GNU_FORMAT)
    changed = []
    eol = []
    for member in inner.getmembers():
        payload = inner.extractfile(member).read() if member.isfile() else None
        if member.isfile():
            if member.name in EXEC_FILES:
                member.mode = 0o755
                changed.append(member.name)
            if _is_text(member.name) and payload is not None and b"\r\n" in payload:
                payload = _to_lf(payload)
                eol.append(member.name)
            member.size = len(payload) if payload is not None else 0
        out.addfile(member, io.BytesIO(payload) if payload is not None else None)
    out.close()
    inner.close()
    if changed:
        print("  app.tgz: +x %s" % ", ".join(changed))
    if eol:
        print("  app.tgz: CRLF→LF %s" % ", ".join(eol[:6]))
    return buf.getvalue()


def main(argv: list) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    path = argv[1]

    outer = tarfile.open(path, "r:gz")
    members = outer.getmembers()
    payloads = {m.name: outer.extractfile(m).read() for m in members if m.isfile()}
    outer.close()

    buf = io.BytesIO()
    out = tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT)
    fixed = []
    eol_fixed = []
    for member in members:
        if member.isfile():
            payload = payloads[member.name]
            if member.name == "app.tgz":
                member.mode = 0o755
                payload = fix_inner_app(payload)
                fixed.append("app.tgz")
            elif member.name.startswith("cmd/"):
                member.mode = 0o755
                fixed.append(member.name)
            else:
                member.mode = 0o644
            if member.name != "app.tgz" and _is_text(member.name) and b"\r\n" in payload:
                payload = _to_lf(payload)
                eol_fixed.append(member.name)
            payloads[member.name] = payload
            # 关键：负载可能被重写过，头部 size 必须同步，否则包会被截断
            member.size = len(payload)
        out.addfile(member, io.BytesIO(payloads[member.name]) if member.isfile() else None)
    out.close()

    with open(path, "wb") as handle:
        with gzip.GzipFile(filename="", mode="wb", fileobj=handle, mtime=0) as gz:
            gz.write(buf.getvalue())

    print("permissions fixed: %d entries" % len(fixed))
    for name in fixed:
        print("  +x %s" % name)
    if eol_fixed:
        print("line endings fixed (CRLF→LF): %s" % ", ".join(eol_fixed))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
