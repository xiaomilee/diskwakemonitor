#!/usr/bin/env python3
"""修正 .fpk 内的文件权限（跨平台可靠，不依赖 MSYS chmod）。

Windows 上打出来的包，脚本一律是 0666——fnOS 上会因缺执行位直接启动失败，
这是 fpk 安装故障的头号常见原因。本脚本在 fnpack build 之后跑一遍：

  - 外层 cmd/* 与 cmd 子目录          → 0755
  - app.tgz 内部 bin/* 可执行文件     → 0755
  - 其余成员保持 fnpack 原始产物不变

用法：python tools/fix_fpk_perm.py <path.fpk>
"""

from __future__ import annotations

import gzip
import io
import sys
import tarfile

EXEC_FILES = {"bin/dwmctl"}


def fix_inner_app(app_bytes: bytes) -> bytes:
    inner = tarfile.open(fileobj=io.BytesIO(app_bytes), mode="r:*")
    buf = io.BytesIO()
    # app.tgz 在包内是 gzip 压缩的 tar，重写时必须保持，否则体积和安装器预期都会变
    out = tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.GNU_FORMAT)
    changed = []
    for member in inner.getmembers():
        if member.isfile() and member.name in EXEC_FILES:
            member.mode = 0o755
            changed.append(member.name)
        out.addfile(member, inner.extractfile(member) if member.isfile() else None)
    out.close()
    inner.close()
    if changed:
        print("  app.tgz: +x %s" % ", ".join(changed))
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
    for member in members:
        if member.isfile():
            if member.name == "app.tgz":
                member.mode = 0o755
                payloads[member.name] = fix_inner_app(payloads[member.name])
                fixed.append("app.tgz")
            elif member.name.startswith("cmd/"):
                member.mode = 0o755
                fixed.append(member.name)
            else:
                member.mode = 0o644
            # 关键：负载可能被重写过，头部 size 必须同步，否则包会被截断
            member.size = len(payloads[member.name])
        out.addfile(member, io.BytesIO(payloads[member.name]) if member.isfile() else None)
    out.close()

    with open(path, "wb") as handle:
        with gzip.GzipFile(filename="", mode="wb", fileobj=handle, mtime=0) as gz:
            gz.write(buf.getvalue())

    print("permissions fixed: %d entries" % len(fixed))
    for name in fixed:
        print("  +x %s" % name)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
