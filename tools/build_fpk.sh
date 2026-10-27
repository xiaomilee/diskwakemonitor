#!/usr/bin/env bash
# 构建 fnOS 应用包（.fpk）
#
# 用法：
#   bash tools/build_fpk.sh              # 同步代码 → 生成图标 → fnpack build
#
# 前置：
#   1. Python 3（本机或 NAS 上都有）
#   2. fnpack 打包工具，按平台从官方下载后放到 .build/ 下或加入 PATH：
#      https://static2.fnnas.com/fnpack/fnpack-1.2.3-<os>-<arch>
#      例：fnpack-1.2.3-windows-amd64 / fnpack-1.2.3-linux-amd64
#
# 产物：dist/diskwakemonitor_<version>_x86.fpk
#       文件名遵循 fnOS 规范 {appname}_{version}_{platform}.fpk，
#       版本与平台均从 manifest / dwm/__init__.py 派生，不在此处硬编码。
#       旧版本产物自动移入 dist/archive/，dist/ 下始终只有当前版本，避免装错。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/fpk-src"
DIST="$ROOT/dist"

cd "$ROOT"

# ---------------------------------------------------------------- 1. 同步应用代码
echo "==> 同步应用代码到 fpk-src/app"
rm -rf "$SRC/app/dwm" "$SRC/app/web" "$SRC/app/bin"
mkdir -p "$SRC/app/bin"
cp -r "$ROOT/dwm" "$SRC/app/dwm"
cp -r "$ROOT/web" "$SRC/app/web"
cp "$ROOT/bin/dwmctl" "$SRC/app/bin/dwmctl"
cp "$ROOT/README.md" "$SRC/app/README.md" 2>/dev/null || true
cp "$ROOT/CHANGELOG.md" "$SRC/app/CHANGELOG.md" 2>/dev/null || true
cp "$ROOT/LICENSE" "$SRC/app/LICENSE" 2>/dev/null || true

# 字节码和系统垃圾不要打进包里
find "$SRC/app" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$SRC/app" -name '.DS_Store' -delete 2>/dev/null || true
find "$SRC/app" -name '*.pyc' -delete 2>/dev/null || true

# ---------------------------------------------------------------- 2. 版本号
# 唯一来源是 dwm/__init__.py 的 __version__：这里写进 manifest 的 version 与
# changelog，并校验 CHANGELOG.md 最新一节与之一致，不一致直接失败。
echo "==> 同步版本号"
python3 "$ROOT/tools/sync_version.py"

# ---------------------------------------------------------------- 3. 图标
echo "==> 生成应用图标"
python3 "$ROOT/tools/gen_fpk_icons.py" "$SRC"

# ---------------------------------------------------------------- 4. 行尾符检查
# 生命周期脚本必须以 LF 结尾，CRLF 会让 fnOS 报 bad interpreter
crlf_found=0
for f in "$SRC"/cmd/*; do
  if head -c 2000 "$f" | grep -q $'\r'; then
    echo "错误：$f 含 CRLF 行尾，已自动转换"
    sed -i 's/\r$//' "$f"
    crlf_found=1
  fi
done
[ "$crlf_found" -eq 1 ] && echo "已修复行尾符" || echo "行尾符检查通过（LF）"

# ---------------------------------------------------------------- 5. 打包
FNPACK=""
for candidate in "$(command -v fnpack 2>/dev/null || true)" \
                 "$ROOT/.build/fnpack" "$ROOT/.build/fnpack.exe"; do
  if [ -n "$candidate" ] && [ -x "$candidate" ]; then
    FNPACK="$candidate"
    break
  fi
done
if [ -z "$FNPACK" ]; then
  echo "错误：未找到 fnpack。请从 https://developer.fnnas.com/docs/cli/fnpack 下载，" >&2
  echo "放到 $ROOT/.build/ 下（Linux/macOS 版记得 chmod +x）或加入 PATH。" >&2
  exit 1
fi

echo "==> fnpack build（$FNPACK）"
mkdir -p "$DIST"
(cd "$SRC" && "$FNPACK" build)

built="$(ls -t "$SRC"/*.fpk 2>/dev/null | head -n 1 || true)"
if [ -z "$built" ]; then
  echo "错误：fnpack 未产出 .fpk，请检查上方输出" >&2
  exit 1
fi

# fnpack 只会产出 appname.fpk，按 fnOS 规范重命名为 appname_version_platform.fpk。
# 文件名由 sync_version.py --name 派生（会先校验 manifest 版本一致性）。
ARTIFACT="$(python3 "$ROOT/tools/sync_version.py" --name)"
if [ -z "$ARTIFACT" ]; then
  echo "错误：无法确定产物文件名" >&2
  exit 1
fi
mv -f "$built" "$DIST/$ARTIFACT"
TARGET="$DIST/$ARTIFACT"

# 历史版本移到 dist/archive/，保证 dist/ 顶层只有当前版本
ARCHIVE="$DIST/archive"
for old in "$DIST"/*.fpk; do
  [ -e "$old" ] || continue
  [ "$old" = "$TARGET" ] && continue
  mkdir -p "$ARCHIVE"
  mv -f "$old" "$ARCHIVE/"
  echo "    旧版本已归档：archive/$(basename "$old")"
done

# Windows 上打的包会丢失执行位（0666），fnOS 上会启动失败，这里统一修正
echo "==> 修正包内脚本执行位"
python3 "$ROOT/tools/fix_fpk_perm.py" "$TARGET"

# 最后一道校验：文件名里的版本必须与包内 manifest / 代码一致
echo "==> 校验产物版本一致性"
python3 - "$TARGET" <<'PY'
import io, re, sys, tarfile
from pathlib import Path

target = Path(sys.argv[1])
code_version = re.search(
    r'__version__\s*=\s*"([^"]+)"', Path("dwm/__init__.py").read_text(encoding="utf-8")
).group(1)
tf = tarfile.open(target, "r:gz")
manifest = tf.extractfile("manifest").read().decode("utf-8")
pkg_version = re.search(r"^version\s*=\s*(.+)$", manifest, re.M).group(1).strip()
platform = re.search(r"^platform\s*=\s*(.+)$", manifest, re.M).group(1).strip()
appname = re.search(r"^appname\s*=\s*(.+)$", manifest, re.M).group(1).strip()

problems = []
if pkg_version != code_version:
    problems.append(f"包内 manifest 版本 {pkg_version} ≠ 代码版本 {code_version}")
if target.name != f"{appname}_{pkg_version}_{platform}.fpk":
    problems.append(f"文件名 {target.name} 不符合 {{appname}}_{{version}}_{{platform}}.fpk")
if problems:
    print("错误：", *problems, sep="\n  ", file=sys.stderr)
    sys.exit(1)

print(f"    文件名版本 = 包内版本 = 代码版本 = v{pkg_version}（{platform}）✓")
PY

echo
echo "==> 完成"
ls -la "$TARGET"
python3 - <<'PY'
import re
from pathlib import Path
version = re.search(r'__version__\s*=\s*"([^"]+)"', Path("dwm/__init__.py").read_text(encoding="utf-8")).group(1)
print(f"    版本：v{version}")
PY
if [ -d "$ARCHIVE" ]; then
  echo "    历史版本目录：$ARCHIVE"
fi
