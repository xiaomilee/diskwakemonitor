#!/usr/bin/env bash
# 安装 / 卸载 disk-wake-monitor
#
#   sudo ./install.sh                  安装（默认 /opt/disk-wake-monitor）
#   sudo ./install.sh --with-deps      安装并自动 apt 安装 fatrace + smartmontools
#   sudo ./install.sh --uninstall      停止并移除服务（保留数据库）
set -euo pipefail

PREFIX="${PREFIX:-/opt/disk-wake-monitor}"
CONF_DIR="/etc/disk-wake-monitor"
DATA_DIR="/var/lib/disk-wake-monitor"
SERVICE="disk-wake-monitor"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WITH_DEPS=0
UNINSTALL=0
for arg in "$@"; do
  case "$arg" in
    --with-deps) WITH_DEPS=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
    *) echo "未知参数：$arg" >&2; exit 1 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "需要 root 权限：sudo $0 $*" >&2
  exit 1
fi

# ---------------------------------------------------------------- 卸载
if [ "$UNINSTALL" -eq 1 ]; then
  echo "==> 停止并移除服务"
  systemctl stop "$SERVICE" 2>/dev/null || true
  systemctl disable "$SERVICE" 2>/dev/null || true
  rm -f "/etc/systemd/system/${SERVICE}.service"
  systemctl daemon-reload
  rm -rf "$PREFIX"
  echo "已移除程序与服务。"
  echo "数据库与配置保留在：$DATA_DIR  $CONF_DIR"
  echo "确认不再需要后可手动删除：rm -rf $DATA_DIR $CONF_DIR"
  exit 0
fi

# ---------------------------------------------------------------- 前置检查
if [ ! -e /proc/diskstats ]; then
  echo "错误：/proc/diskstats 不存在，这不像 Linux 环境" >&2
  exit 1
fi

PY="$(command -v python3 || true)"
if [ -z "$PY" ]; then
  echo "错误：未找到 python3" >&2
  exit 1
fi
PY_OK="$("$PY" -c 'import sys; print(1 if sys.version_info >= (3,9) else 0)')"
if [ "$PY_OK" != "1" ]; then
  echo "错误：需要 Python 3.9+，当前 $("$PY" -V 2>&1)" >&2
  exit 1
fi
echo "==> Python: $("$PY" -V 2>&1)"

# ---------------------------------------------------------------- 可选依赖
if [ "$WITH_DEPS" -eq 1 ]; then
  echo "==> 安装辅助工具 fatrace / smartmontools"
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y fatrace smartmontools || {
      echo "警告：自动安装失败，可手动执行：apt install fatrace smartmontools" >&2
    }
  else
    echo "警告：非 apt 系统，请自行安装 fatrace 与 smartmontools" >&2
  fi
fi

# ---------------------------------------------------------------- 复制程序
echo "==> 安装到 $PREFIX"
mkdir -p "$PREFIX" "$CONF_DIR" "$DATA_DIR"
rm -rf "$PREFIX/dwm" "$PREFIX/web"
cp -r "$SRC_DIR/dwm" "$PREFIX/dwm"
cp -r "$SRC_DIR/web" "$PREFIX/web"
cp "$SRC_DIR/README.md" "$PREFIX/README.md" 2>/dev/null || true

# 清掉可能带过来的字节码，避免版本不一致
find "$PREFIX" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

install -d /usr/local/bin
cat > /usr/local/bin/dwmctl <<EOF
#!/usr/bin/env bash
exec "$PY" "$PREFIX/bin/dwmctl" "\$@"
EOF
chmod 0755 /usr/local/bin/dwmctl

# ---------------------------------------------------------------- 配置
if [ -f "$CONF_DIR/config.json" ]; then
  echo "==> 保留已有配置 $CONF_DIR/config.json"
else
  cp "$SRC_DIR/config.example.json" "$CONF_DIR/config.json"
  echo "==> 生成默认配置 $CONF_DIR/config.json"
fi

# ---------------------------------------------------------------- 自检
echo
echo "==> 环境自检"
echo "------------------------------------------------------------"
"$PY" "$PREFIX/bin/dwmctl" probe || true
echo "------------------------------------------------------------"
echo

# ---------------------------------------------------------------- 服务
echo "==> 注册 systemd 服务"
sed "s#/opt/disk-wake-monitor#$PREFIX#g" "$SRC_DIR/systemd/${SERVICE}.service" \
  > "/etc/systemd/system/${SERVICE}.service"
chmod 0644 "/etc/systemd/system/${SERVICE}.service"
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null

echo
echo "安装完成。常用命令："
echo "  systemctl start  $SERVICE      # 启动采集"
echo "  systemctl status $SERVICE      # 查看状态"
echo "  journalctl -u $SERVICE -f      # 跟随日志"
echo "  dwmctl wakes --hours 24        # 命令行看唤醒记录"
echo
echo "面板默认只监听 127.0.0.1。要在局域网打开，编辑 $CONF_DIR/config.json："
echo "  \"host\": \"0.0.0.0\""
echo "并在前面加一层访问控制（例如 Nginx 反代 + 认证），或设置 \"auth_token\"。"
echo
echo "然后：systemctl start $SERVICE"
echo "访问：http://<NAS-IP>:8765/"
