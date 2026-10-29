"""disk-wake-monitor —— 追踪谁唤醒了休眠硬盘。

面向飞牛 fnOS（Debian 12）等 Linux NAS，纯标准库实现。

版本号唯一来源：本文件的 __version__。
- 运行时：dwmctl --version / probe、面板 /api/health 都读它
- 打包时：tools/sync_version.py 把它连同 CHANGELOG 最新条目写进 fpk-src/manifest
改版本请用 tools/bump_version.py，不要手改 manifest 的 version。
"""

__version__ = "1.3.0"
