"""集中配置：默认值 → JSON 配置文件 → 环境变量覆盖，启动时集中校验、快速失败。

覆盖优先级（后者覆盖前者）：
    dataclass 默认值  →  config.json  →  环境变量 DWM_*

环境变量名 = DWM_ + 字段名大写，例如 idle_threshold_seconds → DWM_IDLE_THRESHOLD_SECONDS
列表型字段用逗号分隔，例如 DWM_MONITOR_DEVICES=sdb,sdc
"""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .errors import ConfigError

ENV_PREFIX = "DWM_"

# 按优先级尝试的默认配置文件路径
DEFAULT_CONFIG_PATHS = (
    "/etc/disk-wake-monitor/config.json",
    "/opt/disk-wake-monitor/config.json",
    "./config.json",
)


@dataclass
class Config:
    # ---- 存储 ----
    data_dir: str = "/var/lib/disk-wake-monitor"
    db_path: str = ""  # 留空则 = <data_dir>/monitor.db
    retention_hours: float = 168.0  # 7 天

    # ---- Web 面板 ----
    host: str = "127.0.0.1"  # 局域网访问需显式改为 0.0.0.0
    port: int = 8765
    auth_token: str = ""  # 非空则所有 /api 请求需带 token

    # ---- 采集节奏 ----
    poll_interval: float = 1.0  # /proc/diskstats 轮询间隔（秒）
    idle_threshold_seconds: float = 120.0  # 多久无 IO 视为「已休眠」
    smart_interval: float = 60.0  # SMART 电源态轮询间隔（秒）
    smart_enabled: bool = True
    smartctl_binary: str = "smartctl"
    smart_timeout: float = 15.0
    # 某些廉价 USB 桥接盒会永远回报「active」，此时 SMART 电源态不可信。
    # 置为 true 则忽略 SMART 的 active 结论，一律按「久静后 IO」推断唤醒。
    assume_sleep_on_idle: bool = False

    # ---- 事件源 ----
    fatrace_enabled: bool = True
    fatrace_binary: str = "fatrace"
    fatrace_filter: str = "OCW"  # O=open R=read W=write C=close-write
    blockdump_fallback: bool = True  # fatrace 不可用时自动启用 block_dump
    blockdump_enabled: bool = False  # 强制启用 block_dump

    # ---- 设备选择 ----
    monitor_only_sleepable: bool = True
    monitor_devices: List[str] = field(default_factory=list)  # 强制监控，如 ["sdb"]
    exclude_devices: List[str] = field(default_factory=list)

    # ---- 归因窗口 ----
    suspect_lookback_seconds: float = 5.0
    suspect_lookahead_seconds: float = 3.0
    dedupe_window_seconds: float = 10.0
    ring_buffer_size: int = 20000

    log_level: str = "INFO"

    # 这些进程自身产生的 IO 不计入归因（避免观测者干扰观测结果）
    ignore_comms: List[str] = field(
        default_factory=lambda: ["dwm", "dwmctl", "fatrace", "dmesg", "smartctl"]
    )

    # ------------------------------------------------------------------
    @property
    def resolved_db_path(self) -> str:
        return self.db_path or str(Path(self.data_dir) / "monitor.db")

    def to_dict(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["db_path_resolved"] = self.resolved_db_path
        return data


def _find_config_file(explicit: Optional[str]) -> Optional[str]:
    if explicit:
        if not os.path.isfile(explicit):
            raise ConfigError(
                f"指定的配置文件不存在：{explicit}",
                hint="检查路径，或去掉 --config 让其自动查找",
            )
        return explicit
    for candidate in DEFAULT_CONFIG_PATHS:
        if os.path.isfile(candidate):
            return candidate
    return None


def _coerce(raw: str, current: Any, name: str) -> Any:
    """按字段当前类型把环境变量字符串转成目标类型。"""
    if isinstance(current, bool):
        lowered = raw.strip().lower()
        if lowered in ("1", "true", "yes", "on"):
            return True
        if lowered in ("0", "false", "no", "off", ""):
            return False
        raise ConfigError(
            f"环境变量 {ENV_PREFIX}{name.upper()} 需要布尔值（true/false），收到 {raw!r}"
        )
    if isinstance(current, list):
        return [item.strip() for item in raw.split(",") if item.strip()]
    if isinstance(current, int) and not isinstance(current, bool):
        try:
            return int(raw)
        except ValueError as exc:
            raise ConfigError(
                f"环境变量 {ENV_PREFIX}{name.upper()} 需要整数，收到 {raw!r}"
            ) from exc
    if isinstance(current, float):
        try:
            return float(raw)
        except ValueError as exc:
            raise ConfigError(
                f"环境变量 {ENV_PREFIX}{name.upper()} 需要数字，收到 {raw!r}"
            ) from exc
    return raw


def validate(cfg: Config) -> Config:
    """集中校验，任何问题都抛 ConfigError 并给出可操作提示。"""
    problems: List[str] = []

    if not (1 <= cfg.port <= 65535):
        problems.append(f"port 必须在 1-65535 之间，当前 {cfg.port}")
    if cfg.poll_interval <= 0:
        problems.append("poll_interval 必须大于 0")
    if cfg.idle_threshold_seconds <= 0:
        problems.append("idle_threshold_seconds 必须大于 0")
    if cfg.smart_interval <= 0:
        problems.append("smart_interval 必须大于 0")
    if cfg.retention_hours <= 0:
        problems.append("retention_hours 必须大于 0")
    if cfg.ring_buffer_size < 100:
        problems.append("ring_buffer_size 不能小于 100")
    if cfg.suspect_lookback_seconds < 0 or cfg.suspect_lookahead_seconds < 0:
        problems.append("归因窗口不能为负数")
    if cfg.log_level.upper() not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        problems.append(f"log_level 非法：{cfg.log_level}")
    for dev in cfg.monitor_devices + cfg.exclude_devices:
        if not isinstance(dev, str) or not dev.strip():
            problems.append("monitor_devices / exclude_devices 含空字符串")

    if problems:
        raise ConfigError(
            "配置校验未通过：\n  - " + "\n  - ".join(problems),
            hint="修正后再启动；可用 dwmctl probe 查看当前生效配置",
        )

    # data_dir 必须可创建可写
    try:
        Path(cfg.data_dir).mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ConfigError(
            f"无法创建数据目录 {cfg.data_dir}：{exc}",
            hint="确认运行用户有写权限，或改 data_dir / DWM_DATA_DIR",
        ) from exc
    return cfg


def load(config_file: Optional[str] = None, *, use_env: bool = True) -> Config:
    """加载并校验配置。"""
    cfg = Config()

    path = _find_config_file(config_file)
    if path:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(
                f"读取配置文件失败 {path}：{exc}",
                hint="确认是合法 JSON（不含注释、末尾无多余逗号）",
            ) from exc
        if not isinstance(payload, dict):
            raise ConfigError(f"配置文件 {path} 顶层必须是对象")

        valid_names = {f.name for f in dataclasses.fields(Config)}
        unknown = set(payload) - valid_names
        if unknown:
            raise ConfigError(
                f"配置文件 {path} 含未知字段：{', '.join(sorted(unknown))}",
                hint=f"可用字段：{', '.join(sorted(valid_names))}",
            )
        for key, value in payload.items():
            setattr(cfg, key, value)

    if use_env:
        for f in dataclasses.fields(Config):
            env_key = ENV_PREFIX + f.name.upper()
            if env_key in os.environ:
                setattr(
                    cfg,
                    f.name,
                    _coerce(os.environ[env_key], getattr(cfg, f.name), f.name),
                )

    return validate(cfg)


def dependency_report(cfg: Config) -> Dict[str, Any]:
    """检查外部依赖（不抛异常，供 probe 使用）。"""
    fatrace_path = shutil.which(cfg.fatrace_binary)
    smartctl_path = shutil.which(cfg.smartctl_binary)
    return {
        "fatrace": {
            "configured": cfg.fatrace_enabled,
            "path": fatrace_path,
            "ok": bool(fatrace_path),
        },
        "smartctl": {
            "configured": cfg.smart_enabled,
            "path": smartctl_path,
            "ok": bool(smartctl_path),
        },
        "block_dump_sysctl": os.path.exists("/proc/sys/vm/block_dump"),
        "proc_diskstats": os.path.exists("/proc/diskstats"),
        "sys_block": os.path.isdir("/sys/block"),
    }
