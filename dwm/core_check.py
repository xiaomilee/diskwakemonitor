"""环境自检。

设计原则：每一项都给出「能不能用 / 缺什么 / 怎么修」，让人不用翻文档就能定位问题。
在有 root 的飞牛上跑一次 dwmctl probe，基本能排除 90% 的启动失败原因。
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from typing import Any, Dict, List, Optional

from .config import Config, dependency_report
from .devices import enumerate_devices
from .errors import DeviceError
from .sources import FanotifySource, probe_fatrace

CheckList = List[Dict[str, str]]


def _check(name: str, level: str, detail: str, hint: str = "") -> Dict[str, str]:
    return {"name": name, "level": level, "detail": detail, "hint": hint}


def _python_check() -> Dict[str, str]:
    version = sys.version_info
    detail = f"{version.major}.{version.minor}.{version.micro}"
    if version < (3, 9):
        return _check("Python 版本", "fail", detail, "需要 Python 3.9+（飞牛自带 3.11）")
    return _check("Python 版本", "ok", detail)


def _platform_check() -> Dict[str, str]:
    if not os.path.exists("/proc/diskstats"):
        return _check(
            "运行平台",
            "fail",
            f"{platform.system()}（缺少 /proc/diskstats）",
            "本工具依赖 Linux 内核接口，只能在飞牛 fnOS / Debian 等 Linux 上运行",
        )
    try:
        kernel = os.uname().release
    except AttributeError:  # pragma: no cover
        kernel = "unknown"
    return _check("运行平台", "ok", f"Linux {kernel}")


def _root_check(deep: bool) -> Dict[str, str]:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:  # pragma: no cover - 非 POSIX
        return _check("权限", "warn", "无法判断（非 POSIX 环境）")
    uid = geteuid()
    if uid == 0:
        return _check("权限", "ok", "root")
    return _check(
        "权限",
        "fail",
        f"当前 uid={uid}，非 root",
        "fanotify 与 block_dump 都需要 root：sudo dwmctl probe",
    )


def _smart_check(cfg: Config, deep: bool) -> List[Dict[str, str]]:
    checks: List[Dict[str, str]] = []
    path = shutil.which(cfg.smartctl_binary)
    if not path:
        checks.append(
            _check(
                "smartctl",
                "warn",
                "未安装",
                "apt install smartmontools —— 装了才能读到硬盘真实休眠状态与启停计数",
            )
        )
        return checks

    version = ""
    if deep:
        try:
            import subprocess

            proc = subprocess.run(
                [path, "--version"], capture_output=True, text=True, timeout=10
            )
            first_line = (proc.stdout or "").splitlines()
            version = first_line[0] if first_line else ""
        except Exception:  # noqa: BLE001
            version = ""
    checks.append(
        _check("smartctl", "ok", version or path, "")
    )
    return checks


def _fatrace_check(cfg: Config, deep: bool) -> List[Dict[str, str]]:
    if not cfg.fatrace_enabled:
        return [_check("fatrace", "warn", "配置中已禁用", "如需文件级归因请设为 true")]
    if not deep:
        path = shutil.which(cfg.fatrace_binary)
        return [
            _check(
                "fatrace",
                "ok" if path else "warn",
                path or "未安装（将降级到 block_dump）",
                "" if path else "apt install fatrace",
            )
        ]

    probe = probe_fatrace(cfg.fatrace_binary)
    if probe["ok"]:
        return [
            _check(
                "fatrace",
                "ok",
                f"{probe['binary']}，输出格式 {probe['format']}（备用源）",
                "内建 fanotify 优先：fatrace 按挂载点打标记，看不到容器内的访问。",
            )
        ]
    return [
        _check(
            "fatrace",
            "warn",
            probe.get("error", "不可用"),
            "可选安装：apt install fatrace（不装也行，内建 fanotify 会顶上）",
        )
    ]


def _mounts_check(devices: List[Dict[str, Any]]) -> Dict[str, str]:
    """被监控盘必须拿到挂载点，否则文件级事件一个都落不到它头上。"""
    monitored = [d for d in devices if d["monitored"]]
    if not monitored:
        return _check("挂载点映射", "warn", "没有纳入监控的盘")
    missing = [d["name"] for d in monitored if not d.get("mounts")]
    if missing:
        return _check(
            "挂载点映射",
            "fail",
            f"{', '.join(missing)} 没有挂载点",
            "这些盘上的访问事件无法归属（会全部落进 no_dev）。"
            "确认盘已挂载；多设备 btrfs 的成员关系需要 /sys/fs/btrfs 可读",
        )
    detail = "；".join(f"{d['name']} → {', '.join(d['mounts'])}" for d in monitored)
    return _check("挂载点映射", "ok", detail)


def _fanotify_check(cfg: Config, devices: List[Dict[str, Any]], deep: bool) -> List[Dict[str, str]]:
    """内建 fanotify 源可用性，以及能否盯住整个文件系统（容器覆盖）。"""
    mounts = [
        mount
        for d in devices
        if d["monitored"]
        for mount in (d.get("mounts") or [])
    ]
    if not mounts:
        return [
            _check(
                "内建fanotify",
                "warn",
                "被监控盘都没有挂载点，无法建立监视",
                "fanotify 只能看到文件系统层事件；块层访问只能靠 /proc 句柄扫描",
            )
        ]
    if not deep:
        return [_check("内建fanotify", "ok", "将在采集时尝试（需 root）")]

    probe = FanotifySource.probe(mounts)
    if not probe["ok"]:
        return [_check("内建fanotify", "warn", probe["error"], "确认以 root 运行")]
    if probe["filesystem"]:
        return [
            _check(
                "内建fanotify",
                "ok",
                "可用，文件系统级标记（容器里的访问同样可见）",
            )
        ]
    return [
        _check(
            "内建fanotify",
            "warn",
            "可用，但只能按挂载点标记",
            "内核不支持 FAN_MARK_FILESYSTEM（需 4.20+）："
            "容器 bind mount 里的访问会漏，归因可能为空",
        )
    ]


def _blockdump_check(cfg: Config) -> Dict[str, str]:
    path = "/proc/sys/vm/block_dump"
    if not os.path.exists(path):
        return _check(
            "block_dump",
            "warn",
            "内核未提供（5.10 起已移除该功能）",
            "无需处理：内建 fanotify 源已覆盖此场景",
        )
    try:
        with open(path, "r", encoding="utf-8") as fh:
            value = fh.read().strip()
    except OSError as exc:
        return _check("block_dump", "warn", f"不可读：{exc}", "需要 root")
    writable = os.access(path, os.W_OK)
    return _check(
        "block_dump",
        "ok" if writable else "warn",
        f"当前值 {value}，{'可写' if writable else '不可写（需 root）'}",
        "" if writable else "sudo 运行才能临时开启",
    )


def _storage_check(cfg: Config) -> Dict[str, str]:
    data_dir = cfg.data_dir
    try:
        os.makedirs(data_dir, exist_ok=True)
        probe_file = os.path.join(data_dir, ".dwm_write_test")
        with open(probe_file, "w", encoding="utf-8") as fh:
            fh.write("ok")
        os.unlink(probe_file)
    except OSError as exc:
        return _check(
            "数据目录", "fail", f"{data_dir} 不可写：{exc}", "改 data_dir 或修正权限"
        )
    exists = os.path.isfile(cfg.resolved_db_path)
    return _check(
        "数据目录",
        "ok",
        f"{data_dir}（数据库{'已存在' if exists else '待创建'}）",
    )


def _devices_section(cfg: Config) -> tuple[List[Dict[str, Any]], Dict[str, str]]:
    try:
        devices = enumerate_devices(
            monitor_only_sleepable=cfg.monitor_only_sleepable,
            monitor_devices=cfg.monitor_devices,
            exclude_devices=cfg.exclude_devices,
        )
    except DeviceError as exc:
        return [], _check("块设备", "fail", str(exc), exc.hint)

    items = [dev.to_dict() for dev in devices.values()]
    monitored = [d for d in items if d["monitored"]]
    if not items:
        return items, _check("块设备", "fail", "未发现任何块设备", "")
    if not monitored:
        return items, _check(
            "块设备",
            "warn",
            f"发现 {len(items)} 个设备，但没有符合「会休眠」判定的",
            "用 DWM_MONITOR_DEVICES=sdb 强制指定，或关掉 monitor_only_sleepable",
        )
    return items, _check(
        "块设备",
        "ok",
        f"发现 {len(items)} 个设备，其中 {len(monitored)} 个纳入监控："
        f"{', '.join(d['name'] for d in monitored)}",
    )


def probe_environment(cfg: Config, deep: bool = True) -> Dict[str, Any]:
    checks: CheckList = []
    checks.append(_python_check())
    checks.append(_platform_check())
    checks.append(_root_check(deep))

    devices, device_check = _devices_section(cfg)
    checks.append(device_check)
    checks.append(_mounts_check(devices))
    checks.extend(_fatrace_check(cfg, deep))
    checks.extend(_fanotify_check(cfg, devices, deep))
    checks.extend(_smart_check(cfg, deep))
    checks.append(_blockdump_check(cfg))
    checks.append(_storage_check(cfg))

    deps = dependency_report(cfg)
    blocking = sum(1 for c in checks if c["level"] == "fail")
    warnings = sum(1 for c in checks if c["level"] == "warn")

    return {
        "version": __import__("dwm").__version__,
        "checks": checks,
        "devices": devices,
        "dependencies": deps,
        "config": cfg.to_dict(),
        "summary": {
            "blocking": blocking,
            "warnings": warnings,
            "monitored_devices": len([d for d in devices if d["monitored"]]),
        },
    }
