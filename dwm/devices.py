"""块设备发现与筛选。

数据来源全部是内核导出的只读接口：
    /sys/block/*            设备元信息（型号、可移动、 rotational）
    /proc/mounts            设备 → 挂载点
    /sys/block/<dev> → realpath 里出现 /usb 就说明是 USB 桥接（这是判断外接最可靠的办法）
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .errors import DeviceError

SYS_BLOCK = "/sys/block"
SYS_FS_BTRFS = "/sys/fs/btrfs"
PROC_MOUNTS = "/proc/mounts"

# 这些是虚拟/聚合设备，唤醒归因对它们没有意义（真正落在 sd*/nvme* 上）
VIRTUAL_PREFIXES = ("loop", "ram", "zram", "dm-", "md", "sr", "fd", "nbd")

_NVME_RE = re.compile(r"^(nvme\d+n\d+)(?:p\d+)?$")
_MMC_RE = re.compile(r"^(mmcblk\d+)(?:p\d+)?$")
_SD_RE = re.compile(r"^((?:sd|hd|vd|xvd|md|dasd)[a-z]+)(?:\d+)?$")


@dataclass
class BlockDevice:
    name: str
    model: str = ""
    transport: str = "unknown"
    removable: bool = False
    rotational: bool = False
    size_bytes: int = 0
    mounts: List[str] = field(default_factory=list)
    monitored: bool = False
    reason: str = ""

    @property
    def dev_path(self) -> str:
        return f"/dev/{self.name}"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "model": self.model,
            "transport": self.transport,
            "removable": self.removable,
            "rotational": self.rotational,
            "size_bytes": self.size_bytes,
            "mounts": self.mounts,
            "monitored": self.monitored,
            "reason": self.reason,
        }


def _read_text(path: str, default: str = "") -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return default


def _read_int(path: str, default: int = 0) -> int:
    try:
        return int(_read_text(path) or default)
    except (TypeError, ValueError):
        return default


def partition_to_disk(name: str) -> str:
    """把分区名归一到整盘名：sdb1→sdb, nvme0n1p2→nvme0n1, mmcblk0p1→mmcblk0。

    唤醒是以整盘为单位的，归因必须先归到整盘。
    """
    name = name.strip()
    if name.startswith("/dev/"):
        name = name[5:]
    for pattern in (_NVME_RE, _MMC_RE, _SD_RE):
        match = pattern.match(name)
        if match:
            return match.group(1)
    return name


def detect_transport(name: str) -> str:
    """靠 sysfs 符号链路判断总线类型。"""
    try:
        real = os.path.realpath(os.path.join(SYS_BLOCK, name))
    except OSError:
        return "unknown"
    lowered = real.lower()
    if "/usb" in lowered:
        return "usb"
    if "nvme" in lowered:
        return "nvme"
    if "virtio" in lowered:
        return "virtio"
    if "mmc" in lowered:
        return "mmc"
    if "/ata" in lowered or "sata" in lowered:
        return "ata"
    if "scsi" in lowered:
        return "scsi"
    return "unknown"


def _array_members(name: str, sys_block: str = SYS_BLOCK) -> List[str]:
    """如果 name 是 md/DM 等阵列设备，返回成员分区名列表（如 ['sda1']）。

    fnOS 的存储空间普遍经 md/DM/btrfs 挂载到 /vol1：/proc/mounts 里的设备
    是 /dev/md0 而不是 /dev/sda1。成员关系在 /sys/block/<阵列>/slaves/ 下。
    """
    slaves_dir = os.path.join(sys_block, name, "slaves")
    try:
        return sorted(os.listdir(slaves_dir))
    except OSError:
        return []


def _btrfs_member_map(sys_fs_btrfs: str = SYS_FS_BTRFS) -> Dict[str, List[str]]:
    """btrfs 多设备文件系统的成员关系：整盘名 → 同组所有整盘名。

    物理盘没有 /sys/block/<盘>/slaves，btrfs 的成员关系只在
    /sys/fs/btrfs/<uuid>/devices/ 下（目录项名就是 sda1 / sdb1 这种设备名）。
    不做这一步的话，多设备 btrfs 只有 /proc/mounts 里写的那一块能拿到挂载点。
    """
    result: Dict[str, List[str]] = {}
    try:
        uuids = os.listdir(sys_fs_btrfs)
    except OSError:
        return result
    for uuid in uuids:
        devices_dir = os.path.join(sys_fs_btrfs, uuid, "devices")
        try:
            members = os.listdir(devices_dir)
        except OSError:
            continue
        disks: List[str] = []
        for member in members:
            disk = partition_to_disk(member)
            if disk and disk not in disks:
                disks.append(disk)
        if len(disks) < 2:
            continue
        for disk in disks:
            group = result.setdefault(disk, [])
            for other in disks:
                if other != disk and other not in group:
                    group.append(other)
    return result


def read_mounts(
    *,
    mounts_file: str = PROC_MOUNTS,
    sys_block: str = SYS_BLOCK,
    sys_fs_btrfs: str = SYS_FS_BTRFS,
) -> Dict[str, List[str]]:
    """返回 整盘名 → 挂载点列表。

    关键处理：挂载在阵列（md/dm/btrfs 多设备）上时，把挂载点同时映射到所有
    成员盘，否则成员盘的 mounts 为空、路径归属会全部失配（fnOS 典型场景）。
    """
    mapping: Dict[str, List[str]] = {}
    try:
        with open(mounts_file, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError as exc:
        raise DeviceError(
            f"无法读取 {mounts_file}：{exc}",
            hint="确认在 Linux 上运行（非 Linux 环境无法采集）",
        ) from exc

    btrfs_groups = _btrfs_member_map(sys_fs_btrfs)

    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue
        source, mountpoint = parts[0], parts[1]
        if not source.startswith("/dev/"):
            continue
        # /dev/disk/by-uuid/xxx 之类的符号链接要解到真实设备
        try:
            real = os.path.realpath(source)
        except OSError:
            real = source
        disk = partition_to_disk(os.path.basename(real))
        if not disk:
            continue
        targets = [disk]
        for member in _array_members(disk, sys_block):
            member_disk = partition_to_disk(member)
            if member_disk and member_disk not in targets:
                targets.append(member_disk)
        for sibling in btrfs_groups.get(disk, []):
            if sibling not in targets:
                targets.append(sibling)
        for target in targets:
            bucket = mapping.setdefault(target, [])
            if mountpoint not in bucket:
                bucket.append(mountpoint)
    return mapping


def stat_dev_map(devices: Dict[str, BlockDevice]) -> Dict[int, List[str]]:
    """建立 st_dev → 整盘名列表 的映射（扫描被监控盘各挂载点）。

    作为路径前缀匹配之外的兜底：btrfs/LVM/多设备文件系统上，
    文件的 os.stat(path).st_dev 与挂载点一致，可直接反查归属盘。
    一个 st_dev 可能对应多块成员盘（md / btrfs 多设备），所以是列表。
    """
    result: Dict[int, List[str]] = {}
    for name, device in devices.items():
        if not device.monitored:
            continue
        for mount in device.mounts:
            try:
                st_dev = os.stat(mount).st_dev
            except OSError:
                continue
            bucket = result.setdefault(st_dev, [])
            if name not in bucket:
                bucket.append(name)
    return result


def is_virtual(name: str) -> bool:
    return any(name.startswith(prefix) for prefix in VIRTUAL_PREFIXES)


def enumerate_devices(
    *,
    monitor_only_sleepable: bool = True,
    monitor_devices: Optional[List[str]] = None,
    exclude_devices: Optional[List[str]] = None,
) -> Dict[str, BlockDevice]:
    if not os.path.isdir(SYS_BLOCK):
        raise DeviceError(
            f"{SYS_BLOCK} 不存在，无法枚举块设备",
            hint="本工具只能在 Linux（飞牛 fnOS / Debian）上运行",
        )

    force = {d.strip() for d in (monitor_devices or []) if d.strip()}
    exclude = {d.strip() for d in (exclude_devices or []) if d.strip()}
    mounts = read_mounts()
    result: Dict[str, BlockDevice] = {}

    for entry in sorted(os.listdir(SYS_BLOCK)):
        if is_virtual(entry):
            continue
        base = os.path.join(SYS_BLOCK, entry)
        if not os.path.isdir(base):
            continue

        size_sectors = _read_int(os.path.join(base, "size"))
        if size_sectors <= 0:
            continue

        device = BlockDevice(
            name=entry,
            model=_read_text(os.path.join(base, "device", "model")) or entry,
            transport=detect_transport(entry),
            removable=_read_int(os.path.join(base, "removable")) == 1,
            rotational=_read_int(os.path.join(base, "queue", "rotational")) == 1,
            size_bytes=size_sectors * 512,
            mounts=mounts.get(entry, []),
        )

        # --- 监控判定 ---
        if entry in exclude:
            device.monitored, device.reason = False, "配置排除"
        elif entry in force:
            device.monitored, device.reason = True, "配置强制监控"
        elif not monitor_only_sleepable:
            device.monitored, device.reason = True, "全量监控模式"
        elif not device.rotational:
            device.monitored, device.reason = False, "非机械盘（无休眠概念）"
        else:
            # 机械盘（无论内置还是外接）都可能配置休眠、都可能被唤醒，默认监控。
            label = "外接/可移动机械盘" if (device.removable or device.transport == "usb") else "内置机械盘"
            device.monitored, device.reason = True, label

        result[entry] = device

    return result


class MountResolver:
    """把文件路径映射到整盘名。最长前缀优先，避免 /mnt/usb 与 /mnt/usb/sub 冲突。

    一个挂载点可能对应多块成员盘（md / btrfs 多设备），此时返回全部候选 ——
    只返回先插入的那一块会让另一块的归因环永远是空的。
    """

    def __init__(self, devices: Dict[str, BlockDevice]) -> None:
        pairs = []
        for name, device in devices.items():
            if not device.monitored:
                continue
            for mount in device.mounts:
                pairs.append((mount.rstrip("/") or "/", name))
        # 前缀长的优先；长度相同时按盘名排序，保证结果稳定可复现
        pairs.sort(key=lambda item: (-len(item[0]), item[1]))
        self._pairs = pairs

    @property
    def empty(self) -> bool:
        return not self._pairs

    def resolve_all(self, path: str) -> List[str]:
        """返回所有匹配同一最长前缀的整盘名（去重保序）。"""
        if not path or not path.startswith("/"):
            return []
        matched_len = -1
        names: List[str] = []
        for prefix, name in self._pairs:
            if prefix == "/":
                continue
            if matched_len >= 0 and len(prefix) < matched_len:
                break  # 已命中更长的前缀，后面的都更短
            if path == prefix or path.startswith(prefix + "/"):
                matched_len = len(prefix)
                if name not in names:
                    names.append(name)
        return names

    def resolve(self, path: str) -> Optional[str]:
        names = self.resolve_all(path)
        return names[0] if names else None

    def mounts_of(self, name: str) -> List[str]:
        return [prefix for prefix, dev in self._pairs if dev == name]
