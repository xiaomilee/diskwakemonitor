"""/proc/diskstats 解析与空闲追踪 —— 唤醒判定的「地面真值」来源。

/proc/diskstats 字段（内核 Documentation/admin-guide/iostats.rst）：
    0 major        1 minor        2 name
    3 reads完成    4 reads合并    5 sectors读     6 ms读
    7 writes完成   8 writes合并   9 sectors写    10 ms写
    11 ios在飞     12 io_ticks(ms) 13 weighted_ms
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List, Optional

PROC_DISKSTATS = "/proc/diskstats"


@dataclass
class DiskStat:
    name: str
    sectors_read: int
    sectors_written: int
    reads: int
    writes: int
    io_ticks: int
    ts: float

    @property
    def total_sectors(self) -> int:
        return self.sectors_read + self.sectors_written


def parse_diskstats_line(line: str, ts: float) -> Optional[DiskStat]:
    parts = line.split()
    if len(parts) < 14:
        return None
    try:
        return DiskStat(
            name=parts[2],
            reads=int(parts[3]),
            sectors_read=int(parts[5]),
            writes=int(parts[7]),
            sectors_written=int(parts[9]),
            io_ticks=int(parts[12]),
            ts=ts,
        )
    except (ValueError, IndexError):
        return None


def parse_diskstats(text: str, ts: Optional[float] = None) -> Dict[str, DiskStat]:
    now = ts if ts is not None else time.time()
    result: Dict[str, DiskStat] = {}
    for line in text.splitlines():
        stat = parse_diskstats_line(line, now)
        if stat is not None:
            result[stat.name] = stat
    return result


def read_diskstats(path: str = PROC_DISKSTATS) -> Dict[str, DiskStat]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_diskstats(fh.read(), time.time())


@dataclass
class Activity:
    """一次 IO 增量。idle_seconds 是「这次 IO 之前已经安静了多久」。"""

    dev: str
    ts: float
    delta_sectors: int
    idle_seconds: float


class IdleTracker:
    """跟踪每个设备上次活跃时间，识别「久静 → 突然有 IO」。"""

    def __init__(self, idle_threshold_seconds: float) -> None:
        self.idle_threshold = idle_threshold_seconds
        self._last_active: Dict[str, float] = {}
        self._last_sectors: Dict[str, int] = {}

    def prime(self, stats: Dict[str, DiskStat], now: Optional[float] = None) -> None:
        """建立基线。时间基准必须取自样本自身，避免与墙钟混用产生负的空闲时长。"""
        for name, stat in stats.items():
            self._last_sectors[name] = stat.total_sectors
            self._last_active.setdefault(name, stat.ts if now is None else now)

    def update(
        self, stats: Dict[str, DiskStat], watched: Optional[set] = None
    ) -> List[Activity]:
        """返回本轮检测到的活跃事件（delta_sectors > 0）。"""
        activities: List[Activity] = []
        for name, stat in stats.items():
            if watched is not None and name not in watched:
                self._last_sectors[name] = stat.total_sectors
                continue

            previous = self._last_sectors.get(name)
            self._last_sectors[name] = stat.total_sectors
            if previous is None:
                self._last_active[name] = stat.ts
                continue

            delta = stat.total_sectors - previous
            if delta <= 0:
                continue

            last_active = self._last_active.get(name, stat.ts)
            idle_seconds = max(0.0, stat.ts - last_active)
            self._last_active[name] = stat.ts
            activities.append(
                Activity(
                    dev=name,
                    ts=stat.ts,
                    delta_sectors=delta,
                    idle_seconds=idle_seconds,
                )
            )
        return activities

    def idle_seconds(self, dev: str, now: Optional[float] = None) -> float:
        now = now if now is not None else time.time()
        last = self._last_active.get(dev)
        return 0.0 if last is None else max(0.0, now - last)

    def is_idle(self, dev: str, now: Optional[float] = None) -> bool:
        return self.idle_seconds(dev, now) >= self.idle_threshold
