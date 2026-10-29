"""归因引擎：把「一次唤醒」和「是哪个进程的哪次 IO 触发的」对上时间轴。

难点在自己这一侧而不是采集：
- fanotify/fatrace 打在系统调用入口，diskstats 的扇区增量要等 IO 完成才出现。
  机械盘上电 3-15 秒，所以 diskstats 看到的时刻比真正的触发晚一大截，
  窗口必须向左留够（默认 20 秒），而不是只看唤醒点前后各几秒。
- 盘转起来之后，smbd、索引、扫描会一拥而上，它们的 last_ts 离「IO 完成时刻」
  最近。所以排序不能取「最近的最后一次」，要取「唤醒之前最早的那一笔」。
- 唤醒点前 2 秒内（spinup floor）几乎不可能是触发者 —— 那正是上电期和涌入期，
  这一段的样本单独归入 post 组，排在 pre 组之后。

窗口内的记录按 (pid, comm) 聚合，命中次数多、时间最早的前几个就是嫌疑进程。
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Iterable, List, Optional, Tuple

PHASE_PRE = "pre"        # 唤醒之前、上电期之外：真正的触发者
PHASE_POST = "post"      # 上电期 / 盘转起来之后涌入
PHASE_BLOCK = "block"    # 块层证据（没有文件系统事件）


@dataclass
class Sample:
    """一条已补全上下文的访问记录。"""

    ts: float
    pid: int
    comm: str
    op: str = ""
    path: str = ""
    uid: Optional[int] = None
    container: str = ""
    cmdline: str = ""
    source: str = ""
    # 同一挂载点对应多块成员盘（md/btrfs）时，无法从路径判定 IO 落在哪一块
    ambiguous: bool = False

    def to_row(self, dev: str) -> tuple:
        return (
            self.ts,
            dev,
            self.pid,
            self.comm,
            self.uid,
            self.op,
            self.path,
            self.container,
            self.source,
        )


@dataclass
class Suspect:
    pid: int
    comm: str
    hits: int
    first_ts: float
    last_ts: float
    sample_path: str = ""
    uid: Optional[int] = None
    container: str = ""
    cmdline: str = ""
    ambiguous: bool = False
    phase: str = PHASE_PRE

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "comm": self.comm,
            "hits": self.hits,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "sample_path": self.sample_path,
            "uid": self.uid,
            "container": self.container,
            "cmdline": self.cmdline,
            "ambiguous": self.ambiguous,
            "phase": self.phase,
        }


@dataclass
class WakeCandidate:
    """一次待定归因的唤醒。"""

    dev: str
    ts: float
    idle_seconds: float
    confidence: str
    note: str = ""
    deadline: float = 0.0


class Correlator:
    def __init__(
        self,
        *,
        ring_buffer_size: int = 20000,
        lookback_seconds: float = 20.0,
        lookahead_seconds: float = 3.0,
        spinup_floor_seconds: float = 2.0,
    ) -> None:
        self.lookback = lookback_seconds
        self.lookahead = lookahead_seconds
        self.spinup_floor = max(0.0, min(spinup_floor_seconds, lookback_seconds))
        self._rings: Dict[str, Deque[Sample]] = {}
        self._ring_size = max(100, ring_buffer_size)

    # ---- 写入 ----
    def add(self, dev: str, sample: Sample) -> None:
        ring = self._rings.get(dev)
        if ring is None:
            ring = deque(maxlen=self._ring_size)
            self._rings[dev] = ring
        ring.append(sample)

    def prune(self, now: Optional[float] = None) -> None:
        """丢弃窗口之外的旧样本，控制内存。"""
        now = now if now is not None else time.time()
        horizon = now - max(self.lookback, 60.0) * 2
        for ring in self._rings.values():
            while ring and ring[0].ts < horizon:
                ring.popleft()

    # ---- 归因 ----
    def attribute(
        self, candidate: "WakeCandidate", lookback: Optional[float] = None
    ) -> List[Suspect]:
        """`lookback` 可临时放宽：SMART 只告诉我们「过去一个轮询周期内醒过」，
        那个场景下锚点不可靠，只能把窗口放大后再看。"""
        ring = self._rings.get(candidate.dev)
        if not ring:
            return []

        span = self.lookback if lookback is None else max(0.0, lookback)
        low = candidate.ts - span
        high = candidate.ts + self.lookahead
        # 「上电期」起点：之前的样本才是先动手的
        gate = candidate.ts - self.spinup_floor
        groups: Dict[Tuple[int, str], Dict[str, object]] = {}

        # deque 已按时间递增，反向遍历更快命中窗口尾部
        for sample in reversed(ring):
            if sample.ts > high:
                continue
            if sample.ts < low:
                break
            key = (sample.pid, sample.comm)
            phase = PHASE_PRE if sample.ts < gate else PHASE_POST
            bucket = groups.get(key)
            if bucket is None:
                groups[key] = {
                    "hits": 1,
                    "first_ts": sample.ts,
                    "last_ts": sample.ts,
                    "sample_path": sample.path,
                    "uid": sample.uid,
                    "container": sample.container,
                    "cmdline": sample.cmdline,
                    "ambiguous": sample.ambiguous,
                    "phase": phase,
                }
            else:
                bucket["hits"] = int(bucket["hits"]) + 1
                if sample.ts < float(bucket["first_ts"]):
                    # 展示为首笔访问的路径 —— 那才是触发者碰的东西
                    bucket["first_ts"] = sample.ts
                    bucket["sample_path"] = sample.path
                bucket["last_ts"] = max(float(bucket["last_ts"]), sample.ts)
                # 组内只要有一条落在 pre 段，就按 pre 归档（它确实先动过手）
                bucket["phase"] = PHASE_PRE if sample.ts < gate else bucket["phase"]
                bucket["ambiguous"] = bool(bucket["ambiguous"]) or sample.ambiguous
                if not bucket["cmdline"] and sample.cmdline:
                    bucket["cmdline"] = sample.cmdline

        suspects = [
            Suspect(
                pid=pid,
                comm=comm,
                hits=int(bucket["hits"]),
                first_ts=float(bucket["first_ts"]),
                last_ts=float(bucket["last_ts"]),
                sample_path=str(bucket["sample_path"]),
                uid=bucket["uid"] if isinstance(bucket["uid"], int) else None,
                container=str(bucket["container"]),
                cmdline=str(bucket["cmdline"]),
                ambiguous=bool(bucket["ambiguous"]),
                phase=str(bucket["phase"]),
            )
            for (pid, comm), bucket in groups.items()
        ]
        # 排序（见模块头注释）：
        #   1. pre 组先于 post 组 —— 唤醒前 2 秒内的一拥而上不是元凶
        #   2. 组内按首笔时间升序 —— 最早动手的那个才是触发者
        #   3. 最后才看命中次数，多盘歧义的往后压
        suspects.sort(
            key=lambda s: (
                0 if s.phase == PHASE_PRE else 1,
                s.first_ts,
                -s.hits,
                1 if s.ambiguous else 0,
            )
        )
        return suspects

    def clear_dev(self, dev: str) -> int:
        """清除某块盘的内存样本（用户清空该盘记录时同步调用）。"""
        ring = self._rings.pop(dev, None)
        return len(ring) if ring else 0

    def window_size(self, dev: str) -> int:
        ring = self._rings.get(dev)
        return len(ring) if ring else 0

    def device_names(self) -> Iterable[str]:
        return self._rings.keys()
