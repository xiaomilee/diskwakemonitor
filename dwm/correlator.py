"""归因引擎：把「一次唤醒」和「是哪个进程的哪次 IO 触发的」对上时间轴。

难点在自己这一侧而不是采集：
- 硬盘从待机到能响应 IO 有 1-3 秒上电延迟，触发唤醒的 IO 往往「看起来晚于」唤醒时刻
- fatrace 的输出有毫秒级缓冲延迟
所以必须用 [醒来前 lookback, 醒来后 lookahead] 的双向窗口，而不是只看唤醒点之前。

窗口内的记录按 (pid, comm) 聚合，命中次数多、时间最贴近的前几个就是嫌疑进程。
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Iterable, List, Optional, Tuple


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
        lookback_seconds: float = 5.0,
        lookahead_seconds: float = 3.0,
    ) -> None:
        self.lookback = lookback_seconds
        self.lookahead = lookahead_seconds
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
    def attribute(self, candidate: WakeCandidate) -> List[Suspect]:
        ring = self._rings.get(candidate.dev)
        if not ring:
            return []

        low = candidate.ts - self.lookback
        high = candidate.ts + self.lookahead
        groups: Dict[Tuple[int, str], Dict[str, object]] = {}

        # deque 已按时间递增，反向遍历更快命中窗口尾部
        for sample in reversed(ring):
            if sample.ts > high:
                continue
            if sample.ts < low:
                break
            key = (sample.pid, sample.comm)
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
                    "closest": abs(sample.ts - candidate.ts),
                }
            else:
                bucket["hits"] = int(bucket["hits"]) + 1
                bucket["first_ts"] = min(float(bucket["first_ts"]), sample.ts)
                bucket["last_ts"] = max(float(bucket["last_ts"]), sample.ts)
                distance = abs(sample.ts - candidate.ts)
                if distance < float(bucket["closest"]):
                    bucket["closest"] = distance
                    bucket["sample_path"] = sample.path
                    bucket["cmdline"] = sample.cmdline or bucket["cmdline"]

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
            )
            for (pid, comm), bucket in groups.items()
        ]
        # 排序：先看时间贴近度，再看命中次数 —— 真正的触发者通常只碰一次但离得最近
        suspects.sort(key=lambda s: (round(abs(s.last_ts - candidate.ts), 1), -s.hits))
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
