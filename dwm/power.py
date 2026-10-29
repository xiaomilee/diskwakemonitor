"""硬盘电源状态探测（smartctl）。

核心技巧：`smartctl -n standby` 让 smartctl 在盘处于待机时**直接退出（码 2）而不唤醒盘**。
这是唯一能「问盘睡没睡又不弄醒它」的可靠手段。

三重唤醒信号，互为补位：
  1. SMART 电源态 standby → active      （高置信）
  2. Start_Stop_Count 属性递增           （高置信，能抓到两次轮询之间的启停）
  3. diskstats 久静 → 有 IO              （推断，SMART 不可用时的兜底）

USB 桥接盒的注意事项：
  - 很多盒子不支持 SAT 直通，需要 `-d sat`，个别需要 `-d usbjmicron` 等
  - 某些盒子的固件在收到任何 SCSI 命令时都会转盘，因此轮询间隔不宜过短
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from .devices import partition_to_disk

STATE_ACTIVE = "active"
STATE_STANDBY = "standby"
STATE_UNKNOWN = "unknown"

# 首次失败后按顺序尝试的 -d 参数
DEVICE_TYPE_FALLBACKS = ("sat", "usbjmicron", "usbsunplus", "sat,12")

_START_STOP_RE = re.compile(r"^\s*4\s+Start_Stop", re.IGNORECASE)
_STANDBY_RE = re.compile(r"\bSTANDBY\b", re.IGNORECASE)


def normalize_dev(dev: str) -> str:
    """`/dev/sda` → `sda`，`/dev/sdb1` → `sdb`。

    电源态、diskstats、面板、数据库必须用同一套键，否则 last_state 永远查不到值。
    """
    if not dev:
        return ""
    base = dev.rsplit("/", 1)[-1]
    return partition_to_disk(base)



@dataclass
class PowerSample:
    ts: float
    dev: str
    state: str
    start_stop: Optional[int] = None
    raw: str = ""
    device_type: str = ""

    @property
    def asleep(self) -> bool:
        return self.state == STATE_STANDBY


def smartctl_available(binary: str = "smartctl") -> bool:
    return shutil.which(binary) is not None


def _run(cmd: list[str], timeout: float) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except OSError as exc:
        return -2, "", str(exc)


def parse_start_stop(stdout: str) -> Optional[int]:
    for line in stdout.splitlines():
        if not _START_STOP_RE.match(line):
            continue
        tokens = line.split()
        if not tokens:
            continue
        raw = tokens[-1]
        raw = raw.split("(")[0].strip()
        try:
            return int(raw)
        except ValueError:
            continue
    return None


class SmartReader:
    def __init__(self, binary: str = "smartctl", timeout: float = 15.0) -> None:
        self.binary = binary
        self.timeout = timeout
        self._device_type: Dict[str, str] = {}
        self._reported_missing = False

    @property
    def available(self) -> bool:
        return smartctl_available(self.binary)

    def _build_cmd(self, dev_path: str, extra: list[str]) -> list[str]:
        cmd = [self.binary, "-n", "standby", *extra]
        dtype = self._device_type.get(dev_path)
        if dtype:
            cmd.extend(["-d", dtype])
        cmd.append(dev_path)
        return cmd

    def sample(self, dev_path: str) -> PowerSample:
        return self._sample(dev_path, attempt=0)

    def _sample(self, dev_path: str, attempt: int) -> PowerSample:
        now = time.time()
        if not self.available:
            if not self._reported_missing:
                self._reported_missing = True
            return PowerSample(ts=now, dev=dev_path, state=STATE_UNKNOWN, raw="smartctl missing")

        cmd = self._build_cmd(dev_path, ["-A", "-i"])
        rc, out, err = _run(cmd, self.timeout)
        combined = (out + "\n" + err).strip()

        # 退出码 2 = 设备处于待机，且已被 smartctl 主动放弃唤醒
        if rc == 2 and "STANDBY" in combined.upper():
            return PowerSample(
                ts=now,
                dev=dev_path,
                state=STATE_STANDBY,
                raw=combined,
                device_type=self._device_type.get(dev_path, ""),
            )
        if rc == 0 and _STANDBY_RE.search(combined):
            # 部分 USB 桥接盒在待机时仍返回 0，只在输出文本里写 STANDBY。
            # 只认退出码会把这类盘永久判成 active，进而拦掉所有唤醒记录。
            return PowerSample(
                ts=now,
                dev=dev_path,
                state=STATE_STANDBY,
                raw=combined,
                device_type=self._device_type.get(dev_path, ""),
            )
        if rc == 0:
            return PowerSample(
                ts=now,
                dev=dev_path,
                state=STATE_ACTIVE,
                start_stop=parse_start_stop(out),
                raw=combined,
                device_type=self._device_type.get(dev_path, ""),
            )

        # 未知 USB 桥接：换 -d 参数重试一次
        if attempt == 0 and ("Unknown USB bridge" in combined or "unsupported" in combined.lower()):
            for candidate in DEVICE_TYPE_FALLBACKS:
                self._device_type[dev_path] = candidate
                probe = self._sample(dev_path, attempt=1)
                if probe.state != STATE_UNKNOWN:
                    return probe
            self._device_type.pop(dev_path, None)

        return PowerSample(
            ts=now, dev=dev_path, state=STATE_UNKNOWN, raw=combined or f"rc={rc}"
        )


class PowerStateTracker:
    """记录上次状态，识别 standby → active 跃变与启停计数递增。

    键统一用整盘名（`sda`），与 diskstats、面板、数据库保持一致；
    传进来的 `PowerSample.dev` 是 `/dev/sda`，这里负责归一。
    """

    def __init__(self) -> None:
        self._last_state: Dict[str, str] = {}
        self._last_start_stop: Dict[str, int] = {}

    def last_state(self, dev: str) -> str:
        return self._last_state.get(normalize_dev(dev), STATE_UNKNOWN)

    def was_asleep(self, dev: str) -> bool:
        return self._last_state.get(normalize_dev(dev)) == STATE_STANDBY

    def observe(self, sample: PowerSample) -> Tuple[bool, str]:
        """返回 (是否发生唤醒, 归因说明)。"""
        dev = normalize_dev(sample.dev)
        if not dev:
            return False, ""
        previous = self._last_state.get(dev, STATE_UNKNOWN)
        woke = False
        reasons = []

        if previous == STATE_STANDBY and sample.state == STATE_ACTIVE:
            woke = True
            reasons.append("电源态 standby→active")

        if sample.start_stop is not None:
            prev_count = self._last_start_stop.get(dev)
            if prev_count is not None and sample.start_stop > prev_count:
                woke = True
                reasons.append(f"启停计数 {prev_count}→{sample.start_stop}")
            self._last_start_stop[dev] = sample.start_stop

        self._last_state[dev] = sample.state
        return woke, "；".join(reasons)
