"""事件源：fatrace（fanotify，能给出「哪个进程碰了哪个文件」）与 block_dump（块层兜底）。

两个源的强弱：
    fatrace     路径级，进程精确；需要 root + fanotify；有 JSONL 与文本两种输出
    block_dump  块级，只有设备名和块号，没有路径；权限要求低一点；会刷爆 dmesg

解析器都是纯函数，便于单测；采集线程只负责喂行。
"""

from __future__ import annotations

import ctypes
import errno
import json
import logging
import os
import re
import select
import struct
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence, Tuple

from .errors import SourceError

LOG = logging.getLogger("dwm.source")

ACCESS_EVENT = "access"
BLOCK_DUMP_SYSCTL = "/proc/sys/vm/block_dump"

_FATRACE_TEXT_RE = re.compile(
    r"^(?:(?P<ts>\d{1,2}:\d{2}:\d{2}\.\d+|\d{10}\.\d+)\s+)?"
    r"(?P<comm>.+?)\((?P<pid>\d+)\)"
    r"(?:\[(?P<uid>\d+):(?P<gid>\d+)\])?"
    r":\s+(?P<types>[A-Za-z+<>]+)\s+(?P<target>.+)$"
)

_FATRACE_DEVICE_RE = re.compile(r"^device\s+(?P<major>\d+):(?P<minor>\d+)(?:\s+inode\s+(?P<inode>\d+))?$")

_BLOCKDUMP_RE = re.compile(
    r"block_dump:\s*(?P<op>[A-Z]+)\s+block\s+(?P<block>\d+)\s+on\s+(?P<dev>[^\s(]+)"
    r"(?:\s*\((?P<extra>[^)]*)\))?"
)
_BLOCKDUMP_COMM_RE = re.compile(r"process=(?P<comm>[^,]+)")
_BLOCKDUMP_PID_RE = re.compile(r"pid=(?P<pid>\d+)")


def _split_blockdump_extra(extra: str) -> tuple:
    """从 "(process=smbd, pid=888)" 或 "(rsync)" 里取出 (comm, pid)。

    注意不能用一个「非贪婪 + 可选组」的正则，那样会只吃掉一个字符。
    """
    if not extra:
        return "", 0
    comm_match = _BLOCKDUMP_COMM_RE.search(extra)
    if comm_match:
        pid_match = _BLOCKDUMP_PID_RE.search(extra)
        return comm_match.group("comm").strip(), int(pid_match.group("pid")) if pid_match else 0
    return extra.strip(), 0


@dataclass
class AccessRecord:
    ts: float
    pid: int
    comm: str
    op: str
    path: str = ""
    uid: Optional[int] = None
    device_hint: str = ""  # 分区名（sdb1）或 "major:minor"
    dev: str = ""          # 归一后的整盘名，由 collector 填充
    source: str = ""
    # 事件源自己就能确定的设备归属（如 fanotify 按超级块分组）：
    # 容器 bind mount 里的路径可能解析不出来，但超级块一定对得上。
    hint_devs: Tuple[str, ...] = ()

    def to_row(self, container: str = "") -> tuple:
        return (
            self.ts,
            self.dev,
            self.pid,
            self.comm,
            self.uid,
            self.op,
            self.path,
            container,
            self.source,
        )


# ---------------------------------------------------------------------------
# 解析器（纯函数）
# ---------------------------------------------------------------------------


def parse_fatrace_text(line: str, ts_fallback: Optional[float] = None) -> Optional[AccessRecord]:
    """解析 fatrace 文本输出。

    支持：
        rsyslogd(875): W /var/log/auth.log
        18:00:00.123456 rsyslogd(875): W /path          （-t）
        1698336000.123456 rsyslogd(875): W /path        （-tt，epoch 秒）
        rsyslogd(875)[0:0]: W /path                     （-u）
        compiz(1971): O device 8:2 inode 658203         （路径不可得）
    """
    line = line.rstrip("\n")
    if not line.strip():
        return None
    match = _FATRACE_TEXT_RE.match(line)
    if not match:
        return None

    comm = (match.group("comm") or "").strip()
    # 进程名可能带 "systemd-udevd" 这种，也可能为空
    uid_raw = match.group("uid")
    target = (match.group("target") or "").strip()
    path = target
    device_hint = ""

    device_match = _FATRACE_DEVICE_RE.match(target)
    if device_match:
        device_hint = f"{device_match.group('major')}:{device_match.group('minor')}"
        path = ""

    ts = ts_fallback if ts_fallback is not None else time.time()
    raw_ts = match.group("ts")
    if raw_ts:
        ts = _parse_fatrace_ts(raw_ts) or ts

    return AccessRecord(
        ts=ts,
        pid=int(match.group("pid")),
        comm=comm,
        op=match.group("types"),
        path=path,
        uid=int(uid_raw) if uid_raw is not None else None,
        device_hint=device_hint,
        source="fatrace",
    )


def _parse_fatrace_ts(raw: str) -> Optional[float]:
    try:
        if "." in raw and ":" in raw:  # HH:MM:SS.micro，只有当天时间
            hh, mm, ss = raw.split(":")
            today = time.localtime()
            base = time.mktime(
                (today.tm_year, today.tm_mon, today.tm_mday, int(hh), int(mm), 0, 0, 0, -1)
            )
            return base + float(ss)
        return float(raw)  # epoch 秒
    except (ValueError, OverflowError):
        return None


def parse_fatrace_json(line: str, ts_fallback: Optional[float] = None) -> Optional[AccessRecord]:
    """解析 fatrace JSONL 输出（较新版本才支持）。"""
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None

    device = payload.get("device") or {}
    device_hint = ""
    if isinstance(device, dict) and "major" in device and "minor" in device:
        device_hint = f"{device['major']}:{device['minor']}"

    ts = ts_fallback if ts_fallback is not None else time.time()
    raw_ts = payload.get("timestamp")
    if isinstance(raw_ts, (int, float)):
        ts = float(raw_ts)
    elif isinstance(raw_ts, str):
        parsed = _parse_fatrace_ts(raw_ts)
        if parsed:
            ts = parsed

    uid = payload.get("uid")
    path = payload.get("path") or ""
    if not path and device_hint:
        path = ""

    return AccessRecord(
        ts=ts,
        pid=int(payload.get("pid") or 0),
        comm=(payload.get("comm") or "").strip(),
        op=str(payload.get("types") or ""),
        path=path,
        uid=int(uid) if isinstance(uid, int) else None,
        device_hint=device_hint,
        source="fatrace-json",
    )


def parse_blockdump(line: str, ts_fallback: Optional[float] = None) -> Optional[AccessRecord]:
    """解析 block_dump 内核日志。

    兼容两种历史格式：
        block_dump: WRITE block 8300664 on sdb1 (rsync)
        block_dump: WRITE block 8300664 on sdb1 (process=rsync, pid=1234)
    """
    match = _BLOCKDUMP_RE.search(line)
    if not match:
        return None

    comm, pid = _split_blockdump_extra(match.group("extra") or "")

    return AccessRecord(
        ts=ts_fallback if ts_fallback is not None else time.time(),
        pid=pid,
        comm=comm,
        op=match.group("op"),
        path="",
        uid=None,
        device_hint=match.group("dev"),
        source="block_dump",
    )


def devnode_from_idstr(idstr: str) -> str:
    """把 "8:16" 或 "sdb1" 变成设备名。major:minor 走 /sys/dev/block。"""
    if not idstr:
        return ""
    if ":" in idstr:
        try:
            return os.path.basename(os.path.realpath(f"/sys/dev/block/{idstr}"))
        except OSError:
            return ""
    return idstr


# ---------------------------------------------------------------------------
# 采集线程
# ---------------------------------------------------------------------------


class EventSource:
    name = "base"

    def __init__(self, on_record: Callable[[AccessRecord], None]) -> None:
        self._on_record = on_record
        self._stopping = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._process: Optional[subprocess.Popen] = None

    def stats(self) -> dict:
        """事件源自身的计数器（溢出、路径解析失败等），供面板排查。"""
        return {}

    def start(self) -> None:
        self._stopping.clear()
        self._thread = threading.Thread(target=self._run_loop, name=f"src-{self.name}", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stopping.set()
        self._terminate()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def _terminate(self) -> None:
        process, self._process = self._process, None
        if process and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=3)
            except (subprocess.SubprocessError, OSError):
                try:
                    process.kill()
                except (subprocess.SubprocessError, OSError):
                    pass

    def _run_loop(self) -> None:  # pragma: no cover - 真实子进程路径
        backoff = 1.0
        while not self._stopping.is_set():
            try:
                self._pump()
                backoff = 1.0
            except SourceError as exc:
                LOG.warning("事件源异常", extra={"source": self.name, "error": str(exc)})
            except Exception as exc:  # noqa: BLE001 - 采集线程不允许崩
                LOG.warning(
                    "事件源意外退出", extra={"source": self.name, "error": repr(exc)}
                )
            if self._stopping.is_set():
                break
            self._stopping.wait(backoff)
            backoff = min(backoff * 2, 60.0)
        self._cleanup()

    def _pump(self) -> None:
        raise NotImplementedError

    def _cleanup(self) -> None:
        return None


class FatraceSource(EventSource):
    name = "fatrace"

    def __init__(
        self,
        on_record: Callable[[AccessRecord], None],
        *,
        binary: str = "fatrace",
        event_filter: str = "OCW",
    ) -> None:
        super().__init__(on_record)
        self.binary = binary
        self.event_filter = event_filter
        self._json_mode: Optional[bool] = None
        self._json_flag = ""

    # --- 能力探测 ---
    def detect_format(self) -> str:
        if self._json_mode is not None:
            return "json" if self._json_mode else "text"
        try:
            proc = subprocess.run(
                [self.binary, "--help"], capture_output=True, text=True, timeout=10
            )
        except FileNotFoundError as exc:
            raise SourceError(
                f"找不到 {self.binary}",
                hint="apt install fatrace，或把 blockdump_fallback 设为 true",
            ) from exc
        except (OSError, subprocess.SubprocessError) as exc:
            raise SourceError(f"执行 {self.binary} --help 失败：{exc}") from exc

        help_text = (proc.stdout or "") + (proc.stderr or "")
        if "--jsonl" in help_text:
            self._json_mode, self._json_flag = True, "--jsonl"
        elif "--json" in help_text:
            self._json_mode, self._json_flag = True, "--json"
        else:
            self._json_mode, self._json_flag = False, ""
        LOG.info(
            "fatrace 输出格式探测完成",
            extra={"format": "json" if self._json_mode else "text", "flag": self._json_flag},
        )
        return "json" if self._json_mode else "text"

    def _command(self) -> List[str]:
        cmd = [self.binary]
        if self.event_filter:
            cmd.append(f"--filter={self.event_filter}")
        if self._json_mode:
            cmd.append(self._json_flag)
        return cmd

    def _pump(self) -> None:
        self.detect_format()
        cmd = self._command()
        LOG.info("启动事件源", extra={"source": self.name, "cmd": " ".join(cmd)})
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError as exc:
            raise SourceError(f"无法启动 {self.binary}（未安装？）") from exc

        stderr_thread = threading.Thread(
            target=self._drain_stderr, name="src-fatrace-err", daemon=True
        )
        stderr_thread.start()

        assert self._process.stdout is not None
        parser = parse_fatrace_json if self._json_mode else parse_fatrace_text
        for line in self._process.stdout:
            if self._stopping.is_set():
                break
            record = parser(line, time.time())
            if record is not None:
                try:
                    self._on_record(record)
                except Exception:  # noqa: BLE001
                    LOG.exception("处理 fatrace 记录失败")
        rc = self._process.wait()
        if not self._stopping.is_set():
            raise SourceError(f"fatrace 退出，返回码 {rc}（非 root 会失败）")

    def _drain_stderr(self) -> None:
        process = self._process
        if not process or process.stderr is None:
            return
        for line in process.stderr:
            text = line.strip()
            if text:
                LOG.debug("fatrace stderr", extra={"line": text})


class BlockDumpSource(EventSource):
    """块层兜底源。会临时打开 /proc/sys/vm/block_dump，退出时务必还原。"""

    name = "block_dump"

    def __init__(self, on_record: Callable[[AccessRecord], None]) -> None:
        super().__init__(on_record)
        self._previous_value: Optional[str] = None
        self._touched = False

    def _enable(self) -> None:
        try:
            with open(BLOCK_DUMP_SYSCTL, "r", encoding="utf-8") as fh:
                self._previous_value = fh.read().strip()
        except OSError as exc:
            raise SourceError(
                f"无法读取 {BLOCK_DUMP_SYSCTL}：{exc}",
                hint="需要 root，且内核需启用 CONFIG_BLOCK dump 支持",
            ) from exc
        try:
            with open(BLOCK_DUMP_SYSCTL, "w", encoding="utf-8") as fh:
                fh.write("1\n")
            self._touched = True
        except OSError as exc:
            raise SourceError(f"无法写入 {BLOCK_DUMP_SYSCTL}：{exc}（需要 root）") from exc
        LOG.info("block_dump 已启用", extra={"previous": self._previous_value})

    def _disable(self) -> None:
        if not self._touched:
            return
        try:
            with open(BLOCK_DUMP_SYSCTL, "w", encoding="utf-8") as fh:
                fh.write((self._previous_value or "0") + "\n")
            LOG.info("block_dump 已还原", extra={"value": self._previous_value})
        except OSError as exc:
            LOG.warning("还原 block_dump 失败，请手动执行 echo 0 > /proc/sys/vm/block_dump")
            LOG.debug("还原失败详情", extra={"error": str(exc)})
        finally:
            self._touched = False

    def _command(self) -> List[str]:
        return ["dmesg", "--follow"]

    def _pump(self) -> None:
        if not self._touched:
            self._enable()
        cmd = self._command()
        LOG.info("启动事件源", extra={"source": self.name, "cmd": " ".join(cmd)})
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError:
            self._pump_kmsg()
            return

        assert self._process.stdout is not None
        for line in self._process.stdout:
            if self._stopping.is_set():
                break
            if "block_dump:" not in line:
                continue
            record = parse_blockdump(line, time.time())
            if record is not None:
                try:
                    self._on_record(record)
                except Exception:  # noqa: BLE001
                    LOG.exception("处理 block_dump 记录失败")
        self._process.wait()
        if not self._stopping.is_set():
            raise SourceError("dmesg 跟随中断")

    def _pump_kmsg(self) -> None:  # pragma: no cover - 取决于环境
        LOG.info("dmesg 不可用，改为直接读取 /dev/kmsg")
        try:
            with open("/dev/kmsg", "r", encoding="utf-8", errors="replace") as fh:
                while not self._stopping.is_set():
                    line = fh.readline()
                    if not line:
                        time.sleep(0.2)
                        continue
                    if "block_dump:" not in line:
                        continue
                    record = parse_blockdump(line, time.time())
                    if record is not None:
                        self._on_record(record)
        except OSError as exc:
            raise SourceError(f"读取 /dev/kmsg 失败：{exc}") from exc

    def _cleanup(self) -> None:
        self._disable()


class NullSource(EventSource):
    name = "none"

    def _pump(self) -> None:
        LOG.error("没有任何可用的事件源，仅能依靠 diskstats + SMART 做推断")
        while not self._stopping.is_set():
            self._stopping.wait(5.0)


# ---------------------------------------------------------------------------
# 内建 fanotify 源（fatrace 的底层机制，纯标准库 ctypes 实现）
#
# 背景：block_dump 在内核 5.10 起被移除（sysctl 可能还在，但内核不再产出
# IO 日志），fnOS 的 6.12 内核上这条路是死的。fanotify 是唯一无依赖的替代：
# glibc 2.13+ 直接导出 fanotify_init / fanotify_mark 包装函数，Debian 系
# （含 fnOS）开箱可用。精度与 fatrace 相同：pid + 进程名 + 文件路径。
# 需要 root（CAP_SYS_ADMIN）。
# ---------------------------------------------------------------------------

_FAN_CLOEXEC = 0x0000_0001
_FAN_NONBLOCK = 0x0000_0002
_FAN_UNLIMITED_QUEUE = 0x0000_0010
_FAN_CLASS_NOTIF = 0x0000_0000

_FAN_MARK_ADD = 0x0000_0001
_FAN_MARK_MOUNT = 0x0000_0010
# 整个超级块（所有挂载，含容器 bind mount）。内核 4.20+，fnOS 6.12 支持。
_FAN_MARK_FILESYSTEM = 0x0000_0100

_FAN_OPEN = 0x0000_0001
_FAN_ACCESS = 0x0000_0002
_FAN_MODIFY = 0x0000_0004
_FAN_CLOSE_WRITE = 0x0000_0008
_FAN_OPEN_EXEC = 0x0000_1000
_FAN_Q_OVERFLOW = 0x0000_4000

_FAN_EVENT_MASK = (
    _FAN_OPEN | _FAN_ACCESS | _FAN_MODIFY | _FAN_CLOSE_WRITE | _FAN_OPEN_EXEC
)
_FAN_OP_MAP = (
    (_FAN_OPEN, "O"),
    (_FAN_ACCESS, "R"),
    (_FAN_MODIFY, "W"),
    (_FAN_CLOSE_WRITE, "C"),
    (_FAN_OPEN_EXEC, "E"),
)

# 单次 read 的缓冲区。64K 在高负载（容器 + 索引）下很容易被一遍刷满，
# 读小了会让内核队列堆积直到溢出。
FANOTIFY_READ_SIZE = 1 << 20
# 单个 fd 单轮最多读几次（防止一个超级块的事件风暴饿死其它超级块）
DRAIN_BATCH = 64

# fanotify_event_metadata 头部（linux/fanotify.h），当前版本固定 24 字节
_FANOTIFY_HEADER = struct.Struct("<IBBHQii")

O_CLOEXEC = 0o2000000  # 0x80000
_AT_FDCWD = -100


def _fanotify_libc() -> ctypes.CDLL:
    try:
        return ctypes.CDLL(None, use_errno=True)
    except OSError as exc:
        raise SourceError(f"无法加载 libc：{exc}") from exc


def parse_fanotify_stream(
    data: bytes,
    ts: float,
    hint_devs: Sequence[str] = (),
    stats: Optional[dict] = None,
) -> List[AccessRecord]:
    """解析 fanotify read() 返回的事件缓冲区（纯函数，便于单测）。

    FAN_CLASS_NOTIF 模式下每条事件头 24 字节，fd 可直接从 /proc/self/fd 取路径。
    `hint_devs` 来自事件所在的超级块分组：路径解析不出来时靠它兜底。
    """
    records: List[AccessRecord] = []
    devs = tuple(hint_devs)
    offset = 0
    total = len(data)
    while offset + _FANOTIFY_HEADER.size <= total:
        event_len, vers, _rsv, _meta_len, mask, pid, fd = _FANOTIFY_HEADER.unpack_from(
            data, offset
        )
        if event_len < _FANOTIFY_HEADER.size or offset + event_len > total:
            break  # 截断的尾部，留给下一次 read（正常情况下 read 返回完整事件）
        offset += event_len
        if vers < 2:
            continue
        if mask & _FAN_Q_OVERFLOW:
            if stats is not None:
                stats["overflow"] = int(stats.get("overflow", 0)) + 1
            continue
        ops = "".join(letter for bit, letter in _FAN_OP_MAP if mask & bit)
        if not ops:
            continue
        path = ""
        if fd >= 0:
            try:
                path = os.readlink(f"/proc/self/fd/{fd}")
            except OSError:
                path = ""
            try:
                os.close(fd)
            except OSError:
                pass
        if not path and stats is not None:
            stats["unresolved_path"] = int(stats.get("unresolved_path", 0)) + 1
        records.append(
            AccessRecord(
                ts=ts,
                pid=int(pid),
                comm="",  # comm 由 collector 的 ProcCache 按 pid 补全
                op=ops,
                path=path,
                device_hint="",
                source="fanotify",
                hint_devs=devs,
            )
        )
    return records


class _MarkGroup:
    """一个超级块（或挂载点）对应的一组监视：独立 fanotify fd + 设备归属。"""

    __slots__ = ("fd", "devs", "mounts", "mode")

    def __init__(self, fd: int, devs: Tuple[str, ...], mounts: List[str], mode: str) -> None:
        self.fd = fd
        self.devs = devs
        self.mounts = mounts
        self.mode = mode


class FanotifySource(EventSource):
    """内建 fanotify 源。

    按「超级块」分组，每组一个 fanotify fd：
      - 用 FAN_MARK_FILESYSTEM 盯整个文件系统，容器里的 bind mount 一样覆盖
        （内核 4.20+；fatrace 只打 FAN_MARK_MOUNT，看不见容器）
      - 不支持时按挂载点退回 FAN_MARK_MOUNT
      - 事件天然带设备归属，路径解析失败（容器私有挂载命名空间）不再丢事件
    """

    name = "fanotify"

    def __init__(
        self,
        on_record: Callable[[AccessRecord], None],
        *,
        targets: Optional[Sequence[Tuple[str, Sequence[str]]]] = None,
        mounts: Optional[Sequence[str]] = None,
        prefer_filesystem: bool = True,
    ) -> None:
        super().__init__(on_record)
        if targets is None:
            targets = [(m, ()) for m in (mounts or [])]
        # mount 路径 → 设备候选；同一路径可能对应多块成员盘
        merged: dict = {}
        for mount, devs in targets:
            mount = (mount or "").rstrip("/") or "/"
            if not mount or mount == "-":
                continue
            bucket = merged.setdefault(mount, [])
            for dev in devs:
                if dev and dev not in bucket:
                    bucket.append(dev)
        self._targets = merged
        self.mounts = sorted(merged)
        self.prefer_filesystem = prefer_filesystem
        self._groups: List[_MarkGroup] = []
        self._stats = {"overflow": 0, "unresolved_path": 0}

    # --- 能力探测（不建立长期监视） ---
    @staticmethod
    def probe(paths: Optional[Sequence[str]] = None) -> dict:
        result = {"ok": False, "error": "", "mark": "", "filesystem": False}
        try:
            libc = _fanotify_libc()
            init = libc.fanotify_init
        except (AttributeError, SourceError) as exc:
            result["error"] = f"glibc 缺少 fanotify_init：{exc}"
            return result
        init.restype = ctypes.c_int
        init.argtypes = [ctypes.c_uint, ctypes.c_uint]
        fd = init(
            _FAN_CLOEXEC | _FAN_NONBLOCK | _FAN_UNLIMITED_QUEUE,
            os.O_RDONLY | O_CLOEXEC,
        )
        if fd < 0:
            err_no = ctypes.get_errno()
            result["error"] = (
                f"fanotify_init 失败：{os.strerror(err_no)}（需要 root / CAP_SYS_ADMIN）"
            )
            return result
        try:
            probe_paths = [p for p in (paths or []) if p and os.path.isdir(p)]
            probe_paths.append("/")
            mark = libc.fanotify_mark
            mark.restype = ctypes.c_int
            mark.argtypes = [
                ctypes.c_int,
                ctypes.c_uint,
                ctypes.c_ulonglong,
                ctypes.c_int,
                ctypes.c_char_p,
            ]
            for flags, mode in (
                (_FAN_MARK_ADD | _FAN_MARK_FILESYSTEM, "filesystem"),
                (_FAN_MARK_ADD | _FAN_MARK_MOUNT, "mount"),
            ):
                for path in probe_paths:
                    if mark(fd, flags, _FAN_EVENT_MASK, _AT_FDCWD, path.encode()) == 0:
                        result["ok"] = True
                        result["mark"] = mode
                        result["filesystem"] = mode == "filesystem"
                        return result
            result["error"] = (
                f"fanotify_mark 失败：{os.strerror(ctypes.get_errno())}"
            )
            return result
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    def stats(self) -> dict:
        return dict(self._stats)

    # --- 分组 ---
    def _plan_groups(self) -> List[Tuple[str, Tuple[str, ...], List[str]]]:
        """同一个 st_dev 的挂载点合并成一组：一次 mark 覆盖整个超级块。"""
        groups: dict = {}
        order: List[str] = []
        for mount in sorted(self._targets):
            try:
                st_dev = os.stat(mount).st_dev
            except OSError:
                continue  # 挂载点已消失
            key = str(st_dev)
            if key not in groups:
                groups[key] = {"mount": mount, "devs": [], "mounts": []}
                order.append(key)
            entry = groups[key]
            entry["mounts"].append(mount)
            for dev in self._targets.get(mount, []):
                if dev not in entry["devs"]:
                    entry["devs"].append(dev)
        return [
            (groups[key]["mount"], tuple(groups[key]["devs"]), groups[key]["mounts"])
            for key in order
        ]

    def _init_fanotify(self) -> int:
        libc = _fanotify_libc()
        init = libc.fanotify_init
        init.restype = ctypes.c_int
        init.argtypes = [ctypes.c_uint, ctypes.c_uint]
        fd = init(
            _FAN_CLOEXEC | _FAN_NONBLOCK | _FAN_UNLIMITED_QUEUE,
            os.O_RDONLY | O_CLOEXEC,
        )
        if fd < 0:
            err_no = ctypes.get_errno()
            raise SourceError(
                f"fanotify_init 失败：{os.strerror(err_no)}",
                hint="需要 root 权限；或确认内核启用 CONFIG_FANOTIFY",
            )
        return fd

    @staticmethod
    def _mark(fd: int, flags: int, path: str) -> int:
        libc = _fanotify_libc()
        mark = libc.fanotify_mark
        mark.restype = ctypes.c_int
        mark.argtypes = [
            ctypes.c_int,
            ctypes.c_uint,
            ctypes.c_ulonglong,
            ctypes.c_int,
            ctypes.c_char_p,
        ]
        rc = mark(fd, flags, _FAN_EVENT_MASK, _AT_FDCWD, path.encode("utf-8"))
        return rc

    def _open_group(self, mount: str, devs: Tuple[str, ...], mounts: List[str]) -> _MarkGroup:
        fd = self._init_fanotify()
        try:
            failures: List[str] = []
            if self.prefer_filesystem:
                if self._mark(fd, _FAN_MARK_ADD | _FAN_MARK_FILESYSTEM, mount) == 0:
                    return _MarkGroup(fd, devs, mounts, "filesystem")
                err_no = ctypes.get_errno()
                failures.append(f"{mount}(filesystem): {os.strerror(err_no)}")
                LOG.debug(
                    "FAN_MARK_FILESYSTEM 失败，退回到挂载点标记",
                    extra={"mount": mount, "errno": err_no},
                )
            marked = 0
            for path in mounts:
                if self._mark(fd, _FAN_MARK_ADD | _FAN_MARK_MOUNT, path) == 0:
                    marked += 1
                else:
                    failures.append(f"{path}(mount): {os.strerror(ctypes.get_errno())}")
            if marked == 0:
                raise SourceError(
                    "无法为挂载点建立 fanotify 监视",
                    hint="; ".join(failures),
                )
            return _MarkGroup(fd, devs, mounts, "mount")
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    def _open_all(self) -> List[_MarkGroup]:
        if not self._targets:
            raise SourceError(
                "没有可监视的挂载点",
                hint="fanotify 只能看到文件系统层事件；被监控盘必须已挂载",
            )
        plan = self._plan_groups()
        if not plan:
            raise SourceError(
                "被监控盘的挂载点都不可访问",
                hint="确认盘已挂载（dwmctl probe 可查看挂载点映射）",
            )
        groups: List[_MarkGroup] = []
        failures: List[str] = []
        for mount, devs, mounts in plan:
            try:
                groups.append(self._open_group(mount, devs, mounts))
            except SourceError as exc:
                failures.append(f"{mount}: {exc}")
        if not groups:
            raise SourceError(
                "所有挂载点都无法建立 fanotify 监视",
                hint="; ".join(failures),
            )
        if failures:
            LOG.warning("部分挂载点 fanotify 标记失败", extra={"failed": failures})
        return groups

    def _pump(self) -> None:
        groups = self._open_all()
        self._groups = groups
        LOG.info(
            "启动事件源",
            extra={
                "source": self.name,
                "groups": [
                    {"mounts": g.mounts, "devs": list(g.devs), "mode": g.mode}
                    for g in groups
                ],
            },
        )
        by_fd = {g.fd: g for g in groups}
        try:
            while not self._stopping.is_set():
                try:
                    readable, _, _ = select.select(list(by_fd), [], [], 0.5)
                except InterruptedError:
                    continue
                except (OSError, ValueError) as exc:
                    raise SourceError(f"select fanotify fd 失败：{exc}")
                for fd in readable:
                    group = by_fd.get(fd)
                    if group is None:
                        continue
                    self._drain(group)
        finally:
            self._close_all()

    def _drain(self, group: _MarkGroup) -> None:
        """把一个 fd 的事件读干净（非阻塞，EAGAIN 即止）。

        单轮最多读 DRAIN_BATCH 次就交还控制权：一次刷出几十万条事件时，
        不能在同一个 fd 上饿死其它超级块。
        """
        for _ in range(DRAIN_BATCH):
            if self._stopping.is_set():
                return
            try:
                data = os.read(group.fd, FANOTIFY_READ_SIZE)
            except InterruptedError:
                continue
            except OSError as exc:
                if exc.errno in (errno.EINTR, errno.EAGAIN):
                    return
                raise SourceError(f"读取 fanotify 事件失败：{exc}")
            if not data:
                return
            for record in parse_fanotify_stream(
                data, time.time(), hint_devs=group.devs, stats=self._stats
            ):
                try:
                    self._on_record(record)
                except Exception:  # noqa: BLE001
                    LOG.exception("处理 fanotify 记录失败")

    def _close_all(self) -> None:
        for group in self._groups:
            try:
                os.close(group.fd)
            except OSError:
                pass
        self._groups = []

    def _cleanup(self) -> None:
        self._close_all()


def probe_fatrace(binary: str = "fatrace") -> dict:
    """供 dwmctl probe 使用：不启动采集，只验证可用性。"""
    result = {"binary": binary, "installed": False, "format": "", "ok": False, "error": ""}
    source = FatraceSource(lambda record: None, binary=binary)
    try:
        source.detect_format()
        result["installed"] = True
        result["format"] = "json" if source._json_mode else "text"
        result["ok"] = True
    except SourceError as exc:
        result["error"] = str(exc)
    return result
