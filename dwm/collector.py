"""采集守护进程：磁盘状态 + 访问事件 + 唤醒判定的编排层。

线程模型（全部写库集中在主线程，避免 sqlite 跨线程问题）：
    main      : 1s 轮询 /proc/diskstats，处理事件队列，落库，判定唤醒
    source-*  : fatrace / block_dump 读行，只往队列塞原始记录
    smart     : 按 smart_interval 轮询硬盘电源态（会阻塞，必须独立线程）
    retention : 定期清理过期数据

三个容易踩的坑，这里都处理了：
1. 观测者效应 —— 自己的进程和辅助工具产生的 IO 必须排除，否则「谁唤醒了盘」的答案会是自己
2. 热插拔 —— fanotify 的监视点在启动时建立，新挂载的外接盘必须重启事件源才能看到
3. 归因时序 —— 硬盘上电有延迟，判定必须等 lookahead 窗口走完再定案
"""

from __future__ import annotations

import logging
import os
import queue
import signal
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from . import db as dbm
from .bus import EventBus
from .config import Config
from .correlator import (
    PHASE_BLOCK,
    Correlator,
    Sample,
    Suspect,
    WakeCandidate,
)
from .devices import (
    BlockDevice,
    MountResolver,
    enumerate_devices,
    partition_to_disk,
    stat_dev_map,
)
from .diskstats import IdleTracker, read_diskstats
from .errors import DeviceError, DwmError
from .power import (
    STATE_ACTIVE,
    STATE_STANDBY,
    STATE_UNKNOWN,
    PowerSample,
    PowerStateTracker,
    SmartReader,
)
from .procfs import ProcCache, iter_open_fds_on
from .sources import (
    BLOCK_DUMP_SYSCTL,
    AccessRecord,
    BlockDumpSource,
    EventSource,
    FatraceSource,
    FanotifySource,
    NullSource,
    devnode_from_idstr,
    probe_fatrace,
)

LOG = logging.getLogger("dwm.collector")

CONFIDENCE_RANK = {"inferred": 1, "state": 2, "smart": 3}
DEVICE_REFRESH_SECONDS = 30.0
RETENTION_INTERVAL_SECONDS = 600.0
QUEUE_MAX = 50000
BATCH_FLUSH_SIZE = 300
FDSCAN_MIN_INTERVAL = 3.0  # 同一块盘两次 fd 扫描的最小间隔（秒）
NOTE_NO_EVIDENCE = "；窗口内未捕获到归因事件（可能来自内核后台任务、SMART 查询或总线层事件）"


@dataclass
class _Pending:
    candidate: WakeCandidate


class Collector:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.bus = EventBus()
        self.conn = dbm.connect(cfg.resolved_db_path)
        dbm.migrate(self.conn)
        self.devices_repo = dbm.DeviceRepo(self.conn)
        self.access_repo = dbm.AccessRepo(self.conn)
        self.wake_repo = dbm.WakeRepo(self.conn)
        self.power_repo = dbm.PowerRepo(self.conn)

        self.devices: Dict[str, BlockDevice] = {}
        self.monitored: Set[str] = set()
        self.resolver = MountResolver({})
        self._statdev: Dict[int, List[str]] = {}
        self._pathdir_cache: Dict[str, Tuple[str, ...]] = {}
        # 事件产出统计：归因排查的关键可见性——「源没吐事件」和
        # 「吐了事件但归属不到盘」是两种完全不同的故障，必须分开看。
        # no_dev 只统计「路径解析不出设备」，not_monitored 是「解析出来了但没监控」。
        self._source_stats = {"seen": 0, "kept": 0, "no_dev": 0, "not_monitored": 0}
        self._suppressed_active = 0
        self._fd_hits: Dict[str, Tuple[float, List[Tuple[int, str, str]]]] = {}
        self._last_fdscan: Dict[str, float] = {}
        self._smart_runs: Dict[str, List[Tuple[float, float]]] = {}
        self.tracker = IdleTracker(cfg.idle_threshold_seconds)
        self.correlator = Correlator(
            ring_buffer_size=cfg.ring_buffer_size,
            lookback_seconds=cfg.suspect_lookback_seconds,
            lookahead_seconds=cfg.suspect_lookahead_seconds,
            spinup_floor_seconds=cfg.suspect_spinup_floor_seconds,
        )
        self.proc_cache = ProcCache()

        self.smart = SmartReader(cfg.smartctl_binary, cfg.smart_timeout)
        self.power_tracker = PowerStateTracker()

        self._own_pid = os.getpid()
        self._ignore_comms = {c.lower() for c in cfg.ignore_comms}
        self._queue: "queue.Queue[Tuple[str, object]]" = queue.Queue(maxsize=QUEUE_MAX)
        self._batch: List[tuple] = []
        self._pending: List[_Pending] = []
        self._recent_wakes: Dict[str, Tuple[float, int, str]] = {}
        self._source: Optional[EventSource] = None
        self._mount_signature = ""
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self._dropped = 0
        self._last_refresh = 0.0
        self._last_retention = time.time()
        self._start_ts = time.time()

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------
    def run(self) -> None:
        self._refresh_devices(initial=True)
        signature = self._signature()
        self._start_source(signature)

        try:
            stats = read_diskstats()
            self.tracker.prime(stats)
        except OSError as exc:
            raise DwmError(
                f"无法读取 /proc/diskstats：{exc}",
                hint="本工具需要 Linux 环境与 root 权限",
            ) from exc

        LOG.info(
            "采集已启动",
            extra={
                "monitored": sorted(self.monitored),
                "idle_threshold": self.cfg.idle_threshold_seconds,
                "db": self.cfg.resolved_db_path,
                "smart": self.smart.available and self.cfg.smart_enabled,
            },
        )

        if self.cfg.smart_enabled and not self.smart.available:
            LOG.warning("smartctl 未安装，唤醒判定退化为「久静后 IO」推断模式")

        self._spawn(self._smart_loop, "smart")
        self._spawn(self._retention_loop, "retention")

        try:
            self._main_loop()
        finally:
            self.shutdown()

    def _spawn(self, target, name: str) -> None:
        thread = threading.Thread(target=target, name=name, daemon=True)
        thread.start()
        self._threads.append(thread)

    def request_stop(self) -> None:
        self._stop.set()

    def shutdown(self) -> None:
        if self._stop.is_set() and self._source is None:
            return
        LOG.info("正在停止采集")
        self._stop.set()

        if self._source is not None:
            try:
                self._source.stop()
            except Exception:  # noqa: BLE001
                LOG.exception("停止事件源失败")
            self._source = None

        for thread in self._threads:
            if thread.is_alive():
                thread.join(timeout=5.0)

        # 停服前把待定唤醒强行定案，避免丢事件
        self._drain_queue(limit=QUEUE_MAX)
        self._flush_batch()
        for pending in list(self._pending):
            self._finalize(pending)
        self._pending.clear()

        try:
            self.conn.close()
        except Exception:  # noqa: BLE001
            pass
        LOG.info("采集已停止", extra={"uptime_seconds": round(time.time() - self._start_ts, 1)})

    # ------------------------------------------------------------------
    # 设备
    # ------------------------------------------------------------------
    def _refresh_devices(self, initial: bool = False) -> None:
        try:
            devices = enumerate_devices(
                monitor_only_sleepable=self.cfg.monitor_only_sleepable,
                monitor_devices=self.cfg.monitor_devices,
                exclude_devices=self.cfg.exclude_devices,
            )
        except DeviceError as exc:
            if initial:
                raise
            LOG.warning("刷新设备列表失败", extra={"error": str(exc)})
            return

        self.devices = devices
        self.monitored = {name for name, dev in devices.items() if dev.monitored}
        self.resolver = MountResolver(devices)
        self._statdev = stat_dev_map(devices)
        self._pathdir_cache = {}
        try:
            self.devices_repo.upsert(devices.values())
        except DwmError as exc:
            LOG.warning("写入设备表失败", extra={"error": str(exc)})

        if initial:
            for name, dev in sorted(devices.items()):
                if dev.monitored:
                    LOG.info(
                        "纳入监控",
                        extra={
                            "dev": name,
                            "model": dev.model,
                            "transport": dev.transport,
                            "mounts": dev.mounts,
                            "reason": dev.reason,
                        },
                    )
                else:
                    LOG.debug("跳过设备", extra={"dev": name, "reason": dev.reason})
            if not self.monitored:
                LOG.warning(
                    "没有发现可监控的休眠盘",
                    hint="确认外接硬盘已挂载；或用 DWM_MONITOR_DEVICES=sdb 强制指定",
                )
            self._warn_if_db_on_monitored_disk()
        self._last_refresh = time.time()

    def _warn_if_db_on_monitored_disk(self) -> None:
        db_path = self.cfg.resolved_db_path
        owner = self.resolver.resolve(db_path)
        if owner:
            LOG.warning(
                "数据库文件位于被监控的磁盘上，本工具自身的写入会干扰观测",
                extra={
                    "db": db_path,
                    "dev": owner,
                    "hint": "建议把 data_dir 放到系统盘",
                },
            )

    def _signature(self) -> str:
        parts = []
        for name in sorted(self.monitored):
            for mount in sorted(self.devices[name].mounts):
                parts.append(f"{name}:{mount}")
        return "|".join(parts)

    # ------------------------------------------------------------------
    # 事件源
    # ------------------------------------------------------------------
    def _fanotify_targets(self) -> List[Tuple[str, Tuple[str, ...]]]:
        """挂载点 → 候选设备，供 fanotify 按超级块分组。

        一个挂载点可能对应多块成员盘（md / btrfs 多设备），全部带上，
        事件进每一块的环，而不是只认第一块。
        """
        by_mount: Dict[str, List[str]] = {}
        for name in sorted(self.monitored):
            device = self.devices.get(name)
            if device is None:
                continue
            for mount in device.mounts:
                bucket = by_mount.setdefault(mount, [])
                if name not in bucket:
                    bucket.append(name)
        return [(mount, tuple(devs)) for mount, devs in sorted(by_mount.items())]

    def _start_source(self, signature: str) -> None:
        cfg = self.cfg
        source: Optional[EventSource] = None
        targets = self._fanotify_targets()

        # 内建 fanotify：用 FAN_MARK_FILESYSTEM 盯整个超级块，容器里的
        # bind mount 一样能看见。fatrace 只打挂载点，在 fnOS 上（应用几乎
        # 全是容器）会系统性漏事件，所以内建源默认排在前面。
        builtin_probe = (
            FanotifySource.probe([mount for mount, _ in targets])
            if targets
            else {"ok": False, "error": "被监控盘均未挂载", "mark": "", "filesystem": False}
        )

        def _builtin() -> FanotifySource:
            return FanotifySource(
                self._on_record,
                targets=targets,
                prefer_filesystem=cfg.fanotify_prefer_filesystem
                and bool(builtin_probe.get("filesystem")),
            )

        if cfg.prefer_builtin_fanotify and builtin_probe["ok"]:
            source = _builtin()
            LOG.info(
                "使用内建 fanotify 事件源",
                extra={
                    "mark": builtin_probe["mark"],
                    "mounts": [mount for mount, _ in targets],
                },
            )
        elif not builtin_probe["ok"] and targets:
            LOG.warning(
                "内建 fanotify 不可用，尝试其他事件源",
                extra={"error": builtin_probe["error"]},
            )

        if source is None and cfg.fatrace_enabled:
            probe = probe_fatrace(cfg.fatrace_binary)
            if probe["ok"]:
                source = FatraceSource(
                    self._on_record,
                    binary=cfg.fatrace_binary,
                    event_filter=cfg.fatrace_filter,
                )
                if targets:
                    LOG.warning(
                        "退回 fatrace：它按挂载点打标记，容器内的访问看不到",
                        extra={"hint": "确认 fanotify 可用（dwmctl probe），或保持 prefer_builtin_fanotify=true"},
                    )
            else:
                LOG.warning(
                    "fatrace 不可用，尝试降级",
                    extra={"error": probe["error"], "fallback": cfg.blockdump_fallback},
                )

        if source is None and builtin_probe["ok"]:
            # prefer_builtin_fanotify=false 时才会走到这里
            source = _builtin()
            LOG.info(
                "使用内建 fanotify 事件源",
                extra={"mark": builtin_probe["mark"]},
            )

        if source is None and (cfg.blockdump_enabled or cfg.blockdump_fallback):
            # 内核 5.10 起移除了 block_dump：sysctl 可能还在但内核不再产出 IO 日志。
            if os.path.exists(BLOCK_DUMP_SYSCTL):
                source = BlockDumpSource(self._on_record)
                LOG.info("使用 block_dump 作为事件源（只有设备级信息，无文件路径）")
            else:
                LOG.warning(
                    "内核已移除 block_dump（5.10+），该兜底不可用",
                    extra={"hint": "确认 fanotify 可用，或安装 fatrace"},
                )

        if source is None:
            source = NullSource(self._on_record)

        self._source = source
        self._mount_signature = signature
        source.start()

    def _restart_source(self, signature: str) -> None:
        LOG.info("挂载点发生变化，重启事件源以覆盖新挂载的外接盘")
        if self._source is not None:
            self._source.stop()
        self._start_source(signature)

    def _on_record(self, record: AccessRecord) -> None:
        """事件源线程回调：只入队，绝不在这里碰数据库。"""
        try:
            self._queue.put_nowait(("access", record))
        except queue.Full:
            self._dropped += 1

    # ------------------------------------------------------------------
    # 主循环
    # ------------------------------------------------------------------
    def _main_loop(self) -> None:
        next_tick = time.monotonic()
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                self._tick()
            except Exception:  # noqa: BLE001 - 主循环不允许因单次异常退出
                LOG.exception("主循环单次处理异常")

            next_tick += self.cfg.poll_interval
            drift = next_tick - time.monotonic()
            if drift > 0:
                self._stop.wait(drift)
            else:
                next_tick = time.monotonic()

    def _tick(self) -> None:
        self._drain_queue()
        self._flush_batch()
        self._poll_diskstats()
        self._finalize_due()
        self._periodic()

    def _drain_queue(self, limit: int = 5000) -> None:
        for _ in range(limit):
            try:
                kind, payload = self._queue.get_nowait()
            except queue.Empty:
                break
            if kind == "access":
                self._handle_access(payload)  # type: ignore[arg-type]
            elif kind == "wake":
                self._enqueue_wake(payload)  # type: ignore[arg-type]
            elif kind == "smart_wake":
                self._handle_smart_wake(payload)
            elif kind == "fdscan":
                self._handle_fdscan(payload)
            elif kind == "power":
                self._handle_power(payload)  # type: ignore[arg-type]
            elif kind == "clear_pending":
                dev = payload
                self._pending = [
                    p for p in self._pending if p.candidate.dev != dev
                ]
                self._recent_wakes.pop(dev, None)

    def _resolve_devs(self, path: str) -> List[str]:
        """路径 → 整盘名候选：先最长前缀匹配，失败再用 st_dev 兜底。

        st_dev 兜底覆盖前缀匹配管不到的场景：btrfs 多设备、LVM、
        挂载点符号链接（fnOS 的 /vol* 就属于这类）。
        按目录缓存，避免每个事件一次 stat。
        返回列表是因为一个挂载点可能对应多块成员盘。
        """
        devs = self.resolver.resolve_all(path)
        if devs:
            return devs

        parent = os.path.dirname(path) or path
        if parent in self._pathdir_cache:
            return list(self._pathdir_cache[parent] or ())
        try:
            devs = list(self._statdev.get(os.stat(parent).st_dev) or [])
        except OSError:
            devs = []
        if len(self._pathdir_cache) > 4096:
            self._pathdir_cache.clear()
        self._pathdir_cache[parent] = tuple(devs)
        return devs

    def _is_ignored(self, info, comm: str) -> bool:
        """观测者自身产生的 IO 必须排除。

        fanotify 的 comm 是空的（要从 /proc 补），所以过滤只能放在补全之后；
        另外 smartctl 是本进程的子进程，按父进程链再兜一层。
        """
        if comm and comm.lower() in self._ignore_comms:
            return True
        if info is None:
            return False
        if info.comm and info.comm.lower() in self._ignore_comms:
            return True
        for _pid, parent_comm in info.parents:
            if parent_comm and parent_comm.lower() in self._ignore_comms:
                return True
        first = (info.cmdline or "").split(" ")[0].rsplit("/", 1)[-1]
        if first and first.lower() in self._ignore_comms:
            return True
        return False

    def _handle_access(self, record: AccessRecord) -> None:
        self._source_stats["seen"] += 1
        if record.pid == self._own_pid:
            return

        devs: List[str] = []
        if record.path:
            devs = self._resolve_devs(record.path)
        # 事件源能确定的归属（fanotify 超级块分组）优先于路径猜测
        if not devs and record.hint_devs:
            devs = list(record.hint_devs)
        if not devs and record.device_hint:
            node = devnode_from_idstr(record.device_hint)
            if node:
                devs = [partition_to_disk(node)]

        monitored = [d for d in devs if d in self.monitored]
        if not monitored:
            # 解析到了但不在监控范围（系统盘、容器 overlay、未挂载的盘）
            # 和「根本解析不出来」是两种问题，混在一起会误导读数
            if devs:
                self._source_stats["not_monitored"] += 1
            else:
                self._source_stats["no_dev"] += 1
                if self._source_stats["no_dev"] in (1, 50, 500) or (
                    self._source_stats["no_dev"] % 5000 == 0
                ):
                    LOG.warning(
                        "访问事件无法归属到任何块设备，已丢弃",
                        extra={
                            "path": record.path[:200],
                            "hint": "检查挂载点映射（dwmctl probe），或盘未挂载",
                        },
                    )
            return

        info = self.proc_cache.get(record.pid, comm_hint=record.comm)
        comm = info.comm or record.comm
        if self._is_ignored(info, comm):
            return

        self._source_stats["kept"] += 1
        sample = Sample(
            ts=record.ts,
            pid=record.pid,
            comm=comm,
            op=record.op,
            path=record.path,
            uid=info.uid if info.uid is not None else record.uid,
            container=info.container,
            cmdline=info.cmdline,
            source=record.source,
            ambiguous=len(monitored) > 1,
        )
        record.dev = monitored[0]
        # 多成员盘：样本进每一块的环，否则另一块的归因永远是空的
        for dev in monitored:
            self.correlator.add(dev, sample)
        self._batch.append(sample.to_row(monitored[0]))
        if len(self._batch) >= BATCH_FLUSH_SIZE:
            self._flush_batch()

    def _handle_power(self, sample: PowerSample) -> None:
        dev = partition_to_disk(os.path.basename(sample.dev))
        try:
            self.power_repo.insert(
                sample.ts, dev, sample.state, sample.start_stop, sample.raw
            )
        except DwmError as exc:
            LOG.warning("写入电源采样失败", extra={"error": str(exc)})

    def _record_smart_run(self, dev: str, started: float, finished: float) -> None:
        """记下每次 smartctl 查询的时间段。

        有些 USB 桥接盒被 `smartctl -n standby` 问一句就会转盘 —— 这种唤醒
        没有任何文件系统事件，注解里必须能指出来，否则用户永远查不到原因。
        """
        runs = self._smart_runs.setdefault(dev, [])
        runs.append((started, finished))
        horizon = finished - max(self.cfg.smart_interval * 4, 300.0)
        self._smart_runs[dev] = [r for r in runs if r[1] >= horizon][-32:]

    def _smart_overlaps(self, dev: str, low: float, high: float) -> bool:
        for started, finished in self._smart_runs.get(dev, []):
            if finished >= low and started <= high:
                return True
        return False

    def _flush_batch(self) -> None:
        if not self._batch:
            return
        rows, self._batch = self._batch, []
        try:
            self.access_repo.insert_many(rows)
        except DwmError as exc:
            LOG.warning("写入访问事件失败", extra={"error": str(exc), "count": len(rows)})

    # ------------------------------------------------------------------
    # 唤醒判定
    # ------------------------------------------------------------------
    def _poll_diskstats(self) -> None:
        try:
            stats = read_diskstats()
        except OSError as exc:
            LOG.warning("读取 /proc/diskstats 失败", extra={"error": str(exc)})
            return

        tracked = {name: stats[name] for name in self.monitored if name in stats}
        activities = self.tracker.update(tracked)

        for activity in activities:
            idle = activity.idle_seconds
            if idle < self.cfg.idle_threshold_seconds:
                continue

            state = self.power_tracker.last_state(activity.dev)
            if state == STATE_ACTIVE and not self.cfg.assume_sleep_on_idle:
                # 盘一直是醒的：不是唤醒，而是「阻止休眠」现象。
                # 这类线索体现在「阻止休眠的元凶」面板里，不记为唤醒事件。
                self._suppressed_active += 1
                LOG.debug(
                    "有 IO 但盘未休眠，属于阻止休眠场景",
                    extra={"dev": activity.dev, "idle": round(idle, 1)},
                )
                continue

            # 块层访问（smartctl / hdparm / md check / btrfs transaction）
            # 不会进 fanotify，只能靠「谁开着 /dev/sdX」反查。
            # 必须现在扫：定案时要等 lookahead，短命进程早退出了。
            self._start_fdscan(activity.dev)

            if state == STATE_ACTIVE:
                confidence = "inferred"
            else:
                confidence = "state" if state != STATE_UNKNOWN else "inferred"
            note = (
                f"diskstats 显示空闲 {idle:.0f}s 后出现 {activity.delta_sectors} 扇区 IO"
                f"（首次观测到增量的时刻，实际下发更早；SMART 电源态 {state}）"
            )
            self._enqueue_wake(
                WakeCandidate(
                    dev=activity.dev,
                    ts=activity.ts,
                    idle_seconds=idle,
                    confidence=confidence,
                    note=note,
                )
            )

    def _start_fdscan(self, dev: str) -> None:
        """扫描「谁开着 /dev/sdX」，结果异步回主循环。

        这条线索只在块层访问时有用（smartctl、hdparm、阵列校验、btrfs
        transaction 都不经过文件系统），但它是这类唤醒唯一的证据来源。
        """
        if not self.cfg.fdscan_enabled:
            return
        now = time.time()
        if now - self._last_fdscan.get(dev, 0.0) < FDSCAN_MIN_INTERVAL:
            return
        self._last_fdscan[dev] = now

        thread = threading.Thread(
            target=self._fdscan_worker, args=(dev, now), name=f"fdscan-{dev}", daemon=True
        )
        thread.start()

    def _fdscan_worker(self, dev: str, started: float) -> None:
        try:
            hits = iter_open_fds_on([f"/dev/{dev}"])
        except Exception:  # noqa: BLE001 - 扫描失败不影响采集
            LOG.debug("扫描设备句柄失败", extra={"dev": dev}, exc_info=True)
            return
        resolved: List[Tuple[int, str, str]] = []
        for pid, _link in hits:
            if pid == self._own_pid:
                continue
            try:
                info = self.proc_cache.get(pid)
            except Exception:  # noqa: BLE001
                info = None
            comm = (info.comm if info else "") or ""
            if not comm:
                continue
            if self._is_ignored(info, comm):
                continue
            resolved.append((pid, comm, info.cmdline if info else ""))
        if not resolved:
            return
        try:
            self._queue.put_nowait(("fdscan", (dev, started, resolved)))
        except queue.Full:
            pass

    def _handle_fdscan(self, payload) -> None:
        dev, started, hits = payload
        self._fd_hits[dev] = (started, hits)

    def _block_evidence(self, candidate: WakeCandidate) -> List[Suspect]:
        """窗口里没有文件系统事件时，用「谁开着 /dev/sdX」给出块层证据。"""
        hit = self._fd_hits.get(candidate.dev)
        if not hit:
            return []
        scanned_at, hits = hit
        low = candidate.ts - self.cfg.suspect_lookback_seconds
        high = candidate.ts + self.cfg.suspect_lookahead_seconds
        if not (low <= scanned_at <= high):
            return []  # 上一轮唤醒留下的旧扫描结果，不能用
        return [
            Suspect(
                pid=pid,
                comm=comm,
                hits=1,
                first_ts=scanned_at,
                last_ts=scanned_at,
                cmdline=cmdline,
                phase=PHASE_BLOCK,
            )
            for pid, comm, cmdline in hits[:8]
        ]

    def _enqueue_wake(self, candidate: WakeCandidate) -> None:
        now = time.time()
        window = self.cfg.dedupe_window_seconds

        # 先看「尚未定案」的候选：diskstats 与 SMART 常在几秒内各报一次，
        # 不合并就会把同一次唤醒记成两条。
        for pending in self._pending:
            existing = pending.candidate
            if existing.dev != candidate.dev:
                continue
            if abs(existing.ts - candidate.ts) > window:
                continue
            if CONFIDENCE_RANK.get(candidate.confidence, 0) > CONFIDENCE_RANK.get(
                existing.confidence, 0
            ):
                existing.confidence = candidate.confidence
            if candidate.note and candidate.note not in existing.note:
                existing.note = f"{existing.note}；{candidate.note}"
            existing.idle_seconds = max(existing.idle_seconds, candidate.idle_seconds)
            existing.deadline = max(
                existing.deadline, candidate.ts + self.cfg.suspect_lookahead_seconds
            )
            return

        recent = self._recent_wakes.get(candidate.dev)
        if recent:
            last_ts, wake_id, last_conf = recent
            if now - last_ts <= window:
                if CONFIDENCE_RANK.get(candidate.confidence, 0) > CONFIDENCE_RANK.get(
                    last_conf, 0
                ):
                    try:
                        self.wake_repo.upgrade_confidence(
                            wake_id, candidate.confidence, candidate.note
                        )
                    except DwmError as exc:
                        LOG.warning("升级唤醒置信度失败", extra={"error": str(exc)})
                    self._recent_wakes[candidate.dev] = (
                        last_ts,
                        wake_id,
                        candidate.confidence,
                    )
                return

        candidate.deadline = candidate.ts + self.cfg.suspect_lookahead_seconds
        self._pending.append(_Pending(candidate=candidate))

    def _finalize_due(self) -> None:
        now = time.time()
        remaining: List[_Pending] = []
        for pending in self._pending:
            if pending.candidate.deadline <= now:
                self._finalize(pending)
            else:
                remaining.append(pending)
        self._pending = remaining

    def _finalize(self, pending: _Pending) -> None:
        candidate = pending.candidate
        suspects = self.correlator.attribute(candidate)

        note = candidate.note
        if not suspects:
            # 窗口里没有文件系统事件：查块层证据（谁开着 /dev/sdX），
            # 并检查是不是我们自己的 smartctl 把盘问醒的。
            block_hits = self._block_evidence(candidate)
            if block_hits:
                suspects = block_hits
                note = (
                    f"{note}；没有文件系统事件，改为块层证据：唤醒窗口内有进程"
                    f"持有 /dev/{candidate.dev}（内核对写 / 阵列校验 / 直接开设备节点）"
                )
            else:
                note = f"{note}{NOTE_NO_EVIDENCE}"
                if self._smart_overlaps(
                    candidate.dev,
                    candidate.ts - self.cfg.suspect_lookback_seconds,
                    candidate.ts + self.cfg.suspect_lookahead_seconds,
                ):
                    note = (
                        f"{note}；同一时段本工具执行过 smartctl 电源态查询，"
                        "部分 USB 硬盘盒被查询即转盘，可把 smart_interval 调大或关闭 SMART 轮询对照"
                    )

        try:
            wake_id = self.wake_repo.insert(
                ts=candidate.ts,
                dev=candidate.dev,
                idle_seconds=candidate.idle_seconds,
                confidence=candidate.confidence,
                note=note,
                suspect_count=len(suspects),
            )
            self.wake_repo.add_suspects(wake_id, suspects)
        except DwmError as exc:
            LOG.warning("写入唤醒事件失败", extra={"error": str(exc)})
            return

        self._recent_wakes[candidate.dev] = (candidate.ts, wake_id, candidate.confidence)
        LOG.info(
            "检测到硬盘唤醒",
            extra={
                "dev": candidate.dev,
                "idle_seconds": round(candidate.idle_seconds, 1),
                "confidence": candidate.confidence,
                "suspects": [
                    {"pid": s.pid, "comm": s.comm, "hits": s.hits, "container": s.container}
                    for s in suspects[:3]
                ],
            },
        )
        self.bus.publish(
            {
                "type": "wake",
                "wake": {
                    "id": wake_id,
                    "ts": candidate.ts,
                    "dev": candidate.dev,
                    "idle_seconds": candidate.idle_seconds,
                    "confidence": candidate.confidence,
                    "note": note,
                    "suspect_count": len(suspects),
                    "suspects": [s.to_dict() for s in suspects[:8]],
                },
            }
        )

    # ------------------------------------------------------------------
    # 后台线程
    # ------------------------------------------------------------------
    def _smart_loop(self) -> None:
        if not self.cfg.smart_enabled:
            return
        if not self.smart.available:
            LOG.info("SMART 轮询未启用：smartctl 不可用")
            return

        while not self._stop.is_set():
            started = time.monotonic()
            for name in sorted(self.monitored):
                if self._stop.is_set():
                    break
                device = self.devices.get(name)
                if device is None:
                    continue
                probe_started = time.time()
                sample = self.smart.sample(device.dev_path)
                probe_finished = time.time()
                if sample.state != STATE_UNKNOWN:
                    woke, reason = self.power_tracker.observe(sample)
                else:
                    woke, reason = False, ""
                self._record_smart_run(name, probe_started, probe_finished)
                try:
                    self._queue.put_nowait(("power", sample))
                except queue.Full:
                    pass
                if woke:
                    # 不在采样时刻新建一条唤醒：SMART 只是「确认」，
                    # 真正的 IO 发生在上一轮轮询之后，可能已经过去几十秒。
                    try:
                        self._queue.put_nowait(
                            ("smart_wake", (name, sample.ts, reason))
                        )
                    except queue.Full:
                        pass
            elapsed = time.monotonic() - started
            self._stop.wait(max(1.0, self.cfg.smart_interval - elapsed))

    def _handle_smart_wake(self, payload) -> None:
        """SMART 确认的唤醒：优先升级已有记录，而不是另插一条。

        diskstats 和 SMART 各自独立报一次，若把 SMART 当成新的唤醒，
        就会出现「置信度最高、窗口里却没有任何访问」的记录 —— 因为候选
        时间用的是采样时刻，比真正触发晚了半个轮询周期。
        """
        dev, ts, reason = payload
        if dev not in self.monitored:
            return
        window = max(
            self.cfg.smart_interval + self.cfg.suspect_lookahead_seconds,
            self.cfg.dedupe_window_seconds,
        )
        note = (
            f"SMART 确认：{reason}"
            f"（轮询间隔 {self.cfg.smart_interval:.0f}s，实际唤醒发生在上次轮询之后）"
        )

        # 1) 还没定案的候选：直接升级并追加说明
        for pending in self._pending:
            existing = pending.candidate
            if existing.dev != dev:
                continue
            if not (ts - window <= existing.ts <= ts + self.cfg.suspect_lookahead_seconds):
                continue
            existing.confidence = "smart"
            if note not in existing.note:
                existing.note = f"{existing.note}；{note}" if existing.note else note
            existing.deadline = max(
                existing.deadline, ts + self.cfg.suspect_lookahead_seconds
            )
            return

        # 2) 已定案的最近一条：升级置信度，并重跑一次归因
        #    （定案时用的窗口可能不含真正的触发者，环还在内存里，重算是免费的）
        recent = self._recent_wakes.get(dev)
        if recent:
            last_ts, wake_id, _last_conf = recent
            if ts - last_ts <= window:
                self._upgrade_finalized(dev, last_ts, wake_id, note)
                return

        # 3) 没有扇区增量，只有 SMART 报警：这才是真的「无 IO 唤醒」
        self._enqueue_wake(
            WakeCandidate(
                dev=dev,
                ts=ts,
                idle_seconds=self.tracker.idle_seconds(dev),
                confidence="smart",
                note=note,
            )
        )

    def _upgrade_finalized(self, dev: str, wake_ts: float, wake_id: int, note: str) -> None:
        try:
            row = self.wake_repo.get(wake_id)
            previous_note = (row["note"] if row is not None else "") or ""
            previous_count = int(row["suspect_count"]) if row is not None else 0
            merged = previous_note
            if note and note not in merged:
                merged = f"{merged}；{note}" if merged else note

            suspects: List[Suspect] = []
            wide = 0.0
            if previous_count == 0:
                # 定案时窗口里什么都没有：SMART 说明「上一轮轮询之后醒过」，
                # 锚点不可靠，把窗口放到一个轮询周期再看一次
                wide = max(
                    self.cfg.smart_interval + self.cfg.suspect_lookahead_seconds,
                    self.cfg.suspect_lookback_seconds,
                )
                suspects = self.correlator.attribute(
                    WakeCandidate(
                        dev=dev, ts=wake_ts, idle_seconds=0.0, confidence="smart"
                    ),
                    lookback=wide,
                )

            if suspects:
                self.wake_repo.replace_suspects(wake_id, suspects)
                self.wake_repo.set_suspect_count(wake_id, len(suspects))
                merged = merged.replace(NOTE_NO_EVIDENCE, "")
                merged = (
                    f"{merged}；归因窗口放宽到 {wide:.0f} 秒（SMART 只能确定上个轮询"
                    "周期内醒过），时间点仅供参考"
                )
            self.wake_repo.upgrade_confidence(wake_id, "smart", merged)

            if suspects:
                self.bus.publish(
                    {
                        "type": "wake_updated",
                        "wake_id": wake_id,
                        "dev": dev,
                        "suspect_count": len(suspects),
                    }
                )
                LOG.info(
                    "SMART 确认后放宽窗口重跑归因，补上了嫌疑进程",
                    extra={
                        "dev": dev,
                        "wake_id": wake_id,
                        "window": round(wide, 1),
                        "suspects": [s.comm for s in suspects[:3]],
                    },
                )
        except DwmError as exc:
            LOG.warning("升级唤醒记录失败", extra={"error": str(exc), "wake_id": wake_id})

    def _retention_loop(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(RETENTION_INTERVAL_SECONDS)
            if self._stop.is_set():
                break
            try:
                stats = dbm.run_retention(self.conn, self.cfg.retention_hours)
                self.correlator.prune()
                LOG.info("过期数据清理完成", extra=stats)
            except DwmError as exc:
                LOG.warning("清理过期数据失败", extra={"error": str(exc)})
            except Exception:  # noqa: BLE001
                LOG.exception("清理线程异常")

    def _periodic(self) -> None:
        now = time.time()
        if now - self._last_refresh >= DEVICE_REFRESH_SECONDS:
            self._refresh_devices()
            signature = self._signature()
            if signature != self._mount_signature and self._source is not None:
                self._restart_source(signature)
        if self._dropped:
            LOG.warning("事件队列溢出，已丢弃记录", extra={"dropped": self._dropped})
            self._dropped = 0

    # ------------------------------------------------------------------
    # 按盘清除（供 API 调用；DB 删除由调用方完成，这里只清内存态）
    # ------------------------------------------------------------------
    def clear_memory(self, dev: str) -> dict:
        """清掉某块盘的归因内存环与待定唤醒，避免旧记录再参与归因。

        会被 HTTP 线程调用，所以真正干活的部分投递回主循环执行。
        """
        removed = self.correlator.clear_dev(dev)
        try:
            self._queue.put_nowait(("clear_pending", dev))
        except queue.Full:
            pass
        LOG.info("已清除盘的内存归因数据", extra={"dev": dev, "samples": removed})
        return {"samples": removed}

    # ------------------------------------------------------------------
    # 状态快照（供 API 复用）
    # ------------------------------------------------------------------
    def snapshot(self) -> dict:
        io_stats = dict(self._source_stats)
        # 事件源自己的计数器（溢出、路径解析失败）必须并进来，
        # 否则「事件丢了」在面板上完全看不见
        if self._source is not None:
            try:
                for key, value in (self._source.stats() or {}).items():
                    io_stats[key] = value
            except Exception:  # noqa: BLE001
                LOG.debug("读取事件源计数失败", exc_info=True)
        io_stats["queue_dropped"] = self._dropped
        io_stats["suppressed_active"] = self._suppressed_active
        return {
            "uptime_seconds": round(time.time() - self._start_ts, 1),
            "monitored": sorted(self.monitored),
            "idle": {
                name: round(self.tracker.idle_seconds(name), 1) for name in sorted(self.monitored)
            },
            "power_state": {
                name: self.power_tracker.last_state(name) for name in sorted(self.monitored)
            },
            "source": self._source.name if self._source else "none",
            "source_mounts": (
                list(getattr(self._source, "mounts", []) or []) if self._source else []
            ),
            "io_stats": io_stats,
            "queue_depth": self._queue.qsize(),
            "dropped": self._dropped,
            "pending_wakes": len(self._pending),
        }


def run(cfg: Config) -> int:
    collector = Collector(cfg)

    def _handle_signal(signum, _frame):  # pragma: no cover - 信号路径
        LOG.info("收到退出信号", extra={"signal": signum})
        collector.request_stop()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    collector.run()
    return 0
