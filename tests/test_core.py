"""纯逻辑单元测试：解析器、设备归一、空闲追踪、归因、存储。

这些不依赖真实磁盘，可在任意平台运行：
    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dwm import db as dbm  # noqa: E402
from dwm.correlator import Correlator, Sample, WakeCandidate  # noqa: E402
from dwm.devices import BlockDevice, MountResolver, partition_to_disk  # noqa: E402
from dwm.diskstats import IdleTracker, parse_diskstats, parse_diskstats_line  # noqa: E402
from dwm.power import parse_start_stop  # noqa: E402
from dwm.procfs import parse_container  # noqa: E402
from dwm.sources import (  # noqa: E402
    devnode_from_idstr,
    parse_blockdump,
    parse_fatrace_json,
    parse_fatrace_text,
)


class TestPartitionToDisk(unittest.TestCase):
    def test_common_patterns(self):
        cases = {
            "sda": "sda",
            "sda1": "sda",
            "sdb12": "sdb",
            "nvme0n1": "nvme0n1",
            "nvme0n1p2": "nvme0n1",
            "mmcblk0p1": "mmcblk0",
            "vdb1": "vdb",
            "/dev/sdc3": "sdc",
        }
        for raw, expected in cases.items():
            self.assertEqual(partition_to_disk(raw), expected, raw)


class TestDiskstats(unittest.TestCase):
    LINE = (
        "   8       0 sda 123456 789 9876543 45678 234567 890 8765432 34567 "
        "0 56789 80234 0 0 0 0 0 0"
    )

    def test_parse_line(self):
        stat = parse_diskstats_line(self.LINE, ts=1000.0)
        self.assertIsNotNone(stat)
        self.assertEqual(stat.name, "sda")
        self.assertEqual(stat.sectors_read, 9876543)
        self.assertEqual(stat.sectors_written, 8765432)
        self.assertEqual(stat.total_sectors, 9876543 + 8765432)

    def test_short_line_ignored(self):
        self.assertIsNone(parse_diskstats_line("8 0 sda 1 2 3", 1.0))

    def test_idle_tracker_detects_wake(self):
        tracker = IdleTracker(idle_threshold_seconds=60)
        t0 = 1000.0
        first = parse_diskstats(
            "   8 0 sdb 0 0 100 0 0 0 200 0 0 0 0", ts=t0
        )
        tracker.prime(first)

        # 60 秒内无 IO
        quiet = parse_diskstats("   8 0 sdb 0 0 100 0 0 0 200 0 0 0 0", ts=t0 + 60)
        self.assertEqual(tracker.update(quiet), [])
        self.assertGreaterEqual(tracker.idle_seconds("sdb", t0 + 60), 59)

        # 突然有 IO
        busy = parse_diskstats("   8 0 sdb 1 0 164 0 0 0 264 0 0 0 0", ts=t0 + 61)
        activities = tracker.update(busy)
        self.assertEqual(len(activities), 1)
        self.assertEqual(activities[0].dev, "sdb")
        self.assertEqual(activities[0].delta_sectors, 128)  # 读 +64、写 +64
        self.assertGreater(activities[0].idle_seconds, 55)


class TestFatraceParsing(unittest.TestCase):
    def test_plain_text(self):
        record = parse_fatrace_text("rsyslogd(875): W /var/log/auth.log", 42.0)
        self.assertIsNotNone(record)
        self.assertEqual(record.pid, 875)
        self.assertEqual(record.comm, "rsyslogd")
        self.assertEqual(record.op, "W")
        self.assertEqual(record.path, "/var/log/auth.log")
        self.assertEqual(record.ts, 42.0)

    def test_with_timestamp_once(self):
        record = parse_fatrace_text("18:00:00.123456 rsync(1234): CW /mnt/usb/a.bin")
        self.assertIsNotNone(record)
        self.assertEqual(record.comm, "rsync")
        self.assertEqual(record.op, "CW")
        self.assertEqual(record.path, "/mnt/usb/a.bin")

    def test_with_timestamp_twice(self):
        record = parse_fatrace_text("1698336000.500000 smbd(99): O /mnt/usb/b.txt")
        self.assertIsNotNone(record)
        self.assertAlmostEqual(record.ts, 1698336000.5, places=3)
        self.assertEqual(record.path, "/mnt/usb/b.txt")

    def test_with_user_field(self):
        record = parse_fatrace_text("smbd(99)[0:0]: R /srv/file")
        self.assertIsNotNone(record)
        self.assertEqual(record.uid, 0)

    def test_device_inode_fallback(self):
        record = parse_fatrace_text("compiz(1971): O device 8:2 inode 658203")
        self.assertIsNotNone(record)
        self.assertEqual(record.path, "")
        self.assertEqual(record.device_hint, "8:2")

    def test_process_name_with_spaces(self):
        record = parse_fatrace_text("python3 script(4242): W /mnt/usb/x.log")
        self.assertIsNotNone(record)
        self.assertEqual(record.comm, "python3 script")
        self.assertEqual(record.pid, 4242)

    def test_garbage_ignored(self):
        self.assertIsNone(parse_fatrace_text(""))
        self.assertIsNone(parse_fatrace_text("totally unrelated line"))

    def test_json_line(self):
        raw = (
            '{"comm":"rsync","pid":1234,"types":"CW","path":"/mnt/usb/a.bin",'
            '"device":{"major":8,"minor":17},"uid":0}'
        )
        record = parse_fatrace_json(raw, 7.0)
        self.assertIsNotNone(record)
        self.assertEqual(record.pid, 1234)
        self.assertEqual(record.comm, "rsync")
        self.assertEqual(record.op, "CW")
        self.assertEqual(record.path, "/mnt/usb/a.bin")
        self.assertEqual(record.device_hint, "8:17")

    def test_json_garbage_ignored(self):
        self.assertIsNone(parse_fatrace_json("{not json"))
        self.assertIsNone(parse_fatrace_json("[1,2,3]"))


class TestBlockDumpParsing(unittest.TestCase):
    def test_legacy_format(self):
        record = parse_blockdump(
            "[ 1234.567] block_dump: WRITE block 8300664 on sdb1 (rsync)", 5.0
        )
        self.assertIsNotNone(record)
        self.assertEqual(record.op, "WRITE")
        self.assertEqual(record.device_hint, "sdb1")
        self.assertEqual(record.comm, "rsync")

    def test_process_pid_format(self):
        record = parse_blockdump(
            "block_dump: READ block 123 on sda (process=smbd, pid=888)"
        )
        self.assertIsNotNone(record)
        self.assertEqual(record.op, "READ")
        self.assertEqual(record.comm, "smbd")
        self.assertEqual(record.pid, 888)

    def test_no_process(self):
        record = parse_blockdump("block_dump: WRITE block 1 on sdb")
        self.assertIsNotNone(record)
        self.assertEqual(record.comm, "")
        self.assertEqual(record.pid, 0)

    def test_non_blockdump_ignored(self):
        self.assertIsNone(parse_blockdump("usb 1-1: new high-speed USB device"))


class TestFanotifyParsing(unittest.TestCase):
    """内建 fanotify 事件缓冲区解析（FAN_CLASS_NOTIF，24 字节头）。"""

    @staticmethod
    def _event(mask, pid, fd, extra=b""):
        import struct as _s

        header = _s.Struct("<IBBHQii")
        body = extra
        return header.pack(header.size + len(body), 3, 0, header.size, mask, pid, fd) + body

    def test_single_event(self):
        from dwm.sources import parse_fanotify_stream

        mask = 0x01 | 0x04  # OPEN | MODIFY
        data = self._event(mask, pid=1234, fd=-1)
        records = parse_fanotify_stream(data, 7.5)
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec.pid, 1234)
        self.assertEqual(rec.op, "OW")
        self.assertEqual(rec.source, "fanotify")
        self.assertEqual(rec.ts, 7.5)

    def test_multiple_events_and_trailing_garbage(self):
        from dwm.sources import parse_fanotify_stream

        e1 = self._event(0x01, 10, -1)          # OPEN
        e2 = self._event(0x02 | 0x08, 20, -1)   # ACCESS | CLOSE_WRITE
        data = e1 + e2 + b"\x00\x01\x02"        # 截断的尾部应被忽略
        records = parse_fanotify_stream(data, 1.0)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].op, "O")
        self.assertEqual(records[1].op, "RC")

    def test_overflow_and_unknown_mask_skipped(self):
        from dwm.sources import parse_fanotify_stream

        overflow = self._event(0x4000, 1, -1)   # FAN_Q_OVERFLOW
        unknown = self._event(0x0100, 2, -1)    # 未订阅的位
        real = self._event(0x01, 3, -1)
        records = parse_fanotify_stream(overflow + unknown + real, 1.0)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].pid, 3)

    def test_fd_event_closes_fd_and_reads_path(self):
        from dwm.sources import parse_fanotify_stream

        # 用一个真实打开的 fd 验证 /proc/self/fd 路径解析（仅 POSIX 可行）
        import os as _os
        import sys as _sys
        if _sys.platform != "win32":
            fd = _os.open(__file__, _os.O_RDONLY)
            try:
                records = parse_fanotify_stream(self._event(0x01, 99, fd), 1.0)
            except Exception:
                _os.close(fd)
                raise
            self.assertEqual(len(records), 1)
            self.assertTrue(records[0].path.endswith("test_core.py"))
            # fd 已被解析器关闭
            with self.assertRaises(OSError):
                _os.fstat(fd)
        else:
            # Windows 上没有 /proc/self/fd，fd=-1 走空路径分支
            records = parse_fanotify_stream(self._event(0x01, 99, -1), 1.0)
            self.assertEqual(records[0].path, "")


class TestStartStopParse(unittest.TestCase):
    def test_standard_line(self):
        output = (
            "ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE\n"
            "  4 Start_Stop_Count        0x0032   098   098   000    Old_age   Always       -       2713\n"
        )
        self.assertEqual(parse_start_stop(output), 2713)

    def test_missing(self):
        self.assertIsNone(parse_start_stop("no attributes here"))


class TestContainerParsing(unittest.TestCase):
    def test_docker_scope(self):
        cgroup = (
            "12:pids:/system.slice/docker-"
            "3f4a5b6c7d8e9f00112233445566778899aabbccddeeff0011223344556677.scope\n"
        )
        label, short = parse_container(cgroup)
        self.assertEqual(len(short), 12)
        self.assertIn("container:", label)

    def test_plain_host(self):
        label, short = parse_container("0::/system.slice/cron.service")
        self.assertEqual((label, short), ("", ""))


class TestMountResolver(unittest.TestCase):
    def _devices(self):
        return {
            "sda": BlockDevice(name="sda", mounts=["/"], monitored=False),
            "sdb": BlockDevice(name="sdb", mounts=["/mnt/usb1"], monitored=True),
            "sdc": BlockDevice(name="sdc", mounts=["/mnt/usb2"], monitored=True),
        }

    def test_longest_prefix_wins(self):
        devices = self._devices()
        devices["sdc"].mounts = ["/mnt/usb1/nested"]
        resolver = MountResolver(devices)
        self.assertEqual(resolver.resolve("/mnt/usb1/nested/deep/file"), "sdc")
        self.assertEqual(resolver.resolve("/mnt/usb1/other/file"), "sdb")

    def test_unmonitored_not_matched(self):
        resolver = MountResolver(self._devices())
        self.assertIsNone(resolver.resolve("/var/log/syslog"))

    def test_prefix_boundary(self):
        resolver = MountResolver(self._devices())
        self.assertIsNone(resolver.resolve("/mnt/usb10/file"))


class TestCorrelator(unittest.TestCase):
    def test_picks_closest_and_counts_hits(self):
        correlator = Correlator(
            ring_buffer_size=1000, lookback_seconds=5.0, lookahead_seconds=3.0
        )
        wake_ts = 1000.0
        # 真正的触发者：紧贴唤醒时刻，只碰一次
        correlator.add("sdb", Sample(ts=wake_ts - 0.2, pid=100, comm="find", path="/mnt/usb1"))
        # 背景噪音：早就不停写
        for offset in (4.5, 4.0, 3.5):
            correlator.add(
                "sdb", Sample(ts=wake_ts - offset, pid=200, comm="rsyslogd", path="/mnt/usb1/a.log")
            )

        suspects = correlator.attribute(WakeCandidate(dev="sdb", ts=wake_ts, idle_seconds=900, confidence="state"))
        self.assertEqual(suspects[0].comm, "find")
        self.assertEqual(suspects[0].pid, 100)

    def test_window_excludes_far_events(self):
        correlator = Correlator(lookback_seconds=5.0, lookahead_seconds=3.0)
        correlator.add("sdb", Sample(ts=100.0, pid=1, comm="old"))
        suspects = correlator.attribute(
            WakeCandidate(dev="sdb", ts=200.0, idle_seconds=900, confidence="state")
        )
        self.assertEqual(suspects, [])

    def test_lookahead_catches_late_io(self):
        correlator = Correlator(lookback_seconds=5.0, lookahead_seconds=3.0)
        correlator.add("sdb", Sample(ts=1002.0, pid=7, comm="smbd", path="/mnt/usb1/f"))
        suspects = correlator.attribute(
            WakeCandidate(dev="sdb", ts=1000.0, idle_seconds=900, confidence="state")
        )
        self.assertEqual(len(suspects), 1)
        self.assertEqual(suspects[0].comm, "smbd")

    def test_unknown_device(self):
        correlator = Correlator()
        self.assertEqual(
            correlator.attribute(
                WakeCandidate(dev="sdz", ts=1.0, idle_seconds=1, confidence="inferred")
            ),
            [],
        )


class TestStorage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dwm-test-")
        self.path = os.path.join(self.tmp, "monitor.db")
        self.conn = dbm.connect(self.path)
        dbm.migrate(self.conn)

    def tearDown(self):
        self.conn.close()
        for name in os.listdir(self.tmp):
            try:
                os.unlink(os.path.join(self.tmp, name))
            except OSError:
                pass
        os.rmdir(self.tmp)

    def test_migration_idempotent(self):
        dbm.migrate(self.conn)
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'"
        ).fetchone()
        self.assertEqual(row["value"], "1")

    def test_device_upsert_and_read(self):
        repo = dbm.DeviceRepo(self.conn)
        repo.upsert([BlockDevice(name="sdb", model="Elements", transport="usb", removable=True, rotational=True, size_bytes=1000, mounts=["/mnt/usb1"], monitored=True, reason="外接")])
        repo.upsert([BlockDevice(name="sdb", model="Elements 25A3", transport="usb", removable=True, rotational=True, size_bytes=2000, mounts=["/mnt/usb1"], monitored=True, reason="外接")])
        rows = repo.all()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["model"], "Elements 25A3")
        self.assertEqual(repo.monitored_names(), ["sdb"])

    def test_wake_with_suspects(self):
        wake_repo = dbm.WakeRepo(self.conn)
        from dwm.correlator import Suspect

        now = time.time()
        wake_id = wake_repo.insert(
            ts=now, dev="sdb", idle_seconds=1800, confidence="smart", note="test", suspect_count=1
        )
        wake_repo.add_suspects(
            wake_id,
            [Suspect(pid=10, comm="rsync", hits=2, first_ts=now - 1, last_ts=now, sample_path="/mnt/usb1/a")],
        )
        rows = wake_repo.recent(hours=1)
        self.assertEqual(len(rows), 1)
        suspects = wake_repo.suspects(wake_id)
        self.assertEqual(len(suspects), 1)
        self.assertEqual(suspects[0]["comm"], "rsync")

    def test_access_batch_and_offenders(self):
        repo = dbm.AccessRepo(self.conn)
        now = time.time()
        rows = [
            (now, "sdb", 1, "rsync", 0, "W", "/mnt/usb1/a", "", "fatrace"),
            (now, "sdb", 1, "rsync", 0, "W", "/mnt/usb1/b", "", "fatrace"),
            (now, "sdb", 2, "smbd", 0, "O", "/mnt/usb1/c", "container:abc", "fatrace"),
        ]
        repo.insert_many(rows)
        offenders = repo.offenders(hours=1)
        self.assertEqual(offenders[0]["comm"], "rsync")
        self.assertEqual(offenders[0]["hits"], 2)

    def test_retention_deletes_old(self):
        repo = dbm.AccessRepo(self.conn)
        old = time.time() - 10 * 86400
        repo.insert_many([(old, "sdb", 1, "old", 0, "W", "/x", "", "fatrace")])
        stats = dbm.run_retention(self.conn, retention_hours=24)
        self.assertEqual(stats["access"], 1)
        self.assertEqual(repo.offenders(hours=24 * 30), [])


class TestConfigValidation(unittest.TestCase):
    def test_env_override_and_coercion(self):
        from dwm.config import Config, validate

        cfg = Config(data_dir=tempfile.mkdtemp(prefix="dwm-cfg-"))
        cfg.port = 9000
        cfg.monitor_devices = ["sdb", "sdc"]
        validate(cfg)
        self.assertEqual(cfg.resolved_db_path, os.path.join(cfg.data_dir, "monitor.db"))

    def test_bad_port_rejected(self):
        from dwm.config import Config, validate
        from dwm.errors import ConfigError

        cfg = Config(data_dir=tempfile.mkdtemp(prefix="dwm-cfg-"))
        cfg.port = 99999
        with self.assertRaises(ConfigError):
            validate(cfg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
