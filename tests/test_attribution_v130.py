"""v1.3.0 归因链路的回归测试。

这一版修的是「唤醒能记下来、但谁干的永远对不上」的一串连锁断点：
1. 电源态键写成 /dev/sda，而 diskstats / 面板查 sda —— last_state 永远 unknown，
   于是「盘明明醒着」拦不住，面板电源态也一直是 unknown
2. SMART 用采样时刻另插一条唤醒，去重窗口 10s 盖不住 60s 的轮询间隔
3. fanotify 用 FAN_MARK_MOUNT，看不见容器里的 bind mount
4. 多成员盘共用一个挂载点时，事件只进第一块的环
"""

from __future__ import annotations

import os
import struct
import tempfile
import unittest
from unittest import mock

from dwm import db as dbm
from dwm.config import Config, ConfigError, validate
from dwm.correlator import Correlator, Sample
from dwm.devices import BlockDevice, MountResolver, read_mounts, stat_dev_map
from dwm.power import (
    STATE_ACTIVE,
    STATE_STANDBY,
    PowerSample,
    PowerStateTracker,
    SmartReader,
    normalize_dev,
)
from dwm.sources import FanotifySource, parse_fanotify_stream


class TestPowerStateKey(unittest.TestCase):
    """电源态必须用整盘名做键，否则 last_state 永远查不到值。"""

    def test_normalize(self):
        self.assertEqual(normalize_dev("/dev/sda"), "sda")
        self.assertEqual(normalize_dev("/dev/nvme0n1p2"), "nvme0n1")
        self.assertEqual(normalize_dev("sdb1"), "sdb")
        self.assertEqual(normalize_dev(""), "")

    def test_observe_then_last_state(self):
        tracker = PowerStateTracker()
        tracker.observe(PowerSample(ts=1.0, dev="/dev/sdb", state=STATE_STANDBY))
        # 面板和 diskstats 查的是 sdb
        self.assertEqual(tracker.last_state("sdb"), STATE_STANDBY)
        self.assertTrue(tracker.was_asleep("sdb"))

        woke, reason = tracker.observe(PowerSample(ts=2.0, dev="/dev/sdb", state=STATE_ACTIVE))
        self.assertTrue(woke)
        self.assertIn("standby", reason)
        self.assertEqual(tracker.last_state("sdb"), STATE_ACTIVE)

    def test_active_disk_is_not_a_wake(self):
        tracker = PowerStateTracker()
        tracker.observe(PowerSample(ts=1.0, dev="/dev/sdc", state=STATE_ACTIVE))
        woke, _ = tracker.observe(PowerSample(ts=2.0, dev="/dev/sdc", state=STATE_ACTIVE))
        self.assertFalse(woke)

    def test_start_stop_increment_uses_disk_key(self):
        tracker = PowerStateTracker()
        tracker.observe(PowerSample(ts=1.0, dev="/dev/sdb", state=STATE_ACTIVE, start_stop=10))
        woke, reason = tracker.observe(
            PowerSample(ts=2.0, dev="/dev/sdb", state=STATE_ACTIVE, start_stop=11)
        )
        self.assertTrue(woke)
        self.assertIn("启停计数", reason)


class TestStandbyTextFallback(unittest.TestCase):
    """有的 USB 桥接盒待机时仍返回 0，只在文本里写 STANDBY。"""

    def test_rc0_with_standby_text(self):
        reader = SmartReader()
        with mock.patch("dwm.power.smartctl_available", return_value=True), mock.patch(
            "dwm.power._run", return_value=(0, "Power mode is:   STANDBY", "")
        ):
            sample = reader.sample("/dev/sdb")
        self.assertEqual(sample.state, STATE_STANDBY)

    def test_rc0_plain_active(self):
        reader = SmartReader()
        with mock.patch("dwm.power.smartctl_available", return_value=True), mock.patch(
            "dwm.power._run", return_value=(0, "Power mode is:   ACTIVE or IDLE", "")
        ):
            sample = reader.sample("/dev/sdb")
        self.assertEqual(sample.state, STATE_ACTIVE)


class TestMultiMemberDisks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dwm-v130-")
        self.sys_block = os.path.join(self.tmp, "block")
        os.makedirs(self.sys_block)
        self.sys_fs_btrfs = os.path.join(self.tmp, "btrfs")
        self.mounts_file = os.path.join(self.tmp, "mounts")

    def test_btrfs_members_share_mountpoint(self):
        devices_dir = os.path.join(self.sys_fs_btrfs, "uuid-1", "devices")
        os.makedirs(os.path.join(devices_dir, "sda1"))
        os.makedirs(os.path.join(devices_dir, "sdb1"))
        with open(self.mounts_file, "w", encoding="utf-8") as fh:
            fh.write("/dev/sda1 /vol2 btrfs rw 0 0\n")

        mapping = read_mounts(
            mounts_file=self.mounts_file,
            sys_block=self.sys_block,
            sys_fs_btrfs=self.sys_fs_btrfs,
        )
        self.assertEqual(mapping["sda"], ["/vol2"])
        # 关键：另一块成员盘也要拿到挂载点
        self.assertEqual(mapping["sdb"], ["/vol2"])

    def test_single_device_btrfs_not_duplicated(self):
        devices_dir = os.path.join(self.sys_fs_btrfs, "uuid-2", "devices")
        os.makedirs(os.path.join(devices_dir, "sdc1"))
        with open(self.mounts_file, "w", encoding="utf-8") as fh:
            fh.write("/dev/sdc1 /vol3 btrfs rw 0 0\n")
        mapping = read_mounts(
            mounts_file=self.mounts_file,
            sys_block=self.sys_block,
            sys_fs_btrfs=self.sys_fs_btrfs,
        )
        self.assertEqual(mapping, {"sdc": ["/vol3"]})

    def test_resolver_returns_all_members(self):
        devices = {
            "sda": BlockDevice(name="sda", mounts=["/vol1"], monitored=True),
            "sdb": BlockDevice(name="sdb", mounts=["/vol1"], monitored=True),
            "sdc": BlockDevice(name="sdc", mounts=["/mnt/usb"], monitored=True),
        }
        resolver = MountResolver(devices)
        self.assertEqual(resolver.resolve_all("/vol1/docker/x"), ["sda", "sdb"])
        self.assertEqual(resolver.resolve_all("/mnt/usb/file"), ["sdc"])
        self.assertEqual(resolver.resolve_all("/var/log/syslog"), [])

    def test_stat_dev_map_keeps_all_members(self):
        mount = os.path.join(self.tmp, "shared")
        os.makedirs(mount)
        devices = {
            "sda": BlockDevice(name="sda", mounts=[mount], monitored=True),
            "sdb": BlockDevice(name="sdb", mounts=[mount], monitored=True),
        }
        mapping = stat_dev_map(devices)
        self.assertEqual(sorted(mapping[os.stat(mount).st_dev]), ["sda", "sdb"])


class TestFanotifyGrouping(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dwm-fan-")
        self.m1 = os.path.join(self.tmp, "vol1")
        self.m2 = os.path.join(self.tmp, "vol1home")
        os.makedirs(self.m1)
        os.makedirs(self.m2)

    def test_same_superblock_merges_into_one_group(self):
        source = FanotifySource(
            lambda record: None,
            targets=[(self.m1, ("sda", "sdb")), (self.m2, ("sda", "sdb"))],
        )
        plan = source._plan_groups()
        self.assertEqual(len(plan), 1)
        mount, devs, mounts = plan[0]
        self.assertEqual(sorted(devs), ["sda", "sdb"])
        self.assertEqual(sorted(mounts), sorted([self.m1, self.m2]))

    def test_missing_mount_is_skipped(self):
        source = FanotifySource(
            lambda record: None,
            targets=[(os.path.join(self.tmp, "gone"), ("sdz",))],
        )
        self.assertEqual(source._plan_groups(), [])


class _Buf:
    """按 fanotify_event_metadata 拼一个事件缓冲区。"""

    HEADER = struct.Struct("<IBBHQii")

    def __init__(self) -> None:
        self.parts = []

    def add(self, mask: int, pid: int, fd: int = -1) -> "_Buf":
        self.parts.append(self.HEADER.pack(24, 2, 0, 24, mask, pid, fd))
        return self

    def build(self) -> bytes:
        return b"".join(self.parts)


class TestFanotifyStream(unittest.TestCase):
    def test_hint_devs_propagate(self):
        data = _Buf().add(0x00000001, 1234, -1).build()
        records = parse_fanotify_stream(data, 1.0, hint_devs=("sda", "sdb"))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].hint_devs, ("sda", "sdb"))

    def test_overflow_is_counted_not_silently_dropped(self):
        data = _Buf().add(0x00004000, 0, -1).add(0x00000002, 77, -1).build()
        stats = {"overflow": 0, "unresolved_path": 0}
        records = parse_fanotify_stream(data, 1.0, stats=stats)
        self.assertEqual(stats["overflow"], 1)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].pid, 77)

    def test_unresolved_path_counted(self):
        data = _Buf().add(0x00000001, 5, 999999).build()
        stats = {"overflow": 0, "unresolved_path": 0}
        records = parse_fanotify_stream(data, 1.0, stats=stats)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].path, "")
        self.assertEqual(stats["unresolved_path"], 1)


class TestSuspectStorage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dwm-v130-db-")
        self.conn = dbm.connect(os.path.join(self.tmp, "m.db"))
        dbm.migrate(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_ambiguous_and_phase_roundtrip(self):
        correlator = Correlator(lookback_seconds=20.0, lookahead_seconds=3.0)
        correlator.add("sdb", Sample(ts=995.0, pid=9, comm="smbd", ambiguous=True))
        suspects = correlator.attribute(
            type("C", (), {"dev": "sdb", "ts": 1000.0, "idle_seconds": 900})()
        )
        wake_id = dbm.WakeRepo(self.conn).insert(
            ts=1000.0, dev="sdb", idle_seconds=900, confidence="state", note="n",
            suspect_count=len(suspects),
        )
        dbm.WakeRepo(self.conn).add_suspects(wake_id, suspects)
        row = dbm.WakeRepo(self.conn).suspects(wake_id)[0]
        self.assertEqual(row["ambiguous"], 1)
        self.assertEqual(row["phase"], "pre")

    def test_replace_suspects(self):
        repo = dbm.WakeRepo(self.conn)
        wake_id = repo.insert(
            ts=1000.0, dev="sdb", idle_seconds=900, confidence="state", note="n",
            suspect_count=1,
        )
        correlator = Correlator(lookback_seconds=20.0, lookahead_seconds=3.0)
        correlator.add("sdb", Sample(ts=980.0, pid=1, comm="first"))
        repo.add_suspects(
            wake_id,
            correlator.attribute(type("C", (), {"dev": "sdb", "ts": 1000.0, "idle_seconds": 0})()),
        )
        correlator.add("sdb", Sample(ts=990.0, pid=2, comm="second"))
        newer = correlator.attribute(type("C", (), {"dev": "sdb", "ts": 1000.0, "idle_seconds": 0})())
        repo.replace_suspects(wake_id, newer)
        repo.set_suspect_count(wake_id, len(newer))
        self.assertEqual([r["comm"] for r in repo.suspects(wake_id)], ["first", "second"])
        self.assertEqual(repo.get(wake_id)["suspect_count"], 2)


class TestWidenedWindow(unittest.TestCase):
    """SMART 只能确定「上个轮询周期内醒过」，此时允许临时放大窗口。"""

    def test_override_lookback(self):
        correlator = Correlator(lookback_seconds=20.0, lookahead_seconds=3.0)
        correlator.add("sdb", Sample(ts=960.0, pid=42, comm="synoindexd"))
        wake = type("C", (), {"dev": "sdb", "ts": 1000.0, "idle_seconds": 900})()
        self.assertEqual(correlator.attribute(wake), [])
        widened = correlator.attribute(wake, lookback=63.0)
        self.assertEqual([s.comm for s in widened], ["synoindexd"])


class TestConfigGuards(unittest.TestCase):
    def test_spinup_floor_must_be_smaller_than_lookback(self):
        cfg = Config()
        cfg.suspect_spinup_floor_seconds = 30.0
        with self.assertRaises(ConfigError):
            validate(cfg)

    def test_new_defaults(self):
        cfg = Config()
        self.assertGreaterEqual(cfg.suspect_lookback_seconds, 15.0)
        self.assertTrue(cfg.prefer_builtin_fanotify)


if __name__ == "__main__":
    unittest.main()
