"""归因链路与按盘清除的回归测试。

守住三个曾经/最容易在生产出问题的点：
1. fnOS 经 md/DM 阵列挂载（/dev/md0 → /vol1）时，成员盘必须拿到挂载点，
   否则 fanotify 事件全部归属失败（v1.1.x「全部未捕获到访问事件」的根因）
2. st_dev 兜底归属
3. 按盘清除：DB 级联 + 内存环清理 + API 参数校验
"""

from __future__ import annotations

import os
import tempfile
import unittest

from dwm import db as dbm
from dwm.correlator import Correlator, Sample, Suspect, WakeCandidate
from dwm.devices import BlockDevice, read_mounts, stat_dev_map
from dwm.server import ApiApp, ApiError
from dwm.config import Config


class TestMountsThroughArray(unittest.TestCase):
    """md/DM 阵列挂载必须穿透到成员盘（fnOS /vol1 场景）。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dwm-mounts-")
        self.sys_block = os.path.join(self.tmp, "block")
        # 模拟 /sys/block/md0/slaves/{sda1,sdb1}
        slaves = os.path.join(self.sys_block, "md0", "slaves")
        os.makedirs(os.path.join(slaves, "sda1"))
        os.makedirs(os.path.join(slaves, "sdb1"))
        self.mounts_file = os.path.join(self.tmp, "mounts")
        with open(self.mounts_file, "w", encoding="utf-8") as fh:
            fh.write("/dev/md0 /vol1 btrfs rw 0 0\n")
            fh.write("/dev/sdc1 /mnt/usb ext4 rw 0 0\n")

    def test_array_mount_reaches_member_disks(self):
        mapping = read_mounts(mounts_file=self.mounts_file, sys_block=self.sys_block)
        self.assertEqual(mapping["sda"], ["/vol1"])
        self.assertEqual(mapping["sdb"], ["/vol1"])
        self.assertEqual(mapping["sdc"], ["/mnt/usb"])

    def test_array_itself_keeps_mount(self):
        mapping = read_mounts(mounts_file=self.mounts_file, sys_block=self.sys_block)
        self.assertEqual(mapping["md0"], ["/vol1"])

    def test_no_slaves_dir_is_plain_disk(self):
        with open(self.mounts_file, "w", encoding="utf-8") as fh:
            fh.write("/dev/sdz1 /data ext4 rw 0 0\n")
        mapping = read_mounts(mounts_file=self.mounts_file, sys_block=self.sys_block)
        self.assertEqual(mapping.get("sdz"), ["/data"])


class TestStatDevMap(unittest.TestCase):
    def test_mount_stat_maps_to_disk(self):
        tmp = tempfile.mkdtemp(prefix="dwm-statdev-")
        devices = {
            "sda": BlockDevice(name="sda", mounts=[tmp], monitored=True),
            "sdb": BlockDevice(name="sdb", mounts=[], monitored=True),
            "sdc": BlockDevice(name="sdc", mounts=[tmp], monitored=False),
        }
        mapping = stat_dev_map(devices)
        st_dev = os.stat(tmp).st_dev
        self.assertEqual(mapping.get(st_dev), "sda")

    def test_unreachable_mount_skipped(self):
        devices = {
            "sda": BlockDevice(name="sda", mounts=["/definitely/not/exist"], monitored=True),
        }
        self.assertEqual(stat_dev_map(devices), {})


class TestClearByDevice(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dwm-clear-")
        self.path = os.path.join(self.tmp, "monitor.db")
        self.conn = dbm.connect(self.path)
        dbm.migrate(self.conn)

    def tearDown(self):
        self.conn.close()

    def _seed(self, dev="sdb"):
        wake_id = dbm.WakeRepo(self.conn).insert(
            ts=1000.0, dev=dev, idle_seconds=900, confidence="state",
            note="n", suspect_count=1,
        )
        dbm.WakeRepo(self.conn).add_suspects(
            wake_id, [Suspect(pid=1, comm="smbd", hits=2, first_ts=1, last_ts=2)]
        )
        dbm.AccessRepo(self.conn).insert_many(
            [(1001.0, dev, 1, "smbd", None, "O", "/x", "", "fanotify")]
        )
        dbm.PowerRepo(self.conn).insert(1002.0, dev, "standby", None, "")
        return wake_id

    def test_wake_clear_cascades_suspects(self):
        other = self._seed("sdc")
        target = self._seed("sdb")
        removed = dbm.WakeRepo(self.conn).clear("sdb")
        self.assertEqual(removed, 1)
        self.assertIsNone(dbm.WakeRepo(self.conn).get(target))
        # 别的盘不受影响；被删盘的嫌疑明细级联清空
        self.assertIsNotNone(dbm.WakeRepo(self.conn).get(other))
        self.assertEqual(dbm.WakeRepo(self.conn).suspects_map([target]), {target: []})

    def test_access_and_power_clear(self):
        self._seed("sdb")
        self._seed("sdb")
        self.assertEqual(dbm.AccessRepo(self.conn).clear("sdb"), 2)
        self.assertEqual(dbm.PowerRepo(self.conn).clear("sdb"), 2)
        self.assertEqual(dbm.AccessRepo(self.conn).clear("sdb"), 0)

    def test_correlator_clear_dev(self):
        correlator = Correlator()
        correlator.add("sdb", Sample(ts=1.0, pid=1, comm="x"))
        correlator.add("sdc", Sample(ts=1.0, pid=1, comm="x"))
        self.assertEqual(correlator.clear_dev("sdb"), 1)
        self.assertEqual(correlator.window_size("sdb"), 0)
        self.assertEqual(correlator.window_size("sdc"), 1)
        self.assertEqual(correlator.clear_dev("sdb"), 0)


class TestApiClear(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dwm-apiclear-")
        self.cfg = Config(data_dir=self.tmp)
        self.conn = dbm.connect(self.cfg.resolved_db_path)
        dbm.migrate(self.conn)
        self.conn.close()
        self.removed_devs = []
        self.app = ApiApp(self.cfg, clear_hook=self._hook)

    def _hook(self, dev):
        self.removed_devs.append(dev)
        return {"samples": 3}

    def _seed(self, dev):
        import time as _time

        conn = dbm.connect(self.cfg.resolved_db_path)
        try:
            dbm.WakeRepo(conn).insert(
                ts=_time.time(), dev=dev, idle_seconds=1, confidence="state",
                note="", suspect_count=0,
            )
        finally:
            conn.close()

    def test_clear_requires_dev(self):
        with self.assertRaises(ApiError) as ctx:
            self.app.api_clear({})
        self.assertEqual(ctx.exception.status, 400)

    def test_clear_missing_db_is_503(self):
        os.remove(self.cfg.resolved_db_path)
        with self.assertRaises(ApiError) as ctx:
            self.app.api_clear({"dev": "sda"})
        self.assertEqual(ctx.exception.status, 503)

    def test_clear_dev_and_hook(self):
        self._seed("sdb")
        self._seed("sda")
        result = self.app.api_clear({"dev": "sdb", "access": "1"})
        self.assertEqual(result["wakes"], 1)
        self.assertEqual(result["access"], 0)  # 没有访问记录时也返回 0
        self.assertEqual(self.removed_devs, ["sdb"])
        # sda 未受影响
        self.assertEqual(len(self.app.api_wakes({"hours": "24"})["items"]), 1)

    def test_clear_wakes_only_by_default(self):
        conn = dbm.connect(self.cfg.resolved_db_path)
        try:
            dbm.AccessRepo(conn).insert_many(
                [(1.0, "sdb", 1, "smbd", None, "O", "/x", "", "fanotify")]
            )
        finally:
            conn.close()
        self._seed("sdb")
        result = self.app.api_clear({"dev": "sdb"})
        self.assertNotIn("access", result)
        self.assertEqual(result["wakes"], 1)


if __name__ == "__main__":
    unittest.main()
