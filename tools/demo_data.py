"""生成演示数据，用于在没有真实磁盘的环境下预览面板或做冒烟测试。

用法：
    python tools/demo_data.py --data-dir ./demo-data
    DWM_DATA_DIR=./demo-data python -m dwm serve
    # 浏览器打开 http://127.0.0.1:8765/

数据是虚构的，模拟一块 USB 外接盘被 SMB 访问、容器里的下载器、以及一个
「未捕获到归因」的场景，方便检查各种界面状态。
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dwm import db as dbm  # noqa: E402
from dwm.correlator import Suspect  # noqa: E402
from dwm.devices import BlockDevice  # noqa: E402

DEVICES = [
    BlockDevice(name="sda", model="Samsung SSD 980 500GB", transport="nvme",
                removable=False, rotational=False, size_bytes=500 * 1024**3,
                mounts=["/"], monitored=False, reason="非机械盘（无休眠概念）"),
    BlockDevice(name="sdb", model="Elements 25A3", transport="usb",
                removable=True, rotational=True, size_bytes=8 * 1024**4,
                mounts=["/vol1"], monitored=True, reason="外接/可移动机械盘"),
    BlockDevice(name="sdc", model="WDC WD40EFRX-68N32N0", transport="ata",
                removable=False, rotational=True, size_bytes=4 * 1024**4,
                mounts=["/vol2"], monitored=True, reason="外接/可移动机械盘"),
]

# (磁盘, 进程, 容器, 命令行, 采样路径, 权重)
ACTORS = [
    ("sdb", "smbd", "", "/usr/sbin/smbd --foreground --no-process-group",
     "/vol1/media/movie.mkv", 6),
    ("sdb", "qbittorrent-nox", "qbittorrent(1a2b3c4d)",
     "/usr/bin/qbittorrent-nox --webui-port=8080", "/vol1/downloads/torrent.tmp", 5),
    ("sdb", "minidlna", "", "/usr/sbin/minidlna -f /etc/minidlna.conf",
     "/vol1/media/cover.jpg", 2),
    ("sdb", "dockerd", "", "/usr/bin/dockerd -H fd://", "/vol1/docker/db.sqlite", 1),
    ("sdc", "rsync", "", "rsync -a /home/backup /vol2/backup",
     "/vol2/backup/daily.tar", 4),
    ("sdc", "smartctl", "", "smartctl -n standby -A /dev/sdc", "/vol2", 1),
    ("sdc", "systemd-journal", "", "/lib/systemd/systemd-journald",
     "/vol2/logs/journal.log", 2),
]

PID_MAP = {name: 1000 + index * 7 for index, name in enumerate({a[1] for a in ACTORS})}


def seed(data_dir: str, hours: float = 24.0, seed_value: int = 20261026) -> str:
    random.seed(seed_value)
    os.makedirs(data_dir, exist_ok=True)
    db_path = os.path.join(data_dir, "monitor.db")
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(db_path + suffix)
        except OSError:
            pass

    conn = dbm.connect(db_path)
    dbm.migrate(conn)
    dbm.DeviceRepo(conn).upsert(DEVICES)

    now = time.time()
    start = now - hours * 3600.0

    access_repo = dbm.AccessRepo(conn)
    wake_repo = dbm.WakeRepo(conn)
    power_repo = dbm.PowerRepo(conn)

    # ---- 背景访问事件（持续的零星 IO，用于「阻止休眠元凶」排行）----
    rows = []
    for dev, comm, container, cmdline, sample_path, weight in ACTORS:
        pid = PID_MAP[comm]
        count = weight * random.randint(40, 90)
        for _ in range(count):
            ts = random.uniform(start, now)
            rows.append((ts, dev, pid, comm, 0, random.choice(["O", "W", "CW"]),
                         sample_path, container, "fatrace"))
    rows.sort(key=lambda r: r[0])
    access_repo.insert_many(rows)

    # ---- 唤醒事件 ----
    scenarios = [
        # 磁盘, 距今小时, 空闲秒数, 置信度, 触发者(comm), 说明
        ("sdb", 0.6, 5400, "smart", "smbd", "SMART 确认：电源态 standby→active"),
        ("sdb", 3.1, 7200, "state", "qbittorrent-nox", "diskstats 显示空闲 7200s 后出现 IO"),
        ("sdb", 6.4, 10800, "smart", "smbd", "SMART 确认：启停计数 2713→2714"),
        ("sdb", 9.2, 3600, "inferred", None, "窗口内未捕获到归因事件"),
        ("sdc", 2.4, 14400, "smart", "rsync", "SMART 确认：电源态 standby→active"),
        ("sdc", 8.8, 9000, "state", "systemd-journal", "diskstats 显示空闲 9000s 后出现 IO"),
        ("sdc", 13.5, 21600, "inferred", None, "窗口内未捕获到归因事件"),
    ]

    for dev, hours_ago, idle, confidence, trigger, note in scenarios:
        ts = now - hours_ago * 3600.0
        suspects = []
        if trigger:
            info = next(a for a in ACTORS if a[1] == trigger)
            pid = PID_MAP[trigger]
            hits = random.randint(1, 4)
            suspects.append(
                Suspect(pid=pid, comm=trigger, hits=hits, first_ts=ts - 2.4,
                        last_ts=ts - 0.6, sample_path=info[4], uid=0,
                        container=info[2], cmdline=info[3])
            )
            if random.random() < 0.5:
                other = random.choice([a for a in ACTORS if a[0] == dev and a[1] != trigger])
                suspects.append(
                    Suspect(pid=PID_MAP[other[1]], comm=other[1], hits=1,
                            first_ts=ts - 4.0, last_ts=ts - 3.6, sample_path=other[4],
                            uid=0, container=other[2], cmdline=other[3])
                )

        wake_id = wake_repo.insert(ts=ts, dev=dev, idle_seconds=idle,
                                   confidence=confidence, note=note,
                                   suspect_count=len(suspects))
        wake_repo.add_suspects(wake_id, suspects)

        # 唤醒前后的密集访问，让时间线看起来合理
        burst = []
        for offset in (-3.0, -2.2, -1.4, -0.8, -0.2, 0.4, 1.2, 2.4):
            comm, container, sample_path = (
                (trigger, next(a[2] for a in ACTORS if a[1] == trigger),
                 next(a[4] for a in ACTORS if a[1] == trigger))
                if trigger else ("kworker/u8:2", "", "")
            )
            burst.append((ts + offset, dev, PID_MAP.get(comm, 0), comm, 0, "W",
                          sample_path, container, "fatrace"))
        access_repo.insert_many(burst)

    # ---- 电源采样 ----
    for dev in ("sdb", "sdc"):
        for index in range(48):
            ts = now - index * 1800.0
            state = "standby" if index % 3 else "active"
            power_repo.insert(ts, dev, state, 2700 + index // 24, "")

    conn.close()
    return db_path


def main() -> int:
    parser = argparse.ArgumentParser(description="生成面板演示数据")
    parser.add_argument("--data-dir", default="./demo-data", help="数据目录")
    parser.add_argument("--hours", type=float, default=24.0)
    args = parser.parse_args()
    path = seed(args.data_dir, args.hours)
    print(f"演示数据已生成：{path}")
    print("预览：DWM_DATA_DIR={} python -m dwm serve".format(args.data_dir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
