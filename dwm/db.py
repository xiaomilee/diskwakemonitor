"""SQLite 存储层：可回滚迁移 + 按职责拆分的仓储类。

设计要点：
- 所有写入走批量 executemany，避免每条事件一次事务
- 只对「被监控设备」写 access_event，控制表增长
- 迁移带版本号，可重复执行（幂等）
"""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .errors import DbError

SCHEMA_VERSION = 2

# 嫌疑进程的读取顺序必须和归因排序一致，否则面板第一条就不是「真正的触发者」：
# pre 组（唤醒前动手的）优先 → 首笔时间最早的优先 → 命中多的优先 → 多盘歧义的靠后
_SUSPECT_ORDER = (
    "CASE phase WHEN 'pre' THEN 0 WHEN 'block' THEN 1 ELSE 2 END, "
    "first_ts ASC, hits DESC, ambiguous ASC"
)

MIGRATIONS: List[Tuple[int, List[str]]] = [
    (
        1,
        [
            """
            CREATE TABLE IF NOT EXISTS device (
                name        TEXT PRIMARY KEY,
                model       TEXT NOT NULL DEFAULT '',
                transport   TEXT NOT NULL DEFAULT 'unknown',
                removable   INTEGER NOT NULL DEFAULT 0,
                rotational  INTEGER NOT NULL DEFAULT 0,
                size_bytes  INTEGER NOT NULL DEFAULT 0,
                mounts      TEXT NOT NULL DEFAULT '',
                monitored   INTEGER NOT NULL DEFAULT 0,
                reason      TEXT NOT NULL DEFAULT '',
                updated_ts  REAL NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS access_event (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        REAL NOT NULL,
                dev       TEXT NOT NULL,
                pid       INTEGER NOT NULL DEFAULT 0,
                comm      TEXT NOT NULL DEFAULT '',
                uid       INTEGER,
                op        TEXT NOT NULL DEFAULT '',
                path      TEXT NOT NULL DEFAULT '',
                container TEXT NOT NULL DEFAULT '',
                source    TEXT NOT NULL DEFAULT ''
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_access_ts ON access_event(ts)",
            "CREATE INDEX IF NOT EXISTS idx_access_dev_ts ON access_event(dev, ts)",
            """
            CREATE TABLE IF NOT EXISTS wake_event (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ts            REAL NOT NULL,
                dev           TEXT NOT NULL,
                idle_seconds  REAL NOT NULL DEFAULT 0,
                confidence    TEXT NOT NULL DEFAULT 'inferred',
                note          TEXT NOT NULL DEFAULT '',
                suspect_count INTEGER NOT NULL DEFAULT 0
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_wake_ts ON wake_event(ts)",
            "CREATE INDEX IF NOT EXISTS idx_wake_dev_ts ON wake_event(dev, ts)",
            """
            CREATE TABLE IF NOT EXISTS wake_suspect (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                wake_id     INTEGER NOT NULL REFERENCES wake_event(id) ON DELETE CASCADE,
                pid         INTEGER NOT NULL DEFAULT 0,
                comm        TEXT NOT NULL DEFAULT '',
                cmdline     TEXT NOT NULL DEFAULT '',
                container   TEXT NOT NULL DEFAULT '',
                uid         INTEGER,
                hits        INTEGER NOT NULL DEFAULT 0,
                first_ts    REAL NOT NULL DEFAULT 0,
                last_ts     REAL NOT NULL DEFAULT 0,
                sample_path TEXT NOT NULL DEFAULT ''
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_suspect_wake ON wake_suspect(wake_id)",
            """
            CREATE TABLE IF NOT EXISTS power_sample (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         REAL NOT NULL,
                dev        TEXT NOT NULL,
                state      TEXT NOT NULL,
                start_stop INTEGER,
                raw        TEXT NOT NULL DEFAULT ''
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_power_dev_ts ON power_sample(dev, ts)",
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        ],
    ),
    (
        # v2：归因结果需要区分「多盘歧义」与「块层证据」，旧库就地加列
        2,
        [
            "ALTER TABLE wake_suspect ADD COLUMN ambiguous INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE wake_suspect ADD COLUMN phase TEXT NOT NULL DEFAULT 'pre'",
        ],
    ),
]


def connect(path: str, *, readonly: bool = False) -> sqlite3.Connection:
    try:
        if readonly:
            if not os.path.isfile(path):
                raise DbError(
                    f"数据库不存在：{path}",
                    hint="先启动采集进程（dwmctl serve / systemctl start disk-wake-monitor）",
                )
            uri = "file:{}?mode=ro".format(path.replace("?", "%3f"))
            conn = sqlite3.connect(uri, uri=True, timeout=10.0)
        else:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(path, timeout=15.0)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
    except sqlite3.Error as exc:
        raise DbError(f"打开数据库失败 {path}：{exc}") from exc

    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        current = int(row["value"]) if row else 0
        for version, statements in MIGRATIONS:
            if version <= current:
                continue
            with conn:
                for stmt in statements:
                    conn.execute(stmt)
                conn.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
                    (str(version),),
                )
            current = version
    except sqlite3.Error as exc:
        raise DbError(f"数据库迁移失败：{exc}", hint="可删除库文件重建（历史记录会丢失）") from exc


# ---------------------------------------------------------------------------
# 仓储层
# ---------------------------------------------------------------------------


class DeviceRepo:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def upsert(self, devices: Iterable[Any]) -> None:
        """device 对象需具备 name/model/transport/removable/rotational/size_bytes/mounts/monitored/reason。"""
        now = time.time()
        rows = [
            (
                d.name,
                d.model,
                d.transport,
                1 if d.removable else 0,
                1 if d.rotational else 0,
                d.size_bytes,
                ",".join(d.mounts),
                1 if d.monitored else 0,
                d.reason,
                now,
            )
            for d in devices
        ]
        if not rows:
            return
        with self.conn:
            self.conn.executemany(
                """
                INSERT INTO device(name, model, transport, removable, rotational,
                                   size_bytes, mounts, monitored, reason, updated_ts)
                VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(name) DO UPDATE SET
                    model=excluded.model, transport=excluded.transport,
                    removable=excluded.removable, rotational=excluded.rotational,
                    size_bytes=excluded.size_bytes, mounts=excluded.mounts,
                    monitored=excluded.monitored, reason=excluded.reason,
                    updated_ts=excluded.updated_ts
                """,
                rows,
            )

    def all(self) -> List[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT * FROM device ORDER BY monitored DESC, name ASC"
            )
        )

    def monitored_names(self) -> List[str]:
        return [
            r["name"]
            for r in self.conn.execute("SELECT name FROM device WHERE monitored=1")
        ]


class AccessRepo:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def insert_many(
        self,
        rows: Sequence[Tuple[float, str, int, str, Optional[int], str, str, str, str]],
    ) -> None:
        if not rows:
            return
        try:
            with self.conn:
                self.conn.executemany(
                    """
                    INSERT INTO access_event(ts, dev, pid, comm, uid, op, path, container, source)
                    VALUES(?,?,?,?,?,?,?,?,?)
                    """,
                    rows,
                )
        except sqlite3.Error as exc:
            raise DbError(f"写入访问事件失败：{exc}") from exc

    def recent(
        self,
        *,
        minutes: float = 30.0,
        dev: Optional[str] = None,
        comm: Optional[str] = None,
        limit: int = 300,
    ) -> List[sqlite3.Row]:
        since = time.time() - minutes * 60.0
        sql = "SELECT * FROM access_event WHERE ts >= ?"
        params: List[Any] = [since]
        if dev:
            sql += " AND dev = ?"
            params.append(dev)
        if comm:
            sql += " AND comm LIKE ?"
            params.append(f"%{comm}%")
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(max(1, min(limit, 5000)))
        return list(self.conn.execute(sql, params))

    def offenders(self, *, hours: float = 24.0, limit: int = 40) -> List[sqlite3.Row]:
        """按 (设备, 进程, 容器) 聚合 IO 次数 —— 用于找「阻止休眠的元凶」。"""
        since = time.time() - hours * 3600.0
        return list(
            self.conn.execute(
                """
                SELECT dev, comm, container, COUNT(*) AS hits,
                       MAX(ts) AS last_ts, MIN(ts) AS first_ts,
                       COUNT(DISTINCT pid) AS pids
                FROM access_event
                WHERE ts >= ?
                GROUP BY dev, comm, container
                ORDER BY hits DESC
                LIMIT ?
                """,
                (since, max(1, min(limit, 500))),
            )
        )

    def bucket_counts(
        self, *, hours: float = 24.0, bucket_seconds: int = 300
    ) -> List[sqlite3.Row]:
        since = time.time() - hours * 3600.0
        return list(
            self.conn.execute(
                """
                SELECT dev,
                       CAST(ts / ? AS INTEGER) * ? AS bucket_ts,
                       COUNT(*) AS hits
                FROM access_event
                WHERE ts >= ?
                GROUP BY dev, bucket_ts
                ORDER BY bucket_ts ASC
                """,
                (bucket_seconds, bucket_seconds, since),
            )
        )

    def delete_older_than(self, cutoff_ts: float) -> int:
        with self.conn:
            cur = self.conn.execute("DELETE FROM access_event WHERE ts < ?", (cutoff_ts,))
        return cur.rowcount or 0

    def clear(self, dev: str) -> int:
        """删除某块盘的全部访问事件。"""
        with self.conn:
            cur = self.conn.execute("DELETE FROM access_event WHERE dev = ?", (dev,))
        return cur.rowcount or 0


class WakeRepo:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def insert(
        self,
        *,
        ts: float,
        dev: str,
        idle_seconds: float,
        confidence: str,
        note: str,
        suspect_count: int,
    ) -> int:
        with self.conn:
            cur = self.conn.execute(
                """
                INSERT INTO wake_event(ts, dev, idle_seconds, confidence, note, suspect_count)
                VALUES(?,?,?,?,?,?)
                """,
                (ts, dev, idle_seconds, confidence, note, suspect_count),
            )
        return int(cur.lastrowid)

    def add_suspects(self, wake_id: int, suspects: Iterable[Any]) -> None:
        rows = [
            (
                wake_id,
                s.pid,
                s.comm,
                s.cmdline,
                s.container,
                s.uid,
                s.hits,
                s.first_ts,
                s.last_ts,
                s.sample_path,
                1 if getattr(s, "ambiguous", False) else 0,
                getattr(s, "phase", "pre") or "pre",
            )
            for s in suspects
        ]
        if not rows:
            return
        with self.conn:
            self.conn.executemany(
                """
                INSERT INTO wake_suspect(wake_id, pid, comm, cmdline, container, uid,
                                         hits, first_ts, last_ts, sample_path,
                                         ambiguous, phase)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                rows,
            )

    def replace_suspects(self, wake_id: int, suspects: Iterable[Any]) -> None:
        """整体替换某次唤醒的嫌疑列表（SMART 后到、重跑归因时用）。"""
        with self.conn:
            self.conn.execute("DELETE FROM wake_suspect WHERE wake_id=?", (wake_id,))
        self.add_suspects(wake_id, suspects)

    def set_suspect_count(self, wake_id: int, count: int) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE wake_event SET suspect_count=? WHERE id=?", (count, wake_id)
            )

    def upgrade_confidence(self, wake_id: int, confidence: str, note: str) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE wake_event SET confidence=?, note=? WHERE id=?",
                (confidence, note, wake_id),
            )

    def recent(
        self, *, hours: float = 24.0, dev: Optional[str] = None, limit: int = 200
    ) -> List[sqlite3.Row]:
        since = time.time() - hours * 3600.0
        sql = "SELECT * FROM wake_event WHERE ts >= ?"
        params: List[Any] = [since]
        if dev:
            sql += " AND dev = ?"
            params.append(dev)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(max(1, min(limit, 2000)))
        return list(self.conn.execute(sql, params))

    def get(self, wake_id: int) -> Optional[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM wake_event WHERE id=?", (wake_id,)).fetchone()

    def suspects(self, wake_id: int) -> List[sqlite3.Row]:
        return list(
            self.conn.execute(
                f"SELECT * FROM wake_suspect WHERE wake_id=? ORDER BY {_SUSPECT_ORDER}",
                (wake_id,),
            )
        )

    def suspects_map(self, wake_ids: Sequence[int]) -> Dict[int, List[sqlite3.Row]]:
        if not wake_ids:
            return {}
        placeholders = ",".join("?" for _ in wake_ids)
        result: Dict[int, List[sqlite3.Row]] = {wid: [] for wid in wake_ids}
        for row in self.conn.execute(
            f"SELECT * FROM wake_suspect WHERE wake_id IN ({placeholders}) "
            f"ORDER BY {_SUSPECT_ORDER}",
            list(wake_ids),
        ):
            result[row["wake_id"]].append(row)
        return result

    def count_since(self, since_ts: float) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM wake_event WHERE ts >= ?", (since_ts,)
        ).fetchone()
        return int(row["n"]) if row else 0

    def count_by_device(self, since_ts: float) -> Dict[str, int]:
        return {
            r["dev"]: int(r["n"])
            for r in self.conn.execute(
                "SELECT dev, COUNT(*) AS n FROM wake_event WHERE ts >= ? GROUP BY dev",
                (since_ts,),
            )
        }

    def last_by_device(self) -> Dict[str, sqlite3.Row]:
        rows = self.conn.execute(
            """
            SELECT w.* FROM wake_event w
            JOIN (SELECT dev, MAX(ts) AS mts FROM wake_event GROUP BY dev) t
              ON w.dev = t.dev AND w.ts = t.mts
            """
        )
        return {r["dev"]: r for r in rows}

    def delete_older_than(self, cutoff_ts: float) -> int:
        with self.conn:
            cur = self.conn.execute("DELETE FROM wake_event WHERE ts < ?", (cutoff_ts,))
        return cur.rowcount or 0

    def clear(self, dev: str) -> int:
        """删除某块盘的全部唤醒事件（嫌疑明细经外键级联删除）。"""
        with self.conn:
            cur = self.conn.execute("DELETE FROM wake_event WHERE dev = ?", (dev,))
        return cur.rowcount or 0


class PowerRepo:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def insert(self, ts: float, dev: str, state: str, start_stop: Optional[int], raw: str) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO power_sample(ts, dev, state, start_stop, raw) VALUES(?,?,?,?,?)",
                (ts, dev, state, start_stop, raw[:500]),
            )

    def latest_by_device(self) -> Dict[str, sqlite3.Row]:
        rows = self.conn.execute(
            """
            SELECT p.* FROM power_sample p
            JOIN (SELECT dev, MAX(ts) AS mts FROM power_sample GROUP BY dev) t
              ON p.dev = t.dev AND p.ts = t.mts
            """
        )
        return {r["dev"]: r for r in rows}

    def delete_older_than(self, cutoff_ts: float) -> int:
        with self.conn:
            cur = self.conn.execute("DELETE FROM power_sample WHERE ts < ?", (cutoff_ts,))
        return cur.rowcount or 0

    def clear(self, dev: str) -> int:
        with self.conn:
            cur = self.conn.execute("DELETE FROM power_sample WHERE dev = ?", (dev,))
        return cur.rowcount or 0


def run_retention(conn: sqlite3.Connection, retention_hours: float) -> Dict[str, int]:
    cutoff = time.time() - retention_hours * 3600.0
    stats = {
        "access": AccessRepo(conn).delete_older_than(cutoff),
        "wakes": WakeRepo(conn).delete_older_than(cutoff),
        "power": PowerRepo(conn).delete_older_than(cutoff),
    }
    return stats
