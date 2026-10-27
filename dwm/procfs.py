"""进程信息补全：命令行、父进程链、容器归属。

为什么需要：fatrace / block_dump 只给出 comm（comm 会被内核截断到 15 字符），
而真实场景里「谁唤醒了盘」经常是 Docker 容器里的某个服务。
只显示 `java` 或 `containerd-shim` 对排查毫无帮助。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

PROC = "/proc"
CACHE_LIMIT = 4096


@dataclass
class ProcInfo:
    pid: int
    comm: str = ""
    cmdline: str = ""
    uid: Optional[int] = None
    parents: List[Tuple[int, str]] = field(default_factory=list)
    container: str = ""
    container_id: str = ""

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "comm": self.comm,
            "cmdline": self.cmdline,
            "uid": self.uid,
            "parents": [{"pid": p, "comm": c} for p, c in self.parents],
            "container": self.container,
            "container_id": self.container_id,
        }


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def read_comm(pid: int) -> str:
    return _read(f"{PROC}/{pid}/comm").strip()


def read_cmdline(pid: int, limit: int = 300) -> str:
    raw = _read(f"{PROC}/{pid}/cmdline")
    if not raw:
        return ""
    text = raw.replace("\x00", " ").strip()
    return text[:limit]


def read_ppid(pid: int) -> Optional[int]:
    """解析 /proc/<pid>/stat。comm 可能含空格和括号，必须以最后一个 ')' 为界。"""
    raw = _read(f"{PROC}/{pid}/stat")
    if not raw:
        return None
    close = raw.rfind(")")
    if close == -1:
        return None
    rest = raw[close + 1 :].split()
    if len(rest) < 2:
        return None
    try:
        return int(rest[1])
    except ValueError:
        return None


def read_uid(pid: int) -> Optional[int]:
    raw = _read(f"{PROC}/{pid}/status")
    for line in raw.splitlines():
        if line.startswith("Uid:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    return None
    return None


def read_cgroup(pid: int) -> str:
    return _read(f"{PROC}/{pid}/cgroup")


_CONTAINER_PATTERNS = (
    ("docker-", ".scope"),
    ("cri-containerd-", ".scope"),
    ("libpod-", ".scope"),
)


def parse_container(cgroup_text: str) -> Tuple[str, str]:
    """返回 (容器展示名, 容器 ID 短码)。非容器环境返回 ("","")。"""
    if not cgroup_text:
        return "", ""
    for line in cgroup_text.splitlines():
        for prefix, suffix in _CONTAINER_PATTERNS:
            idx = line.find(prefix)
            if idx == -1:
                continue
            tail = line[idx + len(prefix) :]
            if suffix:
                end = tail.find(suffix)
                if end != -1:
                    tail = tail[:end]
                else:
                    cut = tail.find("/")
                    if cut != -1:
                        tail = tail[:cut]
            key = tail.strip()
            if len(key) >= 8:
                return f"container:{key[:12]}", key[:12]
    # k8s 风格：/kubepods/.../<64位id>
    if "kubepods" in cgroup_text:
        for line in cgroup_text.splitlines():
            tokens = [t for t in line.strip().split("/") if len(t) >= 32]
            if tokens:
                key = tokens[-1]
                return f"k8s:{key[:12]}", key[:12]
    return "", ""


class DockerNameResolver:
    """懒加载 docker 容器 ID → 名称映射，60 秒缓存，失败静默降级。"""

    def __init__(self, ttl: float = 60.0) -> None:
        self.ttl = ttl
        self._map: Dict[str, str] = {}
        self._loaded_at = 0.0
        self._enabled = shutil.which("docker") is not None
        self._lock = threading.Lock()

    def _refresh(self) -> None:
        with self._lock:
            if time.time() - self._loaded_at < self.ttl:
                return
            self._loaded_at = time.time()
            if not self._enabled:
                return
            try:
                proc = subprocess.run(
                    ["docker", "ps", "--format", "{{.ID}}\t{{.Names}}"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            except (OSError, subprocess.SubprocessError):
                self._enabled = False
                return
            if proc.returncode != 0:
                return
            mapping: Dict[str, str] = {}
            for line in proc.stdout.splitlines():
                if "\t" not in line:
                    continue
                cid, name = line.split("\t", 1)
                mapping[cid.strip()[:12]] = name.strip()
            self._map = mapping

    def name_for(self, short_id: str) -> str:
        if not short_id:
            return ""
        self._refresh()
        return self._map.get(short_id, "")


class ProcCache:
    """缓存 /proc 读取结果，避免高频事件把 /proc 打爆。"""

    def __init__(self, ttl: float = 30.0, with_docker: bool = True) -> None:
        self.ttl = ttl
        self._cache: Dict[int, Tuple[float, ProcInfo]] = {}
        self._docker = DockerNameResolver() if with_docker else None

    def get(self, pid: int, *, comm_hint: str = "") -> ProcInfo:
        if pid <= 0:
            return ProcInfo(pid=pid, comm=comm_hint)

        now = time.time()
        hit = self._cache.get(pid)
        if hit and now - hit[0] < self.ttl:
            info = hit[1]
            if not info.comm and comm_hint:
                info.comm = comm_hint
            return info

        info = ProcInfo(pid=pid)
        info.comm = read_comm(pid) or comm_hint
        info.cmdline = read_cmdline(pid)
        info.uid = read_uid(pid)
        label, cid = parse_container(read_cgroup(pid))
        info.container_id = cid
        if cid and self._docker:
            name = self._docker.name_for(cid)
            info.container = f"{name}({cid[:8]})" if name else label
        else:
            info.container = label

        # 父进程链，最多 4 层
        cursor = read_ppid(pid)
        depth = 0
        while cursor and cursor > 1 and depth < 4:
            info.parents.append((cursor, read_comm(cursor)))
            cursor = read_ppid(cursor)
            depth += 1

        if len(self._cache) > CACHE_LIMIT:
            self._cache.clear()
        self._cache[pid] = (now, info)
        return info

    def describe(self, pid: int, comm_hint: str = "") -> str:
        info = self.get(pid, comm_hint=comm_hint)
        parts = [info.comm or comm_hint or f"pid{pid}"]
        if info.container:
            parts.append(f"@{info.container}")
        if info.parents:
            chain = " ← ".join(f"{comm}({p})" for p, comm in info.parents[:3])
            parts.append(f"[{chain}]")
        return " ".join(parts)


def iter_open_fds_on(dev_paths: List[str], limit: int = 0) -> List[Tuple[int, str]]:
    """扫描 /proc/*/fd 找持有指定设备节点的进程（可选兜底手段）。

    代价较高，仅在需要交叉验证时使用。
    """
    hits: List[Tuple[int, str]] = []
    if not os.path.isdir(PROC):
        return hits
    targets = set(dev_paths)
    for entry in os.listdir(PROC):
        if not entry.isdigit():
            continue
        pid = int(entry)
        fd_dir = f"{PROC}/{entry}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                link = os.readlink(f"{fd_dir}/{fd}")
            except OSError:
                continue
            if link in targets:
                hits.append((pid, link))
                break
        if limit and len(hits) >= limit:
            break
    return hits
