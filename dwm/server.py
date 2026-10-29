"""Web 面板与 JSON API（纯标准库 http.server，无第三方依赖、无外部 CDN）。

安全取舍：
- 默认只监听 127.0.0.1；要局域网访问必须显式 DWM_HOST=0.0.0.0
- 可选 DWM_AUTH_TOKEN，非空时所有 /api 请求需带 X-DWM-Token 或 ?token=
- 严格 CSP，只允许同源资源；不做 CORS 通配
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import queue
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import db as dbm
from .bus import EventBus
from .config import Config
from .power import STATE_UNKNOWN

LOG = logging.getLogger("dwm.http")

WEB_ROOT = Path(__file__).resolve().parent.parent / "web"

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
}

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; "
        "style-src 'self'; script-src 'self'; connect-src 'self'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'self'"
    ),
}


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


class ApiApp:
    """把配置、事件总线与数据访问打包，供 Handler 调用。"""

    def __init__(
        self,
        cfg: Config,
        *,
        bus: Optional[EventBus] = None,
        snapshot: Optional[Callable[[], dict]] = None,
        clear_hook: Optional[Callable[[str], Any]] = None,
    ) -> None:
        self.cfg = cfg
        self.bus = bus
        self.snapshot = snapshot
        self.clear_hook = clear_hook
        self.stopping = threading.Event()

    # ---- 数据访问 ----
    def db_ready(self) -> bool:
        return os.path.isfile(self.cfg.resolved_db_path)

    def with_repos(self, fn):
        if not self.db_ready():
            raise ApiError(
                503,
                "DWM_DB_MISSING",
                "数据库尚未创建，采集进程还没跑起来",
            )
        conn = dbm.connect(self.cfg.resolved_db_path)
        try:
            return fn(conn)
        finally:
            conn.close()

    # ---- 各端点 ----
    def api_health(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "ok": True,
            "version": __import__("dwm").__version__,
            "ts": time.time(),
            "db_ready": self.db_ready(),
            "live": self.bus is not None,
        }
        if self.snapshot:
            payload["collector"] = self.snapshot()
        return payload

    def api_devices(self, params: Dict[str, str]) -> List[Dict[str, Any]]:
        hours = _num(params, "hours", 24.0, 0.1, 24 * 365)
        since = time.time() - hours * 3600.0

        def run(conn):
            devices = dbm.DeviceRepo(conn).all()
            wake_repo = dbm.WakeRepo(conn)
            last = wake_repo.last_by_device()
            counts = wake_repo.count_by_device(since)
            power = dbm.PowerRepo(conn).latest_by_device()
            live = (self.snapshot() if self.snapshot else {}) or {}
            live_idle = live.get("idle", {})
            live_state = live.get("power_state", {})

            result = []
            for row in devices:
                name = row["name"]
                wake_row = last.get(name)
                power_row = power.get(name)
                # "unknown" 是非空字符串，不能用 or 兜底 —— 否则内存里没采到时
                # 永远盖住数据库里那条真正的 SMART 记录
                state = live_state.get(name) or ""
                if not state or state == STATE_UNKNOWN:
                    state = power_row["state"] if power_row else STATE_UNKNOWN
                result.append(
                    {
                        "name": name,
                        "model": row["model"],
                        "transport": row["transport"],
                        "removable": bool(row["removable"]),
                        "rotational": bool(row["rotational"]),
                        "size_bytes": row["size_bytes"],
                        "mounts": [m for m in (row["mounts"] or "").split(",") if m],
                        "monitored": bool(row["monitored"]),
                        "reason": row["reason"],
                        "state": state,
                        "idle_seconds": live_idle.get(name),
                        "wake_count": counts.get(name, 0),
                        "last_wake": (
                            {
                                "ts": wake_row["ts"],
                                "id": wake_row["id"],
                                "confidence": wake_row["confidence"],
                                "suspect_count": wake_row["suspect_count"],
                            }
                            if wake_row
                            else None
                        ),
                    }
                )
            return result

        return self.with_repos(run)

    def api_wakes(self, params: Dict[str, str]) -> Dict[str, Any]:
        hours = _num(params, "hours", 24.0, 0.1, 24 * 365)
        limit = int(_num(params, "limit", 100, 1, 1000))
        dev = params.get("dev") or None

        def run(conn):
            wake_repo = dbm.WakeRepo(conn)
            rows = wake_repo.recent(hours=hours, dev=dev, limit=limit)
            ids = [r["id"] for r in rows]
            suspects = wake_repo.suspects_map(ids)
            items = []
            for row in rows:
                items.append(
                    {
                        "id": row["id"],
                        "ts": row["ts"],
                        "dev": row["dev"],
                        "idle_seconds": row["idle_seconds"],
                        "confidence": row["confidence"],
                        "note": row["note"],
                        "suspect_count": row["suspect_count"],
                        "suspects": [_suspect_dict(s) for s in suspects.get(row["id"], [])],
                    }
                )
            return {"items": items, "hours": hours}

        return self.with_repos(run)

    def api_wake_detail(self, wake_id: int) -> Dict[str, Any]:
        def run(conn):
            wake_repo = dbm.WakeRepo(conn)
            row = wake_repo.get(wake_id)
            if row is None:
                raise ApiError(404, "DWM_NOT_FOUND", f"唤醒记录 {wake_id} 不存在")
            return {
                "id": row["id"],
                "ts": row["ts"],
                "dev": row["dev"],
                "idle_seconds": row["idle_seconds"],
                "confidence": row["confidence"],
                "note": row["note"],
                "suspects": [_suspect_dict(s) for s in wake_repo.suspects(wake_id)],
            }

        return self.with_repos(run)

    def api_events(self, params: Dict[str, str]) -> Dict[str, Any]:
        minutes = _num(params, "minutes", 30.0, 0.1, 24 * 60 * 30)
        limit = int(_num(params, "limit", 200, 1, 2000))
        dev = params.get("dev") or None
        comm = params.get("comm") or None

        def run(conn):
            rows = dbm.AccessRepo(conn).recent(
                minutes=minutes, dev=dev, comm=comm, limit=limit
            )
            return {
                "items": [
                    {
                        "ts": r["ts"],
                        "dev": r["dev"],
                        "pid": r["pid"],
                        "comm": r["comm"],
                        "uid": r["uid"],
                        "op": r["op"],
                        "path": r["path"],
                        "container": r["container"],
                        "source": r["source"],
                    }
                    for r in rows
                ]
            }

        return self.with_repos(run)

    def api_offenders(self, params: Dict[str, str]) -> Dict[str, Any]:
        hours = _num(params, "hours", 24.0, 0.1, 24 * 365)
        limit = int(_num(params, "limit", 30, 1, 200))

        def run(conn):
            rows = dbm.AccessRepo(conn).offenders(hours=hours, limit=limit)
            total = sum(int(r["hits"]) for r in rows) or 1
            return {
                "items": [
                    {
                        "dev": r["dev"],
                        "comm": r["comm"],
                        "container": r["container"],
                        "hits": int(r["hits"]),
                        "share": round(int(r["hits"]) / total, 4),
                        "last_ts": r["last_ts"],
                        "first_ts": r["first_ts"],
                        "pids": int(r["pids"]),
                    }
                    for r in rows
                ]
            }

        return self.with_repos(run)

    def api_timeline(self, params: Dict[str, str]) -> Dict[str, Any]:
        hours = _num(params, "hours", 24.0, 0.5, 24 * 30)
        bucket = int(_num(params, "bucket", 300, 30, 7200))
        since = time.time() - hours * 3600.0

        def run(conn):
            buckets = dbm.AccessRepo(conn).bucket_counts(
                hours=hours, bucket_seconds=bucket
            )
            wakes = dbm.WakeRepo(conn).recent(hours=hours, limit=2000)
            series: Dict[str, List[Dict[str, float]]] = {}
            for row in buckets:
                series.setdefault(row["dev"], []).append(
                    {"ts": row["bucket_ts"], "hits": row["hits"]}
                )
            wake_map: Dict[str, List[Dict[str, Any]]] = {}
            for row in wakes:
                wake_map.setdefault(row["dev"], []).append(
                    {
                        "ts": row["ts"],
                        "id": row["id"],
                        "confidence": row["confidence"],
                        "suspect_count": row["suspect_count"],
                    }
                )
            return {
                "hours": hours,
                "bucket": bucket,
                "start": since,
                "end": time.time(),
                "series": series,
                "wakes": wake_map,
            }

        return self.with_repos(run)

    # ---- 写操作：按盘清除 ----
    def api_clear(self, params: Dict[str, str]) -> Dict[str, Any]:
        """清除某块盘的记录。默认清唤醒事件；access=1 时连访问/电源记录一起清。"""
        dev = (params.get("dev") or "").strip()
        if not dev:
            raise ApiError(400, "DWM_BAD_PARAM", "缺少 dev 参数")
        include_access = (params.get("access") or "") == "1"

        def run(conn):
            wake_repo = dbm.WakeRepo(conn)
            removed = {"wakes": wake_repo.clear(dev)}
            if include_access:
                removed["access"] = dbm.AccessRepo(conn).clear(dev)
                removed["power"] = dbm.PowerRepo(conn).clear(dev)
            return removed

        removed = self.with_repos(run)
        if self.clear_hook:
            try:
                removed["memory"] = self.clear_hook(dev)
            except Exception:  # noqa: BLE001 - 内存清理失败不影响 DB 结果
                LOG.exception("清除内存归因数据失败", extra={"dev": dev})
        LOG.info("已清除盘记录", extra={"dev": dev, **removed})
        return {"dev": dev, **removed}

    def api_summary(self, params: Dict[str, str]) -> Dict[str, Any]:
        hours = _num(params, "hours", 24.0, 0.1, 24 * 365)
        since = time.time() - hours * 3600.0

        def run(conn):
            wake_repo = dbm.WakeRepo(conn)
            rows = wake_repo.recent(hours=hours, limit=2000)
            unattributed = sum(1 for r in rows if int(r["suspect_count"]) == 0)
            by_confidence: Dict[str, int] = {}
            for row in rows:
                by_confidence[row["confidence"]] = by_confidence.get(row["confidence"], 0) + 1
            top = dbm.AccessRepo(conn).offenders(hours=hours, limit=5)
            return {
                "hours": hours,
                "wake_total": len(rows),
                "wake_by_device": wake_repo.count_by_device(since),
                "unattributed": unattributed,
                "by_confidence": by_confidence,
                "top_offenders": [
                    {
                        "dev": r["dev"],
                        "comm": r["comm"],
                        "container": r["container"],
                        "hits": int(r["hits"]),
                    }
                    for r in top
                ],
            }

        return self.with_repos(run)


def _suspect_dict(row) -> Dict[str, Any]:
    keys = row.keys()
    return {
        "pid": row["pid"],
        "comm": row["comm"],
        "cmdline": row["cmdline"],
        "container": row["container"],
        "uid": row["uid"],
        "hits": row["hits"],
        "first_ts": row["first_ts"],
        "last_ts": row["last_ts"],
        "sample_path": row["sample_path"],
        "ambiguous": bool(row["ambiguous"]) if "ambiguous" in keys else False,
        "phase": (row["phase"] if "phase" in keys else "pre") or "pre",
    }


def _num(
    params: Dict[str, str], name: str, default: float, low: float, high: float
) -> float:
    raw = params.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ApiError(400, "DWM_BAD_PARAM", f"参数 {name} 必须是数字") from exc
    return max(low, min(high, value))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "disk-wake-monitor"
    sys_version = ""

    # 由 make_server 注入
    app: ApiApp

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        LOG.debug("http", extra={"client": self.client_address[0], "line": fmt % args})

    # ---- 基础设施 ----
    def _request_id(self) -> str:
        return uuid.uuid4().hex[:8]

    def _send(self, status: int, body: bytes, content_type: str, *, extra=None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        if extra:
            for key, value in extra.items():
                self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _error(self, status: int, code: str, message: str) -> None:
        self._json(status, {"error": {"code": code, "message": message}})

    def _authorized(self, params: Dict[str, str]) -> bool:
        token = self.app.cfg.auth_token
        if not token:
            return True
        provided = self.headers.get("X-DWM-Token") or params.get("token", "")
        return bool(provided) and hmac.compare_digest(provided, token)

    # ---- 路由 ----
    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        request_id = self._request_id()
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = {
            key: values[-1]
            for key, values in urllib.parse.parse_qs(parsed.query).items()
        }

        try:
            if path.startswith("/api/"):
                if not self._authorized(params):
                    raise ApiError(401, "DWM_UNAUTHORIZED", "缺少或错误的访问令牌")
                self._route_api(path, params)
                return
            self._serve_static(path)
        except ApiError as exc:
            LOG.info(
                "API 错误",
                extra={
                    "request_id": request_id,
                    "path": path,
                    "status": exc.status,
                    "code": exc.code,
                },
            )
            self._error(exc.status, exc.code, exc.message)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception:  # noqa: BLE001
            LOG.exception("请求处理失败", extra={"request_id": request_id, "path": path})
            try:
                self._error(500, "DWM_INTERNAL", "服务内部错误，详见服务日志")
            except OSError:
                pass

    def do_POST(self) -> None:  # noqa: N802
        request_id = self._request_id()
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = {
            key: values[-1]
            for key, values in urllib.parse.parse_qs(parsed.query).items()
        }
        # 解析请求体（JSON）并与 query 合并；query 优先，便于 ?token= 鉴权
        length = int(self.headers.get("Content-Length") or 0)
        if length > 0:
            raw = self.rfile.read(min(length, 65536))
            try:
                payload = json.loads(raw.decode("utf-8")) if raw else {}
            except (ValueError, UnicodeDecodeError):
                payload = {}
            if isinstance(payload, dict):
                for key, value in payload.items():
                    if key not in params and value is not None:
                        params[key] = (
                            "1" if value is True else "0" if value is False else str(value)
                        )

        try:
            if path == "/api/clear":
                if not self._authorized(params):
                    raise ApiError(401, "DWM_UNAUTHORIZED", "缺少或错误的访问令牌")
                self._json(200, self.app.api_clear(params))
                return
            raise ApiError(404, "DWM_NO_ROUTE", f"未知接口 {path}")
        except ApiError as exc:
            LOG.info(
                "API 错误",
                extra={
                    "request_id": request_id,
                    "path": path,
                    "status": exc.status,
                    "code": exc.code,
                },
            )
            self._error(exc.status, exc.code, exc.message)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception:  # noqa: BLE001
            LOG.exception("请求处理失败", extra={"request_id": request_id, "path": path})
            try:
                self._error(500, "DWM_INTERNAL", "服务内部错误，详见服务日志")
            except OSError:
                pass

    def _route_api(self, path: str, params: Dict[str, str]) -> None:
        app = self.app
        if path == "/api/health":
            self._json(200, app.api_health())
        elif path == "/api/devices":
            self._json(200, {"items": app.api_devices(params)})
        elif path == "/api/wakes":
            self._json(200, app.api_wakes(params))
        elif path.startswith("/api/wakes/"):
            raw_id = path.rsplit("/", 1)[-1]
            try:
                wake_id = int(raw_id)
            except ValueError as exc:
                raise ApiError(400, "DWM_BAD_PARAM", "唤醒 id 必须是整数") from exc
            self._json(200, app.api_wake_detail(wake_id))
        elif path == "/api/events":
            self._json(200, app.api_events(params))
        elif path == "/api/offenders":
            self._json(200, app.api_offenders(params))
        elif path == "/api/timeline":
            self._json(200, app.api_timeline(params))
        elif path == "/api/summary":
            self._json(200, app.api_summary(params))
        elif path == "/api/stream":
            self._stream()
        else:
            raise ApiError(404, "DWM_NO_ROUTE", f"未知接口 {path}")

    def _serve_static(self, path: str) -> None:
        if path in ("/", ""):
            rel = "index.html"
        else:
            rel = path.lstrip("/")
        if rel == "favicon.ico":
            self._send(204, b"", "image/x-icon")
            return

        target = (WEB_ROOT / rel).resolve()
        # 目录穿越防护
        if not str(target).startswith(str(WEB_ROOT.resolve())) or not target.is_file():
            raise ApiError(404, "DWM_NOT_FOUND", "资源不存在")

        suffix = target.suffix.lower()
        content_type = CONTENT_TYPES.get(suffix, "application/octet-stream")
        body = target.read_bytes()
        cache = "no-cache" if suffix == ".html" else "public, max-age=60"
        self._send(200, body, content_type, extra={"Cache-Control": cache})

    def _stream(self) -> None:
        bus = self.app.bus
        if bus is None:
            raise ApiError(
                503,
                "DWM_STREAM_UNAVAILABLE",
                "当前为只读模式，实时推送仅在采集进程内可用",
            )

        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "keep-alive")
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        self.end_headers()

        channel = bus.subscribe()
        try:
            self.wfile.write(b"retry: 3000\n\n")
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while not self.app.stopping.is_set():
                try:
                    event = channel.get(timeout=15.0)
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    continue
                data = json.dumps(event, ensure_ascii=False, default=str)
                self.wfile.write(f"data: {data}\n\n".encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            bus.unsubscribe(channel)


def make_server(cfg: Config, app: ApiApp) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"app": app})
    try:
        server = ThreadingHTTPServer((cfg.host, cfg.port), handler)
    except OSError as exc:
        raise ApiError(
            500, "DWM_BIND_FAILED", f"无法监听 {cfg.host}:{cfg.port}：{exc}"
        ) from exc
    server.daemon_threads = True
    return server


def start_in_thread(cfg: Config, app: ApiApp) -> Tuple[ThreadingHTTPServer, threading.Thread]:
    server = make_server(cfg, app)
    thread = threading.Thread(
        target=server.serve_forever, name="http", daemon=True
    )
    thread.start()
    LOG.info(
        "面板已就绪",
        extra={
            "url": f"http://{cfg.host}:{cfg.port}/",
            "auth": bool(cfg.auth_token),
            "exposed": cfg.host not in ("127.0.0.1", "localhost"),
        },
    )
    if cfg.host not in ("127.0.0.1", "localhost") and not cfg.auth_token:
        LOG.warning(
            "面板对局域网开放且未设置访问令牌，建议设置 DWM_AUTH_TOKEN",
            extra={"host": cfg.host, "port": cfg.port},
        )
    return server, thread
