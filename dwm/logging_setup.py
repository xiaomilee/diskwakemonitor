"""结构化 JSON 日志。

每条日志一行 JSON，便于 `journalctl -o cat | jq` 直读。
不记录密码、令牌、隐私路径内容之外的东西；路径本身是排查必需，故保留。
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from typing import Any, Optional

_RESERVED = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "taskName", "asctime",
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(record.created))
            + f".{int(record.msecs):03d}"
            + time.strftime("%z", time.localtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key in _RESERVED or key.startswith("_"):
                continue
            try:
                json.dumps(value)
                payload[key] = value
            except (TypeError, ValueError):
                payload[key] = repr(value)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup(level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """配置根 logger，返回项目 logger。可重复调用（幂等）。"""
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    for handler in list(root.handlers):
        root.removeHandler(handler)

    stream = logging.StreamHandler(stream=sys.stdout)
    stream.setFormatter(JsonFormatter())
    root.addHandler(stream)

    if log_file:
        try:
            os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(JsonFormatter())
            root.addHandler(file_handler)
        except OSError:
            root.warning("日志文件不可写，仅输出到 stdout", extra={"path": log_file})

    return logging.getLogger("dwm")
