"""极简进程内事件总线，供 SSE 推送使用。"""

from __future__ import annotations

import queue
import threading
from typing import Any, Dict, List, Optional


class EventBus:
    def __init__(self, max_queued: int = 64) -> None:
        self._subscribers: List["queue.Queue[Dict[str, Any]]"] = []
        self._lock = threading.Lock()
        self._max = max_queued

    def publish(self, event: Dict[str, Any]) -> None:
        with self._lock:
            targets = list(self._subscribers)
        for target in targets:
            try:
                target.put_nowait(event)
            except queue.Full:
                # 慢消费者直接丢弃最新事件，绝不阻塞采集主循环
                pass

    def subscribe(self) -> "queue.Queue[Dict[str, Any]]":
        channel: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=self._max)
        with self._lock:
            self._subscribers.append(channel)
        return channel

    def unsubscribe(self, channel: "queue.Queue[Dict[str, Any]]") -> None:
        with self._lock:
            if channel in self._subscribers:
                self._subscribers.remove(channel)

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)
