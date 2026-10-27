"""类型化错误体系。

分层约定：
- ConfigError    启动期配置/环境问题，必须快速失败
- DeviceError    读取 /sys、/proc 失败
- SourceError    事件源（fatrace / block_dump）不可用或中断
- DbError        数据库读写失败
- ProbeError     probe 自检失败
"""

from __future__ import annotations


class DwmError(Exception):
    """所有本项目异常的基类。"""

    code = "DWM_ERROR"

    def __init__(self, message: str, *, hint: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def to_dict(self) -> dict:
        payload = {"code": self.code, "message": self.message}
        if self.hint:
            payload["hint"] = self.hint
        return payload

    def __str__(self) -> str:  # pragma: no cover - trivial
        if self.hint:
            return f"{self.message}（提示：{self.hint}）"
        return self.message


class ConfigError(DwmError):
    code = "DWM_CONFIG_INVALID"


class DeviceError(DwmError):
    code = "DWM_DEVICE_UNAVAILABLE"


class SourceError(DwmError):
    code = "DWM_SOURCE_UNAVAILABLE"


class DbError(DwmError):
    code = "DWM_DB_ERROR"


class ProbeError(DwmError):
    code = "DWM_PROBE_FAILED"
