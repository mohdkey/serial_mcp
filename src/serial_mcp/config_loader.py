from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any


DEFAULT_CONFIG_FILENAME = "serial_mcp.config.json"


class ConfigStore:
    """负责读取/缓存串口默认配置."""

    def __init__(self, path: str | None = None) -> None:
        self._explicit_path = path
        self.path = self._resolve_path(path)
        self.data: dict[str, Any] | None = None
        self.load()

    def _resolve_path(self, candidate: str | None) -> Path:
        if candidate:
            return Path(candidate).expanduser()
        env_path = os.environ.get("SERIAL_MCP_CONFIG")
        if env_path:
            return Path(env_path).expanduser()
        return Path.cwd() / DEFAULT_CONFIG_FILENAME

    def load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            self.data = None
            return None
        try:
            raw = self.path.read_text(encoding="utf-8")
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise ValueError("JSON 顶层必须是对象")
            self.data = parsed
        except Exception as exc:  # noqa: BLE001
            print(
                f"[serial-mcp] 无法加载配置 {self.path}: {exc}",
                file=sys.stderr,
            )
            self.data = None
        return self.data

    def reload(self, path: str | None = None) -> dict[str, Any] | None:
        if path:
            self.path = self._resolve_path(path)
        return self.load()

    def export(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "active": self.data is not None,
            "config": self.data,
        }

