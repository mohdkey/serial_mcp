from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any


DEFAULT_CONFIG_FILENAME = "serial_mcp.config.json"
# 用于推断项目根目录的文件/脚本哨兵
PROJECT_ROOT_SENTINELS = (
    "pyproject.toml",
    "start-serial-mcp.bat",
)


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
        project_root = self._guess_project_root()
        if project_root:
            return project_root / DEFAULT_CONFIG_FILENAME
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

    def _guess_project_root(self) -> Path | None:
        """
        当服务器由 Cursor 直接启动时，进程工作目录通常在用户 Home，
        需要根据源码位置推断项目根目录，从而定位当前仓库下的配置文件。
        """

        module_dir = Path(__file__).resolve().parent
        for candidate in (module_dir, *module_dir.parents):
            if any((candidate / sentinel).exists() for sentinel in PROJECT_ROOT_SENTINELS):
                return candidate
        return None

