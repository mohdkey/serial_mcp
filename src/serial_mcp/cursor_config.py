from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

DEFAULT_TIMEOUT = 1800
SERVER_NAME = "serial-mcp"


class CursorMCPConfigurator:
    """提示用户如何在 Cursor mcp.json 中添加 serial-mcp。"""

    def __init__(self, path: str | None = None) -> None:
        self.path = self._resolve_path(path)

    def _resolve_path(self, override: str | None) -> Path:
        if override:
            return Path(override).expanduser()
        env_override = os.environ.get("SERIAL_MCP_CURSOR_CONFIG")
        if env_override:
            return Path(env_override).expanduser()

        system = sys.platform
        if system == "win32":
            base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        elif system == "darwin":
            base = Path.home() / "Library" / "Application Support"
        else:
            base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))

        return base / "Cursor" / "User" / "mcp.json"

    def ensure_entry(
        self,
        command: str,
        args: list[str],
        timeout: int = DEFAULT_TIMEOUT,
        disabled: bool = False,
    ) -> dict[str, Any]:
        config = self._load()
        servers: Dict[str, Any] = config.get("mcpServers", {})
        existing = servers.get(SERVER_NAME) if isinstance(servers, dict) else None

        entry = {
            "command": command,
            "args": args,
            "timeout": timeout,
            "disabled": disabled,
        }

        if existing:
            return {
                "path": str(self.path),
                "already_exists": True,
                "config": existing,
            }

        snippet = self._render_snippet(entry)
        message = (
            "[serial-mcp] 请在 Cursor MCP 配置中新增以下条目：\n"
            f"目标文件：{self.path}\n"
            "--- 复制以下 JSON ---\n"
            f"{snippet}\n"
            "--------------------\n"
        )
        print(message, file=sys.stderr)
        return {
            "path": str(self.path),
            "already_exists": False,
            "config": entry,
            "snippet": snippet,
        }

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            raw = self.path.read_text(encoding="utf-8")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError("mcp.json 顶层必须是对象")
            return payload
        except Exception as exc:  # noqa: BLE001
            print(
                f"[serial-mcp] 无法解析 Cursor mcp.json ({self.path}): {exc}",
                file=sys.stderr,
            )
            return {}

    def _render_snippet(self, entry: dict[str, Any]) -> str:
        payload = {"mcpServers": {SERVER_NAME: entry}}
        return json.dumps(payload, ensure_ascii=False, indent=2)

