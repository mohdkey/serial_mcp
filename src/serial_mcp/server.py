from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Literal

import anyio

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from . import __version__
from .config_loader import ConfigStore
from .cursor_config import CursorMCPConfigurator
from .models import SerialConnectionConfig, SerialReadRequest, SerialWriteRequest
from .serial_manager import SerialConnectionManager


manager = SerialConnectionManager()
config_store = ConfigStore()
cursor_configurator = CursorMCPConfigurator()
cursor_configurator.ensure_entry(
    command=sys.executable,
    args=["-m", "serial_mcp.server"],
)
LOG_BASE_DIR = (config_store.path.parent if config_store.path else Path.cwd()) / "session_logs"


class SessionLogStore:
    """持久化保存 CLI 会话的输入输出，便于通过资源回放。"""

    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._lock = anyio.Lock()

    def _safe_session_id(self, session_id: str) -> str:
        allowed = [ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in session_id]
        return "".join(allowed)

    def _path_for(self, session_id: str) -> Path:
        safe_id = self._safe_session_id(session_id)
        return self.base_dir / f"{safe_id}.json"

    async def save(self, payload: dict[str, Any]) -> dict[str, str]:
        session_id = payload.get("session_id") or uuid.uuid4().hex
        payload["session_id"] = session_id
        payload.setdefault(
            "timestamp",
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
        path = self._path_for(session_id)
        data = json.dumps(payload, ensure_ascii=False, indent=2)
        async with self._lock:
            await anyio.to_thread.run_sync(lambda: path.write_text(data, encoding="utf-8"))
        return {"session_id": session_id, "path": str(path)}

    async def read(self, session_id: str) -> str:
        path = self._path_for(session_id)
        if not path.exists():
            raise FileNotFoundError(f"session log not found: {session_id}")
        async with self._lock:
            return await anyio.to_thread.run_sync(lambda: path.read_text(encoding="utf-8"))


class TerminalEnvironment:
    """缓存串口推断出的终端类型，避免重复探测."""

    def __init__(self) -> None:
        self.mode: Literal["shell", "uboot", "unknown"] | None = None

    def reset(self) -> None:
        self.mode = None

    def remember(self, mode: Literal["shell", "uboot", "unknown"]) -> None:
        self.mode = mode


terminal_env = TerminalEnvironment()
terminal_detection_lock = anyio.Lock()
session_log_store = SessionLogStore(LOG_BASE_DIR)

CONNECTION_DEFAULTS = {
    "baudrate": 115200,
    "bytesize": 8,
    "parity": "N",
    "stopbits": 1.0,
    "timeout": 1.0,
    "newline": "\\r\\n",
    "encoding": "utf-8",
    "rtscts": False,
    "dsrdtr": False,
    "xonxoff": False,
    "autopace": 0,
}
CONNECTION_ALLOWED_KEYS = set(CONNECTION_DEFAULTS) | {
    "port",
    "write_timeout",
    "dtr",
    "rts",
}

server = FastMCP(
    name="serial-mcp",
    instructions=f"serial-mcp v{__version__}：面向 Cursor 的串口调试 MCP 服务器。",
)

PROBE_COMMANDS = ["", "?", "h", "help", "whoami", "ls"]
UBOOT_HINTS = ("u-boot", "uboot", "=>", "unknown command")
SHELL_HINTS = (
    "root",
    "admin",
    "uid=",
    "gid=",
    "drwx",
    "lrwx",
    "/bin",
    "/etc",
    "/usr",
    "command not found",
    "No such file",
    "total ",
)

AUTH_LOGIN_HINTS = (
    "login:",
    "username:",
    "user:",
    "account:",
    "帐号",
    "账号",
)

AUTH_PASSWORD_HINTS = (
    "password:",
    "passwd:",
    "pass:",
    "密码",
    "密碼",
)


def _collect_text(response: dict[str, Any] | None) -> str:
    if not response:
        return ""
    texts: list[str] = []

    def _extract(payload: dict[str, Any] | None) -> None:
        if not isinstance(payload, dict):
            return
        text = payload.get("text")
        if text:
            texts.append(text)

    _extract(response.get("payload"))
    for chunk in response.get("chunks", []):
        if isinstance(chunk, dict):
            _extract(chunk.get("payload"))
    return "".join(texts)


def _looks_like_uboot(text: str) -> bool:
    lower = text.lower()
    return any(hint in lower for hint in UBOOT_HINTS)


def _looks_like_shell(text: str) -> bool:
    lower = text.lower()
    return any(hint in lower for hint in SHELL_HINTS)


def _detect_auth_prompt(text: str) -> tuple[bool, set[str]]:
    lower = text.lower()
    matches: set[str] = set()
    if any(hint in lower for hint in AUTH_LOGIN_HINTS):
        matches.add("login")
    if any(hint in lower for hint in AUTH_PASSWORD_HINTS):
        matches.add("password")
    return bool(matches), matches


async def _send_probe(
    command: str,
    *,
    encoding: str | None,
    timeout: float,
) -> dict[str, Any]:
    write_request = SerialWriteRequest(
        text=command,
        hex_data=None,
        append_newline=True,
        encoding=encoding,
    )
    read_request = SerialReadRequest(
        max_bytes=1024,
        timeout=timeout,
        until_newline=False,
        return_hex=False,
        encoding=encoding,
    )
    return await manager.chat(
        write_request,
        read_request,
        settle_time=0.1,
        wait_for_prompt=None,
        max_reads=3,
        read_interval=0.05,
    )


async def _detect_terminal_mode(
    *,
    encoding: str | None,
    timeout: float | None,
) -> Literal["shell", "uboot", "unknown"]:
    probe_timeout = timeout if timeout is not None else 1.0
    probe_timeout = max(0.1, min(probe_timeout, 1.5))
    try:
        await manager.flush("input")
    except RuntimeError:
        return "unknown"

    for command in PROBE_COMMANDS:
        probe_result = await _send_probe(command, encoding=encoding, timeout=probe_timeout)
        text = _collect_text(probe_result)
        if not text:
            continue
        if _looks_like_uboot(text):
            return "uboot"
        if _looks_like_shell(text):
            return "shell"
    return "unknown"


async def _ensure_terminal_mode(
    *,
    encoding: str | None,
    timeout: float | None,
) -> Literal["shell", "uboot", "unknown"]:
    async with terminal_detection_lock:
        if terminal_env.mode:
            return terminal_env.mode
        try:
            detected = await _detect_terminal_mode(encoding=encoding, timeout=timeout)
        except Exception:  # noqa: BLE001
            detected = "unknown"
        terminal_env.remember(detected)
        return detected


@server.tool()
async def list_serial_ports() -> list[dict]:
    """
    枚举当前主机上的可用串口。
    """

    return await manager.list_ports()


@server.tool()
async def connect_serial(
    port: Annotated[str | None, Field(description="串口名，例如 COM7 或 /dev/ttyUSB0")] = None,
    baudrate: Annotated[int | None, Field(ge=75, le=4_000_000)] = None,
    bytesize: Annotated[int | None, Field(ge=5, le=8)] = None,
    parity: Annotated[str | None, Field(description="N/E/O/M/S")] = None,
    stopbits: Annotated[float | None, Field(description="1/1.5/2")] = None,
    timeout: Annotated[float | None, Field(ge=0.0)] = None,
    write_timeout: Annotated[float | None, Field(ge=0.0)] = None,
    newline: Annotated[str | None, Field(description="可用 \\n、\\r、\\x00 等转义")] = None,
    encoding: Annotated[str | None, Field(description="默认文本编码")] = None,
    rtscts: Annotated[bool | None, Field(description="开启 RTS/CTS 流控")] = None,
    dsrdtr: Annotated[bool | None, Field(description="开启 DSR/DTR 流控")] = None,
    xonxoff: Annotated[bool | None, Field(description="开启 XON/XOFF 流控")] = None,
    dtr: Annotated[bool | None, Field(description="连接后强制 DTR 电平")] = None,
    rts: Annotated[bool | None, Field(description="连接后强制 RTS 电平")] = None,
    autopace: Annotated[
        int | None,
        Field(ge=0, le=1000, description="写入字节间隔（毫秒），0 表示关闭"),
    ] = None,
) -> dict:
    """建立或更新串口连接，未显式指定的字段会优先采用 JSON 配置。"""

    overrides = {
        "port": port,
        "baudrate": baudrate,
        "bytesize": bytesize,
        "parity": parity,
        "stopbits": stopbits,
        "timeout": timeout,
        "write_timeout": write_timeout,
        "newline": newline,
        "encoding": encoding,
        "rtscts": rtscts,
        "dsrdtr": dsrdtr,
        "xonxoff": xonxoff,
        "dtr": dtr,
        "rts": rts,
        "autopace": autopace,
    }
    safe_overrides = {k: v for k, v in overrides.items() if v is not None}

    payload = dict(CONNECTION_DEFAULTS)
    if config_store.data:
        payload.update(
            {
                k: v
                for k, v in config_store.data.items()
                if k in CONNECTION_ALLOWED_KEYS and v is not None
            }
        )
    payload.update(safe_overrides)

    if not payload.get("port"):
        raise ValueError(
            "未检测到串口端口号，请在 JSON 配置文件或 connect_serial 参数中提供 port"
        )

    config = SerialConnectionConfig(**payload)
    result = await manager.connect(config)
    terminal_env.reset()
    return result


@server.tool()
async def disconnect_serial() -> dict:
    """断开当前串口连接。"""

    result = await manager.disconnect()
    terminal_env.reset()
    return result


@server.tool()
async def serial_connection_info() -> dict:
    """返回当前连接状态和配置。"""

    return await manager.info()


@server.tool()
async def write_serial(
    text: Annotated[str | None, Field(description="写入的文本")] = None,
    hex_data: Annotated[str | None, Field(description="写入的十六进制字节")] = None,
    append_newline: Annotated[bool, Field(description="是否追加换行")] = False,
    encoding: Annotated[str | None, Field(description="覆盖默认编码")] = None,
) -> dict:
    """将文本或十六进制数据写入串口。"""

    request = SerialWriteRequest(
        text=text,
        hex_data=hex_data,
        append_newline=append_newline,
        encoding=encoding,
    )
    return await manager.write(request)


@server.tool()
async def read_serial(
    max_bytes: Annotated[int, Field(ge=1, le=65_536)] = 256,
    timeout: Annotated[float | None, Field(ge=0.0)] = None,
    until_newline: Annotated[bool, Field(description="遇到换行就返回")] = False,
    return_hex: Annotated[bool, Field(description="结果以十六进制表示")] = False,
    encoding: Annotated[str | None, Field(description="覆盖默认编码")] = None,
) -> dict:
    """按需读取串口缓冲区。"""

    request = SerialReadRequest(
        max_bytes=max_bytes,
        timeout=timeout,
        until_newline=until_newline,
        return_hex=return_hex,
        encoding=encoding,
    )
    return await manager.read(request)


@server.tool()
async def flush_serial_buffers(
    direction: Annotated[
        str,
        Field(description="both / input / output", examples=["both"]),
    ] = "both",
) -> dict:
    """清空串口输入/输出缓冲。"""

    return await manager.flush(direction)


@server.tool()
async def serial_cli_command(
    command: Annotated[str | None, Field(description="要写入 CLI 的文本")] = "",
    hex_data: Annotated[str | None, Field(description="或写入 16 进制字节")] = None,
    append_newline: Annotated[bool, Field(description="末尾是否自动追加换行")] = True,
    encoding: Annotated[str | None, Field(description="覆盖默认编码")] = None,
    settle_time: Annotated[
        float,
        Field(ge=0.0, description="写入后等待多长时间再读取（秒）"),
    ] = 0.1,
    max_bytes: Annotated[int, Field(ge=1, le=65_536)] = 1024,
    timeout: Annotated[float | None, Field(ge=0.0)] = 1.0,
    until_newline: Annotated[bool, Field(description="读取到换行就返回")] = False,
    return_hex: Annotated[bool, Field(description="响应是否以十六进制返回")] = False,
    read_response: Annotated[bool, Field(description="若 False 则仅写入不读取")] = True,
    wait_for_prompt: Annotated[
        str | None,
        Field(description="当检测到该提示符时提前结束读取"),
    ] = "aic>",
    max_reads: Annotated[int, Field(ge=1, le=20)] = 3,
    read_interval: Annotated[
        float,
        Field(ge=0.0, description="多次读取之间的等待时间"),
    ] = 0.0,
    wake_before_command: Annotated[
        bool,
        Field(description="写入命令前是否先发送一次回车进行唤醒"),
    ] = True,
    terminal_mode: Annotated[
        Literal["auto", "shell", "uboot"],
        Field(description="根据终端类型自动调整唤醒、提示符与标记策略"),
    ] = "auto",
    append_done_marker: Annotated[
        bool | None,
        Field(description="自动在命令后追加 echo 标记并据此终止读取"),
    ] = None,
    done_marker: Annotated[
        str,
        Field(description="命令结束标记（与 append_done_marker 配合使用）"),
    ] = "__SERIAL_MCP_DONE__",
    discard_pending_input: Annotated[
        bool | None,
        Field(description="执行命令前是否丢弃串口缓冲区中已存在的数据"),
    ] = None,
) -> dict:
    """
    便捷的 CLI 命令执行：写入后可自动等待并读取响应。
    """

    prompt_hint = (wait_for_prompt or "").lower() if wait_for_prompt else ""
    inferred_mode = terminal_mode
    detected_mode: Literal["shell", "uboot", "unknown"] | None = None
    if inferred_mode == "auto":
        if hex_data is None:
            detected_mode = await _ensure_terminal_mode(encoding=encoding, timeout=timeout)
        if detected_mode and detected_mode != "unknown":
            inferred_mode = detected_mode
        elif "boot" in prompt_hint:
            inferred_mode = "uboot"
        else:
            inferred_mode = "shell"
    is_uboot = inferred_mode == "uboot"

    wake_request = None
    if wake_before_command:
        wake_payload = "\x03" if is_uboot else ""
        wake_request = SerialWriteRequest(
            text=wake_payload,
            hex_data=None,
            append_newline=True,
            encoding=encoding,
        )

    clean_marker = (done_marker or "").strip()
    prepared_command = command or ""
    if append_done_marker is None:
        append_done_marker = (
            not is_uboot
            and not hex_data
            and prepared_command.strip()
            and clean_marker
            and not return_hex
            and read_response
        )
    if discard_pending_input is None:
        discard_pending_input = not is_uboot

    marker_attached = bool(
        append_done_marker
        and not hex_data
        and prepared_command.strip()
        and clean_marker
        and not return_hex
    )
    effective_wait_for_prompt = wait_for_prompt
    if marker_attached and not effective_wait_for_prompt:
        effective_wait_for_prompt = clean_marker
    if (
        inferred_mode == "uboot"
        and (not wait_for_prompt or wait_for_prompt == "aic>")
        and not marker_attached
    ):
        effective_wait_for_prompt = "U-Boot>"

    if marker_attached:
        marker_line = f"echo {clean_marker}"
        prepared_command = "\n".join([prepared_command, marker_line])

    write_request = SerialWriteRequest(
        text=None if hex_data else prepared_command,
        hex_data=hex_data,
        append_newline=append_newline,
        encoding=encoding,
    )

    if not read_response:
        if wake_request:
            await manager.write(wake_request)
        return await manager.write(write_request)

    if discard_pending_input:
        await manager.flush("input")

    if wake_request:
        await manager.write(wake_request)

    read_request = SerialReadRequest(
        max_bytes=max_bytes,
        timeout=timeout,
        until_newline=until_newline,
        return_hex=return_hex,
        encoding=encoding,
    )
    result = await manager.chat(
        write_request,
        read_request,
        settle_time,
        wait_for_prompt=effective_wait_for_prompt,
        max_reads=max_reads,
        read_interval=read_interval,
    )

    result["marker_attached"] = bool(marker_attached)
    result["marker_text"] = clean_marker if marker_attached else None
    result["terminal_mode"] = inferred_mode
    result["detected_terminal_mode"] = detected_mode or terminal_env.mode

    if marker_attached and not return_hex and result.get("prompt_found"):
        def _strip_marker(payload: dict[str, Any]) -> None:
            text = payload.get("text")
            if text is None:
                return
            for token in (
                f"{clean_marker}\r\n",
                f"{clean_marker}\n",
                clean_marker,
            ):
                if token in text:
                    payload["text"] = text.replace(token, "", 1)
                    return

        _strip_marker(result.get("payload", {}))
        for chunk in result.get("chunks", []):
            _strip_marker(chunk.get("payload", {}))

    aggregated_text = _collect_text(result)
    auth_needed, auth_types = _detect_auth_prompt(aggregated_text)
    result["auth_prompt_detected"] = auth_needed
    result["auth_prompt_types"] = sorted(auth_types)
    if auth_needed:
        if {"login", "password"} <= auth_types:
            hint = "检测到登录与密码提示，请输入账号及密码后重试。"
        elif "login" in auth_types:
            hint = "检测到登录提示，请输入账号或用户名。"
        elif "password" in auth_types:
            hint = "检测到密码提示，请输入密码。"
        else:
            hint = "检测到认证提示，请输入账号/密码。"
        result["auth_prompt_hint"] = hint
    else:
        result["auth_prompt_hint"] = None

    log_payload = {
        "type": "serial_cli_command",
        "command": command,
        "hex_data": hex_data,
        "append_newline": append_newline,
        "return_hex": return_hex,
        "read_response": read_response,
        "wait_for_prompt": effective_wait_for_prompt,
        "detected_terminal_mode": result.get("detected_terminal_mode"),
        "inferred_terminal_mode": inferred_mode,
        "timeout": timeout,
        "max_bytes": max_bytes,
        "result": result,
    }
    try:
        log_info = await session_log_store.save(log_payload)
    except Exception as exc:  # noqa: BLE001
        result["session_log_error"] = f"无法写入会话日志: {exc}"
    else:
        result["session_id"] = log_info["session_id"]
        result["session_log_path"] = log_info["path"]
        result["session_log_resource"] = f"serial://sessions/{log_info['session_id']}/log"

    return result


@server.resource(
    "serial://port/{port}/config",
    title="串口配置快照",
    description="查看指定串口在当前连接或默认配置中的参数。",
    mime_type="application/json",
)
async def resource_port_config(port: str) -> str:
    runtime = await manager.info()
    active_config = runtime.get("config") or {}
    payload: dict[str, Any] = {
        "port": port,
        "connected": bool(runtime.get("open") and active_config.get("port") == port),
        "source": None,
        "config": None,
        "config_file": str(config_store.path),
        "notes": [],
    }
    if payload["connected"]:
        payload["source"] = "active_connection"
        payload["config"] = active_config
        payload["notes"].append("信息取自当前串口会话。")
    elif config_store.data and config_store.data.get("port") == port:
        payload["source"] = "config_store"
        payload["config"] = {
            k: v
            for k, v in config_store.data.items()
            if k in CONNECTION_ALLOWED_KEYS
        }
        payload["notes"].append("信息取自 serial_mcp.config.json。")
    else:
        payload["notes"].append("未在运行中会话或默认配置中找到该串口。")
    return json.dumps(payload, ensure_ascii=False, indent=2)


@server.resource(
    "serial://sessions/{session_id}/log",
    title="串口会话日志",
    description="返回指定会话的 CLI 写入/读取结果（JSON）。",
    mime_type="application/json",
)
async def resource_session_log(session_id: str) -> str:
    try:
        return await session_log_store.read(session_id)
    except FileNotFoundError:
        return json.dumps(
            {
                "session_id": session_id,
                "error": "未找到匹配的会话日志。",
                "hint": "请先调用 serial_cli_command，随后使用返回的 session_id 来读取日志。",
            },
            ensure_ascii=False,
            indent=2,
        )


MODBUS_SPEC_RESOURCE = """
# Modbus RTU 速查

## 帧结构
- 起始/停止: 由静默时间界定 (3.5T)
- 地址 (1 字节): 0x01~0xF7，0x00 广播
- 功能码 (1 字节): 0x01/0x02/0x03/0x04 读寄存器；0x05/0x06 写单寄存器；0x0F/0x10 写多个寄存器
- 数据区 (N 字节): 负载或寄存器值
- CRC16 (2 字节，小端): 多项式 0xA001，初始值 0xFFFF

## 常用寄存器映射
- 0xxxx: 线圈输出 (读/写)
- 1xxxx: 离散输入 (只读)
- 3xxxx: 输入寄存器 (只读)
- 4xxxx: 保持寄存器 (读/写)

## 调试建议
1. 明确角色：地址字段指示从机 ID，广播帧无响应。
2. 捕获原始串口数据，检查功能码与 CRC 是否匹配。
3. 对写类功能码，留意响应是否回显写入值，否则说明从机拒绝执行。
4. 若设备提供诊断 (0x08) 或自定义 (0x41+) 功能码，可通过逐字节 fuzz 揭示隐藏命令。
""".strip()


@server.resource(
    "serial://protocols/modbus/spec",
    title="Modbus 协议描述",
    description="提供 Modbus RTU 帧格式与调试注意事项。",
    mime_type="text/markdown",
)
def resource_modbus_spec() -> str:
    return MODBUS_SPEC_RESOURCE


@server.tool()
async def serial_config_info() -> dict:
    """查看当前 JSON 配置文件路径与内容。"""

    return config_store.export()


@server.tool()
async def set_serial_control_lines(
    dtr: Annotated[bool | None, Field(description="设置 DTR 电平 (True=拉高)")] = None,
    rts: Annotated[bool | None, Field(description="设置 RTS 电平 (True=拉高)")] = None,
) -> dict:
    """
    在串口已连接的前提下，动态拉高/拉低控制线。
    """

    if dtr is None and rts is None:
        raise ValueError("必须至少指定 dtr 或 rts 之一")
    return await manager.set_control_lines(dtr, rts)


@server.tool()
async def reload_serial_config(
    path: Annotated[str | None, Field(description="可选的新配置文件路径")] = None,
) -> dict:
    """重新加载 JSON 串口配置，可用于切换端口/波特率预设。"""

    config_store.reload(path)
    return config_store.export()


@server.prompt(
    name="debug_serial_device",
    title="串口调试剧本",
    description="一步步指导 AI 完成串口日志收集、固件提取与安全排查。",
)
def prompt_debug_serial_device() -> list[dict[str, Any]]:
    script = """
你是嵌入式设备串口调试助手，请严格按以下顺序行动并在每步解释观察结果，且**任何判断前必须先实际发送回车/探测命令并观察最新串口回显**。最终输出必须显式区分「日志分析」与「终端分析」两块内容，并在每块下列出对应证据：

0. **实时探测**：不要凭空推理。每次进入新步骤或看到静默输出前，都先调用 `serial_cli_command`（如 `command=""` 或 `command="help"`）发送至少一次空回车/`help`，记录真实返回，再据此决定下一步。
0.1 **登录处理**：若串口提示 `login:`/`password:`，要按照“账号 -> 回车 -> 密码 -> 回车”的顺序，分两次调用 `serial_cli_command` 输入凭据；完成后再次回车确认提示符，确保后续操作确实运行在 shell 内。
1. **日志巡检**（输出时归入“日志分析”）：持续读取串口日志，捕获最新系统事件（内核、网络、守护进程等）并提炼异常/敏感信息（URL、内核入口地址/大小、密钥、证书等），必要时保存 `session_id` 供复盘。
2. **U-Boot 判定**：若提示符或日志显示为 U-Boot，使用 `?`/`help` 列出全部命令。发现 `tftpboot`、`tftp`、`loadx`、`loady`、`dd` 等可用于固件导出的命令时，提醒用户可以直接提取固件；若存在 `bootm`/`bootz`/`booti` 等镜像引导命令，则告知可加载自定义镜像进一步拿到 shell。
3. **Shell 环境**：若进入 Linux shell，先读取 `/proc/mtd` 或 `cat /proc/partitions` 判断固件/分区布局，再检查 `/dev` 中是否暴露 NAND/NOR/EMMC 节点，并分析系统内是否存在 `nc`、`tftp`、`scp` 等可用于外传固件的工具。
4. **安全排查**（输出时归入“终端分析”）：必须系统地遍历终端文件与进程：
   - 目录：`ls -al /etc`, `/etc/init.d`, `/var`, `/home`, `/tmp` 等，寻找明文配置、账户、脚本；对可疑目录执行 `grep -R "KEY"`, `grep -R "password"`, 查找 `.pem/.key/.crt/.bin/.img`。
   - 进程/端口：使用 `ps -w`, `top -b -n1`, `netstat -tunlp` 或 `ss -lntup`，标记主要二进制及监听端口。
   - 记录所有发现（硬编码密钥、弱口令、后门脚本、未授权服务等），并给出复现命令及建议。

输出时先给出「日志分析」章节（步骤 1 的结论），再给出「终端分析」章节（步骤 3/4 的操作与发现），最后附上一份命令清单和下一步建议。
""".strip()
    return [
        {
            "role": "user",
            "content": {
                "type": "text",
                "text": script,
            },
        }
    ]


def run() -> None:
    server.run()


if __name__ == "__main__":
    run()

