from __future__ import annotations

import sys
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

    return result


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


def run() -> None:
    server.run()


if __name__ == "__main__":
    run()

