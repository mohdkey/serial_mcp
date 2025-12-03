from __future__ import annotations

import sys
from typing import Annotated

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

CONNECTION_DEFAULTS = {
    "baudrate": 115200,
    "bytesize": 8,
    "parity": "N",
    "stopbits": 1.0,
    "timeout": 1.0,
    "newline": "\\n",
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
    return await manager.connect(config)


@server.tool()
async def disconnect_serial() -> dict:
    """断开当前串口连接。"""

    return await manager.disconnect()


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
) -> dict:
    """
    便捷的 CLI 命令执行：写入后可自动等待并读取响应。
    """

    write_request = SerialWriteRequest(
        text=command,
        hex_data=hex_data,
        append_newline=append_newline,
        encoding=encoding,
    )

    if not read_response:
        return await manager.write(write_request)

    read_request = SerialReadRequest(
        max_bytes=max_bytes,
        timeout=timeout,
        until_newline=until_newline,
        return_hex=return_hex,
        encoding=encoding,
    )
    return await manager.chat(write_request, read_request, settle_time)


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

