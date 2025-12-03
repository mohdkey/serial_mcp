from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


def _decode_escape_sequences(value: str) -> str:
    """将 \\n、\\r 等转义形式转换成真实字符."""
    if value == "":
        return ""
    try:
        return value.encode("utf-8").decode("unicode_escape")
    except UnicodeDecodeError as exc:
        raise ValueError(f"换行符转义无效: {value}") from exc


class SerialConnectionConfig(BaseModel):
    port: str = Field(..., description="串口名，如 COM5 或 /dev/ttyUSB0")
    baudrate: int = Field(
        115200, ge=75, le=4_000_000, description="波特率，常见为 9600 / 115200"
    )
    bytesize: Literal[5, 6, 7, 8] = Field(
        8, description="数据位，通常为 8"
    )
    parity: Literal["N", "E", "O", "M", "S"] = Field(
        "N", description="校验位，N=无, E=偶, O=奇, M=Mark, S=Space"
    )
    stopbits: float = Field(
        1.0, description="停止位，可选 1、1.5、2"
    )
    timeout: float = Field(
        1.0, ge=0.0, description="读操作超时（秒），0 表示非阻塞"
    )
    write_timeout: float | None = Field(
        default=None, ge=0.0, description="写操作超时，留空使用 pyserial 默认"
    )
    newline: str = Field(
        "\\n", description="用于追加/截断的结束符，允许使用 \\n、\\r、\\x00 等转义"
    )
    encoding: str = Field(
        "utf-8", description="文本读写使用的编码"
    )
    rtscts: bool = Field(
        False, description="是否启用硬件 RTS/CTS 流控"
    )
    dsrdtr: bool = Field(
        False, description="是否启用硬件 DSR/DTR 流控"
    )
    xonxoff: bool = Field(
        False, description="是否启用软件 XON/XOFF 流控"
    )
    autopace: int = Field(
        0, ge=0, le=1000, description="写入时每字节之间的延迟 (毫秒)，0 为关闭"
    )
    dtr: bool | None = Field(
        default=None, description="连接后是否强制设置 DTR 电平 (True=拉高)"
    )
    rts: bool | None = Field(
        default=None, description="连接后是否强制设置 RTS 电平 (True=拉高)"
    )

    @field_validator("parity")
    @classmethod
    def _normalize_parity(cls, value: str) -> str:
        return value.upper()

    @field_validator("stopbits")
    @classmethod
    def _validate_stopbits(cls, value: float) -> float:
        allowed = {1.0, 1.5, 2.0}
        normalized = float(value)
        if normalized not in allowed:
            raise ValueError("stopbits 仅支持 1, 1.5, 2")
        return normalized

    @field_validator("newline")
    @classmethod
    def _normalize_newline(cls, value: str) -> str:
        return _decode_escape_sequences(value)

    def encoded_newline(self) -> bytes:
        """返回编码后的换行符，若为空则返回空字节."""
        if not self.newline:
            return b""
        return self.newline.encode(self.encoding, errors="ignore")

    def public_dict(self) -> dict:
        payload = self.model_dump()
        payload["newline_display"] = self.newline.encode("unicode_escape").decode(
            "ascii"
        )
        return payload


class SerialWriteRequest(BaseModel):
    text: str | None = Field(
        default=None, description="要写入的纯文本（与 hex_data 互斥）"
    )
    hex_data: str | None = Field(
        default=None, description="要写入的 16 进制字节，例如 '0A FF 01'"
    )
    append_newline: bool = Field(
        default=False, description="写入末尾是否追加配置中的换行符"
    )
    encoding: str | None = Field(
        default=None, description="覆盖默认编码"
    )

    @model_validator(mode="after")
    def _validate_payload(self) -> "SerialWriteRequest":
        has_text = self.text is not None
        has_hex = self.hex_data is not None
        if has_text == has_hex:
            raise ValueError("text 与 hex_data 必须二选一")
        return self

    def to_bytes(self, config: SerialConnectionConfig) -> bytes:
        newline = config.encoded_newline() if self.append_newline else b""
        if self.text is not None:
            encoding = self.encoding or config.encoding
            return self.text.encode(encoding) + newline
        hex_clean = self.hex_data.replace(" ", "")
        try:
            data = bytes.fromhex(hex_clean)
        except ValueError as exc:
            raise ValueError(f"无效的 hex_data: {self.hex_data}") from exc
        return data + newline


class SerialReadRequest(BaseModel):
    max_bytes: int = Field(
        256, ge=1, le=65_536, description="读取的最大字节数"
    )
    timeout: float | None = Field(
        default=None, ge=0.0, description="临时覆盖连接的读超时，单位秒"
    )
    until_newline: bool = Field(
        default=False, description="若为 True 则读取到换行符或 max_bytes 为止"
    )
    return_hex: bool = Field(
        default=False, description="返回十六进制字符串而非文本"
    )
    encoding: str | None = Field(
        default=None, description="文本模式时使用的编码"
    )

    def format_bytes(self, data: bytes, config: SerialConnectionConfig) -> dict:
        if self.return_hex:
            return {"hex": data.hex(" "), "length": len(data)}
        encoding = self.encoding or config.encoding
        text = data.decode(encoding, errors="replace")
        return {"text": text, "length": len(data)}

