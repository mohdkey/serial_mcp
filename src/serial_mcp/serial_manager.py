from __future__ import annotations

from typing import Any

import anyio
import serial
from serial import SerialException
from serial.tools import list_ports

from .models import SerialConnectionConfig, SerialReadRequest, SerialWriteRequest


BYTESIZE_MAP = {
    5: serial.FIVEBITS,
    6: serial.SIXBITS,
    7: serial.SEVENBITS,
    8: serial.EIGHTBITS,
}

PARITY_MAP = {
    "N": serial.PARITY_NONE,
    "E": serial.PARITY_EVEN,
    "O": serial.PARITY_ODD,
    "M": serial.PARITY_MARK,
    "S": serial.PARITY_SPACE,
}

STOPBITS_MAP = {
    1.0: serial.STOPBITS_ONE,
    1.5: serial.STOPBITS_ONE_POINT_FIVE,
    2.0: serial.STOPBITS_TWO,
}


class SerialConnectionManager:
    """负责串口的生命周期与读写协调."""

    def __init__(self) -> None:
        self._state_lock = anyio.Lock()
        self._io_lock = anyio.Lock()
        self._serial: serial.Serial | None = None
        self._config: SerialConnectionConfig | None = None

    async def list_ports(self) -> list[dict[str, Any]]:
        def _collect() -> list[dict[str, Any]]:
            ports = []
            for info in list_ports.comports():
                ports.append(
                    {
                        "device": info.device,
                        "description": info.description,
                        "hwid": info.hwid,
                        "manufacturer": info.manufacturer,
                        "product": info.product,
                        "serial_number": info.serial_number,
                        "vid": info.vid,
                        "pid": info.pid,
                        "location": info.location,
                        "interface": info.interface,
                    }
                )
            return ports

        return await anyio.to_thread.run_sync(_collect)

    async def connect(self, config: SerialConnectionConfig) -> dict[str, Any]:
        async with self._state_lock:
            if self._serial:
                await self._close_locked()
            serial_obj = await anyio.to_thread.run_sync(self._open_serial, config)
            self._serial = serial_obj
            self._config = config
            return {
                "status": "connected",
                "port": config.port,
                "config": config.public_dict(),
            }

    async def disconnect(self) -> dict[str, Any]:
        async with self._io_lock:
            async with self._state_lock:
                if not self._serial:
                    return {"status": "disconnected", "message": "串口尚未建立"}
                await self._close_locked()
                return {"status": "disconnected", "message": "串口连接已关闭"}

    async def info(self) -> dict[str, Any]:
        async with self._state_lock:
            open_state = self._serial is not None
            config = self._config.public_dict() if self._config else None
            return {"open": open_state, "config": config}

    async def write(self, request: SerialWriteRequest) -> dict[str, Any]:
        serial_obj, config = await self._require_state()
        payload = request.to_bytes(config)
        async with self._io_lock:
            await self._write_with_autopace(serial_obj, payload, config.autopace)
        return {"bytes_written": len(payload)}

    async def read(self, request: SerialReadRequest) -> dict[str, Any]:
        serial_obj, config = await self._require_state()
        newline = config.encoded_newline()

        def _perform_read() -> bytes:
            original_timeout = serial_obj.timeout
            try:
                if request.timeout is not None:
                    serial_obj.timeout = request.timeout
                if request.until_newline and newline:
                    return serial_obj.read_until(newline, request.max_bytes)
                return serial_obj.read(request.max_bytes)
            finally:
                serial_obj.timeout = original_timeout

        async with self._io_lock:
            data = await anyio.to_thread.run_sync(_perform_read)
        formatted = request.format_bytes(data, config)
        return {
            "bytes_read": len(data),
            "ended_with_newline": bool(newline) and data.endswith(newline),
            "payload": formatted,
        }

    async def flush(self, direction: str = "both") -> dict[str, str]:
        serial_obj, _ = await self._require_state()

        def _flush() -> None:
            if direction in {"in", "input", "both"}:
                serial_obj.reset_input_buffer()
            if direction in {"out", "output", "both"}:
                serial_obj.reset_output_buffer()

        async with self._io_lock:
            await anyio.to_thread.run_sync(_flush)
        return {"status": "flushed", "direction": direction}

    async def set_control_lines(
        self, dtr: bool | None = None, rts: bool | None = None
    ) -> dict[str, bool]:
        serial_obj, _ = await self._require_state()

        def _set() -> tuple[bool, bool]:
            if dtr is not None:
                serial_obj.setDTR(dtr)
            if rts is not None:
                serial_obj.setRTS(rts)
            return serial_obj.dtr, serial_obj.rts

        async with self._io_lock:
            dtr_state, rts_state = await anyio.to_thread.run_sync(_set)
        return {"dtr": dtr_state, "rts": rts_state}

    async def chat(
        self,
        write_request: SerialWriteRequest,
        read_request: SerialReadRequest,
        settle_time: float,
        *,
        wait_for_prompt: str | None = None,
        max_reads: int = 1,
        read_interval: float = 0.0,
    ) -> dict[str, Any]:
        serial_obj, config = await self._require_state()
        payload = write_request.to_bytes(config)
        newline = config.encoded_newline()
        prompt_bytes = (
            wait_for_prompt.encode(read_request.encoding or config.encoding)
            if wait_for_prompt
            else None
        )
        aggregated = bytearray()
        chunks: list[dict[str, Any]] = []
        prompt_found = False

        def _perform_read() -> bytes:
            original_timeout = serial_obj.timeout
            try:
                if read_request.timeout is not None:
                    serial_obj.timeout = read_request.timeout
                if read_request.until_newline and newline:
                    return serial_obj.read_until(newline, read_request.max_bytes)
                return serial_obj.read(read_request.max_bytes)
            finally:
                serial_obj.timeout = original_timeout

        async with self._io_lock:
            await self._write_with_autopace(serial_obj, payload, config.autopace)
            if settle_time > 0:
                await anyio.sleep(settle_time)
            for _ in range(max_reads):
                data = await anyio.to_thread.run_sync(_perform_read)
                aggregated.extend(data)
                chunk_payload = read_request.format_bytes(data, config)
                chunks.append(
                    {
                        "bytes_read": len(data),
                        "ended_with_newline": bool(newline) and data.endswith(newline),
                        "payload": chunk_payload,
                    }
                )
                if not data:
                    break
                if prompt_bytes and not read_request.return_hex:
                    if prompt_bytes in data:
                        prompt_found = True
                        break
                if read_interval > 0:
                    await anyio.sleep(read_interval)

        aggregated_bytes = bytes(aggregated)
        formatted = read_request.format_bytes(aggregated_bytes, config)
        return {
            "bytes_written": len(payload),
            "bytes_read": len(aggregated_bytes),
            "ended_with_newline": bool(newline) and aggregated_bytes.endswith(newline),
            "payload": formatted,
            "chunks": chunks,
            "prompt_found": prompt_found,
        }

    async def _require_state(self) -> tuple[serial.Serial, SerialConnectionConfig]:
        async with self._state_lock:
            if not self._serial or not self._config:
                raise RuntimeError("串口尚未连接，请先调用 connect_serial")
            return self._serial, self._config

    async def _close_locked(self) -> None:
        serial_obj, self._serial, self._config = self._serial, None, None
        if serial_obj:
            await anyio.to_thread.run_sync(serial_obj.close)

    @staticmethod
    def _open_serial(config: SerialConnectionConfig) -> serial.Serial:
        try:
            serial_obj = serial.Serial(
                port=config.port,
                baudrate=config.baudrate,
                bytesize=BYTESIZE_MAP[config.bytesize],
                parity=PARITY_MAP[config.parity],
                stopbits=STOPBITS_MAP[config.stopbits],
                timeout=config.timeout,
                write_timeout=config.write_timeout,
                rtscts=config.rtscts,
                dsrdtr=config.dsrdtr,
                xonxoff=config.xonxoff,
            )
        except SerialException as exc:
            raise RuntimeError(f"无法打开串口 {config.port}: {exc}") from exc

        serial_obj.reset_input_buffer()
        serial_obj.reset_output_buffer()
        if config.dtr is not None:
            serial_obj.setDTR(config.dtr)
        if config.rts is not None:
            serial_obj.setRTS(config.rts)
        return serial_obj

    @staticmethod
    async def _write_with_autopace(
        serial_obj: serial.Serial, payload: bytes, autopace_ms: int
    ) -> None:
        if not payload:
            return
        if autopace_ms <= 0:
            await anyio.to_thread.run_sync(serial_obj.write, payload)
            return

        interval = autopace_ms / 1000.0

        def _write_byte(byte: int) -> None:
            serial_obj.write(bytes([byte]))

        for byte in payload:
            await anyio.to_thread.run_sync(_write_byte, byte)
            await anyio.sleep(interval)

