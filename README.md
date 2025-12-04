# serial-mcp

一个面向 Cursor 的串口调试 Model Context Protocol (MCP) 服务器，借鉴 [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 的批量工具设计理念，让 IDE 可以通过统一的工具接口管理串口连接并与嵌入式目标交互。

## 功能特性

- 枚举本机串口，并返回 VID/PID、厂商等详细信息
- 用户手动配置端口、波特率、数据位、校验位、停止位及编码
- 在 MCP 会话内安全复用串口，提供读写、缓冲刷新等常见操作
- 兼容 Cursor MCP 设置，可通过 `mcp.json` 或设置面板一键接入

## 安装

```powershell
cd D:\serial_mcp
pip install -e .
```

（也可以使用 `uv pip install -e .` 以获得更快的安装体验。）

## 运行

### 方式一：直接运行

```powershell
serial-mcp
# 或显式指定解释器
python -m serial_mcp.server
```

### 方式二：使用 `start-serial-mcp.bat`（Windows）

```powershell
start-serial-mcp.bat
```

- 每次启动都会提示“是否使用现有配置”。输入 `N` 时，脚本会引导你填写串口号与波特率；若 `serial_mcp.config.json` 不存在，会先创建后写入。
- 如需固定 Python 解释器，可在运行前设置 `PYTHON_EXECUTABLE=C:\Path\to\python.exe`，否则脚本会优先使用 `.venv\Scripts\python.exe`，最后回退到系统的 `python`。

无论哪种方式，服务器都会监听来自 MCP 客户端（如 Cursor）的标准输入输出连接，无需额外端口。

### 通过 JSON 预设端口与波特率

启动目录下若存在 `serial_mcp.config.json`（或通过环境变量 `SERIAL_MCP_CONFIG` 指向的文件），`connect_serial` 会自动读取其中的默认配置，省去每次手动输入端口/波特率。例如：

```json
{
  "port": "COM7",
  "baudrate": 230400,
  "bytesize": 8,
  "parity": "N",
  "stopbits": 1,
  "newline": "\\r\\n",
  "rtscts": false,
  "dsrdtr": false,
  "xonxoff": false,
  "dtr": true,
  "rts": true,
  "autopace": 20
}
```

可使用 `serial_config_info` 查看当前配置，或调用 `reload_serial_config` 在运行时重新加载（可传入新的路径）。

### 终端提示 Cursor `mcp.json` 配置

首次运行 `serial-mcp` 会在终端打印一段 JSON 模板，指明 Cursor `mcp.json` 的默认路径，方便复制粘贴：

- Windows: `%APPDATA%\Cursor\User\mcp.json`
- macOS: `~/Library/Application Support/Cursor/User/mcp.json`
- Linux: `~/.config/Cursor/User/mcp.json`

输出示例：

```json
{
  "mcpServers": {
    "serial-mcp": {
      "command": "C:\\Python313\\python.exe",
      "args": ["-m", "serial_mcp.server"],
      "timeout": 1800,
      "disabled": false
    }
  }
}
```

若文件已存在且包含 `serial-mcp` 条目，则不会重复提示。可通过环境变量 `SERIAL_MCP_CURSOR_CONFIG` 指向自定义 `mcp.json` 位置。

## 在 Cursor 中配置

1. 打开 Cursor → Settings → MCP Servers。
2. 点击 “Add New Server”，选择 “Custom Command”。
3. Command 填写：

   ```
   pipx run serial-mcp
   ```

   如果使用本地源码，可换成：

   ```
   python -m serial_mcp.server
   ```

4. 保存后即可在 MCP 面板里看到 `serial-mcp`，并可以直接调用工具。

也可以在 `%APPDATA%\Cursor\User\mcp.json` 中手动添加条目：

```json
{
  "serial-mcp": {
    "command": "uv",
    "args": ["run", "serial-mcp"]
  }
}
```

## 可用工具

| 工具名 | 说明 |
| --- | --- |
| `list_serial_ports` | 返回所有可用串口及其基础信息。 |
| `connect_serial` | 建立或更新串口连接，可指定端口/波特率/校验等参数。 |
| `disconnect_serial` | 关闭当前串口。 |
| `serial_connection_info` | 查看当前连接状态与配置。 |
| `write_serial` | 写入文本或十六进制数据，可选择是否自动追加换行。 |
| `read_serial` | 读取指定字节数或直到换行，可返回文本或十六进制字符串。 |
| `flush_serial_buffers` | 清空输入/输出缓冲。 |
| `serial_cli_command` | 一次性写入命令并等待响应，可配置等待时间和返回格式。 |
| `set_serial_control_lines` | 运行中动态拉高/拉低 DTR、RTS 控制线。 |
| `serial_config_info` | 查看当前 JSON 配置文件路径及内容。 |
| `reload_serial_config` | 重新加载配置文件，可切换到新的 JSON。 |

所有工具均返回结构化 JSON，便于在 Cursor 响应面板中阅读或进一步处理。

### CLI 交互示例

如果目标设备有 CLI 接口，可使用 `serial_cli_command` 实现“发送 + 等待”一体化操作，例如：

```
tool: serial_cli_command
args:
  command: "help"
  append_newline: true
  settle_time: 0.5
  max_bytes: 2048
  until_newline: false
  timeout: 2
  wait_for_prompt: "aic>"
  max_reads: 4
```

这会写入 `help\n`，等待 0.5 秒后开始读取，最多读取 4 个块（每块 2 KB），在检测到 `aic>` 提示符或超时后返回结果。若想只写不读，将 `read_response` 设为 `false` 即可。

> 工具会先自动发送一次“空回车”进行唤醒（可通过 `wake_before_command=false` 关闭），然后再发送真正的 `command`。随后它会在 `wait_for_prompt`（默认 `aic>`）出现前持续读取多次，最多 `max_reads` 次，每次之间可通过 `read_interval` 设定停顿。不传 `command` 参数时，相当于只发送回车。

> v0.1.1 起，`serial_cli_command` 会根据 `terminal_mode` 自动决定是否清空串口输入缓冲、以及是否追加 `echo __SERIAL_MCP_DONE__` 作为完成标记：  
> - `terminal_mode="auto"`（默认）会按照常规 Linux shell 的习惯在命令后附加 `echo`，并在执行前调用 `flush(input)`，保证输出不被背景日志干扰。  
> - `terminal_mode="uboot"` 会发送 `Ctrl+C`+回车唤醒 U-Boot，默认仅依赖提示符（`U-Boot>`）而不开启完成标记，也不会丢弃已有输出，方便观察启动日志。  
> - 若目标环境不支持 `echo` 或你希望保留原始日志，可显式将 `append_done_marker=false`、`discard_pending_input=false`。也可以通过 `done_marker` 自定义标记文字。

> 自动模式下若尚未识别终端种类，工具会先行发送 `?`、`h`、`help`、`whoami`、`ls` 等探测命令：若返回包含 “U-Boot/=>/unknown command” 等特征，则视为 U-Boot；若出现 `root@`、`drwx`、`/bin`、`uid=` 等字样，则判定为常规 shell。探测只进行一次，并缓存结果直到串口重新连接。

> 若命令输出中出现 `login:`、`password:`、`passwd:` 等关键词，工具会在结果里附带 `auth_prompt_detected=true` 以及提示字符串，提醒你输入账号/密码并重新执行相关命令。

若目标设备的 CLI 对输入节奏敏感，可在连接参数或 `serial_mcp.config.json` 中设置 `autopace`（单位毫秒），该值会在写入每个字节后自动等待指定时间。

对于 U-Boot 或其他非标准 shell，可传入：

```
tool: serial_cli_command
args:
  terminal_mode: "uboot"
  command: "printenv"
  max_bytes: 4096
  max_reads: 6
```

- `terminal_mode` 会自动发送 `Ctrl+C` 以打断自动启动，并将默认提示符改为 `U-Boot>`。若提示符不包含 “U-Boot”，也可以依赖内置探测命令自动识别类型。  
- 仍可搭配 `wait_for_prompt` 覆盖提示符，或手动打开完成标记/缓冲刷新逻辑以满足特定固件交互。

## 配置建议

- Windows 平台串口名形如 `COM12`，Linux/macOS 分别为 `/dev/ttyUSB*`、`/dev/tty.*`。
- `newline` 参数支持 `\n`、`\r`、`\r\n`、`\x00` 等转义；传空字符串可禁用。
- 若目标设备依赖硬件/软件流控，可在配置中启用 `rtscts`、`dsrdtr`、`xonxoff`，或使用 `set_serial_control_lines` 动态调整 DTR/RTS。
- CLI 对输入节奏敏感时，可设置 `autopace`（0~1000 ms）让每个字节之间延时，模拟人工敲击或终端宏行为。
- `return_hex=true` 时可用于调试非文本协议。
- 如果需要更高的吞吐，可将 `timeout` 设为 `0` 实现“尽快返回”。

## 故障排查

- “Port busy” 类错误通常是因为串口被占用，请先关闭其他串口工具。
- 若 Cursor 提示工具超时，可在设置中增大 MCP 请求超时时间，或降低 `max_bytes`。
- 遇到编码异常时，使用 `return_hex=true` 获取原始数据，再选择合适编码。

## 许可证

基于 MIT 协议发布。

