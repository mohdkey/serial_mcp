@echo off
setlocal ENABLEDELAYEDEXPANSION

set "_ORIG_CP="
for /f "tokens=2 delims=: " %%F in ('chcp ^| find ":"') do set "_ORIG_CP=%%F"
if defined _ORIG_CP (
    set "_ORIG_CP=!_ORIG_CP: =!"
    chcp 65001 >nul
)

set "EXIT_CODE=0"

cd /d "%~dp0"

set "CONFIG_FILE=%~dp0serial_mcp.config.json"
set "PYTHON_CMD=%PYTHON_EXECUTABLE%"

if not defined PYTHON_CMD (
    if exist "%~dp0.venv\Scripts\python.exe" (
        set "PYTHON_CMD=%~dp0.venv\Scripts\python.exe"
    ) else (
        set "PYTHON_CMD=python"
    )
)

echo [serial-mcp] 配置文件: %CONFIG_FILE%

if exist "%CONFIG_FILE%" (
    call :ASK_DEFAULT
) else (
    echo 尚未检测到配置文件，需要手动输入端口与波特率。
    call :PROMPT_CONFIG
)

:RUN_SERVER
echo.
echo [serial-mcp] 正在启动服务器 (%PYTHON_CMD%) ...
"%PYTHON_CMD%" -m serial_mcp.server
set "EXIT_CODE=%ERRORLEVEL%"
echo.
echo [serial-mcp] 服务器已退出 (code=%EXIT_CODE%)
pause
goto END

:ASK_DEFAULT
echo.
set /p "USE_DEFAULT=是否使用现有配置 (Y/N)? "
if /I "%USE_DEFAULT%"=="Y" (
    goto RUN_SERVER
) else if /I "%USE_DEFAULT%"=="N" (
    call :PROMPT_CONFIG
) else (
    echo 请输入 Y 或 N
    goto ASK_DEFAULT
)
exit /b 0

:PROMPT_CONFIG
echo.
call :PROMPT_PORT
call :PROMPT_BAUD
call :WRITE_CONFIG
goto RUN_SERVER

:PROMPT_PORT
set /p "SERIAL_PORT=请输入串口号 (示例: COM7 或 /dev/ttyUSB0): "
if "%SERIAL_PORT%"=="" (
    echo 串口号不能为空
    goto PROMPT_PORT
)
exit /b 0

:PROMPT_BAUD
set /p "BAUDRATE=请输入波特率 (默认 115200): "
if "%BAUDRATE%"=="" (
    set "BAUDRATE=115200"
    exit /b 0
)
setlocal
set "INPUT=%BAUDRATE%"
set /a "_test=%INPUT%" >nul 2>&1
if errorlevel 1 (
    endlocal
    echo 波特率必须为数字
    set "BAUDRATE="
    goto PROMPT_BAUD
)
endlocal & set "BAUDRATE=%INPUT%"
exit /b 0

:WRITE_CONFIG
echo.
echo [serial-mcp] 正在写入配置...
powershell -NoLogo -NoProfile -Command ^
  "$path = '%CONFIG_FILE%';" ^
  "if (Test-Path $path) {" ^
  "  try { $config = Get-Content $path -Raw | ConvertFrom-Json } catch { $config = @{} }" ^
  "} else { $config = @{} };" ^
  "$config.port = '%SERIAL_PORT%';" ^
  "$config.baudrate = %BAUDRATE%;" ^
  "$json = $config | ConvertTo-Json -Depth 8;" ^
  "Set-Content -Path $path -Encoding UTF8 -Value ($json + [Environment]::NewLine);" ^
  "Write-Host '已更新 ' $path"
if errorlevel 1 (
    echo 无法写入配置，请确认 PowerShell 可用。
    set "EXIT_CODE=1"
    pause
    goto END
)
exit /b 0

:END
if defined _ORIG_CP chcp %_ORIG_CP% >nul
exit /b %EXIT_CODE%

