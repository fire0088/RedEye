@echo off
REM ============================================================
REM  REDEYE one-click launcher (Windows)
REM  Starts the backend server (prints the access password), then
REM  launches the Godot client.
REM ============================================================
cd /d "%~dp0"

echo Starting REDEYE backend (note the password it prints)...
start "REDEYE server" cmd /k python main.py

REM let the server bind + print its password
timeout /t 2 >nul

if exist "%~dp0redeye.exe" (
    REM you exported the client to a standalone .exe -- run it
    start "" "%~dp0redeye.exe"
) else (
    REM no exe yet: open the project directly if Godot is on your PATH
    where godot >nul 2>nul && (
        start "" godot --path "%~dp0godot"
    ) || (
        echo.
        echo Client not started: no redeye.exe found and 'godot' is not on PATH.
        echo Either export the client once ^(Project ^> Export in Godot^),
        echo or install Godot 4.2+ and add it to PATH.
        pause
    )
)
