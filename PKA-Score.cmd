@echo off
setlocal EnableExtensions
title PKA Score Inspector
cd /d "%~dp0"

rem ---- locate Python 3 -------------------------------------------------
set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY (
    where python >nul 2>&1 && set "PY=python"
)
if not defined PY (
    echo.
    echo   ERROR: Python 3 was not found in PATH.
    echo   Install it from https://www.python.org/downloads/
    echo   ^(tick "Add python.exe to PATH" during setup^)
    echo.
    pause
    exit /b 1
)

if not "%~1"=="" goto haveargs

echo.
echo   ============================================================
echo    PKA Score Inspector
echo   ============================================================
echo    Drag a .pka or .pkt file onto this window and press Enter,
echo    or paste its full path below.
echo.
set /p "TARGET=  File: "
if not defined TARGET goto done
call :run "%TARGET%"
goto done

:haveargs
for %%F in (%*) do call :run "%%~F"
goto done

:done
rem Python pauses on success. Only pause here if it failed, so the
rem window does not close before the user can read an error.
if errorlevel 1 (
    echo.
    echo   Something went wrong. Press any key to close.
    pause >nul
    exit /b 1
)
exit /b 0

:run
if "%~1"=="" goto :eof
if not exist "%~1" (
    echo.
    echo   ERROR: file not found: %~1
    exit /b 1
)
echo.
%PY% "%~dp0pka_score.py" "%~1"
if errorlevel 1 exit /b 1
goto :eof
