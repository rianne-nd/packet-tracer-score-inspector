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

rem The Python side shows the file picker and the menu. --no-pause keeps it
rem from pausing on its own, so this window owns the single final prompt and
rem never closes before the user can read the output.
if not "%~1"=="" goto have_args

%PY% "%~dp0pka_score.py" --no-pause
set "RC=%ERRORLEVEL%"
goto finish

:have_args
for %%F in (%*) do (
    %PY% "%~dp0pka_score.py" --no-pause "%%~F"
    if errorlevel 1 goto failed
)
set "RC=0"
goto finish

:failed
set "RC=1"

:finish
echo.
if not "%RC%"=="0" (
    echo   The inspector stopped with exit code %RC%.
)
set "DUMMY="
set /p "DUMMY=  Press Enter to close..."
exit /b %RC%
