@echo off
if "%PROCESSOR_ARCHITECTURE%" EQU "x86" (
    set YARAAPP=%~dp0yara\yara32.exe
) else (
    set YARAAPP=%~dp0yara\yara64.exe
)
set YARACAPP=%~dp0yara\yarac32.exe
set YARARULES=%~dp0rules
"%~dp0yarchk.exe" -c2
IF %errorlevel% NEQ 0 (
    pause
    exit 1
)

:: Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges. Continuing...
    goto :RUN_AS_ADMIN
) else (
    echo Not running as administrator.
    echo Press any key to continue, or close the window to exit...
    pause >nul
    echo User chose to continue. Running without administrator privileges...
    goto :RUN_WITHOUT_ADMIN
)

:RUN_AS_ADMIN
:RUN_WITHOUT_ADMIN

"%~dp0yarchk.exe"
pause
exit /b
