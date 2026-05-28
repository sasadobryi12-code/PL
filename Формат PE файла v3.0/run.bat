@echo off
chcp 65001 >nul
cd /d "%~dp0"

if not exist pe_parser.exe (
    echo Сначала запустите build.bat
    pause
    exit /b 1
)

if "%~1"=="" (
    echo.
    echo Анализ files\PE1.dll ^(импорты как в задании^):
    echo.
    pe_parser.exe files\PE1.dll
    exit /b 0
)

pe_parser.exe %*
