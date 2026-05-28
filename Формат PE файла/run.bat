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
    echo Запуск на PE2.exe ^(короткий вывод^):
    echo.
    pe_parser.exe files\PE2.exe
    exit /b 0
)

pe_parser.exe %*
