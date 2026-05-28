@echo off
chcp 65001 >nul
cd /d "%~dp0"

set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
    set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
)
if not exist "%VCVARS%" (
    where g++ >nul 2>&1
    if errorlevel 1 (
        echo Не найден компилятор. Установите Visual Studio C++ или MinGW.
        pause
        exit /b 1
    )
    echo [build] g++ pe_parser.cpp console_utf8.cpp
    g++ -std=c++17 -O2 -o pe_parser.exe pe_parser.cpp console_utf8.cpp
    goto :test
)

call "%VCVARS%" >nul
taskkill /f /im pe_parser.exe >nul 2>&1
del pe_parser.exe >nul 2>&1
echo [build] cl pe_parser.cpp console_utf8.cpp
cl /nologo /EHsc /std:c++17 /utf-8 /O2 /Fe:pe_parser.exe pe_parser.cpp console_utf8.cpp
if errorlevel 1 (
    pause
    exit /b 1
)

:test
if not exist pe_parser.exe (
    echo Ошибка сборки.
    pause
    exit /b 1
)

echo.
echo === files\PE1.dll ===
pe_parser.exe files\PE1.dll
