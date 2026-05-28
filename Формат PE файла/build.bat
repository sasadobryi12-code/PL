@echo off
chcp 65001 >nul
setlocal

cd /d "%~dp0"

:: Поиск компилятора Visual Studio
set "CL_PATH="
for %%I in (
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
) do (
    if exist %%I (
        call %%I >nul 2>&1
        set CL_FOUND=1
        goto :compile_msvc
    )
)

:: MinGW g++
where g++ >nul 2>&1
if %ERRORLEVEL%==0 (
    echo [build] g++ pe_parser.cpp -o pe_parser.exe
    g++ -std=c++17 -O2 -Wall -o pe_parser.exe pe_parser.cpp
    goto :done
)

echo Ошибка: не найден cl.exe и g++.
echo Установите Visual Studio (C++) или MinGW-w64 и повторите build.bat
exit /b 1

:compile_msvc
    echo [build] cl pe_parser.cpp
cl /nologo /EHsc /std:c++17 /utf-8 /O2 /Fe:pe_parser.exe pe_parser.cpp
if errorlevel 1 exit /b 1

:done
if exist pe_parser.exe (
    chcp 65001 >nul
    echo.
    echo === PE2.exe ^(как на примере^) ===
    pe_parser.exe files\PE2.exe
)
endlocal
