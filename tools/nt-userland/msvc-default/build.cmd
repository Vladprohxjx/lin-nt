@echo off
setlocal
where cl.exe >nul 2>nul || (
    echo Run this from an x64 Native Tools Command Prompt for Visual Studio. 1>&2
    exit /b 1
)
if not exist build mkdir build
rem Intentionally no custom compiler or linker flags.
cl.exe /nologo /W4 /O2 /Fe:build\hello.exe hello.c
if errorlevel 1 exit /b %errorlevel%
echo Built build\hello.exe with the default MSVC linker profile.
