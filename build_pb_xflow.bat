@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

REM ============================================================================
REM PB X-Flow engine: pb_xflow.exe (MSVC x64)
REM Optional: set PB_XFLOW_SIGN_PASSWORD / PFX_PWD
REM Usage: build_pb_xflow.bat [nopause]
REM ============================================================================

if not defined PB_XFLOW_SIGN_PASSWORD set "PB_XFLOW_SIGN_PASSWORD=www.linkleading.com"
if not defined PFX_FILE set "PFX_FILE=my_signature.pfx"
if not defined PFX_PWD if defined PB_XFLOW_SIGN_PASSWORD set "PFX_PWD=%PB_XFLOW_SIGN_PASSWORD%"
if not defined SIGNTOOL (
    for %%I in ("%ProgramFiles(x86)%") do set "SIGNTOOL=%%~sI\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
)
if not defined PB_XFLOW_ARCH set "PB_XFLOW_ARCH=AVX"

set "VCVARS="
if exist "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat"
if not defined VCVARS if exist "C:\Program Files\Microsoft Visual Studio\18\Professional\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Professional\VC\Auxiliary\Build\vcvarsall.bat"
if not defined VCVARS if exist "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
if not defined VCVARS if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
if not defined VCVARS if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat"
if not defined VCVARS if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
if not defined VCVARS if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat"

if not defined VCVARS (
  where vswhere >nul 2>&1
  if !errorlevel! equ 0 (
    for /f "usebackq tokens=*" %%i in (`vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2^>nul`) do (
      if exist "%%i\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARS=%%i\VC\Auxiliary\Build\vcvarsall.bat"
    )
  )
)

if not defined VCVARS (
  echo [ERR] vcvarsall.bat not found.
  if /i not "%~1"=="nopause" pause
  exit /b 1
)

echo [INFO] VCVARS: %VCVARS%
echo [INFO] ARCH: %PB_XFLOW_ARCH%  CRT: /MT
call "%VCVARS%" x64
if errorlevel 1 (
  echo [ERR] vcvars failed
  if /i not "%~1"=="nopause" pause
  exit /b 1
)

echo [1/3] rc resource_xflow.rc
rc.exe /nologo /fo resource_xflow.res resource_xflow.rc
if errorlevel 1 (
  echo [ERR] rc.exe failed
  if /i not "%~1"=="nopause" pause
  exit /b 1
)

echo [2/3] cl pb_xflow.c + xxhash
cl.exe /nologo /std:c11 /MT /O2 /Ob2 /Oi /Ot /Oy /GL /Gy /arch:%PB_XFLOW_ARCH% /W3 /utf-8 /DNDEBUG /D_WIN32_WINNT=0x0602 /Fe:pb_xflow.exe ^
  pb_xflow.c external/xxhash/xxhash.c resource_xflow.res ^
  /link /SUBSYSTEM:CONSOLE /LTCG /OPT:REF /OPT:ICF /STACK:8388608 /ENTRY:wmainCRTStartup ^
  advapi32.lib shell32.lib shlwapi.lib ole32.lib user32.lib pdh.lib winmm.lib ^
  crypt32.lib psapi.lib mpr.lib synchronization.lib vssapi.lib

if errorlevel 1 (
  echo [ERR] cl.exe failed
  if /i not "%~1"=="nopause" pause
  exit /b 1
)

echo [OK] pb_xflow.exe

echo [3/3] optional sign pb_xflow.exe
if not exist "%PFX_FILE%" goto after_sign
if not defined PFX_PWD goto after_sign
if not exist "%SIGNTOOL%" goto sign_no_tool
"%SIGNTOOL%" sign /f "%PFX_FILE%" /p "%PFX_PWD%" /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /d "PB X-Flow" /v pb_xflow.exe
if errorlevel 1 goto sign_warn
"%SIGNTOOL%" verify /pa /v pb_xflow.exe
if errorlevel 1 (
  echo NOTE: verify failed - normal for self-signed cert.
) else (
  echo [OK] sign+verify OK.
)
goto after_sign
:sign_no_tool
echo [SKIP] signtool missing: %SIGNTOOL%
goto after_sign
:sign_warn
echo [WARN] sign failed - try without timestamp...
"%SIGNTOOL%" sign /f "%PFX_FILE%" /p "%PFX_PWD%" /fd SHA256 /d "PB X-Flow" /v pb_xflow.exe
goto after_sign
:after_sign

echo Done.
if /i not "%~1"=="nopause" pause
endlocal
exit /b 0
