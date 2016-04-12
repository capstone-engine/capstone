@echo off

rem ***************************************************************************
rem *                       VARIABLES TO SET FOR BUILDING                     *
rem ***************************************************************************

set WINCE_TOOLCHAIN_ROOT=C:\Windows_CE_Tools\SDKs\SDK_HW90270\Sdk
set TOOLCHAIN=%WINCE_TOOLCHAIN_ROOT%\Bin\i386\Arm;%WINCE_TOOLCHAIN_ROOT%\Bin\i386
set INCLUDE=%WINCE_TOOLCHAIN_ROOT%\Inc;%WINCE_TOOLCHAIN_ROOT%\crt\Include
set LIBPATH=%WINCE_TOOLCHAIN_ROOT%\Lib\ARMV7\retail;%WINCE_TOOLCHAIN_ROOT%\Crt\Lib\ARM
set LIBS=coredll.lib

rem ***************************************************************************
rem *                           CAPSTONE CONFIGURATION                        *
rem ***************************************************************************

set SHARED=1
set DIET_MODE=0
set USE_SYS_DYN_MEM=1
set X86_REDUCE=0
set X86_ATT_DISABLE=0
set DISASM_ARCH_LIST=ARM ARM64 M68K MIPS POWERPC SPARC SYSZ X86 XCORE

rem ***************************************************************************
rem *                              SANITY CHECKS                              *
rem ***************************************************************************

setlocal ENABLEDELAYEDEXPANSION

if "%WINCE_TOOLCHAIN_ROOT%"=="" goto check_dir_exist_WINCE_TOOLCHAIN_ROOT
if not exist "%WINCE_TOOLCHAIN_ROOT%" goto check_dir_exist_WINCE_TOOLCHAIN_ROOT

if "%TOOLCHAIN%"=="" goto check_dir_exist_TOOLCHAIN

set CC=
set LD=
set AR=
for /f "tokens=1-8 delims=;" %%a in ("%TOOLCHAIN%") do (
  for %%i in (%%a %%b %%c %%d %%e %%f %%g %%h) do (
    if not "%%i"=="" (
      if not exist "%%i" goto check_dir_exist_TOOLCHAIN
      if "%CC%"=="" if exist "%%i\cl.exe" set CC=%%i\cl.exe
      if "%LD%"=="" if exist "%%i\link.exe" set LD=%%i\link.exe
      if "%AR%"=="" if exist "%%i\lib.exe" set AR=%%i\lib.exe
    )
  )
)

if "%CC%"=="" goto check_dir_exist_CC_LD_AR
if "%LD%"=="" goto check_dir_exist_CC_LD_AR
if "%AR%"=="" goto check_dir_exist_CC_LD_AR

if "%INCLUDE%"=="" goto check_dir_exist_INCLUDE

set WINDOWS_H=

set INCLUDE_SC=%INCLUDE%
set INCLUDE=
for /f "tokens=1-8 delims=;" %%a in ("%INCLUDE_SC%") do (
  for %%i in ("%%a" "%%b" "%%c" "%%d" "%%e" "%%f" "%%g" "%%h") do (
    if not %%i=="" (
      set INCLUDE=!INCLUDE! -I %%i
    )
  )
)

if "%LIBPATH%"=="" goto check_dir_exist_LIBPATH

set LIBPATH_SC=%LIBPATH%
set LIBPATH=
for /f "tokens=1-8 delims=;" %%a in ("%LIBPATH_SC%") do (
  for %%i in ("%%a" "%%b" "%%c" "%%d" "%%e" "%%f" "%%g" "%%h") do (
    if not %%i=="" (
      set LIBPATH=!LIBPATH! -libpath:%%i
    )
  )
)

rem ***************************************************************************
rem *                            COMPILATION OPTIONS                          *
rem ***************************************************************************

set OS=windowsce
set OS_VERSION=8.0
set OS_VERSION_NUMBER=0x800
set LIBARCH=arm
set MACH=ARM

for /f "delims=" %%i in ('cd') do set THIS_DIR=%%i

set SOURCES_ROOT=%THIS_DIR%\..
set TARGET_DIR=%THIS_DIR%\bin\%OS%_%OS_VERSION%_%LIBARCH%

for /f "tokens=3" %%i in ('findstr /c:"#define CS_API_MAJOR" "%SOURCES_ROOT%\include\capstone\capstone.h"') do set CS_API_MAJOR=%%i
for /f "tokens=3" %%i in ('findstr /c:"#define CS_API_MINOR" "%SOURCES_ROOT%\include\capstone\capstone.h"') do set CS_API_MINOR=%%i

set TARGET_VERSION=%CS_API_MAJOR%.%CS_API_MINOR%
set TAREGET_NAME=capstone-%TARGET_VERSION%

set CPPFLAGS=-D LIBARCH_%LIBARCH% -D LIBARCH=L\"%LIBARCH%\"
set CPPFLAGS=%CPPFLAGS% -D _CRT_SECURE_NO_DEPRECATE -D _WINDOWS -D WINVER=%OS_VERSION_NUMBER% -D UNDER_CE=%OS_VERSION_NUMBER% -D _WIN32_WCE=%OS_VERSION_NUMBER% -D WINCE -D _UNICODE -D UNICODE -D STANDARDSHELL_UI_MODEL -D _USE_MATH_DEFINES -D ARM -D _ARM -D _ARM_ -D __ARM_ARCH_7__ -D __ARM_ARCH_7A__ -D __VFP_FP__=1

for %%a in (%DISASM_ARCH_LIST%) do set CPPFLAGS=!CPPFLAGS! -D CAPSTONE_HAS_%%a

if %SHARED%==0 (
  set CPPFLAGS=!CPPFLAGS! -D CAPSTONE_STATIC -D LIB_EXT=L\".lib\"
) else (
  set CPPFLAGS=!CPPFLAGS! -D CAPSTONE_SHARED -D LIB_EXT=L\".dll\"
)

if not %USE_SYS_DYN_MEM%==0 ( set CPPFLAGS=!CPPFLAGS! -D CAPSTONE_USE_SYS_DYN_MEM )
if not %DIET_MODE%==0 ( set CPPFLAGS=!CPPFLAGS! -D CAPSTONE_DIET )
if not %X86_REDUCE%==0 ( set CPPFLAGS=!CPPFLAGS! -D CAPSTONE_X86_REDUCE )
if not %X86_ATT_DISABLE%==0 ( set CPPFLAGS=!CPPFLAGS! -D CAPSTONE_X86_ATT_DISABLE )

set INCLUDE=-I %SOURCES_ROOT%\include -I %SOURCES_ROOT% %INCLUDE%

set CFLAGS=%CPPFLAGS% %INCLUDE% -nologo -MP -Zi -MT -Oi -GS -fp:fast -Oy- -W3 -WX

set LDFLAGS=-nologo -debug -incremental:no -manifest:no -version:%TARGET_VERSION% -machine:%MACH% -subsystem:WINDOWSCE,%OS_VERSION% %LIBPATH% %LIBS%

set ARFLAGS=-nologo -machine:%MACH% -subsystem:WINDOWSCE,%OS_VERSION% %LIBPATH% %LIBS%

set SOURCES=
for %%f in (%SOURCES_ROOT%\*.c) do set SOURCES=!SOURCES! %%f
for /d %%a in (%SOURCES_ROOT%\arch\*) do for %%f in (%%a\*.c) do set SOURCES=!SOURCES! %%f

rem ***************************************************************************
rem *                           COMPILATION COMMANDS                          *
rem ***************************************************************************

rd /q /s "%TARGET_DIR%"
md "%TARGET_DIR%"

set PATH=%TOOLCHAIN%;%PATH%

rem %CC% -c %CFLAGS% -D DEBUG -D _DEBUG -Od -Fo"%TARGET_DIR%\\" -Fd"%TARGET_DIR%\%TAREGET_NAME%.pdb" %SOURCES%
%CC% -c %CFLAGS% -D NDEBUG -Ox -Fo"%TARGET_DIR%\\" -Fd"%TARGET_DIR%\%TAREGET_NAME%.pdb" %SOURCES%
if errorlevel 1 goto compilation_failed

if %SHARED%==0 (
  %AR% -out:%TARGET_DIR%\%TAREGET_NAME%.lib %ARFLAGS% %TARGET_DIR%\*.obj
) else (
  %LD% -dll -out:%TARGET_DIR%\%TAREGET_NAME%.dll -map:"%TARGET_DIR%\%TAREGET_NAME%.map" -pdb:"%TARGET_DIR%\%TAREGET_NAME%.pdb" %LDFLAGS% -opt:REF -opt:ICF %TARGET_DIR%\*.obj
)

endlocal
goto done

rem ***************************************************************************
rem *                             ERROR REPORTING                             *
rem ***************************************************************************

:check_dir_exist_WINCE_TOOLCHAIN_ROOT
echo ERROR: WINCE_TOOLCHAIN_ROOT does not specify an existing directory.
goto done

:check_dir_exist_TOOLCHAIN
echo ERROR: TOOLCHAIN does not specify an existing directory.
goto done

:check_dir_exist_CC_LD_AR
echo ERROR: TOOLCHAIN does not specify a valid toolchain directory.
goto done

:check_dir_exist_INCLUDE
echo ERROR: INCLUDE does not specify an existing directory.
goto done

:check_dir_exist_LIBPATH
echo ERROR: LIBPATH does not specify an existing directory.
goto done

:compilation_failed
echo ERROR: Compilation failed.
goto done

:done
pause
