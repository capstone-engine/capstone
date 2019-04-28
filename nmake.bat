:: Capstone disassembler engine (www.capstone-engine.org)
:: Build Capstone libs (capstone.dll & capstone.lib) on Windows with CMake & Nmake
:: By Nguyen Anh Quynh, Jorn Vernee, 2017, 2019

@echo off

set flags="-DCMAKE_BUILD_TYPE=Release -DCAPSTONE_BUILD_STATIC_RUNTIME=ON"

if "%1"=="ARM" set flags=%flags% and " -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_ARM_SUPPORT=ON"
if "%1"=="ARM64" set flags=%flags% and " -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_ARM64_SUPPORT=ON"
if "%1"=="M68K" set flags=%flags% and " -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_M68K_SUPPORT=ON"
if "%1"=="MIPS" set flags=%flags% and " -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_MIPS_SUPPORT=ON"
if "%1"=="PowerPC" set flags=%flags% and " -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_PPC_SUPPORT=ON"
if "%1"=="Sparc" set flags=%flags% and " -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_SPARC_SUPPORT=ON"
if "%1"=="SystemZ" set flags=%flags% and " -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_SYSZ_SUPPORT=ON"
if "%1"=="XCore" set flags=%flags% and " -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_XCORE_SUPPORT=ON"
if "%1"=="x86" set flags=%flags% and " -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_X86_SUPPORT=ON"
if "%1"=="TMS320C64x" set flags=%flags% and " -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_TMS320C64X_SUPPORT=ON"
if "%1"=="M680x" set flags=%flags% and " -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_M680X_SUPPORT=ON"
if "%1"=="EVM" set flags=%flags% and " -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_EVM_SUPPORT=ON"
if "%1"=="MOS65XX" set flags=%flags% and " -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_MOS65XX_SUPPORT=ON"

cmake %flags% -G "NMake Makefiles" ..
nmake

