This documentation explains how to compile Capstone for:
- Windows CE 7, a.k.a, [Windows Embedded Compact 7](https://www.microsoft.com/windowsembedded/en-us/windows-embedded-compact-7.aspx), on [ARMv7](http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0406c/index.html).
- Windows CE 8, a.k.a, [Windows Embedded Compact 2013](https://www.microsoft.com/windowsembedded/en-us/windows-embedded-compact-2013.aspx), on [ARMv7](http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0406c/index.html).

To build Capstone for a different platform, please refer to `BUILDING.md`.

# Prerequisites

We support the following scenario regarding the build machine:
- Build running on Microsoft Windows.
- The C Software Develepment Kit of the target Windows CE **device** installed.
- Only for Windows CE 7:
  - C compiler toolchain installed, targeting **Windows Embedded Compact 7** on **ARMv7**.  We recommend the toolchain provided with [Windows Embedded Compact 7 toolkit](https://msdn.microsoft.com/en-us/library/jj200349%28v=winembedded.70%29.aspx), as the toolchain originally provided with **Visual Studio 2008** is relatively old.

Before building Capstone for Windows CE 7 (respectively, Windows CE 8), the build script `windowsce/make_windowsce7-armv7.bat` (respectively, `windowsce/make_windowsce8-armv7.bat`) needs to be modified. The variables specified in the rest of this section are set in this script file.

# Toolchain specification

The following information need to be specified in the build script in order to perform the build:
- `set WINCE_TOOLCHAIN_ROOT=` is the path of the root directory of the Windows CE toolchain. To build for Windows CE 7, this should be set to the Windows Embedded Compact 7 toolchain. To build for Windows CE 8, this should be set to the device toolchain.
Examples:
  - For Windows CE 7:
  ```bat
  set WINCE_TOOLCHAIN_ROOT=C:\WINCE700\sdk
  ```
  - For Windows CE 8:
  ```bat
  set WINCE_TOOLCHAIN_ROOT=C:\Windows_CE_Tools\SDKs\SDK_HW90270\Sdk
  ```

- `set TOOLCHAIN=` is a semicolon-separated list of the paths of the directories containing the binaries of the Windows CE toolchain.
For example:
```bat
set TOOLCHAIN=%WINCE_TOOLCHAIN_ROOT%\Bin\i386\Arm;%WINCE_TOOLCHAIN_ROOT%\Bin\i386
```

- `set INCLUDE=` is a semicolon-separated list of the paths of the directories containing the C header files of the Windows CE device SDK. To build for Windows CE 7, this should also include the directories containing the C header files of the Windows Embedded Compact 7 toolchain.
Examples:
  - For Windows CE 7:
  ```bat
  set INCLUDE=C:\Program Files (x86)\Windows CE Tools\SDKs\Symbol MC3200c70 Windows CE 7.0 PSDK\Include\Armv4i;C:\WINCE700\public\common\sdk\inc
  ```
  - For Windows CE 8:
  ```bat
  set INCLUDE=%WINCE_TOOLCHAIN_ROOT%\Inc;%WINCE_TOOLCHAIN_ROOT%\crt\Include
  ```

- `set LIBPATH=` is a semicolon-separated list of the paths of the directories containing the library (i.e., `.LIB`) files of the Windows CE 7 device SDK.
Examples:
  - For Windows CE 7:
  ```bat
  set LIBPATH=C:\Program Files (x86)\Windows CE Tools\SDKs\Symbol MC3200c70 Windows CE 7.0 PSDK\Lib\ARMv4I
  ```
  - For Windows CE 8:
  ```bat
  set LIBPATH=%WINCE_TOOLCHAIN_ROOT%\Lib\ARMV7\retail;%WINCE_TOOLCHAIN_ROOT%\Crt\Lib\ARM
  ```

- `set LIBS=` is a space-separated list of linker directives controlling library search.
Examples:
  - For Windows CE 7:
  ```bat
  set LIBS=-nodefaultlib:oldnames.lib -nodefaultlib:libcmtd.lib -nodefaultlib:libcmt.lib coredll.lib corelibc.lib
  ```
  - For Windows CE 8:
  ```bat
  set LIBS=coredll.lib
  ```

# Capstone binary format

By default, the build script produces a **dynamic link library** (i.e., `.DLL`). In order to produce a **static library** (i.e., `.LIB`) instead, the `SHARED` variable needs to be set to `0`, i.e.:
```bat
set SHARED=0
```

# Architectures supported at runtime

Capstone supports the following architectures: ARM, ARM64 (AArch64), M68K, MIPS, PowerPC, Sparc, SystemZ, x86 and XCore. However, Capstone can be configured in order to select which architectures need to be supported **at runtime**. This is controlled via the variable `DISASM_ARCH_LIST`, which is a space-separated list that is a combination of the following names:
- `ARM`
- `ARM64`
- `M68K`
- `MIPS`
- `POWERPC`
- `SPARC`
- `SYSTEMZ`
- `X86`
- `XCORE`.

By default, `DISASM_ARCH_LIST` includes support for **all** architectures supported by Capstone.
For example:
```bat
set DISASM_ARCH_LIST=ARM ARM64 X86
```
will produce a Capstone binary that supports the following architectures: ARM, ARM64 and x86.

## Features customization

Capstone has a list of features that can be controlled when needed. Each feature is controlled through setting a variable from the following list:

- In order to produce a smaller binary that provides a **subset** of the features of Capstone, but still supports all the selected architectures, please specify the following:
  ```bat
  set DIET_MODE=1
  ```
  By default, this variable is set to `0`.

- By default, Capstone uses the default system-provided **dynamic memory management** functions (e.g., `malloc()`, `realloc()`, `free()`) for its internal memory management. However, Capstone can instead be configured to call **custom** memory management functions provided by client applications. In order to enable this behavior, set the following:
  ```bat
  set USE_SYS_DYN_MEM=0
  ```

- In order to produce a **smaller** Capstone binary, support for the `x86` architecture can be more **limited**. In order to do so, set the following:
  ```bat
  set X86_REDUCE=1
  ```
  By default, this is set to `0`.

- If the **AT&T** disassembly style of the `x86` architecture is never needed at runtime, then disabling support for it can produce a **smaller** Capstone binary. To do this, please set the following:
  ```bat
  set X86_ATT_DISABLE=1
  ```
  By default, this is set to `0`.

Please refer to `docs/README` for more details on these features.
