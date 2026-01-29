# This example file is for builds on Ubunutu 24.04.
# Search for required packages (compiler + libc) with `apt search s390x`
set(CMAKE_C_COMPILER /usr/bin/s390x-linux-gnu-gcc)
set(CMAKE_ASM_COMPILER /usr/bin/s390x-linux-gnu-gcc)
set(CMAKE_CROSS_COMPILING 1)

set(CMAKE_SYSTEM_NAME Linux)

set(CMAKE_SYSROOT /usr/s390x-linux-gnu/usr/)

set(CMAKE_SYSTEM_PROCESSOR "s390x")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(CMAKE_CROSSCOMPILING_EMULATOR "qemu-s390x-static;-L;/usr/s390x-linux-gnu/")
