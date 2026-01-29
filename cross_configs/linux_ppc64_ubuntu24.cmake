# This example file is for builds on Ubunutu 24.04.
# Search for required packages (compiler + libc) with `apt search PPC64`
# sudo apt install gcc-powerpc64-linux-gnu g++-powerpc64-linux-gnu binutils-powerpc64-linux-gnu libc6-dev-ppc64-cross qemu-user-static
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR ppc64)

set(CMAKE_C_COMPILER   powerpc64-linux-gnu-gcc)
set(CMAKE_ASM_COMPILER powerpc64-linux-gnu-gcc)
set(CMAKE_CROSS_COMPILING 1)

set(CMAKE_SYSROOT /usr/powerpc64-linux-gnu/usr)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(CMAKE_CROSSCOMPILING_EMULATOR qemu-ppc64-static;-L;/usr/powerpc64-linux-gnu)
