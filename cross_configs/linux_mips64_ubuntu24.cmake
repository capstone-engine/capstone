# This example file is for builds on Ubunutu 24.04.
# Search for required packages (compiler + libc) with `apt search mips64`
# sudo apt install gcc-mips64el-linux-gnuabi64 g++-mips64el-linux-gnuabi64 binutils-mips64el-linux-gnuabi64 libc6-dev-mips64el-cross qemu-user-static
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR mips64el)

set(CMAKE_C_COMPILER   mips64el-linux-gnuabi64-gcc)
set(CMAKE_ASM_COMPILER mips64el-linux-gnuabi64-gcc)
set(CMAKE_CROSS_COMPILING 1)

set(CMAKE_SYSROOT /usr/mips64el-linux-gnuabi64/usr/)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(CMAKE_CROSSCOMPILING_EMULATOR qemu-mips64el-static;-L;/usr/mips64el-linux-gnuabi64/)
