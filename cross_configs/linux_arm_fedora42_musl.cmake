# This example file is for ARMv7 cross builds on Fedora 42.
# The toolchain used is https://musl.cc/armv7m-linux-musleabi-cross.tgz
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)
set(CMAKE_C_COMPILE_OPTIONS_SYSROOT "--sysroot=")
set(CMAKE_CXX_COMPILE_OPTIONS_SYSROOT "--sysroot=")

set(TOOLCHAIN_DIR /home/user/toolchains/armv7m-linux-musleabi-cross/)
set(CMAKE_C_COMPILER   ${TOOLCHAIN_DIR}/bin/armv7m-linux-musleabi-gcc)
set(CMAKE_ASM_COMPILER ${TOOLCHAIN_DIR}/bin/armv7m-linux-musleabi-gcc)
set(CMAKE_CROSS_COMPILING 1)

set(CMAKE_SYSROOT /home/user/toolchains/armv7m-linux-musleabi-cross/armv7m-linux-musleabi/)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(CMAKE_CROSSCOMPILING_EMULATOR qemu-arm-static;-L;${CMAKE_SYSROOT})
