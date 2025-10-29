# This example file is for build on Fedora 42.
# Search for required packages with `dnf search s390x`

# Bug of cmake not passing sysroot early enough
# https://stackoverflow.com/questions/36195791/cmake-missing-sysroot-when-cross-compiling
set(CMAKE_C_COMPILE_OPTIONS_SYSROOT "--sysroot=")
set(CMAKE_CXX_COMPILE_OPTIONS_SYSROOT "--sysroot=")


set(CMAKE_C_COMPILER /usr/bin/s390x-linux-gnu-gcc)
set(CMAKE_ASM_COMPILER /usr/bin/s390x-linux-gnu-gcc)
set(CMAKE_CROSS_COMPILING 1)

set(CMAKE_SYSROOT /usr/s390x-redhat-linux/sys-root/fc42/)
set(CMAKE_FIND_ROOT_PATH /usr/s390x-redhat-linux/sys-root/fc42/)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(CMAKE_CROSSCOMPILING_EMULATOR "qemu-s390x-static;-L;${CMAKE_SYSROOT}/usr/")
