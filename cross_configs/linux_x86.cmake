# SPDX-FileCopyrightText: 2025 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: LGPL-3.0-only

# Requires the 32bit libc like glibc-devel.i686 libgcc.i686 (Fedora) or similar
# for other distributions.
# This example was tested on Fedora 43

# the name of the target operating system
set(CMAKE_SYSTEM_NAME Linux)

# which compilers to use for C and C++
set(CMAKE_C_COMPILER gcc)
set(CMAKE_C_FLAGS -m32)
set(CMAKE_CXX_COMPILER g++)
set(CMAKE_CXX_FLAGS -m32)

# where is the target environment located
set(CMAKE_FIND_ROOT_PATH /)

set(CMAKE_SYSTEM_PROCESSOR "i686")

# search headers and libraries in the target environment
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
