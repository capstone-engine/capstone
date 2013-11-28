#! /bin/bash

# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013>

function build {
	make clean

	if [ ${CC}x != x ]; then
		make CC=$CC
	else
		make
	fi
}

case "$1" in
  "" ) build;;
  "nix32" ) CFLAGS=-m32 LDFLAGS=-m32 build;;
  "clang" ) CC=clang build;;
  "cross-win32" ) CROSS=i686-w64-mingw32- build;;
  "cross-win64" ) CROSS=x86_64-w64-mingw32- build;;
  "cygwin-mingw32" ) CROSS=i686-pc-mingw32- build;;
  "cygwin-mingw64" ) CROSS=x86_64-w64-mingw32- build;;
  * ) echo "Usage: compile.sh [nix32|clang|cross-win32|cross-win64|cygwin-mingw32|cygwin-mingw64]"; exit 1;;
esac
