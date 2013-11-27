#! /bin/bash

# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013>

case "$1" in
  "" ) make clean; make;;
  "nix32" ) make clean; CFLAGS=-m32 LDFLAGS=-m32 make;;
  "clang" ) make clean; make CC=clang;;
  "win32" ) make clean; make CROSS=i686-w64-mingw32- windows;;
  "win64" ) make clean; make CROSS=x86_64-w64-mingw32- windows;;
  * ) echo "Usage: compile.sh [nix32|clang|win32|win64]"; exit 1;;
esac
