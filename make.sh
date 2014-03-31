#!/bin/sh

# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013>

# Note: to cross-compile "nix32" on Linux, package gcc-multilib is required.

pathfor() {
	for A in `echo ${PATH} | sed -e 's,:, ,g'` ; do
		if [ -x "$A/$1" ]; then
			echo "$A"
			return;
		fi
	done
}

build() {
	${MAKE} clean

	if [ ${CC}x != x ]; then
		${MAKE} CC=$CC
	else
		${MAKE}
	fi
}

install() {
	if [ ${CC}x != x ]; then
		${MAKE} CC=$CC install
	else
		${MAKE} install
	fi
}

MAKE=make
if [ "$(uname)" = "SunOS" ]; then
	export MAKE=gmake
	export INSTALL_BIN=ginstall
	export CC=gcc
fi

if [ -n "`pathfor gmake`" ]; then
	export MAKE=gmake
	export PREFIX=/usr/local
else
	export PREFIX=/usr
fi

if [ "$(uname)" = Darwin ]; then
	for a in brew port ; do
		SDIR=`pathfor $a`
		if [ -n "${SDIR}" ]; then
			PKGCFGDIR="${SDIR}/../lib/pkgconfig"
			break;
		fi
	done
	export PKGCFGDIR
fi

case "$1" in
  "" ) build;;
  "default" ) build;;
  "install" ) install;;
  "uninstall" ) ${MAKE} uninstall;;
  "nix32" ) CFLAGS=-m32 LDFLAGS=-m32 build;;
  "cross-win32" ) CROSS=i686-w64-mingw32- build;;
  "cross-win64" ) CROSS=x86_64-w64-mingw32- build;;
  "cygwin-mingw32" ) CROSS=i686-pc-mingw32- build;;
  "cygwin-mingw64" ) CROSS=x86_64-w64-mingw32- build;;
  "clang" ) CC=clang build;;
  "gcc" ) CC=gcc build;;
  * ) echo "Usage: make.sh [nix32|cross-win32|cross-win64|cygwin-mingw32|cygwin-mingw64|clang|gcc|install|uninstall]"; exit 1;;
esac
