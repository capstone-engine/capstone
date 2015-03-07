#!/bin/sh

# Capstone Disassembly Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015

# Note: to cross-compile "nix32" on Linux, package gcc-multilib is required.

MAKE_JOBS=$((${MAKE_JOBS}+0))
[ ${MAKE_JOBS} -lt 1 ] && \
  MAKE_JOBS=4

# build iOS lib for all iDevices, or only specific device
build_iOS() {
  ${MAKE} clean
  IOS_SDK=`xcrun --sdk iphoneos --show-sdk-path`
  IOS_CC=`xcrun --sdk iphoneos -f clang`
  IOS_CFLAGS="-Os -Wimplicit -isysroot $IOS_SDK"
  IOS_LDFLAGS="-isysroot $IOS_SDK"
  if [ -z "$1" ]; then
    # build for all iDevices
    IOS_ARCHS="armv7 armv7s arm64"
  else
    IOS_ARCHS="$1"
  fi
  CC="$IOS_CC" \
  CFLAGS="$IOS_CFLAGS" \
  LDFLAGS="$IOS_LDFLAGS" \
  LIBARCHS="$IOS_ARCHS" \
    ${MAKE}
}

build() {
  [ "$UNAME" = Darwin ] && LIBARCHS="i386 x86_64"
  ${MAKE} clean
  ${MAKE}
}

install() {
  # Mac OSX needs to find the right directory for pkgconfig
  if [ "$UNAME" = Darwin ]; then
    # we are going to install into /usr/local, so remove old installs under /usr
    rm -rf /usr/lib/libcapstone.*
    rm -rf /usr/include/capstone
    # install into /usr/local
    PREFIX=/usr/local
    if [ "${HOMEBREW_CAPSTONE}" != 1 ]; then
      # find the directory automatically, so we can support both Macport & Brew
      PKGCFGDIR="$(pkg-config --variable pc_path pkg-config | cut -d ':' -f 1)"
    fi
    ${MAKE} install
  else  # not OSX
    test -d /usr/lib64 && ${MAKE} LIBDIRARCH=lib64
    ${MAKE} install
  fi
}

uninstall() {
  # Mac OSX needs to find the right directory for pkgconfig
  if [ "$UNAME" = "Darwin" ]; then
    # find the directory automatically, so we can support both Macport & Brew
    PKGCFGDIR="$(pkg-config --variable pc_path pkg-config | cut -d ':' -f 1)"
    PREFIX=/usr/local
    ${MAKE} uninstall
  else  # not OSX
    test -d /usr/lib64 && LIBDIRARCH=lib64
    ${MAKE} uninstall
  fi
}

if [ "$UNAME" = SunOS ]; then
  [ -z "${MAKE}" ] && MAKE=gmake
  INSTALL_BIN=ginstall
  CC=gcc
fi

if [ -n "`echo "$UNAME" | grep BSD`" ]; then
  MAKE=gmake
  PREFIX=/usr/local
fi

[ -z "${UNAME}" ] && UNAME=$(uname)
[ -z "${MAKE}" ] && MAKE=make
[ -n "${MAKE_JOBS}" ] && MAKE="$MAKE -j${MAKE_JOBS}"
export CC INSTALL_BIN PREFIX PKGCFGDIR LIBDIRARCH LIBARCHS CFLAGS LDFLAGS

case "$1" in
  "" ) build;;
  "default" ) build;;
  "install" ) install;;
  "uninstall" ) uninstall;;
  "nix32" ) CFLAGS=-m32 LDFLAGS=-m32 build;;
  "cross-win32" ) CROSS=i686-w64-mingw32- build;;
  "cross-win64" ) CROSS=x86_64-w64-mingw32- build;;
  "cygwin-mingw32" ) CROSS=i686-pc-mingw32- build;;
  "cygwin-mingw64" ) CROSS=x86_64-w64-mingw32- build;;
  "cross-android" ) CROSS=arm-linux-androideabi- build;;
  "clang" ) CC=clang build;;
  "gcc" ) CC=gcc build;;
  "ios" ) build_iOS;;
  "ios_armv7" ) build_iOS armv7;;
  "ios_armv7s" ) build_iOS armv7s;;
  "ios_arm64" ) build_iOS arm64;;
  * )
    echo "Usage: $0 ["`grep '^  "' $0 | cut -d '"' -f 2 | tr "\\n" "|"`"]"
    exit 1;;
esac
