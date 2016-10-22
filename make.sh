#!/usr/bin/env bash

# Capstone Disassembly Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014

# Note: to cross-compile "nix32" on Linux, package gcc-multilib is required.


# build iOS lib for all iDevices, or only specific device
function build_iOS {
	IOS_SDK=`xcrun --sdk iphoneos --show-sdk-path`
	IOS_CC=`xcrun --sdk iphoneos -f clang`
	IOS_CFLAGS="-Os -Wimplicit -isysroot $IOS_SDK"
	IOS_LDFLAGS="-isysroot $IOS_SDK"
	if (( $# == 0 )); then
		# build for all iDevices
		IOS_ARCHS="armv7 armv7s arm64"
	else
		IOS_ARCHS="$1"
	fi
	CC="$IOS_CC" CFLAGS="$IOS_CFLAGS" LDFLAGS="$IOS_LDFLAGS" LIBARCHS="$IOS_ARCHS" ${MAKE}
}

# build Android lib for only one supported architecture
function build_android {
    if [ -z "$NDK" ]; then
        echo "ERROR! Please set \$NDK to point at your Android NDK directory."
        exit 1
    fi
    HOSTOS=$(uname -s | tr 'LD' 'ld')
    HOSTARCH=$(uname -m)

    TARGARCH="$1"
    shift

    case "$TARGARCH" in
      arm)
          [ -n "$APILEVEL" ] || APILEVEL="android-14"  # default to ICS
          [ -n "$GCCVER" ] || GCCVER="4.8"
          CROSS=arm-linux-androideabi-
          ;;
      arm64)
          [ -n "$APILEVEL" ] || APILEVEL="android-21"  # first with arm64
          [ -n "$GCCVER" ] || GCCVER="4.9"
          CROSS=aarch64-linux-android-
          ;;

      *)
          echo "ERROR! Building for Android on $1 is not currently supported."
          exit 1
          ;;
    esac

    TOOLCHAIN="$NDK/toolchains/$CROSS$GCCVER/prebuilt/$HOSTOS-$HOSTARCH"
    PLATFORM="$NDK/platforms/$APILEVEL/arch-$TARGARCH"

    CROSS="$TOOLCHAIN/bin/$CROSS" CFLAGS="--sysroot=$PLATFORM" LDFLAGS="--sysroot=$PLATFORM" ${MAKE} $*
}


function build {
	if [ $(uname -s) = Darwin ]; then
		export LIBARCHS="i386 x86_64"
	fi

	if [ -n "$CC" ]; then
		${MAKE} CC="$CC" $*
	else
		${MAKE} $*
	fi
}

function install {
	# Mac OSX needs to find the right directory for pkgconfig
	if [ "$(uname)" == "Darwin" ]; then
		# we are going to install into /usr/local, so remove old installs under /usr
		rm -rf /usr/lib/libcapstone.*
		rm -rf /usr/include/capstone
		# install into /usr/local
		export PREFIX=/usr/local
		# find the directory automatically, so we can support both Macport & Brew
		PKGCFGDIR="$(pkg-config --variable pc_path pkg-config | cut -d ':' -f 1)"
		# set PKGCFGDIR only in non-Brew environment & pkg-config is available
		if [ "$HOMEBREW_CAPSTONE" != "1" ] && [ ${PKGCFGDIR}x != x ]; then
			if [ ${CC}x != x ]; then
				${MAKE} CC=$CC PKGCFGDIR=$PKGCFGDIR install
			else
				${MAKE} PKGCFGDIR=$PKGCFGDIR install
			fi
		else
			if [ ${CC}x != x ]; then
				${MAKE} CC=$CC install
			else
				${MAKE} install
			fi
		fi
	else	# not OSX
		if test -d /usr/lib64; then
			if [ -n "$CC" ]; then
				${MAKE} LIBDIRARCH=lib64 CC="$CC" install
			else
				${MAKE} LIBDIRARCH=lib64 install
			fi
		else
			if [ -n "$CC" ]; then
				${MAKE} CC="$CC" install
			else
				${MAKE} install
			fi
		fi
	fi
}

function uninstall {
	# Mac OSX needs to find the right directory for pkgconfig
	if [ "$(uname)" == "Darwin" ]; then
		# find the directory automatically, so we can support both Macport & Brew
		PKGCFGDIR="$(pkg-config --variable pc_path pkg-config | cut -d ':' -f 1)"
		export PREFIX=/usr/local
		if [ ${PKGCFGDIR}x != x ]; then
			${MAKE} PKGCFGDIR=$PKGCFGDIR uninstall
		else
			${MAKE} uninstall
		fi
	else	# not OSX
		if test -d /usr/lib64; then
			${MAKE} LIBDIRARCH=lib64 uninstall
		else
			${MAKE} uninstall
		fi
	fi
}

MAKE=make
if [ "$(uname)" == "SunOS" ]; then
	export MAKE=gmake
	export INSTALL_BIN=ginstall
	export CC=gcc
fi

if [[ "$(uname)" == *BSD* ]]; then
	export MAKE=gmake
	export PREFIX=/usr/local
fi

TARGET="$1"
shift

case "$TARGET" in
  "" ) build $*;;
  "default" ) build $*;;
  "debug" ) CAPSTONE_USE_SYS_DYN_MEM=yes CAPSTONE_STATIC=yes CFLAGS='-O0 -g -fsanitize=address' LDFLAGS='-fsanitize=address' build $*;;
  "install" ) install;;
  "uninstall" ) uninstall;;
  "nix32" ) CFLAGS=-m32 LDFLAGS=-m32 build $*;;
  "cross-win32" ) CROSS=i686-w64-mingw32- build $*;;
  "cross-win64" ) CROSS=x86_64-w64-mingw32- build $*;;
  "cygwin-mingw32" ) CROSS=i686-pc-mingw32- build $*;;
  "cygwin-mingw64" ) CROSS=x86_64-w64-mingw32- build $*;;
  "cross-android" ) build_android $*;;
  "clang" ) CC=clang build $*;;
  "gcc" ) CC=gcc build $*;;
  "ios" ) build_iOS $*;;
  "ios_armv7" ) build_iOS armv7 $*;;
  "ios_armv7s" ) build_iOS armv7s $*;;
  "ios_arm64" ) build_iOS arm64 $*;;
  "osx-kernel" ) CAPSTONE_USE_SYS_DYN_MEM=yes CAPSTONE_HAS_OSXKERNEL=yes CAPSTONE_ARCHS=x86 CAPSTONE_SHARED=no CAPSTONE_BUILD_CORE_ONLY=yes build $*;;
  * ) echo "Usage: make.sh [nix32|cross-win32|cross-win64|cygwin-mingw32|cygwin-mingw64|ios|ios_armv7|ios_armv7s|ios_arm64|cross-android arm|cross-android arm64|clang|gcc|install|uninstall]"; exit 1;;
esac
