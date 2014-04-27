AC_PREREQ([2.62])

m4_define([capstone_major_version], m4_esyscmd([(grep CS_API_MAJOR include/capstone.h | awk '{ printf "%s", $3; }')]))
m4_define([capstone_minor_version], m4_esyscmd([(grep CS_API_MINOR include/capstone.h | awk '{ printf "%s", $3; }')]))
m4_define([capstone_micro_version], m4_esyscmd([(grep -E '^PKG_EXTRA' pkgconfig.mk | awk '{ printf "%s", $3; }')]))

m4_define([capstone_version], [capstone_major_version.capstone_minor_version.capstone_micro_version])

AC_INIT([capstone], [capstone_version])
AC_CONFIG_SRCDIR([cs.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([-Wall -Werror subdir-objects no-dist-gzip dist-bzip2 foreign])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PROG_CC
AM_PROG_AR
AC_PROG_INSTALL
LT_INIT

AC_ARG_ENABLE(dynamic_memory, [AC_HELP_STRING([--enable-dynamic-memory], [enable dynamic memory [default=yes]])],, [enable_dynamic_memory=yes])
if [[ "x$enable_dynamic_memory" = "xyes" ]]; then
  AC_DEFINE(USE_SYS_DYN_MEM, 1, [Define to 1 if dynamic memory is enabled.])
fi

AC_ARG_ENABLE(diet, [AC_HELP_STRING([--enable-diet], [enable diet mode [default=no]])],, [enable_diet=no])
if [[ "x$enable_diet" = "xyes" ]]; then
  AC_DEFINE(CAPSTONE_DIET, 1, [Define to 1 if a minimal footprint is desired.])
fi

AC_ARG_ENABLE(arm, [AC_HELP_STRING([--enable-arm], [enable ARM support [default=yes]])],, [enable_arm=yes])
if [[ "x$enable_arm" = "xyes" ]]; then
  AC_DEFINE(CAPSTONE_HAS_ARM, 1, [Define to 1 if ARM support is available.])
fi
AM_CONDITIONAL(ENABLE_ARM, [test "x$enable_arm" = "xyes"])

AC_ARG_ENABLE(arm64, [AC_HELP_STRING([--enable-arm64], [enable ARM64 support [default=yes]])],, [enable_arm64=yes])
if [[ "x$enable_arm64" = "xyes" ]]; then
  AC_DEFINE(CAPSTONE_HAS_ARM64, 1, [Define to 1 if ARM64 support is available.])
fi
AM_CONDITIONAL(ENABLE_ARM64, [test "x$enable_arm64" = "xyes"])

AC_ARG_ENABLE(mips, [AC_HELP_STRING([--enable-mips], [enable MIPS support [default=yes]])],, [enable_mips=yes])
if [[ "x$enable_mips" = "xyes" ]]; then
  AC_DEFINE(CAPSTONE_HAS_MIPS, 1, [Define to 1 if MIPS support is available.])
fi
AM_CONDITIONAL(ENABLE_MIPS, [test "x$enable_mips" = "xyes"])

AC_ARG_ENABLE(ppc, [AC_HELP_STRING([--enable-ppc], [enable PPC support [default=yes]])],, [enable_ppc=yes])
if [[ "x$enable_ppc" = "xyes" ]]; then
  AC_DEFINE(CAPSTONE_HAS_PPC, 1, [Define to 1 if PPC support is available.])
fi
AM_CONDITIONAL(ENABLE_PPC, [test "x$enable_ppc" = "xyes"])

AC_ARG_ENABLE(sparc, [AC_HELP_STRING([--enable-sparc], [enable Sparc support [default=yes]])],, [enable_sparc=yes])
if [[ "x$enable_sparc" = "xyes" ]]; then
  AC_DEFINE(CAPSTONE_HAS_SPARC, 1, [Define to 1 if Sparc support is available.])
fi
AM_CONDITIONAL(ENABLE_SPARC, [test "x$enable_sparc" = "xyes"])

AC_ARG_ENABLE(sysz, [AC_HELP_STRING([--enable-sysz], [enable SystemZ support [default=yes]])],, [enable_sysz=yes])
if [[ "x$enable_sysz" = "xyes" ]]; then
  AC_DEFINE(CAPSTONE_HAS_SYSZ, 1, [Define to 1 if SystemZ support is available.])
fi
AM_CONDITIONAL(ENABLE_SYSZ, [test "x$enable_sysz" = "xyes"])

AC_ARG_ENABLE(x86, [AC_HELP_STRING([--enable-x86], [enable X86 support [default=yes]])],, [enable_x86=yes])
if [[ "x$enable_x86" != "xno" ]]; then
  AC_DEFINE(CAPSTONE_HAS_X86, 1, [Define to 1 if X86 support is available.])
fi
if [[ "x$enable_x86" = "xminimal" ]]; then
  AC_DEFINE(CAPSTONE_X86_REDUCE, 1, [Define to 1 if X86 support should be limited to only critical instructions.])
fi
AM_CONDITIONAL(ENABLE_X86, [test "x$enable_x86" != "xno"])

AC_CONFIG_FILES([
	capstone.pc
	Makefile
])
AC_OUTPUT
