/* Capstone Disassembly Engine */
/* By Axel Souchet & Nguyen Anh Quynh, 2014 */

// handle C99 issue (for pre-2013 VisualStudio)
#ifndef CAPSTONE_PLATFORM_H
#define CAPSTONE_PLATFORM_H

#if !defined(__CYGWIN__) && !defined(__MINGW32__) && !defined(__MINGW64__) && (defined (WIN32) || defined (WIN64) || defined (_WIN32) || defined (_WIN64))
// MSVC

// stdbool.h
#if (_MSC_VER < 1800)
#ifndef __cplusplus
typedef unsigned char bool;
#define false 0
#define true 1
#endif

#else
// VisualStudio 2013+ -> C99 is supported
#include <stdbool.h>
#endif

#else // not MSVC -> C99 is supported
#include <stdbool.h>
#endif

#if defined(CS_ARCH_CURRENT) && !defined(CS_MODE_CURRENT) \
    || defined(CS_MODE_CURRENT) && !defined(CS_ARCH_CURRENT)
# error \
    You cannot define only one of CS_ARCH_CURRENT and CS_MODE_CURRENT:          \
    both must be specified when providing the current architecture information  \
    to capstone.
#endif

// Define the current endinanness
#ifndef CS_MODE_CURRENT_ENDIAN
// Big endian
# if defined(__BIG_ENDIAN__) || defined(__ARMEB__) || defined(__THUMBEB__) || defined(__AARCH64EB__) || defined(__MIPSEB) || __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define CS_MODE_CURRENT_ENDIAN CS_MODE_BIG_ENDIAN
// Little endian
# elif defined(__LITTLE_ENDIAN__) || defined(__ARMEL__) || defined(__THUMBEL__) || defined(__AARCH64EL__) || defined(__MIPSEL) || __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define CS_MODE_CURRENT_ENDIAN CS_MODE_LITTLE_ENDIAN
# endif
#endif

// Define the current architecture & mode
#if !defined(CS_ARCH_CURRENT) && !defined(CS_MODE_ARCH_CURRENT)

// ARM-64 / AArch64
#if defined(__aarch64__)
# define CS_ARCH_CURRENT CS_ARCH_ARM64
# define CS_MODE_ARCH_CURRENT CS_MODE_ARM

// ARM
#elif defined(__arm__) || defined(__thumb__) || defined(_M_ARM) || defined(_M_ARMT) || defined(__arm) || defined(_ARM)
# define CS_ARCH_CURRENT CS_ARCH_ARM

# if defined(__thumb__) || defined(_M_ARMT)
#  define CS_MODE_ARCH_CURRENT CS_MODE_THUMB
# else
#  define CS_MODE_ARCH_CURRENT CS_MODE_ARM
# endif

// Mips
#elif defined(__mips) || defined(__mips__)
# define CS_ARCH_CURRENT CS_ARCH_MIPS

# if defined(_MIPS_ISA_MIPS1) || __mips < 2
#  define CS_MODE_ARCH_CURRENT CS_MODE_MIPS32
# elif defined(_MIPS_ISA_MIPS2) || defined(__MIPS_ISA2__) || __mips == 2
#  define CS_MODE_ARCH_CURRENT CS_MODE_MIPS32R6
# elif defined(_MIPS_ISA_MIPS3) || defined(_MIPS_ISA_MIPS4) || __mips > 2 || defined(_R4000)
#  define CS_MODE_ARCH_CURRENT CS_MODE_MIPS64
# endif

// x86
#elif defined(_M_X64) || defined(__amd64) || defined(__i386) || defined(_M_IX86) || defined(_M_I86)
# define CS_ARCH_CURRENT CS_ARCH_X86

# if defined(_M_X64) || defined(__amd64)
#  define CS_MODE_ARCH_CURRENT CS_MODE_64
# elif defined(__i386) || defined(_M_IX86)
#  define CS_MODE_ARCH_CURRENT CS_MODE_32
# else
#  define CS_MODE_ARCH_CURRENT CS_MODE_16
# endif

// PowerPC
#elif defined(__ppc__) || defined(__ppc64__) || defined(_M_PPC) || defined(_ARCH_PPC64)
# define CS_ARCH_CURRENT CS_ARCH_PPC

# if defined(__ppc64__) || defined(_ARCH_PPC64) || _M_PPC >= 620
#  define CS_MODE_ARCH_CURRENT CS_MODE_64
# else
#  define CS_MODE_ARCH_CURRENT CS_MODE_32
# endif

// Sparc
#elif defined(__sparc__) || defined(__sparc)
# define CS_ARCH_CURRENT CS_ARCH_SPARC

# if defined(__sparc_v9__) || defined(__sparcv9)
#  define CS_MODE_ARCH_CURRENT CS_MODE_V9
# endif

// SystemZ
#elif defined(__s390__) || defined(__s390x__) || defined(__zarch__) || defined(__SYSC_ZARCH__)
# define CS_ARCH_CURRENT CS_ARCH_SYSZ

// XCore (no known preprocessor macro checks ATM)
// Unsupported architectures
#else
# define CS_ARCH_CURRENT -1
# define CS_MODE_CURRENT -1
#endif

#endif

#ifndef CS_ARCH_CURRENT
# define CS_ARCH_CURRENT -1
#endif

#ifndef CS_MODE_CURRENT
# if !defined(CS_MODE_CURRENT_ENDIAN) || !defined(CS_MODE_ARCH_CURRENT)
#  define CS_MODE_CURRENT -1
# else
#  define CS_MODE_CURRENT (CS_MODE_CURRENT_ENDIAN | CS_MODE_ARCH_CURRENT)
# endif
#endif

#endif
