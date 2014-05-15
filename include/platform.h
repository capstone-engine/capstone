/* Capstone Disassembly Engine */
/* By Axel Souchet & Nguyen Anh Quynh, 2014 */

// prototypes for MSVC
#ifndef CAPSTONE_PLATFORM_H
#define CAPSTONE_PLATFORM_H

#if !defined(__MINGW32__) && !defined(__MINGW64__)  // this is not MingW
#if defined (WIN32) || defined (WIN64) || defined (_WIN32) || defined (_WIN64)

// inttypes.h
typedef signed char  int8_t;
typedef signed short int16_t;
typedef signed int   int32_t;
typedef unsigned char  uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int   uint32_t;
typedef signed long long   int64_t;
typedef unsigned long long uint64_t;

// stdbool.h
#ifndef __cplusplus
//    typedef unsigned char bool;
#define false 0
#define true 1
#endif


// string.h
#define strcasecmp _stricmp


#endif	// MSVC
#endif	// not MingW

#endif
