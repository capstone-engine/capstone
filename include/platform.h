/* Capstone Disassembly Engine */
/* By Axel Souchet & Nguyen Anh Quynh, 2014 */

// prototypes for MSVC
#ifndef CAPSTONE_PLATFORM_H
#define CAPSTONE_PLATFORM_H

#if !defined(__MINGW32__) && !defined(__MINGW64__)  // this is not MingW
#if defined (WIN32) || defined (WIN64) || defined (_WIN32) || defined (_WIN64)


// string.h
#define strcasecmp _stricmp


#endif	// MSVC
#endif	// not MingW

#endif
