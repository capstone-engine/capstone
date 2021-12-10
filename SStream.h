/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifndef CS_SSTREAM_H_
#define CS_SSTREAM_H_

#include "include/capstone/platform.h"

typedef struct SStream {
	char buffer[256];
	size_t index;
} SStream;

void SStream_Init(SStream *ss);

void SStream_concat(SStream *ss, const char *fmt, ...);

void SStream_concat0(SStream *ss, const char *s);

void SStream_concat1(SStream *ss, const char c);

void printInt64Bang(SStream *O, int64_t val);

void printUInt64Bang(SStream *O, uint64_t val);

void printInt64(SStream *O, int64_t val);

void printUInt64(SStream *O, uint64_t val);

void printInt32Bang(SStream *O, int32_t val);

void printInt32(SStream *O, int32_t val);

void printUInt32Bang(SStream *O, uint32_t val);

void printUInt32(SStream *O, uint32_t val);

// print number in decimal mode
void printInt32BangDec(SStream *O, int32_t val);

#endif
