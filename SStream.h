/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifndef CS_SSTREAM_H_
#define CS_SSTREAM_H_

#include "include/capstone/platform.h"
#include <stdio.h>

typedef enum {
	Markup_Immediate,
	Markup_Register,
	Markup_Target,
	Markup_Memory,
} SStreamMarkup;

#define SSTREAM_BUF_LEN 512

typedef struct SStream {
	char buffer[SSTREAM_BUF_LEN];
	int index;
	bool is_closed;
	bool markup_stream; ///< If true, markups to the stream are allowed.
	bool prefixed_by_markup; ///< Set after the stream wrote a markup for an operand.
} SStream;

#define SSTREAM_OVERFLOW_CHECK(OS, len) \
do { \
	if (OS->index + len + 1 > SSTREAM_BUF_LEN) { \
		fprintf(stderr, "Buffer overflow caught!\n"); \
		return; \
	} \
} while(0)

#define SSTREAM_RETURN_IF_CLOSED(OS) \
do { \
	if (OS->is_closed) \
		return; \
} while(0)

void SStream_Init(SStream *ss);

void SStream_Flush(SStream *ss, FILE *file);

void SStream_Open(SStream *ss);

void SStream_Close(SStream *ss);

void SStream_concat(SStream *ss, const char *fmt, ...);

void SStream_concat0(SStream *ss, const char *s);

void SStream_concat1(SStream *ss, const char c);

void printInt64Bang(SStream *O, int64_t val);

void printUInt64Bang(SStream *O, uint64_t val);

void printInt64(SStream *O, int64_t val);
void printUInt64(SStream *O, uint64_t val);

void printInt32Bang(SStream *O, int32_t val);

void printInt8(SStream *O, int8_t val);
void printInt16(SStream *O, int16_t val);
void printInt32(SStream *O, int32_t val);

void printUInt32Bang(SStream *O, uint32_t val);

void printUInt32(SStream *O, uint32_t val);

// print number in decimal mode
void printInt32BangDec(SStream *O, int32_t val);

void printFloat(SStream *O, float val);

void printFloatBang(SStream *O, float val);

void printExpr(SStream *O, uint64_t val);

SStream *markup_OS(SStream *OS, SStreamMarkup style);

#endif
