#ifndef CAPSTONE_SSTREAM_H_E2CC2C059427479EB357AF22B2282BD0
#define CAPSTONE_SSTREAM_H_E2CC2C059427479EB357AF22B2282BD0

/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

typedef struct SStream {
	char buffer[512];
	int index;
} SStream;

void SStream_Init(SStream *ss);

void SStream_concat(SStream *ss, const char *fmt, ...);

#endif
