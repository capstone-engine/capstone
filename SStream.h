/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#ifndef CS_SSTREAM_H_
#define CS_SSTREAM_H_

typedef struct SStream {
	char buffer[512];
	int index;
} SStream;

void SStream_Init(SStream *ss);

void SStream_concat(SStream *ss, const char *fmt, ...);

#endif
