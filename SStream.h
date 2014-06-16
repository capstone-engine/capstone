/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifndef CS_SSTREAM_H_
#define CS_SSTREAM_H_

typedef struct SStream {
	char buffer[512];
	int index;
} SStream;

void SStream_Init(SStream *ss);

void SStream_concat(SStream *ss, const char *fmt, ...);

void SStream_concat0(SStream *ss, char *s);

#endif
