/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>

#include "SStream.h"
#include "cs_priv.h"

void SStream_Init(SStream *ss)
{
	ss->index = 0;
	ss->buffer[0] = '\0';
}

void SStream_concat(SStream *ss, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	int ret = cs_vsnprintf(ss->buffer + ss->index, sizeof(ss->buffer) - (ss->index + 1), fmt, ap);
	va_end(ap);
	ss->index += ret;
}

/*
   int main()
   {
   SStream ss;
   int64_t i;

   SStream_Init(&ss);

   SStream_concat(&ss, "hello ");
   SStream_concat(&ss, "%d - 0x%x", 200, 16);

   i = 123;
   SStream_concat(&ss, " + %ld", i);
   SStream_concat(&ss, "%s", "haaaaa");

   printf("%s\n", ss.buffer);

   return 0;
   }
 */
