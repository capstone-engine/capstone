/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#include <stdarg.h>
#if defined(CAPSTONE_HAS_OSXKERNEL)
#include <Availability.h>
#include <libkern/libkern.h>
#include <i386/limits.h>
#else
#include <stdio.h>
#include <limits.h>
#endif
#include <string.h>

#include <capstone/platform.h>

#include "SStream.h"
#include "cs_priv.h"
#include "utils.h"

#ifdef _MSC_VER
#pragma warning(disable: 4996) // disable MSVC's warning on strcpy()
#endif

void SStream_Init(SStream *ss)
{
	assert(ss);
	ss->index = 0;
	ss->buffer[0] = '\0';
	ss->is_closed = false;
}

/**
 * Open the output stream. Every write attempt is accepted again.
 */
void SStream_Open(SStream *ss) {
	assert(ss);
	ss->is_closed = false;
}

/**
 * Closes the output stream. Every write attempt is ignored.
 */
void SStream_Close(SStream *ss) {
	assert(ss);
	ss->is_closed = true;
}

/**
 * Copy the string \p s to the buffer of \p ss and terminate it with a '\\0' byte.
 */
void SStream_concat0(SStream *ss, const char *s)
{
#ifndef CAPSTONE_DIET
	SSTREAM_RETURN_IF_CLOSED(ss);
	if (s[0] == '\0')
		return;
	unsigned int len = (unsigned int) strlen(s);

	memcpy(ss->buffer + ss->index, s, len);
	ss->index += len;
	ss->buffer[ss->index] = '\0';
#endif
}

/**
 * Copy the single char \p c to the buffer of \p ss.
 */
void SStream_concat1(SStream *ss, const char c)
{
#ifndef CAPSTONE_DIET
	SSTREAM_RETURN_IF_CLOSED(ss);
	if (c == '\0')
		return;
	ss->buffer[ss->index] = c;
	ss->index++;
	ss->buffer[ss->index] = '\0';
#endif
}

/**
 * Copy all strings given to the buffer of \p ss according to formatting \p fmt.
 */
void SStream_concat(SStream *ss, const char *fmt, ...)
{
#ifndef CAPSTONE_DIET
	SSTREAM_RETURN_IF_CLOSED(ss);
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = cs_vsnprintf(ss->buffer + ss->index, sizeof(ss->buffer) - (ss->index + 1), fmt, ap);
	va_end(ap);
	ss->index += ret;
#endif
}

// print number with prefix #
void printInt64Bang(SStream *O, int64_t val)
{
	SSTREAM_RETURN_IF_CLOSED(O);
	if (val >= 0) {
		if (val > HEX_THRESHOLD)
			SStream_concat(O, "#0x%"PRIx64, val);
		else
			SStream_concat(O, "#%"PRIu64, val);
	} else {
		if (val <- HEX_THRESHOLD) {
			if (val == LONG_MIN)
				SStream_concat(O, "#-0x%"PRIx64, (uint64_t)val);
			else
				SStream_concat(O, "#-0x%"PRIx64, (uint64_t)-val);
		} else
			SStream_concat(O, "#-%"PRIu64, -val);
	}
}

void printUInt64Bang(SStream *O, uint64_t val)
{
	SSTREAM_RETURN_IF_CLOSED(O);
	if (val > HEX_THRESHOLD)
		SStream_concat(O, "#0x%"PRIx64, val);
	else
		SStream_concat(O, "#%"PRIu64, val);
}

// print number
void printInt64(SStream *O, int64_t val)
{
	SSTREAM_RETURN_IF_CLOSED(O);
	if (val >= 0) {
		if (val > HEX_THRESHOLD)
			SStream_concat(O, "0x%"PRIx64, val);
		else
			SStream_concat(O, "%"PRIu64, val);
	} else {
		if (val <- HEX_THRESHOLD) {
			if (val == LONG_MIN)
				SStream_concat(O, "-0x%"PRIx64, (uint64_t)val);
			else
				SStream_concat(O, "-0x%"PRIx64, (uint64_t)-val);
		} else
			SStream_concat(O, "-%"PRIu64, -val);
	}
}

void printUInt64(SStream *O, uint64_t val)
{
	SSTREAM_RETURN_IF_CLOSED(O);
	if (val > HEX_THRESHOLD)
		SStream_concat(O, "0x%"PRIx64, val);
	else
		SStream_concat(O, "%"PRIu64, val);
}

// print number in decimal mode
void printInt32BangDec(SStream *O, int32_t val)
{
	SSTREAM_RETURN_IF_CLOSED(O);
	if (val >= 0)
		SStream_concat(O, "#%u", val);
	else {
		if (val == INT_MIN)
			SStream_concat(O, "#-%u", val);
		else
			SStream_concat(O, "#-%u", (uint32_t)-val);
	}
}

void printInt32Bang(SStream *O, int32_t val)
{
	SSTREAM_RETURN_IF_CLOSED(O);
	if (val >= 0) {
		if (val > HEX_THRESHOLD)
			SStream_concat(O, "#0x%x", val);
		else
			SStream_concat(O, "#%u", val);
	} else {
		if (val <- HEX_THRESHOLD) {
			if (val == INT_MIN)
				SStream_concat(O, "#-0x%x", (uint32_t)val);
			else
				SStream_concat(O, "#-0x%x", (uint32_t)-val);
		} else
			SStream_concat(O, "#-%u", -val);
	}
}

void printInt32(SStream *O, int32_t val)
{
	SSTREAM_RETURN_IF_CLOSED(O);
	if (val >= 0) {
		if (val > HEX_THRESHOLD)
			SStream_concat(O, "0x%x", val);
		else
			SStream_concat(O, "%u", val);
	} else {
		if (val <- HEX_THRESHOLD) {
			if (val == INT_MIN)
				SStream_concat(O, "-0x%x", (uint32_t)val);
			else
				SStream_concat(O, "-0x%x", (uint32_t)-val);
		} else
			SStream_concat(O, "-%u", -val);
	}
}

void printUInt32Bang(SStream *O, uint32_t val)
{
	SSTREAM_RETURN_IF_CLOSED(O);
	if (val > HEX_THRESHOLD)
		SStream_concat(O, "#0x%x", val);
	else
		SStream_concat(O, "#%u", val);
}

void printUInt32(SStream *O, uint32_t val)
{
	SSTREAM_RETURN_IF_CLOSED(O);
	if (val > HEX_THRESHOLD)
		SStream_concat(O, "0x%x", val);
	else
		SStream_concat(O, "%u", val);
}

void printFloat(SStream *O, float val)
{
	SSTREAM_RETURN_IF_CLOSED(O);
	SStream_concat(O, "%e", val);
}

void printFloatBang(SStream *O, float val)
{
	SSTREAM_RETURN_IF_CLOSED(O);
	SStream_concat(O, "#%e", val);
}
