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

void SStream_Init(SStream *ss)
{
	assert(ss);
	ss->index = 0;
	memset(ss->buffer, 0, sizeof(ss->buffer));
	ss->is_closed = false;
	ss->markup_stream = false;
	ss->prefixed_by_markup = false;
}

/// Returns the a pointer to the internal string buffer of the stream.
/// For reading only.
const char *SStream_rbuf(const SStream *ss) {
	assert(ss);
	return ss->buffer;
}

/// Searches in the stream for the first (from the left) occurrence of @elem and replaces
/// it with @repl. It returns the pointer *after* the replaced character
/// or NULL if no character was replaced.
///
/// It will never replace the final \0 byte in the stream buffer.
const char *SStream_replc(const SStream *ss, char elem, char repl) {
	assert(ss);
	char *found = strchr(ss->buffer, elem);
	if (!found || found == ss->buffer + (SSTREAM_BUF_LEN - 1)) {
		return NULL;
	}
	*found = repl;
	found++;
	return found;
}

/// Searches in the stream for the first (from the left) occurrence of @chr and replaces
/// it with @rstr.
void SStream_replc_str(SStream *ss, char chr, const char *rstr) {
	assert(ss && rstr);
	char *found = strchr(ss->buffer, chr);
	if (!found || found == ss->buffer + (SSTREAM_BUF_LEN - 1)) {
		return;
	}
	size_t post_len = strlen(found + 1);
	size_t buf_str_len = strlen(ss->buffer);
	size_t repl_len = strlen(rstr);
	if (repl_len - 1 + buf_str_len >= SSTREAM_BUF_LEN) {
		return;
	}
	memmove(found + repl_len, found + 1, post_len);
	memcpy(found, rstr, repl_len);
	ss->index = strlen(ss->buffer);
}

/// Removes the space characters '\t' and ' ' from the beginning of the stream buffer.
void SStream_trimls(SStream *ss) {
	assert(ss);
	size_t buf_off = 0;
	/// Remove leading spaces
	while (ss->buffer[buf_off] == ' ' || ss->buffer[buf_off] == '\t') {
		buf_off++;
	}
	if (buf_off > 0) {
		memmove(ss->buffer, ss->buffer + buf_off, SSTREAM_BUF_LEN - buf_off);
		ss->index -= buf_off;
	}
}

/// Extract the mnemonic to @mnem_buf and the operand string into @op_str_buf from the stream buffer.
/// The mnemonic is everything up until the first ' ' or '\t' character.
/// The operand string is everything after the first ' ' or '\t' sequence.
void SStream_extract_mnem_opstr(const SStream *ss, char *mnem_buf, size_t mnem_buf_size, char *op_str_buf, size_t op_str_buf_size) {
	assert(ss && mnem_buf && mnem_buf_size > 0 && op_str_buf && op_str_buf_size > 0);
	size_t off = 0;
	// Copy all non space chars to as mnemonic.
	while (ss->buffer[off] && ss->buffer[off] != ' ' && ss->buffer[off] != '\t') {
		if (off < mnem_buf_size - 1) {
			// Only copy if there is space left.
			mnem_buf[off] = ss->buffer[off];
		}
		off++;
	}
	if (!ss->buffer[off]) {
		return;
	}

	// Iterate until next non space char.
	do {
		off++;
	} while (ss->buffer[off] && (ss->buffer[off] == ' ' || ss->buffer[off] == '\t'));

	if (!ss->buffer[off]) {
		return;
	}

	// Copy all follow up characters as op_str
	const char *ss_op_str = ss->buffer + off;
	off = 0;
	while (ss_op_str[off] && off < op_str_buf_size - 1) {
		op_str_buf[off] = ss_op_str[off];
		off++;
	}
}

/// Empty the stream @ss to given @file (stdin/stderr).
/// @file can be NULL. Then the buffer content is not emitted.
void SStream_Flush(SStream *ss, FILE *file)
{
	assert(ss);
	if (file) {
		fprintf(file, "%s\n", ss->buffer);
	}
	SStream_Init(ss);
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
	assert(ss && s);
	SSTREAM_RETURN_IF_CLOSED(ss);
	if (s[0] == '\0')
		return;
	unsigned int len = (unsigned int) strlen(s);

	SSTREAM_OVERFLOW_CHECK(ss, len);

	memcpy(ss->buffer + ss->index, s, len);
	ss->index += len;
	ss->buffer[ss->index] = '\0';
	if (ss->markup_stream && ss->prefixed_by_markup) {
		SSTREAM_OVERFLOW_CHECK(ss, 1);
		ss->buffer[ss->index] = '>';
		ss->index += 1;
		ss->buffer[ss->index] = '\0';
	}
#endif
}

/**
 * Copy the single char \p c to the buffer of \p ss.
 */
void SStream_concat1(SStream *ss, const char c)
{
#ifndef CAPSTONE_DIET
	assert(ss);
	SSTREAM_RETURN_IF_CLOSED(ss);
	if (c == '\0')
		return;

	SSTREAM_OVERFLOW_CHECK(ss, 1);

	ss->buffer[ss->index] = c;
	ss->index++;
	ss->buffer[ss->index] = '\0';
	if (ss->markup_stream && ss->prefixed_by_markup) {
		SSTREAM_OVERFLOW_CHECK(ss, 1);
		ss->buffer[ss->index] = '>';
		ss->index++;
	}
#endif
}

/**
 * Copy all strings given to the buffer of \p ss according to formatting \p fmt.
 */
void SStream_concat(SStream *ss, const char *fmt, ...)
{
#ifndef CAPSTONE_DIET
	assert(ss && fmt);
	SSTREAM_RETURN_IF_CLOSED(ss);
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = cs_vsnprintf(ss->buffer + ss->index, sizeof(ss->buffer) - (ss->index + 1), fmt, ap);
	va_end(ap);
	ss->index += ret;
	if (ss->markup_stream && ss->prefixed_by_markup) {
		SSTREAM_OVERFLOW_CHECK(ss, 1);
		ss->buffer[ss->index] = '>';
		ss->index += 1;
	}
#endif
}

// print number with prefix #
void printInt64Bang(SStream *ss, int64_t val)
{
	assert(ss);
	SSTREAM_RETURN_IF_CLOSED(ss);
	SStream_concat1(ss, '#');
	printInt64(ss, val);
}

void printUInt64Bang(SStream *ss, uint64_t val)
{
	assert(ss);
	SSTREAM_RETURN_IF_CLOSED(ss);
	SStream_concat1(ss, '#');
	printUInt64(ss, val);
}

// print number
void printInt64(SStream *ss, int64_t val)
{
	assert(ss);
	SSTREAM_RETURN_IF_CLOSED(ss);
	if (val >= 0) {
		if (val > HEX_THRESHOLD)
			SStream_concat(ss, "0x%"PRIx64, val);
		else
			SStream_concat(ss, "%"PRIu64, val);
	} else {
		if (val < -HEX_THRESHOLD) {
			if (val == INT64_MIN)
				SStream_concat(ss, "-0x%"PRIx64, (uint64_t) INT64_MAX + 1);
			else
				SStream_concat(ss, "-0x%"PRIx64, (uint64_t)-val);
		} else
			SStream_concat(ss, "-%"PRIu64, -val);
	}
}

void printUInt64(SStream *ss, uint64_t val)
{
	assert(ss);
	SSTREAM_RETURN_IF_CLOSED(ss);
	if (val > HEX_THRESHOLD)
		SStream_concat(ss, "0x%"PRIx64, val);
	else
		SStream_concat(ss, "%"PRIu64, val);
}

// print number in decimal mode
void printInt32BangDec(SStream *ss, int32_t val)
{
	assert(ss);
	SSTREAM_RETURN_IF_CLOSED(ss);
	if (val >= 0)
		SStream_concat(ss, "#%" PRIu32, val);
	else {
		if (val == INT32_MIN)
			SStream_concat(ss, "#-%" PRIu32, val);
		else
			SStream_concat(ss, "#-%" PRIu32, (uint32_t)-val);
	}
}

void printInt32Bang(SStream *ss, int32_t val)
{
	assert(ss);
	SSTREAM_RETURN_IF_CLOSED(ss);
	SStream_concat1(ss, '#');
	printInt32(ss, val);
}

void printInt8(SStream *ss, int8_t val)
{
	assert(ss);
	SSTREAM_RETURN_IF_CLOSED(ss);
	if (val >= 0) {
		if (val > HEX_THRESHOLD)
			SStream_concat(ss, "0x%" PRIx8, val);
		else
			SStream_concat(ss, "%" PRId8, val);
	} else {
		if (val < -HEX_THRESHOLD) {
			if (val == INT8_MIN)
				SStream_concat(ss, "-0x%" PRIx8, (uint8_t) INT8_MAX + 1);
			else
				SStream_concat(ss, "-0x%" PRIx8, (int8_t)-val);
		} else
			SStream_concat(ss, "-%" PRIu8, -val);
	}
}

void printInt16(SStream *ss, int16_t val)
{
	assert(ss);
	SSTREAM_RETURN_IF_CLOSED(ss);
	if (val >= 0) {
		if (val > HEX_THRESHOLD)
			SStream_concat(ss, "0x%" PRIx16, val);
		else
			SStream_concat(ss, "%" PRId16, val);
	} else {
		if (val < -HEX_THRESHOLD) {
			if (val == INT16_MIN)
				SStream_concat(ss, "-0x%" PRIx16, (uint16_t) INT16_MAX + 1);
			else
				SStream_concat(ss, "-0x%" PRIx16, (int16_t)-val);
		} else
			SStream_concat(ss, "-%" PRIu16, -val);
	}
}

void printInt16HexOffset(SStream *ss, int16_t val)
{
	assert(ss);
	SSTREAM_RETURN_IF_CLOSED(ss);
	if (val >= 0) {
		SStream_concat(ss, "+0x%" PRIx16, val);
	} else {
		if (val == INT16_MIN)
			SStream_concat(ss, "-0x%" PRIx16,
				       (uint16_t)INT16_MAX + 1);
		else
			SStream_concat(ss, "-0x%" PRIx16, (int16_t)-val);
	}
}


void printInt32(SStream *ss, int32_t val)
{
	assert(ss);
	SSTREAM_RETURN_IF_CLOSED(ss);
	if (val >= 0) {
		if (val > HEX_THRESHOLD)
			SStream_concat(ss, "0x%" PRIx32, val);
		else
			SStream_concat(ss, "%" PRId32, val);
	} else {
		if (val < -HEX_THRESHOLD) {
			if (val == INT32_MIN)
				SStream_concat(ss, "-0x%" PRIx32, (uint32_t) INT32_MAX + 1);
			else
				SStream_concat(ss, "-0x%" PRIx32, (int32_t)-val);
		} else {
			SStream_concat(ss, "-%" PRIu32, (uint32_t)-val);
		}
	}
}

void printInt32HexOffset(SStream *ss, int32_t val)
{
	assert(ss);
	SSTREAM_RETURN_IF_CLOSED(ss);
	if (val >= 0) {
		SStream_concat(ss, "+0x%" PRIx32, val);
	} else {
		if (val == INT32_MIN)
			SStream_concat(ss, "-0x%" PRIx32,
				       (uint32_t)INT32_MAX + 1);
		else
			SStream_concat(ss, "-0x%" PRIx32, (int32_t)-val);
	}
}

void printInt32Hex(SStream *ss, int32_t val)
{
	assert(ss);
	SSTREAM_RETURN_IF_CLOSED(ss);
	if (val >= 0) {
		SStream_concat(ss, "0x%" PRIx32, val);
	} else {
		if (val == INT32_MIN)
			SStream_concat(ss, "-0x%" PRIx32,
				       (uint32_t)INT32_MAX + 1);
		else
			SStream_concat(ss, "-0x%" PRIx32, (int32_t)-val);
	}
}

void printUInt32Bang(SStream *ss, uint32_t val)
{
	assert(ss);
	SSTREAM_RETURN_IF_CLOSED(ss);
	SStream_concat1(ss, '#');
	printUInt32(ss, val);
}

void printUInt32(SStream *ss, uint32_t val)
{
	assert(ss);
	SSTREAM_RETURN_IF_CLOSED(ss);
	if (val > HEX_THRESHOLD)
		SStream_concat(ss, "0x%x", val);
	else
		SStream_concat(ss, "%u", val);
}

void printFloat(SStream *ss, float val)
{
	assert(ss);
	SSTREAM_RETURN_IF_CLOSED(ss);
	SStream_concat(ss, "%e", val);
}

void printFloatBang(SStream *ss, float val)
{
	assert(ss);
	SSTREAM_RETURN_IF_CLOSED(ss);
	SStream_concat(ss, "#%e", val);
}

void printExpr(SStream *ss, uint64_t val)
{
	assert(ss);
	SSTREAM_RETURN_IF_CLOSED(ss);
	SStream_concat(ss, "%"PRIu64, val);
}

SStream *markup_OS(SStream *OS, SStreamMarkup style) {
	assert(OS);

	if (OS->is_closed || !OS->markup_stream) {
		return OS;
	}
	OS->markup_stream = false; // Disable temporarily.
	switch (style) {
	default:
		SStream_concat0(OS, "<UNKNOWN:");
		return OS;
	case Markup_Immediate:
		SStream_concat0(OS, "<imm:");
		break;
	case Markup_Register:
		SStream_concat0(OS, "<reg:");
		break;
	case Markup_Target:
		SStream_concat0(OS, "<tar:");
		break;
	case Markup_Memory:
		SStream_concat0(OS, "<mem:");
		break;
	}
	OS->markup_stream = true;
	OS->prefixed_by_markup = true;
	return OS;
}
