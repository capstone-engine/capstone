//===- llvm/Support/LEB128.h - [SU]LEB128 utility functions -----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares some utility functions for encoding SLEB128 and
// ULEB128 values.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifndef CS_LLVM_SUPPORT_LEB128_H
#define CS_LLVM_SUPPORT_LEB128_H

#include "include/capstone/capstone.h"

/// Utility function to decode a ULEB128 value.
static inline uint64_t decodeULEB128(const uint8_t *p, unsigned *n)
{
	const uint8_t *orig_p = p;
	uint64_t Value = 0;
	unsigned Shift = 0;
	do {
		Value += (uint64_t)(*p & 0x7f) << Shift;
		Shift += 7;
	} while (*p++ >= 128);
	if (n)
		*n = (unsigned)(p - orig_p);
	return Value;
}

/// Utility function to decode a SLEB128 value.
/// Reading stops at \p end. If the encoding extends past \p end or does not
/// fit into an int64_t, \p error is set to a description, \p n to the number
/// of bytes consumed so far and 0 is returned. Otherwise \p error is set to
/// NULL.
static inline int64_t decodeSLEB128(const uint8_t *p, unsigned *n,
				    const uint8_t *end, const char **error)
{
	const uint8_t *orig_p = p;
	int64_t Value = 0;
	unsigned Shift = 0;
	uint8_t Byte;
	if (error)
		*error = NULL;
	do {
		if (p == end) {
			if (error)
				*error = "malformed sleb128, extends past end";
			if (n)
				*n = (unsigned)(p - orig_p);
			return 0;
		}
		Byte = *p;
		uint64_t Slice = Byte & 0x7f;
		if (Shift >= 63 &&
		    ((Shift == 63 && Slice != 0 && Slice != 0x7f) ||
		     (Shift > 63 && Slice != (Value < 0 ? 0x7f : 0x00)))) {
			if (error)
				*error = "sleb128 too big for int64";
			if (n)
				*n = (unsigned)(p - orig_p);
			return 0;
		}
		if (Shift < 64)
			Value |= (int64_t)(Slice << Shift);
		Shift += 7;
		++p;
	} while (Byte >= 128);
	// Sign extend negative numbers if needed.
	if (Shift < 64 && (Byte & 0x40))
		Value |= (int64_t)(UINT64_MAX << Shift);
	if (n)
		*n = (unsigned)(p - orig_p);
	return Value;
}

#endif // LLVM_SYSTEM_LEB128_H
