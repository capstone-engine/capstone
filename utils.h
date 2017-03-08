/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifndef CS_UTILS_H
#define CS_UTILS_H

#if defined(CAPSTONE_HAS_OSXKERNEL)
#include <libkern/libkern.h>
#else
#include <stddef.h>
#endif
#include "include/capstone.h"
#include "cs_priv.h"

// threshold number, so above this number will be printed in hexa mode
#define HEX_THRESHOLD 9

// map instruction to its characteristics
typedef struct insn_map {
	unsigned short id;
	unsigned short mapid;
#ifndef CAPSTONE_DIET
	unsigned char regs_use[12]; // list of implicit registers used by this instruction
	unsigned char regs_mod[20]; // list of implicit registers modified by this instruction
	unsigned char groups[8]; // list of group this instruction belong to
	bool branch;	// branch instruction?
	bool indirect_branch;	// indirect branch instruction?
#endif
} insn_map;

// look for @id in @m, given its size in @max. first time call will update @cache.
// return 0 if not found
unsigned short insn_find(insn_map *m, unsigned int max, unsigned int id, unsigned short **cache);

// map id to string
typedef struct name_map {
	unsigned int id;
	char *name;
} name_map;

// map a name to its ID
// return 0 if not found
int name2id(name_map* map, int max, const char *name);

// count number of positive members in a list.
// NOTE: list must be guaranteed to end in 0
unsigned int count_positive(unsigned char *list);

#define ARR_SIZE(a) (sizeof(a)/sizeof(a[0]))

char *cs_strdup(const char *str);

#define MIN(x, y) ((x) < (y) ? (x) : (y))

// we need this since Windows doesnt have snprintf()
int cs_snprintf(char *buffer, size_t size, const char *fmt, ...);

#endif

