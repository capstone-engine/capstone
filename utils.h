/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#ifndef __CS_UTILS_H__
#define __CS_UTILS_H__ 

#include <stdbool.h>

typedef struct Pair {
	char *str;
	unsigned num;
} Pair;

// map instruction to its characteristics
typedef struct insn_map {
	unsigned int id;
	unsigned int mapid;
	unsigned int regs_use[32]; // list of implicit registers used by this instruction
	unsigned int regs_mod[32]; // list of implicit registers modified by this instruction
	unsigned int groups[8]; // list of group this instruction belong to
	bool branch;	// branch instruction?
	bool indirect_branch;	// indirect branch instruction?
} insn_map;

bool str_in_list(char **list, char *s);

int insn_find(insn_map *m, unsigned int max, unsigned int id);

// map id to string
typedef struct name_map {
	unsigned int id;
	char *name;
} name_map;

// map a name to its ID
// return 0 if not found
int name2id(name_map* map, int max, char *name);

// reverse mapid to id
// return 0 if not found
unsigned int insn_reverse_id(insn_map *insns, unsigned int max, unsigned int id);

#define ARR_SIZE(a) (sizeof(a)/sizeof(a[0]))

#endif

