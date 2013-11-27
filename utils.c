/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <string.h>

#include "utils.h"

// check to see if a string exists in a list of string ...
bool str_in_list(char **list, char *s)
{
	char **l;

	for(l = list; *l; l++)
		if (!strcasecmp(*l, s))
			return true;

	return false;
}

// binary searching
int insn_find(insn_map *m, unsigned int max, unsigned int id)
{
	unsigned int i, begin, end;

	begin = 0;
	end = max;

	while(begin <= end) {
		i = (begin + end) / 2;
		if (id == m[i].id)
			return i;
		else if (id < m[i].id)
			end = i - 1;
		else
			begin = i + 1;
	}

	// found nothing
	return -1;
}

int name2id(name_map* map, int max, char *name)
{
	int i;

	for (i = 0; i < max; i++) {
		if (!strcasecmp(map[i].name, name)) {
			return map[i].id;
		}
	}

	// nothing match
	return -1;
}

unsigned int insn_reverse_id(insn_map *insns, unsigned int max, unsigned int id)
{
	unsigned int i;

	for (i = 0; i < max; i++) {
		if (id == insns[i].mapid)
			return insns[i].id;
	}

	// found nothing
	return 0;
}

