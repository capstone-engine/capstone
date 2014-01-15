/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stdlib.h>
#include <string.h>

#include "utils.h"

// return the position of a string in a list of strings
// or -1 if given string is not in the list
int str_in_list(char **list, char *s)
{
	char **l;

	int c = 0;
	for(l = list; *l; c++, l++) {
		if (!strcasecmp(*l, s))
			return c;
	}

	return -1;
}

// create a cache for fast id lookup
static unsigned short *make_id2insn(insn_map *insns, unsigned int size)
{
	// NOTE: assume that the max id is always put at the end of insns array
	unsigned short max_id = insns[size - 1].id;
	unsigned int i;

	unsigned short *cache = (unsigned short *)cs_mem_calloc(sizeof(*cache), max_id + 1);

	for (i = 1; i < size; i++)
		cache[insns[i].id] = i;

	return cache;
}

// look for @id in @insns, given its size in @max. first time call will update @cache.
// return 0 if not found
unsigned short insn_find(insn_map *insns, unsigned int max, unsigned int id, unsigned short **cache)
{
	if (id > insns[max - 1].id)
		return 0;

	if (*cache == NULL)
		*cache = make_id2insn(insns, max);

	return (*cache)[id];
}

int name2id(name_map* map, int max, const char *name)
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

// count number of positive members in a list.
// NOTE: list must be guaranteed to end in 0
unsigned int count_positive(unsigned char *list)
{
	unsigned int c;

	for (c = 0; list[c] > 0; c++);

	return c;
}

char *cs_strdup(const char *str)
{
	size_t len = strlen(str)+ 1;
	void *new = cs_mem_malloc(len);

	if (new == NULL)
		return NULL;

	return (char *)memmove(new, str, len);
}
