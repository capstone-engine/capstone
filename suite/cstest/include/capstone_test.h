/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */


#ifndef CAPSTONE_TEST_H
#define CAPSTONE_TEST_H

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>
#include <capstone/capstone.h>
#include "helper.h"
#include "factory.h"

#define cs_assert_err(expect, err)									\
	do {																\
		cs_err __err = err;												\
		if (__err != expect) {											\
			fail_msg("%s",cs_strerror(__err));							\
		}																\
	} while (0)


#define cs_assert_success(err) cs_assert_err(CS_ERR_OK, err)


#define cs_assert_fail(err)											\
	do {																\
		cs_err __err = err;												\
		if (__err == CS_ERR_OK) {										\
			fail_msg("%s",cs_strerror(__err));							\
		}																\
	} while (0)

#define NUMARCH 10
#define NUMMODE 35
#define NUMOPTION 41
#define MAXMEM 1024

typedef struct {
	const char *str;
	unsigned int value;
} single_dict;

typedef struct {
	const char *str;
	unsigned int first_value;
	unsigned int second_value;
} double_dict;

extern char *(*function)(csh *, cs_mode, cs_insn*);

int get_index(double_dict d[], unsigned size, const char *str);
int get_value(single_dict d[], unsigned size, const char *str);
void test_single_MC(csh *handle, int mc_mode, char *line);
void test_single_issue(csh *handle, cs_mode mode, char *line, int detail);
int set_function(int arch);

#endif /* CAPSTONE_TEST_H */
