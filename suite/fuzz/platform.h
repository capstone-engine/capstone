#ifndef CS_FUZZ_PLATFORM_H
#define CS_FUZZ_PLATFORM_H

#include <capstone/capstone.h>

struct platform {
	cs_arch arch;
	cs_mode mode;
	const char *comment;
	const char *cstoolname;
};

extern struct platform platforms[];

// get length of platforms[]
unsigned int platform_len(void);

// get platform entry encoded n (first byte for input data of OSS fuzz)
unsigned int get_platform_entry(uint8_t n);

// get cstoolname from encoded n (first byte for input data of OSS fuzz)
const char *get_platform_cstoolname(uint8_t n);

#endif
