// this tool decodes first input byte feed to OSS fuzz, that encodes arch+mode
// by Nguyen Anh Quynh, 2019

#include <stdio.h>
#include <inttypes.h>

#include <capstone/capstone.h>

#include "platform.h"

static struct platform platforms[] = {
#include "platforms.inc"
};

int main(int argc, char **argv)
{
    unsigned int platforms_len = sizeof(platforms)/sizeof(platforms[0]), data, i;

	if (argc != 2) {
		printf("Decoding OSS fuzz platform\n", argv[0]);
		printf("Syntax: %s <hex-byte>\n", argv[0]);
		return -1;
	}

	data = (unsigned int)strtol(argv[1], NULL, 16);
	i = (unsigned int)data % platforms_len;

	printf("cstool arch+mode = %s\n", platforms[i].cstoolname);

	return 0;
}

