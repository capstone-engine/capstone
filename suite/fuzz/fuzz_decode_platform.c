// this tool decodes first input byte feed to OSS fuzz, that encodes arch+mode
// by Nguyen Anh Quynh, 2019

#include <stdio.h>
#include <inttypes.h>

#include <capstone/capstone.h>

#include "platform.h"

int main(int argc, char **argv)
{
	unsigned char data;

	if (argc != 2) {
		printf("Decoding OSS fuzz platform\n");
		printf("Syntax: %s <hex-byte>\n", argv[0]);
		return -1;
	}

	data = (unsigned int)strtol(argv[1], NULL, 16);

	printf("cstool arch+mode = %s\n", get_platform_cstoolname(data));

	return 0;
}
