#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <capstone/capstone.h>

static size_t uleb32(uint32_t v, uint8_t *out)
{
	size_t n = 0;
	for (;;) {
		uint8_t b = (uint8_t)(v & 0x7f);
		v >>= 7;
		if (v)
			b |= 0x80;
		out[n++] = b;
		if (!v)
			return n;
	}
}

static int run_count_case(csh h, uint32_t labels, size_t count_limit)
{
	uint8_t enc[5];
	size_t enc_len = uleb32(labels, enc);
	size_t len = 1 + enc_len + labels + 1;
	uint8_t *buf = calloc(1, len);
	if (!buf)
		return 1;

	buf[0] = 0x0e;
	memcpy(buf + 1, enc, enc_len);

	cs_insn *insn = NULL;
	size_t count = cs_disasm(h, buf, len, 0, count_limit, &insn);
	printf("labels=%u input_len=%zu requested=%zu returned=%zu\n", labels,
	       len, count_limit, count);
	if (count > 1) {
		cs_free(insn, count);
		free(buf);
		return 1;
	}
	for (size_t i = 0; i < count; i++) {
		printf("  insn[%zu]: address=%" PRIu64 " size=%u id=%u\n", i,
		       insn[i].address, insn[i].size, insn[i].id);
	}

	cs_free(insn, count);
	free(buf);
	return 0;
}

int main(void)
{
	csh h;
	if (cs_open(CS_ARCH_WASM, 0, &h) != CS_ERR_OK)
		return 1;

	if (run_count_case(h, 10, 5) || run_count_case(h, 65531, 5)) {
		cs_close(&h);
		return 1;
	}

	cs_close(&h);
	return 0;
}
