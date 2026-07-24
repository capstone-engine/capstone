/* Capstone Disassembly Engine */
/* By phix33, 2026 */

// Regression test: update_cr0 and bh (branch hint) must be derived from the
// current instruction only. PPC_post_printer used to read insn->mnemonic,
// which the alias early-return paths in PPC_printInst (mr, slwi/srwi, sldi,
// dcbt/dcbtst, dcbf) never fill before it runs. When one cs_insn buffer is
// reused across cs_disasm_iter() calls - the documented usage pattern - those
// aliases inherited update_cr0/bh from the previously decoded instruction.

#include <stdio.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>

struct step {
	const char *code;	// 4 bytes, big-endian
	const char *asm_text;
	bool update_cr0;
	ppc_bh bh;
};

// Each alias is decoded right after an instruction that legitimately sets
// update_cr0 or a branch hint, into the same reused cs_insn.
static const struct step steps[] = {
	{ "\x7c\x85\x32\x15", "add. r4, r5, r6", true, PPC_BH_INVALID },
	{ "\x7c\x29\x0b\x78", "mr r9, r1", false, PPC_BH_INVALID },
	{ "\x7c\x85\x32\x15", "add. r4, r5, r6", true, PPC_BH_INVALID },
	{ "\x54\xa4\x18\x38", "slwi r4, r5, 3", false, PPC_BH_INVALID },
	{ "\x7c\x85\x32\x15", "add. r4, r5, r6", true, PPC_BH_INVALID },
	{ "\x78\xa4\x1f\x24", "sldi r4, r5, 3", false, PPC_BH_INVALID },
	{ "\x7c\x85\x32\x15", "add. r4, r5, r6", true, PPC_BH_INVALID },
	{ "\x7c\x04\x2a\x2c", "dcbt r4, r5", false, PPC_BH_INVALID },
	{ "\x7c\x85\x32\x15", "add. r4, r5, r6", true, PPC_BH_INVALID },
	{ "\x7c\x04\x28\xac", "dcbf r4, r5", false, PPC_BH_INVALID },
	// non-alias path after a record form: was already correct
	{ "\x7c\x85\x32\x15", "add. r4, r5, r6", true, PPC_BH_INVALID },
	{ "\x7c\x85\x32\x14", "add r4, r5, r6", false, PPC_BH_INVALID },
	// branch hints must not leak into the aliases either
	{ "\x40\xe2\x00\x10", "bne+ 0x1010", false, PPC_BH_PLUS },
	{ "\x7c\x29\x0b\x78", "mr r9, r1", false, PPC_BH_INVALID },
	{ "\x40\xc2\x00\x10", "bne- 0x1010", false, PPC_BH_MINUS },
	{ "\x7c\x04\x2a\x2c", "dcbt r4, r5", false, PPC_BH_INVALID },
};

int main(void)
{
	csh handle;
	cs_insn *insn;
	int i, errors = 0;

	if (cs_open(CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN, &handle) != CS_ERR_OK) {
		printf("ERROR: Failed to initialize engine!\n");
		return 1;
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	insn = cs_malloc(handle);

	for (i = 0; i < (int)(sizeof(steps) / sizeof(steps[0])); i++) {
		const uint8_t *code = (const uint8_t *)steps[i].code;
		size_t size = 4;
		uint64_t address = 0x1000;

		if (!cs_disasm_iter(handle, &code, &size, &address, insn)) {
			printf("ERROR: failed to decode '%s'\n", steps[i].asm_text);
			errors++;
			continue;
		}

		bool ok = insn->detail->ppc.update_cr0 == steps[i].update_cr0 &&
			insn->detail->ppc.bh == steps[i].bh;
		printf("%s\t%s: update_cr0=%u (expected %u), bh=%u (expected %u)\n",
				ok ? "OK  " : "FAIL", steps[i].asm_text,
				insn->detail->ppc.update_cr0, steps[i].update_cr0,
				insn->detail->ppc.bh, steps[i].bh);
		if (!ok)
			errors++;
	}

	cs_free(insn, 1);
	cs_close(&handle);

	if (errors) {
		printf("%d test(s) failed\n", errors);
		return 1;
	}
	printf("all tests passed\n");
	return 0;
}
