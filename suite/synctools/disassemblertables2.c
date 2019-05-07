/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

// this tool is to generate arch/X86/X86GenDisassemblerTables2.inc
// NOTE: this requires updated X86GenDisassemblerTables2 & X86GenDisassemblerTables2
// generatedy by ./disassemblertables.py & disassemblertables_reduce.py

#include <stdio.h>
#include <stdint.h>
#include <string.h>

// X86DisassemblerDecoderCommon.h is copied from Capstone src
#include "../../arch/X86/X86DisassemblerDecoderCommon.h"

#define ARR_SIZE(a) (sizeof(a) / sizeof(a[0]))

/// Specifies whether a ModR/M byte is needed and (if so) which
/// instruction each possible value of the ModR/M byte corresponds to.  Once
/// this information is known, we have narrowed down to a single instruction.
struct ModRMDecision {
	uint8_t modrm_type;
	uint16_t instructionIDs;
};

/// Specifies which set of ModR/M->instruction tables to look at
/// given a particular opcode.
struct OpcodeDecision {
	struct ModRMDecision modRMDecisions[256];
};

/// Specifies which opcode->instruction tables to look at given
/// a particular context (set of attributes).  Since there are many possible
/// contexts, the decoder first uses CONTEXTS_SYM to determine which context
/// applies given a specific set of attributes.  Hence there are only IC_max
/// entries in this table, rather than 2^(ATTR_max).
struct ContextDecision {
	struct OpcodeDecision opcodeDecisions[IC_max];
};

#ifdef CAPSTONE_X86_REDUCE
#include "X86GenDisassemblerTables_reduce2.inc"
#else
#include "X86GenDisassemblerTables2.inc"
#endif

static void index_OpcodeDecision(const struct OpcodeDecision *decisions, size_t size,
		const struct OpcodeDecision *emptyDecision, unsigned int *index_table,
		const char *opcodeTable,
		const char *index_opcodeTable)
{
	unsigned int i, count = 0;

	for (i = 0; i < size; i++) {
		if (memcmp((const void *)&decisions[i],
					emptyDecision, sizeof(*emptyDecision)) != 0) {
			// this is a non-zero entry
			// index_table entry must be != 0
			index_table[i] = count + 1;
			count++;
		} else
			// empty entry
			index_table[i] = 0;
	}

	printf("static const unsigned char %s[] = {\n", index_opcodeTable);

	for (i = 0; i < size; i++) {
		printf("  %u,\n", index_table[i]);
	}

	printf("};\n\n");

	printf("static const struct OpcodeDecision %s[] = {\n", opcodeTable);
	for (i = 0; i < size; i++) {
		if (index_table[i]) {
			unsigned int j;
			const struct OpcodeDecision *decision;

			// print out this non-zero entry
			printf("  { {\n");
			decision = &decisions[i];

			for(j = 0; j < ARR_SIZE(emptyDecision->modRMDecisions); j++) {
				const char *modrm;

				switch(decision->modRMDecisions[j].modrm_type) {
					default:
						modrm = "MODRM_ONEENTRY";
						break;
					case 1:
						modrm = "MODRM_SPLITRM";
						break;
					case 2:
						modrm = "MODRM_SPLITMISC";
						break;
					case 3:
						modrm = "MODRM_SPLITREG";
						break;
					case 4:
						modrm = "MODRM_FULL";
						break;
				}
				printf("    { %s, %u },\n",
						modrm, decision->modRMDecisions[j].instructionIDs);
			}
			printf("  } },\n");
		}
	}

	printf("};\n\n");
}


int main(int argc, char **argv)
{
	unsigned int index_table[ARR_SIZE(x86DisassemblerOneByteOpcodes.opcodeDecisions)];
	const struct OpcodeDecision emptyDecision;

	memset((void *)&emptyDecision, 0, sizeof(emptyDecision));

	printf("/* Capstone Disassembly Engine, http://www.capstone-engine.org */\n");
	printf("/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */\n");
	printf("\n");

	index_OpcodeDecision(x86DisassemblerOneByteOpcodes.opcodeDecisions,
			ARR_SIZE(x86DisassemblerOneByteOpcodes.opcodeDecisions),
			&emptyDecision, index_table,
			"x86DisassemblerOneByteOpcodes",
			"index_x86DisassemblerOneByteOpcodes");

	index_OpcodeDecision(x86DisassemblerTwoByteOpcodes.opcodeDecisions,
			ARR_SIZE(x86DisassemblerTwoByteOpcodes.opcodeDecisions),
			&emptyDecision, index_table,
			"x86DisassemblerTwoByteOpcodes",
			"index_x86DisassemblerTwoByteOpcodes");

	index_OpcodeDecision(x86DisassemblerThreeByte38Opcodes.opcodeDecisions,
			ARR_SIZE(x86DisassemblerThreeByte38Opcodes.opcodeDecisions),
			&emptyDecision, index_table,
			"x86DisassemblerThreeByte38Opcodes",
			"index_x86DisassemblerThreeByte38Opcodes");

	index_OpcodeDecision(x86DisassemblerThreeByte3AOpcodes.opcodeDecisions,
			ARR_SIZE(x86DisassemblerThreeByte3AOpcodes.opcodeDecisions),
			&emptyDecision, index_table,
			"x86DisassemblerThreeByte3AOpcodes",
			"index_x86DisassemblerThreeByte3AOpcodes");

#ifndef CAPSTONE_X86_REDUCE
	index_OpcodeDecision(x86DisassemblerXOP8Opcodes.opcodeDecisions,
			ARR_SIZE(x86DisassemblerXOP8Opcodes.opcodeDecisions),
			&emptyDecision, index_table,
			"x86DisassemblerXOP8Opcodes",
			"index_x86DisassemblerXOP8Opcodes");

	index_OpcodeDecision(x86DisassemblerXOP9Opcodes.opcodeDecisions,
			ARR_SIZE(x86DisassemblerXOP9Opcodes.opcodeDecisions),
			&emptyDecision, index_table,
			"x86DisassemblerXOP9Opcodes",
			"index_x86DisassemblerXOP9Opcodes");

	index_OpcodeDecision(x86DisassemblerXOPAOpcodes.opcodeDecisions,
			ARR_SIZE(x86DisassemblerXOPAOpcodes.opcodeDecisions),
			&emptyDecision, index_table,
			"x86DisassemblerXOPAOpcodes",
			"index_x86DisassemblerXOPAOpcodes");

	index_OpcodeDecision(x86Disassembler3DNowOpcodes.opcodeDecisions,
			ARR_SIZE(x86Disassembler3DNowOpcodes.opcodeDecisions),
			&emptyDecision, index_table,
			"x86Disassembler3DNowOpcodes",
			"index_x86Disassembler3DNowOpcodes");
#endif

	return 0;
}
