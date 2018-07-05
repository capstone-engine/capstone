/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh, 2018 */

#include <string.h>

#include "NEODisassembler.h"
#include "NEOMapping.h"

static short opcodes[256] = {
	NEO_INS_PUSH0,
	NEO_INS_PUSHBYTES1,
	NEO_INS_PUSHBYTES2,
	NEO_INS_PUSHBYTES3,
	NEO_INS_PUSHBYTES4,
	NEO_INS_PUSHBYTES5,
	NEO_INS_PUSHBYTES6,
	NEO_INS_PUSHBYTES7,
	NEO_INS_PUSHBYTES8,
	NEO_INS_PUSHBYTES9,
	NEO_INS_PUSHBYTES10,
	NEO_INS_PUSHBYTES11,
	NEO_INS_PUSHBYTES12,
	NEO_INS_PUSHBYTES13,
	NEO_INS_PUSHBYTES14,
	NEO_INS_PUSHBYTES15,
	NEO_INS_PUSHBYTES16,
	NEO_INS_PUSHBYTES17,
	NEO_INS_PUSHBYTES18,
	NEO_INS_PUSHBYTES19,
	NEO_INS_PUSHBYTES20,
	NEO_INS_PUSHBYTES21,
	NEO_INS_PUSHBYTES22,
	NEO_INS_PUSHBYTES23,
	NEO_INS_PUSHBYTES24,
	NEO_INS_PUSHBYTES25,
	NEO_INS_PUSHBYTES26,
	NEO_INS_PUSHBYTES27,
	NEO_INS_PUSHBYTES28,
	NEO_INS_PUSHBYTES29,
	NEO_INS_PUSHBYTES30,
	NEO_INS_PUSHBYTES31,
	NEO_INS_PUSHBYTES32,
	NEO_INS_PUSHBYTES33,
	NEO_INS_PUSHBYTES34,
	NEO_INS_PUSHBYTES35,
	NEO_INS_PUSHBYTES36,
	NEO_INS_PUSHBYTES37,
	NEO_INS_PUSHBYTES38,
	NEO_INS_PUSHBYTES39,
	NEO_INS_PUSHBYTES40,
	NEO_INS_PUSHBYTES41,
	NEO_INS_PUSHBYTES42,
	NEO_INS_PUSHBYTES43,
	NEO_INS_PUSHBYTES44,
	NEO_INS_PUSHBYTES45,
	NEO_INS_PUSHBYTES46,
	NEO_INS_PUSHBYTES47,
	NEO_INS_PUSHBYTES48,
	NEO_INS_PUSHBYTES49,
	NEO_INS_PUSHBYTES50,
	NEO_INS_PUSHBYTES51,
	NEO_INS_PUSHBYTES52,
	NEO_INS_PUSHBYTES53,
	NEO_INS_PUSHBYTES54,
	NEO_INS_PUSHBYTES55,
	NEO_INS_PUSHBYTES56,
	NEO_INS_PUSHBYTES57,
	NEO_INS_PUSHBYTES58,
	NEO_INS_PUSHBYTES59,
	NEO_INS_PUSHBYTES60,
	NEO_INS_PUSHBYTES61,
	NEO_INS_PUSHBYTES62,
	NEO_INS_PUSHBYTES63,
	NEO_INS_PUSHBYTES64,
	NEO_INS_PUSHBYTES65,
	NEO_INS_PUSHBYTES66,
	NEO_INS_PUSHBYTES67,
	NEO_INS_PUSHBYTES68,
	NEO_INS_PUSHBYTES69,
	NEO_INS_PUSHBYTES70,
	NEO_INS_PUSHBYTES71,
	NEO_INS_PUSHBYTES72,
	NEO_INS_PUSHBYTES73,
	NEO_INS_PUSHBYTES74,
	NEO_INS_PUSHBYTES75,
	NEO_INS_PUSHDATA1,
	NEO_INS_PUSHDATA2,
	NEO_INS_PUSHDATA4,
	NEO_INS_PUSHM1,
	-1,
	NEO_INS_PUSH1,
	NEO_INS_PUSH2,
	NEO_INS_PUSH3,
	NEO_INS_PUSH4,
	NEO_INS_PUSH5,
	NEO_INS_PUSH6,
	NEO_INS_PUSH7,
	NEO_INS_PUSH8,
	NEO_INS_PUSH9,
	NEO_INS_PUSH10,
	NEO_INS_PUSH11,
	NEO_INS_PUSH12,
	NEO_INS_PUSH13,
	NEO_INS_PUSH14,
	NEO_INS_PUSH15,
	NEO_INS_PUSH16,
	NEO_INS_NOP,
	NEO_INS_JMP,
	NEO_INS_JMPIF,
	NEO_INS_JMPIFNOT,
	NEO_INS_CALL,
	NEO_INS_RET,
	NEO_INS_APPCALL,
	NEO_INS_SYSCALL,
	NEO_INS_TAILCALL,
	NEO_INS_DUPFROMALTSTACK,
	NEO_INS_TOALTSTACK,
	NEO_INS_FROMALTSTACK,
	NEO_INS_XDROP,
	-1,
	-1,
	-1,
	-1,
	NEO_INS_XSWAP,
	NEO_INS_XTUCK,
	NEO_INS_DEPTH,
	NEO_INS_DROP,
	NEO_INS_DUP,
	NEO_INS_NIP,
	NEO_INS_OVER,
	NEO_INS_PICK,
	NEO_INS_ROLL,
	NEO_INS_ROT,
	NEO_INS_SWAP,
	NEO_INS_TUCK,
	NEO_INS_CAT,
	NEO_INS_SUBSTR,
	NEO_INS_LEFT,
	NEO_INS_RIGHT,
	NEO_INS_SIZE,
	NEO_INS_INVERT,
	NEO_INS_AND,
	NEO_INS_OR,
	NEO_INS_XOR,
	NEO_INS_EQUAL,
	NEO_INS_OP_EQUALVERIFY,
	NEO_INS_OP_RESERVED1,
	NEO_INS_OP_RESERVED2,
	NEO_INS_INC,
	NEO_INS_DEC,
	NEO_INS_SIGN,
	-1,
	NEO_INS_NEGATE,
	NEO_INS_ABS,
	NEO_INS_NOT,
	NEO_INS_NZ,
	NEO_INS_ADD,
	NEO_INS_SUB,
	NEO_INS_MUL,
	NEO_INS_DIV,
	NEO_INS_MOD,
	NEO_INS_SHL,
	NEO_INS_SHR,
	NEO_INS_BOOLAND,
	NEO_INS_BOOLOR,
	NEO_INS_NUMEQUAL,
	-1,
	NEO_INS_NUMNOTEQUAL,
	NEO_INS_LT,
	NEO_INS_GT,
	NEO_INS_LTE,
	NEO_INS_GTE,
	NEO_INS_MIN,
	NEO_INS_MAX,
	NEO_INS_WITHIN,
	-1,
	NEO_INS_SHA1,
	NEO_INS_SHA256,
	NEO_INS_HASH160,
	NEO_INS_HASH256,
	-1,
	NEO_INS_CHECKSIG,
	NEO_INS_VERIFY,
	NEO_INS_CHECKMULTISIG,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	NEO_INS_ARRAYSIZE,
	NEO_INS_PACK,
	NEO_INS_UNPACK,
	NEO_INS_PICKITEM,
	NEO_INS_SETITEM,
	NEO_INS_NEWARRAY,
	NEO_INS_NEWSTRUCT,
	NEO_INS_NEWMAP,
	NEO_INS_APPEND,
	NEO_INS_REVERSE,
	NEO_INS_REMOVE,
	NEO_INS_HASKEY,
	NEO_INS_KEYS,
	NEO_INS_VALUES,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	NEO_INS_THROW,
	NEO_INS_THROWIFNOT,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
};

bool NEO_getInstruction(csh ud, const uint8_t *code, size_t code_len,
	MCInst *MI, uint16_t *size, uint64_t address, void *inst_info)
{
	unsigned char opcode;

	if (code_len == 0)
		return false;

	opcode = code[0];
	if (opcodes[opcode] == -1) {
		// invalid opcode
		return false;
	}

	// valid opcode
	MI->address = address;
	MI->OpcodePub = MI->Opcode = opcode;

	*size = neo_insn_opsize(opcode) + 1;
	if (*size > 1) {
		if (code_len < *size) {
			// not enough data
			return false;
		}

		// copy operand
		memcpy(MI->neo_data, code + 1, *size - 1);
	}

	if (MI->flat_insn->detail) {
		memset(&MI->flat_insn->detail->neo, 0, sizeof(cs_neo));
		NEO_get_insn_id((cs_struct *)ud, MI->flat_insn, opcode);

		MI->flat_insn->detail->regs_read_count = 0;
		MI->flat_insn->detail->regs_write_count = 0;
		MI->flat_insn->detail->groups_count = 0;

		if (MI->flat_insn->detail->neo.pop) {
			MI->flat_insn->detail->groups[MI->flat_insn->detail->groups_count] = NEO_GRP_STACK_READ;
			MI->flat_insn->detail->groups_count++;
		}

		if (MI->flat_insn->detail->neo.push) {
			MI->flat_insn->detail->groups[MI->flat_insn->detail->groups_count] = NEO_GRP_STACK_WRITE;
			MI->flat_insn->detail->groups_count++;
		}

		// setup groups
#if 0
		switch(opcode) {
			default:
				break;
			case NEO_INS_ADD:
			case NEO_INS_MUL:
				MI->flat_insn->detail->groups[MI->flat_insn->detail->groups_count] = NEO_GRP_MATH;
				MI->flat_insn->detail->groups_count++;
				break;

			case NEO_INS_MSTORE:
			case NEO_INS_MSTORE8:
			case NEO_INS_CALLDATACOPY:
			case NEO_INS_CODECOPY:
			case NEO_INS_EXTCODECOPY:
				MI->flat_insn->detail->groups[MI->flat_insn->detail->groups_count] = NEO_GRP_MEM_WRITE;
				MI->flat_insn->detail->groups_count++;
				break;

		}
#endif
	}

	return true;
}
