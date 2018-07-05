/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh, 2018 */

#ifdef CAPSTONE_HAS_NEO

#include <string.h>

#include "../../cs_priv.h"
#include "../../utils.h"

#include "NEOMapping.h"

#ifndef CAPSTONE_DIET
static cs_neo insns[256] = {
#include "NEOMappingInsn.inc"
};
#endif

// look for opsize of @id in @insns, given its size in @max.
// return -1 if not found
int neo_insn_opsize(unsigned int id)
{
	if (id >= 256)
		return -1;

	if (insns[id].fee == 255)
		// unused opcode
		return -1;

	return insns[id].op_size;
}

// fill in details
void NEO_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	insn->id = id;
#ifndef CAPSTONE_DIET
	if (id < 256 && insns[id].fee != 255) {
		if (h->detail) {
			memcpy(&insn->detail->neo, &insns[id], sizeof(insns[id]));
		}
	}
#endif
}

#ifndef CAPSTONE_DIET
static name_map insn_name_maps[] = {
	{ NEO_INS_PUSH0, "push0" },
	{ NEO_INS_PUSHBYTES1, "pushbytes1" },
	{ NEO_INS_PUSHBYTES2, "pushbytes2" },
	{ NEO_INS_PUSHBYTES3, "pushbytes3" },
	{ NEO_INS_PUSHBYTES4, "pushbytes4" },
	{ NEO_INS_PUSHBYTES5, "pushbytes5" },
	{ NEO_INS_PUSHBYTES6, "pushbytes6" },
	{ NEO_INS_PUSHBYTES7, "pushbytes7" },
	{ NEO_INS_PUSHBYTES8, "pushbytes8" },
	{ NEO_INS_PUSHBYTES9, "pushbytes9" },
	{ NEO_INS_PUSHBYTES10, "pushbytes10" },
	{ NEO_INS_PUSHBYTES11, "pushbytes11" },
	{ NEO_INS_PUSHBYTES12, "pushbytes12" },
	{ NEO_INS_PUSHBYTES13, "pushbytes13" },
	{ NEO_INS_PUSHBYTES14, "pushbytes14" },
	{ NEO_INS_PUSHBYTES15, "pushbytes15" },
	{ NEO_INS_PUSHBYTES16, "pushbytes16" },
	{ NEO_INS_PUSHBYTES17, "pushbytes17" },
	{ NEO_INS_PUSHBYTES18, "pushbytes18" },
	{ NEO_INS_PUSHBYTES19, "pushbytes19" },
	{ NEO_INS_PUSHBYTES20, "pushbytes20" },
	{ NEO_INS_PUSHBYTES21, "pushbytes21" },
	{ NEO_INS_PUSHBYTES22, "pushbytes22" },
	{ NEO_INS_PUSHBYTES23, "pushbytes23" },
	{ NEO_INS_PUSHBYTES24, "pushbytes24" },
	{ NEO_INS_PUSHBYTES25, "pushbytes25" },
	{ NEO_INS_PUSHBYTES26, "pushbytes26" },
	{ NEO_INS_PUSHBYTES27, "pushbytes27" },
	{ NEO_INS_PUSHBYTES28, "pushbytes28" },
	{ NEO_INS_PUSHBYTES29, "pushbytes29" },
	{ NEO_INS_PUSHBYTES30, "pushbytes30" },
	{ NEO_INS_PUSHBYTES31, "pushbytes31" },
	{ NEO_INS_PUSHBYTES32, "pushbytes32" },
	{ NEO_INS_PUSHBYTES33, "pushbytes33" },
	{ NEO_INS_PUSHBYTES34, "pushbytes34" },
	{ NEO_INS_PUSHBYTES35, "pushbytes35" },
	{ NEO_INS_PUSHBYTES36, "pushbytes36" },
	{ NEO_INS_PUSHBYTES37, "pushbytes37" },
	{ NEO_INS_PUSHBYTES38, "pushbytes38" },
	{ NEO_INS_PUSHBYTES39, "pushbytes39" },
	{ NEO_INS_PUSHBYTES40, "pushbytes40" },
	{ NEO_INS_PUSHBYTES41, "pushbytes41" },
	{ NEO_INS_PUSHBYTES42, "pushbytes42" },
	{ NEO_INS_PUSHBYTES43, "pushbytes43" },
	{ NEO_INS_PUSHBYTES44, "pushbytes44" },
	{ NEO_INS_PUSHBYTES45, "pushbytes45" },
	{ NEO_INS_PUSHBYTES46, "pushbytes46" },
	{ NEO_INS_PUSHBYTES47, "pushbytes47" },
	{ NEO_INS_PUSHBYTES48, "pushbytes48" },
	{ NEO_INS_PUSHBYTES49, "pushbytes49" },
	{ NEO_INS_PUSHBYTES50, "pushbytes50" },
	{ NEO_INS_PUSHBYTES51, "pushbytes51" },
	{ NEO_INS_PUSHBYTES52, "pushbytes52" },
	{ NEO_INS_PUSHBYTES53, "pushbytes53" },
	{ NEO_INS_PUSHBYTES54, "pushbytes54" },
	{ NEO_INS_PUSHBYTES55, "pushbytes55" },
	{ NEO_INS_PUSHBYTES56, "pushbytes56" },
	{ NEO_INS_PUSHBYTES57, "pushbytes57" },
	{ NEO_INS_PUSHBYTES58, "pushbytes58" },
	{ NEO_INS_PUSHBYTES59, "pushbytes59" },
	{ NEO_INS_PUSHBYTES60, "pushbytes60" },
	{ NEO_INS_PUSHBYTES61, "pushbytes61" },
	{ NEO_INS_PUSHBYTES62, "pushbytes62" },
	{ NEO_INS_PUSHBYTES63, "pushbytes63" },
	{ NEO_INS_PUSHBYTES64, "pushbytes64" },
	{ NEO_INS_PUSHBYTES65, "pushbytes65" },
	{ NEO_INS_PUSHBYTES66, "pushbytes66" },
	{ NEO_INS_PUSHBYTES67, "pushbytes67" },
	{ NEO_INS_PUSHBYTES68, "pushbytes68" },
	{ NEO_INS_PUSHBYTES69, "pushbytes69" },
	{ NEO_INS_PUSHBYTES70, "pushbytes70" },
	{ NEO_INS_PUSHBYTES71, "pushbytes71" },
	{ NEO_INS_PUSHBYTES72, "pushbytes72" },
	{ NEO_INS_PUSHBYTES73, "pushbytes73" },
	{ NEO_INS_PUSHBYTES74, "pushbytes74" },
	{ NEO_INS_PUSHBYTES75, "pushbytes75" },
	{ NEO_INS_PUSHDATA1, "pushdata1" },
	{ NEO_INS_PUSHDATA2, "pushdata2" },
	{ NEO_INS_PUSHDATA4, "pushdata4" },
	{ NEO_INS_PUSHM1, "pushm1" },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_PUSH1, "push1" },
	{ NEO_INS_PUSH2, "push2" },
	{ NEO_INS_PUSH3, "push3" },
	{ NEO_INS_PUSH4, "push4" },
	{ NEO_INS_PUSH5, "push5" },
	{ NEO_INS_PUSH6, "push6" },
	{ NEO_INS_PUSH7, "push7" },
	{ NEO_INS_PUSH8, "push8" },
	{ NEO_INS_PUSH9, "push9" },
	{ NEO_INS_PUSH10, "push10" },
	{ NEO_INS_PUSH11, "push11" },
	{ NEO_INS_PUSH12, "push12" },
	{ NEO_INS_PUSH13, "push13" },
	{ NEO_INS_PUSH14, "push14" },
	{ NEO_INS_PUSH15, "push15" },
	{ NEO_INS_PUSH16, "push16" },
	{ NEO_INS_NOP, "nop" },
	{ NEO_INS_JMP, "jmp" },
	{ NEO_INS_JMPIF, "jmpif" },
	{ NEO_INS_JMPIFNOT, "jmpifnot" },
	{ NEO_INS_CALL, "call" },
	{ NEO_INS_RET, "ret" },
	{ NEO_INS_APPCALL, "appcall" },
	{ NEO_INS_SYSCALL, "syscall" },
	{ NEO_INS_TAILCALL, "tailcall" },
	{ NEO_INS_DUPFROMALTSTACK, "dupfromaltstack" },
	{ NEO_INS_TOALTSTACK, "toaltstack" },
	{ NEO_INS_FROMALTSTACK, "fromaltstack" },
	{ NEO_INS_XDROP, "xdrop" },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_XSWAP, "xswap" },
	{ NEO_INS_XTUCK, "xtuck" },
	{ NEO_INS_DEPTH, "depth" },
	{ NEO_INS_DROP, "drop" },
	{ NEO_INS_DUP, "dup" },
	{ NEO_INS_NIP, "nip" },
	{ NEO_INS_OVER, "over" },
	{ NEO_INS_PICK, "pick" },
	{ NEO_INS_ROLL, "roll" },
	{ NEO_INS_ROT, "rot" },
	{ NEO_INS_SWAP, "swap" },
	{ NEO_INS_TUCK, "tuck" },
	{ NEO_INS_CAT, "cat" },
	{ NEO_INS_SUBSTR, "substr" },
	{ NEO_INS_LEFT, "left" },
	{ NEO_INS_RIGHT, "right" },
	{ NEO_INS_SIZE, "size" },
	{ NEO_INS_INVERT, "invert" },
	{ NEO_INS_AND, "and" },
	{ NEO_INS_OR, "or" },
	{ NEO_INS_XOR, "xor" },
	{ NEO_INS_EQUAL, "equal" },
	{ NEO_INS_OP_EQUALVERIFY, "op_equalverify" },
	{ NEO_INS_OP_RESERVED1, "op_reserved1" },
	{ NEO_INS_OP_RESERVED2, "op_reserved2" },
	{ NEO_INS_INC, "inc" },
	{ NEO_INS_DEC, "dec" },
	{ NEO_INS_SIGN, "sign" },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_NEGATE, "negate" },
	{ NEO_INS_ABS, "abs" },
	{ NEO_INS_NOT, "not" },
	{ NEO_INS_NZ, "nz" },
	{ NEO_INS_ADD, "add" },
	{ NEO_INS_SUB, "sub" },
	{ NEO_INS_MUL, "mul" },
	{ NEO_INS_DIV, "div" },
	{ NEO_INS_MOD, "mod" },
	{ NEO_INS_SHL, "shl" },
	{ NEO_INS_SHR, "shr" },
	{ NEO_INS_BOOLAND, "booland" },
	{ NEO_INS_BOOLOR, "boolor" },
	{ NEO_INS_NUMEQUAL, "numequal" },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_NUMNOTEQUAL, "numnotequal" },
	{ NEO_INS_LT, "lt" },
	{ NEO_INS_GT, "gt" },
	{ NEO_INS_LTE, "lte" },
	{ NEO_INS_GTE, "gte" },
	{ NEO_INS_MIN, "min" },
	{ NEO_INS_MAX, "max" },
	{ NEO_INS_WITHIN, "within" },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_SHA1, "sha1" },
	{ NEO_INS_SHA256, "sha256" },
	{ NEO_INS_HASH160, "hash160" },
	{ NEO_INS_HASH256, "hash256" },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_CHECKSIG, "checksig" },
	{ NEO_INS_VERIFY, "verify" },
	{ NEO_INS_CHECKMULTISIG, "checkmultisig" },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_ARRAYSIZE, "arraysize" },
	{ NEO_INS_PACK, "pack" },
	{ NEO_INS_UNPACK, "unpack" },
	{ NEO_INS_PICKITEM, "pickitem" },
	{ NEO_INS_SETITEM, "setitem" },
	{ NEO_INS_NEWARRAY, "newarray" },
	{ NEO_INS_NEWSTRUCT, "newstruct" },
	{ NEO_INS_NEWMAP, "newmap" },
	{ NEO_INS_APPEND, "append" },
	{ NEO_INS_REVERSE, "reverse" },
	{ NEO_INS_REMOVE, "remove" },
	{ NEO_INS_HASKEY, "haskey" },
	{ NEO_INS_KEYS, "keys" },
	{ NEO_INS_VALUES, "values" },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_THROW, "throw" },
	{ NEO_INS_THROWIFNOT, "throwifnot" },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
	{ NEO_INS_INVALID, NULL },
};
#endif

const char *NEO_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id >= ARR_SIZE(insn_name_maps))
		return NULL;
	else
		return insn_name_maps[id].name;
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static name_map group_name_maps[] = {
	// generic groups
	{ NEO_GRP_INVALID, NULL },
	{ NEO_GRP_JUMP,	"jump" },
	// special groups
	{ NEO_GRP_MATH,	"math" },
	{ NEO_GRP_STACK_WRITE, "stack_write" },
	{ NEO_GRP_STACK_READ, "stack_read" },
};
#endif

const char *NEO_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}
#endif
