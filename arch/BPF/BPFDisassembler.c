/* Capstone Disassembly Engine */
/* BPF Backend by david942j <david942j@gmail.com>, 2019 */

#ifdef CAPSTONE_HAS_BPF

#include <string.h>
#include <stddef.h> // offsetof macro

#include "../../cs_priv.h"

#include "BPFConstants.h"
#include "BPFDisassembler.h"
#include "BPFMapping.h"

static uint16_t read_u16(cs_struct *ud, const uint8_t *code)
{
	if (MODE_IS_BIG_ENDIAN(ud->mode))
		return (code[0] << 8 | code[1]);
	else
		return (code[1] << 8 | code[0]);
}

static uint32_t read_u32(cs_struct *ud, const uint8_t *code)
{
	if (MODE_IS_BIG_ENDIAN(ud->mode))
		return (code[3] << 0) |
			(code[2] << 8) |
			(code[1] << 16) |
			((uint32_t) code[0] << 24);
	else
		return ((uint32_t) code[3] << 24) |
			(code[2] << 16) |
			(code[1] << 8) |
			(code[0] << 0);
}

static bpf_internal *alloc_bpf_internal(size_t code_len)
{
	if (code_len < 8)
		return NULL;
	return cs_mem_malloc(sizeof(bpf_internal));
}

// Fetch a cBPF structure from code
static bpf_internal* fetch_cbpf(cs_struct *ud, const uint8_t *code,
		size_t code_len)
{
	bpf_internal *bpf;

	bpf	= alloc_bpf_internal(code_len);
	if (bpf == NULL)
		return NULL;

	bpf->op = read_u16(ud, code);
	bpf->jt = *(code + 2);
	bpf->jf = *(code + 3);
	bpf->k = read_u32(ud, code + 4);
	return bpf;
}

// Fetch an eBPF structure from code
static bpf_internal* fetch_ebpf(cs_struct *ud, const uint8_t *code,
		size_t code_len)
{
	bpf_internal *bpf;

	bpf = alloc_bpf_internal(code_len);
	if (bpf == NULL)
		return NULL;

	bpf->op = (uint16_t)code[0];
	bpf->dst = *(code + 1) & 0xf;
	bpf->src = (*(code + 1) & 0xf0) >> 4;
	bpf->offset = read_u16(ud, code + 2);
	bpf->k = read_u32(ud, code + 4);
	return bpf;
}

static bool getInstruction(cs_struct *ud, MCInst *MI, bpf_internal *bpf,
		uint64_t address)
{
	cs_detail *detail;
	uint8_t opcode;

	detail = MI->flat_insn->detail;
	// initialize detail
	if (detail) {
		memset(detail, 0, offsetof(cs_detail, bpf) + sizeof(cs_bpf));
	}

	opcode = bpf->op;

	MCInst_clear(MI);
	MI->address = address;
	MCInst_setOpcodePub(MI, opcode);

#ifndef CAPSTONE_DIET
 #define PUSH_GROUP(grp) do { \
		detail->groups[detail->groups_count] = grp; \
		detail->groups_count++; \
	} while(0)
#else
 #define PUSH_GROUP
#endif

	switch (BPF_CLASS(bpf->op)) {
		default:	// will never happen
			break;
		case BPF_CLASS_LD:
			if (detail) {
				PUSH_GROUP(BPF_GRP_LOAD);
			}
			break;
		case BPF_CLASS_LDX:
			if (detail) {
				PUSH_GROUP(BPF_GRP_LOAD);
			}
			break;
		case BPF_CLASS_ST:
			if (detail) {
				PUSH_GROUP(BPF_GRP_STORE);
			}
			break;
		case BPF_CLASS_STX:
			if (detail) {
				PUSH_GROUP(BPF_GRP_STORE);
			}
			break;
		case BPF_CLASS_ALU:
			if (detail) {
				PUSH_GROUP(BPF_GRP_ALU);
			}
			break;
		case BPF_CLASS_JMP:
			if (detail) {
				bpf_insn_group grp = BPF_GRP_JUMP;

				if (EBPF_MODE(ud)) {
					// TODO: use BPF_INSN_CALL / BPF_INSN_RETURN_R0 on MI to check
					if (opcode == 0x85)
						grp = BPF_GRP_CALL;
					else if (opcode == 0x95)
						grp = BPF_GRP_RETURN;
				}
				PUSH_GROUP(grp);
			}
			break;
		case BPF_CLASS_RET:
			// this class in eBPF is reserved.
			if (EBPF_MODE(ud))
				return false;
			if (detail) {
				PUSH_GROUP(BPF_GRP_RETURN);
			}
		// BPF_CLASS_MISC and BPF_CLASS_ALU64 have exactly same value
		case BPF_CLASS_MISC:
		/* case BPF_CLASS_ALU64: */
			if (EBPF_MODE(ud)) {
			}
			else {
				if (opcode & 0x80)
					MCInst_setOpcode(MI, BPF_INS_TXA);
				else
					MCInst_setOpcode(MI, BPF_INS_TAX);
			}
			if (detail) {
				if (EBPF_MODE(ud))
					PUSH_GROUP(BPF_GRP_ALU); // ALU64 in eBPF
				else
					PUSH_GROUP(BPF_GRP_MISC);
			}
	}
#undef PUSH_GROUP
	return true;
}

bool BPF_getInstruction(csh ud, const uint8_t *code, size_t code_len,
		MCInst *instr, uint16_t *size, uint64_t address, void *info)
{
	cs_struct *cs;
	bpf_internal *bpf;

	cs = (cs_struct*)ud;
	if (cs->mode & CS_MODE_BPF_EXTENDED)
		bpf = fetch_ebpf(cs, code, code_len);
	else
		bpf = fetch_cbpf(cs, code, code_len);
	if (bpf == NULL)
		return false;
	if (!getInstruction((cs_struct*)ud, instr, bpf, address))
		return false;

	cs_mem_free(bpf);

	*size = 8;
	return true;
}

#endif
