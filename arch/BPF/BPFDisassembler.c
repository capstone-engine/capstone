/* Capstone Disassembly Engine */
/* BPF Backend by david942j <david942j@gmail.com>, 2019 */

#ifdef CAPSTONE_HAS_BPF

#include "../../cs_priv.h"

#include "BPFDisassembler.h"

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
	return false;
}

bool CBPF_getInstruction(csh ud, const uint8_t *code, size_t code_len,
		MCInst *instr, uint16_t *size, uint64_t address, void *info)
{
	bpf_internal *bpf;

	bpf = fetch_cbpf((cs_struct*)ud, code, code_len);
	if (bpf == NULL)
		return false;
	if (!getInstruction((cs_struct*)ud, instr, bpf, address))
		return false;
	*size = 8;
	return true;
}

bool EBPF_getInstruction(csh ud, const uint8_t *code, size_t code_len,
		MCInst *instr, uint16_t *size, uint64_t address, void *info)
{
	bpf_internal *bpf;

	bpf	= fetch_ebpf((cs_struct*)ud, code, code_len);
	if (bpf == NULL)
		return false;
	if (!getInstruction((cs_struct*)ud, instr, bpf, address))
		return false;
	*size = 8;
	return true;
}

#endif
