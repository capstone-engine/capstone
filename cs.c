/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <capstone.h>

#include "cs_priv.h"

#include "MCRegisterInfo.h"

#include "utils.h"

cs_err (*arch_init[MAX_ARCH])(cs_struct *) = { NULL };
cs_err (*arch_option[MAX_ARCH]) (cs_struct*, cs_opt_type, size_t value);
void (*arch_destroy[MAX_ARCH]) (cs_struct*);

unsigned int all_arch = 0;


unsigned int cs_version(int *major, int *minor)
{
	if (major != NULL && minor != NULL) {
		*major = CS_API_MAJOR;
		*minor = CS_API_MINOR;
	}

	return (CS_API_MAJOR << 8) + CS_API_MINOR;
}

bool cs_support(cs_arch arch)
{
	if (arch == CS_ARCH_ALL)
		return all_arch == ((1 << CS_ARCH_ARM) | (1 << CS_ARCH_ARM64) |
				(1 << CS_ARCH_MIPS) | (1 << CS_ARCH_X86) |
				(1 << CS_ARCH_PPC));

	return all_arch & (1 << arch);
}

cs_err cs_errno(csh handle)
{
	if (!handle)
		return CS_ERR_CSH;

	cs_struct *ud = (cs_struct *)(uintptr_t)handle;

	return ud->errnum;
}

cs_err cs_open(cs_arch arch, cs_mode mode, csh *handle)
{
	cs_struct *ud;

	ud = calloc(1, sizeof(*ud));
	if (!ud) {
		// memory insufficient
		return CS_ERR_MEM;
	}

	if (arch < CS_ARCH_MAX && arch_init[ud->arch]) {
		ud->errnum = CS_ERR_OK;
		ud->arch = arch;
		ud->mode = mode;
		ud->big_endian = mode & CS_MODE_BIG_ENDIAN;
		ud->reg_name = NULL;
		ud->detail = CS_OPT_ON;	// by default break instruction into details

		arch_init[ud->arch](ud);
	} else {
		*handle = 0;
		return CS_ERR_ARCH;
	}

	*handle = (uintptr_t)ud;

	return CS_ERR_OK;
}

cs_err cs_close(csh handle)
{
	if (!handle)
		return CS_ERR_CSH;

	cs_struct *ud = (cs_struct *)(uintptr_t)handle;

	switch (ud->arch) {
		case CS_ARCH_X86:
			break;
		case CS_ARCH_ARM:
		case CS_ARCH_MIPS:
		case CS_ARCH_ARM64:
		case CS_ARCH_PPC:
			free(ud->printer_info);
			break;
		default:	// unsupported architecture
			return CS_ERR_HANDLE;
	}

	memset(ud, 0, sizeof(*ud));
	free(ud);

	if (arch_destroy[ud->arch])
		arch_destroy[ud->arch](ud);

	return CS_ERR_OK;
}

#define MIN(x, y) ((x) < (y) ? (x) : (y))

// fill insn with mnemonic & operands info
static void fill_insn(cs_struct *handle, cs_insn *insn, char *buffer, MCInst *mci,
		PostPrinter_t postprinter, const uint8_t *code)
{
	if (handle->detail) {
		// avoiding copy insn->detail
		memcpy(insn, &mci->flat_insn, sizeof(*insn) - sizeof(insn->detail));

		// NOTE: copy details in 2 chunks, since union is always put at address divisible by 8
		// copy from @regs_read until @arm
		memcpy(insn->detail, (void *)(&(mci->flat_insn)) + offsetof(cs_insn_flat, regs_read),
				offsetof(cs_detail, arm) - offsetof(cs_detail, regs_read));
		// then copy from @arm until end
		memcpy((void *)(insn->detail) + offsetof(cs_detail, arm), (void *)(&(mci->flat_insn)) + offsetof(cs_insn_flat, arm),
				sizeof(cs_detail) - offsetof(cs_detail, arm));
	} else {
		insn->address = mci->address;
		insn->size = mci->insn_size;
	}

	// fill the instruction bytes
	memcpy(insn->bytes, code, MIN(sizeof(insn->bytes), insn->size));

	// map internal instruction opcode to public insn ID
	if (handle->insn_id)
		handle->insn_id(insn, MCInst_getOpcode(mci), handle->detail);

	// alias instruction might have ID saved in OpcodePub
	if (MCInst_getOpcodePub(mci))
		insn->id = MCInst_getOpcodePub(mci);

	// post printer handles some corner cases (hacky)
	if (postprinter)
		postprinter((csh)handle, insn, buffer);

	// fill in mnemonic & operands
	// find first space or tab
	char *sp = buffer;
	for (sp = buffer; *sp; sp++)
		if (*sp == ' '||*sp == '\t')
			break;
	if (*sp) {
		*sp = '\0';
		// find the next non-space char
		sp++;
		for (; ((*sp == ' ') || (*sp == '\t')); sp++);
		strncpy(insn->op_str, sp, sizeof(insn->op_str) - 1);
		insn->op_str[sizeof(insn->op_str) - 1] = '\0';
	} else
		insn->op_str[0] = '\0';

	strncpy(insn->mnemonic, buffer, sizeof(insn->mnemonic) - 1);
	insn->mnemonic[sizeof(insn->mnemonic) - 1] = '\0';
}

cs_err cs_option(csh ud, cs_opt_type type, size_t value)
{
	cs_struct *handle = (cs_struct *)(uintptr_t)ud;
	if (!handle)
		return CS_ERR_CSH;

	if (type == CS_OPT_DETAIL) {
		handle->detail = value;
		return CS_ERR_OK;
	}

	return arch_option[handle->arch](handle, type, value);
}

// dynamicly allocate memory to contain disasm insn
// NOTE: caller must free() the allocated memory itself to avoid memory leaking
size_t cs_disasm_ex(csh ud, const uint8_t *buffer, size_t size, uint64_t offset, size_t count, cs_insn **insn)
{
	cs_struct *handle = (cs_struct *)(uintptr_t)ud;
	MCInst mci;
	uint16_t insn_size;
	size_t c = 0, f = 0;
	cs_insn insn_cache[64];
	void *total = NULL;
	size_t total_size = 0;

	if (!handle) {
		// FIXME: how to handle this case:
		// handle->errnum = CS_ERR_HANDLE;
		return 0;
	}

	handle->errnum = CS_ERR_OK;

	memset(insn_cache, 0, sizeof(insn_cache));

	while (size > 0) {
		MCInst_Init(&mci);
		mci.csh = handle;

		bool r = handle->disasm(ud, buffer, size, &mci, &insn_size, offset, handle->getinsn_info);
		if (r) {
			SStream ss;
			SStream_Init(&ss);

			// relative branches need to know the address & size of current insn
			mci.insn_size = insn_size;
			mci.address = offset;

			if (handle->detail) {
				// save all the information for non-detailed mode
				mci.flat_insn.address = offset;
				mci.flat_insn.size = insn_size;
				// allocate memory for @detail pointer
				insn_cache[f].detail = calloc(1, sizeof(cs_detail));
			}

			handle->printer(&mci, &ss, handle->printer_info);

			fill_insn(handle, &insn_cache[f], ss.buffer, &mci, handle->post_printer, buffer);

			f++;

			if (f == ARR_SIZE(insn_cache)) {
				// resize total to contain newly disasm insns
				total_size += sizeof(insn_cache);
				void *tmp = realloc(total, total_size);
				if (tmp == NULL) {	// insufficient memory
					free(total);
					handle->errnum = CS_ERR_MEM;
					return 0;
				}

				total = tmp;
				memcpy(total + total_size - sizeof(insn_cache), insn_cache, sizeof(insn_cache));
				// reset f back to 0
				f = 0;
			}

			c++;
			buffer += insn_size;
			size -= insn_size;
			offset += insn_size;

			if (count > 0 && c == count)
				break;
		} else	{
			// encounter a broken instruction
			// XXX: TODO: JOXEAN continue here
			break;
		}
	}

	if (f) {
		// resize total to contain newly disasm insns
		void *tmp = realloc(total, total_size + f * sizeof(insn_cache[0]));
		if (tmp == NULL) {	// insufficient memory
			free(total);
			handle->errnum = CS_ERR_MEM;
			return 0;
		}

		total = tmp;
		memcpy(total + total_size, insn_cache, f * sizeof(insn_cache[0]));
	}

	*insn = total;

	return c;
}

void cs_free(cs_insn *insn, size_t count)
{
	size_t i;

	// free all detail pointers
	for (i = 0; i < count; i++)
		free(insn[i].detail);

	// then free pointer to cs_insn array
	free(insn);
}

// return friendly name of regiser in a string
const char *cs_reg_name(csh ud, unsigned int reg)
{
	cs_struct *handle = (cs_struct *)(uintptr_t)ud;

	if (!handle || handle->reg_name == NULL) {
		return NULL;
	}

	return handle->reg_name(ud, reg);
}

const char *cs_insn_name(csh ud, unsigned int insn)
{
	cs_struct *handle = (cs_struct *)(uintptr_t)ud;

	if (!handle || handle->insn_name == NULL) {
		return NULL;
	}

	return handle->insn_name(ud, insn);
}

static bool arr_exist(unsigned char *arr, unsigned char max, unsigned int id)
{
	int i;

	for (i = 0; i < max; i++) {
		if (arr[i] == id)
			return true;
	}

	return false;
}

bool cs_insn_group(csh ud, cs_insn *insn, unsigned int group_id)
{
	if (!ud)
		return false;

	cs_struct *handle = (cs_struct *)(uintptr_t)ud;

	if (!handle->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return false;
	}

	return arr_exist(insn->detail->groups, insn->detail->groups_count, group_id);
}

bool cs_reg_read(csh ud, cs_insn *insn, unsigned int reg_id)
{
	if (!ud)
		return false;

	cs_struct *handle = (cs_struct *)(uintptr_t)ud;

	if (!handle->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return false;
	}

	return arr_exist(insn->detail->regs_read, insn->detail->regs_read_count, reg_id);
}

bool cs_reg_write(csh ud, cs_insn *insn, unsigned int reg_id)
{
	if (!ud)
		return false;

	cs_struct *handle = (cs_struct *)(uintptr_t)ud;

	if (!handle->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return false;
	}

	return arr_exist(insn->detail->regs_write, insn->detail->regs_write_count, reg_id);
}

int cs_op_count(csh ud, cs_insn *insn, unsigned int op_type)
{
	if (!ud)
		return -1;

	cs_struct *handle = (cs_struct *)(uintptr_t)ud;
	unsigned int count = 0, i;

	handle->errnum = CS_ERR_OK;

	switch (handle->arch) {
		default:
			handle->errnum = CS_ERR_HANDLE;
			return -1;
		case CS_ARCH_ARM:
			for (i = 0; i < insn->detail->arm.op_count; i++)
				if (insn->detail->arm.operands[i].type == op_type)
					count++;
			break;
		case CS_ARCH_ARM64:
			for (i = 0; i < insn->detail->arm64.op_count; i++)
				if (insn->detail->arm64.operands[i].type == op_type)
					count++;
			break;
		case CS_ARCH_X86:
			for (i = 0; i < insn->detail->x86.op_count; i++)
				if (insn->detail->x86.operands[i].type == op_type)
					count++;
			break;
		case CS_ARCH_MIPS:
			for (i = 0; i < insn->detail->mips.op_count; i++)
				if (insn->detail->mips.operands[i].type == op_type)
					count++;
			break;
		case CS_ARCH_PPC:
			for (i = 0; i < insn->detail->ppc.op_count; i++)
				if (insn->detail->ppc.operands[i].type == op_type)
					count++;
			break;
	}

	return count;
}

int cs_op_index(csh ud, cs_insn *insn, unsigned int op_type,
		unsigned int post)
{
	if (!ud)
		return -1;

	cs_struct *handle = (cs_struct *)(uintptr_t)ud;
	unsigned int count = 0, i;

	handle->errnum = CS_ERR_OK;

	switch (handle->arch) {
		default:
			handle->errnum = CS_ERR_HANDLE;
			return -1;
		case CS_ARCH_ARM:
			for (i = 0; i < insn->detail->arm.op_count; i++) {
				if (insn->detail->arm.operands[i].type == op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_ARM64:
			for (i = 0; i < insn->detail->arm64.op_count; i++) {
				if (insn->detail->arm64.operands[i].type == op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_X86:
			for (i = 0; i < insn->detail->x86.op_count; i++) {
				if (insn->detail->x86.operands[i].type == op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_MIPS:
			for (i = 0; i < insn->detail->mips.op_count; i++) {
				if (insn->detail->mips.operands[i].type == op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_PPC:
			for (i = 0; i < insn->detail->ppc.op_count; i++) {
				if (insn->detail->ppc.operands[i].type == op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
	}

	return -1;
}
