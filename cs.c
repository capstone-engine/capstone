/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <capstone.h>

#include "utils.h"
#include "MCRegisterInfo.h"

#ifdef USE_SYS_DYN_MEM
#define INSN_CACHE_SIZE 32
#else
// reduce stack variable size for kernel/firmware
#define INSN_CACHE_SIZE 8
#endif

cs_err (*arch_init[MAX_ARCH])(cs_struct *) = { NULL };
cs_err (*arch_option[MAX_ARCH]) (cs_struct *, cs_opt_type, size_t value) = { NULL };
void (*arch_destroy[MAX_ARCH]) (cs_struct *) = { NULL };

extern void ARM_enable(void);
extern void AArch64_enable(void);
extern void Mips_enable(void);
extern void X86_enable(void);
extern void PPC_enable(void);

static void archs_enable(void)
{
	static bool initialized = false;

	if (initialized)
		return;

#ifdef CAPSTONE_HAS_ARM
	ARM_enable();
#endif
#ifdef CAPSTONE_HAS_ARM64
	AArch64_enable();
#endif
#ifdef CAPSTONE_HAS_MIPS
	Mips_enable();
#endif
#ifdef CAPSTONE_HAS_X86
	X86_enable();
#endif
#ifdef CAPSTONE_HAS_POWERPC
	PPC_enable();
#endif

	initialized = true;
}

unsigned int all_arch = 0;

#ifdef USE_SYS_DYN_MEM
cs_malloc_t cs_mem_malloc = malloc;
cs_calloc_t cs_mem_calloc = calloc;
cs_realloc_t cs_mem_realloc = realloc;
cs_free_t cs_mem_free = free;
cs_vsnprintf_t cs_vsnprintf = vsnprintf;
#else
cs_malloc_t cs_mem_malloc = NULL;
cs_calloc_t cs_mem_calloc = NULL;
cs_realloc_t cs_mem_realloc = NULL;
cs_free_t cs_mem_free = NULL;
cs_vsnprintf_t cs_vsnprintf = NULL;
#endif

unsigned int cs_version(int *major, int *minor)
{
	archs_enable();

	if (major != NULL && minor != NULL) {
		*major = CS_API_MAJOR;
		*minor = CS_API_MINOR;
	}

	return (CS_API_MAJOR << 8) + CS_API_MINOR;
}

bool cs_support(int query)
{
	archs_enable();

	if (query == CS_ARCH_ALL)
		return all_arch == ((1 << CS_ARCH_ARM) | (1 << CS_ARCH_ARM64) |
				(1 << CS_ARCH_MIPS) | (1 << CS_ARCH_X86) |
				(1 << CS_ARCH_PPC));

	if ((unsigned int)query < CS_ARCH_MAX)
		return all_arch & (1 << query);

	if (query == CS_SUPPORT_DIET) {
#ifdef CAPSTONE_DIET
		return true;
#else
		return false;
#endif
	}

	// unsupported query
	return false;
}

cs_err cs_errno(csh handle)
{
	if (!handle)
		return CS_ERR_CSH;

	struct cs_struct *ud = (struct cs_struct *)(uintptr_t)handle;

	return ud->errnum;
}

const char *cs_strerror(cs_err code)
{
	switch(code) {
		default:
			return "Unknown error code";
		case CS_ERR_OK:
			return "OK (CS_ERR_OK)";
		case CS_ERR_MEM:
			return "Out of memory (CS_ERR_MEM)";
		case CS_ERR_ARCH:
			return "Invalid architecture (CS_ERR_ARCH)";
		case CS_ERR_HANDLE:
			return "Invalid handle (CS_ERR_HANDLE)";
		case CS_ERR_CSH:
			return "Invalid csh (CS_ERR_CSH)";
		case CS_ERR_MODE:
			return "Invalid mode (CS_ERR_MODE)";
		case CS_ERR_OPTION:
			return "Invalid option (CS_ERR_OPTION)";
		case CS_ERR_DETAIL:
			return "Details are unavailable (CS_ERR_DETAIL)";
		case CS_ERR_MEMSETUP:
			return "Dynamic memory management uninitialized (CS_ERR_MEMSETUP)";
		case CS_ERR_VERSION:
			return "Different API version between core & binding (CS_ERR_VERSION)";
		case CS_ERR_DIET:
			return "Information irrelevant in diet engine (CS_ERR_DIET)";
	}
}

cs_err cs_open(cs_arch arch, cs_mode mode, csh *handle)
{
	if (!cs_mem_malloc || !cs_mem_calloc || !cs_mem_realloc || !cs_mem_free || !cs_vsnprintf)
		// Error: before cs_open(), dynamic memory management must be initialized
		// with cs_option(CS_OPT_MEM)
		return CS_ERR_MEMSETUP;

	archs_enable();

	if (arch < CS_ARCH_MAX && arch_init[arch]) {
		struct cs_struct *ud;

		ud = cs_mem_calloc(1, sizeof(*ud));
		if (!ud) {
			// memory insufficient
			return CS_ERR_MEM;
		}

		ud->errnum = CS_ERR_OK;
		ud->arch = arch;
		ud->mode = mode;
		ud->big_endian = mode & CS_MODE_BIG_ENDIAN;
		// by default, do not break instruction into details
		ud->detail = CS_OPT_OFF;

		cs_err err = arch_init[ud->arch](ud);
		if (err) {
			cs_mem_free(ud);
			*handle = 0;
			return err;
		}

		*handle = (uintptr_t)ud;

		return CS_ERR_OK;
	} else {
		*handle = 0;
		return CS_ERR_ARCH;
	}
}

cs_err cs_close(csh *handle)
{
	if (*handle == 0)
		// invalid handle
		return CS_ERR_CSH;

	struct cs_struct *ud = (struct cs_struct *)(*handle);

	if (ud->printer_info)
		cs_mem_free(ud->printer_info);

	// arch_destroy[ud->arch](ud);

	cs_mem_free(ud->insn_cache);
	memset(ud, 0, sizeof(*ud));
	cs_mem_free(ud);

	// invalidate this handle by ZERO out its value.
	// this is to make sure it is unusable after cs_close()
	*handle = 0;

	return CS_ERR_OK;
}

#define MIN(x, y) ((x) < (y) ? (x) : (y))

// fill insn with mnemonic & operands info
static void fill_insn(struct cs_struct *handle, cs_insn *insn, char *buffer, MCInst *mci,
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
		memcpy((void *)((uintptr_t)(insn->detail) + offsetof(cs_detail, arm)),
				(void *)((uintptr_t)(&(mci->flat_insn)) + offsetof(cs_insn_flat, arm)),
				sizeof(cs_detail) - offsetof(cs_detail, arm));
	} else {
		insn->address = mci->address;
		insn->size = (uint16_t)mci->insn_size;
	}

	// fill the instruction bytes
	memcpy(insn->bytes, code, MIN(sizeof(insn->bytes), insn->size));

	// map internal instruction opcode to public insn ID
	if (handle->insn_id)
		handle->insn_id(handle, insn, MCInst_getOpcode(mci));

	// alias instruction might have ID saved in OpcodePub
	if (MCInst_getOpcodePub(mci))
		insn->id = MCInst_getOpcodePub(mci);

	// post printer handles some corner cases (hacky)
	if (postprinter)
		postprinter((csh)handle, insn, buffer);

#ifndef CAPSTONE_DIET
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
#endif
}

cs_err cs_option(csh ud, cs_opt_type type, size_t value)
{
	archs_enable();

	// cs_option() can be called with NULL handle just for CS_OPT_MEM
	// This is supposed to be executed before all other APIs (even cs_open())
	if (type == CS_OPT_MEM) {
		cs_opt_mem *mem = (cs_opt_mem *)value;

		cs_mem_malloc = mem->malloc;
		cs_mem_calloc = mem->calloc;
		cs_mem_realloc = mem->realloc;
		cs_mem_free = mem->free;
		cs_vsnprintf = mem->vsnprintf;

		return CS_ERR_OK;
	}

	struct cs_struct *handle = (struct cs_struct *)(uintptr_t)ud;
	if (!handle)
		return CS_ERR_CSH;

	if (type == CS_OPT_DETAIL) {
		handle->detail = value;
		return CS_ERR_OK;
	}

	return arch_option[handle->arch](handle, type, value);
}

// get previous instruction, which can be in the cache, or in total buffer
static cs_insn *get_prev_insn(cs_insn *cache, unsigned int f, void *total, size_t total_size)
{
	if (f == 0) {
		if (total == NULL)
			return NULL;
		// get the trailing insn from total buffer, which is at
		// the end of the latest cache trunk
		return (cs_insn *)((void*)((uintptr_t)total + total_size - sizeof(cs_insn)));
	} else
		return &cache[f - 1];
}

// dynamicly allocate memory to contain disasm insn
// NOTE: caller must free() the allocated memory itself to avoid memory leaking
size_t cs_disasm_ex(csh ud, const uint8_t *buffer, size_t size, uint64_t offset, size_t count, cs_insn **insn)
{
	struct cs_struct *handle = (struct cs_struct *)(uintptr_t)ud;
	MCInst mci;
	uint16_t insn_size;
	size_t c = 0;
	unsigned int f = 0;
	cs_insn insn_cache[INSN_CACHE_SIZE];
	void *total = NULL;
	size_t total_size = 0;
	bool r;

	if (!handle) {
		// FIXME: how to handle this case:
		// handle->errnum = CS_ERR_HANDLE;
		return 0;
	}

	handle->errnum = CS_ERR_OK;

	// reset previous prefix for X86
	handle->prev_prefix = 0;

	memset(insn_cache, 0, sizeof(insn_cache));

	while (size > 0) {
		MCInst_Init(&mci);
		mci.csh = handle;

		r = handle->disasm(ud, buffer, size, &mci, &insn_size, offset, handle->getinsn_info);
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
				insn_cache[f].detail = cs_mem_calloc(1, sizeof(cs_detail));
			}

			handle->printer(&mci, &ss, handle->printer_info);

			fill_insn(handle, &insn_cache[f], ss.buffer, &mci, handle->post_printer, buffer);

			if (!handle->check_combine || !handle->check_combine(handle, &insn_cache[f])) {
				f++;

				if (f == ARR_SIZE(insn_cache)) {
					// resize total to contain newly disasm insns
					void *tmp;

					total_size += (sizeof(cs_insn) * INSN_CACHE_SIZE);
					tmp = cs_mem_realloc(total, total_size);
					if (tmp == NULL) {	// insufficient memory
						cs_mem_free(total);
						handle->errnum = CS_ERR_MEM;
						return 0;
					}

					total = tmp;
					memcpy((void*)((uintptr_t)total + total_size - sizeof(insn_cache)), insn_cache, sizeof(insn_cache));

					// reset f back to 0
					f = 0;
				}

				c++;
			} else {
				// combine this instruction with previous prefix "instruction"
				cs_insn *prev = get_prev_insn(insn_cache, f, total, total_size);
				handle->combine(handle, &insn_cache[f], prev);
			}

			buffer += insn_size;
			size -= insn_size;
			offset += insn_size;

			if (count > 0) {
				// x86 hacky
				if (!handle->prev_prefix) {
					if (c == count)
						break;
				} else {
					// only combine 1 prefix with regular instruction
					if (c == count + 1) {
						// the last insn is redundant
						c--;
						f--;
						// free allocated detail pointer of the last redundant instruction
						if (handle->detail)
							cs_mem_free(insn_cache[f].detail);

						break;
					}
				}
			}
		} else	{
			// encounter a broken instruction
			// XXX: TODO: JOXEAN continue here
			break;
		}
	}

	if (f) {
		// resize total to contain newly disasm insns
		void *tmp = cs_mem_realloc(total, total_size + f * sizeof(insn_cache[0]));
		if (tmp == NULL) {	// insufficient memory
			cs_mem_free(total);
			handle->errnum = CS_ERR_MEM;
			return 0;
		}

		total = tmp;
		memcpy((void*)((uintptr_t)total + total_size), insn_cache, f * sizeof(insn_cache[0]));

	}

	*insn = total;

	return c;
}

void cs_free(cs_insn *insn, size_t count)
{
	size_t i;

	// free all detail pointers
	for (i = 0; i < count; i++)
		cs_mem_free(insn[i].detail);

	// then free pointer to cs_insn array
	cs_mem_free(insn);
}

// return friendly name of regiser in a string
const char *cs_reg_name(csh ud, unsigned int reg)
{
	struct cs_struct *handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle || handle->reg_name == NULL) {
		return NULL;
	}

	return handle->reg_name(ud, reg);
}

const char *cs_insn_name(csh ud, unsigned int insn)
{
	struct cs_struct *handle = (struct cs_struct *)(uintptr_t)ud;

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

	struct cs_struct *handle = (struct cs_struct *)(uintptr_t)ud;
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

	struct cs_struct *handle = (struct cs_struct *)(uintptr_t)ud;
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

	struct cs_struct *handle = (struct cs_struct *)(uintptr_t)ud;
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

	struct cs_struct *handle = (struct cs_struct *)(uintptr_t)ud;
	if (!handle->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return -1;
	}

	unsigned int count = 0, i;

	handle->errnum = CS_ERR_OK;

	switch (handle->arch) {
		default:
			handle->errnum = CS_ERR_HANDLE;
			return -1;
		case CS_ARCH_ARM:
			for (i = 0; i < insn->detail->arm.op_count; i++)
				if (insn->detail->arm.operands[i].type == (arm_op_type)op_type)
					count++;
			break;
		case CS_ARCH_ARM64:
			for (i = 0; i < insn->detail->arm64.op_count; i++)
				if (insn->detail->arm64.operands[i].type == (arm64_op_type)op_type)
					count++;
			break;
		case CS_ARCH_X86:
			for (i = 0; i < insn->detail->x86.op_count; i++)
				if (insn->detail->x86.operands[i].type == (x86_op_type)op_type)
					count++;
			break;
		case CS_ARCH_MIPS:
			for (i = 0; i < insn->detail->mips.op_count; i++)
				if (insn->detail->mips.operands[i].type == (mips_op_type)op_type)
					count++;
			break;
		case CS_ARCH_PPC:
			for (i = 0; i < insn->detail->ppc.op_count; i++)
				if (insn->detail->ppc.operands[i].type == (ppc_op_type)op_type)
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

	struct cs_struct *handle = (struct cs_struct *)(uintptr_t)ud;
	if (!handle->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return -1;
	}

	unsigned int count = 0, i;

	handle->errnum = CS_ERR_OK;

	switch (handle->arch) {
		default:
			handle->errnum = CS_ERR_HANDLE;
			return -1;
		case CS_ARCH_ARM:
			for (i = 0; i < insn->detail->arm.op_count; i++) {
				if (insn->detail->arm.operands[i].type == (arm_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_ARM64:
			for (i = 0; i < insn->detail->arm64.op_count; i++) {
				if (insn->detail->arm64.operands[i].type == (arm64_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_X86:
			for (i = 0; i < insn->detail->x86.op_count; i++) {
				if (insn->detail->x86.operands[i].type == (x86_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_MIPS:
			for (i = 0; i < insn->detail->mips.op_count; i++) {
				if (insn->detail->mips.operands[i].type == (mips_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_PPC:
			for (i = 0; i < insn->detail->ppc.op_count; i++) {
				if (insn->detail->ppc.operands[i].type == (ppc_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
	}

	return -1;
}
