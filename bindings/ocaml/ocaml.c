/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stdio.h>		// debug
#include <string.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>

#include "capstone/capstone.h"

#define ARR_SIZE(a) (sizeof(a)/sizeof(a[0]))


// count the number of positive members in @list
static unsigned int list_count(uint8_t *list, unsigned int max)
{
	unsigned int i;

	for(i = 0; i < max; i++)
		if (list[i] == 0)
			return i;

	return max;
}

CAMLprim value _cs_disasm(cs_arch arch, csh handle, const uint8_t * code, size_t code_len, uint64_t addr, size_t count)
{
	CAMLparam0();
	CAMLlocal5(list, cons, rec_insn, array, tmp);
	CAMLlocal4(arch_info, op_info_val, tmp2, tmp3);
	cs_insn *insn;
	size_t c;

	list = Val_emptylist;

	c = cs_disasm(handle, code, code_len, addr, count, &insn);
	if (c) {
		//printf("Found %lu insn, addr: %lx\n", c, addr);
		uint64_t j;
		for (j = c; j > 0; j--) {
			unsigned int lcount, i;
			cons = caml_alloc(2, 0);

			rec_insn = caml_alloc(10, 0);
			Store_field(rec_insn, 0, Val_int(insn[j-1].id));
			Store_field(rec_insn, 1, Val_int(insn[j-1].address));
			Store_field(rec_insn, 2, Val_int(insn[j-1].size));

			// copy raw bytes of instruction
			lcount = insn[j-1].size;
			if (lcount) {
				array = caml_alloc(lcount, 0);
				for (i = 0; i < lcount; i++) {
					Store_field(array, i, Val_int(insn[j-1].bytes[i]));
				}
			} else
				array = Atom(0);	// empty list
			Store_field(rec_insn, 3, array);

			Store_field(rec_insn, 4, caml_copy_string(insn[j-1].mnemonic));
			Store_field(rec_insn, 5, caml_copy_string(insn[j-1].op_str));

			// copy read registers
			if (insn[0].detail) {
				lcount = (insn[j-1]).detail->regs_read_count;
				if (lcount) {
					array = caml_alloc(lcount, 0);
					for (i = 0; i < lcount; i++) {
						Store_field(array, i, Val_int(insn[j-1].detail->regs_read[i]));
					}
				} else
					array = Atom(0);	// empty list
			} else
				array = Atom(0);	// empty list
			Store_field(rec_insn, 6, array);

			if (insn[0].detail) {
				lcount = (insn[j-1]).detail->regs_write_count;
				if (lcount) {
					array = caml_alloc(lcount, 0);
					for (i = 0; i < lcount; i++) {
						Store_field(array, i, Val_int(insn[j-1].detail->regs_write[i]));
					}
				} else
					array = Atom(0);	// empty list
			} else
				array = Atom(0);	// empty list
			Store_field(rec_insn, 7, array);

			if (insn[0].detail) {
				lcount = (insn[j-1]).detail->groups_count;
				if (lcount) {
					array = caml_alloc(lcount, 0);
					for (i = 0; i < lcount; i++) {
						Store_field(array, i, Val_int(insn[j-1].detail->groups[i]));
					}
				} else
					array = Atom(0);	// empty list
			} else
				array = Atom(0);	// empty list
			Store_field(rec_insn, 8, array);

			if (insn[j-1].detail) {
				switch(arch) {
					case CS_ARCH_ARM:
						arch_info = caml_alloc(1, 0);

						op_info_val = caml_alloc(10, 0);
						Store_field(op_info_val, 0, Val_bool(insn[j-1].detail->arm.usermode));
						Store_field(op_info_val, 1, Val_int(insn[j-1].detail->arm.vector_size));
						Store_field(op_info_val, 2, Val_int(insn[j-1].detail->arm.vector_data));
						Store_field(op_info_val, 3, Val_int(insn[j-1].detail->arm.cps_mode));
						Store_field(op_info_val, 4, Val_int(insn[j-1].detail->arm.cps_flag));
						Store_field(op_info_val, 5, Val_int(insn[j-1].detail->arm.cc));
						Store_field(op_info_val, 6, Val_bool(insn[j-1].detail->arm.update_flags));
						Store_field(op_info_val, 7, Val_bool(insn[j-1].detail->arm.writeback));
						Store_field(op_info_val, 8, Val_int(insn[j-1].detail->arm.mem_barrier));

						lcount = insn[j-1].detail->arm.op_count;
						if (lcount > 0) {
							array = caml_alloc(lcount, 0);
							for (i = 0; i < lcount; i++) {
								tmp2 = caml_alloc(5, 0);
								switch(insn[j-1].detail->arm.operands[i].type) {
									case ARM_OP_REG:
									case ARM_OP_SYSREG:
										tmp = caml_alloc(1, 1);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->arm.operands[i].reg));
										break;
									case ARM_OP_CIMM:
										tmp = caml_alloc(1, 2);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->arm.operands[i].imm));
										break;
									case ARM_OP_PIMM:
										tmp = caml_alloc(1, 3);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->arm.operands[i].imm));
										break;
									case ARM_OP_IMM:
										tmp = caml_alloc(1, 4);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->arm.operands[i].imm));
										break;
									case ARM_OP_FP:
										tmp = caml_alloc(1, 5);
										Store_field(tmp, 0, caml_copy_double(insn[j-1].detail->arm.operands[i].fp));
										break;
									case ARM_OP_MEM:
										tmp = caml_alloc(1, 6);
										tmp3 = caml_alloc(5, 0);
										Store_field(tmp3, 0, Val_int(insn[j-1].detail->arm.operands[i].mem.base));
										Store_field(tmp3, 1, Val_int(insn[j-1].detail->arm.operands[i].mem.index));
										Store_field(tmp3, 2, Val_int(insn[j-1].detail->arm.operands[i].mem.scale));
										Store_field(tmp3, 3, Val_int(insn[j-1].detail->arm.operands[i].mem.disp));
										Store_field(tmp3, 4, Val_int(insn[j-1].detail->arm.operands[i].mem.lshift));
										Store_field(tmp, 0, tmp3);
										break;
									case ARM_OP_SETEND:
										tmp = caml_alloc(1, 7);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->arm.operands[i].setend));
										break;
									default: break;
								}
								tmp3 = caml_alloc(2, 0);
								Store_field(tmp3, 0, Val_int(insn[j-1].detail->arm.operands[i].shift.type));
								Store_field(tmp3, 1, Val_int(insn[j-1].detail->arm.operands[i].shift.value));
								Store_field(tmp2, 0, Val_int(insn[j-1].detail->arm.operands[i].vector_index));
								Store_field(tmp2, 1, tmp3);
								Store_field(tmp2, 2, tmp);
								Store_field(tmp2, 3, Val_bool(insn[j-1].detail->arm.operands[i].subtracted));
								Store_field(tmp2, 4, Val_int(insn[j-1].detail->arm.operands[i].access));
								Store_field(tmp2, 5, Val_int(insn[j-1].detail->arm.operands[i].neon_lane));
								Store_field(array, i, tmp2);
							}
						} else	// empty list
							array = Atom(0);

						Store_field(op_info_val, 9, array);

						// finally, insert this into arch_info
						Store_field(arch_info, 0, op_info_val);

						Store_field(rec_insn, 9, arch_info);

						break;
					case CS_ARCH_ARM64:
						arch_info = caml_alloc(1, 1);

						op_info_val = caml_alloc(4, 0);
						Store_field(op_info_val, 0, Val_int(insn[j-1].detail->arm64.cc));
						Store_field(op_info_val, 1, Val_bool(insn[j-1].detail->arm64.update_flags));
						Store_field(op_info_val, 2, Val_bool(insn[j-1].detail->arm64.writeback));

						lcount = insn[j-1].detail->arm64.op_count;
						if (lcount > 0) {
							array = caml_alloc(lcount, 0);
							for (i = 0; i < lcount; i++) {
								tmp2 = caml_alloc(6, 0);
								switch(insn[j-1].detail->arm64.operands[i].type) {
									case ARM64_OP_REG:
										tmp = caml_alloc(1, 1);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->arm64.operands[i].reg));
										break;
									case ARM64_OP_CIMM:
										tmp = caml_alloc(1, 2);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->arm64.operands[i].imm));
										break;
									case ARM64_OP_IMM:
										tmp = caml_alloc(1, 3);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->arm64.operands[i].imm));
										break;
									case ARM64_OP_FP:
										tmp = caml_alloc(1, 4);
										Store_field(tmp, 0, caml_copy_double(insn[j-1].detail->arm64.operands[i].fp));
										break;
									case ARM64_OP_MEM:
										tmp = caml_alloc(1, 5);
										tmp3 = caml_alloc(3, 0);
										Store_field(tmp3, 0, Val_int(insn[j-1].detail->arm64.operands[i].mem.base));
										Store_field(tmp3, 1, Val_int(insn[j-1].detail->arm64.operands[i].mem.index));
										Store_field(tmp3, 2, Val_int(insn[j-1].detail->arm64.operands[i].mem.disp));
										Store_field(tmp, 0, tmp3);
										break;
									case ARM64_OP_REG_MRS:
										tmp = caml_alloc(1, 6);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->arm64.operands[i].reg));
										break;
									case ARM64_OP_REG_MSR:
										tmp = caml_alloc(1, 7);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->arm64.operands[i].reg));
										break;
									case ARM64_OP_PSTATE:
										tmp = caml_alloc(1, 8);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->arm64.operands[i].pstate));
										break;
									case ARM64_OP_SYS:
										tmp = caml_alloc(1, 9);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->arm64.operands[i].sys));
										break;
									case ARM64_OP_PREFETCH:
										tmp = caml_alloc(1, 10);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->arm64.operands[i].prefetch));
										break;
									case ARM64_OP_BARRIER:
										tmp = caml_alloc(1, 11);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->arm64.operands[i].barrier));
										break;
									default: break;
								}
								tmp3 = caml_alloc(2, 0);
								Store_field(tmp3, 0, Val_int(insn[j-1].detail->arm64.operands[i].shift.type));
								Store_field(tmp3, 1, Val_int(insn[j-1].detail->arm64.operands[i].shift.value));

								Store_field(tmp2, 0, Val_int(insn[j-1].detail->arm64.operands[i].vector_index));
								Store_field(tmp2, 1, Val_int(insn[j-1].detail->arm64.operands[i].vas));
								Store_field(tmp2, 2, tmp3);
								Store_field(tmp2, 3, Val_int(insn[j-1].detail->arm64.operands[i].ext));
								Store_field(tmp2, 4, tmp);

								Store_field(array, i, tmp2);
							}
						} else	// empty array
							array = Atom(0);

						Store_field(op_info_val, 3, array);

						// finally, insert this into arch_info
						Store_field(arch_info, 0, op_info_val);

						Store_field(rec_insn, 9, arch_info);

						break;
					case CS_ARCH_MIPS:
						arch_info = caml_alloc(1, 2);

						op_info_val = caml_alloc(1, 0);

						lcount = insn[j-1].detail->mips.op_count;
						if (lcount > 0) {
							array = caml_alloc(lcount, 0);
							for (i = 0; i < lcount; i++) {
								tmp2 = caml_alloc(1, 0);
								switch(insn[j-1].detail->mips.operands[i].type) {
									case MIPS_OP_REG:
										tmp = caml_alloc(1, 1);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->mips.operands[i].reg));
										break;
									case MIPS_OP_IMM:
										tmp = caml_alloc(1, 2);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->mips.operands[i].imm));
										break;
									case MIPS_OP_MEM:
										tmp = caml_alloc(1, 3);
										tmp3 = caml_alloc(2, 0);
										Store_field(tmp3, 0, Val_int(insn[j-1].detail->mips.operands[i].mem.base));
										Store_field(tmp3, 1, Val_int(insn[j-1].detail->mips.operands[i].mem.disp));
										Store_field(tmp, 0, tmp3);
										break;
									default: break;
								}
								Store_field(tmp2, 0, tmp);
								Store_field(array, i, tmp2);
							}
						} else	// empty array
							array = Atom(0);

						Store_field(op_info_val, 0, array);

						// finally, insert this into arch_info
						Store_field(arch_info, 0, op_info_val);

						Store_field(rec_insn, 9, arch_info);

						break;
					case CS_ARCH_X86:
						arch_info = caml_alloc(1, 3);

						op_info_val = caml_alloc(17, 0);

						// fill prefix
						lcount = list_count(insn[j-1].detail->x86.prefix, ARR_SIZE(insn[j-1].detail->x86.prefix));
						if (lcount) {
							array = caml_alloc(lcount, 0);
							for (i = 0; i < lcount; i++) {
								Store_field(array, i, Val_int(insn[j-1].detail->x86.prefix[i]));
							}
						} else
							array = Atom(0);
						Store_field(op_info_val, 0, array);

						// fill opcode
						lcount = list_count(insn[j-1].detail->x86.opcode, ARR_SIZE(insn[j-1].detail->x86.opcode));
						if (lcount) {
							array = caml_alloc(lcount, 0);
							for (i = 0; i < lcount; i++) {
								Store_field(array, i, Val_int(insn[j-1].detail->x86.opcode[i]));
							}
						} else
							array = Atom(0);
						Store_field(op_info_val, 1, array);

						Store_field(op_info_val, 2, Val_int(insn[j-1].detail->x86.rex));

						Store_field(op_info_val, 3, Val_int(insn[j-1].detail->x86.addr_size));

						Store_field(op_info_val, 4, Val_int(insn[j-1].detail->x86.modrm));

						Store_field(op_info_val, 5, Val_int(insn[j-1].detail->x86.sib));

						Store_field(op_info_val, 6, Val_int(insn[j-1].detail->x86.disp));

						Store_field(op_info_val, 7, Val_int(insn[j-1].detail->x86.sib_index));

						Store_field(op_info_val, 8, Val_int(insn[j-1].detail->x86.sib_scale));

						Store_field(op_info_val, 9, Val_int(insn[j-1].detail->x86.sib_base));

						Store_field(op_info_val, 10, Val_int(insn[j-1].detail->x86.xop_cc));
						Store_field(op_info_val, 11, Val_int(insn[j-1].detail->x86.sse_cc));
						Store_field(op_info_val, 12, Val_int(insn[j-1].detail->x86.avx_cc));
						Store_field(op_info_val, 13, Val_int(insn[j-1].detail->x86.avx_sae));
						Store_field(op_info_val, 14, Val_int(insn[j-1].detail->x86.avx_rm));
						Store_field(op_info_val, 15, Val_int(insn[j-1].detail->x86.eflags));

						lcount = insn[j-1].detail->x86.op_count;
						if (lcount > 0) {
							array = caml_alloc(lcount, 0);
							for (i = 0; i < lcount; i++) {
								switch(insn[j-1].detail->x86.operands[i].type) {
									case X86_OP_REG:
										tmp = caml_alloc(1, 1);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->x86.operands[i].reg));
										break;
									case X86_OP_IMM:
										tmp = caml_alloc(1, 2);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->x86.operands[i].imm));
										break;
									case X86_OP_MEM:
										tmp = caml_alloc(1, 3);
										tmp2 = caml_alloc(5, 0);
										Store_field(tmp2, 0, Val_int(insn[j-1].detail->x86.operands[i].mem.segment));
										Store_field(tmp2, 1, Val_int(insn[j-1].detail->x86.operands[i].mem.base));
										Store_field(tmp2, 2, Val_int(insn[j-1].detail->x86.operands[i].mem.index));
										Store_field(tmp2, 3, Val_int(insn[j-1].detail->x86.operands[i].mem.scale));
										Store_field(tmp2, 4, Val_int(insn[j-1].detail->x86.operands[i].mem.disp));

										Store_field(tmp, 0, tmp2);
										break;
									default:
										tmp = caml_alloc(1, 0); // X86_OP_INVALID
										break;
								}

								tmp2 = caml_alloc(5, 0);
								Store_field(tmp2, 0, tmp);
								Store_field(tmp2, 1, Val_int(insn[j-1].detail->x86.operands[i].size));
								Store_field(tmp2, 2, Val_int(insn[j-1].detail->x86.operands[i].access));
								Store_field(tmp2, 3, Val_int(insn[j-1].detail->x86.operands[i].avx_bcast));
								Store_field(tmp2, 4, Val_int(insn[j-1].detail->x86.operands[i].avx_zero_opmask));
								Store_field(array, i, tmp2);
							}
						} else	// empty array
							array = Atom(0);
						Store_field(op_info_val, 16, array);

						// finally, insert this into arch_info
						Store_field(arch_info, 0, op_info_val);

						Store_field(rec_insn, 9, arch_info);
						break;

					case CS_ARCH_PPC:
						arch_info = caml_alloc(1, 4);

						op_info_val = caml_alloc(4, 0);

						Store_field(op_info_val, 0, Val_int(insn[j-1].detail->ppc.bc));
						Store_field(op_info_val, 1, Val_int(insn[j-1].detail->ppc.bh));
						Store_field(op_info_val, 2, Val_bool(insn[j-1].detail->ppc.update_cr0));

						lcount = insn[j-1].detail->ppc.op_count;
						if (lcount > 0) {
							array = caml_alloc(lcount, 0);
							for (i = 0; i < lcount; i++) {
								tmp2 = caml_alloc(1, 0);
								switch(insn[j-1].detail->ppc.operands[i].type) {
									case PPC_OP_REG:
										tmp = caml_alloc(1, 1);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->ppc.operands[i].reg));
										break;
									case PPC_OP_IMM:
										tmp = caml_alloc(1, 2);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->ppc.operands[i].imm));
										break;
									case PPC_OP_MEM:
										tmp = caml_alloc(1, 3);
										tmp3 = caml_alloc(2, 0);
										Store_field(tmp3, 0, Val_int(insn[j-1].detail->ppc.operands[i].mem.base));
										Store_field(tmp3, 1, Val_int(insn[j-1].detail->ppc.operands[i].mem.disp));
										Store_field(tmp, 0, tmp3);
										break;
									case PPC_OP_CRX:
										tmp = caml_alloc(1, 4);
										tmp3 = caml_alloc(3, 0);
										Store_field(tmp3, 0, Val_int(insn[j-1].detail->ppc.operands[i].crx.scale));
										Store_field(tmp3, 1, Val_int(insn[j-1].detail->ppc.operands[i].crx.reg));
										Store_field(tmp3, 2, Val_int(insn[j-1].detail->ppc.operands[i].crx.cond));
										Store_field(tmp, 0, tmp3);
										break;
									default: break;
								}
								Store_field(tmp2, 0, tmp);
								Store_field(array, i, tmp2);
							}
						} else	// empty array
							array = Atom(0);

						Store_field(op_info_val, 3, array);

						// finally, insert this into arch_info
						Store_field(arch_info, 0, op_info_val);

						Store_field(rec_insn, 9, arch_info);

						break;

					case CS_ARCH_SPARC:
						arch_info = caml_alloc(1, 5);

						op_info_val = caml_alloc(3, 0);

						Store_field(op_info_val, 0, Val_int(insn[j-1].detail->sparc.cc));
						Store_field(op_info_val, 1, Val_int(insn[j-1].detail->sparc.hint));

						lcount = insn[j-1].detail->sparc.op_count;
						if (lcount > 0) {
							array = caml_alloc(lcount, 0);
							for (i = 0; i < lcount; i++) {
								tmp2 = caml_alloc(1, 0);
								switch(insn[j-1].detail->sparc.operands[i].type) {
									case SPARC_OP_REG:
										tmp = caml_alloc(1, 1);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->sparc.operands[i].reg));
										break;
									case SPARC_OP_IMM:
										tmp = caml_alloc(1, 2);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->sparc.operands[i].imm));
										break;
									case SPARC_OP_MEM:
										tmp = caml_alloc(1, 3);
										tmp3 = caml_alloc(3, 0);
										Store_field(tmp3, 0, Val_int(insn[j-1].detail->sparc.operands[i].mem.base));
										Store_field(tmp3, 1, Val_int(insn[j-1].detail->sparc.operands[i].mem.index));
										Store_field(tmp3, 2, Val_int(insn[j-1].detail->sparc.operands[i].mem.disp));
										Store_field(tmp, 0, tmp3);
										break;
									default: break;
								}
								Store_field(tmp2, 0, tmp);
								Store_field(array, i, tmp2);
							}
						} else	// empty array
							array = Atom(0);

						Store_field(op_info_val, 2, array);

						// finally, insert this into arch_info
						Store_field(arch_info, 0, op_info_val);

						Store_field(rec_insn, 9, arch_info);

						break;

					case CS_ARCH_SYSZ:
						arch_info = caml_alloc(1, 6);

						op_info_val = caml_alloc(2, 0);

						Store_field(op_info_val, 0, Val_int(insn[j-1].detail->sysz.cc));

						lcount = insn[j-1].detail->sysz.op_count;
						if (lcount > 0) {
							array = caml_alloc(lcount, 0);
							for (i = 0; i < lcount; i++) {
								tmp2 = caml_alloc(1, 0);
								switch(insn[j-1].detail->sysz.operands[i].type) {
									case SYSZ_OP_REG:
										tmp = caml_alloc(1, 1);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->sysz.operands[i].reg));
										break;
									case SYSZ_OP_ACREG:
										tmp = caml_alloc(1, 2);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->sysz.operands[i].reg));
										break;
									case SYSZ_OP_IMM:
										tmp = caml_alloc(1, 3);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->sysz.operands[i].imm));
										break;
									case SYSZ_OP_MEM:
										tmp = caml_alloc(1, 4);
										tmp3 = caml_alloc(4, 0);
										Store_field(tmp3, 0, Val_int(insn[j-1].detail->sysz.operands[i].mem.base));
										Store_field(tmp3, 1, Val_int(insn[j-1].detail->sysz.operands[i].mem.index));
										Store_field(tmp3, 2, caml_copy_int64(insn[j-1].detail->sysz.operands[i].mem.length));
										Store_field(tmp3, 3, caml_copy_int64(insn[j-1].detail->sysz.operands[i].mem.disp));
										Store_field(tmp, 0, tmp3);
										break;
									default: break;
								}
								Store_field(tmp2, 0, tmp);
								Store_field(array, i, tmp2);
							}
						} else	// empty array
							array = Atom(0);

						Store_field(op_info_val, 1, array);

						// finally, insert this into arch_info
						Store_field(arch_info, 0, op_info_val);

						Store_field(rec_insn, 9, arch_info);

						break;

					case CS_ARCH_XCORE:
						arch_info = caml_alloc(1, 7);

						op_info_val = caml_alloc(1, 0);

						lcount = insn[j-1].detail->xcore.op_count;
						if (lcount > 0) {
							array = caml_alloc(lcount, 0);
							for (i = 0; i < lcount; i++) {
								tmp2 = caml_alloc(1, 0);
								switch(insn[j-1].detail->xcore.operands[i].type) {
									case XCORE_OP_REG:
										tmp = caml_alloc(1, 1);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->xcore.operands[i].reg));
										break;
									case XCORE_OP_IMM:
										tmp = caml_alloc(1, 2);
										Store_field(tmp, 0, Val_int(insn[j-1].detail->xcore.operands[i].imm));
										break;
									case XCORE_OP_MEM:
										tmp = caml_alloc(1, 3);
										tmp3 = caml_alloc(4, 0);
										Store_field(tmp3, 0, Val_int(insn[j-1].detail->xcore.operands[i].mem.base));
										Store_field(tmp3, 1, Val_int(insn[j-1].detail->xcore.operands[i].mem.index));
										Store_field(tmp3, 2, caml_copy_int64(insn[j-1].detail->xcore.operands[i].mem.disp));
										Store_field(tmp3, 3, caml_copy_int64(insn[j-1].detail->xcore.operands[i].mem.direct));
										Store_field(tmp, 0, tmp3);
										break;
									default: break;
								}
								Store_field(tmp2, 0, tmp);
								Store_field(array, i, tmp2);
							}
						} else	// empty array
							array = Atom(0);

						Store_field(op_info_val, 0, array);

						// finally, insert this into arch_info
						Store_field(arch_info, 0, op_info_val);

						Store_field(rec_insn, 9, arch_info);

						break;

					case CS_ARCH_M680X:
						arch_info = caml_alloc(1, 8);

						op_info_val = caml_alloc(2, 0); // struct cs_m680x
						Store_field(op_info_val, 0, Val_int(insn[j-1].detail->m680x.flags));

						lcount = insn[j-1].detail->m680x.op_count;
						if (lcount > 0) {
							array = caml_alloc(lcount, 0);
							for (i = 0; i < lcount; i++) {
								tmp2 = caml_alloc(3, 0); // m680x_op
								switch(insn[j-1].detail->m680x.operands[i].type) {
									case M680X_OP_IMMEDIATE:
										tmp = caml_alloc(1, 1); // imm
										Store_field(tmp, 0, Val_int(insn[j-1].detail->m680x.operands[i].imm));
										break;
									case M680X_OP_REGISTER:
										tmp = caml_alloc(1, 2); // reg
										Store_field(tmp, 0, Val_int(insn[j-1].detail->m680x.operands[i].reg));
										break;
									case M680X_OP_INDEXED:
										tmp = caml_alloc(1, 3);
										tmp3 = caml_alloc(7, 0); // m680x_op_idx
										Store_field(tmp3, 0, Val_int(insn[j-1].detail->m680x.operands[i].idx.base_reg));
										Store_field(tmp3, 1, Val_int(insn[j-1].detail->m680x.operands[i].idx.offset_reg));
										Store_field(tmp3, 2, Val_int(insn[j-1].detail->m680x.operands[i].idx.offset));
										Store_field(tmp3, 3, Val_int(insn[j-1].detail->m680x.operands[i].idx.offset_addr));
										Store_field(tmp3, 4, Val_int(insn[j-1].detail->m680x.operands[i].idx.offset_bits));
										Store_field(tmp3, 5, Val_int(insn[j-1].detail->m680x.operands[i].idx.inc_dec));
										Store_field(tmp3, 6, Val_int(insn[j-1].detail->m680x.operands[i].idx.flags));
										Store_field(tmp, 0, tmp3);
										break;
									case M680X_OP_RELATIVE:
										tmp = caml_alloc(1, 4);
										tmp3 = caml_alloc(2, 0); // m680x_op_rel
										Store_field(tmp3, 0, Val_int(insn[j-1].detail->m680x.operands[i].rel.address));
										Store_field(tmp3, 1, Val_int(insn[j-1].detail->m680x.operands[i].rel.offset));
										Store_field(tmp, 0, tmp3);
										break;
									case M680X_OP_EXTENDED:
										tmp = caml_alloc(1, 5);
										tmp3 = caml_alloc(2, 0); // m680x_op_ext
										Store_field(tmp3, 0, Val_int(insn[j-1].detail->m680x.operands[i].ext.address));
										Store_field(tmp3, 1, Val_bool(insn[j-1].detail->m680x.operands[i].ext.indirect));
										Store_field(tmp, 0, tmp3);
										break;
									case M680X_OP_DIRECT:
										tmp = caml_alloc(1, 6); // direct_addr
										Store_field(tmp, 0, Val_int(insn[j-1].detail->m680x.operands[i].direct_addr));
										break;
									case M680X_OP_CONSTANT:
										tmp = caml_alloc(1, 7); // const_val
										Store_field(tmp, 0, Val_int(insn[j-1].detail->m680x.operands[i].const_val));
										break;
									default: break;
								}
								Store_field(tmp2, 0, tmp); // add union
								Store_field(tmp2, 1, Val_int(insn[j-1].detail->m680x.operands[i].size));
								Store_field(tmp2, 2, Val_int(insn[j-1].detail->m680x.operands[i].access));
								Store_field(array, i, tmp2); // add operand to operand array
							}
						} else // empty list
							array = Atom(0);

						Store_field(op_info_val, 1, array);

						// finally, insert this into arch_info
						Store_field(arch_info, 0, op_info_val);

						Store_field(rec_insn, 9, arch_info);

						break;

					default: break;
				}
			}

			Store_field(cons, 0, rec_insn);	// head
			Store_field(cons, 1, list);		// tail
			list = cons;
		}
		cs_free(insn, count);
	}

	// do not free the handle here
	//cs_close(&handle);
    CAMLreturn(list);
}

CAMLprim value ocaml_cs_disasm(value _arch, value _mode, value _code, value _addr, value _count)
{
	CAMLparam5(_arch, _mode, _code, _addr, _count);
	CAMLlocal1(head);
	csh handle;
	cs_arch arch;
	cs_mode mode = 0;
	const uint8_t *code;
	uint64_t addr;
	size_t count, code_len;

	switch (Int_val(_arch)) {
		case 0:
			arch = CS_ARCH_ARM;
			break;
		case 1:
			arch = CS_ARCH_ARM64;
			break;
		case 2:
			arch = CS_ARCH_MIPS;
			break;
		case 3:
			arch = CS_ARCH_X86;
			break;
		case 4:
			arch = CS_ARCH_PPC;
			break;
		case 5:
			arch = CS_ARCH_SPARC;
			break;
		case 6:
			arch = CS_ARCH_SYSZ;
			break;
		case 7:
			arch = CS_ARCH_XCORE;
			break;
		case 8:
			arch = CS_ARCH_M68K;
			break;
		case 9:
			arch = CS_ARCH_TMS320C64X;
			break;
		case 10:
			arch = CS_ARCH_M680X;
			break;
		default:
			caml_invalid_argument("Invalid arch");
			return Val_emptylist;
	}

	while (_mode != Val_emptylist) {
		head = Field(_mode, 0);  /* accessing the head */
		switch (Int_val(head)) {
			case 0:
				mode |= CS_MODE_LITTLE_ENDIAN;
				break;
			case 1:
				mode |= CS_MODE_ARM;
				break;
			case 2:
				mode |= CS_MODE_16;
				break;
			case 3:
				mode |= CS_MODE_32;
				break;
			case 4:
				mode |= CS_MODE_64;
				break;
			case 5:
				mode |= CS_MODE_THUMB;
				break;
			case 6:
				mode |= CS_MODE_MCLASS;
				break;
			case 7:
				mode |= CS_MODE_V8;
				break;
			case 8:
				mode |= CS_MODE_MICRO;
				break;
			case 9:
				mode |= CS_MODE_MIPS3;
				break;
			case 10:
				mode |= CS_MODE_MIPS32R6;
				break;
			case 11:
				mode |= CS_MODE_MIPS2;
				break;
			case 12:
				mode |= CS_MODE_V9;
				break;
			case 13:
				mode |= CS_MODE_BIG_ENDIAN;
				break;
			case 14:
				mode |= CS_MODE_MIPS32;
				break;
			case 15:
				mode |= CS_MODE_MIPS64;
				break;
			case 16:
				mode |= CS_MODE_QPX;
				break;
			case 17:
				mode |= CS_MODE_M680X_6301;
				break;
			case 18:
				mode |= CS_MODE_M680X_6309;
				break;
			case 19:
				mode |= CS_MODE_M680X_6800;
				break;
			case 20:
				mode |= CS_MODE_M680X_6801;
				break;
			case 21:
				mode |= CS_MODE_M680X_6805;
				break;
			case 22:
				mode |= CS_MODE_M680X_6808;
				break;
			case 23:
				mode |= CS_MODE_M680X_6809;
				break;
			case 24:
				mode |= CS_MODE_M680X_6811;
				break;
			case 25:
				mode |= CS_MODE_M680X_CPU12;
				break;
			case 26:
				mode |= CS_MODE_M680X_HCS08;
				break;
			default:
				caml_invalid_argument("Invalid mode");
				return Val_emptylist;
		}
		_mode = Field(_mode, 1);  /* point to the tail for next loop */
	}

	cs_err ret = cs_open(arch, mode, &handle);
	if (ret != CS_ERR_OK) {
		return Val_emptylist;
	}

	code = (uint8_t *)String_val(_code);
	code_len = caml_string_length(_code);
	addr = Int64_val(_addr);
	count = Int64_val(_count);

    CAMLreturn(_cs_disasm(arch, handle, code, code_len, addr, count));
}

CAMLprim value ocaml_cs_disasm_internal(value _arch, value _handle, value _code, value _addr, value _count)
{
	CAMLparam5(_arch, _handle, _code, _addr, _count);
	csh handle;
	cs_arch arch;
	const uint8_t *code;
	uint64_t addr, count, code_len;

	handle = Int64_val(_handle);

	arch = Int_val(_arch);
	code = (uint8_t *)String_val(_code);
	code_len = caml_string_length(_code);
	addr = Int64_val(_addr);
	count = Int64_val(_count);

    CAMLreturn(_cs_disasm(arch, handle, code, code_len, addr, count));
}

CAMLprim value ocaml_open(value _arch, value _mode)
{
	CAMLparam2(_arch, _mode);
	CAMLlocal2(list, head);
	csh handle;
	cs_arch arch;
	cs_mode mode = 0;

	list = Val_emptylist;

	switch (Int_val(_arch)) {
		case 0:
			arch = CS_ARCH_ARM;
			break;
		case 1:
			arch = CS_ARCH_ARM64;
			break;
		case 2:
			arch = CS_ARCH_MIPS;
			break;
		case 3:
			arch = CS_ARCH_X86;
			break;
		case 4:
			arch = CS_ARCH_PPC;
			break;
		case 5:
			arch = CS_ARCH_SPARC;
			break;
		case 6:
			arch = CS_ARCH_SYSZ;
			break;
		case 7:
			arch = CS_ARCH_XCORE;
			break;
		case 8:
			arch = CS_ARCH_M68K;
			break;
		case 9:
			arch = CS_ARCH_TMS320C64X;
			break;
		case 10:
			arch = CS_ARCH_M680X;
			break;
		default:
			caml_invalid_argument("Invalid arch");
			return Val_emptylist;
	}


	while (_mode != Val_emptylist) {
		head = Field(_mode, 0);  /* accessing the head */
		switch (Int_val(head)) {
			case 0:
				mode |= CS_MODE_LITTLE_ENDIAN;
				break;
			case 1:
				mode |= CS_MODE_ARM;
				break;
			case 2:
				mode |= CS_MODE_16;
				break;
			case 3:
				mode |= CS_MODE_32;
				break;
			case 4:
				mode |= CS_MODE_64;
				break;
			case 5:
				mode |= CS_MODE_THUMB;
				break;
			case 6:
				mode |= CS_MODE_MCLASS;
				break;
			case 7:
				mode |= CS_MODE_V8;
				break;
			case 8:
				mode |= CS_MODE_MICRO;
				break;
			case 9:
				mode |= CS_MODE_MIPS3;
				break;
			case 10:
				mode |= CS_MODE_MIPS32R6;
				break;
			case 11:
				mode |= CS_MODE_MIPS2;
				break;
			case 12:
				mode |= CS_MODE_V9;
				break;
			case 13:
				mode |= CS_MODE_BIG_ENDIAN;
				break;
			case 14:
				mode |= CS_MODE_MIPS32;
				break;
			case 15:
				mode |= CS_MODE_MIPS64;
				break;
			case 16:
				mode |= CS_MODE_QPX;
				break;
			case 17:
				mode |= CS_MODE_M680X_6301;
				break;
			case 18:
				mode |= CS_MODE_M680X_6309;
				break;
			case 19:
				mode |= CS_MODE_M680X_6800;
				break;
			case 20:
				mode |= CS_MODE_M680X_6801;
				break;
			case 21:
				mode |= CS_MODE_M680X_6805;
				break;
			case 22:
				mode |= CS_MODE_M680X_6808;
				break;
			case 23:
				mode |= CS_MODE_M680X_6809;
				break;
			case 24:
				mode |= CS_MODE_M680X_6811;
				break;
			case 25:
				mode |= CS_MODE_M680X_CPU12;
				break;
			case 26:
				mode |= CS_MODE_M680X_HCS08;
				break;
			default:
				caml_invalid_argument("Invalid mode");
				return Val_emptylist;
		}
		_mode = Field(_mode, 1);  /* point to the tail for next loop */
	}

	if (cs_open(arch, mode, &handle) != 0)
		CAMLreturn(Val_int(0));

	CAMLlocal1(result);
	result = caml_alloc(1, 0);
	Store_field(result, 0, caml_copy_int64(handle));
	CAMLreturn(result);
}

CAMLprim value ocaml_option(value _handle, value _opt, value _value)
{
	CAMLparam3(_handle, _opt, _value);
	cs_opt_type opt;
	int err;

	switch (Int_val(_opt)) {
		case 0:
			opt = CS_OPT_SYNTAX;
			break;
		case 1:
			opt = CS_OPT_DETAIL;
			break;
		case 2:
			opt = CS_OPT_MODE;
			break;
		case 3:
			opt = CS_OPT_MEM;
			break;
		case 4:
			opt = CS_OPT_SKIPDATA;
			break;
		case 5:
			opt = CS_OPT_SKIPDATA_SETUP;
			break;
		default:
			caml_invalid_argument("Invalid option");
			CAMLreturn(Val_int(CS_ERR_OPTION));
	}

	err = cs_option(Int64_val(_handle), opt, Int64_val(_value));

	CAMLreturn(Val_int(err));
}

CAMLprim value ocaml_register_name(value _handle, value _reg)
{
	const char *name = cs_reg_name(Int64_val(_handle), Int_val(_reg));
	if (!name) {
		caml_invalid_argument("invalid reg_id");
		name = "invalid";
	}

	return caml_copy_string(name);
}

CAMLprim value ocaml_instruction_name(value _handle, value _insn)
{
	const char *name = cs_insn_name(Int64_val(_handle), Int_val(_insn));
	if (!name) {
		caml_invalid_argument("invalid insn_id");
		name = "invalid";
	}

	return caml_copy_string(name);
}

CAMLprim value ocaml_group_name(value _handle, value _insn)
{
	const char *name = cs_group_name(Int64_val(_handle), Int_val(_insn));
	if (!name) {
		caml_invalid_argument("invalid insn_id");
		name = "invalid";
	}

	return caml_copy_string(name);
}

CAMLprim value ocaml_version(void)
{
	int version = cs_version(NULL, NULL);
	return Val_int(version);
}

CAMLprim value ocaml_close(value _handle)
{
	CAMLparam1(_handle);
	csh h;

	h = Int64_val(_handle);

	CAMLreturn(Val_int(cs_close(&h)));
}
