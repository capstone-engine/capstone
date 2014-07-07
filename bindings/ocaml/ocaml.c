/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stdio.h>		// debug
#include <string.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>

#include "../../include/capstone.h"

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

	list = Val_emptylist;

	size_t c = cs_disasm_ex(handle, code, code_len, addr, count, &insn);

	if (c) {
		//printf("Found %lu insn, addr: %lx\n", c, addr);
		uint64_t j;
		for (j = c; j > 0; j--) {
			unsigned int lcount, i;
			cons = caml_alloc(2, 0);

			rec_insn = caml_alloc(13, 0);
			Store_field(rec_insn, 0, Val_int(insn[j-1].id));
			Store_field(rec_insn, 1, Val_int(insn[j-1].address));
			Store_field(rec_insn, 2, Val_int(insn[j-1].size));
			
			Store_field(rec_insn, 4, caml_copy_string(insn[j-1].mnemonic));
			Store_field(rec_insn, 5, caml_copy_string(insn[j-1].op_str));

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


			// copy read registers
			lcount = (insn[j-1]).detail->regs_read_count;
			if (lcount) {
				array = caml_alloc(lcount, 0);
				for (i = 0; i < lcount; i++) {
					Store_field(array, i, Val_int(insn[j-1].detail->regs_read[i]));
				}
			} else
				array = Atom(0);	// empty list
			Store_field(rec_insn, 6, array);
			Store_field(rec_insn, 7, Val_int(lcount));

			lcount = (insn[j-1]).detail->regs_write_count;
			if (lcount) {
				array = caml_alloc(lcount, 0);
				for (i = 0; i < lcount; i++) {
					Store_field(array, i, Val_int(insn[j-1].detail->regs_write[i]));
				}
			} else
				array = Atom(0);	// empty list
			Store_field(rec_insn, 8, array);
			Store_field(rec_insn, 9, Val_int(lcount));


			lcount = (insn[j-1]).detail->groups_count;
			if (lcount) {
				array = caml_alloc(lcount, 0);
				for (i = 0; i < lcount; i++) {
					Store_field(array, i, Val_int(insn[j-1].detail->groups[i]));
				}
			} else
				array = Atom(0);	// empty list
			Store_field(rec_insn, 10, array);
			Store_field(rec_insn, 11, Val_int(lcount));



			if(insn[j-1].detail)
			switch(arch) {
				case CS_ARCH_ARM:
					arch_info = caml_alloc(1, 0);

					op_info_val = caml_alloc(5, 0);
					Store_field(op_info_val, 0, Val_int(insn[j-1].detail->arm.cc));
					Store_field(op_info_val, 1, Val_bool(insn[j-1].detail->arm.update_flags));
					Store_field(op_info_val, 2, Val_bool(insn[j-1].detail->arm.writeback));

					lcount = insn[j-1].detail->arm.op_count;

					Store_field(op_info_val, 3, Val_int(lcount));
					if (lcount > 0) {
						array = caml_alloc(lcount, 0);
						for (i = 0; i < lcount; i++) {
							tmp2 = caml_alloc(2, 0);
							switch(insn[j-1].detail->arm.operands[i].type) {
								case ARM_OP_REG:
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
									tmp3 = caml_alloc(4, 0);
									Store_field(tmp3, 0, Val_int(insn[j-1].detail->arm.operands[i].mem.base));
									Store_field(tmp3, 1, Val_int(insn[j-1].detail->arm.operands[i].mem.index));
									Store_field(tmp3, 2, Val_int(insn[j-1].detail->arm.operands[i].mem.scale));
									Store_field(tmp3, 3, Val_int(insn[j-1].detail->arm.operands[i].mem.disp));
									Store_field(tmp, 0, tmp3);
									break;
								default: break;
							}
							tmp3 = caml_alloc(2, 0);
							Store_field(tmp3, 0, Val_int(insn[j-1].detail->arm.operands[i].shift.type));
							Store_field(tmp3, 1, Val_int(insn[j-1].detail->arm.operands[i].shift.value));
							Store_field(tmp2, 0, tmp3);
							Store_field(tmp2, 1, tmp);
							Store_field(array, i, tmp2);
						}
					} else	// empty list
						array = Atom(0);

					Store_field(op_info_val, 4, array);

					// finally, insert this into arch_info
					Store_field(arch_info, 0, op_info_val);

					Store_field(rec_insn, 12, arch_info);

					break;
				case CS_ARCH_ARM64:
						 arch_info = caml_alloc(1, 1);

						 op_info_val = caml_alloc(5, 0);
						 Store_field(op_info_val, 0, Val_int(insn[j-1].detail->arm64.cc));
						 Store_field(op_info_val, 1, Val_bool(insn[j-1].detail->arm64.update_flags));
						 Store_field(op_info_val, 2, Val_bool(insn[j-1].detail->arm64.writeback));
						 lcount = insn[j-1].detail->arm64.op_count;

						 Store_field(op_info_val, 3, Val_int(lcount));

						 if (lcount > 0) {
							 array = caml_alloc(lcount, 0);
							 for (i = 0; i < lcount; i++) {
								 tmp2 = caml_alloc(3, 0);
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
									 default: break;
								 }
								 tmp3 = caml_alloc(2, 0);
								 Store_field(tmp3, 0, Val_int(insn[j-1].detail->arm64.operands[i].shift.type));
								 Store_field(tmp3, 1, Val_int(insn[j-1].detail->arm64.operands[i].shift.value));
								 Store_field(tmp2, 0, tmp3);
								 Store_field(tmp2, 1, Val_int(insn[j-1].detail->arm64.operands[i].ext));

								 Store_field(tmp2, 2, tmp);
								 Store_field(array, i, tmp2);
							 }
						 } else		// empty array
							 array = Atom(0);

						 Store_field(op_info_val, 4, array);

						 // finally, insert this into arch_info
						 Store_field(arch_info, 0, op_info_val);

						 Store_field(rec_insn, 12, arch_info);

						 break;
				case CS_ARCH_MIPS:
						 arch_info = caml_alloc(1, 2);

						 op_info_val = caml_alloc(2, 0);

						 lcount = insn[j-1].detail->mips.op_count;

						 Store_field(op_info_val, 0, Val_int(lcount));

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
						 } else		// empty array
							 array = Atom(0);

						 Store_field(op_info_val, 1, array);

						 // finally, insert this into arch_info
						 Store_field(arch_info, 0, op_info_val);

						 Store_field(rec_insn, 12, arch_info);

						 break;
				case CS_ARCH_PPC:

						 arch_info = caml_alloc(1, 3);

						 op_info_val = caml_alloc(5, 0);

						 Store_field(op_info_val, 0, Val_int(insn[j-1].detail->ppc.bc));
						 Store_field(op_info_val, 1, Val_int(insn[j-1].detail->ppc.bh));
						 Store_field(op_info_val, 2, Val_bool(insn[j-1].detail->ppc.update_cr0));

						 lcount = insn[j-1].detail->ppc.op_count;

						 Store_field(op_info_val, 3, Val_int(lcount));

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
									 default: break;
								 }
								 Store_field(tmp2, 0, tmp);
								 Store_field(array, i, tmp2);
							 }
						 } else		// empty array
							 array = Atom(0);

						 Store_field(op_info_val, 4, array);

						 // finally, insert this into arch_info
						 Store_field(arch_info, 0, op_info_val);

						 Store_field(rec_insn, 12, arch_info);

						 break;

				case CS_ARCH_X86:

					arch_info = caml_alloc(1, 4);

					op_info_val = caml_alloc(15, 0);

					// fill prefix
					lcount = list_count(insn[j-1].detail->x86.prefix, ARR_SIZE(insn[j-1].detail->x86.prefix));
					if(lcount) {
						array = caml_alloc(lcount, 0);
						for (i = 0; i < lcount; i++) {
					    		Store_field(array, i, Val_int(insn[j-1].detail->x86.prefix[i]));
						}
					} else
						array = Atom(0);
					Store_field(op_info_val, 0, array);

					Store_field(op_info_val, 1, Val_int(insn[j-1].detail->x86.segment));

					// fill opcode
					lcount = list_count(insn[j-1].detail->x86.opcode, ARR_SIZE(insn[j-1].detail->x86.opcode));
					if(lcount) {
						array = caml_alloc(lcount, 0);
						for (i = 0; i < lcount; i++) {
					    		Store_field(array, i, Val_int(insn[j-1].detail->x86.opcode[i]));
						}
					} else
						array = Atom(0);
					Store_field(op_info_val, 2, array);
					Store_field(op_info_val, 3, Val_int(insn[j-1].detail->x86.op_size));

					Store_field(op_info_val, 4, Val_int(insn[j-1].detail->x86.addr_size));

					Store_field(op_info_val, 5, Val_int(insn[j-1].detail->x86.disp_size));

					Store_field(op_info_val, 6, Val_int(insn[j-1].detail->x86.imm_size));

					Store_field(op_info_val, 7, Val_int(insn[j-1].detail->x86.modrm));

					Store_field(op_info_val, 8, Val_int(insn[j-1].detail->x86.sib));

					Store_field(op_info_val, 9, Val_int(insn[j-1].detail->x86.disp));

					Store_field(op_info_val, 10, Val_int(insn[j-1].detail->x86.sib_index));

					Store_field(op_info_val, 11, Val_int(insn[j-1].detail->x86.sib_scale));

					Store_field(op_info_val, 12, Val_int(insn[j-1].detail->x86.sib_base));

					lcount = insn[j-1].detail->x86.op_count;

					Store_field(op_info_val, 13, Val_int(lcount));

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
								case X86_OP_FP:
									tmp = caml_alloc(1, 3);
									Store_field(tmp, 0, caml_copy_double(insn[j-1].detail->x86.operands[i].fp));
									break;
								case X86_OP_MEM:
									tmp = caml_alloc(1, 4);
									tmp2 = caml_alloc(4, 0);
									Store_field(tmp2, 0, Val_int(insn[j-1].detail->x86.operands[i].mem.base));
									Store_field(tmp2, 1, Val_int(insn[j-1].detail->x86.operands[i].mem.index));
									Store_field(tmp2, 2, Val_int(insn[j-1].detail->x86.operands[i].mem.scale));
									Store_field(tmp2, 3, Val_int(insn[j-1].detail->x86.operands[i].mem.disp));
									Store_field(tmp, 0, tmp2);
									break;
								default:
									break;
							}
							Store_field(array, i, tmp);
						}
					} else
						array = Atom(0);	// empty array

					Store_field(op_info_val, 14, array);

					// finally, insert this into arch_info
					Store_field(arch_info, 0, op_info_val);

					Store_field(rec_insn, 12, arch_info);
					break;

				default: break;
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

CAMLprim value ocaml_cs_disasm_quick(value _arch, value _mode, value _code, value _addr, value _count)
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
			arch = CS_ARCH_PPC;
			break;
		case 4:
			arch = CS_ARCH_X86;
			break;
		default:
			caml_invalid_argument("Error message");
			return Val_emptylist;
	}

	while (_mode != Val_emptylist) {
		head = Field(_mode, 0);  /* accessing the head */
		switch (Int_val(head)) {
			case 0:
				mode |= CS_MODE_LITTLE_ENDIAN;
				break;
			case 1:
				mode |= CS_OPT_SYNTAX_INTEL;
				break;
			case 2:
				mode |= CS_MODE_ARM;
				break;
			case 3:
				mode |= CS_MODE_16;
				break;
			case 4:
				mode |= CS_MODE_32;
				break;
			case 5:
				mode |= CS_MODE_64;
				break;
			case 6:
				mode |= CS_MODE_THUMB;
				break;
			case 7:
				mode |= CS_MODE_MICRO;
				break;
			case 8:
				mode |= CS_MODE_N64;
				break;
			case 9:
				mode |= CS_OPT_SYNTAX_ATT;
				break;
			case 10:
				mode |= CS_MODE_BIG_ENDIAN;
				break;
			default:
				caml_invalid_argument("Error message");
				return Val_emptylist;
		}
		_mode = Field(_mode, 1);  /* point to the tail for next loop */
	}

	//CS_ERR_OK = 0,	// No error: everything was fine
	if (cs_open(arch, mode, &handle) != 0)
		return Val_emptylist;

	if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != 0)
		CAMLreturn(Val_int(0));

	code = (uint8_t *)String_val(_code);
	code_len = caml_string_length(_code);
	addr = Int64_val(_addr);
	count = Int64_val(_count);

    CAMLreturn(_cs_disasm(arch, handle, code, code_len, addr, count));
}

CAMLprim value ocaml_cs_disasm_dyn(value _arch, value _handle, value _code, value _addr, value _count)
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

CAMLprim value ocaml_cs_open(value _arch, value _mode)
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
			arch = CS_ARCH_PPC;
			break;
		case 4:
			arch = CS_ARCH_X86;
			break;
		default:
			caml_invalid_argument("Error message");
			return Val_emptylist;
	}


	while (_mode != Val_emptylist) {
		head = Field(_mode, 0);  /* accessing the head */
		switch (Int_val(head)) {
			case 0:
				mode |= CS_MODE_LITTLE_ENDIAN;
				break;
			case 1:
				mode |= CS_OPT_SYNTAX_INTEL;
				break;
			case 2:
				mode |= CS_MODE_ARM;
				break;
			case 3:
				mode |= CS_MODE_16;
				break;
			case 4:
				mode |= CS_MODE_32;
				break;
			case 5:
				mode |= CS_MODE_64;
				break;
			case 6:
				mode |= CS_MODE_THUMB;
				break;
			case 7:
				mode |= CS_MODE_MICRO;
				break;
			case 8:
				mode |= CS_MODE_N64;
				break;
			case 9:
				mode |= CS_OPT_SYNTAX_ATT;
				break;
			case 10:
				mode |= CS_MODE_BIG_ENDIAN;
				break;
			default:
				caml_invalid_argument("Error message");
				return Val_emptylist;
		}
		_mode = Field(_mode, 1);  /* point to the tail for next loop */
	}

	if (cs_open(arch, mode, &handle) != 0) 
		CAMLreturn(Val_int(0));

	if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != 0)
		CAMLreturn(Val_int(0));

	CAMLlocal1(result);
	result = caml_alloc(1, 0);
	Store_field(result, 0, caml_copy_int64(handle));
	CAMLreturn(result);
}

CAMLprim value cs_register_name(value _handle, value _reg)
{
	const char *name = cs_reg_name(Int64_val(_handle), Int_val(_reg));
	if(!name) {
		caml_invalid_argument("invalid reg_id");
		name = "invalid";
	}
	return caml_copy_string(name);
}

CAMLprim value cs_instruction_name(value _handle, value _insn)
{
	const char *name = cs_insn_name(Int64_val(_handle), Int_val(_insn));
	if(!name) {
		caml_invalid_argument("invalid insn_id");
		name = "invalid";
	}
	return caml_copy_string(name);
}
