/* Capstone Disassembly Engine */
/* M68K Backend by Daniel Collin <daniel@collin.com> 2015-2016 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "M68KInstPrinter.h"

#include "M68KDisassembler.h"

#include "../../Mapping.h"
#include "../../cs_priv.h"
#include "../../utils.h"

#include "../../MCInst.h"
#include "../../MCInstrDesc.h"
#include "../../MCRegisterInfo.h"

#ifndef CAPSTONE_DIET
static const char s_spacing[] = " ";

static const char *const s_reg_names[] = {
	"invalid",  "d0",	"d1",	 "d2",	 "d3",	 "d4",	 "d5",	 "d6",
	"d7",	    "a0",	"a1",	 "a2",	 "a3",	 "a4",	 "a5",	 "a6",
	"a7",	    "fp0",	"fp1",	 "fp2",	 "fp3",	 "fp4",	 "fp5",	 "fp6",
	"fp7",	    "pc",	"sr",	 "ccr",	 "sfc",	 "dfc",	 "usp",	 "vbr",
	"cacr",	    "caar",	"msp",	 "isp",	 "tc",	 "itt0", "itt1", "dtt0",
	"dtt1",	    "mmusr",	"urp",	 "srp",

	"fpcr",	    "fpsr",	"fpiar",

	"tt0",	    "tt1",	"crp",	 "acc",	 "acc0", "acc1", "acc2", "acc3",
	"accext01", "accext23", "macsr", "mask",
};

static const char *const s_instruction_names[] = {
	"invalid",   "abcd",	 "add",	     "adda",	  "addi",
	"addq",	     "addx",	 "and",	     "andi",	  "asl",
	"asr",	     "bhs",	 "blo",	     "bhi",	  "bls",
	"bcc",	     "bcs",	 "bne",	     "beq",	  "bvc",
	"bvs",	     "bpl",	 "bmi",	     "bge",	  "blt",
	"bgt",	     "ble",	 "bra",	     "bsr",	  "bchg",
	"bclr",	     "bset",	 "btst",     "bitrev",	  "byterev",
	"bfchg",     "bfclr",	 "bfexts",   "bfextu",	  "bfffo",
	"bfins",     "bfset",	 "bftst",    "bkpt",	  "callm",
	"cas",	     "cas2",	 "chk",	     "chk2",	  "clr",
	"cmp",	     "cmpa",	 "cmpi",     "cmpm",	  "cmp2",
	"cinvl",     "cinvp",	 "cinva",    "cpushl",	  "cpushp",
	"cpusha",    "dbt",	 "dbf",	     "dbhi",	  "dbls",
	"dbcc",	     "dbcs",	 "dbne",     "dbeq",	  "dbvc",
	"dbvs",	     "dbpl",	 "dbmi",     "dbge",	  "dblt",
	"dbgt",	     "dble",	 "dbra",     "divs",	  "divsl",
	"divu",	     "divul",	 "eor",	     "eori",	  "exg",
	"ext",	     "extb",	 "ff1",	     "fabs",	  "fsabs",
	"fdabs",     "facos",	 "fadd",     "fsadd",	  "fdadd",
	"fasin",     "fatan",	 "fatanh",   "fbf",	  "fbeq",
	"fbogt",     "fboge",	 "fbolt",    "fbole",	  "fbogl",
	"fbor",	     "fbun",	 "fbueq",    "fbugt",	  "fbuge",
	"fbult",     "fbule",	 "fbne",     "fbt",	  "fbsf",
	"fbseq",     "fbgt",	 "fbge",     "fblt",	  "fble",
	"fbgl",	     "fbgle",	 "fbngle",   "fbngl",	  "fbnle",
	"fbnlt",     "fbnge",	 "fbngt",    "fbsne",	  "fbst",
	"fcmp",	     "fcos",	 "fcosh",    "fdbf",	  "fdbeq",
	"fdbogt",    "fdboge",	 "fdbolt",   "fdbole",	  "fdbogl",
	"fdbor",     "fdbun",	 "fdbueq",   "fdbugt",	  "fdbuge",
	"fdbult",    "fdbule",	 "fdbne",    "fdbt",	  "fdbsf",
	"fdbseq",    "fdbgt",	 "fdbge",    "fdblt",	  "fdble",
	"fdbgl",     "fdbgle",	 "fdbngle",  "fdbngl",	  "fdbnle",
	"fdbnlt",    "fdbnge",	 "fdbngt",   "fdbsne",	  "fdbst",
	"fdiv",	     "fsdiv",	 "fddiv",    "fetox",	  "fetoxm1",
	"fgetexp",   "fgetman",	 "fint",     "fintrz",	  "flog10",
	"flog2",     "flogn",	 "flognp1",  "fmod",	  "fmove",
	"fsmove",    "fdmove",	 "fmovecr",  "fmovem",	  "fmul",
	"fsmul",     "fdmul",	 "fneg",     "fsneg",	  "fdneg",
	"fnop",	     "frem",	 "frestore", "fsave",	  "fscale",
	"fsgldiv",   "fsglmul",	 "fsin",     "fsincos",	  "fsinh",
	"fsqrt",     "fssqrt",	 "fdsqrt",   "fsf",	  "fseq",
	"fsogt",     "fsoge",	 "fsolt",    "fsole",	  "fsogl",
	"fsor",	     "fsun",	 "fsueq",    "fsugt",	  "fsuge",
	"fsult",     "fsule",	 "fsne",     "fst",	  "fssf",
	"fsseq",     "fsgt",	 "fsge",     "fslt",	  "fsle",
	"fsgl",	     "fsgle",	 "fsngle",   "fsngl",	  "fsnle",
	"fsnlt",     "fsnge",	 "fsngt",    "fssne",	  "fsst",
	"fsub",	     "fssub",	 "fdsub",    "ftan",	  "ftanh",
	"ftentox",   "ftrapf",	 "ftrapeq",  "ftrapogt",  "ftrapoge",
	"ftrapolt",  "ftrapole", "ftrapogl", "ftrapor",	  "ftrapun",
	"ftrapueq",  "ftrapugt", "ftrapuge", "ftrapult",  "ftrapule",
	"ftrapne",   "ftrapt",	 "ftrapsf",  "ftrapseq",  "ftrapgt",
	"ftrapge",   "ftraplt",	 "ftraple",  "ftrapgl",	  "ftrapgle",
	"ftrapngle", "ftrapngl", "ftrapnle", "ftrapnlt",  "ftrapnge",
	"ftrapngt",  "ftrapsne", "ftrapst",  "ftst",	  "ftwotox",
	"halt",	     "illegal",	 "intouch",  "jmp",	  "jsr",
	"lea",	     "link",	 "lpstop",   "lsl",	  "lsr",
	"mac",	     "move",	 "movea",    "movec",	  "movem",
	"movep",     "moveq",	 "moves",    "move16",	  "mov3q",
	"movclr",    "msac",	 "muls",     "mulu",	  "mvs",
	"mvz",	     "nbcd",	 "neg",	     "negx",	  "nop",
	"not",	     "or",	 "ori",	     "pack",	  "pea",
	"pflush",    "pflusha",	 "pflushan", "pflushn",	  "ploadr",
	"ploadw",    "plpar",	 "plpaw",    "pmove",	  "pmovefd",
	"ptestr",    "ptestw",	 "pulse",    "rems",	  "remu",
	"reset",     "rol",	 "ror",	     "roxl",	  "roxr",
	"rtd",	     "rte",	 "rtm",	     "rtr",	  "rts",
	"sats",	     "sbcd",	 "st",	     "sf",	  "shi",
	"sls",	     "scc",	 "shs",	     "scs",	  "slo",
	"sne",	     "seq",	 "svc",	     "svs",	  "spl",
	"smi",	     "sge",	 "slt",	     "sgt",	  "sle",
	"stop",	     "strldsr",	 "sub",	     "suba",	  "subi",
	"subq",	     "subx",	 "swap",     "tas",	  "trap",
	"trapv",     "trapt",	 "trapf",    "traphi",	  "trapls",
	"trapcc",    "traphs",	 "trapcs",   "traplo",	  "trapne",
	"trapeq",    "trapvc",	 "trapvs",   "trappl",	  "trapmi",
	"trapge",    "traplt",	 "trapgt",   "traple",	  "tst",
	"unlk",	     "unpk",	 "wddata",   "wdebug",	  "bgnd",
	"tbls",	     "tblu",	 "tblsn",    "tblun",	  "cp0bcbusy",
	"cp0ld",     "cp0nop",	 "cp0st",    "cp1bcbusy", "cp1ld",
	"cp1nop",    "cp1st",	 "tpf",
};
#endif

#ifndef CAPSTONE_DIET
static const char *getRegName(m68k_reg reg)
{
	return s_reg_names[(int)reg];
}

static void printRegbits(SStream *O, bool *need_sep, uint32_t data,
			 const char *prefix)
{
	unsigned int first;
	int i;

	for (i = 0; i < 8; ++i) {
		if (!(data & (1 << i)))
			continue;

		first = i;
		while (i < 7 && (data & (1 << (i + 1))))
			i++;

		if (*need_sep)
			SStream_concat1(O, '/');
		*need_sep = true;

		SStream_concat(O, "%s%" PRIu32, prefix, first);

		if ((unsigned int)i > first)
			SStream_concat(O, "-%s%" PRIu32, prefix,
				       (unsigned int)i);
	}
}

static void registerBits(SStream *O, const cs_m68k_op *op)
{
	unsigned int data = op->register_bits;
	bool need_sep = false;

	if (!data) {
		SStream_concat(O, "%s", "#$0");
		return;
	}

	printRegbits(O, &need_sep, data & 0xff, "d");
	printRegbits(O, &need_sep, (data >> 8) & 0xff, "a");
	printRegbits(O, &need_sep, (data >> 16) & 0xff, "fp");
}

static void registerPair(SStream *O, const cs_m68k_op *op)
{
	SStream_concat(O, "%s:%s", s_reg_names[op->reg_pair.reg_0],
		       s_reg_names[op->reg_pair.reg_1]);
}

static void printRegisterName(SStream *O, const cs_m68k_op *op)
{
	SStream_concat(O, "%s", getRegName(op->reg));
	if (op->flags & M68K_OP_FLAG_REG_LOWER)
		SStream_concat0(O, "l");
	else if (op->flags & M68K_OP_FLAG_REG_UPPER)
		SStream_concat0(O, "u");
}

static void printScaleFactor(SStream *O, uint8_t scale, int threshold)
{
	if (scale > threshold)
		SStream_concat(O, "%s*%s%" PRId8, s_spacing, s_spacing, scale);
}

static void printIndexReg(SStream *O, const cs_m68k_op *op)
{
	SStream_concat(O, "%s.%c", getRegName(op->mem.index_reg),
		       op->mem.index_size ? 'l' : 'w');
}

static void printBitfield(SStream *O, const cs_m68k_op *op)
{
	if (!op->mem.bitfield)
		return;
	SStream_concat0(O, "{");
	if (M68K_BF_IS_REG(op->mem.offset))
		SStream_concat(O, "d%" PRId8, M68K_BF_REG_NUM(op->mem.offset));
	else
		SStream_concat(O, "%" PRId8, op->mem.offset);
	SStream_concat0(O, ":");
	if (M68K_BF_IS_REG(op->mem.width))
		SStream_concat(O, "d%" PRId8, M68K_BF_REG_NUM(op->mem.width));
	else
		SStream_concat(O, "%" PRId8, op->mem.width);
	SStream_concat0(O, "}");
}

static void printImmediate(SStream *O, const cs_m68k *inst,
			   const cs_m68k_op *op)
{
	if (inst->op_size.type == M68K_SIZE_TYPE_FPU) {
#if defined(_KERNEL_MODE)
		SStream_concat(O, "#<float_point_unsupported>");
		return;
#else
		if (inst->op_size.fpu_size == M68K_FPU_SIZE_SINGLE)
			SStream_concat(O, "#%f", op->simm);
		else if (inst->op_size.fpu_size == M68K_FPU_SIZE_DOUBLE)
			SStream_concat(O, "#%f", op->dimm);
		else
			SStream_concat(O, "#<unsupported>");
		return;
#endif
	}
	SStream_concat(O, "#$%" PRIx64, op->imm);
}

static void printIndex8BitDisp(SStream *O, unsigned int pc,
			       const cs_m68k_op *op)
{
	if (op->address_mode == M68K_AM_PCI_INDEX_8_BIT_DISP) {
		SStream_concat(O, "$%" PRIx32 "(pc,%s", pc + 2 + op->mem.disp,
			       s_spacing);
	} else {
		SStream_concat(O, "%s$%" PRIx16 "(%s,%s",
			       op->mem.disp < 0 ? "-" : "", abs(op->mem.disp),
			       getRegName(op->mem.base_reg), s_spacing);
	}
	printIndexReg(O, op);
	printScaleFactor(O, op->mem.scale, 1);
	SStream_concat0(O, ")");
}

static void printRegAddrMode(SStream *O, unsigned int pc, const cs_m68k_op *op)
{
	m68k_reg base_reg = op->type == M68K_OP_MEM ? op->mem.base_reg :
						      op->reg;

	switch (op->address_mode) {
	case M68K_AM_REG_DIRECT_DATA:
		printRegisterName(O, op);
		break;
	case M68K_AM_REG_DIRECT_ADDR:
		printRegisterName(O, op);
		break;
	case M68K_AM_REGI_ADDR:
		SStream_concat(O, "(a%" PRId32 ")", (base_reg - M68K_REG_A0));
		break;
	case M68K_AM_REGI_ADDR_POST_INC:
		SStream_concat(O, "(a%" PRId32 ")+", (base_reg - M68K_REG_A0));
		break;
	case M68K_AM_REGI_ADDR_PRE_DEC:
		SStream_concat(O, "-(a%" PRId32 ")", (base_reg - M68K_REG_A0));
		break;
	case M68K_AM_REGI_ADDR_DISP:
		SStream_concat(O, "%s$%" PRIx16 "(a%" PRId32 ")",
			       op->mem.disp < 0 ? "-" : "", abs(op->mem.disp),
			       (base_reg - M68K_REG_A0));
		break;
	case M68K_AM_PCI_DISP:
		SStream_concat(O, "$%" PRIx32 "(pc)", pc + 2 + op->mem.disp);
		break;
	default:
		break;
	}
}

static void printBaseDisp(SStream *O, unsigned int pc, const cs_m68k_op *op)
{
	int is_pc = (op->address_mode == M68K_AM_PCI_INDEX_BASE_DISP);

	if (is_pc) {
		SStream_concat(O, "$%" PRIx32, pc + 2 + op->mem.in_disp);
	} else if (op->mem.in_disp != 0) {
		SStream_concat(O, "%s$%" PRIx32,
			       op->mem.in_disp >= 0 ? "" : "-",
			       abs(op->mem.in_disp));
	}

	SStream_concat0(O, "(");

	if (is_pc) {
		SStream_concat0(O, "pc");
	} else if (op->mem.base_reg != M68K_REG_INVALID) {
		SStream_concat(O, "a%" PRId32, op->mem.base_reg - M68K_REG_A0);
	}

	if ((is_pc || op->mem.base_reg != M68K_REG_INVALID) &&
	    op->mem.index_reg != M68K_REG_INVALID)
		SStream_concat(O, ",%s", s_spacing);

	if (op->mem.index_reg != M68K_REG_INVALID) {
		printIndexReg(O, op);
		printScaleFactor(O, op->mem.scale, 0);
	}

	SStream_concat0(O, ")");
}

static void printMemIndirect(SStream *O, unsigned int pc, const cs_m68k_op *op)
{
	int is_pc = (op->address_mode == M68K_AM_PC_MEMI_POST_INDEX ||
		     op->address_mode == M68K_AM_PC_MEMI_PRE_INDEX);
	int is_post = (op->address_mode == M68K_AM_MEMI_POST_INDEX ||
		       op->address_mode == M68K_AM_PC_MEMI_POST_INDEX);
	int is_pre = (op->address_mode == M68K_AM_MEMI_PRE_INDEX ||
		      op->address_mode == M68K_AM_PC_MEMI_PRE_INDEX);

	SStream_concat0(O, "([");

	if (is_pc) {
		SStream_concat(O, "$%" PRIx32, pc + 2 + op->mem.in_disp);
	} else if (op->mem.in_disp != 0) {
		SStream_concat(O, "%s$%" PRIx32,
			       op->mem.in_disp >= 0 ? "" : "-",
			       abs(op->mem.in_disp));
	}

	if (op->mem.base_reg != M68K_REG_INVALID) {
		if (op->mem.in_disp != 0)
			SStream_concat(O, ",%s%s", s_spacing,
				       getRegName(op->mem.base_reg));
		else
			SStream_concat(O, "%s", getRegName(op->mem.base_reg));
	}

	if (is_post)
		SStream_concat0(O, "]");

	if (op->mem.index_reg != M68K_REG_INVALID) {
		SStream_concat(O, ",%s", s_spacing);
		printIndexReg(O, op);
	}

	printScaleFactor(O, op->mem.scale, 0);

	if (is_pre)
		SStream_concat0(O, "]");

	if (op->mem.out_disp != 0) {
		SStream_concat(O, ",%s%s$%" PRIx32, s_spacing,
			       op->mem.out_disp >= 0 ? "" : "-",
			       abs(op->mem.out_disp));
	}

	SStream_concat0(O, ")");
}

static void printAddressingMode(SStream *O, unsigned int pc,
				const cs_m68k *inst, const cs_m68k_op *op)
{
	switch (op->address_mode) {
	case M68K_AM_NONE:
		switch (op->type) {
		case M68K_OP_REG_BITS:
			registerBits(O, op);
			break;
		case M68K_OP_REG_PAIR:
			registerPair(O, op);
			break;
		case M68K_OP_REG:
			printRegisterName(O, op);
			break;
		case M68K_OP_SHIFT:
			if (op->flags & M68K_OP_FLAG_SHIFT_LEFT)
				SStream_concat0(O, "<<");
			else if (op->flags & M68K_OP_FLAG_SHIFT_RIGHT)
				SStream_concat0(O, ">>");
			break;
		default:
			break;
		}
		break;

	case M68K_AM_REG_DIRECT_DATA:
	case M68K_AM_REG_DIRECT_ADDR:
	case M68K_AM_REGI_ADDR:
	case M68K_AM_REGI_ADDR_POST_INC:
	case M68K_AM_REGI_ADDR_PRE_DEC:
	case M68K_AM_REGI_ADDR_DISP:
	case M68K_AM_PCI_DISP:
		printRegAddrMode(O, pc, op);
		break;
	case M68K_AM_ABSOLUTE_DATA_SHORT:
		SStream_concat(O, "$%" PRIx32 ".w", (uint32_t)op->mem.address);
		break;
	case M68K_AM_ABSOLUTE_DATA_LONG:
		SStream_concat(O, "$%" PRIx64 ".l", (uint64_t)op->mem.address);
		break;
	case M68K_AM_IMMEDIATE:
		printImmediate(O, inst, op);
		break;
	case M68K_AM_PCI_INDEX_8_BIT_DISP:
	case M68K_AM_AREGI_INDEX_8_BIT_DISP:
		printIndex8BitDisp(O, pc, op);
		break;
	case M68K_AM_PCI_INDEX_BASE_DISP:
	case M68K_AM_AREGI_INDEX_BASE_DISP:
		printBaseDisp(O, pc, op);
		break;
	case M68K_AM_PC_MEMI_POST_INDEX:
	case M68K_AM_PC_MEMI_PRE_INDEX:
	case M68K_AM_MEMI_PRE_INDEX:
	case M68K_AM_MEMI_POST_INDEX:
		printMemIndirect(O, pc, op);
		break;
	case M68K_AM_BRANCH_DISPLACEMENT:
		SStream_concat(O, "$%" PRIx32, pc + 2 + op->br_disp.disp);
	default:
		break;
	}

	printBitfield(O, op);
	if (op->flags & M68K_OP_FLAG_MEM_UPDATE)
		SStream_concat0(O, "&");
}

static void printCAS2(SStream *O, unsigned int pc, const cs_m68k *ext)
{
	printAddressingMode(O, pc, ext, &ext->operands[0]);
	SStream_concat0(O, ",");
	printAddressingMode(O, pc, ext, &ext->operands[1]);
	SStream_concat0(O, ",");

	SStream_concat(O, "(%s):(%s)",
		       s_reg_names[ext->operands[2].reg_pair.reg_0],
		       s_reg_names[ext->operands[2].reg_pair.reg_1]);
}

static void printCacheOp(SStream *O, unsigned int pc, const cs_m68k *ext)
{
	static const char *const cache_names[] = { "nc", "dc", "ic", "bc" };
	unsigned int sel = (unsigned int)ext->operands[0].imm;
	int i;

	if (sel < ARR_SIZE(cache_names))
		SStream_concat0(O, cache_names[sel]);
	else
		SStream_concat(O, "#$%" PRIx64, ext->operands[0].imm);

	for (i = 1; i < ext->op_count; ++i) {
		SStream_concat(O, ",%s", s_spacing);
		printAddressingMode(O, pc, ext, &ext->operands[i]);
	}
}

#endif

static void printOpSize(SStream *O, const cs_m68k *ext)
{
	switch (ext->op_size.type) {
	case M68K_SIZE_TYPE_INVALID:
		break;
	case M68K_SIZE_TYPE_CPU:
		switch (ext->op_size.cpu_size) {
		case M68K_CPU_SIZE_BYTE:
			SStream_concat0(O, ".b");
			break;
		case M68K_CPU_SIZE_WORD:
			SStream_concat0(O, ".w");
			break;
		case M68K_CPU_SIZE_LONG:
			SStream_concat0(O, ".l");
			break;
		case M68K_CPU_SIZE_NONE:
			break;
		}
		break;
	case M68K_SIZE_TYPE_FPU:
		switch (ext->op_size.fpu_size) {
		case M68K_FPU_SIZE_SINGLE:
			SStream_concat0(O, ".s");
			break;
		case M68K_FPU_SIZE_DOUBLE:
			SStream_concat0(O, ".d");
			break;
		case M68K_FPU_SIZE_EXTENDED:
			SStream_concat0(O, ".x");
			break;
		case M68K_FPU_SIZE_NONE:
			break;
		}
		break;
	}
}

void M68K_printInst(MCInst *MI, SStream *O, void *PrinterInfo)
{
#ifndef CAPSTONE_DIET
	m68k_info *info = (m68k_info *)PrinterInfo;
	cs_m68k *ext = &info->extension;
	cs_detail *detail = NULL;
	int i = 0;

	if (detail_is_set(MI)) {
		detail = get_detail(MI);
		int regs_read_count = MIN((int)ARR_SIZE(detail->regs_read),
					  info->regs_read_count);
		int regs_write_count = MIN((int)ARR_SIZE(detail->regs_write),
					   info->regs_write_count);
		int groups_count =
			MIN((int)ARR_SIZE(detail->groups), info->groups_count);

		memcpy(&detail->m68k, ext, sizeof(cs_m68k));
		memcpy(&detail->regs_read, &info->regs_read,
		       regs_read_count * sizeof(info->regs_read[0]));
		detail->regs_read_count = regs_read_count;

		memcpy(&detail->regs_write, &info->regs_write,
		       regs_write_count * sizeof(info->regs_write[0]));
		detail->regs_write_count = regs_write_count;

		memcpy(&detail->groups, &info->groups, groups_count);
		detail->groups_count = groups_count;
	}

	if (MI->Opcode == M68K_INS_INVALID) {
		if (ext->op_count)
			SStream_concat(O, "dc.w $%" PRIx32,
				       (uint32_t)ext->operands[0].imm);
		else
			SStream_concat(O, "dc.w $<unknown>");
		return;
	}

	SStream_concat0(O, (char *)s_instruction_names[MI->Opcode]);
	printOpSize(O, ext);
	SStream_concat0(O, " ");

	if (MI->Opcode == M68K_INS_CAS2) {
		printCAS2(O, info->pc, ext);
		return;
	}

	if (MI->Opcode >= M68K_INS_CINVL && MI->Opcode <= M68K_INS_CPUSHA) {
		printCacheOp(O, info->pc, ext);
		return;
	}

	for (i = 0; i < ext->op_count; ++i) {
		printAddressingMode(O, info->pc, ext, &ext->operands[i]);
		if ((i + 1) != ext->op_count)
			SStream_concat(O, ",%s", s_spacing);
	}
#endif
}

const char *M68K_reg_name(csh handle, unsigned int reg)
{
#ifdef CAPSTONE_DIET
	return NULL;
#else
	if (reg >= ARR_SIZE(s_reg_names)) {
		return NULL;
	}
	return s_reg_names[(int)reg];
#endif
}

void M68K_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	insn->id = id; // These id's matches for 68k
}

const char *M68K_insn_name(csh handle, unsigned int id)
{
#ifdef CAPSTONE_DIET
	return NULL;
#else
	if (id >= ARR_SIZE(s_instruction_names)) {
		return NULL;
	}
	return s_instruction_names[id];
#endif
}

#ifndef CAPSTONE_DIET
static const name_map group_name_maps[] = {
	{ M68K_GRP_INVALID, NULL },
	{ M68K_GRP_JUMP, "jump" },
	{ M68K_GRP_RET, "ret" },
	{ M68K_GRP_IRET, "iret" },
	{ M68K_GRP_BRANCH_RELATIVE, "branch_relative" },
};
#endif

const char *M68K_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
void M68K_reg_access(const cs_insn *insn, cs_regs regs_read,
		     uint8_t *regs_read_count, cs_regs regs_write,
		     uint8_t *regs_write_count)
{
	uint8_t read_count, write_count;

	read_count = insn->detail->regs_read_count;
	write_count = insn->detail->regs_write_count;

	// implicit registers
	memcpy(regs_read, insn->detail->regs_read,
	       read_count * sizeof(insn->detail->regs_read[0]));
	memcpy(regs_write, insn->detail->regs_write,
	       write_count * sizeof(insn->detail->regs_write[0]));

	*regs_read_count = read_count;
	*regs_write_count = write_count;
}
#endif
