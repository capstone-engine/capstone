/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev  <sibirtsevdl@gmail.com>, 2023 */

#ifdef CAPSTONE_HAS_HPPA

#include <capstone/platform.h>

#include "HPPAInstPrinter.h"
#include "HPPAMapping.h"


static void set_op_imm(cs_hppa *hppa, uint64_t val)
{
	cs_hppa_op *op = &hppa->operands[hppa->op_count++];
	op->type = HPPA_OP_IMM;
	op->imm = val;
}

static void set_op_reg(cs_hppa *hppa, uint64_t val, cs_ac_type access)
{
	cs_hppa_op *op = &hppa->operands[hppa->op_count++];
	op->type = HPPA_OP_REG;
	op->reg = val;
	op->access = access;
}

static void set_op_idx_reg(cs_hppa *hppa, uint64_t reg)
{
	cs_hppa_op *op = &hppa->operands[hppa->op_count++];
	op->type = HPPA_OP_IDX_REG;
	op->reg = reg;
	op->access = CS_AC_READ;
}

static void set_op_disp(cs_hppa *hppa, uint64_t val)
{
	cs_hppa_op *op = &hppa->operands[hppa->op_count++];
	op->type = HPPA_OP_DISP;
	op->imm = val;
}

static void set_op_target(cs_hppa *hppa, uint64_t val)
{
	cs_hppa_op *op = &hppa->operands[hppa->op_count++];
	op->type = HPPA_OP_TARGET;
	op->imm = val;
}

static void set_op_mem(cs_hppa *hppa, uint32_t base, uint32_t space, cs_ac_type base_access)
{
	cs_hppa_op *op = &hppa->operands[hppa->op_count++];
	op->type = HPPA_OP_MEM;
	op->mem.base = base;
	op->mem.space = space;
	op->mem.base_access = base_access;
}

struct pa_insn_fmt
{
    // unsigned long int match;
    // unsigned long int mask;
	hppa_insn insn_id;
    const char *format;
};

/* HPPA instruction formats (access)
   i - imm arguments
   R - read access register
   W - write access register
   w - read + write access register
   r - index register (read only)
   T - offset (pc relative)
   o - displacement (imm)
   0 - register with unknown access (in undocumented instructions)
   Y - %sr0,%r31 -- implicit target of be,l instruction
*/

static const struct pa_insn_fmt pa_formats[] = 
{
	{ HPPA_INS_LDI, "iW" },

	{ HPPA_INS_CMPIB, "iRT" },
	{ HPPA_INS_COMIB, "iRT" },

	{ HPPA_INS_CMPB, "RRT" },
	{ HPPA_INS_COMB, "RRT" },

	{ HPPA_INS_ADDB, "RwT" },

	{ HPPA_INS_ADDIB, "iwT" },

	{ HPPA_INS_NOP, "" },
	{ HPPA_INS_COPY, "RW" },
	{ HPPA_INS_MTSAR, "R" },

	{ HPPA_INS_LDD, "" },
	{ HPPA_INS_LDW, "o(Rb)W" },
	{ HPPA_INS_LDH, "o(Rb)W" },
	{ HPPA_INS_LDB, "o(Rb)W" },
	{ HPPA_INS_STD, "" },
	{ HPPA_INS_STW, "Ro(Rb)" },
	{ HPPA_INS_STH, "Ro(Rb)" },
	{ HPPA_INS_STB, "Ro(Rb)" },
	{ HPPA_INS_LDWM, "o(Rw)W" },
	{ HPPA_INS_STWM, "Ro(Rw)" },
	{ HPPA_INS_LDWX, "r(Rb)W" },
	{ HPPA_INS_LDHX, "r(Rb)W" },
	{ HPPA_INS_LDBX, "r(Rb)W" },
	{ HPPA_INS_LDWA, "" },
	{ HPPA_INS_LDCW, "" },
	{ HPPA_INS_STWA, "" },
	{ HPPA_INS_STBY, "" },
	{ HPPA_INS_LDDA, "" },
	{ HPPA_INS_LDCD, "" },
	{ HPPA_INS_STDA, "" },
	{ HPPA_INS_LDWAX, "r(b)W" },
	{ HPPA_INS_LDCWX, "r(Rb)W" },
	{ HPPA_INS_LDWS, "o(Rb)W" },
	{ HPPA_INS_LDHS, "o(Rb)W" },
	{ HPPA_INS_LDBS, "o(Rb)W" },
	{ HPPA_INS_LDWAS, "o(b)W" },
	{ HPPA_INS_LDCWS, "o(Rb)W" },
	{ HPPA_INS_STWS, "Ro(Rb)" },
	{ HPPA_INS_STHS, "Ro(Rb)" },
	{ HPPA_INS_STBS, "Ro(Rb)" },
	{ HPPA_INS_STWAS, "Ro(b)" },
	{ HPPA_INS_STDBY, "" },
	{ HPPA_INS_STBYS, "Ro(Rb)" },

	{ HPPA_INS_LDO, "o(R)W" },
	{ HPPA_INS_LDIL, "iW" },
	{ HPPA_INS_ADDIL, "iR" },

	{ HPPA_INS_B, "" },
	{ HPPA_INS_BL, "TW" },
	{ HPPA_INS_GATE, "TW" },
	{ HPPA_INS_BLR, "RW" },
	{ HPPA_INS_BV, "R(R)" },
	{ HPPA_INS_BVE, "" },
	{ HPPA_INS_BE, "o(RR)" },
	{ HPPA_INS_BLE, "o(RR)" },
	{ HPPA_INS_MOVB, "RWT" },
	{ HPPA_INS_MOVIB, "iWT" },
	{ HPPA_INS_COMBT, "RRT" },
	{ HPPA_INS_COMBF, "RRT" },
	{ HPPA_INS_COMIBT, "iRT" },
	{ HPPA_INS_COMIBF, "iRT" },
	{ HPPA_INS_ADDBT, "RwT" },
	{ HPPA_INS_ADDBF, "RwT" },
	{ HPPA_INS_ADDIBT, "iwT" },
	{ HPPA_INS_ADDIBF, "iwT" },
	{ HPPA_INS_BB, "RiT" },
	{ HPPA_INS_BVB, "RT" },
	{ HPPA_INS_CLRBTS, "" },
	{ HPPA_INS_POPBTS, "" },
	{ HPPA_INS_PUSHNOM, "" },
	{ HPPA_INS_PUSHBTS, "" },

	{ HPPA_INS_CMPCLR, "" },
	{ HPPA_INS_COMCLR, "RRW" },
	{ HPPA_INS_OR, "RRW" },
	{ HPPA_INS_XOR, "RRW" },
	{ HPPA_INS_AND, "RRW" },
	{ HPPA_INS_ANDCM, "RRW" },
	{ HPPA_INS_UXOR, "RRW" },
	{ HPPA_INS_UADDCM, "RRW" },
	{ HPPA_INS_UADDCMT, "RRW" },
	{ HPPA_INS_DCOR, "RW" },
	{ HPPA_INS_IDCOR, "RW" },
	{ HPPA_INS_ADDI, "iRW" },
	{ HPPA_INS_ADDIO, "iRW" },
	{ HPPA_INS_ADDIT, "iRW" },
	{ HPPA_INS_ADDITO, "iRW" },
	{ HPPA_INS_ADD, "RRW" },
	{ HPPA_INS_ADDL, "RRW" },
	{ HPPA_INS_ADDO, "RRW" },
	{ HPPA_INS_ADDC, "RRW" },
	{ HPPA_INS_ADDCO, "RRW" },
	{ HPPA_INS_SUB, "RRW" },
	{ HPPA_INS_SUBO, "RRW" },
	{ HPPA_INS_SUBB, "RRW" },
	{ HPPA_INS_SUBBO, "RRW" },
	{ HPPA_INS_SUBT, "RRW" },
	{ HPPA_INS_SUBTO, "RRW" },
	{ HPPA_INS_DS, "RRW" },
	{ HPPA_INS_SUBI, "iRW" },
	{ HPPA_INS_SUBIO, "iRW" },
	{ HPPA_INS_CMPICLR, "" },
	{ HPPA_INS_COMICLR, "iRW" },
	{ HPPA_INS_SHLADD, "" },
	{ HPPA_INS_SH1ADD, "RRW" },
	{ HPPA_INS_SH1ADDL, "RRW" },
	{ HPPA_INS_SH1ADDO, "RRW" },
	{ HPPA_INS_SH2ADD, "RRW" },
	{ HPPA_INS_SH2ADDL, "RRW" },
	{ HPPA_INS_SH2ADDO, "RRW" },
	{ HPPA_INS_SH3ADD, "RRW" },
	{ HPPA_INS_SH3ADDL, "RRW" },
	{ HPPA_INS_SH3ADDO, "RRW" },

	{ HPPA_INS_HADD, "" },
	{ HPPA_INS_HAVG, "" },
	{ HPPA_INS_HSHL, "" },
	{ HPPA_INS_HSHLADD, "" },
	{ HPPA_INS_HSHR, "" },
	{ HPPA_INS_HSHRADD, "" },
	{ HPPA_INS_HSUB, "" },
	{ HPPA_INS_MIXH, "" },
	{ HPPA_INS_MIXW, "" },
	{ HPPA_INS_PERMH, "" },

	{ HPPA_INS_SHRPD, "" },
	{ HPPA_INS_SHRPW, "" },
	{ HPPA_INS_VSHD, "RRW" },
	{ HPPA_INS_SHD, "RRiW" },
	{ HPPA_INS_EXTRD, "" },
	{ HPPA_INS_EXTRW, "" },
	{ HPPA_INS_VEXTRU, "RiW" },
	{ HPPA_INS_VEXTRS, "RiW" },
	{ HPPA_INS_EXTRU, "RiiW" },
	{ HPPA_INS_EXTRS, "RiiW" },
	{ HPPA_INS_DEPD, "" },
	{ HPPA_INS_DEPDI, "" },
	{ HPPA_INS_DEPW, "" },
	{ HPPA_INS_DEPWI, "" },
	{ HPPA_INS_ZVDEP, "RiW" },
	{ HPPA_INS_VDEP, "RiW" },
	{ HPPA_INS_ZDEP, "RiiW" },
	{ HPPA_INS_DEP, "RiiW" },
	{ HPPA_INS_ZVDEPI, "iiW" },
	{ HPPA_INS_VDEPI, "iiW" },
	{ HPPA_INS_ZDEPI, "iiiW" },
	{ HPPA_INS_DEPI, "iiiW" },

	{ HPPA_INS_BREAK, "ii" },
	{ HPPA_INS_RFI, "" },
	{ HPPA_INS_RFIR, "" },
	{ HPPA_INS_SSM, "iW" },
	{ HPPA_INS_RSM, "iW" },
	{ HPPA_INS_MTSM, "R" },
	{ HPPA_INS_LDSID, "(RR)W" },
	{ HPPA_INS_MTSP, "RW" },
	{ HPPA_INS_MTCTL, "RW" },
	{ HPPA_INS_MTSARCM, "" },
	{ HPPA_INS_MFIA, "" },
	{ HPPA_INS_MFSP, "RW" },
	{ HPPA_INS_MFCTL, "RW" },
	{ HPPA_INS_SYNC, "" },
	{ HPPA_INS_SYNCDMA, "" },
	{ HPPA_INS_PROBE, "" },
	{ HPPA_INS_PROBEI, "" },
	{ HPPA_INS_PROBER, "(RR)RW" },
	{ HPPA_INS_PROBERI, "(RR)iW" },
	{ HPPA_INS_PROBEW, "(RR)RW" },
	{ HPPA_INS_PROBEWI, "(RR)iW" },
	{ HPPA_INS_LPA, "r(Rb)W" },
	{ HPPA_INS_LCI, "r(RR)W" },
	{ HPPA_INS_PDTLB, "r(Rb)" },
	{ HPPA_INS_PITLB, "r(Rb)" },
	{ HPPA_INS_PDTLBE, "r(Rb)" },
	{ HPPA_INS_PITLBE, "r(Rb)" },
	{ HPPA_INS_IDTLBA, "R(RR)" },
	{ HPPA_INS_IITLBA, "R(RR)" },
	{ HPPA_INS_IDTLBP, "R(RR)" },
	{ HPPA_INS_IITLBP, "R(RR)" },
	{ HPPA_INS_PDC, "r(Rb)" },
	{ HPPA_INS_FDC, "r(Rb)" },
	{ HPPA_INS_FIC, "r(Rb)" },
	{ HPPA_INS_FDCE, "r(Rb)" },
	{ HPPA_INS_FICE, "r(Rb)" },
	{ HPPA_INS_DIAG, "i" },
	{ HPPA_INS_IDTLBT, "" },
	{ HPPA_INS_IITLBT, "" },

	{ HPPA_INS_FLDW, "" },
	{ HPPA_INS_FLDD, "" },
	{ HPPA_INS_FSTW, "" },
	{ HPPA_INS_FSTD, "" },
	{ HPPA_INS_FLDWX, "r(Rb)W" },
	{ HPPA_INS_FLDDX, "r(Rb)W" },
	{ HPPA_INS_FSTWX, "Rr(Rb)" },
	{ HPPA_INS_FSTDX, "Rr(Rb)" },
	{ HPPA_INS_FSTQX, "" },
	{ HPPA_INS_FLDWS, "o(Rb)W" },
	{ HPPA_INS_FLDDS, "o(Rb)W" },
	{ HPPA_INS_FSTWS, "Ro(Rb)" },
	{ HPPA_INS_FSTDS, "Ro(Rb)" },
	{ HPPA_INS_FSTQS, "Ro(Rb)" },
	{ HPPA_INS_FADD, "RRW" },
	{ HPPA_INS_FSUB, "RRW" },
	{ HPPA_INS_FMPY, "RRW" },
	{ HPPA_INS_FDIV, "RRW" },
	{ HPPA_INS_FSQRT, "RW" },
	{ HPPA_INS_FABS, "RW" },
	{ HPPA_INS_FREM, "" },
	{ HPPA_INS_FRND, "RW" },
	{ HPPA_INS_FCPY, "RW" },
	{ HPPA_INS_FCNVFF, "RW" },
	{ HPPA_INS_FCNVXF, "RW" },
	{ HPPA_INS_FCNVFX, "RW" },
	{ HPPA_INS_FCNVFXT, "RW" },
	{ HPPA_INS_FMPYFADD, "" },
	{ HPPA_INS_FMPYNFADD, "" },
	{ HPPA_INS_FNEG, "" },
	{ HPPA_INS_FNEGABS, "" },
	{ HPPA_INS_FCNV, "" },
	{ HPPA_INS_FCMP, "RR" },
	{ HPPA_INS_XMPYU, "RRW" },
	{ HPPA_INS_FMPYADD, "RRWRw" },
	{ HPPA_INS_FMPYSUB, "RRWRw" },
	{ HPPA_INS_FTEST, "" },
	{ HPPA_INS_FID, "" },

	{ HPPA_INS_PMDIS, "" },
	{ HPPA_INS_PMENB, "" },

	{ HPPA_INS_SPOP0, "" },
	{ HPPA_INS_SPOP1, "W" },
	{ HPPA_INS_SPOP2, "R" },
	{ HPPA_INS_SPOP3, "RR" },
	{ HPPA_INS_COPR, "" },
	{ HPPA_INS_CLDW, "" },
	{ HPPA_INS_CLDD, "" },
	{ HPPA_INS_CSTW, "" },
	{ HPPA_INS_CSTD, "" },
	{ HPPA_INS_CLDWX, "r(Rb)W" },
	{ HPPA_INS_CLDDX, "r(Rb)W" },
	{ HPPA_INS_CSTWX, "Rr(Rb)" },
	{ HPPA_INS_CSTDX, "Rr(Rb)" },
	{ HPPA_INS_CLDWS, "o(Rb)W" },
	{ HPPA_INS_CLDDS, "o(Rb)W" },
	{ HPPA_INS_CSTWS, "Ro(Rb)" },
	{ HPPA_INS_CSTDS, "Ro(Rb)" },

	{ HPPA_INS_CALL, "" },
	{ HPPA_INS_RET, "" },
};

static void print_operand(MCInst *MI, struct SStream *O, const cs_hppa_op *op)
{
	switch (op->type) {
	case HPPA_OP_INVALID:
		SStream_concat(O, "invalid");
		break;
	case HPPA_OP_REG:
		SStream_concat(O, HPPA_reg_name((csh)MI->csh, op->reg));
		break;
	case HPPA_OP_IMM:
		printInt64(O, op->imm);
		break;
    case HPPA_OP_DISP:
		printInt64(O, op->imm);
		break;
	case HPPA_OP_IDX_REG:
		SStream_concat(O, HPPA_reg_name((csh)MI->csh, op->reg));
		break;
	case HPPA_OP_MEM:
		SStream_concat(O, "(");
		if (op->mem.space != HPPA_OP_INVALID) {
			SStream_concat(O, HPPA_reg_name((csh)MI->csh, op->mem.space));
			SStream_concat(O, ",");
		}
		SStream_concat(O, HPPA_reg_name((csh)MI->csh, op->mem.base));
		SStream_concat(O, ")");
		break;
	case HPPA_OP_TARGET:
		printInt64(O, MI->address + op->imm);
		break;
	}
}

#define NUMFMTS ((sizeof pa_formats)/(sizeof pa_formats[0]))

static void fill_operands(MCInst *MI, cs_hppa *hppa)
{
	unsigned mc_op_count = MCInst_getNumOperands(MI);
	MCOperand *ops[mc_op_count];
	for (unsigned i = 0; i < mc_op_count; i++) {
		ops[i] = MCInst_getOperand(MI, i);
	}

	hppa->op_count = 0;
	hppa_ext *hppa_ext = &MI->hppa_ext;
	uint32_t opcode = MCInst_getOpcode(MI);

    for (int i = 0; i < NUMFMTS; ++i) {
		const struct pa_insn_fmt *pa_fmt = &pa_formats[i];
		
		if (opcode == pa_fmt->insn_id) {
			char *fmt = (char *)pa_fmt->format;
            uint8_t idx = 0;
            while (*fmt)
			{
				switch (*fmt++)
				{
           	    case 'i':
					set_op_imm(hppa, MCOperand_getImm(ops[idx++]));
                    break;
                case 'o':
                    set_op_disp(hppa, MCOperand_getImm(ops[idx++]));
                    break;
				
				case 'R':
					set_op_reg(hppa, MCOperand_getReg(ops[idx++]), CS_AC_READ);
					break;

				case 'W':
					set_op_reg(hppa, MCOperand_getReg(ops[idx++]), CS_AC_WRITE);
					break;

				case 'w':
					set_op_reg(hppa, MCOperand_getReg(ops[idx++]), CS_AC_READ_WRTE);
					break;

				case 'r':
					set_op_idx_reg(hppa, MCOperand_getReg(ops[idx++]));
					break;

				case 'T':
					set_op_target(hppa, MCOperand_getImm(ops[idx++]) + 8);
					break;

				case 'Y':
					set_op_reg(hppa, MCOperand_getReg(ops[idx++]), CS_AC_WRITE);
					set_op_reg(hppa, MCOperand_getReg(ops[idx++]), CS_AC_WRITE);
					break;

				case '0':
					set_op_reg(hppa, MCOperand_getReg(ops[idx++]), CS_AC_INVALID);
					break;

				case '(':
					uint32_t regs[2] = { HPPA_REG_INVALID, HPPA_REG_INVALID };
					uint8_t reg_idx = 0;
					cs_ac_type base_access = CS_AC_INVALID;
					while (*fmt != ')') {
						regs[reg_idx] = MCOperand_getReg(ops[idx++]);
						if (*fmt == 'R') {
							base_access = CS_AC_READ;
						} else if (*fmt == 'W') {
							base_access = CS_AC_WRITE;
						} else if (*fmt == 'b') {
							base_access = CS_AC_READ; 
							if (hppa_ext->b_writeble)
								base_access |= CS_AC_WRITE;
						}
						fmt++;
						reg_idx++;
					}

					if (regs[1] == HPPA_OP_INVALID)
						set_op_mem(hppa, regs[0], regs[1], base_access);
					else 
						set_op_mem(hppa, regs[1], regs[0], base_access);
					fmt++;
					break;

				default:
					printf("Unknown: %c\n", *(fmt-1));
					break;
				}
			}
			
            break;
        }
    }

}

static void print_modifiers(MCInst *MI, struct SStream *O) 
{
    hppa_ext *hppa_ext = &MI->hppa_ext;
    for (uint8_t i = 0; i < hppa_ext->mod_num; ++i) {
        SStream_concat(O, ",");
        if (hppa_ext->modifiers[i].type == 0)
            SStream_concat(O, hppa_ext->modifiers[i].str_mod);
        else 
            printInt64(O, hppa_ext->modifiers[i].int_mod);
    }
}

void HPPA_printInst(MCInst *MI, struct SStream *O, void *Info)
{
	cs_insn insn;
	cs_hppa hppa;

	insn.detail = NULL;
	/* set pubOpcode as instruction id */
	// HPPA_get_insn_id((cs_struct *)MI->csh, MI->flat_insn, MCInst_getOpcode(MI));
	MCInst_setOpcodePub(MI, MCInst_getOpcode(MI));

	SStream_concat(O, HPPA_insn_name((csh)MI->csh, MCInst_getOpcode(MI)));
    print_modifiers(MI, O);
	SStream_concat(O, "\t");
	fill_operands(MI, &hppa);
	for (int i = 0; i < hppa.op_count; i++) {
		cs_hppa_op *op = &hppa.operands[i];
		print_operand(MI, O, op);
		if (op->type != HPPA_OP_IDX_REG && op->type != HPPA_OP_DISP && 
            i != hppa.op_count-1) {
			SStream_concat(O, ",");
		}
		
	}

#ifndef CAPSTONE_DIET
	if (MI->flat_insn->detail) {
		MI->flat_insn->detail->hppa = hppa;
	}
#endif
}

#endif