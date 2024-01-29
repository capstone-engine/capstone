/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev  <sibirtsevdl@gmail.com>, 2023 */

// #ifdef CAPSTONE_HAS_HPPA

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
	bool cmplt; 	// true if some completer affects on instruction format
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
   x - [r] or [o] defined by the operand kind
   b - base register (may be writable in some cases)
   
*/

static const struct pa_insn_fmt pa_formats[] = 
{
	{ HPPA_INS_LDI, "iW", false },

	{ HPPA_INS_CMPIB, "iRT", false },
	{ HPPA_INS_COMIB, "iRT", false },

	{ HPPA_INS_CMPB, "RRT", false },
	{ HPPA_INS_COMB, "RRT", false },

	{ HPPA_INS_ADDB, "RwT", false },

	{ HPPA_INS_ADDIB, "iwT", false },

	{ HPPA_INS_NOP, "", false },
	{ HPPA_INS_COPY, "RW", false },
	{ HPPA_INS_MTSAR, "R", false },

	{ HPPA_INS_LDD, "x(Rb)W", false },
	// { HPPA_INS_LDW, "o(Rb)W", false },
	{ HPPA_INS_LDW, "x(Rb)W", false },
	// { HPPA_INS_LDH, "o(Rb)W", false },
	{ HPPA_INS_LDH, "x(Rb)W", false },
	// { HPPA_INS_LDB, "o(Rb)W", false },
	{ HPPA_INS_LDB, "x(Rb)W", false },
	{ HPPA_INS_STD, "Ro(Rb)", false },
	{ HPPA_INS_STW, "Ro(Rb)", false },
	{ HPPA_INS_STH, "Ro(Rb)", false },
	{ HPPA_INS_STB, "Ro(Rb)", false },
	{ HPPA_INS_LDWM, "o(Rw)W", false },
	{ HPPA_INS_STWM, "Ro(Rw)", false },
	{ HPPA_INS_LDWX, "r(Rb)W", false },
	{ HPPA_INS_LDHX, "r(Rb)W", false },
	{ HPPA_INS_LDBX, "r(Rb)W", false },
	{ HPPA_INS_LDWA, "x(R)W", false },
	{ HPPA_INS_LDCW, "x(Rb)W", false },
	{ HPPA_INS_STWA, "Ro(b)", false },
	{ HPPA_INS_STBY, "Ro(Rb)", false },
	{ HPPA_INS_LDDA, "x(b)W", false },
	{ HPPA_INS_LDCD, "x(Rb)W", false },
	{ HPPA_INS_STDA, "Ro(b)", false },
	{ HPPA_INS_LDWAX, "r(b)W", false },
	{ HPPA_INS_LDCWX, "r(Rb)W", false },
	{ HPPA_INS_LDWS, "o(Rb)W", false },
	{ HPPA_INS_LDHS, "o(Rb)W", false },
	{ HPPA_INS_LDBS, "o(Rb)W", false },
	{ HPPA_INS_LDWAS, "o(b)W", false },
	{ HPPA_INS_LDCWS, "o(Rb)W", false },
	{ HPPA_INS_STWS, "Ro(Rb)", false },
	{ HPPA_INS_STHS, "Ro(Rb)", false },
	{ HPPA_INS_STBS, "Ro(Rb)", false },
	{ HPPA_INS_STWAS, "Ro(b)", false },
	{ HPPA_INS_STDBY, "Ro(Rb)", false },
	{ HPPA_INS_STBYS, "Ro(Rb)", false },

	{ HPPA_INS_LDO, "o(R)W", false },
	{ HPPA_INS_LDIL, "iW", false },
	{ HPPA_INS_ADDIL, "iR", false },

	{ HPPA_INS_B, "TW", false },
	// { HPPA_INS_B, "TR", false },
	{ HPPA_INS_BL, "TW", false },
	{ HPPA_INS_GATE, "TW", false },
	{ HPPA_INS_BLR, "RW", false },
	{ HPPA_INS_BV, "R(R)", false },
	{ HPPA_INS_BVE, "(b)", false },
	{ HPPA_INS_BVE, "(b)W", true },
	{ HPPA_INS_BE, "o(RR)", false },
	{ HPPA_INS_BE, "o(RR)WW", true },
	{ HPPA_INS_BLE, "o(RR)", false },
	{ HPPA_INS_MOVB, "RWT", false },
	{ HPPA_INS_MOVIB, "iWT", false },
	{ HPPA_INS_COMBT, "RRT", false },
	{ HPPA_INS_COMBF, "RRT", false },
	{ HPPA_INS_COMIBT, "iRT", false },
	{ HPPA_INS_COMIBF, "iRT", false },
	{ HPPA_INS_ADDBT, "RwT", false },
	{ HPPA_INS_ADDBF, "RwT", false },
	{ HPPA_INS_ADDIBT, "iwT", false },
	{ HPPA_INS_ADDIBF, "iwT", false },
	{ HPPA_INS_BB, "RiT", false },
	{ HPPA_INS_BVB, "RT", false },
	{ HPPA_INS_CLRBTS, "", false },
	{ HPPA_INS_POPBTS, "i", false },
	{ HPPA_INS_PUSHNOM, "", false },
	{ HPPA_INS_PUSHBTS, "R", false },

	{ HPPA_INS_CMPCLR, "RRW", false },
	{ HPPA_INS_COMCLR, "RRW", false },
	{ HPPA_INS_OR, "RRW", false },
	{ HPPA_INS_XOR, "RRW", false },
	{ HPPA_INS_AND, "RRW", false },
	{ HPPA_INS_ANDCM, "RRW", false },
	{ HPPA_INS_UXOR, "RRW", false },
	{ HPPA_INS_UADDCM, "RRW", false },
	{ HPPA_INS_UADDCMT, "RRW", false },
	{ HPPA_INS_DCOR, "RW", false },
	{ HPPA_INS_IDCOR, "RW", false },
	{ HPPA_INS_ADDI, "iRW", false },
	{ HPPA_INS_ADDIO, "iRW", false },
	{ HPPA_INS_ADDIT, "iRW", false },
	{ HPPA_INS_ADDITO, "iRW", false },
	{ HPPA_INS_ADD, "RRW", false },
	{ HPPA_INS_ADDL, "RRW", false },
	{ HPPA_INS_ADDO, "RRW", false },
	{ HPPA_INS_ADDC, "RRW", false },
	{ HPPA_INS_ADDCO, "RRW", false },
	{ HPPA_INS_SUB, "RRW", false },
	{ HPPA_INS_SUBO, "RRW", false },
	{ HPPA_INS_SUBB, "RRW", false },
	{ HPPA_INS_SUBBO, "RRW", false },
	{ HPPA_INS_SUBT, "RRW", false },
	{ HPPA_INS_SUBTO, "RRW", false },
	{ HPPA_INS_DS, "RRW", false },
	{ HPPA_INS_SUBI, "iRW", false },
	{ HPPA_INS_SUBIO, "iRW", false },
	{ HPPA_INS_CMPICLR, "iRW", false },
	{ HPPA_INS_COMICLR, "iRW", false },
	{ HPPA_INS_SHLADD, "RiRW", false },
	{ HPPA_INS_SH1ADD, "RRW", false },
	{ HPPA_INS_SH1ADDL, "RRW", false },
	{ HPPA_INS_SH1ADDO, "RRW", false },
	{ HPPA_INS_SH2ADD, "RRW", false },
	{ HPPA_INS_SH2ADDL, "RRW", false },
	{ HPPA_INS_SH2ADDO, "RRW", false },
	{ HPPA_INS_SH3ADD, "RRW", false },
	{ HPPA_INS_SH3ADDL, "RRW", false },
	{ HPPA_INS_SH3ADDO, "RRW", false },

	{ HPPA_INS_HADD, "RRW", false },
	{ HPPA_INS_HAVG, "RRW", false },
	{ HPPA_INS_HSHL, "RiW", false },
	{ HPPA_INS_HSHLADD, "RiRW", false },
	{ HPPA_INS_HSHR, "RiW", false },
	{ HPPA_INS_HSHRADD, "RiRW", false },
	{ HPPA_INS_HSUB, "RRW", false },
	{ HPPA_INS_MIXH, "RRW", false },
	{ HPPA_INS_MIXW, "RRW", false },
	{ HPPA_INS_PERMH, "RW", false },

	{ HPPA_INS_SHRPD, "RRiW", false },
	{ HPPA_INS_SHRPW, "RRiW", false },
	{ HPPA_INS_VSHD, "RRW", false },
	{ HPPA_INS_SHD, "RRiW", false },
	{ HPPA_INS_EXTRD, "RiiW", false },
	{ HPPA_INS_EXTRW, "RiiW", false },
	{ HPPA_INS_VEXTRU, "RiW", false },
	{ HPPA_INS_VEXTRS, "RiW", false },
	{ HPPA_INS_EXTRU, "RiiW", false },
	{ HPPA_INS_EXTRS, "RiiW", false },
	{ HPPA_INS_DEPD, "RiiW", false },
	{ HPPA_INS_DEPDI, "iiiW", false },
	{ HPPA_INS_DEPW, "RiiW", false },
	{ HPPA_INS_DEPWI, "iiiW", false },
	{ HPPA_INS_ZVDEP, "RiW", false },
	{ HPPA_INS_VDEP, "RiW", false },
	{ HPPA_INS_ZDEP, "RiiW", false },
	{ HPPA_INS_DEP, "RiiW", false },
	{ HPPA_INS_ZVDEPI, "iiW", false },
	{ HPPA_INS_VDEPI, "iiW", false },
	{ HPPA_INS_ZDEPI, "iiiW", false },
	{ HPPA_INS_DEPI, "iiiW", false },

	{ HPPA_INS_BREAK, "ii", false },
	{ HPPA_INS_RFI, "", false },
	{ HPPA_INS_RFIR, "", false },
	{ HPPA_INS_SSM, "iW", false },
	{ HPPA_INS_RSM, "iW", false },
	{ HPPA_INS_MTSM, "R", false },
	{ HPPA_INS_LDSID, "(RR)W", false },
	{ HPPA_INS_MTSP, "RW", false },
	{ HPPA_INS_MTCTL, "RW", false },
	{ HPPA_INS_MTSARCM, "R", false },
	{ HPPA_INS_MFIA, "W", false },
	{ HPPA_INS_MFSP, "RW", false },
	{ HPPA_INS_MFCTL, "RW", false },
	{ HPPA_INS_SYNC, "", false },
	{ HPPA_INS_SYNCDMA, "", false },
	{ HPPA_INS_PROBE, "(RR)RW", false },
	{ HPPA_INS_PROBEI, "(RR)iW", false },
	{ HPPA_INS_PROBER, "(RR)RW", false },
	{ HPPA_INS_PROBERI, "(RR)iW", false },
	{ HPPA_INS_PROBEW, "(RR)RW", false },
	{ HPPA_INS_PROBEWI, "(RR)iW", false },
	{ HPPA_INS_LPA, "r(Rb)W", false },
	{ HPPA_INS_LCI, "r(RR)W", false },
	{ HPPA_INS_PDTLB, "r(Rb)", false },
	{ HPPA_INS_PITLB, "r(Rb)", false },
	{ HPPA_INS_PDTLBE, "r(Rb)", false },
	{ HPPA_INS_PITLBE, "r(Rb)", false },
	{ HPPA_INS_IDTLBA, "R(RR)", false },
	{ HPPA_INS_IITLBA, "R(RR)", false },
	{ HPPA_INS_IDTLBP, "R(RR)", false },
	{ HPPA_INS_IITLBP, "R(RR)", false },
	{ HPPA_INS_PDC, "r(Rb)", false },
	{ HPPA_INS_FDC, "r(Rb)", false },
	{ HPPA_INS_FIC, "r(Rb)", false },
	{ HPPA_INS_FDCE, "r(Rb)", false },
	{ HPPA_INS_FICE, "r(Rb)", false },
	{ HPPA_INS_DIAG, "i", false },
	{ HPPA_INS_IDTLBT, "RR", false },
	{ HPPA_INS_IITLBT, "RR", false },

	{ HPPA_INS_FLDW, "x(Rb)W", false },
	{ HPPA_INS_FLDD, "x(Rb)W", false },
	{ HPPA_INS_FSTW, "Rx(Rb)", false },
	{ HPPA_INS_FSTD, "Rx(Rb)", false },
	{ HPPA_INS_FLDWX, "r(Rb)W", false },
	{ HPPA_INS_FLDDX, "r(Rb)W", false },
	{ HPPA_INS_FSTWX, "Rr(Rb)", false },
	{ HPPA_INS_FSTDX, "Rr(Rb)", false },
	{ HPPA_INS_FSTQX, "", false },
	{ HPPA_INS_FLDWS, "o(Rb)W", false },
	{ HPPA_INS_FLDDS, "o(Rb)W", false },
	{ HPPA_INS_FSTWS, "Ro(Rb)", false },
	{ HPPA_INS_FSTDS, "Ro(Rb)", false },
	{ HPPA_INS_FSTQS, "Ro(Rb)", false },
	{ HPPA_INS_FADD, "RRW", false },
	{ HPPA_INS_FSUB, "RRW", false },
	{ HPPA_INS_FMPY, "RRW", false },
	{ HPPA_INS_FDIV, "RRW", false },
	{ HPPA_INS_FSQRT, "RW", false },
	{ HPPA_INS_FABS, "RW", false },
	{ HPPA_INS_FREM, "", false },
	{ HPPA_INS_FRND, "RW", false },
	{ HPPA_INS_FCPY, "RW", false },
	{ HPPA_INS_FCNVFF, "RW", false },
	{ HPPA_INS_FCNVXF, "RW", false },
	{ HPPA_INS_FCNVFX, "RW", false },
	{ HPPA_INS_FCNVFXT, "RW", false },
	{ HPPA_INS_FMPYFADD, "RRRW", false },
	{ HPPA_INS_FMPYNFADD, "RRRW", false },
	{ HPPA_INS_FNEG, "RW", false },
	{ HPPA_INS_FNEGABS, "RW", false },
	{ HPPA_INS_FCNV, "RW", false },
	{ HPPA_INS_FCMP, "RR", false },
	{ HPPA_INS_XMPYU, "RRW", false },
	{ HPPA_INS_FMPYADD, "RRWRw", false },
	{ HPPA_INS_FMPYSUB, "RRWRw", false },
	{ HPPA_INS_FTEST, "", false },
	{ HPPA_INS_FTEST, "i", true },
	{ HPPA_INS_FID, "", false },

	{ HPPA_INS_PMDIS, "", false },
	{ HPPA_INS_PMENB, "", false },

	{ HPPA_INS_SPOP0, "", false },
	{ HPPA_INS_SPOP1, "W", false },
	{ HPPA_INS_SPOP2, "R", false },
	{ HPPA_INS_SPOP3, "RR", false },
	{ HPPA_INS_COPR, "", false },
	{ HPPA_INS_CLDW, "x(Rb)W", false },
	{ HPPA_INS_CLDD, "o(Rb)W", false },
	{ HPPA_INS_CSTW, "Rx(Rb)", false },
	{ HPPA_INS_CSTD, "Rx(Rb)", false },
	{ HPPA_INS_CLDWX, "r(Rb)W", false },
	{ HPPA_INS_CLDDX, "r(Rb)W", false },
	{ HPPA_INS_CSTWX, "Rr(Rb)", false },
	{ HPPA_INS_CSTDX, "Rr(Rb)", false },
	{ HPPA_INS_CLDWS, "o(Rb)W", false },
	{ HPPA_INS_CLDDS, "o(Rb)W", false },
	{ HPPA_INS_CSTWS, "Ro(Rb)", false },
	{ HPPA_INS_CSTDS, "Ro(Rb)", false },

	{ HPPA_INS_CALL, "", false },
	{ HPPA_INS_RET, "", false },
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
		if (opcode == pa_fmt->insn_id && hppa_ext->cmplt == pa_fmt->cmplt) {
			char *fmt = (char *)pa_fmt->format;
            uint8_t idx = 0;
            while (*fmt)
			{
				switch (*fmt++)
				{
           	    case 'i':
					if (MCOperand_isReg(ops[idx])) {
						set_op_reg(hppa, MCOperand_getReg(ops[idx]), CS_AC_READ);
					}
					else {
						set_op_imm(hppa, MCOperand_getImm(ops[idx]));
					}
					idx++;
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

				case 'x':
					if (MCOperand_isReg(ops[idx])) {
						set_op_idx_reg(hppa, MCOperand_getReg(ops[idx]));
					}
					else {
						set_op_disp(hppa, MCOperand_getImm(ops[idx]));
					}
					idx++;
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
	MCInst_setOpcodePub(MI, MCInst_getOpcode(MI));

	SStream_concat(O, HPPA_insn_name((csh)MI->csh, MCInst_getOpcode(MI)));
    print_modifiers(MI, O);
	SStream_concat(O, " ");
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

// #endif