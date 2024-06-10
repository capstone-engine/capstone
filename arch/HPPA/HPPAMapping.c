/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev  <sibirtsevdl@gmail.com>, 2023 */

#ifdef CAPSTONE_HAS_HPPA

#include <string.h>
#include <stdlib.h>

#include "HPPAMapping.h"
#include "HPPAConstants.h"
#include "../../Mapping.h"
#include "../../utils.h"

#ifndef CAPSTONE_DIET
static const name_map group_name_maps[] = {
	{ HPPA_GRP_INVALID, NULL },

	{ HPPA_GRP_COMPUTATION, "computation" },
	{ HPPA_GRP_MULTIMEDIA, "multimedia" },
	{ HPPA_GRP_MEM_REF, "memory_reference" },
	{ HPPA_GRP_LONG_IMM, "long_imm" },
	{ HPPA_GRP_BRANCH, "branch" },
	{ HPPA_GRP_SYSCTRL, "system_control" },
	{ HPPA_GRP_ASSIST, "assist" },
	{ HPPA_GRP_FLOAT, "float" },
};
#endif

const char *HPPA_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static const name_map insn_name_maps[HPPA_INS_ENDING] = {
	{ HPPA_INS_INVALID, NULL },

	{ HPPA_INS_ADD, "add" },
	{ HPPA_INS_ADDI, "addi" },
	{ HPPA_INS_ADDIO, "addio" },
	{ HPPA_INS_ADDIT, "addit" },
	{ HPPA_INS_ADDITO, "addito" },
	{ HPPA_INS_ADDB, "addb" },
	{ HPPA_INS_ADDBT, "addbt" },
	{ HPPA_INS_ADDBF, "addbf" },
	{ HPPA_INS_ADDIB, "addib" },
	{ HPPA_INS_ADDIBT, "addibt" },
	{ HPPA_INS_ADDIBF, "addibf" },
	{ HPPA_INS_ADDIL, "addil" },
	{ HPPA_INS_ADDC, "addc" },
	{ HPPA_INS_ADDCO, "addco" },
	{ HPPA_INS_ADDL, "addl" },
	{ HPPA_INS_ADDO, "addo" },
	{ HPPA_INS_AND, "and" },
	{ HPPA_INS_ANDCM, "andcm" },
	{ HPPA_INS_B, "b" },
	{ HPPA_INS_BB, "bb" },
	{ HPPA_INS_BE, "be" },
	{ HPPA_INS_BL, "bl" },
	{ HPPA_INS_BLE, "ble" },
	{ HPPA_INS_BLR, "blr" },
	{ HPPA_INS_BREAK, "break" },
	{ HPPA_INS_BV, "bv" },
	{ HPPA_INS_BVB, "bvb" },
	{ HPPA_INS_BVE, "bve" },
	{ HPPA_INS_CALL, "call" },
	{ HPPA_INS_CLDD, "cldd" },
	{ HPPA_INS_CLDDS, "cldds" },
	{ HPPA_INS_CLDDX, "clddx" },
	{ HPPA_INS_CLDW, "cldw" },
	{ HPPA_INS_CLDWS, "cldws" },
	{ HPPA_INS_CLDWX, "cldwx" },
	{ HPPA_INS_CLRBTS, "clrbts" },
	{ HPPA_INS_CMPB, "cmpb" },
	{ HPPA_INS_CMPCLR, "cmpclr" },
	{ HPPA_INS_CMPIB, "cmpib" },
	{ HPPA_INS_CMPICLR, "cmpiclr" },
	{ HPPA_INS_COMB, "comb" },
	{ HPPA_INS_COMBT, "combt" },
	{ HPPA_INS_COMBF, "combf" },
	{ HPPA_INS_COMCLR, "comclr" },
	{ HPPA_INS_COMIB, "comib" },
	{ HPPA_INS_COMIBT, "comibt" },
	{ HPPA_INS_COMIBF, "comibf" },
	{ HPPA_INS_COMICLR, "comiclr" },
	{ HPPA_INS_COPR, "copr" },
	{ HPPA_INS_COPY, "copy" },
	{ HPPA_INS_CSTD, "cstd" },
	{ HPPA_INS_CSTDS, "cstds" },
	{ HPPA_INS_CSTDX, "cstdx" },
	{ HPPA_INS_CSTW, "cstw" },
	{ HPPA_INS_CSTWS, "cstws" },
	{ HPPA_INS_CSTWX, "cstwx" },
	{ HPPA_INS_DCOR, "dcor" },
	{ HPPA_INS_DEP, "dep" },
	{ HPPA_INS_DEPI, "depi" },
	{ HPPA_INS_DEPD, "depd" },
	{ HPPA_INS_DEPDI, "depdi" },
	{ HPPA_INS_DEPW, "depw" },
	{ HPPA_INS_DEPWI, "depwi" },
	{ HPPA_INS_DIAG, "diag" },
	{ HPPA_INS_DS, "ds" },
	{ HPPA_INS_EXTRD, "extrd" },
	{ HPPA_INS_EXTRS, "extrs" },
	{ HPPA_INS_EXTRU, "extru" },
	{ HPPA_INS_EXTRW, "extrw" },
	{ HPPA_INS_FABS, "fabs" },
	{ HPPA_INS_FADD, "fadd" },
	{ HPPA_INS_FCMP, "fcmp" },
	{ HPPA_INS_FCNV, "fcnv" },
	{ HPPA_INS_FCNVFF, "fcnvff" },
	{ HPPA_INS_FCNVFX, "fcnvfx" },
	{ HPPA_INS_FCNVFXT, "fcnvfxt" },
	{ HPPA_INS_FCNVXF, "fcnvxf" },
	{ HPPA_INS_FCPY, "fcpy" },
	{ HPPA_INS_FDC, "fdc" },
	{ HPPA_INS_FDCE, "fdce" },
	{ HPPA_INS_FDIV, "fdiv" },
	{ HPPA_INS_FIC, "fic" },
	{ HPPA_INS_FICE, "fice" },
	{ HPPA_INS_FID, "fid" },
	{ HPPA_INS_FLDD, "fldd" },
	{ HPPA_INS_FLDDS, "fldds" },
	{ HPPA_INS_FLDDX, "flddx" },
	{ HPPA_INS_FLDW, "fldw" },
	{ HPPA_INS_FLDWS, "fldws" },
	{ HPPA_INS_FLDWX, "fldwx" },
	{ HPPA_INS_FMPY, "fmpy" },
	{ HPPA_INS_FMPYADD, "fmpyadd" },
	{ HPPA_INS_FMPYFADD, "fmpyfadd" },
	{ HPPA_INS_FMPYNFADD, "fmpynfadd" },
	{ HPPA_INS_FMPYSUB, "fmpysub" },
	{ HPPA_INS_FNEG, "fneg" },
	{ HPPA_INS_FNEGABS, "fnegabs" },
	{ HPPA_INS_FREM, "frem" },
	{ HPPA_INS_FRND, "frnd" },
	{ HPPA_INS_FSQRT, "fsqrt" },
	{ HPPA_INS_FSTD, "fstd" },
	{ HPPA_INS_FSTDS, "fstds" },
	{ HPPA_INS_FSTDX, "fstdx" },
	{ HPPA_INS_FSTW, "fstw" },
	{ HPPA_INS_FSTWS, "fstws" },
	{ HPPA_INS_FSTWX, "fstwx" },
	{ HPPA_INS_FSTQS, "fstqs" },
	{ HPPA_INS_FSTQX, "fstqx" },
	{ HPPA_INS_FSUB, "fsub" },
	{ HPPA_INS_FTEST, "ftest" },
	{ HPPA_INS_GATE, "gate" },
	{ HPPA_INS_GFR, "gfr" },
	{ HPPA_INS_GFW, "gfw" },
	{ HPPA_INS_GRSHDW, "grshdw" },
	{ HPPA_INS_HADD, "hadd" },
	{ HPPA_INS_HAVG, "havg" },
	{ HPPA_INS_HSHL, "hshl" },
	{ HPPA_INS_HSHLADD, "hshladd" },
	{ HPPA_INS_HSHR, "hshr" },
	{ HPPA_INS_HSHRADD, "hshradd" },
	{ HPPA_INS_HSUB, "hsub" },
	{ HPPA_INS_IDTLBA, "idtlba" },
	{ HPPA_INS_IDTLBP, "idtlbp" },
	{ HPPA_INS_IDTLBT, "idtlbt" },
	{ HPPA_INS_IDCOR, "idcor" },
	{ HPPA_INS_IITLBA, "iitlba" },
	{ HPPA_INS_IITLBP, "iitlbp" },
	{ HPPA_INS_IITLBT, "iitlbt" },
	{ HPPA_INS_LCI, "lci" },
	{ HPPA_INS_LDB, "ldb" },
	{ HPPA_INS_LDBS, "ldbs" },
	{ HPPA_INS_LDBX, "ldbx" },
	{ HPPA_INS_LDCD, "ldcd" },
	{ HPPA_INS_LDCW, "ldcw" },
	{ HPPA_INS_LDCWS, "ldcws" },
	{ HPPA_INS_LDCWX, "ldcwx" },
	{ HPPA_INS_LDD, "ldd" },
	{ HPPA_INS_LDDA, "ldda" },
	{ HPPA_INS_LDH, "ldh" },
	{ HPPA_INS_LDHS, "ldhs" },
	{ HPPA_INS_LDHX, "ldhx" },
	{ HPPA_INS_LDI, "ldi" },
	{ HPPA_INS_LDIL, "ldil" },
	{ HPPA_INS_LDO, "ldo" },
	{ HPPA_INS_LDSID, "ldsid" },
	{ HPPA_INS_LDW, "ldw" },
	{ HPPA_INS_LDWA, "ldwa" },
	{ HPPA_INS_LDWAS, "ldwas" },
	{ HPPA_INS_LDWAX, "ldwax" },
	{ HPPA_INS_LDWM, "ldwm" },
	{ HPPA_INS_LDWS, "ldws" },
	{ HPPA_INS_LDWX, "ldwx" },
	{ HPPA_INS_LPA, "lpa" },
	{ HPPA_INS_MFCPU, "mfcpu" },
	{ HPPA_INS_MFCTL, "mfctl" },
	{ HPPA_INS_MFIA, "mfia" },
	{ HPPA_INS_MFSP, "mfsp" },
	{ HPPA_INS_MIXH, "mixh" },
	{ HPPA_INS_MIXW, "mixw" },
	{ HPPA_INS_MOVB, "movb" },
	{ HPPA_INS_MOVIB, "movib" },
	{ HPPA_INS_MTCPU, "mtcpu" },
	{ HPPA_INS_MTCTL, "mtctl" },
	{ HPPA_INS_MTSAR, "mtsar" },
	{ HPPA_INS_MTSARCM, "mtsarcm" },
	{ HPPA_INS_MTSM, "mtsm" },
	{ HPPA_INS_MTSP, "mtsp" },
	{ HPPA_INS_NOP, "nop" },
	{ HPPA_INS_OR, "or" },
	{ HPPA_INS_PDC, "pdc" },
	{ HPPA_INS_PDTLB, "pdtlb" },
	{ HPPA_INS_PDTLBE, "pdtlbe" },
	{ HPPA_INS_PERMH, "permh" },
	{ HPPA_INS_PITLB, "pitlb" },
	{ HPPA_INS_PITLBE, "pitlbe" },
	{ HPPA_INS_PMDIS, "pmdis" },
	{ HPPA_INS_PMENB, "pmenb" },
	{ HPPA_INS_POPBTS, "popbts" },
	{ HPPA_INS_PROBE, "probe" },
	{ HPPA_INS_PROBEI, "probei" },
	{ HPPA_INS_PROBER, "prober" },
	{ HPPA_INS_PROBERI, "proberi" },
	{ HPPA_INS_PROBEW, "probew" },
	{ HPPA_INS_PROBEWI, "probewi" },
	{ HPPA_INS_PUSHBTS, "pushbts" },
	{ HPPA_INS_PUSHNOM, "pushnom" },
	{ HPPA_INS_RET, "ret" },
	{ HPPA_INS_RFI, "rfi" },
	{ HPPA_INS_RFIR, "rfir" },
	{ HPPA_INS_RSM, "rsm" },
	{ HPPA_INS_SHDWGR, "shdwgr" },
	{ HPPA_INS_SHLADD, "shladd" },
	{ HPPA_INS_SH1ADD, "sh1add" },
	{ HPPA_INS_SH1ADDL, "sh1addl" },
	{ HPPA_INS_SH1ADDO, "sh1addo" },
	{ HPPA_INS_SH2ADD, "sh2add" },
	{ HPPA_INS_SH2ADDL, "sh2addl" },
	{ HPPA_INS_SH2ADDO, "sh2addo" },
	{ HPPA_INS_SH3ADD, "sh3add" },
	{ HPPA_INS_SH3ADDL, "sh3addl" },
	{ HPPA_INS_SH3ADDO, "sh3addo" },
	{ HPPA_INS_SHD, "shd" },
	{ HPPA_INS_SHRPD, "shrpd" },
	{ HPPA_INS_SHRPW, "shrpw" },
	{ HPPA_INS_SPOP0, "spop0" },
	{ HPPA_INS_SPOP1, "spop1" },
	{ HPPA_INS_SPOP2, "spop2" },
	{ HPPA_INS_SPOP3, "spop3" },
	{ HPPA_INS_SSM, "ssm" },
	{ HPPA_INS_STB, "stb" },
	{ HPPA_INS_STBS, "stbs" },
	{ HPPA_INS_STBY, "stby" },
	{ HPPA_INS_STBYS, "stbys" },
	{ HPPA_INS_STD, "std" },
	{ HPPA_INS_STDA, "stda" },
	{ HPPA_INS_STDBY, "stdby" },
	{ HPPA_INS_STH, "sth" },
	{ HPPA_INS_STHS, "sths" },
	{ HPPA_INS_STW, "stw" },
	{ HPPA_INS_STWA, "stwa" },
	{ HPPA_INS_STWAS, "stwas" },
	{ HPPA_INS_STWS, "stws" },
	{ HPPA_INS_STWM, "stwm" },
	{ HPPA_INS_SUB, "sub" },
	{ HPPA_INS_SUBB, "subb" },
	{ HPPA_INS_SUBBO, "subbo" },
	{ HPPA_INS_SUBI, "subi" },
	{ HPPA_INS_SUBIO, "subio" },
	{ HPPA_INS_SUBO, "subo" },
	{ HPPA_INS_SUBT, "subt" },
	{ HPPA_INS_SUBTO, "subto" },
	{ HPPA_INS_SYNC, "sync" },
	{ HPPA_INS_SYNCDMA, "syncdma" },
	{ HPPA_INS_TOCDIS, "tocdis" },
	{ HPPA_INS_TOCEN, "tocen" },
	{ HPPA_INS_UADDCM, "uaddcm" },
	{ HPPA_INS_UADDCMT, "uaddcmt" },
	{ HPPA_INS_UXOR, "uxor" },
	{ HPPA_INS_VDEP, "vdep" },
	{ HPPA_INS_VDEPI, "vdepi" },
	{ HPPA_INS_VEXTRS, "vextrs" },
	{ HPPA_INS_VEXTRU, "vextru" },
	{ HPPA_INS_VSHD, "vshd" },
	{ HPPA_INS_XMPYU, "xmpyu" },
	{ HPPA_INS_XOR, "xor" },
	{ HPPA_INS_ZDEP, "zdep" },
	{ HPPA_INS_ZDEPI, "zdepi" },
	{ HPPA_INS_ZVDEP, "zvdep" },
	{ HPPA_INS_ZVDEPI, "zvdepi" },
};
#endif

const char *HPPA_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(insn_name_maps, ARR_SIZE(insn_name_maps), id);
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
/* Integer register names, indexed by the numbers which appear in the
   opcodes.  */
static const char *const reg_names[] = {
	"flags", "r1",	"rp",  "r3",  "r4",   "r5",   "r6",  "r7",
	"r8",	 "r9",	"r10", "r11", "r12",  "r13",  "r14", "r15",
	"r16",	 "r17", "r18", "r19", "r20",  "r21",  "r22", "r23",
	"r24",	 "r25", "r26", "dp",  "ret0", "ret1", "sp",  "r31"
};

/* Floating point register names, indexed by the numbers which appear in the
   opcodes.  */
static const char *const fp_reg_names[] = {
	"fpsr", "fpe2", "fpe4", "fpe6", "fr4",	"fr5",	"fr6",	"fr7",
	"fr8",	"fr9",	"fr10", "fr11", "fr12", "fr13", "fr14", "fr15",
	"fr16", "fr17", "fr18", "fr19", "fr20", "fr21", "fr22", "fr23",
	"fr24", "fr25", "fr26", "fr27", "fr28", "fr29", "fr30", "fr31"
};

static const char *const control_reg[] = {
	"rctr",	 "cr1",	  "cr2",  "cr3", "cr4",	  "cr5",   "cr6",  "cr7",
	"pidr1", "pidr2", "ccr",  "sar", "pidr3", "pidr4", "iva",  "eiem",
	"itmr",	 "pcsq",  "pcoq", "iir", "isr",	  "ior",   "ipsw", "eirr",
	"tr0",	 "tr1",	  "tr2",  "tr3", "tr4",	  "tr5",   "tr6",  "tr7"
};

static const char *const space_reg[] = { "sr0", "sr1", "sr2", "sr3",
					 "sr4", "sr5", "sr6", "sr7" };

static const char *const fpe_reg[] = {
	"fpe1",	 "fpe3",  "fpe5",  "fpe7",  "fr4R",  "fr5R",  "fr6R",  "fr7R",
	"fr8R",	 "fr9R",  "fr10R", "fr11R", "fr12R", "fr13R", "fr14R", "fr15R",
	"fr16R", "fr17R", "fr18R", "fr19R", "fr20R", "fr21R", "fr22R", "fr23R",
	"fr24R", "fr25R", "fr26R", "fr27R", "fr28R", "fr29R", "fr30R", "fr31R"
};

static const char *const sp_fp_reg[] = {
	"fr16L", "fr17L", "fr18L", "fr19L", "fr20L", "fr21L", "fr22L", "fr23L",
	"fr24L", "fr25L", "fr26L", "fr27L", "fr28L", "fr29L", "fr30L", "fr31L",
	"fr16R", "fr17R", "fr18R", "fr19R", "fr20R", "fr21R", "fr22R", "fr23R",
	"fr24R", "fr25R", "fr26R", "fr27R", "fr28R", "fr29R", "fr30R", "fr31R"
};
#endif

const char *HPPA_reg_name(csh handle, unsigned int reg)
{
#ifndef CAPSTONE_DIET
	if (reg >= HPPA_REG_GR0 && reg <= HPPA_REG_GR31)
		return reg_names[reg - HPPA_REG_GR0];
	else if (reg >= HPPA_REG_FPR0 && reg <= HPPA_REG_FPR31)
		return fp_reg_names[reg - HPPA_REG_FPR0];
	else if (reg >= HPPA_REG_SR0 && reg <= HPPA_REG_SR7)
		return space_reg[reg - HPPA_REG_SR0];
	else if (reg >= HPPA_REG_CR0 && reg <= HPPA_REG_CR31)
		return control_reg[reg - HPPA_REG_CR0];
	else if (reg >= HPPA_REG_FPE0 && reg <= HPPA_REG_FPE31)
		return fpe_reg[reg - HPPA_REG_FPE0];
	else if (reg >= HPPA_REG_SP_FPR0 && reg <= HPPA_REG_SP_FPR31)
		return sp_fp_reg[reg - HPPA_REG_SP_FPR0];
	return NULL;
#else
	return NULL;
#endif
}

void HPPA_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int opcode)
{
	insn->id = opcode;
}

static void sort_and_uniq(cs_regs arr, uint8_t n, uint8_t *new_n)
{
	/* arr is always a tiny (usually n < 3) array,
	 * a simple O(n^2) sort is efficient enough. */
	int i;
	int j;
	int iMin;
	int tmp;

	/* a modified selection sort for sorting and making unique */
	for (j = 0; j < n; j++) {
		/* arr[iMin] will be min(arr[j .. n-1]) */
		iMin = j;
		for (i = j + 1; i < n; i++) {
			if (arr[i] < arr[iMin])
				iMin = i;
		}
		if (j != 0 && arr[iMin] == arr[j - 1]) { // duplicate ele found
			arr[iMin] = arr[n - 1];
			--n;
		} else {
			tmp = arr[iMin];
			arr[iMin] = arr[j];
			arr[j] = tmp;
		}
	}

	*new_n = n;
}

void HPPA_reg_access(const cs_insn *insn, cs_regs regs_read,
		     uint8_t *regs_read_count, cs_regs regs_write,
		     uint8_t *regs_write_count)
{
	uint8_t read_count = 0;
	uint8_t write_count = 0;
	const cs_hppa *hppa = &(insn->detail->hppa);

	for (unsigned i = 0; i < hppa->op_count; ++i) {
		const cs_hppa_op *op = &(hppa->operands[i]);
		switch (op->type) {
		case HPPA_OP_REG:
		case HPPA_OP_IDX_REG:
			if (op->access & CS_AC_READ) {
				regs_read[read_count++] = op->reg;
			}
			if (op->access & CS_AC_WRITE) {
				regs_write[write_count++] = op->reg;
			}
			break;
		case HPPA_OP_MEM:
			if (op->mem.space != HPPA_REG_INVALID)
				regs_read[read_count++] = op->mem.space;
			if (op->mem.base_access & CS_AC_READ) {
				regs_read[read_count++] = op->mem.base;
			}
			if (op->mem.base_access & CS_AC_WRITE) {
				regs_write[write_count++] = op->mem.base;
			}
			break;
		default:
			break;
		}
	}

	sort_and_uniq(regs_read, read_count, regs_read_count);
	sort_and_uniq(regs_write, write_count, regs_write_count);
}

#endif
