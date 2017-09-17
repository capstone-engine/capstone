/* Capstone Disassembly Engine */
/* M680X Backend by Wolfgang Schwotzer <wolfgang.schwotzer@gmx.net> 2017 */

/* ======================================================================== */
/* ================================ INCLUDES ============================== */
/* ======================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../../cs_priv.h"
#include "../../utils.h"

#include "../../MCInst.h"
#include "../../MCInstrDesc.h"
#include "../../MCRegisterInfo.h"
#include "M680XInstPrinter.h"
#include "M680XDisassembler.h"
#include "M680XDisassemblerInternals.h"

#ifdef CAPSTONE_HAS_M680X

#ifndef DECL_SPEC
#ifdef _MSC_VER
#define DECL_SPEC __cdecl
#else
#define DECL_SPEC
#endif  // _MSC_VER
#endif  // DECL_SPEC

/* ======================================================================== */
/* ============================ GENERAL DEFINES =========================== */
/* ======================================================================== */

/* ======================================================================== */
/* =============================== PROTOTYPES ============================= */
/* ======================================================================== */

typedef enum insn_hdlr_id {
	illegal_hdlr_id,
	bcc_hdlr_id,
	lbcc_hdlr_id,
	immediate8_hdlr_id,
	immediate16_hdlr_id,
	immediate32_hdlr_id,
	direct_hdlr_id,
	extended_hdlr_id,
	m6800_indexed_hdlr_id,
	m6809_indexed_hdlr_id,
	inherent_hdlr_id,
	reg_reg_hdlr_id,
	reg_bits_hdlr_id,
	hd6301_imm_indexed_hdlr_id,
	hd6309_imm_indexed_hdlr_id,
	hd630x_imm_direct_hdlr_id,
	hd630x_imm_extended_hdlr_id,
	hd6309_bit_move_hdlr_id,
	hd6309_tfm_hdlr_id,
	HANDLER_ID_ENDING,
} insn_hdlr_id;

// Access modes for the first 4 operands. If there are more than
// four operands they use the same access mode as the 4th operand.
//
// u: unchanged
// r: (r)read access
// w: (w)write access
// m: (m)odify access (= read + write)
//
typedef enum e_access_mode {

	uuuu,
	rrrr,
	wwww,
	rwww,
	rrrm,
	rmmm,
	wrrr,
	mrrr,
	mwww,
	mmmm,
	mwrr,
	mmrr,
	wmmm,
	ACCESS_MODE_ENDING,
} e_access_mode;

// Access type values are compatible with enum cs_ac_type:
typedef enum e_access {
	UNCHANGED = CS_AC_INVALID,
	READ = CS_AC_READ,
	WRITE = CS_AC_WRITE,
	MODIFY = (CS_AC_READ | CS_AC_WRITE),
} e_access;

/* Properties of one instruction in PAGE1 (without prefix) */
typedef struct inst_page1 {
	m680x_insn insn : 8;
	insn_hdlr_id handler_id : 5; /* instruction handler id */
} inst_page1;

/* Properties of one instruction in any other PAGE X */
typedef struct inst_pageX {
	unsigned opcode : 8;
	m680x_insn insn : 8;
	insn_hdlr_id handler_id : 5; /* instruction handler id */
} inst_pageX;

typedef struct insn_props {
	unsigned group : 4;
	e_access_mode access_mode : 5;
	m680x_reg reg0 : 5;
	m680x_reg reg1 : 5;
	bool cc_modified : 1;
	bool update_reg_access : 1;
} insn_props;

// M6800/2 instructions
static const inst_page1 g_m6800_inst_page1_table[256] = {
	// 0x0x, inherent instructions
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_NOP, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_TAP, inherent_hdlr_id },
	{ M680X_INS_TPA, inherent_hdlr_id },
	{ M680X_INS_INX, inherent_hdlr_id },
	{ M680X_INS_DEX, inherent_hdlr_id },
	{ M680X_INS_CLV, inherent_hdlr_id },
	{ M680X_INS_SEV, inherent_hdlr_id },
	{ M680X_INS_CLC, inherent_hdlr_id },
	{ M680X_INS_SEC, inherent_hdlr_id },
	{ M680X_INS_CLI, inherent_hdlr_id },
	{ M680X_INS_SEI, inherent_hdlr_id },
	// 0x1x, inherent instructions
	{ M680X_INS_SBA, inherent_hdlr_id },
	{ M680X_INS_CBA, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_TAB, inherent_hdlr_id },
	{ M680X_INS_TBA, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_DAA, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ABA, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	// 0x2x, relative branch instructions
	{ M680X_INS_BRA, bcc_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_BHI, bcc_hdlr_id },
	{ M680X_INS_BLS, bcc_hdlr_id },
	{ M680X_INS_BCC, bcc_hdlr_id },
	{ M680X_INS_BCS, bcc_hdlr_id },
	{ M680X_INS_BNE, bcc_hdlr_id },
	{ M680X_INS_BEQ, bcc_hdlr_id },
	{ M680X_INS_BVC, bcc_hdlr_id },
	{ M680X_INS_BVS, bcc_hdlr_id },
	{ M680X_INS_BPL, bcc_hdlr_id },
	{ M680X_INS_BMI, bcc_hdlr_id },
	{ M680X_INS_BGE, bcc_hdlr_id },
	{ M680X_INS_BLT, bcc_hdlr_id },
	{ M680X_INS_BGT, bcc_hdlr_id },
	{ M680X_INS_BLE, bcc_hdlr_id },
	// 0x3x, inherent instructions
	{ M680X_INS_TSX, inherent_hdlr_id },
	{ M680X_INS_INS, inherent_hdlr_id },
	{ M680X_INS_PULA, inherent_hdlr_id },
	{ M680X_INS_PULB, inherent_hdlr_id },
	{ M680X_INS_DES, inherent_hdlr_id },
	{ M680X_INS_TXS, inherent_hdlr_id },
	{ M680X_INS_PSHA, inherent_hdlr_id },
	{ M680X_INS_PSHB, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_RTS, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_RTI, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_WAI, inherent_hdlr_id },
	{ M680X_INS_SWI, inherent_hdlr_id },
	// 0x4x, Register A instructions
	{ M680X_INS_NEGA, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_COMA, inherent_hdlr_id },
	{ M680X_INS_LSRA, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_RORA, inherent_hdlr_id },
	{ M680X_INS_ASRA, inherent_hdlr_id },
	{ M680X_INS_ASLA, inherent_hdlr_id },
	{ M680X_INS_ROLA, inherent_hdlr_id },
	{ M680X_INS_DECA, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_INCA, inherent_hdlr_id },
	{ M680X_INS_TSTA, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_CLRA, inherent_hdlr_id },
	// 0x5x, Register B instructions
	{ M680X_INS_NEGB, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_COMB, inherent_hdlr_id },
	{ M680X_INS_LSRB, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_RORB, inherent_hdlr_id },
	{ M680X_INS_ASRB, inherent_hdlr_id },
	{ M680X_INS_ASLB, inherent_hdlr_id },
	{ M680X_INS_ROLB, inherent_hdlr_id },
	{ M680X_INS_DECB, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_INCB, inherent_hdlr_id },
	{ M680X_INS_TSTB, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_CLRB, inherent_hdlr_id },
	// 0x6x, indexed instructions
	{ M680X_INS_NEG, m6800_indexed_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_COM, m6800_indexed_hdlr_id },
	{ M680X_INS_LSR, m6800_indexed_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ROR, m6800_indexed_hdlr_id },
	{ M680X_INS_ASR, m6800_indexed_hdlr_id },
	{ M680X_INS_ASL, m6800_indexed_hdlr_id },
	{ M680X_INS_ROL, m6800_indexed_hdlr_id },
	{ M680X_INS_DEC, m6800_indexed_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_INC, m6800_indexed_hdlr_id },
	{ M680X_INS_TST, m6800_indexed_hdlr_id },
	{ M680X_INS_JMP, m6800_indexed_hdlr_id },
	{ M680X_INS_CLR, m6800_indexed_hdlr_id },
	// 0x7x, extended instructions
	{ M680X_INS_NEG, extended_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_COM, extended_hdlr_id },
	{ M680X_INS_LSR, extended_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ROR, extended_hdlr_id },
	{ M680X_INS_ASR, extended_hdlr_id },
	{ M680X_INS_ASL, extended_hdlr_id },
	{ M680X_INS_ROL, extended_hdlr_id },
	{ M680X_INS_DEC, extended_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_INC, extended_hdlr_id },
	{ M680X_INS_TST, extended_hdlr_id },
	{ M680X_INS_JMP, extended_hdlr_id },
	{ M680X_INS_CLR, extended_hdlr_id },
	// 0x8x, immediate instructions with Register A,X,S
	{ M680X_INS_SUBA, immediate8_hdlr_id },
	{ M680X_INS_CMPA, immediate8_hdlr_id },
	{ M680X_INS_SBCA, immediate8_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ANDA, immediate8_hdlr_id },
	{ M680X_INS_BITA, immediate8_hdlr_id },
	{ M680X_INS_LDAA, immediate8_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_EORA, immediate8_hdlr_id },
	{ M680X_INS_ADCA, immediate8_hdlr_id },
	{ M680X_INS_ORAA, immediate8_hdlr_id },
	{ M680X_INS_ADDA, immediate8_hdlr_id },
	{ M680X_INS_CPX, immediate16_hdlr_id },
	{ M680X_INS_BSR, bcc_hdlr_id },
	{ M680X_INS_LDS, immediate16_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	// 0x9x, direct instructions with register A,X,S
	{ M680X_INS_SUBA, direct_hdlr_id },
	{ M680X_INS_CMPA, direct_hdlr_id },
	{ M680X_INS_SBCA, direct_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ANDA, direct_hdlr_id },
	{ M680X_INS_BITA, direct_hdlr_id },
	{ M680X_INS_LDAA, direct_hdlr_id },
	{ M680X_INS_STAA, direct_hdlr_id },
	{ M680X_INS_EORA, direct_hdlr_id },
	{ M680X_INS_ADCA, direct_hdlr_id },
	{ M680X_INS_ORAA, direct_hdlr_id },
	{ M680X_INS_ADDA, direct_hdlr_id },
	{ M680X_INS_CPX, direct_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_LDS, direct_hdlr_id },
	{ M680X_INS_STS, direct_hdlr_id },
	// 0xAx, indexed instructions with Register A,X
	{ M680X_INS_SUBA, m6800_indexed_hdlr_id },
	{ M680X_INS_CMPA, m6800_indexed_hdlr_id },
	{ M680X_INS_SBCA, m6800_indexed_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ANDA, m6800_indexed_hdlr_id },
	{ M680X_INS_BITA, m6800_indexed_hdlr_id },
	{ M680X_INS_LDAA, m6800_indexed_hdlr_id },
	{ M680X_INS_STAA, m6800_indexed_hdlr_id },
	{ M680X_INS_EORA, m6800_indexed_hdlr_id },
	{ M680X_INS_ADCA, m6800_indexed_hdlr_id },
	{ M680X_INS_ORAA, m6800_indexed_hdlr_id },
	{ M680X_INS_ADDA, m6800_indexed_hdlr_id },
	{ M680X_INS_CPX, m6800_indexed_hdlr_id },
	{ M680X_INS_JSR, m6800_indexed_hdlr_id },
	{ M680X_INS_LDS, m6800_indexed_hdlr_id },
	{ M680X_INS_STS, m6800_indexed_hdlr_id },
	// 0xBx, extended instructions with register A,X,S
	{ M680X_INS_SUBA, extended_hdlr_id },
	{ M680X_INS_CMPA, extended_hdlr_id },
	{ M680X_INS_SBCA, extended_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ANDA, extended_hdlr_id },
	{ M680X_INS_BITA, extended_hdlr_id },
	{ M680X_INS_LDAA, extended_hdlr_id },
	{ M680X_INS_STAA, extended_hdlr_id },
	{ M680X_INS_EORA, extended_hdlr_id },
	{ M680X_INS_ADCA, extended_hdlr_id },
	{ M680X_INS_ORAA, extended_hdlr_id },
	{ M680X_INS_ADDA, extended_hdlr_id },
	{ M680X_INS_CPX, extended_hdlr_id },
	{ M680X_INS_JSR, extended_hdlr_id },
	{ M680X_INS_LDS, extended_hdlr_id },
	{ M680X_INS_STS, extended_hdlr_id },
	// 0xCx, immediate instructions with register B,X
	{ M680X_INS_SUBB, immediate8_hdlr_id },
	{ M680X_INS_CMPB, immediate8_hdlr_id },
	{ M680X_INS_SBCB, immediate8_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ANDB, immediate8_hdlr_id },
	{ M680X_INS_BITB, immediate8_hdlr_id },
	{ M680X_INS_LDAB, immediate8_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_EORB, immediate8_hdlr_id },
	{ M680X_INS_ADCB, immediate8_hdlr_id },
	{ M680X_INS_ORAB, immediate8_hdlr_id },
	{ M680X_INS_ADDB, immediate8_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_LDX, immediate16_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	// 0xDx direct instructions with register B,X
	{ M680X_INS_SUBB, direct_hdlr_id },
	{ M680X_INS_CMPB, direct_hdlr_id },
	{ M680X_INS_SBCB, direct_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ANDB, direct_hdlr_id },
	{ M680X_INS_BITB, direct_hdlr_id },
	{ M680X_INS_LDAB, direct_hdlr_id },
	{ M680X_INS_STAB, direct_hdlr_id },
	{ M680X_INS_EORB, direct_hdlr_id },
	{ M680X_INS_ADCB, direct_hdlr_id },
	{ M680X_INS_ORAB, direct_hdlr_id },
	{ M680X_INS_ADDB, direct_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_LDX, direct_hdlr_id },
	{ M680X_INS_STX, direct_hdlr_id },
	// 0xEx, indexed instruction with register B,X
	{ M680X_INS_SUBB, m6800_indexed_hdlr_id },
	{ M680X_INS_CMPB, m6800_indexed_hdlr_id },
	{ M680X_INS_SBCB, m6800_indexed_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ANDB, m6800_indexed_hdlr_id },
	{ M680X_INS_BITB, m6800_indexed_hdlr_id },
	{ M680X_INS_LDAB, m6800_indexed_hdlr_id },
	{ M680X_INS_STAB, m6800_indexed_hdlr_id },
	{ M680X_INS_EORB, m6800_indexed_hdlr_id },
	{ M680X_INS_ADCB, m6800_indexed_hdlr_id },
	{ M680X_INS_ORAB, m6800_indexed_hdlr_id },
	{ M680X_INS_ADDB, m6800_indexed_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_LDX, m6800_indexed_hdlr_id },
	{ M680X_INS_STX, m6800_indexed_hdlr_id },
	// 0xFx, extended instructions with register B,U
	{ M680X_INS_SUBB, extended_hdlr_id },
	{ M680X_INS_CMPB, extended_hdlr_id },
	{ M680X_INS_SBCB, extended_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ANDB, extended_hdlr_id },
	{ M680X_INS_BITB, extended_hdlr_id },
	{ M680X_INS_LDAB, extended_hdlr_id },
	{ M680X_INS_STAB, extended_hdlr_id },
	{ M680X_INS_EORB, extended_hdlr_id },
	{ M680X_INS_ADCB, extended_hdlr_id },
	{ M680X_INS_ORAB, extended_hdlr_id },
	{ M680X_INS_ADDB, extended_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_LDX, extended_hdlr_id },
	{ M680X_INS_STX, extended_hdlr_id },
};

// Additional instructions only supported on M6801/3
static const inst_pageX g_m6801_inst_overlay_table[] = {
	// 0x0x, inherent instructions
	{ 0x04, M680X_INS_LSRD, inherent_hdlr_id },
	{ 0x05, M680X_INS_ASLD, inherent_hdlr_id },
	// 0x2x, relative branch instructions
	{ 0x21, M680X_INS_BRN, bcc_hdlr_id },
	// 0x3x, inherent instructions
	{ 0x38, M680X_INS_PULX, inherent_hdlr_id },
	{ 0x3A, M680X_INS_ABX, inherent_hdlr_id },
	{ 0x3C, M680X_INS_PSHX, inherent_hdlr_id },
	{ 0x3D, M680X_INS_MUL, inherent_hdlr_id  },
	// 0x8x, immediate instructions with Register D
	{ 0x83, M680X_INS_SUBD, immediate16_hdlr_id },
	// 0x9x, direct instructions with register D
	{ 0x93, M680X_INS_SUBD, direct_hdlr_id },
	{ 0x9D, M680X_INS_JSR, direct_hdlr_id },
	// 0xAx, indexed instructions with Register D
	{ 0xA3, M680X_INS_SUBD, m6800_indexed_hdlr_id },
	// 0xBx, extended instructions with register D
	{ 0xB3, M680X_INS_SUBD, extended_hdlr_id },
	// 0xCx, immediate instructions with register D
	{ 0xC3, M680X_INS_ADDD, immediate16_hdlr_id },
	{ 0xCC, M680X_INS_LDD, immediate16_hdlr_id },
	// 0xDx direct instructions with register D
	{ 0xD3, M680X_INS_ADDD, direct_hdlr_id },
	{ 0xDC, M680X_INS_LDD, direct_hdlr_id },
	{ 0xDD, M680X_INS_STD, direct_hdlr_id },
	// 0xEx, indexed instruction with register D
	{ 0xE3, M680X_INS_ADDD, m6800_indexed_hdlr_id },
	{ 0xEC, M680X_INS_LDD, m6800_indexed_hdlr_id },
	{ 0xED, M680X_INS_STD, m6800_indexed_hdlr_id },
	// 0xFx, extended instructions with register D
	{ 0xF3, M680X_INS_ADDD, extended_hdlr_id },
	{ 0xFC, M680X_INS_LDD, extended_hdlr_id },
	{ 0xFD, M680X_INS_STD, extended_hdlr_id },
};

// Additional instructions only supported on HD6301/3
static const inst_pageX g_hd6301_inst_overlay_table[] = {
	{ 0x1B, M680X_INS_XGDX, inherent_hdlr_id },
	{ 0x61, M680X_INS_AIM, hd6301_imm_indexed_hdlr_id },
	{ 0x62, M680X_INS_OIM, hd6301_imm_indexed_hdlr_id },
	{ 0x65, M680X_INS_EIM, hd6301_imm_indexed_hdlr_id },
	{ 0x6B, M680X_INS_TIM, hd6301_imm_indexed_hdlr_id },
	{ 0x71, M680X_INS_AIM, hd630x_imm_direct_hdlr_id },
	{ 0x72, M680X_INS_OIM, hd630x_imm_direct_hdlr_id },
	{ 0x75, M680X_INS_EIM, hd630x_imm_direct_hdlr_id },
	{ 0x7B, M680X_INS_TIM, hd630x_imm_direct_hdlr_id },
};

// M6809/HD6309 PAGE1 instructions
static const inst_page1 g_m6809_inst_page1_table[256] = {
	// 0x0x, direct instructions
	{ M680X_INS_NEG, direct_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_COM, direct_hdlr_id },
	{ M680X_INS_LSR, direct_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ROR, direct_hdlr_id },
	{ M680X_INS_ASR, direct_hdlr_id },
	{ M680X_INS_LSL, direct_hdlr_id },
	{ M680X_INS_ROL, direct_hdlr_id },
	{ M680X_INS_DEC, direct_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_INC, direct_hdlr_id },
	{ M680X_INS_TST, direct_hdlr_id },
	{ M680X_INS_JMP, direct_hdlr_id },
	{ M680X_INS_CLR, direct_hdlr_id },
	// 0x1x, misc instructions
	{ M680X_INS_ILLGL, illegal_hdlr_id }, // PAGE2
	{ M680X_INS_ILLGL, illegal_hdlr_id }, // PAGE3
	{ M680X_INS_NOP, inherent_hdlr_id },
	{ M680X_INS_SYNC, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_LBRA, lbcc_hdlr_id },
	{ M680X_INS_LBSR, lbcc_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_DAA, inherent_hdlr_id },
	{ M680X_INS_ORCC, immediate8_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ANDCC, immediate8_hdlr_id },
	{ M680X_INS_SEX, inherent_hdlr_id },
	{ M680X_INS_EXG, reg_reg_hdlr_id },
	{ M680X_INS_TFR, reg_reg_hdlr_id },
	// 0x2x, relative branch instructions
	{ M680X_INS_BRA, bcc_hdlr_id },
	{ M680X_INS_BRN, bcc_hdlr_id },
	{ M680X_INS_BHI, bcc_hdlr_id },
	{ M680X_INS_BLS, bcc_hdlr_id },
	{ M680X_INS_BCC, bcc_hdlr_id },
	{ M680X_INS_BCS, bcc_hdlr_id },
	{ M680X_INS_BNE, bcc_hdlr_id },
	{ M680X_INS_BEQ, bcc_hdlr_id },
	{ M680X_INS_BVC, bcc_hdlr_id },
	{ M680X_INS_BVS, bcc_hdlr_id },
	{ M680X_INS_BPL, bcc_hdlr_id },
	{ M680X_INS_BMI, bcc_hdlr_id },
	{ M680X_INS_BGE, bcc_hdlr_id },
	{ M680X_INS_BLT, bcc_hdlr_id },
	{ M680X_INS_BGT, bcc_hdlr_id },
	{ M680X_INS_BLE, bcc_hdlr_id },
	// 0x3x, misc instructions
	{ M680X_INS_LEAX, m6809_indexed_hdlr_id },
	{ M680X_INS_LEAY, m6809_indexed_hdlr_id },
	{ M680X_INS_LEAS, m6809_indexed_hdlr_id },
	{ M680X_INS_LEAU, m6809_indexed_hdlr_id },
	{ M680X_INS_PSHS, reg_bits_hdlr_id },
	{ M680X_INS_PULS, reg_bits_hdlr_id },
	{ M680X_INS_PSHU, reg_bits_hdlr_id },
	{ M680X_INS_PULU, reg_bits_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_RTS, inherent_hdlr_id },
	{ M680X_INS_ABX, inherent_hdlr_id },
	{ M680X_INS_RTI, inherent_hdlr_id },
	{ M680X_INS_CWAI, immediate8_hdlr_id },
	{ M680X_INS_MUL, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_SWI, inherent_hdlr_id },
	// 0x4x, Register A instructions
	{ M680X_INS_NEGA, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_COMA, inherent_hdlr_id },
	{ M680X_INS_LSRA, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_RORA, inherent_hdlr_id },
	{ M680X_INS_ASRA, inherent_hdlr_id },
	{ M680X_INS_LSLA, inherent_hdlr_id },
	{ M680X_INS_ROLA, inherent_hdlr_id },
	{ M680X_INS_DECA, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_INCA, inherent_hdlr_id },
	{ M680X_INS_TSTA, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_CLRA, inherent_hdlr_id },
	// 0x5x, Register B instructions
	{ M680X_INS_NEGB, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_COMB, inherent_hdlr_id },
	{ M680X_INS_LSRB, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_RORB, inherent_hdlr_id },
	{ M680X_INS_ASRB, inherent_hdlr_id },
	{ M680X_INS_LSLB, inherent_hdlr_id },
	{ M680X_INS_ROLB, inherent_hdlr_id },
	{ M680X_INS_DECB, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_INCB, inherent_hdlr_id },
	{ M680X_INS_TSTB, inherent_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_CLRB, inherent_hdlr_id },
	// 0x6x, indexed instructions
	{ M680X_INS_NEG, m6809_indexed_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_COM, m6809_indexed_hdlr_id },
	{ M680X_INS_LSR, m6809_indexed_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ROR, m6809_indexed_hdlr_id },
	{ M680X_INS_ASR, m6809_indexed_hdlr_id },
	{ M680X_INS_LSL, m6809_indexed_hdlr_id },
	{ M680X_INS_ROL, m6809_indexed_hdlr_id },
	{ M680X_INS_DEC, m6809_indexed_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_INC, m6809_indexed_hdlr_id },
	{ M680X_INS_TST, m6809_indexed_hdlr_id },
	{ M680X_INS_JMP, m6809_indexed_hdlr_id },
	{ M680X_INS_CLR, m6809_indexed_hdlr_id },
	// 0x7x, extended instructions
	{ M680X_INS_NEG, extended_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_COM, extended_hdlr_id },
	{ M680X_INS_LSR, extended_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_ROR, extended_hdlr_id },
	{ M680X_INS_ASR, extended_hdlr_id },
	{ M680X_INS_LSL, extended_hdlr_id },
	{ M680X_INS_ROL, extended_hdlr_id },
	{ M680X_INS_DEC, extended_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_INC, extended_hdlr_id },
	{ M680X_INS_TST, extended_hdlr_id },
	{ M680X_INS_JMP, extended_hdlr_id },
	{ M680X_INS_CLR, extended_hdlr_id },
	// 0x8x, immediate instructions with Register A,D,X
	{ M680X_INS_SUBA, immediate8_hdlr_id },
	{ M680X_INS_CMPA, immediate8_hdlr_id },
	{ M680X_INS_SBCA, immediate8_hdlr_id },
	{ M680X_INS_SUBD, immediate16_hdlr_id },
	{ M680X_INS_ANDA, immediate8_hdlr_id },
	{ M680X_INS_BITA, immediate8_hdlr_id },
	{ M680X_INS_LDA, immediate8_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_EORA, immediate8_hdlr_id },
	{ M680X_INS_ADCA, immediate8_hdlr_id },
	{ M680X_INS_ORA, immediate8_hdlr_id },
	{ M680X_INS_ADDA, immediate8_hdlr_id },
	{ M680X_INS_CMPX, immediate16_hdlr_id },
	{ M680X_INS_BSR, bcc_hdlr_id },
	{ M680X_INS_LDX, immediate16_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	// 0x9x, direct instructions with register A,D,X
	{ M680X_INS_SUBA, direct_hdlr_id },
	{ M680X_INS_CMPA, direct_hdlr_id },
	{ M680X_INS_SBCA, direct_hdlr_id },
	{ M680X_INS_SUBD, direct_hdlr_id },
	{ M680X_INS_ANDA, direct_hdlr_id },
	{ M680X_INS_BITA, direct_hdlr_id },
	{ M680X_INS_LDA, direct_hdlr_id },
	{ M680X_INS_STA, direct_hdlr_id },
	{ M680X_INS_EORA, direct_hdlr_id },
	{ M680X_INS_ADCA, direct_hdlr_id },
	{ M680X_INS_ORA, direct_hdlr_id },
	{ M680X_INS_ADDA, direct_hdlr_id },
	{ M680X_INS_CMPX, direct_hdlr_id },
	{ M680X_INS_JSR, direct_hdlr_id },
	{ M680X_INS_LDX, direct_hdlr_id },
	{ M680X_INS_STX, direct_hdlr_id },
	// 0xAx, indexed instructions with Register A,D,X
	{ M680X_INS_SUBA, m6809_indexed_hdlr_id },
	{ M680X_INS_CMPA, m6809_indexed_hdlr_id },
	{ M680X_INS_SBCA, m6809_indexed_hdlr_id },
	{ M680X_INS_SUBD, m6809_indexed_hdlr_id },
	{ M680X_INS_ANDA, m6809_indexed_hdlr_id },
	{ M680X_INS_BITA, m6809_indexed_hdlr_id },
	{ M680X_INS_LDA, m6809_indexed_hdlr_id },
	{ M680X_INS_STA, m6809_indexed_hdlr_id },
	{ M680X_INS_EORA, m6809_indexed_hdlr_id },
	{ M680X_INS_ADCA, m6809_indexed_hdlr_id },
	{ M680X_INS_ORA, m6809_indexed_hdlr_id },
	{ M680X_INS_ADDA, m6809_indexed_hdlr_id },
	{ M680X_INS_CMPX, m6809_indexed_hdlr_id },
	{ M680X_INS_JSR, m6809_indexed_hdlr_id },
	{ M680X_INS_LDX, m6809_indexed_hdlr_id },
	{ M680X_INS_STX, m6809_indexed_hdlr_id },
	// 0xBx, extended instructions with register A,D,X
	{ M680X_INS_SUBA, extended_hdlr_id },
	{ M680X_INS_CMPA, extended_hdlr_id },
	{ M680X_INS_SBCA, extended_hdlr_id },
	{ M680X_INS_SUBD, extended_hdlr_id },
	{ M680X_INS_ANDA, extended_hdlr_id },
	{ M680X_INS_BITA, extended_hdlr_id },
	{ M680X_INS_LDA, extended_hdlr_id },
	{ M680X_INS_STA, extended_hdlr_id },
	{ M680X_INS_EORA, extended_hdlr_id },
	{ M680X_INS_ADCA, extended_hdlr_id },
	{ M680X_INS_ORA, extended_hdlr_id },
	{ M680X_INS_ADDA, extended_hdlr_id },
	{ M680X_INS_CMPX, extended_hdlr_id },
	{ M680X_INS_JSR, extended_hdlr_id },
	{ M680X_INS_LDX, extended_hdlr_id },
	{ M680X_INS_STX, extended_hdlr_id },
	// 0xCx, immediate instructions with register B,D,U
	{ M680X_INS_SUBB, immediate8_hdlr_id },
	{ M680X_INS_CMPB, immediate8_hdlr_id },
	{ M680X_INS_SBCB, immediate8_hdlr_id },
	{ M680X_INS_ADDD, immediate16_hdlr_id },
	{ M680X_INS_ANDB, immediate8_hdlr_id },
	{ M680X_INS_BITB, immediate8_hdlr_id },
	{ M680X_INS_LDB, immediate8_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_EORB, immediate8_hdlr_id },
	{ M680X_INS_ADCB, immediate8_hdlr_id },
	{ M680X_INS_ORB, immediate8_hdlr_id },
	{ M680X_INS_ADDB, immediate8_hdlr_id },
	{ M680X_INS_LDD, immediate16_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	{ M680X_INS_LDU, immediate16_hdlr_id },
	{ M680X_INS_ILLGL, illegal_hdlr_id },
	// 0xDx direct instructions with register B,D,U
	{ M680X_INS_SUBB, direct_hdlr_id },
	{ M680X_INS_CMPB, direct_hdlr_id },
	{ M680X_INS_SBCB, direct_hdlr_id },
	{ M680X_INS_ADDD, direct_hdlr_id },
	{ M680X_INS_ANDB, direct_hdlr_id },
	{ M680X_INS_BITB, direct_hdlr_id },
	{ M680X_INS_LDB, direct_hdlr_id },
	{ M680X_INS_STB, direct_hdlr_id },
	{ M680X_INS_EORB, direct_hdlr_id },
	{ M680X_INS_ADCB, direct_hdlr_id },
	{ M680X_INS_ORB, direct_hdlr_id },
	{ M680X_INS_ADDB, direct_hdlr_id },
	{ M680X_INS_LDD, direct_hdlr_id },
	{ M680X_INS_STD, direct_hdlr_id },
	{ M680X_INS_LDU, direct_hdlr_id },
	{ M680X_INS_STU, direct_hdlr_id },
	// 0xEx, indexed instruction with register B,D,U
	{ M680X_INS_SUBB, m6809_indexed_hdlr_id },
	{ M680X_INS_CMPB, m6809_indexed_hdlr_id },
	{ M680X_INS_SBCB, m6809_indexed_hdlr_id },
	{ M680X_INS_ADDD, m6809_indexed_hdlr_id },
	{ M680X_INS_ANDB, m6809_indexed_hdlr_id },
	{ M680X_INS_BITB, m6809_indexed_hdlr_id },
	{ M680X_INS_LDB, m6809_indexed_hdlr_id },
	{ M680X_INS_STB, m6809_indexed_hdlr_id },
	{ M680X_INS_EORB, m6809_indexed_hdlr_id },
	{ M680X_INS_ADCB, m6809_indexed_hdlr_id },
	{ M680X_INS_ORB, m6809_indexed_hdlr_id },
	{ M680X_INS_ADDB, m6809_indexed_hdlr_id },
	{ M680X_INS_LDD, m6809_indexed_hdlr_id },
	{ M680X_INS_STD, m6809_indexed_hdlr_id },
	{ M680X_INS_LDU, m6809_indexed_hdlr_id },
	{ M680X_INS_STU, m6809_indexed_hdlr_id },
	// 0xFx, extended instructions with register B,D,U
	{ M680X_INS_SUBB, extended_hdlr_id },
	{ M680X_INS_CMPB, extended_hdlr_id },
	{ M680X_INS_SBCB, extended_hdlr_id },
	{ M680X_INS_ADDD, extended_hdlr_id },
	{ M680X_INS_ANDB, extended_hdlr_id },
	{ M680X_INS_BITB, extended_hdlr_id },
	{ M680X_INS_LDB, extended_hdlr_id },
	{ M680X_INS_STB, extended_hdlr_id },
	{ M680X_INS_EORB, extended_hdlr_id },
	{ M680X_INS_ADCB, extended_hdlr_id },
	{ M680X_INS_ORB, extended_hdlr_id },
	{ M680X_INS_ADDB, extended_hdlr_id },
	{ M680X_INS_LDD, extended_hdlr_id },
	{ M680X_INS_STD, extended_hdlr_id },
	{ M680X_INS_LDU, extended_hdlr_id },
	{ M680X_INS_STU, extended_hdlr_id },
};

// The following array has to be sorted by increasing
// opcodes. Otherwise the binary_search will fail.
//
// M6809 PAGE2 instructions (with prefix 0x10)
static const inst_pageX g_m6809_inst_page2_table[] = {
	// 0x2x, relative long branch instructions
	{ 0x21, M680X_INS_LBRN, lbcc_hdlr_id },
	{ 0x22, M680X_INS_LBHI, lbcc_hdlr_id },
	{ 0x23, M680X_INS_LBLS, lbcc_hdlr_id },
	{ 0x24, M680X_INS_LBCC, lbcc_hdlr_id },
	{ 0x25, M680X_INS_LBCS, lbcc_hdlr_id },
	{ 0x26, M680X_INS_LBNE, lbcc_hdlr_id },
	{ 0x27, M680X_INS_LBEQ, lbcc_hdlr_id },
	{ 0x28, M680X_INS_LBVC, lbcc_hdlr_id },
	{ 0x29, M680X_INS_LBVS, lbcc_hdlr_id },
	{ 0x2a, M680X_INS_LBPL, lbcc_hdlr_id },
	{ 0x2b, M680X_INS_LBMI, lbcc_hdlr_id },
	{ 0x2c, M680X_INS_LBGE, lbcc_hdlr_id },
	{ 0x2d, M680X_INS_LBLT, lbcc_hdlr_id },
	{ 0x2e, M680X_INS_LBGT, lbcc_hdlr_id },
	{ 0x2f, M680X_INS_LBLE, lbcc_hdlr_id },
	// 0x3x
	{ 0x3f, M680X_INS_SWI2, inherent_hdlr_id },
	// 0x8x, immediate instructions with register D,Y
	{ 0x83, M680X_INS_CMPD, immediate16_hdlr_id },
	{ 0x8c, M680X_INS_CMPY, immediate16_hdlr_id },
	{ 0x8e, M680X_INS_LDY, immediate16_hdlr_id },
	// 0x9x, direct instructions with register D,Y
	{ 0x93, M680X_INS_CMPD, direct_hdlr_id },
	{ 0x9c, M680X_INS_CMPY, direct_hdlr_id },
	{ 0x9e, M680X_INS_LDY, direct_hdlr_id },
	{ 0x9f, M680X_INS_STY, direct_hdlr_id },
	// 0xAx, indexed instructions with register D,Y
	{ 0xa3, M680X_INS_CMPD, m6809_indexed_hdlr_id },
	{ 0xac, M680X_INS_CMPY, m6809_indexed_hdlr_id },
	{ 0xae, M680X_INS_LDY, m6809_indexed_hdlr_id },
	{ 0xaf, M680X_INS_STY, m6809_indexed_hdlr_id },
	// 0xBx, extended instructions with register D,Y
	{ 0xb3, M680X_INS_CMPD, extended_hdlr_id },
	{ 0xbc, M680X_INS_CMPY, extended_hdlr_id },
	{ 0xbe, M680X_INS_LDY, extended_hdlr_id },
	{ 0xbf, M680X_INS_STY, extended_hdlr_id },
	// 0xCx, immediate instructions with register S
	{ 0xce, M680X_INS_LDS, immediate16_hdlr_id },
	// 0xDx, direct instructions with register S
	{ 0xde, M680X_INS_LDS, direct_hdlr_id },
	{ 0xdf, M680X_INS_STS, direct_hdlr_id },
	// 0xEx, indexed instructions with register S
	{ 0xee, M680X_INS_LDS, m6809_indexed_hdlr_id },
	{ 0xef, M680X_INS_STS, m6809_indexed_hdlr_id },
	// 0xFx, extended instructions with register S
	{ 0xfe, M680X_INS_LDS, extended_hdlr_id },
	{ 0xff, M680X_INS_STS, extended_hdlr_id },
};

// The following array has to be sorted by increasing
// opcodes. Otherwise the binary_search will fail.
//
// M6809 PAGE3 instructions (with prefix 0x11)
static const inst_pageX g_m6809_inst_page3_table[] = {
	{ 0x3f, M680X_INS_SWI3, inherent_hdlr_id },
	// 0x8x, immediate instructions with register U,S
	{ 0x83, M680X_INS_CMPU, immediate16_hdlr_id },
	{ 0x8c, M680X_INS_CMPS, immediate16_hdlr_id },
	// 0x9x, direct instructions with register U,S
	{ 0x93, M680X_INS_CMPU, direct_hdlr_id },
	{ 0x9c, M680X_INS_CMPS, direct_hdlr_id },
	// 0xAx, indexed instructions with register U,S
	{ 0xa3, M680X_INS_CMPU, m6809_indexed_hdlr_id },
	{ 0xac, M680X_INS_CMPS, m6809_indexed_hdlr_id },
	// 0xBx, extended instructions with register U,S
	{ 0xb3, M680X_INS_CMPU, extended_hdlr_id },
	{ 0xbc, M680X_INS_CMPS, extended_hdlr_id },
};

// The following array has to be sorted by increasing
// opcodes. Otherwise the binary_search will fail.
//
// Additional instructions only supported on HD6309 PAGE1
static const inst_pageX g_hd6309_inst_overlay_table[] = {
	{ 0x01, M680X_INS_OIM, hd630x_imm_direct_hdlr_id },
	{ 0x02, M680X_INS_AIM, hd630x_imm_direct_hdlr_id },
	{ 0x05, M680X_INS_EIM, hd630x_imm_direct_hdlr_id },
	{ 0x0B, M680X_INS_TIM, hd630x_imm_direct_hdlr_id },
	{ 0x14, M680X_INS_SEXW, inherent_hdlr_id },
	{ 0x61, M680X_INS_OIM, hd6309_imm_indexed_hdlr_id },
	{ 0x62, M680X_INS_AIM, hd6309_imm_indexed_hdlr_id },
	{ 0x65, M680X_INS_EIM, hd6309_imm_indexed_hdlr_id },
	{ 0x6B, M680X_INS_TIM, hd6309_imm_indexed_hdlr_id },
	{ 0x71, M680X_INS_OIM, hd630x_imm_extended_hdlr_id },
	{ 0x72, M680X_INS_AIM, hd630x_imm_extended_hdlr_id },
	{ 0x75, M680X_INS_EIM, hd630x_imm_extended_hdlr_id },
	{ 0x7B, M680X_INS_TIM, hd630x_imm_extended_hdlr_id },
	{ 0xCD, M680X_INS_LDQ, immediate32_hdlr_id },
};

// The following array has to be sorted by increasing
// opcodes. Otherwise the binary_search will fail.
//
// HD6309 PAGE2 instructions (with prefix 0x10)
static const inst_pageX g_hd6309_inst_page2_table[] = {
	// 0x2x, relative long branch instructions
	{ 0x21, M680X_INS_LBRN, lbcc_hdlr_id },
	{ 0x22, M680X_INS_LBHI, lbcc_hdlr_id },
	{ 0x23, M680X_INS_LBLS, lbcc_hdlr_id },
	{ 0x24, M680X_INS_LBCC, lbcc_hdlr_id },
	{ 0x25, M680X_INS_LBCS, lbcc_hdlr_id },
	{ 0x26, M680X_INS_LBNE, lbcc_hdlr_id },
	{ 0x27, M680X_INS_LBEQ, lbcc_hdlr_id },
	{ 0x28, M680X_INS_LBVC, lbcc_hdlr_id },
	{ 0x29, M680X_INS_LBVS, lbcc_hdlr_id },
	{ 0x2a, M680X_INS_LBPL, lbcc_hdlr_id },
	{ 0x2b, M680X_INS_LBMI, lbcc_hdlr_id },
	{ 0x2c, M680X_INS_LBGE, lbcc_hdlr_id },
	{ 0x2d, M680X_INS_LBLT, lbcc_hdlr_id },
	{ 0x2e, M680X_INS_LBGT, lbcc_hdlr_id },
	{ 0x2f, M680X_INS_LBLE, lbcc_hdlr_id },
	// 0x3x
	{ 0x30, M680X_INS_ADDR, reg_reg_hdlr_id },
	{ 0x31, M680X_INS_ADCR, reg_reg_hdlr_id },
	{ 0x32, M680X_INS_SUBR, reg_reg_hdlr_id },
	{ 0x33, M680X_INS_SBCR, reg_reg_hdlr_id },
	{ 0x34, M680X_INS_ANDR, reg_reg_hdlr_id },
	{ 0x35, M680X_INS_ORR, reg_reg_hdlr_id },
	{ 0x36, M680X_INS_EORR, reg_reg_hdlr_id },
	{ 0x37, M680X_INS_CMPR, reg_reg_hdlr_id },
	{ 0x38, M680X_INS_PSHSW, inherent_hdlr_id },
	{ 0x39, M680X_INS_PULSW, inherent_hdlr_id },
	{ 0x3a, M680X_INS_PSHUW, inherent_hdlr_id },
	{ 0x3b, M680X_INS_PULUW, inherent_hdlr_id },
	{ 0x3f, M680X_INS_SWI2, inherent_hdlr_id },
	// 0x4x, Register D instructions
	{ 0x40, M680X_INS_NEGD, inherent_hdlr_id },
	{ 0x43, M680X_INS_COMD, inherent_hdlr_id },
	{ 0x44, M680X_INS_LSRD, inherent_hdlr_id },
	{ 0x46, M680X_INS_RORD, inherent_hdlr_id },
	{ 0x47, M680X_INS_ASRD, inherent_hdlr_id },
	{ 0x48, M680X_INS_LSLD, inherent_hdlr_id },
	{ 0x49, M680X_INS_ROLD, inherent_hdlr_id },
	{ 0x4a, M680X_INS_DECD, inherent_hdlr_id },
	{ 0x4c, M680X_INS_INCD, inherent_hdlr_id },
	{ 0x4d, M680X_INS_TSTD, inherent_hdlr_id },
	{ 0x4f, M680X_INS_CLRD, inherent_hdlr_id },
	// 0x5x, Register W instructions
	{ 0x53, M680X_INS_COMW, inherent_hdlr_id },
	{ 0x54, M680X_INS_LSRW, inherent_hdlr_id },
	{ 0x56, M680X_INS_RORW, inherent_hdlr_id },
	{ 0x59, M680X_INS_ROLW, inherent_hdlr_id },
	{ 0x5a, M680X_INS_DECW, inherent_hdlr_id },
	{ 0x5c, M680X_INS_INCW, inherent_hdlr_id },
	{ 0x5d, M680X_INS_TSTW, inherent_hdlr_id },
	{ 0x5f, M680X_INS_CLRW, inherent_hdlr_id },
	// 0x8x, immediate instructionY with register D,W,Y
	{ 0x80, M680X_INS_SUBW, immediate16_hdlr_id },
	{ 0x81, M680X_INS_CMPW, immediate16_hdlr_id },
	{ 0x82, M680X_INS_SBCD, immediate16_hdlr_id },
	{ 0x83, M680X_INS_CMPD, immediate16_hdlr_id },
	{ 0x84, M680X_INS_ANDD, immediate16_hdlr_id },
	{ 0x85, M680X_INS_BITD, immediate16_hdlr_id },
	{ 0x86, M680X_INS_LDW, immediate16_hdlr_id },
	{ 0x88, M680X_INS_EORD, immediate16_hdlr_id },
	{ 0x89, M680X_INS_ADCD, immediate16_hdlr_id },
	{ 0x8a, M680X_INS_ORD, immediate16_hdlr_id },
	{ 0x8b, M680X_INS_ADDW, immediate16_hdlr_id },
	{ 0x8c, M680X_INS_CMPY, immediate16_hdlr_id },
	{ 0x8e, M680X_INS_LDY, immediate16_hdlr_id },
	// 0x9x, direct instructions with register D,W,Y
	{ 0x90, M680X_INS_SUBW, direct_hdlr_id },
	{ 0x91, M680X_INS_CMPW, direct_hdlr_id },
	{ 0x92, M680X_INS_SBCD, direct_hdlr_id },
	{ 0x93, M680X_INS_CMPD, direct_hdlr_id },
	{ 0x94, M680X_INS_ANDD, direct_hdlr_id },
	{ 0x95, M680X_INS_BITD, direct_hdlr_id },
	{ 0x96, M680X_INS_LDW, direct_hdlr_id },
	{ 0x97, M680X_INS_STW, direct_hdlr_id },
	{ 0x98, M680X_INS_EORD, direct_hdlr_id },
	{ 0x99, M680X_INS_ADCD, direct_hdlr_id },
	{ 0x9a, M680X_INS_ORD, direct_hdlr_id },
	{ 0x9b, M680X_INS_ADDW, direct_hdlr_id },
	{ 0x9c, M680X_INS_CMPY, direct_hdlr_id },
	{ 0x9e, M680X_INS_LDY, direct_hdlr_id },
	{ 0x9f, M680X_INS_STY, direct_hdlr_id },
	// 0xAx, indexed instructions with register D,W,Y
	{ 0xa0, M680X_INS_SUBW, m6809_indexed_hdlr_id },
	{ 0xa1, M680X_INS_CMPW, m6809_indexed_hdlr_id },
	{ 0xa2, M680X_INS_SBCD, m6809_indexed_hdlr_id },
	{ 0xa3, M680X_INS_CMPD, m6809_indexed_hdlr_id },
	{ 0xa4, M680X_INS_ANDD, m6809_indexed_hdlr_id },
	{ 0xa5, M680X_INS_BITD, m6809_indexed_hdlr_id },
	{ 0xa6, M680X_INS_LDW, m6809_indexed_hdlr_id },
	{ 0xa7, M680X_INS_STW, m6809_indexed_hdlr_id },
	{ 0xa8, M680X_INS_EORD, m6809_indexed_hdlr_id },
	{ 0xa9, M680X_INS_ADCD, m6809_indexed_hdlr_id },
	{ 0xaa, M680X_INS_ORD, m6809_indexed_hdlr_id },
	{ 0xab, M680X_INS_ADDW, m6809_indexed_hdlr_id },
	{ 0xac, M680X_INS_CMPY, m6809_indexed_hdlr_id },
	{ 0xae, M680X_INS_LDY, m6809_indexed_hdlr_id },
	{ 0xaf, M680X_INS_STY, m6809_indexed_hdlr_id },
	// 0xBx, extended instructions with register D,W,Y
	{ 0xb0, M680X_INS_SUBW, extended_hdlr_id },
	{ 0xb1, M680X_INS_CMPW, extended_hdlr_id },
	{ 0xb2, M680X_INS_SBCD, extended_hdlr_id },
	{ 0xb3, M680X_INS_CMPD, extended_hdlr_id },
	{ 0xb4, M680X_INS_ANDD, extended_hdlr_id },
	{ 0xb5, M680X_INS_BITD, extended_hdlr_id },
	{ 0xb6, M680X_INS_LDW, extended_hdlr_id },
	{ 0xb7, M680X_INS_STW, extended_hdlr_id },
	{ 0xb8, M680X_INS_EORD, extended_hdlr_id },
	{ 0xb9, M680X_INS_ADCD, extended_hdlr_id },
	{ 0xba, M680X_INS_ORD, extended_hdlr_id },
	{ 0xbb, M680X_INS_ADDW, extended_hdlr_id },
	{ 0xbc, M680X_INS_CMPY, extended_hdlr_id },
	{ 0xbe, M680X_INS_LDY, extended_hdlr_id },
	{ 0xbf, M680X_INS_STY, extended_hdlr_id },
	// 0xCx, immediate instructions with register S
	{ 0xce, M680X_INS_LDS, immediate16_hdlr_id },
	// 0xDx, direct instructions with register S,Q
	{ 0xdc, M680X_INS_LDQ, direct_hdlr_id },
	{ 0xdd, M680X_INS_STQ, direct_hdlr_id },
	{ 0xde, M680X_INS_LDS, direct_hdlr_id },
	{ 0xdf, M680X_INS_STS, direct_hdlr_id },
	// 0xEx, indexed instructions with register S,Q
	{ 0xec, M680X_INS_LDQ, m6809_indexed_hdlr_id },
	{ 0xed, M680X_INS_STQ, m6809_indexed_hdlr_id },
	{ 0xee, M680X_INS_LDS, m6809_indexed_hdlr_id },
	{ 0xef, M680X_INS_STS, m6809_indexed_hdlr_id },
	// 0xFx, extended instructions with register S,Q
	{ 0xfc, M680X_INS_LDQ, extended_hdlr_id },
	{ 0xfd, M680X_INS_STQ, extended_hdlr_id },
	{ 0xfe, M680X_INS_LDS, extended_hdlr_id },
	{ 0xff, M680X_INS_STS, extended_hdlr_id },
};

// The following array has to be sorted by increasing
// opcodes. Otherwise the binary_search will fail.
//
// HD6309 PAGE3 instructions (with prefix 0x11)
static const inst_pageX g_hd6309_inst_page3_table[] = {
	{ 0x30, M680X_INS_BAND, hd6309_bit_move_hdlr_id },
	{ 0x31, M680X_INS_BIAND, hd6309_bit_move_hdlr_id },
	{ 0x32, M680X_INS_BOR, hd6309_bit_move_hdlr_id },
	{ 0x33, M680X_INS_BIOR, hd6309_bit_move_hdlr_id },
	{ 0x34, M680X_INS_BEOR, hd6309_bit_move_hdlr_id },
	{ 0x35, M680X_INS_BIEOR, hd6309_bit_move_hdlr_id },
	{ 0x36, M680X_INS_LDBT, hd6309_bit_move_hdlr_id },
	{ 0x37, M680X_INS_STBT, hd6309_bit_move_hdlr_id },
	{ 0x38, M680X_INS_TFM, hd6309_tfm_hdlr_id },
	{ 0x39, M680X_INS_TFM, hd6309_tfm_hdlr_id },
	{ 0x3a, M680X_INS_TFM, hd6309_tfm_hdlr_id },
	{ 0x3b, M680X_INS_TFM, hd6309_tfm_hdlr_id },
	{ 0x3c, M680X_INS_BITMD, immediate8_hdlr_id },
	{ 0x3d, M680X_INS_LDMD, immediate8_hdlr_id },
	{ 0x3f, M680X_INS_SWI3, inherent_hdlr_id },
	// 0x4x, Register E instructions
	{ 0x43, M680X_INS_COME, inherent_hdlr_id },
	{ 0x4a, M680X_INS_DECE, inherent_hdlr_id },
	{ 0x4c, M680X_INS_INCE, inherent_hdlr_id },
	{ 0x4d, M680X_INS_TSTE, inherent_hdlr_id },
	{ 0x4f, M680X_INS_CLRE, inherent_hdlr_id },
	// 0x5x, Register F instructions
	{ 0x53, M680X_INS_COMF, inherent_hdlr_id },
	{ 0x5a, M680X_INS_DECF, inherent_hdlr_id },
	{ 0x5c, M680X_INS_INCF, inherent_hdlr_id },
	{ 0x5d, M680X_INS_TSTF, inherent_hdlr_id },
	{ 0x5f, M680X_INS_CLRF, inherent_hdlr_id },
	// 0x8x, immediate instructions with register U,S,E
	{ 0x80, M680X_INS_SUBE, immediate8_hdlr_id },
	{ 0x81, M680X_INS_CMPE, immediate8_hdlr_id },
	{ 0x83, M680X_INS_CMPU, immediate16_hdlr_id },
	{ 0x86, M680X_INS_LDE, immediate8_hdlr_id },
	{ 0x8b, M680X_INS_ADDE, immediate8_hdlr_id },
	{ 0x8c, M680X_INS_CMPS, immediate16_hdlr_id },
	{ 0x8d, M680X_INS_DIVD, immediate8_hdlr_id },
	{ 0x8e, M680X_INS_DIVQ, immediate16_hdlr_id },
	{ 0x8f, M680X_INS_MULD, immediate16_hdlr_id },
	// 0x9x, direct instructions with register U,S,E,Q
	{ 0x90, M680X_INS_SUBE, direct_hdlr_id },
	{ 0x91, M680X_INS_CMPE, direct_hdlr_id },
	{ 0x93, M680X_INS_CMPU, direct_hdlr_id },
	{ 0x96, M680X_INS_LDE, direct_hdlr_id },
	{ 0x97, M680X_INS_STE, direct_hdlr_id },
	{ 0x9b, M680X_INS_ADDE, direct_hdlr_id },
	{ 0x9c, M680X_INS_CMPS, direct_hdlr_id },
	{ 0x9d, M680X_INS_DIVD, direct_hdlr_id },
	{ 0x9e, M680X_INS_DIVQ, direct_hdlr_id },
	{ 0x9f, M680X_INS_MULD, direct_hdlr_id },
	// 0xAx, indexed instructions with register U,S,D,Q
	{ 0xa0, M680X_INS_SUBE, m6809_indexed_hdlr_id },
	{ 0xa1, M680X_INS_CMPE, m6809_indexed_hdlr_id },
	{ 0xa3, M680X_INS_CMPU, m6809_indexed_hdlr_id },
	{ 0xa6, M680X_INS_LDE, m6809_indexed_hdlr_id },
	{ 0xa7, M680X_INS_STE, m6809_indexed_hdlr_id },
	{ 0xab, M680X_INS_ADDE, m6809_indexed_hdlr_id },
	{ 0xac, M680X_INS_CMPS, m6809_indexed_hdlr_id },
	{ 0xad, M680X_INS_DIVD, m6809_indexed_hdlr_id },
	{ 0xae, M680X_INS_DIVQ, m6809_indexed_hdlr_id },
	{ 0xaf, M680X_INS_MULD, m6809_indexed_hdlr_id },
	// 0xBx, extended instructions with register U,S,D,Q
	{ 0xb0, M680X_INS_SUBE, extended_hdlr_id },
	{ 0xb1, M680X_INS_CMPE, extended_hdlr_id },
	{ 0xb3, M680X_INS_CMPU, extended_hdlr_id },
	{ 0xb6, M680X_INS_LDE, extended_hdlr_id },
	{ 0xb7, M680X_INS_STE, extended_hdlr_id },
	{ 0xbb, M680X_INS_ADDE, extended_hdlr_id },
	{ 0xbc, M680X_INS_CMPS, extended_hdlr_id },
	{ 0xbd, M680X_INS_DIVD, extended_hdlr_id },
	{ 0xbe, M680X_INS_DIVQ, extended_hdlr_id },
	{ 0xbf, M680X_INS_MULD, extended_hdlr_id },
	// 0xCx, immediate instructions with register F
	{ 0xc0, M680X_INS_SUBF, immediate8_hdlr_id },
	{ 0xc1, M680X_INS_CMPF, immediate8_hdlr_id },
	{ 0xc6, M680X_INS_LDF, immediate8_hdlr_id },
	{ 0xcb, M680X_INS_ADDF, immediate8_hdlr_id },
	// 0xDx, direct instructions with register F
	{ 0xd0, M680X_INS_SUBF, direct_hdlr_id },
	{ 0xd1, M680X_INS_CMPF, direct_hdlr_id },
	{ 0xd6, M680X_INS_LDF, direct_hdlr_id },
	{ 0xd7, M680X_INS_STF, direct_hdlr_id },
	{ 0xdb, M680X_INS_ADDF, direct_hdlr_id },
	// 0xEx, indexed instructions with register F
	{ 0xe0, M680X_INS_SUBF, m6809_indexed_hdlr_id },
	{ 0xe1, M680X_INS_CMPF, m6809_indexed_hdlr_id },
	{ 0xe6, M680X_INS_LDF, m6809_indexed_hdlr_id },
	{ 0xe7, M680X_INS_STF, m6809_indexed_hdlr_id },
	{ 0xeb, M680X_INS_ADDF, m6809_indexed_hdlr_id },
	// 0xFx, extended instructions with register F
	{ 0xf0, M680X_INS_SUBF, extended_hdlr_id },
	{ 0xf1, M680X_INS_CMPF, extended_hdlr_id },
	{ 0xf6, M680X_INS_LDF, extended_hdlr_id },
	{ 0xf7, M680X_INS_STF, extended_hdlr_id },
	{ 0xfb, M680X_INS_ADDF, extended_hdlr_id },
};

// These temporary defines keep the following table short and handy.
#define NOG M680X_GRP_INVALID
#define NOR M680X_REG_INVALID

static const insn_props g_insn_props[] = {
	{ NOG, uuuu, NOR, NOR, false, false }, // INVLD
	{ NOG, rmmm, M680X_REG_B, M680X_REG_A, true, false }, // ABA
	{ NOG, rmmm, M680X_REG_B, M680X_REG_X, false, false }, // ABX
	{ NOG, mrrr, M680X_REG_A, NOR, true, false }, // ADCA
	{ NOG, mrrr, M680X_REG_B, NOR, true, false }, // ADCB
	{ NOG, mrrr, M680X_REG_D, NOR, true, false }, // ADCD
	{ NOG, rmmm, NOR, NOR, true, false }, // ADCR
	{ NOG, mrrr, M680X_REG_A, NOR, true, false }, // ADDA
	{ NOG, mrrr, M680X_REG_B, NOR, true, false }, // ADDB
	{ NOG, mrrr, M680X_REG_D, NOR, true, false }, // ADDD
	{ NOG, mrrr, M680X_REG_E, NOR, true, false }, // ADDE
	{ NOG, mrrr, M680X_REG_F, NOR, true, false }, // ADDF
	{ NOG, rmmm, NOR, NOR, true, false }, // ADDR
	{ NOG, mrrr, M680X_REG_W, NOR, true, false }, // ADDW
	{ NOG, rmmm, NOR, NOR, true, false }, // AIM
	{ NOG, mrrr, M680X_REG_A, NOR, true, false }, // ANDA
	{ NOG, mrrr, M680X_REG_B, NOR, true, false }, // ANDB
	{ NOG, mrrr, M680X_REG_CC, NOR, true, false }, // ANDCC
	{ NOG, mrrr, M680X_REG_D, NOR, true, false }, // ANDD
	{ NOG, rmmm, NOR, NOR, true, false }, // ANDR
	{ NOG, mrrr, NOR, NOR, true, false }, // ASL
	{ NOG, mrrr, M680X_REG_A, NOR, true, false }, // ASLA
	{ NOG, mrrr, M680X_REG_B, NOR, true, false }, // ASLB
	{ NOG, mrrr, M680X_REG_D, NOR, true, false }, // ASLD
	{ NOG, mrrr, NOR, NOR, true, false }, // ASR
	{ NOG, mrrr, M680X_REG_A, NOR, true, false }, // ASRA
	{ NOG, mrrr, M680X_REG_B, NOR, true, false }, // ASRB
	{ NOG, mrrr, M680X_REG_D, NOR, true, false }, // ASRD
	{ NOG, mrrr, NOR, NOR, false, false }, // BAND
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // BCC
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // BCS
	{ NOG, mrrr, NOR, NOR, false, false }, // BEOR
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // BEQ
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // BGE
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // BGT
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // BHI
	{ NOG, mrrr, NOR, NOR, false, false }, // BIAND
	{ NOG, mrrr, NOR, NOR, false, false }, // BIEOR
	{ NOG, mrrr, NOR, NOR, false, false }, // BIOR
	{ NOG, rrrr, M680X_REG_A, NOR, true, false }, // BITA
	{ NOG, rrrr, M680X_REG_B, NOR, true, false }, // BITB
	{ NOG, rrrr, M680X_REG_D, NOR, true, false }, // BITD
	{ NOG, rrrr, M680X_REG_MD, NOR, true, false }, // BITMD
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // BLE
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // BLS
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // BLT
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // BMI
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // BNE
	{ NOG, mrrr, NOR, NOR, false, false }, // BOR
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // BPL
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // BRA
	{ NOG, uuuu, NOR, NOR, false, false }, // BRN never branches
	{ M680X_GRP_CALL, uuuu, NOR, NOR, false, false }, // BSR
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // BVC
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // BVS
	{ NOG, rrrr, M680X_REG_B, M680X_REG_A, true, false }, // CBA
	{ NOG, uuuu, NOR, NOR, true, false }, // CLC
	{ NOG, uuuu, NOR, NOR, true, false }, // CLI
	{ NOG, wrrr, NOR, NOR, true, false }, // CLR
	{ NOG, wrrr, M680X_REG_A, NOR, true, false }, // CLRA
	{ NOG, wrrr, M680X_REG_B, NOR, true, false }, // CLRB
	{ NOG, wrrr, M680X_REG_D, NOR, true, false }, // CLRD
	{ NOG, wrrr, M680X_REG_E, NOR, true, false }, // CLRE
	{ NOG, wrrr, M680X_REG_F, NOR, true, false }, // CLRF
	{ NOG, wrrr, M680X_REG_W, NOR, true, false }, // CLRW
	{ NOG, uuuu, NOR, NOR, true, false }, // CLV
	{ NOG, rrrr, M680X_REG_A, NOR, true, false }, // CMPA
	{ NOG, rrrr, M680X_REG_B, NOR, true, false }, // CMPB
	{ NOG, rrrr, M680X_REG_D, NOR, true, false }, // CMPD
	{ NOG, rrrr, M680X_REG_E, NOR, true, false }, // CMPE
	{ NOG, rrrr, M680X_REG_F, NOR, true, false }, // CMPF
	{ NOG, rrrr, NOR, NOR, true, false }, // CMPR
	{ NOG, rrrr, M680X_REG_S, NOR, true, false }, // CMPS
	{ NOG, rrrr, M680X_REG_U, NOR, true, false }, // CMPU
	{ NOG, rrrr, M680X_REG_W, NOR, true, false }, // CMPW
	{ NOG, rrrr, M680X_REG_X, NOR, true, false }, // CMPX
	{ NOG, rrrr, M680X_REG_Y, NOR, true, false }, // CMPY
	{ NOG, mrrr, NOR, NOR, true, false }, // COM
	{ NOG, mrrr, M680X_REG_A, NOR, true, false }, // COMA
	{ NOG, mrrr, M680X_REG_B, NOR, true, false }, // COMB
	{ NOG, mrrr, M680X_REG_D, NOR, true, false }, // COMD
	{ NOG, mrrr, M680X_REG_E, NOR, true, false }, // COME
	{ NOG, mrrr, M680X_REG_F, NOR, true, false }, // COMF
	{ NOG, mrrr, M680X_REG_W, NOR, true, false }, // COMW
	{ NOG, rrrr, M680X_REG_X, NOR, true, false }, // CPX
	{ NOG, mrrr, NOR, NOR, true, true }, // CWAI
	{ NOG, mrrr, NOR, NOR, true, true }, // DAA
	{ NOG, mrrr, NOR, NOR, true, false }, // DEC
	{ NOG, mrrr, M680X_REG_A, NOR, true, false }, // DECA
	{ NOG, mrrr, M680X_REG_B, NOR, true, false }, // DECB
	{ NOG, mrrr, M680X_REG_D, NOR, true, false }, // DECD
	{ NOG, mrrr, M680X_REG_E, NOR, true, false }, // DECE
	{ NOG, mrrr, M680X_REG_F, NOR, true, false }, // DECF
	{ NOG, mrrr, M680X_REG_W, NOR, true, false }, // DECW
	{ NOG, mrrr, M680X_REG_S, NOR, false, false }, // DES
	{ NOG, mrrr, M680X_REG_X, NOR, true, false }, // DEX
	{ NOG, mrrr, M680X_REG_D, NOR, true, false }, // DIVD
	{ NOG, mrrr, M680X_REG_Q, NOR, true, false }, // DIVQ
	{ NOG, rmmm, NOR, NOR, true, false }, // EIM
	{ NOG, mrrr, M680X_REG_A, NOR, true, false }, // EORA
	{ NOG, mrrr, M680X_REG_B, NOR, true, false }, // EORB
	{ NOG, mrrr, M680X_REG_D, NOR, true, false }, // EORD
	{ NOG, rmmm, NOR, NOR, true, false }, // EORR
	{ NOG, wwww, NOR, NOR, false, false }, // EXG
	{ NOG, uuuu, NOR, NOR, false, false }, // ILLGL
	{ NOG, mrrr, NOR, NOR, true, false }, // INC
	{ NOG, mrrr, M680X_REG_A, NOR, true, false }, // INCA
	{ NOG, mrrr, M680X_REG_B, NOR, true, false }, // INCB
	{ NOG, mrrr, M680X_REG_D, NOR, true, false }, // INCD
	{ NOG, mrrr, M680X_REG_E, NOR, true, false }, // INCE
	{ NOG, mrrr, M680X_REG_F, NOR, true, false }, // INCF
	{ NOG, mrrr, M680X_REG_W, NOR, true, false }, // INCW
	{ NOG, mrrr, M680X_REG_S, NOR, false, false }, // INS
	{ NOG, mrrr, M680X_REG_X, NOR, true, false }, // INX
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // JMP
	{ M680X_GRP_CALL, uuuu, NOR, NOR, false, false }, // JSR
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // LBCC
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // LBCS
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // LBEQ
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // LBGE
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // LBGT
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // LBHI
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // LBLE
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // LBLS
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // LBLT
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // LBMI
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // LBNE
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // LBPL
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // LBRA
	{ NOG, uuuu, NOR, NOR, false, false }, // LBRN never branches
	{ M680X_GRP_CALL, uuuu, NOR, NOR, false, false }, // LBSR
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // LBVC
	{ M680X_GRP_JUMP, uuuu, NOR, NOR, false, false }, // LBVS
	{ NOG, wrrr, M680X_REG_A, NOR, true, false }, // LDA
	{ NOG, wrrr, M680X_REG_A, NOR, true, false }, // LDAA
	{ NOG, wrrr, M680X_REG_B, NOR, true, false }, // LDAB
	{ NOG, wrrr, M680X_REG_B, NOR, true, false }, // LDB
	{ NOG, mrrr, NOR, NOR, false, false }, // LDBT
	{ NOG, wrrr, M680X_REG_D, NOR, true, false }, // LDD
	{ NOG, wrrr, M680X_REG_E, NOR, true, false }, // LDE
	{ NOG, wrrr, M680X_REG_F, NOR, true, false }, // LDF
	{ NOG, mrrr, M680X_REG_MD, NOR, false, false }, // LDMD
	{ NOG, wrrr, M680X_REG_Q, NOR, true, false }, // LDQ
	{ NOG, wrrr, M680X_REG_S, NOR, true, false }, // LDS
	{ NOG, wrrr, M680X_REG_U, NOR, true, false }, // LDU
	{ NOG, wrrr, M680X_REG_W, NOR, true, false }, // LDW
	{ NOG, wrrr, M680X_REG_X, NOR, true, false }, // LDX
	{ NOG, wrrr, M680X_REG_Y, NOR, true, false }, // LDY
	{ NOG, wrrr, M680X_REG_S, NOR, false, false }, // LEAS
	{ NOG, wrrr, M680X_REG_U, NOR, false, false }, // LEAU
	{ NOG, wrrr, M680X_REG_X, NOR, false, false }, // LEAX
	{ NOG, wrrr, M680X_REG_Y, NOR, false, false }, // LEAY
	{ NOG, mrrr, NOR, NOR, true, false }, // LSL
	{ NOG, mrrr, M680X_REG_A, NOR, true, false }, // LSLA
	{ NOG, mrrr, M680X_REG_B, NOR, true, false }, // LSLB
	{ NOG, mrrr, M680X_REG_D, NOR, true, false }, // LSLD
	{ NOG, mrrr, NOR, NOR, true, false }, // LSR
	{ NOG, mrrr, M680X_REG_A, NOR, true, false }, // LSRA
	{ NOG, mrrr, M680X_REG_B, NOR, true, false }, // LSRB
	{ NOG, mrrr, M680X_REG_D, NOR, true, false }, // LSRD
	{ NOG, mrrr, M680X_REG_W, NOR, true, false }, // LSRW
	{ NOG, mmmm, NOR, NOR, true, true }, // MUL
	{ NOG, mwrr, M680X_REG_D, NOR, true, true }, // MULD
	{ NOG, mrrr, NOR, NOR, true, false }, // NEG
	{ NOG, mrrr, M680X_REG_A, NOR, true, false }, // NEGA
	{ NOG, mrrr, M680X_REG_B, NOR, true, false }, // NEGB
	{ NOG, mrrr, M680X_REG_D, NOR, true, false }, // NEGD
	{ NOG, uuuu, NOR, NOR, false, false }, // NOP
	{ NOG, rmmm, NOR, NOR, true, false }, // OIM
	{ NOG, mrrr, M680X_REG_A, NOR, true, false }, // ORA
	{ NOG, mrrr, M680X_REG_A, NOR, true, false }, // ORAA
	{ NOG, mrrr, M680X_REG_B, NOR, true, false }, // ORAB
	{ NOG, mrrr, M680X_REG_B, NOR, true, false }, // ORB
	{ NOG, mrrr, M680X_REG_CC, NOR, true, false }, // ORCC
	{ NOG, mrrr, M680X_REG_D, NOR, true, false }, // ORD
	{ NOG, rmmm, NOR, NOR, true, false }, // ORR
	{ NOG, rmmm, M680X_REG_A, NOR, false, true }, // PSHA
	{ NOG, rmmm, M680X_REG_B, NOR, false, true }, // PSHB
	{ NOG, mrrr, M680X_REG_S, NOR, false, false }, // PSHS
	{ NOG, mrrr, M680X_REG_S, M680X_REG_W, false, false }, // PSHSW
	{ NOG, mrrr, M680X_REG_U, NOR, false, false }, // PSHU
	{ NOG, mrrr, M680X_REG_U, M680X_REG_W, false, false }, // PSHUW
	{ NOG, rmmm, M680X_REG_X, NOR, false, true }, // PSHX
	{ NOG, wmmm, M680X_REG_A, NOR, false, true }, // PULA
	{ NOG, wmmm, M680X_REG_B, NOR, false, true }, // PULB
	{ NOG, mwww, M680X_REG_S, NOR, false, false }, // PULS
	{ NOG, mwww, M680X_REG_S, M680X_REG_W, false, false }, // PULSW
	{ NOG, mwww, M680X_REG_U, NOR, false, false }, // PULU
	{ NOG, mwww, M680X_REG_U, M680X_REG_W, false, false }, // PULUW
	{ NOG, wmmm, M680X_REG_X, NOR, false, true }, // PULX
	{ NOG, mrrr, NOR, NOR, true, false }, // ROL
	{ NOG, mrrr, M680X_REG_A, NOR, true, false }, // ROLA
	{ NOG, mrrr, M680X_REG_B, NOR, true, false }, // ROLB
	{ NOG, mrrr, M680X_REG_D, NOR, true, false }, // ROLD
	{ NOG, mrrr, M680X_REG_W, NOR, true, false }, // ROLW
	{ NOG, mrrr, NOR, NOR, true, false }, // ROR
	{ NOG, mrrr, M680X_REG_A, NOR, true, false }, // RORA
	{ NOG, mrrr, M680X_REG_B, NOR, true, false }, // RORB
	{ NOG, mrrr, M680X_REG_D, NOR, true, false }, // RORD
	{ NOG, mrrr, M680X_REG_W, NOR, true, false }, // RORW
	{ M680X_GRP_IRET, mwww, NOR, NOR, false, true }, // RTI
	{ M680X_GRP_RET, mwww, NOR, NOR, false, true }, // RTS
	{ NOG, rmmm, M680X_REG_B, M680X_REG_A, true, false }, // SBA
	{ NOG, mrrr, M680X_REG_A, NOR, true, false }, // SBCA
	{ NOG, mrrr, M680X_REG_B, NOR, true, false }, // SBCB
	{ NOG, mrrr, M680X_REG_D, NOR, true, false }, // SBCD
	{ NOG, rmmm, NOR, NOR, true, false }, // SBCR
	{ NOG, uuuu, NOR, NOR, true, false }, // SEC
	{ NOG, uuuu, NOR, NOR, true, false }, // SEI
	{ NOG, uuuu, NOR, NOR, true, false }, // SEV
	{ NOG, wrrr, NOR, NOR, true, true }, // SEX
	{ NOG, rwww, M680X_REG_W, NOR, true, true }, // SEXW
	{ NOG, rwww, M680X_REG_A, NOR, true, false }, // STA
	{ NOG, rwww, M680X_REG_A, NOR, true, false }, // STAA
	{ NOG, rwww, M680X_REG_B, NOR, true, false }, // STAB
	{ NOG, rwww, M680X_REG_B, NOR, true, false }, // STB
	{ NOG, rrrm, NOR, NOR, false, false }, // STBT
	{ NOG, rwww, M680X_REG_D, NOR, true, false }, // STD
	{ NOG, rwww, M680X_REG_E, NOR, true, false }, // STE
	{ NOG, rwww, M680X_REG_F, NOR, true, false }, // STF
	{ NOG, rwww, M680X_REG_Q, NOR, true, false }, // STQ
	{ NOG, rwww, M680X_REG_S, NOR, true, false }, // STS
	{ NOG, rwww, M680X_REG_U, NOR, true, false }, // STU
	{ NOG, rwww, M680X_REG_W, NOR, true, false }, // STW
	{ NOG, rwww, M680X_REG_X, NOR, true, false }, // STX
	{ NOG, rwww, M680X_REG_Y, NOR, true, false }, // STY
	{ NOG, mrrr, M680X_REG_A, NOR, true, false }, // SUBA
	{ NOG, mrrr, M680X_REG_B, NOR, true, false }, // SUBB
	{ NOG, mrrr, M680X_REG_D, NOR, true, false }, // SUBD
	{ NOG, mrrr, M680X_REG_E, NOR, true, false }, // SUBE
	{ NOG, mrrr, M680X_REG_F, NOR, true, false }, // SUBF
	{ NOG, rmmm, NOR, NOR, true, false }, // SUBR
	{ NOG, mrrr, M680X_REG_W, NOR, true, false }, // SUBW
	{ M680X_GRP_INT, mmrr, NOR, NOR, true, true }, // SWI
	{ M680X_GRP_INT, mmrr, NOR, NOR, true, true }, // SWI2
	{ M680X_GRP_INT, mmrr, NOR, NOR, true, true }, // SWI3
	{ NOG, uuuu, NOR, NOR, false, false }, // SYNC
	{ NOG, rwww, M680X_REG_A, M680X_REG_B, true, false }, // TAB
	{ NOG, rwww, M680X_REG_A, M680X_REG_CC, false, false }, // TAP
	{ NOG, rwww, M680X_REG_B, M680X_REG_A, true, false }, // TBA
	{ NOG, rwww, M680X_REG_CC, M680X_REG_A, false, false }, // TPA
	{ NOG, rwww, NOR, NOR, false, false }, // TFM
	{ NOG, rwww, NOR, NOR, false, false }, // TFR
	{ NOG, rrrr, NOR, NOR, true, false }, // TIM
	{ NOG, rrrr, NOR, NOR, true, false }, // TST
	{ NOG, rrrr, M680X_REG_A, NOR, true, false }, // TSTA
	{ NOG, rrrr, M680X_REG_B, NOR, true, false }, // TSTB
	{ NOG, rrrr, M680X_REG_D, NOR, true, false }, // TSTD
	{ NOG, rrrr, M680X_REG_E, NOR, true, false }, // TSTE
	{ NOG, rrrr, M680X_REG_F, NOR, true, false }, // TSTF
	{ NOG, rrrr, M680X_REG_W, NOR, true, false }, // TSTW
	{ NOG, rwww, M680X_REG_S, M680X_REG_X, false, false }, // TSX
	{ NOG, rwww, M680X_REG_X, M680X_REG_S, false, false }, // TXS
	{ NOG, mrrr, NOR, NOR, true, true }, // WAI
	{ NOG, mmmm, M680X_REG_D, M680X_REG_X, false, true }, // XGDX
};
#undef NOR
#undef NOG

//////////////////////////////////////////////////////////////////////////////

// M680X instuctions have 1 up to 5 bytes. A reader is needed to read
// a byte or word from a given memory address. See also X86 reader(...)
static bool read_byte(const m680x_info *info, uint8_t *byte, uint16_t address)
{
	if (address - info->offset >= info->size)
		// out of code buffer range
		return false;

	*byte = info->code[address - info->offset];

	return true;
}

static bool read_byte_sign_extended(const m680x_info *info, int16_t *word,
	uint16_t address)
{
	if (address - info->offset >= info->size)
		// out of code buffer range
		return false;

	*word = (int16_t) info->code[address - info->offset];

	if (*word & 0x80)
		*word |= 0xFF00;

	return true;
}

static bool read_word(const m680x_info *info, uint16_t *word, uint16_t address)
{
	if (address + 1 - info->offset >= info->size)
		// out of code buffer range
		return false;

	*word = (uint16_t)info->code[address - info->offset] << 8;
	*word |= (uint16_t)info->code[address + 1 - info->offset];

	return true;
}

static bool read_sdword(const m680x_info *info, int32_t *sdword,
	uint16_t address)
{
	if (address + 3 - info->offset >= info->size)
		// out of code buffer range
		return false;

	*sdword = (uint32_t)info->code[address - info->offset] << 24;
	*sdword |= (uint32_t)info->code[address + 1 - info->offset] << 16;
	*sdword |= (uint32_t)info->code[address + 2 - info->offset] << 8;
	*sdword |= (uint32_t)info->code[address + 3 - info->offset];

	return true;
}

// For PAGE2 and PAGE3 opcodes when using an an array of inst_page1 most
// entries have M680X_INS_ILLGL. To avoid wasting memory an inst_pageX is
// used which contains the opcode. Using a binary search for the right opcode
// is much faster (= O(log n) ) in comparison to a linear search ( = O(n) ).
static int binary_search(const inst_pageX *const inst_pageX_table,
	int table_size, uint8_t opcode)
{
	int first = 0;
	int last = table_size - 1;
	int middle = (first + last) / 2;

	while (first <= last) {
		if (inst_pageX_table[middle].opcode < opcode) {
			first = middle + 1;
		}
		else if (inst_pageX_table[middle].opcode == opcode) {
			return middle;  /* item found */
		}
		else
			last = middle - 1;

		middle = (first + last) / 2;
	}

	if (first > last)
		return -1;  /* item not found */

	return -2;
}

void M680X_get_insn_id(cs_struct *handle, cs_insn *insn, unsigned int id)
{
	const m680x_info *const info = (const m680x_info *)handle->printer_info;
	const cpu_tables *cpu = &info->cpu;
	uint8_t insn_prefix = (id >> 8) & 0xff;
	bool insn_found = false;
	int index;
	int i;

	for (i = 0; i < ARR_SIZE(cpu->pageX_prefix); ++i) {
		if (cpu->pageX_table_size[i] == 0 ||
			(cpu->inst_pageX_table[i] == NULL))
			break;

		if (cpu->pageX_prefix[i] == insn_prefix) {
			index = binary_search(cpu->inst_pageX_table[i],
					cpu->pageX_table_size[i], id & 0xff);
			insn->id = (index >= 0) ?
				cpu->inst_pageX_table[i][index].insn :
				M680X_INS_ILLGL;
			return;
		}
	}

	if (insn_prefix != 0) {
		insn->id = M680X_INS_ILLGL;
		return;
	}

	// Check if opcode byte is present in an overlay table
	for (i = 0; i < ARR_SIZE(cpu->overlay_table_size); ++i) {
		if (cpu->overlay_table_size[i] == 0 ||
		    (cpu->inst_overlay_table[i] == NULL))
			break;

		if ((index = binary_search(cpu->inst_overlay_table[i],
						cpu->overlay_table_size[i],
						id & 0xff)) >= 0) {
			insn->id = cpu->inst_overlay_table[i][index].insn;
			insn_found = true;
		}
	}

	if (!insn_found)
		insn->id = cpu->inst_page1_table[id].insn;
}

static void add_insn_group(cs_detail *detail, m680x_group_type group)
{
	if (detail != NULL &&
		(group != M680X_GRP_INVALID) && (group != M680X_GRP_ENDING))
		detail->groups[detail->groups_count++] = (uint8_t)group;
}

static bool exists_reg_list(uint16_t *regs, uint8_t count, m680x_reg reg)
{
	uint8_t i;

	for (i = 0; i < count; ++i) {
		if (regs[i] == (uint16_t)reg)
			return true;
	}

	return false;
}

static void add_reg_to_rw_list(MCInst *MI, m680x_reg reg, e_access access)
{
	cs_detail *detail = MI->flat_insn->detail;

	if (detail == NULL || (reg == M680X_REG_INVALID))
		return;

	switch (access) {
	case MODIFY:
		if (!exists_reg_list(detail->regs_read,
				detail->regs_read_count, reg))
			detail->regs_read[detail->regs_read_count++] =
				(uint16_t)reg;

	// intentionally fall through

	case WRITE:
		if (!exists_reg_list(detail->regs_write,
				detail->regs_write_count, reg))
			detail->regs_write[detail->regs_write_count++] =
				(uint16_t)reg;

		break;

	case READ:
		if (!exists_reg_list(detail->regs_read,
				detail->regs_read_count, reg))
			detail->regs_read[detail->regs_read_count++] =
				(uint16_t)reg;

		break;

	case UNCHANGED:
	default:
		break;
	}
}

static void update_am_reg_list(MCInst *MI, cs_m680x_op *op,
				e_access access)
{
	if (MI->flat_insn->detail == NULL)
		return;

	switch (op->type) {
	case M680X_OP_REGISTER:
		add_reg_to_rw_list(MI, op->reg, access);
		break;

	case M680X_OP_INDEXED_00:
		add_reg_to_rw_list(MI, op->idx.base_reg, READ);
		break;

	case M680X_OP_INDEXED_09:
		add_reg_to_rw_list(MI, op->idx.base_reg, READ);

		if (op->idx.offset_reg != M680X_REG_INVALID)
			add_reg_to_rw_list(MI, op->idx.offset_reg, READ);

		if (op->idx.inc_dec != M680X_NO_INC_DEC)
			add_reg_to_rw_list(MI, op->idx.base_reg, WRITE);

		break;

	default:
		break;
	}
}

static const e_access g_access_mode_to_access[4][13] = {
	{
		UNCHANGED, READ, WRITE, READ,  READ, READ,   WRITE, MODIFY,
		MODIFY, MODIFY, MODIFY, MODIFY, WRITE,
	},
	{
		UNCHANGED, READ, WRITE, WRITE, READ, MODIFY, READ,  READ,
		WRITE, MODIFY, WRITE, MODIFY, MODIFY,
	},
	{
		UNCHANGED, READ, WRITE, WRITE, READ, MODIFY, READ,  READ,
		WRITE, MODIFY, READ, READ, MODIFY,
	},
	{
		UNCHANGED, READ, WRITE, WRITE, MODIFY, MODIFY, READ, READ,
		WRITE, MODIFY, READ, READ, MODIFY,
	},
};

static e_access get_access(int operator_index, e_access_mode access_mode)
{
	int idx = (operator_index > 3) ? 3 : operator_index;

	return g_access_mode_to_access[idx][access_mode];
}

static void build_regs_read_write_counts(MCInst *MI, m680x_info *info,
					e_access_mode access_mode)
{
	cs_m680x *m680x = &info->m680x;
	int i;

	if (MI->flat_insn->detail == NULL || (!m680x->op_count))
		return;

	for (i = 0; i < m680x->op_count; ++i) {

		e_access access = get_access(i, access_mode);
		update_am_reg_list(MI, &m680x->operands[i], access);
	}
}

static void add_operators_access(MCInst *MI, m680x_info *info,
				e_access_mode access_mode)
{
	cs_m680x *m680x = &info->m680x;
	int offset = 0;
	int i;

	if (MI->flat_insn->detail == NULL || (!m680x->op_count) ||
		(access_mode == uuuu))
		return;

	for (i = 0; i < m680x->op_count; ++i) {

		// Ugly fix: MULD has a register operand, an immediate operand
		// AND an implicitly changed register W
		if (info->insn == M680X_INS_MULD && (i == 1))
			offset = 1;
		e_access access = get_access(i + offset, access_mode);
		m680x->operands[i].access = access;
	}
}

typedef struct insn_to_changed_regs {
	m680x_insn insn;
	m680x_reg regs[10];
} insn_to_changed_regs;

static void set_changed_regs_read_write_counts(MCInst *MI, m680x_info *info)
{
#define EOL M680X_REG_INVALID
	static const insn_to_changed_regs changed_regs[] = {
		{
			M680X_INS_CWAI, {
				M680X_REG_S, M680X_REG_PC, M680X_REG_U,
				M680X_REG_Y, M680X_REG_X, M680X_REG_DP,
				M680X_REG_D, M680X_REG_CC, EOL
			},
		},
		{ M680X_INS_DAA, { M680X_REG_A, EOL } },
		{ M680X_INS_MUL, { M680X_REG_A, M680X_REG_B, EOL } },
		{ M680X_INS_MULD, { M680X_REG_D, M680X_REG_W, EOL } },
		{ M680X_INS_PSHA, { M680X_REG_A, M680X_REG_S, EOL } },
		{ M680X_INS_PSHB, { M680X_REG_B, M680X_REG_S, EOL } },
		{ M680X_INS_PSHX, { M680X_REG_X, M680X_REG_S, EOL } },
		{ M680X_INS_PULA, { M680X_REG_A, M680X_REG_S, EOL } },
		{ M680X_INS_PULB, { M680X_REG_B, M680X_REG_S, EOL } },
		{ M680X_INS_PULX, { M680X_REG_X, M680X_REG_S, EOL } },
		{
			M680X_INS_RTI, {
				M680X_REG_S, M680X_REG_CC, M680X_REG_B,
				M680X_REG_A, M680X_REG_DP, M680X_REG_X,
				M680X_REG_Y, M680X_REG_U, M680X_REG_PC,
				EOL
			},
		},
		{ M680X_INS_RTS, { M680X_REG_S, M680X_REG_PC, EOL } },
		{ M680X_INS_SEX, { M680X_REG_A, M680X_REG_B, EOL } },
		{ M680X_INS_SEXW, { M680X_REG_W, M680X_REG_D, EOL } },
		{
			M680X_INS_SWI, {
				M680X_REG_S, M680X_REG_PC, M680X_REG_U,
				M680X_REG_Y, M680X_REG_X, M680X_REG_DP,
				M680X_REG_A, M680X_REG_B, M680X_REG_CC,
				EOL
			}
		},
		{
			M680X_INS_SWI2, {
				M680X_REG_S, M680X_REG_PC, M680X_REG_U,
				M680X_REG_Y, M680X_REG_X, M680X_REG_DP,
				M680X_REG_A, M680X_REG_B, M680X_REG_CC,
				EOL
			},
		},
		{
			M680X_INS_SWI3, {
				M680X_REG_S, M680X_REG_PC, M680X_REG_U,
				M680X_REG_Y, M680X_REG_X, M680X_REG_DP,
				M680X_REG_A, M680X_REG_B, M680X_REG_CC,
				EOL
			},
		},
		{
			M680X_INS_WAI, {
				M680X_REG_S, M680X_REG_PC, M680X_REG_X,
				M680X_REG_A, M680X_REG_B, M680X_REG_CC,
				EOL
			}
		},
	};
#undef EOL

	int i, j;

	if (MI->flat_insn->detail == NULL)
		return;

	for (i = 0; i < ARR_SIZE(changed_regs); ++i) {
		if (info->insn == changed_regs[i].insn) {
			e_access_mode access_mode =
				g_insn_props[info->insn].access_mode;

			for (j = 0; changed_regs[i].regs[j] !=
				M680X_REG_INVALID; ++j) {
				m680x_reg reg = changed_regs[i].regs[j];
				if (!info->cpu.reg_valid[reg])
					continue;
				e_access access = get_access(j, access_mode);
				add_reg_to_rw_list(MI, reg, access);
			}
		}
	}
}

typedef struct insn_desc {
	uint32_t opcode;
	m680x_insn insn;
	insn_hdlr_id handler_id;
	uint16_t insn_size;
} insn_desc;

static bool is_indexed_post_byte_valid(const m680x_info *info, uint16_t address,
	uint8_t ir, insn_desc *insn_description)
{
	switch (ir & 0x9F) {
	case 0x87:
	case 0x8A:
	case 0x8E:
	case 0x8F:
	case 0x90:
	case 0x92:
	case 0x97:
	case 0x9A:
	case 0x9E:
		return false; // illegal indexed post bytes

	case 0x88: // n8,R
	case 0x8C: // n8,PCR
	case 0x98: // [n8,R]
	case 0x9C: // [n8,PCR]
		insn_description->insn_size++;
		return read_byte(info, &ir, address);

	case 0x89: // n16,R
	case 0x8D: // n16,PCR
	case 0x99: // [n16,R]
	case 0x9D: // [n16,PCR]
		insn_description->insn_size += 2;
		return read_byte(info, &ir, address + 1);

	case 0x9F: // [n]
		insn_description->insn_size += 2;
		return (ir & 0x60) == 0 && read_byte(info, &ir, address + 1);
	}

	return true; // Any other indexed post byte is valid and
	// no additional bytes have to be read.
}

static bool is_tfr_reg_valid(const m680x_info *info, uint8_t reg_nibble)
{
	if (info->cpu.tfr_reg_valid != NULL)
		return info->cpu.tfr_reg_valid[reg_nibble];

	return true; // e.g. for the M6309 all registers are valid
}

static bool is_tfm_reg_valid(const m680x_info *info, uint8_t reg_nibble)
{
	// HD6809 TFM instruction: Only register X,Y,U,S,D is allowed
	return reg_nibble <= 4;
}

static bool is_sufficient_code_size(const m680x_info *info, uint16_t address,
	insn_desc *insn_description)
{
	uint8_t ir;

	switch (insn_description->handler_id) {
	case immediate32_hdlr_id:
		// Check for sufficient code size for additional four bytes
		insn_description->insn_size += 4;
		return read_byte(info, &ir, address + 3);

	case lbcc_hdlr_id:
	case extended_hdlr_id:
	case immediate16_hdlr_id:
		insn_description->insn_size += 2;
		// Check for sufficient code size for additional two bytes
		return read_byte(info, &ir, address + 1);

	case bcc_hdlr_id:
	case direct_hdlr_id:
	case reg_bits_hdlr_id:
	case immediate8_hdlr_id:
		insn_description->insn_size += 1;
		// Check for sufficient code size for an additional byte
		return read_byte(info, &ir, address);

	case illegal_hdlr_id:
	case inherent_hdlr_id:
		return true;

	case m6800_indexed_hdlr_id:
		insn_description->insn_size += 1;
		// Check for sufficient code size for an additional byte
		return read_byte(info, &ir, address);

	case m6809_indexed_hdlr_id:
		insn_description->insn_size += 1;

		// Check for sufficient code size for an additional byte
		if (!read_byte(info, &ir, address))
			return false;

		return is_indexed_post_byte_valid(info, address, ir,
				insn_description);

	case hd6309_tfm_hdlr_id:
		insn_description->insn_size += 1;

		// Check for sufficient code size for an additional byte
		if (!read_byte(info, &ir, address))
			return false;

		return is_tfm_reg_valid(info, (ir >> 4) & 0x0F) &&
			is_tfm_reg_valid(info, ir & 0x0F);

	case reg_reg_hdlr_id:
		insn_description->insn_size += 1;

		// Check for sufficient code size for an additional byte
		if (!read_byte(info, &ir, address))
			return false;

		return is_tfr_reg_valid(info, (ir >> 4) & 0x0F) &&
			is_tfr_reg_valid(info, ir & 0x0F);

	case hd630x_imm_direct_hdlr_id:
	case hd6301_imm_indexed_hdlr_id:
		insn_description->insn_size += 2;
		return read_byte(info, &ir, address + 1);

	case hd6309_bit_move_hdlr_id:
		insn_description->insn_size += 2;
		if (!read_byte(info, &ir, address))
			return false;
		if ((ir & 0xc0) == 0xc0)
			return false; // Invalid register specified
		return read_byte(info, &ir, address + 1);

	case hd6309_imm_indexed_hdlr_id:
		insn_description->insn_size += 1;
		// Check for sufficient code for immediate value
		if (!read_byte(info, &ir, address))
			return false;

		// Check for sufficient code for indexed post byte value
		address++;
		insn_description->insn_size += 1;
		if (!read_byte(info, &ir, address))
			return false;

		return is_indexed_post_byte_valid(info, address, ir,
				insn_description);

	case hd630x_imm_extended_hdlr_id:
		insn_description->insn_size += 3;
		return read_byte(info, &ir, address + 2);

	default:
		fprintf(stderr, "Internal error: Unexpected instruction "
			"handler id %d\n",
			insn_description->handler_id);
	}

	return false;
}

// Check for a valid M680X instruction AND for enough bytes in the code buffer
// Return an instruction description in insn_desc.
static bool decode_insn(const m680x_info *info, uint16_t address,
	insn_desc *insn_description)
{
	const inst_pageX *inst_table = NULL;
	const cpu_tables *cpu = &info->cpu;
	int table_size = 0;
	uint16_t base_address = address;
	uint8_t ir; // instruction register
	int i;
	int index;

	if (!read_byte(info, &ir, address++))
		return false;

	insn_description->opcode = ir;

	// Check if a page prefix byte is present
	for (i = 0; i < ARR_SIZE(info->cpu.pageX_table_size); ++i) {
		if (cpu->pageX_table_size[i] == 0 ||
			(cpu->inst_pageX_table[i] == NULL))
			break;

		if ((info->cpu.pageX_prefix[i] == ir)) {
			inst_table = cpu->inst_pageX_table[i];
			table_size = cpu->pageX_table_size[i];
		}
	}

	if (inst_table != NULL) {
		// Get pageX instruction and handler id. Abort for illegal instr.
		if (!read_byte(info, &ir, address++))
			return false;

		insn_description->opcode = (insn_description->opcode << 8) | ir;

		if ((index = binary_search(inst_table, table_size, ir)) < 0)
			return false;

		insn_description->handler_id = inst_table[index].handler_id;
		insn_description->insn = inst_table[index].insn;
	}
	else {
		bool insn_found = false;

		// Check if opcode byte is present in an overlay table
		for (i = 0; i < ARR_SIZE(cpu->overlay_table_size); ++i) {
			if (cpu->overlay_table_size[i] == 0 ||
				(cpu->inst_overlay_table[i] == NULL))
				break;

			inst_table = cpu->inst_overlay_table[i];
			table_size = cpu->overlay_table_size[i];

			if ((index = binary_search(inst_table, table_size, ir)) >= 0) {
				insn_description->handler_id = inst_table[index].handler_id;
				insn_description->insn = inst_table[index].insn;
				insn_found = true;
			}
		}

		if (!insn_found) {
			// Get page1 insn description
			insn_description->handler_id = cpu->inst_page1_table[ir].handler_id;
			insn_description->insn = cpu->inst_page1_table[ir].insn;
		}
	}

	insn_description->insn_size = address - base_address;

	return is_sufficient_code_size(info, address, insn_description);
}

static void illegal_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x_op *op0 = &info->m680x.operands[info->m680x.op_count++];
	uint8_t temp8 = 0;

	info->insn = M680X_INS_ILLGL;
	read_byte(info, &temp8, (*address)++);
	op0->imm = (int32_t)temp8 & 0xff;
	op0->type = M680X_OP_IMMEDIATE;
	op0->size = 1;
}

static void inherent_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	info->m680x.address_mode = M680X_AM_INHERENT;
}

static const uint8_t g_reg_byte_size[] = {
	0, 1, 1, 1, 1, 1, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 4, 2
};

static void add_reg_operand(cs_m680x *m680x, m680x_reg reg)
{
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];

	op->type = M680X_OP_REGISTER;
	op->reg = reg;
	op->size = g_reg_byte_size[reg];
}

static void set_operand_size(m680x_info *info, cs_m680x_op *op,
				uint8_t default_size)
{
	cs_m680x *m680x = &info->m680x;

	if (info->insn == M680X_INS_JMP || info->insn == M680X_INS_JSR)
		op->size = 0;
	else if (info->insn == M680X_INS_DIVD)
		op->size = 1;
	else if (info->insn == M680X_INS_DIVQ)
		op->size = 2;
	else if ((m680x->op_count > 0) &&
		(m680x->operands[0].type == M680X_OP_REGISTER))
		op->size = m680x->operands[0].size;
	else	
		op->size = default_size;
}

static const m680x_reg reg_s_reg_ids[] = {
	M680X_REG_CC, M680X_REG_A, M680X_REG_B, M680X_REG_DP,
	M680X_REG_X,  M680X_REG_Y, M680X_REG_U, M680X_REG_PC,
};

static const m680x_reg reg_u_reg_ids[] = {
	M680X_REG_CC, M680X_REG_A, M680X_REG_B, M680X_REG_DP,
	M680X_REG_X,  M680X_REG_Y, M680X_REG_S, M680X_REG_PC,
};

static void reg_bits_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op0 = &m680x->operands[0];
	uint8_t reg_bits = 0;
	uint16_t bit_index;
	const m680x_reg *reg_to_reg_ids;

	m680x->address_mode = M680X_AM_REGISTER;

	read_byte(info, &reg_bits, (*address)++);

	switch (op0->reg) {
	case M680X_REG_U:
		reg_to_reg_ids = &reg_u_reg_ids[0];
		break;

	case M680X_REG_S:
		reg_to_reg_ids = &reg_s_reg_ids[0];
		break;

	default:
		fprintf(stderr, "Internal error: Unexpected operand0 register "
			"%d\n", op0->reg);
		abort();
	}

	if ((info->insn == M680X_INS_PULU ||
			(info->insn == M680X_INS_PULS)) &&
		((reg_bits & 0x80) != 0))
		// PULS xxx,PC or PULU xxx,PC which is like return from
		// subroutine (RTS)
		add_insn_group(MI->flat_insn->detail, M680X_GRP_RET);

	for (bit_index = 0; bit_index < 8; ++bit_index) {
		if (reg_bits & (1 << bit_index))
			add_reg_operand(m680x, reg_to_reg_ids[bit_index]);
	}
}

static const m680x_reg g_tfr_exg_reg_ids[] = {
	/* 16-bit registers */
	M680X_REG_D, M680X_REG_X,  M680X_REG_Y,  M680X_REG_U,
	M680X_REG_S, M680X_REG_PC, M680X_REG_W,  M680X_REG_V,
	/* 8-bit registers */
	M680X_REG_A, M680X_REG_B,  M680X_REG_CC, M680X_REG_DP,
	M680X_REG_0, M680X_REG_0,  M680X_REG_E,  M680X_REG_F,
};

static void reg_reg_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	uint8_t regs = 0;

	m680x->address_mode = M680X_AM_REGISTER;

	read_byte(info, &regs, (*address)++);

	add_reg_operand(m680x, g_tfr_exg_reg_ids[regs >> 4]);
	add_reg_operand(m680x, g_tfr_exg_reg_ids[regs & 0x0f]);

	if ((regs & 0x0f) == 0x05) {
		// EXG xxx,PC or TFR xxx,PC which is like a JMP
		add_insn_group(MI->flat_insn->detail, M680X_GRP_JUMP);
	}
}

static void add_rel_operand(m680x_info *info, int16_t offset, uint16_t address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];

	m680x->address_mode = M680X_AM_RELATIVE;

	op->type = M680X_OP_RELATIVE;
	op->size = 0;
	op->rel.offset = offset;
	op->rel.address = address;
}

static void bcc_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	int16_t offset = 0;

	read_byte_sign_extended(info, &offset, (*address)++);
	add_rel_operand(info, offset, *address + offset);
	if (info->insn != M680X_INS_BRN)
		add_insn_group(MI->flat_insn->detail, M680X_GRP_BRAREL);
}

static void lbcc_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	uint16_t offset = 0;

	read_word(info, &offset, *address);
	*address += 2;
	add_rel_operand(info, (int16_t)offset, *address + offset);
	if (info->insn != M680X_INS_LBRN)
		add_insn_group(MI->flat_insn->detail, M680X_GRP_BRAREL);
}

static const m680x_reg g_rr5_to_reg_ids[] = {
	M680X_REG_X, M680X_REG_Y, M680X_REG_U, M680X_REG_S,
};

// M6800/1/2/3 indexed mode handler
static void m6800_indexed_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];
	uint8_t offset = 0;

	m680x->address_mode = M680X_AM_INDEXED;

	read_byte(info, &offset, (*address)++);

	op->type = M680X_OP_INDEXED_00;
	set_operand_size(info, op, 1);
	op->idx.base_reg = M680X_REG_X;
	op->idx.offset_reg = M680X_REG_INVALID;
	op->idx.offset = (uint16_t)offset;
	op->idx.offset_addr = 0;
	op->idx.offset_bits = M680X_OFFSET_BITS_8;
}

// M6809/M6309 indexed mode handler
static void m6809_indexed_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];
	uint8_t post_byte = 0;
	uint16_t offset = 0;
	int16_t soffset = 0;

	m680x->address_mode = M680X_AM_INDEXED;

	read_byte(info, &post_byte, (*address)++);

	op->type = M680X_OP_INDEXED_09;
	set_operand_size(info, op, 1);
	op->idx.base_reg = g_rr5_to_reg_ids[(post_byte >> 5) & 0x03];
	op->idx.offset_reg = M680X_REG_INVALID;

	if (!(post_byte & 0x80)) {
		// n5,R
		if ((post_byte & 0x10) == 0x10)
			op->idx.offset = post_byte | 0xfff0;
		else
			op->idx.offset = post_byte & 0x0f;

		op->idx.offset_addr = op->idx.offset + *address;
		op->idx.offset_bits = M680X_OFFSET_BITS_5;
	}
	else {
		if ((post_byte & 0x10) == 0x10)
			op->idx.flags |= M680X_IDX_INDIRECT;

		// indexed addressing
		switch (post_byte & 0x1f) {
		case 0x00: // ,R+
			op->idx.inc_dec = M680X_POST_INC_1;
			break;

		case 0x11: // [,R++]
		case 0x01: // ,R++
			op->idx.inc_dec = M680X_POST_INC_2;
			break;

		case 0x02: // ,-R
			op->idx.inc_dec = M680X_PRE_DEC_1;
			break;

		case 0x13: // [,--R]
		case 0x03: // ,--R
			op->idx.inc_dec = M680X_PRE_DEC_2;
			break;

		case 0x14: // [,R]
		case 0x04: // ,R
			break;

		case 0x15: // [B,R]
		case 0x05: // B,R
			op->idx.offset_reg = M680X_REG_B;
			break;

		case 0x16: // [A,R]
		case 0x06: // A,R
			op->idx.offset_reg = M680X_REG_A;
			break;

		case 0x1c: // [n8,PCR]
		case 0x0c: // n8,PCR
			op->idx.base_reg = M680X_REG_PC;
			read_byte_sign_extended(info, &soffset, (*address)++);
			op->idx.offset_addr = offset + *address;
			op->idx.offset = soffset;
			op->idx.offset_bits = M680X_OFFSET_BITS_8;
			break;

		case 0x18: // [n8,R]
		case 0x08: // n8,R
			read_byte_sign_extended(info, &soffset, (*address)++);
			op->idx.offset = soffset;
			op->idx.offset_bits = M680X_OFFSET_BITS_8;
			break;

		case 0x1d: // [n16,PCR]
		case 0x0d: // n16,PCR
			op->idx.base_reg = M680X_REG_PC;
			read_word(info, &offset, *address);
			*address += 2;
			op->idx.offset_addr = offset + *address;
			op->idx.offset = (int16_t)offset;
			op->idx.offset_bits = M680X_OFFSET_BITS_16;
			break;

		case 0x19: // [n16,R]
		case 0x09: // n16,R
			read_word(info, &offset, *address);
			*address += 2;
			op->idx.offset = (int16_t)offset;
			op->idx.offset_bits = M680X_OFFSET_BITS_16;
			break;

		case 0x1b: // [D,R]
		case 0x0b: // D,R
			op->idx.offset_reg = M680X_REG_D;
			break;

		case 0x1f: // [n16]
			m680x->address_mode = M680X_AM_EXTENDED;
			op->type = M680X_OP_EXTENDED;
			op->ext.indirect = true;
			read_word(info, &op->ext.address, *address);
			*address += 2;
			break;

		default:
			op->idx.base_reg = M680X_REG_INVALID;
			break;
		}
	}

	if (((info->insn == M680X_INS_LEAU) ||
			(info->insn == M680X_INS_LEAS) ||
			(info->insn == M680X_INS_LEAX) ||
			(info->insn == M680X_INS_LEAY)) &&
		(m680x->operands[0].reg == M680X_REG_X ||
			(m680x->operands[0].reg == M680X_REG_Y)))
		// Only LEAX and LEAY modify CC register
		add_reg_to_rw_list(MI, M680X_REG_CC, MODIFY);
}

static void direct_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];

	m680x->address_mode = M680X_AM_DIRECT;

	op->type = M680X_OP_DIRECT;
	set_operand_size(info, op, 1);
	read_byte(info, &op->direct_addr, (*address)++);
};

static void extended_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];

	m680x->address_mode = M680X_AM_EXTENDED;

	op->type = M680X_OP_EXTENDED;
	set_operand_size(info, op, 1);
	read_word(info, &op->ext.address, *address);
	*address += 2;
}

static void immediate_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];
	uint16_t word = 0;
	int16_t sword = 0;

	m680x->address_mode = M680X_AM_IMMEDIATE;

	op->type = M680X_OP_IMMEDIATE;
	set_operand_size(info, op, 1);

	switch (op->size) {
	case 1:
		read_byte_sign_extended(info, &sword, *address);
		op->imm = sword;
		break;

	case 2:
		read_word(info, &word, *address);
		op->imm = (int16_t)word;
		break;

	case 4:
		read_sdword(info, &op->imm, *address);
		break;

	default:
		op->imm = 0;
		fprintf(stderr, "Internal error: Unexpected immediate byte "
			"size %d.\n", op->size);
	}

	*address += op->size;
}

static void hd630x_imm_direct_hdlr(MCInst *MI, m680x_info *info,
	uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;

	immediate_hdlr(MI, info, address);
	direct_hdlr(MI, info, address);

	m680x->address_mode = M680X_AM_IMM_DIRECT;
}

static void hd6301_imm_indexed_hdlr(MCInst *MI, m680x_info *info,
	uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;

	immediate_hdlr(MI, info, address);
	m6800_indexed_hdlr(MI, info, address);

	m680x->address_mode = M680X_AM_IMM_INDEXED;
}

static void hd6309_imm_indexed_hdlr(MCInst *MI, m680x_info *info,
	uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;

	immediate_hdlr(MI, info, address);
	m6809_indexed_hdlr(MI, info, address);

	m680x->address_mode = M680X_AM_IMM_INDEXED;
}

static void hd630x_imm_extended_hdlr(MCInst *MI, m680x_info *info,
	uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;

	immediate_hdlr(MI, info, address);
	extended_hdlr(MI, info, address);

	m680x->address_mode = M680X_AM_IMM_EXTENDED;
}

static void hd6309_bit_move_hdlr(MCInst *MI, m680x_info *info,
	uint16_t *address)
{
	static const m680x_reg m680x_reg[] = {
		M680X_REG_CC, M680X_REG_A, M680X_REG_B, M680X_REG_INVALID, 
	};

	uint8_t post_byte = 0;
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op;

	read_byte(info, &post_byte, *address);
	(*address)++;

	// operand[0] = register
	add_reg_operand(m680x, m680x_reg[post_byte >> 6]);

	// operand[1] = bit index in source operand
	op = &m680x->operands[m680x->op_count++];
	op->type = M680X_OP_INDEX;
	op->index = (post_byte >> 3) & 0x07;

	// operand[2] = bit index in destination operand
	op = &m680x->operands[m680x->op_count++];
	op->type = M680X_OP_INDEX;
	op->index = post_byte & 0x07;

	direct_hdlr(MI, info, address);

	m680x->address_mode = M680X_AM_BIT_MOVE;
}

static void add_indexed_operand(cs_m680x *m680x, m680x_reg reg,
	m680x_inc_dec inc_dec, bool no_comma)
{
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];

	op->type = M680X_OP_INDEXED_09;
	op->size = 1;
	op->idx.base_reg = reg;
	op->idx.inc_dec = inc_dec;
	op->idx.flags |= (no_comma ? M680X_IDX_NO_COMMA : 0);
}

static void hd6309_tfm_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	static const m680x_inc_dec inc_dec_r0[] = {
		M680X_POST_INC_1, M680X_POST_DEC_1,
		M680X_POST_INC_1, M680X_NO_INC_DEC,
	};
	static const m680x_inc_dec inc_dec_r1[] = {
		M680X_POST_INC_1, M680X_POST_DEC_1,
		M680X_NO_INC_DEC, M680X_POST_INC_1,
	};
	cs_m680x *m680x = &info->m680x;
	uint8_t regs = 0;
	uint8_t index = (MI->Opcode & 0xff) - 0x38;

	read_byte(info, &regs, *address);

	add_indexed_operand(m680x, g_tfr_exg_reg_ids[regs >> 4], 
				inc_dec_r0[index], true);
	add_indexed_operand(m680x, g_tfr_exg_reg_ids[regs & 0x0f], 
				inc_dec_r1[index], true);

	m680x->address_mode = M680X_AM_INDEXED2;

	add_reg_to_rw_list(MI, M680X_REG_W, READ | WRITE);
}

void (*const g_inst_handler[])(MCInst *, m680x_info *, uint16_t *) = {
	illegal_hdlr,
	bcc_hdlr,
	lbcc_hdlr,
	immediate_hdlr, // 8-bit
	immediate_hdlr, // 16-bit
	immediate_hdlr, // 32-bit
	direct_hdlr,
	extended_hdlr,
	m6800_indexed_hdlr,
	m6809_indexed_hdlr,
	inherent_hdlr,
	reg_reg_hdlr,
	reg_bits_hdlr,
	hd6301_imm_indexed_hdlr,
	hd6309_imm_indexed_hdlr,
	hd630x_imm_direct_hdlr,
	hd630x_imm_extended_hdlr,
	hd6309_bit_move_hdlr,
	hd6309_tfm_hdlr,
}; /* handler function pointers */

/* Disasemble one instruction at address and store in str_buff */
static unsigned int m680x_disassemble(MCInst *MI, m680x_info *info,
	uint16_t address)
{
	cs_m680x *m680x = &info->m680x;
	cs_detail *detail = MI->flat_insn->detail;
	uint16_t base_address = address;
	insn_desc insn_description;

	if (detail != NULL) {
		detail->regs_read_count = 0;
		detail->regs_write_count = 0;
		detail->groups_count = 0;
	}

	memset(&insn_description, 0, sizeof(insn_description));
	memset(m680x, 0, sizeof(*m680x));
	info->insn_size = 1;

	if (decode_insn(info, address, &insn_description)) {
		m680x_reg reg;

		if (insn_description.opcode > 0xff)
			address += 2; // 8-bit opcode + page prefix
		else
			address++; // 8-bit opcode only

		info->insn = insn_description.insn;

		MCInst_setOpcode(MI, insn_description.opcode);

		add_insn_group(detail, g_insn_props[info->insn].group);

		reg = g_insn_props[info->insn].reg0;
		if (reg != M680X_REG_INVALID) {
			add_reg_operand(m680x, reg);
			// First (or second) operand is a register which is
			// part of the mnemonic
			m680x->flags |= M680X_FIRST_OP_IN_MNEM;
			reg = g_insn_props[info->insn].reg1;
			if (reg != M680X_REG_INVALID) {
				add_reg_operand(m680x, reg);
				m680x->flags |= M680X_SECOND_OP_IN_MNEM;
			}
		}

		if (g_insn_props[info->insn].cc_modified)
			add_reg_to_rw_list(MI, M680X_REG_CC, MODIFY);

		// Call addressing mode specific instruction handler
		(g_inst_handler[insn_description.handler_id])(MI, info,
			&address);

		e_access_mode access_mode =
			g_insn_props[info->insn].access_mode;
		build_regs_read_write_counts(MI, info, access_mode);
		add_operators_access(MI, info, access_mode);

		if (g_insn_props[info->insn].update_reg_access)
			set_changed_regs_read_write_counts(MI, info);

		info->insn_size = insn_description.insn_size;

		return info->insn_size;
	} else
		MCInst_setOpcode(MI, insn_description.opcode);

	// Illegal instruction
	address = base_address;
	illegal_hdlr(MI, info, &address);
	return 1;
}

static const char *s_cpu_type[] = {
	"INVALID", "6800", "6801", "6805", "6809", "6301", "6309",
};

// Tables to check for a valid register on the CPU
// based on an enum m680x_reg value.
static const bool g_m6800_reg_valid[18] = {
	false, true, true, false, false, false, false, false, true,
	false, false, true, false, true, false, false, false, true,
};

static const bool g_m6801_reg_valid[18] = {
	false, true, true, false, false, false, true, false, true,
	false, false, true, false, true, false, false, false, true,
};

static const bool g_m6809_reg_valid[18] = {
	false, true, true, false, false, false, true, false, true,
	true, false, true, true, true, true, false, false, true,
};

static const bool g_hd6309_reg_valid[18] = {
	false, true, true, true, true, true, true, true, true,
	true, true, true, true, true, true, true, true, true,
};

static bool m680x_setup_internals(m680x_info *info, e_cpu_type cpu_type,
	uint16_t address,
	const uint8_t *code, uint16_t code_len)
{
	// Table to check for a valid register nibble on the M6809 CPU
	// used for TFR and EXG instruction.
	static const bool m6809_tfr_reg_valid[16] = {
		true, true, true, true, true,  true,  false, false,
		true, true, true, true, false, false, false, false,
	};
	cpu_tables *cpu = &info->cpu;
	size_t table_size;

	info->code = code;
	info->size = code_len;
	info->offset = address;
	info->cpu_type = cpu_type;

	memset(cpu, 0, sizeof(*cpu));

	switch (info->cpu_type) {
	case M680X_CPU_TYPE_6800:
		cpu->inst_page1_table = &g_m6800_inst_page1_table[0];
		cpu->reg_valid = &g_m6800_reg_valid[0];
		break;

	case M680X_CPU_TYPE_6801:
		cpu->inst_page1_table = &g_m6800_inst_page1_table[0];
		cpu->inst_overlay_table[0] = &g_m6801_inst_overlay_table[0];
		table_size = ARR_SIZE(g_m6801_inst_overlay_table);
		cpu->overlay_table_size[0] = table_size;
		cpu->reg_valid = &g_m6801_reg_valid[0];
		break;

	case M680X_CPU_TYPE_6301:
		cpu->inst_page1_table = &g_m6800_inst_page1_table[0];
		cpu->inst_overlay_table[0] = &g_m6801_inst_overlay_table[0];
		table_size = ARR_SIZE(g_m6801_inst_overlay_table);
		cpu->overlay_table_size[0] = table_size;
		cpu->inst_overlay_table[1] = &g_hd6301_inst_overlay_table[0];
		table_size = ARR_SIZE(g_hd6301_inst_overlay_table);
		cpu->overlay_table_size[1] = table_size;
		cpu->reg_valid = &g_m6801_reg_valid[0];
		break;

	case M680X_CPU_TYPE_6809:
		cpu->inst_page1_table = &g_m6809_inst_page1_table[0];
		cpu->pageX_prefix[0] = 0x10; // PAGE2 prefix
		cpu->pageX_prefix[1] = 0x11; // PAGE3 prefix
		cpu->inst_pageX_table[0] = &g_m6809_inst_page2_table[0];
		cpu->inst_pageX_table[1] = &g_m6809_inst_page3_table[0];
		cpu->pageX_table_size[0] = ARR_SIZE(g_m6809_inst_page2_table);
		cpu->pageX_table_size[1] = ARR_SIZE(g_m6809_inst_page3_table);
		cpu->reg_valid = &g_m6809_reg_valid[0];
		cpu->tfr_reg_valid = &m6809_tfr_reg_valid[0];
		break;

	case M680X_CPU_TYPE_6309:
		cpu->inst_page1_table = &g_m6809_inst_page1_table[0];
		cpu->inst_overlay_table[0] = &g_hd6309_inst_overlay_table[0];
		table_size = ARR_SIZE(g_hd6309_inst_overlay_table);
		cpu->overlay_table_size[0] = table_size;
		cpu->pageX_prefix[0] = 0x10; // PAGE2 prefix
		cpu->pageX_prefix[1] = 0x11; // PAGE3 prefix
		cpu->inst_pageX_table[0] = &g_hd6309_inst_page2_table[0];
		cpu->inst_pageX_table[1] = &g_hd6309_inst_page3_table[0];
		cpu->pageX_table_size[0] = ARR_SIZE(g_hd6309_inst_page2_table);
		cpu->pageX_table_size[1] = ARR_SIZE(g_hd6309_inst_page3_table);
		cpu->reg_valid = &g_hd6309_reg_valid[0];
		break;

	default:
		fprintf(stderr, "M680X_CPU_TYPE_%s is not suppported yet\n",
			s_cpu_type[cpu_type]);
		return false;
	}

	return true;
}

bool M680X_getInstruction(csh ud, const uint8_t *code, size_t code_len,
	MCInst *MI, uint16_t *size, uint64_t address, void *inst_info)
{
	unsigned int insn_size = 0;
	e_cpu_type cpu_type = M680X_CPU_TYPE_INVALID; // No default CPU type
	cs_struct *handle = (cs_struct *)ud;
	m680x_info *info = (m680x_info *)handle->printer_info;

	MCInst_clear(MI);

	if (handle->mode & CS_MODE_M680X_6800)
		cpu_type = M680X_CPU_TYPE_6800;

	if (handle->mode & CS_MODE_M680X_6801)
		cpu_type = M680X_CPU_TYPE_6801;

	if (handle->mode & CS_MODE_M680X_6805)
		cpu_type = M680X_CPU_TYPE_6805;

	if (handle->mode & CS_MODE_M680X_6809)
		cpu_type = M680X_CPU_TYPE_6809;

	if (handle->mode & CS_MODE_M680X_6301)
		cpu_type = M680X_CPU_TYPE_6301;

	if (handle->mode & CS_MODE_M680X_6309)
		cpu_type = M680X_CPU_TYPE_6309;

	if (cpu_type != M680X_CPU_TYPE_INVALID &&
		m680x_setup_internals(info, cpu_type, (uint16_t)address, code,
					code_len))
		insn_size = m680x_disassemble(MI, info, (uint16_t)address);

	if (insn_size == 0) {
		*size = 1;
		return false;
	}

	// Make sure we always stay within range
	if (insn_size > code_len) {
		*size = (uint16_t)code_len;
		return false;
	}
	else
		*size = (uint16_t)insn_size;

	return true;
}

cs_err M680X_disassembler_init(cs_struct *ud)
{
	if (M680X_REG_ENDING != ARR_SIZE(g_reg_byte_size)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"m680x_reg and g_reg_byte_size\n");

		return CS_ERR_MODE;
	}

	if (M680X_REG_ENDING != ARR_SIZE(g_m6800_reg_valid)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"m680x_reg and g_m6800_reg_valid\n");

		return CS_ERR_MODE;
	}

	if (M680X_REG_ENDING != ARR_SIZE(g_m6801_reg_valid)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"m680x_reg and g_m6801_reg_valid\n");

		return CS_ERR_MODE;
	}

	if (M680X_REG_ENDING != ARR_SIZE(g_m6809_reg_valid)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"m680x_reg and g_m6809_reg_valid\n");

		return CS_ERR_MODE;
	}

	if (M680X_INS_ENDING != ARR_SIZE(g_insn_props)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"m680x_insn and g_insn_props\n");

		return CS_ERR_MODE;
	}

	if (M680X_CPU_TYPE_ENDING != ARR_SIZE(s_cpu_type)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"e_cpu_type and s_cpu_type\n");

		return CS_ERR_MODE;
	}

	if (HANDLER_ID_ENDING != ARR_SIZE(g_inst_handler)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"insn_hdlr_id and g_inst_handler\n");

		return CS_ERR_MODE;
	}

	if (ACCESS_MODE_ENDING !=  MATRIX_SIZE(g_access_mode_to_access)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"e_access_mode and g_access_mode_to_access\n");

		return CS_ERR_MODE;
	}

	return CS_ERR_OK;
}

#ifndef CAPSTONE_DIET
void M680X_reg_access(const cs_insn *insn,
		cs_regs regs_read, uint8_t *regs_read_count,
		cs_regs regs_write, uint8_t *regs_write_count)
{
	if (insn->detail == NULL) {
		*regs_read_count = 0;
		*regs_write_count = 0;
	} else {
		*regs_read_count = insn->detail->regs_read_count;
		*regs_write_count = insn->detail->regs_write_count;

		memcpy(regs_read, insn->detail->regs_read,
			*regs_read_count * sizeof(insn->detail->regs_read[0]));
		memcpy(regs_write, insn->detail->regs_write,
			*regs_write_count *
				sizeof(insn->detail->regs_write[0]));
	}
}
#endif

#endif

