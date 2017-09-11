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
	m6800_reg_inherent_hdlr_id,
	m6809_reg_inherent_hdlr_id,
	reg_reg_hdlr_id,
	reg_bits_hdlr_id,
	hd630x_imm_indexed_hdlr_id,
	hd630x_imm_direct_hdlr_id,
	HANDLER_ID_ENDING,
} insn_hdlr_id;

// access modes for the first 4 register operands. If there are more than
// four registers they use the access mode of the 4th register.
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
	rrrw,
	rmmm,
	wrrr,
	mrrr,
	mwww,
	mmmm,
	mwrr,
} e_access_mode;

typedef enum access_type {
	UNCHANGED,
	READ,
	WRITE,
	MODIFY,
} access_type;

/* Properties of one instruction in PAGE1 (without prefix) */
typedef struct inst_page0 {
	m680x_insn insn : 8;
	m680x_reg reg0 : 5;
	insn_hdlr_id handler_id : 5; /* instruction handler id */
} inst_page0;

/* Properties of one instruction in any other PAGE X */
typedef struct inst_pageX {
	unsigned opcode : 8;
	m680x_insn insn : 8;
	m680x_reg reg0 : 5;
	insn_hdlr_id handler_id : 5; /* instruction handler id */
} inst_pageX;

typedef struct insn_props {
	unsigned group : 4;
	e_access_mode access_mode : 5;
	bool cc_modified : 1;
} insn_props;

// M6800/2 instructions
static const inst_page0 g_m6800_inst_page0_table[256] = {
	// 0x0x, inherent instructions
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_NOP, M680X_REG_INVALID, inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_TAP, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id },
	{ M680X_INS_TPA, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id },
	{ M680X_INS_INX, M680X_REG_X, inherent_hdlr_id },
	{ M680X_INS_DEX, M680X_REG_X, inherent_hdlr_id },
	{ M680X_INS_CLV, M680X_REG_INVALID, inherent_hdlr_id },
	{ M680X_INS_SEV, M680X_REG_INVALID, inherent_hdlr_id },
	{ M680X_INS_CLC, M680X_REG_INVALID, inherent_hdlr_id },
	{ M680X_INS_SEC, M680X_REG_INVALID, inherent_hdlr_id },
	{ M680X_INS_CLI, M680X_REG_INVALID, inherent_hdlr_id },
	{ M680X_INS_SEI, M680X_REG_INVALID, inherent_hdlr_id },
	// 0x1x, inherent instructions
	{ M680X_INS_SBA, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id },
	{ M680X_INS_CBA, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_TAB, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id },
	{ M680X_INS_TBA, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_DAA, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ABA, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	// 0x2x, relative branch instructions
	{ M680X_INS_BRA, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_BHI, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BLS, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BCC, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BCS, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BNE, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BEQ, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BVC, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BVS, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BPL, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BMI, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BGE, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BLT, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BGT, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BLE, M680X_REG_INVALID, bcc_hdlr_id },
	// 0x3x, inherent instructions
	{ M680X_INS_TSX, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id },
	{ M680X_INS_INS, M680X_REG_S, inherent_hdlr_id },
	{ M680X_INS_PULA, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id },
	{ M680X_INS_PULB, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id },
	{ M680X_INS_DES, M680X_REG_S, inherent_hdlr_id },
	{ M680X_INS_TXS, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id },
	{ M680X_INS_PSHA, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id },
	{ M680X_INS_PSHB, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_RTS, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_RTI, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_WAI, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id },
	{ M680X_INS_SWI, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id },
	// 0x4x, Register A instructions
	{ M680X_INS_NEGA, M680X_REG_A, inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_COMA, M680X_REG_A, inherent_hdlr_id },
	{ M680X_INS_LSRA, M680X_REG_A, inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_RORA, M680X_REG_A, inherent_hdlr_id },
	{ M680X_INS_ASRA, M680X_REG_A, inherent_hdlr_id },
	{ M680X_INS_ASLA, M680X_REG_A, inherent_hdlr_id },
	{ M680X_INS_ROLA, M680X_REG_A, inherent_hdlr_id },
	{ M680X_INS_DECA, M680X_REG_A, inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_INCA, M680X_REG_A, inherent_hdlr_id },
	{ M680X_INS_TSTA, M680X_REG_A, inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_CLRA, M680X_REG_A, inherent_hdlr_id },
	// 0x5x, Register B instructions
	{ M680X_INS_NEGB, M680X_REG_B, inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_COMB, M680X_REG_B, inherent_hdlr_id },
	{ M680X_INS_LSRB, M680X_REG_B, inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_RORB, M680X_REG_B, inherent_hdlr_id },
	{ M680X_INS_ASRB, M680X_REG_B, inherent_hdlr_id },
	{ M680X_INS_ASLB, M680X_REG_B, inherent_hdlr_id },
	{ M680X_INS_ROLB, M680X_REG_B, inherent_hdlr_id },
	{ M680X_INS_DECB, M680X_REG_B, inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_INCB, M680X_REG_B, inherent_hdlr_id },
	{ M680X_INS_TSTB, M680X_REG_B, inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_CLRB, M680X_REG_B, inherent_hdlr_id },
	// 0x6x, indexed instructions
	{ M680X_INS_NEG, M680X_REG_INVALID, m6800_indexed_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_COM, M680X_REG_INVALID, m6800_indexed_hdlr_id },
	{ M680X_INS_LSR, M680X_REG_INVALID, m6800_indexed_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ROR, M680X_REG_INVALID, m6800_indexed_hdlr_id },
	{ M680X_INS_ASR, M680X_REG_INVALID, m6800_indexed_hdlr_id },
	{ M680X_INS_ASL, M680X_REG_INVALID, m6800_indexed_hdlr_id },
	{ M680X_INS_ROL, M680X_REG_INVALID, m6800_indexed_hdlr_id },
	{ M680X_INS_DEC, M680X_REG_INVALID, m6800_indexed_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_INC, M680X_REG_INVALID, m6800_indexed_hdlr_id },
	{ M680X_INS_TST, M680X_REG_INVALID, m6800_indexed_hdlr_id },
	{ M680X_INS_JMP, M680X_REG_INVALID, m6800_indexed_hdlr_id },
	{ M680X_INS_CLR, M680X_REG_INVALID, m6800_indexed_hdlr_id },
	// 0x7x, extended instructions
	{ M680X_INS_NEG, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_COM, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_LSR, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ROR, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_ASR, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_ASL, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_ROL, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_DEC, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_INC, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_TST, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_JMP, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_CLR, M680X_REG_INVALID, extended_hdlr_id },
	// 0x8x, immediate instructions with Register A,X,S
	{ M680X_INS_SUBA, M680X_REG_A, immediate8_hdlr_id },
	{ M680X_INS_CMPA, M680X_REG_A, immediate8_hdlr_id },
	{ M680X_INS_SBCA, M680X_REG_A, immediate8_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ANDA, M680X_REG_A, immediate8_hdlr_id },
	{ M680X_INS_BITA, M680X_REG_A, immediate8_hdlr_id },
	{ M680X_INS_LDAA, M680X_REG_A, immediate8_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_EORA, M680X_REG_A, immediate8_hdlr_id },
	{ M680X_INS_ADCA, M680X_REG_A, immediate8_hdlr_id },
	{ M680X_INS_ORAA, M680X_REG_A, immediate8_hdlr_id },
	{ M680X_INS_ADDA, M680X_REG_A, immediate8_hdlr_id },
	{ M680X_INS_CPX, M680X_REG_X, immediate16_hdlr_id },
	{ M680X_INS_BSR, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_LDS, M680X_REG_S, immediate16_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	// 0x9x, direct instructions with register A,X,S
	{ M680X_INS_SUBA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_CMPA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_SBCA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ANDA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_BITA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_LDAA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_STAA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_EORA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_ADCA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_ORAA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_ADDA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_CPX, M680X_REG_X, direct_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_LDS, M680X_REG_S, direct_hdlr_id },
	{ M680X_INS_STS, M680X_REG_S, direct_hdlr_id },
	// 0xAx, indexed instructions with Register A,X
	{ M680X_INS_SUBA, M680X_REG_A, m6800_indexed_hdlr_id },
	{ M680X_INS_CMPA, M680X_REG_A, m6800_indexed_hdlr_id },
	{ M680X_INS_SBCA, M680X_REG_A, m6800_indexed_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ANDA, M680X_REG_A, m6800_indexed_hdlr_id },
	{ M680X_INS_BITA, M680X_REG_A, m6800_indexed_hdlr_id },
	{ M680X_INS_LDAA, M680X_REG_A, m6800_indexed_hdlr_id },
	{ M680X_INS_STAA, M680X_REG_A, m6800_indexed_hdlr_id },
	{ M680X_INS_EORA, M680X_REG_A, m6800_indexed_hdlr_id },
	{ M680X_INS_ADCA, M680X_REG_A, m6800_indexed_hdlr_id },
	{ M680X_INS_ORAA, M680X_REG_A, m6800_indexed_hdlr_id },
	{ M680X_INS_ADDA, M680X_REG_A, m6800_indexed_hdlr_id },
	{ M680X_INS_CPX, M680X_REG_X, m6800_indexed_hdlr_id },
	{ M680X_INS_JSR, M680X_REG_INVALID, m6800_indexed_hdlr_id },
	{ M680X_INS_LDS, M680X_REG_S, m6800_indexed_hdlr_id },
	{ M680X_INS_STS, M680X_REG_S, m6800_indexed_hdlr_id },
	// 0xBx, extended instructions with register A,X,S
	{ M680X_INS_SUBA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_CMPA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_SBCA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ANDA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_BITA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_LDAA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_STAA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_EORA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_ADCA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_ORAA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_ADDA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_CPX, M680X_REG_X, extended_hdlr_id },
	{ M680X_INS_JSR, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_LDS, M680X_REG_S, extended_hdlr_id },
	{ M680X_INS_STS, M680X_REG_S, extended_hdlr_id },
	// 0xCx, immediate instructions with register B,X
	{ M680X_INS_SUBB, M680X_REG_B, immediate8_hdlr_id },
	{ M680X_INS_CMPB, M680X_REG_B, immediate8_hdlr_id },
	{ M680X_INS_SBCB, M680X_REG_B, immediate8_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ANDB, M680X_REG_B, immediate8_hdlr_id },
	{ M680X_INS_BITB, M680X_REG_B, immediate8_hdlr_id },
	{ M680X_INS_LDAB, M680X_REG_B, immediate8_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_EORB, M680X_REG_B, immediate8_hdlr_id },
	{ M680X_INS_ADCB, M680X_REG_B, immediate8_hdlr_id },
	{ M680X_INS_ORAB, M680X_REG_B, immediate8_hdlr_id },
	{ M680X_INS_ADDB, M680X_REG_B, immediate8_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_LDX, M680X_REG_X, immediate16_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	// 0xDx direct instructions with register B,X
	{ M680X_INS_SUBB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_CMPB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_SBCB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ANDB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_BITB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_LDAB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_STAB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_EORB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_ADCB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_ORAB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_ADDB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_LDX, M680X_REG_X, direct_hdlr_id },
	{ M680X_INS_STX, M680X_REG_X, direct_hdlr_id },
	// 0xEx, indexed instruction with register B,X
	{ M680X_INS_SUBB, M680X_REG_B, m6800_indexed_hdlr_id },
	{ M680X_INS_CMPB, M680X_REG_B, m6800_indexed_hdlr_id },
	{ M680X_INS_SBCB, M680X_REG_B, m6800_indexed_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ANDB, M680X_REG_B, m6800_indexed_hdlr_id },
	{ M680X_INS_BITB, M680X_REG_B, m6800_indexed_hdlr_id },
	{ M680X_INS_LDAB, M680X_REG_B, m6800_indexed_hdlr_id },
	{ M680X_INS_STAB, M680X_REG_B, m6800_indexed_hdlr_id },
	{ M680X_INS_EORB, M680X_REG_B, m6800_indexed_hdlr_id },
	{ M680X_INS_ADCB, M680X_REG_B, m6800_indexed_hdlr_id },
	{ M680X_INS_ORAB, M680X_REG_B, m6800_indexed_hdlr_id },
	{ M680X_INS_ADDB, M680X_REG_B, m6800_indexed_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_LDX, M680X_REG_X, m6800_indexed_hdlr_id },
	{ M680X_INS_STX, M680X_REG_X, m6800_indexed_hdlr_id },
	// 0xFx, extended instructions with register B,U
	{ M680X_INS_SUBB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_CMPB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_SBCB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ANDB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_BITB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_LDAB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_STAB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_EORB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_ADCB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_ORAB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_ADDB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_LDX, M680X_REG_X, extended_hdlr_id },
	{ M680X_INS_STX, M680X_REG_X, extended_hdlr_id },
};

// Additional instructions only supported on M6801/3
static const inst_pageX g_m6801_inst_overlay_table[] = {
	// 0x0x, inherent instructions
	{ 0x04, M680X_INS_LSRD, M680X_REG_D, inherent_hdlr_id },
	{ 0x05, M680X_INS_ASLD, M680X_REG_D, inherent_hdlr_id },
	// 0x2x, relative branch instructions
	{ 0x21, M680X_INS_BRN, M680X_REG_INVALID, bcc_hdlr_id },
	// 0x3x, inherent instructions
	{ 0x38, M680X_INS_PULX, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id },
	{ 0x3A, M680X_INS_ABX, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id },
	{ 0x3C, M680X_INS_PSHX, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id },
	{ 0x3D, M680X_INS_MUL, M680X_REG_INVALID, m6800_reg_inherent_hdlr_id  },
	// 0x8x, immediate instructions with Register D
	{ 0x83, M680X_INS_SUBD, M680X_REG_D, immediate16_hdlr_id },
	// 0x9x, direct instructions with register D
	{ 0x93, M680X_INS_SUBD, M680X_REG_D, direct_hdlr_id },
	{ 0x9D, M680X_INS_JSR, M680X_REG_INVALID, direct_hdlr_id },
	// 0xAx, indexed instructions with Register D
	{ 0xA3, M680X_INS_SUBD, M680X_REG_D, m6800_indexed_hdlr_id },
	// 0xBx, extended instructions with register D
	{ 0xB3, M680X_INS_SUBD, M680X_REG_D, extended_hdlr_id },
	// 0xCx, immediate instructions with register D
	{ 0xC3, M680X_INS_ADDD, M680X_REG_D, immediate16_hdlr_id },
	{ 0xCC, M680X_INS_LDD, M680X_REG_D, immediate16_hdlr_id },
	// 0xDx direct instructions with register D
	{ 0xD3, M680X_INS_ADDD, M680X_REG_D, direct_hdlr_id },
	{ 0xDC, M680X_INS_LDD, M680X_REG_D, direct_hdlr_id },
	{ 0xDD, M680X_INS_STD, M680X_REG_D, direct_hdlr_id },
	// 0xEx, indexed instruction with register D
	{ 0xE3, M680X_INS_ADDD, M680X_REG_D, m6800_indexed_hdlr_id },
	{ 0xEC, M680X_INS_LDD, M680X_REG_D, m6800_indexed_hdlr_id },
	{ 0xED, M680X_INS_STD, M680X_REG_D, m6800_indexed_hdlr_id },
	// 0xFx, extended instructions with register D
	{ 0xF3, M680X_INS_ADDD, M680X_REG_D, extended_hdlr_id },
	{ 0xFC, M680X_INS_LDD, M680X_REG_D, extended_hdlr_id },
	{ 0xFD, M680X_INS_STD, M680X_REG_D, extended_hdlr_id },
};

// Additional instructions only supported on HD6301/3
static const inst_pageX g_hd630x_inst_overlay_table[] = {
	{ 0x1B, M680X_INS_XGDX, M680X_REG_INVALID, inherent_hdlr_id },
	{ 0x61, M680X_INS_AIM, M680X_REG_INVALID, hd630x_imm_indexed_hdlr_id },
	{ 0x62, M680X_INS_OIM, M680X_REG_INVALID, hd630x_imm_indexed_hdlr_id },
	{ 0x65, M680X_INS_EIM, M680X_REG_INVALID, hd630x_imm_indexed_hdlr_id },
	{ 0x6B, M680X_INS_TIM, M680X_REG_INVALID, hd630x_imm_indexed_hdlr_id },
	{ 0x71, M680X_INS_AIM, M680X_REG_INVALID, hd630x_imm_direct_hdlr_id },
	{ 0x72, M680X_INS_OIM, M680X_REG_INVALID, hd630x_imm_direct_hdlr_id },
	{ 0x75, M680X_INS_EIM, M680X_REG_INVALID, hd630x_imm_direct_hdlr_id },
	{ 0x7B, M680X_INS_TIM, M680X_REG_INVALID, hd630x_imm_direct_hdlr_id },
};

// M6809/HD6309 PAGE1 instructions
static const inst_page0 g_m6809_inst_page0_table[256] = {
	// 0x0x, direct instructions
	{ M680X_INS_NEG, M680X_REG_INVALID, direct_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_COM, M680X_REG_INVALID, direct_hdlr_id },
	{ M680X_INS_LSR, M680X_REG_INVALID, direct_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ROR, M680X_REG_INVALID, direct_hdlr_id },
	{ M680X_INS_ASR, M680X_REG_INVALID, direct_hdlr_id },
	{ M680X_INS_LSL, M680X_REG_INVALID, direct_hdlr_id },
	{ M680X_INS_ROL, M680X_REG_INVALID, direct_hdlr_id },
	{ M680X_INS_DEC, M680X_REG_INVALID, direct_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_INC, M680X_REG_INVALID, direct_hdlr_id },
	{ M680X_INS_TST, M680X_REG_INVALID, direct_hdlr_id },
	{ M680X_INS_JMP, M680X_REG_INVALID, direct_hdlr_id },
	{ M680X_INS_CLR, M680X_REG_INVALID, direct_hdlr_id },
	// 0x1x, misc instructions
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id }, // PAGE2
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id }, // PAGE3
	{ M680X_INS_NOP, M680X_REG_INVALID, inherent_hdlr_id },
	{ M680X_INS_SYNC, M680X_REG_INVALID, inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_LBRA, M680X_REG_INVALID, lbcc_hdlr_id },
	{ M680X_INS_LBSR, M680X_REG_INVALID, lbcc_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_DAA, M680X_REG_INVALID, m6809_reg_inherent_hdlr_id },
	{ M680X_INS_ORCC, M680X_REG_CC, immediate8_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ANDCC, M680X_REG_CC, immediate8_hdlr_id },
	{ M680X_INS_SEX, M680X_REG_INVALID, m6809_reg_inherent_hdlr_id },
	{ M680X_INS_EXG, M680X_REG_INVALID, reg_reg_hdlr_id },
	{ M680X_INS_TFR, M680X_REG_INVALID, reg_reg_hdlr_id },
	// 0x2x, relative branch instructions
	{ M680X_INS_BRA, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BRN, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BHI, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BLS, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BCC, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BCS, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BNE, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BEQ, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BVC, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BVS, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BPL, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BMI, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BGE, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BLT, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BGT, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_BLE, M680X_REG_INVALID, bcc_hdlr_id },
	// 0x3x, misc instructions
	{ M680X_INS_LEAX, M680X_REG_X, m6809_indexed_hdlr_id },
	{ M680X_INS_LEAY, M680X_REG_Y, m6809_indexed_hdlr_id },
	{ M680X_INS_LEAS, M680X_REG_S, m6809_indexed_hdlr_id },
	{ M680X_INS_LEAU, M680X_REG_U, m6809_indexed_hdlr_id },
	{ M680X_INS_PSHS, M680X_REG_S, reg_bits_hdlr_id },
	{ M680X_INS_PULS, M680X_REG_S, reg_bits_hdlr_id },
	{ M680X_INS_PSHU, M680X_REG_U, reg_bits_hdlr_id },
	{ M680X_INS_PULU, M680X_REG_U, reg_bits_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_RTS, M680X_REG_INVALID, m6809_reg_inherent_hdlr_id },
	{ M680X_INS_ABX, M680X_REG_INVALID, m6809_reg_inherent_hdlr_id },
	{ M680X_INS_RTI, M680X_REG_INVALID, m6809_reg_inherent_hdlr_id },
	{ M680X_INS_CWAI, M680X_REG_INVALID, immediate8_hdlr_id },
	{ M680X_INS_MUL, M680X_REG_INVALID, m6809_reg_inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_SWI, M680X_REG_INVALID, m6809_reg_inherent_hdlr_id },
	// 0x4x, Register A instructions
	{ M680X_INS_NEGA, M680X_REG_A, inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_COMA, M680X_REG_A, inherent_hdlr_id },
	{ M680X_INS_LSRA, M680X_REG_A, inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_RORA, M680X_REG_A, inherent_hdlr_id },
	{ M680X_INS_ASRA, M680X_REG_A, inherent_hdlr_id },
	{ M680X_INS_LSLA, M680X_REG_A, inherent_hdlr_id },
	{ M680X_INS_ROLA, M680X_REG_A, inherent_hdlr_id },
	{ M680X_INS_DECA, M680X_REG_A, inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_INCA, M680X_REG_A, inherent_hdlr_id },
	{ M680X_INS_TSTA, M680X_REG_A, inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_CLRA, M680X_REG_A, inherent_hdlr_id },
	// 0x5x, Register B instructions
	{ M680X_INS_NEGB, M680X_REG_B, inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_COMB, M680X_REG_B, inherent_hdlr_id },
	{ M680X_INS_LSRB, M680X_REG_B, inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_RORB, M680X_REG_B, inherent_hdlr_id },
	{ M680X_INS_ASRB, M680X_REG_B, inherent_hdlr_id },
	{ M680X_INS_LSLB, M680X_REG_B, inherent_hdlr_id },
	{ M680X_INS_ROLB, M680X_REG_B, inherent_hdlr_id },
	{ M680X_INS_DECB, M680X_REG_B, inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_INCB, M680X_REG_B, inherent_hdlr_id },
	{ M680X_INS_TSTB, M680X_REG_B, inherent_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_CLRB, M680X_REG_B, inherent_hdlr_id },
	// 0x6x, indexed instructions
	{ M680X_INS_NEG, M680X_REG_INVALID, m6809_indexed_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_COM, M680X_REG_INVALID, m6809_indexed_hdlr_id },
	{ M680X_INS_LSR, M680X_REG_INVALID, m6809_indexed_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ROR, M680X_REG_INVALID, m6809_indexed_hdlr_id },
	{ M680X_INS_ASR, M680X_REG_INVALID, m6809_indexed_hdlr_id },
	{ M680X_INS_LSL, M680X_REG_INVALID, m6809_indexed_hdlr_id },
	{ M680X_INS_ROL, M680X_REG_INVALID, m6809_indexed_hdlr_id },
	{ M680X_INS_DEC, M680X_REG_INVALID, m6809_indexed_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_INC, M680X_REG_INVALID, m6809_indexed_hdlr_id },
	{ M680X_INS_TST, M680X_REG_INVALID, m6809_indexed_hdlr_id },
	{ M680X_INS_JMP, M680X_REG_INVALID, m6809_indexed_hdlr_id },
	{ M680X_INS_CLR, M680X_REG_INVALID, m6809_indexed_hdlr_id },
	// 0x7x, extended instructions
	{ M680X_INS_NEG, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_COM, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_LSR, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_ROR, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_ASR, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_LSL, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_ROL, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_DEC, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_INC, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_TST, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_JMP, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_CLR, M680X_REG_INVALID, extended_hdlr_id },
	// 0x8x, immediate instructions with Register A,D,X
	{ M680X_INS_SUBA, M680X_REG_A, immediate8_hdlr_id },
	{ M680X_INS_CMPA, M680X_REG_A, immediate8_hdlr_id },
	{ M680X_INS_SBCA, M680X_REG_A, immediate8_hdlr_id },
	{ M680X_INS_SUBD, M680X_REG_D, immediate16_hdlr_id },
	{ M680X_INS_ANDA, M680X_REG_A, immediate8_hdlr_id },
	{ M680X_INS_BITA, M680X_REG_A, immediate8_hdlr_id },
	{ M680X_INS_LDA, M680X_REG_A, immediate8_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_EORA, M680X_REG_A, immediate8_hdlr_id },
	{ M680X_INS_ADCA, M680X_REG_A, immediate8_hdlr_id },
	{ M680X_INS_ORA, M680X_REG_A, immediate8_hdlr_id },
	{ M680X_INS_ADDA, M680X_REG_A, immediate8_hdlr_id },
	{ M680X_INS_CMPX, M680X_REG_X, immediate16_hdlr_id },
	{ M680X_INS_BSR, M680X_REG_INVALID, bcc_hdlr_id },
	{ M680X_INS_LDX, M680X_REG_X, immediate16_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	// 0x9x, direct instructions with register A,D,X
	{ M680X_INS_SUBA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_CMPA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_SBCA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_SUBD, M680X_REG_D, direct_hdlr_id },
	{ M680X_INS_ANDA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_BITA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_LDA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_STA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_EORA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_ADCA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_ORA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_ADDA, M680X_REG_A, direct_hdlr_id },
	{ M680X_INS_CMPX, M680X_REG_X, direct_hdlr_id },
	{ M680X_INS_JSR, M680X_REG_INVALID, direct_hdlr_id },
	{ M680X_INS_LDX, M680X_REG_X, direct_hdlr_id },
	{ M680X_INS_STX, M680X_REG_X, direct_hdlr_id },
	// 0xAx, indexed instructions with Register A,D,X
	{ M680X_INS_SUBA, M680X_REG_A, m6809_indexed_hdlr_id },
	{ M680X_INS_CMPA, M680X_REG_A, m6809_indexed_hdlr_id },
	{ M680X_INS_SBCA, M680X_REG_A, m6809_indexed_hdlr_id },
	{ M680X_INS_SUBD, M680X_REG_D, m6809_indexed_hdlr_id },
	{ M680X_INS_ANDA, M680X_REG_A, m6809_indexed_hdlr_id },
	{ M680X_INS_BITA, M680X_REG_A, m6809_indexed_hdlr_id },
	{ M680X_INS_LDA, M680X_REG_A, m6809_indexed_hdlr_id },
	{ M680X_INS_STA, M680X_REG_A, m6809_indexed_hdlr_id },
	{ M680X_INS_EORA, M680X_REG_A, m6809_indexed_hdlr_id },
	{ M680X_INS_ADCA, M680X_REG_A, m6809_indexed_hdlr_id },
	{ M680X_INS_ORA, M680X_REG_A, m6809_indexed_hdlr_id },
	{ M680X_INS_ADDA, M680X_REG_A, m6809_indexed_hdlr_id },
	{ M680X_INS_CMPX, M680X_REG_X, m6809_indexed_hdlr_id },
	{ M680X_INS_JSR, M680X_REG_INVALID, m6809_indexed_hdlr_id },
	{ M680X_INS_LDX, M680X_REG_X, m6809_indexed_hdlr_id },
	{ M680X_INS_STX, M680X_REG_X, m6809_indexed_hdlr_id },
	// 0xBx, extended instructions with register A,D,X
	{ M680X_INS_SUBA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_CMPA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_SBCA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_SUBD, M680X_REG_D, extended_hdlr_id },
	{ M680X_INS_ANDA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_BITA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_LDA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_STA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_EORA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_ADCA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_ORA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_ADDA, M680X_REG_A, extended_hdlr_id },
	{ M680X_INS_CMPX, M680X_REG_X, extended_hdlr_id },
	{ M680X_INS_JSR, M680X_REG_INVALID, extended_hdlr_id },
	{ M680X_INS_LDX, M680X_REG_X, extended_hdlr_id },
	{ M680X_INS_STX, M680X_REG_X, extended_hdlr_id },
	// 0xCx, immediate instructions with register B,D,U
	{ M680X_INS_SUBB, M680X_REG_B, immediate8_hdlr_id },
	{ M680X_INS_CMPB, M680X_REG_B, immediate8_hdlr_id },
	{ M680X_INS_SBCB, M680X_REG_B, immediate8_hdlr_id },
	{ M680X_INS_ADDD, M680X_REG_D, immediate16_hdlr_id },
	{ M680X_INS_ANDB, M680X_REG_B, immediate8_hdlr_id },
	{ M680X_INS_BITB, M680X_REG_B, immediate8_hdlr_id },
	{ M680X_INS_LDB, M680X_REG_B, immediate8_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_EORB, M680X_REG_B, immediate8_hdlr_id },
	{ M680X_INS_ADCB, M680X_REG_B, immediate8_hdlr_id },
	{ M680X_INS_ORB, M680X_REG_B, immediate8_hdlr_id },
	{ M680X_INS_ADDB, M680X_REG_B, immediate8_hdlr_id },
	{ M680X_INS_LDD, M680X_REG_D, immediate16_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	{ M680X_INS_LDU, M680X_REG_U, immediate16_hdlr_id },
	{ M680X_INS_ILLGL, M680X_REG_INVALID, illegal_hdlr_id },
	// 0xDx direct instructions with register B,D,U
	{ M680X_INS_SUBB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_CMPB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_SBCB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_ADDD, M680X_REG_D, direct_hdlr_id },
	{ M680X_INS_ANDB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_BITB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_LDB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_STB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_EORB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_ADCB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_ORB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_ADDB, M680X_REG_B, direct_hdlr_id },
	{ M680X_INS_LDD, M680X_REG_D, direct_hdlr_id },
	{ M680X_INS_STD, M680X_REG_D, direct_hdlr_id },
	{ M680X_INS_LDU, M680X_REG_U, direct_hdlr_id },
	{ M680X_INS_STU, M680X_REG_U, direct_hdlr_id },
	// 0xEx, indexed instruction with register B,D,U
	{ M680X_INS_SUBB, M680X_REG_B, m6809_indexed_hdlr_id },
	{ M680X_INS_CMPB, M680X_REG_B, m6809_indexed_hdlr_id },
	{ M680X_INS_SBCB, M680X_REG_B, m6809_indexed_hdlr_id },
	{ M680X_INS_ADDD, M680X_REG_D, m6809_indexed_hdlr_id },
	{ M680X_INS_ANDB, M680X_REG_B, m6809_indexed_hdlr_id },
	{ M680X_INS_BITB, M680X_REG_B, m6809_indexed_hdlr_id },
	{ M680X_INS_LDB, M680X_REG_B, m6809_indexed_hdlr_id },
	{ M680X_INS_STB, M680X_REG_B, m6809_indexed_hdlr_id },
	{ M680X_INS_EORB, M680X_REG_B, m6809_indexed_hdlr_id },
	{ M680X_INS_ADCB, M680X_REG_B, m6809_indexed_hdlr_id },
	{ M680X_INS_ORB, M680X_REG_B, m6809_indexed_hdlr_id },
	{ M680X_INS_ADDB, M680X_REG_B, m6809_indexed_hdlr_id },
	{ M680X_INS_LDD, M680X_REG_D, m6809_indexed_hdlr_id },
	{ M680X_INS_STD, M680X_REG_D, m6809_indexed_hdlr_id },
	{ M680X_INS_LDU, M680X_REG_U, m6809_indexed_hdlr_id },
	{ M680X_INS_STU, M680X_REG_U, m6809_indexed_hdlr_id },
	// 0xFx, extended instructions with register B,D,U
	{ M680X_INS_SUBB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_CMPB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_SBCB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_ADDD, M680X_REG_D, extended_hdlr_id },
	{ M680X_INS_ANDB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_BITB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_LDB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_STB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_EORB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_ADCB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_ORB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_ADDB, M680X_REG_B, extended_hdlr_id },
	{ M680X_INS_LDD, M680X_REG_D, extended_hdlr_id },
	{ M680X_INS_STD, M680X_REG_D, extended_hdlr_id },
	{ M680X_INS_LDU, M680X_REG_U, extended_hdlr_id },
	{ M680X_INS_STU, M680X_REG_U, extended_hdlr_id },
};

// The following array has to be sorted by increasing
// opcodes. Otherwise the binary_search will fail.
//
// M6809/HD6309 PAGE2 instructions (with prefix 0x10)
static const inst_pageX g_m6809_inst_page2_table[] = {
	// 0x2x, relative long branch instructions
	{ 0x21, M680X_INS_LBRN, M680X_REG_INVALID, lbcc_hdlr_id },
	{ 0x22, M680X_INS_LBHI, M680X_REG_INVALID, lbcc_hdlr_id },
	{ 0x23, M680X_INS_LBLS, M680X_REG_INVALID, lbcc_hdlr_id },
	{ 0x24, M680X_INS_LBCC, M680X_REG_INVALID, lbcc_hdlr_id },
	{ 0x25, M680X_INS_LBCS, M680X_REG_INVALID, lbcc_hdlr_id },
	{ 0x26, M680X_INS_LBNE, M680X_REG_INVALID, lbcc_hdlr_id },
	{ 0x27, M680X_INS_LBEQ, M680X_REG_INVALID, lbcc_hdlr_id },
	{ 0x28, M680X_INS_LBVC, M680X_REG_INVALID, lbcc_hdlr_id },
	{ 0x29, M680X_INS_LBVS, M680X_REG_INVALID, lbcc_hdlr_id },
	{ 0x2a, M680X_INS_LBPL, M680X_REG_INVALID, lbcc_hdlr_id },
	{ 0x2b, M680X_INS_LBMI, M680X_REG_INVALID, lbcc_hdlr_id },
	{ 0x2c, M680X_INS_LBGE, M680X_REG_INVALID, lbcc_hdlr_id },
	{ 0x2d, M680X_INS_LBLT, M680X_REG_INVALID, lbcc_hdlr_id },
	{ 0x2e, M680X_INS_LBGT, M680X_REG_INVALID, lbcc_hdlr_id },
	{ 0x2f, M680X_INS_LBLE, M680X_REG_INVALID, lbcc_hdlr_id },
	// 0x3x
	{ 0x3f, M680X_INS_SWI2, M680X_REG_INVALID, m6809_reg_inherent_hdlr_id },
	// 0x8x, immediate instructions with register D,Y
	{ 0x83, M680X_INS_CMPD, M680X_REG_D, immediate16_hdlr_id },
	{ 0x8c, M680X_INS_CMPY, M680X_REG_Y, immediate16_hdlr_id },
	{ 0x8e, M680X_INS_LDY, M680X_REG_Y, immediate16_hdlr_id },
	// 0x9x, direct instructions with register D,Y
	{ 0x93, M680X_INS_CMPD, M680X_REG_D, direct_hdlr_id },
	{ 0x9c, M680X_INS_CMPY, M680X_REG_Y, direct_hdlr_id },
	{ 0x9e, M680X_INS_LDY, M680X_REG_Y, direct_hdlr_id },
	{ 0x9f, M680X_INS_STY, M680X_REG_Y, direct_hdlr_id },
	// 0xAx, indexed instructions with register D,Y
	{ 0xa3, M680X_INS_CMPD, M680X_REG_D, m6809_indexed_hdlr_id },
	{ 0xac, M680X_INS_CMPY, M680X_REG_Y, m6809_indexed_hdlr_id },
	{ 0xae, M680X_INS_LDY, M680X_REG_Y, m6809_indexed_hdlr_id },
	{ 0xaf, M680X_INS_STY, M680X_REG_Y, m6809_indexed_hdlr_id },
	// 0xBx, extended instructions with register D,Y
	{ 0xb3, M680X_INS_CMPD, M680X_REG_D, extended_hdlr_id },
	{ 0xbc, M680X_INS_CMPY, M680X_REG_Y, extended_hdlr_id },
	{ 0xbe, M680X_INS_LDY, M680X_REG_Y, extended_hdlr_id },
	{ 0xbf, M680X_INS_LDY, M680X_REG_Y, extended_hdlr_id },
	// 0xCx, immediate instructions with register S
	{ 0xce, M680X_INS_LDS, M680X_REG_S, immediate16_hdlr_id },
	// 0xDx, direct instructions with register S
	{ 0xde, M680X_INS_LDS, M680X_REG_S, direct_hdlr_id },
	{ 0xdf, M680X_INS_STS, M680X_REG_S, direct_hdlr_id },
	// 0xEx, indexed instructions with register S
	{ 0xee, M680X_INS_LDS, M680X_REG_S, m6809_indexed_hdlr_id },
	{ 0xef, M680X_INS_STS, M680X_REG_S, m6809_indexed_hdlr_id },
	// 0xFx, extended instructions with register S
	{ 0xfe, M680X_INS_LDS, M680X_REG_S, extended_hdlr_id },
	{ 0xff, M680X_INS_STS, M680X_REG_S, extended_hdlr_id },
};

// The following array has to be sorted by increasing
// opcodes. Otherwise the binary_search will fail.
//
// M6809/HD6309 PAGE3 instructions (with prefix 0x11)
static const inst_pageX g_m6809_inst_page3_table[] = {
	{ 0x3f, M680X_INS_SWI3, M680X_REG_INVALID, m6809_reg_inherent_hdlr_id },
	// 0x8x, immediate instructions with register U,S
	{ 0x83, M680X_INS_CMPU, M680X_REG_U, immediate16_hdlr_id },
	{ 0x8c, M680X_INS_CMPS, M680X_REG_S, immediate16_hdlr_id },
	// 0x9x, direct instructions with register U,S
	{ 0x93, M680X_INS_CMPU, M680X_REG_U, direct_hdlr_id },
	{ 0x9c, M680X_INS_CMPS, M680X_REG_S, direct_hdlr_id },
	// 0xAx, indexed instructions with register U,S
	{ 0xa3, M680X_INS_CMPU, M680X_REG_U, m6809_indexed_hdlr_id },
	{ 0xac, M680X_INS_CMPS, M680X_REG_S, m6809_indexed_hdlr_id },
	// 0xBx, extended instructions with register U,S
	{ 0xb3, M680X_INS_CMPU, M680X_REG_U, extended_hdlr_id },
	{ 0xbc, M680X_INS_CMPS, M680X_REG_S, extended_hdlr_id },
};

static const insn_props g_insn_props[] = {
	{ M680X_GRP_INVALID, uuuu, false }, // INVLD
	{ M680X_GRP_INVALID, mrrr, true }, // ABA
	{ M680X_GRP_INVALID, mrrr, false }, // ABX
	{ M680X_GRP_INVALID, mrrr, true }, // ADCA
	{ M680X_GRP_INVALID, mrrr, true }, // ADCB
	{ M680X_GRP_INVALID, mrrr, true }, // ADCD
	{ M680X_GRP_INVALID, mrrr, true }, // ADDA
	{ M680X_GRP_INVALID, mrrr, true }, // ADDB
	{ M680X_GRP_INVALID, mrrr, true }, // ADDD
	{ M680X_GRP_INVALID, mrrr, true }, // ADDE
	{ M680X_GRP_INVALID, mrrr, true }, // ADDF
	{ M680X_GRP_INVALID, mrrr, true }, // ADDR
	{ M680X_GRP_INVALID, mrrr, true }, // ADDW
	{ M680X_GRP_INVALID, rmmm, true }, // AIM
	{ M680X_GRP_INVALID, mrrr, true }, // ANDA
	{ M680X_GRP_INVALID, mrrr, true }, // ANDB
	{ M680X_GRP_INVALID, mrrr, true }, // ANDCC
	{ M680X_GRP_INVALID, mrrr, true }, // ANDD
	{ M680X_GRP_INVALID, rmmm, true }, // ANDR
	{ M680X_GRP_INVALID, mrrr, true }, // ASL
	{ M680X_GRP_INVALID, mrrr, true }, // ASLA
	{ M680X_GRP_INVALID, mrrr, true }, // ASLB
	{ M680X_GRP_INVALID, mrrr, true }, // ASLD
	{ M680X_GRP_INVALID, mrrr, true }, // ASR
	{ M680X_GRP_INVALID, mrrr, true }, // ASRA
	{ M680X_GRP_INVALID, mrrr, true }, // ASRB
	{ M680X_GRP_INVALID, mrrr, false }, // BAND
	{ M680X_GRP_JUMP, uuuu, false }, // BCC
	{ M680X_GRP_JUMP, uuuu, false }, // BCS
	{ M680X_GRP_INVALID, mrrr, false }, // BEOR
	{ M680X_GRP_JUMP, uuuu, false }, // BEQ
	{ M680X_GRP_JUMP, uuuu, false }, // BGE
	{ M680X_GRP_JUMP, uuuu, false }, // BGT
	{ M680X_GRP_JUMP, uuuu, false }, // BHI
	{ M680X_GRP_INVALID, mrrr, false }, // BIAND
	{ M680X_GRP_INVALID, mrrr, false }, // BIEOR
	{ M680X_GRP_INVALID, mrrr, false }, // BIOR
	{ M680X_GRP_INVALID, rrrr, true }, // BITA
	{ M680X_GRP_INVALID, rrrr, true }, // BITB
	{ M680X_GRP_INVALID, rrrr, true }, // BITD
	{ M680X_GRP_INVALID, rrrr, true }, // BITMD
	{ M680X_GRP_JUMP, uuuu, false }, // BLE
	{ M680X_GRP_JUMP, uuuu, false }, // BLS
	{ M680X_GRP_JUMP, uuuu, false }, // BLT
	{ M680X_GRP_JUMP, uuuu, false }, // BMI
	{ M680X_GRP_JUMP, uuuu, false }, // BNE
	{ M680X_GRP_JUMP, mrrr, false }, // BOR
	{ M680X_GRP_JUMP, uuuu, false }, // BPL
	{ M680X_GRP_JUMP, uuuu, false }, // BRA
	{ M680X_GRP_INVALID, uuuu, false }, // BRN never branches
	{ M680X_GRP_CALL, uuuu, false }, // BSR
	{ M680X_GRP_INVALID, uuuu, false }, // BVC
	{ M680X_GRP_INVALID, uuuu, false }, // BVS
	{ M680X_GRP_INVALID, rrrr, true }, // CBA
	{ M680X_GRP_INVALID, uuuu, true }, // CLC
	{ M680X_GRP_INVALID, uuuu, true }, // CLI
	{ M680X_GRP_INVALID, wrrr, true }, // CLR
	{ M680X_GRP_INVALID, wrrr, true }, // CLRA
	{ M680X_GRP_INVALID, wrrr, true }, // CLRB
	{ M680X_GRP_INVALID, wrrr, true }, // CLRD
	{ M680X_GRP_INVALID, wrrr, true }, // CLRE
	{ M680X_GRP_INVALID, wrrr, true }, // CLRF
	{ M680X_GRP_INVALID, wrrr, true }, // CLRW
	{ M680X_GRP_INVALID, uuuu, true }, // CLV
	{ M680X_GRP_INVALID, rrrr, true }, // CMPA
	{ M680X_GRP_INVALID, rrrr, true }, // CMPB
	{ M680X_GRP_INVALID, rrrr, true }, // CMPD
	{ M680X_GRP_INVALID, rrrr, true }, // CMPE
	{ M680X_GRP_INVALID, rrrr, true }, // CMPF
	{ M680X_GRP_INVALID, rrrr, true }, // CMPR
	{ M680X_GRP_INVALID, rrrr, true }, // CMPS
	{ M680X_GRP_INVALID, rrrr, true }, // CMPU
	{ M680X_GRP_INVALID, rrrr, true }, // CMPW
	{ M680X_GRP_INVALID, rrrr, true }, // CMPX
	{ M680X_GRP_INVALID, rrrr, true }, // CMPY
	{ M680X_GRP_INVALID, mmmm, true }, // COM
	{ M680X_GRP_INVALID, mrrr, true }, // COMA
	{ M680X_GRP_INVALID, mrrr, true }, // COMB
	{ M680X_GRP_INVALID, mrrr, true }, // COMD
	{ M680X_GRP_INVALID, mrrr, true }, // COME
	{ M680X_GRP_INVALID, mrrr, true }, // COMF
	{ M680X_GRP_INVALID, mrrr, true }, // COMW
	{ M680X_GRP_INVALID, rrrr, true }, // CPX
	{ M680X_GRP_INVALID, mrrr, true }, // CWAI
	{ M680X_GRP_INVALID, mrrr, true }, // DAA
	{ M680X_GRP_INVALID, mrrr, true }, // DEC
	{ M680X_GRP_INVALID, mrrr, true }, // DECA
	{ M680X_GRP_INVALID, mrrr, true }, // DECB
	{ M680X_GRP_INVALID, mrrr, true }, // DECD
	{ M680X_GRP_INVALID, mrrr, true }, // DECE
	{ M680X_GRP_INVALID, mrrr, true }, // DECF
	{ M680X_GRP_INVALID, mrrr, true }, // DECW
	{ M680X_GRP_INVALID, mrrr, false }, // DES
	{ M680X_GRP_INVALID, mrrr, true }, // DEX
	{ M680X_GRP_INVALID, mrrr, true }, // DIVD
	{ M680X_GRP_INVALID, mrrr, true }, // DIVQ
	{ M680X_GRP_INVALID, mrrr, true }, // EIM
	{ M680X_GRP_INVALID, mrrr, true }, // EORA
	{ M680X_GRP_INVALID, mrrr, true }, // EORB
	{ M680X_GRP_INVALID, mrrr, true }, // EORD
	{ M680X_GRP_INVALID, rwww, true }, // EORR
	{ M680X_GRP_INVALID, wwww, false }, // EXG
	{ M680X_GRP_INVALID, uuuu, false }, // ILLGL
	{ M680X_GRP_INVALID, mrrr, true }, // INC
	{ M680X_GRP_INVALID, mrrr, true }, // INCA
	{ M680X_GRP_INVALID, mrrr, true }, // INCB
	{ M680X_GRP_INVALID, mrrr, true }, // INCD
	{ M680X_GRP_INVALID, mrrr, true }, // INCE
	{ M680X_GRP_INVALID, mrrr, true }, // INCF
	{ M680X_GRP_INVALID, mrrr, true }, // INCW
	{ M680X_GRP_INVALID, mrrr, false }, // INS
	{ M680X_GRP_INVALID, mrrr, true }, // INX
	{ M680X_GRP_JUMP, uuuu, false }, // JMP
	{ M680X_GRP_CALL, uuuu, false }, // JSR
	{ M680X_GRP_JUMP, uuuu, false }, // LBCC
	{ M680X_GRP_JUMP, uuuu, false }, // LBCS
	{ M680X_GRP_JUMP, uuuu, false }, // LBEQ
	{ M680X_GRP_JUMP, uuuu, false }, // LBGE
	{ M680X_GRP_JUMP, uuuu, false }, // LBGT
	{ M680X_GRP_JUMP, uuuu, false }, // LBHI
	{ M680X_GRP_JUMP, uuuu, false }, // LBLE
	{ M680X_GRP_JUMP, uuuu, false }, // LBLS
	{ M680X_GRP_JUMP, uuuu, false }, // LBLT
	{ M680X_GRP_JUMP, uuuu, false }, // LBMI
	{ M680X_GRP_JUMP, uuuu, false }, // LBNE
	{ M680X_GRP_JUMP, uuuu, false }, // LBPL
	{ M680X_GRP_JUMP, uuuu, false }, // LBRA
	{ M680X_GRP_INVALID, uuuu, false }, // LBRN never branches
	{ M680X_GRP_CALL, uuuu, false }, // LBSR
	{ M680X_GRP_INVALID, uuuu, false }, // LBVC
	{ M680X_GRP_INVALID, uuuu, false }, // LBVS
	{ M680X_GRP_INVALID, wrrr, true }, // LDA
	{ M680X_GRP_INVALID, wrrr, true }, // LDAA
	{ M680X_GRP_INVALID, wrrr, true }, // LDAB
	{ M680X_GRP_INVALID, wrrr, true }, // LDB
	{ M680X_GRP_INVALID, mrrr, false }, // LDBT
	{ M680X_GRP_INVALID, wrrr, true }, // LDD
	{ M680X_GRP_INVALID, wrrr, true }, // LDE
	{ M680X_GRP_INVALID, wrrr, true }, // LDF
	{ M680X_GRP_INVALID, mrrr, false }, // LDMD
	{ M680X_GRP_INVALID, wrrr, true }, // LDQ
	{ M680X_GRP_INVALID, wrrr, true }, // LDS
	{ M680X_GRP_INVALID, wrrr, true }, // LDU
	{ M680X_GRP_INVALID, wrrr, true }, // LDW
	{ M680X_GRP_INVALID, wrrr, true }, // LDX
	{ M680X_GRP_INVALID, wrrr, true }, // LDY
	{ M680X_GRP_INVALID, wrrr, false }, // LEAS
	{ M680X_GRP_INVALID, wrrr, false }, // LEAU
	{ M680X_GRP_INVALID, wrrr, false }, // LEAX
	{ M680X_GRP_INVALID, wrrr, false }, // LEAY
	{ M680X_GRP_INVALID, mrrr, true }, // LSL
	{ M680X_GRP_INVALID, mrrr, true }, // LSLA
	{ M680X_GRP_INVALID, mrrr, true }, // LSLB
	{ M680X_GRP_INVALID, mrrr, true }, // LSR
	{ M680X_GRP_INVALID, mrrr, true }, // LSRA
	{ M680X_GRP_INVALID, mrrr, true }, // LSRB
	{ M680X_GRP_INVALID, mrrr, true }, // LSRD
	{ M680X_GRP_INVALID, mrrr, true }, // LSRW
	{ M680X_GRP_INVALID, mmmm, true }, // MUL
	{ M680X_GRP_INVALID, mwrr, true }, // MULD
	{ M680X_GRP_INVALID, mrrr, true }, // NEG
	{ M680X_GRP_INVALID, mrrr, true }, // NEGA
	{ M680X_GRP_INVALID, mrrr, true }, // NEGB
	{ M680X_GRP_INVALID, mrrr, true }, // NEGD
	{ M680X_GRP_INVALID, uuuu, false }, // NOP
	{ M680X_GRP_INVALID, mrrr, true }, // OIM
	{ M680X_GRP_INVALID, mrrr, true }, // ORA
	{ M680X_GRP_INVALID, mrrr, true }, // ORAA
	{ M680X_GRP_INVALID, mrrr, true }, // ORAB
	{ M680X_GRP_INVALID, mrrr, true }, // ORB
	{ M680X_GRP_INVALID, mrrr, true }, // ORCC
	{ M680X_GRP_INVALID, mrrr, true }, // ORD
	{ M680X_GRP_INVALID, rmmm, true }, // ORR
	{ M680X_GRP_INVALID, mrrr, false }, // PSHA
	{ M680X_GRP_INVALID, mrrr, false }, // PSHB
	{ M680X_GRP_INVALID, mrrr, false }, // PSHS
	{ M680X_GRP_INVALID, mrrr, false }, // PSHSW
	{ M680X_GRP_INVALID, mrrr, false }, // PSHU
	{ M680X_GRP_INVALID, mrrr, false }, // PSHUW
	{ M680X_GRP_INVALID, mrrr, false }, // PSHX
	{ M680X_GRP_INVALID, mwww, false }, // PULA
	{ M680X_GRP_INVALID, mwww, false }, // PULB
	{ M680X_GRP_INVALID, mwww, false }, // PULS
	{ M680X_GRP_INVALID, mwww, false }, // PULSW
	{ M680X_GRP_INVALID, mwww, false }, // PULU
	{ M680X_GRP_INVALID, mwww, false }, // PULUW
	{ M680X_GRP_INVALID, mwww, false }, // PULX
	{ M680X_GRP_INVALID, mrrr, true }, // ROL
	{ M680X_GRP_INVALID, mrrr, true }, // ROLA
	{ M680X_GRP_INVALID, mrrr, true }, // ROLB
	{ M680X_GRP_INVALID, mrrr, true }, // ROLD
	{ M680X_GRP_INVALID, mrrr, true }, // ROLW
	{ M680X_GRP_INVALID, mrrr, true }, // ROR
	{ M680X_GRP_INVALID, mrrr, true }, // RORA
	{ M680X_GRP_INVALID, mrrr, true }, // RORB
	{ M680X_GRP_INVALID, mrrr, true }, // RORD
	{ M680X_GRP_INVALID, mrrr, true }, // RORW
	{ M680X_GRP_IRET, mwww, false }, // RTI
	{ M680X_GRP_RET, mwww, false }, // RTS
	{ M680X_GRP_INVALID, mrrr, true }, // SBA
	{ M680X_GRP_INVALID, mrrr, true }, // SBCA
	{ M680X_GRP_INVALID, mrrr, true }, // SBCB
	{ M680X_GRP_INVALID, mrrr, true }, // SBCD
	{ M680X_GRP_INVALID, rmmm, true }, // SBCR
	{ M680X_GRP_INVALID, uuuu, true }, // SEC
	{ M680X_GRP_INVALID, uuuu, true }, // SEI
	{ M680X_GRP_INVALID, uuuu, true }, // SEV
	{ M680X_GRP_INVALID, wrrr, true }, // SEX
	{ M680X_GRP_INVALID, wrrr, true }, // SEXW
	{ M680X_GRP_INVALID, rwww, true }, // STA
	{ M680X_GRP_INVALID, rwww, true }, // STAA
	{ M680X_GRP_INVALID, rwww, true }, // STAB
	{ M680X_GRP_INVALID, rwww, true }, // STB
	{ M680X_GRP_INVALID, rrrw, true }, // STBT
	{ M680X_GRP_INVALID, rwww, true }, // STD
	{ M680X_GRP_INVALID, rwww, true }, // STE
	{ M680X_GRP_INVALID, rwww, true }, // STF
	{ M680X_GRP_INVALID, rwww, true }, // STQ
	{ M680X_GRP_INVALID, rwww, true }, // STS
	{ M680X_GRP_INVALID, rwww, true }, // STU
	{ M680X_GRP_INVALID, rwww, true }, // STW
	{ M680X_GRP_INVALID, rwww, true }, // STX
	{ M680X_GRP_INVALID, rwww, true }, // STY
	{ M680X_GRP_INVALID, mrrr, true }, // SUBA
	{ M680X_GRP_INVALID, mrrr, true }, // SUBB
	{ M680X_GRP_INVALID, mrrr, true }, // SUBD
	{ M680X_GRP_INVALID, mrrr, true }, // SUBE
	{ M680X_GRP_INVALID, mrrr, true }, // SUBF
	{ M680X_GRP_INVALID, rwww, true }, // SUBR
	{ M680X_GRP_INVALID, mrrr, true }, // SUBW
	{ M680X_GRP_INT, mrrr, true }, // SWI
	{ M680X_GRP_INT, mrrr, true }, // SWI2
	{ M680X_GRP_INT, mrrr, true }, // SWI3
	{ M680X_GRP_INVALID, uuuu, false }, // SYNC
	{ M680X_GRP_INVALID, rwww, true }, // TAB
	{ M680X_GRP_INVALID, rwww, false }, // TAP
	{ M680X_GRP_INVALID, rwww, true }, // TBA
	{ M680X_GRP_INVALID, rwww, false }, // TPA
	{ M680X_GRP_INVALID, rwww, false }, // TFM
	{ M680X_GRP_INVALID, rwww, false }, // TFR
	{ M680X_GRP_INVALID, rrrr, true }, // TIM
	{ M680X_GRP_INVALID, rrrr, true }, // TST
	{ M680X_GRP_INVALID, rrrr, true }, // TSTA
	{ M680X_GRP_INVALID, rrrr, true }, // TSTB
	{ M680X_GRP_INVALID, rrrr, true }, // TSTD
	{ M680X_GRP_INVALID, rrrr, true }, // TSTE
	{ M680X_GRP_INVALID, rrrr, true }, // TSTF
	{ M680X_GRP_INVALID, rrrr, true }, // TSTW
	{ M680X_GRP_INVALID, rwww, false }, // TSX
	{ M680X_GRP_INVALID, rwww, false }, // TXS
	{ M680X_GRP_INVALID, mrrr, true }, // WAI
	{ M680X_GRP_INVALID, mmmm, false }, // XGDX
};

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

// For PAGE2 and PAGE3 opcodes when using an an array of inst_page0 most
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
	uint8_t pageX_prefix = (id >> 8) & 0xff;
	bool insn_found = false;
	int index;
	int i;

	for (i = 0; i < ARR_SIZE(cpu->pageX_prefix); ++i) {
		if (cpu->pageX_table_size[i] == 0 ||
			(cpu->inst_pageX_table[i] == NULL))
			break;

		if (cpu->pageX_prefix[i] == pageX_prefix) {
			index = binary_search(cpu->inst_pageX_table[i],
					cpu->pageX_table_size[i], id & 0xff);
			insn->id = (index >= 0) ?
				cpu->inst_pageX_table[i][index].insn :
				M680X_INS_ILLGL;
			return;
		}
	}

	// Check if opcode byte is present in an overlay table
	for (i = 0; i < ARR_SIZE(cpu->overlay_table_size); ++i) {
		if (cpu->overlay_table_size[i] == 0 || (cpu->inst_overlay_table[i] == NULL))
			break;

		if ((index = binary_search(cpu->inst_overlay_table[i],
						cpu->overlay_table_size[i],
						id & 0xff)) >= 0) {
			insn->id = cpu->inst_overlay_table[i][index].insn;
			insn_found = true;
		}
	}

	if (!insn_found)
		insn->id = cpu->inst_page0_table[id].insn;
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

static void add_reg_to_rw_list(MCInst *MI, m680x_reg reg, access_type access)
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

static void update_am_reg_list(MCInst *MI, cs_m680x_op *op, access_type access)
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

static const access_type mode_to_access_type[4][11] = {
	{
		UNCHANGED, READ, WRITE, READ,  READ, READ,   WRITE, MODIFY,
		MODIFY, MODIFY, MODIFY
	},
	{
		UNCHANGED, READ, WRITE, WRITE, READ, MODIFY, READ,  READ,
		WRITE, MODIFY, WRITE
	},
	{
		UNCHANGED, READ, WRITE, WRITE, READ, MODIFY, READ,  READ,
		WRITE, MODIFY, READ
	},
	{
		UNCHANGED, READ, WRITE, WRITE, WRITE, MODIFY, READ, READ,
		WRITE, MODIFY, READ
	},
};

static void build_regs_read_write_counts(MCInst *MI, m680x_info *info,
	e_access_mode reg_access_mode)
{
	cs_m680x *m680x = &info->m680x;
	int i;

	if (MI->flat_insn->detail == NULL || (!m680x->op_count))
		return;

	for (i = 0; i < m680x->op_count; ++i) {
		int idx = i > 3 ? 3 : i;

		access_type access = mode_to_access_type[idx][reg_access_mode];
		update_am_reg_list(MI, &m680x->operands[i], access);
	}
}

typedef struct insn_to_changed_regs {
	m680x_insn insn;
	m680x_reg regs[10];
} insn_to_changed_regs;

static void m6800_set_changed_regs_read_write_counts(MCInst *MI,
	m680x_info *info)
{
	static const insn_to_changed_regs changed_regs[] = {
		{M680X_INS_ABA, {M680X_REG_A, M680X_REG_B, M680X_REG_INVALID}},
		{M680X_INS_ABX, {M680X_REG_X, M680X_REG_B, M680X_REG_INVALID}},
		{M680X_INS_CBA, {M680X_REG_A, M680X_REG_B, M680X_REG_INVALID}},
		{M680X_INS_DAA, {M680X_REG_A, M680X_REG_INVALID}},
		{M680X_INS_MUL, {M680X_REG_A, M680X_REG_B, M680X_REG_INVALID}},
		{M680X_INS_PULA, {M680X_REG_S, M680X_REG_A, M680X_REG_INVALID}},
		{M680X_INS_PULB, {M680X_REG_S, M680X_REG_B, M680X_REG_INVALID}},
		{M680X_INS_PULX, {M680X_REG_S, M680X_REG_X, M680X_REG_INVALID}},
		{M680X_INS_PSHA, {M680X_REG_S, M680X_REG_A, M680X_REG_INVALID}},
		{M680X_INS_PSHB, {M680X_REG_S, M680X_REG_B, M680X_REG_INVALID}},
		{M680X_INS_PSHX, {M680X_REG_S, M680X_REG_X, M680X_REG_INVALID}},
		{
			M680X_INS_RTI, {
				M680X_REG_S, M680X_REG_CC, M680X_REG_B,
				M680X_REG_A, M680X_REG_X, M680X_REG_PC,
				M680X_REG_INVALID
			}
		},
		{M680X_INS_RTS, {M680X_REG_S, M680X_REG_PC, M680X_REG_INVALID}},
		{M680X_INS_SBA, {M680X_REG_A, M680X_REG_B, M680X_REG_INVALID}},
		{
			M680X_INS_SWI, {
				M680X_REG_S, M680X_REG_PC, M680X_REG_X,
				M680X_REG_A, M680X_REG_B, M680X_REG_CC,
				M680X_REG_INVALID
			}
		},
		{M680X_INS_TAB, {M680X_REG_A, M680X_REG_B, M680X_REG_INVALID}},
		{M680X_INS_TAP, {M680X_REG_A, M680X_REG_CC, M680X_REG_INVALID}},
		{M680X_INS_TBA, {M680X_REG_B, M680X_REG_A, M680X_REG_INVALID}},
		{M680X_INS_TPA, {M680X_REG_CC, M680X_REG_A, M680X_REG_INVALID}},
		{M680X_INS_TSX, {M680X_REG_S, M680X_REG_X, M680X_REG_INVALID}},
		{M680X_INS_TXS, {M680X_REG_X, M680X_REG_S, M680X_REG_INVALID}},
		{
			M680X_INS_WAI, {
				M680X_REG_S, M680X_REG_PC, M680X_REG_X,
				M680X_REG_A, M680X_REG_B, M680X_REG_CC,
				M680X_REG_INVALID
			}
		},
		{M680X_INS_XGDX, {M680X_REG_D, M680X_REG_X, M680X_REG_INVALID}},
	};

	int i, j;

	if (MI->flat_insn->detail == NULL)
		return;

	for (i = 0; i < ARR_SIZE(changed_regs); ++i) {
		if (info->insn == changed_regs[i].insn) {
			e_access_mode reg_access_mode =
				g_insn_props[info->insn].access_mode;

			for (j = 0; changed_regs[i].regs[j] !=
				M680X_REG_INVALID; ++j) {
				m680x_reg reg = changed_regs[i].regs[j];
				int idx = j > 3 ? 3 : j;

				access_type access =
					mode_to_access_type[idx][reg_access_mode];
				add_reg_to_rw_list(MI, reg, access);
			}
		}
	}
}

static void m6809_set_changed_regs_read_write_counts(MCInst *MI,
	m680x_info *info)
{
	static const insn_to_changed_regs changed_regs[] = {
		{M680X_INS_ABX, {M680X_REG_X, M680X_REG_B, M680X_REG_INVALID}},
		{M680X_INS_DAA, {M680X_REG_A, M680X_REG_INVALID}},
		{
			M680X_INS_CWAI, {
				M680X_REG_S, M680X_REG_PC, M680X_REG_U,
				M680X_REG_Y, M680X_REG_X, M680X_REG_DP,
				M680X_REG_D, M680X_REG_CC, M680X_REG_INVALID
			},
		},
		{M680X_INS_MUL, {M680X_REG_A, M680X_REG_B, M680X_REG_INVALID}},
		{M680X_INS_MULD, {M680X_REG_D, M680X_REG_W, M680X_REG_INVALID}},
		{M680X_INS_RTS, {M680X_REG_S, M680X_REG_PC, M680X_REG_INVALID}},
		{
			M680X_INS_RTI, {
				M680X_REG_S, M680X_REG_CC, M680X_REG_A,
				M680X_REG_B, M680X_REG_DP, M680X_REG_X,
				M680X_REG_Y, M680X_REG_U, M680X_REG_INVALID
			},
		},
		{M680X_INS_SEX, {M680X_REG_A, M680X_REG_B, M680X_REG_INVALID}},
		{M680X_INS_SEXW, {M680X_REG_D, M680X_REG_W, M680X_REG_INVALID}},
		{
			M680X_INS_SWI, {
				M680X_REG_S, M680X_REG_PC, M680X_REG_U,
				M680X_REG_Y, M680X_REG_X, M680X_REG_DP,
				M680X_REG_B, M680X_REG_A, M680X_REG_CC,
				M680X_REG_INVALID
			},
		},
		{
			M680X_INS_SWI2, {
				M680X_REG_S, M680X_REG_PC, M680X_REG_U,
				M680X_REG_Y, M680X_REG_X, M680X_REG_DP,
				M680X_REG_B, M680X_REG_A, M680X_REG_CC,
				M680X_REG_INVALID
			},
		},
		{
			M680X_INS_SWI3, {
				M680X_REG_S, M680X_REG_PC, M680X_REG_U,
				M680X_REG_Y, M680X_REG_X, M680X_REG_DP,
				M680X_REG_B, M680X_REG_A, M680X_REG_CC,
				M680X_REG_INVALID
			},
		},
	};

	int i, j;

	if (MI->flat_insn->detail == NULL)
		return;

	for (i = 0; i < ARR_SIZE(changed_regs); ++i) {
		if (info->insn == changed_regs[i].insn) {
			e_access_mode reg_access_mode =
				g_insn_props[info->insn].access_mode;

			for (j = 0; changed_regs[i].regs[j] !=
				M680X_REG_INVALID; ++j) {
				m680x_reg reg = changed_regs[i].regs[j];
				int idx = j > 3 ? 3 : j;

				access_type access =
					mode_to_access_type[idx][reg_access_mode];
				add_reg_to_rw_list(MI, reg, access);
			}
		}
	}
}

typedef struct insn_desc {
	uint32_t opcode;
	m680x_insn insn;
	m680x_reg reg0;
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

// Table to check for a valid register nibble on the M6809 CPU
// used for TFR and EXG instruction.
static const bool g_m6809_reg_valid[16] = {
	true, true, true, true, true,  true,  false, false,  // 16-bit registers
	true, true, true, true, false, false, false, false,  // 8-bit registers
};

static bool is_reg_valid(const m680x_info *info, uint8_t reg_nibble)
{
	if (info->cpu.reg_valid != NULL)
		return info->cpu.reg_valid[reg_nibble];

	return true; // e.g. for the M6309 all registers are valid
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
	case m6800_reg_inherent_hdlr_id:
	case m6809_reg_inherent_hdlr_id:
		return true;

	case m6800_indexed_hdlr_id:
		insn_description->insn_size += 1;
		// Check for sufficient code size for an additional byte
		return read_byte(info, &ir, address);

	case m6809_indexed_hdlr_id:
		insn_description->insn_size += 1;

		// Check for sufficient code size for an additional byte
		if (!read_byte(info, &ir, address)) {
			return false;
		}

		return is_indexed_post_byte_valid(info, address, ir,
				insn_description);

	case reg_reg_hdlr_id:
		insn_description->insn_size += 1;

		// Check for sufficient code size for an additional byte
		if (!read_byte(info, &ir, address))
			return false;

		return is_reg_valid(info, (ir >> 4) & 0x0F) &&
			is_reg_valid(info, ir & 0x0F);

	case hd630x_imm_direct_hdlr_id:
	case hd630x_imm_indexed_hdlr_id:
		insn_description->insn_size += 2;
		return read_byte(info, &ir, address + 1);

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

	if (!read_byte(info, &ir, address++)) {
		return false;
	}

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
		if (!read_byte(info, &ir, address++) ||
			((index = binary_search(inst_table, table_size, ir)) < 0))
			return false;

		insn_description->opcode = (insn_description->opcode << 8) | ir;
		insn_description->handler_id = inst_table[index].handler_id;
		insn_description->insn = inst_table[index].insn;
		insn_description->reg0 = inst_table[index].reg0;
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
				insn_description->reg0 = inst_table[index].reg0;
				insn_found = true;
			}
		}

		if (!insn_found) {
			// Get page0 insn description
			insn_description->handler_id = cpu->inst_page0_table[ir].handler_id;
			insn_description->insn = cpu->inst_page0_table[ir].insn;
			insn_description->reg0 = cpu->inst_page0_table[ir].reg0;
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
}

// M6800/1/3 inherent handler with changed register list
static void m6800_reg_inherent_hdlr(MCInst *MI, m680x_info *info,
	uint16_t *address)
{
	info->m680x.address_mode = M680X_AM_INHERENT;

	m6800_set_changed_regs_read_write_counts(MI, info);
}

// M6809/M6309 inherent handler with changed register list
static void m6809_reg_inherent_hdlr(MCInst *MI, m680x_info *info,
	uint16_t *address)
{
	info->m680x.address_mode = M680X_AM_INHERENT;

	m6809_set_changed_regs_read_write_counts(MI, info);
}

static void inherent_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	info->m680x.address_mode = M680X_AM_INHERENT;
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
		// PULS xxx,PC or PULU xxx,PC which is like return from subroutine (RTS)
		add_insn_group(MI->flat_insn->detail, M680X_GRP_RET);

	for (bit_index = 0; bit_index < 8; ++bit_index) {
		if (reg_bits & (1 << bit_index))
			m680x->operands[m680x->op_count++].reg =
				reg_to_reg_ids[bit_index];
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

	cs_m680x_op *op0 = &m680x->operands[m680x->op_count++];
	cs_m680x_op *op1 = &m680x->operands[m680x->op_count++];

	op0->reg = g_tfr_exg_reg_ids[regs >> 4] ;
	op1->reg = g_tfr_exg_reg_ids[regs & 0x0f];

	if ((regs & 0x0f) == 0x05) {
		// EXG xxx,PC or TFR xxx,PC which is like a JMP
		add_insn_group(MI->flat_insn->detail, M680X_GRP_JUMP);
	}
}

static void bcc_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op0 = &m680x->operands[m680x->op_count++];
	int16_t offset = 0;

	m680x->address_mode = M680X_AM_RELATIVE;

	read_byte_sign_extended(info, &offset, (*address)++);

	op0->type = M680X_OP_RELATIVE;
	op0->size = 1;
	op0->rel.offset = offset;
	op0->rel.address = *address + offset;
}

static void lbcc_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op0 = &m680x->operands[m680x->op_count++];
	uint16_t offset = 0;

	m680x->address_mode = M680X_AM_RELATIVE;

	read_word(info, &offset, *address);
	*address += 2;

	op0->type = M680X_OP_RELATIVE;
	op0->size = 2;
	op0->rel.offset = (int16_t)offset;
	op0->rel.address = *address + offset;
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
			op->idx.indirect = true;

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
	read_byte(info, &op->direct_addr, (*address)++);
};

static void extended_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];

	m680x->address_mode = M680X_AM_EXTENDED;

	op->type = M680X_OP_EXTENDED;
	read_word(info, &op->ext.address, *address);
	*address += 2;
}

const uint8_t g_reg_byte_size[] = {
	0, 1, 1, 1, 1, 1, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 4, 2
};

static void immediate_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op0 = &m680x->operands[0];
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];
	unsigned int imm_size;
	uint16_t word = 0;
	int16_t sword = 0;

	m680x->address_mode = M680X_AM_IMMEDIATE;

	op->type = M680X_OP_IMMEDIATE;

	if (info->insn != M680X_INS_CWAI)
		imm_size = g_reg_byte_size[op0->reg];
	else
		imm_size = 1; // Special case for CWAI (no register involved)

	switch (imm_size) {
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
			"size %d.\n", imm_size);
	}

	*address += imm_size;

	if (info->insn == M680X_INS_CWAI)
		m6809_set_changed_regs_read_write_counts(MI, info);
}

static void hd630x_imm_indexed_hdlr(MCInst *MI, m680x_info *info,
	uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op0 = &m680x->operands[m680x->op_count++];
	cs_m680x_op *op1 = &m680x->operands[m680x->op_count++];
	uint8_t tmp = 0;

	m680x->address_mode = M680X_AM_IMM_INDEXED;

	read_byte(info, &tmp, *(address++));
	op0->type = M680X_OP_IMMEDIATE;
	op0->imm = (int32_t)(uint16_t)tmp;

	read_byte(info, &tmp, *(address++));
	op1->type = M680X_OP_INDEXED_00;
	op1->idx.base_reg = M680X_REG_X;
	op1->idx.offset = (uint16_t)tmp;
	op1->idx.offset_bits = M680X_OFFSET_BITS_8;
}

static void hd630x_imm_direct_hdlr(MCInst *MI, m680x_info *info,
	uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op0 = &m680x->operands[m680x->op_count++];
	cs_m680x_op *op1 = &m680x->operands[m680x->op_count++];
	uint8_t tmp = 0;

	m680x->address_mode = M680X_AM_IMM_DIRECT;

	read_byte(info, &tmp, *(address++));
	op0->type = M680X_OP_IMMEDIATE;
	op0->imm = (int32_t)(uint16_t)tmp;

	read_byte(info, &tmp, *(address++));
	op1->type = M680X_OP_DIRECT;
	op1->direct_addr = tmp;
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
	m6800_reg_inherent_hdlr,
	m6809_reg_inherent_hdlr,
	reg_reg_hdlr,
	reg_bits_hdlr,
	hd630x_imm_indexed_hdlr,
	hd630x_imm_direct_hdlr,
}; /* handler function pointers */

/* Disasemble one instruction at address and store in str_buff */
static unsigned int m680x_disassemble(MCInst *MI, m680x_info *info,
	uint16_t address)
{
	cs_m680x *m680x = &info->m680x;
	cs_detail *detail = MI->flat_insn->detail;
	uint16_t base_address = address;
	insn_desc insn_description;
	int i;

	if (detail != NULL) {
		detail->regs_read_count = 0;
		detail->regs_write_count = 0;
		detail->groups_count = 0;
	}

	memset(&insn_description, 0, sizeof(insn_description));
	memset(m680x, 0, sizeof(*m680x));
	info->insn_size = 1;

	for (i = 0; i < M680X_OPERAND_COUNT; ++i)
		m680x->operands[i].type = M680X_OP_REGISTER;

	if (decode_insn(info, address, &insn_description)) {
		if (insn_description.opcode > 0xff)
			address += 2; // 8-bit opcode + page prefix
		else
			address++; // 8-bit opcode only

		info->insn = insn_description.insn;

		MCInst_setOpcode(MI, insn_description.opcode);

		e_access_mode reg_access_mode =
			g_insn_props[info->insn].access_mode;

		add_insn_group(detail, g_insn_props[info->insn].group);

		if (insn_description.reg0 != M680X_REG_INVALID) {
			cs_m680x_op *op0 = &m680x->operands[m680x->op_count++];

			op0->reg = insn_description.reg0;
			// First operand is a register which is part of the
			// mnemonic
			m680x->flags |= FIRST_OP_IN_MNEM;
		}

		if (g_insn_props[info->insn].cc_modified)
			add_reg_to_rw_list(MI, M680X_REG_CC, MODIFY);

		(g_inst_handler[insn_description.handler_id])(MI, info,
			&address);
		build_regs_read_write_counts(MI, info, reg_access_mode);

		info->insn_size = insn_description.insn_size;

		return info->insn_size;
	}

	// Illegal instruction
	address = base_address;
	illegal_hdlr(MI, info, &address);
	return 1;
}

static const char *s_cpu_type[] = {
	"INVALID", "6800", "6801", "6805", "6809", "6301", "6309",
};

static bool m680x_setup_internals(m680x_info *info, e_cpu_type cpu_type,
	uint16_t address,
	const uint8_t *code, uint16_t code_len)
{
	info->code = code;
	info->size = code_len;
	info->offset = address;
	info->cpu_type = cpu_type;

	memset(&info->cpu, 0, sizeof(info->cpu));

	switch (info->cpu_type) {
	case M680X_CPU_TYPE_6800:
		info->cpu.inst_page0_table = &g_m6800_inst_page0_table[0];
		break;

	case M680X_CPU_TYPE_6801:
		info->cpu.inst_page0_table = &g_m6800_inst_page0_table[0];
		info->cpu.inst_overlay_table[0] = &g_m6801_inst_overlay_table[0];
		info->cpu.overlay_table_size[0] = ARR_SIZE(g_m6801_inst_overlay_table);
		break;

	case M680X_CPU_TYPE_6301:
		info->cpu.inst_page0_table = &g_m6800_inst_page0_table[0];
		info->cpu.inst_overlay_table[0] = &g_m6801_inst_overlay_table[0];
		info->cpu.overlay_table_size[0] = ARR_SIZE(g_m6801_inst_overlay_table);
		info->cpu.inst_overlay_table[1] = &g_hd630x_inst_overlay_table[0];
		info->cpu.overlay_table_size[1] = ARR_SIZE(g_hd630x_inst_overlay_table);
		break;

	case M680X_CPU_TYPE_6809:
		info->cpu.inst_page0_table = &g_m6809_inst_page0_table[0];
		info->cpu.pageX_prefix[0] = 0x10; // PAGE2 prefix
		info->cpu.pageX_prefix[1] = 0x11; // PAGE3 prefix
		info->cpu.inst_pageX_table[0] = &g_m6809_inst_page2_table[0];
		info->cpu.inst_pageX_table[1] = &g_m6809_inst_page3_table[0];
		info->cpu.pageX_table_size[0] = ARR_SIZE(g_m6809_inst_page2_table);
		info->cpu.pageX_table_size[1] = ARR_SIZE(g_m6809_inst_page3_table);
		info->cpu.reg_valid = &g_m6809_reg_valid[0];
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
		fprintf(stderr, "Internal error: Size mismatch in enum m680x_reg "
			"and g_reg_byte_size\n");

		return CS_ERR_MODE;
	}

	if (M680X_INS_ENDING != ARR_SIZE(g_insn_props)) {
		fprintf(stderr, "Internal error: Size mismatch in enum m680x_insn "
			"and g_insn_props\n");

		return CS_ERR_MODE;
	}

	if (M680X_CPU_TYPE_ENDING != ARR_SIZE(s_cpu_type)) {
		fprintf(stderr, "Internal error: Size mismatch in enum e_cpu_type "
			"and s_cpu_type\n");

		return CS_ERR_MODE;
	}

	if (HANDLER_ID_ENDING != ARR_SIZE(g_inst_handler)) {
		fprintf(stderr, "Internal error: Size mismatch in enum insn_hdlr_id "
			"and g_inst_handler\n");

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

