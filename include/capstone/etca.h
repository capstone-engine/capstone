#ifndef CAPSTONE_ETCA_H
#define CAPSTONE_ETCA_H

/* Capstone Disassembly Engine */
/* By Alexander Nutz, 2025 */

#ifdef __cplusplus
extern "C" {
#endif

#include "platform.h"
#include "cs_operand.h"

#ifdef _MSC_VER
// "anonymous unions are a non-standard extension"
#pragma warning(disable : 4201)
#endif

/// ETCA registers and special registers
typedef enum {
	ETCA_REG_INVALID = 0,

	ETCA_REG_FIRST_BASE,
	ETCA_REG_R0 = ETCA_REG_FIRST_BASE,
	ETCA_REG_R1,
	ETCA_REG_R2,
	ETCA_REG_R3,
	ETCA_REG_R4,
	ETCA_REG_R5,
	ETCA_REG_R6,
	ETCA_REG_R7,
	ETCA_REG_LAST_BASE = ETCA_REG_R7,

	ETCA_REG_FIRST_REX,
	ETCA_REG_R8 = ETCA_REG_FIRST_REX,
	ETCA_REG_R9,
	ETCA_REG_R10,
	ETCA_REG_R11,
	ETCA_REG_R12,
	ETCA_REG_R13,
	ETCA_REG_R14,
	ETCA_REG_R15,
	ETCA_REG_LAST_REX = ETCA_REG_R15,

	ETCA_REG_ENDING,
} cs_etca_reg;

typedef enum {
	ETCA_OP_INVALID = CS_OP_INVALID,
	ETCA_OP_REG = CS_OP_REG, // register operand
	ETCA_OP_IMM = CS_OP_IMM, // (possibly full-) immediate operand
	ETCA_OP_MEM = CS_OP_MEM, // only for MO1/MO2 memory operands
} cs_etca_op_type;

// index + base + displacement
typedef struct {
	// (1 << index_multiplier_log2) * reg[index]
	struct {
		bool enabled;
		cs_etca_reg index;
		// 2^0=1, 2^1=2, 2^2=4, 2^3=8
		uint8_t index_multiplier_log2 : 2;
	} index;

	// reg[base]
	struct {
		bool enabled;
		cs_etca_reg base;
	} base;

	int64_t displacement;
} cs_etca_op_mem;

// Instruction operand
typedef struct {
	cs_etca_op_type type;
	union {
		uint64_t imm; // when ETCA_OP_IMM; after sign extensions
		cs_etca_reg reg; // when ETCA_OP_REG
		cs_etca_op_mem mem; // when ETCA_OP_MEM
	};
} cs_etca_op;

typedef enum etca_insn {
	ETCA_INS_INVALID = 0,

	ETCA_INS_NOP,

	ETCA_INS_REL_JMP,
	ETCA_INS_ABS_JMP,
	ETCA_INS_REL_CALL,
	ETCA_INS_ABS_CALL,

	ETCA_INS_ADD,
	ETCA_INS_SUB,
	ETCA_INS_RSUB,
	ETCA_INS_CMP,
	ETCA_INS_OR,
	ETCA_INS_XOR,
	ETCA_INS_AND,
	ETCA_INS_TEST,
	ETCA_INS_MOVZ,
	ETCA_INS_MOVS,
	ETCA_INS_LOAD,
	ETCA_INS_STORE,
	ETCA_INS_SLO,

	ETCA_INS_READCR,
	ETCA_INS_WRITECR,
	ETCA_INS_SYSCALL,
	ETCA_INS_ERET,
	ETCA_INS_WAIT,

	ETCA_INS_PUSH,
	ETCA_INS_POP,
	ETCA_INS_LEA,
	ETCA_INS_ADC,
	ETCA_INS_SBB,
	ETCA_INS_RSBB,
	ETCA_INS_ASR,
	ETCA_INS_ROL,
	ETCA_INS_ROR,
	ETCA_INS_SHL,
	ETCA_INS_SHR,
	ETCA_INS_RCL,
	ETCA_INS_RCR,
	ETCA_INS_POPCNT,
	ETCA_INS_GREV,
	ETCA_INS_CTZ,
	ETCA_INS_CLZ,
	ETCA_INS_NOT,
	ETCA_INS_ANDN,
	ETCA_INS_UDIV,
	ETCA_INS_SDIV,
	ETCA_INS_UREM,
	ETCA_INS_SREM,
	ETCA_INS_UMUL,
	ETCA_INS_SMUL,
	ETCA_INS_UHMUL,
	ETCA_INS_SHMUL,
	ETCA_INS_LSB,
	ETCA_INS_LSBMSK,
	ETCA_INS_RLSB,
	ETCA_INS_ZHIB,

	ETCA_INS_CACHE_FLUSH_ALL,
	ETCA_INS_DATA_PREFETCH,
	ETCA_INS_INSTRUCTION_PREFETCH,
	ETCA_INS_DCACHE_FLUSH,
	ETCA_INS_ICACHE_INVALIDATE,
	ETCA_INS_CACHE_INVALIDATE_ALL,
	ETCA_INS_DCACHE_INVALIDATE,
	ETCA_INS_ALLOC_ZERO,

	ETCA_INS_ENDING,
} etca_insn;

#define ETCA_MAX_NUM_OP 2

// first bit negates the cond
#define ETCA_COND_Z (0 << 1)
#define ETCA_COND_N (1 << 1)
#define ETCA_COND_C (2 << 1)
#define ETCA_COND_O (3 << 1)
#define ETCA_COND_BE (4 << 1)
#define ETCA_COND_L (5 << 1)
#define ETCA_COND_LE (6 << 1)
#define ETCA_COND_ALWAYS (7 << 1)

#define ETCA_COND_E ETCA_COND_Z
#define ETCA_COND_B ETCA_COND_C

#define ETCA_COND_NZ (1 | ETCA_COND_Z)
#define ETCA_COND_NN (1 | ETCA_COND_N)
#define ETCA_COND_NC (1 | ETCA_COND_C)
#define ETCA_COND_NO (1 | ETCA_COND_O)
#define ETCA_COND_A (1 | ETCA_COND_BE)
#define ETCA_COND_GE (1 | ETCA_COND_L)
#define ETCA_COND_G (1 | ETCA_COND_LE)
#define ETCA_COND_NEVER (1 | ETCA_COND_ALWAYS)

#define ETCA_COND_NE (1 | ETCA_COND_E)
#define ETCA_COND_AE (1 | ETCA_COND_C)

char const *cs_etca_cond_name(uint8_t cond);

typedef enum {
	ETCA_CR_CPUID1 = 0x00,
	ETCA_CR_CPUID2 = 0x01,
	ETCA_CR_FEAT = 0x02,
	ETCA_CR_FLAGS = 0x03,
	ETCA_CR_INT_PC = 0x04,
	ETCA_CR_INT_RET_PC = 0x05,
	ETCA_CR_INT_MASK = 0x06,
	ETCA_CR_INT_PENDING = 0x07,
	ETCA_CR_INT_CAUSE = 0x08,
	ETCA_CR_INT_DATA = 0x09,
	ETCA_CR_INT_SCRATCH_0 = 0x0A,
	ETCA_CR_INT_SCRATCH_1 = 0x0B,
	ETCA_CR_PRIV = 0x0C,
	ETCA_CR_INT_RET_PRIV = 0x0D,
	ETCA_CR_CACHE_LINE_SIZE = 0x0E,
	ETCA_CR_NO_CACHE_START = 0x0F,
	ETCA_CR_NO_CACHE_END = 0x10,
	ETCA_CR_MODE = 0x11,
} cs_etca_cr;

char const *cs_etca_cr_name(cs_etca_cr cr);

/// Instruction structure
typedef struct cs_etca {
	etca_insn insn : 8;
	uint8_t ss : 2;
	uint8_t cond : 4;
	uint8_t op_count : 2;
	cs_etca_op operands[ETCA_MAX_NUM_OP];
} cs_etca;

// instructions can have multiple groups
typedef enum {
	ETCA_GRP_INVALID = 0,
	ETCA_GRP_JUMP,
	ETCA_GRP_CALL,
	ETCA_GRP_PRIV,
	ETCA_GRP_ENDING,
} cs_etca_insn_group;

#ifdef __cplusplus
}
#endif

#endif
