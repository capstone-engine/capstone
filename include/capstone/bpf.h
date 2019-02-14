/* Capstone Disassembly Engine */
/* BPF Backend by david942j <david942j@gmail.com>, 2019 */

#ifndef CAPSTONE_BPF_H
#define CAPSTONE_BPF_H

#ifdef __cplusplus
extern "C" {
#endif

#include "platform.h"

#ifdef _MSC_VER
#pragma warning(disable:4201)
#endif

/// Operand type for instruction's operands
typedef enum bpf_op_type {
	BPF_OP_INVALID = 0,

	BPF_OP_REG,
	BPF_OP_IMM,
	BPF_OP_MEM
} bpf_op_type;

/// BPF registers
typedef enum bpf_reg {
	BPF_REG_INVALID = 0,
	BPF_REG_R0,
	BPF_REG_R1,
	BPF_REG_R2,
	BPF_REG_R3,
	BPF_REG_R4,
	BPF_REG_R5,
	BPF_REG_R6,
	BPF_REG_R7,
	BPF_REG_R8,
	BPF_REG_R9,
	BPF_REG_R10,

	BPF_REG_ENDING,		// <-- mark the end of the list or registers
} bpf_reg;

/// Instruction's operand referring to memory
/// This is associated with BPF_OP_MEM operand type above
typedef struct bpf_op_mem {
	bpf_reg base;	///< base register
	int32_t disp;	///< offset value
} bpf_op_mem;

/// Instruction operand
typedef struct cs_bpf_op {
	bpf_op_type type;
	union {
		uint8_t reg;	///< register value for REG operand
		uint32_t imm;	///< immediate value IMM operand
		bpf_op_mem mem;	///< base/index/scale/disp value for MEM operand
	};
} cs_bpf_op;

/// Instruction structure
typedef struct cs_bpf {
	uint8_t op_count;
	cs_bpf_op *operands;
} cs_bpf;

/// BPF instruction
typedef enum bpf_insn {
	BPF_INSN_ENDING,
} bpf_insn;

/// Group of BPF instructions
typedef enum bpf_insn_group {
	BPF_GRP_INVALID = 0, ///< = CS_GRP_INVALID

	BPF_GRP_LOAD,
	BPF_GRP_STORE,
	BPF_GRP_ALU,
	BPF_GRP_JUMP,
	BPF_GRP_CALL, ///< eBPF only
	BPF_GRP_RETURN,
	BPF_GRP_MISC, ///< cBPF only

	BPF_GRP_ENDING,   ///< <-- mark the end of the list of groups
} bpf_insn_group;

#ifdef __cplusplus
}
#endif

#endif
