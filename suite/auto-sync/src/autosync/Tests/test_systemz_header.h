
/// Enums corresponding to SystemZ condition codes
typedef enum systemz_cc {
	SYSTEMZ_CC_O,
	SYSTEMZ_CC_H,

	SYSTEMZ_CC_NH,
	SYSTEMZ_CC_NO,
	SYSTEMZ_CC_INVALID,
} systemz_cc;

/// Group of SystemZ instructions
typedef enum systemz_insn_group {
	SYSTEMZ_GRP_INVALID = 0, ///< = CS_GRP_INVALID

	// Generic groups
	// all jump instructions (conditional+direct+indirect jumps)
	SYSTEMZ_GRP_JUMP,	///< = CS_GRP_JUMP
	SYSTEMZ_GRP_CALL, ///< CS_GRP_CALL
	SYSTEMZ_GRP_RET, ///< CS_GRP_RET
	SYSTEMZ_GRP_INT, ///< CS_GRP_INT
	SYSTEMZ_GRP_IRET, ///< CS_GRP_IRET
	SYSTEMZ_GRP_PRIVILEGE, ///< CS_GRP_PRIVILEGE
	SYSTEMZ_GRP_BRANCH_RELATIVE, ///< CS_GRP_BRANCH_RELATIVE
	// generated content <SystemZGenCSFeatureEnum.inc> begin
	// clang-format off

	SYSTEMZ_FEATURE_FEATURESOFTFLOAT = 128,
	SYSTEMZ_FEATURE_FEATUREBACKCHAIN,
	SYSTEMZ_FEATURE_FEATUREDISTINCTOPS,
	SYSTEMZ_FEATURE_FEATUREFASTSERIALIZATION,
	SYSTEMZ_FEATURE_FEATURERESETDATPROTECTION,
	SYSTEMZ_FEATURE_FEATUREPROCESSORACTIVITYINSTRUMENTATION,

	// clang-format on
	// generated content <SystemZGenCSFeatureEnum.inc> end

	SYSTEMZ_GRP_ENDING,   // <-- mark the end of the list of groups
} systemz_insn_group;


/// Operand type for instruction's operands
typedef enum systemz_op_type {
	SYSTEMZ_OP_INVALID = CS_OP_INVALID, ///< = CS_OP_INVALID (Uninitialized).
	SYSTEMZ_OP_REG = CS_OP_REG, ///< = CS_OP_REG (Register operand).
	SYSTEMZ_OP_IMM = CS_OP_IMM, ///< = CS_OP_IMM (Immediate operand).
	SYSTEMZ_OP_MEM = CS_OP_MEM, ///< = CS_OP_MEM (Memory operand).
} systemz_op_type;

/// SystemZ registers
typedef enum systemz_reg {
	// generated content <SystemZGenCSRegEnum.inc> begin
	// clang-format off

	SYSTEMZ_REG_INVALID = 0,
	SYSTEMZ_REG_CC = 1,
	SYSTEMZ_REG_FPC = 2,
	SYSTEMZ_REG_R12Q = 193,
	SYSTEMZ_REG_R14Q = 194,
	SYSTEMZ_REG_ENDING, // 195

	// clang-format on
	// generated content <SystemZGenCSRegEnum.inc> end

	// alias registers
	// None
} systemz_reg;

typedef struct {
	systemz_insn_form form;
} systemz_suppl_info;

/// Instruction's operand referring to memory
/// This is associated with SYSTEMZ_OP_MEM operand type above
typedef struct systemz_op_mem {
	systemz_addr_mode am; ///< Address mode. Indicates which field below are set.
	uint8_t /* systemz_reg */ base;		///< base register, can be safely interpreted as
				///< a value of type `systemz_reg`, but it is only
				///< one byte wide
	uint8_t /* systemz_reg */ index;	///< Index register, same conditions apply here
	uint64_t length;	///< Length component. Can be a register or immediate.
	int64_t disp;	///< displacement/offset value
} systemz_op_mem;

/// Instruction operand
typedef struct cs_systemz_op {
	systemz_op_type type;	///< operand type
	union {
		systemz_reg reg;		///< register value for REG operand
		int64_t imm;		///< immediate value for IMM operand
		systemz_op_mem mem;	///< base/disp value for MEM operand
	};
	cs_ac_type access; ///< R/W access of the operand.
	uint8_t imm_width; ///< Bit width of the immediate. 0 if not specified.
} cs_systemz_op;

#define MAX_SYSTEMZ_OPS 6

// Instruction structure
typedef struct cs_systemz {
	systemz_cc cc;		///< Code condition
	systemz_insn_form format; ///< The instruction format.
	/// Number of operands of this instruction,
	/// or 0 when instruction has no operand.
	uint8_t op_count;
	cs_systemz_op operands[MAX_SYSTEMZ_OPS]; ///< operands for this instruction.
} cs_systemz;

/// SystemZ instruction
typedef enum systemz_insn {
	// generated content <SystemZGenCSInsnEnum.inc> begin
	// clang-format off

	SYSTEMZ_INS_INVALID,
	SYSTEMZ_INS_A,
	SYSTEMZ_INS_ZAP,

	// clang-format on
	// generated content <SystemZGenCSInsnEnum.inc> end

	SYSTEMZ_INS_ENDING,

	SYSTEMZ_INS_ALIAS_BEGIN,
	// generated content <SystemZGenCSAliasEnum.inc> begin
	// clang-format off

	SYSTEMZ_INS_ALIAS_VISTRB, // Real instr.: SYSTEMZ_VISTRB
	SYSTEMZ_INS_ALIAS_VSTRCZFS, // Real instr.: SYSTEMZ_VSTRCZFS
	SYSTEMZ_INS_ALIAS_VSTRSH, // Real instr.: SYSTEMZ_VSTRSH
	SYSTEMZ_INS_ALIAS_VSTRSF, // Real instr.: SYSTEMZ_VSTRSF

	// clang-format on
	// generated content <SystemZGenCSAliasEnum.inc> end

	// Hard-coded alias come here

	SYSTEMZ_INS_ALIAS_END,
} systemz_insn;

#ifdef CAPSTONE_SYSTEMZ_COMPAT_HEADER
#include "systemz_compatibility.h"
#endif
