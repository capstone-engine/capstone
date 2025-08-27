/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifndef CS_AARCH64_MAP_H
#define CS_AARCH64_MAP_H

#include "capstone/capstone.h"
#include "../../MCInst.h"
#include "../../SStream.h"

typedef enum {
#include "AArch64GenCSOpGroup.inc"
} aarch64_op_group;

/// Components of an SME matrix.
/// Used when an sme operand is set to signal which part should be set.
typedef enum {
	AARCH64_SME_MATRIX_TILE,
	AARCH64_SME_MATRIX_TILE_LIST,
	AARCH64_SME_MATRIX_SLICE_REG,
	AARCH64_SME_MATRIX_SLICE_OFF,
	AARCH64_SME_MATRIX_SLICE_OFF_RANGE,
} aarch64_sme_op_part;

// return name of register in friendly string
const char *AArch64_reg_name(csh handle, unsigned int reg);

// given internal insn id, return public instruction info
void AArch64_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);

const char *AArch64_insn_name(csh handle, unsigned int id);

const char *AArch64_group_name(csh handle, unsigned int id);

void AArch64_reg_access(const cs_insn *insn, cs_regs regs_read,
			uint8_t *regs_read_count, cs_regs regs_write,
			uint8_t *regs_write_count);

void AArch64_add_cs_detail_0(MCInst *MI, aarch64_op_group op_group,
			     unsigned OpNum);
void AArch64_add_cs_detail_1(MCInst *MI, aarch64_op_group op_group,
			     unsigned OpNum, uint64_t temp_arg_0);
void AArch64_add_cs_detail_2(MCInst *MI, aarch64_op_group op_group,
			     unsigned OpNum, uint64_t temp_arg_0,
			     uint64_t temp_arg_1);
void AArch64_add_cs_detail_4(MCInst *MI, aarch64_op_group op_group,
			     unsigned OpNum, uint64_t temp_arg_0,
			     uint64_t temp_arg_1, uint64_t temp_arg_2,
			     uint64_t temp_arg_3);

void AArch64_init_mri(MCRegisterInfo *MRI);

void AArch64_init_cs_detail(MCInst *MI);

void AArch64_set_instr_map_data(MCInst *MI);

bool AArch64_getInstruction(csh handle, const uint8_t *code, size_t code_len,
			    MCInst *instr, uint16_t *size, uint64_t address,
			    void *info);

void AArch64_printer(MCInst *MI, SStream *O, void * /* MCRegisterInfo* */ info);

void AArch64_set_detail_op_reg(MCInst *MI, unsigned OpNum, aarch64_reg Reg);
void AArch64_set_detail_op_imm(MCInst *MI, unsigned OpNum,
			       aarch64_op_type ImmType, int64_t Imm);
void AArch64_set_detail_op_imm_range(MCInst *MI, unsigned OpNum,
				     uint32_t FirstImm, uint32_t offset);
void AArch64_set_detail_op_mem(MCInst *MI, unsigned OpNum, uint64_t Val);
void AArch64_set_detail_op_mem_offset(MCInst *MI, unsigned OpNum, uint64_t Val);
void AArch64_set_detail_shift_ext(MCInst *MI, unsigned OpNum, bool SignExtend,
				  bool DoShift, unsigned ExtWidth,
				  char SrcRegKind);
void AArch64_set_detail_op_float(MCInst *MI, unsigned OpNum, float Val);
void AArch64_set_detail_op_sys(MCInst *MI, unsigned OpNum, aarch64_sysop sys_op,
			       aarch64_op_type type);
void AArch64_set_detail_op_sme(MCInst *MI, unsigned OpNum,
			       aarch64_sme_op_part part,
			       AArch64Layout_VectorLayout vas, ...);
void AArch64_set_detail_op_pred(MCInst *MI, unsigned OpNum);
void AArch64_insert_detail_op_reg_at(MCInst *MI, unsigned index,
				     aarch64_reg Reg, cs_ac_type access);
void AArch64_insert_detail_op_float_at(MCInst *MI, unsigned index, double val,
				       cs_ac_type access);
void AArch64_insert_detail_op_imm_at(MCInst *MI, unsigned index, int64_t Imm);
void AArch64_insert_detail_op_sys(MCInst *MI, unsigned index,
				  aarch64_sysop sys_op, aarch64_op_type type);
void AArch64_insert_detail_op_sme(MCInst *MI, unsigned index,
				  aarch64_op_sme sme_op);
void AArch64_add_vas(MCInst *MI, const SStream *OS);

#endif
