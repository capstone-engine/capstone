/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifndef CS_ARM_MAPPING_H
#define CS_ARM_MAPPING_H

#include "../../include/capstone/capstone.h"
#include "../../utils.h"
#include "ARMBaseInfo.h"

typedef enum {
#include "ARMGenCSOpGroup.inc"
} arm_op_group;

extern const ARMBankedReg_BankedReg *
ARMBankedReg_lookupBankedRegByEncoding(uint8_t Encoding);
extern const ARMSysReg_MClassSysReg *
ARMSysReg_lookupMClassSysRegByEncoding(uint16_t Encoding);

// return name of register in friendly string
const char *ARM_reg_name(csh handle, unsigned int reg);

void ARM_printer(MCInst *MI, SStream *O, void * /* MCRegisterInfo* */ info);

// given internal insn id, return public instruction ID
void ARM_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);

const char *ARM_insn_name(csh handle, unsigned int id);

const char *ARM_group_name(csh handle, unsigned int id);

// check if this insn is relative branch
bool ARM_rel_branch(cs_struct *h, unsigned int insn_id);

bool ARM_blx_to_arm_mode(cs_struct *h, unsigned int insn_id);

void ARM_reg_access(const cs_insn *insn, cs_regs regs_read,
		    uint8_t *regs_read_count, cs_regs regs_write,
		    uint8_t *regs_write_count);

const ARMBankedReg_BankedReg *
ARMBankedReg_lookupBankedRegByEncoding(uint8_t encoding);

bool ARM_getInstruction(csh handle, const uint8_t *code, size_t code_len,
			MCInst *instr, uint16_t *size, uint64_t address,
			void *info);
void ARM_set_instr_map_data(MCInst *MI);

void ARM_init_mri(MCRegisterInfo *MRI);

// cs_detail related functions
void ARM_init_cs_detail(MCInst *MI);
void ARM_add_cs_detail(MCInst *MI, int /* arm_op_group */ op_group,
		       va_list args);
static inline void add_cs_detail(MCInst *MI, int /* arm_op_group */ op_group,
				 ...)
{
	if (!MI->flat_insn->detail)
		return;
	va_list args;
	va_start(args, op_group);
	ARM_add_cs_detail(MI, op_group, args);
	va_end(args);
}

void ARM_insert_detail_op_reg_at(MCInst *MI, unsigned index, arm_reg Reg,
				 cs_ac_type access);
void ARM_insert_detail_op_imm_at(MCInst *MI, unsigned index, int64_t Val,
				 cs_ac_type access);
void ARM_set_detail_op_reg(MCInst *MI, unsigned OpNum, arm_reg Reg);
void ARM_set_detail_op_sysop(MCInst *MI, int SysReg, arm_op_type type,
			     bool IsOutReg, uint8_t Mask, uint16_t Sysm);
void ARM_set_detail_op_imm(MCInst *MI, unsigned OpNum, arm_op_type ImmType,
			   int64_t Imm);
void ARM_set_detail_op_float(MCInst *MI, unsigned OpNum, uint64_t Imm);
void ARM_set_detail_op_mem(MCInst *MI, unsigned OpNum, bool is_index_reg,
			   int scale, uint64_t Val);
void ARM_set_detail_op_mem_offset(MCInst *MI, unsigned OpNum, uint64_t Val,
				  bool subtracted);
void ARM_set_detail_op_neon_lane(MCInst *MI, unsigned OpNum);

void ARM_check_updates_flags(MCInst *MI);

void ARM_setup_op(cs_arm_op *op);
void ARM_add_vector_data(MCInst *MI, arm_vectordata_type data_type);
void ARM_add_vector_size(MCInst *MI, unsigned size);

#endif // CS_ARM_MAPPING_H
