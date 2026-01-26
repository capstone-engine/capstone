
#ifndef CS_RISCV_MAP_H
#define CS_RISCV_MAP_H

#include "../../include/capstone/capstone.h"
#include "../../cs_priv.h"

typedef enum {
#include "RISCVGenCSOpGroup.inc"
} riscv_op_group;

extern const insn_map *RISCV_insns;
extern const unsigned int RISCV_insn_count;

// given internal insn id, return public instruction info
void RISCV_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);

const char *RISCV_insn_name(csh handle, unsigned int id);

const char *RISCV_group_name(csh handle, unsigned int id);

const char *RISCV_reg_name(csh handle, unsigned int reg);

void RISCV_add_cs_detail_0(MCInst *MI, riscv_op_group opgroup, unsigned OpNum);

void RISCV_add_groups(MCInst *MI);

void RISCV_compact_operands(MCInst *MI);

void RISCV_add_missing_write_access(MCInst *MI);

// map instruction name to instruction ID
riscv_insn RISCV_map_insn(const char *name);

void RISCV_init(MCRegisterInfo *MRI);

#endif
