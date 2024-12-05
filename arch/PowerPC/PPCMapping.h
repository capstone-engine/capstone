/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifndef CS_PPC_MAP_H
#define CS_PPC_MAP_H

#include "../../cs_priv.h"
#include "../../MCDisassembler.h"
#include "capstone/capstone.h"

typedef enum {
#include "PPCGenCSOpGroup.inc"
} ppc_op_group;

void PPC_init_mri(MCRegisterInfo *MRI);

void PPC_init_cs_detail(MCInst *MI);

// return name of register in friendly string
const char *PPC_reg_name(csh handle, unsigned int reg);

void PPC_printer(MCInst *MI, SStream *O, void * /* MCRegisterInfo* */ info);
bool PPC_getInstruction(csh handle, const uint8_t *code, size_t code_len,
			MCInst *instr, uint16_t *size, uint64_t address,
			void *info);

// given internal insn id, return public instruction info
void PPC_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);

const char *PPC_insn_name(csh handle, unsigned int id);
const char *PPC_group_name(csh handle, unsigned int id);

typedef struct {
	unsigned int id; // instruction id
	const char *mnem;
} ppc_alias_id;

void PPC_set_mem_access(MCInst *MI, bool status);
static inline void set_mem_access(MCInst *MI, bool status)
{
	PPC_set_mem_access(MI, status);
}

// map internal raw register to 'public' register
ppc_reg PPC_map_register(unsigned int r);

bool PPC_getFeatureBits(unsigned int mode, unsigned int feature);

void PPC_add_cs_detail_0(MCInst *MI, ppc_op_group op_group, unsigned OpNo);
void PPC_add_cs_detail_1(MCInst *MI, ppc_op_group op_group, unsigned OpNo, const char *Modifier);

void PPC_set_detail_op_reg(MCInst *MI, unsigned OpNum, ppc_reg Reg);
void PPC_set_detail_op_imm(MCInst *MI, unsigned OpNum, int64_t Imm);
void PPC_set_detail_op_mem(MCInst *MI, unsigned OpNum, uint64_t Val,
			   bool is_off_reg);

void PPC_insert_detail_op_imm_at(MCInst *MI, unsigned index, int64_t Val,
				 cs_ac_type access);

void PPC_setup_op(cs_ppc_op *op);

void PPC_check_updates_cr0(MCInst *MI);
void PPC_set_instr_map_data(MCInst *MI, const uint8_t *Bytes, size_t BytesLen);

#endif
