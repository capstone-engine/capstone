/* Capstone Disassembly Engine */
/* M68K Backend by Daniel Collin <daniel@collin.com> 2015 */

#ifndef CS_M68KINSTPRINTER_H
#define CS_M68KINSTPRINTER_H

#include <stdint.h>

#include "capstone/capstone.h"
#include "../../MCRegisterInfo.h"
#include "../../MCInst.h"

struct SStream;

void M68K_init(MCRegisterInfo *MRI);

void M68K_printInst(MCInst* MI, struct SStream* O, void* Info);
bool M68K_getInstruction(csh ud, const uint8_t* code, size_t code_len, MCInst* instr, uint16_t* size, uint64_t address, void* info);
const char* M68K_reg_name(csh handle, unsigned int reg);
void M68K_get_insn_id(cs_struct* h, cs_insn* insn, unsigned int id);
const char *M68K_insn_name(csh handle, unsigned int id);
const char* M68K_group_name(csh handle, unsigned int id);
void M68K_post_printer(csh handle, cs_insn* flat_insn, char* insn_asm, MCInst* mci);

#endif

