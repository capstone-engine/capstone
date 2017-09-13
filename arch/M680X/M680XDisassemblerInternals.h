/* Capstone Disassembly Engine */
/* M680X Backend by Wolfgang Schwotzer <wolfgang.schwotzer@gmx.net> 2017 */

#ifndef CS_M680XDISASSEMBLERINTERNALS_H
#define CS_M680XDISASSEMBLERINTERNALS_H

#include "../../MCInst.h"
#include "../../include/capstone/m680x.h"

typedef enum e_cpu_type {
	M680X_CPU_TYPE_INVALID,
	M680X_CPU_TYPE_6800,	// M680X Motorola 6800,6802 mode
	M680X_CPU_TYPE_6801,	// M680X Motorola 6801,6803 mode
	M680X_CPU_TYPE_6805,	// M680X Motorola 6805 mode
	M680X_CPU_TYPE_6809,	// M680X Motorola 6809 mode
	M680X_CPU_TYPE_6301,	// M680X Hitachi HD6301,HD6303 mode
	M680X_CPU_TYPE_6309,	// M680X Hitachi HD6309 mode
	M680X_CPU_TYPE_ENDING,
} e_cpu_type;

struct inst_page0;
struct inst_pageX;

typedef struct {
	const struct inst_page1 *inst_page1_table;
	const struct inst_pageX *inst_overlay_table[2];
	unsigned int overlay_table_size[2];
	uint8_t pageX_prefix[2];
	const struct inst_pageX *inst_pageX_table[2];
	unsigned int pageX_table_size[2];
	const bool *reg_valid;
} cpu_tables;

/* Private, For internal use only */
typedef struct m680x_info {
	const uint8_t *code;	// code buffer
	uint32_t size;		// byte size of code
	uint16_t offset;	// address offset of first byte in code buffer
	e_cpu_type cpu_type;	// The CPU type to be used for disassembling
	cs_m680x m680x;		// M680X specific properties
	cpu_tables cpu;
	m680x_insn insn;	// Instruction ID
	uint8_t insn_size;	// byte size of instruction
} m680x_info;

extern cs_err M680X_disassembler_init(cs_struct *ud);
extern cs_err M680X_instprinter_init(cs_struct *ud);

#endif

