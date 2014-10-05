/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifndef CS_PRIV_H
#define CS_PRIV_H

#include <capstone.h>

#include "MCInst.h"
#include "SStream.h"

typedef void (*Printer_t)(MCInst *MI, SStream *OS, void *info);

// function to be called after Printer_t
// this is the best time to gather insn's characteristics
typedef void (*PostPrinter_t)(csh handle, cs_insn *, char *mnem, MCInst *mci);

typedef bool (*Disasm_t)(csh handle, const uint8_t *code, size_t code_len, MCInst *instr, uint16_t *size, uint64_t address, void *info);

typedef const char *(*GetName_t)(csh handle, unsigned int id);

typedef void (*GetID_t)(cs_struct *h, cs_insn *insn, unsigned int id);

// return register name, given register ID
typedef char *(*GetRegisterName_t)(unsigned RegNo);

// for ARM only
typedef struct ARM_ITStatus {
	unsigned char ITStates[128];	// FIXME
	unsigned int size;
} ARM_ITStatus;

struct cs_struct {
	cs_arch arch;
	cs_mode mode;
	Printer_t printer;	// asm printer
	void *printer_info; // aux info for printer
	Disasm_t disasm;	// disassembler
	void *getinsn_info; // auxiliary info for printer
	bool big_endian;
	GetName_t reg_name;
	GetName_t insn_name;
	GetName_t group_name;
	GetID_t insn_id;
	PostPrinter_t post_printer;
	cs_err errnum;
	ARM_ITStatus ITBlock;	// for Arm only
	cs_opt_value detail;
	int syntax;	// asm syntax for simple printer such as ARM, Mips & PPC
	bool doing_mem;	// handling memory operand in InstPrinter code
	unsigned short *insn_cache;	// index caching for mapping.c
	GetRegisterName_t get_regname;
	bool skipdata;	// set this to True if we skip data when disassembling
	uint8_t skipdata_size;	// how many bytes to skip
	cs_opt_skipdata skipdata_setup;	// user-defined skipdata setup
	uint8_t *regsize_map;	// map to register size (x86-only for now)
};

#define MAX_ARCH 8

// constructor initialization for all archs
extern cs_err (*arch_init[MAX_ARCH]) (cs_struct *);

// support cs_option() for all archs
extern cs_err (*arch_option[MAX_ARCH]) (cs_struct*, cs_opt_type, size_t value);

// deinitialized functions: to be called when cs_close() is called
extern void (*arch_destroy[MAX_ARCH]) (cs_struct*);

extern unsigned int all_arch;

extern cs_malloc_t cs_mem_malloc;
extern cs_calloc_t cs_mem_calloc;
extern cs_realloc_t cs_mem_realloc;
extern cs_free_t cs_mem_free;
extern cs_vsnprintf_t cs_vsnprintf;

#endif
