/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifndef CS_PRIV_H
#define CS_PRIV_H

#ifdef CAPSTONE_DEBUG
#include <assert.h>
#endif
#include <capstone/capstone.h>

#include "MCInst.h"
#include "SStream.h"

typedef void (*Printer_t)(MCInst *MI, SStream *OS, void *info);

// function to be called after Printer_t
// this is the best time to gather insn's characteristics
typedef void (*PostPrinter_t)(csh handle, cs_insn *, SStream *mnem, MCInst *mci);

typedef bool (*Disasm_t)(csh handle, const uint8_t *code, size_t code_len, MCInst *instr, uint16_t *size, uint64_t address, void *info);

typedef const char *(*GetName_t)(csh handle, unsigned int id);

typedef void (*GetID_t)(cs_struct *h, cs_insn *insn, unsigned int id);

// return registers accessed by instruction
typedef void (*GetRegisterAccess_t)(const cs_insn *insn,
		cs_regs regs_read, uint8_t *regs_read_count,
		cs_regs regs_write, uint8_t *regs_write_count);

// for ARM only
typedef struct ARM_ITBlock {
	unsigned char ITStates[8];
	unsigned int size;
} ARM_ITBlock;

typedef struct ARM_VPTBlock {
	unsigned char VPTStates[8];
	unsigned int size;
} ARM_VPTBlock;

// Customize mnemonic for instructions with alternative name.
struct customized_mnem {
	// ID of instruction to be customized.
	unsigned int id;
	// Customized instruction mnemonic.
	char mnemonic[CS_MNEMONIC_SIZE];
};

struct insn_mnem {
	struct customized_mnem insn;
	struct insn_mnem *next;	// linked list of customized mnemonics
};

struct cs_struct {
	cs_arch arch;
	cs_mode mode;
	Printer_t printer;	// asm printer
	void *printer_info; // aux info for printer
	Disasm_t disasm;	// disassembler
	void *getinsn_info; // auxiliary info for printer
	GetName_t reg_name;
	GetName_t insn_name;
	GetName_t group_name;
	GetID_t insn_id;
	PostPrinter_t post_printer;
	cs_err errnum;
	ARM_ITBlock ITBlock;	// for Arm only
	ARM_VPTBlock VPTBlock;  // for ARM only
	bool PrintBranchImmAsAddress;
	bool ShowVSRNumsAsVR;
	cs_opt_value detail_opt, imm_unsigned;
	int syntax;	// asm syntax for simple printer such as ARM, Mips & PPC
	bool doing_mem;	// handling memory operand in InstPrinter code
	bool doing_SME_Index; // handling a SME instruction that has index
	unsigned short *insn_cache;	// index caching for mapping.c
	bool skipdata;	// set this to True if we skip data when disassembling
	uint8_t skipdata_size;	// how many bytes to skip
	cs_opt_skipdata skipdata_setup;	// user-defined skipdata setup
	const uint8_t *regsize_map;	// map to register size (x86-only for now)
	GetRegisterAccess_t reg_access;
	struct insn_mnem *mnem_list;	// linked list of customized instruction mnemonic
	uint32_t LITBASE; ///< The LITBASE register content. Bit 0 (LSB) indicatess if it is set. Bit[23:8] are the literal base address.
};

#define MAX_ARCH CS_ARCH_MAX

// Returns a bool (0 or 1) whether big endian is enabled for a mode
#define MODE_IS_BIG_ENDIAN(mode) (((mode) & CS_MODE_BIG_ENDIAN) != 0)

/// Returns true of the 16bit flag is set.
#define IS_16BIT(mode) ((mode & CS_MODE_16) != 0)
/// Returns true of the 32bit flag is set.
#define IS_32BIT(mode) ((mode & CS_MODE_32) != 0)
/// Returns true of the 64bit flag is set.
#define IS_64BIT(mode) ((mode & CS_MODE_64) != 0)

extern cs_malloc_t cs_mem_malloc;
extern cs_calloc_t cs_mem_calloc;
extern cs_realloc_t cs_mem_realloc;
extern cs_free_t cs_mem_free;
extern cs_vsnprintf_t cs_vsnprintf;

/// By defining CAPSTONE_DEBUG assertions can be used.
/// For the release build the @expr is not included.
#ifdef CAPSTONE_DEBUG
#define CS_ASSERT(expr) assert(expr)
#else
#define CS_ASSERT(expr)
#endif

/// If compiled in debug mode it will assert(@expr).
/// In the release build it will check the @expr and return @val if false.
#ifdef CAPSTONE_DEBUG
#define CS_ASSERT_RET_VAL(expr, val) assert(expr)
#else
#define CS_ASSERT_RET_VAL(expr, val) \
do { \
	if (!(expr)) { \
		fprintf(stderr, "Hit assert: " #expr "\n"); \
		return val; \
	} \
} while(0)
#endif

/// If compiled in debug mode it will assert(@expr).
/// In the release build it will check the @expr and return if false.
#ifdef CAPSTONE_DEBUG
#define CS_ASSERT_RET(expr) assert(expr)
#else
#define CS_ASSERT_RET(expr) \
do { \
	if (!(expr)) { \
		fprintf(stderr, "Hit assert: " #expr "\n"); \
		return; \
	} \
} while(0)
#endif

#endif
