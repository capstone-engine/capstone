/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
/*    Rot127 <unisono@quyllur.org>, 2022-2023 */

#ifndef CS_MAPPING_H
#define CS_MAPPING_H

#if defined(CAPSTONE_HAS_OSXKERNEL)
#include <libkern/libkern.h>
#else
#include "include/capstone/capstone.h"
#include <stddef.h>
#endif
#include "cs_priv.h"
#include <assert.h>
#include <string.h>

// map instruction to its characteristics
typedef struct insn_map {
	unsigned short id; // The LLVM instruction id
	unsigned short mapid; // The Capstone instruction id
#ifndef CAPSTONE_DIET
	uint16_t regs_use[MAX_IMPL_R_REGS]; ///< list of implicit registers used by
		///< this instruction
	uint16_t regs_mod[MAX_IMPL_W_REGS]; ///< list of implicit registers modified
		///< by this instruction
	unsigned char groups
		[MAX_NUM_GROUPS]; ///< list of group this instruction belong to
	bool branch; // branch instruction?
	bool indirect_branch; // indirect branch instruction?
	union {
		ppc_suppl_info ppc;
		loongarch_suppl_info loongarch;
		aarch64_suppl_info aarch64;
		systemz_suppl_info systemz;
		arm_suppl_info arm;
		xtensa_suppl_info xtensa;
		sparc_suppl_info sparc;
	} suppl_info; // Supplementary information for each instruction.
#endif
} insn_map;

// look for @id in @m, given its size in @max. first time call will update
// @cache. return 0 if not found
unsigned short insn_find(const insn_map *m, unsigned int max, unsigned int id,
			 unsigned short **cache);

unsigned int find_cs_id(unsigned MC_Opcode, const insn_map *imap,
			unsigned imap_size);

#define MAX_NO_DATA_TYPES 16

///< A LLVM<->CS Mapping entry of an MCOperand.
typedef struct {
	uint8_t /* cs_op_type */ type; ///< Operand type (e.g.: reg, imm, mem)
	uint8_t /* cs_ac_type */ access; ///< The access type (read, write)
	/// List of op types. Terminated by CS_DATA_TYPE_LAST
	uint8_t /* cs_data_type */ dtypes[MAX_NO_DATA_TYPES];
} mapping_op;

#define MAX_NO_INSN_MAP_OPS 16

///< MCOperands of an instruction.
typedef struct {
	mapping_op
		ops[MAX_NO_INSN_MAP_OPS]; ///< NULL terminated array of insn_op.
} map_insn_ops;

/// Only usable by `auto-sync` archs!
const cs_op_type mapping_get_op_type(MCInst *MI, unsigned OpNum,
				     const map_insn_ops *insn_ops_map,
				     size_t map_size);

/// Only usable by `auto-sync` archs!
const cs_ac_type mapping_get_op_access(MCInst *MI, unsigned OpNum,
				       const map_insn_ops *insn_ops_map,
				       size_t map_size);

/// Macro for easier access of operand types from the map.
/// Assumes the istruction operands map is called "insn_operands"
/// Only usable by `auto-sync` archs!
#ifndef CAPSTONE_DIET
#define map_get_op_type(MI, OpNum) \
	mapping_get_op_type(MI, OpNum, (const map_insn_ops *)insn_operands, \
			    sizeof(insn_operands) / sizeof(insn_operands[0]))
#else
#define map_get_op_type(MI, OpNum) CS_OP_INVALID
#endif

/// Macro for easier access of operand access flags from the map.
/// Assumes the istruction operands map is called "insn_operands"
/// Only usable by `auto-sync` archs!
#ifndef CAPSTONE_DIET
#define map_get_op_access(MI, OpNum) \
	mapping_get_op_access(MI, OpNum, (const map_insn_ops *)insn_operands, \
			      sizeof(insn_operands) / \
				      sizeof(insn_operands[0]))
#else
#define map_get_op_access(MI, OpNum) CS_AC_INVALID
#endif

///< Map for ids to their string
typedef struct name_map {
	unsigned int id;
	const char *name;
} name_map;

// map a name to its ID
// return 0 if not found
int name2id(const name_map *map, int max, const char *name);

// map ID to a name
// return NULL if not found
const char *id2name(const name_map *map, int max, const unsigned int id);

void map_add_implicit_write(MCInst *MI, uint32_t Reg);
void map_add_implicit_read(MCInst *MI, uint32_t Reg);
void map_remove_implicit_write(MCInst *MI, uint32_t Reg);

void map_implicit_reads(MCInst *MI, const insn_map *imap);

void map_implicit_writes(MCInst *MI, const insn_map *imap);

void add_group(MCInst *MI, unsigned /* arch_group */ group);

void map_groups(MCInst *MI, const insn_map *imap);

void map_cs_id(MCInst *MI, const insn_map *imap, unsigned int imap_size);

const void *map_get_suppl_info(MCInst *MI, const insn_map *imap);

#define DECL_get_detail_op(arch, ARCH) \
	cs_##arch##_op *ARCH##_get_detail_op(MCInst *MI, int offset);

DECL_get_detail_op(arm, ARM);
DECL_get_detail_op(ppc, PPC);
DECL_get_detail_op(tricore, TriCore);
DECL_get_detail_op(aarch64, AArch64);
DECL_get_detail_op(alpha, Alpha);
DECL_get_detail_op(hppa, HPPA);
DECL_get_detail_op(loongarch, LoongArch);
DECL_get_detail_op(mips, Mips);
DECL_get_detail_op(riscv, RISCV);
DECL_get_detail_op(systemz, SystemZ);
DECL_get_detail_op(xtensa, Xtensa);
DECL_get_detail_op(bpf, BPF);
DECL_get_detail_op(arc, ARC);
DECL_get_detail_op(sparc, Sparc);

/// Increments the detail->arch.op_count by one.
#define DEFINE_inc_detail_op_count(arch, ARCH) \
	static inline void ARCH##_inc_op_count(MCInst *MI) \
	{ \
		MI->flat_insn->detail->arch.op_count++; \
	}

/// Decrements the detail->arch.op_count by one.
#define DEFINE_dec_detail_op_count(arch, ARCH) \
	static inline void ARCH##_dec_op_count(MCInst *MI) \
	{ \
		MI->flat_insn->detail->arch.op_count--; \
	}

DEFINE_inc_detail_op_count(arm, ARM);
DEFINE_dec_detail_op_count(arm, ARM);
DEFINE_inc_detail_op_count(ppc, PPC);
DEFINE_dec_detail_op_count(ppc, PPC);
DEFINE_inc_detail_op_count(tricore, TriCore);
DEFINE_dec_detail_op_count(tricore, TriCore);
DEFINE_inc_detail_op_count(aarch64, AArch64);
DEFINE_dec_detail_op_count(aarch64, AArch64);
DEFINE_inc_detail_op_count(alpha, Alpha);
DEFINE_dec_detail_op_count(alpha, Alpha);
DEFINE_inc_detail_op_count(hppa, HPPA);
DEFINE_dec_detail_op_count(hppa, HPPA);
DEFINE_inc_detail_op_count(loongarch, LoongArch);
DEFINE_dec_detail_op_count(loongarch, LoongArch);
DEFINE_inc_detail_op_count(mips, Mips);
DEFINE_dec_detail_op_count(mips, Mips);
DEFINE_inc_detail_op_count(riscv, RISCV);
DEFINE_dec_detail_op_count(riscv, RISCV);
DEFINE_inc_detail_op_count(systemz, SystemZ);
DEFINE_dec_detail_op_count(systemz, SystemZ);
DEFINE_inc_detail_op_count(xtensa, Xtensa);
DEFINE_dec_detail_op_count(xtensa, Xtensa);
DEFINE_inc_detail_op_count(bpf, BPF);
DEFINE_dec_detail_op_count(bpf, BPF);
DEFINE_inc_detail_op_count(arc, ARC);
DEFINE_dec_detail_op_count(arc, ARC);
DEFINE_inc_detail_op_count(sparc, Sparc);
DEFINE_dec_detail_op_count(sparc, Sparc);

/// Returns true if a memory operand is currently edited.
static inline bool doing_mem(const MCInst *MI)
{
	return MI->csh->doing_mem;
}

/// Sets the doing_mem flag to @status.
static inline void set_doing_mem(const MCInst *MI, bool status)
{
	MI->csh->doing_mem = status;
}

/// Returns detail->arch
#define DEFINE_get_arch_detail(arch, ARCH) \
	static inline cs_##arch *ARCH##_get_detail(const MCInst *MI) \
	{ \
		assert(MI && MI->flat_insn && MI->flat_insn->detail); \
		return &MI->flat_insn->detail->arch; \
	}

DEFINE_get_arch_detail(arm, ARM);
DEFINE_get_arch_detail(ppc, PPC);
DEFINE_get_arch_detail(tricore, TriCore);
DEFINE_get_arch_detail(aarch64, AArch64);
DEFINE_get_arch_detail(alpha, Alpha);
DEFINE_get_arch_detail(hppa, HPPA);
DEFINE_get_arch_detail(loongarch, LoongArch);
DEFINE_get_arch_detail(mips, Mips);
DEFINE_get_arch_detail(riscv, RISCV);
DEFINE_get_arch_detail(arc, ARC);
DEFINE_get_arch_detail(systemz, SystemZ);
DEFINE_get_arch_detail(xtensa, Xtensa);
DEFINE_get_arch_detail(bpf, BPF);
DEFINE_get_arch_detail(sparc, Sparc);

#define DEFINE_check_safe_inc(Arch, ARCH) \
	static inline void Arch##_check_safe_inc(const MCInst *MI) \
	{ \
		assert(Arch##_get_detail(MI)->op_count + 1 < \
		       NUM_##ARCH##_OPS); \
	}

DEFINE_check_safe_inc(ARM, ARM);
DEFINE_check_safe_inc(PPC, PPC);
DEFINE_check_safe_inc(TriCore, TRICORE);
DEFINE_check_safe_inc(AArch64, AARCH64);
DEFINE_check_safe_inc(Alpha, ALPHA);
DEFINE_check_safe_inc(HPPA, HPPA);
DEFINE_check_safe_inc(LoongArch, LOONGARCH);
DEFINE_check_safe_inc(RISCV, RISCV);
DEFINE_check_safe_inc(SystemZ, SYSTEMZ);
DEFINE_check_safe_inc(Mips, MIPS);
DEFINE_check_safe_inc(BPF, BPF);
DEFINE_check_safe_inc(ARC, ARC);
DEFINE_check_safe_inc(Sparc, SPARC);

static inline bool detail_is_set(const MCInst *MI)
{
	assert(MI && MI->flat_insn);
	return MI->flat_insn->detail != NULL && MI->csh->detail_opt & CS_OPT_ON;
}

static inline cs_detail *get_detail(const MCInst *MI)
{
	assert(MI && MI->flat_insn);
	return MI->flat_insn->detail;
}

/// Returns if the given instruction is an alias instruction.
#define RETURN_IF_INSN_IS_ALIAS(MI) \
	do { \
		if (MI->isAliasInstr) \
			return; \
	} while (0)

void map_set_fill_detail_ops(MCInst *MI, bool Val);

static inline bool map_fill_detail_ops(MCInst *MI)
{
	assert(MI);
	return MI->fillDetailOps;
}

void map_set_is_alias_insn(MCInst *MI, bool Val, uint64_t Alias);

bool map_use_alias_details(const MCInst *MI);

void map_set_alias_id(MCInst *MI, const SStream *O,
		      const name_map *alias_mnem_id_map, int map_size);

/// Mapping from Capstone enumeration identifiers and their values.
///
/// This map MUST BE sorted to allow binary searches.
/// Please always ensure the map is sorted after you added a value.
///
/// You can sort the map with Python.
/// Copy the map into a file and run:
///
/// ```python
/// with open("/tmp/file_with_map_entries") as f:
///     text = f.readlines()
///
/// text.sort()
/// print(''.join(text))
/// ```
typedef struct {
	const char *str; ///< The name of the enumeration identifier
	uint64_t val; ///< The value of the identifier
} cs_enum_id_map;

uint64_t enum_map_bin_search(const cs_enum_id_map *map, size_t map_len,
			     const char *id, bool *found);

#endif // CS_MAPPING_H
