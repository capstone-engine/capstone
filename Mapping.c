/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
/*    Rot127 <unisono@quyllur.org>, 2022-2023 */

#include "Mapping.h"
#include "capstone/capstone.h"
#include "cs_priv.h"
#include "utils.h"

// create a cache for fast id lookup
static unsigned short *make_id2insn(const insn_map *insns, unsigned int size)
{
	// NOTE: assume that the max id is always put at the end of insns array
	unsigned short max_id = insns[size - 1].id;
	unsigned int i;

	unsigned short *cache =
		(unsigned short *)cs_mem_calloc(max_id + 1, sizeof(*cache));

	for (i = 1; i < size; i++)
		cache[insns[i].id] = i;

	return cache;
}

// look for @id in @insns, given its size in @max. first time call will update
// @cache. return 0 if not found
unsigned short insn_find(const insn_map *insns, unsigned int max,
			 unsigned int id, unsigned short **cache)
{
	if (id > insns[max - 1].id)
		return 0;

	if (*cache == NULL)
		*cache = make_id2insn(insns, max);

	return (*cache)[id];
}

// Gives the id for the given @name if it is saved in @map.
// Returns the id or -1 if not found.
int name2id(const name_map *map, int max, const char *name)
{
	CS_ASSERT_RET_VAL(map && name, -1);
	int i;

	for (i = 0; i < max; i++) {
		if (!map[i].name) {
			return -1;
		}
		if (!strcmp(map[i].name, name)) {
			return map[i].id;
		}
	}

	// nothing match
	return -1;
}

// Gives the name for the given @id if it is saved in @map.
// Returns the name or NULL if not found.
const char *id2name(const name_map *map, int max, const unsigned int id)
{
	int i;

	for (i = 0; i < max; i++) {
		if (map[i].id == id) {
			return map[i].name;
		}
	}

	// nothing match
	return NULL;
}

/// Adds a register to the implicit write register list.
/// It will not add the same register twice.
void map_add_implicit_write(MCInst *MI, uint32_t Reg)
{
	if (!MI->flat_insn->detail)
		return;

	uint16_t *regs_write = MI->flat_insn->detail->regs_write;
	for (int i = 0; i < MAX_IMPL_W_REGS; ++i) {
		if (i == MI->flat_insn->detail->regs_write_count) {
			regs_write[i] = Reg;
			MI->flat_insn->detail->regs_write_count++;
			return;
		}
		if (regs_write[i] == Reg)
			return;
	}
}

/// Adds a register to the implicit read register list.
/// It will not add the same register twice.
void map_add_implicit_read(MCInst *MI, uint32_t Reg)
{
	if (!MI->flat_insn->detail)
		return;

	uint16_t *regs_read = MI->flat_insn->detail->regs_read;
	for (int i = 0; i < MAX_IMPL_R_REGS; ++i) {
		if (i == MI->flat_insn->detail->regs_read_count) {
			regs_read[i] = Reg;
			MI->flat_insn->detail->regs_read_count++;
			return;
		}
		if (regs_read[i] == Reg)
			return;
	}
}

/// Removes a register from the implicit write register list.
void map_remove_implicit_write(MCInst *MI, uint32_t Reg)
{
	if (!MI->flat_insn->detail)
		return;

	uint16_t *regs_write = MI->flat_insn->detail->regs_write;
	bool shorten_list = false;
	for (int i = 0; i < MAX_IMPL_W_REGS; ++i) {
		if (shorten_list) {
			regs_write[i - 1] = regs_write[i];
		}
		if (i >= MI->flat_insn->detail->regs_write_count)
			return;

		if (regs_write[i] == Reg) {
			MI->flat_insn->detail->regs_write_count--;
			// The register should exist only once in the list.
			CS_ASSERT_RET(!shorten_list);
			shorten_list = true;
		}
	}
}

/// Copies the implicit read registers of @imap to @MI->flat_insn.
/// Already present registers will be preserved.
void map_implicit_reads(MCInst *MI, const insn_map *imap)
{
#ifndef CAPSTONE_DIET
	if (!MI->flat_insn->detail)
		return;

	cs_detail *detail = MI->flat_insn->detail;
	unsigned Opcode = MCInst_getOpcode(MI);
	unsigned i = 0;
	uint16_t reg = imap[Opcode].regs_use[i];
	while (reg != 0) {
		if (i >= MAX_IMPL_R_REGS ||
		    detail->regs_read_count >= MAX_IMPL_R_REGS) {
			printf("ERROR: Too many implicit read register defined in "
			       "instruction mapping.\n");
			return;
		}
		detail->regs_read[detail->regs_read_count++] = reg;
		if (i + 1 < MAX_IMPL_R_REGS) {
			// Select next one
			reg = imap[Opcode].regs_use[++i];
		}
	}
#endif // CAPSTONE_DIET
}

/// Copies the implicit write registers of @imap to @MI->flat_insn.
/// Already present registers will be preserved.
void map_implicit_writes(MCInst *MI, const insn_map *imap)
{
#ifndef CAPSTONE_DIET
	if (!MI->flat_insn->detail)
		return;

	cs_detail *detail = MI->flat_insn->detail;
	unsigned Opcode = MCInst_getOpcode(MI);
	unsigned i = 0;
	uint16_t reg = imap[Opcode].regs_mod[i];
	while (reg != 0) {
		if (i >= MAX_IMPL_W_REGS ||
		    detail->regs_write_count >= MAX_IMPL_W_REGS) {
			printf("ERROR: Too many implicit write register defined in "
			       "instruction mapping.\n");
			return;
		}
		detail->regs_write[detail->regs_write_count++] = reg;
		if (i + 1 < MAX_IMPL_W_REGS) {
			// Select next one
			reg = imap[Opcode].regs_mod[++i];
		}
	}
#endif // CAPSTONE_DIET
}

/// Adds a given group to @MI->flat_insn.
/// A group is never added twice.
void add_group(MCInst *MI, unsigned /* arch_group */ group)
{
#ifndef CAPSTONE_DIET
	if (!MI->flat_insn->detail)
		return;

	cs_detail *detail = MI->flat_insn->detail;
	if (detail->groups_count >= MAX_NUM_GROUPS) {
		printf("ERROR: Too many groups defined.\n");
		return;
	}
	for (int i = 0; i < detail->groups_count; ++i) {
		if (detail->groups[i] == group) {
			return;
		}
	}
	detail->groups[detail->groups_count++] = group;
#endif // CAPSTONE_DIET
}

/// Copies the groups from @imap to @MI->flat_insn.
/// Already present groups will be preserved.
void map_groups(MCInst *MI, const insn_map *imap)
{
#ifndef CAPSTONE_DIET
	if (!MI->flat_insn->detail)
		return;

	cs_detail *detail = MI->flat_insn->detail;
	unsigned Opcode = MCInst_getOpcode(MI);
	unsigned i = 0;
	uint16_t group = imap[Opcode].groups[i];
	while (group != 0) {
		if (detail->groups_count >= MAX_NUM_GROUPS) {
			printf("ERROR: Too many groups defined in instruction mapping.\n");
			return;
		}
		detail->groups[detail->groups_count++] = group;
		group = imap[Opcode].groups[++i];
	}
#endif // CAPSTONE_DIET
}

/// Returns the pointer to the supllementary information in
/// the instruction mapping table @imap or NULL in case of failure.
const void *map_get_suppl_info(MCInst *MI, const insn_map *imap)
{
#ifndef CAPSTONE_DIET
	if (!MI->flat_insn->detail)
		return NULL;

	unsigned Opcode = MCInst_getOpcode(MI);
	return &imap[Opcode].suppl_info;
#else
	return NULL;
#endif // CAPSTONE_DIET
}

// Search for the CS instruction id for the given @MC_Opcode in @imap.
// return -1 if none is found.
unsigned int find_cs_id(unsigned MC_Opcode, const insn_map *imap,
			unsigned imap_size)
{
	// binary searching since the IDs are sorted in order
	unsigned int left, right, m;
	unsigned int max = imap_size;

	right = max - 1;

	if (MC_Opcode < imap[0].id || MC_Opcode > imap[right].id)
		// not found
		return -1;

	left = 0;

	while (left <= right) {
		m = (left + right) / 2;
		if (MC_Opcode == imap[m].id) {
			return m;
		}

		if (MC_Opcode < imap[m].id)
			right = m - 1;
		else
			left = m + 1;
	}

	return -1;
}

/// Sets the Capstone instruction id which maps to the @MI opcode.
/// If no mapping is found the function returns and prints an error.
void map_cs_id(MCInst *MI, const insn_map *imap, unsigned int imap_size)
{
	unsigned int i = find_cs_id(MCInst_getOpcode(MI), imap, imap_size);
	if (i != -1) {
		MI->flat_insn->id = imap[i].mapid;
		return;
	}
	printf("ERROR: Could not find CS id for MCInst opcode: %d\n",
	       MCInst_getOpcode(MI));
	return;
}

/// Returns the operand type information from the
/// mapping table for instruction operands.
/// Only usable by `auto-sync` archs!
const cs_op_type mapping_get_op_type(MCInst *MI, unsigned OpNum,
				     const map_insn_ops *insn_ops_map,
				     size_t map_size)
{
	assert(MI);
	assert(MI->Opcode < map_size);
	assert(OpNum < sizeof(insn_ops_map[MI->Opcode].ops) /
			       sizeof(insn_ops_map[MI->Opcode].ops[0]));

	return insn_ops_map[MI->Opcode].ops[OpNum].type;
}

/// Returns the operand access flags from the
/// mapping table for instruction operands.
/// Only usable by `auto-sync` archs!
const cs_ac_type mapping_get_op_access(MCInst *MI, unsigned OpNum,
				       const map_insn_ops *insn_ops_map,
				       size_t map_size)
{
	assert(MI);
	assert(MI->Opcode < map_size);
	assert(OpNum < sizeof(insn_ops_map[MI->Opcode].ops) /
			       sizeof(insn_ops_map[MI->Opcode].ops[0]));

	cs_ac_type access = insn_ops_map[MI->Opcode].ops[OpNum].access;
	if (MCInst_opIsTied(MI, OpNum) || MCInst_opIsTying(MI, OpNum))
		access |= (access == CS_AC_READ) ? CS_AC_WRITE : CS_AC_READ;
	return access;
}

/// Returns the operand at detail->arch.operands[op_count + offset]
/// Or NULL if detail is not set.
#define DEFINE_get_detail_op(arch, ARCH) \
	cs_##arch##_op *ARCH##_get_detail_op(MCInst *MI, int offset) \
	{ \
		if (!MI->flat_insn->detail) \
			return NULL; \
		int OpIdx = MI->flat_insn->detail->arch.op_count + offset; \
		assert(OpIdx >= 0 && OpIdx < MAX_MC_OPS); \
		return &MI->flat_insn->detail->arch.operands[OpIdx]; \
	}

DEFINE_get_detail_op(arm, ARM);
DEFINE_get_detail_op(ppc, PPC);
DEFINE_get_detail_op(tricore, TriCore);
DEFINE_get_detail_op(aarch64, AArch64);
DEFINE_get_detail_op(alpha, Alpha);
DEFINE_get_detail_op(hppa, HPPA);
DEFINE_get_detail_op(loongarch, LoongArch);
DEFINE_get_detail_op(mips, Mips);
DEFINE_get_detail_op(riscv, RISCV);
DEFINE_get_detail_op(systemz, SystemZ);
DEFINE_get_detail_op(xtensa, Xtensa);
DEFINE_get_detail_op(bpf, BPF);
DEFINE_get_detail_op(arc, ARC);

/// Returns true if for this architecture the
/// alias operands should be filled.
/// TODO: Replace this with a proper option.
/// 			So it can be toggled between disas() calls.
bool map_use_alias_details(const MCInst *MI) {
	assert(MI);
	return (MI->csh->detail_opt & CS_OPT_ON) && !(MI->csh->detail_opt & CS_OPT_DETAIL_REAL);
}

/// Sets the setDetailOps flag to @p Val.
/// If detail == NULLit refuses to set the flag to true.
void map_set_fill_detail_ops(MCInst *MI, bool Val) {
	CS_ASSERT_RET(MI);
	if (!detail_is_set(MI)) {
		MI->fillDetailOps = false;
		return;
	}

	MI->fillDetailOps = Val;
}

/// Sets the instruction alias flags and the given alias id.
void map_set_is_alias_insn(MCInst *MI, bool Val, uint64_t Alias) {
	CS_ASSERT_RET(MI);
	MI->isAliasInstr = Val;
	MI->flat_insn->is_alias = Val;
	MI->flat_insn->alias_id = Alias;
}

static inline bool char_ends_mnem(const char c, cs_arch arch) {
	switch (arch) {
	default:
		return (!c || c == ' ' || c == '\t' || c == '.');
	case CS_ARCH_PPC:
		return (!c || c == ' ' || c == '\t');
  }
}

/// Sets an alternative id for some instruction.
/// Or -1 if it fails.
/// You must add (<ARCH>_INS_ALIAS_BEGIN + 1) to the id to get the real id.
void map_set_alias_id(MCInst *MI, const SStream *O, const name_map *alias_mnem_id_map, int map_size) {
	if (!MCInst_isAlias(MI))
		return;

	char alias_mnem[16] = { 0 };
	int i = 0, j = 0;
	const char *asm_str_buf = O->buffer;
	// Skip spaces and tabs
	while (is_blank_char(asm_str_buf[i])) {
		if (!asm_str_buf[i]) {
			MI->flat_insn->alias_id = -1;
			return;
		}
		++i;
	}
	for (; j < sizeof(alias_mnem) - 1; ++j, ++i) {
		if (char_ends_mnem(asm_str_buf[i], MI->csh->arch))
			break;
		alias_mnem[j] = asm_str_buf[i];
	}

	MI->flat_insn->alias_id = name2id(alias_mnem_id_map, map_size, alias_mnem);
}

/// Does a binary search over the given map and searches for @id.
/// If @id exists in @map, it sets @found to true and returns
/// the value for the @id.
/// Otherwise, @found is set to false and it returns UINT64_MAX.
///
/// Of course it assumes the map is sorted.
uint64_t enum_map_bin_search(const cs_enum_id_map *map, size_t map_len,
			     const char *id, bool *found)
{
	size_t l = 0;
	size_t r = map_len;
	size_t id_len = strlen(id);

	while (l <= r) {
		size_t m = (l + r) / 2;
		size_t j = 0;
		size_t i = 0;
		size_t entry_len = strlen(map[m].str);

		while (j < entry_len && i < id_len && id[i] == map[m].str[j]) {
			++j, ++i;
		}
		if (i == id_len && j == entry_len) {
			*found = true;
			return map[m].val;
		}

		if (id[i] < map[m].str[j]) {
			r = m - 1;
		} else if (id[i] > map[m].str[j]) {
			l = m + 1;
		}
		if ((m == 0 && id[i] < map[m].str[j]) || (l + r) / 2 >= map_len) {
			// Break before we go out of bounds.
			break;
		}
	}
	*found = false;
	return UINT64_MAX;
}

