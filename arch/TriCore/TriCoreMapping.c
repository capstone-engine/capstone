/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifdef CAPSTONE_HAS_TRICORE

#include <stdio.h> // debug
#include <string.h>

#include "../../utils.h"

#include "TriCoreMapping.h"

#define GET_INSTRINFO_ENUM
#include "TriCoreGenInstrInfo.inc"

#ifndef CAPSTONE_DIET
static name_map reg_name_maps[] = {
    {TriCore_REG_INVALID, NULL},

    {TriCore_REG_D0, "d0"},
    {TriCore_REG_D1, "d1"},
    {TriCore_REG_D2, "d2"},
    {TriCore_REG_D3, "d3"},
    {TriCore_REG_D4, "d4"},
    {TriCore_REG_D5, "d5"},
    {TriCore_REG_D6, "d6"},
    {TriCore_REG_D7, "d7"},
    {TriCore_REG_D8, "d8"},
    {TriCore_REG_D9, "d9"},
    {TriCore_REG_D10, "d10"},
    {TriCore_REG_D11, "d11"},
    {TriCore_REG_D12, "d12"},
    {TriCore_REG_D13, "d13"},
    {TriCore_REG_D14, "d14"},
    {TriCore_REG_D15, "d15"},
    {TriCore_REG_A0, "a0"},
    {TriCore_REG_A1, "a1"},
    {TriCore_REG_A2, "a2"},
    {TriCore_REG_A3, "a3"},
    {TriCore_REG_A4, "a4"},
    {TriCore_REG_A5, "a5"},
    {TriCore_REG_A6, "a6"},
    {TriCore_REG_A7, "a7"},
    {TriCore_REG_A8, "a8"},
    {TriCore_REG_A9, "a9"},
    {TriCore_REG_A10, "a10"},
    {TriCore_REG_A11, "a11"},
    {TriCore_REG_A12, "a12"},
    {TriCore_REG_A13, "a13"},
    {TriCore_REG_A14, "a14"},
    {TriCore_REG_A15, "a15"},
    {TriCore_REG_E0, "e0"},
    {TriCore_REG_E2, "e2"},
    {TriCore_REG_E4, "e4"},
    {TriCore_REG_E6, "e6"},
    {TriCore_REG_E8, "e8"},
    {TriCore_REG_E10, "e10"},
    {TriCore_REG_E12, "e12"},
    {TriCore_REG_E14, "e14"},

    // control registers
    {TriCore_REG_PSW, "psw"},
    {TriCore_REG_PCXI, "pcxi"},
    {TriCore_REG_PC, "pc"},
    {TriCore_REG_FCX, "fcx"},
};
#endif

const char *TriCore_reg_name(csh handle, unsigned int reg)
{
#ifndef CAPSTONE_DIET
  if (reg >= TriCore_REG_ENDING)
    return NULL;

  return reg_name_maps[reg].name;
#else
  return NULL;
#endif
}

static insn_map insns[] = {
    // dummy item
    {0,
     0,
#ifndef CAPSTONE_DIET
     {0},
     {0},
     {0},
     0,
     0
#endif
    },
#include "./gen/TriCoreGenCSMappingInsn.inc"
};

// given internal insn id, return public instruction info
void TriCore_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
  unsigned short i;

  i = insn_find(insns, ARR_SIZE(insns), id, &h->insn_cache);
  if (i != 0) {
    insn->id = insns[i].mapid;

    if (h->detail) {
#ifndef CAPSTONE_DIET
      memcpy(insn->detail->regs_read, insns[i].regs_use,
	     sizeof(insns[i].regs_use));
      insn->detail->regs_read_count =
	  (uint8_t)count_positive(insns[i].regs_use);

      memcpy(insn->detail->regs_write, insns[i].regs_mod,
	     sizeof(insns[i].regs_mod));
      insn->detail->regs_write_count =
	  (uint8_t)count_positive(insns[i].regs_mod);

      memcpy(insn->detail->groups, insns[i].groups, sizeof(insns[i].groups));
      insn->detail->groups_count = (uint8_t)count_positive(insns[i].groups);

      if (insns[i].branch || insns[i].indirect_branch) {
	// this insn also belongs to JUMP group. add JUMP group
	insn->detail->groups[insn->detail->groups_count] = TriCore_GRP_JUMP;
	insn->detail->groups_count++;
      }
#endif
    }
  }
}

#ifndef CAPSTONE_DIET

static const char *insn_names[] = {
		NULL,
#include "./gen/TriCoreGenCSMappingInsnName.inc"
};

// special alias insn
static name_map alias_insn_names[] = {{0, NULL}};
#endif

const char *TriCore_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
  unsigned int i;

  if (id >= TriCore_INS_ENDING)
    return NULL;

  // handle special alias first
  for (i = 0; i < ARR_SIZE(alias_insn_names); i++) {
    if (alias_insn_names[i].id == id)
      return alias_insn_names[i].name;
  }

  return insn_names[id];
#else
  return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static name_map group_name_maps[] = {
    {TriCore_GRP_INVALID, NULL},
    {TriCore_GRP_JUMP, "jump"},
};
#endif

const char *TriCore_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
  if (id >= TriCore_GRP_ENDING)
    return NULL;

  return group_name_maps[id].name;
#else
  return NULL;
#endif
}

// map internal raw register to 'public' register
tricore_reg TriCore_map_register(unsigned int r)
{
  static unsigned int map[] = {
      0,
      TriCore_REG_FCX,
      TriCore_REG_PC,
      TriCore_REG_PCXI,
      TriCore_REG_PSW,
      TriCore_REG_A0,
      TriCore_REG_A1,
      TriCore_REG_A2,
      TriCore_REG_A3,
      TriCore_REG_A4,
      TriCore_REG_A5,
      TriCore_REG_A6,
      TriCore_REG_A7,
      TriCore_REG_A8,
      TriCore_REG_A9,
      TriCore_REG_A10,
      TriCore_REG_A11,
      TriCore_REG_A12,
      TriCore_REG_A13,
      TriCore_REG_A14,
      TriCore_REG_A15,
      TriCore_REG_D0,
      TriCore_REG_D1,
      TriCore_REG_D2,
      TriCore_REG_D3,
      TriCore_REG_D4,
      TriCore_REG_D5,
      TriCore_REG_D6,
      TriCore_REG_D7,
      TriCore_REG_D8,
      TriCore_REG_D9,
      TriCore_REG_D10,
      TriCore_REG_D11,
      TriCore_REG_D12,
      TriCore_REG_D13,
      TriCore_REG_D14,
      TriCore_REG_D15,
      TriCore_REG_E0,
      TriCore_REG_E2,
      TriCore_REG_E4,
      TriCore_REG_E6,
      TriCore_REG_E8,
      TriCore_REG_E10,
      TriCore_REG_E12,
      TriCore_REG_E14,
  };

  if (r < ARR_SIZE(map))
    return map[r];

  // cannot find this register
  return 0;
}

#endif
