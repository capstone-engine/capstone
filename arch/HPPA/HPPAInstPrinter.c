/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev  <sibirtsevdl@gmail.com>, 2023 */

#ifdef CAPSTONE_HAS_HPPA

#include <capstone/platform.h>

#include "HPPAInstPrinter.h"
#include "HPPAMapping.h"


static void set_op_imm(cs_hppa *hppa, uint64_t val)
{
	cs_hppa_op *op = &hppa->operands[hppa->op_count++];
	op->type = HPPA_OP_IMM;
	op->imm = val;
}

static void set_op_reg(cs_hppa *hppa, uint64_t val, cs_ac_type access)
{
	cs_hppa_op *op = &hppa->operands[hppa->op_count++];
	op->type = HPPA_OP_REG;
	op->reg = val;
	op->access = access;
}

static void set_op_idx_reg(cs_hppa *hppa, uint64_t reg)
{
	cs_hppa_op *op = &hppa->operands[hppa->op_count++];
	op->type = HPPA_OP_IDX_REG;
	op->reg = reg;
	op->access = CS_AC_READ;
}

static void set_op_disp(cs_hppa *hppa, uint64_t val)
{
	cs_hppa_op *op = &hppa->operands[hppa->op_count++];
	op->type = HPPA_OP_DISP;
	op->imm = val;
}

static void set_op_target(cs_hppa *hppa, uint64_t val)
{
	cs_hppa_op *op = &hppa->operands[hppa->op_count++];
	op->type = HPPA_OP_TARGET;
	op->imm = val;
}

static void set_op_mem(cs_hppa *hppa, uint32_t base, uint32_t space, cs_ac_type base_access)
{
	cs_hppa_op *op = &hppa->operands[hppa->op_count++];
	op->type = HPPA_OP_MEM;
	op->mem.base = base;
	op->mem.space = space;
	op->mem.base_access = base_access;
}

struct pa_insn_fmt
{
    unsigned long int match;
    unsigned long int mask;
    const char *format;
};

/* HPPA instruction formats (access)
   i - imm arguments
   R - read access register
   W - write access register
   w - read + write access register
   r - index register (read only)
   T - offset (pc relative)
   o - displacement (imm)
   0 - register with unknown access (in undocumented instructions)
   Y - %sr0,%r31 -- implicit target of be,l instruction
*/

static const struct pa_insn_fmt pa_formats[] = 
{
	{ 0x34000000, 0xffe00000, "iW" },
	{ 0x34000000, 0xffe0c000, "iW" },

	{ 0xec000000, 0xfc000000, "iRT" },
	{ 0x84000000, 0xf4000000, "iRT" },
	{ 0x84000000, 0xfc000000, "iRT" },

	{ 0x8c000000, 0xfc000000, "iRT" },
	{ 0x9c000000, 0xdc000000, "RRT" },
	{ 0x80000000, 0xf4000000, "RRT" },
	{ 0x80000000, 0xfc000000, "RRT" },

	{ 0x88000000, 0xfc000000, "RRT" },
	{ 0xa0000000, 0xf4000000, "RwT" },
	{ 0xa0000000, 0xfc000000, "RwT" },

	{ 0xa8000000, 0xfc000000, "RwT" },
	{ 0xa4000000, 0xf4000000, "iwT" },
	{ 0xa4000000, 0xfc000000, "iwT" },

	{ 0xac000000, 0xfc000000, "iwT" },
	{ 0x08000240, 0xffffffff, "" },
	{ 0x08000240, 0xffe0ffe0, "RW" },
	{ 0x01601840, 0xffe0ffff, "R" },

	{ 0x0c0000c0, 0xfc00d3c0, "r(R)W" },
	{ 0x0c0000c0, 0xfc0013c0, "r(RR)W" },
	{ 0x0c0010e0, 0xfc1ff3e0, "o(R)W" },
	{ 0x0c0010e0, 0xfc1f33e0, "o(RR)W" },
	{ 0x0c0010c0, 0xfc00d3c0, "o(b)W" },
	{ 0x0c0010c0, 0xfc0013c0, "o(Rb)W" },
	{ 0x50000000, 0xfc000002, "o(b)W" },
	{ 0x50000000, 0xfc00c002, "o(b)W" },
	{ 0x50000000, 0xfc000002, "o(Rb)W" },
	{ 0x0c000080, 0xfc00dfc0, "r(R)W" },
	{ 0x0c000080, 0xfc001fc0, "r(RR)W" },
	{ 0x0c000080, 0xfc00d3c0, "r(R)W" },
	{ 0x0c000080, 0xfc0013c0, "r(RR)W" },
	{ 0x0c0010a0, 0xfc1ff3e0, "o(R)W" },
	{ 0x0c0010a0, 0xfc1f33e0, "o(RR)W" },
	{ 0x0c001080, 0xfc00dfc0, "o(b)W" },
	{ 0x0c001080, 0xfc001fc0, "o(Rb)W" },
	{ 0x0c001080, 0xfc00d3c0, "o(b)W" },
	{ 0x0c001080, 0xfc0013c0, "o(Rb)W" },
	{ 0x4c000000, 0xfc000000, "o(b)W" },
	{ 0x5c000004, 0xfc000006, "o(b)W" },
	{ 0x48000000, 0xfc000000, "o(R)W" },
	{ 0x5c000004, 0xfc00c006, "o(b)W" },
	{ 0x5c000004, 0xfc000006, "o(Rb)W" },
	{ 0x4c000000, 0xfc00c000, "o(b)W" },
	{ 0x4c000000, 0xfc000000, "o(Rb)W" },
	{ 0x48000000, 0xfc00c000, "o(R)W" },
	{ 0x48000000, 0xfc000000, "o(RR)W" },
	{ 0x0c000040, 0xfc00dfc0, "r(R)W" },
	{ 0x0c000040, 0xfc001fc0, "r(RR)W" },
	{ 0x0c000040, 0xfc00d3c0, "r(R)W" },
	{ 0x0c000040, 0xfc0013c0, "r(RR)W" },
	{ 0x0c001060, 0xfc1ff3e0, "o(R)W" },
	{ 0x0c001060, 0xfc1f33e0, "o(RR)W" },
	{ 0x0c001040, 0xfc00dfc0, "o(b)W" },
	{ 0x0c001040, 0xfc001fc0, "o(Rb)W" },
	{ 0x0c001040, 0xfc00d3c0, "o(b)W" },
	{ 0x0c001040, 0xfc0013c0, "o(Rb)W" },
	{ 0x44000000, 0xfc000000, "o(R)W" },
	{ 0x44000000, 0xfc00c000, "o(R)W" },
	{ 0x44000000, 0xfc000000, "o(RR)W" },
	{ 0x0c000000, 0xfc00dfc0, "r(R)W" },
	{ 0x0c000000, 0xfc001fc0, "r(RR)W" },
	{ 0x0c000000, 0xfc00d3c0, "r(R)W" },
	{ 0x0c000000, 0xfc0013c0, "r(RR)W" },
	{ 0x0c001020, 0xfc1ff3e0, "o(R)W" },
	{ 0x0c001020, 0xfc1f33e0, "o(RR)W" },
	{ 0x0c001000, 0xfc00dfc0, "o(b)W" },
	{ 0x0c001000, 0xfc001fc0, "o(Rb)W" },
	{ 0x0c001000, 0xfc00d3c0, "o(b)W" },
	{ 0x0c001000, 0xfc0013c0, "o(Rb)W" },
	{ 0x40000000, 0xfc000000, "o(R)W" },
	{ 0x40000000, 0xfc00c000, "o(R)W" },
	{ 0x40000000, 0xfc000000, "o(RR)W" },
	{ 0x0c0012e0, 0xfc00f3ff, "Ro(R)" },
	{ 0x0c0012e0, 0xfc0033ff, "Ro(RR)" },
	{ 0x0c0012c0, 0xfc00d3c0, "Ro(b)" },
	{ 0x0c0012c0, 0xfc0013c0, "Ro(Rb)" },
	{ 0x70000000, 0xfc000002, "Ro(b)" },
	{ 0x70000000, 0xfc00c002, "Ro(b)" },
	{ 0x70000000, 0xfc000002, "Ro(Rb)" },
	{ 0x0c0012a0, 0xfc00f3ff, "Ro(R)" },
	{ 0x0c0012a0, 0xfc0033ff, "Ro(RR)" },
	{ 0x0c001280, 0xfc00dfc0, "Ro(b)" },
	{ 0x0c001280, 0xfc001fc0, "Ro(Rb)" },
	{ 0x0c001280, 0xfc00d3c0, "Ro(b)" },
	{ 0x0c001280, 0xfc0013c0, "Ro(Rb)" },
	{ 0x6c000000, 0xfc000000, "Ro(b)" },
	{ 0x7c000004, 0xfc000006, "Ro(b)" },
	{ 0x68000000, 0xfc000000, "Ro(R)" },
	{ 0x7c000004, 0xfc00c006, "Ro(b)" },
	{ 0x7c000004, 0xfc000006, "Ro(Rb)" },
	{ 0x6c000000, 0xfc00c000, "Ro(b)" },
	{ 0x6c000000, 0xfc000000, "Ro(Rb)" },
	{ 0x68000000, 0xfc00c000, "Ro(R)" },
	{ 0x68000000, 0xfc000000, "Ro(RR)" },
	{ 0x0c001260, 0xfc00f3ff, "Ro(R)" },
	{ 0x0c001260, 0xfc0033ff, "Ro(RR)" },
	{ 0x0c001240, 0xfc00dfc0, "Ro(b)" },
	{ 0x0c001240, 0xfc001fc0, "Ro(Rb)" },
	{ 0x0c001240, 0xfc00d3c0, "Ro(b)" },
	{ 0x0c001240, 0xfc0013c0, "Ro(Rb)" },
	{ 0x64000000, 0xfc000000, "Ro(R)" },
	{ 0x64000000, 0xfc00c000, "Ro(R)" },
	{ 0x64000000, 0xfc000000, "Ro(RR)" },
	{ 0x0c001220, 0xfc00f3ff, "Ro(R)" },
	{ 0x0c001220, 0xfc0033ff, "Ro(RR)" },
	{ 0x0c001200, 0xfc00dfc0, "Ro(b)" },
	{ 0x0c001200, 0xfc001fc0, "Ro(Rb)" },
	{ 0x0c001200, 0xfc00d3c0, "Ro(b)" },
	{ 0x0c001200, 0xfc0013c0, "Ro(Rb)" },
	{ 0x60000000, 0xfc000000, "Ro(R)" },
	{ 0x60000000, 0xfc00c000, "Ro(R)" },
	{ 0x60000000, 0xfc000000, "Ro(RR)" },
	{ 0x4c000000, 0xfc00c000, "o(R)W" },
	{ 0x4c000000, 0xfc000000, "o(RR)W" },
	{ 0x6c000000, 0xfc00c000, "Ro(R)" },
	{ 0x6c000000, 0xfc000000, "Ro(RR)" },
	{ 0x0c000080, 0xfc00dfc0, "r(R)W" },
	{ 0x0c000080, 0xfc001fc0, "r(RR)W" },
	{ 0x0c000080, 0xfc00d3c0, "r(R)W" },
	{ 0x0c000080, 0xfc0013c0, "r(RR)W" },
	{ 0x0c000080, 0xfc00dfc0, "r(R)W" },
	{ 0x0c000080, 0xfc001fc0, "r(RR)W" },
	{ 0x0c000040, 0xfc00dfc0, "r(R)W" },
	{ 0x0c000040, 0xfc001fc0, "r(RR)W" },
	{ 0x0c000040, 0xfc00d3c0, "r(R)W" },
	{ 0x0c000040, 0xfc0013c0, "r(RR)W" },
	{ 0x0c000040, 0xfc00dfc0, "r(R)W" },
	{ 0x0c000040, 0xfc001fc0, "r(RR)W" },
	{ 0x0c000000, 0xfc00dfc0, "r(R)W" },
	{ 0x0c000000, 0xfc001fc0, "r(RR)W" },
	{ 0x0c000000, 0xfc00d3c0, "r(R)W" },
	{ 0x0c000000, 0xfc0013c0, "r(RR)W" },
	{ 0x0c000000, 0xfc00dfc0, "r(R)W" },
	{ 0x0c000000, 0xfc001fc0, "r(RR)W" },
	{ 0x0c000180, 0xfc00dfc0, "r(R)W" },
	{ 0x0c000180, 0xfc00d3c0, "r(R)W" },
	{ 0x0c0011a0, 0xfc1ff3e0, "o(R)W" },
	{ 0x0c001180, 0xfc00dfc0, "o(b)W" },
	{ 0x0c001180, 0xfc00d3c0, "o(b)W" },
	{ 0x0c0001c0, 0xfc00dfc0, "r(R)W" },
	{ 0x0c0001c0, 0xfc001fc0, "r(RR)W" },
	{ 0x0c0001c0, 0xfc00d3c0, "r(R)W" },
	{ 0x0c0001c0, 0xfc0013c0, "r(RR)W" },
	{ 0x0c0011c0, 0xfc00dfc0, "o(b)W" },
	{ 0x0c0011c0, 0xfc001fc0, "o(Rb)W" },
	{ 0x0c0011c0, 0xfc00d3c0, "o(b)W" },
	{ 0x0c0011c0, 0xfc0013c0, "o(Rb)W" },
	{ 0x0c0013a0, 0xfc00d3ff, "Ro(R)" },
	{ 0x0c001380, 0xfc00dfc0, "Ro(b)" },
	{ 0x0c001380, 0xfc00d3c0, "Ro(b)" },
	{ 0x0c001300, 0xfc00dfc0, "Ro(b)" },
	{ 0x0c001300, 0xfc001fc0, "Ro(Rb)" },
	{ 0x0c001300, 0xfc00d3c0, "Ro(b)" },
	{ 0x0c001300, 0xfc0013c0, "Ro(Rb)" },
	{ 0x0c000100, 0xfc00d3c0, "r(R)W" },
	{ 0x0c001120, 0xfc1ff3e0, "o(R)W" },
	{ 0x0c001100, 0xfc00d3c0, "o(b)W" },
	{ 0x0c000140, 0xfc00d3c0, "r(R)W" },
	{ 0x0c000140, 0xfc0013c0, "r(RR)W" },
	{ 0x0c001140, 0xfc00d3c0, "o(b)W" },
	{ 0x0c001140, 0xfc0013c0, "o(Rb)W" },
	{ 0x0c0013e0, 0xfc00f3ff, "Ro(R)" },
	{ 0x0c0013c0, 0xfc00d3c0, "Ro(b)" },
	{ 0x0c000180, 0xfc00dfc0, "r(R)W" },
	{ 0x0c000180, 0xfc00d3c0, "r(R)W" },
	{ 0x0c000180, 0xfc00dfc0, "r(R)W" },
	{ 0x0c0001c0, 0xfc00dfc0, "r(R)W" },
	{ 0x0c0001c0, 0xfc001fc0, "r(RR)W" },
	{ 0x0c0001c0, 0xfc00d3c0, "r(R)W" },
	{ 0x0c0001c0, 0xfc0013c0, "r(RR)W" },
	{ 0x0c0001c0, 0xfc00dfc0, "r(R)W" },
	{ 0x0c0001c0, 0xfc001fc0, "r(RR)W" },
	{ 0x0c001080, 0xfc00dfc0, "o(b)W" },
	{ 0x0c001080, 0xfc001fc0, "o(Rb)W" },
	{ 0x0c001080, 0xfc00d3c0, "o(b)W" },
	{ 0x0c001080, 0xfc0013c0, "o(Rb)W" },
	{ 0x0c001080, 0xfc00dfc0, "o(b)W" },
	{ 0x0c001080, 0xfc001fc0, "o(Rb)W" },
	{ 0x0c001040, 0xfc00dfc0, "o(b)W" },
	{ 0x0c001040, 0xfc001fc0, "o(Rb)W" },
	{ 0x0c001040, 0xfc00d3c0, "o(b)W" },
	{ 0x0c001040, 0xfc0013c0, "o(Rb)W" },
	{ 0x0c001040, 0xfc00dfc0, "o(b)W" },
	{ 0x0c001040, 0xfc001fc0, "o(Rb)W" },
	{ 0x0c001000, 0xfc00dfc0, "o(b)W" },
	{ 0x0c001000, 0xfc001fc0, "o(Rb)W" },
	{ 0x0c001000, 0xfc00d3c0, "o(b)W" },
	{ 0x0c001000, 0xfc0013c0, "o(Rb)W" },
	{ 0x0c001000, 0xfc00dfc0, "o(b)W" },
	{ 0x0c001000, 0xfc001fc0, "o(Rb)W" },
	{ 0x0c001180, 0xfc00dfc0, "o(b)W" },
	{ 0x0c001180, 0xfc00d3c0, "o(b)W" },
	{ 0x0c001180, 0xfc00dfc0, "o(b)W" },
	{ 0x0c0011c0, 0xfc00dfc0, "o(b)W" },
	{ 0x0c0011c0, 0xfc001fc0, "o(Rb)W" },
	{ 0x0c0011c0, 0xfc00d3c0, "o(b)W" },
	{ 0x0c0011c0, 0xfc0013c0, "o(Rb)W" },
	{ 0x0c0011c0, 0xfc00dfc0, "o(b)W" },
	{ 0x0c0011c0, 0xfc001fc0, "o(Rb)W" },
	{ 0x0c001280, 0xfc00dfc0, "Ro(b)" },
	{ 0x0c001280, 0xfc001fc0, "Ro(Rb)" },
	{ 0x0c001280, 0xfc00d3c0, "Ro(b)" },
	{ 0x0c001280, 0xfc0013c0, "Ro(Rb)" },
	{ 0x0c001280, 0xfc00dfc0, "Ro(b)" },
	{ 0x0c001280, 0xfc001fc0, "Ro(Rb)" },
	{ 0x0c001240, 0xfc00dfc0, "Ro(b)" },
	{ 0x0c001240, 0xfc001fc0, "Ro(Rb)" },
	{ 0x0c001240, 0xfc00d3c0, "Ro(b)" },
	{ 0x0c001240, 0xfc0013c0, "Ro(Rb)" },
	{ 0x0c001240, 0xfc00dfc0, "Ro(b)" },
	{ 0x0c001240, 0xfc001fc0, "Ro(Rb)" },
	{ 0x0c001200, 0xfc00dfc0, "Ro(b)" },
	{ 0x0c001200, 0xfc001fc0, "Ro(Rb)" },
	{ 0x0c001200, 0xfc00d3c0, "Ro(b)" },
	{ 0x0c001200, 0xfc0013c0, "Ro(Rb)" },
	{ 0x0c001200, 0xfc00dfc0, "Ro(b)" },
	{ 0x0c001200, 0xfc001fc0, "Ro(Rb)" },
	{ 0x0c001380, 0xfc00dfc0, "Ro(b)" },
	{ 0x0c001380, 0xfc00d3c0, "Ro(b)" },
	{ 0x0c001380, 0xfc00dfc0, "Ro(b)" },
	{ 0x0c001340, 0xfc00d3c0, "Ro(b)" },
	{ 0x0c001340, 0xfc0013c0, "Ro(Rb)" },
	{ 0x0c001300, 0xfc00dfc0, "Ro(b)" },
	{ 0x0c001300, 0xfc001fc0, "Ro(Rb)" },
	{ 0x0c001300, 0xfc00d3c0, "Ro(b)" },
	{ 0x0c001300, 0xfc0013c0, "Ro(Rb)" },
	{ 0x0c001300, 0xfc00dfc0, "Ro(b)" },
	{ 0x0c001300, 0xfc001fc0, "Ro(Rb)" },

	{ 0x34000000, 0xfc000000, "o(R)W" },
	{ 0x34000000, 0xfc00c000, "o(R)W" },
	{ 0x20000000, 0xfc000000, "iW" },
	{ 0x28000000, 0xfc000000, "iRW" },
	{ 0x28000000, 0xfc000000, "iR" },

	{ 0xe8008000, 0xfc00e000, "TW" },
	{ 0xe800a000, 0xfc00e000, "TW" },
	{ 0xe8000000, 0xfc00e000, "TW" },
	{ 0xe8002000, 0xfc00e000, "TW" },
	{ 0xe8000000, 0xffe0e000, "T" },
	{ 0xe8000000, 0xfc00e000, "TW" },
	{ 0xe8002000, 0xfc00e000, "TW" },
	{ 0xe8004000, 0xfc00e001, "RW" },
	{ 0xe800c000, 0xfc00fffd, "r(R)" },
	{ 0xe800c000, 0xfc00fffd, "(R)" },
	{ 0xe800f001, 0xfc1ffffd, "(R)" },
	{ 0xe800f000, 0xfc1ffffd, "(R)" },
	{ 0xe800d001, 0xfc1ffffd, "(R)" },
	{ 0xe800d000, 0xfc1ffffd, "(R)" },
	{ 0xe4000000, 0xfc000000, "o(RR)Y" },
	{ 0xe4000000, 0xfc000000, "o(R)Y" },
	{ 0xe0000000, 0xfc000000, "o(RR)" },
	{ 0xe0000000, 0xfc000000, "o(R)" },
	{ 0xe4000000, 0xfc000000, "o(RR)" },
	{ 0xc8000000, 0xfc000000, "RWT" },
	{ 0xcc000000, 0xfc000000, "iWT" },
	{ 0x80000000, 0xfc000000, "RRT" },
	{ 0x88000000, 0xfc000000, "RRT" },
	{ 0x84000000, 0xfc000000, "iRT" },
	{ 0x8c000000, 0xfc000000, "iRT" },
	{ 0xa0000000, 0xfc000000, "RwT" },
	{ 0xa8000000, 0xfc000000, "RwT" },
	{ 0xa4000000, 0xfc000000, "iwT" },
	{ 0xac000000, 0xfc000000, "iwT" },
	{ 0xc0004000, 0xffe06000, "RRT" },
	{ 0xc0006000, 0xffe06000, "RRT" },
	{ 0xc4004000, 0xfc006000, "RiT" },
	{ 0xc4004000, 0xfc004000, "RiT" },
	{ 0xc0004000, 0xffe04000, "RT" },
	{ 0xe8004005, 0xffffffff, "" },
	{ 0xe8004005, 0xfffff007, "i" },
	{ 0xe8004001, 0xffffffff, "" },
	{ 0xe8004001, 0xffe0ffff, "R" },

	{ 0x080008a0, 0xfc000fe0, "RRW" },
	{ 0x08000880, 0xfc000fe0, "RRW" },
	{ 0x08000880, 0xfc000fe0, "RRW" },
	{ 0x08000260, 0xfc000fe0, "RRW" },
	{ 0x08000240, 0xfc000fe0, "RRW" },
	{ 0x080002a0, 0xfc000fe0, "RRW" },
	{ 0x08000280, 0xfc000fe0, "RRW" },
	{ 0x08000220, 0xfc000fe0, "RRW" },
	{ 0x08000200, 0xfc000fe0, "RRW" },
	{ 0x08000020, 0xfc000fe0, "RRW" },
	{ 0x08000000, 0xfc000fe0, "RRW" },
	{ 0x080003a0, 0xfc000fe0, "RRW" },
	{ 0x08000380, 0xfc000fe0, "RRW" },
	{ 0x080009a0, 0xfc000fa0, "RRW" },
	{ 0x08000980, 0xfc000fa0, "RRW" },
	{ 0x08000980, 0xfc000fe0, "RRW" },
	{ 0x080009c0, 0xfc000fe0, "RRW" },
	{ 0x08000ba0, 0xfc1f0fa0, "RW" },
	{ 0x08000b80, 0xfc1f0fa0, "RW" },
	{ 0x08000b80, 0xfc1f0fe0, "RW" },
	{ 0x08000bc0, 0xfc1f0fe0, "RW" },
	{ 0xb0000000, 0xfc000000, "iRW" },
	{ 0xb4000000, 0xfc000000, "iRW" },
	{ 0xb4000000, 0xfc000800, "iRW" },
	{ 0xb4000800, 0xfc000800, "iRW" },
	{ 0xb0000000, 0xfc000800, "iRW" },
	{ 0xb0000800, 0xfc000800, "iRW" },
	{ 0x08000720, 0xfc0007e0, "RRW" },
	{ 0x08000700, 0xfc0007e0, "RRW" },
	{ 0x08000220, 0xfc0003e0, "RRW" },
	{ 0x08000200, 0xfc0003e0, "RRW" },
	{ 0x08000600, 0xfc000fe0, "RRW" },
	{ 0x08000a00, 0xfc000fe0, "RRW" },
	{ 0x08000e00, 0xfc000fe0, "RRW" },
	{ 0x08000700, 0xfc000fe0, "RRW" },
	{ 0x08000f00, 0xfc000fe0, "RRW" },
	{ 0x080004e0, 0xfc0007e0, "RRW" },
	{ 0x080004c0, 0xfc0007e0, "RRW" },
	{ 0x08000520, 0xfc0007e0, "RRW" },
	{ 0x08000500, 0xfc0007e0, "RRW" },
	{ 0x08000420, 0xfc0007e0, "RRW" },
	{ 0x08000400, 0xfc0007e0, "RRW" },
	{ 0x08000400, 0xfc000fe0, "RRW" },
	{ 0x08000c00, 0xfc000fe0, "RRW" },
	{ 0x08000500, 0xfc000fe0, "RRW" },
	{ 0x08000d00, 0xfc000fe0, "RRW" },
	{ 0x080004c0, 0xfc000fe0, "RRW" },
	{ 0x08000cc0, 0xfc000fe0, "RRW" },
	{ 0x08000440, 0xfc000fe0, "RRW" },
	{ 0x94000000, 0xfc000000, "iRW" },
	{ 0x94000000, 0xfc000800, "iRW" },
	{ 0x94000800, 0xfc000800, "iRW" },
	{ 0x90000800, 0xfc000800, "iRW" },
	{ 0x90000000, 0xfc000800, "iRW" },
	{ 0x90000000, 0xfc000800, "iRW" },
	{ 0x08000220, 0xfc000320, "RiRW" },
	{ 0x08000200, 0xfc000320, "RiRW" },
	{ 0x08000640, 0xfc000fe0, "RRW" },
	{ 0x08000a40, 0xfc000fe0, "RRW" },
	{ 0x08000e40, 0xfc000fe0, "RRW" },
	{ 0x08000680, 0xfc000fe0, "RRW" },
	{ 0x08000a80, 0xfc000fe0, "RRW" },
	{ 0x08000e80, 0xfc000fe0, "RRW" },
	{ 0x080006c0, 0xfc000fe0, "RRW" },
	{ 0x08000ac0, 0xfc000fe0, "RRW" },
	{ 0x08000ec0, 0xfc000fe0, "RRW" },

	{ 0x08000300, 0xfc00ff20, "RRW" },
	{ 0x080002c0, 0xfc00ffe0, "RRW" },
	{ 0xf8008800, 0xffe0fc20, "RiW" },
	{ 0x08000700, 0xfc00ff20, "RiRW" },
	{ 0xf800c800, 0xfc1ff820, "RiW" },
	{ 0x08000500, 0xfc00ff20, "RiRW" },
	{ 0x08000100, 0xfc00ff20, "RRW" },
	{ 0xf8008400, 0xfc009fe0, "RRW" },
	{ 0xf8008000, 0xfc009fe0, "RRW" },
	{ 0xf8000000, 0xfc009020, "RW" },

	{ 0xd0000200, 0xfc001fe0, "RRRW" },
	{ 0xd0000400, 0xfc001400, "RRiW" },
	{ 0xd0000000, 0xfc001fe0, "RRRW" },
	{ 0xd0000800, 0xfc001c00, "RRiW" },
	{ 0xd0000000, 0xfc001fe0, "RRW" },
	{ 0xd0000800, 0xfc001c00, "RRiW" },
	{ 0xd0001200, 0xfc001ae0, "RRiW" },
	{ 0xd8000000, 0xfc000000, "RiiW" },
	{ 0xd0001000, 0xfc001be0, "RRiW" },
	{ 0xd0001800, 0xfc001800, "RiiW" },
	{ 0xd0001000, 0xfc001fe0, "RiW" },
	{ 0xd0001400, 0xfc001fe0, "RiW" },
	{ 0xd0001800, 0xfc001c00, "RiiW" },
	{ 0xd0001c00, 0xfc001c00, "RiiW" },
	{ 0xd4000200, 0xfc001ae0, "RRiW" },
	{ 0xf0000000, 0xfc000000, "RiiW" },
	{ 0xd4001200, 0xfc001ae0, "iRiW" },
	{ 0xf4000000, 0xfc000000, "iiiW" },
	{ 0xd4000000, 0xfc001be0, "RRiW" },
	{ 0xd4000800, 0xfc001800, "RiiW" },
	{ 0xd4001000, 0xfc001be0, "iRiW" },
	{ 0xd4001800, 0xfc001800, "iiiW" },
	{ 0xd4000000, 0xfc001fe0, "RiW" },
	{ 0xd4000400, 0xfc001fe0, "RiW" },
	{ 0xd4000800, 0xfc001c00, "RiiW" },
	{ 0xd4000c00, 0xfc001c00, "RiiW" },
	{ 0xd4001000, 0xfc001fe0, "iit" },
	{ 0xd4001400, 0xfc001fe0, "iit" },
	{ 0xd4001800, 0xfc001c00, "iiiW" },
	{ 0xd4001c00, 0xfc001c00, "iiiW" },

	{ 0x00000000, 0xfc001fe0, "ii" },
	{ 0x00000c00, 0xffffff1f, "" },
	{ 0x00000c00, 0xffffffff, "" },
	{ 0x00000ca0, 0xffffffff, "" },
	{ 0x00000d60, 0xfc00ffe0, "iW" },
	{ 0x00000d60, 0xffe0ffe0, "iW" },
	{ 0x00000e60, 0xfc00ffe0, "iW" },
	{ 0x00000e60, 0xffe0ffe0, "iW" },
	{ 0x00001860, 0xffe0ffff, "R" },
	{ 0x000010a0, 0xfc1fffe0, "(RR)W" },
	{ 0x000010a0, 0xfc1f3fe0, "(R)W" },
	{ 0x00001820, 0xffe01fff, "WR" },
	{ 0x00001840, 0xfc00ffff, "RW" },
	{ 0x016018C0, 0xffe0ffff, "R" },
	{ 0x000014A0, 0xffffffe0, "W" },
	{ 0x000004a0, 0xffff1fe0, "RW" },
	{ 0x016048a0, 0xffffffe0, "RW" },
	{ 0x000008a0, 0xfc1fffe0, "RW" },
	{ 0x00000400, 0xffffffff, "" },
	{ 0x00100400, 0xffffffff, "" },
	{ 0x04001180, 0xfc00ffa0, "(R)RW" },
	{ 0x04001180, 0xfc003fa0, "(RR)RW" },
	{ 0x04003180, 0xfc00ffa0, "(R)iW" },
	{ 0x04003180, 0xfc003fa0, "(RR)iW" },
	{ 0x04001180, 0xfc00ffe0, "(R)RW" },
	{ 0x04001180, 0xfc003fe0, "(RR)RW" },
	{ 0x04003180, 0xfc00ffe0, "(R)iW" },
	{ 0x04003180, 0xfc003fe0, "(RR)iW" },
	{ 0x040011c0, 0xfc00ffe0, "(R)RW" },
	{ 0x040011c0, 0xfc003fe0, "(RR)RW" },
	{ 0x040031c0, 0xfc00ffe0, "(R)iW" },
	{ 0x040031c0, 0xfc003fe0, "(RR)iW" },
	{ 0x04001340, 0xfc00ffc0, "r(b)W" },
	{ 0x04001340, 0xfc003fc0, "r(Rb)W" },
	{ 0x04001300, 0xfc00ffe0, "r(R)W" },
	{ 0x04001300, 0xfc003fe0, "r(RR)W" },
	{ 0x04001600, 0xfc00ffdf, "r(b)" },
	{ 0x04001600, 0xfc003fdf, "r(Rb)" },
	{ 0x04001600, 0xfc1fffdf, "o(b)" },
	{ 0x04001600, 0xfc1f3fdf, "o(Rb)" },
	{ 0x04001200, 0xfc00ffdf, "r(b)" },
	{ 0x04001200, 0xfc003fdf, "r(Rb)" },
	{ 0x04000600, 0xfc001fdf, "r(Rb)" },
	{ 0x04000600, 0xfc1f1fdf, "o(Rb)" },
	{ 0x04000200, 0xfc001fdf, "r(Rb)" },
	{ 0x04001240, 0xfc00ffdf, "r(b)" },
	{ 0x04001240, 0xfc003fdf, "r(Rb)" },
	{ 0x04000240, 0xfc001fdf, "r(Rb)" },
	{ 0x04001040, 0xfc00ffff, "r(R)" },
	{ 0x04001040, 0xfc003fff, "r(RR)" },
	{ 0x04000040, 0xfc001fff, "r(RR)" },
	{ 0x04001000, 0xfc00ffff, "r(R)" },
	{ 0x04001000, 0xfc003fff, "r(RR)" },
	{ 0x04000000, 0xfc001fff, "r(RR)" },
	{ 0x04001380, 0xfc00ffdf, "r(b)" },
	{ 0x04001380, 0xfc003fdf, "r(Rb)" },
	{ 0x04001280, 0xfc00ffdf, "r(b)" },
	{ 0x04001280, 0xfc003fdf, "r(Rb)" },
	{ 0x04003280, 0xfc00ffff, "o(R)" },
	{ 0x04003280, 0xfc003fff, "o(RR)" },
	{ 0x04001280, 0xfc00ffdf, "r(b)" },
	{ 0x04001280, 0xfc003fdf, "r(Rb)" },
	{ 0x040013c0, 0xfc00dfdf, "r(b)" },
	{ 0x04000280, 0xfc001fdf, "r(Rb)" },
	{ 0x040012c0, 0xfc00ffdf, "r(b)" },
	{ 0x040012c0, 0xfc003fdf, "r(Rb)" },
	{ 0x040002c0, 0xfc001fdf, "r(Rb)" },
	{ 0x14000000, 0xfc000000, "i" },
	{ 0x04001800, 0xfc00ffff, "RR" },
	{ 0x04000800, 0xfc00ffff, "RR" },

	{ 0x14001600, 0xfc00ffff, "00" },
	{ 0x14001A00, 0xfc00ffff, "00" },
	{ 0x14403600, 0xffffffff, "" },
	{ 0x14401620, 0xffffffff, "" },
	{ 0x14402600, 0xffffffff, "" },
	{ 0x14400620, 0xffffffff, "" },

	{ 0x04001680, 0xfc00ffdf, "r(0)" },
	{ 0x04001680, 0xfc003fdf, "r(R0)" },
	{ 0x04001a80, 0xfc00ffdf, "r(0)" },
	{ 0x04001a80, 0xfc003fdf, "r(R0)" },

	{ 0x24000000, 0xfc00df80, "r(R)W" },
	{ 0x24000000, 0xfc001f80, "r(RR)W" },
	{ 0x24000000, 0xfc00d380, "r(R)W" },
	{ 0x24000000, 0xfc001380, "r(RR)W" },
	{ 0x24001020, 0xfc1ff3a0, "o(R)W" },
	{ 0x24001020, 0xfc1f33a0, "o(RR)W" },
	{ 0x24001000, 0xfc00df80, "o(b)W" },
	{ 0x24001000, 0xfc001f80, "o(Rb)W" },
	{ 0x24001000, 0xfc00d380, "o(b)W" },
	{ 0x24001000, 0xfc001380, "o(Rb)W" },
	{ 0x5c000000, 0xfc000004, "o(R)W" },
	{ 0x58000000, 0xfc000000, "o(b)W" },
	{ 0x5c000000, 0xfc00c004, "o(R)W" },
	{ 0x5c000000, 0xfc000004, "o(RR)W" },
	{ 0x58000000, 0xfc00c000, "o(b)W" },
	{ 0x58000000, 0xfc000000, "o(Rb)W" },
	{ 0x2c000000, 0xfc00dfc0, "r(R)W" },
	{ 0x2c000000, 0xfc001fc0, "r(RR)W" },
	{ 0x2c000000, 0xfc00d3c0, "r(R)W" },
	{ 0x2c000000, 0xfc0013c0, "r(RR)W" },
	{ 0x2c001020, 0xfc1ff3e0, "o(R)W" },
	{ 0x2c001020, 0xfc1f33e0, "o(RR)W" },
	{ 0x2c001000, 0xfc00dfc0, "o(b)W" },
	{ 0x2c001000, 0xfc001fc0, "o(Rb)W" },
	{ 0x2c001000, 0xfc00d3c0, "o(b)W" },
	{ 0x2c001000, 0xfc0013c0, "o(Rb)W" },
	{ 0x50000002, 0xfc000002, "o(b)W" },
	{ 0x50000002, 0xfc00c002, "o(b)W" },
	{ 0x50000002, 0xfc000002, "o(Rb)W" },
	{ 0x24000200, 0xfc00df80, "Rr(R)" },
	{ 0x24000200, 0xfc001f80, "Rr(RR)" },
	{ 0x24000200, 0xfc00d380, "Rr(R)" },
	{ 0x24000200, 0xfc001380, "Rr(RR)" },
	{ 0x24001220, 0xfc1ff3a0, "Ro(R)" },
	{ 0x24001220, 0xfc1f33a0, "Ro(RR)" },
	{ 0x24001200, 0xfc00df80, "Ro(b)" },
	{ 0x24001200, 0xfc001f80, "Ro(Rb)" },
	{ 0x24001200, 0xfc00df80, "Ro(b)" },
	{ 0x24001200, 0xfc001f80, "Ro(Rb)" },
	{ 0x7c000000, 0xfc000004, "Ro(R)" },
	{ 0x78000000, 0xfc000000, "Ro(b)" },
	{ 0x7c000000, 0xfc00c004, "Ro(R)" },
	{ 0x7c000000, 0xfc000004, "Ro(RR)" },
	{ 0x78000000, 0xfc00c000, "Ro(b)" },
	{ 0x78000000, 0xfc000000, "Ro(Rb)" },
	{ 0x2c000200, 0xfc00dfc0, "Rr(R)" },
	{ 0x2c000200, 0xfc001fc0, "Rr(RR)" },
	{ 0x2c000200, 0xfc00d3c0, "Rr(R)" },
	{ 0x2c000200, 0xfc0013c0, "Rr(RR)" },
	{ 0x2c001220, 0xfc1ff3e0, "Ro(R)" },
	{ 0x2c001220, 0xfc1f33e0, "Ro(RR)" },
	{ 0x2c001200, 0xfc00dfc0, "Ro(b)" },
	{ 0x2c001200, 0xfc001fc0, "Ro(Rb)" },
	{ 0x2c001200, 0xfc00d3c0, "Ro(b)" },
	{ 0x2c001200, 0xfc0013c0, "Ro(Rb)" },
	{ 0x70000002, 0xfc000002, "Ro(b)" },
	{ 0x70000002, 0xfc00c002, "Ro(b)" },
	{ 0x70000002, 0xfc000002, "Ro(Rb)" },
	{ 0x24000000, 0xfc00df80, "r(R)W" },
	{ 0x24000000, 0xfc001f80, "r(RR)W" },
	{ 0x24000000, 0xfc00d380, "r(R)W" },
	{ 0x24000000, 0xfc001380, "r(RR)W" },
	{ 0x24000000, 0xfc00df80, "r(R)W" },
	{ 0x24000000, 0xfc001f80, "r(RR)W" },
	{ 0x2c000000, 0xfc00dfc0, "r(R)W" },
	{ 0x2c000000, 0xfc001fc0, "r(RR)W" },
	{ 0x2c000000, 0xfc00d3c0, "r(R)W" },
	{ 0x2c000000, 0xfc0013c0, "r(RR)W" },
	{ 0x2c000000, 0xfc00dfc0, "r(R)W" },
	{ 0x2c000000, 0xfc001fc0, "r(RR)W" },
	{ 0x24000200, 0xfc00df80, "Rr(R)" },
	{ 0x24000200, 0xfc001f80, "Rr(RR)" },
	{ 0x24000200, 0xfc00d380, "Rr(R)" },
	{ 0x24000200, 0xfc001380, "Rr(RR)" },
	{ 0x24000200, 0xfc00df80, "Rr(R)" },
	{ 0x24000200, 0xfc001f80, "Rr(RR)" },
	{ 0x2c000200, 0xfc00dfc0, "Rr(R)" },
	{ 0x2c000200, 0xfc001fc0, "Rr(RR)" },
	{ 0x2c000200, 0xfc00d3c0, "Rr(R)" },
	{ 0x2c000200, 0xfc0013c0, "Rr(RR)" },
	{ 0x2c000200, 0xfc00dfc0, "Rr(R)" },
	{ 0x2c000200, 0xfc001fc0, "Rr(RR)" },
	{ 0x3c000200, 0xfc00dfc0, "Rr(R)" },
	{ 0x3c000200, 0xfc001fc0, "Rr(RR)" },
	{ 0x24001000, 0xfc00df80, "o(b)W" },
	{ 0x24001000, 0xfc001f80, "o(Rb)W" },
	{ 0x24001000, 0xfc00d380, "o(b)W" },
	{ 0x24001000, 0xfc001380, "o(Rb)W" },
	{ 0x24001000, 0xfc00df80, "o(b)W" },
	{ 0x24001000, 0xfc001f80, "o(Rb)W" },
	{ 0x2c001000, 0xfc00dfc0, "o(b)W" },
	{ 0x2c001000, 0xfc001fc0, "o(Rb)W" },
	{ 0x2c001000, 0xfc00d3c0, "o(b)W" },
	{ 0x2c001000, 0xfc0013c0, "o(Rb)W" },
	{ 0x2c001000, 0xfc00dfc0, "o(b)W" },
	{ 0x2c001000, 0xfc001fc0, "o(Rb)W" },
	{ 0x24001200, 0xfc00df80, "Ro(b)" },
	{ 0x24001200, 0xfc001f80, "Ro(Rb)" },
	{ 0x24001200, 0xfc00d380, "Ro(b)" },
	{ 0x24001200, 0xfc001380, "Ro(Rb)" },
	{ 0x24001200, 0xfc00df80, "Ro(b)" },
	{ 0x24001200, 0xfc001f80, "Ro(Rb)" },
	{ 0x2c001200, 0xfc00dfc0, "Ro(b)" },
	{ 0x2c001200, 0xfc001fc0, "Ro(Rb)" },
	{ 0x2c001200, 0xfc00d3c0, "Ro(b)" },
	{ 0x2c001200, 0xfc0013c0, "Ro(Rb)" },
	{ 0x2c001200, 0xfc00dfc0, "Ro(b)" },
	{ 0x2c001200, 0xfc001fc0, "Ro(Rb)" },
	{ 0x3c001200, 0xfc00dfc0, "Ro(b)" },
	{ 0x3c001200, 0xfc001fc0, "Ro(Rb)" },
	{ 0x30000600, 0xfc00e7e0, "RRW" },
	{ 0x38000600, 0xfc00e720, "RRW" },
	{ 0x30002600, 0xfc00e7e0, "RRW" },
	{ 0x38002600, 0xfc00e720, "RRW" },
	{ 0x30004600, 0xfc00e7e0, "RRW" },
	{ 0x38004600, 0xfc00e720, "RRW" },
	{ 0x30006600, 0xfc00e7e0, "RRW" },
	{ 0x38006600, 0xfc00e720, "RRW" },
	{ 0x30008000, 0xfc1fe7e0, "RW" },
	{ 0x38008000, 0xfc1fe720, "RW" },
	{ 0x30006000, 0xfc1fe7e0, "RW" },
	{ 0x38006000, 0xfc1fe720, "RW" },
	{ 0x30008600, 0xfc00e7e0, "RRW" },
	{ 0x38008600, 0xfc00e720, "RRW" },
	{ 0x3000a000, 0xfc1fe7e0, "RW" },
	{ 0x3800a000, 0xfc1fe720, "RW" },
	{ 0x30004000, 0xfc1fe7e0, "RW" },
	{ 0x38004000, 0xfc1fe720, "RW" },
	{ 0x30000200, 0xfc1f87e0, "RW" },
	{ 0x38000200, 0xfc1f8720, "RW" },
	{ 0x30008200, 0xfc1f87e0, "RW" },
	{ 0x38008200, 0xfc1f8720, "RW" },
	{ 0x30010200, 0xfc1f87e0, "RW" },
	{ 0x38010200, 0xfc1f8720, "RW" },
	{ 0x30018200, 0xfc1f87e0, "RW" },
	{ 0x38018200, 0xfc1f8720, "RW" },
	{ 0xb8000000, 0xfc000020, "RRRW" },
	{ 0xb8000020, 0xfc000020, "RRRW" },
	{ 0x3000c000, 0xfc1fe7e0, "RW" },
	{ 0x3800c000, 0xfc1fe720, "RW" },
	{ 0x3000e000, 0xfc1fe7e0, "RW" },
	{ 0x3800e000, 0xfc1fe720, "RW" },
	{ 0x30000200, 0xfc1c0720, "RW" },
	{ 0x38000200, 0xfc1c0720, "RW" },
	{ 0x30000400, 0xfc00e7e0, "RR" },
	{ 0x38000400, 0xfc00e720, "RR" },
	{ 0x30000400, 0xfc0007e0, "RRi" },
	{ 0x38000400, 0xfc000720, "RRi" },
	{ 0x30000400, 0xfc00e7e0, "RR" },
	{ 0x38000400, 0xfc00e720, "RR" },
	{ 0x38004700, 0xfc00e720, "RRW" },
	{ 0x18000000, 0xfc000000, "RRWRw" },
	{ 0x98000000, 0xfc000000, "RRWRw" },
	{ 0x30002420, 0xffffffff, "" },
	{ 0x30002420, 0xffffffe0, "" },
	{ 0x30000420, 0xffff1fff, "i" },
	{ 0x30000000, 0xffffffff, "" },

	{ 0x30000280, 0xffffffdf, "" },
	{ 0x30000680, 0xffffffff, "" },

	{ 0x10000000, 0xfc000600, "" },
	{ 0x10000200, 0xfc000600, "W" },
	{ 0x10000400, 0xfc000600, "R" },
	{ 0x10000600, 0xfc000600, "RR" },
	{ 0x30000000, 0xfc000000, "" },
	{ 0x24000000, 0xfc00de00, "r(R)W" },
	{ 0x24000000, 0xfc001e00, "r(RR)W" },
	{ 0x24000000, 0xfc00d200, "r(R)W" },
	{ 0x24000000, 0xfc001200, "r(RR)W" },
	{ 0x24001000, 0xfc00d200, "o(R)W" },
	{ 0x24001000, 0xfc001200, "o(RR)W" },
	{ 0x24001000, 0xfc00de00, "o(b)W" },
	{ 0x24001000, 0xfc001e00, "o(Rb)W" },
	{ 0x24001000, 0xfc00d200, "o(b)W" },
	{ 0x24001000, 0xfc001200, "o(Rb)W" },
	{ 0x2c000000, 0xfc00de00, "r(R)W" },
	{ 0x2c000000, 0xfc001e00, "r(RR)W" },
	{ 0x2c000000, 0xfc00d200, "r(R)W" },
	{ 0x2c000000, 0xfc001200, "r(RR)W" },
	{ 0x2c001000, 0xfc00d200, "o(R)W" },
	{ 0x2c001000, 0xfc001200, "o(RR)W" },
	{ 0x2c001000, 0xfc00de00, "o(b)W" },
	{ 0x2c001000, 0xfc001e00, "o(Rb)W" },
	{ 0x2c001000, 0xfc00d200, "o(b)W" },
	{ 0x2c001000, 0xfc001200, "o(Rb)W" },
	{ 0x24000200, 0xfc00de00, "Rr(R)" },
	{ 0x24000200, 0xfc001e00, "Rr(RR)" },
	{ 0x24000200, 0xfc00d200, "Rr(R)" },
	{ 0x24000200, 0xfc001200, "Rr(RR)" },
	{ 0x24001200, 0xfc00d200, "Ro(R)" },
	{ 0x24001200, 0xfc001200, "Ro(RR)" },
	{ 0x24001200, 0xfc00de00, "Ro(b)" },
	{ 0x24001200, 0xfc001e00, "Ro(Rb)" },
	{ 0x24001200, 0xfc00d200, "Ro(b)" },
	{ 0x24001200, 0xfc001200, "Ro(Rb)" },
	{ 0x2c000200, 0xfc00de00, "Rr(R)" },
	{ 0x2c000200, 0xfc001e00, "Rr(RR)" },
	{ 0x2c000200, 0xfc00d200, "Rr(R)" },
	{ 0x2c000200, 0xfc001200, "Rr(RR)" },
	{ 0x2c001200, 0xfc00d200, "Ro(R)" },
	{ 0x2c001200, 0xfc001200, "Ro(RR)" },
	{ 0x2c001200, 0xfc00de00, "Ro(b)" },
	{ 0x2c001200, 0xfc001e00, "Ro(Rb)" },
	{ 0x2c001200, 0xfc00d200, "Ro(b)" },
	{ 0x2c001200, 0xfc001200, "Ro(Rb)" },
	{ 0x24000000, 0xfc00de00, "r(R)W" },
	{ 0x24000000, 0xfc001e00, "r(RR)W" },
	{ 0x24000000, 0xfc00d200, "r(R)W" },
	{ 0x24000000, 0xfc001200, "r(RR)W" },
	{ 0x24000000, 0xfc00de00, "r(R)W" },
	{ 0x24000000, 0xfc001e00, "r(RR)W" },
	{ 0x2c000000, 0xfc00de00, "r(R)W" },
	{ 0x2c000000, 0xfc001e00, "r(RR)W" },
	{ 0x2c000000, 0xfc00d200, "r(R)W" },
	{ 0x2c000000, 0xfc001200, "r(RR)W" },
	{ 0x2c000000, 0xfc00de00, "r(R)W" },
	{ 0x2c000000, 0xfc001e00, "r(RR)W" },
	{ 0x24000200, 0xfc00de00, "Rr(R)" },
	{ 0x24000200, 0xfc001e00, "Rr(RR)" },
	{ 0x24000200, 0xfc00d200, "Rr(R)" },
	{ 0x24000200, 0xfc001200, "Rr(RR)" },
	{ 0x24000200, 0xfc00de00, "Rr(R)" },
	{ 0x24000200, 0xfc001e00, "Rr(RR)" },
	{ 0x2c000200, 0xfc00de00, "Rr(R)" },
	{ 0x2c000200, 0xfc001e00, "Rr(RR)" },
	{ 0x2c000200, 0xfc00d200, "Rr(R)" },
	{ 0x2c000200, 0xfc001200, "Rr(RR)" },
	{ 0x2c000200, 0xfc00de00, "Rr(R)" },
	{ 0x2c000200, 0xfc001e00, "Rr(RR)" },
	{ 0x24001000, 0xfc00de00, "o(b)W" },
	{ 0x24001000, 0xfc001e00, "o(Rb)W" },
	{ 0x24001000, 0xfc00d200, "o(b)W" },
	{ 0x24001000, 0xfc001200, "o(Rb)W" },
	{ 0x24001000, 0xfc00de00, "o(b)W" },
	{ 0x24001000, 0xfc001e00, "o(Rb)W" },
	{ 0x2c001000, 0xfc00de00, "o(b)W" },
	{ 0x2c001000, 0xfc001e00, "o(Rb)W" },
	{ 0x2c001000, 0xfc00d200, "o(b)W" },
	{ 0x2c001000, 0xfc001200, "o(Rb)W" },
	{ 0x2c001000, 0xfc00de00, "o(b)W" },
	{ 0x2c001000, 0xfc001e00, "o(Rb)W" },
	{ 0x24001200, 0xfc00de00, "Ro(b)" },
	{ 0x24001200, 0xfc001e00, "Ro(Rb)" },
	{ 0x24001200, 0xfc00d200, "Ro(b)" },
	{ 0x24001200, 0xfc001200, "Ro(Rb)" },
	{ 0x24001200, 0xfc00de00, "Ro(b)" },
	{ 0x24001200, 0xfc001e00, "Ro(Rb)" },
	{ 0x2c001200, 0xfc00de00, "Ro(b)" },
	{ 0x2c001200, 0xfc001e00, "Ro(Rb)" },
	{ 0x2c001200, 0xfc00d200, "Ro(b)" },
	{ 0x2c001200, 0xfc001200, "Ro(Rb)" },
	{ 0x2c001200, 0xfc00de00, "Ro(b)" },
	{ 0x2c001200, 0xfc001e00, "Ro(Rb)" },
	
	{ 0xe800f000, 0xfc1ffffd, "(R)" },
	{ 0xe800a000, 0xffe0e000, "i" },
	{ 0xe840d000, 0xfffffffd, "" },
};

static void print_operand(MCInst *MI, struct SStream *O, const cs_hppa_op *op)
{
	switch (op->type) {
	case HPPA_OP_INVALID:
		SStream_concat(O, "invalid");
		break;
	case HPPA_OP_REG:
		SStream_concat(O, HPPA_reg_name((csh)MI->csh, op->reg));
		break;
	case HPPA_OP_IMM:
		printInt64(O, op->imm);
		break;
    case HPPA_OP_DISP:
		printInt64(O, op->imm);
		break;
	case HPPA_OP_IDX_REG:
		SStream_concat(O, HPPA_reg_name((csh)MI->csh, op->reg));
		break;
	case HPPA_OP_MEM:
		SStream_concat(O, "(");
		if (op->mem.space != HPPA_OP_INVALID) {
			SStream_concat(O, HPPA_reg_name((csh)MI->csh, op->mem.space));
			SStream_concat(O, ",");
		}
		SStream_concat(O, HPPA_reg_name((csh)MI->csh, op->mem.base));
		SStream_concat(O, ")");
		break;
	case HPPA_OP_TARGET:
		printInt64(O, MI->address + op->imm);
		break;
	}
}

#define NUMFMTS ((sizeof pa_formats)/(sizeof pa_formats[0]))

static void fill_operands(MCInst *MI, cs_hppa *hppa)
{
	unsigned mc_op_count = MCInst_getNumOperands(MI);
	MCOperand *ops[mc_op_count];
	for (unsigned i = 0; i < mc_op_count; i++) {
		ops[i] = MCInst_getOperand(MI, i);
	}

	hppa->op_count = 0;
	hppa_ext *hppa_ext = &MI->hppa;
    uint32_t instr = hppa_ext->full_insn;

    for (int i = 0; i < NUMFMTS; ++i) {
		const struct pa_insn_fmt *pa_fmt = &pa_formats[i];
		if ((instr & pa_fmt->mask) == pa_fmt->match) {
			char *fmt = (char *)pa_fmt->format;
            uint8_t idx = 0;
            while (*fmt)
			{
				switch (*fmt++)
				{
           	    case 'i':
					set_op_imm(hppa, MCOperand_getImm(ops[idx++]));
                    break;
                case 'o':
                    set_op_disp(hppa, MCOperand_getImm(ops[idx++]));
                    break;
				
				case 'R':
					set_op_reg(hppa, MCOperand_getReg(ops[idx++]), CS_AC_READ);
					break;

				case 'W':
					set_op_reg(hppa, MCOperand_getReg(ops[idx++]), CS_AC_WRITE);
					break;

				case 'w':
					set_op_reg(hppa, MCOperand_getReg(ops[idx++]), CS_AC_READ_WRTE);
					break;

				case 'r':
					set_op_idx_reg(hppa, MCOperand_getReg(ops[idx++]));
					break;

				case 'T':
					set_op_target(hppa, MCOperand_getImm(ops[idx++]) + 8);
					break;

				case 'Y':
					set_op_reg(hppa, MCOperand_getReg(ops[idx++]), CS_AC_WRITE);
					set_op_reg(hppa, MCOperand_getReg(ops[idx++]), CS_AC_WRITE);
					break;

				case '0':
					set_op_reg(hppa, MCOperand_getReg(ops[idx++]), CS_AC_INVALID);
					break;

				case '(':
					uint32_t regs[2] = { HPPA_REG_INVALID, HPPA_REG_INVALID };
					uint8_t reg_idx = 0;
					cs_ac_type base_access = CS_AC_INVALID;
					while (*fmt != ')') {
						regs[reg_idx] = MCOperand_getReg(ops[idx++]);
						if (*fmt == 'R') {
							base_access = CS_AC_READ;
						} else if (*fmt == 'W') {
							base_access = CS_AC_WRITE;
						} else if (*fmt == 'b') {
							base_access = CS_AC_READ; 
							if (hppa_ext->b_writeble)
								base_access |= CS_AC_WRITE;
						}
						fmt++;
						reg_idx++;
					}

					if (regs[1] == HPPA_OP_INVALID)
						set_op_mem(hppa, regs[0], regs[1], base_access);
					else 
						set_op_mem(hppa, regs[1], regs[0], base_access);
					fmt++;
					break;

				default:
					printf("Unknown: %c\n", *(fmt-1));
					break;
				}
			}
			
            break;
        }
    }

}

static void print_modifiers(MCInst *MI, struct SStream *O) 
{
    hppa_ext *hppa_ext = &MI->hppa;
    for (uint8_t i = 0; i < hppa_ext->mod_num; ++i) {
        SStream_concat(O, ",");
        if (hppa_ext->modifiers[i].type == 0)
            SStream_concat(O, hppa_ext->modifiers[i].str_mod);
        else 
            printInt64(O, hppa_ext->modifiers[i].int_mod);
    }
}

void HPPA_printInst(MCInst *MI, struct SStream *O, void *Info)
{
	cs_insn insn;
	cs_hppa hppa;

	insn.detail = NULL;
	/* set pubOpcode as instruction id */
	HPPA_get_insn_id((cs_struct *)MI->csh, &insn, MCInst_getOpcode(MI));
	MCInst_setOpcodePub(MI, insn.id);

	SStream_concat(O, HPPA_insn_name((csh)MI->csh, insn.id));
    print_modifiers(MI, O);
	SStream_concat(O, "\t");
	fill_operands(MI, &hppa);
	for (int i = 0; i < hppa.op_count; i++) {
		cs_hppa_op *op = &hppa.operands[i];
		print_operand(MI, O, op);
		if (op->type != HPPA_OP_IDX_REG && op->type != HPPA_OP_DISP && 
            i != hppa.op_count-1) {
			SStream_concat(O, ",");
		}
		
	}

#ifndef CAPSTONE_DIET
	if (MI->flat_insn->detail) {
		MI->flat_insn->detail->hppa = hppa;
	}
#endif
}

#endif