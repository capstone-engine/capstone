/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifndef CS_TRICOREDISASSEMBLER_H
#define CS_TRICOREDISASSEMBLER_H

#if !defined(_MSC_VER) || !defined(_KERNEL_MODE)
#include <stdint.h>
#endif

#include <capstone/capstone.h>
#include "../../MCRegisterInfo.h"
#include "../../MCInst.h"


typedef enum tricore_opcode_arch_val_t
{
	TRICORE_GENERIC = 0x00000000,
	TRICORE_RIDER_A = 0x00000001,
#define TRICORE_V1_1    TRICORE_RIDER_A
	TRICORE_V1_2 	  = 0x00000002,
	TRICORE_V1_3    = 0x00000004,
	TRICORE_V1_3_1  = 0x00000100,
	TRICORE_V1_6    = 0x00000200,
	TRICORE_V1_6_1  = 0x00000400,
	TRICORE_V1_6_2  = 0x00000800,
	TRICORE_PCP     = 0x00000010,
	TRICORE_PCP2    = 0x00000020
} TriCoreISA;


/* Some handy definitions for upward/downward compatibility of insns.  */

//#define TRICORE_V2_UP      TRICORE_V2
#define TRICORE_V1_6_2_UP (TRICORE_V1_6_2)
#define TRICORE_V1_6_1_UP (TRICORE_V1_6_1 | TRICORE_V1_6_2_UP)
#define TRICORE_V1_6_UP   (TRICORE_V1_6 | TRICORE_V1_6_1_UP)
#define TRICORE_V1_3_1_UP (TRICORE_V1_3_1 | TRICORE_V1_6_UP)
#define TRICORE_V1_3_UP   (TRICORE_V1_3 | TRICORE_V1_3_1_UP)
#define TRICORE_V1_2_UP   (TRICORE_V1_2 | TRICORE_V1_3_UP)

#define TRICORE_V1_2_DN    TRICORE_V1_2
#define TRICORE_V1_3_DN   (TRICORE_V1_3 | TRICORE_V1_2_DN )
#define TRICORE_V1_3_X_DN (TRICORE_V1_3 | TRICORE_V1_2_DN | TRICORE_V1_3_1)
#define TRICORE_V1_3_1_DN (TRICORE_V1_3_1 | TRICORE_V1_3_DN)
#define TRICORE_V1_6_DN   (TRICORE_V1_6 | TRICORE_V1_3_1_DN)
#define TRICORE_V1_6_1_DN (TRICORE_V1_6_1 | TRICORE_V1_6_DN)
#define TRICORE_V1_6_2_DN (TRICORE_V1_6_2 | TRICORE_V1_6_1_DN)

void TriCore_init(MCRegisterInfo *MRI);

bool TriCore_getInstruction(csh ud, const uint8_t *code, size_t code_len,
		MCInst *instr, uint16_t *size, uint64_t address, void *info);

#endif

