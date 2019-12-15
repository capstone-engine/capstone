/* Capstone Disassembly Engine */
/* MOS65XX Backend by Sebastian Macke <sebastian@macke.de> 2018 */

#include "capstone/mos65xx.h"
#include "MOS65XXDisassembler.h"

typedef struct OpInfo {
	mos65xx_insn ins;
	mos65xx_address_mode am;
} OpInfo;

static const struct OpInfo OpInfoTable[]= {
	{ MOS65XX_INS_BRK    , MOS65XX_AM_IMP  }, // 0x00
	{ MOS65XX_INS_ORA    , MOS65XX_AM_INDX }, // 0x01
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x02
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x03
	{ MOS65XX_INS_NOP    , MOS65XX_AM_ZP   }, // 0x04
	{ MOS65XX_INS_ORA    , MOS65XX_AM_ZP   }, // 0x05
	{ MOS65XX_INS_ASL    , MOS65XX_AM_ZP   }, // 0x06
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x07
	{ MOS65XX_INS_PHP    , MOS65XX_AM_IMP  }, // 0x08
	{ MOS65XX_INS_ORA    , MOS65XX_AM_IMM  }, // 0x09
	{ MOS65XX_INS_ASL    , MOS65XX_AM_ACC  }, // 0x0a
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x0b
	{ MOS65XX_INS_NOP    , MOS65XX_AM_ABS  }, // 0x0c
	{ MOS65XX_INS_ORA    , MOS65XX_AM_ABS  }, // 0x0d
	{ MOS65XX_INS_ASL    , MOS65XX_AM_ABS  }, // 0x0e
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x0f
	{ MOS65XX_INS_BPL    , MOS65XX_AM_REL  }, // 0x10
	{ MOS65XX_INS_ORA    , MOS65XX_AM_INDY }, // 0x11
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x12
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x13
	{ MOS65XX_INS_NOP    , MOS65XX_AM_ZPX  }, // 0x14
	{ MOS65XX_INS_ORA    , MOS65XX_AM_ZPX  }, // 0x15
	{ MOS65XX_INS_ASL    , MOS65XX_AM_ZPX  }, // 0x16
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x17
	{ MOS65XX_INS_CLC    , MOS65XX_AM_IMP  }, // 0x18
	{ MOS65XX_INS_ORA    , MOS65XX_AM_ABSY }, // 0x19
	{ MOS65XX_INS_NOP    , MOS65XX_AM_IMP  }, // 0x1a
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x1b
	{ MOS65XX_INS_NOP    , MOS65XX_AM_ABS  }, // 0x1c
	{ MOS65XX_INS_ORA    , MOS65XX_AM_ABSX }, // 0x1d
	{ MOS65XX_INS_ASL    , MOS65XX_AM_ABSX }, // 0x1e
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x1f
	{ MOS65XX_INS_JSR    , MOS65XX_AM_ABS  }, // 0x20
	{ MOS65XX_INS_AND    , MOS65XX_AM_INDX }, // 0x21
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x22
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x23
	{ MOS65XX_INS_BIT    , MOS65XX_AM_ZP   }, // 0x24
	{ MOS65XX_INS_AND    , MOS65XX_AM_ZP   }, // 0x25
	{ MOS65XX_INS_ROL    , MOS65XX_AM_ZP   }, // 0x26
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x27
	{ MOS65XX_INS_PLP    , MOS65XX_AM_IMP  }, // 0x28
	{ MOS65XX_INS_AND    , MOS65XX_AM_IMM  }, // 0x29
	{ MOS65XX_INS_ROL    , MOS65XX_AM_ACC  }, // 0x2a
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x2b
	{ MOS65XX_INS_BIT    , MOS65XX_AM_ABS  }, // 0x2c
	{ MOS65XX_INS_AND    , MOS65XX_AM_ABS  }, // 0x2d
	{ MOS65XX_INS_ROL    , MOS65XX_AM_ABS  }, // 0x2e
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x2f
	{ MOS65XX_INS_BMI    , MOS65XX_AM_REL  }, // 0x30
	{ MOS65XX_INS_AND    , MOS65XX_AM_INDY }, // 0x31
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x32
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x33
	{ MOS65XX_INS_NOP    , MOS65XX_AM_ZPX  }, // 0x34
	{ MOS65XX_INS_AND    , MOS65XX_AM_ZPX  }, // 0x35
	{ MOS65XX_INS_ROL    , MOS65XX_AM_ZPX  }, // 0x36
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x37
	{ MOS65XX_INS_SEC    , MOS65XX_AM_IMP  }, // 0x38
	{ MOS65XX_INS_AND    , MOS65XX_AM_ABSY }, // 0x39
	{ MOS65XX_INS_NOP    , MOS65XX_AM_IMP  }, // 0x3a
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x3b
	{ MOS65XX_INS_NOP    , MOS65XX_AM_ABSX }, // 0x3c
	{ MOS65XX_INS_AND    , MOS65XX_AM_ABSX }, // 0x3d
	{ MOS65XX_INS_ROL    , MOS65XX_AM_ABSX }, // 0x3e
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x3f
	{ MOS65XX_INS_RTI    , MOS65XX_AM_IMP  }, // 0x40
	{ MOS65XX_INS_EOR    , MOS65XX_AM_INDX }, // 0x41
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x42
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x43
	{ MOS65XX_INS_NOP    , MOS65XX_AM_ZP   }, // 0x44
	{ MOS65XX_INS_EOR    , MOS65XX_AM_ZP   }, // 0x45
	{ MOS65XX_INS_LSR    , MOS65XX_AM_ZP   }, // 0x46
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x47
	{ MOS65XX_INS_PHA    , MOS65XX_AM_IMP  }, // 0x48
	{ MOS65XX_INS_EOR    , MOS65XX_AM_IMM  }, // 0x49
	{ MOS65XX_INS_LSR    , MOS65XX_AM_ACC  }, // 0x4a
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x4b
	{ MOS65XX_INS_JMP    , MOS65XX_AM_ABS  }, // 0x4c
	{ MOS65XX_INS_EOR    , MOS65XX_AM_ABS  }, // 0x4d
	{ MOS65XX_INS_LSR    , MOS65XX_AM_ABS  }, // 0x4e
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x4f
	{ MOS65XX_INS_BVC    , MOS65XX_AM_REL  }, // 0x50
	{ MOS65XX_INS_EOR    , MOS65XX_AM_INDY }, // 0x51
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x52
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x53
	{ MOS65XX_INS_NOP    , MOS65XX_AM_ZPX  }, // 0x54
	{ MOS65XX_INS_EOR    , MOS65XX_AM_ZPX  }, // 0x55
	{ MOS65XX_INS_LSR    , MOS65XX_AM_ZPX  }, // 0x56
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x57
	{ MOS65XX_INS_CLI    , MOS65XX_AM_IMP  }, // 0x58
	{ MOS65XX_INS_EOR    , MOS65XX_AM_ABSY }, // 0x59
	{ MOS65XX_INS_NOP    , MOS65XX_AM_IMP  }, // 0x5a
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x5b
	{ MOS65XX_INS_NOP    , MOS65XX_AM_ABSX }, // 0x5c
	{ MOS65XX_INS_EOR    , MOS65XX_AM_ABSX }, // 0x5d
	{ MOS65XX_INS_LSR    , MOS65XX_AM_ABSX }, // 0x5e
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x5f
	{ MOS65XX_INS_RTS    , MOS65XX_AM_IMP  }, // 0x60
	{ MOS65XX_INS_ADC    , MOS65XX_AM_INDX }, // 0x61
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x62
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x63
	{ MOS65XX_INS_NOP    , MOS65XX_AM_ZP   }, // 0x64
	{ MOS65XX_INS_ADC    , MOS65XX_AM_ZP   }, // 0x65
	{ MOS65XX_INS_ROR    , MOS65XX_AM_ZP   }, // 0x66
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x67
	{ MOS65XX_INS_PLA    , MOS65XX_AM_IMP  }, // 0x68
	{ MOS65XX_INS_ADC    , MOS65XX_AM_IMM  }, // 0x69
	{ MOS65XX_INS_ROR    , MOS65XX_AM_ACC  }, // 0x6a
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x6b
	{ MOS65XX_INS_JMP    , MOS65XX_AM_IND  }, // 0x6c
	{ MOS65XX_INS_ADC    , MOS65XX_AM_ABS  }, // 0x6d
	{ MOS65XX_INS_ROR    , MOS65XX_AM_ABS  }, // 0x6e
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x6f
	{ MOS65XX_INS_BVS    , MOS65XX_AM_REL  }, // 0x70
	{ MOS65XX_INS_ADC    , MOS65XX_AM_INDY }, // 0x71
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x72
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x73
	{ MOS65XX_INS_NOP    , MOS65XX_AM_ZPX  }, // 0x74
	{ MOS65XX_INS_ADC    , MOS65XX_AM_ZPX  }, // 0x75
	{ MOS65XX_INS_ROR    , MOS65XX_AM_ZPX  }, // 0x76
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x77
	{ MOS65XX_INS_SEI    , MOS65XX_AM_IMP  }, // 0x78
	{ MOS65XX_INS_ADC    , MOS65XX_AM_ABSY }, // 0x79
	{ MOS65XX_INS_NOP    , MOS65XX_AM_IMP  }, // 0x7a
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x7b
	{ MOS65XX_INS_NOP    , MOS65XX_AM_ABSX }, // 0x7c
	{ MOS65XX_INS_ADC    , MOS65XX_AM_ABSX }, // 0x7d
	{ MOS65XX_INS_ROR    , MOS65XX_AM_ABSX }, // 0x7e
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x7f
	{ MOS65XX_INS_NOP    , MOS65XX_AM_IMP  }, // 0x80
	{ MOS65XX_INS_STA    , MOS65XX_AM_INDX }, // 0x81
	{ MOS65XX_INS_NOP    , MOS65XX_AM_IMP  }, // 0x82
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x83
	{ MOS65XX_INS_STY    , MOS65XX_AM_ZP   }, // 0x84
	{ MOS65XX_INS_STA    , MOS65XX_AM_ZP   }, // 0x85
	{ MOS65XX_INS_STX    , MOS65XX_AM_ZP   }, // 0x86
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x87
	{ MOS65XX_INS_DEY    , MOS65XX_AM_IMP  }, // 0x88
	{ MOS65XX_INS_NOP    , MOS65XX_AM_IMP  }, // 0x89
	{ MOS65XX_INS_TXA    , MOS65XX_AM_IMP  }, // 0x8a
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x8b
	{ MOS65XX_INS_STY    , MOS65XX_AM_ABS  }, // 0x8c
	{ MOS65XX_INS_STA    , MOS65XX_AM_ABS  }, // 0x8d
	{ MOS65XX_INS_STX    , MOS65XX_AM_ABS  }, // 0x8e
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x8f
	{ MOS65XX_INS_BCC    , MOS65XX_AM_REL  }, // 0x90
	{ MOS65XX_INS_STA    , MOS65XX_AM_INDY }, // 0x91
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x92
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x93
	{ MOS65XX_INS_STY    , MOS65XX_AM_ZPX  }, // 0x94
	{ MOS65XX_INS_STA    , MOS65XX_AM_ZPX  }, // 0x95
	{ MOS65XX_INS_STX    , MOS65XX_AM_ZPY  }, // 0x96
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x97
	{ MOS65XX_INS_TYA    , MOS65XX_AM_IMP  }, // 0x98
	{ MOS65XX_INS_STA    , MOS65XX_AM_ABSY }, // 0x99
	{ MOS65XX_INS_TXS    , MOS65XX_AM_IMP  }, // 0x9a
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x9b
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x9c
	{ MOS65XX_INS_STA    , MOS65XX_AM_ABSX }, // 0x9d
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x9e
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0x9f
	{ MOS65XX_INS_LDY    , MOS65XX_AM_IMM  }, // 0xa0
	{ MOS65XX_INS_LDA    , MOS65XX_AM_INDX }, // 0xa1
	{ MOS65XX_INS_LDX    , MOS65XX_AM_IMM  }, // 0xa2
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xa3
	{ MOS65XX_INS_LDY    , MOS65XX_AM_ZP   }, // 0xa4
	{ MOS65XX_INS_LDA    , MOS65XX_AM_ZP   }, // 0xa5
	{ MOS65XX_INS_LDX    , MOS65XX_AM_ZP   }, // 0xa6
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xa7
	{ MOS65XX_INS_TAY    , MOS65XX_AM_IMP  }, // 0xa8
	{ MOS65XX_INS_LDA    , MOS65XX_AM_IMM  }, // 0xa9
	{ MOS65XX_INS_TAX    , MOS65XX_AM_IMP  }, // 0xaa
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xab
	{ MOS65XX_INS_LDY    , MOS65XX_AM_ABS  }, // 0xac
	{ MOS65XX_INS_LDA    , MOS65XX_AM_ABS  }, // 0xad
	{ MOS65XX_INS_LDX    , MOS65XX_AM_ABS  }, // 0xae
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xaf
	{ MOS65XX_INS_BCS    , MOS65XX_AM_REL  }, // 0xb0
	{ MOS65XX_INS_LDA    , MOS65XX_AM_INDY }, // 0xb1
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xb2
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xb3
	{ MOS65XX_INS_LDY    , MOS65XX_AM_ZPX  }, // 0xb4
	{ MOS65XX_INS_LDA    , MOS65XX_AM_ZPX  }, // 0xb5
	{ MOS65XX_INS_LDX    , MOS65XX_AM_ZPY  }, // 0xb6
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xb7
	{ MOS65XX_INS_CLV    , MOS65XX_AM_IMP  }, // 0xb8
	{ MOS65XX_INS_LDA    , MOS65XX_AM_ABSY }, // 0xb9
	{ MOS65XX_INS_TSX    , MOS65XX_AM_IMP  }, // 0xba
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xbb
	{ MOS65XX_INS_LDY    , MOS65XX_AM_ABSX }, // 0xbc
	{ MOS65XX_INS_LDA    , MOS65XX_AM_ABSX }, // 0xbd
	{ MOS65XX_INS_LDX    , MOS65XX_AM_ABSY }, // 0xbe
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xbf
	{ MOS65XX_INS_CPY    , MOS65XX_AM_IMM  }, // 0xc0
	{ MOS65XX_INS_CMP    , MOS65XX_AM_INDX }, // 0xc1
	{ MOS65XX_INS_NOP    , MOS65XX_AM_IMP  }, // 0xc2
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xc3
	{ MOS65XX_INS_CPY    , MOS65XX_AM_ZP   }, // 0xc4
	{ MOS65XX_INS_CMP    , MOS65XX_AM_ZP   }, // 0xc5
	{ MOS65XX_INS_DEC    , MOS65XX_AM_ZP   }, // 0xc6
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xc7
	{ MOS65XX_INS_INY    , MOS65XX_AM_IMP  }, // 0xc8
	{ MOS65XX_INS_CMP    , MOS65XX_AM_IMM  }, // 0xc9
	{ MOS65XX_INS_DEX    , MOS65XX_AM_IMP  }, // 0xca
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xcb
	{ MOS65XX_INS_CPY    , MOS65XX_AM_ABS  }, // 0xcc
	{ MOS65XX_INS_CMP    , MOS65XX_AM_ABS  }, // 0xcd
	{ MOS65XX_INS_DEC    , MOS65XX_AM_ABS  }, // 0xce
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xcf
	{ MOS65XX_INS_BNE    , MOS65XX_AM_REL  }, // 0xd0
	{ MOS65XX_INS_CMP    , MOS65XX_AM_INDY }, // 0xd1
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xd2
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xd3
	{ MOS65XX_INS_NOP    , MOS65XX_AM_ZPX  }, // 0xd4
	{ MOS65XX_INS_CMP    , MOS65XX_AM_ZPX  }, // 0xd5
	{ MOS65XX_INS_DEC    , MOS65XX_AM_ZPX  }, // 0xd6
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xd7
	{ MOS65XX_INS_CLD    , MOS65XX_AM_IMP  }, // 0xd8
	{ MOS65XX_INS_CMP    , MOS65XX_AM_ABSY }, // 0xd9
	{ MOS65XX_INS_NOP    , MOS65XX_AM_IMP  }, // 0xda
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xdb
	{ MOS65XX_INS_NOP    , MOS65XX_AM_ABSX }, // 0xdc
	{ MOS65XX_INS_CMP    , MOS65XX_AM_ABSX }, // 0xdd
	{ MOS65XX_INS_DEC    , MOS65XX_AM_ABSX }, // 0xde
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xdf
	{ MOS65XX_INS_CPX    , MOS65XX_AM_IMM  }, // 0xe0
	{ MOS65XX_INS_SBC    , MOS65XX_AM_INDX }, // 0xe1
	{ MOS65XX_INS_NOP    , MOS65XX_AM_IMP  }, // 0xe2
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xe3
	{ MOS65XX_INS_CPX    , MOS65XX_AM_ZP   }, // 0xe4
	{ MOS65XX_INS_SBC    , MOS65XX_AM_ZP   }, // 0xe5
	{ MOS65XX_INS_INC    , MOS65XX_AM_ZP   }, // 0xe6
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xe7
	{ MOS65XX_INS_INX    , MOS65XX_AM_IMP  }, // 0xe8
	{ MOS65XX_INS_SBC    , MOS65XX_AM_IMM  }, // 0xe9
	{ MOS65XX_INS_NOP    , MOS65XX_AM_IMP  }, // 0xea
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xeb
	{ MOS65XX_INS_CPX    , MOS65XX_AM_ABS  }, // 0xec
	{ MOS65XX_INS_SBC    , MOS65XX_AM_ABS  }, // 0xed
	{ MOS65XX_INS_INC    , MOS65XX_AM_ABS  }, // 0xee
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xef
	{ MOS65XX_INS_BEQ    , MOS65XX_AM_REL  }, // 0xf0
	{ MOS65XX_INS_SBC    , MOS65XX_AM_INDY }, // 0xf1
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xf2
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xf3
	{ MOS65XX_INS_NOP    , MOS65XX_AM_ZPX  }, // 0xf4
	{ MOS65XX_INS_SBC    , MOS65XX_AM_ZPX  }, // 0xf5
	{ MOS65XX_INS_INC    , MOS65XX_AM_ZPX  }, // 0xf6
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xf7
	{ MOS65XX_INS_SED    , MOS65XX_AM_IMP  }, // 0xf8
	{ MOS65XX_INS_SBC    , MOS65XX_AM_ABSY }, // 0xf9
	{ MOS65XX_INS_NOP    , MOS65XX_AM_IMP  }, // 0xfa
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xfb
	{ MOS65XX_INS_NOP    , MOS65XX_AM_ABSX }, // 0xfc
	{ MOS65XX_INS_SBC    , MOS65XX_AM_ABSX }, // 0xfd
	{ MOS65XX_INS_INC    , MOS65XX_AM_ABSX }, // 0xfe
	{ MOS65XX_INS_INVALID, MOS65XX_AM_NONE }, // 0xff
};

static const char* RegNames[] = {
	"invalid", "A", "X", "Y", "P", "SP"
};

#ifndef CAPSTONE_DIET
static const char* GroupNames[] = {
	NULL,
	"jump",
	"call",
	"ret",
	NULL,
	"iret",
	"branch_relative"
};

typedef struct InstructionInfo {
	const char* name;
	mos65xx_group_type group_type;
	mos65xx_reg write, read;
	bool modifies_status;
} InstructionInfo;

static const struct InstructionInfo InstructionInfoTable[]= {
	{ "invalid", MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, false },
	{ "adc",     MOS65XX_GRP_INVALID,         MOS65XX_REG_ACC, MOS65XX_REG_INVALID, true },
	{ "and",     MOS65XX_GRP_INVALID,         MOS65XX_REG_ACC,     MOS65XX_REG_INVALID, true },
	{ "asl",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "bcc",     MOS65XX_GRP_BRANCH_RELATIVE, MOS65XX_REG_INVALID, MOS65XX_REG_P,       false },
	{ "bcs",     MOS65XX_GRP_BRANCH_RELATIVE, MOS65XX_REG_INVALID, MOS65XX_REG_P,       false },
	{ "beq",     MOS65XX_GRP_BRANCH_RELATIVE, MOS65XX_REG_INVALID, MOS65XX_REG_P,       false },
	{ "bit",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "bmi",     MOS65XX_GRP_BRANCH_RELATIVE, MOS65XX_REG_INVALID, MOS65XX_REG_P,       false },
	{ "bne",     MOS65XX_GRP_BRANCH_RELATIVE, MOS65XX_REG_INVALID, MOS65XX_REG_P,       false },
	{ "bpl",     MOS65XX_GRP_BRANCH_RELATIVE, MOS65XX_REG_INVALID, MOS65XX_REG_P,       false },
	{ "brk",     MOS65XX_GRP_INVALID,         MOS65XX_REG_SP,      MOS65XX_REG_INVALID, false },
	{ "bvc",     MOS65XX_GRP_BRANCH_RELATIVE, MOS65XX_REG_INVALID, MOS65XX_REG_P,       false },
	{ "bvs",     MOS65XX_GRP_BRANCH_RELATIVE, MOS65XX_REG_INVALID, MOS65XX_REG_P,       false },
	{ "clc",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "cld",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "cli",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "clv",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "cmp",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_ACC,     true },
	{ "cpx",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_X,       true },
	{ "cpy",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_Y,       true },
	{ "dec",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "dex",     MOS65XX_GRP_INVALID,         MOS65XX_REG_X,       MOS65XX_REG_X,       true },
	{ "dey",     MOS65XX_GRP_INVALID,         MOS65XX_REG_Y,       MOS65XX_REG_Y,       true },
	{ "eor",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "inc",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "inx",     MOS65XX_GRP_INVALID,         MOS65XX_REG_X,       MOS65XX_REG_X,       true },
	{ "iny",     MOS65XX_GRP_INVALID,         MOS65XX_REG_Y,       MOS65XX_REG_Y,       true },
	{ "jmp",     MOS65XX_GRP_JUMP,            MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, false },
	{ "jsr",     MOS65XX_GRP_CALL,            MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, false },
	{ "lda",     MOS65XX_GRP_INVALID,         MOS65XX_REG_ACC,     MOS65XX_REG_INVALID, true },
	{ "ldx",     MOS65XX_GRP_INVALID,         MOS65XX_REG_X,       MOS65XX_REG_INVALID, true },
	{ "ldy",     MOS65XX_GRP_INVALID,         MOS65XX_REG_Y,       MOS65XX_REG_INVALID, true },
	{ "lsr",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "nop",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, false },
	{ "ora",     MOS65XX_GRP_INVALID,         MOS65XX_REG_ACC,     MOS65XX_REG_INVALID, true },
	{ "pha",     MOS65XX_GRP_INVALID,         MOS65XX_REG_SP,      MOS65XX_REG_ACC,     false },
	{ "pla",     MOS65XX_GRP_INVALID,         MOS65XX_REG_ACC,     MOS65XX_REG_SP,      true },
	{ "php",     MOS65XX_GRP_INVALID,         MOS65XX_REG_SP,      MOS65XX_REG_P,       false },
	{ "plp",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_SP,      true },
	{ "rol",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "ror",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "rti",     MOS65XX_GRP_IRET,            MOS65XX_REG_SP,      MOS65XX_REG_INVALID, true },
	{ "rts",     MOS65XX_GRP_RET,             MOS65XX_REG_SP,      MOS65XX_REG_INVALID, false },
	{ "sbc",     MOS65XX_GRP_INVALID,         MOS65XX_REG_ACC,     MOS65XX_REG_INVALID, true },
	{ "sec",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "sed",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "sei",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_INVALID, true },
	{ "sta",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_ACC,     false },
	{ "stx",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_X,       false },
	{ "sty",     MOS65XX_GRP_INVALID,         MOS65XX_REG_INVALID, MOS65XX_REG_Y,       false },
	{ "tax",     MOS65XX_GRP_INVALID,         MOS65XX_REG_X,       MOS65XX_REG_ACC,     true },
	{ "tay",     MOS65XX_GRP_INVALID,         MOS65XX_REG_Y,       MOS65XX_REG_ACC,     true },
	{ "tsx",     MOS65XX_GRP_INVALID,         MOS65XX_REG_X,       MOS65XX_REG_SP,      true },
	{ "txa",     MOS65XX_GRP_INVALID,         MOS65XX_REG_ACC,     MOS65XX_REG_X,       true },
	{ "txs",     MOS65XX_GRP_INVALID,         MOS65XX_REG_SP,      MOS65XX_REG_X,       true },
	{ "tya",     MOS65XX_GRP_INVALID,         MOS65XX_REG_ACC,     MOS65XX_REG_Y,       true },
};
#endif

static int getInstructionLength(mos65xx_address_mode am)
{
	switch(am) {
		case MOS65XX_AM_NONE:
		case MOS65XX_AM_ACC:
		case MOS65XX_AM_IMP:
			return 1;

		case MOS65XX_AM_IMM:
		case MOS65XX_AM_ZPX:
		case MOS65XX_AM_ZPY:
		case MOS65XX_AM_ZP:
		case MOS65XX_AM_REL:
		case MOS65XX_AM_INDX:
		case MOS65XX_AM_INDY:
			return 2;

		case MOS65XX_AM_ABS:
		case MOS65XX_AM_ABSX:
		case MOS65XX_AM_ABSY:
		case MOS65XX_AM_IND:
			return 3;
		default:
			return 1;
	}
}

#ifndef CAPSTONE_DIET
static void fillDetails(MCInst *MI, unsigned char opcode)
{
	cs_detail *detail = MI->flat_insn->detail;
	mos65xx_insn ins = OpInfoTable[opcode].ins;
	mos65xx_address_mode am = OpInfoTable[opcode].am;

	detail->mos65xx.am = am;
	detail->mos65xx.modifies_flags = InstructionInfoTable[ins].modifies_status;
	detail->groups_count = 0;
	detail->regs_read_count = 0;
	detail->regs_write_count = 0;
	detail->mos65xx.op_count = 0;

	if (InstructionInfoTable[ins].group_type != MOS65XX_GRP_INVALID) {
		detail->groups[0] = InstructionInfoTable[ins].group_type;
		detail->groups_count++;
	}

	if (InstructionInfoTable[ins].read != MOS65XX_REG_INVALID) {
		detail->regs_read[detail->regs_read_count++] = InstructionInfoTable[ins].read;
	} else if (OpInfoTable[opcode].am == MOS65XX_AM_ACC) {
		detail->regs_read[detail->regs_read_count++] = MOS65XX_REG_ACC;
	} else if (OpInfoTable[opcode].am == MOS65XX_AM_INDY || OpInfoTable[opcode].am == MOS65XX_AM_ABSY || OpInfoTable[opcode].am == MOS65XX_AM_ZPY) {
		detail->regs_read[detail->regs_read_count++] = MOS65XX_REG_Y;
	} else if (OpInfoTable[opcode].am == MOS65XX_AM_INDX || OpInfoTable[opcode].am == MOS65XX_AM_ABSX || OpInfoTable[opcode].am == MOS65XX_AM_ZPX) {
		detail->regs_read[detail->regs_read_count++] = MOS65XX_REG_X;
	}

	if (InstructionInfoTable[ins].write != MOS65XX_REG_INVALID) {
		detail->regs_write[detail->regs_write_count++] = InstructionInfoTable[ins].write;
	} else if (OpInfoTable[opcode].am == MOS65XX_AM_ACC) {
		detail->regs_write[detail->regs_write_count++] = MOS65XX_REG_ACC;
	}

	if (InstructionInfoTable[ins].modifies_status) {
		detail->regs_write[detail->regs_write_count++] = MOS65XX_REG_P;
	}

	switch(am) {
		case MOS65XX_AM_IMP:
		case MOS65XX_AM_REL:
			break;
		case MOS65XX_AM_IMM:
			detail->mos65xx.operands[detail->mos65xx.op_count].type = MOS65XX_OP_IMM;
			detail->mos65xx.operands[detail->mos65xx.op_count].mem = MI->Operands[0].ImmVal;
			detail->mos65xx.op_count++;
			break;
		case MOS65XX_AM_ACC:
			detail->mos65xx.operands[detail->mos65xx.op_count].type = MOS65XX_OP_REG;
			detail->mos65xx.operands[detail->mos65xx.op_count].reg = MOS65XX_REG_ACC;
			detail->mos65xx.op_count++;
			break;
		default:
			detail->mos65xx.operands[detail->mos65xx.op_count].type = MOS65XX_OP_MEM;
			detail->mos65xx.operands[detail->mos65xx.op_count].mem = MI->Operands[0].ImmVal;
			detail->mos65xx.op_count++;
			break;
	}
}
#endif

void MOS65XX_printInst(MCInst *MI, struct SStream *O, void *PrinterInfo)
{
#ifndef CAPSTONE_DIET
	unsigned char opcode = MI->Opcode;
	unsigned int value = MI->Operands[0].ImmVal;

	SStream_concat0(O, InstructionInfoTable[OpInfoTable[MI->Opcode].ins].name);

	switch (OpInfoTable[opcode].am) {
		default:
			break;

		case MOS65XX_AM_IMP:
			break;

		case MOS65XX_AM_ACC:
			SStream_concat(O, " a");
			break;

		case MOS65XX_AM_ABS:
			SStream_concat(O, " $0x%04x", value);
			break;

		case MOS65XX_AM_IMM:
			SStream_concat(O, " #$0x%02x", value);
			break;

		case MOS65XX_AM_ZP:
			SStream_concat(O, " $0x%02x", value);
			break;

		case MOS65XX_AM_ABSX:
			SStream_concat(O, " $0x%04x, x", value);
			break;

		case MOS65XX_AM_ABSY:
			SStream_concat(O, " $0x%04x, y", value);
			break;

		case MOS65XX_AM_ZPX:
			SStream_concat(O, " $0x%02x, x", value);
			break;

		case MOS65XX_AM_ZPY:
			SStream_concat(O, " $0x%02x, y", value);
			break;

		case MOS65XX_AM_REL:
			SStream_concat(O, " $0x%04x", MI->address + (signed char) value + 2);
			break;

		case MOS65XX_AM_IND:
			SStream_concat(O, " ($0x%04x)", value);
			break;

		case MOS65XX_AM_INDX:
			SStream_concat(O, " ($0x%02x, x)", value);
			break;

		case MOS65XX_AM_INDY:
			SStream_concat(O, " ($0x%02x), y", value);
			break;
	}
#endif
}

bool MOS65XX_getInstruction(csh ud, const uint8_t *code, size_t code_len,
							MCInst *MI, uint16_t *size, uint64_t address, void *inst_info)
{
	unsigned char opcode;
	unsigned char len;
	mos65xx_insn ins;

	if (code_len == 0) {
		*size = 1;
		return false;
	}

	opcode = code[0];
	ins = OpInfoTable[opcode].ins;
	if (ins == MOS65XX_INS_INVALID) {
		*size = 1;
		return false;
	}

	len = getInstructionLength(OpInfoTable[opcode].am);
	if (code_len < len) {
		*size = 1;
		return false;
	}

	MI->address = address;
	MI->Opcode = opcode;
	MI->OpcodePub = ins;
	MI->size = 0;

	*size = len;
	if (len == 2) {
		MCOperand_CreateImm0(MI, code[1]);
	} else
	if (len == 3) {
		MCOperand_CreateImm0(MI, (code[2]<<8) | code[1]);
	}
#ifndef CAPSTONE_DIET
	if (MI->flat_insn->detail) {
		fillDetails(MI, opcode);
	}
#endif

	return true;
}

const char *MOS65XX_insn_name(csh handle, unsigned int id)
{
#ifdef CAPSTONE_DIET
	return NULL;
#else
	if (id >= ARR_SIZE(InstructionInfoTable)) {
		return NULL;
	}
	return InstructionInfoTable[id].name;
#endif
}

const char* MOS65XX_reg_name(csh handle, unsigned int reg)
{
#ifdef CAPSTONE_DIET
	return NULL;
#else
	if (reg >= ARR_SIZE(RegNames)) {
		return NULL;
	}
	return RegNames[(int)reg];
#endif
}

void MOS65XX_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	if (id < 256) {
		insn->id = OpInfoTable[id].ins;
	}
}

const char *MOS65XX_group_name(csh handle, unsigned int id)
{
#ifdef CAPSTONE_DIET
	return NULL;
#else
	if (id >= ARR_SIZE(GroupNames)) {
		return NULL;
	}
	return GroupNames[(int)id];
#endif
}
