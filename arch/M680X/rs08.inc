// RS08 Instructions
static const inst_page1 g_rs08_inst_page1_table[] = {
	// 0x0x DIR
	{ M680X_INS_BRSET, dir_hid, inh_hid }, // 0x00
	{ M680X_INS_BRCLR, dir_hid, inh_hid }, // 0x01
	{ M680X_INS_BRSET, dir_hid, inh_hid }, // 0x02
	{ M680X_INS_BRCLR, dir_hid, inh_hid }, // 0x03
	{ M680X_INS_BRSET, dir_hid, inh_hid }, // 0x04
	{ M680X_INS_BRCLR, dir_hid, inh_hid }, // 0x05
	{ M680X_INS_BRSET, dir_hid, inh_hid }, // 0x06
	{ M680X_INS_BRCLR, dir_hid, inh_hid }, // 0x07
	{ M680X_INS_BRSET, dir_hid, inh_hid }, // 0x08
	{ M680X_INS_BRCLR, dir_hid, inh_hid }, // 0x09
	{ M680X_INS_BRSET, dir_hid, inh_hid }, // 0x0A
	{ M680X_INS_BRCLR, dir_hid, inh_hid }, // 0x0B
	{ M680X_INS_BRSET, dir_hid, inh_hid }, // 0x0C
	{ M680X_INS_BRCLR, dir_hid, inh_hid }, // 0x0D
	{ M680X_INS_BRSET, dir_hid, inh_hid }, // 0x0E
	{ M680X_INS_BRCLR, dir_hid, inh_hid }, // 0x0F

	// 0x10 DIR
	{ M680X_INS_BSET, dir_hid, inh_hid }, // 0x10
	{ M680X_INS_BCLR, dir_hid, inh_hid }, // 0x11
	{ M680X_INS_BSET, dir_hid, inh_hid }, // 0x12
	{ M680X_INS_BCLR, dir_hid, inh_hid }, // 0x13
	{ M680X_INS_BSET, dir_hid, inh_hid }, // 0x14
	{ M680X_INS_BCLR, dir_hid, inh_hid }, // 0x15
	{ M680X_INS_BSET, dir_hid, inh_hid }, // 0x16
	{ M680X_INS_BCLR, dir_hid, inh_hid }, // 0x17
	{ M680X_INS_BSET, dir_hid, inh_hid }, // 0x18
	{ M680X_INS_BCLR, dir_hid, inh_hid }, // 0x19
	{ M680X_INS_BSET, dir_hid, inh_hid }, // 0x1A
	{ M680X_INS_BCLR, dir_hid, inh_hid }, // 0x1B
	{ M680X_INS_BSET, dir_hid, inh_hid }, // 0x1A
	{ M680X_INS_BCLR, dir_hid, inh_hid }, // 0x1D
	{ M680X_INS_BSET, dir_hid, inh_hid }, // 0x1E
	{ M680X_INS_BCLR, dir_hid, inh_hid }, // 0x1F

	// 0x2x TNY
	{ M680X_INS_INC, tny_hid, inh_hid }, // 0x20
	{ M680X_INS_INC, tny_hid, inh_hid }, // 0x21
	{ M680X_INS_INC, tny_hid, inh_hid }, // 0x22
	{ M680X_INS_INC, tny_hid, inh_hid }, // 0x23
	{ M680X_INS_INC, tny_hid, inh_hid }, // 0x24
	{ M680X_INS_INC, tny_hid, inh_hid }, // 0x25
	{ M680X_INS_INC, tny_hid, inh_hid }, // 0x26
	{ M680X_INS_INC, tny_hid, inh_hid }, // 0x27
	{ M680X_INS_INC, tny_hid, inh_hid }, // 0x28
	{ M680X_INS_INC, tny_hid, inh_hid }, // 0x29
	{ M680X_INS_INC, tny_hid, inh_hid }, // 0x2A
	{ M680X_INS_INC, tny_hid, inh_hid }, // 0x2B
	{ M680X_INS_INC, tny_hid, inh_hid }, // 0x2C
	{ M680X_INS_INC, tny_hid, inh_hid }, // 0x2D
	{ M680X_INS_INC, tny_hid, inh_hid }, // 0x2E
	{ M680X_INS_INC, tny_hid, inh_hid }, // 0x2F

	// 0x3x
	{ M680X_INS_BRA, rel8_hid, inh_hid }, // 0x30 BRN
	{ M680X_INS_CBEQA, dir_hid, inh_hid }, // 0x31
	{ M680X_INS_ILLGL, inh_hid, inh_hid }, // 0x32
	{ M680X_INS_ILLGL, inh_hid, inh_hid }, // 0x33
	{ M680X_INS_BCC, rel8_hid, inh_hid }, // 0x34
	{ M680X_INS_BCS, rel8_hid, inh_hid }, // 0x35
	{ M680X_INS_BNE, rel8_hid, inh_hid }, // 0x36
	{ M680X_INS_BEQ, rel8_hid, inh_hid }, // 0x37
	{ M680X_INS_CLC, inh_hid, inh_hid }, // 0x38
	{ M680X_INS_SEC, inh_hid, inh_hid }, // 0x39
	{ M680X_INS_DEC, dir_hid, inh_hid }, // 0x3A
	{ M680X_INS_DBNZ, dir_hid, inh_hid }, // 0x3B
	{ M680X_INS_INC, dir_hid, inh_hid }, // 0x3C
	{ M680X_INS_ILLGL, inh_hid, inh_hid }, // 0x3D
	{ M680X_INS_MOV, immdir_hid, inh_hid }, // 0x3E
	{ M680X_INS_CLR, dir_hid, inh_hid }, // 0x3F

	// 0x4x
	{ M680X_INS_ILLGL, inh_hid, inh_hid }, // 0x40
	{ M680X_INS_CBEQA, imm8_hid, inh_hid }, // 0x41
	{ M680X_INS_SLA, inh_hid, inh_hid }, // 0x42
	{ M680X_INS_COMA, inh_hid, inh_hid }, // 0x43
	{ M680X_INS_LSRA, inh_hid, inh_hid }, // 0x44
	{ M680X_INS_SHA, inh_hid, inh_hid }, // 0x45
	{ M680X_INS_RORA, inh_hid, inh_hid }, // 0x46
	{ M680X_INS_ILLGL, inh_hid, inh_hid }, // 0x47
	{ M680X_INS_LSLA, inh_hid, inh_hid }, // 0x48
	{ M680X_INS_ROLA, inh_hid, inh_hid }, // 0x49
	{ M680X_INS_DECA, inh_hid, inh_hid }, // 0x4A
	{ M680X_INS_DBNZA, inh_hid, inh_hid }, // 0x4B
	{ M680X_INS_INCA, inh_hid, inh_hid }, // 0x4C
	{ M680X_INS_ILLGL, inh_hid, inh_hid }, // 0x4D
	{ M680X_INS_MOV, dirdir_hid, inh_hid }, // 0x4E
	{ M680X_INS_CLRA, inh_hid, inh_hid }, // 0x4F

	// 0x5x TNY
	{ M680X_INS_DEC, tny_hid, inh_hid }, // 0x50
	{ M680X_INS_DEC, tny_hid, inh_hid }, // 0X51
	{ M680X_INS_DEC, tny_hid, inh_hid }, // 0X52
	{ M680X_INS_DEC, tny_hid, inh_hid }, // 0X53
	{ M680X_INS_DEC, tny_hid, inh_hid }, // 0X54
	{ M680X_INS_DEC, tny_hid, inh_hid }, // 0X55
	{ M680X_INS_DEC, tny_hid, inh_hid }, // 0X56
	{ M680X_INS_DEC, tny_hid, inh_hid }, // 0X57
	{ M680X_INS_DEC, tny_hid, inh_hid }, // 0X58
	{ M680X_INS_DEC, tny_hid, inh_hid }, // 0X59
	{ M680X_INS_DEC, tny_hid, inh_hid }, // 0X5A
	{ M680X_INS_DEC, tny_hid, inh_hid }, // 0X5B
	{ M680X_INS_DEC, tny_hid, inh_hid }, // 0X5C
	{ M680X_INS_DEC, tny_hid, inh_hid }, // 0X5D
	{ M680X_INS_DEC, tny_hid, inh_hid }, // 0X5E
	{ M680X_INS_DEC, tny_hid, inh_hid }, // 0X5F

	// 0x6x TNY
	{ M680X_INS_ADD, tny_hid, inh_hid }, // 0x60
	{ M680X_INS_ADD, tny_hid, inh_hid }, // 0x61
	{ M680X_INS_ADD, tny_hid, inh_hid }, // 0x62
	{ M680X_INS_ADD, tny_hid, inh_hid }, // 0x63
	{ M680X_INS_ADD, tny_hid, inh_hid }, // 0x64
	{ M680X_INS_ADD, tny_hid, inh_hid }, // 0x65
	{ M680X_INS_ADD, tny_hid, inh_hid }, // 0x66
	{ M680X_INS_ADD, tny_hid, inh_hid }, // 0x67
	{ M680X_INS_ADD, tny_hid, inh_hid }, // 0x68
	{ M680X_INS_ADD, tny_hid, inh_hid }, // 0x69
	{ M680X_INS_ADD, tny_hid, inh_hid }, // 0x6A
	{ M680X_INS_ADD, tny_hid, inh_hid }, // 0x6B
	{ M680X_INS_ADD, tny_hid, inh_hid }, // 0x6C
	{ M680X_INS_ADD, tny_hid, inh_hid }, // 0x6D
	{ M680X_INS_ADD, tny_hid, inh_hid }, // 0x6E
	{ M680X_INS_ADD, tny_hid, inh_hid }, // 0x6F

	// 0x7x TNY
	{ M680X_INS_SUB, tny_hid, inh_hid }, // 0x70
	{ M680X_INS_SUB, tny_hid, inh_hid }, // 0x71
	{ M680X_INS_SUB, tny_hid, inh_hid }, // 0x72
	{ M680X_INS_SUB, tny_hid, inh_hid }, // 0x73
	{ M680X_INS_SUB, tny_hid, inh_hid }, // 0x74
	{ M680X_INS_SUB, tny_hid, inh_hid }, // 0x75
	{ M680X_INS_SUB, tny_hid, inh_hid }, // 0x76
	{ M680X_INS_SUB, tny_hid, inh_hid }, // 0x77
	{ M680X_INS_SUB, tny_hid, inh_hid }, // 0x78
	{ M680X_INS_SUB, tny_hid, inh_hid }, // 0x79
	{ M680X_INS_SUB, tny_hid, inh_hid }, // 0x7A
	{ M680X_INS_SUB, tny_hid, inh_hid }, // 0x7B
	{ M680X_INS_SUB, tny_hid, inh_hid }, // 0x70
	{ M680X_INS_SUB, tny_hid, inh_hid }, // 0x7D
	{ M680X_INS_SUB, tny_hid, inh_hid }, // 0x7E
	{ M680X_INS_SUB, tny_hid, inh_hid }, // 0x7F

	// 0x8x SRT
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x80
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x81
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x82
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x83
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x84
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x85
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x86
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x87
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x88
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x89
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x8A
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x8B
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x8C
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x8D
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x8E
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x8F

	// 0x9x SRT
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x90
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x91
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x92
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x93
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x94
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x95
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x96
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x97
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x98
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x99
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x9A
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x9B
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x9C
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x9D
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x9E
	{ M680X_INS_CLR, srt_hid, inh_hid }, // 0x9F

	// 0xAx
	{ M680X_INS_SUB, imm8_hid, inh_hid }, // 0xA0
	{ M680X_INS_CMP, imm8_hid, inh_hid }, // 0xA1
	{ M680X_INS_SBC, imm8_hid, inh_hid }, // 0xA2
	{ M680X_INS_ILLGL, inh_hid, inh_hid }, // 0xA3
	{ M680X_INS_AND, imm8_hid, inh_hid }, // 0xA4
	{ M680X_INS_ILLGL, inh_hid, inh_hid }, // 0xA5
	{ M680X_INS_LDA, imm8_hid, inh_hid }, // 0xA6
	{ M680X_INS_ILLGL, inh_hid, inh_hid }, // 0xA7
	{ M680X_INS_EOR, imm8_hid, inh_hid }, // 0xA8
	{ M680X_INS_ADC, imm8_hid, inh_hid }, // 0xA9
	{ M680X_INS_ORA, imm8_hid, inh_hid }, // 0xAA
	{ M680X_INS_ADD, imm8_hid, inh_hid }, // 0xAB
	{ M680X_INS_NOP, inh_hid, inh_hid }, // 0xAC
	{ M680X_INS_BSR, rel8_hid, inh_hid }, // 0xAD
	{ M680X_INS_STOP, inh_hid, inh_hid }, // 0xAE
	{ M680X_INS_WAIT, inh_hid, inh_hid }, // 0xAF

	// 0xBx DIR
	{ M680X_INS_SUB, dir_hid, inh_hid }, // 0xB0
	{ M680X_INS_CMP, dir_hid, inh_hid }, // 0xB1
	{ M680X_INS_SBC, dir_hid, inh_hid }, // 0xB2
	{ M680X_INS_ILLGL, inh_hid, inh_hid }, // 0xB3
	{ M680X_INS_AND, dir_hid, inh_hid }, // 0xB4
	{ M680X_INS_ILLGL, inh_hid, inh_hid }, // 0xB5
	{ M680X_INS_LDA, dir_hid, inh_hid }, // 0xB6
	{ M680X_INS_STA, dir_hid, inh_hid }, // 0xB7
	{ M680X_INS_EOR, dir_hid, inh_hid }, // 0xB8
	{ M680X_INS_ADC, dir_hid, inh_hid }, // 0xB9
	{ M680X_INS_ORA, dir_hid, inh_hid }, // 0xBA
	{ M680X_INS_ADD, dir_hid, inh_hid }, // 0xBB
	{ M680X_INS_JMP, ext_hid, inh_hid }, // 0xBC
	{ M680X_INS_JSR, ext_hid, inh_hid }, // 0xBD
	{ M680X_INS_RTS, inh_hid, inh_hid }, // 0xBE
	{ M680X_INS_BGND, inh_hid, inh_hid }, // 0xBF

	// 0xCx SRT
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xC0
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xC1
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xC2
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xC3
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xC4
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xC5
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xC6
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xC7
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xC8
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xC9
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xCA
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xCB
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xCC
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xCD
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xCE
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xCF

	// 0xDx SRT
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xD0
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xD1
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xD2
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xD3
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xD4
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xD5
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xD6
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xD7
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xD8
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xD9
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xDA
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xDB
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xDC
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xDD
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xDE
	{ M680X_INS_LDA, srt_hid, inh_hid }, // 0xDF

	// 0xEx SRT
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xE0
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xE1
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xE2
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xE3
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xE4
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xE5
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xE6
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xE7
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xE8
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xE9
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xEA
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xEB
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xEC
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xED
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xEE
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xEF

	// 0xFx SRT
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xF0
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xF1
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xF2
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xF3
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xF4
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xF5
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xF6
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xF7
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xF8
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xF9
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xFA
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xFB
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xFC
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xFD
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xFE
	{ M680X_INS_STA, srt_hid, inh_hid }, // 0xFF
};