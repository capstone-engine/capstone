
// Additional instructions only supported on M6801/3
static const inst_pageX g_m6801_inst_overlay_table[] = {
	// 0x0x, inherent instructions
	{ 0x04, M680X_INS_LSRD, inherent_hdlr_id },
	{ 0x05, M680X_INS_ASLD, inherent_hdlr_id },
	// 0x2x, relative branch instructions
	{ 0x21, M680X_INS_BRN, relative8_hdlr_id },
	// 0x3x, inherent instructions
	{ 0x38, M680X_INS_PULX, inherent_hdlr_id },
	{ 0x3A, M680X_INS_ABX, inherent_hdlr_id },
	{ 0x3C, M680X_INS_PSHX, inherent_hdlr_id },
	{ 0x3D, M680X_INS_MUL, inherent_hdlr_id  },
	// 0x8x, immediate instructions with Register D
	{ 0x83, M680X_INS_SUBD, immediate16_hdlr_id },
	// 0x9x, direct instructions with register D
	{ 0x93, M680X_INS_SUBD, direct_hdlr_id },
	{ 0x9D, M680X_INS_JSR, direct_hdlr_id },
	// 0xAx, indexed instructions with Register D
	{ 0xA3, M680X_INS_SUBD, indexedX_hdlr_id },
	// 0xBx, extended instructions with register D
	{ 0xB3, M680X_INS_SUBD, extended_hdlr_id },
	// 0xCx, immediate instructions with register D
	{ 0xC3, M680X_INS_ADDD, immediate16_hdlr_id },
	{ 0xCC, M680X_INS_LDD, immediate16_hdlr_id },
	// 0xDx direct instructions with register D
	{ 0xD3, M680X_INS_ADDD, direct_hdlr_id },
	{ 0xDC, M680X_INS_LDD, direct_hdlr_id },
	{ 0xDD, M680X_INS_STD, direct_hdlr_id },
	// 0xEx, indexed instruction with register D
	{ 0xE3, M680X_INS_ADDD, indexedX_hdlr_id },
	{ 0xEC, M680X_INS_LDD, indexedX_hdlr_id },
	{ 0xED, M680X_INS_STD, indexedX_hdlr_id },
	// 0xFx, extended instructions with register D
	{ 0xF3, M680X_INS_ADDD, extended_hdlr_id },
	{ 0xFC, M680X_INS_LDD, extended_hdlr_id },
	{ 0xFD, M680X_INS_STD, extended_hdlr_id },
};

