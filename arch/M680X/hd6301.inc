
// Additional instructions only supported on HD6301/3
static const inst_pageX g_hd6301_inst_overlay_table[] = {
	{ 0x1B, M680X_INS_XGDX, inherent_hdlr_id },
	{ 0x61, M680X_INS_AIM, imm_indexedX_hdlr_id },
	{ 0x62, M680X_INS_OIM, imm_indexedX_hdlr_id },
	{ 0x65, M680X_INS_EIM, imm_indexedX_hdlr_id },
	{ 0x6B, M680X_INS_TIM, imm_indexedX_hdlr_id },
	{ 0x71, M680X_INS_AIM, imm_direct_hdlr_id },
	{ 0x72, M680X_INS_OIM, imm_direct_hdlr_id },
	{ 0x75, M680X_INS_EIM, imm_direct_hdlr_id },
	{ 0x7B, M680X_INS_TIM, imm_direct_hdlr_id },
};

