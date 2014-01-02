#ifndef CAPSTONE_MC_DISASSEMBLER_H_2E7A4C41945948898BD1613609E8955F
#define CAPSTONE_MC_DISASSEMBLER_H_2E7A4C41945948898BD1613609E8955F

/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

typedef enum DecodeStatus {
	MCDisassembler_Fail = 0,
	MCDisassembler_SoftFail = 1,
	MCDisassembler_Success = 3,
} DecodeStatus;

#endif

