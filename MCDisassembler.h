/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#ifndef CAPSTONE_MCDISASSEMBLER_H_FBBF91BBF43140F7A8D1519B73474438
#define CAPSTONE_MCDISASSEMBLER_H_FBBF91BBF43140F7A8D1519B73474438

typedef enum DecodeStatus {
	MCDisassembler_Fail = 0,
	MCDisassembler_SoftFail = 1,
	MCDisassembler_Success = 3,
} DecodeStatus;

#endif

