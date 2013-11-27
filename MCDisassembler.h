/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#ifndef __CS_MCDISASSEMBLER_H__
#define __CS_MCDISASSEMBLER_H__ 

typedef enum DecodeStatus {
	MCDisassembler_Fail = 0,
	MCDisassembler_SoftFail = 1,
	MCDisassembler_Success = 3,
} DecodeStatus;

#endif

