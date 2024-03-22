/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev  <sibirtsevdl@gmail.com>, 2023 */

/* This file defines constants and macros used for parsing a HPPA instruction */

#ifndef CS_HPPA_CONSTANTS_H
#define CS_HPPA_CONSTANTS_H

#define HPPA_OP_TYPE(byte) (byte) >> 2
#define MODE_IS_HPPA_20(mode) (((mode)&CS_MODE_HPPA_20) != 0)
#define MODE_IS_HPPA_20W(mode) (((mode) & (1 << 3)) != 0)

///> HPPA opcode types
#define HPPA_OP_TYPE_SYSOP 0x00
#define HPPA_OP_TYPE_MEMMGMT 0x01
#define HPPA_OP_TYPE_ALU 0x02
#define HPPA_OP_TYPE_IDXMEM 0x03
#define HPPA_OP_TYPE_SPOP 0x04
#define HPPA_OP_TYPE_DIAG 0x05
#define HPPA_OP_TYPE_FMPYADD 0x06
#define HPPA_OP_TYPE_LDIL 0x08
#define HPPA_OP_TYPE_COPRW 0x09
#define HPPA_OP_TYPE_ADDIL 0x0a
#define HPPA_OP_TYPE_COPRDW 0x0b
#define HPPA_OP_TYPE_COPR 0x0c
#define HPPA_OP_TYPE_LDO 0x0d
#define HPPA_OP_TYPE_FLOAT 0x0e
#define HPPA_OP_TYPE_PRDSPEC 0x0f
#define HPPA_OP_TYPE_LDB 0x10
#define HPPA_OP_TYPE_LDH 0x11
#define HPPA_OP_TYPE_LDW 0x12
#define HPPA_OP_TYPE_LDWM 0x13
#define HPPA_OP_TYPE_LOADDW 0x14
#define HPPA_OP_TYPE_FLDW 0x16
#define HPPA_OP_TYPE_LOADW 0x17
#define HPPA_OP_TYPE_STB 0x18
#define HPPA_OP_TYPE_STH 0x19
#define HPPA_OP_TYPE_STW 0x1a
#define HPPA_OP_TYPE_STWM 0x1b
#define HPPA_OP_TYPE_STOREDW 0x1c
#define HPPA_OP_TYPE_FSTW 0x1e
#define HPPA_OP_TYPE_STOREW 0x1f
#define HPPA_OP_TYPE_CMPBT 0x20
#define HPPA_OP_TYPE_CMPIBT 0x21
#define HPPA_OP_TYPE_CMPBF 0x22
#define HPPA_OP_TYPE_CMPIBF 0x23
#define HPPA_OP_TYPE_CMPICLR 0x24
#define HPPA_OP_TYPE_SUBI 0x25
#define HPPA_OP_TYPE_FMPYSUB 0x26
#define HPPA_OP_TYPE_CMPBDWT 0x27
#define HPPA_OP_TYPE_ADDBT 0x28
#define HPPA_OP_TYPE_ADDIBT 0x29
#define HPPA_OP_TYPE_ADDBF 0x2a
#define HPPA_OP_TYPE_ADDIBF 0x2b
#define HPPA_OP_TYPE_ADDIT 0x2c
#define HPPA_OP_TYPE_ADDI 0x2d
#define HPPA_OP_TYPE_FPFUSED 0x2e
#define HPPA_OP_TYPE_CMPBDWF 0x2f
#define HPPA_OP_TYPE_BBS 0x30
#define HPPA_OP_TYPE_BB 0x31
#define HPPA_OP_TYPE_MOVB 0x32
#define HPPA_OP_TYPE_MOVIB 0x33
#define HPPA_OP_TYPE_SHEXDEP0 0x34
#define HPPA_OP_TYPE_SHEXDEP1 0x35
#define HPPA_OP_TYPE_SHEXDEP2 0x36
#define HPPA_OP_TYPE_BE 0x38
#define HPPA_OP_TYPE_BLE 0x39
#define HPPA_OP_TYPE_BRANCH 0x3a
#define HPPA_OP_TYPE_CMPIBDW 0x3b
#define HPPA_OP_TYPE_SHEXDEP3 0x3c
#define HPPA_OP_TYPE_SHEXDEP4 0x3d
#define HPPA_OP_TYPE_MULTMED 0x3e

#endif // CS_HPPA_CONSTANTS_H