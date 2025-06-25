/* Capstone Disassembly Engine */
/* BPF Backend by david942j <david942j@gmail.com>, 2019 */
/* SPDX-FileCopyrightText: 2024 Roee Toledano <roeetoledano10@gmail.com> */
/* SPDX-License-Identifier: BSD-3 */

/* This file defines constants and macros used for parsing a BPF instruction */

#ifndef CS_BPF_CONSTANTS_H
#define CS_BPF_CONSTANTS_H

#define BPF_CLASS(code) ((code) & 0x7)

/// Instruction classes
#define BPF_CLASS_LD 0x00
#define BPF_CLASS_LDX 0x01
#define BPF_CLASS_ST 0x02
#define BPF_CLASS_STX 0x03
#define BPF_CLASS_ALU 0x04
#define BPF_CLASS_JMP 0x05
/// cBPF only
#define BPF_CLASS_RET 0x06
/// eBPF only
#define BPF_CLASS_JMP32 0x06
/// cBPF only
#define BPF_CLASS_MISC 0x07
/// eBPF only
#define BPF_CLASS_ALU64 0x07
#define BPF_OP(code) ((code) & 0xf0)

///< Types of ALU instruction
#define BPF_ALU_ADD 0x00
#define BPF_ALU_SUB 0x10
#define BPF_ALU_MUL 0x20
#define BPF_ALU_DIV 0x30
#define BPF_ALU_OR 0x40
#define BPF_ALU_AND 0x50
#define BPF_ALU_LSH 0x60
#define BPF_ALU_RSH 0x70
#define BPF_ALU_NEG 0x80
#define BPF_ALU_MOD 0x90
#define BPF_ALU_XOR 0xa0
/// eBPF only: mov reg to reg
#define BPF_ALU_MOV 0xb0
/// eBPF only: sign extending shift right
#define BPF_ALU_ARSH 0xc0
/// eBPF only: endianness conversion
#define BPF_ALU_END 0xd0

///< Types of jmp instruction
/// goto
#define BPF_JUMP_JA 0x00
/// '=='
#define BPF_JUMP_JEQ 0x10
/// unsigned '>'
#define BPF_JUMP_JGT 0x20
/// unsigned '>='
#define BPF_JUMP_JGE 0x30
/// '&'
#define BPF_JUMP_JSET 0x40
/// eBPF only: '!=' */
#define BPF_JUMP_JNE 0x50
/// eBPF only: signed '>'
#define BPF_JUMP_JSGT 0x60
/// eBPF only: signed '>='
#define BPF_JUMP_JSGE 0x70
/// eBPF only: function call
#define BPF_JUMP_CALL 0x80
/// eBPF only: exit
#define BPF_JUMP_EXIT 0x90
/// eBPF only: unsigned '<'
#define BPF_JUMP_JLT 0xa0
/// eBPF only: unsigned '<='
#define BPF_JUMP_JLE 0xb0
/// eBPF only: signed '<'
#define BPF_JUMP_JSLT 0xc0
/// eBPF only: signed '<='
#define BPF_JUMP_JSLE 0xd0

/// Types of complex atomic instructions
/// eBPF only: atomic exchange
#define BPF_ATOMIC_XCHG 0xe0
/// eBPF only: atomic compare and exchange
#define BPF_ATOMIC_CMPXCHG 0xf0

#define BPF_SRC(code) ((code) & 0x08)
/// cBPF only: for return types
#define BPF_RVAL(code) ((code) & 0x18)
/// Source operand
#define BPF_SRC_K 0x00
#define BPF_SRC_X 0x08
/// cBPF only
#define BPF_SRC_A 0x10

#define BPF_SRC_LITTLE BPF_SRC_K
#define BPF_SRC_BIG BPF_SRC_X

#define BPF_SIZE(code) ((code) & 0x18)
/// Size modifier
/// word
#define BPF_SIZE_W 0x00
/// half word
#define BPF_SIZE_H 0x08
/// byte
#define BPF_SIZE_B 0x10
/// eBPF only: double word
#define BPF_SIZE_DW 0x18

#define BPF_MODE(code) ((code) & 0xe0)
///< Mode modifier
#define BPF_MODE_IMM 0x00 ///< used for 32-bit mov in cBPF and 64-bit in eBPF
#define BPF_MODE_ABS \
	0x20 ///< absolute indexing of socket buffer. eBPF only, but deprecated in new versions
#define BPF_MODE_IND \
	0x40 ///< indirect indexing of socket buffer. eBPF only, but deprecated in new versions
#define BPF_MODE_MEM 0x60
/// cBPF only, reserved in eBPF
#define BPF_MODE_LEN 0x80
/// cBPF only, reserved in eBPF
#define BPF_MODE_MSH 0xa0
/// eBPF only: atomic operations. Originally BPF_MODE_XADD
#define BPF_MODE_ATOMIC 0xc0

/// eBPF only: overwrite 'src' with what was in the modified mem address before it was modified.
/// NOTE: in contrast to regular modifiers, this one is encoded in the 'imm' field, not opcode!
/// Must be used for BPF_XCHG and BPF_CMPXCHG. Optional for the other atomic operations.
#define BPF_MODE_FETCH 0x01
#define BPF_MISCOP(code) ((code) & 0x80)
/// Operation of misc
#define BPF_MISCOP_TAX 0x00
#define BPF_MISCOP_TXA 0x80

#endif
