(* Capstone Disassembler Engine
 * By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> *)

open Printf
open List
open Capstone

let _X86_CODE16 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00";;
let _X86_CODE32 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00";;
let _X86_CODE64 = "\x55\x48\x8b\x05\xb8\x13\x00\x00";;
let _ARM_CODE = "\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3";;
let _ARM_CODE2 = "\x10\xf1\x10\xe7\x11\xf2\x31\xe7\xdc\xa1\x2e\xf3\xe8\x4e\x62\xf3";;
let _THUMB_CODE = "\x70\x47\xeb\x46\x83\xb0\xc9\x68";;
let _THUMB_CODE2 = "\x4f\xf0\x00\x01\xbd\xe8\x00\x88";;
let _MIPS_CODE = "\x0C\x10\x00\x97\x00\x00\x00\x00\x24\x02\x00\x0c\x8f\xa2\x00\x00\x34\x21\x34\x56";;
let _MIPS_CODE2 = "\x56\x34\x21\x34\xc2\x17\x01\x00";;
let _ARM64_CODE = "\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9";;

let all_tests = [
	(CS_ARCH_X86, [CS_MODE_16], _X86_CODE16, "X86 16bit (Intel syntax)");
	(CS_ARCH_X86, [CS_MODE_32; CS_MODE_SYNTAX_ATT], _X86_CODE32, "X86 32bit (ATT syntax)");
	(CS_ARCH_X86, [CS_MODE_32], _X86_CODE32, "X86 32 (Intel syntax)");
	(CS_ARCH_X86, [CS_MODE_64], _X86_CODE64, "X86 64 (Intel syntax)");
	(CS_ARCH_ARM, [CS_MODE_ARM], _ARM_CODE, "ARM");
	(CS_ARCH_ARM, [CS_MODE_ARM], _ARM_CODE2, "ARM: Cortex-A15 + NEON");
	(CS_ARCH_ARM, [CS_MODE_THUMB], _THUMB_CODE, "THUMB");
	(CS_ARCH_ARM, [CS_MODE_THUMB], _THUMB_CODE2, "THUMB-2");
	(CS_ARCH_ARM64, [CS_MODE_ARM], _ARM64_CODE, "ARM-64");
	(CS_ARCH_MIPS, [CS_MODE_32; CS_MODE_BIG_ENDIAN], _MIPS_CODE, "MIPS-32 (Big-endian)");
	(CS_ARCH_MIPS, [CS_MODE_64;CS_MODE_LITTLE_ENDIAN], _MIPS_CODE2, "MIPS-64-EL (Little-endian)");
];;


let print_insn insn =
	printf "0x%x\t%s\t%s\n" insn.address insn.mnemonic insn.op_str;;

let print_arch x =
	let (arch, mode, code, comment) = x in
		let insns = cs_disasm_quick arch mode code 0x1000L 0L in
			printf "*************\n";
			printf "Platform: %s\n" comment;
			List.iter print_insn insns;;


List.iter print_arch all_tests;;


let print_insn_cls insn =
	printf "0x%x\t%s\t%s\n" insn#address insn#mnemonic insn#op_str;;

let print_arch_cls x =
	let (arch, mode, code, comment) = x in (
		let d = new cs arch mode in
			let insns = d#disasm code 0x1000L 0L in
				printf "*************\n";
				printf "Platform: %s\n" comment;
				List.iter print_insn_cls insns;
	);;

List.iter print_arch_cls all_tests;;

