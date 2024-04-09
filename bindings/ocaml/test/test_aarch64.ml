(* Capstone Disassembly Engine
* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 *)

open Printf
open Capstone
open Aarch64
open Aarch64_const

let _AARCH64_CODE = "\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9\x20\x04\x81\xda\x20\x08\x02\x8b";;

let all_tests = [
        (CS_ARCH_AARCH64, [CS_MODE_ARM], _AARCH64_CODE, "ARM-64");
];;

let print_op handle i op =
	( match op.value with
	| AARCH64_OP_INVALID _ -> ();	(* this would never happens *)
	| AARCH64_OP_REG reg -> printf "\t\top[%d]: REG = %s\n" i (cs_reg_name handle reg);
	| AARCH64_OP_CIMM imm -> printf "\t\top[%d]: C-IMM = %u\n" i imm;
	| AARCH64_OP_IMM imm -> printf "\t\top[%d]: IMM = 0x%x\n" i imm;
	| AARCH64_OP_FP fp -> printf "\t\top[%d]: FP = %f\n" i fp;
	| AARCH64_OP_MEM mem -> ( printf "\t\top[%d]: MEM\n" i;
		if mem.base != 0 then
			printf "\t\t\toperands[%u].mem.base: REG = %s\n" i (cs_reg_name handle mem.base);
		if mem.index != 0 then
			printf "\t\t\toperands[%u].mem.index: REG = %s\n" i (cs_reg_name handle mem.index);
		if mem.disp != 0 then
			printf "\t\t\toperands[%u].mem.disp: 0x%x\n" i mem.disp;
		);
	| AARCH64_OP_REG_MRS reg -> printf "\t\top[%d]: REG_MRS = %u\n" i reg;
	| AARCH64_OP_REG_MSR reg -> printf "\t\top[%d]: REG_MSR = %u\n" i reg;
	| AARCH64_OP_PSTATE v -> printf "\t\top[%d]: PSTATE = %u\n" i v;
	| AARCH64_OP_SYS v -> printf "\t\top[%d]: SYS = %u\n" i v;
	| AARCH64_OP_PREFETCH v -> printf "\t\top[%d]: PREFETCH = %u\n" i v;
	| AARCH64_OP_BARRIER v -> printf "\t\top[%d]: BARRIER = %u\n" i v;
	);

	if op.shift.shift_type != _AARCH64_SFT_INVALID && op.shift.shift_value > 0 then
		printf "\t\t\tShift: type = %u, value = %u\n"
                op.shift.shift_type op.shift.shift_value;
	if op.ext != _AARCH64_EXT_INVALID then
		printf "\t\t\tExt: %u\n" op.ext;

	();;


let print_detail handle insn =
	match insn.arch with
	| CS_INFO_AARCH64 aarch64 -> (
			if aarch64.cc != _AARCH64_CC_AL && aarch64.cc != _AARCH64_CC_INVALID then
			printf "\tCode condition: %u\n" aarch64.cc;

			if aarch64.update_flags then
			printf "\tUpdate-flags: True\n";

			if aarch64.writeback then
			printf "\tWriteback: True\n";

			(* print all operands info (type & value) *)
			if (Array.length aarch64.operands) > 0 then (
				printf "\top_count: %d\n" (Array.length aarch64.operands);
				Array.iteri (print_op handle) aarch64.operands;
			);
			printf "\n";
		)
	| _ -> ();
	;;


let print_insn handle insn =
	printf "0x%x\t%s\t%s\n" insn.address insn.mnemonic insn.op_str;
	print_detail handle insn


let print_arch x =
	let (arch, mode, code, comment) = x in
		let handle = cs_open arch mode in
		let err = cs_option handle CS_OPT_DETAIL _CS_OPT_ON in
		match err with
		| _ -> ();
		let insns = cs_disasm handle code 0x1000L 0L in
			printf "*************\n";
			printf "Platform: %s\n" comment;
			List.iter (print_insn handle) insns;
		match cs_close handle with
		| 0 -> ();
		| _ -> printf "Failed to close handle";
		;;



List.iter print_arch all_tests;;
