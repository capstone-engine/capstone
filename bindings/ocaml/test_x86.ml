(* Capstone Disassembly Engine
* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 *)

open Printf
open Capstone
open X86
open X86_const


let print_string_hex comment str =
	printf "%s" comment;
	for i = 0 to (Array.length str - 1) do
		printf "0x%02x " str.(i)
	done;
	printf "\n"


let _X86_CODE16 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00";;
let _X86_CODE32 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00";;
let _X86_CODE64 = "\x55\x48\x8b\x05\xb8\x13\x00\x00";;


let all_tests = [
	(CS_ARCH_X86, [CS_MODE_16], _X86_CODE16, "X86 16bit (Intel syntax)", 0L);
	(CS_ARCH_X86, [CS_MODE_32], _X86_CODE32, "X86 32bit (ATT syntax)", _CS_OPT_SYNTAX_ATT);
	(CS_ARCH_X86, [CS_MODE_32], _X86_CODE32, "X86 32 (Intel syntax)", 0L);
	(CS_ARCH_X86, [CS_MODE_64], _X86_CODE64, "X86 64 (Intel syntax)", 0L);
];;

let print_op handle i op =
	( match op.value with
	| X86_OP_INVALID _ -> ();	(* this would never happens *)
	| X86_OP_REG reg -> printf "\t\top[%d]: REG = %s\n" i (cs_reg_name handle reg);
	| X86_OP_IMM imm -> printf "\t\top[%d]: IMM = 0x%x\n" i imm;
	| X86_OP_FP fp -> printf "\t\top[%d]: FP = %f\n" i fp;
	| X86_OP_MEM mem -> ( printf "\t\top[%d]: MEM\n" i;
		if mem.base != 0 then
			printf "\t\t\toperands[%u].mem.base: REG = %s\n" i (cs_reg_name handle  mem.base);
		if mem.index != 0 then
			printf "\t\t\toperands[%u].mem.index: REG = %s\n" i (cs_reg_name handle mem.index);
		if mem.scale != 1 then
			printf "\t\t\toperands[%u].mem.scale: %d\n" i mem.scale;
		if mem.disp != 0 then
			printf "\t\t\toperands[%u].mem.disp: 0x%x\n" i mem.disp;
		);
	);
	();;


let print_detail handle mode insn =
	match insn.arch with
	| CS_INFO_X86 x86 -> (
			print_string_hex "\tPrefix: " x86.prefix;

			(* print instruction's opcode *)
			print_string_hex "\tOpcode: " x86.opcode;

			(* print operand's size, address size, displacement size & immediate size *)
			printf "\taddr_size: %u\n" x86.addr_size;

			(* print modRM byte *)
			printf "\tmodrm: 0x%x\n" x86.modrm;

			(* print displacement value *)
			if x86.disp != 0 then
			printf "\tdisp: 0x%x\n" x86.disp;

			(* SIB is invalid in 16-bit mode *)
			if not (List.mem CS_MODE_16 mode) then (
				(* print SIB byte *)
				printf "\tsib: 0x%x\n" x86.sib;

				(* print sib index/scale/base (if applicable) *)
				if x86.sib_index != _X86_REG_INVALID then
				printf "\tsib_index: %s, sib_scale: %u, sib_base: %s\n"
				(cs_reg_name handle x86.sib_index)
				x86.sib_scale
				(cs_reg_name handle x86.sib_base);
			);

			(* print all operands info (type & value) *)
			if (Array.length x86.operands) > 0 then (
				printf "\top_count: %d\n" (Array.length x86.operands);
				Array.iteri (print_op handle) x86.operands;
			);
			printf "\n";
	);
	| _ -> ();
	;;


let print_insn handle mode insn =
	printf "0x%x\t%s\t%s\n" insn.address insn.mnemonic insn.op_str;
	print_detail handle mode insn


let print_arch x =
	let (arch, mode, code, comment, syntax) = x in
	let handle = cs_open arch mode in (
		if syntax != 0L then (
			let err = cs_option handle CS_OPT_SYNTAX syntax in
			match err with
			| _ -> ();
		);
		let err = cs_option handle CS_OPT_DETAIL _CS_OPT_ON in
		match err with
		| _ -> ();
		let insns = cs_disasm handle code 0x1000L 0L in (
			printf "*************\n";
			printf "Platform: %s\n" comment;
			List.iter (print_insn handle mode) insns;
		);
		match cs_close handle with
		| 0 -> ();
		| _ -> printf "Failed to close handle";
	);;

List.iter print_arch all_tests;;
