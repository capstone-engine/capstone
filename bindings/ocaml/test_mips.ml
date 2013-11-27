(* Capstone Disassembler Engine
* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> *)

open Printf
open Capstone
open Mips


let print_string_hex comment str =
	printf "%s" comment;
	for i = 0 to (Array.length str - 1) do
		printf "0x%02x " str.(i)
	done;
	printf "\n"


let _MIPS_CODE  = "\x0C\x10\x00\x97\x00\x00\x00\x00\x24\x02\x00\x0c\x8f\xa2\x00\x00\x34\x21\x34\x56";;
let _MIPS_CODE2 = "\x56\x34\x21\x34\xc2\x17\x01\x00";;

let all_tests = [
	(CS_ARCH_MIPS, [CS_MODE_32; CS_MODE_BIG_ENDIAN], _MIPS_CODE, "MIPS-32 (Big-endian)");
	(CS_ARCH_MIPS, [CS_MODE_64; CS_MODE_LITTLE_ENDIAN], _MIPS_CODE2, "MIPS-64-EL (Little-endian)");
];;

let print_op i op =
	( match op.value with
	| MIPS_OP_INVALID _ -> ();	(* this would never happens *)
	| MIPS_OP_REG reg -> printf "\t\top[%d]: REG = %s\n" i (cs_reg_name CS_ARCH_MIPS reg);
	| MIPS_OP_IMM imm -> printf "\t\top[%d]: IMM = 0x%x\n" i imm;
	| MIPS_OP_MEM mem -> ( printf "\t\top[%d]: MEM\n" i;
		if mem.base != 0 then
			printf "\t\t\toperands[%u].mem.base: REG = %s\n" i (cs_reg_name CS_ARCH_MIPS mem.base);
		if mem.displ != 0 then
			printf "\t\t\toperands[%u].mem.disp: 0x%x\n" i mem.displ;
		);
	);

	();;


let print_detail arch =
	match arch with
	| CS_INFO_ARM _ -> ();
	| CS_INFO_ARM64 _ -> ();
	| CS_INFO_X86 _ -> ();
	| CS_INFO_MIPS mips ->

	(* print all operands info (type & value) *)
	if (Array.length mips.operands) > 0 then (
		printf "\top_count: %d\n" (Array.length mips.operands);
		Array.iteri print_op mips.operands;
	);
	printf "\n";;


let print_insn insn =
	printf "0x%x\t%s\t%s\n" insn.address insn.mnemonic insn.op_str;
	print_detail insn.arch;;


let print_arch x =
	let (arch, mode, code, comment) = x in
		let insns = cs_disasm_quick arch mode code 0x1000L 0L in
			printf "*************\n";
			printf "Platform: %s\n" comment;
			List.iter print_insn insns;;


(*
List.iter print_arch all_tests;;
*)


(* all below code use OO class of Capstone *)
let print_insn_cls insn =
	printf "0x%x\t%s\t%s\n" insn#address insn#mnemonic insn#op_str;
	print_detail insn#arch;;


let print_arch_cls x =
	let (arch, mode, code, comment) = x in (
		let d = new cs arch mode in
			let insns = d#disasm code 0x1000L 0L in
				printf "*************\n";
				printf "Platform: %s\n" comment;
				List.iter print_insn_cls insns;
	);;

List.iter print_arch_cls all_tests;;
