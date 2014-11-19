(* Capstone Disassembly Engine
* By Guillaume Jeanne <guillaume.jeanne@ensimag.fr>, 2014> *)

open Printf
open Capstone
open Ppc


let print_string_hex comment str =
	printf "%s" comment;
	for i = 0 to (Array.length str - 1) do
		printf "0x%02x " str.(i)
	done;
	printf "\n"


let _PPC_CODE = "\x80\x20\x00\x00\x80\x3f\x00\x00\x10\x43\x23\x0e\xd0\x44\x00\x80\x4c\x43\x22\x02\x2d\x03\x00\x80\x7c\x43\x20\x14\x7c\x43\x20\x93\x4f\x20\x00\x21\x4c\xc8\x00\x21";;

let all_tests = [
	(CS_ARCH_PPC, [CS_MODE_64; CS_MODE_BIG_ENDIAN], _PPC_CODE, "PPC-64");
];;

let print_op handle i op =
	( match op.value with
	| PPC_OP_INVALID _ -> ();	(* this would never happens *)
	| PPC_OP_REG reg -> printf "\t\top[%d]: REG = %s\n" i (cs_reg_name handle reg);
	| PPC_OP_IMM imm -> printf "\t\top[%d]: IMM = 0x%x\n" i imm;
	| PPC_OP_MEM mem -> ( printf "\t\top[%d]: MEM\n" i;
		if mem.base != 0 then
			printf "\t\t\toperands[%u].mem.base: REG = %s\n" i (cs_reg_name handle mem.base);
		if mem.disp != 0 then
			printf "\t\t\toperands[%u].mem.disp: 0x%x\n" i mem.disp;
		);
	| PPC_OP_CRX crx -> ( printf "\t\top[%d]: CRX\n" i;
		if crx.scale != 0 then
			printf "\t\t\toperands[%u].crx.scale = %u\n" i crx.scale;
		if crx.reg != 0 then
			printf "\t\t\toperands[%u].crx.reg = %s\n" i (cs_reg_name handle crx.reg);
		if crx.cond != 0 then
			printf "\t\t\toperands[%u].crx.cond = 0x%x\n" i crx.cond;
		);
	);
	();;


let print_detail handle insn =
	match insn.arch with
	| CS_INFO_PPC ppc -> (
			(* print all operands info (type & value) *)
			if (Array.length ppc.operands) > 0 then (
				printf "\top_count: %d\n" (Array.length ppc.operands);
				Array.iteri (print_op handle) ppc.operands;
			);
			printf "\n";
		);
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
