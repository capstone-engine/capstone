(* Capstone Disassembly Engine
* By Guillaume Jeanne <guillaume.jeanne@ensimag.fr>, 2014> *)

open Printf
open Capstone
open Systemz


let print_string_hex comment str =
	printf "%s" comment;
	for i = 0 to (Array.length str - 1) do
		printf "0x%02x " str.(i)
	done;
	printf "\n"


let _SYSZ_CODE = "\xed\x00\x00\x00\x00\x1a\x5a\x0f\x1f\xff\xc2\x09\x80\x00\x00\x00\x07\xf7\xeb\x2a\xff\xff\x7f\x57\xe3\x01\xff\xff\x7f\x57\xeb\x00\xf0\x00\x00\x24\xb2\x4f\x00\x78";;



let all_tests = [
	(CS_ARCH_SYSZ, [CS_MODE_LITTLE_ENDIAN], _SYSZ_CODE, "SystemZ");
];;

let print_op handle i op =
	( match op.value with
	| SYSZ_OP_INVALID _ -> ();	(* this would never happens *)
	| SYSZ_OP_REG reg -> printf "\t\top[%d]: REG = %s\n" i (cs_reg_name handle reg);
	| SYSZ_OP_ACREG reg -> printf "\t\top[%d]: ACREG = %u\n" i reg;
	| SYSZ_OP_IMM imm -> printf "\t\top[%d]: IMM = 0x%x\n" i imm;
	| SYSZ_OP_MEM mem -> ( printf "\t\top[%d]: MEM\n" i;
		if mem.base != 0 then
			printf "\t\t\toperands[%u].mem.base: REG = %s\n" i (cs_reg_name handle mem.base);
		if mem.index != 0 then
			printf "\t\t\toperands[%u].mem.index: 0x%x\n" i mem.index;
		if mem.length != 0L then
			printf "\t\t\toperands[%u].mem.length: 0x%Lx\n" i mem.length;
		if mem.disp != 0L then
			printf "\t\t\toperands[%u].mem.disp: 0x%Lx\n" i mem.disp;
		);
	);
	();;


let print_detail handle insn =
	match insn.arch with
	| CS_INFO_SYSZ sysz -> (
			(* print all operands info (type & value) *)
			if (Array.length sysz.operands) > 0 then (
				printf "\top_count: %d\n" (Array.length sysz.operands);
				Array.iteri (print_op handle) sysz.operands;
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
