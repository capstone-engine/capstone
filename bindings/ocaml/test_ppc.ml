(* Capstone Disassembler Engine
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
	(CS_ARCH_PPC, [CS_MODE_32; CS_MODE_BIG_ENDIAN], _PPC_CODE, "PPC-64");
];;

let print_op csh i op =
	( match op with
	| PPC_OP_INVALID _ -> ();	(* this would never happens *)
	| PPC_OP_REG reg -> printf "\t\top[%d]: REG = %s\n" i (cs_reg_name csh reg);
	| PPC_OP_IMM imm -> printf "\t\top[%d]: IMM = 0x%x\n" i imm;
	| PPC_OP_MEM mem -> ( printf "\t\top[%d]: MEM\n" i;
		if mem.base != 0 then
			printf "\t\t\toperands[%u].mem.base: REG = %s\n" i (cs_reg_name csh mem.base);
		if mem.displ != 0 then
			printf "\t\t\toperands[%u].mem.disp: 0x%x\n" i mem.displ;
		);
	);

	();;


let print_detail csh arch =
	match arch with
	| CS_INFO_ARM _ -> ();
	| CS_INFO_ARM64 _ -> ();
	| CS_INFO_MIPS _ -> ();
	| CS_INFO_X86 _ -> ();
	| CS_INFO_PPC ppc ->

	(* print all operands info (type & value) *)
	if (Array.length ppc.operands) > 0 then (
		printf "\top_count: %d\n" (Array.length ppc.operands);
		Array.iteri (print_op csh) ppc.operands;
	);
	printf "\n";;


let print_insn mode insn =
	printf "0x%x\t%s\t%s\n" insn.address insn.mnemonic insn.op_str;
	let csh = cs_open CS_ARCH_MIPS mode in
	match csh with
	| None -> ()
	| Some v -> print_detail v insn.arch


let print_arch x =
	let (arch, mode, code, comment) = x in
		let insns = cs_disasm_quick arch mode code 0x1000L 0L in
			printf "*************\n";
			printf "Platform: %s\n" comment;
			List.iter (print_insn mode) insns;;



List.iter print_arch all_tests;;



(* all below code use OO class of Capstone *)
let print_insn_cls csh insn =
	printf "0x%x\t%s\t%s\n" insn#address insn#mnemonic insn#op_str;
	print_detail csh insn#arch;;


let print_arch_cls x =
	let (arch, mode, code, comment) = x in (
		let d = new cs arch mode in
			let insns = d#disasm code 0x1000L 0L in
				printf "*************\n";
				printf "Platform: %s\n" comment;
				List.iter (print_insn_cls d#get_csh) insns;
	);;

List.iter print_arch_cls all_tests;;
