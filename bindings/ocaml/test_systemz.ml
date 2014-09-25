(* Capstone Disassembler Engine
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

let print_op csh i op =
	( match op with
	| SYSZ_OP_INVALID _ -> ();	(* this would never happens *)
	| SYSZ_OP_REG reg -> printf "\t\top[%d]: REG = %s\n" i (cs_reg_name csh reg);
	| SYSZ_OP_ACREG reg -> (); (* XXX *)
	| SYSZ_OP_IMM imm -> printf "\t\top[%d]: IMM = 0x%x\n" i imm;
	| SYSZ_OP_MEM mem -> ( printf "\t\top[%d]: MEM\n" i;
		if mem.base != 0 then
			printf "\t\t\toperands[%u].mem.base: REG = %s\n" i (cs_reg_name csh mem.base);
		if mem.index != 0 then
			printf "\t\t\toperands[%u].mem.index: 0x%x\n" i mem.index;
		if mem.length != 0L then
			printf "\t\t\toperands[%u].mem.length: 0x%Lx\n" i mem.length;
		if mem.disp != 0L then
			printf "\t\t\toperands[%u].mem.disp: 0x%Lx\n" i mem.disp;
		);
	);

	();;


let print_detail csh arch =
	match arch with
	| CS_INFO_ARM _ -> ();
	| CS_INFO_ARM64 _ -> ();
	| CS_INFO_MIPS _ -> ();
	| CS_INFO_X86 _ -> ();
	| CS_INFO_PPC _ -> ();
	| CS_INFO_SPARC _ -> ();
	| CS_INFO_XCORE _ -> ();
	| CS_INFO_SYSZ sysz ->

	(* print all operands info (type & value) *)
	if (Array.length sysz.operands) > 0 then (
		printf "\top_count: %d\n" (Array.length sysz.operands);
		Array.iteri (print_op csh) sysz.operands;
	);
	printf "\n";;


let print_insn mode insn =
	printf "0x%x\t%s\t%s\n" insn.address insn.mnemonic insn.op_str;
	let csh = cs_open CS_ARCH_SYSZ mode in
	match csh with
	| None -> ()
	| Some v -> print_detail v insn.arch


let print_arch x =
	let (arch, mode, code, comment) = x in
		let insns = cs_disasm arch mode code 0x1000L 0L in
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
