(* Capstone Disassembly Engine
* By Guillaume Jeanne <guillaume.jeanne@ensimag.fr>, 2014> *)

open Printf
open Capstone
open Sparc


let print_string_hex comment str =
	printf "%s" comment;
	for i = 0 to (Array.length str - 1) do
		printf "0x%02x " str.(i)
	done;
	printf "\n"


let _SPARC_CODE = "\x80\xa0\x40\x02\x85\xc2\x60\x08\x85\xe8\x20\x01\x81\xe8\x00\x00\x90\x10\x20\x01\xd5\xf6\x10\x16\x21\x00\x00\x0a\x86\x00\x40\x02\x01\x00\x00\x00\x12\xbf\xff\xff\x10\xbf\xff\xff\xa0\x02\x00\x09\x0d\xbf\xff\xff\xd4\x20\x60\x00\xd4\x4e\x00\x16\x2a\xc2\x80\x03";;
let _SPARCV9_CODE = "\x81\xa8\x0a\x24\x89\xa0\x10\x20\x89\xa0\x1a\x60\x89\xa0\x00\xe0";;


let all_tests = [
        (CS_ARCH_SPARC, [CS_MODE_BIG_ENDIAN], _SPARC_CODE, "Sparc");
        (CS_ARCH_SPARC, [CS_MODE_BIG_ENDIAN; CS_MODE_V9], _SPARCV9_CODE, "SparcV9");
];;

let print_op csh i op =
	( match op.value with
	| SPARC_OP_INVALID _ -> ();	(* this would never happens *)
	| SPARC_OP_REG reg -> printf "\t\top[%d]: REG = %s\n" i (cs_reg_name csh reg);
	| SPARC_OP_IMM imm -> printf "\t\top[%d]: IMM = 0x%x\n" i imm;
	| SPARC_OP_MEM mem -> ( printf "\t\top[%d]: MEM\n" i;
		if mem.base != 0 then
			printf "\t\t\toperands[%u].mem.base: REG = %s\n" i (cs_reg_name csh mem.base);
		if mem.index != 0 then
			printf "\t\t\toperands[%u].mem.index: 0x%x\n" i mem.index;
		if mem.disp != 0 then
			printf "\t\t\toperands[%u].mem.disp: 0x%x\n" i mem.disp;
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
	| CS_INFO_SYSZ _ -> ();
	| CS_INFO_XCORE _ -> ();
	| CS_INFO_SPARC sparc ->

	(* print all operands info (type & value) *)
	if (Array.length sparc.operands) > 0 then (
		printf "\top_count: %d\n" (Array.length sparc.operands);
		Array.iteri (print_op csh) sparc.operands;
	);
	printf "\n";;


let print_insn mode insn =
	printf "0x%x\t%s\t%s\n" insn.address insn.mnemonic insn.op_str;
	let csh = cs_open CS_ARCH_SPARC mode in
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
