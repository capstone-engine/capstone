(* Capstone Disassembler Engine
* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> *)

open Printf
open Capstone
open X86


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
	(CS_ARCH_X86, [CS_MODE_16], _X86_CODE16, "X86 16bit (Intel syntax)");
	(CS_ARCH_X86, [CS_MODE_32; CS_MODE_SYNTAX_ATT], _X86_CODE32, "X86 32bit (ATT syntax)");
	(CS_ARCH_X86, [CS_MODE_32], _X86_CODE32, "X86 32 (Intel syntax)");
	(CS_ARCH_X86, [CS_MODE_64], _X86_CODE64, "X86 64 (Intel syntax)");
];;

let print_op csh i op =
	( match op with
	| X86_OP_INVALID _ -> ();	(* this would never happens *)
	| X86_OP_REG reg -> printf "\t\top[%d]: REG = %s\n" i (cs_reg_name csh reg);
	| X86_OP_IMM imm -> printf "\t\top[%d]: IMM = 0x%x\n" i imm;
	| X86_OP_FP fp -> printf "\t\top[%d]: FP = %f\n" i fp;
	| X86_OP_MEM mem -> ( printf "\t\top[%d]: MEM\n" i;
		if mem.base != 0 then
			printf "\t\t\toperands[%u].mem.base: REG = %s\n" i (cs_reg_name csh  mem.base);
		if mem.index != 0 then
			printf "\t\t\toperands[%u].mem.index: REG = %s\n" i (cs_reg_name csh mem.index);
		if mem.scale != 1 then
			printf "\t\t\toperands[%u].mem.scale: %d\n" i mem.scale;
		if mem.displ != 0 then
			printf "\t\t\toperands[%u].mem.disp: 0x%x\n" i mem.displ;
		);
	);
	();;


let print_detail mode csh arch =
	match arch with
	| CS_INFO_ARM64 _ -> ();
	| CS_INFO_ARM _ -> ();
	| CS_INFO_MIPS _ -> ();
	| CS_INFO_PPC _ -> ();
	| CS_INFO_X86 x86 ->
	print_string_hex "\tPrefix: " x86.prefix;

	(* print segment override (if applicable) *)
	if x86.segment != _X86_REG_INVALID then
		printf "\tsegment = %s\n" (cs_reg_name csh x86.segment);


	(* print instruction's opcode *)
	print_string_hex "\tOpcode: " x86.opcode;

	(* print operand's size, address size, displacement size & immediate size *)
	printf "\top_size: %u, addr_size: %u, disp_size: %u, imm_size: %u\n" 
		x86.op_size x86.addr_size
		x86.disp_size x86.imm_size;

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
				(cs_reg_name csh x86.sib_index)
				x86.sib_scale
				(cs_reg_name csh x86.sib_base);
	);

	(* print all operands info (type & value) *)
	if (Array.length x86.operands) > 0 then (
		printf "\top_count: %d\n" (Array.length x86.operands);
		Array.iteri (print_op csh) x86.operands;
	);
	printf "\n";;


let print_insn mode insn =
	printf "0x%x\t%s\t%s\n" insn.address insn.mnemonic insn.op_str;
	let csh = cs_open CS_ARCH_X86 mode in
	match csh with
	| None -> ()
	| Some v -> print_detail mode v insn.arch


let print_arch x =
	let (arch, mode, code, comment) = x in
		let insns = cs_disasm_quick arch mode code 0x1000L 0L in
			printf "*************\n";
			printf "Platform: %s\n" comment;
			List.iter (print_insn mode) insns;;



List.iter print_arch all_tests;;


(* all below code use OO class of Capstone *)
let print_insn_cls mode csh insn =
	printf "0x%x\t%s\t%s\n" insn#address insn#mnemonic insn#op_str;
	print_string_hex "\tbytes: " insn#bytes;
	print_detail mode csh insn#arch;;


let print_arch_cls x =
	let (arch, mode, code, comment) = x in (
		let d = new cs arch mode in
			let insns = d#disasm code 0x1000L 0L in
				printf "*************\n";
				printf "Platform: %s\n" comment;
				List.iter (print_insn_cls mode d#get_csh) insns;
	);;


List.iter print_arch_cls all_tests;;

