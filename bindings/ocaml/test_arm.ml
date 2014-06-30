(* Capstone Disassembler Engine
* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> *)

open Printf
open Capstone
open Arm


let print_string_hex comment str =
	printf "%s" comment;
	for i = 0 to (Array.length str - 1) do
		printf "0x%02x " str.(i)
	done;
	printf "\n"


let _ARM_CODE = "\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3";;
let _ARM_CODE2 = "\xd1\xe8\x00\xf0\xf0\x24\x04\x07\x1f\x3c\xf2\xc0\x00\x00\x4f\xf0\x00\x01\x46\x6c";;
let _THUMB_CODE2  = "\x4f\xf0\x00\x01\xbd\xe8\x00\x88\xd1\xe8\x00\xf0";;
let _THUMB_CODE  = "\x70\x47\xeb\x46\x83\xb0\xc9\x68\x1f\xb1";;


let all_tests = [
        (CS_ARCH_ARM, [CS_MODE_ARM], _ARM_CODE, "ARM");
        (CS_ARCH_ARM, [CS_MODE_THUMB], _THUMB_CODE, "Thumb");
        (CS_ARCH_ARM, [CS_MODE_THUMB], _ARM_CODE2, "Thumb-mixed");
        (CS_ARCH_ARM, [CS_MODE_THUMB], _THUMB_CODE2, "Thumb-2");
];;


let print_op csh i op =
	( match op.value with
	| ARM_OP_INVALID _ -> ();	(* this would never happens *)
	| ARM_OP_REG reg -> printf "\t\top[%d]: REG = %s\n" i (cs_reg_name csh reg);
	| ARM_OP_CIMM imm -> printf "\t\top[%d]: C-IMM = %u\n" i imm;
	| ARM_OP_PIMM imm -> printf "\t\top[%d]: P-IMM = %u\n" i imm;
	| ARM_OP_IMM imm -> printf "\t\top[%d]: IMM = 0x%x\n" i imm;
	| ARM_OP_FP fp -> printf "\t\top[%d]: FP = %f\n" i fp;
	| ARM_OP_MEM mem -> ( printf "\t\top[%d]: MEM\n" i;
		if mem.base != 0 then
			printf "\t\t\toperands[%u].mem.base: REG = %s\n" i (cs_reg_name csh mem.base);
		if mem.index != 0 then
			printf "\t\t\toperands[%u].mem.index: REG = %s\n" i (cs_reg_name csh mem.index);
		if mem.scale != 1 then
			printf "\t\t\toperands[%u].mem.scale: %d\n" i mem.scale;
		if mem.displ != 0 then
			printf "\t\t\toperands[%u].mem.disp: 0x%x\n" i mem.displ;
		);
	);

	if op.shift.shift_type != _ARM_SFT_INVALID && op.shift.shift_value > 0 then
		printf "\t\t\tShift: type = %u, value = %u\n"
                op.shift.shift_type op.shift.shift_value;
	();;


let print_detail csh arch =
	match arch with
	| CS_INFO_ARM64 _ -> ();
	| CS_INFO_X86 _ -> ();
	| CS_INFO_MIPS _ -> ();
	| CS_INFO_PPC _ -> ();
	| CS_INFO_ARM arm ->
	if arm.cc != _ARM_CC_AL && arm.cc != _ARM_CC_INVALID then
		printf "\tCode condition: %u\n" arm.cc;

	if arm.update_flags then
		printf "\tUpdate-flags: True\n";

	if arm.writeback then
		printf "\tWriteback: True\n";

	(* print all operands info (type & value) *)
	if (Array.length arm.operands) > 0 then (
		printf "\top_count: %d\n" (Array.length arm.operands);
		Array.iteri (print_op csh) arm.operands;
	);
	printf "\n";;


let print_insn mode insn =
	printf "0x%x\t%s\t%s\n" insn.address insn.mnemonic insn.op_str;
	let csh = cs_open CS_ARCH_ARM mode in
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
