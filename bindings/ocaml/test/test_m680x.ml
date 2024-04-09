(* Capstone Disassembly Engine
* M680X Backend by Wolfgang Schwotzer <wolfgang.schwotzer@gmx.net> 2017 *)

open Printf
open Capstone
open M680x
open M680x_const


let print_char_hex ch =
	printf " 0x%02x" (Char.code ch)

let print_int_hex_short value =
	printf "%02x" value

let print_string_hex comment str =
	printf "%s" comment;
	String.iter print_char_hex str;
	printf "\n"

let print_array_hex_short arr =
	Array.iter print_int_hex_short arr

let s_access = [
	"UNCHANGED"; "READ"; "WRITE"; "READ | WRITE" ];;

let _M6800_CODE = "\x01\x09\x36\x64\x7f\x74\x10\x00\x90\x10\xA4\x10\xb6\x10\x00\x39";;
let _M6801_CODE = "\x04\x05\x3c\x3d\x38\x93\x10\xec\x10\xed\x10\x39";;
let _M6805_CODE = "\x04\x7f\x00\x17\x22\x28\x00\x2e\x00\x40\x42\x5a\x70\x8e\x97\x9c\xa0\x15\xad\x00\xc3\x10\x00\xda\x12\x34\xe5\x7f\xfe";;
let _M6808_CODE = "\x31\x22\x00\x35\x22\x45\x10\x00\x4b\x00\x51\x10\x52\x5e\x22\x62\x65\x12\x34\x72\x84\x85\x86\x87\x8a\x8b\x8c\x94\x95\xa7\x10\xaf\x10\x9e\x60\x7f\x9e\x6b\x7f\x00\x9e\xd6\x10\x00\x9e\xe6\x7f";;
let _HD6301_CODE = "\x6b\x10\x00\x71\x10\x00\x72\x10\x10\x39";;
let _M6809_CODE = "\x06\x10\x19\x1a\x55\x1e\x01\x23\xe9\x31\x06\x34\x55\xa6\x81\xa7\x89\x7f\xff\xa6\x9d\x10\x00\xa7\x91\xa6\x9f\x10\x00\x11\xac\x99\x10\x00\x39\xA6\x07\xA6\x27\xA6\x47\xA6\x67\xA6\x0F\xA6\x10\xA6\x80\xA6\x81\xA6\x82\xA6\x83\xA6\x84\xA6\x85\xA6\x86\xA6\x88\x7F\xA6\x88\x80\xA6\x89\x7F\xFF\xA6\x89\x80\x00\xA6\x8B\xA6\x8C\x10\xA6\x8D\x10\x00\xA6\x91\xA6\x93\xA6\x94\xA6\x95\xA6\x96\xA6\x98\x7F\xA6\x98\x80\xA6\x99\x7F\xFF\xA6\x99\x80\x00\xA6\x9B\xA6\x9C\x10\xA6\x9D\x10\x00\xA6\x9F\x10\x00";;
let _HD6309_CODE = "\x01\x10\x10\x62\x10\x10\x7b\x10\x10\x00\xcd\x49\x96\x02\xd2\x10\x30\x23\x10\x38\x10\x3b\x10\x53\x10\x5d\x11\x30\x43\x10\x11\x37\x25\x10\x11\x38\x12\x11\x39\x23\x11\x3b\x34\x11\x8e\x10\x00\x11\xaf\x10\x11\xab\x10\x11\xf6\x80\x00";;
let _M6811_CODE = "\x02\x03\x12\x7f\x10\x00\x13\x99\x08\x00\x14\x7f\x02\x15\x7f\x01\x1e\x7f\x20\x00\x8f\xcf\x18\x08\x18\x30\x18\x3c\x18\x67\x18\x8c\x10\x00\x18\x8f\x18\xce\x10\x00\x18\xff\x10\x00\x1a\xa3\x7f\x1a\xac\x1a\xee\x7f\x1a\xef\x7f\xcd\xac\x7f";;
let _CPU12_CODE = "\x00\x04\x01\x00\x0c\x00\x80\x0e\x00\x80\x00\x11\x1e\x10\x00\x80\x00\x3b\x4a\x10\x00\x04\x4b\x01\x04\x4f\x7f\x80\x00\x8f\x10\x00\xb7\x52\xb7\xb1\xa6\x67\xa6\xfe\xa6\xf7\x18\x02\xe2\x30\x39\xe2\x10\x00\x18\x0c\x30\x39\x10\x00\x18\x11\x18\x12\x10\x00\x18\x19\x00\x18\x1e\x00\x18\x3e\x18\x3f\x00";;
let _HCS08_CODE = "\x32\x10\x00\x9e\xae\x9e\xce\x7f\x9e\xbe\x10\x00\x9e\xfe\x7f\x3e\x10\x00\x9e\xf3\x7f\x96\x10\x00\x9e\xff\x7f\x82";;

let bit_set value mask =
	value land mask != 0

let all_tests = [
        (CS_ARCH_M680X, [CS_MODE_M680X_6301], _HD6301_CODE, "M680X_HD6301");
        (CS_ARCH_M680X, [CS_MODE_M680X_6309], _HD6309_CODE, "M680X_HD6309");
        (CS_ARCH_M680X, [CS_MODE_M680X_6800], _M6800_CODE, "M680X_M6800");
        (CS_ARCH_M680X, [CS_MODE_M680X_6801], _M6801_CODE, "M680X_M6801");
        (CS_ARCH_M680X, [CS_MODE_M680X_6805], _M6805_CODE, "M680X_M68HC05");
        (CS_ARCH_M680X, [CS_MODE_M680X_6808], _M6808_CODE, "M680X_M68HC08");
        (CS_ARCH_M680X, [CS_MODE_M680X_6809], _M6809_CODE, "M680X_M6809");
        (CS_ARCH_M680X, [CS_MODE_M680X_6811], _M6811_CODE, "M680X_M68HC11");
        (CS_ARCH_M680X, [CS_MODE_M680X_CPU12], _CPU12_CODE, "M680X_CPU12");
        (CS_ARCH_M680X, [CS_MODE_M680X_HCS08], _HCS08_CODE, "M680X_HCS08");
];;

let print_inc_dec inc_dec is_post = (
	printf "\t\t\t";
	if is_post then printf "post" else printf "pre";
	if inc_dec > 0 then
		printf " increment: %d\n" inc_dec
	else
		printf " decrement: %d\n" (abs inc_dec);
	);
	();;

let print_op handle flags i op =
	( match op.value with
	| M680X_OP_INVALID _ -> ();	(* this would never happens *)
	| M680X_OP_REGISTER reg -> (
		printf "\t\toperands[%d].type: REGISTER = %s" i (cs_reg_name handle reg);
		if (((i == 0) && (bit_set flags _M680X_FIRST_OP_IN_MNEM)) ||
		    ((i == 1) && (bit_set flags _M680X_SECOND_OP_IN_MNEM))) then
			printf " (in mnemonic)";
		printf "\n";
		);
	| M680X_OP_IMMEDIATE imm ->
		printf "\t\toperands[%d].type: IMMEDIATE = #%d\n" i imm;
	| M680X_OP_DIRECT direct_addr ->
		printf "\t\toperands[%d].type: DIRECT = 0x%02x\n" i direct_addr;
	| M680X_OP_EXTENDED ext -> (
		printf "\t\toperands[%d].type: EXTENDED " i;
		if ext.indirect then
			printf "INDIRECT";
		printf " = 0x%04x\n" ext.addr_ext;
		);
	| M680X_OP_RELATIVE rel ->
		printf "\t\toperands[%d].type: RELATIVE = 0x%04x\n" i rel.addr_rel;
	| M680X_OP_INDEXED idx -> (
		printf "\t\toperands[%d].type: INDEXED" i;
		if (bit_set idx.flags _M680X_IDX_INDIRECT) then
			printf " INDIRECT";
		printf "\n";
		if idx.base_reg != _M680X_REG_INVALID then
			printf "\t\t\tbase register: %s\n" (cs_reg_name handle idx.base_reg);
		if idx.offset_reg != _M680X_REG_INVALID then
			printf "\t\t\toffset register: %s\n" (cs_reg_name handle idx.offset_reg);
		if idx.offset_bits != 0 && idx.offset_reg == 0 && idx.inc_dec == 0 then begin
			printf "\t\t\toffset: %d\n" idx.offset;
			if idx.base_reg == _M680X_REG_PC then
				printf "\t\t\toffset address: 0x%x\n" idx.offset_addr;
			printf "\t\t\toffset bits: %u\n" idx.offset_bits;
		end;
		if idx.inc_dec != 0 then
			print_inc_dec idx.inc_dec (bit_set idx.flags _M680X_IDX_POST_INC_DEC);
		);
	| M680X_OP_CONSTANT const_val ->
		printf "\t\toperands[%d].type: CONSTANT = %d\n" i const_val;
	);

	if op.size != 0 then
		printf "\t\t\tsize: %d\n" op.size;
	if op.access != _CS_AC_INVALID then
		printf "\t\t\taccess: %s\n" (List.nth s_access op.access);
	();;


let print_detail handle insn =
	match insn.arch with
	| CS_INFO_M680X m680x -> (
			(* print all operands info (type & value) *)
			if (Array.length m680x.operands) > 0 then (
				printf "\top_count: %d\n" (Array.length m680x.operands);
				Array.iteri (print_op handle m680x.flags) m680x.operands;
			);
			);
	| _ -> ();
	;;

let print_reg handle reg =
	printf " %s" (cs_reg_name handle reg)

let print_insn handle insn =
	printf "0x%04x:\t" insn.address;
	print_array_hex_short insn.bytes;
	printf "\t%s\t%s\n" insn.mnemonic insn.op_str;
	print_detail handle insn;
	if (Array.length insn.regs_read) > 0 then begin
		printf "\tRegisters read:";
		Array.iter (print_reg handle) insn.regs_read;
		printf "\n";
	end;
	if (Array.length insn.regs_write) > 0 then begin
		printf "\tRegisters modified:";
		Array.iter (print_reg handle) insn.regs_write;
		printf "\n";
	end;
	if (Array.length insn.groups) > 0 then
		printf "\tgroups_count: %d\n" (Array.length insn.groups);
	printf "\n"

let print_arch x =
	let (arch, mode, code, comment) = x in
		let handle = cs_open arch mode in
		let err = cs_option handle CS_OPT_DETAIL _CS_OPT_ON in
		match err with
		| _ -> ();
		let insns = cs_disasm handle code 0x1000L 0L in
			printf "********************\n";
			printf "Platform: %s\n" comment;
			print_string_hex "Code: " code;
			printf "Disasm:\n";
			List.iter (print_insn handle) insns;
		match cs_close handle with
		| 0 -> ();
		| _ -> printf "Failed to close handle";
		;;

List.iter print_arch all_tests;;

