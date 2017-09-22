(* Capstone Disassembly Engine
* M680X Backend by Wolfgang Schwotzer <wolfgang.schwotzer@gmx.net> 2017 *)

open Printf
open Capstone
open M680x
open M680x_const


let print_char_hex ch =
	printf " 0x%02X" (Char.code ch)

let print_int_hex_short value =
	printf "%02X" value

let print_string_hex comment str =
	printf "%s" comment;
	String.iter print_char_hex str;
	printf "\n"

let print_array_hex_short arr =
	Array.iter print_int_hex_short arr

let s_address_modes = [
        "M680X_AM_NONE";
        "M680X_AM_INHERENT";
        "M680X_AM_REGISTER";
        "M680X_AM_IMMEDIATE";
        "M680X_AM_INDEXED";
        "M680X_AM_EXTENDED";
        "M680X_AM_DIRECT";
        "M680X_AM_RELATIVE";
        "M680X_AM_IMM_DIRECT";
        "M680X_AM_IMM_INDEXED";
        "M680X_AM_IMM_EXTENDED";
        "M680X_AM_BIT_MOVE";
        "M680X_AM_INDEXED2";
        "M680X_AM_DIR_IMM_REL";
        "M680X_AM_IDX_IMM_REL";
        "M680X_AM_DIRECT_IMM";
        "M680X_AM_INDEXED_IMM";
        "M680X_AM_IDX_DIR_REL";
        "M680X_AM_IDX_DIRECT"; ];;

let s_access = [
	"UNCHANGED"; "READ"; "WRITE"; "READ | WRITE" ];;

let s_inc_dec = [
	"no inc-/decrement";
        "pre decrement: 1"; "pre decrement: 2"; "post increment: 1";
        "post increment: 2"; "post decrement: 1" ];;

let _M6800_CODE = "\x01\x09\x36\x64\x7f\x74\x10\x00\x90\x10\xA4\x10\xb6\x10\x00\x39";;
let _M6801_CODE = "\x04\x05\x3c\x3d\x38\x93\x10\xec\x10\xed\x10\x39";;
let _M6805_CODE = "\x04\x7f\x00\x17\x22\x28\x00\x2e\x00\x40\x42\x5a\x70\x8e\x97\x9c\xa0\x15\xad\x00\xc3\x10\x00\xda\x12\x34\xe5\x7f\xfe";;
let _HD6301_CODE = "\x6b\x10\x00\x71\x10\x00\x72\x10\x10\x39";;
let _M6809_CODE = "\x06\x10\x19\x1a\x55\x1e\x01\x23\xe9\x31\x06\x34\x55\xa6\x81\xa7\x89\x7f\xff\xa6\x9d\x10\x00\xa7\x91\xa6\x9f\x10\x00\x11\xac\x99\x10\x00\x39\xA6\x07\xA6\x27\xA6\x47\xA6\x67\xA6\x0F\xA6\x10\xA6\x80\xA6\x81\xA6\x82\xA6\x83\xA6\x84\xA6\x85\xA6\x86\xA6\x88\x7F\xA6\x88\x80\xA6\x89\x7F\xFF\xA6\x89\x80\x00\xA6\x8B\xA6\x8C\x10\xA6\x8D\x10\x00\xA6\x91\xA6\x93\xA6\x94\xA6\x95\xA6\x96\xA6\x98\x7F\xA6\x98\x80\xA6\x99\x7F\xFF\xA6\x99\x80\x00\xA6\x9B\xA6\x9C\x10\xA6\x9D\x10\x00\xA6\x9F\x10\x00";;
let _HD6309_CODE = "\x01\x10\x10\x62\x10\x10\x7b\x10\x10\x00\xcd\x49\x96\x02\xd2\x10\x30\x23\x10\x38\x10\x3b\x10\x53\x10\x5d\x11\x30\x43\x10\x11\x37\x25\x10\x11\x38\x12\x11\x39\x23\x11\x3b\x34\x11\x8e\x10\x00\x11\xaf\x10\x11\xab\x10\x11\xf6\x80\x00";;
let _M6811_CODE = "\x02\x03\x12\x7f\x10\x00\x13\x99\x08\x00\x14\x7f\x02\x15\x7f\x01\x1e\x7f\x20\x00\x8f\xcf\x18\x08\x18\x30\x18\x3c\x18\x67\x18\x8c\x10\x00\x18\x8f\x18\xce\x10\x00\x18\xff\x10\x00\x1a\xa3\x7f\x1a\xac\x1a\xee\x7f\x1a\xef\x7f\xcd\xac\x7f";;

let bit_set value mask =
	value land mask != 0

let all_tests = [
        (CS_ARCH_M680X, [CS_MODE_M680X_6800], _M6800_CODE, "M680X_M6800");
        (CS_ARCH_M680X, [CS_MODE_M680X_6801], _M6801_CODE, "M680X_M6801");
        (CS_ARCH_M680X, [CS_MODE_M680X_6805], _M6805_CODE, "M680X_M68HC05");
        (CS_ARCH_M680X, [CS_MODE_M680X_6301], _HD6301_CODE, "M680X_HD6301");
        (CS_ARCH_M680X, [CS_MODE_M680X_6809], _M6809_CODE, "M680X_M6809");
        (CS_ARCH_M680X, [CS_MODE_M680X_6309], _HD6309_CODE, "M680X_HD6309");
        (CS_ARCH_M680X, [CS_MODE_M680X_6811], _M6811_CODE, "M680X_M68HC11");
];;

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
	| M680X_OP_IMMEDIATE imm -> (
		printf "\t\toperands[%d].type: IMMEDIATE = #%d\n" i imm;
		);
	| M680X_OP_DIRECT direct_addr -> (
		printf "\t\toperands[%d].type: DIRECT = 0x%02X\n" i direct_addr;
		);
	| M680X_OP_EXTENDED ext -> (
		printf "\t\toperands[%d].type: EXTENDED " i;
		if ext.indirect then
			printf "INDIRECT";
		printf " = 0x%04X\n" ext.addr_ext;
		);
	| M680X_OP_RELATIVE rel -> (
		printf "\t\toperands[%d].type: RELATIVE = 0x%04X\n" i rel.addr_rel;
		);
	| M680X_OP_INDEXED idx -> (
		printf "\t\toperands[%d].type: INDEXED" i;
		if (bit_set idx.flags _M680X_IDX_INDIRECT) then
			printf " INDIRECT";
		printf "\n";
		if idx.base_reg != _M680X_REG_INVALID then
			printf "\t\t\tbase register: %s\n" (cs_reg_name handle idx.base_reg);
		if idx.offset_reg != _M680X_REG_INVALID then
			printf "\t\t\toffset register: %s\n" (cs_reg_name handle idx.offset_reg);
		if idx.offset_bits != 0 && idx.offset_reg == 0 && idx.inc_dec == _M680X_NO_INC_DEC then begin
			printf "\t\t\toffset: %d\n" idx.offset;
			if idx.base_reg == _M680X_REG_PC then
				printf "\t\t\toffset address: 0x%X\n" idx.offset_addr;
			printf "\t\t\toffset bits: %u\n" idx.offset_bits;
		end;
		if idx.inc_dec != _M680X_NO_INC_DEC then
			printf "\t\t\t%s\n" (List.nth s_inc_dec idx.inc_dec);
		);
	| M680X_OP_INDEX index -> (
		printf "\t\toperands[%d].type: INDEX = %d\n" i index;
		);
	);
	if op.size != 0 then
		printf "\t\t\tsize: %d\n" op.size;
	if op.access != _CS_AC_INVALID then
		printf "\t\t\taccess: %s\n" (List.nth s_access op.access);

	();;


let print_detail handle insn =
	match insn.arch with
	| CS_INFO_M680X m680x -> (
			printf "\taddress_mode: %s\n" (List.nth s_address_modes m680x.address_mode);
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
	printf "0x%04X:\t" insn.address;
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

