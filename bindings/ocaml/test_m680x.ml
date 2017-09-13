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
        "M680X_AM_IMM_INDEXED" ];;

let s_insn_ids = [
        "M680X_INS_INVLD"; "M680X_INS_ABA"; "M680X_INS_ABX"; "M680X_INS_ADCA";
        "M680X_INS_ADCB"; "M680X_INS_ADCD"; "M680X_INS_ADDA"; "M680X_INS_ADDB";
        "M680X_INS_ADDD"; "M680X_INS_ADDE"; "M680X_INS_ADDF"; "M680X_INS_ADDR";
        "M680X_INS_ADDW"; "M680X_INS_AIM"; "M680X_INS_ANDA"; "M680X_INS_ANDB";
        "M680X_INS_ANDCC"; "M680X_INS_ANDD"; "M680X_INS_ANDR"; "M680X_INS_ASL";
        "M680X_INS_ASLA"; "M680X_INS_ASLB"; "M680X_INS_ASLD"; "M680X_INS_ASR";
        "M680X_INS_ASRA"; "M680X_INS_ASRB"; "M680X_INS_BAND"; "M680X_INS_BCC";
        "M680X_INS_BCS"; "M680X_INS_BEOR"; "M680X_INS_BEQ"; "M680X_INS_BGE";
        "M680X_INS_BGT"; "M680X_INS_BHI"; "M680X_INS_BIAND"; "M680X_INS_BIEOR";
        "M680X_INS_BIOR"; "M680X_INS_BITA"; "M680X_INS_BITB"; "M680X_INS_BITD";
        "M680X_INS_BITMD"; "M680X_INS_BLE"; "M680X_INS_BLS"; "M680X_INS_BLT";
        "M680X_INS_BMI"; "M680X_INS_BNE"; "M680X_INS_BOR"; "M680X_INS_BPL";
        "M680X_INS_BRA"; "M680X_INS_BRN"; "M680X_INS_BSR"; "M680X_INS_BVC";
        "M680X_INS_BVS"; "M680X_INS_CBA"; "M680X_INS_CLC"; "M680X_INS_CLI";
        "M680X_INS_CLR"; "M680X_INS_CLRA"; "M680X_INS_CLRB"; "M680X_INS_CLRD";
        "M680X_INS_CLRE"; "M680X_INS_CLRF"; "M680X_INS_CLRW"; "M680X_INS_CLV";
        "M680X_INS_CMPA"; "M680X_INS_CMPB"; "M680X_INS_CMPD"; "M680X_INS_CMPE";
        "M680X_INS_CMPF"; "M680X_INS_CMPR"; "M680X_INS_CMPS"; "M680X_INS_CMPU";
        "M680X_INS_CMPW"; "M680X_INS_CMPX"; "M680X_INS_CMPY"; "M680X_INS_COM";
        "M680X_INS_COMA"; "M680X_INS_COMB"; "M680X_INS_COMD"; "M680X_INS_COME";
        "M680X_INS_COMF"; "M680X_INS_COMW"; "M680X_INS_CPX"; "M680X_INS_CWAI";
        "M680X_INS_DAA"; "M680X_INS_DEC"; "M680X_INS_DECA"; "M680X_INS_DECB";
        "M680X_INS_DECD"; "M680X_INS_DECE"; "M680X_INS_DECF"; "M680X_INS_DECW";
        "M680X_INS_DES"; "M680X_INS_DEX"; "M680X_INS_DIVD"; "M680X_INS_DIVQ";
        "M680X_INS_EIM"; "M680X_INS_EORA"; "M680X_INS_EORB"; "M680X_INS_EORD";
        "M680X_INS_EORR"; "M680X_INS_EXG"; "M680X_INS_ILLGL"; "M680X_INS_INC";
        "M680X_INS_INCA"; "M680X_INS_INCB"; "M680X_INS_INCD"; "M680X_INS_INCE";
        "M680X_INS_INCF"; "M680X_INS_INCW"; "M680X_INS_INS"; "M680X_INS_INX";
        "M680X_INS_JMP"; "M680X_INS_JSR"; "M680X_INS_LBCC"; "M680X_INS_LBCS";
        "M680X_INS_LBEQ"; "M680X_INS_LBGE"; "M680X_INS_LBGT"; "M680X_INS_LBHI";
        "M680X_INS_LBLE"; "M680X_INS_LBLS"; "M680X_INS_LBLT"; "M680X_INS_LBMI";
        "M680X_INS_LBNE"; "M680X_INS_LBPL"; "M680X_INS_LBRA"; "M680X_INS_LBRN";
        "M680X_INS_LBSR"; "M680X_INS_LBVC"; "M680X_INS_LBVS"; "M680X_INS_LDA";
        "M680X_INS_LDAA"; "M680X_INS_LDAB"; "M680X_INS_LDB"; "M680X_INS_LDBT";
        "M680X_INS_LDD"; "M680X_INS_LDE"; "M680X_INS_LDF"; "M680X_INS_LDMD";
        "M680X_INS_LDQ"; "M680X_INS_LDS"; "M680X_INS_LDU"; "M680X_INS_LDW";
        "M680X_INS_LDX"; "M680X_INS_LDY"; "M680X_INS_LEAS"; "M680X_INS_LEAU";
        "M680X_INS_LEAX"; "M680X_INS_LEAY"; "M680X_INS_LSL"; "M680X_INS_LSLA";
        "M680X_INS_LSLB"; "M680X_INS_LSR"; "M680X_INS_LSRA"; "M680X_INS_LSRB";
        "M680X_INS_LSRD"; "M680X_INS_LSRW"; "M680X_INS_MUL"; "M680X_INS_MULD";
        "M680X_INS_NEG"; "M680X_INS_NEGA"; "M680X_INS_NEGB"; "M680X_INS_NEGD";
        "M680X_INS_NOP"; "M680X_INS_OIM"; "M680X_INS_ORA"; "M680X_INS_ORAA";
        "M680X_INS_ORAB"; "M680X_INS_ORB"; "M680X_INS_ORCC"; "M680X_INS_ORD";
        "M680X_INS_ORR"; "M680X_INS_PSHA"; "M680X_INS_PSHB"; "M680X_INS_PSHS";
        "M680X_INS_PSHSW"; "M680X_INS_PSHU"; "M680X_INS_PSHUW"; "M680X_INS_PSHX";
        "M680X_INS_PULA"; "M680X_INS_PULB"; "M680X_INS_PULS"; "M680X_INS_PULSW";
        "M680X_INS_PULU"; "M680X_INS_PULUW"; "M680X_INS_PULX"; "M680X_INS_ROL";
        "M680X_INS_ROLA"; "M680X_INS_ROLB"; "M680X_INS_ROLD"; "M680X_INS_ROLW";
        "M680X_INS_ROR"; "M680X_INS_RORA"; "M680X_INS_RORB"; "M680X_INS_RORD";
        "M680X_INS_RORW"; "M680X_INS_RTI"; "M680X_INS_RTS"; "M680X_INS_SBA";
        "M680X_INS_SBCA"; "M680X_INS_SBCB"; "M680X_INS_SBCD"; "M680X_INS_SBCR";
        "M680X_INS_SEC"; "M680X_INS_SEI"; "M680X_INS_SEV"; "M680X_INS_SEX";
        "M680X_INS_SEXW"; "M680X_INS_STA"; "M680X_INS_STAA"; "M680X_INS_STAB";
        "M680X_INS_STB"; "M680X_INS_STBT"; "M680X_INS_STD"; "M680X_INS_STE";
        "M680X_INS_STF"; "M680X_INS_STQ"; "M680X_INS_STS"; "M680X_INS_STU";
        "M680X_INS_STW"; "M680X_INS_STX"; "M680X_INS_STY"; "M680X_INS_SUBA";
        "M680X_INS_SUBB"; "M680X_INS_SUBD"; "M680X_INS_SUBE"; "M680X_INS_SUBF";
        "M680X_INS_SUBR"; "M680X_INS_SUBW"; "M680X_INS_SWI"; "M680X_INS_SWI2";
        "M680X_INS_SWI3"; "M680X_INS_SYNC"; "M680X_INS_TAB"; "M680X_INS_TAP";
        "M680X_INS_TBA"; "M680X_INS_TPA"; "M680X_INS_TFM"; "M680X_INS_TFR";
        "M680X_INS_TIM"; "M680X_INS_TST"; "M680X_INS_TSTA"; "M680X_INS_TSTB";
        "M680X_INS_TSTD"; "M680X_INS_TSTE"; "M680X_INS_TSTF"; "M680X_INS_TSTW";
        "M680X_INS_TSX"; "M680X_INS_TXS"; "M680X_INS_WAI"; "M680X_INS_XGDX" ];;

let _M6800_CODE = "\x01\x09\x36\x64\x7f\x74\x10\x00\x90\x10\xA4\x10\xb6\x10\x00\x39";;
let _M6801_CODE = "\x04\x05\x3c\x3d\x38\x93\x10\xec\x10\xed\x10\x39";;
let _HD6301_CODE = "\x6b\x10\x00\x71\x10\x00\x72\x10\x10\x39";;
let _M6809_CODE = "\x06\x10\x19\x1a\x55\x1e\x01\x23\xe9\x31\x06\x34\x55\xa6\x81\xa7\x89\x7f\xff\xa6\x9d\x10\x00\xa7\x91\xa6\x9f\x10\x00\x11\xac\x99\x10\x00\x39\xA6\x07\xA6\x27\xA6\x47\xA6\x67\xA6\x0F\xA6\x10\xA6\x80\xA6\x81\xA6\x82\xA6\x83\xA6\x84\xA6\x85\xA6\x86\xA6\x88\x7F\xA6\x88\x80\xA6\x89\x7F\xFF\xA6\x89\x80\x00\xA6\x8B\xA6\x8C\x10\xA6\x8D\x10\x00\xA6\x91\xA6\x93\xA6\x94\xA6\x95\xA6\x96\xA6\x98\x7F\xA6\x98\x80\xA6\x99\x7F\xFF\xA6\x99\x80\x00\xA6\x9B\xA6\x9C\x10\xA6\x9D\x10\x00\xA6\x9F\x10\x00";;

let bit_set value mask =
	value land mask != 0

let all_tests = [
        (CS_ARCH_M680X, [CS_MODE_M680X_6800], _M6800_CODE, "M680X_M6800");
        (CS_ARCH_M680X, [CS_MODE_M680X_6801], _M6801_CODE, "M680X_M6801");
        (CS_ARCH_M680X, [CS_MODE_M680X_6301], _HD6301_CODE, "M680X_HD6301");
        (CS_ARCH_M680X, [CS_MODE_M680X_6809], _M6809_CODE, "M680X_M6809");
];;

let print_op handle flags i op =
	( match op.value with
	| M680X_OP_INVALID _ -> ();	(* this would never happens *)
	| M680X_OP_REGISTER reg -> (
		printf "\t\toperands[%d].type: REGISTER = %s" i (cs_reg_name handle reg);
		if (i == 0) && (bit_set flags _M680X_FIRST_OP_IN_MNEM) then
			printf " (in mnemonic)";
		printf "\n";
		);
	| M680X_OP_IMMEDIATE imm -> printf "\t\toperands[%d].type: IMMEDIATE = #%d\n" i imm;
	| M680X_OP_DIRECT direct_addr -> printf "\t\toperands[%d].type: DIRECT = 0x%02X\n" i direct_addr;
	| M680X_OP_EXTENDED ext -> ( printf "\t\toperands[%d].type: EXTENDED " i;
		if ext.indirect then
			printf "INDIRECT";
		printf " = 0x%04X\n" ext.addr_ext;
		);
	| M680X_OP_RELATIVE rel -> printf "\t\toperands[%d].type: RELATIVE = 0x%04X\n" i rel.addr_rel;
	| M680X_OP_INDEXED_00 idx -> ( printf "\t\toperands[%d].type: INDEXED_M6800\n" i;
		if idx.base_reg != 0 then
			printf "\t\t\tbase register: %s\n" (cs_reg_name handle idx.base_reg);
		if idx.offset_bits != 0 then
			printf "\t\t\toffset: %u\n" idx.offset;
			printf "\t\t\toffset bits: %u\n" idx.offset_bits;
		);
	| M680X_OP_INDEXED_09 idx -> ( printf "\t\toperands[%d].type: INDEXED_M6809" i;
		if idx.indirect then
			printf " INDIRECT";
		printf "\n";
		if idx.base_reg != _M680X_REG_INVALID then
			printf "\t\t\tbase register: %s\n" (cs_reg_name handle idx.base_reg);
		if idx.offset_reg != _M680X_REG_INVALID then
			printf "\t\t\toffset register: %s\n" (cs_reg_name handle idx.offset_reg);
		if idx.offset_bits != 0 && idx.offset_reg == 0 && idx.inc_dec == 0 then begin
			printf "\t\t\toffset: %d\n" idx.offset;
			if idx.base_reg == _M680X_REG_PC then
				printf "\t\t\toffset address: 0x%X\n" idx.offset_addr;
			printf "\t\t\toffset bits: %u\n" idx.offset_bits;
		end;
		if idx.inc_dec > 0 then
			printf "\t\t\tpost increment: %d\n" idx.inc_dec;
		if idx.inc_dec < 0 then
			printf "\t\t\tpre decrement: %d\n" idx.inc_dec;
		);
	);

	();;


let print_detail handle insn =
	match insn.arch with
	| CS_INFO_M680X m680x -> (
			printf "\tinsn id: %s\n" (List.nth s_insn_ids insn.id);
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

