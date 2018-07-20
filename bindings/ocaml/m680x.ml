(* Capstone Disassembly Engine
 * M680X Backend by Wolfgang Schwotzer <wolfgang.schwotzer@gmx.net> 2017 *)

open M680x_const


(* architecture specific info of instruction *)
type m680x_op_idx = {
	base_reg: int;
	offset_reg: int;
	offset: int;
	offset_addr: int;
	offset_bits: int;
	inc_dec: int;
	flags: int;
}

type m680x_op_rel = {
	addr_rel: int;
	offset: int;
}

type m680x_op_ext = {
	addr_ext: int;
	indirect: bool;
}

type m680x_op_value =
	| M680X_OP_INVALID of int
	| M680X_OP_IMMEDIATE of int
	| M680X_OP_REGISTER of int
	| M680X_OP_INDEXED of m680x_op_idx
	| M680X_OP_RELATIVE of m680x_op_rel
	| M680X_OP_EXTENDED of m680x_op_ext
	| M680X_OP_DIRECT of int
	| M680X_OP_CONSTANT of int

type m680x_op = {
	value: m680x_op_value;
	size: int;
	access: int;
}

type cs_m680x = {
	flags: int;
	operands: m680x_op array;
}

