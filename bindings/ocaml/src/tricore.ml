(* Capstone Disassembly Engine
 * By Anton Kochkov <anton.kochkov@gmail.com>, 2024 *)

(* architecture specific info of instruction *)

type tricore_op_mem = {
	base: int;
	disp: int;
}

type tricore_op_value =
	| TRICORE_OP_INVALID of int
	| TRICORE_OP_REG of int
	| TRICORE_OP_IMM of int
	| TRICORE_OP_MEM of tricore_op_mem

type tricore_op = {
	value: tricore_op_value;
	access: int;
}

type cs_tricore = {
	operands: tricore_op array;
	update_flags: bool;
}
