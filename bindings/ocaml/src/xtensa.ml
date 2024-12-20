(* Capstone Disassembly Engine
 * By Anton Kochkov <anton.kochkov@gmail.com>, 2024 *)

(* architecture specific info of instruction *)

type xtensa_op_mem = {
	base: int;
	disp: int;
}

type xtensa_op_value =
	| XTENSA_OP_INVALID of int
	| XTENSA_OP_REG of int
	| XTENSA_OP_IMM of int
	| XTENSA_OP_MEM of xtensa_op_mem
	| XTENSA_OP_MEM_REG of int
	| XTENSA_OP_MEM_IMM of int
	| XTENSA_OP_L32R of int

type xtensa_op = {
	value: xtensa_op_value;
	access: int;
}

type cs_xtensa = {
	operands: xtensa_op array;
    format: int;
}
