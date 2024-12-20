(* Capstone Disassembly Engine
 * By Anton Kochkov <anton.kochkov@gmail.com>, 2024 *)

(* architecture specific info of instruction *)

type loongarch_op_mem = {
	base: int;
	index: int;
	disp: int
}

type loongarch_op_value =
	| LOONGARCH_OP_INVALID of int
	| LOONGARCH_OP_REG of int
	| LOONGARCH_OP_IMM of int
	| LOONGARCH_OP_MEM of loongarch_op_mem

type loongarch_op = {
	value: loongarch_op_value;
	access: int;
}

type cs_loongarch = {
	operands: loongarch_op array;
}
