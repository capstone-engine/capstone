(* Capstone Disassembly Engine
 * By Anton Kochkov <anton.kochkov@gmail.com>, 2024 *)

(* architecture specific info of instruction *)

type sh_op_mem = {
	address: int;
	reg: int;
	disp: int
}

type sh_op_value =
	| SH_OP_INVALID of int
	| SH_OP_REG of int
	| SH_OP_IMM of int
	| SH_OP_MEM of sh_op_mem

type sh_op = {
	value: sh_op_value;
}

type cs_sh = {
	operands: sh_op array;
	size: int;
}
