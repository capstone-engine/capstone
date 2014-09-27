(* Capstone Disassembly Engine
 * By Guillaume Jeanne <guillaume.jeanne@ensimag.fr>, 2014> *)

open Xcore_const

type xcore_op_mem = {
	base: int;
	index: int;
	disp: int;
	direct: int;
}

type xcore_op_value =
	| XCORE_OP_INVALID of int
	| XCORE_OP_REG of int
	| XCORE_OP_IMM of int
	| XCORE_OP_MEM of xcore_op_mem

type xcore_op = {
	value: xcore_op_value;
}

type cs_xcore = { 
	operands: xcore_op array;
}

