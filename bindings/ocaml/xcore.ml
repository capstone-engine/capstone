(* Capstone Disassembler Engine
 * By Guillaume Jeanne <guillaume.jeanne@ensimag.fr>, 2014> *)

open Xcore_const

type xcore_op_mem = {
	base: int;
	index: int;
	displ: int;
	direct: int;
}

type xcore_op = 
	| XCORE_OP_INVALID of int
	| XCORE_OP_REG of int
	| XCORE_OP_IMM of int
	| XCORE_OP_MEM of xcore_op_mem

type cs_xcore = { 
	op_count: int;
	operands: xcore_op array;
}

