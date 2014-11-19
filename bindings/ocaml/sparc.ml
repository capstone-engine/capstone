(* Capstone Disassembly Engine
 * By Guillaume Jeanne <guillaume.jeanne@ensimag.fr>, 2014> *)

open Sparc_const

type sparc_op_mem = {
	base: int;
	index: int;
	disp: int;
}

type sparc_op_value = 
	| SPARC_OP_INVALID of int
	| SPARC_OP_REG of int
	| SPARC_OP_IMM of int
	| SPARC_OP_MEM of sparc_op_mem

type sparc_op = {
	value: sparc_op_value;
}

type cs_sparc = { 
	cc: int;
	hint: int;
	operands: sparc_op array;
}

