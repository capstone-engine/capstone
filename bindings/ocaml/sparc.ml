(* Capstone Disassembler Engine
 * By Guillaume Jeanne <guillaume.jeanne@ensimag.fr>, 2014> *)

open Sparc_const

type sparc_op_mem = {
	base: int;
	index: int;
	displ: int;
}

type sparc_op = 
	| SPARC_OP_INVALID of int
	| SPARC_OP_REG of int
	| SPARC_OP_IMM of int
	| SPARC_OP_MEM of sparc_op_mem

type cs_sparc = { 
	cc: int;
	hint: int;
	op_count: int;
	operands: sparc_op array;
}

