(* Capstone Disassembler Engine
 * By Guillaume Jeanne <guillaume.jeanne@ensimag.fr>, 2014> *)

open Sysz_const

type sysz_op_mem = {
	base: int;
	index: int;
	length: int64;
	disp: int64;
}

type sysz_op = 
	| SYSZ_OP_INVALID of int
	| SYSZ_OP_REG of int
	| SYSZ_OP_ACREG of int
	| SYSZ_OP_IMM of int
	| SYSZ_OP_MEM of sysz_op_mem

type cs_sysz = { 
	cc: int;
	op_count: int;
	operands: sysz_op array;
}
