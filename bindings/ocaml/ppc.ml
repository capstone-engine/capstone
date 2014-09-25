(* Capstone Disassembler Engine
 * By Guillaume Jeanne <guillaume.jeanne@ensimag.fr>, 2014> *)

open Ppc_const

type ppc_op_mem = {
	base: int;
	disp: int;
}

type ppc_op = 
	| PPC_OP_INVALID of int
	| PPC_OP_REG of int
	| PPC_OP_IMM of int
	| PPC_OP_MEM of ppc_op_mem

type cs_ppc = { 
	bc: int;
	bh: int;
	update_cr0: bool;
	op_count: int;
	operands: ppc_op array;
}

