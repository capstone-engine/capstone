(* Capstone Disassembly Engine
 * By Guillaume Jeanne <guillaume.jeanne@ensimag.fr>, 2014> *)

open Ppc_const

type ppc_op_mem = {
	base: int;
	disp: int;
}

type ppc_op_crx = {
	scale: int;
	reg: int;
	cond: int;
}

type ppc_op_value = 
	| PPC_OP_INVALID of int
	| PPC_OP_REG of int
	| PPC_OP_IMM of int
	| PPC_OP_MEM of ppc_op_mem
	| PPC_OP_CRX of ppc_op_crx

type ppc_op = {
	value: ppc_op_value;
}

type cs_ppc = { 
	bc: int;
	bh: int;
	update_cr0: bool;
	operands: ppc_op array;
}

