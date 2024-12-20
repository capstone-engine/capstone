(* Capstone Disassembly Engine
 * By Guillaume Jeanne <guillaume.jeanne@ensimag.fr>, 2014 *)

type systemz_op_mem = {
	base: int;
	index: int;
	length: int64;
	disp: int64;
}

type systemz_op_value = 
	| SYSTEMZ_OP_INVALID of int
	| SYSTEMZ_OP_REG of int
	| SYSTEMZ_OP_ACREG of int
	| SYSTEMZ_OP_IMM of int
	| SYSTEMZ_OP_MEM of systemz_op_mem

type systemz_op = {
	value: systemz_op_value;
}

type cs_systemz = { 
	cc: int;
	operands: systemz_op array;
}
