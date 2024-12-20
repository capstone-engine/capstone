(* Capstone Disassembly Engine
 * By Anton Kochkov <anton.kochkov@gmail.com>, 2024> *)

type alpha_op_value = 
	| ALPHA_OP_INVALID of int
	| ALPHA_OP_REG of int
	| ALPHA_OP_IMM of int

type alpha_op = {
	value: alpha_op_value;
}

type cs_alpha = { 
	operands: alpha_op array;
}

