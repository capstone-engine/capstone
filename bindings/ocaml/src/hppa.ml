(* Capstone Disassembly Engine
 * By Anton Kochkov <anton.kochkov@gmail.com>, 2024 *)

(* architecture specific info of instruction *)

type hppa_op_mem = {
	base: int;
	space: int;
	base_access: int
}

type hppa_op_value =
	| HPPA_OP_INVALID of int
	| HPPA_OP_REG of int
	| HPPA_OP_IMM of int
	| HPPA_OP_IDX_REG of int
	| HPPA_OP_DISP_REG of int
	| HPPA_OP_MEM of hppa_op_mem
	| HPPA_OP_TARGET of int

type hppa_op = {
	value: hppa_op_value;
	access: int;
}

type cs_hppa = {
	operands: hppa_op array;
}
