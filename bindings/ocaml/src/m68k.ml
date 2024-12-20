(* Capstone Disassembly Engine
 * By Anton Kochkov <anton.kochkov@gmail.com>, 2024 *)

(* architecture specific info of instruction *)

type m68k_op_mem = {
	base_reg: int;
	index_reg: int;
	in_base_reg: int;
	in_disp: int;
	out_disp: int;
	disp: int;
	scale: int;
	bitfield: int;
	width: int;
	offset: int;
	index_size: int;
}

type m68k_op_br_disp = {
	disp: int;
	disp_size: int;
}

type m68k_op_value =
	| M68K_OP_INVALID of int
	| M68K_OP_REG of int
	| M68K_OP_IMM of int
	| HPPA_OP_MEM of m68k_op_mem
	| HPPA_OP_FP_SINGLE of float
	| HPPA_OP_FP_DOUBLE of float
	| HPPA_OP_REG_BITS of int
	| HPPA_OP_REG_PAIR of int
	| HPPA_OP_BR_DISP of m68k_op_br_disp

type m68k_op_size =
	| M68K_CPU_SIZE of int
	| M68K_FPU_SIZE of int

type m68k_op = {
	value: m68k_op_value;
	address_mode: int;
}

type cs_m68k = {
	operands: m68k_op array;
	op_size: m68k_op_size;
}
