(* Capstone Disassembly Engine
 * By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 *)

open Aarch64_const

(* architecture specific info of instruction *)
type aarch64_op_shift = {
	shift_type: int;
	shift_value: int;
}

type aarch64_op_mem = {
	base: int;
	index: int;
	disp: int
}

type aarch64_op_value =
	| AARCH64_OP_INVALID of int
	| AARCH64_OP_REG of int
	| AARCH64_OP_CIMM of int
	| AARCH64_OP_IMM of int
	| AARCH64_OP_FP of float
	| AARCH64_OP_MEM of aarch64_op_mem
	| AARCH64_OP_REG_MRS of int
	| AARCH64_OP_REG_MSR of int
	| AARCH64_OP_PSTATE of int
	| AARCH64_OP_SYS of int
	| AARCH64_OP_PREFETCH of int
	| AARCH64_OP_BARRIER of int

type aarch64_op = {
	vector_index: int;
	vas: int;
	shift: aarch64_op_shift;
	ext: int;
	value: aarch64_op_value;
}

type cs_aarch64 = {
	cc: int;
	update_flags: bool;
	writeback: bool;
	operands: aarch64_op array;
}
