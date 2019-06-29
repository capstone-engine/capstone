(* Capstone Disassembly Engine
 * By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 *)

open Arm64_const

(* architecture specific info of instruction *)
type arm64_op_shift = {
	shift_type: int;
	shift_value: int;
}

type arm64_op_mem = {
	base: int;
	index: int;
	disp: int
}

type arm64_op_value =
	| ARM64_OP_INVALID of int
	| ARM64_OP_REG of int
	| ARM64_OP_CIMM of int
	| ARM64_OP_IMM of int
	| ARM64_OP_FP of float
	| ARM64_OP_MEM of arm64_op_mem
	| ARM64_OP_REG_MRS of int
	| ARM64_OP_REG_MSR of int
	| ARM64_OP_PSTATE of int
	| ARM64_OP_SYS of int
	| ARM64_OP_PREFETCH of int
	| ARM64_OP_BARRIER of int

type arm64_op = {
	vector_index: int;
	vas: int;
	shift: arm64_op_shift;
	ext: int;
	value: arm64_op_value;
}

type cs_arm64 = {
	cc: int;
	update_flags: bool;
	writeback: bool;
	operands: arm64_op array;
}
