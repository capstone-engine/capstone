(* Capstone Disassembler Engine
 * By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> *)

open Arm64_const

(* architecture specific info of instruction *)
type arm64_op_shift = {
	shift_type: int;	(* TODO: covert this to pattern like arm_op_value? *)
	shift_value: int;
}

type arm64_op_mem = {
	base: int;
	index: int;
	displ: int
}

type arm64_op_value =
	| ARM64_OP_INVALID of int
	| ARM64_OP_REG of int
	| ARM64_OP_CIMM of int
	| ARM64_OP_IMM of int
	| ARM64_OP_FP of float
	| ARM64_OP_MEM of arm64_op_mem

type arm64_op = {
	shift: arm64_op_shift;
	ext: int;
	value: arm64_op_value;
}

type cs_arm64 = {
	cc: int;
	update_flags: bool;
	writeback: bool;
	op_count: int;
	operands: arm64_op array;
}
