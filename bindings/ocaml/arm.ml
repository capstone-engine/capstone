(* Capstone Disassembler Engine
 * By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> *)

open Arm_const

let _CS_OP_ARCH = 5;;
let _CS_OP_CIMM = _CS_OP_ARCH         (* C-Immediate *)
let _CS_OP_PIMM = _CS_OP_ARCH + 1     (* P-Immediate *)


(* architecture specific info of instruction *)
type arm_op_shift = {
	shift_type: int;	(* TODO: covert this to pattern like arm_op_value? *)
	shift_value: int;
}

type arm_op_mem = {
	base: int;
	index: int;
	scale: int;
	displ: int
}

type arm_op_value =
	| ARM_OP_INVALID of int
	| ARM_OP_REG of int
	| ARM_OP_CIMM of int
	| ARM_OP_PIMM of int
	| ARM_OP_IMM of int
	| ARM_OP_FP of float
	| ARM_OP_MEM of arm_op_mem

type arm_op = {
	shift: arm_op_shift;
	value: arm_op_value;
}

type cs_arm = {
	cc: int;
	update_flags: bool;
	writeback: bool;
	op_count: int;
	operands: arm_op array;
}
