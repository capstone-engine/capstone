(* Capstone Disassembly Engine
 * By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 *)

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
	disp: int
}

type arm_op_value =
	| ARM_OP_INVALID of int
	| ARM_OP_REG of int
	| ARM_OP_CIMM of int
	| ARM_OP_PIMM of int
	| ARM_OP_IMM of int
	| ARM_OP_FP of float
	| ARM_OP_MEM of arm_op_mem
	| ARM_OP_SETEND of int

type arm_op = {
	vector_index: int;
	shift: arm_op_shift;
	value: arm_op_value;
	subtracted: bool;
}

type cs_arm = {
	usermode: bool;
	vector_size: int;
	vector_data: int;
	cps_mode: int;
	cps_flag: int;
	cc: int;
	update_flags: bool;
	writeback: bool;
	mem_barrier: int;
	operands: arm_op array;
}
