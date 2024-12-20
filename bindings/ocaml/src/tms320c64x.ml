(* Capstone Disassembly Engine
* By Anton Kochkov <anton.kochkov@gmail.com>, 2024 *)

(* architecture specific info of instruction *)

type tms320c64x_op_mem = {
   base: int;
   disp: int;
   unit: int;
   scaled: int;
   disptype: int;
   direction: int;
   modify: int
}

type tms320c64x_op_value =
   | TMS320C64X_OP_INVALID of int
   | TMS320C64X_OP_REG of int
   | TMS320C64X_OP_IMM of int
   | TMS320C64X_OP_MEM of tms320c64x_op_mem
   | TMS320C64X_OP_REGPAIR of int

type tms320c64x_op = {
   value: tms320c64x_op_value;
}

type tms320c64x_condition = {
	reg: int;
	zero: int;
}

type tms320c64x_funit = {
	unit: int;
	side: int;
	crosspath: int;
}

type cs_tms320c64x = {
   operands: tms320c64x_op array;
   condition: tms320c64x_condition;
   funit: tms320c64x_funit;
   parallel: int;
}
