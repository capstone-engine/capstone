(* Capstone Disassembly Engine
 * By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 *)

open Arm
open Arm64
open Mips
open Ppc
open X86
open Sparc
open Systemz
open Xcore
open M680x
open Printf	(* debug *)

(* Hardware architectures *)
type arch =
  | CS_ARCH_ARM
  | CS_ARCH_ARM64
  | CS_ARCH_MIPS
  | CS_ARCH_X86
  | CS_ARCH_PPC
  | CS_ARCH_SPARC
  | CS_ARCH_SYSZ
  | CS_ARCH_XCORE
  | CS_ARCH_M68K
  | CS_ARCH_TMS320C64X
  | CS_ARCH_M680X

(* Hardware modes *)
type mode =
  |	CS_MODE_LITTLE_ENDIAN	(* little-endian mode (default mode) *)
  |	CS_MODE_ARM			(* ARM mode *)
  |	CS_MODE_16			(* 16-bit mode (for X86) *)
  |	CS_MODE_32			(* 32-bit mode (for X86) *)
  |	CS_MODE_64			(* 64-bit mode (for X86, PPC) *)
  |	CS_MODE_THUMB		(* ARM's Thumb mode, including Thumb-2 *)
  |	CS_MODE_MCLASS		(* ARM's MClass mode *)
  |	CS_MODE_V8    		(* ARMv8 A32 encodings for ARM *)
  |	CS_MODE_MICRO		(* MicroMips mode (MIPS architecture) *)
  |	CS_MODE_MIPS3		(* Mips3 mode (MIPS architecture) *)
  |	CS_MODE_MIPS32R6	(* Mips32-R6 mode (MIPS architecture) *)
  |	CS_MODE_MIPS2		(* Mips2 mode (MIPS architecture) *)
  |	CS_MODE_V9			(* SparcV9 mode (Sparc architecture) *)
  |	CS_MODE_BIG_ENDIAN	(* big-endian mode *)
  |	CS_MODE_MIPS32		(* Mips32 mode (for Mips) *)
  |	CS_MODE_MIPS64		(* Mips64 mode (for Mips) *)
  |	CS_MODE_QPX			(* Quad Processing eXtensions mode (PowerPC) *)
  |	CS_MODE_SPE			(* Signal Processing Engine mode (PowerPC) *)
  |	CS_MODE_BOOKE		(* Book-E mode (PowerPC) *)
  |	CS_MODE_PS			(* Paired-singles mode (PowerPC) *)
  |	CS_MODE_M680X_6301	(* M680X Hitachi 6301,6303 mode *)
  |	CS_MODE_M680X_6309	(* M680X Hitachi 6309 mode *)
  |	CS_MODE_M680X_6800	(* M680X Motorola 6800,6802 mode *)
  |	CS_MODE_M680X_6801	(* M680X Motorola 6801,6803 mode *)
  |	CS_MODE_M680X_6805	(* M680X Motorola 6805 mode *)
  |	CS_MODE_M680X_6808	(* M680X Motorola 6808 mode *)
  |	CS_MODE_M680X_6809	(* M680X Motorola 6809 mode *)
  |	CS_MODE_M680X_6811	(* M680X Motorola/Freescale 68HC11 mode *)
  |	CS_MODE_M680X_CPU12	(* M680X Motorola/Freescale/NXP CPU12 mode *)
  |	CS_MODE_M680X_HCS08	(* M680X Freescale HCS08 mode *)



(* Runtime option for the disassembled engine *)
type opt_type =
  |	CS_OPT_SYNTAX		(*  Asssembly output syntax *)
  |	CS_OPT_DETAIL		(* Break down instruction structure into details *)
  |	CS_OPT_MODE		(* Change engine's mode at run-time *)
  |	CS_OPT_MEM		(* User-defined dynamic memory related functions *)
  |	CS_OPT_SKIPDATA		(* Skip data when disassembling. Then engine is in SKIPDATA mode. *)
  |	CS_OPT_SKIPDATA_SETUP 	(* Setup user-defined function for SKIPDATA option *)


(* Common instruction operand access types - to be consistent across all architectures. *)
(* It is possible to combine access types, for example: CS_AC_READ | CS_AC_WRITE *)
let _CS_AC_INVALID = 0;;	(* Uninitialized/invalid access type. *)
let _CS_AC_READ    = 1 lsl 0;; (* Operand read from memory or register. *)
let _CS_AC_WRITE   = 1 lsl 1;; (* Operand write to memory or register. *)

(* Runtime option value (associated with option type above) *)
let _CS_OPT_OFF = 0L;; (* Turn OFF an option - default option of CS_OPT_DETAIL, CS_OPT_SKIPDATA. *)
let _CS_OPT_ON = 3L;;  (* Turn ON an option (CS_OPT_DETAIL, CS_OPT_SKIPDATA). *)
let _CS_OPT_SYNTAX_DEFAULT = 0L;; (* Default asm syntax (CS_OPT_SYNTAX). *)
let _CS_OPT_SYNTAX_INTEL = 1L;; (* X86 Intel asm syntax - default on X86 (CS_OPT_SYNTAX). *)
let _CS_OPT_SYNTAX_ATT = 2L;; (* X86 ATT asm syntax (CS_OPT_SYNTAX). *)
let _CS_OPT_SYNTAX_NOREGNAME = 3L;; (* Prints register name with only number (CS_OPT_SYNTAX) *)

(* Common instruction operand types - to be consistent across all architectures. *)
let _CS_OP_INVALID = 0;;  (* uninitialized/invalid operand. *)
let _CS_OP_REG     = 1;;  (* Register operand. *)
let _CS_OP_IMM     = 2;;  (* Immediate operand. *)
let _CS_OP_MEM     = 3;;  (* Memory operand. *)
let _CS_OP_FP      = 4;;  (* Floating-Point operand. *)

(* Common instruction groups - to be consistent across all architectures. *)
let _CS_GRP_INVALID = 0;;  (* uninitialized/invalid group. *)
let _CS_GRP_JUMP    = 1;;  (* all jump instructions (conditional+direct+indirect jumps) *)
let _CS_GRP_CALL    = 2;;  (* all call instructions *)
let _CS_GRP_RET     = 3;;  (* all return instructions *)
let _CS_GRP_INT     = 4;;  (* all interrupt instructions (int+syscall) *)
let _CS_GRP_IRET    = 5;;  (* all interrupt return instructions *)
let _CS_GRP_PRIVILEGE = 6;;  (* all privileged instructions *)

type cs_arch =
	| CS_INFO_ARM of cs_arm
	| CS_INFO_ARM64 of cs_arm64
	| CS_INFO_MIPS of cs_mips
	| CS_INFO_X86 of cs_x86
	| CS_INFO_PPC of cs_ppc
	| CS_INFO_SPARC of cs_sparc
	| CS_INFO_SYSZ of cs_sysz
	| CS_INFO_XCORE of cs_xcore
	| CS_INFO_M680X of cs_m680x


type csh = {
	h: Int64.t;
	a: arch;
}

type cs_insn0 = {
	id: int;
	address: int;
	size: int;
	bytes: int array;
	mnemonic: string;
	op_str: string;
	regs_read: int array;
	regs_write: int array;
	groups: int array;
	arch: cs_arch;
}

external _cs_open: arch -> mode list -> Int64.t option = "ocaml_open"
external cs_disasm_quick: arch -> mode list -> string -> Int64.t -> Int64.t -> cs_insn0 list = "ocaml_cs_disasm"
external _cs_disasm_internal: arch -> Int64.t -> string -> Int64.t -> Int64.t -> cs_insn0 list = "ocaml_cs_disasm_internal"
external _cs_reg_name: Int64.t -> int -> string = "ocaml_register_name"
external _cs_insn_name: Int64.t -> int -> string = "ocaml_instruction_name"
external _cs_group_name: Int64.t -> int -> string = "ocaml_group_name"
external cs_version: unit -> int = "ocaml_version"
external _cs_option: Int64.t -> opt_type -> Int64.t -> int = "ocaml_option"
external _cs_close: Int64.t -> int = "ocaml_close"


let cs_open _arch _mode: csh = (
	let _handle = _cs_open _arch _mode in (
	match _handle with
	| None -> { h = 0L; a = _arch }
	| Some v -> { h = v; a = _arch }
	);
);;

let cs_close handle = (
	_cs_close handle.h;
)

let cs_option handle opt value = (
	_cs_option handle.h opt value;
);;

let cs_disasm handle code address count = (
	_cs_disasm_internal handle.a handle.h code address count;
);;

let cs_reg_name handle id = (
	_cs_reg_name handle.h id;
);;

let cs_insn_name handle id = (
	_cs_insn_name handle.h id;
);;

let cs_group_name handle id = (
	_cs_group_name handle.h id;
);;

class cs_insn c a =
	let csh = c in
	let (id, address, size, bytes, mnemonic, op_str, regs_read,
        regs_write, groups, arch) =
        (a.id, a.address, a.size, a.bytes, a.mnemonic, a.op_str,
        a.regs_read, a.regs_write, a.groups, a.arch) in
	object
		method id = id;
		method address = address;
		method size = size;
	        method bytes = bytes;
		method mnemonic = mnemonic;
		method op_str = op_str;
		method regs_read = regs_read;
		method regs_write = regs_write;
		method groups = groups;
		method arch = arch;
		method reg_name id = _cs_reg_name csh.h id;
		method insn_name id = _cs_insn_name csh.h id;
		method group_name id = _cs_group_name csh.h id;
	end;;

let cs_insn_group handle insn group_id =
	List.exists (fun g -> g == group_id) (Array.to_list insn.groups);;

let cs_reg_read handle insn reg_id =
	List.exists (fun g -> g == reg_id) (Array.to_list insn.regs_read);;

let cs_reg_write handle insn reg_id =
	List.exists (fun g -> g == reg_id) (Array.to_list insn.regs_write);;


class cs a m =
	let mode = m and arch = a in
	let handle = cs_open arch mode in
	object
		method disasm code offset count =
			let insns = (_cs_disasm_internal arch handle.h code offset count) in
			List.map (fun x -> new cs_insn handle x) insns;

	end;;
