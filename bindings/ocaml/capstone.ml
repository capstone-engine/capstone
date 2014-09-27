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
open Printf	(* debug *)

type arch =
  | CS_ARCH_ARM
  | CS_ARCH_ARM64
  | CS_ARCH_MIPS
  | CS_ARCH_X86
  | CS_ARCH_PPC
  | CS_ARCH_SPARC
  | CS_ARCH_SYSZ
  | CS_ARCH_XCORE

type mode =
  |	CS_MODE_LITTLE_ENDIAN	(* little-endian mode (default mode) *)
  |	CS_MODE_ARM			(* ARM mode *)
  |	CS_MODE_16			(* 16-bit mode (for X86, Mips) *)
  |	CS_MODE_32			(* 32-bit mode (for X86, Mips) *)
  |	CS_MODE_64			(* 64-bit mode (for X86, Mips) *)
  |	CS_MODE_THUMB		(* ARM's Thumb mode, including Thumb-2 *)
  |	CS_MODE_MCLASS		(* ARM's MClass mode *)
  |	CS_MODE_MICRO		(* MicroMips mode (MIPS architecture) *)
  |	CS_MODE_N64			(* Nintendo-64 mode (MIPS architecture) *)
  |	CS_MODE_MIPS3		(* Mips3 mode (MIPS architecture) *)
  |	CS_MODE_MIPS32R6	(* Mips32-R6 mode (MIPS architecture) *)
  |	CS_MODE_MIPSGP64	(* MipsGP64 mode (MIPS architecture) *)
  |	CS_MODE_V9			(* SparcV9 mode (Sparc architecture) *)
  |	CS_MODE_BIG_ENDIAN	(* big-endian mode *)


type opt_type =
  |	CS_OPT_SYNTAX		(*  Asssembly output syntax *)
  |	CS_OPT_DETAIL		(* Break down instruction structure into details *)
  |	CS_OPT_MODE		(* Change engine's mode at run-time *)
  |	CS_OPT_MEM		(* User-defined dynamic memory related functions *)
  |	CS_OPT_SKIPDATA		(* Skip data when disassembling. Then engine is in SKIPDATA mode. *)
  |	CS_OPT_SKIPDATA_SETUP 	(* Setup user-defined function for SKIPDATA option *)


type opt_value = 
  |	CS_OPT_OFF 		(* Turn OFF an option - default option of CS_OPT_DETAIL, CS_OPT_SKIPDATA. *)
  |	CS_OPT_ON  		(* Turn ON an option (CS_OPT_DETAIL, CS_OPT_SKIPDATA). *)
  |	CS_OPT_SYNTAX_DEFAULT 	(* Default asm syntax (CS_OPT_SYNTAX). *)
  |	CS_OPT_SYNTAX_INTEL 	(* X86 Intel asm syntax - default on X86 (CS_OPT_SYNTAX). *)
  |	CS_OPT_SYNTAX_ATT 	(* X86 ATT asm syntax (CS_OPT_SYNTAX). *)
  |	CS_OPT_SYNTAX_NOREGNAME	(* Prints register name with only number (CS_OPT_SYNTAX) *)

type cs_arch = 
	| CS_INFO_ARM of cs_arm
	| CS_INFO_ARM64 of cs_arm64
	| CS_INFO_MIPS of cs_mips
	| CS_INFO_X86 of cs_x86
	| CS_INFO_PPC of cs_ppc
	| CS_INFO_SPARC of cs_sparc
	| CS_INFO_SYSZ of cs_sysz
	| CS_INFO_XCORE of cs_xcore


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

external cs_open: arch -> mode list -> Int64.t option = "ocaml_cs_open"
external cs_disasm: arch -> mode list -> string -> Int64.t -> Int64.t -> cs_insn0 list = "ocaml_cs_disasm"
external _cs_disasm_internal: arch -> Int64.t -> string -> Int64.t -> Int64.t -> cs_insn0 list = "ocaml_cs_disasm_internal"
external cs_reg_name: Int64.t -> int -> string = "ocaml_register_name"
external cs_insn_name: Int64.t -> int -> string = "ocaml_instruction_name"
external cs_group_name: Int64.t -> int -> string = "ocaml_group_name"
external cs_version: unit -> int = "ocaml_version"

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
		method insn_name = cs_insn_name csh id;
	end;;

let cs_insn_group handle insn group_id =
	List.exists (fun g -> g == group_id) (Array.to_list insn.groups);;

let cs_reg_read handle insn reg_id =
	List.exists (fun g -> g == reg_id) (Array.to_list insn.regs_read);;

let cs_reg_write handle insn reg_id =
	List.exists (fun g -> g == reg_id) (Array.to_list insn.regs_write);;


class cs a m =
	let mode = m and arch = a in
	let csh = cs_open arch mode in
	object
		val handle = match csh with
			| None -> failwith "impossible to open an handle"
			| Some v -> v

		method get_csh = handle

		method disasm code offset count =
			let insns = (_cs_disasm_internal arch handle code offset count) in
			List.map (fun x -> new cs_insn handle x) insns;

	end;;

