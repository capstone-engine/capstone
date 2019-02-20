/*
	Capstone Disassembly Engine bindings for VB6
	Contributed by FireEye FLARE Team
	Author:  David Zimmer <david.zimmer@fireeye.com>, <dzzie@yahoo.com>
	License: Apache  
	Copyright: FireEye 2017

	This dll is a small stdcall shim so VB6 can access the capstone API
*/

#include <stdio.h>
#include <conio.h>
#include <string.h>

#include <capstone.h>
#pragma comment(lib, "capstone.lib")

#define EXPORT comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)

unsigned int __stdcall bs_version(int *major, int *minor){
#pragma EXPORT
	return cs_version(major,minor);	
}

bool __stdcall bs_support(int query){
#pragma EXPORT
	return cs_support(query);
}

cs_err __stdcall bs_open(cs_arch arch, cs_mode mode, csh *handle){
#pragma EXPORT
	return cs_open(arch, mode, handle);
}

cs_err __stdcall bs_close(csh *handle){
#pragma EXPORT
	return cs_close(handle);
}

cs_err __stdcall bs_option(csh handle, cs_opt_type type, size_t value){
#pragma EXPORT
	return cs_option(handle, type, value);
}

cs_err __stdcall bs_errno(csh handle){
#pragma EXPORT
	return cs_errno(handle);
}

const char* __stdcall bs_strerror(cs_err code){
#pragma EXPORT
	return cs_strerror(code);
}

size_t __stdcall bs_disasm(csh handle, const uint8_t *code, size_t code_size, uint64_t address, size_t count, cs_insn **insn){
#pragma EXPORT
	return cs_disasm(handle, code, code_size, address, count, insn);
}

void __stdcall getInstruction(cs_insn *insn, uint32_t index, void* curInst, uint32_t bufSize){
#pragma EXPORT
	memcpy(curInst, (void*)&insn[index], bufSize); //size lets us get a partial version of whatever we have implemented in the vbstruct...
}

const char* __stdcall bs_reg_name(csh handle, unsigned int reg_id){
#pragma EXPORT
	return cs_reg_name(handle, reg_id);
}

void __stdcall bs_free(cs_insn *insn, size_t count){
#pragma EXPORT
	return cs_free(insn, count);
}

cs_insn* __stdcall bs_malloc(csh handle){
#pragma EXPORT
	return cs_malloc(handle);
}


int __stdcall bs_op_index(csh handle, const cs_insn *insn, unsigned int op_type, unsigned int position){
#pragma EXPORT
	return cs_op_index(handle,insn,op_type,position);
}

int __stdcall bs_op_count(csh handle, const cs_insn *insn, unsigned int op_type){
#pragma EXPORT
	return cs_op_count(handle,insn,op_type);
}

bool __stdcall bs_reg_write(csh handle, const cs_insn *insn, unsigned int reg_id){
#pragma EXPORT
	return cs_reg_write(handle,insn,reg_id);
}

bool __stdcall bs_reg_read(csh handle, const cs_insn *insn, unsigned int reg_id){
#pragma EXPORT
	return cs_reg_read(handle,insn,reg_id);
}

bool __stdcall bs_insn_group(csh handle, const cs_insn *insn, unsigned int group_id){
#pragma EXPORT
	return cs_insn_group(handle,insn,group_id);
}

const char* __stdcall bcs_group_name(csh handle, unsigned int group_id){
#pragma EXPORT
	return cs_group_name(handle,group_id);
}

const char* __stdcall bs_insn_name(csh handle, unsigned int insn_id){
#pragma EXPORT
	return cs_insn_name(handle,insn_id);
}

bool __stdcall bs_disasm_iter(csh handle, const uint8_t **code, size_t *size, uint64_t *address, cs_insn *insn){
#pragma EXPORT
	return cs_disasm_iter(handle, code, size, address, insn);
}
