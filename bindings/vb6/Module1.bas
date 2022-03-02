Attribute VB_Name = "mCapStone"
Option Explicit

'Capstone Disassembly Engine bindings for VB6
'Contributed by FireEye FLARE Team
'Author:  David Zimmer <david.zimmer@fireeye.com>, <dzzie@yahoo.com>
'License: Apache 2.0
'Copyright: FireEye 2017

'todo: cs_disasm_iter / skipdata

'this is for my vb code and how much info it spits out in tostring methods..
Global Const DEBUG_DUMP = 0

'Architecture type
Public Enum cs_arch
    CS_ARCH_ARM = 0      ' ARM architecture (including Thumb, Thumb-2)
    CS_ARCH_ARM64        ' ARM-64, also called AArch64
    CS_ARCH_MIPS         ' Mips architecture
    CS_ARCH_X86          ' X86 architecture (including x86 & x86-64)
    CS_ARCH_PPC          ' PowerPC architecture
    CS_ARCH_SPARC        ' Sparc architecture
    CS_ARCH_SYSZ         ' SystemZ architecture
    CS_ARCH_XCORE        ' XCore architecture
    CS_ARCH_MAX
    CS_ARCH_ALL = &HFFFF ' All architectures - for cs_support()
End Enum

Public Enum cs_mode
    CS_MODE_LITTLE_ENDIAN = 0       ' little-endian mode (default mode)
    CS_MODE_ARM = 0                 ' 32-bit ARM
    CS_MODE_16 = 2                  ' 16-bit mode (X86)
    CS_MODE_32 = 4                  ' 32-bit mode (X86)
    CS_MODE_64 = 8                  ' 64-bit mode (X86, PPC)
    CS_MODE_THUMB = 16              ' ARM's Thumb mode, including Thumb-2
    CS_MODE_MCLASS = 32             ' ARM's Cortex-M series
    CS_MODE_V8 = 64                 ' ARMv8 A32 encodings for ARM
    CS_MODE_MICRO = 16              ' MicroMips mode (MIPS)
    CS_MODE_MIPS3 = 32              ' Mips III ISA
    CS_MODE_MIPS32R6 = 64           ' Mips32r6 ISA
    CS_MODE_MIPSGP64 = 128          ' General Purpose Registers are 64-bit wide (MIPS)
    CS_MODE_V9 = 16                 ' SparcV9 mode (Sparc)
    CS_MODE_BIG_ENDIAN = &H80000000 ' big-endian mode
    CS_MODE_MIPS32 = CS_MODE_32     ' Mips32 ISA (Mips)
    CS_MODE_MIPS64 = CS_MODE_64     ' Mips64 ISA (Mips)
End Enum

'Runtime option for the disassembled engine
Public Enum cs_opt_type
    CS_OPT_SYNTAX = 1     ' Assembly output syntax
    CS_OPT_DETAIL         ' Break down instruction structure into details
    CS_OPT_MODE           ' Change engine's mode at run-time
    CS_OPT_MEM            ' User-defined dynamic memory related functions
    CS_OPT_SKIPDATA       ' Skip data when disassembling. Then engine is in SKIPDATA mode.
    CS_OPT_SKIPDATA_SETUP ' Setup user-defined function for SKIPDATA option
End Enum


'Runtime option value (associated with option type above)
Public Enum cs_opt_value
    CS_OPT_OFF = 0          ' Turn OFF an option - default option of CS_OPT_DETAIL, CS_OPT_SKIPDATA.
    CS_OPT_ON = 3           ' Turn ON an option (CS_OPT_DETAIL, CS_OPT_SKIPDATA).
    CS_OPT_SYNTAX_DEFAULT = 0 ' Default asm syntax (CS_OPT_SYNTAX).
    CS_OPT_SYNTAX_INTEL     ' X86 Intel asm syntax - default on X86 (CS_OPT_SYNTAX).
    CS_OPT_SYNTAX_ATT       ' X86 ATT asm syntax (CS_OPT_SYNTAX).
    CS_OPT_SYNTAX_NOREGNAME ' Prints register name with only number (CS_OPT_SYNTAX)
End Enum

'Common instruction operand types - to be consistent across all architectures.
Public Enum cs_op_type
    CS_OP_INVALID = 0 ' uninitialized/invalid operand.
    CS_OP_REG       ' Register operand.
    CS_OP_IMM       ' Immediate operand.
    CS_OP_MEM       ' Memory operand.
    CS_OP_FP        ' Floating-Point operand.
End Enum

'Common instruction groups - to be consistent across all architectures.
Public Enum cs_group_type
    CS_GRP_INVALID = 0 ' uninitialized/invalid group.
    CS_GRP_JUMP      ' all jump instructions (conditional+direct+indirect jumps)
    CS_GRP_CALL      ' all call instructions
    CS_GRP_RET       ' all return instructions
    CS_GRP_INT       ' all interrupt instructions (int+syscall)
    CS_GRP_IRET      ' all interrupt return instructions
End Enum


'NOTE: All information in cs_detail is only available when CS_OPT_DETAIL = CS_OPT_ON
Public Type cs_detail
    regs_read(0 To 15) As Byte      ' list of implicit registers read by this insn UNSIGNED
    regs_read_count As Byte         ' number of implicit registers read by this insn UNSIGNED
    regs_write(0 To 19) As Byte     ' list of implicit registers modified by this insn UNSIGNED
    regs_write_count As Byte        ' number of implicit registers modified by this insn UNSIGNED
    groups(0 To 7) As Byte          ' list of group this instruction belong to UNSIGNED
    groups_count As Byte            ' number of groups this insn belongs to UNSIGNED
End Type

'typedef struct cs_detail {
'    uint8_t regs_read[16]; // list of implicit registers read by this insn
'    uint8_t regs_read_count; // number of implicit registers read by this insn
'
'    uint8_t regs_write[20]; // list of implicit registers modified by this insn
'    uint8_t regs_write_count; // number of implicit registers modified by this insn
'
'    uint8_t groups[8]; // list of group this instruction belong to
'    uint8_t groups_count; // number of groups this insn belongs to
'
'    // Architecture-specific instruction info
'    union {
'        cs_x86 x86; // X86 architecture, including 16-bit, 32-bit & 64-bit mode
'        cs_arm64 arm64; // ARM64 architecture (aka AArch64)
'        cs_arm arm;     // ARM architecture (including Thumb/Thumb2)
'        cs_mips mips;   // MIPS architecture
'        cs_ppc ppc; // PowerPC architecture
'        cs_sparc sparc; // Sparc architecture
'        cs_sysz sysz;   // SystemZ architecture
'        cs_xcore xcore; // XCore architecture
'    };
'} cs_detail;

'Detail information of disassembled instruction
Public Type cs_insn
                              ' Instruction ID (basically a numeric ID for the instruction mnemonic)
                              ' Find the instruction id in the '[ARCH]_insn' enum in the header file
                              ' of corresponding architecture, such as 'arm_insn' in arm.h for ARM,
                              ' 'x86_insn' in x86.h for X86, etc...
                              ' available even when CS_OPT_DETAIL = CS_OPT_OFF
                              ' NOTE: in Skipdata mode, "data" instruction has 0 for this id field. UNSIGNED
    ID As Long                '
    align As Long             'not sure why it needs this..but it does..
    address As Currency       ' Address (EIP) of this instruction available even when CS_OPT_DETAIL = CS_OPT_OFF UNSIGNED
    size As Integer           ' Size of this instruction available even when CS_OPT_DETAIL = CS_OPT_OFF UNSIGNED
    bytes(0 To 23) As Byte    ' Machine bytes of this instruction, with number of bytes indicated by @size above available even when CS_OPT_DETAIL = CS_OPT_OFF
    mnemonic(0 To 31) As Byte ' Ascii text of instruction mnemonic available even when CS_OPT_DETAIL = CS_OPT_OFF
    op_str(0 To 159) As Byte  ' Ascii text of instruction operands available even when CS_OPT_DETAIL = CS_OPT_OFF
                            
                              ' Pointer to cs_detail.
                              ' NOTE: detail pointer is only valid when both requirements below are met:
                              ' (1) CS_OP_DETAIL = CS_OPT_ON
                              ' (2) Engine is not in Skipdata mode (CS_OP_SKIPDATA option set to CS_OPT_ON)
                              ' NOTE 2: when in Skipdata mode, or when detail mode is OFF, even if this pointer
                              '  is not NULL, its content is still irrelevant.
    lpDetail As Long          '  points to a cs_detail structure NOTE: only available when CS_OPT_DETAIL = CS_OPT_ON

End Type

'All type of errors encountered by Capstone API.
'These are values returned by cs_errno()
Public Enum cs_err
    CS_ERR_OK = 0    ' No error: everything was fine
    CS_ERR_MEM       ' Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
    CS_ERR_ARCH      ' Unsupported architecture: cs_open()
    CS_ERR_HANDLE    ' Invalid handle: cs_op_count(), cs_op_index()
    CS_ERR_CSH       ' Invalid csh argument: cs_close(), cs_errno(), cs_option()
    CS_ERR_MODE      ' Invalid/unsupported mode: cs_open()
    CS_ERR_OPTION    ' Invalid/unsupported option: cs_option()
    CS_ERR_DETAIL    ' Information is unavailable because detail option is OFF
    CS_ERR_MEMSETUP  ' Dynamic memory management uninitialized (see CS_OPT_MEM)
    CS_ERR_VERSION   ' Unsupported version (bindings)
    CS_ERR_DIET      ' Access irrelevant data in "diet" engine
    CS_ERR_SKIPDATA  ' Access irrelevant data for "data" instruction in SKIPDATA mode
    CS_ERR_X86_ATT   ' X86 AT&T syntax is unsupported (opt-out at compile time)
    CS_ERR_X86_INTEL ' X86 Intel syntax is unsupported (opt-out at compile time)
End Enum


'/*
' Return combined API version & major and minor version numbers.
'
' @major: major number of API version
' @minor: minor number of API version
'
' @return hexical number as (major << 8 | minor), which encodes both
'     major & minor versions.
'     NOTE: This returned value can be compared with version number made
'     with macro CS_MAKE_VERSION
'
' For example, second API version would return 1 in @major, and 1 in @minor
' The return value would be 0x0101
'
' NOTE: if you only care about returned value, but not major and minor values,
' set both @major & @minor arguments to NULL.
'*/
'CAPSTONE_EXPORT
'unsigned int cs_version(int *major, int *minor);
Public Declare Function cs_version Lib "vbCapstone.dll" Alias "bs_version" (ByRef major As Long, ByRef minor As Long) As Long



'
'/*
' This API can be used to either ask for archs supported by this library,
' or check to see if the library was compile with 'diet' option (or called
' in 'diet' mode).
'
' To check if a particular arch is supported by this library, set @query to
' arch mode (CS_ARCH_* value).
' To verify if this library supports all the archs, use CS_ARCH_ALL.
'
' To check if this library is in 'diet' mode, set @query to CS_SUPPORT_DIET.
'
' @return True if this library supports the given arch, or in 'diet' mode.
'*/
'CAPSTONE_EXPORT
'bool cs_support(int query);
Public Declare Function cs_support Lib "vbCapstone.dll" Alias "bs_support" (ByVal query As Long) As Long



'/*
' Initialize CS handle: this must be done before any usage of CS.
'
' @arch: architecture type (CS_ARCH_*)
' @mode: hardware mode. This is combined of CS_MODE_*
' @handle: pointer to handle, which will be updated at return time
'
' @return CS_ERR_OK on success, or other value on failure (refer to cs_err enum
' for detailed error).
'*/
'CAPSTONE_EXPORT
'cs_err cs_open(cs_arch arch, cs_mode mode, csh *handle);
Public Declare Function cs_open Lib "vbCapstone.dll" Alias "bs_open" (ByVal arch As cs_arch, ByVal mode As cs_mode, ByRef hEngine As Long) As cs_err


'/*
' Close CS handle: MUST do to release the handle when it is not used anymore.
' NOTE: this must be only called when there is no longer usage of Capstone,
' not even access to cs_insn array. The reason is the this API releases some
' cached memory, thus access to any Capstone API after cs_close() might crash
' your application.
'
' In fact,this API invalidate @handle by ZERO out its value (i.e *handle = 0).
'
' @handle: pointer to a handle returned by cs_open()
'
' @return CS_ERR_OK on success, or other value on failure (refer to cs_err enum
' for detailed error).
'*/
'CAPSTONE_EXPORT
'cs_err cs_close(csh *handle);
Public Declare Function cs_close Lib "vbCapstone.dll" Alias "bs_close" (ByRef hEngine As Long) As cs_err



'/*
' Set option for disassembling engine at runtime
'
' @handle: handle returned by cs_open()
' @type: type of option to be set
' @value: option value corresponding with @type
'
' @return: CS_ERR_OK on success, or other value on failure.
' Refer to cs_err enum for detailed error.
'
' NOTE: in the case of CS_OPT_MEM, handle's value can be anything,
' so that cs_option(handle, CS_OPT_MEM, value) can (i.e must) be called
' even before cs_open()
'*/
'CAPSTONE_EXPORT
'cs_err cs_option(csh handle, cs_opt_type type, size_t value);
Public Declare Function cs_option Lib "vbCapstone.dll" Alias "bs_option" (ByVal hEngine As Long, ByVal typ As cs_opt_type, ByVal size As Long) As cs_err



'/*
' Report the last error number when some API function fail.
' Like glibc's errno, cs_errno might not retain its old value once accessed.
'
' @handle: handle returned by cs_open()
'
' @return: error code of cs_err enum type (CS_ERR_*, see above)
'*/
'CAPSTONE_EXPORT
'cs_err cs_errno(csh handle);
Public Declare Function cs_errno Lib "vbCapstone.dll" Alias "bs_errno" (ByVal hEngine As Long) As cs_err

'
'/*
' Return a string describing given error code.
'
' @code: error code (see CS_ERR_* above)
'
' @return: returns a pointer to a string that describes the error code
'    passed in the argument @code
'*/
'CAPSTONE_EXPORT
'const char *cs_strerror(cs_err code);
Public Declare Function cs_strerror Lib "vbCapstone.dll" Alias "bs_strerror" (ByVal errCode As cs_err) As Long


'/*
' Disassemble binary code, given the code buffer, size, address and number
' of instructions to be decoded.
' This API dynamically allocate memory to contain disassembled instruction.
' Resulting instructions will be put into @*insn
'
' NOTE 1: this API will automatically determine memory needed to contain
' output disassembled instructions in @insn.
'
' NOTE 2: caller must free the allocated memory itself to avoid memory leaking.
'
' NOTE 3: for system with scarce memory to be dynamically allocated such as
' OS kernel or firmware, the API cs_disasm_iter() might be a better choice than
' cs_disasm(). The reason is that with cs_disasm(), based on limited available
' memory, we have to calculate in advance how many instructions to be disassembled,
' which complicates things. This is especially troublesome for the case @count=0,
' when cs_disasm() runs uncontrollably (until either end of input buffer, or
' when it encounters an invalid instruction).
'
' @handle: handle returned by cs_open()
' @code: buffer containing raw binary code to be disassembled.
' @code_size: size of the above code buffer.
' @address: address of the first instruction in given raw code buffer.
' @insn: array of instructions filled in by this API.
'       NOTE: @insn will be allocated by this function, and should be freed
'       with cs_free() API.
' @count: number of instructions to be disassembled, or 0 to get all of them
'
' @return: the number of successfully disassembled instructions,
' or 0 if this function failed to disassemble the given code
'
' On failure, call cs_errno() for error code.
'*/
'CAPSTONE_EXPORT
'size_t cs_disasm(
'        csh handle,
'        const uint8_t *code,
'        size_t code_size,
'        uint64_t address,
'        size_t count,
'        cs_insn **insn
');
Public Declare Function cs_disasm Lib "vbCapstone.dll" Alias "bs_disasm" ( _
    ByVal hEngine As Long, _
    ByRef code As Byte, _
    ByVal size As Long, _
    ByVal address As Currency, _
    ByVal count As Long, _
    ByRef instAryPtr As Long _
) As Long

'this proto also lets use byte() to get a dump easily..
Public Declare Sub getInstruction Lib "vbCapstone.dll" (ByVal hInstrAry As Long, ByVal index As Long, ByVal insPtr As Long, ByVal size As Long)


'/*
'  Deprecated function - to be retired in the next version!
'  Use cs_disasm() instead of cs_disasm_ex()
'*/
'CAPSTONE_EXPORT
'CAPSTONE_DEPRECATED
'size_t cs_disasm_ex(csh handle,
'        const uint8_t *code, size_t code_size,
'        uint64_t address,
'        size_t count,
'        cs_insn **insn);



'/*
' Free memory allocated by cs_malloc() or cs_disasm() (argument @insn)
'
' @insn: pointer returned by @insn argument in cs_disasm() or cs_malloc()
' @count: number of cs_insn structures returned by cs_disasm(), or 1
'     to free memory allocated by cs_malloc().
'*/
'CAPSTONE_EXPORT
'void cs_free(cs_insn *insn, size_t count);
Public Declare Sub cs_free Lib "vbCapstone.dll" Alias "bs_free" (ByVal instr As Long, ByVal count As Long)


'
'/*
' Allocate memory for 1 instruction to be used by cs_disasm_iter().
'
' @handle: handle returned by cs_open()
'
' NOTE: when no longer in use, you can reclaim the memory allocated for
' this instruction with cs_free(insn, 1)
'*/
'CAPSTONE_EXPORT
'cs_insn *cs_malloc(csh handle);
Public Declare Function cs_malloc Lib "vbCapstone.dll" Alias "bs_malloc" (ByVal handle As Long) As Long



'/*
' Fast API to disassemble binary code, given the code buffer, size, address
' and number of instructions to be decoded.
' This API puts the resulting instruction into a given cache in @insn.
' See tests/test_iter.c for sample code demonstrating this API.
'
' NOTE 1: this API will update @code, @size & @address to point to the next
' instruction in the input buffer. Therefore, it is convenient to use
' cs_disasm_iter() inside a loop to quickly iterate all the instructions.
' While decoding one instruction at a time can also be achieved with
' cs_disasm(count=1), some benchmarks shown that cs_disasm_iter() can be 30%
' faster on random input.
'
' NOTE 2: the cache in @insn can be created with cs_malloc() API.
'
' NOTE 3: for system with scarce memory to be dynamically allocated such as
' OS kernel or firmware, this API is recommended over cs_disasm(), which
' allocates memory based on the number of instructions to be disassembled.
' The reason is that with cs_disasm(), based on limited available memory,
' we have to calculate in advance how many instructions to be disassembled,
' which complicates things. This is especially troublesome for the case
' @count=0, when cs_disasm() runs uncontrollably (until either end of input
' buffer, or when it encounters an invalid instruction).
'
' @handle: handle returned by cs_open()
' @code: buffer containing raw binary code to be disassembled
' @code_size: size of above code
' @address: address of the first insn in given raw code buffer
' @insn: pointer to instruction to be filled in by this API.
'
' @return: true if this API successfully decode 1 instruction,
' or false otherwise.
'
' On failure, call cs_errno() for error code.
'*/
'CAPSTONE_EXPORT
'bool cs_disasm_iter(csh handle, const uint8_t **code, size_t *size, uint64_t *address, cs_insn *insn);



'/*
' Return friendly name of register in a string.
' Find the instruction id from header file of corresponding architecture (arm.h for ARM,
' x86.h for X86, ...)
'
' WARN: when in 'diet' mode, this API is irrelevant because engine does not
' store register name.
'
' @handle: handle returned by cs_open()
' @reg_id: register id
'
' @return: string name of the register, or NULL if @reg_id is invalid.
'*/
'CAPSTONE_EXPORT
'const char *cs_reg_name(csh handle, unsigned int reg_id);
Public Declare Function cs_reg_name Lib "vbCapstone.dll" Alias "bs_reg_name" (ByVal handle As Long, ByVal regID As Long) As Long




'/*
' Return friendly name of an instruction in a string.
' Find the instruction id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
'
' WARN: when in 'diet' mode, this API is irrelevant because the engine does not
' store instruction name.
'
' @handle: handle returned by cs_open()
' @insn_id: instruction id
'
' @return: string name of the instruction, or NULL if @insn_id is invalid.
'*/
'CAPSTONE_EXPORT
'const char *cs_insn_name(csh handle, unsigned int insn_id);
Public Declare Function cs_insn_name Lib "vbCapstone.dll" Alias "bs_insn_name" (ByVal handle As Long, ByVal insn_id As Long) As Long




'/*
' Return friendly name of a group id (that an instruction can belong to)
' Find the group id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
'
' WARN: when in 'diet' mode, this API is irrelevant because the engine does not
' store group name.
'
' @handle: handle returned by cs_open()
' @group_id: group id
'
' @return: string name of the group, or NULL if @group_id is invalid.
'*/
'CAPSTONE_EXPORT
'const char *cs_group_name(csh handle, unsigned int group_id);
Public Declare Function cs_group_name Lib "vbCapstone.dll" Alias "bs_group_name" (ByVal handle As Long, ByVal group_id As Long) As Long



'/*
' Check if a disassembled instruction belong to a particular group.
' Find the group id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
' Internally, this simply verifies if @group_id matches any member of insn->groups array.
'
' NOTE: this API is only valid when detail option is ON (which is OFF by default).
'
' WARN: when in 'diet' mode, this API is irrelevant because the engine does not
' update @groups array.
'
' @handle: handle returned by cs_open()
' @insn: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
' @group_id: group that you want to check if this instruction belong to.
'
' @return: true if this instruction indeed belongs to the given group, or false otherwise.
'*/
'CAPSTONE_EXPORT
'bool cs_insn_group(csh handle, const cs_insn *insn, unsigned int group_id);
Public Declare Function cs_insn_group Lib "vbCapstone.dll" Alias "bs_insn_group" (ByVal handle As Long, ByVal instruction As Long, ByVal group_id As Long) As Long



'/*
' Check if a disassembled instruction IMPLICITLY used a particular register.
' Find the register id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
' Internally, this simply verifies if @reg_id matches any member of insn->regs_read array.
'
' NOTE: this API is only valid when detail option is ON (which is OFF by default)
'
' WARN: when in 'diet' mode, this API is irrelevant because the engine does not
' update @regs_read array.
'
' @insn: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
' @reg_id: register that you want to check if this instruction used it.
'
' @return: true if this instruction indeed implicitly used the given register, or false otherwise.
'*/
'CAPSTONE_EXPORT
'bool cs_reg_read(csh handle, const cs_insn *insn, unsigned int reg_id);
Public Declare Function cs_reg_read Lib "vbCapstone.dll" Alias "bs_reg_read" (ByVal handle As Long, ByVal instruction As Long, ByVal reg_id As Long) As Long



'/*
' Check if a disassembled instruction IMPLICITLY modified a particular register.
' Find the register id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
' Internally, this simply verifies if @reg_id matches any member of insn->regs_write array.
'
' NOTE: this API is only valid when detail option is ON (which is OFF by default)
'
' WARN: when in 'diet' mode, this API is irrelevant because the engine does not
' update @regs_write array.
'
' @insn: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
' @reg_id: register that you want to check if this instruction modified it.
'
' @return: true if this instruction indeed implicitly modified the given register, or false otherwise.
'*/
'CAPSTONE_EXPORT
'bool cs_reg_write(csh handle, const cs_insn *insn, unsigned int reg_id);
Public Declare Function cs_reg_write Lib "vbCapstone.dll" Alias "bs_reg_write" (ByVal handle As Long, ByVal instruction As Long, ByVal reg_id As Long) As Long



'/*
' Count the number of operands of a given type.
' Find the operand type in header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
'
' NOTE: this API is only valid when detail option is ON (which is OFF by default)
'
' @handle: handle returned by cs_open()
' @insn: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
' @op_type: Operand type to be found.
'
' @return: number of operands of given type @op_type in instruction @insn,
' or -1 on failure.
'*/
'CAPSTONE_EXPORT
'int cs_op_count(csh handle, const cs_insn *insn, unsigned int op_type);
Public Declare Function cs_op_count Lib "vbCapstone.dll" Alias "bs_op_count" (ByVal handle As Long, ByVal instruction As Long, ByVal op_type As Long) As Long



'/*
' Retrieve the position of operand of given type in <arch>.operands[] array.
' Later, the operand can be accessed using the returned position.
' Find the operand type in header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
'
' NOTE: this API is only valid when detail option is ON (which is OFF by default)
'
' @handle: handle returned by cs_open()
' @insn: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
' @op_type: Operand type to be found.
' @position: position of the operand to be found. This must be in the range
'            [1, cs_op_count(handle, insn, op_type)]
'
' @return: index of operand of given type @op_type in <arch>.operands[] array
' in instruction @insn, or -1 on failure.
'*/
'CAPSTONE_EXPORT
'int cs_op_index(csh handle, const cs_insn *insn, unsigned int op_type, unsigned int position);
Public Declare Function cs_op_index Lib "vbCapstone.dll" Alias "bs_op_index" (ByVal handle As Long, ByVal instruction As Long, ByVal op_type As Long, ByVal position As Long) As Long



Private Declare Function lstrcpy Lib "kernel32" Alias "lstrcpyA" (ByVal lpString1 As String, ByVal lpString2 As String) As Long
Private Declare Function lstrlen Lib "kernel32" Alias "lstrlenA" (ByVal lpString As Long) As Long

Function cstr2vb(lpStr As Long) As String

    Dim length As Long
    Dim buf() As Byte

    If lpStr = 0 Then Exit Function

    length = lstrlen(lpStr)
    If length < 1 Then Exit Function
    
    ReDim buf(1 To length)
    CopyMemory buf(1), ByVal lpStr, length

    cstr2vb = StrConv(buf, vbUnicode, &H409)

End Function

Function err2str(e As cs_err) As String
    Dim lpStr As Long
    lpStr = cs_strerror(e)
    err2str = cstr2vb(lpStr)
End Function

Function regName(hEngine As Long, regID As Long) As String
    Dim lpStr As Long
    lpStr = cs_reg_name(hEngine, regID)
    regName = cstr2vb(lpStr)
    If Len(regName) = 0 Or DEBUG_DUMP Then regName = regName & " (" & Hex(regID) & ")"
End Function

Function insnName(hEngine As Long, insnID As Long) As String
    Dim lpStr As Long
    lpStr = cs_insn_name(hEngine, insnID)
    insnName = cstr2vb(lpStr)
    If Len(insnName) = 0 Or DEBUG_DUMP Then insnName = insnName & " (" & Hex(insnID) & ")"
End Function

Function groupName(hEngine As Long, groupID As Long) As String
    Dim lpStr As Long
    lpStr = cs_group_name(hEngine, groupID)
    groupName = cstr2vb(lpStr)
    If Len(groupName) = 0 Or DEBUG_DUMP Then groupName = groupName & " (" & Hex(groupID) & ")"
End Function
