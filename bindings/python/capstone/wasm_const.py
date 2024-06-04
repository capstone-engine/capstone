from . import CS_OP_INVALID, CS_OP_REG, CS_OP_IMM, CS_OP_FP, CS_OP_PRED, CS_OP_SPECIAL, CS_OP_MEM, CS_OP_MEM_REG, CS_OP_MEM_IMM, UINT16_MAX
# For Capstone Engine. AUTO-GENERATED FILE, DO NOT EDIT [wasm_const.py]

WASM_OP_INVALID = 0
WASM_OP_NONE = 1
WASM_OP_INT7 = 2
WASM_OP_VARUINT32 = 3
WASM_OP_VARUINT64 = 4
WASM_OP_UINT32 = 5
WASM_OP_UINT64 = 6
WASM_OP_IMM = 7
WASM_OP_BRTABLE = 8
WASM_INS_UNREACHABLE = 0x0
WASM_INS_NOP = 0x1
WASM_INS_BLOCK = 0x2
WASM_INS_LOOP = 0x3
WASM_INS_IF = 0x4
WASM_INS_ELSE = 0x5
WASM_INS_END = 0xb
WASM_INS_BR = 0xc
WASM_INS_BR_IF = 0xd
WASM_INS_BR_TABLE = 0xe
WASM_INS_RETURN = 0xf
WASM_INS_CALL = 0x10
WASM_INS_CALL_INDIRECT = 0x11
WASM_INS_DROP = 0x1a
WASM_INS_SELECT = 0x1b
WASM_INS_GET_LOCAL = 0x20
WASM_INS_SET_LOCAL = 0x21
WASM_INS_TEE_LOCAL = 0x22
WASM_INS_GET_GLOBAL = 0x23
WASM_INS_SET_GLOBAL = 0x24
WASM_INS_I32_LOAD = 0x28
WASM_INS_I64_LOAD = 0x29
WASM_INS_F32_LOAD = 0x2a
WASM_INS_F64_LOAD = 0x2b
WASM_INS_I32_LOAD8_S = 0x2c
WASM_INS_I32_LOAD8_U = 0x2d
WASM_INS_I32_LOAD16_S = 0x2e
WASM_INS_I32_LOAD16_U = 0x2f
WASM_INS_I64_LOAD8_S = 0x30
WASM_INS_I64_LOAD8_U = 0x31
WASM_INS_I64_LOAD16_S = 0x32
WASM_INS_I64_LOAD16_U = 0x33
WASM_INS_I64_LOAD32_S = 0x34
WASM_INS_I64_LOAD32_U = 0x35
WASM_INS_I32_STORE = 0x36
WASM_INS_I64_STORE = 0x37
WASM_INS_F32_STORE = 0x38
WASM_INS_F64_STORE = 0x39
WASM_INS_I32_STORE8 = 0x3a
WASM_INS_I32_STORE16 = 0x3b
WASM_INS_I64_STORE8 = 0x3c
WASM_INS_I64_STORE16 = 0x3d
WASM_INS_I64_STORE32 = 0x3e
WASM_INS_CURRENT_MEMORY = 0x3f
WASM_INS_GROW_MEMORY = 0x40
WASM_INS_I32_CONST = 0x41
WASM_INS_I64_CONST = 0x42
WASM_INS_F32_CONST = 0x43
WASM_INS_F64_CONST = 0x44
WASM_INS_I32_EQZ = 0x45
WASM_INS_I32_EQ = 0x46
WASM_INS_I32_NE = 0x47
WASM_INS_I32_LT_S = 0x48
WASM_INS_I32_LT_U = 0x49
WASM_INS_I32_GT_S = 0x4a
WASM_INS_I32_GT_U = 0x4b
WASM_INS_I32_LE_S = 0x4c
WASM_INS_I32_LE_U = 0x4d
WASM_INS_I32_GE_S = 0x4e
WASM_INS_I32_GE_U = 0x4f
WASM_INS_I64_EQZ = 0x50
WASM_INS_I64_EQ = 0x51
WASM_INS_I64_NE = 0x52
WASM_INS_I64_LT_S = 0x53
WASM_INS_I64_LT_U = 0x54
WASM_INS_I64_GT_U = 0x56
WASM_INS_I64_LE_S = 0x57
WASM_INS_I64_LE_U = 0x58
WASM_INS_I64_GE_S = 0x59
WASM_INS_I64_GE_U = 0x5a
WASM_INS_F32_EQ = 0x5b
WASM_INS_F32_NE = 0x5c
WASM_INS_F32_LT = 0x5d
WASM_INS_F32_GT = 0x5e
WASM_INS_F32_LE = 0x5f
WASM_INS_F32_GE = 0x60
WASM_INS_F64_EQ = 0x61
WASM_INS_F64_NE = 0x62
WASM_INS_F64_LT = 0x63
WASM_INS_F64_GT = 0x64
WASM_INS_F64_LE = 0x65
WASM_INS_F64_GE = 0x66
WASM_INS_I32_CLZ = 0x67
WASM_INS_I32_CTZ = 0x68
WASM_INS_I32_POPCNT = 0x69
WASM_INS_I32_ADD = 0x6a
WASM_INS_I32_SUB = 0x6b
WASM_INS_I32_MUL = 0x6c
WASM_INS_I32_DIV_S = 0x6d
WASM_INS_I32_DIV_U = 0x6e
WASM_INS_I32_REM_S = 0x6f
WASM_INS_I32_REM_U = 0x70
WASM_INS_I32_AND = 0x71
WASM_INS_I32_OR = 0x72
WASM_INS_I32_XOR = 0x73
WASM_INS_I32_SHL = 0x74
WASM_INS_I32_SHR_S = 0x75
WASM_INS_I32_SHR_U = 0x76
WASM_INS_I32_ROTL = 0x77
WASM_INS_I32_ROTR = 0x78
WASM_INS_I64_CLZ = 0x79
WASM_INS_I64_CTZ = 0x7a
WASM_INS_I64_POPCNT = 0x7b
WASM_INS_I64_ADD = 0x7c
WASM_INS_I64_SUB = 0x7d
WASM_INS_I64_MUL = 0x7e
WASM_INS_I64_DIV_S = 0x7f
WASM_INS_I64_DIV_U = 0x80
WASM_INS_I64_REM_S = 0x81
WASM_INS_I64_REM_U = 0x82
WASM_INS_I64_AND = 0x83
WASM_INS_I64_OR = 0x84
WASM_INS_I64_XOR = 0x85
WASM_INS_I64_SHL = 0x86
WASM_INS_I64_SHR_S = 0x87
WASM_INS_I64_SHR_U = 0x88
WASM_INS_I64_ROTL = 0x89
WASM_INS_I64_ROTR = 0x8a
WASM_INS_F32_ABS = 0x8b
WASM_INS_F32_NEG = 0x8c
WASM_INS_F32_CEIL = 0x8d
WASM_INS_F32_FLOOR = 0x8e
WASM_INS_F32_TRUNC = 0x8f
WASM_INS_F32_NEAREST = 0x90
WASM_INS_F32_SQRT = 0x91
WASM_INS_F32_ADD = 0x92
WASM_INS_F32_SUB = 0x93
WASM_INS_F32_MUL = 0x94
WASM_INS_F32_DIV = 0x95
WASM_INS_F32_MIN = 0x96
WASM_INS_F32_MAX = 0x97
WASM_INS_F32_COPYSIGN = 0x98
WASM_INS_F64_ABS = 0x99
WASM_INS_F64_NEG = 0x9a
WASM_INS_F64_CEIL = 0x9b
WASM_INS_F64_FLOOR = 0x9c
WASM_INS_F64_TRUNC = 0x9d
WASM_INS_F64_NEAREST = 0x9e
WASM_INS_F64_SQRT = 0x9f
WASM_INS_F64_ADD = 0xa0
WASM_INS_F64_SUB = 0xa1
WASM_INS_F64_MUL = 0xa2
WASM_INS_F64_DIV = 0xa3
WASM_INS_F64_MIN = 0xa4
WASM_INS_F64_MAX = 0xa5
WASM_INS_F64_COPYSIGN = 0xa6
WASM_INS_I32_WARP_I64 = 0xa7
WASM_INS_I32_TRUNC_U_F32 = 0xa9
WASM_INS_I32_TRUNC_S_F64 = 0xaa
WASM_INS_I32_TRUNC_U_F64 = 0xab
WASM_INS_I64_EXTEND_S_I32 = 0xac
WASM_INS_I64_EXTEND_U_I32 = 0xad
WASM_INS_I64_TRUNC_S_F32 = 0xae
WASM_INS_I64_TRUNC_U_F32 = 0xaf
WASM_INS_I64_TRUNC_S_F64 = 0xb0
WASM_INS_I64_TRUNC_U_F64 = 0xb1
WASM_INS_F32_CONVERT_S_I32 = 0xb2
WASM_INS_F32_CONVERT_U_I32 = 0xb3
WASM_INS_F32_CONVERT_S_I64 = 0xb4
WASM_INS_F32_CONVERT_U_I64 = 0xb5
WASM_INS_F32_DEMOTE_F64 = 0xb6
WASM_INS_F64_CONVERT_S_I32 = 0xb7
WASM_INS_F64_CONVERT_U_I32 = 0xb8
WASM_INS_F64_CONVERT_S_I64 = 0xb9
WASM_INS_F64_CONVERT_U_I64 = 0xba
WASM_INS_F64_PROMOTE_F32 = 0xbb
WASM_INS_I32_REINTERPRET_F32 = 0xbc
WASM_INS_I64_REINTERPRET_F64 = 0xbd
WASM_INS_F32_REINTERPRET_I32 = 0xbe
WASM_INS_F64_REINTERPRET_I64 = 0xbf
WASM_INS_INVALID = 512
WASM_INS_ENDING = 513

WASM_GRP_INVALID = 0
WASM_GRP_NUMBERIC = 8
WASM_GRP_PARAMETRIC = 9
WASM_GRP_VARIABLE = 10
WASM_GRP_MEMORY = 11
WASM_GRP_CONTROL = 12
WASM_GRP_ENDING = 13
