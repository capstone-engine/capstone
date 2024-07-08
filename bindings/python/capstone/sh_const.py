from . import CS_OP_INVALID, CS_OP_REG, CS_OP_IMM, CS_OP_FP, CS_OP_PRED, CS_OP_SPECIAL, CS_OP_MEM, CS_OP_MEM_REG, CS_OP_MEM_IMM, UINT16_MAX
# For Capstone Engine. AUTO-GENERATED FILE, DO NOT EDIT [sh_const.py]

SH_REG_INVALID = 0
SH_REG_R0 = 1
SH_REG_R1 = 2
SH_REG_R2 = 3
SH_REG_R3 = 4
SH_REG_R4 = 5
SH_REG_R5 = 6
SH_REG_R6 = 7
SH_REG_R7 = 8
SH_REG_R8 = 9
SH_REG_R9 = 10
SH_REG_R10 = 11
SH_REG_R11 = 12
SH_REG_R12 = 13
SH_REG_R13 = 14
SH_REG_R14 = 15
SH_REG_R15 = 16
SH_REG_R0_BANK = 17
SH_REG_R1_BANK = 18
SH_REG_R2_BANK = 19
SH_REG_R3_BANK = 20
SH_REG_R4_BANK = 21
SH_REG_R5_BANK = 22
SH_REG_R6_BANK = 23
SH_REG_R7_BANK = 24
SH_REG_FR0 = 25
SH_REG_FR1 = 26
SH_REG_FR2 = 27
SH_REG_FR3 = 28
SH_REG_FR4 = 29
SH_REG_FR5 = 30
SH_REG_FR6 = 31
SH_REG_FR7 = 32
SH_REG_FR8 = 33
SH_REG_FR9 = 34
SH_REG_FR10 = 35
SH_REG_FR11 = 36
SH_REG_FR12 = 37
SH_REG_FR13 = 38
SH_REG_FR14 = 39
SH_REG_FR15 = 40
SH_REG_DR0 = 41
SH_REG_DR2 = 42
SH_REG_DR4 = 43
SH_REG_DR6 = 44
SH_REG_DR8 = 45
SH_REG_DR10 = 46
SH_REG_DR12 = 47
SH_REG_DR14 = 48
SH_REG_XD0 = 49
SH_REG_XD2 = 50
SH_REG_XD4 = 51
SH_REG_XD6 = 52
SH_REG_XD8 = 53
SH_REG_XD10 = 54
SH_REG_XD12 = 55
SH_REG_XD14 = 56
SH_REG_XF0 = 57
SH_REG_XF1 = 58
SH_REG_XF2 = 59
SH_REG_XF3 = 60
SH_REG_XF4 = 61
SH_REG_XF5 = 62
SH_REG_XF6 = 63
SH_REG_XF7 = 64
SH_REG_XF8 = 65
SH_REG_XF9 = 66
SH_REG_XF10 = 67
SH_REG_XF11 = 68
SH_REG_XF12 = 69
SH_REG_XF13 = 70
SH_REG_XF14 = 71
SH_REG_XF15 = 72
SH_REG_FV0 = 73
SH_REG_FV4 = 74
SH_REG_FV8 = 75
SH_REG_FV12 = 76
SH_REG_XMATRX = 77
SH_REG_PC = 78
SH_REG_PR = 79
SH_REG_MACH = 80
SH_REG_MACL = 81
SH_REG_SR = 82
SH_REG_GBR = 83
SH_REG_SSR = 84
SH_REG_SPC = 85
SH_REG_SGR = 86
SH_REG_DBR = 87
SH_REG_VBR = 88
SH_REG_TBR = 89
SH_REG_RS = 90
SH_REG_RE = 91
SH_REG_MOD = 92
SH_REG_FPUL = 93
SH_REG_FPSCR = 94
SH_REG_DSP_X0 = 95
SH_REG_DSP_X1 = 96
SH_REG_DSP_Y0 = 97
SH_REG_DSP_Y1 = 98
SH_REG_DSP_A0 = 99
SH_REG_DSP_A1 = 100
SH_REG_DSP_A0G = 101
SH_REG_DSP_A1G = 102
SH_REG_DSP_M0 = 103
SH_REG_DSP_M1 = 104
SH_REG_DSP_DSR = 105
SH_REG_DSP_RSV0 = 106
SH_REG_DSP_RSV1 = 107
SH_REG_DSP_RSV2 = 108
SH_REG_DSP_RSV3 = 109
SH_REG_DSP_RSV4 = 110
SH_REG_DSP_RSV5 = 111
SH_REG_DSP_RSV6 = 112
SH_REG_DSP_RSV7 = 113
SH_REG_DSP_RSV8 = 114
SH_REG_DSP_RSV9 = 115
SH_REG_DSP_RSVA = 116
SH_REG_DSP_RSVB = 117
SH_REG_DSP_RSVC = 118
SH_REG_DSP_RSVD = 119
SH_REG_DSP_RSVE = 120
SH_REG_DSP_RSVF = 121
SH_REG_ENDING = 122

SH_OP_INVALID = 0
SH_OP_REG = 1
SH_OP_IMM = 2
SH_OP_MEM = 3

SH_OP_MEM_INVALID = 0
SH_OP_MEM_REG_IND = 1
SH_OP_MEM_REG_POST = 2
SH_OP_MEM_REG_PRE = 3
SH_OP_MEM_REG_DISP = 4
SH_OP_MEM_REG_R0 = 5
SH_OP_MEM_GBR_DISP = 6
SH_OP_MEM_GBR_R0 = 7
SH_OP_MEM_PCR = 8
SH_OP_MEM_TBR_DISP = 9
SH_INS_DSP_INVALID = 10
SH_INS_DSP_DOUBLE = 11
SH_INS_DSP_SINGLE = 12
SH_INS_DSP_PARALLEL = 13
SH_INS_DSP_NOP = 1
SH_INS_DSP_MOV = 2
SH_INS_DSP_PSHL = 3
SH_INS_DSP_PSHA = 4
SH_INS_DSP_PMULS = 5
SH_INS_DSP_PCLR_PMULS = 6
SH_INS_DSP_PSUB_PMULS = 7
SH_INS_DSP_PADD_PMULS = 8
SH_INS_DSP_PSUBC = 9
SH_INS_DSP_PADDC = 10
SH_INS_DSP_PCMP = 11
SH_INS_DSP_PABS = 12
SH_INS_DSP_PRND = 13
SH_INS_DSP_PSUB = 14
SH_INS_DSP_PSUBr = 15
SH_INS_DSP_PADD = 16
SH_INS_DSP_PAND = 17
SH_INS_DSP_PXOR = 18
SH_INS_DSP_POR = 19
SH_INS_DSP_PDEC = 20
SH_INS_DSP_PINC = 21
SH_INS_DSP_PCLR = 22
SH_INS_DSP_PDMSB = 23
SH_INS_DSP_PNEG = 24
SH_INS_DSP_PCOPY = 25
SH_INS_DSP_PSTS = 26
SH_INS_DSP_PLDS = 27
SH_INS_DSP_PSWAP = 28
SH_INS_DSP_PWAD = 29
SH_INS_DSP_PWSB = 30
SH_OP_DSP_INVALID = 31
SH_OP_DSP_REG_PRE = 32
SH_OP_DSP_REG_IND = 33
SH_OP_DSP_REG_POST = 34
SH_OP_DSP_REG_INDEX = 35
SH_OP_DSP_REG = 36
SH_OP_DSP_IMM = 37
SH_DSP_CC_INVALID = 38
SH_DSP_CC_NONE = 39
SH_DSP_CC_DCT = 40
SH_DSP_CC_DCF = 41
SH_INS_INVALID = 42
SH_INS_ADD_r = 43
SH_INS_ADD = 44
SH_INS_ADDC = 45
SH_INS_ADDV = 46
SH_INS_AND = 47
SH_INS_BAND = 48
SH_INS_BANDNOT = 49
SH_INS_BCLR = 50
SH_INS_BF = 51
SH_INS_BF_S = 52
SH_INS_BLD = 53
SH_INS_BLDNOT = 54
SH_INS_BOR = 55
SH_INS_BORNOT = 56
SH_INS_BRA = 57
SH_INS_BRAF = 58
SH_INS_BSET = 59
SH_INS_BSR = 60
SH_INS_BSRF = 61
SH_INS_BST = 62
SH_INS_BT = 63
SH_INS_BT_S = 64
SH_INS_BXOR = 65
SH_INS_CLIPS = 66
SH_INS_CLIPU = 67
SH_INS_CLRDMXY = 68
SH_INS_CLRMAC = 69
SH_INS_CLRS = 70
SH_INS_CLRT = 71
SH_INS_CMP_EQ = 72
SH_INS_CMP_GE = 73
SH_INS_CMP_GT = 74
SH_INS_CMP_HI = 75
SH_INS_CMP_HS = 76
SH_INS_CMP_PL = 77
SH_INS_CMP_PZ = 78
SH_INS_CMP_STR = 79
SH_INS_DIV0S = 80
SH_INS_DIV0U = 81
SH_INS_DIV1 = 82
SH_INS_DIVS = 83
SH_INS_DIVU = 84
SH_INS_DMULS_L = 85
SH_INS_DMULU_L = 86
SH_INS_DT = 87
SH_INS_EXTS_B = 88
SH_INS_EXTS_W = 89
SH_INS_EXTU_B = 90
SH_INS_EXTU_W = 91
SH_INS_FABS = 92
SH_INS_FADD = 93
SH_INS_FCMP_EQ = 94
SH_INS_FCMP_GT = 95
SH_INS_FCNVDS = 96
SH_INS_FCNVSD = 97
SH_INS_FDIV = 98
SH_INS_FIPR = 99
SH_INS_FLDI0 = 100
SH_INS_FLDI1 = 101
SH_INS_FLDS = 102
SH_INS_FLOAT = 103
SH_INS_FMAC = 104
SH_INS_FMOV = 105
SH_INS_FMUL = 106
SH_INS_FNEG = 107
SH_INS_FPCHG = 108
SH_INS_FRCHG = 109
SH_INS_FSCA = 110
SH_INS_FSCHG = 111
SH_INS_FSQRT = 112
SH_INS_FSRRA = 113
SH_INS_FSTS = 114
SH_INS_FSUB = 115
SH_INS_FTRC = 116
SH_INS_FTRV = 117
SH_INS_ICBI = 118
SH_INS_JMP = 119
SH_INS_JSR = 120
SH_INS_JSR_N = 121
SH_INS_LDBANK = 122
SH_INS_LDC = 123
SH_INS_LDRC = 124
SH_INS_LDRE = 125
SH_INS_LDRS = 126
SH_INS_LDS = 127
SH_INS_LDTLB = 128
SH_INS_MAC_L = 129
SH_INS_MAC_W = 130
SH_INS_MOV = 131
SH_INS_MOVA = 132
SH_INS_MOVCA = 133
SH_INS_MOVCO = 134
SH_INS_MOVI20 = 135
SH_INS_MOVI20S = 136
SH_INS_MOVLI = 137
SH_INS_MOVML = 138
SH_INS_MOVMU = 139
SH_INS_MOVRT = 140
SH_INS_MOVT = 141
SH_INS_MOVU = 142
SH_INS_MOVUA = 143
SH_INS_MUL_L = 144
SH_INS_MULR = 145
SH_INS_MULS_W = 146
SH_INS_MULU_W = 147
SH_INS_NEG = 148
SH_INS_NEGC = 149
SH_INS_NOP = 150
SH_INS_NOT = 151
SH_INS_NOTT = 152
SH_INS_OCBI = 153
SH_INS_OCBP = 154
SH_INS_OCBWB = 155
SH_INS_OR = 156
SH_INS_PREF = 157
SH_INS_PREFI = 158
SH_INS_RESBANK = 159
SH_INS_ROTCL = 160
SH_INS_ROTCR = 161
SH_INS_ROTL = 162
SH_INS_ROTR = 163
SH_INS_RTE = 164
SH_INS_RTS = 165
SH_INS_RTS_N = 166
SH_INS_RTV_N = 167
SH_INS_SETDMX = 168
SH_INS_SETDMY = 169
SH_INS_SETRC = 170
SH_INS_SETS = 171
SH_INS_SETT = 172
SH_INS_SHAD = 173
SH_INS_SHAL = 174
SH_INS_SHAR = 175
SH_INS_SHLD = 176
SH_INS_SHLL = 177
SH_INS_SHLL16 = 178
SH_INS_SHLL2 = 179
SH_INS_SHLL8 = 180
SH_INS_SHLR = 181
SH_INS_SHLR16 = 182
SH_INS_SHLR2 = 183
SH_INS_SHLR8 = 184
SH_INS_SLEEP = 185
SH_INS_STBANK = 186
SH_INS_STC = 187
SH_INS_STS = 188
SH_INS_SUB = 189
SH_INS_SUBC = 190
SH_INS_SUBV = 191
SH_INS_SWAP_B = 192
SH_INS_SWAP_W = 193
SH_INS_SYNCO = 194
SH_INS_TAS = 195
SH_INS_TRAPA = 196
SH_INS_TST = 197
SH_INS_XOR = 198
SH_INS_XTRCT = 199
SH_INS_DSP = 200
SH_INS_ENDING = 201

SH_GRP_INVALID = 0
SH_GRP_JUMP = 1
SH_GRP_CALL = 2
SH_GRP_INT = 3
SH_GRP_RET = 4
SH_GRP_IRET = 5
SH_GRP_PRIVILEGE = 6
SH_GRP_BRANCH_RELATIVE = 7
SH_GRP_SH1 = 8
SH_GRP_SH2 = 9
SH_GRP_SH2E = 10
SH_GRP_SH2DSP = 11
SH_GRP_SH2A = 12
SH_GRP_SH2AFPU = 13
SH_GRP_SH3 = 14
SH_GRP_SH3DSP = 15
SH_GRP_SH4 = 16
SH_GRP_SH4A = 17
SH_GRP_ENDING = 18
