#ifndef __Riscv_insn_mapping_gen_inc__
#define __Riscv_insn_mapping_gen_inc__
#include <stdint.h>

#include <stddef.h>

#include "../include/capstone/riscv_insn.gen.inc"
#include <string.h>

static const uint16_t to_insn[294][21] = {
    [RISCV_REV8] = {RISCV_REV8},
    [RISCV_WXTYPE] = {RISCV_WX_VSUBU, RISCV_WX_VSUB, RISCV_WX_VADDU,
                      RISCV_WX_VADD},
    [RISCV_C_SRLI_HINT] = {RISCV_C_SRLI_HINT},
    [RISCV_AES64DS] = {RISCV_AES64DS},
    [RISCV_VMSBF_M] = {RISCV_VMSBF_M},
    [RISCV_RTYPE] = {RISCV_XOR, RISCV_SUB, RISCV_SRL, RISCV_SRA, RISCV_SLTU,
                     RISCV_SLT, RISCV_SLL, RISCV_OR, RISCV_AND, RISCV_ADD},
    [RISCV_VFMERGE] = {RISCV_VFMERGE},
    [RISCV_RIVVTYPE] = {RISCV_IVV_VWREDSUMU, RISCV_IVV_VWREDSUM},
    [RISCV_C_ZEXT_W] = {RISCV_C_ZEXT_W},
    [RISCV_SFENCE_INVAL_IR] = {RISCV_SFENCE_INVAL_IR},
    [RISCV_XPERM4] = {RISCV_XPERM4},
    [RISCV_C_AND] = {RISCV_C_AND},
    [RISCV_AES32DSI] = {RISCV_AES32DSI},
    [RISCV_RORI] = {RISCV_RORI},
    [RISCV_JALR] = {RISCV_JALR},
    [RISCV_VMSIF_M] = {RISCV_VMSIF_M},
    [RISCV_VLSSEGTYPE] = {RISCV_VLSSEGTYPE},
    [RISCV_SHA512SIG1H] = {RISCV_SHA512SIG1H},
    [RISCV_FLTQ_S] = {RISCV_FLTQ_S},
    [RISCV_VXSG] = {RISCV_VX_VSLIDEUP, RISCV_VX_VSLIDEDOWN, RISCV_VX_VRGATHER},
    [RISCV_VXCMPTYPE] = {RISCV_VXCMP_VMSNE, RISCV_VXCMP_VMSLTU,
                         RISCV_VXCMP_VMSLT, RISCV_VXCMP_VMSLEU,
                         RISCV_VXCMP_VMSLE, RISCV_VXCMP_VMSGTU,
                         RISCV_VXCMP_VMSGT, RISCV_VXCMP_VMSEQ},
    [RISCV_C_LHU] = {RISCV_C_LHU},
    [RISCV_JAL] = {RISCV_JAL},
    [RISCV_ECALL] = {RISCV_ECALL},
    [RISCV_C_FSWSP] = {RISCV_C_FSWSP},
    [RISCV_VMVXS] = {RISCV_VMVXS},
    [RISCV_C_FLD] = {RISCV_C_FLD},
    [RISCV_SHIFTIWOP] = {RISCV_SRLIW, RISCV_SRAIW, RISCV_SLLIW},
    [RISCV_UNZIP] = {RISCV_UNZIP},
    [RISCV_ZICBOM] = {RISCV_CBO_INVAL, RISCV_CBO_FLUSH, RISCV_CBO_CLEAN},
    [RISCV_SHA512SIG1] = {RISCV_SHA512SIG1},
    [RISCV_NITYPE] = {RISCV_NI_VNCLIPU, RISCV_NI_VNCLIP},
    [RISCV_WFI] = {RISCV_WFI},
    [RISCV_VVMTYPE] = {RISCV_VVM_VMSBC, RISCV_VVM_VMADC},
    [RISCV_MVXMATYPE] = {RISCV_MVX_VNMSUB, RISCV_MVX_VNMSAC, RISCV_MVX_VMADD,
                         RISCV_MVX_VMACC},
    [RISCV_FLI_D] = {RISCV_FLI_D},
    [RISCV_C_ADDI_HINT] = {RISCV_C_ADDI_HINT},
    [RISCV_MASKTYPEX] = {RISCV_MASKTYPEX},
    [RISCV_FROUNDNX_D] = {RISCV_FROUNDNX_D},
    [RISCV_FROUND_D] = {RISCV_FROUND_D},
    [RISCV_VSETIVLI] = {RISCV_VSETIVLI},
    [RISCV_FMAXM_D] = {RISCV_FMAXM_D},
    [RISCV_C_SD] = {RISCV_C_SD},
    [RISCV_F_BIN_TYPE_H] = {RISCV_FSGNJ_H, RISCV_FSGNJX_H, RISCV_FSGNJN_H,
                            RISCV_FMIN_H, RISCV_FMAX_H, RISCV_FLT_H,
                            RISCV_FLE_H, RISCV_FEQ_H},
    [RISCV_ZBKB_PACKW] = {RISCV_ZBKB_PACKW},
    [RISCV_FVVMTYPE] = {RISCV_FVVM_VMFNE, RISCV_FVVM_VMFLT, RISCV_FVVM_VMFLE,
                        RISCV_FVVM_VMFEQ},
    [RISCV_VMVSX] = {RISCV_VMVSX},
    [RISCV_F_UN_RM_TYPE_D] = {RISCV_FSQRT_D, RISCV_FCVT_W_D, RISCV_FCVT_WU_D,
                              RISCV_FCVT_S_D, RISCV_FCVT_L_D, RISCV_FCVT_LU_D,
                              RISCV_FCVT_D_WU, RISCV_FCVT_D_W, RISCV_FCVT_D_S,
                              RISCV_FCVT_D_LU, RISCV_FCVT_D_L},
    [RISCV_ORCB] = {RISCV_ORCB},
    [RISCV_C_MUL] = {RISCV_C_MUL},
    [RISCV_SM3P1] = {RISCV_SM3P1},
    [RISCV_CLMUL] = {RISCV_CLMUL},
    [RISCV_FLEQ_S] = {RISCV_FLEQ_S},
    [RISCV_WVXTYPE] = {RISCV_WVX_VWMULU, RISCV_WVX_VWMULSU, RISCV_WVX_VWMUL,
                       RISCV_WVX_VSUBU, RISCV_WVX_VSUB, RISCV_WVX_VADDU,
                       RISCV_WVX_VADD},
    [RISCV_FMAXM_S] = {RISCV_FMAXM_S},
    [RISCV_C_ILLEGAL] = {RISCV_C_ILLEGAL},
    [RISCV_NXSTYPE] = {RISCV_NXS_VNSRL, RISCV_NXS_VNSRA},
    [RISCV_VSOXSEGTYPE] = {RISCV_VSOXSEGTYPE},
    [RISCV_C_NOP] = {RISCV_C_NOP},
    [RISCV_VXMCTYPE] = {RISCV_VXMC_VMSBC, RISCV_VXMC_VMADC},
    [RISCV_MMTYPE] = {RISCV_MM_VMXOR, RISCV_MM_VMXNOR, RISCV_MM_VMORN,
                      RISCV_MM_VMOR, RISCV_MM_VMNOR, RISCV_MM_VMNAND,
                      RISCV_MM_VMANDN, RISCV_MM_VMAND},
    [RISCV_F_UN_TYPE_S] = {RISCV_FMV_X_W, RISCV_FMV_W_X, RISCV_FCLASS_S},
    [RISCV_NVTYPE] = {RISCV_NV_VNCLIPU, RISCV_NV_VNCLIP},
    [RISCV_AES64KS2] = {RISCV_AES64KS2},
    [RISCV_AES32ESMI] = {RISCV_AES32ESMI},
    [RISCV_F_MADD_TYPE_H] = {RISCV_FNMSUB_H, RISCV_FNMADD_H, RISCV_FMSUB_H,
                             RISCV_FMADD_H},
    [RISCV_FROUNDNX_H] = {RISCV_FROUNDNX_H},
    [RISCV_MOVETYPEI] = {RISCV_MOVETYPEI},
    [RISCV_FLTQ_H] = {RISCV_FLTQ_H},
    [RISCV_C_LW] = {RISCV_C_LW},
    [RISCV_C_LWSP] = {RISCV_C_LWSP},
    [RISCV_C_ADDI16SP] = {RISCV_C_ADDI16SP},
    [RISCV_SHA512SIG0L] = {RISCV_SHA512SIG0L},
    [RISCV_SM3P0] = {RISCV_SM3P0},
    [RISCV_SM4ED] = {RISCV_SM4ED},
    [RISCV_FMINM_D] = {RISCV_FMINM_D},
    [RISCV_AES64IM] = {RISCV_AES64IM},
    [RISCV_VLRETYPE] = {RISCV_VLRETYPE},
    [RISCV_VFMVFS] = {RISCV_VFMVFS},
    [RISCV_CTZ] = {RISCV_CTZ},
    [RISCV_FMVH_X_D] = {RISCV_FMVH_X_D},
    [RISCV_SLLIUW] = {RISCV_SLLIUW},
    [RISCV_FMINM_S] = {RISCV_FMINM_S},
    [RISCV_ZBA_RTYPEUW] = {RISCV_SH3ADDUW, RISCV_SH2ADDUW, RISCV_SH1ADDUW,
                           RISCV_ADDUW},
    [RISCV_F_BIN_RM_TYPE_D] = {RISCV_FSUB_D, RISCV_FMUL_D, RISCV_FDIV_D,
                               RISCV_FADD_D},
    [RISCV_C_ADD_HINT] = {RISCV_C_ADD_HINT},
    [RISCV_F_MADD_TYPE_S] = {RISCV_FNMSUB_S, RISCV_FNMADD_S, RISCV_FMSUB_S,
                             RISCV_FMADD_S},
    [RISCV_ZIP] = {RISCV_ZIP},
    [RISCV_SHA512SUM1] = {RISCV_SHA512SUM1},
    [RISCV_C_LDSP] = {RISCV_C_LDSP},
    [RISCV_F_UN_RM_TYPE_H] = {RISCV_FSQRT_H, RISCV_FCVT_W_H, RISCV_FCVT_WU_H,
                              RISCV_FCVT_S_H, RISCV_FCVT_L_H, RISCV_FCVT_LU_H,
                              RISCV_FCVT_H_WU, RISCV_FCVT_H_W, RISCV_FCVT_H_S,
                              RISCV_FCVT_H_LU, RISCV_FCVT_H_L, RISCV_FCVT_H_D,
                              RISCV_FCVT_D_H},
    [RISCV_CPOP] = {RISCV_CPOP},
    [RISCV_FWFTYPE] = {RISCV_FWF_VSUB, RISCV_FWF_VADD},
    [RISCV_FWVTYPE] = {RISCV_FWV_VSUB, RISCV_FWV_VADD},
    [RISCV_ZBB_RTYPE] = {RISCV_XNOR, RISCV_ROR, RISCV_ROL, RISCV_ORN,
                         RISCV_MINU, RISCV_MIN, RISCV_MAXU, RISCV_MAX,
                         RISCV_ANDN},
    [RISCV_SM4KS] = {RISCV_SM4KS},
    [RISCV_RORIW] = {RISCV_RORIW},
    [RISCV_NXTYPE] = {RISCV_NX_VNCLIPU, RISCV_NX_VNCLIP},
    [RISCV_C_ADDIW] = {RISCV_C_ADDIW},
    [RISCV_C_LD] = {RISCV_C_LD},
    [RISCV_CTZW] = {RISCV_CTZW},
    [RISCV_XPERM8] = {RISCV_XPERM8},
    [RISCV_ITYPE] = {RISCV_XORI, RISCV_SLTIU, RISCV_SLTI, RISCV_ORI, RISCV_ANDI,
                     RISCV_ADDI},
    [RISCV_VID_V] = {RISCV_VID_V},
    [RISCV_FENCE] = {RISCV_FENCE},
    [RISCV_C_FLWSP] = {RISCV_C_FLWSP},
    [RISCV_STORE] = {RISCV_STORE},
    [RISCV_F_BIN_TYPE_S] = {RISCV_FSGNJ_S, RISCV_FSGNJX_S, RISCV_FSGNJN_S,
                            RISCV_FMIN_S, RISCV_FMAX_S, RISCV_FLT_S,
                            RISCV_FLE_S, RISCV_FEQ_S},
    [RISCV_VSSEGTYPE] = {RISCV_VSSEGTYPE},
    [RISCV_F_BIN_TYPE_D] = {RISCV_FSGNJ_D, RISCV_FSGNJX_D, RISCV_FSGNJN_D,
                            RISCV_FMIN_D, RISCV_FMAX_D, RISCV_FLT_D,
                            RISCV_FLE_D, RISCV_FEQ_D},
    [RISCV_ZICOND_RTYPE] = {RISCV_CZERO_NEZ, RISCV_CZERO_EQZ},
    [RISCV_C_FSDSP] = {RISCV_C_FSDSP},
    [RISCV_SRET] = {RISCV_SRET},
    [RISCV_STORE_FP] = {RISCV_STORE_FP},
    [RISCV_C_JALR] = {RISCV_C_JALR},
    [RISCV_FENCE_TSO] = {RISCV_FENCE_TSO},
    [RISCV_SHA512SIG0] = {RISCV_SHA512SIG0},
    [RISCV_FLI_S] = {RISCV_FLI_S},
    [RISCV_C_SB] = {RISCV_C_SB},
    [RISCV_ZBB_RTYPEW] = {RISCV_RORW, RISCV_ROLW},
    [RISCV_C_FLDSP] = {RISCV_C_FLDSP},
    [RISCV_C_MV_HINT] = {RISCV_C_MV_HINT},
    [RISCV_FCVTMOD_W_D] = {RISCV_FCVTMOD_W_D},
    [RISCV_RFVVTYPE] = {RISCV_FVV_VFWREDUSUM, RISCV_FVV_VFWREDOSUM,
                        RISCV_FVV_VFREDUSUM, RISCV_FVV_VFREDOSUM,
                        RISCV_FVV_VFREDMIN, RISCV_FVV_VFREDMAX},
    [RISCV_SHA512SIG0H] = {RISCV_SHA512SIG0H},
    [RISCV_AMO] = {RISCV_AMOXOR, RISCV_AMOSWAP, RISCV_AMOOR, RISCV_AMOMINU,
                   RISCV_AMOMIN, RISCV_AMOMAXU, RISCV_AMOMAX, RISCV_AMOAND,
                   RISCV_AMOADD},
    [RISCV_LOAD_FP] = {RISCV_LOAD_FP},
    [RISCV_VVMSTYPE] = {RISCV_VVMS_VSBC, RISCV_VVMS_VADC},
    [RISCV_FVVMATYPE] = {RISCV_FVV_VNMSUB, RISCV_FVV_VNMSAC, RISCV_FVV_VNMADD,
                         RISCV_FVV_VNMACC, RISCV_FVV_VMSUB, RISCV_FVV_VMSAC,
                         RISCV_FVV_VMADD, RISCV_FVV_VMACC},
    [RISCV_VEXT2TYPE] = {RISCV_VEXT2_ZVF2, RISCV_VEXT2_SVF2},
    [RISCV_EBREAK] = {RISCV_EBREAK},
    [RISCV_C_LUI] = {RISCV_C_LUI},
    [RISCV_F_MADD_TYPE_D] = {RISCV_FNMSUB_D, RISCV_FNMADD_D, RISCV_FMSUB_D,
                             RISCV_FMADD_D},
    [RISCV_C_ZEXT_H] = {RISCV_C_ZEXT_H},
    [RISCV_SHA512SIG1L] = {RISCV_SHA512SIG1L},
    [RISCV_VLSEGTYPE] = {RISCV_VLSEGTYPE},
    [RISCV_SHA256SIG0] = {RISCV_SHA256SIG0},
    [RISCV_F_UN_TYPE_H] = {RISCV_FMV_X_H, RISCV_FMV_H_X, RISCV_FCLASS_H},
    [RISCV_C_ADDI4SPN] = {RISCV_C_ADDI4SPN},
    [RISCV_VVTYPE] = {RISCV_VV_VXOR,         RISCV_VV_VSUB,     RISCV_VV_VSSUBU,
                      RISCV_VV_VSSUB,        RISCV_VV_VSSRL,    RISCV_VV_VSSRA,
                      RISCV_VV_VSRL,         RISCV_VV_VSRA,     RISCV_VV_VSMUL,
                      RISCV_VV_VSLL,         RISCV_VV_VSADDU,   RISCV_VV_VSADD,
                      RISCV_VV_VRGATHEREI16, RISCV_VV_VRGATHER, RISCV_VV_VOR,
                      RISCV_VV_VMINU,        RISCV_VV_VMIN,     RISCV_VV_VMAXU,
                      RISCV_VV_VMAX,         RISCV_VV_VAND,     RISCV_VV_VADD},
    [RISCV_FLEQ_H] = {RISCV_FLEQ_H},
    [RISCV_VICMPTYPE] = {RISCV_VICMP_VMSNE, RISCV_VICMP_VMSLEU,
                         RISCV_VICMP_VMSLE, RISCV_VICMP_VMSGTU,
                         RISCV_VICMP_VMSGT, RISCV_VICMP_VMSEQ},
    [RISCV_C_FLW] = {RISCV_C_FLW},
    [RISCV_C_SWSP] = {RISCV_C_SWSP},
    [RISCV_FLTQ_D] = {RISCV_FLTQ_D},
    [RISCV_AES64ES] = {RISCV_AES64ES},
    [RISCV_C_SRAI_HINT] = {RISCV_C_SRAI_HINT},
    [RISCV_DIV] = {RISCV_DIV},
    [RISCV_F_UN_TYPE_D] = {RISCV_FMV_X_D, RISCV_FMV_D_X, RISCV_FCLASS_D},
    [RISCV_C_LH] = {RISCV_C_LH},
    [RISCV_C_NOP_HINT] = {RISCV_C_NOP_HINT},
    [RISCV_VFIRST_M] = {RISCV_VFIRST_M},
    [RISCV_MVVMATYPE] = {RISCV_MVV_VNMSUB, RISCV_MVV_VNMSAC, RISCV_MVV_VMADD,
                         RISCV_MVV_VMACC},
    [RISCV_FENCEI_RESERVED] = {RISCV_FENCEI_RESERVED},
    [RISCV_C_ADDI] = {RISCV_C_ADDI},
    [RISCV_VLOXSEGTYPE] = {RISCV_VLOXSEGTYPE},
    [RISCV_MUL] = {RISCV_MUL},
    [RISCV_VMSOF_M] = {RISCV_VMSOF_M},
    [RISCV_FLEQ_D] = {RISCV_FLEQ_D},
    [RISCV_VSSSEGTYPE] = {RISCV_VSSSEGTYPE},
    [RISCV_VXTYPE] = {RISCV_VX_VXOR,  RISCV_VX_VSUB,   RISCV_VX_VSSUBU,
                      RISCV_VX_VSSUB, RISCV_VX_VSSRL,  RISCV_VX_VSSRA,
                      RISCV_VX_VSRL,  RISCV_VX_VSRA,   RISCV_VX_VSMUL,
                      RISCV_VX_VSLL,  RISCV_VX_VSADDU, RISCV_VX_VSADD,
                      RISCV_VX_VRSUB, RISCV_VX_VOR,    RISCV_VX_VMINU,
                      RISCV_VX_VMIN,  RISCV_VX_VMAXU,  RISCV_VX_VMAX,
                      RISCV_VX_VAND,  RISCV_VX_VADD},
    [RISCV_BTYPE] = {RISCV_BNE, RISCV_BLTU, RISCV_BLT, RISCV_BGEU, RISCV_BGE,
                     RISCV_BEQ},
    [RISCV_LOAD] = {RISCV_LOAD},
    [RISCV_VIOTA_M] = {RISCV_VIOTA_M},
    [RISCV_CLMULR] = {RISCV_CLMULR},
    [RISCV_VXMSTYPE] = {RISCV_VXMS_VSBC, RISCV_VXMS_VADC},
    [RISCV_CLZ] = {RISCV_CLZ},
    [RISCV_UTYPE] = {RISCV_LUI, RISCV_AUIPC},
    [RISCV_CLMULH] = {RISCV_CLMULH},
    [RISCV_FLI_H] = {RISCV_FLI_H},
    [RISCV_F_BIN_RM_TYPE_H] = {RISCV_FSUB_H, RISCV_FMUL_H, RISCV_FDIV_H,
                               RISCV_FADD_H},
    [RISCV_VSETVLI] = {RISCV_VSETVLI},
    [RISCV_C_SEXT_B] = {RISCV_C_SEXT_B},
    [RISCV_VLUXSEGTYPE] = {RISCV_VLUXSEGTYPE},
    [RISCV_SHA512SUM1R] = {RISCV_SHA512SUM1R},
    [RISCV_VITYPE] = {RISCV_VI_VXOR, RISCV_VI_VSSRL, RISCV_VI_VSSRA,
                      RISCV_VI_VSRL, RISCV_VI_VSRA, RISCV_VI_VSLL,
                      RISCV_VI_VSADDU, RISCV_VI_VSADD, RISCV_VI_VRSUB,
                      RISCV_VI_VOR, RISCV_VI_VAND, RISCV_VI_VADD},
    [RISCV_STORECON] = {RISCV_STORECON},
    [RISCV_VMVRTYPE] = {RISCV_VMVRTYPE},
    [RISCV_ZBKB_RTYPE] = {RISCV_PACKH, RISCV_PACK},
    [RISCV_VISG] = {RISCV_VI_VSLIDEUP, RISCV_VI_VSLIDEDOWN, RISCV_VI_VRGATHER},
    [RISCV_C_ADD] = {RISCV_C_ADD},
    [RISCV_FVFTYPE] = {RISCV_VF_VSUB, RISCV_VF_VSLIDE1UP, RISCV_VF_VSLIDE1DOWN,
                       RISCV_VF_VSGNJX, RISCV_VF_VSGNJN, RISCV_VF_VSGNJ,
                       RISCV_VF_VRSUB, RISCV_VF_VRDIV, RISCV_VF_VMUL,
                       RISCV_VF_VMIN, RISCV_VF_VMAX, RISCV_VF_VDIV,
                       RISCV_VF_VADD},
    [RISCV_FENCE_RESERVED] = {RISCV_FENCE_RESERVED},
    [RISCV_MASKTYPEI] = {RISCV_MASKTYPEI},
    [RISCV_FVVTYPE] = {RISCV_FVV_VSUB, RISCV_FVV_VSGNJX, RISCV_FVV_VSGNJN,
                       RISCV_FVV_VSGNJ, RISCV_FVV_VMUL, RISCV_FVV_VMIN,
                       RISCV_FVV_VMAX, RISCV_FVV_VDIV, RISCV_FVV_VADD},
    [RISCV_CPOPW] = {RISCV_CPOPW},
    [RISCV_C_LI_HINT] = {RISCV_C_LI_HINT},
    [RISCV_SHA256SUM1] = {RISCV_SHA256SUM1},
    [RISCV_VSUXSEGTYPE] = {RISCV_VSUXSEGTYPE},
    [RISCV_VIMCTYPE] = {RISCV_VIMC_VMADC},
    [RISCV_VIMSTYPE] = {RISCV_VIMS_VADC},
    [RISCV_MASKTYPEV] = {RISCV_MASKTYPEV},
    [RISCV_FVFMTYPE] = {RISCV_VFM_VMFNE, RISCV_VFM_VMFLT, RISCV_VFM_VMFLE,
                        RISCV_VFM_VMFGT, RISCV_VFM_VMFGE, RISCV_VFM_VMFEQ},
    [RISCV_ADDIW] = {RISCV_ADDIW},
    [RISCV_MRET] = {RISCV_MRET},
    [RISCV_VLSEGFFTYPE] = {RISCV_VLSEGFFTYPE},
    [RISCV_C_ANDI] = {RISCV_C_ANDI},
    [RISCV_WVTYPE] = {RISCV_WV_VSUBU, RISCV_WV_VSUB, RISCV_WV_VADDU,
                      RISCV_WV_VADD},
    [RISCV_C_SDSP] = {RISCV_C_SDSP},
    [RISCV_C_SUBW] = {RISCV_C_SUBW},
    [RISCV_VEXT4TYPE] = {RISCV_VEXT4_ZVF4, RISCV_VEXT4_SVF4},
    [RISCV_VSETVL] = {RISCV_VSETVL},
    [RISCV_C_SH] = {RISCV_C_SH},
    [RISCV_MVVCOMPRESS] = {RISCV_MVVCOMPRESS},
    [RISCV_FWVVTYPE] = {RISCV_FWVV_VSUB, RISCV_FWVV_VMUL, RISCV_FWVV_VADD},
    [RISCV_VMTYPE] = {RISCV_VSM, RISCV_VLM},
    [RISCV_FROUND_H] = {RISCV_FROUND_H},
    [RISCV_C_JAL] = {RISCV_C_JAL},
    [RISCV_SFENCE_VMA] = {RISCV_SFENCE_VMA},
    [RISCV_NVSTYPE] = {RISCV_NVS_VNSRL, RISCV_NVS_VNSRA},
    [RISCV_FROUND_S] = {RISCV_FROUND_S},
    [RISCV_NISTYPE] = {RISCV_NIS_VNSRL, RISCV_NIS_VNSRA},
    [RISCV_C_SLLI] = {RISCV_C_SLLI},
    [RISCV_VXMTYPE] = {RISCV_VXM_VMSBC, RISCV_VXM_VMADC},
    [RISCV_FENCEI] = {RISCV_FENCEI},
    [RISCV_VFMVSF] = {RISCV_VFMVSF},
    [RISCV_VEXT8TYPE] = {RISCV_VEXT8_ZVF8, RISCV_VEXT8_SVF8},
    [RISCV_C_OR] = {RISCV_C_OR},
    [RISCV_FWVFMATYPE] = {RISCV_FWVF_VNMSAC, RISCV_FWVF_VNMACC,
                          RISCV_FWVF_VMSAC, RISCV_FWVF_VMACC},
    [RISCV_SHIFTIOP] = {RISCV_SRLI, RISCV_SRAI, RISCV_SLLI},
    [RISCV_DIVW] = {RISCV_DIVW},
    [RISCV_C_ZEXT_B] = {RISCV_C_ZEXT_B},
    [RISCV_C_MV] = {RISCV_C_MV},
    [RISCV_VIMTYPE] = {RISCV_VIM_VMADC},
    [RISCV_LOADRES] = {RISCV_LOADRES},
    [RISCV_C_J] = {RISCV_C_J},
    [RISCV_AES32ESI] = {RISCV_AES32ESI},
    [RISCV_C_BEQZ] = {RISCV_C_BEQZ},
    [RISCV_SHA512SUM0] = {RISCV_SHA512SUM0},
    [RISCV_SHA512SUM0R] = {RISCV_SHA512SUM0R},
    [RISCV_REMW] = {RISCV_REMW},
    [RISCV_VFMV] = {RISCV_VFMV},
    [RISCV_C_SEXT_H] = {RISCV_C_SEXT_H},
    [RISCV_WMVXTYPE] = {RISCV_WMVX_VWMACCUS, RISCV_WMVX_VWMACCU,
                        RISCV_WMVX_VWMACCSU, RISCV_WMVX_VWMACC},
    [RISCV_C_FSW] = {RISCV_C_FSW},
    [RISCV_C_SW] = {RISCV_C_SW},
    [RISCV_ZBS_RTYPE] = {RISCV_BSET, RISCV_BINV, RISCV_BEXT, RISCV_BCLR},
    [RISCV_C_SUB] = {RISCV_C_SUB},
    [RISCV_VFUNARY0] = {RISCV_FV_CVT_X_F, RISCV_FV_CVT_XU_F,
                        RISCV_FV_CVT_RTZ_X_F, RISCV_FV_CVT_RTZ_XU_F,
                        RISCV_FV_CVT_F_XU, RISCV_FV_CVT_F_X},
    [RISCV_FROUNDNX_S] = {RISCV_FROUNDNX_S},
    [RISCV_ZICBOZ] = {RISCV_ZICBOZ},
    [RISCV_SFENCE_W_INVAL] = {RISCV_SFENCE_W_INVAL},
    [RISCV_C_JR] = {RISCV_C_JR},
    [RISCV_C_NOT] = {RISCV_C_NOT},
    [RISCV_ZBB_EXTOP] = {RISCV_ZEXTH, RISCV_SEXTH, RISCV_SEXTB},
    [RISCV_MVVTYPE] = {RISCV_MVV_VREMU, RISCV_MVV_VREM, RISCV_MVV_VMULHU,
                       RISCV_MVV_VMULHSU, RISCV_MVV_VMULH, RISCV_MVV_VMUL,
                       RISCV_MVV_VDIVU, RISCV_MVV_VDIV, RISCV_MVV_VASUBU,
                       RISCV_MVV_VASUB, RISCV_MVV_VAADDU, RISCV_MVV_VAADD},
    [RISCV_FVFMATYPE] = {RISCV_VF_VNMSUB, RISCV_VF_VNMSAC, RISCV_VF_VNMADD,
                         RISCV_VF_VNMACC, RISCV_VF_VMSUB, RISCV_VF_VMSAC,
                         RISCV_VF_VMADD, RISCV_VF_VMACC},
    [RISCV_FMAXM_H] = {RISCV_FMAXM_H},
    [RISCV_SHA256SUM0] = {RISCV_SHA256SUM0},
    [RISCV_ZBS_IOP] = {RISCV_BSETI, RISCV_BINVI, RISCV_BEXTI, RISCV_BCLRI},
    [RISCV_C_XOR] = {RISCV_C_XOR},
    [RISCV_FMINM_H] = {RISCV_FMINM_H},
    [RISCV_C_LUI_HINT] = {RISCV_C_LUI_HINT},
    [RISCV_VVMCTYPE] = {RISCV_VVMC_VMSBC, RISCV_VVMC_VMADC},
    [RISCV_F_BIN_RM_TYPE_S] = {RISCV_FSUB_S, RISCV_FMUL_S, RISCV_FDIV_S,
                               RISCV_FADD_S},
    [RISCV_SINVAL_VMA] = {RISCV_SINVAL_VMA},
    [RISCV_MOVETYPEX] = {RISCV_MOVETYPEX},
    [RISCV_C_BNEZ] = {RISCV_C_BNEZ},
    [RISCV_FWVVMATYPE] = {RISCV_FWVV_VNMSAC, RISCV_FWVV_VNMACC,
                          RISCV_FWVV_VMSAC, RISCV_FWVV_VMACC},
    [RISCV_AES64KS1I] = {RISCV_AES64KS1I},
    [RISCV_RMVVTYPE] = {RISCV_MVV_VREDXOR, RISCV_MVV_VREDSUM, RISCV_MVV_VREDOR,
                        RISCV_MVV_VREDMINU, RISCV_MVV_VREDMIN,
                        RISCV_MVV_VREDMAXU, RISCV_MVV_VREDMAX,
                        RISCV_MVV_VREDAND},
    [RISCV_CLZW] = {RISCV_CLZW},
    [RISCV_REM] = {RISCV_REM},
    [RISCV_C_EBREAK] = {RISCV_C_EBREAK},
    [RISCV_AES64ESM] = {RISCV_AES64ESM},
    [RISCV_VFNUNARY0] = {RISCV_FNV_CVT_X_F, RISCV_FNV_CVT_XU_F,
                         RISCV_FNV_CVT_RTZ_X_F, RISCV_FNV_CVT_RTZ_XU_F,
                         RISCV_FNV_CVT_ROD_F_F, RISCV_FNV_CVT_F_XU,
                         RISCV_FNV_CVT_F_X, RISCV_FNV_CVT_F_F},
    [RISCV_VFWUNARY0] = {RISCV_FWV_CVT_X_F, RISCV_FWV_CVT_XU_F,
                         RISCV_FWV_CVT_RTZ_X_F, RISCV_FWV_CVT_RTZ_XU_F,
                         RISCV_FWV_CVT_F_XU, RISCV_FWV_CVT_F_X,
                         RISCV_FWV_CVT_F_F},
    [RISCV_MOVETYPEV] = {RISCV_MOVETYPEV},
    [RISCV_VFUNARY1] = {RISCV_FVV_VSQRT, RISCV_FVV_VRSQRT7, RISCV_FVV_VREC7,
                        RISCV_FVV_VCLASS},
    [RISCV_FWVFTYPE] = {RISCV_FWVF_VSUB, RISCV_FWVF_VMUL, RISCV_FWVF_VADD},
    [RISCV_ZBA_RTYPE] = {RISCV_SH3ADD, RISCV_SH2ADD, RISCV_SH1ADD},
    [RISCV_C_SRLI] = {RISCV_C_SRLI},
    [RISCV_VSRETYPE] = {RISCV_VSRETYPE},
    [RISCV_C_SLLI_HINT] = {RISCV_C_SLLI_HINT},
    [RISCV_WVVTYPE] = {RISCV_WVV_VWMULU, RISCV_WVV_VWMULSU, RISCV_WVV_VWMUL,
                       RISCV_WVV_VSUBU, RISCV_WVV_VSUB, RISCV_WVV_VADDU,
                       RISCV_WVV_VADD},
    [RISCV_AES64DSM] = {RISCV_AES64DSM},
    [RISCV_C_LI] = {RISCV_C_LI},
    [RISCV_CSR] = {RISCV_CSRRW, RISCV_CSRRS, RISCV_CSRRC},
    [RISCV_C_SRAI] = {RISCV_C_SRAI},
    [RISCV_FMVP_D_X] = {RISCV_FMVP_D_X},
    [RISCV_C_LBU] = {RISCV_C_LBU},
    [RISCV_F_UN_RM_TYPE_S] = {RISCV_FSQRT_S, RISCV_FCVT_W_S, RISCV_FCVT_WU_S,
                              RISCV_FCVT_S_WU, RISCV_FCVT_S_W, RISCV_FCVT_S_LU,
                              RISCV_FCVT_S_L, RISCV_FCVT_L_S, RISCV_FCVT_LU_S},
    [RISCV_RTYPEW] = {RISCV_SUBW, RISCV_SRLW, RISCV_SRAW, RISCV_SLLW,
                      RISCV_ADDW},
    [RISCV_WMVVTYPE] = {RISCV_WMVV_VWMACCU, RISCV_WMVV_VWMACCSU,
                        RISCV_WMVV_VWMACC},
    [RISCV_MULW] = {RISCV_MULW},
    [RISCV_VVCMPTYPE] = {RISCV_VVCMP_VMSNE, RISCV_VVCMP_VMSLTU,
                         RISCV_VVCMP_VMSLT, RISCV_VVCMP_VMSLEU,
                         RISCV_VVCMP_VMSLE, RISCV_VVCMP_VMSEQ},
    [RISCV_ILLEGAL] = {RISCV_ILLEGAL},
    [RISCV_BREV8] = {RISCV_BREV8},
    [RISCV_AES32DSMI] = {RISCV_AES32DSMI},
    [RISCV_C_FSD] = {RISCV_C_FSD},
    [RISCV_C_ADDW] = {RISCV_C_ADDW},
    [RISCV_VCPOP_M] = {RISCV_VCPOP_M},
    [RISCV_SHA256SIG1] = {RISCV_SHA256SIG1},
    [RISCV_MVXTYPE] = {RISCV_MVX_VSLIDE1UP, RISCV_MVX_VSLIDE1DOWN,
                       RISCV_MVX_VREMU, RISCV_MVX_VREM, RISCV_MVX_VMULHU,
                       RISCV_MVX_VMULHSU, RISCV_MVX_VMULH, RISCV_MVX_VMUL,
                       RISCV_MVX_VDIVU, RISCV_MVX_VDIV, RISCV_MVX_VASUBU,
                       RISCV_MVX_VASUB, RISCV_MVX_VAADDU, RISCV_MVX_VAADD},
};
static uint16_t get_insn_type(struct ast *tree) {
  switch (tree->ast_node_type) {
  case RISCV_WXTYPE:
    return to_insn[RISCV_WXTYPE][tree->ast_node.wxtype.funct6];
  case RISCV_RTYPE:
    return to_insn[RISCV_RTYPE][tree->ast_node.rtype.op];
  case RISCV_RIVVTYPE:
    return to_insn[RISCV_RIVVTYPE][tree->ast_node.rivvtype.funct6];
  case RISCV_VXSG:
    return to_insn[RISCV_VXSG][tree->ast_node.vxsg.funct6];
  case RISCV_VXCMPTYPE:
    return to_insn[RISCV_VXCMPTYPE][tree->ast_node.vxcmptype.funct6];
  case RISCV_SHIFTIWOP:
    return to_insn[RISCV_SHIFTIWOP][tree->ast_node.shiftiwop.op];
  case RISCV_ZICBOM:
    return to_insn[RISCV_ZICBOM][tree->ast_node.riscv_zicbom.cbop];
  case RISCV_NITYPE:
    return to_insn[RISCV_NITYPE][tree->ast_node.nitype.funct6];
  case RISCV_VVMTYPE:
    return to_insn[RISCV_VVMTYPE][tree->ast_node.vvmtype.funct6];
  case RISCV_MVXMATYPE:
    return to_insn[RISCV_MVXMATYPE][tree->ast_node.mvxmatype.funct6];
  case RISCV_F_BIN_TYPE_H:
    return to_insn[RISCV_F_BIN_TYPE_H][tree->ast_node.f_bin_type_h.fle_h];
  case RISCV_FVVMTYPE:
    return to_insn[RISCV_FVVMTYPE][tree->ast_node.fvvmtype.funct6];
  case RISCV_F_UN_RM_TYPE_D:
    return to_insn[RISCV_F_UN_RM_TYPE_D]
                  [tree->ast_node.f_un_rm_type_d.fcvt_d_lu];
  case RISCV_WVXTYPE:
    return to_insn[RISCV_WVXTYPE][tree->ast_node.wvxtype.funct6];
  case RISCV_NXSTYPE:
    return to_insn[RISCV_NXSTYPE][tree->ast_node.nxstype.funct6];
  case RISCV_VXMCTYPE:
    return to_insn[RISCV_VXMCTYPE][tree->ast_node.vxmctype.funct6];
  case RISCV_MMTYPE:
    return to_insn[RISCV_MMTYPE][tree->ast_node.mmtype.funct6];
  case RISCV_F_UN_TYPE_S:
    return to_insn[RISCV_F_UN_TYPE_S][tree->ast_node.f_un_type_s.fmv_w_x];
  case RISCV_NVTYPE:
    return to_insn[RISCV_NVTYPE][tree->ast_node.nvtype.funct6];
  case RISCV_F_MADD_TYPE_H:
    return to_insn[RISCV_F_MADD_TYPE_H][tree->ast_node.f_madd_type_h.op];
  case RISCV_ZBA_RTYPEUW:
    return to_insn[RISCV_ZBA_RTYPEUW][tree->ast_node.zba_rtypeuw.op];
  case RISCV_F_BIN_RM_TYPE_D:
    return to_insn[RISCV_F_BIN_RM_TYPE_D][tree->ast_node.f_bin_rm_type_d.op];
  case RISCV_F_MADD_TYPE_S:
    return to_insn[RISCV_F_MADD_TYPE_S][tree->ast_node.f_madd_type_s.op];
  case RISCV_F_UN_RM_TYPE_H:
    return to_insn[RISCV_F_UN_RM_TYPE_H]
                  [tree->ast_node.f_un_rm_type_h.fcvt_h_lu];
  case RISCV_FWFTYPE:
    return to_insn[RISCV_FWFTYPE][tree->ast_node.fwftype.funct6];
  case RISCV_FWVTYPE:
    return to_insn[RISCV_FWVTYPE][tree->ast_node.fwvtype.funct6];
  case RISCV_ZBB_RTYPE:
    return to_insn[RISCV_ZBB_RTYPE][tree->ast_node.zbb_rtype.op];
  case RISCV_NXTYPE:
    return to_insn[RISCV_NXTYPE][tree->ast_node.nxtype.funct6];
  case RISCV_ITYPE:
    return to_insn[RISCV_ITYPE][tree->ast_node.itype.op];
  case RISCV_F_BIN_TYPE_S:
    return to_insn[RISCV_F_BIN_TYPE_S][tree->ast_node.f_bin_type_s.fle_s];
  case RISCV_F_BIN_TYPE_D:
    return to_insn[RISCV_F_BIN_TYPE_D][tree->ast_node.f_bin_type_d.fle_d];
  case RISCV_ZICOND_RTYPE:
    return to_insn[RISCV_ZICOND_RTYPE]
                  [tree->ast_node.zicond_rtype.riscv_czero_nez];
  case RISCV_ZBB_RTYPEW:
    return to_insn[RISCV_ZBB_RTYPEW][tree->ast_node.zbb_rtypew.op];
  case RISCV_RFVVTYPE:
    return to_insn[RISCV_RFVVTYPE][tree->ast_node.rfvvtype.funct6];
  case RISCV_AMO:
    return to_insn[RISCV_AMO][tree->ast_node.amo.op];
  case RISCV_VVMSTYPE:
    return to_insn[RISCV_VVMSTYPE][tree->ast_node.vvmstype.funct6];
  case RISCV_FVVMATYPE:
    return to_insn[RISCV_FVVMATYPE][tree->ast_node.fvvmatype.funct6];
  case RISCV_VEXT2TYPE:
    return to_insn[RISCV_VEXT2TYPE][tree->ast_node.vext2type.funct6];
  case RISCV_F_MADD_TYPE_D:
    return to_insn[RISCV_F_MADD_TYPE_D][tree->ast_node.f_madd_type_d.op];
  case RISCV_F_UN_TYPE_H:
    return to_insn[RISCV_F_UN_TYPE_H][tree->ast_node.f_un_type_h.fmv_h_x];
  case RISCV_VVTYPE:
    return to_insn[RISCV_VVTYPE][tree->ast_node.vvtype.funct6];
  case RISCV_VICMPTYPE:
    return to_insn[RISCV_VICMPTYPE][tree->ast_node.vicmptype.funct6];
  case RISCV_F_UN_TYPE_D:
    return to_insn[RISCV_F_UN_TYPE_D][tree->ast_node.f_un_type_d.fmv_d_x];
  case RISCV_MVVMATYPE:
    return to_insn[RISCV_MVVMATYPE][tree->ast_node.mvvmatype.funct6];
  case RISCV_VXTYPE:
    return to_insn[RISCV_VXTYPE][tree->ast_node.vxtype.funct6];
  case RISCV_BTYPE:
    return to_insn[RISCV_BTYPE][tree->ast_node.btype.op];
  case RISCV_VXMSTYPE:
    return to_insn[RISCV_VXMSTYPE][tree->ast_node.vxmstype.funct6];
  case RISCV_UTYPE:
    return to_insn[RISCV_UTYPE][tree->ast_node.utype.op];
  case RISCV_F_BIN_RM_TYPE_H:
    return to_insn[RISCV_F_BIN_RM_TYPE_H][tree->ast_node.f_bin_rm_type_h.op];
  case RISCV_VITYPE:
    return to_insn[RISCV_VITYPE][tree->ast_node.vitype.funct6];
  case RISCV_ZBKB_RTYPE:
    return to_insn[RISCV_ZBKB_RTYPE][tree->ast_node.zbkb_rtype.op];
  case RISCV_VISG:
    return to_insn[RISCV_VISG][tree->ast_node.visg.funct6];
  case RISCV_FVFTYPE:
    return to_insn[RISCV_FVFTYPE][tree->ast_node.fvftype.funct6];
  case RISCV_FVVTYPE:
    return to_insn[RISCV_FVVTYPE][tree->ast_node.fvvtype.funct6];
  case RISCV_VIMCTYPE:
    return to_insn[RISCV_VIMCTYPE][tree->ast_node.vimctype.funct6];
  case RISCV_VIMSTYPE:
    return to_insn[RISCV_VIMSTYPE][tree->ast_node.vimstype.funct6];
  case RISCV_FVFMTYPE:
    return to_insn[RISCV_FVFMTYPE][tree->ast_node.fvfmtype.funct6];
  case RISCV_WVTYPE:
    return to_insn[RISCV_WVTYPE][tree->ast_node.wvtype.funct6];
  case RISCV_VEXT4TYPE:
    return to_insn[RISCV_VEXT4TYPE][tree->ast_node.vext4type.funct6];
  case RISCV_FWVVTYPE:
    return to_insn[RISCV_FWVVTYPE][tree->ast_node.fwvvtype.funct6];
  case RISCV_VMTYPE:
    return to_insn[RISCV_VMTYPE][tree->ast_node.vmtype.op];
  case RISCV_NVSTYPE:
    return to_insn[RISCV_NVSTYPE][tree->ast_node.nvstype.funct6];
  case RISCV_NISTYPE:
    return to_insn[RISCV_NISTYPE][tree->ast_node.nistype.funct6];
  case RISCV_VXMTYPE:
    return to_insn[RISCV_VXMTYPE][tree->ast_node.vxmtype.funct6];
  case RISCV_VEXT8TYPE:
    return to_insn[RISCV_VEXT8TYPE][tree->ast_node.vext8type.funct6];
  case RISCV_FWVFMATYPE:
    return to_insn[RISCV_FWVFMATYPE][tree->ast_node.fwvfmatype.funct6];
  case RISCV_SHIFTIOP:
    return to_insn[RISCV_SHIFTIOP][tree->ast_node.shiftiop.op];
  case RISCV_VIMTYPE:
    return to_insn[RISCV_VIMTYPE][tree->ast_node.vimtype.funct6];
  case RISCV_WMVXTYPE:
    return to_insn[RISCV_WMVXTYPE][tree->ast_node.wmvxtype.funct6];
  case RISCV_ZBS_RTYPE:
    return to_insn[RISCV_ZBS_RTYPE][tree->ast_node.zbs_rtype.op];
  case RISCV_VFUNARY0:
    return to_insn[RISCV_VFUNARY0][tree->ast_node.vfunary0.vfunary0];
  case RISCV_ZBB_EXTOP:
    return to_insn[RISCV_ZBB_EXTOP][tree->ast_node.zbb_extop.op];
  case RISCV_MVVTYPE:
    return to_insn[RISCV_MVVTYPE][tree->ast_node.mvvtype.funct6];
  case RISCV_FVFMATYPE:
    return to_insn[RISCV_FVFMATYPE][tree->ast_node.fvfmatype.funct6];
  case RISCV_ZBS_IOP:
    return to_insn[RISCV_ZBS_IOP][tree->ast_node.zbs_iop.op];
  case RISCV_VVMCTYPE:
    return to_insn[RISCV_VVMCTYPE][tree->ast_node.vvmctype.funct6];
  case RISCV_F_BIN_RM_TYPE_S:
    return to_insn[RISCV_F_BIN_RM_TYPE_S][tree->ast_node.f_bin_rm_type_s.op];
  case RISCV_FWVVMATYPE:
    return to_insn[RISCV_FWVVMATYPE][tree->ast_node.fwvvmatype.funct6];
  case RISCV_RMVVTYPE:
    return to_insn[RISCV_RMVVTYPE][tree->ast_node.rmvvtype.funct6];
  case RISCV_VFNUNARY0:
    return to_insn[RISCV_VFNUNARY0][tree->ast_node.vfnunary0.vfnunary0];
  case RISCV_VFWUNARY0:
    return to_insn[RISCV_VFWUNARY0][tree->ast_node.vfwunary0.vfwunary0];
  case RISCV_VFUNARY1:
    return to_insn[RISCV_VFUNARY1][tree->ast_node.vfunary1.vfunary1];
  case RISCV_FWVFTYPE:
    return to_insn[RISCV_FWVFTYPE][tree->ast_node.fwvftype.funct6];
  case RISCV_ZBA_RTYPE:
    return to_insn[RISCV_ZBA_RTYPE][tree->ast_node.zba_rtype.op];
  case RISCV_WVVTYPE:
    return to_insn[RISCV_WVVTYPE][tree->ast_node.wvvtype.funct6];
  case RISCV_CSR:
    return to_insn[RISCV_CSR][tree->ast_node.csr.op];
  case RISCV_F_UN_RM_TYPE_S:
    return to_insn[RISCV_F_UN_RM_TYPE_S]
                  [tree->ast_node.f_un_rm_type_s.fcvt_s_lu];
  case RISCV_RTYPEW:
    return to_insn[RISCV_RTYPEW][tree->ast_node.rtypew.op];
  case RISCV_WMVVTYPE:
    return to_insn[RISCV_WMVVTYPE][tree->ast_node.wmvvtype.funct6];
  case RISCV_VVCMPTYPE:
    return to_insn[RISCV_VVCMPTYPE][tree->ast_node.vvcmptype.funct6];
  case RISCV_MVXTYPE:
    return to_insn[RISCV_MVXTYPE][tree->ast_node.mvxtype.funct6];
  default:
    return to_insn[tree->ast_node_type][0];
  }
}

#endif
