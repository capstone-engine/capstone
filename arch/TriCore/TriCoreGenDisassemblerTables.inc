/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/*    Rot127 <unisono@quyllur.org> 2022-2023 */
/* Automatically generated file by the LLVM TableGen Disassembler Backend. */
/* Do not edit. */

#include "../../MCInst.h"
#include "../../LEB128.h"

// Helper function for extracting fields from encoded instructions.
#define FieldFromInstruction(fname, InsnType) \
static InsnType fname(InsnType insn, unsigned startBit, unsigned numBits) \
{ \
  InsnType fieldMask; \
  if (numBits == sizeof(InsnType) * 8) \
    fieldMask = (InsnType)(-1LL); \
  else \
    fieldMask = (((InsnType)1 << numBits) - 1) << startBit; \
  return (insn & fieldMask) >> startBit; \
}

static const uint8_t DecoderTable16[] = {
/* 0 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 3 */       MCD_OPC_FilterValue, 0, 74, 0, 0, // Skip to: 82
/* 8 */       MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 11 */      MCD_OPC_FilterValue, 0, 48, 0, 0, // Skip to: 64
/* 16 */      MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 19 */      MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 28
/* 24 */      MCD_OPC_Decode, 210, 6, 0, // Opcode: NOP_sr
/* 28 */      MCD_OPC_FilterValue, 7, 4, 0, 0, // Skip to: 37
/* 33 */      MCD_OPC_Decode, 160, 3, 0, // Opcode: FRET_sr
/* 37 */      MCD_OPC_FilterValue, 8, 4, 0, 0, // Skip to: 46
/* 42 */      MCD_OPC_Decode, 246, 6, 0, // Opcode: RFE_sr
/* 46 */      MCD_OPC_FilterValue, 9, 4, 0, 0, // Skip to: 55
/* 51 */      MCD_OPC_Decode, 244, 6, 0, // Opcode: RET_sr
/* 55 */      MCD_OPC_FilterValue, 10, 251, 4, 0, // Skip to: 1335
/* 60 */      MCD_OPC_Decode, 247, 2, 0, // Opcode: DEBUG_sr
/* 64 */      MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 73
/* 69 */      MCD_OPC_Decode, 193, 5, 1, // Opcode: MOV_AA_srr
/* 73 */      MCD_OPC_FilterValue, 2, 233, 4, 0, // Skip to: 1335
/* 78 */      MCD_OPC_Decode, 198, 5, 1, // Opcode: MOV_D_srr
/* 82 */      MCD_OPC_FilterValue, 2, 39, 0, 0, // Skip to: 126
/* 87 */      MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 90 */      MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 99
/* 95 */      MCD_OPC_Decode, 209, 5, 1, // Opcode: MOV_srr
/* 99 */      MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 108
/* 104 */     MCD_OPC_Decode, 160, 2, 1, // Opcode: ADD_srr
/* 108 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 117
/* 113 */     MCD_OPC_Decode, 207, 5, 2, // Opcode: MOV_srcDa
/* 117 */     MCD_OPC_FilterValue, 3, 189, 4, 0, // Skip to: 1335
/* 122 */     MCD_OPC_Decode, 157, 2, 2, // Opcode: ADD_src
/* 126 */     MCD_OPC_FilterValue, 4, 39, 0, 0, // Skip to: 170
/* 131 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 134 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 143
/* 139 */     MCD_OPC_Decode, 136, 4, 3, // Opcode: LD_BU_slr_post
/* 143 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 152
/* 148 */     MCD_OPC_Decode, 191, 4, 3, // Opcode: LD_W_slr_post
/* 152 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 161
/* 157 */     MCD_OPC_Decode, 173, 4, 3, // Opcode: LD_H_slr_post
/* 161 */     MCD_OPC_FilterValue, 3, 145, 4, 0, // Skip to: 1335
/* 166 */     MCD_OPC_Decode, 253, 3, 3, // Opcode: LD_A_slr_post
/* 170 */     MCD_OPC_FilterValue, 6, 46, 0, 0, // Skip to: 221
/* 175 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 178 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 187
/* 183 */     MCD_OPC_Decode, 171, 7, 2, // Opcode: SH_src
/* 187 */     MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 203
/* 192 */     MCD_OPC_CheckField, 12, 4, 0, 112, 4, 0, // Skip to: 1335
/* 199 */     MCD_OPC_Decode, 215, 6, 0, // Opcode: NOT_sr
/* 203 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 212
/* 208 */     MCD_OPC_Decode, 145, 7, 2, // Opcode: SHA_src
/* 212 */     MCD_OPC_FilterValue, 3, 94, 4, 0, // Skip to: 1335
/* 217 */     MCD_OPC_Decode, 162, 8, 1, // Opcode: XOR_srr
/* 221 */     MCD_OPC_FilterValue, 8, 39, 0, 0, // Skip to: 265
/* 226 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 229 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 238
/* 234 */     MCD_OPC_Decode, 137, 4, 4, // Opcode: LD_BU_slro
/* 238 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 247
/* 243 */     MCD_OPC_Decode, 192, 4, 4, // Opcode: LD_W_slro
/* 247 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 256
/* 252 */     MCD_OPC_Decode, 174, 4, 4, // Opcode: LD_H_slro
/* 256 */     MCD_OPC_FilterValue, 3, 50, 4, 0, // Skip to: 1335
/* 261 */     MCD_OPC_Decode, 254, 3, 4, // Opcode: LD_A_slro
/* 265 */     MCD_OPC_FilterValue, 10, 21, 0, 0, // Skip to: 291
/* 270 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 273 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 282
/* 278 */     MCD_OPC_Decode, 222, 2, 2, // Opcode: CADD_src
/* 282 */     MCD_OPC_FilterValue, 3, 24, 4, 0, // Skip to: 1335
/* 287 */     MCD_OPC_Decode, 219, 2, 2, // Opcode: CADDN_src
/* 291 */     MCD_OPC_FilterValue, 12, 39, 0, 0, // Skip to: 335
/* 296 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 299 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 308
/* 304 */     MCD_OPC_Decode, 138, 4, 5, // Opcode: LD_BU_sro
/* 308 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 317
/* 313 */     MCD_OPC_Decode, 193, 4, 5, // Opcode: LD_W_sro
/* 317 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 326
/* 322 */     MCD_OPC_Decode, 175, 4, 5, // Opcode: LD_H_sro
/* 326 */     MCD_OPC_FilterValue, 3, 236, 3, 0, // Skip to: 1335
/* 331 */     MCD_OPC_Decode, 255, 3, 5, // Opcode: LD_A_sro
/* 335 */     MCD_OPC_FilterValue, 13, 18, 0, 0, // Skip to: 358
/* 340 */     MCD_OPC_CheckField, 12, 4, 3, 220, 3, 0, // Skip to: 1335
/* 347 */     MCD_OPC_CheckField, 6, 2, 0, 213, 3, 0, // Skip to: 1335
/* 354 */     MCD_OPC_Decode, 161, 3, 0, // Opcode: FRET_sys
/* 358 */     MCD_OPC_FilterValue, 14, 39, 0, 0, // Skip to: 402
/* 363 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 366 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 375
/* 371 */     MCD_OPC_Decode, 203, 3, 6, // Opcode: JLTZ_sbr
/* 375 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 384
/* 380 */     MCD_OPC_Decode, 197, 3, 6, // Opcode: JGTZ_sbr
/* 384 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 393
/* 389 */     MCD_OPC_Decode, 201, 3, 6, // Opcode: JLEZ_sbr
/* 393 */     MCD_OPC_FilterValue, 3, 169, 3, 0, // Skip to: 1335
/* 398 */     MCD_OPC_Decode, 192, 3, 6, // Opcode: JGEZ_sbr
/* 402 */     MCD_OPC_FilterValue, 16, 4, 0, 0, // Skip to: 411
/* 407 */     MCD_OPC_Decode, 140, 2, 7, // Opcode: ADDSC_A_srrs
/* 411 */     MCD_OPC_FilterValue, 18, 39, 0, 0, // Skip to: 455
/* 416 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 419 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 428
/* 424 */     MCD_OPC_Decode, 162, 2, 1, // Opcode: ADD_srr_a15
/* 428 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 437
/* 433 */     MCD_OPC_Decode, 254, 7, 1, // Opcode: SUB_srr_a15
/* 437 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 446
/* 442 */     MCD_OPC_Decode, 159, 2, 2, // Opcode: ADD_src_a15
/* 446 */     MCD_OPC_FilterValue, 3, 116, 3, 0, // Skip to: 1335
/* 451 */     MCD_OPC_Decode, 208, 5, 2, // Opcode: MOV_srcEa
/* 455 */     MCD_OPC_FilterValue, 20, 39, 0, 0, // Skip to: 499
/* 460 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 463 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 472
/* 468 */     MCD_OPC_Decode, 135, 4, 3, // Opcode: LD_BU_slr
/* 472 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 481
/* 477 */     MCD_OPC_Decode, 190, 4, 3, // Opcode: LD_W_slr
/* 481 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 490
/* 486 */     MCD_OPC_Decode, 172, 4, 3, // Opcode: LD_H_slr
/* 490 */     MCD_OPC_FilterValue, 3, 72, 3, 0, // Skip to: 1335
/* 495 */     MCD_OPC_Decode, 252, 3, 3, // Opcode: LD_A_slr
/* 499 */     MCD_OPC_FilterValue, 22, 21, 0, 0, // Skip to: 525
/* 504 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 507 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 516
/* 512 */     MCD_OPC_Decode, 185, 2, 8, // Opcode: AND_src
/* 516 */     MCD_OPC_FilterValue, 2, 46, 3, 0, // Skip to: 1335
/* 521 */     MCD_OPC_Decode, 238, 6, 8, // Opcode: OR_sc
/* 525 */     MCD_OPC_FilterValue, 24, 21, 0, 0, // Skip to: 551
/* 530 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 533 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 542
/* 538 */     MCD_OPC_Decode, 189, 4, 8, // Opcode: LD_W_sc
/* 542 */     MCD_OPC_FilterValue, 3, 20, 3, 0, // Skip to: 1335
/* 547 */     MCD_OPC_Decode, 251, 3, 8, // Opcode: LD_A_sc
/* 551 */     MCD_OPC_FilterValue, 26, 39, 0, 0, // Skip to: 595
/* 556 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 559 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 568
/* 564 */     MCD_OPC_Decode, 161, 2, 1, // Opcode: ADD_srr_15a
/* 568 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 577
/* 573 */     MCD_OPC_Decode, 253, 7, 1, // Opcode: SUB_srr_15a
/* 577 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 586
/* 582 */     MCD_OPC_Decode, 158, 2, 2, // Opcode: ADD_src_15a
/* 586 */     MCD_OPC_FilterValue, 3, 232, 2, 0, // Skip to: 1335
/* 591 */     MCD_OPC_Decode, 206, 5, 8, // Opcode: MOV_sc
/* 595 */     MCD_OPC_FilterValue, 28, 18, 0, 0, // Skip to: 618
/* 600 */     MCD_OPC_CheckField, 12, 4, 0, 216, 2, 0, // Skip to: 1335
/* 607 */     MCD_OPC_CheckField, 6, 2, 3, 209, 2, 0, // Skip to: 1335
/* 614 */     MCD_OPC_Decode, 199, 3, 0, // Opcode: JI_sr
/* 618 */     MCD_OPC_FilterValue, 30, 39, 0, 0, // Skip to: 662
/* 623 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 626 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 635
/* 631 */     MCD_OPC_Decode, 188, 3, 9, // Opcode: JEQ_sbc1
/* 635 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 644
/* 640 */     MCD_OPC_Decode, 216, 3, 9, // Opcode: JNE_sbc1
/* 644 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 653
/* 649 */     MCD_OPC_Decode, 189, 3, 9, // Opcode: JEQ_sbc2
/* 653 */     MCD_OPC_FilterValue, 3, 165, 2, 0, // Skip to: 1335
/* 658 */     MCD_OPC_Decode, 217, 3, 9, // Opcode: JNE_sbc2
/* 662 */     MCD_OPC_FilterValue, 32, 39, 0, 0, // Skip to: 706
/* 667 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 670 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 679
/* 675 */     MCD_OPC_Decode, 248, 7, 8, // Opcode: SUB_A_sc
/* 679 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 688
/* 684 */     MCD_OPC_Decode, 196, 5, 1, // Opcode: MOV_A_srr
/* 688 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 697
/* 693 */     MCD_OPC_Decode, 195, 5, 2, // Opcode: MOV_A_src
/* 697 */     MCD_OPC_FilterValue, 3, 121, 2, 0, // Skip to: 1335
/* 702 */     MCD_OPC_Decode, 188, 2, 8, // Opcode: BISR_sc
/* 706 */     MCD_OPC_FilterValue, 34, 39, 0, 0, // Skip to: 750
/* 711 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 714 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 723
/* 719 */     MCD_OPC_Decode, 147, 2, 1, // Opcode: ADDS_srr
/* 723 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 732
/* 728 */     MCD_OPC_Decode, 245, 7, 1, // Opcode: SUBS_srr
/* 732 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 741
/* 737 */     MCD_OPC_Decode, 252, 7, 1, // Opcode: SUB_srr
/* 741 */     MCD_OPC_FilterValue, 3, 77, 2, 0, // Skip to: 1335
/* 746 */     MCD_OPC_Decode, 202, 6, 1, // Opcode: MUL_srr
/* 750 */     MCD_OPC_FilterValue, 35, 11, 0, 0, // Skip to: 766
/* 755 */     MCD_OPC_CheckField, 6, 2, 2, 61, 2, 0, // Skip to: 1335
/* 762 */     MCD_OPC_Decode, 223, 3, 10, // Opcode: JNZ_T_sbrn
/* 766 */     MCD_OPC_FilterValue, 36, 39, 0, 0, // Skip to: 810
/* 771 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 774 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 783
/* 779 */     MCD_OPC_Decode, 197, 7, 11, // Opcode: ST_B_ssr_pos
/* 783 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 792
/* 788 */     MCD_OPC_Decode, 238, 7, 11, // Opcode: ST_W_ssr_pos
/* 792 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 801
/* 797 */     MCD_OPC_Decode, 220, 7, 11, // Opcode: ST_H_ssr_pos
/* 801 */     MCD_OPC_FilterValue, 3, 17, 2, 0, // Skip to: 1335
/* 806 */     MCD_OPC_Decode, 186, 7, 11, // Opcode: ST_A_ssr_pos
/* 810 */     MCD_OPC_FilterValue, 38, 21, 0, 0, // Skip to: 836
/* 815 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 818 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 827
/* 823 */     MCD_OPC_Decode, 186, 2, 1, // Opcode: AND_srr
/* 827 */     MCD_OPC_FilterValue, 2, 247, 1, 0, // Skip to: 1335
/* 832 */     MCD_OPC_Decode, 239, 6, 1, // Opcode: OR_srr
/* 836 */     MCD_OPC_FilterValue, 40, 39, 0, 0, // Skip to: 880
/* 841 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 844 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 853
/* 849 */     MCD_OPC_Decode, 198, 7, 12, // Opcode: ST_B_ssro
/* 853 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 862
/* 858 */     MCD_OPC_Decode, 239, 7, 12, // Opcode: ST_W_ssro
/* 862 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 871
/* 867 */     MCD_OPC_Decode, 221, 7, 12, // Opcode: ST_H_ssro
/* 871 */     MCD_OPC_FilterValue, 3, 203, 1, 0, // Skip to: 1335
/* 876 */     MCD_OPC_Decode, 187, 7, 12, // Opcode: ST_A_ssro
/* 880 */     MCD_OPC_FilterValue, 42, 39, 0, 0, // Skip to: 924
/* 885 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 888 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 897
/* 893 */     MCD_OPC_Decode, 235, 2, 1, // Opcode: CMOV_srr
/* 897 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 906
/* 902 */     MCD_OPC_Decode, 233, 2, 1, // Opcode: CMOVN_srr
/* 906 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 915
/* 911 */     MCD_OPC_Decode, 234, 2, 2, // Opcode: CMOV_src
/* 915 */     MCD_OPC_FilterValue, 3, 159, 1, 0, // Skip to: 1335
/* 920 */     MCD_OPC_Decode, 232, 2, 2, // Opcode: CMOVN_src
/* 924 */     MCD_OPC_FilterValue, 44, 39, 0, 0, // Skip to: 968
/* 929 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 932 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 941
/* 937 */     MCD_OPC_Decode, 195, 7, 5, // Opcode: ST_B_sro
/* 941 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 950
/* 946 */     MCD_OPC_Decode, 236, 7, 5, // Opcode: ST_W_sro
/* 950 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 959
/* 955 */     MCD_OPC_Decode, 218, 7, 5, // Opcode: ST_H_sro
/* 959 */     MCD_OPC_FilterValue, 3, 115, 1, 0, // Skip to: 1335
/* 964 */     MCD_OPC_Decode, 184, 7, 5, // Opcode: ST_A_sro
/* 968 */     MCD_OPC_FilterValue, 46, 30, 0, 0, // Skip to: 1003
/* 973 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 976 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 985
/* 981 */     MCD_OPC_Decode, 229, 3, 10, // Opcode: JZ_T_sbrn
/* 985 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 994
/* 990 */     MCD_OPC_Decode, 230, 3, 13, // Opcode: JZ_sb
/* 994 */     MCD_OPC_FilterValue, 3, 80, 1, 0, // Skip to: 1335
/* 999 */     MCD_OPC_Decode, 224, 3, 13, // Opcode: JNZ_sb
/* 1003 */    MCD_OPC_FilterValue, 48, 21, 0, 0, // Skip to: 1029
/* 1008 */    MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 1011 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1020
/* 1016 */    MCD_OPC_Decode, 152, 2, 1, // Opcode: ADD_A_srr
/* 1020 */    MCD_OPC_FilterValue, 2, 54, 1, 0, // Skip to: 1335
/* 1025 */    MCD_OPC_Decode, 151, 2, 2, // Opcode: ADD_A_src
/* 1029 */    MCD_OPC_FilterValue, 50, 83, 0, 0, // Skip to: 1117
/* 1034 */    MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 1037 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1053
/* 1042 */    MCD_OPC_CheckField, 6, 2, 0, 30, 1, 0, // Skip to: 1335
/* 1049 */    MCD_OPC_Decode, 130, 7, 0, // Opcode: SAT_B_sr
/* 1053 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 1069
/* 1058 */    MCD_OPC_CheckField, 6, 2, 0, 14, 1, 0, // Skip to: 1335
/* 1065 */    MCD_OPC_Decode, 128, 7, 0, // Opcode: SAT_BU_sr
/* 1069 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 1085
/* 1074 */    MCD_OPC_CheckField, 6, 2, 0, 254, 0, 0, // Skip to: 1335
/* 1081 */    MCD_OPC_Decode, 134, 7, 0, // Opcode: SAT_H_sr
/* 1085 */    MCD_OPC_FilterValue, 3, 11, 0, 0, // Skip to: 1101
/* 1090 */    MCD_OPC_CheckField, 6, 2, 0, 238, 0, 0, // Skip to: 1335
/* 1097 */    MCD_OPC_Decode, 132, 7, 0, // Opcode: SAT_HU_sr
/* 1101 */    MCD_OPC_FilterValue, 5, 229, 0, 0, // Skip to: 1335
/* 1106 */    MCD_OPC_CheckField, 6, 2, 0, 222, 0, 0, // Skip to: 1335
/* 1113 */    MCD_OPC_Decode, 254, 6, 0, // Opcode: RSUB_sr
/* 1117 */    MCD_OPC_FilterValue, 52, 39, 0, 0, // Skip to: 1161
/* 1122 */    MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 1125 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1134
/* 1130 */    MCD_OPC_Decode, 196, 7, 11, // Opcode: ST_B_ssr
/* 1134 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1143
/* 1139 */    MCD_OPC_Decode, 237, 7, 11, // Opcode: ST_W_ssr
/* 1143 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1152
/* 1148 */    MCD_OPC_Decode, 219, 7, 11, // Opcode: ST_H_ssr
/* 1152 */    MCD_OPC_FilterValue, 3, 178, 0, 0, // Skip to: 1335
/* 1157 */    MCD_OPC_Decode, 185, 7, 11, // Opcode: ST_A_ssr
/* 1161 */    MCD_OPC_FilterValue, 54, 21, 0, 0, // Skip to: 1187
/* 1166 */    MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 1169 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1178
/* 1174 */    MCD_OPC_Decode, 231, 3, 6, // Opcode: JZ_sbr
/* 1178 */    MCD_OPC_FilterValue, 3, 152, 0, 0, // Skip to: 1335
/* 1183 */    MCD_OPC_Decode, 225, 3, 6, // Opcode: JNZ_sbr
/* 1187 */    MCD_OPC_FilterValue, 56, 11, 0, 0, // Skip to: 1203
/* 1192 */    MCD_OPC_CheckField, 6, 2, 3, 136, 0, 0, // Skip to: 1335
/* 1199 */    MCD_OPC_Decode, 183, 7, 8, // Opcode: ST_A_sc
/* 1203 */    MCD_OPC_FilterValue, 58, 39, 0, 0, // Skip to: 1247
/* 1208 */    MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 1211 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1220
/* 1216 */    MCD_OPC_Decode, 150, 3, 1, // Opcode: EQ_srr
/* 1220 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1229
/* 1225 */    MCD_OPC_Decode, 213, 4, 1, // Opcode: LT_srr
/* 1229 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1238
/* 1234 */    MCD_OPC_Decode, 149, 3, 2, // Opcode: EQ_src
/* 1238 */    MCD_OPC_FilterValue, 3, 92, 0, 0, // Skip to: 1335
/* 1243 */    MCD_OPC_Decode, 212, 4, 2, // Opcode: LT_src
/* 1247 */    MCD_OPC_FilterValue, 60, 39, 0, 0, // Skip to: 1291
/* 1252 */    MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 1255 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1264
/* 1260 */    MCD_OPC_Decode, 233, 3, 13, // Opcode: J_sb
/* 1264 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1273
/* 1269 */    MCD_OPC_Decode, 221, 3, 6, // Opcode: JNZ_A_sbr
/* 1273 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1282
/* 1278 */    MCD_OPC_Decode, 227, 3, 6, // Opcode: JZ_A_sbr
/* 1282 */    MCD_OPC_FilterValue, 3, 48, 0, 0, // Skip to: 1335
/* 1287 */    MCD_OPC_Decode, 200, 4, 6, // Opcode: LOOP_sbr
/* 1291 */    MCD_OPC_FilterValue, 62, 39, 0, 0, // Skip to: 1335
/* 1296 */    MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 1299 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1308
/* 1304 */    MCD_OPC_Decode, 190, 3, 6, // Opcode: JEQ_sbr1
/* 1308 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1317
/* 1313 */    MCD_OPC_Decode, 218, 3, 6, // Opcode: JNE_sbr1
/* 1317 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1326
/* 1322 */    MCD_OPC_Decode, 191, 3, 6, // Opcode: JEQ_sbr2
/* 1326 */    MCD_OPC_FilterValue, 3, 4, 0, 0, // Skip to: 1335
/* 1331 */    MCD_OPC_Decode, 219, 3, 6, // Opcode: JNE_sbr2
/* 1335 */    MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTable32[] = {
/* 0 */       MCD_OPC_ExtractField, 0, 7,  // Inst{6-0} ...
/* 3 */       MCD_OPC_FilterValue, 0, 19, 0, 0, // Skip to: 27
/* 8 */       MCD_OPC_CheckField, 12, 20, 128, 104, 191, 42, 0, // Skip to: 10959
/* 16 */      MCD_OPC_CheckField, 7, 1, 0, 184, 42, 0, // Skip to: 10959
/* 23 */      MCD_OPC_Decode, 211, 6, 14, // Opcode: NOP_sys
/* 27 */      MCD_OPC_FilterValue, 1, 221, 0, 0, // Skip to: 253
/* 32 */      MCD_OPC_ExtractField, 18, 10,  // Inst{27-18} ...
/* 35 */      MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 51
/* 40 */      MCD_OPC_CheckField, 7, 1, 0, 160, 42, 0, // Skip to: 10959
/* 47 */      MCD_OPC_Decode, 192, 5, 15, // Opcode: MOV_AA_rr
/* 51 */      MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 67
/* 56 */      MCD_OPC_CheckField, 7, 1, 0, 144, 42, 0, // Skip to: 10959
/* 63 */      MCD_OPC_Decode, 150, 2, 15, // Opcode: ADD_A_rr
/* 67 */      MCD_OPC_FilterValue, 8, 11, 0, 0, // Skip to: 83
/* 72 */      MCD_OPC_CheckField, 7, 1, 0, 128, 42, 0, // Skip to: 10959
/* 79 */      MCD_OPC_Decode, 247, 7, 15, // Opcode: SUB_A_rr
/* 83 */      MCD_OPC_FilterValue, 128, 2, 11, 0, 0, // Skip to: 100
/* 89 */      MCD_OPC_CheckField, 7, 1, 0, 111, 42, 0, // Skip to: 10959
/* 96 */      MCD_OPC_Decode, 143, 3, 15, // Opcode: EQ_A_rr
/* 100 */     MCD_OPC_FilterValue, 132, 2, 11, 0, 0, // Skip to: 117
/* 106 */     MCD_OPC_CheckField, 7, 1, 0, 94, 42, 0, // Skip to: 10959
/* 113 */     MCD_OPC_Decode, 207, 6, 15, // Opcode: NE_A
/* 117 */     MCD_OPC_FilterValue, 136, 2, 11, 0, 0, // Skip to: 134
/* 123 */     MCD_OPC_CheckField, 7, 1, 0, 77, 42, 0, // Skip to: 10959
/* 130 */     MCD_OPC_Decode, 201, 4, 15, // Opcode: LT_A_rr
/* 134 */     MCD_OPC_FilterValue, 140, 2, 11, 0, 0, // Skip to: 151
/* 140 */     MCD_OPC_CheckField, 7, 1, 0, 60, 42, 0, // Skip to: 10959
/* 147 */     MCD_OPC_Decode, 162, 3, 15, // Opcode: GE_A_rr
/* 151 */     MCD_OPC_FilterValue, 160, 2, 11, 0, 0, // Skip to: 168
/* 157 */     MCD_OPC_CheckField, 7, 1, 0, 43, 42, 0, // Skip to: 10959
/* 164 */     MCD_OPC_Decode, 142, 3, 15, // Opcode: EQZ_A_rr
/* 168 */     MCD_OPC_FilterValue, 164, 2, 11, 0, 0, // Skip to: 185
/* 174 */     MCD_OPC_CheckField, 7, 1, 0, 26, 42, 0, // Skip to: 10959
/* 181 */     MCD_OPC_Decode, 206, 6, 15, // Opcode: NEZ_A
/* 185 */     MCD_OPC_FilterValue, 176, 2, 11, 0, 0, // Skip to: 202
/* 191 */     MCD_OPC_CheckField, 7, 1, 0, 9, 42, 0, // Skip to: 10959
/* 198 */     MCD_OPC_Decode, 197, 5, 15, // Opcode: MOV_D_rr
/* 202 */     MCD_OPC_FilterValue, 128, 3, 11, 0, 0, // Skip to: 219
/* 208 */     MCD_OPC_CheckField, 7, 1, 0, 248, 41, 0, // Skip to: 10959
/* 215 */     MCD_OPC_Decode, 139, 2, 15, // Opcode: ADDSC_A_rr
/* 219 */     MCD_OPC_FilterValue, 136, 3, 11, 0, 0, // Skip to: 236
/* 225 */     MCD_OPC_CheckField, 7, 1, 0, 231, 41, 0, // Skip to: 10959
/* 232 */     MCD_OPC_Decode, 138, 2, 15, // Opcode: ADDSC_AT_rr
/* 236 */     MCD_OPC_FilterValue, 140, 3, 221, 41, 0, // Skip to: 10959
/* 242 */     MCD_OPC_CheckField, 7, 1, 0, 214, 41, 0, // Skip to: 10959
/* 249 */     MCD_OPC_Decode, 194, 5, 15, // Opcode: MOV_A_rr
/* 253 */     MCD_OPC_FilterValue, 3, 248, 1, 0, // Skip to: 762
/* 258 */     MCD_OPC_ExtractField, 18, 6,  // Inst{23-18} ...
/* 261 */     MCD_OPC_FilterValue, 2, 18, 0, 0, // Skip to: 284
/* 266 */     MCD_OPC_CheckField, 16, 2, 2, 190, 41, 0, // Skip to: 10959
/* 273 */     MCD_OPC_CheckField, 7, 1, 0, 183, 41, 0, // Skip to: 10959
/* 280 */     MCD_OPC_Decode, 172, 5, 16, // Opcode: MADD_rrr2
/* 284 */     MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 300
/* 289 */     MCD_OPC_CheckField, 7, 1, 1, 167, 41, 0, // Skip to: 10959
/* 296 */     MCD_OPC_Decode, 232, 4, 17, // Opcode: MADDR_H_rrr1_UL
/* 300 */     MCD_OPC_FilterValue, 13, 11, 0, 0, // Skip to: 316
/* 305 */     MCD_OPC_CheckField, 7, 1, 1, 151, 41, 0, // Skip to: 10959
/* 312 */     MCD_OPC_Decode, 231, 4, 17, // Opcode: MADDR_H_rrr1_LU
/* 316 */     MCD_OPC_FilterValue, 14, 11, 0, 0, // Skip to: 332
/* 321 */     MCD_OPC_CheckField, 7, 1, 1, 135, 41, 0, // Skip to: 10959
/* 328 */     MCD_OPC_Decode, 230, 4, 17, // Opcode: MADDR_H_rrr1_LL
/* 332 */     MCD_OPC_FilterValue, 15, 11, 0, 0, // Skip to: 348
/* 337 */     MCD_OPC_CheckField, 7, 1, 1, 119, 41, 0, // Skip to: 10959
/* 344 */     MCD_OPC_Decode, 233, 4, 17, // Opcode: MADDR_H_rrr1_UU
/* 348 */     MCD_OPC_FilterValue, 24, 11, 0, 0, // Skip to: 364
/* 353 */     MCD_OPC_CheckField, 7, 1, 1, 103, 41, 0, // Skip to: 10959
/* 360 */     MCD_OPC_Decode, 156, 5, 17, // Opcode: MADD_H_rrr1_UL
/* 364 */     MCD_OPC_FilterValue, 25, 11, 0, 0, // Skip to: 380
/* 369 */     MCD_OPC_CheckField, 7, 1, 1, 87, 41, 0, // Skip to: 10959
/* 376 */     MCD_OPC_Decode, 155, 5, 17, // Opcode: MADD_H_rrr1_LU
/* 380 */     MCD_OPC_FilterValue, 26, 38, 0, 0, // Skip to: 423
/* 385 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 388 */     MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 414
/* 393 */     MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 396 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 405
/* 401 */     MCD_OPC_Decode, 169, 5, 16, // Opcode: MADD_U_rrr2
/* 405 */     MCD_OPC_FilterValue, 2, 53, 41, 0, // Skip to: 10959
/* 410 */     MCD_OPC_Decode, 173, 5, 16, // Opcode: MADD_rrr2_e
/* 414 */     MCD_OPC_FilterValue, 1, 44, 41, 0, // Skip to: 10959
/* 419 */     MCD_OPC_Decode, 154, 5, 17, // Opcode: MADD_H_rrr1_LL
/* 423 */     MCD_OPC_FilterValue, 27, 11, 0, 0, // Skip to: 439
/* 428 */     MCD_OPC_CheckField, 7, 1, 1, 28, 41, 0, // Skip to: 10959
/* 435 */     MCD_OPC_Decode, 157, 5, 17, // Opcode: MADD_H_rrr1_UU
/* 439 */     MCD_OPC_FilterValue, 28, 11, 0, 0, // Skip to: 455
/* 444 */     MCD_OPC_CheckField, 7, 1, 1, 12, 41, 0, // Skip to: 10959
/* 451 */     MCD_OPC_Decode, 220, 4, 17, // Opcode: MADDM_H_rrr1_UL
/* 455 */     MCD_OPC_FilterValue, 29, 11, 0, 0, // Skip to: 471
/* 460 */     MCD_OPC_CheckField, 7, 1, 1, 252, 40, 0, // Skip to: 10959
/* 467 */     MCD_OPC_Decode, 219, 4, 17, // Opcode: MADDM_H_rrr1_LU
/* 471 */     MCD_OPC_FilterValue, 30, 11, 0, 0, // Skip to: 487
/* 476 */     MCD_OPC_CheckField, 7, 1, 1, 236, 40, 0, // Skip to: 10959
/* 483 */     MCD_OPC_Decode, 218, 4, 17, // Opcode: MADDM_H_rrr1_LL
/* 487 */     MCD_OPC_FilterValue, 31, 11, 0, 0, // Skip to: 503
/* 492 */     MCD_OPC_CheckField, 7, 1, 1, 220, 40, 0, // Skip to: 10959
/* 499 */     MCD_OPC_Decode, 221, 4, 17, // Opcode: MADDM_H_rrr1_UU
/* 503 */     MCD_OPC_FilterValue, 34, 35, 0, 0, // Skip to: 543
/* 508 */     MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 511 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 527
/* 516 */     MCD_OPC_CheckField, 7, 1, 0, 196, 40, 0, // Skip to: 10959
/* 523 */     MCD_OPC_Decode, 148, 5, 16, // Opcode: MADDS_U_rrr2
/* 527 */     MCD_OPC_FilterValue, 2, 187, 40, 0, // Skip to: 10959
/* 532 */     MCD_OPC_CheckField, 7, 1, 0, 180, 40, 0, // Skip to: 10959
/* 539 */     MCD_OPC_Decode, 152, 5, 16, // Opcode: MADDS_rrr2
/* 543 */     MCD_OPC_FilterValue, 44, 11, 0, 0, // Skip to: 559
/* 548 */     MCD_OPC_CheckField, 7, 1, 1, 164, 40, 0, // Skip to: 10959
/* 555 */     MCD_OPC_Decode, 225, 4, 17, // Opcode: MADDRS_H_rrr1_UL
/* 559 */     MCD_OPC_FilterValue, 45, 11, 0, 0, // Skip to: 575
/* 564 */     MCD_OPC_CheckField, 7, 1, 1, 148, 40, 0, // Skip to: 10959
/* 571 */     MCD_OPC_Decode, 224, 4, 17, // Opcode: MADDRS_H_rrr1_LU
/* 575 */     MCD_OPC_FilterValue, 46, 11, 0, 0, // Skip to: 591
/* 580 */     MCD_OPC_CheckField, 7, 1, 1, 132, 40, 0, // Skip to: 10959
/* 587 */     MCD_OPC_Decode, 223, 4, 17, // Opcode: MADDRS_H_rrr1_LL
/* 591 */     MCD_OPC_FilterValue, 47, 11, 0, 0, // Skip to: 607
/* 596 */     MCD_OPC_CheckField, 7, 1, 1, 116, 40, 0, // Skip to: 10959
/* 603 */     MCD_OPC_Decode, 226, 4, 17, // Opcode: MADDRS_H_rrr1_UU
/* 607 */     MCD_OPC_FilterValue, 56, 11, 0, 0, // Skip to: 623
/* 612 */     MCD_OPC_CheckField, 7, 1, 1, 100, 40, 0, // Skip to: 10959
/* 619 */     MCD_OPC_Decode, 134, 5, 17, // Opcode: MADDS_H_rrr1_UL
/* 623 */     MCD_OPC_FilterValue, 57, 11, 0, 0, // Skip to: 639
/* 628 */     MCD_OPC_CheckField, 7, 1, 1, 84, 40, 0, // Skip to: 10959
/* 635 */     MCD_OPC_Decode, 133, 5, 17, // Opcode: MADDS_H_rrr1_LU
/* 639 */     MCD_OPC_FilterValue, 58, 38, 0, 0, // Skip to: 682
/* 644 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 647 */     MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 673
/* 652 */     MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 655 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 664
/* 660 */     MCD_OPC_Decode, 149, 5, 16, // Opcode: MADDS_U_rrr2_e
/* 664 */     MCD_OPC_FilterValue, 2, 50, 40, 0, // Skip to: 10959
/* 669 */     MCD_OPC_Decode, 153, 5, 16, // Opcode: MADDS_rrr2_e
/* 673 */     MCD_OPC_FilterValue, 1, 41, 40, 0, // Skip to: 10959
/* 678 */     MCD_OPC_Decode, 132, 5, 17, // Opcode: MADDS_H_rrr1_LL
/* 682 */     MCD_OPC_FilterValue, 59, 11, 0, 0, // Skip to: 698
/* 687 */     MCD_OPC_CheckField, 7, 1, 1, 25, 40, 0, // Skip to: 10959
/* 694 */     MCD_OPC_Decode, 135, 5, 17, // Opcode: MADDS_H_rrr1_UU
/* 698 */     MCD_OPC_FilterValue, 60, 11, 0, 0, // Skip to: 714
/* 703 */     MCD_OPC_CheckField, 7, 1, 1, 9, 40, 0, // Skip to: 10959
/* 710 */     MCD_OPC_Decode, 216, 4, 17, // Opcode: MADDMS_H_rrr1_UL
/* 714 */     MCD_OPC_FilterValue, 61, 11, 0, 0, // Skip to: 730
/* 719 */     MCD_OPC_CheckField, 7, 1, 1, 249, 39, 0, // Skip to: 10959
/* 726 */     MCD_OPC_Decode, 215, 4, 17, // Opcode: MADDMS_H_rrr1_LU
/* 730 */     MCD_OPC_FilterValue, 62, 11, 0, 0, // Skip to: 746
/* 735 */     MCD_OPC_CheckField, 7, 1, 1, 233, 39, 0, // Skip to: 10959
/* 742 */     MCD_OPC_Decode, 214, 4, 17, // Opcode: MADDMS_H_rrr1_LL
/* 746 */     MCD_OPC_FilterValue, 63, 224, 39, 0, // Skip to: 10959
/* 751 */     MCD_OPC_CheckField, 7, 1, 1, 217, 39, 0, // Skip to: 10959
/* 758 */     MCD_OPC_Decode, 217, 4, 17, // Opcode: MADDMS_H_rrr1_UU
/* 762 */     MCD_OPC_FilterValue, 5, 107, 0, 0, // Skip to: 874
/* 767 */     MCD_OPC_ExtractField, 26, 2,  // Inst{27-26} ...
/* 770 */     MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 796
/* 775 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 778 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 787
/* 783 */     MCD_OPC_Decode, 139, 4, 18, // Opcode: LD_B_abs
/* 787 */     MCD_OPC_FilterValue, 1, 183, 39, 0, // Skip to: 10959
/* 792 */     MCD_OPC_Decode, 182, 4, 18, // Opcode: LD_W_abs
/* 796 */     MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 822
/* 801 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 804 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 813
/* 809 */     MCD_OPC_Decode, 128, 4, 18, // Opcode: LD_BU_abs
/* 813 */     MCD_OPC_FilterValue, 1, 157, 39, 0, // Skip to: 10959
/* 818 */     MCD_OPC_Decode, 152, 4, 18, // Opcode: LD_D_abs
/* 822 */     MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 848
/* 827 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 830 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 839
/* 835 */     MCD_OPC_Decode, 165, 4, 18, // Opcode: LD_H_abs
/* 839 */     MCD_OPC_FilterValue, 1, 131, 39, 0, // Skip to: 10959
/* 844 */     MCD_OPC_Decode, 244, 3, 18, // Opcode: LD_A_abs
/* 848 */     MCD_OPC_FilterValue, 3, 122, 39, 0, // Skip to: 10959
/* 853 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 856 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 865
/* 861 */     MCD_OPC_Decode, 158, 4, 18, // Opcode: LD_HU_abs
/* 865 */     MCD_OPC_FilterValue, 1, 105, 39, 0, // Skip to: 10959
/* 870 */     MCD_OPC_Decode, 146, 4, 18, // Opcode: LD_DA_abs
/* 874 */     MCD_OPC_FilterValue, 7, 107, 0, 0, // Skip to: 986
/* 879 */     MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 882 */     MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 908
/* 887 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 890 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 899
/* 895 */     MCD_OPC_Decode, 203, 6, 19, // Opcode: NAND_T
/* 899 */     MCD_OPC_FilterValue, 1, 71, 39, 0, // Skip to: 10959
/* 904 */     MCD_OPC_Decode, 182, 2, 19, // Opcode: AND_T
/* 908 */     MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 934
/* 913 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 916 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 925
/* 921 */     MCD_OPC_Decode, 216, 6, 19, // Opcode: ORN_T
/* 925 */     MCD_OPC_FilterValue, 1, 45, 39, 0, // Skip to: 10959
/* 930 */     MCD_OPC_Decode, 235, 6, 19, // Opcode: OR_T
/* 934 */     MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 960
/* 939 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 942 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 951
/* 947 */     MCD_OPC_Decode, 144, 8, 19, // Opcode: XNOR_T
/* 951 */     MCD_OPC_FilterValue, 1, 19, 39, 0, // Skip to: 10959
/* 956 */     MCD_OPC_Decode, 212, 6, 19, // Opcode: NOR_T
/* 960 */     MCD_OPC_FilterValue, 3, 10, 39, 0, // Skip to: 10959
/* 965 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 968 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 977
/* 973 */     MCD_OPC_Decode, 159, 8, 19, // Opcode: XOR_T
/* 977 */     MCD_OPC_FilterValue, 1, 249, 38, 0, // Skip to: 10959
/* 982 */     MCD_OPC_Decode, 163, 2, 19, // Opcode: ANDN_T
/* 986 */     MCD_OPC_FilterValue, 9, 171, 3, 0, // Skip to: 1930
/* 991 */     MCD_OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 994 */     MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 1020
/* 999 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1002 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1011
/* 1007 */    MCD_OPC_Decode, 140, 4, 20, // Opcode: LD_B_bo_bso
/* 1011 */    MCD_OPC_FilterValue, 1, 215, 38, 0, // Skip to: 10959
/* 1016 */    MCD_OPC_Decode, 191, 7, 20, // Opcode: ST_B_bo_pos
/* 1020 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 1036
/* 1025 */    MCD_OPC_CheckField, 7, 1, 0, 199, 38, 0, // Skip to: 10959
/* 1032 */    MCD_OPC_Decode, 131, 4, 20, // Opcode: LD_BU_bo_pos
/* 1036 */    MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 1062
/* 1041 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1044 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1053
/* 1049 */    MCD_OPC_Decode, 168, 4, 20, // Opcode: LD_H_bo_pos
/* 1053 */    MCD_OPC_FilterValue, 1, 173, 38, 0, // Skip to: 10959
/* 1058 */    MCD_OPC_Decode, 214, 7, 20, // Opcode: ST_H_bo_pos
/* 1062 */    MCD_OPC_FilterValue, 3, 11, 0, 0, // Skip to: 1078
/* 1067 */    MCD_OPC_CheckField, 7, 1, 0, 157, 38, 0, // Skip to: 10959
/* 1074 */    MCD_OPC_Decode, 161, 4, 20, // Opcode: LD_HU_bo_pos
/* 1078 */    MCD_OPC_FilterValue, 4, 21, 0, 0, // Skip to: 1104
/* 1083 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1086 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1095
/* 1091 */    MCD_OPC_Decode, 185, 4, 20, // Opcode: LD_W_bo_pos
/* 1095 */    MCD_OPC_FilterValue, 1, 131, 38, 0, // Skip to: 10959
/* 1100 */    MCD_OPC_Decode, 232, 7, 20, // Opcode: ST_W_bo_pos
/* 1104 */    MCD_OPC_FilterValue, 5, 21, 0, 0, // Skip to: 1130
/* 1109 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1112 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1121
/* 1117 */    MCD_OPC_Decode, 155, 4, 20, // Opcode: LD_D_bo_pos
/* 1121 */    MCD_OPC_FilterValue, 1, 105, 38, 0, // Skip to: 10959
/* 1126 */    MCD_OPC_Decode, 208, 7, 20, // Opcode: ST_D_bo_pos
/* 1130 */    MCD_OPC_FilterValue, 6, 21, 0, 0, // Skip to: 1156
/* 1135 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1138 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1147
/* 1143 */    MCD_OPC_Decode, 247, 3, 20, // Opcode: LD_A_bo_pos
/* 1147 */    MCD_OPC_FilterValue, 1, 79, 38, 0, // Skip to: 10959
/* 1152 */    MCD_OPC_Decode, 179, 7, 20, // Opcode: ST_A_bo_pos
/* 1156 */    MCD_OPC_FilterValue, 7, 21, 0, 0, // Skip to: 1182
/* 1161 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1164 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1173
/* 1169 */    MCD_OPC_Decode, 149, 4, 20, // Opcode: LD_DA_bo_pos
/* 1173 */    MCD_OPC_FilterValue, 1, 53, 38, 0, // Skip to: 10959
/* 1178 */    MCD_OPC_Decode, 202, 7, 20, // Opcode: ST_DA_bo_pos
/* 1182 */    MCD_OPC_FilterValue, 8, 21, 0, 0, // Skip to: 1208
/* 1187 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1190 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1199
/* 1195 */    MCD_OPC_Decode, 179, 4, 20, // Opcode: LD_Q_bo_pos
/* 1199 */    MCD_OPC_FilterValue, 1, 27, 38, 0, // Skip to: 10959
/* 1204 */    MCD_OPC_Decode, 225, 7, 20, // Opcode: ST_Q_bo_pos
/* 1208 */    MCD_OPC_FilterValue, 10, 11, 0, 0, // Skip to: 1224
/* 1213 */    MCD_OPC_CheckField, 7, 1, 1, 11, 38, 0, // Skip to: 10959
/* 1220 */    MCD_OPC_Decode, 192, 2, 20, // Opcode: CACHEI_I_bo_pos
/* 1224 */    MCD_OPC_FilterValue, 11, 11, 0, 0, // Skip to: 1240
/* 1229 */    MCD_OPC_CheckField, 7, 1, 1, 251, 37, 0, // Skip to: 10959
/* 1236 */    MCD_OPC_Decode, 199, 2, 20, // Opcode: CACHEI_W_bo_pos
/* 1240 */    MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 1256
/* 1245 */    MCD_OPC_CheckField, 7, 1, 1, 235, 37, 0, // Skip to: 10959
/* 1252 */    MCD_OPC_Decode, 214, 2, 20, // Opcode: CACHE_W_bo_pos
/* 1256 */    MCD_OPC_FilterValue, 13, 11, 0, 0, // Skip to: 1272
/* 1261 */    MCD_OPC_CheckField, 7, 1, 1, 219, 37, 0, // Skip to: 10959
/* 1268 */    MCD_OPC_Decode, 209, 2, 20, // Opcode: CACHE_WI_bo_pos
/* 1272 */    MCD_OPC_FilterValue, 14, 11, 0, 0, // Skip to: 1288
/* 1277 */    MCD_OPC_CheckField, 7, 1, 1, 203, 37, 0, // Skip to: 10959
/* 1284 */    MCD_OPC_Decode, 204, 2, 20, // Opcode: CACHE_I_bo_pos
/* 1288 */    MCD_OPC_FilterValue, 15, 11, 0, 0, // Skip to: 1304
/* 1293 */    MCD_OPC_CheckField, 7, 1, 1, 187, 37, 0, // Skip to: 10959
/* 1300 */    MCD_OPC_Decode, 195, 2, 20, // Opcode: CACHEI_WI_bo_pos
/* 1304 */    MCD_OPC_FilterValue, 16, 21, 0, 0, // Skip to: 1330
/* 1309 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1312 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1321
/* 1317 */    MCD_OPC_Decode, 142, 4, 20, // Opcode: LD_B_bo_pos
/* 1321 */    MCD_OPC_FilterValue, 1, 161, 37, 0, // Skip to: 10959
/* 1326 */    MCD_OPC_Decode, 192, 7, 20, // Opcode: ST_B_bo_pre
/* 1330 */    MCD_OPC_FilterValue, 17, 11, 0, 0, // Skip to: 1346
/* 1335 */    MCD_OPC_CheckField, 7, 1, 0, 145, 37, 0, // Skip to: 10959
/* 1342 */    MCD_OPC_Decode, 132, 4, 20, // Opcode: LD_BU_bo_pre
/* 1346 */    MCD_OPC_FilterValue, 18, 21, 0, 0, // Skip to: 1372
/* 1351 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1354 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1363
/* 1359 */    MCD_OPC_Decode, 169, 4, 20, // Opcode: LD_H_bo_pre
/* 1363 */    MCD_OPC_FilterValue, 1, 119, 37, 0, // Skip to: 10959
/* 1368 */    MCD_OPC_Decode, 215, 7, 20, // Opcode: ST_H_bo_pre
/* 1372 */    MCD_OPC_FilterValue, 19, 11, 0, 0, // Skip to: 1388
/* 1377 */    MCD_OPC_CheckField, 7, 1, 0, 103, 37, 0, // Skip to: 10959
/* 1384 */    MCD_OPC_Decode, 162, 4, 20, // Opcode: LD_HU_bo_pre
/* 1388 */    MCD_OPC_FilterValue, 20, 21, 0, 0, // Skip to: 1414
/* 1393 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1396 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1405
/* 1401 */    MCD_OPC_Decode, 186, 4, 20, // Opcode: LD_W_bo_pre
/* 1405 */    MCD_OPC_FilterValue, 1, 77, 37, 0, // Skip to: 10959
/* 1410 */    MCD_OPC_Decode, 233, 7, 20, // Opcode: ST_W_bo_pre
/* 1414 */    MCD_OPC_FilterValue, 21, 21, 0, 0, // Skip to: 1440
/* 1419 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1422 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1431
/* 1427 */    MCD_OPC_Decode, 156, 4, 20, // Opcode: LD_D_bo_pre
/* 1431 */    MCD_OPC_FilterValue, 1, 51, 37, 0, // Skip to: 10959
/* 1436 */    MCD_OPC_Decode, 209, 7, 20, // Opcode: ST_D_bo_pre
/* 1440 */    MCD_OPC_FilterValue, 22, 21, 0, 0, // Skip to: 1466
/* 1445 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1448 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1457
/* 1453 */    MCD_OPC_Decode, 248, 3, 20, // Opcode: LD_A_bo_pre
/* 1457 */    MCD_OPC_FilterValue, 1, 25, 37, 0, // Skip to: 10959
/* 1462 */    MCD_OPC_Decode, 180, 7, 20, // Opcode: ST_A_bo_pre
/* 1466 */    MCD_OPC_FilterValue, 23, 21, 0, 0, // Skip to: 1492
/* 1471 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1474 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1483
/* 1479 */    MCD_OPC_Decode, 150, 4, 20, // Opcode: LD_DA_bo_pre
/* 1483 */    MCD_OPC_FilterValue, 1, 255, 36, 0, // Skip to: 10959
/* 1488 */    MCD_OPC_Decode, 203, 7, 20, // Opcode: ST_DA_bo_pre
/* 1492 */    MCD_OPC_FilterValue, 24, 21, 0, 0, // Skip to: 1518
/* 1497 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1500 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1509
/* 1505 */    MCD_OPC_Decode, 180, 4, 20, // Opcode: LD_Q_bo_pre
/* 1509 */    MCD_OPC_FilterValue, 1, 229, 36, 0, // Skip to: 10959
/* 1514 */    MCD_OPC_Decode, 226, 7, 20, // Opcode: ST_Q_bo_pre
/* 1518 */    MCD_OPC_FilterValue, 26, 11, 0, 0, // Skip to: 1534
/* 1523 */    MCD_OPC_CheckField, 7, 1, 1, 213, 36, 0, // Skip to: 10959
/* 1530 */    MCD_OPC_Decode, 193, 2, 20, // Opcode: CACHEI_I_bo_pre
/* 1534 */    MCD_OPC_FilterValue, 27, 11, 0, 0, // Skip to: 1550
/* 1539 */    MCD_OPC_CheckField, 7, 1, 1, 197, 36, 0, // Skip to: 10959
/* 1546 */    MCD_OPC_Decode, 200, 2, 20, // Opcode: CACHEI_W_bo_pre
/* 1550 */    MCD_OPC_FilterValue, 28, 11, 0, 0, // Skip to: 1566
/* 1555 */    MCD_OPC_CheckField, 7, 1, 1, 181, 36, 0, // Skip to: 10959
/* 1562 */    MCD_OPC_Decode, 215, 2, 20, // Opcode: CACHE_W_bo_pre
/* 1566 */    MCD_OPC_FilterValue, 29, 11, 0, 0, // Skip to: 1582
/* 1571 */    MCD_OPC_CheckField, 7, 1, 1, 165, 36, 0, // Skip to: 10959
/* 1578 */    MCD_OPC_Decode, 210, 2, 20, // Opcode: CACHE_WI_bo_pre
/* 1582 */    MCD_OPC_FilterValue, 30, 11, 0, 0, // Skip to: 1598
/* 1587 */    MCD_OPC_CheckField, 7, 1, 1, 149, 36, 0, // Skip to: 10959
/* 1594 */    MCD_OPC_Decode, 205, 2, 20, // Opcode: CACHE_I_bo_pre
/* 1598 */    MCD_OPC_FilterValue, 31, 11, 0, 0, // Skip to: 1614
/* 1603 */    MCD_OPC_CheckField, 7, 1, 1, 133, 36, 0, // Skip to: 10959
/* 1610 */    MCD_OPC_Decode, 196, 2, 20, // Opcode: CACHEI_WI_bo_pre
/* 1614 */    MCD_OPC_FilterValue, 32, 11, 0, 0, // Skip to: 1630
/* 1619 */    MCD_OPC_CheckField, 7, 1, 1, 117, 36, 0, // Skip to: 10959
/* 1626 */    MCD_OPC_Decode, 189, 7, 20, // Opcode: ST_B_bo_bso
/* 1630 */    MCD_OPC_FilterValue, 33, 11, 0, 0, // Skip to: 1646
/* 1635 */    MCD_OPC_CheckField, 7, 1, 0, 101, 36, 0, // Skip to: 10959
/* 1642 */    MCD_OPC_Decode, 129, 4, 20, // Opcode: LD_BU_bo_bso
/* 1646 */    MCD_OPC_FilterValue, 34, 21, 0, 0, // Skip to: 1672
/* 1651 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1654 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1663
/* 1659 */    MCD_OPC_Decode, 166, 4, 20, // Opcode: LD_H_bo_bso
/* 1663 */    MCD_OPC_FilterValue, 1, 75, 36, 0, // Skip to: 10959
/* 1668 */    MCD_OPC_Decode, 212, 7, 20, // Opcode: ST_H_bo_bso
/* 1672 */    MCD_OPC_FilterValue, 35, 11, 0, 0, // Skip to: 1688
/* 1677 */    MCD_OPC_CheckField, 7, 1, 0, 59, 36, 0, // Skip to: 10959
/* 1684 */    MCD_OPC_Decode, 159, 4, 20, // Opcode: LD_HU_bo_bso
/* 1688 */    MCD_OPC_FilterValue, 36, 21, 0, 0, // Skip to: 1714
/* 1693 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1696 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1705
/* 1701 */    MCD_OPC_Decode, 183, 4, 20, // Opcode: LD_W_bo_bso
/* 1705 */    MCD_OPC_FilterValue, 1, 33, 36, 0, // Skip to: 10959
/* 1710 */    MCD_OPC_Decode, 230, 7, 20, // Opcode: ST_W_bo_bso
/* 1714 */    MCD_OPC_FilterValue, 37, 21, 0, 0, // Skip to: 1740
/* 1719 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1722 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1731
/* 1727 */    MCD_OPC_Decode, 153, 4, 20, // Opcode: LD_D_bo_bso
/* 1731 */    MCD_OPC_FilterValue, 1, 7, 36, 0, // Skip to: 10959
/* 1736 */    MCD_OPC_Decode, 206, 7, 20, // Opcode: ST_D_bo_bso
/* 1740 */    MCD_OPC_FilterValue, 38, 21, 0, 0, // Skip to: 1766
/* 1745 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1748 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1757
/* 1753 */    MCD_OPC_Decode, 245, 3, 20, // Opcode: LD_A_bo_bso
/* 1757 */    MCD_OPC_FilterValue, 1, 237, 35, 0, // Skip to: 10959
/* 1762 */    MCD_OPC_Decode, 177, 7, 20, // Opcode: ST_A_bo_bso
/* 1766 */    MCD_OPC_FilterValue, 39, 21, 0, 0, // Skip to: 1792
/* 1771 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1774 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1783
/* 1779 */    MCD_OPC_Decode, 147, 4, 20, // Opcode: LD_DA_bo_bso
/* 1783 */    MCD_OPC_FilterValue, 1, 211, 35, 0, // Skip to: 10959
/* 1788 */    MCD_OPC_Decode, 200, 7, 20, // Opcode: ST_DA_bo_bso
/* 1792 */    MCD_OPC_FilterValue, 40, 21, 0, 0, // Skip to: 1818
/* 1797 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1800 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1809
/* 1805 */    MCD_OPC_Decode, 177, 4, 20, // Opcode: LD_Q_bo_bso
/* 1809 */    MCD_OPC_FilterValue, 1, 185, 35, 0, // Skip to: 10959
/* 1814 */    MCD_OPC_Decode, 223, 7, 20, // Opcode: ST_Q_bo_bso
/* 1818 */    MCD_OPC_FilterValue, 41, 11, 0, 0, // Skip to: 1834
/* 1823 */    MCD_OPC_CheckField, 7, 1, 0, 169, 35, 0, // Skip to: 10959
/* 1830 */    MCD_OPC_Decode, 143, 4, 20, // Opcode: LD_B_bo_pre
/* 1834 */    MCD_OPC_FilterValue, 42, 11, 0, 0, // Skip to: 1850
/* 1839 */    MCD_OPC_CheckField, 7, 1, 1, 153, 35, 0, // Skip to: 10959
/* 1846 */    MCD_OPC_Decode, 191, 2, 20, // Opcode: CACHEI_I_bo_bso
/* 1850 */    MCD_OPC_FilterValue, 43, 11, 0, 0, // Skip to: 1866
/* 1855 */    MCD_OPC_CheckField, 7, 1, 1, 137, 35, 0, // Skip to: 10959
/* 1862 */    MCD_OPC_Decode, 197, 2, 20, // Opcode: CACHEI_W_bo_bso
/* 1866 */    MCD_OPC_FilterValue, 44, 11, 0, 0, // Skip to: 1882
/* 1871 */    MCD_OPC_CheckField, 7, 1, 1, 121, 35, 0, // Skip to: 10959
/* 1878 */    MCD_OPC_Decode, 212, 2, 20, // Opcode: CACHE_W_bo_bso
/* 1882 */    MCD_OPC_FilterValue, 45, 11, 0, 0, // Skip to: 1898
/* 1887 */    MCD_OPC_CheckField, 7, 1, 1, 105, 35, 0, // Skip to: 10959
/* 1894 */    MCD_OPC_Decode, 207, 2, 20, // Opcode: CACHE_WI_bo_bso
/* 1898 */    MCD_OPC_FilterValue, 46, 11, 0, 0, // Skip to: 1914
/* 1903 */    MCD_OPC_CheckField, 7, 1, 1, 89, 35, 0, // Skip to: 10959
/* 1910 */    MCD_OPC_Decode, 202, 2, 20, // Opcode: CACHE_I_bo_bso
/* 1914 */    MCD_OPC_FilterValue, 47, 80, 35, 0, // Skip to: 10959
/* 1919 */    MCD_OPC_CheckField, 7, 1, 1, 73, 35, 0, // Skip to: 10959
/* 1926 */    MCD_OPC_Decode, 194, 2, 20, // Opcode: CACHEI_WI_bo_bso
/* 1930 */    MCD_OPC_FilterValue, 11, 147, 8, 0, // Skip to: 4130
/* 1935 */    MCD_OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 1938 */    MCD_OPC_FilterValue, 0, 81, 0, 0, // Skip to: 2024
/* 1943 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1946 */    MCD_OPC_FilterValue, 0, 64, 0, 0, // Skip to: 2015
/* 1951 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 1954 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1963
/* 1959 */    MCD_OPC_Decode, 156, 2, 15, // Opcode: ADD_rr
/* 1963 */    MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 1989
/* 1968 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 1971 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1980
/* 1976 */    MCD_OPC_Decode, 244, 7, 21, // Opcode: SUBS_rr
/* 1980 */    MCD_OPC_FilterValue, 3, 14, 35, 0, // Skip to: 10959
/* 1985 */    MCD_OPC_Decode, 243, 7, 21, // Opcode: SUBS_U_rr
/* 1989 */    MCD_OPC_FilterValue, 3, 5, 35, 0, // Skip to: 10959
/* 1994 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 1997 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2006
/* 2002 */    MCD_OPC_Decode, 246, 7, 21, // Opcode: SUBX_rr
/* 2006 */    MCD_OPC_FilterValue, 1, 244, 34, 0, // Skip to: 10959
/* 2011 */    MCD_OPC_Decode, 240, 7, 21, // Opcode: SUBC_rr
/* 2015 */    MCD_OPC_FilterValue, 1, 235, 34, 0, // Skip to: 10959
/* 2020 */    MCD_OPC_Decode, 155, 2, 22, // Opcode: ADD_rc
/* 2024 */    MCD_OPC_FilterValue, 1, 35, 0, 0, // Skip to: 2064
/* 2029 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2032 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2048
/* 2037 */    MCD_OPC_CheckField, 7, 1, 0, 211, 34, 0, // Skip to: 10959
/* 2044 */    MCD_OPC_Decode, 146, 2, 15, // Opcode: ADDS_rr
/* 2048 */    MCD_OPC_FilterValue, 4, 202, 34, 0, // Skip to: 10959
/* 2053 */    MCD_OPC_CheckField, 7, 1, 0, 195, 34, 0, // Skip to: 10959
/* 2060 */    MCD_OPC_Decode, 143, 2, 15, // Opcode: ADDS_U
/* 2064 */    MCD_OPC_FilterValue, 2, 38, 0, 0, // Skip to: 2107
/* 2069 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2072 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2098
/* 2077 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2080 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2089
/* 2085 */    MCD_OPC_Decode, 149, 2, 15, // Opcode: ADDX_rr
/* 2089 */    MCD_OPC_FilterValue, 4, 161, 34, 0, // Skip to: 10959
/* 2094 */    MCD_OPC_Decode, 134, 2, 15, // Opcode: ADDC_rr
/* 2098 */    MCD_OPC_FilterValue, 1, 152, 34, 0, // Skip to: 10959
/* 2103 */    MCD_OPC_Decode, 145, 2, 22, // Opcode: ADDS_rc
/* 2107 */    MCD_OPC_FilterValue, 3, 38, 0, 0, // Skip to: 2150
/* 2112 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2115 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2141
/* 2120 */    MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 2123 */    MCD_OPC_FilterValue, 10, 4, 0, 0, // Skip to: 2132
/* 2128 */    MCD_OPC_Decode, 242, 7, 21, // Opcode: SUBS_H_rr
/* 2132 */    MCD_OPC_FilterValue, 11, 118, 34, 0, // Skip to: 10959
/* 2137 */    MCD_OPC_Decode, 241, 7, 21, // Opcode: SUBS_HU_rr
/* 2141 */    MCD_OPC_FilterValue, 1, 109, 34, 0, // Skip to: 10959
/* 2146 */    MCD_OPC_Decode, 144, 2, 22, // Opcode: ADDS_U_rc
/* 2150 */    MCD_OPC_FilterValue, 4, 28, 0, 0, // Skip to: 2183
/* 2155 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2158 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2174
/* 2163 */    MCD_OPC_CheckField, 18, 3, 0, 85, 34, 0, // Skip to: 10959
/* 2170 */    MCD_OPC_Decode, 251, 7, 15, // Opcode: SUB_rr
/* 2174 */    MCD_OPC_FilterValue, 1, 76, 34, 0, // Skip to: 10959
/* 2179 */    MCD_OPC_Decode, 148, 2, 22, // Opcode: ADDX_rc
/* 2183 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 2199
/* 2188 */    MCD_OPC_CheckField, 7, 1, 1, 60, 34, 0, // Skip to: 10959
/* 2195 */    MCD_OPC_Decode, 133, 2, 22, // Opcode: ADDC_rc
/* 2199 */    MCD_OPC_FilterValue, 7, 35, 0, 0, // Skip to: 2239
/* 2204 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2207 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2223
/* 2212 */    MCD_OPC_CheckField, 7, 1, 0, 36, 34, 0, // Skip to: 10959
/* 2219 */    MCD_OPC_Decode, 255, 1, 15, // Opcode: ABSDIF_rr
/* 2223 */    MCD_OPC_FilterValue, 4, 27, 34, 0, // Skip to: 10959
/* 2228 */    MCD_OPC_CheckField, 7, 1, 0, 20, 34, 0, // Skip to: 10959
/* 2235 */    MCD_OPC_Decode, 251, 1, 15, // Opcode: ABSDIFS_rr
/* 2239 */    MCD_OPC_FilterValue, 8, 38, 0, 0, // Skip to: 2282
/* 2244 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2247 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2273
/* 2252 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2255 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2264
/* 2260 */    MCD_OPC_Decode, 148, 3, 15, // Opcode: EQ_rr
/* 2264 */    MCD_OPC_FilterValue, 4, 242, 33, 0, // Skip to: 10959
/* 2269 */    MCD_OPC_Decode, 209, 6, 15, // Opcode: NE_rr
/* 2273 */    MCD_OPC_FilterValue, 1, 233, 33, 0, // Skip to: 10959
/* 2278 */    MCD_OPC_Decode, 253, 6, 22, // Opcode: RSUB_rc
/* 2282 */    MCD_OPC_FilterValue, 9, 35, 0, 0, // Skip to: 2322
/* 2287 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2290 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2306
/* 2295 */    MCD_OPC_CheckField, 7, 1, 0, 209, 33, 0, // Skip to: 10959
/* 2302 */    MCD_OPC_Decode, 211, 4, 15, // Opcode: LT_rr
/* 2306 */    MCD_OPC_FilterValue, 4, 200, 33, 0, // Skip to: 10959
/* 2311 */    MCD_OPC_CheckField, 7, 1, 0, 193, 33, 0, // Skip to: 10959
/* 2318 */    MCD_OPC_Decode, 207, 4, 15, // Opcode: LT_U_rr
/* 2322 */    MCD_OPC_FilterValue, 10, 38, 0, 0, // Skip to: 2365
/* 2327 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2330 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2356
/* 2335 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2338 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2347
/* 2343 */    MCD_OPC_Decode, 166, 3, 15, // Opcode: GE_rr
/* 2347 */    MCD_OPC_FilterValue, 4, 159, 33, 0, // Skip to: 10959
/* 2352 */    MCD_OPC_Decode, 164, 3, 15, // Opcode: GE_U_rr
/* 2356 */    MCD_OPC_FilterValue, 1, 150, 33, 0, // Skip to: 10959
/* 2361 */    MCD_OPC_Decode, 252, 6, 22, // Opcode: RSUBS_rc
/* 2365 */    MCD_OPC_FilterValue, 11, 11, 0, 0, // Skip to: 2381
/* 2370 */    MCD_OPC_CheckField, 7, 1, 1, 134, 33, 0, // Skip to: 10959
/* 2377 */    MCD_OPC_Decode, 251, 6, 22, // Opcode: RSUBS_U_rc
/* 2381 */    MCD_OPC_FilterValue, 12, 35, 0, 0, // Skip to: 2421
/* 2386 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2389 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2405
/* 2394 */    MCD_OPC_CheckField, 7, 1, 0, 110, 33, 0, // Skip to: 10959
/* 2401 */    MCD_OPC_Decode, 190, 5, 15, // Opcode: MIN_rr
/* 2405 */    MCD_OPC_FilterValue, 4, 101, 33, 0, // Skip to: 10959
/* 2410 */    MCD_OPC_CheckField, 7, 1, 0, 94, 33, 0, // Skip to: 10959
/* 2417 */    MCD_OPC_Decode, 188, 5, 15, // Opcode: MIN_U_rr
/* 2421 */    MCD_OPC_FilterValue, 13, 35, 0, 0, // Skip to: 2461
/* 2426 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2429 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2445
/* 2434 */    MCD_OPC_CheckField, 7, 1, 0, 70, 33, 0, // Skip to: 10959
/* 2441 */    MCD_OPC_Decode, 181, 5, 15, // Opcode: MAX_rr
/* 2445 */    MCD_OPC_FilterValue, 4, 61, 33, 0, // Skip to: 10959
/* 2450 */    MCD_OPC_CheckField, 7, 1, 0, 54, 33, 0, // Skip to: 10959
/* 2457 */    MCD_OPC_Decode, 179, 5, 15, // Opcode: MAX_U_rr
/* 2461 */    MCD_OPC_FilterValue, 14, 38, 0, 0, // Skip to: 2504
/* 2466 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2469 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2495
/* 2474 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2477 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2486
/* 2482 */    MCD_OPC_Decode, 132, 2, 15, // Opcode: ABS_rr
/* 2486 */    MCD_OPC_FilterValue, 4, 20, 33, 0, // Skip to: 10959
/* 2491 */    MCD_OPC_Decode, 129, 2, 15, // Opcode: ABSS_rr
/* 2495 */    MCD_OPC_FilterValue, 1, 11, 33, 0, // Skip to: 10959
/* 2500 */    MCD_OPC_Decode, 254, 1, 22, // Opcode: ABSDIF_rc
/* 2504 */    MCD_OPC_FilterValue, 15, 28, 0, 0, // Skip to: 2537
/* 2509 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2512 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2528
/* 2517 */    MCD_OPC_CheckField, 18, 3, 4, 243, 32, 0, // Skip to: 10959
/* 2524 */    MCD_OPC_Decode, 203, 5, 15, // Opcode: MOV_rrDcDb
/* 2528 */    MCD_OPC_FilterValue, 1, 234, 32, 0, // Skip to: 10959
/* 2533 */    MCD_OPC_Decode, 250, 1, 22, // Opcode: ABSDIFS_rc
/* 2537 */    MCD_OPC_FilterValue, 16, 38, 0, 0, // Skip to: 2580
/* 2542 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2545 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2571
/* 2550 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2553 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2562
/* 2558 */    MCD_OPC_Decode, 169, 2, 15, // Opcode: AND_EQ_rr
/* 2562 */    MCD_OPC_FilterValue, 4, 200, 32, 0, // Skip to: 10959
/* 2567 */    MCD_OPC_Decode, 179, 2, 15, // Opcode: AND_NE_rr
/* 2571 */    MCD_OPC_FilterValue, 1, 191, 32, 0, // Skip to: 10959
/* 2576 */    MCD_OPC_Decode, 147, 3, 22, // Opcode: EQ_rc
/* 2580 */    MCD_OPC_FilterValue, 17, 38, 0, 0, // Skip to: 2623
/* 2585 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2588 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2614
/* 2593 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2596 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2605
/* 2601 */    MCD_OPC_Decode, 177, 2, 15, // Opcode: AND_LT_rr
/* 2605 */    MCD_OPC_FilterValue, 4, 157, 32, 0, // Skip to: 10959
/* 2610 */    MCD_OPC_Decode, 175, 2, 15, // Opcode: AND_LT_U_rr
/* 2614 */    MCD_OPC_FilterValue, 1, 148, 32, 0, // Skip to: 10959
/* 2619 */    MCD_OPC_Decode, 208, 6, 22, // Opcode: NE_rc
/* 2623 */    MCD_OPC_FilterValue, 18, 38, 0, 0, // Skip to: 2666
/* 2628 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2631 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2657
/* 2636 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2639 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2648
/* 2644 */    MCD_OPC_Decode, 173, 2, 15, // Opcode: AND_GE_rr
/* 2648 */    MCD_OPC_FilterValue, 4, 114, 32, 0, // Skip to: 10959
/* 2653 */    MCD_OPC_Decode, 171, 2, 15, // Opcode: AND_GE_U_rr
/* 2657 */    MCD_OPC_FilterValue, 1, 105, 32, 0, // Skip to: 10959
/* 2662 */    MCD_OPC_Decode, 210, 4, 22, // Opcode: LT_rc
/* 2666 */    MCD_OPC_FilterValue, 19, 28, 0, 0, // Skip to: 2699
/* 2671 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2674 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2690
/* 2679 */    MCD_OPC_CheckField, 18, 3, 4, 81, 32, 0, // Skip to: 10959
/* 2686 */    MCD_OPC_Decode, 222, 6, 15, // Opcode: OR_EQ_rr
/* 2690 */    MCD_OPC_FilterValue, 1, 72, 32, 0, // Skip to: 10959
/* 2695 */    MCD_OPC_Decode, 206, 4, 22, // Opcode: LT_U_rc
/* 2699 */    MCD_OPC_FilterValue, 20, 38, 0, 0, // Skip to: 2742
/* 2704 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2707 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2733
/* 2712 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2715 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2724
/* 2720 */    MCD_OPC_Decode, 232, 6, 15, // Opcode: OR_NE_rr
/* 2724 */    MCD_OPC_FilterValue, 4, 38, 32, 0, // Skip to: 10959
/* 2729 */    MCD_OPC_Decode, 230, 6, 15, // Opcode: OR_LT_rr
/* 2733 */    MCD_OPC_FilterValue, 1, 29, 32, 0, // Skip to: 10959
/* 2738 */    MCD_OPC_Decode, 165, 3, 22, // Opcode: GE_rc
/* 2742 */    MCD_OPC_FilterValue, 21, 38, 0, 0, // Skip to: 2785
/* 2747 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2750 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2776
/* 2755 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2758 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2767
/* 2763 */    MCD_OPC_Decode, 228, 6, 15, // Opcode: OR_LT_U_rr
/* 2767 */    MCD_OPC_FilterValue, 4, 251, 31, 0, // Skip to: 10959
/* 2772 */    MCD_OPC_Decode, 226, 6, 15, // Opcode: OR_GE_rr
/* 2776 */    MCD_OPC_FilterValue, 1, 242, 31, 0, // Skip to: 10959
/* 2781 */    MCD_OPC_Decode, 163, 3, 22, // Opcode: GE_U_rc
/* 2785 */    MCD_OPC_FilterValue, 22, 18, 0, 0, // Skip to: 2808
/* 2790 */    MCD_OPC_CheckField, 18, 3, 0, 226, 31, 0, // Skip to: 10959
/* 2797 */    MCD_OPC_CheckField, 7, 1, 0, 219, 31, 0, // Skip to: 10959
/* 2804 */    MCD_OPC_Decode, 224, 6, 15, // Opcode: OR_GE_U_rr
/* 2808 */    MCD_OPC_FilterValue, 23, 18, 0, 0, // Skip to: 2831
/* 2813 */    MCD_OPC_CheckField, 18, 3, 4, 203, 31, 0, // Skip to: 10959
/* 2820 */    MCD_OPC_CheckField, 7, 1, 0, 196, 31, 0, // Skip to: 10959
/* 2827 */    MCD_OPC_Decode, 148, 8, 15, // Opcode: XOR_EQ_rr
/* 2831 */    MCD_OPC_FilterValue, 24, 38, 0, 0, // Skip to: 2874
/* 2836 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2839 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2865
/* 2844 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2847 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2856
/* 2852 */    MCD_OPC_Decode, 158, 8, 15, // Opcode: XOR_NE_rr
/* 2856 */    MCD_OPC_FilterValue, 4, 162, 31, 0, // Skip to: 10959
/* 2861 */    MCD_OPC_Decode, 156, 8, 15, // Opcode: XOR_LT_rr
/* 2865 */    MCD_OPC_FilterValue, 1, 153, 31, 0, // Skip to: 10959
/* 2870 */    MCD_OPC_Decode, 189, 5, 22, // Opcode: MIN_rc
/* 2874 */    MCD_OPC_FilterValue, 25, 38, 0, 0, // Skip to: 2917
/* 2879 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2882 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2908
/* 2887 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2890 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2899
/* 2895 */    MCD_OPC_Decode, 154, 8, 15, // Opcode: XOR_LT_U_rr
/* 2899 */    MCD_OPC_FilterValue, 4, 119, 31, 0, // Skip to: 10959
/* 2904 */    MCD_OPC_Decode, 152, 8, 15, // Opcode: XOR_GE_rr
/* 2908 */    MCD_OPC_FilterValue, 1, 110, 31, 0, // Skip to: 10959
/* 2913 */    MCD_OPC_Decode, 187, 5, 22, // Opcode: MIN_U_rc
/* 2917 */    MCD_OPC_FilterValue, 26, 28, 0, 0, // Skip to: 2950
/* 2922 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2925 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2941
/* 2930 */    MCD_OPC_CheckField, 18, 3, 0, 86, 31, 0, // Skip to: 10959
/* 2937 */    MCD_OPC_Decode, 150, 8, 15, // Opcode: XOR_GE_U_rr
/* 2941 */    MCD_OPC_FilterValue, 1, 77, 31, 0, // Skip to: 10959
/* 2946 */    MCD_OPC_Decode, 180, 5, 22, // Opcode: MAX_rc
/* 2950 */    MCD_OPC_FilterValue, 27, 28, 0, 0, // Skip to: 2983
/* 2955 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2958 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2974
/* 2963 */    MCD_OPC_CheckField, 18, 3, 4, 53, 31, 0, // Skip to: 10959
/* 2970 */    MCD_OPC_Decode, 150, 7, 15, // Opcode: SH_EQ_rr
/* 2974 */    MCD_OPC_FilterValue, 1, 44, 31, 0, // Skip to: 10959
/* 2979 */    MCD_OPC_Decode, 178, 5, 22, // Opcode: MAX_U_rc
/* 2983 */    MCD_OPC_FilterValue, 28, 35, 0, 0, // Skip to: 3023
/* 2988 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2991 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3007
/* 2996 */    MCD_OPC_CheckField, 7, 1, 0, 20, 31, 0, // Skip to: 10959
/* 3003 */    MCD_OPC_Decode, 163, 7, 15, // Opcode: SH_NE_rr
/* 3007 */    MCD_OPC_FilterValue, 4, 11, 31, 0, // Skip to: 10959
/* 3012 */    MCD_OPC_CheckField, 7, 1, 0, 4, 31, 0, // Skip to: 10959
/* 3019 */    MCD_OPC_Decode, 160, 7, 15, // Opcode: SH_LT_rr
/* 3023 */    MCD_OPC_FilterValue, 29, 35, 0, 0, // Skip to: 3063
/* 3028 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3031 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3047
/* 3036 */    MCD_OPC_CheckField, 7, 1, 0, 236, 30, 0, // Skip to: 10959
/* 3043 */    MCD_OPC_Decode, 158, 7, 15, // Opcode: SH_LT_U_rr
/* 3047 */    MCD_OPC_FilterValue, 4, 227, 30, 0, // Skip to: 10959
/* 3052 */    MCD_OPC_CheckField, 7, 1, 0, 220, 30, 0, // Skip to: 10959
/* 3059 */    MCD_OPC_Decode, 154, 7, 15, // Opcode: SH_GE_rr
/* 3063 */    MCD_OPC_FilterValue, 30, 18, 0, 0, // Skip to: 3086
/* 3068 */    MCD_OPC_CheckField, 18, 3, 0, 204, 30, 0, // Skip to: 10959
/* 3075 */    MCD_OPC_CheckField, 7, 1, 0, 197, 30, 0, // Skip to: 10959
/* 3082 */    MCD_OPC_Decode, 152, 7, 15, // Opcode: SH_GE_U_rr
/* 3086 */    MCD_OPC_FilterValue, 32, 28, 0, 0, // Skip to: 3119
/* 3091 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3094 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3110
/* 3099 */    MCD_OPC_CheckField, 18, 3, 0, 173, 30, 0, // Skip to: 10959
/* 3106 */    MCD_OPC_Decode, 153, 2, 15, // Opcode: ADD_B_rr
/* 3110 */    MCD_OPC_FilterValue, 1, 164, 30, 0, // Skip to: 10959
/* 3115 */    MCD_OPC_Decode, 168, 2, 22, // Opcode: AND_EQ_rc
/* 3119 */    MCD_OPC_FilterValue, 33, 11, 0, 0, // Skip to: 3135
/* 3124 */    MCD_OPC_CheckField, 7, 1, 1, 148, 30, 0, // Skip to: 10959
/* 3131 */    MCD_OPC_Decode, 178, 2, 22, // Opcode: AND_NE_rc
/* 3135 */    MCD_OPC_FilterValue, 34, 11, 0, 0, // Skip to: 3151
/* 3140 */    MCD_OPC_CheckField, 7, 1, 1, 132, 30, 0, // Skip to: 10959
/* 3147 */    MCD_OPC_Decode, 176, 2, 22, // Opcode: AND_LT_rc
/* 3151 */    MCD_OPC_FilterValue, 35, 11, 0, 0, // Skip to: 3167
/* 3156 */    MCD_OPC_CheckField, 7, 1, 1, 116, 30, 0, // Skip to: 10959
/* 3163 */    MCD_OPC_Decode, 174, 2, 22, // Opcode: AND_LT_U_rc
/* 3167 */    MCD_OPC_FilterValue, 36, 28, 0, 0, // Skip to: 3200
/* 3172 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3175 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3191
/* 3180 */    MCD_OPC_CheckField, 18, 3, 0, 92, 30, 0, // Skip to: 10959
/* 3187 */    MCD_OPC_Decode, 249, 7, 15, // Opcode: SUB_B_rr
/* 3191 */    MCD_OPC_FilterValue, 1, 83, 30, 0, // Skip to: 10959
/* 3196 */    MCD_OPC_Decode, 172, 2, 22, // Opcode: AND_GE_rc
/* 3200 */    MCD_OPC_FilterValue, 37, 11, 0, 0, // Skip to: 3216
/* 3205 */    MCD_OPC_CheckField, 7, 1, 1, 67, 30, 0, // Skip to: 10959
/* 3212 */    MCD_OPC_Decode, 170, 2, 22, // Opcode: AND_GE_U_rc
/* 3216 */    MCD_OPC_FilterValue, 39, 28, 0, 0, // Skip to: 3249
/* 3221 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3224 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3240
/* 3229 */    MCD_OPC_CheckField, 18, 3, 0, 43, 30, 0, // Skip to: 10959
/* 3236 */    MCD_OPC_Decode, 252, 1, 15, // Opcode: ABSDIF_B_rr
/* 3240 */    MCD_OPC_FilterValue, 1, 34, 30, 0, // Skip to: 10959
/* 3245 */    MCD_OPC_Decode, 221, 6, 22, // Opcode: OR_EQ_rc
/* 3249 */    MCD_OPC_FilterValue, 40, 28, 0, 0, // Skip to: 3282
/* 3254 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3257 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3273
/* 3262 */    MCD_OPC_CheckField, 18, 3, 0, 10, 30, 0, // Skip to: 10959
/* 3269 */    MCD_OPC_Decode, 144, 3, 15, // Opcode: EQ_B_rr
/* 3273 */    MCD_OPC_FilterValue, 1, 1, 30, 0, // Skip to: 10959
/* 3278 */    MCD_OPC_Decode, 231, 6, 22, // Opcode: OR_NE_rc
/* 3282 */    MCD_OPC_FilterValue, 41, 38, 0, 0, // Skip to: 3325
/* 3287 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3290 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3316
/* 3295 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3298 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3307
/* 3303 */    MCD_OPC_Decode, 202, 4, 15, // Opcode: LT_B
/* 3307 */    MCD_OPC_FilterValue, 4, 223, 29, 0, // Skip to: 10959
/* 3312 */    MCD_OPC_Decode, 203, 4, 15, // Opcode: LT_BU
/* 3316 */    MCD_OPC_FilterValue, 1, 214, 29, 0, // Skip to: 10959
/* 3321 */    MCD_OPC_Decode, 229, 6, 22, // Opcode: OR_LT_rc
/* 3325 */    MCD_OPC_FilterValue, 42, 11, 0, 0, // Skip to: 3341
/* 3330 */    MCD_OPC_CheckField, 7, 1, 1, 198, 29, 0, // Skip to: 10959
/* 3337 */    MCD_OPC_Decode, 227, 6, 22, // Opcode: OR_LT_U_rc
/* 3341 */    MCD_OPC_FilterValue, 43, 28, 0, 0, // Skip to: 3374
/* 3346 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3349 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3365
/* 3354 */    MCD_OPC_CheckField, 18, 3, 0, 174, 29, 0, // Skip to: 10959
/* 3361 */    MCD_OPC_Decode, 139, 3, 15, // Opcode: EQANY_B_rr
/* 3365 */    MCD_OPC_FilterValue, 1, 165, 29, 0, // Skip to: 10959
/* 3370 */    MCD_OPC_Decode, 225, 6, 22, // Opcode: OR_GE_rc
/* 3374 */    MCD_OPC_FilterValue, 44, 38, 0, 0, // Skip to: 3417
/* 3379 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3382 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3408
/* 3387 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3390 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3399
/* 3395 */    MCD_OPC_Decode, 183, 5, 15, // Opcode: MIN_B
/* 3399 */    MCD_OPC_FilterValue, 4, 131, 29, 0, // Skip to: 10959
/* 3404 */    MCD_OPC_Decode, 184, 5, 15, // Opcode: MIN_BU
/* 3408 */    MCD_OPC_FilterValue, 1, 122, 29, 0, // Skip to: 10959
/* 3413 */    MCD_OPC_Decode, 223, 6, 22, // Opcode: OR_GE_U_rc
/* 3417 */    MCD_OPC_FilterValue, 45, 35, 0, 0, // Skip to: 3457
/* 3422 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3425 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3441
/* 3430 */    MCD_OPC_CheckField, 7, 1, 0, 98, 29, 0, // Skip to: 10959
/* 3437 */    MCD_OPC_Decode, 174, 5, 15, // Opcode: MAX_B
/* 3441 */    MCD_OPC_FilterValue, 4, 89, 29, 0, // Skip to: 10959
/* 3446 */    MCD_OPC_CheckField, 7, 1, 0, 82, 29, 0, // Skip to: 10959
/* 3453 */    MCD_OPC_Decode, 175, 5, 15, // Opcode: MAX_BU
/* 3457 */    MCD_OPC_FilterValue, 46, 18, 0, 0, // Skip to: 3480
/* 3462 */    MCD_OPC_CheckField, 18, 3, 0, 66, 29, 0, // Skip to: 10959
/* 3469 */    MCD_OPC_CheckField, 7, 1, 0, 59, 29, 0, // Skip to: 10959
/* 3476 */    MCD_OPC_Decode, 130, 2, 15, // Opcode: ABS_B_rr
/* 3480 */    MCD_OPC_FilterValue, 47, 38, 0, 0, // Skip to: 3523
/* 3485 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3488 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3514
/* 3493 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3496 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3505
/* 3501 */    MCD_OPC_Decode, 129, 7, 15, // Opcode: SAT_B_rr
/* 3505 */    MCD_OPC_FilterValue, 4, 25, 29, 0, // Skip to: 10959
/* 3510 */    MCD_OPC_Decode, 255, 6, 15, // Opcode: SAT_BU_rr
/* 3514 */    MCD_OPC_FilterValue, 1, 16, 29, 0, // Skip to: 10959
/* 3519 */    MCD_OPC_Decode, 147, 8, 22, // Opcode: XOR_EQ_rc
/* 3523 */    MCD_OPC_FilterValue, 48, 28, 0, 0, // Skip to: 3556
/* 3528 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3531 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3547
/* 3536 */    MCD_OPC_CheckField, 18, 3, 0, 248, 28, 0, // Skip to: 10959
/* 3543 */    MCD_OPC_Decode, 154, 2, 15, // Opcode: ADD_H_rr
/* 3547 */    MCD_OPC_FilterValue, 1, 239, 28, 0, // Skip to: 10959
/* 3552 */    MCD_OPC_Decode, 157, 8, 22, // Opcode: XOR_NE_rc
/* 3556 */    MCD_OPC_FilterValue, 49, 38, 0, 0, // Skip to: 3599
/* 3561 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3564 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3590
/* 3569 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3572 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3581
/* 3577 */    MCD_OPC_Decode, 141, 2, 15, // Opcode: ADDS_H
/* 3581 */    MCD_OPC_FilterValue, 4, 205, 28, 0, // Skip to: 10959
/* 3586 */    MCD_OPC_Decode, 142, 2, 15, // Opcode: ADDS_HU
/* 3590 */    MCD_OPC_FilterValue, 1, 196, 28, 0, // Skip to: 10959
/* 3595 */    MCD_OPC_Decode, 155, 8, 22, // Opcode: XOR_LT_rc
/* 3599 */    MCD_OPC_FilterValue, 50, 11, 0, 0, // Skip to: 3615
/* 3604 */    MCD_OPC_CheckField, 7, 1, 1, 180, 28, 0, // Skip to: 10959
/* 3611 */    MCD_OPC_Decode, 153, 8, 22, // Opcode: XOR_LT_U_rc
/* 3615 */    MCD_OPC_FilterValue, 51, 11, 0, 0, // Skip to: 3631
/* 3620 */    MCD_OPC_CheckField, 7, 1, 1, 164, 28, 0, // Skip to: 10959
/* 3627 */    MCD_OPC_Decode, 151, 8, 22, // Opcode: XOR_GE_rc
/* 3631 */    MCD_OPC_FilterValue, 52, 28, 0, 0, // Skip to: 3664
/* 3636 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3639 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3655
/* 3644 */    MCD_OPC_CheckField, 18, 3, 0, 140, 28, 0, // Skip to: 10959
/* 3651 */    MCD_OPC_Decode, 250, 7, 15, // Opcode: SUB_H_rr
/* 3655 */    MCD_OPC_FilterValue, 1, 131, 28, 0, // Skip to: 10959
/* 3660 */    MCD_OPC_Decode, 149, 8, 22, // Opcode: XOR_GE_U_rc
/* 3664 */    MCD_OPC_FilterValue, 55, 38, 0, 0, // Skip to: 3707
/* 3669 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3672 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3698
/* 3677 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3680 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3689
/* 3685 */    MCD_OPC_Decode, 253, 1, 15, // Opcode: ABSDIF_H_rr
/* 3689 */    MCD_OPC_FilterValue, 4, 97, 28, 0, // Skip to: 10959
/* 3694 */    MCD_OPC_Decode, 249, 1, 15, // Opcode: ABSDIFS_H_rr
/* 3698 */    MCD_OPC_FilterValue, 1, 88, 28, 0, // Skip to: 10959
/* 3703 */    MCD_OPC_Decode, 149, 7, 22, // Opcode: SH_EQ_rc
/* 3707 */    MCD_OPC_FilterValue, 56, 28, 0, 0, // Skip to: 3740
/* 3712 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3715 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3731
/* 3720 */    MCD_OPC_CheckField, 18, 3, 0, 64, 28, 0, // Skip to: 10959
/* 3727 */    MCD_OPC_Decode, 145, 3, 15, // Opcode: EQ_H_rr
/* 3731 */    MCD_OPC_FilterValue, 1, 55, 28, 0, // Skip to: 10959
/* 3736 */    MCD_OPC_Decode, 162, 7, 22, // Opcode: SH_NE_rc
/* 3740 */    MCD_OPC_FilterValue, 57, 38, 0, 0, // Skip to: 3783
/* 3745 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3748 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3774
/* 3753 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3756 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3765
/* 3761 */    MCD_OPC_Decode, 204, 4, 15, // Opcode: LT_H
/* 3765 */    MCD_OPC_FilterValue, 4, 21, 28, 0, // Skip to: 10959
/* 3770 */    MCD_OPC_Decode, 205, 4, 15, // Opcode: LT_HU
/* 3774 */    MCD_OPC_FilterValue, 1, 12, 28, 0, // Skip to: 10959
/* 3779 */    MCD_OPC_Decode, 159, 7, 22, // Opcode: SH_LT_rc
/* 3783 */    MCD_OPC_FilterValue, 58, 11, 0, 0, // Skip to: 3799
/* 3788 */    MCD_OPC_CheckField, 7, 1, 1, 252, 27, 0, // Skip to: 10959
/* 3795 */    MCD_OPC_Decode, 157, 7, 22, // Opcode: SH_LT_U_rc
/* 3799 */    MCD_OPC_FilterValue, 59, 28, 0, 0, // Skip to: 3832
/* 3804 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3807 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3823
/* 3812 */    MCD_OPC_CheckField, 18, 3, 0, 228, 27, 0, // Skip to: 10959
/* 3819 */    MCD_OPC_Decode, 141, 3, 15, // Opcode: EQANY_H_rr
/* 3823 */    MCD_OPC_FilterValue, 1, 219, 27, 0, // Skip to: 10959
/* 3828 */    MCD_OPC_Decode, 153, 7, 22, // Opcode: SH_GE_rc
/* 3832 */    MCD_OPC_FilterValue, 60, 38, 0, 0, // Skip to: 3875
/* 3837 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3840 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3866
/* 3845 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3848 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3857
/* 3853 */    MCD_OPC_Decode, 185, 5, 15, // Opcode: MIN_H
/* 3857 */    MCD_OPC_FilterValue, 4, 185, 27, 0, // Skip to: 10959
/* 3862 */    MCD_OPC_Decode, 186, 5, 15, // Opcode: MIN_HU
/* 3866 */    MCD_OPC_FilterValue, 1, 176, 27, 0, // Skip to: 10959
/* 3871 */    MCD_OPC_Decode, 151, 7, 22, // Opcode: SH_GE_U_rc
/* 3875 */    MCD_OPC_FilterValue, 61, 35, 0, 0, // Skip to: 3915
/* 3880 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3883 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3899
/* 3888 */    MCD_OPC_CheckField, 7, 1, 0, 152, 27, 0, // Skip to: 10959
/* 3895 */    MCD_OPC_Decode, 176, 5, 15, // Opcode: MAX_H
/* 3899 */    MCD_OPC_FilterValue, 4, 143, 27, 0, // Skip to: 10959
/* 3904 */    MCD_OPC_CheckField, 7, 1, 0, 136, 27, 0, // Skip to: 10959
/* 3911 */    MCD_OPC_Decode, 177, 5, 15, // Opcode: MAX_HU
/* 3915 */    MCD_OPC_FilterValue, 62, 35, 0, 0, // Skip to: 3955
/* 3920 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3923 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3939
/* 3928 */    MCD_OPC_CheckField, 7, 1, 0, 112, 27, 0, // Skip to: 10959
/* 3935 */    MCD_OPC_Decode, 131, 2, 15, // Opcode: ABS_H_rr
/* 3939 */    MCD_OPC_FilterValue, 4, 103, 27, 0, // Skip to: 10959
/* 3944 */    MCD_OPC_CheckField, 7, 1, 0, 96, 27, 0, // Skip to: 10959
/* 3951 */    MCD_OPC_Decode, 128, 2, 15, // Opcode: ABSS_H_rr
/* 3955 */    MCD_OPC_FilterValue, 63, 35, 0, 0, // Skip to: 3995
/* 3960 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3963 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3979
/* 3968 */    MCD_OPC_CheckField, 7, 1, 0, 72, 27, 0, // Skip to: 10959
/* 3975 */    MCD_OPC_Decode, 133, 7, 15, // Opcode: SAT_H_rr
/* 3979 */    MCD_OPC_FilterValue, 4, 63, 27, 0, // Skip to: 10959
/* 3984 */    MCD_OPC_CheckField, 7, 1, 0, 56, 27, 0, // Skip to: 10959
/* 3991 */    MCD_OPC_Decode, 131, 7, 15, // Opcode: SAT_HU_rr
/* 3995 */    MCD_OPC_FilterValue, 64, 35, 0, 0, // Skip to: 4035
/* 4000 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4003 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4019
/* 4008 */    MCD_OPC_CheckField, 7, 1, 0, 32, 27, 0, // Skip to: 10959
/* 4015 */    MCD_OPC_Decode, 205, 5, 15, // Opcode: MOV_rrEcDb
/* 4019 */    MCD_OPC_FilterValue, 4, 23, 27, 0, // Skip to: 10959
/* 4024 */    MCD_OPC_CheckField, 7, 1, 0, 16, 27, 0, // Skip to: 10959
/* 4031 */    MCD_OPC_Decode, 204, 5, 15, // Opcode: MOV_rrEcDaDb
/* 4035 */    MCD_OPC_FilterValue, 72, 18, 0, 0, // Skip to: 4058
/* 4040 */    MCD_OPC_CheckField, 18, 3, 0, 0, 27, 0, // Skip to: 10959
/* 4047 */    MCD_OPC_CheckField, 7, 1, 0, 249, 26, 0, // Skip to: 10959
/* 4054 */    MCD_OPC_Decode, 146, 3, 15, // Opcode: EQ_W_rr
/* 4058 */    MCD_OPC_FilterValue, 73, 35, 0, 0, // Skip to: 4098
/* 4063 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4066 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4082
/* 4071 */    MCD_OPC_CheckField, 7, 1, 0, 225, 26, 0, // Skip to: 10959
/* 4078 */    MCD_OPC_Decode, 208, 4, 15, // Opcode: LT_W
/* 4082 */    MCD_OPC_FilterValue, 4, 216, 26, 0, // Skip to: 10959
/* 4087 */    MCD_OPC_CheckField, 7, 1, 0, 209, 26, 0, // Skip to: 10959
/* 4094 */    MCD_OPC_Decode, 209, 4, 15, // Opcode: LT_WU
/* 4098 */    MCD_OPC_FilterValue, 86, 11, 0, 0, // Skip to: 4114
/* 4103 */    MCD_OPC_CheckField, 7, 1, 1, 193, 26, 0, // Skip to: 10959
/* 4110 */    MCD_OPC_Decode, 138, 3, 22, // Opcode: EQANY_B_rc
/* 4114 */    MCD_OPC_FilterValue, 118, 184, 26, 0, // Skip to: 10959
/* 4119 */    MCD_OPC_CheckField, 7, 1, 1, 177, 26, 0, // Skip to: 10959
/* 4126 */    MCD_OPC_Decode, 140, 3, 22, // Opcode: EQANY_H_rc
/* 4130 */    MCD_OPC_FilterValue, 13, 7, 1, 0, // Skip to: 4398
/* 4135 */    MCD_OPC_ExtractField, 12, 20,  // Inst{31-12} ...
/* 4138 */    MCD_OPC_FilterValue, 128, 32, 11, 0, 0, // Skip to: 4155
/* 4144 */    MCD_OPC_CheckField, 7, 1, 0, 152, 26, 0, // Skip to: 10959
/* 4151 */    MCD_OPC_Decode, 248, 2, 14, // Opcode: DEBUG_sys
/* 4155 */    MCD_OPC_FilterValue, 128, 40, 11, 0, 0, // Skip to: 4172
/* 4161 */    MCD_OPC_CheckField, 7, 1, 0, 135, 26, 0, // Skip to: 10959
/* 4168 */    MCD_OPC_Decode, 248, 6, 14, // Opcode: RFM_sys
/* 4172 */    MCD_OPC_FilterValue, 128, 48, 11, 0, 0, // Skip to: 4189
/* 4178 */    MCD_OPC_CheckField, 7, 1, 0, 118, 26, 0, // Skip to: 10959
/* 4185 */    MCD_OPC_Decode, 245, 6, 14, // Opcode: RET_sys
/* 4189 */    MCD_OPC_FilterValue, 128, 56, 11, 0, 0, // Skip to: 4206
/* 4195 */    MCD_OPC_CheckField, 7, 1, 0, 101, 26, 0, // Skip to: 10959
/* 4202 */    MCD_OPC_Decode, 247, 6, 14, // Opcode: RFE_sys
/* 4206 */    MCD_OPC_FilterValue, 128, 64, 11, 0, 0, // Skip to: 4223
/* 4212 */    MCD_OPC_CheckField, 7, 1, 0, 84, 26, 0, // Skip to: 10959
/* 4219 */    MCD_OPC_Decode, 255, 7, 14, // Opcode: SVLCX_sys
/* 4223 */    MCD_OPC_FilterValue, 128, 72, 11, 0, 0, // Skip to: 4240
/* 4229 */    MCD_OPC_CheckField, 7, 1, 0, 67, 26, 0, // Skip to: 10959
/* 4236 */    MCD_OPC_Decode, 249, 6, 14, // Opcode: RSLCX_sys
/* 4240 */    MCD_OPC_FilterValue, 128, 96, 11, 0, 0, // Skip to: 4257
/* 4246 */    MCD_OPC_CheckField, 7, 1, 0, 50, 26, 0, // Skip to: 10959
/* 4253 */    MCD_OPC_Decode, 137, 3, 14, // Opcode: ENABLE_sys
/* 4257 */    MCD_OPC_FilterValue, 128, 104, 11, 0, 0, // Skip to: 4274
/* 4263 */    MCD_OPC_CheckField, 7, 1, 0, 33, 26, 0, // Skip to: 10959
/* 4270 */    MCD_OPC_Decode, 251, 2, 14, // Opcode: DISABLE_sys
/* 4274 */    MCD_OPC_FilterValue, 128, 112, 11, 0, 0, // Skip to: 4291
/* 4280 */    MCD_OPC_CheckField, 7, 1, 0, 16, 26, 0, // Skip to: 10959
/* 4287 */    MCD_OPC_Decode, 243, 6, 14, // Opcode: RESTORE_sys
/* 4291 */    MCD_OPC_FilterValue, 128, 120, 11, 0, 0, // Skip to: 4308
/* 4297 */    MCD_OPC_CheckField, 7, 1, 0, 255, 25, 0, // Skip to: 10959
/* 4304 */    MCD_OPC_Decode, 252, 2, 14, // Opcode: DISABLE_sys_1
/* 4308 */    MCD_OPC_FilterValue, 128, 144, 1, 11, 0, 0, // Skip to: 4326
/* 4315 */    MCD_OPC_CheckField, 7, 1, 0, 237, 25, 0, // Skip to: 10959
/* 4322 */    MCD_OPC_Decode, 255, 2, 14, // Opcode: DSYNC_sys
/* 4326 */    MCD_OPC_FilterValue, 128, 152, 1, 11, 0, 0, // Skip to: 4344
/* 4333 */    MCD_OPC_CheckField, 7, 1, 0, 219, 25, 0, // Skip to: 10959
/* 4340 */    MCD_OPC_Decode, 179, 3, 14, // Opcode: ISYNC_sys
/* 4344 */    MCD_OPC_FilterValue, 128, 160, 1, 11, 0, 0, // Skip to: 4362
/* 4351 */    MCD_OPC_CheckField, 7, 1, 0, 201, 25, 0, // Skip to: 10959
/* 4358 */    MCD_OPC_Decode, 141, 8, 14, // Opcode: TRAPV_sys
/* 4362 */    MCD_OPC_FilterValue, 128, 168, 1, 11, 0, 0, // Skip to: 4380
/* 4369 */    MCD_OPC_CheckField, 7, 1, 0, 183, 25, 0, // Skip to: 10959
/* 4376 */    MCD_OPC_Decode, 140, 8, 14, // Opcode: TRAPSV_sys
/* 4380 */    MCD_OPC_FilterValue, 128, 176, 1, 172, 25, 0, // Skip to: 10959
/* 4387 */    MCD_OPC_CheckField, 7, 1, 0, 165, 25, 0, // Skip to: 10959
/* 4394 */    MCD_OPC_Decode, 143, 8, 14, // Opcode: WAIT_sys
/* 4398 */    MCD_OPC_FilterValue, 15, 53, 2, 0, // Skip to: 4968
/* 4403 */    MCD_OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 4406 */    MCD_OPC_FilterValue, 0, 38, 0, 0, // Skip to: 4449
/* 4411 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 4414 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 4440
/* 4419 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4422 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 4431
/* 4427 */    MCD_OPC_Decode, 170, 7, 15, // Opcode: SH_rr
/* 4431 */    MCD_OPC_FilterValue, 4, 123, 25, 0, // Skip to: 10959
/* 4436 */    MCD_OPC_Decode, 144, 7, 15, // Opcode: SHA_rr
/* 4440 */    MCD_OPC_FilterValue, 1, 114, 25, 0, // Skip to: 10959
/* 4445 */    MCD_OPC_Decode, 169, 7, 22, // Opcode: SH_rc
/* 4449 */    MCD_OPC_FilterValue, 1, 28, 0, 0, // Skip to: 4482
/* 4454 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 4457 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4473
/* 4462 */    MCD_OPC_CheckField, 18, 3, 0, 90, 25, 0, // Skip to: 10959
/* 4469 */    MCD_OPC_Decode, 140, 7, 15, // Opcode: SHAS_rr
/* 4473 */    MCD_OPC_FilterValue, 1, 81, 25, 0, // Skip to: 10959
/* 4478 */    MCD_OPC_Decode, 143, 7, 22, // Opcode: SHA_rc
/* 4482 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 4498
/* 4487 */    MCD_OPC_CheckField, 7, 1, 1, 65, 25, 0, // Skip to: 10959
/* 4494 */    MCD_OPC_Decode, 139, 7, 22, // Opcode: SHAS_rc
/* 4498 */    MCD_OPC_FilterValue, 4, 35, 0, 0, // Skip to: 4538
/* 4503 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4506 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4522
/* 4511 */    MCD_OPC_CheckField, 7, 1, 0, 41, 25, 0, // Skip to: 10959
/* 4518 */    MCD_OPC_Decode, 184, 2, 15, // Opcode: AND_rr
/* 4522 */    MCD_OPC_FilterValue, 4, 32, 25, 0, // Skip to: 10959
/* 4527 */    MCD_OPC_CheckField, 7, 1, 0, 25, 25, 0, // Skip to: 10959
/* 4534 */    MCD_OPC_Decode, 205, 6, 15, // Opcode: NAND_rr
/* 4538 */    MCD_OPC_FilterValue, 5, 35, 0, 0, // Skip to: 4578
/* 4543 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4546 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4562
/* 4551 */    MCD_OPC_CheckField, 7, 1, 0, 1, 25, 0, // Skip to: 10959
/* 4558 */    MCD_OPC_Decode, 237, 6, 15, // Opcode: OR_rr
/* 4562 */    MCD_OPC_FilterValue, 4, 248, 24, 0, // Skip to: 10959
/* 4567 */    MCD_OPC_CheckField, 7, 1, 0, 241, 24, 0, // Skip to: 10959
/* 4574 */    MCD_OPC_Decode, 214, 6, 15, // Opcode: NOR_rr
/* 4578 */    MCD_OPC_FilterValue, 6, 35, 0, 0, // Skip to: 4618
/* 4583 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4586 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4602
/* 4591 */    MCD_OPC_CheckField, 7, 1, 0, 217, 24, 0, // Skip to: 10959
/* 4598 */    MCD_OPC_Decode, 161, 8, 15, // Opcode: XOR_rr
/* 4602 */    MCD_OPC_FilterValue, 4, 208, 24, 0, // Skip to: 10959
/* 4607 */    MCD_OPC_CheckField, 7, 1, 0, 201, 24, 0, // Skip to: 10959
/* 4614 */    MCD_OPC_Decode, 146, 8, 15, // Opcode: XNOR_rr
/* 4618 */    MCD_OPC_FilterValue, 7, 38, 0, 0, // Skip to: 4661
/* 4623 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 4626 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 4652
/* 4631 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4634 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 4643
/* 4639 */    MCD_OPC_Decode, 165, 2, 15, // Opcode: ANDN_rr
/* 4643 */    MCD_OPC_FilterValue, 4, 167, 24, 0, // Skip to: 10959
/* 4648 */    MCD_OPC_Decode, 218, 6, 15, // Opcode: ORN_rr
/* 4652 */    MCD_OPC_FilterValue, 1, 158, 24, 0, // Skip to: 10959
/* 4657 */    MCD_OPC_Decode, 146, 7, 22, // Opcode: SHUFFLE_rc
/* 4661 */    MCD_OPC_FilterValue, 8, 11, 0, 0, // Skip to: 4677
/* 4666 */    MCD_OPC_CheckField, 7, 1, 1, 142, 24, 0, // Skip to: 10959
/* 4673 */    MCD_OPC_Decode, 183, 2, 22, // Opcode: AND_rc
/* 4677 */    MCD_OPC_FilterValue, 9, 11, 0, 0, // Skip to: 4693
/* 4682 */    MCD_OPC_CheckField, 7, 1, 1, 126, 24, 0, // Skip to: 10959
/* 4689 */    MCD_OPC_Decode, 204, 6, 22, // Opcode: NAND_rc
/* 4693 */    MCD_OPC_FilterValue, 10, 11, 0, 0, // Skip to: 4709
/* 4698 */    MCD_OPC_CheckField, 7, 1, 1, 110, 24, 0, // Skip to: 10959
/* 4705 */    MCD_OPC_Decode, 236, 6, 22, // Opcode: OR_rc
/* 4709 */    MCD_OPC_FilterValue, 11, 11, 0, 0, // Skip to: 4725
/* 4714 */    MCD_OPC_CheckField, 7, 1, 1, 94, 24, 0, // Skip to: 10959
/* 4721 */    MCD_OPC_Decode, 213, 6, 22, // Opcode: NOR_rc
/* 4725 */    MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 4741
/* 4730 */    MCD_OPC_CheckField, 7, 1, 1, 78, 24, 0, // Skip to: 10959
/* 4737 */    MCD_OPC_Decode, 160, 8, 22, // Opcode: XOR_rc
/* 4741 */    MCD_OPC_FilterValue, 13, 28, 0, 0, // Skip to: 4774
/* 4746 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 4749 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4765
/* 4754 */    MCD_OPC_CheckField, 18, 3, 4, 54, 24, 0, // Skip to: 10959
/* 4761 */    MCD_OPC_Decode, 231, 2, 15, // Opcode: CLZ_rr
/* 4765 */    MCD_OPC_FilterValue, 1, 45, 24, 0, // Skip to: 10959
/* 4770 */    MCD_OPC_Decode, 145, 8, 22, // Opcode: XNOR_rc
/* 4774 */    MCD_OPC_FilterValue, 14, 38, 0, 0, // Skip to: 4817
/* 4779 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 4782 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 4808
/* 4787 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4790 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 4799
/* 4795 */    MCD_OPC_Decode, 227, 2, 15, // Opcode: CLO_rr
/* 4799 */    MCD_OPC_FilterValue, 4, 11, 24, 0, // Skip to: 10959
/* 4804 */    MCD_OPC_Decode, 229, 2, 15, // Opcode: CLS_rr
/* 4808 */    MCD_OPC_FilterValue, 1, 2, 24, 0, // Skip to: 10959
/* 4813 */    MCD_OPC_Decode, 164, 2, 22, // Opcode: ANDN_rc
/* 4817 */    MCD_OPC_FilterValue, 15, 11, 0, 0, // Skip to: 4833
/* 4822 */    MCD_OPC_CheckField, 7, 1, 1, 242, 23, 0, // Skip to: 10959
/* 4829 */    MCD_OPC_Decode, 217, 6, 22, // Opcode: ORN_rc
/* 4833 */    MCD_OPC_FilterValue, 32, 35, 0, 0, // Skip to: 4873
/* 4838 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4841 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4857
/* 4846 */    MCD_OPC_CheckField, 7, 1, 0, 218, 23, 0, // Skip to: 10959
/* 4853 */    MCD_OPC_Decode, 156, 7, 15, // Opcode: SH_H_rr
/* 4857 */    MCD_OPC_FilterValue, 4, 209, 23, 0, // Skip to: 10959
/* 4862 */    MCD_OPC_CheckField, 7, 1, 0, 202, 23, 0, // Skip to: 10959
/* 4869 */    MCD_OPC_Decode, 142, 7, 15, // Opcode: SHA_H_rr
/* 4873 */    MCD_OPC_FilterValue, 62, 35, 0, 0, // Skip to: 4913
/* 4878 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4881 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4897
/* 4886 */    MCD_OPC_CheckField, 7, 1, 0, 178, 23, 0, // Skip to: 10959
/* 4893 */    MCD_OPC_Decode, 230, 2, 15, // Opcode: CLZ_H_rr
/* 4897 */    MCD_OPC_FilterValue, 4, 169, 23, 0, // Skip to: 10959
/* 4902 */    MCD_OPC_CheckField, 7, 1, 0, 162, 23, 0, // Skip to: 10959
/* 4909 */    MCD_OPC_Decode, 226, 2, 15, // Opcode: CLO_H_rr
/* 4913 */    MCD_OPC_FilterValue, 63, 18, 0, 0, // Skip to: 4936
/* 4918 */    MCD_OPC_CheckField, 18, 3, 0, 146, 23, 0, // Skip to: 10959
/* 4925 */    MCD_OPC_CheckField, 7, 1, 0, 139, 23, 0, // Skip to: 10959
/* 4932 */    MCD_OPC_Decode, 228, 2, 15, // Opcode: CLS_H_rr
/* 4936 */    MCD_OPC_FilterValue, 64, 11, 0, 0, // Skip to: 4952
/* 4941 */    MCD_OPC_CheckField, 7, 1, 1, 123, 23, 0, // Skip to: 10959
/* 4948 */    MCD_OPC_Decode, 155, 7, 22, // Opcode: SH_H_rc
/* 4952 */    MCD_OPC_FilterValue, 65, 114, 23, 0, // Skip to: 10959
/* 4957 */    MCD_OPC_CheckField, 7, 1, 1, 107, 23, 0, // Skip to: 10959
/* 4964 */    MCD_OPC_Decode, 141, 7, 22, // Opcode: SHA_H_rc
/* 4968 */    MCD_OPC_FilterValue, 17, 21, 0, 0, // Skip to: 4994
/* 4973 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 4976 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 4985
/* 4981 */    MCD_OPC_Decode, 135, 2, 23, // Opcode: ADDIH_A_rlc
/* 4985 */    MCD_OPC_FilterValue, 1, 81, 23, 0, // Skip to: 10959
/* 4990 */    MCD_OPC_Decode, 191, 5, 23, // Opcode: MOVH_A_rlc
/* 4994 */    MCD_OPC_FilterValue, 19, 85, 1, 0, // Skip to: 5340
/* 4999 */    MCD_OPC_ExtractField, 21, 3,  // Inst{23-21} ...
/* 5002 */    MCD_OPC_FilterValue, 0, 164, 0, 0, // Skip to: 5171
/* 5007 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 5010 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 5033
/* 5015 */    MCD_OPC_CheckField, 24, 4, 0, 49, 23, 0, // Skip to: 10959
/* 5022 */    MCD_OPC_CheckField, 7, 1, 1, 42, 23, 0, // Skip to: 10959
/* 5029 */    MCD_OPC_Decode, 192, 6, 24, // Opcode: MUL_Q_rr1_2_U
/* 5033 */    MCD_OPC_FilterValue, 1, 18, 0, 0, // Skip to: 5056
/* 5038 */    MCD_OPC_CheckField, 24, 4, 0, 26, 23, 0, // Skip to: 10959
/* 5045 */    MCD_OPC_CheckField, 7, 1, 1, 19, 23, 0, // Skip to: 10959
/* 5052 */    MCD_OPC_Decode, 190, 6, 24, // Opcode: MUL_Q_rr1_2_L
/* 5056 */    MCD_OPC_FilterValue, 2, 18, 0, 0, // Skip to: 5079
/* 5061 */    MCD_OPC_CheckField, 24, 4, 0, 3, 23, 0, // Skip to: 10959
/* 5068 */    MCD_OPC_CheckField, 7, 1, 1, 252, 22, 0, // Skip to: 10959
/* 5075 */    MCD_OPC_Decode, 194, 6, 24, // Opcode: MUL_Q_rr1_2__
/* 5079 */    MCD_OPC_FilterValue, 4, 18, 0, 0, // Skip to: 5102
/* 5084 */    MCD_OPC_CheckField, 24, 4, 0, 236, 22, 0, // Skip to: 10959
/* 5091 */    MCD_OPC_CheckField, 7, 1, 1, 229, 22, 0, // Skip to: 10959
/* 5098 */    MCD_OPC_Decode, 189, 6, 24, // Opcode: MUL_Q_rr1_2UU
/* 5102 */    MCD_OPC_FilterValue, 5, 18, 0, 0, // Skip to: 5125
/* 5107 */    MCD_OPC_CheckField, 24, 4, 0, 213, 22, 0, // Skip to: 10959
/* 5114 */    MCD_OPC_CheckField, 7, 1, 1, 206, 22, 0, // Skip to: 10959
/* 5121 */    MCD_OPC_Decode, 188, 6, 24, // Opcode: MUL_Q_rr1_2LL
/* 5125 */    MCD_OPC_FilterValue, 6, 18, 0, 0, // Skip to: 5148
/* 5130 */    MCD_OPC_CheckField, 24, 4, 0, 190, 22, 0, // Skip to: 10959
/* 5137 */    MCD_OPC_CheckField, 7, 1, 1, 183, 22, 0, // Skip to: 10959
/* 5144 */    MCD_OPC_Decode, 179, 6, 24, // Opcode: MULR_Q_rr1_2UU
/* 5148 */    MCD_OPC_FilterValue, 7, 174, 22, 0, // Skip to: 10959
/* 5153 */    MCD_OPC_CheckField, 24, 4, 0, 167, 22, 0, // Skip to: 10959
/* 5160 */    MCD_OPC_CheckField, 7, 1, 1, 160, 22, 0, // Skip to: 10959
/* 5167 */    MCD_OPC_Decode, 178, 6, 24, // Opcode: MULR_Q_rr1_2LL
/* 5171 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 5187
/* 5176 */    MCD_OPC_CheckField, 7, 1, 0, 144, 22, 0, // Skip to: 10959
/* 5183 */    MCD_OPC_Decode, 170, 5, 25, // Opcode: MADD_rcr
/* 5187 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 5203
/* 5192 */    MCD_OPC_CheckField, 7, 1, 0, 128, 22, 0, // Skip to: 10959
/* 5199 */    MCD_OPC_Decode, 168, 5, 25, // Opcode: MADD_U_rcr
/* 5203 */    MCD_OPC_FilterValue, 3, 68, 0, 0, // Skip to: 5276
/* 5208 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 5211 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5220
/* 5216 */    MCD_OPC_Decode, 171, 5, 25, // Opcode: MADD_rcr_e
/* 5220 */    MCD_OPC_FilterValue, 1, 102, 22, 0, // Skip to: 10959
/* 5225 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 5228 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 5244
/* 5233 */    MCD_OPC_CheckField, 24, 4, 0, 87, 22, 0, // Skip to: 10959
/* 5240 */    MCD_OPC_Decode, 193, 6, 24, // Opcode: MUL_Q_rr1_2_Ue
/* 5244 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 5260
/* 5249 */    MCD_OPC_CheckField, 24, 4, 0, 71, 22, 0, // Skip to: 10959
/* 5256 */    MCD_OPC_Decode, 191, 6, 24, // Opcode: MUL_Q_rr1_2_Le
/* 5260 */    MCD_OPC_FilterValue, 3, 62, 22, 0, // Skip to: 10959
/* 5265 */    MCD_OPC_CheckField, 24, 4, 0, 55, 22, 0, // Skip to: 10959
/* 5272 */    MCD_OPC_Decode, 195, 6, 24, // Opcode: MUL_Q_rr1_2__e
/* 5276 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 5292
/* 5281 */    MCD_OPC_CheckField, 7, 1, 0, 39, 22, 0, // Skip to: 10959
/* 5288 */    MCD_OPC_Decode, 146, 5, 25, // Opcode: MADDS_U_rcr
/* 5292 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 5308
/* 5297 */    MCD_OPC_CheckField, 7, 1, 0, 23, 22, 0, // Skip to: 10959
/* 5304 */    MCD_OPC_Decode, 150, 5, 25, // Opcode: MADDS_rcr
/* 5308 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 5324
/* 5313 */    MCD_OPC_CheckField, 7, 1, 0, 7, 22, 0, // Skip to: 10959
/* 5320 */    MCD_OPC_Decode, 147, 5, 25, // Opcode: MADDS_U_rcr_e
/* 5324 */    MCD_OPC_FilterValue, 7, 254, 21, 0, // Skip to: 10959
/* 5329 */    MCD_OPC_CheckField, 7, 1, 0, 247, 21, 0, // Skip to: 10959
/* 5336 */    MCD_OPC_Decode, 151, 5, 25, // Opcode: MADDS_rcr_e
/* 5340 */    MCD_OPC_FilterValue, 21, 67, 0, 0, // Skip to: 5412
/* 5345 */    MCD_OPC_ExtractField, 26, 2,  // Inst{27-26} ...
/* 5348 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 5364
/* 5353 */    MCD_OPC_CheckField, 7, 1, 0, 223, 21, 0, // Skip to: 10959
/* 5360 */    MCD_OPC_Decode, 172, 7, 18, // Opcode: STLCX_abs
/* 5364 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 5380
/* 5369 */    MCD_OPC_CheckField, 7, 1, 0, 207, 21, 0, // Skip to: 10959
/* 5376 */    MCD_OPC_Decode, 174, 7, 18, // Opcode: STUCX_abs
/* 5380 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 5396
/* 5385 */    MCD_OPC_CheckField, 7, 1, 0, 191, 21, 0, // Skip to: 10959
/* 5392 */    MCD_OPC_Decode, 234, 3, 18, // Opcode: LDLCX_abs
/* 5396 */    MCD_OPC_FilterValue, 3, 182, 21, 0, // Skip to: 10959
/* 5401 */    MCD_OPC_CheckField, 7, 1, 0, 175, 21, 0, // Skip to: 10959
/* 5408 */    MCD_OPC_Decode, 242, 3, 18, // Opcode: LDUCX_abs
/* 5412 */    MCD_OPC_FilterValue, 23, 105, 0, 0, // Skip to: 5522
/* 5417 */    MCD_OPC_ExtractField, 21, 3,  // Inst{23-21} ...
/* 5420 */    MCD_OPC_FilterValue, 0, 28, 0, 0, // Skip to: 5453
/* 5425 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 5428 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5437
/* 5433 */    MCD_OPC_Decode, 175, 3, 26, // Opcode: INSERT_rrrr
/* 5437 */    MCD_OPC_FilterValue, 1, 141, 21, 0, // Skip to: 10959
/* 5442 */    MCD_OPC_CheckField, 16, 5, 0, 134, 21, 0, // Skip to: 10959
/* 5449 */    MCD_OPC_Decode, 172, 3, 27, // Opcode: INSERT_rcrr
/* 5453 */    MCD_OPC_FilterValue, 2, 18, 0, 0, // Skip to: 5476
/* 5458 */    MCD_OPC_CheckField, 16, 5, 0, 118, 21, 0, // Skip to: 10959
/* 5465 */    MCD_OPC_CheckField, 7, 1, 0, 111, 21, 0, // Skip to: 10959
/* 5472 */    MCD_OPC_Decode, 155, 3, 28, // Opcode: EXTR_rrrr
/* 5476 */    MCD_OPC_FilterValue, 3, 18, 0, 0, // Skip to: 5499
/* 5481 */    MCD_OPC_CheckField, 16, 5, 0, 95, 21, 0, // Skip to: 10959
/* 5488 */    MCD_OPC_CheckField, 7, 1, 0, 88, 21, 0, // Skip to: 10959
/* 5495 */    MCD_OPC_Decode, 152, 3, 28, // Opcode: EXTR_U_rrrr
/* 5499 */    MCD_OPC_FilterValue, 4, 79, 21, 0, // Skip to: 10959
/* 5504 */    MCD_OPC_CheckField, 16, 5, 0, 72, 21, 0, // Skip to: 10959
/* 5511 */    MCD_OPC_CheckField, 7, 1, 0, 65, 21, 0, // Skip to: 10959
/* 5518 */    MCD_OPC_Decode, 250, 2, 28, // Opcode: DEXTR_rrrr
/* 5522 */    MCD_OPC_FilterValue, 25, 21, 0, 0, // Skip to: 5548
/* 5527 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 5530 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5539
/* 5535 */    MCD_OPC_Decode, 188, 4, 29, // Opcode: LD_W_bol
/* 5539 */    MCD_OPC_FilterValue, 1, 39, 21, 0, // Skip to: 10959
/* 5544 */    MCD_OPC_Decode, 250, 3, 29, // Opcode: LD_A_bol
/* 5548 */    MCD_OPC_FilterValue, 27, 21, 0, 0, // Skip to: 5574
/* 5553 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 5556 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5565
/* 5561 */    MCD_OPC_Decode, 137, 2, 23, // Opcode: ADDI_rlc
/* 5565 */    MCD_OPC_FilterValue, 1, 13, 21, 0, // Skip to: 10959
/* 5570 */    MCD_OPC_Decode, 136, 2, 23, // Opcode: ADDIH_rlc
/* 5574 */    MCD_OPC_FilterValue, 29, 21, 0, 0, // Skip to: 5600
/* 5579 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 5582 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5591
/* 5587 */    MCD_OPC_Decode, 232, 3, 30, // Opcode: J_b
/* 5591 */    MCD_OPC_FilterValue, 1, 243, 20, 0, // Skip to: 10959
/* 5596 */    MCD_OPC_Decode, 184, 3, 30, // Opcode: JA_b
/* 5600 */    MCD_OPC_FilterValue, 31, 55, 0, 0, // Skip to: 5660
/* 5605 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 5608 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 5634
/* 5613 */    MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 5616 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5625
/* 5621 */    MCD_OPC_Decode, 212, 3, 31, // Opcode: JNEI_brr
/* 5625 */    MCD_OPC_FilterValue, 1, 209, 20, 0, // Skip to: 10959
/* 5630 */    MCD_OPC_Decode, 210, 3, 31, // Opcode: JNED_brr
/* 5634 */    MCD_OPC_FilterValue, 1, 200, 20, 0, // Skip to: 10959
/* 5639 */    MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 5642 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5651
/* 5647 */    MCD_OPC_Decode, 211, 3, 32, // Opcode: JNEI_brc
/* 5651 */    MCD_OPC_FilterValue, 1, 183, 20, 0, // Skip to: 10959
/* 5656 */    MCD_OPC_Decode, 209, 3, 32, // Opcode: JNED_brc
/* 5660 */    MCD_OPC_FilterValue, 32, 35, 0, 0, // Skip to: 5700
/* 5665 */    MCD_OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 5668 */    MCD_OPC_FilterValue, 16, 11, 0, 0, // Skip to: 5684
/* 5673 */    MCD_OPC_CheckField, 7, 1, 0, 159, 20, 0, // Skip to: 10959
/* 5680 */    MCD_OPC_Decode, 144, 4, 20, // Opcode: LD_B_bo_r
/* 5684 */    MCD_OPC_FilterValue, 41, 150, 20, 0, // Skip to: 10959
/* 5689 */    MCD_OPC_CheckField, 7, 1, 0, 143, 20, 0, // Skip to: 10959
/* 5696 */    MCD_OPC_Decode, 141, 4, 20, // Opcode: LD_B_bo_c
/* 5700 */    MCD_OPC_FilterValue, 35, 248, 1, 0, // Skip to: 6209
/* 5705 */    MCD_OPC_ExtractField, 18, 6,  // Inst{23-18} ...
/* 5708 */    MCD_OPC_FilterValue, 2, 18, 0, 0, // Skip to: 5731
/* 5713 */    MCD_OPC_CheckField, 16, 2, 2, 119, 20, 0, // Skip to: 10959
/* 5720 */    MCD_OPC_CheckField, 7, 1, 0, 112, 20, 0, // Skip to: 10959
/* 5727 */    MCD_OPC_Decode, 168, 6, 16, // Opcode: MSUB_rrr2
/* 5731 */    MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 5747
/* 5736 */    MCD_OPC_CheckField, 7, 1, 1, 96, 20, 0, // Skip to: 10959
/* 5743 */    MCD_OPC_Decode, 252, 5, 17, // Opcode: MSUBR_H_rrr1_UL
/* 5747 */    MCD_OPC_FilterValue, 13, 11, 0, 0, // Skip to: 5763
/* 5752 */    MCD_OPC_CheckField, 7, 1, 1, 80, 20, 0, // Skip to: 10959
/* 5759 */    MCD_OPC_Decode, 251, 5, 17, // Opcode: MSUBR_H_rrr1_LU
/* 5763 */    MCD_OPC_FilterValue, 14, 11, 0, 0, // Skip to: 5779
/* 5768 */    MCD_OPC_CheckField, 7, 1, 1, 64, 20, 0, // Skip to: 10959
/* 5775 */    MCD_OPC_Decode, 250, 5, 17, // Opcode: MSUBR_H_rrr1_LL
/* 5779 */    MCD_OPC_FilterValue, 15, 11, 0, 0, // Skip to: 5795
/* 5784 */    MCD_OPC_CheckField, 7, 1, 1, 48, 20, 0, // Skip to: 10959
/* 5791 */    MCD_OPC_Decode, 253, 5, 17, // Opcode: MSUBR_H_rrr1_UU
/* 5795 */    MCD_OPC_FilterValue, 24, 11, 0, 0, // Skip to: 5811
/* 5800 */    MCD_OPC_CheckField, 7, 1, 1, 32, 20, 0, // Skip to: 10959
/* 5807 */    MCD_OPC_Decode, 152, 6, 17, // Opcode: MSUB_H_rrr1_UL
/* 5811 */    MCD_OPC_FilterValue, 25, 11, 0, 0, // Skip to: 5827
/* 5816 */    MCD_OPC_CheckField, 7, 1, 1, 16, 20, 0, // Skip to: 10959
/* 5823 */    MCD_OPC_Decode, 151, 6, 17, // Opcode: MSUB_H_rrr1_LU
/* 5827 */    MCD_OPC_FilterValue, 26, 38, 0, 0, // Skip to: 5870
/* 5832 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 5835 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 5861
/* 5840 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 5843 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5852
/* 5848 */    MCD_OPC_Decode, 165, 6, 16, // Opcode: MSUB_U_rrr2
/* 5852 */    MCD_OPC_FilterValue, 2, 238, 19, 0, // Skip to: 10959
/* 5857 */    MCD_OPC_Decode, 169, 6, 16, // Opcode: MSUB_rrr2_e
/* 5861 */    MCD_OPC_FilterValue, 1, 229, 19, 0, // Skip to: 10959
/* 5866 */    MCD_OPC_Decode, 150, 6, 17, // Opcode: MSUB_H_rrr1_LL
/* 5870 */    MCD_OPC_FilterValue, 27, 11, 0, 0, // Skip to: 5886
/* 5875 */    MCD_OPC_CheckField, 7, 1, 1, 213, 19, 0, // Skip to: 10959
/* 5882 */    MCD_OPC_Decode, 153, 6, 17, // Opcode: MSUB_H_rrr1_UU
/* 5886 */    MCD_OPC_FilterValue, 28, 11, 0, 0, // Skip to: 5902
/* 5891 */    MCD_OPC_CheckField, 7, 1, 1, 197, 19, 0, // Skip to: 10959
/* 5898 */    MCD_OPC_Decode, 240, 5, 17, // Opcode: MSUBM_H_rrr1_UL
/* 5902 */    MCD_OPC_FilterValue, 29, 11, 0, 0, // Skip to: 5918
/* 5907 */    MCD_OPC_CheckField, 7, 1, 1, 181, 19, 0, // Skip to: 10959
/* 5914 */    MCD_OPC_Decode, 239, 5, 17, // Opcode: MSUBM_H_rrr1_LU
/* 5918 */    MCD_OPC_FilterValue, 30, 11, 0, 0, // Skip to: 5934
/* 5923 */    MCD_OPC_CheckField, 7, 1, 1, 165, 19, 0, // Skip to: 10959
/* 5930 */    MCD_OPC_Decode, 238, 5, 17, // Opcode: MSUBM_H_rrr1_LL
/* 5934 */    MCD_OPC_FilterValue, 31, 11, 0, 0, // Skip to: 5950
/* 5939 */    MCD_OPC_CheckField, 7, 1, 1, 149, 19, 0, // Skip to: 10959
/* 5946 */    MCD_OPC_Decode, 241, 5, 17, // Opcode: MSUBM_H_rrr1_UU
/* 5950 */    MCD_OPC_FilterValue, 34, 35, 0, 0, // Skip to: 5990
/* 5955 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 5958 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 5974
/* 5963 */    MCD_OPC_CheckField, 7, 1, 0, 125, 19, 0, // Skip to: 10959
/* 5970 */    MCD_OPC_Decode, 144, 6, 16, // Opcode: MSUBS_U_rrr2
/* 5974 */    MCD_OPC_FilterValue, 2, 116, 19, 0, // Skip to: 10959
/* 5979 */    MCD_OPC_CheckField, 7, 1, 0, 109, 19, 0, // Skip to: 10959
/* 5986 */    MCD_OPC_Decode, 148, 6, 16, // Opcode: MSUBS_rrr2
/* 5990 */    MCD_OPC_FilterValue, 44, 11, 0, 0, // Skip to: 6006
/* 5995 */    MCD_OPC_CheckField, 7, 1, 1, 93, 19, 0, // Skip to: 10959
/* 6002 */    MCD_OPC_Decode, 245, 5, 17, // Opcode: MSUBRS_H_rrr1_UL
/* 6006 */    MCD_OPC_FilterValue, 45, 11, 0, 0, // Skip to: 6022
/* 6011 */    MCD_OPC_CheckField, 7, 1, 1, 77, 19, 0, // Skip to: 10959
/* 6018 */    MCD_OPC_Decode, 244, 5, 17, // Opcode: MSUBRS_H_rrr1_LU
/* 6022 */    MCD_OPC_FilterValue, 46, 11, 0, 0, // Skip to: 6038
/* 6027 */    MCD_OPC_CheckField, 7, 1, 1, 61, 19, 0, // Skip to: 10959
/* 6034 */    MCD_OPC_Decode, 243, 5, 17, // Opcode: MSUBRS_H_rrr1_LL
/* 6038 */    MCD_OPC_FilterValue, 47, 11, 0, 0, // Skip to: 6054
/* 6043 */    MCD_OPC_CheckField, 7, 1, 1, 45, 19, 0, // Skip to: 10959
/* 6050 */    MCD_OPC_Decode, 246, 5, 17, // Opcode: MSUBRS_H_rrr1_UU
/* 6054 */    MCD_OPC_FilterValue, 56, 11, 0, 0, // Skip to: 6070
/* 6059 */    MCD_OPC_CheckField, 7, 1, 1, 29, 19, 0, // Skip to: 10959
/* 6066 */    MCD_OPC_Decode, 130, 6, 17, // Opcode: MSUBS_H_rrr1_UL
/* 6070 */    MCD_OPC_FilterValue, 57, 11, 0, 0, // Skip to: 6086
/* 6075 */    MCD_OPC_CheckField, 7, 1, 1, 13, 19, 0, // Skip to: 10959
/* 6082 */    MCD_OPC_Decode, 129, 6, 17, // Opcode: MSUBS_H_rrr1_LU
/* 6086 */    MCD_OPC_FilterValue, 58, 38, 0, 0, // Skip to: 6129
/* 6091 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6094 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 6120
/* 6099 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 6102 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6111
/* 6107 */    MCD_OPC_Decode, 145, 6, 16, // Opcode: MSUBS_U_rrr2_e
/* 6111 */    MCD_OPC_FilterValue, 2, 235, 18, 0, // Skip to: 10959
/* 6116 */    MCD_OPC_Decode, 149, 6, 16, // Opcode: MSUBS_rrr2_e
/* 6120 */    MCD_OPC_FilterValue, 1, 226, 18, 0, // Skip to: 10959
/* 6125 */    MCD_OPC_Decode, 128, 6, 17, // Opcode: MSUBS_H_rrr1_LL
/* 6129 */    MCD_OPC_FilterValue, 59, 11, 0, 0, // Skip to: 6145
/* 6134 */    MCD_OPC_CheckField, 7, 1, 1, 210, 18, 0, // Skip to: 10959
/* 6141 */    MCD_OPC_Decode, 131, 6, 17, // Opcode: MSUBS_H_rrr1_UU
/* 6145 */    MCD_OPC_FilterValue, 60, 11, 0, 0, // Skip to: 6161
/* 6150 */    MCD_OPC_CheckField, 7, 1, 1, 194, 18, 0, // Skip to: 10959
/* 6157 */    MCD_OPC_Decode, 236, 5, 17, // Opcode: MSUBMS_H_rrr1_UL
/* 6161 */    MCD_OPC_FilterValue, 61, 11, 0, 0, // Skip to: 6177
/* 6166 */    MCD_OPC_CheckField, 7, 1, 1, 178, 18, 0, // Skip to: 10959
/* 6173 */    MCD_OPC_Decode, 235, 5, 17, // Opcode: MSUBMS_H_rrr1_LU
/* 6177 */    MCD_OPC_FilterValue, 62, 11, 0, 0, // Skip to: 6193
/* 6182 */    MCD_OPC_CheckField, 7, 1, 1, 162, 18, 0, // Skip to: 10959
/* 6189 */    MCD_OPC_Decode, 234, 5, 17, // Opcode: MSUBMS_H_rrr1_LL
/* 6193 */    MCD_OPC_FilterValue, 63, 153, 18, 0, // Skip to: 10959
/* 6198 */    MCD_OPC_CheckField, 7, 1, 1, 146, 18, 0, // Skip to: 10959
/* 6205 */    MCD_OPC_Decode, 237, 5, 17, // Opcode: MSUBMS_H_rrr1_UU
/* 6209 */    MCD_OPC_FilterValue, 37, 87, 0, 0, // Skip to: 6301
/* 6214 */    MCD_OPC_ExtractField, 26, 2,  // Inst{27-26} ...
/* 6217 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 6243
/* 6222 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6225 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6234
/* 6230 */    MCD_OPC_Decode, 188, 7, 18, // Opcode: ST_B_abs
/* 6234 */    MCD_OPC_FilterValue, 1, 112, 18, 0, // Skip to: 10959
/* 6239 */    MCD_OPC_Decode, 229, 7, 18, // Opcode: ST_W_abs
/* 6243 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 6259
/* 6248 */    MCD_OPC_CheckField, 7, 1, 1, 96, 18, 0, // Skip to: 10959
/* 6255 */    MCD_OPC_Decode, 205, 7, 18, // Opcode: ST_D_abs
/* 6259 */    MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 6285
/* 6264 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6267 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6276
/* 6272 */    MCD_OPC_Decode, 211, 7, 18, // Opcode: ST_H_abs
/* 6276 */    MCD_OPC_FilterValue, 1, 70, 18, 0, // Skip to: 10959
/* 6281 */    MCD_OPC_Decode, 176, 7, 18, // Opcode: ST_A_abs
/* 6285 */    MCD_OPC_FilterValue, 3, 61, 18, 0, // Skip to: 10959
/* 6290 */    MCD_OPC_CheckField, 7, 1, 1, 54, 18, 0, // Skip to: 10959
/* 6297 */    MCD_OPC_Decode, 199, 7, 18, // Opcode: ST_DA_abs
/* 6301 */    MCD_OPC_FilterValue, 39, 107, 0, 0, // Skip to: 6413
/* 6306 */    MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 6309 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 6335
/* 6314 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6317 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6326
/* 6322 */    MCD_OPC_Decode, 148, 7, 19, // Opcode: SH_AND_T
/* 6326 */    MCD_OPC_FilterValue, 1, 20, 18, 0, // Skip to: 10959
/* 6331 */    MCD_OPC_Decode, 161, 7, 19, // Opcode: SH_NAND_T
/* 6335 */    MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 6361
/* 6340 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6343 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6352
/* 6348 */    MCD_OPC_Decode, 166, 7, 19, // Opcode: SH_OR_T
/* 6352 */    MCD_OPC_FilterValue, 1, 250, 17, 0, // Skip to: 10959
/* 6357 */    MCD_OPC_Decode, 165, 7, 19, // Opcode: SH_ORN_T
/* 6361 */    MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 6387
/* 6366 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6369 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6378
/* 6374 */    MCD_OPC_Decode, 164, 7, 19, // Opcode: SH_NOR_T
/* 6378 */    MCD_OPC_FilterValue, 1, 224, 17, 0, // Skip to: 10959
/* 6383 */    MCD_OPC_Decode, 167, 7, 19, // Opcode: SH_XNOR_T
/* 6387 */    MCD_OPC_FilterValue, 3, 215, 17, 0, // Skip to: 10959
/* 6392 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6395 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6404
/* 6400 */    MCD_OPC_Decode, 147, 7, 19, // Opcode: SH_ANDN_T
/* 6404 */    MCD_OPC_FilterValue, 1, 198, 17, 0, // Skip to: 10959
/* 6409 */    MCD_OPC_Decode, 168, 7, 19, // Opcode: SH_XOR_T
/* 6413 */    MCD_OPC_FilterValue, 41, 27, 2, 0, // Skip to: 6957
/* 6418 */    MCD_OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 6421 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6437
/* 6426 */    MCD_OPC_CheckField, 7, 1, 1, 174, 17, 0, // Skip to: 10959
/* 6433 */    MCD_OPC_Decode, 193, 7, 20, // Opcode: ST_B_bo_r
/* 6437 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 6453
/* 6442 */    MCD_OPC_CheckField, 7, 1, 0, 158, 17, 0, // Skip to: 10959
/* 6449 */    MCD_OPC_Decode, 133, 4, 20, // Opcode: LD_BU_bo_r
/* 6453 */    MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 6479
/* 6458 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6461 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6470
/* 6466 */    MCD_OPC_Decode, 170, 4, 20, // Opcode: LD_H_bo_r
/* 6470 */    MCD_OPC_FilterValue, 1, 132, 17, 0, // Skip to: 10959
/* 6475 */    MCD_OPC_Decode, 216, 7, 20, // Opcode: ST_H_bo_r
/* 6479 */    MCD_OPC_FilterValue, 3, 11, 0, 0, // Skip to: 6495
/* 6484 */    MCD_OPC_CheckField, 7, 1, 0, 116, 17, 0, // Skip to: 10959
/* 6491 */    MCD_OPC_Decode, 163, 4, 20, // Opcode: LD_HU_bo_r
/* 6495 */    MCD_OPC_FilterValue, 4, 21, 0, 0, // Skip to: 6521
/* 6500 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6503 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6512
/* 6508 */    MCD_OPC_Decode, 187, 4, 20, // Opcode: LD_W_bo_r
/* 6512 */    MCD_OPC_FilterValue, 1, 90, 17, 0, // Skip to: 10959
/* 6517 */    MCD_OPC_Decode, 234, 7, 20, // Opcode: ST_W_bo_r
/* 6521 */    MCD_OPC_FilterValue, 5, 21, 0, 0, // Skip to: 6547
/* 6526 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6529 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6538
/* 6534 */    MCD_OPC_Decode, 157, 4, 20, // Opcode: LD_D_bo_r
/* 6538 */    MCD_OPC_FilterValue, 1, 64, 17, 0, // Skip to: 10959
/* 6543 */    MCD_OPC_Decode, 210, 7, 20, // Opcode: ST_D_bo_r
/* 6547 */    MCD_OPC_FilterValue, 6, 21, 0, 0, // Skip to: 6573
/* 6552 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6555 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6564
/* 6560 */    MCD_OPC_Decode, 249, 3, 20, // Opcode: LD_A_bo_r
/* 6564 */    MCD_OPC_FilterValue, 1, 38, 17, 0, // Skip to: 10959
/* 6569 */    MCD_OPC_Decode, 181, 7, 20, // Opcode: ST_A_bo_r
/* 6573 */    MCD_OPC_FilterValue, 7, 21, 0, 0, // Skip to: 6599
/* 6578 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6581 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6590
/* 6586 */    MCD_OPC_Decode, 151, 4, 20, // Opcode: LD_DA_bo_r
/* 6590 */    MCD_OPC_FilterValue, 1, 12, 17, 0, // Skip to: 10959
/* 6595 */    MCD_OPC_Decode, 204, 7, 20, // Opcode: ST_DA_bo_r
/* 6599 */    MCD_OPC_FilterValue, 8, 21, 0, 0, // Skip to: 6625
/* 6604 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6607 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6616
/* 6612 */    MCD_OPC_Decode, 181, 4, 20, // Opcode: LD_Q_bo_r
/* 6616 */    MCD_OPC_FilterValue, 1, 242, 16, 0, // Skip to: 10959
/* 6621 */    MCD_OPC_Decode, 227, 7, 20, // Opcode: ST_Q_bo_r
/* 6625 */    MCD_OPC_FilterValue, 11, 11, 0, 0, // Skip to: 6641
/* 6630 */    MCD_OPC_CheckField, 7, 1, 1, 226, 16, 0, // Skip to: 10959
/* 6637 */    MCD_OPC_Decode, 201, 2, 20, // Opcode: CACHEI_W_bo_r
/* 6641 */    MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 6657
/* 6646 */    MCD_OPC_CheckField, 7, 1, 1, 210, 16, 0, // Skip to: 10959
/* 6653 */    MCD_OPC_Decode, 216, 2, 20, // Opcode: CACHE_W_bo_r
/* 6657 */    MCD_OPC_FilterValue, 13, 11, 0, 0, // Skip to: 6673
/* 6662 */    MCD_OPC_CheckField, 7, 1, 1, 194, 16, 0, // Skip to: 10959
/* 6669 */    MCD_OPC_Decode, 211, 2, 20, // Opcode: CACHE_WI_bo_r
/* 6673 */    MCD_OPC_FilterValue, 14, 11, 0, 0, // Skip to: 6689
/* 6678 */    MCD_OPC_CheckField, 7, 1, 1, 178, 16, 0, // Skip to: 10959
/* 6685 */    MCD_OPC_Decode, 206, 2, 20, // Opcode: CACHE_I_bo_r
/* 6689 */    MCD_OPC_FilterValue, 16, 11, 0, 0, // Skip to: 6705
/* 6694 */    MCD_OPC_CheckField, 7, 1, 1, 162, 16, 0, // Skip to: 10959
/* 6701 */    MCD_OPC_Decode, 190, 7, 20, // Opcode: ST_B_bo_c
/* 6705 */    MCD_OPC_FilterValue, 17, 11, 0, 0, // Skip to: 6721
/* 6710 */    MCD_OPC_CheckField, 7, 1, 0, 146, 16, 0, // Skip to: 10959
/* 6717 */    MCD_OPC_Decode, 130, 4, 20, // Opcode: LD_BU_bo_c
/* 6721 */    MCD_OPC_FilterValue, 18, 21, 0, 0, // Skip to: 6747
/* 6726 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6729 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6738
/* 6734 */    MCD_OPC_Decode, 167, 4, 20, // Opcode: LD_H_bo_c
/* 6738 */    MCD_OPC_FilterValue, 1, 120, 16, 0, // Skip to: 10959
/* 6743 */    MCD_OPC_Decode, 213, 7, 20, // Opcode: ST_H_bo_c
/* 6747 */    MCD_OPC_FilterValue, 19, 11, 0, 0, // Skip to: 6763
/* 6752 */    MCD_OPC_CheckField, 7, 1, 0, 104, 16, 0, // Skip to: 10959
/* 6759 */    MCD_OPC_Decode, 160, 4, 20, // Opcode: LD_HU_bo_c
/* 6763 */    MCD_OPC_FilterValue, 20, 21, 0, 0, // Skip to: 6789
/* 6768 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6771 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6780
/* 6776 */    MCD_OPC_Decode, 184, 4, 20, // Opcode: LD_W_bo_c
/* 6780 */    MCD_OPC_FilterValue, 1, 78, 16, 0, // Skip to: 10959
/* 6785 */    MCD_OPC_Decode, 231, 7, 20, // Opcode: ST_W_bo_c
/* 6789 */    MCD_OPC_FilterValue, 21, 21, 0, 0, // Skip to: 6815
/* 6794 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6797 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6806
/* 6802 */    MCD_OPC_Decode, 154, 4, 20, // Opcode: LD_D_bo_c
/* 6806 */    MCD_OPC_FilterValue, 1, 52, 16, 0, // Skip to: 10959
/* 6811 */    MCD_OPC_Decode, 207, 7, 20, // Opcode: ST_D_bo_c
/* 6815 */    MCD_OPC_FilterValue, 22, 21, 0, 0, // Skip to: 6841
/* 6820 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6823 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6832
/* 6828 */    MCD_OPC_Decode, 246, 3, 20, // Opcode: LD_A_bo_c
/* 6832 */    MCD_OPC_FilterValue, 1, 26, 16, 0, // Skip to: 10959
/* 6837 */    MCD_OPC_Decode, 178, 7, 20, // Opcode: ST_A_bo_c
/* 6841 */    MCD_OPC_FilterValue, 23, 21, 0, 0, // Skip to: 6867
/* 6846 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6849 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6858
/* 6854 */    MCD_OPC_Decode, 148, 4, 20, // Opcode: LD_DA_bo_c
/* 6858 */    MCD_OPC_FilterValue, 1, 0, 16, 0, // Skip to: 10959
/* 6863 */    MCD_OPC_Decode, 201, 7, 20, // Opcode: ST_DA_bo_c
/* 6867 */    MCD_OPC_FilterValue, 24, 21, 0, 0, // Skip to: 6893
/* 6872 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6875 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6884
/* 6880 */    MCD_OPC_Decode, 178, 4, 20, // Opcode: LD_Q_bo_c
/* 6884 */    MCD_OPC_FilterValue, 1, 230, 15, 0, // Skip to: 10959
/* 6889 */    MCD_OPC_Decode, 224, 7, 20, // Opcode: ST_Q_bo_c
/* 6893 */    MCD_OPC_FilterValue, 27, 11, 0, 0, // Skip to: 6909
/* 6898 */    MCD_OPC_CheckField, 7, 1, 1, 214, 15, 0, // Skip to: 10959
/* 6905 */    MCD_OPC_Decode, 198, 2, 20, // Opcode: CACHEI_W_bo_c
/* 6909 */    MCD_OPC_FilterValue, 28, 11, 0, 0, // Skip to: 6925
/* 6914 */    MCD_OPC_CheckField, 7, 1, 1, 198, 15, 0, // Skip to: 10959
/* 6921 */    MCD_OPC_Decode, 213, 2, 20, // Opcode: CACHE_W_bo_c
/* 6925 */    MCD_OPC_FilterValue, 29, 11, 0, 0, // Skip to: 6941
/* 6930 */    MCD_OPC_CheckField, 7, 1, 1, 182, 15, 0, // Skip to: 10959
/* 6937 */    MCD_OPC_Decode, 208, 2, 20, // Opcode: CACHE_WI_bo_c
/* 6941 */    MCD_OPC_FilterValue, 30, 173, 15, 0, // Skip to: 10959
/* 6946 */    MCD_OPC_CheckField, 7, 1, 1, 166, 15, 0, // Skip to: 10959
/* 6953 */    MCD_OPC_Decode, 203, 2, 20, // Opcode: CACHE_I_bo_c
/* 6957 */    MCD_OPC_FilterValue, 43, 161, 0, 0, // Skip to: 7123
/* 6962 */    MCD_OPC_ExtractField, 21, 3,  // Inst{23-21} ...
/* 6965 */    MCD_OPC_FilterValue, 0, 38, 0, 0, // Skip to: 7008
/* 6970 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6973 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 6999
/* 6978 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 6981 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6990
/* 6986 */    MCD_OPC_Decode, 221, 2, 33, // Opcode: CADD_rrr
/* 6990 */    MCD_OPC_FilterValue, 4, 124, 15, 0, // Skip to: 10959
/* 6995 */    MCD_OPC_Decode, 218, 2, 33, // Opcode: CADDN_rrr
/* 6999 */    MCD_OPC_FilterValue, 1, 115, 15, 0, // Skip to: 10959
/* 7004 */    MCD_OPC_Decode, 220, 2, 25, // Opcode: CADD_rcr
/* 7008 */    MCD_OPC_FilterValue, 1, 38, 0, 0, // Skip to: 7051
/* 7013 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7016 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 7042
/* 7021 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 7024 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7033
/* 7029 */    MCD_OPC_Decode, 246, 2, 33, // Opcode: CSUB_rrr
/* 7033 */    MCD_OPC_FilterValue, 4, 81, 15, 0, // Skip to: 10959
/* 7038 */    MCD_OPC_Decode, 245, 2, 33, // Opcode: CSUBN_rrr
/* 7042 */    MCD_OPC_FilterValue, 1, 72, 15, 0, // Skip to: 10959
/* 7047 */    MCD_OPC_Decode, 217, 2, 25, // Opcode: CADDN_rcr
/* 7051 */    MCD_OPC_FilterValue, 2, 35, 0, 0, // Skip to: 7091
/* 7056 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 7059 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7075
/* 7064 */    MCD_OPC_CheckField, 7, 1, 0, 48, 15, 0, // Skip to: 10959
/* 7071 */    MCD_OPC_Decode, 138, 7, 33, // Opcode: SEL_rrr
/* 7075 */    MCD_OPC_FilterValue, 4, 39, 15, 0, // Skip to: 10959
/* 7080 */    MCD_OPC_CheckField, 7, 1, 0, 32, 15, 0, // Skip to: 10959
/* 7087 */    MCD_OPC_Decode, 136, 7, 33, // Opcode: SELN_rrr
/* 7091 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 7107
/* 7096 */    MCD_OPC_CheckField, 7, 1, 1, 16, 15, 0, // Skip to: 10959
/* 7103 */    MCD_OPC_Decode, 137, 7, 25, // Opcode: SEL_rcr
/* 7107 */    MCD_OPC_FilterValue, 5, 7, 15, 0, // Skip to: 10959
/* 7112 */    MCD_OPC_CheckField, 7, 1, 1, 0, 15, 0, // Skip to: 10959
/* 7119 */    MCD_OPC_Decode, 135, 7, 25, // Opcode: SELN_rcr
/* 7123 */    MCD_OPC_FilterValue, 45, 102, 0, 0, // Skip to: 7230
/* 7128 */    MCD_OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 7131 */    MCD_OPC_FilterValue, 0, 38, 0, 0, // Skip to: 7174
/* 7136 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7139 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 7165
/* 7144 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 7147 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7156
/* 7152 */    MCD_OPC_Decode, 224, 2, 15, // Opcode: CALLI_rr
/* 7156 */    MCD_OPC_FilterValue, 4, 214, 14, 0, // Skip to: 10959
/* 7161 */    MCD_OPC_Decode, 158, 3, 15, // Opcode: FCALLA_i
/* 7165 */    MCD_OPC_FilterValue, 1, 205, 14, 0, // Skip to: 10959
/* 7170 */    MCD_OPC_Decode, 187, 2, 22, // Opcode: BISR_rc
/* 7174 */    MCD_OPC_FilterValue, 1, 35, 0, 0, // Skip to: 7214
/* 7179 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 7182 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7198
/* 7187 */    MCD_OPC_CheckField, 7, 1, 0, 181, 14, 0, // Skip to: 10959
/* 7194 */    MCD_OPC_Decode, 202, 3, 15, // Opcode: JLI_rr
/* 7198 */    MCD_OPC_FilterValue, 4, 172, 14, 0, // Skip to: 10959
/* 7203 */    MCD_OPC_CheckField, 7, 1, 0, 165, 14, 0, // Skip to: 10959
/* 7210 */    MCD_OPC_Decode, 198, 3, 15, // Opcode: JI_rr
/* 7214 */    MCD_OPC_FilterValue, 4, 156, 14, 0, // Skip to: 10959
/* 7219 */    MCD_OPC_CheckField, 7, 1, 1, 149, 14, 0, // Skip to: 10959
/* 7226 */    MCD_OPC_Decode, 139, 8, 22, // Opcode: SYSCALL_rc
/* 7230 */    MCD_OPC_FilterValue, 47, 18, 0, 0, // Skip to: 7253
/* 7235 */    MCD_OPC_CheckField, 12, 20, 0, 133, 14, 0, // Skip to: 10959
/* 7242 */    MCD_OPC_CheckField, 7, 1, 0, 126, 14, 0, // Skip to: 10959
/* 7249 */    MCD_OPC_Decode, 250, 6, 14, // Opcode: RSTV_sys
/* 7253 */    MCD_OPC_FilterValue, 51, 69, 1, 0, // Skip to: 7583
/* 7258 */    MCD_OPC_ExtractField, 21, 3,  // Inst{23-21} ...
/* 7261 */    MCD_OPC_FilterValue, 1, 84, 0, 0, // Skip to: 7350
/* 7266 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7269 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7278
/* 7274 */    MCD_OPC_Decode, 166, 6, 25, // Opcode: MSUB_rcr
/* 7278 */    MCD_OPC_FilterValue, 1, 92, 14, 0, // Skip to: 10959
/* 7283 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 7286 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 7302
/* 7291 */    MCD_OPC_CheckField, 24, 4, 0, 77, 14, 0, // Skip to: 10959
/* 7298 */    MCD_OPC_Decode, 176, 6, 24, // Opcode: MULR_H_rr1_UL2e
/* 7302 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 7318
/* 7307 */    MCD_OPC_CheckField, 24, 4, 0, 61, 14, 0, // Skip to: 10959
/* 7314 */    MCD_OPC_Decode, 175, 6, 24, // Opcode: MULR_H_rr1_LU2e
/* 7318 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 7334
/* 7323 */    MCD_OPC_CheckField, 24, 4, 0, 45, 14, 0, // Skip to: 10959
/* 7330 */    MCD_OPC_Decode, 174, 6, 24, // Opcode: MULR_H_rr1_LL2e
/* 7334 */    MCD_OPC_FilterValue, 7, 36, 14, 0, // Skip to: 10959
/* 7339 */    MCD_OPC_CheckField, 24, 4, 0, 29, 14, 0, // Skip to: 10959
/* 7346 */    MCD_OPC_Decode, 177, 6, 24, // Opcode: MULR_H_rr1_UU2e
/* 7350 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 7366
/* 7355 */    MCD_OPC_CheckField, 7, 1, 0, 13, 14, 0, // Skip to: 10959
/* 7362 */    MCD_OPC_Decode, 164, 6, 25, // Opcode: MSUB_U_rcr
/* 7366 */    MCD_OPC_FilterValue, 3, 148, 0, 0, // Skip to: 7519
/* 7371 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7374 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7383
/* 7379 */    MCD_OPC_Decode, 167, 6, 25, // Opcode: MSUB_rcr_e
/* 7383 */    MCD_OPC_FilterValue, 1, 243, 13, 0, // Skip to: 10959
/* 7388 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 7391 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7407
/* 7396 */    MCD_OPC_CheckField, 24, 4, 0, 228, 13, 0, // Skip to: 10959
/* 7403 */    MCD_OPC_Decode, 186, 6, 24, // Opcode: MUL_H_rr1_UL2e
/* 7407 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 7423
/* 7412 */    MCD_OPC_CheckField, 24, 4, 0, 212, 13, 0, // Skip to: 10959
/* 7419 */    MCD_OPC_Decode, 185, 6, 24, // Opcode: MUL_H_rr1_LU2e
/* 7423 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 7439
/* 7428 */    MCD_OPC_CheckField, 24, 4, 0, 196, 13, 0, // Skip to: 10959
/* 7435 */    MCD_OPC_Decode, 184, 6, 24, // Opcode: MUL_H_rr1_LL2e
/* 7439 */    MCD_OPC_FilterValue, 3, 11, 0, 0, // Skip to: 7455
/* 7444 */    MCD_OPC_CheckField, 24, 4, 0, 180, 13, 0, // Skip to: 10959
/* 7451 */    MCD_OPC_Decode, 187, 6, 24, // Opcode: MUL_H_rr1_UU2e
/* 7455 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 7471
/* 7460 */    MCD_OPC_CheckField, 24, 4, 0, 164, 13, 0, // Skip to: 10959
/* 7467 */    MCD_OPC_Decode, 172, 6, 24, // Opcode: MULM_H_rr1_UL2e
/* 7471 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 7487
/* 7476 */    MCD_OPC_CheckField, 24, 4, 0, 148, 13, 0, // Skip to: 10959
/* 7483 */    MCD_OPC_Decode, 171, 6, 24, // Opcode: MULM_H_rr1_LU2e
/* 7487 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 7503
/* 7492 */    MCD_OPC_CheckField, 24, 4, 0, 132, 13, 0, // Skip to: 10959
/* 7499 */    MCD_OPC_Decode, 170, 6, 24, // Opcode: MULM_H_rr1_LL2e
/* 7503 */    MCD_OPC_FilterValue, 7, 123, 13, 0, // Skip to: 10959
/* 7508 */    MCD_OPC_CheckField, 24, 4, 0, 116, 13, 0, // Skip to: 10959
/* 7515 */    MCD_OPC_Decode, 173, 6, 24, // Opcode: MULM_H_rr1_UU2e
/* 7519 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 7535
/* 7524 */    MCD_OPC_CheckField, 7, 1, 0, 100, 13, 0, // Skip to: 10959
/* 7531 */    MCD_OPC_Decode, 142, 6, 25, // Opcode: MSUBS_U_rcr
/* 7535 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 7551
/* 7540 */    MCD_OPC_CheckField, 7, 1, 0, 84, 13, 0, // Skip to: 10959
/* 7547 */    MCD_OPC_Decode, 146, 6, 25, // Opcode: MSUBS_rcr
/* 7551 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 7567
/* 7556 */    MCD_OPC_CheckField, 7, 1, 0, 68, 13, 0, // Skip to: 10959
/* 7563 */    MCD_OPC_Decode, 143, 6, 25, // Opcode: MSUBS_U_rcr_e
/* 7567 */    MCD_OPC_FilterValue, 7, 59, 13, 0, // Skip to: 10959
/* 7572 */    MCD_OPC_CheckField, 7, 1, 0, 52, 13, 0, // Skip to: 10959
/* 7579 */    MCD_OPC_Decode, 147, 6, 25, // Opcode: MSUBS_rcr_e
/* 7583 */    MCD_OPC_FilterValue, 53, 11, 0, 0, // Skip to: 7599
/* 7588 */    MCD_OPC_CheckField, 7, 1, 1, 36, 13, 0, // Skip to: 10959
/* 7595 */    MCD_OPC_Decode, 182, 7, 29, // Opcode: ST_A_bol
/* 7599 */    MCD_OPC_FilterValue, 55, 87, 0, 0, // Skip to: 7691
/* 7604 */    MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 7607 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 7633
/* 7612 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7615 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7624
/* 7620 */    MCD_OPC_Decode, 174, 3, 34, // Opcode: INSERT_rrpw
/* 7624 */    MCD_OPC_FilterValue, 1, 2, 13, 0, // Skip to: 10959
/* 7629 */    MCD_OPC_Decode, 171, 3, 35, // Opcode: INSERT_rcpw
/* 7633 */    MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 7659
/* 7638 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7641 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7650
/* 7646 */    MCD_OPC_Decode, 169, 3, 34, // Opcode: IMASK_rrpw
/* 7650 */    MCD_OPC_FilterValue, 1, 232, 12, 0, // Skip to: 10959
/* 7655 */    MCD_OPC_Decode, 167, 3, 35, // Opcode: IMASK_rcpw
/* 7659 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 7675
/* 7664 */    MCD_OPC_CheckField, 7, 1, 0, 216, 12, 0, // Skip to: 10959
/* 7671 */    MCD_OPC_Decode, 154, 3, 34, // Opcode: EXTR_rrpw
/* 7675 */    MCD_OPC_FilterValue, 3, 207, 12, 0, // Skip to: 10959
/* 7680 */    MCD_OPC_CheckField, 7, 1, 0, 200, 12, 0, // Skip to: 10959
/* 7687 */    MCD_OPC_Decode, 151, 3, 34, // Opcode: EXTR_U_rrpw
/* 7691 */    MCD_OPC_FilterValue, 57, 21, 0, 0, // Skip to: 7717
/* 7696 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7699 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7708
/* 7704 */    MCD_OPC_Decode, 134, 4, 29, // Opcode: LD_BU_bol
/* 7708 */    MCD_OPC_FilterValue, 1, 174, 12, 0, // Skip to: 10959
/* 7713 */    MCD_OPC_Decode, 164, 4, 29, // Opcode: LD_HU_bol
/* 7717 */    MCD_OPC_FilterValue, 59, 21, 0, 0, // Skip to: 7743
/* 7722 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7725 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7734
/* 7730 */    MCD_OPC_Decode, 201, 5, 23, // Opcode: MOV_rlcDc
/* 7734 */    MCD_OPC_FilterValue, 1, 148, 12, 0, // Skip to: 10959
/* 7739 */    MCD_OPC_Decode, 200, 5, 23, // Opcode: MOV_U_rlc
/* 7743 */    MCD_OPC_FilterValue, 61, 35, 0, 0, // Skip to: 7783
/* 7748 */    MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 7751 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7767
/* 7756 */    MCD_OPC_CheckField, 7, 1, 1, 124, 12, 0, // Skip to: 10959
/* 7763 */    MCD_OPC_Decode, 226, 3, 31, // Opcode: JZ_A_brr
/* 7767 */    MCD_OPC_FilterValue, 1, 115, 12, 0, // Skip to: 10959
/* 7772 */    MCD_OPC_CheckField, 7, 1, 1, 108, 12, 0, // Skip to: 10959
/* 7779 */    MCD_OPC_Decode, 220, 3, 31, // Opcode: JNZ_A_brr
/* 7783 */    MCD_OPC_FilterValue, 63, 55, 0, 0, // Skip to: 7843
/* 7788 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7791 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 7817
/* 7796 */    MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 7799 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7808
/* 7804 */    MCD_OPC_Decode, 207, 3, 31, // Opcode: JLT_brr
/* 7808 */    MCD_OPC_FilterValue, 1, 74, 12, 0, // Skip to: 10959
/* 7813 */    MCD_OPC_Decode, 205, 3, 31, // Opcode: JLT_U_brr
/* 7817 */    MCD_OPC_FilterValue, 1, 65, 12, 0, // Skip to: 10959
/* 7822 */    MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 7825 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7834
/* 7830 */    MCD_OPC_Decode, 206, 3, 32, // Opcode: JLT_brc
/* 7834 */    MCD_OPC_FilterValue, 1, 48, 12, 0, // Skip to: 10959
/* 7839 */    MCD_OPC_Decode, 204, 3, 32, // Opcode: JLT_U_brc
/* 7843 */    MCD_OPC_FilterValue, 67, 219, 2, 0, // Skip to: 8579
/* 7848 */    MCD_OPC_ExtractField, 18, 6,  // Inst{23-18} ...
/* 7851 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7867
/* 7856 */    MCD_OPC_CheckField, 7, 1, 0, 24, 12, 0, // Skip to: 10959
/* 7863 */    MCD_OPC_Decode, 161, 5, 17, // Opcode: MADD_Q_rrr1_U
/* 7867 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 7883
/* 7872 */    MCD_OPC_CheckField, 7, 1, 0, 8, 12, 0, // Skip to: 10959
/* 7879 */    MCD_OPC_Decode, 159, 5, 17, // Opcode: MADD_Q_rrr1_L
/* 7883 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 7899
/* 7888 */    MCD_OPC_CheckField, 7, 1, 0, 248, 11, 0, // Skip to: 10959
/* 7895 */    MCD_OPC_Decode, 158, 5, 17, // Opcode: MADD_Q_rrr1
/* 7899 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 7915
/* 7904 */    MCD_OPC_CheckField, 7, 1, 0, 232, 11, 0, // Skip to: 10959
/* 7911 */    MCD_OPC_Decode, 162, 5, 17, // Opcode: MADD_Q_rrr1_U_U
/* 7915 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 7931
/* 7920 */    MCD_OPC_CheckField, 7, 1, 0, 216, 11, 0, // Skip to: 10959
/* 7927 */    MCD_OPC_Decode, 160, 5, 17, // Opcode: MADD_Q_rrr1_L_L
/* 7931 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 7947
/* 7936 */    MCD_OPC_CheckField, 7, 1, 0, 200, 11, 0, // Skip to: 10959
/* 7943 */    MCD_OPC_Decode, 235, 4, 17, // Opcode: MADDR_Q_rrr1_U_U
/* 7947 */    MCD_OPC_FilterValue, 7, 11, 0, 0, // Skip to: 7963
/* 7952 */    MCD_OPC_CheckField, 7, 1, 0, 184, 11, 0, // Skip to: 10959
/* 7959 */    MCD_OPC_Decode, 234, 4, 17, // Opcode: MADDR_Q_rrr1_L_L
/* 7963 */    MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 7979
/* 7968 */    MCD_OPC_CheckField, 7, 1, 1, 168, 11, 0, // Skip to: 10959
/* 7975 */    MCD_OPC_Decode, 250, 4, 17, // Opcode: MADDSUR_H_rrr1_UL
/* 7979 */    MCD_OPC_FilterValue, 13, 11, 0, 0, // Skip to: 7995
/* 7984 */    MCD_OPC_CheckField, 7, 1, 1, 152, 11, 0, // Skip to: 10959
/* 7991 */    MCD_OPC_Decode, 249, 4, 17, // Opcode: MADDSUR_H_rrr1_LU
/* 7995 */    MCD_OPC_FilterValue, 14, 11, 0, 0, // Skip to: 8011
/* 8000 */    MCD_OPC_CheckField, 7, 1, 1, 136, 11, 0, // Skip to: 10959
/* 8007 */    MCD_OPC_Decode, 248, 4, 17, // Opcode: MADDSUR_H_rrr1_LL
/* 8011 */    MCD_OPC_FilterValue, 15, 11, 0, 0, // Skip to: 8027
/* 8016 */    MCD_OPC_CheckField, 7, 1, 1, 120, 11, 0, // Skip to: 10959
/* 8023 */    MCD_OPC_Decode, 251, 4, 17, // Opcode: MADDSUR_H_rrr1_UU
/* 8027 */    MCD_OPC_FilterValue, 24, 21, 0, 0, // Skip to: 8053
/* 8032 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8035 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8044
/* 8040 */    MCD_OPC_Decode, 166, 5, 17, // Opcode: MADD_Q_rrr1_e_U
/* 8044 */    MCD_OPC_FilterValue, 1, 94, 11, 0, // Skip to: 10959
/* 8049 */    MCD_OPC_Decode, 130, 5, 17, // Opcode: MADDSU_H_rrr1_UL
/* 8053 */    MCD_OPC_FilterValue, 25, 21, 0, 0, // Skip to: 8079
/* 8058 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8061 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8070
/* 8066 */    MCD_OPC_Decode, 164, 5, 17, // Opcode: MADD_Q_rrr1_e_L
/* 8070 */    MCD_OPC_FilterValue, 1, 68, 11, 0, // Skip to: 10959
/* 8075 */    MCD_OPC_Decode, 129, 5, 17, // Opcode: MADDSU_H_rrr1_LU
/* 8079 */    MCD_OPC_FilterValue, 26, 11, 0, 0, // Skip to: 8095
/* 8084 */    MCD_OPC_CheckField, 7, 1, 1, 52, 11, 0, // Skip to: 10959
/* 8091 */    MCD_OPC_Decode, 128, 5, 17, // Opcode: MADDSU_H_rrr1_LL
/* 8095 */    MCD_OPC_FilterValue, 27, 21, 0, 0, // Skip to: 8121
/* 8100 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8103 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8112
/* 8108 */    MCD_OPC_Decode, 163, 5, 17, // Opcode: MADD_Q_rrr1_e
/* 8112 */    MCD_OPC_FilterValue, 1, 26, 11, 0, // Skip to: 10959
/* 8117 */    MCD_OPC_Decode, 131, 5, 17, // Opcode: MADDSU_H_rrr1_UU
/* 8121 */    MCD_OPC_FilterValue, 28, 21, 0, 0, // Skip to: 8147
/* 8126 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8129 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8138
/* 8134 */    MCD_OPC_Decode, 167, 5, 17, // Opcode: MADD_Q_rrr1_e_U_U
/* 8138 */    MCD_OPC_FilterValue, 1, 0, 11, 0, // Skip to: 10959
/* 8143 */    MCD_OPC_Decode, 242, 4, 17, // Opcode: MADDSUM_H_rrr1_UL
/* 8147 */    MCD_OPC_FilterValue, 29, 21, 0, 0, // Skip to: 8173
/* 8152 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8155 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8164
/* 8160 */    MCD_OPC_Decode, 165, 5, 17, // Opcode: MADD_Q_rrr1_e_L_L
/* 8164 */    MCD_OPC_FilterValue, 1, 230, 10, 0, // Skip to: 10959
/* 8169 */    MCD_OPC_Decode, 241, 4, 17, // Opcode: MADDSUM_H_rrr1_LU
/* 8173 */    MCD_OPC_FilterValue, 30, 21, 0, 0, // Skip to: 8199
/* 8178 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8181 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8190
/* 8186 */    MCD_OPC_Decode, 229, 4, 17, // Opcode: MADDR_H_rrr1_DcEdDaDbUL
/* 8190 */    MCD_OPC_FilterValue, 1, 204, 10, 0, // Skip to: 10959
/* 8195 */    MCD_OPC_Decode, 240, 4, 17, // Opcode: MADDSUM_H_rrr1_LL
/* 8199 */    MCD_OPC_FilterValue, 31, 11, 0, 0, // Skip to: 8215
/* 8204 */    MCD_OPC_CheckField, 7, 1, 1, 188, 10, 0, // Skip to: 10959
/* 8211 */    MCD_OPC_Decode, 243, 4, 17, // Opcode: MADDSUM_H_rrr1_UU
/* 8215 */    MCD_OPC_FilterValue, 32, 11, 0, 0, // Skip to: 8231
/* 8220 */    MCD_OPC_CheckField, 7, 1, 0, 172, 10, 0, // Skip to: 10959
/* 8227 */    MCD_OPC_Decode, 139, 5, 17, // Opcode: MADDS_Q_rrr1_U
/* 8231 */    MCD_OPC_FilterValue, 33, 11, 0, 0, // Skip to: 8247
/* 8236 */    MCD_OPC_CheckField, 7, 1, 0, 156, 10, 0, // Skip to: 10959
/* 8243 */    MCD_OPC_Decode, 137, 5, 17, // Opcode: MADDS_Q_rrr1_L
/* 8247 */    MCD_OPC_FilterValue, 34, 11, 0, 0, // Skip to: 8263
/* 8252 */    MCD_OPC_CheckField, 7, 1, 0, 140, 10, 0, // Skip to: 10959
/* 8259 */    MCD_OPC_Decode, 136, 5, 17, // Opcode: MADDS_Q_rrr1
/* 8263 */    MCD_OPC_FilterValue, 36, 11, 0, 0, // Skip to: 8279
/* 8268 */    MCD_OPC_CheckField, 7, 1, 0, 124, 10, 0, // Skip to: 10959
/* 8275 */    MCD_OPC_Decode, 140, 5, 17, // Opcode: MADDS_Q_rrr1_U_U
/* 8279 */    MCD_OPC_FilterValue, 37, 11, 0, 0, // Skip to: 8295
/* 8284 */    MCD_OPC_CheckField, 7, 1, 0, 108, 10, 0, // Skip to: 10959
/* 8291 */    MCD_OPC_Decode, 138, 5, 17, // Opcode: MADDS_Q_rrr1_L_L
/* 8295 */    MCD_OPC_FilterValue, 38, 11, 0, 0, // Skip to: 8311
/* 8300 */    MCD_OPC_CheckField, 7, 1, 0, 92, 10, 0, // Skip to: 10959
/* 8307 */    MCD_OPC_Decode, 228, 4, 17, // Opcode: MADDRS_Q_rrr1_U_U
/* 8311 */    MCD_OPC_FilterValue, 39, 11, 0, 0, // Skip to: 8327
/* 8316 */    MCD_OPC_CheckField, 7, 1, 0, 76, 10, 0, // Skip to: 10959
/* 8323 */    MCD_OPC_Decode, 227, 4, 17, // Opcode: MADDRS_Q_rrr1_L_L
/* 8327 */    MCD_OPC_FilterValue, 44, 11, 0, 0, // Skip to: 8343
/* 8332 */    MCD_OPC_CheckField, 7, 1, 1, 60, 10, 0, // Skip to: 10959
/* 8339 */    MCD_OPC_Decode, 246, 4, 17, // Opcode: MADDSURS_H_rrr1_UL
/* 8343 */    MCD_OPC_FilterValue, 45, 11, 0, 0, // Skip to: 8359
/* 8348 */    MCD_OPC_CheckField, 7, 1, 1, 44, 10, 0, // Skip to: 10959
/* 8355 */    MCD_OPC_Decode, 245, 4, 17, // Opcode: MADDSURS_H_rrr1_LU
/* 8359 */    MCD_OPC_FilterValue, 46, 11, 0, 0, // Skip to: 8375
/* 8364 */    MCD_OPC_CheckField, 7, 1, 1, 28, 10, 0, // Skip to: 10959
/* 8371 */    MCD_OPC_Decode, 244, 4, 17, // Opcode: MADDSURS_H_rrr1_LL
/* 8375 */    MCD_OPC_FilterValue, 47, 11, 0, 0, // Skip to: 8391
/* 8380 */    MCD_OPC_CheckField, 7, 1, 1, 12, 10, 0, // Skip to: 10959
/* 8387 */    MCD_OPC_Decode, 247, 4, 17, // Opcode: MADDSURS_H_rrr1_UU
/* 8391 */    MCD_OPC_FilterValue, 56, 21, 0, 0, // Skip to: 8417
/* 8396 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8399 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8408
/* 8404 */    MCD_OPC_Decode, 144, 5, 17, // Opcode: MADDS_Q_rrr1_e_U
/* 8408 */    MCD_OPC_FilterValue, 1, 242, 9, 0, // Skip to: 10959
/* 8413 */    MCD_OPC_Decode, 254, 4, 17, // Opcode: MADDSUS_H_rrr1_UL
/* 8417 */    MCD_OPC_FilterValue, 57, 21, 0, 0, // Skip to: 8443
/* 8422 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8425 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8434
/* 8430 */    MCD_OPC_Decode, 142, 5, 17, // Opcode: MADDS_Q_rrr1_e_L
/* 8434 */    MCD_OPC_FilterValue, 1, 216, 9, 0, // Skip to: 10959
/* 8439 */    MCD_OPC_Decode, 253, 4, 17, // Opcode: MADDSUS_H_rrr1_LU
/* 8443 */    MCD_OPC_FilterValue, 58, 11, 0, 0, // Skip to: 8459
/* 8448 */    MCD_OPC_CheckField, 7, 1, 1, 200, 9, 0, // Skip to: 10959
/* 8455 */    MCD_OPC_Decode, 252, 4, 17, // Opcode: MADDSUS_H_rrr1_LL
/* 8459 */    MCD_OPC_FilterValue, 59, 21, 0, 0, // Skip to: 8485
/* 8464 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8467 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8476
/* 8472 */    MCD_OPC_Decode, 141, 5, 17, // Opcode: MADDS_Q_rrr1_e
/* 8476 */    MCD_OPC_FilterValue, 1, 174, 9, 0, // Skip to: 10959
/* 8481 */    MCD_OPC_Decode, 255, 4, 17, // Opcode: MADDSUS_H_rrr1_UU
/* 8485 */    MCD_OPC_FilterValue, 60, 21, 0, 0, // Skip to: 8511
/* 8490 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8493 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8502
/* 8498 */    MCD_OPC_Decode, 145, 5, 17, // Opcode: MADDS_Q_rrr1_e_U_U
/* 8502 */    MCD_OPC_FilterValue, 1, 148, 9, 0, // Skip to: 10959
/* 8507 */    MCD_OPC_Decode, 238, 4, 17, // Opcode: MADDSUMS_H_rrr1_UL
/* 8511 */    MCD_OPC_FilterValue, 61, 21, 0, 0, // Skip to: 8537
/* 8516 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8519 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8528
/* 8524 */    MCD_OPC_Decode, 143, 5, 17, // Opcode: MADDS_Q_rrr1_e_L_L
/* 8528 */    MCD_OPC_FilterValue, 1, 122, 9, 0, // Skip to: 10959
/* 8533 */    MCD_OPC_Decode, 237, 4, 17, // Opcode: MADDSUMS_H_rrr1_LU
/* 8537 */    MCD_OPC_FilterValue, 62, 21, 0, 0, // Skip to: 8563
/* 8542 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8545 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8554
/* 8550 */    MCD_OPC_Decode, 222, 4, 17, // Opcode: MADDRS_H_rrr1_DcEdDaDbUL
/* 8554 */    MCD_OPC_FilterValue, 1, 96, 9, 0, // Skip to: 10959
/* 8559 */    MCD_OPC_Decode, 236, 4, 17, // Opcode: MADDSUMS_H_rrr1_LL
/* 8563 */    MCD_OPC_FilterValue, 63, 87, 9, 0, // Skip to: 10959
/* 8568 */    MCD_OPC_CheckField, 7, 1, 1, 80, 9, 0, // Skip to: 10959
/* 8575 */    MCD_OPC_Decode, 239, 4, 17, // Opcode: MADDSUMS_H_rrr1_UU
/* 8579 */    MCD_OPC_FilterValue, 69, 45, 0, 0, // Skip to: 8629
/* 8584 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8587 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 8603
/* 8592 */    MCD_OPC_CheckField, 26, 2, 0, 56, 9, 0, // Skip to: 10959
/* 8599 */    MCD_OPC_Decode, 176, 4, 18, // Opcode: LD_Q_abs
/* 8603 */    MCD_OPC_FilterValue, 1, 47, 9, 0, // Skip to: 10959
/* 8608 */    MCD_OPC_ExtractField, 26, 2,  // Inst{27-26} ...
/* 8611 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8620
/* 8616 */    MCD_OPC_Decode, 194, 4, 18, // Opcode: LEA_abs
/* 8620 */    MCD_OPC_FilterValue, 1, 30, 9, 0, // Skip to: 10959
/* 8625 */    MCD_OPC_Decode, 197, 4, 18, // Opcode: LHA_abs
/* 8629 */    MCD_OPC_FilterValue, 71, 107, 0, 0, // Skip to: 8741
/* 8634 */    MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 8637 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 8663
/* 8642 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8645 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8654
/* 8650 */    MCD_OPC_Decode, 167, 2, 19, // Opcode: AND_AND_T
/* 8654 */    MCD_OPC_FilterValue, 1, 252, 8, 0, // Skip to: 10959
/* 8659 */    MCD_OPC_Decode, 220, 6, 19, // Opcode: OR_AND_T
/* 8663 */    MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 8689
/* 8668 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8671 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8680
/* 8676 */    MCD_OPC_Decode, 181, 2, 19, // Opcode: AND_OR_T
/* 8680 */    MCD_OPC_FilterValue, 1, 226, 8, 0, // Skip to: 10959
/* 8685 */    MCD_OPC_Decode, 234, 6, 19, // Opcode: OR_OR_T
/* 8689 */    MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 8715
/* 8694 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8697 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8706
/* 8702 */    MCD_OPC_Decode, 180, 2, 19, // Opcode: AND_NOR_T
/* 8706 */    MCD_OPC_FilterValue, 1, 200, 8, 0, // Skip to: 10959
/* 8711 */    MCD_OPC_Decode, 233, 6, 19, // Opcode: OR_NOR_T
/* 8715 */    MCD_OPC_FilterValue, 3, 191, 8, 0, // Skip to: 10959
/* 8720 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8723 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8732
/* 8728 */    MCD_OPC_Decode, 166, 2, 19, // Opcode: AND_ANDN_T
/* 8732 */    MCD_OPC_FilterValue, 1, 174, 8, 0, // Skip to: 10959
/* 8737 */    MCD_OPC_Decode, 219, 6, 19, // Opcode: OR_ANDN_T
/* 8741 */    MCD_OPC_FilterValue, 73, 173, 0, 0, // Skip to: 8919
/* 8746 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8749 */    MCD_OPC_FilterValue, 0, 156, 0, 0, // Skip to: 8910
/* 8754 */    MCD_OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 8757 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8766
/* 8762 */    MCD_OPC_Decode, 136, 8, 20, // Opcode: SWAP_W_bo_pos
/* 8766 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 8775
/* 8771 */    MCD_OPC_Decode, 239, 3, 20, // Opcode: LDMST_bo_pos
/* 8775 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 8784
/* 8780 */    MCD_OPC_Decode, 130, 8, 20, // Opcode: SWAPMSK_W_bo_pos
/* 8784 */    MCD_OPC_FilterValue, 3, 4, 0, 0, // Skip to: 8793
/* 8789 */    MCD_OPC_Decode, 238, 2, 20, // Opcode: CMPSWAP_W_bo_pos
/* 8793 */    MCD_OPC_FilterValue, 16, 4, 0, 0, // Skip to: 8802
/* 8798 */    MCD_OPC_Decode, 137, 8, 20, // Opcode: SWAP_W_bo_pre
/* 8802 */    MCD_OPC_FilterValue, 17, 4, 0, 0, // Skip to: 8811
/* 8807 */    MCD_OPC_Decode, 240, 3, 20, // Opcode: LDMST_bo_pre
/* 8811 */    MCD_OPC_FilterValue, 18, 4, 0, 0, // Skip to: 8820
/* 8816 */    MCD_OPC_Decode, 131, 8, 20, // Opcode: SWAPMSK_W_bo_pre
/* 8820 */    MCD_OPC_FilterValue, 19, 4, 0, 0, // Skip to: 8829
/* 8825 */    MCD_OPC_Decode, 239, 2, 20, // Opcode: CMPSWAP_W_bo_pre
/* 8829 */    MCD_OPC_FilterValue, 32, 4, 0, 0, // Skip to: 8838
/* 8834 */    MCD_OPC_Decode, 134, 8, 20, // Opcode: SWAP_W_bo_bso
/* 8838 */    MCD_OPC_FilterValue, 33, 4, 0, 0, // Skip to: 8847
/* 8843 */    MCD_OPC_Decode, 237, 3, 20, // Opcode: LDMST_bo_bso
/* 8847 */    MCD_OPC_FilterValue, 34, 4, 0, 0, // Skip to: 8856
/* 8852 */    MCD_OPC_Decode, 128, 8, 20, // Opcode: SWAPMSK_W_bo_bso
/* 8856 */    MCD_OPC_FilterValue, 35, 4, 0, 0, // Skip to: 8865
/* 8861 */    MCD_OPC_Decode, 236, 2, 20, // Opcode: CMPSWAP_W_bo_bso
/* 8865 */    MCD_OPC_FilterValue, 36, 4, 0, 0, // Skip to: 8874
/* 8870 */    MCD_OPC_Decode, 235, 3, 20, // Opcode: LDLCX_bo_bso
/* 8874 */    MCD_OPC_FilterValue, 37, 4, 0, 0, // Skip to: 8883
/* 8879 */    MCD_OPC_Decode, 243, 3, 20, // Opcode: LDUCX_bo_bso
/* 8883 */    MCD_OPC_FilterValue, 38, 4, 0, 0, // Skip to: 8892
/* 8888 */    MCD_OPC_Decode, 173, 7, 20, // Opcode: STLCX_bo_bso
/* 8892 */    MCD_OPC_FilterValue, 39, 4, 0, 0, // Skip to: 8901
/* 8897 */    MCD_OPC_Decode, 175, 7, 20, // Opcode: STUCX_bo_bso
/* 8901 */    MCD_OPC_FilterValue, 40, 5, 8, 0, // Skip to: 10959
/* 8906 */    MCD_OPC_Decode, 195, 4, 20, // Opcode: LEA_bo_bso
/* 8910 */    MCD_OPC_FilterValue, 1, 252, 7, 0, // Skip to: 10959
/* 8915 */    MCD_OPC_Decode, 171, 4, 29, // Opcode: LD_H_bol
/* 8919 */    MCD_OPC_FilterValue, 75, 10, 1, 0, // Skip to: 9190
/* 8924 */    MCD_OPC_ExtractField, 18, 10,  // Inst{27-18} ...
/* 8927 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 8943
/* 8932 */    MCD_OPC_CheckField, 7, 1, 0, 228, 7, 0, // Skip to: 10959
/* 8939 */    MCD_OPC_Decode, 189, 2, 15, // Opcode: BMAERGE_rr
/* 8943 */    MCD_OPC_FilterValue, 8, 11, 0, 0, // Skip to: 8959
/* 8948 */    MCD_OPC_CheckField, 7, 1, 0, 212, 7, 0, // Skip to: 10959
/* 8955 */    MCD_OPC_Decode, 241, 6, 15, // Opcode: PARITY_rr
/* 8959 */    MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 8975
/* 8964 */    MCD_OPC_CheckField, 7, 1, 0, 196, 7, 0, // Skip to: 10959
/* 8971 */    MCD_OPC_Decode, 241, 2, 15, // Opcode: CRC32B_W_rr
/* 8975 */    MCD_OPC_FilterValue, 24, 11, 0, 0, // Skip to: 8991
/* 8980 */    MCD_OPC_CheckField, 7, 1, 0, 180, 7, 0, // Skip to: 10959
/* 8987 */    MCD_OPC_Decode, 243, 2, 15, // Opcode: CRC32_B_rr
/* 8991 */    MCD_OPC_FilterValue, 28, 11, 0, 0, // Skip to: 9007
/* 8996 */    MCD_OPC_CheckField, 7, 1, 0, 164, 7, 0, // Skip to: 10959
/* 9003 */    MCD_OPC_Decode, 242, 2, 15, // Opcode: CRC32L_W_rr
/* 9007 */    MCD_OPC_FilterValue, 32, 11, 0, 0, // Skip to: 9023
/* 9012 */    MCD_OPC_CheckField, 7, 1, 0, 148, 7, 0, // Skip to: 10959
/* 9019 */    MCD_OPC_Decode, 142, 8, 15, // Opcode: UNPACK_rr
/* 9023 */    MCD_OPC_FilterValue, 36, 11, 0, 0, // Skip to: 9039
/* 9028 */    MCD_OPC_CheckField, 7, 1, 0, 132, 7, 0, // Skip to: 10959
/* 9035 */    MCD_OPC_Decode, 190, 2, 15, // Opcode: BSPLIT_rr
/* 9039 */    MCD_OPC_FilterValue, 40, 11, 0, 0, // Skip to: 9055
/* 9044 */    MCD_OPC_CheckField, 7, 1, 0, 116, 7, 0, // Skip to: 10959
/* 9051 */    MCD_OPC_Decode, 133, 3, 15, // Opcode: DVINIT_U_rr
/* 9055 */    MCD_OPC_FilterValue, 104, 11, 0, 0, // Skip to: 9071
/* 9060 */    MCD_OPC_CheckField, 7, 1, 0, 100, 7, 0, // Skip to: 10959
/* 9067 */    MCD_OPC_Decode, 134, 3, 15, // Opcode: DVINIT_rr
/* 9071 */    MCD_OPC_FilterValue, 128, 1, 11, 0, 0, // Skip to: 9088
/* 9077 */    MCD_OPC_CheckField, 7, 1, 0, 83, 7, 0, // Skip to: 10959
/* 9084 */    MCD_OPC_Decode, 254, 2, 15, // Opcode: DIV_rr
/* 9088 */    MCD_OPC_FilterValue, 132, 1, 11, 0, 0, // Skip to: 9105
/* 9094 */    MCD_OPC_CheckField, 7, 1, 0, 66, 7, 0, // Skip to: 10959
/* 9101 */    MCD_OPC_Decode, 253, 2, 15, // Opcode: DIV_U_rr
/* 9105 */    MCD_OPC_FilterValue, 136, 1, 11, 0, 0, // Skip to: 9122
/* 9111 */    MCD_OPC_CheckField, 7, 1, 0, 49, 7, 0, // Skip to: 10959
/* 9118 */    MCD_OPC_Decode, 242, 6, 15, // Opcode: POPCNT_W_rr
/* 9122 */    MCD_OPC_FilterValue, 168, 1, 11, 0, 0, // Skip to: 9139
/* 9128 */    MCD_OPC_CheckField, 7, 1, 0, 32, 7, 0, // Skip to: 10959
/* 9135 */    MCD_OPC_Decode, 131, 3, 15, // Opcode: DVINIT_HU_rr
/* 9139 */    MCD_OPC_FilterValue, 232, 1, 11, 0, 0, // Skip to: 9156
/* 9145 */    MCD_OPC_CheckField, 7, 1, 0, 15, 7, 0, // Skip to: 10959
/* 9152 */    MCD_OPC_Decode, 132, 3, 15, // Opcode: DVINIT_H_rr
/* 9156 */    MCD_OPC_FilterValue, 168, 2, 11, 0, 0, // Skip to: 9173
/* 9162 */    MCD_OPC_CheckField, 7, 1, 0, 254, 6, 0, // Skip to: 10959
/* 9169 */    MCD_OPC_Decode, 129, 3, 15, // Opcode: DVINIT_BU_rr
/* 9173 */    MCD_OPC_FilterValue, 232, 2, 244, 6, 0, // Skip to: 10959
/* 9179 */    MCD_OPC_CheckField, 7, 1, 0, 237, 6, 0, // Skip to: 10959
/* 9186 */    MCD_OPC_Decode, 130, 3, 15, // Opcode: DVINIT_B_rr
/* 9190 */    MCD_OPC_FilterValue, 77, 11, 0, 0, // Skip to: 9206
/* 9195 */    MCD_OPC_CheckField, 7, 1, 0, 221, 6, 0, // Skip to: 10959
/* 9202 */    MCD_OPC_Decode, 182, 5, 23, // Opcode: MFCR_rlc
/* 9206 */    MCD_OPC_FilterValue, 83, 83, 0, 0, // Skip to: 9294
/* 9211 */    MCD_OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 9214 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 9230
/* 9219 */    MCD_OPC_CheckField, 7, 1, 0, 197, 6, 0, // Skip to: 10959
/* 9226 */    MCD_OPC_Decode, 198, 6, 22, // Opcode: MUL_rc
/* 9230 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 9246
/* 9235 */    MCD_OPC_CheckField, 7, 1, 0, 181, 6, 0, // Skip to: 10959
/* 9242 */    MCD_OPC_Decode, 196, 6, 22, // Opcode: MUL_U_rc
/* 9246 */    MCD_OPC_FilterValue, 3, 11, 0, 0, // Skip to: 9262
/* 9251 */    MCD_OPC_CheckField, 7, 1, 0, 165, 6, 0, // Skip to: 10959
/* 9258 */    MCD_OPC_Decode, 199, 6, 22, // Opcode: MUL_rc_e
/* 9262 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 9278
/* 9267 */    MCD_OPC_CheckField, 7, 1, 0, 149, 6, 0, // Skip to: 10959
/* 9274 */    MCD_OPC_Decode, 180, 6, 22, // Opcode: MULS_U_rc
/* 9278 */    MCD_OPC_FilterValue, 5, 140, 6, 0, // Skip to: 10959
/* 9283 */    MCD_OPC_CheckField, 7, 1, 0, 133, 6, 0, // Skip to: 10959
/* 9290 */    MCD_OPC_Decode, 182, 6, 22, // Opcode: MULS_rc
/* 9294 */    MCD_OPC_FilterValue, 85, 18, 0, 0, // Skip to: 9317
/* 9299 */    MCD_OPC_CheckField, 26, 2, 0, 117, 6, 0, // Skip to: 10959
/* 9306 */    MCD_OPC_CheckField, 7, 1, 1, 110, 6, 0, // Skip to: 10959
/* 9313 */    MCD_OPC_Decode, 228, 7, 36, // Opcode: ST_T
/* 9317 */    MCD_OPC_FilterValue, 87, 87, 0, 0, // Skip to: 9409
/* 9322 */    MCD_OPC_ExtractField, 21, 3,  // Inst{23-21} ...
/* 9325 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 9351
/* 9330 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9333 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9342
/* 9338 */    MCD_OPC_Decode, 176, 3, 26, // Opcode: INSERT_rrrw
/* 9342 */    MCD_OPC_FilterValue, 1, 76, 6, 0, // Skip to: 10959
/* 9347 */    MCD_OPC_Decode, 173, 3, 37, // Opcode: INSERT_rcrw
/* 9351 */    MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 9377
/* 9356 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9359 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9368
/* 9364 */    MCD_OPC_Decode, 170, 3, 26, // Opcode: IMASK_rrrw
/* 9368 */    MCD_OPC_FilterValue, 1, 50, 6, 0, // Skip to: 10959
/* 9373 */    MCD_OPC_Decode, 168, 3, 37, // Opcode: IMASK_rcrw
/* 9377 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 9393
/* 9382 */    MCD_OPC_CheckField, 7, 1, 0, 34, 6, 0, // Skip to: 10959
/* 9389 */    MCD_OPC_Decode, 156, 3, 26, // Opcode: EXTR_rrrw
/* 9393 */    MCD_OPC_FilterValue, 3, 25, 6, 0, // Skip to: 10959
/* 9398 */    MCD_OPC_CheckField, 7, 1, 0, 18, 6, 0, // Skip to: 10959
/* 9405 */    MCD_OPC_Decode, 153, 3, 26, // Opcode: EXTR_U_rrrw
/* 9409 */    MCD_OPC_FilterValue, 89, 21, 0, 0, // Skip to: 9435
/* 9414 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9417 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9426
/* 9422 */    MCD_OPC_Decode, 235, 7, 29, // Opcode: ST_W_bol
/* 9426 */    MCD_OPC_FilterValue, 1, 248, 5, 0, // Skip to: 10959
/* 9431 */    MCD_OPC_Decode, 196, 4, 29, // Opcode: LEA_bol
/* 9435 */    MCD_OPC_FilterValue, 93, 21, 0, 0, // Skip to: 9461
/* 9440 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9443 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9452
/* 9448 */    MCD_OPC_Decode, 208, 3, 30, // Opcode: JL_b
/* 9452 */    MCD_OPC_FilterValue, 1, 222, 5, 0, // Skip to: 10959
/* 9457 */    MCD_OPC_Decode, 200, 3, 30, // Opcode: JLA_b
/* 9461 */    MCD_OPC_FilterValue, 95, 55, 0, 0, // Skip to: 9521
/* 9466 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9469 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 9495
/* 9474 */    MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 9477 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9486
/* 9482 */    MCD_OPC_Decode, 187, 3, 31, // Opcode: JEQ_brr
/* 9486 */    MCD_OPC_FilterValue, 1, 188, 5, 0, // Skip to: 10959
/* 9491 */    MCD_OPC_Decode, 215, 3, 31, // Opcode: JNE_brr
/* 9495 */    MCD_OPC_FilterValue, 1, 179, 5, 0, // Skip to: 10959
/* 9500 */    MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 9503 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9512
/* 9508 */    MCD_OPC_Decode, 186, 3, 32, // Opcode: JEQ_brc
/* 9512 */    MCD_OPC_FilterValue, 1, 162, 5, 0, // Skip to: 10959
/* 9517 */    MCD_OPC_Decode, 214, 3, 32, // Opcode: JNE_brc
/* 9521 */    MCD_OPC_FilterValue, 97, 21, 0, 0, // Skip to: 9547
/* 9526 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9529 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9538
/* 9534 */    MCD_OPC_Decode, 159, 3, 30, // Opcode: FCALL_b
/* 9538 */    MCD_OPC_FilterValue, 1, 136, 5, 0, // Skip to: 10959
/* 9543 */    MCD_OPC_Decode, 157, 3, 30, // Opcode: FCALLA_b
/* 9547 */    MCD_OPC_FilterValue, 99, 219, 2, 0, // Skip to: 10283
/* 9552 */    MCD_OPC_ExtractField, 18, 6,  // Inst{23-18} ...
/* 9555 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 9571
/* 9560 */    MCD_OPC_CheckField, 7, 1, 0, 112, 5, 0, // Skip to: 10959
/* 9567 */    MCD_OPC_Decode, 157, 6, 17, // Opcode: MSUB_Q_rrr1_U
/* 9571 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 9587
/* 9576 */    MCD_OPC_CheckField, 7, 1, 0, 96, 5, 0, // Skip to: 10959
/* 9583 */    MCD_OPC_Decode, 155, 6, 17, // Opcode: MSUB_Q_rrr1_L
/* 9587 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 9603
/* 9592 */    MCD_OPC_CheckField, 7, 1, 0, 80, 5, 0, // Skip to: 10959
/* 9599 */    MCD_OPC_Decode, 154, 6, 17, // Opcode: MSUB_Q_rrr1
/* 9603 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 9619
/* 9608 */    MCD_OPC_CheckField, 7, 1, 0, 64, 5, 0, // Skip to: 10959
/* 9615 */    MCD_OPC_Decode, 158, 6, 17, // Opcode: MSUB_Q_rrr1_U_U
/* 9619 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 9635
/* 9624 */    MCD_OPC_CheckField, 7, 1, 0, 48, 5, 0, // Skip to: 10959
/* 9631 */    MCD_OPC_Decode, 156, 6, 17, // Opcode: MSUB_Q_rrr1_L_L
/* 9635 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 9651
/* 9640 */    MCD_OPC_CheckField, 7, 1, 0, 32, 5, 0, // Skip to: 10959
/* 9647 */    MCD_OPC_Decode, 255, 5, 17, // Opcode: MSUBR_Q_rrr1_U_U
/* 9651 */    MCD_OPC_FilterValue, 7, 11, 0, 0, // Skip to: 9667
/* 9656 */    MCD_OPC_CheckField, 7, 1, 0, 16, 5, 0, // Skip to: 10959
/* 9663 */    MCD_OPC_Decode, 254, 5, 17, // Opcode: MSUBR_Q_rrr1_L_L
/* 9667 */    MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 9683
/* 9672 */    MCD_OPC_CheckField, 7, 1, 1, 0, 5, 0, // Skip to: 10959
/* 9679 */    MCD_OPC_Decode, 224, 5, 17, // Opcode: MSUBADR_H_rrr1_UL
/* 9683 */    MCD_OPC_FilterValue, 13, 11, 0, 0, // Skip to: 9699
/* 9688 */    MCD_OPC_CheckField, 7, 1, 1, 240, 4, 0, // Skip to: 10959
/* 9695 */    MCD_OPC_Decode, 223, 5, 17, // Opcode: MSUBADR_H_rrr1_LU
/* 9699 */    MCD_OPC_FilterValue, 14, 11, 0, 0, // Skip to: 9715
/* 9704 */    MCD_OPC_CheckField, 7, 1, 1, 224, 4, 0, // Skip to: 10959
/* 9711 */    MCD_OPC_Decode, 222, 5, 17, // Opcode: MSUBADR_H_rrr1_LL
/* 9715 */    MCD_OPC_FilterValue, 15, 11, 0, 0, // Skip to: 9731
/* 9720 */    MCD_OPC_CheckField, 7, 1, 1, 208, 4, 0, // Skip to: 10959
/* 9727 */    MCD_OPC_Decode, 225, 5, 17, // Opcode: MSUBADR_H_rrr1_UU
/* 9731 */    MCD_OPC_FilterValue, 24, 21, 0, 0, // Skip to: 9757
/* 9736 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9739 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9748
/* 9744 */    MCD_OPC_Decode, 162, 6, 17, // Opcode: MSUB_Q_rrr1_e_U
/* 9748 */    MCD_OPC_FilterValue, 1, 182, 4, 0, // Skip to: 10959
/* 9753 */    MCD_OPC_Decode, 232, 5, 17, // Opcode: MSUBAD_H_rrr1_UL
/* 9757 */    MCD_OPC_FilterValue, 25, 21, 0, 0, // Skip to: 9783
/* 9762 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9765 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9774
/* 9770 */    MCD_OPC_Decode, 160, 6, 17, // Opcode: MSUB_Q_rrr1_e_L
/* 9774 */    MCD_OPC_FilterValue, 1, 156, 4, 0, // Skip to: 10959
/* 9779 */    MCD_OPC_Decode, 231, 5, 17, // Opcode: MSUBAD_H_rrr1_LU
/* 9783 */    MCD_OPC_FilterValue, 26, 11, 0, 0, // Skip to: 9799
/* 9788 */    MCD_OPC_CheckField, 7, 1, 1, 140, 4, 0, // Skip to: 10959
/* 9795 */    MCD_OPC_Decode, 230, 5, 17, // Opcode: MSUBAD_H_rrr1_LL
/* 9799 */    MCD_OPC_FilterValue, 27, 21, 0, 0, // Skip to: 9825
/* 9804 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9807 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9816
/* 9812 */    MCD_OPC_Decode, 159, 6, 17, // Opcode: MSUB_Q_rrr1_e
/* 9816 */    MCD_OPC_FilterValue, 1, 114, 4, 0, // Skip to: 10959
/* 9821 */    MCD_OPC_Decode, 233, 5, 17, // Opcode: MSUBAD_H_rrr1_UU
/* 9825 */    MCD_OPC_FilterValue, 28, 21, 0, 0, // Skip to: 9851
/* 9830 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9833 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9842
/* 9838 */    MCD_OPC_Decode, 163, 6, 17, // Opcode: MSUB_Q_rrr1_e_U_U
/* 9842 */    MCD_OPC_FilterValue, 1, 88, 4, 0, // Skip to: 10959
/* 9847 */    MCD_OPC_Decode, 216, 5, 17, // Opcode: MSUBADM_H_rrr1_UL
/* 9851 */    MCD_OPC_FilterValue, 29, 21, 0, 0, // Skip to: 9877
/* 9856 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9859 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9868
/* 9864 */    MCD_OPC_Decode, 161, 6, 17, // Opcode: MSUB_Q_rrr1_e_L_L
/* 9868 */    MCD_OPC_FilterValue, 1, 62, 4, 0, // Skip to: 10959
/* 9873 */    MCD_OPC_Decode, 215, 5, 17, // Opcode: MSUBADM_H_rrr1_LU
/* 9877 */    MCD_OPC_FilterValue, 30, 21, 0, 0, // Skip to: 9903
/* 9882 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9885 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9894
/* 9890 */    MCD_OPC_Decode, 249, 5, 17, // Opcode: MSUBR_H_rrr1_DcEdDaDbUL
/* 9894 */    MCD_OPC_FilterValue, 1, 36, 4, 0, // Skip to: 10959
/* 9899 */    MCD_OPC_Decode, 214, 5, 17, // Opcode: MSUBADM_H_rrr1_LL
/* 9903 */    MCD_OPC_FilterValue, 31, 11, 0, 0, // Skip to: 9919
/* 9908 */    MCD_OPC_CheckField, 7, 1, 1, 20, 4, 0, // Skip to: 10959
/* 9915 */    MCD_OPC_Decode, 217, 5, 17, // Opcode: MSUBADM_H_rrr1_UU
/* 9919 */    MCD_OPC_FilterValue, 32, 11, 0, 0, // Skip to: 9935
/* 9924 */    MCD_OPC_CheckField, 7, 1, 0, 4, 4, 0, // Skip to: 10959
/* 9931 */    MCD_OPC_Decode, 135, 6, 17, // Opcode: MSUBS_Q_rrr1_U
/* 9935 */    MCD_OPC_FilterValue, 33, 11, 0, 0, // Skip to: 9951
/* 9940 */    MCD_OPC_CheckField, 7, 1, 0, 244, 3, 0, // Skip to: 10959
/* 9947 */    MCD_OPC_Decode, 133, 6, 17, // Opcode: MSUBS_Q_rrr1_L
/* 9951 */    MCD_OPC_FilterValue, 34, 11, 0, 0, // Skip to: 9967
/* 9956 */    MCD_OPC_CheckField, 7, 1, 0, 228, 3, 0, // Skip to: 10959
/* 9963 */    MCD_OPC_Decode, 132, 6, 17, // Opcode: MSUBS_Q_rrr1
/* 9967 */    MCD_OPC_FilterValue, 36, 11, 0, 0, // Skip to: 9983
/* 9972 */    MCD_OPC_CheckField, 7, 1, 0, 212, 3, 0, // Skip to: 10959
/* 9979 */    MCD_OPC_Decode, 136, 6, 17, // Opcode: MSUBS_Q_rrr1_U_U
/* 9983 */    MCD_OPC_FilterValue, 37, 11, 0, 0, // Skip to: 9999
/* 9988 */    MCD_OPC_CheckField, 7, 1, 0, 196, 3, 0, // Skip to: 10959
/* 9995 */    MCD_OPC_Decode, 134, 6, 17, // Opcode: MSUBS_Q_rrr1_L_L
/* 9999 */    MCD_OPC_FilterValue, 38, 11, 0, 0, // Skip to: 10015
/* 10004 */   MCD_OPC_CheckField, 7, 1, 0, 180, 3, 0, // Skip to: 10959
/* 10011 */   MCD_OPC_Decode, 248, 5, 17, // Opcode: MSUBRS_Q_rrr1_U_U
/* 10015 */   MCD_OPC_FilterValue, 39, 11, 0, 0, // Skip to: 10031
/* 10020 */   MCD_OPC_CheckField, 7, 1, 0, 164, 3, 0, // Skip to: 10959
/* 10027 */   MCD_OPC_Decode, 247, 5, 17, // Opcode: MSUBRS_Q_rrr1_L_L
/* 10031 */   MCD_OPC_FilterValue, 44, 11, 0, 0, // Skip to: 10047
/* 10036 */   MCD_OPC_CheckField, 7, 1, 1, 148, 3, 0, // Skip to: 10959
/* 10043 */   MCD_OPC_Decode, 220, 5, 17, // Opcode: MSUBADRS_H_rrr1_UL
/* 10047 */   MCD_OPC_FilterValue, 45, 11, 0, 0, // Skip to: 10063
/* 10052 */   MCD_OPC_CheckField, 7, 1, 1, 132, 3, 0, // Skip to: 10959
/* 10059 */   MCD_OPC_Decode, 219, 5, 17, // Opcode: MSUBADRS_H_rrr1_LU
/* 10063 */   MCD_OPC_FilterValue, 46, 11, 0, 0, // Skip to: 10079
/* 10068 */   MCD_OPC_CheckField, 7, 1, 1, 116, 3, 0, // Skip to: 10959
/* 10075 */   MCD_OPC_Decode, 218, 5, 17, // Opcode: MSUBADRS_H_rrr1_LL
/* 10079 */   MCD_OPC_FilterValue, 47, 11, 0, 0, // Skip to: 10095
/* 10084 */   MCD_OPC_CheckField, 7, 1, 1, 100, 3, 0, // Skip to: 10959
/* 10091 */   MCD_OPC_Decode, 221, 5, 17, // Opcode: MSUBADRS_H_rrr1_UU
/* 10095 */   MCD_OPC_FilterValue, 56, 21, 0, 0, // Skip to: 10121
/* 10100 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10103 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10112
/* 10108 */   MCD_OPC_Decode, 140, 6, 17, // Opcode: MSUBS_Q_rrr1_e_U
/* 10112 */   MCD_OPC_FilterValue, 1, 74, 3, 0, // Skip to: 10959
/* 10117 */   MCD_OPC_Decode, 228, 5, 17, // Opcode: MSUBADS_H_rrr1_UL
/* 10121 */   MCD_OPC_FilterValue, 57, 21, 0, 0, // Skip to: 10147
/* 10126 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10129 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10138
/* 10134 */   MCD_OPC_Decode, 138, 6, 17, // Opcode: MSUBS_Q_rrr1_e_L
/* 10138 */   MCD_OPC_FilterValue, 1, 48, 3, 0, // Skip to: 10959
/* 10143 */   MCD_OPC_Decode, 227, 5, 17, // Opcode: MSUBADS_H_rrr1_LU
/* 10147 */   MCD_OPC_FilterValue, 58, 11, 0, 0, // Skip to: 10163
/* 10152 */   MCD_OPC_CheckField, 7, 1, 1, 32, 3, 0, // Skip to: 10959
/* 10159 */   MCD_OPC_Decode, 226, 5, 17, // Opcode: MSUBADS_H_rrr1_LL
/* 10163 */   MCD_OPC_FilterValue, 59, 21, 0, 0, // Skip to: 10189
/* 10168 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10171 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10180
/* 10176 */   MCD_OPC_Decode, 137, 6, 17, // Opcode: MSUBS_Q_rrr1_e
/* 10180 */   MCD_OPC_FilterValue, 1, 6, 3, 0, // Skip to: 10959
/* 10185 */   MCD_OPC_Decode, 229, 5, 17, // Opcode: MSUBADS_H_rrr1_UU
/* 10189 */   MCD_OPC_FilterValue, 60, 21, 0, 0, // Skip to: 10215
/* 10194 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10197 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10206
/* 10202 */   MCD_OPC_Decode, 141, 6, 17, // Opcode: MSUBS_Q_rrr1_e_U_U
/* 10206 */   MCD_OPC_FilterValue, 1, 236, 2, 0, // Skip to: 10959
/* 10211 */   MCD_OPC_Decode, 212, 5, 17, // Opcode: MSUBADMS_H_rrr1_UL
/* 10215 */   MCD_OPC_FilterValue, 61, 21, 0, 0, // Skip to: 10241
/* 10220 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10223 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10232
/* 10228 */   MCD_OPC_Decode, 139, 6, 17, // Opcode: MSUBS_Q_rrr1_e_L_L
/* 10232 */   MCD_OPC_FilterValue, 1, 210, 2, 0, // Skip to: 10959
/* 10237 */   MCD_OPC_Decode, 211, 5, 17, // Opcode: MSUBADMS_H_rrr1_LU
/* 10241 */   MCD_OPC_FilterValue, 62, 21, 0, 0, // Skip to: 10267
/* 10246 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10249 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10258
/* 10254 */   MCD_OPC_Decode, 242, 5, 17, // Opcode: MSUBRS_H_rrr1_DcEdDaDbUL
/* 10258 */   MCD_OPC_FilterValue, 1, 184, 2, 0, // Skip to: 10959
/* 10263 */   MCD_OPC_Decode, 210, 5, 17, // Opcode: MSUBADMS_H_rrr1_LL
/* 10267 */   MCD_OPC_FilterValue, 63, 175, 2, 0, // Skip to: 10959
/* 10272 */   MCD_OPC_CheckField, 7, 1, 1, 168, 2, 0, // Skip to: 10959
/* 10279 */   MCD_OPC_Decode, 213, 5, 17, // Opcode: MSUBADMS_H_rrr1_UU
/* 10283 */   MCD_OPC_FilterValue, 101, 45, 0, 0, // Skip to: 10333
/* 10288 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10291 */   MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 10307
/* 10296 */   MCD_OPC_CheckField, 26, 2, 0, 144, 2, 0, // Skip to: 10959
/* 10303 */   MCD_OPC_Decode, 222, 7, 18, // Opcode: ST_Q_abs
/* 10307 */   MCD_OPC_FilterValue, 1, 135, 2, 0, // Skip to: 10959
/* 10312 */   MCD_OPC_ExtractField, 26, 2,  // Inst{27-26} ...
/* 10315 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10324
/* 10320 */   MCD_OPC_Decode, 133, 8, 18, // Opcode: SWAP_W_abs
/* 10324 */   MCD_OPC_FilterValue, 1, 118, 2, 0, // Skip to: 10959
/* 10329 */   MCD_OPC_Decode, 236, 3, 18, // Opcode: LDMST_abs
/* 10333 */   MCD_OPC_FilterValue, 103, 35, 0, 0, // Skip to: 10373
/* 10338 */   MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 10341 */   MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 10357
/* 10346 */   MCD_OPC_CheckField, 7, 1, 0, 94, 2, 0, // Skip to: 10959
/* 10353 */   MCD_OPC_Decode, 178, 3, 19, // Opcode: INS_T
/* 10357 */   MCD_OPC_FilterValue, 1, 85, 2, 0, // Skip to: 10959
/* 10362 */   MCD_OPC_CheckField, 7, 1, 0, 78, 2, 0, // Skip to: 10959
/* 10369 */   MCD_OPC_Decode, 177, 3, 19, // Opcode: INSN_T
/* 10373 */   MCD_OPC_FilterValue, 105, 92, 0, 0, // Skip to: 10470
/* 10378 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10381 */   MCD_OPC_FilterValue, 0, 75, 0, 0, // Skip to: 10461
/* 10386 */   MCD_OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 10389 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10398
/* 10394 */   MCD_OPC_Decode, 138, 8, 20, // Opcode: SWAP_W_bo_r
/* 10398 */   MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 10407
/* 10403 */   MCD_OPC_Decode, 241, 3, 20, // Opcode: LDMST_bo_r
/* 10407 */   MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 10416
/* 10412 */   MCD_OPC_Decode, 132, 8, 20, // Opcode: SWAPMSK_W_bo_r
/* 10416 */   MCD_OPC_FilterValue, 3, 4, 0, 0, // Skip to: 10425
/* 10421 */   MCD_OPC_Decode, 240, 2, 20, // Opcode: CMPSWAP_W_bo_r
/* 10425 */   MCD_OPC_FilterValue, 16, 4, 0, 0, // Skip to: 10434
/* 10430 */   MCD_OPC_Decode, 135, 8, 20, // Opcode: SWAP_W_bo_c
/* 10434 */   MCD_OPC_FilterValue, 17, 4, 0, 0, // Skip to: 10443
/* 10439 */   MCD_OPC_Decode, 238, 3, 20, // Opcode: LDMST_bo_c
/* 10443 */   MCD_OPC_FilterValue, 18, 4, 0, 0, // Skip to: 10452
/* 10448 */   MCD_OPC_Decode, 129, 8, 20, // Opcode: SWAPMSK_W_bo_c
/* 10452 */   MCD_OPC_FilterValue, 19, 246, 1, 0, // Skip to: 10959
/* 10457 */   MCD_OPC_Decode, 237, 2, 20, // Opcode: CMPSWAP_W_bo_c
/* 10461 */   MCD_OPC_FilterValue, 1, 237, 1, 0, // Skip to: 10959
/* 10466 */   MCD_OPC_Decode, 194, 7, 29, // Opcode: ST_B_bol
/* 10470 */   MCD_OPC_FilterValue, 107, 147, 0, 0, // Skip to: 10622
/* 10475 */   MCD_OPC_ExtractField, 18, 6,  // Inst{23-18} ...
/* 10478 */   MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 10494
/* 10483 */   MCD_OPC_CheckField, 7, 1, 0, 213, 1, 0, // Skip to: 10959
/* 10490 */   MCD_OPC_Decode, 240, 6, 33, // Opcode: PACK_rrr
/* 10494 */   MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 10510
/* 10499 */   MCD_OPC_CheckField, 7, 1, 0, 197, 1, 0, // Skip to: 10959
/* 10506 */   MCD_OPC_Decode, 244, 2, 33, // Opcode: CRCN_rrr
/* 10510 */   MCD_OPC_FilterValue, 32, 11, 0, 0, // Skip to: 10526
/* 10515 */   MCD_OPC_CheckField, 7, 1, 0, 181, 1, 0, // Skip to: 10959
/* 10522 */   MCD_OPC_Decode, 183, 3, 33, // Opcode: IXMIN_rrr
/* 10526 */   MCD_OPC_FilterValue, 36, 11, 0, 0, // Skip to: 10542
/* 10531 */   MCD_OPC_CheckField, 7, 1, 0, 165, 1, 0, // Skip to: 10959
/* 10538 */   MCD_OPC_Decode, 182, 3, 33, // Opcode: IXMIN_U_rrr
/* 10542 */   MCD_OPC_FilterValue, 40, 11, 0, 0, // Skip to: 10558
/* 10547 */   MCD_OPC_CheckField, 7, 1, 0, 149, 1, 0, // Skip to: 10959
/* 10554 */   MCD_OPC_Decode, 181, 3, 33, // Opcode: IXMAX_rrr
/* 10558 */   MCD_OPC_FilterValue, 44, 11, 0, 0, // Skip to: 10574
/* 10563 */   MCD_OPC_CheckField, 7, 1, 0, 133, 1, 0, // Skip to: 10959
/* 10570 */   MCD_OPC_Decode, 180, 3, 33, // Opcode: IXMAX_U_rrr
/* 10574 */   MCD_OPC_FilterValue, 52, 11, 0, 0, // Skip to: 10590
/* 10579 */   MCD_OPC_CheckField, 7, 1, 0, 117, 1, 0, // Skip to: 10959
/* 10586 */   MCD_OPC_Decode, 128, 3, 33, // Opcode: DVADJ_rrr
/* 10590 */   MCD_OPC_FilterValue, 56, 11, 0, 0, // Skip to: 10606
/* 10595 */   MCD_OPC_CheckField, 7, 1, 0, 101, 1, 0, // Skip to: 10959
/* 10602 */   MCD_OPC_Decode, 135, 3, 33, // Opcode: DVSTEP_U_rrr
/* 10606 */   MCD_OPC_FilterValue, 60, 92, 1, 0, // Skip to: 10959
/* 10611 */   MCD_OPC_CheckField, 7, 1, 0, 85, 1, 0, // Skip to: 10959
/* 10618 */   MCD_OPC_Decode, 136, 3, 33, // Opcode: DVSTEP_rrr
/* 10622 */   MCD_OPC_FilterValue, 109, 21, 0, 0, // Skip to: 10648
/* 10627 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10630 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10639
/* 10635 */   MCD_OPC_Decode, 225, 2, 30, // Opcode: CALL_b
/* 10639 */   MCD_OPC_FilterValue, 1, 59, 1, 0, // Skip to: 10959
/* 10644 */   MCD_OPC_Decode, 223, 2, 30, // Opcode: CALLA_b
/* 10648 */   MCD_OPC_FilterValue, 111, 21, 0, 0, // Skip to: 10674
/* 10653 */   MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 10656 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10665
/* 10661 */   MCD_OPC_Decode, 228, 3, 38, // Opcode: JZ_T_brn
/* 10665 */   MCD_OPC_FilterValue, 1, 33, 1, 0, // Skip to: 10959
/* 10670 */   MCD_OPC_Decode, 222, 3, 38, // Opcode: JNZ_T_brn
/* 10674 */   MCD_OPC_FilterValue, 115, 85, 0, 0, // Skip to: 10764
/* 10679 */   MCD_OPC_ExtractField, 16, 12,  // Inst{27-16} ...
/* 10682 */   MCD_OPC_FilterValue, 10, 11, 0, 0, // Skip to: 10698
/* 10687 */   MCD_OPC_CheckField, 7, 1, 0, 9, 1, 0, // Skip to: 10959
/* 10694 */   MCD_OPC_Decode, 200, 6, 21, // Opcode: MUL_rr2
/* 10698 */   MCD_OPC_FilterValue, 104, 11, 0, 0, // Skip to: 10714
/* 10703 */   MCD_OPC_CheckField, 7, 1, 0, 249, 0, 0, // Skip to: 10959
/* 10710 */   MCD_OPC_Decode, 197, 6, 21, // Opcode: MUL_U_rr2
/* 10714 */   MCD_OPC_FilterValue, 106, 11, 0, 0, // Skip to: 10730
/* 10719 */   MCD_OPC_CheckField, 7, 1, 0, 233, 0, 0, // Skip to: 10959
/* 10726 */   MCD_OPC_Decode, 201, 6, 21, // Opcode: MUL_rr2_e
/* 10730 */   MCD_OPC_FilterValue, 136, 1, 11, 0, 0, // Skip to: 10747
/* 10736 */   MCD_OPC_CheckField, 7, 1, 0, 216, 0, 0, // Skip to: 10959
/* 10743 */   MCD_OPC_Decode, 181, 6, 21, // Opcode: MULS_U_rr2
/* 10747 */   MCD_OPC_FilterValue, 138, 1, 206, 0, 0, // Skip to: 10959
/* 10753 */   MCD_OPC_CheckField, 7, 1, 0, 199, 0, 0, // Skip to: 10959
/* 10760 */   MCD_OPC_Decode, 183, 6, 21, // Opcode: MULS_rr2
/* 10764 */   MCD_OPC_FilterValue, 119, 18, 0, 0, // Skip to: 10787
/* 10769 */   MCD_OPC_CheckField, 21, 2, 0, 183, 0, 0, // Skip to: 10959
/* 10776 */   MCD_OPC_CheckField, 7, 1, 0, 176, 0, 0, // Skip to: 10959
/* 10783 */   MCD_OPC_Decode, 249, 2, 34, // Opcode: DEXTR_rrpw
/* 10787 */   MCD_OPC_FilterValue, 121, 21, 0, 0, // Skip to: 10813
/* 10792 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10795 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10804
/* 10800 */   MCD_OPC_Decode, 145, 4, 29, // Opcode: LD_B_bol
/* 10804 */   MCD_OPC_FilterValue, 1, 150, 0, 0, // Skip to: 10959
/* 10809 */   MCD_OPC_Decode, 217, 7, 29, // Opcode: ST_H_bol
/* 10813 */   MCD_OPC_FilterValue, 123, 21, 0, 0, // Skip to: 10839
/* 10818 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10821 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10830
/* 10826 */   MCD_OPC_Decode, 199, 5, 23, // Opcode: MOV_H_rlc
/* 10830 */   MCD_OPC_FilterValue, 1, 124, 0, 0, // Skip to: 10959
/* 10835 */   MCD_OPC_Decode, 202, 5, 23, // Opcode: MOV_rlcEc
/* 10839 */   MCD_OPC_FilterValue, 125, 55, 0, 0, // Skip to: 10899
/* 10844 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10847 */   MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 10873
/* 10852 */   MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 10855 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10864
/* 10860 */   MCD_OPC_Decode, 185, 3, 31, // Opcode: JEQ_A_brr
/* 10864 */   MCD_OPC_FilterValue, 1, 90, 0, 0, // Skip to: 10959
/* 10869 */   MCD_OPC_Decode, 213, 3, 31, // Opcode: JNE_A_brr
/* 10873 */   MCD_OPC_FilterValue, 1, 81, 0, 0, // Skip to: 10959
/* 10878 */   MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 10881 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10890
/* 10886 */   MCD_OPC_Decode, 199, 4, 31, // Opcode: LOOP_brr
/* 10890 */   MCD_OPC_FilterValue, 1, 64, 0, 0, // Skip to: 10959
/* 10895 */   MCD_OPC_Decode, 198, 4, 31, // Opcode: LOOPU_brr
/* 10899 */   MCD_OPC_FilterValue, 127, 55, 0, 0, // Skip to: 10959
/* 10904 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10907 */   MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 10933
/* 10912 */   MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 10915 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10924
/* 10920 */   MCD_OPC_Decode, 196, 3, 31, // Opcode: JGE_brr
/* 10924 */   MCD_OPC_FilterValue, 1, 30, 0, 0, // Skip to: 10959
/* 10929 */   MCD_OPC_Decode, 194, 3, 31, // Opcode: JGE_U_brr
/* 10933 */   MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 10959
/* 10938 */   MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 10941 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10950
/* 10946 */   MCD_OPC_Decode, 195, 3, 32, // Opcode: JGE_brc
/* 10950 */   MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 10959
/* 10955 */   MCD_OPC_Decode, 193, 3, 32, // Opcode: JGE_U_brc
/* 10959 */   MCD_OPC_Fail,
  0
};

static bool checkDecoderPredicate(MCInst *Inst, unsigned Idx) {
  /* llvm_unreachable("Invalid index!"); */
}

#define DecodeToMCInst(fname, fieldname, InsnType) \
static DecodeStatus fname(DecodeStatus S, unsigned Idx, InsnType insn, MCInst *MI, \
		uint64_t Address, bool *Decoder) \
{ \
  InsnType tmp; \
  switch (Idx) { \
  default: /* llvm_unreachable("Invalid index!"); */ \
  case 0: \
    if (DecodeSRInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 1: \
    if (DecodeSRRInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 2: \
    if (DecodeSRCInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 3: \
    if (DecodeSLRInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 4: \
    if (DecodeSLROInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 5: \
    if (DecodeSROInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 6: \
    if (DecodeSBRInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 7: \
    if (DecodeSRRSInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 8: \
    if (DecodeSCInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 9: \
    if (DecodeSBCInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 10: \
    if (DecodeSBRNInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 11: \
    if (DecodeSSRInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 12: \
    if (DecodeSSROInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 13: \
    if (DecodeSBInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 14: \
    if (DecodeSYSInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 15: \
    if (DecodeRRInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 16: \
    if (DecodeRRR2Instruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 17: \
    if (DecodeRRR1Instruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 18: \
    if (DecodeABSInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 19: \
    if (DecodeBITInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 20: \
    if (DecodeBOInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 21: \
    if (DecodeRR2Instruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 22: \
    if (DecodeRCInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 23: \
    if (DecodeRLCInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 24: \
    if (DecodeRR1Instruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 25: \
    if (DecodeRCRInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 26: \
    if (DecodeRRRWInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 27: \
    if (DecodeRCRRInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 28: \
    if (DecodeRRRRInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 29: \
    if (DecodeBOLInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 30: \
    if (DecodeBInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 31: \
    if (DecodeBRRInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 32: \
    if (DecodeBRCInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 33: \
    if (DecodeRRRInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 34: \
    if (DecodeRRPWInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 35: \
    if (DecodeRCPWInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 36: \
    if (DecodeABSBInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 37: \
    if (DecodeRCRWInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 38: \
    if (DecodeBRNInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  } \
}

#define DecodeInstruction(fname, fieldname, decoder, InsnType) \
static DecodeStatus fname(const uint8_t DecodeTable[], MCInst *MI, \
                                      InsnType insn, uint64_t Address) { \
  const uint8_t *Ptr = DecodeTable; \
  uint64_t CurFieldValue = 0; \
  DecodeStatus S = MCDisassembler_Success; \
  while (true) { \
    switch (*Ptr) { \
    default: \
      return MCDisassembler_Fail; \
    case MCD_OPC_ExtractField: { \
      unsigned Start = *++Ptr; \
      unsigned Len = *++Ptr; \
      ++Ptr; \
      CurFieldValue = fieldname(insn, Start, Len); \
      break; \
    } \
    case MCD_OPC_FilterValue: { \
      /* Decode the field value. */ \
      unsigned Len; \
      uint64_t Val = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      /* NumToSkip is a plain 24-bit integer. */ \
      unsigned NumToSkip = *Ptr++; \
      NumToSkip |= (*Ptr++) << 8; \
      NumToSkip |= (*Ptr++) << 16; \
      /* Perform the filter operation. */ \
      if (Val != CurFieldValue) \
        Ptr += NumToSkip; \
      break; \
    } \
    case MCD_OPC_CheckField: { \
      unsigned Start = *++Ptr; \
      unsigned Len = *++Ptr; \
      uint64_t FieldValue = fieldname(insn, Start, Len); \
      /* Decode the field value. */ \
      unsigned PtrLen = 0; \
      uint64_t ExpectedValue = decodeULEB128(++Ptr, &PtrLen); \
      Ptr += PtrLen; \
      /* NumToSkip is a plain 24-bit integer. */ \
      unsigned NumToSkip = *Ptr++; \
      NumToSkip |= (*Ptr++) << 8; \
      NumToSkip |= (*Ptr++) << 16; \
      /* If the actual and expected values don't match, skip. */ \
      if (ExpectedValue != FieldValue) \
        Ptr += NumToSkip; \
      break; \
    } \
    case MCD_OPC_CheckPredicate: { \
      unsigned Len; \
      /* Decode the Predicate Index value. */ \
      unsigned PIdx = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      /* NumToSkip is a plain 24-bit integer. */ \
      unsigned NumToSkip = *Ptr++; \
      NumToSkip |= (*Ptr++) << 8; \
      NumToSkip |= (*Ptr++) << 16; \
      /* Check the predicate. */ \
      bool Pred = checkDecoderPredicate(MI, PIdx); \
      if (!Pred) \
        Ptr += NumToSkip; \
      break; \
    } \
    case MCD_OPC_Decode: { \
      unsigned Len; \
      /* Decode the Opcode value. */ \
      unsigned Opc = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      unsigned DecodeIdx = decodeULEB128(Ptr, &Len); \
      Ptr += Len; \
      MCInst_clear(MI); \
      MCInst_setOpcode(MI, Opc); \
      bool DecodeComplete; \
      S = decoder(S, DecodeIdx, insn, MI, Address, &DecodeComplete); \
      return S; \
    } \
    case MCD_OPC_TryDecode: { \
      unsigned Len; \
      /* Decode the Opcode value. */ \
      unsigned Opc = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      unsigned DecodeIdx = decodeULEB128(Ptr, &Len); \
      Ptr += Len; \
      /* NumToSkip is a plain 24-bit integer. */ \
      unsigned NumToSkip = *Ptr++; \
      NumToSkip |= (*Ptr++) << 8; \
      NumToSkip |= (*Ptr++) << 16; \
      /* Perform the decode operation. */ \
      MCInst_setOpcode(MI, Opc); \
      bool DecodeComplete; \
      S = decoder(S, DecodeIdx, insn, MI, Address, &DecodeComplete); \
      if (DecodeComplete) { \
        /* Decoding complete. */ \
        return S; \
      } else { \
        /* If the decoding was incomplete, skip. */ \
        Ptr += NumToSkip; \
        /* Reset decode status. This also drops a SoftFail status that could be */ \
        /* set before the decode attempt. */ \
        S = MCDisassembler_Success; \
      } \
      break; \
    } \
    case MCD_OPC_SoftFail: { \
      /* Decode the mask values. */ \
      unsigned Len; \
      uint64_t PositiveMask = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      uint64_t NegativeMask = decodeULEB128(Ptr, &Len); \
      Ptr += Len; \
      bool Fail = (insn & PositiveMask) != 0 || (~insn & NegativeMask) != 0; \
      if (Fail) \
        S = MCDisassembler_SoftFail; \
      break; \
    } \
    case MCD_OPC_Fail: { \
      return MCDisassembler_Fail; \
    } \
    } \
  } \
  /* Bogisity detected in disassembler state machine! */ \
}

FieldFromInstruction(fieldFromInstruction_2, uint16_t)
DecodeToMCInst(decodeToMCInst_2, fieldFromInstruction_2, uint16_t)
DecodeInstruction(decodeInstruction_2, fieldFromInstruction_2, decodeToMCInst_2, uint16_t)

FieldFromInstruction(fieldFromInstruction_4, uint32_t)
DecodeToMCInst(decodeToMCInst_4, fieldFromInstruction_4, uint32_t)
DecodeInstruction(decodeInstruction_4, fieldFromInstruction_4, decodeToMCInst_4, uint32_t)
