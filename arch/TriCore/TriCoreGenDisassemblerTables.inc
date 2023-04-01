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
/* 24 */      MCD_OPC_Decode, 233, 6, 0, // Opcode: NOP_sr
/* 28 */      MCD_OPC_FilterValue, 7, 4, 0, 0, // Skip to: 37
/* 33 */      MCD_OPC_Decode, 170, 3, 0, // Opcode: FRET_sr
/* 37 */      MCD_OPC_FilterValue, 8, 4, 0, 0, // Skip to: 46
/* 42 */      MCD_OPC_Decode, 143, 7, 0, // Opcode: RFE_sr
/* 46 */      MCD_OPC_FilterValue, 9, 4, 0, 0, // Skip to: 55
/* 51 */      MCD_OPC_Decode, 141, 7, 0, // Opcode: RET_sr
/* 55 */      MCD_OPC_FilterValue, 10, 5, 5, 0, // Skip to: 1345
/* 60 */      MCD_OPC_Decode, 128, 3, 0, // Opcode: DEBUG_sr
/* 64 */      MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 73
/* 69 */      MCD_OPC_Decode, 214, 5, 1, // Opcode: MOV_AA_srr
/* 73 */      MCD_OPC_FilterValue, 2, 243, 4, 0, // Skip to: 1345
/* 78 */      MCD_OPC_Decode, 219, 5, 1, // Opcode: MOV_D_srr
/* 82 */      MCD_OPC_FilterValue, 2, 39, 0, 0, // Skip to: 126
/* 87 */      MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 90 */      MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 99
/* 95 */      MCD_OPC_Decode, 229, 5, 1, // Opcode: MOV_srr
/* 99 */      MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 108
/* 104 */     MCD_OPC_Decode, 167, 2, 1, // Opcode: ADD_srr
/* 108 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 117
/* 113 */     MCD_OPC_Decode, 227, 5, 2, // Opcode: MOV_srcDa
/* 117 */     MCD_OPC_FilterValue, 3, 199, 4, 0, // Skip to: 1345
/* 122 */     MCD_OPC_Decode, 164, 2, 2, // Opcode: ADD_src
/* 126 */     MCD_OPC_FilterValue, 4, 39, 0, 0, // Skip to: 170
/* 131 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 134 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 143
/* 139 */     MCD_OPC_Decode, 155, 4, 3, // Opcode: LD_BU_slr_post
/* 143 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 152
/* 148 */     MCD_OPC_Decode, 210, 4, 3, // Opcode: LD_W_slr_post
/* 152 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 161
/* 157 */     MCD_OPC_Decode, 192, 4, 3, // Opcode: LD_H_slr_post
/* 161 */     MCD_OPC_FilterValue, 3, 155, 4, 0, // Skip to: 1345
/* 166 */     MCD_OPC_Decode, 144, 4, 3, // Opcode: LD_A_slr_post
/* 170 */     MCD_OPC_FilterValue, 6, 46, 0, 0, // Skip to: 221
/* 175 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 178 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 187
/* 183 */     MCD_OPC_Decode, 196, 7, 2, // Opcode: SH_src
/* 187 */     MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 203
/* 192 */     MCD_OPC_CheckField, 12, 4, 0, 122, 4, 0, // Skip to: 1345
/* 199 */     MCD_OPC_Decode, 238, 6, 0, // Opcode: NOT_sr
/* 203 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 212
/* 208 */     MCD_OPC_Decode, 170, 7, 2, // Opcode: SHA_src
/* 212 */     MCD_OPC_FilterValue, 3, 104, 4, 0, // Skip to: 1345
/* 217 */     MCD_OPC_Decode, 190, 8, 1, // Opcode: XOR_srr
/* 221 */     MCD_OPC_FilterValue, 8, 39, 0, 0, // Skip to: 265
/* 226 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 229 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 238
/* 234 */     MCD_OPC_Decode, 156, 4, 4, // Opcode: LD_BU_slro
/* 238 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 247
/* 243 */     MCD_OPC_Decode, 211, 4, 4, // Opcode: LD_W_slro
/* 247 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 256
/* 252 */     MCD_OPC_Decode, 193, 4, 4, // Opcode: LD_H_slro
/* 256 */     MCD_OPC_FilterValue, 3, 60, 4, 0, // Skip to: 1345
/* 261 */     MCD_OPC_Decode, 145, 4, 4, // Opcode: LD_A_slro
/* 265 */     MCD_OPC_FilterValue, 10, 21, 0, 0, // Skip to: 291
/* 270 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 273 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 282
/* 278 */     MCD_OPC_Decode, 229, 2, 2, // Opcode: CADD_src
/* 282 */     MCD_OPC_FilterValue, 3, 34, 4, 0, // Skip to: 1345
/* 287 */     MCD_OPC_Decode, 226, 2, 2, // Opcode: CADDN_src
/* 291 */     MCD_OPC_FilterValue, 12, 39, 0, 0, // Skip to: 335
/* 296 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 299 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 308
/* 304 */     MCD_OPC_Decode, 157, 4, 5, // Opcode: LD_BU_sro
/* 308 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 317
/* 313 */     MCD_OPC_Decode, 212, 4, 5, // Opcode: LD_W_sro
/* 317 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 326
/* 322 */     MCD_OPC_Decode, 194, 4, 5, // Opcode: LD_H_sro
/* 326 */     MCD_OPC_FilterValue, 3, 246, 3, 0, // Skip to: 1345
/* 331 */     MCD_OPC_Decode, 146, 4, 5, // Opcode: LD_A_sro
/* 335 */     MCD_OPC_FilterValue, 13, 18, 0, 0, // Skip to: 358
/* 340 */     MCD_OPC_CheckField, 12, 4, 3, 230, 3, 0, // Skip to: 1345
/* 347 */     MCD_OPC_CheckField, 6, 2, 0, 223, 3, 0, // Skip to: 1345
/* 354 */     MCD_OPC_Decode, 171, 3, 0, // Opcode: FRET_sys
/* 358 */     MCD_OPC_FilterValue, 14, 39, 0, 0, // Skip to: 402
/* 363 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 366 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 375
/* 371 */     MCD_OPC_Decode, 222, 3, 6, // Opcode: JLTZ_sbr
/* 375 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 384
/* 380 */     MCD_OPC_Decode, 216, 3, 6, // Opcode: JGTZ_sbr
/* 384 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 393
/* 389 */     MCD_OPC_Decode, 220, 3, 6, // Opcode: JLEZ_sbr
/* 393 */     MCD_OPC_FilterValue, 3, 179, 3, 0, // Skip to: 1345
/* 398 */     MCD_OPC_Decode, 211, 3, 6, // Opcode: JGEZ_sbr
/* 402 */     MCD_OPC_FilterValue, 16, 4, 0, 0, // Skip to: 411
/* 407 */     MCD_OPC_Decode, 144, 2, 7, // Opcode: ADDSC_A_srrs_v120u
/* 411 */     MCD_OPC_FilterValue, 18, 39, 0, 0, // Skip to: 455
/* 416 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 419 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 428
/* 424 */     MCD_OPC_Decode, 169, 2, 1, // Opcode: ADD_srr_a15
/* 428 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 437
/* 433 */     MCD_OPC_Decode, 152, 8, 1, // Opcode: SUB_srr_a15
/* 437 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 446
/* 442 */     MCD_OPC_Decode, 166, 2, 2, // Opcode: ADD_src_a15
/* 446 */     MCD_OPC_FilterValue, 3, 126, 3, 0, // Skip to: 1345
/* 451 */     MCD_OPC_Decode, 228, 5, 2, // Opcode: MOV_srcEa
/* 455 */     MCD_OPC_FilterValue, 20, 39, 0, 0, // Skip to: 499
/* 460 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 463 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 472
/* 468 */     MCD_OPC_Decode, 154, 4, 3, // Opcode: LD_BU_slr
/* 472 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 481
/* 477 */     MCD_OPC_Decode, 209, 4, 3, // Opcode: LD_W_slr
/* 481 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 490
/* 486 */     MCD_OPC_Decode, 191, 4, 3, // Opcode: LD_H_slr
/* 490 */     MCD_OPC_FilterValue, 3, 82, 3, 0, // Skip to: 1345
/* 495 */     MCD_OPC_Decode, 143, 4, 3, // Opcode: LD_A_slr
/* 499 */     MCD_OPC_FilterValue, 22, 21, 0, 0, // Skip to: 525
/* 504 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 507 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 516
/* 512 */     MCD_OPC_Decode, 192, 2, 8, // Opcode: AND_src
/* 516 */     MCD_OPC_FilterValue, 2, 56, 3, 0, // Skip to: 1345
/* 521 */     MCD_OPC_Decode, 133, 7, 8, // Opcode: OR_sc
/* 525 */     MCD_OPC_FilterValue, 24, 21, 0, 0, // Skip to: 551
/* 530 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 533 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 542
/* 538 */     MCD_OPC_Decode, 208, 4, 8, // Opcode: LD_W_sc
/* 542 */     MCD_OPC_FilterValue, 3, 30, 3, 0, // Skip to: 1345
/* 547 */     MCD_OPC_Decode, 142, 4, 8, // Opcode: LD_A_sc
/* 551 */     MCD_OPC_FilterValue, 26, 39, 0, 0, // Skip to: 595
/* 556 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 559 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 568
/* 564 */     MCD_OPC_Decode, 168, 2, 1, // Opcode: ADD_srr_15a
/* 568 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 577
/* 573 */     MCD_OPC_Decode, 151, 8, 1, // Opcode: SUB_srr_15a
/* 577 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 586
/* 582 */     MCD_OPC_Decode, 165, 2, 2, // Opcode: ADD_src_15a
/* 586 */     MCD_OPC_FilterValue, 3, 242, 2, 0, // Skip to: 1345
/* 591 */     MCD_OPC_Decode, 226, 5, 8, // Opcode: MOV_sc
/* 595 */     MCD_OPC_FilterValue, 28, 28, 0, 0, // Skip to: 628
/* 600 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 603 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 612
/* 608 */     MCD_OPC_Decode, 233, 2, 9, // Opcode: CALL_sb
/* 612 */     MCD_OPC_FilterValue, 3, 216, 2, 0, // Skip to: 1345
/* 617 */     MCD_OPC_CheckField, 12, 4, 0, 209, 2, 0, // Skip to: 1345
/* 624 */     MCD_OPC_Decode, 218, 3, 0, // Opcode: JI_sr
/* 628 */     MCD_OPC_FilterValue, 30, 39, 0, 0, // Skip to: 672
/* 633 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 636 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 645
/* 641 */     MCD_OPC_Decode, 207, 3, 10, // Opcode: JEQ_sbc1
/* 645 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 654
/* 650 */     MCD_OPC_Decode, 235, 3, 10, // Opcode: JNE_sbc1
/* 654 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 663
/* 659 */     MCD_OPC_Decode, 208, 3, 10, // Opcode: JEQ_sbc2
/* 663 */     MCD_OPC_FilterValue, 3, 165, 2, 0, // Skip to: 1345
/* 668 */     MCD_OPC_Decode, 236, 3, 10, // Opcode: JNE_sbc2
/* 672 */     MCD_OPC_FilterValue, 32, 39, 0, 0, // Skip to: 716
/* 677 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 680 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 689
/* 685 */     MCD_OPC_Decode, 145, 8, 8, // Opcode: SUB_A_sc
/* 689 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 698
/* 694 */     MCD_OPC_Decode, 217, 5, 1, // Opcode: MOV_A_srr
/* 698 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 707
/* 703 */     MCD_OPC_Decode, 216, 5, 2, // Opcode: MOV_A_src
/* 707 */     MCD_OPC_FilterValue, 3, 121, 2, 0, // Skip to: 1345
/* 712 */     MCD_OPC_Decode, 195, 2, 8, // Opcode: BISR_sc
/* 716 */     MCD_OPC_FilterValue, 34, 39, 0, 0, // Skip to: 760
/* 721 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 724 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 733
/* 729 */     MCD_OPC_Decode, 153, 2, 1, // Opcode: ADDS_srr
/* 733 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 742
/* 738 */     MCD_OPC_Decode, 142, 8, 1, // Opcode: SUBS_srr
/* 742 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 751
/* 747 */     MCD_OPC_Decode, 150, 8, 1, // Opcode: SUB_srr
/* 751 */     MCD_OPC_FilterValue, 3, 77, 2, 0, // Skip to: 1345
/* 756 */     MCD_OPC_Decode, 225, 6, 1, // Opcode: MUL_srr
/* 760 */     MCD_OPC_FilterValue, 35, 11, 0, 0, // Skip to: 776
/* 765 */     MCD_OPC_CheckField, 6, 2, 2, 61, 2, 0, // Skip to: 1345
/* 772 */     MCD_OPC_Decode, 242, 3, 11, // Opcode: JNZ_T_sbrn
/* 776 */     MCD_OPC_FilterValue, 36, 39, 0, 0, // Skip to: 820
/* 781 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 784 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 793
/* 789 */     MCD_OPC_Decode, 222, 7, 12, // Opcode: ST_B_ssr_pos
/* 793 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 802
/* 798 */     MCD_OPC_Decode, 135, 8, 12, // Opcode: ST_W_ssr_pos
/* 802 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 811
/* 807 */     MCD_OPC_Decode, 245, 7, 12, // Opcode: ST_H_ssr_pos
/* 811 */     MCD_OPC_FilterValue, 3, 17, 2, 0, // Skip to: 1345
/* 816 */     MCD_OPC_Decode, 211, 7, 12, // Opcode: ST_A_ssr_pos
/* 820 */     MCD_OPC_FilterValue, 38, 21, 0, 0, // Skip to: 846
/* 825 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 828 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 837
/* 833 */     MCD_OPC_Decode, 193, 2, 1, // Opcode: AND_srr
/* 837 */     MCD_OPC_FilterValue, 2, 247, 1, 0, // Skip to: 1345
/* 842 */     MCD_OPC_Decode, 134, 7, 1, // Opcode: OR_srr
/* 846 */     MCD_OPC_FilterValue, 40, 39, 0, 0, // Skip to: 890
/* 851 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 854 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 863
/* 859 */     MCD_OPC_Decode, 223, 7, 13, // Opcode: ST_B_ssro
/* 863 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 872
/* 868 */     MCD_OPC_Decode, 136, 8, 13, // Opcode: ST_W_ssro
/* 872 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 881
/* 877 */     MCD_OPC_Decode, 246, 7, 13, // Opcode: ST_H_ssro
/* 881 */     MCD_OPC_FilterValue, 3, 203, 1, 0, // Skip to: 1345
/* 886 */     MCD_OPC_Decode, 212, 7, 13, // Opcode: ST_A_ssro
/* 890 */     MCD_OPC_FilterValue, 42, 39, 0, 0, // Skip to: 934
/* 895 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 898 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 907
/* 903 */     MCD_OPC_Decode, 243, 2, 1, // Opcode: CMOV_srr
/* 907 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 916
/* 912 */     MCD_OPC_Decode, 241, 2, 1, // Opcode: CMOVN_srr
/* 916 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 925
/* 921 */     MCD_OPC_Decode, 242, 2, 2, // Opcode: CMOV_src
/* 925 */     MCD_OPC_FilterValue, 3, 159, 1, 0, // Skip to: 1345
/* 930 */     MCD_OPC_Decode, 240, 2, 2, // Opcode: CMOVN_src
/* 934 */     MCD_OPC_FilterValue, 44, 39, 0, 0, // Skip to: 978
/* 939 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 942 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 951
/* 947 */     MCD_OPC_Decode, 220, 7, 5, // Opcode: ST_B_sro
/* 951 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 960
/* 956 */     MCD_OPC_Decode, 133, 8, 5, // Opcode: ST_W_sro
/* 960 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 969
/* 965 */     MCD_OPC_Decode, 243, 7, 5, // Opcode: ST_H_sro
/* 969 */     MCD_OPC_FilterValue, 3, 115, 1, 0, // Skip to: 1345
/* 974 */     MCD_OPC_Decode, 209, 7, 5, // Opcode: ST_A_sro
/* 978 */     MCD_OPC_FilterValue, 46, 30, 0, 0, // Skip to: 1013
/* 983 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 986 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 995
/* 991 */     MCD_OPC_Decode, 248, 3, 11, // Opcode: JZ_T_sbrn
/* 995 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1004
/* 1000 */    MCD_OPC_Decode, 249, 3, 9, // Opcode: JZ_sb
/* 1004 */    MCD_OPC_FilterValue, 3, 80, 1, 0, // Skip to: 1345
/* 1009 */    MCD_OPC_Decode, 243, 3, 9, // Opcode: JNZ_sb
/* 1013 */    MCD_OPC_FilterValue, 48, 21, 0, 0, // Skip to: 1039
/* 1018 */    MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 1021 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1030
/* 1026 */    MCD_OPC_Decode, 158, 2, 1, // Opcode: ADD_A_srr
/* 1030 */    MCD_OPC_FilterValue, 2, 54, 1, 0, // Skip to: 1345
/* 1035 */    MCD_OPC_Decode, 157, 2, 2, // Opcode: ADD_A_src
/* 1039 */    MCD_OPC_FilterValue, 50, 83, 0, 0, // Skip to: 1127
/* 1044 */    MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 1047 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1063
/* 1052 */    MCD_OPC_CheckField, 6, 2, 0, 30, 1, 0, // Skip to: 1345
/* 1059 */    MCD_OPC_Decode, 155, 7, 0, // Opcode: SAT_B_sr
/* 1063 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 1079
/* 1068 */    MCD_OPC_CheckField, 6, 2, 0, 14, 1, 0, // Skip to: 1345
/* 1075 */    MCD_OPC_Decode, 153, 7, 0, // Opcode: SAT_BU_sr
/* 1079 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 1095
/* 1084 */    MCD_OPC_CheckField, 6, 2, 0, 254, 0, 0, // Skip to: 1345
/* 1091 */    MCD_OPC_Decode, 159, 7, 0, // Opcode: SAT_H_sr
/* 1095 */    MCD_OPC_FilterValue, 3, 11, 0, 0, // Skip to: 1111
/* 1100 */    MCD_OPC_CheckField, 6, 2, 0, 238, 0, 0, // Skip to: 1345
/* 1107 */    MCD_OPC_Decode, 157, 7, 0, // Opcode: SAT_HU_sr
/* 1111 */    MCD_OPC_FilterValue, 5, 229, 0, 0, // Skip to: 1345
/* 1116 */    MCD_OPC_CheckField, 6, 2, 0, 222, 0, 0, // Skip to: 1345
/* 1123 */    MCD_OPC_Decode, 151, 7, 0, // Opcode: RSUB_sr
/* 1127 */    MCD_OPC_FilterValue, 52, 39, 0, 0, // Skip to: 1171
/* 1132 */    MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 1135 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1144
/* 1140 */    MCD_OPC_Decode, 221, 7, 12, // Opcode: ST_B_ssr
/* 1144 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1153
/* 1149 */    MCD_OPC_Decode, 134, 8, 12, // Opcode: ST_W_ssr
/* 1153 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1162
/* 1158 */    MCD_OPC_Decode, 244, 7, 12, // Opcode: ST_H_ssr
/* 1162 */    MCD_OPC_FilterValue, 3, 178, 0, 0, // Skip to: 1345
/* 1167 */    MCD_OPC_Decode, 210, 7, 12, // Opcode: ST_A_ssr
/* 1171 */    MCD_OPC_FilterValue, 54, 21, 0, 0, // Skip to: 1197
/* 1176 */    MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 1179 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1188
/* 1184 */    MCD_OPC_Decode, 250, 3, 6, // Opcode: JZ_sbr
/* 1188 */    MCD_OPC_FilterValue, 3, 152, 0, 0, // Skip to: 1345
/* 1193 */    MCD_OPC_Decode, 244, 3, 6, // Opcode: JNZ_sbr
/* 1197 */    MCD_OPC_FilterValue, 56, 11, 0, 0, // Skip to: 1213
/* 1202 */    MCD_OPC_CheckField, 6, 2, 3, 136, 0, 0, // Skip to: 1345
/* 1209 */    MCD_OPC_Decode, 208, 7, 8, // Opcode: ST_A_sc
/* 1213 */    MCD_OPC_FilterValue, 58, 39, 0, 0, // Skip to: 1257
/* 1218 */    MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 1221 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1230
/* 1226 */    MCD_OPC_Decode, 160, 3, 1, // Opcode: EQ_srr
/* 1230 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1239
/* 1235 */    MCD_OPC_Decode, 232, 4, 1, // Opcode: LT_srr
/* 1239 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1248
/* 1244 */    MCD_OPC_Decode, 159, 3, 2, // Opcode: EQ_src
/* 1248 */    MCD_OPC_FilterValue, 3, 92, 0, 0, // Skip to: 1345
/* 1253 */    MCD_OPC_Decode, 231, 4, 2, // Opcode: LT_src
/* 1257 */    MCD_OPC_FilterValue, 60, 39, 0, 0, // Skip to: 1301
/* 1262 */    MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 1265 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1274
/* 1270 */    MCD_OPC_Decode, 252, 3, 9, // Opcode: J_sb
/* 1274 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1283
/* 1279 */    MCD_OPC_Decode, 240, 3, 6, // Opcode: JNZ_A_sbr
/* 1283 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1292
/* 1288 */    MCD_OPC_Decode, 246, 3, 6, // Opcode: JZ_A_sbr
/* 1292 */    MCD_OPC_FilterValue, 3, 48, 0, 0, // Skip to: 1345
/* 1297 */    MCD_OPC_Decode, 219, 4, 6, // Opcode: LOOP_sbr
/* 1301 */    MCD_OPC_FilterValue, 62, 39, 0, 0, // Skip to: 1345
/* 1306 */    MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 1309 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1318
/* 1314 */    MCD_OPC_Decode, 209, 3, 6, // Opcode: JEQ_sbr1
/* 1318 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1327
/* 1323 */    MCD_OPC_Decode, 237, 3, 6, // Opcode: JNE_sbr1
/* 1327 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1336
/* 1332 */    MCD_OPC_Decode, 210, 3, 6, // Opcode: JEQ_sbr2
/* 1336 */    MCD_OPC_FilterValue, 3, 4, 0, 0, // Skip to: 1345
/* 1341 */    MCD_OPC_Decode, 238, 3, 6, // Opcode: JNE_sbr2
/* 1345 */    MCD_OPC_Fail,
              0
};

static const uint8_t DecoderTable32[] = {
/* 0 */       MCD_OPC_ExtractField, 0, 7,  // Inst{6-0} ...
/* 3 */       MCD_OPC_FilterValue, 0, 19, 0, 0, // Skip to: 27
/* 8 */       MCD_OPC_CheckField, 12, 20, 128, 104, 12, 44, 0, // Skip to: 11292
/* 16 */      MCD_OPC_CheckField, 7, 1, 0, 5, 44, 0, // Skip to: 11292
/* 23 */      MCD_OPC_Decode, 234, 6, 14, // Opcode: NOP_sys
/* 27 */      MCD_OPC_FilterValue, 1, 221, 0, 0, // Skip to: 253
/* 32 */      MCD_OPC_ExtractField, 18, 10,  // Inst{27-18} ...
/* 35 */      MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 51
/* 40 */      MCD_OPC_CheckField, 7, 1, 0, 237, 43, 0, // Skip to: 11292
/* 47 */      MCD_OPC_Decode, 213, 5, 15, // Opcode: MOV_AA_rr
/* 51 */      MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 67
/* 56 */      MCD_OPC_CheckField, 7, 1, 0, 221, 43, 0, // Skip to: 11292
/* 63 */      MCD_OPC_Decode, 156, 2, 15, // Opcode: ADD_A_rr
/* 67 */      MCD_OPC_FilterValue, 8, 11, 0, 0, // Skip to: 83
/* 72 */      MCD_OPC_CheckField, 7, 1, 0, 205, 43, 0, // Skip to: 11292
/* 79 */      MCD_OPC_Decode, 144, 8, 15, // Opcode: SUB_A_rr
/* 83 */      MCD_OPC_FilterValue, 128, 2, 11, 0, 0, // Skip to: 100
/* 89 */      MCD_OPC_CheckField, 7, 1, 0, 188, 43, 0, // Skip to: 11292
/* 96 */      MCD_OPC_Decode, 153, 3, 15, // Opcode: EQ_A_rr
/* 100 */     MCD_OPC_FilterValue, 132, 2, 11, 0, 0, // Skip to: 117
/* 106 */     MCD_OPC_CheckField, 7, 1, 0, 171, 43, 0, // Skip to: 11292
/* 113 */     MCD_OPC_Decode, 230, 6, 15, // Opcode: NE_A
/* 117 */     MCD_OPC_FilterValue, 136, 2, 11, 0, 0, // Skip to: 134
/* 123 */     MCD_OPC_CheckField, 7, 1, 0, 154, 43, 0, // Skip to: 11292
/* 130 */     MCD_OPC_Decode, 220, 4, 15, // Opcode: LT_A_rr
/* 134 */     MCD_OPC_FilterValue, 140, 2, 11, 0, 0, // Skip to: 151
/* 140 */     MCD_OPC_CheckField, 7, 1, 0, 137, 43, 0, // Skip to: 11292
/* 147 */     MCD_OPC_Decode, 179, 3, 15, // Opcode: GE_A_rr
/* 151 */     MCD_OPC_FilterValue, 160, 2, 11, 0, 0, // Skip to: 168
/* 157 */     MCD_OPC_CheckField, 7, 1, 0, 120, 43, 0, // Skip to: 11292
/* 164 */     MCD_OPC_Decode, 152, 3, 15, // Opcode: EQZ_A_rr
/* 168 */     MCD_OPC_FilterValue, 164, 2, 11, 0, 0, // Skip to: 185
/* 174 */     MCD_OPC_CheckField, 7, 1, 0, 103, 43, 0, // Skip to: 11292
/* 181 */     MCD_OPC_Decode, 229, 6, 15, // Opcode: NEZ_A
/* 185 */     MCD_OPC_FilterValue, 176, 2, 11, 0, 0, // Skip to: 202
/* 191 */     MCD_OPC_CheckField, 7, 1, 0, 86, 43, 0, // Skip to: 11292
/* 198 */     MCD_OPC_Decode, 218, 5, 15, // Opcode: MOV_D_rr
/* 202 */     MCD_OPC_FilterValue, 128, 3, 11, 0, 0, // Skip to: 219
/* 208 */     MCD_OPC_CheckField, 7, 1, 0, 69, 43, 0, // Skip to: 11292
/* 215 */     MCD_OPC_Decode, 142, 2, 15, // Opcode: ADDSC_A_rr_v120u
/* 219 */     MCD_OPC_FilterValue, 136, 3, 11, 0, 0, // Skip to: 236
/* 225 */     MCD_OPC_CheckField, 7, 1, 0, 52, 43, 0, // Skip to: 11292
/* 232 */     MCD_OPC_Decode, 140, 2, 15, // Opcode: ADDSC_AT_rr_v120u
/* 236 */     MCD_OPC_FilterValue, 140, 3, 42, 43, 0, // Skip to: 11292
/* 242 */     MCD_OPC_CheckField, 7, 1, 0, 35, 43, 0, // Skip to: 11292
/* 249 */     MCD_OPC_Decode, 215, 5, 15, // Opcode: MOV_A_rr
/* 253 */     MCD_OPC_FilterValue, 3, 248, 1, 0, // Skip to: 762
/* 258 */     MCD_OPC_ExtractField, 18, 6,  // Inst{23-18} ...
/* 261 */     MCD_OPC_FilterValue, 2, 18, 0, 0, // Skip to: 284
/* 266 */     MCD_OPC_CheckField, 16, 2, 2, 11, 43, 0, // Skip to: 11292
/* 273 */     MCD_OPC_CheckField, 7, 1, 0, 4, 43, 0, // Skip to: 11292
/* 280 */     MCD_OPC_Decode, 192, 5, 16, // Opcode: MADD_rrr2
/* 284 */     MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 300
/* 289 */     MCD_OPC_CheckField, 7, 1, 1, 244, 42, 0, // Skip to: 11292
/* 296 */     MCD_OPC_Decode, 251, 4, 17, // Opcode: MADDR_H_rrr1_UL
/* 300 */     MCD_OPC_FilterValue, 13, 11, 0, 0, // Skip to: 316
/* 305 */     MCD_OPC_CheckField, 7, 1, 1, 228, 42, 0, // Skip to: 11292
/* 312 */     MCD_OPC_Decode, 250, 4, 17, // Opcode: MADDR_H_rrr1_LU
/* 316 */     MCD_OPC_FilterValue, 14, 11, 0, 0, // Skip to: 332
/* 321 */     MCD_OPC_CheckField, 7, 1, 1, 212, 42, 0, // Skip to: 11292
/* 328 */     MCD_OPC_Decode, 249, 4, 17, // Opcode: MADDR_H_rrr1_LL
/* 332 */     MCD_OPC_FilterValue, 15, 11, 0, 0, // Skip to: 348
/* 337 */     MCD_OPC_CheckField, 7, 1, 1, 196, 42, 0, // Skip to: 11292
/* 344 */     MCD_OPC_Decode, 252, 4, 17, // Opcode: MADDR_H_rrr1_UU
/* 348 */     MCD_OPC_FilterValue, 24, 11, 0, 0, // Skip to: 364
/* 353 */     MCD_OPC_CheckField, 7, 1, 1, 180, 42, 0, // Skip to: 11292
/* 360 */     MCD_OPC_Decode, 176, 5, 17, // Opcode: MADD_H_rrr1_UL
/* 364 */     MCD_OPC_FilterValue, 25, 11, 0, 0, // Skip to: 380
/* 369 */     MCD_OPC_CheckField, 7, 1, 1, 164, 42, 0, // Skip to: 11292
/* 376 */     MCD_OPC_Decode, 175, 5, 17, // Opcode: MADD_H_rrr1_LU
/* 380 */     MCD_OPC_FilterValue, 26, 38, 0, 0, // Skip to: 423
/* 385 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 388 */     MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 414
/* 393 */     MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 396 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 405
/* 401 */     MCD_OPC_Decode, 189, 5, 16, // Opcode: MADD_U_rrr2
/* 405 */     MCD_OPC_FilterValue, 2, 130, 42, 0, // Skip to: 11292
/* 410 */     MCD_OPC_Decode, 193, 5, 16, // Opcode: MADD_rrr2_e
/* 414 */     MCD_OPC_FilterValue, 1, 121, 42, 0, // Skip to: 11292
/* 419 */     MCD_OPC_Decode, 174, 5, 17, // Opcode: MADD_H_rrr1_LL
/* 423 */     MCD_OPC_FilterValue, 27, 11, 0, 0, // Skip to: 439
/* 428 */     MCD_OPC_CheckField, 7, 1, 1, 105, 42, 0, // Skip to: 11292
/* 435 */     MCD_OPC_Decode, 177, 5, 17, // Opcode: MADD_H_rrr1_UU
/* 439 */     MCD_OPC_FilterValue, 28, 11, 0, 0, // Skip to: 455
/* 444 */     MCD_OPC_CheckField, 7, 1, 1, 89, 42, 0, // Skip to: 11292
/* 451 */     MCD_OPC_Decode, 239, 4, 17, // Opcode: MADDM_H_rrr1_UL
/* 455 */     MCD_OPC_FilterValue, 29, 11, 0, 0, // Skip to: 471
/* 460 */     MCD_OPC_CheckField, 7, 1, 1, 73, 42, 0, // Skip to: 11292
/* 467 */     MCD_OPC_Decode, 238, 4, 17, // Opcode: MADDM_H_rrr1_LU
/* 471 */     MCD_OPC_FilterValue, 30, 11, 0, 0, // Skip to: 487
/* 476 */     MCD_OPC_CheckField, 7, 1, 1, 57, 42, 0, // Skip to: 11292
/* 483 */     MCD_OPC_Decode, 237, 4, 17, // Opcode: MADDM_H_rrr1_LL
/* 487 */     MCD_OPC_FilterValue, 31, 11, 0, 0, // Skip to: 503
/* 492 */     MCD_OPC_CheckField, 7, 1, 1, 41, 42, 0, // Skip to: 11292
/* 499 */     MCD_OPC_Decode, 240, 4, 17, // Opcode: MADDM_H_rrr1_UU
/* 503 */     MCD_OPC_FilterValue, 34, 35, 0, 0, // Skip to: 543
/* 508 */     MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 511 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 527
/* 516 */     MCD_OPC_CheckField, 7, 1, 0, 17, 42, 0, // Skip to: 11292
/* 523 */     MCD_OPC_Decode, 167, 5, 16, // Opcode: MADDS_U_rrr2
/* 527 */     MCD_OPC_FilterValue, 2, 8, 42, 0, // Skip to: 11292
/* 532 */     MCD_OPC_CheckField, 7, 1, 0, 1, 42, 0, // Skip to: 11292
/* 539 */     MCD_OPC_Decode, 171, 5, 16, // Opcode: MADDS_rrr2
/* 543 */     MCD_OPC_FilterValue, 44, 11, 0, 0, // Skip to: 559
/* 548 */     MCD_OPC_CheckField, 7, 1, 1, 241, 41, 0, // Skip to: 11292
/* 555 */     MCD_OPC_Decode, 244, 4, 17, // Opcode: MADDRS_H_rrr1_UL
/* 559 */     MCD_OPC_FilterValue, 45, 11, 0, 0, // Skip to: 575
/* 564 */     MCD_OPC_CheckField, 7, 1, 1, 225, 41, 0, // Skip to: 11292
/* 571 */     MCD_OPC_Decode, 243, 4, 17, // Opcode: MADDRS_H_rrr1_LU
/* 575 */     MCD_OPC_FilterValue, 46, 11, 0, 0, // Skip to: 591
/* 580 */     MCD_OPC_CheckField, 7, 1, 1, 209, 41, 0, // Skip to: 11292
/* 587 */     MCD_OPC_Decode, 242, 4, 17, // Opcode: MADDRS_H_rrr1_LL
/* 591 */     MCD_OPC_FilterValue, 47, 11, 0, 0, // Skip to: 607
/* 596 */     MCD_OPC_CheckField, 7, 1, 1, 193, 41, 0, // Skip to: 11292
/* 603 */     MCD_OPC_Decode, 245, 4, 17, // Opcode: MADDRS_H_rrr1_UU
/* 607 */     MCD_OPC_FilterValue, 56, 11, 0, 0, // Skip to: 623
/* 612 */     MCD_OPC_CheckField, 7, 1, 1, 177, 41, 0, // Skip to: 11292
/* 619 */     MCD_OPC_Decode, 153, 5, 17, // Opcode: MADDS_H_rrr1_UL
/* 623 */     MCD_OPC_FilterValue, 57, 11, 0, 0, // Skip to: 639
/* 628 */     MCD_OPC_CheckField, 7, 1, 1, 161, 41, 0, // Skip to: 11292
/* 635 */     MCD_OPC_Decode, 152, 5, 17, // Opcode: MADDS_H_rrr1_LU
/* 639 */     MCD_OPC_FilterValue, 58, 38, 0, 0, // Skip to: 682
/* 644 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 647 */     MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 673
/* 652 */     MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 655 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 664
/* 660 */     MCD_OPC_Decode, 168, 5, 16, // Opcode: MADDS_U_rrr2_e
/* 664 */     MCD_OPC_FilterValue, 2, 127, 41, 0, // Skip to: 11292
/* 669 */     MCD_OPC_Decode, 172, 5, 16, // Opcode: MADDS_rrr2_e
/* 673 */     MCD_OPC_FilterValue, 1, 118, 41, 0, // Skip to: 11292
/* 678 */     MCD_OPC_Decode, 151, 5, 17, // Opcode: MADDS_H_rrr1_LL
/* 682 */     MCD_OPC_FilterValue, 59, 11, 0, 0, // Skip to: 698
/* 687 */     MCD_OPC_CheckField, 7, 1, 1, 102, 41, 0, // Skip to: 11292
/* 694 */     MCD_OPC_Decode, 154, 5, 17, // Opcode: MADDS_H_rrr1_UU
/* 698 */     MCD_OPC_FilterValue, 60, 11, 0, 0, // Skip to: 714
/* 703 */     MCD_OPC_CheckField, 7, 1, 1, 86, 41, 0, // Skip to: 11292
/* 710 */     MCD_OPC_Decode, 235, 4, 17, // Opcode: MADDMS_H_rrr1_UL
/* 714 */     MCD_OPC_FilterValue, 61, 11, 0, 0, // Skip to: 730
/* 719 */     MCD_OPC_CheckField, 7, 1, 1, 70, 41, 0, // Skip to: 11292
/* 726 */     MCD_OPC_Decode, 234, 4, 17, // Opcode: MADDMS_H_rrr1_LU
/* 730 */     MCD_OPC_FilterValue, 62, 11, 0, 0, // Skip to: 746
/* 735 */     MCD_OPC_CheckField, 7, 1, 1, 54, 41, 0, // Skip to: 11292
/* 742 */     MCD_OPC_Decode, 233, 4, 17, // Opcode: MADDMS_H_rrr1_LL
/* 746 */     MCD_OPC_FilterValue, 63, 45, 41, 0, // Skip to: 11292
/* 751 */     MCD_OPC_CheckField, 7, 1, 1, 38, 41, 0, // Skip to: 11292
/* 758 */     MCD_OPC_Decode, 236, 4, 17, // Opcode: MADDMS_H_rrr1_UU
/* 762 */     MCD_OPC_FilterValue, 5, 107, 0, 0, // Skip to: 874
/* 767 */     MCD_OPC_ExtractField, 26, 2,  // Inst{27-26} ...
/* 770 */     MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 796
/* 775 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 778 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 787
/* 783 */     MCD_OPC_Decode, 158, 4, 18, // Opcode: LD_B_abs
/* 787 */     MCD_OPC_FilterValue, 1, 4, 41, 0, // Skip to: 11292
/* 792 */     MCD_OPC_Decode, 201, 4, 18, // Opcode: LD_W_abs
/* 796 */     MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 822
/* 801 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 804 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 813
/* 809 */     MCD_OPC_Decode, 147, 4, 18, // Opcode: LD_BU_abs
/* 813 */     MCD_OPC_FilterValue, 1, 234, 40, 0, // Skip to: 11292
/* 818 */     MCD_OPC_Decode, 171, 4, 18, // Opcode: LD_D_abs
/* 822 */     MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 848
/* 827 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 830 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 839
/* 835 */     MCD_OPC_Decode, 184, 4, 18, // Opcode: LD_H_abs
/* 839 */     MCD_OPC_FilterValue, 1, 208, 40, 0, // Skip to: 11292
/* 844 */     MCD_OPC_Decode, 135, 4, 18, // Opcode: LD_A_abs
/* 848 */     MCD_OPC_FilterValue, 3, 199, 40, 0, // Skip to: 11292
/* 853 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 856 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 865
/* 861 */     MCD_OPC_Decode, 177, 4, 18, // Opcode: LD_HU_abs
/* 865 */     MCD_OPC_FilterValue, 1, 182, 40, 0, // Skip to: 11292
/* 870 */     MCD_OPC_Decode, 165, 4, 18, // Opcode: LD_DA_abs
/* 874 */     MCD_OPC_FilterValue, 7, 107, 0, 0, // Skip to: 986
/* 879 */     MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 882 */     MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 908
/* 887 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 890 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 899
/* 895 */     MCD_OPC_Decode, 226, 6, 19, // Opcode: NAND_T
/* 899 */     MCD_OPC_FilterValue, 1, 148, 40, 0, // Skip to: 11292
/* 904 */     MCD_OPC_Decode, 189, 2, 19, // Opcode: AND_T
/* 908 */     MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 934
/* 913 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 916 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 925
/* 921 */     MCD_OPC_Decode, 239, 6, 19, // Opcode: ORN_T
/* 925 */     MCD_OPC_FilterValue, 1, 122, 40, 0, // Skip to: 11292
/* 930 */     MCD_OPC_Decode, 130, 7, 19, // Opcode: OR_T
/* 934 */     MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 960
/* 939 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 942 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 951
/* 947 */     MCD_OPC_Decode, 172, 8, 19, // Opcode: XNOR_T
/* 951 */     MCD_OPC_FilterValue, 1, 96, 40, 0, // Skip to: 11292
/* 956 */     MCD_OPC_Decode, 235, 6, 19, // Opcode: NOR_T
/* 960 */     MCD_OPC_FilterValue, 3, 87, 40, 0, // Skip to: 11292
/* 965 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 968 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 977
/* 973 */     MCD_OPC_Decode, 187, 8, 19, // Opcode: XOR_T
/* 977 */     MCD_OPC_FilterValue, 1, 70, 40, 0, // Skip to: 11292
/* 982 */     MCD_OPC_Decode, 170, 2, 19, // Opcode: ANDN_T
/* 986 */     MCD_OPC_FilterValue, 9, 165, 3, 0, // Skip to: 1924
/* 991 */     MCD_OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 994 */     MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 1020
/* 999 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1002 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1011
/* 1007 */    MCD_OPC_Decode, 161, 4, 20, // Opcode: LD_B_bo_pos
/* 1011 */    MCD_OPC_FilterValue, 1, 36, 40, 0, // Skip to: 11292
/* 1016 */    MCD_OPC_Decode, 216, 7, 20, // Opcode: ST_B_bo_pos
/* 1020 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 1036
/* 1025 */    MCD_OPC_CheckField, 7, 1, 0, 20, 40, 0, // Skip to: 11292
/* 1032 */    MCD_OPC_Decode, 150, 4, 20, // Opcode: LD_BU_bo_pos
/* 1036 */    MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 1062
/* 1041 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1044 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1053
/* 1049 */    MCD_OPC_Decode, 187, 4, 20, // Opcode: LD_H_bo_pos
/* 1053 */    MCD_OPC_FilterValue, 1, 250, 39, 0, // Skip to: 11292
/* 1058 */    MCD_OPC_Decode, 239, 7, 20, // Opcode: ST_H_bo_pos
/* 1062 */    MCD_OPC_FilterValue, 3, 11, 0, 0, // Skip to: 1078
/* 1067 */    MCD_OPC_CheckField, 7, 1, 0, 234, 39, 0, // Skip to: 11292
/* 1074 */    MCD_OPC_Decode, 180, 4, 20, // Opcode: LD_HU_bo_pos
/* 1078 */    MCD_OPC_FilterValue, 4, 21, 0, 0, // Skip to: 1104
/* 1083 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1086 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1095
/* 1091 */    MCD_OPC_Decode, 204, 4, 20, // Opcode: LD_W_bo_pos
/* 1095 */    MCD_OPC_FilterValue, 1, 208, 39, 0, // Skip to: 11292
/* 1100 */    MCD_OPC_Decode, 129, 8, 20, // Opcode: ST_W_bo_pos
/* 1104 */    MCD_OPC_FilterValue, 5, 21, 0, 0, // Skip to: 1130
/* 1109 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1112 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1121
/* 1117 */    MCD_OPC_Decode, 174, 4, 20, // Opcode: LD_D_bo_pos
/* 1121 */    MCD_OPC_FilterValue, 1, 182, 39, 0, // Skip to: 11292
/* 1126 */    MCD_OPC_Decode, 233, 7, 20, // Opcode: ST_D_bo_pos
/* 1130 */    MCD_OPC_FilterValue, 6, 21, 0, 0, // Skip to: 1156
/* 1135 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1138 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1147
/* 1143 */    MCD_OPC_Decode, 138, 4, 20, // Opcode: LD_A_bo_pos
/* 1147 */    MCD_OPC_FilterValue, 1, 156, 39, 0, // Skip to: 11292
/* 1152 */    MCD_OPC_Decode, 204, 7, 20, // Opcode: ST_A_bo_pos
/* 1156 */    MCD_OPC_FilterValue, 7, 21, 0, 0, // Skip to: 1182
/* 1161 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1164 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1173
/* 1169 */    MCD_OPC_Decode, 168, 4, 20, // Opcode: LD_DA_bo_pos
/* 1173 */    MCD_OPC_FilterValue, 1, 130, 39, 0, // Skip to: 11292
/* 1178 */    MCD_OPC_Decode, 227, 7, 20, // Opcode: ST_DA_bo_pos
/* 1182 */    MCD_OPC_FilterValue, 8, 21, 0, 0, // Skip to: 1208
/* 1187 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1190 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1199
/* 1195 */    MCD_OPC_Decode, 198, 4, 20, // Opcode: LD_Q_bo_pos
/* 1199 */    MCD_OPC_FilterValue, 1, 104, 39, 0, // Skip to: 11292
/* 1204 */    MCD_OPC_Decode, 250, 7, 20, // Opcode: ST_Q_bo_pos
/* 1208 */    MCD_OPC_FilterValue, 10, 11, 0, 0, // Skip to: 1224
/* 1213 */    MCD_OPC_CheckField, 7, 1, 1, 88, 39, 0, // Skip to: 11292
/* 1220 */    MCD_OPC_Decode, 199, 2, 20, // Opcode: CACHEI_I_bo_pos
/* 1224 */    MCD_OPC_FilterValue, 11, 11, 0, 0, // Skip to: 1240
/* 1229 */    MCD_OPC_CheckField, 7, 1, 1, 72, 39, 0, // Skip to: 11292
/* 1236 */    MCD_OPC_Decode, 206, 2, 20, // Opcode: CACHEI_W_bo_pos
/* 1240 */    MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 1256
/* 1245 */    MCD_OPC_CheckField, 7, 1, 1, 56, 39, 0, // Skip to: 11292
/* 1252 */    MCD_OPC_Decode, 221, 2, 20, // Opcode: CACHE_W_bo_pos
/* 1256 */    MCD_OPC_FilterValue, 13, 11, 0, 0, // Skip to: 1272
/* 1261 */    MCD_OPC_CheckField, 7, 1, 1, 40, 39, 0, // Skip to: 11292
/* 1268 */    MCD_OPC_Decode, 216, 2, 20, // Opcode: CACHE_WI_bo_pos
/* 1272 */    MCD_OPC_FilterValue, 14, 11, 0, 0, // Skip to: 1288
/* 1277 */    MCD_OPC_CheckField, 7, 1, 1, 24, 39, 0, // Skip to: 11292
/* 1284 */    MCD_OPC_Decode, 211, 2, 20, // Opcode: CACHE_I_bo_pos
/* 1288 */    MCD_OPC_FilterValue, 15, 11, 0, 0, // Skip to: 1304
/* 1293 */    MCD_OPC_CheckField, 7, 1, 1, 8, 39, 0, // Skip to: 11292
/* 1300 */    MCD_OPC_Decode, 202, 2, 20, // Opcode: CACHEI_WI_bo_pos
/* 1304 */    MCD_OPC_FilterValue, 16, 21, 0, 0, // Skip to: 1330
/* 1309 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1312 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1321
/* 1317 */    MCD_OPC_Decode, 162, 4, 20, // Opcode: LD_B_bo_pre
/* 1321 */    MCD_OPC_FilterValue, 1, 238, 38, 0, // Skip to: 11292
/* 1326 */    MCD_OPC_Decode, 217, 7, 20, // Opcode: ST_B_bo_pre
/* 1330 */    MCD_OPC_FilterValue, 17, 11, 0, 0, // Skip to: 1346
/* 1335 */    MCD_OPC_CheckField, 7, 1, 0, 222, 38, 0, // Skip to: 11292
/* 1342 */    MCD_OPC_Decode, 151, 4, 20, // Opcode: LD_BU_bo_pre
/* 1346 */    MCD_OPC_FilterValue, 18, 21, 0, 0, // Skip to: 1372
/* 1351 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1354 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1363
/* 1359 */    MCD_OPC_Decode, 188, 4, 20, // Opcode: LD_H_bo_pre
/* 1363 */    MCD_OPC_FilterValue, 1, 196, 38, 0, // Skip to: 11292
/* 1368 */    MCD_OPC_Decode, 240, 7, 20, // Opcode: ST_H_bo_pre
/* 1372 */    MCD_OPC_FilterValue, 19, 11, 0, 0, // Skip to: 1388
/* 1377 */    MCD_OPC_CheckField, 7, 1, 0, 180, 38, 0, // Skip to: 11292
/* 1384 */    MCD_OPC_Decode, 181, 4, 20, // Opcode: LD_HU_bo_pre
/* 1388 */    MCD_OPC_FilterValue, 20, 21, 0, 0, // Skip to: 1414
/* 1393 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1396 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1405
/* 1401 */    MCD_OPC_Decode, 205, 4, 20, // Opcode: LD_W_bo_pre
/* 1405 */    MCD_OPC_FilterValue, 1, 154, 38, 0, // Skip to: 11292
/* 1410 */    MCD_OPC_Decode, 130, 8, 20, // Opcode: ST_W_bo_pre
/* 1414 */    MCD_OPC_FilterValue, 21, 21, 0, 0, // Skip to: 1440
/* 1419 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1422 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1431
/* 1427 */    MCD_OPC_Decode, 175, 4, 20, // Opcode: LD_D_bo_pre
/* 1431 */    MCD_OPC_FilterValue, 1, 128, 38, 0, // Skip to: 11292
/* 1436 */    MCD_OPC_Decode, 234, 7, 20, // Opcode: ST_D_bo_pre
/* 1440 */    MCD_OPC_FilterValue, 22, 21, 0, 0, // Skip to: 1466
/* 1445 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1448 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1457
/* 1453 */    MCD_OPC_Decode, 139, 4, 20, // Opcode: LD_A_bo_pre
/* 1457 */    MCD_OPC_FilterValue, 1, 102, 38, 0, // Skip to: 11292
/* 1462 */    MCD_OPC_Decode, 205, 7, 20, // Opcode: ST_A_bo_pre
/* 1466 */    MCD_OPC_FilterValue, 23, 21, 0, 0, // Skip to: 1492
/* 1471 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1474 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1483
/* 1479 */    MCD_OPC_Decode, 169, 4, 20, // Opcode: LD_DA_bo_pre
/* 1483 */    MCD_OPC_FilterValue, 1, 76, 38, 0, // Skip to: 11292
/* 1488 */    MCD_OPC_Decode, 228, 7, 20, // Opcode: ST_DA_bo_pre
/* 1492 */    MCD_OPC_FilterValue, 24, 21, 0, 0, // Skip to: 1518
/* 1497 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1500 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1509
/* 1505 */    MCD_OPC_Decode, 199, 4, 20, // Opcode: LD_Q_bo_pre
/* 1509 */    MCD_OPC_FilterValue, 1, 50, 38, 0, // Skip to: 11292
/* 1514 */    MCD_OPC_Decode, 251, 7, 20, // Opcode: ST_Q_bo_pre
/* 1518 */    MCD_OPC_FilterValue, 26, 11, 0, 0, // Skip to: 1534
/* 1523 */    MCD_OPC_CheckField, 7, 1, 1, 34, 38, 0, // Skip to: 11292
/* 1530 */    MCD_OPC_Decode, 200, 2, 20, // Opcode: CACHEI_I_bo_pre
/* 1534 */    MCD_OPC_FilterValue, 27, 11, 0, 0, // Skip to: 1550
/* 1539 */    MCD_OPC_CheckField, 7, 1, 1, 18, 38, 0, // Skip to: 11292
/* 1546 */    MCD_OPC_Decode, 207, 2, 20, // Opcode: CACHEI_W_bo_pre
/* 1550 */    MCD_OPC_FilterValue, 28, 11, 0, 0, // Skip to: 1566
/* 1555 */    MCD_OPC_CheckField, 7, 1, 1, 2, 38, 0, // Skip to: 11292
/* 1562 */    MCD_OPC_Decode, 222, 2, 20, // Opcode: CACHE_W_bo_pre
/* 1566 */    MCD_OPC_FilterValue, 29, 11, 0, 0, // Skip to: 1582
/* 1571 */    MCD_OPC_CheckField, 7, 1, 1, 242, 37, 0, // Skip to: 11292
/* 1578 */    MCD_OPC_Decode, 217, 2, 20, // Opcode: CACHE_WI_bo_pre
/* 1582 */    MCD_OPC_FilterValue, 30, 11, 0, 0, // Skip to: 1598
/* 1587 */    MCD_OPC_CheckField, 7, 1, 1, 226, 37, 0, // Skip to: 11292
/* 1594 */    MCD_OPC_Decode, 212, 2, 20, // Opcode: CACHE_I_bo_pre
/* 1598 */    MCD_OPC_FilterValue, 31, 11, 0, 0, // Skip to: 1614
/* 1603 */    MCD_OPC_CheckField, 7, 1, 1, 210, 37, 0, // Skip to: 11292
/* 1610 */    MCD_OPC_Decode, 203, 2, 20, // Opcode: CACHEI_WI_bo_pre
/* 1614 */    MCD_OPC_FilterValue, 32, 21, 0, 0, // Skip to: 1640
/* 1619 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1622 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1631
/* 1627 */    MCD_OPC_Decode, 159, 4, 20, // Opcode: LD_B_bo_bso
/* 1631 */    MCD_OPC_FilterValue, 1, 184, 37, 0, // Skip to: 11292
/* 1636 */    MCD_OPC_Decode, 214, 7, 20, // Opcode: ST_B_bo_bso
/* 1640 */    MCD_OPC_FilterValue, 33, 11, 0, 0, // Skip to: 1656
/* 1645 */    MCD_OPC_CheckField, 7, 1, 0, 168, 37, 0, // Skip to: 11292
/* 1652 */    MCD_OPC_Decode, 148, 4, 20, // Opcode: LD_BU_bo_bso
/* 1656 */    MCD_OPC_FilterValue, 34, 21, 0, 0, // Skip to: 1682
/* 1661 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1664 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1673
/* 1669 */    MCD_OPC_Decode, 185, 4, 20, // Opcode: LD_H_bo_bso
/* 1673 */    MCD_OPC_FilterValue, 1, 142, 37, 0, // Skip to: 11292
/* 1678 */    MCD_OPC_Decode, 237, 7, 20, // Opcode: ST_H_bo_bso
/* 1682 */    MCD_OPC_FilterValue, 35, 11, 0, 0, // Skip to: 1698
/* 1687 */    MCD_OPC_CheckField, 7, 1, 0, 126, 37, 0, // Skip to: 11292
/* 1694 */    MCD_OPC_Decode, 178, 4, 20, // Opcode: LD_HU_bo_bso
/* 1698 */    MCD_OPC_FilterValue, 36, 21, 0, 0, // Skip to: 1724
/* 1703 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1706 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1715
/* 1711 */    MCD_OPC_Decode, 202, 4, 20, // Opcode: LD_W_bo_bso
/* 1715 */    MCD_OPC_FilterValue, 1, 100, 37, 0, // Skip to: 11292
/* 1720 */    MCD_OPC_Decode, 255, 7, 20, // Opcode: ST_W_bo_bso
/* 1724 */    MCD_OPC_FilterValue, 37, 21, 0, 0, // Skip to: 1750
/* 1729 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1732 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1741
/* 1737 */    MCD_OPC_Decode, 172, 4, 20, // Opcode: LD_D_bo_bso
/* 1741 */    MCD_OPC_FilterValue, 1, 74, 37, 0, // Skip to: 11292
/* 1746 */    MCD_OPC_Decode, 231, 7, 20, // Opcode: ST_D_bo_bso
/* 1750 */    MCD_OPC_FilterValue, 38, 21, 0, 0, // Skip to: 1776
/* 1755 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1758 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1767
/* 1763 */    MCD_OPC_Decode, 136, 4, 20, // Opcode: LD_A_bo_bso
/* 1767 */    MCD_OPC_FilterValue, 1, 48, 37, 0, // Skip to: 11292
/* 1772 */    MCD_OPC_Decode, 202, 7, 20, // Opcode: ST_A_bo_bso
/* 1776 */    MCD_OPC_FilterValue, 39, 21, 0, 0, // Skip to: 1802
/* 1781 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1784 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1793
/* 1789 */    MCD_OPC_Decode, 166, 4, 20, // Opcode: LD_DA_bo_bso
/* 1793 */    MCD_OPC_FilterValue, 1, 22, 37, 0, // Skip to: 11292
/* 1798 */    MCD_OPC_Decode, 225, 7, 20, // Opcode: ST_DA_bo_bso
/* 1802 */    MCD_OPC_FilterValue, 40, 21, 0, 0, // Skip to: 1828
/* 1807 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1810 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1819
/* 1815 */    MCD_OPC_Decode, 196, 4, 20, // Opcode: LD_Q_bo_bso
/* 1819 */    MCD_OPC_FilterValue, 1, 252, 36, 0, // Skip to: 11292
/* 1824 */    MCD_OPC_Decode, 248, 7, 20, // Opcode: ST_Q_bo_bso
/* 1828 */    MCD_OPC_FilterValue, 42, 11, 0, 0, // Skip to: 1844
/* 1833 */    MCD_OPC_CheckField, 7, 1, 1, 236, 36, 0, // Skip to: 11292
/* 1840 */    MCD_OPC_Decode, 198, 2, 20, // Opcode: CACHEI_I_bo_bso
/* 1844 */    MCD_OPC_FilterValue, 43, 11, 0, 0, // Skip to: 1860
/* 1849 */    MCD_OPC_CheckField, 7, 1, 1, 220, 36, 0, // Skip to: 11292
/* 1856 */    MCD_OPC_Decode, 204, 2, 20, // Opcode: CACHEI_W_bo_bso
/* 1860 */    MCD_OPC_FilterValue, 44, 11, 0, 0, // Skip to: 1876
/* 1865 */    MCD_OPC_CheckField, 7, 1, 1, 204, 36, 0, // Skip to: 11292
/* 1872 */    MCD_OPC_Decode, 219, 2, 20, // Opcode: CACHE_W_bo_bso
/* 1876 */    MCD_OPC_FilterValue, 45, 11, 0, 0, // Skip to: 1892
/* 1881 */    MCD_OPC_CheckField, 7, 1, 1, 188, 36, 0, // Skip to: 11292
/* 1888 */    MCD_OPC_Decode, 214, 2, 20, // Opcode: CACHE_WI_bo_bso
/* 1892 */    MCD_OPC_FilterValue, 46, 11, 0, 0, // Skip to: 1908
/* 1897 */    MCD_OPC_CheckField, 7, 1, 1, 172, 36, 0, // Skip to: 11292
/* 1904 */    MCD_OPC_Decode, 209, 2, 20, // Opcode: CACHE_I_bo_bso
/* 1908 */    MCD_OPC_FilterValue, 47, 163, 36, 0, // Skip to: 11292
/* 1913 */    MCD_OPC_CheckField, 7, 1, 1, 156, 36, 0, // Skip to: 11292
/* 1920 */    MCD_OPC_Decode, 201, 2, 20, // Opcode: CACHEI_WI_bo_bso
/* 1924 */    MCD_OPC_FilterValue, 11, 174, 8, 0, // Skip to: 4151
/* 1929 */    MCD_OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 1932 */    MCD_OPC_FilterValue, 0, 81, 0, 0, // Skip to: 2018
/* 1937 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1940 */    MCD_OPC_FilterValue, 0, 64, 0, 0, // Skip to: 2009
/* 1945 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 1948 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1957
/* 1953 */    MCD_OPC_Decode, 163, 2, 15, // Opcode: ADD_rr
/* 1957 */    MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 1983
/* 1962 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 1965 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1974
/* 1970 */    MCD_OPC_Decode, 141, 8, 21, // Opcode: SUBS_rr
/* 1974 */    MCD_OPC_FilterValue, 3, 97, 36, 0, // Skip to: 11292
/* 1979 */    MCD_OPC_Decode, 140, 8, 21, // Opcode: SUBS_U_rr
/* 1983 */    MCD_OPC_FilterValue, 3, 88, 36, 0, // Skip to: 11292
/* 1988 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 1991 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2000
/* 1996 */    MCD_OPC_Decode, 143, 8, 21, // Opcode: SUBX_rr
/* 2000 */    MCD_OPC_FilterValue, 1, 71, 36, 0, // Skip to: 11292
/* 2005 */    MCD_OPC_Decode, 137, 8, 21, // Opcode: SUBC_rr
/* 2009 */    MCD_OPC_FilterValue, 1, 62, 36, 0, // Skip to: 11292
/* 2014 */    MCD_OPC_Decode, 162, 2, 22, // Opcode: ADD_rc
/* 2018 */    MCD_OPC_FilterValue, 1, 35, 0, 0, // Skip to: 2058
/* 2023 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2026 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2042
/* 2031 */    MCD_OPC_CheckField, 7, 1, 0, 38, 36, 0, // Skip to: 11292
/* 2038 */    MCD_OPC_Decode, 152, 2, 15, // Opcode: ADDS_rr
/* 2042 */    MCD_OPC_FilterValue, 4, 29, 36, 0, // Skip to: 11292
/* 2047 */    MCD_OPC_CheckField, 7, 1, 0, 22, 36, 0, // Skip to: 11292
/* 2054 */    MCD_OPC_Decode, 149, 2, 15, // Opcode: ADDS_U
/* 2058 */    MCD_OPC_FilterValue, 2, 38, 0, 0, // Skip to: 2101
/* 2063 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2066 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2092
/* 2071 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2074 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2083
/* 2079 */    MCD_OPC_Decode, 155, 2, 15, // Opcode: ADDX_rr
/* 2083 */    MCD_OPC_FilterValue, 4, 244, 35, 0, // Skip to: 11292
/* 2088 */    MCD_OPC_Decode, 135, 2, 15, // Opcode: ADDC_rr
/* 2092 */    MCD_OPC_FilterValue, 1, 235, 35, 0, // Skip to: 11292
/* 2097 */    MCD_OPC_Decode, 151, 2, 22, // Opcode: ADDS_rc
/* 2101 */    MCD_OPC_FilterValue, 3, 38, 0, 0, // Skip to: 2144
/* 2106 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2109 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2135
/* 2114 */    MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 2117 */    MCD_OPC_FilterValue, 10, 4, 0, 0, // Skip to: 2126
/* 2122 */    MCD_OPC_Decode, 139, 8, 21, // Opcode: SUBS_H_rr
/* 2126 */    MCD_OPC_FilterValue, 11, 201, 35, 0, // Skip to: 11292
/* 2131 */    MCD_OPC_Decode, 138, 8, 21, // Opcode: SUBS_HU_rr
/* 2135 */    MCD_OPC_FilterValue, 1, 192, 35, 0, // Skip to: 11292
/* 2140 */    MCD_OPC_Decode, 150, 2, 22, // Opcode: ADDS_U_rc
/* 2144 */    MCD_OPC_FilterValue, 4, 28, 0, 0, // Skip to: 2177
/* 2149 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2152 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2168
/* 2157 */    MCD_OPC_CheckField, 18, 3, 0, 168, 35, 0, // Skip to: 11292
/* 2164 */    MCD_OPC_Decode, 149, 8, 15, // Opcode: SUB_rr
/* 2168 */    MCD_OPC_FilterValue, 1, 159, 35, 0, // Skip to: 11292
/* 2173 */    MCD_OPC_Decode, 154, 2, 22, // Opcode: ADDX_rc
/* 2177 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 2193
/* 2182 */    MCD_OPC_CheckField, 7, 1, 1, 143, 35, 0, // Skip to: 11292
/* 2189 */    MCD_OPC_Decode, 134, 2, 22, // Opcode: ADDC_rc
/* 2193 */    MCD_OPC_FilterValue, 7, 35, 0, 0, // Skip to: 2233
/* 2198 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2201 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2217
/* 2206 */    MCD_OPC_CheckField, 7, 1, 0, 119, 35, 0, // Skip to: 11292
/* 2213 */    MCD_OPC_Decode, 255, 1, 15, // Opcode: ABSDIF_rr
/* 2217 */    MCD_OPC_FilterValue, 4, 110, 35, 0, // Skip to: 11292
/* 2222 */    MCD_OPC_CheckField, 7, 1, 0, 103, 35, 0, // Skip to: 11292
/* 2229 */    MCD_OPC_Decode, 251, 1, 15, // Opcode: ABSDIFS_rr
/* 2233 */    MCD_OPC_FilterValue, 8, 38, 0, 0, // Skip to: 2276
/* 2238 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2241 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2267
/* 2246 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2249 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2258
/* 2254 */    MCD_OPC_Decode, 158, 3, 15, // Opcode: EQ_rr
/* 2258 */    MCD_OPC_FilterValue, 4, 69, 35, 0, // Skip to: 11292
/* 2263 */    MCD_OPC_Decode, 232, 6, 15, // Opcode: NE_rr
/* 2267 */    MCD_OPC_FilterValue, 1, 60, 35, 0, // Skip to: 11292
/* 2272 */    MCD_OPC_Decode, 150, 7, 22, // Opcode: RSUB_rc
/* 2276 */    MCD_OPC_FilterValue, 9, 35, 0, 0, // Skip to: 2316
/* 2281 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2284 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2300
/* 2289 */    MCD_OPC_CheckField, 7, 1, 0, 36, 35, 0, // Skip to: 11292
/* 2296 */    MCD_OPC_Decode, 230, 4, 15, // Opcode: LT_rr
/* 2300 */    MCD_OPC_FilterValue, 4, 27, 35, 0, // Skip to: 11292
/* 2305 */    MCD_OPC_CheckField, 7, 1, 0, 20, 35, 0, // Skip to: 11292
/* 2312 */    MCD_OPC_Decode, 226, 4, 15, // Opcode: LT_U_rr
/* 2316 */    MCD_OPC_FilterValue, 10, 38, 0, 0, // Skip to: 2359
/* 2321 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2324 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2350
/* 2329 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2332 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2341
/* 2337 */    MCD_OPC_Decode, 183, 3, 15, // Opcode: GE_rr
/* 2341 */    MCD_OPC_FilterValue, 4, 242, 34, 0, // Skip to: 11292
/* 2346 */    MCD_OPC_Decode, 181, 3, 15, // Opcode: GE_U_rr
/* 2350 */    MCD_OPC_FilterValue, 1, 233, 34, 0, // Skip to: 11292
/* 2355 */    MCD_OPC_Decode, 149, 7, 22, // Opcode: RSUBS_rc
/* 2359 */    MCD_OPC_FilterValue, 11, 11, 0, 0, // Skip to: 2375
/* 2364 */    MCD_OPC_CheckField, 7, 1, 1, 217, 34, 0, // Skip to: 11292
/* 2371 */    MCD_OPC_Decode, 148, 7, 22, // Opcode: RSUBS_U_rc
/* 2375 */    MCD_OPC_FilterValue, 12, 35, 0, 0, // Skip to: 2415
/* 2380 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2383 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2399
/* 2388 */    MCD_OPC_CheckField, 7, 1, 0, 193, 34, 0, // Skip to: 11292
/* 2395 */    MCD_OPC_Decode, 210, 5, 15, // Opcode: MIN_rr
/* 2399 */    MCD_OPC_FilterValue, 4, 184, 34, 0, // Skip to: 11292
/* 2404 */    MCD_OPC_CheckField, 7, 1, 0, 177, 34, 0, // Skip to: 11292
/* 2411 */    MCD_OPC_Decode, 208, 5, 15, // Opcode: MIN_U_rr
/* 2415 */    MCD_OPC_FilterValue, 13, 35, 0, 0, // Skip to: 2455
/* 2420 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2423 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2439
/* 2428 */    MCD_OPC_CheckField, 7, 1, 0, 153, 34, 0, // Skip to: 11292
/* 2435 */    MCD_OPC_Decode, 201, 5, 15, // Opcode: MAX_rr
/* 2439 */    MCD_OPC_FilterValue, 4, 144, 34, 0, // Skip to: 11292
/* 2444 */    MCD_OPC_CheckField, 7, 1, 0, 137, 34, 0, // Skip to: 11292
/* 2451 */    MCD_OPC_Decode, 199, 5, 15, // Opcode: MAX_U_rr
/* 2455 */    MCD_OPC_FilterValue, 14, 38, 0, 0, // Skip to: 2498
/* 2460 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2463 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2489
/* 2468 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2471 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2480
/* 2476 */    MCD_OPC_Decode, 133, 2, 15, // Opcode: ABS_rr
/* 2480 */    MCD_OPC_FilterValue, 4, 103, 34, 0, // Skip to: 11292
/* 2485 */    MCD_OPC_Decode, 130, 2, 15, // Opcode: ABSS_rr
/* 2489 */    MCD_OPC_FilterValue, 1, 94, 34, 0, // Skip to: 11292
/* 2494 */    MCD_OPC_Decode, 254, 1, 22, // Opcode: ABSDIF_rc
/* 2498 */    MCD_OPC_FilterValue, 15, 28, 0, 0, // Skip to: 2531
/* 2503 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2506 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2522
/* 2511 */    MCD_OPC_CheckField, 18, 3, 4, 70, 34, 0, // Skip to: 11292
/* 2518 */    MCD_OPC_Decode, 223, 5, 15, // Opcode: MOV_rrDcDb
/* 2522 */    MCD_OPC_FilterValue, 1, 61, 34, 0, // Skip to: 11292
/* 2527 */    MCD_OPC_Decode, 250, 1, 22, // Opcode: ABSDIFS_rc
/* 2531 */    MCD_OPC_FilterValue, 16, 38, 0, 0, // Skip to: 2574
/* 2536 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2539 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2565
/* 2544 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2547 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2556
/* 2552 */    MCD_OPC_Decode, 176, 2, 15, // Opcode: AND_EQ_rr
/* 2556 */    MCD_OPC_FilterValue, 4, 27, 34, 0, // Skip to: 11292
/* 2561 */    MCD_OPC_Decode, 186, 2, 15, // Opcode: AND_NE_rr
/* 2565 */    MCD_OPC_FilterValue, 1, 18, 34, 0, // Skip to: 11292
/* 2570 */    MCD_OPC_Decode, 157, 3, 22, // Opcode: EQ_rc
/* 2574 */    MCD_OPC_FilterValue, 17, 38, 0, 0, // Skip to: 2617
/* 2579 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2582 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2608
/* 2587 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2590 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2599
/* 2595 */    MCD_OPC_Decode, 184, 2, 15, // Opcode: AND_LT_rr
/* 2599 */    MCD_OPC_FilterValue, 4, 240, 33, 0, // Skip to: 11292
/* 2604 */    MCD_OPC_Decode, 182, 2, 15, // Opcode: AND_LT_U_rr
/* 2608 */    MCD_OPC_FilterValue, 1, 231, 33, 0, // Skip to: 11292
/* 2613 */    MCD_OPC_Decode, 231, 6, 22, // Opcode: NE_rc
/* 2617 */    MCD_OPC_FilterValue, 18, 38, 0, 0, // Skip to: 2660
/* 2622 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2625 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2651
/* 2630 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2633 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2642
/* 2638 */    MCD_OPC_Decode, 180, 2, 15, // Opcode: AND_GE_rr
/* 2642 */    MCD_OPC_FilterValue, 4, 197, 33, 0, // Skip to: 11292
/* 2647 */    MCD_OPC_Decode, 178, 2, 15, // Opcode: AND_GE_U_rr
/* 2651 */    MCD_OPC_FilterValue, 1, 188, 33, 0, // Skip to: 11292
/* 2656 */    MCD_OPC_Decode, 229, 4, 22, // Opcode: LT_rc
/* 2660 */    MCD_OPC_FilterValue, 19, 28, 0, 0, // Skip to: 2693
/* 2665 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2668 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2684
/* 2673 */    MCD_OPC_CheckField, 18, 3, 4, 164, 33, 0, // Skip to: 11292
/* 2680 */    MCD_OPC_Decode, 245, 6, 15, // Opcode: OR_EQ_rr
/* 2684 */    MCD_OPC_FilterValue, 1, 155, 33, 0, // Skip to: 11292
/* 2689 */    MCD_OPC_Decode, 225, 4, 22, // Opcode: LT_U_rc
/* 2693 */    MCD_OPC_FilterValue, 20, 38, 0, 0, // Skip to: 2736
/* 2698 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2701 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2727
/* 2706 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2709 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2718
/* 2714 */    MCD_OPC_Decode, 255, 6, 15, // Opcode: OR_NE_rr
/* 2718 */    MCD_OPC_FilterValue, 4, 121, 33, 0, // Skip to: 11292
/* 2723 */    MCD_OPC_Decode, 253, 6, 15, // Opcode: OR_LT_rr
/* 2727 */    MCD_OPC_FilterValue, 1, 112, 33, 0, // Skip to: 11292
/* 2732 */    MCD_OPC_Decode, 182, 3, 22, // Opcode: GE_rc
/* 2736 */    MCD_OPC_FilterValue, 21, 38, 0, 0, // Skip to: 2779
/* 2741 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2744 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2770
/* 2749 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2752 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2761
/* 2757 */    MCD_OPC_Decode, 251, 6, 15, // Opcode: OR_LT_U_rr
/* 2761 */    MCD_OPC_FilterValue, 4, 78, 33, 0, // Skip to: 11292
/* 2766 */    MCD_OPC_Decode, 249, 6, 15, // Opcode: OR_GE_rr
/* 2770 */    MCD_OPC_FilterValue, 1, 69, 33, 0, // Skip to: 11292
/* 2775 */    MCD_OPC_Decode, 180, 3, 22, // Opcode: GE_U_rc
/* 2779 */    MCD_OPC_FilterValue, 22, 18, 0, 0, // Skip to: 2802
/* 2784 */    MCD_OPC_CheckField, 18, 3, 0, 53, 33, 0, // Skip to: 11292
/* 2791 */    MCD_OPC_CheckField, 7, 1, 0, 46, 33, 0, // Skip to: 11292
/* 2798 */    MCD_OPC_Decode, 247, 6, 15, // Opcode: OR_GE_U_rr
/* 2802 */    MCD_OPC_FilterValue, 23, 18, 0, 0, // Skip to: 2825
/* 2807 */    MCD_OPC_CheckField, 18, 3, 4, 30, 33, 0, // Skip to: 11292
/* 2814 */    MCD_OPC_CheckField, 7, 1, 0, 23, 33, 0, // Skip to: 11292
/* 2821 */    MCD_OPC_Decode, 176, 8, 15, // Opcode: XOR_EQ_rr
/* 2825 */    MCD_OPC_FilterValue, 24, 38, 0, 0, // Skip to: 2868
/* 2830 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2833 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2859
/* 2838 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2841 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2850
/* 2846 */    MCD_OPC_Decode, 186, 8, 15, // Opcode: XOR_NE_rr
/* 2850 */    MCD_OPC_FilterValue, 4, 245, 32, 0, // Skip to: 11292
/* 2855 */    MCD_OPC_Decode, 184, 8, 15, // Opcode: XOR_LT_rr
/* 2859 */    MCD_OPC_FilterValue, 1, 236, 32, 0, // Skip to: 11292
/* 2864 */    MCD_OPC_Decode, 209, 5, 22, // Opcode: MIN_rc
/* 2868 */    MCD_OPC_FilterValue, 25, 38, 0, 0, // Skip to: 2911
/* 2873 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2876 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2902
/* 2881 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2884 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2893
/* 2889 */    MCD_OPC_Decode, 182, 8, 15, // Opcode: XOR_LT_U_rr
/* 2893 */    MCD_OPC_FilterValue, 4, 202, 32, 0, // Skip to: 11292
/* 2898 */    MCD_OPC_Decode, 180, 8, 15, // Opcode: XOR_GE_rr
/* 2902 */    MCD_OPC_FilterValue, 1, 193, 32, 0, // Skip to: 11292
/* 2907 */    MCD_OPC_Decode, 207, 5, 22, // Opcode: MIN_U_rc
/* 2911 */    MCD_OPC_FilterValue, 26, 28, 0, 0, // Skip to: 2944
/* 2916 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2919 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2935
/* 2924 */    MCD_OPC_CheckField, 18, 3, 0, 169, 32, 0, // Skip to: 11292
/* 2931 */    MCD_OPC_Decode, 178, 8, 15, // Opcode: XOR_GE_U_rr
/* 2935 */    MCD_OPC_FilterValue, 1, 160, 32, 0, // Skip to: 11292
/* 2940 */    MCD_OPC_Decode, 200, 5, 22, // Opcode: MAX_rc
/* 2944 */    MCD_OPC_FilterValue, 27, 28, 0, 0, // Skip to: 2977
/* 2949 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2952 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2968
/* 2957 */    MCD_OPC_CheckField, 18, 3, 4, 136, 32, 0, // Skip to: 11292
/* 2964 */    MCD_OPC_Decode, 175, 7, 15, // Opcode: SH_EQ_rr
/* 2968 */    MCD_OPC_FilterValue, 1, 127, 32, 0, // Skip to: 11292
/* 2973 */    MCD_OPC_Decode, 198, 5, 22, // Opcode: MAX_U_rc
/* 2977 */    MCD_OPC_FilterValue, 28, 35, 0, 0, // Skip to: 3017
/* 2982 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2985 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3001
/* 2990 */    MCD_OPC_CheckField, 7, 1, 0, 103, 32, 0, // Skip to: 11292
/* 2997 */    MCD_OPC_Decode, 188, 7, 15, // Opcode: SH_NE_rr
/* 3001 */    MCD_OPC_FilterValue, 4, 94, 32, 0, // Skip to: 11292
/* 3006 */    MCD_OPC_CheckField, 7, 1, 0, 87, 32, 0, // Skip to: 11292
/* 3013 */    MCD_OPC_Decode, 185, 7, 15, // Opcode: SH_LT_rr
/* 3017 */    MCD_OPC_FilterValue, 29, 35, 0, 0, // Skip to: 3057
/* 3022 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3025 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3041
/* 3030 */    MCD_OPC_CheckField, 7, 1, 0, 63, 32, 0, // Skip to: 11292
/* 3037 */    MCD_OPC_Decode, 183, 7, 15, // Opcode: SH_LT_U_rr
/* 3041 */    MCD_OPC_FilterValue, 4, 54, 32, 0, // Skip to: 11292
/* 3046 */    MCD_OPC_CheckField, 7, 1, 0, 47, 32, 0, // Skip to: 11292
/* 3053 */    MCD_OPC_Decode, 179, 7, 15, // Opcode: SH_GE_rr
/* 3057 */    MCD_OPC_FilterValue, 30, 18, 0, 0, // Skip to: 3080
/* 3062 */    MCD_OPC_CheckField, 18, 3, 0, 31, 32, 0, // Skip to: 11292
/* 3069 */    MCD_OPC_CheckField, 7, 1, 0, 24, 32, 0, // Skip to: 11292
/* 3076 */    MCD_OPC_Decode, 177, 7, 15, // Opcode: SH_GE_U_rr
/* 3080 */    MCD_OPC_FilterValue, 32, 28, 0, 0, // Skip to: 3113
/* 3085 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3088 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3104
/* 3093 */    MCD_OPC_CheckField, 18, 3, 0, 0, 32, 0, // Skip to: 11292
/* 3100 */    MCD_OPC_Decode, 159, 2, 15, // Opcode: ADD_B_rr
/* 3104 */    MCD_OPC_FilterValue, 1, 247, 31, 0, // Skip to: 11292
/* 3109 */    MCD_OPC_Decode, 175, 2, 22, // Opcode: AND_EQ_rc
/* 3113 */    MCD_OPC_FilterValue, 33, 11, 0, 0, // Skip to: 3129
/* 3118 */    MCD_OPC_CheckField, 7, 1, 1, 231, 31, 0, // Skip to: 11292
/* 3125 */    MCD_OPC_Decode, 185, 2, 22, // Opcode: AND_NE_rc
/* 3129 */    MCD_OPC_FilterValue, 34, 11, 0, 0, // Skip to: 3145
/* 3134 */    MCD_OPC_CheckField, 7, 1, 1, 215, 31, 0, // Skip to: 11292
/* 3141 */    MCD_OPC_Decode, 183, 2, 22, // Opcode: AND_LT_rc
/* 3145 */    MCD_OPC_FilterValue, 35, 11, 0, 0, // Skip to: 3161
/* 3150 */    MCD_OPC_CheckField, 7, 1, 1, 199, 31, 0, // Skip to: 11292
/* 3157 */    MCD_OPC_Decode, 181, 2, 22, // Opcode: AND_LT_U_rc
/* 3161 */    MCD_OPC_FilterValue, 36, 28, 0, 0, // Skip to: 3194
/* 3166 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3169 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3185
/* 3174 */    MCD_OPC_CheckField, 18, 3, 0, 175, 31, 0, // Skip to: 11292
/* 3181 */    MCD_OPC_Decode, 146, 8, 15, // Opcode: SUB_B_rr
/* 3185 */    MCD_OPC_FilterValue, 1, 166, 31, 0, // Skip to: 11292
/* 3190 */    MCD_OPC_Decode, 179, 2, 22, // Opcode: AND_GE_rc
/* 3194 */    MCD_OPC_FilterValue, 37, 11, 0, 0, // Skip to: 3210
/* 3199 */    MCD_OPC_CheckField, 7, 1, 1, 150, 31, 0, // Skip to: 11292
/* 3206 */    MCD_OPC_Decode, 177, 2, 22, // Opcode: AND_GE_U_rc
/* 3210 */    MCD_OPC_FilterValue, 39, 38, 0, 0, // Skip to: 3253
/* 3215 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3218 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3244
/* 3223 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3226 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3235
/* 3231 */    MCD_OPC_Decode, 252, 1, 15, // Opcode: ABSDIF_B_rr
/* 3235 */    MCD_OPC_FilterValue, 4, 116, 31, 0, // Skip to: 11292
/* 3240 */    MCD_OPC_Decode, 248, 1, 15, // Opcode: ABSDIFS_B_rr_v110
/* 3244 */    MCD_OPC_FilterValue, 1, 107, 31, 0, // Skip to: 11292
/* 3249 */    MCD_OPC_Decode, 244, 6, 22, // Opcode: OR_EQ_rc
/* 3253 */    MCD_OPC_FilterValue, 40, 28, 0, 0, // Skip to: 3286
/* 3258 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3261 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3277
/* 3266 */    MCD_OPC_CheckField, 18, 3, 0, 83, 31, 0, // Skip to: 11292
/* 3273 */    MCD_OPC_Decode, 154, 3, 15, // Opcode: EQ_B_rr
/* 3277 */    MCD_OPC_FilterValue, 1, 74, 31, 0, // Skip to: 11292
/* 3282 */    MCD_OPC_Decode, 254, 6, 22, // Opcode: OR_NE_rc
/* 3286 */    MCD_OPC_FilterValue, 41, 38, 0, 0, // Skip to: 3329
/* 3291 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3294 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3320
/* 3299 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3302 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3311
/* 3307 */    MCD_OPC_Decode, 221, 4, 15, // Opcode: LT_B
/* 3311 */    MCD_OPC_FilterValue, 4, 40, 31, 0, // Skip to: 11292
/* 3316 */    MCD_OPC_Decode, 222, 4, 15, // Opcode: LT_BU
/* 3320 */    MCD_OPC_FilterValue, 1, 31, 31, 0, // Skip to: 11292
/* 3325 */    MCD_OPC_Decode, 252, 6, 22, // Opcode: OR_LT_rc
/* 3329 */    MCD_OPC_FilterValue, 42, 11, 0, 0, // Skip to: 3345
/* 3334 */    MCD_OPC_CheckField, 7, 1, 1, 15, 31, 0, // Skip to: 11292
/* 3341 */    MCD_OPC_Decode, 250, 6, 22, // Opcode: OR_LT_U_rc
/* 3345 */    MCD_OPC_FilterValue, 43, 28, 0, 0, // Skip to: 3378
/* 3350 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3353 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3369
/* 3358 */    MCD_OPC_CheckField, 18, 3, 0, 247, 30, 0, // Skip to: 11292
/* 3365 */    MCD_OPC_Decode, 149, 3, 15, // Opcode: EQANY_B_rr
/* 3369 */    MCD_OPC_FilterValue, 1, 238, 30, 0, // Skip to: 11292
/* 3374 */    MCD_OPC_Decode, 248, 6, 22, // Opcode: OR_GE_rc
/* 3378 */    MCD_OPC_FilterValue, 44, 38, 0, 0, // Skip to: 3421
/* 3383 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3386 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3412
/* 3391 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3394 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3403
/* 3399 */    MCD_OPC_Decode, 203, 5, 15, // Opcode: MIN_B
/* 3403 */    MCD_OPC_FilterValue, 4, 204, 30, 0, // Skip to: 11292
/* 3408 */    MCD_OPC_Decode, 204, 5, 15, // Opcode: MIN_BU
/* 3412 */    MCD_OPC_FilterValue, 1, 195, 30, 0, // Skip to: 11292
/* 3417 */    MCD_OPC_Decode, 246, 6, 22, // Opcode: OR_GE_U_rc
/* 3421 */    MCD_OPC_FilterValue, 45, 35, 0, 0, // Skip to: 3461
/* 3426 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3429 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3445
/* 3434 */    MCD_OPC_CheckField, 7, 1, 0, 171, 30, 0, // Skip to: 11292
/* 3441 */    MCD_OPC_Decode, 194, 5, 15, // Opcode: MAX_B
/* 3445 */    MCD_OPC_FilterValue, 4, 162, 30, 0, // Skip to: 11292
/* 3450 */    MCD_OPC_CheckField, 7, 1, 0, 155, 30, 0, // Skip to: 11292
/* 3457 */    MCD_OPC_Decode, 195, 5, 15, // Opcode: MAX_BU
/* 3461 */    MCD_OPC_FilterValue, 46, 35, 0, 0, // Skip to: 3501
/* 3466 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3469 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3485
/* 3474 */    MCD_OPC_CheckField, 7, 1, 0, 131, 30, 0, // Skip to: 11292
/* 3481 */    MCD_OPC_Decode, 131, 2, 15, // Opcode: ABS_B_rr
/* 3485 */    MCD_OPC_FilterValue, 4, 122, 30, 0, // Skip to: 11292
/* 3490 */    MCD_OPC_CheckField, 7, 1, 0, 115, 30, 0, // Skip to: 11292
/* 3497 */    MCD_OPC_Decode, 128, 2, 15, // Opcode: ABSS_B_rr_v110
/* 3501 */    MCD_OPC_FilterValue, 47, 38, 0, 0, // Skip to: 3544
/* 3506 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3509 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3535
/* 3514 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3517 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3526
/* 3522 */    MCD_OPC_Decode, 154, 7, 15, // Opcode: SAT_B_rr
/* 3526 */    MCD_OPC_FilterValue, 4, 81, 30, 0, // Skip to: 11292
/* 3531 */    MCD_OPC_Decode, 152, 7, 15, // Opcode: SAT_BU_rr
/* 3535 */    MCD_OPC_FilterValue, 1, 72, 30, 0, // Skip to: 11292
/* 3540 */    MCD_OPC_Decode, 175, 8, 22, // Opcode: XOR_EQ_rc
/* 3544 */    MCD_OPC_FilterValue, 48, 28, 0, 0, // Skip to: 3577
/* 3549 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3552 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3568
/* 3557 */    MCD_OPC_CheckField, 18, 3, 0, 48, 30, 0, // Skip to: 11292
/* 3564 */    MCD_OPC_Decode, 161, 2, 15, // Opcode: ADD_H_rr
/* 3568 */    MCD_OPC_FilterValue, 1, 39, 30, 0, // Skip to: 11292
/* 3573 */    MCD_OPC_Decode, 185, 8, 22, // Opcode: XOR_NE_rc
/* 3577 */    MCD_OPC_FilterValue, 49, 38, 0, 0, // Skip to: 3620
/* 3582 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3585 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3611
/* 3590 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3593 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3602
/* 3598 */    MCD_OPC_Decode, 147, 2, 15, // Opcode: ADDS_H
/* 3602 */    MCD_OPC_FilterValue, 4, 5, 30, 0, // Skip to: 11292
/* 3607 */    MCD_OPC_Decode, 148, 2, 15, // Opcode: ADDS_HU
/* 3611 */    MCD_OPC_FilterValue, 1, 252, 29, 0, // Skip to: 11292
/* 3616 */    MCD_OPC_Decode, 183, 8, 22, // Opcode: XOR_LT_rc
/* 3620 */    MCD_OPC_FilterValue, 50, 11, 0, 0, // Skip to: 3636
/* 3625 */    MCD_OPC_CheckField, 7, 1, 1, 236, 29, 0, // Skip to: 11292
/* 3632 */    MCD_OPC_Decode, 181, 8, 22, // Opcode: XOR_LT_U_rc
/* 3636 */    MCD_OPC_FilterValue, 51, 11, 0, 0, // Skip to: 3652
/* 3641 */    MCD_OPC_CheckField, 7, 1, 1, 220, 29, 0, // Skip to: 11292
/* 3648 */    MCD_OPC_Decode, 179, 8, 22, // Opcode: XOR_GE_rc
/* 3652 */    MCD_OPC_FilterValue, 52, 28, 0, 0, // Skip to: 3685
/* 3657 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3660 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3676
/* 3665 */    MCD_OPC_CheckField, 18, 3, 0, 196, 29, 0, // Skip to: 11292
/* 3672 */    MCD_OPC_Decode, 148, 8, 15, // Opcode: SUB_H_rr
/* 3676 */    MCD_OPC_FilterValue, 1, 187, 29, 0, // Skip to: 11292
/* 3681 */    MCD_OPC_Decode, 177, 8, 22, // Opcode: XOR_GE_U_rc
/* 3685 */    MCD_OPC_FilterValue, 55, 38, 0, 0, // Skip to: 3728
/* 3690 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3693 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3719
/* 3698 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3701 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3710
/* 3706 */    MCD_OPC_Decode, 253, 1, 15, // Opcode: ABSDIF_H_rr
/* 3710 */    MCD_OPC_FilterValue, 4, 153, 29, 0, // Skip to: 11292
/* 3715 */    MCD_OPC_Decode, 249, 1, 15, // Opcode: ABSDIFS_H_rr
/* 3719 */    MCD_OPC_FilterValue, 1, 144, 29, 0, // Skip to: 11292
/* 3724 */    MCD_OPC_Decode, 174, 7, 22, // Opcode: SH_EQ_rc
/* 3728 */    MCD_OPC_FilterValue, 56, 28, 0, 0, // Skip to: 3761
/* 3733 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3736 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3752
/* 3741 */    MCD_OPC_CheckField, 18, 3, 0, 120, 29, 0, // Skip to: 11292
/* 3748 */    MCD_OPC_Decode, 155, 3, 15, // Opcode: EQ_H_rr
/* 3752 */    MCD_OPC_FilterValue, 1, 111, 29, 0, // Skip to: 11292
/* 3757 */    MCD_OPC_Decode, 187, 7, 22, // Opcode: SH_NE_rc
/* 3761 */    MCD_OPC_FilterValue, 57, 38, 0, 0, // Skip to: 3804
/* 3766 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3769 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3795
/* 3774 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3777 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3786
/* 3782 */    MCD_OPC_Decode, 223, 4, 15, // Opcode: LT_H
/* 3786 */    MCD_OPC_FilterValue, 4, 77, 29, 0, // Skip to: 11292
/* 3791 */    MCD_OPC_Decode, 224, 4, 15, // Opcode: LT_HU
/* 3795 */    MCD_OPC_FilterValue, 1, 68, 29, 0, // Skip to: 11292
/* 3800 */    MCD_OPC_Decode, 184, 7, 22, // Opcode: SH_LT_rc
/* 3804 */    MCD_OPC_FilterValue, 58, 11, 0, 0, // Skip to: 3820
/* 3809 */    MCD_OPC_CheckField, 7, 1, 1, 52, 29, 0, // Skip to: 11292
/* 3816 */    MCD_OPC_Decode, 182, 7, 22, // Opcode: SH_LT_U_rc
/* 3820 */    MCD_OPC_FilterValue, 59, 28, 0, 0, // Skip to: 3853
/* 3825 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3828 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3844
/* 3833 */    MCD_OPC_CheckField, 18, 3, 0, 28, 29, 0, // Skip to: 11292
/* 3840 */    MCD_OPC_Decode, 151, 3, 15, // Opcode: EQANY_H_rr
/* 3844 */    MCD_OPC_FilterValue, 1, 19, 29, 0, // Skip to: 11292
/* 3849 */    MCD_OPC_Decode, 178, 7, 22, // Opcode: SH_GE_rc
/* 3853 */    MCD_OPC_FilterValue, 60, 38, 0, 0, // Skip to: 3896
/* 3858 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3861 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3887
/* 3866 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3869 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3878
/* 3874 */    MCD_OPC_Decode, 205, 5, 15, // Opcode: MIN_H
/* 3878 */    MCD_OPC_FilterValue, 4, 241, 28, 0, // Skip to: 11292
/* 3883 */    MCD_OPC_Decode, 206, 5, 15, // Opcode: MIN_HU
/* 3887 */    MCD_OPC_FilterValue, 1, 232, 28, 0, // Skip to: 11292
/* 3892 */    MCD_OPC_Decode, 176, 7, 22, // Opcode: SH_GE_U_rc
/* 3896 */    MCD_OPC_FilterValue, 61, 35, 0, 0, // Skip to: 3936
/* 3901 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3904 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3920
/* 3909 */    MCD_OPC_CheckField, 7, 1, 0, 208, 28, 0, // Skip to: 11292
/* 3916 */    MCD_OPC_Decode, 196, 5, 15, // Opcode: MAX_H
/* 3920 */    MCD_OPC_FilterValue, 4, 199, 28, 0, // Skip to: 11292
/* 3925 */    MCD_OPC_CheckField, 7, 1, 0, 192, 28, 0, // Skip to: 11292
/* 3932 */    MCD_OPC_Decode, 197, 5, 15, // Opcode: MAX_HU
/* 3936 */    MCD_OPC_FilterValue, 62, 35, 0, 0, // Skip to: 3976
/* 3941 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3944 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3960
/* 3949 */    MCD_OPC_CheckField, 7, 1, 0, 168, 28, 0, // Skip to: 11292
/* 3956 */    MCD_OPC_Decode, 132, 2, 15, // Opcode: ABS_H_rr
/* 3960 */    MCD_OPC_FilterValue, 4, 159, 28, 0, // Skip to: 11292
/* 3965 */    MCD_OPC_CheckField, 7, 1, 0, 152, 28, 0, // Skip to: 11292
/* 3972 */    MCD_OPC_Decode, 129, 2, 15, // Opcode: ABSS_H_rr
/* 3976 */    MCD_OPC_FilterValue, 63, 35, 0, 0, // Skip to: 4016
/* 3981 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3984 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4000
/* 3989 */    MCD_OPC_CheckField, 7, 1, 0, 128, 28, 0, // Skip to: 11292
/* 3996 */    MCD_OPC_Decode, 158, 7, 15, // Opcode: SAT_H_rr
/* 4000 */    MCD_OPC_FilterValue, 4, 119, 28, 0, // Skip to: 11292
/* 4005 */    MCD_OPC_CheckField, 7, 1, 0, 112, 28, 0, // Skip to: 11292
/* 4012 */    MCD_OPC_Decode, 156, 7, 15, // Opcode: SAT_HU_rr
/* 4016 */    MCD_OPC_FilterValue, 64, 35, 0, 0, // Skip to: 4056
/* 4021 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4024 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4040
/* 4029 */    MCD_OPC_CheckField, 7, 1, 0, 88, 28, 0, // Skip to: 11292
/* 4036 */    MCD_OPC_Decode, 225, 5, 15, // Opcode: MOV_rrEcDb
/* 4040 */    MCD_OPC_FilterValue, 4, 79, 28, 0, // Skip to: 11292
/* 4045 */    MCD_OPC_CheckField, 7, 1, 0, 72, 28, 0, // Skip to: 11292
/* 4052 */    MCD_OPC_Decode, 224, 5, 15, // Opcode: MOV_rrEcDaDb
/* 4056 */    MCD_OPC_FilterValue, 72, 18, 0, 0, // Skip to: 4079
/* 4061 */    MCD_OPC_CheckField, 18, 3, 0, 56, 28, 0, // Skip to: 11292
/* 4068 */    MCD_OPC_CheckField, 7, 1, 0, 49, 28, 0, // Skip to: 11292
/* 4075 */    MCD_OPC_Decode, 156, 3, 15, // Opcode: EQ_W_rr
/* 4079 */    MCD_OPC_FilterValue, 73, 35, 0, 0, // Skip to: 4119
/* 4084 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4087 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4103
/* 4092 */    MCD_OPC_CheckField, 7, 1, 0, 25, 28, 0, // Skip to: 11292
/* 4099 */    MCD_OPC_Decode, 227, 4, 15, // Opcode: LT_W
/* 4103 */    MCD_OPC_FilterValue, 4, 16, 28, 0, // Skip to: 11292
/* 4108 */    MCD_OPC_CheckField, 7, 1, 0, 9, 28, 0, // Skip to: 11292
/* 4115 */    MCD_OPC_Decode, 228, 4, 15, // Opcode: LT_WU
/* 4119 */    MCD_OPC_FilterValue, 86, 11, 0, 0, // Skip to: 4135
/* 4124 */    MCD_OPC_CheckField, 7, 1, 1, 249, 27, 0, // Skip to: 11292
/* 4131 */    MCD_OPC_Decode, 148, 3, 22, // Opcode: EQANY_B_rc
/* 4135 */    MCD_OPC_FilterValue, 118, 240, 27, 0, // Skip to: 11292
/* 4140 */    MCD_OPC_CheckField, 7, 1, 1, 233, 27, 0, // Skip to: 11292
/* 4147 */    MCD_OPC_Decode, 150, 3, 22, // Opcode: EQANY_H_rc
/* 4151 */    MCD_OPC_FilterValue, 13, 7, 1, 0, // Skip to: 4419
/* 4156 */    MCD_OPC_ExtractField, 12, 20,  // Inst{31-12} ...
/* 4159 */    MCD_OPC_FilterValue, 128, 32, 11, 0, 0, // Skip to: 4176
/* 4165 */    MCD_OPC_CheckField, 7, 1, 0, 208, 27, 0, // Skip to: 11292
/* 4172 */    MCD_OPC_Decode, 129, 3, 14, // Opcode: DEBUG_sys
/* 4176 */    MCD_OPC_FilterValue, 128, 40, 11, 0, 0, // Skip to: 4193
/* 4182 */    MCD_OPC_CheckField, 7, 1, 0, 191, 27, 0, // Skip to: 11292
/* 4189 */    MCD_OPC_Decode, 145, 7, 14, // Opcode: RFM_sys
/* 4193 */    MCD_OPC_FilterValue, 128, 48, 11, 0, 0, // Skip to: 4210
/* 4199 */    MCD_OPC_CheckField, 7, 1, 0, 174, 27, 0, // Skip to: 11292
/* 4206 */    MCD_OPC_Decode, 142, 7, 14, // Opcode: RET_sys
/* 4210 */    MCD_OPC_FilterValue, 128, 56, 11, 0, 0, // Skip to: 4227
/* 4216 */    MCD_OPC_CheckField, 7, 1, 0, 157, 27, 0, // Skip to: 11292
/* 4223 */    MCD_OPC_Decode, 144, 7, 14, // Opcode: RFE_sys
/* 4227 */    MCD_OPC_FilterValue, 128, 64, 11, 0, 0, // Skip to: 4244
/* 4233 */    MCD_OPC_CheckField, 7, 1, 0, 140, 27, 0, // Skip to: 11292
/* 4240 */    MCD_OPC_Decode, 153, 8, 14, // Opcode: SVLCX_sys
/* 4244 */    MCD_OPC_FilterValue, 128, 72, 11, 0, 0, // Skip to: 4261
/* 4250 */    MCD_OPC_CheckField, 7, 1, 0, 123, 27, 0, // Skip to: 11292
/* 4257 */    MCD_OPC_Decode, 146, 7, 14, // Opcode: RSLCX_sys
/* 4261 */    MCD_OPC_FilterValue, 128, 96, 11, 0, 0, // Skip to: 4278
/* 4267 */    MCD_OPC_CheckField, 7, 1, 0, 106, 27, 0, // Skip to: 11292
/* 4274 */    MCD_OPC_Decode, 147, 3, 14, // Opcode: ENABLE_sys
/* 4278 */    MCD_OPC_FilterValue, 128, 104, 11, 0, 0, // Skip to: 4295
/* 4284 */    MCD_OPC_CheckField, 7, 1, 0, 89, 27, 0, // Skip to: 11292
/* 4291 */    MCD_OPC_Decode, 132, 3, 14, // Opcode: DISABLE_sys
/* 4295 */    MCD_OPC_FilterValue, 128, 112, 11, 0, 0, // Skip to: 4312
/* 4301 */    MCD_OPC_CheckField, 7, 1, 0, 72, 27, 0, // Skip to: 11292
/* 4308 */    MCD_OPC_Decode, 140, 7, 14, // Opcode: RESTORE_sys
/* 4312 */    MCD_OPC_FilterValue, 128, 120, 11, 0, 0, // Skip to: 4329
/* 4318 */    MCD_OPC_CheckField, 7, 1, 0, 55, 27, 0, // Skip to: 11292
/* 4325 */    MCD_OPC_Decode, 133, 3, 14, // Opcode: DISABLE_sys_1
/* 4329 */    MCD_OPC_FilterValue, 128, 144, 1, 11, 0, 0, // Skip to: 4347
/* 4336 */    MCD_OPC_CheckField, 7, 1, 0, 37, 27, 0, // Skip to: 11292
/* 4343 */    MCD_OPC_Decode, 137, 3, 14, // Opcode: DSYNC_sys
/* 4347 */    MCD_OPC_FilterValue, 128, 152, 1, 11, 0, 0, // Skip to: 4365
/* 4354 */    MCD_OPC_CheckField, 7, 1, 0, 19, 27, 0, // Skip to: 11292
/* 4361 */    MCD_OPC_Decode, 197, 3, 14, // Opcode: ISYNC_sys
/* 4365 */    MCD_OPC_FilterValue, 128, 160, 1, 11, 0, 0, // Skip to: 4383
/* 4372 */    MCD_OPC_CheckField, 7, 1, 0, 1, 27, 0, // Skip to: 11292
/* 4379 */    MCD_OPC_Decode, 167, 8, 14, // Opcode: TRAPV_sys
/* 4383 */    MCD_OPC_FilterValue, 128, 168, 1, 11, 0, 0, // Skip to: 4401
/* 4390 */    MCD_OPC_CheckField, 7, 1, 0, 239, 26, 0, // Skip to: 11292
/* 4397 */    MCD_OPC_Decode, 166, 8, 14, // Opcode: TRAPSV_sys
/* 4401 */    MCD_OPC_FilterValue, 128, 176, 1, 228, 26, 0, // Skip to: 11292
/* 4408 */    MCD_OPC_CheckField, 7, 1, 0, 221, 26, 0, // Skip to: 11292
/* 4415 */    MCD_OPC_Decode, 171, 8, 14, // Opcode: WAIT_sys
/* 4419 */    MCD_OPC_FilterValue, 15, 53, 2, 0, // Skip to: 4989
/* 4424 */    MCD_OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 4427 */    MCD_OPC_FilterValue, 0, 38, 0, 0, // Skip to: 4470
/* 4432 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 4435 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 4461
/* 4440 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4443 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 4452
/* 4448 */    MCD_OPC_Decode, 195, 7, 15, // Opcode: SH_rr
/* 4452 */    MCD_OPC_FilterValue, 4, 179, 26, 0, // Skip to: 11292
/* 4457 */    MCD_OPC_Decode, 169, 7, 15, // Opcode: SHA_rr
/* 4461 */    MCD_OPC_FilterValue, 1, 170, 26, 0, // Skip to: 11292
/* 4466 */    MCD_OPC_Decode, 194, 7, 22, // Opcode: SH_rc
/* 4470 */    MCD_OPC_FilterValue, 1, 28, 0, 0, // Skip to: 4503
/* 4475 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 4478 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4494
/* 4483 */    MCD_OPC_CheckField, 18, 3, 0, 146, 26, 0, // Skip to: 11292
/* 4490 */    MCD_OPC_Decode, 165, 7, 15, // Opcode: SHAS_rr
/* 4494 */    MCD_OPC_FilterValue, 1, 137, 26, 0, // Skip to: 11292
/* 4499 */    MCD_OPC_Decode, 168, 7, 22, // Opcode: SHA_rc
/* 4503 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 4519
/* 4508 */    MCD_OPC_CheckField, 7, 1, 1, 121, 26, 0, // Skip to: 11292
/* 4515 */    MCD_OPC_Decode, 164, 7, 22, // Opcode: SHAS_rc
/* 4519 */    MCD_OPC_FilterValue, 4, 35, 0, 0, // Skip to: 4559
/* 4524 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4527 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4543
/* 4532 */    MCD_OPC_CheckField, 7, 1, 0, 97, 26, 0, // Skip to: 11292
/* 4539 */    MCD_OPC_Decode, 191, 2, 15, // Opcode: AND_rr
/* 4543 */    MCD_OPC_FilterValue, 4, 88, 26, 0, // Skip to: 11292
/* 4548 */    MCD_OPC_CheckField, 7, 1, 0, 81, 26, 0, // Skip to: 11292
/* 4555 */    MCD_OPC_Decode, 228, 6, 15, // Opcode: NAND_rr
/* 4559 */    MCD_OPC_FilterValue, 5, 35, 0, 0, // Skip to: 4599
/* 4564 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4567 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4583
/* 4572 */    MCD_OPC_CheckField, 7, 1, 0, 57, 26, 0, // Skip to: 11292
/* 4579 */    MCD_OPC_Decode, 132, 7, 15, // Opcode: OR_rr
/* 4583 */    MCD_OPC_FilterValue, 4, 48, 26, 0, // Skip to: 11292
/* 4588 */    MCD_OPC_CheckField, 7, 1, 0, 41, 26, 0, // Skip to: 11292
/* 4595 */    MCD_OPC_Decode, 237, 6, 15, // Opcode: NOR_rr
/* 4599 */    MCD_OPC_FilterValue, 6, 35, 0, 0, // Skip to: 4639
/* 4604 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4607 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4623
/* 4612 */    MCD_OPC_CheckField, 7, 1, 0, 17, 26, 0, // Skip to: 11292
/* 4619 */    MCD_OPC_Decode, 189, 8, 15, // Opcode: XOR_rr
/* 4623 */    MCD_OPC_FilterValue, 4, 8, 26, 0, // Skip to: 11292
/* 4628 */    MCD_OPC_CheckField, 7, 1, 0, 1, 26, 0, // Skip to: 11292
/* 4635 */    MCD_OPC_Decode, 174, 8, 15, // Opcode: XNOR_rr
/* 4639 */    MCD_OPC_FilterValue, 7, 38, 0, 0, // Skip to: 4682
/* 4644 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 4647 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 4673
/* 4652 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4655 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 4664
/* 4660 */    MCD_OPC_Decode, 172, 2, 15, // Opcode: ANDN_rr
/* 4664 */    MCD_OPC_FilterValue, 4, 223, 25, 0, // Skip to: 11292
/* 4669 */    MCD_OPC_Decode, 241, 6, 15, // Opcode: ORN_rr
/* 4673 */    MCD_OPC_FilterValue, 1, 214, 25, 0, // Skip to: 11292
/* 4678 */    MCD_OPC_Decode, 171, 7, 22, // Opcode: SHUFFLE_rc
/* 4682 */    MCD_OPC_FilterValue, 8, 11, 0, 0, // Skip to: 4698
/* 4687 */    MCD_OPC_CheckField, 7, 1, 1, 198, 25, 0, // Skip to: 11292
/* 4694 */    MCD_OPC_Decode, 190, 2, 22, // Opcode: AND_rc
/* 4698 */    MCD_OPC_FilterValue, 9, 11, 0, 0, // Skip to: 4714
/* 4703 */    MCD_OPC_CheckField, 7, 1, 1, 182, 25, 0, // Skip to: 11292
/* 4710 */    MCD_OPC_Decode, 227, 6, 22, // Opcode: NAND_rc
/* 4714 */    MCD_OPC_FilterValue, 10, 11, 0, 0, // Skip to: 4730
/* 4719 */    MCD_OPC_CheckField, 7, 1, 1, 166, 25, 0, // Skip to: 11292
/* 4726 */    MCD_OPC_Decode, 131, 7, 22, // Opcode: OR_rc
/* 4730 */    MCD_OPC_FilterValue, 11, 11, 0, 0, // Skip to: 4746
/* 4735 */    MCD_OPC_CheckField, 7, 1, 1, 150, 25, 0, // Skip to: 11292
/* 4742 */    MCD_OPC_Decode, 236, 6, 22, // Opcode: NOR_rc
/* 4746 */    MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 4762
/* 4751 */    MCD_OPC_CheckField, 7, 1, 1, 134, 25, 0, // Skip to: 11292
/* 4758 */    MCD_OPC_Decode, 188, 8, 22, // Opcode: XOR_rc
/* 4762 */    MCD_OPC_FilterValue, 13, 28, 0, 0, // Skip to: 4795
/* 4767 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 4770 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4786
/* 4775 */    MCD_OPC_CheckField, 18, 3, 4, 110, 25, 0, // Skip to: 11292
/* 4782 */    MCD_OPC_Decode, 239, 2, 15, // Opcode: CLZ_rr
/* 4786 */    MCD_OPC_FilterValue, 1, 101, 25, 0, // Skip to: 11292
/* 4791 */    MCD_OPC_Decode, 173, 8, 22, // Opcode: XNOR_rc
/* 4795 */    MCD_OPC_FilterValue, 14, 38, 0, 0, // Skip to: 4838
/* 4800 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 4803 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 4829
/* 4808 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4811 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 4820
/* 4816 */    MCD_OPC_Decode, 235, 2, 15, // Opcode: CLO_rr
/* 4820 */    MCD_OPC_FilterValue, 4, 67, 25, 0, // Skip to: 11292
/* 4825 */    MCD_OPC_Decode, 237, 2, 15, // Opcode: CLS_rr
/* 4829 */    MCD_OPC_FilterValue, 1, 58, 25, 0, // Skip to: 11292
/* 4834 */    MCD_OPC_Decode, 171, 2, 22, // Opcode: ANDN_rc
/* 4838 */    MCD_OPC_FilterValue, 15, 11, 0, 0, // Skip to: 4854
/* 4843 */    MCD_OPC_CheckField, 7, 1, 1, 42, 25, 0, // Skip to: 11292
/* 4850 */    MCD_OPC_Decode, 240, 6, 22, // Opcode: ORN_rc
/* 4854 */    MCD_OPC_FilterValue, 32, 35, 0, 0, // Skip to: 4894
/* 4859 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4862 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4878
/* 4867 */    MCD_OPC_CheckField, 7, 1, 0, 18, 25, 0, // Skip to: 11292
/* 4874 */    MCD_OPC_Decode, 181, 7, 15, // Opcode: SH_H_rr
/* 4878 */    MCD_OPC_FilterValue, 4, 9, 25, 0, // Skip to: 11292
/* 4883 */    MCD_OPC_CheckField, 7, 1, 0, 2, 25, 0, // Skip to: 11292
/* 4890 */    MCD_OPC_Decode, 167, 7, 15, // Opcode: SHA_H_rr
/* 4894 */    MCD_OPC_FilterValue, 62, 35, 0, 0, // Skip to: 4934
/* 4899 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4902 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4918
/* 4907 */    MCD_OPC_CheckField, 7, 1, 0, 234, 24, 0, // Skip to: 11292
/* 4914 */    MCD_OPC_Decode, 238, 2, 15, // Opcode: CLZ_H_rr
/* 4918 */    MCD_OPC_FilterValue, 4, 225, 24, 0, // Skip to: 11292
/* 4923 */    MCD_OPC_CheckField, 7, 1, 0, 218, 24, 0, // Skip to: 11292
/* 4930 */    MCD_OPC_Decode, 234, 2, 15, // Opcode: CLO_H_rr
/* 4934 */    MCD_OPC_FilterValue, 63, 18, 0, 0, // Skip to: 4957
/* 4939 */    MCD_OPC_CheckField, 18, 3, 0, 202, 24, 0, // Skip to: 11292
/* 4946 */    MCD_OPC_CheckField, 7, 1, 0, 195, 24, 0, // Skip to: 11292
/* 4953 */    MCD_OPC_Decode, 236, 2, 15, // Opcode: CLS_H_rr
/* 4957 */    MCD_OPC_FilterValue, 64, 11, 0, 0, // Skip to: 4973
/* 4962 */    MCD_OPC_CheckField, 7, 1, 1, 179, 24, 0, // Skip to: 11292
/* 4969 */    MCD_OPC_Decode, 180, 7, 22, // Opcode: SH_H_rc
/* 4973 */    MCD_OPC_FilterValue, 65, 170, 24, 0, // Skip to: 11292
/* 4978 */    MCD_OPC_CheckField, 7, 1, 1, 163, 24, 0, // Skip to: 11292
/* 4985 */    MCD_OPC_Decode, 166, 7, 22, // Opcode: SHA_H_rc
/* 4989 */    MCD_OPC_FilterValue, 17, 21, 0, 0, // Skip to: 5015
/* 4994 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 4997 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5006
/* 5002 */    MCD_OPC_Decode, 136, 2, 23, // Opcode: ADDIH_A_rlc
/* 5006 */    MCD_OPC_FilterValue, 1, 137, 24, 0, // Skip to: 11292
/* 5011 */    MCD_OPC_Decode, 211, 5, 23, // Opcode: MOVH_A_rlc
/* 5015 */    MCD_OPC_FilterValue, 19, 85, 1, 0, // Skip to: 5361
/* 5020 */    MCD_OPC_ExtractField, 21, 3,  // Inst{23-21} ...
/* 5023 */    MCD_OPC_FilterValue, 0, 164, 0, 0, // Skip to: 5192
/* 5028 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 5031 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 5054
/* 5036 */    MCD_OPC_CheckField, 24, 4, 0, 105, 24, 0, // Skip to: 11292
/* 5043 */    MCD_OPC_CheckField, 7, 1, 1, 98, 24, 0, // Skip to: 11292
/* 5050 */    MCD_OPC_Decode, 215, 6, 24, // Opcode: MUL_Q_rr1_2_U
/* 5054 */    MCD_OPC_FilterValue, 1, 18, 0, 0, // Skip to: 5077
/* 5059 */    MCD_OPC_CheckField, 24, 4, 0, 82, 24, 0, // Skip to: 11292
/* 5066 */    MCD_OPC_CheckField, 7, 1, 1, 75, 24, 0, // Skip to: 11292
/* 5073 */    MCD_OPC_Decode, 213, 6, 24, // Opcode: MUL_Q_rr1_2_L
/* 5077 */    MCD_OPC_FilterValue, 2, 18, 0, 0, // Skip to: 5100
/* 5082 */    MCD_OPC_CheckField, 24, 4, 0, 59, 24, 0, // Skip to: 11292
/* 5089 */    MCD_OPC_CheckField, 7, 1, 1, 52, 24, 0, // Skip to: 11292
/* 5096 */    MCD_OPC_Decode, 217, 6, 24, // Opcode: MUL_Q_rr1_2__
/* 5100 */    MCD_OPC_FilterValue, 4, 18, 0, 0, // Skip to: 5123
/* 5105 */    MCD_OPC_CheckField, 24, 4, 0, 36, 24, 0, // Skip to: 11292
/* 5112 */    MCD_OPC_CheckField, 7, 1, 1, 29, 24, 0, // Skip to: 11292
/* 5119 */    MCD_OPC_Decode, 212, 6, 24, // Opcode: MUL_Q_rr1_2UU
/* 5123 */    MCD_OPC_FilterValue, 5, 18, 0, 0, // Skip to: 5146
/* 5128 */    MCD_OPC_CheckField, 24, 4, 0, 13, 24, 0, // Skip to: 11292
/* 5135 */    MCD_OPC_CheckField, 7, 1, 1, 6, 24, 0, // Skip to: 11292
/* 5142 */    MCD_OPC_Decode, 211, 6, 24, // Opcode: MUL_Q_rr1_2LL
/* 5146 */    MCD_OPC_FilterValue, 6, 18, 0, 0, // Skip to: 5169
/* 5151 */    MCD_OPC_CheckField, 24, 4, 0, 246, 23, 0, // Skip to: 11292
/* 5158 */    MCD_OPC_CheckField, 7, 1, 1, 239, 23, 0, // Skip to: 11292
/* 5165 */    MCD_OPC_Decode, 201, 6, 24, // Opcode: MULR_Q_rr1_2UU
/* 5169 */    MCD_OPC_FilterValue, 7, 230, 23, 0, // Skip to: 11292
/* 5174 */    MCD_OPC_CheckField, 24, 4, 0, 223, 23, 0, // Skip to: 11292
/* 5181 */    MCD_OPC_CheckField, 7, 1, 1, 216, 23, 0, // Skip to: 11292
/* 5188 */    MCD_OPC_Decode, 200, 6, 24, // Opcode: MULR_Q_rr1_2LL
/* 5192 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 5208
/* 5197 */    MCD_OPC_CheckField, 7, 1, 0, 200, 23, 0, // Skip to: 11292
/* 5204 */    MCD_OPC_Decode, 190, 5, 25, // Opcode: MADD_rcr
/* 5208 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 5224
/* 5213 */    MCD_OPC_CheckField, 7, 1, 0, 184, 23, 0, // Skip to: 11292
/* 5220 */    MCD_OPC_Decode, 188, 5, 25, // Opcode: MADD_U_rcr
/* 5224 */    MCD_OPC_FilterValue, 3, 68, 0, 0, // Skip to: 5297
/* 5229 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 5232 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5241
/* 5237 */    MCD_OPC_Decode, 191, 5, 25, // Opcode: MADD_rcr_e
/* 5241 */    MCD_OPC_FilterValue, 1, 158, 23, 0, // Skip to: 11292
/* 5246 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 5249 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 5265
/* 5254 */    MCD_OPC_CheckField, 24, 4, 0, 143, 23, 0, // Skip to: 11292
/* 5261 */    MCD_OPC_Decode, 216, 6, 24, // Opcode: MUL_Q_rr1_2_Ue
/* 5265 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 5281
/* 5270 */    MCD_OPC_CheckField, 24, 4, 0, 127, 23, 0, // Skip to: 11292
/* 5277 */    MCD_OPC_Decode, 214, 6, 24, // Opcode: MUL_Q_rr1_2_Le
/* 5281 */    MCD_OPC_FilterValue, 3, 118, 23, 0, // Skip to: 11292
/* 5286 */    MCD_OPC_CheckField, 24, 4, 0, 111, 23, 0, // Skip to: 11292
/* 5293 */    MCD_OPC_Decode, 218, 6, 24, // Opcode: MUL_Q_rr1_2__e
/* 5297 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 5313
/* 5302 */    MCD_OPC_CheckField, 7, 1, 0, 95, 23, 0, // Skip to: 11292
/* 5309 */    MCD_OPC_Decode, 165, 5, 25, // Opcode: MADDS_U_rcr
/* 5313 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 5329
/* 5318 */    MCD_OPC_CheckField, 7, 1, 0, 79, 23, 0, // Skip to: 11292
/* 5325 */    MCD_OPC_Decode, 169, 5, 25, // Opcode: MADDS_rcr
/* 5329 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 5345
/* 5334 */    MCD_OPC_CheckField, 7, 1, 0, 63, 23, 0, // Skip to: 11292
/* 5341 */    MCD_OPC_Decode, 166, 5, 25, // Opcode: MADDS_U_rcr_e
/* 5345 */    MCD_OPC_FilterValue, 7, 54, 23, 0, // Skip to: 11292
/* 5350 */    MCD_OPC_CheckField, 7, 1, 0, 47, 23, 0, // Skip to: 11292
/* 5357 */    MCD_OPC_Decode, 170, 5, 25, // Opcode: MADDS_rcr_e
/* 5361 */    MCD_OPC_FilterValue, 21, 67, 0, 0, // Skip to: 5433
/* 5366 */    MCD_OPC_ExtractField, 26, 2,  // Inst{27-26} ...
/* 5369 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 5385
/* 5374 */    MCD_OPC_CheckField, 7, 1, 0, 23, 23, 0, // Skip to: 11292
/* 5381 */    MCD_OPC_Decode, 197, 7, 18, // Opcode: STLCX_abs
/* 5385 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 5401
/* 5390 */    MCD_OPC_CheckField, 7, 1, 0, 7, 23, 0, // Skip to: 11292
/* 5397 */    MCD_OPC_Decode, 199, 7, 18, // Opcode: STUCX_abs
/* 5401 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 5417
/* 5406 */    MCD_OPC_CheckField, 7, 1, 0, 247, 22, 0, // Skip to: 11292
/* 5413 */    MCD_OPC_Decode, 253, 3, 18, // Opcode: LDLCX_abs
/* 5417 */    MCD_OPC_FilterValue, 3, 238, 22, 0, // Skip to: 11292
/* 5422 */    MCD_OPC_CheckField, 7, 1, 0, 231, 22, 0, // Skip to: 11292
/* 5429 */    MCD_OPC_Decode, 133, 4, 18, // Opcode: LDUCX_abs
/* 5433 */    MCD_OPC_FilterValue, 23, 105, 0, 0, // Skip to: 5543
/* 5438 */    MCD_OPC_ExtractField, 21, 3,  // Inst{23-21} ...
/* 5441 */    MCD_OPC_FilterValue, 0, 28, 0, 0, // Skip to: 5474
/* 5446 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 5449 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5458
/* 5454 */    MCD_OPC_Decode, 193, 3, 26, // Opcode: INSERT_rrrr
/* 5458 */    MCD_OPC_FilterValue, 1, 197, 22, 0, // Skip to: 11292
/* 5463 */    MCD_OPC_CheckField, 16, 5, 0, 190, 22, 0, // Skip to: 11292
/* 5470 */    MCD_OPC_Decode, 190, 3, 27, // Opcode: INSERT_rcrr
/* 5474 */    MCD_OPC_FilterValue, 2, 18, 0, 0, // Skip to: 5497
/* 5479 */    MCD_OPC_CheckField, 16, 5, 0, 174, 22, 0, // Skip to: 11292
/* 5486 */    MCD_OPC_CheckField, 7, 1, 0, 167, 22, 0, // Skip to: 11292
/* 5493 */    MCD_OPC_Decode, 165, 3, 28, // Opcode: EXTR_rrrr
/* 5497 */    MCD_OPC_FilterValue, 3, 18, 0, 0, // Skip to: 5520
/* 5502 */    MCD_OPC_CheckField, 16, 5, 0, 151, 22, 0, // Skip to: 11292
/* 5509 */    MCD_OPC_CheckField, 7, 1, 0, 144, 22, 0, // Skip to: 11292
/* 5516 */    MCD_OPC_Decode, 162, 3, 28, // Opcode: EXTR_U_rrrr
/* 5520 */    MCD_OPC_FilterValue, 4, 135, 22, 0, // Skip to: 11292
/* 5525 */    MCD_OPC_CheckField, 16, 5, 0, 128, 22, 0, // Skip to: 11292
/* 5532 */    MCD_OPC_CheckField, 7, 1, 0, 121, 22, 0, // Skip to: 11292
/* 5539 */    MCD_OPC_Decode, 131, 3, 28, // Opcode: DEXTR_rrrr
/* 5543 */    MCD_OPC_FilterValue, 25, 21, 0, 0, // Skip to: 5569
/* 5548 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 5551 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5560
/* 5556 */    MCD_OPC_Decode, 207, 4, 29, // Opcode: LD_W_bol
/* 5560 */    MCD_OPC_FilterValue, 1, 95, 22, 0, // Skip to: 11292
/* 5565 */    MCD_OPC_Decode, 141, 4, 29, // Opcode: LD_A_bol
/* 5569 */    MCD_OPC_FilterValue, 27, 21, 0, 0, // Skip to: 5595
/* 5574 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 5577 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5586
/* 5582 */    MCD_OPC_Decode, 138, 2, 23, // Opcode: ADDI_rlc
/* 5586 */    MCD_OPC_FilterValue, 1, 69, 22, 0, // Skip to: 11292
/* 5591 */    MCD_OPC_Decode, 137, 2, 23, // Opcode: ADDIH_rlc
/* 5595 */    MCD_OPC_FilterValue, 29, 21, 0, 0, // Skip to: 5621
/* 5600 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 5603 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5612
/* 5608 */    MCD_OPC_Decode, 251, 3, 30, // Opcode: J_b
/* 5612 */    MCD_OPC_FilterValue, 1, 43, 22, 0, // Skip to: 11292
/* 5617 */    MCD_OPC_Decode, 203, 3, 30, // Opcode: JA_b
/* 5621 */    MCD_OPC_FilterValue, 31, 55, 0, 0, // Skip to: 5681
/* 5626 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 5629 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 5655
/* 5634 */    MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 5637 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5646
/* 5642 */    MCD_OPC_Decode, 231, 3, 31, // Opcode: JNEI_brr
/* 5646 */    MCD_OPC_FilterValue, 1, 9, 22, 0, // Skip to: 11292
/* 5651 */    MCD_OPC_Decode, 229, 3, 31, // Opcode: JNED_brr
/* 5655 */    MCD_OPC_FilterValue, 1, 0, 22, 0, // Skip to: 11292
/* 5660 */    MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 5663 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5672
/* 5668 */    MCD_OPC_Decode, 230, 3, 32, // Opcode: JNEI_brc
/* 5672 */    MCD_OPC_FilterValue, 1, 239, 21, 0, // Skip to: 11292
/* 5677 */    MCD_OPC_Decode, 228, 3, 32, // Opcode: JNED_brc
/* 5681 */    MCD_OPC_FilterValue, 35, 248, 1, 0, // Skip to: 6190
/* 5686 */    MCD_OPC_ExtractField, 18, 6,  // Inst{23-18} ...
/* 5689 */    MCD_OPC_FilterValue, 2, 18, 0, 0, // Skip to: 5712
/* 5694 */    MCD_OPC_CheckField, 16, 2, 2, 215, 21, 0, // Skip to: 11292
/* 5701 */    MCD_OPC_CheckField, 7, 1, 0, 208, 21, 0, // Skip to: 11292
/* 5708 */    MCD_OPC_Decode, 189, 6, 16, // Opcode: MSUB_rrr2
/* 5712 */    MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 5728
/* 5717 */    MCD_OPC_CheckField, 7, 1, 1, 192, 21, 0, // Skip to: 11292
/* 5724 */    MCD_OPC_Decode, 144, 6, 17, // Opcode: MSUBR_H_rrr1_UL
/* 5728 */    MCD_OPC_FilterValue, 13, 11, 0, 0, // Skip to: 5744
/* 5733 */    MCD_OPC_CheckField, 7, 1, 1, 176, 21, 0, // Skip to: 11292
/* 5740 */    MCD_OPC_Decode, 143, 6, 17, // Opcode: MSUBR_H_rrr1_LU
/* 5744 */    MCD_OPC_FilterValue, 14, 11, 0, 0, // Skip to: 5760
/* 5749 */    MCD_OPC_CheckField, 7, 1, 1, 160, 21, 0, // Skip to: 11292
/* 5756 */    MCD_OPC_Decode, 142, 6, 17, // Opcode: MSUBR_H_rrr1_LL
/* 5760 */    MCD_OPC_FilterValue, 15, 11, 0, 0, // Skip to: 5776
/* 5765 */    MCD_OPC_CheckField, 7, 1, 1, 144, 21, 0, // Skip to: 11292
/* 5772 */    MCD_OPC_Decode, 145, 6, 17, // Opcode: MSUBR_H_rrr1_UU
/* 5776 */    MCD_OPC_FilterValue, 24, 11, 0, 0, // Skip to: 5792
/* 5781 */    MCD_OPC_CheckField, 7, 1, 1, 128, 21, 0, // Skip to: 11292
/* 5788 */    MCD_OPC_Decode, 173, 6, 17, // Opcode: MSUB_H_rrr1_UL
/* 5792 */    MCD_OPC_FilterValue, 25, 11, 0, 0, // Skip to: 5808
/* 5797 */    MCD_OPC_CheckField, 7, 1, 1, 112, 21, 0, // Skip to: 11292
/* 5804 */    MCD_OPC_Decode, 172, 6, 17, // Opcode: MSUB_H_rrr1_LU
/* 5808 */    MCD_OPC_FilterValue, 26, 38, 0, 0, // Skip to: 5851
/* 5813 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 5816 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 5842
/* 5821 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 5824 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5833
/* 5829 */    MCD_OPC_Decode, 186, 6, 16, // Opcode: MSUB_U_rrr2
/* 5833 */    MCD_OPC_FilterValue, 2, 78, 21, 0, // Skip to: 11292
/* 5838 */    MCD_OPC_Decode, 190, 6, 16, // Opcode: MSUB_rrr2_e
/* 5842 */    MCD_OPC_FilterValue, 1, 69, 21, 0, // Skip to: 11292
/* 5847 */    MCD_OPC_Decode, 171, 6, 17, // Opcode: MSUB_H_rrr1_LL
/* 5851 */    MCD_OPC_FilterValue, 27, 11, 0, 0, // Skip to: 5867
/* 5856 */    MCD_OPC_CheckField, 7, 1, 1, 53, 21, 0, // Skip to: 11292
/* 5863 */    MCD_OPC_Decode, 174, 6, 17, // Opcode: MSUB_H_rrr1_UU
/* 5867 */    MCD_OPC_FilterValue, 28, 11, 0, 0, // Skip to: 5883
/* 5872 */    MCD_OPC_CheckField, 7, 1, 1, 37, 21, 0, // Skip to: 11292
/* 5879 */    MCD_OPC_Decode, 132, 6, 17, // Opcode: MSUBM_H_rrr1_UL
/* 5883 */    MCD_OPC_FilterValue, 29, 11, 0, 0, // Skip to: 5899
/* 5888 */    MCD_OPC_CheckField, 7, 1, 1, 21, 21, 0, // Skip to: 11292
/* 5895 */    MCD_OPC_Decode, 131, 6, 17, // Opcode: MSUBM_H_rrr1_LU
/* 5899 */    MCD_OPC_FilterValue, 30, 11, 0, 0, // Skip to: 5915
/* 5904 */    MCD_OPC_CheckField, 7, 1, 1, 5, 21, 0, // Skip to: 11292
/* 5911 */    MCD_OPC_Decode, 130, 6, 17, // Opcode: MSUBM_H_rrr1_LL
/* 5915 */    MCD_OPC_FilterValue, 31, 11, 0, 0, // Skip to: 5931
/* 5920 */    MCD_OPC_CheckField, 7, 1, 1, 245, 20, 0, // Skip to: 11292
/* 5927 */    MCD_OPC_Decode, 133, 6, 17, // Opcode: MSUBM_H_rrr1_UU
/* 5931 */    MCD_OPC_FilterValue, 34, 35, 0, 0, // Skip to: 5971
/* 5936 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 5939 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 5955
/* 5944 */    MCD_OPC_CheckField, 7, 1, 0, 221, 20, 0, // Skip to: 11292
/* 5951 */    MCD_OPC_Decode, 164, 6, 16, // Opcode: MSUBS_U_rrr2
/* 5955 */    MCD_OPC_FilterValue, 2, 212, 20, 0, // Skip to: 11292
/* 5960 */    MCD_OPC_CheckField, 7, 1, 0, 205, 20, 0, // Skip to: 11292
/* 5967 */    MCD_OPC_Decode, 168, 6, 16, // Opcode: MSUBS_rrr2
/* 5971 */    MCD_OPC_FilterValue, 44, 11, 0, 0, // Skip to: 5987
/* 5976 */    MCD_OPC_CheckField, 7, 1, 1, 189, 20, 0, // Skip to: 11292
/* 5983 */    MCD_OPC_Decode, 137, 6, 17, // Opcode: MSUBRS_H_rrr1_UL
/* 5987 */    MCD_OPC_FilterValue, 45, 11, 0, 0, // Skip to: 6003
/* 5992 */    MCD_OPC_CheckField, 7, 1, 1, 173, 20, 0, // Skip to: 11292
/* 5999 */    MCD_OPC_Decode, 136, 6, 17, // Opcode: MSUBRS_H_rrr1_LU
/* 6003 */    MCD_OPC_FilterValue, 46, 11, 0, 0, // Skip to: 6019
/* 6008 */    MCD_OPC_CheckField, 7, 1, 1, 157, 20, 0, // Skip to: 11292
/* 6015 */    MCD_OPC_Decode, 135, 6, 17, // Opcode: MSUBRS_H_rrr1_LL
/* 6019 */    MCD_OPC_FilterValue, 47, 11, 0, 0, // Skip to: 6035
/* 6024 */    MCD_OPC_CheckField, 7, 1, 1, 141, 20, 0, // Skip to: 11292
/* 6031 */    MCD_OPC_Decode, 138, 6, 17, // Opcode: MSUBRS_H_rrr1_UU
/* 6035 */    MCD_OPC_FilterValue, 56, 11, 0, 0, // Skip to: 6051
/* 6040 */    MCD_OPC_CheckField, 7, 1, 1, 125, 20, 0, // Skip to: 11292
/* 6047 */    MCD_OPC_Decode, 150, 6, 17, // Opcode: MSUBS_H_rrr1_UL
/* 6051 */    MCD_OPC_FilterValue, 57, 11, 0, 0, // Skip to: 6067
/* 6056 */    MCD_OPC_CheckField, 7, 1, 1, 109, 20, 0, // Skip to: 11292
/* 6063 */    MCD_OPC_Decode, 149, 6, 17, // Opcode: MSUBS_H_rrr1_LU
/* 6067 */    MCD_OPC_FilterValue, 58, 38, 0, 0, // Skip to: 6110
/* 6072 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6075 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 6101
/* 6080 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 6083 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6092
/* 6088 */    MCD_OPC_Decode, 165, 6, 16, // Opcode: MSUBS_U_rrr2_e
/* 6092 */    MCD_OPC_FilterValue, 2, 75, 20, 0, // Skip to: 11292
/* 6097 */    MCD_OPC_Decode, 169, 6, 16, // Opcode: MSUBS_rrr2_e
/* 6101 */    MCD_OPC_FilterValue, 1, 66, 20, 0, // Skip to: 11292
/* 6106 */    MCD_OPC_Decode, 148, 6, 17, // Opcode: MSUBS_H_rrr1_LL
/* 6110 */    MCD_OPC_FilterValue, 59, 11, 0, 0, // Skip to: 6126
/* 6115 */    MCD_OPC_CheckField, 7, 1, 1, 50, 20, 0, // Skip to: 11292
/* 6122 */    MCD_OPC_Decode, 151, 6, 17, // Opcode: MSUBS_H_rrr1_UU
/* 6126 */    MCD_OPC_FilterValue, 60, 11, 0, 0, // Skip to: 6142
/* 6131 */    MCD_OPC_CheckField, 7, 1, 1, 34, 20, 0, // Skip to: 11292
/* 6138 */    MCD_OPC_Decode, 128, 6, 17, // Opcode: MSUBMS_H_rrr1_UL
/* 6142 */    MCD_OPC_FilterValue, 61, 11, 0, 0, // Skip to: 6158
/* 6147 */    MCD_OPC_CheckField, 7, 1, 1, 18, 20, 0, // Skip to: 11292
/* 6154 */    MCD_OPC_Decode, 255, 5, 17, // Opcode: MSUBMS_H_rrr1_LU
/* 6158 */    MCD_OPC_FilterValue, 62, 11, 0, 0, // Skip to: 6174
/* 6163 */    MCD_OPC_CheckField, 7, 1, 1, 2, 20, 0, // Skip to: 11292
/* 6170 */    MCD_OPC_Decode, 254, 5, 17, // Opcode: MSUBMS_H_rrr1_LL
/* 6174 */    MCD_OPC_FilterValue, 63, 249, 19, 0, // Skip to: 11292
/* 6179 */    MCD_OPC_CheckField, 7, 1, 1, 242, 19, 0, // Skip to: 11292
/* 6186 */    MCD_OPC_Decode, 129, 6, 17, // Opcode: MSUBMS_H_rrr1_UU
/* 6190 */    MCD_OPC_FilterValue, 37, 87, 0, 0, // Skip to: 6282
/* 6195 */    MCD_OPC_ExtractField, 26, 2,  // Inst{27-26} ...
/* 6198 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 6224
/* 6203 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6206 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6215
/* 6211 */    MCD_OPC_Decode, 213, 7, 18, // Opcode: ST_B_abs
/* 6215 */    MCD_OPC_FilterValue, 1, 208, 19, 0, // Skip to: 11292
/* 6220 */    MCD_OPC_Decode, 254, 7, 18, // Opcode: ST_W_abs
/* 6224 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 6240
/* 6229 */    MCD_OPC_CheckField, 7, 1, 1, 192, 19, 0, // Skip to: 11292
/* 6236 */    MCD_OPC_Decode, 230, 7, 18, // Opcode: ST_D_abs
/* 6240 */    MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 6266
/* 6245 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6248 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6257
/* 6253 */    MCD_OPC_Decode, 236, 7, 18, // Opcode: ST_H_abs
/* 6257 */    MCD_OPC_FilterValue, 1, 166, 19, 0, // Skip to: 11292
/* 6262 */    MCD_OPC_Decode, 201, 7, 18, // Opcode: ST_A_abs
/* 6266 */    MCD_OPC_FilterValue, 3, 157, 19, 0, // Skip to: 11292
/* 6271 */    MCD_OPC_CheckField, 7, 1, 1, 150, 19, 0, // Skip to: 11292
/* 6278 */    MCD_OPC_Decode, 224, 7, 18, // Opcode: ST_DA_abs
/* 6282 */    MCD_OPC_FilterValue, 39, 107, 0, 0, // Skip to: 6394
/* 6287 */    MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 6290 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 6316
/* 6295 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6298 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6307
/* 6303 */    MCD_OPC_Decode, 173, 7, 19, // Opcode: SH_AND_T
/* 6307 */    MCD_OPC_FilterValue, 1, 116, 19, 0, // Skip to: 11292
/* 6312 */    MCD_OPC_Decode, 186, 7, 19, // Opcode: SH_NAND_T
/* 6316 */    MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 6342
/* 6321 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6324 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6333
/* 6329 */    MCD_OPC_Decode, 191, 7, 19, // Opcode: SH_OR_T
/* 6333 */    MCD_OPC_FilterValue, 1, 90, 19, 0, // Skip to: 11292
/* 6338 */    MCD_OPC_Decode, 190, 7, 19, // Opcode: SH_ORN_T
/* 6342 */    MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 6368
/* 6347 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6350 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6359
/* 6355 */    MCD_OPC_Decode, 189, 7, 19, // Opcode: SH_NOR_T
/* 6359 */    MCD_OPC_FilterValue, 1, 64, 19, 0, // Skip to: 11292
/* 6364 */    MCD_OPC_Decode, 192, 7, 19, // Opcode: SH_XNOR_T
/* 6368 */    MCD_OPC_FilterValue, 3, 55, 19, 0, // Skip to: 11292
/* 6373 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6376 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6385
/* 6381 */    MCD_OPC_Decode, 172, 7, 19, // Opcode: SH_ANDN_T
/* 6385 */    MCD_OPC_FilterValue, 1, 38, 19, 0, // Skip to: 11292
/* 6390 */    MCD_OPC_Decode, 193, 7, 19, // Opcode: SH_XOR_T
/* 6394 */    MCD_OPC_FilterValue, 41, 47, 2, 0, // Skip to: 6958
/* 6399 */    MCD_OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 6402 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 6428
/* 6407 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6410 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6419
/* 6415 */    MCD_OPC_Decode, 163, 4, 20, // Opcode: LD_B_bo_r
/* 6419 */    MCD_OPC_FilterValue, 1, 4, 19, 0, // Skip to: 11292
/* 6424 */    MCD_OPC_Decode, 218, 7, 20, // Opcode: ST_B_bo_r
/* 6428 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 6444
/* 6433 */    MCD_OPC_CheckField, 7, 1, 0, 244, 18, 0, // Skip to: 11292
/* 6440 */    MCD_OPC_Decode, 152, 4, 20, // Opcode: LD_BU_bo_r
/* 6444 */    MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 6470
/* 6449 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6452 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6461
/* 6457 */    MCD_OPC_Decode, 189, 4, 20, // Opcode: LD_H_bo_r
/* 6461 */    MCD_OPC_FilterValue, 1, 218, 18, 0, // Skip to: 11292
/* 6466 */    MCD_OPC_Decode, 241, 7, 20, // Opcode: ST_H_bo_r
/* 6470 */    MCD_OPC_FilterValue, 3, 11, 0, 0, // Skip to: 6486
/* 6475 */    MCD_OPC_CheckField, 7, 1, 0, 202, 18, 0, // Skip to: 11292
/* 6482 */    MCD_OPC_Decode, 182, 4, 20, // Opcode: LD_HU_bo_r
/* 6486 */    MCD_OPC_FilterValue, 4, 21, 0, 0, // Skip to: 6512
/* 6491 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6494 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6503
/* 6499 */    MCD_OPC_Decode, 206, 4, 20, // Opcode: LD_W_bo_r
/* 6503 */    MCD_OPC_FilterValue, 1, 176, 18, 0, // Skip to: 11292
/* 6508 */    MCD_OPC_Decode, 131, 8, 20, // Opcode: ST_W_bo_r
/* 6512 */    MCD_OPC_FilterValue, 5, 21, 0, 0, // Skip to: 6538
/* 6517 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6520 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6529
/* 6525 */    MCD_OPC_Decode, 176, 4, 20, // Opcode: LD_D_bo_r
/* 6529 */    MCD_OPC_FilterValue, 1, 150, 18, 0, // Skip to: 11292
/* 6534 */    MCD_OPC_Decode, 235, 7, 20, // Opcode: ST_D_bo_r
/* 6538 */    MCD_OPC_FilterValue, 6, 21, 0, 0, // Skip to: 6564
/* 6543 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6546 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6555
/* 6551 */    MCD_OPC_Decode, 140, 4, 20, // Opcode: LD_A_bo_r
/* 6555 */    MCD_OPC_FilterValue, 1, 124, 18, 0, // Skip to: 11292
/* 6560 */    MCD_OPC_Decode, 206, 7, 20, // Opcode: ST_A_bo_r
/* 6564 */    MCD_OPC_FilterValue, 7, 21, 0, 0, // Skip to: 6590
/* 6569 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6572 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6581
/* 6577 */    MCD_OPC_Decode, 170, 4, 20, // Opcode: LD_DA_bo_r
/* 6581 */    MCD_OPC_FilterValue, 1, 98, 18, 0, // Skip to: 11292
/* 6586 */    MCD_OPC_Decode, 229, 7, 20, // Opcode: ST_DA_bo_r
/* 6590 */    MCD_OPC_FilterValue, 8, 21, 0, 0, // Skip to: 6616
/* 6595 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6598 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6607
/* 6603 */    MCD_OPC_Decode, 200, 4, 20, // Opcode: LD_Q_bo_r
/* 6607 */    MCD_OPC_FilterValue, 1, 72, 18, 0, // Skip to: 11292
/* 6612 */    MCD_OPC_Decode, 252, 7, 20, // Opcode: ST_Q_bo_r
/* 6616 */    MCD_OPC_FilterValue, 11, 11, 0, 0, // Skip to: 6632
/* 6621 */    MCD_OPC_CheckField, 7, 1, 1, 56, 18, 0, // Skip to: 11292
/* 6628 */    MCD_OPC_Decode, 208, 2, 20, // Opcode: CACHEI_W_bo_r
/* 6632 */    MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 6648
/* 6637 */    MCD_OPC_CheckField, 7, 1, 1, 40, 18, 0, // Skip to: 11292
/* 6644 */    MCD_OPC_Decode, 223, 2, 20, // Opcode: CACHE_W_bo_r
/* 6648 */    MCD_OPC_FilterValue, 13, 11, 0, 0, // Skip to: 6664
/* 6653 */    MCD_OPC_CheckField, 7, 1, 1, 24, 18, 0, // Skip to: 11292
/* 6660 */    MCD_OPC_Decode, 218, 2, 20, // Opcode: CACHE_WI_bo_r
/* 6664 */    MCD_OPC_FilterValue, 14, 11, 0, 0, // Skip to: 6680
/* 6669 */    MCD_OPC_CheckField, 7, 1, 1, 8, 18, 0, // Skip to: 11292
/* 6676 */    MCD_OPC_Decode, 213, 2, 20, // Opcode: CACHE_I_bo_r
/* 6680 */    MCD_OPC_FilterValue, 16, 21, 0, 0, // Skip to: 6706
/* 6685 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6688 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6697
/* 6693 */    MCD_OPC_Decode, 160, 4, 20, // Opcode: LD_B_bo_c
/* 6697 */    MCD_OPC_FilterValue, 1, 238, 17, 0, // Skip to: 11292
/* 6702 */    MCD_OPC_Decode, 215, 7, 20, // Opcode: ST_B_bo_c
/* 6706 */    MCD_OPC_FilterValue, 17, 11, 0, 0, // Skip to: 6722
/* 6711 */    MCD_OPC_CheckField, 7, 1, 0, 222, 17, 0, // Skip to: 11292
/* 6718 */    MCD_OPC_Decode, 149, 4, 20, // Opcode: LD_BU_bo_c
/* 6722 */    MCD_OPC_FilterValue, 18, 21, 0, 0, // Skip to: 6748
/* 6727 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6730 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6739
/* 6735 */    MCD_OPC_Decode, 186, 4, 20, // Opcode: LD_H_bo_c
/* 6739 */    MCD_OPC_FilterValue, 1, 196, 17, 0, // Skip to: 11292
/* 6744 */    MCD_OPC_Decode, 238, 7, 20, // Opcode: ST_H_bo_c
/* 6748 */    MCD_OPC_FilterValue, 19, 11, 0, 0, // Skip to: 6764
/* 6753 */    MCD_OPC_CheckField, 7, 1, 0, 180, 17, 0, // Skip to: 11292
/* 6760 */    MCD_OPC_Decode, 179, 4, 20, // Opcode: LD_HU_bo_c
/* 6764 */    MCD_OPC_FilterValue, 20, 21, 0, 0, // Skip to: 6790
/* 6769 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6772 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6781
/* 6777 */    MCD_OPC_Decode, 203, 4, 20, // Opcode: LD_W_bo_c
/* 6781 */    MCD_OPC_FilterValue, 1, 154, 17, 0, // Skip to: 11292
/* 6786 */    MCD_OPC_Decode, 128, 8, 20, // Opcode: ST_W_bo_c
/* 6790 */    MCD_OPC_FilterValue, 21, 21, 0, 0, // Skip to: 6816
/* 6795 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6798 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6807
/* 6803 */    MCD_OPC_Decode, 173, 4, 20, // Opcode: LD_D_bo_c
/* 6807 */    MCD_OPC_FilterValue, 1, 128, 17, 0, // Skip to: 11292
/* 6812 */    MCD_OPC_Decode, 232, 7, 20, // Opcode: ST_D_bo_c
/* 6816 */    MCD_OPC_FilterValue, 22, 21, 0, 0, // Skip to: 6842
/* 6821 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6824 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6833
/* 6829 */    MCD_OPC_Decode, 137, 4, 20, // Opcode: LD_A_bo_c
/* 6833 */    MCD_OPC_FilterValue, 1, 102, 17, 0, // Skip to: 11292
/* 6838 */    MCD_OPC_Decode, 203, 7, 20, // Opcode: ST_A_bo_c
/* 6842 */    MCD_OPC_FilterValue, 23, 21, 0, 0, // Skip to: 6868
/* 6847 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6850 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6859
/* 6855 */    MCD_OPC_Decode, 167, 4, 20, // Opcode: LD_DA_bo_c
/* 6859 */    MCD_OPC_FilterValue, 1, 76, 17, 0, // Skip to: 11292
/* 6864 */    MCD_OPC_Decode, 226, 7, 20, // Opcode: ST_DA_bo_c
/* 6868 */    MCD_OPC_FilterValue, 24, 21, 0, 0, // Skip to: 6894
/* 6873 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6876 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6885
/* 6881 */    MCD_OPC_Decode, 197, 4, 20, // Opcode: LD_Q_bo_c
/* 6885 */    MCD_OPC_FilterValue, 1, 50, 17, 0, // Skip to: 11292
/* 6890 */    MCD_OPC_Decode, 249, 7, 20, // Opcode: ST_Q_bo_c
/* 6894 */    MCD_OPC_FilterValue, 27, 11, 0, 0, // Skip to: 6910
/* 6899 */    MCD_OPC_CheckField, 7, 1, 1, 34, 17, 0, // Skip to: 11292
/* 6906 */    MCD_OPC_Decode, 205, 2, 20, // Opcode: CACHEI_W_bo_c
/* 6910 */    MCD_OPC_FilterValue, 28, 11, 0, 0, // Skip to: 6926
/* 6915 */    MCD_OPC_CheckField, 7, 1, 1, 18, 17, 0, // Skip to: 11292
/* 6922 */    MCD_OPC_Decode, 220, 2, 20, // Opcode: CACHE_W_bo_c
/* 6926 */    MCD_OPC_FilterValue, 29, 11, 0, 0, // Skip to: 6942
/* 6931 */    MCD_OPC_CheckField, 7, 1, 1, 2, 17, 0, // Skip to: 11292
/* 6938 */    MCD_OPC_Decode, 215, 2, 20, // Opcode: CACHE_WI_bo_c
/* 6942 */    MCD_OPC_FilterValue, 30, 249, 16, 0, // Skip to: 11292
/* 6947 */    MCD_OPC_CheckField, 7, 1, 1, 242, 16, 0, // Skip to: 11292
/* 6954 */    MCD_OPC_Decode, 210, 2, 20, // Opcode: CACHE_I_bo_c
/* 6958 */    MCD_OPC_FilterValue, 43, 161, 0, 0, // Skip to: 7124
/* 6963 */    MCD_OPC_ExtractField, 21, 3,  // Inst{23-21} ...
/* 6966 */    MCD_OPC_FilterValue, 0, 38, 0, 0, // Skip to: 7009
/* 6971 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6974 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 7000
/* 6979 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 6982 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6991
/* 6987 */    MCD_OPC_Decode, 228, 2, 33, // Opcode: CADD_rrr
/* 6991 */    MCD_OPC_FilterValue, 4, 200, 16, 0, // Skip to: 11292
/* 6996 */    MCD_OPC_Decode, 225, 2, 33, // Opcode: CADDN_rrr
/* 7000 */    MCD_OPC_FilterValue, 1, 191, 16, 0, // Skip to: 11292
/* 7005 */    MCD_OPC_Decode, 227, 2, 25, // Opcode: CADD_rcr
/* 7009 */    MCD_OPC_FilterValue, 1, 38, 0, 0, // Skip to: 7052
/* 7014 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7017 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 7043
/* 7022 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 7025 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7034
/* 7030 */    MCD_OPC_Decode, 255, 2, 33, // Opcode: CSUB_rrr
/* 7034 */    MCD_OPC_FilterValue, 4, 157, 16, 0, // Skip to: 11292
/* 7039 */    MCD_OPC_Decode, 254, 2, 33, // Opcode: CSUBN_rrr
/* 7043 */    MCD_OPC_FilterValue, 1, 148, 16, 0, // Skip to: 11292
/* 7048 */    MCD_OPC_Decode, 224, 2, 25, // Opcode: CADDN_rcr
/* 7052 */    MCD_OPC_FilterValue, 2, 35, 0, 0, // Skip to: 7092
/* 7057 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 7060 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7076
/* 7065 */    MCD_OPC_CheckField, 7, 1, 0, 124, 16, 0, // Skip to: 11292
/* 7072 */    MCD_OPC_Decode, 163, 7, 33, // Opcode: SEL_rrr
/* 7076 */    MCD_OPC_FilterValue, 4, 115, 16, 0, // Skip to: 11292
/* 7081 */    MCD_OPC_CheckField, 7, 1, 0, 108, 16, 0, // Skip to: 11292
/* 7088 */    MCD_OPC_Decode, 161, 7, 33, // Opcode: SELN_rrr
/* 7092 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 7108
/* 7097 */    MCD_OPC_CheckField, 7, 1, 1, 92, 16, 0, // Skip to: 11292
/* 7104 */    MCD_OPC_Decode, 162, 7, 25, // Opcode: SEL_rcr
/* 7108 */    MCD_OPC_FilterValue, 5, 83, 16, 0, // Skip to: 11292
/* 7113 */    MCD_OPC_CheckField, 7, 1, 1, 76, 16, 0, // Skip to: 11292
/* 7120 */    MCD_OPC_Decode, 160, 7, 25, // Opcode: SELN_rcr
/* 7124 */    MCD_OPC_FilterValue, 45, 102, 0, 0, // Skip to: 7231
/* 7129 */    MCD_OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 7132 */    MCD_OPC_FilterValue, 0, 38, 0, 0, // Skip to: 7175
/* 7137 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7140 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 7166
/* 7145 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 7148 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7157
/* 7153 */    MCD_OPC_Decode, 231, 2, 15, // Opcode: CALLI_rr
/* 7157 */    MCD_OPC_FilterValue, 4, 34, 16, 0, // Skip to: 11292
/* 7162 */    MCD_OPC_Decode, 168, 3, 15, // Opcode: FCALLA_i
/* 7166 */    MCD_OPC_FilterValue, 1, 25, 16, 0, // Skip to: 11292
/* 7171 */    MCD_OPC_Decode, 194, 2, 22, // Opcode: BISR_rc
/* 7175 */    MCD_OPC_FilterValue, 1, 35, 0, 0, // Skip to: 7215
/* 7180 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 7183 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7199
/* 7188 */    MCD_OPC_CheckField, 7, 1, 0, 1, 16, 0, // Skip to: 11292
/* 7195 */    MCD_OPC_Decode, 221, 3, 15, // Opcode: JLI_rr
/* 7199 */    MCD_OPC_FilterValue, 4, 248, 15, 0, // Skip to: 11292
/* 7204 */    MCD_OPC_CheckField, 7, 1, 0, 241, 15, 0, // Skip to: 11292
/* 7211 */    MCD_OPC_Decode, 217, 3, 15, // Opcode: JI_rr
/* 7215 */    MCD_OPC_FilterValue, 4, 232, 15, 0, // Skip to: 11292
/* 7220 */    MCD_OPC_CheckField, 7, 1, 1, 225, 15, 0, // Skip to: 11292
/* 7227 */    MCD_OPC_Decode, 165, 8, 22, // Opcode: SYSCALL_rc
/* 7231 */    MCD_OPC_FilterValue, 47, 18, 0, 0, // Skip to: 7254
/* 7236 */    MCD_OPC_CheckField, 12, 20, 0, 209, 15, 0, // Skip to: 11292
/* 7243 */    MCD_OPC_CheckField, 7, 1, 0, 202, 15, 0, // Skip to: 11292
/* 7250 */    MCD_OPC_Decode, 147, 7, 14, // Opcode: RSTV_sys
/* 7254 */    MCD_OPC_FilterValue, 51, 69, 1, 0, // Skip to: 7584
/* 7259 */    MCD_OPC_ExtractField, 21, 3,  // Inst{23-21} ...
/* 7262 */    MCD_OPC_FilterValue, 1, 84, 0, 0, // Skip to: 7351
/* 7267 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7270 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7279
/* 7275 */    MCD_OPC_Decode, 187, 6, 25, // Opcode: MSUB_rcr
/* 7279 */    MCD_OPC_FilterValue, 1, 168, 15, 0, // Skip to: 11292
/* 7284 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 7287 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 7303
/* 7292 */    MCD_OPC_CheckField, 24, 4, 0, 153, 15, 0, // Skip to: 11292
/* 7299 */    MCD_OPC_Decode, 198, 6, 24, // Opcode: MULR_H_rr1_UL2e
/* 7303 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 7319
/* 7308 */    MCD_OPC_CheckField, 24, 4, 0, 137, 15, 0, // Skip to: 11292
/* 7315 */    MCD_OPC_Decode, 197, 6, 24, // Opcode: MULR_H_rr1_LU2e
/* 7319 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 7335
/* 7324 */    MCD_OPC_CheckField, 24, 4, 0, 121, 15, 0, // Skip to: 11292
/* 7331 */    MCD_OPC_Decode, 196, 6, 24, // Opcode: MULR_H_rr1_LL2e
/* 7335 */    MCD_OPC_FilterValue, 7, 112, 15, 0, // Skip to: 11292
/* 7340 */    MCD_OPC_CheckField, 24, 4, 0, 105, 15, 0, // Skip to: 11292
/* 7347 */    MCD_OPC_Decode, 199, 6, 24, // Opcode: MULR_H_rr1_UU2e
/* 7351 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 7367
/* 7356 */    MCD_OPC_CheckField, 7, 1, 0, 89, 15, 0, // Skip to: 11292
/* 7363 */    MCD_OPC_Decode, 185, 6, 25, // Opcode: MSUB_U_rcr
/* 7367 */    MCD_OPC_FilterValue, 3, 148, 0, 0, // Skip to: 7520
/* 7372 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7375 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7384
/* 7380 */    MCD_OPC_Decode, 188, 6, 25, // Opcode: MSUB_rcr_e
/* 7384 */    MCD_OPC_FilterValue, 1, 63, 15, 0, // Skip to: 11292
/* 7389 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 7392 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7408
/* 7397 */    MCD_OPC_CheckField, 24, 4, 0, 48, 15, 0, // Skip to: 11292
/* 7404 */    MCD_OPC_Decode, 209, 6, 24, // Opcode: MUL_H_rr1_UL2e
/* 7408 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 7424
/* 7413 */    MCD_OPC_CheckField, 24, 4, 0, 32, 15, 0, // Skip to: 11292
/* 7420 */    MCD_OPC_Decode, 208, 6, 24, // Opcode: MUL_H_rr1_LU2e
/* 7424 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 7440
/* 7429 */    MCD_OPC_CheckField, 24, 4, 0, 16, 15, 0, // Skip to: 11292
/* 7436 */    MCD_OPC_Decode, 207, 6, 24, // Opcode: MUL_H_rr1_LL2e
/* 7440 */    MCD_OPC_FilterValue, 3, 11, 0, 0, // Skip to: 7456
/* 7445 */    MCD_OPC_CheckField, 24, 4, 0, 0, 15, 0, // Skip to: 11292
/* 7452 */    MCD_OPC_Decode, 210, 6, 24, // Opcode: MUL_H_rr1_UU2e
/* 7456 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 7472
/* 7461 */    MCD_OPC_CheckField, 24, 4, 0, 240, 14, 0, // Skip to: 11292
/* 7468 */    MCD_OPC_Decode, 194, 6, 24, // Opcode: MULM_H_rr1_UL2e
/* 7472 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 7488
/* 7477 */    MCD_OPC_CheckField, 24, 4, 0, 224, 14, 0, // Skip to: 11292
/* 7484 */    MCD_OPC_Decode, 193, 6, 24, // Opcode: MULM_H_rr1_LU2e
/* 7488 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 7504
/* 7493 */    MCD_OPC_CheckField, 24, 4, 0, 208, 14, 0, // Skip to: 11292
/* 7500 */    MCD_OPC_Decode, 192, 6, 24, // Opcode: MULM_H_rr1_LL2e
/* 7504 */    MCD_OPC_FilterValue, 7, 199, 14, 0, // Skip to: 11292
/* 7509 */    MCD_OPC_CheckField, 24, 4, 0, 192, 14, 0, // Skip to: 11292
/* 7516 */    MCD_OPC_Decode, 195, 6, 24, // Opcode: MULM_H_rr1_UU2e
/* 7520 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 7536
/* 7525 */    MCD_OPC_CheckField, 7, 1, 0, 176, 14, 0, // Skip to: 11292
/* 7532 */    MCD_OPC_Decode, 162, 6, 25, // Opcode: MSUBS_U_rcr
/* 7536 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 7552
/* 7541 */    MCD_OPC_CheckField, 7, 1, 0, 160, 14, 0, // Skip to: 11292
/* 7548 */    MCD_OPC_Decode, 166, 6, 25, // Opcode: MSUBS_rcr
/* 7552 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 7568
/* 7557 */    MCD_OPC_CheckField, 7, 1, 0, 144, 14, 0, // Skip to: 11292
/* 7564 */    MCD_OPC_Decode, 163, 6, 25, // Opcode: MSUBS_U_rcr_e
/* 7568 */    MCD_OPC_FilterValue, 7, 135, 14, 0, // Skip to: 11292
/* 7573 */    MCD_OPC_CheckField, 7, 1, 0, 128, 14, 0, // Skip to: 11292
/* 7580 */    MCD_OPC_Decode, 167, 6, 25, // Opcode: MSUBS_rcr_e
/* 7584 */    MCD_OPC_FilterValue, 53, 11, 0, 0, // Skip to: 7600
/* 7589 */    MCD_OPC_CheckField, 7, 1, 1, 112, 14, 0, // Skip to: 11292
/* 7596 */    MCD_OPC_Decode, 207, 7, 29, // Opcode: ST_A_bol
/* 7600 */    MCD_OPC_FilterValue, 55, 87, 0, 0, // Skip to: 7692
/* 7605 */    MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 7608 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 7634
/* 7613 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7616 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7625
/* 7621 */    MCD_OPC_Decode, 192, 3, 34, // Opcode: INSERT_rrpw
/* 7625 */    MCD_OPC_FilterValue, 1, 78, 14, 0, // Skip to: 11292
/* 7630 */    MCD_OPC_Decode, 189, 3, 35, // Opcode: INSERT_rcpw
/* 7634 */    MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 7660
/* 7639 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7642 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7651
/* 7647 */    MCD_OPC_Decode, 187, 3, 34, // Opcode: IMASK_rrpw
/* 7651 */    MCD_OPC_FilterValue, 1, 52, 14, 0, // Skip to: 11292
/* 7656 */    MCD_OPC_Decode, 185, 3, 35, // Opcode: IMASK_rcpw
/* 7660 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 7676
/* 7665 */    MCD_OPC_CheckField, 7, 1, 0, 36, 14, 0, // Skip to: 11292
/* 7672 */    MCD_OPC_Decode, 164, 3, 34, // Opcode: EXTR_rrpw
/* 7676 */    MCD_OPC_FilterValue, 3, 27, 14, 0, // Skip to: 11292
/* 7681 */    MCD_OPC_CheckField, 7, 1, 0, 20, 14, 0, // Skip to: 11292
/* 7688 */    MCD_OPC_Decode, 161, 3, 34, // Opcode: EXTR_U_rrpw
/* 7692 */    MCD_OPC_FilterValue, 57, 21, 0, 0, // Skip to: 7718
/* 7697 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7700 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7709
/* 7705 */    MCD_OPC_Decode, 153, 4, 29, // Opcode: LD_BU_bol
/* 7709 */    MCD_OPC_FilterValue, 1, 250, 13, 0, // Skip to: 11292
/* 7714 */    MCD_OPC_Decode, 183, 4, 29, // Opcode: LD_HU_bol
/* 7718 */    MCD_OPC_FilterValue, 59, 21, 0, 0, // Skip to: 7744
/* 7723 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7726 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7735
/* 7731 */    MCD_OPC_Decode, 221, 5, 23, // Opcode: MOV_rlcDc
/* 7735 */    MCD_OPC_FilterValue, 1, 224, 13, 0, // Skip to: 11292
/* 7740 */    MCD_OPC_Decode, 220, 5, 23, // Opcode: MOV_U_rlc
/* 7744 */    MCD_OPC_FilterValue, 61, 35, 0, 0, // Skip to: 7784
/* 7749 */    MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 7752 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7768
/* 7757 */    MCD_OPC_CheckField, 7, 1, 1, 200, 13, 0, // Skip to: 11292
/* 7764 */    MCD_OPC_Decode, 245, 3, 31, // Opcode: JZ_A_brr
/* 7768 */    MCD_OPC_FilterValue, 1, 191, 13, 0, // Skip to: 11292
/* 7773 */    MCD_OPC_CheckField, 7, 1, 1, 184, 13, 0, // Skip to: 11292
/* 7780 */    MCD_OPC_Decode, 239, 3, 31, // Opcode: JNZ_A_brr
/* 7784 */    MCD_OPC_FilterValue, 63, 55, 0, 0, // Skip to: 7844
/* 7789 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7792 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 7818
/* 7797 */    MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 7800 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7809
/* 7805 */    MCD_OPC_Decode, 226, 3, 31, // Opcode: JLT_brr
/* 7809 */    MCD_OPC_FilterValue, 1, 150, 13, 0, // Skip to: 11292
/* 7814 */    MCD_OPC_Decode, 224, 3, 31, // Opcode: JLT_U_brr
/* 7818 */    MCD_OPC_FilterValue, 1, 141, 13, 0, // Skip to: 11292
/* 7823 */    MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 7826 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7835
/* 7831 */    MCD_OPC_Decode, 225, 3, 32, // Opcode: JLT_brc
/* 7835 */    MCD_OPC_FilterValue, 1, 124, 13, 0, // Skip to: 11292
/* 7840 */    MCD_OPC_Decode, 223, 3, 32, // Opcode: JLT_U_brc
/* 7844 */    MCD_OPC_FilterValue, 67, 219, 2, 0, // Skip to: 8580
/* 7849 */    MCD_OPC_ExtractField, 18, 6,  // Inst{23-18} ...
/* 7852 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7868
/* 7857 */    MCD_OPC_CheckField, 7, 1, 0, 100, 13, 0, // Skip to: 11292
/* 7864 */    MCD_OPC_Decode, 181, 5, 17, // Opcode: MADD_Q_rrr1_U
/* 7868 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 7884
/* 7873 */    MCD_OPC_CheckField, 7, 1, 0, 84, 13, 0, // Skip to: 11292
/* 7880 */    MCD_OPC_Decode, 179, 5, 17, // Opcode: MADD_Q_rrr1_L
/* 7884 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 7900
/* 7889 */    MCD_OPC_CheckField, 7, 1, 0, 68, 13, 0, // Skip to: 11292
/* 7896 */    MCD_OPC_Decode, 178, 5, 17, // Opcode: MADD_Q_rrr1
/* 7900 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 7916
/* 7905 */    MCD_OPC_CheckField, 7, 1, 0, 52, 13, 0, // Skip to: 11292
/* 7912 */    MCD_OPC_Decode, 182, 5, 17, // Opcode: MADD_Q_rrr1_U_U
/* 7916 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 7932
/* 7921 */    MCD_OPC_CheckField, 7, 1, 0, 36, 13, 0, // Skip to: 11292
/* 7928 */    MCD_OPC_Decode, 180, 5, 17, // Opcode: MADD_Q_rrr1_L_L
/* 7932 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 7948
/* 7937 */    MCD_OPC_CheckField, 7, 1, 0, 20, 13, 0, // Skip to: 11292
/* 7944 */    MCD_OPC_Decode, 254, 4, 17, // Opcode: MADDR_Q_rrr1_U_U
/* 7948 */    MCD_OPC_FilterValue, 7, 11, 0, 0, // Skip to: 7964
/* 7953 */    MCD_OPC_CheckField, 7, 1, 0, 4, 13, 0, // Skip to: 11292
/* 7960 */    MCD_OPC_Decode, 253, 4, 17, // Opcode: MADDR_Q_rrr1_L_L
/* 7964 */    MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 7980
/* 7969 */    MCD_OPC_CheckField, 7, 1, 1, 244, 12, 0, // Skip to: 11292
/* 7976 */    MCD_OPC_Decode, 141, 5, 17, // Opcode: MADDSUR_H_rrr1_UL
/* 7980 */    MCD_OPC_FilterValue, 13, 11, 0, 0, // Skip to: 7996
/* 7985 */    MCD_OPC_CheckField, 7, 1, 1, 228, 12, 0, // Skip to: 11292
/* 7992 */    MCD_OPC_Decode, 140, 5, 17, // Opcode: MADDSUR_H_rrr1_LU
/* 7996 */    MCD_OPC_FilterValue, 14, 11, 0, 0, // Skip to: 8012
/* 8001 */    MCD_OPC_CheckField, 7, 1, 1, 212, 12, 0, // Skip to: 11292
/* 8008 */    MCD_OPC_Decode, 139, 5, 17, // Opcode: MADDSUR_H_rrr1_LL
/* 8012 */    MCD_OPC_FilterValue, 15, 11, 0, 0, // Skip to: 8028
/* 8017 */    MCD_OPC_CheckField, 7, 1, 1, 196, 12, 0, // Skip to: 11292
/* 8024 */    MCD_OPC_Decode, 142, 5, 17, // Opcode: MADDSUR_H_rrr1_UU
/* 8028 */    MCD_OPC_FilterValue, 24, 21, 0, 0, // Skip to: 8054
/* 8033 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8036 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8045
/* 8041 */    MCD_OPC_Decode, 186, 5, 17, // Opcode: MADD_Q_rrr1_e_U
/* 8045 */    MCD_OPC_FilterValue, 1, 170, 12, 0, // Skip to: 11292
/* 8050 */    MCD_OPC_Decode, 149, 5, 17, // Opcode: MADDSU_H_rrr1_UL
/* 8054 */    MCD_OPC_FilterValue, 25, 21, 0, 0, // Skip to: 8080
/* 8059 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8062 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8071
/* 8067 */    MCD_OPC_Decode, 184, 5, 17, // Opcode: MADD_Q_rrr1_e_L
/* 8071 */    MCD_OPC_FilterValue, 1, 144, 12, 0, // Skip to: 11292
/* 8076 */    MCD_OPC_Decode, 148, 5, 17, // Opcode: MADDSU_H_rrr1_LU
/* 8080 */    MCD_OPC_FilterValue, 26, 11, 0, 0, // Skip to: 8096
/* 8085 */    MCD_OPC_CheckField, 7, 1, 1, 128, 12, 0, // Skip to: 11292
/* 8092 */    MCD_OPC_Decode, 147, 5, 17, // Opcode: MADDSU_H_rrr1_LL
/* 8096 */    MCD_OPC_FilterValue, 27, 21, 0, 0, // Skip to: 8122
/* 8101 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8104 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8113
/* 8109 */    MCD_OPC_Decode, 183, 5, 17, // Opcode: MADD_Q_rrr1_e
/* 8113 */    MCD_OPC_FilterValue, 1, 102, 12, 0, // Skip to: 11292
/* 8118 */    MCD_OPC_Decode, 150, 5, 17, // Opcode: MADDSU_H_rrr1_UU
/* 8122 */    MCD_OPC_FilterValue, 28, 21, 0, 0, // Skip to: 8148
/* 8127 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8130 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8139
/* 8135 */    MCD_OPC_Decode, 187, 5, 17, // Opcode: MADD_Q_rrr1_e_U_U
/* 8139 */    MCD_OPC_FilterValue, 1, 76, 12, 0, // Skip to: 11292
/* 8144 */    MCD_OPC_Decode, 133, 5, 17, // Opcode: MADDSUM_H_rrr1_UL
/* 8148 */    MCD_OPC_FilterValue, 29, 21, 0, 0, // Skip to: 8174
/* 8153 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8156 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8165
/* 8161 */    MCD_OPC_Decode, 185, 5, 17, // Opcode: MADD_Q_rrr1_e_L_L
/* 8165 */    MCD_OPC_FilterValue, 1, 50, 12, 0, // Skip to: 11292
/* 8170 */    MCD_OPC_Decode, 132, 5, 17, // Opcode: MADDSUM_H_rrr1_LU
/* 8174 */    MCD_OPC_FilterValue, 30, 21, 0, 0, // Skip to: 8200
/* 8179 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8182 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8191
/* 8187 */    MCD_OPC_Decode, 248, 4, 17, // Opcode: MADDR_H_rrr1_DcEdDaDbUL
/* 8191 */    MCD_OPC_FilterValue, 1, 24, 12, 0, // Skip to: 11292
/* 8196 */    MCD_OPC_Decode, 131, 5, 17, // Opcode: MADDSUM_H_rrr1_LL
/* 8200 */    MCD_OPC_FilterValue, 31, 11, 0, 0, // Skip to: 8216
/* 8205 */    MCD_OPC_CheckField, 7, 1, 1, 8, 12, 0, // Skip to: 11292
/* 8212 */    MCD_OPC_Decode, 134, 5, 17, // Opcode: MADDSUM_H_rrr1_UU
/* 8216 */    MCD_OPC_FilterValue, 32, 11, 0, 0, // Skip to: 8232
/* 8221 */    MCD_OPC_CheckField, 7, 1, 0, 248, 11, 0, // Skip to: 11292
/* 8228 */    MCD_OPC_Decode, 158, 5, 17, // Opcode: MADDS_Q_rrr1_U
/* 8232 */    MCD_OPC_FilterValue, 33, 11, 0, 0, // Skip to: 8248
/* 8237 */    MCD_OPC_CheckField, 7, 1, 0, 232, 11, 0, // Skip to: 11292
/* 8244 */    MCD_OPC_Decode, 156, 5, 17, // Opcode: MADDS_Q_rrr1_L
/* 8248 */    MCD_OPC_FilterValue, 34, 11, 0, 0, // Skip to: 8264
/* 8253 */    MCD_OPC_CheckField, 7, 1, 0, 216, 11, 0, // Skip to: 11292
/* 8260 */    MCD_OPC_Decode, 155, 5, 17, // Opcode: MADDS_Q_rrr1
/* 8264 */    MCD_OPC_FilterValue, 36, 11, 0, 0, // Skip to: 8280
/* 8269 */    MCD_OPC_CheckField, 7, 1, 0, 200, 11, 0, // Skip to: 11292
/* 8276 */    MCD_OPC_Decode, 159, 5, 17, // Opcode: MADDS_Q_rrr1_U_U
/* 8280 */    MCD_OPC_FilterValue, 37, 11, 0, 0, // Skip to: 8296
/* 8285 */    MCD_OPC_CheckField, 7, 1, 0, 184, 11, 0, // Skip to: 11292
/* 8292 */    MCD_OPC_Decode, 157, 5, 17, // Opcode: MADDS_Q_rrr1_L_L
/* 8296 */    MCD_OPC_FilterValue, 38, 11, 0, 0, // Skip to: 8312
/* 8301 */    MCD_OPC_CheckField, 7, 1, 0, 168, 11, 0, // Skip to: 11292
/* 8308 */    MCD_OPC_Decode, 247, 4, 17, // Opcode: MADDRS_Q_rrr1_U_U
/* 8312 */    MCD_OPC_FilterValue, 39, 11, 0, 0, // Skip to: 8328
/* 8317 */    MCD_OPC_CheckField, 7, 1, 0, 152, 11, 0, // Skip to: 11292
/* 8324 */    MCD_OPC_Decode, 246, 4, 17, // Opcode: MADDRS_Q_rrr1_L_L
/* 8328 */    MCD_OPC_FilterValue, 44, 11, 0, 0, // Skip to: 8344
/* 8333 */    MCD_OPC_CheckField, 7, 1, 1, 136, 11, 0, // Skip to: 11292
/* 8340 */    MCD_OPC_Decode, 137, 5, 17, // Opcode: MADDSURS_H_rrr1_UL
/* 8344 */    MCD_OPC_FilterValue, 45, 11, 0, 0, // Skip to: 8360
/* 8349 */    MCD_OPC_CheckField, 7, 1, 1, 120, 11, 0, // Skip to: 11292
/* 8356 */    MCD_OPC_Decode, 136, 5, 17, // Opcode: MADDSURS_H_rrr1_LU
/* 8360 */    MCD_OPC_FilterValue, 46, 11, 0, 0, // Skip to: 8376
/* 8365 */    MCD_OPC_CheckField, 7, 1, 1, 104, 11, 0, // Skip to: 11292
/* 8372 */    MCD_OPC_Decode, 135, 5, 17, // Opcode: MADDSURS_H_rrr1_LL
/* 8376 */    MCD_OPC_FilterValue, 47, 11, 0, 0, // Skip to: 8392
/* 8381 */    MCD_OPC_CheckField, 7, 1, 1, 88, 11, 0, // Skip to: 11292
/* 8388 */    MCD_OPC_Decode, 138, 5, 17, // Opcode: MADDSURS_H_rrr1_UU
/* 8392 */    MCD_OPC_FilterValue, 56, 21, 0, 0, // Skip to: 8418
/* 8397 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8400 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8409
/* 8405 */    MCD_OPC_Decode, 163, 5, 17, // Opcode: MADDS_Q_rrr1_e_U
/* 8409 */    MCD_OPC_FilterValue, 1, 62, 11, 0, // Skip to: 11292
/* 8414 */    MCD_OPC_Decode, 145, 5, 17, // Opcode: MADDSUS_H_rrr1_UL
/* 8418 */    MCD_OPC_FilterValue, 57, 21, 0, 0, // Skip to: 8444
/* 8423 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8426 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8435
/* 8431 */    MCD_OPC_Decode, 161, 5, 17, // Opcode: MADDS_Q_rrr1_e_L
/* 8435 */    MCD_OPC_FilterValue, 1, 36, 11, 0, // Skip to: 11292
/* 8440 */    MCD_OPC_Decode, 144, 5, 17, // Opcode: MADDSUS_H_rrr1_LU
/* 8444 */    MCD_OPC_FilterValue, 58, 11, 0, 0, // Skip to: 8460
/* 8449 */    MCD_OPC_CheckField, 7, 1, 1, 20, 11, 0, // Skip to: 11292
/* 8456 */    MCD_OPC_Decode, 143, 5, 17, // Opcode: MADDSUS_H_rrr1_LL
/* 8460 */    MCD_OPC_FilterValue, 59, 21, 0, 0, // Skip to: 8486
/* 8465 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8468 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8477
/* 8473 */    MCD_OPC_Decode, 160, 5, 17, // Opcode: MADDS_Q_rrr1_e
/* 8477 */    MCD_OPC_FilterValue, 1, 250, 10, 0, // Skip to: 11292
/* 8482 */    MCD_OPC_Decode, 146, 5, 17, // Opcode: MADDSUS_H_rrr1_UU
/* 8486 */    MCD_OPC_FilterValue, 60, 21, 0, 0, // Skip to: 8512
/* 8491 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8494 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8503
/* 8499 */    MCD_OPC_Decode, 164, 5, 17, // Opcode: MADDS_Q_rrr1_e_U_U
/* 8503 */    MCD_OPC_FilterValue, 1, 224, 10, 0, // Skip to: 11292
/* 8508 */    MCD_OPC_Decode, 129, 5, 17, // Opcode: MADDSUMS_H_rrr1_UL
/* 8512 */    MCD_OPC_FilterValue, 61, 21, 0, 0, // Skip to: 8538
/* 8517 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8520 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8529
/* 8525 */    MCD_OPC_Decode, 162, 5, 17, // Opcode: MADDS_Q_rrr1_e_L_L
/* 8529 */    MCD_OPC_FilterValue, 1, 198, 10, 0, // Skip to: 11292
/* 8534 */    MCD_OPC_Decode, 128, 5, 17, // Opcode: MADDSUMS_H_rrr1_LU
/* 8538 */    MCD_OPC_FilterValue, 62, 21, 0, 0, // Skip to: 8564
/* 8543 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8546 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8555
/* 8551 */    MCD_OPC_Decode, 241, 4, 17, // Opcode: MADDRS_H_rrr1_DcEdDaDbUL
/* 8555 */    MCD_OPC_FilterValue, 1, 172, 10, 0, // Skip to: 11292
/* 8560 */    MCD_OPC_Decode, 255, 4, 17, // Opcode: MADDSUMS_H_rrr1_LL
/* 8564 */    MCD_OPC_FilterValue, 63, 163, 10, 0, // Skip to: 11292
/* 8569 */    MCD_OPC_CheckField, 7, 1, 1, 156, 10, 0, // Skip to: 11292
/* 8576 */    MCD_OPC_Decode, 130, 5, 17, // Opcode: MADDSUMS_H_rrr1_UU
/* 8580 */    MCD_OPC_FilterValue, 69, 45, 0, 0, // Skip to: 8630
/* 8585 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8588 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 8604
/* 8593 */    MCD_OPC_CheckField, 26, 2, 0, 132, 10, 0, // Skip to: 11292
/* 8600 */    MCD_OPC_Decode, 195, 4, 18, // Opcode: LD_Q_abs
/* 8604 */    MCD_OPC_FilterValue, 1, 123, 10, 0, // Skip to: 11292
/* 8609 */    MCD_OPC_ExtractField, 26, 2,  // Inst{27-26} ...
/* 8612 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8621
/* 8617 */    MCD_OPC_Decode, 213, 4, 18, // Opcode: LEA_abs
/* 8621 */    MCD_OPC_FilterValue, 1, 106, 10, 0, // Skip to: 11292
/* 8626 */    MCD_OPC_Decode, 216, 4, 18, // Opcode: LHA_abs
/* 8630 */    MCD_OPC_FilterValue, 71, 107, 0, 0, // Skip to: 8742
/* 8635 */    MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 8638 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 8664
/* 8643 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8646 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8655
/* 8651 */    MCD_OPC_Decode, 174, 2, 19, // Opcode: AND_AND_T
/* 8655 */    MCD_OPC_FilterValue, 1, 72, 10, 0, // Skip to: 11292
/* 8660 */    MCD_OPC_Decode, 243, 6, 19, // Opcode: OR_AND_T
/* 8664 */    MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 8690
/* 8669 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8672 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8681
/* 8677 */    MCD_OPC_Decode, 188, 2, 19, // Opcode: AND_OR_T
/* 8681 */    MCD_OPC_FilterValue, 1, 46, 10, 0, // Skip to: 11292
/* 8686 */    MCD_OPC_Decode, 129, 7, 19, // Opcode: OR_OR_T
/* 8690 */    MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 8716
/* 8695 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8698 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8707
/* 8703 */    MCD_OPC_Decode, 187, 2, 19, // Opcode: AND_NOR_T
/* 8707 */    MCD_OPC_FilterValue, 1, 20, 10, 0, // Skip to: 11292
/* 8712 */    MCD_OPC_Decode, 128, 7, 19, // Opcode: OR_NOR_T
/* 8716 */    MCD_OPC_FilterValue, 3, 11, 10, 0, // Skip to: 11292
/* 8721 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8724 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8733
/* 8729 */    MCD_OPC_Decode, 173, 2, 19, // Opcode: AND_ANDN_T
/* 8733 */    MCD_OPC_FilterValue, 1, 250, 9, 0, // Skip to: 11292
/* 8738 */    MCD_OPC_Decode, 242, 6, 19, // Opcode: OR_ANDN_T
/* 8742 */    MCD_OPC_FilterValue, 73, 173, 0, 0, // Skip to: 8920
/* 8747 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8750 */    MCD_OPC_FilterValue, 0, 156, 0, 0, // Skip to: 8911
/* 8755 */    MCD_OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 8758 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8767
/* 8763 */    MCD_OPC_Decode, 162, 8, 20, // Opcode: SWAP_W_bo_pos
/* 8767 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 8776
/* 8772 */    MCD_OPC_Decode, 130, 4, 20, // Opcode: LDMST_bo_pos
/* 8776 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 8785
/* 8781 */    MCD_OPC_Decode, 156, 8, 20, // Opcode: SWAPMSK_W_bo_pos
/* 8785 */    MCD_OPC_FilterValue, 3, 4, 0, 0, // Skip to: 8794
/* 8790 */    MCD_OPC_Decode, 246, 2, 20, // Opcode: CMPSWAP_W_bo_pos
/* 8794 */    MCD_OPC_FilterValue, 16, 4, 0, 0, // Skip to: 8803
/* 8799 */    MCD_OPC_Decode, 163, 8, 20, // Opcode: SWAP_W_bo_pre
/* 8803 */    MCD_OPC_FilterValue, 17, 4, 0, 0, // Skip to: 8812
/* 8808 */    MCD_OPC_Decode, 131, 4, 20, // Opcode: LDMST_bo_pre
/* 8812 */    MCD_OPC_FilterValue, 18, 4, 0, 0, // Skip to: 8821
/* 8817 */    MCD_OPC_Decode, 157, 8, 20, // Opcode: SWAPMSK_W_bo_pre
/* 8821 */    MCD_OPC_FilterValue, 19, 4, 0, 0, // Skip to: 8830
/* 8826 */    MCD_OPC_Decode, 247, 2, 20, // Opcode: CMPSWAP_W_bo_pre
/* 8830 */    MCD_OPC_FilterValue, 32, 4, 0, 0, // Skip to: 8839
/* 8835 */    MCD_OPC_Decode, 160, 8, 20, // Opcode: SWAP_W_bo_bso
/* 8839 */    MCD_OPC_FilterValue, 33, 4, 0, 0, // Skip to: 8848
/* 8844 */    MCD_OPC_Decode, 128, 4, 20, // Opcode: LDMST_bo_bso
/* 8848 */    MCD_OPC_FilterValue, 34, 4, 0, 0, // Skip to: 8857
/* 8853 */    MCD_OPC_Decode, 154, 8, 20, // Opcode: SWAPMSK_W_bo_bso
/* 8857 */    MCD_OPC_FilterValue, 35, 4, 0, 0, // Skip to: 8866
/* 8862 */    MCD_OPC_Decode, 244, 2, 20, // Opcode: CMPSWAP_W_bo_bso
/* 8866 */    MCD_OPC_FilterValue, 36, 4, 0, 0, // Skip to: 8875
/* 8871 */    MCD_OPC_Decode, 254, 3, 20, // Opcode: LDLCX_bo_bso
/* 8875 */    MCD_OPC_FilterValue, 37, 4, 0, 0, // Skip to: 8884
/* 8880 */    MCD_OPC_Decode, 134, 4, 20, // Opcode: LDUCX_bo_bso
/* 8884 */    MCD_OPC_FilterValue, 38, 4, 0, 0, // Skip to: 8893
/* 8889 */    MCD_OPC_Decode, 198, 7, 20, // Opcode: STLCX_bo_bso
/* 8893 */    MCD_OPC_FilterValue, 39, 4, 0, 0, // Skip to: 8902
/* 8898 */    MCD_OPC_Decode, 200, 7, 20, // Opcode: STUCX_bo_bso
/* 8902 */    MCD_OPC_FilterValue, 40, 81, 9, 0, // Skip to: 11292
/* 8907 */    MCD_OPC_Decode, 214, 4, 20, // Opcode: LEA_bo_bso
/* 8911 */    MCD_OPC_FilterValue, 1, 72, 9, 0, // Skip to: 11292
/* 8916 */    MCD_OPC_Decode, 190, 4, 29, // Opcode: LD_H_bol
/* 8920 */    MCD_OPC_FilterValue, 75, 12, 2, 0, // Skip to: 9449
/* 8925 */    MCD_OPC_ExtractField, 18, 10,  // Inst{27-18} ...
/* 8928 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 8944
/* 8933 */    MCD_OPC_CheckField, 7, 1, 0, 48, 9, 0, // Skip to: 11292
/* 8940 */    MCD_OPC_Decode, 249, 2, 15, // Opcode: CMP_F_rr
/* 8944 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 8960
/* 8949 */    MCD_OPC_CheckField, 7, 1, 0, 32, 9, 0, // Skip to: 11292
/* 8956 */    MCD_OPC_Decode, 196, 2, 15, // Opcode: BMAERGE_rr
/* 8960 */    MCD_OPC_FilterValue, 8, 11, 0, 0, // Skip to: 8976
/* 8965 */    MCD_OPC_CheckField, 7, 1, 0, 16, 9, 0, // Skip to: 11292
/* 8972 */    MCD_OPC_Decode, 136, 7, 15, // Opcode: PARITY_rr
/* 8976 */    MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 8992
/* 8981 */    MCD_OPC_CheckField, 7, 1, 0, 0, 9, 0, // Skip to: 11292
/* 8988 */    MCD_OPC_Decode, 250, 2, 15, // Opcode: CRC32B_W_rr
/* 8992 */    MCD_OPC_FilterValue, 16, 11, 0, 0, // Skip to: 9008
/* 8997 */    MCD_OPC_CheckField, 7, 1, 0, 240, 8, 0, // Skip to: 11292
/* 9004 */    MCD_OPC_Decode, 206, 6, 15, // Opcode: MUL_F_rrr
/* 9008 */    MCD_OPC_FilterValue, 20, 11, 0, 0, // Skip to: 9024
/* 9013 */    MCD_OPC_CheckField, 7, 1, 0, 224, 8, 0, // Skip to: 11292
/* 9020 */    MCD_OPC_Decode, 134, 3, 15, // Opcode: DIV_F_rr
/* 9024 */    MCD_OPC_FilterValue, 24, 11, 0, 0, // Skip to: 9040
/* 9029 */    MCD_OPC_CheckField, 7, 1, 0, 208, 8, 0, // Skip to: 11292
/* 9036 */    MCD_OPC_Decode, 252, 2, 15, // Opcode: CRC32_B_rr
/* 9040 */    MCD_OPC_FilterValue, 28, 11, 0, 0, // Skip to: 9056
/* 9045 */    MCD_OPC_CheckField, 7, 1, 0, 192, 8, 0, // Skip to: 11292
/* 9052 */    MCD_OPC_Decode, 251, 2, 15, // Opcode: CRC32L_W_rr
/* 9056 */    MCD_OPC_FilterValue, 32, 11, 0, 0, // Skip to: 9072
/* 9061 */    MCD_OPC_CheckField, 7, 1, 0, 176, 8, 0, // Skip to: 11292
/* 9068 */    MCD_OPC_Decode, 168, 8, 15, // Opcode: UNPACK_rr
/* 9072 */    MCD_OPC_FilterValue, 36, 11, 0, 0, // Skip to: 9088
/* 9077 */    MCD_OPC_CheckField, 7, 1, 0, 160, 8, 0, // Skip to: 11292
/* 9084 */    MCD_OPC_Decode, 197, 2, 15, // Opcode: BSPLIT_rr
/* 9088 */    MCD_OPC_FilterValue, 40, 11, 0, 0, // Skip to: 9104
/* 9093 */    MCD_OPC_CheckField, 7, 1, 0, 144, 8, 0, // Skip to: 11292
/* 9100 */    MCD_OPC_Decode, 143, 3, 15, // Opcode: DVINIT_U_rr
/* 9104 */    MCD_OPC_FilterValue, 48, 11, 0, 0, // Skip to: 9120
/* 9109 */    MCD_OPC_CheckField, 7, 1, 0, 128, 8, 0, // Skip to: 11292
/* 9116 */    MCD_OPC_Decode, 169, 8, 15, // Opcode: UPDFL_rr
/* 9120 */    MCD_OPC_FilterValue, 64, 11, 0, 0, // Skip to: 9136
/* 9125 */    MCD_OPC_CheckField, 7, 1, 0, 112, 8, 0, // Skip to: 11292
/* 9132 */    MCD_OPC_Decode, 174, 3, 15, // Opcode: FTOI_rr
/* 9136 */    MCD_OPC_FilterValue, 68, 11, 0, 0, // Skip to: 9152
/* 9141 */    MCD_OPC_CheckField, 7, 1, 0, 96, 8, 0, // Skip to: 11292
/* 9148 */    MCD_OPC_Decode, 176, 3, 15, // Opcode: FTOQ31_rr
/* 9152 */    MCD_OPC_FilterValue, 72, 11, 0, 0, // Skip to: 9168
/* 9157 */    MCD_OPC_CheckField, 7, 1, 0, 80, 8, 0, // Skip to: 11292
/* 9164 */    MCD_OPC_Decode, 178, 3, 15, // Opcode: FTOU_rr
/* 9168 */    MCD_OPC_FilterValue, 76, 11, 0, 0, // Skip to: 9184
/* 9173 */    MCD_OPC_CheckField, 7, 1, 0, 64, 8, 0, // Skip to: 11292
/* 9180 */    MCD_OPC_Decode, 173, 3, 15, // Opcode: FTOIZ_rr
/* 9184 */    MCD_OPC_FilterValue, 80, 11, 0, 0, // Skip to: 9200
/* 9189 */    MCD_OPC_CheckField, 7, 1, 0, 48, 8, 0, // Skip to: 11292
/* 9196 */    MCD_OPC_Decode, 198, 3, 15, // Opcode: ITOF_rr
/* 9200 */    MCD_OPC_FilterValue, 84, 11, 0, 0, // Skip to: 9216
/* 9205 */    MCD_OPC_CheckField, 7, 1, 0, 32, 8, 0, // Skip to: 11292
/* 9212 */    MCD_OPC_Decode, 138, 7, 15, // Opcode: Q31TOF_rr
/* 9216 */    MCD_OPC_FilterValue, 88, 11, 0, 0, // Skip to: 9232
/* 9221 */    MCD_OPC_CheckField, 7, 1, 0, 16, 8, 0, // Skip to: 11292
/* 9228 */    MCD_OPC_Decode, 170, 8, 15, // Opcode: UTOF_rr
/* 9232 */    MCD_OPC_FilterValue, 92, 11, 0, 0, // Skip to: 9248
/* 9237 */    MCD_OPC_CheckField, 7, 1, 0, 0, 8, 0, // Skip to: 11292
/* 9244 */    MCD_OPC_Decode, 177, 3, 15, // Opcode: FTOUZ_rr
/* 9248 */    MCD_OPC_FilterValue, 96, 11, 0, 0, // Skip to: 9264
/* 9253 */    MCD_OPC_CheckField, 7, 1, 0, 240, 7, 0, // Skip to: 11292
/* 9260 */    MCD_OPC_Decode, 175, 3, 15, // Opcode: FTOQ31Z_rr
/* 9264 */    MCD_OPC_FilterValue, 100, 11, 0, 0, // Skip to: 9280
/* 9269 */    MCD_OPC_CheckField, 7, 1, 0, 224, 7, 0, // Skip to: 11292
/* 9276 */    MCD_OPC_Decode, 139, 7, 15, // Opcode: QSEED_F_rr
/* 9280 */    MCD_OPC_FilterValue, 104, 11, 0, 0, // Skip to: 9296
/* 9285 */    MCD_OPC_CheckField, 7, 1, 0, 208, 7, 0, // Skip to: 11292
/* 9292 */    MCD_OPC_Decode, 144, 3, 15, // Opcode: DVINIT_rr
/* 9296 */    MCD_OPC_FilterValue, 128, 1, 11, 0, 0, // Skip to: 9313
/* 9302 */    MCD_OPC_CheckField, 7, 1, 0, 191, 7, 0, // Skip to: 11292
/* 9309 */    MCD_OPC_Decode, 136, 3, 15, // Opcode: DIV_rr
/* 9313 */    MCD_OPC_FilterValue, 132, 1, 11, 0, 0, // Skip to: 9330
/* 9319 */    MCD_OPC_CheckField, 7, 1, 0, 174, 7, 0, // Skip to: 11292
/* 9326 */    MCD_OPC_Decode, 135, 3, 15, // Opcode: DIV_U_rr
/* 9330 */    MCD_OPC_FilterValue, 136, 1, 11, 0, 0, // Skip to: 9347
/* 9336 */    MCD_OPC_CheckField, 7, 1, 0, 157, 7, 0, // Skip to: 11292
/* 9343 */    MCD_OPC_Decode, 137, 7, 15, // Opcode: POPCNT_W_rr
/* 9347 */    MCD_OPC_FilterValue, 144, 1, 11, 0, 0, // Skip to: 9364
/* 9353 */    MCD_OPC_CheckField, 7, 1, 0, 140, 7, 0, // Skip to: 11292
/* 9360 */    MCD_OPC_Decode, 184, 3, 15, // Opcode: HPTOF_rr
/* 9364 */    MCD_OPC_FilterValue, 148, 1, 11, 0, 0, // Skip to: 9381
/* 9370 */    MCD_OPC_CheckField, 7, 1, 0, 123, 7, 0, // Skip to: 11292
/* 9377 */    MCD_OPC_Decode, 172, 3, 15, // Opcode: FTOHP_rr
/* 9381 */    MCD_OPC_FilterValue, 168, 1, 11, 0, 0, // Skip to: 9398
/* 9387 */    MCD_OPC_CheckField, 7, 1, 0, 106, 7, 0, // Skip to: 11292
/* 9394 */    MCD_OPC_Decode, 141, 3, 15, // Opcode: DVINIT_HU_rr
/* 9398 */    MCD_OPC_FilterValue, 232, 1, 11, 0, 0, // Skip to: 9415
/* 9404 */    MCD_OPC_CheckField, 7, 1, 0, 89, 7, 0, // Skip to: 11292
/* 9411 */    MCD_OPC_Decode, 142, 3, 15, // Opcode: DVINIT_H_rr
/* 9415 */    MCD_OPC_FilterValue, 168, 2, 11, 0, 0, // Skip to: 9432
/* 9421 */    MCD_OPC_CheckField, 7, 1, 0, 72, 7, 0, // Skip to: 11292
/* 9428 */    MCD_OPC_Decode, 139, 3, 15, // Opcode: DVINIT_BU_rr
/* 9432 */    MCD_OPC_FilterValue, 232, 2, 62, 7, 0, // Skip to: 11292
/* 9438 */    MCD_OPC_CheckField, 7, 1, 0, 55, 7, 0, // Skip to: 11292
/* 9445 */    MCD_OPC_Decode, 140, 3, 15, // Opcode: DVINIT_B_rr
/* 9449 */    MCD_OPC_FilterValue, 77, 21, 0, 0, // Skip to: 9475
/* 9454 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9457 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9466
/* 9462 */    MCD_OPC_Decode, 202, 5, 23, // Opcode: MFCR_rlc
/* 9466 */    MCD_OPC_FilterValue, 1, 29, 7, 0, // Skip to: 11292
/* 9471 */    MCD_OPC_Decode, 191, 6, 23, // Opcode: MTCR_rlc
/* 9475 */    MCD_OPC_FilterValue, 83, 83, 0, 0, // Skip to: 9563
/* 9480 */    MCD_OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 9483 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 9499
/* 9488 */    MCD_OPC_CheckField, 7, 1, 0, 5, 7, 0, // Skip to: 11292
/* 9495 */    MCD_OPC_Decode, 221, 6, 22, // Opcode: MUL_rc
/* 9499 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 9515
/* 9504 */    MCD_OPC_CheckField, 7, 1, 0, 245, 6, 0, // Skip to: 11292
/* 9511 */    MCD_OPC_Decode, 219, 6, 22, // Opcode: MUL_U_rc
/* 9515 */    MCD_OPC_FilterValue, 3, 11, 0, 0, // Skip to: 9531
/* 9520 */    MCD_OPC_CheckField, 7, 1, 0, 229, 6, 0, // Skip to: 11292
/* 9527 */    MCD_OPC_Decode, 222, 6, 22, // Opcode: MUL_rc_e
/* 9531 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 9547
/* 9536 */    MCD_OPC_CheckField, 7, 1, 0, 213, 6, 0, // Skip to: 11292
/* 9543 */    MCD_OPC_Decode, 202, 6, 22, // Opcode: MULS_U_rc
/* 9547 */    MCD_OPC_FilterValue, 5, 204, 6, 0, // Skip to: 11292
/* 9552 */    MCD_OPC_CheckField, 7, 1, 0, 197, 6, 0, // Skip to: 11292
/* 9559 */    MCD_OPC_Decode, 204, 6, 22, // Opcode: MULS_rc
/* 9563 */    MCD_OPC_FilterValue, 85, 18, 0, 0, // Skip to: 9586
/* 9568 */    MCD_OPC_CheckField, 26, 2, 0, 181, 6, 0, // Skip to: 11292
/* 9575 */    MCD_OPC_CheckField, 7, 1, 1, 174, 6, 0, // Skip to: 11292
/* 9582 */    MCD_OPC_Decode, 253, 7, 36, // Opcode: ST_T
/* 9586 */    MCD_OPC_FilterValue, 87, 87, 0, 0, // Skip to: 9678
/* 9591 */    MCD_OPC_ExtractField, 21, 3,  // Inst{23-21} ...
/* 9594 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 9620
/* 9599 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9602 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9611
/* 9607 */    MCD_OPC_Decode, 194, 3, 26, // Opcode: INSERT_rrrw
/* 9611 */    MCD_OPC_FilterValue, 1, 140, 6, 0, // Skip to: 11292
/* 9616 */    MCD_OPC_Decode, 191, 3, 37, // Opcode: INSERT_rcrw
/* 9620 */    MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 9646
/* 9625 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9628 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9637
/* 9633 */    MCD_OPC_Decode, 188, 3, 26, // Opcode: IMASK_rrrw
/* 9637 */    MCD_OPC_FilterValue, 1, 114, 6, 0, // Skip to: 11292
/* 9642 */    MCD_OPC_Decode, 186, 3, 37, // Opcode: IMASK_rcrw
/* 9646 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 9662
/* 9651 */    MCD_OPC_CheckField, 7, 1, 0, 98, 6, 0, // Skip to: 11292
/* 9658 */    MCD_OPC_Decode, 166, 3, 26, // Opcode: EXTR_rrrw
/* 9662 */    MCD_OPC_FilterValue, 3, 89, 6, 0, // Skip to: 11292
/* 9667 */    MCD_OPC_CheckField, 7, 1, 0, 82, 6, 0, // Skip to: 11292
/* 9674 */    MCD_OPC_Decode, 163, 3, 26, // Opcode: EXTR_U_rrrw
/* 9678 */    MCD_OPC_FilterValue, 89, 21, 0, 0, // Skip to: 9704
/* 9683 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9686 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9695
/* 9691 */    MCD_OPC_Decode, 132, 8, 29, // Opcode: ST_W_bol
/* 9695 */    MCD_OPC_FilterValue, 1, 56, 6, 0, // Skip to: 11292
/* 9700 */    MCD_OPC_Decode, 215, 4, 29, // Opcode: LEA_bol
/* 9704 */    MCD_OPC_FilterValue, 93, 21, 0, 0, // Skip to: 9730
/* 9709 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9712 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9721
/* 9717 */    MCD_OPC_Decode, 227, 3, 30, // Opcode: JL_b
/* 9721 */    MCD_OPC_FilterValue, 1, 30, 6, 0, // Skip to: 11292
/* 9726 */    MCD_OPC_Decode, 219, 3, 30, // Opcode: JLA_b
/* 9730 */    MCD_OPC_FilterValue, 95, 55, 0, 0, // Skip to: 9790
/* 9735 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9738 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 9764
/* 9743 */    MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 9746 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9755
/* 9751 */    MCD_OPC_Decode, 206, 3, 31, // Opcode: JEQ_brr
/* 9755 */    MCD_OPC_FilterValue, 1, 252, 5, 0, // Skip to: 11292
/* 9760 */    MCD_OPC_Decode, 234, 3, 31, // Opcode: JNE_brr
/* 9764 */    MCD_OPC_FilterValue, 1, 243, 5, 0, // Skip to: 11292
/* 9769 */    MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 9772 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9781
/* 9777 */    MCD_OPC_Decode, 205, 3, 32, // Opcode: JEQ_brc
/* 9781 */    MCD_OPC_FilterValue, 1, 226, 5, 0, // Skip to: 11292
/* 9786 */    MCD_OPC_Decode, 233, 3, 32, // Opcode: JNE_brc
/* 9790 */    MCD_OPC_FilterValue, 97, 21, 0, 0, // Skip to: 9816
/* 9795 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9798 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9807
/* 9803 */    MCD_OPC_Decode, 169, 3, 30, // Opcode: FCALL_b
/* 9807 */    MCD_OPC_FilterValue, 1, 200, 5, 0, // Skip to: 11292
/* 9812 */    MCD_OPC_Decode, 167, 3, 30, // Opcode: FCALLA_b
/* 9816 */    MCD_OPC_FilterValue, 99, 219, 2, 0, // Skip to: 10552
/* 9821 */    MCD_OPC_ExtractField, 18, 6,  // Inst{23-18} ...
/* 9824 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 9840
/* 9829 */    MCD_OPC_CheckField, 7, 1, 0, 176, 5, 0, // Skip to: 11292
/* 9836 */    MCD_OPC_Decode, 178, 6, 17, // Opcode: MSUB_Q_rrr1_U
/* 9840 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 9856
/* 9845 */    MCD_OPC_CheckField, 7, 1, 0, 160, 5, 0, // Skip to: 11292
/* 9852 */    MCD_OPC_Decode, 176, 6, 17, // Opcode: MSUB_Q_rrr1_L
/* 9856 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 9872
/* 9861 */    MCD_OPC_CheckField, 7, 1, 0, 144, 5, 0, // Skip to: 11292
/* 9868 */    MCD_OPC_Decode, 175, 6, 17, // Opcode: MSUB_Q_rrr1
/* 9872 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 9888
/* 9877 */    MCD_OPC_CheckField, 7, 1, 0, 128, 5, 0, // Skip to: 11292
/* 9884 */    MCD_OPC_Decode, 179, 6, 17, // Opcode: MSUB_Q_rrr1_U_U
/* 9888 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 9904
/* 9893 */    MCD_OPC_CheckField, 7, 1, 0, 112, 5, 0, // Skip to: 11292
/* 9900 */    MCD_OPC_Decode, 177, 6, 17, // Opcode: MSUB_Q_rrr1_L_L
/* 9904 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 9920
/* 9909 */    MCD_OPC_CheckField, 7, 1, 0, 96, 5, 0, // Skip to: 11292
/* 9916 */    MCD_OPC_Decode, 147, 6, 17, // Opcode: MSUBR_Q_rrr1_U_U
/* 9920 */    MCD_OPC_FilterValue, 7, 11, 0, 0, // Skip to: 9936
/* 9925 */    MCD_OPC_CheckField, 7, 1, 0, 80, 5, 0, // Skip to: 11292
/* 9932 */    MCD_OPC_Decode, 146, 6, 17, // Opcode: MSUBR_Q_rrr1_L_L
/* 9936 */    MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 9952
/* 9941 */    MCD_OPC_CheckField, 7, 1, 1, 64, 5, 0, // Skip to: 11292
/* 9948 */    MCD_OPC_Decode, 244, 5, 17, // Opcode: MSUBADR_H_rrr1_UL
/* 9952 */    MCD_OPC_FilterValue, 13, 11, 0, 0, // Skip to: 9968
/* 9957 */    MCD_OPC_CheckField, 7, 1, 1, 48, 5, 0, // Skip to: 11292
/* 9964 */    MCD_OPC_Decode, 243, 5, 17, // Opcode: MSUBADR_H_rrr1_LU
/* 9968 */    MCD_OPC_FilterValue, 14, 11, 0, 0, // Skip to: 9984
/* 9973 */    MCD_OPC_CheckField, 7, 1, 1, 32, 5, 0, // Skip to: 11292
/* 9980 */    MCD_OPC_Decode, 242, 5, 17, // Opcode: MSUBADR_H_rrr1_LL
/* 9984 */    MCD_OPC_FilterValue, 15, 11, 0, 0, // Skip to: 10000
/* 9989 */    MCD_OPC_CheckField, 7, 1, 1, 16, 5, 0, // Skip to: 11292
/* 9996 */    MCD_OPC_Decode, 245, 5, 17, // Opcode: MSUBADR_H_rrr1_UU
/* 10000 */   MCD_OPC_FilterValue, 24, 21, 0, 0, // Skip to: 10026
/* 10005 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10008 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10017
/* 10013 */   MCD_OPC_Decode, 183, 6, 17, // Opcode: MSUB_Q_rrr1_e_U
/* 10017 */   MCD_OPC_FilterValue, 1, 246, 4, 0, // Skip to: 11292
/* 10022 */   MCD_OPC_Decode, 252, 5, 17, // Opcode: MSUBAD_H_rrr1_UL
/* 10026 */   MCD_OPC_FilterValue, 25, 21, 0, 0, // Skip to: 10052
/* 10031 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10034 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10043
/* 10039 */   MCD_OPC_Decode, 181, 6, 17, // Opcode: MSUB_Q_rrr1_e_L
/* 10043 */   MCD_OPC_FilterValue, 1, 220, 4, 0, // Skip to: 11292
/* 10048 */   MCD_OPC_Decode, 251, 5, 17, // Opcode: MSUBAD_H_rrr1_LU
/* 10052 */   MCD_OPC_FilterValue, 26, 11, 0, 0, // Skip to: 10068
/* 10057 */   MCD_OPC_CheckField, 7, 1, 1, 204, 4, 0, // Skip to: 11292
/* 10064 */   MCD_OPC_Decode, 250, 5, 17, // Opcode: MSUBAD_H_rrr1_LL
/* 10068 */   MCD_OPC_FilterValue, 27, 21, 0, 0, // Skip to: 10094
/* 10073 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10076 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10085
/* 10081 */   MCD_OPC_Decode, 180, 6, 17, // Opcode: MSUB_Q_rrr1_e
/* 10085 */   MCD_OPC_FilterValue, 1, 178, 4, 0, // Skip to: 11292
/* 10090 */   MCD_OPC_Decode, 253, 5, 17, // Opcode: MSUBAD_H_rrr1_UU
/* 10094 */   MCD_OPC_FilterValue, 28, 21, 0, 0, // Skip to: 10120
/* 10099 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10102 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10111
/* 10107 */   MCD_OPC_Decode, 184, 6, 17, // Opcode: MSUB_Q_rrr1_e_U_U
/* 10111 */   MCD_OPC_FilterValue, 1, 152, 4, 0, // Skip to: 11292
/* 10116 */   MCD_OPC_Decode, 236, 5, 17, // Opcode: MSUBADM_H_rrr1_UL
/* 10120 */   MCD_OPC_FilterValue, 29, 21, 0, 0, // Skip to: 10146
/* 10125 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10128 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10137
/* 10133 */   MCD_OPC_Decode, 182, 6, 17, // Opcode: MSUB_Q_rrr1_e_L_L
/* 10137 */   MCD_OPC_FilterValue, 1, 126, 4, 0, // Skip to: 11292
/* 10142 */   MCD_OPC_Decode, 235, 5, 17, // Opcode: MSUBADM_H_rrr1_LU
/* 10146 */   MCD_OPC_FilterValue, 30, 21, 0, 0, // Skip to: 10172
/* 10151 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10154 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10163
/* 10159 */   MCD_OPC_Decode, 141, 6, 17, // Opcode: MSUBR_H_rrr1_DcEdDaDbUL
/* 10163 */   MCD_OPC_FilterValue, 1, 100, 4, 0, // Skip to: 11292
/* 10168 */   MCD_OPC_Decode, 234, 5, 17, // Opcode: MSUBADM_H_rrr1_LL
/* 10172 */   MCD_OPC_FilterValue, 31, 11, 0, 0, // Skip to: 10188
/* 10177 */   MCD_OPC_CheckField, 7, 1, 1, 84, 4, 0, // Skip to: 11292
/* 10184 */   MCD_OPC_Decode, 237, 5, 17, // Opcode: MSUBADM_H_rrr1_UU
/* 10188 */   MCD_OPC_FilterValue, 32, 11, 0, 0, // Skip to: 10204
/* 10193 */   MCD_OPC_CheckField, 7, 1, 0, 68, 4, 0, // Skip to: 11292
/* 10200 */   MCD_OPC_Decode, 155, 6, 17, // Opcode: MSUBS_Q_rrr1_U
/* 10204 */   MCD_OPC_FilterValue, 33, 11, 0, 0, // Skip to: 10220
/* 10209 */   MCD_OPC_CheckField, 7, 1, 0, 52, 4, 0, // Skip to: 11292
/* 10216 */   MCD_OPC_Decode, 153, 6, 17, // Opcode: MSUBS_Q_rrr1_L
/* 10220 */   MCD_OPC_FilterValue, 34, 11, 0, 0, // Skip to: 10236
/* 10225 */   MCD_OPC_CheckField, 7, 1, 0, 36, 4, 0, // Skip to: 11292
/* 10232 */   MCD_OPC_Decode, 152, 6, 17, // Opcode: MSUBS_Q_rrr1
/* 10236 */   MCD_OPC_FilterValue, 36, 11, 0, 0, // Skip to: 10252
/* 10241 */   MCD_OPC_CheckField, 7, 1, 0, 20, 4, 0, // Skip to: 11292
/* 10248 */   MCD_OPC_Decode, 156, 6, 17, // Opcode: MSUBS_Q_rrr1_U_U
/* 10252 */   MCD_OPC_FilterValue, 37, 11, 0, 0, // Skip to: 10268
/* 10257 */   MCD_OPC_CheckField, 7, 1, 0, 4, 4, 0, // Skip to: 11292
/* 10264 */   MCD_OPC_Decode, 154, 6, 17, // Opcode: MSUBS_Q_rrr1_L_L
/* 10268 */   MCD_OPC_FilterValue, 38, 11, 0, 0, // Skip to: 10284
/* 10273 */   MCD_OPC_CheckField, 7, 1, 0, 244, 3, 0, // Skip to: 11292
/* 10280 */   MCD_OPC_Decode, 140, 6, 17, // Opcode: MSUBRS_Q_rrr1_U_U
/* 10284 */   MCD_OPC_FilterValue, 39, 11, 0, 0, // Skip to: 10300
/* 10289 */   MCD_OPC_CheckField, 7, 1, 0, 228, 3, 0, // Skip to: 11292
/* 10296 */   MCD_OPC_Decode, 139, 6, 17, // Opcode: MSUBRS_Q_rrr1_L_L
/* 10300 */   MCD_OPC_FilterValue, 44, 11, 0, 0, // Skip to: 10316
/* 10305 */   MCD_OPC_CheckField, 7, 1, 1, 212, 3, 0, // Skip to: 11292
/* 10312 */   MCD_OPC_Decode, 240, 5, 17, // Opcode: MSUBADRS_H_rrr1_UL
/* 10316 */   MCD_OPC_FilterValue, 45, 11, 0, 0, // Skip to: 10332
/* 10321 */   MCD_OPC_CheckField, 7, 1, 1, 196, 3, 0, // Skip to: 11292
/* 10328 */   MCD_OPC_Decode, 239, 5, 17, // Opcode: MSUBADRS_H_rrr1_LU
/* 10332 */   MCD_OPC_FilterValue, 46, 11, 0, 0, // Skip to: 10348
/* 10337 */   MCD_OPC_CheckField, 7, 1, 1, 180, 3, 0, // Skip to: 11292
/* 10344 */   MCD_OPC_Decode, 238, 5, 17, // Opcode: MSUBADRS_H_rrr1_LL
/* 10348 */   MCD_OPC_FilterValue, 47, 11, 0, 0, // Skip to: 10364
/* 10353 */   MCD_OPC_CheckField, 7, 1, 1, 164, 3, 0, // Skip to: 11292
/* 10360 */   MCD_OPC_Decode, 241, 5, 17, // Opcode: MSUBADRS_H_rrr1_UU
/* 10364 */   MCD_OPC_FilterValue, 56, 21, 0, 0, // Skip to: 10390
/* 10369 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10372 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10381
/* 10377 */   MCD_OPC_Decode, 160, 6, 17, // Opcode: MSUBS_Q_rrr1_e_U
/* 10381 */   MCD_OPC_FilterValue, 1, 138, 3, 0, // Skip to: 11292
/* 10386 */   MCD_OPC_Decode, 248, 5, 17, // Opcode: MSUBADS_H_rrr1_UL
/* 10390 */   MCD_OPC_FilterValue, 57, 21, 0, 0, // Skip to: 10416
/* 10395 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10398 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10407
/* 10403 */   MCD_OPC_Decode, 158, 6, 17, // Opcode: MSUBS_Q_rrr1_e_L
/* 10407 */   MCD_OPC_FilterValue, 1, 112, 3, 0, // Skip to: 11292
/* 10412 */   MCD_OPC_Decode, 247, 5, 17, // Opcode: MSUBADS_H_rrr1_LU
/* 10416 */   MCD_OPC_FilterValue, 58, 11, 0, 0, // Skip to: 10432
/* 10421 */   MCD_OPC_CheckField, 7, 1, 1, 96, 3, 0, // Skip to: 11292
/* 10428 */   MCD_OPC_Decode, 246, 5, 17, // Opcode: MSUBADS_H_rrr1_LL
/* 10432 */   MCD_OPC_FilterValue, 59, 21, 0, 0, // Skip to: 10458
/* 10437 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10440 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10449
/* 10445 */   MCD_OPC_Decode, 157, 6, 17, // Opcode: MSUBS_Q_rrr1_e
/* 10449 */   MCD_OPC_FilterValue, 1, 70, 3, 0, // Skip to: 11292
/* 10454 */   MCD_OPC_Decode, 249, 5, 17, // Opcode: MSUBADS_H_rrr1_UU
/* 10458 */   MCD_OPC_FilterValue, 60, 21, 0, 0, // Skip to: 10484
/* 10463 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10466 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10475
/* 10471 */   MCD_OPC_Decode, 161, 6, 17, // Opcode: MSUBS_Q_rrr1_e_U_U
/* 10475 */   MCD_OPC_FilterValue, 1, 44, 3, 0, // Skip to: 11292
/* 10480 */   MCD_OPC_Decode, 232, 5, 17, // Opcode: MSUBADMS_H_rrr1_UL
/* 10484 */   MCD_OPC_FilterValue, 61, 21, 0, 0, // Skip to: 10510
/* 10489 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10492 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10501
/* 10497 */   MCD_OPC_Decode, 159, 6, 17, // Opcode: MSUBS_Q_rrr1_e_L_L
/* 10501 */   MCD_OPC_FilterValue, 1, 18, 3, 0, // Skip to: 11292
/* 10506 */   MCD_OPC_Decode, 231, 5, 17, // Opcode: MSUBADMS_H_rrr1_LU
/* 10510 */   MCD_OPC_FilterValue, 62, 21, 0, 0, // Skip to: 10536
/* 10515 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10518 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10527
/* 10523 */   MCD_OPC_Decode, 134, 6, 17, // Opcode: MSUBRS_H_rrr1_DcEdDaDbUL
/* 10527 */   MCD_OPC_FilterValue, 1, 248, 2, 0, // Skip to: 11292
/* 10532 */   MCD_OPC_Decode, 230, 5, 17, // Opcode: MSUBADMS_H_rrr1_LL
/* 10536 */   MCD_OPC_FilterValue, 63, 239, 2, 0, // Skip to: 11292
/* 10541 */   MCD_OPC_CheckField, 7, 1, 1, 232, 2, 0, // Skip to: 11292
/* 10548 */   MCD_OPC_Decode, 233, 5, 17, // Opcode: MSUBADMS_H_rrr1_UU
/* 10552 */   MCD_OPC_FilterValue, 101, 45, 0, 0, // Skip to: 10602
/* 10557 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10560 */   MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 10576
/* 10565 */   MCD_OPC_CheckField, 26, 2, 0, 208, 2, 0, // Skip to: 11292
/* 10572 */   MCD_OPC_Decode, 247, 7, 18, // Opcode: ST_Q_abs
/* 10576 */   MCD_OPC_FilterValue, 1, 199, 2, 0, // Skip to: 11292
/* 10581 */   MCD_OPC_ExtractField, 26, 2,  // Inst{27-26} ...
/* 10584 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10593
/* 10589 */   MCD_OPC_Decode, 159, 8, 18, // Opcode: SWAP_W_abs
/* 10593 */   MCD_OPC_FilterValue, 1, 182, 2, 0, // Skip to: 11292
/* 10598 */   MCD_OPC_Decode, 255, 3, 18, // Opcode: LDMST_abs
/* 10602 */   MCD_OPC_FilterValue, 103, 35, 0, 0, // Skip to: 10642
/* 10607 */   MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 10610 */   MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 10626
/* 10615 */   MCD_OPC_CheckField, 7, 1, 0, 158, 2, 0, // Skip to: 11292
/* 10622 */   MCD_OPC_Decode, 196, 3, 19, // Opcode: INS_T
/* 10626 */   MCD_OPC_FilterValue, 1, 149, 2, 0, // Skip to: 11292
/* 10631 */   MCD_OPC_CheckField, 7, 1, 0, 142, 2, 0, // Skip to: 11292
/* 10638 */   MCD_OPC_Decode, 195, 3, 19, // Opcode: INSN_T
/* 10642 */   MCD_OPC_FilterValue, 105, 92, 0, 0, // Skip to: 10739
/* 10647 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10650 */   MCD_OPC_FilterValue, 0, 75, 0, 0, // Skip to: 10730
/* 10655 */   MCD_OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 10658 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10667
/* 10663 */   MCD_OPC_Decode, 164, 8, 20, // Opcode: SWAP_W_bo_r
/* 10667 */   MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 10676
/* 10672 */   MCD_OPC_Decode, 132, 4, 20, // Opcode: LDMST_bo_r
/* 10676 */   MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 10685
/* 10681 */   MCD_OPC_Decode, 158, 8, 20, // Opcode: SWAPMSK_W_bo_r
/* 10685 */   MCD_OPC_FilterValue, 3, 4, 0, 0, // Skip to: 10694
/* 10690 */   MCD_OPC_Decode, 248, 2, 20, // Opcode: CMPSWAP_W_bo_r
/* 10694 */   MCD_OPC_FilterValue, 16, 4, 0, 0, // Skip to: 10703
/* 10699 */   MCD_OPC_Decode, 161, 8, 20, // Opcode: SWAP_W_bo_c
/* 10703 */   MCD_OPC_FilterValue, 17, 4, 0, 0, // Skip to: 10712
/* 10708 */   MCD_OPC_Decode, 129, 4, 20, // Opcode: LDMST_bo_c
/* 10712 */   MCD_OPC_FilterValue, 18, 4, 0, 0, // Skip to: 10721
/* 10717 */   MCD_OPC_Decode, 155, 8, 20, // Opcode: SWAPMSK_W_bo_c
/* 10721 */   MCD_OPC_FilterValue, 19, 54, 2, 0, // Skip to: 11292
/* 10726 */   MCD_OPC_Decode, 245, 2, 20, // Opcode: CMPSWAP_W_bo_c
/* 10730 */   MCD_OPC_FilterValue, 1, 45, 2, 0, // Skip to: 11292
/* 10735 */   MCD_OPC_Decode, 219, 7, 29, // Opcode: ST_B_bol
/* 10739 */   MCD_OPC_FilterValue, 107, 211, 0, 0, // Skip to: 10955
/* 10744 */   MCD_OPC_ExtractField, 18, 6,  // Inst{23-18} ...
/* 10747 */   MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 10763
/* 10752 */   MCD_OPC_CheckField, 7, 1, 0, 21, 2, 0, // Skip to: 11292
/* 10759 */   MCD_OPC_Decode, 135, 7, 33, // Opcode: PACK_rrr
/* 10763 */   MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 10779
/* 10768 */   MCD_OPC_CheckField, 7, 1, 0, 5, 2, 0, // Skip to: 11292
/* 10775 */   MCD_OPC_Decode, 253, 2, 33, // Opcode: CRCN_rrr
/* 10779 */   MCD_OPC_FilterValue, 8, 11, 0, 0, // Skip to: 10795
/* 10784 */   MCD_OPC_CheckField, 7, 1, 0, 245, 1, 0, // Skip to: 11292
/* 10791 */   MCD_OPC_Decode, 160, 2, 33, // Opcode: ADD_F_rrr
/* 10795 */   MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 10811
/* 10800 */   MCD_OPC_CheckField, 7, 1, 0, 229, 1, 0, // Skip to: 11292
/* 10807 */   MCD_OPC_Decode, 147, 8, 33, // Opcode: SUB_F_rrr
/* 10811 */   MCD_OPC_FilterValue, 24, 11, 0, 0, // Skip to: 10827
/* 10816 */   MCD_OPC_CheckField, 7, 1, 0, 213, 1, 0, // Skip to: 11292
/* 10823 */   MCD_OPC_Decode, 173, 5, 33, // Opcode: MADD_F_rrr
/* 10827 */   MCD_OPC_FilterValue, 28, 11, 0, 0, // Skip to: 10843
/* 10832 */   MCD_OPC_CheckField, 7, 1, 0, 197, 1, 0, // Skip to: 11292
/* 10839 */   MCD_OPC_Decode, 170, 6, 33, // Opcode: MSUB_F_rrr
/* 10843 */   MCD_OPC_FilterValue, 32, 11, 0, 0, // Skip to: 10859
/* 10848 */   MCD_OPC_CheckField, 7, 1, 0, 181, 1, 0, // Skip to: 11292
/* 10855 */   MCD_OPC_Decode, 202, 3, 33, // Opcode: IXMIN_rrr
/* 10859 */   MCD_OPC_FilterValue, 36, 11, 0, 0, // Skip to: 10875
/* 10864 */   MCD_OPC_CheckField, 7, 1, 0, 165, 1, 0, // Skip to: 11292
/* 10871 */   MCD_OPC_Decode, 201, 3, 33, // Opcode: IXMIN_U_rrr
/* 10875 */   MCD_OPC_FilterValue, 40, 11, 0, 0, // Skip to: 10891
/* 10880 */   MCD_OPC_CheckField, 7, 1, 0, 149, 1, 0, // Skip to: 11292
/* 10887 */   MCD_OPC_Decode, 200, 3, 33, // Opcode: IXMAX_rrr
/* 10891 */   MCD_OPC_FilterValue, 44, 11, 0, 0, // Skip to: 10907
/* 10896 */   MCD_OPC_CheckField, 7, 1, 0, 133, 1, 0, // Skip to: 11292
/* 10903 */   MCD_OPC_Decode, 199, 3, 33, // Opcode: IXMAX_U_rrr
/* 10907 */   MCD_OPC_FilterValue, 52, 11, 0, 0, // Skip to: 10923
/* 10912 */   MCD_OPC_CheckField, 7, 1, 0, 117, 1, 0, // Skip to: 11292
/* 10919 */   MCD_OPC_Decode, 138, 3, 33, // Opcode: DVADJ_rrr
/* 10923 */   MCD_OPC_FilterValue, 56, 11, 0, 0, // Skip to: 10939
/* 10928 */   MCD_OPC_CheckField, 7, 1, 0, 101, 1, 0, // Skip to: 11292
/* 10935 */   MCD_OPC_Decode, 145, 3, 33, // Opcode: DVSTEP_U_rrr
/* 10939 */   MCD_OPC_FilterValue, 60, 92, 1, 0, // Skip to: 11292
/* 10944 */   MCD_OPC_CheckField, 7, 1, 0, 85, 1, 0, // Skip to: 11292
/* 10951 */   MCD_OPC_Decode, 146, 3, 33, // Opcode: DVSTEP_rrr
/* 10955 */   MCD_OPC_FilterValue, 109, 21, 0, 0, // Skip to: 10981
/* 10960 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10963 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10972
/* 10968 */   MCD_OPC_Decode, 232, 2, 30, // Opcode: CALL_b
/* 10972 */   MCD_OPC_FilterValue, 1, 59, 1, 0, // Skip to: 11292
/* 10977 */   MCD_OPC_Decode, 230, 2, 30, // Opcode: CALLA_b
/* 10981 */   MCD_OPC_FilterValue, 111, 21, 0, 0, // Skip to: 11007
/* 10986 */   MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 10989 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10998
/* 10994 */   MCD_OPC_Decode, 247, 3, 38, // Opcode: JZ_T_brn
/* 10998 */   MCD_OPC_FilterValue, 1, 33, 1, 0, // Skip to: 11292
/* 11003 */   MCD_OPC_Decode, 241, 3, 38, // Opcode: JNZ_T_brn
/* 11007 */   MCD_OPC_FilterValue, 115, 85, 0, 0, // Skip to: 11097
/* 11012 */   MCD_OPC_ExtractField, 16, 12,  // Inst{27-16} ...
/* 11015 */   MCD_OPC_FilterValue, 10, 11, 0, 0, // Skip to: 11031
/* 11020 */   MCD_OPC_CheckField, 7, 1, 0, 9, 1, 0, // Skip to: 11292
/* 11027 */   MCD_OPC_Decode, 223, 6, 21, // Opcode: MUL_rr2
/* 11031 */   MCD_OPC_FilterValue, 104, 11, 0, 0, // Skip to: 11047
/* 11036 */   MCD_OPC_CheckField, 7, 1, 0, 249, 0, 0, // Skip to: 11292
/* 11043 */   MCD_OPC_Decode, 220, 6, 21, // Opcode: MUL_U_rr2
/* 11047 */   MCD_OPC_FilterValue, 106, 11, 0, 0, // Skip to: 11063
/* 11052 */   MCD_OPC_CheckField, 7, 1, 0, 233, 0, 0, // Skip to: 11292
/* 11059 */   MCD_OPC_Decode, 224, 6, 21, // Opcode: MUL_rr2_e
/* 11063 */   MCD_OPC_FilterValue, 136, 1, 11, 0, 0, // Skip to: 11080
/* 11069 */   MCD_OPC_CheckField, 7, 1, 0, 216, 0, 0, // Skip to: 11292
/* 11076 */   MCD_OPC_Decode, 203, 6, 21, // Opcode: MULS_U_rr2
/* 11080 */   MCD_OPC_FilterValue, 138, 1, 206, 0, 0, // Skip to: 11292
/* 11086 */   MCD_OPC_CheckField, 7, 1, 0, 199, 0, 0, // Skip to: 11292
/* 11093 */   MCD_OPC_Decode, 205, 6, 21, // Opcode: MULS_rr2
/* 11097 */   MCD_OPC_FilterValue, 119, 18, 0, 0, // Skip to: 11120
/* 11102 */   MCD_OPC_CheckField, 21, 2, 0, 183, 0, 0, // Skip to: 11292
/* 11109 */   MCD_OPC_CheckField, 7, 1, 0, 176, 0, 0, // Skip to: 11292
/* 11116 */   MCD_OPC_Decode, 130, 3, 34, // Opcode: DEXTR_rrpw
/* 11120 */   MCD_OPC_FilterValue, 121, 21, 0, 0, // Skip to: 11146
/* 11125 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 11128 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 11137
/* 11133 */   MCD_OPC_Decode, 164, 4, 29, // Opcode: LD_B_bol
/* 11137 */   MCD_OPC_FilterValue, 1, 150, 0, 0, // Skip to: 11292
/* 11142 */   MCD_OPC_Decode, 242, 7, 29, // Opcode: ST_H_bol
/* 11146 */   MCD_OPC_FilterValue, 123, 21, 0, 0, // Skip to: 11172
/* 11151 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 11154 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 11163
/* 11159 */   MCD_OPC_Decode, 212, 5, 23, // Opcode: MOVH_rlc
/* 11163 */   MCD_OPC_FilterValue, 1, 124, 0, 0, // Skip to: 11292
/* 11168 */   MCD_OPC_Decode, 222, 5, 23, // Opcode: MOV_rlcEc
/* 11172 */   MCD_OPC_FilterValue, 125, 55, 0, 0, // Skip to: 11232
/* 11177 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 11180 */   MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 11206
/* 11185 */   MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 11188 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 11197
/* 11193 */   MCD_OPC_Decode, 204, 3, 31, // Opcode: JEQ_A_brr
/* 11197 */   MCD_OPC_FilterValue, 1, 90, 0, 0, // Skip to: 11292
/* 11202 */   MCD_OPC_Decode, 232, 3, 31, // Opcode: JNE_A_brr
/* 11206 */   MCD_OPC_FilterValue, 1, 81, 0, 0, // Skip to: 11292
/* 11211 */   MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 11214 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 11223
/* 11219 */   MCD_OPC_Decode, 218, 4, 31, // Opcode: LOOP_brr
/* 11223 */   MCD_OPC_FilterValue, 1, 64, 0, 0, // Skip to: 11292
/* 11228 */   MCD_OPC_Decode, 217, 4, 31, // Opcode: LOOPU_brr
/* 11232 */   MCD_OPC_FilterValue, 127, 55, 0, 0, // Skip to: 11292
/* 11237 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 11240 */   MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 11266
/* 11245 */   MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 11248 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 11257
/* 11253 */   MCD_OPC_Decode, 215, 3, 31, // Opcode: JGE_brr
/* 11257 */   MCD_OPC_FilterValue, 1, 30, 0, 0, // Skip to: 11292
/* 11262 */   MCD_OPC_Decode, 213, 3, 31, // Opcode: JGE_U_brr
/* 11266 */   MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 11292
/* 11271 */   MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 11274 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 11283
/* 11279 */   MCD_OPC_Decode, 214, 3, 32, // Opcode: JGE_brc
/* 11283 */   MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 11292
/* 11288 */   MCD_OPC_Decode, 212, 3, 32, // Opcode: JGE_U_brc
/* 11292 */   MCD_OPC_Fail,
              0
};

static const uint8_t DecoderTableV11016[] = {
/* 0 */       MCD_OPC_CheckField, 0, 6, 16, 4, 0, 0, // Skip to: 11
/* 7 */       MCD_OPC_Decode, 143, 2, 7, // Opcode: ADDSC_A_srrs_v110
/* 11 */      MCD_OPC_Fail,
              0
};

static const uint8_t DecoderTableV11032[] = {
/* 0 */       MCD_OPC_ExtractField, 18, 10,  // Inst{27-18} ...
/* 3 */       MCD_OPC_FilterValue, 136, 2, 11, 0, 0, // Skip to: 20
/* 9 */       MCD_OPC_CheckField, 0, 8, 11, 55, 0, 0, // Skip to: 71
/* 16 */      MCD_OPC_Decode, 146, 2, 15, // Opcode: ADDS_B_rr_v110
/* 20 */      MCD_OPC_FilterValue, 140, 2, 11, 0, 0, // Skip to: 37
/* 26 */      MCD_OPC_CheckField, 0, 8, 11, 38, 0, 0, // Skip to: 71
/* 33 */      MCD_OPC_Decode, 145, 2, 15, // Opcode: ADDS_BU_rr_v110
/* 37 */      MCD_OPC_FilterValue, 128, 3, 11, 0, 0, // Skip to: 54
/* 43 */      MCD_OPC_CheckField, 0, 8, 1, 21, 0, 0, // Skip to: 71
/* 50 */      MCD_OPC_Decode, 141, 2, 15, // Opcode: ADDSC_A_rr_v110
/* 54 */      MCD_OPC_FilterValue, 136, 3, 11, 0, 0, // Skip to: 71
/* 60 */      MCD_OPC_CheckField, 0, 8, 1, 4, 0, 0, // Skip to: 71
/* 67 */      MCD_OPC_Decode, 139, 2, 15, // Opcode: ADDSC_AT_rr_v110
/* 71 */      MCD_OPC_Fail,
              0
};

static bool checkDecoderPredicate(MCInst *Inst, unsigned Idx) {
	/* llvm_unreachable("Invalid index!"); */
}

#define DecodeToMCInst(fname, fieldname, InsnType) \
static DecodeStatus fname(DecodeStatus S, unsigned Idx, InsnType insn, MCInst *MI, \
        uint64_t Address, void *Decoder) \
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
    if (DecodeSBInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 10: \
    if (DecodeSBCInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 11: \
    if (DecodeSBRNInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 12: \
    if (DecodeSSRInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 13: \
    if (DecodeSSROInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
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
           InsnType insn, uint64_t Address, MCRegisterInfo *MRI, int feature) \
{ \
  uint64_t Bits = getFeatureBits(feature); \
  const uint8_t *Ptr = DecodeTable; \
  uint64_t CurFieldValue = 0, ExpectedValue; \
  DecodeStatus S = MCDisassembler_Success; \
  unsigned Start, Len, NumToSkip, PIdx, Opc, DecodeIdx; \
  InsnType Val, FieldValue, PositiveMask, NegativeMask; \
  bool Pred, Fail; \
  for (;;) { \
    switch (*Ptr) { \
    default: \
      return MCDisassembler_Fail; \
    case MCD_OPC_ExtractField: { \
      Start = *++Ptr; \
      Len = *++Ptr; \
      ++Ptr; \
      CurFieldValue = fieldname(insn, Start, Len); \
      break; \
    } \
    case MCD_OPC_FilterValue: { \
      Val = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      NumToSkip = *Ptr++; \
      NumToSkip |= (*Ptr++) << 8; \
      NumToSkip |= (*Ptr++) << 16; \
      if (Val != CurFieldValue) \
        Ptr += NumToSkip; \
      break; \
    } \
    case MCD_OPC_CheckField: { \
      Start = *++Ptr; \
      Len = *++Ptr; \
      FieldValue = fieldname(insn, Start, Len); \
      ExpectedValue = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      NumToSkip = *Ptr++; \
      NumToSkip |= (*Ptr++) << 8; \
      NumToSkip |= (*Ptr++) << 16; \
      if (ExpectedValue != FieldValue) \
        Ptr += NumToSkip; \
      break; \
    } \
    case MCD_OPC_CheckPredicate: { \
      PIdx = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      NumToSkip = *Ptr++; \
      NumToSkip |= (*Ptr++) << 8; \
      NumToSkip |= (*Ptr++) << 16; \
      Pred = checkDecoderPredicate(MI, PIdx); \
      if (!Pred) \
        Ptr += NumToSkip; \
      break; \
    } \
    case MCD_OPC_Decode: { \
      Opc = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      DecodeIdx = decodeULEB128(Ptr, &Len); \
      Ptr += Len; \
      MCInst_clear(MI); \
      MCInst_setOpcode(MI, Opc); \
      return decoder(S, DecodeIdx, insn, MI, Address, MRI); \
    } \
    case MCD_OPC_TryDecode: { \
      /* Decode the Opcode value. */ \
      Opc = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      DecodeIdx = decodeULEB128(Ptr, &Len); \
      Ptr += Len; \
      /* NumToSkip is a plain 24-bit integer. */ \
      NumToSkip = *Ptr++; \
      NumToSkip |= (*Ptr++) << 8; \
      NumToSkip |= (*Ptr++) << 16; \
      /* Perform the decode operation. */ \
      MCInst_setOpcode(MI, Opc); \
      if (decoder(S, DecodeIdx, insn, MI, Address, MRI)) { \
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
      PositiveMask = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      NegativeMask = decodeULEB128(Ptr, &Len); \
      Ptr += Len; \
      Fail = (insn & PositiveMask) || (~insn & NegativeMask); \
      if (Fail) \
        S = MCDisassembler_SoftFail; \
      break; \
    } \
    case MCD_OPC_Fail: { \
      return MCDisassembler_Fail; \
    } \
    } \
  } \
}

FieldFromInstruction(fieldFromInstruction_2, uint16_t)
DecodeToMCInst(decodeToMCInst_2, fieldFromInstruction_2, uint16_t)
DecodeInstruction(decodeInstruction_2, fieldFromInstruction_2, decodeToMCInst_2, uint16_t)

FieldFromInstruction(fieldFromInstruction_4, uint32_t)
DecodeToMCInst(decodeToMCInst_4, fieldFromInstruction_4, uint32_t)
DecodeInstruction(decodeInstruction_4, fieldFromInstruction_4, decodeToMCInst_4, uint32_t)
