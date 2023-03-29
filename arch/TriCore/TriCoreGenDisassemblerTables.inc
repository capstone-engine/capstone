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
/* 24 */      MCD_OPC_Decode, 226, 6, 0, // Opcode: NOP_sr
/* 28 */      MCD_OPC_FilterValue, 7, 4, 0, 0, // Skip to: 37
/* 33 */      MCD_OPC_Decode, 163, 3, 0, // Opcode: FRET_sr
/* 37 */      MCD_OPC_FilterValue, 8, 4, 0, 0, // Skip to: 46
/* 42 */      MCD_OPC_Decode, 136, 7, 0, // Opcode: RFE_sr
/* 46 */      MCD_OPC_FilterValue, 9, 4, 0, 0, // Skip to: 55
/* 51 */      MCD_OPC_Decode, 134, 7, 0, // Opcode: RET_sr
/* 55 */      MCD_OPC_FilterValue, 10, 5, 5, 0, // Skip to: 1345
/* 60 */      MCD_OPC_Decode, 249, 2, 0, // Opcode: DEBUG_sr
/* 64 */      MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 73
/* 69 */      MCD_OPC_Decode, 207, 5, 1, // Opcode: MOV_AA_srr
/* 73 */      MCD_OPC_FilterValue, 2, 243, 4, 0, // Skip to: 1345
/* 78 */      MCD_OPC_Decode, 212, 5, 1, // Opcode: MOV_D_srr
/* 82 */      MCD_OPC_FilterValue, 2, 39, 0, 0, // Skip to: 126
/* 87 */      MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 90 */      MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 99
/* 95 */      MCD_OPC_Decode, 222, 5, 1, // Opcode: MOV_srr
/* 99 */      MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 108
/* 104 */     MCD_OPC_Decode, 160, 2, 1, // Opcode: ADD_srr
/* 108 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 117
/* 113 */     MCD_OPC_Decode, 220, 5, 2, // Opcode: MOV_srcDa
/* 117 */     MCD_OPC_FilterValue, 3, 199, 4, 0, // Skip to: 1345
/* 122 */     MCD_OPC_Decode, 157, 2, 2, // Opcode: ADD_src
/* 126 */     MCD_OPC_FilterValue, 4, 39, 0, 0, // Skip to: 170
/* 131 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 134 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 143
/* 139 */     MCD_OPC_Decode, 148, 4, 3, // Opcode: LD_BU_slr_post
/* 143 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 152
/* 148 */     MCD_OPC_Decode, 203, 4, 3, // Opcode: LD_W_slr_post
/* 152 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 161
/* 157 */     MCD_OPC_Decode, 185, 4, 3, // Opcode: LD_H_slr_post
/* 161 */     MCD_OPC_FilterValue, 3, 155, 4, 0, // Skip to: 1345
/* 166 */     MCD_OPC_Decode, 137, 4, 3, // Opcode: LD_A_slr_post
/* 170 */     MCD_OPC_FilterValue, 6, 46, 0, 0, // Skip to: 221
/* 175 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 178 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 187
/* 183 */     MCD_OPC_Decode, 189, 7, 2, // Opcode: SH_src
/* 187 */     MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 203
/* 192 */     MCD_OPC_CheckField, 12, 4, 0, 122, 4, 0, // Skip to: 1345
/* 199 */     MCD_OPC_Decode, 231, 6, 0, // Opcode: NOT_sr
/* 203 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 212
/* 208 */     MCD_OPC_Decode, 163, 7, 2, // Opcode: SHA_src
/* 212 */     MCD_OPC_FilterValue, 3, 104, 4, 0, // Skip to: 1345
/* 217 */     MCD_OPC_Decode, 183, 8, 1, // Opcode: XOR_srr
/* 221 */     MCD_OPC_FilterValue, 8, 39, 0, 0, // Skip to: 265
/* 226 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 229 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 238
/* 234 */     MCD_OPC_Decode, 149, 4, 4, // Opcode: LD_BU_slro
/* 238 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 247
/* 243 */     MCD_OPC_Decode, 204, 4, 4, // Opcode: LD_W_slro
/* 247 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 256
/* 252 */     MCD_OPC_Decode, 186, 4, 4, // Opcode: LD_H_slro
/* 256 */     MCD_OPC_FilterValue, 3, 60, 4, 0, // Skip to: 1345
/* 261 */     MCD_OPC_Decode, 138, 4, 4, // Opcode: LD_A_slro
/* 265 */     MCD_OPC_FilterValue, 10, 21, 0, 0, // Skip to: 291
/* 270 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 273 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 282
/* 278 */     MCD_OPC_Decode, 222, 2, 2, // Opcode: CADD_src
/* 282 */     MCD_OPC_FilterValue, 3, 34, 4, 0, // Skip to: 1345
/* 287 */     MCD_OPC_Decode, 219, 2, 2, // Opcode: CADDN_src
/* 291 */     MCD_OPC_FilterValue, 12, 39, 0, 0, // Skip to: 335
/* 296 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 299 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 308
/* 304 */     MCD_OPC_Decode, 150, 4, 5, // Opcode: LD_BU_sro
/* 308 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 317
/* 313 */     MCD_OPC_Decode, 205, 4, 5, // Opcode: LD_W_sro
/* 317 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 326
/* 322 */     MCD_OPC_Decode, 187, 4, 5, // Opcode: LD_H_sro
/* 326 */     MCD_OPC_FilterValue, 3, 246, 3, 0, // Skip to: 1345
/* 331 */     MCD_OPC_Decode, 139, 4, 5, // Opcode: LD_A_sro
/* 335 */     MCD_OPC_FilterValue, 13, 18, 0, 0, // Skip to: 358
/* 340 */     MCD_OPC_CheckField, 12, 4, 3, 230, 3, 0, // Skip to: 1345
/* 347 */     MCD_OPC_CheckField, 6, 2, 0, 223, 3, 0, // Skip to: 1345
/* 354 */     MCD_OPC_Decode, 164, 3, 0, // Opcode: FRET_sys
/* 358 */     MCD_OPC_FilterValue, 14, 39, 0, 0, // Skip to: 402
/* 363 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 366 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 375
/* 371 */     MCD_OPC_Decode, 215, 3, 6, // Opcode: JLTZ_sbr
/* 375 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 384
/* 380 */     MCD_OPC_Decode, 209, 3, 6, // Opcode: JGTZ_sbr
/* 384 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 393
/* 389 */     MCD_OPC_Decode, 213, 3, 6, // Opcode: JLEZ_sbr
/* 393 */     MCD_OPC_FilterValue, 3, 179, 3, 0, // Skip to: 1345
/* 398 */     MCD_OPC_Decode, 204, 3, 6, // Opcode: JGEZ_sbr
/* 402 */     MCD_OPC_FilterValue, 16, 4, 0, 0, // Skip to: 411
/* 407 */     MCD_OPC_Decode, 139, 2, 7, // Opcode: ADDSC_A_srrs
/* 411 */     MCD_OPC_FilterValue, 18, 39, 0, 0, // Skip to: 455
/* 416 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 419 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 428
/* 424 */     MCD_OPC_Decode, 162, 2, 1, // Opcode: ADD_srr_a15
/* 428 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 437
/* 433 */     MCD_OPC_Decode, 145, 8, 1, // Opcode: SUB_srr_a15
/* 437 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 446
/* 442 */     MCD_OPC_Decode, 159, 2, 2, // Opcode: ADD_src_a15
/* 446 */     MCD_OPC_FilterValue, 3, 126, 3, 0, // Skip to: 1345
/* 451 */     MCD_OPC_Decode, 221, 5, 2, // Opcode: MOV_srcEa
/* 455 */     MCD_OPC_FilterValue, 20, 39, 0, 0, // Skip to: 499
/* 460 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 463 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 472
/* 468 */     MCD_OPC_Decode, 147, 4, 3, // Opcode: LD_BU_slr
/* 472 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 481
/* 477 */     MCD_OPC_Decode, 202, 4, 3, // Opcode: LD_W_slr
/* 481 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 490
/* 486 */     MCD_OPC_Decode, 184, 4, 3, // Opcode: LD_H_slr
/* 490 */     MCD_OPC_FilterValue, 3, 82, 3, 0, // Skip to: 1345
/* 495 */     MCD_OPC_Decode, 136, 4, 3, // Opcode: LD_A_slr
/* 499 */     MCD_OPC_FilterValue, 22, 21, 0, 0, // Skip to: 525
/* 504 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 507 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 516
/* 512 */     MCD_OPC_Decode, 185, 2, 8, // Opcode: AND_src
/* 516 */     MCD_OPC_FilterValue, 2, 56, 3, 0, // Skip to: 1345
/* 521 */     MCD_OPC_Decode, 254, 6, 8, // Opcode: OR_sc
/* 525 */     MCD_OPC_FilterValue, 24, 21, 0, 0, // Skip to: 551
/* 530 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 533 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 542
/* 538 */     MCD_OPC_Decode, 201, 4, 8, // Opcode: LD_W_sc
/* 542 */     MCD_OPC_FilterValue, 3, 30, 3, 0, // Skip to: 1345
/* 547 */     MCD_OPC_Decode, 135, 4, 8, // Opcode: LD_A_sc
/* 551 */     MCD_OPC_FilterValue, 26, 39, 0, 0, // Skip to: 595
/* 556 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 559 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 568
/* 564 */     MCD_OPC_Decode, 161, 2, 1, // Opcode: ADD_srr_15a
/* 568 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 577
/* 573 */     MCD_OPC_Decode, 144, 8, 1, // Opcode: SUB_srr_15a
/* 577 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 586
/* 582 */     MCD_OPC_Decode, 158, 2, 2, // Opcode: ADD_src_15a
/* 586 */     MCD_OPC_FilterValue, 3, 242, 2, 0, // Skip to: 1345
/* 591 */     MCD_OPC_Decode, 219, 5, 8, // Opcode: MOV_sc
/* 595 */     MCD_OPC_FilterValue, 28, 28, 0, 0, // Skip to: 628
/* 600 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 603 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 612
/* 608 */     MCD_OPC_Decode, 226, 2, 9, // Opcode: CALL_sb
/* 612 */     MCD_OPC_FilterValue, 3, 216, 2, 0, // Skip to: 1345
/* 617 */     MCD_OPC_CheckField, 12, 4, 0, 209, 2, 0, // Skip to: 1345
/* 624 */     MCD_OPC_Decode, 211, 3, 0, // Opcode: JI_sr
/* 628 */     MCD_OPC_FilterValue, 30, 39, 0, 0, // Skip to: 672
/* 633 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 636 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 645
/* 641 */     MCD_OPC_Decode, 200, 3, 10, // Opcode: JEQ_sbc1
/* 645 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 654
/* 650 */     MCD_OPC_Decode, 228, 3, 10, // Opcode: JNE_sbc1
/* 654 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 663
/* 659 */     MCD_OPC_Decode, 201, 3, 10, // Opcode: JEQ_sbc2
/* 663 */     MCD_OPC_FilterValue, 3, 165, 2, 0, // Skip to: 1345
/* 668 */     MCD_OPC_Decode, 229, 3, 10, // Opcode: JNE_sbc2
/* 672 */     MCD_OPC_FilterValue, 32, 39, 0, 0, // Skip to: 716
/* 677 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 680 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 689
/* 685 */     MCD_OPC_Decode, 138, 8, 8, // Opcode: SUB_A_sc
/* 689 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 698
/* 694 */     MCD_OPC_Decode, 210, 5, 1, // Opcode: MOV_A_srr
/* 698 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 707
/* 703 */     MCD_OPC_Decode, 209, 5, 2, // Opcode: MOV_A_src
/* 707 */     MCD_OPC_FilterValue, 3, 121, 2, 0, // Skip to: 1345
/* 712 */     MCD_OPC_Decode, 188, 2, 8, // Opcode: BISR_sc
/* 716 */     MCD_OPC_FilterValue, 34, 39, 0, 0, // Skip to: 760
/* 721 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 724 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 733
/* 729 */     MCD_OPC_Decode, 146, 2, 1, // Opcode: ADDS_srr
/* 733 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 742
/* 738 */     MCD_OPC_Decode, 135, 8, 1, // Opcode: SUBS_srr
/* 742 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 751
/* 747 */     MCD_OPC_Decode, 143, 8, 1, // Opcode: SUB_srr
/* 751 */     MCD_OPC_FilterValue, 3, 77, 2, 0, // Skip to: 1345
/* 756 */     MCD_OPC_Decode, 218, 6, 1, // Opcode: MUL_srr
/* 760 */     MCD_OPC_FilterValue, 35, 11, 0, 0, // Skip to: 776
/* 765 */     MCD_OPC_CheckField, 6, 2, 2, 61, 2, 0, // Skip to: 1345
/* 772 */     MCD_OPC_Decode, 235, 3, 11, // Opcode: JNZ_T_sbrn
/* 776 */     MCD_OPC_FilterValue, 36, 39, 0, 0, // Skip to: 820
/* 781 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 784 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 793
/* 789 */     MCD_OPC_Decode, 215, 7, 12, // Opcode: ST_B_ssr_pos
/* 793 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 802
/* 798 */     MCD_OPC_Decode, 128, 8, 12, // Opcode: ST_W_ssr_pos
/* 802 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 811
/* 807 */     MCD_OPC_Decode, 238, 7, 12, // Opcode: ST_H_ssr_pos
/* 811 */     MCD_OPC_FilterValue, 3, 17, 2, 0, // Skip to: 1345
/* 816 */     MCD_OPC_Decode, 204, 7, 12, // Opcode: ST_A_ssr_pos
/* 820 */     MCD_OPC_FilterValue, 38, 21, 0, 0, // Skip to: 846
/* 825 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 828 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 837
/* 833 */     MCD_OPC_Decode, 186, 2, 1, // Opcode: AND_srr
/* 837 */     MCD_OPC_FilterValue, 2, 247, 1, 0, // Skip to: 1345
/* 842 */     MCD_OPC_Decode, 255, 6, 1, // Opcode: OR_srr
/* 846 */     MCD_OPC_FilterValue, 40, 39, 0, 0, // Skip to: 890
/* 851 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 854 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 863
/* 859 */     MCD_OPC_Decode, 216, 7, 13, // Opcode: ST_B_ssro
/* 863 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 872
/* 868 */     MCD_OPC_Decode, 129, 8, 13, // Opcode: ST_W_ssro
/* 872 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 881
/* 877 */     MCD_OPC_Decode, 239, 7, 13, // Opcode: ST_H_ssro
/* 881 */     MCD_OPC_FilterValue, 3, 203, 1, 0, // Skip to: 1345
/* 886 */     MCD_OPC_Decode, 205, 7, 13, // Opcode: ST_A_ssro
/* 890 */     MCD_OPC_FilterValue, 42, 39, 0, 0, // Skip to: 934
/* 895 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 898 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 907
/* 903 */     MCD_OPC_Decode, 236, 2, 1, // Opcode: CMOV_srr
/* 907 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 916
/* 912 */     MCD_OPC_Decode, 234, 2, 1, // Opcode: CMOVN_srr
/* 916 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 925
/* 921 */     MCD_OPC_Decode, 235, 2, 2, // Opcode: CMOV_src
/* 925 */     MCD_OPC_FilterValue, 3, 159, 1, 0, // Skip to: 1345
/* 930 */     MCD_OPC_Decode, 233, 2, 2, // Opcode: CMOVN_src
/* 934 */     MCD_OPC_FilterValue, 44, 39, 0, 0, // Skip to: 978
/* 939 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 942 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 951
/* 947 */     MCD_OPC_Decode, 213, 7, 5, // Opcode: ST_B_sro
/* 951 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 960
/* 956 */     MCD_OPC_Decode, 254, 7, 5, // Opcode: ST_W_sro
/* 960 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 969
/* 965 */     MCD_OPC_Decode, 236, 7, 5, // Opcode: ST_H_sro
/* 969 */     MCD_OPC_FilterValue, 3, 115, 1, 0, // Skip to: 1345
/* 974 */     MCD_OPC_Decode, 202, 7, 5, // Opcode: ST_A_sro
/* 978 */     MCD_OPC_FilterValue, 46, 30, 0, 0, // Skip to: 1013
/* 983 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 986 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 995
/* 991 */     MCD_OPC_Decode, 241, 3, 11, // Opcode: JZ_T_sbrn
/* 995 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1004
/* 1000 */    MCD_OPC_Decode, 242, 3, 9, // Opcode: JZ_sb
/* 1004 */    MCD_OPC_FilterValue, 3, 80, 1, 0, // Skip to: 1345
/* 1009 */    MCD_OPC_Decode, 236, 3, 9, // Opcode: JNZ_sb
/* 1013 */    MCD_OPC_FilterValue, 48, 21, 0, 0, // Skip to: 1039
/* 1018 */    MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 1021 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1030
/* 1026 */    MCD_OPC_Decode, 151, 2, 1, // Opcode: ADD_A_srr
/* 1030 */    MCD_OPC_FilterValue, 2, 54, 1, 0, // Skip to: 1345
/* 1035 */    MCD_OPC_Decode, 150, 2, 2, // Opcode: ADD_A_src
/* 1039 */    MCD_OPC_FilterValue, 50, 83, 0, 0, // Skip to: 1127
/* 1044 */    MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 1047 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1063
/* 1052 */    MCD_OPC_CheckField, 6, 2, 0, 30, 1, 0, // Skip to: 1345
/* 1059 */    MCD_OPC_Decode, 148, 7, 0, // Opcode: SAT_B_sr
/* 1063 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 1079
/* 1068 */    MCD_OPC_CheckField, 6, 2, 0, 14, 1, 0, // Skip to: 1345
/* 1075 */    MCD_OPC_Decode, 146, 7, 0, // Opcode: SAT_BU_sr
/* 1079 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 1095
/* 1084 */    MCD_OPC_CheckField, 6, 2, 0, 254, 0, 0, // Skip to: 1345
/* 1091 */    MCD_OPC_Decode, 152, 7, 0, // Opcode: SAT_H_sr
/* 1095 */    MCD_OPC_FilterValue, 3, 11, 0, 0, // Skip to: 1111
/* 1100 */    MCD_OPC_CheckField, 6, 2, 0, 238, 0, 0, // Skip to: 1345
/* 1107 */    MCD_OPC_Decode, 150, 7, 0, // Opcode: SAT_HU_sr
/* 1111 */    MCD_OPC_FilterValue, 5, 229, 0, 0, // Skip to: 1345
/* 1116 */    MCD_OPC_CheckField, 6, 2, 0, 222, 0, 0, // Skip to: 1345
/* 1123 */    MCD_OPC_Decode, 144, 7, 0, // Opcode: RSUB_sr
/* 1127 */    MCD_OPC_FilterValue, 52, 39, 0, 0, // Skip to: 1171
/* 1132 */    MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 1135 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1144
/* 1140 */    MCD_OPC_Decode, 214, 7, 12, // Opcode: ST_B_ssr
/* 1144 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1153
/* 1149 */    MCD_OPC_Decode, 255, 7, 12, // Opcode: ST_W_ssr
/* 1153 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1162
/* 1158 */    MCD_OPC_Decode, 237, 7, 12, // Opcode: ST_H_ssr
/* 1162 */    MCD_OPC_FilterValue, 3, 178, 0, 0, // Skip to: 1345
/* 1167 */    MCD_OPC_Decode, 203, 7, 12, // Opcode: ST_A_ssr
/* 1171 */    MCD_OPC_FilterValue, 54, 21, 0, 0, // Skip to: 1197
/* 1176 */    MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 1179 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1188
/* 1184 */    MCD_OPC_Decode, 243, 3, 6, // Opcode: JZ_sbr
/* 1188 */    MCD_OPC_FilterValue, 3, 152, 0, 0, // Skip to: 1345
/* 1193 */    MCD_OPC_Decode, 237, 3, 6, // Opcode: JNZ_sbr
/* 1197 */    MCD_OPC_FilterValue, 56, 11, 0, 0, // Skip to: 1213
/* 1202 */    MCD_OPC_CheckField, 6, 2, 3, 136, 0, 0, // Skip to: 1345
/* 1209 */    MCD_OPC_Decode, 201, 7, 8, // Opcode: ST_A_sc
/* 1213 */    MCD_OPC_FilterValue, 58, 39, 0, 0, // Skip to: 1257
/* 1218 */    MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 1221 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1230
/* 1226 */    MCD_OPC_Decode, 153, 3, 1, // Opcode: EQ_srr
/* 1230 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1239
/* 1235 */    MCD_OPC_Decode, 225, 4, 1, // Opcode: LT_srr
/* 1239 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1248
/* 1244 */    MCD_OPC_Decode, 152, 3, 2, // Opcode: EQ_src
/* 1248 */    MCD_OPC_FilterValue, 3, 92, 0, 0, // Skip to: 1345
/* 1253 */    MCD_OPC_Decode, 224, 4, 2, // Opcode: LT_src
/* 1257 */    MCD_OPC_FilterValue, 60, 39, 0, 0, // Skip to: 1301
/* 1262 */    MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 1265 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1274
/* 1270 */    MCD_OPC_Decode, 245, 3, 9, // Opcode: J_sb
/* 1274 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1283
/* 1279 */    MCD_OPC_Decode, 233, 3, 6, // Opcode: JNZ_A_sbr
/* 1283 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1292
/* 1288 */    MCD_OPC_Decode, 239, 3, 6, // Opcode: JZ_A_sbr
/* 1292 */    MCD_OPC_FilterValue, 3, 48, 0, 0, // Skip to: 1345
/* 1297 */    MCD_OPC_Decode, 212, 4, 6, // Opcode: LOOP_sbr
/* 1301 */    MCD_OPC_FilterValue, 62, 39, 0, 0, // Skip to: 1345
/* 1306 */    MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 1309 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1318
/* 1314 */    MCD_OPC_Decode, 202, 3, 6, // Opcode: JEQ_sbr1
/* 1318 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1327
/* 1323 */    MCD_OPC_Decode, 230, 3, 6, // Opcode: JNE_sbr1
/* 1327 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1336
/* 1332 */    MCD_OPC_Decode, 203, 3, 6, // Opcode: JEQ_sbr2
/* 1336 */    MCD_OPC_FilterValue, 3, 4, 0, 0, // Skip to: 1345
/* 1341 */    MCD_OPC_Decode, 231, 3, 6, // Opcode: JNE_sbr2
/* 1345 */    MCD_OPC_Fail,
              0
};

static const uint8_t DecoderTable32[] = {
/* 0 */       MCD_OPC_ExtractField, 0, 7,  // Inst{6-0} ...
/* 3 */       MCD_OPC_FilterValue, 0, 19, 0, 0, // Skip to: 27
/* 8 */       MCD_OPC_CheckField, 12, 20, 128, 104, 241, 43, 0, // Skip to: 11265
/* 16 */      MCD_OPC_CheckField, 7, 1, 0, 234, 43, 0, // Skip to: 11265
/* 23 */      MCD_OPC_Decode, 227, 6, 14, // Opcode: NOP_sys
/* 27 */      MCD_OPC_FilterValue, 1, 221, 0, 0, // Skip to: 253
/* 32 */      MCD_OPC_ExtractField, 18, 10,  // Inst{27-18} ...
/* 35 */      MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 51
/* 40 */      MCD_OPC_CheckField, 7, 1, 0, 210, 43, 0, // Skip to: 11265
/* 47 */      MCD_OPC_Decode, 206, 5, 15, // Opcode: MOV_AA_rr
/* 51 */      MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 67
/* 56 */      MCD_OPC_CheckField, 7, 1, 0, 194, 43, 0, // Skip to: 11265
/* 63 */      MCD_OPC_Decode, 149, 2, 15, // Opcode: ADD_A_rr
/* 67 */      MCD_OPC_FilterValue, 8, 11, 0, 0, // Skip to: 83
/* 72 */      MCD_OPC_CheckField, 7, 1, 0, 178, 43, 0, // Skip to: 11265
/* 79 */      MCD_OPC_Decode, 137, 8, 15, // Opcode: SUB_A_rr
/* 83 */      MCD_OPC_FilterValue, 128, 2, 11, 0, 0, // Skip to: 100
/* 89 */      MCD_OPC_CheckField, 7, 1, 0, 161, 43, 0, // Skip to: 11265
/* 96 */      MCD_OPC_Decode, 146, 3, 15, // Opcode: EQ_A_rr
/* 100 */     MCD_OPC_FilterValue, 132, 2, 11, 0, 0, // Skip to: 117
/* 106 */     MCD_OPC_CheckField, 7, 1, 0, 144, 43, 0, // Skip to: 11265
/* 113 */     MCD_OPC_Decode, 223, 6, 15, // Opcode: NE_A
/* 117 */     MCD_OPC_FilterValue, 136, 2, 11, 0, 0, // Skip to: 134
/* 123 */     MCD_OPC_CheckField, 7, 1, 0, 127, 43, 0, // Skip to: 11265
/* 130 */     MCD_OPC_Decode, 213, 4, 15, // Opcode: LT_A_rr
/* 134 */     MCD_OPC_FilterValue, 140, 2, 11, 0, 0, // Skip to: 151
/* 140 */     MCD_OPC_CheckField, 7, 1, 0, 110, 43, 0, // Skip to: 11265
/* 147 */     MCD_OPC_Decode, 172, 3, 15, // Opcode: GE_A_rr
/* 151 */     MCD_OPC_FilterValue, 160, 2, 11, 0, 0, // Skip to: 168
/* 157 */     MCD_OPC_CheckField, 7, 1, 0, 93, 43, 0, // Skip to: 11265
/* 164 */     MCD_OPC_Decode, 145, 3, 15, // Opcode: EQZ_A_rr
/* 168 */     MCD_OPC_FilterValue, 164, 2, 11, 0, 0, // Skip to: 185
/* 174 */     MCD_OPC_CheckField, 7, 1, 0, 76, 43, 0, // Skip to: 11265
/* 181 */     MCD_OPC_Decode, 222, 6, 15, // Opcode: NEZ_A
/* 185 */     MCD_OPC_FilterValue, 176, 2, 11, 0, 0, // Skip to: 202
/* 191 */     MCD_OPC_CheckField, 7, 1, 0, 59, 43, 0, // Skip to: 11265
/* 198 */     MCD_OPC_Decode, 211, 5, 15, // Opcode: MOV_D_rr
/* 202 */     MCD_OPC_FilterValue, 128, 3, 11, 0, 0, // Skip to: 219
/* 208 */     MCD_OPC_CheckField, 7, 1, 0, 42, 43, 0, // Skip to: 11265
/* 215 */     MCD_OPC_Decode, 138, 2, 15, // Opcode: ADDSC_A_rr
/* 219 */     MCD_OPC_FilterValue, 136, 3, 11, 0, 0, // Skip to: 236
/* 225 */     MCD_OPC_CheckField, 7, 1, 0, 25, 43, 0, // Skip to: 11265
/* 232 */     MCD_OPC_Decode, 137, 2, 15, // Opcode: ADDSC_AT_rr
/* 236 */     MCD_OPC_FilterValue, 140, 3, 15, 43, 0, // Skip to: 11265
/* 242 */     MCD_OPC_CheckField, 7, 1, 0, 8, 43, 0, // Skip to: 11265
/* 249 */     MCD_OPC_Decode, 208, 5, 15, // Opcode: MOV_A_rr
/* 253 */     MCD_OPC_FilterValue, 3, 248, 1, 0, // Skip to: 762
/* 258 */     MCD_OPC_ExtractField, 18, 6,  // Inst{23-18} ...
/* 261 */     MCD_OPC_FilterValue, 2, 18, 0, 0, // Skip to: 284
/* 266 */     MCD_OPC_CheckField, 16, 2, 2, 240, 42, 0, // Skip to: 11265
/* 273 */     MCD_OPC_CheckField, 7, 1, 0, 233, 42, 0, // Skip to: 11265
/* 280 */     MCD_OPC_Decode, 185, 5, 16, // Opcode: MADD_rrr2
/* 284 */     MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 300
/* 289 */     MCD_OPC_CheckField, 7, 1, 1, 217, 42, 0, // Skip to: 11265
/* 296 */     MCD_OPC_Decode, 244, 4, 17, // Opcode: MADDR_H_rrr1_UL
/* 300 */     MCD_OPC_FilterValue, 13, 11, 0, 0, // Skip to: 316
/* 305 */     MCD_OPC_CheckField, 7, 1, 1, 201, 42, 0, // Skip to: 11265
/* 312 */     MCD_OPC_Decode, 243, 4, 17, // Opcode: MADDR_H_rrr1_LU
/* 316 */     MCD_OPC_FilterValue, 14, 11, 0, 0, // Skip to: 332
/* 321 */     MCD_OPC_CheckField, 7, 1, 1, 185, 42, 0, // Skip to: 11265
/* 328 */     MCD_OPC_Decode, 242, 4, 17, // Opcode: MADDR_H_rrr1_LL
/* 332 */     MCD_OPC_FilterValue, 15, 11, 0, 0, // Skip to: 348
/* 337 */     MCD_OPC_CheckField, 7, 1, 1, 169, 42, 0, // Skip to: 11265
/* 344 */     MCD_OPC_Decode, 245, 4, 17, // Opcode: MADDR_H_rrr1_UU
/* 348 */     MCD_OPC_FilterValue, 24, 11, 0, 0, // Skip to: 364
/* 353 */     MCD_OPC_CheckField, 7, 1, 1, 153, 42, 0, // Skip to: 11265
/* 360 */     MCD_OPC_Decode, 169, 5, 17, // Opcode: MADD_H_rrr1_UL
/* 364 */     MCD_OPC_FilterValue, 25, 11, 0, 0, // Skip to: 380
/* 369 */     MCD_OPC_CheckField, 7, 1, 1, 137, 42, 0, // Skip to: 11265
/* 376 */     MCD_OPC_Decode, 168, 5, 17, // Opcode: MADD_H_rrr1_LU
/* 380 */     MCD_OPC_FilterValue, 26, 38, 0, 0, // Skip to: 423
/* 385 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 388 */     MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 414
/* 393 */     MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 396 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 405
/* 401 */     MCD_OPC_Decode, 182, 5, 16, // Opcode: MADD_U_rrr2
/* 405 */     MCD_OPC_FilterValue, 2, 103, 42, 0, // Skip to: 11265
/* 410 */     MCD_OPC_Decode, 186, 5, 16, // Opcode: MADD_rrr2_e
/* 414 */     MCD_OPC_FilterValue, 1, 94, 42, 0, // Skip to: 11265
/* 419 */     MCD_OPC_Decode, 167, 5, 17, // Opcode: MADD_H_rrr1_LL
/* 423 */     MCD_OPC_FilterValue, 27, 11, 0, 0, // Skip to: 439
/* 428 */     MCD_OPC_CheckField, 7, 1, 1, 78, 42, 0, // Skip to: 11265
/* 435 */     MCD_OPC_Decode, 170, 5, 17, // Opcode: MADD_H_rrr1_UU
/* 439 */     MCD_OPC_FilterValue, 28, 11, 0, 0, // Skip to: 455
/* 444 */     MCD_OPC_CheckField, 7, 1, 1, 62, 42, 0, // Skip to: 11265
/* 451 */     MCD_OPC_Decode, 232, 4, 17, // Opcode: MADDM_H_rrr1_UL
/* 455 */     MCD_OPC_FilterValue, 29, 11, 0, 0, // Skip to: 471
/* 460 */     MCD_OPC_CheckField, 7, 1, 1, 46, 42, 0, // Skip to: 11265
/* 467 */     MCD_OPC_Decode, 231, 4, 17, // Opcode: MADDM_H_rrr1_LU
/* 471 */     MCD_OPC_FilterValue, 30, 11, 0, 0, // Skip to: 487
/* 476 */     MCD_OPC_CheckField, 7, 1, 1, 30, 42, 0, // Skip to: 11265
/* 483 */     MCD_OPC_Decode, 230, 4, 17, // Opcode: MADDM_H_rrr1_LL
/* 487 */     MCD_OPC_FilterValue, 31, 11, 0, 0, // Skip to: 503
/* 492 */     MCD_OPC_CheckField, 7, 1, 1, 14, 42, 0, // Skip to: 11265
/* 499 */     MCD_OPC_Decode, 233, 4, 17, // Opcode: MADDM_H_rrr1_UU
/* 503 */     MCD_OPC_FilterValue, 34, 35, 0, 0, // Skip to: 543
/* 508 */     MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 511 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 527
/* 516 */     MCD_OPC_CheckField, 7, 1, 0, 246, 41, 0, // Skip to: 11265
/* 523 */     MCD_OPC_Decode, 160, 5, 16, // Opcode: MADDS_U_rrr2
/* 527 */     MCD_OPC_FilterValue, 2, 237, 41, 0, // Skip to: 11265
/* 532 */     MCD_OPC_CheckField, 7, 1, 0, 230, 41, 0, // Skip to: 11265
/* 539 */     MCD_OPC_Decode, 164, 5, 16, // Opcode: MADDS_rrr2
/* 543 */     MCD_OPC_FilterValue, 44, 11, 0, 0, // Skip to: 559
/* 548 */     MCD_OPC_CheckField, 7, 1, 1, 214, 41, 0, // Skip to: 11265
/* 555 */     MCD_OPC_Decode, 237, 4, 17, // Opcode: MADDRS_H_rrr1_UL
/* 559 */     MCD_OPC_FilterValue, 45, 11, 0, 0, // Skip to: 575
/* 564 */     MCD_OPC_CheckField, 7, 1, 1, 198, 41, 0, // Skip to: 11265
/* 571 */     MCD_OPC_Decode, 236, 4, 17, // Opcode: MADDRS_H_rrr1_LU
/* 575 */     MCD_OPC_FilterValue, 46, 11, 0, 0, // Skip to: 591
/* 580 */     MCD_OPC_CheckField, 7, 1, 1, 182, 41, 0, // Skip to: 11265
/* 587 */     MCD_OPC_Decode, 235, 4, 17, // Opcode: MADDRS_H_rrr1_LL
/* 591 */     MCD_OPC_FilterValue, 47, 11, 0, 0, // Skip to: 607
/* 596 */     MCD_OPC_CheckField, 7, 1, 1, 166, 41, 0, // Skip to: 11265
/* 603 */     MCD_OPC_Decode, 238, 4, 17, // Opcode: MADDRS_H_rrr1_UU
/* 607 */     MCD_OPC_FilterValue, 56, 11, 0, 0, // Skip to: 623
/* 612 */     MCD_OPC_CheckField, 7, 1, 1, 150, 41, 0, // Skip to: 11265
/* 619 */     MCD_OPC_Decode, 146, 5, 17, // Opcode: MADDS_H_rrr1_UL
/* 623 */     MCD_OPC_FilterValue, 57, 11, 0, 0, // Skip to: 639
/* 628 */     MCD_OPC_CheckField, 7, 1, 1, 134, 41, 0, // Skip to: 11265
/* 635 */     MCD_OPC_Decode, 145, 5, 17, // Opcode: MADDS_H_rrr1_LU
/* 639 */     MCD_OPC_FilterValue, 58, 38, 0, 0, // Skip to: 682
/* 644 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 647 */     MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 673
/* 652 */     MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 655 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 664
/* 660 */     MCD_OPC_Decode, 161, 5, 16, // Opcode: MADDS_U_rrr2_e
/* 664 */     MCD_OPC_FilterValue, 2, 100, 41, 0, // Skip to: 11265
/* 669 */     MCD_OPC_Decode, 165, 5, 16, // Opcode: MADDS_rrr2_e
/* 673 */     MCD_OPC_FilterValue, 1, 91, 41, 0, // Skip to: 11265
/* 678 */     MCD_OPC_Decode, 144, 5, 17, // Opcode: MADDS_H_rrr1_LL
/* 682 */     MCD_OPC_FilterValue, 59, 11, 0, 0, // Skip to: 698
/* 687 */     MCD_OPC_CheckField, 7, 1, 1, 75, 41, 0, // Skip to: 11265
/* 694 */     MCD_OPC_Decode, 147, 5, 17, // Opcode: MADDS_H_rrr1_UU
/* 698 */     MCD_OPC_FilterValue, 60, 11, 0, 0, // Skip to: 714
/* 703 */     MCD_OPC_CheckField, 7, 1, 1, 59, 41, 0, // Skip to: 11265
/* 710 */     MCD_OPC_Decode, 228, 4, 17, // Opcode: MADDMS_H_rrr1_UL
/* 714 */     MCD_OPC_FilterValue, 61, 11, 0, 0, // Skip to: 730
/* 719 */     MCD_OPC_CheckField, 7, 1, 1, 43, 41, 0, // Skip to: 11265
/* 726 */     MCD_OPC_Decode, 227, 4, 17, // Opcode: MADDMS_H_rrr1_LU
/* 730 */     MCD_OPC_FilterValue, 62, 11, 0, 0, // Skip to: 746
/* 735 */     MCD_OPC_CheckField, 7, 1, 1, 27, 41, 0, // Skip to: 11265
/* 742 */     MCD_OPC_Decode, 226, 4, 17, // Opcode: MADDMS_H_rrr1_LL
/* 746 */     MCD_OPC_FilterValue, 63, 18, 41, 0, // Skip to: 11265
/* 751 */     MCD_OPC_CheckField, 7, 1, 1, 11, 41, 0, // Skip to: 11265
/* 758 */     MCD_OPC_Decode, 229, 4, 17, // Opcode: MADDMS_H_rrr1_UU
/* 762 */     MCD_OPC_FilterValue, 5, 107, 0, 0, // Skip to: 874
/* 767 */     MCD_OPC_ExtractField, 26, 2,  // Inst{27-26} ...
/* 770 */     MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 796
/* 775 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 778 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 787
/* 783 */     MCD_OPC_Decode, 151, 4, 18, // Opcode: LD_B_abs
/* 787 */     MCD_OPC_FilterValue, 1, 233, 40, 0, // Skip to: 11265
/* 792 */     MCD_OPC_Decode, 194, 4, 18, // Opcode: LD_W_abs
/* 796 */     MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 822
/* 801 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 804 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 813
/* 809 */     MCD_OPC_Decode, 140, 4, 18, // Opcode: LD_BU_abs
/* 813 */     MCD_OPC_FilterValue, 1, 207, 40, 0, // Skip to: 11265
/* 818 */     MCD_OPC_Decode, 164, 4, 18, // Opcode: LD_D_abs
/* 822 */     MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 848
/* 827 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 830 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 839
/* 835 */     MCD_OPC_Decode, 177, 4, 18, // Opcode: LD_H_abs
/* 839 */     MCD_OPC_FilterValue, 1, 181, 40, 0, // Skip to: 11265
/* 844 */     MCD_OPC_Decode, 128, 4, 18, // Opcode: LD_A_abs
/* 848 */     MCD_OPC_FilterValue, 3, 172, 40, 0, // Skip to: 11265
/* 853 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 856 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 865
/* 861 */     MCD_OPC_Decode, 170, 4, 18, // Opcode: LD_HU_abs
/* 865 */     MCD_OPC_FilterValue, 1, 155, 40, 0, // Skip to: 11265
/* 870 */     MCD_OPC_Decode, 158, 4, 18, // Opcode: LD_DA_abs
/* 874 */     MCD_OPC_FilterValue, 7, 107, 0, 0, // Skip to: 986
/* 879 */     MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 882 */     MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 908
/* 887 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 890 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 899
/* 895 */     MCD_OPC_Decode, 219, 6, 19, // Opcode: NAND_T
/* 899 */     MCD_OPC_FilterValue, 1, 121, 40, 0, // Skip to: 11265
/* 904 */     MCD_OPC_Decode, 182, 2, 19, // Opcode: AND_T
/* 908 */     MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 934
/* 913 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 916 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 925
/* 921 */     MCD_OPC_Decode, 232, 6, 19, // Opcode: ORN_T
/* 925 */     MCD_OPC_FilterValue, 1, 95, 40, 0, // Skip to: 11265
/* 930 */     MCD_OPC_Decode, 251, 6, 19, // Opcode: OR_T
/* 934 */     MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 960
/* 939 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 942 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 951
/* 947 */     MCD_OPC_Decode, 165, 8, 19, // Opcode: XNOR_T
/* 951 */     MCD_OPC_FilterValue, 1, 69, 40, 0, // Skip to: 11265
/* 956 */     MCD_OPC_Decode, 228, 6, 19, // Opcode: NOR_T
/* 960 */     MCD_OPC_FilterValue, 3, 60, 40, 0, // Skip to: 11265
/* 965 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 968 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 977
/* 973 */     MCD_OPC_Decode, 180, 8, 19, // Opcode: XOR_T
/* 977 */     MCD_OPC_FilterValue, 1, 43, 40, 0, // Skip to: 11265
/* 982 */     MCD_OPC_Decode, 163, 2, 19, // Opcode: ANDN_T
/* 986 */     MCD_OPC_FilterValue, 9, 165, 3, 0, // Skip to: 1924
/* 991 */     MCD_OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 994 */     MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 1020
/* 999 */     MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1002 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1011
/* 1007 */    MCD_OPC_Decode, 154, 4, 20, // Opcode: LD_B_bo_pos
/* 1011 */    MCD_OPC_FilterValue, 1, 9, 40, 0, // Skip to: 11265
/* 1016 */    MCD_OPC_Decode, 209, 7, 20, // Opcode: ST_B_bo_pos
/* 1020 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 1036
/* 1025 */    MCD_OPC_CheckField, 7, 1, 0, 249, 39, 0, // Skip to: 11265
/* 1032 */    MCD_OPC_Decode, 143, 4, 20, // Opcode: LD_BU_bo_pos
/* 1036 */    MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 1062
/* 1041 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1044 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1053
/* 1049 */    MCD_OPC_Decode, 180, 4, 20, // Opcode: LD_H_bo_pos
/* 1053 */    MCD_OPC_FilterValue, 1, 223, 39, 0, // Skip to: 11265
/* 1058 */    MCD_OPC_Decode, 232, 7, 20, // Opcode: ST_H_bo_pos
/* 1062 */    MCD_OPC_FilterValue, 3, 11, 0, 0, // Skip to: 1078
/* 1067 */    MCD_OPC_CheckField, 7, 1, 0, 207, 39, 0, // Skip to: 11265
/* 1074 */    MCD_OPC_Decode, 173, 4, 20, // Opcode: LD_HU_bo_pos
/* 1078 */    MCD_OPC_FilterValue, 4, 21, 0, 0, // Skip to: 1104
/* 1083 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1086 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1095
/* 1091 */    MCD_OPC_Decode, 197, 4, 20, // Opcode: LD_W_bo_pos
/* 1095 */    MCD_OPC_FilterValue, 1, 181, 39, 0, // Skip to: 11265
/* 1100 */    MCD_OPC_Decode, 250, 7, 20, // Opcode: ST_W_bo_pos
/* 1104 */    MCD_OPC_FilterValue, 5, 21, 0, 0, // Skip to: 1130
/* 1109 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1112 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1121
/* 1117 */    MCD_OPC_Decode, 167, 4, 20, // Opcode: LD_D_bo_pos
/* 1121 */    MCD_OPC_FilterValue, 1, 155, 39, 0, // Skip to: 11265
/* 1126 */    MCD_OPC_Decode, 226, 7, 20, // Opcode: ST_D_bo_pos
/* 1130 */    MCD_OPC_FilterValue, 6, 21, 0, 0, // Skip to: 1156
/* 1135 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1138 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1147
/* 1143 */    MCD_OPC_Decode, 131, 4, 20, // Opcode: LD_A_bo_pos
/* 1147 */    MCD_OPC_FilterValue, 1, 129, 39, 0, // Skip to: 11265
/* 1152 */    MCD_OPC_Decode, 197, 7, 20, // Opcode: ST_A_bo_pos
/* 1156 */    MCD_OPC_FilterValue, 7, 21, 0, 0, // Skip to: 1182
/* 1161 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1164 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1173
/* 1169 */    MCD_OPC_Decode, 161, 4, 20, // Opcode: LD_DA_bo_pos
/* 1173 */    MCD_OPC_FilterValue, 1, 103, 39, 0, // Skip to: 11265
/* 1178 */    MCD_OPC_Decode, 220, 7, 20, // Opcode: ST_DA_bo_pos
/* 1182 */    MCD_OPC_FilterValue, 8, 21, 0, 0, // Skip to: 1208
/* 1187 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1190 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1199
/* 1195 */    MCD_OPC_Decode, 191, 4, 20, // Opcode: LD_Q_bo_pos
/* 1199 */    MCD_OPC_FilterValue, 1, 77, 39, 0, // Skip to: 11265
/* 1204 */    MCD_OPC_Decode, 243, 7, 20, // Opcode: ST_Q_bo_pos
/* 1208 */    MCD_OPC_FilterValue, 10, 11, 0, 0, // Skip to: 1224
/* 1213 */    MCD_OPC_CheckField, 7, 1, 1, 61, 39, 0, // Skip to: 11265
/* 1220 */    MCD_OPC_Decode, 192, 2, 20, // Opcode: CACHEI_I_bo_pos
/* 1224 */    MCD_OPC_FilterValue, 11, 11, 0, 0, // Skip to: 1240
/* 1229 */    MCD_OPC_CheckField, 7, 1, 1, 45, 39, 0, // Skip to: 11265
/* 1236 */    MCD_OPC_Decode, 199, 2, 20, // Opcode: CACHEI_W_bo_pos
/* 1240 */    MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 1256
/* 1245 */    MCD_OPC_CheckField, 7, 1, 1, 29, 39, 0, // Skip to: 11265
/* 1252 */    MCD_OPC_Decode, 214, 2, 20, // Opcode: CACHE_W_bo_pos
/* 1256 */    MCD_OPC_FilterValue, 13, 11, 0, 0, // Skip to: 1272
/* 1261 */    MCD_OPC_CheckField, 7, 1, 1, 13, 39, 0, // Skip to: 11265
/* 1268 */    MCD_OPC_Decode, 209, 2, 20, // Opcode: CACHE_WI_bo_pos
/* 1272 */    MCD_OPC_FilterValue, 14, 11, 0, 0, // Skip to: 1288
/* 1277 */    MCD_OPC_CheckField, 7, 1, 1, 253, 38, 0, // Skip to: 11265
/* 1284 */    MCD_OPC_Decode, 204, 2, 20, // Opcode: CACHE_I_bo_pos
/* 1288 */    MCD_OPC_FilterValue, 15, 11, 0, 0, // Skip to: 1304
/* 1293 */    MCD_OPC_CheckField, 7, 1, 1, 237, 38, 0, // Skip to: 11265
/* 1300 */    MCD_OPC_Decode, 195, 2, 20, // Opcode: CACHEI_WI_bo_pos
/* 1304 */    MCD_OPC_FilterValue, 16, 21, 0, 0, // Skip to: 1330
/* 1309 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1312 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1321
/* 1317 */    MCD_OPC_Decode, 155, 4, 20, // Opcode: LD_B_bo_pre
/* 1321 */    MCD_OPC_FilterValue, 1, 211, 38, 0, // Skip to: 11265
/* 1326 */    MCD_OPC_Decode, 210, 7, 20, // Opcode: ST_B_bo_pre
/* 1330 */    MCD_OPC_FilterValue, 17, 11, 0, 0, // Skip to: 1346
/* 1335 */    MCD_OPC_CheckField, 7, 1, 0, 195, 38, 0, // Skip to: 11265
/* 1342 */    MCD_OPC_Decode, 144, 4, 20, // Opcode: LD_BU_bo_pre
/* 1346 */    MCD_OPC_FilterValue, 18, 21, 0, 0, // Skip to: 1372
/* 1351 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1354 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1363
/* 1359 */    MCD_OPC_Decode, 181, 4, 20, // Opcode: LD_H_bo_pre
/* 1363 */    MCD_OPC_FilterValue, 1, 169, 38, 0, // Skip to: 11265
/* 1368 */    MCD_OPC_Decode, 233, 7, 20, // Opcode: ST_H_bo_pre
/* 1372 */    MCD_OPC_FilterValue, 19, 11, 0, 0, // Skip to: 1388
/* 1377 */    MCD_OPC_CheckField, 7, 1, 0, 153, 38, 0, // Skip to: 11265
/* 1384 */    MCD_OPC_Decode, 174, 4, 20, // Opcode: LD_HU_bo_pre
/* 1388 */    MCD_OPC_FilterValue, 20, 21, 0, 0, // Skip to: 1414
/* 1393 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1396 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1405
/* 1401 */    MCD_OPC_Decode, 198, 4, 20, // Opcode: LD_W_bo_pre
/* 1405 */    MCD_OPC_FilterValue, 1, 127, 38, 0, // Skip to: 11265
/* 1410 */    MCD_OPC_Decode, 251, 7, 20, // Opcode: ST_W_bo_pre
/* 1414 */    MCD_OPC_FilterValue, 21, 21, 0, 0, // Skip to: 1440
/* 1419 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1422 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1431
/* 1427 */    MCD_OPC_Decode, 168, 4, 20, // Opcode: LD_D_bo_pre
/* 1431 */    MCD_OPC_FilterValue, 1, 101, 38, 0, // Skip to: 11265
/* 1436 */    MCD_OPC_Decode, 227, 7, 20, // Opcode: ST_D_bo_pre
/* 1440 */    MCD_OPC_FilterValue, 22, 21, 0, 0, // Skip to: 1466
/* 1445 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1448 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1457
/* 1453 */    MCD_OPC_Decode, 132, 4, 20, // Opcode: LD_A_bo_pre
/* 1457 */    MCD_OPC_FilterValue, 1, 75, 38, 0, // Skip to: 11265
/* 1462 */    MCD_OPC_Decode, 198, 7, 20, // Opcode: ST_A_bo_pre
/* 1466 */    MCD_OPC_FilterValue, 23, 21, 0, 0, // Skip to: 1492
/* 1471 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1474 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1483
/* 1479 */    MCD_OPC_Decode, 162, 4, 20, // Opcode: LD_DA_bo_pre
/* 1483 */    MCD_OPC_FilterValue, 1, 49, 38, 0, // Skip to: 11265
/* 1488 */    MCD_OPC_Decode, 221, 7, 20, // Opcode: ST_DA_bo_pre
/* 1492 */    MCD_OPC_FilterValue, 24, 21, 0, 0, // Skip to: 1518
/* 1497 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1500 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1509
/* 1505 */    MCD_OPC_Decode, 192, 4, 20, // Opcode: LD_Q_bo_pre
/* 1509 */    MCD_OPC_FilterValue, 1, 23, 38, 0, // Skip to: 11265
/* 1514 */    MCD_OPC_Decode, 244, 7, 20, // Opcode: ST_Q_bo_pre
/* 1518 */    MCD_OPC_FilterValue, 26, 11, 0, 0, // Skip to: 1534
/* 1523 */    MCD_OPC_CheckField, 7, 1, 1, 7, 38, 0, // Skip to: 11265
/* 1530 */    MCD_OPC_Decode, 193, 2, 20, // Opcode: CACHEI_I_bo_pre
/* 1534 */    MCD_OPC_FilterValue, 27, 11, 0, 0, // Skip to: 1550
/* 1539 */    MCD_OPC_CheckField, 7, 1, 1, 247, 37, 0, // Skip to: 11265
/* 1546 */    MCD_OPC_Decode, 200, 2, 20, // Opcode: CACHEI_W_bo_pre
/* 1550 */    MCD_OPC_FilterValue, 28, 11, 0, 0, // Skip to: 1566
/* 1555 */    MCD_OPC_CheckField, 7, 1, 1, 231, 37, 0, // Skip to: 11265
/* 1562 */    MCD_OPC_Decode, 215, 2, 20, // Opcode: CACHE_W_bo_pre
/* 1566 */    MCD_OPC_FilterValue, 29, 11, 0, 0, // Skip to: 1582
/* 1571 */    MCD_OPC_CheckField, 7, 1, 1, 215, 37, 0, // Skip to: 11265
/* 1578 */    MCD_OPC_Decode, 210, 2, 20, // Opcode: CACHE_WI_bo_pre
/* 1582 */    MCD_OPC_FilterValue, 30, 11, 0, 0, // Skip to: 1598
/* 1587 */    MCD_OPC_CheckField, 7, 1, 1, 199, 37, 0, // Skip to: 11265
/* 1594 */    MCD_OPC_Decode, 205, 2, 20, // Opcode: CACHE_I_bo_pre
/* 1598 */    MCD_OPC_FilterValue, 31, 11, 0, 0, // Skip to: 1614
/* 1603 */    MCD_OPC_CheckField, 7, 1, 1, 183, 37, 0, // Skip to: 11265
/* 1610 */    MCD_OPC_Decode, 196, 2, 20, // Opcode: CACHEI_WI_bo_pre
/* 1614 */    MCD_OPC_FilterValue, 32, 21, 0, 0, // Skip to: 1640
/* 1619 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1622 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1631
/* 1627 */    MCD_OPC_Decode, 152, 4, 20, // Opcode: LD_B_bo_bso
/* 1631 */    MCD_OPC_FilterValue, 1, 157, 37, 0, // Skip to: 11265
/* 1636 */    MCD_OPC_Decode, 207, 7, 20, // Opcode: ST_B_bo_bso
/* 1640 */    MCD_OPC_FilterValue, 33, 11, 0, 0, // Skip to: 1656
/* 1645 */    MCD_OPC_CheckField, 7, 1, 0, 141, 37, 0, // Skip to: 11265
/* 1652 */    MCD_OPC_Decode, 141, 4, 20, // Opcode: LD_BU_bo_bso
/* 1656 */    MCD_OPC_FilterValue, 34, 21, 0, 0, // Skip to: 1682
/* 1661 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1664 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1673
/* 1669 */    MCD_OPC_Decode, 178, 4, 20, // Opcode: LD_H_bo_bso
/* 1673 */    MCD_OPC_FilterValue, 1, 115, 37, 0, // Skip to: 11265
/* 1678 */    MCD_OPC_Decode, 230, 7, 20, // Opcode: ST_H_bo_bso
/* 1682 */    MCD_OPC_FilterValue, 35, 11, 0, 0, // Skip to: 1698
/* 1687 */    MCD_OPC_CheckField, 7, 1, 0, 99, 37, 0, // Skip to: 11265
/* 1694 */    MCD_OPC_Decode, 171, 4, 20, // Opcode: LD_HU_bo_bso
/* 1698 */    MCD_OPC_FilterValue, 36, 21, 0, 0, // Skip to: 1724
/* 1703 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1706 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1715
/* 1711 */    MCD_OPC_Decode, 195, 4, 20, // Opcode: LD_W_bo_bso
/* 1715 */    MCD_OPC_FilterValue, 1, 73, 37, 0, // Skip to: 11265
/* 1720 */    MCD_OPC_Decode, 248, 7, 20, // Opcode: ST_W_bo_bso
/* 1724 */    MCD_OPC_FilterValue, 37, 21, 0, 0, // Skip to: 1750
/* 1729 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1732 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1741
/* 1737 */    MCD_OPC_Decode, 165, 4, 20, // Opcode: LD_D_bo_bso
/* 1741 */    MCD_OPC_FilterValue, 1, 47, 37, 0, // Skip to: 11265
/* 1746 */    MCD_OPC_Decode, 224, 7, 20, // Opcode: ST_D_bo_bso
/* 1750 */    MCD_OPC_FilterValue, 38, 21, 0, 0, // Skip to: 1776
/* 1755 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1758 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1767
/* 1763 */    MCD_OPC_Decode, 129, 4, 20, // Opcode: LD_A_bo_bso
/* 1767 */    MCD_OPC_FilterValue, 1, 21, 37, 0, // Skip to: 11265
/* 1772 */    MCD_OPC_Decode, 195, 7, 20, // Opcode: ST_A_bo_bso
/* 1776 */    MCD_OPC_FilterValue, 39, 21, 0, 0, // Skip to: 1802
/* 1781 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1784 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1793
/* 1789 */    MCD_OPC_Decode, 159, 4, 20, // Opcode: LD_DA_bo_bso
/* 1793 */    MCD_OPC_FilterValue, 1, 251, 36, 0, // Skip to: 11265
/* 1798 */    MCD_OPC_Decode, 218, 7, 20, // Opcode: ST_DA_bo_bso
/* 1802 */    MCD_OPC_FilterValue, 40, 21, 0, 0, // Skip to: 1828
/* 1807 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1810 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1819
/* 1815 */    MCD_OPC_Decode, 189, 4, 20, // Opcode: LD_Q_bo_bso
/* 1819 */    MCD_OPC_FilterValue, 1, 225, 36, 0, // Skip to: 11265
/* 1824 */    MCD_OPC_Decode, 241, 7, 20, // Opcode: ST_Q_bo_bso
/* 1828 */    MCD_OPC_FilterValue, 42, 11, 0, 0, // Skip to: 1844
/* 1833 */    MCD_OPC_CheckField, 7, 1, 1, 209, 36, 0, // Skip to: 11265
/* 1840 */    MCD_OPC_Decode, 191, 2, 20, // Opcode: CACHEI_I_bo_bso
/* 1844 */    MCD_OPC_FilterValue, 43, 11, 0, 0, // Skip to: 1860
/* 1849 */    MCD_OPC_CheckField, 7, 1, 1, 193, 36, 0, // Skip to: 11265
/* 1856 */    MCD_OPC_Decode, 197, 2, 20, // Opcode: CACHEI_W_bo_bso
/* 1860 */    MCD_OPC_FilterValue, 44, 11, 0, 0, // Skip to: 1876
/* 1865 */    MCD_OPC_CheckField, 7, 1, 1, 177, 36, 0, // Skip to: 11265
/* 1872 */    MCD_OPC_Decode, 212, 2, 20, // Opcode: CACHE_W_bo_bso
/* 1876 */    MCD_OPC_FilterValue, 45, 11, 0, 0, // Skip to: 1892
/* 1881 */    MCD_OPC_CheckField, 7, 1, 1, 161, 36, 0, // Skip to: 11265
/* 1888 */    MCD_OPC_Decode, 207, 2, 20, // Opcode: CACHE_WI_bo_bso
/* 1892 */    MCD_OPC_FilterValue, 46, 11, 0, 0, // Skip to: 1908
/* 1897 */    MCD_OPC_CheckField, 7, 1, 1, 145, 36, 0, // Skip to: 11265
/* 1904 */    MCD_OPC_Decode, 202, 2, 20, // Opcode: CACHE_I_bo_bso
/* 1908 */    MCD_OPC_FilterValue, 47, 136, 36, 0, // Skip to: 11265
/* 1913 */    MCD_OPC_CheckField, 7, 1, 1, 129, 36, 0, // Skip to: 11265
/* 1920 */    MCD_OPC_Decode, 194, 2, 20, // Opcode: CACHEI_WI_bo_bso
/* 1924 */    MCD_OPC_FilterValue, 11, 147, 8, 0, // Skip to: 4124
/* 1929 */    MCD_OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 1932 */    MCD_OPC_FilterValue, 0, 81, 0, 0, // Skip to: 2018
/* 1937 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1940 */    MCD_OPC_FilterValue, 0, 64, 0, 0, // Skip to: 2009
/* 1945 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 1948 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1957
/* 1953 */    MCD_OPC_Decode, 156, 2, 15, // Opcode: ADD_rr
/* 1957 */    MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 1983
/* 1962 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 1965 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1974
/* 1970 */    MCD_OPC_Decode, 134, 8, 21, // Opcode: SUBS_rr
/* 1974 */    MCD_OPC_FilterValue, 3, 70, 36, 0, // Skip to: 11265
/* 1979 */    MCD_OPC_Decode, 133, 8, 21, // Opcode: SUBS_U_rr
/* 1983 */    MCD_OPC_FilterValue, 3, 61, 36, 0, // Skip to: 11265
/* 1988 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 1991 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2000
/* 1996 */    MCD_OPC_Decode, 136, 8, 21, // Opcode: SUBX_rr
/* 2000 */    MCD_OPC_FilterValue, 1, 44, 36, 0, // Skip to: 11265
/* 2005 */    MCD_OPC_Decode, 130, 8, 21, // Opcode: SUBC_rr
/* 2009 */    MCD_OPC_FilterValue, 1, 35, 36, 0, // Skip to: 11265
/* 2014 */    MCD_OPC_Decode, 155, 2, 22, // Opcode: ADD_rc
/* 2018 */    MCD_OPC_FilterValue, 1, 35, 0, 0, // Skip to: 2058
/* 2023 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2026 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2042
/* 2031 */    MCD_OPC_CheckField, 7, 1, 0, 11, 36, 0, // Skip to: 11265
/* 2038 */    MCD_OPC_Decode, 145, 2, 15, // Opcode: ADDS_rr
/* 2042 */    MCD_OPC_FilterValue, 4, 2, 36, 0, // Skip to: 11265
/* 2047 */    MCD_OPC_CheckField, 7, 1, 0, 251, 35, 0, // Skip to: 11265
/* 2054 */    MCD_OPC_Decode, 142, 2, 15, // Opcode: ADDS_U
/* 2058 */    MCD_OPC_FilterValue, 2, 38, 0, 0, // Skip to: 2101
/* 2063 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2066 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2092
/* 2071 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2074 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2083
/* 2079 */    MCD_OPC_Decode, 148, 2, 15, // Opcode: ADDX_rr
/* 2083 */    MCD_OPC_FilterValue, 4, 217, 35, 0, // Skip to: 11265
/* 2088 */    MCD_OPC_Decode, 133, 2, 15, // Opcode: ADDC_rr
/* 2092 */    MCD_OPC_FilterValue, 1, 208, 35, 0, // Skip to: 11265
/* 2097 */    MCD_OPC_Decode, 144, 2, 22, // Opcode: ADDS_rc
/* 2101 */    MCD_OPC_FilterValue, 3, 38, 0, 0, // Skip to: 2144
/* 2106 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2109 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2135
/* 2114 */    MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 2117 */    MCD_OPC_FilterValue, 10, 4, 0, 0, // Skip to: 2126
/* 2122 */    MCD_OPC_Decode, 132, 8, 21, // Opcode: SUBS_H_rr
/* 2126 */    MCD_OPC_FilterValue, 11, 174, 35, 0, // Skip to: 11265
/* 2131 */    MCD_OPC_Decode, 131, 8, 21, // Opcode: SUBS_HU_rr
/* 2135 */    MCD_OPC_FilterValue, 1, 165, 35, 0, // Skip to: 11265
/* 2140 */    MCD_OPC_Decode, 143, 2, 22, // Opcode: ADDS_U_rc
/* 2144 */    MCD_OPC_FilterValue, 4, 28, 0, 0, // Skip to: 2177
/* 2149 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2152 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2168
/* 2157 */    MCD_OPC_CheckField, 18, 3, 0, 141, 35, 0, // Skip to: 11265
/* 2164 */    MCD_OPC_Decode, 142, 8, 15, // Opcode: SUB_rr
/* 2168 */    MCD_OPC_FilterValue, 1, 132, 35, 0, // Skip to: 11265
/* 2173 */    MCD_OPC_Decode, 147, 2, 22, // Opcode: ADDX_rc
/* 2177 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 2193
/* 2182 */    MCD_OPC_CheckField, 7, 1, 1, 116, 35, 0, // Skip to: 11265
/* 2189 */    MCD_OPC_Decode, 132, 2, 22, // Opcode: ADDC_rc
/* 2193 */    MCD_OPC_FilterValue, 7, 35, 0, 0, // Skip to: 2233
/* 2198 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2201 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2217
/* 2206 */    MCD_OPC_CheckField, 7, 1, 0, 92, 35, 0, // Skip to: 11265
/* 2213 */    MCD_OPC_Decode, 254, 1, 15, // Opcode: ABSDIF_rr
/* 2217 */    MCD_OPC_FilterValue, 4, 83, 35, 0, // Skip to: 11265
/* 2222 */    MCD_OPC_CheckField, 7, 1, 0, 76, 35, 0, // Skip to: 11265
/* 2229 */    MCD_OPC_Decode, 250, 1, 15, // Opcode: ABSDIFS_rr
/* 2233 */    MCD_OPC_FilterValue, 8, 38, 0, 0, // Skip to: 2276
/* 2238 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2241 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2267
/* 2246 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2249 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2258
/* 2254 */    MCD_OPC_Decode, 151, 3, 15, // Opcode: EQ_rr
/* 2258 */    MCD_OPC_FilterValue, 4, 42, 35, 0, // Skip to: 11265
/* 2263 */    MCD_OPC_Decode, 225, 6, 15, // Opcode: NE_rr
/* 2267 */    MCD_OPC_FilterValue, 1, 33, 35, 0, // Skip to: 11265
/* 2272 */    MCD_OPC_Decode, 143, 7, 22, // Opcode: RSUB_rc
/* 2276 */    MCD_OPC_FilterValue, 9, 35, 0, 0, // Skip to: 2316
/* 2281 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2284 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2300
/* 2289 */    MCD_OPC_CheckField, 7, 1, 0, 9, 35, 0, // Skip to: 11265
/* 2296 */    MCD_OPC_Decode, 223, 4, 15, // Opcode: LT_rr
/* 2300 */    MCD_OPC_FilterValue, 4, 0, 35, 0, // Skip to: 11265
/* 2305 */    MCD_OPC_CheckField, 7, 1, 0, 249, 34, 0, // Skip to: 11265
/* 2312 */    MCD_OPC_Decode, 219, 4, 15, // Opcode: LT_U_rr
/* 2316 */    MCD_OPC_FilterValue, 10, 38, 0, 0, // Skip to: 2359
/* 2321 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2324 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2350
/* 2329 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2332 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2341
/* 2337 */    MCD_OPC_Decode, 176, 3, 15, // Opcode: GE_rr
/* 2341 */    MCD_OPC_FilterValue, 4, 215, 34, 0, // Skip to: 11265
/* 2346 */    MCD_OPC_Decode, 174, 3, 15, // Opcode: GE_U_rr
/* 2350 */    MCD_OPC_FilterValue, 1, 206, 34, 0, // Skip to: 11265
/* 2355 */    MCD_OPC_Decode, 142, 7, 22, // Opcode: RSUBS_rc
/* 2359 */    MCD_OPC_FilterValue, 11, 11, 0, 0, // Skip to: 2375
/* 2364 */    MCD_OPC_CheckField, 7, 1, 1, 190, 34, 0, // Skip to: 11265
/* 2371 */    MCD_OPC_Decode, 141, 7, 22, // Opcode: RSUBS_U_rc
/* 2375 */    MCD_OPC_FilterValue, 12, 35, 0, 0, // Skip to: 2415
/* 2380 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2383 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2399
/* 2388 */    MCD_OPC_CheckField, 7, 1, 0, 166, 34, 0, // Skip to: 11265
/* 2395 */    MCD_OPC_Decode, 203, 5, 15, // Opcode: MIN_rr
/* 2399 */    MCD_OPC_FilterValue, 4, 157, 34, 0, // Skip to: 11265
/* 2404 */    MCD_OPC_CheckField, 7, 1, 0, 150, 34, 0, // Skip to: 11265
/* 2411 */    MCD_OPC_Decode, 201, 5, 15, // Opcode: MIN_U_rr
/* 2415 */    MCD_OPC_FilterValue, 13, 35, 0, 0, // Skip to: 2455
/* 2420 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2423 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2439
/* 2428 */    MCD_OPC_CheckField, 7, 1, 0, 126, 34, 0, // Skip to: 11265
/* 2435 */    MCD_OPC_Decode, 194, 5, 15, // Opcode: MAX_rr
/* 2439 */    MCD_OPC_FilterValue, 4, 117, 34, 0, // Skip to: 11265
/* 2444 */    MCD_OPC_CheckField, 7, 1, 0, 110, 34, 0, // Skip to: 11265
/* 2451 */    MCD_OPC_Decode, 192, 5, 15, // Opcode: MAX_U_rr
/* 2455 */    MCD_OPC_FilterValue, 14, 38, 0, 0, // Skip to: 2498
/* 2460 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2463 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2489
/* 2468 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2471 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2480
/* 2476 */    MCD_OPC_Decode, 131, 2, 15, // Opcode: ABS_rr
/* 2480 */    MCD_OPC_FilterValue, 4, 76, 34, 0, // Skip to: 11265
/* 2485 */    MCD_OPC_Decode, 128, 2, 15, // Opcode: ABSS_rr
/* 2489 */    MCD_OPC_FilterValue, 1, 67, 34, 0, // Skip to: 11265
/* 2494 */    MCD_OPC_Decode, 253, 1, 22, // Opcode: ABSDIF_rc
/* 2498 */    MCD_OPC_FilterValue, 15, 28, 0, 0, // Skip to: 2531
/* 2503 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2506 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2522
/* 2511 */    MCD_OPC_CheckField, 18, 3, 4, 43, 34, 0, // Skip to: 11265
/* 2518 */    MCD_OPC_Decode, 216, 5, 15, // Opcode: MOV_rrDcDb
/* 2522 */    MCD_OPC_FilterValue, 1, 34, 34, 0, // Skip to: 11265
/* 2527 */    MCD_OPC_Decode, 249, 1, 22, // Opcode: ABSDIFS_rc
/* 2531 */    MCD_OPC_FilterValue, 16, 38, 0, 0, // Skip to: 2574
/* 2536 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2539 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2565
/* 2544 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2547 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2556
/* 2552 */    MCD_OPC_Decode, 169, 2, 15, // Opcode: AND_EQ_rr
/* 2556 */    MCD_OPC_FilterValue, 4, 0, 34, 0, // Skip to: 11265
/* 2561 */    MCD_OPC_Decode, 179, 2, 15, // Opcode: AND_NE_rr
/* 2565 */    MCD_OPC_FilterValue, 1, 247, 33, 0, // Skip to: 11265
/* 2570 */    MCD_OPC_Decode, 150, 3, 22, // Opcode: EQ_rc
/* 2574 */    MCD_OPC_FilterValue, 17, 38, 0, 0, // Skip to: 2617
/* 2579 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2582 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2608
/* 2587 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2590 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2599
/* 2595 */    MCD_OPC_Decode, 177, 2, 15, // Opcode: AND_LT_rr
/* 2599 */    MCD_OPC_FilterValue, 4, 213, 33, 0, // Skip to: 11265
/* 2604 */    MCD_OPC_Decode, 175, 2, 15, // Opcode: AND_LT_U_rr
/* 2608 */    MCD_OPC_FilterValue, 1, 204, 33, 0, // Skip to: 11265
/* 2613 */    MCD_OPC_Decode, 224, 6, 22, // Opcode: NE_rc
/* 2617 */    MCD_OPC_FilterValue, 18, 38, 0, 0, // Skip to: 2660
/* 2622 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2625 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2651
/* 2630 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2633 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2642
/* 2638 */    MCD_OPC_Decode, 173, 2, 15, // Opcode: AND_GE_rr
/* 2642 */    MCD_OPC_FilterValue, 4, 170, 33, 0, // Skip to: 11265
/* 2647 */    MCD_OPC_Decode, 171, 2, 15, // Opcode: AND_GE_U_rr
/* 2651 */    MCD_OPC_FilterValue, 1, 161, 33, 0, // Skip to: 11265
/* 2656 */    MCD_OPC_Decode, 222, 4, 22, // Opcode: LT_rc
/* 2660 */    MCD_OPC_FilterValue, 19, 28, 0, 0, // Skip to: 2693
/* 2665 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2668 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2684
/* 2673 */    MCD_OPC_CheckField, 18, 3, 4, 137, 33, 0, // Skip to: 11265
/* 2680 */    MCD_OPC_Decode, 238, 6, 15, // Opcode: OR_EQ_rr
/* 2684 */    MCD_OPC_FilterValue, 1, 128, 33, 0, // Skip to: 11265
/* 2689 */    MCD_OPC_Decode, 218, 4, 22, // Opcode: LT_U_rc
/* 2693 */    MCD_OPC_FilterValue, 20, 38, 0, 0, // Skip to: 2736
/* 2698 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2701 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2727
/* 2706 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2709 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2718
/* 2714 */    MCD_OPC_Decode, 248, 6, 15, // Opcode: OR_NE_rr
/* 2718 */    MCD_OPC_FilterValue, 4, 94, 33, 0, // Skip to: 11265
/* 2723 */    MCD_OPC_Decode, 246, 6, 15, // Opcode: OR_LT_rr
/* 2727 */    MCD_OPC_FilterValue, 1, 85, 33, 0, // Skip to: 11265
/* 2732 */    MCD_OPC_Decode, 175, 3, 22, // Opcode: GE_rc
/* 2736 */    MCD_OPC_FilterValue, 21, 38, 0, 0, // Skip to: 2779
/* 2741 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2744 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2770
/* 2749 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2752 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2761
/* 2757 */    MCD_OPC_Decode, 244, 6, 15, // Opcode: OR_LT_U_rr
/* 2761 */    MCD_OPC_FilterValue, 4, 51, 33, 0, // Skip to: 11265
/* 2766 */    MCD_OPC_Decode, 242, 6, 15, // Opcode: OR_GE_rr
/* 2770 */    MCD_OPC_FilterValue, 1, 42, 33, 0, // Skip to: 11265
/* 2775 */    MCD_OPC_Decode, 173, 3, 22, // Opcode: GE_U_rc
/* 2779 */    MCD_OPC_FilterValue, 22, 18, 0, 0, // Skip to: 2802
/* 2784 */    MCD_OPC_CheckField, 18, 3, 0, 26, 33, 0, // Skip to: 11265
/* 2791 */    MCD_OPC_CheckField, 7, 1, 0, 19, 33, 0, // Skip to: 11265
/* 2798 */    MCD_OPC_Decode, 240, 6, 15, // Opcode: OR_GE_U_rr
/* 2802 */    MCD_OPC_FilterValue, 23, 18, 0, 0, // Skip to: 2825
/* 2807 */    MCD_OPC_CheckField, 18, 3, 4, 3, 33, 0, // Skip to: 11265
/* 2814 */    MCD_OPC_CheckField, 7, 1, 0, 252, 32, 0, // Skip to: 11265
/* 2821 */    MCD_OPC_Decode, 169, 8, 15, // Opcode: XOR_EQ_rr
/* 2825 */    MCD_OPC_FilterValue, 24, 38, 0, 0, // Skip to: 2868
/* 2830 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2833 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2859
/* 2838 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2841 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2850
/* 2846 */    MCD_OPC_Decode, 179, 8, 15, // Opcode: XOR_NE_rr
/* 2850 */    MCD_OPC_FilterValue, 4, 218, 32, 0, // Skip to: 11265
/* 2855 */    MCD_OPC_Decode, 177, 8, 15, // Opcode: XOR_LT_rr
/* 2859 */    MCD_OPC_FilterValue, 1, 209, 32, 0, // Skip to: 11265
/* 2864 */    MCD_OPC_Decode, 202, 5, 22, // Opcode: MIN_rc
/* 2868 */    MCD_OPC_FilterValue, 25, 38, 0, 0, // Skip to: 2911
/* 2873 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2876 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 2902
/* 2881 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2884 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2893
/* 2889 */    MCD_OPC_Decode, 175, 8, 15, // Opcode: XOR_LT_U_rr
/* 2893 */    MCD_OPC_FilterValue, 4, 175, 32, 0, // Skip to: 11265
/* 2898 */    MCD_OPC_Decode, 173, 8, 15, // Opcode: XOR_GE_rr
/* 2902 */    MCD_OPC_FilterValue, 1, 166, 32, 0, // Skip to: 11265
/* 2907 */    MCD_OPC_Decode, 200, 5, 22, // Opcode: MIN_U_rc
/* 2911 */    MCD_OPC_FilterValue, 26, 28, 0, 0, // Skip to: 2944
/* 2916 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2919 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2935
/* 2924 */    MCD_OPC_CheckField, 18, 3, 0, 142, 32, 0, // Skip to: 11265
/* 2931 */    MCD_OPC_Decode, 171, 8, 15, // Opcode: XOR_GE_U_rr
/* 2935 */    MCD_OPC_FilterValue, 1, 133, 32, 0, // Skip to: 11265
/* 2940 */    MCD_OPC_Decode, 193, 5, 22, // Opcode: MAX_rc
/* 2944 */    MCD_OPC_FilterValue, 27, 28, 0, 0, // Skip to: 2977
/* 2949 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 2952 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2968
/* 2957 */    MCD_OPC_CheckField, 18, 3, 4, 109, 32, 0, // Skip to: 11265
/* 2964 */    MCD_OPC_Decode, 168, 7, 15, // Opcode: SH_EQ_rr
/* 2968 */    MCD_OPC_FilterValue, 1, 100, 32, 0, // Skip to: 11265
/* 2973 */    MCD_OPC_Decode, 191, 5, 22, // Opcode: MAX_U_rc
/* 2977 */    MCD_OPC_FilterValue, 28, 35, 0, 0, // Skip to: 3017
/* 2982 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 2985 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3001
/* 2990 */    MCD_OPC_CheckField, 7, 1, 0, 76, 32, 0, // Skip to: 11265
/* 2997 */    MCD_OPC_Decode, 181, 7, 15, // Opcode: SH_NE_rr
/* 3001 */    MCD_OPC_FilterValue, 4, 67, 32, 0, // Skip to: 11265
/* 3006 */    MCD_OPC_CheckField, 7, 1, 0, 60, 32, 0, // Skip to: 11265
/* 3013 */    MCD_OPC_Decode, 178, 7, 15, // Opcode: SH_LT_rr
/* 3017 */    MCD_OPC_FilterValue, 29, 35, 0, 0, // Skip to: 3057
/* 3022 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3025 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3041
/* 3030 */    MCD_OPC_CheckField, 7, 1, 0, 36, 32, 0, // Skip to: 11265
/* 3037 */    MCD_OPC_Decode, 176, 7, 15, // Opcode: SH_LT_U_rr
/* 3041 */    MCD_OPC_FilterValue, 4, 27, 32, 0, // Skip to: 11265
/* 3046 */    MCD_OPC_CheckField, 7, 1, 0, 20, 32, 0, // Skip to: 11265
/* 3053 */    MCD_OPC_Decode, 172, 7, 15, // Opcode: SH_GE_rr
/* 3057 */    MCD_OPC_FilterValue, 30, 18, 0, 0, // Skip to: 3080
/* 3062 */    MCD_OPC_CheckField, 18, 3, 0, 4, 32, 0, // Skip to: 11265
/* 3069 */    MCD_OPC_CheckField, 7, 1, 0, 253, 31, 0, // Skip to: 11265
/* 3076 */    MCD_OPC_Decode, 170, 7, 15, // Opcode: SH_GE_U_rr
/* 3080 */    MCD_OPC_FilterValue, 32, 28, 0, 0, // Skip to: 3113
/* 3085 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3088 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3104
/* 3093 */    MCD_OPC_CheckField, 18, 3, 0, 229, 31, 0, // Skip to: 11265
/* 3100 */    MCD_OPC_Decode, 152, 2, 15, // Opcode: ADD_B_rr
/* 3104 */    MCD_OPC_FilterValue, 1, 220, 31, 0, // Skip to: 11265
/* 3109 */    MCD_OPC_Decode, 168, 2, 22, // Opcode: AND_EQ_rc
/* 3113 */    MCD_OPC_FilterValue, 33, 11, 0, 0, // Skip to: 3129
/* 3118 */    MCD_OPC_CheckField, 7, 1, 1, 204, 31, 0, // Skip to: 11265
/* 3125 */    MCD_OPC_Decode, 178, 2, 22, // Opcode: AND_NE_rc
/* 3129 */    MCD_OPC_FilterValue, 34, 11, 0, 0, // Skip to: 3145
/* 3134 */    MCD_OPC_CheckField, 7, 1, 1, 188, 31, 0, // Skip to: 11265
/* 3141 */    MCD_OPC_Decode, 176, 2, 22, // Opcode: AND_LT_rc
/* 3145 */    MCD_OPC_FilterValue, 35, 11, 0, 0, // Skip to: 3161
/* 3150 */    MCD_OPC_CheckField, 7, 1, 1, 172, 31, 0, // Skip to: 11265
/* 3157 */    MCD_OPC_Decode, 174, 2, 22, // Opcode: AND_LT_U_rc
/* 3161 */    MCD_OPC_FilterValue, 36, 28, 0, 0, // Skip to: 3194
/* 3166 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3169 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3185
/* 3174 */    MCD_OPC_CheckField, 18, 3, 0, 148, 31, 0, // Skip to: 11265
/* 3181 */    MCD_OPC_Decode, 139, 8, 15, // Opcode: SUB_B_rr
/* 3185 */    MCD_OPC_FilterValue, 1, 139, 31, 0, // Skip to: 11265
/* 3190 */    MCD_OPC_Decode, 172, 2, 22, // Opcode: AND_GE_rc
/* 3194 */    MCD_OPC_FilterValue, 37, 11, 0, 0, // Skip to: 3210
/* 3199 */    MCD_OPC_CheckField, 7, 1, 1, 123, 31, 0, // Skip to: 11265
/* 3206 */    MCD_OPC_Decode, 170, 2, 22, // Opcode: AND_GE_U_rc
/* 3210 */    MCD_OPC_FilterValue, 39, 28, 0, 0, // Skip to: 3243
/* 3215 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3218 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3234
/* 3223 */    MCD_OPC_CheckField, 18, 3, 0, 99, 31, 0, // Skip to: 11265
/* 3230 */    MCD_OPC_Decode, 251, 1, 15, // Opcode: ABSDIF_B_rr
/* 3234 */    MCD_OPC_FilterValue, 1, 90, 31, 0, // Skip to: 11265
/* 3239 */    MCD_OPC_Decode, 237, 6, 22, // Opcode: OR_EQ_rc
/* 3243 */    MCD_OPC_FilterValue, 40, 28, 0, 0, // Skip to: 3276
/* 3248 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3251 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3267
/* 3256 */    MCD_OPC_CheckField, 18, 3, 0, 66, 31, 0, // Skip to: 11265
/* 3263 */    MCD_OPC_Decode, 147, 3, 15, // Opcode: EQ_B_rr
/* 3267 */    MCD_OPC_FilterValue, 1, 57, 31, 0, // Skip to: 11265
/* 3272 */    MCD_OPC_Decode, 247, 6, 22, // Opcode: OR_NE_rc
/* 3276 */    MCD_OPC_FilterValue, 41, 38, 0, 0, // Skip to: 3319
/* 3281 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3284 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3310
/* 3289 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3292 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3301
/* 3297 */    MCD_OPC_Decode, 214, 4, 15, // Opcode: LT_B
/* 3301 */    MCD_OPC_FilterValue, 4, 23, 31, 0, // Skip to: 11265
/* 3306 */    MCD_OPC_Decode, 215, 4, 15, // Opcode: LT_BU
/* 3310 */    MCD_OPC_FilterValue, 1, 14, 31, 0, // Skip to: 11265
/* 3315 */    MCD_OPC_Decode, 245, 6, 22, // Opcode: OR_LT_rc
/* 3319 */    MCD_OPC_FilterValue, 42, 11, 0, 0, // Skip to: 3335
/* 3324 */    MCD_OPC_CheckField, 7, 1, 1, 254, 30, 0, // Skip to: 11265
/* 3331 */    MCD_OPC_Decode, 243, 6, 22, // Opcode: OR_LT_U_rc
/* 3335 */    MCD_OPC_FilterValue, 43, 28, 0, 0, // Skip to: 3368
/* 3340 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3343 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3359
/* 3348 */    MCD_OPC_CheckField, 18, 3, 0, 230, 30, 0, // Skip to: 11265
/* 3355 */    MCD_OPC_Decode, 142, 3, 15, // Opcode: EQANY_B_rr
/* 3359 */    MCD_OPC_FilterValue, 1, 221, 30, 0, // Skip to: 11265
/* 3364 */    MCD_OPC_Decode, 241, 6, 22, // Opcode: OR_GE_rc
/* 3368 */    MCD_OPC_FilterValue, 44, 38, 0, 0, // Skip to: 3411
/* 3373 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3376 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3402
/* 3381 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3384 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3393
/* 3389 */    MCD_OPC_Decode, 196, 5, 15, // Opcode: MIN_B
/* 3393 */    MCD_OPC_FilterValue, 4, 187, 30, 0, // Skip to: 11265
/* 3398 */    MCD_OPC_Decode, 197, 5, 15, // Opcode: MIN_BU
/* 3402 */    MCD_OPC_FilterValue, 1, 178, 30, 0, // Skip to: 11265
/* 3407 */    MCD_OPC_Decode, 239, 6, 22, // Opcode: OR_GE_U_rc
/* 3411 */    MCD_OPC_FilterValue, 45, 35, 0, 0, // Skip to: 3451
/* 3416 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3419 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3435
/* 3424 */    MCD_OPC_CheckField, 7, 1, 0, 154, 30, 0, // Skip to: 11265
/* 3431 */    MCD_OPC_Decode, 187, 5, 15, // Opcode: MAX_B
/* 3435 */    MCD_OPC_FilterValue, 4, 145, 30, 0, // Skip to: 11265
/* 3440 */    MCD_OPC_CheckField, 7, 1, 0, 138, 30, 0, // Skip to: 11265
/* 3447 */    MCD_OPC_Decode, 188, 5, 15, // Opcode: MAX_BU
/* 3451 */    MCD_OPC_FilterValue, 46, 18, 0, 0, // Skip to: 3474
/* 3456 */    MCD_OPC_CheckField, 18, 3, 0, 122, 30, 0, // Skip to: 11265
/* 3463 */    MCD_OPC_CheckField, 7, 1, 0, 115, 30, 0, // Skip to: 11265
/* 3470 */    MCD_OPC_Decode, 129, 2, 15, // Opcode: ABS_B_rr
/* 3474 */    MCD_OPC_FilterValue, 47, 38, 0, 0, // Skip to: 3517
/* 3479 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3482 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3508
/* 3487 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3490 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3499
/* 3495 */    MCD_OPC_Decode, 147, 7, 15, // Opcode: SAT_B_rr
/* 3499 */    MCD_OPC_FilterValue, 4, 81, 30, 0, // Skip to: 11265
/* 3504 */    MCD_OPC_Decode, 145, 7, 15, // Opcode: SAT_BU_rr
/* 3508 */    MCD_OPC_FilterValue, 1, 72, 30, 0, // Skip to: 11265
/* 3513 */    MCD_OPC_Decode, 168, 8, 22, // Opcode: XOR_EQ_rc
/* 3517 */    MCD_OPC_FilterValue, 48, 28, 0, 0, // Skip to: 3550
/* 3522 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3525 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3541
/* 3530 */    MCD_OPC_CheckField, 18, 3, 0, 48, 30, 0, // Skip to: 11265
/* 3537 */    MCD_OPC_Decode, 154, 2, 15, // Opcode: ADD_H_rr
/* 3541 */    MCD_OPC_FilterValue, 1, 39, 30, 0, // Skip to: 11265
/* 3546 */    MCD_OPC_Decode, 178, 8, 22, // Opcode: XOR_NE_rc
/* 3550 */    MCD_OPC_FilterValue, 49, 38, 0, 0, // Skip to: 3593
/* 3555 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3558 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3584
/* 3563 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3566 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3575
/* 3571 */    MCD_OPC_Decode, 140, 2, 15, // Opcode: ADDS_H
/* 3575 */    MCD_OPC_FilterValue, 4, 5, 30, 0, // Skip to: 11265
/* 3580 */    MCD_OPC_Decode, 141, 2, 15, // Opcode: ADDS_HU
/* 3584 */    MCD_OPC_FilterValue, 1, 252, 29, 0, // Skip to: 11265
/* 3589 */    MCD_OPC_Decode, 176, 8, 22, // Opcode: XOR_LT_rc
/* 3593 */    MCD_OPC_FilterValue, 50, 11, 0, 0, // Skip to: 3609
/* 3598 */    MCD_OPC_CheckField, 7, 1, 1, 236, 29, 0, // Skip to: 11265
/* 3605 */    MCD_OPC_Decode, 174, 8, 22, // Opcode: XOR_LT_U_rc
/* 3609 */    MCD_OPC_FilterValue, 51, 11, 0, 0, // Skip to: 3625
/* 3614 */    MCD_OPC_CheckField, 7, 1, 1, 220, 29, 0, // Skip to: 11265
/* 3621 */    MCD_OPC_Decode, 172, 8, 22, // Opcode: XOR_GE_rc
/* 3625 */    MCD_OPC_FilterValue, 52, 28, 0, 0, // Skip to: 3658
/* 3630 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3633 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3649
/* 3638 */    MCD_OPC_CheckField, 18, 3, 0, 196, 29, 0, // Skip to: 11265
/* 3645 */    MCD_OPC_Decode, 141, 8, 15, // Opcode: SUB_H_rr
/* 3649 */    MCD_OPC_FilterValue, 1, 187, 29, 0, // Skip to: 11265
/* 3654 */    MCD_OPC_Decode, 170, 8, 22, // Opcode: XOR_GE_U_rc
/* 3658 */    MCD_OPC_FilterValue, 55, 38, 0, 0, // Skip to: 3701
/* 3663 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3666 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3692
/* 3671 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3674 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3683
/* 3679 */    MCD_OPC_Decode, 252, 1, 15, // Opcode: ABSDIF_H_rr
/* 3683 */    MCD_OPC_FilterValue, 4, 153, 29, 0, // Skip to: 11265
/* 3688 */    MCD_OPC_Decode, 248, 1, 15, // Opcode: ABSDIFS_H_rr
/* 3692 */    MCD_OPC_FilterValue, 1, 144, 29, 0, // Skip to: 11265
/* 3697 */    MCD_OPC_Decode, 167, 7, 22, // Opcode: SH_EQ_rc
/* 3701 */    MCD_OPC_FilterValue, 56, 28, 0, 0, // Skip to: 3734
/* 3706 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3709 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3725
/* 3714 */    MCD_OPC_CheckField, 18, 3, 0, 120, 29, 0, // Skip to: 11265
/* 3721 */    MCD_OPC_Decode, 148, 3, 15, // Opcode: EQ_H_rr
/* 3725 */    MCD_OPC_FilterValue, 1, 111, 29, 0, // Skip to: 11265
/* 3730 */    MCD_OPC_Decode, 180, 7, 22, // Opcode: SH_NE_rc
/* 3734 */    MCD_OPC_FilterValue, 57, 38, 0, 0, // Skip to: 3777
/* 3739 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3742 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3768
/* 3747 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3750 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3759
/* 3755 */    MCD_OPC_Decode, 216, 4, 15, // Opcode: LT_H
/* 3759 */    MCD_OPC_FilterValue, 4, 77, 29, 0, // Skip to: 11265
/* 3764 */    MCD_OPC_Decode, 217, 4, 15, // Opcode: LT_HU
/* 3768 */    MCD_OPC_FilterValue, 1, 68, 29, 0, // Skip to: 11265
/* 3773 */    MCD_OPC_Decode, 177, 7, 22, // Opcode: SH_LT_rc
/* 3777 */    MCD_OPC_FilterValue, 58, 11, 0, 0, // Skip to: 3793
/* 3782 */    MCD_OPC_CheckField, 7, 1, 1, 52, 29, 0, // Skip to: 11265
/* 3789 */    MCD_OPC_Decode, 175, 7, 22, // Opcode: SH_LT_U_rc
/* 3793 */    MCD_OPC_FilterValue, 59, 28, 0, 0, // Skip to: 3826
/* 3798 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3801 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3817
/* 3806 */    MCD_OPC_CheckField, 18, 3, 0, 28, 29, 0, // Skip to: 11265
/* 3813 */    MCD_OPC_Decode, 144, 3, 15, // Opcode: EQANY_H_rr
/* 3817 */    MCD_OPC_FilterValue, 1, 19, 29, 0, // Skip to: 11265
/* 3822 */    MCD_OPC_Decode, 171, 7, 22, // Opcode: SH_GE_rc
/* 3826 */    MCD_OPC_FilterValue, 60, 38, 0, 0, // Skip to: 3869
/* 3831 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 3834 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 3860
/* 3839 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3842 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 3851
/* 3847 */    MCD_OPC_Decode, 198, 5, 15, // Opcode: MIN_H
/* 3851 */    MCD_OPC_FilterValue, 4, 241, 28, 0, // Skip to: 11265
/* 3856 */    MCD_OPC_Decode, 199, 5, 15, // Opcode: MIN_HU
/* 3860 */    MCD_OPC_FilterValue, 1, 232, 28, 0, // Skip to: 11265
/* 3865 */    MCD_OPC_Decode, 169, 7, 22, // Opcode: SH_GE_U_rc
/* 3869 */    MCD_OPC_FilterValue, 61, 35, 0, 0, // Skip to: 3909
/* 3874 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3877 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3893
/* 3882 */    MCD_OPC_CheckField, 7, 1, 0, 208, 28, 0, // Skip to: 11265
/* 3889 */    MCD_OPC_Decode, 189, 5, 15, // Opcode: MAX_H
/* 3893 */    MCD_OPC_FilterValue, 4, 199, 28, 0, // Skip to: 11265
/* 3898 */    MCD_OPC_CheckField, 7, 1, 0, 192, 28, 0, // Skip to: 11265
/* 3905 */    MCD_OPC_Decode, 190, 5, 15, // Opcode: MAX_HU
/* 3909 */    MCD_OPC_FilterValue, 62, 35, 0, 0, // Skip to: 3949
/* 3914 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3917 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3933
/* 3922 */    MCD_OPC_CheckField, 7, 1, 0, 168, 28, 0, // Skip to: 11265
/* 3929 */    MCD_OPC_Decode, 130, 2, 15, // Opcode: ABS_H_rr
/* 3933 */    MCD_OPC_FilterValue, 4, 159, 28, 0, // Skip to: 11265
/* 3938 */    MCD_OPC_CheckField, 7, 1, 0, 152, 28, 0, // Skip to: 11265
/* 3945 */    MCD_OPC_Decode, 255, 1, 15, // Opcode: ABSS_H_rr
/* 3949 */    MCD_OPC_FilterValue, 63, 35, 0, 0, // Skip to: 3989
/* 3954 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3957 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 3973
/* 3962 */    MCD_OPC_CheckField, 7, 1, 0, 128, 28, 0, // Skip to: 11265
/* 3969 */    MCD_OPC_Decode, 151, 7, 15, // Opcode: SAT_H_rr
/* 3973 */    MCD_OPC_FilterValue, 4, 119, 28, 0, // Skip to: 11265
/* 3978 */    MCD_OPC_CheckField, 7, 1, 0, 112, 28, 0, // Skip to: 11265
/* 3985 */    MCD_OPC_Decode, 149, 7, 15, // Opcode: SAT_HU_rr
/* 3989 */    MCD_OPC_FilterValue, 64, 35, 0, 0, // Skip to: 4029
/* 3994 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3997 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4013
/* 4002 */    MCD_OPC_CheckField, 7, 1, 0, 88, 28, 0, // Skip to: 11265
/* 4009 */    MCD_OPC_Decode, 218, 5, 15, // Opcode: MOV_rrEcDb
/* 4013 */    MCD_OPC_FilterValue, 4, 79, 28, 0, // Skip to: 11265
/* 4018 */    MCD_OPC_CheckField, 7, 1, 0, 72, 28, 0, // Skip to: 11265
/* 4025 */    MCD_OPC_Decode, 217, 5, 15, // Opcode: MOV_rrEcDaDb
/* 4029 */    MCD_OPC_FilterValue, 72, 18, 0, 0, // Skip to: 4052
/* 4034 */    MCD_OPC_CheckField, 18, 3, 0, 56, 28, 0, // Skip to: 11265
/* 4041 */    MCD_OPC_CheckField, 7, 1, 0, 49, 28, 0, // Skip to: 11265
/* 4048 */    MCD_OPC_Decode, 149, 3, 15, // Opcode: EQ_W_rr
/* 4052 */    MCD_OPC_FilterValue, 73, 35, 0, 0, // Skip to: 4092
/* 4057 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4060 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4076
/* 4065 */    MCD_OPC_CheckField, 7, 1, 0, 25, 28, 0, // Skip to: 11265
/* 4072 */    MCD_OPC_Decode, 220, 4, 15, // Opcode: LT_W
/* 4076 */    MCD_OPC_FilterValue, 4, 16, 28, 0, // Skip to: 11265
/* 4081 */    MCD_OPC_CheckField, 7, 1, 0, 9, 28, 0, // Skip to: 11265
/* 4088 */    MCD_OPC_Decode, 221, 4, 15, // Opcode: LT_WU
/* 4092 */    MCD_OPC_FilterValue, 86, 11, 0, 0, // Skip to: 4108
/* 4097 */    MCD_OPC_CheckField, 7, 1, 1, 249, 27, 0, // Skip to: 11265
/* 4104 */    MCD_OPC_Decode, 141, 3, 22, // Opcode: EQANY_B_rc
/* 4108 */    MCD_OPC_FilterValue, 118, 240, 27, 0, // Skip to: 11265
/* 4113 */    MCD_OPC_CheckField, 7, 1, 1, 233, 27, 0, // Skip to: 11265
/* 4120 */    MCD_OPC_Decode, 143, 3, 22, // Opcode: EQANY_H_rc
/* 4124 */    MCD_OPC_FilterValue, 13, 7, 1, 0, // Skip to: 4392
/* 4129 */    MCD_OPC_ExtractField, 12, 20,  // Inst{31-12} ...
/* 4132 */    MCD_OPC_FilterValue, 128, 32, 11, 0, 0, // Skip to: 4149
/* 4138 */    MCD_OPC_CheckField, 7, 1, 0, 208, 27, 0, // Skip to: 11265
/* 4145 */    MCD_OPC_Decode, 250, 2, 14, // Opcode: DEBUG_sys
/* 4149 */    MCD_OPC_FilterValue, 128, 40, 11, 0, 0, // Skip to: 4166
/* 4155 */    MCD_OPC_CheckField, 7, 1, 0, 191, 27, 0, // Skip to: 11265
/* 4162 */    MCD_OPC_Decode, 138, 7, 14, // Opcode: RFM_sys
/* 4166 */    MCD_OPC_FilterValue, 128, 48, 11, 0, 0, // Skip to: 4183
/* 4172 */    MCD_OPC_CheckField, 7, 1, 0, 174, 27, 0, // Skip to: 11265
/* 4179 */    MCD_OPC_Decode, 135, 7, 14, // Opcode: RET_sys
/* 4183 */    MCD_OPC_FilterValue, 128, 56, 11, 0, 0, // Skip to: 4200
/* 4189 */    MCD_OPC_CheckField, 7, 1, 0, 157, 27, 0, // Skip to: 11265
/* 4196 */    MCD_OPC_Decode, 137, 7, 14, // Opcode: RFE_sys
/* 4200 */    MCD_OPC_FilterValue, 128, 64, 11, 0, 0, // Skip to: 4217
/* 4206 */    MCD_OPC_CheckField, 7, 1, 0, 140, 27, 0, // Skip to: 11265
/* 4213 */    MCD_OPC_Decode, 146, 8, 14, // Opcode: SVLCX_sys
/* 4217 */    MCD_OPC_FilterValue, 128, 72, 11, 0, 0, // Skip to: 4234
/* 4223 */    MCD_OPC_CheckField, 7, 1, 0, 123, 27, 0, // Skip to: 11265
/* 4230 */    MCD_OPC_Decode, 139, 7, 14, // Opcode: RSLCX_sys
/* 4234 */    MCD_OPC_FilterValue, 128, 96, 11, 0, 0, // Skip to: 4251
/* 4240 */    MCD_OPC_CheckField, 7, 1, 0, 106, 27, 0, // Skip to: 11265
/* 4247 */    MCD_OPC_Decode, 140, 3, 14, // Opcode: ENABLE_sys
/* 4251 */    MCD_OPC_FilterValue, 128, 104, 11, 0, 0, // Skip to: 4268
/* 4257 */    MCD_OPC_CheckField, 7, 1, 0, 89, 27, 0, // Skip to: 11265
/* 4264 */    MCD_OPC_Decode, 253, 2, 14, // Opcode: DISABLE_sys
/* 4268 */    MCD_OPC_FilterValue, 128, 112, 11, 0, 0, // Skip to: 4285
/* 4274 */    MCD_OPC_CheckField, 7, 1, 0, 72, 27, 0, // Skip to: 11265
/* 4281 */    MCD_OPC_Decode, 133, 7, 14, // Opcode: RESTORE_sys
/* 4285 */    MCD_OPC_FilterValue, 128, 120, 11, 0, 0, // Skip to: 4302
/* 4291 */    MCD_OPC_CheckField, 7, 1, 0, 55, 27, 0, // Skip to: 11265
/* 4298 */    MCD_OPC_Decode, 254, 2, 14, // Opcode: DISABLE_sys_1
/* 4302 */    MCD_OPC_FilterValue, 128, 144, 1, 11, 0, 0, // Skip to: 4320
/* 4309 */    MCD_OPC_CheckField, 7, 1, 0, 37, 27, 0, // Skip to: 11265
/* 4316 */    MCD_OPC_Decode, 130, 3, 14, // Opcode: DSYNC_sys
/* 4320 */    MCD_OPC_FilterValue, 128, 152, 1, 11, 0, 0, // Skip to: 4338
/* 4327 */    MCD_OPC_CheckField, 7, 1, 0, 19, 27, 0, // Skip to: 11265
/* 4334 */    MCD_OPC_Decode, 190, 3, 14, // Opcode: ISYNC_sys
/* 4338 */    MCD_OPC_FilterValue, 128, 160, 1, 11, 0, 0, // Skip to: 4356
/* 4345 */    MCD_OPC_CheckField, 7, 1, 0, 1, 27, 0, // Skip to: 11265
/* 4352 */    MCD_OPC_Decode, 160, 8, 14, // Opcode: TRAPV_sys
/* 4356 */    MCD_OPC_FilterValue, 128, 168, 1, 11, 0, 0, // Skip to: 4374
/* 4363 */    MCD_OPC_CheckField, 7, 1, 0, 239, 26, 0, // Skip to: 11265
/* 4370 */    MCD_OPC_Decode, 159, 8, 14, // Opcode: TRAPSV_sys
/* 4374 */    MCD_OPC_FilterValue, 128, 176, 1, 228, 26, 0, // Skip to: 11265
/* 4381 */    MCD_OPC_CheckField, 7, 1, 0, 221, 26, 0, // Skip to: 11265
/* 4388 */    MCD_OPC_Decode, 164, 8, 14, // Opcode: WAIT_sys
/* 4392 */    MCD_OPC_FilterValue, 15, 53, 2, 0, // Skip to: 4962
/* 4397 */    MCD_OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 4400 */    MCD_OPC_FilterValue, 0, 38, 0, 0, // Skip to: 4443
/* 4405 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 4408 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 4434
/* 4413 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4416 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 4425
/* 4421 */    MCD_OPC_Decode, 188, 7, 15, // Opcode: SH_rr
/* 4425 */    MCD_OPC_FilterValue, 4, 179, 26, 0, // Skip to: 11265
/* 4430 */    MCD_OPC_Decode, 162, 7, 15, // Opcode: SHA_rr
/* 4434 */    MCD_OPC_FilterValue, 1, 170, 26, 0, // Skip to: 11265
/* 4439 */    MCD_OPC_Decode, 187, 7, 22, // Opcode: SH_rc
/* 4443 */    MCD_OPC_FilterValue, 1, 28, 0, 0, // Skip to: 4476
/* 4448 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 4451 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4467
/* 4456 */    MCD_OPC_CheckField, 18, 3, 0, 146, 26, 0, // Skip to: 11265
/* 4463 */    MCD_OPC_Decode, 158, 7, 15, // Opcode: SHAS_rr
/* 4467 */    MCD_OPC_FilterValue, 1, 137, 26, 0, // Skip to: 11265
/* 4472 */    MCD_OPC_Decode, 161, 7, 22, // Opcode: SHA_rc
/* 4476 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 4492
/* 4481 */    MCD_OPC_CheckField, 7, 1, 1, 121, 26, 0, // Skip to: 11265
/* 4488 */    MCD_OPC_Decode, 157, 7, 22, // Opcode: SHAS_rc
/* 4492 */    MCD_OPC_FilterValue, 4, 35, 0, 0, // Skip to: 4532
/* 4497 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4500 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4516
/* 4505 */    MCD_OPC_CheckField, 7, 1, 0, 97, 26, 0, // Skip to: 11265
/* 4512 */    MCD_OPC_Decode, 184, 2, 15, // Opcode: AND_rr
/* 4516 */    MCD_OPC_FilterValue, 4, 88, 26, 0, // Skip to: 11265
/* 4521 */    MCD_OPC_CheckField, 7, 1, 0, 81, 26, 0, // Skip to: 11265
/* 4528 */    MCD_OPC_Decode, 221, 6, 15, // Opcode: NAND_rr
/* 4532 */    MCD_OPC_FilterValue, 5, 35, 0, 0, // Skip to: 4572
/* 4537 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4540 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4556
/* 4545 */    MCD_OPC_CheckField, 7, 1, 0, 57, 26, 0, // Skip to: 11265
/* 4552 */    MCD_OPC_Decode, 253, 6, 15, // Opcode: OR_rr
/* 4556 */    MCD_OPC_FilterValue, 4, 48, 26, 0, // Skip to: 11265
/* 4561 */    MCD_OPC_CheckField, 7, 1, 0, 41, 26, 0, // Skip to: 11265
/* 4568 */    MCD_OPC_Decode, 230, 6, 15, // Opcode: NOR_rr
/* 4572 */    MCD_OPC_FilterValue, 6, 35, 0, 0, // Skip to: 4612
/* 4577 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4580 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4596
/* 4585 */    MCD_OPC_CheckField, 7, 1, 0, 17, 26, 0, // Skip to: 11265
/* 4592 */    MCD_OPC_Decode, 182, 8, 15, // Opcode: XOR_rr
/* 4596 */    MCD_OPC_FilterValue, 4, 8, 26, 0, // Skip to: 11265
/* 4601 */    MCD_OPC_CheckField, 7, 1, 0, 1, 26, 0, // Skip to: 11265
/* 4608 */    MCD_OPC_Decode, 167, 8, 15, // Opcode: XNOR_rr
/* 4612 */    MCD_OPC_FilterValue, 7, 38, 0, 0, // Skip to: 4655
/* 4617 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 4620 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 4646
/* 4625 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4628 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 4637
/* 4633 */    MCD_OPC_Decode, 165, 2, 15, // Opcode: ANDN_rr
/* 4637 */    MCD_OPC_FilterValue, 4, 223, 25, 0, // Skip to: 11265
/* 4642 */    MCD_OPC_Decode, 234, 6, 15, // Opcode: ORN_rr
/* 4646 */    MCD_OPC_FilterValue, 1, 214, 25, 0, // Skip to: 11265
/* 4651 */    MCD_OPC_Decode, 164, 7, 22, // Opcode: SHUFFLE_rc
/* 4655 */    MCD_OPC_FilterValue, 8, 11, 0, 0, // Skip to: 4671
/* 4660 */    MCD_OPC_CheckField, 7, 1, 1, 198, 25, 0, // Skip to: 11265
/* 4667 */    MCD_OPC_Decode, 183, 2, 22, // Opcode: AND_rc
/* 4671 */    MCD_OPC_FilterValue, 9, 11, 0, 0, // Skip to: 4687
/* 4676 */    MCD_OPC_CheckField, 7, 1, 1, 182, 25, 0, // Skip to: 11265
/* 4683 */    MCD_OPC_Decode, 220, 6, 22, // Opcode: NAND_rc
/* 4687 */    MCD_OPC_FilterValue, 10, 11, 0, 0, // Skip to: 4703
/* 4692 */    MCD_OPC_CheckField, 7, 1, 1, 166, 25, 0, // Skip to: 11265
/* 4699 */    MCD_OPC_Decode, 252, 6, 22, // Opcode: OR_rc
/* 4703 */    MCD_OPC_FilterValue, 11, 11, 0, 0, // Skip to: 4719
/* 4708 */    MCD_OPC_CheckField, 7, 1, 1, 150, 25, 0, // Skip to: 11265
/* 4715 */    MCD_OPC_Decode, 229, 6, 22, // Opcode: NOR_rc
/* 4719 */    MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 4735
/* 4724 */    MCD_OPC_CheckField, 7, 1, 1, 134, 25, 0, // Skip to: 11265
/* 4731 */    MCD_OPC_Decode, 181, 8, 22, // Opcode: XOR_rc
/* 4735 */    MCD_OPC_FilterValue, 13, 28, 0, 0, // Skip to: 4768
/* 4740 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 4743 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4759
/* 4748 */    MCD_OPC_CheckField, 18, 3, 4, 110, 25, 0, // Skip to: 11265
/* 4755 */    MCD_OPC_Decode, 232, 2, 15, // Opcode: CLZ_rr
/* 4759 */    MCD_OPC_FilterValue, 1, 101, 25, 0, // Skip to: 11265
/* 4764 */    MCD_OPC_Decode, 166, 8, 22, // Opcode: XNOR_rc
/* 4768 */    MCD_OPC_FilterValue, 14, 38, 0, 0, // Skip to: 4811
/* 4773 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 4776 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 4802
/* 4781 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4784 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 4793
/* 4789 */    MCD_OPC_Decode, 228, 2, 15, // Opcode: CLO_rr
/* 4793 */    MCD_OPC_FilterValue, 4, 67, 25, 0, // Skip to: 11265
/* 4798 */    MCD_OPC_Decode, 230, 2, 15, // Opcode: CLS_rr
/* 4802 */    MCD_OPC_FilterValue, 1, 58, 25, 0, // Skip to: 11265
/* 4807 */    MCD_OPC_Decode, 164, 2, 22, // Opcode: ANDN_rc
/* 4811 */    MCD_OPC_FilterValue, 15, 11, 0, 0, // Skip to: 4827
/* 4816 */    MCD_OPC_CheckField, 7, 1, 1, 42, 25, 0, // Skip to: 11265
/* 4823 */    MCD_OPC_Decode, 233, 6, 22, // Opcode: ORN_rc
/* 4827 */    MCD_OPC_FilterValue, 32, 35, 0, 0, // Skip to: 4867
/* 4832 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4835 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4851
/* 4840 */    MCD_OPC_CheckField, 7, 1, 0, 18, 25, 0, // Skip to: 11265
/* 4847 */    MCD_OPC_Decode, 174, 7, 15, // Opcode: SH_H_rr
/* 4851 */    MCD_OPC_FilterValue, 4, 9, 25, 0, // Skip to: 11265
/* 4856 */    MCD_OPC_CheckField, 7, 1, 0, 2, 25, 0, // Skip to: 11265
/* 4863 */    MCD_OPC_Decode, 160, 7, 15, // Opcode: SHA_H_rr
/* 4867 */    MCD_OPC_FilterValue, 62, 35, 0, 0, // Skip to: 4907
/* 4872 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 4875 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 4891
/* 4880 */    MCD_OPC_CheckField, 7, 1, 0, 234, 24, 0, // Skip to: 11265
/* 4887 */    MCD_OPC_Decode, 231, 2, 15, // Opcode: CLZ_H_rr
/* 4891 */    MCD_OPC_FilterValue, 4, 225, 24, 0, // Skip to: 11265
/* 4896 */    MCD_OPC_CheckField, 7, 1, 0, 218, 24, 0, // Skip to: 11265
/* 4903 */    MCD_OPC_Decode, 227, 2, 15, // Opcode: CLO_H_rr
/* 4907 */    MCD_OPC_FilterValue, 63, 18, 0, 0, // Skip to: 4930
/* 4912 */    MCD_OPC_CheckField, 18, 3, 0, 202, 24, 0, // Skip to: 11265
/* 4919 */    MCD_OPC_CheckField, 7, 1, 0, 195, 24, 0, // Skip to: 11265
/* 4926 */    MCD_OPC_Decode, 229, 2, 15, // Opcode: CLS_H_rr
/* 4930 */    MCD_OPC_FilterValue, 64, 11, 0, 0, // Skip to: 4946
/* 4935 */    MCD_OPC_CheckField, 7, 1, 1, 179, 24, 0, // Skip to: 11265
/* 4942 */    MCD_OPC_Decode, 173, 7, 22, // Opcode: SH_H_rc
/* 4946 */    MCD_OPC_FilterValue, 65, 170, 24, 0, // Skip to: 11265
/* 4951 */    MCD_OPC_CheckField, 7, 1, 1, 163, 24, 0, // Skip to: 11265
/* 4958 */    MCD_OPC_Decode, 159, 7, 22, // Opcode: SHA_H_rc
/* 4962 */    MCD_OPC_FilterValue, 17, 21, 0, 0, // Skip to: 4988
/* 4967 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 4970 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 4979
/* 4975 */    MCD_OPC_Decode, 134, 2, 23, // Opcode: ADDIH_A_rlc
/* 4979 */    MCD_OPC_FilterValue, 1, 137, 24, 0, // Skip to: 11265
/* 4984 */    MCD_OPC_Decode, 204, 5, 23, // Opcode: MOVH_A_rlc
/* 4988 */    MCD_OPC_FilterValue, 19, 85, 1, 0, // Skip to: 5334
/* 4993 */    MCD_OPC_ExtractField, 21, 3,  // Inst{23-21} ...
/* 4996 */    MCD_OPC_FilterValue, 0, 164, 0, 0, // Skip to: 5165
/* 5001 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 5004 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 5027
/* 5009 */    MCD_OPC_CheckField, 24, 4, 0, 105, 24, 0, // Skip to: 11265
/* 5016 */    MCD_OPC_CheckField, 7, 1, 1, 98, 24, 0, // Skip to: 11265
/* 5023 */    MCD_OPC_Decode, 208, 6, 24, // Opcode: MUL_Q_rr1_2_U
/* 5027 */    MCD_OPC_FilterValue, 1, 18, 0, 0, // Skip to: 5050
/* 5032 */    MCD_OPC_CheckField, 24, 4, 0, 82, 24, 0, // Skip to: 11265
/* 5039 */    MCD_OPC_CheckField, 7, 1, 1, 75, 24, 0, // Skip to: 11265
/* 5046 */    MCD_OPC_Decode, 206, 6, 24, // Opcode: MUL_Q_rr1_2_L
/* 5050 */    MCD_OPC_FilterValue, 2, 18, 0, 0, // Skip to: 5073
/* 5055 */    MCD_OPC_CheckField, 24, 4, 0, 59, 24, 0, // Skip to: 11265
/* 5062 */    MCD_OPC_CheckField, 7, 1, 1, 52, 24, 0, // Skip to: 11265
/* 5069 */    MCD_OPC_Decode, 210, 6, 24, // Opcode: MUL_Q_rr1_2__
/* 5073 */    MCD_OPC_FilterValue, 4, 18, 0, 0, // Skip to: 5096
/* 5078 */    MCD_OPC_CheckField, 24, 4, 0, 36, 24, 0, // Skip to: 11265
/* 5085 */    MCD_OPC_CheckField, 7, 1, 1, 29, 24, 0, // Skip to: 11265
/* 5092 */    MCD_OPC_Decode, 205, 6, 24, // Opcode: MUL_Q_rr1_2UU
/* 5096 */    MCD_OPC_FilterValue, 5, 18, 0, 0, // Skip to: 5119
/* 5101 */    MCD_OPC_CheckField, 24, 4, 0, 13, 24, 0, // Skip to: 11265
/* 5108 */    MCD_OPC_CheckField, 7, 1, 1, 6, 24, 0, // Skip to: 11265
/* 5115 */    MCD_OPC_Decode, 204, 6, 24, // Opcode: MUL_Q_rr1_2LL
/* 5119 */    MCD_OPC_FilterValue, 6, 18, 0, 0, // Skip to: 5142
/* 5124 */    MCD_OPC_CheckField, 24, 4, 0, 246, 23, 0, // Skip to: 11265
/* 5131 */    MCD_OPC_CheckField, 7, 1, 1, 239, 23, 0, // Skip to: 11265
/* 5138 */    MCD_OPC_Decode, 194, 6, 24, // Opcode: MULR_Q_rr1_2UU
/* 5142 */    MCD_OPC_FilterValue, 7, 230, 23, 0, // Skip to: 11265
/* 5147 */    MCD_OPC_CheckField, 24, 4, 0, 223, 23, 0, // Skip to: 11265
/* 5154 */    MCD_OPC_CheckField, 7, 1, 1, 216, 23, 0, // Skip to: 11265
/* 5161 */    MCD_OPC_Decode, 193, 6, 24, // Opcode: MULR_Q_rr1_2LL
/* 5165 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 5181
/* 5170 */    MCD_OPC_CheckField, 7, 1, 0, 200, 23, 0, // Skip to: 11265
/* 5177 */    MCD_OPC_Decode, 183, 5, 25, // Opcode: MADD_rcr
/* 5181 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 5197
/* 5186 */    MCD_OPC_CheckField, 7, 1, 0, 184, 23, 0, // Skip to: 11265
/* 5193 */    MCD_OPC_Decode, 181, 5, 25, // Opcode: MADD_U_rcr
/* 5197 */    MCD_OPC_FilterValue, 3, 68, 0, 0, // Skip to: 5270
/* 5202 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 5205 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5214
/* 5210 */    MCD_OPC_Decode, 184, 5, 25, // Opcode: MADD_rcr_e
/* 5214 */    MCD_OPC_FilterValue, 1, 158, 23, 0, // Skip to: 11265
/* 5219 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 5222 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 5238
/* 5227 */    MCD_OPC_CheckField, 24, 4, 0, 143, 23, 0, // Skip to: 11265
/* 5234 */    MCD_OPC_Decode, 209, 6, 24, // Opcode: MUL_Q_rr1_2_Ue
/* 5238 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 5254
/* 5243 */    MCD_OPC_CheckField, 24, 4, 0, 127, 23, 0, // Skip to: 11265
/* 5250 */    MCD_OPC_Decode, 207, 6, 24, // Opcode: MUL_Q_rr1_2_Le
/* 5254 */    MCD_OPC_FilterValue, 3, 118, 23, 0, // Skip to: 11265
/* 5259 */    MCD_OPC_CheckField, 24, 4, 0, 111, 23, 0, // Skip to: 11265
/* 5266 */    MCD_OPC_Decode, 211, 6, 24, // Opcode: MUL_Q_rr1_2__e
/* 5270 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 5286
/* 5275 */    MCD_OPC_CheckField, 7, 1, 0, 95, 23, 0, // Skip to: 11265
/* 5282 */    MCD_OPC_Decode, 158, 5, 25, // Opcode: MADDS_U_rcr
/* 5286 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 5302
/* 5291 */    MCD_OPC_CheckField, 7, 1, 0, 79, 23, 0, // Skip to: 11265
/* 5298 */    MCD_OPC_Decode, 162, 5, 25, // Opcode: MADDS_rcr
/* 5302 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 5318
/* 5307 */    MCD_OPC_CheckField, 7, 1, 0, 63, 23, 0, // Skip to: 11265
/* 5314 */    MCD_OPC_Decode, 159, 5, 25, // Opcode: MADDS_U_rcr_e
/* 5318 */    MCD_OPC_FilterValue, 7, 54, 23, 0, // Skip to: 11265
/* 5323 */    MCD_OPC_CheckField, 7, 1, 0, 47, 23, 0, // Skip to: 11265
/* 5330 */    MCD_OPC_Decode, 163, 5, 25, // Opcode: MADDS_rcr_e
/* 5334 */    MCD_OPC_FilterValue, 21, 67, 0, 0, // Skip to: 5406
/* 5339 */    MCD_OPC_ExtractField, 26, 2,  // Inst{27-26} ...
/* 5342 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 5358
/* 5347 */    MCD_OPC_CheckField, 7, 1, 0, 23, 23, 0, // Skip to: 11265
/* 5354 */    MCD_OPC_Decode, 190, 7, 18, // Opcode: STLCX_abs
/* 5358 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 5374
/* 5363 */    MCD_OPC_CheckField, 7, 1, 0, 7, 23, 0, // Skip to: 11265
/* 5370 */    MCD_OPC_Decode, 192, 7, 18, // Opcode: STUCX_abs
/* 5374 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 5390
/* 5379 */    MCD_OPC_CheckField, 7, 1, 0, 247, 22, 0, // Skip to: 11265
/* 5386 */    MCD_OPC_Decode, 246, 3, 18, // Opcode: LDLCX_abs
/* 5390 */    MCD_OPC_FilterValue, 3, 238, 22, 0, // Skip to: 11265
/* 5395 */    MCD_OPC_CheckField, 7, 1, 0, 231, 22, 0, // Skip to: 11265
/* 5402 */    MCD_OPC_Decode, 254, 3, 18, // Opcode: LDUCX_abs
/* 5406 */    MCD_OPC_FilterValue, 23, 105, 0, 0, // Skip to: 5516
/* 5411 */    MCD_OPC_ExtractField, 21, 3,  // Inst{23-21} ...
/* 5414 */    MCD_OPC_FilterValue, 0, 28, 0, 0, // Skip to: 5447
/* 5419 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 5422 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5431
/* 5427 */    MCD_OPC_Decode, 186, 3, 26, // Opcode: INSERT_rrrr
/* 5431 */    MCD_OPC_FilterValue, 1, 197, 22, 0, // Skip to: 11265
/* 5436 */    MCD_OPC_CheckField, 16, 5, 0, 190, 22, 0, // Skip to: 11265
/* 5443 */    MCD_OPC_Decode, 183, 3, 27, // Opcode: INSERT_rcrr
/* 5447 */    MCD_OPC_FilterValue, 2, 18, 0, 0, // Skip to: 5470
/* 5452 */    MCD_OPC_CheckField, 16, 5, 0, 174, 22, 0, // Skip to: 11265
/* 5459 */    MCD_OPC_CheckField, 7, 1, 0, 167, 22, 0, // Skip to: 11265
/* 5466 */    MCD_OPC_Decode, 158, 3, 28, // Opcode: EXTR_rrrr
/* 5470 */    MCD_OPC_FilterValue, 3, 18, 0, 0, // Skip to: 5493
/* 5475 */    MCD_OPC_CheckField, 16, 5, 0, 151, 22, 0, // Skip to: 11265
/* 5482 */    MCD_OPC_CheckField, 7, 1, 0, 144, 22, 0, // Skip to: 11265
/* 5489 */    MCD_OPC_Decode, 155, 3, 28, // Opcode: EXTR_U_rrrr
/* 5493 */    MCD_OPC_FilterValue, 4, 135, 22, 0, // Skip to: 11265
/* 5498 */    MCD_OPC_CheckField, 16, 5, 0, 128, 22, 0, // Skip to: 11265
/* 5505 */    MCD_OPC_CheckField, 7, 1, 0, 121, 22, 0, // Skip to: 11265
/* 5512 */    MCD_OPC_Decode, 252, 2, 28, // Opcode: DEXTR_rrrr
/* 5516 */    MCD_OPC_FilterValue, 25, 21, 0, 0, // Skip to: 5542
/* 5521 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 5524 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5533
/* 5529 */    MCD_OPC_Decode, 200, 4, 29, // Opcode: LD_W_bol
/* 5533 */    MCD_OPC_FilterValue, 1, 95, 22, 0, // Skip to: 11265
/* 5538 */    MCD_OPC_Decode, 134, 4, 29, // Opcode: LD_A_bol
/* 5542 */    MCD_OPC_FilterValue, 27, 21, 0, 0, // Skip to: 5568
/* 5547 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 5550 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5559
/* 5555 */    MCD_OPC_Decode, 136, 2, 23, // Opcode: ADDI_rlc
/* 5559 */    MCD_OPC_FilterValue, 1, 69, 22, 0, // Skip to: 11265
/* 5564 */    MCD_OPC_Decode, 135, 2, 23, // Opcode: ADDIH_rlc
/* 5568 */    MCD_OPC_FilterValue, 29, 21, 0, 0, // Skip to: 5594
/* 5573 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 5576 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5585
/* 5581 */    MCD_OPC_Decode, 244, 3, 30, // Opcode: J_b
/* 5585 */    MCD_OPC_FilterValue, 1, 43, 22, 0, // Skip to: 11265
/* 5590 */    MCD_OPC_Decode, 196, 3, 30, // Opcode: JA_b
/* 5594 */    MCD_OPC_FilterValue, 31, 55, 0, 0, // Skip to: 5654
/* 5599 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 5602 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 5628
/* 5607 */    MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 5610 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5619
/* 5615 */    MCD_OPC_Decode, 224, 3, 31, // Opcode: JNEI_brr
/* 5619 */    MCD_OPC_FilterValue, 1, 9, 22, 0, // Skip to: 11265
/* 5624 */    MCD_OPC_Decode, 222, 3, 31, // Opcode: JNED_brr
/* 5628 */    MCD_OPC_FilterValue, 1, 0, 22, 0, // Skip to: 11265
/* 5633 */    MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 5636 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5645
/* 5641 */    MCD_OPC_Decode, 223, 3, 32, // Opcode: JNEI_brc
/* 5645 */    MCD_OPC_FilterValue, 1, 239, 21, 0, // Skip to: 11265
/* 5650 */    MCD_OPC_Decode, 221, 3, 32, // Opcode: JNED_brc
/* 5654 */    MCD_OPC_FilterValue, 35, 248, 1, 0, // Skip to: 6163
/* 5659 */    MCD_OPC_ExtractField, 18, 6,  // Inst{23-18} ...
/* 5662 */    MCD_OPC_FilterValue, 2, 18, 0, 0, // Skip to: 5685
/* 5667 */    MCD_OPC_CheckField, 16, 2, 2, 215, 21, 0, // Skip to: 11265
/* 5674 */    MCD_OPC_CheckField, 7, 1, 0, 208, 21, 0, // Skip to: 11265
/* 5681 */    MCD_OPC_Decode, 182, 6, 16, // Opcode: MSUB_rrr2
/* 5685 */    MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 5701
/* 5690 */    MCD_OPC_CheckField, 7, 1, 1, 192, 21, 0, // Skip to: 11265
/* 5697 */    MCD_OPC_Decode, 137, 6, 17, // Opcode: MSUBR_H_rrr1_UL
/* 5701 */    MCD_OPC_FilterValue, 13, 11, 0, 0, // Skip to: 5717
/* 5706 */    MCD_OPC_CheckField, 7, 1, 1, 176, 21, 0, // Skip to: 11265
/* 5713 */    MCD_OPC_Decode, 136, 6, 17, // Opcode: MSUBR_H_rrr1_LU
/* 5717 */    MCD_OPC_FilterValue, 14, 11, 0, 0, // Skip to: 5733
/* 5722 */    MCD_OPC_CheckField, 7, 1, 1, 160, 21, 0, // Skip to: 11265
/* 5729 */    MCD_OPC_Decode, 135, 6, 17, // Opcode: MSUBR_H_rrr1_LL
/* 5733 */    MCD_OPC_FilterValue, 15, 11, 0, 0, // Skip to: 5749
/* 5738 */    MCD_OPC_CheckField, 7, 1, 1, 144, 21, 0, // Skip to: 11265
/* 5745 */    MCD_OPC_Decode, 138, 6, 17, // Opcode: MSUBR_H_rrr1_UU
/* 5749 */    MCD_OPC_FilterValue, 24, 11, 0, 0, // Skip to: 5765
/* 5754 */    MCD_OPC_CheckField, 7, 1, 1, 128, 21, 0, // Skip to: 11265
/* 5761 */    MCD_OPC_Decode, 166, 6, 17, // Opcode: MSUB_H_rrr1_UL
/* 5765 */    MCD_OPC_FilterValue, 25, 11, 0, 0, // Skip to: 5781
/* 5770 */    MCD_OPC_CheckField, 7, 1, 1, 112, 21, 0, // Skip to: 11265
/* 5777 */    MCD_OPC_Decode, 165, 6, 17, // Opcode: MSUB_H_rrr1_LU
/* 5781 */    MCD_OPC_FilterValue, 26, 38, 0, 0, // Skip to: 5824
/* 5786 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 5789 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 5815
/* 5794 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 5797 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 5806
/* 5802 */    MCD_OPC_Decode, 179, 6, 16, // Opcode: MSUB_U_rrr2
/* 5806 */    MCD_OPC_FilterValue, 2, 78, 21, 0, // Skip to: 11265
/* 5811 */    MCD_OPC_Decode, 183, 6, 16, // Opcode: MSUB_rrr2_e
/* 5815 */    MCD_OPC_FilterValue, 1, 69, 21, 0, // Skip to: 11265
/* 5820 */    MCD_OPC_Decode, 164, 6, 17, // Opcode: MSUB_H_rrr1_LL
/* 5824 */    MCD_OPC_FilterValue, 27, 11, 0, 0, // Skip to: 5840
/* 5829 */    MCD_OPC_CheckField, 7, 1, 1, 53, 21, 0, // Skip to: 11265
/* 5836 */    MCD_OPC_Decode, 167, 6, 17, // Opcode: MSUB_H_rrr1_UU
/* 5840 */    MCD_OPC_FilterValue, 28, 11, 0, 0, // Skip to: 5856
/* 5845 */    MCD_OPC_CheckField, 7, 1, 1, 37, 21, 0, // Skip to: 11265
/* 5852 */    MCD_OPC_Decode, 253, 5, 17, // Opcode: MSUBM_H_rrr1_UL
/* 5856 */    MCD_OPC_FilterValue, 29, 11, 0, 0, // Skip to: 5872
/* 5861 */    MCD_OPC_CheckField, 7, 1, 1, 21, 21, 0, // Skip to: 11265
/* 5868 */    MCD_OPC_Decode, 252, 5, 17, // Opcode: MSUBM_H_rrr1_LU
/* 5872 */    MCD_OPC_FilterValue, 30, 11, 0, 0, // Skip to: 5888
/* 5877 */    MCD_OPC_CheckField, 7, 1, 1, 5, 21, 0, // Skip to: 11265
/* 5884 */    MCD_OPC_Decode, 251, 5, 17, // Opcode: MSUBM_H_rrr1_LL
/* 5888 */    MCD_OPC_FilterValue, 31, 11, 0, 0, // Skip to: 5904
/* 5893 */    MCD_OPC_CheckField, 7, 1, 1, 245, 20, 0, // Skip to: 11265
/* 5900 */    MCD_OPC_Decode, 254, 5, 17, // Opcode: MSUBM_H_rrr1_UU
/* 5904 */    MCD_OPC_FilterValue, 34, 35, 0, 0, // Skip to: 5944
/* 5909 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 5912 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 5928
/* 5917 */    MCD_OPC_CheckField, 7, 1, 0, 221, 20, 0, // Skip to: 11265
/* 5924 */    MCD_OPC_Decode, 157, 6, 16, // Opcode: MSUBS_U_rrr2
/* 5928 */    MCD_OPC_FilterValue, 2, 212, 20, 0, // Skip to: 11265
/* 5933 */    MCD_OPC_CheckField, 7, 1, 0, 205, 20, 0, // Skip to: 11265
/* 5940 */    MCD_OPC_Decode, 161, 6, 16, // Opcode: MSUBS_rrr2
/* 5944 */    MCD_OPC_FilterValue, 44, 11, 0, 0, // Skip to: 5960
/* 5949 */    MCD_OPC_CheckField, 7, 1, 1, 189, 20, 0, // Skip to: 11265
/* 5956 */    MCD_OPC_Decode, 130, 6, 17, // Opcode: MSUBRS_H_rrr1_UL
/* 5960 */    MCD_OPC_FilterValue, 45, 11, 0, 0, // Skip to: 5976
/* 5965 */    MCD_OPC_CheckField, 7, 1, 1, 173, 20, 0, // Skip to: 11265
/* 5972 */    MCD_OPC_Decode, 129, 6, 17, // Opcode: MSUBRS_H_rrr1_LU
/* 5976 */    MCD_OPC_FilterValue, 46, 11, 0, 0, // Skip to: 5992
/* 5981 */    MCD_OPC_CheckField, 7, 1, 1, 157, 20, 0, // Skip to: 11265
/* 5988 */    MCD_OPC_Decode, 128, 6, 17, // Opcode: MSUBRS_H_rrr1_LL
/* 5992 */    MCD_OPC_FilterValue, 47, 11, 0, 0, // Skip to: 6008
/* 5997 */    MCD_OPC_CheckField, 7, 1, 1, 141, 20, 0, // Skip to: 11265
/* 6004 */    MCD_OPC_Decode, 131, 6, 17, // Opcode: MSUBRS_H_rrr1_UU
/* 6008 */    MCD_OPC_FilterValue, 56, 11, 0, 0, // Skip to: 6024
/* 6013 */    MCD_OPC_CheckField, 7, 1, 1, 125, 20, 0, // Skip to: 11265
/* 6020 */    MCD_OPC_Decode, 143, 6, 17, // Opcode: MSUBS_H_rrr1_UL
/* 6024 */    MCD_OPC_FilterValue, 57, 11, 0, 0, // Skip to: 6040
/* 6029 */    MCD_OPC_CheckField, 7, 1, 1, 109, 20, 0, // Skip to: 11265
/* 6036 */    MCD_OPC_Decode, 142, 6, 17, // Opcode: MSUBS_H_rrr1_LU
/* 6040 */    MCD_OPC_FilterValue, 58, 38, 0, 0, // Skip to: 6083
/* 6045 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6048 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 6074
/* 6053 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 6056 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6065
/* 6061 */    MCD_OPC_Decode, 158, 6, 16, // Opcode: MSUBS_U_rrr2_e
/* 6065 */    MCD_OPC_FilterValue, 2, 75, 20, 0, // Skip to: 11265
/* 6070 */    MCD_OPC_Decode, 162, 6, 16, // Opcode: MSUBS_rrr2_e
/* 6074 */    MCD_OPC_FilterValue, 1, 66, 20, 0, // Skip to: 11265
/* 6079 */    MCD_OPC_Decode, 141, 6, 17, // Opcode: MSUBS_H_rrr1_LL
/* 6083 */    MCD_OPC_FilterValue, 59, 11, 0, 0, // Skip to: 6099
/* 6088 */    MCD_OPC_CheckField, 7, 1, 1, 50, 20, 0, // Skip to: 11265
/* 6095 */    MCD_OPC_Decode, 144, 6, 17, // Opcode: MSUBS_H_rrr1_UU
/* 6099 */    MCD_OPC_FilterValue, 60, 11, 0, 0, // Skip to: 6115
/* 6104 */    MCD_OPC_CheckField, 7, 1, 1, 34, 20, 0, // Skip to: 11265
/* 6111 */    MCD_OPC_Decode, 249, 5, 17, // Opcode: MSUBMS_H_rrr1_UL
/* 6115 */    MCD_OPC_FilterValue, 61, 11, 0, 0, // Skip to: 6131
/* 6120 */    MCD_OPC_CheckField, 7, 1, 1, 18, 20, 0, // Skip to: 11265
/* 6127 */    MCD_OPC_Decode, 248, 5, 17, // Opcode: MSUBMS_H_rrr1_LU
/* 6131 */    MCD_OPC_FilterValue, 62, 11, 0, 0, // Skip to: 6147
/* 6136 */    MCD_OPC_CheckField, 7, 1, 1, 2, 20, 0, // Skip to: 11265
/* 6143 */    MCD_OPC_Decode, 247, 5, 17, // Opcode: MSUBMS_H_rrr1_LL
/* 6147 */    MCD_OPC_FilterValue, 63, 249, 19, 0, // Skip to: 11265
/* 6152 */    MCD_OPC_CheckField, 7, 1, 1, 242, 19, 0, // Skip to: 11265
/* 6159 */    MCD_OPC_Decode, 250, 5, 17, // Opcode: MSUBMS_H_rrr1_UU
/* 6163 */    MCD_OPC_FilterValue, 37, 87, 0, 0, // Skip to: 6255
/* 6168 */    MCD_OPC_ExtractField, 26, 2,  // Inst{27-26} ...
/* 6171 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 6197
/* 6176 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6179 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6188
/* 6184 */    MCD_OPC_Decode, 206, 7, 18, // Opcode: ST_B_abs
/* 6188 */    MCD_OPC_FilterValue, 1, 208, 19, 0, // Skip to: 11265
/* 6193 */    MCD_OPC_Decode, 247, 7, 18, // Opcode: ST_W_abs
/* 6197 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 6213
/* 6202 */    MCD_OPC_CheckField, 7, 1, 1, 192, 19, 0, // Skip to: 11265
/* 6209 */    MCD_OPC_Decode, 223, 7, 18, // Opcode: ST_D_abs
/* 6213 */    MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 6239
/* 6218 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6221 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6230
/* 6226 */    MCD_OPC_Decode, 229, 7, 18, // Opcode: ST_H_abs
/* 6230 */    MCD_OPC_FilterValue, 1, 166, 19, 0, // Skip to: 11265
/* 6235 */    MCD_OPC_Decode, 194, 7, 18, // Opcode: ST_A_abs
/* 6239 */    MCD_OPC_FilterValue, 3, 157, 19, 0, // Skip to: 11265
/* 6244 */    MCD_OPC_CheckField, 7, 1, 1, 150, 19, 0, // Skip to: 11265
/* 6251 */    MCD_OPC_Decode, 217, 7, 18, // Opcode: ST_DA_abs
/* 6255 */    MCD_OPC_FilterValue, 39, 107, 0, 0, // Skip to: 6367
/* 6260 */    MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 6263 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 6289
/* 6268 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6271 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6280
/* 6276 */    MCD_OPC_Decode, 166, 7, 19, // Opcode: SH_AND_T
/* 6280 */    MCD_OPC_FilterValue, 1, 116, 19, 0, // Skip to: 11265
/* 6285 */    MCD_OPC_Decode, 179, 7, 19, // Opcode: SH_NAND_T
/* 6289 */    MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 6315
/* 6294 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6297 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6306
/* 6302 */    MCD_OPC_Decode, 184, 7, 19, // Opcode: SH_OR_T
/* 6306 */    MCD_OPC_FilterValue, 1, 90, 19, 0, // Skip to: 11265
/* 6311 */    MCD_OPC_Decode, 183, 7, 19, // Opcode: SH_ORN_T
/* 6315 */    MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 6341
/* 6320 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6323 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6332
/* 6328 */    MCD_OPC_Decode, 182, 7, 19, // Opcode: SH_NOR_T
/* 6332 */    MCD_OPC_FilterValue, 1, 64, 19, 0, // Skip to: 11265
/* 6337 */    MCD_OPC_Decode, 185, 7, 19, // Opcode: SH_XNOR_T
/* 6341 */    MCD_OPC_FilterValue, 3, 55, 19, 0, // Skip to: 11265
/* 6346 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6349 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6358
/* 6354 */    MCD_OPC_Decode, 165, 7, 19, // Opcode: SH_ANDN_T
/* 6358 */    MCD_OPC_FilterValue, 1, 38, 19, 0, // Skip to: 11265
/* 6363 */    MCD_OPC_Decode, 186, 7, 19, // Opcode: SH_XOR_T
/* 6367 */    MCD_OPC_FilterValue, 41, 47, 2, 0, // Skip to: 6931
/* 6372 */    MCD_OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 6375 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 6401
/* 6380 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6383 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6392
/* 6388 */    MCD_OPC_Decode, 156, 4, 20, // Opcode: LD_B_bo_r
/* 6392 */    MCD_OPC_FilterValue, 1, 4, 19, 0, // Skip to: 11265
/* 6397 */    MCD_OPC_Decode, 211, 7, 20, // Opcode: ST_B_bo_r
/* 6401 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 6417
/* 6406 */    MCD_OPC_CheckField, 7, 1, 0, 244, 18, 0, // Skip to: 11265
/* 6413 */    MCD_OPC_Decode, 145, 4, 20, // Opcode: LD_BU_bo_r
/* 6417 */    MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 6443
/* 6422 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6425 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6434
/* 6430 */    MCD_OPC_Decode, 182, 4, 20, // Opcode: LD_H_bo_r
/* 6434 */    MCD_OPC_FilterValue, 1, 218, 18, 0, // Skip to: 11265
/* 6439 */    MCD_OPC_Decode, 234, 7, 20, // Opcode: ST_H_bo_r
/* 6443 */    MCD_OPC_FilterValue, 3, 11, 0, 0, // Skip to: 6459
/* 6448 */    MCD_OPC_CheckField, 7, 1, 0, 202, 18, 0, // Skip to: 11265
/* 6455 */    MCD_OPC_Decode, 175, 4, 20, // Opcode: LD_HU_bo_r
/* 6459 */    MCD_OPC_FilterValue, 4, 21, 0, 0, // Skip to: 6485
/* 6464 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6467 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6476
/* 6472 */    MCD_OPC_Decode, 199, 4, 20, // Opcode: LD_W_bo_r
/* 6476 */    MCD_OPC_FilterValue, 1, 176, 18, 0, // Skip to: 11265
/* 6481 */    MCD_OPC_Decode, 252, 7, 20, // Opcode: ST_W_bo_r
/* 6485 */    MCD_OPC_FilterValue, 5, 21, 0, 0, // Skip to: 6511
/* 6490 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6493 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6502
/* 6498 */    MCD_OPC_Decode, 169, 4, 20, // Opcode: LD_D_bo_r
/* 6502 */    MCD_OPC_FilterValue, 1, 150, 18, 0, // Skip to: 11265
/* 6507 */    MCD_OPC_Decode, 228, 7, 20, // Opcode: ST_D_bo_r
/* 6511 */    MCD_OPC_FilterValue, 6, 21, 0, 0, // Skip to: 6537
/* 6516 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6519 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6528
/* 6524 */    MCD_OPC_Decode, 133, 4, 20, // Opcode: LD_A_bo_r
/* 6528 */    MCD_OPC_FilterValue, 1, 124, 18, 0, // Skip to: 11265
/* 6533 */    MCD_OPC_Decode, 199, 7, 20, // Opcode: ST_A_bo_r
/* 6537 */    MCD_OPC_FilterValue, 7, 21, 0, 0, // Skip to: 6563
/* 6542 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6545 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6554
/* 6550 */    MCD_OPC_Decode, 163, 4, 20, // Opcode: LD_DA_bo_r
/* 6554 */    MCD_OPC_FilterValue, 1, 98, 18, 0, // Skip to: 11265
/* 6559 */    MCD_OPC_Decode, 222, 7, 20, // Opcode: ST_DA_bo_r
/* 6563 */    MCD_OPC_FilterValue, 8, 21, 0, 0, // Skip to: 6589
/* 6568 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6571 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6580
/* 6576 */    MCD_OPC_Decode, 193, 4, 20, // Opcode: LD_Q_bo_r
/* 6580 */    MCD_OPC_FilterValue, 1, 72, 18, 0, // Skip to: 11265
/* 6585 */    MCD_OPC_Decode, 245, 7, 20, // Opcode: ST_Q_bo_r
/* 6589 */    MCD_OPC_FilterValue, 11, 11, 0, 0, // Skip to: 6605
/* 6594 */    MCD_OPC_CheckField, 7, 1, 1, 56, 18, 0, // Skip to: 11265
/* 6601 */    MCD_OPC_Decode, 201, 2, 20, // Opcode: CACHEI_W_bo_r
/* 6605 */    MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 6621
/* 6610 */    MCD_OPC_CheckField, 7, 1, 1, 40, 18, 0, // Skip to: 11265
/* 6617 */    MCD_OPC_Decode, 216, 2, 20, // Opcode: CACHE_W_bo_r
/* 6621 */    MCD_OPC_FilterValue, 13, 11, 0, 0, // Skip to: 6637
/* 6626 */    MCD_OPC_CheckField, 7, 1, 1, 24, 18, 0, // Skip to: 11265
/* 6633 */    MCD_OPC_Decode, 211, 2, 20, // Opcode: CACHE_WI_bo_r
/* 6637 */    MCD_OPC_FilterValue, 14, 11, 0, 0, // Skip to: 6653
/* 6642 */    MCD_OPC_CheckField, 7, 1, 1, 8, 18, 0, // Skip to: 11265
/* 6649 */    MCD_OPC_Decode, 206, 2, 20, // Opcode: CACHE_I_bo_r
/* 6653 */    MCD_OPC_FilterValue, 16, 21, 0, 0, // Skip to: 6679
/* 6658 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6661 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6670
/* 6666 */    MCD_OPC_Decode, 153, 4, 20, // Opcode: LD_B_bo_c
/* 6670 */    MCD_OPC_FilterValue, 1, 238, 17, 0, // Skip to: 11265
/* 6675 */    MCD_OPC_Decode, 208, 7, 20, // Opcode: ST_B_bo_c
/* 6679 */    MCD_OPC_FilterValue, 17, 11, 0, 0, // Skip to: 6695
/* 6684 */    MCD_OPC_CheckField, 7, 1, 0, 222, 17, 0, // Skip to: 11265
/* 6691 */    MCD_OPC_Decode, 142, 4, 20, // Opcode: LD_BU_bo_c
/* 6695 */    MCD_OPC_FilterValue, 18, 21, 0, 0, // Skip to: 6721
/* 6700 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6703 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6712
/* 6708 */    MCD_OPC_Decode, 179, 4, 20, // Opcode: LD_H_bo_c
/* 6712 */    MCD_OPC_FilterValue, 1, 196, 17, 0, // Skip to: 11265
/* 6717 */    MCD_OPC_Decode, 231, 7, 20, // Opcode: ST_H_bo_c
/* 6721 */    MCD_OPC_FilterValue, 19, 11, 0, 0, // Skip to: 6737
/* 6726 */    MCD_OPC_CheckField, 7, 1, 0, 180, 17, 0, // Skip to: 11265
/* 6733 */    MCD_OPC_Decode, 172, 4, 20, // Opcode: LD_HU_bo_c
/* 6737 */    MCD_OPC_FilterValue, 20, 21, 0, 0, // Skip to: 6763
/* 6742 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6745 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6754
/* 6750 */    MCD_OPC_Decode, 196, 4, 20, // Opcode: LD_W_bo_c
/* 6754 */    MCD_OPC_FilterValue, 1, 154, 17, 0, // Skip to: 11265
/* 6759 */    MCD_OPC_Decode, 249, 7, 20, // Opcode: ST_W_bo_c
/* 6763 */    MCD_OPC_FilterValue, 21, 21, 0, 0, // Skip to: 6789
/* 6768 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6771 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6780
/* 6776 */    MCD_OPC_Decode, 166, 4, 20, // Opcode: LD_D_bo_c
/* 6780 */    MCD_OPC_FilterValue, 1, 128, 17, 0, // Skip to: 11265
/* 6785 */    MCD_OPC_Decode, 225, 7, 20, // Opcode: ST_D_bo_c
/* 6789 */    MCD_OPC_FilterValue, 22, 21, 0, 0, // Skip to: 6815
/* 6794 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6797 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6806
/* 6802 */    MCD_OPC_Decode, 130, 4, 20, // Opcode: LD_A_bo_c
/* 6806 */    MCD_OPC_FilterValue, 1, 102, 17, 0, // Skip to: 11265
/* 6811 */    MCD_OPC_Decode, 196, 7, 20, // Opcode: ST_A_bo_c
/* 6815 */    MCD_OPC_FilterValue, 23, 21, 0, 0, // Skip to: 6841
/* 6820 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6823 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6832
/* 6828 */    MCD_OPC_Decode, 160, 4, 20, // Opcode: LD_DA_bo_c
/* 6832 */    MCD_OPC_FilterValue, 1, 76, 17, 0, // Skip to: 11265
/* 6837 */    MCD_OPC_Decode, 219, 7, 20, // Opcode: ST_DA_bo_c
/* 6841 */    MCD_OPC_FilterValue, 24, 21, 0, 0, // Skip to: 6867
/* 6846 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6849 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6858
/* 6854 */    MCD_OPC_Decode, 190, 4, 20, // Opcode: LD_Q_bo_c
/* 6858 */    MCD_OPC_FilterValue, 1, 50, 17, 0, // Skip to: 11265
/* 6863 */    MCD_OPC_Decode, 242, 7, 20, // Opcode: ST_Q_bo_c
/* 6867 */    MCD_OPC_FilterValue, 27, 11, 0, 0, // Skip to: 6883
/* 6872 */    MCD_OPC_CheckField, 7, 1, 1, 34, 17, 0, // Skip to: 11265
/* 6879 */    MCD_OPC_Decode, 198, 2, 20, // Opcode: CACHEI_W_bo_c
/* 6883 */    MCD_OPC_FilterValue, 28, 11, 0, 0, // Skip to: 6899
/* 6888 */    MCD_OPC_CheckField, 7, 1, 1, 18, 17, 0, // Skip to: 11265
/* 6895 */    MCD_OPC_Decode, 213, 2, 20, // Opcode: CACHE_W_bo_c
/* 6899 */    MCD_OPC_FilterValue, 29, 11, 0, 0, // Skip to: 6915
/* 6904 */    MCD_OPC_CheckField, 7, 1, 1, 2, 17, 0, // Skip to: 11265
/* 6911 */    MCD_OPC_Decode, 208, 2, 20, // Opcode: CACHE_WI_bo_c
/* 6915 */    MCD_OPC_FilterValue, 30, 249, 16, 0, // Skip to: 11265
/* 6920 */    MCD_OPC_CheckField, 7, 1, 1, 242, 16, 0, // Skip to: 11265
/* 6927 */    MCD_OPC_Decode, 203, 2, 20, // Opcode: CACHE_I_bo_c
/* 6931 */    MCD_OPC_FilterValue, 43, 161, 0, 0, // Skip to: 7097
/* 6936 */    MCD_OPC_ExtractField, 21, 3,  // Inst{23-21} ...
/* 6939 */    MCD_OPC_FilterValue, 0, 38, 0, 0, // Skip to: 6982
/* 6944 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6947 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 6973
/* 6952 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 6955 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6964
/* 6960 */    MCD_OPC_Decode, 221, 2, 33, // Opcode: CADD_rrr
/* 6964 */    MCD_OPC_FilterValue, 4, 200, 16, 0, // Skip to: 11265
/* 6969 */    MCD_OPC_Decode, 218, 2, 33, // Opcode: CADDN_rrr
/* 6973 */    MCD_OPC_FilterValue, 1, 191, 16, 0, // Skip to: 11265
/* 6978 */    MCD_OPC_Decode, 220, 2, 25, // Opcode: CADD_rcr
/* 6982 */    MCD_OPC_FilterValue, 1, 38, 0, 0, // Skip to: 7025
/* 6987 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 6990 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 7016
/* 6995 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 6998 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7007
/* 7003 */    MCD_OPC_Decode, 248, 2, 33, // Opcode: CSUB_rrr
/* 7007 */    MCD_OPC_FilterValue, 4, 157, 16, 0, // Skip to: 11265
/* 7012 */    MCD_OPC_Decode, 247, 2, 33, // Opcode: CSUBN_rrr
/* 7016 */    MCD_OPC_FilterValue, 1, 148, 16, 0, // Skip to: 11265
/* 7021 */    MCD_OPC_Decode, 217, 2, 25, // Opcode: CADDN_rcr
/* 7025 */    MCD_OPC_FilterValue, 2, 35, 0, 0, // Skip to: 7065
/* 7030 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 7033 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7049
/* 7038 */    MCD_OPC_CheckField, 7, 1, 0, 124, 16, 0, // Skip to: 11265
/* 7045 */    MCD_OPC_Decode, 156, 7, 33, // Opcode: SEL_rrr
/* 7049 */    MCD_OPC_FilterValue, 4, 115, 16, 0, // Skip to: 11265
/* 7054 */    MCD_OPC_CheckField, 7, 1, 0, 108, 16, 0, // Skip to: 11265
/* 7061 */    MCD_OPC_Decode, 154, 7, 33, // Opcode: SELN_rrr
/* 7065 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 7081
/* 7070 */    MCD_OPC_CheckField, 7, 1, 1, 92, 16, 0, // Skip to: 11265
/* 7077 */    MCD_OPC_Decode, 155, 7, 25, // Opcode: SEL_rcr
/* 7081 */    MCD_OPC_FilterValue, 5, 83, 16, 0, // Skip to: 11265
/* 7086 */    MCD_OPC_CheckField, 7, 1, 1, 76, 16, 0, // Skip to: 11265
/* 7093 */    MCD_OPC_Decode, 153, 7, 25, // Opcode: SELN_rcr
/* 7097 */    MCD_OPC_FilterValue, 45, 102, 0, 0, // Skip to: 7204
/* 7102 */    MCD_OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 7105 */    MCD_OPC_FilterValue, 0, 38, 0, 0, // Skip to: 7148
/* 7110 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7113 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 7139
/* 7118 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 7121 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7130
/* 7126 */    MCD_OPC_Decode, 224, 2, 15, // Opcode: CALLI_rr
/* 7130 */    MCD_OPC_FilterValue, 4, 34, 16, 0, // Skip to: 11265
/* 7135 */    MCD_OPC_Decode, 161, 3, 15, // Opcode: FCALLA_i
/* 7139 */    MCD_OPC_FilterValue, 1, 25, 16, 0, // Skip to: 11265
/* 7144 */    MCD_OPC_Decode, 187, 2, 22, // Opcode: BISR_rc
/* 7148 */    MCD_OPC_FilterValue, 1, 35, 0, 0, // Skip to: 7188
/* 7153 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 7156 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7172
/* 7161 */    MCD_OPC_CheckField, 7, 1, 0, 1, 16, 0, // Skip to: 11265
/* 7168 */    MCD_OPC_Decode, 214, 3, 15, // Opcode: JLI_rr
/* 7172 */    MCD_OPC_FilterValue, 4, 248, 15, 0, // Skip to: 11265
/* 7177 */    MCD_OPC_CheckField, 7, 1, 0, 241, 15, 0, // Skip to: 11265
/* 7184 */    MCD_OPC_Decode, 210, 3, 15, // Opcode: JI_rr
/* 7188 */    MCD_OPC_FilterValue, 4, 232, 15, 0, // Skip to: 11265
/* 7193 */    MCD_OPC_CheckField, 7, 1, 1, 225, 15, 0, // Skip to: 11265
/* 7200 */    MCD_OPC_Decode, 158, 8, 22, // Opcode: SYSCALL_rc
/* 7204 */    MCD_OPC_FilterValue, 47, 18, 0, 0, // Skip to: 7227
/* 7209 */    MCD_OPC_CheckField, 12, 20, 0, 209, 15, 0, // Skip to: 11265
/* 7216 */    MCD_OPC_CheckField, 7, 1, 0, 202, 15, 0, // Skip to: 11265
/* 7223 */    MCD_OPC_Decode, 140, 7, 14, // Opcode: RSTV_sys
/* 7227 */    MCD_OPC_FilterValue, 51, 69, 1, 0, // Skip to: 7557
/* 7232 */    MCD_OPC_ExtractField, 21, 3,  // Inst{23-21} ...
/* 7235 */    MCD_OPC_FilterValue, 1, 84, 0, 0, // Skip to: 7324
/* 7240 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7243 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7252
/* 7248 */    MCD_OPC_Decode, 180, 6, 25, // Opcode: MSUB_rcr
/* 7252 */    MCD_OPC_FilterValue, 1, 168, 15, 0, // Skip to: 11265
/* 7257 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 7260 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 7276
/* 7265 */    MCD_OPC_CheckField, 24, 4, 0, 153, 15, 0, // Skip to: 11265
/* 7272 */    MCD_OPC_Decode, 191, 6, 24, // Opcode: MULR_H_rr1_UL2e
/* 7276 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 7292
/* 7281 */    MCD_OPC_CheckField, 24, 4, 0, 137, 15, 0, // Skip to: 11265
/* 7288 */    MCD_OPC_Decode, 190, 6, 24, // Opcode: MULR_H_rr1_LU2e
/* 7292 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 7308
/* 7297 */    MCD_OPC_CheckField, 24, 4, 0, 121, 15, 0, // Skip to: 11265
/* 7304 */    MCD_OPC_Decode, 189, 6, 24, // Opcode: MULR_H_rr1_LL2e
/* 7308 */    MCD_OPC_FilterValue, 7, 112, 15, 0, // Skip to: 11265
/* 7313 */    MCD_OPC_CheckField, 24, 4, 0, 105, 15, 0, // Skip to: 11265
/* 7320 */    MCD_OPC_Decode, 192, 6, 24, // Opcode: MULR_H_rr1_UU2e
/* 7324 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 7340
/* 7329 */    MCD_OPC_CheckField, 7, 1, 0, 89, 15, 0, // Skip to: 11265
/* 7336 */    MCD_OPC_Decode, 178, 6, 25, // Opcode: MSUB_U_rcr
/* 7340 */    MCD_OPC_FilterValue, 3, 148, 0, 0, // Skip to: 7493
/* 7345 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7348 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7357
/* 7353 */    MCD_OPC_Decode, 181, 6, 25, // Opcode: MSUB_rcr_e
/* 7357 */    MCD_OPC_FilterValue, 1, 63, 15, 0, // Skip to: 11265
/* 7362 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 7365 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7381
/* 7370 */    MCD_OPC_CheckField, 24, 4, 0, 48, 15, 0, // Skip to: 11265
/* 7377 */    MCD_OPC_Decode, 202, 6, 24, // Opcode: MUL_H_rr1_UL2e
/* 7381 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 7397
/* 7386 */    MCD_OPC_CheckField, 24, 4, 0, 32, 15, 0, // Skip to: 11265
/* 7393 */    MCD_OPC_Decode, 201, 6, 24, // Opcode: MUL_H_rr1_LU2e
/* 7397 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 7413
/* 7402 */    MCD_OPC_CheckField, 24, 4, 0, 16, 15, 0, // Skip to: 11265
/* 7409 */    MCD_OPC_Decode, 200, 6, 24, // Opcode: MUL_H_rr1_LL2e
/* 7413 */    MCD_OPC_FilterValue, 3, 11, 0, 0, // Skip to: 7429
/* 7418 */    MCD_OPC_CheckField, 24, 4, 0, 0, 15, 0, // Skip to: 11265
/* 7425 */    MCD_OPC_Decode, 203, 6, 24, // Opcode: MUL_H_rr1_UU2e
/* 7429 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 7445
/* 7434 */    MCD_OPC_CheckField, 24, 4, 0, 240, 14, 0, // Skip to: 11265
/* 7441 */    MCD_OPC_Decode, 187, 6, 24, // Opcode: MULM_H_rr1_UL2e
/* 7445 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 7461
/* 7450 */    MCD_OPC_CheckField, 24, 4, 0, 224, 14, 0, // Skip to: 11265
/* 7457 */    MCD_OPC_Decode, 186, 6, 24, // Opcode: MULM_H_rr1_LU2e
/* 7461 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 7477
/* 7466 */    MCD_OPC_CheckField, 24, 4, 0, 208, 14, 0, // Skip to: 11265
/* 7473 */    MCD_OPC_Decode, 185, 6, 24, // Opcode: MULM_H_rr1_LL2e
/* 7477 */    MCD_OPC_FilterValue, 7, 199, 14, 0, // Skip to: 11265
/* 7482 */    MCD_OPC_CheckField, 24, 4, 0, 192, 14, 0, // Skip to: 11265
/* 7489 */    MCD_OPC_Decode, 188, 6, 24, // Opcode: MULM_H_rr1_UU2e
/* 7493 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 7509
/* 7498 */    MCD_OPC_CheckField, 7, 1, 0, 176, 14, 0, // Skip to: 11265
/* 7505 */    MCD_OPC_Decode, 155, 6, 25, // Opcode: MSUBS_U_rcr
/* 7509 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 7525
/* 7514 */    MCD_OPC_CheckField, 7, 1, 0, 160, 14, 0, // Skip to: 11265
/* 7521 */    MCD_OPC_Decode, 159, 6, 25, // Opcode: MSUBS_rcr
/* 7525 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 7541
/* 7530 */    MCD_OPC_CheckField, 7, 1, 0, 144, 14, 0, // Skip to: 11265
/* 7537 */    MCD_OPC_Decode, 156, 6, 25, // Opcode: MSUBS_U_rcr_e
/* 7541 */    MCD_OPC_FilterValue, 7, 135, 14, 0, // Skip to: 11265
/* 7546 */    MCD_OPC_CheckField, 7, 1, 0, 128, 14, 0, // Skip to: 11265
/* 7553 */    MCD_OPC_Decode, 160, 6, 25, // Opcode: MSUBS_rcr_e
/* 7557 */    MCD_OPC_FilterValue, 53, 11, 0, 0, // Skip to: 7573
/* 7562 */    MCD_OPC_CheckField, 7, 1, 1, 112, 14, 0, // Skip to: 11265
/* 7569 */    MCD_OPC_Decode, 200, 7, 29, // Opcode: ST_A_bol
/* 7573 */    MCD_OPC_FilterValue, 55, 87, 0, 0, // Skip to: 7665
/* 7578 */    MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 7581 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 7607
/* 7586 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7589 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7598
/* 7594 */    MCD_OPC_Decode, 185, 3, 34, // Opcode: INSERT_rrpw
/* 7598 */    MCD_OPC_FilterValue, 1, 78, 14, 0, // Skip to: 11265
/* 7603 */    MCD_OPC_Decode, 182, 3, 35, // Opcode: INSERT_rcpw
/* 7607 */    MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 7633
/* 7612 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7615 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7624
/* 7620 */    MCD_OPC_Decode, 180, 3, 34, // Opcode: IMASK_rrpw
/* 7624 */    MCD_OPC_FilterValue, 1, 52, 14, 0, // Skip to: 11265
/* 7629 */    MCD_OPC_Decode, 178, 3, 35, // Opcode: IMASK_rcpw
/* 7633 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 7649
/* 7638 */    MCD_OPC_CheckField, 7, 1, 0, 36, 14, 0, // Skip to: 11265
/* 7645 */    MCD_OPC_Decode, 157, 3, 34, // Opcode: EXTR_rrpw
/* 7649 */    MCD_OPC_FilterValue, 3, 27, 14, 0, // Skip to: 11265
/* 7654 */    MCD_OPC_CheckField, 7, 1, 0, 20, 14, 0, // Skip to: 11265
/* 7661 */    MCD_OPC_Decode, 154, 3, 34, // Opcode: EXTR_U_rrpw
/* 7665 */    MCD_OPC_FilterValue, 57, 21, 0, 0, // Skip to: 7691
/* 7670 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7673 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7682
/* 7678 */    MCD_OPC_Decode, 146, 4, 29, // Opcode: LD_BU_bol
/* 7682 */    MCD_OPC_FilterValue, 1, 250, 13, 0, // Skip to: 11265
/* 7687 */    MCD_OPC_Decode, 176, 4, 29, // Opcode: LD_HU_bol
/* 7691 */    MCD_OPC_FilterValue, 59, 21, 0, 0, // Skip to: 7717
/* 7696 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7699 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7708
/* 7704 */    MCD_OPC_Decode, 214, 5, 23, // Opcode: MOV_rlcDc
/* 7708 */    MCD_OPC_FilterValue, 1, 224, 13, 0, // Skip to: 11265
/* 7713 */    MCD_OPC_Decode, 213, 5, 23, // Opcode: MOV_U_rlc
/* 7717 */    MCD_OPC_FilterValue, 61, 35, 0, 0, // Skip to: 7757
/* 7722 */    MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 7725 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7741
/* 7730 */    MCD_OPC_CheckField, 7, 1, 1, 200, 13, 0, // Skip to: 11265
/* 7737 */    MCD_OPC_Decode, 238, 3, 31, // Opcode: JZ_A_brr
/* 7741 */    MCD_OPC_FilterValue, 1, 191, 13, 0, // Skip to: 11265
/* 7746 */    MCD_OPC_CheckField, 7, 1, 1, 184, 13, 0, // Skip to: 11265
/* 7753 */    MCD_OPC_Decode, 232, 3, 31, // Opcode: JNZ_A_brr
/* 7757 */    MCD_OPC_FilterValue, 63, 55, 0, 0, // Skip to: 7817
/* 7762 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 7765 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 7791
/* 7770 */    MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 7773 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7782
/* 7778 */    MCD_OPC_Decode, 219, 3, 31, // Opcode: JLT_brr
/* 7782 */    MCD_OPC_FilterValue, 1, 150, 13, 0, // Skip to: 11265
/* 7787 */    MCD_OPC_Decode, 217, 3, 31, // Opcode: JLT_U_brr
/* 7791 */    MCD_OPC_FilterValue, 1, 141, 13, 0, // Skip to: 11265
/* 7796 */    MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 7799 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7808
/* 7804 */    MCD_OPC_Decode, 218, 3, 32, // Opcode: JLT_brc
/* 7808 */    MCD_OPC_FilterValue, 1, 124, 13, 0, // Skip to: 11265
/* 7813 */    MCD_OPC_Decode, 216, 3, 32, // Opcode: JLT_U_brc
/* 7817 */    MCD_OPC_FilterValue, 67, 219, 2, 0, // Skip to: 8553
/* 7822 */    MCD_OPC_ExtractField, 18, 6,  // Inst{23-18} ...
/* 7825 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7841
/* 7830 */    MCD_OPC_CheckField, 7, 1, 0, 100, 13, 0, // Skip to: 11265
/* 7837 */    MCD_OPC_Decode, 174, 5, 17, // Opcode: MADD_Q_rrr1_U
/* 7841 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 7857
/* 7846 */    MCD_OPC_CheckField, 7, 1, 0, 84, 13, 0, // Skip to: 11265
/* 7853 */    MCD_OPC_Decode, 172, 5, 17, // Opcode: MADD_Q_rrr1_L
/* 7857 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 7873
/* 7862 */    MCD_OPC_CheckField, 7, 1, 0, 68, 13, 0, // Skip to: 11265
/* 7869 */    MCD_OPC_Decode, 171, 5, 17, // Opcode: MADD_Q_rrr1
/* 7873 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 7889
/* 7878 */    MCD_OPC_CheckField, 7, 1, 0, 52, 13, 0, // Skip to: 11265
/* 7885 */    MCD_OPC_Decode, 175, 5, 17, // Opcode: MADD_Q_rrr1_U_U
/* 7889 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 7905
/* 7894 */    MCD_OPC_CheckField, 7, 1, 0, 36, 13, 0, // Skip to: 11265
/* 7901 */    MCD_OPC_Decode, 173, 5, 17, // Opcode: MADD_Q_rrr1_L_L
/* 7905 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 7921
/* 7910 */    MCD_OPC_CheckField, 7, 1, 0, 20, 13, 0, // Skip to: 11265
/* 7917 */    MCD_OPC_Decode, 247, 4, 17, // Opcode: MADDR_Q_rrr1_U_U
/* 7921 */    MCD_OPC_FilterValue, 7, 11, 0, 0, // Skip to: 7937
/* 7926 */    MCD_OPC_CheckField, 7, 1, 0, 4, 13, 0, // Skip to: 11265
/* 7933 */    MCD_OPC_Decode, 246, 4, 17, // Opcode: MADDR_Q_rrr1_L_L
/* 7937 */    MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 7953
/* 7942 */    MCD_OPC_CheckField, 7, 1, 1, 244, 12, 0, // Skip to: 11265
/* 7949 */    MCD_OPC_Decode, 134, 5, 17, // Opcode: MADDSUR_H_rrr1_UL
/* 7953 */    MCD_OPC_FilterValue, 13, 11, 0, 0, // Skip to: 7969
/* 7958 */    MCD_OPC_CheckField, 7, 1, 1, 228, 12, 0, // Skip to: 11265
/* 7965 */    MCD_OPC_Decode, 133, 5, 17, // Opcode: MADDSUR_H_rrr1_LU
/* 7969 */    MCD_OPC_FilterValue, 14, 11, 0, 0, // Skip to: 7985
/* 7974 */    MCD_OPC_CheckField, 7, 1, 1, 212, 12, 0, // Skip to: 11265
/* 7981 */    MCD_OPC_Decode, 132, 5, 17, // Opcode: MADDSUR_H_rrr1_LL
/* 7985 */    MCD_OPC_FilterValue, 15, 11, 0, 0, // Skip to: 8001
/* 7990 */    MCD_OPC_CheckField, 7, 1, 1, 196, 12, 0, // Skip to: 11265
/* 7997 */    MCD_OPC_Decode, 135, 5, 17, // Opcode: MADDSUR_H_rrr1_UU
/* 8001 */    MCD_OPC_FilterValue, 24, 21, 0, 0, // Skip to: 8027
/* 8006 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8009 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8018
/* 8014 */    MCD_OPC_Decode, 179, 5, 17, // Opcode: MADD_Q_rrr1_e_U
/* 8018 */    MCD_OPC_FilterValue, 1, 170, 12, 0, // Skip to: 11265
/* 8023 */    MCD_OPC_Decode, 142, 5, 17, // Opcode: MADDSU_H_rrr1_UL
/* 8027 */    MCD_OPC_FilterValue, 25, 21, 0, 0, // Skip to: 8053
/* 8032 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8035 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8044
/* 8040 */    MCD_OPC_Decode, 177, 5, 17, // Opcode: MADD_Q_rrr1_e_L
/* 8044 */    MCD_OPC_FilterValue, 1, 144, 12, 0, // Skip to: 11265
/* 8049 */    MCD_OPC_Decode, 141, 5, 17, // Opcode: MADDSU_H_rrr1_LU
/* 8053 */    MCD_OPC_FilterValue, 26, 11, 0, 0, // Skip to: 8069
/* 8058 */    MCD_OPC_CheckField, 7, 1, 1, 128, 12, 0, // Skip to: 11265
/* 8065 */    MCD_OPC_Decode, 140, 5, 17, // Opcode: MADDSU_H_rrr1_LL
/* 8069 */    MCD_OPC_FilterValue, 27, 21, 0, 0, // Skip to: 8095
/* 8074 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8077 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8086
/* 8082 */    MCD_OPC_Decode, 176, 5, 17, // Opcode: MADD_Q_rrr1_e
/* 8086 */    MCD_OPC_FilterValue, 1, 102, 12, 0, // Skip to: 11265
/* 8091 */    MCD_OPC_Decode, 143, 5, 17, // Opcode: MADDSU_H_rrr1_UU
/* 8095 */    MCD_OPC_FilterValue, 28, 21, 0, 0, // Skip to: 8121
/* 8100 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8103 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8112
/* 8108 */    MCD_OPC_Decode, 180, 5, 17, // Opcode: MADD_Q_rrr1_e_U_U
/* 8112 */    MCD_OPC_FilterValue, 1, 76, 12, 0, // Skip to: 11265
/* 8117 */    MCD_OPC_Decode, 254, 4, 17, // Opcode: MADDSUM_H_rrr1_UL
/* 8121 */    MCD_OPC_FilterValue, 29, 21, 0, 0, // Skip to: 8147
/* 8126 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8129 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8138
/* 8134 */    MCD_OPC_Decode, 178, 5, 17, // Opcode: MADD_Q_rrr1_e_L_L
/* 8138 */    MCD_OPC_FilterValue, 1, 50, 12, 0, // Skip to: 11265
/* 8143 */    MCD_OPC_Decode, 253, 4, 17, // Opcode: MADDSUM_H_rrr1_LU
/* 8147 */    MCD_OPC_FilterValue, 30, 21, 0, 0, // Skip to: 8173
/* 8152 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8155 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8164
/* 8160 */    MCD_OPC_Decode, 241, 4, 17, // Opcode: MADDR_H_rrr1_DcEdDaDbUL
/* 8164 */    MCD_OPC_FilterValue, 1, 24, 12, 0, // Skip to: 11265
/* 8169 */    MCD_OPC_Decode, 252, 4, 17, // Opcode: MADDSUM_H_rrr1_LL
/* 8173 */    MCD_OPC_FilterValue, 31, 11, 0, 0, // Skip to: 8189
/* 8178 */    MCD_OPC_CheckField, 7, 1, 1, 8, 12, 0, // Skip to: 11265
/* 8185 */    MCD_OPC_Decode, 255, 4, 17, // Opcode: MADDSUM_H_rrr1_UU
/* 8189 */    MCD_OPC_FilterValue, 32, 11, 0, 0, // Skip to: 8205
/* 8194 */    MCD_OPC_CheckField, 7, 1, 0, 248, 11, 0, // Skip to: 11265
/* 8201 */    MCD_OPC_Decode, 151, 5, 17, // Opcode: MADDS_Q_rrr1_U
/* 8205 */    MCD_OPC_FilterValue, 33, 11, 0, 0, // Skip to: 8221
/* 8210 */    MCD_OPC_CheckField, 7, 1, 0, 232, 11, 0, // Skip to: 11265
/* 8217 */    MCD_OPC_Decode, 149, 5, 17, // Opcode: MADDS_Q_rrr1_L
/* 8221 */    MCD_OPC_FilterValue, 34, 11, 0, 0, // Skip to: 8237
/* 8226 */    MCD_OPC_CheckField, 7, 1, 0, 216, 11, 0, // Skip to: 11265
/* 8233 */    MCD_OPC_Decode, 148, 5, 17, // Opcode: MADDS_Q_rrr1
/* 8237 */    MCD_OPC_FilterValue, 36, 11, 0, 0, // Skip to: 8253
/* 8242 */    MCD_OPC_CheckField, 7, 1, 0, 200, 11, 0, // Skip to: 11265
/* 8249 */    MCD_OPC_Decode, 152, 5, 17, // Opcode: MADDS_Q_rrr1_U_U
/* 8253 */    MCD_OPC_FilterValue, 37, 11, 0, 0, // Skip to: 8269
/* 8258 */    MCD_OPC_CheckField, 7, 1, 0, 184, 11, 0, // Skip to: 11265
/* 8265 */    MCD_OPC_Decode, 150, 5, 17, // Opcode: MADDS_Q_rrr1_L_L
/* 8269 */    MCD_OPC_FilterValue, 38, 11, 0, 0, // Skip to: 8285
/* 8274 */    MCD_OPC_CheckField, 7, 1, 0, 168, 11, 0, // Skip to: 11265
/* 8281 */    MCD_OPC_Decode, 240, 4, 17, // Opcode: MADDRS_Q_rrr1_U_U
/* 8285 */    MCD_OPC_FilterValue, 39, 11, 0, 0, // Skip to: 8301
/* 8290 */    MCD_OPC_CheckField, 7, 1, 0, 152, 11, 0, // Skip to: 11265
/* 8297 */    MCD_OPC_Decode, 239, 4, 17, // Opcode: MADDRS_Q_rrr1_L_L
/* 8301 */    MCD_OPC_FilterValue, 44, 11, 0, 0, // Skip to: 8317
/* 8306 */    MCD_OPC_CheckField, 7, 1, 1, 136, 11, 0, // Skip to: 11265
/* 8313 */    MCD_OPC_Decode, 130, 5, 17, // Opcode: MADDSURS_H_rrr1_UL
/* 8317 */    MCD_OPC_FilterValue, 45, 11, 0, 0, // Skip to: 8333
/* 8322 */    MCD_OPC_CheckField, 7, 1, 1, 120, 11, 0, // Skip to: 11265
/* 8329 */    MCD_OPC_Decode, 129, 5, 17, // Opcode: MADDSURS_H_rrr1_LU
/* 8333 */    MCD_OPC_FilterValue, 46, 11, 0, 0, // Skip to: 8349
/* 8338 */    MCD_OPC_CheckField, 7, 1, 1, 104, 11, 0, // Skip to: 11265
/* 8345 */    MCD_OPC_Decode, 128, 5, 17, // Opcode: MADDSURS_H_rrr1_LL
/* 8349 */    MCD_OPC_FilterValue, 47, 11, 0, 0, // Skip to: 8365
/* 8354 */    MCD_OPC_CheckField, 7, 1, 1, 88, 11, 0, // Skip to: 11265
/* 8361 */    MCD_OPC_Decode, 131, 5, 17, // Opcode: MADDSURS_H_rrr1_UU
/* 8365 */    MCD_OPC_FilterValue, 56, 21, 0, 0, // Skip to: 8391
/* 8370 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8373 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8382
/* 8378 */    MCD_OPC_Decode, 156, 5, 17, // Opcode: MADDS_Q_rrr1_e_U
/* 8382 */    MCD_OPC_FilterValue, 1, 62, 11, 0, // Skip to: 11265
/* 8387 */    MCD_OPC_Decode, 138, 5, 17, // Opcode: MADDSUS_H_rrr1_UL
/* 8391 */    MCD_OPC_FilterValue, 57, 21, 0, 0, // Skip to: 8417
/* 8396 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8399 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8408
/* 8404 */    MCD_OPC_Decode, 154, 5, 17, // Opcode: MADDS_Q_rrr1_e_L
/* 8408 */    MCD_OPC_FilterValue, 1, 36, 11, 0, // Skip to: 11265
/* 8413 */    MCD_OPC_Decode, 137, 5, 17, // Opcode: MADDSUS_H_rrr1_LU
/* 8417 */    MCD_OPC_FilterValue, 58, 11, 0, 0, // Skip to: 8433
/* 8422 */    MCD_OPC_CheckField, 7, 1, 1, 20, 11, 0, // Skip to: 11265
/* 8429 */    MCD_OPC_Decode, 136, 5, 17, // Opcode: MADDSUS_H_rrr1_LL
/* 8433 */    MCD_OPC_FilterValue, 59, 21, 0, 0, // Skip to: 8459
/* 8438 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8441 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8450
/* 8446 */    MCD_OPC_Decode, 153, 5, 17, // Opcode: MADDS_Q_rrr1_e
/* 8450 */    MCD_OPC_FilterValue, 1, 250, 10, 0, // Skip to: 11265
/* 8455 */    MCD_OPC_Decode, 139, 5, 17, // Opcode: MADDSUS_H_rrr1_UU
/* 8459 */    MCD_OPC_FilterValue, 60, 21, 0, 0, // Skip to: 8485
/* 8464 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8467 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8476
/* 8472 */    MCD_OPC_Decode, 157, 5, 17, // Opcode: MADDS_Q_rrr1_e_U_U
/* 8476 */    MCD_OPC_FilterValue, 1, 224, 10, 0, // Skip to: 11265
/* 8481 */    MCD_OPC_Decode, 250, 4, 17, // Opcode: MADDSUMS_H_rrr1_UL
/* 8485 */    MCD_OPC_FilterValue, 61, 21, 0, 0, // Skip to: 8511
/* 8490 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8493 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8502
/* 8498 */    MCD_OPC_Decode, 155, 5, 17, // Opcode: MADDS_Q_rrr1_e_L_L
/* 8502 */    MCD_OPC_FilterValue, 1, 198, 10, 0, // Skip to: 11265
/* 8507 */    MCD_OPC_Decode, 249, 4, 17, // Opcode: MADDSUMS_H_rrr1_LU
/* 8511 */    MCD_OPC_FilterValue, 62, 21, 0, 0, // Skip to: 8537
/* 8516 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8519 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8528
/* 8524 */    MCD_OPC_Decode, 234, 4, 17, // Opcode: MADDRS_H_rrr1_DcEdDaDbUL
/* 8528 */    MCD_OPC_FilterValue, 1, 172, 10, 0, // Skip to: 11265
/* 8533 */    MCD_OPC_Decode, 248, 4, 17, // Opcode: MADDSUMS_H_rrr1_LL
/* 8537 */    MCD_OPC_FilterValue, 63, 163, 10, 0, // Skip to: 11265
/* 8542 */    MCD_OPC_CheckField, 7, 1, 1, 156, 10, 0, // Skip to: 11265
/* 8549 */    MCD_OPC_Decode, 251, 4, 17, // Opcode: MADDSUMS_H_rrr1_UU
/* 8553 */    MCD_OPC_FilterValue, 69, 45, 0, 0, // Skip to: 8603
/* 8558 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8561 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 8577
/* 8566 */    MCD_OPC_CheckField, 26, 2, 0, 132, 10, 0, // Skip to: 11265
/* 8573 */    MCD_OPC_Decode, 188, 4, 18, // Opcode: LD_Q_abs
/* 8577 */    MCD_OPC_FilterValue, 1, 123, 10, 0, // Skip to: 11265
/* 8582 */    MCD_OPC_ExtractField, 26, 2,  // Inst{27-26} ...
/* 8585 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8594
/* 8590 */    MCD_OPC_Decode, 206, 4, 18, // Opcode: LEA_abs
/* 8594 */    MCD_OPC_FilterValue, 1, 106, 10, 0, // Skip to: 11265
/* 8599 */    MCD_OPC_Decode, 209, 4, 18, // Opcode: LHA_abs
/* 8603 */    MCD_OPC_FilterValue, 71, 107, 0, 0, // Skip to: 8715
/* 8608 */    MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 8611 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 8637
/* 8616 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8619 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8628
/* 8624 */    MCD_OPC_Decode, 167, 2, 19, // Opcode: AND_AND_T
/* 8628 */    MCD_OPC_FilterValue, 1, 72, 10, 0, // Skip to: 11265
/* 8633 */    MCD_OPC_Decode, 236, 6, 19, // Opcode: OR_AND_T
/* 8637 */    MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 8663
/* 8642 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8645 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8654
/* 8650 */    MCD_OPC_Decode, 181, 2, 19, // Opcode: AND_OR_T
/* 8654 */    MCD_OPC_FilterValue, 1, 46, 10, 0, // Skip to: 11265
/* 8659 */    MCD_OPC_Decode, 250, 6, 19, // Opcode: OR_OR_T
/* 8663 */    MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 8689
/* 8668 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8671 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8680
/* 8676 */    MCD_OPC_Decode, 180, 2, 19, // Opcode: AND_NOR_T
/* 8680 */    MCD_OPC_FilterValue, 1, 20, 10, 0, // Skip to: 11265
/* 8685 */    MCD_OPC_Decode, 249, 6, 19, // Opcode: OR_NOR_T
/* 8689 */    MCD_OPC_FilterValue, 3, 11, 10, 0, // Skip to: 11265
/* 8694 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8697 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8706
/* 8702 */    MCD_OPC_Decode, 166, 2, 19, // Opcode: AND_ANDN_T
/* 8706 */    MCD_OPC_FilterValue, 1, 250, 9, 0, // Skip to: 11265
/* 8711 */    MCD_OPC_Decode, 235, 6, 19, // Opcode: OR_ANDN_T
/* 8715 */    MCD_OPC_FilterValue, 73, 173, 0, 0, // Skip to: 8893
/* 8720 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 8723 */    MCD_OPC_FilterValue, 0, 156, 0, 0, // Skip to: 8884
/* 8728 */    MCD_OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 8731 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 8740
/* 8736 */    MCD_OPC_Decode, 155, 8, 20, // Opcode: SWAP_W_bo_pos
/* 8740 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 8749
/* 8745 */    MCD_OPC_Decode, 251, 3, 20, // Opcode: LDMST_bo_pos
/* 8749 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 8758
/* 8754 */    MCD_OPC_Decode, 149, 8, 20, // Opcode: SWAPMSK_W_bo_pos
/* 8758 */    MCD_OPC_FilterValue, 3, 4, 0, 0, // Skip to: 8767
/* 8763 */    MCD_OPC_Decode, 239, 2, 20, // Opcode: CMPSWAP_W_bo_pos
/* 8767 */    MCD_OPC_FilterValue, 16, 4, 0, 0, // Skip to: 8776
/* 8772 */    MCD_OPC_Decode, 156, 8, 20, // Opcode: SWAP_W_bo_pre
/* 8776 */    MCD_OPC_FilterValue, 17, 4, 0, 0, // Skip to: 8785
/* 8781 */    MCD_OPC_Decode, 252, 3, 20, // Opcode: LDMST_bo_pre
/* 8785 */    MCD_OPC_FilterValue, 18, 4, 0, 0, // Skip to: 8794
/* 8790 */    MCD_OPC_Decode, 150, 8, 20, // Opcode: SWAPMSK_W_bo_pre
/* 8794 */    MCD_OPC_FilterValue, 19, 4, 0, 0, // Skip to: 8803
/* 8799 */    MCD_OPC_Decode, 240, 2, 20, // Opcode: CMPSWAP_W_bo_pre
/* 8803 */    MCD_OPC_FilterValue, 32, 4, 0, 0, // Skip to: 8812
/* 8808 */    MCD_OPC_Decode, 153, 8, 20, // Opcode: SWAP_W_bo_bso
/* 8812 */    MCD_OPC_FilterValue, 33, 4, 0, 0, // Skip to: 8821
/* 8817 */    MCD_OPC_Decode, 249, 3, 20, // Opcode: LDMST_bo_bso
/* 8821 */    MCD_OPC_FilterValue, 34, 4, 0, 0, // Skip to: 8830
/* 8826 */    MCD_OPC_Decode, 147, 8, 20, // Opcode: SWAPMSK_W_bo_bso
/* 8830 */    MCD_OPC_FilterValue, 35, 4, 0, 0, // Skip to: 8839
/* 8835 */    MCD_OPC_Decode, 237, 2, 20, // Opcode: CMPSWAP_W_bo_bso
/* 8839 */    MCD_OPC_FilterValue, 36, 4, 0, 0, // Skip to: 8848
/* 8844 */    MCD_OPC_Decode, 247, 3, 20, // Opcode: LDLCX_bo_bso
/* 8848 */    MCD_OPC_FilterValue, 37, 4, 0, 0, // Skip to: 8857
/* 8853 */    MCD_OPC_Decode, 255, 3, 20, // Opcode: LDUCX_bo_bso
/* 8857 */    MCD_OPC_FilterValue, 38, 4, 0, 0, // Skip to: 8866
/* 8862 */    MCD_OPC_Decode, 191, 7, 20, // Opcode: STLCX_bo_bso
/* 8866 */    MCD_OPC_FilterValue, 39, 4, 0, 0, // Skip to: 8875
/* 8871 */    MCD_OPC_Decode, 193, 7, 20, // Opcode: STUCX_bo_bso
/* 8875 */    MCD_OPC_FilterValue, 40, 81, 9, 0, // Skip to: 11265
/* 8880 */    MCD_OPC_Decode, 207, 4, 20, // Opcode: LEA_bo_bso
/* 8884 */    MCD_OPC_FilterValue, 1, 72, 9, 0, // Skip to: 11265
/* 8889 */    MCD_OPC_Decode, 183, 4, 29, // Opcode: LD_H_bol
/* 8893 */    MCD_OPC_FilterValue, 75, 12, 2, 0, // Skip to: 9422
/* 8898 */    MCD_OPC_ExtractField, 18, 10,  // Inst{27-18} ...
/* 8901 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 8917
/* 8906 */    MCD_OPC_CheckField, 7, 1, 0, 48, 9, 0, // Skip to: 11265
/* 8913 */    MCD_OPC_Decode, 242, 2, 15, // Opcode: CMP_F_rr
/* 8917 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 8933
/* 8922 */    MCD_OPC_CheckField, 7, 1, 0, 32, 9, 0, // Skip to: 11265
/* 8929 */    MCD_OPC_Decode, 189, 2, 15, // Opcode: BMAERGE_rr
/* 8933 */    MCD_OPC_FilterValue, 8, 11, 0, 0, // Skip to: 8949
/* 8938 */    MCD_OPC_CheckField, 7, 1, 0, 16, 9, 0, // Skip to: 11265
/* 8945 */    MCD_OPC_Decode, 129, 7, 15, // Opcode: PARITY_rr
/* 8949 */    MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 8965
/* 8954 */    MCD_OPC_CheckField, 7, 1, 0, 0, 9, 0, // Skip to: 11265
/* 8961 */    MCD_OPC_Decode, 243, 2, 15, // Opcode: CRC32B_W_rr
/* 8965 */    MCD_OPC_FilterValue, 16, 11, 0, 0, // Skip to: 8981
/* 8970 */    MCD_OPC_CheckField, 7, 1, 0, 240, 8, 0, // Skip to: 11265
/* 8977 */    MCD_OPC_Decode, 199, 6, 15, // Opcode: MUL_F_rrr
/* 8981 */    MCD_OPC_FilterValue, 20, 11, 0, 0, // Skip to: 8997
/* 8986 */    MCD_OPC_CheckField, 7, 1, 0, 224, 8, 0, // Skip to: 11265
/* 8993 */    MCD_OPC_Decode, 255, 2, 15, // Opcode: DIV_F_rr
/* 8997 */    MCD_OPC_FilterValue, 24, 11, 0, 0, // Skip to: 9013
/* 9002 */    MCD_OPC_CheckField, 7, 1, 0, 208, 8, 0, // Skip to: 11265
/* 9009 */    MCD_OPC_Decode, 245, 2, 15, // Opcode: CRC32_B_rr
/* 9013 */    MCD_OPC_FilterValue, 28, 11, 0, 0, // Skip to: 9029
/* 9018 */    MCD_OPC_CheckField, 7, 1, 0, 192, 8, 0, // Skip to: 11265
/* 9025 */    MCD_OPC_Decode, 244, 2, 15, // Opcode: CRC32L_W_rr
/* 9029 */    MCD_OPC_FilterValue, 32, 11, 0, 0, // Skip to: 9045
/* 9034 */    MCD_OPC_CheckField, 7, 1, 0, 176, 8, 0, // Skip to: 11265
/* 9041 */    MCD_OPC_Decode, 161, 8, 15, // Opcode: UNPACK_rr
/* 9045 */    MCD_OPC_FilterValue, 36, 11, 0, 0, // Skip to: 9061
/* 9050 */    MCD_OPC_CheckField, 7, 1, 0, 160, 8, 0, // Skip to: 11265
/* 9057 */    MCD_OPC_Decode, 190, 2, 15, // Opcode: BSPLIT_rr
/* 9061 */    MCD_OPC_FilterValue, 40, 11, 0, 0, // Skip to: 9077
/* 9066 */    MCD_OPC_CheckField, 7, 1, 0, 144, 8, 0, // Skip to: 11265
/* 9073 */    MCD_OPC_Decode, 136, 3, 15, // Opcode: DVINIT_U_rr
/* 9077 */    MCD_OPC_FilterValue, 48, 11, 0, 0, // Skip to: 9093
/* 9082 */    MCD_OPC_CheckField, 7, 1, 0, 128, 8, 0, // Skip to: 11265
/* 9089 */    MCD_OPC_Decode, 162, 8, 15, // Opcode: UPDFL_rr
/* 9093 */    MCD_OPC_FilterValue, 64, 11, 0, 0, // Skip to: 9109
/* 9098 */    MCD_OPC_CheckField, 7, 1, 0, 112, 8, 0, // Skip to: 11265
/* 9105 */    MCD_OPC_Decode, 167, 3, 15, // Opcode: FTOI_rr
/* 9109 */    MCD_OPC_FilterValue, 68, 11, 0, 0, // Skip to: 9125
/* 9114 */    MCD_OPC_CheckField, 7, 1, 0, 96, 8, 0, // Skip to: 11265
/* 9121 */    MCD_OPC_Decode, 169, 3, 15, // Opcode: FTOQ31_rr
/* 9125 */    MCD_OPC_FilterValue, 72, 11, 0, 0, // Skip to: 9141
/* 9130 */    MCD_OPC_CheckField, 7, 1, 0, 80, 8, 0, // Skip to: 11265
/* 9137 */    MCD_OPC_Decode, 171, 3, 15, // Opcode: FTOU_rr
/* 9141 */    MCD_OPC_FilterValue, 76, 11, 0, 0, // Skip to: 9157
/* 9146 */    MCD_OPC_CheckField, 7, 1, 0, 64, 8, 0, // Skip to: 11265
/* 9153 */    MCD_OPC_Decode, 166, 3, 15, // Opcode: FTOIZ_rr
/* 9157 */    MCD_OPC_FilterValue, 80, 11, 0, 0, // Skip to: 9173
/* 9162 */    MCD_OPC_CheckField, 7, 1, 0, 48, 8, 0, // Skip to: 11265
/* 9169 */    MCD_OPC_Decode, 191, 3, 15, // Opcode: ITOF_rr
/* 9173 */    MCD_OPC_FilterValue, 84, 11, 0, 0, // Skip to: 9189
/* 9178 */    MCD_OPC_CheckField, 7, 1, 0, 32, 8, 0, // Skip to: 11265
/* 9185 */    MCD_OPC_Decode, 131, 7, 15, // Opcode: Q31TOF_rr
/* 9189 */    MCD_OPC_FilterValue, 88, 11, 0, 0, // Skip to: 9205
/* 9194 */    MCD_OPC_CheckField, 7, 1, 0, 16, 8, 0, // Skip to: 11265
/* 9201 */    MCD_OPC_Decode, 163, 8, 15, // Opcode: UTOF_rr
/* 9205 */    MCD_OPC_FilterValue, 92, 11, 0, 0, // Skip to: 9221
/* 9210 */    MCD_OPC_CheckField, 7, 1, 0, 0, 8, 0, // Skip to: 11265
/* 9217 */    MCD_OPC_Decode, 170, 3, 15, // Opcode: FTOUZ_rr
/* 9221 */    MCD_OPC_FilterValue, 96, 11, 0, 0, // Skip to: 9237
/* 9226 */    MCD_OPC_CheckField, 7, 1, 0, 240, 7, 0, // Skip to: 11265
/* 9233 */    MCD_OPC_Decode, 168, 3, 15, // Opcode: FTOQ31Z_rr
/* 9237 */    MCD_OPC_FilterValue, 100, 11, 0, 0, // Skip to: 9253
/* 9242 */    MCD_OPC_CheckField, 7, 1, 0, 224, 7, 0, // Skip to: 11265
/* 9249 */    MCD_OPC_Decode, 132, 7, 15, // Opcode: QSEED_F_rr
/* 9253 */    MCD_OPC_FilterValue, 104, 11, 0, 0, // Skip to: 9269
/* 9258 */    MCD_OPC_CheckField, 7, 1, 0, 208, 7, 0, // Skip to: 11265
/* 9265 */    MCD_OPC_Decode, 137, 3, 15, // Opcode: DVINIT_rr
/* 9269 */    MCD_OPC_FilterValue, 128, 1, 11, 0, 0, // Skip to: 9286
/* 9275 */    MCD_OPC_CheckField, 7, 1, 0, 191, 7, 0, // Skip to: 11265
/* 9282 */    MCD_OPC_Decode, 129, 3, 15, // Opcode: DIV_rr
/* 9286 */    MCD_OPC_FilterValue, 132, 1, 11, 0, 0, // Skip to: 9303
/* 9292 */    MCD_OPC_CheckField, 7, 1, 0, 174, 7, 0, // Skip to: 11265
/* 9299 */    MCD_OPC_Decode, 128, 3, 15, // Opcode: DIV_U_rr
/* 9303 */    MCD_OPC_FilterValue, 136, 1, 11, 0, 0, // Skip to: 9320
/* 9309 */    MCD_OPC_CheckField, 7, 1, 0, 157, 7, 0, // Skip to: 11265
/* 9316 */    MCD_OPC_Decode, 130, 7, 15, // Opcode: POPCNT_W_rr
/* 9320 */    MCD_OPC_FilterValue, 144, 1, 11, 0, 0, // Skip to: 9337
/* 9326 */    MCD_OPC_CheckField, 7, 1, 0, 140, 7, 0, // Skip to: 11265
/* 9333 */    MCD_OPC_Decode, 177, 3, 15, // Opcode: HPTOF_rr
/* 9337 */    MCD_OPC_FilterValue, 148, 1, 11, 0, 0, // Skip to: 9354
/* 9343 */    MCD_OPC_CheckField, 7, 1, 0, 123, 7, 0, // Skip to: 11265
/* 9350 */    MCD_OPC_Decode, 165, 3, 15, // Opcode: FTOHP_rr
/* 9354 */    MCD_OPC_FilterValue, 168, 1, 11, 0, 0, // Skip to: 9371
/* 9360 */    MCD_OPC_CheckField, 7, 1, 0, 106, 7, 0, // Skip to: 11265
/* 9367 */    MCD_OPC_Decode, 134, 3, 15, // Opcode: DVINIT_HU_rr
/* 9371 */    MCD_OPC_FilterValue, 232, 1, 11, 0, 0, // Skip to: 9388
/* 9377 */    MCD_OPC_CheckField, 7, 1, 0, 89, 7, 0, // Skip to: 11265
/* 9384 */    MCD_OPC_Decode, 135, 3, 15, // Opcode: DVINIT_H_rr
/* 9388 */    MCD_OPC_FilterValue, 168, 2, 11, 0, 0, // Skip to: 9405
/* 9394 */    MCD_OPC_CheckField, 7, 1, 0, 72, 7, 0, // Skip to: 11265
/* 9401 */    MCD_OPC_Decode, 132, 3, 15, // Opcode: DVINIT_BU_rr
/* 9405 */    MCD_OPC_FilterValue, 232, 2, 62, 7, 0, // Skip to: 11265
/* 9411 */    MCD_OPC_CheckField, 7, 1, 0, 55, 7, 0, // Skip to: 11265
/* 9418 */    MCD_OPC_Decode, 133, 3, 15, // Opcode: DVINIT_B_rr
/* 9422 */    MCD_OPC_FilterValue, 77, 21, 0, 0, // Skip to: 9448
/* 9427 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9430 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9439
/* 9435 */    MCD_OPC_Decode, 195, 5, 23, // Opcode: MFCR_rlc
/* 9439 */    MCD_OPC_FilterValue, 1, 29, 7, 0, // Skip to: 11265
/* 9444 */    MCD_OPC_Decode, 184, 6, 23, // Opcode: MTCR_rlc
/* 9448 */    MCD_OPC_FilterValue, 83, 83, 0, 0, // Skip to: 9536
/* 9453 */    MCD_OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 9456 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 9472
/* 9461 */    MCD_OPC_CheckField, 7, 1, 0, 5, 7, 0, // Skip to: 11265
/* 9468 */    MCD_OPC_Decode, 214, 6, 22, // Opcode: MUL_rc
/* 9472 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 9488
/* 9477 */    MCD_OPC_CheckField, 7, 1, 0, 245, 6, 0, // Skip to: 11265
/* 9484 */    MCD_OPC_Decode, 212, 6, 22, // Opcode: MUL_U_rc
/* 9488 */    MCD_OPC_FilterValue, 3, 11, 0, 0, // Skip to: 9504
/* 9493 */    MCD_OPC_CheckField, 7, 1, 0, 229, 6, 0, // Skip to: 11265
/* 9500 */    MCD_OPC_Decode, 215, 6, 22, // Opcode: MUL_rc_e
/* 9504 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 9520
/* 9509 */    MCD_OPC_CheckField, 7, 1, 0, 213, 6, 0, // Skip to: 11265
/* 9516 */    MCD_OPC_Decode, 195, 6, 22, // Opcode: MULS_U_rc
/* 9520 */    MCD_OPC_FilterValue, 5, 204, 6, 0, // Skip to: 11265
/* 9525 */    MCD_OPC_CheckField, 7, 1, 0, 197, 6, 0, // Skip to: 11265
/* 9532 */    MCD_OPC_Decode, 197, 6, 22, // Opcode: MULS_rc
/* 9536 */    MCD_OPC_FilterValue, 85, 18, 0, 0, // Skip to: 9559
/* 9541 */    MCD_OPC_CheckField, 26, 2, 0, 181, 6, 0, // Skip to: 11265
/* 9548 */    MCD_OPC_CheckField, 7, 1, 1, 174, 6, 0, // Skip to: 11265
/* 9555 */    MCD_OPC_Decode, 246, 7, 36, // Opcode: ST_T
/* 9559 */    MCD_OPC_FilterValue, 87, 87, 0, 0, // Skip to: 9651
/* 9564 */    MCD_OPC_ExtractField, 21, 3,  // Inst{23-21} ...
/* 9567 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 9593
/* 9572 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9575 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9584
/* 9580 */    MCD_OPC_Decode, 187, 3, 26, // Opcode: INSERT_rrrw
/* 9584 */    MCD_OPC_FilterValue, 1, 140, 6, 0, // Skip to: 11265
/* 9589 */    MCD_OPC_Decode, 184, 3, 37, // Opcode: INSERT_rcrw
/* 9593 */    MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 9619
/* 9598 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9601 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9610
/* 9606 */    MCD_OPC_Decode, 181, 3, 26, // Opcode: IMASK_rrrw
/* 9610 */    MCD_OPC_FilterValue, 1, 114, 6, 0, // Skip to: 11265
/* 9615 */    MCD_OPC_Decode, 179, 3, 37, // Opcode: IMASK_rcrw
/* 9619 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 9635
/* 9624 */    MCD_OPC_CheckField, 7, 1, 0, 98, 6, 0, // Skip to: 11265
/* 9631 */    MCD_OPC_Decode, 159, 3, 26, // Opcode: EXTR_rrrw
/* 9635 */    MCD_OPC_FilterValue, 3, 89, 6, 0, // Skip to: 11265
/* 9640 */    MCD_OPC_CheckField, 7, 1, 0, 82, 6, 0, // Skip to: 11265
/* 9647 */    MCD_OPC_Decode, 156, 3, 26, // Opcode: EXTR_U_rrrw
/* 9651 */    MCD_OPC_FilterValue, 89, 21, 0, 0, // Skip to: 9677
/* 9656 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9659 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9668
/* 9664 */    MCD_OPC_Decode, 253, 7, 29, // Opcode: ST_W_bol
/* 9668 */    MCD_OPC_FilterValue, 1, 56, 6, 0, // Skip to: 11265
/* 9673 */    MCD_OPC_Decode, 208, 4, 29, // Opcode: LEA_bol
/* 9677 */    MCD_OPC_FilterValue, 93, 21, 0, 0, // Skip to: 9703
/* 9682 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9685 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9694
/* 9690 */    MCD_OPC_Decode, 220, 3, 30, // Opcode: JL_b
/* 9694 */    MCD_OPC_FilterValue, 1, 30, 6, 0, // Skip to: 11265
/* 9699 */    MCD_OPC_Decode, 212, 3, 30, // Opcode: JLA_b
/* 9703 */    MCD_OPC_FilterValue, 95, 55, 0, 0, // Skip to: 9763
/* 9708 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9711 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 9737
/* 9716 */    MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 9719 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9728
/* 9724 */    MCD_OPC_Decode, 199, 3, 31, // Opcode: JEQ_brr
/* 9728 */    MCD_OPC_FilterValue, 1, 252, 5, 0, // Skip to: 11265
/* 9733 */    MCD_OPC_Decode, 227, 3, 31, // Opcode: JNE_brr
/* 9737 */    MCD_OPC_FilterValue, 1, 243, 5, 0, // Skip to: 11265
/* 9742 */    MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 9745 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9754
/* 9750 */    MCD_OPC_Decode, 198, 3, 32, // Opcode: JEQ_brc
/* 9754 */    MCD_OPC_FilterValue, 1, 226, 5, 0, // Skip to: 11265
/* 9759 */    MCD_OPC_Decode, 226, 3, 32, // Opcode: JNE_brc
/* 9763 */    MCD_OPC_FilterValue, 97, 21, 0, 0, // Skip to: 9789
/* 9768 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9771 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9780
/* 9776 */    MCD_OPC_Decode, 162, 3, 30, // Opcode: FCALL_b
/* 9780 */    MCD_OPC_FilterValue, 1, 200, 5, 0, // Skip to: 11265
/* 9785 */    MCD_OPC_Decode, 160, 3, 30, // Opcode: FCALLA_b
/* 9789 */    MCD_OPC_FilterValue, 99, 219, 2, 0, // Skip to: 10525
/* 9794 */    MCD_OPC_ExtractField, 18, 6,  // Inst{23-18} ...
/* 9797 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 9813
/* 9802 */    MCD_OPC_CheckField, 7, 1, 0, 176, 5, 0, // Skip to: 11265
/* 9809 */    MCD_OPC_Decode, 171, 6, 17, // Opcode: MSUB_Q_rrr1_U
/* 9813 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 9829
/* 9818 */    MCD_OPC_CheckField, 7, 1, 0, 160, 5, 0, // Skip to: 11265
/* 9825 */    MCD_OPC_Decode, 169, 6, 17, // Opcode: MSUB_Q_rrr1_L
/* 9829 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 9845
/* 9834 */    MCD_OPC_CheckField, 7, 1, 0, 144, 5, 0, // Skip to: 11265
/* 9841 */    MCD_OPC_Decode, 168, 6, 17, // Opcode: MSUB_Q_rrr1
/* 9845 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 9861
/* 9850 */    MCD_OPC_CheckField, 7, 1, 0, 128, 5, 0, // Skip to: 11265
/* 9857 */    MCD_OPC_Decode, 172, 6, 17, // Opcode: MSUB_Q_rrr1_U_U
/* 9861 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 9877
/* 9866 */    MCD_OPC_CheckField, 7, 1, 0, 112, 5, 0, // Skip to: 11265
/* 9873 */    MCD_OPC_Decode, 170, 6, 17, // Opcode: MSUB_Q_rrr1_L_L
/* 9877 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 9893
/* 9882 */    MCD_OPC_CheckField, 7, 1, 0, 96, 5, 0, // Skip to: 11265
/* 9889 */    MCD_OPC_Decode, 140, 6, 17, // Opcode: MSUBR_Q_rrr1_U_U
/* 9893 */    MCD_OPC_FilterValue, 7, 11, 0, 0, // Skip to: 9909
/* 9898 */    MCD_OPC_CheckField, 7, 1, 0, 80, 5, 0, // Skip to: 11265
/* 9905 */    MCD_OPC_Decode, 139, 6, 17, // Opcode: MSUBR_Q_rrr1_L_L
/* 9909 */    MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 9925
/* 9914 */    MCD_OPC_CheckField, 7, 1, 1, 64, 5, 0, // Skip to: 11265
/* 9921 */    MCD_OPC_Decode, 237, 5, 17, // Opcode: MSUBADR_H_rrr1_UL
/* 9925 */    MCD_OPC_FilterValue, 13, 11, 0, 0, // Skip to: 9941
/* 9930 */    MCD_OPC_CheckField, 7, 1, 1, 48, 5, 0, // Skip to: 11265
/* 9937 */    MCD_OPC_Decode, 236, 5, 17, // Opcode: MSUBADR_H_rrr1_LU
/* 9941 */    MCD_OPC_FilterValue, 14, 11, 0, 0, // Skip to: 9957
/* 9946 */    MCD_OPC_CheckField, 7, 1, 1, 32, 5, 0, // Skip to: 11265
/* 9953 */    MCD_OPC_Decode, 235, 5, 17, // Opcode: MSUBADR_H_rrr1_LL
/* 9957 */    MCD_OPC_FilterValue, 15, 11, 0, 0, // Skip to: 9973
/* 9962 */    MCD_OPC_CheckField, 7, 1, 1, 16, 5, 0, // Skip to: 11265
/* 9969 */    MCD_OPC_Decode, 238, 5, 17, // Opcode: MSUBADR_H_rrr1_UU
/* 9973 */    MCD_OPC_FilterValue, 24, 21, 0, 0, // Skip to: 9999
/* 9978 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 9981 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 9990
/* 9986 */    MCD_OPC_Decode, 176, 6, 17, // Opcode: MSUB_Q_rrr1_e_U
/* 9990 */    MCD_OPC_FilterValue, 1, 246, 4, 0, // Skip to: 11265
/* 9995 */    MCD_OPC_Decode, 245, 5, 17, // Opcode: MSUBAD_H_rrr1_UL
/* 9999 */    MCD_OPC_FilterValue, 25, 21, 0, 0, // Skip to: 10025
/* 10004 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10007 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10016
/* 10012 */   MCD_OPC_Decode, 174, 6, 17, // Opcode: MSUB_Q_rrr1_e_L
/* 10016 */   MCD_OPC_FilterValue, 1, 220, 4, 0, // Skip to: 11265
/* 10021 */   MCD_OPC_Decode, 244, 5, 17, // Opcode: MSUBAD_H_rrr1_LU
/* 10025 */   MCD_OPC_FilterValue, 26, 11, 0, 0, // Skip to: 10041
/* 10030 */   MCD_OPC_CheckField, 7, 1, 1, 204, 4, 0, // Skip to: 11265
/* 10037 */   MCD_OPC_Decode, 243, 5, 17, // Opcode: MSUBAD_H_rrr1_LL
/* 10041 */   MCD_OPC_FilterValue, 27, 21, 0, 0, // Skip to: 10067
/* 10046 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10049 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10058
/* 10054 */   MCD_OPC_Decode, 173, 6, 17, // Opcode: MSUB_Q_rrr1_e
/* 10058 */   MCD_OPC_FilterValue, 1, 178, 4, 0, // Skip to: 11265
/* 10063 */   MCD_OPC_Decode, 246, 5, 17, // Opcode: MSUBAD_H_rrr1_UU
/* 10067 */   MCD_OPC_FilterValue, 28, 21, 0, 0, // Skip to: 10093
/* 10072 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10075 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10084
/* 10080 */   MCD_OPC_Decode, 177, 6, 17, // Opcode: MSUB_Q_rrr1_e_U_U
/* 10084 */   MCD_OPC_FilterValue, 1, 152, 4, 0, // Skip to: 11265
/* 10089 */   MCD_OPC_Decode, 229, 5, 17, // Opcode: MSUBADM_H_rrr1_UL
/* 10093 */   MCD_OPC_FilterValue, 29, 21, 0, 0, // Skip to: 10119
/* 10098 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10101 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10110
/* 10106 */   MCD_OPC_Decode, 175, 6, 17, // Opcode: MSUB_Q_rrr1_e_L_L
/* 10110 */   MCD_OPC_FilterValue, 1, 126, 4, 0, // Skip to: 11265
/* 10115 */   MCD_OPC_Decode, 228, 5, 17, // Opcode: MSUBADM_H_rrr1_LU
/* 10119 */   MCD_OPC_FilterValue, 30, 21, 0, 0, // Skip to: 10145
/* 10124 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10127 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10136
/* 10132 */   MCD_OPC_Decode, 134, 6, 17, // Opcode: MSUBR_H_rrr1_DcEdDaDbUL
/* 10136 */   MCD_OPC_FilterValue, 1, 100, 4, 0, // Skip to: 11265
/* 10141 */   MCD_OPC_Decode, 227, 5, 17, // Opcode: MSUBADM_H_rrr1_LL
/* 10145 */   MCD_OPC_FilterValue, 31, 11, 0, 0, // Skip to: 10161
/* 10150 */   MCD_OPC_CheckField, 7, 1, 1, 84, 4, 0, // Skip to: 11265
/* 10157 */   MCD_OPC_Decode, 230, 5, 17, // Opcode: MSUBADM_H_rrr1_UU
/* 10161 */   MCD_OPC_FilterValue, 32, 11, 0, 0, // Skip to: 10177
/* 10166 */   MCD_OPC_CheckField, 7, 1, 0, 68, 4, 0, // Skip to: 11265
/* 10173 */   MCD_OPC_Decode, 148, 6, 17, // Opcode: MSUBS_Q_rrr1_U
/* 10177 */   MCD_OPC_FilterValue, 33, 11, 0, 0, // Skip to: 10193
/* 10182 */   MCD_OPC_CheckField, 7, 1, 0, 52, 4, 0, // Skip to: 11265
/* 10189 */   MCD_OPC_Decode, 146, 6, 17, // Opcode: MSUBS_Q_rrr1_L
/* 10193 */   MCD_OPC_FilterValue, 34, 11, 0, 0, // Skip to: 10209
/* 10198 */   MCD_OPC_CheckField, 7, 1, 0, 36, 4, 0, // Skip to: 11265
/* 10205 */   MCD_OPC_Decode, 145, 6, 17, // Opcode: MSUBS_Q_rrr1
/* 10209 */   MCD_OPC_FilterValue, 36, 11, 0, 0, // Skip to: 10225
/* 10214 */   MCD_OPC_CheckField, 7, 1, 0, 20, 4, 0, // Skip to: 11265
/* 10221 */   MCD_OPC_Decode, 149, 6, 17, // Opcode: MSUBS_Q_rrr1_U_U
/* 10225 */   MCD_OPC_FilterValue, 37, 11, 0, 0, // Skip to: 10241
/* 10230 */   MCD_OPC_CheckField, 7, 1, 0, 4, 4, 0, // Skip to: 11265
/* 10237 */   MCD_OPC_Decode, 147, 6, 17, // Opcode: MSUBS_Q_rrr1_L_L
/* 10241 */   MCD_OPC_FilterValue, 38, 11, 0, 0, // Skip to: 10257
/* 10246 */   MCD_OPC_CheckField, 7, 1, 0, 244, 3, 0, // Skip to: 11265
/* 10253 */   MCD_OPC_Decode, 133, 6, 17, // Opcode: MSUBRS_Q_rrr1_U_U
/* 10257 */   MCD_OPC_FilterValue, 39, 11, 0, 0, // Skip to: 10273
/* 10262 */   MCD_OPC_CheckField, 7, 1, 0, 228, 3, 0, // Skip to: 11265
/* 10269 */   MCD_OPC_Decode, 132, 6, 17, // Opcode: MSUBRS_Q_rrr1_L_L
/* 10273 */   MCD_OPC_FilterValue, 44, 11, 0, 0, // Skip to: 10289
/* 10278 */   MCD_OPC_CheckField, 7, 1, 1, 212, 3, 0, // Skip to: 11265
/* 10285 */   MCD_OPC_Decode, 233, 5, 17, // Opcode: MSUBADRS_H_rrr1_UL
/* 10289 */   MCD_OPC_FilterValue, 45, 11, 0, 0, // Skip to: 10305
/* 10294 */   MCD_OPC_CheckField, 7, 1, 1, 196, 3, 0, // Skip to: 11265
/* 10301 */   MCD_OPC_Decode, 232, 5, 17, // Opcode: MSUBADRS_H_rrr1_LU
/* 10305 */   MCD_OPC_FilterValue, 46, 11, 0, 0, // Skip to: 10321
/* 10310 */   MCD_OPC_CheckField, 7, 1, 1, 180, 3, 0, // Skip to: 11265
/* 10317 */   MCD_OPC_Decode, 231, 5, 17, // Opcode: MSUBADRS_H_rrr1_LL
/* 10321 */   MCD_OPC_FilterValue, 47, 11, 0, 0, // Skip to: 10337
/* 10326 */   MCD_OPC_CheckField, 7, 1, 1, 164, 3, 0, // Skip to: 11265
/* 10333 */   MCD_OPC_Decode, 234, 5, 17, // Opcode: MSUBADRS_H_rrr1_UU
/* 10337 */   MCD_OPC_FilterValue, 56, 21, 0, 0, // Skip to: 10363
/* 10342 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10345 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10354
/* 10350 */   MCD_OPC_Decode, 153, 6, 17, // Opcode: MSUBS_Q_rrr1_e_U
/* 10354 */   MCD_OPC_FilterValue, 1, 138, 3, 0, // Skip to: 11265
/* 10359 */   MCD_OPC_Decode, 241, 5, 17, // Opcode: MSUBADS_H_rrr1_UL
/* 10363 */   MCD_OPC_FilterValue, 57, 21, 0, 0, // Skip to: 10389
/* 10368 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10371 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10380
/* 10376 */   MCD_OPC_Decode, 151, 6, 17, // Opcode: MSUBS_Q_rrr1_e_L
/* 10380 */   MCD_OPC_FilterValue, 1, 112, 3, 0, // Skip to: 11265
/* 10385 */   MCD_OPC_Decode, 240, 5, 17, // Opcode: MSUBADS_H_rrr1_LU
/* 10389 */   MCD_OPC_FilterValue, 58, 11, 0, 0, // Skip to: 10405
/* 10394 */   MCD_OPC_CheckField, 7, 1, 1, 96, 3, 0, // Skip to: 11265
/* 10401 */   MCD_OPC_Decode, 239, 5, 17, // Opcode: MSUBADS_H_rrr1_LL
/* 10405 */   MCD_OPC_FilterValue, 59, 21, 0, 0, // Skip to: 10431
/* 10410 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10413 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10422
/* 10418 */   MCD_OPC_Decode, 150, 6, 17, // Opcode: MSUBS_Q_rrr1_e
/* 10422 */   MCD_OPC_FilterValue, 1, 70, 3, 0, // Skip to: 11265
/* 10427 */   MCD_OPC_Decode, 242, 5, 17, // Opcode: MSUBADS_H_rrr1_UU
/* 10431 */   MCD_OPC_FilterValue, 60, 21, 0, 0, // Skip to: 10457
/* 10436 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10439 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10448
/* 10444 */   MCD_OPC_Decode, 154, 6, 17, // Opcode: MSUBS_Q_rrr1_e_U_U
/* 10448 */   MCD_OPC_FilterValue, 1, 44, 3, 0, // Skip to: 11265
/* 10453 */   MCD_OPC_Decode, 225, 5, 17, // Opcode: MSUBADMS_H_rrr1_UL
/* 10457 */   MCD_OPC_FilterValue, 61, 21, 0, 0, // Skip to: 10483
/* 10462 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10465 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10474
/* 10470 */   MCD_OPC_Decode, 152, 6, 17, // Opcode: MSUBS_Q_rrr1_e_L_L
/* 10474 */   MCD_OPC_FilterValue, 1, 18, 3, 0, // Skip to: 11265
/* 10479 */   MCD_OPC_Decode, 224, 5, 17, // Opcode: MSUBADMS_H_rrr1_LU
/* 10483 */   MCD_OPC_FilterValue, 62, 21, 0, 0, // Skip to: 10509
/* 10488 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10491 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10500
/* 10496 */   MCD_OPC_Decode, 255, 5, 17, // Opcode: MSUBRS_H_rrr1_DcEdDaDbUL
/* 10500 */   MCD_OPC_FilterValue, 1, 248, 2, 0, // Skip to: 11265
/* 10505 */   MCD_OPC_Decode, 223, 5, 17, // Opcode: MSUBADMS_H_rrr1_LL
/* 10509 */   MCD_OPC_FilterValue, 63, 239, 2, 0, // Skip to: 11265
/* 10514 */   MCD_OPC_CheckField, 7, 1, 1, 232, 2, 0, // Skip to: 11265
/* 10521 */   MCD_OPC_Decode, 226, 5, 17, // Opcode: MSUBADMS_H_rrr1_UU
/* 10525 */   MCD_OPC_FilterValue, 101, 45, 0, 0, // Skip to: 10575
/* 10530 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10533 */   MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 10549
/* 10538 */   MCD_OPC_CheckField, 26, 2, 0, 208, 2, 0, // Skip to: 11265
/* 10545 */   MCD_OPC_Decode, 240, 7, 18, // Opcode: ST_Q_abs
/* 10549 */   MCD_OPC_FilterValue, 1, 199, 2, 0, // Skip to: 11265
/* 10554 */   MCD_OPC_ExtractField, 26, 2,  // Inst{27-26} ...
/* 10557 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10566
/* 10562 */   MCD_OPC_Decode, 152, 8, 18, // Opcode: SWAP_W_abs
/* 10566 */   MCD_OPC_FilterValue, 1, 182, 2, 0, // Skip to: 11265
/* 10571 */   MCD_OPC_Decode, 248, 3, 18, // Opcode: LDMST_abs
/* 10575 */   MCD_OPC_FilterValue, 103, 35, 0, 0, // Skip to: 10615
/* 10580 */   MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 10583 */   MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 10599
/* 10588 */   MCD_OPC_CheckField, 7, 1, 0, 158, 2, 0, // Skip to: 11265
/* 10595 */   MCD_OPC_Decode, 189, 3, 19, // Opcode: INS_T
/* 10599 */   MCD_OPC_FilterValue, 1, 149, 2, 0, // Skip to: 11265
/* 10604 */   MCD_OPC_CheckField, 7, 1, 0, 142, 2, 0, // Skip to: 11265
/* 10611 */   MCD_OPC_Decode, 188, 3, 19, // Opcode: INSN_T
/* 10615 */   MCD_OPC_FilterValue, 105, 92, 0, 0, // Skip to: 10712
/* 10620 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10623 */   MCD_OPC_FilterValue, 0, 75, 0, 0, // Skip to: 10703
/* 10628 */   MCD_OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 10631 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10640
/* 10636 */   MCD_OPC_Decode, 157, 8, 20, // Opcode: SWAP_W_bo_r
/* 10640 */   MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 10649
/* 10645 */   MCD_OPC_Decode, 253, 3, 20, // Opcode: LDMST_bo_r
/* 10649 */   MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 10658
/* 10654 */   MCD_OPC_Decode, 151, 8, 20, // Opcode: SWAPMSK_W_bo_r
/* 10658 */   MCD_OPC_FilterValue, 3, 4, 0, 0, // Skip to: 10667
/* 10663 */   MCD_OPC_Decode, 241, 2, 20, // Opcode: CMPSWAP_W_bo_r
/* 10667 */   MCD_OPC_FilterValue, 16, 4, 0, 0, // Skip to: 10676
/* 10672 */   MCD_OPC_Decode, 154, 8, 20, // Opcode: SWAP_W_bo_c
/* 10676 */   MCD_OPC_FilterValue, 17, 4, 0, 0, // Skip to: 10685
/* 10681 */   MCD_OPC_Decode, 250, 3, 20, // Opcode: LDMST_bo_c
/* 10685 */   MCD_OPC_FilterValue, 18, 4, 0, 0, // Skip to: 10694
/* 10690 */   MCD_OPC_Decode, 148, 8, 20, // Opcode: SWAPMSK_W_bo_c
/* 10694 */   MCD_OPC_FilterValue, 19, 54, 2, 0, // Skip to: 11265
/* 10699 */   MCD_OPC_Decode, 238, 2, 20, // Opcode: CMPSWAP_W_bo_c
/* 10703 */   MCD_OPC_FilterValue, 1, 45, 2, 0, // Skip to: 11265
/* 10708 */   MCD_OPC_Decode, 212, 7, 29, // Opcode: ST_B_bol
/* 10712 */   MCD_OPC_FilterValue, 107, 211, 0, 0, // Skip to: 10928
/* 10717 */   MCD_OPC_ExtractField, 18, 6,  // Inst{23-18} ...
/* 10720 */   MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 10736
/* 10725 */   MCD_OPC_CheckField, 7, 1, 0, 21, 2, 0, // Skip to: 11265
/* 10732 */   MCD_OPC_Decode, 128, 7, 33, // Opcode: PACK_rrr
/* 10736 */   MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 10752
/* 10741 */   MCD_OPC_CheckField, 7, 1, 0, 5, 2, 0, // Skip to: 11265
/* 10748 */   MCD_OPC_Decode, 246, 2, 33, // Opcode: CRCN_rrr
/* 10752 */   MCD_OPC_FilterValue, 8, 11, 0, 0, // Skip to: 10768
/* 10757 */   MCD_OPC_CheckField, 7, 1, 0, 245, 1, 0, // Skip to: 11265
/* 10764 */   MCD_OPC_Decode, 153, 2, 33, // Opcode: ADD_F_rrr
/* 10768 */   MCD_OPC_FilterValue, 12, 11, 0, 0, // Skip to: 10784
/* 10773 */   MCD_OPC_CheckField, 7, 1, 0, 229, 1, 0, // Skip to: 11265
/* 10780 */   MCD_OPC_Decode, 140, 8, 33, // Opcode: SUB_F_rrr
/* 10784 */   MCD_OPC_FilterValue, 24, 11, 0, 0, // Skip to: 10800
/* 10789 */   MCD_OPC_CheckField, 7, 1, 0, 213, 1, 0, // Skip to: 11265
/* 10796 */   MCD_OPC_Decode, 166, 5, 33, // Opcode: MADD_F_rrr
/* 10800 */   MCD_OPC_FilterValue, 28, 11, 0, 0, // Skip to: 10816
/* 10805 */   MCD_OPC_CheckField, 7, 1, 0, 197, 1, 0, // Skip to: 11265
/* 10812 */   MCD_OPC_Decode, 163, 6, 33, // Opcode: MSUB_F_rrr
/* 10816 */   MCD_OPC_FilterValue, 32, 11, 0, 0, // Skip to: 10832
/* 10821 */   MCD_OPC_CheckField, 7, 1, 0, 181, 1, 0, // Skip to: 11265
/* 10828 */   MCD_OPC_Decode, 195, 3, 33, // Opcode: IXMIN_rrr
/* 10832 */   MCD_OPC_FilterValue, 36, 11, 0, 0, // Skip to: 10848
/* 10837 */   MCD_OPC_CheckField, 7, 1, 0, 165, 1, 0, // Skip to: 11265
/* 10844 */   MCD_OPC_Decode, 194, 3, 33, // Opcode: IXMIN_U_rrr
/* 10848 */   MCD_OPC_FilterValue, 40, 11, 0, 0, // Skip to: 10864
/* 10853 */   MCD_OPC_CheckField, 7, 1, 0, 149, 1, 0, // Skip to: 11265
/* 10860 */   MCD_OPC_Decode, 193, 3, 33, // Opcode: IXMAX_rrr
/* 10864 */   MCD_OPC_FilterValue, 44, 11, 0, 0, // Skip to: 10880
/* 10869 */   MCD_OPC_CheckField, 7, 1, 0, 133, 1, 0, // Skip to: 11265
/* 10876 */   MCD_OPC_Decode, 192, 3, 33, // Opcode: IXMAX_U_rrr
/* 10880 */   MCD_OPC_FilterValue, 52, 11, 0, 0, // Skip to: 10896
/* 10885 */   MCD_OPC_CheckField, 7, 1, 0, 117, 1, 0, // Skip to: 11265
/* 10892 */   MCD_OPC_Decode, 131, 3, 33, // Opcode: DVADJ_rrr
/* 10896 */   MCD_OPC_FilterValue, 56, 11, 0, 0, // Skip to: 10912
/* 10901 */   MCD_OPC_CheckField, 7, 1, 0, 101, 1, 0, // Skip to: 11265
/* 10908 */   MCD_OPC_Decode, 138, 3, 33, // Opcode: DVSTEP_U_rrr
/* 10912 */   MCD_OPC_FilterValue, 60, 92, 1, 0, // Skip to: 11265
/* 10917 */   MCD_OPC_CheckField, 7, 1, 0, 85, 1, 0, // Skip to: 11265
/* 10924 */   MCD_OPC_Decode, 139, 3, 33, // Opcode: DVSTEP_rrr
/* 10928 */   MCD_OPC_FilterValue, 109, 21, 0, 0, // Skip to: 10954
/* 10933 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 10936 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10945
/* 10941 */   MCD_OPC_Decode, 225, 2, 30, // Opcode: CALL_b
/* 10945 */   MCD_OPC_FilterValue, 1, 59, 1, 0, // Skip to: 11265
/* 10950 */   MCD_OPC_Decode, 223, 2, 30, // Opcode: CALLA_b
/* 10954 */   MCD_OPC_FilterValue, 111, 21, 0, 0, // Skip to: 10980
/* 10959 */   MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 10962 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 10971
/* 10967 */   MCD_OPC_Decode, 240, 3, 38, // Opcode: JZ_T_brn
/* 10971 */   MCD_OPC_FilterValue, 1, 33, 1, 0, // Skip to: 11265
/* 10976 */   MCD_OPC_Decode, 234, 3, 38, // Opcode: JNZ_T_brn
/* 10980 */   MCD_OPC_FilterValue, 115, 85, 0, 0, // Skip to: 11070
/* 10985 */   MCD_OPC_ExtractField, 16, 12,  // Inst{27-16} ...
/* 10988 */   MCD_OPC_FilterValue, 10, 11, 0, 0, // Skip to: 11004
/* 10993 */   MCD_OPC_CheckField, 7, 1, 0, 9, 1, 0, // Skip to: 11265
/* 11000 */   MCD_OPC_Decode, 216, 6, 21, // Opcode: MUL_rr2
/* 11004 */   MCD_OPC_FilterValue, 104, 11, 0, 0, // Skip to: 11020
/* 11009 */   MCD_OPC_CheckField, 7, 1, 0, 249, 0, 0, // Skip to: 11265
/* 11016 */   MCD_OPC_Decode, 213, 6, 21, // Opcode: MUL_U_rr2
/* 11020 */   MCD_OPC_FilterValue, 106, 11, 0, 0, // Skip to: 11036
/* 11025 */   MCD_OPC_CheckField, 7, 1, 0, 233, 0, 0, // Skip to: 11265
/* 11032 */   MCD_OPC_Decode, 217, 6, 21, // Opcode: MUL_rr2_e
/* 11036 */   MCD_OPC_FilterValue, 136, 1, 11, 0, 0, // Skip to: 11053
/* 11042 */   MCD_OPC_CheckField, 7, 1, 0, 216, 0, 0, // Skip to: 11265
/* 11049 */   MCD_OPC_Decode, 196, 6, 21, // Opcode: MULS_U_rr2
/* 11053 */   MCD_OPC_FilterValue, 138, 1, 206, 0, 0, // Skip to: 11265
/* 11059 */   MCD_OPC_CheckField, 7, 1, 0, 199, 0, 0, // Skip to: 11265
/* 11066 */   MCD_OPC_Decode, 198, 6, 21, // Opcode: MULS_rr2
/* 11070 */   MCD_OPC_FilterValue, 119, 18, 0, 0, // Skip to: 11093
/* 11075 */   MCD_OPC_CheckField, 21, 2, 0, 183, 0, 0, // Skip to: 11265
/* 11082 */   MCD_OPC_CheckField, 7, 1, 0, 176, 0, 0, // Skip to: 11265
/* 11089 */   MCD_OPC_Decode, 251, 2, 34, // Opcode: DEXTR_rrpw
/* 11093 */   MCD_OPC_FilterValue, 121, 21, 0, 0, // Skip to: 11119
/* 11098 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 11101 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 11110
/* 11106 */   MCD_OPC_Decode, 157, 4, 29, // Opcode: LD_B_bol
/* 11110 */   MCD_OPC_FilterValue, 1, 150, 0, 0, // Skip to: 11265
/* 11115 */   MCD_OPC_Decode, 235, 7, 29, // Opcode: ST_H_bol
/* 11119 */   MCD_OPC_FilterValue, 123, 21, 0, 0, // Skip to: 11145
/* 11124 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 11127 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 11136
/* 11132 */   MCD_OPC_Decode, 205, 5, 23, // Opcode: MOVH_rlc
/* 11136 */   MCD_OPC_FilterValue, 1, 124, 0, 0, // Skip to: 11265
/* 11141 */   MCD_OPC_Decode, 215, 5, 23, // Opcode: MOV_rlcEc
/* 11145 */   MCD_OPC_FilterValue, 125, 55, 0, 0, // Skip to: 11205
/* 11150 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 11153 */   MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 11179
/* 11158 */   MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 11161 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 11170
/* 11166 */   MCD_OPC_Decode, 197, 3, 31, // Opcode: JEQ_A_brr
/* 11170 */   MCD_OPC_FilterValue, 1, 90, 0, 0, // Skip to: 11265
/* 11175 */   MCD_OPC_Decode, 225, 3, 31, // Opcode: JNE_A_brr
/* 11179 */   MCD_OPC_FilterValue, 1, 81, 0, 0, // Skip to: 11265
/* 11184 */   MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 11187 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 11196
/* 11192 */   MCD_OPC_Decode, 211, 4, 31, // Opcode: LOOP_brr
/* 11196 */   MCD_OPC_FilterValue, 1, 64, 0, 0, // Skip to: 11265
/* 11201 */   MCD_OPC_Decode, 210, 4, 31, // Opcode: LOOPU_brr
/* 11205 */   MCD_OPC_FilterValue, 127, 55, 0, 0, // Skip to: 11265
/* 11210 */   MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 11213 */   MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 11239
/* 11218 */   MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 11221 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 11230
/* 11226 */   MCD_OPC_Decode, 208, 3, 31, // Opcode: JGE_brr
/* 11230 */   MCD_OPC_FilterValue, 1, 30, 0, 0, // Skip to: 11265
/* 11235 */   MCD_OPC_Decode, 206, 3, 31, // Opcode: JGE_U_brr
/* 11239 */   MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 11265
/* 11244 */   MCD_OPC_ExtractField, 31, 1,  // Inst{31} ...
/* 11247 */   MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 11256
/* 11252 */   MCD_OPC_Decode, 207, 3, 32, // Opcode: JGE_brc
/* 11256 */   MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 11265
/* 11261 */   MCD_OPC_Decode, 205, 3, 32, // Opcode: JGE_U_brc
/* 11265 */   MCD_OPC_Fail,
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
