/* Capstone Disassembly Engine, https://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/*    Rot127 <unisono@quyllur.org> 2022-2024 */
/* Automatically generated file by Capstone's LLVM TableGen Disassembler Backend. */

/* LLVM-commit: <commit> */
/* LLVM-tag: <tag> */

/* Do not edit. */

/* Capstone's LLVM TableGen Backends: */
/* https://github.com/capstone-engine/llvm-capstone */

#include "../../MCInst.h"
#include "../../cs_priv.h"
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

static bool Check(DecodeStatus *Out, const DecodeStatus In) {
  *Out = (DecodeStatus) (*Out & In);
  return *Out != MCDisassembler_Fail;
}

static const uint8_t DecoderTable16[] = {
/* 0 */       MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 3 */       MCD_OPC_FilterValue, 8, 21, 0, 0, // Skip to: 29
/* 8 */       MCD_OPC_ExtractField, 2, 1,  // Inst{2} ...
/* 11 */      MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 20
/* 16 */      MCD_OPC_Decode, 247, 2, 0, // Opcode: COMPACT_MOV_S_hreg
/* 20 */      MCD_OPC_FilterValue, 1, 209, 4, 0, // Skip to: 1258
/* 25 */      MCD_OPC_Decode, 246, 2, 1, // Opcode: COMPACT_LD_S
/* 29 */      MCD_OPC_FilterValue, 9, 38, 0, 0, // Skip to: 72
/* 34 */      MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 37 */      MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 63
/* 42 */      MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 45 */      MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 54
/* 50 */      MCD_OPC_Decode, 228, 3, 2, // Opcode: LD_S_AS_rrr
/* 54 */      MCD_OPC_FilterValue, 1, 175, 4, 0, // Skip to: 1258
/* 59 */      MCD_OPC_Decode, 184, 5, 2, // Opcode: SUB_S_rrr
/* 63 */      MCD_OPC_FilterValue, 1, 166, 4, 0, // Skip to: 1258
/* 68 */      MCD_OPC_Decode, 167, 2, 3, // Opcode: ADD_S_rru6
/* 72 */      MCD_OPC_FilterValue, 10, 38, 0, 0, // Skip to: 115
/* 77 */      MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 80 */      MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 106
/* 85 */      MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 88 */      MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 97
/* 93 */      MCD_OPC_Decode, 231, 3, 4, // Opcode: LD_S_s11
/* 97 */      MCD_OPC_FilterValue, 1, 132, 4, 0, // Skip to: 1258
/* 102 */     MCD_OPC_Decode, 151, 5, 4, // Opcode: ST_S_s11
/* 106 */     MCD_OPC_FilterValue, 1, 123, 4, 0, // Skip to: 1258
/* 111 */     MCD_OPC_Decode, 220, 3, 5, // Opcode: LDI_S_u7
/* 115 */     MCD_OPC_FilterValue, 11, 21, 0, 0, // Skip to: 141
/* 120 */     MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 123 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 132
/* 128 */     MCD_OPC_Decode, 171, 3, 6, // Opcode: JLI_S
/* 132 */     MCD_OPC_FilterValue, 1, 97, 4, 0, // Skip to: 1258
/* 137 */     MCD_OPC_Decode, 249, 2, 6, // Opcode: EI_S
/* 141 */     MCD_OPC_FilterValue, 12, 39, 0, 0, // Skip to: 185
/* 146 */     MCD_OPC_ExtractField, 3, 2,  // Inst{4-3} ...
/* 149 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 158
/* 154 */     MCD_OPC_Decode, 230, 3, 2, // Opcode: LD_S_rrr
/* 158 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 167
/* 163 */     MCD_OPC_Decode, 183, 3, 2, // Opcode: LDB_S_rrr
/* 167 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 176
/* 172 */     MCD_OPC_Decode, 206, 3, 2, // Opcode: LDH_S_rrr
/* 176 */     MCD_OPC_FilterValue, 3, 53, 4, 0, // Skip to: 1258
/* 181 */     MCD_OPC_Decode, 166, 2, 2, // Opcode: ADD_S_rrr
/* 185 */     MCD_OPC_FilterValue, 13, 39, 0, 0, // Skip to: 229
/* 190 */     MCD_OPC_ExtractField, 3, 2,  // Inst{4-3} ...
/* 193 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 202
/* 198 */     MCD_OPC_Decode, 169, 2, 7, // Opcode: ADD_S_ru3
/* 202 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 211
/* 207 */     MCD_OPC_Decode, 185, 5, 7, // Opcode: SUB_S_ru3
/* 211 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 220
/* 216 */     MCD_OPC_Decode, 191, 2, 7, // Opcode: ASL_S_ru3
/* 220 */     MCD_OPC_FilterValue, 3, 9, 4, 0, // Skip to: 1258
/* 225 */     MCD_OPC_Decode, 203, 2, 7, // Opcode: ASR_S_ru3
/* 229 */     MCD_OPC_FilterValue, 14, 75, 0, 0, // Skip to: 309
/* 234 */     MCD_OPC_ExtractField, 2, 3,  // Inst{4-2} ...
/* 237 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 246
/* 242 */     MCD_OPC_Decode, 165, 2, 8, // Opcode: ADD_S_rr
/* 246 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 255
/* 251 */     MCD_OPC_Decode, 168, 2, 9, // Opcode: ADD_S_rs3
/* 255 */     MCD_OPC_FilterValue, 3, 22, 0, 0, // Skip to: 282
/* 260 */     MCD_OPC_CheckField, 5, 3, 6, 11, 0, 0, // Skip to: 278
/* 267 */     MCD_OPC_CheckField, 0, 2, 3, 4, 0, 0, // Skip to: 278
/* 274 */     MCD_OPC_Decode, 144, 4, 10, // Opcode: MOV_S_s3
/* 278 */     MCD_OPC_Decode, 143, 4, 9, // Opcode: MOV_S_rs3
/* 282 */     MCD_OPC_FilterValue, 4, 4, 0, 0, // Skip to: 291
/* 287 */     MCD_OPC_Decode, 240, 2, 8, // Opcode: CMP_S_rr
/* 291 */     MCD_OPC_FilterValue, 5, 4, 0, 0, // Skip to: 300
/* 296 */     MCD_OPC_Decode, 241, 2, 9, // Opcode: CMP_S_rs3
/* 300 */     MCD_OPC_FilterValue, 7, 185, 3, 0, // Skip to: 1258
/* 305 */     MCD_OPC_Decode, 142, 4, 8, // Opcode: MOV_S_NE_rr
/* 309 */     MCD_OPC_FilterValue, 15, 121, 1, 0, // Skip to: 691
/* 314 */     MCD_OPC_ExtractField, 0, 5,  // Inst{4-0} ...
/* 317 */     MCD_OPC_FilterValue, 0, 119, 0, 0, // Skip to: 441
/* 322 */     MCD_OPC_ExtractField, 5, 3,  // Inst{7-5} ...
/* 325 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 334
/* 330 */     MCD_OPC_Decode, 144, 3, 11, // Opcode: GEN_J_S
/* 334 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 343
/* 339 */     MCD_OPC_Decode, 145, 3, 11, // Opcode: GEN_J_S_D
/* 343 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 352
/* 348 */     MCD_OPC_Decode, 141, 3, 11, // Opcode: GEN_JL_S
/* 352 */     MCD_OPC_FilterValue, 3, 4, 0, 0, // Skip to: 361
/* 357 */     MCD_OPC_Decode, 142, 3, 11, // Opcode: GEN_JL_S_D
/* 361 */     MCD_OPC_FilterValue, 6, 4, 0, 0, // Skip to: 370
/* 366 */     MCD_OPC_Decode, 159, 3, 11, // Opcode: GEN_SUB_S_NE
/* 370 */     MCD_OPC_FilterValue, 7, 115, 3, 0, // Skip to: 1258
/* 375 */     MCD_OPC_ExtractField, 8, 3,  // Inst{10-8} ...
/* 378 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 387
/* 383 */     MCD_OPC_Decode, 153, 3, 12, // Opcode: GEN_NOP_S
/* 387 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 396
/* 392 */     MCD_OPC_Decode, 163, 3, 12, // Opcode: GEN_UNIMP_S
/* 396 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 405
/* 401 */     MCD_OPC_Decode, 160, 3, 12, // Opcode: GEN_SWI_S
/* 405 */     MCD_OPC_FilterValue, 4, 4, 0, 0, // Skip to: 414
/* 410 */     MCD_OPC_Decode, 140, 3, 12, // Opcode: GEN_JEQ_S
/* 414 */     MCD_OPC_FilterValue, 5, 4, 0, 0, // Skip to: 423
/* 419 */     MCD_OPC_Decode, 143, 3, 12, // Opcode: GEN_JNE_S
/* 423 */     MCD_OPC_FilterValue, 6, 4, 0, 0, // Skip to: 432
/* 428 */     MCD_OPC_Decode, 174, 3, 12, // Opcode: J_S_BLINK
/* 432 */     MCD_OPC_FilterValue, 7, 53, 3, 0, // Skip to: 1258
/* 437 */     MCD_OPC_Decode, 146, 3, 12, // Opcode: GEN_J_S_D_BLINK
/* 441 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 450
/* 446 */     MCD_OPC_Decode, 158, 3, 13, // Opcode: GEN_SUB_S
/* 450 */     MCD_OPC_FilterValue, 4, 4, 0, 0, // Skip to: 459
/* 455 */     MCD_OPC_Decode, 131, 3, 13, // Opcode: GEN_AND_S
/* 459 */     MCD_OPC_FilterValue, 5, 4, 0, 0, // Skip to: 468
/* 464 */     MCD_OPC_Decode, 155, 3, 13, // Opcode: GEN_OR_S
/* 468 */     MCD_OPC_FilterValue, 6, 4, 0, 0, // Skip to: 477
/* 473 */     MCD_OPC_Decode, 136, 3, 13, // Opcode: GEN_BIC_S
/* 477 */     MCD_OPC_FilterValue, 7, 4, 0, 0, // Skip to: 486
/* 482 */     MCD_OPC_Decode, 164, 3, 13, // Opcode: GEN_XOR_S
/* 486 */     MCD_OPC_FilterValue, 9, 4, 0, 0, // Skip to: 495
/* 491 */     MCD_OPC_Decode, 150, 3, 13, // Opcode: GEN_MPYW_S
/* 495 */     MCD_OPC_FilterValue, 10, 4, 0, 0, // Skip to: 504
/* 500 */     MCD_OPC_Decode, 149, 3, 13, // Opcode: GEN_MPYUW_S
/* 504 */     MCD_OPC_FilterValue, 11, 4, 0, 0, // Skip to: 513
/* 509 */     MCD_OPC_Decode, 162, 3, 13, // Opcode: GEN_TST_S
/* 513 */     MCD_OPC_FilterValue, 12, 4, 0, 0, // Skip to: 522
/* 518 */     MCD_OPC_Decode, 151, 3, 13, // Opcode: GEN_MPY_S
/* 522 */     MCD_OPC_FilterValue, 13, 4, 0, 0, // Skip to: 531
/* 527 */     MCD_OPC_Decode, 156, 3, 13, // Opcode: GEN_SEXB_S
/* 531 */     MCD_OPC_FilterValue, 14, 4, 0, 0, // Skip to: 540
/* 536 */     MCD_OPC_Decode, 157, 3, 13, // Opcode: GEN_SEXH_S
/* 540 */     MCD_OPC_FilterValue, 15, 4, 0, 0, // Skip to: 549
/* 545 */     MCD_OPC_Decode, 138, 3, 13, // Opcode: GEN_EXTB_S
/* 549 */     MCD_OPC_FilterValue, 16, 4, 0, 0, // Skip to: 558
/* 554 */     MCD_OPC_Decode, 139, 3, 13, // Opcode: GEN_EXTH_S
/* 558 */     MCD_OPC_FilterValue, 17, 4, 0, 0, // Skip to: 567
/* 563 */     MCD_OPC_Decode, 255, 2, 13, // Opcode: GEN_ABS_S
/* 567 */     MCD_OPC_FilterValue, 18, 4, 0, 0, // Skip to: 576
/* 572 */     MCD_OPC_Decode, 154, 3, 13, // Opcode: GEN_NOT_S
/* 576 */     MCD_OPC_FilterValue, 19, 4, 0, 0, // Skip to: 585
/* 581 */     MCD_OPC_Decode, 152, 3, 13, // Opcode: GEN_NEG_S
/* 585 */     MCD_OPC_FilterValue, 20, 4, 0, 0, // Skip to: 594
/* 590 */     MCD_OPC_Decode, 128, 3, 13, // Opcode: GEN_ADD1_S
/* 594 */     MCD_OPC_FilterValue, 21, 4, 0, 0, // Skip to: 603
/* 599 */     MCD_OPC_Decode, 129, 3, 13, // Opcode: GEN_ADD2_S
/* 603 */     MCD_OPC_FilterValue, 22, 4, 0, 0, // Skip to: 612
/* 608 */     MCD_OPC_Decode, 130, 3, 13, // Opcode: GEN_ADD3_S
/* 612 */     MCD_OPC_FilterValue, 24, 4, 0, 0, // Skip to: 621
/* 617 */     MCD_OPC_Decode, 134, 3, 13, // Opcode: GEN_ASL_S
/* 621 */     MCD_OPC_FilterValue, 25, 4, 0, 0, // Skip to: 630
/* 626 */     MCD_OPC_Decode, 148, 3, 13, // Opcode: GEN_LSR_S
/* 630 */     MCD_OPC_FilterValue, 26, 4, 0, 0, // Skip to: 639
/* 635 */     MCD_OPC_Decode, 135, 3, 13, // Opcode: GEN_ASR_S
/* 639 */     MCD_OPC_FilterValue, 27, 4, 0, 0, // Skip to: 648
/* 644 */     MCD_OPC_Decode, 132, 3, 13, // Opcode: GEN_AS1L_S
/* 648 */     MCD_OPC_FilterValue, 28, 4, 0, 0, // Skip to: 657
/* 653 */     MCD_OPC_Decode, 133, 3, 13, // Opcode: GEN_AS1R_S
/* 657 */     MCD_OPC_FilterValue, 29, 4, 0, 0, // Skip to: 666
/* 662 */     MCD_OPC_Decode, 147, 3, 13, // Opcode: GEN_LS1R_S
/* 666 */     MCD_OPC_FilterValue, 30, 4, 0, 0, // Skip to: 675
/* 671 */     MCD_OPC_Decode, 161, 3, 14, // Opcode: GEN_TRAP_S
/* 675 */     MCD_OPC_FilterValue, 31, 66, 2, 0, // Skip to: 1258
/* 680 */     MCD_OPC_CheckField, 5, 6, 63, 59, 2, 0, // Skip to: 1258
/* 687 */     MCD_OPC_Decode, 137, 3, 12, // Opcode: GEN_BRK_S
/* 691 */     MCD_OPC_FilterValue, 16, 4, 0, 0, // Skip to: 700
/* 696 */     MCD_OPC_Decode, 229, 3, 15, // Opcode: LD_S_OFF
/* 700 */     MCD_OPC_FilterValue, 17, 4, 0, 0, // Skip to: 709
/* 705 */     MCD_OPC_Decode, 182, 3, 16, // Opcode: LDB_S_OFF
/* 709 */     MCD_OPC_FilterValue, 18, 4, 0, 0, // Skip to: 718
/* 714 */     MCD_OPC_Decode, 204, 3, 17, // Opcode: LDH_S_OFF
/* 718 */     MCD_OPC_FilterValue, 19, 4, 0, 0, // Skip to: 727
/* 723 */     MCD_OPC_Decode, 205, 3, 17, // Opcode: LDH_S_X_OFF
/* 727 */     MCD_OPC_FilterValue, 20, 4, 0, 0, // Skip to: 736
/* 732 */     MCD_OPC_Decode, 150, 5, 15, // Opcode: ST_S_OFF
/* 736 */     MCD_OPC_FilterValue, 21, 4, 0, 0, // Skip to: 745
/* 741 */     MCD_OPC_Decode, 132, 5, 16, // Opcode: STB_S_OFF
/* 745 */     MCD_OPC_FilterValue, 22, 4, 0, 0, // Skip to: 754
/* 750 */     MCD_OPC_Decode, 141, 5, 17, // Opcode: STH_S_OFF
/* 754 */     MCD_OPC_FilterValue, 23, 75, 0, 0, // Skip to: 834
/* 759 */     MCD_OPC_ExtractField, 5, 3,  // Inst{7-5} ...
/* 762 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 771
/* 767 */     MCD_OPC_Decode, 192, 2, 18, // Opcode: ASL_S_ru5
/* 771 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 780
/* 776 */     MCD_OPC_Decode, 238, 3, 18, // Opcode: LSR_S_ru5
/* 780 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 789
/* 785 */     MCD_OPC_Decode, 204, 2, 18, // Opcode: ASR_S_ru5
/* 789 */     MCD_OPC_FilterValue, 3, 4, 0, 0, // Skip to: 798
/* 794 */     MCD_OPC_Decode, 186, 5, 18, // Opcode: SUB_S_ru5
/* 798 */     MCD_OPC_FilterValue, 4, 4, 0, 0, // Skip to: 807
/* 803 */     MCD_OPC_Decode, 234, 2, 18, // Opcode: BSET_S_ru5
/* 807 */     MCD_OPC_FilterValue, 5, 4, 0, 0, // Skip to: 816
/* 812 */     MCD_OPC_Decode, 215, 2, 18, // Opcode: BCLR_S_ru5
/* 816 */     MCD_OPC_FilterValue, 6, 4, 0, 0, // Skip to: 825
/* 821 */     MCD_OPC_Decode, 227, 2, 18, // Opcode: BMSK_S_ru5
/* 825 */     MCD_OPC_FilterValue, 7, 172, 1, 0, // Skip to: 1258
/* 830 */     MCD_OPC_Decode, 235, 2, 18, // Opcode: BTST_S_ru5
/* 834 */     MCD_OPC_FilterValue, 24, 181, 0, 0, // Skip to: 1020
/* 839 */     MCD_OPC_ExtractField, 5, 3,  // Inst{7-5} ...
/* 842 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 851
/* 847 */     MCD_OPC_Decode, 250, 4, 19, // Opcode: SP_LD_S
/* 851 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 860
/* 856 */     MCD_OPC_Decode, 249, 4, 19, // Opcode: SP_LDB_S
/* 860 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 869
/* 865 */     MCD_OPC_Decode, 252, 4, 19, // Opcode: SP_ST_S
/* 869 */     MCD_OPC_FilterValue, 3, 4, 0, 0, // Skip to: 878
/* 874 */     MCD_OPC_Decode, 251, 4, 19, // Opcode: SP_STB_S
/* 878 */     MCD_OPC_FilterValue, 4, 4, 0, 0, // Skip to: 887
/* 883 */     MCD_OPC_Decode, 247, 4, 19, // Opcode: SP_ADD_S
/* 887 */     MCD_OPC_FilterValue, 5, 21, 0, 0, // Skip to: 913
/* 892 */     MCD_OPC_ExtractField, 8, 3,  // Inst{10-8} ...
/* 895 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 904
/* 900 */     MCD_OPC_Decode, 248, 4, 20, // Opcode: SP_ADD_SP_S
/* 904 */     MCD_OPC_FilterValue, 1, 93, 1, 0, // Skip to: 1258
/* 909 */     MCD_OPC_Decode, 253, 4, 20, // Opcode: SP_SUB_SP_S
/* 913 */     MCD_OPC_FilterValue, 6, 45, 0, 0, // Skip to: 963
/* 918 */     MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 921 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 930
/* 926 */     MCD_OPC_Decode, 235, 3, 21, // Opcode: LEAVE_S
/* 930 */     MCD_OPC_FilterValue, 1, 67, 1, 0, // Skip to: 1258
/* 935 */     MCD_OPC_ExtractField, 1, 4,  // Inst{4-1} ...
/* 938 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 947
/* 943 */     MCD_OPC_Decode, 202, 4, 22, // Opcode: PUSH_S_r
/* 947 */     MCD_OPC_FilterValue, 8, 50, 1, 0, // Skip to: 1258
/* 952 */     MCD_OPC_CheckField, 8, 3, 0, 43, 1, 0, // Skip to: 1258
/* 959 */     MCD_OPC_Decode, 199, 4, 12, // Opcode: POP_S_BLINK
/* 963 */     MCD_OPC_FilterValue, 7, 34, 1, 0, // Skip to: 1258
/* 968 */     MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 971 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 987
/* 976 */     MCD_OPC_CheckField, 10, 1, 0, 19, 1, 0, // Skip to: 1258
/* 983 */     MCD_OPC_Decode, 250, 2, 23, // Opcode: ENTER_S
/* 987 */     MCD_OPC_FilterValue, 1, 10, 1, 0, // Skip to: 1258
/* 992 */     MCD_OPC_ExtractField, 1, 4,  // Inst{4-1} ...
/* 995 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1004
/* 1000 */    MCD_OPC_Decode, 200, 4, 22, // Opcode: POP_S_r
/* 1004 */    MCD_OPC_FilterValue, 8, 249, 0, 0, // Skip to: 1258
/* 1009 */    MCD_OPC_CheckField, 8, 3, 0, 242, 0, 0, // Skip to: 1258
/* 1016 */    MCD_OPC_Decode, 201, 4, 12, // Opcode: PUSH_S_BLINK
/* 1020 */    MCD_OPC_FilterValue, 25, 39, 0, 0, // Skip to: 1064
/* 1025 */    MCD_OPC_ExtractField, 9, 2,  // Inst{10-9} ...
/* 1028 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1037
/* 1033 */    MCD_OPC_Decode, 168, 3, 24, // Opcode: GP_LD_S
/* 1037 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1046
/* 1042 */    MCD_OPC_Decode, 166, 3, 25, // Opcode: GP_LDB_S
/* 1046 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1055
/* 1051 */    MCD_OPC_Decode, 167, 3, 26, // Opcode: GP_LDH_S
/* 1055 */    MCD_OPC_FilterValue, 3, 198, 0, 0, // Skip to: 1258
/* 1060 */    MCD_OPC_Decode, 165, 3, 24, // Opcode: GP_ADD_S
/* 1064 */    MCD_OPC_FilterValue, 26, 4, 0, 0, // Skip to: 1073
/* 1069 */    MCD_OPC_Decode, 198, 4, 27, // Opcode: PCL_LD
/* 1073 */    MCD_OPC_FilterValue, 27, 4, 0, 0, // Skip to: 1082
/* 1078 */    MCD_OPC_Decode, 145, 4, 28, // Opcode: MOV_S_u8
/* 1082 */    MCD_OPC_FilterValue, 28, 21, 0, 0, // Skip to: 1108
/* 1087 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1090 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1099
/* 1095 */    MCD_OPC_Decode, 170, 2, 29, // Opcode: ADD_S_u7
/* 1099 */    MCD_OPC_FilterValue, 1, 154, 0, 0, // Skip to: 1258
/* 1104 */    MCD_OPC_Decode, 242, 2, 29, // Opcode: CMP_S_u7
/* 1108 */    MCD_OPC_FilterValue, 29, 21, 0, 0, // Skip to: 1134
/* 1113 */    MCD_OPC_ExtractField, 7, 1,  // Inst{7} ...
/* 1116 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1125
/* 1121 */    MCD_OPC_Decode, 230, 2, 30, // Opcode: BREQ_S
/* 1125 */    MCD_OPC_FilterValue, 1, 128, 0, 0, // Skip to: 1258
/* 1130 */    MCD_OPC_Decode, 231, 2, 30, // Opcode: BRNE_S
/* 1134 */    MCD_OPC_FilterValue, 30, 110, 0, 0, // Skip to: 1249
/* 1139 */    MCD_OPC_ExtractField, 9, 2,  // Inst{10-9} ...
/* 1142 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1151
/* 1147 */    MCD_OPC_Decode, 236, 2, 31, // Opcode: B_S
/* 1151 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1160
/* 1156 */    MCD_OPC_Decode, 216, 2, 31, // Opcode: BEQ_S
/* 1160 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1169
/* 1165 */    MCD_OPC_Decode, 228, 2, 31, // Opcode: BNE_S
/* 1169 */    MCD_OPC_FilterValue, 3, 84, 0, 0, // Skip to: 1258
/* 1174 */    MCD_OPC_ExtractField, 6, 3,  // Inst{8-6} ...
/* 1177 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1186
/* 1182 */    MCD_OPC_Decode, 218, 2, 32, // Opcode: BGT_S
/* 1186 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1195
/* 1191 */    MCD_OPC_Decode, 217, 2, 32, // Opcode: BGE_S
/* 1195 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1204
/* 1200 */    MCD_OPC_Decode, 225, 2, 32, // Opcode: BLT_S
/* 1204 */    MCD_OPC_FilterValue, 3, 4, 0, 0, // Skip to: 1213
/* 1209 */    MCD_OPC_Decode, 222, 2, 32, // Opcode: BLE_S
/* 1213 */    MCD_OPC_FilterValue, 4, 4, 0, 0, // Skip to: 1222
/* 1218 */    MCD_OPC_Decode, 219, 2, 32, // Opcode: BHI_S
/* 1222 */    MCD_OPC_FilterValue, 5, 4, 0, 0, // Skip to: 1231
/* 1227 */    MCD_OPC_Decode, 220, 2, 32, // Opcode: BHS_S
/* 1231 */    MCD_OPC_FilterValue, 6, 4, 0, 0, // Skip to: 1240
/* 1236 */    MCD_OPC_Decode, 223, 2, 32, // Opcode: BLO_S
/* 1240 */    MCD_OPC_FilterValue, 7, 13, 0, 0, // Skip to: 1258
/* 1245 */    MCD_OPC_Decode, 224, 2, 32, // Opcode: BLS_S
/* 1249 */    MCD_OPC_FilterValue, 31, 4, 0, 0, // Skip to: 1258
/* 1254 */    MCD_OPC_Decode, 226, 2, 33, // Opcode: BL_S
/* 1258 */    MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTable32[] = {
/* 0 */       MCD_OPC_ExtractField, 27, 5,  // Inst{31-27} ...
/* 3 */       MCD_OPC_FilterValue, 0, 28, 0, 0, // Skip to: 36
/* 8 */       MCD_OPC_ExtractField, 16, 1,  // Inst{16} ...
/* 11 */      MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 20
/* 16 */      MCD_OPC_Decode, 237, 2, 34, // Opcode: Bcc
/* 20 */      MCD_OPC_FilterValue, 1, 205, 10, 0, // Skip to: 2790
/* 25 */      MCD_OPC_CheckField, 4, 1, 0, 198, 10, 0, // Skip to: 2790
/* 32 */      MCD_OPC_Decode, 229, 2, 35, // Opcode: BR
/* 36 */      MCD_OPC_FilterValue, 1, 66, 0, 0, // Skip to: 107
/* 41 */      MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 44 */      MCD_OPC_FilterValue, 0, 35, 0, 0, // Skip to: 84
/* 49 */      MCD_OPC_ExtractField, 16, 1,  // Inst{16} ...
/* 52 */      MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 68
/* 57 */      MCD_OPC_CheckField, 17, 1, 1, 166, 10, 0, // Skip to: 2790
/* 64 */      MCD_OPC_Decode, 221, 2, 36, // Opcode: BL
/* 68 */      MCD_OPC_FilterValue, 1, 157, 10, 0, // Skip to: 2790
/* 73 */      MCD_OPC_CheckField, 3, 1, 0, 150, 10, 0, // Skip to: 2790
/* 80 */      MCD_OPC_Decode, 232, 2, 37, // Opcode: BRcc_rr
/* 84 */      MCD_OPC_FilterValue, 1, 141, 10, 0, // Skip to: 2790
/* 89 */      MCD_OPC_CheckField, 16, 1, 1, 134, 10, 0, // Skip to: 2790
/* 96 */      MCD_OPC_CheckField, 3, 1, 0, 127, 10, 0, // Skip to: 2790
/* 103 */     MCD_OPC_Decode, 233, 2, 38, // Opcode: BRcc_ru6
/* 107 */     MCD_OPC_FilterValue, 2, 17, 1, 0, // Skip to: 385
/* 112 */     MCD_OPC_ExtractField, 6, 6,  // Inst{11-6} ...
/* 115 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 124
/* 120 */     MCD_OPC_Decode, 234, 3, 39, // Opcode: LD_rs9
/* 124 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 133
/* 129 */     MCD_OPC_Decode, 196, 3, 39, // Opcode: LDB_rs9
/* 133 */     MCD_OPC_FilterValue, 3, 4, 0, 0, // Skip to: 142
/* 138 */     MCD_OPC_Decode, 193, 3, 39, // Opcode: LDB_X_rs9
/* 142 */     MCD_OPC_FilterValue, 4, 4, 0, 0, // Skip to: 151
/* 147 */     MCD_OPC_Decode, 219, 3, 39, // Opcode: LDH_rs9
/* 151 */     MCD_OPC_FilterValue, 5, 4, 0, 0, // Skip to: 160
/* 156 */     MCD_OPC_Decode, 216, 3, 39, // Opcode: LDH_X_rs9
/* 160 */     MCD_OPC_FilterValue, 8, 4, 0, 0, // Skip to: 169
/* 165 */     MCD_OPC_Decode, 222, 3, 40, // Opcode: LD_AW_rs9
/* 169 */     MCD_OPC_FilterValue, 10, 4, 0, 0, // Skip to: 178
/* 174 */     MCD_OPC_Decode, 176, 3, 40, // Opcode: LDB_AW_rs9
/* 178 */     MCD_OPC_FilterValue, 11, 4, 0, 0, // Skip to: 187
/* 183 */     MCD_OPC_Decode, 185, 3, 40, // Opcode: LDB_X_AW_rs9
/* 187 */     MCD_OPC_FilterValue, 12, 4, 0, 0, // Skip to: 196
/* 192 */     MCD_OPC_Decode, 198, 3, 40, // Opcode: LDH_AW_rs9
/* 196 */     MCD_OPC_FilterValue, 13, 4, 0, 0, // Skip to: 205
/* 201 */     MCD_OPC_Decode, 208, 3, 40, // Opcode: LDH_X_AW_rs9
/* 205 */     MCD_OPC_FilterValue, 16, 4, 0, 0, // Skip to: 214
/* 210 */     MCD_OPC_Decode, 221, 3, 40, // Opcode: LD_AB_rs9
/* 214 */     MCD_OPC_FilterValue, 18, 4, 0, 0, // Skip to: 223
/* 219 */     MCD_OPC_Decode, 175, 3, 40, // Opcode: LDB_AB_rs9
/* 223 */     MCD_OPC_FilterValue, 19, 4, 0, 0, // Skip to: 232
/* 228 */     MCD_OPC_Decode, 184, 3, 40, // Opcode: LDB_X_AB_rs9
/* 232 */     MCD_OPC_FilterValue, 20, 4, 0, 0, // Skip to: 241
/* 237 */     MCD_OPC_Decode, 197, 3, 40, // Opcode: LDH_AB_rs9
/* 241 */     MCD_OPC_FilterValue, 21, 4, 0, 0, // Skip to: 250
/* 246 */     MCD_OPC_Decode, 207, 3, 40, // Opcode: LDH_X_AB_rs9
/* 250 */     MCD_OPC_FilterValue, 32, 4, 0, 0, // Skip to: 259
/* 255 */     MCD_OPC_Decode, 227, 3, 39, // Opcode: LD_DI_rs9
/* 259 */     MCD_OPC_FilterValue, 34, 4, 0, 0, // Skip to: 268
/* 264 */     MCD_OPC_Decode, 181, 3, 39, // Opcode: LDB_DI_rs9
/* 268 */     MCD_OPC_FilterValue, 35, 4, 0, 0, // Skip to: 277
/* 273 */     MCD_OPC_Decode, 190, 3, 39, // Opcode: LDB_X_DI_rs9
/* 277 */     MCD_OPC_FilterValue, 36, 4, 0, 0, // Skip to: 286
/* 282 */     MCD_OPC_Decode, 203, 3, 39, // Opcode: LDH_DI_rs9
/* 286 */     MCD_OPC_FilterValue, 37, 4, 0, 0, // Skip to: 295
/* 291 */     MCD_OPC_Decode, 213, 3, 39, // Opcode: LDH_X_DI_rs9
/* 295 */     MCD_OPC_FilterValue, 40, 4, 0, 0, // Skip to: 304
/* 300 */     MCD_OPC_Decode, 224, 3, 40, // Opcode: LD_DI_AW_rs9
/* 304 */     MCD_OPC_FilterValue, 42, 4, 0, 0, // Skip to: 313
/* 309 */     MCD_OPC_Decode, 178, 3, 40, // Opcode: LDB_DI_AW_rs9
/* 313 */     MCD_OPC_FilterValue, 43, 4, 0, 0, // Skip to: 322
/* 318 */     MCD_OPC_Decode, 187, 3, 40, // Opcode: LDB_X_DI_AW_rs9
/* 322 */     MCD_OPC_FilterValue, 44, 4, 0, 0, // Skip to: 331
/* 327 */     MCD_OPC_Decode, 200, 3, 40, // Opcode: LDH_DI_AW_rs9
/* 331 */     MCD_OPC_FilterValue, 45, 4, 0, 0, // Skip to: 340
/* 336 */     MCD_OPC_Decode, 210, 3, 40, // Opcode: LDH_X_DI_AW_rs9
/* 340 */     MCD_OPC_FilterValue, 48, 4, 0, 0, // Skip to: 349
/* 345 */     MCD_OPC_Decode, 223, 3, 40, // Opcode: LD_DI_AB_rs9
/* 349 */     MCD_OPC_FilterValue, 50, 4, 0, 0, // Skip to: 358
/* 354 */     MCD_OPC_Decode, 177, 3, 40, // Opcode: LDB_DI_AB_rs9
/* 358 */     MCD_OPC_FilterValue, 51, 4, 0, 0, // Skip to: 367
/* 363 */     MCD_OPC_Decode, 186, 3, 40, // Opcode: LDB_X_DI_AB_rs9
/* 367 */     MCD_OPC_FilterValue, 52, 4, 0, 0, // Skip to: 376
/* 372 */     MCD_OPC_Decode, 199, 3, 40, // Opcode: LDH_DI_AB_rs9
/* 376 */     MCD_OPC_FilterValue, 53, 105, 9, 0, // Skip to: 2790
/* 381 */     MCD_OPC_Decode, 209, 3, 40, // Opcode: LDH_X_DI_AB_rs9
/* 385 */     MCD_OPC_FilterValue, 3, 165, 0, 0, // Skip to: 555
/* 390 */     MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 393 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 402
/* 398 */     MCD_OPC_Decode, 153, 5, 41, // Opcode: ST_rs9
/* 402 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 411
/* 407 */     MCD_OPC_Decode, 134, 5, 41, // Opcode: STB_rs9
/* 411 */     MCD_OPC_FilterValue, 4, 4, 0, 0, // Skip to: 420
/* 416 */     MCD_OPC_Decode, 143, 5, 41, // Opcode: STH_rs9
/* 420 */     MCD_OPC_FilterValue, 8, 4, 0, 0, // Skip to: 429
/* 425 */     MCD_OPC_Decode, 145, 5, 42, // Opcode: ST_AW_rs9
/* 429 */     MCD_OPC_FilterValue, 10, 4, 0, 0, // Skip to: 438
/* 434 */     MCD_OPC_Decode, 255, 4, 42, // Opcode: STB_AW_rs9
/* 438 */     MCD_OPC_FilterValue, 12, 4, 0, 0, // Skip to: 447
/* 443 */     MCD_OPC_Decode, 136, 5, 42, // Opcode: STH_AW_rs9
/* 447 */     MCD_OPC_FilterValue, 16, 4, 0, 0, // Skip to: 456
/* 452 */     MCD_OPC_Decode, 144, 5, 42, // Opcode: ST_AB_rs9
/* 456 */     MCD_OPC_FilterValue, 18, 4, 0, 0, // Skip to: 465
/* 461 */     MCD_OPC_Decode, 254, 4, 42, // Opcode: STB_AB_rs9
/* 465 */     MCD_OPC_FilterValue, 20, 4, 0, 0, // Skip to: 474
/* 470 */     MCD_OPC_Decode, 135, 5, 42, // Opcode: STH_AB_rs9
/* 474 */     MCD_OPC_FilterValue, 32, 4, 0, 0, // Skip to: 483
/* 479 */     MCD_OPC_Decode, 149, 5, 41, // Opcode: ST_DI_rs9
/* 483 */     MCD_OPC_FilterValue, 34, 4, 0, 0, // Skip to: 492
/* 488 */     MCD_OPC_Decode, 131, 5, 41, // Opcode: STB_DI_rs9
/* 492 */     MCD_OPC_FilterValue, 36, 4, 0, 0, // Skip to: 501
/* 497 */     MCD_OPC_Decode, 140, 5, 41, // Opcode: STH_DI_rs9
/* 501 */     MCD_OPC_FilterValue, 40, 4, 0, 0, // Skip to: 510
/* 506 */     MCD_OPC_Decode, 147, 5, 42, // Opcode: ST_DI_AW_rs9
/* 510 */     MCD_OPC_FilterValue, 42, 4, 0, 0, // Skip to: 519
/* 515 */     MCD_OPC_Decode, 129, 5, 42, // Opcode: STB_DI_AW_rs9
/* 519 */     MCD_OPC_FilterValue, 44, 4, 0, 0, // Skip to: 528
/* 524 */     MCD_OPC_Decode, 138, 5, 42, // Opcode: STH_DI_AW_rs9
/* 528 */     MCD_OPC_FilterValue, 48, 4, 0, 0, // Skip to: 537
/* 533 */     MCD_OPC_Decode, 146, 5, 42, // Opcode: ST_DI_AB_rs9
/* 537 */     MCD_OPC_FilterValue, 50, 4, 0, 0, // Skip to: 546
/* 542 */     MCD_OPC_Decode, 128, 5, 42, // Opcode: STB_DI_AB_rs9
/* 546 */     MCD_OPC_FilterValue, 52, 191, 8, 0, // Skip to: 2790
/* 551 */     MCD_OPC_Decode, 137, 5, 42, // Opcode: STH_DI_AB_rs9
/* 555 */     MCD_OPC_FilterValue, 4, 230, 6, 0, // Skip to: 2326
/* 560 */     MCD_OPC_ExtractField, 15, 9,  // Inst{23-15} ...
/* 563 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 572
/* 568 */     MCD_OPC_Decode, 178, 2, 43, // Opcode: ADD_rrr
/* 572 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 581
/* 577 */     MCD_OPC_Decode, 174, 2, 43, // Opcode: ADD_f_rrr
/* 581 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 590
/* 586 */     MCD_OPC_Decode, 160, 2, 43, // Opcode: ADC_rrr
/* 590 */     MCD_OPC_FilterValue, 3, 4, 0, 0, // Skip to: 599
/* 595 */     MCD_OPC_Decode, 156, 2, 43, // Opcode: ADC_f_rrr
/* 599 */     MCD_OPC_FilterValue, 4, 4, 0, 0, // Skip to: 608
/* 604 */     MCD_OPC_Decode, 194, 5, 43, // Opcode: SUB_rrr
/* 608 */     MCD_OPC_FilterValue, 5, 4, 0, 0, // Skip to: 617
/* 613 */     MCD_OPC_Decode, 190, 5, 43, // Opcode: SUB_f_rrr
/* 617 */     MCD_OPC_FilterValue, 6, 4, 0, 0, // Skip to: 626
/* 622 */     MCD_OPC_Decode, 230, 4, 43, // Opcode: SBC_rrr
/* 626 */     MCD_OPC_FilterValue, 7, 4, 0, 0, // Skip to: 635
/* 631 */     MCD_OPC_Decode, 226, 4, 43, // Opcode: SBC_f_rrr
/* 635 */     MCD_OPC_FilterValue, 8, 4, 0, 0, // Skip to: 644
/* 640 */     MCD_OPC_Decode, 188, 2, 43, // Opcode: AND_rrr
/* 644 */     MCD_OPC_FilterValue, 9, 4, 0, 0, // Skip to: 653
/* 649 */     MCD_OPC_Decode, 184, 2, 43, // Opcode: AND_f_rrr
/* 653 */     MCD_OPC_FilterValue, 10, 4, 0, 0, // Skip to: 662
/* 658 */     MCD_OPC_Decode, 195, 4, 43, // Opcode: OR_rrr
/* 662 */     MCD_OPC_FilterValue, 11, 4, 0, 0, // Skip to: 671
/* 667 */     MCD_OPC_Decode, 191, 4, 43, // Opcode: OR_f_rrr
/* 671 */     MCD_OPC_FilterValue, 14, 4, 0, 0, // Skip to: 680
/* 676 */     MCD_OPC_Decode, 204, 5, 43, // Opcode: XOR_rrr
/* 680 */     MCD_OPC_FilterValue, 15, 4, 0, 0, // Skip to: 689
/* 685 */     MCD_OPC_Decode, 200, 5, 43, // Opcode: XOR_f_rrr
/* 689 */     MCD_OPC_FilterValue, 16, 4, 0, 0, // Skip to: 698
/* 694 */     MCD_OPC_Decode, 128, 4, 43, // Opcode: MAX_rrr
/* 698 */     MCD_OPC_FilterValue, 17, 4, 0, 0, // Skip to: 707
/* 703 */     MCD_OPC_Decode, 252, 3, 43, // Opcode: MAX_f_rrr
/* 707 */     MCD_OPC_FilterValue, 18, 4, 0, 0, // Skip to: 716
/* 712 */     MCD_OPC_Decode, 138, 4, 43, // Opcode: MIN_rrr
/* 716 */     MCD_OPC_FilterValue, 19, 4, 0, 0, // Skip to: 725
/* 721 */     MCD_OPC_Decode, 134, 4, 43, // Opcode: MIN_f_rrr
/* 725 */     MCD_OPC_FilterValue, 20, 4, 0, 0, // Skip to: 734
/* 730 */     MCD_OPC_Decode, 151, 4, 44, // Opcode: MOV_rr
/* 734 */     MCD_OPC_FilterValue, 25, 4, 0, 0, // Skip to: 743
/* 739 */     MCD_OPC_Decode, 244, 2, 44, // Opcode: CMP_rr
/* 743 */     MCD_OPC_FilterValue, 28, 4, 0, 0, // Skip to: 752
/* 748 */     MCD_OPC_Decode, 220, 4, 43, // Opcode: RSUB_rrr
/* 752 */     MCD_OPC_FilterValue, 29, 4, 0, 0, // Skip to: 761
/* 757 */     MCD_OPC_Decode, 216, 4, 43, // Opcode: RSUB_f_rrr
/* 761 */     MCD_OPC_FilterValue, 46, 4, 0, 0, // Skip to: 770
/* 766 */     MCD_OPC_Decode, 161, 5, 43, // Opcode: SUB1_rrr
/* 770 */     MCD_OPC_FilterValue, 47, 4, 0, 0, // Skip to: 779
/* 775 */     MCD_OPC_Decode, 157, 5, 43, // Opcode: SUB1_f_rrr
/* 779 */     MCD_OPC_FilterValue, 48, 4, 0, 0, // Skip to: 788
/* 784 */     MCD_OPC_Decode, 171, 5, 43, // Opcode: SUB2_rrr
/* 788 */     MCD_OPC_FilterValue, 49, 4, 0, 0, // Skip to: 797
/* 793 */     MCD_OPC_Decode, 167, 5, 43, // Opcode: SUB2_f_rrr
/* 797 */     MCD_OPC_FilterValue, 50, 4, 0, 0, // Skip to: 806
/* 802 */     MCD_OPC_Decode, 181, 5, 43, // Opcode: SUB3_rrr
/* 806 */     MCD_OPC_FilterValue, 51, 4, 0, 0, // Skip to: 815
/* 811 */     MCD_OPC_Decode, 177, 5, 43, // Opcode: SUB3_f_rrr
/* 815 */     MCD_OPC_FilterValue, 52, 4, 0, 0, // Skip to: 824
/* 820 */     MCD_OPC_Decode, 181, 4, 43, // Opcode: MPY_rrr
/* 824 */     MCD_OPC_FilterValue, 53, 4, 0, 0, // Skip to: 833
/* 829 */     MCD_OPC_Decode, 177, 4, 43, // Opcode: MPY_f_rrr
/* 833 */     MCD_OPC_FilterValue, 54, 4, 0, 0, // Skip to: 842
/* 838 */     MCD_OPC_Decode, 171, 4, 43, // Opcode: MPYM_rrr
/* 842 */     MCD_OPC_FilterValue, 55, 4, 0, 0, // Skip to: 851
/* 847 */     MCD_OPC_Decode, 167, 4, 43, // Opcode: MPYM_f_rrr
/* 851 */     MCD_OPC_FilterValue, 56, 4, 0, 0, // Skip to: 860
/* 856 */     MCD_OPC_Decode, 161, 4, 43, // Opcode: MPYMU_rrr
/* 860 */     MCD_OPC_FilterValue, 57, 4, 0, 0, // Skip to: 869
/* 865 */     MCD_OPC_Decode, 157, 4, 43, // Opcode: MPYMU_f_rrr
/* 869 */     MCD_OPC_FilterValue, 64, 4, 0, 0, // Skip to: 878
/* 874 */     MCD_OPC_Decode, 169, 3, 45, // Opcode: J
/* 878 */     MCD_OPC_FilterValue, 68, 4, 0, 0, // Skip to: 887
/* 883 */     MCD_OPC_Decode, 170, 3, 45, // Opcode: JL
/* 887 */     MCD_OPC_FilterValue, 94, 21, 0, 0, // Skip to: 913
/* 892 */     MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 895 */     MCD_OPC_FilterValue, 5, 4, 0, 0, // Skip to: 904
/* 900 */     MCD_OPC_Decode, 244, 4, 44, // Opcode: SEXB_rr
/* 904 */     MCD_OPC_FilterValue, 6, 89, 7, 0, // Skip to: 2790
/* 909 */     MCD_OPC_Decode, 246, 4, 44, // Opcode: SEXH_rr
/* 913 */     MCD_OPC_FilterValue, 95, 21, 0, 0, // Skip to: 939
/* 918 */     MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 921 */     MCD_OPC_FilterValue, 5, 4, 0, 0, // Skip to: 930
/* 926 */     MCD_OPC_Decode, 243, 4, 44, // Opcode: SEXB_f_rr
/* 930 */     MCD_OPC_FilterValue, 6, 63, 7, 0, // Skip to: 2790
/* 935 */     MCD_OPC_Decode, 245, 4, 44, // Opcode: SEXH_f_rr
/* 939 */     MCD_OPC_FilterValue, 112, 4, 0, 0, // Skip to: 948
/* 944 */     MCD_OPC_Decode, 240, 4, 43, // Opcode: SETEQ_rrr
/* 948 */     MCD_OPC_FilterValue, 113, 4, 0, 0, // Skip to: 957
/* 953 */     MCD_OPC_Decode, 236, 4, 43, // Opcode: SETEQ_f_rrr
/* 957 */     MCD_OPC_FilterValue, 128, 1, 4, 0, 0, // Skip to: 967
/* 963 */     MCD_OPC_Decode, 180, 2, 46, // Opcode: ADD_rru6
/* 967 */     MCD_OPC_FilterValue, 129, 1, 4, 0, 0, // Skip to: 977
/* 973 */     MCD_OPC_Decode, 176, 2, 46, // Opcode: ADD_f_rru6
/* 977 */     MCD_OPC_FilterValue, 130, 1, 4, 0, 0, // Skip to: 987
/* 983 */     MCD_OPC_Decode, 162, 2, 46, // Opcode: ADC_rru6
/* 987 */     MCD_OPC_FilterValue, 131, 1, 4, 0, 0, // Skip to: 997
/* 993 */     MCD_OPC_Decode, 158, 2, 46, // Opcode: ADC_f_rru6
/* 997 */     MCD_OPC_FilterValue, 132, 1, 4, 0, 0, // Skip to: 1007
/* 1003 */    MCD_OPC_Decode, 196, 5, 46, // Opcode: SUB_rru6
/* 1007 */    MCD_OPC_FilterValue, 133, 1, 4, 0, 0, // Skip to: 1017
/* 1013 */    MCD_OPC_Decode, 192, 5, 46, // Opcode: SUB_f_rru6
/* 1017 */    MCD_OPC_FilterValue, 134, 1, 4, 0, 0, // Skip to: 1027
/* 1023 */    MCD_OPC_Decode, 232, 4, 46, // Opcode: SBC_rru6
/* 1027 */    MCD_OPC_FilterValue, 135, 1, 4, 0, 0, // Skip to: 1037
/* 1033 */    MCD_OPC_Decode, 228, 4, 46, // Opcode: SBC_f_rru6
/* 1037 */    MCD_OPC_FilterValue, 136, 1, 4, 0, 0, // Skip to: 1047
/* 1043 */    MCD_OPC_Decode, 190, 2, 46, // Opcode: AND_rru6
/* 1047 */    MCD_OPC_FilterValue, 137, 1, 4, 0, 0, // Skip to: 1057
/* 1053 */    MCD_OPC_Decode, 186, 2, 46, // Opcode: AND_f_rru6
/* 1057 */    MCD_OPC_FilterValue, 138, 1, 4, 0, 0, // Skip to: 1067
/* 1063 */    MCD_OPC_Decode, 197, 4, 46, // Opcode: OR_rru6
/* 1067 */    MCD_OPC_FilterValue, 139, 1, 4, 0, 0, // Skip to: 1077
/* 1073 */    MCD_OPC_Decode, 193, 4, 46, // Opcode: OR_f_rru6
/* 1077 */    MCD_OPC_FilterValue, 142, 1, 4, 0, 0, // Skip to: 1087
/* 1083 */    MCD_OPC_Decode, 206, 5, 46, // Opcode: XOR_rru6
/* 1087 */    MCD_OPC_FilterValue, 143, 1, 4, 0, 0, // Skip to: 1097
/* 1093 */    MCD_OPC_Decode, 202, 5, 46, // Opcode: XOR_f_rru6
/* 1097 */    MCD_OPC_FilterValue, 144, 1, 4, 0, 0, // Skip to: 1107
/* 1103 */    MCD_OPC_Decode, 130, 4, 46, // Opcode: MAX_rru6
/* 1107 */    MCD_OPC_FilterValue, 145, 1, 4, 0, 0, // Skip to: 1117
/* 1113 */    MCD_OPC_Decode, 254, 3, 46, // Opcode: MAX_f_rru6
/* 1117 */    MCD_OPC_FilterValue, 146, 1, 4, 0, 0, // Skip to: 1127
/* 1123 */    MCD_OPC_Decode, 140, 4, 46, // Opcode: MIN_rru6
/* 1127 */    MCD_OPC_FilterValue, 147, 1, 4, 0, 0, // Skip to: 1137
/* 1133 */    MCD_OPC_Decode, 136, 4, 46, // Opcode: MIN_f_rru6
/* 1137 */    MCD_OPC_FilterValue, 148, 1, 4, 0, 0, // Skip to: 1147
/* 1143 */    MCD_OPC_Decode, 153, 4, 47, // Opcode: MOV_ru6
/* 1147 */    MCD_OPC_FilterValue, 149, 1, 4, 0, 0, // Skip to: 1157
/* 1153 */    MCD_OPC_Decode, 149, 4, 47, // Opcode: MOV_f_ru6
/* 1157 */    MCD_OPC_FilterValue, 153, 1, 4, 0, 0, // Skip to: 1167
/* 1163 */    MCD_OPC_Decode, 245, 2, 47, // Opcode: CMP_ru6
/* 1167 */    MCD_OPC_FilterValue, 156, 1, 4, 0, 0, // Skip to: 1177
/* 1173 */    MCD_OPC_Decode, 222, 4, 46, // Opcode: RSUB_rru6
/* 1177 */    MCD_OPC_FilterValue, 157, 1, 4, 0, 0, // Skip to: 1187
/* 1183 */    MCD_OPC_Decode, 218, 4, 46, // Opcode: RSUB_f_rru6
/* 1187 */    MCD_OPC_FilterValue, 174, 1, 4, 0, 0, // Skip to: 1197
/* 1193 */    MCD_OPC_Decode, 163, 5, 46, // Opcode: SUB1_rru6
/* 1197 */    MCD_OPC_FilterValue, 175, 1, 4, 0, 0, // Skip to: 1207
/* 1203 */    MCD_OPC_Decode, 159, 5, 46, // Opcode: SUB1_f_rru6
/* 1207 */    MCD_OPC_FilterValue, 176, 1, 4, 0, 0, // Skip to: 1217
/* 1213 */    MCD_OPC_Decode, 173, 5, 46, // Opcode: SUB2_rru6
/* 1217 */    MCD_OPC_FilterValue, 177, 1, 4, 0, 0, // Skip to: 1227
/* 1223 */    MCD_OPC_Decode, 169, 5, 46, // Opcode: SUB2_f_rru6
/* 1227 */    MCD_OPC_FilterValue, 178, 1, 4, 0, 0, // Skip to: 1237
/* 1233 */    MCD_OPC_Decode, 183, 5, 46, // Opcode: SUB3_rru6
/* 1237 */    MCD_OPC_FilterValue, 179, 1, 4, 0, 0, // Skip to: 1247
/* 1243 */    MCD_OPC_Decode, 179, 5, 46, // Opcode: SUB3_f_rru6
/* 1247 */    MCD_OPC_FilterValue, 180, 1, 4, 0, 0, // Skip to: 1257
/* 1253 */    MCD_OPC_Decode, 183, 4, 46, // Opcode: MPY_rru6
/* 1257 */    MCD_OPC_FilterValue, 181, 1, 4, 0, 0, // Skip to: 1267
/* 1263 */    MCD_OPC_Decode, 179, 4, 46, // Opcode: MPY_f_rru6
/* 1267 */    MCD_OPC_FilterValue, 182, 1, 4, 0, 0, // Skip to: 1277
/* 1273 */    MCD_OPC_Decode, 173, 4, 46, // Opcode: MPYM_rru6
/* 1277 */    MCD_OPC_FilterValue, 183, 1, 4, 0, 0, // Skip to: 1287
/* 1283 */    MCD_OPC_Decode, 169, 4, 46, // Opcode: MPYM_f_rru6
/* 1287 */    MCD_OPC_FilterValue, 184, 1, 4, 0, 0, // Skip to: 1297
/* 1293 */    MCD_OPC_Decode, 163, 4, 46, // Opcode: MPYMU_rru6
/* 1297 */    MCD_OPC_FilterValue, 185, 1, 4, 0, 0, // Skip to: 1307
/* 1303 */    MCD_OPC_Decode, 159, 4, 46, // Opcode: MPYMU_f_rru6
/* 1307 */    MCD_OPC_FilterValue, 212, 1, 11, 0, 0, // Skip to: 1324
/* 1313 */    MCD_OPC_CheckField, 0, 6, 0, 190, 5, 0, // Skip to: 2790
/* 1320 */    MCD_OPC_Decode, 237, 3, 48, // Opcode: LR_ru6
/* 1324 */    MCD_OPC_FilterValue, 240, 1, 4, 0, 0, // Skip to: 1334
/* 1330 */    MCD_OPC_Decode, 242, 4, 46, // Opcode: SETEQ_rru6
/* 1334 */    MCD_OPC_FilterValue, 241, 1, 4, 0, 0, // Skip to: 1344
/* 1340 */    MCD_OPC_Decode, 238, 4, 46, // Opcode: SETEQ_f_rru6
/* 1344 */    MCD_OPC_FilterValue, 128, 2, 4, 0, 0, // Skip to: 1354
/* 1350 */    MCD_OPC_Decode, 179, 2, 49, // Opcode: ADD_rrs12
/* 1354 */    MCD_OPC_FilterValue, 129, 2, 4, 0, 0, // Skip to: 1364
/* 1360 */    MCD_OPC_Decode, 175, 2, 49, // Opcode: ADD_f_rrs12
/* 1364 */    MCD_OPC_FilterValue, 130, 2, 4, 0, 0, // Skip to: 1374
/* 1370 */    MCD_OPC_Decode, 161, 2, 49, // Opcode: ADC_rrs12
/* 1374 */    MCD_OPC_FilterValue, 131, 2, 4, 0, 0, // Skip to: 1384
/* 1380 */    MCD_OPC_Decode, 157, 2, 49, // Opcode: ADC_f_rrs12
/* 1384 */    MCD_OPC_FilterValue, 132, 2, 4, 0, 0, // Skip to: 1394
/* 1390 */    MCD_OPC_Decode, 195, 5, 49, // Opcode: SUB_rrs12
/* 1394 */    MCD_OPC_FilterValue, 133, 2, 4, 0, 0, // Skip to: 1404
/* 1400 */    MCD_OPC_Decode, 191, 5, 49, // Opcode: SUB_f_rrs12
/* 1404 */    MCD_OPC_FilterValue, 134, 2, 4, 0, 0, // Skip to: 1414
/* 1410 */    MCD_OPC_Decode, 231, 4, 49, // Opcode: SBC_rrs12
/* 1414 */    MCD_OPC_FilterValue, 135, 2, 4, 0, 0, // Skip to: 1424
/* 1420 */    MCD_OPC_Decode, 227, 4, 49, // Opcode: SBC_f_rrs12
/* 1424 */    MCD_OPC_FilterValue, 136, 2, 4, 0, 0, // Skip to: 1434
/* 1430 */    MCD_OPC_Decode, 189, 2, 49, // Opcode: AND_rrs12
/* 1434 */    MCD_OPC_FilterValue, 137, 2, 4, 0, 0, // Skip to: 1444
/* 1440 */    MCD_OPC_Decode, 185, 2, 49, // Opcode: AND_f_rrs12
/* 1444 */    MCD_OPC_FilterValue, 138, 2, 4, 0, 0, // Skip to: 1454
/* 1450 */    MCD_OPC_Decode, 196, 4, 49, // Opcode: OR_rrs12
/* 1454 */    MCD_OPC_FilterValue, 139, 2, 4, 0, 0, // Skip to: 1464
/* 1460 */    MCD_OPC_Decode, 192, 4, 49, // Opcode: OR_f_rrs12
/* 1464 */    MCD_OPC_FilterValue, 142, 2, 4, 0, 0, // Skip to: 1474
/* 1470 */    MCD_OPC_Decode, 205, 5, 49, // Opcode: XOR_rrs12
/* 1474 */    MCD_OPC_FilterValue, 143, 2, 4, 0, 0, // Skip to: 1484
/* 1480 */    MCD_OPC_Decode, 201, 5, 49, // Opcode: XOR_f_rrs12
/* 1484 */    MCD_OPC_FilterValue, 144, 2, 4, 0, 0, // Skip to: 1494
/* 1490 */    MCD_OPC_Decode, 129, 4, 49, // Opcode: MAX_rrs12
/* 1494 */    MCD_OPC_FilterValue, 145, 2, 4, 0, 0, // Skip to: 1504
/* 1500 */    MCD_OPC_Decode, 253, 3, 49, // Opcode: MAX_f_rrs12
/* 1504 */    MCD_OPC_FilterValue, 146, 2, 4, 0, 0, // Skip to: 1514
/* 1510 */    MCD_OPC_Decode, 139, 4, 49, // Opcode: MIN_rrs12
/* 1514 */    MCD_OPC_FilterValue, 147, 2, 4, 0, 0, // Skip to: 1524
/* 1520 */    MCD_OPC_Decode, 135, 4, 49, // Opcode: MIN_f_rrs12
/* 1524 */    MCD_OPC_FilterValue, 148, 2, 4, 0, 0, // Skip to: 1534
/* 1530 */    MCD_OPC_Decode, 152, 4, 50, // Opcode: MOV_rs12
/* 1534 */    MCD_OPC_FilterValue, 156, 2, 4, 0, 0, // Skip to: 1544
/* 1540 */    MCD_OPC_Decode, 221, 4, 49, // Opcode: RSUB_rrs12
/* 1544 */    MCD_OPC_FilterValue, 157, 2, 4, 0, 0, // Skip to: 1554
/* 1550 */    MCD_OPC_Decode, 217, 4, 49, // Opcode: RSUB_f_rrs12
/* 1554 */    MCD_OPC_FilterValue, 174, 2, 4, 0, 0, // Skip to: 1564
/* 1560 */    MCD_OPC_Decode, 162, 5, 49, // Opcode: SUB1_rrs12
/* 1564 */    MCD_OPC_FilterValue, 175, 2, 4, 0, 0, // Skip to: 1574
/* 1570 */    MCD_OPC_Decode, 158, 5, 49, // Opcode: SUB1_f_rrs12
/* 1574 */    MCD_OPC_FilterValue, 176, 2, 4, 0, 0, // Skip to: 1584
/* 1580 */    MCD_OPC_Decode, 172, 5, 49, // Opcode: SUB2_rrs12
/* 1584 */    MCD_OPC_FilterValue, 177, 2, 4, 0, 0, // Skip to: 1594
/* 1590 */    MCD_OPC_Decode, 168, 5, 49, // Opcode: SUB2_f_rrs12
/* 1594 */    MCD_OPC_FilterValue, 178, 2, 4, 0, 0, // Skip to: 1604
/* 1600 */    MCD_OPC_Decode, 182, 5, 49, // Opcode: SUB3_rrs12
/* 1604 */    MCD_OPC_FilterValue, 179, 2, 4, 0, 0, // Skip to: 1614
/* 1610 */    MCD_OPC_Decode, 178, 5, 49, // Opcode: SUB3_f_rrs12
/* 1614 */    MCD_OPC_FilterValue, 180, 2, 4, 0, 0, // Skip to: 1624
/* 1620 */    MCD_OPC_Decode, 182, 4, 49, // Opcode: MPY_rrs12
/* 1624 */    MCD_OPC_FilterValue, 181, 2, 4, 0, 0, // Skip to: 1634
/* 1630 */    MCD_OPC_Decode, 178, 4, 49, // Opcode: MPY_f_rrs12
/* 1634 */    MCD_OPC_FilterValue, 182, 2, 4, 0, 0, // Skip to: 1644
/* 1640 */    MCD_OPC_Decode, 172, 4, 49, // Opcode: MPYM_rrs12
/* 1644 */    MCD_OPC_FilterValue, 183, 2, 4, 0, 0, // Skip to: 1654
/* 1650 */    MCD_OPC_Decode, 168, 4, 49, // Opcode: MPYM_f_rrs12
/* 1654 */    MCD_OPC_FilterValue, 184, 2, 4, 0, 0, // Skip to: 1664
/* 1660 */    MCD_OPC_Decode, 162, 4, 49, // Opcode: MPYMU_rrs12
/* 1664 */    MCD_OPC_FilterValue, 185, 2, 4, 0, 0, // Skip to: 1674
/* 1670 */    MCD_OPC_Decode, 158, 4, 49, // Opcode: MPYMU_f_rrs12
/* 1674 */    MCD_OPC_FilterValue, 212, 2, 4, 0, 0, // Skip to: 1684
/* 1680 */    MCD_OPC_Decode, 236, 3, 51, // Opcode: LR_rs12
/* 1684 */    MCD_OPC_FilterValue, 240, 2, 4, 0, 0, // Skip to: 1694
/* 1690 */    MCD_OPC_Decode, 241, 4, 49, // Opcode: SETEQ_rrs12
/* 1694 */    MCD_OPC_FilterValue, 241, 2, 4, 0, 0, // Skip to: 1704
/* 1700 */    MCD_OPC_Decode, 237, 4, 49, // Opcode: SETEQ_f_rrs12
/* 1704 */    MCD_OPC_FilterValue, 128, 3, 11, 0, 0, // Skip to: 1721
/* 1710 */    MCD_OPC_CheckField, 5, 1, 1, 49, 4, 0, // Skip to: 2790
/* 1717 */    MCD_OPC_Decode, 172, 2, 52, // Opcode: ADD_cc_rru6
/* 1721 */    MCD_OPC_FilterValue, 129, 3, 11, 0, 0, // Skip to: 1738
/* 1727 */    MCD_OPC_CheckField, 5, 1, 1, 32, 4, 0, // Skip to: 2790
/* 1734 */    MCD_OPC_Decode, 171, 2, 52, // Opcode: ADD_cc_f_rru6
/* 1738 */    MCD_OPC_FilterValue, 130, 3, 11, 0, 0, // Skip to: 1755
/* 1744 */    MCD_OPC_CheckField, 5, 1, 1, 15, 4, 0, // Skip to: 2790
/* 1751 */    MCD_OPC_Decode, 154, 2, 52, // Opcode: ADC_cc_rru6
/* 1755 */    MCD_OPC_FilterValue, 131, 3, 11, 0, 0, // Skip to: 1772
/* 1761 */    MCD_OPC_CheckField, 5, 1, 1, 254, 3, 0, // Skip to: 2790
/* 1768 */    MCD_OPC_Decode, 153, 2, 52, // Opcode: ADC_cc_f_rru6
/* 1772 */    MCD_OPC_FilterValue, 132, 3, 11, 0, 0, // Skip to: 1789
/* 1778 */    MCD_OPC_CheckField, 5, 1, 1, 237, 3, 0, // Skip to: 2790
/* 1785 */    MCD_OPC_Decode, 188, 5, 52, // Opcode: SUB_cc_rru6
/* 1789 */    MCD_OPC_FilterValue, 133, 3, 11, 0, 0, // Skip to: 1806
/* 1795 */    MCD_OPC_CheckField, 5, 1, 1, 220, 3, 0, // Skip to: 2790
/* 1802 */    MCD_OPC_Decode, 187, 5, 52, // Opcode: SUB_cc_f_rru6
/* 1806 */    MCD_OPC_FilterValue, 134, 3, 11, 0, 0, // Skip to: 1823
/* 1812 */    MCD_OPC_CheckField, 5, 1, 1, 203, 3, 0, // Skip to: 2790
/* 1819 */    MCD_OPC_Decode, 224, 4, 52, // Opcode: SBC_cc_rru6
/* 1823 */    MCD_OPC_FilterValue, 135, 3, 11, 0, 0, // Skip to: 1840
/* 1829 */    MCD_OPC_CheckField, 5, 1, 1, 186, 3, 0, // Skip to: 2790
/* 1836 */    MCD_OPC_Decode, 223, 4, 52, // Opcode: SBC_cc_f_rru6
/* 1840 */    MCD_OPC_FilterValue, 136, 3, 11, 0, 0, // Skip to: 1857
/* 1846 */    MCD_OPC_CheckField, 5, 1, 1, 169, 3, 0, // Skip to: 2790
/* 1853 */    MCD_OPC_Decode, 182, 2, 52, // Opcode: AND_cc_rru6
/* 1857 */    MCD_OPC_FilterValue, 137, 3, 11, 0, 0, // Skip to: 1874
/* 1863 */    MCD_OPC_CheckField, 5, 1, 1, 152, 3, 0, // Skip to: 2790
/* 1870 */    MCD_OPC_Decode, 181, 2, 52, // Opcode: AND_cc_f_rru6
/* 1874 */    MCD_OPC_FilterValue, 138, 3, 11, 0, 0, // Skip to: 1891
/* 1880 */    MCD_OPC_CheckField, 5, 1, 1, 135, 3, 0, // Skip to: 2790
/* 1887 */    MCD_OPC_Decode, 189, 4, 52, // Opcode: OR_cc_rru6
/* 1891 */    MCD_OPC_FilterValue, 139, 3, 11, 0, 0, // Skip to: 1908
/* 1897 */    MCD_OPC_CheckField, 5, 1, 1, 118, 3, 0, // Skip to: 2790
/* 1904 */    MCD_OPC_Decode, 188, 4, 52, // Opcode: OR_cc_f_rru6
/* 1908 */    MCD_OPC_FilterValue, 142, 3, 11, 0, 0, // Skip to: 1925
/* 1914 */    MCD_OPC_CheckField, 5, 1, 1, 101, 3, 0, // Skip to: 2790
/* 1921 */    MCD_OPC_Decode, 198, 5, 52, // Opcode: XOR_cc_rru6
/* 1925 */    MCD_OPC_FilterValue, 143, 3, 11, 0, 0, // Skip to: 1942
/* 1931 */    MCD_OPC_CheckField, 5, 1, 1, 84, 3, 0, // Skip to: 2790
/* 1938 */    MCD_OPC_Decode, 197, 5, 52, // Opcode: XOR_cc_f_rru6
/* 1942 */    MCD_OPC_FilterValue, 144, 3, 11, 0, 0, // Skip to: 1959
/* 1948 */    MCD_OPC_CheckField, 5, 1, 1, 67, 3, 0, // Skip to: 2790
/* 1955 */    MCD_OPC_Decode, 250, 3, 52, // Opcode: MAX_cc_rru6
/* 1959 */    MCD_OPC_FilterValue, 145, 3, 11, 0, 0, // Skip to: 1976
/* 1965 */    MCD_OPC_CheckField, 5, 1, 1, 50, 3, 0, // Skip to: 2790
/* 1972 */    MCD_OPC_Decode, 249, 3, 52, // Opcode: MAX_cc_f_rru6
/* 1976 */    MCD_OPC_FilterValue, 146, 3, 11, 0, 0, // Skip to: 1993
/* 1982 */    MCD_OPC_CheckField, 5, 1, 1, 33, 3, 0, // Skip to: 2790
/* 1989 */    MCD_OPC_Decode, 132, 4, 52, // Opcode: MIN_cc_rru6
/* 1993 */    MCD_OPC_FilterValue, 147, 3, 11, 0, 0, // Skip to: 2010
/* 1999 */    MCD_OPC_CheckField, 5, 1, 1, 16, 3, 0, // Skip to: 2790
/* 2006 */    MCD_OPC_Decode, 131, 4, 52, // Opcode: MIN_cc_f_rru6
/* 2010 */    MCD_OPC_FilterValue, 148, 3, 21, 0, 0, // Skip to: 2037
/* 2016 */    MCD_OPC_ExtractField, 5, 1,  // Inst{5} ...
/* 2019 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2028
/* 2024 */    MCD_OPC_Decode, 146, 4, 53, // Opcode: MOV_cc
/* 2028 */    MCD_OPC_FilterValue, 1, 245, 2, 0, // Skip to: 2790
/* 2033 */    MCD_OPC_Decode, 148, 4, 54, // Opcode: MOV_cc_ru6
/* 2037 */    MCD_OPC_FilterValue, 149, 3, 11, 0, 0, // Skip to: 2054
/* 2043 */    MCD_OPC_CheckField, 5, 1, 1, 228, 2, 0, // Skip to: 2790
/* 2050 */    MCD_OPC_Decode, 147, 4, 54, // Opcode: MOV_cc_f_ru6
/* 2054 */    MCD_OPC_FilterValue, 156, 3, 11, 0, 0, // Skip to: 2071
/* 2060 */    MCD_OPC_CheckField, 5, 1, 1, 211, 2, 0, // Skip to: 2790
/* 2067 */    MCD_OPC_Decode, 214, 4, 52, // Opcode: RSUB_cc_rru6
/* 2071 */    MCD_OPC_FilterValue, 157, 3, 11, 0, 0, // Skip to: 2088
/* 2077 */    MCD_OPC_CheckField, 5, 1, 1, 194, 2, 0, // Skip to: 2790
/* 2084 */    MCD_OPC_Decode, 213, 4, 52, // Opcode: RSUB_cc_f_rru6
/* 2088 */    MCD_OPC_FilterValue, 174, 3, 11, 0, 0, // Skip to: 2105
/* 2094 */    MCD_OPC_CheckField, 5, 1, 1, 177, 2, 0, // Skip to: 2790
/* 2101 */    MCD_OPC_Decode, 155, 5, 52, // Opcode: SUB1_cc_rru6
/* 2105 */    MCD_OPC_FilterValue, 175, 3, 11, 0, 0, // Skip to: 2122
/* 2111 */    MCD_OPC_CheckField, 5, 1, 1, 160, 2, 0, // Skip to: 2790
/* 2118 */    MCD_OPC_Decode, 154, 5, 52, // Opcode: SUB1_cc_f_rru6
/* 2122 */    MCD_OPC_FilterValue, 176, 3, 11, 0, 0, // Skip to: 2139
/* 2128 */    MCD_OPC_CheckField, 5, 1, 1, 143, 2, 0, // Skip to: 2790
/* 2135 */    MCD_OPC_Decode, 165, 5, 52, // Opcode: SUB2_cc_rru6
/* 2139 */    MCD_OPC_FilterValue, 177, 3, 11, 0, 0, // Skip to: 2156
/* 2145 */    MCD_OPC_CheckField, 5, 1, 1, 126, 2, 0, // Skip to: 2790
/* 2152 */    MCD_OPC_Decode, 164, 5, 52, // Opcode: SUB2_cc_f_rru6
/* 2156 */    MCD_OPC_FilterValue, 178, 3, 11, 0, 0, // Skip to: 2173
/* 2162 */    MCD_OPC_CheckField, 5, 1, 1, 109, 2, 0, // Skip to: 2790
/* 2169 */    MCD_OPC_Decode, 175, 5, 52, // Opcode: SUB3_cc_rru6
/* 2173 */    MCD_OPC_FilterValue, 179, 3, 11, 0, 0, // Skip to: 2190
/* 2179 */    MCD_OPC_CheckField, 5, 1, 1, 92, 2, 0, // Skip to: 2790
/* 2186 */    MCD_OPC_Decode, 174, 5, 52, // Opcode: SUB3_cc_f_rru6
/* 2190 */    MCD_OPC_FilterValue, 180, 3, 11, 0, 0, // Skip to: 2207
/* 2196 */    MCD_OPC_CheckField, 5, 1, 1, 75, 2, 0, // Skip to: 2790
/* 2203 */    MCD_OPC_Decode, 175, 4, 52, // Opcode: MPY_cc_rru6
/* 2207 */    MCD_OPC_FilterValue, 181, 3, 11, 0, 0, // Skip to: 2224
/* 2213 */    MCD_OPC_CheckField, 5, 1, 1, 58, 2, 0, // Skip to: 2790
/* 2220 */    MCD_OPC_Decode, 174, 4, 52, // Opcode: MPY_cc_f_rru6
/* 2224 */    MCD_OPC_FilterValue, 182, 3, 11, 0, 0, // Skip to: 2241
/* 2230 */    MCD_OPC_CheckField, 5, 1, 1, 41, 2, 0, // Skip to: 2790
/* 2237 */    MCD_OPC_Decode, 165, 4, 52, // Opcode: MPYM_cc_rru6
/* 2241 */    MCD_OPC_FilterValue, 183, 3, 11, 0, 0, // Skip to: 2258
/* 2247 */    MCD_OPC_CheckField, 5, 1, 1, 24, 2, 0, // Skip to: 2790
/* 2254 */    MCD_OPC_Decode, 164, 4, 52, // Opcode: MPYM_cc_f_rru6
/* 2258 */    MCD_OPC_FilterValue, 184, 3, 11, 0, 0, // Skip to: 2275
/* 2264 */    MCD_OPC_CheckField, 5, 1, 1, 7, 2, 0, // Skip to: 2790
/* 2271 */    MCD_OPC_Decode, 155, 4, 52, // Opcode: MPYMU_cc_rru6
/* 2275 */    MCD_OPC_FilterValue, 185, 3, 11, 0, 0, // Skip to: 2292
/* 2281 */    MCD_OPC_CheckField, 5, 1, 1, 246, 1, 0, // Skip to: 2790
/* 2288 */    MCD_OPC_Decode, 154, 4, 52, // Opcode: MPYMU_cc_f_rru6
/* 2292 */    MCD_OPC_FilterValue, 240, 3, 11, 0, 0, // Skip to: 2309
/* 2298 */    MCD_OPC_CheckField, 5, 1, 1, 229, 1, 0, // Skip to: 2790
/* 2305 */    MCD_OPC_Decode, 234, 4, 52, // Opcode: SETEQ_cc_rru6
/* 2309 */    MCD_OPC_FilterValue, 241, 3, 219, 1, 0, // Skip to: 2790
/* 2315 */    MCD_OPC_CheckField, 5, 1, 1, 212, 1, 0, // Skip to: 2790
/* 2322 */    MCD_OPC_Decode, 233, 4, 52, // Opcode: SETEQ_cc_f_rru6
/* 2326 */    MCD_OPC_FilterValue, 5, 203, 1, 0, // Skip to: 2790
/* 2331 */    MCD_OPC_ExtractField, 15, 9,  // Inst{23-15} ...
/* 2334 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2343
/* 2339 */    MCD_OPC_Decode, 200, 2, 43, // Opcode: ASL_rrr
/* 2343 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 2352
/* 2348 */    MCD_OPC_Decode, 196, 2, 43, // Opcode: ASL_f_rrr
/* 2352 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 2361
/* 2357 */    MCD_OPC_Decode, 246, 3, 43, // Opcode: LSR_rrr
/* 2361 */    MCD_OPC_FilterValue, 3, 4, 0, 0, // Skip to: 2370
/* 2366 */    MCD_OPC_Decode, 242, 3, 43, // Opcode: LSR_f_rrr
/* 2370 */    MCD_OPC_FilterValue, 4, 4, 0, 0, // Skip to: 2379
/* 2375 */    MCD_OPC_Decode, 212, 2, 43, // Opcode: ASR_rrr
/* 2379 */    MCD_OPC_FilterValue, 5, 4, 0, 0, // Skip to: 2388
/* 2384 */    MCD_OPC_Decode, 208, 2, 43, // Opcode: ASR_f_rrr
/* 2388 */    MCD_OPC_FilterValue, 6, 4, 0, 0, // Skip to: 2397
/* 2393 */    MCD_OPC_Decode, 210, 4, 43, // Opcode: ROR_rrr
/* 2397 */    MCD_OPC_FilterValue, 7, 4, 0, 0, // Skip to: 2406
/* 2402 */    MCD_OPC_Decode, 206, 4, 43, // Opcode: ROR_f_rrr
/* 2406 */    MCD_OPC_FilterValue, 94, 39, 0, 0, // Skip to: 2450
/* 2411 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 2414 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 2423
/* 2419 */    MCD_OPC_Decode, 187, 4, 44, // Opcode: NORM_rr
/* 2423 */    MCD_OPC_FilterValue, 8, 4, 0, 0, // Skip to: 2432
/* 2428 */    MCD_OPC_Decode, 185, 4, 44, // Opcode: NORMH_rr
/* 2432 */    MCD_OPC_FilterValue, 18, 4, 0, 0, // Skip to: 2441
/* 2437 */    MCD_OPC_Decode, 252, 2, 44, // Opcode: FFS_rr
/* 2441 */    MCD_OPC_FilterValue, 19, 88, 1, 0, // Skip to: 2790
/* 2446 */    MCD_OPC_Decode, 254, 2, 44, // Opcode: FLS_rr
/* 2450 */    MCD_OPC_FilterValue, 95, 39, 0, 0, // Skip to: 2494
/* 2455 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 2458 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 2467
/* 2463 */    MCD_OPC_Decode, 186, 4, 44, // Opcode: NORM_f_rr
/* 2467 */    MCD_OPC_FilterValue, 8, 4, 0, 0, // Skip to: 2476
/* 2472 */    MCD_OPC_Decode, 184, 4, 44, // Opcode: NORMH_f_rr
/* 2476 */    MCD_OPC_FilterValue, 18, 4, 0, 0, // Skip to: 2485
/* 2481 */    MCD_OPC_Decode, 251, 2, 44, // Opcode: FFS_f_rr
/* 2485 */    MCD_OPC_FilterValue, 19, 44, 1, 0, // Skip to: 2790
/* 2490 */    MCD_OPC_Decode, 253, 2, 44, // Opcode: FLS_f_rr
/* 2494 */    MCD_OPC_FilterValue, 128, 1, 4, 0, 0, // Skip to: 2504
/* 2500 */    MCD_OPC_Decode, 202, 2, 46, // Opcode: ASL_rru6
/* 2504 */    MCD_OPC_FilterValue, 129, 1, 4, 0, 0, // Skip to: 2514
/* 2510 */    MCD_OPC_Decode, 198, 2, 46, // Opcode: ASL_f_rru6
/* 2514 */    MCD_OPC_FilterValue, 130, 1, 4, 0, 0, // Skip to: 2524
/* 2520 */    MCD_OPC_Decode, 248, 3, 46, // Opcode: LSR_rru6
/* 2524 */    MCD_OPC_FilterValue, 131, 1, 4, 0, 0, // Skip to: 2534
/* 2530 */    MCD_OPC_Decode, 244, 3, 46, // Opcode: LSR_f_rru6
/* 2534 */    MCD_OPC_FilterValue, 132, 1, 4, 0, 0, // Skip to: 2544
/* 2540 */    MCD_OPC_Decode, 214, 2, 46, // Opcode: ASR_rru6
/* 2544 */    MCD_OPC_FilterValue, 133, 1, 4, 0, 0, // Skip to: 2554
/* 2550 */    MCD_OPC_Decode, 210, 2, 46, // Opcode: ASR_f_rru6
/* 2554 */    MCD_OPC_FilterValue, 134, 1, 4, 0, 0, // Skip to: 2564
/* 2560 */    MCD_OPC_Decode, 212, 4, 46, // Opcode: ROR_rru6
/* 2564 */    MCD_OPC_FilterValue, 135, 1, 4, 0, 0, // Skip to: 2574
/* 2570 */    MCD_OPC_Decode, 208, 4, 46, // Opcode: ROR_f_rru6
/* 2574 */    MCD_OPC_FilterValue, 128, 2, 4, 0, 0, // Skip to: 2584
/* 2580 */    MCD_OPC_Decode, 201, 2, 49, // Opcode: ASL_rrs12
/* 2584 */    MCD_OPC_FilterValue, 129, 2, 4, 0, 0, // Skip to: 2594
/* 2590 */    MCD_OPC_Decode, 197, 2, 49, // Opcode: ASL_f_rrs12
/* 2594 */    MCD_OPC_FilterValue, 130, 2, 4, 0, 0, // Skip to: 2604
/* 2600 */    MCD_OPC_Decode, 247, 3, 49, // Opcode: LSR_rrs12
/* 2604 */    MCD_OPC_FilterValue, 131, 2, 4, 0, 0, // Skip to: 2614
/* 2610 */    MCD_OPC_Decode, 243, 3, 49, // Opcode: LSR_f_rrs12
/* 2614 */    MCD_OPC_FilterValue, 132, 2, 4, 0, 0, // Skip to: 2624
/* 2620 */    MCD_OPC_Decode, 213, 2, 49, // Opcode: ASR_rrs12
/* 2624 */    MCD_OPC_FilterValue, 133, 2, 4, 0, 0, // Skip to: 2634
/* 2630 */    MCD_OPC_Decode, 209, 2, 49, // Opcode: ASR_f_rrs12
/* 2634 */    MCD_OPC_FilterValue, 134, 2, 4, 0, 0, // Skip to: 2644
/* 2640 */    MCD_OPC_Decode, 211, 4, 49, // Opcode: ROR_rrs12
/* 2644 */    MCD_OPC_FilterValue, 135, 2, 4, 0, 0, // Skip to: 2654
/* 2650 */    MCD_OPC_Decode, 207, 4, 49, // Opcode: ROR_f_rrs12
/* 2654 */    MCD_OPC_FilterValue, 128, 3, 11, 0, 0, // Skip to: 2671
/* 2660 */    MCD_OPC_CheckField, 5, 1, 1, 123, 0, 0, // Skip to: 2790
/* 2667 */    MCD_OPC_Decode, 194, 2, 52, // Opcode: ASL_cc_rru6
/* 2671 */    MCD_OPC_FilterValue, 129, 3, 11, 0, 0, // Skip to: 2688
/* 2677 */    MCD_OPC_CheckField, 5, 1, 1, 106, 0, 0, // Skip to: 2790
/* 2684 */    MCD_OPC_Decode, 193, 2, 52, // Opcode: ASL_cc_f_rru6
/* 2688 */    MCD_OPC_FilterValue, 130, 3, 11, 0, 0, // Skip to: 2705
/* 2694 */    MCD_OPC_CheckField, 5, 1, 1, 89, 0, 0, // Skip to: 2790
/* 2701 */    MCD_OPC_Decode, 240, 3, 52, // Opcode: LSR_cc_rru6
/* 2705 */    MCD_OPC_FilterValue, 131, 3, 11, 0, 0, // Skip to: 2722
/* 2711 */    MCD_OPC_CheckField, 5, 1, 1, 72, 0, 0, // Skip to: 2790
/* 2718 */    MCD_OPC_Decode, 239, 3, 52, // Opcode: LSR_cc_f_rru6
/* 2722 */    MCD_OPC_FilterValue, 132, 3, 11, 0, 0, // Skip to: 2739
/* 2728 */    MCD_OPC_CheckField, 5, 1, 1, 55, 0, 0, // Skip to: 2790
/* 2735 */    MCD_OPC_Decode, 206, 2, 52, // Opcode: ASR_cc_rru6
/* 2739 */    MCD_OPC_FilterValue, 133, 3, 11, 0, 0, // Skip to: 2756
/* 2745 */    MCD_OPC_CheckField, 5, 1, 1, 38, 0, 0, // Skip to: 2790
/* 2752 */    MCD_OPC_Decode, 205, 2, 52, // Opcode: ASR_cc_f_rru6
/* 2756 */    MCD_OPC_FilterValue, 134, 3, 11, 0, 0, // Skip to: 2773
/* 2762 */    MCD_OPC_CheckField, 5, 1, 1, 21, 0, 0, // Skip to: 2790
/* 2769 */    MCD_OPC_Decode, 204, 4, 52, // Opcode: ROR_cc_rru6
/* 2773 */    MCD_OPC_FilterValue, 135, 3, 11, 0, 0, // Skip to: 2790
/* 2779 */    MCD_OPC_CheckField, 5, 1, 1, 4, 0, 0, // Skip to: 2790
/* 2786 */    MCD_OPC_Decode, 203, 4, 52, // Opcode: ROR_cc_f_rru6
/* 2790 */    MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTable48[] = {
/* 0 */       MCD_OPC_ExtractField, 0, 3,  // Inst{2-0} ...
/* 3 */       MCD_OPC_FilterValue, 3, 45, 0, 0, // Skip to: 53
/* 8 */       MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 11 */      MCD_OPC_FilterValue, 8, 11, 0, 0, // Skip to: 27
/* 16 */      MCD_OPC_CheckField, 5, 3, 6, 86, 0, 0, // Skip to: 109
/* 23 */      MCD_OPC_Decode, 248, 2, 0, // Opcode: COMPACT_MOV_S_limm
/* 27 */      MCD_OPC_FilterValue, 14, 77, 0, 0, // Skip to: 109
/* 32 */      MCD_OPC_ExtractField, 3, 5,  // Inst{7-3} ...
/* 35 */      MCD_OPC_FilterValue, 24, 4, 0, 0, // Skip to: 44
/* 40 */      MCD_OPC_Decode, 164, 2, 55, // Opcode: ADD_S_rlimm
/* 44 */      MCD_OPC_FilterValue, 26, 60, 0, 0, // Skip to: 109
/* 49 */      MCD_OPC_Decode, 239, 2, 55, // Opcode: CMP_S_rlimm
/* 53 */      MCD_OPC_FilterValue, 7, 51, 0, 0, // Skip to: 109
/* 58 */      MCD_OPC_ExtractField, 3, 5,  // Inst{7-3} ...
/* 61 */      MCD_OPC_FilterValue, 24, 11, 0, 0, // Skip to: 77
/* 66 */      MCD_OPC_CheckField, 11, 5, 14, 36, 0, 0, // Skip to: 109
/* 73 */      MCD_OPC_Decode, 163, 2, 56, // Opcode: ADD_S_limms3
/* 77 */      MCD_OPC_FilterValue, 26, 11, 0, 0, // Skip to: 93
/* 82 */      MCD_OPC_CheckField, 11, 5, 14, 20, 0, 0, // Skip to: 109
/* 89 */      MCD_OPC_Decode, 238, 2, 56, // Opcode: CMP_S_limms3
/* 93 */      MCD_OPC_FilterValue, 27, 11, 0, 0, // Skip to: 109
/* 98 */      MCD_OPC_CheckField, 11, 5, 14, 4, 0, 0, // Skip to: 109
/* 105 */     MCD_OPC_Decode, 141, 4, 55, // Opcode: MOV_S_NE_rlimm
/* 109 */     MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTable64[] = {
/* 0 */       MCD_OPC_ExtractField, 15, 9,  // Inst{23-15} ...
/* 3 */       MCD_OPC_FilterValue, 0, 103, 1, 0, // Skip to: 367
/* 8 */       MCD_OPC_ExtractField, 27, 5,  // Inst{31-27} ...
/* 11 */      MCD_OPC_FilterValue, 2, 173, 0, 0, // Skip to: 189
/* 16 */      MCD_OPC_ExtractField, 6, 9,  // Inst{14-6} ...
/* 19 */      MCD_OPC_FilterValue, 192, 3, 11, 0, 0, // Skip to: 36
/* 25 */      MCD_OPC_CheckField, 24, 3, 6, 255, 5, 0, // Skip to: 1567
/* 32 */      MCD_OPC_Decode, 232, 3, 57, // Opcode: LD_limm
/* 36 */      MCD_OPC_FilterValue, 194, 3, 11, 0, 0, // Skip to: 53
/* 42 */      MCD_OPC_CheckField, 24, 3, 6, 238, 5, 0, // Skip to: 1567
/* 49 */      MCD_OPC_Decode, 194, 3, 57, // Opcode: LDB_limm
/* 53 */      MCD_OPC_FilterValue, 195, 3, 11, 0, 0, // Skip to: 70
/* 59 */      MCD_OPC_CheckField, 24, 3, 6, 221, 5, 0, // Skip to: 1567
/* 66 */      MCD_OPC_Decode, 191, 3, 57, // Opcode: LDB_X_limm
/* 70 */      MCD_OPC_FilterValue, 196, 3, 11, 0, 0, // Skip to: 87
/* 76 */      MCD_OPC_CheckField, 24, 3, 6, 204, 5, 0, // Skip to: 1567
/* 83 */      MCD_OPC_Decode, 217, 3, 57, // Opcode: LDH_limm
/* 87 */      MCD_OPC_FilterValue, 197, 3, 11, 0, 0, // Skip to: 104
/* 93 */      MCD_OPC_CheckField, 24, 3, 6, 187, 5, 0, // Skip to: 1567
/* 100 */     MCD_OPC_Decode, 214, 3, 57, // Opcode: LDH_X_limm
/* 104 */     MCD_OPC_FilterValue, 224, 3, 11, 0, 0, // Skip to: 121
/* 110 */     MCD_OPC_CheckField, 24, 3, 6, 170, 5, 0, // Skip to: 1567
/* 117 */     MCD_OPC_Decode, 225, 3, 57, // Opcode: LD_DI_limm
/* 121 */     MCD_OPC_FilterValue, 226, 3, 11, 0, 0, // Skip to: 138
/* 127 */     MCD_OPC_CheckField, 24, 3, 6, 153, 5, 0, // Skip to: 1567
/* 134 */     MCD_OPC_Decode, 179, 3, 57, // Opcode: LDB_DI_limm
/* 138 */     MCD_OPC_FilterValue, 227, 3, 11, 0, 0, // Skip to: 155
/* 144 */     MCD_OPC_CheckField, 24, 3, 6, 136, 5, 0, // Skip to: 1567
/* 151 */     MCD_OPC_Decode, 188, 3, 57, // Opcode: LDB_X_DI_limm
/* 155 */     MCD_OPC_FilterValue, 228, 3, 11, 0, 0, // Skip to: 172
/* 161 */     MCD_OPC_CheckField, 24, 3, 6, 119, 5, 0, // Skip to: 1567
/* 168 */     MCD_OPC_Decode, 201, 3, 57, // Opcode: LDH_DI_limm
/* 172 */     MCD_OPC_FilterValue, 229, 3, 109, 5, 0, // Skip to: 1567
/* 178 */     MCD_OPC_CheckField, 24, 3, 6, 102, 5, 0, // Skip to: 1567
/* 185 */     MCD_OPC_Decode, 211, 3, 57, // Opcode: LDH_X_DI_limm
/* 189 */     MCD_OPC_FilterValue, 3, 141, 0, 0, // Skip to: 335
/* 194 */     MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 197 */     MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 220
/* 202 */     MCD_OPC_CheckField, 24, 3, 6, 78, 5, 0, // Skip to: 1567
/* 209 */     MCD_OPC_CheckField, 12, 3, 7, 71, 5, 0, // Skip to: 1567
/* 216 */     MCD_OPC_Decode, 152, 5, 58, // Opcode: ST_limm
/* 220 */     MCD_OPC_FilterValue, 2, 18, 0, 0, // Skip to: 243
/* 225 */     MCD_OPC_CheckField, 24, 3, 6, 55, 5, 0, // Skip to: 1567
/* 232 */     MCD_OPC_CheckField, 12, 3, 7, 48, 5, 0, // Skip to: 1567
/* 239 */     MCD_OPC_Decode, 133, 5, 58, // Opcode: STB_limm
/* 243 */     MCD_OPC_FilterValue, 4, 18, 0, 0, // Skip to: 266
/* 248 */     MCD_OPC_CheckField, 24, 3, 6, 32, 5, 0, // Skip to: 1567
/* 255 */     MCD_OPC_CheckField, 12, 3, 7, 25, 5, 0, // Skip to: 1567
/* 262 */     MCD_OPC_Decode, 142, 5, 58, // Opcode: STH_limm
/* 266 */     MCD_OPC_FilterValue, 32, 18, 0, 0, // Skip to: 289
/* 271 */     MCD_OPC_CheckField, 24, 3, 6, 9, 5, 0, // Skip to: 1567
/* 278 */     MCD_OPC_CheckField, 12, 3, 7, 2, 5, 0, // Skip to: 1567
/* 285 */     MCD_OPC_Decode, 148, 5, 58, // Opcode: ST_DI_limm
/* 289 */     MCD_OPC_FilterValue, 34, 18, 0, 0, // Skip to: 312
/* 294 */     MCD_OPC_CheckField, 24, 3, 6, 242, 4, 0, // Skip to: 1567
/* 301 */     MCD_OPC_CheckField, 12, 3, 7, 235, 4, 0, // Skip to: 1567
/* 308 */     MCD_OPC_Decode, 130, 5, 58, // Opcode: STB_DI_limm
/* 312 */     MCD_OPC_FilterValue, 36, 226, 4, 0, // Skip to: 1567
/* 317 */     MCD_OPC_CheckField, 24, 3, 6, 219, 4, 0, // Skip to: 1567
/* 324 */     MCD_OPC_CheckField, 12, 3, 7, 212, 4, 0, // Skip to: 1567
/* 331 */     MCD_OPC_Decode, 139, 5, 58, // Opcode: STH_DI_limm
/* 335 */     MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 351
/* 340 */     MCD_OPC_CheckField, 6, 6, 62, 196, 4, 0, // Skip to: 1567
/* 347 */     MCD_OPC_Decode, 177, 2, 59, // Opcode: ADD_rrlimm
/* 351 */     MCD_OPC_FilterValue, 5, 187, 4, 0, // Skip to: 1567
/* 356 */     MCD_OPC_CheckField, 6, 6, 62, 180, 4, 0, // Skip to: 1567
/* 363 */     MCD_OPC_Decode, 199, 2, 59, // Opcode: ASL_rrlimm
/* 367 */     MCD_OPC_FilterValue, 1, 35, 0, 0, // Skip to: 407
/* 372 */     MCD_OPC_ExtractField, 27, 5,  // Inst{31-27} ...
/* 375 */     MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 391
/* 380 */     MCD_OPC_CheckField, 6, 6, 62, 156, 4, 0, // Skip to: 1567
/* 387 */     MCD_OPC_Decode, 173, 2, 59, // Opcode: ADD_f_rrlimm
/* 391 */     MCD_OPC_FilterValue, 5, 147, 4, 0, // Skip to: 1567
/* 396 */     MCD_OPC_CheckField, 6, 6, 62, 140, 4, 0, // Skip to: 1567
/* 403 */     MCD_OPC_Decode, 195, 2, 59, // Opcode: ASL_f_rrlimm
/* 407 */     MCD_OPC_FilterValue, 2, 35, 0, 0, // Skip to: 447
/* 412 */     MCD_OPC_ExtractField, 27, 5,  // Inst{31-27} ...
/* 415 */     MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 431
/* 420 */     MCD_OPC_CheckField, 6, 6, 62, 116, 4, 0, // Skip to: 1567
/* 427 */     MCD_OPC_Decode, 159, 2, 59, // Opcode: ADC_rrlimm
/* 431 */     MCD_OPC_FilterValue, 5, 107, 4, 0, // Skip to: 1567
/* 436 */     MCD_OPC_CheckField, 6, 6, 62, 100, 4, 0, // Skip to: 1567
/* 443 */     MCD_OPC_Decode, 245, 3, 59, // Opcode: LSR_rrlimm
/* 447 */     MCD_OPC_FilterValue, 3, 35, 0, 0, // Skip to: 487
/* 452 */     MCD_OPC_ExtractField, 27, 5,  // Inst{31-27} ...
/* 455 */     MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 471
/* 460 */     MCD_OPC_CheckField, 6, 6, 62, 76, 4, 0, // Skip to: 1567
/* 467 */     MCD_OPC_Decode, 155, 2, 59, // Opcode: ADC_f_rrlimm
/* 471 */     MCD_OPC_FilterValue, 5, 67, 4, 0, // Skip to: 1567
/* 476 */     MCD_OPC_CheckField, 6, 6, 62, 60, 4, 0, // Skip to: 1567
/* 483 */     MCD_OPC_Decode, 241, 3, 59, // Opcode: LSR_f_rrlimm
/* 487 */     MCD_OPC_FilterValue, 4, 35, 0, 0, // Skip to: 527
/* 492 */     MCD_OPC_ExtractField, 27, 5,  // Inst{31-27} ...
/* 495 */     MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 511
/* 500 */     MCD_OPC_CheckField, 6, 6, 62, 36, 4, 0, // Skip to: 1567
/* 507 */     MCD_OPC_Decode, 193, 5, 59, // Opcode: SUB_rrlimm
/* 511 */     MCD_OPC_FilterValue, 5, 27, 4, 0, // Skip to: 1567
/* 516 */     MCD_OPC_CheckField, 6, 6, 62, 20, 4, 0, // Skip to: 1567
/* 523 */     MCD_OPC_Decode, 211, 2, 59, // Opcode: ASR_rrlimm
/* 527 */     MCD_OPC_FilterValue, 5, 35, 0, 0, // Skip to: 567
/* 532 */     MCD_OPC_ExtractField, 27, 5,  // Inst{31-27} ...
/* 535 */     MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 551
/* 540 */     MCD_OPC_CheckField, 6, 6, 62, 252, 3, 0, // Skip to: 1567
/* 547 */     MCD_OPC_Decode, 189, 5, 59, // Opcode: SUB_f_rrlimm
/* 551 */     MCD_OPC_FilterValue, 5, 243, 3, 0, // Skip to: 1567
/* 556 */     MCD_OPC_CheckField, 6, 6, 62, 236, 3, 0, // Skip to: 1567
/* 563 */     MCD_OPC_Decode, 207, 2, 59, // Opcode: ASR_f_rrlimm
/* 567 */     MCD_OPC_FilterValue, 6, 35, 0, 0, // Skip to: 607
/* 572 */     MCD_OPC_ExtractField, 27, 5,  // Inst{31-27} ...
/* 575 */     MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 591
/* 580 */     MCD_OPC_CheckField, 6, 6, 62, 212, 3, 0, // Skip to: 1567
/* 587 */     MCD_OPC_Decode, 229, 4, 59, // Opcode: SBC_rrlimm
/* 591 */     MCD_OPC_FilterValue, 5, 203, 3, 0, // Skip to: 1567
/* 596 */     MCD_OPC_CheckField, 6, 6, 62, 196, 3, 0, // Skip to: 1567
/* 603 */     MCD_OPC_Decode, 209, 4, 59, // Opcode: ROR_rrlimm
/* 607 */     MCD_OPC_FilterValue, 7, 35, 0, 0, // Skip to: 647
/* 612 */     MCD_OPC_ExtractField, 27, 5,  // Inst{31-27} ...
/* 615 */     MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 631
/* 620 */     MCD_OPC_CheckField, 6, 6, 62, 172, 3, 0, // Skip to: 1567
/* 627 */     MCD_OPC_Decode, 225, 4, 59, // Opcode: SBC_f_rrlimm
/* 631 */     MCD_OPC_FilterValue, 5, 163, 3, 0, // Skip to: 1567
/* 636 */     MCD_OPC_CheckField, 6, 6, 62, 156, 3, 0, // Skip to: 1567
/* 643 */     MCD_OPC_Decode, 205, 4, 59, // Opcode: ROR_f_rrlimm
/* 647 */     MCD_OPC_FilterValue, 8, 18, 0, 0, // Skip to: 670
/* 652 */     MCD_OPC_CheckField, 27, 5, 4, 140, 3, 0, // Skip to: 1567
/* 659 */     MCD_OPC_CheckField, 6, 6, 62, 133, 3, 0, // Skip to: 1567
/* 666 */     MCD_OPC_Decode, 187, 2, 59, // Opcode: AND_rrlimm
/* 670 */     MCD_OPC_FilterValue, 9, 18, 0, 0, // Skip to: 693
/* 675 */     MCD_OPC_CheckField, 27, 5, 4, 117, 3, 0, // Skip to: 1567
/* 682 */     MCD_OPC_CheckField, 6, 6, 62, 110, 3, 0, // Skip to: 1567
/* 689 */     MCD_OPC_Decode, 183, 2, 59, // Opcode: AND_f_rrlimm
/* 693 */     MCD_OPC_FilterValue, 10, 18, 0, 0, // Skip to: 716
/* 698 */     MCD_OPC_CheckField, 27, 5, 4, 94, 3, 0, // Skip to: 1567
/* 705 */     MCD_OPC_CheckField, 6, 6, 62, 87, 3, 0, // Skip to: 1567
/* 712 */     MCD_OPC_Decode, 194, 4, 59, // Opcode: OR_rrlimm
/* 716 */     MCD_OPC_FilterValue, 11, 18, 0, 0, // Skip to: 739
/* 721 */     MCD_OPC_CheckField, 27, 5, 4, 71, 3, 0, // Skip to: 1567
/* 728 */     MCD_OPC_CheckField, 6, 6, 62, 64, 3, 0, // Skip to: 1567
/* 735 */     MCD_OPC_Decode, 190, 4, 59, // Opcode: OR_f_rrlimm
/* 739 */     MCD_OPC_FilterValue, 14, 18, 0, 0, // Skip to: 762
/* 744 */     MCD_OPC_CheckField, 27, 5, 4, 48, 3, 0, // Skip to: 1567
/* 751 */     MCD_OPC_CheckField, 6, 6, 62, 41, 3, 0, // Skip to: 1567
/* 758 */     MCD_OPC_Decode, 203, 5, 59, // Opcode: XOR_rrlimm
/* 762 */     MCD_OPC_FilterValue, 15, 18, 0, 0, // Skip to: 785
/* 767 */     MCD_OPC_CheckField, 27, 5, 4, 25, 3, 0, // Skip to: 1567
/* 774 */     MCD_OPC_CheckField, 6, 6, 62, 18, 3, 0, // Skip to: 1567
/* 781 */     MCD_OPC_Decode, 199, 5, 59, // Opcode: XOR_f_rrlimm
/* 785 */     MCD_OPC_FilterValue, 16, 18, 0, 0, // Skip to: 808
/* 790 */     MCD_OPC_CheckField, 27, 5, 4, 2, 3, 0, // Skip to: 1567
/* 797 */     MCD_OPC_CheckField, 6, 6, 62, 251, 2, 0, // Skip to: 1567
/* 804 */     MCD_OPC_Decode, 255, 3, 59, // Opcode: MAX_rrlimm
/* 808 */     MCD_OPC_FilterValue, 17, 18, 0, 0, // Skip to: 831
/* 813 */     MCD_OPC_CheckField, 27, 5, 4, 235, 2, 0, // Skip to: 1567
/* 820 */     MCD_OPC_CheckField, 6, 6, 62, 228, 2, 0, // Skip to: 1567
/* 827 */     MCD_OPC_Decode, 251, 3, 59, // Opcode: MAX_f_rrlimm
/* 831 */     MCD_OPC_FilterValue, 18, 18, 0, 0, // Skip to: 854
/* 836 */     MCD_OPC_CheckField, 27, 5, 4, 212, 2, 0, // Skip to: 1567
/* 843 */     MCD_OPC_CheckField, 6, 6, 62, 205, 2, 0, // Skip to: 1567
/* 850 */     MCD_OPC_Decode, 137, 4, 59, // Opcode: MIN_rrlimm
/* 854 */     MCD_OPC_FilterValue, 19, 18, 0, 0, // Skip to: 877
/* 859 */     MCD_OPC_CheckField, 27, 5, 4, 189, 2, 0, // Skip to: 1567
/* 866 */     MCD_OPC_CheckField, 6, 6, 62, 182, 2, 0, // Skip to: 1567
/* 873 */     MCD_OPC_Decode, 133, 4, 59, // Opcode: MIN_f_rrlimm
/* 877 */     MCD_OPC_FilterValue, 20, 18, 0, 0, // Skip to: 900
/* 882 */     MCD_OPC_CheckField, 27, 5, 4, 166, 2, 0, // Skip to: 1567
/* 889 */     MCD_OPC_CheckField, 6, 6, 62, 159, 2, 0, // Skip to: 1567
/* 896 */     MCD_OPC_Decode, 150, 4, 60, // Opcode: MOV_rlimm
/* 900 */     MCD_OPC_FilterValue, 25, 18, 0, 0, // Skip to: 923
/* 905 */     MCD_OPC_CheckField, 27, 5, 4, 143, 2, 0, // Skip to: 1567
/* 912 */     MCD_OPC_CheckField, 6, 6, 62, 136, 2, 0, // Skip to: 1567
/* 919 */     MCD_OPC_Decode, 243, 2, 60, // Opcode: CMP_rlimm
/* 923 */     MCD_OPC_FilterValue, 28, 18, 0, 0, // Skip to: 946
/* 928 */     MCD_OPC_CheckField, 27, 5, 4, 120, 2, 0, // Skip to: 1567
/* 935 */     MCD_OPC_CheckField, 6, 6, 62, 113, 2, 0, // Skip to: 1567
/* 942 */     MCD_OPC_Decode, 219, 4, 59, // Opcode: RSUB_rrlimm
/* 946 */     MCD_OPC_FilterValue, 29, 18, 0, 0, // Skip to: 969
/* 951 */     MCD_OPC_CheckField, 27, 5, 4, 97, 2, 0, // Skip to: 1567
/* 958 */     MCD_OPC_CheckField, 6, 6, 62, 90, 2, 0, // Skip to: 1567
/* 965 */     MCD_OPC_Decode, 215, 4, 59, // Opcode: RSUB_f_rrlimm
/* 969 */     MCD_OPC_FilterValue, 46, 18, 0, 0, // Skip to: 992
/* 974 */     MCD_OPC_CheckField, 27, 5, 4, 74, 2, 0, // Skip to: 1567
/* 981 */     MCD_OPC_CheckField, 6, 6, 62, 67, 2, 0, // Skip to: 1567
/* 988 */     MCD_OPC_Decode, 160, 5, 59, // Opcode: SUB1_rrlimm
/* 992 */     MCD_OPC_FilterValue, 47, 18, 0, 0, // Skip to: 1015
/* 997 */     MCD_OPC_CheckField, 27, 5, 4, 51, 2, 0, // Skip to: 1567
/* 1004 */    MCD_OPC_CheckField, 6, 6, 62, 44, 2, 0, // Skip to: 1567
/* 1011 */    MCD_OPC_Decode, 156, 5, 59, // Opcode: SUB1_f_rrlimm
/* 1015 */    MCD_OPC_FilterValue, 48, 18, 0, 0, // Skip to: 1038
/* 1020 */    MCD_OPC_CheckField, 27, 5, 4, 28, 2, 0, // Skip to: 1567
/* 1027 */    MCD_OPC_CheckField, 6, 6, 62, 21, 2, 0, // Skip to: 1567
/* 1034 */    MCD_OPC_Decode, 170, 5, 59, // Opcode: SUB2_rrlimm
/* 1038 */    MCD_OPC_FilterValue, 49, 18, 0, 0, // Skip to: 1061
/* 1043 */    MCD_OPC_CheckField, 27, 5, 4, 5, 2, 0, // Skip to: 1567
/* 1050 */    MCD_OPC_CheckField, 6, 6, 62, 254, 1, 0, // Skip to: 1567
/* 1057 */    MCD_OPC_Decode, 166, 5, 59, // Opcode: SUB2_f_rrlimm
/* 1061 */    MCD_OPC_FilterValue, 50, 18, 0, 0, // Skip to: 1084
/* 1066 */    MCD_OPC_CheckField, 27, 5, 4, 238, 1, 0, // Skip to: 1567
/* 1073 */    MCD_OPC_CheckField, 6, 6, 62, 231, 1, 0, // Skip to: 1567
/* 1080 */    MCD_OPC_Decode, 180, 5, 59, // Opcode: SUB3_rrlimm
/* 1084 */    MCD_OPC_FilterValue, 51, 18, 0, 0, // Skip to: 1107
/* 1089 */    MCD_OPC_CheckField, 27, 5, 4, 215, 1, 0, // Skip to: 1567
/* 1096 */    MCD_OPC_CheckField, 6, 6, 62, 208, 1, 0, // Skip to: 1567
/* 1103 */    MCD_OPC_Decode, 176, 5, 59, // Opcode: SUB3_f_rrlimm
/* 1107 */    MCD_OPC_FilterValue, 52, 18, 0, 0, // Skip to: 1130
/* 1112 */    MCD_OPC_CheckField, 27, 5, 4, 192, 1, 0, // Skip to: 1567
/* 1119 */    MCD_OPC_CheckField, 6, 6, 62, 185, 1, 0, // Skip to: 1567
/* 1126 */    MCD_OPC_Decode, 180, 4, 59, // Opcode: MPY_rrlimm
/* 1130 */    MCD_OPC_FilterValue, 53, 18, 0, 0, // Skip to: 1153
/* 1135 */    MCD_OPC_CheckField, 27, 5, 4, 169, 1, 0, // Skip to: 1567
/* 1142 */    MCD_OPC_CheckField, 6, 6, 62, 162, 1, 0, // Skip to: 1567
/* 1149 */    MCD_OPC_Decode, 176, 4, 59, // Opcode: MPY_f_rrlimm
/* 1153 */    MCD_OPC_FilterValue, 54, 18, 0, 0, // Skip to: 1176
/* 1158 */    MCD_OPC_CheckField, 27, 5, 4, 146, 1, 0, // Skip to: 1567
/* 1165 */    MCD_OPC_CheckField, 6, 6, 62, 139, 1, 0, // Skip to: 1567
/* 1172 */    MCD_OPC_Decode, 170, 4, 59, // Opcode: MPYM_rrlimm
/* 1176 */    MCD_OPC_FilterValue, 55, 18, 0, 0, // Skip to: 1199
/* 1181 */    MCD_OPC_CheckField, 27, 5, 4, 123, 1, 0, // Skip to: 1567
/* 1188 */    MCD_OPC_CheckField, 6, 6, 62, 116, 1, 0, // Skip to: 1567
/* 1195 */    MCD_OPC_Decode, 166, 4, 59, // Opcode: MPYM_f_rrlimm
/* 1199 */    MCD_OPC_FilterValue, 56, 18, 0, 0, // Skip to: 1222
/* 1204 */    MCD_OPC_CheckField, 27, 5, 4, 100, 1, 0, // Skip to: 1567
/* 1211 */    MCD_OPC_CheckField, 6, 6, 62, 93, 1, 0, // Skip to: 1567
/* 1218 */    MCD_OPC_Decode, 160, 4, 59, // Opcode: MPYMU_rrlimm
/* 1222 */    MCD_OPC_FilterValue, 57, 18, 0, 0, // Skip to: 1245
/* 1227 */    MCD_OPC_CheckField, 27, 5, 4, 77, 1, 0, // Skip to: 1567
/* 1234 */    MCD_OPC_CheckField, 6, 6, 62, 70, 1, 0, // Skip to: 1567
/* 1241 */    MCD_OPC_Decode, 156, 4, 59, // Opcode: MPYMU_f_rrlimm
/* 1245 */    MCD_OPC_FilterValue, 64, 18, 0, 0, // Skip to: 1268
/* 1250 */    MCD_OPC_CheckField, 27, 5, 4, 54, 1, 0, // Skip to: 1567
/* 1257 */    MCD_OPC_CheckField, 6, 6, 62, 47, 1, 0, // Skip to: 1567
/* 1264 */    MCD_OPC_Decode, 173, 3, 61, // Opcode: J_LImm
/* 1268 */    MCD_OPC_FilterValue, 68, 18, 0, 0, // Skip to: 1291
/* 1273 */    MCD_OPC_CheckField, 27, 5, 4, 31, 1, 0, // Skip to: 1567
/* 1280 */    MCD_OPC_CheckField, 6, 6, 62, 24, 1, 0, // Skip to: 1567
/* 1287 */    MCD_OPC_Decode, 172, 3, 61, // Opcode: JL_LImm
/* 1291 */    MCD_OPC_FilterValue, 96, 18, 0, 0, // Skip to: 1314
/* 1296 */    MCD_OPC_CheckField, 27, 5, 4, 8, 1, 0, // Skip to: 1567
/* 1303 */    MCD_OPC_CheckField, 6, 6, 62, 1, 1, 0, // Skip to: 1567
/* 1310 */    MCD_OPC_Decode, 233, 3, 62, // Opcode: LD_rlimm
/* 1314 */    MCD_OPC_FilterValue, 97, 18, 0, 0, // Skip to: 1337
/* 1319 */    MCD_OPC_CheckField, 27, 5, 4, 241, 0, 0, // Skip to: 1567
/* 1326 */    MCD_OPC_CheckField, 6, 6, 62, 234, 0, 0, // Skip to: 1567
/* 1333 */    MCD_OPC_Decode, 226, 3, 62, // Opcode: LD_DI_rlimm
/* 1337 */    MCD_OPC_FilterValue, 100, 18, 0, 0, // Skip to: 1360
/* 1342 */    MCD_OPC_CheckField, 27, 5, 4, 218, 0, 0, // Skip to: 1567
/* 1349 */    MCD_OPC_CheckField, 6, 6, 62, 211, 0, 0, // Skip to: 1567
/* 1356 */    MCD_OPC_Decode, 195, 3, 62, // Opcode: LDB_rlimm
/* 1360 */    MCD_OPC_FilterValue, 101, 18, 0, 0, // Skip to: 1383
/* 1365 */    MCD_OPC_CheckField, 27, 5, 4, 195, 0, 0, // Skip to: 1567
/* 1372 */    MCD_OPC_CheckField, 6, 6, 62, 188, 0, 0, // Skip to: 1567
/* 1379 */    MCD_OPC_Decode, 180, 3, 62, // Opcode: LDB_DI_rlimm
/* 1383 */    MCD_OPC_FilterValue, 102, 18, 0, 0, // Skip to: 1406
/* 1388 */    MCD_OPC_CheckField, 27, 5, 4, 172, 0, 0, // Skip to: 1567
/* 1395 */    MCD_OPC_CheckField, 6, 6, 62, 165, 0, 0, // Skip to: 1567
/* 1402 */    MCD_OPC_Decode, 192, 3, 62, // Opcode: LDB_X_rlimm
/* 1406 */    MCD_OPC_FilterValue, 103, 18, 0, 0, // Skip to: 1429
/* 1411 */    MCD_OPC_CheckField, 27, 5, 4, 149, 0, 0, // Skip to: 1567
/* 1418 */    MCD_OPC_CheckField, 6, 6, 62, 142, 0, 0, // Skip to: 1567
/* 1425 */    MCD_OPC_Decode, 189, 3, 62, // Opcode: LDB_X_DI_rlimm
/* 1429 */    MCD_OPC_FilterValue, 104, 18, 0, 0, // Skip to: 1452
/* 1434 */    MCD_OPC_CheckField, 27, 5, 4, 126, 0, 0, // Skip to: 1567
/* 1441 */    MCD_OPC_CheckField, 6, 6, 62, 119, 0, 0, // Skip to: 1567
/* 1448 */    MCD_OPC_Decode, 218, 3, 62, // Opcode: LDH_rlimm
/* 1452 */    MCD_OPC_FilterValue, 105, 18, 0, 0, // Skip to: 1475
/* 1457 */    MCD_OPC_CheckField, 27, 5, 4, 103, 0, 0, // Skip to: 1567
/* 1464 */    MCD_OPC_CheckField, 6, 6, 62, 96, 0, 0, // Skip to: 1567
/* 1471 */    MCD_OPC_Decode, 202, 3, 62, // Opcode: LDH_DI_rlimm
/* 1475 */    MCD_OPC_FilterValue, 106, 18, 0, 0, // Skip to: 1498
/* 1480 */    MCD_OPC_CheckField, 27, 5, 4, 80, 0, 0, // Skip to: 1567
/* 1487 */    MCD_OPC_CheckField, 6, 6, 62, 73, 0, 0, // Skip to: 1567
/* 1494 */    MCD_OPC_Decode, 215, 3, 62, // Opcode: LDH_X_rlimm
/* 1498 */    MCD_OPC_FilterValue, 107, 18, 0, 0, // Skip to: 1521
/* 1503 */    MCD_OPC_CheckField, 27, 5, 4, 57, 0, 0, // Skip to: 1567
/* 1510 */    MCD_OPC_CheckField, 6, 6, 62, 50, 0, 0, // Skip to: 1567
/* 1517 */    MCD_OPC_Decode, 212, 3, 62, // Opcode: LDH_X_DI_rlimm
/* 1521 */    MCD_OPC_FilterValue, 112, 18, 0, 0, // Skip to: 1544
/* 1526 */    MCD_OPC_CheckField, 27, 5, 4, 34, 0, 0, // Skip to: 1567
/* 1533 */    MCD_OPC_CheckField, 6, 6, 62, 27, 0, 0, // Skip to: 1567
/* 1540 */    MCD_OPC_Decode, 239, 4, 59, // Opcode: SETEQ_rrlimm
/* 1544 */    MCD_OPC_FilterValue, 113, 18, 0, 0, // Skip to: 1567
/* 1549 */    MCD_OPC_CheckField, 27, 5, 4, 11, 0, 0, // Skip to: 1567
/* 1556 */    MCD_OPC_CheckField, 6, 6, 62, 4, 0, 0, // Skip to: 1567
/* 1563 */    MCD_OPC_Decode, 235, 4, 59, // Opcode: SETEQ_f_rrlimm
/* 1567 */    MCD_OPC_Fail,
  0
};

static bool checkDecoderPredicate(MCInst *Inst, unsigned Idx) {
  return false;
}

#define DecodeToMCInst(fname, fieldname, InsnType) \
static DecodeStatus fname(DecodeStatus S, unsigned Idx, InsnType insn, MCInst *MI, \
		uint64_t Address, const void *Decoder, bool *DecodeComplete) \
{ \
  *DecodeComplete = true; \
  InsnType tmp; \
  switch (Idx) { \
  default: CS_ASSERT_RET_VAL(0 && "Invalid index!", MCDisassembler_Fail); \
  case 0: \
    if (!Check(&S, DecodeMoveHRegInstruction(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 1: \
    tmp = fieldname(insn, 8, 2); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 2) << 3; \
    tmp |= fieldname(insn, 5, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 3, 2) << 2; \
    tmp |= fieldname(insn, 10, 1) << 4; \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 2: \
    tmp = fieldname(insn, 0, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 3: \
    tmp = fieldname(insn, 7, 1); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 3) << 0; \
    tmp |= fieldname(insn, 4, 3) << 3; \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 4: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 3) << 2; \
    tmp |= fieldname(insn, 5, 6) << 5; \
    if (!Check(&S, DecodeSignedOperand_11(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 5: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 3) << 0; \
    tmp |= fieldname(insn, 4, 4) << 3; \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 6: \
    tmp = fieldname(insn, 0, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 7: \
    tmp = fieldname(insn, 5, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 8: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 2) << 3; \
    tmp |= fieldname(insn, 5, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 9: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 2) << 3; \
    tmp |= fieldname(insn, 5, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeFromCyclicRange_3(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 10: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeFromCyclicRange_3(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 11: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 12: \
    return S; \
  case 13: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 14: \
    tmp = fieldname(insn, 5, 6); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 15: \
    tmp = fieldname(insn, 5, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5) << 2; \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 16: \
    tmp = fieldname(insn, 5, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 17: \
    tmp = fieldname(insn, 5, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5) << 1; \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 18: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 19: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeGBR32ShortRegister(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5) << 2; \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 20: \
    tmp = fieldname(insn, 0, 5) << 2; \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 21: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 1, 4) << 0; \
    tmp |= fieldname(insn, 8, 3) << 4; \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 22: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeGBR32ShortRegister(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 23: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 1, 4) << 0; \
    tmp |= fieldname(insn, 8, 2) << 4; \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 24: \
    tmp = fieldname(insn, 0, 9) << 2; \
    if (!Check(&S, DecodeSignedOperand_11(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 25: \
    tmp = fieldname(insn, 0, 9); \
    if (!Check(&S, DecodeSignedOperand_9(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 26: \
    tmp = fieldname(insn, 0, 9) << 1; \
    if (!Check(&S, DecodeSignedOperand_10(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 27: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 8) << 2; \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 28: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 29: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 7); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 30: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 7) << 1; \
    if (!Check(&S, DecodeBranchTargetS_8(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 31: \
    tmp = fieldname(insn, 0, 9) << 1; \
    if (!Check(&S, DecodeBranchTargetS_10(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 32: \
    tmp = fieldname(insn, 0, 6) << 1; \
    if (!Check(&S, DecodeBranchTargetS_7(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 33: \
    tmp = fieldname(insn, 0, 11) << 2; \
    if (!Check(&S, DecodeBranchTargetS_13(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 34: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 6, 10) << 11; \
    tmp |= fieldname(insn, 17, 10) << 1; \
    if (!Check(&S, DecodeBranchTargetS_21(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 35: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 4) << 21; \
    tmp |= fieldname(insn, 6, 10) << 11; \
    tmp |= fieldname(insn, 17, 10) << 1; \
    if (!Check(&S, DecodeBranchTargetS_25(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 36: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 4) << 21; \
    tmp |= fieldname(insn, 6, 10) << 11; \
    tmp |= fieldname(insn, 18, 9) << 2; \
    if (!Check(&S, DecodeBranchTargetS_25(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 37: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 15, 1) << 8; \
    tmp |= fieldname(insn, 17, 7) << 1; \
    if (!Check(&S, DecodeBranchTargetS_9(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 12, 3) << 3; \
    tmp |= fieldname(insn, 24, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 6); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 38: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 15, 1) << 8; \
    tmp |= fieldname(insn, 17, 7) << 1; \
    if (!Check(&S, DecodeBranchTargetS_9(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 12, 3) << 3; \
    tmp |= fieldname(insn, 24, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 6); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 0, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 39: \
    tmp = fieldname(insn, 0, 6); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 12, 3) << 12; \
    tmp |= fieldname(insn, 15, 1) << 8; \
    tmp |= fieldname(insn, 16, 8) << 0; \
    tmp |= fieldname(insn, 24, 3) << 9; \
    if (!Check(&S, DecodeMEMrs9(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 40: \
    tmp = fieldname(insn, 0, 6); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 12, 3) << 3; \
    tmp |= fieldname(insn, 24, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 12, 3) << 3; \
    tmp |= fieldname(insn, 24, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 15, 1) << 8; \
    tmp |= fieldname(insn, 16, 8) << 0; \
    if (!Check(&S, DecodeSignedOperand_9(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 41: \
    tmp = fieldname(insn, 6, 6); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 12, 3) << 12; \
    tmp |= fieldname(insn, 15, 1) << 8; \
    tmp |= fieldname(insn, 16, 8) << 0; \
    tmp |= fieldname(insn, 24, 3) << 9; \
    if (!Check(&S, DecodeMEMrs9(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 42: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 12, 3) << 3; \
    tmp |= fieldname(insn, 24, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 6); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 12, 3) << 3; \
    tmp |= fieldname(insn, 24, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 15, 1) << 8; \
    tmp |= fieldname(insn, 16, 8) << 0; \
    if (!Check(&S, DecodeSignedOperand_9(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 43: \
    tmp = fieldname(insn, 0, 6); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 12, 3) << 3; \
    tmp |= fieldname(insn, 24, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 6); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 44: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 12, 3) << 3; \
    tmp |= fieldname(insn, 24, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 6); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 45: \
    tmp = fieldname(insn, 6, 6); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 46: \
    tmp = fieldname(insn, 0, 6); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 12, 3) << 3; \
    tmp |= fieldname(insn, 24, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 6); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 47: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 12, 3) << 3; \
    tmp |= fieldname(insn, 24, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 6); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 48: \
    if (!Check(&S, DecodeSOPwithRU6(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 49: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 12, 3) << 3; \
    tmp |= fieldname(insn, 24, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 12, 3) << 3; \
    tmp |= fieldname(insn, 24, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 6) << 6; \
    tmp |= fieldname(insn, 6, 6) << 0; \
    if (!Check(&S, DecodeSignedOperand_12(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 50: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 12, 3) << 3; \
    tmp |= fieldname(insn, 24, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 6) << 6; \
    tmp |= fieldname(insn, 6, 6) << 0; \
    if (!Check(&S, DecodeSignedOperand_12(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 51: \
    if (!Check(&S, DecodeSOPwithRS12(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 52: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 12, 3) << 3; \
    tmp |= fieldname(insn, 24, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 6); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 0, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = 0x0; \
    tmp |= fieldname(insn, 12, 3) << 3; \
    tmp |= fieldname(insn, 24, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 53: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 12, 3) << 3; \
    tmp |= fieldname(insn, 24, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 6); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 12, 3) << 3; \
    tmp |= fieldname(insn, 24, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 54: \
    if (!Check(&S, DecodeCCRU6Instruction(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 55: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 32); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 56: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeFromCyclicRange_3(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 32); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 57: \
    if (!Check(&S, DecodeLdLImmInstruction(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 58: \
    if (!Check(&S, DecodeStLImmInstruction(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 59: \
    tmp = fieldname(insn, 0, 6); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 12, 3) << 3; \
    tmp |= fieldname(insn, 24, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 32, 32); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 60: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 12, 3) << 3; \
    tmp |= fieldname(insn, 24, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 32, 32); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 61: \
    tmp = fieldname(insn, 32, 32); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 62: \
    if (!Check(&S, DecodeLdRLImmInstruction(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  } \
}

#define DecodeInstruction(fname, fieldname, decoder, InsnType) \
static DecodeStatus fname(const uint8_t DecodeTable[], MCInst *MI, \
                                      InsnType insn, uint64_t Address, const void *Decoder) { \
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
      S = decoder(S, DecodeIdx, insn, MI, Address, Decoder, &DecodeComplete); \
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
      S = decoder(S, DecodeIdx, insn, MI, Address, Decoder, &DecodeComplete); \
      if (DecodeComplete) { \
        /* Decoding complete. */ \
        return S; \
      } else { \
        /* LLVM uses a MCInst on the stack, but for our use case, */ \
        /* it is enough for now to reset the op counter. */ \
        MCInst_clear(MI); \
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
FieldFromInstruction(fieldFromInstruction_8, uint64_t)
DecodeToMCInst(decodeToMCInst_8, fieldFromInstruction_8, uint64_t)
DecodeInstruction(decodeInstruction_8, fieldFromInstruction_8, decodeToMCInst_8, uint64_t)
