/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* * Mips Disassembler                                                        *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#include "../../MCInst.h"
#include "../../LEB128.h"

// Helper function for extracting fields from encoded instructions.
#define FieldFromInstruction(fname, InsnType) \
static InsnType fname(InsnType insn, unsigned startBit, unsigned numBits) \
{ \
  InsnType fieldMask; \
  if (numBits == sizeof(InsnType)*8) \
    fieldMask = (InsnType)(-1LL); \
  else \
    fieldMask = (((InsnType)1 << numBits) - 1) << startBit; \
  return (insn & fieldMask) >> startBit; \
}

static uint8_t DecoderTableCOP3_32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 51, 8, 0, // Skip to: 15
/* 7 */       MCD_OPC_CheckPredicate, 1, 40, 0, // Skip to: 51
/* 11 */      MCD_OPC_Decode, 160, 7, 10, // Opcode: LWC3
/* 15 */      MCD_OPC_FilterValue, 55, 8, 0, // Skip to: 27
/* 19 */      MCD_OPC_CheckPredicate, 2, 28, 0, // Skip to: 51
/* 23 */      MCD_OPC_Decode, 238, 6, 10, // Opcode: LDC3
/* 27 */      MCD_OPC_FilterValue, 59, 8, 0, // Skip to: 39
/* 31 */      MCD_OPC_CheckPredicate, 1, 16, 0, // Skip to: 51
/* 35 */      MCD_OPC_Decode, 145, 12, 10, // Opcode: SWC3
/* 39 */      MCD_OPC_FilterValue, 63, 8, 0, // Skip to: 51
/* 43 */      MCD_OPC_CheckPredicate, 2, 4, 0, // Skip to: 51
/* 47 */      MCD_OPC_Decode, 198, 10, 10, // Opcode: SDC3
/* 51 */      MCD_OPC_Fail,
  0
};

static uint8_t DecoderTableMicroMips32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 30, 3, // Skip to: 805
/* 7 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10 */      MCD_OPC_FilterValue, 0, 51, 0, // Skip to: 65
/* 14 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 17 */      MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 29
/* 21 */      MCD_OPC_CheckPredicate, 3, 12, 5, // Skip to: 1317
/* 25 */      MCD_OPC_Decode, 145, 11, 13, // Opcode: SLL_MM
/* 29 */      MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 41
/* 33 */      MCD_OPC_CheckPredicate, 3, 0, 5, // Skip to: 1317
/* 37 */      MCD_OPC_Decode, 212, 11, 13, // Opcode: SRL_MM
/* 41 */      MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 53
/* 45 */      MCD_OPC_CheckPredicate, 3, 244, 4, // Skip to: 1317
/* 49 */      MCD_OPC_Decode, 192, 11, 13, // Opcode: SRA_MM
/* 53 */      MCD_OPC_FilterValue, 3, 236, 4, // Skip to: 1317
/* 57 */      MCD_OPC_CheckPredicate, 3, 232, 4, // Skip to: 1317
/* 61 */      MCD_OPC_Decode, 162, 10, 13, // Opcode: ROTR_MM
/* 65 */      MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 77
/* 69 */      MCD_OPC_CheckPredicate, 3, 220, 4, // Skip to: 1317
/* 73 */      MCD_OPC_Decode, 129, 2, 14, // Opcode: BREAK_MM
/* 77 */      MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 89
/* 81 */      MCD_OPC_CheckPredicate, 3, 208, 4, // Skip to: 1317
/* 85 */      MCD_OPC_Decode, 199, 6, 15, // Opcode: INS_MM
/* 89 */      MCD_OPC_FilterValue, 16, 180, 0, // Skip to: 273
/* 93 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 96 */      MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 108
/* 100 */     MCD_OPC_CheckPredicate, 3, 189, 4, // Skip to: 1317
/* 104 */     MCD_OPC_Decode, 141, 11, 16, // Opcode: SLLV_MM
/* 108 */     MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 120
/* 112 */     MCD_OPC_CheckPredicate, 3, 177, 4, // Skip to: 1317
/* 116 */     MCD_OPC_Decode, 208, 11, 16, // Opcode: SRLV_MM
/* 120 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 132
/* 124 */     MCD_OPC_CheckPredicate, 3, 165, 4, // Skip to: 1317
/* 128 */     MCD_OPC_Decode, 188, 11, 16, // Opcode: SRAV_MM
/* 132 */     MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 144
/* 136 */     MCD_OPC_CheckPredicate, 3, 153, 4, // Skip to: 1317
/* 140 */     MCD_OPC_Decode, 161, 10, 16, // Opcode: ROTRV_MM
/* 144 */     MCD_OPC_FilterValue, 4, 7, 0, // Skip to: 155
/* 148 */     MCD_OPC_CheckPredicate, 3, 141, 4, // Skip to: 1317
/* 152 */     MCD_OPC_Decode, 64, 17, // Opcode: ADD_MM
/* 155 */     MCD_OPC_FilterValue, 5, 7, 0, // Skip to: 166
/* 159 */     MCD_OPC_CheckPredicate, 3, 130, 4, // Skip to: 1317
/* 163 */     MCD_OPC_Decode, 70, 17, // Opcode: ADDu_MM
/* 166 */     MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 178
/* 170 */     MCD_OPC_CheckPredicate, 3, 119, 4, // Skip to: 1317
/* 174 */     MCD_OPC_Decode, 133, 12, 17, // Opcode: SUB_MM
/* 178 */     MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 190
/* 182 */     MCD_OPC_CheckPredicate, 3, 107, 4, // Skip to: 1317
/* 186 */     MCD_OPC_Decode, 135, 12, 17, // Opcode: SUBu_MM
/* 190 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 202
/* 194 */     MCD_OPC_CheckPredicate, 3, 95, 4, // Skip to: 1317
/* 198 */     MCD_OPC_Decode, 149, 9, 17, // Opcode: MUL_MM
/* 202 */     MCD_OPC_FilterValue, 9, 7, 0, // Skip to: 213
/* 206 */     MCD_OPC_CheckPredicate, 3, 83, 4, // Skip to: 1317
/* 210 */     MCD_OPC_Decode, 78, 17, // Opcode: AND_MM
/* 213 */     MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 225
/* 217 */     MCD_OPC_CheckPredicate, 3, 72, 4, // Skip to: 1317
/* 221 */     MCD_OPC_Decode, 195, 9, 17, // Opcode: OR_MM
/* 225 */     MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 237
/* 229 */     MCD_OPC_CheckPredicate, 3, 60, 4, // Skip to: 1317
/* 233 */     MCD_OPC_Decode, 185, 9, 17, // Opcode: NOR_MM
/* 237 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 249
/* 241 */     MCD_OPC_CheckPredicate, 3, 48, 4, // Skip to: 1317
/* 245 */     MCD_OPC_Decode, 132, 13, 17, // Opcode: XOR_MM
/* 249 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 261
/* 253 */     MCD_OPC_CheckPredicate, 3, 36, 4, // Skip to: 1317
/* 257 */     MCD_OPC_Decode, 149, 11, 17, // Opcode: SLT_MM
/* 261 */     MCD_OPC_FilterValue, 14, 28, 4, // Skip to: 1317
/* 265 */     MCD_OPC_CheckPredicate, 3, 24, 4, // Skip to: 1317
/* 269 */     MCD_OPC_Decode, 158, 11, 17, // Opcode: SLTu_MM
/* 273 */     MCD_OPC_FilterValue, 24, 27, 0, // Skip to: 304
/* 277 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 280 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 292
/* 284 */     MCD_OPC_CheckPredicate, 3, 5, 4, // Skip to: 1317
/* 288 */     MCD_OPC_Decode, 185, 8, 18, // Opcode: MOVN_I_MM
/* 292 */     MCD_OPC_FilterValue, 1, 253, 3, // Skip to: 1317
/* 296 */     MCD_OPC_CheckPredicate, 3, 249, 3, // Skip to: 1317
/* 300 */     MCD_OPC_Decode, 205, 8, 18, // Opcode: MOVZ_I_MM
/* 304 */     MCD_OPC_FilterValue, 44, 8, 0, // Skip to: 316
/* 308 */     MCD_OPC_CheckPredicate, 3, 237, 3, // Skip to: 1317
/* 312 */     MCD_OPC_Decode, 241, 4, 19, // Opcode: EXT_MM
/* 316 */     MCD_OPC_FilterValue, 60, 229, 3, // Skip to: 1317
/* 320 */     MCD_OPC_ExtractField, 6, 6,  // Inst{11-6} ...
/* 323 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 335
/* 327 */     MCD_OPC_CheckPredicate, 3, 218, 3, // Skip to: 1317
/* 331 */     MCD_OPC_Decode, 210, 12, 20, // Opcode: TEQ_MM
/* 335 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 347
/* 339 */     MCD_OPC_CheckPredicate, 3, 206, 3, // Skip to: 1317
/* 343 */     MCD_OPC_Decode, 218, 12, 20, // Opcode: TGE_MM
/* 347 */     MCD_OPC_FilterValue, 13, 51, 0, // Skip to: 402
/* 351 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 354 */     MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 366
/* 358 */     MCD_OPC_CheckPredicate, 3, 187, 3, // Skip to: 1317
/* 362 */     MCD_OPC_Decode, 253, 12, 21, // Opcode: WAIT_MM
/* 366 */     MCD_OPC_FilterValue, 14, 14, 0, // Skip to: 384
/* 370 */     MCD_OPC_CheckPredicate, 3, 175, 3, // Skip to: 1317
/* 374 */     MCD_OPC_CheckField, 16, 10, 0, 169, 3, // Skip to: 1317
/* 380 */     MCD_OPC_Decode, 129, 4, 0, // Opcode: DERET_MM
/* 384 */     MCD_OPC_FilterValue, 15, 161, 3, // Skip to: 1317
/* 388 */     MCD_OPC_CheckPredicate, 3, 157, 3, // Skip to: 1317
/* 392 */     MCD_OPC_CheckField, 16, 10, 0, 151, 3, // Skip to: 1317
/* 398 */     MCD_OPC_Decode, 225, 4, 0, // Opcode: ERET_MM
/* 402 */     MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 414
/* 406 */     MCD_OPC_CheckPredicate, 3, 139, 3, // Skip to: 1317
/* 410 */     MCD_OPC_Decode, 217, 12, 20, // Opcode: TGEU_MM
/* 414 */     MCD_OPC_FilterValue, 29, 39, 0, // Skip to: 457
/* 418 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 421 */     MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 439
/* 425 */     MCD_OPC_CheckPredicate, 3, 120, 3, // Skip to: 1317
/* 429 */     MCD_OPC_CheckField, 21, 5, 0, 114, 3, // Skip to: 1317
/* 435 */     MCD_OPC_Decode, 147, 4, 22, // Opcode: DI_MM
/* 439 */     MCD_OPC_FilterValue, 5, 106, 3, // Skip to: 1317
/* 443 */     MCD_OPC_CheckPredicate, 3, 102, 3, // Skip to: 1317
/* 447 */     MCD_OPC_CheckField, 21, 5, 0, 96, 3, // Skip to: 1317
/* 453 */     MCD_OPC_Decode, 223, 4, 22, // Opcode: EI_MM
/* 457 */     MCD_OPC_FilterValue, 32, 8, 0, // Skip to: 469
/* 461 */     MCD_OPC_CheckPredicate, 3, 84, 3, // Skip to: 1317
/* 465 */     MCD_OPC_Decode, 229, 12, 20, // Opcode: TLT_MM
/* 469 */     MCD_OPC_FilterValue, 40, 8, 0, // Skip to: 481
/* 473 */     MCD_OPC_CheckPredicate, 3, 72, 3, // Skip to: 1317
/* 477 */     MCD_OPC_Decode, 228, 12, 20, // Opcode: TLTU_MM
/* 481 */     MCD_OPC_FilterValue, 44, 159, 0, // Skip to: 644
/* 485 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 488 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 500
/* 492 */     MCD_OPC_CheckPredicate, 3, 53, 3, // Skip to: 1317
/* 496 */     MCD_OPC_Decode, 207, 10, 23, // Opcode: SEB_MM
/* 500 */     MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 512
/* 504 */     MCD_OPC_CheckPredicate, 3, 41, 3, // Skip to: 1317
/* 508 */     MCD_OPC_Decode, 210, 10, 23, // Opcode: SEH_MM
/* 512 */     MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 524
/* 516 */     MCD_OPC_CheckPredicate, 3, 29, 3, // Skip to: 1317
/* 520 */     MCD_OPC_Decode, 216, 2, 23, // Opcode: CLO_MM
/* 524 */     MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 536
/* 528 */     MCD_OPC_CheckPredicate, 3, 17, 3, // Skip to: 1317
/* 532 */     MCD_OPC_Decode, 235, 2, 23, // Opcode: CLZ_MM
/* 536 */     MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 548
/* 540 */     MCD_OPC_CheckPredicate, 3, 5, 3, // Skip to: 1317
/* 544 */     MCD_OPC_Decode, 128, 13, 23, // Opcode: WSBH_MM
/* 548 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 560
/* 552 */     MCD_OPC_CheckPredicate, 3, 249, 2, // Skip to: 1317
/* 556 */     MCD_OPC_Decode, 141, 9, 24, // Opcode: MULT_MM
/* 560 */     MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 572
/* 564 */     MCD_OPC_CheckPredicate, 3, 237, 2, // Skip to: 1317
/* 568 */     MCD_OPC_Decode, 143, 9, 24, // Opcode: MULTu_MM
/* 572 */     MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 584
/* 576 */     MCD_OPC_CheckPredicate, 3, 225, 2, // Skip to: 1317
/* 580 */     MCD_OPC_Decode, 200, 10, 24, // Opcode: SDIV_MM
/* 584 */     MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 596
/* 588 */     MCD_OPC_CheckPredicate, 3, 213, 2, // Skip to: 1317
/* 592 */     MCD_OPC_Decode, 244, 12, 24, // Opcode: UDIV_MM
/* 596 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 608
/* 600 */     MCD_OPC_CheckPredicate, 3, 201, 2, // Skip to: 1317
/* 604 */     MCD_OPC_Decode, 207, 7, 24, // Opcode: MADD_MM
/* 608 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 620
/* 612 */     MCD_OPC_CheckPredicate, 3, 189, 2, // Skip to: 1317
/* 616 */     MCD_OPC_Decode, 198, 7, 24, // Opcode: MADDU_MM
/* 620 */     MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 632
/* 624 */     MCD_OPC_CheckPredicate, 3, 177, 2, // Skip to: 1317
/* 628 */     MCD_OPC_Decode, 224, 8, 24, // Opcode: MSUB_MM
/* 632 */     MCD_OPC_FilterValue, 15, 169, 2, // Skip to: 1317
/* 636 */     MCD_OPC_CheckPredicate, 3, 165, 2, // Skip to: 1317
/* 640 */     MCD_OPC_Decode, 215, 8, 24, // Opcode: MSUBU_MM
/* 644 */     MCD_OPC_FilterValue, 45, 33, 0, // Skip to: 681
/* 648 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 651 */     MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 669
/* 655 */     MCD_OPC_CheckPredicate, 3, 146, 2, // Skip to: 1317
/* 659 */     MCD_OPC_CheckField, 21, 5, 0, 140, 2, // Skip to: 1317
/* 665 */     MCD_OPC_Decode, 156, 12, 25, // Opcode: SYNC_MM
/* 669 */     MCD_OPC_FilterValue, 8, 132, 2, // Skip to: 1317
/* 673 */     MCD_OPC_CheckPredicate, 3, 128, 2, // Skip to: 1317
/* 677 */     MCD_OPC_Decode, 158, 12, 21, // Opcode: SYSCALL_MM
/* 681 */     MCD_OPC_FilterValue, 48, 8, 0, // Skip to: 693
/* 685 */     MCD_OPC_CheckPredicate, 3, 116, 2, // Skip to: 1317
/* 689 */     MCD_OPC_Decode, 233, 12, 20, // Opcode: TNE_MM
/* 693 */     MCD_OPC_FilterValue, 53, 75, 0, // Skip to: 772
/* 697 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 700 */     MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 718
/* 704 */     MCD_OPC_CheckPredicate, 3, 97, 2, // Skip to: 1317
/* 708 */     MCD_OPC_CheckField, 21, 5, 0, 91, 2, // Skip to: 1317
/* 714 */     MCD_OPC_Decode, 251, 7, 22, // Opcode: MFHI_MM
/* 718 */     MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 736
/* 722 */     MCD_OPC_CheckPredicate, 3, 79, 2, // Skip to: 1317
/* 726 */     MCD_OPC_CheckField, 21, 5, 0, 73, 2, // Skip to: 1317
/* 732 */     MCD_OPC_Decode, 128, 8, 22, // Opcode: MFLO_MM
/* 736 */     MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 754
/* 740 */     MCD_OPC_CheckPredicate, 3, 61, 2, // Skip to: 1317
/* 744 */     MCD_OPC_CheckField, 21, 5, 0, 55, 2, // Skip to: 1317
/* 750 */     MCD_OPC_Decode, 239, 8, 22, // Opcode: MTHI_MM
/* 754 */     MCD_OPC_FilterValue, 3, 47, 2, // Skip to: 1317
/* 758 */     MCD_OPC_CheckPredicate, 3, 43, 2, // Skip to: 1317
/* 762 */     MCD_OPC_CheckField, 21, 5, 0, 37, 2, // Skip to: 1317
/* 768 */     MCD_OPC_Decode, 244, 8, 22, // Opcode: MTLO_MM
/* 772 */     MCD_OPC_FilterValue, 60, 29, 2, // Skip to: 1317
/* 776 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 779 */     MCD_OPC_FilterValue, 0, 22, 2, // Skip to: 1317
/* 783 */     MCD_OPC_CheckPredicate, 3, 10, 0, // Skip to: 797
/* 787 */     MCD_OPC_CheckField, 21, 5, 0, 4, 0, // Skip to: 797
/* 793 */     MCD_OPC_Decode, 217, 6, 22, // Opcode: JR_MM
/* 797 */     MCD_OPC_CheckPredicate, 3, 4, 2, // Skip to: 1317
/* 801 */     MCD_OPC_Decode, 208, 6, 23, // Opcode: JALR_MM
/* 805 */     MCD_OPC_FilterValue, 4, 7, 0, // Skip to: 816
/* 809 */     MCD_OPC_CheckPredicate, 3, 248, 1, // Skip to: 1317
/* 813 */     MCD_OPC_Decode, 66, 26, // Opcode: ADDi_MM
/* 816 */     MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 828
/* 820 */     MCD_OPC_CheckPredicate, 3, 237, 1, // Skip to: 1317
/* 824 */     MCD_OPC_Decode, 231, 6, 27, // Opcode: LBu_MM
/* 828 */     MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 840
/* 832 */     MCD_OPC_CheckPredicate, 3, 225, 1, // Skip to: 1317
/* 836 */     MCD_OPC_Decode, 184, 10, 27, // Opcode: SB_MM
/* 840 */     MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 852
/* 844 */     MCD_OPC_CheckPredicate, 3, 213, 1, // Skip to: 1317
/* 848 */     MCD_OPC_Decode, 228, 6, 27, // Opcode: LB_MM
/* 852 */     MCD_OPC_FilterValue, 12, 7, 0, // Skip to: 863
/* 856 */     MCD_OPC_CheckPredicate, 3, 201, 1, // Skip to: 1317
/* 860 */     MCD_OPC_Decode, 68, 26, // Opcode: ADDiu_MM
/* 863 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 875
/* 867 */     MCD_OPC_CheckPredicate, 3, 190, 1, // Skip to: 1317
/* 871 */     MCD_OPC_Decode, 133, 7, 27, // Opcode: LHu_MM
/* 875 */     MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 887
/* 879 */     MCD_OPC_CheckPredicate, 3, 178, 1, // Skip to: 1317
/* 883 */     MCD_OPC_Decode, 252, 10, 27, // Opcode: SH_MM
/* 887 */     MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 899
/* 891 */     MCD_OPC_CheckPredicate, 3, 166, 1, // Skip to: 1317
/* 895 */     MCD_OPC_Decode, 130, 7, 27, // Opcode: LH_MM
/* 899 */     MCD_OPC_FilterValue, 16, 159, 0, // Skip to: 1062
/* 903 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 906 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 918
/* 910 */     MCD_OPC_CheckPredicate, 3, 147, 1, // Skip to: 1317
/* 914 */     MCD_OPC_Decode, 228, 1, 28, // Opcode: BLTZ_MM
/* 918 */     MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 930
/* 922 */     MCD_OPC_CheckPredicate, 3, 135, 1, // Skip to: 1317
/* 926 */     MCD_OPC_Decode, 226, 1, 28, // Opcode: BLTZAL_MM
/* 930 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 942
/* 934 */     MCD_OPC_CheckPredicate, 3, 123, 1, // Skip to: 1317
/* 938 */     MCD_OPC_Decode, 191, 1, 28, // Opcode: BGEZ_MM
/* 942 */     MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 954
/* 946 */     MCD_OPC_CheckPredicate, 3, 111, 1, // Skip to: 1317
/* 950 */     MCD_OPC_Decode, 189, 1, 28, // Opcode: BGEZAL_MM
/* 954 */     MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 966
/* 958 */     MCD_OPC_CheckPredicate, 3, 99, 1, // Skip to: 1317
/* 962 */     MCD_OPC_Decode, 219, 1, 28, // Opcode: BLEZ_MM
/* 966 */     MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 978
/* 970 */     MCD_OPC_CheckPredicate, 3, 87, 1, // Skip to: 1317
/* 974 */     MCD_OPC_Decode, 196, 1, 28, // Opcode: BGTZ_MM
/* 978 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 990
/* 982 */     MCD_OPC_CheckPredicate, 3, 75, 1, // Skip to: 1317
/* 986 */     MCD_OPC_Decode, 226, 12, 29, // Opcode: TLTI_MM
/* 990 */     MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 1002
/* 994 */     MCD_OPC_CheckPredicate, 3, 63, 1, // Skip to: 1317
/* 998 */     MCD_OPC_Decode, 215, 12, 29, // Opcode: TGEI_MM
/* 1002 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 1014
/* 1006 */    MCD_OPC_CheckPredicate, 3, 51, 1, // Skip to: 1317
/* 1010 */    MCD_OPC_Decode, 225, 12, 29, // Opcode: TLTIU_MM
/* 1014 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1026
/* 1018 */    MCD_OPC_CheckPredicate, 3, 39, 1, // Skip to: 1317
/* 1022 */    MCD_OPC_Decode, 214, 12, 29, // Opcode: TGEIU_MM
/* 1026 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 1038
/* 1030 */    MCD_OPC_CheckPredicate, 3, 27, 1, // Skip to: 1317
/* 1034 */    MCD_OPC_Decode, 232, 12, 29, // Opcode: TNEI_MM
/* 1038 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 1050
/* 1042 */    MCD_OPC_CheckPredicate, 3, 15, 1, // Skip to: 1317
/* 1046 */    MCD_OPC_Decode, 153, 7, 29, // Opcode: LUi_MM
/* 1050 */    MCD_OPC_FilterValue, 14, 7, 1, // Skip to: 1317
/* 1054 */    MCD_OPC_CheckPredicate, 3, 3, 1, // Skip to: 1317
/* 1058 */    MCD_OPC_Decode, 209, 12, 29, // Opcode: TEQI_MM
/* 1062 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 1074
/* 1066 */    MCD_OPC_CheckPredicate, 3, 247, 0, // Skip to: 1317
/* 1070 */    MCD_OPC_Decode, 202, 9, 30, // Opcode: ORi_MM
/* 1074 */    MCD_OPC_FilterValue, 21, 29, 0, // Skip to: 1107
/* 1078 */    MCD_OPC_ExtractField, 0, 13,  // Inst{12-0} ...
/* 1081 */    MCD_OPC_FilterValue, 251, 2, 8, 0, // Skip to: 1094
/* 1086 */    MCD_OPC_CheckPredicate, 3, 227, 0, // Skip to: 1317
/* 1090 */    MCD_OPC_Decode, 173, 8, 31, // Opcode: MOVF_I_MM
/* 1094 */    MCD_OPC_FilterValue, 251, 18, 218, 0, // Skip to: 1317
/* 1099 */    MCD_OPC_CheckPredicate, 3, 214, 0, // Skip to: 1317
/* 1103 */    MCD_OPC_Decode, 193, 8, 31, // Opcode: MOVT_I_MM
/* 1107 */    MCD_OPC_FilterValue, 24, 87, 0, // Skip to: 1198
/* 1111 */    MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 1114 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1126
/* 1118 */    MCD_OPC_CheckPredicate, 3, 195, 0, // Skip to: 1317
/* 1122 */    MCD_OPC_Decode, 163, 7, 32, // Opcode: LWL_MM
/* 1126 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 1138
/* 1130 */    MCD_OPC_CheckPredicate, 3, 183, 0, // Skip to: 1317
/* 1134 */    MCD_OPC_Decode, 167, 7, 32, // Opcode: LWR_MM
/* 1138 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 1150
/* 1142 */    MCD_OPC_CheckPredicate, 3, 171, 0, // Skip to: 1317
/* 1146 */    MCD_OPC_Decode, 137, 7, 32, // Opcode: LL_MM
/* 1150 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 1162
/* 1154 */    MCD_OPC_CheckPredicate, 3, 159, 0, // Skip to: 1317
/* 1158 */    MCD_OPC_Decode, 148, 12, 32, // Opcode: SWL_MM
/* 1162 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 1174
/* 1166 */    MCD_OPC_CheckPredicate, 3, 147, 0, // Skip to: 1317
/* 1170 */    MCD_OPC_Decode, 151, 12, 32, // Opcode: SWR_MM
/* 1174 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1186
/* 1178 */    MCD_OPC_CheckPredicate, 3, 135, 0, // Skip to: 1317
/* 1182 */    MCD_OPC_Decode, 188, 10, 32, // Opcode: SC_MM
/* 1186 */    MCD_OPC_FilterValue, 14, 127, 0, // Skip to: 1317
/* 1190 */    MCD_OPC_CheckPredicate, 3, 123, 0, // Skip to: 1317
/* 1194 */    MCD_OPC_Decode, 169, 7, 32, // Opcode: LWU_MM
/* 1198 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 1210
/* 1202 */    MCD_OPC_CheckPredicate, 3, 111, 0, // Skip to: 1317
/* 1206 */    MCD_OPC_Decode, 139, 13, 30, // Opcode: XORi_MM
/* 1210 */    MCD_OPC_FilterValue, 36, 8, 0, // Skip to: 1222
/* 1214 */    MCD_OPC_CheckPredicate, 3, 99, 0, // Skip to: 1317
/* 1218 */    MCD_OPC_Decode, 152, 11, 26, // Opcode: SLTi_MM
/* 1222 */    MCD_OPC_FilterValue, 37, 8, 0, // Skip to: 1234
/* 1226 */    MCD_OPC_CheckPredicate, 3, 87, 0, // Skip to: 1317
/* 1230 */    MCD_OPC_Decode, 182, 1, 33, // Opcode: BEQ_MM
/* 1234 */    MCD_OPC_FilterValue, 44, 8, 0, // Skip to: 1246
/* 1238 */    MCD_OPC_CheckPredicate, 3, 75, 0, // Skip to: 1317
/* 1242 */    MCD_OPC_Decode, 155, 11, 26, // Opcode: SLTiu_MM
/* 1246 */    MCD_OPC_FilterValue, 45, 8, 0, // Skip to: 1258
/* 1250 */    MCD_OPC_CheckPredicate, 3, 63, 0, // Skip to: 1317
/* 1254 */    MCD_OPC_Decode, 246, 1, 33, // Opcode: BNE_MM
/* 1258 */    MCD_OPC_FilterValue, 52, 7, 0, // Skip to: 1269
/* 1262 */    MCD_OPC_CheckPredicate, 3, 51, 0, // Skip to: 1317
/* 1266 */    MCD_OPC_Decode, 85, 30, // Opcode: ANDi_MM
/* 1269 */    MCD_OPC_FilterValue, 53, 8, 0, // Skip to: 1281
/* 1273 */    MCD_OPC_CheckPredicate, 3, 40, 0, // Skip to: 1317
/* 1277 */    MCD_OPC_Decode, 218, 6, 34, // Opcode: J_MM
/* 1281 */    MCD_OPC_FilterValue, 61, 8, 0, // Skip to: 1293
/* 1285 */    MCD_OPC_CheckPredicate, 3, 28, 0, // Skip to: 1317
/* 1289 */    MCD_OPC_Decode, 210, 6, 34, // Opcode: JAL_MM
/* 1293 */    MCD_OPC_FilterValue, 62, 8, 0, // Skip to: 1305
/* 1297 */    MCD_OPC_CheckPredicate, 3, 16, 0, // Skip to: 1317
/* 1301 */    MCD_OPC_Decode, 154, 12, 27, // Opcode: SW_MM
/* 1305 */    MCD_OPC_FilterValue, 63, 8, 0, // Skip to: 1317
/* 1309 */    MCD_OPC_CheckPredicate, 3, 4, 0, // Skip to: 1317
/* 1313 */    MCD_OPC_Decode, 173, 7, 27, // Opcode: LW_MM
/* 1317 */    MCD_OPC_Fail,
  0
};

static uint8_t DecoderTableMips32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 173, 3, // Skip to: 948
/* 7 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10 */      MCD_OPC_FilterValue, 0, 54, 0, // Skip to: 68
/* 14 */      MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 17 */      MCD_OPC_FilterValue, 0, 51, 51, // Skip to: 13128
/* 21 */      MCD_OPC_ExtractField, 6, 15,  // Inst{20-6} ...
/* 24 */      MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 36
/* 28 */      MCD_OPC_CheckPredicate, 1, 28, 0, // Skip to: 60
/* 32 */      MCD_OPC_Decode, 214, 11, 0, // Opcode: SSNOP
/* 36 */      MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 48
/* 40 */      MCD_OPC_CheckPredicate, 1, 16, 0, // Skip to: 60
/* 44 */      MCD_OPC_Decode, 221, 4, 0, // Opcode: EHB
/* 48 */      MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 60
/* 52 */      MCD_OPC_CheckPredicate, 4, 4, 0, // Skip to: 60
/* 56 */      MCD_OPC_Decode, 205, 9, 0, // Opcode: PAUSE
/* 60 */      MCD_OPC_CheckPredicate, 1, 8, 51, // Skip to: 13128
/* 64 */      MCD_OPC_Decode, 133, 11, 35, // Opcode: SLL
/* 68 */      MCD_OPC_FilterValue, 1, 39, 0, // Skip to: 111
/* 72 */      MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 75 */      MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 93
/* 79 */      MCD_OPC_CheckPredicate, 5, 245, 50, // Skip to: 13128
/* 83 */      MCD_OPC_CheckField, 6, 5, 0, 239, 50, // Skip to: 13128
/* 89 */      MCD_OPC_Decode, 171, 8, 36, // Opcode: MOVF_I
/* 93 */      MCD_OPC_FilterValue, 1, 231, 50, // Skip to: 13128
/* 97 */      MCD_OPC_CheckPredicate, 5, 227, 50, // Skip to: 13128
/* 101 */     MCD_OPC_CheckField, 6, 5, 0, 221, 50, // Skip to: 13128
/* 107 */     MCD_OPC_Decode, 191, 8, 36, // Opcode: MOVT_I
/* 111 */     MCD_OPC_FilterValue, 2, 27, 0, // Skip to: 142
/* 115 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 118 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 130
/* 122 */     MCD_OPC_CheckPredicate, 1, 202, 50, // Skip to: 13128
/* 126 */     MCD_OPC_Decode, 194, 11, 35, // Opcode: SRL
/* 130 */     MCD_OPC_FilterValue, 1, 194, 50, // Skip to: 13128
/* 134 */     MCD_OPC_CheckPredicate, 4, 190, 50, // Skip to: 13128
/* 138 */     MCD_OPC_Decode, 159, 10, 35, // Opcode: ROTR
/* 142 */     MCD_OPC_FilterValue, 3, 14, 0, // Skip to: 160
/* 146 */     MCD_OPC_CheckPredicate, 1, 178, 50, // Skip to: 13128
/* 150 */     MCD_OPC_CheckField, 21, 5, 0, 172, 50, // Skip to: 13128
/* 156 */     MCD_OPC_Decode, 174, 11, 35, // Opcode: SRA
/* 160 */     MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 178
/* 164 */     MCD_OPC_CheckPredicate, 1, 160, 50, // Skip to: 13128
/* 168 */     MCD_OPC_CheckField, 6, 5, 0, 154, 50, // Skip to: 13128
/* 174 */     MCD_OPC_Decode, 140, 11, 17, // Opcode: SLLV
/* 178 */     MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 196
/* 182 */     MCD_OPC_CheckPredicate, 6, 142, 50, // Skip to: 13128
/* 186 */     MCD_OPC_CheckField, 8, 3, 0, 136, 50, // Skip to: 13128
/* 192 */     MCD_OPC_Decode, 146, 7, 37, // Opcode: LSA
/* 196 */     MCD_OPC_FilterValue, 6, 27, 0, // Skip to: 227
/* 200 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 203 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 215
/* 207 */     MCD_OPC_CheckPredicate, 1, 117, 50, // Skip to: 13128
/* 211 */     MCD_OPC_Decode, 207, 11, 17, // Opcode: SRLV
/* 215 */     MCD_OPC_FilterValue, 1, 109, 50, // Skip to: 13128
/* 219 */     MCD_OPC_CheckPredicate, 4, 105, 50, // Skip to: 13128
/* 223 */     MCD_OPC_Decode, 160, 10, 17, // Opcode: ROTRV
/* 227 */     MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 245
/* 231 */     MCD_OPC_CheckPredicate, 1, 93, 50, // Skip to: 13128
/* 235 */     MCD_OPC_CheckField, 6, 5, 0, 87, 50, // Skip to: 13128
/* 241 */     MCD_OPC_Decode, 187, 11, 17, // Opcode: SRAV
/* 245 */     MCD_OPC_FilterValue, 8, 27, 0, // Skip to: 276
/* 249 */     MCD_OPC_ExtractField, 6, 15,  // Inst{20-6} ...
/* 252 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 264
/* 256 */     MCD_OPC_CheckPredicate, 1, 68, 50, // Skip to: 13128
/* 260 */     MCD_OPC_Decode, 213, 6, 38, // Opcode: JR
/* 264 */     MCD_OPC_FilterValue, 16, 60, 50, // Skip to: 13128
/* 268 */     MCD_OPC_CheckPredicate, 7, 56, 50, // Skip to: 13128
/* 272 */     MCD_OPC_Decode, 215, 6, 38, // Opcode: JR_HB
/* 276 */     MCD_OPC_FilterValue, 9, 39, 0, // Skip to: 319
/* 280 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 283 */     MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 301
/* 287 */     MCD_OPC_CheckPredicate, 8, 37, 50, // Skip to: 13128
/* 291 */     MCD_OPC_CheckField, 16, 5, 0, 31, 50, // Skip to: 13128
/* 297 */     MCD_OPC_Decode, 202, 6, 39, // Opcode: JALR
/* 301 */     MCD_OPC_FilterValue, 16, 23, 50, // Skip to: 13128
/* 305 */     MCD_OPC_CheckPredicate, 9, 19, 50, // Skip to: 13128
/* 309 */     MCD_OPC_CheckField, 16, 5, 0, 13, 50, // Skip to: 13128
/* 315 */     MCD_OPC_Decode, 207, 6, 39, // Opcode: JALR_HB
/* 319 */     MCD_OPC_FilterValue, 10, 14, 0, // Skip to: 337
/* 323 */     MCD_OPC_CheckPredicate, 5, 1, 50, // Skip to: 13128
/* 327 */     MCD_OPC_CheckField, 6, 5, 0, 251, 49, // Skip to: 13128
/* 333 */     MCD_OPC_Decode, 203, 8, 40, // Opcode: MOVZ_I_I
/* 337 */     MCD_OPC_FilterValue, 11, 14, 0, // Skip to: 355
/* 341 */     MCD_OPC_CheckPredicate, 5, 239, 49, // Skip to: 13128
/* 345 */     MCD_OPC_CheckField, 6, 5, 0, 233, 49, // Skip to: 13128
/* 351 */     MCD_OPC_Decode, 183, 8, 40, // Opcode: MOVN_I_I
/* 355 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 367
/* 359 */     MCD_OPC_CheckPredicate, 1, 221, 49, // Skip to: 13128
/* 363 */     MCD_OPC_Decode, 157, 12, 41, // Opcode: SYSCALL
/* 367 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 379
/* 371 */     MCD_OPC_CheckPredicate, 1, 209, 49, // Skip to: 13128
/* 375 */     MCD_OPC_Decode, 128, 2, 14, // Opcode: BREAK
/* 379 */     MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 391
/* 383 */     MCD_OPC_CheckPredicate, 9, 197, 49, // Skip to: 13128
/* 387 */     MCD_OPC_Decode, 155, 12, 42, // Opcode: SYNC
/* 391 */     MCD_OPC_FilterValue, 16, 43, 0, // Skip to: 438
/* 395 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 398 */     MCD_OPC_FilterValue, 0, 182, 49, // Skip to: 13128
/* 402 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 405 */     MCD_OPC_FilterValue, 0, 175, 49, // Skip to: 13128
/* 409 */     MCD_OPC_ExtractField, 23, 3,  // Inst{25-23} ...
/* 412 */     MCD_OPC_FilterValue, 0, 168, 49, // Skip to: 13128
/* 416 */     MCD_OPC_CheckPredicate, 10, 10, 0, // Skip to: 430
/* 420 */     MCD_OPC_CheckField, 21, 2, 0, 4, 0, // Skip to: 430
/* 426 */     MCD_OPC_Decode, 247, 7, 43, // Opcode: MFHI
/* 430 */     MCD_OPC_CheckPredicate, 11, 150, 49, // Skip to: 13128
/* 434 */     MCD_OPC_Decode, 250, 7, 44, // Opcode: MFHI_DSP
/* 438 */     MCD_OPC_FilterValue, 17, 36, 0, // Skip to: 478
/* 442 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 445 */     MCD_OPC_FilterValue, 0, 135, 49, // Skip to: 13128
/* 449 */     MCD_OPC_ExtractField, 13, 8,  // Inst{20-13} ...
/* 452 */     MCD_OPC_FilterValue, 0, 128, 49, // Skip to: 13128
/* 456 */     MCD_OPC_CheckPredicate, 12, 10, 0, // Skip to: 470
/* 460 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 470
/* 466 */     MCD_OPC_Decode, 236, 8, 38, // Opcode: MTHI
/* 470 */     MCD_OPC_CheckPredicate, 11, 110, 49, // Skip to: 13128
/* 474 */     MCD_OPC_Decode, 238, 8, 45, // Opcode: MTHI_DSP
/* 478 */     MCD_OPC_FilterValue, 18, 43, 0, // Skip to: 525
/* 482 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 485 */     MCD_OPC_FilterValue, 0, 95, 49, // Skip to: 13128
/* 489 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 492 */     MCD_OPC_FilterValue, 0, 88, 49, // Skip to: 13128
/* 496 */     MCD_OPC_ExtractField, 23, 3,  // Inst{25-23} ...
/* 499 */     MCD_OPC_FilterValue, 0, 81, 49, // Skip to: 13128
/* 503 */     MCD_OPC_CheckPredicate, 10, 10, 0, // Skip to: 517
/* 507 */     MCD_OPC_CheckField, 21, 2, 0, 4, 0, // Skip to: 517
/* 513 */     MCD_OPC_Decode, 252, 7, 43, // Opcode: MFLO
/* 517 */     MCD_OPC_CheckPredicate, 11, 63, 49, // Skip to: 13128
/* 521 */     MCD_OPC_Decode, 255, 7, 44, // Opcode: MFLO_DSP
/* 525 */     MCD_OPC_FilterValue, 19, 36, 0, // Skip to: 565
/* 529 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 532 */     MCD_OPC_FilterValue, 0, 48, 49, // Skip to: 13128
/* 536 */     MCD_OPC_ExtractField, 13, 8,  // Inst{20-13} ...
/* 539 */     MCD_OPC_FilterValue, 0, 41, 49, // Skip to: 13128
/* 543 */     MCD_OPC_CheckPredicate, 12, 10, 0, // Skip to: 557
/* 547 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 557
/* 553 */     MCD_OPC_Decode, 241, 8, 38, // Opcode: MTLO
/* 557 */     MCD_OPC_CheckPredicate, 11, 23, 49, // Skip to: 13128
/* 561 */     MCD_OPC_Decode, 243, 8, 46, // Opcode: MTLO_DSP
/* 565 */     MCD_OPC_FilterValue, 21, 14, 0, // Skip to: 583
/* 569 */     MCD_OPC_CheckPredicate, 13, 11, 49, // Skip to: 13128
/* 573 */     MCD_OPC_CheckField, 8, 3, 0, 5, 49, // Skip to: 13128
/* 579 */     MCD_OPC_Decode, 148, 4, 47, // Opcode: DLSA
/* 583 */     MCD_OPC_FilterValue, 24, 36, 0, // Skip to: 623
/* 587 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 590 */     MCD_OPC_FilterValue, 0, 246, 48, // Skip to: 13128
/* 594 */     MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 597 */     MCD_OPC_FilterValue, 0, 239, 48, // Skip to: 13128
/* 601 */     MCD_OPC_CheckPredicate, 12, 10, 0, // Skip to: 615
/* 605 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 615
/* 611 */     MCD_OPC_Decode, 138, 9, 23, // Opcode: MULT
/* 615 */     MCD_OPC_CheckPredicate, 11, 221, 48, // Skip to: 13128
/* 619 */     MCD_OPC_Decode, 140, 9, 48, // Opcode: MULT_DSP
/* 623 */     MCD_OPC_FilterValue, 25, 36, 0, // Skip to: 663
/* 627 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 630 */     MCD_OPC_FilterValue, 0, 206, 48, // Skip to: 13128
/* 634 */     MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 637 */     MCD_OPC_FilterValue, 0, 199, 48, // Skip to: 13128
/* 641 */     MCD_OPC_CheckPredicate, 12, 10, 0, // Skip to: 655
/* 645 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 655
/* 651 */     MCD_OPC_Decode, 142, 9, 23, // Opcode: MULTu
/* 655 */     MCD_OPC_CheckPredicate, 11, 181, 48, // Skip to: 13128
/* 659 */     MCD_OPC_Decode, 139, 9, 48, // Opcode: MULTU_DSP
/* 663 */     MCD_OPC_FilterValue, 26, 14, 0, // Skip to: 681
/* 667 */     MCD_OPC_CheckPredicate, 12, 169, 48, // Skip to: 13128
/* 671 */     MCD_OPC_CheckField, 6, 10, 0, 163, 48, // Skip to: 13128
/* 677 */     MCD_OPC_Decode, 199, 10, 23, // Opcode: SDIV
/* 681 */     MCD_OPC_FilterValue, 27, 14, 0, // Skip to: 699
/* 685 */     MCD_OPC_CheckPredicate, 12, 151, 48, // Skip to: 13128
/* 689 */     MCD_OPC_CheckField, 6, 10, 0, 145, 48, // Skip to: 13128
/* 695 */     MCD_OPC_Decode, 243, 12, 23, // Opcode: UDIV
/* 699 */     MCD_OPC_FilterValue, 32, 13, 0, // Skip to: 716
/* 703 */     MCD_OPC_CheckPredicate, 1, 133, 48, // Skip to: 13128
/* 707 */     MCD_OPC_CheckField, 6, 5, 0, 127, 48, // Skip to: 13128
/* 713 */     MCD_OPC_Decode, 23, 16, // Opcode: ADD
/* 716 */     MCD_OPC_FilterValue, 33, 13, 0, // Skip to: 733
/* 720 */     MCD_OPC_CheckPredicate, 1, 116, 48, // Skip to: 13128
/* 724 */     MCD_OPC_CheckField, 6, 5, 0, 110, 48, // Skip to: 13128
/* 730 */     MCD_OPC_Decode, 69, 16, // Opcode: ADDu
/* 733 */     MCD_OPC_FilterValue, 34, 14, 0, // Skip to: 751
/* 737 */     MCD_OPC_CheckPredicate, 1, 99, 48, // Skip to: 13128
/* 741 */     MCD_OPC_CheckField, 6, 5, 0, 93, 48, // Skip to: 13128
/* 747 */     MCD_OPC_Decode, 223, 11, 16, // Opcode: SUB
/* 751 */     MCD_OPC_FilterValue, 35, 14, 0, // Skip to: 769
/* 755 */     MCD_OPC_CheckPredicate, 1, 81, 48, // Skip to: 13128
/* 759 */     MCD_OPC_CheckField, 6, 5, 0, 75, 48, // Skip to: 13128
/* 765 */     MCD_OPC_Decode, 134, 12, 16, // Opcode: SUBu
/* 769 */     MCD_OPC_FilterValue, 36, 13, 0, // Skip to: 786
/* 773 */     MCD_OPC_CheckPredicate, 1, 63, 48, // Skip to: 13128
/* 777 */     MCD_OPC_CheckField, 6, 5, 0, 57, 48, // Skip to: 13128
/* 783 */     MCD_OPC_Decode, 75, 16, // Opcode: AND
/* 786 */     MCD_OPC_FilterValue, 37, 14, 0, // Skip to: 804
/* 790 */     MCD_OPC_CheckPredicate, 1, 46, 48, // Skip to: 13128
/* 794 */     MCD_OPC_CheckField, 6, 5, 0, 40, 48, // Skip to: 13128
/* 800 */     MCD_OPC_Decode, 192, 9, 16, // Opcode: OR
/* 804 */     MCD_OPC_FilterValue, 38, 14, 0, // Skip to: 822
/* 808 */     MCD_OPC_CheckPredicate, 1, 28, 48, // Skip to: 13128
/* 812 */     MCD_OPC_CheckField, 6, 5, 0, 22, 48, // Skip to: 13128
/* 818 */     MCD_OPC_Decode, 129, 13, 16, // Opcode: XOR
/* 822 */     MCD_OPC_FilterValue, 39, 14, 0, // Skip to: 840
/* 826 */     MCD_OPC_CheckPredicate, 1, 10, 48, // Skip to: 13128
/* 830 */     MCD_OPC_CheckField, 6, 5, 0, 4, 48, // Skip to: 13128
/* 836 */     MCD_OPC_Decode, 182, 9, 16, // Opcode: NOR
/* 840 */     MCD_OPC_FilterValue, 42, 14, 0, // Skip to: 858
/* 844 */     MCD_OPC_CheckPredicate, 1, 248, 47, // Skip to: 13128
/* 848 */     MCD_OPC_CheckField, 6, 5, 0, 242, 47, // Skip to: 13128
/* 854 */     MCD_OPC_Decode, 147, 11, 16, // Opcode: SLT
/* 858 */     MCD_OPC_FilterValue, 43, 14, 0, // Skip to: 876
/* 862 */     MCD_OPC_CheckPredicate, 1, 230, 47, // Skip to: 13128
/* 866 */     MCD_OPC_CheckField, 6, 5, 0, 224, 47, // Skip to: 13128
/* 872 */     MCD_OPC_Decode, 156, 11, 16, // Opcode: SLTu
/* 876 */     MCD_OPC_FilterValue, 48, 8, 0, // Skip to: 888
/* 880 */     MCD_OPC_CheckPredicate, 1, 212, 47, // Skip to: 13128
/* 884 */     MCD_OPC_Decode, 211, 12, 49, // Opcode: TGE
/* 888 */     MCD_OPC_FilterValue, 49, 8, 0, // Skip to: 900
/* 892 */     MCD_OPC_CheckPredicate, 1, 200, 47, // Skip to: 13128
/* 896 */     MCD_OPC_Decode, 216, 12, 49, // Opcode: TGEU
/* 900 */     MCD_OPC_FilterValue, 50, 8, 0, // Skip to: 912
/* 904 */     MCD_OPC_CheckPredicate, 1, 188, 47, // Skip to: 13128
/* 908 */     MCD_OPC_Decode, 223, 12, 49, // Opcode: TLT
/* 912 */     MCD_OPC_FilterValue, 51, 8, 0, // Skip to: 924
/* 916 */     MCD_OPC_CheckPredicate, 1, 176, 47, // Skip to: 13128
/* 920 */     MCD_OPC_Decode, 227, 12, 49, // Opcode: TLTU
/* 924 */     MCD_OPC_FilterValue, 52, 8, 0, // Skip to: 936
/* 928 */     MCD_OPC_CheckPredicate, 1, 164, 47, // Skip to: 13128
/* 932 */     MCD_OPC_Decode, 207, 12, 49, // Opcode: TEQ
/* 936 */     MCD_OPC_FilterValue, 54, 156, 47, // Skip to: 13128
/* 940 */     MCD_OPC_CheckPredicate, 1, 152, 47, // Skip to: 13128
/* 944 */     MCD_OPC_Decode, 230, 12, 49, // Opcode: TNE
/* 948 */     MCD_OPC_FilterValue, 1, 141, 0, // Skip to: 1093
/* 952 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 955 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 967
/* 959 */     MCD_OPC_CheckPredicate, 1, 133, 47, // Skip to: 13128
/* 963 */     MCD_OPC_Decode, 222, 1, 50, // Opcode: BLTZ
/* 967 */     MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 979
/* 971 */     MCD_OPC_CheckPredicate, 1, 121, 47, // Skip to: 13128
/* 975 */     MCD_OPC_Decode, 185, 1, 50, // Opcode: BGEZ
/* 979 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 991
/* 983 */     MCD_OPC_CheckPredicate, 14, 109, 47, // Skip to: 13128
/* 987 */     MCD_OPC_Decode, 212, 12, 51, // Opcode: TGEI
/* 991 */     MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 1003
/* 995 */     MCD_OPC_CheckPredicate, 14, 97, 47, // Skip to: 13128
/* 999 */     MCD_OPC_Decode, 213, 12, 51, // Opcode: TGEIU
/* 1003 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 1015
/* 1007 */    MCD_OPC_CheckPredicate, 14, 85, 47, // Skip to: 13128
/* 1011 */    MCD_OPC_Decode, 224, 12, 51, // Opcode: TLTI
/* 1015 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1027
/* 1019 */    MCD_OPC_CheckPredicate, 14, 73, 47, // Skip to: 13128
/* 1023 */    MCD_OPC_Decode, 242, 12, 51, // Opcode: TTLTIU
/* 1027 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 1039
/* 1031 */    MCD_OPC_CheckPredicate, 14, 61, 47, // Skip to: 13128
/* 1035 */    MCD_OPC_Decode, 208, 12, 51, // Opcode: TEQI
/* 1039 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 1051
/* 1043 */    MCD_OPC_CheckPredicate, 14, 49, 47, // Skip to: 13128
/* 1047 */    MCD_OPC_Decode, 231, 12, 51, // Opcode: TNEI
/* 1051 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 1063
/* 1055 */    MCD_OPC_CheckPredicate, 12, 37, 47, // Skip to: 13128
/* 1059 */    MCD_OPC_Decode, 224, 1, 50, // Opcode: BLTZAL
/* 1063 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 1075
/* 1067 */    MCD_OPC_CheckPredicate, 12, 25, 47, // Skip to: 13128
/* 1071 */    MCD_OPC_Decode, 187, 1, 50, // Opcode: BGEZAL
/* 1075 */    MCD_OPC_FilterValue, 28, 17, 47, // Skip to: 13128
/* 1079 */    MCD_OPC_CheckPredicate, 11, 13, 47, // Skip to: 13128
/* 1083 */    MCD_OPC_CheckField, 21, 5, 0, 7, 47, // Skip to: 13128
/* 1089 */    MCD_OPC_Decode, 254, 1, 52, // Opcode: BPOSGE32
/* 1093 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 1105
/* 1097 */    MCD_OPC_CheckPredicate, 9, 251, 46, // Skip to: 13128
/* 1101 */    MCD_OPC_Decode, 200, 6, 53, // Opcode: J
/* 1105 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 1117
/* 1109 */    MCD_OPC_CheckPredicate, 1, 239, 46, // Skip to: 13128
/* 1113 */    MCD_OPC_Decode, 201, 6, 53, // Opcode: JAL
/* 1117 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 1129
/* 1121 */    MCD_OPC_CheckPredicate, 1, 227, 46, // Skip to: 13128
/* 1125 */    MCD_OPC_Decode, 177, 1, 54, // Opcode: BEQ
/* 1129 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 1141
/* 1133 */    MCD_OPC_CheckPredicate, 1, 215, 46, // Skip to: 13128
/* 1137 */    MCD_OPC_Decode, 233, 1, 54, // Opcode: BNE
/* 1141 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 1159
/* 1145 */    MCD_OPC_CheckPredicate, 1, 203, 46, // Skip to: 13128
/* 1149 */    MCD_OPC_CheckField, 16, 5, 0, 197, 46, // Skip to: 13128
/* 1155 */    MCD_OPC_Decode, 215, 1, 50, // Opcode: BLEZ
/* 1159 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 1177
/* 1163 */    MCD_OPC_CheckPredicate, 1, 185, 46, // Skip to: 13128
/* 1167 */    MCD_OPC_CheckField, 16, 5, 0, 179, 46, // Skip to: 13128
/* 1173 */    MCD_OPC_Decode, 192, 1, 50, // Opcode: BGTZ
/* 1177 */    MCD_OPC_FilterValue, 8, 7, 0, // Skip to: 1188
/* 1181 */    MCD_OPC_CheckPredicate, 12, 167, 46, // Skip to: 13128
/* 1185 */    MCD_OPC_Decode, 65, 55, // Opcode: ADDi
/* 1188 */    MCD_OPC_FilterValue, 9, 7, 0, // Skip to: 1199
/* 1192 */    MCD_OPC_CheckPredicate, 1, 156, 46, // Skip to: 13128
/* 1196 */    MCD_OPC_Decode, 67, 55, // Opcode: ADDiu
/* 1199 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 1211
/* 1203 */    MCD_OPC_CheckPredicate, 1, 145, 46, // Skip to: 13128
/* 1207 */    MCD_OPC_Decode, 150, 11, 55, // Opcode: SLTi
/* 1211 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1223
/* 1215 */    MCD_OPC_CheckPredicate, 1, 133, 46, // Skip to: 13128
/* 1219 */    MCD_OPC_Decode, 153, 11, 55, // Opcode: SLTiu
/* 1223 */    MCD_OPC_FilterValue, 12, 7, 0, // Skip to: 1234
/* 1227 */    MCD_OPC_CheckPredicate, 1, 121, 46, // Skip to: 13128
/* 1231 */    MCD_OPC_Decode, 83, 56, // Opcode: ANDi
/* 1234 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 1246
/* 1238 */    MCD_OPC_CheckPredicate, 1, 110, 46, // Skip to: 13128
/* 1242 */    MCD_OPC_Decode, 200, 9, 56, // Opcode: ORi
/* 1246 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 1258
/* 1250 */    MCD_OPC_CheckPredicate, 1, 98, 46, // Skip to: 13128
/* 1254 */    MCD_OPC_Decode, 137, 13, 56, // Opcode: XORi
/* 1258 */    MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 1276
/* 1262 */    MCD_OPC_CheckPredicate, 1, 86, 46, // Skip to: 13128
/* 1266 */    MCD_OPC_CheckField, 21, 5, 0, 80, 46, // Skip to: 13128
/* 1272 */    MCD_OPC_Decode, 151, 7, 29, // Opcode: LUi
/* 1276 */    MCD_OPC_FilterValue, 16, 248, 0, // Skip to: 1528
/* 1280 */    MCD_OPC_ExtractField, 3, 8,  // Inst{10-3} ...
/* 1283 */    MCD_OPC_FilterValue, 0, 112, 0, // Skip to: 1399
/* 1287 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1290 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1302
/* 1294 */    MCD_OPC_CheckPredicate, 9, 54, 46, // Skip to: 13128
/* 1298 */    MCD_OPC_Decode, 240, 7, 57, // Opcode: MFC0
/* 1302 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 1314
/* 1306 */    MCD_OPC_CheckPredicate, 9, 42, 46, // Skip to: 13128
/* 1310 */    MCD_OPC_Decode, 229, 8, 57, // Opcode: MTC0
/* 1314 */    MCD_OPC_FilterValue, 11, 20, 0, // Skip to: 1338
/* 1318 */    MCD_OPC_CheckPredicate, 4, 30, 46, // Skip to: 13128
/* 1322 */    MCD_OPC_CheckField, 11, 5, 12, 24, 46, // Skip to: 13128
/* 1328 */    MCD_OPC_CheckField, 0, 3, 0, 18, 46, // Skip to: 13128
/* 1334 */    MCD_OPC_Decode, 133, 4, 22, // Opcode: DI
/* 1338 */    MCD_OPC_FilterValue, 16, 10, 46, // Skip to: 13128
/* 1342 */    MCD_OPC_ExtractField, 0, 3,  // Inst{2-0} ...
/* 1345 */    MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 1363
/* 1349 */    MCD_OPC_CheckPredicate, 1, 255, 45, // Skip to: 13128
/* 1353 */    MCD_OPC_CheckField, 11, 10, 0, 249, 45, // Skip to: 13128
/* 1359 */    MCD_OPC_Decode, 220, 12, 0, // Opcode: TLBR
/* 1363 */    MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 1381
/* 1367 */    MCD_OPC_CheckPredicate, 1, 237, 45, // Skip to: 13128
/* 1371 */    MCD_OPC_CheckField, 11, 10, 0, 231, 45, // Skip to: 13128
/* 1377 */    MCD_OPC_Decode, 221, 12, 0, // Opcode: TLBWI
/* 1381 */    MCD_OPC_FilterValue, 6, 223, 45, // Skip to: 13128
/* 1385 */    MCD_OPC_CheckPredicate, 1, 219, 45, // Skip to: 13128
/* 1389 */    MCD_OPC_CheckField, 11, 10, 0, 213, 45, // Skip to: 13128
/* 1395 */    MCD_OPC_Decode, 222, 12, 0, // Opcode: TLBWR
/* 1399 */    MCD_OPC_FilterValue, 1, 22, 0, // Skip to: 1425
/* 1403 */    MCD_OPC_CheckPredicate, 1, 201, 45, // Skip to: 13128
/* 1407 */    MCD_OPC_CheckField, 11, 15, 128, 128, 1, 193, 45, // Skip to: 13128
/* 1415 */    MCD_OPC_CheckField, 0, 3, 0, 187, 45, // Skip to: 13128
/* 1421 */    MCD_OPC_Decode, 219, 12, 0, // Opcode: TLBP
/* 1425 */    MCD_OPC_FilterValue, 3, 43, 0, // Skip to: 1472
/* 1429 */    MCD_OPC_ExtractField, 0, 3,  // Inst{2-0} ...
/* 1432 */    MCD_OPC_FilterValue, 0, 16, 0, // Skip to: 1452
/* 1436 */    MCD_OPC_CheckPredicate, 15, 168, 45, // Skip to: 13128
/* 1440 */    MCD_OPC_CheckField, 11, 15, 128, 128, 1, 160, 45, // Skip to: 13128
/* 1448 */    MCD_OPC_Decode, 224, 4, 0, // Opcode: ERET
/* 1452 */    MCD_OPC_FilterValue, 7, 152, 45, // Skip to: 13128
/* 1456 */    MCD_OPC_CheckPredicate, 9, 148, 45, // Skip to: 13128
/* 1460 */    MCD_OPC_CheckField, 11, 15, 128, 128, 1, 140, 45, // Skip to: 13128
/* 1468 */    MCD_OPC_Decode, 128, 4, 0, // Opcode: DERET
/* 1472 */    MCD_OPC_FilterValue, 4, 132, 45, // Skip to: 13128
/* 1476 */    MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 1479 */    MCD_OPC_FilterValue, 0, 21, 0, // Skip to: 1504
/* 1483 */    MCD_OPC_CheckPredicate, 16, 121, 45, // Skip to: 13128
/* 1487 */    MCD_OPC_CheckField, 16, 10, 128, 4, 114, 45, // Skip to: 13128
/* 1494 */    MCD_OPC_CheckField, 0, 3, 0, 108, 45, // Skip to: 13128
/* 1500 */    MCD_OPC_Decode, 252, 12, 0, // Opcode: WAIT
/* 1504 */    MCD_OPC_FilterValue, 12, 100, 45, // Skip to: 13128
/* 1508 */    MCD_OPC_CheckPredicate, 4, 96, 45, // Skip to: 13128
/* 1512 */    MCD_OPC_CheckField, 21, 5, 11, 90, 45, // Skip to: 13128
/* 1518 */    MCD_OPC_CheckField, 0, 3, 0, 84, 45, // Skip to: 13128
/* 1524 */    MCD_OPC_Decode, 222, 4, 22, // Opcode: EI
/* 1528 */    MCD_OPC_FilterValue, 17, 253, 5, // Skip to: 3065
/* 1532 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1535 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 1553
/* 1539 */    MCD_OPC_CheckPredicate, 1, 65, 45, // Skip to: 13128
/* 1543 */    MCD_OPC_CheckField, 0, 11, 0, 59, 45, // Skip to: 13128
/* 1549 */    MCD_OPC_Decode, 241, 7, 58, // Opcode: MFC1
/* 1553 */    MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 1571
/* 1557 */    MCD_OPC_CheckPredicate, 17, 47, 45, // Skip to: 13128
/* 1561 */    MCD_OPC_CheckField, 0, 11, 0, 41, 45, // Skip to: 13128
/* 1567 */    MCD_OPC_Decode, 151, 4, 59, // Opcode: DMFC1
/* 1571 */    MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 1589
/* 1575 */    MCD_OPC_CheckPredicate, 1, 29, 45, // Skip to: 13128
/* 1579 */    MCD_OPC_CheckField, 0, 11, 0, 23, 45, // Skip to: 13128
/* 1585 */    MCD_OPC_Decode, 192, 2, 60, // Opcode: CFC1
/* 1589 */    MCD_OPC_FilterValue, 3, 14, 0, // Skip to: 1607
/* 1593 */    MCD_OPC_CheckPredicate, 18, 11, 45, // Skip to: 13128
/* 1597 */    MCD_OPC_CheckField, 0, 11, 0, 5, 45, // Skip to: 13128
/* 1603 */    MCD_OPC_Decode, 244, 7, 61, // Opcode: MFHC1_D32
/* 1607 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 1625
/* 1611 */    MCD_OPC_CheckPredicate, 1, 249, 44, // Skip to: 13128
/* 1615 */    MCD_OPC_CheckField, 0, 11, 0, 243, 44, // Skip to: 13128
/* 1621 */    MCD_OPC_Decode, 230, 8, 62, // Opcode: MTC1
/* 1625 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 1643
/* 1629 */    MCD_OPC_CheckPredicate, 17, 231, 44, // Skip to: 13128
/* 1633 */    MCD_OPC_CheckField, 0, 11, 0, 225, 44, // Skip to: 13128
/* 1639 */    MCD_OPC_Decode, 156, 4, 63, // Opcode: DMTC1
/* 1643 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 1661
/* 1647 */    MCD_OPC_CheckPredicate, 1, 213, 44, // Skip to: 13128
/* 1651 */    MCD_OPC_CheckField, 0, 11, 0, 207, 44, // Skip to: 13128
/* 1657 */    MCD_OPC_Decode, 164, 3, 64, // Opcode: CTC1
/* 1661 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 1679
/* 1665 */    MCD_OPC_CheckPredicate, 18, 195, 44, // Skip to: 13128
/* 1669 */    MCD_OPC_CheckField, 0, 11, 0, 189, 44, // Skip to: 13128
/* 1675 */    MCD_OPC_Decode, 233, 8, 65, // Opcode: MTHC1_D32
/* 1679 */    MCD_OPC_FilterValue, 8, 27, 0, // Skip to: 1710
/* 1683 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 1686 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1698
/* 1690 */    MCD_OPC_CheckPredicate, 12, 170, 44, // Skip to: 13128
/* 1694 */    MCD_OPC_Decode, 162, 1, 66, // Opcode: BC1F
/* 1698 */    MCD_OPC_FilterValue, 1, 162, 44, // Skip to: 13128
/* 1702 */    MCD_OPC_CheckPredicate, 12, 158, 44, // Skip to: 13128
/* 1706 */    MCD_OPC_Decode, 165, 1, 66, // Opcode: BC1T
/* 1710 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1722
/* 1714 */    MCD_OPC_CheckPredicate, 6, 146, 44, // Skip to: 13128
/* 1718 */    MCD_OPC_Decode, 148, 2, 67, // Opcode: BZ_V
/* 1722 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 1734
/* 1726 */    MCD_OPC_CheckPredicate, 6, 134, 44, // Skip to: 13128
/* 1730 */    MCD_OPC_Decode, 251, 1, 67, // Opcode: BNZ_V
/* 1734 */    MCD_OPC_FilterValue, 16, 80, 2, // Skip to: 2330
/* 1738 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1741 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1753
/* 1745 */    MCD_OPC_CheckPredicate, 1, 115, 44, // Skip to: 13128
/* 1749 */    MCD_OPC_Decode, 255, 4, 68, // Opcode: FADD_S
/* 1753 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 1765
/* 1757 */    MCD_OPC_CheckPredicate, 1, 103, 44, // Skip to: 13128
/* 1761 */    MCD_OPC_Decode, 129, 6, 68, // Opcode: FSUB_S
/* 1765 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 1777
/* 1769 */    MCD_OPC_CheckPredicate, 1, 91, 44, // Skip to: 13128
/* 1773 */    MCD_OPC_Decode, 220, 5, 68, // Opcode: FMUL_S
/* 1777 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 1789
/* 1781 */    MCD_OPC_CheckPredicate, 1, 79, 44, // Skip to: 13128
/* 1785 */    MCD_OPC_Decode, 163, 5, 68, // Opcode: FDIV_S
/* 1789 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 1807
/* 1793 */    MCD_OPC_CheckPredicate, 2, 67, 44, // Skip to: 13128
/* 1797 */    MCD_OPC_CheckField, 16, 5, 0, 61, 44, // Skip to: 13128
/* 1803 */    MCD_OPC_Decode, 250, 5, 69, // Opcode: FSQRT_S
/* 1807 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 1825
/* 1811 */    MCD_OPC_CheckPredicate, 1, 49, 44, // Skip to: 13128
/* 1815 */    MCD_OPC_CheckField, 16, 5, 0, 43, 44, // Skip to: 13128
/* 1821 */    MCD_OPC_Decode, 248, 4, 69, // Opcode: FABS_S
/* 1825 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 1843
/* 1829 */    MCD_OPC_CheckPredicate, 1, 31, 44, // Skip to: 13128
/* 1833 */    MCD_OPC_CheckField, 16, 5, 0, 25, 44, // Skip to: 13128
/* 1839 */    MCD_OPC_Decode, 212, 5, 69, // Opcode: FMOV_S
/* 1843 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 1861
/* 1847 */    MCD_OPC_CheckPredicate, 1, 13, 44, // Skip to: 13128
/* 1851 */    MCD_OPC_CheckField, 16, 5, 0, 7, 44, // Skip to: 13128
/* 1857 */    MCD_OPC_Decode, 226, 5, 69, // Opcode: FNEG_S
/* 1861 */    MCD_OPC_FilterValue, 12, 14, 0, // Skip to: 1879
/* 1865 */    MCD_OPC_CheckPredicate, 2, 251, 43, // Skip to: 13128
/* 1869 */    MCD_OPC_CheckField, 16, 5, 0, 245, 43, // Skip to: 13128
/* 1875 */    MCD_OPC_Decode, 168, 10, 69, // Opcode: ROUND_W_S
/* 1879 */    MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 1897
/* 1883 */    MCD_OPC_CheckPredicate, 2, 233, 43, // Skip to: 13128
/* 1887 */    MCD_OPC_CheckField, 16, 5, 0, 227, 43, // Skip to: 13128
/* 1893 */    MCD_OPC_Decode, 240, 12, 69, // Opcode: TRUNC_W_S
/* 1897 */    MCD_OPC_FilterValue, 14, 14, 0, // Skip to: 1915
/* 1901 */    MCD_OPC_CheckPredicate, 2, 215, 43, // Skip to: 13128
/* 1905 */    MCD_OPC_CheckField, 16, 5, 0, 209, 43, // Skip to: 13128
/* 1911 */    MCD_OPC_Decode, 182, 2, 69, // Opcode: CEIL_W_S
/* 1915 */    MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 1933
/* 1919 */    MCD_OPC_CheckPredicate, 2, 197, 43, // Skip to: 13128
/* 1923 */    MCD_OPC_CheckField, 16, 5, 0, 191, 43, // Skip to: 13128
/* 1929 */    MCD_OPC_Decode, 197, 5, 69, // Opcode: FLOOR_W_S
/* 1933 */    MCD_OPC_FilterValue, 17, 27, 0, // Skip to: 1964
/* 1937 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 1940 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1952
/* 1944 */    MCD_OPC_CheckPredicate, 5, 172, 43, // Skip to: 13128
/* 1948 */    MCD_OPC_Decode, 174, 8, 70, // Opcode: MOVF_S
/* 1952 */    MCD_OPC_FilterValue, 1, 164, 43, // Skip to: 13128
/* 1956 */    MCD_OPC_CheckPredicate, 5, 160, 43, // Skip to: 13128
/* 1960 */    MCD_OPC_Decode, 194, 8, 70, // Opcode: MOVT_S
/* 1964 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 1976
/* 1968 */    MCD_OPC_CheckPredicate, 5, 148, 43, // Skip to: 13128
/* 1972 */    MCD_OPC_Decode, 206, 8, 71, // Opcode: MOVZ_I_S
/* 1976 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 1988
/* 1980 */    MCD_OPC_CheckPredicate, 5, 136, 43, // Skip to: 13128
/* 1984 */    MCD_OPC_Decode, 186, 8, 71, // Opcode: MOVN_I_S
/* 1988 */    MCD_OPC_FilterValue, 33, 14, 0, // Skip to: 2006
/* 1992 */    MCD_OPC_CheckPredicate, 19, 124, 43, // Skip to: 13128
/* 1996 */    MCD_OPC_CheckField, 16, 5, 0, 118, 43, // Skip to: 13128
/* 2002 */    MCD_OPC_Decode, 167, 3, 72, // Opcode: CVT_D32_S
/* 2006 */    MCD_OPC_FilterValue, 36, 14, 0, // Skip to: 2024
/* 2010 */    MCD_OPC_CheckPredicate, 1, 106, 43, // Skip to: 13128
/* 2014 */    MCD_OPC_CheckField, 16, 5, 0, 100, 43, // Skip to: 13128
/* 2020 */    MCD_OPC_Decode, 187, 3, 69, // Opcode: CVT_W_S
/* 2024 */    MCD_OPC_FilterValue, 37, 14, 0, // Skip to: 2042
/* 2028 */    MCD_OPC_CheckPredicate, 20, 88, 43, // Skip to: 13128
/* 2032 */    MCD_OPC_CheckField, 16, 5, 0, 82, 43, // Skip to: 13128
/* 2038 */    MCD_OPC_Decode, 176, 3, 73, // Opcode: CVT_L_S
/* 2042 */    MCD_OPC_FilterValue, 48, 14, 0, // Skip to: 2060
/* 2046 */    MCD_OPC_CheckPredicate, 12, 70, 43, // Skip to: 13128
/* 2050 */    MCD_OPC_CheckField, 6, 5, 0, 64, 43, // Skip to: 13128
/* 2056 */    MCD_OPC_Decode, 194, 3, 74, // Opcode: C_F_S
/* 2060 */    MCD_OPC_FilterValue, 49, 14, 0, // Skip to: 2078
/* 2064 */    MCD_OPC_CheckPredicate, 12, 52, 43, // Skip to: 13128
/* 2068 */    MCD_OPC_CheckField, 6, 5, 0, 46, 43, // Skip to: 13128
/* 2074 */    MCD_OPC_Decode, 236, 3, 74, // Opcode: C_UN_S
/* 2078 */    MCD_OPC_FilterValue, 50, 14, 0, // Skip to: 2096
/* 2082 */    MCD_OPC_CheckPredicate, 12, 34, 43, // Skip to: 13128
/* 2086 */    MCD_OPC_CheckField, 6, 5, 0, 28, 43, // Skip to: 13128
/* 2092 */    MCD_OPC_Decode, 191, 3, 74, // Opcode: C_EQ_S
/* 2096 */    MCD_OPC_FilterValue, 51, 14, 0, // Skip to: 2114
/* 2100 */    MCD_OPC_CheckPredicate, 12, 16, 43, // Skip to: 13128
/* 2104 */    MCD_OPC_CheckField, 6, 5, 0, 10, 43, // Skip to: 13128
/* 2110 */    MCD_OPC_Decode, 227, 3, 74, // Opcode: C_UEQ_S
/* 2114 */    MCD_OPC_FilterValue, 52, 14, 0, // Skip to: 2132
/* 2118 */    MCD_OPC_CheckPredicate, 12, 254, 42, // Skip to: 13128
/* 2122 */    MCD_OPC_CheckField, 6, 5, 0, 248, 42, // Skip to: 13128
/* 2128 */    MCD_OPC_Decode, 218, 3, 74, // Opcode: C_OLT_S
/* 2132 */    MCD_OPC_FilterValue, 53, 14, 0, // Skip to: 2150
/* 2136 */    MCD_OPC_CheckPredicate, 12, 236, 42, // Skip to: 13128
/* 2140 */    MCD_OPC_CheckField, 6, 5, 0, 230, 42, // Skip to: 13128
/* 2146 */    MCD_OPC_Decode, 233, 3, 74, // Opcode: C_ULT_S
/* 2150 */    MCD_OPC_FilterValue, 54, 14, 0, // Skip to: 2168
/* 2154 */    MCD_OPC_CheckPredicate, 12, 218, 42, // Skip to: 13128
/* 2158 */    MCD_OPC_CheckField, 6, 5, 0, 212, 42, // Skip to: 13128
/* 2164 */    MCD_OPC_Decode, 215, 3, 74, // Opcode: C_OLE_S
/* 2168 */    MCD_OPC_FilterValue, 55, 14, 0, // Skip to: 2186
/* 2172 */    MCD_OPC_CheckPredicate, 12, 200, 42, // Skip to: 13128
/* 2176 */    MCD_OPC_CheckField, 6, 5, 0, 194, 42, // Skip to: 13128
/* 2182 */    MCD_OPC_Decode, 230, 3, 74, // Opcode: C_ULE_S
/* 2186 */    MCD_OPC_FilterValue, 56, 14, 0, // Skip to: 2204
/* 2190 */    MCD_OPC_CheckPredicate, 12, 182, 42, // Skip to: 13128
/* 2194 */    MCD_OPC_CheckField, 6, 5, 0, 176, 42, // Skip to: 13128
/* 2200 */    MCD_OPC_Decode, 224, 3, 74, // Opcode: C_SF_S
/* 2204 */    MCD_OPC_FilterValue, 57, 14, 0, // Skip to: 2222
/* 2208 */    MCD_OPC_CheckPredicate, 12, 164, 42, // Skip to: 13128
/* 2212 */    MCD_OPC_CheckField, 6, 5, 0, 158, 42, // Skip to: 13128
/* 2218 */    MCD_OPC_Decode, 206, 3, 74, // Opcode: C_NGLE_S
/* 2222 */    MCD_OPC_FilterValue, 58, 14, 0, // Skip to: 2240
/* 2226 */    MCD_OPC_CheckPredicate, 12, 146, 42, // Skip to: 13128
/* 2230 */    MCD_OPC_CheckField, 6, 5, 0, 140, 42, // Skip to: 13128
/* 2236 */    MCD_OPC_Decode, 221, 3, 74, // Opcode: C_SEQ_S
/* 2240 */    MCD_OPC_FilterValue, 59, 14, 0, // Skip to: 2258
/* 2244 */    MCD_OPC_CheckPredicate, 12, 128, 42, // Skip to: 13128
/* 2248 */    MCD_OPC_CheckField, 6, 5, 0, 122, 42, // Skip to: 13128
/* 2254 */    MCD_OPC_Decode, 209, 3, 74, // Opcode: C_NGL_S
/* 2258 */    MCD_OPC_FilterValue, 60, 14, 0, // Skip to: 2276
/* 2262 */    MCD_OPC_CheckPredicate, 12, 110, 42, // Skip to: 13128
/* 2266 */    MCD_OPC_CheckField, 6, 5, 0, 104, 42, // Skip to: 13128
/* 2272 */    MCD_OPC_Decode, 200, 3, 74, // Opcode: C_LT_S
/* 2276 */    MCD_OPC_FilterValue, 61, 14, 0, // Skip to: 2294
/* 2280 */    MCD_OPC_CheckPredicate, 12, 92, 42, // Skip to: 13128
/* 2284 */    MCD_OPC_CheckField, 6, 5, 0, 86, 42, // Skip to: 13128
/* 2290 */    MCD_OPC_Decode, 203, 3, 74, // Opcode: C_NGE_S
/* 2294 */    MCD_OPC_FilterValue, 62, 14, 0, // Skip to: 2312
/* 2298 */    MCD_OPC_CheckPredicate, 12, 74, 42, // Skip to: 13128
/* 2302 */    MCD_OPC_CheckField, 6, 5, 0, 68, 42, // Skip to: 13128
/* 2308 */    MCD_OPC_Decode, 197, 3, 74, // Opcode: C_LE_S
/* 2312 */    MCD_OPC_FilterValue, 63, 60, 42, // Skip to: 13128
/* 2316 */    MCD_OPC_CheckPredicate, 12, 56, 42, // Skip to: 13128
/* 2320 */    MCD_OPC_CheckField, 6, 5, 0, 50, 42, // Skip to: 13128
/* 2326 */    MCD_OPC_Decode, 212, 3, 74, // Opcode: C_NGT_S
/* 2330 */    MCD_OPC_FilterValue, 17, 80, 2, // Skip to: 2926
/* 2334 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 2337 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 2349
/* 2341 */    MCD_OPC_CheckPredicate, 19, 31, 42, // Skip to: 13128
/* 2345 */    MCD_OPC_Decode, 252, 4, 75, // Opcode: FADD_D32
/* 2349 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 2361
/* 2353 */    MCD_OPC_CheckPredicate, 19, 19, 42, // Skip to: 13128
/* 2357 */    MCD_OPC_Decode, 254, 5, 75, // Opcode: FSUB_D32
/* 2361 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 2373
/* 2365 */    MCD_OPC_CheckPredicate, 19, 7, 42, // Skip to: 13128
/* 2369 */    MCD_OPC_Decode, 217, 5, 75, // Opcode: FMUL_D32
/* 2373 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 2385
/* 2377 */    MCD_OPC_CheckPredicate, 19, 251, 41, // Skip to: 13128
/* 2381 */    MCD_OPC_Decode, 160, 5, 75, // Opcode: FDIV_D32
/* 2385 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 2403
/* 2389 */    MCD_OPC_CheckPredicate, 21, 239, 41, // Skip to: 13128
/* 2393 */    MCD_OPC_CheckField, 16, 5, 0, 233, 41, // Skip to: 13128
/* 2399 */    MCD_OPC_Decode, 247, 5, 76, // Opcode: FSQRT_D32
/* 2403 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 2421
/* 2407 */    MCD_OPC_CheckPredicate, 19, 221, 41, // Skip to: 13128
/* 2411 */    MCD_OPC_CheckField, 16, 5, 0, 215, 41, // Skip to: 13128
/* 2417 */    MCD_OPC_Decode, 245, 4, 76, // Opcode: FABS_D32
/* 2421 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 2439
/* 2425 */    MCD_OPC_CheckPredicate, 19, 203, 41, // Skip to: 13128
/* 2429 */    MCD_OPC_CheckField, 16, 5, 0, 197, 41, // Skip to: 13128
/* 2435 */    MCD_OPC_Decode, 209, 5, 76, // Opcode: FMOV_D32
/* 2439 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 2457
/* 2443 */    MCD_OPC_CheckPredicate, 19, 185, 41, // Skip to: 13128
/* 2447 */    MCD_OPC_CheckField, 16, 5, 0, 179, 41, // Skip to: 13128
/* 2453 */    MCD_OPC_Decode, 223, 5, 76, // Opcode: FNEG_D32
/* 2457 */    MCD_OPC_FilterValue, 12, 14, 0, // Skip to: 2475
/* 2461 */    MCD_OPC_CheckPredicate, 21, 167, 41, // Skip to: 13128
/* 2465 */    MCD_OPC_CheckField, 16, 5, 0, 161, 41, // Skip to: 13128
/* 2471 */    MCD_OPC_Decode, 165, 10, 77, // Opcode: ROUND_W_D32
/* 2475 */    MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 2493
/* 2479 */    MCD_OPC_CheckPredicate, 21, 149, 41, // Skip to: 13128
/* 2483 */    MCD_OPC_CheckField, 16, 5, 0, 143, 41, // Skip to: 13128
/* 2489 */    MCD_OPC_Decode, 237, 12, 77, // Opcode: TRUNC_W_D32
/* 2493 */    MCD_OPC_FilterValue, 14, 14, 0, // Skip to: 2511
/* 2497 */    MCD_OPC_CheckPredicate, 21, 131, 41, // Skip to: 13128
/* 2501 */    MCD_OPC_CheckField, 16, 5, 0, 125, 41, // Skip to: 13128
/* 2507 */    MCD_OPC_Decode, 179, 2, 77, // Opcode: CEIL_W_D32
/* 2511 */    MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 2529
/* 2515 */    MCD_OPC_CheckPredicate, 21, 113, 41, // Skip to: 13128
/* 2519 */    MCD_OPC_CheckField, 16, 5, 0, 107, 41, // Skip to: 13128
/* 2525 */    MCD_OPC_Decode, 194, 5, 77, // Opcode: FLOOR_W_D32
/* 2529 */    MCD_OPC_FilterValue, 17, 27, 0, // Skip to: 2560
/* 2533 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 2536 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 2548
/* 2540 */    MCD_OPC_CheckPredicate, 22, 88, 41, // Skip to: 13128
/* 2544 */    MCD_OPC_Decode, 168, 8, 78, // Opcode: MOVF_D32
/* 2548 */    MCD_OPC_FilterValue, 1, 80, 41, // Skip to: 13128
/* 2552 */    MCD_OPC_CheckPredicate, 22, 76, 41, // Skip to: 13128
/* 2556 */    MCD_OPC_Decode, 188, 8, 78, // Opcode: MOVT_D32
/* 2560 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 2572
/* 2564 */    MCD_OPC_CheckPredicate, 22, 64, 41, // Skip to: 13128
/* 2568 */    MCD_OPC_Decode, 200, 8, 79, // Opcode: MOVZ_I_D32
/* 2572 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 2584
/* 2576 */    MCD_OPC_CheckPredicate, 22, 52, 41, // Skip to: 13128
/* 2580 */    MCD_OPC_Decode, 180, 8, 79, // Opcode: MOVN_I_D32
/* 2584 */    MCD_OPC_FilterValue, 32, 14, 0, // Skip to: 2602
/* 2588 */    MCD_OPC_CheckPredicate, 19, 40, 41, // Skip to: 13128
/* 2592 */    MCD_OPC_CheckField, 16, 5, 0, 34, 41, // Skip to: 13128
/* 2598 */    MCD_OPC_Decode, 178, 3, 77, // Opcode: CVT_S_D32
/* 2602 */    MCD_OPC_FilterValue, 36, 14, 0, // Skip to: 2620
/* 2606 */    MCD_OPC_CheckPredicate, 19, 22, 41, // Skip to: 13128
/* 2610 */    MCD_OPC_CheckField, 16, 5, 0, 16, 41, // Skip to: 13128
/* 2616 */    MCD_OPC_Decode, 184, 3, 77, // Opcode: CVT_W_D32
/* 2620 */    MCD_OPC_FilterValue, 37, 14, 0, // Skip to: 2638
/* 2624 */    MCD_OPC_CheckPredicate, 20, 4, 41, // Skip to: 13128
/* 2628 */    MCD_OPC_CheckField, 16, 5, 0, 254, 40, // Skip to: 13128
/* 2634 */    MCD_OPC_Decode, 174, 3, 80, // Opcode: CVT_L_D64
/* 2638 */    MCD_OPC_FilterValue, 48, 14, 0, // Skip to: 2656
/* 2642 */    MCD_OPC_CheckPredicate, 23, 242, 40, // Skip to: 13128
/* 2646 */    MCD_OPC_CheckField, 6, 5, 0, 236, 40, // Skip to: 13128
/* 2652 */    MCD_OPC_Decode, 192, 3, 81, // Opcode: C_F_D32
/* 2656 */    MCD_OPC_FilterValue, 49, 14, 0, // Skip to: 2674
/* 2660 */    MCD_OPC_CheckPredicate, 23, 224, 40, // Skip to: 13128
/* 2664 */    MCD_OPC_CheckField, 6, 5, 0, 218, 40, // Skip to: 13128
/* 2670 */    MCD_OPC_Decode, 234, 3, 81, // Opcode: C_UN_D32
/* 2674 */    MCD_OPC_FilterValue, 50, 14, 0, // Skip to: 2692
/* 2678 */    MCD_OPC_CheckPredicate, 23, 206, 40, // Skip to: 13128
/* 2682 */    MCD_OPC_CheckField, 6, 5, 0, 200, 40, // Skip to: 13128
/* 2688 */    MCD_OPC_Decode, 189, 3, 81, // Opcode: C_EQ_D32
/* 2692 */    MCD_OPC_FilterValue, 51, 14, 0, // Skip to: 2710
/* 2696 */    MCD_OPC_CheckPredicate, 23, 188, 40, // Skip to: 13128
/* 2700 */    MCD_OPC_CheckField, 6, 5, 0, 182, 40, // Skip to: 13128
/* 2706 */    MCD_OPC_Decode, 225, 3, 81, // Opcode: C_UEQ_D32
/* 2710 */    MCD_OPC_FilterValue, 52, 14, 0, // Skip to: 2728
/* 2714 */    MCD_OPC_CheckPredicate, 23, 170, 40, // Skip to: 13128
/* 2718 */    MCD_OPC_CheckField, 6, 5, 0, 164, 40, // Skip to: 13128
/* 2724 */    MCD_OPC_Decode, 216, 3, 81, // Opcode: C_OLT_D32
/* 2728 */    MCD_OPC_FilterValue, 53, 14, 0, // Skip to: 2746
/* 2732 */    MCD_OPC_CheckPredicate, 23, 152, 40, // Skip to: 13128
/* 2736 */    MCD_OPC_CheckField, 6, 5, 0, 146, 40, // Skip to: 13128
/* 2742 */    MCD_OPC_Decode, 231, 3, 81, // Opcode: C_ULT_D32
/* 2746 */    MCD_OPC_FilterValue, 54, 14, 0, // Skip to: 2764
/* 2750 */    MCD_OPC_CheckPredicate, 23, 134, 40, // Skip to: 13128
/* 2754 */    MCD_OPC_CheckField, 6, 5, 0, 128, 40, // Skip to: 13128
/* 2760 */    MCD_OPC_Decode, 213, 3, 81, // Opcode: C_OLE_D32
/* 2764 */    MCD_OPC_FilterValue, 55, 14, 0, // Skip to: 2782
/* 2768 */    MCD_OPC_CheckPredicate, 23, 116, 40, // Skip to: 13128
/* 2772 */    MCD_OPC_CheckField, 6, 5, 0, 110, 40, // Skip to: 13128
/* 2778 */    MCD_OPC_Decode, 228, 3, 81, // Opcode: C_ULE_D32
/* 2782 */    MCD_OPC_FilterValue, 56, 14, 0, // Skip to: 2800
/* 2786 */    MCD_OPC_CheckPredicate, 23, 98, 40, // Skip to: 13128
/* 2790 */    MCD_OPC_CheckField, 6, 5, 0, 92, 40, // Skip to: 13128
/* 2796 */    MCD_OPC_Decode, 222, 3, 81, // Opcode: C_SF_D32
/* 2800 */    MCD_OPC_FilterValue, 57, 14, 0, // Skip to: 2818
/* 2804 */    MCD_OPC_CheckPredicate, 23, 80, 40, // Skip to: 13128
/* 2808 */    MCD_OPC_CheckField, 6, 5, 0, 74, 40, // Skip to: 13128
/* 2814 */    MCD_OPC_Decode, 204, 3, 81, // Opcode: C_NGLE_D32
/* 2818 */    MCD_OPC_FilterValue, 58, 14, 0, // Skip to: 2836
/* 2822 */    MCD_OPC_CheckPredicate, 23, 62, 40, // Skip to: 13128
/* 2826 */    MCD_OPC_CheckField, 6, 5, 0, 56, 40, // Skip to: 13128
/* 2832 */    MCD_OPC_Decode, 219, 3, 81, // Opcode: C_SEQ_D32
/* 2836 */    MCD_OPC_FilterValue, 59, 14, 0, // Skip to: 2854
/* 2840 */    MCD_OPC_CheckPredicate, 23, 44, 40, // Skip to: 13128
/* 2844 */    MCD_OPC_CheckField, 6, 5, 0, 38, 40, // Skip to: 13128
/* 2850 */    MCD_OPC_Decode, 207, 3, 81, // Opcode: C_NGL_D32
/* 2854 */    MCD_OPC_FilterValue, 60, 14, 0, // Skip to: 2872
/* 2858 */    MCD_OPC_CheckPredicate, 23, 26, 40, // Skip to: 13128
/* 2862 */    MCD_OPC_CheckField, 6, 5, 0, 20, 40, // Skip to: 13128
/* 2868 */    MCD_OPC_Decode, 198, 3, 81, // Opcode: C_LT_D32
/* 2872 */    MCD_OPC_FilterValue, 61, 14, 0, // Skip to: 2890
/* 2876 */    MCD_OPC_CheckPredicate, 23, 8, 40, // Skip to: 13128
/* 2880 */    MCD_OPC_CheckField, 6, 5, 0, 2, 40, // Skip to: 13128
/* 2886 */    MCD_OPC_Decode, 201, 3, 81, // Opcode: C_NGE_D32
/* 2890 */    MCD_OPC_FilterValue, 62, 14, 0, // Skip to: 2908
/* 2894 */    MCD_OPC_CheckPredicate, 23, 246, 39, // Skip to: 13128
/* 2898 */    MCD_OPC_CheckField, 6, 5, 0, 240, 39, // Skip to: 13128
/* 2904 */    MCD_OPC_Decode, 195, 3, 81, // Opcode: C_LE_D32
/* 2908 */    MCD_OPC_FilterValue, 63, 232, 39, // Skip to: 13128
/* 2912 */    MCD_OPC_CheckPredicate, 23, 228, 39, // Skip to: 13128
/* 2916 */    MCD_OPC_CheckField, 6, 5, 0, 222, 39, // Skip to: 13128
/* 2922 */    MCD_OPC_Decode, 210, 3, 81, // Opcode: C_NGT_D32
/* 2926 */    MCD_OPC_FilterValue, 20, 39, 0, // Skip to: 2969
/* 2930 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 2933 */    MCD_OPC_FilterValue, 32, 14, 0, // Skip to: 2951
/* 2937 */    MCD_OPC_CheckPredicate, 1, 203, 39, // Skip to: 13128
/* 2941 */    MCD_OPC_CheckField, 16, 5, 0, 197, 39, // Skip to: 13128
/* 2947 */    MCD_OPC_Decode, 182, 3, 69, // Opcode: CVT_S_W
/* 2951 */    MCD_OPC_FilterValue, 33, 189, 39, // Skip to: 13128
/* 2955 */    MCD_OPC_CheckPredicate, 19, 185, 39, // Skip to: 13128
/* 2959 */    MCD_OPC_CheckField, 16, 5, 0, 179, 39, // Skip to: 13128
/* 2965 */    MCD_OPC_Decode, 168, 3, 72, // Opcode: CVT_D32_W
/* 2969 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 2981
/* 2973 */    MCD_OPC_CheckPredicate, 6, 167, 39, // Skip to: 13128
/* 2977 */    MCD_OPC_Decode, 145, 2, 67, // Opcode: BZ_B
/* 2981 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 2993
/* 2985 */    MCD_OPC_CheckPredicate, 6, 155, 39, // Skip to: 13128
/* 2989 */    MCD_OPC_Decode, 147, 2, 82, // Opcode: BZ_H
/* 2993 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 3005
/* 2997 */    MCD_OPC_CheckPredicate, 6, 143, 39, // Skip to: 13128
/* 3001 */    MCD_OPC_Decode, 149, 2, 83, // Opcode: BZ_W
/* 3005 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 3017
/* 3009 */    MCD_OPC_CheckPredicate, 6, 131, 39, // Skip to: 13128
/* 3013 */    MCD_OPC_Decode, 146, 2, 84, // Opcode: BZ_D
/* 3017 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 3029
/* 3021 */    MCD_OPC_CheckPredicate, 6, 119, 39, // Skip to: 13128
/* 3025 */    MCD_OPC_Decode, 248, 1, 67, // Opcode: BNZ_B
/* 3029 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 3041
/* 3033 */    MCD_OPC_CheckPredicate, 6, 107, 39, // Skip to: 13128
/* 3037 */    MCD_OPC_Decode, 250, 1, 82, // Opcode: BNZ_H
/* 3041 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 3053
/* 3045 */    MCD_OPC_CheckPredicate, 6, 95, 39, // Skip to: 13128
/* 3049 */    MCD_OPC_Decode, 252, 1, 83, // Opcode: BNZ_W
/* 3053 */    MCD_OPC_FilterValue, 31, 87, 39, // Skip to: 13128
/* 3057 */    MCD_OPC_CheckPredicate, 6, 83, 39, // Skip to: 13128
/* 3061 */    MCD_OPC_Decode, 249, 1, 84, // Opcode: BNZ_D
/* 3065 */    MCD_OPC_FilterValue, 18, 39, 0, // Skip to: 3108
/* 3069 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 3072 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 3090
/* 3076 */    MCD_OPC_CheckPredicate, 1, 64, 39, // Skip to: 13128
/* 3080 */    MCD_OPC_CheckField, 3, 8, 0, 58, 39, // Skip to: 13128
/* 3086 */    MCD_OPC_Decode, 243, 7, 57, // Opcode: MFC2
/* 3090 */    MCD_OPC_FilterValue, 4, 50, 39, // Skip to: 13128
/* 3094 */    MCD_OPC_CheckPredicate, 1, 46, 39, // Skip to: 13128
/* 3098 */    MCD_OPC_CheckField, 3, 8, 0, 40, 39, // Skip to: 13128
/* 3104 */    MCD_OPC_Decode, 232, 8, 57, // Opcode: MTC2
/* 3108 */    MCD_OPC_FilterValue, 19, 207, 0, // Skip to: 3319
/* 3112 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 3115 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 3133
/* 3119 */    MCD_OPC_CheckPredicate, 24, 21, 39, // Skip to: 13128
/* 3123 */    MCD_OPC_CheckField, 11, 5, 0, 15, 39, // Skip to: 13128
/* 3129 */    MCD_OPC_Decode, 171, 7, 85, // Opcode: LWXC1
/* 3133 */    MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 3151
/* 3137 */    MCD_OPC_CheckPredicate, 25, 3, 39, // Skip to: 13128
/* 3141 */    MCD_OPC_CheckField, 11, 5, 0, 253, 38, // Skip to: 13128
/* 3147 */    MCD_OPC_Decode, 246, 6, 86, // Opcode: LDXC1
/* 3151 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 3169
/* 3155 */    MCD_OPC_CheckPredicate, 26, 241, 38, // Skip to: 13128
/* 3159 */    MCD_OPC_CheckField, 11, 5, 0, 235, 38, // Skip to: 13128
/* 3165 */    MCD_OPC_Decode, 148, 7, 86, // Opcode: LUXC1
/* 3169 */    MCD_OPC_FilterValue, 8, 14, 0, // Skip to: 3187
/* 3173 */    MCD_OPC_CheckPredicate, 24, 223, 38, // Skip to: 13128
/* 3177 */    MCD_OPC_CheckField, 6, 5, 0, 217, 38, // Skip to: 13128
/* 3183 */    MCD_OPC_Decode, 152, 12, 87, // Opcode: SWXC1
/* 3187 */    MCD_OPC_FilterValue, 9, 14, 0, // Skip to: 3205
/* 3191 */    MCD_OPC_CheckPredicate, 25, 205, 38, // Skip to: 13128
/* 3195 */    MCD_OPC_CheckField, 6, 5, 0, 199, 38, // Skip to: 13128
/* 3201 */    MCD_OPC_Decode, 203, 10, 88, // Opcode: SDXC1
/* 3205 */    MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 3223
/* 3209 */    MCD_OPC_CheckPredicate, 26, 187, 38, // Skip to: 13128
/* 3213 */    MCD_OPC_CheckField, 6, 5, 0, 181, 38, // Skip to: 13128
/* 3219 */    MCD_OPC_Decode, 136, 12, 88, // Opcode: SUXC1
/* 3223 */    MCD_OPC_FilterValue, 32, 8, 0, // Skip to: 3235
/* 3227 */    MCD_OPC_CheckPredicate, 27, 169, 38, // Skip to: 13128
/* 3231 */    MCD_OPC_Decode, 210, 7, 89, // Opcode: MADD_S
/* 3235 */    MCD_OPC_FilterValue, 33, 8, 0, // Skip to: 3247
/* 3239 */    MCD_OPC_CheckPredicate, 28, 157, 38, // Skip to: 13128
/* 3243 */    MCD_OPC_Decode, 203, 7, 90, // Opcode: MADD_D32
/* 3247 */    MCD_OPC_FilterValue, 40, 8, 0, // Skip to: 3259
/* 3251 */    MCD_OPC_CheckPredicate, 27, 145, 38, // Skip to: 13128
/* 3255 */    MCD_OPC_Decode, 227, 8, 89, // Opcode: MSUB_S
/* 3259 */    MCD_OPC_FilterValue, 41, 8, 0, // Skip to: 3271
/* 3263 */    MCD_OPC_CheckPredicate, 28, 133, 38, // Skip to: 13128
/* 3267 */    MCD_OPC_Decode, 220, 8, 90, // Opcode: MSUB_D32
/* 3271 */    MCD_OPC_FilterValue, 48, 8, 0, // Skip to: 3283
/* 3275 */    MCD_OPC_CheckPredicate, 27, 121, 38, // Skip to: 13128
/* 3279 */    MCD_OPC_Decode, 174, 9, 89, // Opcode: NMADD_S
/* 3283 */    MCD_OPC_FilterValue, 49, 8, 0, // Skip to: 3295
/* 3287 */    MCD_OPC_CheckPredicate, 28, 109, 38, // Skip to: 13128
/* 3291 */    MCD_OPC_Decode, 171, 9, 90, // Opcode: NMADD_D32
/* 3295 */    MCD_OPC_FilterValue, 56, 8, 0, // Skip to: 3307
/* 3299 */    MCD_OPC_CheckPredicate, 27, 97, 38, // Skip to: 13128
/* 3303 */    MCD_OPC_Decode, 179, 9, 89, // Opcode: NMSUB_S
/* 3307 */    MCD_OPC_FilterValue, 57, 89, 38, // Skip to: 13128
/* 3311 */    MCD_OPC_CheckPredicate, 28, 85, 38, // Skip to: 13128
/* 3315 */    MCD_OPC_Decode, 176, 9, 90, // Opcode: NMSUB_D32
/* 3319 */    MCD_OPC_FilterValue, 28, 229, 0, // Skip to: 3552
/* 3323 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 3326 */    MCD_OPC_FilterValue, 0, 36, 0, // Skip to: 3366
/* 3330 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 3333 */    MCD_OPC_FilterValue, 0, 63, 38, // Skip to: 13128
/* 3337 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3340 */    MCD_OPC_FilterValue, 0, 56, 38, // Skip to: 13128
/* 3344 */    MCD_OPC_CheckPredicate, 7, 10, 0, // Skip to: 3358
/* 3348 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3358
/* 3354 */    MCD_OPC_Decode, 191, 7, 23, // Opcode: MADD
/* 3358 */    MCD_OPC_CheckPredicate, 11, 38, 38, // Skip to: 13128
/* 3362 */    MCD_OPC_Decode, 206, 7, 91, // Opcode: MADD_DSP
/* 3366 */    MCD_OPC_FilterValue, 1, 36, 0, // Skip to: 3406
/* 3370 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 3373 */    MCD_OPC_FilterValue, 0, 23, 38, // Skip to: 13128
/* 3377 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3380 */    MCD_OPC_FilterValue, 0, 16, 38, // Skip to: 13128
/* 3384 */    MCD_OPC_CheckPredicate, 7, 10, 0, // Skip to: 3398
/* 3388 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3398
/* 3394 */    MCD_OPC_Decode, 196, 7, 23, // Opcode: MADDU
/* 3398 */    MCD_OPC_CheckPredicate, 11, 254, 37, // Skip to: 13128
/* 3402 */    MCD_OPC_Decode, 197, 7, 91, // Opcode: MADDU_DSP
/* 3406 */    MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 3424
/* 3410 */    MCD_OPC_CheckPredicate, 7, 242, 37, // Skip to: 13128
/* 3414 */    MCD_OPC_CheckField, 6, 5, 0, 236, 37, // Skip to: 13128
/* 3420 */    MCD_OPC_Decode, 253, 8, 16, // Opcode: MUL
/* 3424 */    MCD_OPC_FilterValue, 4, 36, 0, // Skip to: 3464
/* 3428 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 3431 */    MCD_OPC_FilterValue, 0, 221, 37, // Skip to: 13128
/* 3435 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3438 */    MCD_OPC_FilterValue, 0, 214, 37, // Skip to: 13128
/* 3442 */    MCD_OPC_CheckPredicate, 7, 10, 0, // Skip to: 3456
/* 3446 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3456
/* 3452 */    MCD_OPC_Decode, 208, 8, 23, // Opcode: MSUB
/* 3456 */    MCD_OPC_CheckPredicate, 11, 196, 37, // Skip to: 13128
/* 3460 */    MCD_OPC_Decode, 223, 8, 91, // Opcode: MSUB_DSP
/* 3464 */    MCD_OPC_FilterValue, 5, 36, 0, // Skip to: 3504
/* 3468 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 3471 */    MCD_OPC_FilterValue, 0, 181, 37, // Skip to: 13128
/* 3475 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3478 */    MCD_OPC_FilterValue, 0, 174, 37, // Skip to: 13128
/* 3482 */    MCD_OPC_CheckPredicate, 7, 10, 0, // Skip to: 3496
/* 3486 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3496
/* 3492 */    MCD_OPC_Decode, 213, 8, 23, // Opcode: MSUBU
/* 3496 */    MCD_OPC_CheckPredicate, 11, 156, 37, // Skip to: 13128
/* 3500 */    MCD_OPC_Decode, 214, 8, 91, // Opcode: MSUBU_DSP
/* 3504 */    MCD_OPC_FilterValue, 32, 14, 0, // Skip to: 3522
/* 3508 */    MCD_OPC_CheckPredicate, 7, 144, 37, // Skip to: 13128
/* 3512 */    MCD_OPC_CheckField, 6, 5, 0, 138, 37, // Skip to: 13128
/* 3518 */    MCD_OPC_Decode, 234, 2, 92, // Opcode: CLZ
/* 3522 */    MCD_OPC_FilterValue, 33, 14, 0, // Skip to: 3540
/* 3526 */    MCD_OPC_CheckPredicate, 7, 126, 37, // Skip to: 13128
/* 3530 */    MCD_OPC_CheckField, 6, 5, 0, 120, 37, // Skip to: 13128
/* 3536 */    MCD_OPC_Decode, 215, 2, 92, // Opcode: CLO
/* 3540 */    MCD_OPC_FilterValue, 63, 112, 37, // Skip to: 13128
/* 3544 */    MCD_OPC_CheckPredicate, 7, 108, 37, // Skip to: 13128
/* 3548 */    MCD_OPC_Decode, 191, 10, 41, // Opcode: SDBBP
/* 3552 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 3564
/* 3556 */    MCD_OPC_CheckPredicate, 7, 96, 37, // Skip to: 13128
/* 3560 */    MCD_OPC_Decode, 209, 6, 53, // Opcode: JALX
/* 3564 */    MCD_OPC_FilterValue, 30, 179, 26, // Skip to: 10403
/* 3568 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 3571 */    MCD_OPC_FilterValue, 0, 50, 0, // Skip to: 3625
/* 3575 */    MCD_OPC_ExtractField, 24, 2,  // Inst{25-24} ...
/* 3578 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 3589
/* 3582 */    MCD_OPC_CheckPredicate, 6, 70, 37, // Skip to: 13128
/* 3586 */    MCD_OPC_Decode, 77, 93, // Opcode: ANDI_B
/* 3589 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3601
/* 3593 */    MCD_OPC_CheckPredicate, 6, 59, 37, // Skip to: 13128
/* 3597 */    MCD_OPC_Decode, 194, 9, 93, // Opcode: ORI_B
/* 3601 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 3613
/* 3605 */    MCD_OPC_CheckPredicate, 6, 47, 37, // Skip to: 13128
/* 3609 */    MCD_OPC_Decode, 184, 9, 93, // Opcode: NORI_B
/* 3613 */    MCD_OPC_FilterValue, 3, 39, 37, // Skip to: 13128
/* 3617 */    MCD_OPC_CheckPredicate, 6, 35, 37, // Skip to: 13128
/* 3621 */    MCD_OPC_Decode, 131, 13, 93, // Opcode: XORI_B
/* 3625 */    MCD_OPC_FilterValue, 1, 39, 0, // Skip to: 3668
/* 3629 */    MCD_OPC_ExtractField, 24, 2,  // Inst{25-24} ...
/* 3632 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3644
/* 3636 */    MCD_OPC_CheckPredicate, 6, 16, 37, // Skip to: 13128
/* 3640 */    MCD_OPC_Decode, 229, 1, 94, // Opcode: BMNZI_B
/* 3644 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3656
/* 3648 */    MCD_OPC_CheckPredicate, 6, 4, 37, // Skip to: 13128
/* 3652 */    MCD_OPC_Decode, 231, 1, 94, // Opcode: BMZI_B
/* 3656 */    MCD_OPC_FilterValue, 2, 252, 36, // Skip to: 13128
/* 3660 */    MCD_OPC_CheckPredicate, 6, 248, 36, // Skip to: 13128
/* 3664 */    MCD_OPC_Decode, 130, 2, 94, // Opcode: BSELI_B
/* 3668 */    MCD_OPC_FilterValue, 2, 39, 0, // Skip to: 3711
/* 3672 */    MCD_OPC_ExtractField, 24, 2,  // Inst{25-24} ...
/* 3675 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3687
/* 3679 */    MCD_OPC_CheckPredicate, 6, 229, 36, // Skip to: 13128
/* 3683 */    MCD_OPC_Decode, 225, 10, 93, // Opcode: SHF_B
/* 3687 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3699
/* 3691 */    MCD_OPC_CheckPredicate, 6, 217, 36, // Skip to: 13128
/* 3695 */    MCD_OPC_Decode, 226, 10, 95, // Opcode: SHF_H
/* 3699 */    MCD_OPC_FilterValue, 2, 209, 36, // Skip to: 13128
/* 3703 */    MCD_OPC_CheckPredicate, 6, 205, 36, // Skip to: 13128
/* 3707 */    MCD_OPC_Decode, 227, 10, 96, // Opcode: SHF_W
/* 3711 */    MCD_OPC_FilterValue, 6, 31, 1, // Skip to: 4002
/* 3715 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 3718 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 3729
/* 3722 */    MCD_OPC_CheckPredicate, 6, 186, 36, // Skip to: 13128
/* 3726 */    MCD_OPC_Decode, 51, 97, // Opcode: ADDVI_B
/* 3729 */    MCD_OPC_FilterValue, 1, 7, 0, // Skip to: 3740
/* 3733 */    MCD_OPC_CheckPredicate, 6, 175, 36, // Skip to: 13128
/* 3737 */    MCD_OPC_Decode, 53, 98, // Opcode: ADDVI_H
/* 3740 */    MCD_OPC_FilterValue, 2, 7, 0, // Skip to: 3751
/* 3744 */    MCD_OPC_CheckPredicate, 6, 164, 36, // Skip to: 13128
/* 3748 */    MCD_OPC_Decode, 54, 99, // Opcode: ADDVI_W
/* 3751 */    MCD_OPC_FilterValue, 3, 7, 0, // Skip to: 3762
/* 3755 */    MCD_OPC_CheckPredicate, 6, 153, 36, // Skip to: 13128
/* 3759 */    MCD_OPC_Decode, 52, 100, // Opcode: ADDVI_D
/* 3762 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 3774
/* 3766 */    MCD_OPC_CheckPredicate, 6, 142, 36, // Skip to: 13128
/* 3770 */    MCD_OPC_Decode, 253, 11, 97, // Opcode: SUBVI_B
/* 3774 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 3786
/* 3778 */    MCD_OPC_CheckPredicate, 6, 130, 36, // Skip to: 13128
/* 3782 */    MCD_OPC_Decode, 255, 11, 98, // Opcode: SUBVI_H
/* 3786 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 3798
/* 3790 */    MCD_OPC_CheckPredicate, 6, 118, 36, // Skip to: 13128
/* 3794 */    MCD_OPC_Decode, 128, 12, 99, // Opcode: SUBVI_W
/* 3798 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 3810
/* 3802 */    MCD_OPC_CheckPredicate, 6, 106, 36, // Skip to: 13128
/* 3806 */    MCD_OPC_Decode, 254, 11, 100, // Opcode: SUBVI_D
/* 3810 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 3822
/* 3814 */    MCD_OPC_CheckPredicate, 6, 94, 36, // Skip to: 13128
/* 3818 */    MCD_OPC_Decode, 218, 7, 97, // Opcode: MAXI_S_B
/* 3822 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 3834
/* 3826 */    MCD_OPC_CheckPredicate, 6, 82, 36, // Skip to: 13128
/* 3830 */    MCD_OPC_Decode, 220, 7, 98, // Opcode: MAXI_S_H
/* 3834 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 3846
/* 3838 */    MCD_OPC_CheckPredicate, 6, 70, 36, // Skip to: 13128
/* 3842 */    MCD_OPC_Decode, 221, 7, 99, // Opcode: MAXI_S_W
/* 3846 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 3858
/* 3850 */    MCD_OPC_CheckPredicate, 6, 58, 36, // Skip to: 13128
/* 3854 */    MCD_OPC_Decode, 219, 7, 100, // Opcode: MAXI_S_D
/* 3858 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 3870
/* 3862 */    MCD_OPC_CheckPredicate, 6, 46, 36, // Skip to: 13128
/* 3866 */    MCD_OPC_Decode, 222, 7, 97, // Opcode: MAXI_U_B
/* 3870 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 3882
/* 3874 */    MCD_OPC_CheckPredicate, 6, 34, 36, // Skip to: 13128
/* 3878 */    MCD_OPC_Decode, 224, 7, 98, // Opcode: MAXI_U_H
/* 3882 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 3894
/* 3886 */    MCD_OPC_CheckPredicate, 6, 22, 36, // Skip to: 13128
/* 3890 */    MCD_OPC_Decode, 225, 7, 99, // Opcode: MAXI_U_W
/* 3894 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 3906
/* 3898 */    MCD_OPC_CheckPredicate, 6, 10, 36, // Skip to: 13128
/* 3902 */    MCD_OPC_Decode, 223, 7, 100, // Opcode: MAXI_U_D
/* 3906 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 3918
/* 3910 */    MCD_OPC_CheckPredicate, 6, 254, 35, // Skip to: 13128
/* 3914 */    MCD_OPC_Decode, 131, 8, 97, // Opcode: MINI_S_B
/* 3918 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 3930
/* 3922 */    MCD_OPC_CheckPredicate, 6, 242, 35, // Skip to: 13128
/* 3926 */    MCD_OPC_Decode, 133, 8, 98, // Opcode: MINI_S_H
/* 3930 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 3942
/* 3934 */    MCD_OPC_CheckPredicate, 6, 230, 35, // Skip to: 13128
/* 3938 */    MCD_OPC_Decode, 134, 8, 99, // Opcode: MINI_S_W
/* 3942 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 3954
/* 3946 */    MCD_OPC_CheckPredicate, 6, 218, 35, // Skip to: 13128
/* 3950 */    MCD_OPC_Decode, 132, 8, 100, // Opcode: MINI_S_D
/* 3954 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 3966
/* 3958 */    MCD_OPC_CheckPredicate, 6, 206, 35, // Skip to: 13128
/* 3962 */    MCD_OPC_Decode, 135, 8, 97, // Opcode: MINI_U_B
/* 3966 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 3978
/* 3970 */    MCD_OPC_CheckPredicate, 6, 194, 35, // Skip to: 13128
/* 3974 */    MCD_OPC_Decode, 137, 8, 98, // Opcode: MINI_U_H
/* 3978 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 3990
/* 3982 */    MCD_OPC_CheckPredicate, 6, 182, 35, // Skip to: 13128
/* 3986 */    MCD_OPC_Decode, 138, 8, 99, // Opcode: MINI_U_W
/* 3990 */    MCD_OPC_FilterValue, 23, 174, 35, // Skip to: 13128
/* 3994 */    MCD_OPC_CheckPredicate, 6, 170, 35, // Skip to: 13128
/* 3998 */    MCD_OPC_Decode, 136, 8, 100, // Opcode: MINI_U_D
/* 4002 */    MCD_OPC_FilterValue, 7, 35, 1, // Skip to: 4297
/* 4006 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 4009 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4021
/* 4013 */    MCD_OPC_CheckPredicate, 6, 151, 35, // Skip to: 13128
/* 4017 */    MCD_OPC_Decode, 184, 2, 97, // Opcode: CEQI_B
/* 4021 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 4033
/* 4025 */    MCD_OPC_CheckPredicate, 6, 139, 35, // Skip to: 13128
/* 4029 */    MCD_OPC_Decode, 186, 2, 98, // Opcode: CEQI_H
/* 4033 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 4045
/* 4037 */    MCD_OPC_CheckPredicate, 6, 127, 35, // Skip to: 13128
/* 4041 */    MCD_OPC_Decode, 187, 2, 99, // Opcode: CEQI_W
/* 4045 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 4057
/* 4049 */    MCD_OPC_CheckPredicate, 6, 115, 35, // Skip to: 13128
/* 4053 */    MCD_OPC_Decode, 185, 2, 100, // Opcode: CEQI_D
/* 4057 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 4069
/* 4061 */    MCD_OPC_CheckPredicate, 6, 103, 35, // Skip to: 13128
/* 4065 */    MCD_OPC_Decode, 218, 2, 97, // Opcode: CLTI_S_B
/* 4069 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 4081
/* 4073 */    MCD_OPC_CheckPredicate, 6, 91, 35, // Skip to: 13128
/* 4077 */    MCD_OPC_Decode, 220, 2, 98, // Opcode: CLTI_S_H
/* 4081 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 4093
/* 4085 */    MCD_OPC_CheckPredicate, 6, 79, 35, // Skip to: 13128
/* 4089 */    MCD_OPC_Decode, 221, 2, 99, // Opcode: CLTI_S_W
/* 4093 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 4105
/* 4097 */    MCD_OPC_CheckPredicate, 6, 67, 35, // Skip to: 13128
/* 4101 */    MCD_OPC_Decode, 219, 2, 100, // Opcode: CLTI_S_D
/* 4105 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 4117
/* 4109 */    MCD_OPC_CheckPredicate, 6, 55, 35, // Skip to: 13128
/* 4113 */    MCD_OPC_Decode, 222, 2, 97, // Opcode: CLTI_U_B
/* 4117 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 4129
/* 4121 */    MCD_OPC_CheckPredicate, 6, 43, 35, // Skip to: 13128
/* 4125 */    MCD_OPC_Decode, 224, 2, 98, // Opcode: CLTI_U_H
/* 4129 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 4141
/* 4133 */    MCD_OPC_CheckPredicate, 6, 31, 35, // Skip to: 13128
/* 4137 */    MCD_OPC_Decode, 225, 2, 99, // Opcode: CLTI_U_W
/* 4141 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 4153
/* 4145 */    MCD_OPC_CheckPredicate, 6, 19, 35, // Skip to: 13128
/* 4149 */    MCD_OPC_Decode, 223, 2, 100, // Opcode: CLTI_U_D
/* 4153 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 4165
/* 4157 */    MCD_OPC_CheckPredicate, 6, 7, 35, // Skip to: 13128
/* 4161 */    MCD_OPC_Decode, 199, 2, 97, // Opcode: CLEI_S_B
/* 4165 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 4177
/* 4169 */    MCD_OPC_CheckPredicate, 6, 251, 34, // Skip to: 13128
/* 4173 */    MCD_OPC_Decode, 201, 2, 98, // Opcode: CLEI_S_H
/* 4177 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 4189
/* 4181 */    MCD_OPC_CheckPredicate, 6, 239, 34, // Skip to: 13128
/* 4185 */    MCD_OPC_Decode, 202, 2, 99, // Opcode: CLEI_S_W
/* 4189 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 4201
/* 4193 */    MCD_OPC_CheckPredicate, 6, 227, 34, // Skip to: 13128
/* 4197 */    MCD_OPC_Decode, 200, 2, 100, // Opcode: CLEI_S_D
/* 4201 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 4213
/* 4205 */    MCD_OPC_CheckPredicate, 6, 215, 34, // Skip to: 13128
/* 4209 */    MCD_OPC_Decode, 203, 2, 97, // Opcode: CLEI_U_B
/* 4213 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 4225
/* 4217 */    MCD_OPC_CheckPredicate, 6, 203, 34, // Skip to: 13128
/* 4221 */    MCD_OPC_Decode, 205, 2, 98, // Opcode: CLEI_U_H
/* 4225 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 4237
/* 4229 */    MCD_OPC_CheckPredicate, 6, 191, 34, // Skip to: 13128
/* 4233 */    MCD_OPC_Decode, 206, 2, 99, // Opcode: CLEI_U_W
/* 4237 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 4249
/* 4241 */    MCD_OPC_CheckPredicate, 6, 179, 34, // Skip to: 13128
/* 4245 */    MCD_OPC_Decode, 204, 2, 100, // Opcode: CLEI_U_D
/* 4249 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 4261
/* 4253 */    MCD_OPC_CheckPredicate, 6, 167, 34, // Skip to: 13128
/* 4257 */    MCD_OPC_Decode, 239, 6, 101, // Opcode: LDI_B
/* 4261 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 4273
/* 4265 */    MCD_OPC_CheckPredicate, 6, 155, 34, // Skip to: 13128
/* 4269 */    MCD_OPC_Decode, 241, 6, 102, // Opcode: LDI_H
/* 4273 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 4285
/* 4277 */    MCD_OPC_CheckPredicate, 6, 143, 34, // Skip to: 13128
/* 4281 */    MCD_OPC_Decode, 242, 6, 103, // Opcode: LDI_W
/* 4285 */    MCD_OPC_FilterValue, 27, 135, 34, // Skip to: 13128
/* 4289 */    MCD_OPC_CheckPredicate, 6, 131, 34, // Skip to: 13128
/* 4293 */    MCD_OPC_Decode, 240, 6, 104, // Opcode: LDI_D
/* 4297 */    MCD_OPC_FilterValue, 9, 35, 2, // Skip to: 4848
/* 4301 */    MCD_OPC_ExtractField, 22, 4,  // Inst{25-22} ...
/* 4304 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4316
/* 4308 */    MCD_OPC_CheckPredicate, 6, 112, 34, // Skip to: 13128
/* 4312 */    MCD_OPC_Decode, 137, 11, 105, // Opcode: SLLI_D
/* 4316 */    MCD_OPC_FilterValue, 1, 52, 0, // Skip to: 4372
/* 4320 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4323 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4335
/* 4327 */    MCD_OPC_CheckPredicate, 6, 93, 34, // Skip to: 13128
/* 4331 */    MCD_OPC_Decode, 139, 11, 99, // Opcode: SLLI_W
/* 4335 */    MCD_OPC_FilterValue, 1, 85, 34, // Skip to: 13128
/* 4339 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4342 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4354
/* 4346 */    MCD_OPC_CheckPredicate, 6, 74, 34, // Skip to: 13128
/* 4350 */    MCD_OPC_Decode, 138, 11, 106, // Opcode: SLLI_H
/* 4354 */    MCD_OPC_FilterValue, 1, 66, 34, // Skip to: 13128
/* 4358 */    MCD_OPC_CheckPredicate, 6, 62, 34, // Skip to: 13128
/* 4362 */    MCD_OPC_CheckField, 19, 1, 0, 56, 34, // Skip to: 13128
/* 4368 */    MCD_OPC_Decode, 136, 11, 107, // Opcode: SLLI_B
/* 4372 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 4384
/* 4376 */    MCD_OPC_CheckPredicate, 6, 44, 34, // Skip to: 13128
/* 4380 */    MCD_OPC_Decode, 176, 11, 105, // Opcode: SRAI_D
/* 4384 */    MCD_OPC_FilterValue, 3, 52, 0, // Skip to: 4440
/* 4388 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4391 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4403
/* 4395 */    MCD_OPC_CheckPredicate, 6, 25, 34, // Skip to: 13128
/* 4399 */    MCD_OPC_Decode, 178, 11, 99, // Opcode: SRAI_W
/* 4403 */    MCD_OPC_FilterValue, 1, 17, 34, // Skip to: 13128
/* 4407 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4410 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4422
/* 4414 */    MCD_OPC_CheckPredicate, 6, 6, 34, // Skip to: 13128
/* 4418 */    MCD_OPC_Decode, 177, 11, 106, // Opcode: SRAI_H
/* 4422 */    MCD_OPC_FilterValue, 1, 254, 33, // Skip to: 13128
/* 4426 */    MCD_OPC_CheckPredicate, 6, 250, 33, // Skip to: 13128
/* 4430 */    MCD_OPC_CheckField, 19, 1, 0, 244, 33, // Skip to: 13128
/* 4436 */    MCD_OPC_Decode, 175, 11, 107, // Opcode: SRAI_B
/* 4440 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 4452
/* 4444 */    MCD_OPC_CheckPredicate, 6, 232, 33, // Skip to: 13128
/* 4448 */    MCD_OPC_Decode, 196, 11, 105, // Opcode: SRLI_D
/* 4452 */    MCD_OPC_FilterValue, 5, 52, 0, // Skip to: 4508
/* 4456 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4459 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4471
/* 4463 */    MCD_OPC_CheckPredicate, 6, 213, 33, // Skip to: 13128
/* 4467 */    MCD_OPC_Decode, 198, 11, 99, // Opcode: SRLI_W
/* 4471 */    MCD_OPC_FilterValue, 1, 205, 33, // Skip to: 13128
/* 4475 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4478 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4490
/* 4482 */    MCD_OPC_CheckPredicate, 6, 194, 33, // Skip to: 13128
/* 4486 */    MCD_OPC_Decode, 197, 11, 106, // Opcode: SRLI_H
/* 4490 */    MCD_OPC_FilterValue, 1, 186, 33, // Skip to: 13128
/* 4494 */    MCD_OPC_CheckPredicate, 6, 182, 33, // Skip to: 13128
/* 4498 */    MCD_OPC_CheckField, 19, 1, 0, 176, 33, // Skip to: 13128
/* 4504 */    MCD_OPC_Decode, 195, 11, 107, // Opcode: SRLI_B
/* 4508 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 4520
/* 4512 */    MCD_OPC_CheckPredicate, 6, 164, 33, // Skip to: 13128
/* 4516 */    MCD_OPC_Decode, 170, 1, 105, // Opcode: BCLRI_D
/* 4520 */    MCD_OPC_FilterValue, 7, 52, 0, // Skip to: 4576
/* 4524 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4527 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4539
/* 4531 */    MCD_OPC_CheckPredicate, 6, 145, 33, // Skip to: 13128
/* 4535 */    MCD_OPC_Decode, 172, 1, 99, // Opcode: BCLRI_W
/* 4539 */    MCD_OPC_FilterValue, 1, 137, 33, // Skip to: 13128
/* 4543 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4546 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4558
/* 4550 */    MCD_OPC_CheckPredicate, 6, 126, 33, // Skip to: 13128
/* 4554 */    MCD_OPC_Decode, 171, 1, 106, // Opcode: BCLRI_H
/* 4558 */    MCD_OPC_FilterValue, 1, 118, 33, // Skip to: 13128
/* 4562 */    MCD_OPC_CheckPredicate, 6, 114, 33, // Skip to: 13128
/* 4566 */    MCD_OPC_CheckField, 19, 1, 0, 108, 33, // Skip to: 13128
/* 4572 */    MCD_OPC_Decode, 169, 1, 107, // Opcode: BCLRI_B
/* 4576 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 4588
/* 4580 */    MCD_OPC_CheckPredicate, 6, 96, 33, // Skip to: 13128
/* 4584 */    MCD_OPC_Decode, 138, 2, 105, // Opcode: BSETI_D
/* 4588 */    MCD_OPC_FilterValue, 9, 52, 0, // Skip to: 4644
/* 4592 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4595 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4607
/* 4599 */    MCD_OPC_CheckPredicate, 6, 77, 33, // Skip to: 13128
/* 4603 */    MCD_OPC_Decode, 140, 2, 99, // Opcode: BSETI_W
/* 4607 */    MCD_OPC_FilterValue, 1, 69, 33, // Skip to: 13128
/* 4611 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4614 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4626
/* 4618 */    MCD_OPC_CheckPredicate, 6, 58, 33, // Skip to: 13128
/* 4622 */    MCD_OPC_Decode, 139, 2, 106, // Opcode: BSETI_H
/* 4626 */    MCD_OPC_FilterValue, 1, 50, 33, // Skip to: 13128
/* 4630 */    MCD_OPC_CheckPredicate, 6, 46, 33, // Skip to: 13128
/* 4634 */    MCD_OPC_CheckField, 19, 1, 0, 40, 33, // Skip to: 13128
/* 4640 */    MCD_OPC_Decode, 137, 2, 107, // Opcode: BSETI_B
/* 4644 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 4656
/* 4648 */    MCD_OPC_CheckPredicate, 6, 28, 33, // Skip to: 13128
/* 4652 */    MCD_OPC_Decode, 237, 1, 105, // Opcode: BNEGI_D
/* 4656 */    MCD_OPC_FilterValue, 11, 52, 0, // Skip to: 4712
/* 4660 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4663 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4675
/* 4667 */    MCD_OPC_CheckPredicate, 6, 9, 33, // Skip to: 13128
/* 4671 */    MCD_OPC_Decode, 239, 1, 99, // Opcode: BNEGI_W
/* 4675 */    MCD_OPC_FilterValue, 1, 1, 33, // Skip to: 13128
/* 4679 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4682 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4694
/* 4686 */    MCD_OPC_CheckPredicate, 6, 246, 32, // Skip to: 13128
/* 4690 */    MCD_OPC_Decode, 238, 1, 106, // Opcode: BNEGI_H
/* 4694 */    MCD_OPC_FilterValue, 1, 238, 32, // Skip to: 13128
/* 4698 */    MCD_OPC_CheckPredicate, 6, 234, 32, // Skip to: 13128
/* 4702 */    MCD_OPC_CheckField, 19, 1, 0, 228, 32, // Skip to: 13128
/* 4708 */    MCD_OPC_Decode, 236, 1, 107, // Opcode: BNEGI_B
/* 4712 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 4724
/* 4716 */    MCD_OPC_CheckPredicate, 6, 216, 32, // Skip to: 13128
/* 4720 */    MCD_OPC_Decode, 198, 1, 108, // Opcode: BINSLI_D
/* 4724 */    MCD_OPC_FilterValue, 13, 52, 0, // Skip to: 4780
/* 4728 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4731 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4743
/* 4735 */    MCD_OPC_CheckPredicate, 6, 197, 32, // Skip to: 13128
/* 4739 */    MCD_OPC_Decode, 200, 1, 109, // Opcode: BINSLI_W
/* 4743 */    MCD_OPC_FilterValue, 1, 189, 32, // Skip to: 13128
/* 4747 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4750 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4762
/* 4754 */    MCD_OPC_CheckPredicate, 6, 178, 32, // Skip to: 13128
/* 4758 */    MCD_OPC_Decode, 199, 1, 110, // Opcode: BINSLI_H
/* 4762 */    MCD_OPC_FilterValue, 1, 170, 32, // Skip to: 13128
/* 4766 */    MCD_OPC_CheckPredicate, 6, 166, 32, // Skip to: 13128
/* 4770 */    MCD_OPC_CheckField, 19, 1, 0, 160, 32, // Skip to: 13128
/* 4776 */    MCD_OPC_Decode, 197, 1, 111, // Opcode: BINSLI_B
/* 4780 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 4792
/* 4784 */    MCD_OPC_CheckPredicate, 6, 148, 32, // Skip to: 13128
/* 4788 */    MCD_OPC_Decode, 206, 1, 108, // Opcode: BINSRI_D
/* 4792 */    MCD_OPC_FilterValue, 15, 140, 32, // Skip to: 13128
/* 4796 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4799 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4811
/* 4803 */    MCD_OPC_CheckPredicate, 6, 129, 32, // Skip to: 13128
/* 4807 */    MCD_OPC_Decode, 208, 1, 109, // Opcode: BINSRI_W
/* 4811 */    MCD_OPC_FilterValue, 1, 121, 32, // Skip to: 13128
/* 4815 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4818 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4830
/* 4822 */    MCD_OPC_CheckPredicate, 6, 110, 32, // Skip to: 13128
/* 4826 */    MCD_OPC_Decode, 207, 1, 110, // Opcode: BINSRI_H
/* 4830 */    MCD_OPC_FilterValue, 1, 102, 32, // Skip to: 13128
/* 4834 */    MCD_OPC_CheckPredicate, 6, 98, 32, // Skip to: 13128
/* 4838 */    MCD_OPC_CheckField, 19, 1, 0, 92, 32, // Skip to: 13128
/* 4844 */    MCD_OPC_Decode, 205, 1, 111, // Opcode: BINSRI_B
/* 4848 */    MCD_OPC_FilterValue, 10, 19, 1, // Skip to: 5127
/* 4852 */    MCD_OPC_ExtractField, 22, 4,  // Inst{25-22} ...
/* 4855 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4867
/* 4859 */    MCD_OPC_CheckPredicate, 6, 73, 32, // Skip to: 13128
/* 4863 */    MCD_OPC_Decode, 175, 10, 105, // Opcode: SAT_S_D
/* 4867 */    MCD_OPC_FilterValue, 1, 52, 0, // Skip to: 4923
/* 4871 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4874 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4886
/* 4878 */    MCD_OPC_CheckPredicate, 6, 54, 32, // Skip to: 13128
/* 4882 */    MCD_OPC_Decode, 177, 10, 99, // Opcode: SAT_S_W
/* 4886 */    MCD_OPC_FilterValue, 1, 46, 32, // Skip to: 13128
/* 4890 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4893 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4905
/* 4897 */    MCD_OPC_CheckPredicate, 6, 35, 32, // Skip to: 13128
/* 4901 */    MCD_OPC_Decode, 176, 10, 106, // Opcode: SAT_S_H
/* 4905 */    MCD_OPC_FilterValue, 1, 27, 32, // Skip to: 13128
/* 4909 */    MCD_OPC_CheckPredicate, 6, 23, 32, // Skip to: 13128
/* 4913 */    MCD_OPC_CheckField, 19, 1, 0, 17, 32, // Skip to: 13128
/* 4919 */    MCD_OPC_Decode, 174, 10, 107, // Opcode: SAT_S_B
/* 4923 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 4935
/* 4927 */    MCD_OPC_CheckPredicate, 6, 5, 32, // Skip to: 13128
/* 4931 */    MCD_OPC_Decode, 179, 10, 105, // Opcode: SAT_U_D
/* 4935 */    MCD_OPC_FilterValue, 3, 52, 0, // Skip to: 4991
/* 4939 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4942 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4954
/* 4946 */    MCD_OPC_CheckPredicate, 6, 242, 31, // Skip to: 13128
/* 4950 */    MCD_OPC_Decode, 181, 10, 99, // Opcode: SAT_U_W
/* 4954 */    MCD_OPC_FilterValue, 1, 234, 31, // Skip to: 13128
/* 4958 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4961 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4973
/* 4965 */    MCD_OPC_CheckPredicate, 6, 223, 31, // Skip to: 13128
/* 4969 */    MCD_OPC_Decode, 180, 10, 106, // Opcode: SAT_U_H
/* 4973 */    MCD_OPC_FilterValue, 1, 215, 31, // Skip to: 13128
/* 4977 */    MCD_OPC_CheckPredicate, 6, 211, 31, // Skip to: 13128
/* 4981 */    MCD_OPC_CheckField, 19, 1, 0, 205, 31, // Skip to: 13128
/* 4987 */    MCD_OPC_Decode, 178, 10, 107, // Opcode: SAT_U_B
/* 4991 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 5003
/* 4995 */    MCD_OPC_CheckPredicate, 6, 193, 31, // Skip to: 13128
/* 4999 */    MCD_OPC_Decode, 180, 11, 105, // Opcode: SRARI_D
/* 5003 */    MCD_OPC_FilterValue, 5, 52, 0, // Skip to: 5059
/* 5007 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 5010 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5022
/* 5014 */    MCD_OPC_CheckPredicate, 6, 174, 31, // Skip to: 13128
/* 5018 */    MCD_OPC_Decode, 182, 11, 99, // Opcode: SRARI_W
/* 5022 */    MCD_OPC_FilterValue, 1, 166, 31, // Skip to: 13128
/* 5026 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 5029 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5041
/* 5033 */    MCD_OPC_CheckPredicate, 6, 155, 31, // Skip to: 13128
/* 5037 */    MCD_OPC_Decode, 181, 11, 106, // Opcode: SRARI_H
/* 5041 */    MCD_OPC_FilterValue, 1, 147, 31, // Skip to: 13128
/* 5045 */    MCD_OPC_CheckPredicate, 6, 143, 31, // Skip to: 13128
/* 5049 */    MCD_OPC_CheckField, 19, 1, 0, 137, 31, // Skip to: 13128
/* 5055 */    MCD_OPC_Decode, 179, 11, 107, // Opcode: SRARI_B
/* 5059 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 5071
/* 5063 */    MCD_OPC_CheckPredicate, 6, 125, 31, // Skip to: 13128
/* 5067 */    MCD_OPC_Decode, 200, 11, 105, // Opcode: SRLRI_D
/* 5071 */    MCD_OPC_FilterValue, 7, 117, 31, // Skip to: 13128
/* 5075 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 5078 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5090
/* 5082 */    MCD_OPC_CheckPredicate, 6, 106, 31, // Skip to: 13128
/* 5086 */    MCD_OPC_Decode, 202, 11, 99, // Opcode: SRLRI_W
/* 5090 */    MCD_OPC_FilterValue, 1, 98, 31, // Skip to: 13128
/* 5094 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 5097 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5109
/* 5101 */    MCD_OPC_CheckPredicate, 6, 87, 31, // Skip to: 13128
/* 5105 */    MCD_OPC_Decode, 201, 11, 106, // Opcode: SRLRI_H
/* 5109 */    MCD_OPC_FilterValue, 1, 79, 31, // Skip to: 13128
/* 5113 */    MCD_OPC_CheckPredicate, 6, 75, 31, // Skip to: 13128
/* 5117 */    MCD_OPC_CheckField, 19, 1, 0, 69, 31, // Skip to: 13128
/* 5123 */    MCD_OPC_Decode, 199, 11, 107, // Opcode: SRLRI_B
/* 5127 */    MCD_OPC_FilterValue, 13, 131, 1, // Skip to: 5518
/* 5131 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 5134 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5146
/* 5138 */    MCD_OPC_CheckPredicate, 6, 50, 31, // Skip to: 13128
/* 5142 */    MCD_OPC_Decode, 142, 11, 112, // Opcode: SLL_B
/* 5146 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 5158
/* 5150 */    MCD_OPC_CheckPredicate, 6, 38, 31, // Skip to: 13128
/* 5154 */    MCD_OPC_Decode, 144, 11, 113, // Opcode: SLL_H
/* 5158 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 5170
/* 5162 */    MCD_OPC_CheckPredicate, 6, 26, 31, // Skip to: 13128
/* 5166 */    MCD_OPC_Decode, 146, 11, 114, // Opcode: SLL_W
/* 5170 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 5182
/* 5174 */    MCD_OPC_CheckPredicate, 6, 14, 31, // Skip to: 13128
/* 5178 */    MCD_OPC_Decode, 143, 11, 115, // Opcode: SLL_D
/* 5182 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 5194
/* 5186 */    MCD_OPC_CheckPredicate, 6, 2, 31, // Skip to: 13128
/* 5190 */    MCD_OPC_Decode, 189, 11, 112, // Opcode: SRA_B
/* 5194 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 5206
/* 5198 */    MCD_OPC_CheckPredicate, 6, 246, 30, // Skip to: 13128
/* 5202 */    MCD_OPC_Decode, 191, 11, 113, // Opcode: SRA_H
/* 5206 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 5218
/* 5210 */    MCD_OPC_CheckPredicate, 6, 234, 30, // Skip to: 13128
/* 5214 */    MCD_OPC_Decode, 193, 11, 114, // Opcode: SRA_W
/* 5218 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 5230
/* 5222 */    MCD_OPC_CheckPredicate, 6, 222, 30, // Skip to: 13128
/* 5226 */    MCD_OPC_Decode, 190, 11, 115, // Opcode: SRA_D
/* 5230 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 5242
/* 5234 */    MCD_OPC_CheckPredicate, 6, 210, 30, // Skip to: 13128
/* 5238 */    MCD_OPC_Decode, 209, 11, 112, // Opcode: SRL_B
/* 5242 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 5254
/* 5246 */    MCD_OPC_CheckPredicate, 6, 198, 30, // Skip to: 13128
/* 5250 */    MCD_OPC_Decode, 211, 11, 113, // Opcode: SRL_H
/* 5254 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 5266
/* 5258 */    MCD_OPC_CheckPredicate, 6, 186, 30, // Skip to: 13128
/* 5262 */    MCD_OPC_Decode, 213, 11, 114, // Opcode: SRL_W
/* 5266 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 5278
/* 5270 */    MCD_OPC_CheckPredicate, 6, 174, 30, // Skip to: 13128
/* 5274 */    MCD_OPC_Decode, 210, 11, 115, // Opcode: SRL_D
/* 5278 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 5290
/* 5282 */    MCD_OPC_CheckPredicate, 6, 162, 30, // Skip to: 13128
/* 5286 */    MCD_OPC_Decode, 173, 1, 112, // Opcode: BCLR_B
/* 5290 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 5302
/* 5294 */    MCD_OPC_CheckPredicate, 6, 150, 30, // Skip to: 13128
/* 5298 */    MCD_OPC_Decode, 175, 1, 113, // Opcode: BCLR_H
/* 5302 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 5314
/* 5306 */    MCD_OPC_CheckPredicate, 6, 138, 30, // Skip to: 13128
/* 5310 */    MCD_OPC_Decode, 176, 1, 114, // Opcode: BCLR_W
/* 5314 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 5326
/* 5318 */    MCD_OPC_CheckPredicate, 6, 126, 30, // Skip to: 13128
/* 5322 */    MCD_OPC_Decode, 174, 1, 115, // Opcode: BCLR_D
/* 5326 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 5338
/* 5330 */    MCD_OPC_CheckPredicate, 6, 114, 30, // Skip to: 13128
/* 5334 */    MCD_OPC_Decode, 141, 2, 112, // Opcode: BSET_B
/* 5338 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 5350
/* 5342 */    MCD_OPC_CheckPredicate, 6, 102, 30, // Skip to: 13128
/* 5346 */    MCD_OPC_Decode, 143, 2, 113, // Opcode: BSET_H
/* 5350 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 5362
/* 5354 */    MCD_OPC_CheckPredicate, 6, 90, 30, // Skip to: 13128
/* 5358 */    MCD_OPC_Decode, 144, 2, 114, // Opcode: BSET_W
/* 5362 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 5374
/* 5366 */    MCD_OPC_CheckPredicate, 6, 78, 30, // Skip to: 13128
/* 5370 */    MCD_OPC_Decode, 142, 2, 115, // Opcode: BSET_D
/* 5374 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 5386
/* 5378 */    MCD_OPC_CheckPredicate, 6, 66, 30, // Skip to: 13128
/* 5382 */    MCD_OPC_Decode, 240, 1, 112, // Opcode: BNEG_B
/* 5386 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 5398
/* 5390 */    MCD_OPC_CheckPredicate, 6, 54, 30, // Skip to: 13128
/* 5394 */    MCD_OPC_Decode, 242, 1, 113, // Opcode: BNEG_H
/* 5398 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 5410
/* 5402 */    MCD_OPC_CheckPredicate, 6, 42, 30, // Skip to: 13128
/* 5406 */    MCD_OPC_Decode, 243, 1, 114, // Opcode: BNEG_W
/* 5410 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 5422
/* 5414 */    MCD_OPC_CheckPredicate, 6, 30, 30, // Skip to: 13128
/* 5418 */    MCD_OPC_Decode, 241, 1, 115, // Opcode: BNEG_D
/* 5422 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 5434
/* 5426 */    MCD_OPC_CheckPredicate, 6, 18, 30, // Skip to: 13128
/* 5430 */    MCD_OPC_Decode, 201, 1, 116, // Opcode: BINSL_B
/* 5434 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 5446
/* 5438 */    MCD_OPC_CheckPredicate, 6, 6, 30, // Skip to: 13128
/* 5442 */    MCD_OPC_Decode, 203, 1, 117, // Opcode: BINSL_H
/* 5446 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 5458
/* 5450 */    MCD_OPC_CheckPredicate, 6, 250, 29, // Skip to: 13128
/* 5454 */    MCD_OPC_Decode, 204, 1, 118, // Opcode: BINSL_W
/* 5458 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 5470
/* 5462 */    MCD_OPC_CheckPredicate, 6, 238, 29, // Skip to: 13128
/* 5466 */    MCD_OPC_Decode, 202, 1, 119, // Opcode: BINSL_D
/* 5470 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 5482
/* 5474 */    MCD_OPC_CheckPredicate, 6, 226, 29, // Skip to: 13128
/* 5478 */    MCD_OPC_Decode, 209, 1, 116, // Opcode: BINSR_B
/* 5482 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 5494
/* 5486 */    MCD_OPC_CheckPredicate, 6, 214, 29, // Skip to: 13128
/* 5490 */    MCD_OPC_Decode, 211, 1, 117, // Opcode: BINSR_H
/* 5494 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 5506
/* 5498 */    MCD_OPC_CheckPredicate, 6, 202, 29, // Skip to: 13128
/* 5502 */    MCD_OPC_Decode, 212, 1, 118, // Opcode: BINSR_W
/* 5506 */    MCD_OPC_FilterValue, 31, 194, 29, // Skip to: 13128
/* 5510 */    MCD_OPC_CheckPredicate, 6, 190, 29, // Skip to: 13128
/* 5514 */    MCD_OPC_Decode, 210, 1, 119, // Opcode: BINSR_D
/* 5518 */    MCD_OPC_FilterValue, 14, 127, 1, // Skip to: 5905
/* 5522 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 5525 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 5536
/* 5529 */    MCD_OPC_CheckPredicate, 6, 171, 29, // Skip to: 13128
/* 5533 */    MCD_OPC_Decode, 55, 112, // Opcode: ADDV_B
/* 5536 */    MCD_OPC_FilterValue, 1, 7, 0, // Skip to: 5547
/* 5540 */    MCD_OPC_CheckPredicate, 6, 160, 29, // Skip to: 13128
/* 5544 */    MCD_OPC_Decode, 57, 113, // Opcode: ADDV_H
/* 5547 */    MCD_OPC_FilterValue, 2, 7, 0, // Skip to: 5558
/* 5551 */    MCD_OPC_CheckPredicate, 6, 149, 29, // Skip to: 13128
/* 5555 */    MCD_OPC_Decode, 58, 114, // Opcode: ADDV_W
/* 5558 */    MCD_OPC_FilterValue, 3, 7, 0, // Skip to: 5569
/* 5562 */    MCD_OPC_CheckPredicate, 6, 138, 29, // Skip to: 13128
/* 5566 */    MCD_OPC_Decode, 56, 115, // Opcode: ADDV_D
/* 5569 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 5581
/* 5573 */    MCD_OPC_CheckPredicate, 6, 127, 29, // Skip to: 13128
/* 5577 */    MCD_OPC_Decode, 129, 12, 112, // Opcode: SUBV_B
/* 5581 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 5593
/* 5585 */    MCD_OPC_CheckPredicate, 6, 115, 29, // Skip to: 13128
/* 5589 */    MCD_OPC_Decode, 131, 12, 113, // Opcode: SUBV_H
/* 5593 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 5605
/* 5597 */    MCD_OPC_CheckPredicate, 6, 103, 29, // Skip to: 13128
/* 5601 */    MCD_OPC_Decode, 132, 12, 114, // Opcode: SUBV_W
/* 5605 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 5617
/* 5609 */    MCD_OPC_CheckPredicate, 6, 91, 29, // Skip to: 13128
/* 5613 */    MCD_OPC_Decode, 130, 12, 115, // Opcode: SUBV_D
/* 5617 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 5629
/* 5621 */    MCD_OPC_CheckPredicate, 6, 79, 29, // Skip to: 13128
/* 5625 */    MCD_OPC_Decode, 232, 7, 112, // Opcode: MAX_S_B
/* 5629 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 5641
/* 5633 */    MCD_OPC_CheckPredicate, 6, 67, 29, // Skip to: 13128
/* 5637 */    MCD_OPC_Decode, 234, 7, 113, // Opcode: MAX_S_H
/* 5641 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 5653
/* 5645 */    MCD_OPC_CheckPredicate, 6, 55, 29, // Skip to: 13128
/* 5649 */    MCD_OPC_Decode, 235, 7, 114, // Opcode: MAX_S_W
/* 5653 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 5665
/* 5657 */    MCD_OPC_CheckPredicate, 6, 43, 29, // Skip to: 13128
/* 5661 */    MCD_OPC_Decode, 233, 7, 115, // Opcode: MAX_S_D
/* 5665 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 5677
/* 5669 */    MCD_OPC_CheckPredicate, 6, 31, 29, // Skip to: 13128
/* 5673 */    MCD_OPC_Decode, 236, 7, 112, // Opcode: MAX_U_B
/* 5677 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 5689
/* 5681 */    MCD_OPC_CheckPredicate, 6, 19, 29, // Skip to: 13128
/* 5685 */    MCD_OPC_Decode, 238, 7, 113, // Opcode: MAX_U_H
/* 5689 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 5701
/* 5693 */    MCD_OPC_CheckPredicate, 6, 7, 29, // Skip to: 13128
/* 5697 */    MCD_OPC_Decode, 239, 7, 114, // Opcode: MAX_U_W
/* 5701 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 5713
/* 5705 */    MCD_OPC_CheckPredicate, 6, 251, 28, // Skip to: 13128
/* 5709 */    MCD_OPC_Decode, 237, 7, 115, // Opcode: MAX_U_D
/* 5713 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 5725
/* 5717 */    MCD_OPC_CheckPredicate, 6, 239, 28, // Skip to: 13128
/* 5721 */    MCD_OPC_Decode, 145, 8, 112, // Opcode: MIN_S_B
/* 5725 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 5737
/* 5729 */    MCD_OPC_CheckPredicate, 6, 227, 28, // Skip to: 13128
/* 5733 */    MCD_OPC_Decode, 147, 8, 113, // Opcode: MIN_S_H
/* 5737 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 5749
/* 5741 */    MCD_OPC_CheckPredicate, 6, 215, 28, // Skip to: 13128
/* 5745 */    MCD_OPC_Decode, 148, 8, 114, // Opcode: MIN_S_W
/* 5749 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 5761
/* 5753 */    MCD_OPC_CheckPredicate, 6, 203, 28, // Skip to: 13128
/* 5757 */    MCD_OPC_Decode, 146, 8, 115, // Opcode: MIN_S_D
/* 5761 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 5773
/* 5765 */    MCD_OPC_CheckPredicate, 6, 191, 28, // Skip to: 13128
/* 5769 */    MCD_OPC_Decode, 149, 8, 112, // Opcode: MIN_U_B
/* 5773 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 5785
/* 5777 */    MCD_OPC_CheckPredicate, 6, 179, 28, // Skip to: 13128
/* 5781 */    MCD_OPC_Decode, 151, 8, 113, // Opcode: MIN_U_H
/* 5785 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 5797
/* 5789 */    MCD_OPC_CheckPredicate, 6, 167, 28, // Skip to: 13128
/* 5793 */    MCD_OPC_Decode, 152, 8, 114, // Opcode: MIN_U_W
/* 5797 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 5809
/* 5801 */    MCD_OPC_CheckPredicate, 6, 155, 28, // Skip to: 13128
/* 5805 */    MCD_OPC_Decode, 150, 8, 115, // Opcode: MIN_U_D
/* 5809 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 5821
/* 5813 */    MCD_OPC_CheckPredicate, 6, 143, 28, // Skip to: 13128
/* 5817 */    MCD_OPC_Decode, 226, 7, 112, // Opcode: MAX_A_B
/* 5821 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 5833
/* 5825 */    MCD_OPC_CheckPredicate, 6, 131, 28, // Skip to: 13128
/* 5829 */    MCD_OPC_Decode, 228, 7, 113, // Opcode: MAX_A_H
/* 5833 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 5845
/* 5837 */    MCD_OPC_CheckPredicate, 6, 119, 28, // Skip to: 13128
/* 5841 */    MCD_OPC_Decode, 229, 7, 114, // Opcode: MAX_A_W
/* 5845 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 5857
/* 5849 */    MCD_OPC_CheckPredicate, 6, 107, 28, // Skip to: 13128
/* 5853 */    MCD_OPC_Decode, 227, 7, 115, // Opcode: MAX_A_D
/* 5857 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 5869
/* 5861 */    MCD_OPC_CheckPredicate, 6, 95, 28, // Skip to: 13128
/* 5865 */    MCD_OPC_Decode, 139, 8, 112, // Opcode: MIN_A_B
/* 5869 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 5881
/* 5873 */    MCD_OPC_CheckPredicate, 6, 83, 28, // Skip to: 13128
/* 5877 */    MCD_OPC_Decode, 141, 8, 113, // Opcode: MIN_A_H
/* 5881 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 5893
/* 5885 */    MCD_OPC_CheckPredicate, 6, 71, 28, // Skip to: 13128
/* 5889 */    MCD_OPC_Decode, 142, 8, 114, // Opcode: MIN_A_W
/* 5893 */    MCD_OPC_FilterValue, 31, 63, 28, // Skip to: 13128
/* 5897 */    MCD_OPC_CheckPredicate, 6, 59, 28, // Skip to: 13128
/* 5901 */    MCD_OPC_Decode, 140, 8, 115, // Opcode: MIN_A_D
/* 5905 */    MCD_OPC_FilterValue, 15, 243, 0, // Skip to: 6152
/* 5909 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 5912 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5924
/* 5916 */    MCD_OPC_CheckPredicate, 6, 40, 28, // Skip to: 13128
/* 5920 */    MCD_OPC_Decode, 188, 2, 112, // Opcode: CEQ_B
/* 5924 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 5936
/* 5928 */    MCD_OPC_CheckPredicate, 6, 28, 28, // Skip to: 13128
/* 5932 */    MCD_OPC_Decode, 190, 2, 113, // Opcode: CEQ_H
/* 5936 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 5948
/* 5940 */    MCD_OPC_CheckPredicate, 6, 16, 28, // Skip to: 13128
/* 5944 */    MCD_OPC_Decode, 191, 2, 114, // Opcode: CEQ_W
/* 5948 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 5960
/* 5952 */    MCD_OPC_CheckPredicate, 6, 4, 28, // Skip to: 13128
/* 5956 */    MCD_OPC_Decode, 189, 2, 115, // Opcode: CEQ_D
/* 5960 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 5972
/* 5964 */    MCD_OPC_CheckPredicate, 6, 248, 27, // Skip to: 13128
/* 5968 */    MCD_OPC_Decode, 226, 2, 112, // Opcode: CLT_S_B
/* 5972 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 5984
/* 5976 */    MCD_OPC_CheckPredicate, 6, 236, 27, // Skip to: 13128
/* 5980 */    MCD_OPC_Decode, 228, 2, 113, // Opcode: CLT_S_H
/* 5984 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 5996
/* 5988 */    MCD_OPC_CheckPredicate, 6, 224, 27, // Skip to: 13128
/* 5992 */    MCD_OPC_Decode, 229, 2, 114, // Opcode: CLT_S_W
/* 5996 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 6008
/* 6000 */    MCD_OPC_CheckPredicate, 6, 212, 27, // Skip to: 13128
/* 6004 */    MCD_OPC_Decode, 227, 2, 115, // Opcode: CLT_S_D
/* 6008 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 6020
/* 6012 */    MCD_OPC_CheckPredicate, 6, 200, 27, // Skip to: 13128
/* 6016 */    MCD_OPC_Decode, 230, 2, 112, // Opcode: CLT_U_B
/* 6020 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 6032
/* 6024 */    MCD_OPC_CheckPredicate, 6, 188, 27, // Skip to: 13128
/* 6028 */    MCD_OPC_Decode, 232, 2, 113, // Opcode: CLT_U_H
/* 6032 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 6044
/* 6036 */    MCD_OPC_CheckPredicate, 6, 176, 27, // Skip to: 13128
/* 6040 */    MCD_OPC_Decode, 233, 2, 114, // Opcode: CLT_U_W
/* 6044 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 6056
/* 6048 */    MCD_OPC_CheckPredicate, 6, 164, 27, // Skip to: 13128
/* 6052 */    MCD_OPC_Decode, 231, 2, 115, // Opcode: CLT_U_D
/* 6056 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 6068
/* 6060 */    MCD_OPC_CheckPredicate, 6, 152, 27, // Skip to: 13128
/* 6064 */    MCD_OPC_Decode, 207, 2, 112, // Opcode: CLE_S_B
/* 6068 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 6080
/* 6072 */    MCD_OPC_CheckPredicate, 6, 140, 27, // Skip to: 13128
/* 6076 */    MCD_OPC_Decode, 209, 2, 113, // Opcode: CLE_S_H
/* 6080 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 6092
/* 6084 */    MCD_OPC_CheckPredicate, 6, 128, 27, // Skip to: 13128
/* 6088 */    MCD_OPC_Decode, 210, 2, 114, // Opcode: CLE_S_W
/* 6092 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 6104
/* 6096 */    MCD_OPC_CheckPredicate, 6, 116, 27, // Skip to: 13128
/* 6100 */    MCD_OPC_Decode, 208, 2, 115, // Opcode: CLE_S_D
/* 6104 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 6116
/* 6108 */    MCD_OPC_CheckPredicate, 6, 104, 27, // Skip to: 13128
/* 6112 */    MCD_OPC_Decode, 211, 2, 112, // Opcode: CLE_U_B
/* 6116 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 6128
/* 6120 */    MCD_OPC_CheckPredicate, 6, 92, 27, // Skip to: 13128
/* 6124 */    MCD_OPC_Decode, 213, 2, 113, // Opcode: CLE_U_H
/* 6128 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 6140
/* 6132 */    MCD_OPC_CheckPredicate, 6, 80, 27, // Skip to: 13128
/* 6136 */    MCD_OPC_Decode, 214, 2, 114, // Opcode: CLE_U_W
/* 6140 */    MCD_OPC_FilterValue, 23, 72, 27, // Skip to: 13128
/* 6144 */    MCD_OPC_CheckPredicate, 6, 68, 27, // Skip to: 13128
/* 6148 */    MCD_OPC_Decode, 212, 2, 115, // Opcode: CLE_U_D
/* 6152 */    MCD_OPC_FilterValue, 16, 115, 1, // Skip to: 6527
/* 6156 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 6159 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 6170
/* 6163 */    MCD_OPC_CheckPredicate, 6, 49, 27, // Skip to: 13128
/* 6167 */    MCD_OPC_Decode, 60, 112, // Opcode: ADD_A_B
/* 6170 */    MCD_OPC_FilterValue, 1, 7, 0, // Skip to: 6181
/* 6174 */    MCD_OPC_CheckPredicate, 6, 38, 27, // Skip to: 13128
/* 6178 */    MCD_OPC_Decode, 62, 113, // Opcode: ADD_A_H
/* 6181 */    MCD_OPC_FilterValue, 2, 7, 0, // Skip to: 6192
/* 6185 */    MCD_OPC_CheckPredicate, 6, 27, 27, // Skip to: 13128
/* 6189 */    MCD_OPC_Decode, 63, 114, // Opcode: ADD_A_W
/* 6192 */    MCD_OPC_FilterValue, 3, 7, 0, // Skip to: 6203
/* 6196 */    MCD_OPC_CheckPredicate, 6, 16, 27, // Skip to: 13128
/* 6200 */    MCD_OPC_Decode, 61, 115, // Opcode: ADD_A_D
/* 6203 */    MCD_OPC_FilterValue, 4, 7, 0, // Skip to: 6214
/* 6207 */    MCD_OPC_CheckPredicate, 6, 5, 27, // Skip to: 13128
/* 6211 */    MCD_OPC_Decode, 33, 112, // Opcode: ADDS_A_B
/* 6214 */    MCD_OPC_FilterValue, 5, 7, 0, // Skip to: 6225
/* 6218 */    MCD_OPC_CheckPredicate, 6, 250, 26, // Skip to: 13128
/* 6222 */    MCD_OPC_Decode, 35, 113, // Opcode: ADDS_A_H
/* 6225 */    MCD_OPC_FilterValue, 6, 7, 0, // Skip to: 6236
/* 6229 */    MCD_OPC_CheckPredicate, 6, 239, 26, // Skip to: 13128
/* 6233 */    MCD_OPC_Decode, 36, 114, // Opcode: ADDS_A_W
/* 6236 */    MCD_OPC_FilterValue, 7, 7, 0, // Skip to: 6247
/* 6240 */    MCD_OPC_CheckPredicate, 6, 228, 26, // Skip to: 13128
/* 6244 */    MCD_OPC_Decode, 34, 115, // Opcode: ADDS_A_D
/* 6247 */    MCD_OPC_FilterValue, 8, 7, 0, // Skip to: 6258
/* 6251 */    MCD_OPC_CheckPredicate, 6, 217, 26, // Skip to: 13128
/* 6255 */    MCD_OPC_Decode, 37, 112, // Opcode: ADDS_S_B
/* 6258 */    MCD_OPC_FilterValue, 9, 7, 0, // Skip to: 6269
/* 6262 */    MCD_OPC_CheckPredicate, 6, 206, 26, // Skip to: 13128
/* 6266 */    MCD_OPC_Decode, 39, 113, // Opcode: ADDS_S_H
/* 6269 */    MCD_OPC_FilterValue, 10, 7, 0, // Skip to: 6280
/* 6273 */    MCD_OPC_CheckPredicate, 6, 195, 26, // Skip to: 13128
/* 6277 */    MCD_OPC_Decode, 40, 114, // Opcode: ADDS_S_W
/* 6280 */    MCD_OPC_FilterValue, 11, 7, 0, // Skip to: 6291
/* 6284 */    MCD_OPC_CheckPredicate, 6, 184, 26, // Skip to: 13128
/* 6288 */    MCD_OPC_Decode, 38, 115, // Opcode: ADDS_S_D
/* 6291 */    MCD_OPC_FilterValue, 12, 7, 0, // Skip to: 6302
/* 6295 */    MCD_OPC_CheckPredicate, 6, 173, 26, // Skip to: 13128
/* 6299 */    MCD_OPC_Decode, 41, 112, // Opcode: ADDS_U_B
/* 6302 */    MCD_OPC_FilterValue, 13, 7, 0, // Skip to: 6313
/* 6306 */    MCD_OPC_CheckPredicate, 6, 162, 26, // Skip to: 13128
/* 6310 */    MCD_OPC_Decode, 43, 113, // Opcode: ADDS_U_H
/* 6313 */    MCD_OPC_FilterValue, 14, 7, 0, // Skip to: 6324
/* 6317 */    MCD_OPC_CheckPredicate, 6, 151, 26, // Skip to: 13128
/* 6321 */    MCD_OPC_Decode, 44, 114, // Opcode: ADDS_U_W
/* 6324 */    MCD_OPC_FilterValue, 15, 7, 0, // Skip to: 6335
/* 6328 */    MCD_OPC_CheckPredicate, 6, 140, 26, // Skip to: 13128
/* 6332 */    MCD_OPC_Decode, 42, 115, // Opcode: ADDS_U_D
/* 6335 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 6347
/* 6339 */    MCD_OPC_CheckPredicate, 6, 129, 26, // Skip to: 13128
/* 6343 */    MCD_OPC_Decode, 137, 1, 112, // Opcode: AVE_S_B
/* 6347 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 6359
/* 6351 */    MCD_OPC_CheckPredicate, 6, 117, 26, // Skip to: 13128
/* 6355 */    MCD_OPC_Decode, 139, 1, 113, // Opcode: AVE_S_H
/* 6359 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 6371
/* 6363 */    MCD_OPC_CheckPredicate, 6, 105, 26, // Skip to: 13128
/* 6367 */    MCD_OPC_Decode, 140, 1, 114, // Opcode: AVE_S_W
/* 6371 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 6383
/* 6375 */    MCD_OPC_CheckPredicate, 6, 93, 26, // Skip to: 13128
/* 6379 */    MCD_OPC_Decode, 138, 1, 115, // Opcode: AVE_S_D
/* 6383 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 6395
/* 6387 */    MCD_OPC_CheckPredicate, 6, 81, 26, // Skip to: 13128
/* 6391 */    MCD_OPC_Decode, 141, 1, 112, // Opcode: AVE_U_B
/* 6395 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 6407
/* 6399 */    MCD_OPC_CheckPredicate, 6, 69, 26, // Skip to: 13128
/* 6403 */    MCD_OPC_Decode, 143, 1, 113, // Opcode: AVE_U_H
/* 6407 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 6419
/* 6411 */    MCD_OPC_CheckPredicate, 6, 57, 26, // Skip to: 13128
/* 6415 */    MCD_OPC_Decode, 144, 1, 114, // Opcode: AVE_U_W
/* 6419 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 6431
/* 6423 */    MCD_OPC_CheckPredicate, 6, 45, 26, // Skip to: 13128
/* 6427 */    MCD_OPC_Decode, 142, 1, 115, // Opcode: AVE_U_D
/* 6431 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 6443
/* 6435 */    MCD_OPC_CheckPredicate, 6, 33, 26, // Skip to: 13128
/* 6439 */    MCD_OPC_Decode, 129, 1, 112, // Opcode: AVER_S_B
/* 6443 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 6455
/* 6447 */    MCD_OPC_CheckPredicate, 6, 21, 26, // Skip to: 13128
/* 6451 */    MCD_OPC_Decode, 131, 1, 113, // Opcode: AVER_S_H
/* 6455 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 6467
/* 6459 */    MCD_OPC_CheckPredicate, 6, 9, 26, // Skip to: 13128
/* 6463 */    MCD_OPC_Decode, 132, 1, 114, // Opcode: AVER_S_W
/* 6467 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 6479
/* 6471 */    MCD_OPC_CheckPredicate, 6, 253, 25, // Skip to: 13128
/* 6475 */    MCD_OPC_Decode, 130, 1, 115, // Opcode: AVER_S_D
/* 6479 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 6491
/* 6483 */    MCD_OPC_CheckPredicate, 6, 241, 25, // Skip to: 13128
/* 6487 */    MCD_OPC_Decode, 133, 1, 112, // Opcode: AVER_U_B
/* 6491 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 6503
/* 6495 */    MCD_OPC_CheckPredicate, 6, 229, 25, // Skip to: 13128
/* 6499 */    MCD_OPC_Decode, 135, 1, 113, // Opcode: AVER_U_H
/* 6503 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 6515
/* 6507 */    MCD_OPC_CheckPredicate, 6, 217, 25, // Skip to: 13128
/* 6511 */    MCD_OPC_Decode, 136, 1, 114, // Opcode: AVER_U_W
/* 6515 */    MCD_OPC_FilterValue, 31, 209, 25, // Skip to: 13128
/* 6519 */    MCD_OPC_CheckPredicate, 6, 205, 25, // Skip to: 13128
/* 6523 */    MCD_OPC_Decode, 134, 1, 115, // Opcode: AVER_U_D
/* 6527 */    MCD_OPC_FilterValue, 17, 27, 1, // Skip to: 6814
/* 6531 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 6534 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 6546
/* 6538 */    MCD_OPC_CheckPredicate, 6, 186, 25, // Skip to: 13128
/* 6542 */    MCD_OPC_Decode, 239, 11, 112, // Opcode: SUBS_S_B
/* 6546 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 6558
/* 6550 */    MCD_OPC_CheckPredicate, 6, 174, 25, // Skip to: 13128
/* 6554 */    MCD_OPC_Decode, 241, 11, 113, // Opcode: SUBS_S_H
/* 6558 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 6570
/* 6562 */    MCD_OPC_CheckPredicate, 6, 162, 25, // Skip to: 13128
/* 6566 */    MCD_OPC_Decode, 242, 11, 114, // Opcode: SUBS_S_W
/* 6570 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 6582
/* 6574 */    MCD_OPC_CheckPredicate, 6, 150, 25, // Skip to: 13128
/* 6578 */    MCD_OPC_Decode, 240, 11, 115, // Opcode: SUBS_S_D
/* 6582 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 6594
/* 6586 */    MCD_OPC_CheckPredicate, 6, 138, 25, // Skip to: 13128
/* 6590 */    MCD_OPC_Decode, 243, 11, 112, // Opcode: SUBS_U_B
/* 6594 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 6606
/* 6598 */    MCD_OPC_CheckPredicate, 6, 126, 25, // Skip to: 13128
/* 6602 */    MCD_OPC_Decode, 245, 11, 113, // Opcode: SUBS_U_H
/* 6606 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 6618
/* 6610 */    MCD_OPC_CheckPredicate, 6, 114, 25, // Skip to: 13128
/* 6614 */    MCD_OPC_Decode, 246, 11, 114, // Opcode: SUBS_U_W
/* 6618 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 6630
/* 6622 */    MCD_OPC_CheckPredicate, 6, 102, 25, // Skip to: 13128
/* 6626 */    MCD_OPC_Decode, 244, 11, 115, // Opcode: SUBS_U_D
/* 6630 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 6642
/* 6634 */    MCD_OPC_CheckPredicate, 6, 90, 25, // Skip to: 13128
/* 6638 */    MCD_OPC_Decode, 231, 11, 112, // Opcode: SUBSUS_U_B
/* 6642 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 6654
/* 6646 */    MCD_OPC_CheckPredicate, 6, 78, 25, // Skip to: 13128
/* 6650 */    MCD_OPC_Decode, 233, 11, 113, // Opcode: SUBSUS_U_H
/* 6654 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 6666
/* 6658 */    MCD_OPC_CheckPredicate, 6, 66, 25, // Skip to: 13128
/* 6662 */    MCD_OPC_Decode, 234, 11, 114, // Opcode: SUBSUS_U_W
/* 6666 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 6678
/* 6670 */    MCD_OPC_CheckPredicate, 6, 54, 25, // Skip to: 13128
/* 6674 */    MCD_OPC_Decode, 232, 11, 115, // Opcode: SUBSUS_U_D
/* 6678 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 6690
/* 6682 */    MCD_OPC_CheckPredicate, 6, 42, 25, // Skip to: 13128
/* 6686 */    MCD_OPC_Decode, 235, 11, 112, // Opcode: SUBSUU_S_B
/* 6690 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 6702
/* 6694 */    MCD_OPC_CheckPredicate, 6, 30, 25, // Skip to: 13128
/* 6698 */    MCD_OPC_Decode, 237, 11, 113, // Opcode: SUBSUU_S_H
/* 6702 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 6714
/* 6706 */    MCD_OPC_CheckPredicate, 6, 18, 25, // Skip to: 13128
/* 6710 */    MCD_OPC_Decode, 238, 11, 114, // Opcode: SUBSUU_S_W
/* 6714 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 6726
/* 6718 */    MCD_OPC_CheckPredicate, 6, 6, 25, // Skip to: 13128
/* 6722 */    MCD_OPC_Decode, 236, 11, 115, // Opcode: SUBSUU_S_D
/* 6726 */    MCD_OPC_FilterValue, 16, 7, 0, // Skip to: 6737
/* 6730 */    MCD_OPC_CheckPredicate, 6, 250, 24, // Skip to: 13128
/* 6734 */    MCD_OPC_Decode, 87, 112, // Opcode: ASUB_S_B
/* 6737 */    MCD_OPC_FilterValue, 17, 7, 0, // Skip to: 6748
/* 6741 */    MCD_OPC_CheckPredicate, 6, 239, 24, // Skip to: 13128
/* 6745 */    MCD_OPC_Decode, 89, 113, // Opcode: ASUB_S_H
/* 6748 */    MCD_OPC_FilterValue, 18, 7, 0, // Skip to: 6759
/* 6752 */    MCD_OPC_CheckPredicate, 6, 228, 24, // Skip to: 13128
/* 6756 */    MCD_OPC_Decode, 90, 114, // Opcode: ASUB_S_W
/* 6759 */    MCD_OPC_FilterValue, 19, 7, 0, // Skip to: 6770
/* 6763 */    MCD_OPC_CheckPredicate, 6, 217, 24, // Skip to: 13128
/* 6767 */    MCD_OPC_Decode, 88, 115, // Opcode: ASUB_S_D
/* 6770 */    MCD_OPC_FilterValue, 20, 7, 0, // Skip to: 6781
/* 6774 */    MCD_OPC_CheckPredicate, 6, 206, 24, // Skip to: 13128
/* 6778 */    MCD_OPC_Decode, 91, 112, // Opcode: ASUB_U_B
/* 6781 */    MCD_OPC_FilterValue, 21, 7, 0, // Skip to: 6792
/* 6785 */    MCD_OPC_CheckPredicate, 6, 195, 24, // Skip to: 13128
/* 6789 */    MCD_OPC_Decode, 93, 113, // Opcode: ASUB_U_H
/* 6792 */    MCD_OPC_FilterValue, 22, 7, 0, // Skip to: 6803
/* 6796 */    MCD_OPC_CheckPredicate, 6, 184, 24, // Skip to: 13128
/* 6800 */    MCD_OPC_Decode, 94, 114, // Opcode: ASUB_U_W
/* 6803 */    MCD_OPC_FilterValue, 23, 177, 24, // Skip to: 13128
/* 6807 */    MCD_OPC_CheckPredicate, 6, 173, 24, // Skip to: 13128
/* 6811 */    MCD_OPC_Decode, 92, 115, // Opcode: ASUB_U_D
/* 6814 */    MCD_OPC_FilterValue, 18, 83, 1, // Skip to: 7157
/* 6818 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 6821 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 6833
/* 6825 */    MCD_OPC_CheckPredicate, 6, 155, 24, // Skip to: 13128
/* 6829 */    MCD_OPC_Decode, 145, 9, 112, // Opcode: MULV_B
/* 6833 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 6845
/* 6837 */    MCD_OPC_CheckPredicate, 6, 143, 24, // Skip to: 13128
/* 6841 */    MCD_OPC_Decode, 147, 9, 113, // Opcode: MULV_H
/* 6845 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 6857
/* 6849 */    MCD_OPC_CheckPredicate, 6, 131, 24, // Skip to: 13128
/* 6853 */    MCD_OPC_Decode, 148, 9, 114, // Opcode: MULV_W
/* 6857 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 6869
/* 6861 */    MCD_OPC_CheckPredicate, 6, 119, 24, // Skip to: 13128
/* 6865 */    MCD_OPC_Decode, 146, 9, 115, // Opcode: MULV_D
/* 6869 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 6881
/* 6873 */    MCD_OPC_CheckPredicate, 6, 107, 24, // Skip to: 13128
/* 6877 */    MCD_OPC_Decode, 199, 7, 116, // Opcode: MADDV_B
/* 6881 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 6893
/* 6885 */    MCD_OPC_CheckPredicate, 6, 95, 24, // Skip to: 13128
/* 6889 */    MCD_OPC_Decode, 201, 7, 117, // Opcode: MADDV_H
/* 6893 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 6905
/* 6897 */    MCD_OPC_CheckPredicate, 6, 83, 24, // Skip to: 13128
/* 6901 */    MCD_OPC_Decode, 202, 7, 118, // Opcode: MADDV_W
/* 6905 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 6917
/* 6909 */    MCD_OPC_CheckPredicate, 6, 71, 24, // Skip to: 13128
/* 6913 */    MCD_OPC_Decode, 200, 7, 119, // Opcode: MADDV_D
/* 6917 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 6929
/* 6921 */    MCD_OPC_CheckPredicate, 6, 59, 24, // Skip to: 13128
/* 6925 */    MCD_OPC_Decode, 216, 8, 116, // Opcode: MSUBV_B
/* 6929 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 6941
/* 6933 */    MCD_OPC_CheckPredicate, 6, 47, 24, // Skip to: 13128
/* 6937 */    MCD_OPC_Decode, 218, 8, 117, // Opcode: MSUBV_H
/* 6941 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 6953
/* 6945 */    MCD_OPC_CheckPredicate, 6, 35, 24, // Skip to: 13128
/* 6949 */    MCD_OPC_Decode, 219, 8, 118, // Opcode: MSUBV_W
/* 6953 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 6965
/* 6957 */    MCD_OPC_CheckPredicate, 6, 23, 24, // Skip to: 13128
/* 6961 */    MCD_OPC_Decode, 217, 8, 119, // Opcode: MSUBV_D
/* 6965 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 6977
/* 6969 */    MCD_OPC_CheckPredicate, 6, 11, 24, // Skip to: 13128
/* 6973 */    MCD_OPC_Decode, 139, 4, 112, // Opcode: DIV_S_B
/* 6977 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 6989
/* 6981 */    MCD_OPC_CheckPredicate, 6, 255, 23, // Skip to: 13128
/* 6985 */    MCD_OPC_Decode, 141, 4, 113, // Opcode: DIV_S_H
/* 6989 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 7001
/* 6993 */    MCD_OPC_CheckPredicate, 6, 243, 23, // Skip to: 13128
/* 6997 */    MCD_OPC_Decode, 142, 4, 114, // Opcode: DIV_S_W
/* 7001 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 7013
/* 7005 */    MCD_OPC_CheckPredicate, 6, 231, 23, // Skip to: 13128
/* 7009 */    MCD_OPC_Decode, 140, 4, 115, // Opcode: DIV_S_D
/* 7013 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 7025
/* 7017 */    MCD_OPC_CheckPredicate, 6, 219, 23, // Skip to: 13128
/* 7021 */    MCD_OPC_Decode, 143, 4, 112, // Opcode: DIV_U_B
/* 7025 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 7037
/* 7029 */    MCD_OPC_CheckPredicate, 6, 207, 23, // Skip to: 13128
/* 7033 */    MCD_OPC_Decode, 145, 4, 113, // Opcode: DIV_U_H
/* 7037 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 7049
/* 7041 */    MCD_OPC_CheckPredicate, 6, 195, 23, // Skip to: 13128
/* 7045 */    MCD_OPC_Decode, 146, 4, 114, // Opcode: DIV_U_W
/* 7049 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 7061
/* 7053 */    MCD_OPC_CheckPredicate, 6, 183, 23, // Skip to: 13128
/* 7057 */    MCD_OPC_Decode, 144, 4, 115, // Opcode: DIV_U_D
/* 7061 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 7073
/* 7065 */    MCD_OPC_CheckPredicate, 6, 171, 23, // Skip to: 13128
/* 7069 */    MCD_OPC_Decode, 158, 8, 112, // Opcode: MOD_S_B
/* 7073 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 7085
/* 7077 */    MCD_OPC_CheckPredicate, 6, 159, 23, // Skip to: 13128
/* 7081 */    MCD_OPC_Decode, 160, 8, 113, // Opcode: MOD_S_H
/* 7085 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 7097
/* 7089 */    MCD_OPC_CheckPredicate, 6, 147, 23, // Skip to: 13128
/* 7093 */    MCD_OPC_Decode, 161, 8, 114, // Opcode: MOD_S_W
/* 7097 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 7109
/* 7101 */    MCD_OPC_CheckPredicate, 6, 135, 23, // Skip to: 13128
/* 7105 */    MCD_OPC_Decode, 159, 8, 115, // Opcode: MOD_S_D
/* 7109 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 7121
/* 7113 */    MCD_OPC_CheckPredicate, 6, 123, 23, // Skip to: 13128
/* 7117 */    MCD_OPC_Decode, 162, 8, 112, // Opcode: MOD_U_B
/* 7121 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 7133
/* 7125 */    MCD_OPC_CheckPredicate, 6, 111, 23, // Skip to: 13128
/* 7129 */    MCD_OPC_Decode, 164, 8, 113, // Opcode: MOD_U_H
/* 7133 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 7145
/* 7137 */    MCD_OPC_CheckPredicate, 6, 99, 23, // Skip to: 13128
/* 7141 */    MCD_OPC_Decode, 165, 8, 114, // Opcode: MOD_U_W
/* 7145 */    MCD_OPC_FilterValue, 31, 91, 23, // Skip to: 13128
/* 7149 */    MCD_OPC_CheckPredicate, 6, 87, 23, // Skip to: 13128
/* 7153 */    MCD_OPC_Decode, 163, 8, 115, // Opcode: MOD_U_D
/* 7157 */    MCD_OPC_FilterValue, 19, 219, 0, // Skip to: 7380
/* 7161 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 7164 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 7176
/* 7168 */    MCD_OPC_CheckPredicate, 6, 68, 23, // Skip to: 13128
/* 7172 */    MCD_OPC_Decode, 166, 4, 120, // Opcode: DOTP_S_H
/* 7176 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 7188
/* 7180 */    MCD_OPC_CheckPredicate, 6, 56, 23, // Skip to: 13128
/* 7184 */    MCD_OPC_Decode, 167, 4, 121, // Opcode: DOTP_S_W
/* 7188 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 7200
/* 7192 */    MCD_OPC_CheckPredicate, 6, 44, 23, // Skip to: 13128
/* 7196 */    MCD_OPC_Decode, 165, 4, 122, // Opcode: DOTP_S_D
/* 7200 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 7212
/* 7204 */    MCD_OPC_CheckPredicate, 6, 32, 23, // Skip to: 13128
/* 7208 */    MCD_OPC_Decode, 169, 4, 120, // Opcode: DOTP_U_H
/* 7212 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 7224
/* 7216 */    MCD_OPC_CheckPredicate, 6, 20, 23, // Skip to: 13128
/* 7220 */    MCD_OPC_Decode, 170, 4, 121, // Opcode: DOTP_U_W
/* 7224 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 7236
/* 7228 */    MCD_OPC_CheckPredicate, 6, 8, 23, // Skip to: 13128
/* 7232 */    MCD_OPC_Decode, 168, 4, 122, // Opcode: DOTP_U_D
/* 7236 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 7248
/* 7240 */    MCD_OPC_CheckPredicate, 6, 252, 22, // Skip to: 13128
/* 7244 */    MCD_OPC_Decode, 172, 4, 123, // Opcode: DPADD_S_H
/* 7248 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 7260
/* 7252 */    MCD_OPC_CheckPredicate, 6, 240, 22, // Skip to: 13128
/* 7256 */    MCD_OPC_Decode, 173, 4, 124, // Opcode: DPADD_S_W
/* 7260 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 7272
/* 7264 */    MCD_OPC_CheckPredicate, 6, 228, 22, // Skip to: 13128
/* 7268 */    MCD_OPC_Decode, 171, 4, 125, // Opcode: DPADD_S_D
/* 7272 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 7284
/* 7276 */    MCD_OPC_CheckPredicate, 6, 216, 22, // Skip to: 13128
/* 7280 */    MCD_OPC_Decode, 175, 4, 123, // Opcode: DPADD_U_H
/* 7284 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 7296
/* 7288 */    MCD_OPC_CheckPredicate, 6, 204, 22, // Skip to: 13128
/* 7292 */    MCD_OPC_Decode, 176, 4, 124, // Opcode: DPADD_U_W
/* 7296 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 7308
/* 7300 */    MCD_OPC_CheckPredicate, 6, 192, 22, // Skip to: 13128
/* 7304 */    MCD_OPC_Decode, 174, 4, 125, // Opcode: DPADD_U_D
/* 7308 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 7320
/* 7312 */    MCD_OPC_CheckPredicate, 6, 180, 22, // Skip to: 13128
/* 7316 */    MCD_OPC_Decode, 191, 4, 123, // Opcode: DPSUB_S_H
/* 7320 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 7332
/* 7324 */    MCD_OPC_CheckPredicate, 6, 168, 22, // Skip to: 13128
/* 7328 */    MCD_OPC_Decode, 192, 4, 124, // Opcode: DPSUB_S_W
/* 7332 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 7344
/* 7336 */    MCD_OPC_CheckPredicate, 6, 156, 22, // Skip to: 13128
/* 7340 */    MCD_OPC_Decode, 190, 4, 125, // Opcode: DPSUB_S_D
/* 7344 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 7356
/* 7348 */    MCD_OPC_CheckPredicate, 6, 144, 22, // Skip to: 13128
/* 7352 */    MCD_OPC_Decode, 194, 4, 123, // Opcode: DPSUB_U_H
/* 7356 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 7368
/* 7360 */    MCD_OPC_CheckPredicate, 6, 132, 22, // Skip to: 13128
/* 7364 */    MCD_OPC_Decode, 195, 4, 124, // Opcode: DPSUB_U_W
/* 7368 */    MCD_OPC_FilterValue, 23, 124, 22, // Skip to: 13128
/* 7372 */    MCD_OPC_CheckPredicate, 6, 120, 22, // Skip to: 13128
/* 7376 */    MCD_OPC_Decode, 193, 4, 125, // Opcode: DPSUB_U_D
/* 7380 */    MCD_OPC_FilterValue, 20, 137, 1, // Skip to: 7777
/* 7384 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 7387 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 7399
/* 7391 */    MCD_OPC_CheckPredicate, 6, 101, 22, // Skip to: 13128
/* 7395 */    MCD_OPC_Decode, 129, 11, 126, // Opcode: SLD_B
/* 7399 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 7411
/* 7403 */    MCD_OPC_CheckPredicate, 6, 89, 22, // Skip to: 13128
/* 7407 */    MCD_OPC_Decode, 131, 11, 127, // Opcode: SLD_H
/* 7411 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 7424
/* 7415 */    MCD_OPC_CheckPredicate, 6, 77, 22, // Skip to: 13128
/* 7419 */    MCD_OPC_Decode, 132, 11, 128, 1, // Opcode: SLD_W
/* 7424 */    MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 7437
/* 7428 */    MCD_OPC_CheckPredicate, 6, 64, 22, // Skip to: 13128
/* 7432 */    MCD_OPC_Decode, 130, 11, 129, 1, // Opcode: SLD_D
/* 7437 */    MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 7450
/* 7441 */    MCD_OPC_CheckPredicate, 6, 51, 22, // Skip to: 13128
/* 7445 */    MCD_OPC_Decode, 170, 11, 130, 1, // Opcode: SPLAT_B
/* 7450 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 7463
/* 7454 */    MCD_OPC_CheckPredicate, 6, 38, 22, // Skip to: 13128
/* 7458 */    MCD_OPC_Decode, 172, 11, 131, 1, // Opcode: SPLAT_H
/* 7463 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 7476
/* 7467 */    MCD_OPC_CheckPredicate, 6, 25, 22, // Skip to: 13128
/* 7471 */    MCD_OPC_Decode, 173, 11, 132, 1, // Opcode: SPLAT_W
/* 7476 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 7489
/* 7480 */    MCD_OPC_CheckPredicate, 6, 12, 22, // Skip to: 13128
/* 7484 */    MCD_OPC_Decode, 171, 11, 133, 1, // Opcode: SPLAT_D
/* 7489 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 7501
/* 7493 */    MCD_OPC_CheckPredicate, 6, 255, 21, // Skip to: 13128
/* 7497 */    MCD_OPC_Decode, 206, 9, 112, // Opcode: PCKEV_B
/* 7501 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 7513
/* 7505 */    MCD_OPC_CheckPredicate, 6, 243, 21, // Skip to: 13128
/* 7509 */    MCD_OPC_Decode, 208, 9, 113, // Opcode: PCKEV_H
/* 7513 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 7525
/* 7517 */    MCD_OPC_CheckPredicate, 6, 231, 21, // Skip to: 13128
/* 7521 */    MCD_OPC_Decode, 209, 9, 114, // Opcode: PCKEV_W
/* 7525 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 7537
/* 7529 */    MCD_OPC_CheckPredicate, 6, 219, 21, // Skip to: 13128
/* 7533 */    MCD_OPC_Decode, 207, 9, 115, // Opcode: PCKEV_D
/* 7537 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 7549
/* 7541 */    MCD_OPC_CheckPredicate, 6, 207, 21, // Skip to: 13128
/* 7545 */    MCD_OPC_Decode, 210, 9, 112, // Opcode: PCKOD_B
/* 7549 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 7561
/* 7553 */    MCD_OPC_CheckPredicate, 6, 195, 21, // Skip to: 13128
/* 7557 */    MCD_OPC_Decode, 212, 9, 113, // Opcode: PCKOD_H
/* 7561 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 7573
/* 7565 */    MCD_OPC_CheckPredicate, 6, 183, 21, // Skip to: 13128
/* 7569 */    MCD_OPC_Decode, 213, 9, 114, // Opcode: PCKOD_W
/* 7573 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 7585
/* 7577 */    MCD_OPC_CheckPredicate, 6, 171, 21, // Skip to: 13128
/* 7581 */    MCD_OPC_Decode, 211, 9, 115, // Opcode: PCKOD_D
/* 7585 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 7597
/* 7589 */    MCD_OPC_CheckPredicate, 6, 159, 21, // Skip to: 13128
/* 7593 */    MCD_OPC_Decode, 169, 6, 112, // Opcode: ILVL_B
/* 7597 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 7609
/* 7601 */    MCD_OPC_CheckPredicate, 6, 147, 21, // Skip to: 13128
/* 7605 */    MCD_OPC_Decode, 171, 6, 113, // Opcode: ILVL_H
/* 7609 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 7621
/* 7613 */    MCD_OPC_CheckPredicate, 6, 135, 21, // Skip to: 13128
/* 7617 */    MCD_OPC_Decode, 172, 6, 114, // Opcode: ILVL_W
/* 7621 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 7633
/* 7625 */    MCD_OPC_CheckPredicate, 6, 123, 21, // Skip to: 13128
/* 7629 */    MCD_OPC_Decode, 170, 6, 115, // Opcode: ILVL_D
/* 7633 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 7645
/* 7637 */    MCD_OPC_CheckPredicate, 6, 111, 21, // Skip to: 13128
/* 7641 */    MCD_OPC_Decode, 177, 6, 112, // Opcode: ILVR_B
/* 7645 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 7657
/* 7649 */    MCD_OPC_CheckPredicate, 6, 99, 21, // Skip to: 13128
/* 7653 */    MCD_OPC_Decode, 179, 6, 113, // Opcode: ILVR_H
/* 7657 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 7669
/* 7661 */    MCD_OPC_CheckPredicate, 6, 87, 21, // Skip to: 13128
/* 7665 */    MCD_OPC_Decode, 180, 6, 114, // Opcode: ILVR_W
/* 7669 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 7681
/* 7673 */    MCD_OPC_CheckPredicate, 6, 75, 21, // Skip to: 13128
/* 7677 */    MCD_OPC_Decode, 178, 6, 115, // Opcode: ILVR_D
/* 7681 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 7693
/* 7685 */    MCD_OPC_CheckPredicate, 6, 63, 21, // Skip to: 13128
/* 7689 */    MCD_OPC_Decode, 165, 6, 112, // Opcode: ILVEV_B
/* 7693 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 7705
/* 7697 */    MCD_OPC_CheckPredicate, 6, 51, 21, // Skip to: 13128
/* 7701 */    MCD_OPC_Decode, 167, 6, 113, // Opcode: ILVEV_H
/* 7705 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 7717
/* 7709 */    MCD_OPC_CheckPredicate, 6, 39, 21, // Skip to: 13128
/* 7713 */    MCD_OPC_Decode, 168, 6, 114, // Opcode: ILVEV_W
/* 7717 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 7729
/* 7721 */    MCD_OPC_CheckPredicate, 6, 27, 21, // Skip to: 13128
/* 7725 */    MCD_OPC_Decode, 166, 6, 115, // Opcode: ILVEV_D
/* 7729 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 7741
/* 7733 */    MCD_OPC_CheckPredicate, 6, 15, 21, // Skip to: 13128
/* 7737 */    MCD_OPC_Decode, 173, 6, 112, // Opcode: ILVOD_B
/* 7741 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 7753
/* 7745 */    MCD_OPC_CheckPredicate, 6, 3, 21, // Skip to: 13128
/* 7749 */    MCD_OPC_Decode, 175, 6, 113, // Opcode: ILVOD_H
/* 7753 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 7765
/* 7757 */    MCD_OPC_CheckPredicate, 6, 247, 20, // Skip to: 13128
/* 7761 */    MCD_OPC_Decode, 176, 6, 114, // Opcode: ILVOD_W
/* 7765 */    MCD_OPC_FilterValue, 31, 239, 20, // Skip to: 13128
/* 7769 */    MCD_OPC_CheckPredicate, 6, 235, 20, // Skip to: 13128
/* 7773 */    MCD_OPC_Decode, 174, 6, 115, // Opcode: ILVOD_D
/* 7777 */    MCD_OPC_FilterValue, 21, 35, 1, // Skip to: 8072
/* 7781 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 7784 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 7796
/* 7788 */    MCD_OPC_CheckPredicate, 6, 216, 20, // Skip to: 13128
/* 7792 */    MCD_OPC_Decode, 248, 12, 116, // Opcode: VSHF_B
/* 7796 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 7808
/* 7800 */    MCD_OPC_CheckPredicate, 6, 204, 20, // Skip to: 13128
/* 7804 */    MCD_OPC_Decode, 250, 12, 117, // Opcode: VSHF_H
/* 7808 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 7820
/* 7812 */    MCD_OPC_CheckPredicate, 6, 192, 20, // Skip to: 13128
/* 7816 */    MCD_OPC_Decode, 251, 12, 118, // Opcode: VSHF_W
/* 7820 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 7832
/* 7824 */    MCD_OPC_CheckPredicate, 6, 180, 20, // Skip to: 13128
/* 7828 */    MCD_OPC_Decode, 249, 12, 119, // Opcode: VSHF_D
/* 7832 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 7844
/* 7836 */    MCD_OPC_CheckPredicate, 6, 168, 20, // Skip to: 13128
/* 7840 */    MCD_OPC_Decode, 183, 11, 112, // Opcode: SRAR_B
/* 7844 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 7856
/* 7848 */    MCD_OPC_CheckPredicate, 6, 156, 20, // Skip to: 13128
/* 7852 */    MCD_OPC_Decode, 185, 11, 113, // Opcode: SRAR_H
/* 7856 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 7868
/* 7860 */    MCD_OPC_CheckPredicate, 6, 144, 20, // Skip to: 13128
/* 7864 */    MCD_OPC_Decode, 186, 11, 114, // Opcode: SRAR_W
/* 7868 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 7880
/* 7872 */    MCD_OPC_CheckPredicate, 6, 132, 20, // Skip to: 13128
/* 7876 */    MCD_OPC_Decode, 184, 11, 115, // Opcode: SRAR_D
/* 7880 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 7892
/* 7884 */    MCD_OPC_CheckPredicate, 6, 120, 20, // Skip to: 13128
/* 7888 */    MCD_OPC_Decode, 203, 11, 112, // Opcode: SRLR_B
/* 7892 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 7904
/* 7896 */    MCD_OPC_CheckPredicate, 6, 108, 20, // Skip to: 13128
/* 7900 */    MCD_OPC_Decode, 205, 11, 113, // Opcode: SRLR_H
/* 7904 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 7916
/* 7908 */    MCD_OPC_CheckPredicate, 6, 96, 20, // Skip to: 13128
/* 7912 */    MCD_OPC_Decode, 206, 11, 114, // Opcode: SRLR_W
/* 7916 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 7928
/* 7920 */    MCD_OPC_CheckPredicate, 6, 84, 20, // Skip to: 13128
/* 7924 */    MCD_OPC_Decode, 204, 11, 115, // Opcode: SRLR_D
/* 7928 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 7940
/* 7932 */    MCD_OPC_CheckPredicate, 6, 72, 20, // Skip to: 13128
/* 7936 */    MCD_OPC_Decode, 154, 6, 120, // Opcode: HADD_S_H
/* 7940 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 7952
/* 7944 */    MCD_OPC_CheckPredicate, 6, 60, 20, // Skip to: 13128
/* 7948 */    MCD_OPC_Decode, 155, 6, 121, // Opcode: HADD_S_W
/* 7952 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 7964
/* 7956 */    MCD_OPC_CheckPredicate, 6, 48, 20, // Skip to: 13128
/* 7960 */    MCD_OPC_Decode, 153, 6, 122, // Opcode: HADD_S_D
/* 7964 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 7976
/* 7968 */    MCD_OPC_CheckPredicate, 6, 36, 20, // Skip to: 13128
/* 7972 */    MCD_OPC_Decode, 157, 6, 120, // Opcode: HADD_U_H
/* 7976 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 7988
/* 7980 */    MCD_OPC_CheckPredicate, 6, 24, 20, // Skip to: 13128
/* 7984 */    MCD_OPC_Decode, 158, 6, 121, // Opcode: HADD_U_W
/* 7988 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 8000
/* 7992 */    MCD_OPC_CheckPredicate, 6, 12, 20, // Skip to: 13128
/* 7996 */    MCD_OPC_Decode, 156, 6, 122, // Opcode: HADD_U_D
/* 8000 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 8012
/* 8004 */    MCD_OPC_CheckPredicate, 6, 0, 20, // Skip to: 13128
/* 8008 */    MCD_OPC_Decode, 160, 6, 120, // Opcode: HSUB_S_H
/* 8012 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 8024
/* 8016 */    MCD_OPC_CheckPredicate, 6, 244, 19, // Skip to: 13128
/* 8020 */    MCD_OPC_Decode, 161, 6, 121, // Opcode: HSUB_S_W
/* 8024 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 8036
/* 8028 */    MCD_OPC_CheckPredicate, 6, 232, 19, // Skip to: 13128
/* 8032 */    MCD_OPC_Decode, 159, 6, 122, // Opcode: HSUB_S_D
/* 8036 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 8048
/* 8040 */    MCD_OPC_CheckPredicate, 6, 220, 19, // Skip to: 13128
/* 8044 */    MCD_OPC_Decode, 163, 6, 120, // Opcode: HSUB_U_H
/* 8048 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 8060
/* 8052 */    MCD_OPC_CheckPredicate, 6, 208, 19, // Skip to: 13128
/* 8056 */    MCD_OPC_Decode, 164, 6, 121, // Opcode: HSUB_U_W
/* 8060 */    MCD_OPC_FilterValue, 31, 200, 19, // Skip to: 13128
/* 8064 */    MCD_OPC_CheckPredicate, 6, 196, 19, // Skip to: 13128
/* 8068 */    MCD_OPC_Decode, 162, 6, 122, // Opcode: HSUB_U_D
/* 8072 */    MCD_OPC_FilterValue, 25, 230, 1, // Skip to: 8562
/* 8076 */    MCD_OPC_ExtractField, 20, 6,  // Inst{25-20} ...
/* 8079 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8092
/* 8083 */    MCD_OPC_CheckPredicate, 6, 177, 19, // Skip to: 13128
/* 8087 */    MCD_OPC_Decode, 253, 10, 134, 1, // Opcode: SLDI_B
/* 8092 */    MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 8111
/* 8096 */    MCD_OPC_CheckPredicate, 6, 164, 19, // Skip to: 13128
/* 8100 */    MCD_OPC_CheckField, 19, 1, 0, 158, 19, // Skip to: 13128
/* 8106 */    MCD_OPC_Decode, 255, 10, 135, 1, // Opcode: SLDI_H
/* 8111 */    MCD_OPC_FilterValue, 3, 54, 0, // Skip to: 8169
/* 8115 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 8118 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8131
/* 8122 */    MCD_OPC_CheckPredicate, 6, 138, 19, // Skip to: 13128
/* 8126 */    MCD_OPC_Decode, 128, 11, 136, 1, // Opcode: SLDI_W
/* 8131 */    MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 8150
/* 8135 */    MCD_OPC_CheckPredicate, 6, 125, 19, // Skip to: 13128
/* 8139 */    MCD_OPC_CheckField, 17, 1, 0, 119, 19, // Skip to: 13128
/* 8145 */    MCD_OPC_Decode, 254, 10, 137, 1, // Opcode: SLDI_D
/* 8150 */    MCD_OPC_FilterValue, 3, 110, 19, // Skip to: 13128
/* 8154 */    MCD_OPC_CheckPredicate, 6, 106, 19, // Skip to: 13128
/* 8158 */    MCD_OPC_CheckField, 16, 2, 2, 100, 19, // Skip to: 13128
/* 8164 */    MCD_OPC_Decode, 166, 3, 138, 1, // Opcode: CTCMSA
/* 8169 */    MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 8182
/* 8173 */    MCD_OPC_CheckPredicate, 6, 87, 19, // Skip to: 13128
/* 8177 */    MCD_OPC_Decode, 166, 11, 139, 1, // Opcode: SPLATI_B
/* 8182 */    MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 8201
/* 8186 */    MCD_OPC_CheckPredicate, 6, 74, 19, // Skip to: 13128
/* 8190 */    MCD_OPC_CheckField, 19, 1, 0, 68, 19, // Skip to: 13128
/* 8196 */    MCD_OPC_Decode, 168, 11, 140, 1, // Opcode: SPLATI_H
/* 8201 */    MCD_OPC_FilterValue, 7, 54, 0, // Skip to: 8259
/* 8205 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 8208 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8221
/* 8212 */    MCD_OPC_CheckPredicate, 6, 48, 19, // Skip to: 13128
/* 8216 */    MCD_OPC_Decode, 169, 11, 141, 1, // Opcode: SPLATI_W
/* 8221 */    MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 8240
/* 8225 */    MCD_OPC_CheckPredicate, 6, 35, 19, // Skip to: 13128
/* 8229 */    MCD_OPC_CheckField, 17, 1, 0, 29, 19, // Skip to: 13128
/* 8235 */    MCD_OPC_Decode, 167, 11, 142, 1, // Opcode: SPLATI_D
/* 8240 */    MCD_OPC_FilterValue, 3, 20, 19, // Skip to: 13128
/* 8244 */    MCD_OPC_CheckPredicate, 6, 16, 19, // Skip to: 13128
/* 8248 */    MCD_OPC_CheckField, 16, 2, 2, 10, 19, // Skip to: 13128
/* 8254 */    MCD_OPC_Decode, 194, 2, 143, 1, // Opcode: CFCMSA
/* 8259 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 8272
/* 8263 */    MCD_OPC_CheckPredicate, 6, 253, 18, // Skip to: 13128
/* 8267 */    MCD_OPC_Decode, 156, 3, 144, 1, // Opcode: COPY_S_B
/* 8272 */    MCD_OPC_FilterValue, 10, 15, 0, // Skip to: 8291
/* 8276 */    MCD_OPC_CheckPredicate, 6, 240, 18, // Skip to: 13128
/* 8280 */    MCD_OPC_CheckField, 19, 1, 0, 234, 18, // Skip to: 13128
/* 8286 */    MCD_OPC_Decode, 158, 3, 145, 1, // Opcode: COPY_S_H
/* 8291 */    MCD_OPC_FilterValue, 11, 54, 0, // Skip to: 8349
/* 8295 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 8298 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8311
/* 8302 */    MCD_OPC_CheckPredicate, 6, 214, 18, // Skip to: 13128
/* 8306 */    MCD_OPC_Decode, 159, 3, 146, 1, // Opcode: COPY_S_W
/* 8311 */    MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 8330
/* 8315 */    MCD_OPC_CheckPredicate, 13, 201, 18, // Skip to: 13128
/* 8319 */    MCD_OPC_CheckField, 17, 1, 0, 195, 18, // Skip to: 13128
/* 8325 */    MCD_OPC_Decode, 157, 3, 147, 1, // Opcode: COPY_S_D
/* 8330 */    MCD_OPC_FilterValue, 3, 186, 18, // Skip to: 13128
/* 8334 */    MCD_OPC_CheckPredicate, 6, 182, 18, // Skip to: 13128
/* 8338 */    MCD_OPC_CheckField, 16, 2, 2, 176, 18, // Skip to: 13128
/* 8344 */    MCD_OPC_Decode, 167, 8, 148, 1, // Opcode: MOVE_V
/* 8349 */    MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 8362
/* 8353 */    MCD_OPC_CheckPredicate, 6, 163, 18, // Skip to: 13128
/* 8357 */    MCD_OPC_Decode, 160, 3, 144, 1, // Opcode: COPY_U_B
/* 8362 */    MCD_OPC_FilterValue, 14, 15, 0, // Skip to: 8381
/* 8366 */    MCD_OPC_CheckPredicate, 6, 150, 18, // Skip to: 13128
/* 8370 */    MCD_OPC_CheckField, 19, 1, 0, 144, 18, // Skip to: 13128
/* 8376 */    MCD_OPC_Decode, 162, 3, 145, 1, // Opcode: COPY_U_H
/* 8381 */    MCD_OPC_FilterValue, 15, 35, 0, // Skip to: 8420
/* 8385 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 8388 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8401
/* 8392 */    MCD_OPC_CheckPredicate, 6, 124, 18, // Skip to: 13128
/* 8396 */    MCD_OPC_Decode, 163, 3, 146, 1, // Opcode: COPY_U_W
/* 8401 */    MCD_OPC_FilterValue, 2, 115, 18, // Skip to: 13128
/* 8405 */    MCD_OPC_CheckPredicate, 13, 111, 18, // Skip to: 13128
/* 8409 */    MCD_OPC_CheckField, 17, 1, 0, 105, 18, // Skip to: 13128
/* 8415 */    MCD_OPC_Decode, 161, 3, 147, 1, // Opcode: COPY_U_D
/* 8420 */    MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 8433
/* 8424 */    MCD_OPC_CheckPredicate, 6, 92, 18, // Skip to: 13128
/* 8428 */    MCD_OPC_Decode, 182, 6, 149, 1, // Opcode: INSERT_B
/* 8433 */    MCD_OPC_FilterValue, 18, 15, 0, // Skip to: 8452
/* 8437 */    MCD_OPC_CheckPredicate, 6, 79, 18, // Skip to: 13128
/* 8441 */    MCD_OPC_CheckField, 19, 1, 0, 73, 18, // Skip to: 13128
/* 8447 */    MCD_OPC_Decode, 190, 6, 150, 1, // Opcode: INSERT_H
/* 8452 */    MCD_OPC_FilterValue, 19, 35, 0, // Skip to: 8491
/* 8456 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 8459 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8472
/* 8463 */    MCD_OPC_CheckPredicate, 6, 53, 18, // Skip to: 13128
/* 8467 */    MCD_OPC_Decode, 192, 6, 151, 1, // Opcode: INSERT_W
/* 8472 */    MCD_OPC_FilterValue, 2, 44, 18, // Skip to: 13128
/* 8476 */    MCD_OPC_CheckPredicate, 13, 40, 18, // Skip to: 13128
/* 8480 */    MCD_OPC_CheckField, 17, 1, 0, 34, 18, // Skip to: 13128
/* 8486 */    MCD_OPC_Decode, 184, 6, 152, 1, // Opcode: INSERT_D
/* 8491 */    MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 8504
/* 8495 */    MCD_OPC_CheckPredicate, 6, 21, 18, // Skip to: 13128
/* 8499 */    MCD_OPC_Decode, 195, 6, 153, 1, // Opcode: INSVE_B
/* 8504 */    MCD_OPC_FilterValue, 22, 15, 0, // Skip to: 8523
/* 8508 */    MCD_OPC_CheckPredicate, 6, 8, 18, // Skip to: 13128
/* 8512 */    MCD_OPC_CheckField, 19, 1, 0, 2, 18, // Skip to: 13128
/* 8518 */    MCD_OPC_Decode, 197, 6, 153, 1, // Opcode: INSVE_H
/* 8523 */    MCD_OPC_FilterValue, 23, 249, 17, // Skip to: 13128
/* 8527 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 8530 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8543
/* 8534 */    MCD_OPC_CheckPredicate, 6, 238, 17, // Skip to: 13128
/* 8538 */    MCD_OPC_Decode, 198, 6, 153, 1, // Opcode: INSVE_W
/* 8543 */    MCD_OPC_FilterValue, 2, 229, 17, // Skip to: 13128
/* 8547 */    MCD_OPC_CheckPredicate, 6, 225, 17, // Skip to: 13128
/* 8551 */    MCD_OPC_CheckField, 17, 1, 0, 219, 17, // Skip to: 13128
/* 8557 */    MCD_OPC_Decode, 196, 6, 153, 1, // Opcode: INSVE_D
/* 8562 */    MCD_OPC_FilterValue, 26, 131, 1, // Skip to: 8953
/* 8566 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 8569 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 8581
/* 8573 */    MCD_OPC_CheckPredicate, 6, 199, 17, // Skip to: 13128
/* 8577 */    MCD_OPC_Decode, 131, 5, 114, // Opcode: FCAF_W
/* 8581 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 8593
/* 8585 */    MCD_OPC_CheckPredicate, 6, 187, 17, // Skip to: 13128
/* 8589 */    MCD_OPC_Decode, 130, 5, 115, // Opcode: FCAF_D
/* 8593 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 8605
/* 8597 */    MCD_OPC_CheckPredicate, 6, 175, 17, // Skip to: 13128
/* 8601 */    MCD_OPC_Decode, 158, 5, 114, // Opcode: FCUN_W
/* 8605 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 8617
/* 8609 */    MCD_OPC_CheckPredicate, 6, 163, 17, // Skip to: 13128
/* 8613 */    MCD_OPC_Decode, 157, 5, 115, // Opcode: FCUN_D
/* 8617 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 8629
/* 8621 */    MCD_OPC_CheckPredicate, 6, 151, 17, // Skip to: 13128
/* 8625 */    MCD_OPC_Decode, 133, 5, 114, // Opcode: FCEQ_W
/* 8629 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 8641
/* 8633 */    MCD_OPC_CheckPredicate, 6, 139, 17, // Skip to: 13128
/* 8637 */    MCD_OPC_Decode, 132, 5, 115, // Opcode: FCEQ_D
/* 8641 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 8653
/* 8645 */    MCD_OPC_CheckPredicate, 6, 127, 17, // Skip to: 13128
/* 8649 */    MCD_OPC_Decode, 150, 5, 114, // Opcode: FCUEQ_W
/* 8653 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 8665
/* 8657 */    MCD_OPC_CheckPredicate, 6, 115, 17, // Skip to: 13128
/* 8661 */    MCD_OPC_Decode, 149, 5, 115, // Opcode: FCUEQ_D
/* 8665 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 8677
/* 8669 */    MCD_OPC_CheckPredicate, 6, 103, 17, // Skip to: 13128
/* 8673 */    MCD_OPC_Decode, 139, 5, 114, // Opcode: FCLT_W
/* 8677 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 8689
/* 8681 */    MCD_OPC_CheckPredicate, 6, 91, 17, // Skip to: 13128
/* 8685 */    MCD_OPC_Decode, 138, 5, 115, // Opcode: FCLT_D
/* 8689 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 8701
/* 8693 */    MCD_OPC_CheckPredicate, 6, 79, 17, // Skip to: 13128
/* 8697 */    MCD_OPC_Decode, 154, 5, 114, // Opcode: FCULT_W
/* 8701 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 8713
/* 8705 */    MCD_OPC_CheckPredicate, 6, 67, 17, // Skip to: 13128
/* 8709 */    MCD_OPC_Decode, 153, 5, 115, // Opcode: FCULT_D
/* 8713 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 8725
/* 8717 */    MCD_OPC_CheckPredicate, 6, 55, 17, // Skip to: 13128
/* 8721 */    MCD_OPC_Decode, 137, 5, 114, // Opcode: FCLE_W
/* 8725 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 8737
/* 8729 */    MCD_OPC_CheckPredicate, 6, 43, 17, // Skip to: 13128
/* 8733 */    MCD_OPC_Decode, 136, 5, 115, // Opcode: FCLE_D
/* 8737 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 8749
/* 8741 */    MCD_OPC_CheckPredicate, 6, 31, 17, // Skip to: 13128
/* 8745 */    MCD_OPC_Decode, 152, 5, 114, // Opcode: FCULE_W
/* 8749 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 8761
/* 8753 */    MCD_OPC_CheckPredicate, 6, 19, 17, // Skip to: 13128
/* 8757 */    MCD_OPC_Decode, 151, 5, 115, // Opcode: FCULE_D
/* 8761 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 8773
/* 8765 */    MCD_OPC_CheckPredicate, 6, 7, 17, // Skip to: 13128
/* 8769 */    MCD_OPC_Decode, 235, 5, 114, // Opcode: FSAF_W
/* 8773 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 8785
/* 8777 */    MCD_OPC_CheckPredicate, 6, 251, 16, // Skip to: 13128
/* 8781 */    MCD_OPC_Decode, 234, 5, 115, // Opcode: FSAF_D
/* 8785 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 8797
/* 8789 */    MCD_OPC_CheckPredicate, 6, 239, 16, // Skip to: 13128
/* 8793 */    MCD_OPC_Decode, 141, 6, 114, // Opcode: FSUN_W
/* 8797 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 8809
/* 8801 */    MCD_OPC_CheckPredicate, 6, 227, 16, // Skip to: 13128
/* 8805 */    MCD_OPC_Decode, 140, 6, 115, // Opcode: FSUN_D
/* 8809 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 8821
/* 8813 */    MCD_OPC_CheckPredicate, 6, 215, 16, // Skip to: 13128
/* 8817 */    MCD_OPC_Decode, 237, 5, 114, // Opcode: FSEQ_W
/* 8821 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 8833
/* 8825 */    MCD_OPC_CheckPredicate, 6, 203, 16, // Skip to: 13128
/* 8829 */    MCD_OPC_Decode, 236, 5, 115, // Opcode: FSEQ_D
/* 8833 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 8845
/* 8837 */    MCD_OPC_CheckPredicate, 6, 191, 16, // Skip to: 13128
/* 8841 */    MCD_OPC_Decode, 133, 6, 114, // Opcode: FSUEQ_W
/* 8845 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 8857
/* 8849 */    MCD_OPC_CheckPredicate, 6, 179, 16, // Skip to: 13128
/* 8853 */    MCD_OPC_Decode, 132, 6, 115, // Opcode: FSUEQ_D
/* 8857 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 8869
/* 8861 */    MCD_OPC_CheckPredicate, 6, 167, 16, // Skip to: 13128
/* 8865 */    MCD_OPC_Decode, 241, 5, 114, // Opcode: FSLT_W
/* 8869 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 8881
/* 8873 */    MCD_OPC_CheckPredicate, 6, 155, 16, // Skip to: 13128
/* 8877 */    MCD_OPC_Decode, 240, 5, 115, // Opcode: FSLT_D
/* 8881 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 8893
/* 8885 */    MCD_OPC_CheckPredicate, 6, 143, 16, // Skip to: 13128
/* 8889 */    MCD_OPC_Decode, 137, 6, 114, // Opcode: FSULT_W
/* 8893 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 8905
/* 8897 */    MCD_OPC_CheckPredicate, 6, 131, 16, // Skip to: 13128
/* 8901 */    MCD_OPC_Decode, 136, 6, 115, // Opcode: FSULT_D
/* 8905 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 8917
/* 8909 */    MCD_OPC_CheckPredicate, 6, 119, 16, // Skip to: 13128
/* 8913 */    MCD_OPC_Decode, 239, 5, 114, // Opcode: FSLE_W
/* 8917 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 8929
/* 8921 */    MCD_OPC_CheckPredicate, 6, 107, 16, // Skip to: 13128
/* 8925 */    MCD_OPC_Decode, 238, 5, 115, // Opcode: FSLE_D
/* 8929 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 8941
/* 8933 */    MCD_OPC_CheckPredicate, 6, 95, 16, // Skip to: 13128
/* 8937 */    MCD_OPC_Decode, 135, 6, 114, // Opcode: FSULE_W
/* 8941 */    MCD_OPC_FilterValue, 31, 87, 16, // Skip to: 13128
/* 8945 */    MCD_OPC_CheckPredicate, 6, 83, 16, // Skip to: 13128
/* 8949 */    MCD_OPC_Decode, 134, 6, 115, // Opcode: FSULE_D
/* 8953 */    MCD_OPC_FilterValue, 27, 63, 1, // Skip to: 9276
/* 8957 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 8960 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 8972
/* 8964 */    MCD_OPC_CheckPredicate, 6, 64, 16, // Skip to: 13128
/* 8968 */    MCD_OPC_Decode, 129, 5, 114, // Opcode: FADD_W
/* 8972 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 8984
/* 8976 */    MCD_OPC_CheckPredicate, 6, 52, 16, // Skip to: 13128
/* 8980 */    MCD_OPC_Decode, 251, 4, 115, // Opcode: FADD_D
/* 8984 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 8996
/* 8988 */    MCD_OPC_CheckPredicate, 6, 40, 16, // Skip to: 13128
/* 8992 */    MCD_OPC_Decode, 131, 6, 114, // Opcode: FSUB_W
/* 8996 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 9008
/* 9000 */    MCD_OPC_CheckPredicate, 6, 28, 16, // Skip to: 13128
/* 9004 */    MCD_OPC_Decode, 253, 5, 115, // Opcode: FSUB_D
/* 9008 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 9020
/* 9012 */    MCD_OPC_CheckPredicate, 6, 16, 16, // Skip to: 13128
/* 9016 */    MCD_OPC_Decode, 222, 5, 114, // Opcode: FMUL_W
/* 9020 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 9032
/* 9024 */    MCD_OPC_CheckPredicate, 6, 4, 16, // Skip to: 13128
/* 9028 */    MCD_OPC_Decode, 216, 5, 115, // Opcode: FMUL_D
/* 9032 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 9044
/* 9036 */    MCD_OPC_CheckPredicate, 6, 248, 15, // Skip to: 13128
/* 9040 */    MCD_OPC_Decode, 165, 5, 114, // Opcode: FDIV_W
/* 9044 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 9056
/* 9048 */    MCD_OPC_CheckPredicate, 6, 236, 15, // Skip to: 13128
/* 9052 */    MCD_OPC_Decode, 159, 5, 115, // Opcode: FDIV_D
/* 9056 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 9068
/* 9060 */    MCD_OPC_CheckPredicate, 6, 224, 15, // Skip to: 13128
/* 9064 */    MCD_OPC_Decode, 200, 5, 118, // Opcode: FMADD_W
/* 9068 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 9080
/* 9072 */    MCD_OPC_CheckPredicate, 6, 212, 15, // Skip to: 13128
/* 9076 */    MCD_OPC_Decode, 199, 5, 119, // Opcode: FMADD_D
/* 9080 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 9092
/* 9084 */    MCD_OPC_CheckPredicate, 6, 200, 15, // Skip to: 13128
/* 9088 */    MCD_OPC_Decode, 215, 5, 118, // Opcode: FMSUB_W
/* 9092 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 9104
/* 9096 */    MCD_OPC_CheckPredicate, 6, 188, 15, // Skip to: 13128
/* 9100 */    MCD_OPC_Decode, 214, 5, 119, // Opcode: FMSUB_D
/* 9104 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 9116
/* 9108 */    MCD_OPC_CheckPredicate, 6, 176, 15, // Skip to: 13128
/* 9112 */    MCD_OPC_Decode, 170, 5, 114, // Opcode: FEXP2_W
/* 9116 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 9128
/* 9120 */    MCD_OPC_CheckPredicate, 6, 164, 15, // Skip to: 13128
/* 9124 */    MCD_OPC_Decode, 168, 5, 115, // Opcode: FEXP2_D
/* 9128 */    MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 9141
/* 9132 */    MCD_OPC_CheckPredicate, 6, 152, 15, // Skip to: 13128
/* 9136 */    MCD_OPC_Decode, 166, 5, 154, 1, // Opcode: FEXDO_H
/* 9141 */    MCD_OPC_FilterValue, 17, 9, 0, // Skip to: 9154
/* 9145 */    MCD_OPC_CheckPredicate, 6, 139, 15, // Skip to: 13128
/* 9149 */    MCD_OPC_Decode, 167, 5, 155, 1, // Opcode: FEXDO_W
/* 9154 */    MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 9167
/* 9158 */    MCD_OPC_CheckPredicate, 6, 126, 15, // Skip to: 13128
/* 9162 */    MCD_OPC_Decode, 146, 6, 154, 1, // Opcode: FTQ_H
/* 9167 */    MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 9180
/* 9171 */    MCD_OPC_CheckPredicate, 6, 113, 15, // Skip to: 13128
/* 9175 */    MCD_OPC_Decode, 147, 6, 155, 1, // Opcode: FTQ_W
/* 9180 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 9192
/* 9184 */    MCD_OPC_CheckPredicate, 6, 100, 15, // Skip to: 13128
/* 9188 */    MCD_OPC_Decode, 208, 5, 114, // Opcode: FMIN_W
/* 9192 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 9204
/* 9196 */    MCD_OPC_CheckPredicate, 6, 88, 15, // Skip to: 13128
/* 9200 */    MCD_OPC_Decode, 207, 5, 115, // Opcode: FMIN_D
/* 9204 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 9216
/* 9208 */    MCD_OPC_CheckPredicate, 6, 76, 15, // Skip to: 13128
/* 9212 */    MCD_OPC_Decode, 206, 5, 114, // Opcode: FMIN_A_W
/* 9216 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 9228
/* 9220 */    MCD_OPC_CheckPredicate, 6, 64, 15, // Skip to: 13128
/* 9224 */    MCD_OPC_Decode, 205, 5, 115, // Opcode: FMIN_A_D
/* 9228 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 9240
/* 9232 */    MCD_OPC_CheckPredicate, 6, 52, 15, // Skip to: 13128
/* 9236 */    MCD_OPC_Decode, 204, 5, 114, // Opcode: FMAX_W
/* 9240 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 9252
/* 9244 */    MCD_OPC_CheckPredicate, 6, 40, 15, // Skip to: 13128
/* 9248 */    MCD_OPC_Decode, 203, 5, 115, // Opcode: FMAX_D
/* 9252 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 9264
/* 9256 */    MCD_OPC_CheckPredicate, 6, 28, 15, // Skip to: 13128
/* 9260 */    MCD_OPC_Decode, 202, 5, 114, // Opcode: FMAX_A_W
/* 9264 */    MCD_OPC_FilterValue, 31, 20, 15, // Skip to: 13128
/* 9268 */    MCD_OPC_CheckPredicate, 6, 16, 15, // Skip to: 13128
/* 9272 */    MCD_OPC_Decode, 201, 5, 115, // Opcode: FMAX_A_D
/* 9276 */    MCD_OPC_FilterValue, 28, 35, 1, // Skip to: 9571
/* 9280 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 9283 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 9295
/* 9287 */    MCD_OPC_CheckPredicate, 6, 253, 14, // Skip to: 13128
/* 9291 */    MCD_OPC_Decode, 148, 5, 114, // Opcode: FCOR_W
/* 9295 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 9307
/* 9299 */    MCD_OPC_CheckPredicate, 6, 241, 14, // Skip to: 13128
/* 9303 */    MCD_OPC_Decode, 147, 5, 115, // Opcode: FCOR_D
/* 9307 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 9319
/* 9311 */    MCD_OPC_CheckPredicate, 6, 229, 14, // Skip to: 13128
/* 9315 */    MCD_OPC_Decode, 156, 5, 114, // Opcode: FCUNE_W
/* 9319 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 9331
/* 9323 */    MCD_OPC_CheckPredicate, 6, 217, 14, // Skip to: 13128
/* 9327 */    MCD_OPC_Decode, 155, 5, 115, // Opcode: FCUNE_D
/* 9331 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 9343
/* 9335 */    MCD_OPC_CheckPredicate, 6, 205, 14, // Skip to: 13128
/* 9339 */    MCD_OPC_Decode, 146, 5, 114, // Opcode: FCNE_W
/* 9343 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 9355
/* 9347 */    MCD_OPC_CheckPredicate, 6, 193, 14, // Skip to: 13128
/* 9351 */    MCD_OPC_Decode, 145, 5, 115, // Opcode: FCNE_D
/* 9355 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 9367
/* 9359 */    MCD_OPC_CheckPredicate, 6, 181, 14, // Skip to: 13128
/* 9363 */    MCD_OPC_Decode, 151, 9, 113, // Opcode: MUL_Q_H
/* 9367 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 9379
/* 9371 */    MCD_OPC_CheckPredicate, 6, 169, 14, // Skip to: 13128
/* 9375 */    MCD_OPC_Decode, 152, 9, 114, // Opcode: MUL_Q_W
/* 9379 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 9391
/* 9383 */    MCD_OPC_CheckPredicate, 6, 157, 14, // Skip to: 13128
/* 9387 */    MCD_OPC_Decode, 208, 7, 117, // Opcode: MADD_Q_H
/* 9391 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 9403
/* 9395 */    MCD_OPC_CheckPredicate, 6, 145, 14, // Skip to: 13128
/* 9399 */    MCD_OPC_Decode, 209, 7, 118, // Opcode: MADD_Q_W
/* 9403 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 9415
/* 9407 */    MCD_OPC_CheckPredicate, 6, 133, 14, // Skip to: 13128
/* 9411 */    MCD_OPC_Decode, 225, 8, 117, // Opcode: MSUB_Q_H
/* 9415 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 9427
/* 9419 */    MCD_OPC_CheckPredicate, 6, 121, 14, // Skip to: 13128
/* 9423 */    MCD_OPC_Decode, 226, 8, 118, // Opcode: MSUB_Q_W
/* 9427 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 9439
/* 9431 */    MCD_OPC_CheckPredicate, 6, 109, 14, // Skip to: 13128
/* 9435 */    MCD_OPC_Decode, 245, 5, 114, // Opcode: FSOR_W
/* 9439 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 9451
/* 9443 */    MCD_OPC_CheckPredicate, 6, 97, 14, // Skip to: 13128
/* 9447 */    MCD_OPC_Decode, 244, 5, 115, // Opcode: FSOR_D
/* 9451 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 9463
/* 9455 */    MCD_OPC_CheckPredicate, 6, 85, 14, // Skip to: 13128
/* 9459 */    MCD_OPC_Decode, 139, 6, 114, // Opcode: FSUNE_W
/* 9463 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 9475
/* 9467 */    MCD_OPC_CheckPredicate, 6, 73, 14, // Skip to: 13128
/* 9471 */    MCD_OPC_Decode, 138, 6, 115, // Opcode: FSUNE_D
/* 9475 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 9487
/* 9479 */    MCD_OPC_CheckPredicate, 6, 61, 14, // Skip to: 13128
/* 9483 */    MCD_OPC_Decode, 243, 5, 114, // Opcode: FSNE_W
/* 9487 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 9499
/* 9491 */    MCD_OPC_CheckPredicate, 6, 49, 14, // Skip to: 13128
/* 9495 */    MCD_OPC_Decode, 242, 5, 115, // Opcode: FSNE_D
/* 9499 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 9511
/* 9503 */    MCD_OPC_CheckPredicate, 6, 37, 14, // Skip to: 13128
/* 9507 */    MCD_OPC_Decode, 134, 9, 113, // Opcode: MULR_Q_H
/* 9511 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 9523
/* 9515 */    MCD_OPC_CheckPredicate, 6, 25, 14, // Skip to: 13128
/* 9519 */    MCD_OPC_Decode, 135, 9, 114, // Opcode: MULR_Q_W
/* 9523 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 9535
/* 9527 */    MCD_OPC_CheckPredicate, 6, 13, 14, // Skip to: 13128
/* 9531 */    MCD_OPC_Decode, 194, 7, 117, // Opcode: MADDR_Q_H
/* 9535 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 9547
/* 9539 */    MCD_OPC_CheckPredicate, 6, 1, 14, // Skip to: 13128
/* 9543 */    MCD_OPC_Decode, 195, 7, 118, // Opcode: MADDR_Q_W
/* 9547 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 9559
/* 9551 */    MCD_OPC_CheckPredicate, 6, 245, 13, // Skip to: 13128
/* 9555 */    MCD_OPC_Decode, 211, 8, 117, // Opcode: MSUBR_Q_H
/* 9559 */    MCD_OPC_FilterValue, 29, 237, 13, // Skip to: 13128
/* 9563 */    MCD_OPC_CheckPredicate, 6, 233, 13, // Skip to: 13128
/* 9567 */    MCD_OPC_Decode, 212, 8, 118, // Opcode: MSUBR_Q_W
/* 9571 */    MCD_OPC_FilterValue, 30, 212, 2, // Skip to: 10299
/* 9575 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 9578 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 9589
/* 9582 */    MCD_OPC_CheckPredicate, 6, 214, 13, // Skip to: 13128
/* 9586 */    MCD_OPC_Decode, 79, 112, // Opcode: AND_V
/* 9589 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 9601
/* 9593 */    MCD_OPC_CheckPredicate, 6, 203, 13, // Skip to: 13128
/* 9597 */    MCD_OPC_Decode, 196, 9, 112, // Opcode: OR_V
/* 9601 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 9613
/* 9605 */    MCD_OPC_CheckPredicate, 6, 191, 13, // Skip to: 13128
/* 9609 */    MCD_OPC_Decode, 186, 9, 112, // Opcode: NOR_V
/* 9613 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 9625
/* 9617 */    MCD_OPC_CheckPredicate, 6, 179, 13, // Skip to: 13128
/* 9621 */    MCD_OPC_Decode, 133, 13, 112, // Opcode: XOR_V
/* 9625 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 9637
/* 9629 */    MCD_OPC_CheckPredicate, 6, 167, 13, // Skip to: 13128
/* 9633 */    MCD_OPC_Decode, 230, 1, 116, // Opcode: BMNZ_V
/* 9637 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 9649
/* 9641 */    MCD_OPC_CheckPredicate, 6, 155, 13, // Skip to: 13128
/* 9645 */    MCD_OPC_Decode, 232, 1, 116, // Opcode: BMZ_V
/* 9649 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 9661
/* 9653 */    MCD_OPC_CheckPredicate, 6, 143, 13, // Skip to: 13128
/* 9657 */    MCD_OPC_Decode, 135, 2, 116, // Opcode: BSEL_V
/* 9661 */    MCD_OPC_FilterValue, 24, 211, 0, // Skip to: 9876
/* 9665 */    MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 9668 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 9681
/* 9672 */    MCD_OPC_CheckPredicate, 6, 124, 13, // Skip to: 13128
/* 9676 */    MCD_OPC_Decode, 184, 5, 156, 1, // Opcode: FILL_B
/* 9681 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 9694
/* 9685 */    MCD_OPC_CheckPredicate, 6, 111, 13, // Skip to: 13128
/* 9689 */    MCD_OPC_Decode, 188, 5, 157, 1, // Opcode: FILL_H
/* 9694 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 9707
/* 9698 */    MCD_OPC_CheckPredicate, 6, 98, 13, // Skip to: 13128
/* 9702 */    MCD_OPC_Decode, 189, 5, 158, 1, // Opcode: FILL_W
/* 9707 */    MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 9720
/* 9711 */    MCD_OPC_CheckPredicate, 13, 85, 13, // Skip to: 13128
/* 9715 */    MCD_OPC_Decode, 185, 5, 159, 1, // Opcode: FILL_D
/* 9720 */    MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 9733
/* 9724 */    MCD_OPC_CheckPredicate, 6, 72, 13, // Skip to: 13128
/* 9728 */    MCD_OPC_Decode, 214, 9, 148, 1, // Opcode: PCNT_B
/* 9733 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 9746
/* 9737 */    MCD_OPC_CheckPredicate, 6, 59, 13, // Skip to: 13128
/* 9741 */    MCD_OPC_Decode, 216, 9, 160, 1, // Opcode: PCNT_H
/* 9746 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 9759
/* 9750 */    MCD_OPC_CheckPredicate, 6, 46, 13, // Skip to: 13128
/* 9754 */    MCD_OPC_Decode, 217, 9, 161, 1, // Opcode: PCNT_W
/* 9759 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 9772
/* 9763 */    MCD_OPC_CheckPredicate, 6, 33, 13, // Skip to: 13128
/* 9767 */    MCD_OPC_Decode, 215, 9, 162, 1, // Opcode: PCNT_D
/* 9772 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 9785
/* 9776 */    MCD_OPC_CheckPredicate, 6, 20, 13, // Skip to: 13128
/* 9780 */    MCD_OPC_Decode, 163, 9, 148, 1, // Opcode: NLOC_B
/* 9785 */    MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 9798
/* 9789 */    MCD_OPC_CheckPredicate, 6, 7, 13, // Skip to: 13128
/* 9793 */    MCD_OPC_Decode, 165, 9, 160, 1, // Opcode: NLOC_H
/* 9798 */    MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 9811
/* 9802 */    MCD_OPC_CheckPredicate, 6, 250, 12, // Skip to: 13128
/* 9806 */    MCD_OPC_Decode, 166, 9, 161, 1, // Opcode: NLOC_W
/* 9811 */    MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 9824
/* 9815 */    MCD_OPC_CheckPredicate, 6, 237, 12, // Skip to: 13128
/* 9819 */    MCD_OPC_Decode, 164, 9, 162, 1, // Opcode: NLOC_D
/* 9824 */    MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 9837
/* 9828 */    MCD_OPC_CheckPredicate, 6, 224, 12, // Skip to: 13128
/* 9832 */    MCD_OPC_Decode, 167, 9, 148, 1, // Opcode: NLZC_B
/* 9837 */    MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 9850
/* 9841 */    MCD_OPC_CheckPredicate, 6, 211, 12, // Skip to: 13128
/* 9845 */    MCD_OPC_Decode, 169, 9, 160, 1, // Opcode: NLZC_H
/* 9850 */    MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 9863
/* 9854 */    MCD_OPC_CheckPredicate, 6, 198, 12, // Skip to: 13128
/* 9858 */    MCD_OPC_Decode, 170, 9, 161, 1, // Opcode: NLZC_W
/* 9863 */    MCD_OPC_FilterValue, 15, 189, 12, // Skip to: 13128
/* 9867 */    MCD_OPC_CheckPredicate, 6, 185, 12, // Skip to: 13128
/* 9871 */    MCD_OPC_Decode, 168, 9, 162, 1, // Opcode: NLZC_D
/* 9876 */    MCD_OPC_FilterValue, 25, 176, 12, // Skip to: 13128
/* 9880 */    MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 9883 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 9896
/* 9887 */    MCD_OPC_CheckPredicate, 6, 165, 12, // Skip to: 13128
/* 9891 */    MCD_OPC_Decode, 135, 5, 161, 1, // Opcode: FCLASS_W
/* 9896 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 9909
/* 9900 */    MCD_OPC_CheckPredicate, 6, 152, 12, // Skip to: 13128
/* 9904 */    MCD_OPC_Decode, 134, 5, 162, 1, // Opcode: FCLASS_D
/* 9909 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 9922
/* 9913 */    MCD_OPC_CheckPredicate, 6, 139, 12, // Skip to: 13128
/* 9917 */    MCD_OPC_Decode, 149, 6, 161, 1, // Opcode: FTRUNC_S_W
/* 9922 */    MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 9935
/* 9926 */    MCD_OPC_CheckPredicate, 6, 126, 12, // Skip to: 13128
/* 9930 */    MCD_OPC_Decode, 148, 6, 162, 1, // Opcode: FTRUNC_S_D
/* 9935 */    MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 9948
/* 9939 */    MCD_OPC_CheckPredicate, 6, 113, 12, // Skip to: 13128
/* 9943 */    MCD_OPC_Decode, 151, 6, 161, 1, // Opcode: FTRUNC_U_W
/* 9948 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 9961
/* 9952 */    MCD_OPC_CheckPredicate, 6, 100, 12, // Skip to: 13128
/* 9956 */    MCD_OPC_Decode, 150, 6, 162, 1, // Opcode: FTRUNC_U_D
/* 9961 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 9974
/* 9965 */    MCD_OPC_CheckPredicate, 6, 87, 12, // Skip to: 13128
/* 9969 */    MCD_OPC_Decode, 252, 5, 161, 1, // Opcode: FSQRT_W
/* 9974 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 9987
/* 9978 */    MCD_OPC_CheckPredicate, 6, 74, 12, // Skip to: 13128
/* 9982 */    MCD_OPC_Decode, 246, 5, 162, 1, // Opcode: FSQRT_D
/* 9987 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 10000
/* 9991 */    MCD_OPC_CheckPredicate, 6, 61, 12, // Skip to: 13128
/* 9995 */    MCD_OPC_Decode, 233, 5, 161, 1, // Opcode: FRSQRT_W
/* 10000 */   MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 10013
/* 10004 */   MCD_OPC_CheckPredicate, 6, 48, 12, // Skip to: 13128
/* 10008 */   MCD_OPC_Decode, 232, 5, 162, 1, // Opcode: FRSQRT_D
/* 10013 */   MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 10026
/* 10017 */   MCD_OPC_CheckPredicate, 6, 35, 12, // Skip to: 13128
/* 10021 */   MCD_OPC_Decode, 229, 5, 161, 1, // Opcode: FRCP_W
/* 10026 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 10039
/* 10030 */   MCD_OPC_CheckPredicate, 6, 22, 12, // Skip to: 13128
/* 10034 */   MCD_OPC_Decode, 228, 5, 162, 1, // Opcode: FRCP_D
/* 10039 */   MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 10052
/* 10043 */   MCD_OPC_CheckPredicate, 6, 9, 12, // Skip to: 13128
/* 10047 */   MCD_OPC_Decode, 231, 5, 161, 1, // Opcode: FRINT_W
/* 10052 */   MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 10065
/* 10056 */   MCD_OPC_CheckPredicate, 6, 252, 11, // Skip to: 13128
/* 10060 */   MCD_OPC_Decode, 230, 5, 162, 1, // Opcode: FRINT_D
/* 10065 */   MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 10078
/* 10069 */   MCD_OPC_CheckPredicate, 6, 239, 11, // Skip to: 13128
/* 10073 */   MCD_OPC_Decode, 191, 5, 161, 1, // Opcode: FLOG2_W
/* 10078 */   MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 10091
/* 10082 */   MCD_OPC_CheckPredicate, 6, 226, 11, // Skip to: 13128
/* 10086 */   MCD_OPC_Decode, 190, 5, 162, 1, // Opcode: FLOG2_D
/* 10091 */   MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 10104
/* 10095 */   MCD_OPC_CheckPredicate, 6, 213, 11, // Skip to: 13128
/* 10099 */   MCD_OPC_Decode, 173, 5, 163, 1, // Opcode: FEXUPL_W
/* 10104 */   MCD_OPC_FilterValue, 17, 9, 0, // Skip to: 10117
/* 10108 */   MCD_OPC_CheckPredicate, 6, 200, 11, // Skip to: 13128
/* 10112 */   MCD_OPC_Decode, 172, 5, 164, 1, // Opcode: FEXUPL_D
/* 10117 */   MCD_OPC_FilterValue, 18, 9, 0, // Skip to: 10130
/* 10121 */   MCD_OPC_CheckPredicate, 6, 187, 11, // Skip to: 13128
/* 10125 */   MCD_OPC_Decode, 175, 5, 163, 1, // Opcode: FEXUPR_W
/* 10130 */   MCD_OPC_FilterValue, 19, 9, 0, // Skip to: 10143
/* 10134 */   MCD_OPC_CheckPredicate, 6, 174, 11, // Skip to: 13128
/* 10138 */   MCD_OPC_Decode, 174, 5, 164, 1, // Opcode: FEXUPR_D
/* 10143 */   MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 10156
/* 10147 */   MCD_OPC_CheckPredicate, 6, 161, 11, // Skip to: 13128
/* 10151 */   MCD_OPC_Decode, 181, 5, 163, 1, // Opcode: FFQL_W
/* 10156 */   MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 10169
/* 10160 */   MCD_OPC_CheckPredicate, 6, 148, 11, // Skip to: 13128
/* 10164 */   MCD_OPC_Decode, 180, 5, 164, 1, // Opcode: FFQL_D
/* 10169 */   MCD_OPC_FilterValue, 22, 9, 0, // Skip to: 10182
/* 10173 */   MCD_OPC_CheckPredicate, 6, 135, 11, // Skip to: 13128
/* 10177 */   MCD_OPC_Decode, 183, 5, 163, 1, // Opcode: FFQR_W
/* 10182 */   MCD_OPC_FilterValue, 23, 9, 0, // Skip to: 10195
/* 10186 */   MCD_OPC_CheckPredicate, 6, 122, 11, // Skip to: 13128
/* 10190 */   MCD_OPC_Decode, 182, 5, 164, 1, // Opcode: FFQR_D
/* 10195 */   MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 10208
/* 10199 */   MCD_OPC_CheckPredicate, 6, 109, 11, // Skip to: 13128
/* 10203 */   MCD_OPC_Decode, 143, 6, 161, 1, // Opcode: FTINT_S_W
/* 10208 */   MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 10221
/* 10212 */   MCD_OPC_CheckPredicate, 6, 96, 11, // Skip to: 13128
/* 10216 */   MCD_OPC_Decode, 142, 6, 162, 1, // Opcode: FTINT_S_D
/* 10221 */   MCD_OPC_FilterValue, 26, 9, 0, // Skip to: 10234
/* 10225 */   MCD_OPC_CheckPredicate, 6, 83, 11, // Skip to: 13128
/* 10229 */   MCD_OPC_Decode, 145, 6, 161, 1, // Opcode: FTINT_U_W
/* 10234 */   MCD_OPC_FilterValue, 27, 9, 0, // Skip to: 10247
/* 10238 */   MCD_OPC_CheckPredicate, 6, 70, 11, // Skip to: 13128
/* 10242 */   MCD_OPC_Decode, 144, 6, 162, 1, // Opcode: FTINT_U_D
/* 10247 */   MCD_OPC_FilterValue, 28, 9, 0, // Skip to: 10260
/* 10251 */   MCD_OPC_CheckPredicate, 6, 57, 11, // Skip to: 13128
/* 10255 */   MCD_OPC_Decode, 177, 5, 161, 1, // Opcode: FFINT_S_W
/* 10260 */   MCD_OPC_FilterValue, 29, 9, 0, // Skip to: 10273
/* 10264 */   MCD_OPC_CheckPredicate, 6, 44, 11, // Skip to: 13128
/* 10268 */   MCD_OPC_Decode, 176, 5, 162, 1, // Opcode: FFINT_S_D
/* 10273 */   MCD_OPC_FilterValue, 30, 9, 0, // Skip to: 10286
/* 10277 */   MCD_OPC_CheckPredicate, 6, 31, 11, // Skip to: 13128
/* 10281 */   MCD_OPC_Decode, 179, 5, 161, 1, // Opcode: FFINT_U_W
/* 10286 */   MCD_OPC_FilterValue, 31, 22, 11, // Skip to: 13128
/* 10290 */   MCD_OPC_CheckPredicate, 6, 18, 11, // Skip to: 13128
/* 10294 */   MCD_OPC_Decode, 178, 5, 162, 1, // Opcode: FFINT_U_D
/* 10299 */   MCD_OPC_FilterValue, 32, 9, 0, // Skip to: 10312
/* 10303 */   MCD_OPC_CheckPredicate, 6, 5, 11, // Skip to: 13128
/* 10307 */   MCD_OPC_Decode, 248, 6, 165, 1, // Opcode: LD_B
/* 10312 */   MCD_OPC_FilterValue, 33, 9, 0, // Skip to: 10325
/* 10316 */   MCD_OPC_CheckPredicate, 6, 248, 10, // Skip to: 13128
/* 10320 */   MCD_OPC_Decode, 250, 6, 165, 1, // Opcode: LD_H
/* 10325 */   MCD_OPC_FilterValue, 34, 9, 0, // Skip to: 10338
/* 10329 */   MCD_OPC_CheckPredicate, 6, 235, 10, // Skip to: 13128
/* 10333 */   MCD_OPC_Decode, 251, 6, 165, 1, // Opcode: LD_W
/* 10338 */   MCD_OPC_FilterValue, 35, 9, 0, // Skip to: 10351
/* 10342 */   MCD_OPC_CheckPredicate, 6, 222, 10, // Skip to: 13128
/* 10346 */   MCD_OPC_Decode, 249, 6, 165, 1, // Opcode: LD_D
/* 10351 */   MCD_OPC_FilterValue, 36, 9, 0, // Skip to: 10364
/* 10355 */   MCD_OPC_CheckPredicate, 6, 209, 10, // Skip to: 13128
/* 10359 */   MCD_OPC_Decode, 219, 11, 165, 1, // Opcode: ST_B
/* 10364 */   MCD_OPC_FilterValue, 37, 9, 0, // Skip to: 10377
/* 10368 */   MCD_OPC_CheckPredicate, 6, 196, 10, // Skip to: 13128
/* 10372 */   MCD_OPC_Decode, 221, 11, 165, 1, // Opcode: ST_H
/* 10377 */   MCD_OPC_FilterValue, 38, 9, 0, // Skip to: 10390
/* 10381 */   MCD_OPC_CheckPredicate, 6, 183, 10, // Skip to: 13128
/* 10385 */   MCD_OPC_Decode, 222, 11, 165, 1, // Opcode: ST_W
/* 10390 */   MCD_OPC_FilterValue, 39, 174, 10, // Skip to: 13128
/* 10394 */   MCD_OPC_CheckPredicate, 6, 170, 10, // Skip to: 13128
/* 10398 */   MCD_OPC_Decode, 220, 11, 165, 1, // Opcode: ST_D
/* 10403 */   MCD_OPC_FilterValue, 31, 113, 9, // Skip to: 12824
/* 10407 */   MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10410 */   MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 10423
/* 10414 */   MCD_OPC_CheckPredicate, 4, 150, 10, // Skip to: 13128
/* 10418 */   MCD_OPC_Decode, 226, 4, 166, 1, // Opcode: EXT
/* 10423 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 10436
/* 10427 */   MCD_OPC_CheckPredicate, 4, 137, 10, // Skip to: 13128
/* 10431 */   MCD_OPC_Decode, 181, 6, 167, 1, // Opcode: INS
/* 10436 */   MCD_OPC_FilterValue, 10, 42, 0, // Skip to: 10482
/* 10440 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 10443 */   MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 10456
/* 10447 */   MCD_OPC_CheckPredicate, 11, 117, 10, // Skip to: 13128
/* 10451 */   MCD_OPC_Decode, 170, 7, 168, 1, // Opcode: LWX
/* 10456 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 10469
/* 10460 */   MCD_OPC_CheckPredicate, 11, 104, 10, // Skip to: 13128
/* 10464 */   MCD_OPC_Decode, 129, 7, 168, 1, // Opcode: LHX
/* 10469 */   MCD_OPC_FilterValue, 6, 95, 10, // Skip to: 13128
/* 10473 */   MCD_OPC_CheckPredicate, 11, 91, 10, // Skip to: 13128
/* 10477 */   MCD_OPC_Decode, 227, 6, 168, 1, // Opcode: LBUX
/* 10482 */   MCD_OPC_FilterValue, 12, 15, 0, // Skip to: 10501
/* 10486 */   MCD_OPC_CheckPredicate, 11, 78, 10, // Skip to: 13128
/* 10490 */   MCD_OPC_CheckField, 6, 10, 0, 72, 10, // Skip to: 13128
/* 10496 */   MCD_OPC_Decode, 194, 6, 169, 1, // Opcode: INSV
/* 10501 */   MCD_OPC_FilterValue, 16, 51, 1, // Skip to: 10812
/* 10505 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 10508 */   MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 10520
/* 10512 */   MCD_OPC_CheckPredicate, 11, 52, 10, // Skip to: 13128
/* 10516 */   MCD_OPC_Decode, 48, 170, 1, // Opcode: ADDU_QB
/* 10520 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 10533
/* 10524 */   MCD_OPC_CheckPredicate, 11, 40, 10, // Skip to: 13128
/* 10528 */   MCD_OPC_Decode, 250, 11, 170, 1, // Opcode: SUBU_QB
/* 10533 */   MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 10545
/* 10537 */   MCD_OPC_CheckPredicate, 11, 27, 10, // Skip to: 13128
/* 10541 */   MCD_OPC_Decode, 50, 170, 1, // Opcode: ADDU_S_QB
/* 10545 */   MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 10558
/* 10549 */   MCD_OPC_CheckPredicate, 11, 15, 10, // Skip to: 13128
/* 10553 */   MCD_OPC_Decode, 252, 11, 170, 1, // Opcode: SUBU_S_QB
/* 10558 */   MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 10571
/* 10562 */   MCD_OPC_CheckPredicate, 11, 2, 10, // Skip to: 13128
/* 10566 */   MCD_OPC_Decode, 128, 9, 170, 1, // Opcode: MULEU_S_PH_QBL
/* 10571 */   MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 10584
/* 10575 */   MCD_OPC_CheckPredicate, 11, 245, 9, // Skip to: 13128
/* 10579 */   MCD_OPC_Decode, 129, 9, 170, 1, // Opcode: MULEU_S_PH_QBR
/* 10584 */   MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 10596
/* 10588 */   MCD_OPC_CheckPredicate, 29, 232, 9, // Skip to: 13128
/* 10592 */   MCD_OPC_Decode, 47, 170, 1, // Opcode: ADDU_PH
/* 10596 */   MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 10609
/* 10600 */   MCD_OPC_CheckPredicate, 29, 220, 9, // Skip to: 13128
/* 10604 */   MCD_OPC_Decode, 249, 11, 170, 1, // Opcode: SUBU_PH
/* 10609 */   MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 10621
/* 10613 */   MCD_OPC_CheckPredicate, 11, 207, 9, // Skip to: 13128
/* 10617 */   MCD_OPC_Decode, 29, 170, 1, // Opcode: ADDQ_PH
/* 10621 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 10634
/* 10625 */   MCD_OPC_CheckPredicate, 11, 195, 9, // Skip to: 13128
/* 10629 */   MCD_OPC_Decode, 228, 11, 170, 1, // Opcode: SUBQ_PH
/* 10634 */   MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 10646
/* 10638 */   MCD_OPC_CheckPredicate, 29, 182, 9, // Skip to: 13128
/* 10642 */   MCD_OPC_Decode, 49, 170, 1, // Opcode: ADDU_S_PH
/* 10646 */   MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 10659
/* 10650 */   MCD_OPC_CheckPredicate, 29, 170, 9, // Skip to: 13128
/* 10654 */   MCD_OPC_Decode, 251, 11, 170, 1, // Opcode: SUBU_S_PH
/* 10659 */   MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 10671
/* 10663 */   MCD_OPC_CheckPredicate, 11, 157, 9, // Skip to: 13128
/* 10667 */   MCD_OPC_Decode, 30, 170, 1, // Opcode: ADDQ_S_PH
/* 10671 */   MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 10684
/* 10675 */   MCD_OPC_CheckPredicate, 11, 145, 9, // Skip to: 13128
/* 10679 */   MCD_OPC_Decode, 229, 11, 170, 1, // Opcode: SUBQ_S_PH
/* 10684 */   MCD_OPC_FilterValue, 16, 7, 0, // Skip to: 10695
/* 10688 */   MCD_OPC_CheckPredicate, 11, 132, 9, // Skip to: 13128
/* 10692 */   MCD_OPC_Decode, 32, 16, // Opcode: ADDSC
/* 10695 */   MCD_OPC_FilterValue, 17, 7, 0, // Skip to: 10706
/* 10699 */   MCD_OPC_CheckPredicate, 11, 121, 9, // Skip to: 13128
/* 10703 */   MCD_OPC_Decode, 59, 16, // Opcode: ADDWC
/* 10706 */   MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 10718
/* 10710 */   MCD_OPC_CheckPredicate, 11, 110, 9, // Skip to: 13128
/* 10714 */   MCD_OPC_Decode, 156, 8, 16, // Opcode: MODSUB
/* 10718 */   MCD_OPC_FilterValue, 20, 15, 0, // Skip to: 10737
/* 10722 */   MCD_OPC_CheckPredicate, 11, 98, 9, // Skip to: 13128
/* 10726 */   MCD_OPC_CheckField, 16, 5, 0, 92, 9, // Skip to: 13128
/* 10732 */   MCD_OPC_Decode, 149, 10, 171, 1, // Opcode: RADDU_W_QB
/* 10737 */   MCD_OPC_FilterValue, 22, 7, 0, // Skip to: 10748
/* 10741 */   MCD_OPC_CheckPredicate, 11, 79, 9, // Skip to: 13128
/* 10745 */   MCD_OPC_Decode, 31, 16, // Opcode: ADDQ_S_W
/* 10748 */   MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 10760
/* 10752 */   MCD_OPC_CheckPredicate, 11, 68, 9, // Skip to: 13128
/* 10756 */   MCD_OPC_Decode, 230, 11, 16, // Opcode: SUBQ_S_W
/* 10760 */   MCD_OPC_FilterValue, 28, 9, 0, // Skip to: 10773
/* 10764 */   MCD_OPC_CheckPredicate, 11, 56, 9, // Skip to: 13128
/* 10768 */   MCD_OPC_Decode, 254, 8, 172, 1, // Opcode: MULEQ_S_W_PHL
/* 10773 */   MCD_OPC_FilterValue, 29, 9, 0, // Skip to: 10786
/* 10777 */   MCD_OPC_CheckPredicate, 11, 43, 9, // Skip to: 13128
/* 10781 */   MCD_OPC_Decode, 255, 8, 172, 1, // Opcode: MULEQ_S_W_PHR
/* 10786 */   MCD_OPC_FilterValue, 30, 9, 0, // Skip to: 10799
/* 10790 */   MCD_OPC_CheckPredicate, 29, 30, 9, // Skip to: 13128
/* 10794 */   MCD_OPC_Decode, 132, 9, 170, 1, // Opcode: MULQ_S_PH
/* 10799 */   MCD_OPC_FilterValue, 31, 21, 9, // Skip to: 13128
/* 10803 */   MCD_OPC_CheckPredicate, 11, 17, 9, // Skip to: 13128
/* 10807 */   MCD_OPC_Decode, 130, 9, 170, 1, // Opcode: MULQ_RS_PH
/* 10812 */   MCD_OPC_FilterValue, 17, 69, 1, // Skip to: 11141
/* 10816 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 10819 */   MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 10838
/* 10823 */   MCD_OPC_CheckPredicate, 11, 253, 8, // Skip to: 13128
/* 10827 */   MCD_OPC_CheckField, 11, 5, 0, 247, 8, // Skip to: 13128
/* 10833 */   MCD_OPC_Decode, 243, 2, 173, 1, // Opcode: CMPU_EQ_QB
/* 10838 */   MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 10857
/* 10842 */   MCD_OPC_CheckPredicate, 11, 234, 8, // Skip to: 13128
/* 10846 */   MCD_OPC_CheckField, 11, 5, 0, 228, 8, // Skip to: 13128
/* 10852 */   MCD_OPC_Decode, 245, 2, 173, 1, // Opcode: CMPU_LT_QB
/* 10857 */   MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 10876
/* 10861 */   MCD_OPC_CheckPredicate, 11, 215, 8, // Skip to: 13128
/* 10865 */   MCD_OPC_CheckField, 11, 5, 0, 209, 8, // Skip to: 13128
/* 10871 */   MCD_OPC_Decode, 244, 2, 173, 1, // Opcode: CMPU_LE_QB
/* 10876 */   MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 10889
/* 10880 */   MCD_OPC_CheckPredicate, 11, 196, 8, // Skip to: 13128
/* 10884 */   MCD_OPC_Decode, 219, 9, 170, 1, // Opcode: PICK_QB
/* 10889 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 10902
/* 10893 */   MCD_OPC_CheckPredicate, 11, 183, 8, // Skip to: 13128
/* 10897 */   MCD_OPC_Decode, 240, 2, 172, 1, // Opcode: CMPGU_EQ_QB
/* 10902 */   MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 10915
/* 10906 */   MCD_OPC_CheckPredicate, 11, 170, 8, // Skip to: 13128
/* 10910 */   MCD_OPC_Decode, 242, 2, 172, 1, // Opcode: CMPGU_LT_QB
/* 10915 */   MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 10928
/* 10919 */   MCD_OPC_CheckPredicate, 11, 157, 8, // Skip to: 13128
/* 10923 */   MCD_OPC_Decode, 241, 2, 172, 1, // Opcode: CMPGU_LE_QB
/* 10928 */   MCD_OPC_FilterValue, 8, 15, 0, // Skip to: 10947
/* 10932 */   MCD_OPC_CheckPredicate, 11, 144, 8, // Skip to: 13128
/* 10936 */   MCD_OPC_CheckField, 11, 5, 0, 138, 8, // Skip to: 13128
/* 10942 */   MCD_OPC_Decode, 247, 2, 173, 1, // Opcode: CMP_EQ_PH
/* 10947 */   MCD_OPC_FilterValue, 9, 15, 0, // Skip to: 10966
/* 10951 */   MCD_OPC_CheckPredicate, 11, 125, 8, // Skip to: 13128
/* 10955 */   MCD_OPC_CheckField, 11, 5, 0, 119, 8, // Skip to: 13128
/* 10961 */   MCD_OPC_Decode, 255, 2, 173, 1, // Opcode: CMP_LT_PH
/* 10966 */   MCD_OPC_FilterValue, 10, 15, 0, // Skip to: 10985
/* 10970 */   MCD_OPC_CheckPredicate, 11, 106, 8, // Skip to: 13128
/* 10974 */   MCD_OPC_CheckField, 11, 5, 0, 100, 8, // Skip to: 13128
/* 10980 */   MCD_OPC_Decode, 252, 2, 173, 1, // Opcode: CMP_LE_PH
/* 10985 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 10998
/* 10989 */   MCD_OPC_CheckPredicate, 11, 87, 8, // Skip to: 13128
/* 10993 */   MCD_OPC_Decode, 218, 9, 170, 1, // Opcode: PICK_PH
/* 10998 */   MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 11011
/* 11002 */   MCD_OPC_CheckPredicate, 11, 74, 8, // Skip to: 13128
/* 11006 */   MCD_OPC_Decode, 233, 9, 170, 1, // Opcode: PRECRQ_QB_PH
/* 11011 */   MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 11024
/* 11015 */   MCD_OPC_CheckPredicate, 29, 61, 8, // Skip to: 13128
/* 11019 */   MCD_OPC_Decode, 235, 9, 170, 1, // Opcode: PRECR_QB_PH
/* 11024 */   MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 11037
/* 11028 */   MCD_OPC_CheckPredicate, 11, 48, 8, // Skip to: 13128
/* 11032 */   MCD_OPC_Decode, 204, 9, 170, 1, // Opcode: PACKRL_PH
/* 11037 */   MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 11050
/* 11041 */   MCD_OPC_CheckPredicate, 11, 35, 8, // Skip to: 13128
/* 11045 */   MCD_OPC_Decode, 231, 9, 170, 1, // Opcode: PRECRQU_S_QB_PH
/* 11050 */   MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 11063
/* 11054 */   MCD_OPC_CheckPredicate, 11, 22, 8, // Skip to: 13128
/* 11058 */   MCD_OPC_Decode, 232, 9, 174, 1, // Opcode: PRECRQ_PH_W
/* 11063 */   MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 11076
/* 11067 */   MCD_OPC_CheckPredicate, 11, 9, 8, // Skip to: 13128
/* 11071 */   MCD_OPC_Decode, 234, 9, 174, 1, // Opcode: PRECRQ_RS_PH_W
/* 11076 */   MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 11089
/* 11080 */   MCD_OPC_CheckPredicate, 29, 252, 7, // Skip to: 13128
/* 11084 */   MCD_OPC_Decode, 237, 2, 172, 1, // Opcode: CMPGDU_EQ_QB
/* 11089 */   MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 11102
/* 11093 */   MCD_OPC_CheckPredicate, 29, 239, 7, // Skip to: 13128
/* 11097 */   MCD_OPC_Decode, 239, 2, 172, 1, // Opcode: CMPGDU_LT_QB
/* 11102 */   MCD_OPC_FilterValue, 26, 9, 0, // Skip to: 11115
/* 11106 */   MCD_OPC_CheckPredicate, 29, 226, 7, // Skip to: 13128
/* 11110 */   MCD_OPC_Decode, 238, 2, 172, 1, // Opcode: CMPGDU_LE_QB
/* 11115 */   MCD_OPC_FilterValue, 30, 9, 0, // Skip to: 11128
/* 11119 */   MCD_OPC_CheckPredicate, 29, 213, 7, // Skip to: 13128
/* 11123 */   MCD_OPC_Decode, 236, 9, 175, 1, // Opcode: PRECR_SRA_PH_W
/* 11128 */   MCD_OPC_FilterValue, 31, 204, 7, // Skip to: 13128
/* 11132 */   MCD_OPC_CheckPredicate, 29, 200, 7, // Skip to: 13128
/* 11136 */   MCD_OPC_Decode, 237, 9, 175, 1, // Opcode: PRECR_SRA_R_PH_W
/* 11141 */   MCD_OPC_FilterValue, 18, 74, 1, // Skip to: 11475
/* 11145 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11148 */   MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 11166
/* 11152 */   MCD_OPC_CheckPredicate, 29, 180, 7, // Skip to: 13128
/* 11156 */   MCD_OPC_CheckField, 21, 5, 0, 174, 7, // Skip to: 13128
/* 11162 */   MCD_OPC_Decode, 21, 176, 1, // Opcode: ABSQ_S_QB
/* 11166 */   MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 11179
/* 11170 */   MCD_OPC_CheckPredicate, 11, 162, 7, // Skip to: 13128
/* 11174 */   MCD_OPC_Decode, 156, 10, 177, 1, // Opcode: REPL_QB
/* 11179 */   MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 11198
/* 11183 */   MCD_OPC_CheckPredicate, 11, 149, 7, // Skip to: 13128
/* 11187 */   MCD_OPC_CheckField, 21, 5, 0, 143, 7, // Skip to: 13128
/* 11193 */   MCD_OPC_Decode, 154, 10, 178, 1, // Opcode: REPLV_QB
/* 11198 */   MCD_OPC_FilterValue, 4, 15, 0, // Skip to: 11217
/* 11202 */   MCD_OPC_CheckPredicate, 11, 130, 7, // Skip to: 13128
/* 11206 */   MCD_OPC_CheckField, 21, 5, 0, 124, 7, // Skip to: 13128
/* 11212 */   MCD_OPC_Decode, 221, 9, 176, 1, // Opcode: PRECEQU_PH_QBL
/* 11217 */   MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 11236
/* 11221 */   MCD_OPC_CheckPredicate, 11, 111, 7, // Skip to: 13128
/* 11225 */   MCD_OPC_CheckField, 21, 5, 0, 105, 7, // Skip to: 13128
/* 11231 */   MCD_OPC_Decode, 223, 9, 176, 1, // Opcode: PRECEQU_PH_QBR
/* 11236 */   MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 11255
/* 11240 */   MCD_OPC_CheckPredicate, 11, 92, 7, // Skip to: 13128
/* 11244 */   MCD_OPC_CheckField, 21, 5, 0, 86, 7, // Skip to: 13128
/* 11250 */   MCD_OPC_Decode, 222, 9, 176, 1, // Opcode: PRECEQU_PH_QBLA
/* 11255 */   MCD_OPC_FilterValue, 7, 15, 0, // Skip to: 11274
/* 11259 */   MCD_OPC_CheckPredicate, 11, 73, 7, // Skip to: 13128
/* 11263 */   MCD_OPC_CheckField, 21, 5, 0, 67, 7, // Skip to: 13128
/* 11269 */   MCD_OPC_Decode, 224, 9, 176, 1, // Opcode: PRECEQU_PH_QBRA
/* 11274 */   MCD_OPC_FilterValue, 9, 14, 0, // Skip to: 11292
/* 11278 */   MCD_OPC_CheckPredicate, 11, 54, 7, // Skip to: 13128
/* 11282 */   MCD_OPC_CheckField, 21, 5, 0, 48, 7, // Skip to: 13128
/* 11288 */   MCD_OPC_Decode, 20, 176, 1, // Opcode: ABSQ_S_PH
/* 11292 */   MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 11305
/* 11296 */   MCD_OPC_CheckPredicate, 11, 36, 7, // Skip to: 13128
/* 11300 */   MCD_OPC_Decode, 155, 10, 177, 1, // Opcode: REPL_PH
/* 11305 */   MCD_OPC_FilterValue, 11, 15, 0, // Skip to: 11324
/* 11309 */   MCD_OPC_CheckPredicate, 11, 23, 7, // Skip to: 13128
/* 11313 */   MCD_OPC_CheckField, 21, 5, 0, 17, 7, // Skip to: 13128
/* 11319 */   MCD_OPC_Decode, 153, 10, 178, 1, // Opcode: REPLV_PH
/* 11324 */   MCD_OPC_FilterValue, 12, 15, 0, // Skip to: 11343
/* 11328 */   MCD_OPC_CheckPredicate, 11, 4, 7, // Skip to: 13128
/* 11332 */   MCD_OPC_CheckField, 21, 5, 0, 254, 6, // Skip to: 13128
/* 11338 */   MCD_OPC_Decode, 225, 9, 179, 1, // Opcode: PRECEQ_W_PHL
/* 11343 */   MCD_OPC_FilterValue, 13, 15, 0, // Skip to: 11362
/* 11347 */   MCD_OPC_CheckPredicate, 11, 241, 6, // Skip to: 13128
/* 11351 */   MCD_OPC_CheckField, 21, 5, 0, 235, 6, // Skip to: 13128
/* 11357 */   MCD_OPC_Decode, 226, 9, 179, 1, // Opcode: PRECEQ_W_PHR
/* 11362 */   MCD_OPC_FilterValue, 17, 14, 0, // Skip to: 11380
/* 11366 */   MCD_OPC_CheckPredicate, 11, 222, 6, // Skip to: 13128
/* 11370 */   MCD_OPC_CheckField, 21, 5, 0, 216, 6, // Skip to: 13128
/* 11376 */   MCD_OPC_Decode, 22, 180, 1, // Opcode: ABSQ_S_W
/* 11380 */   MCD_OPC_FilterValue, 27, 15, 0, // Skip to: 11399
/* 11384 */   MCD_OPC_CheckPredicate, 11, 204, 6, // Skip to: 13128
/* 11388 */   MCD_OPC_CheckField, 21, 5, 0, 198, 6, // Skip to: 13128
/* 11394 */   MCD_OPC_Decode, 213, 1, 180, 1, // Opcode: BITREV
/* 11399 */   MCD_OPC_FilterValue, 28, 15, 0, // Skip to: 11418
/* 11403 */   MCD_OPC_CheckPredicate, 11, 185, 6, // Skip to: 13128
/* 11407 */   MCD_OPC_CheckField, 21, 5, 0, 179, 6, // Skip to: 13128
/* 11413 */   MCD_OPC_Decode, 227, 9, 176, 1, // Opcode: PRECEU_PH_QBL
/* 11418 */   MCD_OPC_FilterValue, 29, 15, 0, // Skip to: 11437
/* 11422 */   MCD_OPC_CheckPredicate, 11, 166, 6, // Skip to: 13128
/* 11426 */   MCD_OPC_CheckField, 21, 5, 0, 160, 6, // Skip to: 13128
/* 11432 */   MCD_OPC_Decode, 229, 9, 176, 1, // Opcode: PRECEU_PH_QBR
/* 11437 */   MCD_OPC_FilterValue, 30, 15, 0, // Skip to: 11456
/* 11441 */   MCD_OPC_CheckPredicate, 11, 147, 6, // Skip to: 13128
/* 11445 */   MCD_OPC_CheckField, 21, 5, 0, 141, 6, // Skip to: 13128
/* 11451 */   MCD_OPC_Decode, 228, 9, 176, 1, // Opcode: PRECEU_PH_QBLA
/* 11456 */   MCD_OPC_FilterValue, 31, 132, 6, // Skip to: 13128
/* 11460 */   MCD_OPC_CheckPredicate, 11, 128, 6, // Skip to: 13128
/* 11464 */   MCD_OPC_CheckField, 21, 5, 0, 122, 6, // Skip to: 13128
/* 11470 */   MCD_OPC_Decode, 230, 9, 176, 1, // Opcode: PRECEU_PH_QBRA
/* 11475 */   MCD_OPC_FilterValue, 19, 31, 1, // Skip to: 11766
/* 11479 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11482 */   MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 11495
/* 11486 */   MCD_OPC_CheckPredicate, 11, 102, 6, // Skip to: 13128
/* 11490 */   MCD_OPC_Decode, 235, 10, 181, 1, // Opcode: SHLL_QB
/* 11495 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 11508
/* 11499 */   MCD_OPC_CheckPredicate, 11, 89, 6, // Skip to: 13128
/* 11503 */   MCD_OPC_Decode, 251, 10, 181, 1, // Opcode: SHRL_QB
/* 11508 */   MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 11521
/* 11512 */   MCD_OPC_CheckPredicate, 11, 76, 6, // Skip to: 13128
/* 11516 */   MCD_OPC_Decode, 231, 10, 182, 1, // Opcode: SHLLV_QB
/* 11521 */   MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 11534
/* 11525 */   MCD_OPC_CheckPredicate, 11, 63, 6, // Skip to: 13128
/* 11529 */   MCD_OPC_Decode, 249, 10, 182, 1, // Opcode: SHRLV_QB
/* 11534 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 11547
/* 11538 */   MCD_OPC_CheckPredicate, 29, 50, 6, // Skip to: 13128
/* 11542 */   MCD_OPC_Decode, 244, 10, 181, 1, // Opcode: SHRA_QB
/* 11547 */   MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 11560
/* 11551 */   MCD_OPC_CheckPredicate, 29, 37, 6, // Skip to: 13128
/* 11555 */   MCD_OPC_Decode, 246, 10, 181, 1, // Opcode: SHRA_R_QB
/* 11560 */   MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 11573
/* 11564 */   MCD_OPC_CheckPredicate, 29, 24, 6, // Skip to: 13128
/* 11568 */   MCD_OPC_Decode, 239, 10, 182, 1, // Opcode: SHRAV_QB
/* 11573 */   MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 11586
/* 11577 */   MCD_OPC_CheckPredicate, 29, 11, 6, // Skip to: 13128
/* 11581 */   MCD_OPC_Decode, 241, 10, 182, 1, // Opcode: SHRAV_R_QB
/* 11586 */   MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 11599
/* 11590 */   MCD_OPC_CheckPredicate, 11, 254, 5, // Skip to: 13128
/* 11594 */   MCD_OPC_Decode, 234, 10, 181, 1, // Opcode: SHLL_PH
/* 11599 */   MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 11612
/* 11603 */   MCD_OPC_CheckPredicate, 11, 241, 5, // Skip to: 13128
/* 11607 */   MCD_OPC_Decode, 243, 10, 181, 1, // Opcode: SHRA_PH
/* 11612 */   MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 11625
/* 11616 */   MCD_OPC_CheckPredicate, 11, 228, 5, // Skip to: 13128
/* 11620 */   MCD_OPC_Decode, 230, 10, 182, 1, // Opcode: SHLLV_PH
/* 11625 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 11638
/* 11629 */   MCD_OPC_CheckPredicate, 11, 215, 5, // Skip to: 13128
/* 11633 */   MCD_OPC_Decode, 238, 10, 182, 1, // Opcode: SHRAV_PH
/* 11638 */   MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 11651
/* 11642 */   MCD_OPC_CheckPredicate, 11, 202, 5, // Skip to: 13128
/* 11646 */   MCD_OPC_Decode, 236, 10, 181, 1, // Opcode: SHLL_S_PH
/* 11651 */   MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 11664
/* 11655 */   MCD_OPC_CheckPredicate, 11, 189, 5, // Skip to: 13128
/* 11659 */   MCD_OPC_Decode, 245, 10, 181, 1, // Opcode: SHRA_R_PH
/* 11664 */   MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 11677
/* 11668 */   MCD_OPC_CheckPredicate, 11, 176, 5, // Skip to: 13128
/* 11672 */   MCD_OPC_Decode, 232, 10, 182, 1, // Opcode: SHLLV_S_PH
/* 11677 */   MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 11690
/* 11681 */   MCD_OPC_CheckPredicate, 11, 163, 5, // Skip to: 13128
/* 11685 */   MCD_OPC_Decode, 240, 10, 182, 1, // Opcode: SHRAV_R_PH
/* 11690 */   MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 11703
/* 11694 */   MCD_OPC_CheckPredicate, 11, 150, 5, // Skip to: 13128
/* 11698 */   MCD_OPC_Decode, 237, 10, 183, 1, // Opcode: SHLL_S_W
/* 11703 */   MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 11716
/* 11707 */   MCD_OPC_CheckPredicate, 11, 137, 5, // Skip to: 13128
/* 11711 */   MCD_OPC_Decode, 247, 10, 183, 1, // Opcode: SHRA_R_W
/* 11716 */   MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 11728
/* 11720 */   MCD_OPC_CheckPredicate, 11, 124, 5, // Skip to: 13128
/* 11724 */   MCD_OPC_Decode, 233, 10, 17, // Opcode: SHLLV_S_W
/* 11728 */   MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 11740
/* 11732 */   MCD_OPC_CheckPredicate, 11, 112, 5, // Skip to: 13128
/* 11736 */   MCD_OPC_Decode, 242, 10, 17, // Opcode: SHRAV_R_W
/* 11740 */   MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 11753
/* 11744 */   MCD_OPC_CheckPredicate, 29, 100, 5, // Skip to: 13128
/* 11748 */   MCD_OPC_Decode, 250, 10, 181, 1, // Opcode: SHRL_PH
/* 11753 */   MCD_OPC_FilterValue, 27, 91, 5, // Skip to: 13128
/* 11757 */   MCD_OPC_CheckPredicate, 29, 87, 5, // Skip to: 13128
/* 11761 */   MCD_OPC_Decode, 248, 10, 182, 1, // Opcode: SHRLV_PH
/* 11766 */   MCD_OPC_FilterValue, 24, 199, 0, // Skip to: 11969
/* 11770 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11773 */   MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 11785
/* 11777 */   MCD_OPC_CheckPredicate, 29, 67, 5, // Skip to: 13128
/* 11781 */   MCD_OPC_Decode, 45, 170, 1, // Opcode: ADDUH_QB
/* 11785 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 11798
/* 11789 */   MCD_OPC_CheckPredicate, 29, 55, 5, // Skip to: 13128
/* 11793 */   MCD_OPC_Decode, 247, 11, 170, 1, // Opcode: SUBUH_QB
/* 11798 */   MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 11810
/* 11802 */   MCD_OPC_CheckPredicate, 29, 42, 5, // Skip to: 13128
/* 11806 */   MCD_OPC_Decode, 46, 170, 1, // Opcode: ADDUH_R_QB
/* 11810 */   MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 11823
/* 11814 */   MCD_OPC_CheckPredicate, 29, 30, 5, // Skip to: 13128
/* 11818 */   MCD_OPC_Decode, 248, 11, 170, 1, // Opcode: SUBUH_R_QB
/* 11823 */   MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 11835
/* 11827 */   MCD_OPC_CheckPredicate, 29, 17, 5, // Skip to: 13128
/* 11831 */   MCD_OPC_Decode, 25, 170, 1, // Opcode: ADDQH_PH
/* 11835 */   MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 11848
/* 11839 */   MCD_OPC_CheckPredicate, 29, 5, 5, // Skip to: 13128
/* 11843 */   MCD_OPC_Decode, 224, 11, 170, 1, // Opcode: SUBQH_PH
/* 11848 */   MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 11860
/* 11852 */   MCD_OPC_CheckPredicate, 29, 248, 4, // Skip to: 13128
/* 11856 */   MCD_OPC_Decode, 26, 170, 1, // Opcode: ADDQH_R_PH
/* 11860 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 11873
/* 11864 */   MCD_OPC_CheckPredicate, 29, 236, 4, // Skip to: 13128
/* 11868 */   MCD_OPC_Decode, 225, 11, 170, 1, // Opcode: SUBQH_R_PH
/* 11873 */   MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 11886
/* 11877 */   MCD_OPC_CheckPredicate, 29, 223, 4, // Skip to: 13128
/* 11881 */   MCD_OPC_Decode, 150, 9, 170, 1, // Opcode: MUL_PH
/* 11886 */   MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 11899
/* 11890 */   MCD_OPC_CheckPredicate, 29, 210, 4, // Skip to: 13128
/* 11894 */   MCD_OPC_Decode, 154, 9, 170, 1, // Opcode: MUL_S_PH
/* 11899 */   MCD_OPC_FilterValue, 16, 7, 0, // Skip to: 11910
/* 11903 */   MCD_OPC_CheckPredicate, 29, 197, 4, // Skip to: 13128
/* 11907 */   MCD_OPC_Decode, 28, 16, // Opcode: ADDQH_W
/* 11910 */   MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 11922
/* 11914 */   MCD_OPC_CheckPredicate, 29, 186, 4, // Skip to: 13128
/* 11918 */   MCD_OPC_Decode, 227, 11, 16, // Opcode: SUBQH_W
/* 11922 */   MCD_OPC_FilterValue, 18, 7, 0, // Skip to: 11933
/* 11926 */   MCD_OPC_CheckPredicate, 29, 174, 4, // Skip to: 13128
/* 11930 */   MCD_OPC_Decode, 27, 16, // Opcode: ADDQH_R_W
/* 11933 */   MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 11945
/* 11937 */   MCD_OPC_CheckPredicate, 29, 163, 4, // Skip to: 13128
/* 11941 */   MCD_OPC_Decode, 226, 11, 16, // Opcode: SUBQH_R_W
/* 11945 */   MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 11957
/* 11949 */   MCD_OPC_CheckPredicate, 29, 151, 4, // Skip to: 13128
/* 11953 */   MCD_OPC_Decode, 133, 9, 16, // Opcode: MULQ_S_W
/* 11957 */   MCD_OPC_FilterValue, 23, 143, 4, // Skip to: 13128
/* 11961 */   MCD_OPC_CheckPredicate, 29, 139, 4, // Skip to: 13128
/* 11965 */   MCD_OPC_Decode, 131, 9, 16, // Opcode: MULQ_RS_W
/* 11969 */   MCD_OPC_FilterValue, 32, 60, 0, // Skip to: 12033
/* 11973 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11976 */   MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 11995
/* 11980 */   MCD_OPC_CheckPredicate, 4, 120, 4, // Skip to: 13128
/* 11984 */   MCD_OPC_CheckField, 21, 5, 0, 114, 4, // Skip to: 13128
/* 11990 */   MCD_OPC_Decode, 255, 12, 180, 1, // Opcode: WSBH
/* 11995 */   MCD_OPC_FilterValue, 16, 15, 0, // Skip to: 12014
/* 11999 */   MCD_OPC_CheckPredicate, 4, 101, 4, // Skip to: 13128
/* 12003 */   MCD_OPC_CheckField, 21, 5, 0, 95, 4, // Skip to: 13128
/* 12009 */   MCD_OPC_Decode, 205, 10, 180, 1, // Opcode: SEB
/* 12014 */   MCD_OPC_FilterValue, 24, 86, 4, // Skip to: 13128
/* 12018 */   MCD_OPC_CheckPredicate, 4, 82, 4, // Skip to: 13128
/* 12022 */   MCD_OPC_CheckField, 21, 5, 0, 76, 4, // Skip to: 13128
/* 12028 */   MCD_OPC_Decode, 208, 10, 180, 1, // Opcode: SEH
/* 12033 */   MCD_OPC_FilterValue, 48, 143, 1, // Skip to: 12436
/* 12037 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 12040 */   MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 12058
/* 12044 */   MCD_OPC_CheckPredicate, 29, 56, 4, // Skip to: 13128
/* 12048 */   MCD_OPC_CheckField, 13, 3, 0, 50, 4, // Skip to: 13128
/* 12054 */   MCD_OPC_Decode, 184, 4, 91, // Opcode: DPA_W_PH
/* 12058 */   MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 12076
/* 12062 */   MCD_OPC_CheckPredicate, 29, 38, 4, // Skip to: 13128
/* 12066 */   MCD_OPC_CheckField, 13, 3, 0, 32, 4, // Skip to: 13128
/* 12072 */   MCD_OPC_Decode, 199, 4, 91, // Opcode: DPS_W_PH
/* 12076 */   MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 12094
/* 12080 */   MCD_OPC_CheckPredicate, 29, 20, 4, // Skip to: 13128
/* 12084 */   MCD_OPC_CheckField, 13, 3, 0, 14, 4, // Skip to: 13128
/* 12090 */   MCD_OPC_Decode, 137, 9, 91, // Opcode: MULSA_W_PH
/* 12094 */   MCD_OPC_FilterValue, 3, 14, 0, // Skip to: 12112
/* 12098 */   MCD_OPC_CheckPredicate, 11, 2, 4, // Skip to: 13128
/* 12102 */   MCD_OPC_CheckField, 13, 3, 0, 252, 3, // Skip to: 13128
/* 12108 */   MCD_OPC_Decode, 181, 4, 91, // Opcode: DPAU_H_QBL
/* 12112 */   MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 12130
/* 12116 */   MCD_OPC_CheckPredicate, 11, 240, 3, // Skip to: 13128
/* 12120 */   MCD_OPC_CheckField, 13, 3, 0, 234, 3, // Skip to: 13128
/* 12126 */   MCD_OPC_Decode, 180, 4, 91, // Opcode: DPAQ_S_W_PH
/* 12130 */   MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 12148
/* 12134 */   MCD_OPC_CheckPredicate, 11, 222, 3, // Skip to: 13128
/* 12138 */   MCD_OPC_CheckField, 13, 3, 0, 216, 3, // Skip to: 13128
/* 12144 */   MCD_OPC_Decode, 189, 4, 91, // Opcode: DPSQ_S_W_PH
/* 12148 */   MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 12166
/* 12152 */   MCD_OPC_CheckPredicate, 11, 204, 3, // Skip to: 13128
/* 12156 */   MCD_OPC_CheckField, 13, 3, 0, 198, 3, // Skip to: 13128
/* 12162 */   MCD_OPC_Decode, 136, 9, 91, // Opcode: MULSAQ_S_W_PH
/* 12166 */   MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 12184
/* 12170 */   MCD_OPC_CheckPredicate, 11, 186, 3, // Skip to: 13128
/* 12174 */   MCD_OPC_CheckField, 13, 3, 0, 180, 3, // Skip to: 13128
/* 12180 */   MCD_OPC_Decode, 182, 4, 91, // Opcode: DPAU_H_QBR
/* 12184 */   MCD_OPC_FilterValue, 8, 14, 0, // Skip to: 12202
/* 12188 */   MCD_OPC_CheckPredicate, 29, 168, 3, // Skip to: 13128
/* 12192 */   MCD_OPC_CheckField, 13, 3, 0, 162, 3, // Skip to: 13128
/* 12198 */   MCD_OPC_Decode, 183, 4, 91, // Opcode: DPAX_W_PH
/* 12202 */   MCD_OPC_FilterValue, 9, 14, 0, // Skip to: 12220
/* 12206 */   MCD_OPC_CheckPredicate, 29, 150, 3, // Skip to: 13128
/* 12210 */   MCD_OPC_CheckField, 13, 3, 0, 144, 3, // Skip to: 13128
/* 12216 */   MCD_OPC_Decode, 198, 4, 91, // Opcode: DPSX_W_PH
/* 12220 */   MCD_OPC_FilterValue, 11, 14, 0, // Skip to: 12238
/* 12224 */   MCD_OPC_CheckPredicate, 11, 132, 3, // Skip to: 13128
/* 12228 */   MCD_OPC_CheckField, 13, 3, 0, 126, 3, // Skip to: 13128
/* 12234 */   MCD_OPC_Decode, 196, 4, 91, // Opcode: DPSU_H_QBL
/* 12238 */   MCD_OPC_FilterValue, 12, 14, 0, // Skip to: 12256
/* 12242 */   MCD_OPC_CheckPredicate, 11, 114, 3, // Skip to: 13128
/* 12246 */   MCD_OPC_CheckField, 13, 3, 0, 108, 3, // Skip to: 13128
/* 12252 */   MCD_OPC_Decode, 179, 4, 91, // Opcode: DPAQ_SA_L_W
/* 12256 */   MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 12274
/* 12260 */   MCD_OPC_CheckPredicate, 11, 96, 3, // Skip to: 13128
/* 12264 */   MCD_OPC_CheckField, 13, 3, 0, 90, 3, // Skip to: 13128
/* 12270 */   MCD_OPC_Decode, 188, 4, 91, // Opcode: DPSQ_SA_L_W
/* 12274 */   MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 12292
/* 12278 */   MCD_OPC_CheckPredicate, 11, 78, 3, // Skip to: 13128
/* 12282 */   MCD_OPC_CheckField, 13, 3, 0, 72, 3, // Skip to: 13128
/* 12288 */   MCD_OPC_Decode, 197, 4, 91, // Opcode: DPSU_H_QBR
/* 12292 */   MCD_OPC_FilterValue, 16, 14, 0, // Skip to: 12310
/* 12296 */   MCD_OPC_CheckPredicate, 11, 60, 3, // Skip to: 13128
/* 12300 */   MCD_OPC_CheckField, 13, 3, 0, 54, 3, // Skip to: 13128
/* 12306 */   MCD_OPC_Decode, 212, 7, 91, // Opcode: MAQ_SA_W_PHL
/* 12310 */   MCD_OPC_FilterValue, 18, 14, 0, // Skip to: 12328
/* 12314 */   MCD_OPC_CheckPredicate, 11, 42, 3, // Skip to: 13128
/* 12318 */   MCD_OPC_CheckField, 13, 3, 0, 36, 3, // Skip to: 13128
/* 12324 */   MCD_OPC_Decode, 213, 7, 91, // Opcode: MAQ_SA_W_PHR
/* 12328 */   MCD_OPC_FilterValue, 20, 14, 0, // Skip to: 12346
/* 12332 */   MCD_OPC_CheckPredicate, 11, 24, 3, // Skip to: 13128
/* 12336 */   MCD_OPC_CheckField, 13, 3, 0, 18, 3, // Skip to: 13128
/* 12342 */   MCD_OPC_Decode, 214, 7, 91, // Opcode: MAQ_S_W_PHL
/* 12346 */   MCD_OPC_FilterValue, 22, 14, 0, // Skip to: 12364
/* 12350 */   MCD_OPC_CheckPredicate, 11, 6, 3, // Skip to: 13128
/* 12354 */   MCD_OPC_CheckField, 13, 3, 0, 0, 3, // Skip to: 13128
/* 12360 */   MCD_OPC_Decode, 215, 7, 91, // Opcode: MAQ_S_W_PHR
/* 12364 */   MCD_OPC_FilterValue, 24, 14, 0, // Skip to: 12382
/* 12368 */   MCD_OPC_CheckPredicate, 29, 244, 2, // Skip to: 13128
/* 12372 */   MCD_OPC_CheckField, 13, 3, 0, 238, 2, // Skip to: 13128
/* 12378 */   MCD_OPC_Decode, 178, 4, 91, // Opcode: DPAQX_S_W_PH
/* 12382 */   MCD_OPC_FilterValue, 25, 14, 0, // Skip to: 12400
/* 12386 */   MCD_OPC_CheckPredicate, 29, 226, 2, // Skip to: 13128
/* 12390 */   MCD_OPC_CheckField, 13, 3, 0, 220, 2, // Skip to: 13128
/* 12396 */   MCD_OPC_Decode, 187, 4, 91, // Opcode: DPSQX_S_W_PH
/* 12400 */   MCD_OPC_FilterValue, 26, 14, 0, // Skip to: 12418
/* 12404 */   MCD_OPC_CheckPredicate, 29, 208, 2, // Skip to: 13128
/* 12408 */   MCD_OPC_CheckField, 13, 3, 0, 202, 2, // Skip to: 13128
/* 12414 */   MCD_OPC_Decode, 177, 4, 91, // Opcode: DPAQX_SA_W_PH
/* 12418 */   MCD_OPC_FilterValue, 27, 194, 2, // Skip to: 13128
/* 12422 */   MCD_OPC_CheckPredicate, 29, 190, 2, // Skip to: 13128
/* 12426 */   MCD_OPC_CheckField, 13, 3, 0, 184, 2, // Skip to: 13128
/* 12432 */   MCD_OPC_Decode, 186, 4, 91, // Opcode: DPSQX_SA_W_PH
/* 12436 */   MCD_OPC_FilterValue, 49, 41, 0, // Skip to: 12481
/* 12440 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 12443 */   MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 12455
/* 12447 */   MCD_OPC_CheckPredicate, 29, 165, 2, // Skip to: 13128
/* 12451 */   MCD_OPC_Decode, 86, 184, 1, // Opcode: APPEND
/* 12455 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 12468
/* 12459 */   MCD_OPC_CheckPredicate, 29, 153, 2, // Skip to: 13128
/* 12463 */   MCD_OPC_Decode, 240, 9, 184, 1, // Opcode: PREPEND
/* 12468 */   MCD_OPC_FilterValue, 16, 144, 2, // Skip to: 13128
/* 12472 */   MCD_OPC_CheckPredicate, 29, 140, 2, // Skip to: 13128
/* 12476 */   MCD_OPC_Decode, 158, 1, 184, 1, // Opcode: BALIGN
/* 12481 */   MCD_OPC_FilterValue, 56, 58, 1, // Skip to: 12799
/* 12485 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 12488 */   MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 12507
/* 12492 */   MCD_OPC_CheckPredicate, 11, 120, 2, // Skip to: 13128
/* 12496 */   MCD_OPC_CheckField, 13, 3, 0, 114, 2, // Skip to: 13128
/* 12502 */   MCD_OPC_Decode, 238, 4, 185, 1, // Opcode: EXTR_W
/* 12507 */   MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 12526
/* 12511 */   MCD_OPC_CheckPredicate, 11, 101, 2, // Skip to: 13128
/* 12515 */   MCD_OPC_CheckField, 13, 3, 0, 95, 2, // Skip to: 13128
/* 12521 */   MCD_OPC_Decode, 234, 4, 186, 1, // Opcode: EXTRV_W
/* 12526 */   MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 12545
/* 12530 */   MCD_OPC_CheckPredicate, 11, 82, 2, // Skip to: 13128
/* 12534 */   MCD_OPC_CheckField, 13, 3, 0, 76, 2, // Skip to: 13128
/* 12540 */   MCD_OPC_Decode, 227, 4, 185, 1, // Opcode: EXTP
/* 12545 */   MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 12564
/* 12549 */   MCD_OPC_CheckPredicate, 11, 63, 2, // Skip to: 13128
/* 12553 */   MCD_OPC_CheckField, 13, 3, 0, 57, 2, // Skip to: 13128
/* 12559 */   MCD_OPC_Decode, 230, 4, 186, 1, // Opcode: EXTPV
/* 12564 */   MCD_OPC_FilterValue, 4, 15, 0, // Skip to: 12583
/* 12568 */   MCD_OPC_CheckPredicate, 11, 44, 2, // Skip to: 13128
/* 12572 */   MCD_OPC_CheckField, 13, 3, 0, 38, 2, // Skip to: 13128
/* 12578 */   MCD_OPC_Decode, 236, 4, 185, 1, // Opcode: EXTR_R_W
/* 12583 */   MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 12602
/* 12587 */   MCD_OPC_CheckPredicate, 11, 25, 2, // Skip to: 13128
/* 12591 */   MCD_OPC_CheckField, 13, 3, 0, 19, 2, // Skip to: 13128
/* 12597 */   MCD_OPC_Decode, 232, 4, 186, 1, // Opcode: EXTRV_R_W
/* 12602 */   MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 12621
/* 12606 */   MCD_OPC_CheckPredicate, 11, 6, 2, // Skip to: 13128
/* 12610 */   MCD_OPC_CheckField, 13, 3, 0, 0, 2, // Skip to: 13128
/* 12616 */   MCD_OPC_Decode, 235, 4, 185, 1, // Opcode: EXTR_RS_W
/* 12621 */   MCD_OPC_FilterValue, 7, 15, 0, // Skip to: 12640
/* 12625 */   MCD_OPC_CheckPredicate, 11, 243, 1, // Skip to: 13128
/* 12629 */   MCD_OPC_CheckField, 13, 3, 0, 237, 1, // Skip to: 13128
/* 12635 */   MCD_OPC_Decode, 231, 4, 186, 1, // Opcode: EXTRV_RS_W
/* 12640 */   MCD_OPC_FilterValue, 10, 15, 0, // Skip to: 12659
/* 12644 */   MCD_OPC_CheckPredicate, 11, 224, 1, // Skip to: 13128
/* 12648 */   MCD_OPC_CheckField, 13, 3, 0, 218, 1, // Skip to: 13128
/* 12654 */   MCD_OPC_Decode, 228, 4, 185, 1, // Opcode: EXTPDP
/* 12659 */   MCD_OPC_FilterValue, 11, 15, 0, // Skip to: 12678
/* 12663 */   MCD_OPC_CheckPredicate, 11, 205, 1, // Skip to: 13128
/* 12667 */   MCD_OPC_CheckField, 13, 3, 0, 199, 1, // Skip to: 13128
/* 12673 */   MCD_OPC_Decode, 229, 4, 186, 1, // Opcode: EXTPDPV
/* 12678 */   MCD_OPC_FilterValue, 14, 15, 0, // Skip to: 12697
/* 12682 */   MCD_OPC_CheckPredicate, 11, 186, 1, // Skip to: 13128
/* 12686 */   MCD_OPC_CheckField, 13, 3, 0, 180, 1, // Skip to: 13128
/* 12692 */   MCD_OPC_Decode, 237, 4, 185, 1, // Opcode: EXTR_S_H
/* 12697 */   MCD_OPC_FilterValue, 15, 15, 0, // Skip to: 12716
/* 12701 */   MCD_OPC_CheckPredicate, 11, 167, 1, // Skip to: 13128
/* 12705 */   MCD_OPC_CheckField, 13, 3, 0, 161, 1, // Skip to: 13128
/* 12711 */   MCD_OPC_Decode, 233, 4, 186, 1, // Opcode: EXTRV_S_H
/* 12716 */   MCD_OPC_FilterValue, 18, 9, 0, // Skip to: 12729
/* 12720 */   MCD_OPC_CheckPredicate, 11, 148, 1, // Skip to: 13128
/* 12724 */   MCD_OPC_Decode, 150, 10, 187, 1, // Opcode: RDDSP
/* 12729 */   MCD_OPC_FilterValue, 19, 9, 0, // Skip to: 12742
/* 12733 */   MCD_OPC_CheckPredicate, 11, 135, 1, // Skip to: 13128
/* 12737 */   MCD_OPC_Decode, 254, 12, 188, 1, // Opcode: WRDSP
/* 12742 */   MCD_OPC_FilterValue, 26, 15, 0, // Skip to: 12761
/* 12746 */   MCD_OPC_CheckPredicate, 11, 122, 1, // Skip to: 13128
/* 12750 */   MCD_OPC_CheckField, 13, 7, 0, 116, 1, // Skip to: 13128
/* 12756 */   MCD_OPC_Decode, 228, 10, 189, 1, // Opcode: SHILO
/* 12761 */   MCD_OPC_FilterValue, 27, 15, 0, // Skip to: 12780
/* 12765 */   MCD_OPC_CheckPredicate, 11, 103, 1, // Skip to: 13128
/* 12769 */   MCD_OPC_CheckField, 13, 8, 0, 97, 1, // Skip to: 13128
/* 12775 */   MCD_OPC_Decode, 229, 10, 190, 1, // Opcode: SHILOV
/* 12780 */   MCD_OPC_FilterValue, 31, 88, 1, // Skip to: 13128
/* 12784 */   MCD_OPC_CheckPredicate, 11, 84, 1, // Skip to: 13128
/* 12788 */   MCD_OPC_CheckField, 13, 8, 0, 78, 1, // Skip to: 13128
/* 12794 */   MCD_OPC_Decode, 240, 8, 190, 1, // Opcode: MTHLIP
/* 12799 */   MCD_OPC_FilterValue, 59, 69, 1, // Skip to: 13128
/* 12803 */   MCD_OPC_CheckPredicate, 1, 65, 1, // Skip to: 13128
/* 12807 */   MCD_OPC_CheckField, 21, 5, 0, 59, 1, // Skip to: 13128
/* 12813 */   MCD_OPC_CheckField, 6, 5, 0, 53, 1, // Skip to: 13128
/* 12819 */   MCD_OPC_Decode, 151, 10, 191, 1, // Opcode: RDHWR
/* 12824 */   MCD_OPC_FilterValue, 32, 9, 0, // Skip to: 12837
/* 12828 */   MCD_OPC_CheckPredicate, 1, 40, 1, // Skip to: 13128
/* 12832 */   MCD_OPC_Decode, 225, 6, 192, 1, // Opcode: LB
/* 12837 */   MCD_OPC_FilterValue, 33, 9, 0, // Skip to: 12850
/* 12841 */   MCD_OPC_CheckPredicate, 1, 27, 1, // Skip to: 13128
/* 12845 */   MCD_OPC_Decode, 255, 6, 192, 1, // Opcode: LH
/* 12850 */   MCD_OPC_FilterValue, 34, 9, 0, // Skip to: 12863
/* 12854 */   MCD_OPC_CheckPredicate, 10, 14, 1, // Skip to: 13128
/* 12858 */   MCD_OPC_Decode, 161, 7, 192, 1, // Opcode: LWL
/* 12863 */   MCD_OPC_FilterValue, 35, 9, 0, // Skip to: 12876
/* 12867 */   MCD_OPC_CheckPredicate, 1, 1, 1, // Skip to: 13128
/* 12871 */   MCD_OPC_Decode, 154, 7, 192, 1, // Opcode: LW
/* 12876 */   MCD_OPC_FilterValue, 36, 9, 0, // Skip to: 12889
/* 12880 */   MCD_OPC_CheckPredicate, 1, 244, 0, // Skip to: 13128
/* 12884 */   MCD_OPC_Decode, 229, 6, 192, 1, // Opcode: LBu
/* 12889 */   MCD_OPC_FilterValue, 37, 9, 0, // Skip to: 12902
/* 12893 */   MCD_OPC_CheckPredicate, 1, 231, 0, // Skip to: 13128
/* 12897 */   MCD_OPC_Decode, 131, 7, 192, 1, // Opcode: LHu
/* 12902 */   MCD_OPC_FilterValue, 38, 9, 0, // Skip to: 12915
/* 12906 */   MCD_OPC_CheckPredicate, 10, 218, 0, // Skip to: 13128
/* 12910 */   MCD_OPC_Decode, 165, 7, 192, 1, // Opcode: LWR
/* 12915 */   MCD_OPC_FilterValue, 40, 9, 0, // Skip to: 12928
/* 12919 */   MCD_OPC_CheckPredicate, 1, 205, 0, // Skip to: 13128
/* 12923 */   MCD_OPC_Decode, 182, 10, 192, 1, // Opcode: SB
/* 12928 */   MCD_OPC_FilterValue, 41, 9, 0, // Skip to: 12941
/* 12932 */   MCD_OPC_CheckPredicate, 1, 192, 0, // Skip to: 13128
/* 12936 */   MCD_OPC_Decode, 223, 10, 192, 1, // Opcode: SH
/* 12941 */   MCD_OPC_FilterValue, 42, 9, 0, // Skip to: 12954
/* 12945 */   MCD_OPC_CheckPredicate, 10, 179, 0, // Skip to: 13128
/* 12949 */   MCD_OPC_Decode, 146, 12, 192, 1, // Opcode: SWL
/* 12954 */   MCD_OPC_FilterValue, 43, 9, 0, // Skip to: 12967
/* 12958 */   MCD_OPC_CheckPredicate, 1, 166, 0, // Skip to: 13128
/* 12962 */   MCD_OPC_Decode, 139, 12, 192, 1, // Opcode: SW
/* 12967 */   MCD_OPC_FilterValue, 46, 9, 0, // Skip to: 12980
/* 12971 */   MCD_OPC_CheckPredicate, 10, 153, 0, // Skip to: 13128
/* 12975 */   MCD_OPC_Decode, 149, 12, 192, 1, // Opcode: SWR
/* 12980 */   MCD_OPC_FilterValue, 47, 9, 0, // Skip to: 12993
/* 12984 */   MCD_OPC_CheckPredicate, 30, 140, 0, // Skip to: 13128
/* 12988 */   MCD_OPC_Decode, 175, 2, 193, 1, // Opcode: CACHE
/* 12993 */   MCD_OPC_FilterValue, 48, 9, 0, // Skip to: 13006
/* 12997 */   MCD_OPC_CheckPredicate, 31, 127, 0, // Skip to: 13128
/* 13001 */   MCD_OPC_Decode, 134, 7, 192, 1, // Opcode: LL
/* 13006 */   MCD_OPC_FilterValue, 49, 8, 0, // Skip to: 13018
/* 13010 */   MCD_OPC_CheckPredicate, 1, 114, 0, // Skip to: 13128
/* 13014 */   MCD_OPC_Decode, 156, 7, 10, // Opcode: LWC1
/* 13018 */   MCD_OPC_FilterValue, 50, 8, 0, // Skip to: 13030
/* 13022 */   MCD_OPC_CheckPredicate, 12, 102, 0, // Skip to: 13128
/* 13026 */   MCD_OPC_Decode, 158, 7, 10, // Opcode: LWC2
/* 13030 */   MCD_OPC_FilterValue, 51, 9, 0, // Skip to: 13043
/* 13034 */   MCD_OPC_CheckPredicate, 30, 90, 0, // Skip to: 13128
/* 13038 */   MCD_OPC_Decode, 238, 9, 193, 1, // Opcode: PREF
/* 13043 */   MCD_OPC_FilterValue, 53, 8, 0, // Skip to: 13055
/* 13047 */   MCD_OPC_CheckPredicate, 32, 77, 0, // Skip to: 13128
/* 13051 */   MCD_OPC_Decode, 233, 6, 10, // Opcode: LDC1
/* 13055 */   MCD_OPC_FilterValue, 54, 8, 0, // Skip to: 13067
/* 13059 */   MCD_OPC_CheckPredicate, 14, 65, 0, // Skip to: 13128
/* 13063 */   MCD_OPC_Decode, 236, 6, 10, // Opcode: LDC2
/* 13067 */   MCD_OPC_FilterValue, 56, 9, 0, // Skip to: 13080
/* 13071 */   MCD_OPC_CheckPredicate, 31, 53, 0, // Skip to: 13128
/* 13075 */   MCD_OPC_Decode, 185, 10, 192, 1, // Opcode: SC
/* 13080 */   MCD_OPC_FilterValue, 57, 8, 0, // Skip to: 13092
/* 13084 */   MCD_OPC_CheckPredicate, 1, 40, 0, // Skip to: 13128
/* 13088 */   MCD_OPC_Decode, 141, 12, 10, // Opcode: SWC1
/* 13092 */   MCD_OPC_FilterValue, 58, 8, 0, // Skip to: 13104
/* 13096 */   MCD_OPC_CheckPredicate, 12, 28, 0, // Skip to: 13128
/* 13100 */   MCD_OPC_Decode, 143, 12, 10, // Opcode: SWC2
/* 13104 */   MCD_OPC_FilterValue, 61, 8, 0, // Skip to: 13116
/* 13108 */   MCD_OPC_CheckPredicate, 32, 16, 0, // Skip to: 13128
/* 13112 */   MCD_OPC_Decode, 193, 10, 10, // Opcode: SDC1
/* 13116 */   MCD_OPC_FilterValue, 62, 8, 0, // Skip to: 13128
/* 13120 */   MCD_OPC_CheckPredicate, 14, 4, 0, // Skip to: 13128
/* 13124 */   MCD_OPC_Decode, 196, 10, 10, // Opcode: SDC2
/* 13128 */   MCD_OPC_Fail,
  0
};

static uint8_t DecoderTableMips32r6_64r632[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 205, 1, // Skip to: 468
/* 7 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10 */      MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 29
/* 14 */      MCD_OPC_CheckPredicate, 33, 38, 7, // Skip to: 1848
/* 18 */      MCD_OPC_CheckField, 8, 3, 0, 32, 7, // Skip to: 1848
/* 24 */      MCD_OPC_Decode, 147, 7, 194, 1, // Opcode: LSA_R6
/* 29 */      MCD_OPC_FilterValue, 9, 14, 0, // Skip to: 47
/* 33 */      MCD_OPC_CheckPredicate, 33, 19, 7, // Skip to: 1848
/* 37 */      MCD_OPC_CheckField, 6, 15, 16, 13, 7, // Skip to: 1848
/* 43 */      MCD_OPC_Decode, 216, 6, 38, // Opcode: JR_HB_R6
/* 47 */      MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 59
/* 51 */      MCD_OPC_CheckPredicate, 33, 1, 7, // Skip to: 1848
/* 55 */      MCD_OPC_Decode, 192, 10, 41, // Opcode: SDBBP_R6
/* 59 */      MCD_OPC_FilterValue, 16, 20, 0, // Skip to: 83
/* 63 */      MCD_OPC_CheckPredicate, 33, 245, 6, // Skip to: 1848
/* 67 */      MCD_OPC_CheckField, 16, 5, 0, 239, 6, // Skip to: 1848
/* 73 */      MCD_OPC_CheckField, 6, 5, 1, 233, 6, // Skip to: 1848
/* 79 */      MCD_OPC_Decode, 236, 2, 39, // Opcode: CLZ_R6
/* 83 */      MCD_OPC_FilterValue, 17, 20, 0, // Skip to: 107
/* 87 */      MCD_OPC_CheckPredicate, 33, 221, 6, // Skip to: 1848
/* 91 */      MCD_OPC_CheckField, 16, 5, 0, 215, 6, // Skip to: 1848
/* 97 */      MCD_OPC_CheckField, 6, 5, 1, 209, 6, // Skip to: 1848
/* 103 */     MCD_OPC_Decode, 217, 2, 39, // Opcode: CLO_R6
/* 107 */     MCD_OPC_FilterValue, 18, 21, 0, // Skip to: 132
/* 111 */     MCD_OPC_CheckPredicate, 34, 197, 6, // Skip to: 1848
/* 115 */     MCD_OPC_CheckField, 16, 5, 0, 191, 6, // Skip to: 1848
/* 121 */     MCD_OPC_CheckField, 6, 5, 1, 185, 6, // Skip to: 1848
/* 127 */     MCD_OPC_Decode, 253, 3, 195, 1, // Opcode: DCLZ_R6
/* 132 */     MCD_OPC_FilterValue, 19, 21, 0, // Skip to: 157
/* 136 */     MCD_OPC_CheckPredicate, 34, 172, 6, // Skip to: 1848
/* 140 */     MCD_OPC_CheckField, 16, 5, 0, 166, 6, // Skip to: 1848
/* 146 */     MCD_OPC_CheckField, 6, 5, 1, 160, 6, // Skip to: 1848
/* 152 */     MCD_OPC_Decode, 251, 3, 195, 1, // Opcode: DCLO_R6
/* 157 */     MCD_OPC_FilterValue, 21, 15, 0, // Skip to: 176
/* 161 */     MCD_OPC_CheckPredicate, 34, 147, 6, // Skip to: 1848
/* 165 */     MCD_OPC_CheckField, 8, 3, 0, 141, 6, // Skip to: 1848
/* 171 */     MCD_OPC_Decode, 149, 4, 196, 1, // Opcode: DLSA_R6
/* 176 */     MCD_OPC_FilterValue, 24, 27, 0, // Skip to: 207
/* 180 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 183 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 195
/* 187 */     MCD_OPC_CheckPredicate, 33, 121, 6, // Skip to: 1848
/* 191 */     MCD_OPC_Decode, 153, 9, 16, // Opcode: MUL_R6
/* 195 */     MCD_OPC_FilterValue, 3, 113, 6, // Skip to: 1848
/* 199 */     MCD_OPC_CheckPredicate, 33, 109, 6, // Skip to: 1848
/* 203 */     MCD_OPC_Decode, 251, 8, 16, // Opcode: MUH
/* 207 */     MCD_OPC_FilterValue, 25, 27, 0, // Skip to: 238
/* 211 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 214 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 226
/* 218 */     MCD_OPC_CheckPredicate, 33, 90, 6, // Skip to: 1848
/* 222 */     MCD_OPC_Decode, 144, 9, 16, // Opcode: MULU
/* 226 */     MCD_OPC_FilterValue, 3, 82, 6, // Skip to: 1848
/* 230 */     MCD_OPC_CheckPredicate, 33, 78, 6, // Skip to: 1848
/* 234 */     MCD_OPC_Decode, 252, 8, 16, // Opcode: MUHU
/* 238 */     MCD_OPC_FilterValue, 26, 27, 0, // Skip to: 269
/* 242 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 245 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 257
/* 249 */     MCD_OPC_CheckPredicate, 33, 59, 6, // Skip to: 1848
/* 253 */     MCD_OPC_Decode, 137, 4, 16, // Opcode: DIV
/* 257 */     MCD_OPC_FilterValue, 3, 51, 6, // Skip to: 1848
/* 261 */     MCD_OPC_CheckPredicate, 33, 47, 6, // Skip to: 1848
/* 265 */     MCD_OPC_Decode, 155, 8, 16, // Opcode: MOD
/* 269 */     MCD_OPC_FilterValue, 27, 27, 0, // Skip to: 300
/* 273 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 276 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 288
/* 280 */     MCD_OPC_CheckPredicate, 33, 28, 6, // Skip to: 1848
/* 284 */     MCD_OPC_Decode, 138, 4, 16, // Opcode: DIVU
/* 288 */     MCD_OPC_FilterValue, 3, 20, 6, // Skip to: 1848
/* 292 */     MCD_OPC_CheckPredicate, 33, 16, 6, // Skip to: 1848
/* 296 */     MCD_OPC_Decode, 157, 8, 16, // Opcode: MODU
/* 300 */     MCD_OPC_FilterValue, 28, 29, 0, // Skip to: 333
/* 304 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 307 */     MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 320
/* 311 */     MCD_OPC_CheckPredicate, 34, 253, 5, // Skip to: 1848
/* 315 */     MCD_OPC_Decode, 164, 4, 197, 1, // Opcode: DMUL_R6
/* 320 */     MCD_OPC_FilterValue, 3, 244, 5, // Skip to: 1848
/* 324 */     MCD_OPC_CheckPredicate, 34, 240, 5, // Skip to: 1848
/* 328 */     MCD_OPC_Decode, 158, 4, 197, 1, // Opcode: DMUH
/* 333 */     MCD_OPC_FilterValue, 29, 29, 0, // Skip to: 366
/* 337 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 340 */     MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 353
/* 344 */     MCD_OPC_CheckPredicate, 34, 220, 5, // Skip to: 1848
/* 348 */     MCD_OPC_Decode, 163, 4, 197, 1, // Opcode: DMULU
/* 353 */     MCD_OPC_FilterValue, 3, 211, 5, // Skip to: 1848
/* 357 */     MCD_OPC_CheckPredicate, 34, 207, 5, // Skip to: 1848
/* 361 */     MCD_OPC_Decode, 159, 4, 197, 1, // Opcode: DMUHU
/* 366 */     MCD_OPC_FilterValue, 30, 29, 0, // Skip to: 399
/* 370 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 373 */     MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 386
/* 377 */     MCD_OPC_CheckPredicate, 34, 187, 5, // Skip to: 1848
/* 381 */     MCD_OPC_Decode, 254, 3, 197, 1, // Opcode: DDIV
/* 386 */     MCD_OPC_FilterValue, 3, 178, 5, // Skip to: 1848
/* 390 */     MCD_OPC_CheckPredicate, 34, 174, 5, // Skip to: 1848
/* 394 */     MCD_OPC_Decode, 153, 4, 197, 1, // Opcode: DMOD
/* 399 */     MCD_OPC_FilterValue, 31, 29, 0, // Skip to: 432
/* 403 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 406 */     MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 419
/* 410 */     MCD_OPC_CheckPredicate, 34, 154, 5, // Skip to: 1848
/* 414 */     MCD_OPC_Decode, 255, 3, 197, 1, // Opcode: DDIVU
/* 419 */     MCD_OPC_FilterValue, 3, 145, 5, // Skip to: 1848
/* 423 */     MCD_OPC_CheckPredicate, 34, 141, 5, // Skip to: 1848
/* 427 */     MCD_OPC_Decode, 154, 4, 197, 1, // Opcode: DMODU
/* 432 */     MCD_OPC_FilterValue, 53, 14, 0, // Skip to: 450
/* 436 */     MCD_OPC_CheckPredicate, 35, 128, 5, // Skip to: 1848
/* 440 */     MCD_OPC_CheckField, 6, 5, 0, 122, 5, // Skip to: 1848
/* 446 */     MCD_OPC_Decode, 211, 10, 16, // Opcode: SELEQZ
/* 450 */     MCD_OPC_FilterValue, 55, 114, 5, // Skip to: 1848
/* 454 */     MCD_OPC_CheckPredicate, 35, 110, 5, // Skip to: 1848
/* 458 */     MCD_OPC_CheckField, 6, 5, 0, 104, 5, // Skip to: 1848
/* 464 */     MCD_OPC_Decode, 215, 10, 16, // Opcode: SELNEZ
/* 468 */     MCD_OPC_FilterValue, 1, 47, 0, // Skip to: 519
/* 472 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 475 */     MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 488
/* 479 */     MCD_OPC_CheckPredicate, 34, 85, 5, // Skip to: 1848
/* 483 */     MCD_OPC_Decode, 245, 3, 198, 1, // Opcode: DAHI
/* 488 */     MCD_OPC_FilterValue, 17, 14, 0, // Skip to: 506
/* 492 */     MCD_OPC_CheckPredicate, 33, 72, 5, // Skip to: 1848
/* 496 */     MCD_OPC_CheckField, 21, 5, 0, 66, 5, // Skip to: 1848
/* 502 */     MCD_OPC_Decode, 156, 1, 52, // Opcode: BAL
/* 506 */     MCD_OPC_FilterValue, 30, 58, 5, // Skip to: 1848
/* 510 */     MCD_OPC_CheckPredicate, 34, 54, 5, // Skip to: 1848
/* 514 */     MCD_OPC_Decode, 247, 3, 198, 1, // Opcode: DATI
/* 519 */     MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 532
/* 523 */     MCD_OPC_CheckPredicate, 33, 41, 5, // Skip to: 1848
/* 527 */     MCD_OPC_Decode, 188, 1, 199, 1, // Opcode: BGEZALC
/* 532 */     MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 545
/* 536 */     MCD_OPC_CheckPredicate, 33, 28, 5, // Skip to: 1848
/* 540 */     MCD_OPC_Decode, 225, 1, 200, 1, // Opcode: BLTZALC
/* 545 */     MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 558
/* 549 */     MCD_OPC_CheckPredicate, 33, 15, 5, // Skip to: 1848
/* 553 */     MCD_OPC_Decode, 179, 1, 201, 1, // Opcode: BEQC
/* 558 */     MCD_OPC_FilterValue, 15, 7, 0, // Skip to: 569
/* 562 */     MCD_OPC_CheckPredicate, 33, 2, 5, // Skip to: 1848
/* 566 */     MCD_OPC_Decode, 127, 26, // Opcode: AUI
/* 569 */     MCD_OPC_FilterValue, 17, 5, 3, // Skip to: 1346
/* 573 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 576 */     MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 589
/* 580 */     MCD_OPC_CheckPredicate, 33, 240, 4, // Skip to: 1848
/* 584 */     MCD_OPC_Decode, 161, 1, 202, 1, // Opcode: BC1EQZ
/* 589 */     MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 602
/* 593 */     MCD_OPC_CheckPredicate, 33, 227, 4, // Skip to: 1848
/* 597 */     MCD_OPC_Decode, 164, 1, 202, 1, // Opcode: BC1NEZ
/* 602 */     MCD_OPC_FilterValue, 16, 150, 0, // Skip to: 756
/* 606 */     MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 609 */     MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 622
/* 613 */     MCD_OPC_CheckPredicate, 33, 207, 4, // Skip to: 1848
/* 617 */     MCD_OPC_Decode, 220, 10, 203, 1, // Opcode: SEL_S
/* 622 */     MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 634
/* 626 */     MCD_OPC_CheckPredicate, 33, 194, 4, // Skip to: 1848
/* 630 */     MCD_OPC_Decode, 214, 10, 68, // Opcode: SELEQZ_S
/* 634 */     MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 646
/* 638 */     MCD_OPC_CheckPredicate, 33, 182, 4, // Skip to: 1848
/* 642 */     MCD_OPC_Decode, 218, 10, 68, // Opcode: SELNEZ_S
/* 646 */     MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 659
/* 650 */     MCD_OPC_CheckPredicate, 33, 170, 4, // Skip to: 1848
/* 654 */     MCD_OPC_Decode, 193, 7, 204, 1, // Opcode: MADDF_S
/* 659 */     MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 672
/* 663 */     MCD_OPC_CheckPredicate, 33, 157, 4, // Skip to: 1848
/* 667 */     MCD_OPC_Decode, 210, 8, 204, 1, // Opcode: MSUBF_S
/* 672 */     MCD_OPC_FilterValue, 26, 14, 0, // Skip to: 690
/* 676 */     MCD_OPC_CheckPredicate, 33, 144, 4, // Skip to: 1848
/* 680 */     MCD_OPC_CheckField, 16, 5, 0, 138, 4, // Skip to: 1848
/* 686 */     MCD_OPC_Decode, 158, 10, 69, // Opcode: RINT_S
/* 690 */     MCD_OPC_FilterValue, 27, 14, 0, // Skip to: 708
/* 694 */     MCD_OPC_CheckPredicate, 33, 126, 4, // Skip to: 1848
/* 698 */     MCD_OPC_CheckField, 16, 5, 0, 120, 4, // Skip to: 1848
/* 704 */     MCD_OPC_Decode, 198, 2, 69, // Opcode: CLASS_S
/* 708 */     MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 720
/* 712 */     MCD_OPC_CheckPredicate, 33, 108, 4, // Skip to: 1848
/* 716 */     MCD_OPC_Decode, 144, 8, 68, // Opcode: MIN_S
/* 720 */     MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 732
/* 724 */     MCD_OPC_CheckPredicate, 33, 96, 4, // Skip to: 1848
/* 728 */     MCD_OPC_Decode, 231, 7, 68, // Opcode: MAX_S
/* 732 */     MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 744
/* 736 */     MCD_OPC_CheckPredicate, 33, 84, 4, // Skip to: 1848
/* 740 */     MCD_OPC_Decode, 130, 8, 68, // Opcode: MINA_S
/* 744 */     MCD_OPC_FilterValue, 31, 76, 4, // Skip to: 1848
/* 748 */     MCD_OPC_CheckPredicate, 33, 72, 4, // Skip to: 1848
/* 752 */     MCD_OPC_Decode, 217, 7, 68, // Opcode: MAXA_S
/* 756 */     MCD_OPC_FilterValue, 17, 156, 0, // Skip to: 916
/* 760 */     MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 763 */     MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 776
/* 767 */     MCD_OPC_CheckPredicate, 33, 53, 4, // Skip to: 1848
/* 771 */     MCD_OPC_Decode, 219, 10, 205, 1, // Opcode: SEL_D
/* 776 */     MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 789
/* 780 */     MCD_OPC_CheckPredicate, 33, 40, 4, // Skip to: 1848
/* 784 */     MCD_OPC_Decode, 213, 10, 206, 1, // Opcode: SELEQZ_D
/* 789 */     MCD_OPC_FilterValue, 23, 9, 0, // Skip to: 802
/* 793 */     MCD_OPC_CheckPredicate, 33, 27, 4, // Skip to: 1848
/* 797 */     MCD_OPC_Decode, 217, 10, 206, 1, // Opcode: SELNEZ_D
/* 802 */     MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 815
/* 806 */     MCD_OPC_CheckPredicate, 33, 14, 4, // Skip to: 1848
/* 810 */     MCD_OPC_Decode, 192, 7, 207, 1, // Opcode: MADDF_D
/* 815 */     MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 828
/* 819 */     MCD_OPC_CheckPredicate, 33, 1, 4, // Skip to: 1848
/* 823 */     MCD_OPC_Decode, 209, 8, 207, 1, // Opcode: MSUBF_D
/* 828 */     MCD_OPC_FilterValue, 26, 14, 0, // Skip to: 846
/* 832 */     MCD_OPC_CheckPredicate, 33, 244, 3, // Skip to: 1848
/* 836 */     MCD_OPC_CheckField, 16, 5, 0, 238, 3, // Skip to: 1848
/* 842 */     MCD_OPC_Decode, 157, 10, 80, // Opcode: RINT_D
/* 846 */     MCD_OPC_FilterValue, 27, 14, 0, // Skip to: 864
/* 850 */     MCD_OPC_CheckPredicate, 33, 226, 3, // Skip to: 1848
/* 854 */     MCD_OPC_CheckField, 16, 5, 0, 220, 3, // Skip to: 1848
/* 860 */     MCD_OPC_Decode, 197, 2, 80, // Opcode: CLASS_D
/* 864 */     MCD_OPC_FilterValue, 28, 9, 0, // Skip to: 877
/* 868 */     MCD_OPC_CheckPredicate, 33, 208, 3, // Skip to: 1848
/* 872 */     MCD_OPC_Decode, 143, 8, 206, 1, // Opcode: MIN_D
/* 877 */     MCD_OPC_FilterValue, 29, 9, 0, // Skip to: 890
/* 881 */     MCD_OPC_CheckPredicate, 33, 195, 3, // Skip to: 1848
/* 885 */     MCD_OPC_Decode, 230, 7, 206, 1, // Opcode: MAX_D
/* 890 */     MCD_OPC_FilterValue, 30, 9, 0, // Skip to: 903
/* 894 */     MCD_OPC_CheckPredicate, 33, 182, 3, // Skip to: 1848
/* 898 */     MCD_OPC_Decode, 129, 8, 206, 1, // Opcode: MINA_D
/* 903 */     MCD_OPC_FilterValue, 31, 173, 3, // Skip to: 1848
/* 907 */     MCD_OPC_CheckPredicate, 33, 169, 3, // Skip to: 1848
/* 911 */     MCD_OPC_Decode, 216, 7, 206, 1, // Opcode: MAXA_D
/* 916 */     MCD_OPC_FilterValue, 20, 211, 0, // Skip to: 1131
/* 920 */     MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 923 */     MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 936
/* 927 */     MCD_OPC_CheckPredicate, 33, 149, 3, // Skip to: 1848
/* 931 */     MCD_OPC_Decode, 250, 2, 208, 1, // Opcode: CMP_F_S
/* 936 */     MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 949
/* 940 */     MCD_OPC_CheckPredicate, 33, 136, 3, // Skip to: 1848
/* 944 */     MCD_OPC_Decode, 152, 3, 208, 1, // Opcode: CMP_UN_S
/* 949 */     MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 962
/* 953 */     MCD_OPC_CheckPredicate, 33, 123, 3, // Skip to: 1848
/* 957 */     MCD_OPC_Decode, 248, 2, 208, 1, // Opcode: CMP_EQ_S
/* 962 */     MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 975
/* 966 */     MCD_OPC_CheckPredicate, 33, 110, 3, // Skip to: 1848
/* 970 */     MCD_OPC_Decode, 146, 3, 208, 1, // Opcode: CMP_UEQ_S
/* 975 */     MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 988
/* 979 */     MCD_OPC_CheckPredicate, 33, 97, 3, // Skip to: 1848
/* 983 */     MCD_OPC_Decode, 128, 3, 208, 1, // Opcode: CMP_LT_S
/* 988 */     MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 1001
/* 992 */     MCD_OPC_CheckPredicate, 33, 84, 3, // Skip to: 1848
/* 996 */     MCD_OPC_Decode, 150, 3, 208, 1, // Opcode: CMP_ULT_S
/* 1001 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 1014
/* 1005 */    MCD_OPC_CheckPredicate, 33, 71, 3, // Skip to: 1848
/* 1009 */    MCD_OPC_Decode, 253, 2, 208, 1, // Opcode: CMP_LE_S
/* 1014 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 1027
/* 1018 */    MCD_OPC_CheckPredicate, 33, 58, 3, // Skip to: 1848
/* 1022 */    MCD_OPC_Decode, 148, 3, 208, 1, // Opcode: CMP_ULE_S
/* 1027 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 1040
/* 1031 */    MCD_OPC_CheckPredicate, 33, 45, 3, // Skip to: 1848
/* 1035 */    MCD_OPC_Decode, 130, 3, 208, 1, // Opcode: CMP_SAF_S
/* 1040 */    MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 1053
/* 1044 */    MCD_OPC_CheckPredicate, 33, 32, 3, // Skip to: 1848
/* 1048 */    MCD_OPC_Decode, 144, 3, 208, 1, // Opcode: CMP_SUN_S
/* 1053 */    MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 1066
/* 1057 */    MCD_OPC_CheckPredicate, 33, 19, 3, // Skip to: 1848
/* 1061 */    MCD_OPC_Decode, 132, 3, 208, 1, // Opcode: CMP_SEQ_S
/* 1066 */    MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 1079
/* 1070 */    MCD_OPC_CheckPredicate, 33, 6, 3, // Skip to: 1848
/* 1074 */    MCD_OPC_Decode, 138, 3, 208, 1, // Opcode: CMP_SUEQ_S
/* 1079 */    MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 1092
/* 1083 */    MCD_OPC_CheckPredicate, 33, 249, 2, // Skip to: 1848
/* 1087 */    MCD_OPC_Decode, 136, 3, 208, 1, // Opcode: CMP_SLT_S
/* 1092 */    MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 1105
/* 1096 */    MCD_OPC_CheckPredicate, 33, 236, 2, // Skip to: 1848
/* 1100 */    MCD_OPC_Decode, 142, 3, 208, 1, // Opcode: CMP_SULT_S
/* 1105 */    MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 1118
/* 1109 */    MCD_OPC_CheckPredicate, 33, 223, 2, // Skip to: 1848
/* 1113 */    MCD_OPC_Decode, 134, 3, 208, 1, // Opcode: CMP_SLE_S
/* 1118 */    MCD_OPC_FilterValue, 15, 214, 2, // Skip to: 1848
/* 1122 */    MCD_OPC_CheckPredicate, 33, 210, 2, // Skip to: 1848
/* 1126 */    MCD_OPC_Decode, 140, 3, 208, 1, // Opcode: CMP_SULE_S
/* 1131 */    MCD_OPC_FilterValue, 21, 201, 2, // Skip to: 1848
/* 1135 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1138 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 1151
/* 1142 */    MCD_OPC_CheckPredicate, 33, 190, 2, // Skip to: 1848
/* 1146 */    MCD_OPC_Decode, 249, 2, 209, 1, // Opcode: CMP_F_D
/* 1151 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 1164
/* 1155 */    MCD_OPC_CheckPredicate, 33, 177, 2, // Skip to: 1848
/* 1159 */    MCD_OPC_Decode, 151, 3, 209, 1, // Opcode: CMP_UN_D
/* 1164 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 1177
/* 1168 */    MCD_OPC_CheckPredicate, 33, 164, 2, // Skip to: 1848
/* 1172 */    MCD_OPC_Decode, 246, 2, 209, 1, // Opcode: CMP_EQ_D
/* 1177 */    MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 1190
/* 1181 */    MCD_OPC_CheckPredicate, 33, 151, 2, // Skip to: 1848
/* 1185 */    MCD_OPC_Decode, 145, 3, 209, 1, // Opcode: CMP_UEQ_D
/* 1190 */    MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 1203
/* 1194 */    MCD_OPC_CheckPredicate, 33, 138, 2, // Skip to: 1848
/* 1198 */    MCD_OPC_Decode, 254, 2, 209, 1, // Opcode: CMP_LT_D
/* 1203 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 1216
/* 1207 */    MCD_OPC_CheckPredicate, 33, 125, 2, // Skip to: 1848
/* 1211 */    MCD_OPC_Decode, 149, 3, 209, 1, // Opcode: CMP_ULT_D
/* 1216 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 1229
/* 1220 */    MCD_OPC_CheckPredicate, 33, 112, 2, // Skip to: 1848
/* 1224 */    MCD_OPC_Decode, 251, 2, 209, 1, // Opcode: CMP_LE_D
/* 1229 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 1242
/* 1233 */    MCD_OPC_CheckPredicate, 33, 99, 2, // Skip to: 1848
/* 1237 */    MCD_OPC_Decode, 147, 3, 209, 1, // Opcode: CMP_ULE_D
/* 1242 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 1255
/* 1246 */    MCD_OPC_CheckPredicate, 33, 86, 2, // Skip to: 1848
/* 1250 */    MCD_OPC_Decode, 129, 3, 209, 1, // Opcode: CMP_SAF_D
/* 1255 */    MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 1268
/* 1259 */    MCD_OPC_CheckPredicate, 33, 73, 2, // Skip to: 1848
/* 1263 */    MCD_OPC_Decode, 143, 3, 209, 1, // Opcode: CMP_SUN_D
/* 1268 */    MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 1281
/* 1272 */    MCD_OPC_CheckPredicate, 33, 60, 2, // Skip to: 1848
/* 1276 */    MCD_OPC_Decode, 131, 3, 209, 1, // Opcode: CMP_SEQ_D
/* 1281 */    MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 1294
/* 1285 */    MCD_OPC_CheckPredicate, 33, 47, 2, // Skip to: 1848
/* 1289 */    MCD_OPC_Decode, 137, 3, 209, 1, // Opcode: CMP_SUEQ_D
/* 1294 */    MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 1307
/* 1298 */    MCD_OPC_CheckPredicate, 33, 34, 2, // Skip to: 1848
/* 1302 */    MCD_OPC_Decode, 135, 3, 209, 1, // Opcode: CMP_SLT_D
/* 1307 */    MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 1320
/* 1311 */    MCD_OPC_CheckPredicate, 33, 21, 2, // Skip to: 1848
/* 1315 */    MCD_OPC_Decode, 141, 3, 209, 1, // Opcode: CMP_SULT_D
/* 1320 */    MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 1333
/* 1324 */    MCD_OPC_CheckPredicate, 33, 8, 2, // Skip to: 1848
/* 1328 */    MCD_OPC_Decode, 133, 3, 209, 1, // Opcode: CMP_SLE_D
/* 1333 */    MCD_OPC_FilterValue, 15, 255, 1, // Skip to: 1848
/* 1337 */    MCD_OPC_CheckPredicate, 33, 251, 1, // Skip to: 1848
/* 1341 */    MCD_OPC_Decode, 139, 3, 209, 1, // Opcode: CMP_SULE_D
/* 1346 */    MCD_OPC_FilterValue, 18, 81, 0, // Skip to: 1431
/* 1350 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1353 */    MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 1366
/* 1357 */    MCD_OPC_CheckPredicate, 33, 231, 1, // Skip to: 1848
/* 1361 */    MCD_OPC_Decode, 167, 1, 210, 1, // Opcode: BC2EQZ
/* 1366 */    MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 1379
/* 1370 */    MCD_OPC_CheckPredicate, 33, 218, 1, // Skip to: 1848
/* 1374 */    MCD_OPC_Decode, 159, 7, 211, 1, // Opcode: LWC2_R6
/* 1379 */    MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 1392
/* 1383 */    MCD_OPC_CheckPredicate, 33, 205, 1, // Skip to: 1848
/* 1387 */    MCD_OPC_Decode, 144, 12, 211, 1, // Opcode: SWC2_R6
/* 1392 */    MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 1405
/* 1396 */    MCD_OPC_CheckPredicate, 33, 192, 1, // Skip to: 1848
/* 1400 */    MCD_OPC_Decode, 168, 1, 210, 1, // Opcode: BC2NEZ
/* 1405 */    MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 1418
/* 1409 */    MCD_OPC_CheckPredicate, 33, 179, 1, // Skip to: 1848
/* 1413 */    MCD_OPC_Decode, 237, 6, 211, 1, // Opcode: LDC2_R6
/* 1418 */    MCD_OPC_FilterValue, 15, 170, 1, // Skip to: 1848
/* 1422 */    MCD_OPC_CheckPredicate, 33, 166, 1, // Skip to: 1848
/* 1426 */    MCD_OPC_Decode, 197, 10, 211, 1, // Opcode: SDC2_R6
/* 1431 */    MCD_OPC_FilterValue, 22, 9, 0, // Skip to: 1444
/* 1435 */    MCD_OPC_CheckPredicate, 33, 153, 1, // Skip to: 1848
/* 1439 */    MCD_OPC_Decode, 190, 1, 212, 1, // Opcode: BGEZC
/* 1444 */    MCD_OPC_FilterValue, 23, 9, 0, // Skip to: 1457
/* 1448 */    MCD_OPC_CheckPredicate, 33, 140, 1, // Skip to: 1848
/* 1452 */    MCD_OPC_Decode, 227, 1, 213, 1, // Opcode: BLTZC
/* 1457 */    MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 1470
/* 1461 */    MCD_OPC_CheckPredicate, 33, 127, 1, // Skip to: 1848
/* 1465 */    MCD_OPC_Decode, 235, 1, 214, 1, // Opcode: BNEC
/* 1470 */    MCD_OPC_FilterValue, 29, 9, 0, // Skip to: 1483
/* 1474 */    MCD_OPC_CheckPredicate, 34, 114, 1, // Skip to: 1848
/* 1478 */    MCD_OPC_Decode, 248, 3, 215, 1, // Opcode: DAUI
/* 1483 */    MCD_OPC_FilterValue, 31, 182, 0, // Skip to: 1669
/* 1487 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1490 */    MCD_OPC_FilterValue, 32, 40, 0, // Skip to: 1534
/* 1494 */    MCD_OPC_ExtractField, 8, 3,  // Inst{10-8} ...
/* 1497 */    MCD_OPC_FilterValue, 0, 21, 0, // Skip to: 1522
/* 1501 */    MCD_OPC_CheckPredicate, 33, 87, 1, // Skip to: 1848
/* 1505 */    MCD_OPC_CheckField, 21, 5, 0, 81, 1, // Skip to: 1848
/* 1511 */    MCD_OPC_CheckField, 6, 2, 0, 75, 1, // Skip to: 1848
/* 1517 */    MCD_OPC_Decode, 214, 1, 180, 1, // Opcode: BITSWAP
/* 1522 */    MCD_OPC_FilterValue, 2, 66, 1, // Skip to: 1848
/* 1526 */    MCD_OPC_CheckPredicate, 33, 62, 1, // Skip to: 1848
/* 1530 */    MCD_OPC_Decode, 73, 194, 1, // Opcode: ALIGN
/* 1534 */    MCD_OPC_FilterValue, 36, 41, 0, // Skip to: 1579
/* 1538 */    MCD_OPC_ExtractField, 9, 2,  // Inst{10-9} ...
/* 1541 */    MCD_OPC_FilterValue, 0, 21, 0, // Skip to: 1566
/* 1545 */    MCD_OPC_CheckPredicate, 34, 43, 1, // Skip to: 1848
/* 1549 */    MCD_OPC_CheckField, 21, 5, 0, 37, 1, // Skip to: 1848
/* 1555 */    MCD_OPC_CheckField, 6, 3, 0, 31, 1, // Skip to: 1848
/* 1561 */    MCD_OPC_Decode, 249, 3, 216, 1, // Opcode: DBITSWAP
/* 1566 */    MCD_OPC_FilterValue, 1, 22, 1, // Skip to: 1848
/* 1570 */    MCD_OPC_CheckPredicate, 34, 18, 1, // Skip to: 1848
/* 1574 */    MCD_OPC_Decode, 246, 3, 217, 1, // Opcode: DALIGN
/* 1579 */    MCD_OPC_FilterValue, 37, 15, 0, // Skip to: 1598
/* 1583 */    MCD_OPC_CheckPredicate, 33, 5, 1, // Skip to: 1848
/* 1587 */    MCD_OPC_CheckField, 6, 1, 0, 255, 0, // Skip to: 1848
/* 1593 */    MCD_OPC_Decode, 176, 2, 218, 1, // Opcode: CACHE_R6
/* 1598 */    MCD_OPC_FilterValue, 38, 9, 0, // Skip to: 1611
/* 1602 */    MCD_OPC_CheckPredicate, 33, 242, 0, // Skip to: 1848
/* 1606 */    MCD_OPC_Decode, 189, 10, 219, 1, // Opcode: SC_R6
/* 1611 */    MCD_OPC_FilterValue, 39, 9, 0, // Skip to: 1624
/* 1615 */    MCD_OPC_CheckPredicate, 33, 229, 0, // Skip to: 1848
/* 1619 */    MCD_OPC_Decode, 187, 10, 219, 1, // Opcode: SCD_R6
/* 1624 */    MCD_OPC_FilterValue, 53, 15, 0, // Skip to: 1643
/* 1628 */    MCD_OPC_CheckPredicate, 33, 216, 0, // Skip to: 1848
/* 1632 */    MCD_OPC_CheckField, 6, 1, 0, 210, 0, // Skip to: 1848
/* 1638 */    MCD_OPC_Decode, 239, 9, 218, 1, // Opcode: PREF_R6
/* 1643 */    MCD_OPC_FilterValue, 54, 9, 0, // Skip to: 1656
/* 1647 */    MCD_OPC_CheckPredicate, 33, 197, 0, // Skip to: 1848
/* 1651 */    MCD_OPC_Decode, 138, 7, 219, 1, // Opcode: LL_R6
/* 1656 */    MCD_OPC_FilterValue, 55, 188, 0, // Skip to: 1848
/* 1660 */    MCD_OPC_CheckPredicate, 33, 184, 0, // Skip to: 1848
/* 1664 */    MCD_OPC_Decode, 136, 7, 219, 1, // Opcode: LLD_R6
/* 1669 */    MCD_OPC_FilterValue, 50, 9, 0, // Skip to: 1682
/* 1673 */    MCD_OPC_CheckPredicate, 33, 171, 0, // Skip to: 1848
/* 1677 */    MCD_OPC_Decode, 160, 1, 220, 1, // Opcode: BC
/* 1682 */    MCD_OPC_FilterValue, 54, 24, 0, // Skip to: 1710
/* 1686 */    MCD_OPC_CheckPredicate, 33, 11, 0, // Skip to: 1701
/* 1690 */    MCD_OPC_CheckField, 21, 5, 0, 5, 0, // Skip to: 1701
/* 1696 */    MCD_OPC_Decode, 212, 6, 221, 1, // Opcode: JIC
/* 1701 */    MCD_OPC_CheckPredicate, 33, 143, 0, // Skip to: 1848
/* 1705 */    MCD_OPC_Decode, 181, 1, 222, 1, // Opcode: BEQZC
/* 1710 */    MCD_OPC_FilterValue, 58, 9, 0, // Skip to: 1723
/* 1714 */    MCD_OPC_CheckPredicate, 33, 130, 0, // Skip to: 1848
/* 1718 */    MCD_OPC_Decode, 157, 1, 220, 1, // Opcode: BALC
/* 1723 */    MCD_OPC_FilterValue, 59, 93, 0, // Skip to: 1820
/* 1727 */    MCD_OPC_ExtractField, 19, 2,  // Inst{20-19} ...
/* 1730 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1742
/* 1734 */    MCD_OPC_CheckPredicate, 33, 110, 0, // Skip to: 1848
/* 1738 */    MCD_OPC_Decode, 24, 223, 1, // Opcode: ADDIUPC
/* 1742 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 1755
/* 1746 */    MCD_OPC_CheckPredicate, 33, 98, 0, // Skip to: 1848
/* 1750 */    MCD_OPC_Decode, 164, 7, 223, 1, // Opcode: LWPC
/* 1755 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 1768
/* 1759 */    MCD_OPC_CheckPredicate, 33, 85, 0, // Skip to: 1848
/* 1763 */    MCD_OPC_Decode, 168, 7, 223, 1, // Opcode: LWUPC
/* 1768 */    MCD_OPC_FilterValue, 3, 76, 0, // Skip to: 1848
/* 1772 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 1775 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 1788
/* 1779 */    MCD_OPC_CheckPredicate, 34, 65, 0, // Skip to: 1848
/* 1783 */    MCD_OPC_Decode, 244, 6, 224, 1, // Opcode: LDPC
/* 1788 */    MCD_OPC_FilterValue, 1, 56, 0, // Skip to: 1848
/* 1792 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 1795 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 1808
/* 1799 */    MCD_OPC_CheckPredicate, 33, 45, 0, // Skip to: 1848
/* 1803 */    MCD_OPC_Decode, 128, 1, 225, 1, // Opcode: AUIPC
/* 1808 */    MCD_OPC_FilterValue, 3, 36, 0, // Skip to: 1848
/* 1812 */    MCD_OPC_CheckPredicate, 33, 32, 0, // Skip to: 1848
/* 1816 */    MCD_OPC_Decode, 74, 225, 1, // Opcode: ALUIPC
/* 1820 */    MCD_OPC_FilterValue, 62, 24, 0, // Skip to: 1848
/* 1824 */    MCD_OPC_CheckPredicate, 33, 11, 0, // Skip to: 1839
/* 1828 */    MCD_OPC_CheckField, 21, 5, 0, 5, 0, // Skip to: 1839
/* 1834 */    MCD_OPC_Decode, 211, 6, 221, 1, // Opcode: JIALC
/* 1839 */    MCD_OPC_CheckPredicate, 33, 5, 0, // Skip to: 1848
/* 1843 */    MCD_OPC_Decode, 245, 1, 222, 1, // Opcode: BNEZC
/* 1848 */    MCD_OPC_Fail,
  0
};

static uint8_t DecoderTableMips32r6_64r6_GP6432[] = {
/* 0 */       MCD_OPC_ExtractField, 0, 11,  // Inst{10-0} ...
/* 3 */       MCD_OPC_FilterValue, 53, 15, 0, // Skip to: 22
/* 7 */       MCD_OPC_CheckPredicate, 36, 30, 0, // Skip to: 41
/* 11 */      MCD_OPC_CheckField, 26, 6, 0, 24, 0, // Skip to: 41
/* 17 */      MCD_OPC_Decode, 212, 10, 197, 1, // Opcode: SELEQZ64
/* 22 */      MCD_OPC_FilterValue, 55, 15, 0, // Skip to: 41
/* 26 */      MCD_OPC_CheckPredicate, 36, 11, 0, // Skip to: 41
/* 30 */      MCD_OPC_CheckField, 26, 6, 0, 5, 0, // Skip to: 41
/* 36 */      MCD_OPC_Decode, 216, 10, 197, 1, // Opcode: SELNEZ64
/* 41 */      MCD_OPC_Fail,
  0
};

static uint8_t DecoderTableMips6432[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 112, 1, // Skip to: 375
/* 7 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10 */      MCD_OPC_FilterValue, 20, 15, 0, // Skip to: 29
/* 14 */      MCD_OPC_CheckPredicate, 17, 192, 8, // Skip to: 2258
/* 18 */      MCD_OPC_CheckField, 6, 5, 0, 186, 8, // Skip to: 2258
/* 24 */      MCD_OPC_Decode, 209, 4, 226, 1, // Opcode: DSLLV
/* 29 */      MCD_OPC_FilterValue, 22, 29, 0, // Skip to: 62
/* 33 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 36 */      MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 49
/* 40 */      MCD_OPC_CheckPredicate, 17, 166, 8, // Skip to: 2258
/* 44 */      MCD_OPC_Decode, 215, 4, 226, 1, // Opcode: DSRLV
/* 49 */      MCD_OPC_FilterValue, 1, 157, 8, // Skip to: 2258
/* 53 */      MCD_OPC_CheckPredicate, 37, 153, 8, // Skip to: 2258
/* 57 */      MCD_OPC_Decode, 202, 4, 226, 1, // Opcode: DROTRV
/* 62 */      MCD_OPC_FilterValue, 23, 15, 0, // Skip to: 81
/* 66 */      MCD_OPC_CheckPredicate, 17, 140, 8, // Skip to: 2258
/* 70 */      MCD_OPC_CheckField, 6, 5, 0, 134, 8, // Skip to: 2258
/* 76 */      MCD_OPC_Decode, 212, 4, 226, 1, // Opcode: DSRAV
/* 81 */      MCD_OPC_FilterValue, 28, 15, 0, // Skip to: 100
/* 85 */      MCD_OPC_CheckPredicate, 38, 121, 8, // Skip to: 2258
/* 89 */      MCD_OPC_CheckField, 6, 10, 0, 115, 8, // Skip to: 2258
/* 95 */      MCD_OPC_Decode, 161, 4, 227, 1, // Opcode: DMULT
/* 100 */     MCD_OPC_FilterValue, 29, 15, 0, // Skip to: 119
/* 104 */     MCD_OPC_CheckPredicate, 38, 102, 8, // Skip to: 2258
/* 108 */     MCD_OPC_CheckField, 6, 10, 0, 96, 8, // Skip to: 2258
/* 114 */     MCD_OPC_Decode, 162, 4, 227, 1, // Opcode: DMULTu
/* 119 */     MCD_OPC_FilterValue, 30, 15, 0, // Skip to: 138
/* 123 */     MCD_OPC_CheckPredicate, 38, 83, 8, // Skip to: 2258
/* 127 */     MCD_OPC_CheckField, 6, 10, 0, 77, 8, // Skip to: 2258
/* 133 */     MCD_OPC_Decode, 204, 4, 227, 1, // Opcode: DSDIV
/* 138 */     MCD_OPC_FilterValue, 31, 15, 0, // Skip to: 157
/* 142 */     MCD_OPC_CheckPredicate, 38, 64, 8, // Skip to: 2258
/* 146 */     MCD_OPC_CheckField, 6, 10, 0, 58, 8, // Skip to: 2258
/* 152 */     MCD_OPC_Decode, 218, 4, 227, 1, // Opcode: DUDIV
/* 157 */     MCD_OPC_FilterValue, 44, 15, 0, // Skip to: 176
/* 161 */     MCD_OPC_CheckPredicate, 17, 45, 8, // Skip to: 2258
/* 165 */     MCD_OPC_CheckField, 6, 5, 0, 39, 8, // Skip to: 2258
/* 171 */     MCD_OPC_Decode, 241, 3, 197, 1, // Opcode: DADD
/* 176 */     MCD_OPC_FilterValue, 45, 15, 0, // Skip to: 195
/* 180 */     MCD_OPC_CheckPredicate, 17, 26, 8, // Skip to: 2258
/* 184 */     MCD_OPC_CheckField, 6, 5, 0, 20, 8, // Skip to: 2258
/* 190 */     MCD_OPC_Decode, 244, 3, 197, 1, // Opcode: DADDu
/* 195 */     MCD_OPC_FilterValue, 46, 15, 0, // Skip to: 214
/* 199 */     MCD_OPC_CheckPredicate, 17, 7, 8, // Skip to: 2258
/* 203 */     MCD_OPC_CheckField, 6, 5, 0, 1, 8, // Skip to: 2258
/* 209 */     MCD_OPC_Decode, 216, 4, 197, 1, // Opcode: DSUB
/* 214 */     MCD_OPC_FilterValue, 47, 15, 0, // Skip to: 233
/* 218 */     MCD_OPC_CheckPredicate, 17, 244, 7, // Skip to: 2258
/* 222 */     MCD_OPC_CheckField, 6, 5, 0, 238, 7, // Skip to: 2258
/* 228 */     MCD_OPC_Decode, 217, 4, 197, 1, // Opcode: DSUBu
/* 233 */     MCD_OPC_FilterValue, 56, 15, 0, // Skip to: 252
/* 237 */     MCD_OPC_CheckPredicate, 17, 225, 7, // Skip to: 2258
/* 241 */     MCD_OPC_CheckField, 21, 5, 0, 219, 7, // Skip to: 2258
/* 247 */     MCD_OPC_Decode, 206, 4, 228, 1, // Opcode: DSLL
/* 252 */     MCD_OPC_FilterValue, 58, 29, 0, // Skip to: 285
/* 256 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 259 */     MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 272
/* 263 */     MCD_OPC_CheckPredicate, 17, 199, 7, // Skip to: 2258
/* 267 */     MCD_OPC_Decode, 213, 4, 228, 1, // Opcode: DSRL
/* 272 */     MCD_OPC_FilterValue, 1, 190, 7, // Skip to: 2258
/* 276 */     MCD_OPC_CheckPredicate, 37, 186, 7, // Skip to: 2258
/* 280 */     MCD_OPC_Decode, 200, 4, 228, 1, // Opcode: DROTR
/* 285 */     MCD_OPC_FilterValue, 59, 15, 0, // Skip to: 304
/* 289 */     MCD_OPC_CheckPredicate, 17, 173, 7, // Skip to: 2258
/* 293 */     MCD_OPC_CheckField, 21, 5, 0, 167, 7, // Skip to: 2258
/* 299 */     MCD_OPC_Decode, 210, 4, 228, 1, // Opcode: DSRA
/* 304 */     MCD_OPC_FilterValue, 60, 15, 0, // Skip to: 323
/* 308 */     MCD_OPC_CheckPredicate, 17, 154, 7, // Skip to: 2258
/* 312 */     MCD_OPC_CheckField, 21, 5, 0, 148, 7, // Skip to: 2258
/* 318 */     MCD_OPC_Decode, 207, 4, 228, 1, // Opcode: DSLL32
/* 323 */     MCD_OPC_FilterValue, 62, 29, 0, // Skip to: 356
/* 327 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 330 */     MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 343
/* 334 */     MCD_OPC_CheckPredicate, 17, 128, 7, // Skip to: 2258
/* 338 */     MCD_OPC_Decode, 214, 4, 228, 1, // Opcode: DSRL32
/* 343 */     MCD_OPC_FilterValue, 1, 119, 7, // Skip to: 2258
/* 347 */     MCD_OPC_CheckPredicate, 37, 115, 7, // Skip to: 2258
/* 351 */     MCD_OPC_Decode, 201, 4, 228, 1, // Opcode: DROTR32
/* 356 */     MCD_OPC_FilterValue, 63, 106, 7, // Skip to: 2258
/* 360 */     MCD_OPC_CheckPredicate, 17, 102, 7, // Skip to: 2258
/* 364 */     MCD_OPC_CheckField, 21, 5, 0, 96, 7, // Skip to: 2258
/* 370 */     MCD_OPC_Decode, 211, 4, 228, 1, // Opcode: DSRA32
/* 375 */     MCD_OPC_FilterValue, 16, 41, 0, // Skip to: 420
/* 379 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 382 */     MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 401
/* 386 */     MCD_OPC_CheckPredicate, 39, 76, 7, // Skip to: 2258
/* 390 */     MCD_OPC_CheckField, 3, 8, 0, 70, 7, // Skip to: 2258
/* 396 */     MCD_OPC_Decode, 150, 4, 229, 1, // Opcode: DMFC0
/* 401 */     MCD_OPC_FilterValue, 5, 61, 7, // Skip to: 2258
/* 405 */     MCD_OPC_CheckPredicate, 39, 57, 7, // Skip to: 2258
/* 409 */     MCD_OPC_CheckField, 3, 8, 0, 51, 7, // Skip to: 2258
/* 415 */     MCD_OPC_Decode, 155, 4, 229, 1, // Opcode: DMTC0
/* 420 */     MCD_OPC_FilterValue, 17, 222, 3, // Skip to: 1414
/* 424 */     MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 427 */     MCD_OPC_FilterValue, 0, 54, 0, // Skip to: 485
/* 431 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 434 */     MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 453
/* 438 */     MCD_OPC_CheckPredicate, 40, 24, 7, // Skip to: 2258
/* 442 */     MCD_OPC_CheckField, 6, 5, 0, 18, 7, // Skip to: 2258
/* 448 */     MCD_OPC_Decode, 245, 7, 230, 1, // Opcode: MFHC1_D64
/* 453 */     MCD_OPC_FilterValue, 7, 15, 0, // Skip to: 472
/* 457 */     MCD_OPC_CheckPredicate, 40, 5, 7, // Skip to: 2258
/* 461 */     MCD_OPC_CheckField, 6, 5, 0, 255, 6, // Skip to: 2258
/* 467 */     MCD_OPC_Decode, 234, 8, 231, 1, // Opcode: MTHC1_D64
/* 472 */     MCD_OPC_FilterValue, 17, 246, 6, // Skip to: 2258
/* 476 */     MCD_OPC_CheckPredicate, 41, 242, 6, // Skip to: 2258
/* 480 */     MCD_OPC_Decode, 253, 4, 206, 1, // Opcode: FADD_D64
/* 485 */     MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 504
/* 489 */     MCD_OPC_CheckPredicate, 41, 229, 6, // Skip to: 2258
/* 493 */     MCD_OPC_CheckField, 21, 5, 17, 223, 6, // Skip to: 2258
/* 499 */     MCD_OPC_Decode, 255, 5, 206, 1, // Opcode: FSUB_D64
/* 504 */     MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 523
/* 508 */     MCD_OPC_CheckPredicate, 41, 210, 6, // Skip to: 2258
/* 512 */     MCD_OPC_CheckField, 21, 5, 17, 204, 6, // Skip to: 2258
/* 518 */     MCD_OPC_Decode, 218, 5, 206, 1, // Opcode: FMUL_D64
/* 523 */     MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 542
/* 527 */     MCD_OPC_CheckPredicate, 41, 191, 6, // Skip to: 2258
/* 531 */     MCD_OPC_CheckField, 21, 5, 17, 185, 6, // Skip to: 2258
/* 537 */     MCD_OPC_Decode, 161, 5, 206, 1, // Opcode: FDIV_D64
/* 542 */     MCD_OPC_FilterValue, 4, 15, 0, // Skip to: 561
/* 546 */     MCD_OPC_CheckPredicate, 42, 172, 6, // Skip to: 2258
/* 550 */     MCD_OPC_CheckField, 16, 10, 160, 4, 165, 6, // Skip to: 2258
/* 557 */     MCD_OPC_Decode, 248, 5, 80, // Opcode: FSQRT_D64
/* 561 */     MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 580
/* 565 */     MCD_OPC_CheckPredicate, 41, 153, 6, // Skip to: 2258
/* 569 */     MCD_OPC_CheckField, 16, 10, 160, 4, 146, 6, // Skip to: 2258
/* 576 */     MCD_OPC_Decode, 246, 4, 80, // Opcode: FABS_D64
/* 580 */     MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 599
/* 584 */     MCD_OPC_CheckPredicate, 41, 134, 6, // Skip to: 2258
/* 588 */     MCD_OPC_CheckField, 16, 10, 160, 4, 127, 6, // Skip to: 2258
/* 595 */     MCD_OPC_Decode, 211, 5, 80, // Opcode: FMOV_D64
/* 599 */     MCD_OPC_FilterValue, 7, 15, 0, // Skip to: 618
/* 603 */     MCD_OPC_CheckPredicate, 41, 115, 6, // Skip to: 2258
/* 607 */     MCD_OPC_CheckField, 16, 10, 160, 4, 108, 6, // Skip to: 2258
/* 614 */     MCD_OPC_Decode, 224, 5, 80, // Opcode: FNEG_D64
/* 618 */     MCD_OPC_FilterValue, 8, 29, 0, // Skip to: 651
/* 622 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 625 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 638
/* 630 */     MCD_OPC_CheckPredicate, 41, 88, 6, // Skip to: 2258
/* 634 */     MCD_OPC_Decode, 164, 10, 73, // Opcode: ROUND_L_S
/* 638 */     MCD_OPC_FilterValue, 160, 4, 79, 6, // Skip to: 2258
/* 643 */     MCD_OPC_CheckPredicate, 41, 75, 6, // Skip to: 2258
/* 647 */     MCD_OPC_Decode, 163, 10, 80, // Opcode: ROUND_L_D64
/* 651 */     MCD_OPC_FilterValue, 9, 29, 0, // Skip to: 684
/* 655 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 658 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 671
/* 663 */     MCD_OPC_CheckPredicate, 41, 55, 6, // Skip to: 2258
/* 667 */     MCD_OPC_Decode, 236, 12, 73, // Opcode: TRUNC_L_S
/* 671 */     MCD_OPC_FilterValue, 160, 4, 46, 6, // Skip to: 2258
/* 676 */     MCD_OPC_CheckPredicate, 41, 42, 6, // Skip to: 2258
/* 680 */     MCD_OPC_Decode, 235, 12, 80, // Opcode: TRUNC_L_D64
/* 684 */     MCD_OPC_FilterValue, 10, 29, 0, // Skip to: 717
/* 688 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 691 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 704
/* 696 */     MCD_OPC_CheckPredicate, 41, 22, 6, // Skip to: 2258
/* 700 */     MCD_OPC_Decode, 178, 2, 73, // Opcode: CEIL_L_S
/* 704 */     MCD_OPC_FilterValue, 160, 4, 13, 6, // Skip to: 2258
/* 709 */     MCD_OPC_CheckPredicate, 41, 9, 6, // Skip to: 2258
/* 713 */     MCD_OPC_Decode, 177, 2, 80, // Opcode: CEIL_L_D64
/* 717 */     MCD_OPC_FilterValue, 11, 29, 0, // Skip to: 750
/* 721 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 724 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 737
/* 729 */     MCD_OPC_CheckPredicate, 41, 245, 5, // Skip to: 2258
/* 733 */     MCD_OPC_Decode, 193, 5, 73, // Opcode: FLOOR_L_S
/* 737 */     MCD_OPC_FilterValue, 160, 4, 236, 5, // Skip to: 2258
/* 742 */     MCD_OPC_CheckPredicate, 41, 232, 5, // Skip to: 2258
/* 746 */     MCD_OPC_Decode, 192, 5, 80, // Opcode: FLOOR_L_D64
/* 750 */     MCD_OPC_FilterValue, 12, 16, 0, // Skip to: 770
/* 754 */     MCD_OPC_CheckPredicate, 42, 220, 5, // Skip to: 2258
/* 758 */     MCD_OPC_CheckField, 16, 10, 160, 4, 213, 5, // Skip to: 2258
/* 765 */     MCD_OPC_Decode, 166, 10, 232, 1, // Opcode: ROUND_W_D64
/* 770 */     MCD_OPC_FilterValue, 13, 16, 0, // Skip to: 790
/* 774 */     MCD_OPC_CheckPredicate, 42, 200, 5, // Skip to: 2258
/* 778 */     MCD_OPC_CheckField, 16, 10, 160, 4, 193, 5, // Skip to: 2258
/* 785 */     MCD_OPC_Decode, 238, 12, 232, 1, // Opcode: TRUNC_W_D64
/* 790 */     MCD_OPC_FilterValue, 14, 16, 0, // Skip to: 810
/* 794 */     MCD_OPC_CheckPredicate, 42, 180, 5, // Skip to: 2258
/* 798 */     MCD_OPC_CheckField, 16, 10, 160, 4, 173, 5, // Skip to: 2258
/* 805 */     MCD_OPC_Decode, 180, 2, 232, 1, // Opcode: CEIL_W_D64
/* 810 */     MCD_OPC_FilterValue, 15, 16, 0, // Skip to: 830
/* 814 */     MCD_OPC_CheckPredicate, 42, 160, 5, // Skip to: 2258
/* 818 */     MCD_OPC_CheckField, 16, 10, 160, 4, 153, 5, // Skip to: 2258
/* 825 */     MCD_OPC_Decode, 195, 5, 232, 1, // Opcode: FLOOR_W_D64
/* 830 */     MCD_OPC_FilterValue, 17, 41, 0, // Skip to: 875
/* 834 */     MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 837 */     MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 856
/* 841 */     MCD_OPC_CheckPredicate, 43, 133, 5, // Skip to: 2258
/* 845 */     MCD_OPC_CheckField, 21, 5, 17, 127, 5, // Skip to: 2258
/* 851 */     MCD_OPC_Decode, 170, 8, 233, 1, // Opcode: MOVF_D64
/* 856 */     MCD_OPC_FilterValue, 1, 118, 5, // Skip to: 2258
/* 860 */     MCD_OPC_CheckPredicate, 43, 114, 5, // Skip to: 2258
/* 864 */     MCD_OPC_CheckField, 21, 5, 17, 108, 5, // Skip to: 2258
/* 870 */     MCD_OPC_Decode, 190, 8, 233, 1, // Opcode: MOVT_D64
/* 875 */     MCD_OPC_FilterValue, 18, 15, 0, // Skip to: 894
/* 879 */     MCD_OPC_CheckPredicate, 43, 95, 5, // Skip to: 2258
/* 883 */     MCD_OPC_CheckField, 21, 5, 17, 89, 5, // Skip to: 2258
/* 889 */     MCD_OPC_Decode, 202, 8, 234, 1, // Opcode: MOVZ_I_D64
/* 894 */     MCD_OPC_FilterValue, 19, 15, 0, // Skip to: 913
/* 898 */     MCD_OPC_CheckPredicate, 43, 76, 5, // Skip to: 2258
/* 902 */     MCD_OPC_CheckField, 21, 5, 17, 70, 5, // Skip to: 2258
/* 908 */     MCD_OPC_Decode, 182, 8, 234, 1, // Opcode: MOVN_I_D64
/* 913 */     MCD_OPC_FilterValue, 32, 31, 0, // Skip to: 948
/* 917 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 920 */     MCD_OPC_FilterValue, 160, 4, 9, 0, // Skip to: 934
/* 925 */     MCD_OPC_CheckPredicate, 41, 49, 5, // Skip to: 2258
/* 929 */     MCD_OPC_Decode, 180, 3, 232, 1, // Opcode: CVT_S_D64
/* 934 */     MCD_OPC_FilterValue, 160, 5, 39, 5, // Skip to: 2258
/* 939 */     MCD_OPC_CheckPredicate, 41, 35, 5, // Skip to: 2258
/* 943 */     MCD_OPC_Decode, 181, 3, 232, 1, // Opcode: CVT_S_L
/* 948 */     MCD_OPC_FilterValue, 33, 42, 0, // Skip to: 994
/* 952 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 955 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 968
/* 960 */     MCD_OPC_CheckPredicate, 41, 14, 5, // Skip to: 2258
/* 964 */     MCD_OPC_Decode, 171, 3, 73, // Opcode: CVT_D64_S
/* 968 */     MCD_OPC_FilterValue, 128, 5, 8, 0, // Skip to: 981
/* 973 */     MCD_OPC_CheckPredicate, 41, 1, 5, // Skip to: 2258
/* 977 */     MCD_OPC_Decode, 172, 3, 73, // Opcode: CVT_D64_W
/* 981 */     MCD_OPC_FilterValue, 160, 5, 248, 4, // Skip to: 2258
/* 986 */     MCD_OPC_CheckPredicate, 41, 244, 4, // Skip to: 2258
/* 990 */     MCD_OPC_Decode, 170, 3, 80, // Opcode: CVT_D64_L
/* 994 */     MCD_OPC_FilterValue, 36, 16, 0, // Skip to: 1014
/* 998 */     MCD_OPC_CheckPredicate, 41, 232, 4, // Skip to: 2258
/* 1002 */    MCD_OPC_CheckField, 16, 10, 160, 4, 225, 4, // Skip to: 2258
/* 1009 */    MCD_OPC_Decode, 185, 3, 232, 1, // Opcode: CVT_W_D64
/* 1014 */    MCD_OPC_FilterValue, 48, 21, 0, // Skip to: 1039
/* 1018 */    MCD_OPC_CheckPredicate, 44, 212, 4, // Skip to: 2258
/* 1022 */    MCD_OPC_CheckField, 21, 5, 17, 206, 4, // Skip to: 2258
/* 1028 */    MCD_OPC_CheckField, 6, 5, 0, 200, 4, // Skip to: 2258
/* 1034 */    MCD_OPC_Decode, 193, 3, 235, 1, // Opcode: C_F_D64
/* 1039 */    MCD_OPC_FilterValue, 49, 21, 0, // Skip to: 1064
/* 1043 */    MCD_OPC_CheckPredicate, 44, 187, 4, // Skip to: 2258
/* 1047 */    MCD_OPC_CheckField, 21, 5, 17, 181, 4, // Skip to: 2258
/* 1053 */    MCD_OPC_CheckField, 6, 5, 0, 175, 4, // Skip to: 2258
/* 1059 */    MCD_OPC_Decode, 235, 3, 235, 1, // Opcode: C_UN_D64
/* 1064 */    MCD_OPC_FilterValue, 50, 21, 0, // Skip to: 1089
/* 1068 */    MCD_OPC_CheckPredicate, 44, 162, 4, // Skip to: 2258
/* 1072 */    MCD_OPC_CheckField, 21, 5, 17, 156, 4, // Skip to: 2258
/* 1078 */    MCD_OPC_CheckField, 6, 5, 0, 150, 4, // Skip to: 2258
/* 1084 */    MCD_OPC_Decode, 190, 3, 235, 1, // Opcode: C_EQ_D64
/* 1089 */    MCD_OPC_FilterValue, 51, 21, 0, // Skip to: 1114
/* 1093 */    MCD_OPC_CheckPredicate, 44, 137, 4, // Skip to: 2258
/* 1097 */    MCD_OPC_CheckField, 21, 5, 17, 131, 4, // Skip to: 2258
/* 1103 */    MCD_OPC_CheckField, 6, 5, 0, 125, 4, // Skip to: 2258
/* 1109 */    MCD_OPC_Decode, 226, 3, 235, 1, // Opcode: C_UEQ_D64
/* 1114 */    MCD_OPC_FilterValue, 52, 21, 0, // Skip to: 1139
/* 1118 */    MCD_OPC_CheckPredicate, 44, 112, 4, // Skip to: 2258
/* 1122 */    MCD_OPC_CheckField, 21, 5, 17, 106, 4, // Skip to: 2258
/* 1128 */    MCD_OPC_CheckField, 6, 5, 0, 100, 4, // Skip to: 2258
/* 1134 */    MCD_OPC_Decode, 217, 3, 235, 1, // Opcode: C_OLT_D64
/* 1139 */    MCD_OPC_FilterValue, 53, 21, 0, // Skip to: 1164
/* 1143 */    MCD_OPC_CheckPredicate, 44, 87, 4, // Skip to: 2258
/* 1147 */    MCD_OPC_CheckField, 21, 5, 17, 81, 4, // Skip to: 2258
/* 1153 */    MCD_OPC_CheckField, 6, 5, 0, 75, 4, // Skip to: 2258
/* 1159 */    MCD_OPC_Decode, 232, 3, 235, 1, // Opcode: C_ULT_D64
/* 1164 */    MCD_OPC_FilterValue, 54, 21, 0, // Skip to: 1189
/* 1168 */    MCD_OPC_CheckPredicate, 44, 62, 4, // Skip to: 2258
/* 1172 */    MCD_OPC_CheckField, 21, 5, 17, 56, 4, // Skip to: 2258
/* 1178 */    MCD_OPC_CheckField, 6, 5, 0, 50, 4, // Skip to: 2258
/* 1184 */    MCD_OPC_Decode, 214, 3, 235, 1, // Opcode: C_OLE_D64
/* 1189 */    MCD_OPC_FilterValue, 55, 21, 0, // Skip to: 1214
/* 1193 */    MCD_OPC_CheckPredicate, 44, 37, 4, // Skip to: 2258
/* 1197 */    MCD_OPC_CheckField, 21, 5, 17, 31, 4, // Skip to: 2258
/* 1203 */    MCD_OPC_CheckField, 6, 5, 0, 25, 4, // Skip to: 2258
/* 1209 */    MCD_OPC_Decode, 229, 3, 235, 1, // Opcode: C_ULE_D64
/* 1214 */    MCD_OPC_FilterValue, 56, 21, 0, // Skip to: 1239
/* 1218 */    MCD_OPC_CheckPredicate, 44, 12, 4, // Skip to: 2258
/* 1222 */    MCD_OPC_CheckField, 21, 5, 17, 6, 4, // Skip to: 2258
/* 1228 */    MCD_OPC_CheckField, 6, 5, 0, 0, 4, // Skip to: 2258
/* 1234 */    MCD_OPC_Decode, 223, 3, 235, 1, // Opcode: C_SF_D64
/* 1239 */    MCD_OPC_FilterValue, 57, 21, 0, // Skip to: 1264
/* 1243 */    MCD_OPC_CheckPredicate, 44, 243, 3, // Skip to: 2258
/* 1247 */    MCD_OPC_CheckField, 21, 5, 17, 237, 3, // Skip to: 2258
/* 1253 */    MCD_OPC_CheckField, 6, 5, 0, 231, 3, // Skip to: 2258
/* 1259 */    MCD_OPC_Decode, 205, 3, 235, 1, // Opcode: C_NGLE_D64
/* 1264 */    MCD_OPC_FilterValue, 58, 21, 0, // Skip to: 1289
/* 1268 */    MCD_OPC_CheckPredicate, 44, 218, 3, // Skip to: 2258
/* 1272 */    MCD_OPC_CheckField, 21, 5, 17, 212, 3, // Skip to: 2258
/* 1278 */    MCD_OPC_CheckField, 6, 5, 0, 206, 3, // Skip to: 2258
/* 1284 */    MCD_OPC_Decode, 220, 3, 235, 1, // Opcode: C_SEQ_D64
/* 1289 */    MCD_OPC_FilterValue, 59, 21, 0, // Skip to: 1314
/* 1293 */    MCD_OPC_CheckPredicate, 44, 193, 3, // Skip to: 2258
/* 1297 */    MCD_OPC_CheckField, 21, 5, 17, 187, 3, // Skip to: 2258
/* 1303 */    MCD_OPC_CheckField, 6, 5, 0, 181, 3, // Skip to: 2258
/* 1309 */    MCD_OPC_Decode, 208, 3, 235, 1, // Opcode: C_NGL_D64
/* 1314 */    MCD_OPC_FilterValue, 60, 21, 0, // Skip to: 1339
/* 1318 */    MCD_OPC_CheckPredicate, 44, 168, 3, // Skip to: 2258
/* 1322 */    MCD_OPC_CheckField, 21, 5, 17, 162, 3, // Skip to: 2258
/* 1328 */    MCD_OPC_CheckField, 6, 5, 0, 156, 3, // Skip to: 2258
/* 1334 */    MCD_OPC_Decode, 199, 3, 235, 1, // Opcode: C_LT_D64
/* 1339 */    MCD_OPC_FilterValue, 61, 21, 0, // Skip to: 1364
/* 1343 */    MCD_OPC_CheckPredicate, 44, 143, 3, // Skip to: 2258
/* 1347 */    MCD_OPC_CheckField, 21, 5, 17, 137, 3, // Skip to: 2258
/* 1353 */    MCD_OPC_CheckField, 6, 5, 0, 131, 3, // Skip to: 2258
/* 1359 */    MCD_OPC_Decode, 202, 3, 235, 1, // Opcode: C_NGE_D64
/* 1364 */    MCD_OPC_FilterValue, 62, 21, 0, // Skip to: 1389
/* 1368 */    MCD_OPC_CheckPredicate, 44, 118, 3, // Skip to: 2258
/* 1372 */    MCD_OPC_CheckField, 21, 5, 17, 112, 3, // Skip to: 2258
/* 1378 */    MCD_OPC_CheckField, 6, 5, 0, 106, 3, // Skip to: 2258
/* 1384 */    MCD_OPC_Decode, 196, 3, 235, 1, // Opcode: C_LE_D64
/* 1389 */    MCD_OPC_FilterValue, 63, 97, 3, // Skip to: 2258
/* 1393 */    MCD_OPC_CheckPredicate, 44, 93, 3, // Skip to: 2258
/* 1397 */    MCD_OPC_CheckField, 21, 5, 17, 87, 3, // Skip to: 2258
/* 1403 */    MCD_OPC_CheckField, 6, 5, 0, 81, 3, // Skip to: 2258
/* 1409 */    MCD_OPC_Decode, 211, 3, 235, 1, // Opcode: C_NGT_D64
/* 1414 */    MCD_OPC_FilterValue, 18, 41, 0, // Skip to: 1459
/* 1418 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1421 */    MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 1440
/* 1425 */    MCD_OPC_CheckPredicate, 39, 61, 3, // Skip to: 2258
/* 1429 */    MCD_OPC_CheckField, 3, 8, 0, 55, 3, // Skip to: 2258
/* 1435 */    MCD_OPC_Decode, 152, 4, 229, 1, // Opcode: DMFC2
/* 1440 */    MCD_OPC_FilterValue, 5, 46, 3, // Skip to: 2258
/* 1444 */    MCD_OPC_CheckPredicate, 39, 42, 3, // Skip to: 2258
/* 1448 */    MCD_OPC_CheckField, 3, 8, 0, 36, 3, // Skip to: 2258
/* 1454 */    MCD_OPC_Decode, 157, 4, 229, 1, // Opcode: DMTC2
/* 1459 */    MCD_OPC_FilterValue, 19, 79, 0, // Skip to: 1542
/* 1463 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1466 */    MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 1485
/* 1470 */    MCD_OPC_CheckPredicate, 45, 16, 3, // Skip to: 2258
/* 1474 */    MCD_OPC_CheckField, 11, 5, 0, 10, 3, // Skip to: 2258
/* 1480 */    MCD_OPC_Decode, 247, 6, 236, 1, // Opcode: LDXC164
/* 1485 */    MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 1504
/* 1489 */    MCD_OPC_CheckPredicate, 46, 253, 2, // Skip to: 2258
/* 1493 */    MCD_OPC_CheckField, 11, 5, 0, 247, 2, // Skip to: 2258
/* 1499 */    MCD_OPC_Decode, 149, 7, 236, 1, // Opcode: LUXC164
/* 1504 */    MCD_OPC_FilterValue, 9, 15, 0, // Skip to: 1523
/* 1508 */    MCD_OPC_CheckPredicate, 45, 234, 2, // Skip to: 2258
/* 1512 */    MCD_OPC_CheckField, 6, 5, 0, 228, 2, // Skip to: 2258
/* 1518 */    MCD_OPC_Decode, 204, 10, 237, 1, // Opcode: SDXC164
/* 1523 */    MCD_OPC_FilterValue, 13, 219, 2, // Skip to: 2258
/* 1527 */    MCD_OPC_CheckPredicate, 46, 215, 2, // Skip to: 2258
/* 1531 */    MCD_OPC_CheckField, 6, 5, 0, 209, 2, // Skip to: 2258
/* 1537 */    MCD_OPC_Decode, 137, 12, 237, 1, // Opcode: SUXC164
/* 1542 */    MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 1555
/* 1546 */    MCD_OPC_CheckPredicate, 38, 196, 2, // Skip to: 2258
/* 1550 */    MCD_OPC_Decode, 242, 3, 238, 1, // Opcode: DADDi
/* 1555 */    MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 1568
/* 1559 */    MCD_OPC_CheckPredicate, 17, 183, 2, // Skip to: 2258
/* 1563 */    MCD_OPC_Decode, 243, 3, 238, 1, // Opcode: DADDiu
/* 1568 */    MCD_OPC_FilterValue, 26, 9, 0, // Skip to: 1581
/* 1572 */    MCD_OPC_CheckPredicate, 38, 170, 2, // Skip to: 2258
/* 1576 */    MCD_OPC_Decode, 243, 6, 192, 1, // Opcode: LDL
/* 1581 */    MCD_OPC_FilterValue, 27, 9, 0, // Skip to: 1594
/* 1585 */    MCD_OPC_CheckPredicate, 38, 157, 2, // Skip to: 2258
/* 1589 */    MCD_OPC_Decode, 245, 6, 192, 1, // Opcode: LDR
/* 1594 */    MCD_OPC_FilterValue, 28, 159, 1, // Skip to: 2013
/* 1598 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1601 */    MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 1620
/* 1605 */    MCD_OPC_CheckPredicate, 47, 137, 2, // Skip to: 2258
/* 1609 */    MCD_OPC_CheckField, 6, 5, 0, 131, 2, // Skip to: 2258
/* 1615 */    MCD_OPC_Decode, 160, 4, 197, 1, // Opcode: DMUL
/* 1620 */    MCD_OPC_FilterValue, 8, 15, 0, // Skip to: 1639
/* 1624 */    MCD_OPC_CheckPredicate, 47, 118, 2, // Skip to: 2258
/* 1628 */    MCD_OPC_CheckField, 6, 15, 0, 112, 2, // Skip to: 2258
/* 1634 */    MCD_OPC_Decode, 245, 8, 239, 1, // Opcode: MTM0
/* 1639 */    MCD_OPC_FilterValue, 9, 15, 0, // Skip to: 1658
/* 1643 */    MCD_OPC_CheckPredicate, 47, 99, 2, // Skip to: 2258
/* 1647 */    MCD_OPC_CheckField, 6, 15, 0, 93, 2, // Skip to: 2258
/* 1653 */    MCD_OPC_Decode, 248, 8, 239, 1, // Opcode: MTP0
/* 1658 */    MCD_OPC_FilterValue, 10, 15, 0, // Skip to: 1677
/* 1662 */    MCD_OPC_CheckPredicate, 47, 80, 2, // Skip to: 2258
/* 1666 */    MCD_OPC_CheckField, 6, 15, 0, 74, 2, // Skip to: 2258
/* 1672 */    MCD_OPC_Decode, 249, 8, 239, 1, // Opcode: MTP1
/* 1677 */    MCD_OPC_FilterValue, 11, 15, 0, // Skip to: 1696
/* 1681 */    MCD_OPC_CheckPredicate, 47, 61, 2, // Skip to: 2258
/* 1685 */    MCD_OPC_CheckField, 6, 15, 0, 55, 2, // Skip to: 2258
/* 1691 */    MCD_OPC_Decode, 250, 8, 239, 1, // Opcode: MTP2
/* 1696 */    MCD_OPC_FilterValue, 12, 15, 0, // Skip to: 1715
/* 1700 */    MCD_OPC_CheckPredicate, 47, 42, 2, // Skip to: 2258
/* 1704 */    MCD_OPC_CheckField, 6, 15, 0, 36, 2, // Skip to: 2258
/* 1710 */    MCD_OPC_Decode, 246, 8, 239, 1, // Opcode: MTM1
/* 1715 */    MCD_OPC_FilterValue, 13, 15, 0, // Skip to: 1734
/* 1719 */    MCD_OPC_CheckPredicate, 47, 23, 2, // Skip to: 2258
/* 1723 */    MCD_OPC_CheckField, 6, 15, 0, 17, 2, // Skip to: 2258
/* 1729 */    MCD_OPC_Decode, 247, 8, 239, 1, // Opcode: MTM2
/* 1734 */    MCD_OPC_FilterValue, 15, 15, 0, // Skip to: 1753
/* 1738 */    MCD_OPC_CheckPredicate, 47, 4, 2, // Skip to: 2258
/* 1742 */    MCD_OPC_CheckField, 6, 5, 0, 254, 1, // Skip to: 2258
/* 1748 */    MCD_OPC_Decode, 247, 12, 197, 1, // Opcode: VMULU
/* 1753 */    MCD_OPC_FilterValue, 16, 15, 0, // Skip to: 1772
/* 1757 */    MCD_OPC_CheckPredicate, 47, 241, 1, // Skip to: 2258
/* 1761 */    MCD_OPC_CheckField, 6, 5, 0, 235, 1, // Skip to: 2258
/* 1767 */    MCD_OPC_Decode, 246, 12, 197, 1, // Opcode: VMM0
/* 1772 */    MCD_OPC_FilterValue, 17, 15, 0, // Skip to: 1791
/* 1776 */    MCD_OPC_CheckPredicate, 47, 222, 1, // Skip to: 2258
/* 1780 */    MCD_OPC_CheckField, 6, 5, 0, 216, 1, // Skip to: 2258
/* 1786 */    MCD_OPC_Decode, 245, 12, 197, 1, // Opcode: V3MULU
/* 1791 */    MCD_OPC_FilterValue, 36, 15, 0, // Skip to: 1810
/* 1795 */    MCD_OPC_CheckPredicate, 48, 203, 1, // Skip to: 2258
/* 1799 */    MCD_OPC_CheckField, 6, 5, 0, 197, 1, // Skip to: 2258
/* 1805 */    MCD_OPC_Decode, 252, 3, 240, 1, // Opcode: DCLZ
/* 1810 */    MCD_OPC_FilterValue, 37, 15, 0, // Skip to: 1829
/* 1814 */    MCD_OPC_CheckPredicate, 48, 184, 1, // Skip to: 2258
/* 1818 */    MCD_OPC_CheckField, 6, 5, 0, 178, 1, // Skip to: 2258
/* 1824 */    MCD_OPC_Decode, 250, 3, 240, 1, // Opcode: DCLO
/* 1829 */    MCD_OPC_FilterValue, 40, 15, 0, // Skip to: 1848
/* 1833 */    MCD_OPC_CheckPredicate, 47, 165, 1, // Skip to: 2258
/* 1837 */    MCD_OPC_CheckField, 6, 5, 0, 159, 1, // Skip to: 2258
/* 1843 */    MCD_OPC_Decode, 155, 1, 197, 1, // Opcode: BADDu
/* 1848 */    MCD_OPC_FilterValue, 42, 15, 0, // Skip to: 1867
/* 1852 */    MCD_OPC_CheckPredicate, 47, 146, 1, // Skip to: 2258
/* 1856 */    MCD_OPC_CheckField, 6, 5, 0, 140, 1, // Skip to: 2258
/* 1862 */    MCD_OPC_Decode, 221, 10, 197, 1, // Opcode: SEQ
/* 1867 */    MCD_OPC_FilterValue, 43, 15, 0, // Skip to: 1886
/* 1871 */    MCD_OPC_CheckPredicate, 47, 127, 1, // Skip to: 2258
/* 1875 */    MCD_OPC_CheckField, 6, 5, 0, 121, 1, // Skip to: 2258
/* 1881 */    MCD_OPC_Decode, 159, 11, 197, 1, // Opcode: SNE
/* 1886 */    MCD_OPC_FilterValue, 44, 20, 0, // Skip to: 1910
/* 1890 */    MCD_OPC_CheckPredicate, 47, 108, 1, // Skip to: 2258
/* 1894 */    MCD_OPC_CheckField, 16, 5, 0, 102, 1, // Skip to: 2258
/* 1900 */    MCD_OPC_CheckField, 6, 5, 0, 96, 1, // Skip to: 2258
/* 1906 */    MCD_OPC_Decode, 220, 9, 39, // Opcode: POP
/* 1910 */    MCD_OPC_FilterValue, 45, 21, 0, // Skip to: 1935
/* 1914 */    MCD_OPC_CheckPredicate, 47, 84, 1, // Skip to: 2258
/* 1918 */    MCD_OPC_CheckField, 16, 5, 0, 78, 1, // Skip to: 2258
/* 1924 */    MCD_OPC_CheckField, 6, 5, 0, 72, 1, // Skip to: 2258
/* 1930 */    MCD_OPC_Decode, 185, 4, 195, 1, // Opcode: DPOP
/* 1935 */    MCD_OPC_FilterValue, 46, 9, 0, // Skip to: 1948
/* 1939 */    MCD_OPC_CheckPredicate, 47, 59, 1, // Skip to: 2258
/* 1943 */    MCD_OPC_Decode, 222, 10, 241, 1, // Opcode: SEQi
/* 1948 */    MCD_OPC_FilterValue, 47, 9, 0, // Skip to: 1961
/* 1952 */    MCD_OPC_CheckPredicate, 47, 46, 1, // Skip to: 2258
/* 1956 */    MCD_OPC_Decode, 160, 11, 241, 1, // Opcode: SNEi
/* 1961 */    MCD_OPC_FilterValue, 50, 9, 0, // Skip to: 1974
/* 1965 */    MCD_OPC_CheckPredicate, 47, 33, 1, // Skip to: 2258
/* 1969 */    MCD_OPC_Decode, 195, 2, 242, 1, // Opcode: CINS
/* 1974 */    MCD_OPC_FilterValue, 51, 9, 0, // Skip to: 1987
/* 1978 */    MCD_OPC_CheckPredicate, 47, 20, 1, // Skip to: 2258
/* 1982 */    MCD_OPC_Decode, 196, 2, 242, 1, // Opcode: CINS32
/* 1987 */    MCD_OPC_FilterValue, 58, 9, 0, // Skip to: 2000
/* 1991 */    MCD_OPC_CheckPredicate, 47, 7, 1, // Skip to: 2258
/* 1995 */    MCD_OPC_Decode, 239, 4, 242, 1, // Opcode: EXTS
/* 2000 */    MCD_OPC_FilterValue, 59, 254, 0, // Skip to: 2258
/* 2004 */    MCD_OPC_CheckPredicate, 47, 250, 0, // Skip to: 2258
/* 2008 */    MCD_OPC_Decode, 240, 4, 242, 1, // Opcode: EXTS32
/* 2013 */    MCD_OPC_FilterValue, 31, 126, 0, // Skip to: 2143
/* 2017 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 2020 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 2033
/* 2024 */    MCD_OPC_CheckPredicate, 4, 230, 0, // Skip to: 2258
/* 2028 */    MCD_OPC_Decode, 131, 4, 243, 1, // Opcode: DEXTM
/* 2033 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 2046
/* 2037 */    MCD_OPC_CheckPredicate, 4, 217, 0, // Skip to: 2258
/* 2041 */    MCD_OPC_Decode, 132, 4, 243, 1, // Opcode: DEXTU
/* 2046 */    MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 2059
/* 2050 */    MCD_OPC_CheckPredicate, 4, 204, 0, // Skip to: 2258
/* 2054 */    MCD_OPC_Decode, 130, 4, 243, 1, // Opcode: DEXT
/* 2059 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 2072
/* 2063 */    MCD_OPC_CheckPredicate, 4, 191, 0, // Skip to: 2258
/* 2067 */    MCD_OPC_Decode, 135, 4, 244, 1, // Opcode: DINSM
/* 2072 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 2085
/* 2076 */    MCD_OPC_CheckPredicate, 4, 178, 0, // Skip to: 2258
/* 2080 */    MCD_OPC_Decode, 136, 4, 244, 1, // Opcode: DINSU
/* 2085 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 2098
/* 2089 */    MCD_OPC_CheckPredicate, 4, 165, 0, // Skip to: 2258
/* 2093 */    MCD_OPC_Decode, 134, 4, 244, 1, // Opcode: DINS
/* 2098 */    MCD_OPC_FilterValue, 36, 156, 0, // Skip to: 2258
/* 2102 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 2105 */    MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 2124
/* 2109 */    MCD_OPC_CheckPredicate, 37, 145, 0, // Skip to: 2258
/* 2113 */    MCD_OPC_CheckField, 21, 5, 0, 139, 0, // Skip to: 2258
/* 2119 */    MCD_OPC_Decode, 203, 4, 216, 1, // Opcode: DSBH
/* 2124 */    MCD_OPC_FilterValue, 5, 130, 0, // Skip to: 2258
/* 2128 */    MCD_OPC_CheckPredicate, 37, 126, 0, // Skip to: 2258
/* 2132 */    MCD_OPC_CheckField, 21, 5, 0, 120, 0, // Skip to: 2258
/* 2138 */    MCD_OPC_Decode, 205, 4, 216, 1, // Opcode: DSHD
/* 2143 */    MCD_OPC_FilterValue, 39, 9, 0, // Skip to: 2156
/* 2147 */    MCD_OPC_CheckPredicate, 17, 107, 0, // Skip to: 2258
/* 2151 */    MCD_OPC_Decode, 174, 7, 192, 1, // Opcode: LWu
/* 2156 */    MCD_OPC_FilterValue, 44, 9, 0, // Skip to: 2169
/* 2160 */    MCD_OPC_CheckPredicate, 38, 94, 0, // Skip to: 2258
/* 2164 */    MCD_OPC_Decode, 201, 10, 192, 1, // Opcode: SDL
/* 2169 */    MCD_OPC_FilterValue, 45, 9, 0, // Skip to: 2182
/* 2173 */    MCD_OPC_CheckPredicate, 38, 81, 0, // Skip to: 2258
/* 2177 */    MCD_OPC_Decode, 202, 10, 192, 1, // Opcode: SDR
/* 2182 */    MCD_OPC_FilterValue, 52, 9, 0, // Skip to: 2195
/* 2186 */    MCD_OPC_CheckPredicate, 38, 68, 0, // Skip to: 2258
/* 2190 */    MCD_OPC_Decode, 135, 7, 192, 1, // Opcode: LLD
/* 2195 */    MCD_OPC_FilterValue, 53, 8, 0, // Skip to: 2207
/* 2199 */    MCD_OPC_CheckPredicate, 49, 55, 0, // Skip to: 2258
/* 2203 */    MCD_OPC_Decode, 234, 6, 10, // Opcode: LDC164
/* 2207 */    MCD_OPC_FilterValue, 55, 9, 0, // Skip to: 2220
/* 2211 */    MCD_OPC_CheckPredicate, 17, 43, 0, // Skip to: 2258
/* 2215 */    MCD_OPC_Decode, 232, 6, 192, 1, // Opcode: LD
/* 2220 */    MCD_OPC_FilterValue, 60, 9, 0, // Skip to: 2233
/* 2224 */    MCD_OPC_CheckPredicate, 38, 30, 0, // Skip to: 2258
/* 2228 */    MCD_OPC_Decode, 186, 10, 192, 1, // Opcode: SCD
/* 2233 */    MCD_OPC_FilterValue, 61, 8, 0, // Skip to: 2245
/* 2237 */    MCD_OPC_CheckPredicate, 49, 17, 0, // Skip to: 2258
/* 2241 */    MCD_OPC_Decode, 194, 10, 10, // Opcode: SDC164
/* 2245 */    MCD_OPC_FilterValue, 63, 9, 0, // Skip to: 2258
/* 2249 */    MCD_OPC_CheckPredicate, 17, 5, 0, // Skip to: 2258
/* 2253 */    MCD_OPC_Decode, 190, 10, 192, 1, // Opcode: SD
/* 2258 */    MCD_OPC_Fail,
  0
};

static bool getbool(uint64_t b)
{
	return b != 0;
}

static bool checkDecoderPredicate(unsigned Idx, uint64_t Bits)
{
  switch (Idx) {
  default: // llvm_unreachable("Invalid index!");
  case 0:
    return getbool((Bits & Mips_FeatureMips16));
  case 1:
    return getbool(!(Bits & Mips_FeatureMips16));
  case 2:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips2));
  case 3:
    return getbool((Bits & Mips_FeatureMicroMips));
  case 4:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips32r2));
  case 5:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips4_32) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 6:
    return getbool((Bits & Mips_FeatureMSA));
  case 7:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips32) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 8:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMicroMips));
  case 9:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips32));
  case 10:
    return getbool(!(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6) && !(Bits & Mips_FeatureMicroMips));
  case 11:
    return getbool((Bits & Mips_FeatureDSP));
  case 12:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 13:
    return getbool((Bits & Mips_FeatureMSA) && (Bits & Mips_FeatureMips64));
  case 14:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips2) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 15:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips3_32));
  case 16:
    return getbool(!(Bits & Mips_FeatureMicroMips));
  case 17:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips3));
  case 18:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips32r2) && !(Bits & Mips_FeatureFP64Bit));
  case 19:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureFP64Bit));
  case 20:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips3_32r2));
  case 21:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips2) && !(Bits & Mips_FeatureFP64Bit));
  case 22:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureFP64Bit) && (Bits & Mips_FeatureMips4_32) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 23:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6) && !(Bits & Mips_FeatureFP64Bit));
  case 24:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips4_32r2) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 25:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureFP64Bit) && (Bits & Mips_FeatureMips4_32r2) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6) && !(Bits & Mips_FeatureMicroMips));
  case 26:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureFP64Bit) && (Bits & Mips_FeatureMips5_32r2) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 27:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips32r2) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 28:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureFP64Bit) && (Bits & Mips_FeatureMips32r2) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 29:
    return getbool((Bits & Mips_FeatureDSPR2));
  case 30:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips3_32) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 31:
    return getbool((Bits & Mips_FeatureMips2) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6) && !(Bits & Mips_FeatureMicroMips));
  case 32:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureFP64Bit) && (Bits & Mips_FeatureMips2));
  case 33:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips32r6));
  case 34:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips64r6));
  case 35:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureGP64Bit) && (Bits & Mips_FeatureMips32r6));
  case 36:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureGP64Bit) && (Bits & Mips_FeatureMips32r6));
  case 37:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips64r2));
  case 38:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips3) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 39:
    return getbool((Bits & Mips_FeatureMips64));
  case 40:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips32r2) && (Bits & Mips_FeatureFP64Bit));
  case 41:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureFP64Bit));
  case 42:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips2) && (Bits & Mips_FeatureFP64Bit));
  case 43:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureFP64Bit) && (Bits & Mips_FeatureMips4_32) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 44:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6) && (Bits & Mips_FeatureFP64Bit));
  case 45:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureFP64Bit) && (Bits & Mips_FeatureMips4_32r2) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 46:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureFP64Bit) && (Bits & Mips_FeatureMips5_32r2) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 47:
    return getbool((Bits & Mips_FeatureCnMips));
  case 48:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips64) && !(Bits & Mips_FeatureMips64r6));
  case 49:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureFP64Bit) && (Bits & Mips_FeatureMips2));
  }
}

#define DecodeToMCInst(fname,fieldname, InsnType) \
static DecodeStatus fname(DecodeStatus S, unsigned Idx, InsnType insn, MCInst *MI, \
                uint64_t Address, void *Decoder) \
{ \
  InsnType tmp; \
  switch (Idx) { \
  default: \
  case 0: \
    return S; \
  case 1: \
    tmp = fieldname(insn, 8, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 2: \
    tmp = fieldname(insn, 8, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 3: \
    tmp = 0; \
    tmp |= (fieldname(insn, 3, 2) << 3); \
    tmp |= (fieldname(insn, 5, 3) << 0); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 4: \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 5: \
    tmp = fieldname(insn, 2, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 5, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 6: \
    tmp = fieldname(insn, 8, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 5, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 7: \
    tmp = fieldname(insn, 8, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 5, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 8: \
    tmp = 0; \
    tmp |= (fieldname(insn, 0, 5) << 0); \
    tmp |= (fieldname(insn, 16, 5) << 11); \
    tmp |= (fieldname(insn, 21, 6) << 5); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 9: \
    tmp = fieldname(insn, 5, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 10: \
    if (DecodeFMem(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 11: \
    tmp = fieldname(insn, 5, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 12: \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 13: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 14: \
    tmp = fieldname(insn, 16, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 6, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 15: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeInsSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 16: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 17: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 18: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 19: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeExtSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 20: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 21: \
    tmp = fieldname(insn, 16, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 22: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 23: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 24: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 25: \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 26: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 27: \
    if (DecodeMemMMImm16(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 28: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTargetMM(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 29: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 30: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 31: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 13, 3); \
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 32: \
    if (DecodeMemMMImm12(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 33: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTargetMM(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 34: \
    if (DecodeJumpTargetMM(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 35: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 36: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 18, 3); \
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 37: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 2); \
    if (DecodeLSAImm(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 38: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 39: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 40: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 41: \
    tmp = fieldname(insn, 6, 20); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 42: \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 43: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 44: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 45: \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeHI32DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 46: \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeLO32DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 47: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 2); \
    if (DecodeLSAImm(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 48: \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 49: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 50: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 51: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 52: \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 53: \
    if (DecodeJumpTarget(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 54: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 55: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 56: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 57: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 58: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 59: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 60: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeCCRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 61: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 62: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 63: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 64: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeCCRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 65: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 66: \
    tmp = fieldname(insn, 18, 3); \
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 67: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 68: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 69: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 70: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 18, 3); \
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 71: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 72: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 73: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 74: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 75: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 76: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 77: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 78: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 18, 3); \
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 79: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 80: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 81: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 82: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 83: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 84: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 85: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 86: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 87: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 88: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 89: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 90: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 91: \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 92: \
    tmp = 0; \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    tmp |= (fieldname(insn, 16, 5) << 0); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 93: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 94: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 95: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 96: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 97: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 98: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 99: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 100: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 101: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 102: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 103: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 104: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 105: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 6); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 106: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 107: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 108: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 6); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 109: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 110: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 111: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 112: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 113: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 114: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 115: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 116: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 117: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 118: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 119: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 120: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 121: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 122: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 123: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 124: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 125: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 126: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 127: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 128: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 129: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 130: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 131: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 132: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 133: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 134: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 135: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 136: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 137: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 138: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSACtrlRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 139: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 140: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 141: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 142: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 143: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSACtrlRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 144: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 145: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 146: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 147: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 148: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 149: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 150: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 151: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 152: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 153: \
    if (DecodeINSVE_DF_4(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 154: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 155: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 156: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 157: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 158: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 159: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 160: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 161: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 162: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 163: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 164: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 165: \
    if (DecodeMSA128Mem(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 166: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeExtSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 167: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeInsSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 168: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 169: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 170: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 171: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 172: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 173: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 174: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 175: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 176: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 177: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 178: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 179: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 180: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 181: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 182: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 183: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 184: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 185: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 186: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 187: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 188: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 189: \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 20, 6); \
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 190: \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 191: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeHWRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 192: \
    if (DecodeMem(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 193: \
    tmp = 0; \
    tmp |= (fieldname(insn, 0, 16) << 0); \
    tmp |= (fieldname(insn, 21, 5) << 16); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 194: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 195: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 196: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 197: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 198: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 199: \
    if (DecodeBlezGroupBranch_4(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 200: \
    if (DecodeBgtzGroupBranch_4(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 201: \
    if (DecodeAddiGroupBranch_4(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 202: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 203: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGRCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 204: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 205: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGRCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 206: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 207: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 208: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGRCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 209: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGRCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 210: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeCOP2RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 211: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeCOP2RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 0, 11) << 0); \
    tmp |= (fieldname(insn, 11, 5) << 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 212: \
    if (DecodeBlezlGroupBranch_4(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 213: \
    if (DecodeBgtzlGroupBranch_4(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 214: \
    if (DecodeDaddiGroupBranch_4(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 215: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 216: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 217: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 218: \
    tmp = 0; \
    tmp |= (fieldname(insn, 7, 9) << 0); \
    tmp |= (fieldname(insn, 21, 5) << 16); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 219: \
    if (DecodeSpecial3LlSc(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 220: \
    tmp = fieldname(insn, 0, 26); \
    if (DecodeBranchTarget26(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 221: \
    if (DecodeSimm16(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 222: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 21); \
    if (DecodeBranchTarget21(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 223: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 19); \
    if (DecodeSimm19Lsl2(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 224: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 18); \
    if (DecodeSimm18Lsl3(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 225: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 226: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 227: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 228: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 229: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 230: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 231: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 232: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 233: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 18, 3); \
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 234: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 235: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 236: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 237: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 238: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 239: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 240: \
    tmp = 0; \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    tmp |= (fieldname(insn, 16, 5) << 0); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 241: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 242: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 243: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeExtSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 244: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeInsSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  } \
} 

#define DecodeInstruction(fname, fieldname, decoder, InsnType) \
static DecodeStatus fname(uint8_t DecodeTable[], MCInst *MI, \
           InsnType insn, uint64_t Address, MCRegisterInfo *MRI, int feature) \
{ \
  uint64_t Bits = getFeatureBits(feature); \
  uint8_t *Ptr = DecodeTable; \
  uint32_t CurFieldValue = 0, ExpectedValue; \
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
      CurFieldValue = (uint32_t)fieldname(insn, Start, Len); \
      break; \
    } \
    case MCD_OPC_FilterValue: { \
      Val = (InsnType)decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      NumToSkip = *Ptr++; \
      NumToSkip |= (*Ptr++) << 8; \
      if (Val != CurFieldValue) \
        Ptr += NumToSkip; \
      break; \
    } \
    case MCD_OPC_CheckField: { \
      Start = *++Ptr; \
      Len = *++Ptr; \
      FieldValue = fieldname(insn, Start, Len); \
      ExpectedValue = (uint32_t)decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      NumToSkip = *Ptr++; \
      NumToSkip |= (*Ptr++) << 8; \
      if (ExpectedValue != FieldValue) \
        Ptr += NumToSkip; \
      break; \
    } \
    case MCD_OPC_CheckPredicate: { \
      PIdx = (uint32_t)decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      NumToSkip = *Ptr++; \
      NumToSkip |= (*Ptr++) << 8; \
      Pred = checkDecoderPredicate(PIdx, Bits); \
      if (!Pred) \
        Ptr += NumToSkip; \
      (void)Pred; \
      break; \
    } \
    case MCD_OPC_Decode: { \
      Opc = (unsigned)decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      DecodeIdx = (unsigned)decodeULEB128(Ptr, &Len); \
      Ptr += Len; \
      MCInst_setOpcode(MI, Opc); \
      return decoder(S, DecodeIdx, insn, MI, Address, MRI); \
    } \
    case MCD_OPC_SoftFail: { \
      PositiveMask = (InsnType)decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      NegativeMask = (InsnType)decodeULEB128(Ptr, &Len); \
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

FieldFromInstruction(fieldFromInstruction, uint32_t)
DecodeToMCInst(decodeToMCInst, fieldFromInstruction, uint32_t)
DecodeInstruction(decodeInstruction, fieldFromInstruction, decodeToMCInst, uint32_t)
