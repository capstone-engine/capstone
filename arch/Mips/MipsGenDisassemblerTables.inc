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

static uint8_t DecoderTableMicroMips32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 23, 3, // Skip to: 798
/* 7 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10 */      MCD_OPC_FilterValue, 0, 51, 0, // Skip to: 65
/* 14 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 17 */      MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 29
/* 21 */      MCD_OPC_CheckPredicate, 1, 5, 5, // Skip to: 1310
/* 25 */      MCD_OPC_Decode, 220, 9, 10, // Opcode: SLL_MM
/* 29 */      MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 41
/* 33 */      MCD_OPC_CheckPredicate, 1, 249, 4, // Skip to: 1310
/* 37 */      MCD_OPC_Decode, 157, 10, 10, // Opcode: SRL_MM
/* 41 */      MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 53
/* 45 */      MCD_OPC_CheckPredicate, 1, 237, 4, // Skip to: 1310
/* 49 */      MCD_OPC_Decode, 137, 10, 10, // Opcode: SRA_MM
/* 53 */      MCD_OPC_FilterValue, 3, 229, 4, // Skip to: 1310
/* 57 */      MCD_OPC_CheckPredicate, 1, 225, 4, // Skip to: 1310
/* 61 */      MCD_OPC_Decode, 255, 8, 10, // Opcode: ROTR_MM
/* 65 */      MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 77
/* 69 */      MCD_OPC_CheckPredicate, 1, 213, 4, // Skip to: 1310
/* 73 */      MCD_OPC_Decode, 222, 1, 11, // Opcode: BREAK_MM
/* 77 */      MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 89
/* 81 */      MCD_OPC_CheckPredicate, 1, 201, 4, // Skip to: 1310
/* 85 */      MCD_OPC_Decode, 222, 5, 12, // Opcode: INS_MM
/* 89 */      MCD_OPC_FilterValue, 16, 180, 0, // Skip to: 273
/* 93 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 96 */      MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 108
/* 100 */     MCD_OPC_CheckPredicate, 1, 182, 4, // Skip to: 1310
/* 104 */     MCD_OPC_Decode, 216, 9, 13, // Opcode: SLLV_MM
/* 108 */     MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 120
/* 112 */     MCD_OPC_CheckPredicate, 1, 170, 4, // Skip to: 1310
/* 116 */     MCD_OPC_Decode, 153, 10, 13, // Opcode: SRLV_MM
/* 120 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 132
/* 124 */     MCD_OPC_CheckPredicate, 1, 158, 4, // Skip to: 1310
/* 128 */     MCD_OPC_Decode, 133, 10, 13, // Opcode: SRAV_MM
/* 132 */     MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 144
/* 136 */     MCD_OPC_CheckPredicate, 1, 146, 4, // Skip to: 1310
/* 140 */     MCD_OPC_Decode, 254, 8, 13, // Opcode: ROTRV_MM
/* 144 */     MCD_OPC_FilterValue, 4, 7, 0, // Skip to: 155
/* 148 */     MCD_OPC_CheckPredicate, 1, 134, 4, // Skip to: 1310
/* 152 */     MCD_OPC_Decode, 62, 14, // Opcode: ADD_MM
/* 155 */     MCD_OPC_FilterValue, 5, 7, 0, // Skip to: 166
/* 159 */     MCD_OPC_CheckPredicate, 1, 123, 4, // Skip to: 1310
/* 163 */     MCD_OPC_Decode, 68, 14, // Opcode: ADDu_MM
/* 166 */     MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 178
/* 170 */     MCD_OPC_CheckPredicate, 1, 112, 4, // Skip to: 1310
/* 174 */     MCD_OPC_Decode, 205, 10, 14, // Opcode: SUB_MM
/* 178 */     MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 190
/* 182 */     MCD_OPC_CheckPredicate, 1, 100, 4, // Skip to: 1310
/* 186 */     MCD_OPC_Decode, 207, 10, 14, // Opcode: SUBu_MM
/* 190 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 202
/* 194 */     MCD_OPC_CheckPredicate, 1, 88, 4, // Skip to: 1310
/* 198 */     MCD_OPC_Decode, 251, 7, 14, // Opcode: MUL_MM
/* 202 */     MCD_OPC_FilterValue, 9, 7, 0, // Skip to: 213
/* 206 */     MCD_OPC_CheckPredicate, 1, 76, 4, // Skip to: 1310
/* 210 */     MCD_OPC_Decode, 74, 14, // Opcode: AND_MM
/* 213 */     MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 225
/* 217 */     MCD_OPC_CheckPredicate, 1, 65, 4, // Skip to: 1310
/* 221 */     MCD_OPC_Decode, 168, 8, 14, // Opcode: OR_MM
/* 225 */     MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 237
/* 229 */     MCD_OPC_CheckPredicate, 1, 53, 4, // Skip to: 1310
/* 233 */     MCD_OPC_Decode, 158, 8, 14, // Opcode: NOR_MM
/* 237 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 249
/* 241 */     MCD_OPC_CheckPredicate, 1, 41, 4, // Skip to: 1310
/* 245 */     MCD_OPC_Decode, 195, 11, 14, // Opcode: XOR_MM
/* 249 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 261
/* 253 */     MCD_OPC_CheckPredicate, 1, 29, 4, // Skip to: 1310
/* 257 */     MCD_OPC_Decode, 224, 9, 14, // Opcode: SLT_MM
/* 261 */     MCD_OPC_FilterValue, 14, 21, 4, // Skip to: 1310
/* 265 */     MCD_OPC_CheckPredicate, 1, 17, 4, // Skip to: 1310
/* 269 */     MCD_OPC_Decode, 233, 9, 14, // Opcode: SLTu_MM
/* 273 */     MCD_OPC_FilterValue, 24, 27, 0, // Skip to: 304
/* 277 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 280 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 292
/* 284 */     MCD_OPC_CheckPredicate, 1, 254, 3, // Skip to: 1310
/* 288 */     MCD_OPC_Decode, 171, 7, 15, // Opcode: MOVN_I_MM
/* 292 */     MCD_OPC_FilterValue, 1, 246, 3, // Skip to: 1310
/* 296 */     MCD_OPC_CheckPredicate, 1, 242, 3, // Skip to: 1310
/* 300 */     MCD_OPC_Decode, 191, 7, 15, // Opcode: MOVZ_I_MM
/* 304 */     MCD_OPC_FilterValue, 44, 8, 0, // Skip to: 316
/* 308 */     MCD_OPC_CheckPredicate, 1, 230, 3, // Skip to: 1310
/* 312 */     MCD_OPC_Decode, 142, 4, 16, // Opcode: EXT_MM
/* 316 */     MCD_OPC_FilterValue, 60, 222, 3, // Skip to: 1310
/* 320 */     MCD_OPC_ExtractField, 6, 6,  // Inst{11-6} ...
/* 323 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 335
/* 327 */     MCD_OPC_CheckPredicate, 1, 211, 3, // Skip to: 1310
/* 331 */     MCD_OPC_Decode, 152, 11, 17, // Opcode: TEQ_MM
/* 335 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 347
/* 339 */     MCD_OPC_CheckPredicate, 1, 199, 3, // Skip to: 1310
/* 343 */     MCD_OPC_Decode, 160, 11, 17, // Opcode: TGE_MM
/* 347 */     MCD_OPC_FilterValue, 13, 39, 0, // Skip to: 390
/* 351 */     MCD_OPC_ExtractField, 12, 14,  // Inst{25-12} ...
/* 354 */     MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 366
/* 358 */     MCD_OPC_CheckPredicate, 1, 180, 3, // Skip to: 1310
/* 362 */     MCD_OPC_Decode, 188, 11, 0, // Opcode: WAIT_MM
/* 366 */     MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 378
/* 370 */     MCD_OPC_CheckPredicate, 1, 168, 3, // Skip to: 1310
/* 374 */     MCD_OPC_Decode, 173, 3, 0, // Opcode: DERET_MM
/* 378 */     MCD_OPC_FilterValue, 15, 160, 3, // Skip to: 1310
/* 382 */     MCD_OPC_CheckPredicate, 1, 156, 3, // Skip to: 1310
/* 386 */     MCD_OPC_Decode, 128, 4, 0, // Opcode: ERET_MM
/* 390 */     MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 402
/* 394 */     MCD_OPC_CheckPredicate, 1, 144, 3, // Skip to: 1310
/* 398 */     MCD_OPC_Decode, 159, 11, 17, // Opcode: TGEU_MM
/* 402 */     MCD_OPC_FilterValue, 29, 39, 0, // Skip to: 445
/* 406 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 409 */     MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 427
/* 413 */     MCD_OPC_CheckPredicate, 1, 125, 3, // Skip to: 1310
/* 417 */     MCD_OPC_CheckField, 21, 5, 0, 119, 3, // Skip to: 1310
/* 423 */     MCD_OPC_Decode, 189, 3, 18, // Opcode: DI_MM
/* 427 */     MCD_OPC_FilterValue, 5, 111, 3, // Skip to: 1310
/* 431 */     MCD_OPC_CheckPredicate, 1, 107, 3, // Skip to: 1310
/* 435 */     MCD_OPC_CheckField, 21, 5, 0, 101, 3, // Skip to: 1310
/* 441 */     MCD_OPC_Decode, 254, 3, 18, // Opcode: EI_MM
/* 445 */     MCD_OPC_FilterValue, 32, 8, 0, // Skip to: 457
/* 449 */     MCD_OPC_CheckPredicate, 1, 89, 3, // Skip to: 1310
/* 453 */     MCD_OPC_Decode, 167, 11, 17, // Opcode: TLT_MM
/* 457 */     MCD_OPC_FilterValue, 40, 8, 0, // Skip to: 469
/* 461 */     MCD_OPC_CheckPredicate, 1, 77, 3, // Skip to: 1310
/* 465 */     MCD_OPC_Decode, 166, 11, 17, // Opcode: TLTU_MM
/* 469 */     MCD_OPC_FilterValue, 43, 14, 0, // Skip to: 487
/* 473 */     MCD_OPC_CheckPredicate, 1, 65, 3, // Skip to: 1310
/* 477 */     MCD_OPC_CheckField, 12, 4, 8, 59, 3, // Skip to: 1310
/* 483 */     MCD_OPC_Decode, 228, 10, 19, // Opcode: SYSCALL_MM
/* 487 */     MCD_OPC_FilterValue, 44, 159, 0, // Skip to: 650
/* 491 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 494 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 506
/* 498 */     MCD_OPC_CheckPredicate, 1, 40, 3, // Skip to: 1310
/* 502 */     MCD_OPC_Decode, 166, 9, 20, // Opcode: SEB_MM
/* 506 */     MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 518
/* 510 */     MCD_OPC_CheckPredicate, 1, 28, 3, // Skip to: 1310
/* 514 */     MCD_OPC_Decode, 169, 9, 20, // Opcode: SEH_MM
/* 518 */     MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 530
/* 522 */     MCD_OPC_CheckPredicate, 1, 16, 3, // Skip to: 1310
/* 526 */     MCD_OPC_Decode, 175, 2, 20, // Opcode: CLO_MM
/* 530 */     MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 542
/* 534 */     MCD_OPC_CheckPredicate, 1, 4, 3, // Skip to: 1310
/* 538 */     MCD_OPC_Decode, 193, 2, 20, // Opcode: CLZ_MM
/* 542 */     MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 554
/* 546 */     MCD_OPC_CheckPredicate, 1, 248, 2, // Skip to: 1310
/* 550 */     MCD_OPC_Decode, 191, 11, 20, // Opcode: WSBH_MM
/* 554 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 566
/* 558 */     MCD_OPC_CheckPredicate, 1, 236, 2, // Skip to: 1310
/* 562 */     MCD_OPC_Decode, 244, 7, 21, // Opcode: MULT_MM
/* 566 */     MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 578
/* 570 */     MCD_OPC_CheckPredicate, 1, 224, 2, // Skip to: 1310
/* 574 */     MCD_OPC_Decode, 246, 7, 21, // Opcode: MULTu_MM
/* 578 */     MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 590
/* 582 */     MCD_OPC_CheckPredicate, 1, 212, 2, // Skip to: 1310
/* 586 */     MCD_OPC_Decode, 159, 9, 21, // Opcode: SDIV_MM
/* 590 */     MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 602
/* 594 */     MCD_OPC_CheckPredicate, 1, 200, 2, // Skip to: 1310
/* 598 */     MCD_OPC_Decode, 182, 11, 21, // Opcode: UDIV_MM
/* 602 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 614
/* 606 */     MCD_OPC_CheckPredicate, 1, 188, 2, // Skip to: 1310
/* 610 */     MCD_OPC_Decode, 207, 6, 21, // Opcode: MADD_MM
/* 614 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 626
/* 618 */     MCD_OPC_CheckPredicate, 1, 176, 2, // Skip to: 1310
/* 622 */     MCD_OPC_Decode, 198, 6, 21, // Opcode: MADDU_MM
/* 626 */     MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 638
/* 630 */     MCD_OPC_CheckPredicate, 1, 164, 2, // Skip to: 1310
/* 634 */     MCD_OPC_Decode, 208, 7, 21, // Opcode: MSUB_MM
/* 638 */     MCD_OPC_FilterValue, 15, 156, 2, // Skip to: 1310
/* 642 */     MCD_OPC_CheckPredicate, 1, 152, 2, // Skip to: 1310
/* 646 */     MCD_OPC_Decode, 199, 7, 21, // Opcode: MSUBU_MM
/* 650 */     MCD_OPC_FilterValue, 45, 20, 0, // Skip to: 674
/* 654 */     MCD_OPC_CheckPredicate, 1, 140, 2, // Skip to: 1310
/* 658 */     MCD_OPC_CheckField, 21, 5, 0, 134, 2, // Skip to: 1310
/* 664 */     MCD_OPC_CheckField, 12, 4, 6, 128, 2, // Skip to: 1310
/* 670 */     MCD_OPC_Decode, 226, 10, 22, // Opcode: SYNC_MM
/* 674 */     MCD_OPC_FilterValue, 48, 8, 0, // Skip to: 686
/* 678 */     MCD_OPC_CheckPredicate, 1, 116, 2, // Skip to: 1310
/* 682 */     MCD_OPC_Decode, 171, 11, 17, // Opcode: TNE_MM
/* 686 */     MCD_OPC_FilterValue, 53, 75, 0, // Skip to: 765
/* 690 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 693 */     MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 711
/* 697 */     MCD_OPC_CheckPredicate, 1, 97, 2, // Skip to: 1310
/* 701 */     MCD_OPC_CheckField, 21, 5, 0, 91, 2, // Skip to: 1310
/* 707 */     MCD_OPC_Decode, 245, 6, 18, // Opcode: MFHI_MM
/* 711 */     MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 729
/* 715 */     MCD_OPC_CheckPredicate, 1, 79, 2, // Skip to: 1310
/* 719 */     MCD_OPC_CheckField, 21, 5, 0, 73, 2, // Skip to: 1310
/* 725 */     MCD_OPC_Decode, 249, 6, 18, // Opcode: MFLO_MM
/* 729 */     MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 747
/* 733 */     MCD_OPC_CheckPredicate, 1, 61, 2, // Skip to: 1310
/* 737 */     MCD_OPC_CheckField, 21, 5, 0, 55, 2, // Skip to: 1310
/* 743 */     MCD_OPC_Decode, 222, 7, 18, // Opcode: MTHI_MM
/* 747 */     MCD_OPC_FilterValue, 3, 47, 2, // Skip to: 1310
/* 751 */     MCD_OPC_CheckPredicate, 1, 43, 2, // Skip to: 1310
/* 755 */     MCD_OPC_CheckField, 21, 5, 0, 37, 2, // Skip to: 1310
/* 761 */     MCD_OPC_Decode, 227, 7, 18, // Opcode: MTLO_MM
/* 765 */     MCD_OPC_FilterValue, 60, 29, 2, // Skip to: 1310
/* 769 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 772 */     MCD_OPC_FilterValue, 0, 22, 2, // Skip to: 1310
/* 776 */     MCD_OPC_CheckPredicate, 1, 10, 0, // Skip to: 790
/* 780 */     MCD_OPC_CheckField, 21, 5, 0, 4, 0, // Skip to: 790
/* 786 */     MCD_OPC_Decode, 233, 5, 18, // Opcode: JR_MM
/* 790 */     MCD_OPC_CheckPredicate, 1, 4, 2, // Skip to: 1310
/* 794 */     MCD_OPC_Decode, 229, 5, 20, // Opcode: JALR_MM
/* 798 */     MCD_OPC_FilterValue, 4, 7, 0, // Skip to: 809
/* 802 */     MCD_OPC_CheckPredicate, 1, 248, 1, // Skip to: 1310
/* 806 */     MCD_OPC_Decode, 64, 23, // Opcode: ADDi_MM
/* 809 */     MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 821
/* 813 */     MCD_OPC_CheckPredicate, 1, 237, 1, // Skip to: 1310
/* 817 */     MCD_OPC_Decode, 247, 5, 24, // Opcode: LBu_MM
/* 821 */     MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 833
/* 825 */     MCD_OPC_CheckPredicate, 1, 225, 1, // Skip to: 1310
/* 829 */     MCD_OPC_Decode, 149, 9, 24, // Opcode: SB_MM
/* 833 */     MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 845
/* 837 */     MCD_OPC_CheckPredicate, 1, 213, 1, // Skip to: 1310
/* 841 */     MCD_OPC_Decode, 244, 5, 24, // Opcode: LB_MM
/* 845 */     MCD_OPC_FilterValue, 12, 7, 0, // Skip to: 856
/* 849 */     MCD_OPC_CheckPredicate, 1, 201, 1, // Skip to: 1310
/* 853 */     MCD_OPC_Decode, 66, 23, // Opcode: ADDiu_MM
/* 856 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 868
/* 860 */     MCD_OPC_CheckPredicate, 1, 190, 1, // Skip to: 1310
/* 864 */     MCD_OPC_Decode, 146, 6, 24, // Opcode: LHu_MM
/* 868 */     MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 880
/* 872 */     MCD_OPC_CheckPredicate, 1, 178, 1, // Skip to: 1310
/* 876 */     MCD_OPC_Decode, 199, 9, 24, // Opcode: SH_MM
/* 880 */     MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 892
/* 884 */     MCD_OPC_CheckPredicate, 1, 166, 1, // Skip to: 1310
/* 888 */     MCD_OPC_Decode, 143, 6, 24, // Opcode: LH_MM
/* 892 */     MCD_OPC_FilterValue, 16, 159, 0, // Skip to: 1055
/* 896 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 899 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 911
/* 903 */     MCD_OPC_CheckPredicate, 1, 147, 1, // Skip to: 1310
/* 907 */     MCD_OPC_Decode, 198, 1, 25, // Opcode: BLTZ_MM
/* 911 */     MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 923
/* 915 */     MCD_OPC_CheckPredicate, 1, 135, 1, // Skip to: 1310
/* 919 */     MCD_OPC_Decode, 197, 1, 25, // Opcode: BLTZAL_MM
/* 923 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 935
/* 927 */     MCD_OPC_CheckPredicate, 1, 123, 1, // Skip to: 1310
/* 931 */     MCD_OPC_Decode, 170, 1, 25, // Opcode: BGEZ_MM
/* 935 */     MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 947
/* 939 */     MCD_OPC_CheckPredicate, 1, 111, 1, // Skip to: 1310
/* 943 */     MCD_OPC_Decode, 169, 1, 25, // Opcode: BGEZAL_MM
/* 947 */     MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 959
/* 951 */     MCD_OPC_CheckPredicate, 1, 99, 1, // Skip to: 1310
/* 955 */     MCD_OPC_Decode, 193, 1, 25, // Opcode: BLEZ_MM
/* 959 */     MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 971
/* 963 */     MCD_OPC_CheckPredicate, 1, 87, 1, // Skip to: 1310
/* 967 */     MCD_OPC_Decode, 173, 1, 25, // Opcode: BGTZ_MM
/* 971 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 983
/* 975 */     MCD_OPC_CheckPredicate, 1, 75, 1, // Skip to: 1310
/* 979 */     MCD_OPC_Decode, 164, 11, 26, // Opcode: TLTI_MM
/* 983 */     MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 995
/* 987 */     MCD_OPC_CheckPredicate, 1, 63, 1, // Skip to: 1310
/* 991 */     MCD_OPC_Decode, 157, 11, 26, // Opcode: TGEI_MM
/* 995 */     MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 1007
/* 999 */     MCD_OPC_CheckPredicate, 1, 51, 1, // Skip to: 1310
/* 1003 */    MCD_OPC_Decode, 163, 11, 26, // Opcode: TLTIU_MM
/* 1007 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1019
/* 1011 */    MCD_OPC_CheckPredicate, 1, 39, 1, // Skip to: 1310
/* 1015 */    MCD_OPC_Decode, 156, 11, 26, // Opcode: TGEIU_MM
/* 1019 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 1031
/* 1023 */    MCD_OPC_CheckPredicate, 1, 27, 1, // Skip to: 1310
/* 1027 */    MCD_OPC_Decode, 170, 11, 26, // Opcode: TNEI_MM
/* 1031 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 1043
/* 1035 */    MCD_OPC_CheckPredicate, 1, 15, 1, // Skip to: 1310
/* 1039 */    MCD_OPC_Decode, 160, 6, 26, // Opcode: LUi_MM
/* 1043 */    MCD_OPC_FilterValue, 14, 7, 1, // Skip to: 1310
/* 1047 */    MCD_OPC_CheckPredicate, 1, 3, 1, // Skip to: 1310
/* 1051 */    MCD_OPC_Decode, 151, 11, 26, // Opcode: TEQI_MM
/* 1055 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 1067
/* 1059 */    MCD_OPC_CheckPredicate, 1, 247, 0, // Skip to: 1310
/* 1063 */    MCD_OPC_Decode, 175, 8, 27, // Opcode: ORi_MM
/* 1067 */    MCD_OPC_FilterValue, 21, 29, 0, // Skip to: 1100
/* 1071 */    MCD_OPC_ExtractField, 0, 13,  // Inst{12-0} ...
/* 1074 */    MCD_OPC_FilterValue, 251, 2, 8, 0, // Skip to: 1087
/* 1079 */    MCD_OPC_CheckPredicate, 1, 227, 0, // Skip to: 1310
/* 1083 */    MCD_OPC_Decode, 159, 7, 28, // Opcode: MOVF_I_MM
/* 1087 */    MCD_OPC_FilterValue, 251, 18, 218, 0, // Skip to: 1310
/* 1092 */    MCD_OPC_CheckPredicate, 1, 214, 0, // Skip to: 1310
/* 1096 */    MCD_OPC_Decode, 179, 7, 28, // Opcode: MOVT_I_MM
/* 1100 */    MCD_OPC_FilterValue, 24, 87, 0, // Skip to: 1191
/* 1104 */    MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 1107 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1119
/* 1111 */    MCD_OPC_CheckPredicate, 1, 195, 0, // Skip to: 1310
/* 1115 */    MCD_OPC_Decode, 168, 6, 29, // Opcode: LWL_MM
/* 1119 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 1131
/* 1123 */    MCD_OPC_CheckPredicate, 1, 183, 0, // Skip to: 1310
/* 1127 */    MCD_OPC_Decode, 171, 6, 29, // Opcode: LWR_MM
/* 1131 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 1143
/* 1135 */    MCD_OPC_CheckPredicate, 1, 171, 0, // Skip to: 1310
/* 1139 */    MCD_OPC_Decode, 149, 6, 29, // Opcode: LL_MM
/* 1143 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 1155
/* 1147 */    MCD_OPC_CheckPredicate, 1, 159, 0, // Skip to: 1310
/* 1151 */    MCD_OPC_Decode, 218, 10, 29, // Opcode: SWL_MM
/* 1155 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 1167
/* 1159 */    MCD_OPC_CheckPredicate, 1, 147, 0, // Skip to: 1310
/* 1163 */    MCD_OPC_Decode, 221, 10, 29, // Opcode: SWR_MM
/* 1167 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1179
/* 1171 */    MCD_OPC_CheckPredicate, 1, 135, 0, // Skip to: 1310
/* 1175 */    MCD_OPC_Decode, 152, 9, 29, // Opcode: SC_MM
/* 1179 */    MCD_OPC_FilterValue, 14, 127, 0, // Skip to: 1310
/* 1183 */    MCD_OPC_CheckPredicate, 1, 123, 0, // Skip to: 1310
/* 1187 */    MCD_OPC_Decode, 172, 6, 29, // Opcode: LWU_MM
/* 1191 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 1203
/* 1195 */    MCD_OPC_CheckPredicate, 1, 111, 0, // Skip to: 1310
/* 1199 */    MCD_OPC_Decode, 202, 11, 27, // Opcode: XORi_MM
/* 1203 */    MCD_OPC_FilterValue, 36, 8, 0, // Skip to: 1215
/* 1207 */    MCD_OPC_CheckPredicate, 1, 99, 0, // Skip to: 1310
/* 1211 */    MCD_OPC_Decode, 227, 9, 23, // Opcode: SLTi_MM
/* 1215 */    MCD_OPC_FilterValue, 37, 8, 0, // Skip to: 1227
/* 1219 */    MCD_OPC_CheckPredicate, 1, 87, 0, // Skip to: 1310
/* 1223 */    MCD_OPC_Decode, 165, 1, 30, // Opcode: BEQ_MM
/* 1227 */    MCD_OPC_FilterValue, 44, 8, 0, // Skip to: 1239
/* 1231 */    MCD_OPC_CheckPredicate, 1, 75, 0, // Skip to: 1310
/* 1235 */    MCD_OPC_Decode, 230, 9, 23, // Opcode: SLTiu_MM
/* 1239 */    MCD_OPC_FilterValue, 45, 8, 0, // Skip to: 1251
/* 1243 */    MCD_OPC_CheckPredicate, 1, 63, 0, // Skip to: 1310
/* 1247 */    MCD_OPC_Decode, 213, 1, 30, // Opcode: BNE_MM
/* 1251 */    MCD_OPC_FilterValue, 52, 7, 0, // Skip to: 1262
/* 1255 */    MCD_OPC_CheckPredicate, 1, 51, 0, // Skip to: 1310
/* 1259 */    MCD_OPC_Decode, 81, 27, // Opcode: ANDi_MM
/* 1262 */    MCD_OPC_FilterValue, 53, 8, 0, // Skip to: 1274
/* 1266 */    MCD_OPC_CheckPredicate, 1, 40, 0, // Skip to: 1310
/* 1270 */    MCD_OPC_Decode, 234, 5, 31, // Opcode: J_MM
/* 1274 */    MCD_OPC_FilterValue, 61, 8, 0, // Skip to: 1286
/* 1278 */    MCD_OPC_CheckPredicate, 1, 28, 0, // Skip to: 1310
/* 1282 */    MCD_OPC_Decode, 230, 5, 31, // Opcode: JAL_MM
/* 1286 */    MCD_OPC_FilterValue, 62, 8, 0, // Skip to: 1298
/* 1290 */    MCD_OPC_CheckPredicate, 1, 16, 0, // Skip to: 1310
/* 1294 */    MCD_OPC_Decode, 224, 10, 24, // Opcode: SW_MM
/* 1298 */    MCD_OPC_FilterValue, 63, 8, 0, // Skip to: 1310
/* 1302 */    MCD_OPC_CheckPredicate, 1, 4, 0, // Skip to: 1310
/* 1306 */    MCD_OPC_Decode, 176, 6, 24, // Opcode: LW_MM
/* 1310 */    MCD_OPC_Fail,
  0
};

static uint8_t DecoderTableMips32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 101, 3, // Skip to: 876
/* 7 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10 */      MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 28
/* 14 */      MCD_OPC_CheckPredicate, 2, 11, 50, // Skip to: 12829
/* 18 */      MCD_OPC_CheckField, 21, 5, 0, 5, 50, // Skip to: 12829
/* 24 */      MCD_OPC_Decode, 208, 9, 32, // Opcode: SLL
/* 28 */      MCD_OPC_FilterValue, 1, 39, 0, // Skip to: 71
/* 32 */      MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 35 */      MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 53
/* 39 */      MCD_OPC_CheckPredicate, 2, 242, 49, // Skip to: 12829
/* 43 */      MCD_OPC_CheckField, 6, 5, 0, 236, 49, // Skip to: 12829
/* 49 */      MCD_OPC_Decode, 157, 7, 33, // Opcode: MOVF_I
/* 53 */      MCD_OPC_FilterValue, 1, 228, 49, // Skip to: 12829
/* 57 */      MCD_OPC_CheckPredicate, 2, 224, 49, // Skip to: 12829
/* 61 */      MCD_OPC_CheckField, 6, 5, 0, 218, 49, // Skip to: 12829
/* 67 */      MCD_OPC_Decode, 177, 7, 33, // Opcode: MOVT_I
/* 71 */      MCD_OPC_FilterValue, 2, 27, 0, // Skip to: 102
/* 75 */      MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 78 */      MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 90
/* 82 */      MCD_OPC_CheckPredicate, 2, 199, 49, // Skip to: 12829
/* 86 */      MCD_OPC_Decode, 139, 10, 32, // Opcode: SRL
/* 90 */      MCD_OPC_FilterValue, 1, 191, 49, // Skip to: 12829
/* 94 */      MCD_OPC_CheckPredicate, 3, 187, 49, // Skip to: 12829
/* 98 */      MCD_OPC_Decode, 252, 8, 32, // Opcode: ROTR
/* 102 */     MCD_OPC_FilterValue, 3, 14, 0, // Skip to: 120
/* 106 */     MCD_OPC_CheckPredicate, 2, 175, 49, // Skip to: 12829
/* 110 */     MCD_OPC_CheckField, 21, 5, 0, 169, 49, // Skip to: 12829
/* 116 */     MCD_OPC_Decode, 247, 9, 32, // Opcode: SRA
/* 120 */     MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 138
/* 124 */     MCD_OPC_CheckPredicate, 2, 157, 49, // Skip to: 12829
/* 128 */     MCD_OPC_CheckField, 6, 5, 0, 151, 49, // Skip to: 12829
/* 134 */     MCD_OPC_Decode, 215, 9, 14, // Opcode: SLLV
/* 138 */     MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 156
/* 142 */     MCD_OPC_CheckPredicate, 4, 139, 49, // Skip to: 12829
/* 146 */     MCD_OPC_CheckField, 8, 3, 0, 133, 49, // Skip to: 12829
/* 152 */     MCD_OPC_Decode, 154, 6, 34, // Opcode: LSA
/* 156 */     MCD_OPC_FilterValue, 6, 27, 0, // Skip to: 187
/* 160 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 163 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 175
/* 167 */     MCD_OPC_CheckPredicate, 2, 114, 49, // Skip to: 12829
/* 171 */     MCD_OPC_Decode, 152, 10, 14, // Opcode: SRLV
/* 175 */     MCD_OPC_FilterValue, 1, 106, 49, // Skip to: 12829
/* 179 */     MCD_OPC_CheckPredicate, 3, 102, 49, // Skip to: 12829
/* 183 */     MCD_OPC_Decode, 253, 8, 14, // Opcode: ROTRV
/* 187 */     MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 205
/* 191 */     MCD_OPC_CheckPredicate, 2, 90, 49, // Skip to: 12829
/* 195 */     MCD_OPC_CheckField, 6, 5, 0, 84, 49, // Skip to: 12829
/* 201 */     MCD_OPC_Decode, 132, 10, 14, // Opcode: SRAV
/* 205 */     MCD_OPC_FilterValue, 8, 14, 0, // Skip to: 223
/* 209 */     MCD_OPC_CheckPredicate, 2, 72, 49, // Skip to: 12829
/* 213 */     MCD_OPC_CheckField, 6, 15, 0, 66, 49, // Skip to: 12829
/* 219 */     MCD_OPC_Decode, 231, 5, 35, // Opcode: JR
/* 223 */     MCD_OPC_FilterValue, 9, 20, 0, // Skip to: 247
/* 227 */     MCD_OPC_CheckPredicate, 2, 54, 49, // Skip to: 12829
/* 231 */     MCD_OPC_CheckField, 16, 5, 0, 48, 49, // Skip to: 12829
/* 237 */     MCD_OPC_CheckField, 6, 5, 0, 42, 49, // Skip to: 12829
/* 243 */     MCD_OPC_Decode, 225, 5, 36, // Opcode: JALR
/* 247 */     MCD_OPC_FilterValue, 10, 14, 0, // Skip to: 265
/* 251 */     MCD_OPC_CheckPredicate, 2, 30, 49, // Skip to: 12829
/* 255 */     MCD_OPC_CheckField, 6, 5, 0, 24, 49, // Skip to: 12829
/* 261 */     MCD_OPC_Decode, 189, 7, 37, // Opcode: MOVZ_I_I
/* 265 */     MCD_OPC_FilterValue, 11, 14, 0, // Skip to: 283
/* 269 */     MCD_OPC_CheckPredicate, 2, 12, 49, // Skip to: 12829
/* 273 */     MCD_OPC_CheckField, 6, 5, 0, 6, 49, // Skip to: 12829
/* 279 */     MCD_OPC_Decode, 169, 7, 37, // Opcode: MOVN_I_I
/* 283 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 295
/* 287 */     MCD_OPC_CheckPredicate, 2, 250, 48, // Skip to: 12829
/* 291 */     MCD_OPC_Decode, 227, 10, 38, // Opcode: SYSCALL
/* 295 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 307
/* 299 */     MCD_OPC_CheckPredicate, 2, 238, 48, // Skip to: 12829
/* 303 */     MCD_OPC_Decode, 221, 1, 11, // Opcode: BREAK
/* 307 */     MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 319
/* 311 */     MCD_OPC_CheckPredicate, 2, 226, 48, // Skip to: 12829
/* 315 */     MCD_OPC_Decode, 225, 10, 39, // Opcode: SYNC
/* 319 */     MCD_OPC_FilterValue, 16, 43, 0, // Skip to: 366
/* 323 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 326 */     MCD_OPC_FilterValue, 0, 211, 48, // Skip to: 12829
/* 330 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 333 */     MCD_OPC_FilterValue, 0, 204, 48, // Skip to: 12829
/* 337 */     MCD_OPC_ExtractField, 23, 3,  // Inst{25-23} ...
/* 340 */     MCD_OPC_FilterValue, 0, 197, 48, // Skip to: 12829
/* 344 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 358
/* 348 */     MCD_OPC_CheckField, 21, 2, 0, 4, 0, // Skip to: 358
/* 354 */     MCD_OPC_Decode, 242, 6, 40, // Opcode: MFHI
/* 358 */     MCD_OPC_CheckPredicate, 5, 179, 48, // Skip to: 12829
/* 362 */     MCD_OPC_Decode, 244, 6, 41, // Opcode: MFHI_DSP
/* 366 */     MCD_OPC_FilterValue, 17, 36, 0, // Skip to: 406
/* 370 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 373 */     MCD_OPC_FilterValue, 0, 164, 48, // Skip to: 12829
/* 377 */     MCD_OPC_ExtractField, 13, 8,  // Inst{20-13} ...
/* 380 */     MCD_OPC_FilterValue, 0, 157, 48, // Skip to: 12829
/* 384 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 398
/* 388 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 398
/* 394 */     MCD_OPC_Decode, 219, 7, 35, // Opcode: MTHI
/* 398 */     MCD_OPC_CheckPredicate, 5, 139, 48, // Skip to: 12829
/* 402 */     MCD_OPC_Decode, 221, 7, 42, // Opcode: MTHI_DSP
/* 406 */     MCD_OPC_FilterValue, 18, 43, 0, // Skip to: 453
/* 410 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 413 */     MCD_OPC_FilterValue, 0, 124, 48, // Skip to: 12829
/* 417 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 420 */     MCD_OPC_FilterValue, 0, 117, 48, // Skip to: 12829
/* 424 */     MCD_OPC_ExtractField, 23, 3,  // Inst{25-23} ...
/* 427 */     MCD_OPC_FilterValue, 0, 110, 48, // Skip to: 12829
/* 431 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 445
/* 435 */     MCD_OPC_CheckField, 21, 2, 0, 4, 0, // Skip to: 445
/* 441 */     MCD_OPC_Decode, 246, 6, 40, // Opcode: MFLO
/* 445 */     MCD_OPC_CheckPredicate, 5, 92, 48, // Skip to: 12829
/* 449 */     MCD_OPC_Decode, 248, 6, 41, // Opcode: MFLO_DSP
/* 453 */     MCD_OPC_FilterValue, 19, 36, 0, // Skip to: 493
/* 457 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 460 */     MCD_OPC_FilterValue, 0, 77, 48, // Skip to: 12829
/* 464 */     MCD_OPC_ExtractField, 13, 8,  // Inst{20-13} ...
/* 467 */     MCD_OPC_FilterValue, 0, 70, 48, // Skip to: 12829
/* 471 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 485
/* 475 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 485
/* 481 */     MCD_OPC_Decode, 224, 7, 35, // Opcode: MTLO
/* 485 */     MCD_OPC_CheckPredicate, 5, 52, 48, // Skip to: 12829
/* 489 */     MCD_OPC_Decode, 226, 7, 43, // Opcode: MTLO_DSP
/* 493 */     MCD_OPC_FilterValue, 21, 14, 0, // Skip to: 511
/* 497 */     MCD_OPC_CheckPredicate, 6, 40, 48, // Skip to: 12829
/* 501 */     MCD_OPC_CheckField, 8, 3, 0, 34, 48, // Skip to: 12829
/* 507 */     MCD_OPC_Decode, 190, 3, 44, // Opcode: DLSA
/* 511 */     MCD_OPC_FilterValue, 24, 36, 0, // Skip to: 551
/* 515 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 518 */     MCD_OPC_FilterValue, 0, 19, 48, // Skip to: 12829
/* 522 */     MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 525 */     MCD_OPC_FilterValue, 0, 12, 48, // Skip to: 12829
/* 529 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 543
/* 533 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 543
/* 539 */     MCD_OPC_Decode, 241, 7, 20, // Opcode: MULT
/* 543 */     MCD_OPC_CheckPredicate, 5, 250, 47, // Skip to: 12829
/* 547 */     MCD_OPC_Decode, 243, 7, 45, // Opcode: MULT_DSP
/* 551 */     MCD_OPC_FilterValue, 25, 36, 0, // Skip to: 591
/* 555 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 558 */     MCD_OPC_FilterValue, 0, 235, 47, // Skip to: 12829
/* 562 */     MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 565 */     MCD_OPC_FilterValue, 0, 228, 47, // Skip to: 12829
/* 569 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 583
/* 573 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 583
/* 579 */     MCD_OPC_Decode, 245, 7, 20, // Opcode: MULTu
/* 583 */     MCD_OPC_CheckPredicate, 5, 210, 47, // Skip to: 12829
/* 587 */     MCD_OPC_Decode, 242, 7, 45, // Opcode: MULTU_DSP
/* 591 */     MCD_OPC_FilterValue, 26, 14, 0, // Skip to: 609
/* 595 */     MCD_OPC_CheckPredicate, 2, 198, 47, // Skip to: 12829
/* 599 */     MCD_OPC_CheckField, 6, 10, 0, 192, 47, // Skip to: 12829
/* 605 */     MCD_OPC_Decode, 158, 9, 20, // Opcode: SDIV
/* 609 */     MCD_OPC_FilterValue, 27, 14, 0, // Skip to: 627
/* 613 */     MCD_OPC_CheckPredicate, 2, 180, 47, // Skip to: 12829
/* 617 */     MCD_OPC_CheckField, 6, 10, 0, 174, 47, // Skip to: 12829
/* 623 */     MCD_OPC_Decode, 181, 11, 20, // Opcode: UDIV
/* 627 */     MCD_OPC_FilterValue, 32, 13, 0, // Skip to: 644
/* 631 */     MCD_OPC_CheckPredicate, 2, 162, 47, // Skip to: 12829
/* 635 */     MCD_OPC_CheckField, 6, 5, 0, 156, 47, // Skip to: 12829
/* 641 */     MCD_OPC_Decode, 22, 13, // Opcode: ADD
/* 644 */     MCD_OPC_FilterValue, 33, 13, 0, // Skip to: 661
/* 648 */     MCD_OPC_CheckPredicate, 2, 145, 47, // Skip to: 12829
/* 652 */     MCD_OPC_CheckField, 6, 5, 0, 139, 47, // Skip to: 12829
/* 658 */     MCD_OPC_Decode, 67, 13, // Opcode: ADDu
/* 661 */     MCD_OPC_FilterValue, 34, 14, 0, // Skip to: 679
/* 665 */     MCD_OPC_CheckPredicate, 2, 128, 47, // Skip to: 12829
/* 669 */     MCD_OPC_CheckField, 6, 5, 0, 122, 47, // Skip to: 12829
/* 675 */     MCD_OPC_Decode, 167, 10, 13, // Opcode: SUB
/* 679 */     MCD_OPC_FilterValue, 35, 14, 0, // Skip to: 697
/* 683 */     MCD_OPC_CheckPredicate, 2, 110, 47, // Skip to: 12829
/* 687 */     MCD_OPC_CheckField, 6, 5, 0, 104, 47, // Skip to: 12829
/* 693 */     MCD_OPC_Decode, 206, 10, 13, // Opcode: SUBu
/* 697 */     MCD_OPC_FilterValue, 36, 13, 0, // Skip to: 714
/* 701 */     MCD_OPC_CheckPredicate, 2, 92, 47, // Skip to: 12829
/* 705 */     MCD_OPC_CheckField, 6, 5, 0, 86, 47, // Skip to: 12829
/* 711 */     MCD_OPC_Decode, 71, 13, // Opcode: AND
/* 714 */     MCD_OPC_FilterValue, 37, 14, 0, // Skip to: 732
/* 718 */     MCD_OPC_CheckPredicate, 2, 75, 47, // Skip to: 12829
/* 722 */     MCD_OPC_CheckField, 6, 5, 0, 69, 47, // Skip to: 12829
/* 728 */     MCD_OPC_Decode, 165, 8, 13, // Opcode: OR
/* 732 */     MCD_OPC_FilterValue, 38, 14, 0, // Skip to: 750
/* 736 */     MCD_OPC_CheckPredicate, 2, 57, 47, // Skip to: 12829
/* 740 */     MCD_OPC_CheckField, 6, 5, 0, 51, 47, // Skip to: 12829
/* 746 */     MCD_OPC_Decode, 192, 11, 13, // Opcode: XOR
/* 750 */     MCD_OPC_FilterValue, 39, 14, 0, // Skip to: 768
/* 754 */     MCD_OPC_CheckPredicate, 2, 39, 47, // Skip to: 12829
/* 758 */     MCD_OPC_CheckField, 6, 5, 0, 33, 47, // Skip to: 12829
/* 764 */     MCD_OPC_Decode, 155, 8, 13, // Opcode: NOR
/* 768 */     MCD_OPC_FilterValue, 42, 14, 0, // Skip to: 786
/* 772 */     MCD_OPC_CheckPredicate, 2, 21, 47, // Skip to: 12829
/* 776 */     MCD_OPC_CheckField, 6, 5, 0, 15, 47, // Skip to: 12829
/* 782 */     MCD_OPC_Decode, 222, 9, 13, // Opcode: SLT
/* 786 */     MCD_OPC_FilterValue, 43, 14, 0, // Skip to: 804
/* 790 */     MCD_OPC_CheckPredicate, 2, 3, 47, // Skip to: 12829
/* 794 */     MCD_OPC_CheckField, 6, 5, 0, 253, 46, // Skip to: 12829
/* 800 */     MCD_OPC_Decode, 231, 9, 13, // Opcode: SLTu
/* 804 */     MCD_OPC_FilterValue, 48, 8, 0, // Skip to: 816
/* 808 */     MCD_OPC_CheckPredicate, 2, 241, 46, // Skip to: 12829
/* 812 */     MCD_OPC_Decode, 153, 11, 46, // Opcode: TGE
/* 816 */     MCD_OPC_FilterValue, 49, 8, 0, // Skip to: 828
/* 820 */     MCD_OPC_CheckPredicate, 2, 229, 46, // Skip to: 12829
/* 824 */     MCD_OPC_Decode, 158, 11, 46, // Opcode: TGEU
/* 828 */     MCD_OPC_FilterValue, 50, 8, 0, // Skip to: 840
/* 832 */     MCD_OPC_CheckPredicate, 2, 217, 46, // Skip to: 12829
/* 836 */     MCD_OPC_Decode, 161, 11, 46, // Opcode: TLT
/* 840 */     MCD_OPC_FilterValue, 51, 8, 0, // Skip to: 852
/* 844 */     MCD_OPC_CheckPredicate, 2, 205, 46, // Skip to: 12829
/* 848 */     MCD_OPC_Decode, 165, 11, 46, // Opcode: TLTU
/* 852 */     MCD_OPC_FilterValue, 52, 8, 0, // Skip to: 864
/* 856 */     MCD_OPC_CheckPredicate, 2, 193, 46, // Skip to: 12829
/* 860 */     MCD_OPC_Decode, 149, 11, 46, // Opcode: TEQ
/* 864 */     MCD_OPC_FilterValue, 54, 185, 46, // Skip to: 12829
/* 868 */     MCD_OPC_CheckPredicate, 2, 181, 46, // Skip to: 12829
/* 872 */     MCD_OPC_Decode, 168, 11, 46, // Opcode: TNE
/* 876 */     MCD_OPC_FilterValue, 1, 141, 0, // Skip to: 1021
/* 880 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 883 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 895
/* 887 */     MCD_OPC_CheckPredicate, 2, 162, 46, // Skip to: 12829
/* 891 */     MCD_OPC_Decode, 194, 1, 47, // Opcode: BLTZ
/* 895 */     MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 907
/* 899 */     MCD_OPC_CheckPredicate, 2, 150, 46, // Skip to: 12829
/* 903 */     MCD_OPC_Decode, 166, 1, 47, // Opcode: BGEZ
/* 907 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 919
/* 911 */     MCD_OPC_CheckPredicate, 2, 138, 46, // Skip to: 12829
/* 915 */     MCD_OPC_Decode, 154, 11, 48, // Opcode: TGEI
/* 919 */     MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 931
/* 923 */     MCD_OPC_CheckPredicate, 2, 126, 46, // Skip to: 12829
/* 927 */     MCD_OPC_Decode, 155, 11, 48, // Opcode: TGEIU
/* 931 */     MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 943
/* 935 */     MCD_OPC_CheckPredicate, 2, 114, 46, // Skip to: 12829
/* 939 */     MCD_OPC_Decode, 162, 11, 48, // Opcode: TLTI
/* 943 */     MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 955
/* 947 */     MCD_OPC_CheckPredicate, 2, 102, 46, // Skip to: 12829
/* 951 */     MCD_OPC_Decode, 180, 11, 48, // Opcode: TTLTIU
/* 955 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 967
/* 959 */     MCD_OPC_CheckPredicate, 2, 90, 46, // Skip to: 12829
/* 963 */     MCD_OPC_Decode, 150, 11, 48, // Opcode: TEQI
/* 967 */     MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 979
/* 971 */     MCD_OPC_CheckPredicate, 2, 78, 46, // Skip to: 12829
/* 975 */     MCD_OPC_Decode, 169, 11, 48, // Opcode: TNEI
/* 979 */     MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 991
/* 983 */     MCD_OPC_CheckPredicate, 2, 66, 46, // Skip to: 12829
/* 987 */     MCD_OPC_Decode, 196, 1, 47, // Opcode: BLTZAL
/* 991 */     MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 1003
/* 995 */     MCD_OPC_CheckPredicate, 2, 54, 46, // Skip to: 12829
/* 999 */     MCD_OPC_Decode, 168, 1, 47, // Opcode: BGEZAL
/* 1003 */    MCD_OPC_FilterValue, 28, 46, 46, // Skip to: 12829
/* 1007 */    MCD_OPC_CheckPredicate, 5, 42, 46, // Skip to: 12829
/* 1011 */    MCD_OPC_CheckField, 21, 5, 0, 36, 46, // Skip to: 12829
/* 1017 */    MCD_OPC_Decode, 219, 1, 49, // Opcode: BPOSGE32
/* 1021 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 1033
/* 1025 */    MCD_OPC_CheckPredicate, 7, 24, 46, // Skip to: 12829
/* 1029 */    MCD_OPC_Decode, 223, 5, 50, // Opcode: J
/* 1033 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 1045
/* 1037 */    MCD_OPC_CheckPredicate, 2, 12, 46, // Skip to: 12829
/* 1041 */    MCD_OPC_Decode, 224, 5, 50, // Opcode: JAL
/* 1045 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 1057
/* 1049 */    MCD_OPC_CheckPredicate, 2, 0, 46, // Skip to: 12829
/* 1053 */    MCD_OPC_Decode, 163, 1, 51, // Opcode: BEQ
/* 1057 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 1069
/* 1061 */    MCD_OPC_CheckPredicate, 2, 244, 45, // Skip to: 12829
/* 1065 */    MCD_OPC_Decode, 203, 1, 51, // Opcode: BNE
/* 1069 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 1087
/* 1073 */    MCD_OPC_CheckPredicate, 2, 232, 45, // Skip to: 12829
/* 1077 */    MCD_OPC_CheckField, 16, 5, 0, 226, 45, // Skip to: 12829
/* 1083 */    MCD_OPC_Decode, 191, 1, 47, // Opcode: BLEZ
/* 1087 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 1105
/* 1091 */    MCD_OPC_CheckPredicate, 2, 214, 45, // Skip to: 12829
/* 1095 */    MCD_OPC_CheckField, 16, 5, 0, 208, 45, // Skip to: 12829
/* 1101 */    MCD_OPC_Decode, 171, 1, 47, // Opcode: BGTZ
/* 1105 */    MCD_OPC_FilterValue, 8, 7, 0, // Skip to: 1116
/* 1109 */    MCD_OPC_CheckPredicate, 2, 196, 45, // Skip to: 12829
/* 1113 */    MCD_OPC_Decode, 63, 52, // Opcode: ADDi
/* 1116 */    MCD_OPC_FilterValue, 9, 7, 0, // Skip to: 1127
/* 1120 */    MCD_OPC_CheckPredicate, 2, 185, 45, // Skip to: 12829
/* 1124 */    MCD_OPC_Decode, 65, 52, // Opcode: ADDiu
/* 1127 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 1139
/* 1131 */    MCD_OPC_CheckPredicate, 2, 174, 45, // Skip to: 12829
/* 1135 */    MCD_OPC_Decode, 225, 9, 52, // Opcode: SLTi
/* 1139 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1151
/* 1143 */    MCD_OPC_CheckPredicate, 2, 162, 45, // Skip to: 12829
/* 1147 */    MCD_OPC_Decode, 228, 9, 52, // Opcode: SLTiu
/* 1151 */    MCD_OPC_FilterValue, 12, 7, 0, // Skip to: 1162
/* 1155 */    MCD_OPC_CheckPredicate, 2, 150, 45, // Skip to: 12829
/* 1159 */    MCD_OPC_Decode, 79, 53, // Opcode: ANDi
/* 1162 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 1174
/* 1166 */    MCD_OPC_CheckPredicate, 2, 139, 45, // Skip to: 12829
/* 1170 */    MCD_OPC_Decode, 173, 8, 53, // Opcode: ORi
/* 1174 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 1186
/* 1178 */    MCD_OPC_CheckPredicate, 2, 127, 45, // Skip to: 12829
/* 1182 */    MCD_OPC_Decode, 200, 11, 53, // Opcode: XORi
/* 1186 */    MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 1204
/* 1190 */    MCD_OPC_CheckPredicate, 2, 115, 45, // Skip to: 12829
/* 1194 */    MCD_OPC_CheckField, 21, 5, 0, 109, 45, // Skip to: 12829
/* 1200 */    MCD_OPC_Decode, 158, 6, 26, // Opcode: LUi
/* 1204 */    MCD_OPC_FilterValue, 16, 117, 0, // Skip to: 1325
/* 1208 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1211 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 1229
/* 1215 */    MCD_OPC_CheckPredicate, 2, 90, 45, // Skip to: 12829
/* 1219 */    MCD_OPC_CheckField, 3, 8, 0, 84, 45, // Skip to: 12829
/* 1225 */    MCD_OPC_Decode, 236, 6, 54, // Opcode: MFC0
/* 1229 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 1247
/* 1233 */    MCD_OPC_CheckPredicate, 2, 72, 45, // Skip to: 12829
/* 1237 */    MCD_OPC_CheckField, 3, 8, 0, 66, 45, // Skip to: 12829
/* 1243 */    MCD_OPC_Decode, 213, 7, 54, // Opcode: MTC0
/* 1247 */    MCD_OPC_FilterValue, 11, 31, 0, // Skip to: 1282
/* 1251 */    MCD_OPC_ExtractField, 0, 16,  // Inst{15-0} ...
/* 1254 */    MCD_OPC_FilterValue, 128, 192, 1, 8, 0, // Skip to: 1268
/* 1260 */    MCD_OPC_CheckPredicate, 2, 45, 45, // Skip to: 12829
/* 1264 */    MCD_OPC_Decode, 177, 3, 18, // Opcode: DI
/* 1268 */    MCD_OPC_FilterValue, 160, 192, 1, 35, 45, // Skip to: 12829
/* 1274 */    MCD_OPC_CheckPredicate, 2, 31, 45, // Skip to: 12829
/* 1278 */    MCD_OPC_Decode, 253, 3, 18, // Opcode: EI
/* 1282 */    MCD_OPC_FilterValue, 16, 23, 45, // Skip to: 12829
/* 1286 */    MCD_OPC_ExtractField, 0, 21,  // Inst{20-0} ...
/* 1289 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 1301
/* 1293 */    MCD_OPC_CheckPredicate, 2, 12, 45, // Skip to: 12829
/* 1297 */    MCD_OPC_Decode, 255, 3, 0, // Opcode: ERET
/* 1301 */    MCD_OPC_FilterValue, 31, 8, 0, // Skip to: 1313
/* 1305 */    MCD_OPC_CheckPredicate, 2, 0, 45, // Skip to: 12829
/* 1309 */    MCD_OPC_Decode, 172, 3, 0, // Opcode: DERET
/* 1313 */    MCD_OPC_FilterValue, 32, 248, 44, // Skip to: 12829
/* 1317 */    MCD_OPC_CheckPredicate, 2, 244, 44, // Skip to: 12829
/* 1321 */    MCD_OPC_Decode, 187, 11, 0, // Opcode: WAIT
/* 1325 */    MCD_OPC_FilterValue, 17, 253, 5, // Skip to: 2862
/* 1329 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1332 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 1350
/* 1336 */    MCD_OPC_CheckPredicate, 2, 225, 44, // Skip to: 12829
/* 1340 */    MCD_OPC_CheckField, 0, 11, 0, 219, 44, // Skip to: 12829
/* 1346 */    MCD_OPC_Decode, 237, 6, 55, // Opcode: MFC1
/* 1350 */    MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 1368
/* 1354 */    MCD_OPC_CheckPredicate, 2, 207, 44, // Skip to: 12829
/* 1358 */    MCD_OPC_CheckField, 0, 11, 0, 201, 44, // Skip to: 12829
/* 1364 */    MCD_OPC_Decode, 192, 3, 56, // Opcode: DMFC1
/* 1368 */    MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 1386
/* 1372 */    MCD_OPC_CheckPredicate, 2, 189, 44, // Skip to: 12829
/* 1376 */    MCD_OPC_CheckField, 0, 11, 0, 183, 44, // Skip to: 12829
/* 1382 */    MCD_OPC_Decode, 155, 2, 57, // Opcode: CFC1
/* 1386 */    MCD_OPC_FilterValue, 3, 14, 0, // Skip to: 1404
/* 1390 */    MCD_OPC_CheckPredicate, 2, 171, 44, // Skip to: 12829
/* 1394 */    MCD_OPC_CheckField, 0, 11, 0, 165, 44, // Skip to: 12829
/* 1400 */    MCD_OPC_Decode, 240, 6, 58, // Opcode: MFHC1
/* 1404 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 1422
/* 1408 */    MCD_OPC_CheckPredicate, 2, 153, 44, // Skip to: 12829
/* 1412 */    MCD_OPC_CheckField, 0, 11, 0, 147, 44, // Skip to: 12829
/* 1418 */    MCD_OPC_Decode, 214, 7, 59, // Opcode: MTC1
/* 1422 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 1440
/* 1426 */    MCD_OPC_CheckPredicate, 2, 135, 44, // Skip to: 12829
/* 1430 */    MCD_OPC_CheckField, 0, 11, 0, 129, 44, // Skip to: 12829
/* 1436 */    MCD_OPC_Decode, 195, 3, 60, // Opcode: DMTC1
/* 1440 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 1458
/* 1444 */    MCD_OPC_CheckPredicate, 2, 117, 44, // Skip to: 12829
/* 1448 */    MCD_OPC_CheckField, 0, 11, 0, 111, 44, // Skip to: 12829
/* 1454 */    MCD_OPC_Decode, 217, 2, 61, // Opcode: CTC1
/* 1458 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 1476
/* 1462 */    MCD_OPC_CheckPredicate, 2, 99, 44, // Skip to: 12829
/* 1466 */    MCD_OPC_CheckField, 0, 11, 0, 93, 44, // Skip to: 12829
/* 1472 */    MCD_OPC_Decode, 217, 7, 62, // Opcode: MTHC1
/* 1476 */    MCD_OPC_FilterValue, 8, 27, 0, // Skip to: 1507
/* 1480 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 1483 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1495
/* 1487 */    MCD_OPC_CheckPredicate, 2, 74, 44, // Skip to: 12829
/* 1491 */    MCD_OPC_Decode, 151, 1, 63, // Opcode: BC1F
/* 1495 */    MCD_OPC_FilterValue, 1, 66, 44, // Skip to: 12829
/* 1499 */    MCD_OPC_CheckPredicate, 2, 62, 44, // Skip to: 12829
/* 1503 */    MCD_OPC_Decode, 153, 1, 63, // Opcode: BC1T
/* 1507 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1519
/* 1511 */    MCD_OPC_CheckPredicate, 4, 50, 44, // Skip to: 12829
/* 1515 */    MCD_OPC_Decode, 241, 1, 64, // Opcode: BZ_V
/* 1519 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 1531
/* 1523 */    MCD_OPC_CheckPredicate, 4, 38, 44, // Skip to: 12829
/* 1527 */    MCD_OPC_Decode, 217, 1, 64, // Opcode: BNZ_V
/* 1531 */    MCD_OPC_FilterValue, 16, 80, 2, // Skip to: 2127
/* 1535 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1538 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1550
/* 1542 */    MCD_OPC_CheckPredicate, 2, 19, 44, // Skip to: 12829
/* 1546 */    MCD_OPC_Decode, 156, 4, 65, // Opcode: FADD_S
/* 1550 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 1562
/* 1554 */    MCD_OPC_CheckPredicate, 2, 7, 44, // Skip to: 12829
/* 1558 */    MCD_OPC_Decode, 158, 5, 65, // Opcode: FSUB_S
/* 1562 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 1574
/* 1566 */    MCD_OPC_CheckPredicate, 2, 251, 43, // Skip to: 12829
/* 1570 */    MCD_OPC_Decode, 249, 4, 65, // Opcode: FMUL_S
/* 1574 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 1586
/* 1578 */    MCD_OPC_CheckPredicate, 2, 239, 43, // Skip to: 12829
/* 1582 */    MCD_OPC_Decode, 192, 4, 65, // Opcode: FDIV_S
/* 1586 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 1604
/* 1590 */    MCD_OPC_CheckPredicate, 2, 227, 43, // Skip to: 12829
/* 1594 */    MCD_OPC_CheckField, 16, 5, 0, 221, 43, // Skip to: 12829
/* 1600 */    MCD_OPC_Decode, 151, 5, 66, // Opcode: FSQRT_S
/* 1604 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 1622
/* 1608 */    MCD_OPC_CheckPredicate, 7, 209, 43, // Skip to: 12829
/* 1612 */    MCD_OPC_CheckField, 16, 5, 0, 203, 43, // Skip to: 12829
/* 1618 */    MCD_OPC_Decode, 149, 4, 66, // Opcode: FABS_S
/* 1622 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 1640
/* 1626 */    MCD_OPC_CheckPredicate, 2, 191, 43, // Skip to: 12829
/* 1630 */    MCD_OPC_CheckField, 16, 5, 0, 185, 43, // Skip to: 12829
/* 1636 */    MCD_OPC_Decode, 241, 4, 66, // Opcode: FMOV_S
/* 1640 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 1658
/* 1644 */    MCD_OPC_CheckPredicate, 7, 173, 43, // Skip to: 12829
/* 1648 */    MCD_OPC_CheckField, 16, 5, 0, 167, 43, // Skip to: 12829
/* 1654 */    MCD_OPC_Decode, 255, 4, 66, // Opcode: FNEG_S
/* 1658 */    MCD_OPC_FilterValue, 12, 14, 0, // Skip to: 1676
/* 1662 */    MCD_OPC_CheckPredicate, 2, 155, 43, // Skip to: 12829
/* 1666 */    MCD_OPC_CheckField, 16, 5, 0, 149, 43, // Skip to: 12829
/* 1672 */    MCD_OPC_Decode, 133, 9, 66, // Opcode: ROUND_W_S
/* 1676 */    MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 1694
/* 1680 */    MCD_OPC_CheckPredicate, 2, 137, 43, // Skip to: 12829
/* 1684 */    MCD_OPC_CheckField, 16, 5, 0, 131, 43, // Skip to: 12829
/* 1690 */    MCD_OPC_Decode, 178, 11, 66, // Opcode: TRUNC_W_S
/* 1694 */    MCD_OPC_FilterValue, 14, 14, 0, // Skip to: 1712
/* 1698 */    MCD_OPC_CheckPredicate, 2, 119, 43, // Skip to: 12829
/* 1702 */    MCD_OPC_CheckField, 16, 5, 0, 113, 43, // Skip to: 12829
/* 1708 */    MCD_OPC_Decode, 145, 2, 66, // Opcode: CEIL_W_S
/* 1712 */    MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 1730
/* 1716 */    MCD_OPC_CheckPredicate, 2, 101, 43, // Skip to: 12829
/* 1720 */    MCD_OPC_CheckField, 16, 5, 0, 95, 43, // Skip to: 12829
/* 1726 */    MCD_OPC_Decode, 226, 4, 66, // Opcode: FLOOR_W_S
/* 1730 */    MCD_OPC_FilterValue, 17, 27, 0, // Skip to: 1761
/* 1734 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 1737 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1749
/* 1741 */    MCD_OPC_CheckPredicate, 2, 76, 43, // Skip to: 12829
/* 1745 */    MCD_OPC_Decode, 160, 7, 67, // Opcode: MOVF_S
/* 1749 */    MCD_OPC_FilterValue, 1, 68, 43, // Skip to: 12829
/* 1753 */    MCD_OPC_CheckPredicate, 2, 64, 43, // Skip to: 12829
/* 1757 */    MCD_OPC_Decode, 180, 7, 67, // Opcode: MOVT_S
/* 1761 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 1773
/* 1765 */    MCD_OPC_CheckPredicate, 2, 52, 43, // Skip to: 12829
/* 1769 */    MCD_OPC_Decode, 192, 7, 68, // Opcode: MOVZ_I_S
/* 1773 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 1785
/* 1777 */    MCD_OPC_CheckPredicate, 2, 40, 43, // Skip to: 12829
/* 1781 */    MCD_OPC_Decode, 172, 7, 68, // Opcode: MOVN_I_S
/* 1785 */    MCD_OPC_FilterValue, 33, 14, 0, // Skip to: 1803
/* 1789 */    MCD_OPC_CheckPredicate, 8, 28, 43, // Skip to: 12829
/* 1793 */    MCD_OPC_CheckField, 16, 5, 0, 22, 43, // Skip to: 12829
/* 1799 */    MCD_OPC_Decode, 220, 2, 69, // Opcode: CVT_D32_S
/* 1803 */    MCD_OPC_FilterValue, 36, 14, 0, // Skip to: 1821
/* 1807 */    MCD_OPC_CheckPredicate, 2, 10, 43, // Skip to: 12829
/* 1811 */    MCD_OPC_CheckField, 16, 5, 0, 4, 43, // Skip to: 12829
/* 1817 */    MCD_OPC_Decode, 240, 2, 66, // Opcode: CVT_W_S
/* 1821 */    MCD_OPC_FilterValue, 37, 14, 0, // Skip to: 1839
/* 1825 */    MCD_OPC_CheckPredicate, 2, 248, 42, // Skip to: 12829
/* 1829 */    MCD_OPC_CheckField, 16, 5, 0, 242, 42, // Skip to: 12829
/* 1835 */    MCD_OPC_Decode, 229, 2, 70, // Opcode: CVT_L_S
/* 1839 */    MCD_OPC_FilterValue, 48, 14, 0, // Skip to: 1857
/* 1843 */    MCD_OPC_CheckPredicate, 2, 230, 42, // Skip to: 12829
/* 1847 */    MCD_OPC_CheckField, 6, 5, 0, 224, 42, // Skip to: 12829
/* 1853 */    MCD_OPC_Decode, 247, 2, 71, // Opcode: C_F_S
/* 1857 */    MCD_OPC_FilterValue, 49, 14, 0, // Skip to: 1875
/* 1861 */    MCD_OPC_CheckPredicate, 2, 212, 42, // Skip to: 12829
/* 1865 */    MCD_OPC_CheckField, 6, 5, 0, 206, 42, // Skip to: 12829
/* 1871 */    MCD_OPC_Decode, 161, 3, 71, // Opcode: C_UN_S
/* 1875 */    MCD_OPC_FilterValue, 50, 14, 0, // Skip to: 1893
/* 1879 */    MCD_OPC_CheckPredicate, 2, 194, 42, // Skip to: 12829
/* 1883 */    MCD_OPC_CheckField, 6, 5, 0, 188, 42, // Skip to: 12829
/* 1889 */    MCD_OPC_Decode, 244, 2, 71, // Opcode: C_EQ_S
/* 1893 */    MCD_OPC_FilterValue, 51, 14, 0, // Skip to: 1911
/* 1897 */    MCD_OPC_CheckPredicate, 2, 176, 42, // Skip to: 12829
/* 1901 */    MCD_OPC_CheckField, 6, 5, 0, 170, 42, // Skip to: 12829
/* 1907 */    MCD_OPC_Decode, 152, 3, 71, // Opcode: C_UEQ_S
/* 1911 */    MCD_OPC_FilterValue, 52, 14, 0, // Skip to: 1929
/* 1915 */    MCD_OPC_CheckPredicate, 2, 158, 42, // Skip to: 12829
/* 1919 */    MCD_OPC_CheckField, 6, 5, 0, 152, 42, // Skip to: 12829
/* 1925 */    MCD_OPC_Decode, 143, 3, 71, // Opcode: C_OLT_S
/* 1929 */    MCD_OPC_FilterValue, 53, 14, 0, // Skip to: 1947
/* 1933 */    MCD_OPC_CheckPredicate, 2, 140, 42, // Skip to: 12829
/* 1937 */    MCD_OPC_CheckField, 6, 5, 0, 134, 42, // Skip to: 12829
/* 1943 */    MCD_OPC_Decode, 158, 3, 71, // Opcode: C_ULT_S
/* 1947 */    MCD_OPC_FilterValue, 54, 14, 0, // Skip to: 1965
/* 1951 */    MCD_OPC_CheckPredicate, 2, 122, 42, // Skip to: 12829
/* 1955 */    MCD_OPC_CheckField, 6, 5, 0, 116, 42, // Skip to: 12829
/* 1961 */    MCD_OPC_Decode, 140, 3, 71, // Opcode: C_OLE_S
/* 1965 */    MCD_OPC_FilterValue, 55, 14, 0, // Skip to: 1983
/* 1969 */    MCD_OPC_CheckPredicate, 2, 104, 42, // Skip to: 12829
/* 1973 */    MCD_OPC_CheckField, 6, 5, 0, 98, 42, // Skip to: 12829
/* 1979 */    MCD_OPC_Decode, 155, 3, 71, // Opcode: C_ULE_S
/* 1983 */    MCD_OPC_FilterValue, 56, 14, 0, // Skip to: 2001
/* 1987 */    MCD_OPC_CheckPredicate, 2, 86, 42, // Skip to: 12829
/* 1991 */    MCD_OPC_CheckField, 6, 5, 0, 80, 42, // Skip to: 12829
/* 1997 */    MCD_OPC_Decode, 149, 3, 71, // Opcode: C_SF_S
/* 2001 */    MCD_OPC_FilterValue, 57, 14, 0, // Skip to: 2019
/* 2005 */    MCD_OPC_CheckPredicate, 2, 68, 42, // Skip to: 12829
/* 2009 */    MCD_OPC_CheckField, 6, 5, 0, 62, 42, // Skip to: 12829
/* 2015 */    MCD_OPC_Decode, 131, 3, 71, // Opcode: C_NGLE_S
/* 2019 */    MCD_OPC_FilterValue, 58, 14, 0, // Skip to: 2037
/* 2023 */    MCD_OPC_CheckPredicate, 2, 50, 42, // Skip to: 12829
/* 2027 */    MCD_OPC_CheckField, 6, 5, 0, 44, 42, // Skip to: 12829
/* 2033 */    MCD_OPC_Decode, 146, 3, 71, // Opcode: C_SEQ_S
/* 2037 */    MCD_OPC_FilterValue, 59, 14, 0, // Skip to: 2055
/* 2041 */    MCD_OPC_CheckPredicate, 2, 32, 42, // Skip to: 12829
/* 2045 */    MCD_OPC_CheckField, 6, 5, 0, 26, 42, // Skip to: 12829
/* 2051 */    MCD_OPC_Decode, 134, 3, 71, // Opcode: C_NGL_S
/* 2055 */    MCD_OPC_FilterValue, 60, 14, 0, // Skip to: 2073
/* 2059 */    MCD_OPC_CheckPredicate, 2, 14, 42, // Skip to: 12829
/* 2063 */    MCD_OPC_CheckField, 6, 5, 0, 8, 42, // Skip to: 12829
/* 2069 */    MCD_OPC_Decode, 253, 2, 71, // Opcode: C_LT_S
/* 2073 */    MCD_OPC_FilterValue, 61, 14, 0, // Skip to: 2091
/* 2077 */    MCD_OPC_CheckPredicate, 2, 252, 41, // Skip to: 12829
/* 2081 */    MCD_OPC_CheckField, 6, 5, 0, 246, 41, // Skip to: 12829
/* 2087 */    MCD_OPC_Decode, 128, 3, 71, // Opcode: C_NGE_S
/* 2091 */    MCD_OPC_FilterValue, 62, 14, 0, // Skip to: 2109
/* 2095 */    MCD_OPC_CheckPredicate, 2, 234, 41, // Skip to: 12829
/* 2099 */    MCD_OPC_CheckField, 6, 5, 0, 228, 41, // Skip to: 12829
/* 2105 */    MCD_OPC_Decode, 250, 2, 71, // Opcode: C_LE_S
/* 2109 */    MCD_OPC_FilterValue, 63, 220, 41, // Skip to: 12829
/* 2113 */    MCD_OPC_CheckPredicate, 2, 216, 41, // Skip to: 12829
/* 2117 */    MCD_OPC_CheckField, 6, 5, 0, 210, 41, // Skip to: 12829
/* 2123 */    MCD_OPC_Decode, 137, 3, 71, // Opcode: C_NGT_S
/* 2127 */    MCD_OPC_FilterValue, 17, 80, 2, // Skip to: 2723
/* 2131 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 2134 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 2146
/* 2138 */    MCD_OPC_CheckPredicate, 8, 191, 41, // Skip to: 12829
/* 2142 */    MCD_OPC_Decode, 153, 4, 72, // Opcode: FADD_D32
/* 2146 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 2158
/* 2150 */    MCD_OPC_CheckPredicate, 8, 179, 41, // Skip to: 12829
/* 2154 */    MCD_OPC_Decode, 155, 5, 72, // Opcode: FSUB_D32
/* 2158 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 2170
/* 2162 */    MCD_OPC_CheckPredicate, 8, 167, 41, // Skip to: 12829
/* 2166 */    MCD_OPC_Decode, 246, 4, 72, // Opcode: FMUL_D32
/* 2170 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 2182
/* 2174 */    MCD_OPC_CheckPredicate, 8, 155, 41, // Skip to: 12829
/* 2178 */    MCD_OPC_Decode, 189, 4, 72, // Opcode: FDIV_D32
/* 2182 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 2200
/* 2186 */    MCD_OPC_CheckPredicate, 8, 143, 41, // Skip to: 12829
/* 2190 */    MCD_OPC_CheckField, 16, 5, 0, 137, 41, // Skip to: 12829
/* 2196 */    MCD_OPC_Decode, 148, 5, 73, // Opcode: FSQRT_D32
/* 2200 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 2218
/* 2204 */    MCD_OPC_CheckPredicate, 7, 125, 41, // Skip to: 12829
/* 2208 */    MCD_OPC_CheckField, 16, 5, 0, 119, 41, // Skip to: 12829
/* 2214 */    MCD_OPC_Decode, 146, 4, 73, // Opcode: FABS_D32
/* 2218 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 2236
/* 2222 */    MCD_OPC_CheckPredicate, 8, 107, 41, // Skip to: 12829
/* 2226 */    MCD_OPC_CheckField, 16, 5, 0, 101, 41, // Skip to: 12829
/* 2232 */    MCD_OPC_Decode, 238, 4, 73, // Opcode: FMOV_D32
/* 2236 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 2254
/* 2240 */    MCD_OPC_CheckPredicate, 7, 89, 41, // Skip to: 12829
/* 2244 */    MCD_OPC_CheckField, 16, 5, 0, 83, 41, // Skip to: 12829
/* 2250 */    MCD_OPC_Decode, 252, 4, 73, // Opcode: FNEG_D32
/* 2254 */    MCD_OPC_FilterValue, 12, 14, 0, // Skip to: 2272
/* 2258 */    MCD_OPC_CheckPredicate, 8, 71, 41, // Skip to: 12829
/* 2262 */    MCD_OPC_CheckField, 16, 5, 0, 65, 41, // Skip to: 12829
/* 2268 */    MCD_OPC_Decode, 130, 9, 74, // Opcode: ROUND_W_D32
/* 2272 */    MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 2290
/* 2276 */    MCD_OPC_CheckPredicate, 8, 53, 41, // Skip to: 12829
/* 2280 */    MCD_OPC_CheckField, 16, 5, 0, 47, 41, // Skip to: 12829
/* 2286 */    MCD_OPC_Decode, 175, 11, 74, // Opcode: TRUNC_W_D32
/* 2290 */    MCD_OPC_FilterValue, 14, 14, 0, // Skip to: 2308
/* 2294 */    MCD_OPC_CheckPredicate, 8, 35, 41, // Skip to: 12829
/* 2298 */    MCD_OPC_CheckField, 16, 5, 0, 29, 41, // Skip to: 12829
/* 2304 */    MCD_OPC_Decode, 142, 2, 74, // Opcode: CEIL_W_D32
/* 2308 */    MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 2326
/* 2312 */    MCD_OPC_CheckPredicate, 8, 17, 41, // Skip to: 12829
/* 2316 */    MCD_OPC_CheckField, 16, 5, 0, 11, 41, // Skip to: 12829
/* 2322 */    MCD_OPC_Decode, 223, 4, 74, // Opcode: FLOOR_W_D32
/* 2326 */    MCD_OPC_FilterValue, 17, 27, 0, // Skip to: 2357
/* 2330 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 2333 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 2345
/* 2337 */    MCD_OPC_CheckPredicate, 8, 248, 40, // Skip to: 12829
/* 2341 */    MCD_OPC_Decode, 154, 7, 75, // Opcode: MOVF_D32
/* 2345 */    MCD_OPC_FilterValue, 1, 240, 40, // Skip to: 12829
/* 2349 */    MCD_OPC_CheckPredicate, 8, 236, 40, // Skip to: 12829
/* 2353 */    MCD_OPC_Decode, 174, 7, 75, // Opcode: MOVT_D32
/* 2357 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 2369
/* 2361 */    MCD_OPC_CheckPredicate, 8, 224, 40, // Skip to: 12829
/* 2365 */    MCD_OPC_Decode, 186, 7, 76, // Opcode: MOVZ_I_D32
/* 2369 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 2381
/* 2373 */    MCD_OPC_CheckPredicate, 8, 212, 40, // Skip to: 12829
/* 2377 */    MCD_OPC_Decode, 166, 7, 76, // Opcode: MOVN_I_D32
/* 2381 */    MCD_OPC_FilterValue, 32, 14, 0, // Skip to: 2399
/* 2385 */    MCD_OPC_CheckPredicate, 8, 200, 40, // Skip to: 12829
/* 2389 */    MCD_OPC_CheckField, 16, 5, 0, 194, 40, // Skip to: 12829
/* 2395 */    MCD_OPC_Decode, 231, 2, 74, // Opcode: CVT_S_D32
/* 2399 */    MCD_OPC_FilterValue, 36, 14, 0, // Skip to: 2417
/* 2403 */    MCD_OPC_CheckPredicate, 8, 182, 40, // Skip to: 12829
/* 2407 */    MCD_OPC_CheckField, 16, 5, 0, 176, 40, // Skip to: 12829
/* 2413 */    MCD_OPC_Decode, 237, 2, 74, // Opcode: CVT_W_D32
/* 2417 */    MCD_OPC_FilterValue, 37, 14, 0, // Skip to: 2435
/* 2421 */    MCD_OPC_CheckPredicate, 2, 164, 40, // Skip to: 12829
/* 2425 */    MCD_OPC_CheckField, 16, 5, 0, 158, 40, // Skip to: 12829
/* 2431 */    MCD_OPC_Decode, 227, 2, 77, // Opcode: CVT_L_D64
/* 2435 */    MCD_OPC_FilterValue, 48, 14, 0, // Skip to: 2453
/* 2439 */    MCD_OPC_CheckPredicate, 8, 146, 40, // Skip to: 12829
/* 2443 */    MCD_OPC_CheckField, 6, 5, 0, 140, 40, // Skip to: 12829
/* 2449 */    MCD_OPC_Decode, 245, 2, 78, // Opcode: C_F_D32
/* 2453 */    MCD_OPC_FilterValue, 49, 14, 0, // Skip to: 2471
/* 2457 */    MCD_OPC_CheckPredicate, 8, 128, 40, // Skip to: 12829
/* 2461 */    MCD_OPC_CheckField, 6, 5, 0, 122, 40, // Skip to: 12829
/* 2467 */    MCD_OPC_Decode, 159, 3, 78, // Opcode: C_UN_D32
/* 2471 */    MCD_OPC_FilterValue, 50, 14, 0, // Skip to: 2489
/* 2475 */    MCD_OPC_CheckPredicate, 8, 110, 40, // Skip to: 12829
/* 2479 */    MCD_OPC_CheckField, 6, 5, 0, 104, 40, // Skip to: 12829
/* 2485 */    MCD_OPC_Decode, 242, 2, 78, // Opcode: C_EQ_D32
/* 2489 */    MCD_OPC_FilterValue, 51, 14, 0, // Skip to: 2507
/* 2493 */    MCD_OPC_CheckPredicate, 8, 92, 40, // Skip to: 12829
/* 2497 */    MCD_OPC_CheckField, 6, 5, 0, 86, 40, // Skip to: 12829
/* 2503 */    MCD_OPC_Decode, 150, 3, 78, // Opcode: C_UEQ_D32
/* 2507 */    MCD_OPC_FilterValue, 52, 14, 0, // Skip to: 2525
/* 2511 */    MCD_OPC_CheckPredicate, 8, 74, 40, // Skip to: 12829
/* 2515 */    MCD_OPC_CheckField, 6, 5, 0, 68, 40, // Skip to: 12829
/* 2521 */    MCD_OPC_Decode, 141, 3, 78, // Opcode: C_OLT_D32
/* 2525 */    MCD_OPC_FilterValue, 53, 14, 0, // Skip to: 2543
/* 2529 */    MCD_OPC_CheckPredicate, 8, 56, 40, // Skip to: 12829
/* 2533 */    MCD_OPC_CheckField, 6, 5, 0, 50, 40, // Skip to: 12829
/* 2539 */    MCD_OPC_Decode, 156, 3, 78, // Opcode: C_ULT_D32
/* 2543 */    MCD_OPC_FilterValue, 54, 14, 0, // Skip to: 2561
/* 2547 */    MCD_OPC_CheckPredicate, 8, 38, 40, // Skip to: 12829
/* 2551 */    MCD_OPC_CheckField, 6, 5, 0, 32, 40, // Skip to: 12829
/* 2557 */    MCD_OPC_Decode, 138, 3, 78, // Opcode: C_OLE_D32
/* 2561 */    MCD_OPC_FilterValue, 55, 14, 0, // Skip to: 2579
/* 2565 */    MCD_OPC_CheckPredicate, 8, 20, 40, // Skip to: 12829
/* 2569 */    MCD_OPC_CheckField, 6, 5, 0, 14, 40, // Skip to: 12829
/* 2575 */    MCD_OPC_Decode, 153, 3, 78, // Opcode: C_ULE_D32
/* 2579 */    MCD_OPC_FilterValue, 56, 14, 0, // Skip to: 2597
/* 2583 */    MCD_OPC_CheckPredicate, 8, 2, 40, // Skip to: 12829
/* 2587 */    MCD_OPC_CheckField, 6, 5, 0, 252, 39, // Skip to: 12829
/* 2593 */    MCD_OPC_Decode, 147, 3, 78, // Opcode: C_SF_D32
/* 2597 */    MCD_OPC_FilterValue, 57, 14, 0, // Skip to: 2615
/* 2601 */    MCD_OPC_CheckPredicate, 8, 240, 39, // Skip to: 12829
/* 2605 */    MCD_OPC_CheckField, 6, 5, 0, 234, 39, // Skip to: 12829
/* 2611 */    MCD_OPC_Decode, 129, 3, 78, // Opcode: C_NGLE_D32
/* 2615 */    MCD_OPC_FilterValue, 58, 14, 0, // Skip to: 2633
/* 2619 */    MCD_OPC_CheckPredicate, 8, 222, 39, // Skip to: 12829
/* 2623 */    MCD_OPC_CheckField, 6, 5, 0, 216, 39, // Skip to: 12829
/* 2629 */    MCD_OPC_Decode, 144, 3, 78, // Opcode: C_SEQ_D32
/* 2633 */    MCD_OPC_FilterValue, 59, 14, 0, // Skip to: 2651
/* 2637 */    MCD_OPC_CheckPredicate, 8, 204, 39, // Skip to: 12829
/* 2641 */    MCD_OPC_CheckField, 6, 5, 0, 198, 39, // Skip to: 12829
/* 2647 */    MCD_OPC_Decode, 132, 3, 78, // Opcode: C_NGL_D32
/* 2651 */    MCD_OPC_FilterValue, 60, 14, 0, // Skip to: 2669
/* 2655 */    MCD_OPC_CheckPredicate, 8, 186, 39, // Skip to: 12829
/* 2659 */    MCD_OPC_CheckField, 6, 5, 0, 180, 39, // Skip to: 12829
/* 2665 */    MCD_OPC_Decode, 251, 2, 78, // Opcode: C_LT_D32
/* 2669 */    MCD_OPC_FilterValue, 61, 14, 0, // Skip to: 2687
/* 2673 */    MCD_OPC_CheckPredicate, 8, 168, 39, // Skip to: 12829
/* 2677 */    MCD_OPC_CheckField, 6, 5, 0, 162, 39, // Skip to: 12829
/* 2683 */    MCD_OPC_Decode, 254, 2, 78, // Opcode: C_NGE_D32
/* 2687 */    MCD_OPC_FilterValue, 62, 14, 0, // Skip to: 2705
/* 2691 */    MCD_OPC_CheckPredicate, 8, 150, 39, // Skip to: 12829
/* 2695 */    MCD_OPC_CheckField, 6, 5, 0, 144, 39, // Skip to: 12829
/* 2701 */    MCD_OPC_Decode, 248, 2, 78, // Opcode: C_LE_D32
/* 2705 */    MCD_OPC_FilterValue, 63, 136, 39, // Skip to: 12829
/* 2709 */    MCD_OPC_CheckPredicate, 8, 132, 39, // Skip to: 12829
/* 2713 */    MCD_OPC_CheckField, 6, 5, 0, 126, 39, // Skip to: 12829
/* 2719 */    MCD_OPC_Decode, 135, 3, 78, // Opcode: C_NGT_D32
/* 2723 */    MCD_OPC_FilterValue, 20, 39, 0, // Skip to: 2766
/* 2727 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 2730 */    MCD_OPC_FilterValue, 32, 14, 0, // Skip to: 2748
/* 2734 */    MCD_OPC_CheckPredicate, 2, 107, 39, // Skip to: 12829
/* 2738 */    MCD_OPC_CheckField, 16, 5, 0, 101, 39, // Skip to: 12829
/* 2744 */    MCD_OPC_Decode, 235, 2, 66, // Opcode: CVT_S_W
/* 2748 */    MCD_OPC_FilterValue, 33, 93, 39, // Skip to: 12829
/* 2752 */    MCD_OPC_CheckPredicate, 8, 89, 39, // Skip to: 12829
/* 2756 */    MCD_OPC_CheckField, 16, 5, 0, 83, 39, // Skip to: 12829
/* 2762 */    MCD_OPC_Decode, 221, 2, 69, // Opcode: CVT_D32_W
/* 2766 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 2778
/* 2770 */    MCD_OPC_CheckPredicate, 4, 71, 39, // Skip to: 12829
/* 2774 */    MCD_OPC_Decode, 238, 1, 64, // Opcode: BZ_B
/* 2778 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 2790
/* 2782 */    MCD_OPC_CheckPredicate, 4, 59, 39, // Skip to: 12829
/* 2786 */    MCD_OPC_Decode, 240, 1, 79, // Opcode: BZ_H
/* 2790 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 2802
/* 2794 */    MCD_OPC_CheckPredicate, 4, 47, 39, // Skip to: 12829
/* 2798 */    MCD_OPC_Decode, 242, 1, 80, // Opcode: BZ_W
/* 2802 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 2814
/* 2806 */    MCD_OPC_CheckPredicate, 4, 35, 39, // Skip to: 12829
/* 2810 */    MCD_OPC_Decode, 239, 1, 81, // Opcode: BZ_D
/* 2814 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 2826
/* 2818 */    MCD_OPC_CheckPredicate, 4, 23, 39, // Skip to: 12829
/* 2822 */    MCD_OPC_Decode, 214, 1, 64, // Opcode: BNZ_B
/* 2826 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 2838
/* 2830 */    MCD_OPC_CheckPredicate, 4, 11, 39, // Skip to: 12829
/* 2834 */    MCD_OPC_Decode, 216, 1, 79, // Opcode: BNZ_H
/* 2838 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 2850
/* 2842 */    MCD_OPC_CheckPredicate, 4, 255, 38, // Skip to: 12829
/* 2846 */    MCD_OPC_Decode, 218, 1, 80, // Opcode: BNZ_W
/* 2850 */    MCD_OPC_FilterValue, 31, 247, 38, // Skip to: 12829
/* 2854 */    MCD_OPC_CheckPredicate, 4, 243, 38, // Skip to: 12829
/* 2858 */    MCD_OPC_Decode, 215, 1, 81, // Opcode: BNZ_D
/* 2862 */    MCD_OPC_FilterValue, 18, 39, 0, // Skip to: 2905
/* 2866 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 2869 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 2887
/* 2873 */    MCD_OPC_CheckPredicate, 2, 224, 38, // Skip to: 12829
/* 2877 */    MCD_OPC_CheckField, 3, 8, 0, 218, 38, // Skip to: 12829
/* 2883 */    MCD_OPC_Decode, 239, 6, 54, // Opcode: MFC2
/* 2887 */    MCD_OPC_FilterValue, 4, 210, 38, // Skip to: 12829
/* 2891 */    MCD_OPC_CheckPredicate, 2, 206, 38, // Skip to: 12829
/* 2895 */    MCD_OPC_CheckField, 3, 8, 0, 200, 38, // Skip to: 12829
/* 2901 */    MCD_OPC_Decode, 216, 7, 54, // Opcode: MTC2
/* 2905 */    MCD_OPC_FilterValue, 19, 207, 0, // Skip to: 3116
/* 2909 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 2912 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 2930
/* 2916 */    MCD_OPC_CheckPredicate, 9, 181, 38, // Skip to: 12829
/* 2920 */    MCD_OPC_CheckField, 11, 5, 0, 175, 38, // Skip to: 12829
/* 2926 */    MCD_OPC_Decode, 174, 6, 82, // Opcode: LWXC1
/* 2930 */    MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 2948
/* 2934 */    MCD_OPC_CheckPredicate, 10, 163, 38, // Skip to: 12829
/* 2938 */    MCD_OPC_CheckField, 11, 5, 0, 157, 38, // Skip to: 12829
/* 2944 */    MCD_OPC_Decode, 131, 6, 83, // Opcode: LDXC1
/* 2948 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 2966
/* 2952 */    MCD_OPC_CheckPredicate, 8, 145, 38, // Skip to: 12829
/* 2956 */    MCD_OPC_CheckField, 11, 5, 0, 139, 38, // Skip to: 12829
/* 2962 */    MCD_OPC_Decode, 155, 6, 83, // Opcode: LUXC1
/* 2966 */    MCD_OPC_FilterValue, 8, 14, 0, // Skip to: 2984
/* 2970 */    MCD_OPC_CheckPredicate, 9, 127, 38, // Skip to: 12829
/* 2974 */    MCD_OPC_CheckField, 6, 5, 0, 121, 38, // Skip to: 12829
/* 2980 */    MCD_OPC_Decode, 222, 10, 84, // Opcode: SWXC1
/* 2984 */    MCD_OPC_FilterValue, 9, 14, 0, // Skip to: 3002
/* 2988 */    MCD_OPC_CheckPredicate, 10, 109, 38, // Skip to: 12829
/* 2992 */    MCD_OPC_CheckField, 6, 5, 0, 103, 38, // Skip to: 12829
/* 2998 */    MCD_OPC_Decode, 162, 9, 85, // Opcode: SDXC1
/* 3002 */    MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 3020
/* 3006 */    MCD_OPC_CheckPredicate, 8, 91, 38, // Skip to: 12829
/* 3010 */    MCD_OPC_CheckField, 6, 5, 0, 85, 38, // Skip to: 12829
/* 3016 */    MCD_OPC_Decode, 208, 10, 85, // Opcode: SUXC1
/* 3020 */    MCD_OPC_FilterValue, 32, 8, 0, // Skip to: 3032
/* 3024 */    MCD_OPC_CheckPredicate, 3, 73, 38, // Skip to: 12829
/* 3028 */    MCD_OPC_Decode, 210, 6, 86, // Opcode: MADD_S
/* 3032 */    MCD_OPC_FilterValue, 33, 8, 0, // Skip to: 3044
/* 3036 */    MCD_OPC_CheckPredicate, 11, 61, 38, // Skip to: 12829
/* 3040 */    MCD_OPC_Decode, 203, 6, 87, // Opcode: MADD_D32
/* 3044 */    MCD_OPC_FilterValue, 40, 8, 0, // Skip to: 3056
/* 3048 */    MCD_OPC_CheckPredicate, 3, 49, 38, // Skip to: 12829
/* 3052 */    MCD_OPC_Decode, 211, 7, 86, // Opcode: MSUB_S
/* 3056 */    MCD_OPC_FilterValue, 41, 8, 0, // Skip to: 3068
/* 3060 */    MCD_OPC_CheckPredicate, 11, 37, 38, // Skip to: 12829
/* 3064 */    MCD_OPC_Decode, 204, 7, 87, // Opcode: MSUB_D32
/* 3068 */    MCD_OPC_FilterValue, 48, 8, 0, // Skip to: 3080
/* 3072 */    MCD_OPC_CheckPredicate, 12, 25, 38, // Skip to: 12829
/* 3076 */    MCD_OPC_Decode, 147, 8, 86, // Opcode: NMADD_S
/* 3080 */    MCD_OPC_FilterValue, 49, 8, 0, // Skip to: 3092
/* 3084 */    MCD_OPC_CheckPredicate, 13, 13, 38, // Skip to: 12829
/* 3088 */    MCD_OPC_Decode, 144, 8, 87, // Opcode: NMADD_D32
/* 3092 */    MCD_OPC_FilterValue, 56, 8, 0, // Skip to: 3104
/* 3096 */    MCD_OPC_CheckPredicate, 12, 1, 38, // Skip to: 12829
/* 3100 */    MCD_OPC_Decode, 152, 8, 86, // Opcode: NMSUB_S
/* 3104 */    MCD_OPC_FilterValue, 57, 249, 37, // Skip to: 12829
/* 3108 */    MCD_OPC_CheckPredicate, 13, 245, 37, // Skip to: 12829
/* 3112 */    MCD_OPC_Decode, 149, 8, 87, // Opcode: NMSUB_D32
/* 3116 */    MCD_OPC_FilterValue, 28, 171, 0, // Skip to: 3291
/* 3120 */    MCD_OPC_ExtractField, 0, 11,  // Inst{10-0} ...
/* 3123 */    MCD_OPC_FilterValue, 0, 29, 0, // Skip to: 3156
/* 3127 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3130 */    MCD_OPC_FilterValue, 0, 223, 37, // Skip to: 12829
/* 3134 */    MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 3148
/* 3138 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3148
/* 3144 */    MCD_OPC_Decode, 193, 6, 20, // Opcode: MADD
/* 3148 */    MCD_OPC_CheckPredicate, 5, 205, 37, // Skip to: 12829
/* 3152 */    MCD_OPC_Decode, 206, 6, 88, // Opcode: MADD_DSP
/* 3156 */    MCD_OPC_FilterValue, 1, 29, 0, // Skip to: 3189
/* 3160 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3163 */    MCD_OPC_FilterValue, 0, 190, 37, // Skip to: 12829
/* 3167 */    MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 3181
/* 3171 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3181
/* 3177 */    MCD_OPC_Decode, 196, 6, 20, // Opcode: MADDU
/* 3181 */    MCD_OPC_CheckPredicate, 5, 172, 37, // Skip to: 12829
/* 3185 */    MCD_OPC_Decode, 197, 6, 88, // Opcode: MADDU_DSP
/* 3189 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 3201
/* 3193 */    MCD_OPC_CheckPredicate, 2, 160, 37, // Skip to: 12829
/* 3197 */    MCD_OPC_Decode, 228, 7, 13, // Opcode: MUL
/* 3201 */    MCD_OPC_FilterValue, 4, 29, 0, // Skip to: 3234
/* 3205 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3208 */    MCD_OPC_FilterValue, 0, 145, 37, // Skip to: 12829
/* 3212 */    MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 3226
/* 3216 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3226
/* 3222 */    MCD_OPC_Decode, 194, 7, 20, // Opcode: MSUB
/* 3226 */    MCD_OPC_CheckPredicate, 5, 127, 37, // Skip to: 12829
/* 3230 */    MCD_OPC_Decode, 207, 7, 88, // Opcode: MSUB_DSP
/* 3234 */    MCD_OPC_FilterValue, 5, 29, 0, // Skip to: 3267
/* 3238 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3241 */    MCD_OPC_FilterValue, 0, 112, 37, // Skip to: 12829
/* 3245 */    MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 3259
/* 3249 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3259
/* 3255 */    MCD_OPC_Decode, 197, 7, 20, // Opcode: MSUBU
/* 3259 */    MCD_OPC_CheckPredicate, 5, 94, 37, // Skip to: 12829
/* 3263 */    MCD_OPC_Decode, 198, 7, 88, // Opcode: MSUBU_DSP
/* 3267 */    MCD_OPC_FilterValue, 32, 8, 0, // Skip to: 3279
/* 3271 */    MCD_OPC_CheckPredicate, 14, 82, 37, // Skip to: 12829
/* 3275 */    MCD_OPC_Decode, 192, 2, 89, // Opcode: CLZ
/* 3279 */    MCD_OPC_FilterValue, 33, 74, 37, // Skip to: 12829
/* 3283 */    MCD_OPC_CheckPredicate, 14, 70, 37, // Skip to: 12829
/* 3287 */    MCD_OPC_Decode, 174, 2, 89, // Opcode: CLO
/* 3291 */    MCD_OPC_FilterValue, 30, 171, 26, // Skip to: 10122
/* 3295 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 3298 */    MCD_OPC_FilterValue, 0, 50, 0, // Skip to: 3352
/* 3302 */    MCD_OPC_ExtractField, 24, 2,  // Inst{25-24} ...
/* 3305 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 3316
/* 3309 */    MCD_OPC_CheckPredicate, 4, 44, 37, // Skip to: 12829
/* 3313 */    MCD_OPC_Decode, 73, 90, // Opcode: ANDI_B
/* 3316 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3328
/* 3320 */    MCD_OPC_CheckPredicate, 4, 33, 37, // Skip to: 12829
/* 3324 */    MCD_OPC_Decode, 167, 8, 90, // Opcode: ORI_B
/* 3328 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 3340
/* 3332 */    MCD_OPC_CheckPredicate, 4, 21, 37, // Skip to: 12829
/* 3336 */    MCD_OPC_Decode, 157, 8, 90, // Opcode: NORI_B
/* 3340 */    MCD_OPC_FilterValue, 3, 13, 37, // Skip to: 12829
/* 3344 */    MCD_OPC_CheckPredicate, 4, 9, 37, // Skip to: 12829
/* 3348 */    MCD_OPC_Decode, 194, 11, 90, // Opcode: XORI_B
/* 3352 */    MCD_OPC_FilterValue, 1, 39, 0, // Skip to: 3395
/* 3356 */    MCD_OPC_ExtractField, 24, 2,  // Inst{25-24} ...
/* 3359 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3371
/* 3363 */    MCD_OPC_CheckPredicate, 4, 246, 36, // Skip to: 12829
/* 3367 */    MCD_OPC_Decode, 199, 1, 91, // Opcode: BMNZI_B
/* 3371 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3383
/* 3375 */    MCD_OPC_CheckPredicate, 4, 234, 36, // Skip to: 12829
/* 3379 */    MCD_OPC_Decode, 201, 1, 91, // Opcode: BMZI_B
/* 3383 */    MCD_OPC_FilterValue, 2, 226, 36, // Skip to: 12829
/* 3387 */    MCD_OPC_CheckPredicate, 4, 222, 36, // Skip to: 12829
/* 3391 */    MCD_OPC_Decode, 223, 1, 91, // Opcode: BSELI_B
/* 3395 */    MCD_OPC_FilterValue, 2, 39, 0, // Skip to: 3438
/* 3399 */    MCD_OPC_ExtractField, 24, 2,  // Inst{25-24} ...
/* 3402 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3414
/* 3406 */    MCD_OPC_CheckPredicate, 4, 203, 36, // Skip to: 12829
/* 3410 */    MCD_OPC_Decode, 172, 9, 90, // Opcode: SHF_B
/* 3414 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3426
/* 3418 */    MCD_OPC_CheckPredicate, 4, 191, 36, // Skip to: 12829
/* 3422 */    MCD_OPC_Decode, 173, 9, 92, // Opcode: SHF_H
/* 3426 */    MCD_OPC_FilterValue, 2, 183, 36, // Skip to: 12829
/* 3430 */    MCD_OPC_CheckPredicate, 4, 179, 36, // Skip to: 12829
/* 3434 */    MCD_OPC_Decode, 174, 9, 93, // Opcode: SHF_W
/* 3438 */    MCD_OPC_FilterValue, 6, 31, 1, // Skip to: 3729
/* 3442 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 3445 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 3456
/* 3449 */    MCD_OPC_CheckPredicate, 4, 160, 36, // Skip to: 12829
/* 3453 */    MCD_OPC_Decode, 49, 94, // Opcode: ADDVI_B
/* 3456 */    MCD_OPC_FilterValue, 1, 7, 0, // Skip to: 3467
/* 3460 */    MCD_OPC_CheckPredicate, 4, 149, 36, // Skip to: 12829
/* 3464 */    MCD_OPC_Decode, 51, 95, // Opcode: ADDVI_H
/* 3467 */    MCD_OPC_FilterValue, 2, 7, 0, // Skip to: 3478
/* 3471 */    MCD_OPC_CheckPredicate, 4, 138, 36, // Skip to: 12829
/* 3475 */    MCD_OPC_Decode, 52, 96, // Opcode: ADDVI_W
/* 3478 */    MCD_OPC_FilterValue, 3, 7, 0, // Skip to: 3489
/* 3482 */    MCD_OPC_CheckPredicate, 4, 127, 36, // Skip to: 12829
/* 3486 */    MCD_OPC_Decode, 50, 97, // Opcode: ADDVI_D
/* 3489 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 3501
/* 3493 */    MCD_OPC_CheckPredicate, 4, 116, 36, // Skip to: 12829
/* 3497 */    MCD_OPC_Decode, 197, 10, 94, // Opcode: SUBVI_B
/* 3501 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 3513
/* 3505 */    MCD_OPC_CheckPredicate, 4, 104, 36, // Skip to: 12829
/* 3509 */    MCD_OPC_Decode, 199, 10, 95, // Opcode: SUBVI_H
/* 3513 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 3525
/* 3517 */    MCD_OPC_CheckPredicate, 4, 92, 36, // Skip to: 12829
/* 3521 */    MCD_OPC_Decode, 200, 10, 96, // Opcode: SUBVI_W
/* 3525 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 3537
/* 3529 */    MCD_OPC_CheckPredicate, 4, 80, 36, // Skip to: 12829
/* 3533 */    MCD_OPC_Decode, 198, 10, 97, // Opcode: SUBVI_D
/* 3537 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 3549
/* 3541 */    MCD_OPC_CheckPredicate, 4, 68, 36, // Skip to: 12829
/* 3545 */    MCD_OPC_Decode, 216, 6, 94, // Opcode: MAXI_S_B
/* 3549 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 3561
/* 3553 */    MCD_OPC_CheckPredicate, 4, 56, 36, // Skip to: 12829
/* 3557 */    MCD_OPC_Decode, 218, 6, 95, // Opcode: MAXI_S_H
/* 3561 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 3573
/* 3565 */    MCD_OPC_CheckPredicate, 4, 44, 36, // Skip to: 12829
/* 3569 */    MCD_OPC_Decode, 219, 6, 96, // Opcode: MAXI_S_W
/* 3573 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 3585
/* 3577 */    MCD_OPC_CheckPredicate, 4, 32, 36, // Skip to: 12829
/* 3581 */    MCD_OPC_Decode, 217, 6, 97, // Opcode: MAXI_S_D
/* 3585 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 3597
/* 3589 */    MCD_OPC_CheckPredicate, 4, 20, 36, // Skip to: 12829
/* 3593 */    MCD_OPC_Decode, 220, 6, 94, // Opcode: MAXI_U_B
/* 3597 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 3609
/* 3601 */    MCD_OPC_CheckPredicate, 4, 8, 36, // Skip to: 12829
/* 3605 */    MCD_OPC_Decode, 222, 6, 95, // Opcode: MAXI_U_H
/* 3609 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 3621
/* 3613 */    MCD_OPC_CheckPredicate, 4, 252, 35, // Skip to: 12829
/* 3617 */    MCD_OPC_Decode, 223, 6, 96, // Opcode: MAXI_U_W
/* 3621 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 3633
/* 3625 */    MCD_OPC_CheckPredicate, 4, 240, 35, // Skip to: 12829
/* 3629 */    MCD_OPC_Decode, 221, 6, 97, // Opcode: MAXI_U_D
/* 3633 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 3645
/* 3637 */    MCD_OPC_CheckPredicate, 4, 228, 35, // Skip to: 12829
/* 3641 */    MCD_OPC_Decode, 250, 6, 94, // Opcode: MINI_S_B
/* 3645 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 3657
/* 3649 */    MCD_OPC_CheckPredicate, 4, 216, 35, // Skip to: 12829
/* 3653 */    MCD_OPC_Decode, 252, 6, 95, // Opcode: MINI_S_H
/* 3657 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 3669
/* 3661 */    MCD_OPC_CheckPredicate, 4, 204, 35, // Skip to: 12829
/* 3665 */    MCD_OPC_Decode, 253, 6, 96, // Opcode: MINI_S_W
/* 3669 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 3681
/* 3673 */    MCD_OPC_CheckPredicate, 4, 192, 35, // Skip to: 12829
/* 3677 */    MCD_OPC_Decode, 251, 6, 97, // Opcode: MINI_S_D
/* 3681 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 3693
/* 3685 */    MCD_OPC_CheckPredicate, 4, 180, 35, // Skip to: 12829
/* 3689 */    MCD_OPC_Decode, 254, 6, 94, // Opcode: MINI_U_B
/* 3693 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 3705
/* 3697 */    MCD_OPC_CheckPredicate, 4, 168, 35, // Skip to: 12829
/* 3701 */    MCD_OPC_Decode, 128, 7, 95, // Opcode: MINI_U_H
/* 3705 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 3717
/* 3709 */    MCD_OPC_CheckPredicate, 4, 156, 35, // Skip to: 12829
/* 3713 */    MCD_OPC_Decode, 129, 7, 96, // Opcode: MINI_U_W
/* 3717 */    MCD_OPC_FilterValue, 23, 148, 35, // Skip to: 12829
/* 3721 */    MCD_OPC_CheckPredicate, 4, 144, 35, // Skip to: 12829
/* 3725 */    MCD_OPC_Decode, 255, 6, 97, // Opcode: MINI_U_D
/* 3729 */    MCD_OPC_FilterValue, 7, 35, 1, // Skip to: 4024
/* 3733 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 3736 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3748
/* 3740 */    MCD_OPC_CheckPredicate, 4, 125, 35, // Skip to: 12829
/* 3744 */    MCD_OPC_Decode, 147, 2, 94, // Opcode: CEQI_B
/* 3748 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3760
/* 3752 */    MCD_OPC_CheckPredicate, 4, 113, 35, // Skip to: 12829
/* 3756 */    MCD_OPC_Decode, 149, 2, 95, // Opcode: CEQI_H
/* 3760 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 3772
/* 3764 */    MCD_OPC_CheckPredicate, 4, 101, 35, // Skip to: 12829
/* 3768 */    MCD_OPC_Decode, 150, 2, 96, // Opcode: CEQI_W
/* 3772 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 3784
/* 3776 */    MCD_OPC_CheckPredicate, 4, 89, 35, // Skip to: 12829
/* 3780 */    MCD_OPC_Decode, 148, 2, 97, // Opcode: CEQI_D
/* 3784 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 3796
/* 3788 */    MCD_OPC_CheckPredicate, 4, 77, 35, // Skip to: 12829
/* 3792 */    MCD_OPC_Decode, 176, 2, 94, // Opcode: CLTI_S_B
/* 3796 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 3808
/* 3800 */    MCD_OPC_CheckPredicate, 4, 65, 35, // Skip to: 12829
/* 3804 */    MCD_OPC_Decode, 178, 2, 95, // Opcode: CLTI_S_H
/* 3808 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 3820
/* 3812 */    MCD_OPC_CheckPredicate, 4, 53, 35, // Skip to: 12829
/* 3816 */    MCD_OPC_Decode, 179, 2, 96, // Opcode: CLTI_S_W
/* 3820 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 3832
/* 3824 */    MCD_OPC_CheckPredicate, 4, 41, 35, // Skip to: 12829
/* 3828 */    MCD_OPC_Decode, 177, 2, 97, // Opcode: CLTI_S_D
/* 3832 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 3844
/* 3836 */    MCD_OPC_CheckPredicate, 4, 29, 35, // Skip to: 12829
/* 3840 */    MCD_OPC_Decode, 180, 2, 94, // Opcode: CLTI_U_B
/* 3844 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 3856
/* 3848 */    MCD_OPC_CheckPredicate, 4, 17, 35, // Skip to: 12829
/* 3852 */    MCD_OPC_Decode, 182, 2, 95, // Opcode: CLTI_U_H
/* 3856 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 3868
/* 3860 */    MCD_OPC_CheckPredicate, 4, 5, 35, // Skip to: 12829
/* 3864 */    MCD_OPC_Decode, 183, 2, 96, // Opcode: CLTI_U_W
/* 3868 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 3880
/* 3872 */    MCD_OPC_CheckPredicate, 4, 249, 34, // Skip to: 12829
/* 3876 */    MCD_OPC_Decode, 181, 2, 97, // Opcode: CLTI_U_D
/* 3880 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 3892
/* 3884 */    MCD_OPC_CheckPredicate, 4, 237, 34, // Skip to: 12829
/* 3888 */    MCD_OPC_Decode, 158, 2, 94, // Opcode: CLEI_S_B
/* 3892 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 3904
/* 3896 */    MCD_OPC_CheckPredicate, 4, 225, 34, // Skip to: 12829
/* 3900 */    MCD_OPC_Decode, 160, 2, 95, // Opcode: CLEI_S_H
/* 3904 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 3916
/* 3908 */    MCD_OPC_CheckPredicate, 4, 213, 34, // Skip to: 12829
/* 3912 */    MCD_OPC_Decode, 161, 2, 96, // Opcode: CLEI_S_W
/* 3916 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 3928
/* 3920 */    MCD_OPC_CheckPredicate, 4, 201, 34, // Skip to: 12829
/* 3924 */    MCD_OPC_Decode, 159, 2, 97, // Opcode: CLEI_S_D
/* 3928 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 3940
/* 3932 */    MCD_OPC_CheckPredicate, 4, 189, 34, // Skip to: 12829
/* 3936 */    MCD_OPC_Decode, 162, 2, 94, // Opcode: CLEI_U_B
/* 3940 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 3952
/* 3944 */    MCD_OPC_CheckPredicate, 4, 177, 34, // Skip to: 12829
/* 3948 */    MCD_OPC_Decode, 164, 2, 95, // Opcode: CLEI_U_H
/* 3952 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 3964
/* 3956 */    MCD_OPC_CheckPredicate, 4, 165, 34, // Skip to: 12829
/* 3960 */    MCD_OPC_Decode, 165, 2, 96, // Opcode: CLEI_U_W
/* 3964 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 3976
/* 3968 */    MCD_OPC_CheckPredicate, 4, 153, 34, // Skip to: 12829
/* 3972 */    MCD_OPC_Decode, 163, 2, 97, // Opcode: CLEI_U_D
/* 3976 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 3988
/* 3980 */    MCD_OPC_CheckPredicate, 4, 141, 34, // Skip to: 12829
/* 3984 */    MCD_OPC_Decode, 253, 5, 98, // Opcode: LDI_B
/* 3988 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 4000
/* 3992 */    MCD_OPC_CheckPredicate, 4, 129, 34, // Skip to: 12829
/* 3996 */    MCD_OPC_Decode, 255, 5, 99, // Opcode: LDI_H
/* 4000 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 4012
/* 4004 */    MCD_OPC_CheckPredicate, 4, 117, 34, // Skip to: 12829
/* 4008 */    MCD_OPC_Decode, 128, 6, 100, // Opcode: LDI_W
/* 4012 */    MCD_OPC_FilterValue, 27, 109, 34, // Skip to: 12829
/* 4016 */    MCD_OPC_CheckPredicate, 4, 105, 34, // Skip to: 12829
/* 4020 */    MCD_OPC_Decode, 254, 5, 101, // Opcode: LDI_D
/* 4024 */    MCD_OPC_FilterValue, 9, 35, 2, // Skip to: 4575
/* 4028 */    MCD_OPC_ExtractField, 22, 4,  // Inst{25-22} ...
/* 4031 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4043
/* 4035 */    MCD_OPC_CheckPredicate, 4, 86, 34, // Skip to: 12829
/* 4039 */    MCD_OPC_Decode, 212, 9, 102, // Opcode: SLLI_D
/* 4043 */    MCD_OPC_FilterValue, 1, 52, 0, // Skip to: 4099
/* 4047 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4050 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4062
/* 4054 */    MCD_OPC_CheckPredicate, 4, 67, 34, // Skip to: 12829
/* 4058 */    MCD_OPC_Decode, 214, 9, 96, // Opcode: SLLI_W
/* 4062 */    MCD_OPC_FilterValue, 1, 59, 34, // Skip to: 12829
/* 4066 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4069 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4081
/* 4073 */    MCD_OPC_CheckPredicate, 4, 48, 34, // Skip to: 12829
/* 4077 */    MCD_OPC_Decode, 213, 9, 103, // Opcode: SLLI_H
/* 4081 */    MCD_OPC_FilterValue, 1, 40, 34, // Skip to: 12829
/* 4085 */    MCD_OPC_CheckPredicate, 4, 36, 34, // Skip to: 12829
/* 4089 */    MCD_OPC_CheckField, 19, 1, 0, 30, 34, // Skip to: 12829
/* 4095 */    MCD_OPC_Decode, 211, 9, 104, // Opcode: SLLI_B
/* 4099 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 4111
/* 4103 */    MCD_OPC_CheckPredicate, 4, 18, 34, // Skip to: 12829
/* 4107 */    MCD_OPC_Decode, 249, 9, 102, // Opcode: SRAI_D
/* 4111 */    MCD_OPC_FilterValue, 3, 52, 0, // Skip to: 4167
/* 4115 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4118 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4130
/* 4122 */    MCD_OPC_CheckPredicate, 4, 255, 33, // Skip to: 12829
/* 4126 */    MCD_OPC_Decode, 251, 9, 96, // Opcode: SRAI_W
/* 4130 */    MCD_OPC_FilterValue, 1, 247, 33, // Skip to: 12829
/* 4134 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4137 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4149
/* 4141 */    MCD_OPC_CheckPredicate, 4, 236, 33, // Skip to: 12829
/* 4145 */    MCD_OPC_Decode, 250, 9, 103, // Opcode: SRAI_H
/* 4149 */    MCD_OPC_FilterValue, 1, 228, 33, // Skip to: 12829
/* 4153 */    MCD_OPC_CheckPredicate, 4, 224, 33, // Skip to: 12829
/* 4157 */    MCD_OPC_CheckField, 19, 1, 0, 218, 33, // Skip to: 12829
/* 4163 */    MCD_OPC_Decode, 248, 9, 104, // Opcode: SRAI_B
/* 4167 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 4179
/* 4171 */    MCD_OPC_CheckPredicate, 4, 206, 33, // Skip to: 12829
/* 4175 */    MCD_OPC_Decode, 141, 10, 102, // Opcode: SRLI_D
/* 4179 */    MCD_OPC_FilterValue, 5, 52, 0, // Skip to: 4235
/* 4183 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4186 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4198
/* 4190 */    MCD_OPC_CheckPredicate, 4, 187, 33, // Skip to: 12829
/* 4194 */    MCD_OPC_Decode, 143, 10, 96, // Opcode: SRLI_W
/* 4198 */    MCD_OPC_FilterValue, 1, 179, 33, // Skip to: 12829
/* 4202 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4205 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4217
/* 4209 */    MCD_OPC_CheckPredicate, 4, 168, 33, // Skip to: 12829
/* 4213 */    MCD_OPC_Decode, 142, 10, 103, // Opcode: SRLI_H
/* 4217 */    MCD_OPC_FilterValue, 1, 160, 33, // Skip to: 12829
/* 4221 */    MCD_OPC_CheckPredicate, 4, 156, 33, // Skip to: 12829
/* 4225 */    MCD_OPC_CheckField, 19, 1, 0, 150, 33, // Skip to: 12829
/* 4231 */    MCD_OPC_Decode, 140, 10, 104, // Opcode: SRLI_B
/* 4235 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 4247
/* 4239 */    MCD_OPC_CheckPredicate, 4, 138, 33, // Skip to: 12829
/* 4243 */    MCD_OPC_Decode, 156, 1, 102, // Opcode: BCLRI_D
/* 4247 */    MCD_OPC_FilterValue, 7, 52, 0, // Skip to: 4303
/* 4251 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4254 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4266
/* 4258 */    MCD_OPC_CheckPredicate, 4, 119, 33, // Skip to: 12829
/* 4262 */    MCD_OPC_Decode, 158, 1, 96, // Opcode: BCLRI_W
/* 4266 */    MCD_OPC_FilterValue, 1, 111, 33, // Skip to: 12829
/* 4270 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4273 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4285
/* 4277 */    MCD_OPC_CheckPredicate, 4, 100, 33, // Skip to: 12829
/* 4281 */    MCD_OPC_Decode, 157, 1, 103, // Opcode: BCLRI_H
/* 4285 */    MCD_OPC_FilterValue, 1, 92, 33, // Skip to: 12829
/* 4289 */    MCD_OPC_CheckPredicate, 4, 88, 33, // Skip to: 12829
/* 4293 */    MCD_OPC_CheckField, 19, 1, 0, 82, 33, // Skip to: 12829
/* 4299 */    MCD_OPC_Decode, 155, 1, 104, // Opcode: BCLRI_B
/* 4303 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 4315
/* 4307 */    MCD_OPC_CheckPredicate, 4, 70, 33, // Skip to: 12829
/* 4311 */    MCD_OPC_Decode, 231, 1, 102, // Opcode: BSETI_D
/* 4315 */    MCD_OPC_FilterValue, 9, 52, 0, // Skip to: 4371
/* 4319 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4322 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4334
/* 4326 */    MCD_OPC_CheckPredicate, 4, 51, 33, // Skip to: 12829
/* 4330 */    MCD_OPC_Decode, 233, 1, 96, // Opcode: BSETI_W
/* 4334 */    MCD_OPC_FilterValue, 1, 43, 33, // Skip to: 12829
/* 4338 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4341 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4353
/* 4345 */    MCD_OPC_CheckPredicate, 4, 32, 33, // Skip to: 12829
/* 4349 */    MCD_OPC_Decode, 232, 1, 103, // Opcode: BSETI_H
/* 4353 */    MCD_OPC_FilterValue, 1, 24, 33, // Skip to: 12829
/* 4357 */    MCD_OPC_CheckPredicate, 4, 20, 33, // Skip to: 12829
/* 4361 */    MCD_OPC_CheckField, 19, 1, 0, 14, 33, // Skip to: 12829
/* 4367 */    MCD_OPC_Decode, 230, 1, 104, // Opcode: BSETI_B
/* 4371 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 4383
/* 4375 */    MCD_OPC_CheckPredicate, 4, 2, 33, // Skip to: 12829
/* 4379 */    MCD_OPC_Decode, 206, 1, 102, // Opcode: BNEGI_D
/* 4383 */    MCD_OPC_FilterValue, 11, 52, 0, // Skip to: 4439
/* 4387 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4390 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4402
/* 4394 */    MCD_OPC_CheckPredicate, 4, 239, 32, // Skip to: 12829
/* 4398 */    MCD_OPC_Decode, 208, 1, 96, // Opcode: BNEGI_W
/* 4402 */    MCD_OPC_FilterValue, 1, 231, 32, // Skip to: 12829
/* 4406 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4409 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4421
/* 4413 */    MCD_OPC_CheckPredicate, 4, 220, 32, // Skip to: 12829
/* 4417 */    MCD_OPC_Decode, 207, 1, 103, // Opcode: BNEGI_H
/* 4421 */    MCD_OPC_FilterValue, 1, 212, 32, // Skip to: 12829
/* 4425 */    MCD_OPC_CheckPredicate, 4, 208, 32, // Skip to: 12829
/* 4429 */    MCD_OPC_CheckField, 19, 1, 0, 202, 32, // Skip to: 12829
/* 4435 */    MCD_OPC_Decode, 205, 1, 104, // Opcode: BNEGI_B
/* 4439 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 4451
/* 4443 */    MCD_OPC_CheckPredicate, 4, 190, 32, // Skip to: 12829
/* 4447 */    MCD_OPC_Decode, 175, 1, 105, // Opcode: BINSLI_D
/* 4451 */    MCD_OPC_FilterValue, 13, 52, 0, // Skip to: 4507
/* 4455 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4458 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4470
/* 4462 */    MCD_OPC_CheckPredicate, 4, 171, 32, // Skip to: 12829
/* 4466 */    MCD_OPC_Decode, 177, 1, 106, // Opcode: BINSLI_W
/* 4470 */    MCD_OPC_FilterValue, 1, 163, 32, // Skip to: 12829
/* 4474 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4477 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4489
/* 4481 */    MCD_OPC_CheckPredicate, 4, 152, 32, // Skip to: 12829
/* 4485 */    MCD_OPC_Decode, 176, 1, 107, // Opcode: BINSLI_H
/* 4489 */    MCD_OPC_FilterValue, 1, 144, 32, // Skip to: 12829
/* 4493 */    MCD_OPC_CheckPredicate, 4, 140, 32, // Skip to: 12829
/* 4497 */    MCD_OPC_CheckField, 19, 1, 0, 134, 32, // Skip to: 12829
/* 4503 */    MCD_OPC_Decode, 174, 1, 108, // Opcode: BINSLI_B
/* 4507 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 4519
/* 4511 */    MCD_OPC_CheckPredicate, 4, 122, 32, // Skip to: 12829
/* 4515 */    MCD_OPC_Decode, 183, 1, 105, // Opcode: BINSRI_D
/* 4519 */    MCD_OPC_FilterValue, 15, 114, 32, // Skip to: 12829
/* 4523 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4526 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4538
/* 4530 */    MCD_OPC_CheckPredicate, 4, 103, 32, // Skip to: 12829
/* 4534 */    MCD_OPC_Decode, 185, 1, 106, // Opcode: BINSRI_W
/* 4538 */    MCD_OPC_FilterValue, 1, 95, 32, // Skip to: 12829
/* 4542 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4545 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4557
/* 4549 */    MCD_OPC_CheckPredicate, 4, 84, 32, // Skip to: 12829
/* 4553 */    MCD_OPC_Decode, 184, 1, 107, // Opcode: BINSRI_H
/* 4557 */    MCD_OPC_FilterValue, 1, 76, 32, // Skip to: 12829
/* 4561 */    MCD_OPC_CheckPredicate, 4, 72, 32, // Skip to: 12829
/* 4565 */    MCD_OPC_CheckField, 19, 1, 0, 66, 32, // Skip to: 12829
/* 4571 */    MCD_OPC_Decode, 182, 1, 108, // Opcode: BINSRI_B
/* 4575 */    MCD_OPC_FilterValue, 10, 19, 1, // Skip to: 4854
/* 4579 */    MCD_OPC_ExtractField, 22, 4,  // Inst{25-22} ...
/* 4582 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4594
/* 4586 */    MCD_OPC_CheckPredicate, 4, 47, 32, // Skip to: 12829
/* 4590 */    MCD_OPC_Decode, 140, 9, 102, // Opcode: SAT_S_D
/* 4594 */    MCD_OPC_FilterValue, 1, 52, 0, // Skip to: 4650
/* 4598 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4601 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4613
/* 4605 */    MCD_OPC_CheckPredicate, 4, 28, 32, // Skip to: 12829
/* 4609 */    MCD_OPC_Decode, 142, 9, 96, // Opcode: SAT_S_W
/* 4613 */    MCD_OPC_FilterValue, 1, 20, 32, // Skip to: 12829
/* 4617 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4620 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4632
/* 4624 */    MCD_OPC_CheckPredicate, 4, 9, 32, // Skip to: 12829
/* 4628 */    MCD_OPC_Decode, 141, 9, 103, // Opcode: SAT_S_H
/* 4632 */    MCD_OPC_FilterValue, 1, 1, 32, // Skip to: 12829
/* 4636 */    MCD_OPC_CheckPredicate, 4, 253, 31, // Skip to: 12829
/* 4640 */    MCD_OPC_CheckField, 19, 1, 0, 247, 31, // Skip to: 12829
/* 4646 */    MCD_OPC_Decode, 139, 9, 104, // Opcode: SAT_S_B
/* 4650 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 4662
/* 4654 */    MCD_OPC_CheckPredicate, 4, 235, 31, // Skip to: 12829
/* 4658 */    MCD_OPC_Decode, 144, 9, 102, // Opcode: SAT_U_D
/* 4662 */    MCD_OPC_FilterValue, 3, 52, 0, // Skip to: 4718
/* 4666 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4669 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4681
/* 4673 */    MCD_OPC_CheckPredicate, 4, 216, 31, // Skip to: 12829
/* 4677 */    MCD_OPC_Decode, 146, 9, 96, // Opcode: SAT_U_W
/* 4681 */    MCD_OPC_FilterValue, 1, 208, 31, // Skip to: 12829
/* 4685 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4688 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4700
/* 4692 */    MCD_OPC_CheckPredicate, 4, 197, 31, // Skip to: 12829
/* 4696 */    MCD_OPC_Decode, 145, 9, 103, // Opcode: SAT_U_H
/* 4700 */    MCD_OPC_FilterValue, 1, 189, 31, // Skip to: 12829
/* 4704 */    MCD_OPC_CheckPredicate, 4, 185, 31, // Skip to: 12829
/* 4708 */    MCD_OPC_CheckField, 19, 1, 0, 179, 31, // Skip to: 12829
/* 4714 */    MCD_OPC_Decode, 143, 9, 104, // Opcode: SAT_U_B
/* 4718 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 4730
/* 4722 */    MCD_OPC_CheckPredicate, 4, 167, 31, // Skip to: 12829
/* 4726 */    MCD_OPC_Decode, 253, 9, 102, // Opcode: SRARI_D
/* 4730 */    MCD_OPC_FilterValue, 5, 52, 0, // Skip to: 4786
/* 4734 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4737 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4749
/* 4741 */    MCD_OPC_CheckPredicate, 4, 148, 31, // Skip to: 12829
/* 4745 */    MCD_OPC_Decode, 255, 9, 96, // Opcode: SRARI_W
/* 4749 */    MCD_OPC_FilterValue, 1, 140, 31, // Skip to: 12829
/* 4753 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4756 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4768
/* 4760 */    MCD_OPC_CheckPredicate, 4, 129, 31, // Skip to: 12829
/* 4764 */    MCD_OPC_Decode, 254, 9, 103, // Opcode: SRARI_H
/* 4768 */    MCD_OPC_FilterValue, 1, 121, 31, // Skip to: 12829
/* 4772 */    MCD_OPC_CheckPredicate, 4, 117, 31, // Skip to: 12829
/* 4776 */    MCD_OPC_CheckField, 19, 1, 0, 111, 31, // Skip to: 12829
/* 4782 */    MCD_OPC_Decode, 252, 9, 104, // Opcode: SRARI_B
/* 4786 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 4798
/* 4790 */    MCD_OPC_CheckPredicate, 4, 99, 31, // Skip to: 12829
/* 4794 */    MCD_OPC_Decode, 145, 10, 102, // Opcode: SRLRI_D
/* 4798 */    MCD_OPC_FilterValue, 7, 91, 31, // Skip to: 12829
/* 4802 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4805 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4817
/* 4809 */    MCD_OPC_CheckPredicate, 4, 80, 31, // Skip to: 12829
/* 4813 */    MCD_OPC_Decode, 147, 10, 96, // Opcode: SRLRI_W
/* 4817 */    MCD_OPC_FilterValue, 1, 72, 31, // Skip to: 12829
/* 4821 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4824 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4836
/* 4828 */    MCD_OPC_CheckPredicate, 4, 61, 31, // Skip to: 12829
/* 4832 */    MCD_OPC_Decode, 146, 10, 103, // Opcode: SRLRI_H
/* 4836 */    MCD_OPC_FilterValue, 1, 53, 31, // Skip to: 12829
/* 4840 */    MCD_OPC_CheckPredicate, 4, 49, 31, // Skip to: 12829
/* 4844 */    MCD_OPC_CheckField, 19, 1, 0, 43, 31, // Skip to: 12829
/* 4850 */    MCD_OPC_Decode, 144, 10, 104, // Opcode: SRLRI_B
/* 4854 */    MCD_OPC_FilterValue, 13, 131, 1, // Skip to: 5245
/* 4858 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 4861 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4873
/* 4865 */    MCD_OPC_CheckPredicate, 4, 24, 31, // Skip to: 12829
/* 4869 */    MCD_OPC_Decode, 217, 9, 109, // Opcode: SLL_B
/* 4873 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 4885
/* 4877 */    MCD_OPC_CheckPredicate, 4, 12, 31, // Skip to: 12829
/* 4881 */    MCD_OPC_Decode, 219, 9, 110, // Opcode: SLL_H
/* 4885 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 4897
/* 4889 */    MCD_OPC_CheckPredicate, 4, 0, 31, // Skip to: 12829
/* 4893 */    MCD_OPC_Decode, 221, 9, 111, // Opcode: SLL_W
/* 4897 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 4909
/* 4901 */    MCD_OPC_CheckPredicate, 4, 244, 30, // Skip to: 12829
/* 4905 */    MCD_OPC_Decode, 218, 9, 112, // Opcode: SLL_D
/* 4909 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 4921
/* 4913 */    MCD_OPC_CheckPredicate, 4, 232, 30, // Skip to: 12829
/* 4917 */    MCD_OPC_Decode, 134, 10, 109, // Opcode: SRA_B
/* 4921 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 4933
/* 4925 */    MCD_OPC_CheckPredicate, 4, 220, 30, // Skip to: 12829
/* 4929 */    MCD_OPC_Decode, 136, 10, 110, // Opcode: SRA_H
/* 4933 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 4945
/* 4937 */    MCD_OPC_CheckPredicate, 4, 208, 30, // Skip to: 12829
/* 4941 */    MCD_OPC_Decode, 138, 10, 111, // Opcode: SRA_W
/* 4945 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 4957
/* 4949 */    MCD_OPC_CheckPredicate, 4, 196, 30, // Skip to: 12829
/* 4953 */    MCD_OPC_Decode, 135, 10, 112, // Opcode: SRA_D
/* 4957 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 4969
/* 4961 */    MCD_OPC_CheckPredicate, 4, 184, 30, // Skip to: 12829
/* 4965 */    MCD_OPC_Decode, 154, 10, 109, // Opcode: SRL_B
/* 4969 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 4981
/* 4973 */    MCD_OPC_CheckPredicate, 4, 172, 30, // Skip to: 12829
/* 4977 */    MCD_OPC_Decode, 156, 10, 110, // Opcode: SRL_H
/* 4981 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 4993
/* 4985 */    MCD_OPC_CheckPredicate, 4, 160, 30, // Skip to: 12829
/* 4989 */    MCD_OPC_Decode, 158, 10, 111, // Opcode: SRL_W
/* 4993 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 5005
/* 4997 */    MCD_OPC_CheckPredicate, 4, 148, 30, // Skip to: 12829
/* 5001 */    MCD_OPC_Decode, 155, 10, 112, // Opcode: SRL_D
/* 5005 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 5017
/* 5009 */    MCD_OPC_CheckPredicate, 4, 136, 30, // Skip to: 12829
/* 5013 */    MCD_OPC_Decode, 159, 1, 109, // Opcode: BCLR_B
/* 5017 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 5029
/* 5021 */    MCD_OPC_CheckPredicate, 4, 124, 30, // Skip to: 12829
/* 5025 */    MCD_OPC_Decode, 161, 1, 110, // Opcode: BCLR_H
/* 5029 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 5041
/* 5033 */    MCD_OPC_CheckPredicate, 4, 112, 30, // Skip to: 12829
/* 5037 */    MCD_OPC_Decode, 162, 1, 111, // Opcode: BCLR_W
/* 5041 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 5053
/* 5045 */    MCD_OPC_CheckPredicate, 4, 100, 30, // Skip to: 12829
/* 5049 */    MCD_OPC_Decode, 160, 1, 112, // Opcode: BCLR_D
/* 5053 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 5065
/* 5057 */    MCD_OPC_CheckPredicate, 4, 88, 30, // Skip to: 12829
/* 5061 */    MCD_OPC_Decode, 234, 1, 109, // Opcode: BSET_B
/* 5065 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 5077
/* 5069 */    MCD_OPC_CheckPredicate, 4, 76, 30, // Skip to: 12829
/* 5073 */    MCD_OPC_Decode, 236, 1, 110, // Opcode: BSET_H
/* 5077 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 5089
/* 5081 */    MCD_OPC_CheckPredicate, 4, 64, 30, // Skip to: 12829
/* 5085 */    MCD_OPC_Decode, 237, 1, 111, // Opcode: BSET_W
/* 5089 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 5101
/* 5093 */    MCD_OPC_CheckPredicate, 4, 52, 30, // Skip to: 12829
/* 5097 */    MCD_OPC_Decode, 235, 1, 112, // Opcode: BSET_D
/* 5101 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 5113
/* 5105 */    MCD_OPC_CheckPredicate, 4, 40, 30, // Skip to: 12829
/* 5109 */    MCD_OPC_Decode, 209, 1, 109, // Opcode: BNEG_B
/* 5113 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 5125
/* 5117 */    MCD_OPC_CheckPredicate, 4, 28, 30, // Skip to: 12829
/* 5121 */    MCD_OPC_Decode, 211, 1, 110, // Opcode: BNEG_H
/* 5125 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 5137
/* 5129 */    MCD_OPC_CheckPredicate, 4, 16, 30, // Skip to: 12829
/* 5133 */    MCD_OPC_Decode, 212, 1, 111, // Opcode: BNEG_W
/* 5137 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 5149
/* 5141 */    MCD_OPC_CheckPredicate, 4, 4, 30, // Skip to: 12829
/* 5145 */    MCD_OPC_Decode, 210, 1, 112, // Opcode: BNEG_D
/* 5149 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 5161
/* 5153 */    MCD_OPC_CheckPredicate, 4, 248, 29, // Skip to: 12829
/* 5157 */    MCD_OPC_Decode, 178, 1, 113, // Opcode: BINSL_B
/* 5161 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 5173
/* 5165 */    MCD_OPC_CheckPredicate, 4, 236, 29, // Skip to: 12829
/* 5169 */    MCD_OPC_Decode, 180, 1, 114, // Opcode: BINSL_H
/* 5173 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 5185
/* 5177 */    MCD_OPC_CheckPredicate, 4, 224, 29, // Skip to: 12829
/* 5181 */    MCD_OPC_Decode, 181, 1, 115, // Opcode: BINSL_W
/* 5185 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 5197
/* 5189 */    MCD_OPC_CheckPredicate, 4, 212, 29, // Skip to: 12829
/* 5193 */    MCD_OPC_Decode, 179, 1, 116, // Opcode: BINSL_D
/* 5197 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 5209
/* 5201 */    MCD_OPC_CheckPredicate, 4, 200, 29, // Skip to: 12829
/* 5205 */    MCD_OPC_Decode, 186, 1, 113, // Opcode: BINSR_B
/* 5209 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 5221
/* 5213 */    MCD_OPC_CheckPredicate, 4, 188, 29, // Skip to: 12829
/* 5217 */    MCD_OPC_Decode, 188, 1, 114, // Opcode: BINSR_H
/* 5221 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 5233
/* 5225 */    MCD_OPC_CheckPredicate, 4, 176, 29, // Skip to: 12829
/* 5229 */    MCD_OPC_Decode, 189, 1, 115, // Opcode: BINSR_W
/* 5233 */    MCD_OPC_FilterValue, 31, 168, 29, // Skip to: 12829
/* 5237 */    MCD_OPC_CheckPredicate, 4, 164, 29, // Skip to: 12829
/* 5241 */    MCD_OPC_Decode, 187, 1, 116, // Opcode: BINSR_D
/* 5245 */    MCD_OPC_FilterValue, 14, 127, 1, // Skip to: 5632
/* 5249 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 5252 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 5263
/* 5256 */    MCD_OPC_CheckPredicate, 4, 145, 29, // Skip to: 12829
/* 5260 */    MCD_OPC_Decode, 53, 109, // Opcode: ADDV_B
/* 5263 */    MCD_OPC_FilterValue, 1, 7, 0, // Skip to: 5274
/* 5267 */    MCD_OPC_CheckPredicate, 4, 134, 29, // Skip to: 12829
/* 5271 */    MCD_OPC_Decode, 55, 110, // Opcode: ADDV_H
/* 5274 */    MCD_OPC_FilterValue, 2, 7, 0, // Skip to: 5285
/* 5278 */    MCD_OPC_CheckPredicate, 4, 123, 29, // Skip to: 12829
/* 5282 */    MCD_OPC_Decode, 56, 111, // Opcode: ADDV_W
/* 5285 */    MCD_OPC_FilterValue, 3, 7, 0, // Skip to: 5296
/* 5289 */    MCD_OPC_CheckPredicate, 4, 112, 29, // Skip to: 12829
/* 5293 */    MCD_OPC_Decode, 54, 112, // Opcode: ADDV_D
/* 5296 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 5308
/* 5300 */    MCD_OPC_CheckPredicate, 4, 101, 29, // Skip to: 12829
/* 5304 */    MCD_OPC_Decode, 201, 10, 109, // Opcode: SUBV_B
/* 5308 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 5320
/* 5312 */    MCD_OPC_CheckPredicate, 4, 89, 29, // Skip to: 12829
/* 5316 */    MCD_OPC_Decode, 203, 10, 110, // Opcode: SUBV_H
/* 5320 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 5332
/* 5324 */    MCD_OPC_CheckPredicate, 4, 77, 29, // Skip to: 12829
/* 5328 */    MCD_OPC_Decode, 204, 10, 111, // Opcode: SUBV_W
/* 5332 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 5344
/* 5336 */    MCD_OPC_CheckPredicate, 4, 65, 29, // Skip to: 12829
/* 5340 */    MCD_OPC_Decode, 202, 10, 112, // Opcode: SUBV_D
/* 5344 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 5356
/* 5348 */    MCD_OPC_CheckPredicate, 4, 53, 29, // Skip to: 12829
/* 5352 */    MCD_OPC_Decode, 228, 6, 109, // Opcode: MAX_S_B
/* 5356 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 5368
/* 5360 */    MCD_OPC_CheckPredicate, 4, 41, 29, // Skip to: 12829
/* 5364 */    MCD_OPC_Decode, 230, 6, 110, // Opcode: MAX_S_H
/* 5368 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 5380
/* 5372 */    MCD_OPC_CheckPredicate, 4, 29, 29, // Skip to: 12829
/* 5376 */    MCD_OPC_Decode, 231, 6, 111, // Opcode: MAX_S_W
/* 5380 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 5392
/* 5384 */    MCD_OPC_CheckPredicate, 4, 17, 29, // Skip to: 12829
/* 5388 */    MCD_OPC_Decode, 229, 6, 112, // Opcode: MAX_S_D
/* 5392 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 5404
/* 5396 */    MCD_OPC_CheckPredicate, 4, 5, 29, // Skip to: 12829
/* 5400 */    MCD_OPC_Decode, 232, 6, 109, // Opcode: MAX_U_B
/* 5404 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 5416
/* 5408 */    MCD_OPC_CheckPredicate, 4, 249, 28, // Skip to: 12829
/* 5412 */    MCD_OPC_Decode, 234, 6, 110, // Opcode: MAX_U_H
/* 5416 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 5428
/* 5420 */    MCD_OPC_CheckPredicate, 4, 237, 28, // Skip to: 12829
/* 5424 */    MCD_OPC_Decode, 235, 6, 111, // Opcode: MAX_U_W
/* 5428 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 5440
/* 5432 */    MCD_OPC_CheckPredicate, 4, 225, 28, // Skip to: 12829
/* 5436 */    MCD_OPC_Decode, 233, 6, 112, // Opcode: MAX_U_D
/* 5440 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 5452
/* 5444 */    MCD_OPC_CheckPredicate, 4, 213, 28, // Skip to: 12829
/* 5448 */    MCD_OPC_Decode, 134, 7, 109, // Opcode: MIN_S_B
/* 5452 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 5464
/* 5456 */    MCD_OPC_CheckPredicate, 4, 201, 28, // Skip to: 12829
/* 5460 */    MCD_OPC_Decode, 136, 7, 110, // Opcode: MIN_S_H
/* 5464 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 5476
/* 5468 */    MCD_OPC_CheckPredicate, 4, 189, 28, // Skip to: 12829
/* 5472 */    MCD_OPC_Decode, 137, 7, 111, // Opcode: MIN_S_W
/* 5476 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 5488
/* 5480 */    MCD_OPC_CheckPredicate, 4, 177, 28, // Skip to: 12829
/* 5484 */    MCD_OPC_Decode, 135, 7, 112, // Opcode: MIN_S_D
/* 5488 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 5500
/* 5492 */    MCD_OPC_CheckPredicate, 4, 165, 28, // Skip to: 12829
/* 5496 */    MCD_OPC_Decode, 138, 7, 109, // Opcode: MIN_U_B
/* 5500 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 5512
/* 5504 */    MCD_OPC_CheckPredicate, 4, 153, 28, // Skip to: 12829
/* 5508 */    MCD_OPC_Decode, 140, 7, 110, // Opcode: MIN_U_H
/* 5512 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 5524
/* 5516 */    MCD_OPC_CheckPredicate, 4, 141, 28, // Skip to: 12829
/* 5520 */    MCD_OPC_Decode, 141, 7, 111, // Opcode: MIN_U_W
/* 5524 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 5536
/* 5528 */    MCD_OPC_CheckPredicate, 4, 129, 28, // Skip to: 12829
/* 5532 */    MCD_OPC_Decode, 139, 7, 112, // Opcode: MIN_U_D
/* 5536 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 5548
/* 5540 */    MCD_OPC_CheckPredicate, 4, 117, 28, // Skip to: 12829
/* 5544 */    MCD_OPC_Decode, 224, 6, 109, // Opcode: MAX_A_B
/* 5548 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 5560
/* 5552 */    MCD_OPC_CheckPredicate, 4, 105, 28, // Skip to: 12829
/* 5556 */    MCD_OPC_Decode, 226, 6, 110, // Opcode: MAX_A_H
/* 5560 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 5572
/* 5564 */    MCD_OPC_CheckPredicate, 4, 93, 28, // Skip to: 12829
/* 5568 */    MCD_OPC_Decode, 227, 6, 111, // Opcode: MAX_A_W
/* 5572 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 5584
/* 5576 */    MCD_OPC_CheckPredicate, 4, 81, 28, // Skip to: 12829
/* 5580 */    MCD_OPC_Decode, 225, 6, 112, // Opcode: MAX_A_D
/* 5584 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 5596
/* 5588 */    MCD_OPC_CheckPredicate, 4, 69, 28, // Skip to: 12829
/* 5592 */    MCD_OPC_Decode, 130, 7, 109, // Opcode: MIN_A_B
/* 5596 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 5608
/* 5600 */    MCD_OPC_CheckPredicate, 4, 57, 28, // Skip to: 12829
/* 5604 */    MCD_OPC_Decode, 132, 7, 110, // Opcode: MIN_A_H
/* 5608 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 5620
/* 5612 */    MCD_OPC_CheckPredicate, 4, 45, 28, // Skip to: 12829
/* 5616 */    MCD_OPC_Decode, 133, 7, 111, // Opcode: MIN_A_W
/* 5620 */    MCD_OPC_FilterValue, 31, 37, 28, // Skip to: 12829
/* 5624 */    MCD_OPC_CheckPredicate, 4, 33, 28, // Skip to: 12829
/* 5628 */    MCD_OPC_Decode, 131, 7, 112, // Opcode: MIN_A_D
/* 5632 */    MCD_OPC_FilterValue, 15, 243, 0, // Skip to: 5879
/* 5636 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 5639 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5651
/* 5643 */    MCD_OPC_CheckPredicate, 4, 14, 28, // Skip to: 12829
/* 5647 */    MCD_OPC_Decode, 151, 2, 109, // Opcode: CEQ_B
/* 5651 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 5663
/* 5655 */    MCD_OPC_CheckPredicate, 4, 2, 28, // Skip to: 12829
/* 5659 */    MCD_OPC_Decode, 153, 2, 110, // Opcode: CEQ_H
/* 5663 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 5675
/* 5667 */    MCD_OPC_CheckPredicate, 4, 246, 27, // Skip to: 12829
/* 5671 */    MCD_OPC_Decode, 154, 2, 111, // Opcode: CEQ_W
/* 5675 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 5687
/* 5679 */    MCD_OPC_CheckPredicate, 4, 234, 27, // Skip to: 12829
/* 5683 */    MCD_OPC_Decode, 152, 2, 112, // Opcode: CEQ_D
/* 5687 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 5699
/* 5691 */    MCD_OPC_CheckPredicate, 4, 222, 27, // Skip to: 12829
/* 5695 */    MCD_OPC_Decode, 184, 2, 109, // Opcode: CLT_S_B
/* 5699 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 5711
/* 5703 */    MCD_OPC_CheckPredicate, 4, 210, 27, // Skip to: 12829
/* 5707 */    MCD_OPC_Decode, 186, 2, 110, // Opcode: CLT_S_H
/* 5711 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 5723
/* 5715 */    MCD_OPC_CheckPredicate, 4, 198, 27, // Skip to: 12829
/* 5719 */    MCD_OPC_Decode, 187, 2, 111, // Opcode: CLT_S_W
/* 5723 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 5735
/* 5727 */    MCD_OPC_CheckPredicate, 4, 186, 27, // Skip to: 12829
/* 5731 */    MCD_OPC_Decode, 185, 2, 112, // Opcode: CLT_S_D
/* 5735 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 5747
/* 5739 */    MCD_OPC_CheckPredicate, 4, 174, 27, // Skip to: 12829
/* 5743 */    MCD_OPC_Decode, 188, 2, 109, // Opcode: CLT_U_B
/* 5747 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 5759
/* 5751 */    MCD_OPC_CheckPredicate, 4, 162, 27, // Skip to: 12829
/* 5755 */    MCD_OPC_Decode, 190, 2, 110, // Opcode: CLT_U_H
/* 5759 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 5771
/* 5763 */    MCD_OPC_CheckPredicate, 4, 150, 27, // Skip to: 12829
/* 5767 */    MCD_OPC_Decode, 191, 2, 111, // Opcode: CLT_U_W
/* 5771 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 5783
/* 5775 */    MCD_OPC_CheckPredicate, 4, 138, 27, // Skip to: 12829
/* 5779 */    MCD_OPC_Decode, 189, 2, 112, // Opcode: CLT_U_D
/* 5783 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 5795
/* 5787 */    MCD_OPC_CheckPredicate, 4, 126, 27, // Skip to: 12829
/* 5791 */    MCD_OPC_Decode, 166, 2, 109, // Opcode: CLE_S_B
/* 5795 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 5807
/* 5799 */    MCD_OPC_CheckPredicate, 4, 114, 27, // Skip to: 12829
/* 5803 */    MCD_OPC_Decode, 168, 2, 110, // Opcode: CLE_S_H
/* 5807 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 5819
/* 5811 */    MCD_OPC_CheckPredicate, 4, 102, 27, // Skip to: 12829
/* 5815 */    MCD_OPC_Decode, 169, 2, 111, // Opcode: CLE_S_W
/* 5819 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 5831
/* 5823 */    MCD_OPC_CheckPredicate, 4, 90, 27, // Skip to: 12829
/* 5827 */    MCD_OPC_Decode, 167, 2, 112, // Opcode: CLE_S_D
/* 5831 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 5843
/* 5835 */    MCD_OPC_CheckPredicate, 4, 78, 27, // Skip to: 12829
/* 5839 */    MCD_OPC_Decode, 170, 2, 109, // Opcode: CLE_U_B
/* 5843 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 5855
/* 5847 */    MCD_OPC_CheckPredicate, 4, 66, 27, // Skip to: 12829
/* 5851 */    MCD_OPC_Decode, 172, 2, 110, // Opcode: CLE_U_H
/* 5855 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 5867
/* 5859 */    MCD_OPC_CheckPredicate, 4, 54, 27, // Skip to: 12829
/* 5863 */    MCD_OPC_Decode, 173, 2, 111, // Opcode: CLE_U_W
/* 5867 */    MCD_OPC_FilterValue, 23, 46, 27, // Skip to: 12829
/* 5871 */    MCD_OPC_CheckPredicate, 4, 42, 27, // Skip to: 12829
/* 5875 */    MCD_OPC_Decode, 171, 2, 112, // Opcode: CLE_U_D
/* 5879 */    MCD_OPC_FilterValue, 16, 110, 1, // Skip to: 6249
/* 5883 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 5886 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 5897
/* 5890 */    MCD_OPC_CheckPredicate, 4, 23, 27, // Skip to: 12829
/* 5894 */    MCD_OPC_Decode, 58, 109, // Opcode: ADD_A_B
/* 5897 */    MCD_OPC_FilterValue, 1, 7, 0, // Skip to: 5908
/* 5901 */    MCD_OPC_CheckPredicate, 4, 12, 27, // Skip to: 12829
/* 5905 */    MCD_OPC_Decode, 60, 110, // Opcode: ADD_A_H
/* 5908 */    MCD_OPC_FilterValue, 2, 7, 0, // Skip to: 5919
/* 5912 */    MCD_OPC_CheckPredicate, 4, 1, 27, // Skip to: 12829
/* 5916 */    MCD_OPC_Decode, 61, 111, // Opcode: ADD_A_W
/* 5919 */    MCD_OPC_FilterValue, 3, 7, 0, // Skip to: 5930
/* 5923 */    MCD_OPC_CheckPredicate, 4, 246, 26, // Skip to: 12829
/* 5927 */    MCD_OPC_Decode, 59, 112, // Opcode: ADD_A_D
/* 5930 */    MCD_OPC_FilterValue, 4, 7, 0, // Skip to: 5941
/* 5934 */    MCD_OPC_CheckPredicate, 4, 235, 26, // Skip to: 12829
/* 5938 */    MCD_OPC_Decode, 31, 109, // Opcode: ADDS_A_B
/* 5941 */    MCD_OPC_FilterValue, 5, 7, 0, // Skip to: 5952
/* 5945 */    MCD_OPC_CheckPredicate, 4, 224, 26, // Skip to: 12829
/* 5949 */    MCD_OPC_Decode, 33, 110, // Opcode: ADDS_A_H
/* 5952 */    MCD_OPC_FilterValue, 6, 7, 0, // Skip to: 5963
/* 5956 */    MCD_OPC_CheckPredicate, 4, 213, 26, // Skip to: 12829
/* 5960 */    MCD_OPC_Decode, 34, 111, // Opcode: ADDS_A_W
/* 5963 */    MCD_OPC_FilterValue, 7, 7, 0, // Skip to: 5974
/* 5967 */    MCD_OPC_CheckPredicate, 4, 202, 26, // Skip to: 12829
/* 5971 */    MCD_OPC_Decode, 32, 112, // Opcode: ADDS_A_D
/* 5974 */    MCD_OPC_FilterValue, 8, 7, 0, // Skip to: 5985
/* 5978 */    MCD_OPC_CheckPredicate, 4, 191, 26, // Skip to: 12829
/* 5982 */    MCD_OPC_Decode, 35, 109, // Opcode: ADDS_S_B
/* 5985 */    MCD_OPC_FilterValue, 9, 7, 0, // Skip to: 5996
/* 5989 */    MCD_OPC_CheckPredicate, 4, 180, 26, // Skip to: 12829
/* 5993 */    MCD_OPC_Decode, 37, 110, // Opcode: ADDS_S_H
/* 5996 */    MCD_OPC_FilterValue, 10, 7, 0, // Skip to: 6007
/* 6000 */    MCD_OPC_CheckPredicate, 4, 169, 26, // Skip to: 12829
/* 6004 */    MCD_OPC_Decode, 38, 111, // Opcode: ADDS_S_W
/* 6007 */    MCD_OPC_FilterValue, 11, 7, 0, // Skip to: 6018
/* 6011 */    MCD_OPC_CheckPredicate, 4, 158, 26, // Skip to: 12829
/* 6015 */    MCD_OPC_Decode, 36, 112, // Opcode: ADDS_S_D
/* 6018 */    MCD_OPC_FilterValue, 12, 7, 0, // Skip to: 6029
/* 6022 */    MCD_OPC_CheckPredicate, 4, 147, 26, // Skip to: 12829
/* 6026 */    MCD_OPC_Decode, 39, 109, // Opcode: ADDS_U_B
/* 6029 */    MCD_OPC_FilterValue, 13, 7, 0, // Skip to: 6040
/* 6033 */    MCD_OPC_CheckPredicate, 4, 136, 26, // Skip to: 12829
/* 6037 */    MCD_OPC_Decode, 41, 110, // Opcode: ADDS_U_H
/* 6040 */    MCD_OPC_FilterValue, 14, 7, 0, // Skip to: 6051
/* 6044 */    MCD_OPC_CheckPredicate, 4, 125, 26, // Skip to: 12829
/* 6048 */    MCD_OPC_Decode, 42, 111, // Opcode: ADDS_U_W
/* 6051 */    MCD_OPC_FilterValue, 15, 7, 0, // Skip to: 6062
/* 6055 */    MCD_OPC_CheckPredicate, 4, 114, 26, // Skip to: 12829
/* 6059 */    MCD_OPC_Decode, 40, 112, // Opcode: ADDS_U_D
/* 6062 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 6074
/* 6066 */    MCD_OPC_CheckPredicate, 4, 103, 26, // Skip to: 12829
/* 6070 */    MCD_OPC_Decode, 131, 1, 109, // Opcode: AVE_S_B
/* 6074 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 6086
/* 6078 */    MCD_OPC_CheckPredicate, 4, 91, 26, // Skip to: 12829
/* 6082 */    MCD_OPC_Decode, 133, 1, 110, // Opcode: AVE_S_H
/* 6086 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 6098
/* 6090 */    MCD_OPC_CheckPredicate, 4, 79, 26, // Skip to: 12829
/* 6094 */    MCD_OPC_Decode, 134, 1, 111, // Opcode: AVE_S_W
/* 6098 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 6110
/* 6102 */    MCD_OPC_CheckPredicate, 4, 67, 26, // Skip to: 12829
/* 6106 */    MCD_OPC_Decode, 132, 1, 112, // Opcode: AVE_S_D
/* 6110 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 6122
/* 6114 */    MCD_OPC_CheckPredicate, 4, 55, 26, // Skip to: 12829
/* 6118 */    MCD_OPC_Decode, 135, 1, 109, // Opcode: AVE_U_B
/* 6122 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 6134
/* 6126 */    MCD_OPC_CheckPredicate, 4, 43, 26, // Skip to: 12829
/* 6130 */    MCD_OPC_Decode, 137, 1, 110, // Opcode: AVE_U_H
/* 6134 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 6146
/* 6138 */    MCD_OPC_CheckPredicate, 4, 31, 26, // Skip to: 12829
/* 6142 */    MCD_OPC_Decode, 138, 1, 111, // Opcode: AVE_U_W
/* 6146 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 6158
/* 6150 */    MCD_OPC_CheckPredicate, 4, 19, 26, // Skip to: 12829
/* 6154 */    MCD_OPC_Decode, 136, 1, 112, // Opcode: AVE_U_D
/* 6158 */    MCD_OPC_FilterValue, 24, 7, 0, // Skip to: 6169
/* 6162 */    MCD_OPC_CheckPredicate, 4, 7, 26, // Skip to: 12829
/* 6166 */    MCD_OPC_Decode, 123, 109, // Opcode: AVER_S_B
/* 6169 */    MCD_OPC_FilterValue, 25, 7, 0, // Skip to: 6180
/* 6173 */    MCD_OPC_CheckPredicate, 4, 252, 25, // Skip to: 12829
/* 6177 */    MCD_OPC_Decode, 125, 110, // Opcode: AVER_S_H
/* 6180 */    MCD_OPC_FilterValue, 26, 7, 0, // Skip to: 6191
/* 6184 */    MCD_OPC_CheckPredicate, 4, 241, 25, // Skip to: 12829
/* 6188 */    MCD_OPC_Decode, 126, 111, // Opcode: AVER_S_W
/* 6191 */    MCD_OPC_FilterValue, 27, 7, 0, // Skip to: 6202
/* 6195 */    MCD_OPC_CheckPredicate, 4, 230, 25, // Skip to: 12829
/* 6199 */    MCD_OPC_Decode, 124, 112, // Opcode: AVER_S_D
/* 6202 */    MCD_OPC_FilterValue, 28, 7, 0, // Skip to: 6213
/* 6206 */    MCD_OPC_CheckPredicate, 4, 219, 25, // Skip to: 12829
/* 6210 */    MCD_OPC_Decode, 127, 109, // Opcode: AVER_U_B
/* 6213 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 6225
/* 6217 */    MCD_OPC_CheckPredicate, 4, 208, 25, // Skip to: 12829
/* 6221 */    MCD_OPC_Decode, 129, 1, 110, // Opcode: AVER_U_H
/* 6225 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 6237
/* 6229 */    MCD_OPC_CheckPredicate, 4, 196, 25, // Skip to: 12829
/* 6233 */    MCD_OPC_Decode, 130, 1, 111, // Opcode: AVER_U_W
/* 6237 */    MCD_OPC_FilterValue, 31, 188, 25, // Skip to: 12829
/* 6241 */    MCD_OPC_CheckPredicate, 4, 184, 25, // Skip to: 12829
/* 6245 */    MCD_OPC_Decode, 128, 1, 112, // Opcode: AVER_U_D
/* 6249 */    MCD_OPC_FilterValue, 17, 27, 1, // Skip to: 6536
/* 6253 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 6256 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 6268
/* 6260 */    MCD_OPC_CheckPredicate, 4, 165, 25, // Skip to: 12829
/* 6264 */    MCD_OPC_Decode, 183, 10, 109, // Opcode: SUBS_S_B
/* 6268 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 6280
/* 6272 */    MCD_OPC_CheckPredicate, 4, 153, 25, // Skip to: 12829
/* 6276 */    MCD_OPC_Decode, 185, 10, 110, // Opcode: SUBS_S_H
/* 6280 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 6292
/* 6284 */    MCD_OPC_CheckPredicate, 4, 141, 25, // Skip to: 12829
/* 6288 */    MCD_OPC_Decode, 186, 10, 111, // Opcode: SUBS_S_W
/* 6292 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 6304
/* 6296 */    MCD_OPC_CheckPredicate, 4, 129, 25, // Skip to: 12829
/* 6300 */    MCD_OPC_Decode, 184, 10, 112, // Opcode: SUBS_S_D
/* 6304 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 6316
/* 6308 */    MCD_OPC_CheckPredicate, 4, 117, 25, // Skip to: 12829
/* 6312 */    MCD_OPC_Decode, 187, 10, 109, // Opcode: SUBS_U_B
/* 6316 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 6328
/* 6320 */    MCD_OPC_CheckPredicate, 4, 105, 25, // Skip to: 12829
/* 6324 */    MCD_OPC_Decode, 189, 10, 110, // Opcode: SUBS_U_H
/* 6328 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 6340
/* 6332 */    MCD_OPC_CheckPredicate, 4, 93, 25, // Skip to: 12829
/* 6336 */    MCD_OPC_Decode, 190, 10, 111, // Opcode: SUBS_U_W
/* 6340 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 6352
/* 6344 */    MCD_OPC_CheckPredicate, 4, 81, 25, // Skip to: 12829
/* 6348 */    MCD_OPC_Decode, 188, 10, 112, // Opcode: SUBS_U_D
/* 6352 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 6364
/* 6356 */    MCD_OPC_CheckPredicate, 4, 69, 25, // Skip to: 12829
/* 6360 */    MCD_OPC_Decode, 175, 10, 109, // Opcode: SUBSUS_U_B
/* 6364 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 6376
/* 6368 */    MCD_OPC_CheckPredicate, 4, 57, 25, // Skip to: 12829
/* 6372 */    MCD_OPC_Decode, 177, 10, 110, // Opcode: SUBSUS_U_H
/* 6376 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 6388
/* 6380 */    MCD_OPC_CheckPredicate, 4, 45, 25, // Skip to: 12829
/* 6384 */    MCD_OPC_Decode, 178, 10, 111, // Opcode: SUBSUS_U_W
/* 6388 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 6400
/* 6392 */    MCD_OPC_CheckPredicate, 4, 33, 25, // Skip to: 12829
/* 6396 */    MCD_OPC_Decode, 176, 10, 112, // Opcode: SUBSUS_U_D
/* 6400 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 6412
/* 6404 */    MCD_OPC_CheckPredicate, 4, 21, 25, // Skip to: 12829
/* 6408 */    MCD_OPC_Decode, 179, 10, 109, // Opcode: SUBSUU_S_B
/* 6412 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 6424
/* 6416 */    MCD_OPC_CheckPredicate, 4, 9, 25, // Skip to: 12829
/* 6420 */    MCD_OPC_Decode, 181, 10, 110, // Opcode: SUBSUU_S_H
/* 6424 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 6436
/* 6428 */    MCD_OPC_CheckPredicate, 4, 253, 24, // Skip to: 12829
/* 6432 */    MCD_OPC_Decode, 182, 10, 111, // Opcode: SUBSUU_S_W
/* 6436 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 6448
/* 6440 */    MCD_OPC_CheckPredicate, 4, 241, 24, // Skip to: 12829
/* 6444 */    MCD_OPC_Decode, 180, 10, 112, // Opcode: SUBSUU_S_D
/* 6448 */    MCD_OPC_FilterValue, 16, 7, 0, // Skip to: 6459
/* 6452 */    MCD_OPC_CheckPredicate, 4, 229, 24, // Skip to: 12829
/* 6456 */    MCD_OPC_Decode, 83, 109, // Opcode: ASUB_S_B
/* 6459 */    MCD_OPC_FilterValue, 17, 7, 0, // Skip to: 6470
/* 6463 */    MCD_OPC_CheckPredicate, 4, 218, 24, // Skip to: 12829
/* 6467 */    MCD_OPC_Decode, 85, 110, // Opcode: ASUB_S_H
/* 6470 */    MCD_OPC_FilterValue, 18, 7, 0, // Skip to: 6481
/* 6474 */    MCD_OPC_CheckPredicate, 4, 207, 24, // Skip to: 12829
/* 6478 */    MCD_OPC_Decode, 86, 111, // Opcode: ASUB_S_W
/* 6481 */    MCD_OPC_FilterValue, 19, 7, 0, // Skip to: 6492
/* 6485 */    MCD_OPC_CheckPredicate, 4, 196, 24, // Skip to: 12829
/* 6489 */    MCD_OPC_Decode, 84, 112, // Opcode: ASUB_S_D
/* 6492 */    MCD_OPC_FilterValue, 20, 7, 0, // Skip to: 6503
/* 6496 */    MCD_OPC_CheckPredicate, 4, 185, 24, // Skip to: 12829
/* 6500 */    MCD_OPC_Decode, 87, 109, // Opcode: ASUB_U_B
/* 6503 */    MCD_OPC_FilterValue, 21, 7, 0, // Skip to: 6514
/* 6507 */    MCD_OPC_CheckPredicate, 4, 174, 24, // Skip to: 12829
/* 6511 */    MCD_OPC_Decode, 89, 110, // Opcode: ASUB_U_H
/* 6514 */    MCD_OPC_FilterValue, 22, 7, 0, // Skip to: 6525
/* 6518 */    MCD_OPC_CheckPredicate, 4, 163, 24, // Skip to: 12829
/* 6522 */    MCD_OPC_Decode, 90, 111, // Opcode: ASUB_U_W
/* 6525 */    MCD_OPC_FilterValue, 23, 156, 24, // Skip to: 12829
/* 6529 */    MCD_OPC_CheckPredicate, 4, 152, 24, // Skip to: 12829
/* 6533 */    MCD_OPC_Decode, 88, 112, // Opcode: ASUB_U_D
/* 6536 */    MCD_OPC_FilterValue, 18, 83, 1, // Skip to: 6879
/* 6540 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 6543 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 6555
/* 6547 */    MCD_OPC_CheckPredicate, 4, 134, 24, // Skip to: 12829
/* 6551 */    MCD_OPC_Decode, 247, 7, 109, // Opcode: MULV_B
/* 6555 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 6567
/* 6559 */    MCD_OPC_CheckPredicate, 4, 122, 24, // Skip to: 12829
/* 6563 */    MCD_OPC_Decode, 249, 7, 110, // Opcode: MULV_H
/* 6567 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 6579
/* 6571 */    MCD_OPC_CheckPredicate, 4, 110, 24, // Skip to: 12829
/* 6575 */    MCD_OPC_Decode, 250, 7, 111, // Opcode: MULV_W
/* 6579 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 6591
/* 6583 */    MCD_OPC_CheckPredicate, 4, 98, 24, // Skip to: 12829
/* 6587 */    MCD_OPC_Decode, 248, 7, 112, // Opcode: MULV_D
/* 6591 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 6603
/* 6595 */    MCD_OPC_CheckPredicate, 4, 86, 24, // Skip to: 12829
/* 6599 */    MCD_OPC_Decode, 199, 6, 113, // Opcode: MADDV_B
/* 6603 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 6615
/* 6607 */    MCD_OPC_CheckPredicate, 4, 74, 24, // Skip to: 12829
/* 6611 */    MCD_OPC_Decode, 201, 6, 114, // Opcode: MADDV_H
/* 6615 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 6627
/* 6619 */    MCD_OPC_CheckPredicate, 4, 62, 24, // Skip to: 12829
/* 6623 */    MCD_OPC_Decode, 202, 6, 115, // Opcode: MADDV_W
/* 6627 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 6639
/* 6631 */    MCD_OPC_CheckPredicate, 4, 50, 24, // Skip to: 12829
/* 6635 */    MCD_OPC_Decode, 200, 6, 116, // Opcode: MADDV_D
/* 6639 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 6651
/* 6643 */    MCD_OPC_CheckPredicate, 4, 38, 24, // Skip to: 12829
/* 6647 */    MCD_OPC_Decode, 200, 7, 113, // Opcode: MSUBV_B
/* 6651 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 6663
/* 6655 */    MCD_OPC_CheckPredicate, 4, 26, 24, // Skip to: 12829
/* 6659 */    MCD_OPC_Decode, 202, 7, 114, // Opcode: MSUBV_H
/* 6663 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 6675
/* 6667 */    MCD_OPC_CheckPredicate, 4, 14, 24, // Skip to: 12829
/* 6671 */    MCD_OPC_Decode, 203, 7, 115, // Opcode: MSUBV_W
/* 6675 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 6687
/* 6679 */    MCD_OPC_CheckPredicate, 4, 2, 24, // Skip to: 12829
/* 6683 */    MCD_OPC_Decode, 201, 7, 116, // Opcode: MSUBV_D
/* 6687 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 6699
/* 6691 */    MCD_OPC_CheckPredicate, 4, 246, 23, // Skip to: 12829
/* 6695 */    MCD_OPC_Decode, 181, 3, 109, // Opcode: DIV_S_B
/* 6699 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 6711
/* 6703 */    MCD_OPC_CheckPredicate, 4, 234, 23, // Skip to: 12829
/* 6707 */    MCD_OPC_Decode, 183, 3, 110, // Opcode: DIV_S_H
/* 6711 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 6723
/* 6715 */    MCD_OPC_CheckPredicate, 4, 222, 23, // Skip to: 12829
/* 6719 */    MCD_OPC_Decode, 184, 3, 111, // Opcode: DIV_S_W
/* 6723 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 6735
/* 6727 */    MCD_OPC_CheckPredicate, 4, 210, 23, // Skip to: 12829
/* 6731 */    MCD_OPC_Decode, 182, 3, 112, // Opcode: DIV_S_D
/* 6735 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 6747
/* 6739 */    MCD_OPC_CheckPredicate, 4, 198, 23, // Skip to: 12829
/* 6743 */    MCD_OPC_Decode, 185, 3, 109, // Opcode: DIV_U_B
/* 6747 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 6759
/* 6751 */    MCD_OPC_CheckPredicate, 4, 186, 23, // Skip to: 12829
/* 6755 */    MCD_OPC_Decode, 187, 3, 110, // Opcode: DIV_U_H
/* 6759 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 6771
/* 6763 */    MCD_OPC_CheckPredicate, 4, 174, 23, // Skip to: 12829
/* 6767 */    MCD_OPC_Decode, 188, 3, 111, // Opcode: DIV_U_W
/* 6771 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 6783
/* 6775 */    MCD_OPC_CheckPredicate, 4, 162, 23, // Skip to: 12829
/* 6779 */    MCD_OPC_Decode, 186, 3, 112, // Opcode: DIV_U_D
/* 6783 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 6795
/* 6787 */    MCD_OPC_CheckPredicate, 4, 150, 23, // Skip to: 12829
/* 6791 */    MCD_OPC_Decode, 145, 7, 109, // Opcode: MOD_S_B
/* 6795 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 6807
/* 6799 */    MCD_OPC_CheckPredicate, 4, 138, 23, // Skip to: 12829
/* 6803 */    MCD_OPC_Decode, 147, 7, 110, // Opcode: MOD_S_H
/* 6807 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 6819
/* 6811 */    MCD_OPC_CheckPredicate, 4, 126, 23, // Skip to: 12829
/* 6815 */    MCD_OPC_Decode, 148, 7, 111, // Opcode: MOD_S_W
/* 6819 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 6831
/* 6823 */    MCD_OPC_CheckPredicate, 4, 114, 23, // Skip to: 12829
/* 6827 */    MCD_OPC_Decode, 146, 7, 112, // Opcode: MOD_S_D
/* 6831 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 6843
/* 6835 */    MCD_OPC_CheckPredicate, 4, 102, 23, // Skip to: 12829
/* 6839 */    MCD_OPC_Decode, 149, 7, 109, // Opcode: MOD_U_B
/* 6843 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 6855
/* 6847 */    MCD_OPC_CheckPredicate, 4, 90, 23, // Skip to: 12829
/* 6851 */    MCD_OPC_Decode, 151, 7, 110, // Opcode: MOD_U_H
/* 6855 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 6867
/* 6859 */    MCD_OPC_CheckPredicate, 4, 78, 23, // Skip to: 12829
/* 6863 */    MCD_OPC_Decode, 152, 7, 111, // Opcode: MOD_U_W
/* 6867 */    MCD_OPC_FilterValue, 31, 70, 23, // Skip to: 12829
/* 6871 */    MCD_OPC_CheckPredicate, 4, 66, 23, // Skip to: 12829
/* 6875 */    MCD_OPC_Decode, 150, 7, 112, // Opcode: MOD_U_D
/* 6879 */    MCD_OPC_FilterValue, 19, 219, 0, // Skip to: 7102
/* 6883 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 6886 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 6898
/* 6890 */    MCD_OPC_CheckPredicate, 4, 47, 23, // Skip to: 12829
/* 6894 */    MCD_OPC_Decode, 200, 3, 117, // Opcode: DOTP_S_H
/* 6898 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 6910
/* 6902 */    MCD_OPC_CheckPredicate, 4, 35, 23, // Skip to: 12829
/* 6906 */    MCD_OPC_Decode, 201, 3, 118, // Opcode: DOTP_S_W
/* 6910 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 6922
/* 6914 */    MCD_OPC_CheckPredicate, 4, 23, 23, // Skip to: 12829
/* 6918 */    MCD_OPC_Decode, 199, 3, 119, // Opcode: DOTP_S_D
/* 6922 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 6934
/* 6926 */    MCD_OPC_CheckPredicate, 4, 11, 23, // Skip to: 12829
/* 6930 */    MCD_OPC_Decode, 203, 3, 117, // Opcode: DOTP_U_H
/* 6934 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 6946
/* 6938 */    MCD_OPC_CheckPredicate, 4, 255, 22, // Skip to: 12829
/* 6942 */    MCD_OPC_Decode, 204, 3, 118, // Opcode: DOTP_U_W
/* 6946 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 6958
/* 6950 */    MCD_OPC_CheckPredicate, 4, 243, 22, // Skip to: 12829
/* 6954 */    MCD_OPC_Decode, 202, 3, 119, // Opcode: DOTP_U_D
/* 6958 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 6970
/* 6962 */    MCD_OPC_CheckPredicate, 4, 231, 22, // Skip to: 12829
/* 6966 */    MCD_OPC_Decode, 206, 3, 120, // Opcode: DPADD_S_H
/* 6970 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 6982
/* 6974 */    MCD_OPC_CheckPredicate, 4, 219, 22, // Skip to: 12829
/* 6978 */    MCD_OPC_Decode, 207, 3, 121, // Opcode: DPADD_S_W
/* 6982 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 6994
/* 6986 */    MCD_OPC_CheckPredicate, 4, 207, 22, // Skip to: 12829
/* 6990 */    MCD_OPC_Decode, 205, 3, 122, // Opcode: DPADD_S_D
/* 6994 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 7006
/* 6998 */    MCD_OPC_CheckPredicate, 4, 195, 22, // Skip to: 12829
/* 7002 */    MCD_OPC_Decode, 209, 3, 120, // Opcode: DPADD_U_H
/* 7006 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 7018
/* 7010 */    MCD_OPC_CheckPredicate, 4, 183, 22, // Skip to: 12829
/* 7014 */    MCD_OPC_Decode, 210, 3, 121, // Opcode: DPADD_U_W
/* 7018 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 7030
/* 7022 */    MCD_OPC_CheckPredicate, 4, 171, 22, // Skip to: 12829
/* 7026 */    MCD_OPC_Decode, 208, 3, 122, // Opcode: DPADD_U_D
/* 7030 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 7042
/* 7034 */    MCD_OPC_CheckPredicate, 4, 159, 22, // Skip to: 12829
/* 7038 */    MCD_OPC_Decode, 224, 3, 120, // Opcode: DPSUB_S_H
/* 7042 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 7054
/* 7046 */    MCD_OPC_CheckPredicate, 4, 147, 22, // Skip to: 12829
/* 7050 */    MCD_OPC_Decode, 225, 3, 121, // Opcode: DPSUB_S_W
/* 7054 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 7066
/* 7058 */    MCD_OPC_CheckPredicate, 4, 135, 22, // Skip to: 12829
/* 7062 */    MCD_OPC_Decode, 223, 3, 122, // Opcode: DPSUB_S_D
/* 7066 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 7078
/* 7070 */    MCD_OPC_CheckPredicate, 4, 123, 22, // Skip to: 12829
/* 7074 */    MCD_OPC_Decode, 227, 3, 120, // Opcode: DPSUB_U_H
/* 7078 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 7090
/* 7082 */    MCD_OPC_CheckPredicate, 4, 111, 22, // Skip to: 12829
/* 7086 */    MCD_OPC_Decode, 228, 3, 121, // Opcode: DPSUB_U_W
/* 7090 */    MCD_OPC_FilterValue, 23, 103, 22, // Skip to: 12829
/* 7094 */    MCD_OPC_CheckPredicate, 4, 99, 22, // Skip to: 12829
/* 7098 */    MCD_OPC_Decode, 226, 3, 122, // Opcode: DPSUB_U_D
/* 7102 */    MCD_OPC_FilterValue, 20, 134, 1, // Skip to: 7496
/* 7106 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 7109 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 7121
/* 7113 */    MCD_OPC_CheckPredicate, 4, 80, 22, // Skip to: 12829
/* 7117 */    MCD_OPC_Decode, 204, 9, 123, // Opcode: SLD_B
/* 7121 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 7133
/* 7125 */    MCD_OPC_CheckPredicate, 4, 68, 22, // Skip to: 12829
/* 7129 */    MCD_OPC_Decode, 206, 9, 124, // Opcode: SLD_H
/* 7133 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 7145
/* 7137 */    MCD_OPC_CheckPredicate, 4, 56, 22, // Skip to: 12829
/* 7141 */    MCD_OPC_Decode, 207, 9, 125, // Opcode: SLD_W
/* 7145 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 7157
/* 7149 */    MCD_OPC_CheckPredicate, 4, 44, 22, // Skip to: 12829
/* 7153 */    MCD_OPC_Decode, 205, 9, 126, // Opcode: SLD_D
/* 7157 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 7169
/* 7161 */    MCD_OPC_CheckPredicate, 4, 32, 22, // Skip to: 12829
/* 7165 */    MCD_OPC_Decode, 243, 9, 127, // Opcode: SPLAT_B
/* 7169 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 7182
/* 7173 */    MCD_OPC_CheckPredicate, 4, 20, 22, // Skip to: 12829
/* 7177 */    MCD_OPC_Decode, 245, 9, 128, 1, // Opcode: SPLAT_H
/* 7182 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 7195
/* 7186 */    MCD_OPC_CheckPredicate, 4, 7, 22, // Skip to: 12829
/* 7190 */    MCD_OPC_Decode, 246, 9, 129, 1, // Opcode: SPLAT_W
/* 7195 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 7208
/* 7199 */    MCD_OPC_CheckPredicate, 4, 250, 21, // Skip to: 12829
/* 7203 */    MCD_OPC_Decode, 244, 9, 130, 1, // Opcode: SPLAT_D
/* 7208 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 7220
/* 7212 */    MCD_OPC_CheckPredicate, 4, 237, 21, // Skip to: 12829
/* 7216 */    MCD_OPC_Decode, 178, 8, 109, // Opcode: PCKEV_B
/* 7220 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 7232
/* 7224 */    MCD_OPC_CheckPredicate, 4, 225, 21, // Skip to: 12829
/* 7228 */    MCD_OPC_Decode, 180, 8, 110, // Opcode: PCKEV_H
/* 7232 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 7244
/* 7236 */    MCD_OPC_CheckPredicate, 4, 213, 21, // Skip to: 12829
/* 7240 */    MCD_OPC_Decode, 181, 8, 111, // Opcode: PCKEV_W
/* 7244 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 7256
/* 7248 */    MCD_OPC_CheckPredicate, 4, 201, 21, // Skip to: 12829
/* 7252 */    MCD_OPC_Decode, 179, 8, 112, // Opcode: PCKEV_D
/* 7256 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 7268
/* 7260 */    MCD_OPC_CheckPredicate, 4, 189, 21, // Skip to: 12829
/* 7264 */    MCD_OPC_Decode, 182, 8, 109, // Opcode: PCKOD_B
/* 7268 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 7280
/* 7272 */    MCD_OPC_CheckPredicate, 4, 177, 21, // Skip to: 12829
/* 7276 */    MCD_OPC_Decode, 184, 8, 110, // Opcode: PCKOD_H
/* 7280 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 7292
/* 7284 */    MCD_OPC_CheckPredicate, 4, 165, 21, // Skip to: 12829
/* 7288 */    MCD_OPC_Decode, 185, 8, 111, // Opcode: PCKOD_W
/* 7292 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 7304
/* 7296 */    MCD_OPC_CheckPredicate, 4, 153, 21, // Skip to: 12829
/* 7300 */    MCD_OPC_Decode, 183, 8, 112, // Opcode: PCKOD_D
/* 7304 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 7316
/* 7308 */    MCD_OPC_CheckPredicate, 4, 141, 21, // Skip to: 12829
/* 7312 */    MCD_OPC_Decode, 198, 5, 109, // Opcode: ILVL_B
/* 7316 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 7328
/* 7320 */    MCD_OPC_CheckPredicate, 4, 129, 21, // Skip to: 12829
/* 7324 */    MCD_OPC_Decode, 200, 5, 110, // Opcode: ILVL_H
/* 7328 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 7340
/* 7332 */    MCD_OPC_CheckPredicate, 4, 117, 21, // Skip to: 12829
/* 7336 */    MCD_OPC_Decode, 201, 5, 111, // Opcode: ILVL_W
/* 7340 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 7352
/* 7344 */    MCD_OPC_CheckPredicate, 4, 105, 21, // Skip to: 12829
/* 7348 */    MCD_OPC_Decode, 199, 5, 112, // Opcode: ILVL_D
/* 7352 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 7364
/* 7356 */    MCD_OPC_CheckPredicate, 4, 93, 21, // Skip to: 12829
/* 7360 */    MCD_OPC_Decode, 206, 5, 109, // Opcode: ILVR_B
/* 7364 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 7376
/* 7368 */    MCD_OPC_CheckPredicate, 4, 81, 21, // Skip to: 12829
/* 7372 */    MCD_OPC_Decode, 208, 5, 110, // Opcode: ILVR_H
/* 7376 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 7388
/* 7380 */    MCD_OPC_CheckPredicate, 4, 69, 21, // Skip to: 12829
/* 7384 */    MCD_OPC_Decode, 209, 5, 111, // Opcode: ILVR_W
/* 7388 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 7400
/* 7392 */    MCD_OPC_CheckPredicate, 4, 57, 21, // Skip to: 12829
/* 7396 */    MCD_OPC_Decode, 207, 5, 112, // Opcode: ILVR_D
/* 7400 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 7412
/* 7404 */    MCD_OPC_CheckPredicate, 4, 45, 21, // Skip to: 12829
/* 7408 */    MCD_OPC_Decode, 194, 5, 109, // Opcode: ILVEV_B
/* 7412 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 7424
/* 7416 */    MCD_OPC_CheckPredicate, 4, 33, 21, // Skip to: 12829
/* 7420 */    MCD_OPC_Decode, 196, 5, 110, // Opcode: ILVEV_H
/* 7424 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 7436
/* 7428 */    MCD_OPC_CheckPredicate, 4, 21, 21, // Skip to: 12829
/* 7432 */    MCD_OPC_Decode, 197, 5, 111, // Opcode: ILVEV_W
/* 7436 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 7448
/* 7440 */    MCD_OPC_CheckPredicate, 4, 9, 21, // Skip to: 12829
/* 7444 */    MCD_OPC_Decode, 195, 5, 112, // Opcode: ILVEV_D
/* 7448 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 7460
/* 7452 */    MCD_OPC_CheckPredicate, 4, 253, 20, // Skip to: 12829
/* 7456 */    MCD_OPC_Decode, 202, 5, 109, // Opcode: ILVOD_B
/* 7460 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 7472
/* 7464 */    MCD_OPC_CheckPredicate, 4, 241, 20, // Skip to: 12829
/* 7468 */    MCD_OPC_Decode, 204, 5, 110, // Opcode: ILVOD_H
/* 7472 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 7484
/* 7476 */    MCD_OPC_CheckPredicate, 4, 229, 20, // Skip to: 12829
/* 7480 */    MCD_OPC_Decode, 205, 5, 111, // Opcode: ILVOD_W
/* 7484 */    MCD_OPC_FilterValue, 31, 221, 20, // Skip to: 12829
/* 7488 */    MCD_OPC_CheckPredicate, 4, 217, 20, // Skip to: 12829
/* 7492 */    MCD_OPC_Decode, 203, 5, 112, // Opcode: ILVOD_D
/* 7496 */    MCD_OPC_FilterValue, 21, 35, 1, // Skip to: 7791
/* 7500 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 7503 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 7515
/* 7507 */    MCD_OPC_CheckPredicate, 4, 198, 20, // Skip to: 12829
/* 7511 */    MCD_OPC_Decode, 183, 11, 113, // Opcode: VSHF_B
/* 7515 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 7527
/* 7519 */    MCD_OPC_CheckPredicate, 4, 186, 20, // Skip to: 12829
/* 7523 */    MCD_OPC_Decode, 185, 11, 114, // Opcode: VSHF_H
/* 7527 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 7539
/* 7531 */    MCD_OPC_CheckPredicate, 4, 174, 20, // Skip to: 12829
/* 7535 */    MCD_OPC_Decode, 186, 11, 115, // Opcode: VSHF_W
/* 7539 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 7551
/* 7543 */    MCD_OPC_CheckPredicate, 4, 162, 20, // Skip to: 12829
/* 7547 */    MCD_OPC_Decode, 184, 11, 116, // Opcode: VSHF_D
/* 7551 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 7563
/* 7555 */    MCD_OPC_CheckPredicate, 4, 150, 20, // Skip to: 12829
/* 7559 */    MCD_OPC_Decode, 128, 10, 109, // Opcode: SRAR_B
/* 7563 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 7575
/* 7567 */    MCD_OPC_CheckPredicate, 4, 138, 20, // Skip to: 12829
/* 7571 */    MCD_OPC_Decode, 130, 10, 110, // Opcode: SRAR_H
/* 7575 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 7587
/* 7579 */    MCD_OPC_CheckPredicate, 4, 126, 20, // Skip to: 12829
/* 7583 */    MCD_OPC_Decode, 131, 10, 111, // Opcode: SRAR_W
/* 7587 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 7599
/* 7591 */    MCD_OPC_CheckPredicate, 4, 114, 20, // Skip to: 12829
/* 7595 */    MCD_OPC_Decode, 129, 10, 112, // Opcode: SRAR_D
/* 7599 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 7611
/* 7603 */    MCD_OPC_CheckPredicate, 4, 102, 20, // Skip to: 12829
/* 7607 */    MCD_OPC_Decode, 148, 10, 109, // Opcode: SRLR_B
/* 7611 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 7623
/* 7615 */    MCD_OPC_CheckPredicate, 4, 90, 20, // Skip to: 12829
/* 7619 */    MCD_OPC_Decode, 150, 10, 110, // Opcode: SRLR_H
/* 7623 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 7635
/* 7627 */    MCD_OPC_CheckPredicate, 4, 78, 20, // Skip to: 12829
/* 7631 */    MCD_OPC_Decode, 151, 10, 111, // Opcode: SRLR_W
/* 7635 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 7647
/* 7639 */    MCD_OPC_CheckPredicate, 4, 66, 20, // Skip to: 12829
/* 7643 */    MCD_OPC_Decode, 149, 10, 112, // Opcode: SRLR_D
/* 7647 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 7659
/* 7651 */    MCD_OPC_CheckPredicate, 4, 54, 20, // Skip to: 12829
/* 7655 */    MCD_OPC_Decode, 183, 5, 117, // Opcode: HADD_S_H
/* 7659 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 7671
/* 7663 */    MCD_OPC_CheckPredicate, 4, 42, 20, // Skip to: 12829
/* 7667 */    MCD_OPC_Decode, 184, 5, 118, // Opcode: HADD_S_W
/* 7671 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 7683
/* 7675 */    MCD_OPC_CheckPredicate, 4, 30, 20, // Skip to: 12829
/* 7679 */    MCD_OPC_Decode, 182, 5, 119, // Opcode: HADD_S_D
/* 7683 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 7695
/* 7687 */    MCD_OPC_CheckPredicate, 4, 18, 20, // Skip to: 12829
/* 7691 */    MCD_OPC_Decode, 186, 5, 117, // Opcode: HADD_U_H
/* 7695 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 7707
/* 7699 */    MCD_OPC_CheckPredicate, 4, 6, 20, // Skip to: 12829
/* 7703 */    MCD_OPC_Decode, 187, 5, 118, // Opcode: HADD_U_W
/* 7707 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 7719
/* 7711 */    MCD_OPC_CheckPredicate, 4, 250, 19, // Skip to: 12829
/* 7715 */    MCD_OPC_Decode, 185, 5, 119, // Opcode: HADD_U_D
/* 7719 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 7731
/* 7723 */    MCD_OPC_CheckPredicate, 4, 238, 19, // Skip to: 12829
/* 7727 */    MCD_OPC_Decode, 189, 5, 117, // Opcode: HSUB_S_H
/* 7731 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 7743
/* 7735 */    MCD_OPC_CheckPredicate, 4, 226, 19, // Skip to: 12829
/* 7739 */    MCD_OPC_Decode, 190, 5, 118, // Opcode: HSUB_S_W
/* 7743 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 7755
/* 7747 */    MCD_OPC_CheckPredicate, 4, 214, 19, // Skip to: 12829
/* 7751 */    MCD_OPC_Decode, 188, 5, 119, // Opcode: HSUB_S_D
/* 7755 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 7767
/* 7759 */    MCD_OPC_CheckPredicate, 4, 202, 19, // Skip to: 12829
/* 7763 */    MCD_OPC_Decode, 192, 5, 117, // Opcode: HSUB_U_H
/* 7767 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 7779
/* 7771 */    MCD_OPC_CheckPredicate, 4, 190, 19, // Skip to: 12829
/* 7775 */    MCD_OPC_Decode, 193, 5, 118, // Opcode: HSUB_U_W
/* 7779 */    MCD_OPC_FilterValue, 31, 182, 19, // Skip to: 12829
/* 7783 */    MCD_OPC_CheckPredicate, 4, 178, 19, // Skip to: 12829
/* 7787 */    MCD_OPC_Decode, 191, 5, 119, // Opcode: HSUB_U_D
/* 7791 */    MCD_OPC_FilterValue, 25, 230, 1, // Skip to: 8281
/* 7795 */    MCD_OPC_ExtractField, 20, 6,  // Inst{25-20} ...
/* 7798 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 7811
/* 7802 */    MCD_OPC_CheckPredicate, 4, 159, 19, // Skip to: 12829
/* 7806 */    MCD_OPC_Decode, 200, 9, 131, 1, // Opcode: SLDI_B
/* 7811 */    MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 7830
/* 7815 */    MCD_OPC_CheckPredicate, 4, 146, 19, // Skip to: 12829
/* 7819 */    MCD_OPC_CheckField, 19, 1, 0, 140, 19, // Skip to: 12829
/* 7825 */    MCD_OPC_Decode, 202, 9, 132, 1, // Opcode: SLDI_H
/* 7830 */    MCD_OPC_FilterValue, 3, 54, 0, // Skip to: 7888
/* 7834 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 7837 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 7850
/* 7841 */    MCD_OPC_CheckPredicate, 4, 120, 19, // Skip to: 12829
/* 7845 */    MCD_OPC_Decode, 203, 9, 133, 1, // Opcode: SLDI_W
/* 7850 */    MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 7869
/* 7854 */    MCD_OPC_CheckPredicate, 4, 107, 19, // Skip to: 12829
/* 7858 */    MCD_OPC_CheckField, 17, 1, 0, 101, 19, // Skip to: 12829
/* 7864 */    MCD_OPC_Decode, 201, 9, 134, 1, // Opcode: SLDI_D
/* 7869 */    MCD_OPC_FilterValue, 3, 92, 19, // Skip to: 12829
/* 7873 */    MCD_OPC_CheckPredicate, 4, 88, 19, // Skip to: 12829
/* 7877 */    MCD_OPC_CheckField, 16, 2, 2, 82, 19, // Skip to: 12829
/* 7883 */    MCD_OPC_Decode, 219, 2, 135, 1, // Opcode: CTCMSA
/* 7888 */    MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 7901
/* 7892 */    MCD_OPC_CheckPredicate, 4, 69, 19, // Skip to: 12829
/* 7896 */    MCD_OPC_Decode, 239, 9, 136, 1, // Opcode: SPLATI_B
/* 7901 */    MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 7920
/* 7905 */    MCD_OPC_CheckPredicate, 4, 56, 19, // Skip to: 12829
/* 7909 */    MCD_OPC_CheckField, 19, 1, 0, 50, 19, // Skip to: 12829
/* 7915 */    MCD_OPC_Decode, 241, 9, 137, 1, // Opcode: SPLATI_H
/* 7920 */    MCD_OPC_FilterValue, 7, 54, 0, // Skip to: 7978
/* 7924 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 7927 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 7940
/* 7931 */    MCD_OPC_CheckPredicate, 4, 30, 19, // Skip to: 12829
/* 7935 */    MCD_OPC_Decode, 242, 9, 138, 1, // Opcode: SPLATI_W
/* 7940 */    MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 7959
/* 7944 */    MCD_OPC_CheckPredicate, 4, 17, 19, // Skip to: 12829
/* 7948 */    MCD_OPC_CheckField, 17, 1, 0, 11, 19, // Skip to: 12829
/* 7954 */    MCD_OPC_Decode, 240, 9, 139, 1, // Opcode: SPLATI_D
/* 7959 */    MCD_OPC_FilterValue, 3, 2, 19, // Skip to: 12829
/* 7963 */    MCD_OPC_CheckPredicate, 4, 254, 18, // Skip to: 12829
/* 7967 */    MCD_OPC_CheckField, 16, 2, 2, 248, 18, // Skip to: 12829
/* 7973 */    MCD_OPC_Decode, 157, 2, 140, 1, // Opcode: CFCMSA
/* 7978 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 7991
/* 7982 */    MCD_OPC_CheckPredicate, 4, 235, 18, // Skip to: 12829
/* 7986 */    MCD_OPC_Decode, 209, 2, 141, 1, // Opcode: COPY_S_B
/* 7991 */    MCD_OPC_FilterValue, 10, 15, 0, // Skip to: 8010
/* 7995 */    MCD_OPC_CheckPredicate, 4, 222, 18, // Skip to: 12829
/* 7999 */    MCD_OPC_CheckField, 19, 1, 0, 216, 18, // Skip to: 12829
/* 8005 */    MCD_OPC_Decode, 211, 2, 142, 1, // Opcode: COPY_S_H
/* 8010 */    MCD_OPC_FilterValue, 11, 54, 0, // Skip to: 8068
/* 8014 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 8017 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8030
/* 8021 */    MCD_OPC_CheckPredicate, 4, 196, 18, // Skip to: 12829
/* 8025 */    MCD_OPC_Decode, 212, 2, 143, 1, // Opcode: COPY_S_W
/* 8030 */    MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 8049
/* 8034 */    MCD_OPC_CheckPredicate, 6, 183, 18, // Skip to: 12829
/* 8038 */    MCD_OPC_CheckField, 17, 1, 0, 177, 18, // Skip to: 12829
/* 8044 */    MCD_OPC_Decode, 210, 2, 144, 1, // Opcode: COPY_S_D
/* 8049 */    MCD_OPC_FilterValue, 3, 168, 18, // Skip to: 12829
/* 8053 */    MCD_OPC_CheckPredicate, 4, 164, 18, // Skip to: 12829
/* 8057 */    MCD_OPC_CheckField, 16, 2, 2, 158, 18, // Skip to: 12829
/* 8063 */    MCD_OPC_Decode, 153, 7, 145, 1, // Opcode: MOVE_V
/* 8068 */    MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 8081
/* 8072 */    MCD_OPC_CheckPredicate, 4, 145, 18, // Skip to: 12829
/* 8076 */    MCD_OPC_Decode, 213, 2, 141, 1, // Opcode: COPY_U_B
/* 8081 */    MCD_OPC_FilterValue, 14, 15, 0, // Skip to: 8100
/* 8085 */    MCD_OPC_CheckPredicate, 4, 132, 18, // Skip to: 12829
/* 8089 */    MCD_OPC_CheckField, 19, 1, 0, 126, 18, // Skip to: 12829
/* 8095 */    MCD_OPC_Decode, 215, 2, 142, 1, // Opcode: COPY_U_H
/* 8100 */    MCD_OPC_FilterValue, 15, 35, 0, // Skip to: 8139
/* 8104 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 8107 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8120
/* 8111 */    MCD_OPC_CheckPredicate, 4, 106, 18, // Skip to: 12829
/* 8115 */    MCD_OPC_Decode, 216, 2, 143, 1, // Opcode: COPY_U_W
/* 8120 */    MCD_OPC_FilterValue, 2, 97, 18, // Skip to: 12829
/* 8124 */    MCD_OPC_CheckPredicate, 6, 93, 18, // Skip to: 12829
/* 8128 */    MCD_OPC_CheckField, 17, 1, 0, 87, 18, // Skip to: 12829
/* 8134 */    MCD_OPC_Decode, 214, 2, 144, 1, // Opcode: COPY_U_D
/* 8139 */    MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 8152
/* 8143 */    MCD_OPC_CheckPredicate, 4, 74, 18, // Skip to: 12829
/* 8147 */    MCD_OPC_Decode, 211, 5, 146, 1, // Opcode: INSERT_B
/* 8152 */    MCD_OPC_FilterValue, 18, 15, 0, // Skip to: 8171
/* 8156 */    MCD_OPC_CheckPredicate, 4, 61, 18, // Skip to: 12829
/* 8160 */    MCD_OPC_CheckField, 19, 1, 0, 55, 18, // Skip to: 12829
/* 8166 */    MCD_OPC_Decode, 215, 5, 147, 1, // Opcode: INSERT_H
/* 8171 */    MCD_OPC_FilterValue, 19, 35, 0, // Skip to: 8210
/* 8175 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 8178 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8191
/* 8182 */    MCD_OPC_CheckPredicate, 4, 35, 18, // Skip to: 12829
/* 8186 */    MCD_OPC_Decode, 216, 5, 148, 1, // Opcode: INSERT_W
/* 8191 */    MCD_OPC_FilterValue, 2, 26, 18, // Skip to: 12829
/* 8195 */    MCD_OPC_CheckPredicate, 6, 22, 18, // Skip to: 12829
/* 8199 */    MCD_OPC_CheckField, 17, 1, 0, 16, 18, // Skip to: 12829
/* 8205 */    MCD_OPC_Decode, 212, 5, 149, 1, // Opcode: INSERT_D
/* 8210 */    MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 8223
/* 8214 */    MCD_OPC_CheckPredicate, 4, 3, 18, // Skip to: 12829
/* 8218 */    MCD_OPC_Decode, 218, 5, 150, 1, // Opcode: INSVE_B
/* 8223 */    MCD_OPC_FilterValue, 22, 15, 0, // Skip to: 8242
/* 8227 */    MCD_OPC_CheckPredicate, 4, 246, 17, // Skip to: 12829
/* 8231 */    MCD_OPC_CheckField, 19, 1, 0, 240, 17, // Skip to: 12829
/* 8237 */    MCD_OPC_Decode, 220, 5, 151, 1, // Opcode: INSVE_H
/* 8242 */    MCD_OPC_FilterValue, 23, 231, 17, // Skip to: 12829
/* 8246 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 8249 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8262
/* 8253 */    MCD_OPC_CheckPredicate, 4, 220, 17, // Skip to: 12829
/* 8257 */    MCD_OPC_Decode, 221, 5, 152, 1, // Opcode: INSVE_W
/* 8262 */    MCD_OPC_FilterValue, 2, 211, 17, // Skip to: 12829
/* 8266 */    MCD_OPC_CheckPredicate, 4, 207, 17, // Skip to: 12829
/* 8270 */    MCD_OPC_CheckField, 17, 1, 0, 201, 17, // Skip to: 12829
/* 8276 */    MCD_OPC_Decode, 219, 5, 153, 1, // Opcode: INSVE_D
/* 8281 */    MCD_OPC_FilterValue, 26, 131, 1, // Skip to: 8672
/* 8285 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 8288 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 8300
/* 8292 */    MCD_OPC_CheckPredicate, 4, 181, 17, // Skip to: 12829
/* 8296 */    MCD_OPC_Decode, 160, 4, 111, // Opcode: FCAF_W
/* 8300 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 8312
/* 8304 */    MCD_OPC_CheckPredicate, 4, 169, 17, // Skip to: 12829
/* 8308 */    MCD_OPC_Decode, 159, 4, 112, // Opcode: FCAF_D
/* 8312 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 8324
/* 8316 */    MCD_OPC_CheckPredicate, 4, 157, 17, // Skip to: 12829
/* 8320 */    MCD_OPC_Decode, 187, 4, 111, // Opcode: FCUN_W
/* 8324 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 8336
/* 8328 */    MCD_OPC_CheckPredicate, 4, 145, 17, // Skip to: 12829
/* 8332 */    MCD_OPC_Decode, 186, 4, 112, // Opcode: FCUN_D
/* 8336 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 8348
/* 8340 */    MCD_OPC_CheckPredicate, 4, 133, 17, // Skip to: 12829
/* 8344 */    MCD_OPC_Decode, 162, 4, 111, // Opcode: FCEQ_W
/* 8348 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 8360
/* 8352 */    MCD_OPC_CheckPredicate, 4, 121, 17, // Skip to: 12829
/* 8356 */    MCD_OPC_Decode, 161, 4, 112, // Opcode: FCEQ_D
/* 8360 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 8372
/* 8364 */    MCD_OPC_CheckPredicate, 4, 109, 17, // Skip to: 12829
/* 8368 */    MCD_OPC_Decode, 179, 4, 111, // Opcode: FCUEQ_W
/* 8372 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 8384
/* 8376 */    MCD_OPC_CheckPredicate, 4, 97, 17, // Skip to: 12829
/* 8380 */    MCD_OPC_Decode, 178, 4, 112, // Opcode: FCUEQ_D
/* 8384 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 8396
/* 8388 */    MCD_OPC_CheckPredicate, 4, 85, 17, // Skip to: 12829
/* 8392 */    MCD_OPC_Decode, 168, 4, 111, // Opcode: FCLT_W
/* 8396 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 8408
/* 8400 */    MCD_OPC_CheckPredicate, 4, 73, 17, // Skip to: 12829
/* 8404 */    MCD_OPC_Decode, 167, 4, 112, // Opcode: FCLT_D
/* 8408 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 8420
/* 8412 */    MCD_OPC_CheckPredicate, 4, 61, 17, // Skip to: 12829
/* 8416 */    MCD_OPC_Decode, 183, 4, 111, // Opcode: FCULT_W
/* 8420 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 8432
/* 8424 */    MCD_OPC_CheckPredicate, 4, 49, 17, // Skip to: 12829
/* 8428 */    MCD_OPC_Decode, 182, 4, 112, // Opcode: FCULT_D
/* 8432 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 8444
/* 8436 */    MCD_OPC_CheckPredicate, 4, 37, 17, // Skip to: 12829
/* 8440 */    MCD_OPC_Decode, 166, 4, 111, // Opcode: FCLE_W
/* 8444 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 8456
/* 8448 */    MCD_OPC_CheckPredicate, 4, 25, 17, // Skip to: 12829
/* 8452 */    MCD_OPC_Decode, 165, 4, 112, // Opcode: FCLE_D
/* 8456 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 8468
/* 8460 */    MCD_OPC_CheckPredicate, 4, 13, 17, // Skip to: 12829
/* 8464 */    MCD_OPC_Decode, 181, 4, 111, // Opcode: FCULE_W
/* 8468 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 8480
/* 8472 */    MCD_OPC_CheckPredicate, 4, 1, 17, // Skip to: 12829
/* 8476 */    MCD_OPC_Decode, 180, 4, 112, // Opcode: FCULE_D
/* 8480 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 8492
/* 8484 */    MCD_OPC_CheckPredicate, 4, 245, 16, // Skip to: 12829
/* 8488 */    MCD_OPC_Decode, 136, 5, 111, // Opcode: FSAF_W
/* 8492 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 8504
/* 8496 */    MCD_OPC_CheckPredicate, 4, 233, 16, // Skip to: 12829
/* 8500 */    MCD_OPC_Decode, 135, 5, 112, // Opcode: FSAF_D
/* 8504 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 8516
/* 8508 */    MCD_OPC_CheckPredicate, 4, 221, 16, // Skip to: 12829
/* 8512 */    MCD_OPC_Decode, 170, 5, 111, // Opcode: FSUN_W
/* 8516 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 8528
/* 8520 */    MCD_OPC_CheckPredicate, 4, 209, 16, // Skip to: 12829
/* 8524 */    MCD_OPC_Decode, 169, 5, 112, // Opcode: FSUN_D
/* 8528 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 8540
/* 8532 */    MCD_OPC_CheckPredicate, 4, 197, 16, // Skip to: 12829
/* 8536 */    MCD_OPC_Decode, 138, 5, 111, // Opcode: FSEQ_W
/* 8540 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 8552
/* 8544 */    MCD_OPC_CheckPredicate, 4, 185, 16, // Skip to: 12829
/* 8548 */    MCD_OPC_Decode, 137, 5, 112, // Opcode: FSEQ_D
/* 8552 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 8564
/* 8556 */    MCD_OPC_CheckPredicate, 4, 173, 16, // Skip to: 12829
/* 8560 */    MCD_OPC_Decode, 162, 5, 111, // Opcode: FSUEQ_W
/* 8564 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 8576
/* 8568 */    MCD_OPC_CheckPredicate, 4, 161, 16, // Skip to: 12829
/* 8572 */    MCD_OPC_Decode, 161, 5, 112, // Opcode: FSUEQ_D
/* 8576 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 8588
/* 8580 */    MCD_OPC_CheckPredicate, 4, 149, 16, // Skip to: 12829
/* 8584 */    MCD_OPC_Decode, 142, 5, 111, // Opcode: FSLT_W
/* 8588 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 8600
/* 8592 */    MCD_OPC_CheckPredicate, 4, 137, 16, // Skip to: 12829
/* 8596 */    MCD_OPC_Decode, 141, 5, 112, // Opcode: FSLT_D
/* 8600 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 8612
/* 8604 */    MCD_OPC_CheckPredicate, 4, 125, 16, // Skip to: 12829
/* 8608 */    MCD_OPC_Decode, 166, 5, 111, // Opcode: FSULT_W
/* 8612 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 8624
/* 8616 */    MCD_OPC_CheckPredicate, 4, 113, 16, // Skip to: 12829
/* 8620 */    MCD_OPC_Decode, 165, 5, 112, // Opcode: FSULT_D
/* 8624 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 8636
/* 8628 */    MCD_OPC_CheckPredicate, 4, 101, 16, // Skip to: 12829
/* 8632 */    MCD_OPC_Decode, 140, 5, 111, // Opcode: FSLE_W
/* 8636 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 8648
/* 8640 */    MCD_OPC_CheckPredicate, 4, 89, 16, // Skip to: 12829
/* 8644 */    MCD_OPC_Decode, 139, 5, 112, // Opcode: FSLE_D
/* 8648 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 8660
/* 8652 */    MCD_OPC_CheckPredicate, 4, 77, 16, // Skip to: 12829
/* 8656 */    MCD_OPC_Decode, 164, 5, 111, // Opcode: FSULE_W
/* 8660 */    MCD_OPC_FilterValue, 31, 69, 16, // Skip to: 12829
/* 8664 */    MCD_OPC_CheckPredicate, 4, 65, 16, // Skip to: 12829
/* 8668 */    MCD_OPC_Decode, 163, 5, 112, // Opcode: FSULE_D
/* 8672 */    MCD_OPC_FilterValue, 27, 63, 1, // Skip to: 8995
/* 8676 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 8679 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 8691
/* 8683 */    MCD_OPC_CheckPredicate, 4, 46, 16, // Skip to: 12829
/* 8687 */    MCD_OPC_Decode, 158, 4, 111, // Opcode: FADD_W
/* 8691 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 8703
/* 8695 */    MCD_OPC_CheckPredicate, 4, 34, 16, // Skip to: 12829
/* 8699 */    MCD_OPC_Decode, 152, 4, 112, // Opcode: FADD_D
/* 8703 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 8715
/* 8707 */    MCD_OPC_CheckPredicate, 4, 22, 16, // Skip to: 12829
/* 8711 */    MCD_OPC_Decode, 160, 5, 111, // Opcode: FSUB_W
/* 8715 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 8727
/* 8719 */    MCD_OPC_CheckPredicate, 4, 10, 16, // Skip to: 12829
/* 8723 */    MCD_OPC_Decode, 154, 5, 112, // Opcode: FSUB_D
/* 8727 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 8739
/* 8731 */    MCD_OPC_CheckPredicate, 4, 254, 15, // Skip to: 12829
/* 8735 */    MCD_OPC_Decode, 251, 4, 111, // Opcode: FMUL_W
/* 8739 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 8751
/* 8743 */    MCD_OPC_CheckPredicate, 4, 242, 15, // Skip to: 12829
/* 8747 */    MCD_OPC_Decode, 245, 4, 112, // Opcode: FMUL_D
/* 8751 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 8763
/* 8755 */    MCD_OPC_CheckPredicate, 4, 230, 15, // Skip to: 12829
/* 8759 */    MCD_OPC_Decode, 194, 4, 111, // Opcode: FDIV_W
/* 8763 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 8775
/* 8767 */    MCD_OPC_CheckPredicate, 4, 218, 15, // Skip to: 12829
/* 8771 */    MCD_OPC_Decode, 188, 4, 112, // Opcode: FDIV_D
/* 8775 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 8787
/* 8779 */    MCD_OPC_CheckPredicate, 4, 206, 15, // Skip to: 12829
/* 8783 */    MCD_OPC_Decode, 229, 4, 115, // Opcode: FMADD_W
/* 8787 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 8799
/* 8791 */    MCD_OPC_CheckPredicate, 4, 194, 15, // Skip to: 12829
/* 8795 */    MCD_OPC_Decode, 228, 4, 116, // Opcode: FMADD_D
/* 8799 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 8811
/* 8803 */    MCD_OPC_CheckPredicate, 4, 182, 15, // Skip to: 12829
/* 8807 */    MCD_OPC_Decode, 244, 4, 115, // Opcode: FMSUB_W
/* 8811 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 8823
/* 8815 */    MCD_OPC_CheckPredicate, 4, 170, 15, // Skip to: 12829
/* 8819 */    MCD_OPC_Decode, 243, 4, 116, // Opcode: FMSUB_D
/* 8823 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 8835
/* 8827 */    MCD_OPC_CheckPredicate, 4, 158, 15, // Skip to: 12829
/* 8831 */    MCD_OPC_Decode, 199, 4, 111, // Opcode: FEXP2_W
/* 8835 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 8847
/* 8839 */    MCD_OPC_CheckPredicate, 4, 146, 15, // Skip to: 12829
/* 8843 */    MCD_OPC_Decode, 197, 4, 112, // Opcode: FEXP2_D
/* 8847 */    MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 8860
/* 8851 */    MCD_OPC_CheckPredicate, 4, 134, 15, // Skip to: 12829
/* 8855 */    MCD_OPC_Decode, 195, 4, 154, 1, // Opcode: FEXDO_H
/* 8860 */    MCD_OPC_FilterValue, 17, 9, 0, // Skip to: 8873
/* 8864 */    MCD_OPC_CheckPredicate, 4, 121, 15, // Skip to: 12829
/* 8868 */    MCD_OPC_Decode, 196, 4, 155, 1, // Opcode: FEXDO_W
/* 8873 */    MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 8886
/* 8877 */    MCD_OPC_CheckPredicate, 4, 108, 15, // Skip to: 12829
/* 8881 */    MCD_OPC_Decode, 175, 5, 154, 1, // Opcode: FTQ_H
/* 8886 */    MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 8899
/* 8890 */    MCD_OPC_CheckPredicate, 4, 95, 15, // Skip to: 12829
/* 8894 */    MCD_OPC_Decode, 176, 5, 155, 1, // Opcode: FTQ_W
/* 8899 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 8911
/* 8903 */    MCD_OPC_CheckPredicate, 4, 82, 15, // Skip to: 12829
/* 8907 */    MCD_OPC_Decode, 237, 4, 111, // Opcode: FMIN_W
/* 8911 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 8923
/* 8915 */    MCD_OPC_CheckPredicate, 4, 70, 15, // Skip to: 12829
/* 8919 */    MCD_OPC_Decode, 236, 4, 112, // Opcode: FMIN_D
/* 8923 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 8935
/* 8927 */    MCD_OPC_CheckPredicate, 4, 58, 15, // Skip to: 12829
/* 8931 */    MCD_OPC_Decode, 235, 4, 111, // Opcode: FMIN_A_W
/* 8935 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 8947
/* 8939 */    MCD_OPC_CheckPredicate, 4, 46, 15, // Skip to: 12829
/* 8943 */    MCD_OPC_Decode, 234, 4, 112, // Opcode: FMIN_A_D
/* 8947 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 8959
/* 8951 */    MCD_OPC_CheckPredicate, 4, 34, 15, // Skip to: 12829
/* 8955 */    MCD_OPC_Decode, 233, 4, 111, // Opcode: FMAX_W
/* 8959 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 8971
/* 8963 */    MCD_OPC_CheckPredicate, 4, 22, 15, // Skip to: 12829
/* 8967 */    MCD_OPC_Decode, 232, 4, 112, // Opcode: FMAX_D
/* 8971 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 8983
/* 8975 */    MCD_OPC_CheckPredicate, 4, 10, 15, // Skip to: 12829
/* 8979 */    MCD_OPC_Decode, 231, 4, 111, // Opcode: FMAX_A_W
/* 8983 */    MCD_OPC_FilterValue, 31, 2, 15, // Skip to: 12829
/* 8987 */    MCD_OPC_CheckPredicate, 4, 254, 14, // Skip to: 12829
/* 8991 */    MCD_OPC_Decode, 230, 4, 112, // Opcode: FMAX_A_D
/* 8995 */    MCD_OPC_FilterValue, 28, 35, 1, // Skip to: 9290
/* 8999 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 9002 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 9014
/* 9006 */    MCD_OPC_CheckPredicate, 4, 235, 14, // Skip to: 12829
/* 9010 */    MCD_OPC_Decode, 177, 4, 111, // Opcode: FCOR_W
/* 9014 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 9026
/* 9018 */    MCD_OPC_CheckPredicate, 4, 223, 14, // Skip to: 12829
/* 9022 */    MCD_OPC_Decode, 176, 4, 112, // Opcode: FCOR_D
/* 9026 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 9038
/* 9030 */    MCD_OPC_CheckPredicate, 4, 211, 14, // Skip to: 12829
/* 9034 */    MCD_OPC_Decode, 185, 4, 111, // Opcode: FCUNE_W
/* 9038 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 9050
/* 9042 */    MCD_OPC_CheckPredicate, 4, 199, 14, // Skip to: 12829
/* 9046 */    MCD_OPC_Decode, 184, 4, 112, // Opcode: FCUNE_D
/* 9050 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 9062
/* 9054 */    MCD_OPC_CheckPredicate, 4, 187, 14, // Skip to: 12829
/* 9058 */    MCD_OPC_Decode, 175, 4, 111, // Opcode: FCNE_W
/* 9062 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 9074
/* 9066 */    MCD_OPC_CheckPredicate, 4, 175, 14, // Skip to: 12829
/* 9070 */    MCD_OPC_Decode, 174, 4, 112, // Opcode: FCNE_D
/* 9074 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 9086
/* 9078 */    MCD_OPC_CheckPredicate, 4, 163, 14, // Skip to: 12829
/* 9082 */    MCD_OPC_Decode, 253, 7, 110, // Opcode: MUL_Q_H
/* 9086 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 9098
/* 9090 */    MCD_OPC_CheckPredicate, 4, 151, 14, // Skip to: 12829
/* 9094 */    MCD_OPC_Decode, 254, 7, 111, // Opcode: MUL_Q_W
/* 9098 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 9110
/* 9102 */    MCD_OPC_CheckPredicate, 4, 139, 14, // Skip to: 12829
/* 9106 */    MCD_OPC_Decode, 208, 6, 114, // Opcode: MADD_Q_H
/* 9110 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 9122
/* 9114 */    MCD_OPC_CheckPredicate, 4, 127, 14, // Skip to: 12829
/* 9118 */    MCD_OPC_Decode, 209, 6, 115, // Opcode: MADD_Q_W
/* 9122 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 9134
/* 9126 */    MCD_OPC_CheckPredicate, 4, 115, 14, // Skip to: 12829
/* 9130 */    MCD_OPC_Decode, 209, 7, 114, // Opcode: MSUB_Q_H
/* 9134 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 9146
/* 9138 */    MCD_OPC_CheckPredicate, 4, 103, 14, // Skip to: 12829
/* 9142 */    MCD_OPC_Decode, 210, 7, 115, // Opcode: MSUB_Q_W
/* 9146 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 9158
/* 9150 */    MCD_OPC_CheckPredicate, 4, 91, 14, // Skip to: 12829
/* 9154 */    MCD_OPC_Decode, 146, 5, 111, // Opcode: FSOR_W
/* 9158 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 9170
/* 9162 */    MCD_OPC_CheckPredicate, 4, 79, 14, // Skip to: 12829
/* 9166 */    MCD_OPC_Decode, 145, 5, 112, // Opcode: FSOR_D
/* 9170 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 9182
/* 9174 */    MCD_OPC_CheckPredicate, 4, 67, 14, // Skip to: 12829
/* 9178 */    MCD_OPC_Decode, 168, 5, 111, // Opcode: FSUNE_W
/* 9182 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 9194
/* 9186 */    MCD_OPC_CheckPredicate, 4, 55, 14, // Skip to: 12829
/* 9190 */    MCD_OPC_Decode, 167, 5, 112, // Opcode: FSUNE_D
/* 9194 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 9206
/* 9198 */    MCD_OPC_CheckPredicate, 4, 43, 14, // Skip to: 12829
/* 9202 */    MCD_OPC_Decode, 144, 5, 111, // Opcode: FSNE_W
/* 9206 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 9218
/* 9210 */    MCD_OPC_CheckPredicate, 4, 31, 14, // Skip to: 12829
/* 9214 */    MCD_OPC_Decode, 143, 5, 112, // Opcode: FSNE_D
/* 9218 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 9230
/* 9222 */    MCD_OPC_CheckPredicate, 4, 19, 14, // Skip to: 12829
/* 9226 */    MCD_OPC_Decode, 237, 7, 110, // Opcode: MULR_Q_H
/* 9230 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 9242
/* 9234 */    MCD_OPC_CheckPredicate, 4, 7, 14, // Skip to: 12829
/* 9238 */    MCD_OPC_Decode, 238, 7, 111, // Opcode: MULR_Q_W
/* 9242 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 9254
/* 9246 */    MCD_OPC_CheckPredicate, 4, 251, 13, // Skip to: 12829
/* 9250 */    MCD_OPC_Decode, 194, 6, 114, // Opcode: MADDR_Q_H
/* 9254 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 9266
/* 9258 */    MCD_OPC_CheckPredicate, 4, 239, 13, // Skip to: 12829
/* 9262 */    MCD_OPC_Decode, 195, 6, 115, // Opcode: MADDR_Q_W
/* 9266 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 9278
/* 9270 */    MCD_OPC_CheckPredicate, 4, 227, 13, // Skip to: 12829
/* 9274 */    MCD_OPC_Decode, 195, 7, 114, // Opcode: MSUBR_Q_H
/* 9278 */    MCD_OPC_FilterValue, 29, 219, 13, // Skip to: 12829
/* 9282 */    MCD_OPC_CheckPredicate, 4, 215, 13, // Skip to: 12829
/* 9286 */    MCD_OPC_Decode, 196, 7, 115, // Opcode: MSUBR_Q_W
/* 9290 */    MCD_OPC_FilterValue, 30, 212, 2, // Skip to: 10018
/* 9294 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 9297 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 9308
/* 9301 */    MCD_OPC_CheckPredicate, 4, 196, 13, // Skip to: 12829
/* 9305 */    MCD_OPC_Decode, 75, 109, // Opcode: AND_V
/* 9308 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 9320
/* 9312 */    MCD_OPC_CheckPredicate, 4, 185, 13, // Skip to: 12829
/* 9316 */    MCD_OPC_Decode, 169, 8, 109, // Opcode: OR_V
/* 9320 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 9332
/* 9324 */    MCD_OPC_CheckPredicate, 4, 173, 13, // Skip to: 12829
/* 9328 */    MCD_OPC_Decode, 159, 8, 109, // Opcode: NOR_V
/* 9332 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 9344
/* 9336 */    MCD_OPC_CheckPredicate, 4, 161, 13, // Skip to: 12829
/* 9340 */    MCD_OPC_Decode, 196, 11, 109, // Opcode: XOR_V
/* 9344 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 9356
/* 9348 */    MCD_OPC_CheckPredicate, 4, 149, 13, // Skip to: 12829
/* 9352 */    MCD_OPC_Decode, 200, 1, 113, // Opcode: BMNZ_V
/* 9356 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 9368
/* 9360 */    MCD_OPC_CheckPredicate, 4, 137, 13, // Skip to: 12829
/* 9364 */    MCD_OPC_Decode, 202, 1, 113, // Opcode: BMZ_V
/* 9368 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 9380
/* 9372 */    MCD_OPC_CheckPredicate, 4, 125, 13, // Skip to: 12829
/* 9376 */    MCD_OPC_Decode, 228, 1, 113, // Opcode: BSEL_V
/* 9380 */    MCD_OPC_FilterValue, 24, 211, 0, // Skip to: 9595
/* 9384 */    MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 9387 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 9400
/* 9391 */    MCD_OPC_CheckPredicate, 4, 106, 13, // Skip to: 12829
/* 9395 */    MCD_OPC_Decode, 213, 4, 156, 1, // Opcode: FILL_B
/* 9400 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 9413
/* 9404 */    MCD_OPC_CheckPredicate, 4, 93, 13, // Skip to: 12829
/* 9408 */    MCD_OPC_Decode, 217, 4, 157, 1, // Opcode: FILL_H
/* 9413 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 9426
/* 9417 */    MCD_OPC_CheckPredicate, 4, 80, 13, // Skip to: 12829
/* 9421 */    MCD_OPC_Decode, 218, 4, 158, 1, // Opcode: FILL_W
/* 9426 */    MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 9439
/* 9430 */    MCD_OPC_CheckPredicate, 6, 67, 13, // Skip to: 12829
/* 9434 */    MCD_OPC_Decode, 214, 4, 159, 1, // Opcode: FILL_D
/* 9439 */    MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 9452
/* 9443 */    MCD_OPC_CheckPredicate, 4, 54, 13, // Skip to: 12829
/* 9447 */    MCD_OPC_Decode, 186, 8, 145, 1, // Opcode: PCNT_B
/* 9452 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 9465
/* 9456 */    MCD_OPC_CheckPredicate, 4, 41, 13, // Skip to: 12829
/* 9460 */    MCD_OPC_Decode, 188, 8, 160, 1, // Opcode: PCNT_H
/* 9465 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 9478
/* 9469 */    MCD_OPC_CheckPredicate, 4, 28, 13, // Skip to: 12829
/* 9473 */    MCD_OPC_Decode, 189, 8, 161, 1, // Opcode: PCNT_W
/* 9478 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 9491
/* 9482 */    MCD_OPC_CheckPredicate, 4, 15, 13, // Skip to: 12829
/* 9486 */    MCD_OPC_Decode, 187, 8, 162, 1, // Opcode: PCNT_D
/* 9491 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 9504
/* 9495 */    MCD_OPC_CheckPredicate, 4, 2, 13, // Skip to: 12829
/* 9499 */    MCD_OPC_Decode, 136, 8, 145, 1, // Opcode: NLOC_B
/* 9504 */    MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 9517
/* 9508 */    MCD_OPC_CheckPredicate, 4, 245, 12, // Skip to: 12829
/* 9512 */    MCD_OPC_Decode, 138, 8, 160, 1, // Opcode: NLOC_H
/* 9517 */    MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 9530
/* 9521 */    MCD_OPC_CheckPredicate, 4, 232, 12, // Skip to: 12829
/* 9525 */    MCD_OPC_Decode, 139, 8, 161, 1, // Opcode: NLOC_W
/* 9530 */    MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 9543
/* 9534 */    MCD_OPC_CheckPredicate, 4, 219, 12, // Skip to: 12829
/* 9538 */    MCD_OPC_Decode, 137, 8, 162, 1, // Opcode: NLOC_D
/* 9543 */    MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 9556
/* 9547 */    MCD_OPC_CheckPredicate, 4, 206, 12, // Skip to: 12829
/* 9551 */    MCD_OPC_Decode, 140, 8, 145, 1, // Opcode: NLZC_B
/* 9556 */    MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 9569
/* 9560 */    MCD_OPC_CheckPredicate, 4, 193, 12, // Skip to: 12829
/* 9564 */    MCD_OPC_Decode, 142, 8, 160, 1, // Opcode: NLZC_H
/* 9569 */    MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 9582
/* 9573 */    MCD_OPC_CheckPredicate, 4, 180, 12, // Skip to: 12829
/* 9577 */    MCD_OPC_Decode, 143, 8, 161, 1, // Opcode: NLZC_W
/* 9582 */    MCD_OPC_FilterValue, 15, 171, 12, // Skip to: 12829
/* 9586 */    MCD_OPC_CheckPredicate, 4, 167, 12, // Skip to: 12829
/* 9590 */    MCD_OPC_Decode, 141, 8, 162, 1, // Opcode: NLZC_D
/* 9595 */    MCD_OPC_FilterValue, 25, 158, 12, // Skip to: 12829
/* 9599 */    MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 9602 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 9615
/* 9606 */    MCD_OPC_CheckPredicate, 4, 147, 12, // Skip to: 12829
/* 9610 */    MCD_OPC_Decode, 164, 4, 161, 1, // Opcode: FCLASS_W
/* 9615 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 9628
/* 9619 */    MCD_OPC_CheckPredicate, 4, 134, 12, // Skip to: 12829
/* 9623 */    MCD_OPC_Decode, 163, 4, 162, 1, // Opcode: FCLASS_D
/* 9628 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 9641
/* 9632 */    MCD_OPC_CheckPredicate, 4, 121, 12, // Skip to: 12829
/* 9636 */    MCD_OPC_Decode, 178, 5, 161, 1, // Opcode: FTRUNC_S_W
/* 9641 */    MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 9654
/* 9645 */    MCD_OPC_CheckPredicate, 4, 108, 12, // Skip to: 12829
/* 9649 */    MCD_OPC_Decode, 177, 5, 162, 1, // Opcode: FTRUNC_S_D
/* 9654 */    MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 9667
/* 9658 */    MCD_OPC_CheckPredicate, 4, 95, 12, // Skip to: 12829
/* 9662 */    MCD_OPC_Decode, 180, 5, 161, 1, // Opcode: FTRUNC_U_W
/* 9667 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 9680
/* 9671 */    MCD_OPC_CheckPredicate, 4, 82, 12, // Skip to: 12829
/* 9675 */    MCD_OPC_Decode, 179, 5, 162, 1, // Opcode: FTRUNC_U_D
/* 9680 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 9693
/* 9684 */    MCD_OPC_CheckPredicate, 4, 69, 12, // Skip to: 12829
/* 9688 */    MCD_OPC_Decode, 153, 5, 161, 1, // Opcode: FSQRT_W
/* 9693 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 9706
/* 9697 */    MCD_OPC_CheckPredicate, 4, 56, 12, // Skip to: 12829
/* 9701 */    MCD_OPC_Decode, 147, 5, 162, 1, // Opcode: FSQRT_D
/* 9706 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 9719
/* 9710 */    MCD_OPC_CheckPredicate, 4, 43, 12, // Skip to: 12829
/* 9714 */    MCD_OPC_Decode, 134, 5, 161, 1, // Opcode: FRSQRT_W
/* 9719 */    MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 9732
/* 9723 */    MCD_OPC_CheckPredicate, 4, 30, 12, // Skip to: 12829
/* 9727 */    MCD_OPC_Decode, 133, 5, 162, 1, // Opcode: FRSQRT_D
/* 9732 */    MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 9745
/* 9736 */    MCD_OPC_CheckPredicate, 4, 17, 12, // Skip to: 12829
/* 9740 */    MCD_OPC_Decode, 130, 5, 161, 1, // Opcode: FRCP_W
/* 9745 */    MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 9758
/* 9749 */    MCD_OPC_CheckPredicate, 4, 4, 12, // Skip to: 12829
/* 9753 */    MCD_OPC_Decode, 129, 5, 162, 1, // Opcode: FRCP_D
/* 9758 */    MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 9771
/* 9762 */    MCD_OPC_CheckPredicate, 4, 247, 11, // Skip to: 12829
/* 9766 */    MCD_OPC_Decode, 132, 5, 161, 1, // Opcode: FRINT_W
/* 9771 */    MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 9784
/* 9775 */    MCD_OPC_CheckPredicate, 4, 234, 11, // Skip to: 12829
/* 9779 */    MCD_OPC_Decode, 131, 5, 162, 1, // Opcode: FRINT_D
/* 9784 */    MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 9797
/* 9788 */    MCD_OPC_CheckPredicate, 4, 221, 11, // Skip to: 12829
/* 9792 */    MCD_OPC_Decode, 220, 4, 161, 1, // Opcode: FLOG2_W
/* 9797 */    MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 9810
/* 9801 */    MCD_OPC_CheckPredicate, 4, 208, 11, // Skip to: 12829
/* 9805 */    MCD_OPC_Decode, 219, 4, 162, 1, // Opcode: FLOG2_D
/* 9810 */    MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 9823
/* 9814 */    MCD_OPC_CheckPredicate, 4, 195, 11, // Skip to: 12829
/* 9818 */    MCD_OPC_Decode, 202, 4, 163, 1, // Opcode: FEXUPL_W
/* 9823 */    MCD_OPC_FilterValue, 17, 9, 0, // Skip to: 9836
/* 9827 */    MCD_OPC_CheckPredicate, 4, 182, 11, // Skip to: 12829
/* 9831 */    MCD_OPC_Decode, 201, 4, 164, 1, // Opcode: FEXUPL_D
/* 9836 */    MCD_OPC_FilterValue, 18, 9, 0, // Skip to: 9849
/* 9840 */    MCD_OPC_CheckPredicate, 4, 169, 11, // Skip to: 12829
/* 9844 */    MCD_OPC_Decode, 204, 4, 163, 1, // Opcode: FEXUPR_W
/* 9849 */    MCD_OPC_FilterValue, 19, 9, 0, // Skip to: 9862
/* 9853 */    MCD_OPC_CheckPredicate, 4, 156, 11, // Skip to: 12829
/* 9857 */    MCD_OPC_Decode, 203, 4, 164, 1, // Opcode: FEXUPR_D
/* 9862 */    MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 9875
/* 9866 */    MCD_OPC_CheckPredicate, 4, 143, 11, // Skip to: 12829
/* 9870 */    MCD_OPC_Decode, 210, 4, 163, 1, // Opcode: FFQL_W
/* 9875 */    MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 9888
/* 9879 */    MCD_OPC_CheckPredicate, 4, 130, 11, // Skip to: 12829
/* 9883 */    MCD_OPC_Decode, 209, 4, 164, 1, // Opcode: FFQL_D
/* 9888 */    MCD_OPC_FilterValue, 22, 9, 0, // Skip to: 9901
/* 9892 */    MCD_OPC_CheckPredicate, 4, 117, 11, // Skip to: 12829
/* 9896 */    MCD_OPC_Decode, 212, 4, 163, 1, // Opcode: FFQR_W
/* 9901 */    MCD_OPC_FilterValue, 23, 9, 0, // Skip to: 9914
/* 9905 */    MCD_OPC_CheckPredicate, 4, 104, 11, // Skip to: 12829
/* 9909 */    MCD_OPC_Decode, 211, 4, 164, 1, // Opcode: FFQR_D
/* 9914 */    MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 9927
/* 9918 */    MCD_OPC_CheckPredicate, 4, 91, 11, // Skip to: 12829
/* 9922 */    MCD_OPC_Decode, 172, 5, 161, 1, // Opcode: FTINT_S_W
/* 9927 */    MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 9940
/* 9931 */    MCD_OPC_CheckPredicate, 4, 78, 11, // Skip to: 12829
/* 9935 */    MCD_OPC_Decode, 171, 5, 162, 1, // Opcode: FTINT_S_D
/* 9940 */    MCD_OPC_FilterValue, 26, 9, 0, // Skip to: 9953
/* 9944 */    MCD_OPC_CheckPredicate, 4, 65, 11, // Skip to: 12829
/* 9948 */    MCD_OPC_Decode, 174, 5, 161, 1, // Opcode: FTINT_U_W
/* 9953 */    MCD_OPC_FilterValue, 27, 9, 0, // Skip to: 9966
/* 9957 */    MCD_OPC_CheckPredicate, 4, 52, 11, // Skip to: 12829
/* 9961 */    MCD_OPC_Decode, 173, 5, 162, 1, // Opcode: FTINT_U_D
/* 9966 */    MCD_OPC_FilterValue, 28, 9, 0, // Skip to: 9979
/* 9970 */    MCD_OPC_CheckPredicate, 4, 39, 11, // Skip to: 12829
/* 9974 */    MCD_OPC_Decode, 206, 4, 161, 1, // Opcode: FFINT_S_W
/* 9979 */    MCD_OPC_FilterValue, 29, 9, 0, // Skip to: 9992
/* 9983 */    MCD_OPC_CheckPredicate, 4, 26, 11, // Skip to: 12829
/* 9987 */    MCD_OPC_Decode, 205, 4, 162, 1, // Opcode: FFINT_S_D
/* 9992 */    MCD_OPC_FilterValue, 30, 9, 0, // Skip to: 10005
/* 9996 */    MCD_OPC_CheckPredicate, 4, 13, 11, // Skip to: 12829
/* 10000 */   MCD_OPC_Decode, 208, 4, 161, 1, // Opcode: FFINT_U_W
/* 10005 */   MCD_OPC_FilterValue, 31, 4, 11, // Skip to: 12829
/* 10009 */   MCD_OPC_CheckPredicate, 4, 0, 11, // Skip to: 12829
/* 10013 */   MCD_OPC_Decode, 207, 4, 162, 1, // Opcode: FFINT_U_D
/* 10018 */   MCD_OPC_FilterValue, 32, 9, 0, // Skip to: 10031
/* 10022 */   MCD_OPC_CheckPredicate, 4, 243, 10, // Skip to: 12829
/* 10026 */   MCD_OPC_Decode, 133, 6, 165, 1, // Opcode: LD_B
/* 10031 */   MCD_OPC_FilterValue, 33, 9, 0, // Skip to: 10044
/* 10035 */   MCD_OPC_CheckPredicate, 4, 230, 10, // Skip to: 12829
/* 10039 */   MCD_OPC_Decode, 135, 6, 165, 1, // Opcode: LD_H
/* 10044 */   MCD_OPC_FilterValue, 34, 9, 0, // Skip to: 10057
/* 10048 */   MCD_OPC_CheckPredicate, 4, 217, 10, // Skip to: 12829
/* 10052 */   MCD_OPC_Decode, 136, 6, 165, 1, // Opcode: LD_W
/* 10057 */   MCD_OPC_FilterValue, 35, 9, 0, // Skip to: 10070
/* 10061 */   MCD_OPC_CheckPredicate, 4, 204, 10, // Skip to: 12829
/* 10065 */   MCD_OPC_Decode, 134, 6, 165, 1, // Opcode: LD_D
/* 10070 */   MCD_OPC_FilterValue, 36, 9, 0, // Skip to: 10083
/* 10074 */   MCD_OPC_CheckPredicate, 4, 191, 10, // Skip to: 12829
/* 10078 */   MCD_OPC_Decode, 163, 10, 165, 1, // Opcode: ST_B
/* 10083 */   MCD_OPC_FilterValue, 37, 9, 0, // Skip to: 10096
/* 10087 */   MCD_OPC_CheckPredicate, 4, 178, 10, // Skip to: 12829
/* 10091 */   MCD_OPC_Decode, 165, 10, 165, 1, // Opcode: ST_H
/* 10096 */   MCD_OPC_FilterValue, 38, 9, 0, // Skip to: 10109
/* 10100 */   MCD_OPC_CheckPredicate, 4, 165, 10, // Skip to: 12829
/* 10104 */   MCD_OPC_Decode, 166, 10, 165, 1, // Opcode: ST_W
/* 10109 */   MCD_OPC_FilterValue, 39, 156, 10, // Skip to: 12829
/* 10113 */   MCD_OPC_CheckPredicate, 4, 152, 10, // Skip to: 12829
/* 10117 */   MCD_OPC_Decode, 164, 10, 165, 1, // Opcode: ST_D
/* 10122 */   MCD_OPC_FilterValue, 31, 113, 9, // Skip to: 12543
/* 10126 */   MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10129 */   MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 10142
/* 10133 */   MCD_OPC_CheckPredicate, 3, 132, 10, // Skip to: 12829
/* 10137 */   MCD_OPC_Decode, 129, 4, 166, 1, // Opcode: EXT
/* 10142 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 10155
/* 10146 */   MCD_OPC_CheckPredicate, 3, 119, 10, // Skip to: 12829
/* 10150 */   MCD_OPC_Decode, 210, 5, 167, 1, // Opcode: INS
/* 10155 */   MCD_OPC_FilterValue, 10, 42, 0, // Skip to: 10201
/* 10159 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 10162 */   MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 10175
/* 10166 */   MCD_OPC_CheckPredicate, 5, 99, 10, // Skip to: 12829
/* 10170 */   MCD_OPC_Decode, 173, 6, 168, 1, // Opcode: LWX
/* 10175 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 10188
/* 10179 */   MCD_OPC_CheckPredicate, 5, 86, 10, // Skip to: 12829
/* 10183 */   MCD_OPC_Decode, 142, 6, 168, 1, // Opcode: LHX
/* 10188 */   MCD_OPC_FilterValue, 6, 77, 10, // Skip to: 12829
/* 10192 */   MCD_OPC_CheckPredicate, 5, 73, 10, // Skip to: 12829
/* 10196 */   MCD_OPC_Decode, 243, 5, 168, 1, // Opcode: LBUX
/* 10201 */   MCD_OPC_FilterValue, 12, 15, 0, // Skip to: 10220
/* 10205 */   MCD_OPC_CheckPredicate, 5, 60, 10, // Skip to: 12829
/* 10209 */   MCD_OPC_CheckField, 6, 10, 0, 54, 10, // Skip to: 12829
/* 10215 */   MCD_OPC_Decode, 217, 5, 169, 1, // Opcode: INSV
/* 10220 */   MCD_OPC_FilterValue, 16, 51, 1, // Skip to: 10531
/* 10224 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 10227 */   MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 10239
/* 10231 */   MCD_OPC_CheckPredicate, 5, 34, 10, // Skip to: 12829
/* 10235 */   MCD_OPC_Decode, 46, 170, 1, // Opcode: ADDU_QB
/* 10239 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 10252
/* 10243 */   MCD_OPC_CheckPredicate, 5, 22, 10, // Skip to: 12829
/* 10247 */   MCD_OPC_Decode, 194, 10, 170, 1, // Opcode: SUBU_QB
/* 10252 */   MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 10264
/* 10256 */   MCD_OPC_CheckPredicate, 5, 9, 10, // Skip to: 12829
/* 10260 */   MCD_OPC_Decode, 48, 170, 1, // Opcode: ADDU_S_QB
/* 10264 */   MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 10277
/* 10268 */   MCD_OPC_CheckPredicate, 5, 253, 9, // Skip to: 12829
/* 10272 */   MCD_OPC_Decode, 196, 10, 170, 1, // Opcode: SUBU_S_QB
/* 10277 */   MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 10290
/* 10281 */   MCD_OPC_CheckPredicate, 5, 240, 9, // Skip to: 12829
/* 10285 */   MCD_OPC_Decode, 231, 7, 170, 1, // Opcode: MULEU_S_PH_QBL
/* 10290 */   MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 10303
/* 10294 */   MCD_OPC_CheckPredicate, 5, 227, 9, // Skip to: 12829
/* 10298 */   MCD_OPC_Decode, 232, 7, 170, 1, // Opcode: MULEU_S_PH_QBR
/* 10303 */   MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 10315
/* 10307 */   MCD_OPC_CheckPredicate, 15, 214, 9, // Skip to: 12829
/* 10311 */   MCD_OPC_Decode, 45, 170, 1, // Opcode: ADDU_PH
/* 10315 */   MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 10328
/* 10319 */   MCD_OPC_CheckPredicate, 15, 202, 9, // Skip to: 12829
/* 10323 */   MCD_OPC_Decode, 193, 10, 170, 1, // Opcode: SUBU_PH
/* 10328 */   MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 10340
/* 10332 */   MCD_OPC_CheckPredicate, 5, 189, 9, // Skip to: 12829
/* 10336 */   MCD_OPC_Decode, 27, 170, 1, // Opcode: ADDQ_PH
/* 10340 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 10353
/* 10344 */   MCD_OPC_CheckPredicate, 5, 177, 9, // Skip to: 12829
/* 10348 */   MCD_OPC_Decode, 172, 10, 170, 1, // Opcode: SUBQ_PH
/* 10353 */   MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 10365
/* 10357 */   MCD_OPC_CheckPredicate, 15, 164, 9, // Skip to: 12829
/* 10361 */   MCD_OPC_Decode, 47, 170, 1, // Opcode: ADDU_S_PH
/* 10365 */   MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 10378
/* 10369 */   MCD_OPC_CheckPredicate, 15, 152, 9, // Skip to: 12829
/* 10373 */   MCD_OPC_Decode, 195, 10, 170, 1, // Opcode: SUBU_S_PH
/* 10378 */   MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 10390
/* 10382 */   MCD_OPC_CheckPredicate, 5, 139, 9, // Skip to: 12829
/* 10386 */   MCD_OPC_Decode, 28, 170, 1, // Opcode: ADDQ_S_PH
/* 10390 */   MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 10403
/* 10394 */   MCD_OPC_CheckPredicate, 5, 127, 9, // Skip to: 12829
/* 10398 */   MCD_OPC_Decode, 173, 10, 170, 1, // Opcode: SUBQ_S_PH
/* 10403 */   MCD_OPC_FilterValue, 16, 7, 0, // Skip to: 10414
/* 10407 */   MCD_OPC_CheckPredicate, 5, 114, 9, // Skip to: 12829
/* 10411 */   MCD_OPC_Decode, 30, 13, // Opcode: ADDSC
/* 10414 */   MCD_OPC_FilterValue, 17, 7, 0, // Skip to: 10425
/* 10418 */   MCD_OPC_CheckPredicate, 5, 103, 9, // Skip to: 12829
/* 10422 */   MCD_OPC_Decode, 57, 13, // Opcode: ADDWC
/* 10425 */   MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 10437
/* 10429 */   MCD_OPC_CheckPredicate, 5, 92, 9, // Skip to: 12829
/* 10433 */   MCD_OPC_Decode, 144, 7, 13, // Opcode: MODSUB
/* 10437 */   MCD_OPC_FilterValue, 20, 15, 0, // Skip to: 10456
/* 10441 */   MCD_OPC_CheckPredicate, 5, 80, 9, // Skip to: 12829
/* 10445 */   MCD_OPC_CheckField, 16, 5, 0, 74, 9, // Skip to: 12829
/* 10451 */   MCD_OPC_Decode, 242, 8, 171, 1, // Opcode: RADDU_W_QB
/* 10456 */   MCD_OPC_FilterValue, 22, 7, 0, // Skip to: 10467
/* 10460 */   MCD_OPC_CheckPredicate, 5, 61, 9, // Skip to: 12829
/* 10464 */   MCD_OPC_Decode, 29, 13, // Opcode: ADDQ_S_W
/* 10467 */   MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 10479
/* 10471 */   MCD_OPC_CheckPredicate, 5, 50, 9, // Skip to: 12829
/* 10475 */   MCD_OPC_Decode, 174, 10, 13, // Opcode: SUBQ_S_W
/* 10479 */   MCD_OPC_FilterValue, 28, 9, 0, // Skip to: 10492
/* 10483 */   MCD_OPC_CheckPredicate, 5, 38, 9, // Skip to: 12829
/* 10487 */   MCD_OPC_Decode, 229, 7, 172, 1, // Opcode: MULEQ_S_W_PHL
/* 10492 */   MCD_OPC_FilterValue, 29, 9, 0, // Skip to: 10505
/* 10496 */   MCD_OPC_CheckPredicate, 5, 25, 9, // Skip to: 12829
/* 10500 */   MCD_OPC_Decode, 230, 7, 172, 1, // Opcode: MULEQ_S_W_PHR
/* 10505 */   MCD_OPC_FilterValue, 30, 9, 0, // Skip to: 10518
/* 10509 */   MCD_OPC_CheckPredicate, 15, 12, 9, // Skip to: 12829
/* 10513 */   MCD_OPC_Decode, 235, 7, 170, 1, // Opcode: MULQ_S_PH
/* 10518 */   MCD_OPC_FilterValue, 31, 3, 9, // Skip to: 12829
/* 10522 */   MCD_OPC_CheckPredicate, 5, 255, 8, // Skip to: 12829
/* 10526 */   MCD_OPC_Decode, 233, 7, 170, 1, // Opcode: MULQ_RS_PH
/* 10531 */   MCD_OPC_FilterValue, 17, 69, 1, // Skip to: 10860
/* 10535 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 10538 */   MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 10557
/* 10542 */   MCD_OPC_CheckPredicate, 5, 235, 8, // Skip to: 12829
/* 10546 */   MCD_OPC_CheckField, 11, 5, 0, 229, 8, // Skip to: 12829
/* 10552 */   MCD_OPC_Decode, 200, 2, 173, 1, // Opcode: CMPU_EQ_QB
/* 10557 */   MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 10576
/* 10561 */   MCD_OPC_CheckPredicate, 5, 216, 8, // Skip to: 12829
/* 10565 */   MCD_OPC_CheckField, 11, 5, 0, 210, 8, // Skip to: 12829
/* 10571 */   MCD_OPC_Decode, 202, 2, 173, 1, // Opcode: CMPU_LT_QB
/* 10576 */   MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 10595
/* 10580 */   MCD_OPC_CheckPredicate, 5, 197, 8, // Skip to: 12829
/* 10584 */   MCD_OPC_CheckField, 11, 5, 0, 191, 8, // Skip to: 12829
/* 10590 */   MCD_OPC_Decode, 201, 2, 173, 1, // Opcode: CMPU_LE_QB
/* 10595 */   MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 10608
/* 10599 */   MCD_OPC_CheckPredicate, 5, 178, 8, // Skip to: 12829
/* 10603 */   MCD_OPC_Decode, 191, 8, 170, 1, // Opcode: PICK_QB
/* 10608 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 10621
/* 10612 */   MCD_OPC_CheckPredicate, 5, 165, 8, // Skip to: 12829
/* 10616 */   MCD_OPC_Decode, 197, 2, 172, 1, // Opcode: CMPGU_EQ_QB
/* 10621 */   MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 10634
/* 10625 */   MCD_OPC_CheckPredicate, 5, 152, 8, // Skip to: 12829
/* 10629 */   MCD_OPC_Decode, 199, 2, 172, 1, // Opcode: CMPGU_LT_QB
/* 10634 */   MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 10647
/* 10638 */   MCD_OPC_CheckPredicate, 5, 139, 8, // Skip to: 12829
/* 10642 */   MCD_OPC_Decode, 198, 2, 172, 1, // Opcode: CMPGU_LE_QB
/* 10647 */   MCD_OPC_FilterValue, 8, 15, 0, // Skip to: 10666
/* 10651 */   MCD_OPC_CheckPredicate, 5, 126, 8, // Skip to: 12829
/* 10655 */   MCD_OPC_CheckField, 11, 5, 0, 120, 8, // Skip to: 12829
/* 10661 */   MCD_OPC_Decode, 203, 2, 173, 1, // Opcode: CMP_EQ_PH
/* 10666 */   MCD_OPC_FilterValue, 9, 15, 0, // Skip to: 10685
/* 10670 */   MCD_OPC_CheckPredicate, 5, 107, 8, // Skip to: 12829
/* 10674 */   MCD_OPC_CheckField, 11, 5, 0, 101, 8, // Skip to: 12829
/* 10680 */   MCD_OPC_Decode, 205, 2, 173, 1, // Opcode: CMP_LT_PH
/* 10685 */   MCD_OPC_FilterValue, 10, 15, 0, // Skip to: 10704
/* 10689 */   MCD_OPC_CheckPredicate, 5, 88, 8, // Skip to: 12829
/* 10693 */   MCD_OPC_CheckField, 11, 5, 0, 82, 8, // Skip to: 12829
/* 10699 */   MCD_OPC_Decode, 204, 2, 173, 1, // Opcode: CMP_LE_PH
/* 10704 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 10717
/* 10708 */   MCD_OPC_CheckPredicate, 5, 69, 8, // Skip to: 12829
/* 10712 */   MCD_OPC_Decode, 190, 8, 170, 1, // Opcode: PICK_PH
/* 10717 */   MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 10730
/* 10721 */   MCD_OPC_CheckPredicate, 5, 56, 8, // Skip to: 12829
/* 10725 */   MCD_OPC_Decode, 204, 8, 170, 1, // Opcode: PRECRQ_QB_PH
/* 10730 */   MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 10743
/* 10734 */   MCD_OPC_CheckPredicate, 15, 43, 8, // Skip to: 12829
/* 10738 */   MCD_OPC_Decode, 206, 8, 170, 1, // Opcode: PRECR_QB_PH
/* 10743 */   MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 10756
/* 10747 */   MCD_OPC_CheckPredicate, 5, 30, 8, // Skip to: 12829
/* 10751 */   MCD_OPC_Decode, 177, 8, 170, 1, // Opcode: PACKRL_PH
/* 10756 */   MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 10769
/* 10760 */   MCD_OPC_CheckPredicate, 5, 17, 8, // Skip to: 12829
/* 10764 */   MCD_OPC_Decode, 202, 8, 170, 1, // Opcode: PRECRQU_S_QB_PH
/* 10769 */   MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 10782
/* 10773 */   MCD_OPC_CheckPredicate, 5, 4, 8, // Skip to: 12829
/* 10777 */   MCD_OPC_Decode, 203, 8, 174, 1, // Opcode: PRECRQ_PH_W
/* 10782 */   MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 10795
/* 10786 */   MCD_OPC_CheckPredicate, 5, 247, 7, // Skip to: 12829
/* 10790 */   MCD_OPC_Decode, 205, 8, 174, 1, // Opcode: PRECRQ_RS_PH_W
/* 10795 */   MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 10808
/* 10799 */   MCD_OPC_CheckPredicate, 15, 234, 7, // Skip to: 12829
/* 10803 */   MCD_OPC_Decode, 194, 2, 172, 1, // Opcode: CMPGDU_EQ_QB
/* 10808 */   MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 10821
/* 10812 */   MCD_OPC_CheckPredicate, 15, 221, 7, // Skip to: 12829
/* 10816 */   MCD_OPC_Decode, 196, 2, 172, 1, // Opcode: CMPGDU_LT_QB
/* 10821 */   MCD_OPC_FilterValue, 26, 9, 0, // Skip to: 10834
/* 10825 */   MCD_OPC_CheckPredicate, 15, 208, 7, // Skip to: 12829
/* 10829 */   MCD_OPC_Decode, 195, 2, 172, 1, // Opcode: CMPGDU_LE_QB
/* 10834 */   MCD_OPC_FilterValue, 30, 9, 0, // Skip to: 10847
/* 10838 */   MCD_OPC_CheckPredicate, 15, 195, 7, // Skip to: 12829
/* 10842 */   MCD_OPC_Decode, 207, 8, 175, 1, // Opcode: PRECR_SRA_PH_W
/* 10847 */   MCD_OPC_FilterValue, 31, 186, 7, // Skip to: 12829
/* 10851 */   MCD_OPC_CheckPredicate, 15, 182, 7, // Skip to: 12829
/* 10855 */   MCD_OPC_Decode, 208, 8, 175, 1, // Opcode: PRECR_SRA_R_PH_W
/* 10860 */   MCD_OPC_FilterValue, 18, 74, 1, // Skip to: 11194
/* 10864 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 10867 */   MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 10885
/* 10871 */   MCD_OPC_CheckPredicate, 15, 162, 7, // Skip to: 12829
/* 10875 */   MCD_OPC_CheckField, 21, 5, 0, 156, 7, // Skip to: 12829
/* 10881 */   MCD_OPC_Decode, 20, 176, 1, // Opcode: ABSQ_S_QB
/* 10885 */   MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 10898
/* 10889 */   MCD_OPC_CheckPredicate, 5, 144, 7, // Skip to: 12829
/* 10893 */   MCD_OPC_Decode, 249, 8, 177, 1, // Opcode: REPL_QB
/* 10898 */   MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 10917
/* 10902 */   MCD_OPC_CheckPredicate, 5, 131, 7, // Skip to: 12829
/* 10906 */   MCD_OPC_CheckField, 21, 5, 0, 125, 7, // Skip to: 12829
/* 10912 */   MCD_OPC_Decode, 247, 8, 178, 1, // Opcode: REPLV_QB
/* 10917 */   MCD_OPC_FilterValue, 4, 15, 0, // Skip to: 10936
/* 10921 */   MCD_OPC_CheckPredicate, 5, 112, 7, // Skip to: 12829
/* 10925 */   MCD_OPC_CheckField, 21, 5, 0, 106, 7, // Skip to: 12829
/* 10931 */   MCD_OPC_Decode, 192, 8, 176, 1, // Opcode: PRECEQU_PH_QBL
/* 10936 */   MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 10955
/* 10940 */   MCD_OPC_CheckPredicate, 5, 93, 7, // Skip to: 12829
/* 10944 */   MCD_OPC_CheckField, 21, 5, 0, 87, 7, // Skip to: 12829
/* 10950 */   MCD_OPC_Decode, 194, 8, 176, 1, // Opcode: PRECEQU_PH_QBR
/* 10955 */   MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 10974
/* 10959 */   MCD_OPC_CheckPredicate, 5, 74, 7, // Skip to: 12829
/* 10963 */   MCD_OPC_CheckField, 21, 5, 0, 68, 7, // Skip to: 12829
/* 10969 */   MCD_OPC_Decode, 193, 8, 176, 1, // Opcode: PRECEQU_PH_QBLA
/* 10974 */   MCD_OPC_FilterValue, 7, 15, 0, // Skip to: 10993
/* 10978 */   MCD_OPC_CheckPredicate, 5, 55, 7, // Skip to: 12829
/* 10982 */   MCD_OPC_CheckField, 21, 5, 0, 49, 7, // Skip to: 12829
/* 10988 */   MCD_OPC_Decode, 195, 8, 176, 1, // Opcode: PRECEQU_PH_QBRA
/* 10993 */   MCD_OPC_FilterValue, 9, 14, 0, // Skip to: 11011
/* 10997 */   MCD_OPC_CheckPredicate, 5, 36, 7, // Skip to: 12829
/* 11001 */   MCD_OPC_CheckField, 21, 5, 0, 30, 7, // Skip to: 12829
/* 11007 */   MCD_OPC_Decode, 19, 176, 1, // Opcode: ABSQ_S_PH
/* 11011 */   MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 11024
/* 11015 */   MCD_OPC_CheckPredicate, 5, 18, 7, // Skip to: 12829
/* 11019 */   MCD_OPC_Decode, 248, 8, 177, 1, // Opcode: REPL_PH
/* 11024 */   MCD_OPC_FilterValue, 11, 15, 0, // Skip to: 11043
/* 11028 */   MCD_OPC_CheckPredicate, 5, 5, 7, // Skip to: 12829
/* 11032 */   MCD_OPC_CheckField, 21, 5, 0, 255, 6, // Skip to: 12829
/* 11038 */   MCD_OPC_Decode, 246, 8, 178, 1, // Opcode: REPLV_PH
/* 11043 */   MCD_OPC_FilterValue, 12, 15, 0, // Skip to: 11062
/* 11047 */   MCD_OPC_CheckPredicate, 5, 242, 6, // Skip to: 12829
/* 11051 */   MCD_OPC_CheckField, 21, 5, 0, 236, 6, // Skip to: 12829
/* 11057 */   MCD_OPC_Decode, 196, 8, 179, 1, // Opcode: PRECEQ_W_PHL
/* 11062 */   MCD_OPC_FilterValue, 13, 15, 0, // Skip to: 11081
/* 11066 */   MCD_OPC_CheckPredicate, 5, 223, 6, // Skip to: 12829
/* 11070 */   MCD_OPC_CheckField, 21, 5, 0, 217, 6, // Skip to: 12829
/* 11076 */   MCD_OPC_Decode, 197, 8, 179, 1, // Opcode: PRECEQ_W_PHR
/* 11081 */   MCD_OPC_FilterValue, 17, 14, 0, // Skip to: 11099
/* 11085 */   MCD_OPC_CheckPredicate, 5, 204, 6, // Skip to: 12829
/* 11089 */   MCD_OPC_CheckField, 21, 5, 0, 198, 6, // Skip to: 12829
/* 11095 */   MCD_OPC_Decode, 21, 180, 1, // Opcode: ABSQ_S_W
/* 11099 */   MCD_OPC_FilterValue, 27, 15, 0, // Skip to: 11118
/* 11103 */   MCD_OPC_CheckPredicate, 5, 186, 6, // Skip to: 12829
/* 11107 */   MCD_OPC_CheckField, 21, 5, 0, 180, 6, // Skip to: 12829
/* 11113 */   MCD_OPC_Decode, 190, 1, 180, 1, // Opcode: BITREV
/* 11118 */   MCD_OPC_FilterValue, 28, 15, 0, // Skip to: 11137
/* 11122 */   MCD_OPC_CheckPredicate, 5, 167, 6, // Skip to: 12829
/* 11126 */   MCD_OPC_CheckField, 21, 5, 0, 161, 6, // Skip to: 12829
/* 11132 */   MCD_OPC_Decode, 198, 8, 176, 1, // Opcode: PRECEU_PH_QBL
/* 11137 */   MCD_OPC_FilterValue, 29, 15, 0, // Skip to: 11156
/* 11141 */   MCD_OPC_CheckPredicate, 5, 148, 6, // Skip to: 12829
/* 11145 */   MCD_OPC_CheckField, 21, 5, 0, 142, 6, // Skip to: 12829
/* 11151 */   MCD_OPC_Decode, 200, 8, 176, 1, // Opcode: PRECEU_PH_QBR
/* 11156 */   MCD_OPC_FilterValue, 30, 15, 0, // Skip to: 11175
/* 11160 */   MCD_OPC_CheckPredicate, 5, 129, 6, // Skip to: 12829
/* 11164 */   MCD_OPC_CheckField, 21, 5, 0, 123, 6, // Skip to: 12829
/* 11170 */   MCD_OPC_Decode, 199, 8, 176, 1, // Opcode: PRECEU_PH_QBLA
/* 11175 */   MCD_OPC_FilterValue, 31, 114, 6, // Skip to: 12829
/* 11179 */   MCD_OPC_CheckPredicate, 5, 110, 6, // Skip to: 12829
/* 11183 */   MCD_OPC_CheckField, 21, 5, 0, 104, 6, // Skip to: 12829
/* 11189 */   MCD_OPC_Decode, 201, 8, 176, 1, // Opcode: PRECEU_PH_QBRA
/* 11194 */   MCD_OPC_FilterValue, 19, 31, 1, // Skip to: 11485
/* 11198 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11201 */   MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 11214
/* 11205 */   MCD_OPC_CheckPredicate, 5, 84, 6, // Skip to: 12829
/* 11209 */   MCD_OPC_Decode, 182, 9, 181, 1, // Opcode: SHLL_QB
/* 11214 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 11227
/* 11218 */   MCD_OPC_CheckPredicate, 5, 71, 6, // Skip to: 12829
/* 11222 */   MCD_OPC_Decode, 198, 9, 181, 1, // Opcode: SHRL_QB
/* 11227 */   MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 11240
/* 11231 */   MCD_OPC_CheckPredicate, 5, 58, 6, // Skip to: 12829
/* 11235 */   MCD_OPC_Decode, 178, 9, 182, 1, // Opcode: SHLLV_QB
/* 11240 */   MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 11253
/* 11244 */   MCD_OPC_CheckPredicate, 5, 45, 6, // Skip to: 12829
/* 11248 */   MCD_OPC_Decode, 196, 9, 182, 1, // Opcode: SHRLV_QB
/* 11253 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 11266
/* 11257 */   MCD_OPC_CheckPredicate, 15, 32, 6, // Skip to: 12829
/* 11261 */   MCD_OPC_Decode, 191, 9, 181, 1, // Opcode: SHRA_QB
/* 11266 */   MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 11279
/* 11270 */   MCD_OPC_CheckPredicate, 15, 19, 6, // Skip to: 12829
/* 11274 */   MCD_OPC_Decode, 193, 9, 181, 1, // Opcode: SHRA_R_QB
/* 11279 */   MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 11292
/* 11283 */   MCD_OPC_CheckPredicate, 15, 6, 6, // Skip to: 12829
/* 11287 */   MCD_OPC_Decode, 186, 9, 182, 1, // Opcode: SHRAV_QB
/* 11292 */   MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 11305
/* 11296 */   MCD_OPC_CheckPredicate, 15, 249, 5, // Skip to: 12829
/* 11300 */   MCD_OPC_Decode, 188, 9, 182, 1, // Opcode: SHRAV_R_QB
/* 11305 */   MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 11318
/* 11309 */   MCD_OPC_CheckPredicate, 5, 236, 5, // Skip to: 12829
/* 11313 */   MCD_OPC_Decode, 181, 9, 181, 1, // Opcode: SHLL_PH
/* 11318 */   MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 11331
/* 11322 */   MCD_OPC_CheckPredicate, 5, 223, 5, // Skip to: 12829
/* 11326 */   MCD_OPC_Decode, 190, 9, 181, 1, // Opcode: SHRA_PH
/* 11331 */   MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 11344
/* 11335 */   MCD_OPC_CheckPredicate, 5, 210, 5, // Skip to: 12829
/* 11339 */   MCD_OPC_Decode, 177, 9, 182, 1, // Opcode: SHLLV_PH
/* 11344 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 11357
/* 11348 */   MCD_OPC_CheckPredicate, 5, 197, 5, // Skip to: 12829
/* 11352 */   MCD_OPC_Decode, 185, 9, 182, 1, // Opcode: SHRAV_PH
/* 11357 */   MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 11370
/* 11361 */   MCD_OPC_CheckPredicate, 5, 184, 5, // Skip to: 12829
/* 11365 */   MCD_OPC_Decode, 183, 9, 181, 1, // Opcode: SHLL_S_PH
/* 11370 */   MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 11383
/* 11374 */   MCD_OPC_CheckPredicate, 5, 171, 5, // Skip to: 12829
/* 11378 */   MCD_OPC_Decode, 192, 9, 181, 1, // Opcode: SHRA_R_PH
/* 11383 */   MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 11396
/* 11387 */   MCD_OPC_CheckPredicate, 5, 158, 5, // Skip to: 12829
/* 11391 */   MCD_OPC_Decode, 179, 9, 182, 1, // Opcode: SHLLV_S_PH
/* 11396 */   MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 11409
/* 11400 */   MCD_OPC_CheckPredicate, 5, 145, 5, // Skip to: 12829
/* 11404 */   MCD_OPC_Decode, 187, 9, 182, 1, // Opcode: SHRAV_R_PH
/* 11409 */   MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 11422
/* 11413 */   MCD_OPC_CheckPredicate, 5, 132, 5, // Skip to: 12829
/* 11417 */   MCD_OPC_Decode, 184, 9, 183, 1, // Opcode: SHLL_S_W
/* 11422 */   MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 11435
/* 11426 */   MCD_OPC_CheckPredicate, 5, 119, 5, // Skip to: 12829
/* 11430 */   MCD_OPC_Decode, 194, 9, 183, 1, // Opcode: SHRA_R_W
/* 11435 */   MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 11447
/* 11439 */   MCD_OPC_CheckPredicate, 5, 106, 5, // Skip to: 12829
/* 11443 */   MCD_OPC_Decode, 180, 9, 14, // Opcode: SHLLV_S_W
/* 11447 */   MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 11459
/* 11451 */   MCD_OPC_CheckPredicate, 5, 94, 5, // Skip to: 12829
/* 11455 */   MCD_OPC_Decode, 189, 9, 14, // Opcode: SHRAV_R_W
/* 11459 */   MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 11472
/* 11463 */   MCD_OPC_CheckPredicate, 15, 82, 5, // Skip to: 12829
/* 11467 */   MCD_OPC_Decode, 197, 9, 181, 1, // Opcode: SHRL_PH
/* 11472 */   MCD_OPC_FilterValue, 27, 73, 5, // Skip to: 12829
/* 11476 */   MCD_OPC_CheckPredicate, 15, 69, 5, // Skip to: 12829
/* 11480 */   MCD_OPC_Decode, 195, 9, 182, 1, // Opcode: SHRLV_PH
/* 11485 */   MCD_OPC_FilterValue, 24, 199, 0, // Skip to: 11688
/* 11489 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11492 */   MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 11504
/* 11496 */   MCD_OPC_CheckPredicate, 15, 49, 5, // Skip to: 12829
/* 11500 */   MCD_OPC_Decode, 43, 170, 1, // Opcode: ADDUH_QB
/* 11504 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 11517
/* 11508 */   MCD_OPC_CheckPredicate, 15, 37, 5, // Skip to: 12829
/* 11512 */   MCD_OPC_Decode, 191, 10, 170, 1, // Opcode: SUBUH_QB
/* 11517 */   MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 11529
/* 11521 */   MCD_OPC_CheckPredicate, 15, 24, 5, // Skip to: 12829
/* 11525 */   MCD_OPC_Decode, 44, 170, 1, // Opcode: ADDUH_R_QB
/* 11529 */   MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 11542
/* 11533 */   MCD_OPC_CheckPredicate, 15, 12, 5, // Skip to: 12829
/* 11537 */   MCD_OPC_Decode, 192, 10, 170, 1, // Opcode: SUBUH_R_QB
/* 11542 */   MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 11554
/* 11546 */   MCD_OPC_CheckPredicate, 15, 255, 4, // Skip to: 12829
/* 11550 */   MCD_OPC_Decode, 23, 170, 1, // Opcode: ADDQH_PH
/* 11554 */   MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 11567
/* 11558 */   MCD_OPC_CheckPredicate, 15, 243, 4, // Skip to: 12829
/* 11562 */   MCD_OPC_Decode, 168, 10, 170, 1, // Opcode: SUBQH_PH
/* 11567 */   MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 11579
/* 11571 */   MCD_OPC_CheckPredicate, 15, 230, 4, // Skip to: 12829
/* 11575 */   MCD_OPC_Decode, 24, 170, 1, // Opcode: ADDQH_R_PH
/* 11579 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 11592
/* 11583 */   MCD_OPC_CheckPredicate, 15, 218, 4, // Skip to: 12829
/* 11587 */   MCD_OPC_Decode, 169, 10, 170, 1, // Opcode: SUBQH_R_PH
/* 11592 */   MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 11605
/* 11596 */   MCD_OPC_CheckPredicate, 15, 205, 4, // Skip to: 12829
/* 11600 */   MCD_OPC_Decode, 252, 7, 170, 1, // Opcode: MUL_PH
/* 11605 */   MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 11618
/* 11609 */   MCD_OPC_CheckPredicate, 15, 192, 4, // Skip to: 12829
/* 11613 */   MCD_OPC_Decode, 255, 7, 170, 1, // Opcode: MUL_S_PH
/* 11618 */   MCD_OPC_FilterValue, 16, 7, 0, // Skip to: 11629
/* 11622 */   MCD_OPC_CheckPredicate, 15, 179, 4, // Skip to: 12829
/* 11626 */   MCD_OPC_Decode, 26, 13, // Opcode: ADDQH_W
/* 11629 */   MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 11641
/* 11633 */   MCD_OPC_CheckPredicate, 15, 168, 4, // Skip to: 12829
/* 11637 */   MCD_OPC_Decode, 171, 10, 13, // Opcode: SUBQH_W
/* 11641 */   MCD_OPC_FilterValue, 18, 7, 0, // Skip to: 11652
/* 11645 */   MCD_OPC_CheckPredicate, 15, 156, 4, // Skip to: 12829
/* 11649 */   MCD_OPC_Decode, 25, 13, // Opcode: ADDQH_R_W
/* 11652 */   MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 11664
/* 11656 */   MCD_OPC_CheckPredicate, 15, 145, 4, // Skip to: 12829
/* 11660 */   MCD_OPC_Decode, 170, 10, 13, // Opcode: SUBQH_R_W
/* 11664 */   MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 11676
/* 11668 */   MCD_OPC_CheckPredicate, 15, 133, 4, // Skip to: 12829
/* 11672 */   MCD_OPC_Decode, 236, 7, 13, // Opcode: MULQ_S_W
/* 11676 */   MCD_OPC_FilterValue, 23, 125, 4, // Skip to: 12829
/* 11680 */   MCD_OPC_CheckPredicate, 15, 121, 4, // Skip to: 12829
/* 11684 */   MCD_OPC_Decode, 234, 7, 13, // Opcode: MULQ_RS_W
/* 11688 */   MCD_OPC_FilterValue, 32, 60, 0, // Skip to: 11752
/* 11692 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11695 */   MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 11714
/* 11699 */   MCD_OPC_CheckPredicate, 16, 102, 4, // Skip to: 12829
/* 11703 */   MCD_OPC_CheckField, 21, 5, 0, 96, 4, // Skip to: 12829
/* 11709 */   MCD_OPC_Decode, 190, 11, 180, 1, // Opcode: WSBH
/* 11714 */   MCD_OPC_FilterValue, 16, 15, 0, // Skip to: 11733
/* 11718 */   MCD_OPC_CheckPredicate, 17, 83, 4, // Skip to: 12829
/* 11722 */   MCD_OPC_CheckField, 21, 5, 0, 77, 4, // Skip to: 12829
/* 11728 */   MCD_OPC_Decode, 164, 9, 180, 1, // Opcode: SEB
/* 11733 */   MCD_OPC_FilterValue, 24, 68, 4, // Skip to: 12829
/* 11737 */   MCD_OPC_CheckPredicate, 17, 64, 4, // Skip to: 12829
/* 11741 */   MCD_OPC_CheckField, 21, 5, 0, 58, 4, // Skip to: 12829
/* 11747 */   MCD_OPC_Decode, 167, 9, 180, 1, // Opcode: SEH
/* 11752 */   MCD_OPC_FilterValue, 48, 143, 1, // Skip to: 12155
/* 11756 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11759 */   MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 11777
/* 11763 */   MCD_OPC_CheckPredicate, 15, 38, 4, // Skip to: 12829
/* 11767 */   MCD_OPC_CheckField, 13, 3, 0, 32, 4, // Skip to: 12829
/* 11773 */   MCD_OPC_Decode, 218, 3, 88, // Opcode: DPA_W_PH
/* 11777 */   MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 11795
/* 11781 */   MCD_OPC_CheckPredicate, 15, 20, 4, // Skip to: 12829
/* 11785 */   MCD_OPC_CheckField, 13, 3, 0, 14, 4, // Skip to: 12829
/* 11791 */   MCD_OPC_Decode, 232, 3, 88, // Opcode: DPS_W_PH
/* 11795 */   MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 11813
/* 11799 */   MCD_OPC_CheckPredicate, 15, 2, 4, // Skip to: 12829
/* 11803 */   MCD_OPC_CheckField, 13, 3, 0, 252, 3, // Skip to: 12829
/* 11809 */   MCD_OPC_Decode, 240, 7, 88, // Opcode: MULSA_W_PH
/* 11813 */   MCD_OPC_FilterValue, 3, 14, 0, // Skip to: 11831
/* 11817 */   MCD_OPC_CheckPredicate, 5, 240, 3, // Skip to: 12829
/* 11821 */   MCD_OPC_CheckField, 13, 3, 0, 234, 3, // Skip to: 12829
/* 11827 */   MCD_OPC_Decode, 215, 3, 88, // Opcode: DPAU_H_QBL
/* 11831 */   MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 11849
/* 11835 */   MCD_OPC_CheckPredicate, 5, 222, 3, // Skip to: 12829
/* 11839 */   MCD_OPC_CheckField, 13, 3, 0, 216, 3, // Skip to: 12829
/* 11845 */   MCD_OPC_Decode, 214, 3, 88, // Opcode: DPAQ_S_W_PH
/* 11849 */   MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 11867
/* 11853 */   MCD_OPC_CheckPredicate, 5, 204, 3, // Skip to: 12829
/* 11857 */   MCD_OPC_CheckField, 13, 3, 0, 198, 3, // Skip to: 12829
/* 11863 */   MCD_OPC_Decode, 222, 3, 88, // Opcode: DPSQ_S_W_PH
/* 11867 */   MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 11885
/* 11871 */   MCD_OPC_CheckPredicate, 5, 186, 3, // Skip to: 12829
/* 11875 */   MCD_OPC_CheckField, 13, 3, 0, 180, 3, // Skip to: 12829
/* 11881 */   MCD_OPC_Decode, 239, 7, 88, // Opcode: MULSAQ_S_W_PH
/* 11885 */   MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 11903
/* 11889 */   MCD_OPC_CheckPredicate, 5, 168, 3, // Skip to: 12829
/* 11893 */   MCD_OPC_CheckField, 13, 3, 0, 162, 3, // Skip to: 12829
/* 11899 */   MCD_OPC_Decode, 216, 3, 88, // Opcode: DPAU_H_QBR
/* 11903 */   MCD_OPC_FilterValue, 8, 14, 0, // Skip to: 11921
/* 11907 */   MCD_OPC_CheckPredicate, 15, 150, 3, // Skip to: 12829
/* 11911 */   MCD_OPC_CheckField, 13, 3, 0, 144, 3, // Skip to: 12829
/* 11917 */   MCD_OPC_Decode, 217, 3, 88, // Opcode: DPAX_W_PH
/* 11921 */   MCD_OPC_FilterValue, 9, 14, 0, // Skip to: 11939
/* 11925 */   MCD_OPC_CheckPredicate, 15, 132, 3, // Skip to: 12829
/* 11929 */   MCD_OPC_CheckField, 13, 3, 0, 126, 3, // Skip to: 12829
/* 11935 */   MCD_OPC_Decode, 231, 3, 88, // Opcode: DPSX_W_PH
/* 11939 */   MCD_OPC_FilterValue, 11, 14, 0, // Skip to: 11957
/* 11943 */   MCD_OPC_CheckPredicate, 5, 114, 3, // Skip to: 12829
/* 11947 */   MCD_OPC_CheckField, 13, 3, 0, 108, 3, // Skip to: 12829
/* 11953 */   MCD_OPC_Decode, 229, 3, 88, // Opcode: DPSU_H_QBL
/* 11957 */   MCD_OPC_FilterValue, 12, 14, 0, // Skip to: 11975
/* 11961 */   MCD_OPC_CheckPredicate, 5, 96, 3, // Skip to: 12829
/* 11965 */   MCD_OPC_CheckField, 13, 3, 0, 90, 3, // Skip to: 12829
/* 11971 */   MCD_OPC_Decode, 213, 3, 88, // Opcode: DPAQ_SA_L_W
/* 11975 */   MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 11993
/* 11979 */   MCD_OPC_CheckPredicate, 5, 78, 3, // Skip to: 12829
/* 11983 */   MCD_OPC_CheckField, 13, 3, 0, 72, 3, // Skip to: 12829
/* 11989 */   MCD_OPC_Decode, 221, 3, 88, // Opcode: DPSQ_SA_L_W
/* 11993 */   MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 12011
/* 11997 */   MCD_OPC_CheckPredicate, 5, 60, 3, // Skip to: 12829
/* 12001 */   MCD_OPC_CheckField, 13, 3, 0, 54, 3, // Skip to: 12829
/* 12007 */   MCD_OPC_Decode, 230, 3, 88, // Opcode: DPSU_H_QBR
/* 12011 */   MCD_OPC_FilterValue, 16, 14, 0, // Skip to: 12029
/* 12015 */   MCD_OPC_CheckPredicate, 5, 42, 3, // Skip to: 12829
/* 12019 */   MCD_OPC_CheckField, 13, 3, 0, 36, 3, // Skip to: 12829
/* 12025 */   MCD_OPC_Decode, 212, 6, 88, // Opcode: MAQ_SA_W_PHL
/* 12029 */   MCD_OPC_FilterValue, 18, 14, 0, // Skip to: 12047
/* 12033 */   MCD_OPC_CheckPredicate, 5, 24, 3, // Skip to: 12829
/* 12037 */   MCD_OPC_CheckField, 13, 3, 0, 18, 3, // Skip to: 12829
/* 12043 */   MCD_OPC_Decode, 213, 6, 88, // Opcode: MAQ_SA_W_PHR
/* 12047 */   MCD_OPC_FilterValue, 20, 14, 0, // Skip to: 12065
/* 12051 */   MCD_OPC_CheckPredicate, 5, 6, 3, // Skip to: 12829
/* 12055 */   MCD_OPC_CheckField, 13, 3, 0, 0, 3, // Skip to: 12829
/* 12061 */   MCD_OPC_Decode, 214, 6, 88, // Opcode: MAQ_S_W_PHL
/* 12065 */   MCD_OPC_FilterValue, 22, 14, 0, // Skip to: 12083
/* 12069 */   MCD_OPC_CheckPredicate, 5, 244, 2, // Skip to: 12829
/* 12073 */   MCD_OPC_CheckField, 13, 3, 0, 238, 2, // Skip to: 12829
/* 12079 */   MCD_OPC_Decode, 215, 6, 88, // Opcode: MAQ_S_W_PHR
/* 12083 */   MCD_OPC_FilterValue, 24, 14, 0, // Skip to: 12101
/* 12087 */   MCD_OPC_CheckPredicate, 15, 226, 2, // Skip to: 12829
/* 12091 */   MCD_OPC_CheckField, 13, 3, 0, 220, 2, // Skip to: 12829
/* 12097 */   MCD_OPC_Decode, 212, 3, 88, // Opcode: DPAQX_S_W_PH
/* 12101 */   MCD_OPC_FilterValue, 25, 14, 0, // Skip to: 12119
/* 12105 */   MCD_OPC_CheckPredicate, 15, 208, 2, // Skip to: 12829
/* 12109 */   MCD_OPC_CheckField, 13, 3, 0, 202, 2, // Skip to: 12829
/* 12115 */   MCD_OPC_Decode, 220, 3, 88, // Opcode: DPSQX_S_W_PH
/* 12119 */   MCD_OPC_FilterValue, 26, 14, 0, // Skip to: 12137
/* 12123 */   MCD_OPC_CheckPredicate, 15, 190, 2, // Skip to: 12829
/* 12127 */   MCD_OPC_CheckField, 13, 3, 0, 184, 2, // Skip to: 12829
/* 12133 */   MCD_OPC_Decode, 211, 3, 88, // Opcode: DPAQX_SA_W_PH
/* 12137 */   MCD_OPC_FilterValue, 27, 176, 2, // Skip to: 12829
/* 12141 */   MCD_OPC_CheckPredicate, 15, 172, 2, // Skip to: 12829
/* 12145 */   MCD_OPC_CheckField, 13, 3, 0, 166, 2, // Skip to: 12829
/* 12151 */   MCD_OPC_Decode, 219, 3, 88, // Opcode: DPSQX_SA_W_PH
/* 12155 */   MCD_OPC_FilterValue, 49, 41, 0, // Skip to: 12200
/* 12159 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 12162 */   MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 12174
/* 12166 */   MCD_OPC_CheckPredicate, 15, 147, 2, // Skip to: 12829
/* 12170 */   MCD_OPC_Decode, 82, 184, 1, // Opcode: APPEND
/* 12174 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 12187
/* 12178 */   MCD_OPC_CheckPredicate, 15, 135, 2, // Skip to: 12829
/* 12182 */   MCD_OPC_Decode, 209, 8, 184, 1, // Opcode: PREPEND
/* 12187 */   MCD_OPC_FilterValue, 16, 126, 2, // Skip to: 12829
/* 12191 */   MCD_OPC_CheckPredicate, 15, 122, 2, // Skip to: 12829
/* 12195 */   MCD_OPC_Decode, 149, 1, 184, 1, // Opcode: BALIGN
/* 12200 */   MCD_OPC_FilterValue, 56, 58, 1, // Skip to: 12518
/* 12204 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 12207 */   MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 12226
/* 12211 */   MCD_OPC_CheckPredicate, 5, 102, 2, // Skip to: 12829
/* 12215 */   MCD_OPC_CheckField, 13, 3, 0, 96, 2, // Skip to: 12829
/* 12221 */   MCD_OPC_Decode, 141, 4, 185, 1, // Opcode: EXTR_W
/* 12226 */   MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 12245
/* 12230 */   MCD_OPC_CheckPredicate, 5, 83, 2, // Skip to: 12829
/* 12234 */   MCD_OPC_CheckField, 13, 3, 0, 77, 2, // Skip to: 12829
/* 12240 */   MCD_OPC_Decode, 137, 4, 186, 1, // Opcode: EXTRV_W
/* 12245 */   MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 12264
/* 12249 */   MCD_OPC_CheckPredicate, 5, 64, 2, // Skip to: 12829
/* 12253 */   MCD_OPC_CheckField, 13, 3, 0, 58, 2, // Skip to: 12829
/* 12259 */   MCD_OPC_Decode, 130, 4, 185, 1, // Opcode: EXTP
/* 12264 */   MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 12283
/* 12268 */   MCD_OPC_CheckPredicate, 5, 45, 2, // Skip to: 12829
/* 12272 */   MCD_OPC_CheckField, 13, 3, 0, 39, 2, // Skip to: 12829
/* 12278 */   MCD_OPC_Decode, 133, 4, 186, 1, // Opcode: EXTPV
/* 12283 */   MCD_OPC_FilterValue, 4, 15, 0, // Skip to: 12302
/* 12287 */   MCD_OPC_CheckPredicate, 5, 26, 2, // Skip to: 12829
/* 12291 */   MCD_OPC_CheckField, 13, 3, 0, 20, 2, // Skip to: 12829
/* 12297 */   MCD_OPC_Decode, 139, 4, 185, 1, // Opcode: EXTR_R_W
/* 12302 */   MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 12321
/* 12306 */   MCD_OPC_CheckPredicate, 5, 7, 2, // Skip to: 12829
/* 12310 */   MCD_OPC_CheckField, 13, 3, 0, 1, 2, // Skip to: 12829
/* 12316 */   MCD_OPC_Decode, 135, 4, 186, 1, // Opcode: EXTRV_R_W
/* 12321 */   MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 12340
/* 12325 */   MCD_OPC_CheckPredicate, 5, 244, 1, // Skip to: 12829
/* 12329 */   MCD_OPC_CheckField, 13, 3, 0, 238, 1, // Skip to: 12829
/* 12335 */   MCD_OPC_Decode, 138, 4, 185, 1, // Opcode: EXTR_RS_W
/* 12340 */   MCD_OPC_FilterValue, 7, 15, 0, // Skip to: 12359
/* 12344 */   MCD_OPC_CheckPredicate, 5, 225, 1, // Skip to: 12829
/* 12348 */   MCD_OPC_CheckField, 13, 3, 0, 219, 1, // Skip to: 12829
/* 12354 */   MCD_OPC_Decode, 134, 4, 186, 1, // Opcode: EXTRV_RS_W
/* 12359 */   MCD_OPC_FilterValue, 10, 15, 0, // Skip to: 12378
/* 12363 */   MCD_OPC_CheckPredicate, 5, 206, 1, // Skip to: 12829
/* 12367 */   MCD_OPC_CheckField, 13, 3, 0, 200, 1, // Skip to: 12829
/* 12373 */   MCD_OPC_Decode, 131, 4, 185, 1, // Opcode: EXTPDP
/* 12378 */   MCD_OPC_FilterValue, 11, 15, 0, // Skip to: 12397
/* 12382 */   MCD_OPC_CheckPredicate, 5, 187, 1, // Skip to: 12829
/* 12386 */   MCD_OPC_CheckField, 13, 3, 0, 181, 1, // Skip to: 12829
/* 12392 */   MCD_OPC_Decode, 132, 4, 186, 1, // Opcode: EXTPDPV
/* 12397 */   MCD_OPC_FilterValue, 14, 15, 0, // Skip to: 12416
/* 12401 */   MCD_OPC_CheckPredicate, 5, 168, 1, // Skip to: 12829
/* 12405 */   MCD_OPC_CheckField, 13, 3, 0, 162, 1, // Skip to: 12829
/* 12411 */   MCD_OPC_Decode, 140, 4, 185, 1, // Opcode: EXTR_S_H
/* 12416 */   MCD_OPC_FilterValue, 15, 15, 0, // Skip to: 12435
/* 12420 */   MCD_OPC_CheckPredicate, 5, 149, 1, // Skip to: 12829
/* 12424 */   MCD_OPC_CheckField, 13, 3, 0, 143, 1, // Skip to: 12829
/* 12430 */   MCD_OPC_Decode, 136, 4, 186, 1, // Opcode: EXTRV_S_H
/* 12435 */   MCD_OPC_FilterValue, 18, 9, 0, // Skip to: 12448
/* 12439 */   MCD_OPC_CheckPredicate, 5, 130, 1, // Skip to: 12829
/* 12443 */   MCD_OPC_Decode, 243, 8, 187, 1, // Opcode: RDDSP
/* 12448 */   MCD_OPC_FilterValue, 19, 9, 0, // Skip to: 12461
/* 12452 */   MCD_OPC_CheckPredicate, 5, 117, 1, // Skip to: 12829
/* 12456 */   MCD_OPC_Decode, 189, 11, 188, 1, // Opcode: WRDSP
/* 12461 */   MCD_OPC_FilterValue, 26, 15, 0, // Skip to: 12480
/* 12465 */   MCD_OPC_CheckPredicate, 5, 104, 1, // Skip to: 12829
/* 12469 */   MCD_OPC_CheckField, 13, 7, 0, 98, 1, // Skip to: 12829
/* 12475 */   MCD_OPC_Decode, 175, 9, 189, 1, // Opcode: SHILO
/* 12480 */   MCD_OPC_FilterValue, 27, 15, 0, // Skip to: 12499
/* 12484 */   MCD_OPC_CheckPredicate, 5, 85, 1, // Skip to: 12829
/* 12488 */   MCD_OPC_CheckField, 13, 8, 0, 79, 1, // Skip to: 12829
/* 12494 */   MCD_OPC_Decode, 176, 9, 190, 1, // Opcode: SHILOV
/* 12499 */   MCD_OPC_FilterValue, 31, 70, 1, // Skip to: 12829
/* 12503 */   MCD_OPC_CheckPredicate, 5, 66, 1, // Skip to: 12829
/* 12507 */   MCD_OPC_CheckField, 13, 8, 0, 60, 1, // Skip to: 12829
/* 12513 */   MCD_OPC_Decode, 223, 7, 190, 1, // Opcode: MTHLIP
/* 12518 */   MCD_OPC_FilterValue, 59, 51, 1, // Skip to: 12829
/* 12522 */   MCD_OPC_CheckPredicate, 2, 47, 1, // Skip to: 12829
/* 12526 */   MCD_OPC_CheckField, 21, 5, 0, 41, 1, // Skip to: 12829
/* 12532 */   MCD_OPC_CheckField, 6, 5, 0, 35, 1, // Skip to: 12829
/* 12538 */   MCD_OPC_Decode, 244, 8, 191, 1, // Opcode: RDHWR
/* 12543 */   MCD_OPC_FilterValue, 32, 9, 0, // Skip to: 12556
/* 12547 */   MCD_OPC_CheckPredicate, 2, 22, 1, // Skip to: 12829
/* 12551 */   MCD_OPC_Decode, 241, 5, 192, 1, // Opcode: LB
/* 12556 */   MCD_OPC_FilterValue, 33, 9, 0, // Skip to: 12569
/* 12560 */   MCD_OPC_CheckPredicate, 2, 9, 1, // Skip to: 12829
/* 12564 */   MCD_OPC_Decode, 140, 6, 192, 1, // Opcode: LH
/* 12569 */   MCD_OPC_FilterValue, 34, 9, 0, // Skip to: 12582
/* 12573 */   MCD_OPC_CheckPredicate, 18, 252, 0, // Skip to: 12829
/* 12577 */   MCD_OPC_Decode, 166, 6, 192, 1, // Opcode: LWL
/* 12582 */   MCD_OPC_FilterValue, 35, 9, 0, // Skip to: 12595
/* 12586 */   MCD_OPC_CheckPredicate, 2, 239, 0, // Skip to: 12829
/* 12590 */   MCD_OPC_Decode, 161, 6, 192, 1, // Opcode: LW
/* 12595 */   MCD_OPC_FilterValue, 36, 9, 0, // Skip to: 12608
/* 12599 */   MCD_OPC_CheckPredicate, 2, 226, 0, // Skip to: 12829
/* 12603 */   MCD_OPC_Decode, 245, 5, 192, 1, // Opcode: LBu
/* 12608 */   MCD_OPC_FilterValue, 37, 9, 0, // Skip to: 12621
/* 12612 */   MCD_OPC_CheckPredicate, 2, 213, 0, // Skip to: 12829
/* 12616 */   MCD_OPC_Decode, 144, 6, 192, 1, // Opcode: LHu
/* 12621 */   MCD_OPC_FilterValue, 38, 9, 0, // Skip to: 12634
/* 12625 */   MCD_OPC_CheckPredicate, 18, 200, 0, // Skip to: 12829
/* 12629 */   MCD_OPC_Decode, 169, 6, 192, 1, // Opcode: LWR
/* 12634 */   MCD_OPC_FilterValue, 40, 9, 0, // Skip to: 12647
/* 12638 */   MCD_OPC_CheckPredicate, 2, 187, 0, // Skip to: 12829
/* 12642 */   MCD_OPC_Decode, 147, 9, 192, 1, // Opcode: SB
/* 12647 */   MCD_OPC_FilterValue, 41, 9, 0, // Skip to: 12660
/* 12651 */   MCD_OPC_CheckPredicate, 2, 174, 0, // Skip to: 12829
/* 12655 */   MCD_OPC_Decode, 170, 9, 192, 1, // Opcode: SH
/* 12660 */   MCD_OPC_FilterValue, 42, 9, 0, // Skip to: 12673
/* 12664 */   MCD_OPC_CheckPredicate, 18, 161, 0, // Skip to: 12829
/* 12668 */   MCD_OPC_Decode, 216, 10, 192, 1, // Opcode: SWL
/* 12673 */   MCD_OPC_FilterValue, 43, 9, 0, // Skip to: 12686
/* 12677 */   MCD_OPC_CheckPredicate, 2, 148, 0, // Skip to: 12829
/* 12681 */   MCD_OPC_Decode, 211, 10, 192, 1, // Opcode: SW
/* 12686 */   MCD_OPC_FilterValue, 46, 9, 0, // Skip to: 12699
/* 12690 */   MCD_OPC_CheckPredicate, 18, 135, 0, // Skip to: 12829
/* 12694 */   MCD_OPC_Decode, 219, 10, 192, 1, // Opcode: SWR
/* 12699 */   MCD_OPC_FilterValue, 48, 9, 0, // Skip to: 12712
/* 12703 */   MCD_OPC_CheckPredicate, 18, 122, 0, // Skip to: 12829
/* 12707 */   MCD_OPC_Decode, 147, 6, 192, 1, // Opcode: LL
/* 12712 */   MCD_OPC_FilterValue, 49, 9, 0, // Skip to: 12725
/* 12716 */   MCD_OPC_CheckPredicate, 2, 109, 0, // Skip to: 12829
/* 12720 */   MCD_OPC_Decode, 163, 6, 193, 1, // Opcode: LWC1
/* 12725 */   MCD_OPC_FilterValue, 50, 9, 0, // Skip to: 12738
/* 12729 */   MCD_OPC_CheckPredicate, 2, 96, 0, // Skip to: 12829
/* 12733 */   MCD_OPC_Decode, 165, 6, 193, 1, // Opcode: LWC2
/* 12738 */   MCD_OPC_FilterValue, 53, 9, 0, // Skip to: 12751
/* 12742 */   MCD_OPC_CheckPredicate, 8, 83, 0, // Skip to: 12829
/* 12746 */   MCD_OPC_Decode, 249, 5, 193, 1, // Opcode: LDC1
/* 12751 */   MCD_OPC_FilterValue, 54, 9, 0, // Skip to: 12764
/* 12755 */   MCD_OPC_CheckPredicate, 2, 70, 0, // Skip to: 12829
/* 12759 */   MCD_OPC_Decode, 252, 5, 193, 1, // Opcode: LDC2
/* 12764 */   MCD_OPC_FilterValue, 56, 9, 0, // Skip to: 12777
/* 12768 */   MCD_OPC_CheckPredicate, 18, 57, 0, // Skip to: 12829
/* 12772 */   MCD_OPC_Decode, 150, 9, 192, 1, // Opcode: SC
/* 12777 */   MCD_OPC_FilterValue, 57, 9, 0, // Skip to: 12790
/* 12781 */   MCD_OPC_CheckPredicate, 2, 44, 0, // Skip to: 12829
/* 12785 */   MCD_OPC_Decode, 213, 10, 193, 1, // Opcode: SWC1
/* 12790 */   MCD_OPC_FilterValue, 58, 9, 0, // Skip to: 12803
/* 12794 */   MCD_OPC_CheckPredicate, 2, 31, 0, // Skip to: 12829
/* 12798 */   MCD_OPC_Decode, 215, 10, 193, 1, // Opcode: SWC2
/* 12803 */   MCD_OPC_FilterValue, 61, 9, 0, // Skip to: 12816
/* 12807 */   MCD_OPC_CheckPredicate, 8, 18, 0, // Skip to: 12829
/* 12811 */   MCD_OPC_Decode, 154, 9, 193, 1, // Opcode: SDC1
/* 12816 */   MCD_OPC_FilterValue, 62, 9, 0, // Skip to: 12829
/* 12820 */   MCD_OPC_CheckPredicate, 2, 5, 0, // Skip to: 12829
/* 12824 */   MCD_OPC_Decode, 157, 9, 193, 1, // Opcode: SDC2
/* 12829 */   MCD_OPC_Fail,
  0
};

static uint8_t DecoderTableMips6432[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 93, 1, // Skip to: 356
/* 7 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10 */      MCD_OPC_FilterValue, 20, 15, 0, // Skip to: 29
/* 14 */      MCD_OPC_CheckPredicate, 2, 6, 7, // Skip to: 1816
/* 18 */      MCD_OPC_CheckField, 6, 5, 0, 0, 7, // Skip to: 1816
/* 24 */      MCD_OPC_Decode, 242, 3, 194, 1, // Opcode: DSLLV
/* 29 */      MCD_OPC_FilterValue, 22, 29, 0, // Skip to: 62
/* 33 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 36 */      MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 49
/* 40 */      MCD_OPC_CheckPredicate, 2, 236, 6, // Skip to: 1816
/* 44 */      MCD_OPC_Decode, 248, 3, 194, 1, // Opcode: DSRLV
/* 49 */      MCD_OPC_FilterValue, 1, 227, 6, // Skip to: 1816
/* 53 */      MCD_OPC_CheckPredicate, 19, 223, 6, // Skip to: 1816
/* 57 */      MCD_OPC_Decode, 235, 3, 194, 1, // Opcode: DROTRV
/* 62 */      MCD_OPC_FilterValue, 23, 15, 0, // Skip to: 81
/* 66 */      MCD_OPC_CheckPredicate, 2, 210, 6, // Skip to: 1816
/* 70 */      MCD_OPC_CheckField, 6, 5, 0, 204, 6, // Skip to: 1816
/* 76 */      MCD_OPC_Decode, 245, 3, 194, 1, // Opcode: DSRAV
/* 81 */      MCD_OPC_FilterValue, 28, 15, 0, // Skip to: 100
/* 85 */      MCD_OPC_CheckPredicate, 2, 191, 6, // Skip to: 1816
/* 89 */      MCD_OPC_CheckField, 6, 10, 0, 185, 6, // Skip to: 1816
/* 95 */      MCD_OPC_Decode, 197, 3, 195, 1, // Opcode: DMULT
/* 100 */     MCD_OPC_FilterValue, 29, 15, 0, // Skip to: 119
/* 104 */     MCD_OPC_CheckPredicate, 2, 172, 6, // Skip to: 1816
/* 108 */     MCD_OPC_CheckField, 6, 10, 0, 166, 6, // Skip to: 1816
/* 114 */     MCD_OPC_Decode, 198, 3, 195, 1, // Opcode: DMULTu
/* 119 */     MCD_OPC_FilterValue, 30, 15, 0, // Skip to: 138
/* 123 */     MCD_OPC_CheckPredicate, 2, 153, 6, // Skip to: 1816
/* 127 */     MCD_OPC_CheckField, 6, 10, 0, 147, 6, // Skip to: 1816
/* 133 */     MCD_OPC_Decode, 237, 3, 195, 1, // Opcode: DSDIV
/* 138 */     MCD_OPC_FilterValue, 31, 15, 0, // Skip to: 157
/* 142 */     MCD_OPC_CheckPredicate, 2, 134, 6, // Skip to: 1816
/* 146 */     MCD_OPC_CheckField, 6, 10, 0, 128, 6, // Skip to: 1816
/* 152 */     MCD_OPC_Decode, 250, 3, 195, 1, // Opcode: DUDIV
/* 157 */     MCD_OPC_FilterValue, 44, 15, 0, // Skip to: 176
/* 161 */     MCD_OPC_CheckPredicate, 2, 115, 6, // Skip to: 1816
/* 165 */     MCD_OPC_CheckField, 6, 5, 0, 109, 6, // Skip to: 1816
/* 171 */     MCD_OPC_Decode, 166, 3, 196, 1, // Opcode: DADD
/* 176 */     MCD_OPC_FilterValue, 45, 15, 0, // Skip to: 195
/* 180 */     MCD_OPC_CheckPredicate, 2, 96, 6, // Skip to: 1816
/* 184 */     MCD_OPC_CheckField, 6, 5, 0, 90, 6, // Skip to: 1816
/* 190 */     MCD_OPC_Decode, 169, 3, 196, 1, // Opcode: DADDu
/* 195 */     MCD_OPC_FilterValue, 47, 15, 0, // Skip to: 214
/* 199 */     MCD_OPC_CheckPredicate, 2, 77, 6, // Skip to: 1816
/* 203 */     MCD_OPC_CheckField, 6, 5, 0, 71, 6, // Skip to: 1816
/* 209 */     MCD_OPC_Decode, 249, 3, 196, 1, // Opcode: DSUBu
/* 214 */     MCD_OPC_FilterValue, 56, 15, 0, // Skip to: 233
/* 218 */     MCD_OPC_CheckPredicate, 2, 58, 6, // Skip to: 1816
/* 222 */     MCD_OPC_CheckField, 21, 5, 0, 52, 6, // Skip to: 1816
/* 228 */     MCD_OPC_Decode, 239, 3, 197, 1, // Opcode: DSLL
/* 233 */     MCD_OPC_FilterValue, 58, 29, 0, // Skip to: 266
/* 237 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 240 */     MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 253
/* 244 */     MCD_OPC_CheckPredicate, 2, 32, 6, // Skip to: 1816
/* 248 */     MCD_OPC_Decode, 246, 3, 197, 1, // Opcode: DSRL
/* 253 */     MCD_OPC_FilterValue, 1, 23, 6, // Skip to: 1816
/* 257 */     MCD_OPC_CheckPredicate, 19, 19, 6, // Skip to: 1816
/* 261 */     MCD_OPC_Decode, 233, 3, 197, 1, // Opcode: DROTR
/* 266 */     MCD_OPC_FilterValue, 59, 15, 0, // Skip to: 285
/* 270 */     MCD_OPC_CheckPredicate, 2, 6, 6, // Skip to: 1816
/* 274 */     MCD_OPC_CheckField, 21, 5, 0, 0, 6, // Skip to: 1816
/* 280 */     MCD_OPC_Decode, 243, 3, 197, 1, // Opcode: DSRA
/* 285 */     MCD_OPC_FilterValue, 60, 15, 0, // Skip to: 304
/* 289 */     MCD_OPC_CheckPredicate, 2, 243, 5, // Skip to: 1816
/* 293 */     MCD_OPC_CheckField, 21, 5, 0, 237, 5, // Skip to: 1816
/* 299 */     MCD_OPC_Decode, 240, 3, 197, 1, // Opcode: DSLL32
/* 304 */     MCD_OPC_FilterValue, 62, 29, 0, // Skip to: 337
/* 308 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 311 */     MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 324
/* 315 */     MCD_OPC_CheckPredicate, 2, 217, 5, // Skip to: 1816
/* 319 */     MCD_OPC_Decode, 247, 3, 197, 1, // Opcode: DSRL32
/* 324 */     MCD_OPC_FilterValue, 1, 208, 5, // Skip to: 1816
/* 328 */     MCD_OPC_CheckPredicate, 19, 204, 5, // Skip to: 1816
/* 332 */     MCD_OPC_Decode, 234, 3, 197, 1, // Opcode: DROTR32
/* 337 */     MCD_OPC_FilterValue, 63, 195, 5, // Skip to: 1816
/* 341 */     MCD_OPC_CheckPredicate, 2, 191, 5, // Skip to: 1816
/* 345 */     MCD_OPC_CheckField, 21, 5, 0, 185, 5, // Skip to: 1816
/* 351 */     MCD_OPC_Decode, 244, 3, 197, 1, // Opcode: DSRA32
/* 356 */     MCD_OPC_FilterValue, 16, 41, 0, // Skip to: 401
/* 360 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 363 */     MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 382
/* 367 */     MCD_OPC_CheckPredicate, 20, 165, 5, // Skip to: 1816
/* 371 */     MCD_OPC_CheckField, 3, 8, 0, 159, 5, // Skip to: 1816
/* 377 */     MCD_OPC_Decode, 191, 3, 198, 1, // Opcode: DMFC0
/* 382 */     MCD_OPC_FilterValue, 5, 150, 5, // Skip to: 1816
/* 386 */     MCD_OPC_CheckPredicate, 20, 146, 5, // Skip to: 1816
/* 390 */     MCD_OPC_CheckField, 3, 8, 0, 140, 5, // Skip to: 1816
/* 396 */     MCD_OPC_Decode, 194, 3, 198, 1, // Opcode: DMTC0
/* 401 */     MCD_OPC_FilterValue, 17, 183, 3, // Skip to: 1356
/* 405 */     MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 408 */     MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 427
/* 412 */     MCD_OPC_CheckPredicate, 21, 120, 5, // Skip to: 1816
/* 416 */     MCD_OPC_CheckField, 21, 5, 17, 114, 5, // Skip to: 1816
/* 422 */     MCD_OPC_Decode, 154, 4, 199, 1, // Opcode: FADD_D64
/* 427 */     MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 446
/* 431 */     MCD_OPC_CheckPredicate, 21, 101, 5, // Skip to: 1816
/* 435 */     MCD_OPC_CheckField, 21, 5, 17, 95, 5, // Skip to: 1816
/* 441 */     MCD_OPC_Decode, 156, 5, 199, 1, // Opcode: FSUB_D64
/* 446 */     MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 465
/* 450 */     MCD_OPC_CheckPredicate, 21, 82, 5, // Skip to: 1816
/* 454 */     MCD_OPC_CheckField, 21, 5, 17, 76, 5, // Skip to: 1816
/* 460 */     MCD_OPC_Decode, 247, 4, 199, 1, // Opcode: FMUL_D64
/* 465 */     MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 484
/* 469 */     MCD_OPC_CheckPredicate, 21, 63, 5, // Skip to: 1816
/* 473 */     MCD_OPC_CheckField, 21, 5, 17, 57, 5, // Skip to: 1816
/* 479 */     MCD_OPC_Decode, 190, 4, 199, 1, // Opcode: FDIV_D64
/* 484 */     MCD_OPC_FilterValue, 4, 15, 0, // Skip to: 503
/* 488 */     MCD_OPC_CheckPredicate, 21, 44, 5, // Skip to: 1816
/* 492 */     MCD_OPC_CheckField, 16, 10, 160, 4, 37, 5, // Skip to: 1816
/* 499 */     MCD_OPC_Decode, 149, 5, 77, // Opcode: FSQRT_D64
/* 503 */     MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 522
/* 507 */     MCD_OPC_CheckPredicate, 7, 25, 5, // Skip to: 1816
/* 511 */     MCD_OPC_CheckField, 16, 10, 160, 4, 18, 5, // Skip to: 1816
/* 518 */     MCD_OPC_Decode, 147, 4, 77, // Opcode: FABS_D64
/* 522 */     MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 541
/* 526 */     MCD_OPC_CheckPredicate, 21, 6, 5, // Skip to: 1816
/* 530 */     MCD_OPC_CheckField, 16, 10, 160, 4, 255, 4, // Skip to: 1816
/* 537 */     MCD_OPC_Decode, 240, 4, 77, // Opcode: FMOV_D64
/* 541 */     MCD_OPC_FilterValue, 7, 15, 0, // Skip to: 560
/* 545 */     MCD_OPC_CheckPredicate, 7, 243, 4, // Skip to: 1816
/* 549 */     MCD_OPC_CheckField, 16, 10, 160, 4, 236, 4, // Skip to: 1816
/* 556 */     MCD_OPC_Decode, 253, 4, 77, // Opcode: FNEG_D64
/* 560 */     MCD_OPC_FilterValue, 8, 29, 0, // Skip to: 593
/* 564 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 567 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 580
/* 572 */     MCD_OPC_CheckPredicate, 21, 216, 4, // Skip to: 1816
/* 576 */     MCD_OPC_Decode, 129, 9, 70, // Opcode: ROUND_L_S
/* 580 */     MCD_OPC_FilterValue, 160, 4, 207, 4, // Skip to: 1816
/* 585 */     MCD_OPC_CheckPredicate, 21, 203, 4, // Skip to: 1816
/* 589 */     MCD_OPC_Decode, 128, 9, 77, // Opcode: ROUND_L_D64
/* 593 */     MCD_OPC_FilterValue, 9, 29, 0, // Skip to: 626
/* 597 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 600 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 613
/* 605 */     MCD_OPC_CheckPredicate, 21, 183, 4, // Skip to: 1816
/* 609 */     MCD_OPC_Decode, 174, 11, 70, // Opcode: TRUNC_L_S
/* 613 */     MCD_OPC_FilterValue, 160, 4, 174, 4, // Skip to: 1816
/* 618 */     MCD_OPC_CheckPredicate, 21, 170, 4, // Skip to: 1816
/* 622 */     MCD_OPC_Decode, 173, 11, 77, // Opcode: TRUNC_L_D64
/* 626 */     MCD_OPC_FilterValue, 10, 29, 0, // Skip to: 659
/* 630 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 633 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 646
/* 638 */     MCD_OPC_CheckPredicate, 21, 150, 4, // Skip to: 1816
/* 642 */     MCD_OPC_Decode, 141, 2, 70, // Opcode: CEIL_L_S
/* 646 */     MCD_OPC_FilterValue, 160, 4, 141, 4, // Skip to: 1816
/* 651 */     MCD_OPC_CheckPredicate, 21, 137, 4, // Skip to: 1816
/* 655 */     MCD_OPC_Decode, 140, 2, 77, // Opcode: CEIL_L_D64
/* 659 */     MCD_OPC_FilterValue, 11, 29, 0, // Skip to: 692
/* 663 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 666 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 679
/* 671 */     MCD_OPC_CheckPredicate, 21, 117, 4, // Skip to: 1816
/* 675 */     MCD_OPC_Decode, 222, 4, 70, // Opcode: FLOOR_L_S
/* 679 */     MCD_OPC_FilterValue, 160, 4, 108, 4, // Skip to: 1816
/* 684 */     MCD_OPC_CheckPredicate, 21, 104, 4, // Skip to: 1816
/* 688 */     MCD_OPC_Decode, 221, 4, 77, // Opcode: FLOOR_L_D64
/* 692 */     MCD_OPC_FilterValue, 12, 16, 0, // Skip to: 712
/* 696 */     MCD_OPC_CheckPredicate, 21, 92, 4, // Skip to: 1816
/* 700 */     MCD_OPC_CheckField, 16, 10, 160, 4, 85, 4, // Skip to: 1816
/* 707 */     MCD_OPC_Decode, 131, 9, 200, 1, // Opcode: ROUND_W_D64
/* 712 */     MCD_OPC_FilterValue, 13, 16, 0, // Skip to: 732
/* 716 */     MCD_OPC_CheckPredicate, 21, 72, 4, // Skip to: 1816
/* 720 */     MCD_OPC_CheckField, 16, 10, 160, 4, 65, 4, // Skip to: 1816
/* 727 */     MCD_OPC_Decode, 176, 11, 200, 1, // Opcode: TRUNC_W_D64
/* 732 */     MCD_OPC_FilterValue, 14, 16, 0, // Skip to: 752
/* 736 */     MCD_OPC_CheckPredicate, 21, 52, 4, // Skip to: 1816
/* 740 */     MCD_OPC_CheckField, 16, 10, 160, 4, 45, 4, // Skip to: 1816
/* 747 */     MCD_OPC_Decode, 143, 2, 200, 1, // Opcode: CEIL_W_D64
/* 752 */     MCD_OPC_FilterValue, 15, 16, 0, // Skip to: 772
/* 756 */     MCD_OPC_CheckPredicate, 21, 32, 4, // Skip to: 1816
/* 760 */     MCD_OPC_CheckField, 16, 10, 160, 4, 25, 4, // Skip to: 1816
/* 767 */     MCD_OPC_Decode, 224, 4, 200, 1, // Opcode: FLOOR_W_D64
/* 772 */     MCD_OPC_FilterValue, 17, 41, 0, // Skip to: 817
/* 776 */     MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 779 */     MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 798
/* 783 */     MCD_OPC_CheckPredicate, 21, 5, 4, // Skip to: 1816
/* 787 */     MCD_OPC_CheckField, 21, 5, 17, 255, 3, // Skip to: 1816
/* 793 */     MCD_OPC_Decode, 156, 7, 201, 1, // Opcode: MOVF_D64
/* 798 */     MCD_OPC_FilterValue, 1, 246, 3, // Skip to: 1816
/* 802 */     MCD_OPC_CheckPredicate, 21, 242, 3, // Skip to: 1816
/* 806 */     MCD_OPC_CheckField, 21, 5, 17, 236, 3, // Skip to: 1816
/* 812 */     MCD_OPC_Decode, 176, 7, 201, 1, // Opcode: MOVT_D64
/* 817 */     MCD_OPC_FilterValue, 18, 15, 0, // Skip to: 836
/* 821 */     MCD_OPC_CheckPredicate, 21, 223, 3, // Skip to: 1816
/* 825 */     MCD_OPC_CheckField, 21, 5, 17, 217, 3, // Skip to: 1816
/* 831 */     MCD_OPC_Decode, 188, 7, 202, 1, // Opcode: MOVZ_I_D64
/* 836 */     MCD_OPC_FilterValue, 19, 15, 0, // Skip to: 855
/* 840 */     MCD_OPC_CheckPredicate, 21, 204, 3, // Skip to: 1816
/* 844 */     MCD_OPC_CheckField, 21, 5, 17, 198, 3, // Skip to: 1816
/* 850 */     MCD_OPC_Decode, 168, 7, 202, 1, // Opcode: MOVN_I_D64
/* 855 */     MCD_OPC_FilterValue, 32, 31, 0, // Skip to: 890
/* 859 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 862 */     MCD_OPC_FilterValue, 160, 4, 9, 0, // Skip to: 876
/* 867 */     MCD_OPC_CheckPredicate, 21, 177, 3, // Skip to: 1816
/* 871 */     MCD_OPC_Decode, 233, 2, 200, 1, // Opcode: CVT_S_D64
/* 876 */     MCD_OPC_FilterValue, 160, 5, 167, 3, // Skip to: 1816
/* 881 */     MCD_OPC_CheckPredicate, 21, 163, 3, // Skip to: 1816
/* 885 */     MCD_OPC_Decode, 234, 2, 200, 1, // Opcode: CVT_S_L
/* 890 */     MCD_OPC_FilterValue, 33, 42, 0, // Skip to: 936
/* 894 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 897 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 910
/* 902 */     MCD_OPC_CheckPredicate, 21, 142, 3, // Skip to: 1816
/* 906 */     MCD_OPC_Decode, 224, 2, 70, // Opcode: CVT_D64_S
/* 910 */     MCD_OPC_FilterValue, 128, 5, 8, 0, // Skip to: 923
/* 915 */     MCD_OPC_CheckPredicate, 21, 129, 3, // Skip to: 1816
/* 919 */     MCD_OPC_Decode, 225, 2, 70, // Opcode: CVT_D64_W
/* 923 */     MCD_OPC_FilterValue, 160, 5, 120, 3, // Skip to: 1816
/* 928 */     MCD_OPC_CheckPredicate, 21, 116, 3, // Skip to: 1816
/* 932 */     MCD_OPC_Decode, 223, 2, 77, // Opcode: CVT_D64_L
/* 936 */     MCD_OPC_FilterValue, 36, 16, 0, // Skip to: 956
/* 940 */     MCD_OPC_CheckPredicate, 21, 104, 3, // Skip to: 1816
/* 944 */     MCD_OPC_CheckField, 16, 10, 160, 4, 97, 3, // Skip to: 1816
/* 951 */     MCD_OPC_Decode, 238, 2, 200, 1, // Opcode: CVT_W_D64
/* 956 */     MCD_OPC_FilterValue, 48, 21, 0, // Skip to: 981
/* 960 */     MCD_OPC_CheckPredicate, 21, 84, 3, // Skip to: 1816
/* 964 */     MCD_OPC_CheckField, 21, 5, 17, 78, 3, // Skip to: 1816
/* 970 */     MCD_OPC_CheckField, 6, 5, 0, 72, 3, // Skip to: 1816
/* 976 */     MCD_OPC_Decode, 246, 2, 203, 1, // Opcode: C_F_D64
/* 981 */     MCD_OPC_FilterValue, 49, 21, 0, // Skip to: 1006
/* 985 */     MCD_OPC_CheckPredicate, 21, 59, 3, // Skip to: 1816
/* 989 */     MCD_OPC_CheckField, 21, 5, 17, 53, 3, // Skip to: 1816
/* 995 */     MCD_OPC_CheckField, 6, 5, 0, 47, 3, // Skip to: 1816
/* 1001 */    MCD_OPC_Decode, 160, 3, 203, 1, // Opcode: C_UN_D64
/* 1006 */    MCD_OPC_FilterValue, 50, 21, 0, // Skip to: 1031
/* 1010 */    MCD_OPC_CheckPredicate, 21, 34, 3, // Skip to: 1816
/* 1014 */    MCD_OPC_CheckField, 21, 5, 17, 28, 3, // Skip to: 1816
/* 1020 */    MCD_OPC_CheckField, 6, 5, 0, 22, 3, // Skip to: 1816
/* 1026 */    MCD_OPC_Decode, 243, 2, 203, 1, // Opcode: C_EQ_D64
/* 1031 */    MCD_OPC_FilterValue, 51, 21, 0, // Skip to: 1056
/* 1035 */    MCD_OPC_CheckPredicate, 21, 9, 3, // Skip to: 1816
/* 1039 */    MCD_OPC_CheckField, 21, 5, 17, 3, 3, // Skip to: 1816
/* 1045 */    MCD_OPC_CheckField, 6, 5, 0, 253, 2, // Skip to: 1816
/* 1051 */    MCD_OPC_Decode, 151, 3, 203, 1, // Opcode: C_UEQ_D64
/* 1056 */    MCD_OPC_FilterValue, 52, 21, 0, // Skip to: 1081
/* 1060 */    MCD_OPC_CheckPredicate, 21, 240, 2, // Skip to: 1816
/* 1064 */    MCD_OPC_CheckField, 21, 5, 17, 234, 2, // Skip to: 1816
/* 1070 */    MCD_OPC_CheckField, 6, 5, 0, 228, 2, // Skip to: 1816
/* 1076 */    MCD_OPC_Decode, 142, 3, 203, 1, // Opcode: C_OLT_D64
/* 1081 */    MCD_OPC_FilterValue, 53, 21, 0, // Skip to: 1106
/* 1085 */    MCD_OPC_CheckPredicate, 21, 215, 2, // Skip to: 1816
/* 1089 */    MCD_OPC_CheckField, 21, 5, 17, 209, 2, // Skip to: 1816
/* 1095 */    MCD_OPC_CheckField, 6, 5, 0, 203, 2, // Skip to: 1816
/* 1101 */    MCD_OPC_Decode, 157, 3, 203, 1, // Opcode: C_ULT_D64
/* 1106 */    MCD_OPC_FilterValue, 54, 21, 0, // Skip to: 1131
/* 1110 */    MCD_OPC_CheckPredicate, 21, 190, 2, // Skip to: 1816
/* 1114 */    MCD_OPC_CheckField, 21, 5, 17, 184, 2, // Skip to: 1816
/* 1120 */    MCD_OPC_CheckField, 6, 5, 0, 178, 2, // Skip to: 1816
/* 1126 */    MCD_OPC_Decode, 139, 3, 203, 1, // Opcode: C_OLE_D64
/* 1131 */    MCD_OPC_FilterValue, 55, 21, 0, // Skip to: 1156
/* 1135 */    MCD_OPC_CheckPredicate, 21, 165, 2, // Skip to: 1816
/* 1139 */    MCD_OPC_CheckField, 21, 5, 17, 159, 2, // Skip to: 1816
/* 1145 */    MCD_OPC_CheckField, 6, 5, 0, 153, 2, // Skip to: 1816
/* 1151 */    MCD_OPC_Decode, 154, 3, 203, 1, // Opcode: C_ULE_D64
/* 1156 */    MCD_OPC_FilterValue, 56, 21, 0, // Skip to: 1181
/* 1160 */    MCD_OPC_CheckPredicate, 21, 140, 2, // Skip to: 1816
/* 1164 */    MCD_OPC_CheckField, 21, 5, 17, 134, 2, // Skip to: 1816
/* 1170 */    MCD_OPC_CheckField, 6, 5, 0, 128, 2, // Skip to: 1816
/* 1176 */    MCD_OPC_Decode, 148, 3, 203, 1, // Opcode: C_SF_D64
/* 1181 */    MCD_OPC_FilterValue, 57, 21, 0, // Skip to: 1206
/* 1185 */    MCD_OPC_CheckPredicate, 21, 115, 2, // Skip to: 1816
/* 1189 */    MCD_OPC_CheckField, 21, 5, 17, 109, 2, // Skip to: 1816
/* 1195 */    MCD_OPC_CheckField, 6, 5, 0, 103, 2, // Skip to: 1816
/* 1201 */    MCD_OPC_Decode, 130, 3, 203, 1, // Opcode: C_NGLE_D64
/* 1206 */    MCD_OPC_FilterValue, 58, 21, 0, // Skip to: 1231
/* 1210 */    MCD_OPC_CheckPredicate, 21, 90, 2, // Skip to: 1816
/* 1214 */    MCD_OPC_CheckField, 21, 5, 17, 84, 2, // Skip to: 1816
/* 1220 */    MCD_OPC_CheckField, 6, 5, 0, 78, 2, // Skip to: 1816
/* 1226 */    MCD_OPC_Decode, 145, 3, 203, 1, // Opcode: C_SEQ_D64
/* 1231 */    MCD_OPC_FilterValue, 59, 21, 0, // Skip to: 1256
/* 1235 */    MCD_OPC_CheckPredicate, 21, 65, 2, // Skip to: 1816
/* 1239 */    MCD_OPC_CheckField, 21, 5, 17, 59, 2, // Skip to: 1816
/* 1245 */    MCD_OPC_CheckField, 6, 5, 0, 53, 2, // Skip to: 1816
/* 1251 */    MCD_OPC_Decode, 133, 3, 203, 1, // Opcode: C_NGL_D64
/* 1256 */    MCD_OPC_FilterValue, 60, 21, 0, // Skip to: 1281
/* 1260 */    MCD_OPC_CheckPredicate, 21, 40, 2, // Skip to: 1816
/* 1264 */    MCD_OPC_CheckField, 21, 5, 17, 34, 2, // Skip to: 1816
/* 1270 */    MCD_OPC_CheckField, 6, 5, 0, 28, 2, // Skip to: 1816
/* 1276 */    MCD_OPC_Decode, 252, 2, 203, 1, // Opcode: C_LT_D64
/* 1281 */    MCD_OPC_FilterValue, 61, 21, 0, // Skip to: 1306
/* 1285 */    MCD_OPC_CheckPredicate, 21, 15, 2, // Skip to: 1816
/* 1289 */    MCD_OPC_CheckField, 21, 5, 17, 9, 2, // Skip to: 1816
/* 1295 */    MCD_OPC_CheckField, 6, 5, 0, 3, 2, // Skip to: 1816
/* 1301 */    MCD_OPC_Decode, 255, 2, 203, 1, // Opcode: C_NGE_D64
/* 1306 */    MCD_OPC_FilterValue, 62, 21, 0, // Skip to: 1331
/* 1310 */    MCD_OPC_CheckPredicate, 21, 246, 1, // Skip to: 1816
/* 1314 */    MCD_OPC_CheckField, 21, 5, 17, 240, 1, // Skip to: 1816
/* 1320 */    MCD_OPC_CheckField, 6, 5, 0, 234, 1, // Skip to: 1816
/* 1326 */    MCD_OPC_Decode, 249, 2, 203, 1, // Opcode: C_LE_D64
/* 1331 */    MCD_OPC_FilterValue, 63, 225, 1, // Skip to: 1816
/* 1335 */    MCD_OPC_CheckPredicate, 21, 221, 1, // Skip to: 1816
/* 1339 */    MCD_OPC_CheckField, 21, 5, 17, 215, 1, // Skip to: 1816
/* 1345 */    MCD_OPC_CheckField, 6, 5, 0, 209, 1, // Skip to: 1816
/* 1351 */    MCD_OPC_Decode, 136, 3, 203, 1, // Opcode: C_NGT_D64
/* 1356 */    MCD_OPC_FilterValue, 18, 41, 0, // Skip to: 1401
/* 1360 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1363 */    MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 1382
/* 1367 */    MCD_OPC_CheckPredicate, 20, 189, 1, // Skip to: 1816
/* 1371 */    MCD_OPC_CheckField, 3, 8, 0, 183, 1, // Skip to: 1816
/* 1377 */    MCD_OPC_Decode, 193, 3, 198, 1, // Opcode: DMFC2
/* 1382 */    MCD_OPC_FilterValue, 5, 174, 1, // Skip to: 1816
/* 1386 */    MCD_OPC_CheckPredicate, 20, 170, 1, // Skip to: 1816
/* 1390 */    MCD_OPC_CheckField, 3, 8, 0, 164, 1, // Skip to: 1816
/* 1396 */    MCD_OPC_Decode, 196, 3, 198, 1, // Opcode: DMTC2
/* 1401 */    MCD_OPC_FilterValue, 19, 79, 0, // Skip to: 1484
/* 1405 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1408 */    MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 1427
/* 1412 */    MCD_OPC_CheckPredicate, 22, 144, 1, // Skip to: 1816
/* 1416 */    MCD_OPC_CheckField, 11, 5, 0, 138, 1, // Skip to: 1816
/* 1422 */    MCD_OPC_Decode, 132, 6, 204, 1, // Opcode: LDXC164
/* 1427 */    MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 1446
/* 1431 */    MCD_OPC_CheckPredicate, 21, 125, 1, // Skip to: 1816
/* 1435 */    MCD_OPC_CheckField, 11, 5, 0, 119, 1, // Skip to: 1816
/* 1441 */    MCD_OPC_Decode, 156, 6, 204, 1, // Opcode: LUXC164
/* 1446 */    MCD_OPC_FilterValue, 9, 15, 0, // Skip to: 1465
/* 1450 */    MCD_OPC_CheckPredicate, 22, 106, 1, // Skip to: 1816
/* 1454 */    MCD_OPC_CheckField, 6, 5, 0, 100, 1, // Skip to: 1816
/* 1460 */    MCD_OPC_Decode, 163, 9, 205, 1, // Opcode: SDXC164
/* 1465 */    MCD_OPC_FilterValue, 13, 91, 1, // Skip to: 1816
/* 1469 */    MCD_OPC_CheckPredicate, 21, 87, 1, // Skip to: 1816
/* 1473 */    MCD_OPC_CheckField, 6, 5, 0, 81, 1, // Skip to: 1816
/* 1479 */    MCD_OPC_Decode, 209, 10, 205, 1, // Opcode: SUXC164
/* 1484 */    MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 1497
/* 1488 */    MCD_OPC_CheckPredicate, 2, 68, 1, // Skip to: 1816
/* 1492 */    MCD_OPC_Decode, 167, 3, 206, 1, // Opcode: DADDi
/* 1497 */    MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 1510
/* 1501 */    MCD_OPC_CheckPredicate, 2, 55, 1, // Skip to: 1816
/* 1505 */    MCD_OPC_Decode, 168, 3, 206, 1, // Opcode: DADDiu
/* 1510 */    MCD_OPC_FilterValue, 26, 9, 0, // Skip to: 1523
/* 1514 */    MCD_OPC_CheckPredicate, 2, 42, 1, // Skip to: 1816
/* 1518 */    MCD_OPC_Decode, 129, 6, 192, 1, // Opcode: LDL
/* 1523 */    MCD_OPC_FilterValue, 27, 9, 0, // Skip to: 1536
/* 1527 */    MCD_OPC_CheckPredicate, 2, 29, 1, // Skip to: 1816
/* 1531 */    MCD_OPC_Decode, 130, 6, 192, 1, // Opcode: LDR
/* 1536 */    MCD_OPC_FilterValue, 28, 29, 0, // Skip to: 1569
/* 1540 */    MCD_OPC_ExtractField, 0, 11,  // Inst{10-0} ...
/* 1543 */    MCD_OPC_FilterValue, 36, 9, 0, // Skip to: 1556
/* 1547 */    MCD_OPC_CheckPredicate, 14, 9, 1, // Skip to: 1816
/* 1551 */    MCD_OPC_Decode, 171, 3, 207, 1, // Opcode: DCLZ
/* 1556 */    MCD_OPC_FilterValue, 37, 0, 1, // Skip to: 1816
/* 1560 */    MCD_OPC_CheckPredicate, 14, 252, 0, // Skip to: 1816
/* 1564 */    MCD_OPC_Decode, 170, 3, 207, 1, // Opcode: DCLO
/* 1569 */    MCD_OPC_FilterValue, 31, 126, 0, // Skip to: 1699
/* 1573 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1576 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 1589
/* 1580 */    MCD_OPC_CheckPredicate, 3, 232, 0, // Skip to: 1816
/* 1584 */    MCD_OPC_Decode, 175, 3, 208, 1, // Opcode: DEXTM
/* 1589 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 1602
/* 1593 */    MCD_OPC_CheckPredicate, 3, 219, 0, // Skip to: 1816
/* 1597 */    MCD_OPC_Decode, 176, 3, 208, 1, // Opcode: DEXTU
/* 1602 */    MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 1615
/* 1606 */    MCD_OPC_CheckPredicate, 3, 206, 0, // Skip to: 1816
/* 1610 */    MCD_OPC_Decode, 174, 3, 208, 1, // Opcode: DEXT
/* 1615 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 1628
/* 1619 */    MCD_OPC_CheckPredicate, 3, 193, 0, // Skip to: 1816
/* 1623 */    MCD_OPC_Decode, 179, 3, 209, 1, // Opcode: DINSM
/* 1628 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 1641
/* 1632 */    MCD_OPC_CheckPredicate, 3, 180, 0, // Skip to: 1816
/* 1636 */    MCD_OPC_Decode, 180, 3, 209, 1, // Opcode: DINSU
/* 1641 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 1654
/* 1645 */    MCD_OPC_CheckPredicate, 3, 167, 0, // Skip to: 1816
/* 1649 */    MCD_OPC_Decode, 178, 3, 209, 1, // Opcode: DINS
/* 1654 */    MCD_OPC_FilterValue, 36, 158, 0, // Skip to: 1816
/* 1658 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 1661 */    MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 1680
/* 1665 */    MCD_OPC_CheckPredicate, 16, 147, 0, // Skip to: 1816
/* 1669 */    MCD_OPC_CheckField, 21, 5, 0, 141, 0, // Skip to: 1816
/* 1675 */    MCD_OPC_Decode, 236, 3, 210, 1, // Opcode: DSBH
/* 1680 */    MCD_OPC_FilterValue, 5, 132, 0, // Skip to: 1816
/* 1684 */    MCD_OPC_CheckPredicate, 16, 128, 0, // Skip to: 1816
/* 1688 */    MCD_OPC_CheckField, 21, 5, 0, 122, 0, // Skip to: 1816
/* 1694 */    MCD_OPC_Decode, 238, 3, 210, 1, // Opcode: DSHD
/* 1699 */    MCD_OPC_FilterValue, 39, 9, 0, // Skip to: 1712
/* 1703 */    MCD_OPC_CheckPredicate, 2, 109, 0, // Skip to: 1816
/* 1707 */    MCD_OPC_Decode, 177, 6, 192, 1, // Opcode: LWu
/* 1712 */    MCD_OPC_FilterValue, 44, 9, 0, // Skip to: 1725
/* 1716 */    MCD_OPC_CheckPredicate, 2, 96, 0, // Skip to: 1816
/* 1720 */    MCD_OPC_Decode, 160, 9, 192, 1, // Opcode: SDL
/* 1725 */    MCD_OPC_FilterValue, 45, 9, 0, // Skip to: 1738
/* 1729 */    MCD_OPC_CheckPredicate, 2, 83, 0, // Skip to: 1816
/* 1733 */    MCD_OPC_Decode, 161, 9, 192, 1, // Opcode: SDR
/* 1738 */    MCD_OPC_FilterValue, 52, 9, 0, // Skip to: 1751
/* 1742 */    MCD_OPC_CheckPredicate, 2, 70, 0, // Skip to: 1816
/* 1746 */    MCD_OPC_Decode, 148, 6, 192, 1, // Opcode: LLD
/* 1751 */    MCD_OPC_FilterValue, 53, 9, 0, // Skip to: 1764
/* 1755 */    MCD_OPC_CheckPredicate, 21, 57, 0, // Skip to: 1816
/* 1759 */    MCD_OPC_Decode, 250, 5, 193, 1, // Opcode: LDC164
/* 1764 */    MCD_OPC_FilterValue, 55, 9, 0, // Skip to: 1777
/* 1768 */    MCD_OPC_CheckPredicate, 2, 44, 0, // Skip to: 1816
/* 1772 */    MCD_OPC_Decode, 248, 5, 192, 1, // Opcode: LD
/* 1777 */    MCD_OPC_FilterValue, 60, 9, 0, // Skip to: 1790
/* 1781 */    MCD_OPC_CheckPredicate, 2, 31, 0, // Skip to: 1816
/* 1785 */    MCD_OPC_Decode, 151, 9, 192, 1, // Opcode: SCD
/* 1790 */    MCD_OPC_FilterValue, 61, 9, 0, // Skip to: 1803
/* 1794 */    MCD_OPC_CheckPredicate, 21, 18, 0, // Skip to: 1816
/* 1798 */    MCD_OPC_Decode, 155, 9, 193, 1, // Opcode: SDC164
/* 1803 */    MCD_OPC_FilterValue, 63, 9, 0, // Skip to: 1816
/* 1807 */    MCD_OPC_CheckPredicate, 2, 5, 0, // Skip to: 1816
/* 1811 */    MCD_OPC_Decode, 153, 9, 192, 1, // Opcode: SD
/* 1816 */    MCD_OPC_Fail,
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
    return getbool((Bits & Mips_FeatureMicroMips));
  case 2:
    return getbool(!(Bits & Mips_FeatureMips16));
  case 3:
    return getbool((Bits & Mips_FeatureMips32r2) && !(Bits & Mips_FeatureMips16));
  case 4:
    return getbool((Bits & Mips_FeatureMSA));
  case 5:
    return getbool((Bits & Mips_FeatureDSP));
  case 6:
    return getbool((Bits & Mips_FeatureMSA) && (Bits & Mips_FeatureMips64));
  case 7:
    return getbool((Bits & Mips_FeatureMips32) && !(Bits & Mips_FeatureMips16));
  case 8:
    return getbool(!(Bits & Mips_FeatureFP64Bit) && !(Bits & Mips_FeatureMips16));
  case 9:
    return getbool((Bits & Mips_FeatureFPIdx) && !(Bits & Mips_FeatureMips16));
  case 10:
    return getbool((Bits & Mips_FeatureFPIdx) && !(Bits & Mips_FeatureFP64Bit) && !(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMicroMips));
  case 11:
    return getbool((Bits & Mips_FeatureMips32r2) && !(Bits & Mips_FeatureFP64Bit) && !(Bits & Mips_FeatureMips16));
  case 12:
    return getbool((Bits & Mips_FeatureMips32r2) && (Bits & Mips_FeatureMips32) && !(Bits & Mips_FeatureMips16));
  case 13:
    return getbool((Bits & Mips_FeatureMips32r2) && !(Bits & Mips_FeatureFP64Bit) && (Bits & Mips_FeatureMips32) && !(Bits & Mips_FeatureMips16));
  case 14:
    return getbool((Bits & Mips_FeatureBitCount) && !(Bits & Mips_FeatureMips16));
  case 15:
    return getbool((Bits & Mips_FeatureDSPR2));
  case 16:
    return getbool((Bits & Mips_FeatureSwap) && !(Bits & Mips_FeatureMips16));
  case 17:
    return getbool((Bits & Mips_FeatureSEInReg) && !(Bits & Mips_FeatureMips16));
  case 18:
    return getbool(!(Bits & Mips_FeatureMicroMips));
  case 19:
    return getbool((Bits & Mips_FeatureMips64r2) && !(Bits & Mips_FeatureMips16));
  case 20:
    return getbool((Bits & Mips_FeatureMips64));
  case 21:
    return getbool((Bits & Mips_FeatureFP64Bit) && !(Bits & Mips_FeatureMips16));
  case 22:
    return getbool((Bits & Mips_FeatureFPIdx) && (Bits & Mips_FeatureFP64Bit) && !(Bits & Mips_FeatureMips16));
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
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 11: \
    tmp = fieldname(insn, 16, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 6, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 12: \
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
  case 13: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 14: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 15: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 16: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeExtSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 17: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 18: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 19: \
    tmp = fieldname(insn, 16, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 20: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 21: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 22: \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 23: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 24: \
    if (DecodeMemMMImm16(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 25: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTargetMM(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 26: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 27: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 28: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 13, 3); \
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 29: \
    if (DecodeMemMMImm12(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 30: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTargetMM(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 31: \
    if (DecodeJumpTargetMM(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 32: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 33: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 18, 3); \
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 34: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 2); \
    if (DecodeLSAImm(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 35: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 36: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 37: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 38: \
    tmp = fieldname(insn, 6, 20); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 39: \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 40: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 41: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 42: \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeHI32DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 43: \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeLO32DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 44: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 2); \
    if (DecodeLSAImm(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 45: \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 46: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 47: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 48: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 49: \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 50: \
    if (DecodeJumpTarget(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 51: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 52: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 53: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 54: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 55: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 56: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 57: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeCCRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 58: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGRH32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 59: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 60: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 61: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeCCRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 62: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGRH32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 63: \
    tmp = fieldname(insn, 18, 3); \
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 64: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 65: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 66: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 67: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 18, 3); \
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 68: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 69: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 70: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 71: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 72: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 73: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 74: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 75: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 18, 3); \
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 76: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 77: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 78: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 79: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 80: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 81: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 82: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 83: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 84: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 85: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 86: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 87: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 88: \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 89: \
    tmp = 0; \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    tmp |= (fieldname(insn, 16, 5) << 0); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 90: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 91: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 92: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 93: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 94: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 95: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 96: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 97: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 98: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 99: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 100: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 101: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 102: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 6); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 103: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 104: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 105: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 6); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 106: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 107: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 108: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 109: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 110: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 111: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 112: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 113: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 114: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 115: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 116: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 117: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 118: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 119: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 120: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
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
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 123: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 124: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 125: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 126: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 127: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 128: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 129: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 130: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 131: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 132: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 133: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 134: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 135: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSACtrlRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 136: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 137: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 138: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 139: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 140: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSACtrlRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 141: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 142: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 143: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 144: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 145: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 146: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 147: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 148: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 149: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 150: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 151: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 152: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 153: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
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
    if (DecodeFMem(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 194: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 195: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 196: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 197: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 198: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 199: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 200: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 201: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 18, 3); \
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 202: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 203: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 204: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 205: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 206: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 207: \
    tmp = 0; \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    tmp |= (fieldname(insn, 16, 5) << 0); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 208: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeExtSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 209: \
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
  case 210: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
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
      Opc = (uint32_t)decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      DecodeIdx = (uint32_t)decodeULEB128(Ptr, &Len); \
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
