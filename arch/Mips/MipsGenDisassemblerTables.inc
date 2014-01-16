/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* * Mips Disassembler                                                        *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

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
/* 21 */      MCD_OPC_CheckPredicate, 1, 249, 4, // Skip to: 1298
/* 25 */      MCD_OPC_Decode, 214, 9, 10, // Opcode: SLL_MM
/* 29 */      MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 41
/* 33 */      MCD_OPC_CheckPredicate, 1, 237, 4, // Skip to: 1298
/* 37 */      MCD_OPC_Decode, 151, 10, 10, // Opcode: SRL_MM
/* 41 */      MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 53
/* 45 */      MCD_OPC_CheckPredicate, 1, 225, 4, // Skip to: 1298
/* 49 */      MCD_OPC_Decode, 131, 10, 10, // Opcode: SRA_MM
/* 53 */      MCD_OPC_FilterValue, 3, 217, 4, // Skip to: 1298
/* 57 */      MCD_OPC_CheckPredicate, 1, 213, 4, // Skip to: 1298
/* 61 */      MCD_OPC_Decode, 249, 8, 10, // Opcode: ROTR_MM
/* 65 */      MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 77
/* 69 */      MCD_OPC_CheckPredicate, 1, 201, 4, // Skip to: 1298
/* 73 */      MCD_OPC_Decode, 222, 1, 11, // Opcode: BREAK_MM
/* 77 */      MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 89
/* 81 */      MCD_OPC_CheckPredicate, 1, 189, 4, // Skip to: 1298
/* 85 */      MCD_OPC_Decode, 217, 5, 12, // Opcode: INS_MM
/* 89 */      MCD_OPC_FilterValue, 16, 180, 0, // Skip to: 273
/* 93 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 96 */      MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 108
/* 100 */     MCD_OPC_CheckPredicate, 1, 170, 4, // Skip to: 1298
/* 104 */     MCD_OPC_Decode, 210, 9, 13, // Opcode: SLLV_MM
/* 108 */     MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 120
/* 112 */     MCD_OPC_CheckPredicate, 1, 158, 4, // Skip to: 1298
/* 116 */     MCD_OPC_Decode, 147, 10, 13, // Opcode: SRLV_MM
/* 120 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 132
/* 124 */     MCD_OPC_CheckPredicate, 1, 146, 4, // Skip to: 1298
/* 128 */     MCD_OPC_Decode, 255, 9, 13, // Opcode: SRAV_MM
/* 132 */     MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 144
/* 136 */     MCD_OPC_CheckPredicate, 1, 134, 4, // Skip to: 1298
/* 140 */     MCD_OPC_Decode, 248, 8, 13, // Opcode: ROTRV_MM
/* 144 */     MCD_OPC_FilterValue, 4, 7, 0, // Skip to: 155
/* 148 */     MCD_OPC_CheckPredicate, 1, 122, 4, // Skip to: 1298
/* 152 */     MCD_OPC_Decode, 62, 14, // Opcode: ADD_MM
/* 155 */     MCD_OPC_FilterValue, 5, 7, 0, // Skip to: 166
/* 159 */     MCD_OPC_CheckPredicate, 1, 111, 4, // Skip to: 1298
/* 163 */     MCD_OPC_Decode, 68, 14, // Opcode: ADDu_MM
/* 166 */     MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 178
/* 170 */     MCD_OPC_CheckPredicate, 1, 100, 4, // Skip to: 1298
/* 174 */     MCD_OPC_Decode, 199, 10, 14, // Opcode: SUB_MM
/* 178 */     MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 190
/* 182 */     MCD_OPC_CheckPredicate, 1, 88, 4, // Skip to: 1298
/* 186 */     MCD_OPC_Decode, 201, 10, 14, // Opcode: SUBu_MM
/* 190 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 202
/* 194 */     MCD_OPC_CheckPredicate, 1, 76, 4, // Skip to: 1298
/* 198 */     MCD_OPC_Decode, 245, 7, 14, // Opcode: MUL_MM
/* 202 */     MCD_OPC_FilterValue, 9, 7, 0, // Skip to: 213
/* 206 */     MCD_OPC_CheckPredicate, 1, 64, 4, // Skip to: 1298
/* 210 */     MCD_OPC_Decode, 74, 14, // Opcode: AND_MM
/* 213 */     MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 225
/* 217 */     MCD_OPC_CheckPredicate, 1, 53, 4, // Skip to: 1298
/* 221 */     MCD_OPC_Decode, 162, 8, 14, // Opcode: OR_MM
/* 225 */     MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 237
/* 229 */     MCD_OPC_CheckPredicate, 1, 41, 4, // Skip to: 1298
/* 233 */     MCD_OPC_Decode, 152, 8, 14, // Opcode: NOR_MM
/* 237 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 249
/* 241 */     MCD_OPC_CheckPredicate, 1, 29, 4, // Skip to: 1298
/* 245 */     MCD_OPC_Decode, 189, 11, 14, // Opcode: XOR_MM
/* 249 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 261
/* 253 */     MCD_OPC_CheckPredicate, 1, 17, 4, // Skip to: 1298
/* 257 */     MCD_OPC_Decode, 218, 9, 14, // Opcode: SLT_MM
/* 261 */     MCD_OPC_FilterValue, 14, 9, 4, // Skip to: 1298
/* 265 */     MCD_OPC_CheckPredicate, 1, 5, 4, // Skip to: 1298
/* 269 */     MCD_OPC_Decode, 227, 9, 14, // Opcode: SLTu_MM
/* 273 */     MCD_OPC_FilterValue, 24, 27, 0, // Skip to: 304
/* 277 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 280 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 292
/* 284 */     MCD_OPC_CheckPredicate, 1, 242, 3, // Skip to: 1298
/* 288 */     MCD_OPC_Decode, 165, 7, 15, // Opcode: MOVN_I_MM
/* 292 */     MCD_OPC_FilterValue, 1, 234, 3, // Skip to: 1298
/* 296 */     MCD_OPC_CheckPredicate, 1, 230, 3, // Skip to: 1298
/* 300 */     MCD_OPC_Decode, 185, 7, 15, // Opcode: MOVZ_I_MM
/* 304 */     MCD_OPC_FilterValue, 44, 8, 0, // Skip to: 316
/* 308 */     MCD_OPC_CheckPredicate, 1, 218, 3, // Skip to: 1298
/* 312 */     MCD_OPC_Decode, 139, 4, 16, // Opcode: EXT_MM
/* 316 */     MCD_OPC_FilterValue, 60, 210, 3, // Skip to: 1298
/* 320 */     MCD_OPC_ExtractField, 6, 6,  // Inst{11-6} ...
/* 323 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 335
/* 327 */     MCD_OPC_CheckPredicate, 1, 199, 3, // Skip to: 1298
/* 331 */     MCD_OPC_Decode, 146, 11, 17, // Opcode: TEQ_MM
/* 335 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 347
/* 339 */     MCD_OPC_CheckPredicate, 1, 187, 3, // Skip to: 1298
/* 343 */     MCD_OPC_Decode, 154, 11, 17, // Opcode: TGE_MM
/* 347 */     MCD_OPC_FilterValue, 13, 39, 0, // Skip to: 390
/* 351 */     MCD_OPC_ExtractField, 12, 14,  // Inst{25-12} ...
/* 354 */     MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 366
/* 358 */     MCD_OPC_CheckPredicate, 1, 168, 3, // Skip to: 1298
/* 362 */     MCD_OPC_Decode, 182, 11, 0, // Opcode: WAIT_MM
/* 366 */     MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 378
/* 370 */     MCD_OPC_CheckPredicate, 1, 156, 3, // Skip to: 1298
/* 374 */     MCD_OPC_Decode, 171, 3, 0, // Opcode: DERET_MM
/* 378 */     MCD_OPC_FilterValue, 15, 148, 3, // Skip to: 1298
/* 382 */     MCD_OPC_CheckPredicate, 1, 144, 3, // Skip to: 1298
/* 386 */     MCD_OPC_Decode, 253, 3, 0, // Opcode: ERET_MM
/* 390 */     MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 402
/* 394 */     MCD_OPC_CheckPredicate, 1, 132, 3, // Skip to: 1298
/* 398 */     MCD_OPC_Decode, 153, 11, 17, // Opcode: TGEU_MM
/* 402 */     MCD_OPC_FilterValue, 29, 39, 0, // Skip to: 445
/* 406 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 409 */     MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 427
/* 413 */     MCD_OPC_CheckPredicate, 1, 113, 3, // Skip to: 1298
/* 417 */     MCD_OPC_CheckField, 21, 5, 0, 107, 3, // Skip to: 1298
/* 423 */     MCD_OPC_Decode, 187, 3, 18, // Opcode: DI_MM
/* 427 */     MCD_OPC_FilterValue, 5, 99, 3, // Skip to: 1298
/* 431 */     MCD_OPC_CheckPredicate, 1, 95, 3, // Skip to: 1298
/* 435 */     MCD_OPC_CheckField, 21, 5, 0, 89, 3, // Skip to: 1298
/* 441 */     MCD_OPC_Decode, 251, 3, 18, // Opcode: EI_MM
/* 445 */     MCD_OPC_FilterValue, 32, 8, 0, // Skip to: 457
/* 449 */     MCD_OPC_CheckPredicate, 1, 77, 3, // Skip to: 1298
/* 453 */     MCD_OPC_Decode, 161, 11, 17, // Opcode: TLT_MM
/* 457 */     MCD_OPC_FilterValue, 40, 8, 0, // Skip to: 469
/* 461 */     MCD_OPC_CheckPredicate, 1, 65, 3, // Skip to: 1298
/* 465 */     MCD_OPC_Decode, 160, 11, 17, // Opcode: TLTU_MM
/* 469 */     MCD_OPC_FilterValue, 43, 14, 0, // Skip to: 487
/* 473 */     MCD_OPC_CheckPredicate, 1, 53, 3, // Skip to: 1298
/* 477 */     MCD_OPC_CheckField, 12, 4, 8, 47, 3, // Skip to: 1298
/* 483 */     MCD_OPC_Decode, 222, 10, 19, // Opcode: SYSCALL_MM
/* 487 */     MCD_OPC_FilterValue, 44, 159, 0, // Skip to: 650
/* 491 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 494 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 506
/* 498 */     MCD_OPC_CheckPredicate, 1, 28, 3, // Skip to: 1298
/* 502 */     MCD_OPC_Decode, 160, 9, 20, // Opcode: SEB_MM
/* 506 */     MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 518
/* 510 */     MCD_OPC_CheckPredicate, 1, 16, 3, // Skip to: 1298
/* 514 */     MCD_OPC_Decode, 163, 9, 20, // Opcode: SEH_MM
/* 518 */     MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 530
/* 522 */     MCD_OPC_CheckPredicate, 1, 4, 3, // Skip to: 1298
/* 526 */     MCD_OPC_Decode, 175, 2, 20, // Opcode: CLO_MM
/* 530 */     MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 542
/* 534 */     MCD_OPC_CheckPredicate, 1, 248, 2, // Skip to: 1298
/* 538 */     MCD_OPC_Decode, 193, 2, 20, // Opcode: CLZ_MM
/* 542 */     MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 554
/* 546 */     MCD_OPC_CheckPredicate, 1, 236, 2, // Skip to: 1298
/* 550 */     MCD_OPC_Decode, 185, 11, 20, // Opcode: WSBH_MM
/* 554 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 566
/* 558 */     MCD_OPC_CheckPredicate, 1, 224, 2, // Skip to: 1298
/* 562 */     MCD_OPC_Decode, 238, 7, 21, // Opcode: MULT_MM
/* 566 */     MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 578
/* 570 */     MCD_OPC_CheckPredicate, 1, 212, 2, // Skip to: 1298
/* 574 */     MCD_OPC_Decode, 240, 7, 21, // Opcode: MULTu_MM
/* 578 */     MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 590
/* 582 */     MCD_OPC_CheckPredicate, 1, 200, 2, // Skip to: 1298
/* 586 */     MCD_OPC_Decode, 153, 9, 21, // Opcode: SDIV_MM
/* 590 */     MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 602
/* 594 */     MCD_OPC_CheckPredicate, 1, 188, 2, // Skip to: 1298
/* 598 */     MCD_OPC_Decode, 176, 11, 21, // Opcode: UDIV_MM
/* 602 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 614
/* 606 */     MCD_OPC_CheckPredicate, 1, 176, 2, // Skip to: 1298
/* 610 */     MCD_OPC_Decode, 201, 6, 21, // Opcode: MADD_MM
/* 614 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 626
/* 618 */     MCD_OPC_CheckPredicate, 1, 164, 2, // Skip to: 1298
/* 622 */     MCD_OPC_Decode, 192, 6, 21, // Opcode: MADDU_MM
/* 626 */     MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 638
/* 630 */     MCD_OPC_CheckPredicate, 1, 152, 2, // Skip to: 1298
/* 634 */     MCD_OPC_Decode, 202, 7, 21, // Opcode: MSUB_MM
/* 638 */     MCD_OPC_FilterValue, 15, 144, 2, // Skip to: 1298
/* 642 */     MCD_OPC_CheckPredicate, 1, 140, 2, // Skip to: 1298
/* 646 */     MCD_OPC_Decode, 193, 7, 21, // Opcode: MSUBU_MM
/* 650 */     MCD_OPC_FilterValue, 45, 20, 0, // Skip to: 674
/* 654 */     MCD_OPC_CheckPredicate, 1, 128, 2, // Skip to: 1298
/* 658 */     MCD_OPC_CheckField, 21, 5, 0, 122, 2, // Skip to: 1298
/* 664 */     MCD_OPC_CheckField, 12, 4, 6, 116, 2, // Skip to: 1298
/* 670 */     MCD_OPC_Decode, 220, 10, 22, // Opcode: SYNC_MM
/* 674 */     MCD_OPC_FilterValue, 48, 8, 0, // Skip to: 686
/* 678 */     MCD_OPC_CheckPredicate, 1, 104, 2, // Skip to: 1298
/* 682 */     MCD_OPC_Decode, 165, 11, 17, // Opcode: TNE_MM
/* 686 */     MCD_OPC_FilterValue, 53, 75, 0, // Skip to: 765
/* 690 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 693 */     MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 711
/* 697 */     MCD_OPC_CheckPredicate, 1, 85, 2, // Skip to: 1298
/* 701 */     MCD_OPC_CheckField, 21, 5, 0, 79, 2, // Skip to: 1298
/* 707 */     MCD_OPC_Decode, 239, 6, 18, // Opcode: MFHI_MM
/* 711 */     MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 729
/* 715 */     MCD_OPC_CheckPredicate, 1, 67, 2, // Skip to: 1298
/* 719 */     MCD_OPC_CheckField, 21, 5, 0, 61, 2, // Skip to: 1298
/* 725 */     MCD_OPC_Decode, 243, 6, 18, // Opcode: MFLO_MM
/* 729 */     MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 747
/* 733 */     MCD_OPC_CheckPredicate, 1, 49, 2, // Skip to: 1298
/* 737 */     MCD_OPC_CheckField, 21, 5, 0, 43, 2, // Skip to: 1298
/* 743 */     MCD_OPC_Decode, 216, 7, 18, // Opcode: MTHI_MM
/* 747 */     MCD_OPC_FilterValue, 3, 35, 2, // Skip to: 1298
/* 751 */     MCD_OPC_CheckPredicate, 1, 31, 2, // Skip to: 1298
/* 755 */     MCD_OPC_CheckField, 21, 5, 0, 25, 2, // Skip to: 1298
/* 761 */     MCD_OPC_Decode, 221, 7, 18, // Opcode: MTLO_MM
/* 765 */     MCD_OPC_FilterValue, 60, 17, 2, // Skip to: 1298
/* 769 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 772 */     MCD_OPC_FilterValue, 0, 10, 2, // Skip to: 1298
/* 776 */     MCD_OPC_CheckPredicate, 1, 10, 0, // Skip to: 790
/* 780 */     MCD_OPC_CheckField, 21, 5, 0, 4, 0, // Skip to: 790
/* 786 */     MCD_OPC_Decode, 228, 5, 18, // Opcode: JR_MM
/* 790 */     MCD_OPC_CheckPredicate, 1, 248, 1, // Skip to: 1298
/* 794 */     MCD_OPC_Decode, 224, 5, 20, // Opcode: JALR_MM
/* 798 */     MCD_OPC_FilterValue, 4, 7, 0, // Skip to: 809
/* 802 */     MCD_OPC_CheckPredicate, 1, 236, 1, // Skip to: 1298
/* 806 */     MCD_OPC_Decode, 64, 23, // Opcode: ADDi_MM
/* 809 */     MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 821
/* 813 */     MCD_OPC_CheckPredicate, 1, 225, 1, // Skip to: 1298
/* 817 */     MCD_OPC_Decode, 242, 5, 24, // Opcode: LBu_MM
/* 821 */     MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 833
/* 825 */     MCD_OPC_CheckPredicate, 1, 213, 1, // Skip to: 1298
/* 829 */     MCD_OPC_Decode, 143, 9, 24, // Opcode: SB_MM
/* 833 */     MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 845
/* 837 */     MCD_OPC_CheckPredicate, 1, 201, 1, // Skip to: 1298
/* 841 */     MCD_OPC_Decode, 239, 5, 24, // Opcode: LB_MM
/* 845 */     MCD_OPC_FilterValue, 12, 7, 0, // Skip to: 856
/* 849 */     MCD_OPC_CheckPredicate, 1, 189, 1, // Skip to: 1298
/* 853 */     MCD_OPC_Decode, 66, 23, // Opcode: ADDiu_MM
/* 856 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 868
/* 860 */     MCD_OPC_CheckPredicate, 1, 178, 1, // Skip to: 1298
/* 864 */     MCD_OPC_Decode, 141, 6, 24, // Opcode: LHu_MM
/* 868 */     MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 880
/* 872 */     MCD_OPC_CheckPredicate, 1, 166, 1, // Skip to: 1298
/* 876 */     MCD_OPC_Decode, 193, 9, 24, // Opcode: SH_MM
/* 880 */     MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 892
/* 884 */     MCD_OPC_CheckPredicate, 1, 154, 1, // Skip to: 1298
/* 888 */     MCD_OPC_Decode, 138, 6, 24, // Opcode: LH_MM
/* 892 */     MCD_OPC_FilterValue, 16, 159, 0, // Skip to: 1055
/* 896 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 899 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 911
/* 903 */     MCD_OPC_CheckPredicate, 1, 135, 1, // Skip to: 1298
/* 907 */     MCD_OPC_Decode, 198, 1, 25, // Opcode: BLTZ_MM
/* 911 */     MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 923
/* 915 */     MCD_OPC_CheckPredicate, 1, 123, 1, // Skip to: 1298
/* 919 */     MCD_OPC_Decode, 197, 1, 25, // Opcode: BLTZAL_MM
/* 923 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 935
/* 927 */     MCD_OPC_CheckPredicate, 1, 111, 1, // Skip to: 1298
/* 931 */     MCD_OPC_Decode, 170, 1, 25, // Opcode: BGEZ_MM
/* 935 */     MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 947
/* 939 */     MCD_OPC_CheckPredicate, 1, 99, 1, // Skip to: 1298
/* 943 */     MCD_OPC_Decode, 169, 1, 25, // Opcode: BGEZAL_MM
/* 947 */     MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 959
/* 951 */     MCD_OPC_CheckPredicate, 1, 87, 1, // Skip to: 1298
/* 955 */     MCD_OPC_Decode, 193, 1, 25, // Opcode: BLEZ_MM
/* 959 */     MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 971
/* 963 */     MCD_OPC_CheckPredicate, 1, 75, 1, // Skip to: 1298
/* 967 */     MCD_OPC_Decode, 173, 1, 25, // Opcode: BGTZ_MM
/* 971 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 983
/* 975 */     MCD_OPC_CheckPredicate, 1, 63, 1, // Skip to: 1298
/* 979 */     MCD_OPC_Decode, 158, 11, 26, // Opcode: TLTI_MM
/* 983 */     MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 995
/* 987 */     MCD_OPC_CheckPredicate, 1, 51, 1, // Skip to: 1298
/* 991 */     MCD_OPC_Decode, 151, 11, 26, // Opcode: TGEI_MM
/* 995 */     MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 1007
/* 999 */     MCD_OPC_CheckPredicate, 1, 39, 1, // Skip to: 1298
/* 1003 */    MCD_OPC_Decode, 157, 11, 26, // Opcode: TLTIU_MM
/* 1007 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1019
/* 1011 */    MCD_OPC_CheckPredicate, 1, 27, 1, // Skip to: 1298
/* 1015 */    MCD_OPC_Decode, 150, 11, 26, // Opcode: TGEIU_MM
/* 1019 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 1031
/* 1023 */    MCD_OPC_CheckPredicate, 1, 15, 1, // Skip to: 1298
/* 1027 */    MCD_OPC_Decode, 164, 11, 26, // Opcode: TNEI_MM
/* 1031 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 1043
/* 1035 */    MCD_OPC_CheckPredicate, 1, 3, 1, // Skip to: 1298
/* 1039 */    MCD_OPC_Decode, 155, 6, 26, // Opcode: LUi_MM
/* 1043 */    MCD_OPC_FilterValue, 14, 251, 0, // Skip to: 1298
/* 1047 */    MCD_OPC_CheckPredicate, 1, 247, 0, // Skip to: 1298
/* 1051 */    MCD_OPC_Decode, 145, 11, 26, // Opcode: TEQI_MM
/* 1055 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 1067
/* 1059 */    MCD_OPC_CheckPredicate, 1, 235, 0, // Skip to: 1298
/* 1063 */    MCD_OPC_Decode, 169, 8, 27, // Opcode: ORi_MM
/* 1067 */    MCD_OPC_FilterValue, 21, 29, 0, // Skip to: 1100
/* 1071 */    MCD_OPC_ExtractField, 0, 13,  // Inst{12-0} ...
/* 1074 */    MCD_OPC_FilterValue, 251, 2, 8, 0, // Skip to: 1087
/* 1079 */    MCD_OPC_CheckPredicate, 1, 215, 0, // Skip to: 1298
/* 1083 */    MCD_OPC_Decode, 153, 7, 28, // Opcode: MOVF_I_MM
/* 1087 */    MCD_OPC_FilterValue, 251, 18, 206, 0, // Skip to: 1298
/* 1092 */    MCD_OPC_CheckPredicate, 1, 202, 0, // Skip to: 1298
/* 1096 */    MCD_OPC_Decode, 173, 7, 28, // Opcode: MOVT_I_MM
/* 1100 */    MCD_OPC_FilterValue, 24, 75, 0, // Skip to: 1179
/* 1104 */    MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 1107 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1119
/* 1111 */    MCD_OPC_CheckPredicate, 1, 183, 0, // Skip to: 1298
/* 1115 */    MCD_OPC_Decode, 163, 6, 29, // Opcode: LWL_MM
/* 1119 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 1131
/* 1123 */    MCD_OPC_CheckPredicate, 1, 171, 0, // Skip to: 1298
/* 1127 */    MCD_OPC_Decode, 166, 6, 29, // Opcode: LWR_MM
/* 1131 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 1143
/* 1135 */    MCD_OPC_CheckPredicate, 1, 159, 0, // Skip to: 1298
/* 1139 */    MCD_OPC_Decode, 144, 6, 30, // Opcode: LL_MM
/* 1143 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 1155
/* 1147 */    MCD_OPC_CheckPredicate, 1, 147, 0, // Skip to: 1298
/* 1151 */    MCD_OPC_Decode, 212, 10, 29, // Opcode: SWL_MM
/* 1155 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 1167
/* 1159 */    MCD_OPC_CheckPredicate, 1, 135, 0, // Skip to: 1298
/* 1163 */    MCD_OPC_Decode, 215, 10, 29, // Opcode: SWR_MM
/* 1167 */    MCD_OPC_FilterValue, 11, 127, 0, // Skip to: 1298
/* 1171 */    MCD_OPC_CheckPredicate, 1, 123, 0, // Skip to: 1298
/* 1175 */    MCD_OPC_Decode, 146, 9, 30, // Opcode: SC_MM
/* 1179 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 1191
/* 1183 */    MCD_OPC_CheckPredicate, 1, 111, 0, // Skip to: 1298
/* 1187 */    MCD_OPC_Decode, 196, 11, 27, // Opcode: XORi_MM
/* 1191 */    MCD_OPC_FilterValue, 36, 8, 0, // Skip to: 1203
/* 1195 */    MCD_OPC_CheckPredicate, 1, 99, 0, // Skip to: 1298
/* 1199 */    MCD_OPC_Decode, 221, 9, 23, // Opcode: SLTi_MM
/* 1203 */    MCD_OPC_FilterValue, 37, 8, 0, // Skip to: 1215
/* 1207 */    MCD_OPC_CheckPredicate, 1, 87, 0, // Skip to: 1298
/* 1211 */    MCD_OPC_Decode, 165, 1, 31, // Opcode: BEQ_MM
/* 1215 */    MCD_OPC_FilterValue, 44, 8, 0, // Skip to: 1227
/* 1219 */    MCD_OPC_CheckPredicate, 1, 75, 0, // Skip to: 1298
/* 1223 */    MCD_OPC_Decode, 224, 9, 23, // Opcode: SLTiu_MM
/* 1227 */    MCD_OPC_FilterValue, 45, 8, 0, // Skip to: 1239
/* 1231 */    MCD_OPC_CheckPredicate, 1, 63, 0, // Skip to: 1298
/* 1235 */    MCD_OPC_Decode, 213, 1, 31, // Opcode: BNE_MM
/* 1239 */    MCD_OPC_FilterValue, 52, 7, 0, // Skip to: 1250
/* 1243 */    MCD_OPC_CheckPredicate, 1, 51, 0, // Skip to: 1298
/* 1247 */    MCD_OPC_Decode, 81, 27, // Opcode: ANDi_MM
/* 1250 */    MCD_OPC_FilterValue, 53, 8, 0, // Skip to: 1262
/* 1254 */    MCD_OPC_CheckPredicate, 1, 40, 0, // Skip to: 1298
/* 1258 */    MCD_OPC_Decode, 229, 5, 32, // Opcode: J_MM
/* 1262 */    MCD_OPC_FilterValue, 61, 8, 0, // Skip to: 1274
/* 1266 */    MCD_OPC_CheckPredicate, 1, 28, 0, // Skip to: 1298
/* 1270 */    MCD_OPC_Decode, 225, 5, 32, // Opcode: JAL_MM
/* 1274 */    MCD_OPC_FilterValue, 62, 8, 0, // Skip to: 1286
/* 1278 */    MCD_OPC_CheckPredicate, 1, 16, 0, // Skip to: 1298
/* 1282 */    MCD_OPC_Decode, 218, 10, 24, // Opcode: SW_MM
/* 1286 */    MCD_OPC_FilterValue, 63, 8, 0, // Skip to: 1298
/* 1290 */    MCD_OPC_CheckPredicate, 1, 4, 0, // Skip to: 1298
/* 1294 */    MCD_OPC_Decode, 170, 6, 24, // Opcode: LW_MM
/* 1298 */    MCD_OPC_Fail,
  0
};

static uint8_t DecoderTableMips32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 83, 3, // Skip to: 858
/* 7 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10 */      MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 28
/* 14 */      MCD_OPC_CheckPredicate, 2, 163, 49, // Skip to: 12725
/* 18 */      MCD_OPC_CheckField, 21, 5, 0, 157, 49, // Skip to: 12725
/* 24 */      MCD_OPC_Decode, 202, 9, 33, // Opcode: SLL
/* 28 */      MCD_OPC_FilterValue, 1, 39, 0, // Skip to: 71
/* 32 */      MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 35 */      MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 53
/* 39 */      MCD_OPC_CheckPredicate, 2, 138, 49, // Skip to: 12725
/* 43 */      MCD_OPC_CheckField, 6, 5, 0, 132, 49, // Skip to: 12725
/* 49 */      MCD_OPC_Decode, 151, 7, 34, // Opcode: MOVF_I
/* 53 */      MCD_OPC_FilterValue, 1, 124, 49, // Skip to: 12725
/* 57 */      MCD_OPC_CheckPredicate, 2, 120, 49, // Skip to: 12725
/* 61 */      MCD_OPC_CheckField, 6, 5, 0, 114, 49, // Skip to: 12725
/* 67 */      MCD_OPC_Decode, 171, 7, 34, // Opcode: MOVT_I
/* 71 */      MCD_OPC_FilterValue, 2, 27, 0, // Skip to: 102
/* 75 */      MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 78 */      MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 90
/* 82 */      MCD_OPC_CheckPredicate, 2, 95, 49, // Skip to: 12725
/* 86 */      MCD_OPC_Decode, 133, 10, 33, // Opcode: SRL
/* 90 */      MCD_OPC_FilterValue, 1, 87, 49, // Skip to: 12725
/* 94 */      MCD_OPC_CheckPredicate, 3, 83, 49, // Skip to: 12725
/* 98 */      MCD_OPC_Decode, 246, 8, 33, // Opcode: ROTR
/* 102 */     MCD_OPC_FilterValue, 3, 14, 0, // Skip to: 120
/* 106 */     MCD_OPC_CheckPredicate, 2, 71, 49, // Skip to: 12725
/* 110 */     MCD_OPC_CheckField, 21, 5, 0, 65, 49, // Skip to: 12725
/* 116 */     MCD_OPC_Decode, 241, 9, 33, // Opcode: SRA
/* 120 */     MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 138
/* 124 */     MCD_OPC_CheckPredicate, 2, 53, 49, // Skip to: 12725
/* 128 */     MCD_OPC_CheckField, 6, 5, 0, 47, 49, // Skip to: 12725
/* 134 */     MCD_OPC_Decode, 209, 9, 14, // Opcode: SLLV
/* 138 */     MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 156
/* 142 */     MCD_OPC_CheckPredicate, 4, 35, 49, // Skip to: 12725
/* 146 */     MCD_OPC_CheckField, 8, 3, 0, 29, 49, // Skip to: 12725
/* 152 */     MCD_OPC_Decode, 149, 6, 35, // Opcode: LSA
/* 156 */     MCD_OPC_FilterValue, 6, 27, 0, // Skip to: 187
/* 160 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 163 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 175
/* 167 */     MCD_OPC_CheckPredicate, 2, 10, 49, // Skip to: 12725
/* 171 */     MCD_OPC_Decode, 146, 10, 14, // Opcode: SRLV
/* 175 */     MCD_OPC_FilterValue, 1, 2, 49, // Skip to: 12725
/* 179 */     MCD_OPC_CheckPredicate, 3, 254, 48, // Skip to: 12725
/* 183 */     MCD_OPC_Decode, 247, 8, 14, // Opcode: ROTRV
/* 187 */     MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 205
/* 191 */     MCD_OPC_CheckPredicate, 2, 242, 48, // Skip to: 12725
/* 195 */     MCD_OPC_CheckField, 6, 5, 0, 236, 48, // Skip to: 12725
/* 201 */     MCD_OPC_Decode, 254, 9, 14, // Opcode: SRAV
/* 205 */     MCD_OPC_FilterValue, 8, 14, 0, // Skip to: 223
/* 209 */     MCD_OPC_CheckPredicate, 2, 224, 48, // Skip to: 12725
/* 213 */     MCD_OPC_CheckField, 6, 15, 0, 218, 48, // Skip to: 12725
/* 219 */     MCD_OPC_Decode, 226, 5, 36, // Opcode: JR
/* 223 */     MCD_OPC_FilterValue, 9, 20, 0, // Skip to: 247
/* 227 */     MCD_OPC_CheckPredicate, 2, 206, 48, // Skip to: 12725
/* 231 */     MCD_OPC_CheckField, 16, 5, 0, 200, 48, // Skip to: 12725
/* 237 */     MCD_OPC_CheckField, 6, 5, 0, 194, 48, // Skip to: 12725
/* 243 */     MCD_OPC_Decode, 220, 5, 37, // Opcode: JALR
/* 247 */     MCD_OPC_FilterValue, 10, 14, 0, // Skip to: 265
/* 251 */     MCD_OPC_CheckPredicate, 2, 182, 48, // Skip to: 12725
/* 255 */     MCD_OPC_CheckField, 6, 5, 0, 176, 48, // Skip to: 12725
/* 261 */     MCD_OPC_Decode, 183, 7, 38, // Opcode: MOVZ_I_I
/* 265 */     MCD_OPC_FilterValue, 11, 14, 0, // Skip to: 283
/* 269 */     MCD_OPC_CheckPredicate, 2, 164, 48, // Skip to: 12725
/* 273 */     MCD_OPC_CheckField, 6, 5, 0, 158, 48, // Skip to: 12725
/* 279 */     MCD_OPC_Decode, 163, 7, 38, // Opcode: MOVN_I_I
/* 283 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 295
/* 287 */     MCD_OPC_CheckPredicate, 2, 146, 48, // Skip to: 12725
/* 291 */     MCD_OPC_Decode, 221, 10, 39, // Opcode: SYSCALL
/* 295 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 307
/* 299 */     MCD_OPC_CheckPredicate, 2, 134, 48, // Skip to: 12725
/* 303 */     MCD_OPC_Decode, 221, 1, 11, // Opcode: BREAK
/* 307 */     MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 319
/* 311 */     MCD_OPC_CheckPredicate, 2, 122, 48, // Skip to: 12725
/* 315 */     MCD_OPC_Decode, 219, 10, 40, // Opcode: SYNC
/* 319 */     MCD_OPC_FilterValue, 16, 43, 0, // Skip to: 366
/* 323 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 326 */     MCD_OPC_FilterValue, 0, 107, 48, // Skip to: 12725
/* 330 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 333 */     MCD_OPC_FilterValue, 0, 100, 48, // Skip to: 12725
/* 337 */     MCD_OPC_ExtractField, 23, 3,  // Inst{25-23} ...
/* 340 */     MCD_OPC_FilterValue, 0, 93, 48, // Skip to: 12725
/* 344 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 358
/* 348 */     MCD_OPC_CheckField, 21, 2, 0, 4, 0, // Skip to: 358
/* 354 */     MCD_OPC_Decode, 236, 6, 41, // Opcode: MFHI
/* 358 */     MCD_OPC_CheckPredicate, 5, 75, 48, // Skip to: 12725
/* 362 */     MCD_OPC_Decode, 238, 6, 42, // Opcode: MFHI_DSP
/* 366 */     MCD_OPC_FilterValue, 17, 36, 0, // Skip to: 406
/* 370 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 373 */     MCD_OPC_FilterValue, 0, 60, 48, // Skip to: 12725
/* 377 */     MCD_OPC_ExtractField, 13, 8,  // Inst{20-13} ...
/* 380 */     MCD_OPC_FilterValue, 0, 53, 48, // Skip to: 12725
/* 384 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 398
/* 388 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 398
/* 394 */     MCD_OPC_Decode, 213, 7, 36, // Opcode: MTHI
/* 398 */     MCD_OPC_CheckPredicate, 5, 35, 48, // Skip to: 12725
/* 402 */     MCD_OPC_Decode, 215, 7, 43, // Opcode: MTHI_DSP
/* 406 */     MCD_OPC_FilterValue, 18, 43, 0, // Skip to: 453
/* 410 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 413 */     MCD_OPC_FilterValue, 0, 20, 48, // Skip to: 12725
/* 417 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 420 */     MCD_OPC_FilterValue, 0, 13, 48, // Skip to: 12725
/* 424 */     MCD_OPC_ExtractField, 23, 3,  // Inst{25-23} ...
/* 427 */     MCD_OPC_FilterValue, 0, 6, 48, // Skip to: 12725
/* 431 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 445
/* 435 */     MCD_OPC_CheckField, 21, 2, 0, 4, 0, // Skip to: 445
/* 441 */     MCD_OPC_Decode, 240, 6, 41, // Opcode: MFLO
/* 445 */     MCD_OPC_CheckPredicate, 5, 244, 47, // Skip to: 12725
/* 449 */     MCD_OPC_Decode, 242, 6, 42, // Opcode: MFLO_DSP
/* 453 */     MCD_OPC_FilterValue, 19, 36, 0, // Skip to: 493
/* 457 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 460 */     MCD_OPC_FilterValue, 0, 229, 47, // Skip to: 12725
/* 464 */     MCD_OPC_ExtractField, 13, 8,  // Inst{20-13} ...
/* 467 */     MCD_OPC_FilterValue, 0, 222, 47, // Skip to: 12725
/* 471 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 485
/* 475 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 485
/* 481 */     MCD_OPC_Decode, 218, 7, 36, // Opcode: MTLO
/* 485 */     MCD_OPC_CheckPredicate, 5, 204, 47, // Skip to: 12725
/* 489 */     MCD_OPC_Decode, 220, 7, 44, // Opcode: MTLO_DSP
/* 493 */     MCD_OPC_FilterValue, 24, 36, 0, // Skip to: 533
/* 497 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 500 */     MCD_OPC_FilterValue, 0, 189, 47, // Skip to: 12725
/* 504 */     MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 507 */     MCD_OPC_FilterValue, 0, 182, 47, // Skip to: 12725
/* 511 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 525
/* 515 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 525
/* 521 */     MCD_OPC_Decode, 235, 7, 20, // Opcode: MULT
/* 525 */     MCD_OPC_CheckPredicate, 5, 164, 47, // Skip to: 12725
/* 529 */     MCD_OPC_Decode, 237, 7, 45, // Opcode: MULT_DSP
/* 533 */     MCD_OPC_FilterValue, 25, 36, 0, // Skip to: 573
/* 537 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 540 */     MCD_OPC_FilterValue, 0, 149, 47, // Skip to: 12725
/* 544 */     MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 547 */     MCD_OPC_FilterValue, 0, 142, 47, // Skip to: 12725
/* 551 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 565
/* 555 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 565
/* 561 */     MCD_OPC_Decode, 239, 7, 20, // Opcode: MULTu
/* 565 */     MCD_OPC_CheckPredicate, 5, 124, 47, // Skip to: 12725
/* 569 */     MCD_OPC_Decode, 236, 7, 45, // Opcode: MULTU_DSP
/* 573 */     MCD_OPC_FilterValue, 26, 14, 0, // Skip to: 591
/* 577 */     MCD_OPC_CheckPredicate, 2, 112, 47, // Skip to: 12725
/* 581 */     MCD_OPC_CheckField, 6, 10, 0, 106, 47, // Skip to: 12725
/* 587 */     MCD_OPC_Decode, 152, 9, 20, // Opcode: SDIV
/* 591 */     MCD_OPC_FilterValue, 27, 14, 0, // Skip to: 609
/* 595 */     MCD_OPC_CheckPredicate, 2, 94, 47, // Skip to: 12725
/* 599 */     MCD_OPC_CheckField, 6, 10, 0, 88, 47, // Skip to: 12725
/* 605 */     MCD_OPC_Decode, 175, 11, 20, // Opcode: UDIV
/* 609 */     MCD_OPC_FilterValue, 32, 13, 0, // Skip to: 626
/* 613 */     MCD_OPC_CheckPredicate, 2, 76, 47, // Skip to: 12725
/* 617 */     MCD_OPC_CheckField, 6, 5, 0, 70, 47, // Skip to: 12725
/* 623 */     MCD_OPC_Decode, 22, 13, // Opcode: ADD
/* 626 */     MCD_OPC_FilterValue, 33, 13, 0, // Skip to: 643
/* 630 */     MCD_OPC_CheckPredicate, 2, 59, 47, // Skip to: 12725
/* 634 */     MCD_OPC_CheckField, 6, 5, 0, 53, 47, // Skip to: 12725
/* 640 */     MCD_OPC_Decode, 67, 13, // Opcode: ADDu
/* 643 */     MCD_OPC_FilterValue, 34, 14, 0, // Skip to: 661
/* 647 */     MCD_OPC_CheckPredicate, 2, 42, 47, // Skip to: 12725
/* 651 */     MCD_OPC_CheckField, 6, 5, 0, 36, 47, // Skip to: 12725
/* 657 */     MCD_OPC_Decode, 161, 10, 13, // Opcode: SUB
/* 661 */     MCD_OPC_FilterValue, 35, 14, 0, // Skip to: 679
/* 665 */     MCD_OPC_CheckPredicate, 2, 24, 47, // Skip to: 12725
/* 669 */     MCD_OPC_CheckField, 6, 5, 0, 18, 47, // Skip to: 12725
/* 675 */     MCD_OPC_Decode, 200, 10, 13, // Opcode: SUBu
/* 679 */     MCD_OPC_FilterValue, 36, 13, 0, // Skip to: 696
/* 683 */     MCD_OPC_CheckPredicate, 2, 6, 47, // Skip to: 12725
/* 687 */     MCD_OPC_CheckField, 6, 5, 0, 0, 47, // Skip to: 12725
/* 693 */     MCD_OPC_Decode, 71, 13, // Opcode: AND
/* 696 */     MCD_OPC_FilterValue, 37, 14, 0, // Skip to: 714
/* 700 */     MCD_OPC_CheckPredicate, 2, 245, 46, // Skip to: 12725
/* 704 */     MCD_OPC_CheckField, 6, 5, 0, 239, 46, // Skip to: 12725
/* 710 */     MCD_OPC_Decode, 159, 8, 13, // Opcode: OR
/* 714 */     MCD_OPC_FilterValue, 38, 14, 0, // Skip to: 732
/* 718 */     MCD_OPC_CheckPredicate, 2, 227, 46, // Skip to: 12725
/* 722 */     MCD_OPC_CheckField, 6, 5, 0, 221, 46, // Skip to: 12725
/* 728 */     MCD_OPC_Decode, 186, 11, 13, // Opcode: XOR
/* 732 */     MCD_OPC_FilterValue, 39, 14, 0, // Skip to: 750
/* 736 */     MCD_OPC_CheckPredicate, 2, 209, 46, // Skip to: 12725
/* 740 */     MCD_OPC_CheckField, 6, 5, 0, 203, 46, // Skip to: 12725
/* 746 */     MCD_OPC_Decode, 149, 8, 13, // Opcode: NOR
/* 750 */     MCD_OPC_FilterValue, 42, 14, 0, // Skip to: 768
/* 754 */     MCD_OPC_CheckPredicate, 2, 191, 46, // Skip to: 12725
/* 758 */     MCD_OPC_CheckField, 6, 5, 0, 185, 46, // Skip to: 12725
/* 764 */     MCD_OPC_Decode, 216, 9, 13, // Opcode: SLT
/* 768 */     MCD_OPC_FilterValue, 43, 14, 0, // Skip to: 786
/* 772 */     MCD_OPC_CheckPredicate, 2, 173, 46, // Skip to: 12725
/* 776 */     MCD_OPC_CheckField, 6, 5, 0, 167, 46, // Skip to: 12725
/* 782 */     MCD_OPC_Decode, 225, 9, 13, // Opcode: SLTu
/* 786 */     MCD_OPC_FilterValue, 48, 8, 0, // Skip to: 798
/* 790 */     MCD_OPC_CheckPredicate, 2, 155, 46, // Skip to: 12725
/* 794 */     MCD_OPC_Decode, 147, 11, 46, // Opcode: TGE
/* 798 */     MCD_OPC_FilterValue, 49, 8, 0, // Skip to: 810
/* 802 */     MCD_OPC_CheckPredicate, 2, 143, 46, // Skip to: 12725
/* 806 */     MCD_OPC_Decode, 152, 11, 46, // Opcode: TGEU
/* 810 */     MCD_OPC_FilterValue, 50, 8, 0, // Skip to: 822
/* 814 */     MCD_OPC_CheckPredicate, 2, 131, 46, // Skip to: 12725
/* 818 */     MCD_OPC_Decode, 155, 11, 46, // Opcode: TLT
/* 822 */     MCD_OPC_FilterValue, 51, 8, 0, // Skip to: 834
/* 826 */     MCD_OPC_CheckPredicate, 2, 119, 46, // Skip to: 12725
/* 830 */     MCD_OPC_Decode, 159, 11, 46, // Opcode: TLTU
/* 834 */     MCD_OPC_FilterValue, 52, 8, 0, // Skip to: 846
/* 838 */     MCD_OPC_CheckPredicate, 2, 107, 46, // Skip to: 12725
/* 842 */     MCD_OPC_Decode, 143, 11, 46, // Opcode: TEQ
/* 846 */     MCD_OPC_FilterValue, 54, 99, 46, // Skip to: 12725
/* 850 */     MCD_OPC_CheckPredicate, 2, 95, 46, // Skip to: 12725
/* 854 */     MCD_OPC_Decode, 162, 11, 46, // Opcode: TNE
/* 858 */     MCD_OPC_FilterValue, 1, 141, 0, // Skip to: 1003
/* 862 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 865 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 877
/* 869 */     MCD_OPC_CheckPredicate, 2, 76, 46, // Skip to: 12725
/* 873 */     MCD_OPC_Decode, 194, 1, 47, // Opcode: BLTZ
/* 877 */     MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 889
/* 881 */     MCD_OPC_CheckPredicate, 2, 64, 46, // Skip to: 12725
/* 885 */     MCD_OPC_Decode, 166, 1, 47, // Opcode: BGEZ
/* 889 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 901
/* 893 */     MCD_OPC_CheckPredicate, 2, 52, 46, // Skip to: 12725
/* 897 */     MCD_OPC_Decode, 148, 11, 48, // Opcode: TGEI
/* 901 */     MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 913
/* 905 */     MCD_OPC_CheckPredicate, 2, 40, 46, // Skip to: 12725
/* 909 */     MCD_OPC_Decode, 149, 11, 48, // Opcode: TGEIU
/* 913 */     MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 925
/* 917 */     MCD_OPC_CheckPredicate, 2, 28, 46, // Skip to: 12725
/* 921 */     MCD_OPC_Decode, 156, 11, 48, // Opcode: TLTI
/* 925 */     MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 937
/* 929 */     MCD_OPC_CheckPredicate, 2, 16, 46, // Skip to: 12725
/* 933 */     MCD_OPC_Decode, 174, 11, 48, // Opcode: TTLTIU
/* 937 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 949
/* 941 */     MCD_OPC_CheckPredicate, 2, 4, 46, // Skip to: 12725
/* 945 */     MCD_OPC_Decode, 144, 11, 48, // Opcode: TEQI
/* 949 */     MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 961
/* 953 */     MCD_OPC_CheckPredicate, 2, 248, 45, // Skip to: 12725
/* 957 */     MCD_OPC_Decode, 163, 11, 48, // Opcode: TNEI
/* 961 */     MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 973
/* 965 */     MCD_OPC_CheckPredicate, 2, 236, 45, // Skip to: 12725
/* 969 */     MCD_OPC_Decode, 196, 1, 47, // Opcode: BLTZAL
/* 973 */     MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 985
/* 977 */     MCD_OPC_CheckPredicate, 2, 224, 45, // Skip to: 12725
/* 981 */     MCD_OPC_Decode, 168, 1, 47, // Opcode: BGEZAL
/* 985 */     MCD_OPC_FilterValue, 28, 216, 45, // Skip to: 12725
/* 989 */     MCD_OPC_CheckPredicate, 5, 212, 45, // Skip to: 12725
/* 993 */     MCD_OPC_CheckField, 21, 5, 0, 206, 45, // Skip to: 12725
/* 999 */     MCD_OPC_Decode, 219, 1, 49, // Opcode: BPOSGE32
/* 1003 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 1015
/* 1007 */    MCD_OPC_CheckPredicate, 6, 194, 45, // Skip to: 12725
/* 1011 */    MCD_OPC_Decode, 218, 5, 50, // Opcode: J
/* 1015 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 1027
/* 1019 */    MCD_OPC_CheckPredicate, 2, 182, 45, // Skip to: 12725
/* 1023 */    MCD_OPC_Decode, 219, 5, 50, // Opcode: JAL
/* 1027 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 1039
/* 1031 */    MCD_OPC_CheckPredicate, 2, 170, 45, // Skip to: 12725
/* 1035 */    MCD_OPC_Decode, 163, 1, 51, // Opcode: BEQ
/* 1039 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 1051
/* 1043 */    MCD_OPC_CheckPredicate, 2, 158, 45, // Skip to: 12725
/* 1047 */    MCD_OPC_Decode, 203, 1, 51, // Opcode: BNE
/* 1051 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 1069
/* 1055 */    MCD_OPC_CheckPredicate, 2, 146, 45, // Skip to: 12725
/* 1059 */    MCD_OPC_CheckField, 16, 5, 0, 140, 45, // Skip to: 12725
/* 1065 */    MCD_OPC_Decode, 191, 1, 47, // Opcode: BLEZ
/* 1069 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 1087
/* 1073 */    MCD_OPC_CheckPredicate, 2, 128, 45, // Skip to: 12725
/* 1077 */    MCD_OPC_CheckField, 16, 5, 0, 122, 45, // Skip to: 12725
/* 1083 */    MCD_OPC_Decode, 171, 1, 47, // Opcode: BGTZ
/* 1087 */    MCD_OPC_FilterValue, 8, 7, 0, // Skip to: 1098
/* 1091 */    MCD_OPC_CheckPredicate, 2, 110, 45, // Skip to: 12725
/* 1095 */    MCD_OPC_Decode, 63, 52, // Opcode: ADDi
/* 1098 */    MCD_OPC_FilterValue, 9, 7, 0, // Skip to: 1109
/* 1102 */    MCD_OPC_CheckPredicate, 2, 99, 45, // Skip to: 12725
/* 1106 */    MCD_OPC_Decode, 65, 52, // Opcode: ADDiu
/* 1109 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 1121
/* 1113 */    MCD_OPC_CheckPredicate, 2, 88, 45, // Skip to: 12725
/* 1117 */    MCD_OPC_Decode, 219, 9, 52, // Opcode: SLTi
/* 1121 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1133
/* 1125 */    MCD_OPC_CheckPredicate, 2, 76, 45, // Skip to: 12725
/* 1129 */    MCD_OPC_Decode, 222, 9, 52, // Opcode: SLTiu
/* 1133 */    MCD_OPC_FilterValue, 12, 7, 0, // Skip to: 1144
/* 1137 */    MCD_OPC_CheckPredicate, 2, 64, 45, // Skip to: 12725
/* 1141 */    MCD_OPC_Decode, 79, 53, // Opcode: ANDi
/* 1144 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 1156
/* 1148 */    MCD_OPC_CheckPredicate, 2, 53, 45, // Skip to: 12725
/* 1152 */    MCD_OPC_Decode, 167, 8, 53, // Opcode: ORi
/* 1156 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 1168
/* 1160 */    MCD_OPC_CheckPredicate, 2, 41, 45, // Skip to: 12725
/* 1164 */    MCD_OPC_Decode, 194, 11, 53, // Opcode: XORi
/* 1168 */    MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 1186
/* 1172 */    MCD_OPC_CheckPredicate, 2, 29, 45, // Skip to: 12725
/* 1176 */    MCD_OPC_CheckField, 21, 5, 0, 23, 45, // Skip to: 12725
/* 1182 */    MCD_OPC_Decode, 153, 6, 26, // Opcode: LUi
/* 1186 */    MCD_OPC_FilterValue, 16, 117, 0, // Skip to: 1307
/* 1190 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1193 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 1211
/* 1197 */    MCD_OPC_CheckPredicate, 2, 4, 45, // Skip to: 12725
/* 1201 */    MCD_OPC_CheckField, 3, 8, 0, 254, 44, // Skip to: 12725
/* 1207 */    MCD_OPC_Decode, 230, 6, 54, // Opcode: MFC0
/* 1211 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 1229
/* 1215 */    MCD_OPC_CheckPredicate, 2, 242, 44, // Skip to: 12725
/* 1219 */    MCD_OPC_CheckField, 3, 8, 0, 236, 44, // Skip to: 12725
/* 1225 */    MCD_OPC_Decode, 207, 7, 54, // Opcode: MTC0
/* 1229 */    MCD_OPC_FilterValue, 11, 31, 0, // Skip to: 1264
/* 1233 */    MCD_OPC_ExtractField, 0, 16,  // Inst{15-0} ...
/* 1236 */    MCD_OPC_FilterValue, 128, 192, 1, 8, 0, // Skip to: 1250
/* 1242 */    MCD_OPC_CheckPredicate, 2, 215, 44, // Skip to: 12725
/* 1246 */    MCD_OPC_Decode, 175, 3, 18, // Opcode: DI
/* 1250 */    MCD_OPC_FilterValue, 160, 192, 1, 205, 44, // Skip to: 12725
/* 1256 */    MCD_OPC_CheckPredicate, 2, 201, 44, // Skip to: 12725
/* 1260 */    MCD_OPC_Decode, 250, 3, 18, // Opcode: EI
/* 1264 */    MCD_OPC_FilterValue, 16, 193, 44, // Skip to: 12725
/* 1268 */    MCD_OPC_ExtractField, 0, 21,  // Inst{20-0} ...
/* 1271 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 1283
/* 1275 */    MCD_OPC_CheckPredicate, 2, 182, 44, // Skip to: 12725
/* 1279 */    MCD_OPC_Decode, 252, 3, 0, // Opcode: ERET
/* 1283 */    MCD_OPC_FilterValue, 31, 8, 0, // Skip to: 1295
/* 1287 */    MCD_OPC_CheckPredicate, 2, 170, 44, // Skip to: 12725
/* 1291 */    MCD_OPC_Decode, 170, 3, 0, // Opcode: DERET
/* 1295 */    MCD_OPC_FilterValue, 32, 162, 44, // Skip to: 12725
/* 1299 */    MCD_OPC_CheckPredicate, 2, 158, 44, // Skip to: 12725
/* 1303 */    MCD_OPC_Decode, 181, 11, 0, // Opcode: WAIT
/* 1307 */    MCD_OPC_FilterValue, 17, 253, 5, // Skip to: 2844
/* 1311 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1314 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 1332
/* 1318 */    MCD_OPC_CheckPredicate, 2, 139, 44, // Skip to: 12725
/* 1322 */    MCD_OPC_CheckField, 0, 11, 0, 133, 44, // Skip to: 12725
/* 1328 */    MCD_OPC_Decode, 231, 6, 55, // Opcode: MFC1
/* 1332 */    MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 1350
/* 1336 */    MCD_OPC_CheckPredicate, 2, 121, 44, // Skip to: 12725
/* 1340 */    MCD_OPC_CheckField, 0, 11, 0, 115, 44, // Skip to: 12725
/* 1346 */    MCD_OPC_Decode, 189, 3, 56, // Opcode: DMFC1
/* 1350 */    MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 1368
/* 1354 */    MCD_OPC_CheckPredicate, 2, 103, 44, // Skip to: 12725
/* 1358 */    MCD_OPC_CheckField, 0, 11, 0, 97, 44, // Skip to: 12725
/* 1364 */    MCD_OPC_Decode, 155, 2, 57, // Opcode: CFC1
/* 1368 */    MCD_OPC_FilterValue, 3, 14, 0, // Skip to: 1386
/* 1372 */    MCD_OPC_CheckPredicate, 2, 85, 44, // Skip to: 12725
/* 1376 */    MCD_OPC_CheckField, 0, 11, 0, 79, 44, // Skip to: 12725
/* 1382 */    MCD_OPC_Decode, 234, 6, 58, // Opcode: MFHC1
/* 1386 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 1404
/* 1390 */    MCD_OPC_CheckPredicate, 2, 67, 44, // Skip to: 12725
/* 1394 */    MCD_OPC_CheckField, 0, 11, 0, 61, 44, // Skip to: 12725
/* 1400 */    MCD_OPC_Decode, 208, 7, 59, // Opcode: MTC1
/* 1404 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 1422
/* 1408 */    MCD_OPC_CheckPredicate, 2, 49, 44, // Skip to: 12725
/* 1412 */    MCD_OPC_CheckField, 0, 11, 0, 43, 44, // Skip to: 12725
/* 1418 */    MCD_OPC_Decode, 192, 3, 60, // Opcode: DMTC1
/* 1422 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 1440
/* 1426 */    MCD_OPC_CheckPredicate, 2, 31, 44, // Skip to: 12725
/* 1430 */    MCD_OPC_CheckField, 0, 11, 0, 25, 44, // Skip to: 12725
/* 1436 */    MCD_OPC_Decode, 215, 2, 61, // Opcode: CTC1
/* 1440 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 1458
/* 1444 */    MCD_OPC_CheckPredicate, 2, 13, 44, // Skip to: 12725
/* 1448 */    MCD_OPC_CheckField, 0, 11, 0, 7, 44, // Skip to: 12725
/* 1454 */    MCD_OPC_Decode, 211, 7, 62, // Opcode: MTHC1
/* 1458 */    MCD_OPC_FilterValue, 8, 27, 0, // Skip to: 1489
/* 1462 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 1465 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1477
/* 1469 */    MCD_OPC_CheckPredicate, 2, 244, 43, // Skip to: 12725
/* 1473 */    MCD_OPC_Decode, 151, 1, 63, // Opcode: BC1F
/* 1477 */    MCD_OPC_FilterValue, 1, 236, 43, // Skip to: 12725
/* 1481 */    MCD_OPC_CheckPredicate, 2, 232, 43, // Skip to: 12725
/* 1485 */    MCD_OPC_Decode, 153, 1, 63, // Opcode: BC1T
/* 1489 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1501
/* 1493 */    MCD_OPC_CheckPredicate, 4, 220, 43, // Skip to: 12725
/* 1497 */    MCD_OPC_Decode, 241, 1, 64, // Opcode: BZ_V
/* 1501 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 1513
/* 1505 */    MCD_OPC_CheckPredicate, 4, 208, 43, // Skip to: 12725
/* 1509 */    MCD_OPC_Decode, 217, 1, 64, // Opcode: BNZ_V
/* 1513 */    MCD_OPC_FilterValue, 16, 80, 2, // Skip to: 2109
/* 1517 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1520 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1532
/* 1524 */    MCD_OPC_CheckPredicate, 2, 189, 43, // Skip to: 12725
/* 1528 */    MCD_OPC_Decode, 153, 4, 65, // Opcode: FADD_S
/* 1532 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 1544
/* 1536 */    MCD_OPC_CheckPredicate, 2, 177, 43, // Skip to: 12725
/* 1540 */    MCD_OPC_Decode, 154, 5, 65, // Opcode: FSUB_S
/* 1544 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 1556
/* 1548 */    MCD_OPC_CheckPredicate, 2, 165, 43, // Skip to: 12725
/* 1552 */    MCD_OPC_Decode, 245, 4, 65, // Opcode: FMUL_S
/* 1556 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 1568
/* 1560 */    MCD_OPC_CheckPredicate, 2, 153, 43, // Skip to: 12725
/* 1564 */    MCD_OPC_Decode, 189, 4, 65, // Opcode: FDIV_S
/* 1568 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 1586
/* 1572 */    MCD_OPC_CheckPredicate, 2, 141, 43, // Skip to: 12725
/* 1576 */    MCD_OPC_CheckField, 16, 5, 0, 135, 43, // Skip to: 12725
/* 1582 */    MCD_OPC_Decode, 147, 5, 66, // Opcode: FSQRT_S
/* 1586 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 1604
/* 1590 */    MCD_OPC_CheckPredicate, 6, 123, 43, // Skip to: 12725
/* 1594 */    MCD_OPC_CheckField, 16, 5, 0, 117, 43, // Skip to: 12725
/* 1600 */    MCD_OPC_Decode, 146, 4, 66, // Opcode: FABS_S
/* 1604 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 1622
/* 1608 */    MCD_OPC_CheckPredicate, 2, 105, 43, // Skip to: 12725
/* 1612 */    MCD_OPC_CheckField, 16, 5, 0, 99, 43, // Skip to: 12725
/* 1618 */    MCD_OPC_Decode, 237, 4, 66, // Opcode: FMOV_S
/* 1622 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 1640
/* 1626 */    MCD_OPC_CheckPredicate, 6, 87, 43, // Skip to: 12725
/* 1630 */    MCD_OPC_CheckField, 16, 5, 0, 81, 43, // Skip to: 12725
/* 1636 */    MCD_OPC_Decode, 251, 4, 66, // Opcode: FNEG_S
/* 1640 */    MCD_OPC_FilterValue, 12, 14, 0, // Skip to: 1658
/* 1644 */    MCD_OPC_CheckPredicate, 2, 69, 43, // Skip to: 12725
/* 1648 */    MCD_OPC_CheckField, 16, 5, 0, 63, 43, // Skip to: 12725
/* 1654 */    MCD_OPC_Decode, 255, 8, 66, // Opcode: ROUND_W_S
/* 1658 */    MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 1676
/* 1662 */    MCD_OPC_CheckPredicate, 2, 51, 43, // Skip to: 12725
/* 1666 */    MCD_OPC_CheckField, 16, 5, 0, 45, 43, // Skip to: 12725
/* 1672 */    MCD_OPC_Decode, 172, 11, 66, // Opcode: TRUNC_W_S
/* 1676 */    MCD_OPC_FilterValue, 14, 14, 0, // Skip to: 1694
/* 1680 */    MCD_OPC_CheckPredicate, 2, 33, 43, // Skip to: 12725
/* 1684 */    MCD_OPC_CheckField, 16, 5, 0, 27, 43, // Skip to: 12725
/* 1690 */    MCD_OPC_Decode, 145, 2, 66, // Opcode: CEIL_W_S
/* 1694 */    MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 1712
/* 1698 */    MCD_OPC_CheckPredicate, 2, 15, 43, // Skip to: 12725
/* 1702 */    MCD_OPC_CheckField, 16, 5, 0, 9, 43, // Skip to: 12725
/* 1708 */    MCD_OPC_Decode, 222, 4, 66, // Opcode: FLOOR_W_S
/* 1712 */    MCD_OPC_FilterValue, 17, 27, 0, // Skip to: 1743
/* 1716 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 1719 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1731
/* 1723 */    MCD_OPC_CheckPredicate, 2, 246, 42, // Skip to: 12725
/* 1727 */    MCD_OPC_Decode, 154, 7, 67, // Opcode: MOVF_S
/* 1731 */    MCD_OPC_FilterValue, 1, 238, 42, // Skip to: 12725
/* 1735 */    MCD_OPC_CheckPredicate, 2, 234, 42, // Skip to: 12725
/* 1739 */    MCD_OPC_Decode, 174, 7, 67, // Opcode: MOVT_S
/* 1743 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 1755
/* 1747 */    MCD_OPC_CheckPredicate, 2, 222, 42, // Skip to: 12725
/* 1751 */    MCD_OPC_Decode, 186, 7, 68, // Opcode: MOVZ_I_S
/* 1755 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 1767
/* 1759 */    MCD_OPC_CheckPredicate, 2, 210, 42, // Skip to: 12725
/* 1763 */    MCD_OPC_Decode, 166, 7, 68, // Opcode: MOVN_I_S
/* 1767 */    MCD_OPC_FilterValue, 33, 14, 0, // Skip to: 1785
/* 1771 */    MCD_OPC_CheckPredicate, 7, 198, 42, // Skip to: 12725
/* 1775 */    MCD_OPC_CheckField, 16, 5, 0, 192, 42, // Skip to: 12725
/* 1781 */    MCD_OPC_Decode, 218, 2, 69, // Opcode: CVT_D32_S
/* 1785 */    MCD_OPC_FilterValue, 36, 14, 0, // Skip to: 1803
/* 1789 */    MCD_OPC_CheckPredicate, 2, 180, 42, // Skip to: 12725
/* 1793 */    MCD_OPC_CheckField, 16, 5, 0, 174, 42, // Skip to: 12725
/* 1799 */    MCD_OPC_Decode, 238, 2, 66, // Opcode: CVT_W_S
/* 1803 */    MCD_OPC_FilterValue, 37, 14, 0, // Skip to: 1821
/* 1807 */    MCD_OPC_CheckPredicate, 2, 162, 42, // Skip to: 12725
/* 1811 */    MCD_OPC_CheckField, 16, 5, 0, 156, 42, // Skip to: 12725
/* 1817 */    MCD_OPC_Decode, 227, 2, 70, // Opcode: CVT_L_S
/* 1821 */    MCD_OPC_FilterValue, 48, 14, 0, // Skip to: 1839
/* 1825 */    MCD_OPC_CheckPredicate, 2, 144, 42, // Skip to: 12725
/* 1829 */    MCD_OPC_CheckField, 6, 5, 0, 138, 42, // Skip to: 12725
/* 1835 */    MCD_OPC_Decode, 245, 2, 71, // Opcode: C_F_S
/* 1839 */    MCD_OPC_FilterValue, 49, 14, 0, // Skip to: 1857
/* 1843 */    MCD_OPC_CheckPredicate, 2, 126, 42, // Skip to: 12725
/* 1847 */    MCD_OPC_CheckField, 6, 5, 0, 120, 42, // Skip to: 12725
/* 1853 */    MCD_OPC_Decode, 159, 3, 71, // Opcode: C_UN_S
/* 1857 */    MCD_OPC_FilterValue, 50, 14, 0, // Skip to: 1875
/* 1861 */    MCD_OPC_CheckPredicate, 2, 108, 42, // Skip to: 12725
/* 1865 */    MCD_OPC_CheckField, 6, 5, 0, 102, 42, // Skip to: 12725
/* 1871 */    MCD_OPC_Decode, 242, 2, 71, // Opcode: C_EQ_S
/* 1875 */    MCD_OPC_FilterValue, 51, 14, 0, // Skip to: 1893
/* 1879 */    MCD_OPC_CheckPredicate, 2, 90, 42, // Skip to: 12725
/* 1883 */    MCD_OPC_CheckField, 6, 5, 0, 84, 42, // Skip to: 12725
/* 1889 */    MCD_OPC_Decode, 150, 3, 71, // Opcode: C_UEQ_S
/* 1893 */    MCD_OPC_FilterValue, 52, 14, 0, // Skip to: 1911
/* 1897 */    MCD_OPC_CheckPredicate, 2, 72, 42, // Skip to: 12725
/* 1901 */    MCD_OPC_CheckField, 6, 5, 0, 66, 42, // Skip to: 12725
/* 1907 */    MCD_OPC_Decode, 141, 3, 71, // Opcode: C_OLT_S
/* 1911 */    MCD_OPC_FilterValue, 53, 14, 0, // Skip to: 1929
/* 1915 */    MCD_OPC_CheckPredicate, 2, 54, 42, // Skip to: 12725
/* 1919 */    MCD_OPC_CheckField, 6, 5, 0, 48, 42, // Skip to: 12725
/* 1925 */    MCD_OPC_Decode, 156, 3, 71, // Opcode: C_ULT_S
/* 1929 */    MCD_OPC_FilterValue, 54, 14, 0, // Skip to: 1947
/* 1933 */    MCD_OPC_CheckPredicate, 2, 36, 42, // Skip to: 12725
/* 1937 */    MCD_OPC_CheckField, 6, 5, 0, 30, 42, // Skip to: 12725
/* 1943 */    MCD_OPC_Decode, 138, 3, 71, // Opcode: C_OLE_S
/* 1947 */    MCD_OPC_FilterValue, 55, 14, 0, // Skip to: 1965
/* 1951 */    MCD_OPC_CheckPredicate, 2, 18, 42, // Skip to: 12725
/* 1955 */    MCD_OPC_CheckField, 6, 5, 0, 12, 42, // Skip to: 12725
/* 1961 */    MCD_OPC_Decode, 153, 3, 71, // Opcode: C_ULE_S
/* 1965 */    MCD_OPC_FilterValue, 56, 14, 0, // Skip to: 1983
/* 1969 */    MCD_OPC_CheckPredicate, 2, 0, 42, // Skip to: 12725
/* 1973 */    MCD_OPC_CheckField, 6, 5, 0, 250, 41, // Skip to: 12725
/* 1979 */    MCD_OPC_Decode, 147, 3, 71, // Opcode: C_SF_S
/* 1983 */    MCD_OPC_FilterValue, 57, 14, 0, // Skip to: 2001
/* 1987 */    MCD_OPC_CheckPredicate, 2, 238, 41, // Skip to: 12725
/* 1991 */    MCD_OPC_CheckField, 6, 5, 0, 232, 41, // Skip to: 12725
/* 1997 */    MCD_OPC_Decode, 129, 3, 71, // Opcode: C_NGLE_S
/* 2001 */    MCD_OPC_FilterValue, 58, 14, 0, // Skip to: 2019
/* 2005 */    MCD_OPC_CheckPredicate, 2, 220, 41, // Skip to: 12725
/* 2009 */    MCD_OPC_CheckField, 6, 5, 0, 214, 41, // Skip to: 12725
/* 2015 */    MCD_OPC_Decode, 144, 3, 71, // Opcode: C_SEQ_S
/* 2019 */    MCD_OPC_FilterValue, 59, 14, 0, // Skip to: 2037
/* 2023 */    MCD_OPC_CheckPredicate, 2, 202, 41, // Skip to: 12725
/* 2027 */    MCD_OPC_CheckField, 6, 5, 0, 196, 41, // Skip to: 12725
/* 2033 */    MCD_OPC_Decode, 132, 3, 71, // Opcode: C_NGL_S
/* 2037 */    MCD_OPC_FilterValue, 60, 14, 0, // Skip to: 2055
/* 2041 */    MCD_OPC_CheckPredicate, 2, 184, 41, // Skip to: 12725
/* 2045 */    MCD_OPC_CheckField, 6, 5, 0, 178, 41, // Skip to: 12725
/* 2051 */    MCD_OPC_Decode, 251, 2, 71, // Opcode: C_LT_S
/* 2055 */    MCD_OPC_FilterValue, 61, 14, 0, // Skip to: 2073
/* 2059 */    MCD_OPC_CheckPredicate, 2, 166, 41, // Skip to: 12725
/* 2063 */    MCD_OPC_CheckField, 6, 5, 0, 160, 41, // Skip to: 12725
/* 2069 */    MCD_OPC_Decode, 254, 2, 71, // Opcode: C_NGE_S
/* 2073 */    MCD_OPC_FilterValue, 62, 14, 0, // Skip to: 2091
/* 2077 */    MCD_OPC_CheckPredicate, 2, 148, 41, // Skip to: 12725
/* 2081 */    MCD_OPC_CheckField, 6, 5, 0, 142, 41, // Skip to: 12725
/* 2087 */    MCD_OPC_Decode, 248, 2, 71, // Opcode: C_LE_S
/* 2091 */    MCD_OPC_FilterValue, 63, 134, 41, // Skip to: 12725
/* 2095 */    MCD_OPC_CheckPredicate, 2, 130, 41, // Skip to: 12725
/* 2099 */    MCD_OPC_CheckField, 6, 5, 0, 124, 41, // Skip to: 12725
/* 2105 */    MCD_OPC_Decode, 135, 3, 71, // Opcode: C_NGT_S
/* 2109 */    MCD_OPC_FilterValue, 17, 80, 2, // Skip to: 2705
/* 2113 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 2116 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 2128
/* 2120 */    MCD_OPC_CheckPredicate, 7, 105, 41, // Skip to: 12725
/* 2124 */    MCD_OPC_Decode, 150, 4, 72, // Opcode: FADD_D32
/* 2128 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 2140
/* 2132 */    MCD_OPC_CheckPredicate, 7, 93, 41, // Skip to: 12725
/* 2136 */    MCD_OPC_Decode, 151, 5, 72, // Opcode: FSUB_D32
/* 2140 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 2152
/* 2144 */    MCD_OPC_CheckPredicate, 7, 81, 41, // Skip to: 12725
/* 2148 */    MCD_OPC_Decode, 242, 4, 72, // Opcode: FMUL_D32
/* 2152 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 2164
/* 2156 */    MCD_OPC_CheckPredicate, 7, 69, 41, // Skip to: 12725
/* 2160 */    MCD_OPC_Decode, 186, 4, 72, // Opcode: FDIV_D32
/* 2164 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 2182
/* 2168 */    MCD_OPC_CheckPredicate, 7, 57, 41, // Skip to: 12725
/* 2172 */    MCD_OPC_CheckField, 16, 5, 0, 51, 41, // Skip to: 12725
/* 2178 */    MCD_OPC_Decode, 144, 5, 73, // Opcode: FSQRT_D32
/* 2182 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 2200
/* 2186 */    MCD_OPC_CheckPredicate, 6, 39, 41, // Skip to: 12725
/* 2190 */    MCD_OPC_CheckField, 16, 5, 0, 33, 41, // Skip to: 12725
/* 2196 */    MCD_OPC_Decode, 143, 4, 73, // Opcode: FABS_D32
/* 2200 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 2218
/* 2204 */    MCD_OPC_CheckPredicate, 7, 21, 41, // Skip to: 12725
/* 2208 */    MCD_OPC_CheckField, 16, 5, 0, 15, 41, // Skip to: 12725
/* 2214 */    MCD_OPC_Decode, 234, 4, 73, // Opcode: FMOV_D32
/* 2218 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 2236
/* 2222 */    MCD_OPC_CheckPredicate, 6, 3, 41, // Skip to: 12725
/* 2226 */    MCD_OPC_CheckField, 16, 5, 0, 253, 40, // Skip to: 12725
/* 2232 */    MCD_OPC_Decode, 248, 4, 73, // Opcode: FNEG_D32
/* 2236 */    MCD_OPC_FilterValue, 12, 14, 0, // Skip to: 2254
/* 2240 */    MCD_OPC_CheckPredicate, 7, 241, 40, // Skip to: 12725
/* 2244 */    MCD_OPC_CheckField, 16, 5, 0, 235, 40, // Skip to: 12725
/* 2250 */    MCD_OPC_Decode, 252, 8, 74, // Opcode: ROUND_W_D32
/* 2254 */    MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 2272
/* 2258 */    MCD_OPC_CheckPredicate, 7, 223, 40, // Skip to: 12725
/* 2262 */    MCD_OPC_CheckField, 16, 5, 0, 217, 40, // Skip to: 12725
/* 2268 */    MCD_OPC_Decode, 169, 11, 74, // Opcode: TRUNC_W_D32
/* 2272 */    MCD_OPC_FilterValue, 14, 14, 0, // Skip to: 2290
/* 2276 */    MCD_OPC_CheckPredicate, 7, 205, 40, // Skip to: 12725
/* 2280 */    MCD_OPC_CheckField, 16, 5, 0, 199, 40, // Skip to: 12725
/* 2286 */    MCD_OPC_Decode, 142, 2, 74, // Opcode: CEIL_W_D32
/* 2290 */    MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 2308
/* 2294 */    MCD_OPC_CheckPredicate, 7, 187, 40, // Skip to: 12725
/* 2298 */    MCD_OPC_CheckField, 16, 5, 0, 181, 40, // Skip to: 12725
/* 2304 */    MCD_OPC_Decode, 219, 4, 74, // Opcode: FLOOR_W_D32
/* 2308 */    MCD_OPC_FilterValue, 17, 27, 0, // Skip to: 2339
/* 2312 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 2315 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 2327
/* 2319 */    MCD_OPC_CheckPredicate, 7, 162, 40, // Skip to: 12725
/* 2323 */    MCD_OPC_Decode, 148, 7, 75, // Opcode: MOVF_D32
/* 2327 */    MCD_OPC_FilterValue, 1, 154, 40, // Skip to: 12725
/* 2331 */    MCD_OPC_CheckPredicate, 7, 150, 40, // Skip to: 12725
/* 2335 */    MCD_OPC_Decode, 168, 7, 75, // Opcode: MOVT_D32
/* 2339 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 2351
/* 2343 */    MCD_OPC_CheckPredicate, 7, 138, 40, // Skip to: 12725
/* 2347 */    MCD_OPC_Decode, 180, 7, 76, // Opcode: MOVZ_I_D32
/* 2351 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 2363
/* 2355 */    MCD_OPC_CheckPredicate, 7, 126, 40, // Skip to: 12725
/* 2359 */    MCD_OPC_Decode, 160, 7, 76, // Opcode: MOVN_I_D32
/* 2363 */    MCD_OPC_FilterValue, 32, 14, 0, // Skip to: 2381
/* 2367 */    MCD_OPC_CheckPredicate, 7, 114, 40, // Skip to: 12725
/* 2371 */    MCD_OPC_CheckField, 16, 5, 0, 108, 40, // Skip to: 12725
/* 2377 */    MCD_OPC_Decode, 229, 2, 74, // Opcode: CVT_S_D32
/* 2381 */    MCD_OPC_FilterValue, 36, 14, 0, // Skip to: 2399
/* 2385 */    MCD_OPC_CheckPredicate, 7, 96, 40, // Skip to: 12725
/* 2389 */    MCD_OPC_CheckField, 16, 5, 0, 90, 40, // Skip to: 12725
/* 2395 */    MCD_OPC_Decode, 235, 2, 74, // Opcode: CVT_W_D32
/* 2399 */    MCD_OPC_FilterValue, 37, 14, 0, // Skip to: 2417
/* 2403 */    MCD_OPC_CheckPredicate, 2, 78, 40, // Skip to: 12725
/* 2407 */    MCD_OPC_CheckField, 16, 5, 0, 72, 40, // Skip to: 12725
/* 2413 */    MCD_OPC_Decode, 225, 2, 77, // Opcode: CVT_L_D64
/* 2417 */    MCD_OPC_FilterValue, 48, 14, 0, // Skip to: 2435
/* 2421 */    MCD_OPC_CheckPredicate, 7, 60, 40, // Skip to: 12725
/* 2425 */    MCD_OPC_CheckField, 6, 5, 0, 54, 40, // Skip to: 12725
/* 2431 */    MCD_OPC_Decode, 243, 2, 78, // Opcode: C_F_D32
/* 2435 */    MCD_OPC_FilterValue, 49, 14, 0, // Skip to: 2453
/* 2439 */    MCD_OPC_CheckPredicate, 7, 42, 40, // Skip to: 12725
/* 2443 */    MCD_OPC_CheckField, 6, 5, 0, 36, 40, // Skip to: 12725
/* 2449 */    MCD_OPC_Decode, 157, 3, 78, // Opcode: C_UN_D32
/* 2453 */    MCD_OPC_FilterValue, 50, 14, 0, // Skip to: 2471
/* 2457 */    MCD_OPC_CheckPredicate, 7, 24, 40, // Skip to: 12725
/* 2461 */    MCD_OPC_CheckField, 6, 5, 0, 18, 40, // Skip to: 12725
/* 2467 */    MCD_OPC_Decode, 240, 2, 78, // Opcode: C_EQ_D32
/* 2471 */    MCD_OPC_FilterValue, 51, 14, 0, // Skip to: 2489
/* 2475 */    MCD_OPC_CheckPredicate, 7, 6, 40, // Skip to: 12725
/* 2479 */    MCD_OPC_CheckField, 6, 5, 0, 0, 40, // Skip to: 12725
/* 2485 */    MCD_OPC_Decode, 148, 3, 78, // Opcode: C_UEQ_D32
/* 2489 */    MCD_OPC_FilterValue, 52, 14, 0, // Skip to: 2507
/* 2493 */    MCD_OPC_CheckPredicate, 7, 244, 39, // Skip to: 12725
/* 2497 */    MCD_OPC_CheckField, 6, 5, 0, 238, 39, // Skip to: 12725
/* 2503 */    MCD_OPC_Decode, 139, 3, 78, // Opcode: C_OLT_D32
/* 2507 */    MCD_OPC_FilterValue, 53, 14, 0, // Skip to: 2525
/* 2511 */    MCD_OPC_CheckPredicate, 7, 226, 39, // Skip to: 12725
/* 2515 */    MCD_OPC_CheckField, 6, 5, 0, 220, 39, // Skip to: 12725
/* 2521 */    MCD_OPC_Decode, 154, 3, 78, // Opcode: C_ULT_D32
/* 2525 */    MCD_OPC_FilterValue, 54, 14, 0, // Skip to: 2543
/* 2529 */    MCD_OPC_CheckPredicate, 7, 208, 39, // Skip to: 12725
/* 2533 */    MCD_OPC_CheckField, 6, 5, 0, 202, 39, // Skip to: 12725
/* 2539 */    MCD_OPC_Decode, 136, 3, 78, // Opcode: C_OLE_D32
/* 2543 */    MCD_OPC_FilterValue, 55, 14, 0, // Skip to: 2561
/* 2547 */    MCD_OPC_CheckPredicate, 7, 190, 39, // Skip to: 12725
/* 2551 */    MCD_OPC_CheckField, 6, 5, 0, 184, 39, // Skip to: 12725
/* 2557 */    MCD_OPC_Decode, 151, 3, 78, // Opcode: C_ULE_D32
/* 2561 */    MCD_OPC_FilterValue, 56, 14, 0, // Skip to: 2579
/* 2565 */    MCD_OPC_CheckPredicate, 7, 172, 39, // Skip to: 12725
/* 2569 */    MCD_OPC_CheckField, 6, 5, 0, 166, 39, // Skip to: 12725
/* 2575 */    MCD_OPC_Decode, 145, 3, 78, // Opcode: C_SF_D32
/* 2579 */    MCD_OPC_FilterValue, 57, 14, 0, // Skip to: 2597
/* 2583 */    MCD_OPC_CheckPredicate, 7, 154, 39, // Skip to: 12725
/* 2587 */    MCD_OPC_CheckField, 6, 5, 0, 148, 39, // Skip to: 12725
/* 2593 */    MCD_OPC_Decode, 255, 2, 78, // Opcode: C_NGLE_D32
/* 2597 */    MCD_OPC_FilterValue, 58, 14, 0, // Skip to: 2615
/* 2601 */    MCD_OPC_CheckPredicate, 7, 136, 39, // Skip to: 12725
/* 2605 */    MCD_OPC_CheckField, 6, 5, 0, 130, 39, // Skip to: 12725
/* 2611 */    MCD_OPC_Decode, 142, 3, 78, // Opcode: C_SEQ_D32
/* 2615 */    MCD_OPC_FilterValue, 59, 14, 0, // Skip to: 2633
/* 2619 */    MCD_OPC_CheckPredicate, 7, 118, 39, // Skip to: 12725
/* 2623 */    MCD_OPC_CheckField, 6, 5, 0, 112, 39, // Skip to: 12725
/* 2629 */    MCD_OPC_Decode, 130, 3, 78, // Opcode: C_NGL_D32
/* 2633 */    MCD_OPC_FilterValue, 60, 14, 0, // Skip to: 2651
/* 2637 */    MCD_OPC_CheckPredicate, 7, 100, 39, // Skip to: 12725
/* 2641 */    MCD_OPC_CheckField, 6, 5, 0, 94, 39, // Skip to: 12725
/* 2647 */    MCD_OPC_Decode, 249, 2, 78, // Opcode: C_LT_D32
/* 2651 */    MCD_OPC_FilterValue, 61, 14, 0, // Skip to: 2669
/* 2655 */    MCD_OPC_CheckPredicate, 7, 82, 39, // Skip to: 12725
/* 2659 */    MCD_OPC_CheckField, 6, 5, 0, 76, 39, // Skip to: 12725
/* 2665 */    MCD_OPC_Decode, 252, 2, 78, // Opcode: C_NGE_D32
/* 2669 */    MCD_OPC_FilterValue, 62, 14, 0, // Skip to: 2687
/* 2673 */    MCD_OPC_CheckPredicate, 7, 64, 39, // Skip to: 12725
/* 2677 */    MCD_OPC_CheckField, 6, 5, 0, 58, 39, // Skip to: 12725
/* 2683 */    MCD_OPC_Decode, 246, 2, 78, // Opcode: C_LE_D32
/* 2687 */    MCD_OPC_FilterValue, 63, 50, 39, // Skip to: 12725
/* 2691 */    MCD_OPC_CheckPredicate, 7, 46, 39, // Skip to: 12725
/* 2695 */    MCD_OPC_CheckField, 6, 5, 0, 40, 39, // Skip to: 12725
/* 2701 */    MCD_OPC_Decode, 133, 3, 78, // Opcode: C_NGT_D32
/* 2705 */    MCD_OPC_FilterValue, 20, 39, 0, // Skip to: 2748
/* 2709 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 2712 */    MCD_OPC_FilterValue, 32, 14, 0, // Skip to: 2730
/* 2716 */    MCD_OPC_CheckPredicate, 2, 21, 39, // Skip to: 12725
/* 2720 */    MCD_OPC_CheckField, 16, 5, 0, 15, 39, // Skip to: 12725
/* 2726 */    MCD_OPC_Decode, 233, 2, 66, // Opcode: CVT_S_W
/* 2730 */    MCD_OPC_FilterValue, 33, 7, 39, // Skip to: 12725
/* 2734 */    MCD_OPC_CheckPredicate, 7, 3, 39, // Skip to: 12725
/* 2738 */    MCD_OPC_CheckField, 16, 5, 0, 253, 38, // Skip to: 12725
/* 2744 */    MCD_OPC_Decode, 219, 2, 69, // Opcode: CVT_D32_W
/* 2748 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 2760
/* 2752 */    MCD_OPC_CheckPredicate, 4, 241, 38, // Skip to: 12725
/* 2756 */    MCD_OPC_Decode, 238, 1, 64, // Opcode: BZ_B
/* 2760 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 2772
/* 2764 */    MCD_OPC_CheckPredicate, 4, 229, 38, // Skip to: 12725
/* 2768 */    MCD_OPC_Decode, 240, 1, 79, // Opcode: BZ_H
/* 2772 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 2784
/* 2776 */    MCD_OPC_CheckPredicate, 4, 217, 38, // Skip to: 12725
/* 2780 */    MCD_OPC_Decode, 242, 1, 80, // Opcode: BZ_W
/* 2784 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 2796
/* 2788 */    MCD_OPC_CheckPredicate, 4, 205, 38, // Skip to: 12725
/* 2792 */    MCD_OPC_Decode, 239, 1, 81, // Opcode: BZ_D
/* 2796 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 2808
/* 2800 */    MCD_OPC_CheckPredicate, 4, 193, 38, // Skip to: 12725
/* 2804 */    MCD_OPC_Decode, 214, 1, 64, // Opcode: BNZ_B
/* 2808 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 2820
/* 2812 */    MCD_OPC_CheckPredicate, 4, 181, 38, // Skip to: 12725
/* 2816 */    MCD_OPC_Decode, 216, 1, 79, // Opcode: BNZ_H
/* 2820 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 2832
/* 2824 */    MCD_OPC_CheckPredicate, 4, 169, 38, // Skip to: 12725
/* 2828 */    MCD_OPC_Decode, 218, 1, 80, // Opcode: BNZ_W
/* 2832 */    MCD_OPC_FilterValue, 31, 161, 38, // Skip to: 12725
/* 2836 */    MCD_OPC_CheckPredicate, 4, 157, 38, // Skip to: 12725
/* 2840 */    MCD_OPC_Decode, 215, 1, 81, // Opcode: BNZ_D
/* 2844 */    MCD_OPC_FilterValue, 18, 39, 0, // Skip to: 2887
/* 2848 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 2851 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 2869
/* 2855 */    MCD_OPC_CheckPredicate, 2, 138, 38, // Skip to: 12725
/* 2859 */    MCD_OPC_CheckField, 3, 8, 0, 132, 38, // Skip to: 12725
/* 2865 */    MCD_OPC_Decode, 233, 6, 54, // Opcode: MFC2
/* 2869 */    MCD_OPC_FilterValue, 4, 124, 38, // Skip to: 12725
/* 2873 */    MCD_OPC_CheckPredicate, 2, 120, 38, // Skip to: 12725
/* 2877 */    MCD_OPC_CheckField, 3, 8, 0, 114, 38, // Skip to: 12725
/* 2883 */    MCD_OPC_Decode, 210, 7, 54, // Opcode: MTC2
/* 2887 */    MCD_OPC_FilterValue, 19, 207, 0, // Skip to: 3098
/* 2891 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 2894 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 2912
/* 2898 */    MCD_OPC_CheckPredicate, 8, 95, 38, // Skip to: 12725
/* 2902 */    MCD_OPC_CheckField, 11, 5, 0, 89, 38, // Skip to: 12725
/* 2908 */    MCD_OPC_Decode, 168, 6, 82, // Opcode: LWXC1
/* 2912 */    MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 2930
/* 2916 */    MCD_OPC_CheckPredicate, 9, 77, 38, // Skip to: 12725
/* 2920 */    MCD_OPC_CheckField, 11, 5, 0, 71, 38, // Skip to: 12725
/* 2926 */    MCD_OPC_Decode, 254, 5, 83, // Opcode: LDXC1
/* 2930 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 2948
/* 2934 */    MCD_OPC_CheckPredicate, 7, 59, 38, // Skip to: 12725
/* 2938 */    MCD_OPC_CheckField, 11, 5, 0, 53, 38, // Skip to: 12725
/* 2944 */    MCD_OPC_Decode, 150, 6, 83, // Opcode: LUXC1
/* 2948 */    MCD_OPC_FilterValue, 8, 14, 0, // Skip to: 2966
/* 2952 */    MCD_OPC_CheckPredicate, 8, 41, 38, // Skip to: 12725
/* 2956 */    MCD_OPC_CheckField, 6, 5, 0, 35, 38, // Skip to: 12725
/* 2962 */    MCD_OPC_Decode, 216, 10, 84, // Opcode: SWXC1
/* 2966 */    MCD_OPC_FilterValue, 9, 14, 0, // Skip to: 2984
/* 2970 */    MCD_OPC_CheckPredicate, 9, 23, 38, // Skip to: 12725
/* 2974 */    MCD_OPC_CheckField, 6, 5, 0, 17, 38, // Skip to: 12725
/* 2980 */    MCD_OPC_Decode, 156, 9, 85, // Opcode: SDXC1
/* 2984 */    MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 3002
/* 2988 */    MCD_OPC_CheckPredicate, 7, 5, 38, // Skip to: 12725
/* 2992 */    MCD_OPC_CheckField, 6, 5, 0, 255, 37, // Skip to: 12725
/* 2998 */    MCD_OPC_Decode, 202, 10, 85, // Opcode: SUXC1
/* 3002 */    MCD_OPC_FilterValue, 32, 8, 0, // Skip to: 3014
/* 3006 */    MCD_OPC_CheckPredicate, 3, 243, 37, // Skip to: 12725
/* 3010 */    MCD_OPC_Decode, 204, 6, 86, // Opcode: MADD_S
/* 3014 */    MCD_OPC_FilterValue, 33, 8, 0, // Skip to: 3026
/* 3018 */    MCD_OPC_CheckPredicate, 10, 231, 37, // Skip to: 12725
/* 3022 */    MCD_OPC_Decode, 197, 6, 87, // Opcode: MADD_D32
/* 3026 */    MCD_OPC_FilterValue, 40, 8, 0, // Skip to: 3038
/* 3030 */    MCD_OPC_CheckPredicate, 3, 219, 37, // Skip to: 12725
/* 3034 */    MCD_OPC_Decode, 205, 7, 86, // Opcode: MSUB_S
/* 3038 */    MCD_OPC_FilterValue, 41, 8, 0, // Skip to: 3050
/* 3042 */    MCD_OPC_CheckPredicate, 10, 207, 37, // Skip to: 12725
/* 3046 */    MCD_OPC_Decode, 198, 7, 87, // Opcode: MSUB_D32
/* 3050 */    MCD_OPC_FilterValue, 48, 8, 0, // Skip to: 3062
/* 3054 */    MCD_OPC_CheckPredicate, 11, 195, 37, // Skip to: 12725
/* 3058 */    MCD_OPC_Decode, 141, 8, 86, // Opcode: NMADD_S
/* 3062 */    MCD_OPC_FilterValue, 49, 8, 0, // Skip to: 3074
/* 3066 */    MCD_OPC_CheckPredicate, 12, 183, 37, // Skip to: 12725
/* 3070 */    MCD_OPC_Decode, 138, 8, 87, // Opcode: NMADD_D32
/* 3074 */    MCD_OPC_FilterValue, 56, 8, 0, // Skip to: 3086
/* 3078 */    MCD_OPC_CheckPredicate, 11, 171, 37, // Skip to: 12725
/* 3082 */    MCD_OPC_Decode, 146, 8, 86, // Opcode: NMSUB_S
/* 3086 */    MCD_OPC_FilterValue, 57, 163, 37, // Skip to: 12725
/* 3090 */    MCD_OPC_CheckPredicate, 12, 159, 37, // Skip to: 12725
/* 3094 */    MCD_OPC_Decode, 143, 8, 87, // Opcode: NMSUB_D32
/* 3098 */    MCD_OPC_FilterValue, 28, 171, 0, // Skip to: 3273
/* 3102 */    MCD_OPC_ExtractField, 0, 11,  // Inst{10-0} ...
/* 3105 */    MCD_OPC_FilterValue, 0, 29, 0, // Skip to: 3138
/* 3109 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3112 */    MCD_OPC_FilterValue, 0, 137, 37, // Skip to: 12725
/* 3116 */    MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 3130
/* 3120 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3130
/* 3126 */    MCD_OPC_Decode, 187, 6, 20, // Opcode: MADD
/* 3130 */    MCD_OPC_CheckPredicate, 5, 119, 37, // Skip to: 12725
/* 3134 */    MCD_OPC_Decode, 200, 6, 88, // Opcode: MADD_DSP
/* 3138 */    MCD_OPC_FilterValue, 1, 29, 0, // Skip to: 3171
/* 3142 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3145 */    MCD_OPC_FilterValue, 0, 104, 37, // Skip to: 12725
/* 3149 */    MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 3163
/* 3153 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3163
/* 3159 */    MCD_OPC_Decode, 190, 6, 20, // Opcode: MADDU
/* 3163 */    MCD_OPC_CheckPredicate, 5, 86, 37, // Skip to: 12725
/* 3167 */    MCD_OPC_Decode, 191, 6, 88, // Opcode: MADDU_DSP
/* 3171 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 3183
/* 3175 */    MCD_OPC_CheckPredicate, 2, 74, 37, // Skip to: 12725
/* 3179 */    MCD_OPC_Decode, 222, 7, 13, // Opcode: MUL
/* 3183 */    MCD_OPC_FilterValue, 4, 29, 0, // Skip to: 3216
/* 3187 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3190 */    MCD_OPC_FilterValue, 0, 59, 37, // Skip to: 12725
/* 3194 */    MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 3208
/* 3198 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3208
/* 3204 */    MCD_OPC_Decode, 188, 7, 20, // Opcode: MSUB
/* 3208 */    MCD_OPC_CheckPredicate, 5, 41, 37, // Skip to: 12725
/* 3212 */    MCD_OPC_Decode, 201, 7, 88, // Opcode: MSUB_DSP
/* 3216 */    MCD_OPC_FilterValue, 5, 29, 0, // Skip to: 3249
/* 3220 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3223 */    MCD_OPC_FilterValue, 0, 26, 37, // Skip to: 12725
/* 3227 */    MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 3241
/* 3231 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3241
/* 3237 */    MCD_OPC_Decode, 191, 7, 20, // Opcode: MSUBU
/* 3241 */    MCD_OPC_CheckPredicate, 5, 8, 37, // Skip to: 12725
/* 3245 */    MCD_OPC_Decode, 192, 7, 88, // Opcode: MSUBU_DSP
/* 3249 */    MCD_OPC_FilterValue, 32, 8, 0, // Skip to: 3261
/* 3253 */    MCD_OPC_CheckPredicate, 13, 252, 36, // Skip to: 12725
/* 3257 */    MCD_OPC_Decode, 192, 2, 89, // Opcode: CLZ
/* 3261 */    MCD_OPC_FilterValue, 33, 244, 36, // Skip to: 12725
/* 3265 */    MCD_OPC_CheckPredicate, 13, 240, 36, // Skip to: 12725
/* 3269 */    MCD_OPC_Decode, 174, 2, 89, // Opcode: CLO
/* 3273 */    MCD_OPC_FilterValue, 30, 99, 26, // Skip to: 10032
/* 3277 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 3280 */    MCD_OPC_FilterValue, 0, 50, 0, // Skip to: 3334
/* 3284 */    MCD_OPC_ExtractField, 24, 2,  // Inst{25-24} ...
/* 3287 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 3298
/* 3291 */    MCD_OPC_CheckPredicate, 4, 214, 36, // Skip to: 12725
/* 3295 */    MCD_OPC_Decode, 73, 90, // Opcode: ANDI_B
/* 3298 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3310
/* 3302 */    MCD_OPC_CheckPredicate, 4, 203, 36, // Skip to: 12725
/* 3306 */    MCD_OPC_Decode, 161, 8, 90, // Opcode: ORI_B
/* 3310 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 3322
/* 3314 */    MCD_OPC_CheckPredicate, 4, 191, 36, // Skip to: 12725
/* 3318 */    MCD_OPC_Decode, 151, 8, 90, // Opcode: NORI_B
/* 3322 */    MCD_OPC_FilterValue, 3, 183, 36, // Skip to: 12725
/* 3326 */    MCD_OPC_CheckPredicate, 4, 179, 36, // Skip to: 12725
/* 3330 */    MCD_OPC_Decode, 188, 11, 90, // Opcode: XORI_B
/* 3334 */    MCD_OPC_FilterValue, 1, 39, 0, // Skip to: 3377
/* 3338 */    MCD_OPC_ExtractField, 24, 2,  // Inst{25-24} ...
/* 3341 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3353
/* 3345 */    MCD_OPC_CheckPredicate, 4, 160, 36, // Skip to: 12725
/* 3349 */    MCD_OPC_Decode, 199, 1, 91, // Opcode: BMNZI_B
/* 3353 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3365
/* 3357 */    MCD_OPC_CheckPredicate, 4, 148, 36, // Skip to: 12725
/* 3361 */    MCD_OPC_Decode, 201, 1, 91, // Opcode: BMZI_B
/* 3365 */    MCD_OPC_FilterValue, 2, 140, 36, // Skip to: 12725
/* 3369 */    MCD_OPC_CheckPredicate, 4, 136, 36, // Skip to: 12725
/* 3373 */    MCD_OPC_Decode, 223, 1, 91, // Opcode: BSELI_B
/* 3377 */    MCD_OPC_FilterValue, 2, 39, 0, // Skip to: 3420
/* 3381 */    MCD_OPC_ExtractField, 24, 2,  // Inst{25-24} ...
/* 3384 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3396
/* 3388 */    MCD_OPC_CheckPredicate, 4, 117, 36, // Skip to: 12725
/* 3392 */    MCD_OPC_Decode, 166, 9, 90, // Opcode: SHF_B
/* 3396 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3408
/* 3400 */    MCD_OPC_CheckPredicate, 4, 105, 36, // Skip to: 12725
/* 3404 */    MCD_OPC_Decode, 167, 9, 92, // Opcode: SHF_H
/* 3408 */    MCD_OPC_FilterValue, 2, 97, 36, // Skip to: 12725
/* 3412 */    MCD_OPC_CheckPredicate, 4, 93, 36, // Skip to: 12725
/* 3416 */    MCD_OPC_Decode, 168, 9, 93, // Opcode: SHF_W
/* 3420 */    MCD_OPC_FilterValue, 6, 31, 1, // Skip to: 3711
/* 3424 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 3427 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 3438
/* 3431 */    MCD_OPC_CheckPredicate, 4, 74, 36, // Skip to: 12725
/* 3435 */    MCD_OPC_Decode, 49, 94, // Opcode: ADDVI_B
/* 3438 */    MCD_OPC_FilterValue, 1, 7, 0, // Skip to: 3449
/* 3442 */    MCD_OPC_CheckPredicate, 4, 63, 36, // Skip to: 12725
/* 3446 */    MCD_OPC_Decode, 51, 95, // Opcode: ADDVI_H
/* 3449 */    MCD_OPC_FilterValue, 2, 7, 0, // Skip to: 3460
/* 3453 */    MCD_OPC_CheckPredicate, 4, 52, 36, // Skip to: 12725
/* 3457 */    MCD_OPC_Decode, 52, 96, // Opcode: ADDVI_W
/* 3460 */    MCD_OPC_FilterValue, 3, 7, 0, // Skip to: 3471
/* 3464 */    MCD_OPC_CheckPredicate, 4, 41, 36, // Skip to: 12725
/* 3468 */    MCD_OPC_Decode, 50, 97, // Opcode: ADDVI_D
/* 3471 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 3483
/* 3475 */    MCD_OPC_CheckPredicate, 4, 30, 36, // Skip to: 12725
/* 3479 */    MCD_OPC_Decode, 191, 10, 94, // Opcode: SUBVI_B
/* 3483 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 3495
/* 3487 */    MCD_OPC_CheckPredicate, 4, 18, 36, // Skip to: 12725
/* 3491 */    MCD_OPC_Decode, 193, 10, 95, // Opcode: SUBVI_H
/* 3495 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 3507
/* 3499 */    MCD_OPC_CheckPredicate, 4, 6, 36, // Skip to: 12725
/* 3503 */    MCD_OPC_Decode, 194, 10, 96, // Opcode: SUBVI_W
/* 3507 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 3519
/* 3511 */    MCD_OPC_CheckPredicate, 4, 250, 35, // Skip to: 12725
/* 3515 */    MCD_OPC_Decode, 192, 10, 97, // Opcode: SUBVI_D
/* 3519 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 3531
/* 3523 */    MCD_OPC_CheckPredicate, 4, 238, 35, // Skip to: 12725
/* 3527 */    MCD_OPC_Decode, 210, 6, 94, // Opcode: MAXI_S_B
/* 3531 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 3543
/* 3535 */    MCD_OPC_CheckPredicate, 4, 226, 35, // Skip to: 12725
/* 3539 */    MCD_OPC_Decode, 212, 6, 95, // Opcode: MAXI_S_H
/* 3543 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 3555
/* 3547 */    MCD_OPC_CheckPredicate, 4, 214, 35, // Skip to: 12725
/* 3551 */    MCD_OPC_Decode, 213, 6, 96, // Opcode: MAXI_S_W
/* 3555 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 3567
/* 3559 */    MCD_OPC_CheckPredicate, 4, 202, 35, // Skip to: 12725
/* 3563 */    MCD_OPC_Decode, 211, 6, 97, // Opcode: MAXI_S_D
/* 3567 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 3579
/* 3571 */    MCD_OPC_CheckPredicate, 4, 190, 35, // Skip to: 12725
/* 3575 */    MCD_OPC_Decode, 214, 6, 94, // Opcode: MAXI_U_B
/* 3579 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 3591
/* 3583 */    MCD_OPC_CheckPredicate, 4, 178, 35, // Skip to: 12725
/* 3587 */    MCD_OPC_Decode, 216, 6, 95, // Opcode: MAXI_U_H
/* 3591 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 3603
/* 3595 */    MCD_OPC_CheckPredicate, 4, 166, 35, // Skip to: 12725
/* 3599 */    MCD_OPC_Decode, 217, 6, 96, // Opcode: MAXI_U_W
/* 3603 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 3615
/* 3607 */    MCD_OPC_CheckPredicate, 4, 154, 35, // Skip to: 12725
/* 3611 */    MCD_OPC_Decode, 215, 6, 97, // Opcode: MAXI_U_D
/* 3615 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 3627
/* 3619 */    MCD_OPC_CheckPredicate, 4, 142, 35, // Skip to: 12725
/* 3623 */    MCD_OPC_Decode, 244, 6, 94, // Opcode: MINI_S_B
/* 3627 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 3639
/* 3631 */    MCD_OPC_CheckPredicate, 4, 130, 35, // Skip to: 12725
/* 3635 */    MCD_OPC_Decode, 246, 6, 95, // Opcode: MINI_S_H
/* 3639 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 3651
/* 3643 */    MCD_OPC_CheckPredicate, 4, 118, 35, // Skip to: 12725
/* 3647 */    MCD_OPC_Decode, 247, 6, 96, // Opcode: MINI_S_W
/* 3651 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 3663
/* 3655 */    MCD_OPC_CheckPredicate, 4, 106, 35, // Skip to: 12725
/* 3659 */    MCD_OPC_Decode, 245, 6, 97, // Opcode: MINI_S_D
/* 3663 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 3675
/* 3667 */    MCD_OPC_CheckPredicate, 4, 94, 35, // Skip to: 12725
/* 3671 */    MCD_OPC_Decode, 248, 6, 94, // Opcode: MINI_U_B
/* 3675 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 3687
/* 3679 */    MCD_OPC_CheckPredicate, 4, 82, 35, // Skip to: 12725
/* 3683 */    MCD_OPC_Decode, 250, 6, 95, // Opcode: MINI_U_H
/* 3687 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 3699
/* 3691 */    MCD_OPC_CheckPredicate, 4, 70, 35, // Skip to: 12725
/* 3695 */    MCD_OPC_Decode, 251, 6, 96, // Opcode: MINI_U_W
/* 3699 */    MCD_OPC_FilterValue, 23, 62, 35, // Skip to: 12725
/* 3703 */    MCD_OPC_CheckPredicate, 4, 58, 35, // Skip to: 12725
/* 3707 */    MCD_OPC_Decode, 249, 6, 97, // Opcode: MINI_U_D
/* 3711 */    MCD_OPC_FilterValue, 7, 35, 1, // Skip to: 4006
/* 3715 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 3718 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3730
/* 3722 */    MCD_OPC_CheckPredicate, 4, 39, 35, // Skip to: 12725
/* 3726 */    MCD_OPC_Decode, 147, 2, 94, // Opcode: CEQI_B
/* 3730 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3742
/* 3734 */    MCD_OPC_CheckPredicate, 4, 27, 35, // Skip to: 12725
/* 3738 */    MCD_OPC_Decode, 149, 2, 95, // Opcode: CEQI_H
/* 3742 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 3754
/* 3746 */    MCD_OPC_CheckPredicate, 4, 15, 35, // Skip to: 12725
/* 3750 */    MCD_OPC_Decode, 150, 2, 96, // Opcode: CEQI_W
/* 3754 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 3766
/* 3758 */    MCD_OPC_CheckPredicate, 4, 3, 35, // Skip to: 12725
/* 3762 */    MCD_OPC_Decode, 148, 2, 97, // Opcode: CEQI_D
/* 3766 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 3778
/* 3770 */    MCD_OPC_CheckPredicate, 4, 247, 34, // Skip to: 12725
/* 3774 */    MCD_OPC_Decode, 176, 2, 94, // Opcode: CLTI_S_B
/* 3778 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 3790
/* 3782 */    MCD_OPC_CheckPredicate, 4, 235, 34, // Skip to: 12725
/* 3786 */    MCD_OPC_Decode, 178, 2, 95, // Opcode: CLTI_S_H
/* 3790 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 3802
/* 3794 */    MCD_OPC_CheckPredicate, 4, 223, 34, // Skip to: 12725
/* 3798 */    MCD_OPC_Decode, 179, 2, 96, // Opcode: CLTI_S_W
/* 3802 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 3814
/* 3806 */    MCD_OPC_CheckPredicate, 4, 211, 34, // Skip to: 12725
/* 3810 */    MCD_OPC_Decode, 177, 2, 97, // Opcode: CLTI_S_D
/* 3814 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 3826
/* 3818 */    MCD_OPC_CheckPredicate, 4, 199, 34, // Skip to: 12725
/* 3822 */    MCD_OPC_Decode, 180, 2, 94, // Opcode: CLTI_U_B
/* 3826 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 3838
/* 3830 */    MCD_OPC_CheckPredicate, 4, 187, 34, // Skip to: 12725
/* 3834 */    MCD_OPC_Decode, 182, 2, 95, // Opcode: CLTI_U_H
/* 3838 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 3850
/* 3842 */    MCD_OPC_CheckPredicate, 4, 175, 34, // Skip to: 12725
/* 3846 */    MCD_OPC_Decode, 183, 2, 96, // Opcode: CLTI_U_W
/* 3850 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 3862
/* 3854 */    MCD_OPC_CheckPredicate, 4, 163, 34, // Skip to: 12725
/* 3858 */    MCD_OPC_Decode, 181, 2, 97, // Opcode: CLTI_U_D
/* 3862 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 3874
/* 3866 */    MCD_OPC_CheckPredicate, 4, 151, 34, // Skip to: 12725
/* 3870 */    MCD_OPC_Decode, 158, 2, 94, // Opcode: CLEI_S_B
/* 3874 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 3886
/* 3878 */    MCD_OPC_CheckPredicate, 4, 139, 34, // Skip to: 12725
/* 3882 */    MCD_OPC_Decode, 160, 2, 95, // Opcode: CLEI_S_H
/* 3886 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 3898
/* 3890 */    MCD_OPC_CheckPredicate, 4, 127, 34, // Skip to: 12725
/* 3894 */    MCD_OPC_Decode, 161, 2, 96, // Opcode: CLEI_S_W
/* 3898 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 3910
/* 3902 */    MCD_OPC_CheckPredicate, 4, 115, 34, // Skip to: 12725
/* 3906 */    MCD_OPC_Decode, 159, 2, 97, // Opcode: CLEI_S_D
/* 3910 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 3922
/* 3914 */    MCD_OPC_CheckPredicate, 4, 103, 34, // Skip to: 12725
/* 3918 */    MCD_OPC_Decode, 162, 2, 94, // Opcode: CLEI_U_B
/* 3922 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 3934
/* 3926 */    MCD_OPC_CheckPredicate, 4, 91, 34, // Skip to: 12725
/* 3930 */    MCD_OPC_Decode, 164, 2, 95, // Opcode: CLEI_U_H
/* 3934 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 3946
/* 3938 */    MCD_OPC_CheckPredicate, 4, 79, 34, // Skip to: 12725
/* 3942 */    MCD_OPC_Decode, 165, 2, 96, // Opcode: CLEI_U_W
/* 3946 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 3958
/* 3950 */    MCD_OPC_CheckPredicate, 4, 67, 34, // Skip to: 12725
/* 3954 */    MCD_OPC_Decode, 163, 2, 97, // Opcode: CLEI_U_D
/* 3958 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 3970
/* 3962 */    MCD_OPC_CheckPredicate, 4, 55, 34, // Skip to: 12725
/* 3966 */    MCD_OPC_Decode, 248, 5, 98, // Opcode: LDI_B
/* 3970 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 3982
/* 3974 */    MCD_OPC_CheckPredicate, 4, 43, 34, // Skip to: 12725
/* 3978 */    MCD_OPC_Decode, 250, 5, 99, // Opcode: LDI_H
/* 3982 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 3994
/* 3986 */    MCD_OPC_CheckPredicate, 4, 31, 34, // Skip to: 12725
/* 3990 */    MCD_OPC_Decode, 251, 5, 100, // Opcode: LDI_W
/* 3994 */    MCD_OPC_FilterValue, 27, 23, 34, // Skip to: 12725
/* 3998 */    MCD_OPC_CheckPredicate, 4, 19, 34, // Skip to: 12725
/* 4002 */    MCD_OPC_Decode, 249, 5, 101, // Opcode: LDI_D
/* 4006 */    MCD_OPC_FilterValue, 9, 35, 2, // Skip to: 4557
/* 4010 */    MCD_OPC_ExtractField, 22, 4,  // Inst{25-22} ...
/* 4013 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4025
/* 4017 */    MCD_OPC_CheckPredicate, 4, 0, 34, // Skip to: 12725
/* 4021 */    MCD_OPC_Decode, 206, 9, 102, // Opcode: SLLI_D
/* 4025 */    MCD_OPC_FilterValue, 1, 52, 0, // Skip to: 4081
/* 4029 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4032 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4044
/* 4036 */    MCD_OPC_CheckPredicate, 4, 237, 33, // Skip to: 12725
/* 4040 */    MCD_OPC_Decode, 208, 9, 96, // Opcode: SLLI_W
/* 4044 */    MCD_OPC_FilterValue, 1, 229, 33, // Skip to: 12725
/* 4048 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4051 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4063
/* 4055 */    MCD_OPC_CheckPredicate, 4, 218, 33, // Skip to: 12725
/* 4059 */    MCD_OPC_Decode, 207, 9, 103, // Opcode: SLLI_H
/* 4063 */    MCD_OPC_FilterValue, 1, 210, 33, // Skip to: 12725
/* 4067 */    MCD_OPC_CheckPredicate, 4, 206, 33, // Skip to: 12725
/* 4071 */    MCD_OPC_CheckField, 19, 1, 0, 200, 33, // Skip to: 12725
/* 4077 */    MCD_OPC_Decode, 205, 9, 104, // Opcode: SLLI_B
/* 4081 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 4093
/* 4085 */    MCD_OPC_CheckPredicate, 4, 188, 33, // Skip to: 12725
/* 4089 */    MCD_OPC_Decode, 243, 9, 102, // Opcode: SRAI_D
/* 4093 */    MCD_OPC_FilterValue, 3, 52, 0, // Skip to: 4149
/* 4097 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4100 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4112
/* 4104 */    MCD_OPC_CheckPredicate, 4, 169, 33, // Skip to: 12725
/* 4108 */    MCD_OPC_Decode, 245, 9, 96, // Opcode: SRAI_W
/* 4112 */    MCD_OPC_FilterValue, 1, 161, 33, // Skip to: 12725
/* 4116 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4119 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4131
/* 4123 */    MCD_OPC_CheckPredicate, 4, 150, 33, // Skip to: 12725
/* 4127 */    MCD_OPC_Decode, 244, 9, 103, // Opcode: SRAI_H
/* 4131 */    MCD_OPC_FilterValue, 1, 142, 33, // Skip to: 12725
/* 4135 */    MCD_OPC_CheckPredicate, 4, 138, 33, // Skip to: 12725
/* 4139 */    MCD_OPC_CheckField, 19, 1, 0, 132, 33, // Skip to: 12725
/* 4145 */    MCD_OPC_Decode, 242, 9, 104, // Opcode: SRAI_B
/* 4149 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 4161
/* 4153 */    MCD_OPC_CheckPredicate, 4, 120, 33, // Skip to: 12725
/* 4157 */    MCD_OPC_Decode, 135, 10, 102, // Opcode: SRLI_D
/* 4161 */    MCD_OPC_FilterValue, 5, 52, 0, // Skip to: 4217
/* 4165 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4168 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4180
/* 4172 */    MCD_OPC_CheckPredicate, 4, 101, 33, // Skip to: 12725
/* 4176 */    MCD_OPC_Decode, 137, 10, 96, // Opcode: SRLI_W
/* 4180 */    MCD_OPC_FilterValue, 1, 93, 33, // Skip to: 12725
/* 4184 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4187 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4199
/* 4191 */    MCD_OPC_CheckPredicate, 4, 82, 33, // Skip to: 12725
/* 4195 */    MCD_OPC_Decode, 136, 10, 103, // Opcode: SRLI_H
/* 4199 */    MCD_OPC_FilterValue, 1, 74, 33, // Skip to: 12725
/* 4203 */    MCD_OPC_CheckPredicate, 4, 70, 33, // Skip to: 12725
/* 4207 */    MCD_OPC_CheckField, 19, 1, 0, 64, 33, // Skip to: 12725
/* 4213 */    MCD_OPC_Decode, 134, 10, 104, // Opcode: SRLI_B
/* 4217 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 4229
/* 4221 */    MCD_OPC_CheckPredicate, 4, 52, 33, // Skip to: 12725
/* 4225 */    MCD_OPC_Decode, 156, 1, 102, // Opcode: BCLRI_D
/* 4229 */    MCD_OPC_FilterValue, 7, 52, 0, // Skip to: 4285
/* 4233 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4236 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4248
/* 4240 */    MCD_OPC_CheckPredicate, 4, 33, 33, // Skip to: 12725
/* 4244 */    MCD_OPC_Decode, 158, 1, 96, // Opcode: BCLRI_W
/* 4248 */    MCD_OPC_FilterValue, 1, 25, 33, // Skip to: 12725
/* 4252 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4255 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4267
/* 4259 */    MCD_OPC_CheckPredicate, 4, 14, 33, // Skip to: 12725
/* 4263 */    MCD_OPC_Decode, 157, 1, 103, // Opcode: BCLRI_H
/* 4267 */    MCD_OPC_FilterValue, 1, 6, 33, // Skip to: 12725
/* 4271 */    MCD_OPC_CheckPredicate, 4, 2, 33, // Skip to: 12725
/* 4275 */    MCD_OPC_CheckField, 19, 1, 0, 252, 32, // Skip to: 12725
/* 4281 */    MCD_OPC_Decode, 155, 1, 104, // Opcode: BCLRI_B
/* 4285 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 4297
/* 4289 */    MCD_OPC_CheckPredicate, 4, 240, 32, // Skip to: 12725
/* 4293 */    MCD_OPC_Decode, 231, 1, 102, // Opcode: BSETI_D
/* 4297 */    MCD_OPC_FilterValue, 9, 52, 0, // Skip to: 4353
/* 4301 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4304 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4316
/* 4308 */    MCD_OPC_CheckPredicate, 4, 221, 32, // Skip to: 12725
/* 4312 */    MCD_OPC_Decode, 233, 1, 96, // Opcode: BSETI_W
/* 4316 */    MCD_OPC_FilterValue, 1, 213, 32, // Skip to: 12725
/* 4320 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4323 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4335
/* 4327 */    MCD_OPC_CheckPredicate, 4, 202, 32, // Skip to: 12725
/* 4331 */    MCD_OPC_Decode, 232, 1, 103, // Opcode: BSETI_H
/* 4335 */    MCD_OPC_FilterValue, 1, 194, 32, // Skip to: 12725
/* 4339 */    MCD_OPC_CheckPredicate, 4, 190, 32, // Skip to: 12725
/* 4343 */    MCD_OPC_CheckField, 19, 1, 0, 184, 32, // Skip to: 12725
/* 4349 */    MCD_OPC_Decode, 230, 1, 104, // Opcode: BSETI_B
/* 4353 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 4365
/* 4357 */    MCD_OPC_CheckPredicate, 4, 172, 32, // Skip to: 12725
/* 4361 */    MCD_OPC_Decode, 206, 1, 102, // Opcode: BNEGI_D
/* 4365 */    MCD_OPC_FilterValue, 11, 52, 0, // Skip to: 4421
/* 4369 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4372 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4384
/* 4376 */    MCD_OPC_CheckPredicate, 4, 153, 32, // Skip to: 12725
/* 4380 */    MCD_OPC_Decode, 208, 1, 96, // Opcode: BNEGI_W
/* 4384 */    MCD_OPC_FilterValue, 1, 145, 32, // Skip to: 12725
/* 4388 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4391 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4403
/* 4395 */    MCD_OPC_CheckPredicate, 4, 134, 32, // Skip to: 12725
/* 4399 */    MCD_OPC_Decode, 207, 1, 103, // Opcode: BNEGI_H
/* 4403 */    MCD_OPC_FilterValue, 1, 126, 32, // Skip to: 12725
/* 4407 */    MCD_OPC_CheckPredicate, 4, 122, 32, // Skip to: 12725
/* 4411 */    MCD_OPC_CheckField, 19, 1, 0, 116, 32, // Skip to: 12725
/* 4417 */    MCD_OPC_Decode, 205, 1, 104, // Opcode: BNEGI_B
/* 4421 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 4433
/* 4425 */    MCD_OPC_CheckPredicate, 4, 104, 32, // Skip to: 12725
/* 4429 */    MCD_OPC_Decode, 175, 1, 105, // Opcode: BINSLI_D
/* 4433 */    MCD_OPC_FilterValue, 13, 52, 0, // Skip to: 4489
/* 4437 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4440 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4452
/* 4444 */    MCD_OPC_CheckPredicate, 4, 85, 32, // Skip to: 12725
/* 4448 */    MCD_OPC_Decode, 177, 1, 106, // Opcode: BINSLI_W
/* 4452 */    MCD_OPC_FilterValue, 1, 77, 32, // Skip to: 12725
/* 4456 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4459 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4471
/* 4463 */    MCD_OPC_CheckPredicate, 4, 66, 32, // Skip to: 12725
/* 4467 */    MCD_OPC_Decode, 176, 1, 107, // Opcode: BINSLI_H
/* 4471 */    MCD_OPC_FilterValue, 1, 58, 32, // Skip to: 12725
/* 4475 */    MCD_OPC_CheckPredicate, 4, 54, 32, // Skip to: 12725
/* 4479 */    MCD_OPC_CheckField, 19, 1, 0, 48, 32, // Skip to: 12725
/* 4485 */    MCD_OPC_Decode, 174, 1, 108, // Opcode: BINSLI_B
/* 4489 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 4501
/* 4493 */    MCD_OPC_CheckPredicate, 4, 36, 32, // Skip to: 12725
/* 4497 */    MCD_OPC_Decode, 183, 1, 105, // Opcode: BINSRI_D
/* 4501 */    MCD_OPC_FilterValue, 15, 28, 32, // Skip to: 12725
/* 4505 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4508 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4520
/* 4512 */    MCD_OPC_CheckPredicate, 4, 17, 32, // Skip to: 12725
/* 4516 */    MCD_OPC_Decode, 185, 1, 106, // Opcode: BINSRI_W
/* 4520 */    MCD_OPC_FilterValue, 1, 9, 32, // Skip to: 12725
/* 4524 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4527 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4539
/* 4531 */    MCD_OPC_CheckPredicate, 4, 254, 31, // Skip to: 12725
/* 4535 */    MCD_OPC_Decode, 184, 1, 107, // Opcode: BINSRI_H
/* 4539 */    MCD_OPC_FilterValue, 1, 246, 31, // Skip to: 12725
/* 4543 */    MCD_OPC_CheckPredicate, 4, 242, 31, // Skip to: 12725
/* 4547 */    MCD_OPC_CheckField, 19, 1, 0, 236, 31, // Skip to: 12725
/* 4553 */    MCD_OPC_Decode, 182, 1, 108, // Opcode: BINSRI_B
/* 4557 */    MCD_OPC_FilterValue, 10, 19, 1, // Skip to: 4836
/* 4561 */    MCD_OPC_ExtractField, 22, 4,  // Inst{25-22} ...
/* 4564 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4576
/* 4568 */    MCD_OPC_CheckPredicate, 4, 217, 31, // Skip to: 12725
/* 4572 */    MCD_OPC_Decode, 134, 9, 102, // Opcode: SAT_S_D
/* 4576 */    MCD_OPC_FilterValue, 1, 52, 0, // Skip to: 4632
/* 4580 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4583 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4595
/* 4587 */    MCD_OPC_CheckPredicate, 4, 198, 31, // Skip to: 12725
/* 4591 */    MCD_OPC_Decode, 136, 9, 96, // Opcode: SAT_S_W
/* 4595 */    MCD_OPC_FilterValue, 1, 190, 31, // Skip to: 12725
/* 4599 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4602 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4614
/* 4606 */    MCD_OPC_CheckPredicate, 4, 179, 31, // Skip to: 12725
/* 4610 */    MCD_OPC_Decode, 135, 9, 103, // Opcode: SAT_S_H
/* 4614 */    MCD_OPC_FilterValue, 1, 171, 31, // Skip to: 12725
/* 4618 */    MCD_OPC_CheckPredicate, 4, 167, 31, // Skip to: 12725
/* 4622 */    MCD_OPC_CheckField, 19, 1, 0, 161, 31, // Skip to: 12725
/* 4628 */    MCD_OPC_Decode, 133, 9, 104, // Opcode: SAT_S_B
/* 4632 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 4644
/* 4636 */    MCD_OPC_CheckPredicate, 4, 149, 31, // Skip to: 12725
/* 4640 */    MCD_OPC_Decode, 138, 9, 102, // Opcode: SAT_U_D
/* 4644 */    MCD_OPC_FilterValue, 3, 52, 0, // Skip to: 4700
/* 4648 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4651 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4663
/* 4655 */    MCD_OPC_CheckPredicate, 4, 130, 31, // Skip to: 12725
/* 4659 */    MCD_OPC_Decode, 140, 9, 96, // Opcode: SAT_U_W
/* 4663 */    MCD_OPC_FilterValue, 1, 122, 31, // Skip to: 12725
/* 4667 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4670 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4682
/* 4674 */    MCD_OPC_CheckPredicate, 4, 111, 31, // Skip to: 12725
/* 4678 */    MCD_OPC_Decode, 139, 9, 103, // Opcode: SAT_U_H
/* 4682 */    MCD_OPC_FilterValue, 1, 103, 31, // Skip to: 12725
/* 4686 */    MCD_OPC_CheckPredicate, 4, 99, 31, // Skip to: 12725
/* 4690 */    MCD_OPC_CheckField, 19, 1, 0, 93, 31, // Skip to: 12725
/* 4696 */    MCD_OPC_Decode, 137, 9, 104, // Opcode: SAT_U_B
/* 4700 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 4712
/* 4704 */    MCD_OPC_CheckPredicate, 4, 81, 31, // Skip to: 12725
/* 4708 */    MCD_OPC_Decode, 247, 9, 102, // Opcode: SRARI_D
/* 4712 */    MCD_OPC_FilterValue, 5, 52, 0, // Skip to: 4768
/* 4716 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4719 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4731
/* 4723 */    MCD_OPC_CheckPredicate, 4, 62, 31, // Skip to: 12725
/* 4727 */    MCD_OPC_Decode, 249, 9, 96, // Opcode: SRARI_W
/* 4731 */    MCD_OPC_FilterValue, 1, 54, 31, // Skip to: 12725
/* 4735 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4738 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4750
/* 4742 */    MCD_OPC_CheckPredicate, 4, 43, 31, // Skip to: 12725
/* 4746 */    MCD_OPC_Decode, 248, 9, 103, // Opcode: SRARI_H
/* 4750 */    MCD_OPC_FilterValue, 1, 35, 31, // Skip to: 12725
/* 4754 */    MCD_OPC_CheckPredicate, 4, 31, 31, // Skip to: 12725
/* 4758 */    MCD_OPC_CheckField, 19, 1, 0, 25, 31, // Skip to: 12725
/* 4764 */    MCD_OPC_Decode, 246, 9, 104, // Opcode: SRARI_B
/* 4768 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 4780
/* 4772 */    MCD_OPC_CheckPredicate, 4, 13, 31, // Skip to: 12725
/* 4776 */    MCD_OPC_Decode, 139, 10, 102, // Opcode: SRLRI_D
/* 4780 */    MCD_OPC_FilterValue, 7, 5, 31, // Skip to: 12725
/* 4784 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4787 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4799
/* 4791 */    MCD_OPC_CheckPredicate, 4, 250, 30, // Skip to: 12725
/* 4795 */    MCD_OPC_Decode, 141, 10, 96, // Opcode: SRLRI_W
/* 4799 */    MCD_OPC_FilterValue, 1, 242, 30, // Skip to: 12725
/* 4803 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4806 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4818
/* 4810 */    MCD_OPC_CheckPredicate, 4, 231, 30, // Skip to: 12725
/* 4814 */    MCD_OPC_Decode, 140, 10, 103, // Opcode: SRLRI_H
/* 4818 */    MCD_OPC_FilterValue, 1, 223, 30, // Skip to: 12725
/* 4822 */    MCD_OPC_CheckPredicate, 4, 219, 30, // Skip to: 12725
/* 4826 */    MCD_OPC_CheckField, 19, 1, 0, 213, 30, // Skip to: 12725
/* 4832 */    MCD_OPC_Decode, 138, 10, 104, // Opcode: SRLRI_B
/* 4836 */    MCD_OPC_FilterValue, 13, 131, 1, // Skip to: 5227
/* 4840 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 4843 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4855
/* 4847 */    MCD_OPC_CheckPredicate, 4, 194, 30, // Skip to: 12725
/* 4851 */    MCD_OPC_Decode, 211, 9, 109, // Opcode: SLL_B
/* 4855 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 4867
/* 4859 */    MCD_OPC_CheckPredicate, 4, 182, 30, // Skip to: 12725
/* 4863 */    MCD_OPC_Decode, 213, 9, 110, // Opcode: SLL_H
/* 4867 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 4879
/* 4871 */    MCD_OPC_CheckPredicate, 4, 170, 30, // Skip to: 12725
/* 4875 */    MCD_OPC_Decode, 215, 9, 111, // Opcode: SLL_W
/* 4879 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 4891
/* 4883 */    MCD_OPC_CheckPredicate, 4, 158, 30, // Skip to: 12725
/* 4887 */    MCD_OPC_Decode, 212, 9, 112, // Opcode: SLL_D
/* 4891 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 4903
/* 4895 */    MCD_OPC_CheckPredicate, 4, 146, 30, // Skip to: 12725
/* 4899 */    MCD_OPC_Decode, 128, 10, 109, // Opcode: SRA_B
/* 4903 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 4915
/* 4907 */    MCD_OPC_CheckPredicate, 4, 134, 30, // Skip to: 12725
/* 4911 */    MCD_OPC_Decode, 130, 10, 110, // Opcode: SRA_H
/* 4915 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 4927
/* 4919 */    MCD_OPC_CheckPredicate, 4, 122, 30, // Skip to: 12725
/* 4923 */    MCD_OPC_Decode, 132, 10, 111, // Opcode: SRA_W
/* 4927 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 4939
/* 4931 */    MCD_OPC_CheckPredicate, 4, 110, 30, // Skip to: 12725
/* 4935 */    MCD_OPC_Decode, 129, 10, 112, // Opcode: SRA_D
/* 4939 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 4951
/* 4943 */    MCD_OPC_CheckPredicate, 4, 98, 30, // Skip to: 12725
/* 4947 */    MCD_OPC_Decode, 148, 10, 109, // Opcode: SRL_B
/* 4951 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 4963
/* 4955 */    MCD_OPC_CheckPredicate, 4, 86, 30, // Skip to: 12725
/* 4959 */    MCD_OPC_Decode, 150, 10, 110, // Opcode: SRL_H
/* 4963 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 4975
/* 4967 */    MCD_OPC_CheckPredicate, 4, 74, 30, // Skip to: 12725
/* 4971 */    MCD_OPC_Decode, 152, 10, 111, // Opcode: SRL_W
/* 4975 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 4987
/* 4979 */    MCD_OPC_CheckPredicate, 4, 62, 30, // Skip to: 12725
/* 4983 */    MCD_OPC_Decode, 149, 10, 112, // Opcode: SRL_D
/* 4987 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 4999
/* 4991 */    MCD_OPC_CheckPredicate, 4, 50, 30, // Skip to: 12725
/* 4995 */    MCD_OPC_Decode, 159, 1, 109, // Opcode: BCLR_B
/* 4999 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 5011
/* 5003 */    MCD_OPC_CheckPredicate, 4, 38, 30, // Skip to: 12725
/* 5007 */    MCD_OPC_Decode, 161, 1, 110, // Opcode: BCLR_H
/* 5011 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 5023
/* 5015 */    MCD_OPC_CheckPredicate, 4, 26, 30, // Skip to: 12725
/* 5019 */    MCD_OPC_Decode, 162, 1, 111, // Opcode: BCLR_W
/* 5023 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 5035
/* 5027 */    MCD_OPC_CheckPredicate, 4, 14, 30, // Skip to: 12725
/* 5031 */    MCD_OPC_Decode, 160, 1, 112, // Opcode: BCLR_D
/* 5035 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 5047
/* 5039 */    MCD_OPC_CheckPredicate, 4, 2, 30, // Skip to: 12725
/* 5043 */    MCD_OPC_Decode, 234, 1, 109, // Opcode: BSET_B
/* 5047 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 5059
/* 5051 */    MCD_OPC_CheckPredicate, 4, 246, 29, // Skip to: 12725
/* 5055 */    MCD_OPC_Decode, 236, 1, 110, // Opcode: BSET_H
/* 5059 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 5071
/* 5063 */    MCD_OPC_CheckPredicate, 4, 234, 29, // Skip to: 12725
/* 5067 */    MCD_OPC_Decode, 237, 1, 111, // Opcode: BSET_W
/* 5071 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 5083
/* 5075 */    MCD_OPC_CheckPredicate, 4, 222, 29, // Skip to: 12725
/* 5079 */    MCD_OPC_Decode, 235, 1, 112, // Opcode: BSET_D
/* 5083 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 5095
/* 5087 */    MCD_OPC_CheckPredicate, 4, 210, 29, // Skip to: 12725
/* 5091 */    MCD_OPC_Decode, 209, 1, 109, // Opcode: BNEG_B
/* 5095 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 5107
/* 5099 */    MCD_OPC_CheckPredicate, 4, 198, 29, // Skip to: 12725
/* 5103 */    MCD_OPC_Decode, 211, 1, 110, // Opcode: BNEG_H
/* 5107 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 5119
/* 5111 */    MCD_OPC_CheckPredicate, 4, 186, 29, // Skip to: 12725
/* 5115 */    MCD_OPC_Decode, 212, 1, 111, // Opcode: BNEG_W
/* 5119 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 5131
/* 5123 */    MCD_OPC_CheckPredicate, 4, 174, 29, // Skip to: 12725
/* 5127 */    MCD_OPC_Decode, 210, 1, 112, // Opcode: BNEG_D
/* 5131 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 5143
/* 5135 */    MCD_OPC_CheckPredicate, 4, 162, 29, // Skip to: 12725
/* 5139 */    MCD_OPC_Decode, 178, 1, 113, // Opcode: BINSL_B
/* 5143 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 5155
/* 5147 */    MCD_OPC_CheckPredicate, 4, 150, 29, // Skip to: 12725
/* 5151 */    MCD_OPC_Decode, 180, 1, 114, // Opcode: BINSL_H
/* 5155 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 5167
/* 5159 */    MCD_OPC_CheckPredicate, 4, 138, 29, // Skip to: 12725
/* 5163 */    MCD_OPC_Decode, 181, 1, 115, // Opcode: BINSL_W
/* 5167 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 5179
/* 5171 */    MCD_OPC_CheckPredicate, 4, 126, 29, // Skip to: 12725
/* 5175 */    MCD_OPC_Decode, 179, 1, 116, // Opcode: BINSL_D
/* 5179 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 5191
/* 5183 */    MCD_OPC_CheckPredicate, 4, 114, 29, // Skip to: 12725
/* 5187 */    MCD_OPC_Decode, 186, 1, 113, // Opcode: BINSR_B
/* 5191 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 5203
/* 5195 */    MCD_OPC_CheckPredicate, 4, 102, 29, // Skip to: 12725
/* 5199 */    MCD_OPC_Decode, 188, 1, 114, // Opcode: BINSR_H
/* 5203 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 5215
/* 5207 */    MCD_OPC_CheckPredicate, 4, 90, 29, // Skip to: 12725
/* 5211 */    MCD_OPC_Decode, 189, 1, 115, // Opcode: BINSR_W
/* 5215 */    MCD_OPC_FilterValue, 31, 82, 29, // Skip to: 12725
/* 5219 */    MCD_OPC_CheckPredicate, 4, 78, 29, // Skip to: 12725
/* 5223 */    MCD_OPC_Decode, 187, 1, 116, // Opcode: BINSR_D
/* 5227 */    MCD_OPC_FilterValue, 14, 127, 1, // Skip to: 5614
/* 5231 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 5234 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 5245
/* 5238 */    MCD_OPC_CheckPredicate, 4, 59, 29, // Skip to: 12725
/* 5242 */    MCD_OPC_Decode, 53, 109, // Opcode: ADDV_B
/* 5245 */    MCD_OPC_FilterValue, 1, 7, 0, // Skip to: 5256
/* 5249 */    MCD_OPC_CheckPredicate, 4, 48, 29, // Skip to: 12725
/* 5253 */    MCD_OPC_Decode, 55, 110, // Opcode: ADDV_H
/* 5256 */    MCD_OPC_FilterValue, 2, 7, 0, // Skip to: 5267
/* 5260 */    MCD_OPC_CheckPredicate, 4, 37, 29, // Skip to: 12725
/* 5264 */    MCD_OPC_Decode, 56, 111, // Opcode: ADDV_W
/* 5267 */    MCD_OPC_FilterValue, 3, 7, 0, // Skip to: 5278
/* 5271 */    MCD_OPC_CheckPredicate, 4, 26, 29, // Skip to: 12725
/* 5275 */    MCD_OPC_Decode, 54, 112, // Opcode: ADDV_D
/* 5278 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 5290
/* 5282 */    MCD_OPC_CheckPredicate, 4, 15, 29, // Skip to: 12725
/* 5286 */    MCD_OPC_Decode, 195, 10, 109, // Opcode: SUBV_B
/* 5290 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 5302
/* 5294 */    MCD_OPC_CheckPredicate, 4, 3, 29, // Skip to: 12725
/* 5298 */    MCD_OPC_Decode, 197, 10, 110, // Opcode: SUBV_H
/* 5302 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 5314
/* 5306 */    MCD_OPC_CheckPredicate, 4, 247, 28, // Skip to: 12725
/* 5310 */    MCD_OPC_Decode, 198, 10, 111, // Opcode: SUBV_W
/* 5314 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 5326
/* 5318 */    MCD_OPC_CheckPredicate, 4, 235, 28, // Skip to: 12725
/* 5322 */    MCD_OPC_Decode, 196, 10, 112, // Opcode: SUBV_D
/* 5326 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 5338
/* 5330 */    MCD_OPC_CheckPredicate, 4, 223, 28, // Skip to: 12725
/* 5334 */    MCD_OPC_Decode, 222, 6, 109, // Opcode: MAX_S_B
/* 5338 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 5350
/* 5342 */    MCD_OPC_CheckPredicate, 4, 211, 28, // Skip to: 12725
/* 5346 */    MCD_OPC_Decode, 224, 6, 110, // Opcode: MAX_S_H
/* 5350 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 5362
/* 5354 */    MCD_OPC_CheckPredicate, 4, 199, 28, // Skip to: 12725
/* 5358 */    MCD_OPC_Decode, 225, 6, 111, // Opcode: MAX_S_W
/* 5362 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 5374
/* 5366 */    MCD_OPC_CheckPredicate, 4, 187, 28, // Skip to: 12725
/* 5370 */    MCD_OPC_Decode, 223, 6, 112, // Opcode: MAX_S_D
/* 5374 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 5386
/* 5378 */    MCD_OPC_CheckPredicate, 4, 175, 28, // Skip to: 12725
/* 5382 */    MCD_OPC_Decode, 226, 6, 109, // Opcode: MAX_U_B
/* 5386 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 5398
/* 5390 */    MCD_OPC_CheckPredicate, 4, 163, 28, // Skip to: 12725
/* 5394 */    MCD_OPC_Decode, 228, 6, 110, // Opcode: MAX_U_H
/* 5398 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 5410
/* 5402 */    MCD_OPC_CheckPredicate, 4, 151, 28, // Skip to: 12725
/* 5406 */    MCD_OPC_Decode, 229, 6, 111, // Opcode: MAX_U_W
/* 5410 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 5422
/* 5414 */    MCD_OPC_CheckPredicate, 4, 139, 28, // Skip to: 12725
/* 5418 */    MCD_OPC_Decode, 227, 6, 112, // Opcode: MAX_U_D
/* 5422 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 5434
/* 5426 */    MCD_OPC_CheckPredicate, 4, 127, 28, // Skip to: 12725
/* 5430 */    MCD_OPC_Decode, 128, 7, 109, // Opcode: MIN_S_B
/* 5434 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 5446
/* 5438 */    MCD_OPC_CheckPredicate, 4, 115, 28, // Skip to: 12725
/* 5442 */    MCD_OPC_Decode, 130, 7, 110, // Opcode: MIN_S_H
/* 5446 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 5458
/* 5450 */    MCD_OPC_CheckPredicate, 4, 103, 28, // Skip to: 12725
/* 5454 */    MCD_OPC_Decode, 131, 7, 111, // Opcode: MIN_S_W
/* 5458 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 5470
/* 5462 */    MCD_OPC_CheckPredicate, 4, 91, 28, // Skip to: 12725
/* 5466 */    MCD_OPC_Decode, 129, 7, 112, // Opcode: MIN_S_D
/* 5470 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 5482
/* 5474 */    MCD_OPC_CheckPredicate, 4, 79, 28, // Skip to: 12725
/* 5478 */    MCD_OPC_Decode, 132, 7, 109, // Opcode: MIN_U_B
/* 5482 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 5494
/* 5486 */    MCD_OPC_CheckPredicate, 4, 67, 28, // Skip to: 12725
/* 5490 */    MCD_OPC_Decode, 134, 7, 110, // Opcode: MIN_U_H
/* 5494 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 5506
/* 5498 */    MCD_OPC_CheckPredicate, 4, 55, 28, // Skip to: 12725
/* 5502 */    MCD_OPC_Decode, 135, 7, 111, // Opcode: MIN_U_W
/* 5506 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 5518
/* 5510 */    MCD_OPC_CheckPredicate, 4, 43, 28, // Skip to: 12725
/* 5514 */    MCD_OPC_Decode, 133, 7, 112, // Opcode: MIN_U_D
/* 5518 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 5530
/* 5522 */    MCD_OPC_CheckPredicate, 4, 31, 28, // Skip to: 12725
/* 5526 */    MCD_OPC_Decode, 218, 6, 109, // Opcode: MAX_A_B
/* 5530 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 5542
/* 5534 */    MCD_OPC_CheckPredicate, 4, 19, 28, // Skip to: 12725
/* 5538 */    MCD_OPC_Decode, 220, 6, 110, // Opcode: MAX_A_H
/* 5542 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 5554
/* 5546 */    MCD_OPC_CheckPredicate, 4, 7, 28, // Skip to: 12725
/* 5550 */    MCD_OPC_Decode, 221, 6, 111, // Opcode: MAX_A_W
/* 5554 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 5566
/* 5558 */    MCD_OPC_CheckPredicate, 4, 251, 27, // Skip to: 12725
/* 5562 */    MCD_OPC_Decode, 219, 6, 112, // Opcode: MAX_A_D
/* 5566 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 5578
/* 5570 */    MCD_OPC_CheckPredicate, 4, 239, 27, // Skip to: 12725
/* 5574 */    MCD_OPC_Decode, 252, 6, 109, // Opcode: MIN_A_B
/* 5578 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 5590
/* 5582 */    MCD_OPC_CheckPredicate, 4, 227, 27, // Skip to: 12725
/* 5586 */    MCD_OPC_Decode, 254, 6, 110, // Opcode: MIN_A_H
/* 5590 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 5602
/* 5594 */    MCD_OPC_CheckPredicate, 4, 215, 27, // Skip to: 12725
/* 5598 */    MCD_OPC_Decode, 255, 6, 111, // Opcode: MIN_A_W
/* 5602 */    MCD_OPC_FilterValue, 31, 207, 27, // Skip to: 12725
/* 5606 */    MCD_OPC_CheckPredicate, 4, 203, 27, // Skip to: 12725
/* 5610 */    MCD_OPC_Decode, 253, 6, 112, // Opcode: MIN_A_D
/* 5614 */    MCD_OPC_FilterValue, 15, 243, 0, // Skip to: 5861
/* 5618 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 5621 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5633
/* 5625 */    MCD_OPC_CheckPredicate, 4, 184, 27, // Skip to: 12725
/* 5629 */    MCD_OPC_Decode, 151, 2, 109, // Opcode: CEQ_B
/* 5633 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 5645
/* 5637 */    MCD_OPC_CheckPredicate, 4, 172, 27, // Skip to: 12725
/* 5641 */    MCD_OPC_Decode, 153, 2, 110, // Opcode: CEQ_H
/* 5645 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 5657
/* 5649 */    MCD_OPC_CheckPredicate, 4, 160, 27, // Skip to: 12725
/* 5653 */    MCD_OPC_Decode, 154, 2, 111, // Opcode: CEQ_W
/* 5657 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 5669
/* 5661 */    MCD_OPC_CheckPredicate, 4, 148, 27, // Skip to: 12725
/* 5665 */    MCD_OPC_Decode, 152, 2, 112, // Opcode: CEQ_D
/* 5669 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 5681
/* 5673 */    MCD_OPC_CheckPredicate, 4, 136, 27, // Skip to: 12725
/* 5677 */    MCD_OPC_Decode, 184, 2, 109, // Opcode: CLT_S_B
/* 5681 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 5693
/* 5685 */    MCD_OPC_CheckPredicate, 4, 124, 27, // Skip to: 12725
/* 5689 */    MCD_OPC_Decode, 186, 2, 110, // Opcode: CLT_S_H
/* 5693 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 5705
/* 5697 */    MCD_OPC_CheckPredicate, 4, 112, 27, // Skip to: 12725
/* 5701 */    MCD_OPC_Decode, 187, 2, 111, // Opcode: CLT_S_W
/* 5705 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 5717
/* 5709 */    MCD_OPC_CheckPredicate, 4, 100, 27, // Skip to: 12725
/* 5713 */    MCD_OPC_Decode, 185, 2, 112, // Opcode: CLT_S_D
/* 5717 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 5729
/* 5721 */    MCD_OPC_CheckPredicate, 4, 88, 27, // Skip to: 12725
/* 5725 */    MCD_OPC_Decode, 188, 2, 109, // Opcode: CLT_U_B
/* 5729 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 5741
/* 5733 */    MCD_OPC_CheckPredicate, 4, 76, 27, // Skip to: 12725
/* 5737 */    MCD_OPC_Decode, 190, 2, 110, // Opcode: CLT_U_H
/* 5741 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 5753
/* 5745 */    MCD_OPC_CheckPredicate, 4, 64, 27, // Skip to: 12725
/* 5749 */    MCD_OPC_Decode, 191, 2, 111, // Opcode: CLT_U_W
/* 5753 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 5765
/* 5757 */    MCD_OPC_CheckPredicate, 4, 52, 27, // Skip to: 12725
/* 5761 */    MCD_OPC_Decode, 189, 2, 112, // Opcode: CLT_U_D
/* 5765 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 5777
/* 5769 */    MCD_OPC_CheckPredicate, 4, 40, 27, // Skip to: 12725
/* 5773 */    MCD_OPC_Decode, 166, 2, 109, // Opcode: CLE_S_B
/* 5777 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 5789
/* 5781 */    MCD_OPC_CheckPredicate, 4, 28, 27, // Skip to: 12725
/* 5785 */    MCD_OPC_Decode, 168, 2, 110, // Opcode: CLE_S_H
/* 5789 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 5801
/* 5793 */    MCD_OPC_CheckPredicate, 4, 16, 27, // Skip to: 12725
/* 5797 */    MCD_OPC_Decode, 169, 2, 111, // Opcode: CLE_S_W
/* 5801 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 5813
/* 5805 */    MCD_OPC_CheckPredicate, 4, 4, 27, // Skip to: 12725
/* 5809 */    MCD_OPC_Decode, 167, 2, 112, // Opcode: CLE_S_D
/* 5813 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 5825
/* 5817 */    MCD_OPC_CheckPredicate, 4, 248, 26, // Skip to: 12725
/* 5821 */    MCD_OPC_Decode, 170, 2, 109, // Opcode: CLE_U_B
/* 5825 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 5837
/* 5829 */    MCD_OPC_CheckPredicate, 4, 236, 26, // Skip to: 12725
/* 5833 */    MCD_OPC_Decode, 172, 2, 110, // Opcode: CLE_U_H
/* 5837 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 5849
/* 5841 */    MCD_OPC_CheckPredicate, 4, 224, 26, // Skip to: 12725
/* 5845 */    MCD_OPC_Decode, 173, 2, 111, // Opcode: CLE_U_W
/* 5849 */    MCD_OPC_FilterValue, 23, 216, 26, // Skip to: 12725
/* 5853 */    MCD_OPC_CheckPredicate, 4, 212, 26, // Skip to: 12725
/* 5857 */    MCD_OPC_Decode, 171, 2, 112, // Opcode: CLE_U_D
/* 5861 */    MCD_OPC_FilterValue, 16, 110, 1, // Skip to: 6231
/* 5865 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 5868 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 5879
/* 5872 */    MCD_OPC_CheckPredicate, 4, 193, 26, // Skip to: 12725
/* 5876 */    MCD_OPC_Decode, 58, 109, // Opcode: ADD_A_B
/* 5879 */    MCD_OPC_FilterValue, 1, 7, 0, // Skip to: 5890
/* 5883 */    MCD_OPC_CheckPredicate, 4, 182, 26, // Skip to: 12725
/* 5887 */    MCD_OPC_Decode, 60, 110, // Opcode: ADD_A_H
/* 5890 */    MCD_OPC_FilterValue, 2, 7, 0, // Skip to: 5901
/* 5894 */    MCD_OPC_CheckPredicate, 4, 171, 26, // Skip to: 12725
/* 5898 */    MCD_OPC_Decode, 61, 111, // Opcode: ADD_A_W
/* 5901 */    MCD_OPC_FilterValue, 3, 7, 0, // Skip to: 5912
/* 5905 */    MCD_OPC_CheckPredicate, 4, 160, 26, // Skip to: 12725
/* 5909 */    MCD_OPC_Decode, 59, 112, // Opcode: ADD_A_D
/* 5912 */    MCD_OPC_FilterValue, 4, 7, 0, // Skip to: 5923
/* 5916 */    MCD_OPC_CheckPredicate, 4, 149, 26, // Skip to: 12725
/* 5920 */    MCD_OPC_Decode, 31, 109, // Opcode: ADDS_A_B
/* 5923 */    MCD_OPC_FilterValue, 5, 7, 0, // Skip to: 5934
/* 5927 */    MCD_OPC_CheckPredicate, 4, 138, 26, // Skip to: 12725
/* 5931 */    MCD_OPC_Decode, 33, 110, // Opcode: ADDS_A_H
/* 5934 */    MCD_OPC_FilterValue, 6, 7, 0, // Skip to: 5945
/* 5938 */    MCD_OPC_CheckPredicate, 4, 127, 26, // Skip to: 12725
/* 5942 */    MCD_OPC_Decode, 34, 111, // Opcode: ADDS_A_W
/* 5945 */    MCD_OPC_FilterValue, 7, 7, 0, // Skip to: 5956
/* 5949 */    MCD_OPC_CheckPredicate, 4, 116, 26, // Skip to: 12725
/* 5953 */    MCD_OPC_Decode, 32, 112, // Opcode: ADDS_A_D
/* 5956 */    MCD_OPC_FilterValue, 8, 7, 0, // Skip to: 5967
/* 5960 */    MCD_OPC_CheckPredicate, 4, 105, 26, // Skip to: 12725
/* 5964 */    MCD_OPC_Decode, 35, 109, // Opcode: ADDS_S_B
/* 5967 */    MCD_OPC_FilterValue, 9, 7, 0, // Skip to: 5978
/* 5971 */    MCD_OPC_CheckPredicate, 4, 94, 26, // Skip to: 12725
/* 5975 */    MCD_OPC_Decode, 37, 110, // Opcode: ADDS_S_H
/* 5978 */    MCD_OPC_FilterValue, 10, 7, 0, // Skip to: 5989
/* 5982 */    MCD_OPC_CheckPredicate, 4, 83, 26, // Skip to: 12725
/* 5986 */    MCD_OPC_Decode, 38, 111, // Opcode: ADDS_S_W
/* 5989 */    MCD_OPC_FilterValue, 11, 7, 0, // Skip to: 6000
/* 5993 */    MCD_OPC_CheckPredicate, 4, 72, 26, // Skip to: 12725
/* 5997 */    MCD_OPC_Decode, 36, 112, // Opcode: ADDS_S_D
/* 6000 */    MCD_OPC_FilterValue, 12, 7, 0, // Skip to: 6011
/* 6004 */    MCD_OPC_CheckPredicate, 4, 61, 26, // Skip to: 12725
/* 6008 */    MCD_OPC_Decode, 39, 109, // Opcode: ADDS_U_B
/* 6011 */    MCD_OPC_FilterValue, 13, 7, 0, // Skip to: 6022
/* 6015 */    MCD_OPC_CheckPredicate, 4, 50, 26, // Skip to: 12725
/* 6019 */    MCD_OPC_Decode, 41, 110, // Opcode: ADDS_U_H
/* 6022 */    MCD_OPC_FilterValue, 14, 7, 0, // Skip to: 6033
/* 6026 */    MCD_OPC_CheckPredicate, 4, 39, 26, // Skip to: 12725
/* 6030 */    MCD_OPC_Decode, 42, 111, // Opcode: ADDS_U_W
/* 6033 */    MCD_OPC_FilterValue, 15, 7, 0, // Skip to: 6044
/* 6037 */    MCD_OPC_CheckPredicate, 4, 28, 26, // Skip to: 12725
/* 6041 */    MCD_OPC_Decode, 40, 112, // Opcode: ADDS_U_D
/* 6044 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 6056
/* 6048 */    MCD_OPC_CheckPredicate, 4, 17, 26, // Skip to: 12725
/* 6052 */    MCD_OPC_Decode, 131, 1, 109, // Opcode: AVE_S_B
/* 6056 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 6068
/* 6060 */    MCD_OPC_CheckPredicate, 4, 5, 26, // Skip to: 12725
/* 6064 */    MCD_OPC_Decode, 133, 1, 110, // Opcode: AVE_S_H
/* 6068 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 6080
/* 6072 */    MCD_OPC_CheckPredicate, 4, 249, 25, // Skip to: 12725
/* 6076 */    MCD_OPC_Decode, 134, 1, 111, // Opcode: AVE_S_W
/* 6080 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 6092
/* 6084 */    MCD_OPC_CheckPredicate, 4, 237, 25, // Skip to: 12725
/* 6088 */    MCD_OPC_Decode, 132, 1, 112, // Opcode: AVE_S_D
/* 6092 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 6104
/* 6096 */    MCD_OPC_CheckPredicate, 4, 225, 25, // Skip to: 12725
/* 6100 */    MCD_OPC_Decode, 135, 1, 109, // Opcode: AVE_U_B
/* 6104 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 6116
/* 6108 */    MCD_OPC_CheckPredicate, 4, 213, 25, // Skip to: 12725
/* 6112 */    MCD_OPC_Decode, 137, 1, 110, // Opcode: AVE_U_H
/* 6116 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 6128
/* 6120 */    MCD_OPC_CheckPredicate, 4, 201, 25, // Skip to: 12725
/* 6124 */    MCD_OPC_Decode, 138, 1, 111, // Opcode: AVE_U_W
/* 6128 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 6140
/* 6132 */    MCD_OPC_CheckPredicate, 4, 189, 25, // Skip to: 12725
/* 6136 */    MCD_OPC_Decode, 136, 1, 112, // Opcode: AVE_U_D
/* 6140 */    MCD_OPC_FilterValue, 24, 7, 0, // Skip to: 6151
/* 6144 */    MCD_OPC_CheckPredicate, 4, 177, 25, // Skip to: 12725
/* 6148 */    MCD_OPC_Decode, 123, 109, // Opcode: AVER_S_B
/* 6151 */    MCD_OPC_FilterValue, 25, 7, 0, // Skip to: 6162
/* 6155 */    MCD_OPC_CheckPredicate, 4, 166, 25, // Skip to: 12725
/* 6159 */    MCD_OPC_Decode, 125, 110, // Opcode: AVER_S_H
/* 6162 */    MCD_OPC_FilterValue, 26, 7, 0, // Skip to: 6173
/* 6166 */    MCD_OPC_CheckPredicate, 4, 155, 25, // Skip to: 12725
/* 6170 */    MCD_OPC_Decode, 126, 111, // Opcode: AVER_S_W
/* 6173 */    MCD_OPC_FilterValue, 27, 7, 0, // Skip to: 6184
/* 6177 */    MCD_OPC_CheckPredicate, 4, 144, 25, // Skip to: 12725
/* 6181 */    MCD_OPC_Decode, 124, 112, // Opcode: AVER_S_D
/* 6184 */    MCD_OPC_FilterValue, 28, 7, 0, // Skip to: 6195
/* 6188 */    MCD_OPC_CheckPredicate, 4, 133, 25, // Skip to: 12725
/* 6192 */    MCD_OPC_Decode, 127, 109, // Opcode: AVER_U_B
/* 6195 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 6207
/* 6199 */    MCD_OPC_CheckPredicate, 4, 122, 25, // Skip to: 12725
/* 6203 */    MCD_OPC_Decode, 129, 1, 110, // Opcode: AVER_U_H
/* 6207 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 6219
/* 6211 */    MCD_OPC_CheckPredicate, 4, 110, 25, // Skip to: 12725
/* 6215 */    MCD_OPC_Decode, 130, 1, 111, // Opcode: AVER_U_W
/* 6219 */    MCD_OPC_FilterValue, 31, 102, 25, // Skip to: 12725
/* 6223 */    MCD_OPC_CheckPredicate, 4, 98, 25, // Skip to: 12725
/* 6227 */    MCD_OPC_Decode, 128, 1, 112, // Opcode: AVER_U_D
/* 6231 */    MCD_OPC_FilterValue, 17, 27, 1, // Skip to: 6518
/* 6235 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 6238 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 6250
/* 6242 */    MCD_OPC_CheckPredicate, 4, 79, 25, // Skip to: 12725
/* 6246 */    MCD_OPC_Decode, 177, 10, 109, // Opcode: SUBS_S_B
/* 6250 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 6262
/* 6254 */    MCD_OPC_CheckPredicate, 4, 67, 25, // Skip to: 12725
/* 6258 */    MCD_OPC_Decode, 179, 10, 110, // Opcode: SUBS_S_H
/* 6262 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 6274
/* 6266 */    MCD_OPC_CheckPredicate, 4, 55, 25, // Skip to: 12725
/* 6270 */    MCD_OPC_Decode, 180, 10, 111, // Opcode: SUBS_S_W
/* 6274 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 6286
/* 6278 */    MCD_OPC_CheckPredicate, 4, 43, 25, // Skip to: 12725
/* 6282 */    MCD_OPC_Decode, 178, 10, 112, // Opcode: SUBS_S_D
/* 6286 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 6298
/* 6290 */    MCD_OPC_CheckPredicate, 4, 31, 25, // Skip to: 12725
/* 6294 */    MCD_OPC_Decode, 181, 10, 109, // Opcode: SUBS_U_B
/* 6298 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 6310
/* 6302 */    MCD_OPC_CheckPredicate, 4, 19, 25, // Skip to: 12725
/* 6306 */    MCD_OPC_Decode, 183, 10, 110, // Opcode: SUBS_U_H
/* 6310 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 6322
/* 6314 */    MCD_OPC_CheckPredicate, 4, 7, 25, // Skip to: 12725
/* 6318 */    MCD_OPC_Decode, 184, 10, 111, // Opcode: SUBS_U_W
/* 6322 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 6334
/* 6326 */    MCD_OPC_CheckPredicate, 4, 251, 24, // Skip to: 12725
/* 6330 */    MCD_OPC_Decode, 182, 10, 112, // Opcode: SUBS_U_D
/* 6334 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 6346
/* 6338 */    MCD_OPC_CheckPredicate, 4, 239, 24, // Skip to: 12725
/* 6342 */    MCD_OPC_Decode, 169, 10, 109, // Opcode: SUBSUS_U_B
/* 6346 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 6358
/* 6350 */    MCD_OPC_CheckPredicate, 4, 227, 24, // Skip to: 12725
/* 6354 */    MCD_OPC_Decode, 171, 10, 110, // Opcode: SUBSUS_U_H
/* 6358 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 6370
/* 6362 */    MCD_OPC_CheckPredicate, 4, 215, 24, // Skip to: 12725
/* 6366 */    MCD_OPC_Decode, 172, 10, 111, // Opcode: SUBSUS_U_W
/* 6370 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 6382
/* 6374 */    MCD_OPC_CheckPredicate, 4, 203, 24, // Skip to: 12725
/* 6378 */    MCD_OPC_Decode, 170, 10, 112, // Opcode: SUBSUS_U_D
/* 6382 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 6394
/* 6386 */    MCD_OPC_CheckPredicate, 4, 191, 24, // Skip to: 12725
/* 6390 */    MCD_OPC_Decode, 173, 10, 109, // Opcode: SUBSUU_S_B
/* 6394 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 6406
/* 6398 */    MCD_OPC_CheckPredicate, 4, 179, 24, // Skip to: 12725
/* 6402 */    MCD_OPC_Decode, 175, 10, 110, // Opcode: SUBSUU_S_H
/* 6406 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 6418
/* 6410 */    MCD_OPC_CheckPredicate, 4, 167, 24, // Skip to: 12725
/* 6414 */    MCD_OPC_Decode, 176, 10, 111, // Opcode: SUBSUU_S_W
/* 6418 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 6430
/* 6422 */    MCD_OPC_CheckPredicate, 4, 155, 24, // Skip to: 12725
/* 6426 */    MCD_OPC_Decode, 174, 10, 112, // Opcode: SUBSUU_S_D
/* 6430 */    MCD_OPC_FilterValue, 16, 7, 0, // Skip to: 6441
/* 6434 */    MCD_OPC_CheckPredicate, 4, 143, 24, // Skip to: 12725
/* 6438 */    MCD_OPC_Decode, 83, 109, // Opcode: ASUB_S_B
/* 6441 */    MCD_OPC_FilterValue, 17, 7, 0, // Skip to: 6452
/* 6445 */    MCD_OPC_CheckPredicate, 4, 132, 24, // Skip to: 12725
/* 6449 */    MCD_OPC_Decode, 85, 110, // Opcode: ASUB_S_H
/* 6452 */    MCD_OPC_FilterValue, 18, 7, 0, // Skip to: 6463
/* 6456 */    MCD_OPC_CheckPredicate, 4, 121, 24, // Skip to: 12725
/* 6460 */    MCD_OPC_Decode, 86, 111, // Opcode: ASUB_S_W
/* 6463 */    MCD_OPC_FilterValue, 19, 7, 0, // Skip to: 6474
/* 6467 */    MCD_OPC_CheckPredicate, 4, 110, 24, // Skip to: 12725
/* 6471 */    MCD_OPC_Decode, 84, 112, // Opcode: ASUB_S_D
/* 6474 */    MCD_OPC_FilterValue, 20, 7, 0, // Skip to: 6485
/* 6478 */    MCD_OPC_CheckPredicate, 4, 99, 24, // Skip to: 12725
/* 6482 */    MCD_OPC_Decode, 87, 109, // Opcode: ASUB_U_B
/* 6485 */    MCD_OPC_FilterValue, 21, 7, 0, // Skip to: 6496
/* 6489 */    MCD_OPC_CheckPredicate, 4, 88, 24, // Skip to: 12725
/* 6493 */    MCD_OPC_Decode, 89, 110, // Opcode: ASUB_U_H
/* 6496 */    MCD_OPC_FilterValue, 22, 7, 0, // Skip to: 6507
/* 6500 */    MCD_OPC_CheckPredicate, 4, 77, 24, // Skip to: 12725
/* 6504 */    MCD_OPC_Decode, 90, 111, // Opcode: ASUB_U_W
/* 6507 */    MCD_OPC_FilterValue, 23, 70, 24, // Skip to: 12725
/* 6511 */    MCD_OPC_CheckPredicate, 4, 66, 24, // Skip to: 12725
/* 6515 */    MCD_OPC_Decode, 88, 112, // Opcode: ASUB_U_D
/* 6518 */    MCD_OPC_FilterValue, 18, 83, 1, // Skip to: 6861
/* 6522 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 6525 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 6537
/* 6529 */    MCD_OPC_CheckPredicate, 4, 48, 24, // Skip to: 12725
/* 6533 */    MCD_OPC_Decode, 241, 7, 109, // Opcode: MULV_B
/* 6537 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 6549
/* 6541 */    MCD_OPC_CheckPredicate, 4, 36, 24, // Skip to: 12725
/* 6545 */    MCD_OPC_Decode, 243, 7, 110, // Opcode: MULV_H
/* 6549 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 6561
/* 6553 */    MCD_OPC_CheckPredicate, 4, 24, 24, // Skip to: 12725
/* 6557 */    MCD_OPC_Decode, 244, 7, 111, // Opcode: MULV_W
/* 6561 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 6573
/* 6565 */    MCD_OPC_CheckPredicate, 4, 12, 24, // Skip to: 12725
/* 6569 */    MCD_OPC_Decode, 242, 7, 112, // Opcode: MULV_D
/* 6573 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 6585
/* 6577 */    MCD_OPC_CheckPredicate, 4, 0, 24, // Skip to: 12725
/* 6581 */    MCD_OPC_Decode, 193, 6, 113, // Opcode: MADDV_B
/* 6585 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 6597
/* 6589 */    MCD_OPC_CheckPredicate, 4, 244, 23, // Skip to: 12725
/* 6593 */    MCD_OPC_Decode, 195, 6, 114, // Opcode: MADDV_H
/* 6597 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 6609
/* 6601 */    MCD_OPC_CheckPredicate, 4, 232, 23, // Skip to: 12725
/* 6605 */    MCD_OPC_Decode, 196, 6, 115, // Opcode: MADDV_W
/* 6609 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 6621
/* 6613 */    MCD_OPC_CheckPredicate, 4, 220, 23, // Skip to: 12725
/* 6617 */    MCD_OPC_Decode, 194, 6, 116, // Opcode: MADDV_D
/* 6621 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 6633
/* 6625 */    MCD_OPC_CheckPredicate, 4, 208, 23, // Skip to: 12725
/* 6629 */    MCD_OPC_Decode, 194, 7, 113, // Opcode: MSUBV_B
/* 6633 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 6645
/* 6637 */    MCD_OPC_CheckPredicate, 4, 196, 23, // Skip to: 12725
/* 6641 */    MCD_OPC_Decode, 196, 7, 114, // Opcode: MSUBV_H
/* 6645 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 6657
/* 6649 */    MCD_OPC_CheckPredicate, 4, 184, 23, // Skip to: 12725
/* 6653 */    MCD_OPC_Decode, 197, 7, 115, // Opcode: MSUBV_W
/* 6657 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 6669
/* 6661 */    MCD_OPC_CheckPredicate, 4, 172, 23, // Skip to: 12725
/* 6665 */    MCD_OPC_Decode, 195, 7, 116, // Opcode: MSUBV_D
/* 6669 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 6681
/* 6673 */    MCD_OPC_CheckPredicate, 4, 160, 23, // Skip to: 12725
/* 6677 */    MCD_OPC_Decode, 179, 3, 109, // Opcode: DIV_S_B
/* 6681 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 6693
/* 6685 */    MCD_OPC_CheckPredicate, 4, 148, 23, // Skip to: 12725
/* 6689 */    MCD_OPC_Decode, 181, 3, 110, // Opcode: DIV_S_H
/* 6693 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 6705
/* 6697 */    MCD_OPC_CheckPredicate, 4, 136, 23, // Skip to: 12725
/* 6701 */    MCD_OPC_Decode, 182, 3, 111, // Opcode: DIV_S_W
/* 6705 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 6717
/* 6709 */    MCD_OPC_CheckPredicate, 4, 124, 23, // Skip to: 12725
/* 6713 */    MCD_OPC_Decode, 180, 3, 112, // Opcode: DIV_S_D
/* 6717 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 6729
/* 6721 */    MCD_OPC_CheckPredicate, 4, 112, 23, // Skip to: 12725
/* 6725 */    MCD_OPC_Decode, 183, 3, 109, // Opcode: DIV_U_B
/* 6729 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 6741
/* 6733 */    MCD_OPC_CheckPredicate, 4, 100, 23, // Skip to: 12725
/* 6737 */    MCD_OPC_Decode, 185, 3, 110, // Opcode: DIV_U_H
/* 6741 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 6753
/* 6745 */    MCD_OPC_CheckPredicate, 4, 88, 23, // Skip to: 12725
/* 6749 */    MCD_OPC_Decode, 186, 3, 111, // Opcode: DIV_U_W
/* 6753 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 6765
/* 6757 */    MCD_OPC_CheckPredicate, 4, 76, 23, // Skip to: 12725
/* 6761 */    MCD_OPC_Decode, 184, 3, 112, // Opcode: DIV_U_D
/* 6765 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 6777
/* 6769 */    MCD_OPC_CheckPredicate, 4, 64, 23, // Skip to: 12725
/* 6773 */    MCD_OPC_Decode, 139, 7, 109, // Opcode: MOD_S_B
/* 6777 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 6789
/* 6781 */    MCD_OPC_CheckPredicate, 4, 52, 23, // Skip to: 12725
/* 6785 */    MCD_OPC_Decode, 141, 7, 110, // Opcode: MOD_S_H
/* 6789 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 6801
/* 6793 */    MCD_OPC_CheckPredicate, 4, 40, 23, // Skip to: 12725
/* 6797 */    MCD_OPC_Decode, 142, 7, 111, // Opcode: MOD_S_W
/* 6801 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 6813
/* 6805 */    MCD_OPC_CheckPredicate, 4, 28, 23, // Skip to: 12725
/* 6809 */    MCD_OPC_Decode, 140, 7, 112, // Opcode: MOD_S_D
/* 6813 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 6825
/* 6817 */    MCD_OPC_CheckPredicate, 4, 16, 23, // Skip to: 12725
/* 6821 */    MCD_OPC_Decode, 143, 7, 109, // Opcode: MOD_U_B
/* 6825 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 6837
/* 6829 */    MCD_OPC_CheckPredicate, 4, 4, 23, // Skip to: 12725
/* 6833 */    MCD_OPC_Decode, 145, 7, 110, // Opcode: MOD_U_H
/* 6837 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 6849
/* 6841 */    MCD_OPC_CheckPredicate, 4, 248, 22, // Skip to: 12725
/* 6845 */    MCD_OPC_Decode, 146, 7, 111, // Opcode: MOD_U_W
/* 6849 */    MCD_OPC_FilterValue, 31, 240, 22, // Skip to: 12725
/* 6853 */    MCD_OPC_CheckPredicate, 4, 236, 22, // Skip to: 12725
/* 6857 */    MCD_OPC_Decode, 144, 7, 112, // Opcode: MOD_U_D
/* 6861 */    MCD_OPC_FilterValue, 19, 219, 0, // Skip to: 7084
/* 6865 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 6868 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 6880
/* 6872 */    MCD_OPC_CheckPredicate, 4, 217, 22, // Skip to: 12725
/* 6876 */    MCD_OPC_Decode, 197, 3, 117, // Opcode: DOTP_S_H
/* 6880 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 6892
/* 6884 */    MCD_OPC_CheckPredicate, 4, 205, 22, // Skip to: 12725
/* 6888 */    MCD_OPC_Decode, 198, 3, 118, // Opcode: DOTP_S_W
/* 6892 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 6904
/* 6896 */    MCD_OPC_CheckPredicate, 4, 193, 22, // Skip to: 12725
/* 6900 */    MCD_OPC_Decode, 196, 3, 119, // Opcode: DOTP_S_D
/* 6904 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 6916
/* 6908 */    MCD_OPC_CheckPredicate, 4, 181, 22, // Skip to: 12725
/* 6912 */    MCD_OPC_Decode, 200, 3, 117, // Opcode: DOTP_U_H
/* 6916 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 6928
/* 6920 */    MCD_OPC_CheckPredicate, 4, 169, 22, // Skip to: 12725
/* 6924 */    MCD_OPC_Decode, 201, 3, 118, // Opcode: DOTP_U_W
/* 6928 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 6940
/* 6932 */    MCD_OPC_CheckPredicate, 4, 157, 22, // Skip to: 12725
/* 6936 */    MCD_OPC_Decode, 199, 3, 119, // Opcode: DOTP_U_D
/* 6940 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 6952
/* 6944 */    MCD_OPC_CheckPredicate, 4, 145, 22, // Skip to: 12725
/* 6948 */    MCD_OPC_Decode, 203, 3, 120, // Opcode: DPADD_S_H
/* 6952 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 6964
/* 6956 */    MCD_OPC_CheckPredicate, 4, 133, 22, // Skip to: 12725
/* 6960 */    MCD_OPC_Decode, 204, 3, 121, // Opcode: DPADD_S_W
/* 6964 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 6976
/* 6968 */    MCD_OPC_CheckPredicate, 4, 121, 22, // Skip to: 12725
/* 6972 */    MCD_OPC_Decode, 202, 3, 122, // Opcode: DPADD_S_D
/* 6976 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 6988
/* 6980 */    MCD_OPC_CheckPredicate, 4, 109, 22, // Skip to: 12725
/* 6984 */    MCD_OPC_Decode, 206, 3, 120, // Opcode: DPADD_U_H
/* 6988 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 7000
/* 6992 */    MCD_OPC_CheckPredicate, 4, 97, 22, // Skip to: 12725
/* 6996 */    MCD_OPC_Decode, 207, 3, 121, // Opcode: DPADD_U_W
/* 7000 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 7012
/* 7004 */    MCD_OPC_CheckPredicate, 4, 85, 22, // Skip to: 12725
/* 7008 */    MCD_OPC_Decode, 205, 3, 122, // Opcode: DPADD_U_D
/* 7012 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 7024
/* 7016 */    MCD_OPC_CheckPredicate, 4, 73, 22, // Skip to: 12725
/* 7020 */    MCD_OPC_Decode, 221, 3, 120, // Opcode: DPSUB_S_H
/* 7024 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 7036
/* 7028 */    MCD_OPC_CheckPredicate, 4, 61, 22, // Skip to: 12725
/* 7032 */    MCD_OPC_Decode, 222, 3, 121, // Opcode: DPSUB_S_W
/* 7036 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 7048
/* 7040 */    MCD_OPC_CheckPredicate, 4, 49, 22, // Skip to: 12725
/* 7044 */    MCD_OPC_Decode, 220, 3, 122, // Opcode: DPSUB_S_D
/* 7048 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 7060
/* 7052 */    MCD_OPC_CheckPredicate, 4, 37, 22, // Skip to: 12725
/* 7056 */    MCD_OPC_Decode, 224, 3, 120, // Opcode: DPSUB_U_H
/* 7060 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 7072
/* 7064 */    MCD_OPC_CheckPredicate, 4, 25, 22, // Skip to: 12725
/* 7068 */    MCD_OPC_Decode, 225, 3, 121, // Opcode: DPSUB_U_W
/* 7072 */    MCD_OPC_FilterValue, 23, 17, 22, // Skip to: 12725
/* 7076 */    MCD_OPC_CheckPredicate, 4, 13, 22, // Skip to: 12725
/* 7080 */    MCD_OPC_Decode, 223, 3, 122, // Opcode: DPSUB_U_D
/* 7084 */    MCD_OPC_FilterValue, 20, 134, 1, // Skip to: 7478
/* 7088 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 7091 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 7103
/* 7095 */    MCD_OPC_CheckPredicate, 4, 250, 21, // Skip to: 12725
/* 7099 */    MCD_OPC_Decode, 198, 9, 123, // Opcode: SLD_B
/* 7103 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 7115
/* 7107 */    MCD_OPC_CheckPredicate, 4, 238, 21, // Skip to: 12725
/* 7111 */    MCD_OPC_Decode, 200, 9, 124, // Opcode: SLD_H
/* 7115 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 7127
/* 7119 */    MCD_OPC_CheckPredicate, 4, 226, 21, // Skip to: 12725
/* 7123 */    MCD_OPC_Decode, 201, 9, 125, // Opcode: SLD_W
/* 7127 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 7139
/* 7131 */    MCD_OPC_CheckPredicate, 4, 214, 21, // Skip to: 12725
/* 7135 */    MCD_OPC_Decode, 199, 9, 126, // Opcode: SLD_D
/* 7139 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 7151
/* 7143 */    MCD_OPC_CheckPredicate, 4, 202, 21, // Skip to: 12725
/* 7147 */    MCD_OPC_Decode, 237, 9, 127, // Opcode: SPLAT_B
/* 7151 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 7164
/* 7155 */    MCD_OPC_CheckPredicate, 4, 190, 21, // Skip to: 12725
/* 7159 */    MCD_OPC_Decode, 239, 9, 128, 1, // Opcode: SPLAT_H
/* 7164 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 7177
/* 7168 */    MCD_OPC_CheckPredicate, 4, 177, 21, // Skip to: 12725
/* 7172 */    MCD_OPC_Decode, 240, 9, 129, 1, // Opcode: SPLAT_W
/* 7177 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 7190
/* 7181 */    MCD_OPC_CheckPredicate, 4, 164, 21, // Skip to: 12725
/* 7185 */    MCD_OPC_Decode, 238, 9, 130, 1, // Opcode: SPLAT_D
/* 7190 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 7202
/* 7194 */    MCD_OPC_CheckPredicate, 4, 151, 21, // Skip to: 12725
/* 7198 */    MCD_OPC_Decode, 172, 8, 109, // Opcode: PCKEV_B
/* 7202 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 7214
/* 7206 */    MCD_OPC_CheckPredicate, 4, 139, 21, // Skip to: 12725
/* 7210 */    MCD_OPC_Decode, 174, 8, 110, // Opcode: PCKEV_H
/* 7214 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 7226
/* 7218 */    MCD_OPC_CheckPredicate, 4, 127, 21, // Skip to: 12725
/* 7222 */    MCD_OPC_Decode, 175, 8, 111, // Opcode: PCKEV_W
/* 7226 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 7238
/* 7230 */    MCD_OPC_CheckPredicate, 4, 115, 21, // Skip to: 12725
/* 7234 */    MCD_OPC_Decode, 173, 8, 112, // Opcode: PCKEV_D
/* 7238 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 7250
/* 7242 */    MCD_OPC_CheckPredicate, 4, 103, 21, // Skip to: 12725
/* 7246 */    MCD_OPC_Decode, 176, 8, 109, // Opcode: PCKOD_B
/* 7250 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 7262
/* 7254 */    MCD_OPC_CheckPredicate, 4, 91, 21, // Skip to: 12725
/* 7258 */    MCD_OPC_Decode, 178, 8, 110, // Opcode: PCKOD_H
/* 7262 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 7274
/* 7266 */    MCD_OPC_CheckPredicate, 4, 79, 21, // Skip to: 12725
/* 7270 */    MCD_OPC_Decode, 179, 8, 111, // Opcode: PCKOD_W
/* 7274 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 7286
/* 7278 */    MCD_OPC_CheckPredicate, 4, 67, 21, // Skip to: 12725
/* 7282 */    MCD_OPC_Decode, 177, 8, 112, // Opcode: PCKOD_D
/* 7286 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 7298
/* 7290 */    MCD_OPC_CheckPredicate, 4, 55, 21, // Skip to: 12725
/* 7294 */    MCD_OPC_Decode, 194, 5, 109, // Opcode: ILVL_B
/* 7298 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 7310
/* 7302 */    MCD_OPC_CheckPredicate, 4, 43, 21, // Skip to: 12725
/* 7306 */    MCD_OPC_Decode, 196, 5, 110, // Opcode: ILVL_H
/* 7310 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 7322
/* 7314 */    MCD_OPC_CheckPredicate, 4, 31, 21, // Skip to: 12725
/* 7318 */    MCD_OPC_Decode, 197, 5, 111, // Opcode: ILVL_W
/* 7322 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 7334
/* 7326 */    MCD_OPC_CheckPredicate, 4, 19, 21, // Skip to: 12725
/* 7330 */    MCD_OPC_Decode, 195, 5, 112, // Opcode: ILVL_D
/* 7334 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 7346
/* 7338 */    MCD_OPC_CheckPredicate, 4, 7, 21, // Skip to: 12725
/* 7342 */    MCD_OPC_Decode, 202, 5, 109, // Opcode: ILVR_B
/* 7346 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 7358
/* 7350 */    MCD_OPC_CheckPredicate, 4, 251, 20, // Skip to: 12725
/* 7354 */    MCD_OPC_Decode, 204, 5, 110, // Opcode: ILVR_H
/* 7358 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 7370
/* 7362 */    MCD_OPC_CheckPredicate, 4, 239, 20, // Skip to: 12725
/* 7366 */    MCD_OPC_Decode, 205, 5, 111, // Opcode: ILVR_W
/* 7370 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 7382
/* 7374 */    MCD_OPC_CheckPredicate, 4, 227, 20, // Skip to: 12725
/* 7378 */    MCD_OPC_Decode, 203, 5, 112, // Opcode: ILVR_D
/* 7382 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 7394
/* 7386 */    MCD_OPC_CheckPredicate, 4, 215, 20, // Skip to: 12725
/* 7390 */    MCD_OPC_Decode, 190, 5, 109, // Opcode: ILVEV_B
/* 7394 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 7406
/* 7398 */    MCD_OPC_CheckPredicate, 4, 203, 20, // Skip to: 12725
/* 7402 */    MCD_OPC_Decode, 192, 5, 110, // Opcode: ILVEV_H
/* 7406 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 7418
/* 7410 */    MCD_OPC_CheckPredicate, 4, 191, 20, // Skip to: 12725
/* 7414 */    MCD_OPC_Decode, 193, 5, 111, // Opcode: ILVEV_W
/* 7418 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 7430
/* 7422 */    MCD_OPC_CheckPredicate, 4, 179, 20, // Skip to: 12725
/* 7426 */    MCD_OPC_Decode, 191, 5, 112, // Opcode: ILVEV_D
/* 7430 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 7442
/* 7434 */    MCD_OPC_CheckPredicate, 4, 167, 20, // Skip to: 12725
/* 7438 */    MCD_OPC_Decode, 198, 5, 109, // Opcode: ILVOD_B
/* 7442 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 7454
/* 7446 */    MCD_OPC_CheckPredicate, 4, 155, 20, // Skip to: 12725
/* 7450 */    MCD_OPC_Decode, 200, 5, 110, // Opcode: ILVOD_H
/* 7454 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 7466
/* 7458 */    MCD_OPC_CheckPredicate, 4, 143, 20, // Skip to: 12725
/* 7462 */    MCD_OPC_Decode, 201, 5, 111, // Opcode: ILVOD_W
/* 7466 */    MCD_OPC_FilterValue, 31, 135, 20, // Skip to: 12725
/* 7470 */    MCD_OPC_CheckPredicate, 4, 131, 20, // Skip to: 12725
/* 7474 */    MCD_OPC_Decode, 199, 5, 112, // Opcode: ILVOD_D
/* 7478 */    MCD_OPC_FilterValue, 21, 35, 1, // Skip to: 7773
/* 7482 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 7485 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 7497
/* 7489 */    MCD_OPC_CheckPredicate, 4, 112, 20, // Skip to: 12725
/* 7493 */    MCD_OPC_Decode, 177, 11, 113, // Opcode: VSHF_B
/* 7497 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 7509
/* 7501 */    MCD_OPC_CheckPredicate, 4, 100, 20, // Skip to: 12725
/* 7505 */    MCD_OPC_Decode, 179, 11, 114, // Opcode: VSHF_H
/* 7509 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 7521
/* 7513 */    MCD_OPC_CheckPredicate, 4, 88, 20, // Skip to: 12725
/* 7517 */    MCD_OPC_Decode, 180, 11, 115, // Opcode: VSHF_W
/* 7521 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 7533
/* 7525 */    MCD_OPC_CheckPredicate, 4, 76, 20, // Skip to: 12725
/* 7529 */    MCD_OPC_Decode, 178, 11, 116, // Opcode: VSHF_D
/* 7533 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 7545
/* 7537 */    MCD_OPC_CheckPredicate, 4, 64, 20, // Skip to: 12725
/* 7541 */    MCD_OPC_Decode, 250, 9, 109, // Opcode: SRAR_B
/* 7545 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 7557
/* 7549 */    MCD_OPC_CheckPredicate, 4, 52, 20, // Skip to: 12725
/* 7553 */    MCD_OPC_Decode, 252, 9, 110, // Opcode: SRAR_H
/* 7557 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 7569
/* 7561 */    MCD_OPC_CheckPredicate, 4, 40, 20, // Skip to: 12725
/* 7565 */    MCD_OPC_Decode, 253, 9, 111, // Opcode: SRAR_W
/* 7569 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 7581
/* 7573 */    MCD_OPC_CheckPredicate, 4, 28, 20, // Skip to: 12725
/* 7577 */    MCD_OPC_Decode, 251, 9, 112, // Opcode: SRAR_D
/* 7581 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 7593
/* 7585 */    MCD_OPC_CheckPredicate, 4, 16, 20, // Skip to: 12725
/* 7589 */    MCD_OPC_Decode, 142, 10, 109, // Opcode: SRLR_B
/* 7593 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 7605
/* 7597 */    MCD_OPC_CheckPredicate, 4, 4, 20, // Skip to: 12725
/* 7601 */    MCD_OPC_Decode, 144, 10, 110, // Opcode: SRLR_H
/* 7605 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 7617
/* 7609 */    MCD_OPC_CheckPredicate, 4, 248, 19, // Skip to: 12725
/* 7613 */    MCD_OPC_Decode, 145, 10, 111, // Opcode: SRLR_W
/* 7617 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 7629
/* 7621 */    MCD_OPC_CheckPredicate, 4, 236, 19, // Skip to: 12725
/* 7625 */    MCD_OPC_Decode, 143, 10, 112, // Opcode: SRLR_D
/* 7629 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 7641
/* 7633 */    MCD_OPC_CheckPredicate, 4, 224, 19, // Skip to: 12725
/* 7637 */    MCD_OPC_Decode, 179, 5, 117, // Opcode: HADD_S_H
/* 7641 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 7653
/* 7645 */    MCD_OPC_CheckPredicate, 4, 212, 19, // Skip to: 12725
/* 7649 */    MCD_OPC_Decode, 180, 5, 118, // Opcode: HADD_S_W
/* 7653 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 7665
/* 7657 */    MCD_OPC_CheckPredicate, 4, 200, 19, // Skip to: 12725
/* 7661 */    MCD_OPC_Decode, 178, 5, 119, // Opcode: HADD_S_D
/* 7665 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 7677
/* 7669 */    MCD_OPC_CheckPredicate, 4, 188, 19, // Skip to: 12725
/* 7673 */    MCD_OPC_Decode, 182, 5, 117, // Opcode: HADD_U_H
/* 7677 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 7689
/* 7681 */    MCD_OPC_CheckPredicate, 4, 176, 19, // Skip to: 12725
/* 7685 */    MCD_OPC_Decode, 183, 5, 118, // Opcode: HADD_U_W
/* 7689 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 7701
/* 7693 */    MCD_OPC_CheckPredicate, 4, 164, 19, // Skip to: 12725
/* 7697 */    MCD_OPC_Decode, 181, 5, 119, // Opcode: HADD_U_D
/* 7701 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 7713
/* 7705 */    MCD_OPC_CheckPredicate, 4, 152, 19, // Skip to: 12725
/* 7709 */    MCD_OPC_Decode, 185, 5, 117, // Opcode: HSUB_S_H
/* 7713 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 7725
/* 7717 */    MCD_OPC_CheckPredicate, 4, 140, 19, // Skip to: 12725
/* 7721 */    MCD_OPC_Decode, 186, 5, 118, // Opcode: HSUB_S_W
/* 7725 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 7737
/* 7729 */    MCD_OPC_CheckPredicate, 4, 128, 19, // Skip to: 12725
/* 7733 */    MCD_OPC_Decode, 184, 5, 119, // Opcode: HSUB_S_D
/* 7737 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 7749
/* 7741 */    MCD_OPC_CheckPredicate, 4, 116, 19, // Skip to: 12725
/* 7745 */    MCD_OPC_Decode, 188, 5, 117, // Opcode: HSUB_U_H
/* 7749 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 7761
/* 7753 */    MCD_OPC_CheckPredicate, 4, 104, 19, // Skip to: 12725
/* 7757 */    MCD_OPC_Decode, 189, 5, 118, // Opcode: HSUB_U_W
/* 7761 */    MCD_OPC_FilterValue, 31, 96, 19, // Skip to: 12725
/* 7765 */    MCD_OPC_CheckPredicate, 4, 92, 19, // Skip to: 12725
/* 7769 */    MCD_OPC_Decode, 187, 5, 119, // Opcode: HSUB_U_D
/* 7773 */    MCD_OPC_FilterValue, 25, 171, 1, // Skip to: 8204
/* 7777 */    MCD_OPC_ExtractField, 20, 6,  // Inst{25-20} ...
/* 7780 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 7793
/* 7784 */    MCD_OPC_CheckPredicate, 4, 73, 19, // Skip to: 12725
/* 7788 */    MCD_OPC_Decode, 194, 9, 131, 1, // Opcode: SLDI_B
/* 7793 */    MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 7812
/* 7797 */    MCD_OPC_CheckPredicate, 4, 60, 19, // Skip to: 12725
/* 7801 */    MCD_OPC_CheckField, 19, 1, 0, 54, 19, // Skip to: 12725
/* 7807 */    MCD_OPC_Decode, 196, 9, 132, 1, // Opcode: SLDI_H
/* 7812 */    MCD_OPC_FilterValue, 3, 54, 0, // Skip to: 7870
/* 7816 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 7819 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 7832
/* 7823 */    MCD_OPC_CheckPredicate, 4, 34, 19, // Skip to: 12725
/* 7827 */    MCD_OPC_Decode, 197, 9, 133, 1, // Opcode: SLDI_W
/* 7832 */    MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 7851
/* 7836 */    MCD_OPC_CheckPredicate, 4, 21, 19, // Skip to: 12725
/* 7840 */    MCD_OPC_CheckField, 17, 1, 0, 15, 19, // Skip to: 12725
/* 7846 */    MCD_OPC_Decode, 195, 9, 134, 1, // Opcode: SLDI_D
/* 7851 */    MCD_OPC_FilterValue, 3, 6, 19, // Skip to: 12725
/* 7855 */    MCD_OPC_CheckPredicate, 4, 2, 19, // Skip to: 12725
/* 7859 */    MCD_OPC_CheckField, 16, 2, 2, 252, 18, // Skip to: 12725
/* 7865 */    MCD_OPC_Decode, 217, 2, 135, 1, // Opcode: CTCMSA
/* 7870 */    MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 7883
/* 7874 */    MCD_OPC_CheckPredicate, 4, 239, 18, // Skip to: 12725
/* 7878 */    MCD_OPC_Decode, 233, 9, 136, 1, // Opcode: SPLATI_B
/* 7883 */    MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 7902
/* 7887 */    MCD_OPC_CheckPredicate, 4, 226, 18, // Skip to: 12725
/* 7891 */    MCD_OPC_CheckField, 19, 1, 0, 220, 18, // Skip to: 12725
/* 7897 */    MCD_OPC_Decode, 235, 9, 137, 1, // Opcode: SPLATI_H
/* 7902 */    MCD_OPC_FilterValue, 7, 54, 0, // Skip to: 7960
/* 7906 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 7909 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 7922
/* 7913 */    MCD_OPC_CheckPredicate, 4, 200, 18, // Skip to: 12725
/* 7917 */    MCD_OPC_Decode, 236, 9, 138, 1, // Opcode: SPLATI_W
/* 7922 */    MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 7941
/* 7926 */    MCD_OPC_CheckPredicate, 4, 187, 18, // Skip to: 12725
/* 7930 */    MCD_OPC_CheckField, 17, 1, 0, 181, 18, // Skip to: 12725
/* 7936 */    MCD_OPC_Decode, 234, 9, 139, 1, // Opcode: SPLATI_D
/* 7941 */    MCD_OPC_FilterValue, 3, 172, 18, // Skip to: 12725
/* 7945 */    MCD_OPC_CheckPredicate, 4, 168, 18, // Skip to: 12725
/* 7949 */    MCD_OPC_CheckField, 16, 2, 2, 162, 18, // Skip to: 12725
/* 7955 */    MCD_OPC_Decode, 157, 2, 140, 1, // Opcode: CFCMSA
/* 7960 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 7973
/* 7964 */    MCD_OPC_CheckPredicate, 4, 149, 18, // Skip to: 12725
/* 7968 */    MCD_OPC_Decode, 209, 2, 141, 1, // Opcode: COPY_S_B
/* 7973 */    MCD_OPC_FilterValue, 10, 15, 0, // Skip to: 7992
/* 7977 */    MCD_OPC_CheckPredicate, 4, 136, 18, // Skip to: 12725
/* 7981 */    MCD_OPC_CheckField, 19, 1, 0, 130, 18, // Skip to: 12725
/* 7987 */    MCD_OPC_Decode, 210, 2, 142, 1, // Opcode: COPY_S_H
/* 7992 */    MCD_OPC_FilterValue, 11, 35, 0, // Skip to: 8031
/* 7996 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 7999 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8012
/* 8003 */    MCD_OPC_CheckPredicate, 4, 110, 18, // Skip to: 12725
/* 8007 */    MCD_OPC_Decode, 211, 2, 143, 1, // Opcode: COPY_S_W
/* 8012 */    MCD_OPC_FilterValue, 3, 101, 18, // Skip to: 12725
/* 8016 */    MCD_OPC_CheckPredicate, 4, 97, 18, // Skip to: 12725
/* 8020 */    MCD_OPC_CheckField, 16, 2, 2, 91, 18, // Skip to: 12725
/* 8026 */    MCD_OPC_Decode, 147, 7, 144, 1, // Opcode: MOVE_V
/* 8031 */    MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 8044
/* 8035 */    MCD_OPC_CheckPredicate, 4, 78, 18, // Skip to: 12725
/* 8039 */    MCD_OPC_Decode, 212, 2, 141, 1, // Opcode: COPY_U_B
/* 8044 */    MCD_OPC_FilterValue, 14, 15, 0, // Skip to: 8063
/* 8048 */    MCD_OPC_CheckPredicate, 4, 65, 18, // Skip to: 12725
/* 8052 */    MCD_OPC_CheckField, 19, 1, 0, 59, 18, // Skip to: 12725
/* 8058 */    MCD_OPC_Decode, 213, 2, 142, 1, // Opcode: COPY_U_H
/* 8063 */    MCD_OPC_FilterValue, 15, 15, 0, // Skip to: 8082
/* 8067 */    MCD_OPC_CheckPredicate, 4, 46, 18, // Skip to: 12725
/* 8071 */    MCD_OPC_CheckField, 18, 2, 0, 40, 18, // Skip to: 12725
/* 8077 */    MCD_OPC_Decode, 214, 2, 143, 1, // Opcode: COPY_U_W
/* 8082 */    MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 8095
/* 8086 */    MCD_OPC_CheckPredicate, 4, 27, 18, // Skip to: 12725
/* 8090 */    MCD_OPC_Decode, 207, 5, 145, 1, // Opcode: INSERT_B
/* 8095 */    MCD_OPC_FilterValue, 18, 15, 0, // Skip to: 8114
/* 8099 */    MCD_OPC_CheckPredicate, 4, 14, 18, // Skip to: 12725
/* 8103 */    MCD_OPC_CheckField, 19, 1, 0, 8, 18, // Skip to: 12725
/* 8109 */    MCD_OPC_Decode, 210, 5, 146, 1, // Opcode: INSERT_H
/* 8114 */    MCD_OPC_FilterValue, 19, 15, 0, // Skip to: 8133
/* 8118 */    MCD_OPC_CheckPredicate, 4, 251, 17, // Skip to: 12725
/* 8122 */    MCD_OPC_CheckField, 18, 2, 0, 245, 17, // Skip to: 12725
/* 8128 */    MCD_OPC_Decode, 211, 5, 147, 1, // Opcode: INSERT_W
/* 8133 */    MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 8146
/* 8137 */    MCD_OPC_CheckPredicate, 4, 232, 17, // Skip to: 12725
/* 8141 */    MCD_OPC_Decode, 213, 5, 148, 1, // Opcode: INSVE_B
/* 8146 */    MCD_OPC_FilterValue, 22, 15, 0, // Skip to: 8165
/* 8150 */    MCD_OPC_CheckPredicate, 4, 219, 17, // Skip to: 12725
/* 8154 */    MCD_OPC_CheckField, 19, 1, 0, 213, 17, // Skip to: 12725
/* 8160 */    MCD_OPC_Decode, 215, 5, 149, 1, // Opcode: INSVE_H
/* 8165 */    MCD_OPC_FilterValue, 23, 204, 17, // Skip to: 12725
/* 8169 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 8172 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8185
/* 8176 */    MCD_OPC_CheckPredicate, 4, 193, 17, // Skip to: 12725
/* 8180 */    MCD_OPC_Decode, 216, 5, 150, 1, // Opcode: INSVE_W
/* 8185 */    MCD_OPC_FilterValue, 2, 184, 17, // Skip to: 12725
/* 8189 */    MCD_OPC_CheckPredicate, 4, 180, 17, // Skip to: 12725
/* 8193 */    MCD_OPC_CheckField, 17, 1, 0, 174, 17, // Skip to: 12725
/* 8199 */    MCD_OPC_Decode, 214, 5, 151, 1, // Opcode: INSVE_D
/* 8204 */    MCD_OPC_FilterValue, 26, 131, 1, // Skip to: 8595
/* 8208 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 8211 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 8223
/* 8215 */    MCD_OPC_CheckPredicate, 4, 154, 17, // Skip to: 12725
/* 8219 */    MCD_OPC_Decode, 157, 4, 111, // Opcode: FCAF_W
/* 8223 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 8235
/* 8227 */    MCD_OPC_CheckPredicate, 4, 142, 17, // Skip to: 12725
/* 8231 */    MCD_OPC_Decode, 156, 4, 112, // Opcode: FCAF_D
/* 8235 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 8247
/* 8239 */    MCD_OPC_CheckPredicate, 4, 130, 17, // Skip to: 12725
/* 8243 */    MCD_OPC_Decode, 184, 4, 111, // Opcode: FCUN_W
/* 8247 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 8259
/* 8251 */    MCD_OPC_CheckPredicate, 4, 118, 17, // Skip to: 12725
/* 8255 */    MCD_OPC_Decode, 183, 4, 112, // Opcode: FCUN_D
/* 8259 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 8271
/* 8263 */    MCD_OPC_CheckPredicate, 4, 106, 17, // Skip to: 12725
/* 8267 */    MCD_OPC_Decode, 159, 4, 111, // Opcode: FCEQ_W
/* 8271 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 8283
/* 8275 */    MCD_OPC_CheckPredicate, 4, 94, 17, // Skip to: 12725
/* 8279 */    MCD_OPC_Decode, 158, 4, 112, // Opcode: FCEQ_D
/* 8283 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 8295
/* 8287 */    MCD_OPC_CheckPredicate, 4, 82, 17, // Skip to: 12725
/* 8291 */    MCD_OPC_Decode, 176, 4, 111, // Opcode: FCUEQ_W
/* 8295 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 8307
/* 8299 */    MCD_OPC_CheckPredicate, 4, 70, 17, // Skip to: 12725
/* 8303 */    MCD_OPC_Decode, 175, 4, 112, // Opcode: FCUEQ_D
/* 8307 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 8319
/* 8311 */    MCD_OPC_CheckPredicate, 4, 58, 17, // Skip to: 12725
/* 8315 */    MCD_OPC_Decode, 165, 4, 111, // Opcode: FCLT_W
/* 8319 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 8331
/* 8323 */    MCD_OPC_CheckPredicate, 4, 46, 17, // Skip to: 12725
/* 8327 */    MCD_OPC_Decode, 164, 4, 112, // Opcode: FCLT_D
/* 8331 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 8343
/* 8335 */    MCD_OPC_CheckPredicate, 4, 34, 17, // Skip to: 12725
/* 8339 */    MCD_OPC_Decode, 180, 4, 111, // Opcode: FCULT_W
/* 8343 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 8355
/* 8347 */    MCD_OPC_CheckPredicate, 4, 22, 17, // Skip to: 12725
/* 8351 */    MCD_OPC_Decode, 179, 4, 112, // Opcode: FCULT_D
/* 8355 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 8367
/* 8359 */    MCD_OPC_CheckPredicate, 4, 10, 17, // Skip to: 12725
/* 8363 */    MCD_OPC_Decode, 163, 4, 111, // Opcode: FCLE_W
/* 8367 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 8379
/* 8371 */    MCD_OPC_CheckPredicate, 4, 254, 16, // Skip to: 12725
/* 8375 */    MCD_OPC_Decode, 162, 4, 112, // Opcode: FCLE_D
/* 8379 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 8391
/* 8383 */    MCD_OPC_CheckPredicate, 4, 242, 16, // Skip to: 12725
/* 8387 */    MCD_OPC_Decode, 178, 4, 111, // Opcode: FCULE_W
/* 8391 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 8403
/* 8395 */    MCD_OPC_CheckPredicate, 4, 230, 16, // Skip to: 12725
/* 8399 */    MCD_OPC_Decode, 177, 4, 112, // Opcode: FCULE_D
/* 8403 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 8415
/* 8407 */    MCD_OPC_CheckPredicate, 4, 218, 16, // Skip to: 12725
/* 8411 */    MCD_OPC_Decode, 132, 5, 111, // Opcode: FSAF_W
/* 8415 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 8427
/* 8419 */    MCD_OPC_CheckPredicate, 4, 206, 16, // Skip to: 12725
/* 8423 */    MCD_OPC_Decode, 131, 5, 112, // Opcode: FSAF_D
/* 8427 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 8439
/* 8431 */    MCD_OPC_CheckPredicate, 4, 194, 16, // Skip to: 12725
/* 8435 */    MCD_OPC_Decode, 166, 5, 111, // Opcode: FSUN_W
/* 8439 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 8451
/* 8443 */    MCD_OPC_CheckPredicate, 4, 182, 16, // Skip to: 12725
/* 8447 */    MCD_OPC_Decode, 165, 5, 112, // Opcode: FSUN_D
/* 8451 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 8463
/* 8455 */    MCD_OPC_CheckPredicate, 4, 170, 16, // Skip to: 12725
/* 8459 */    MCD_OPC_Decode, 134, 5, 111, // Opcode: FSEQ_W
/* 8463 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 8475
/* 8467 */    MCD_OPC_CheckPredicate, 4, 158, 16, // Skip to: 12725
/* 8471 */    MCD_OPC_Decode, 133, 5, 112, // Opcode: FSEQ_D
/* 8475 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 8487
/* 8479 */    MCD_OPC_CheckPredicate, 4, 146, 16, // Skip to: 12725
/* 8483 */    MCD_OPC_Decode, 158, 5, 111, // Opcode: FSUEQ_W
/* 8487 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 8499
/* 8491 */    MCD_OPC_CheckPredicate, 4, 134, 16, // Skip to: 12725
/* 8495 */    MCD_OPC_Decode, 157, 5, 112, // Opcode: FSUEQ_D
/* 8499 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 8511
/* 8503 */    MCD_OPC_CheckPredicate, 4, 122, 16, // Skip to: 12725
/* 8507 */    MCD_OPC_Decode, 138, 5, 111, // Opcode: FSLT_W
/* 8511 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 8523
/* 8515 */    MCD_OPC_CheckPredicate, 4, 110, 16, // Skip to: 12725
/* 8519 */    MCD_OPC_Decode, 137, 5, 112, // Opcode: FSLT_D
/* 8523 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 8535
/* 8527 */    MCD_OPC_CheckPredicate, 4, 98, 16, // Skip to: 12725
/* 8531 */    MCD_OPC_Decode, 162, 5, 111, // Opcode: FSULT_W
/* 8535 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 8547
/* 8539 */    MCD_OPC_CheckPredicate, 4, 86, 16, // Skip to: 12725
/* 8543 */    MCD_OPC_Decode, 161, 5, 112, // Opcode: FSULT_D
/* 8547 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 8559
/* 8551 */    MCD_OPC_CheckPredicate, 4, 74, 16, // Skip to: 12725
/* 8555 */    MCD_OPC_Decode, 136, 5, 111, // Opcode: FSLE_W
/* 8559 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 8571
/* 8563 */    MCD_OPC_CheckPredicate, 4, 62, 16, // Skip to: 12725
/* 8567 */    MCD_OPC_Decode, 135, 5, 112, // Opcode: FSLE_D
/* 8571 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 8583
/* 8575 */    MCD_OPC_CheckPredicate, 4, 50, 16, // Skip to: 12725
/* 8579 */    MCD_OPC_Decode, 160, 5, 111, // Opcode: FSULE_W
/* 8583 */    MCD_OPC_FilterValue, 31, 42, 16, // Skip to: 12725
/* 8587 */    MCD_OPC_CheckPredicate, 4, 38, 16, // Skip to: 12725
/* 8591 */    MCD_OPC_Decode, 159, 5, 112, // Opcode: FSULE_D
/* 8595 */    MCD_OPC_FilterValue, 27, 63, 1, // Skip to: 8918
/* 8599 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 8602 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 8614
/* 8606 */    MCD_OPC_CheckPredicate, 4, 19, 16, // Skip to: 12725
/* 8610 */    MCD_OPC_Decode, 155, 4, 111, // Opcode: FADD_W
/* 8614 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 8626
/* 8618 */    MCD_OPC_CheckPredicate, 4, 7, 16, // Skip to: 12725
/* 8622 */    MCD_OPC_Decode, 149, 4, 112, // Opcode: FADD_D
/* 8626 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 8638
/* 8630 */    MCD_OPC_CheckPredicate, 4, 251, 15, // Skip to: 12725
/* 8634 */    MCD_OPC_Decode, 156, 5, 111, // Opcode: FSUB_W
/* 8638 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 8650
/* 8642 */    MCD_OPC_CheckPredicate, 4, 239, 15, // Skip to: 12725
/* 8646 */    MCD_OPC_Decode, 150, 5, 112, // Opcode: FSUB_D
/* 8650 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 8662
/* 8654 */    MCD_OPC_CheckPredicate, 4, 227, 15, // Skip to: 12725
/* 8658 */    MCD_OPC_Decode, 247, 4, 111, // Opcode: FMUL_W
/* 8662 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 8674
/* 8666 */    MCD_OPC_CheckPredicate, 4, 215, 15, // Skip to: 12725
/* 8670 */    MCD_OPC_Decode, 241, 4, 112, // Opcode: FMUL_D
/* 8674 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 8686
/* 8678 */    MCD_OPC_CheckPredicate, 4, 203, 15, // Skip to: 12725
/* 8682 */    MCD_OPC_Decode, 191, 4, 111, // Opcode: FDIV_W
/* 8686 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 8698
/* 8690 */    MCD_OPC_CheckPredicate, 4, 191, 15, // Skip to: 12725
/* 8694 */    MCD_OPC_Decode, 185, 4, 112, // Opcode: FDIV_D
/* 8698 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 8710
/* 8702 */    MCD_OPC_CheckPredicate, 4, 179, 15, // Skip to: 12725
/* 8706 */    MCD_OPC_Decode, 225, 4, 115, // Opcode: FMADD_W
/* 8710 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 8722
/* 8714 */    MCD_OPC_CheckPredicate, 4, 167, 15, // Skip to: 12725
/* 8718 */    MCD_OPC_Decode, 224, 4, 116, // Opcode: FMADD_D
/* 8722 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 8734
/* 8726 */    MCD_OPC_CheckPredicate, 4, 155, 15, // Skip to: 12725
/* 8730 */    MCD_OPC_Decode, 240, 4, 115, // Opcode: FMSUB_W
/* 8734 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 8746
/* 8738 */    MCD_OPC_CheckPredicate, 4, 143, 15, // Skip to: 12725
/* 8742 */    MCD_OPC_Decode, 239, 4, 116, // Opcode: FMSUB_D
/* 8746 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 8758
/* 8750 */    MCD_OPC_CheckPredicate, 4, 131, 15, // Skip to: 12725
/* 8754 */    MCD_OPC_Decode, 196, 4, 111, // Opcode: FEXP2_W
/* 8758 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 8770
/* 8762 */    MCD_OPC_CheckPredicate, 4, 119, 15, // Skip to: 12725
/* 8766 */    MCD_OPC_Decode, 194, 4, 112, // Opcode: FEXP2_D
/* 8770 */    MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 8783
/* 8774 */    MCD_OPC_CheckPredicate, 4, 107, 15, // Skip to: 12725
/* 8778 */    MCD_OPC_Decode, 192, 4, 152, 1, // Opcode: FEXDO_H
/* 8783 */    MCD_OPC_FilterValue, 17, 9, 0, // Skip to: 8796
/* 8787 */    MCD_OPC_CheckPredicate, 4, 94, 15, // Skip to: 12725
/* 8791 */    MCD_OPC_Decode, 193, 4, 153, 1, // Opcode: FEXDO_W
/* 8796 */    MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 8809
/* 8800 */    MCD_OPC_CheckPredicate, 4, 81, 15, // Skip to: 12725
/* 8804 */    MCD_OPC_Decode, 171, 5, 152, 1, // Opcode: FTQ_H
/* 8809 */    MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 8822
/* 8813 */    MCD_OPC_CheckPredicate, 4, 68, 15, // Skip to: 12725
/* 8817 */    MCD_OPC_Decode, 172, 5, 153, 1, // Opcode: FTQ_W
/* 8822 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 8834
/* 8826 */    MCD_OPC_CheckPredicate, 4, 55, 15, // Skip to: 12725
/* 8830 */    MCD_OPC_Decode, 233, 4, 111, // Opcode: FMIN_W
/* 8834 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 8846
/* 8838 */    MCD_OPC_CheckPredicate, 4, 43, 15, // Skip to: 12725
/* 8842 */    MCD_OPC_Decode, 232, 4, 112, // Opcode: FMIN_D
/* 8846 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 8858
/* 8850 */    MCD_OPC_CheckPredicate, 4, 31, 15, // Skip to: 12725
/* 8854 */    MCD_OPC_Decode, 231, 4, 111, // Opcode: FMIN_A_W
/* 8858 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 8870
/* 8862 */    MCD_OPC_CheckPredicate, 4, 19, 15, // Skip to: 12725
/* 8866 */    MCD_OPC_Decode, 230, 4, 112, // Opcode: FMIN_A_D
/* 8870 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 8882
/* 8874 */    MCD_OPC_CheckPredicate, 4, 7, 15, // Skip to: 12725
/* 8878 */    MCD_OPC_Decode, 229, 4, 111, // Opcode: FMAX_W
/* 8882 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 8894
/* 8886 */    MCD_OPC_CheckPredicate, 4, 251, 14, // Skip to: 12725
/* 8890 */    MCD_OPC_Decode, 228, 4, 112, // Opcode: FMAX_D
/* 8894 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 8906
/* 8898 */    MCD_OPC_CheckPredicate, 4, 239, 14, // Skip to: 12725
/* 8902 */    MCD_OPC_Decode, 227, 4, 111, // Opcode: FMAX_A_W
/* 8906 */    MCD_OPC_FilterValue, 31, 231, 14, // Skip to: 12725
/* 8910 */    MCD_OPC_CheckPredicate, 4, 227, 14, // Skip to: 12725
/* 8914 */    MCD_OPC_Decode, 226, 4, 112, // Opcode: FMAX_A_D
/* 8918 */    MCD_OPC_FilterValue, 28, 35, 1, // Skip to: 9213
/* 8922 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 8925 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 8937
/* 8929 */    MCD_OPC_CheckPredicate, 4, 208, 14, // Skip to: 12725
/* 8933 */    MCD_OPC_Decode, 174, 4, 111, // Opcode: FCOR_W
/* 8937 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 8949
/* 8941 */    MCD_OPC_CheckPredicate, 4, 196, 14, // Skip to: 12725
/* 8945 */    MCD_OPC_Decode, 173, 4, 112, // Opcode: FCOR_D
/* 8949 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 8961
/* 8953 */    MCD_OPC_CheckPredicate, 4, 184, 14, // Skip to: 12725
/* 8957 */    MCD_OPC_Decode, 182, 4, 111, // Opcode: FCUNE_W
/* 8961 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 8973
/* 8965 */    MCD_OPC_CheckPredicate, 4, 172, 14, // Skip to: 12725
/* 8969 */    MCD_OPC_Decode, 181, 4, 112, // Opcode: FCUNE_D
/* 8973 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 8985
/* 8977 */    MCD_OPC_CheckPredicate, 4, 160, 14, // Skip to: 12725
/* 8981 */    MCD_OPC_Decode, 172, 4, 111, // Opcode: FCNE_W
/* 8985 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 8997
/* 8989 */    MCD_OPC_CheckPredicate, 4, 148, 14, // Skip to: 12725
/* 8993 */    MCD_OPC_Decode, 171, 4, 112, // Opcode: FCNE_D
/* 8997 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 9009
/* 9001 */    MCD_OPC_CheckPredicate, 4, 136, 14, // Skip to: 12725
/* 9005 */    MCD_OPC_Decode, 247, 7, 110, // Opcode: MUL_Q_H
/* 9009 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 9021
/* 9013 */    MCD_OPC_CheckPredicate, 4, 124, 14, // Skip to: 12725
/* 9017 */    MCD_OPC_Decode, 248, 7, 111, // Opcode: MUL_Q_W
/* 9021 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 9033
/* 9025 */    MCD_OPC_CheckPredicate, 4, 112, 14, // Skip to: 12725
/* 9029 */    MCD_OPC_Decode, 202, 6, 114, // Opcode: MADD_Q_H
/* 9033 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 9045
/* 9037 */    MCD_OPC_CheckPredicate, 4, 100, 14, // Skip to: 12725
/* 9041 */    MCD_OPC_Decode, 203, 6, 115, // Opcode: MADD_Q_W
/* 9045 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 9057
/* 9049 */    MCD_OPC_CheckPredicate, 4, 88, 14, // Skip to: 12725
/* 9053 */    MCD_OPC_Decode, 203, 7, 114, // Opcode: MSUB_Q_H
/* 9057 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 9069
/* 9061 */    MCD_OPC_CheckPredicate, 4, 76, 14, // Skip to: 12725
/* 9065 */    MCD_OPC_Decode, 204, 7, 115, // Opcode: MSUB_Q_W
/* 9069 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 9081
/* 9073 */    MCD_OPC_CheckPredicate, 4, 64, 14, // Skip to: 12725
/* 9077 */    MCD_OPC_Decode, 142, 5, 111, // Opcode: FSOR_W
/* 9081 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 9093
/* 9085 */    MCD_OPC_CheckPredicate, 4, 52, 14, // Skip to: 12725
/* 9089 */    MCD_OPC_Decode, 141, 5, 112, // Opcode: FSOR_D
/* 9093 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 9105
/* 9097 */    MCD_OPC_CheckPredicate, 4, 40, 14, // Skip to: 12725
/* 9101 */    MCD_OPC_Decode, 164, 5, 111, // Opcode: FSUNE_W
/* 9105 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 9117
/* 9109 */    MCD_OPC_CheckPredicate, 4, 28, 14, // Skip to: 12725
/* 9113 */    MCD_OPC_Decode, 163, 5, 112, // Opcode: FSUNE_D
/* 9117 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 9129
/* 9121 */    MCD_OPC_CheckPredicate, 4, 16, 14, // Skip to: 12725
/* 9125 */    MCD_OPC_Decode, 140, 5, 111, // Opcode: FSNE_W
/* 9129 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 9141
/* 9133 */    MCD_OPC_CheckPredicate, 4, 4, 14, // Skip to: 12725
/* 9137 */    MCD_OPC_Decode, 139, 5, 112, // Opcode: FSNE_D
/* 9141 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 9153
/* 9145 */    MCD_OPC_CheckPredicate, 4, 248, 13, // Skip to: 12725
/* 9149 */    MCD_OPC_Decode, 231, 7, 110, // Opcode: MULR_Q_H
/* 9153 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 9165
/* 9157 */    MCD_OPC_CheckPredicate, 4, 236, 13, // Skip to: 12725
/* 9161 */    MCD_OPC_Decode, 232, 7, 111, // Opcode: MULR_Q_W
/* 9165 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 9177
/* 9169 */    MCD_OPC_CheckPredicate, 4, 224, 13, // Skip to: 12725
/* 9173 */    MCD_OPC_Decode, 188, 6, 114, // Opcode: MADDR_Q_H
/* 9177 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 9189
/* 9181 */    MCD_OPC_CheckPredicate, 4, 212, 13, // Skip to: 12725
/* 9185 */    MCD_OPC_Decode, 189, 6, 115, // Opcode: MADDR_Q_W
/* 9189 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 9201
/* 9193 */    MCD_OPC_CheckPredicate, 4, 200, 13, // Skip to: 12725
/* 9197 */    MCD_OPC_Decode, 189, 7, 114, // Opcode: MSUBR_Q_H
/* 9201 */    MCD_OPC_FilterValue, 29, 192, 13, // Skip to: 12725
/* 9205 */    MCD_OPC_CheckPredicate, 4, 188, 13, // Skip to: 12725
/* 9209 */    MCD_OPC_Decode, 190, 7, 115, // Opcode: MSUBR_Q_W
/* 9213 */    MCD_OPC_FilterValue, 30, 199, 2, // Skip to: 9928
/* 9217 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 9220 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 9231
/* 9224 */    MCD_OPC_CheckPredicate, 4, 169, 13, // Skip to: 12725
/* 9228 */    MCD_OPC_Decode, 75, 109, // Opcode: AND_V
/* 9231 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 9243
/* 9235 */    MCD_OPC_CheckPredicate, 4, 158, 13, // Skip to: 12725
/* 9239 */    MCD_OPC_Decode, 163, 8, 109, // Opcode: OR_V
/* 9243 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 9255
/* 9247 */    MCD_OPC_CheckPredicate, 4, 146, 13, // Skip to: 12725
/* 9251 */    MCD_OPC_Decode, 153, 8, 109, // Opcode: NOR_V
/* 9255 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 9267
/* 9259 */    MCD_OPC_CheckPredicate, 4, 134, 13, // Skip to: 12725
/* 9263 */    MCD_OPC_Decode, 190, 11, 109, // Opcode: XOR_V
/* 9267 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 9279
/* 9271 */    MCD_OPC_CheckPredicate, 4, 122, 13, // Skip to: 12725
/* 9275 */    MCD_OPC_Decode, 200, 1, 113, // Opcode: BMNZ_V
/* 9279 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 9291
/* 9283 */    MCD_OPC_CheckPredicate, 4, 110, 13, // Skip to: 12725
/* 9287 */    MCD_OPC_Decode, 202, 1, 113, // Opcode: BMZ_V
/* 9291 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 9303
/* 9295 */    MCD_OPC_CheckPredicate, 4, 98, 13, // Skip to: 12725
/* 9299 */    MCD_OPC_Decode, 228, 1, 113, // Opcode: BSEL_V
/* 9303 */    MCD_OPC_FilterValue, 24, 198, 0, // Skip to: 9505
/* 9307 */    MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 9310 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 9323
/* 9314 */    MCD_OPC_CheckPredicate, 4, 79, 13, // Skip to: 12725
/* 9318 */    MCD_OPC_Decode, 210, 4, 154, 1, // Opcode: FILL_B
/* 9323 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 9336
/* 9327 */    MCD_OPC_CheckPredicate, 4, 66, 13, // Skip to: 12725
/* 9331 */    MCD_OPC_Decode, 213, 4, 155, 1, // Opcode: FILL_H
/* 9336 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 9349
/* 9340 */    MCD_OPC_CheckPredicate, 4, 53, 13, // Skip to: 12725
/* 9344 */    MCD_OPC_Decode, 214, 4, 156, 1, // Opcode: FILL_W
/* 9349 */    MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 9362
/* 9353 */    MCD_OPC_CheckPredicate, 4, 40, 13, // Skip to: 12725
/* 9357 */    MCD_OPC_Decode, 180, 8, 144, 1, // Opcode: PCNT_B
/* 9362 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 9375
/* 9366 */    MCD_OPC_CheckPredicate, 4, 27, 13, // Skip to: 12725
/* 9370 */    MCD_OPC_Decode, 182, 8, 157, 1, // Opcode: PCNT_H
/* 9375 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 9388
/* 9379 */    MCD_OPC_CheckPredicate, 4, 14, 13, // Skip to: 12725
/* 9383 */    MCD_OPC_Decode, 183, 8, 158, 1, // Opcode: PCNT_W
/* 9388 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 9401
/* 9392 */    MCD_OPC_CheckPredicate, 4, 1, 13, // Skip to: 12725
/* 9396 */    MCD_OPC_Decode, 181, 8, 159, 1, // Opcode: PCNT_D
/* 9401 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 9414
/* 9405 */    MCD_OPC_CheckPredicate, 4, 244, 12, // Skip to: 12725
/* 9409 */    MCD_OPC_Decode, 130, 8, 144, 1, // Opcode: NLOC_B
/* 9414 */    MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 9427
/* 9418 */    MCD_OPC_CheckPredicate, 4, 231, 12, // Skip to: 12725
/* 9422 */    MCD_OPC_Decode, 132, 8, 157, 1, // Opcode: NLOC_H
/* 9427 */    MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 9440
/* 9431 */    MCD_OPC_CheckPredicate, 4, 218, 12, // Skip to: 12725
/* 9435 */    MCD_OPC_Decode, 133, 8, 158, 1, // Opcode: NLOC_W
/* 9440 */    MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 9453
/* 9444 */    MCD_OPC_CheckPredicate, 4, 205, 12, // Skip to: 12725
/* 9448 */    MCD_OPC_Decode, 131, 8, 159, 1, // Opcode: NLOC_D
/* 9453 */    MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 9466
/* 9457 */    MCD_OPC_CheckPredicate, 4, 192, 12, // Skip to: 12725
/* 9461 */    MCD_OPC_Decode, 134, 8, 144, 1, // Opcode: NLZC_B
/* 9466 */    MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 9479
/* 9470 */    MCD_OPC_CheckPredicate, 4, 179, 12, // Skip to: 12725
/* 9474 */    MCD_OPC_Decode, 136, 8, 157, 1, // Opcode: NLZC_H
/* 9479 */    MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 9492
/* 9483 */    MCD_OPC_CheckPredicate, 4, 166, 12, // Skip to: 12725
/* 9487 */    MCD_OPC_Decode, 137, 8, 158, 1, // Opcode: NLZC_W
/* 9492 */    MCD_OPC_FilterValue, 15, 157, 12, // Skip to: 12725
/* 9496 */    MCD_OPC_CheckPredicate, 4, 153, 12, // Skip to: 12725
/* 9500 */    MCD_OPC_Decode, 135, 8, 159, 1, // Opcode: NLZC_D
/* 9505 */    MCD_OPC_FilterValue, 25, 144, 12, // Skip to: 12725
/* 9509 */    MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 9512 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 9525
/* 9516 */    MCD_OPC_CheckPredicate, 4, 133, 12, // Skip to: 12725
/* 9520 */    MCD_OPC_Decode, 161, 4, 158, 1, // Opcode: FCLASS_W
/* 9525 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 9538
/* 9529 */    MCD_OPC_CheckPredicate, 4, 120, 12, // Skip to: 12725
/* 9533 */    MCD_OPC_Decode, 160, 4, 159, 1, // Opcode: FCLASS_D
/* 9538 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 9551
/* 9542 */    MCD_OPC_CheckPredicate, 4, 107, 12, // Skip to: 12725
/* 9546 */    MCD_OPC_Decode, 174, 5, 158, 1, // Opcode: FTRUNC_S_W
/* 9551 */    MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 9564
/* 9555 */    MCD_OPC_CheckPredicate, 4, 94, 12, // Skip to: 12725
/* 9559 */    MCD_OPC_Decode, 173, 5, 159, 1, // Opcode: FTRUNC_S_D
/* 9564 */    MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 9577
/* 9568 */    MCD_OPC_CheckPredicate, 4, 81, 12, // Skip to: 12725
/* 9572 */    MCD_OPC_Decode, 176, 5, 158, 1, // Opcode: FTRUNC_U_W
/* 9577 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 9590
/* 9581 */    MCD_OPC_CheckPredicate, 4, 68, 12, // Skip to: 12725
/* 9585 */    MCD_OPC_Decode, 175, 5, 159, 1, // Opcode: FTRUNC_U_D
/* 9590 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 9603
/* 9594 */    MCD_OPC_CheckPredicate, 4, 55, 12, // Skip to: 12725
/* 9598 */    MCD_OPC_Decode, 149, 5, 158, 1, // Opcode: FSQRT_W
/* 9603 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 9616
/* 9607 */    MCD_OPC_CheckPredicate, 4, 42, 12, // Skip to: 12725
/* 9611 */    MCD_OPC_Decode, 143, 5, 159, 1, // Opcode: FSQRT_D
/* 9616 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 9629
/* 9620 */    MCD_OPC_CheckPredicate, 4, 29, 12, // Skip to: 12725
/* 9624 */    MCD_OPC_Decode, 130, 5, 158, 1, // Opcode: FRSQRT_W
/* 9629 */    MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 9642
/* 9633 */    MCD_OPC_CheckPredicate, 4, 16, 12, // Skip to: 12725
/* 9637 */    MCD_OPC_Decode, 129, 5, 159, 1, // Opcode: FRSQRT_D
/* 9642 */    MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 9655
/* 9646 */    MCD_OPC_CheckPredicate, 4, 3, 12, // Skip to: 12725
/* 9650 */    MCD_OPC_Decode, 254, 4, 158, 1, // Opcode: FRCP_W
/* 9655 */    MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 9668
/* 9659 */    MCD_OPC_CheckPredicate, 4, 246, 11, // Skip to: 12725
/* 9663 */    MCD_OPC_Decode, 253, 4, 159, 1, // Opcode: FRCP_D
/* 9668 */    MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 9681
/* 9672 */    MCD_OPC_CheckPredicate, 4, 233, 11, // Skip to: 12725
/* 9676 */    MCD_OPC_Decode, 128, 5, 158, 1, // Opcode: FRINT_W
/* 9681 */    MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 9694
/* 9685 */    MCD_OPC_CheckPredicate, 4, 220, 11, // Skip to: 12725
/* 9689 */    MCD_OPC_Decode, 255, 4, 159, 1, // Opcode: FRINT_D
/* 9694 */    MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 9707
/* 9698 */    MCD_OPC_CheckPredicate, 4, 207, 11, // Skip to: 12725
/* 9702 */    MCD_OPC_Decode, 216, 4, 158, 1, // Opcode: FLOG2_W
/* 9707 */    MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 9720
/* 9711 */    MCD_OPC_CheckPredicate, 4, 194, 11, // Skip to: 12725
/* 9715 */    MCD_OPC_Decode, 215, 4, 159, 1, // Opcode: FLOG2_D
/* 9720 */    MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 9733
/* 9724 */    MCD_OPC_CheckPredicate, 4, 181, 11, // Skip to: 12725
/* 9728 */    MCD_OPC_Decode, 199, 4, 160, 1, // Opcode: FEXUPL_W
/* 9733 */    MCD_OPC_FilterValue, 17, 9, 0, // Skip to: 9746
/* 9737 */    MCD_OPC_CheckPredicate, 4, 168, 11, // Skip to: 12725
/* 9741 */    MCD_OPC_Decode, 198, 4, 161, 1, // Opcode: FEXUPL_D
/* 9746 */    MCD_OPC_FilterValue, 18, 9, 0, // Skip to: 9759
/* 9750 */    MCD_OPC_CheckPredicate, 4, 155, 11, // Skip to: 12725
/* 9754 */    MCD_OPC_Decode, 201, 4, 160, 1, // Opcode: FEXUPR_W
/* 9759 */    MCD_OPC_FilterValue, 19, 9, 0, // Skip to: 9772
/* 9763 */    MCD_OPC_CheckPredicate, 4, 142, 11, // Skip to: 12725
/* 9767 */    MCD_OPC_Decode, 200, 4, 161, 1, // Opcode: FEXUPR_D
/* 9772 */    MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 9785
/* 9776 */    MCD_OPC_CheckPredicate, 4, 129, 11, // Skip to: 12725
/* 9780 */    MCD_OPC_Decode, 207, 4, 160, 1, // Opcode: FFQL_W
/* 9785 */    MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 9798
/* 9789 */    MCD_OPC_CheckPredicate, 4, 116, 11, // Skip to: 12725
/* 9793 */    MCD_OPC_Decode, 206, 4, 161, 1, // Opcode: FFQL_D
/* 9798 */    MCD_OPC_FilterValue, 22, 9, 0, // Skip to: 9811
/* 9802 */    MCD_OPC_CheckPredicate, 4, 103, 11, // Skip to: 12725
/* 9806 */    MCD_OPC_Decode, 209, 4, 160, 1, // Opcode: FFQR_W
/* 9811 */    MCD_OPC_FilterValue, 23, 9, 0, // Skip to: 9824
/* 9815 */    MCD_OPC_CheckPredicate, 4, 90, 11, // Skip to: 12725
/* 9819 */    MCD_OPC_Decode, 208, 4, 161, 1, // Opcode: FFQR_D
/* 9824 */    MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 9837
/* 9828 */    MCD_OPC_CheckPredicate, 4, 77, 11, // Skip to: 12725
/* 9832 */    MCD_OPC_Decode, 168, 5, 158, 1, // Opcode: FTINT_S_W
/* 9837 */    MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 9850
/* 9841 */    MCD_OPC_CheckPredicate, 4, 64, 11, // Skip to: 12725
/* 9845 */    MCD_OPC_Decode, 167, 5, 159, 1, // Opcode: FTINT_S_D
/* 9850 */    MCD_OPC_FilterValue, 26, 9, 0, // Skip to: 9863
/* 9854 */    MCD_OPC_CheckPredicate, 4, 51, 11, // Skip to: 12725
/* 9858 */    MCD_OPC_Decode, 170, 5, 158, 1, // Opcode: FTINT_U_W
/* 9863 */    MCD_OPC_FilterValue, 27, 9, 0, // Skip to: 9876
/* 9867 */    MCD_OPC_CheckPredicate, 4, 38, 11, // Skip to: 12725
/* 9871 */    MCD_OPC_Decode, 169, 5, 159, 1, // Opcode: FTINT_U_D
/* 9876 */    MCD_OPC_FilterValue, 28, 9, 0, // Skip to: 9889
/* 9880 */    MCD_OPC_CheckPredicate, 4, 25, 11, // Skip to: 12725
/* 9884 */    MCD_OPC_Decode, 203, 4, 158, 1, // Opcode: FFINT_S_W
/* 9889 */    MCD_OPC_FilterValue, 29, 9, 0, // Skip to: 9902
/* 9893 */    MCD_OPC_CheckPredicate, 4, 12, 11, // Skip to: 12725
/* 9897 */    MCD_OPC_Decode, 202, 4, 159, 1, // Opcode: FFINT_S_D
/* 9902 */    MCD_OPC_FilterValue, 30, 9, 0, // Skip to: 9915
/* 9906 */    MCD_OPC_CheckPredicate, 4, 255, 10, // Skip to: 12725
/* 9910 */    MCD_OPC_Decode, 205, 4, 158, 1, // Opcode: FFINT_U_W
/* 9915 */    MCD_OPC_FilterValue, 31, 246, 10, // Skip to: 12725
/* 9919 */    MCD_OPC_CheckPredicate, 4, 242, 10, // Skip to: 12725
/* 9923 */    MCD_OPC_Decode, 204, 4, 159, 1, // Opcode: FFINT_U_D
/* 9928 */    MCD_OPC_FilterValue, 32, 9, 0, // Skip to: 9941
/* 9932 */    MCD_OPC_CheckPredicate, 4, 229, 10, // Skip to: 12725
/* 9936 */    MCD_OPC_Decode, 128, 6, 162, 1, // Opcode: LD_B
/* 9941 */    MCD_OPC_FilterValue, 33, 9, 0, // Skip to: 9954
/* 9945 */    MCD_OPC_CheckPredicate, 4, 216, 10, // Skip to: 12725
/* 9949 */    MCD_OPC_Decode, 130, 6, 162, 1, // Opcode: LD_H
/* 9954 */    MCD_OPC_FilterValue, 34, 9, 0, // Skip to: 9967
/* 9958 */    MCD_OPC_CheckPredicate, 4, 203, 10, // Skip to: 12725
/* 9962 */    MCD_OPC_Decode, 131, 6, 162, 1, // Opcode: LD_W
/* 9967 */    MCD_OPC_FilterValue, 35, 9, 0, // Skip to: 9980
/* 9971 */    MCD_OPC_CheckPredicate, 4, 190, 10, // Skip to: 12725
/* 9975 */    MCD_OPC_Decode, 129, 6, 162, 1, // Opcode: LD_D
/* 9980 */    MCD_OPC_FilterValue, 36, 9, 0, // Skip to: 9993
/* 9984 */    MCD_OPC_CheckPredicate, 4, 177, 10, // Skip to: 12725
/* 9988 */    MCD_OPC_Decode, 157, 10, 162, 1, // Opcode: ST_B
/* 9993 */    MCD_OPC_FilterValue, 37, 9, 0, // Skip to: 10006
/* 9997 */    MCD_OPC_CheckPredicate, 4, 164, 10, // Skip to: 12725
/* 10001 */   MCD_OPC_Decode, 159, 10, 162, 1, // Opcode: ST_H
/* 10006 */   MCD_OPC_FilterValue, 38, 9, 0, // Skip to: 10019
/* 10010 */   MCD_OPC_CheckPredicate, 4, 151, 10, // Skip to: 12725
/* 10014 */   MCD_OPC_Decode, 160, 10, 162, 1, // Opcode: ST_W
/* 10019 */   MCD_OPC_FilterValue, 39, 142, 10, // Skip to: 12725
/* 10023 */   MCD_OPC_CheckPredicate, 4, 138, 10, // Skip to: 12725
/* 10027 */   MCD_OPC_Decode, 158, 10, 162, 1, // Opcode: ST_D
/* 10032 */   MCD_OPC_FilterValue, 31, 113, 9, // Skip to: 12453
/* 10036 */   MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10039 */   MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 10052
/* 10043 */   MCD_OPC_CheckPredicate, 3, 118, 10, // Skip to: 12725
/* 10047 */   MCD_OPC_Decode, 254, 3, 163, 1, // Opcode: EXT
/* 10052 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 10065
/* 10056 */   MCD_OPC_CheckPredicate, 3, 105, 10, // Skip to: 12725
/* 10060 */   MCD_OPC_Decode, 206, 5, 164, 1, // Opcode: INS
/* 10065 */   MCD_OPC_FilterValue, 10, 42, 0, // Skip to: 10111
/* 10069 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 10072 */   MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 10085
/* 10076 */   MCD_OPC_CheckPredicate, 5, 85, 10, // Skip to: 12725
/* 10080 */   MCD_OPC_Decode, 167, 6, 165, 1, // Opcode: LWX
/* 10085 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 10098
/* 10089 */   MCD_OPC_CheckPredicate, 5, 72, 10, // Skip to: 12725
/* 10093 */   MCD_OPC_Decode, 137, 6, 165, 1, // Opcode: LHX
/* 10098 */   MCD_OPC_FilterValue, 6, 63, 10, // Skip to: 12725
/* 10102 */   MCD_OPC_CheckPredicate, 5, 59, 10, // Skip to: 12725
/* 10106 */   MCD_OPC_Decode, 238, 5, 165, 1, // Opcode: LBUX
/* 10111 */   MCD_OPC_FilterValue, 12, 15, 0, // Skip to: 10130
/* 10115 */   MCD_OPC_CheckPredicate, 5, 46, 10, // Skip to: 12725
/* 10119 */   MCD_OPC_CheckField, 6, 10, 0, 40, 10, // Skip to: 12725
/* 10125 */   MCD_OPC_Decode, 212, 5, 166, 1, // Opcode: INSV
/* 10130 */   MCD_OPC_FilterValue, 16, 51, 1, // Skip to: 10441
/* 10134 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 10137 */   MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 10149
/* 10141 */   MCD_OPC_CheckPredicate, 5, 20, 10, // Skip to: 12725
/* 10145 */   MCD_OPC_Decode, 46, 167, 1, // Opcode: ADDU_QB
/* 10149 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 10162
/* 10153 */   MCD_OPC_CheckPredicate, 5, 8, 10, // Skip to: 12725
/* 10157 */   MCD_OPC_Decode, 188, 10, 167, 1, // Opcode: SUBU_QB
/* 10162 */   MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 10174
/* 10166 */   MCD_OPC_CheckPredicate, 5, 251, 9, // Skip to: 12725
/* 10170 */   MCD_OPC_Decode, 48, 167, 1, // Opcode: ADDU_S_QB
/* 10174 */   MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 10187
/* 10178 */   MCD_OPC_CheckPredicate, 5, 239, 9, // Skip to: 12725
/* 10182 */   MCD_OPC_Decode, 190, 10, 167, 1, // Opcode: SUBU_S_QB
/* 10187 */   MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 10200
/* 10191 */   MCD_OPC_CheckPredicate, 5, 226, 9, // Skip to: 12725
/* 10195 */   MCD_OPC_Decode, 225, 7, 167, 1, // Opcode: MULEU_S_PH_QBL
/* 10200 */   MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 10213
/* 10204 */   MCD_OPC_CheckPredicate, 5, 213, 9, // Skip to: 12725
/* 10208 */   MCD_OPC_Decode, 226, 7, 167, 1, // Opcode: MULEU_S_PH_QBR
/* 10213 */   MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 10225
/* 10217 */   MCD_OPC_CheckPredicate, 14, 200, 9, // Skip to: 12725
/* 10221 */   MCD_OPC_Decode, 45, 167, 1, // Opcode: ADDU_PH
/* 10225 */   MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 10238
/* 10229 */   MCD_OPC_CheckPredicate, 14, 188, 9, // Skip to: 12725
/* 10233 */   MCD_OPC_Decode, 187, 10, 167, 1, // Opcode: SUBU_PH
/* 10238 */   MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 10250
/* 10242 */   MCD_OPC_CheckPredicate, 5, 175, 9, // Skip to: 12725
/* 10246 */   MCD_OPC_Decode, 27, 167, 1, // Opcode: ADDQ_PH
/* 10250 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 10263
/* 10254 */   MCD_OPC_CheckPredicate, 5, 163, 9, // Skip to: 12725
/* 10258 */   MCD_OPC_Decode, 166, 10, 167, 1, // Opcode: SUBQ_PH
/* 10263 */   MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 10275
/* 10267 */   MCD_OPC_CheckPredicate, 14, 150, 9, // Skip to: 12725
/* 10271 */   MCD_OPC_Decode, 47, 167, 1, // Opcode: ADDU_S_PH
/* 10275 */   MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 10288
/* 10279 */   MCD_OPC_CheckPredicate, 14, 138, 9, // Skip to: 12725
/* 10283 */   MCD_OPC_Decode, 189, 10, 167, 1, // Opcode: SUBU_S_PH
/* 10288 */   MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 10300
/* 10292 */   MCD_OPC_CheckPredicate, 5, 125, 9, // Skip to: 12725
/* 10296 */   MCD_OPC_Decode, 28, 167, 1, // Opcode: ADDQ_S_PH
/* 10300 */   MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 10313
/* 10304 */   MCD_OPC_CheckPredicate, 5, 113, 9, // Skip to: 12725
/* 10308 */   MCD_OPC_Decode, 167, 10, 167, 1, // Opcode: SUBQ_S_PH
/* 10313 */   MCD_OPC_FilterValue, 16, 7, 0, // Skip to: 10324
/* 10317 */   MCD_OPC_CheckPredicate, 5, 100, 9, // Skip to: 12725
/* 10321 */   MCD_OPC_Decode, 30, 13, // Opcode: ADDSC
/* 10324 */   MCD_OPC_FilterValue, 17, 7, 0, // Skip to: 10335
/* 10328 */   MCD_OPC_CheckPredicate, 5, 89, 9, // Skip to: 12725
/* 10332 */   MCD_OPC_Decode, 57, 13, // Opcode: ADDWC
/* 10335 */   MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 10347
/* 10339 */   MCD_OPC_CheckPredicate, 5, 78, 9, // Skip to: 12725
/* 10343 */   MCD_OPC_Decode, 138, 7, 13, // Opcode: MODSUB
/* 10347 */   MCD_OPC_FilterValue, 20, 15, 0, // Skip to: 10366
/* 10351 */   MCD_OPC_CheckPredicate, 5, 66, 9, // Skip to: 12725
/* 10355 */   MCD_OPC_CheckField, 16, 5, 0, 60, 9, // Skip to: 12725
/* 10361 */   MCD_OPC_Decode, 236, 8, 168, 1, // Opcode: RADDU_W_QB
/* 10366 */   MCD_OPC_FilterValue, 22, 7, 0, // Skip to: 10377
/* 10370 */   MCD_OPC_CheckPredicate, 5, 47, 9, // Skip to: 12725
/* 10374 */   MCD_OPC_Decode, 29, 13, // Opcode: ADDQ_S_W
/* 10377 */   MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 10389
/* 10381 */   MCD_OPC_CheckPredicate, 5, 36, 9, // Skip to: 12725
/* 10385 */   MCD_OPC_Decode, 168, 10, 13, // Opcode: SUBQ_S_W
/* 10389 */   MCD_OPC_FilterValue, 28, 9, 0, // Skip to: 10402
/* 10393 */   MCD_OPC_CheckPredicate, 5, 24, 9, // Skip to: 12725
/* 10397 */   MCD_OPC_Decode, 223, 7, 169, 1, // Opcode: MULEQ_S_W_PHL
/* 10402 */   MCD_OPC_FilterValue, 29, 9, 0, // Skip to: 10415
/* 10406 */   MCD_OPC_CheckPredicate, 5, 11, 9, // Skip to: 12725
/* 10410 */   MCD_OPC_Decode, 224, 7, 169, 1, // Opcode: MULEQ_S_W_PHR
/* 10415 */   MCD_OPC_FilterValue, 30, 9, 0, // Skip to: 10428
/* 10419 */   MCD_OPC_CheckPredicate, 14, 254, 8, // Skip to: 12725
/* 10423 */   MCD_OPC_Decode, 229, 7, 167, 1, // Opcode: MULQ_S_PH
/* 10428 */   MCD_OPC_FilterValue, 31, 245, 8, // Skip to: 12725
/* 10432 */   MCD_OPC_CheckPredicate, 5, 241, 8, // Skip to: 12725
/* 10436 */   MCD_OPC_Decode, 227, 7, 167, 1, // Opcode: MULQ_RS_PH
/* 10441 */   MCD_OPC_FilterValue, 17, 69, 1, // Skip to: 10770
/* 10445 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 10448 */   MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 10467
/* 10452 */   MCD_OPC_CheckPredicate, 5, 221, 8, // Skip to: 12725
/* 10456 */   MCD_OPC_CheckField, 11, 5, 0, 215, 8, // Skip to: 12725
/* 10462 */   MCD_OPC_Decode, 200, 2, 170, 1, // Opcode: CMPU_EQ_QB
/* 10467 */   MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 10486
/* 10471 */   MCD_OPC_CheckPredicate, 5, 202, 8, // Skip to: 12725
/* 10475 */   MCD_OPC_CheckField, 11, 5, 0, 196, 8, // Skip to: 12725
/* 10481 */   MCD_OPC_Decode, 202, 2, 170, 1, // Opcode: CMPU_LT_QB
/* 10486 */   MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 10505
/* 10490 */   MCD_OPC_CheckPredicate, 5, 183, 8, // Skip to: 12725
/* 10494 */   MCD_OPC_CheckField, 11, 5, 0, 177, 8, // Skip to: 12725
/* 10500 */   MCD_OPC_Decode, 201, 2, 170, 1, // Opcode: CMPU_LE_QB
/* 10505 */   MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 10518
/* 10509 */   MCD_OPC_CheckPredicate, 5, 164, 8, // Skip to: 12725
/* 10513 */   MCD_OPC_Decode, 185, 8, 167, 1, // Opcode: PICK_QB
/* 10518 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 10531
/* 10522 */   MCD_OPC_CheckPredicate, 5, 151, 8, // Skip to: 12725
/* 10526 */   MCD_OPC_Decode, 197, 2, 169, 1, // Opcode: CMPGU_EQ_QB
/* 10531 */   MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 10544
/* 10535 */   MCD_OPC_CheckPredicate, 5, 138, 8, // Skip to: 12725
/* 10539 */   MCD_OPC_Decode, 199, 2, 169, 1, // Opcode: CMPGU_LT_QB
/* 10544 */   MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 10557
/* 10548 */   MCD_OPC_CheckPredicate, 5, 125, 8, // Skip to: 12725
/* 10552 */   MCD_OPC_Decode, 198, 2, 169, 1, // Opcode: CMPGU_LE_QB
/* 10557 */   MCD_OPC_FilterValue, 8, 15, 0, // Skip to: 10576
/* 10561 */   MCD_OPC_CheckPredicate, 5, 112, 8, // Skip to: 12725
/* 10565 */   MCD_OPC_CheckField, 11, 5, 0, 106, 8, // Skip to: 12725
/* 10571 */   MCD_OPC_Decode, 203, 2, 170, 1, // Opcode: CMP_EQ_PH
/* 10576 */   MCD_OPC_FilterValue, 9, 15, 0, // Skip to: 10595
/* 10580 */   MCD_OPC_CheckPredicate, 5, 93, 8, // Skip to: 12725
/* 10584 */   MCD_OPC_CheckField, 11, 5, 0, 87, 8, // Skip to: 12725
/* 10590 */   MCD_OPC_Decode, 205, 2, 170, 1, // Opcode: CMP_LT_PH
/* 10595 */   MCD_OPC_FilterValue, 10, 15, 0, // Skip to: 10614
/* 10599 */   MCD_OPC_CheckPredicate, 5, 74, 8, // Skip to: 12725
/* 10603 */   MCD_OPC_CheckField, 11, 5, 0, 68, 8, // Skip to: 12725
/* 10609 */   MCD_OPC_Decode, 204, 2, 170, 1, // Opcode: CMP_LE_PH
/* 10614 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 10627
/* 10618 */   MCD_OPC_CheckPredicate, 5, 55, 8, // Skip to: 12725
/* 10622 */   MCD_OPC_Decode, 184, 8, 167, 1, // Opcode: PICK_PH
/* 10627 */   MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 10640
/* 10631 */   MCD_OPC_CheckPredicate, 5, 42, 8, // Skip to: 12725
/* 10635 */   MCD_OPC_Decode, 198, 8, 167, 1, // Opcode: PRECRQ_QB_PH
/* 10640 */   MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 10653
/* 10644 */   MCD_OPC_CheckPredicate, 14, 29, 8, // Skip to: 12725
/* 10648 */   MCD_OPC_Decode, 200, 8, 167, 1, // Opcode: PRECR_QB_PH
/* 10653 */   MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 10666
/* 10657 */   MCD_OPC_CheckPredicate, 5, 16, 8, // Skip to: 12725
/* 10661 */   MCD_OPC_Decode, 171, 8, 167, 1, // Opcode: PACKRL_PH
/* 10666 */   MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 10679
/* 10670 */   MCD_OPC_CheckPredicate, 5, 3, 8, // Skip to: 12725
/* 10674 */   MCD_OPC_Decode, 196, 8, 167, 1, // Opcode: PRECRQU_S_QB_PH
/* 10679 */   MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 10692
/* 10683 */   MCD_OPC_CheckPredicate, 5, 246, 7, // Skip to: 12725
/* 10687 */   MCD_OPC_Decode, 197, 8, 171, 1, // Opcode: PRECRQ_PH_W
/* 10692 */   MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 10705
/* 10696 */   MCD_OPC_CheckPredicate, 5, 233, 7, // Skip to: 12725
/* 10700 */   MCD_OPC_Decode, 199, 8, 171, 1, // Opcode: PRECRQ_RS_PH_W
/* 10705 */   MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 10718
/* 10709 */   MCD_OPC_CheckPredicate, 14, 220, 7, // Skip to: 12725
/* 10713 */   MCD_OPC_Decode, 194, 2, 169, 1, // Opcode: CMPGDU_EQ_QB
/* 10718 */   MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 10731
/* 10722 */   MCD_OPC_CheckPredicate, 14, 207, 7, // Skip to: 12725
/* 10726 */   MCD_OPC_Decode, 196, 2, 169, 1, // Opcode: CMPGDU_LT_QB
/* 10731 */   MCD_OPC_FilterValue, 26, 9, 0, // Skip to: 10744
/* 10735 */   MCD_OPC_CheckPredicate, 14, 194, 7, // Skip to: 12725
/* 10739 */   MCD_OPC_Decode, 195, 2, 169, 1, // Opcode: CMPGDU_LE_QB
/* 10744 */   MCD_OPC_FilterValue, 30, 9, 0, // Skip to: 10757
/* 10748 */   MCD_OPC_CheckPredicate, 14, 181, 7, // Skip to: 12725
/* 10752 */   MCD_OPC_Decode, 201, 8, 172, 1, // Opcode: PRECR_SRA_PH_W
/* 10757 */   MCD_OPC_FilterValue, 31, 172, 7, // Skip to: 12725
/* 10761 */   MCD_OPC_CheckPredicate, 14, 168, 7, // Skip to: 12725
/* 10765 */   MCD_OPC_Decode, 202, 8, 172, 1, // Opcode: PRECR_SRA_R_PH_W
/* 10770 */   MCD_OPC_FilterValue, 18, 74, 1, // Skip to: 11104
/* 10774 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 10777 */   MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 10795
/* 10781 */   MCD_OPC_CheckPredicate, 14, 148, 7, // Skip to: 12725
/* 10785 */   MCD_OPC_CheckField, 21, 5, 0, 142, 7, // Skip to: 12725
/* 10791 */   MCD_OPC_Decode, 20, 173, 1, // Opcode: ABSQ_S_QB
/* 10795 */   MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 10808
/* 10799 */   MCD_OPC_CheckPredicate, 5, 130, 7, // Skip to: 12725
/* 10803 */   MCD_OPC_Decode, 243, 8, 174, 1, // Opcode: REPL_QB
/* 10808 */   MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 10827
/* 10812 */   MCD_OPC_CheckPredicate, 5, 117, 7, // Skip to: 12725
/* 10816 */   MCD_OPC_CheckField, 21, 5, 0, 111, 7, // Skip to: 12725
/* 10822 */   MCD_OPC_Decode, 241, 8, 175, 1, // Opcode: REPLV_QB
/* 10827 */   MCD_OPC_FilterValue, 4, 15, 0, // Skip to: 10846
/* 10831 */   MCD_OPC_CheckPredicate, 5, 98, 7, // Skip to: 12725
/* 10835 */   MCD_OPC_CheckField, 21, 5, 0, 92, 7, // Skip to: 12725
/* 10841 */   MCD_OPC_Decode, 186, 8, 173, 1, // Opcode: PRECEQU_PH_QBL
/* 10846 */   MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 10865
/* 10850 */   MCD_OPC_CheckPredicate, 5, 79, 7, // Skip to: 12725
/* 10854 */   MCD_OPC_CheckField, 21, 5, 0, 73, 7, // Skip to: 12725
/* 10860 */   MCD_OPC_Decode, 188, 8, 173, 1, // Opcode: PRECEQU_PH_QBR
/* 10865 */   MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 10884
/* 10869 */   MCD_OPC_CheckPredicate, 5, 60, 7, // Skip to: 12725
/* 10873 */   MCD_OPC_CheckField, 21, 5, 0, 54, 7, // Skip to: 12725
/* 10879 */   MCD_OPC_Decode, 187, 8, 173, 1, // Opcode: PRECEQU_PH_QBLA
/* 10884 */   MCD_OPC_FilterValue, 7, 15, 0, // Skip to: 10903
/* 10888 */   MCD_OPC_CheckPredicate, 5, 41, 7, // Skip to: 12725
/* 10892 */   MCD_OPC_CheckField, 21, 5, 0, 35, 7, // Skip to: 12725
/* 10898 */   MCD_OPC_Decode, 189, 8, 173, 1, // Opcode: PRECEQU_PH_QBRA
/* 10903 */   MCD_OPC_FilterValue, 9, 14, 0, // Skip to: 10921
/* 10907 */   MCD_OPC_CheckPredicate, 5, 22, 7, // Skip to: 12725
/* 10911 */   MCD_OPC_CheckField, 21, 5, 0, 16, 7, // Skip to: 12725
/* 10917 */   MCD_OPC_Decode, 19, 173, 1, // Opcode: ABSQ_S_PH
/* 10921 */   MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 10934
/* 10925 */   MCD_OPC_CheckPredicate, 5, 4, 7, // Skip to: 12725
/* 10929 */   MCD_OPC_Decode, 242, 8, 174, 1, // Opcode: REPL_PH
/* 10934 */   MCD_OPC_FilterValue, 11, 15, 0, // Skip to: 10953
/* 10938 */   MCD_OPC_CheckPredicate, 5, 247, 6, // Skip to: 12725
/* 10942 */   MCD_OPC_CheckField, 21, 5, 0, 241, 6, // Skip to: 12725
/* 10948 */   MCD_OPC_Decode, 240, 8, 175, 1, // Opcode: REPLV_PH
/* 10953 */   MCD_OPC_FilterValue, 12, 15, 0, // Skip to: 10972
/* 10957 */   MCD_OPC_CheckPredicate, 5, 228, 6, // Skip to: 12725
/* 10961 */   MCD_OPC_CheckField, 21, 5, 0, 222, 6, // Skip to: 12725
/* 10967 */   MCD_OPC_Decode, 190, 8, 176, 1, // Opcode: PRECEQ_W_PHL
/* 10972 */   MCD_OPC_FilterValue, 13, 15, 0, // Skip to: 10991
/* 10976 */   MCD_OPC_CheckPredicate, 5, 209, 6, // Skip to: 12725
/* 10980 */   MCD_OPC_CheckField, 21, 5, 0, 203, 6, // Skip to: 12725
/* 10986 */   MCD_OPC_Decode, 191, 8, 176, 1, // Opcode: PRECEQ_W_PHR
/* 10991 */   MCD_OPC_FilterValue, 17, 14, 0, // Skip to: 11009
/* 10995 */   MCD_OPC_CheckPredicate, 5, 190, 6, // Skip to: 12725
/* 10999 */   MCD_OPC_CheckField, 21, 5, 0, 184, 6, // Skip to: 12725
/* 11005 */   MCD_OPC_Decode, 21, 177, 1, // Opcode: ABSQ_S_W
/* 11009 */   MCD_OPC_FilterValue, 27, 15, 0, // Skip to: 11028
/* 11013 */   MCD_OPC_CheckPredicate, 5, 172, 6, // Skip to: 12725
/* 11017 */   MCD_OPC_CheckField, 21, 5, 0, 166, 6, // Skip to: 12725
/* 11023 */   MCD_OPC_Decode, 190, 1, 177, 1, // Opcode: BITREV
/* 11028 */   MCD_OPC_FilterValue, 28, 15, 0, // Skip to: 11047
/* 11032 */   MCD_OPC_CheckPredicate, 5, 153, 6, // Skip to: 12725
/* 11036 */   MCD_OPC_CheckField, 21, 5, 0, 147, 6, // Skip to: 12725
/* 11042 */   MCD_OPC_Decode, 192, 8, 173, 1, // Opcode: PRECEU_PH_QBL
/* 11047 */   MCD_OPC_FilterValue, 29, 15, 0, // Skip to: 11066
/* 11051 */   MCD_OPC_CheckPredicate, 5, 134, 6, // Skip to: 12725
/* 11055 */   MCD_OPC_CheckField, 21, 5, 0, 128, 6, // Skip to: 12725
/* 11061 */   MCD_OPC_Decode, 194, 8, 173, 1, // Opcode: PRECEU_PH_QBR
/* 11066 */   MCD_OPC_FilterValue, 30, 15, 0, // Skip to: 11085
/* 11070 */   MCD_OPC_CheckPredicate, 5, 115, 6, // Skip to: 12725
/* 11074 */   MCD_OPC_CheckField, 21, 5, 0, 109, 6, // Skip to: 12725
/* 11080 */   MCD_OPC_Decode, 193, 8, 173, 1, // Opcode: PRECEU_PH_QBLA
/* 11085 */   MCD_OPC_FilterValue, 31, 100, 6, // Skip to: 12725
/* 11089 */   MCD_OPC_CheckPredicate, 5, 96, 6, // Skip to: 12725
/* 11093 */   MCD_OPC_CheckField, 21, 5, 0, 90, 6, // Skip to: 12725
/* 11099 */   MCD_OPC_Decode, 195, 8, 173, 1, // Opcode: PRECEU_PH_QBRA
/* 11104 */   MCD_OPC_FilterValue, 19, 31, 1, // Skip to: 11395
/* 11108 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11111 */   MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 11124
/* 11115 */   MCD_OPC_CheckPredicate, 5, 70, 6, // Skip to: 12725
/* 11119 */   MCD_OPC_Decode, 176, 9, 178, 1, // Opcode: SHLL_QB
/* 11124 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 11137
/* 11128 */   MCD_OPC_CheckPredicate, 5, 57, 6, // Skip to: 12725
/* 11132 */   MCD_OPC_Decode, 192, 9, 178, 1, // Opcode: SHRL_QB
/* 11137 */   MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 11150
/* 11141 */   MCD_OPC_CheckPredicate, 5, 44, 6, // Skip to: 12725
/* 11145 */   MCD_OPC_Decode, 172, 9, 179, 1, // Opcode: SHLLV_QB
/* 11150 */   MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 11163
/* 11154 */   MCD_OPC_CheckPredicate, 5, 31, 6, // Skip to: 12725
/* 11158 */   MCD_OPC_Decode, 190, 9, 179, 1, // Opcode: SHRLV_QB
/* 11163 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 11176
/* 11167 */   MCD_OPC_CheckPredicate, 14, 18, 6, // Skip to: 12725
/* 11171 */   MCD_OPC_Decode, 185, 9, 178, 1, // Opcode: SHRA_QB
/* 11176 */   MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 11189
/* 11180 */   MCD_OPC_CheckPredicate, 14, 5, 6, // Skip to: 12725
/* 11184 */   MCD_OPC_Decode, 187, 9, 178, 1, // Opcode: SHRA_R_QB
/* 11189 */   MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 11202
/* 11193 */   MCD_OPC_CheckPredicate, 14, 248, 5, // Skip to: 12725
/* 11197 */   MCD_OPC_Decode, 180, 9, 179, 1, // Opcode: SHRAV_QB
/* 11202 */   MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 11215
/* 11206 */   MCD_OPC_CheckPredicate, 14, 235, 5, // Skip to: 12725
/* 11210 */   MCD_OPC_Decode, 182, 9, 179, 1, // Opcode: SHRAV_R_QB
/* 11215 */   MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 11228
/* 11219 */   MCD_OPC_CheckPredicate, 5, 222, 5, // Skip to: 12725
/* 11223 */   MCD_OPC_Decode, 175, 9, 178, 1, // Opcode: SHLL_PH
/* 11228 */   MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 11241
/* 11232 */   MCD_OPC_CheckPredicate, 5, 209, 5, // Skip to: 12725
/* 11236 */   MCD_OPC_Decode, 184, 9, 178, 1, // Opcode: SHRA_PH
/* 11241 */   MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 11254
/* 11245 */   MCD_OPC_CheckPredicate, 5, 196, 5, // Skip to: 12725
/* 11249 */   MCD_OPC_Decode, 171, 9, 179, 1, // Opcode: SHLLV_PH
/* 11254 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 11267
/* 11258 */   MCD_OPC_CheckPredicate, 5, 183, 5, // Skip to: 12725
/* 11262 */   MCD_OPC_Decode, 179, 9, 179, 1, // Opcode: SHRAV_PH
/* 11267 */   MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 11280
/* 11271 */   MCD_OPC_CheckPredicate, 5, 170, 5, // Skip to: 12725
/* 11275 */   MCD_OPC_Decode, 177, 9, 178, 1, // Opcode: SHLL_S_PH
/* 11280 */   MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 11293
/* 11284 */   MCD_OPC_CheckPredicate, 5, 157, 5, // Skip to: 12725
/* 11288 */   MCD_OPC_Decode, 186, 9, 178, 1, // Opcode: SHRA_R_PH
/* 11293 */   MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 11306
/* 11297 */   MCD_OPC_CheckPredicate, 5, 144, 5, // Skip to: 12725
/* 11301 */   MCD_OPC_Decode, 173, 9, 179, 1, // Opcode: SHLLV_S_PH
/* 11306 */   MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 11319
/* 11310 */   MCD_OPC_CheckPredicate, 5, 131, 5, // Skip to: 12725
/* 11314 */   MCD_OPC_Decode, 181, 9, 179, 1, // Opcode: SHRAV_R_PH
/* 11319 */   MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 11332
/* 11323 */   MCD_OPC_CheckPredicate, 5, 118, 5, // Skip to: 12725
/* 11327 */   MCD_OPC_Decode, 178, 9, 180, 1, // Opcode: SHLL_S_W
/* 11332 */   MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 11345
/* 11336 */   MCD_OPC_CheckPredicate, 5, 105, 5, // Skip to: 12725
/* 11340 */   MCD_OPC_Decode, 188, 9, 180, 1, // Opcode: SHRA_R_W
/* 11345 */   MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 11357
/* 11349 */   MCD_OPC_CheckPredicate, 5, 92, 5, // Skip to: 12725
/* 11353 */   MCD_OPC_Decode, 174, 9, 14, // Opcode: SHLLV_S_W
/* 11357 */   MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 11369
/* 11361 */   MCD_OPC_CheckPredicate, 5, 80, 5, // Skip to: 12725
/* 11365 */   MCD_OPC_Decode, 183, 9, 14, // Opcode: SHRAV_R_W
/* 11369 */   MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 11382
/* 11373 */   MCD_OPC_CheckPredicate, 14, 68, 5, // Skip to: 12725
/* 11377 */   MCD_OPC_Decode, 191, 9, 178, 1, // Opcode: SHRL_PH
/* 11382 */   MCD_OPC_FilterValue, 27, 59, 5, // Skip to: 12725
/* 11386 */   MCD_OPC_CheckPredicate, 14, 55, 5, // Skip to: 12725
/* 11390 */   MCD_OPC_Decode, 189, 9, 179, 1, // Opcode: SHRLV_PH
/* 11395 */   MCD_OPC_FilterValue, 24, 199, 0, // Skip to: 11598
/* 11399 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11402 */   MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 11414
/* 11406 */   MCD_OPC_CheckPredicate, 14, 35, 5, // Skip to: 12725
/* 11410 */   MCD_OPC_Decode, 43, 167, 1, // Opcode: ADDUH_QB
/* 11414 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 11427
/* 11418 */   MCD_OPC_CheckPredicate, 14, 23, 5, // Skip to: 12725
/* 11422 */   MCD_OPC_Decode, 185, 10, 167, 1, // Opcode: SUBUH_QB
/* 11427 */   MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 11439
/* 11431 */   MCD_OPC_CheckPredicate, 14, 10, 5, // Skip to: 12725
/* 11435 */   MCD_OPC_Decode, 44, 167, 1, // Opcode: ADDUH_R_QB
/* 11439 */   MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 11452
/* 11443 */   MCD_OPC_CheckPredicate, 14, 254, 4, // Skip to: 12725
/* 11447 */   MCD_OPC_Decode, 186, 10, 167, 1, // Opcode: SUBUH_R_QB
/* 11452 */   MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 11464
/* 11456 */   MCD_OPC_CheckPredicate, 14, 241, 4, // Skip to: 12725
/* 11460 */   MCD_OPC_Decode, 23, 167, 1, // Opcode: ADDQH_PH
/* 11464 */   MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 11477
/* 11468 */   MCD_OPC_CheckPredicate, 14, 229, 4, // Skip to: 12725
/* 11472 */   MCD_OPC_Decode, 162, 10, 167, 1, // Opcode: SUBQH_PH
/* 11477 */   MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 11489
/* 11481 */   MCD_OPC_CheckPredicate, 14, 216, 4, // Skip to: 12725
/* 11485 */   MCD_OPC_Decode, 24, 167, 1, // Opcode: ADDQH_R_PH
/* 11489 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 11502
/* 11493 */   MCD_OPC_CheckPredicate, 14, 204, 4, // Skip to: 12725
/* 11497 */   MCD_OPC_Decode, 163, 10, 167, 1, // Opcode: SUBQH_R_PH
/* 11502 */   MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 11515
/* 11506 */   MCD_OPC_CheckPredicate, 14, 191, 4, // Skip to: 12725
/* 11510 */   MCD_OPC_Decode, 246, 7, 167, 1, // Opcode: MUL_PH
/* 11515 */   MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 11528
/* 11519 */   MCD_OPC_CheckPredicate, 14, 178, 4, // Skip to: 12725
/* 11523 */   MCD_OPC_Decode, 249, 7, 167, 1, // Opcode: MUL_S_PH
/* 11528 */   MCD_OPC_FilterValue, 16, 7, 0, // Skip to: 11539
/* 11532 */   MCD_OPC_CheckPredicate, 14, 165, 4, // Skip to: 12725
/* 11536 */   MCD_OPC_Decode, 26, 13, // Opcode: ADDQH_W
/* 11539 */   MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 11551
/* 11543 */   MCD_OPC_CheckPredicate, 14, 154, 4, // Skip to: 12725
/* 11547 */   MCD_OPC_Decode, 165, 10, 13, // Opcode: SUBQH_W
/* 11551 */   MCD_OPC_FilterValue, 18, 7, 0, // Skip to: 11562
/* 11555 */   MCD_OPC_CheckPredicate, 14, 142, 4, // Skip to: 12725
/* 11559 */   MCD_OPC_Decode, 25, 13, // Opcode: ADDQH_R_W
/* 11562 */   MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 11574
/* 11566 */   MCD_OPC_CheckPredicate, 14, 131, 4, // Skip to: 12725
/* 11570 */   MCD_OPC_Decode, 164, 10, 13, // Opcode: SUBQH_R_W
/* 11574 */   MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 11586
/* 11578 */   MCD_OPC_CheckPredicate, 14, 119, 4, // Skip to: 12725
/* 11582 */   MCD_OPC_Decode, 230, 7, 13, // Opcode: MULQ_S_W
/* 11586 */   MCD_OPC_FilterValue, 23, 111, 4, // Skip to: 12725
/* 11590 */   MCD_OPC_CheckPredicate, 14, 107, 4, // Skip to: 12725
/* 11594 */   MCD_OPC_Decode, 228, 7, 13, // Opcode: MULQ_RS_W
/* 11598 */   MCD_OPC_FilterValue, 32, 60, 0, // Skip to: 11662
/* 11602 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11605 */   MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 11624
/* 11609 */   MCD_OPC_CheckPredicate, 15, 88, 4, // Skip to: 12725
/* 11613 */   MCD_OPC_CheckField, 21, 5, 0, 82, 4, // Skip to: 12725
/* 11619 */   MCD_OPC_Decode, 184, 11, 177, 1, // Opcode: WSBH
/* 11624 */   MCD_OPC_FilterValue, 16, 15, 0, // Skip to: 11643
/* 11628 */   MCD_OPC_CheckPredicate, 16, 69, 4, // Skip to: 12725
/* 11632 */   MCD_OPC_CheckField, 21, 5, 0, 63, 4, // Skip to: 12725
/* 11638 */   MCD_OPC_Decode, 158, 9, 177, 1, // Opcode: SEB
/* 11643 */   MCD_OPC_FilterValue, 24, 54, 4, // Skip to: 12725
/* 11647 */   MCD_OPC_CheckPredicate, 16, 50, 4, // Skip to: 12725
/* 11651 */   MCD_OPC_CheckField, 21, 5, 0, 44, 4, // Skip to: 12725
/* 11657 */   MCD_OPC_Decode, 161, 9, 177, 1, // Opcode: SEH
/* 11662 */   MCD_OPC_FilterValue, 48, 143, 1, // Skip to: 12065
/* 11666 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11669 */   MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 11687
/* 11673 */   MCD_OPC_CheckPredicate, 14, 24, 4, // Skip to: 12725
/* 11677 */   MCD_OPC_CheckField, 13, 3, 0, 18, 4, // Skip to: 12725
/* 11683 */   MCD_OPC_Decode, 215, 3, 88, // Opcode: DPA_W_PH
/* 11687 */   MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 11705
/* 11691 */   MCD_OPC_CheckPredicate, 14, 6, 4, // Skip to: 12725
/* 11695 */   MCD_OPC_CheckField, 13, 3, 0, 0, 4, // Skip to: 12725
/* 11701 */   MCD_OPC_Decode, 229, 3, 88, // Opcode: DPS_W_PH
/* 11705 */   MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 11723
/* 11709 */   MCD_OPC_CheckPredicate, 14, 244, 3, // Skip to: 12725
/* 11713 */   MCD_OPC_CheckField, 13, 3, 0, 238, 3, // Skip to: 12725
/* 11719 */   MCD_OPC_Decode, 234, 7, 88, // Opcode: MULSA_W_PH
/* 11723 */   MCD_OPC_FilterValue, 3, 14, 0, // Skip to: 11741
/* 11727 */   MCD_OPC_CheckPredicate, 5, 226, 3, // Skip to: 12725
/* 11731 */   MCD_OPC_CheckField, 13, 3, 0, 220, 3, // Skip to: 12725
/* 11737 */   MCD_OPC_Decode, 212, 3, 88, // Opcode: DPAU_H_QBL
/* 11741 */   MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 11759
/* 11745 */   MCD_OPC_CheckPredicate, 5, 208, 3, // Skip to: 12725
/* 11749 */   MCD_OPC_CheckField, 13, 3, 0, 202, 3, // Skip to: 12725
/* 11755 */   MCD_OPC_Decode, 211, 3, 88, // Opcode: DPAQ_S_W_PH
/* 11759 */   MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 11777
/* 11763 */   MCD_OPC_CheckPredicate, 5, 190, 3, // Skip to: 12725
/* 11767 */   MCD_OPC_CheckField, 13, 3, 0, 184, 3, // Skip to: 12725
/* 11773 */   MCD_OPC_Decode, 219, 3, 88, // Opcode: DPSQ_S_W_PH
/* 11777 */   MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 11795
/* 11781 */   MCD_OPC_CheckPredicate, 5, 172, 3, // Skip to: 12725
/* 11785 */   MCD_OPC_CheckField, 13, 3, 0, 166, 3, // Skip to: 12725
/* 11791 */   MCD_OPC_Decode, 233, 7, 88, // Opcode: MULSAQ_S_W_PH
/* 11795 */   MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 11813
/* 11799 */   MCD_OPC_CheckPredicate, 5, 154, 3, // Skip to: 12725
/* 11803 */   MCD_OPC_CheckField, 13, 3, 0, 148, 3, // Skip to: 12725
/* 11809 */   MCD_OPC_Decode, 213, 3, 88, // Opcode: DPAU_H_QBR
/* 11813 */   MCD_OPC_FilterValue, 8, 14, 0, // Skip to: 11831
/* 11817 */   MCD_OPC_CheckPredicate, 14, 136, 3, // Skip to: 12725
/* 11821 */   MCD_OPC_CheckField, 13, 3, 0, 130, 3, // Skip to: 12725
/* 11827 */   MCD_OPC_Decode, 214, 3, 88, // Opcode: DPAX_W_PH
/* 11831 */   MCD_OPC_FilterValue, 9, 14, 0, // Skip to: 11849
/* 11835 */   MCD_OPC_CheckPredicate, 14, 118, 3, // Skip to: 12725
/* 11839 */   MCD_OPC_CheckField, 13, 3, 0, 112, 3, // Skip to: 12725
/* 11845 */   MCD_OPC_Decode, 228, 3, 88, // Opcode: DPSX_W_PH
/* 11849 */   MCD_OPC_FilterValue, 11, 14, 0, // Skip to: 11867
/* 11853 */   MCD_OPC_CheckPredicate, 5, 100, 3, // Skip to: 12725
/* 11857 */   MCD_OPC_CheckField, 13, 3, 0, 94, 3, // Skip to: 12725
/* 11863 */   MCD_OPC_Decode, 226, 3, 88, // Opcode: DPSU_H_QBL
/* 11867 */   MCD_OPC_FilterValue, 12, 14, 0, // Skip to: 11885
/* 11871 */   MCD_OPC_CheckPredicate, 5, 82, 3, // Skip to: 12725
/* 11875 */   MCD_OPC_CheckField, 13, 3, 0, 76, 3, // Skip to: 12725
/* 11881 */   MCD_OPC_Decode, 210, 3, 88, // Opcode: DPAQ_SA_L_W
/* 11885 */   MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 11903
/* 11889 */   MCD_OPC_CheckPredicate, 5, 64, 3, // Skip to: 12725
/* 11893 */   MCD_OPC_CheckField, 13, 3, 0, 58, 3, // Skip to: 12725
/* 11899 */   MCD_OPC_Decode, 218, 3, 88, // Opcode: DPSQ_SA_L_W
/* 11903 */   MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 11921
/* 11907 */   MCD_OPC_CheckPredicate, 5, 46, 3, // Skip to: 12725
/* 11911 */   MCD_OPC_CheckField, 13, 3, 0, 40, 3, // Skip to: 12725
/* 11917 */   MCD_OPC_Decode, 227, 3, 88, // Opcode: DPSU_H_QBR
/* 11921 */   MCD_OPC_FilterValue, 16, 14, 0, // Skip to: 11939
/* 11925 */   MCD_OPC_CheckPredicate, 5, 28, 3, // Skip to: 12725
/* 11929 */   MCD_OPC_CheckField, 13, 3, 0, 22, 3, // Skip to: 12725
/* 11935 */   MCD_OPC_Decode, 206, 6, 88, // Opcode: MAQ_SA_W_PHL
/* 11939 */   MCD_OPC_FilterValue, 18, 14, 0, // Skip to: 11957
/* 11943 */   MCD_OPC_CheckPredicate, 5, 10, 3, // Skip to: 12725
/* 11947 */   MCD_OPC_CheckField, 13, 3, 0, 4, 3, // Skip to: 12725
/* 11953 */   MCD_OPC_Decode, 207, 6, 88, // Opcode: MAQ_SA_W_PHR
/* 11957 */   MCD_OPC_FilterValue, 20, 14, 0, // Skip to: 11975
/* 11961 */   MCD_OPC_CheckPredicate, 5, 248, 2, // Skip to: 12725
/* 11965 */   MCD_OPC_CheckField, 13, 3, 0, 242, 2, // Skip to: 12725
/* 11971 */   MCD_OPC_Decode, 208, 6, 88, // Opcode: MAQ_S_W_PHL
/* 11975 */   MCD_OPC_FilterValue, 22, 14, 0, // Skip to: 11993
/* 11979 */   MCD_OPC_CheckPredicate, 5, 230, 2, // Skip to: 12725
/* 11983 */   MCD_OPC_CheckField, 13, 3, 0, 224, 2, // Skip to: 12725
/* 11989 */   MCD_OPC_Decode, 209, 6, 88, // Opcode: MAQ_S_W_PHR
/* 11993 */   MCD_OPC_FilterValue, 24, 14, 0, // Skip to: 12011
/* 11997 */   MCD_OPC_CheckPredicate, 14, 212, 2, // Skip to: 12725
/* 12001 */   MCD_OPC_CheckField, 13, 3, 0, 206, 2, // Skip to: 12725
/* 12007 */   MCD_OPC_Decode, 209, 3, 88, // Opcode: DPAQX_S_W_PH
/* 12011 */   MCD_OPC_FilterValue, 25, 14, 0, // Skip to: 12029
/* 12015 */   MCD_OPC_CheckPredicate, 14, 194, 2, // Skip to: 12725
/* 12019 */   MCD_OPC_CheckField, 13, 3, 0, 188, 2, // Skip to: 12725
/* 12025 */   MCD_OPC_Decode, 217, 3, 88, // Opcode: DPSQX_S_W_PH
/* 12029 */   MCD_OPC_FilterValue, 26, 14, 0, // Skip to: 12047
/* 12033 */   MCD_OPC_CheckPredicate, 14, 176, 2, // Skip to: 12725
/* 12037 */   MCD_OPC_CheckField, 13, 3, 0, 170, 2, // Skip to: 12725
/* 12043 */   MCD_OPC_Decode, 208, 3, 88, // Opcode: DPAQX_SA_W_PH
/* 12047 */   MCD_OPC_FilterValue, 27, 162, 2, // Skip to: 12725
/* 12051 */   MCD_OPC_CheckPredicate, 14, 158, 2, // Skip to: 12725
/* 12055 */   MCD_OPC_CheckField, 13, 3, 0, 152, 2, // Skip to: 12725
/* 12061 */   MCD_OPC_Decode, 216, 3, 88, // Opcode: DPSQX_SA_W_PH
/* 12065 */   MCD_OPC_FilterValue, 49, 41, 0, // Skip to: 12110
/* 12069 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 12072 */   MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 12084
/* 12076 */   MCD_OPC_CheckPredicate, 14, 133, 2, // Skip to: 12725
/* 12080 */   MCD_OPC_Decode, 82, 181, 1, // Opcode: APPEND
/* 12084 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 12097
/* 12088 */   MCD_OPC_CheckPredicate, 14, 121, 2, // Skip to: 12725
/* 12092 */   MCD_OPC_Decode, 203, 8, 181, 1, // Opcode: PREPEND
/* 12097 */   MCD_OPC_FilterValue, 16, 112, 2, // Skip to: 12725
/* 12101 */   MCD_OPC_CheckPredicate, 14, 108, 2, // Skip to: 12725
/* 12105 */   MCD_OPC_Decode, 149, 1, 181, 1, // Opcode: BALIGN
/* 12110 */   MCD_OPC_FilterValue, 56, 58, 1, // Skip to: 12428
/* 12114 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 12117 */   MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 12136
/* 12121 */   MCD_OPC_CheckPredicate, 5, 88, 2, // Skip to: 12725
/* 12125 */   MCD_OPC_CheckField, 13, 3, 0, 82, 2, // Skip to: 12725
/* 12131 */   MCD_OPC_Decode, 138, 4, 182, 1, // Opcode: EXTR_W
/* 12136 */   MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 12155
/* 12140 */   MCD_OPC_CheckPredicate, 5, 69, 2, // Skip to: 12725
/* 12144 */   MCD_OPC_CheckField, 13, 3, 0, 63, 2, // Skip to: 12725
/* 12150 */   MCD_OPC_Decode, 134, 4, 183, 1, // Opcode: EXTRV_W
/* 12155 */   MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 12174
/* 12159 */   MCD_OPC_CheckPredicate, 5, 50, 2, // Skip to: 12725
/* 12163 */   MCD_OPC_CheckField, 13, 3, 0, 44, 2, // Skip to: 12725
/* 12169 */   MCD_OPC_Decode, 255, 3, 182, 1, // Opcode: EXTP
/* 12174 */   MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 12193
/* 12178 */   MCD_OPC_CheckPredicate, 5, 31, 2, // Skip to: 12725
/* 12182 */   MCD_OPC_CheckField, 13, 3, 0, 25, 2, // Skip to: 12725
/* 12188 */   MCD_OPC_Decode, 130, 4, 183, 1, // Opcode: EXTPV
/* 12193 */   MCD_OPC_FilterValue, 4, 15, 0, // Skip to: 12212
/* 12197 */   MCD_OPC_CheckPredicate, 5, 12, 2, // Skip to: 12725
/* 12201 */   MCD_OPC_CheckField, 13, 3, 0, 6, 2, // Skip to: 12725
/* 12207 */   MCD_OPC_Decode, 136, 4, 182, 1, // Opcode: EXTR_R_W
/* 12212 */   MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 12231
/* 12216 */   MCD_OPC_CheckPredicate, 5, 249, 1, // Skip to: 12725
/* 12220 */   MCD_OPC_CheckField, 13, 3, 0, 243, 1, // Skip to: 12725
/* 12226 */   MCD_OPC_Decode, 132, 4, 183, 1, // Opcode: EXTRV_R_W
/* 12231 */   MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 12250
/* 12235 */   MCD_OPC_CheckPredicate, 5, 230, 1, // Skip to: 12725
/* 12239 */   MCD_OPC_CheckField, 13, 3, 0, 224, 1, // Skip to: 12725
/* 12245 */   MCD_OPC_Decode, 135, 4, 182, 1, // Opcode: EXTR_RS_W
/* 12250 */   MCD_OPC_FilterValue, 7, 15, 0, // Skip to: 12269
/* 12254 */   MCD_OPC_CheckPredicate, 5, 211, 1, // Skip to: 12725
/* 12258 */   MCD_OPC_CheckField, 13, 3, 0, 205, 1, // Skip to: 12725
/* 12264 */   MCD_OPC_Decode, 131, 4, 183, 1, // Opcode: EXTRV_RS_W
/* 12269 */   MCD_OPC_FilterValue, 10, 15, 0, // Skip to: 12288
/* 12273 */   MCD_OPC_CheckPredicate, 5, 192, 1, // Skip to: 12725
/* 12277 */   MCD_OPC_CheckField, 13, 3, 0, 186, 1, // Skip to: 12725
/* 12283 */   MCD_OPC_Decode, 128, 4, 182, 1, // Opcode: EXTPDP
/* 12288 */   MCD_OPC_FilterValue, 11, 15, 0, // Skip to: 12307
/* 12292 */   MCD_OPC_CheckPredicate, 5, 173, 1, // Skip to: 12725
/* 12296 */   MCD_OPC_CheckField, 13, 3, 0, 167, 1, // Skip to: 12725
/* 12302 */   MCD_OPC_Decode, 129, 4, 183, 1, // Opcode: EXTPDPV
/* 12307 */   MCD_OPC_FilterValue, 14, 15, 0, // Skip to: 12326
/* 12311 */   MCD_OPC_CheckPredicate, 5, 154, 1, // Skip to: 12725
/* 12315 */   MCD_OPC_CheckField, 13, 3, 0, 148, 1, // Skip to: 12725
/* 12321 */   MCD_OPC_Decode, 137, 4, 182, 1, // Opcode: EXTR_S_H
/* 12326 */   MCD_OPC_FilterValue, 15, 15, 0, // Skip to: 12345
/* 12330 */   MCD_OPC_CheckPredicate, 5, 135, 1, // Skip to: 12725
/* 12334 */   MCD_OPC_CheckField, 13, 3, 0, 129, 1, // Skip to: 12725
/* 12340 */   MCD_OPC_Decode, 133, 4, 183, 1, // Opcode: EXTRV_S_H
/* 12345 */   MCD_OPC_FilterValue, 18, 9, 0, // Skip to: 12358
/* 12349 */   MCD_OPC_CheckPredicate, 5, 116, 1, // Skip to: 12725
/* 12353 */   MCD_OPC_Decode, 237, 8, 184, 1, // Opcode: RDDSP
/* 12358 */   MCD_OPC_FilterValue, 19, 9, 0, // Skip to: 12371
/* 12362 */   MCD_OPC_CheckPredicate, 5, 103, 1, // Skip to: 12725
/* 12366 */   MCD_OPC_Decode, 183, 11, 185, 1, // Opcode: WRDSP
/* 12371 */   MCD_OPC_FilterValue, 26, 15, 0, // Skip to: 12390
/* 12375 */   MCD_OPC_CheckPredicate, 5, 90, 1, // Skip to: 12725
/* 12379 */   MCD_OPC_CheckField, 13, 7, 0, 84, 1, // Skip to: 12725
/* 12385 */   MCD_OPC_Decode, 169, 9, 186, 1, // Opcode: SHILO
/* 12390 */   MCD_OPC_FilterValue, 27, 15, 0, // Skip to: 12409
/* 12394 */   MCD_OPC_CheckPredicate, 5, 71, 1, // Skip to: 12725
/* 12398 */   MCD_OPC_CheckField, 13, 8, 0, 65, 1, // Skip to: 12725
/* 12404 */   MCD_OPC_Decode, 170, 9, 187, 1, // Opcode: SHILOV
/* 12409 */   MCD_OPC_FilterValue, 31, 56, 1, // Skip to: 12725
/* 12413 */   MCD_OPC_CheckPredicate, 5, 52, 1, // Skip to: 12725
/* 12417 */   MCD_OPC_CheckField, 13, 8, 0, 46, 1, // Skip to: 12725
/* 12423 */   MCD_OPC_Decode, 217, 7, 187, 1, // Opcode: MTHLIP
/* 12428 */   MCD_OPC_FilterValue, 59, 37, 1, // Skip to: 12725
/* 12432 */   MCD_OPC_CheckPredicate, 2, 33, 1, // Skip to: 12725
/* 12436 */   MCD_OPC_CheckField, 21, 5, 0, 27, 1, // Skip to: 12725
/* 12442 */   MCD_OPC_CheckField, 6, 5, 0, 21, 1, // Skip to: 12725
/* 12448 */   MCD_OPC_Decode, 238, 8, 188, 1, // Opcode: RDHWR
/* 12453 */   MCD_OPC_FilterValue, 32, 8, 0, // Skip to: 12465
/* 12457 */   MCD_OPC_CheckPredicate, 2, 8, 1, // Skip to: 12725
/* 12461 */   MCD_OPC_Decode, 236, 5, 30, // Opcode: LB
/* 12465 */   MCD_OPC_FilterValue, 33, 8, 0, // Skip to: 12477
/* 12469 */   MCD_OPC_CheckPredicate, 2, 252, 0, // Skip to: 12725
/* 12473 */   MCD_OPC_Decode, 135, 6, 30, // Opcode: LH
/* 12477 */   MCD_OPC_FilterValue, 34, 8, 0, // Skip to: 12489
/* 12481 */   MCD_OPC_CheckPredicate, 17, 240, 0, // Skip to: 12725
/* 12485 */   MCD_OPC_Decode, 161, 6, 30, // Opcode: LWL
/* 12489 */   MCD_OPC_FilterValue, 35, 8, 0, // Skip to: 12501
/* 12493 */   MCD_OPC_CheckPredicate, 2, 228, 0, // Skip to: 12725
/* 12497 */   MCD_OPC_Decode, 156, 6, 30, // Opcode: LW
/* 12501 */   MCD_OPC_FilterValue, 36, 8, 0, // Skip to: 12513
/* 12505 */   MCD_OPC_CheckPredicate, 2, 216, 0, // Skip to: 12725
/* 12509 */   MCD_OPC_Decode, 240, 5, 30, // Opcode: LBu
/* 12513 */   MCD_OPC_FilterValue, 37, 8, 0, // Skip to: 12525
/* 12517 */   MCD_OPC_CheckPredicate, 2, 204, 0, // Skip to: 12725
/* 12521 */   MCD_OPC_Decode, 139, 6, 30, // Opcode: LHu
/* 12525 */   MCD_OPC_FilterValue, 38, 8, 0, // Skip to: 12537
/* 12529 */   MCD_OPC_CheckPredicate, 17, 192, 0, // Skip to: 12725
/* 12533 */   MCD_OPC_Decode, 164, 6, 30, // Opcode: LWR
/* 12537 */   MCD_OPC_FilterValue, 40, 8, 0, // Skip to: 12549
/* 12541 */   MCD_OPC_CheckPredicate, 2, 180, 0, // Skip to: 12725
/* 12545 */   MCD_OPC_Decode, 141, 9, 30, // Opcode: SB
/* 12549 */   MCD_OPC_FilterValue, 41, 8, 0, // Skip to: 12561
/* 12553 */   MCD_OPC_CheckPredicate, 2, 168, 0, // Skip to: 12725
/* 12557 */   MCD_OPC_Decode, 164, 9, 30, // Opcode: SH
/* 12561 */   MCD_OPC_FilterValue, 42, 8, 0, // Skip to: 12573
/* 12565 */   MCD_OPC_CheckPredicate, 17, 156, 0, // Skip to: 12725
/* 12569 */   MCD_OPC_Decode, 210, 10, 30, // Opcode: SWL
/* 12573 */   MCD_OPC_FilterValue, 43, 8, 0, // Skip to: 12585
/* 12577 */   MCD_OPC_CheckPredicate, 2, 144, 0, // Skip to: 12725
/* 12581 */   MCD_OPC_Decode, 205, 10, 30, // Opcode: SW
/* 12585 */   MCD_OPC_FilterValue, 46, 8, 0, // Skip to: 12597
/* 12589 */   MCD_OPC_CheckPredicate, 17, 132, 0, // Skip to: 12725
/* 12593 */   MCD_OPC_Decode, 213, 10, 30, // Opcode: SWR
/* 12597 */   MCD_OPC_FilterValue, 48, 8, 0, // Skip to: 12609
/* 12601 */   MCD_OPC_CheckPredicate, 17, 120, 0, // Skip to: 12725
/* 12605 */   MCD_OPC_Decode, 142, 6, 30, // Opcode: LL
/* 12609 */   MCD_OPC_FilterValue, 49, 9, 0, // Skip to: 12622
/* 12613 */   MCD_OPC_CheckPredicate, 2, 108, 0, // Skip to: 12725
/* 12617 */   MCD_OPC_Decode, 158, 6, 189, 1, // Opcode: LWC1
/* 12622 */   MCD_OPC_FilterValue, 50, 9, 0, // Skip to: 12635
/* 12626 */   MCD_OPC_CheckPredicate, 2, 95, 0, // Skip to: 12725
/* 12630 */   MCD_OPC_Decode, 160, 6, 189, 1, // Opcode: LWC2
/* 12635 */   MCD_OPC_FilterValue, 53, 9, 0, // Skip to: 12648
/* 12639 */   MCD_OPC_CheckPredicate, 7, 82, 0, // Skip to: 12725
/* 12643 */   MCD_OPC_Decode, 244, 5, 189, 1, // Opcode: LDC1
/* 12648 */   MCD_OPC_FilterValue, 54, 9, 0, // Skip to: 12661
/* 12652 */   MCD_OPC_CheckPredicate, 2, 69, 0, // Skip to: 12725
/* 12656 */   MCD_OPC_Decode, 247, 5, 189, 1, // Opcode: LDC2
/* 12661 */   MCD_OPC_FilterValue, 56, 8, 0, // Skip to: 12673
/* 12665 */   MCD_OPC_CheckPredicate, 17, 56, 0, // Skip to: 12725
/* 12669 */   MCD_OPC_Decode, 144, 9, 30, // Opcode: SC
/* 12673 */   MCD_OPC_FilterValue, 57, 9, 0, // Skip to: 12686
/* 12677 */   MCD_OPC_CheckPredicate, 2, 44, 0, // Skip to: 12725
/* 12681 */   MCD_OPC_Decode, 207, 10, 189, 1, // Opcode: SWC1
/* 12686 */   MCD_OPC_FilterValue, 58, 9, 0, // Skip to: 12699
/* 12690 */   MCD_OPC_CheckPredicate, 2, 31, 0, // Skip to: 12725
/* 12694 */   MCD_OPC_Decode, 209, 10, 189, 1, // Opcode: SWC2
/* 12699 */   MCD_OPC_FilterValue, 61, 9, 0, // Skip to: 12712
/* 12703 */   MCD_OPC_CheckPredicate, 7, 18, 0, // Skip to: 12725
/* 12707 */   MCD_OPC_Decode, 148, 9, 189, 1, // Opcode: SDC1
/* 12712 */   MCD_OPC_FilterValue, 62, 9, 0, // Skip to: 12725
/* 12716 */   MCD_OPC_CheckPredicate, 2, 5, 0, // Skip to: 12725
/* 12720 */   MCD_OPC_Decode, 151, 9, 189, 1, // Opcode: SDC2
/* 12725 */   MCD_OPC_Fail,
  0
};

static uint8_t DecoderTableMips6432[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 93, 1, // Skip to: 356
/* 7 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10 */      MCD_OPC_FilterValue, 20, 15, 0, // Skip to: 29
/* 14 */      MCD_OPC_CheckPredicate, 2, 253, 6, // Skip to: 1807
/* 18 */      MCD_OPC_CheckField, 6, 5, 0, 247, 6, // Skip to: 1807
/* 24 */      MCD_OPC_Decode, 239, 3, 190, 1, // Opcode: DSLLV
/* 29 */      MCD_OPC_FilterValue, 22, 29, 0, // Skip to: 62
/* 33 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 36 */      MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 49
/* 40 */      MCD_OPC_CheckPredicate, 2, 227, 6, // Skip to: 1807
/* 44 */      MCD_OPC_Decode, 245, 3, 190, 1, // Opcode: DSRLV
/* 49 */      MCD_OPC_FilterValue, 1, 218, 6, // Skip to: 1807
/* 53 */      MCD_OPC_CheckPredicate, 18, 214, 6, // Skip to: 1807
/* 57 */      MCD_OPC_Decode, 232, 3, 190, 1, // Opcode: DROTRV
/* 62 */      MCD_OPC_FilterValue, 23, 15, 0, // Skip to: 81
/* 66 */      MCD_OPC_CheckPredicate, 2, 201, 6, // Skip to: 1807
/* 70 */      MCD_OPC_CheckField, 6, 5, 0, 195, 6, // Skip to: 1807
/* 76 */      MCD_OPC_Decode, 242, 3, 190, 1, // Opcode: DSRAV
/* 81 */      MCD_OPC_FilterValue, 28, 15, 0, // Skip to: 100
/* 85 */      MCD_OPC_CheckPredicate, 2, 182, 6, // Skip to: 1807
/* 89 */      MCD_OPC_CheckField, 6, 10, 0, 176, 6, // Skip to: 1807
/* 95 */      MCD_OPC_Decode, 194, 3, 191, 1, // Opcode: DMULT
/* 100 */     MCD_OPC_FilterValue, 29, 15, 0, // Skip to: 119
/* 104 */     MCD_OPC_CheckPredicate, 2, 163, 6, // Skip to: 1807
/* 108 */     MCD_OPC_CheckField, 6, 10, 0, 157, 6, // Skip to: 1807
/* 114 */     MCD_OPC_Decode, 195, 3, 191, 1, // Opcode: DMULTu
/* 119 */     MCD_OPC_FilterValue, 30, 15, 0, // Skip to: 138
/* 123 */     MCD_OPC_CheckPredicate, 2, 144, 6, // Skip to: 1807
/* 127 */     MCD_OPC_CheckField, 6, 10, 0, 138, 6, // Skip to: 1807
/* 133 */     MCD_OPC_Decode, 234, 3, 191, 1, // Opcode: DSDIV
/* 138 */     MCD_OPC_FilterValue, 31, 15, 0, // Skip to: 157
/* 142 */     MCD_OPC_CheckPredicate, 2, 125, 6, // Skip to: 1807
/* 146 */     MCD_OPC_CheckField, 6, 10, 0, 119, 6, // Skip to: 1807
/* 152 */     MCD_OPC_Decode, 247, 3, 191, 1, // Opcode: DUDIV
/* 157 */     MCD_OPC_FilterValue, 44, 15, 0, // Skip to: 176
/* 161 */     MCD_OPC_CheckPredicate, 2, 106, 6, // Skip to: 1807
/* 165 */     MCD_OPC_CheckField, 6, 5, 0, 100, 6, // Skip to: 1807
/* 171 */     MCD_OPC_Decode, 164, 3, 192, 1, // Opcode: DADD
/* 176 */     MCD_OPC_FilterValue, 45, 15, 0, // Skip to: 195
/* 180 */     MCD_OPC_CheckPredicate, 2, 87, 6, // Skip to: 1807
/* 184 */     MCD_OPC_CheckField, 6, 5, 0, 81, 6, // Skip to: 1807
/* 190 */     MCD_OPC_Decode, 167, 3, 192, 1, // Opcode: DADDu
/* 195 */     MCD_OPC_FilterValue, 47, 15, 0, // Skip to: 214
/* 199 */     MCD_OPC_CheckPredicate, 2, 68, 6, // Skip to: 1807
/* 203 */     MCD_OPC_CheckField, 6, 5, 0, 62, 6, // Skip to: 1807
/* 209 */     MCD_OPC_Decode, 246, 3, 192, 1, // Opcode: DSUBu
/* 214 */     MCD_OPC_FilterValue, 56, 15, 0, // Skip to: 233
/* 218 */     MCD_OPC_CheckPredicate, 2, 49, 6, // Skip to: 1807
/* 222 */     MCD_OPC_CheckField, 21, 5, 0, 43, 6, // Skip to: 1807
/* 228 */     MCD_OPC_Decode, 236, 3, 193, 1, // Opcode: DSLL
/* 233 */     MCD_OPC_FilterValue, 58, 29, 0, // Skip to: 266
/* 237 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 240 */     MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 253
/* 244 */     MCD_OPC_CheckPredicate, 2, 23, 6, // Skip to: 1807
/* 248 */     MCD_OPC_Decode, 243, 3, 193, 1, // Opcode: DSRL
/* 253 */     MCD_OPC_FilterValue, 1, 14, 6, // Skip to: 1807
/* 257 */     MCD_OPC_CheckPredicate, 18, 10, 6, // Skip to: 1807
/* 261 */     MCD_OPC_Decode, 230, 3, 193, 1, // Opcode: DROTR
/* 266 */     MCD_OPC_FilterValue, 59, 15, 0, // Skip to: 285
/* 270 */     MCD_OPC_CheckPredicate, 2, 253, 5, // Skip to: 1807
/* 274 */     MCD_OPC_CheckField, 21, 5, 0, 247, 5, // Skip to: 1807
/* 280 */     MCD_OPC_Decode, 240, 3, 193, 1, // Opcode: DSRA
/* 285 */     MCD_OPC_FilterValue, 60, 15, 0, // Skip to: 304
/* 289 */     MCD_OPC_CheckPredicate, 2, 234, 5, // Skip to: 1807
/* 293 */     MCD_OPC_CheckField, 21, 5, 0, 228, 5, // Skip to: 1807
/* 299 */     MCD_OPC_Decode, 237, 3, 193, 1, // Opcode: DSLL32
/* 304 */     MCD_OPC_FilterValue, 62, 29, 0, // Skip to: 337
/* 308 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 311 */     MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 324
/* 315 */     MCD_OPC_CheckPredicate, 2, 208, 5, // Skip to: 1807
/* 319 */     MCD_OPC_Decode, 244, 3, 193, 1, // Opcode: DSRL32
/* 324 */     MCD_OPC_FilterValue, 1, 199, 5, // Skip to: 1807
/* 328 */     MCD_OPC_CheckPredicate, 18, 195, 5, // Skip to: 1807
/* 332 */     MCD_OPC_Decode, 231, 3, 193, 1, // Opcode: DROTR32
/* 337 */     MCD_OPC_FilterValue, 63, 186, 5, // Skip to: 1807
/* 341 */     MCD_OPC_CheckPredicate, 2, 182, 5, // Skip to: 1807
/* 345 */     MCD_OPC_CheckField, 21, 5, 0, 176, 5, // Skip to: 1807
/* 351 */     MCD_OPC_Decode, 241, 3, 193, 1, // Opcode: DSRA32
/* 356 */     MCD_OPC_FilterValue, 16, 41, 0, // Skip to: 401
/* 360 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 363 */     MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 382
/* 367 */     MCD_OPC_CheckPredicate, 19, 156, 5, // Skip to: 1807
/* 371 */     MCD_OPC_CheckField, 3, 8, 0, 150, 5, // Skip to: 1807
/* 377 */     MCD_OPC_Decode, 188, 3, 194, 1, // Opcode: DMFC0
/* 382 */     MCD_OPC_FilterValue, 5, 141, 5, // Skip to: 1807
/* 386 */     MCD_OPC_CheckPredicate, 19, 137, 5, // Skip to: 1807
/* 390 */     MCD_OPC_CheckField, 3, 8, 0, 131, 5, // Skip to: 1807
/* 396 */     MCD_OPC_Decode, 191, 3, 194, 1, // Opcode: DMTC0
/* 401 */     MCD_OPC_FilterValue, 17, 183, 3, // Skip to: 1356
/* 405 */     MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 408 */     MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 427
/* 412 */     MCD_OPC_CheckPredicate, 20, 111, 5, // Skip to: 1807
/* 416 */     MCD_OPC_CheckField, 21, 5, 17, 105, 5, // Skip to: 1807
/* 422 */     MCD_OPC_Decode, 151, 4, 195, 1, // Opcode: FADD_D64
/* 427 */     MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 446
/* 431 */     MCD_OPC_CheckPredicate, 20, 92, 5, // Skip to: 1807
/* 435 */     MCD_OPC_CheckField, 21, 5, 17, 86, 5, // Skip to: 1807
/* 441 */     MCD_OPC_Decode, 152, 5, 195, 1, // Opcode: FSUB_D64
/* 446 */     MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 465
/* 450 */     MCD_OPC_CheckPredicate, 20, 73, 5, // Skip to: 1807
/* 454 */     MCD_OPC_CheckField, 21, 5, 17, 67, 5, // Skip to: 1807
/* 460 */     MCD_OPC_Decode, 243, 4, 195, 1, // Opcode: FMUL_D64
/* 465 */     MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 484
/* 469 */     MCD_OPC_CheckPredicate, 20, 54, 5, // Skip to: 1807
/* 473 */     MCD_OPC_CheckField, 21, 5, 17, 48, 5, // Skip to: 1807
/* 479 */     MCD_OPC_Decode, 187, 4, 195, 1, // Opcode: FDIV_D64
/* 484 */     MCD_OPC_FilterValue, 4, 15, 0, // Skip to: 503
/* 488 */     MCD_OPC_CheckPredicate, 20, 35, 5, // Skip to: 1807
/* 492 */     MCD_OPC_CheckField, 16, 10, 160, 4, 28, 5, // Skip to: 1807
/* 499 */     MCD_OPC_Decode, 145, 5, 77, // Opcode: FSQRT_D64
/* 503 */     MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 522
/* 507 */     MCD_OPC_CheckPredicate, 6, 16, 5, // Skip to: 1807
/* 511 */     MCD_OPC_CheckField, 16, 10, 160, 4, 9, 5, // Skip to: 1807
/* 518 */     MCD_OPC_Decode, 144, 4, 77, // Opcode: FABS_D64
/* 522 */     MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 541
/* 526 */     MCD_OPC_CheckPredicate, 20, 253, 4, // Skip to: 1807
/* 530 */     MCD_OPC_CheckField, 16, 10, 160, 4, 246, 4, // Skip to: 1807
/* 537 */     MCD_OPC_Decode, 236, 4, 77, // Opcode: FMOV_D64
/* 541 */     MCD_OPC_FilterValue, 7, 15, 0, // Skip to: 560
/* 545 */     MCD_OPC_CheckPredicate, 6, 234, 4, // Skip to: 1807
/* 549 */     MCD_OPC_CheckField, 16, 10, 160, 4, 227, 4, // Skip to: 1807
/* 556 */     MCD_OPC_Decode, 249, 4, 77, // Opcode: FNEG_D64
/* 560 */     MCD_OPC_FilterValue, 8, 29, 0, // Skip to: 593
/* 564 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 567 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 580
/* 572 */     MCD_OPC_CheckPredicate, 20, 207, 4, // Skip to: 1807
/* 576 */     MCD_OPC_Decode, 251, 8, 70, // Opcode: ROUND_L_S
/* 580 */     MCD_OPC_FilterValue, 160, 4, 198, 4, // Skip to: 1807
/* 585 */     MCD_OPC_CheckPredicate, 20, 194, 4, // Skip to: 1807
/* 589 */     MCD_OPC_Decode, 250, 8, 77, // Opcode: ROUND_L_D64
/* 593 */     MCD_OPC_FilterValue, 9, 29, 0, // Skip to: 626
/* 597 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 600 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 613
/* 605 */     MCD_OPC_CheckPredicate, 20, 174, 4, // Skip to: 1807
/* 609 */     MCD_OPC_Decode, 168, 11, 70, // Opcode: TRUNC_L_S
/* 613 */     MCD_OPC_FilterValue, 160, 4, 165, 4, // Skip to: 1807
/* 618 */     MCD_OPC_CheckPredicate, 20, 161, 4, // Skip to: 1807
/* 622 */     MCD_OPC_Decode, 167, 11, 77, // Opcode: TRUNC_L_D64
/* 626 */     MCD_OPC_FilterValue, 10, 29, 0, // Skip to: 659
/* 630 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 633 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 646
/* 638 */     MCD_OPC_CheckPredicate, 20, 141, 4, // Skip to: 1807
/* 642 */     MCD_OPC_Decode, 141, 2, 70, // Opcode: CEIL_L_S
/* 646 */     MCD_OPC_FilterValue, 160, 4, 132, 4, // Skip to: 1807
/* 651 */     MCD_OPC_CheckPredicate, 20, 128, 4, // Skip to: 1807
/* 655 */     MCD_OPC_Decode, 140, 2, 77, // Opcode: CEIL_L_D64
/* 659 */     MCD_OPC_FilterValue, 11, 29, 0, // Skip to: 692
/* 663 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 666 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 679
/* 671 */     MCD_OPC_CheckPredicate, 20, 108, 4, // Skip to: 1807
/* 675 */     MCD_OPC_Decode, 218, 4, 70, // Opcode: FLOOR_L_S
/* 679 */     MCD_OPC_FilterValue, 160, 4, 99, 4, // Skip to: 1807
/* 684 */     MCD_OPC_CheckPredicate, 20, 95, 4, // Skip to: 1807
/* 688 */     MCD_OPC_Decode, 217, 4, 77, // Opcode: FLOOR_L_D64
/* 692 */     MCD_OPC_FilterValue, 12, 16, 0, // Skip to: 712
/* 696 */     MCD_OPC_CheckPredicate, 20, 83, 4, // Skip to: 1807
/* 700 */     MCD_OPC_CheckField, 16, 10, 160, 4, 76, 4, // Skip to: 1807
/* 707 */     MCD_OPC_Decode, 253, 8, 196, 1, // Opcode: ROUND_W_D64
/* 712 */     MCD_OPC_FilterValue, 13, 16, 0, // Skip to: 732
/* 716 */     MCD_OPC_CheckPredicate, 20, 63, 4, // Skip to: 1807
/* 720 */     MCD_OPC_CheckField, 16, 10, 160, 4, 56, 4, // Skip to: 1807
/* 727 */     MCD_OPC_Decode, 170, 11, 196, 1, // Opcode: TRUNC_W_D64
/* 732 */     MCD_OPC_FilterValue, 14, 16, 0, // Skip to: 752
/* 736 */     MCD_OPC_CheckPredicate, 20, 43, 4, // Skip to: 1807
/* 740 */     MCD_OPC_CheckField, 16, 10, 160, 4, 36, 4, // Skip to: 1807
/* 747 */     MCD_OPC_Decode, 143, 2, 196, 1, // Opcode: CEIL_W_D64
/* 752 */     MCD_OPC_FilterValue, 15, 16, 0, // Skip to: 772
/* 756 */     MCD_OPC_CheckPredicate, 20, 23, 4, // Skip to: 1807
/* 760 */     MCD_OPC_CheckField, 16, 10, 160, 4, 16, 4, // Skip to: 1807
/* 767 */     MCD_OPC_Decode, 220, 4, 196, 1, // Opcode: FLOOR_W_D64
/* 772 */     MCD_OPC_FilterValue, 17, 41, 0, // Skip to: 817
/* 776 */     MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 779 */     MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 798
/* 783 */     MCD_OPC_CheckPredicate, 20, 252, 3, // Skip to: 1807
/* 787 */     MCD_OPC_CheckField, 21, 5, 17, 246, 3, // Skip to: 1807
/* 793 */     MCD_OPC_Decode, 150, 7, 197, 1, // Opcode: MOVF_D64
/* 798 */     MCD_OPC_FilterValue, 1, 237, 3, // Skip to: 1807
/* 802 */     MCD_OPC_CheckPredicate, 20, 233, 3, // Skip to: 1807
/* 806 */     MCD_OPC_CheckField, 21, 5, 17, 227, 3, // Skip to: 1807
/* 812 */     MCD_OPC_Decode, 170, 7, 197, 1, // Opcode: MOVT_D64
/* 817 */     MCD_OPC_FilterValue, 18, 15, 0, // Skip to: 836
/* 821 */     MCD_OPC_CheckPredicate, 20, 214, 3, // Skip to: 1807
/* 825 */     MCD_OPC_CheckField, 21, 5, 17, 208, 3, // Skip to: 1807
/* 831 */     MCD_OPC_Decode, 182, 7, 198, 1, // Opcode: MOVZ_I_D64
/* 836 */     MCD_OPC_FilterValue, 19, 15, 0, // Skip to: 855
/* 840 */     MCD_OPC_CheckPredicate, 20, 195, 3, // Skip to: 1807
/* 844 */     MCD_OPC_CheckField, 21, 5, 17, 189, 3, // Skip to: 1807
/* 850 */     MCD_OPC_Decode, 162, 7, 198, 1, // Opcode: MOVN_I_D64
/* 855 */     MCD_OPC_FilterValue, 32, 31, 0, // Skip to: 890
/* 859 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 862 */     MCD_OPC_FilterValue, 160, 4, 9, 0, // Skip to: 876
/* 867 */     MCD_OPC_CheckPredicate, 20, 168, 3, // Skip to: 1807
/* 871 */     MCD_OPC_Decode, 231, 2, 196, 1, // Opcode: CVT_S_D64
/* 876 */     MCD_OPC_FilterValue, 160, 5, 158, 3, // Skip to: 1807
/* 881 */     MCD_OPC_CheckPredicate, 20, 154, 3, // Skip to: 1807
/* 885 */     MCD_OPC_Decode, 232, 2, 196, 1, // Opcode: CVT_S_L
/* 890 */     MCD_OPC_FilterValue, 33, 42, 0, // Skip to: 936
/* 894 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 897 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 910
/* 902 */     MCD_OPC_CheckPredicate, 20, 133, 3, // Skip to: 1807
/* 906 */     MCD_OPC_Decode, 222, 2, 70, // Opcode: CVT_D64_S
/* 910 */     MCD_OPC_FilterValue, 128, 5, 8, 0, // Skip to: 923
/* 915 */     MCD_OPC_CheckPredicate, 20, 120, 3, // Skip to: 1807
/* 919 */     MCD_OPC_Decode, 223, 2, 70, // Opcode: CVT_D64_W
/* 923 */     MCD_OPC_FilterValue, 160, 5, 111, 3, // Skip to: 1807
/* 928 */     MCD_OPC_CheckPredicate, 20, 107, 3, // Skip to: 1807
/* 932 */     MCD_OPC_Decode, 221, 2, 77, // Opcode: CVT_D64_L
/* 936 */     MCD_OPC_FilterValue, 36, 16, 0, // Skip to: 956
/* 940 */     MCD_OPC_CheckPredicate, 20, 95, 3, // Skip to: 1807
/* 944 */     MCD_OPC_CheckField, 16, 10, 160, 4, 88, 3, // Skip to: 1807
/* 951 */     MCD_OPC_Decode, 236, 2, 196, 1, // Opcode: CVT_W_D64
/* 956 */     MCD_OPC_FilterValue, 48, 21, 0, // Skip to: 981
/* 960 */     MCD_OPC_CheckPredicate, 20, 75, 3, // Skip to: 1807
/* 964 */     MCD_OPC_CheckField, 21, 5, 17, 69, 3, // Skip to: 1807
/* 970 */     MCD_OPC_CheckField, 6, 5, 0, 63, 3, // Skip to: 1807
/* 976 */     MCD_OPC_Decode, 244, 2, 199, 1, // Opcode: C_F_D64
/* 981 */     MCD_OPC_FilterValue, 49, 21, 0, // Skip to: 1006
/* 985 */     MCD_OPC_CheckPredicate, 20, 50, 3, // Skip to: 1807
/* 989 */     MCD_OPC_CheckField, 21, 5, 17, 44, 3, // Skip to: 1807
/* 995 */     MCD_OPC_CheckField, 6, 5, 0, 38, 3, // Skip to: 1807
/* 1001 */    MCD_OPC_Decode, 158, 3, 199, 1, // Opcode: C_UN_D64
/* 1006 */    MCD_OPC_FilterValue, 50, 21, 0, // Skip to: 1031
/* 1010 */    MCD_OPC_CheckPredicate, 20, 25, 3, // Skip to: 1807
/* 1014 */    MCD_OPC_CheckField, 21, 5, 17, 19, 3, // Skip to: 1807
/* 1020 */    MCD_OPC_CheckField, 6, 5, 0, 13, 3, // Skip to: 1807
/* 1026 */    MCD_OPC_Decode, 241, 2, 199, 1, // Opcode: C_EQ_D64
/* 1031 */    MCD_OPC_FilterValue, 51, 21, 0, // Skip to: 1056
/* 1035 */    MCD_OPC_CheckPredicate, 20, 0, 3, // Skip to: 1807
/* 1039 */    MCD_OPC_CheckField, 21, 5, 17, 250, 2, // Skip to: 1807
/* 1045 */    MCD_OPC_CheckField, 6, 5, 0, 244, 2, // Skip to: 1807
/* 1051 */    MCD_OPC_Decode, 149, 3, 199, 1, // Opcode: C_UEQ_D64
/* 1056 */    MCD_OPC_FilterValue, 52, 21, 0, // Skip to: 1081
/* 1060 */    MCD_OPC_CheckPredicate, 20, 231, 2, // Skip to: 1807
/* 1064 */    MCD_OPC_CheckField, 21, 5, 17, 225, 2, // Skip to: 1807
/* 1070 */    MCD_OPC_CheckField, 6, 5, 0, 219, 2, // Skip to: 1807
/* 1076 */    MCD_OPC_Decode, 140, 3, 199, 1, // Opcode: C_OLT_D64
/* 1081 */    MCD_OPC_FilterValue, 53, 21, 0, // Skip to: 1106
/* 1085 */    MCD_OPC_CheckPredicate, 20, 206, 2, // Skip to: 1807
/* 1089 */    MCD_OPC_CheckField, 21, 5, 17, 200, 2, // Skip to: 1807
/* 1095 */    MCD_OPC_CheckField, 6, 5, 0, 194, 2, // Skip to: 1807
/* 1101 */    MCD_OPC_Decode, 155, 3, 199, 1, // Opcode: C_ULT_D64
/* 1106 */    MCD_OPC_FilterValue, 54, 21, 0, // Skip to: 1131
/* 1110 */    MCD_OPC_CheckPredicate, 20, 181, 2, // Skip to: 1807
/* 1114 */    MCD_OPC_CheckField, 21, 5, 17, 175, 2, // Skip to: 1807
/* 1120 */    MCD_OPC_CheckField, 6, 5, 0, 169, 2, // Skip to: 1807
/* 1126 */    MCD_OPC_Decode, 137, 3, 199, 1, // Opcode: C_OLE_D64
/* 1131 */    MCD_OPC_FilterValue, 55, 21, 0, // Skip to: 1156
/* 1135 */    MCD_OPC_CheckPredicate, 20, 156, 2, // Skip to: 1807
/* 1139 */    MCD_OPC_CheckField, 21, 5, 17, 150, 2, // Skip to: 1807
/* 1145 */    MCD_OPC_CheckField, 6, 5, 0, 144, 2, // Skip to: 1807
/* 1151 */    MCD_OPC_Decode, 152, 3, 199, 1, // Opcode: C_ULE_D64
/* 1156 */    MCD_OPC_FilterValue, 56, 21, 0, // Skip to: 1181
/* 1160 */    MCD_OPC_CheckPredicate, 20, 131, 2, // Skip to: 1807
/* 1164 */    MCD_OPC_CheckField, 21, 5, 17, 125, 2, // Skip to: 1807
/* 1170 */    MCD_OPC_CheckField, 6, 5, 0, 119, 2, // Skip to: 1807
/* 1176 */    MCD_OPC_Decode, 146, 3, 199, 1, // Opcode: C_SF_D64
/* 1181 */    MCD_OPC_FilterValue, 57, 21, 0, // Skip to: 1206
/* 1185 */    MCD_OPC_CheckPredicate, 20, 106, 2, // Skip to: 1807
/* 1189 */    MCD_OPC_CheckField, 21, 5, 17, 100, 2, // Skip to: 1807
/* 1195 */    MCD_OPC_CheckField, 6, 5, 0, 94, 2, // Skip to: 1807
/* 1201 */    MCD_OPC_Decode, 128, 3, 199, 1, // Opcode: C_NGLE_D64
/* 1206 */    MCD_OPC_FilterValue, 58, 21, 0, // Skip to: 1231
/* 1210 */    MCD_OPC_CheckPredicate, 20, 81, 2, // Skip to: 1807
/* 1214 */    MCD_OPC_CheckField, 21, 5, 17, 75, 2, // Skip to: 1807
/* 1220 */    MCD_OPC_CheckField, 6, 5, 0, 69, 2, // Skip to: 1807
/* 1226 */    MCD_OPC_Decode, 143, 3, 199, 1, // Opcode: C_SEQ_D64
/* 1231 */    MCD_OPC_FilterValue, 59, 21, 0, // Skip to: 1256
/* 1235 */    MCD_OPC_CheckPredicate, 20, 56, 2, // Skip to: 1807
/* 1239 */    MCD_OPC_CheckField, 21, 5, 17, 50, 2, // Skip to: 1807
/* 1245 */    MCD_OPC_CheckField, 6, 5, 0, 44, 2, // Skip to: 1807
/* 1251 */    MCD_OPC_Decode, 131, 3, 199, 1, // Opcode: C_NGL_D64
/* 1256 */    MCD_OPC_FilterValue, 60, 21, 0, // Skip to: 1281
/* 1260 */    MCD_OPC_CheckPredicate, 20, 31, 2, // Skip to: 1807
/* 1264 */    MCD_OPC_CheckField, 21, 5, 17, 25, 2, // Skip to: 1807
/* 1270 */    MCD_OPC_CheckField, 6, 5, 0, 19, 2, // Skip to: 1807
/* 1276 */    MCD_OPC_Decode, 250, 2, 199, 1, // Opcode: C_LT_D64
/* 1281 */    MCD_OPC_FilterValue, 61, 21, 0, // Skip to: 1306
/* 1285 */    MCD_OPC_CheckPredicate, 20, 6, 2, // Skip to: 1807
/* 1289 */    MCD_OPC_CheckField, 21, 5, 17, 0, 2, // Skip to: 1807
/* 1295 */    MCD_OPC_CheckField, 6, 5, 0, 250, 1, // Skip to: 1807
/* 1301 */    MCD_OPC_Decode, 253, 2, 199, 1, // Opcode: C_NGE_D64
/* 1306 */    MCD_OPC_FilterValue, 62, 21, 0, // Skip to: 1331
/* 1310 */    MCD_OPC_CheckPredicate, 20, 237, 1, // Skip to: 1807
/* 1314 */    MCD_OPC_CheckField, 21, 5, 17, 231, 1, // Skip to: 1807
/* 1320 */    MCD_OPC_CheckField, 6, 5, 0, 225, 1, // Skip to: 1807
/* 1326 */    MCD_OPC_Decode, 247, 2, 199, 1, // Opcode: C_LE_D64
/* 1331 */    MCD_OPC_FilterValue, 63, 216, 1, // Skip to: 1807
/* 1335 */    MCD_OPC_CheckPredicate, 20, 212, 1, // Skip to: 1807
/* 1339 */    MCD_OPC_CheckField, 21, 5, 17, 206, 1, // Skip to: 1807
/* 1345 */    MCD_OPC_CheckField, 6, 5, 0, 200, 1, // Skip to: 1807
/* 1351 */    MCD_OPC_Decode, 134, 3, 199, 1, // Opcode: C_NGT_D64
/* 1356 */    MCD_OPC_FilterValue, 18, 41, 0, // Skip to: 1401
/* 1360 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1363 */    MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 1382
/* 1367 */    MCD_OPC_CheckPredicate, 19, 180, 1, // Skip to: 1807
/* 1371 */    MCD_OPC_CheckField, 3, 8, 0, 174, 1, // Skip to: 1807
/* 1377 */    MCD_OPC_Decode, 190, 3, 194, 1, // Opcode: DMFC2
/* 1382 */    MCD_OPC_FilterValue, 5, 165, 1, // Skip to: 1807
/* 1386 */    MCD_OPC_CheckPredicate, 19, 161, 1, // Skip to: 1807
/* 1390 */    MCD_OPC_CheckField, 3, 8, 0, 155, 1, // Skip to: 1807
/* 1396 */    MCD_OPC_Decode, 193, 3, 194, 1, // Opcode: DMTC2
/* 1401 */    MCD_OPC_FilterValue, 19, 79, 0, // Skip to: 1484
/* 1405 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1408 */    MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 1427
/* 1412 */    MCD_OPC_CheckPredicate, 21, 135, 1, // Skip to: 1807
/* 1416 */    MCD_OPC_CheckField, 11, 5, 0, 129, 1, // Skip to: 1807
/* 1422 */    MCD_OPC_Decode, 255, 5, 200, 1, // Opcode: LDXC164
/* 1427 */    MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 1446
/* 1431 */    MCD_OPC_CheckPredicate, 20, 116, 1, // Skip to: 1807
/* 1435 */    MCD_OPC_CheckField, 11, 5, 0, 110, 1, // Skip to: 1807
/* 1441 */    MCD_OPC_Decode, 151, 6, 200, 1, // Opcode: LUXC164
/* 1446 */    MCD_OPC_FilterValue, 9, 15, 0, // Skip to: 1465
/* 1450 */    MCD_OPC_CheckPredicate, 21, 97, 1, // Skip to: 1807
/* 1454 */    MCD_OPC_CheckField, 6, 5, 0, 91, 1, // Skip to: 1807
/* 1460 */    MCD_OPC_Decode, 157, 9, 201, 1, // Opcode: SDXC164
/* 1465 */    MCD_OPC_FilterValue, 13, 82, 1, // Skip to: 1807
/* 1469 */    MCD_OPC_CheckPredicate, 20, 78, 1, // Skip to: 1807
/* 1473 */    MCD_OPC_CheckField, 6, 5, 0, 72, 1, // Skip to: 1807
/* 1479 */    MCD_OPC_Decode, 203, 10, 201, 1, // Opcode: SUXC164
/* 1484 */    MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 1497
/* 1488 */    MCD_OPC_CheckPredicate, 2, 59, 1, // Skip to: 1807
/* 1492 */    MCD_OPC_Decode, 165, 3, 202, 1, // Opcode: DADDi
/* 1497 */    MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 1510
/* 1501 */    MCD_OPC_CheckPredicate, 2, 46, 1, // Skip to: 1807
/* 1505 */    MCD_OPC_Decode, 166, 3, 202, 1, // Opcode: DADDiu
/* 1510 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 1522
/* 1514 */    MCD_OPC_CheckPredicate, 2, 33, 1, // Skip to: 1807
/* 1518 */    MCD_OPC_Decode, 252, 5, 30, // Opcode: LDL
/* 1522 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 1534
/* 1526 */    MCD_OPC_CheckPredicate, 2, 21, 1, // Skip to: 1807
/* 1530 */    MCD_OPC_Decode, 253, 5, 30, // Opcode: LDR
/* 1534 */    MCD_OPC_FilterValue, 28, 29, 0, // Skip to: 1567
/* 1538 */    MCD_OPC_ExtractField, 0, 11,  // Inst{10-0} ...
/* 1541 */    MCD_OPC_FilterValue, 36, 9, 0, // Skip to: 1554
/* 1545 */    MCD_OPC_CheckPredicate, 13, 2, 1, // Skip to: 1807
/* 1549 */    MCD_OPC_Decode, 169, 3, 203, 1, // Opcode: DCLZ
/* 1554 */    MCD_OPC_FilterValue, 37, 249, 0, // Skip to: 1807
/* 1558 */    MCD_OPC_CheckPredicate, 13, 245, 0, // Skip to: 1807
/* 1562 */    MCD_OPC_Decode, 168, 3, 203, 1, // Opcode: DCLO
/* 1567 */    MCD_OPC_FilterValue, 31, 126, 0, // Skip to: 1697
/* 1571 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1574 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 1587
/* 1578 */    MCD_OPC_CheckPredicate, 3, 225, 0, // Skip to: 1807
/* 1582 */    MCD_OPC_Decode, 173, 3, 204, 1, // Opcode: DEXTM
/* 1587 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 1600
/* 1591 */    MCD_OPC_CheckPredicate, 3, 212, 0, // Skip to: 1807
/* 1595 */    MCD_OPC_Decode, 174, 3, 204, 1, // Opcode: DEXTU
/* 1600 */    MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 1613
/* 1604 */    MCD_OPC_CheckPredicate, 3, 199, 0, // Skip to: 1807
/* 1608 */    MCD_OPC_Decode, 172, 3, 204, 1, // Opcode: DEXT
/* 1613 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 1626
/* 1617 */    MCD_OPC_CheckPredicate, 3, 186, 0, // Skip to: 1807
/* 1621 */    MCD_OPC_Decode, 177, 3, 205, 1, // Opcode: DINSM
/* 1626 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 1639
/* 1630 */    MCD_OPC_CheckPredicate, 3, 173, 0, // Skip to: 1807
/* 1634 */    MCD_OPC_Decode, 178, 3, 205, 1, // Opcode: DINSU
/* 1639 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 1652
/* 1643 */    MCD_OPC_CheckPredicate, 3, 160, 0, // Skip to: 1807
/* 1647 */    MCD_OPC_Decode, 176, 3, 205, 1, // Opcode: DINS
/* 1652 */    MCD_OPC_FilterValue, 36, 151, 0, // Skip to: 1807
/* 1656 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 1659 */    MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 1678
/* 1663 */    MCD_OPC_CheckPredicate, 15, 140, 0, // Skip to: 1807
/* 1667 */    MCD_OPC_CheckField, 21, 5, 0, 134, 0, // Skip to: 1807
/* 1673 */    MCD_OPC_Decode, 233, 3, 206, 1, // Opcode: DSBH
/* 1678 */    MCD_OPC_FilterValue, 5, 125, 0, // Skip to: 1807
/* 1682 */    MCD_OPC_CheckPredicate, 15, 121, 0, // Skip to: 1807
/* 1686 */    MCD_OPC_CheckField, 21, 5, 0, 115, 0, // Skip to: 1807
/* 1692 */    MCD_OPC_Decode, 235, 3, 206, 1, // Opcode: DSHD
/* 1697 */    MCD_OPC_FilterValue, 39, 8, 0, // Skip to: 1709
/* 1701 */    MCD_OPC_CheckPredicate, 2, 102, 0, // Skip to: 1807
/* 1705 */    MCD_OPC_Decode, 171, 6, 30, // Opcode: LWu
/* 1709 */    MCD_OPC_FilterValue, 44, 8, 0, // Skip to: 1721
/* 1713 */    MCD_OPC_CheckPredicate, 2, 90, 0, // Skip to: 1807
/* 1717 */    MCD_OPC_Decode, 154, 9, 30, // Opcode: SDL
/* 1721 */    MCD_OPC_FilterValue, 45, 8, 0, // Skip to: 1733
/* 1725 */    MCD_OPC_CheckPredicate, 2, 78, 0, // Skip to: 1807
/* 1729 */    MCD_OPC_Decode, 155, 9, 30, // Opcode: SDR
/* 1733 */    MCD_OPC_FilterValue, 52, 8, 0, // Skip to: 1745
/* 1737 */    MCD_OPC_CheckPredicate, 2, 66, 0, // Skip to: 1807
/* 1741 */    MCD_OPC_Decode, 143, 6, 30, // Opcode: LLD
/* 1745 */    MCD_OPC_FilterValue, 53, 9, 0, // Skip to: 1758
/* 1749 */    MCD_OPC_CheckPredicate, 20, 54, 0, // Skip to: 1807
/* 1753 */    MCD_OPC_Decode, 245, 5, 189, 1, // Opcode: LDC164
/* 1758 */    MCD_OPC_FilterValue, 55, 8, 0, // Skip to: 1770
/* 1762 */    MCD_OPC_CheckPredicate, 2, 41, 0, // Skip to: 1807
/* 1766 */    MCD_OPC_Decode, 243, 5, 30, // Opcode: LD
/* 1770 */    MCD_OPC_FilterValue, 60, 8, 0, // Skip to: 1782
/* 1774 */    MCD_OPC_CheckPredicate, 2, 29, 0, // Skip to: 1807
/* 1778 */    MCD_OPC_Decode, 145, 9, 30, // Opcode: SCD
/* 1782 */    MCD_OPC_FilterValue, 61, 9, 0, // Skip to: 1795
/* 1786 */    MCD_OPC_CheckPredicate, 20, 17, 0, // Skip to: 1807
/* 1790 */    MCD_OPC_Decode, 149, 9, 189, 1, // Opcode: SDC164
/* 1795 */    MCD_OPC_FilterValue, 63, 8, 0, // Skip to: 1807
/* 1799 */    MCD_OPC_CheckPredicate, 2, 4, 0, // Skip to: 1807
/* 1803 */    MCD_OPC_Decode, 147, 9, 30, // Opcode: SD
/* 1807 */    MCD_OPC_Fail,
  0
};

static bool checkDecoderPredicate(unsigned Idx, uint64_t Bits)
{
  switch (Idx) {
  default: // llvm_unreachable("Invalid index!");
  case 0:
    return ((Bits & Mips_FeatureMips16));
  case 1:
    return ((Bits & Mips_FeatureMicroMips));
  case 2:
    return (!(Bits & Mips_FeatureMips16));
  case 3:
    return ((Bits & Mips_FeatureMips32r2) && !(Bits & Mips_FeatureMips16));
  case 4:
    return ((Bits & Mips_FeatureMSA));
  case 5:
    return ((Bits & Mips_FeatureDSP));
  case 6:
    return ((Bits & Mips_FeatureMips32) && !(Bits & Mips_FeatureMips16));
  case 7:
    return (!(Bits & Mips_FeatureFP64Bit) && !(Bits & Mips_FeatureMips16));
  case 8:
    return ((Bits & Mips_FeatureFPIdx) && !(Bits & Mips_FeatureMips16));
  case 9:
    return ((Bits & Mips_FeatureFPIdx) && !(Bits & Mips_FeatureFP64Bit) && !(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMicroMips));
  case 10:
    return ((Bits & Mips_FeatureMips32r2) && !(Bits & Mips_FeatureFP64Bit) && !(Bits & Mips_FeatureMips16));
  case 11:
    return ((Bits & Mips_FeatureMips32r2) && (Bits & Mips_FeatureMips32) && !(Bits & Mips_FeatureMips16));
  case 12:
    return ((Bits & Mips_FeatureMips32r2) && !(Bits & Mips_FeatureFP64Bit) && (Bits & Mips_FeatureMips32) && !(Bits & Mips_FeatureMips16));
  case 13:
    return ((Bits & Mips_FeatureBitCount) && !(Bits & Mips_FeatureMips16));
  case 14:
    return ((Bits & Mips_FeatureDSPR2));
  case 15:
    return ((Bits & Mips_FeatureSwap) && !(Bits & Mips_FeatureMips16));
  case 16:
    return ((Bits & Mips_FeatureSEInReg) && !(Bits & Mips_FeatureMips16));
  case 17:
    return (!(Bits & Mips_FeatureMicroMips));
  case 18:
    return ((Bits & Mips_FeatureMips64r2) && !(Bits & Mips_FeatureMips16));
  case 19:
    return ((Bits & Mips_FeatureMips64));
  case 20:
    return ((Bits & Mips_FeatureFP64Bit) && !(Bits & Mips_FeatureMips16));
  case 21:
    return ((Bits & Mips_FeatureFPIdx) && (Bits & Mips_FeatureFP64Bit) && !(Bits & Mips_FeatureMips16));
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
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 11: \
    tmp = fieldname(insn, 16, 10); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    tmp = fieldname(insn, 6, 10); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 12: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
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
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeExtSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 17: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 18: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 19: \
    tmp = fieldname(insn, 16, 10); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
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
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
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
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 27: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
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
    if (DecodeMem(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 31: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTargetMM(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 32: \
    if (DecodeJumpTargetMM(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 33: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 34: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 18, 3); \
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 35: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 2); \
    if (DecodeLSAImm(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 36: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 37: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 38: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 39: \
    tmp = fieldname(insn, 6, 20); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 40: \
    tmp = fieldname(insn, 6, 5); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 41: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 42: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 43: \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeHI32DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 44: \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeLO32DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
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
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
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
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
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
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 54: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 3); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
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
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 91: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 8); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 92: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 8); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 93: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 8); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 94: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 95: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 96: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 97: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 98: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 10); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 99: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 10); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 100: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 10); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 101: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 10); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 102: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 6); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 103: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 104: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 105: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 6); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 106: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 107: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 108: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
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
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 132: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 133: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 2); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 134: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 1); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
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
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 137: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 138: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 2); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 139: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 1); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
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
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 142: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 143: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 2); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 144: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 145: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 146: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 147: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 2); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 148: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 149: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 150: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 2); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 151: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 1); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 152: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 153: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 154: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 155: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 156: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 157: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 158: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 159: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 160: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 161: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 162: \
    if (DecodeMSA128Mem(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 163: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeExtSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 164: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeInsSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 165: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 166: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 167: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 168: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 169: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 170: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 171: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 172: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 173: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 174: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 10); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 175: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 176: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 177: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 178: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 179: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 180: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 181: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 182: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 183: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 184: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 10); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 185: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 10); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 186: \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 20, 6); \
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 187: \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 188: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeHWRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 189: \
    if (DecodeFMem(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 190: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 191: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 192: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 193: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 194: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 3); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    return S; \
  case 195: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 196: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 197: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 18, 3); \
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 198: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 199: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 200: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 201: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 202: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 203: \
    tmp = 0; \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    tmp |= (fieldname(insn, 16, 5) << 0); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 204: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeExtSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 205: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp)); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeInsSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 206: \
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
  uint32_t CurFieldValue = 0; \
  DecodeStatus S = MCDisassembler_Success; \
  for (;;) { \
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
      unsigned Len; \
      InsnType Val = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      unsigned NumToSkip = *Ptr++; \
      NumToSkip |= (*Ptr++) << 8; \
      if (Val != CurFieldValue) \
        Ptr += NumToSkip; \
      break; \
    } \
    case MCD_OPC_CheckField: { \
      unsigned Start = *++Ptr; \
      unsigned Len = *++Ptr; \
      InsnType FieldValue = fieldname(insn, Start, Len); \
      uint32_t ExpectedValue = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      unsigned NumToSkip = *Ptr++; \
      NumToSkip |= (*Ptr++) << 8; \
      if (ExpectedValue != FieldValue) \
        Ptr += NumToSkip; \
      break; \
    } \
    case MCD_OPC_CheckPredicate: { \
      unsigned Len; \
      unsigned PIdx = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      unsigned NumToSkip = *Ptr++; \
      NumToSkip |= (*Ptr++) << 8; \
      bool Pred; \
      if (!(Pred = checkDecoderPredicate(PIdx, Bits))) \
        Ptr += NumToSkip; \
      (void)Pred; \
      break; \
    } \
    case MCD_OPC_Decode: { \
      unsigned Len; \
      unsigned Opc = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      unsigned DecodeIdx = decodeULEB128(Ptr, &Len); \
      Ptr += Len; \
      MCInst_setOpcode(MI, Opc); \
      return decoder(S, DecodeIdx, insn, MI, Address, MRI); \
    } \
    case MCD_OPC_SoftFail: { \
      unsigned Len; \
      InsnType PositiveMask = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      InsnType NegativeMask = decodeULEB128(Ptr, &Len); \
      Ptr += Len; \
      bool Fail = (insn & PositiveMask) || (~insn & NegativeMask); \
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
