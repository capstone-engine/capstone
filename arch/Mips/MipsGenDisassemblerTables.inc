/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* * Mips Disassembler                                                        *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include "../../LEB128.h"

// Helper function for extracting fields from encoded instructions.
static uint32_t fieldFromInstruction(uint32_t insn, unsigned startBit,
                                     unsigned numBits)
{
    //assert(startBit + numBits <= (sizeof(uint32_t)*8) &&
    //       "Instruction field out of bounds!");
    uint32_t fieldMask;
    if (numBits == sizeof(uint32_t)*8)
      fieldMask = (uint32_t)(-1LL);
    else
      fieldMask = (((uint32_t)1 << numBits) - 1) << startBit;
    return (insn & fieldMask) >> startBit;
}

static uint8_t DecoderTableMicroMips32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 61, 2, // Skip to: 580
/* 7 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10 */      MCD_OPC_FilterValue, 0, 51, 0, // Skip to: 65
/* 14 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 17 */      MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 29
/* 21 */      MCD_OPC_CheckPredicate, 1, 191, 3, // Skip to: 984
/* 25 */      MCD_OPC_Decode, 141, 9, 10, // Opcode: SLL_MM
/* 29 */      MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 41
/* 33 */      MCD_OPC_CheckPredicate, 1, 179, 3, // Skip to: 984
/* 37 */      MCD_OPC_Decode, 206, 9, 10, // Opcode: SRL_MM
/* 41 */      MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 53
/* 45 */      MCD_OPC_CheckPredicate, 1, 167, 3, // Skip to: 984
/* 49 */      MCD_OPC_Decode, 186, 9, 10, // Opcode: SRA_MM
/* 53 */      MCD_OPC_FilterValue, 3, 159, 3, // Skip to: 984
/* 57 */      MCD_OPC_CheckPredicate, 1, 155, 3, // Skip to: 984
/* 61 */      MCD_OPC_Decode, 180, 8, 10, // Opcode: ROTR_MM
/* 65 */      MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 77
/* 69 */      MCD_OPC_CheckPredicate, 1, 143, 3, // Skip to: 984
/* 73 */      MCD_OPC_Decode, 175, 5, 11, // Opcode: INS_MM
/* 77 */      MCD_OPC_FilterValue, 16, 180, 0, // Skip to: 261
/* 81 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 84 */      MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 96
/* 88 */      MCD_OPC_CheckPredicate, 1, 124, 3, // Skip to: 984
/* 92 */      MCD_OPC_Decode, 137, 9, 12, // Opcode: SLLV_MM
/* 96 */      MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 108
/* 100 */     MCD_OPC_CheckPredicate, 1, 112, 3, // Skip to: 984
/* 104 */     MCD_OPC_Decode, 202, 9, 12, // Opcode: SRLV_MM
/* 108 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 120
/* 112 */     MCD_OPC_CheckPredicate, 1, 100, 3, // Skip to: 984
/* 116 */     MCD_OPC_Decode, 182, 9, 12, // Opcode: SRAV_MM
/* 120 */     MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 132
/* 124 */     MCD_OPC_CheckPredicate, 1, 88, 3, // Skip to: 984
/* 128 */     MCD_OPC_Decode, 179, 8, 12, // Opcode: ROTRV_MM
/* 132 */     MCD_OPC_FilterValue, 4, 7, 0, // Skip to: 143
/* 136 */     MCD_OPC_CheckPredicate, 1, 76, 3, // Skip to: 984
/* 140 */     MCD_OPC_Decode, 62, 13, // Opcode: ADD_MM
/* 143 */     MCD_OPC_FilterValue, 5, 7, 0, // Skip to: 154
/* 147 */     MCD_OPC_CheckPredicate, 1, 65, 3, // Skip to: 984
/* 151 */     MCD_OPC_Decode, 68, 13, // Opcode: ADDu_MM
/* 154 */     MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 166
/* 158 */     MCD_OPC_CheckPredicate, 1, 54, 3, // Skip to: 984
/* 162 */     MCD_OPC_Decode, 254, 9, 13, // Opcode: SUB_MM
/* 166 */     MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 178
/* 170 */     MCD_OPC_CheckPredicate, 1, 42, 3, // Skip to: 984
/* 174 */     MCD_OPC_Decode, 128, 10, 13, // Opcode: SUBu_MM
/* 178 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 190
/* 182 */     MCD_OPC_CheckPredicate, 1, 30, 3, // Skip to: 984
/* 186 */     MCD_OPC_Decode, 180, 7, 13, // Opcode: MUL_MM
/* 190 */     MCD_OPC_FilterValue, 9, 7, 0, // Skip to: 201
/* 194 */     MCD_OPC_CheckPredicate, 1, 18, 3, // Skip to: 984
/* 198 */     MCD_OPC_Decode, 74, 13, // Opcode: AND_MM
/* 201 */     MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 213
/* 205 */     MCD_OPC_CheckPredicate, 1, 7, 3, // Skip to: 984
/* 209 */     MCD_OPC_Decode, 221, 7, 13, // Opcode: OR_MM
/* 213 */     MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 225
/* 217 */     MCD_OPC_CheckPredicate, 1, 251, 2, // Skip to: 984
/* 221 */     MCD_OPC_Decode, 211, 7, 13, // Opcode: NOR_MM
/* 225 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 237
/* 229 */     MCD_OPC_CheckPredicate, 1, 239, 2, // Skip to: 984
/* 233 */     MCD_OPC_Decode, 226, 10, 13, // Opcode: XOR_MM
/* 237 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 249
/* 241 */     MCD_OPC_CheckPredicate, 1, 227, 2, // Skip to: 984
/* 245 */     MCD_OPC_Decode, 145, 9, 13, // Opcode: SLT_MM
/* 249 */     MCD_OPC_FilterValue, 14, 219, 2, // Skip to: 984
/* 253 */     MCD_OPC_CheckPredicate, 1, 215, 2, // Skip to: 984
/* 257 */     MCD_OPC_Decode, 154, 9, 13, // Opcode: SLTu_MM
/* 261 */     MCD_OPC_FilterValue, 24, 27, 0, // Skip to: 292
/* 265 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 268 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 280
/* 272 */     MCD_OPC_CheckPredicate, 1, 196, 2, // Skip to: 984
/* 276 */     MCD_OPC_Decode, 237, 6, 14, // Opcode: MOVN_I_MM
/* 280 */     MCD_OPC_FilterValue, 1, 188, 2, // Skip to: 984
/* 284 */     MCD_OPC_CheckPredicate, 1, 184, 2, // Skip to: 984
/* 288 */     MCD_OPC_Decode, 253, 6, 14, // Opcode: MOVZ_I_MM
/* 292 */     MCD_OPC_FilterValue, 44, 8, 0, // Skip to: 304
/* 296 */     MCD_OPC_CheckPredicate, 1, 172, 2, // Skip to: 984
/* 300 */     MCD_OPC_Decode, 245, 3, 15, // Opcode: EXT_MM
/* 304 */     MCD_OPC_FilterValue, 60, 164, 2, // Skip to: 984
/* 308 */     MCD_OPC_ExtractField, 6, 10,  // Inst{15-6} ...
/* 311 */     MCD_OPC_FilterValue, 53, 14, 0, // Skip to: 329
/* 315 */     MCD_OPC_CheckPredicate, 1, 153, 2, // Skip to: 984
/* 319 */     MCD_OPC_CheckField, 21, 5, 0, 147, 2, // Skip to: 984
/* 325 */     MCD_OPC_Decode, 186, 6, 16, // Opcode: MFHI_MM
/* 329 */     MCD_OPC_FilterValue, 60, 22, 0, // Skip to: 355
/* 333 */     MCD_OPC_CheckPredicate, 1, 10, 0, // Skip to: 347
/* 337 */     MCD_OPC_CheckField, 21, 5, 0, 4, 0, // Skip to: 347
/* 343 */     MCD_OPC_Decode, 186, 5, 16, // Opcode: JR_MM
/* 347 */     MCD_OPC_CheckPredicate, 1, 121, 2, // Skip to: 984
/* 351 */     MCD_OPC_Decode, 182, 5, 17, // Opcode: JALR_MM
/* 355 */     MCD_OPC_FilterValue, 117, 14, 0, // Skip to: 373
/* 359 */     MCD_OPC_CheckPredicate, 1, 109, 2, // Skip to: 984
/* 363 */     MCD_OPC_CheckField, 21, 5, 0, 103, 2, // Skip to: 984
/* 369 */     MCD_OPC_Decode, 190, 6, 16, // Opcode: MFLO_MM
/* 373 */     MCD_OPC_FilterValue, 172, 1, 8, 0, // Skip to: 386
/* 378 */     MCD_OPC_CheckPredicate, 1, 90, 2, // Skip to: 984
/* 382 */     MCD_OPC_Decode, 215, 8, 17, // Opcode: SEB_MM
/* 386 */     MCD_OPC_FilterValue, 181, 1, 14, 0, // Skip to: 405
/* 391 */     MCD_OPC_CheckPredicate, 1, 77, 2, // Skip to: 984
/* 395 */     MCD_OPC_CheckField, 21, 5, 0, 71, 2, // Skip to: 984
/* 401 */     MCD_OPC_Decode, 151, 7, 16, // Opcode: MTHI_MM
/* 405 */     MCD_OPC_FilterValue, 236, 1, 8, 0, // Skip to: 418
/* 410 */     MCD_OPC_CheckPredicate, 1, 58, 2, // Skip to: 984
/* 414 */     MCD_OPC_Decode, 218, 8, 17, // Opcode: SEH_MM
/* 418 */     MCD_OPC_FilterValue, 245, 1, 14, 0, // Skip to: 437
/* 423 */     MCD_OPC_CheckPredicate, 1, 45, 2, // Skip to: 984
/* 427 */     MCD_OPC_CheckField, 21, 5, 0, 39, 2, // Skip to: 984
/* 433 */     MCD_OPC_Decode, 156, 7, 16, // Opcode: MTLO_MM
/* 437 */     MCD_OPC_FilterValue, 172, 2, 8, 0, // Skip to: 450
/* 442 */     MCD_OPC_CheckPredicate, 1, 26, 2, // Skip to: 984
/* 446 */     MCD_OPC_Decode, 166, 2, 17, // Opcode: CLO_MM
/* 450 */     MCD_OPC_FilterValue, 236, 2, 8, 0, // Skip to: 463
/* 455 */     MCD_OPC_CheckPredicate, 1, 13, 2, // Skip to: 984
/* 459 */     MCD_OPC_Decode, 184, 2, 17, // Opcode: CLZ_MM
/* 463 */     MCD_OPC_FilterValue, 236, 3, 8, 0, // Skip to: 476
/* 468 */     MCD_OPC_CheckPredicate, 1, 0, 2, // Skip to: 984
/* 472 */     MCD_OPC_Decode, 222, 10, 17, // Opcode: WSBH_MM
/* 476 */     MCD_OPC_FilterValue, 172, 4, 8, 0, // Skip to: 489
/* 481 */     MCD_OPC_CheckPredicate, 1, 243, 1, // Skip to: 984
/* 485 */     MCD_OPC_Decode, 173, 7, 18, // Opcode: MULT_MM
/* 489 */     MCD_OPC_FilterValue, 236, 4, 8, 0, // Skip to: 502
/* 494 */     MCD_OPC_CheckPredicate, 1, 230, 1, // Skip to: 984
/* 498 */     MCD_OPC_Decode, 175, 7, 18, // Opcode: MULTu_MM
/* 502 */     MCD_OPC_FilterValue, 172, 5, 8, 0, // Skip to: 515
/* 507 */     MCD_OPC_CheckPredicate, 1, 217, 1, // Skip to: 984
/* 511 */     MCD_OPC_Decode, 208, 8, 18, // Opcode: SDIV_MM
/* 515 */     MCD_OPC_FilterValue, 236, 5, 8, 0, // Skip to: 528
/* 520 */     MCD_OPC_CheckPredicate, 1, 204, 1, // Skip to: 984
/* 524 */     MCD_OPC_Decode, 214, 10, 18, // Opcode: UDIV_MM
/* 528 */     MCD_OPC_FilterValue, 172, 6, 8, 0, // Skip to: 541
/* 533 */     MCD_OPC_CheckPredicate, 1, 191, 1, // Skip to: 984
/* 537 */     MCD_OPC_Decode, 151, 6, 18, // Opcode: MADD_MM
/* 541 */     MCD_OPC_FilterValue, 236, 6, 8, 0, // Skip to: 554
/* 546 */     MCD_OPC_CheckPredicate, 1, 178, 1, // Skip to: 984
/* 550 */     MCD_OPC_Decode, 143, 6, 18, // Opcode: MADDU_MM
/* 554 */     MCD_OPC_FilterValue, 172, 7, 8, 0, // Skip to: 567
/* 559 */     MCD_OPC_CheckPredicate, 1, 165, 1, // Skip to: 984
/* 563 */     MCD_OPC_Decode, 140, 7, 18, // Opcode: MSUB_MM
/* 567 */     MCD_OPC_FilterValue, 236, 7, 156, 1, // Skip to: 984
/* 572 */     MCD_OPC_CheckPredicate, 1, 152, 1, // Skip to: 984
/* 576 */     MCD_OPC_Decode, 132, 7, 18, // Opcode: MSUBU_MM
/* 580 */     MCD_OPC_FilterValue, 4, 7, 0, // Skip to: 591
/* 584 */     MCD_OPC_CheckPredicate, 1, 140, 1, // Skip to: 984
/* 588 */     MCD_OPC_Decode, 64, 19, // Opcode: ADDi_MM
/* 591 */     MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 603
/* 595 */     MCD_OPC_CheckPredicate, 1, 129, 1, // Skip to: 984
/* 599 */     MCD_OPC_Decode, 199, 5, 20, // Opcode: LBu_MM
/* 603 */     MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 615
/* 607 */     MCD_OPC_CheckPredicate, 1, 117, 1, // Skip to: 984
/* 611 */     MCD_OPC_Decode, 200, 8, 20, // Opcode: SB_MM
/* 615 */     MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 627
/* 619 */     MCD_OPC_CheckPredicate, 1, 105, 1, // Skip to: 984
/* 623 */     MCD_OPC_Decode, 196, 5, 20, // Opcode: LB_MM
/* 627 */     MCD_OPC_FilterValue, 12, 7, 0, // Skip to: 638
/* 631 */     MCD_OPC_CheckPredicate, 1, 93, 1, // Skip to: 984
/* 635 */     MCD_OPC_Decode, 66, 19, // Opcode: ADDiu_MM
/* 638 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 650
/* 642 */     MCD_OPC_CheckPredicate, 1, 82, 1, // Skip to: 984
/* 646 */     MCD_OPC_Decode, 224, 5, 20, // Opcode: LHu_MM
/* 650 */     MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 662
/* 654 */     MCD_OPC_CheckPredicate, 1, 70, 1, // Skip to: 984
/* 658 */     MCD_OPC_Decode, 248, 8, 20, // Opcode: SH_MM
/* 662 */     MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 674
/* 666 */     MCD_OPC_CheckPredicate, 1, 58, 1, // Skip to: 984
/* 670 */     MCD_OPC_Decode, 221, 5, 20, // Opcode: LH_MM
/* 674 */     MCD_OPC_FilterValue, 16, 87, 0, // Skip to: 765
/* 678 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 681 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 693
/* 685 */     MCD_OPC_CheckPredicate, 1, 39, 1, // Skip to: 984
/* 689 */     MCD_OPC_Decode, 196, 1, 21, // Opcode: BLTZ_MM
/* 693 */     MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 705
/* 697 */     MCD_OPC_CheckPredicate, 1, 27, 1, // Skip to: 984
/* 701 */     MCD_OPC_Decode, 195, 1, 21, // Opcode: BLTZAL_MM
/* 705 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 717
/* 709 */     MCD_OPC_CheckPredicate, 1, 15, 1, // Skip to: 984
/* 713 */     MCD_OPC_Decode, 168, 1, 21, // Opcode: BGEZ_MM
/* 717 */     MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 729
/* 721 */     MCD_OPC_CheckPredicate, 1, 3, 1, // Skip to: 984
/* 725 */     MCD_OPC_Decode, 167, 1, 21, // Opcode: BGEZAL_MM
/* 729 */     MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 741
/* 733 */     MCD_OPC_CheckPredicate, 1, 247, 0, // Skip to: 984
/* 737 */     MCD_OPC_Decode, 191, 1, 21, // Opcode: BLEZ_MM
/* 741 */     MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 753
/* 745 */     MCD_OPC_CheckPredicate, 1, 235, 0, // Skip to: 984
/* 749 */     MCD_OPC_Decode, 171, 1, 21, // Opcode: BGTZ_MM
/* 753 */     MCD_OPC_FilterValue, 13, 227, 0, // Skip to: 984
/* 757 */     MCD_OPC_CheckPredicate, 1, 223, 0, // Skip to: 984
/* 761 */     MCD_OPC_Decode, 236, 5, 22, // Opcode: LUi_MM
/* 765 */     MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 777
/* 769 */     MCD_OPC_CheckPredicate, 1, 211, 0, // Skip to: 984
/* 773 */     MCD_OPC_Decode, 228, 7, 23, // Opcode: ORi_MM
/* 777 */     MCD_OPC_FilterValue, 21, 29, 0, // Skip to: 810
/* 781 */     MCD_OPC_ExtractField, 0, 13,  // Inst{12-0} ...
/* 784 */     MCD_OPC_FilterValue, 251, 2, 8, 0, // Skip to: 797
/* 789 */     MCD_OPC_CheckPredicate, 1, 191, 0, // Skip to: 984
/* 793 */     MCD_OPC_Decode, 227, 6, 24, // Opcode: MOVF_I_MM
/* 797 */     MCD_OPC_FilterValue, 251, 18, 182, 0, // Skip to: 984
/* 802 */     MCD_OPC_CheckPredicate, 1, 178, 0, // Skip to: 984
/* 806 */     MCD_OPC_Decode, 243, 6, 24, // Opcode: MOVT_I_MM
/* 810 */     MCD_OPC_FilterValue, 24, 51, 0, // Skip to: 865
/* 814 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 817 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 829
/* 821 */     MCD_OPC_CheckPredicate, 1, 159, 0, // Skip to: 984
/* 825 */     MCD_OPC_Decode, 243, 5, 25, // Opcode: LWL_MM
/* 829 */     MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 841
/* 833 */     MCD_OPC_CheckPredicate, 1, 147, 0, // Skip to: 984
/* 837 */     MCD_OPC_Decode, 246, 5, 25, // Opcode: LWR_MM
/* 841 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 853
/* 845 */     MCD_OPC_CheckPredicate, 1, 135, 0, // Skip to: 984
/* 849 */     MCD_OPC_Decode, 137, 10, 25, // Opcode: SWL_MM
/* 853 */     MCD_OPC_FilterValue, 9, 127, 0, // Skip to: 984
/* 857 */     MCD_OPC_CheckPredicate, 1, 123, 0, // Skip to: 984
/* 861 */     MCD_OPC_Decode, 140, 10, 25, // Opcode: SWR_MM
/* 865 */     MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 877
/* 869 */     MCD_OPC_CheckPredicate, 1, 111, 0, // Skip to: 984
/* 873 */     MCD_OPC_Decode, 233, 10, 23, // Opcode: XORi_MM
/* 877 */     MCD_OPC_FilterValue, 36, 8, 0, // Skip to: 889
/* 881 */     MCD_OPC_CheckPredicate, 1, 99, 0, // Skip to: 984
/* 885 */     MCD_OPC_Decode, 148, 9, 26, // Opcode: SLTi_MM
/* 889 */     MCD_OPC_FilterValue, 37, 8, 0, // Skip to: 901
/* 893 */     MCD_OPC_CheckPredicate, 1, 87, 0, // Skip to: 984
/* 897 */     MCD_OPC_Decode, 163, 1, 27, // Opcode: BEQ_MM
/* 901 */     MCD_OPC_FilterValue, 44, 8, 0, // Skip to: 913
/* 905 */     MCD_OPC_CheckPredicate, 1, 75, 0, // Skip to: 984
/* 909 */     MCD_OPC_Decode, 151, 9, 26, // Opcode: SLTiu_MM
/* 913 */     MCD_OPC_FilterValue, 45, 8, 0, // Skip to: 925
/* 917 */     MCD_OPC_CheckPredicate, 1, 63, 0, // Skip to: 984
/* 921 */     MCD_OPC_Decode, 211, 1, 27, // Opcode: BNE_MM
/* 925 */     MCD_OPC_FilterValue, 52, 7, 0, // Skip to: 936
/* 929 */     MCD_OPC_CheckPredicate, 1, 51, 0, // Skip to: 984
/* 933 */     MCD_OPC_Decode, 81, 23, // Opcode: ANDi_MM
/* 936 */     MCD_OPC_FilterValue, 53, 8, 0, // Skip to: 948
/* 940 */     MCD_OPC_CheckPredicate, 1, 40, 0, // Skip to: 984
/* 944 */     MCD_OPC_Decode, 187, 5, 28, // Opcode: J_MM
/* 948 */     MCD_OPC_FilterValue, 61, 8, 0, // Skip to: 960
/* 952 */     MCD_OPC_CheckPredicate, 1, 28, 0, // Skip to: 984
/* 956 */     MCD_OPC_Decode, 183, 5, 28, // Opcode: JAL_MM
/* 960 */     MCD_OPC_FilterValue, 62, 8, 0, // Skip to: 972
/* 964 */     MCD_OPC_CheckPredicate, 1, 16, 0, // Skip to: 984
/* 968 */     MCD_OPC_Decode, 142, 10, 20, // Opcode: SW_MM
/* 972 */     MCD_OPC_FilterValue, 63, 8, 0, // Skip to: 984
/* 976 */     MCD_OPC_CheckPredicate, 1, 4, 0, // Skip to: 984
/* 980 */     MCD_OPC_Decode, 249, 5, 20, // Opcode: LW_MM
/* 984 */     MCD_OPC_Fail,
  0
};

static uint8_t DecoderTableMips32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 83, 3, // Skip to: 858
/* 7 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10 */      MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 28
/* 14 */      MCD_OPC_CheckPredicate, 2, 168, 49, // Skip to: 12730
/* 18 */      MCD_OPC_CheckField, 21, 5, 0, 162, 49, // Skip to: 12730
/* 24 */      MCD_OPC_Decode, 129, 9, 29, // Opcode: SLL
/* 28 */      MCD_OPC_FilterValue, 1, 39, 0, // Skip to: 71
/* 32 */      MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 35 */      MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 53
/* 39 */      MCD_OPC_CheckPredicate, 2, 143, 49, // Skip to: 12730
/* 43 */      MCD_OPC_CheckField, 6, 5, 0, 137, 49, // Skip to: 12730
/* 49 */      MCD_OPC_Decode, 225, 6, 30, // Opcode: MOVF_I
/* 53 */      MCD_OPC_FilterValue, 1, 129, 49, // Skip to: 12730
/* 57 */      MCD_OPC_CheckPredicate, 2, 125, 49, // Skip to: 12730
/* 61 */      MCD_OPC_CheckField, 6, 5, 0, 119, 49, // Skip to: 12730
/* 67 */      MCD_OPC_Decode, 241, 6, 30, // Opcode: MOVT_I
/* 71 */      MCD_OPC_FilterValue, 2, 27, 0, // Skip to: 102
/* 75 */      MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 78 */      MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 90
/* 82 */      MCD_OPC_CheckPredicate, 2, 100, 49, // Skip to: 12730
/* 86 */      MCD_OPC_Decode, 188, 9, 29, // Opcode: SRL
/* 90 */      MCD_OPC_FilterValue, 1, 92, 49, // Skip to: 12730
/* 94 */      MCD_OPC_CheckPredicate, 3, 88, 49, // Skip to: 12730
/* 98 */      MCD_OPC_Decode, 177, 8, 29, // Opcode: ROTR
/* 102 */     MCD_OPC_FilterValue, 3, 14, 0, // Skip to: 120
/* 106 */     MCD_OPC_CheckPredicate, 2, 76, 49, // Skip to: 12730
/* 110 */     MCD_OPC_CheckField, 21, 5, 0, 70, 49, // Skip to: 12730
/* 116 */     MCD_OPC_Decode, 168, 9, 29, // Opcode: SRA
/* 120 */     MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 138
/* 124 */     MCD_OPC_CheckPredicate, 2, 58, 49, // Skip to: 12730
/* 128 */     MCD_OPC_CheckField, 6, 5, 0, 52, 49, // Skip to: 12730
/* 134 */     MCD_OPC_Decode, 136, 9, 13, // Opcode: SLLV
/* 138 */     MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 156
/* 142 */     MCD_OPC_CheckPredicate, 4, 40, 49, // Skip to: 12730
/* 146 */     MCD_OPC_CheckField, 8, 3, 0, 34, 49, // Skip to: 12730
/* 152 */     MCD_OPC_Decode, 231, 5, 31, // Opcode: LSA
/* 156 */     MCD_OPC_FilterValue, 6, 27, 0, // Skip to: 187
/* 160 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 163 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 175
/* 167 */     MCD_OPC_CheckPredicate, 2, 15, 49, // Skip to: 12730
/* 171 */     MCD_OPC_Decode, 201, 9, 13, // Opcode: SRLV
/* 175 */     MCD_OPC_FilterValue, 1, 7, 49, // Skip to: 12730
/* 179 */     MCD_OPC_CheckPredicate, 3, 3, 49, // Skip to: 12730
/* 183 */     MCD_OPC_Decode, 178, 8, 13, // Opcode: ROTRV
/* 187 */     MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 205
/* 191 */     MCD_OPC_CheckPredicate, 2, 247, 48, // Skip to: 12730
/* 195 */     MCD_OPC_CheckField, 6, 5, 0, 241, 48, // Skip to: 12730
/* 201 */     MCD_OPC_Decode, 181, 9, 13, // Opcode: SRAV
/* 205 */     MCD_OPC_FilterValue, 8, 14, 0, // Skip to: 223
/* 209 */     MCD_OPC_CheckPredicate, 2, 229, 48, // Skip to: 12730
/* 213 */     MCD_OPC_CheckField, 6, 15, 0, 223, 48, // Skip to: 12730
/* 219 */     MCD_OPC_Decode, 184, 5, 32, // Opcode: JR
/* 223 */     MCD_OPC_FilterValue, 9, 20, 0, // Skip to: 247
/* 227 */     MCD_OPC_CheckPredicate, 2, 211, 48, // Skip to: 12730
/* 231 */     MCD_OPC_CheckField, 16, 5, 0, 205, 48, // Skip to: 12730
/* 237 */     MCD_OPC_CheckField, 6, 5, 0, 199, 48, // Skip to: 12730
/* 243 */     MCD_OPC_Decode, 178, 5, 33, // Opcode: JALR
/* 247 */     MCD_OPC_FilterValue, 10, 14, 0, // Skip to: 265
/* 251 */     MCD_OPC_CheckPredicate, 2, 187, 48, // Skip to: 12730
/* 255 */     MCD_OPC_CheckField, 6, 5, 0, 181, 48, // Skip to: 12730
/* 261 */     MCD_OPC_Decode, 251, 6, 34, // Opcode: MOVZ_I_I
/* 265 */     MCD_OPC_FilterValue, 11, 14, 0, // Skip to: 283
/* 269 */     MCD_OPC_CheckPredicate, 2, 169, 48, // Skip to: 12730
/* 273 */     MCD_OPC_CheckField, 6, 5, 0, 163, 48, // Skip to: 12730
/* 279 */     MCD_OPC_Decode, 235, 6, 34, // Opcode: MOVN_I_I
/* 283 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 295
/* 287 */     MCD_OPC_CheckPredicate, 2, 151, 48, // Skip to: 12730
/* 291 */     MCD_OPC_Decode, 144, 10, 35, // Opcode: SYSCALL
/* 295 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 307
/* 299 */     MCD_OPC_CheckPredicate, 2, 139, 48, // Skip to: 12730
/* 303 */     MCD_OPC_Decode, 219, 1, 36, // Opcode: BREAK
/* 307 */     MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 319
/* 311 */     MCD_OPC_CheckPredicate, 2, 127, 48, // Skip to: 12730
/* 315 */     MCD_OPC_Decode, 143, 10, 37, // Opcode: SYNC
/* 319 */     MCD_OPC_FilterValue, 16, 43, 0, // Skip to: 366
/* 323 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 326 */     MCD_OPC_FilterValue, 0, 112, 48, // Skip to: 12730
/* 330 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 333 */     MCD_OPC_FilterValue, 0, 105, 48, // Skip to: 12730
/* 337 */     MCD_OPC_ExtractField, 23, 3,  // Inst{25-23} ...
/* 340 */     MCD_OPC_FilterValue, 0, 98, 48, // Skip to: 12730
/* 344 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 358
/* 348 */     MCD_OPC_CheckField, 21, 2, 0, 4, 0, // Skip to: 358
/* 354 */     MCD_OPC_Decode, 183, 6, 38, // Opcode: MFHI
/* 358 */     MCD_OPC_CheckPredicate, 5, 80, 48, // Skip to: 12730
/* 362 */     MCD_OPC_Decode, 185, 6, 39, // Opcode: MFHI_DSP
/* 366 */     MCD_OPC_FilterValue, 17, 36, 0, // Skip to: 406
/* 370 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 373 */     MCD_OPC_FilterValue, 0, 65, 48, // Skip to: 12730
/* 377 */     MCD_OPC_ExtractField, 13, 8,  // Inst{20-13} ...
/* 380 */     MCD_OPC_FilterValue, 0, 58, 48, // Skip to: 12730
/* 384 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 398
/* 388 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 398
/* 394 */     MCD_OPC_Decode, 148, 7, 32, // Opcode: MTHI
/* 398 */     MCD_OPC_CheckPredicate, 5, 40, 48, // Skip to: 12730
/* 402 */     MCD_OPC_Decode, 150, 7, 40, // Opcode: MTHI_DSP
/* 406 */     MCD_OPC_FilterValue, 18, 43, 0, // Skip to: 453
/* 410 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 413 */     MCD_OPC_FilterValue, 0, 25, 48, // Skip to: 12730
/* 417 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 420 */     MCD_OPC_FilterValue, 0, 18, 48, // Skip to: 12730
/* 424 */     MCD_OPC_ExtractField, 23, 3,  // Inst{25-23} ...
/* 427 */     MCD_OPC_FilterValue, 0, 11, 48, // Skip to: 12730
/* 431 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 445
/* 435 */     MCD_OPC_CheckField, 21, 2, 0, 4, 0, // Skip to: 445
/* 441 */     MCD_OPC_Decode, 187, 6, 38, // Opcode: MFLO
/* 445 */     MCD_OPC_CheckPredicate, 5, 249, 47, // Skip to: 12730
/* 449 */     MCD_OPC_Decode, 189, 6, 39, // Opcode: MFLO_DSP
/* 453 */     MCD_OPC_FilterValue, 19, 36, 0, // Skip to: 493
/* 457 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 460 */     MCD_OPC_FilterValue, 0, 234, 47, // Skip to: 12730
/* 464 */     MCD_OPC_ExtractField, 13, 8,  // Inst{20-13} ...
/* 467 */     MCD_OPC_FilterValue, 0, 227, 47, // Skip to: 12730
/* 471 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 485
/* 475 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 485
/* 481 */     MCD_OPC_Decode, 153, 7, 32, // Opcode: MTLO
/* 485 */     MCD_OPC_CheckPredicate, 5, 209, 47, // Skip to: 12730
/* 489 */     MCD_OPC_Decode, 155, 7, 41, // Opcode: MTLO_DSP
/* 493 */     MCD_OPC_FilterValue, 24, 36, 0, // Skip to: 533
/* 497 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 500 */     MCD_OPC_FilterValue, 0, 194, 47, // Skip to: 12730
/* 504 */     MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 507 */     MCD_OPC_FilterValue, 0, 187, 47, // Skip to: 12730
/* 511 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 525
/* 515 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 525
/* 521 */     MCD_OPC_Decode, 170, 7, 17, // Opcode: MULT
/* 525 */     MCD_OPC_CheckPredicate, 5, 169, 47, // Skip to: 12730
/* 529 */     MCD_OPC_Decode, 172, 7, 42, // Opcode: MULT_DSP
/* 533 */     MCD_OPC_FilterValue, 25, 36, 0, // Skip to: 573
/* 537 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 540 */     MCD_OPC_FilterValue, 0, 154, 47, // Skip to: 12730
/* 544 */     MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 547 */     MCD_OPC_FilterValue, 0, 147, 47, // Skip to: 12730
/* 551 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 565
/* 555 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 565
/* 561 */     MCD_OPC_Decode, 174, 7, 17, // Opcode: MULTu
/* 565 */     MCD_OPC_CheckPredicate, 5, 129, 47, // Skip to: 12730
/* 569 */     MCD_OPC_Decode, 171, 7, 42, // Opcode: MULTU_DSP
/* 573 */     MCD_OPC_FilterValue, 26, 14, 0, // Skip to: 591
/* 577 */     MCD_OPC_CheckPredicate, 2, 117, 47, // Skip to: 12730
/* 581 */     MCD_OPC_CheckField, 6, 10, 0, 111, 47, // Skip to: 12730
/* 587 */     MCD_OPC_Decode, 207, 8, 17, // Opcode: SDIV
/* 591 */     MCD_OPC_FilterValue, 27, 14, 0, // Skip to: 609
/* 595 */     MCD_OPC_CheckPredicate, 2, 99, 47, // Skip to: 12730
/* 599 */     MCD_OPC_CheckField, 6, 10, 0, 93, 47, // Skip to: 12730
/* 605 */     MCD_OPC_Decode, 213, 10, 17, // Opcode: UDIV
/* 609 */     MCD_OPC_FilterValue, 32, 13, 0, // Skip to: 626
/* 613 */     MCD_OPC_CheckPredicate, 2, 81, 47, // Skip to: 12730
/* 617 */     MCD_OPC_CheckField, 6, 5, 0, 75, 47, // Skip to: 12730
/* 623 */     MCD_OPC_Decode, 22, 12, // Opcode: ADD
/* 626 */     MCD_OPC_FilterValue, 33, 13, 0, // Skip to: 643
/* 630 */     MCD_OPC_CheckPredicate, 2, 64, 47, // Skip to: 12730
/* 634 */     MCD_OPC_CheckField, 6, 5, 0, 58, 47, // Skip to: 12730
/* 640 */     MCD_OPC_Decode, 67, 12, // Opcode: ADDu
/* 643 */     MCD_OPC_FilterValue, 34, 14, 0, // Skip to: 661
/* 647 */     MCD_OPC_CheckPredicate, 2, 47, 47, // Skip to: 12730
/* 651 */     MCD_OPC_CheckField, 6, 5, 0, 41, 47, // Skip to: 12730
/* 657 */     MCD_OPC_Decode, 216, 9, 12, // Opcode: SUB
/* 661 */     MCD_OPC_FilterValue, 35, 14, 0, // Skip to: 679
/* 665 */     MCD_OPC_CheckPredicate, 2, 29, 47, // Skip to: 12730
/* 669 */     MCD_OPC_CheckField, 6, 5, 0, 23, 47, // Skip to: 12730
/* 675 */     MCD_OPC_Decode, 255, 9, 12, // Opcode: SUBu
/* 679 */     MCD_OPC_FilterValue, 36, 13, 0, // Skip to: 696
/* 683 */     MCD_OPC_CheckPredicate, 2, 11, 47, // Skip to: 12730
/* 687 */     MCD_OPC_CheckField, 6, 5, 0, 5, 47, // Skip to: 12730
/* 693 */     MCD_OPC_Decode, 71, 12, // Opcode: AND
/* 696 */     MCD_OPC_FilterValue, 37, 14, 0, // Skip to: 714
/* 700 */     MCD_OPC_CheckPredicate, 2, 250, 46, // Skip to: 12730
/* 704 */     MCD_OPC_CheckField, 6, 5, 0, 244, 46, // Skip to: 12730
/* 710 */     MCD_OPC_Decode, 218, 7, 12, // Opcode: OR
/* 714 */     MCD_OPC_FilterValue, 38, 14, 0, // Skip to: 732
/* 718 */     MCD_OPC_CheckPredicate, 2, 232, 46, // Skip to: 12730
/* 722 */     MCD_OPC_CheckField, 6, 5, 0, 226, 46, // Skip to: 12730
/* 728 */     MCD_OPC_Decode, 223, 10, 12, // Opcode: XOR
/* 732 */     MCD_OPC_FilterValue, 39, 14, 0, // Skip to: 750
/* 736 */     MCD_OPC_CheckPredicate, 2, 214, 46, // Skip to: 12730
/* 740 */     MCD_OPC_CheckField, 6, 5, 0, 208, 46, // Skip to: 12730
/* 746 */     MCD_OPC_Decode, 208, 7, 12, // Opcode: NOR
/* 750 */     MCD_OPC_FilterValue, 42, 14, 0, // Skip to: 768
/* 754 */     MCD_OPC_CheckPredicate, 2, 196, 46, // Skip to: 12730
/* 758 */     MCD_OPC_CheckField, 6, 5, 0, 190, 46, // Skip to: 12730
/* 764 */     MCD_OPC_Decode, 143, 9, 12, // Opcode: SLT
/* 768 */     MCD_OPC_FilterValue, 43, 14, 0, // Skip to: 786
/* 772 */     MCD_OPC_CheckPredicate, 2, 178, 46, // Skip to: 12730
/* 776 */     MCD_OPC_CheckField, 6, 5, 0, 172, 46, // Skip to: 12730
/* 782 */     MCD_OPC_Decode, 152, 9, 12, // Opcode: SLTu
/* 786 */     MCD_OPC_FilterValue, 48, 8, 0, // Skip to: 798
/* 790 */     MCD_OPC_CheckPredicate, 2, 160, 46, // Skip to: 12730
/* 794 */     MCD_OPC_Decode, 197, 10, 43, // Opcode: TGE
/* 798 */     MCD_OPC_FilterValue, 49, 8, 0, // Skip to: 810
/* 802 */     MCD_OPC_CheckPredicate, 2, 148, 46, // Skip to: 12730
/* 806 */     MCD_OPC_Decode, 200, 10, 43, // Opcode: TGEU
/* 810 */     MCD_OPC_FilterValue, 50, 8, 0, // Skip to: 822
/* 814 */     MCD_OPC_CheckPredicate, 2, 136, 46, // Skip to: 12730
/* 818 */     MCD_OPC_Decode, 201, 10, 43, // Opcode: TLT
/* 822 */     MCD_OPC_FilterValue, 51, 8, 0, // Skip to: 834
/* 826 */     MCD_OPC_CheckPredicate, 2, 124, 46, // Skip to: 12730
/* 830 */     MCD_OPC_Decode, 203, 10, 43, // Opcode: TLTU
/* 834 */     MCD_OPC_FilterValue, 52, 8, 0, // Skip to: 846
/* 838 */     MCD_OPC_CheckPredicate, 2, 112, 46, // Skip to: 12730
/* 842 */     MCD_OPC_Decode, 195, 10, 43, // Opcode: TEQ
/* 846 */     MCD_OPC_FilterValue, 54, 104, 46, // Skip to: 12730
/* 850 */     MCD_OPC_CheckPredicate, 2, 100, 46, // Skip to: 12730
/* 854 */     MCD_OPC_Decode, 204, 10, 43, // Opcode: TNE
/* 858 */     MCD_OPC_FilterValue, 1, 141, 0, // Skip to: 1003
/* 862 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 865 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 877
/* 869 */     MCD_OPC_CheckPredicate, 2, 81, 46, // Skip to: 12730
/* 873 */     MCD_OPC_Decode, 192, 1, 44, // Opcode: BLTZ
/* 877 */     MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 889
/* 881 */     MCD_OPC_CheckPredicate, 2, 69, 46, // Skip to: 12730
/* 885 */     MCD_OPC_Decode, 164, 1, 44, // Opcode: BGEZ
/* 889 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 901
/* 893 */     MCD_OPC_CheckPredicate, 2, 57, 46, // Skip to: 12730
/* 897 */     MCD_OPC_Decode, 198, 10, 45, // Opcode: TGEI
/* 901 */     MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 913
/* 905 */     MCD_OPC_CheckPredicate, 2, 45, 46, // Skip to: 12730
/* 909 */     MCD_OPC_Decode, 199, 10, 45, // Opcode: TGEIU
/* 913 */     MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 925
/* 917 */     MCD_OPC_CheckPredicate, 2, 33, 46, // Skip to: 12730
/* 921 */     MCD_OPC_Decode, 202, 10, 45, // Opcode: TLTI
/* 925 */     MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 937
/* 929 */     MCD_OPC_CheckPredicate, 2, 21, 46, // Skip to: 12730
/* 933 */     MCD_OPC_Decode, 212, 10, 45, // Opcode: TTLTIU
/* 937 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 949
/* 941 */     MCD_OPC_CheckPredicate, 2, 9, 46, // Skip to: 12730
/* 945 */     MCD_OPC_Decode, 196, 10, 45, // Opcode: TEQI
/* 949 */     MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 961
/* 953 */     MCD_OPC_CheckPredicate, 2, 253, 45, // Skip to: 12730
/* 957 */     MCD_OPC_Decode, 205, 10, 45, // Opcode: TNEI
/* 961 */     MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 973
/* 965 */     MCD_OPC_CheckPredicate, 2, 241, 45, // Skip to: 12730
/* 969 */     MCD_OPC_Decode, 194, 1, 44, // Opcode: BLTZAL
/* 973 */     MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 985
/* 977 */     MCD_OPC_CheckPredicate, 2, 229, 45, // Skip to: 12730
/* 981 */     MCD_OPC_Decode, 166, 1, 44, // Opcode: BGEZAL
/* 985 */     MCD_OPC_FilterValue, 28, 221, 45, // Skip to: 12730
/* 989 */     MCD_OPC_CheckPredicate, 5, 217, 45, // Skip to: 12730
/* 993 */     MCD_OPC_CheckField, 21, 5, 0, 211, 45, // Skip to: 12730
/* 999 */     MCD_OPC_Decode, 217, 1, 46, // Opcode: BPOSGE32
/* 1003 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 1015
/* 1007 */    MCD_OPC_CheckPredicate, 6, 199, 45, // Skip to: 12730
/* 1011 */    MCD_OPC_Decode, 176, 5, 47, // Opcode: J
/* 1015 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 1027
/* 1019 */    MCD_OPC_CheckPredicate, 2, 187, 45, // Skip to: 12730
/* 1023 */    MCD_OPC_Decode, 177, 5, 47, // Opcode: JAL
/* 1027 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 1039
/* 1031 */    MCD_OPC_CheckPredicate, 2, 175, 45, // Skip to: 12730
/* 1035 */    MCD_OPC_Decode, 161, 1, 48, // Opcode: BEQ
/* 1039 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 1051
/* 1043 */    MCD_OPC_CheckPredicate, 2, 163, 45, // Skip to: 12730
/* 1047 */    MCD_OPC_Decode, 201, 1, 48, // Opcode: BNE
/* 1051 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 1069
/* 1055 */    MCD_OPC_CheckPredicate, 2, 151, 45, // Skip to: 12730
/* 1059 */    MCD_OPC_CheckField, 16, 5, 0, 145, 45, // Skip to: 12730
/* 1065 */    MCD_OPC_Decode, 189, 1, 44, // Opcode: BLEZ
/* 1069 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 1087
/* 1073 */    MCD_OPC_CheckPredicate, 2, 133, 45, // Skip to: 12730
/* 1077 */    MCD_OPC_CheckField, 16, 5, 0, 127, 45, // Skip to: 12730
/* 1083 */    MCD_OPC_Decode, 169, 1, 44, // Opcode: BGTZ
/* 1087 */    MCD_OPC_FilterValue, 8, 7, 0, // Skip to: 1098
/* 1091 */    MCD_OPC_CheckPredicate, 2, 115, 45, // Skip to: 12730
/* 1095 */    MCD_OPC_Decode, 63, 26, // Opcode: ADDi
/* 1098 */    MCD_OPC_FilterValue, 9, 7, 0, // Skip to: 1109
/* 1102 */    MCD_OPC_CheckPredicate, 2, 104, 45, // Skip to: 12730
/* 1106 */    MCD_OPC_Decode, 65, 26, // Opcode: ADDiu
/* 1109 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 1121
/* 1113 */    MCD_OPC_CheckPredicate, 2, 93, 45, // Skip to: 12730
/* 1117 */    MCD_OPC_Decode, 146, 9, 26, // Opcode: SLTi
/* 1121 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1133
/* 1125 */    MCD_OPC_CheckPredicate, 2, 81, 45, // Skip to: 12730
/* 1129 */    MCD_OPC_Decode, 149, 9, 26, // Opcode: SLTiu
/* 1133 */    MCD_OPC_FilterValue, 12, 7, 0, // Skip to: 1144
/* 1137 */    MCD_OPC_CheckPredicate, 2, 69, 45, // Skip to: 12730
/* 1141 */    MCD_OPC_Decode, 79, 49, // Opcode: ANDi
/* 1144 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 1156
/* 1148 */    MCD_OPC_CheckPredicate, 2, 58, 45, // Skip to: 12730
/* 1152 */    MCD_OPC_Decode, 226, 7, 49, // Opcode: ORi
/* 1156 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 1168
/* 1160 */    MCD_OPC_CheckPredicate, 2, 46, 45, // Skip to: 12730
/* 1164 */    MCD_OPC_Decode, 231, 10, 49, // Opcode: XORi
/* 1168 */    MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 1186
/* 1172 */    MCD_OPC_CheckPredicate, 2, 34, 45, // Skip to: 12730
/* 1176 */    MCD_OPC_CheckField, 21, 5, 0, 28, 45, // Skip to: 12730
/* 1182 */    MCD_OPC_Decode, 234, 5, 22, // Opcode: LUi
/* 1186 */    MCD_OPC_FilterValue, 16, 117, 0, // Skip to: 1307
/* 1190 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1193 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 1211
/* 1197 */    MCD_OPC_CheckPredicate, 2, 9, 45, // Skip to: 12730
/* 1201 */    MCD_OPC_CheckField, 3, 8, 0, 3, 45, // Skip to: 12730
/* 1207 */    MCD_OPC_Decode, 179, 6, 50, // Opcode: MFC0
/* 1211 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 1229
/* 1215 */    MCD_OPC_CheckPredicate, 2, 247, 44, // Skip to: 12730
/* 1219 */    MCD_OPC_CheckField, 3, 8, 0, 241, 44, // Skip to: 12730
/* 1225 */    MCD_OPC_Decode, 144, 7, 50, // Opcode: MTC0
/* 1229 */    MCD_OPC_FilterValue, 11, 31, 0, // Skip to: 1264
/* 1233 */    MCD_OPC_ExtractField, 0, 16,  // Inst{15-0} ...
/* 1236 */    MCD_OPC_FilterValue, 128, 192, 1, 8, 0, // Skip to: 1250
/* 1242 */    MCD_OPC_CheckPredicate, 2, 220, 44, // Skip to: 12730
/* 1246 */    MCD_OPC_Decode, 156, 3, 16, // Opcode: DI
/* 1250 */    MCD_OPC_FilterValue, 160, 192, 1, 210, 44, // Skip to: 12730
/* 1256 */    MCD_OPC_CheckPredicate, 2, 206, 44, // Skip to: 12730
/* 1260 */    MCD_OPC_Decode, 230, 3, 16, // Opcode: EI
/* 1264 */    MCD_OPC_FilterValue, 16, 198, 44, // Skip to: 12730
/* 1268 */    MCD_OPC_ExtractField, 0, 21,  // Inst{20-0} ...
/* 1271 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 1283
/* 1275 */    MCD_OPC_CheckPredicate, 2, 187, 44, // Skip to: 12730
/* 1279 */    MCD_OPC_Decode, 231, 3, 2, // Opcode: ERET
/* 1283 */    MCD_OPC_FilterValue, 31, 8, 0, // Skip to: 1295
/* 1287 */    MCD_OPC_CheckPredicate, 2, 175, 44, // Skip to: 12730
/* 1291 */    MCD_OPC_Decode, 152, 3, 2, // Opcode: DERET
/* 1295 */    MCD_OPC_FilterValue, 32, 167, 44, // Skip to: 12730
/* 1299 */    MCD_OPC_CheckPredicate, 2, 163, 44, // Skip to: 12730
/* 1303 */    MCD_OPC_Decode, 219, 10, 2, // Opcode: WAIT
/* 1307 */    MCD_OPC_FilterValue, 17, 249, 5, // Skip to: 2840
/* 1311 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1314 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 1332
/* 1318 */    MCD_OPC_CheckPredicate, 2, 144, 44, // Skip to: 12730
/* 1322 */    MCD_OPC_CheckField, 0, 11, 0, 138, 44, // Skip to: 12730
/* 1328 */    MCD_OPC_Decode, 180, 6, 51, // Opcode: MFC1
/* 1332 */    MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 1350
/* 1336 */    MCD_OPC_CheckPredicate, 2, 126, 44, // Skip to: 12730
/* 1340 */    MCD_OPC_CheckField, 0, 11, 0, 120, 44, // Skip to: 12730
/* 1346 */    MCD_OPC_Decode, 169, 3, 52, // Opcode: DMFC1
/* 1350 */    MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 1368
/* 1354 */    MCD_OPC_CheckPredicate, 2, 108, 44, // Skip to: 12730
/* 1358 */    MCD_OPC_CheckField, 0, 11, 0, 102, 44, // Skip to: 12730
/* 1364 */    MCD_OPC_Decode, 147, 2, 53, // Opcode: CFC1
/* 1368 */    MCD_OPC_FilterValue, 3, 14, 0, // Skip to: 1386
/* 1372 */    MCD_OPC_CheckPredicate, 2, 90, 44, // Skip to: 12730
/* 1376 */    MCD_OPC_CheckField, 0, 11, 0, 84, 44, // Skip to: 12730
/* 1382 */    MCD_OPC_Decode, 182, 6, 54, // Opcode: MFHC1
/* 1386 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 1404
/* 1390 */    MCD_OPC_CheckPredicate, 2, 72, 44, // Skip to: 12730
/* 1394 */    MCD_OPC_CheckField, 0, 11, 0, 66, 44, // Skip to: 12730
/* 1400 */    MCD_OPC_Decode, 145, 7, 55, // Opcode: MTC1
/* 1404 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 1422
/* 1408 */    MCD_OPC_CheckPredicate, 2, 54, 44, // Skip to: 12730
/* 1412 */    MCD_OPC_CheckField, 0, 11, 0, 48, 44, // Skip to: 12730
/* 1418 */    MCD_OPC_Decode, 172, 3, 56, // Opcode: DMTC1
/* 1422 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 1440
/* 1426 */    MCD_OPC_CheckPredicate, 2, 36, 44, // Skip to: 12730
/* 1430 */    MCD_OPC_CheckField, 0, 11, 0, 30, 44, // Skip to: 12730
/* 1436 */    MCD_OPC_Decode, 206, 2, 57, // Opcode: CTC1
/* 1440 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 1458
/* 1444 */    MCD_OPC_CheckPredicate, 2, 18, 44, // Skip to: 12730
/* 1448 */    MCD_OPC_CheckField, 0, 11, 0, 12, 44, // Skip to: 12730
/* 1454 */    MCD_OPC_Decode, 147, 7, 58, // Opcode: MTHC1
/* 1458 */    MCD_OPC_FilterValue, 8, 35, 0, // Skip to: 1497
/* 1462 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 1465 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1477
/* 1469 */    MCD_OPC_CheckPredicate, 2, 16, 0, // Skip to: 1489
/* 1473 */    MCD_OPC_Decode, 151, 1, 59, // Opcode: BC1F
/* 1477 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 1489
/* 1481 */    MCD_OPC_CheckPredicate, 2, 4, 0, // Skip to: 1489
/* 1485 */    MCD_OPC_Decode, 152, 1, 59, // Opcode: BC1T
/* 1489 */    MCD_OPC_CheckPredicate, 4, 229, 43, // Skip to: 12730
/* 1493 */    MCD_OPC_Decode, 215, 1, 60, // Opcode: BNZ_V
/* 1497 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1509
/* 1501 */    MCD_OPC_CheckPredicate, 4, 217, 43, // Skip to: 12730
/* 1505 */    MCD_OPC_Decode, 238, 1, 60, // Opcode: BZ_V
/* 1509 */    MCD_OPC_FilterValue, 16, 80, 2, // Skip to: 2105
/* 1513 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1516 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1528
/* 1520 */    MCD_OPC_CheckPredicate, 2, 198, 43, // Skip to: 12730
/* 1524 */    MCD_OPC_Decode, 128, 4, 61, // Opcode: FADD_S
/* 1528 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 1540
/* 1532 */    MCD_OPC_CheckPredicate, 2, 186, 43, // Skip to: 12730
/* 1536 */    MCD_OPC_Decode, 241, 4, 61, // Opcode: FSUB_S
/* 1540 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 1552
/* 1544 */    MCD_OPC_CheckPredicate, 2, 174, 43, // Skip to: 12730
/* 1548 */    MCD_OPC_Decode, 210, 4, 61, // Opcode: FMUL_S
/* 1552 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 1564
/* 1556 */    MCD_OPC_CheckPredicate, 2, 162, 43, // Skip to: 12730
/* 1560 */    MCD_OPC_Decode, 160, 4, 61, // Opcode: FDIV_S
/* 1564 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 1582
/* 1568 */    MCD_OPC_CheckPredicate, 2, 150, 43, // Skip to: 12730
/* 1572 */    MCD_OPC_CheckField, 16, 5, 0, 144, 43, // Skip to: 12730
/* 1578 */    MCD_OPC_Decode, 236, 4, 62, // Opcode: FSQRT_S
/* 1582 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 1600
/* 1586 */    MCD_OPC_CheckPredicate, 6, 132, 43, // Skip to: 12730
/* 1590 */    MCD_OPC_CheckField, 16, 5, 0, 126, 43, // Skip to: 12730
/* 1596 */    MCD_OPC_Decode, 251, 3, 62, // Opcode: FABS_S
/* 1600 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 1618
/* 1604 */    MCD_OPC_CheckPredicate, 2, 114, 43, // Skip to: 12730
/* 1608 */    MCD_OPC_CheckField, 16, 5, 0, 108, 43, // Skip to: 12730
/* 1614 */    MCD_OPC_Decode, 204, 4, 62, // Opcode: FMOV_S
/* 1618 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 1636
/* 1622 */    MCD_OPC_CheckPredicate, 6, 96, 43, // Skip to: 12730
/* 1626 */    MCD_OPC_CheckField, 16, 5, 0, 90, 43, // Skip to: 12730
/* 1632 */    MCD_OPC_Decode, 214, 4, 62, // Opcode: FNEG_S
/* 1636 */    MCD_OPC_FilterValue, 12, 14, 0, // Skip to: 1654
/* 1640 */    MCD_OPC_CheckPredicate, 2, 78, 43, // Skip to: 12730
/* 1644 */    MCD_OPC_CheckField, 16, 5, 0, 72, 43, // Skip to: 12730
/* 1650 */    MCD_OPC_Decode, 185, 8, 62, // Opcode: ROUND_W_S
/* 1654 */    MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 1672
/* 1658 */    MCD_OPC_CheckPredicate, 2, 60, 43, // Skip to: 12730
/* 1662 */    MCD_OPC_CheckField, 16, 5, 0, 54, 43, // Skip to: 12730
/* 1668 */    MCD_OPC_Decode, 211, 10, 62, // Opcode: TRUNC_W_S
/* 1672 */    MCD_OPC_FilterValue, 14, 14, 0, // Skip to: 1690
/* 1676 */    MCD_OPC_CheckPredicate, 2, 42, 43, // Skip to: 12730
/* 1680 */    MCD_OPC_CheckField, 16, 5, 0, 36, 43, // Skip to: 12730
/* 1686 */    MCD_OPC_Decode, 138, 2, 62, // Opcode: CEIL_W_S
/* 1690 */    MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 1708
/* 1694 */    MCD_OPC_CheckPredicate, 2, 24, 43, // Skip to: 12730
/* 1698 */    MCD_OPC_CheckField, 16, 5, 0, 18, 43, // Skip to: 12730
/* 1704 */    MCD_OPC_Decode, 191, 4, 62, // Opcode: FLOOR_W_S
/* 1708 */    MCD_OPC_FilterValue, 17, 27, 0, // Skip to: 1739
/* 1712 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 1715 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1727
/* 1719 */    MCD_OPC_CheckPredicate, 2, 255, 42, // Skip to: 12730
/* 1723 */    MCD_OPC_Decode, 228, 6, 63, // Opcode: MOVF_S
/* 1727 */    MCD_OPC_FilterValue, 1, 247, 42, // Skip to: 12730
/* 1731 */    MCD_OPC_CheckPredicate, 2, 243, 42, // Skip to: 12730
/* 1735 */    MCD_OPC_Decode, 244, 6, 63, // Opcode: MOVT_S
/* 1739 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 1751
/* 1743 */    MCD_OPC_CheckPredicate, 2, 231, 42, // Skip to: 12730
/* 1747 */    MCD_OPC_Decode, 254, 6, 64, // Opcode: MOVZ_I_S
/* 1751 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 1763
/* 1755 */    MCD_OPC_CheckPredicate, 2, 219, 42, // Skip to: 12730
/* 1759 */    MCD_OPC_Decode, 238, 6, 64, // Opcode: MOVN_I_S
/* 1763 */    MCD_OPC_FilterValue, 33, 14, 0, // Skip to: 1781
/* 1767 */    MCD_OPC_CheckPredicate, 7, 207, 42, // Skip to: 12730
/* 1771 */    MCD_OPC_CheckField, 16, 5, 0, 201, 42, // Skip to: 12730
/* 1777 */    MCD_OPC_Decode, 208, 2, 65, // Opcode: CVT_D32_S
/* 1781 */    MCD_OPC_FilterValue, 36, 14, 0, // Skip to: 1799
/* 1785 */    MCD_OPC_CheckPredicate, 2, 189, 42, // Skip to: 12730
/* 1789 */    MCD_OPC_CheckField, 16, 5, 0, 183, 42, // Skip to: 12730
/* 1795 */    MCD_OPC_Decode, 221, 2, 62, // Opcode: CVT_W_S
/* 1799 */    MCD_OPC_FilterValue, 37, 14, 0, // Skip to: 1817
/* 1803 */    MCD_OPC_CheckPredicate, 2, 171, 42, // Skip to: 12730
/* 1807 */    MCD_OPC_CheckField, 16, 5, 0, 165, 42, // Skip to: 12730
/* 1813 */    MCD_OPC_Decode, 214, 2, 66, // Opcode: CVT_L_S
/* 1817 */    MCD_OPC_FilterValue, 48, 14, 0, // Skip to: 1835
/* 1821 */    MCD_OPC_CheckPredicate, 2, 153, 42, // Skip to: 12730
/* 1825 */    MCD_OPC_CheckField, 6, 5, 0, 147, 42, // Skip to: 12730
/* 1831 */    MCD_OPC_Decode, 227, 2, 67, // Opcode: C_F_S
/* 1835 */    MCD_OPC_FilterValue, 49, 14, 0, // Skip to: 1853
/* 1839 */    MCD_OPC_CheckPredicate, 2, 135, 42, // Skip to: 12730
/* 1843 */    MCD_OPC_CheckField, 6, 5, 0, 129, 42, // Skip to: 12730
/* 1849 */    MCD_OPC_Decode, 141, 3, 67, // Opcode: C_UN_S
/* 1853 */    MCD_OPC_FilterValue, 50, 14, 0, // Skip to: 1871
/* 1857 */    MCD_OPC_CheckPredicate, 2, 117, 42, // Skip to: 12730
/* 1861 */    MCD_OPC_CheckField, 6, 5, 0, 111, 42, // Skip to: 12730
/* 1867 */    MCD_OPC_Decode, 224, 2, 67, // Opcode: C_EQ_S
/* 1871 */    MCD_OPC_FilterValue, 51, 14, 0, // Skip to: 1889
/* 1875 */    MCD_OPC_CheckPredicate, 2, 99, 42, // Skip to: 12730
/* 1879 */    MCD_OPC_CheckField, 6, 5, 0, 93, 42, // Skip to: 12730
/* 1885 */    MCD_OPC_Decode, 132, 3, 67, // Opcode: C_UEQ_S
/* 1889 */    MCD_OPC_FilterValue, 52, 14, 0, // Skip to: 1907
/* 1893 */    MCD_OPC_CheckPredicate, 2, 81, 42, // Skip to: 12730
/* 1897 */    MCD_OPC_CheckField, 6, 5, 0, 75, 42, // Skip to: 12730
/* 1903 */    MCD_OPC_Decode, 251, 2, 67, // Opcode: C_OLT_S
/* 1907 */    MCD_OPC_FilterValue, 53, 14, 0, // Skip to: 1925
/* 1911 */    MCD_OPC_CheckPredicate, 2, 63, 42, // Skip to: 12730
/* 1915 */    MCD_OPC_CheckField, 6, 5, 0, 57, 42, // Skip to: 12730
/* 1921 */    MCD_OPC_Decode, 138, 3, 67, // Opcode: C_ULT_S
/* 1925 */    MCD_OPC_FilterValue, 54, 14, 0, // Skip to: 1943
/* 1929 */    MCD_OPC_CheckPredicate, 2, 45, 42, // Skip to: 12730
/* 1933 */    MCD_OPC_CheckField, 6, 5, 0, 39, 42, // Skip to: 12730
/* 1939 */    MCD_OPC_Decode, 248, 2, 67, // Opcode: C_OLE_S
/* 1943 */    MCD_OPC_FilterValue, 55, 14, 0, // Skip to: 1961
/* 1947 */    MCD_OPC_CheckPredicate, 2, 27, 42, // Skip to: 12730
/* 1951 */    MCD_OPC_CheckField, 6, 5, 0, 21, 42, // Skip to: 12730
/* 1957 */    MCD_OPC_Decode, 135, 3, 67, // Opcode: C_ULE_S
/* 1961 */    MCD_OPC_FilterValue, 56, 14, 0, // Skip to: 1979
/* 1965 */    MCD_OPC_CheckPredicate, 2, 9, 42, // Skip to: 12730
/* 1969 */    MCD_OPC_CheckField, 6, 5, 0, 3, 42, // Skip to: 12730
/* 1975 */    MCD_OPC_Decode, 129, 3, 67, // Opcode: C_SF_S
/* 1979 */    MCD_OPC_FilterValue, 57, 14, 0, // Skip to: 1997
/* 1983 */    MCD_OPC_CheckPredicate, 2, 247, 41, // Skip to: 12730
/* 1987 */    MCD_OPC_CheckField, 6, 5, 0, 241, 41, // Skip to: 12730
/* 1993 */    MCD_OPC_Decode, 239, 2, 67, // Opcode: C_NGLE_S
/* 1997 */    MCD_OPC_FilterValue, 58, 14, 0, // Skip to: 2015
/* 2001 */    MCD_OPC_CheckPredicate, 2, 229, 41, // Skip to: 12730
/* 2005 */    MCD_OPC_CheckField, 6, 5, 0, 223, 41, // Skip to: 12730
/* 2011 */    MCD_OPC_Decode, 254, 2, 67, // Opcode: C_SEQ_S
/* 2015 */    MCD_OPC_FilterValue, 59, 14, 0, // Skip to: 2033
/* 2019 */    MCD_OPC_CheckPredicate, 2, 211, 41, // Skip to: 12730
/* 2023 */    MCD_OPC_CheckField, 6, 5, 0, 205, 41, // Skip to: 12730
/* 2029 */    MCD_OPC_Decode, 242, 2, 67, // Opcode: C_NGL_S
/* 2033 */    MCD_OPC_FilterValue, 60, 14, 0, // Skip to: 2051
/* 2037 */    MCD_OPC_CheckPredicate, 2, 193, 41, // Skip to: 12730
/* 2041 */    MCD_OPC_CheckField, 6, 5, 0, 187, 41, // Skip to: 12730
/* 2047 */    MCD_OPC_Decode, 233, 2, 67, // Opcode: C_LT_S
/* 2051 */    MCD_OPC_FilterValue, 61, 14, 0, // Skip to: 2069
/* 2055 */    MCD_OPC_CheckPredicate, 2, 175, 41, // Skip to: 12730
/* 2059 */    MCD_OPC_CheckField, 6, 5, 0, 169, 41, // Skip to: 12730
/* 2065 */    MCD_OPC_Decode, 236, 2, 67, // Opcode: C_NGE_S
/* 2069 */    MCD_OPC_FilterValue, 62, 14, 0, // Skip to: 2087
/* 2073 */    MCD_OPC_CheckPredicate, 2, 157, 41, // Skip to: 12730
/* 2077 */    MCD_OPC_CheckField, 6, 5, 0, 151, 41, // Skip to: 12730
/* 2083 */    MCD_OPC_Decode, 230, 2, 67, // Opcode: C_LE_S
/* 2087 */    MCD_OPC_FilterValue, 63, 143, 41, // Skip to: 12730
/* 2091 */    MCD_OPC_CheckPredicate, 2, 139, 41, // Skip to: 12730
/* 2095 */    MCD_OPC_CheckField, 6, 5, 0, 133, 41, // Skip to: 12730
/* 2101 */    MCD_OPC_Decode, 245, 2, 67, // Opcode: C_NGT_S
/* 2105 */    MCD_OPC_FilterValue, 17, 80, 2, // Skip to: 2701
/* 2109 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 2112 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 2124
/* 2116 */    MCD_OPC_CheckPredicate, 7, 114, 41, // Skip to: 12730
/* 2120 */    MCD_OPC_Decode, 254, 3, 68, // Opcode: FADD_D32
/* 2124 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 2136
/* 2128 */    MCD_OPC_CheckPredicate, 7, 102, 41, // Skip to: 12730
/* 2132 */    MCD_OPC_Decode, 239, 4, 68, // Opcode: FSUB_D32
/* 2136 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 2148
/* 2140 */    MCD_OPC_CheckPredicate, 7, 90, 41, // Skip to: 12730
/* 2144 */    MCD_OPC_Decode, 208, 4, 68, // Opcode: FMUL_D32
/* 2148 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 2160
/* 2152 */    MCD_OPC_CheckPredicate, 7, 78, 41, // Skip to: 12730
/* 2156 */    MCD_OPC_Decode, 158, 4, 68, // Opcode: FDIV_D32
/* 2160 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 2178
/* 2164 */    MCD_OPC_CheckPredicate, 7, 66, 41, // Skip to: 12730
/* 2168 */    MCD_OPC_CheckField, 16, 5, 0, 60, 41, // Skip to: 12730
/* 2174 */    MCD_OPC_Decode, 234, 4, 69, // Opcode: FSQRT_D32
/* 2178 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 2196
/* 2182 */    MCD_OPC_CheckPredicate, 6, 48, 41, // Skip to: 12730
/* 2186 */    MCD_OPC_CheckField, 16, 5, 0, 42, 41, // Skip to: 12730
/* 2192 */    MCD_OPC_Decode, 249, 3, 69, // Opcode: FABS_D32
/* 2196 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 2214
/* 2200 */    MCD_OPC_CheckPredicate, 7, 30, 41, // Skip to: 12730
/* 2204 */    MCD_OPC_CheckField, 16, 5, 0, 24, 41, // Skip to: 12730
/* 2210 */    MCD_OPC_Decode, 202, 4, 69, // Opcode: FMOV_D32
/* 2214 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 2232
/* 2218 */    MCD_OPC_CheckPredicate, 6, 12, 41, // Skip to: 12730
/* 2222 */    MCD_OPC_CheckField, 16, 5, 0, 6, 41, // Skip to: 12730
/* 2228 */    MCD_OPC_Decode, 212, 4, 69, // Opcode: FNEG_D32
/* 2232 */    MCD_OPC_FilterValue, 12, 14, 0, // Skip to: 2250
/* 2236 */    MCD_OPC_CheckPredicate, 7, 250, 40, // Skip to: 12730
/* 2240 */    MCD_OPC_CheckField, 16, 5, 0, 244, 40, // Skip to: 12730
/* 2246 */    MCD_OPC_Decode, 183, 8, 70, // Opcode: ROUND_W_D32
/* 2250 */    MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 2268
/* 2254 */    MCD_OPC_CheckPredicate, 7, 232, 40, // Skip to: 12730
/* 2258 */    MCD_OPC_CheckField, 16, 5, 0, 226, 40, // Skip to: 12730
/* 2264 */    MCD_OPC_Decode, 209, 10, 70, // Opcode: TRUNC_W_D32
/* 2268 */    MCD_OPC_FilterValue, 14, 14, 0, // Skip to: 2286
/* 2272 */    MCD_OPC_CheckPredicate, 7, 214, 40, // Skip to: 12730
/* 2276 */    MCD_OPC_CheckField, 16, 5, 0, 208, 40, // Skip to: 12730
/* 2282 */    MCD_OPC_Decode, 136, 2, 70, // Opcode: CEIL_W_D32
/* 2286 */    MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 2304
/* 2290 */    MCD_OPC_CheckPredicate, 7, 196, 40, // Skip to: 12730
/* 2294 */    MCD_OPC_CheckField, 16, 5, 0, 190, 40, // Skip to: 12730
/* 2300 */    MCD_OPC_Decode, 189, 4, 70, // Opcode: FLOOR_W_D32
/* 2304 */    MCD_OPC_FilterValue, 17, 27, 0, // Skip to: 2335
/* 2308 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 2311 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 2323
/* 2315 */    MCD_OPC_CheckPredicate, 7, 171, 40, // Skip to: 12730
/* 2319 */    MCD_OPC_Decode, 223, 6, 71, // Opcode: MOVF_D32
/* 2323 */    MCD_OPC_FilterValue, 1, 163, 40, // Skip to: 12730
/* 2327 */    MCD_OPC_CheckPredicate, 7, 159, 40, // Skip to: 12730
/* 2331 */    MCD_OPC_Decode, 239, 6, 71, // Opcode: MOVT_D32
/* 2335 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 2347
/* 2339 */    MCD_OPC_CheckPredicate, 7, 147, 40, // Skip to: 12730
/* 2343 */    MCD_OPC_Decode, 249, 6, 72, // Opcode: MOVZ_I_D32
/* 2347 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 2359
/* 2351 */    MCD_OPC_CheckPredicate, 7, 135, 40, // Skip to: 12730
/* 2355 */    MCD_OPC_Decode, 233, 6, 72, // Opcode: MOVN_I_D32
/* 2359 */    MCD_OPC_FilterValue, 32, 14, 0, // Skip to: 2377
/* 2363 */    MCD_OPC_CheckPredicate, 7, 123, 40, // Skip to: 12730
/* 2367 */    MCD_OPC_CheckField, 16, 5, 0, 117, 40, // Skip to: 12730
/* 2373 */    MCD_OPC_Decode, 215, 2, 70, // Opcode: CVT_S_D32
/* 2377 */    MCD_OPC_FilterValue, 36, 14, 0, // Skip to: 2395
/* 2381 */    MCD_OPC_CheckPredicate, 7, 105, 40, // Skip to: 12730
/* 2385 */    MCD_OPC_CheckField, 16, 5, 0, 99, 40, // Skip to: 12730
/* 2391 */    MCD_OPC_Decode, 219, 2, 70, // Opcode: CVT_W_D32
/* 2395 */    MCD_OPC_FilterValue, 37, 14, 0, // Skip to: 2413
/* 2399 */    MCD_OPC_CheckPredicate, 2, 87, 40, // Skip to: 12730
/* 2403 */    MCD_OPC_CheckField, 16, 5, 0, 81, 40, // Skip to: 12730
/* 2409 */    MCD_OPC_Decode, 213, 2, 73, // Opcode: CVT_L_D64
/* 2413 */    MCD_OPC_FilterValue, 48, 14, 0, // Skip to: 2431
/* 2417 */    MCD_OPC_CheckPredicate, 7, 69, 40, // Skip to: 12730
/* 2421 */    MCD_OPC_CheckField, 6, 5, 0, 63, 40, // Skip to: 12730
/* 2427 */    MCD_OPC_Decode, 225, 2, 74, // Opcode: C_F_D32
/* 2431 */    MCD_OPC_FilterValue, 49, 14, 0, // Skip to: 2449
/* 2435 */    MCD_OPC_CheckPredicate, 7, 51, 40, // Skip to: 12730
/* 2439 */    MCD_OPC_CheckField, 6, 5, 0, 45, 40, // Skip to: 12730
/* 2445 */    MCD_OPC_Decode, 139, 3, 74, // Opcode: C_UN_D32
/* 2449 */    MCD_OPC_FilterValue, 50, 14, 0, // Skip to: 2467
/* 2453 */    MCD_OPC_CheckPredicate, 7, 33, 40, // Skip to: 12730
/* 2457 */    MCD_OPC_CheckField, 6, 5, 0, 27, 40, // Skip to: 12730
/* 2463 */    MCD_OPC_Decode, 222, 2, 74, // Opcode: C_EQ_D32
/* 2467 */    MCD_OPC_FilterValue, 51, 14, 0, // Skip to: 2485
/* 2471 */    MCD_OPC_CheckPredicate, 7, 15, 40, // Skip to: 12730
/* 2475 */    MCD_OPC_CheckField, 6, 5, 0, 9, 40, // Skip to: 12730
/* 2481 */    MCD_OPC_Decode, 130, 3, 74, // Opcode: C_UEQ_D32
/* 2485 */    MCD_OPC_FilterValue, 52, 14, 0, // Skip to: 2503
/* 2489 */    MCD_OPC_CheckPredicate, 7, 253, 39, // Skip to: 12730
/* 2493 */    MCD_OPC_CheckField, 6, 5, 0, 247, 39, // Skip to: 12730
/* 2499 */    MCD_OPC_Decode, 249, 2, 74, // Opcode: C_OLT_D32
/* 2503 */    MCD_OPC_FilterValue, 53, 14, 0, // Skip to: 2521
/* 2507 */    MCD_OPC_CheckPredicate, 7, 235, 39, // Skip to: 12730
/* 2511 */    MCD_OPC_CheckField, 6, 5, 0, 229, 39, // Skip to: 12730
/* 2517 */    MCD_OPC_Decode, 136, 3, 74, // Opcode: C_ULT_D32
/* 2521 */    MCD_OPC_FilterValue, 54, 14, 0, // Skip to: 2539
/* 2525 */    MCD_OPC_CheckPredicate, 7, 217, 39, // Skip to: 12730
/* 2529 */    MCD_OPC_CheckField, 6, 5, 0, 211, 39, // Skip to: 12730
/* 2535 */    MCD_OPC_Decode, 246, 2, 74, // Opcode: C_OLE_D32
/* 2539 */    MCD_OPC_FilterValue, 55, 14, 0, // Skip to: 2557
/* 2543 */    MCD_OPC_CheckPredicate, 7, 199, 39, // Skip to: 12730
/* 2547 */    MCD_OPC_CheckField, 6, 5, 0, 193, 39, // Skip to: 12730
/* 2553 */    MCD_OPC_Decode, 133, 3, 74, // Opcode: C_ULE_D32
/* 2557 */    MCD_OPC_FilterValue, 56, 14, 0, // Skip to: 2575
/* 2561 */    MCD_OPC_CheckPredicate, 7, 181, 39, // Skip to: 12730
/* 2565 */    MCD_OPC_CheckField, 6, 5, 0, 175, 39, // Skip to: 12730
/* 2571 */    MCD_OPC_Decode, 255, 2, 74, // Opcode: C_SF_D32
/* 2575 */    MCD_OPC_FilterValue, 57, 14, 0, // Skip to: 2593
/* 2579 */    MCD_OPC_CheckPredicate, 7, 163, 39, // Skip to: 12730
/* 2583 */    MCD_OPC_CheckField, 6, 5, 0, 157, 39, // Skip to: 12730
/* 2589 */    MCD_OPC_Decode, 237, 2, 74, // Opcode: C_NGLE_D32
/* 2593 */    MCD_OPC_FilterValue, 58, 14, 0, // Skip to: 2611
/* 2597 */    MCD_OPC_CheckPredicate, 7, 145, 39, // Skip to: 12730
/* 2601 */    MCD_OPC_CheckField, 6, 5, 0, 139, 39, // Skip to: 12730
/* 2607 */    MCD_OPC_Decode, 252, 2, 74, // Opcode: C_SEQ_D32
/* 2611 */    MCD_OPC_FilterValue, 59, 14, 0, // Skip to: 2629
/* 2615 */    MCD_OPC_CheckPredicate, 7, 127, 39, // Skip to: 12730
/* 2619 */    MCD_OPC_CheckField, 6, 5, 0, 121, 39, // Skip to: 12730
/* 2625 */    MCD_OPC_Decode, 240, 2, 74, // Opcode: C_NGL_D32
/* 2629 */    MCD_OPC_FilterValue, 60, 14, 0, // Skip to: 2647
/* 2633 */    MCD_OPC_CheckPredicate, 7, 109, 39, // Skip to: 12730
/* 2637 */    MCD_OPC_CheckField, 6, 5, 0, 103, 39, // Skip to: 12730
/* 2643 */    MCD_OPC_Decode, 231, 2, 74, // Opcode: C_LT_D32
/* 2647 */    MCD_OPC_FilterValue, 61, 14, 0, // Skip to: 2665
/* 2651 */    MCD_OPC_CheckPredicate, 7, 91, 39, // Skip to: 12730
/* 2655 */    MCD_OPC_CheckField, 6, 5, 0, 85, 39, // Skip to: 12730
/* 2661 */    MCD_OPC_Decode, 234, 2, 74, // Opcode: C_NGE_D32
/* 2665 */    MCD_OPC_FilterValue, 62, 14, 0, // Skip to: 2683
/* 2669 */    MCD_OPC_CheckPredicate, 7, 73, 39, // Skip to: 12730
/* 2673 */    MCD_OPC_CheckField, 6, 5, 0, 67, 39, // Skip to: 12730
/* 2679 */    MCD_OPC_Decode, 228, 2, 74, // Opcode: C_LE_D32
/* 2683 */    MCD_OPC_FilterValue, 63, 59, 39, // Skip to: 12730
/* 2687 */    MCD_OPC_CheckPredicate, 7, 55, 39, // Skip to: 12730
/* 2691 */    MCD_OPC_CheckField, 6, 5, 0, 49, 39, // Skip to: 12730
/* 2697 */    MCD_OPC_Decode, 243, 2, 74, // Opcode: C_NGT_D32
/* 2701 */    MCD_OPC_FilterValue, 20, 39, 0, // Skip to: 2744
/* 2705 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 2708 */    MCD_OPC_FilterValue, 32, 14, 0, // Skip to: 2726
/* 2712 */    MCD_OPC_CheckPredicate, 2, 30, 39, // Skip to: 12730
/* 2716 */    MCD_OPC_CheckField, 16, 5, 0, 24, 39, // Skip to: 12730
/* 2722 */    MCD_OPC_Decode, 218, 2, 62, // Opcode: CVT_S_W
/* 2726 */    MCD_OPC_FilterValue, 33, 16, 39, // Skip to: 12730
/* 2730 */    MCD_OPC_CheckPredicate, 7, 12, 39, // Skip to: 12730
/* 2734 */    MCD_OPC_CheckField, 16, 5, 0, 6, 39, // Skip to: 12730
/* 2740 */    MCD_OPC_Decode, 209, 2, 65, // Opcode: CVT_D32_W
/* 2744 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 2756
/* 2748 */    MCD_OPC_CheckPredicate, 4, 250, 38, // Skip to: 12730
/* 2752 */    MCD_OPC_Decode, 235, 1, 60, // Opcode: BZ_B
/* 2756 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 2768
/* 2760 */    MCD_OPC_CheckPredicate, 4, 238, 38, // Skip to: 12730
/* 2764 */    MCD_OPC_Decode, 237, 1, 75, // Opcode: BZ_H
/* 2768 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 2780
/* 2772 */    MCD_OPC_CheckPredicate, 4, 226, 38, // Skip to: 12730
/* 2776 */    MCD_OPC_Decode, 239, 1, 76, // Opcode: BZ_W
/* 2780 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 2792
/* 2784 */    MCD_OPC_CheckPredicate, 4, 214, 38, // Skip to: 12730
/* 2788 */    MCD_OPC_Decode, 236, 1, 77, // Opcode: BZ_D
/* 2792 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 2804
/* 2796 */    MCD_OPC_CheckPredicate, 4, 202, 38, // Skip to: 12730
/* 2800 */    MCD_OPC_Decode, 212, 1, 60, // Opcode: BNZ_B
/* 2804 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 2816
/* 2808 */    MCD_OPC_CheckPredicate, 4, 190, 38, // Skip to: 12730
/* 2812 */    MCD_OPC_Decode, 214, 1, 75, // Opcode: BNZ_H
/* 2816 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 2828
/* 2820 */    MCD_OPC_CheckPredicate, 4, 178, 38, // Skip to: 12730
/* 2824 */    MCD_OPC_Decode, 216, 1, 76, // Opcode: BNZ_W
/* 2828 */    MCD_OPC_FilterValue, 31, 170, 38, // Skip to: 12730
/* 2832 */    MCD_OPC_CheckPredicate, 4, 166, 38, // Skip to: 12730
/* 2836 */    MCD_OPC_Decode, 213, 1, 77, // Opcode: BNZ_D
/* 2840 */    MCD_OPC_FilterValue, 18, 39, 0, // Skip to: 2883
/* 2844 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 2847 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 2865
/* 2851 */    MCD_OPC_CheckPredicate, 2, 147, 38, // Skip to: 12730
/* 2855 */    MCD_OPC_CheckField, 3, 8, 0, 141, 38, // Skip to: 12730
/* 2861 */    MCD_OPC_Decode, 181, 6, 50, // Opcode: MFC2
/* 2865 */    MCD_OPC_FilterValue, 4, 133, 38, // Skip to: 12730
/* 2869 */    MCD_OPC_CheckPredicate, 2, 129, 38, // Skip to: 12730
/* 2873 */    MCD_OPC_CheckField, 3, 8, 0, 123, 38, // Skip to: 12730
/* 2879 */    MCD_OPC_Decode, 146, 7, 50, // Opcode: MTC2
/* 2883 */    MCD_OPC_FilterValue, 19, 207, 0, // Skip to: 3094
/* 2887 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 2890 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 2908
/* 2894 */    MCD_OPC_CheckPredicate, 8, 104, 38, // Skip to: 12730
/* 2898 */    MCD_OPC_CheckField, 11, 5, 0, 98, 38, // Skip to: 12730
/* 2904 */    MCD_OPC_Decode, 248, 5, 78, // Opcode: LWXC1
/* 2908 */    MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 2926
/* 2912 */    MCD_OPC_CheckPredicate, 9, 86, 38, // Skip to: 12730
/* 2916 */    MCD_OPC_CheckField, 11, 5, 0, 80, 38, // Skip to: 12730
/* 2922 */    MCD_OPC_Decode, 210, 5, 79, // Opcode: LDXC1
/* 2926 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 2944
/* 2930 */    MCD_OPC_CheckPredicate, 7, 68, 38, // Skip to: 12730
/* 2934 */    MCD_OPC_CheckField, 11, 5, 0, 62, 38, // Skip to: 12730
/* 2940 */    MCD_OPC_Decode, 232, 5, 79, // Opcode: LUXC1
/* 2944 */    MCD_OPC_FilterValue, 8, 14, 0, // Skip to: 2962
/* 2948 */    MCD_OPC_CheckPredicate, 8, 50, 38, // Skip to: 12730
/* 2952 */    MCD_OPC_CheckField, 6, 5, 0, 44, 38, // Skip to: 12730
/* 2958 */    MCD_OPC_Decode, 141, 10, 80, // Opcode: SWXC1
/* 2962 */    MCD_OPC_FilterValue, 9, 14, 0, // Skip to: 2980
/* 2966 */    MCD_OPC_CheckPredicate, 9, 32, 38, // Skip to: 12730
/* 2970 */    MCD_OPC_CheckField, 6, 5, 0, 26, 38, // Skip to: 12730
/* 2976 */    MCD_OPC_Decode, 211, 8, 81, // Opcode: SDXC1
/* 2980 */    MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 2998
/* 2984 */    MCD_OPC_CheckPredicate, 7, 14, 38, // Skip to: 12730
/* 2988 */    MCD_OPC_CheckField, 6, 5, 0, 8, 38, // Skip to: 12730
/* 2994 */    MCD_OPC_Decode, 129, 10, 81, // Opcode: SUXC1
/* 2998 */    MCD_OPC_FilterValue, 32, 8, 0, // Skip to: 3010
/* 3002 */    MCD_OPC_CheckPredicate, 3, 252, 37, // Skip to: 12730
/* 3006 */    MCD_OPC_Decode, 154, 6, 82, // Opcode: MADD_S
/* 3010 */    MCD_OPC_FilterValue, 33, 8, 0, // Skip to: 3022
/* 3014 */    MCD_OPC_CheckPredicate, 10, 240, 37, // Skip to: 12730
/* 3018 */    MCD_OPC_Decode, 148, 6, 83, // Opcode: MADD_D32
/* 3022 */    MCD_OPC_FilterValue, 40, 8, 0, // Skip to: 3034
/* 3026 */    MCD_OPC_CheckPredicate, 3, 228, 37, // Skip to: 12730
/* 3030 */    MCD_OPC_Decode, 143, 7, 82, // Opcode: MSUB_S
/* 3034 */    MCD_OPC_FilterValue, 41, 8, 0, // Skip to: 3046
/* 3038 */    MCD_OPC_CheckPredicate, 10, 216, 37, // Skip to: 12730
/* 3042 */    MCD_OPC_Decode, 137, 7, 83, // Opcode: MSUB_D32
/* 3046 */    MCD_OPC_FilterValue, 48, 8, 0, // Skip to: 3058
/* 3050 */    MCD_OPC_CheckPredicate, 11, 204, 37, // Skip to: 12730
/* 3054 */    MCD_OPC_Decode, 203, 7, 82, // Opcode: NMADD_S
/* 3058 */    MCD_OPC_FilterValue, 49, 8, 0, // Skip to: 3070
/* 3062 */    MCD_OPC_CheckPredicate, 12, 192, 37, // Skip to: 12730
/* 3066 */    MCD_OPC_Decode, 201, 7, 83, // Opcode: NMADD_D32
/* 3070 */    MCD_OPC_FilterValue, 56, 8, 0, // Skip to: 3082
/* 3074 */    MCD_OPC_CheckPredicate, 11, 180, 37, // Skip to: 12730
/* 3078 */    MCD_OPC_Decode, 206, 7, 82, // Opcode: NMSUB_S
/* 3082 */    MCD_OPC_FilterValue, 57, 172, 37, // Skip to: 12730
/* 3086 */    MCD_OPC_CheckPredicate, 12, 168, 37, // Skip to: 12730
/* 3090 */    MCD_OPC_Decode, 204, 7, 83, // Opcode: NMSUB_D32
/* 3094 */    MCD_OPC_FilterValue, 28, 171, 0, // Skip to: 3269
/* 3098 */    MCD_OPC_ExtractField, 0, 11,  // Inst{10-0} ...
/* 3101 */    MCD_OPC_FilterValue, 0, 29, 0, // Skip to: 3134
/* 3105 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3108 */    MCD_OPC_FilterValue, 0, 146, 37, // Skip to: 12730
/* 3112 */    MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 3126
/* 3116 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3126
/* 3122 */    MCD_OPC_Decode, 138, 6, 17, // Opcode: MADD
/* 3126 */    MCD_OPC_CheckPredicate, 5, 128, 37, // Skip to: 12730
/* 3130 */    MCD_OPC_Decode, 150, 6, 84, // Opcode: MADD_DSP
/* 3134 */    MCD_OPC_FilterValue, 1, 29, 0, // Skip to: 3167
/* 3138 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3141 */    MCD_OPC_FilterValue, 0, 113, 37, // Skip to: 12730
/* 3145 */    MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 3159
/* 3149 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3159
/* 3155 */    MCD_OPC_Decode, 141, 6, 17, // Opcode: MADDU
/* 3159 */    MCD_OPC_CheckPredicate, 5, 95, 37, // Skip to: 12730
/* 3163 */    MCD_OPC_Decode, 142, 6, 84, // Opcode: MADDU_DSP
/* 3167 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 3179
/* 3171 */    MCD_OPC_CheckPredicate, 2, 83, 37, // Skip to: 12730
/* 3175 */    MCD_OPC_Decode, 157, 7, 12, // Opcode: MUL
/* 3179 */    MCD_OPC_FilterValue, 4, 29, 0, // Skip to: 3212
/* 3183 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3186 */    MCD_OPC_FilterValue, 0, 68, 37, // Skip to: 12730
/* 3190 */    MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 3204
/* 3194 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3204
/* 3200 */    MCD_OPC_Decode, 255, 6, 17, // Opcode: MSUB
/* 3204 */    MCD_OPC_CheckPredicate, 5, 50, 37, // Skip to: 12730
/* 3208 */    MCD_OPC_Decode, 139, 7, 84, // Opcode: MSUB_DSP
/* 3212 */    MCD_OPC_FilterValue, 5, 29, 0, // Skip to: 3245
/* 3216 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3219 */    MCD_OPC_FilterValue, 0, 35, 37, // Skip to: 12730
/* 3223 */    MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 3237
/* 3227 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3237
/* 3233 */    MCD_OPC_Decode, 130, 7, 17, // Opcode: MSUBU
/* 3237 */    MCD_OPC_CheckPredicate, 5, 17, 37, // Skip to: 12730
/* 3241 */    MCD_OPC_Decode, 131, 7, 84, // Opcode: MSUBU_DSP
/* 3245 */    MCD_OPC_FilterValue, 32, 8, 0, // Skip to: 3257
/* 3249 */    MCD_OPC_CheckPredicate, 13, 5, 37, // Skip to: 12730
/* 3253 */    MCD_OPC_Decode, 183, 2, 85, // Opcode: CLZ
/* 3257 */    MCD_OPC_FilterValue, 33, 253, 36, // Skip to: 12730
/* 3261 */    MCD_OPC_CheckPredicate, 13, 249, 36, // Skip to: 12730
/* 3265 */    MCD_OPC_Decode, 165, 2, 85, // Opcode: CLO
/* 3269 */    MCD_OPC_FilterValue, 30, 94, 26, // Skip to: 10023
/* 3273 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 3276 */    MCD_OPC_FilterValue, 0, 50, 0, // Skip to: 3330
/* 3280 */    MCD_OPC_ExtractField, 24, 2,  // Inst{25-24} ...
/* 3283 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 3294
/* 3287 */    MCD_OPC_CheckPredicate, 4, 223, 36, // Skip to: 12730
/* 3291 */    MCD_OPC_Decode, 73, 86, // Opcode: ANDI_B
/* 3294 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3306
/* 3298 */    MCD_OPC_CheckPredicate, 4, 212, 36, // Skip to: 12730
/* 3302 */    MCD_OPC_Decode, 220, 7, 86, // Opcode: ORI_B
/* 3306 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 3318
/* 3310 */    MCD_OPC_CheckPredicate, 4, 200, 36, // Skip to: 12730
/* 3314 */    MCD_OPC_Decode, 210, 7, 86, // Opcode: NORI_B
/* 3318 */    MCD_OPC_FilterValue, 3, 192, 36, // Skip to: 12730
/* 3322 */    MCD_OPC_CheckPredicate, 4, 188, 36, // Skip to: 12730
/* 3326 */    MCD_OPC_Decode, 225, 10, 86, // Opcode: XORI_B
/* 3330 */    MCD_OPC_FilterValue, 1, 39, 0, // Skip to: 3373
/* 3334 */    MCD_OPC_ExtractField, 24, 2,  // Inst{25-24} ...
/* 3337 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3349
/* 3341 */    MCD_OPC_CheckPredicate, 4, 169, 36, // Skip to: 12730
/* 3345 */    MCD_OPC_Decode, 197, 1, 87, // Opcode: BMNZI_B
/* 3349 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3361
/* 3353 */    MCD_OPC_CheckPredicate, 4, 157, 36, // Skip to: 12730
/* 3357 */    MCD_OPC_Decode, 199, 1, 87, // Opcode: BMZI_B
/* 3361 */    MCD_OPC_FilterValue, 2, 149, 36, // Skip to: 12730
/* 3365 */    MCD_OPC_CheckPredicate, 4, 145, 36, // Skip to: 12730
/* 3369 */    MCD_OPC_Decode, 220, 1, 87, // Opcode: BSELI_B
/* 3373 */    MCD_OPC_FilterValue, 2, 39, 0, // Skip to: 3416
/* 3377 */    MCD_OPC_ExtractField, 24, 2,  // Inst{25-24} ...
/* 3380 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3392
/* 3384 */    MCD_OPC_CheckPredicate, 4, 126, 36, // Skip to: 12730
/* 3388 */    MCD_OPC_Decode, 221, 8, 86, // Opcode: SHF_B
/* 3392 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3404
/* 3396 */    MCD_OPC_CheckPredicate, 4, 114, 36, // Skip to: 12730
/* 3400 */    MCD_OPC_Decode, 222, 8, 88, // Opcode: SHF_H
/* 3404 */    MCD_OPC_FilterValue, 2, 106, 36, // Skip to: 12730
/* 3408 */    MCD_OPC_CheckPredicate, 4, 102, 36, // Skip to: 12730
/* 3412 */    MCD_OPC_Decode, 223, 8, 89, // Opcode: SHF_W
/* 3416 */    MCD_OPC_FilterValue, 6, 31, 1, // Skip to: 3707
/* 3420 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 3423 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 3434
/* 3427 */    MCD_OPC_CheckPredicate, 4, 83, 36, // Skip to: 12730
/* 3431 */    MCD_OPC_Decode, 49, 90, // Opcode: ADDVI_B
/* 3434 */    MCD_OPC_FilterValue, 1, 7, 0, // Skip to: 3445
/* 3438 */    MCD_OPC_CheckPredicate, 4, 72, 36, // Skip to: 12730
/* 3442 */    MCD_OPC_Decode, 51, 91, // Opcode: ADDVI_H
/* 3445 */    MCD_OPC_FilterValue, 2, 7, 0, // Skip to: 3456
/* 3449 */    MCD_OPC_CheckPredicate, 4, 61, 36, // Skip to: 12730
/* 3453 */    MCD_OPC_Decode, 52, 92, // Opcode: ADDVI_W
/* 3456 */    MCD_OPC_FilterValue, 3, 7, 0, // Skip to: 3467
/* 3460 */    MCD_OPC_CheckPredicate, 4, 50, 36, // Skip to: 12730
/* 3464 */    MCD_OPC_Decode, 50, 93, // Opcode: ADDVI_D
/* 3467 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 3479
/* 3471 */    MCD_OPC_CheckPredicate, 4, 39, 36, // Skip to: 12730
/* 3475 */    MCD_OPC_Decode, 246, 9, 90, // Opcode: SUBVI_B
/* 3479 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 3491
/* 3483 */    MCD_OPC_CheckPredicate, 4, 27, 36, // Skip to: 12730
/* 3487 */    MCD_OPC_Decode, 248, 9, 91, // Opcode: SUBVI_H
/* 3491 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 3503
/* 3495 */    MCD_OPC_CheckPredicate, 4, 15, 36, // Skip to: 12730
/* 3499 */    MCD_OPC_Decode, 249, 9, 92, // Opcode: SUBVI_W
/* 3503 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 3515
/* 3507 */    MCD_OPC_CheckPredicate, 4, 3, 36, // Skip to: 12730
/* 3511 */    MCD_OPC_Decode, 247, 9, 93, // Opcode: SUBVI_D
/* 3515 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 3527
/* 3519 */    MCD_OPC_CheckPredicate, 4, 247, 35, // Skip to: 12730
/* 3523 */    MCD_OPC_Decode, 159, 6, 90, // Opcode: MAXI_S_B
/* 3527 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 3539
/* 3531 */    MCD_OPC_CheckPredicate, 4, 235, 35, // Skip to: 12730
/* 3535 */    MCD_OPC_Decode, 161, 6, 91, // Opcode: MAXI_S_H
/* 3539 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 3551
/* 3543 */    MCD_OPC_CheckPredicate, 4, 223, 35, // Skip to: 12730
/* 3547 */    MCD_OPC_Decode, 162, 6, 92, // Opcode: MAXI_S_W
/* 3551 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 3563
/* 3555 */    MCD_OPC_CheckPredicate, 4, 211, 35, // Skip to: 12730
/* 3559 */    MCD_OPC_Decode, 160, 6, 93, // Opcode: MAXI_S_D
/* 3563 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 3575
/* 3567 */    MCD_OPC_CheckPredicate, 4, 199, 35, // Skip to: 12730
/* 3571 */    MCD_OPC_Decode, 163, 6, 90, // Opcode: MAXI_U_B
/* 3575 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 3587
/* 3579 */    MCD_OPC_CheckPredicate, 4, 187, 35, // Skip to: 12730
/* 3583 */    MCD_OPC_Decode, 165, 6, 91, // Opcode: MAXI_U_H
/* 3587 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 3599
/* 3591 */    MCD_OPC_CheckPredicate, 4, 175, 35, // Skip to: 12730
/* 3595 */    MCD_OPC_Decode, 166, 6, 92, // Opcode: MAXI_U_W
/* 3599 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 3611
/* 3603 */    MCD_OPC_CheckPredicate, 4, 163, 35, // Skip to: 12730
/* 3607 */    MCD_OPC_Decode, 164, 6, 93, // Opcode: MAXI_U_D
/* 3611 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 3623
/* 3615 */    MCD_OPC_CheckPredicate, 4, 151, 35, // Skip to: 12730
/* 3619 */    MCD_OPC_Decode, 191, 6, 90, // Opcode: MINI_S_B
/* 3623 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 3635
/* 3627 */    MCD_OPC_CheckPredicate, 4, 139, 35, // Skip to: 12730
/* 3631 */    MCD_OPC_Decode, 193, 6, 91, // Opcode: MINI_S_H
/* 3635 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 3647
/* 3639 */    MCD_OPC_CheckPredicate, 4, 127, 35, // Skip to: 12730
/* 3643 */    MCD_OPC_Decode, 194, 6, 92, // Opcode: MINI_S_W
/* 3647 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 3659
/* 3651 */    MCD_OPC_CheckPredicate, 4, 115, 35, // Skip to: 12730
/* 3655 */    MCD_OPC_Decode, 192, 6, 93, // Opcode: MINI_S_D
/* 3659 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 3671
/* 3663 */    MCD_OPC_CheckPredicate, 4, 103, 35, // Skip to: 12730
/* 3667 */    MCD_OPC_Decode, 195, 6, 90, // Opcode: MINI_U_B
/* 3671 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 3683
/* 3675 */    MCD_OPC_CheckPredicate, 4, 91, 35, // Skip to: 12730
/* 3679 */    MCD_OPC_Decode, 197, 6, 91, // Opcode: MINI_U_H
/* 3683 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 3695
/* 3687 */    MCD_OPC_CheckPredicate, 4, 79, 35, // Skip to: 12730
/* 3691 */    MCD_OPC_Decode, 198, 6, 92, // Opcode: MINI_U_W
/* 3695 */    MCD_OPC_FilterValue, 23, 71, 35, // Skip to: 12730
/* 3699 */    MCD_OPC_CheckPredicate, 4, 67, 35, // Skip to: 12730
/* 3703 */    MCD_OPC_Decode, 196, 6, 93, // Opcode: MINI_U_D
/* 3707 */    MCD_OPC_FilterValue, 7, 243, 0, // Skip to: 3954
/* 3711 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 3714 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3726
/* 3718 */    MCD_OPC_CheckPredicate, 4, 48, 35, // Skip to: 12730
/* 3722 */    MCD_OPC_Decode, 139, 2, 90, // Opcode: CEQI_B
/* 3726 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3738
/* 3730 */    MCD_OPC_CheckPredicate, 4, 36, 35, // Skip to: 12730
/* 3734 */    MCD_OPC_Decode, 141, 2, 91, // Opcode: CEQI_H
/* 3738 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 3750
/* 3742 */    MCD_OPC_CheckPredicate, 4, 24, 35, // Skip to: 12730
/* 3746 */    MCD_OPC_Decode, 142, 2, 92, // Opcode: CEQI_W
/* 3750 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 3762
/* 3754 */    MCD_OPC_CheckPredicate, 4, 12, 35, // Skip to: 12730
/* 3758 */    MCD_OPC_Decode, 140, 2, 93, // Opcode: CEQI_D
/* 3762 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 3774
/* 3766 */    MCD_OPC_CheckPredicate, 4, 0, 35, // Skip to: 12730
/* 3770 */    MCD_OPC_Decode, 167, 2, 90, // Opcode: CLTI_S_B
/* 3774 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 3786
/* 3778 */    MCD_OPC_CheckPredicate, 4, 244, 34, // Skip to: 12730
/* 3782 */    MCD_OPC_Decode, 169, 2, 91, // Opcode: CLTI_S_H
/* 3786 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 3798
/* 3790 */    MCD_OPC_CheckPredicate, 4, 232, 34, // Skip to: 12730
/* 3794 */    MCD_OPC_Decode, 170, 2, 92, // Opcode: CLTI_S_W
/* 3798 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 3810
/* 3802 */    MCD_OPC_CheckPredicate, 4, 220, 34, // Skip to: 12730
/* 3806 */    MCD_OPC_Decode, 168, 2, 93, // Opcode: CLTI_S_D
/* 3810 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 3822
/* 3814 */    MCD_OPC_CheckPredicate, 4, 208, 34, // Skip to: 12730
/* 3818 */    MCD_OPC_Decode, 171, 2, 90, // Opcode: CLTI_U_B
/* 3822 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 3834
/* 3826 */    MCD_OPC_CheckPredicate, 4, 196, 34, // Skip to: 12730
/* 3830 */    MCD_OPC_Decode, 173, 2, 91, // Opcode: CLTI_U_H
/* 3834 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 3846
/* 3838 */    MCD_OPC_CheckPredicate, 4, 184, 34, // Skip to: 12730
/* 3842 */    MCD_OPC_Decode, 174, 2, 92, // Opcode: CLTI_U_W
/* 3846 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 3858
/* 3850 */    MCD_OPC_CheckPredicate, 4, 172, 34, // Skip to: 12730
/* 3854 */    MCD_OPC_Decode, 172, 2, 93, // Opcode: CLTI_U_D
/* 3858 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 3870
/* 3862 */    MCD_OPC_CheckPredicate, 4, 160, 34, // Skip to: 12730
/* 3866 */    MCD_OPC_Decode, 149, 2, 90, // Opcode: CLEI_S_B
/* 3870 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 3882
/* 3874 */    MCD_OPC_CheckPredicate, 4, 148, 34, // Skip to: 12730
/* 3878 */    MCD_OPC_Decode, 151, 2, 91, // Opcode: CLEI_S_H
/* 3882 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 3894
/* 3886 */    MCD_OPC_CheckPredicate, 4, 136, 34, // Skip to: 12730
/* 3890 */    MCD_OPC_Decode, 152, 2, 92, // Opcode: CLEI_S_W
/* 3894 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 3906
/* 3898 */    MCD_OPC_CheckPredicate, 4, 124, 34, // Skip to: 12730
/* 3902 */    MCD_OPC_Decode, 150, 2, 93, // Opcode: CLEI_S_D
/* 3906 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 3918
/* 3910 */    MCD_OPC_CheckPredicate, 4, 112, 34, // Skip to: 12730
/* 3914 */    MCD_OPC_Decode, 153, 2, 90, // Opcode: CLEI_U_B
/* 3918 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 3930
/* 3922 */    MCD_OPC_CheckPredicate, 4, 100, 34, // Skip to: 12730
/* 3926 */    MCD_OPC_Decode, 155, 2, 91, // Opcode: CLEI_U_H
/* 3930 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 3942
/* 3934 */    MCD_OPC_CheckPredicate, 4, 88, 34, // Skip to: 12730
/* 3938 */    MCD_OPC_Decode, 156, 2, 92, // Opcode: CLEI_U_W
/* 3942 */    MCD_OPC_FilterValue, 23, 80, 34, // Skip to: 12730
/* 3946 */    MCD_OPC_CheckPredicate, 4, 76, 34, // Skip to: 12730
/* 3950 */    MCD_OPC_Decode, 154, 2, 93, // Opcode: CLEI_U_D
/* 3954 */    MCD_OPC_FilterValue, 9, 35, 2, // Skip to: 4505
/* 3958 */    MCD_OPC_ExtractField, 22, 4,  // Inst{25-22} ...
/* 3961 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3973
/* 3965 */    MCD_OPC_CheckPredicate, 4, 57, 34, // Skip to: 12730
/* 3969 */    MCD_OPC_Decode, 133, 9, 94, // Opcode: SLLI_D
/* 3973 */    MCD_OPC_FilterValue, 1, 52, 0, // Skip to: 4029
/* 3977 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 3980 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3992
/* 3984 */    MCD_OPC_CheckPredicate, 4, 38, 34, // Skip to: 12730
/* 3988 */    MCD_OPC_Decode, 135, 9, 92, // Opcode: SLLI_W
/* 3992 */    MCD_OPC_FilterValue, 1, 30, 34, // Skip to: 12730
/* 3996 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 3999 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4011
/* 4003 */    MCD_OPC_CheckPredicate, 4, 19, 34, // Skip to: 12730
/* 4007 */    MCD_OPC_Decode, 134, 9, 95, // Opcode: SLLI_H
/* 4011 */    MCD_OPC_FilterValue, 1, 11, 34, // Skip to: 12730
/* 4015 */    MCD_OPC_CheckPredicate, 4, 7, 34, // Skip to: 12730
/* 4019 */    MCD_OPC_CheckField, 19, 1, 0, 1, 34, // Skip to: 12730
/* 4025 */    MCD_OPC_Decode, 132, 9, 96, // Opcode: SLLI_B
/* 4029 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 4041
/* 4033 */    MCD_OPC_CheckPredicate, 4, 245, 33, // Skip to: 12730
/* 4037 */    MCD_OPC_Decode, 170, 9, 94, // Opcode: SRAI_D
/* 4041 */    MCD_OPC_FilterValue, 3, 52, 0, // Skip to: 4097
/* 4045 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4048 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4060
/* 4052 */    MCD_OPC_CheckPredicate, 4, 226, 33, // Skip to: 12730
/* 4056 */    MCD_OPC_Decode, 172, 9, 92, // Opcode: SRAI_W
/* 4060 */    MCD_OPC_FilterValue, 1, 218, 33, // Skip to: 12730
/* 4064 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4067 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4079
/* 4071 */    MCD_OPC_CheckPredicate, 4, 207, 33, // Skip to: 12730
/* 4075 */    MCD_OPC_Decode, 171, 9, 95, // Opcode: SRAI_H
/* 4079 */    MCD_OPC_FilterValue, 1, 199, 33, // Skip to: 12730
/* 4083 */    MCD_OPC_CheckPredicate, 4, 195, 33, // Skip to: 12730
/* 4087 */    MCD_OPC_CheckField, 19, 1, 0, 189, 33, // Skip to: 12730
/* 4093 */    MCD_OPC_Decode, 169, 9, 96, // Opcode: SRAI_B
/* 4097 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 4109
/* 4101 */    MCD_OPC_CheckPredicate, 4, 177, 33, // Skip to: 12730
/* 4105 */    MCD_OPC_Decode, 190, 9, 94, // Opcode: SRLI_D
/* 4109 */    MCD_OPC_FilterValue, 5, 52, 0, // Skip to: 4165
/* 4113 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4116 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4128
/* 4120 */    MCD_OPC_CheckPredicate, 4, 158, 33, // Skip to: 12730
/* 4124 */    MCD_OPC_Decode, 192, 9, 92, // Opcode: SRLI_W
/* 4128 */    MCD_OPC_FilterValue, 1, 150, 33, // Skip to: 12730
/* 4132 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4135 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4147
/* 4139 */    MCD_OPC_CheckPredicate, 4, 139, 33, // Skip to: 12730
/* 4143 */    MCD_OPC_Decode, 191, 9, 95, // Opcode: SRLI_H
/* 4147 */    MCD_OPC_FilterValue, 1, 131, 33, // Skip to: 12730
/* 4151 */    MCD_OPC_CheckPredicate, 4, 127, 33, // Skip to: 12730
/* 4155 */    MCD_OPC_CheckField, 19, 1, 0, 121, 33, // Skip to: 12730
/* 4161 */    MCD_OPC_Decode, 189, 9, 96, // Opcode: SRLI_B
/* 4165 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 4177
/* 4169 */    MCD_OPC_CheckPredicate, 4, 109, 33, // Skip to: 12730
/* 4173 */    MCD_OPC_Decode, 154, 1, 94, // Opcode: BCLRI_D
/* 4177 */    MCD_OPC_FilterValue, 7, 52, 0, // Skip to: 4233
/* 4181 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4184 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4196
/* 4188 */    MCD_OPC_CheckPredicate, 4, 90, 33, // Skip to: 12730
/* 4192 */    MCD_OPC_Decode, 156, 1, 92, // Opcode: BCLRI_W
/* 4196 */    MCD_OPC_FilterValue, 1, 82, 33, // Skip to: 12730
/* 4200 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4203 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4215
/* 4207 */    MCD_OPC_CheckPredicate, 4, 71, 33, // Skip to: 12730
/* 4211 */    MCD_OPC_Decode, 155, 1, 95, // Opcode: BCLRI_H
/* 4215 */    MCD_OPC_FilterValue, 1, 63, 33, // Skip to: 12730
/* 4219 */    MCD_OPC_CheckPredicate, 4, 59, 33, // Skip to: 12730
/* 4223 */    MCD_OPC_CheckField, 19, 1, 0, 53, 33, // Skip to: 12730
/* 4229 */    MCD_OPC_Decode, 153, 1, 96, // Opcode: BCLRI_B
/* 4233 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 4245
/* 4237 */    MCD_OPC_CheckPredicate, 4, 41, 33, // Skip to: 12730
/* 4241 */    MCD_OPC_Decode, 228, 1, 94, // Opcode: BSETI_D
/* 4245 */    MCD_OPC_FilterValue, 9, 52, 0, // Skip to: 4301
/* 4249 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4252 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4264
/* 4256 */    MCD_OPC_CheckPredicate, 4, 22, 33, // Skip to: 12730
/* 4260 */    MCD_OPC_Decode, 230, 1, 92, // Opcode: BSETI_W
/* 4264 */    MCD_OPC_FilterValue, 1, 14, 33, // Skip to: 12730
/* 4268 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4271 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4283
/* 4275 */    MCD_OPC_CheckPredicate, 4, 3, 33, // Skip to: 12730
/* 4279 */    MCD_OPC_Decode, 229, 1, 95, // Opcode: BSETI_H
/* 4283 */    MCD_OPC_FilterValue, 1, 251, 32, // Skip to: 12730
/* 4287 */    MCD_OPC_CheckPredicate, 4, 247, 32, // Skip to: 12730
/* 4291 */    MCD_OPC_CheckField, 19, 1, 0, 241, 32, // Skip to: 12730
/* 4297 */    MCD_OPC_Decode, 227, 1, 96, // Opcode: BSETI_B
/* 4301 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 4313
/* 4305 */    MCD_OPC_CheckPredicate, 4, 229, 32, // Skip to: 12730
/* 4309 */    MCD_OPC_Decode, 204, 1, 94, // Opcode: BNEGI_D
/* 4313 */    MCD_OPC_FilterValue, 11, 52, 0, // Skip to: 4369
/* 4317 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4320 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4332
/* 4324 */    MCD_OPC_CheckPredicate, 4, 210, 32, // Skip to: 12730
/* 4328 */    MCD_OPC_Decode, 206, 1, 92, // Opcode: BNEGI_W
/* 4332 */    MCD_OPC_FilterValue, 1, 202, 32, // Skip to: 12730
/* 4336 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4339 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4351
/* 4343 */    MCD_OPC_CheckPredicate, 4, 191, 32, // Skip to: 12730
/* 4347 */    MCD_OPC_Decode, 205, 1, 95, // Opcode: BNEGI_H
/* 4351 */    MCD_OPC_FilterValue, 1, 183, 32, // Skip to: 12730
/* 4355 */    MCD_OPC_CheckPredicate, 4, 179, 32, // Skip to: 12730
/* 4359 */    MCD_OPC_CheckField, 19, 1, 0, 173, 32, // Skip to: 12730
/* 4365 */    MCD_OPC_Decode, 203, 1, 96, // Opcode: BNEGI_B
/* 4369 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 4381
/* 4373 */    MCD_OPC_CheckPredicate, 4, 161, 32, // Skip to: 12730
/* 4377 */    MCD_OPC_Decode, 173, 1, 97, // Opcode: BINSLI_D
/* 4381 */    MCD_OPC_FilterValue, 13, 52, 0, // Skip to: 4437
/* 4385 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4388 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4400
/* 4392 */    MCD_OPC_CheckPredicate, 4, 142, 32, // Skip to: 12730
/* 4396 */    MCD_OPC_Decode, 175, 1, 98, // Opcode: BINSLI_W
/* 4400 */    MCD_OPC_FilterValue, 1, 134, 32, // Skip to: 12730
/* 4404 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4407 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4419
/* 4411 */    MCD_OPC_CheckPredicate, 4, 123, 32, // Skip to: 12730
/* 4415 */    MCD_OPC_Decode, 174, 1, 99, // Opcode: BINSLI_H
/* 4419 */    MCD_OPC_FilterValue, 1, 115, 32, // Skip to: 12730
/* 4423 */    MCD_OPC_CheckPredicate, 4, 111, 32, // Skip to: 12730
/* 4427 */    MCD_OPC_CheckField, 19, 1, 0, 105, 32, // Skip to: 12730
/* 4433 */    MCD_OPC_Decode, 172, 1, 100, // Opcode: BINSLI_B
/* 4437 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 4449
/* 4441 */    MCD_OPC_CheckPredicate, 4, 93, 32, // Skip to: 12730
/* 4445 */    MCD_OPC_Decode, 181, 1, 97, // Opcode: BINSRI_D
/* 4449 */    MCD_OPC_FilterValue, 15, 85, 32, // Skip to: 12730
/* 4453 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4456 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4468
/* 4460 */    MCD_OPC_CheckPredicate, 4, 74, 32, // Skip to: 12730
/* 4464 */    MCD_OPC_Decode, 183, 1, 98, // Opcode: BINSRI_W
/* 4468 */    MCD_OPC_FilterValue, 1, 66, 32, // Skip to: 12730
/* 4472 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4475 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4487
/* 4479 */    MCD_OPC_CheckPredicate, 4, 55, 32, // Skip to: 12730
/* 4483 */    MCD_OPC_Decode, 182, 1, 99, // Opcode: BINSRI_H
/* 4487 */    MCD_OPC_FilterValue, 1, 47, 32, // Skip to: 12730
/* 4491 */    MCD_OPC_CheckPredicate, 4, 43, 32, // Skip to: 12730
/* 4495 */    MCD_OPC_CheckField, 19, 1, 0, 37, 32, // Skip to: 12730
/* 4501 */    MCD_OPC_Decode, 180, 1, 100, // Opcode: BINSRI_B
/* 4505 */    MCD_OPC_FilterValue, 10, 19, 1, // Skip to: 4784
/* 4509 */    MCD_OPC_ExtractField, 22, 4,  // Inst{25-22} ...
/* 4512 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4524
/* 4516 */    MCD_OPC_CheckPredicate, 4, 18, 32, // Skip to: 12730
/* 4520 */    MCD_OPC_Decode, 191, 8, 94, // Opcode: SAT_S_D
/* 4524 */    MCD_OPC_FilterValue, 1, 52, 0, // Skip to: 4580
/* 4528 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4531 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4543
/* 4535 */    MCD_OPC_CheckPredicate, 4, 255, 31, // Skip to: 12730
/* 4539 */    MCD_OPC_Decode, 193, 8, 92, // Opcode: SAT_S_W
/* 4543 */    MCD_OPC_FilterValue, 1, 247, 31, // Skip to: 12730
/* 4547 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4550 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4562
/* 4554 */    MCD_OPC_CheckPredicate, 4, 236, 31, // Skip to: 12730
/* 4558 */    MCD_OPC_Decode, 192, 8, 95, // Opcode: SAT_S_H
/* 4562 */    MCD_OPC_FilterValue, 1, 228, 31, // Skip to: 12730
/* 4566 */    MCD_OPC_CheckPredicate, 4, 224, 31, // Skip to: 12730
/* 4570 */    MCD_OPC_CheckField, 19, 1, 0, 218, 31, // Skip to: 12730
/* 4576 */    MCD_OPC_Decode, 190, 8, 96, // Opcode: SAT_S_B
/* 4580 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 4592
/* 4584 */    MCD_OPC_CheckPredicate, 4, 206, 31, // Skip to: 12730
/* 4588 */    MCD_OPC_Decode, 195, 8, 94, // Opcode: SAT_U_D
/* 4592 */    MCD_OPC_FilterValue, 3, 52, 0, // Skip to: 4648
/* 4596 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4599 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4611
/* 4603 */    MCD_OPC_CheckPredicate, 4, 187, 31, // Skip to: 12730
/* 4607 */    MCD_OPC_Decode, 197, 8, 92, // Opcode: SAT_U_W
/* 4611 */    MCD_OPC_FilterValue, 1, 179, 31, // Skip to: 12730
/* 4615 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4618 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4630
/* 4622 */    MCD_OPC_CheckPredicate, 4, 168, 31, // Skip to: 12730
/* 4626 */    MCD_OPC_Decode, 196, 8, 95, // Opcode: SAT_U_H
/* 4630 */    MCD_OPC_FilterValue, 1, 160, 31, // Skip to: 12730
/* 4634 */    MCD_OPC_CheckPredicate, 4, 156, 31, // Skip to: 12730
/* 4638 */    MCD_OPC_CheckField, 19, 1, 0, 150, 31, // Skip to: 12730
/* 4644 */    MCD_OPC_Decode, 194, 8, 96, // Opcode: SAT_U_B
/* 4648 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 4660
/* 4652 */    MCD_OPC_CheckPredicate, 4, 138, 31, // Skip to: 12730
/* 4656 */    MCD_OPC_Decode, 174, 9, 94, // Opcode: SRARI_D
/* 4660 */    MCD_OPC_FilterValue, 5, 52, 0, // Skip to: 4716
/* 4664 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4667 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4679
/* 4671 */    MCD_OPC_CheckPredicate, 4, 119, 31, // Skip to: 12730
/* 4675 */    MCD_OPC_Decode, 176, 9, 92, // Opcode: SRARI_W
/* 4679 */    MCD_OPC_FilterValue, 1, 111, 31, // Skip to: 12730
/* 4683 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4686 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4698
/* 4690 */    MCD_OPC_CheckPredicate, 4, 100, 31, // Skip to: 12730
/* 4694 */    MCD_OPC_Decode, 175, 9, 95, // Opcode: SRARI_H
/* 4698 */    MCD_OPC_FilterValue, 1, 92, 31, // Skip to: 12730
/* 4702 */    MCD_OPC_CheckPredicate, 4, 88, 31, // Skip to: 12730
/* 4706 */    MCD_OPC_CheckField, 19, 1, 0, 82, 31, // Skip to: 12730
/* 4712 */    MCD_OPC_Decode, 173, 9, 96, // Opcode: SRARI_B
/* 4716 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 4728
/* 4720 */    MCD_OPC_CheckPredicate, 4, 70, 31, // Skip to: 12730
/* 4724 */    MCD_OPC_Decode, 194, 9, 94, // Opcode: SRLRI_D
/* 4728 */    MCD_OPC_FilterValue, 7, 62, 31, // Skip to: 12730
/* 4732 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4735 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4747
/* 4739 */    MCD_OPC_CheckPredicate, 4, 51, 31, // Skip to: 12730
/* 4743 */    MCD_OPC_Decode, 196, 9, 92, // Opcode: SRLRI_W
/* 4747 */    MCD_OPC_FilterValue, 1, 43, 31, // Skip to: 12730
/* 4751 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4754 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4766
/* 4758 */    MCD_OPC_CheckPredicate, 4, 32, 31, // Skip to: 12730
/* 4762 */    MCD_OPC_Decode, 195, 9, 95, // Opcode: SRLRI_H
/* 4766 */    MCD_OPC_FilterValue, 1, 24, 31, // Skip to: 12730
/* 4770 */    MCD_OPC_CheckPredicate, 4, 20, 31, // Skip to: 12730
/* 4774 */    MCD_OPC_CheckField, 19, 1, 0, 14, 31, // Skip to: 12730
/* 4780 */    MCD_OPC_Decode, 193, 9, 96, // Opcode: SRLRI_B
/* 4784 */    MCD_OPC_FilterValue, 12, 51, 0, // Skip to: 4839
/* 4788 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 4791 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 4803
/* 4795 */    MCD_OPC_CheckPredicate, 4, 251, 30, // Skip to: 12730
/* 4799 */    MCD_OPC_Decode, 204, 5, 101, // Opcode: LDI_B
/* 4803 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 4815
/* 4807 */    MCD_OPC_CheckPredicate, 4, 239, 30, // Skip to: 12730
/* 4811 */    MCD_OPC_Decode, 206, 5, 102, // Opcode: LDI_H
/* 4815 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 4827
/* 4819 */    MCD_OPC_CheckPredicate, 4, 227, 30, // Skip to: 12730
/* 4823 */    MCD_OPC_Decode, 207, 5, 103, // Opcode: LDI_W
/* 4827 */    MCD_OPC_FilterValue, 11, 219, 30, // Skip to: 12730
/* 4831 */    MCD_OPC_CheckPredicate, 4, 215, 30, // Skip to: 12730
/* 4835 */    MCD_OPC_Decode, 205, 5, 104, // Opcode: LDI_D
/* 4839 */    MCD_OPC_FilterValue, 13, 131, 1, // Skip to: 5230
/* 4843 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 4846 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4858
/* 4850 */    MCD_OPC_CheckPredicate, 4, 196, 30, // Skip to: 12730
/* 4854 */    MCD_OPC_Decode, 138, 9, 105, // Opcode: SLL_B
/* 4858 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 4870
/* 4862 */    MCD_OPC_CheckPredicate, 4, 184, 30, // Skip to: 12730
/* 4866 */    MCD_OPC_Decode, 140, 9, 106, // Opcode: SLL_H
/* 4870 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 4882
/* 4874 */    MCD_OPC_CheckPredicate, 4, 172, 30, // Skip to: 12730
/* 4878 */    MCD_OPC_Decode, 142, 9, 107, // Opcode: SLL_W
/* 4882 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 4894
/* 4886 */    MCD_OPC_CheckPredicate, 4, 160, 30, // Skip to: 12730
/* 4890 */    MCD_OPC_Decode, 139, 9, 108, // Opcode: SLL_D
/* 4894 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 4906
/* 4898 */    MCD_OPC_CheckPredicate, 4, 148, 30, // Skip to: 12730
/* 4902 */    MCD_OPC_Decode, 183, 9, 105, // Opcode: SRA_B
/* 4906 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 4918
/* 4910 */    MCD_OPC_CheckPredicate, 4, 136, 30, // Skip to: 12730
/* 4914 */    MCD_OPC_Decode, 185, 9, 106, // Opcode: SRA_H
/* 4918 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 4930
/* 4922 */    MCD_OPC_CheckPredicate, 4, 124, 30, // Skip to: 12730
/* 4926 */    MCD_OPC_Decode, 187, 9, 107, // Opcode: SRA_W
/* 4930 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 4942
/* 4934 */    MCD_OPC_CheckPredicate, 4, 112, 30, // Skip to: 12730
/* 4938 */    MCD_OPC_Decode, 184, 9, 108, // Opcode: SRA_D
/* 4942 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 4954
/* 4946 */    MCD_OPC_CheckPredicate, 4, 100, 30, // Skip to: 12730
/* 4950 */    MCD_OPC_Decode, 203, 9, 105, // Opcode: SRL_B
/* 4954 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 4966
/* 4958 */    MCD_OPC_CheckPredicate, 4, 88, 30, // Skip to: 12730
/* 4962 */    MCD_OPC_Decode, 205, 9, 106, // Opcode: SRL_H
/* 4966 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 4978
/* 4970 */    MCD_OPC_CheckPredicate, 4, 76, 30, // Skip to: 12730
/* 4974 */    MCD_OPC_Decode, 207, 9, 107, // Opcode: SRL_W
/* 4978 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 4990
/* 4982 */    MCD_OPC_CheckPredicate, 4, 64, 30, // Skip to: 12730
/* 4986 */    MCD_OPC_Decode, 204, 9, 108, // Opcode: SRL_D
/* 4990 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 5002
/* 4994 */    MCD_OPC_CheckPredicate, 4, 52, 30, // Skip to: 12730
/* 4998 */    MCD_OPC_Decode, 157, 1, 105, // Opcode: BCLR_B
/* 5002 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 5014
/* 5006 */    MCD_OPC_CheckPredicate, 4, 40, 30, // Skip to: 12730
/* 5010 */    MCD_OPC_Decode, 159, 1, 106, // Opcode: BCLR_H
/* 5014 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 5026
/* 5018 */    MCD_OPC_CheckPredicate, 4, 28, 30, // Skip to: 12730
/* 5022 */    MCD_OPC_Decode, 160, 1, 107, // Opcode: BCLR_W
/* 5026 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 5038
/* 5030 */    MCD_OPC_CheckPredicate, 4, 16, 30, // Skip to: 12730
/* 5034 */    MCD_OPC_Decode, 158, 1, 108, // Opcode: BCLR_D
/* 5038 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 5050
/* 5042 */    MCD_OPC_CheckPredicate, 4, 4, 30, // Skip to: 12730
/* 5046 */    MCD_OPC_Decode, 231, 1, 105, // Opcode: BSET_B
/* 5050 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 5062
/* 5054 */    MCD_OPC_CheckPredicate, 4, 248, 29, // Skip to: 12730
/* 5058 */    MCD_OPC_Decode, 233, 1, 106, // Opcode: BSET_H
/* 5062 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 5074
/* 5066 */    MCD_OPC_CheckPredicate, 4, 236, 29, // Skip to: 12730
/* 5070 */    MCD_OPC_Decode, 234, 1, 107, // Opcode: BSET_W
/* 5074 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 5086
/* 5078 */    MCD_OPC_CheckPredicate, 4, 224, 29, // Skip to: 12730
/* 5082 */    MCD_OPC_Decode, 232, 1, 108, // Opcode: BSET_D
/* 5086 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 5098
/* 5090 */    MCD_OPC_CheckPredicate, 4, 212, 29, // Skip to: 12730
/* 5094 */    MCD_OPC_Decode, 207, 1, 105, // Opcode: BNEG_B
/* 5098 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 5110
/* 5102 */    MCD_OPC_CheckPredicate, 4, 200, 29, // Skip to: 12730
/* 5106 */    MCD_OPC_Decode, 209, 1, 106, // Opcode: BNEG_H
/* 5110 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 5122
/* 5114 */    MCD_OPC_CheckPredicate, 4, 188, 29, // Skip to: 12730
/* 5118 */    MCD_OPC_Decode, 210, 1, 107, // Opcode: BNEG_W
/* 5122 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 5134
/* 5126 */    MCD_OPC_CheckPredicate, 4, 176, 29, // Skip to: 12730
/* 5130 */    MCD_OPC_Decode, 208, 1, 108, // Opcode: BNEG_D
/* 5134 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 5146
/* 5138 */    MCD_OPC_CheckPredicate, 4, 164, 29, // Skip to: 12730
/* 5142 */    MCD_OPC_Decode, 176, 1, 109, // Opcode: BINSL_B
/* 5146 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 5158
/* 5150 */    MCD_OPC_CheckPredicate, 4, 152, 29, // Skip to: 12730
/* 5154 */    MCD_OPC_Decode, 178, 1, 110, // Opcode: BINSL_H
/* 5158 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 5170
/* 5162 */    MCD_OPC_CheckPredicate, 4, 140, 29, // Skip to: 12730
/* 5166 */    MCD_OPC_Decode, 179, 1, 111, // Opcode: BINSL_W
/* 5170 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 5182
/* 5174 */    MCD_OPC_CheckPredicate, 4, 128, 29, // Skip to: 12730
/* 5178 */    MCD_OPC_Decode, 177, 1, 112, // Opcode: BINSL_D
/* 5182 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 5194
/* 5186 */    MCD_OPC_CheckPredicate, 4, 116, 29, // Skip to: 12730
/* 5190 */    MCD_OPC_Decode, 184, 1, 109, // Opcode: BINSR_B
/* 5194 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 5206
/* 5198 */    MCD_OPC_CheckPredicate, 4, 104, 29, // Skip to: 12730
/* 5202 */    MCD_OPC_Decode, 186, 1, 110, // Opcode: BINSR_H
/* 5206 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 5218
/* 5210 */    MCD_OPC_CheckPredicate, 4, 92, 29, // Skip to: 12730
/* 5214 */    MCD_OPC_Decode, 187, 1, 111, // Opcode: BINSR_W
/* 5218 */    MCD_OPC_FilterValue, 31, 84, 29, // Skip to: 12730
/* 5222 */    MCD_OPC_CheckPredicate, 4, 80, 29, // Skip to: 12730
/* 5226 */    MCD_OPC_Decode, 185, 1, 112, // Opcode: BINSR_D
/* 5230 */    MCD_OPC_FilterValue, 14, 127, 1, // Skip to: 5617
/* 5234 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 5237 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 5248
/* 5241 */    MCD_OPC_CheckPredicate, 4, 61, 29, // Skip to: 12730
/* 5245 */    MCD_OPC_Decode, 53, 105, // Opcode: ADDV_B
/* 5248 */    MCD_OPC_FilterValue, 1, 7, 0, // Skip to: 5259
/* 5252 */    MCD_OPC_CheckPredicate, 4, 50, 29, // Skip to: 12730
/* 5256 */    MCD_OPC_Decode, 55, 106, // Opcode: ADDV_H
/* 5259 */    MCD_OPC_FilterValue, 2, 7, 0, // Skip to: 5270
/* 5263 */    MCD_OPC_CheckPredicate, 4, 39, 29, // Skip to: 12730
/* 5267 */    MCD_OPC_Decode, 56, 107, // Opcode: ADDV_W
/* 5270 */    MCD_OPC_FilterValue, 3, 7, 0, // Skip to: 5281
/* 5274 */    MCD_OPC_CheckPredicate, 4, 28, 29, // Skip to: 12730
/* 5278 */    MCD_OPC_Decode, 54, 108, // Opcode: ADDV_D
/* 5281 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 5293
/* 5285 */    MCD_OPC_CheckPredicate, 4, 17, 29, // Skip to: 12730
/* 5289 */    MCD_OPC_Decode, 250, 9, 105, // Opcode: SUBV_B
/* 5293 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 5305
/* 5297 */    MCD_OPC_CheckPredicate, 4, 5, 29, // Skip to: 12730
/* 5301 */    MCD_OPC_Decode, 252, 9, 106, // Opcode: SUBV_H
/* 5305 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 5317
/* 5309 */    MCD_OPC_CheckPredicate, 4, 249, 28, // Skip to: 12730
/* 5313 */    MCD_OPC_Decode, 253, 9, 107, // Opcode: SUBV_W
/* 5317 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 5329
/* 5321 */    MCD_OPC_CheckPredicate, 4, 237, 28, // Skip to: 12730
/* 5325 */    MCD_OPC_Decode, 251, 9, 108, // Opcode: SUBV_D
/* 5329 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 5341
/* 5333 */    MCD_OPC_CheckPredicate, 4, 225, 28, // Skip to: 12730
/* 5337 */    MCD_OPC_Decode, 171, 6, 105, // Opcode: MAX_S_B
/* 5341 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 5353
/* 5345 */    MCD_OPC_CheckPredicate, 4, 213, 28, // Skip to: 12730
/* 5349 */    MCD_OPC_Decode, 173, 6, 106, // Opcode: MAX_S_H
/* 5353 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 5365
/* 5357 */    MCD_OPC_CheckPredicate, 4, 201, 28, // Skip to: 12730
/* 5361 */    MCD_OPC_Decode, 174, 6, 107, // Opcode: MAX_S_W
/* 5365 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 5377
/* 5369 */    MCD_OPC_CheckPredicate, 4, 189, 28, // Skip to: 12730
/* 5373 */    MCD_OPC_Decode, 172, 6, 108, // Opcode: MAX_S_D
/* 5377 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 5389
/* 5381 */    MCD_OPC_CheckPredicate, 4, 177, 28, // Skip to: 12730
/* 5385 */    MCD_OPC_Decode, 175, 6, 105, // Opcode: MAX_U_B
/* 5389 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 5401
/* 5393 */    MCD_OPC_CheckPredicate, 4, 165, 28, // Skip to: 12730
/* 5397 */    MCD_OPC_Decode, 177, 6, 106, // Opcode: MAX_U_H
/* 5401 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 5413
/* 5405 */    MCD_OPC_CheckPredicate, 4, 153, 28, // Skip to: 12730
/* 5409 */    MCD_OPC_Decode, 178, 6, 107, // Opcode: MAX_U_W
/* 5413 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 5425
/* 5417 */    MCD_OPC_CheckPredicate, 4, 141, 28, // Skip to: 12730
/* 5421 */    MCD_OPC_Decode, 176, 6, 108, // Opcode: MAX_U_D
/* 5425 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 5437
/* 5429 */    MCD_OPC_CheckPredicate, 4, 129, 28, // Skip to: 12730
/* 5433 */    MCD_OPC_Decode, 203, 6, 105, // Opcode: MIN_S_B
/* 5437 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 5449
/* 5441 */    MCD_OPC_CheckPredicate, 4, 117, 28, // Skip to: 12730
/* 5445 */    MCD_OPC_Decode, 205, 6, 106, // Opcode: MIN_S_H
/* 5449 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 5461
/* 5453 */    MCD_OPC_CheckPredicate, 4, 105, 28, // Skip to: 12730
/* 5457 */    MCD_OPC_Decode, 206, 6, 107, // Opcode: MIN_S_W
/* 5461 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 5473
/* 5465 */    MCD_OPC_CheckPredicate, 4, 93, 28, // Skip to: 12730
/* 5469 */    MCD_OPC_Decode, 204, 6, 108, // Opcode: MIN_S_D
/* 5473 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 5485
/* 5477 */    MCD_OPC_CheckPredicate, 4, 81, 28, // Skip to: 12730
/* 5481 */    MCD_OPC_Decode, 207, 6, 105, // Opcode: MIN_U_B
/* 5485 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 5497
/* 5489 */    MCD_OPC_CheckPredicate, 4, 69, 28, // Skip to: 12730
/* 5493 */    MCD_OPC_Decode, 209, 6, 106, // Opcode: MIN_U_H
/* 5497 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 5509
/* 5501 */    MCD_OPC_CheckPredicate, 4, 57, 28, // Skip to: 12730
/* 5505 */    MCD_OPC_Decode, 210, 6, 107, // Opcode: MIN_U_W
/* 5509 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 5521
/* 5513 */    MCD_OPC_CheckPredicate, 4, 45, 28, // Skip to: 12730
/* 5517 */    MCD_OPC_Decode, 208, 6, 108, // Opcode: MIN_U_D
/* 5521 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 5533
/* 5525 */    MCD_OPC_CheckPredicate, 4, 33, 28, // Skip to: 12730
/* 5529 */    MCD_OPC_Decode, 167, 6, 105, // Opcode: MAX_A_B
/* 5533 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 5545
/* 5537 */    MCD_OPC_CheckPredicate, 4, 21, 28, // Skip to: 12730
/* 5541 */    MCD_OPC_Decode, 169, 6, 106, // Opcode: MAX_A_H
/* 5545 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 5557
/* 5549 */    MCD_OPC_CheckPredicate, 4, 9, 28, // Skip to: 12730
/* 5553 */    MCD_OPC_Decode, 170, 6, 107, // Opcode: MAX_A_W
/* 5557 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 5569
/* 5561 */    MCD_OPC_CheckPredicate, 4, 253, 27, // Skip to: 12730
/* 5565 */    MCD_OPC_Decode, 168, 6, 108, // Opcode: MAX_A_D
/* 5569 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 5581
/* 5573 */    MCD_OPC_CheckPredicate, 4, 241, 27, // Skip to: 12730
/* 5577 */    MCD_OPC_Decode, 199, 6, 105, // Opcode: MIN_A_B
/* 5581 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 5593
/* 5585 */    MCD_OPC_CheckPredicate, 4, 229, 27, // Skip to: 12730
/* 5589 */    MCD_OPC_Decode, 201, 6, 106, // Opcode: MIN_A_H
/* 5593 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 5605
/* 5597 */    MCD_OPC_CheckPredicate, 4, 217, 27, // Skip to: 12730
/* 5601 */    MCD_OPC_Decode, 202, 6, 107, // Opcode: MIN_A_W
/* 5605 */    MCD_OPC_FilterValue, 31, 209, 27, // Skip to: 12730
/* 5609 */    MCD_OPC_CheckPredicate, 4, 205, 27, // Skip to: 12730
/* 5613 */    MCD_OPC_Decode, 200, 6, 108, // Opcode: MIN_A_D
/* 5617 */    MCD_OPC_FilterValue, 15, 243, 0, // Skip to: 5864
/* 5621 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 5624 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5636
/* 5628 */    MCD_OPC_CheckPredicate, 4, 186, 27, // Skip to: 12730
/* 5632 */    MCD_OPC_Decode, 143, 2, 105, // Opcode: CEQ_B
/* 5636 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 5648
/* 5640 */    MCD_OPC_CheckPredicate, 4, 174, 27, // Skip to: 12730
/* 5644 */    MCD_OPC_Decode, 145, 2, 106, // Opcode: CEQ_H
/* 5648 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 5660
/* 5652 */    MCD_OPC_CheckPredicate, 4, 162, 27, // Skip to: 12730
/* 5656 */    MCD_OPC_Decode, 146, 2, 107, // Opcode: CEQ_W
/* 5660 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 5672
/* 5664 */    MCD_OPC_CheckPredicate, 4, 150, 27, // Skip to: 12730
/* 5668 */    MCD_OPC_Decode, 144, 2, 108, // Opcode: CEQ_D
/* 5672 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 5684
/* 5676 */    MCD_OPC_CheckPredicate, 4, 138, 27, // Skip to: 12730
/* 5680 */    MCD_OPC_Decode, 175, 2, 105, // Opcode: CLT_S_B
/* 5684 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 5696
/* 5688 */    MCD_OPC_CheckPredicate, 4, 126, 27, // Skip to: 12730
/* 5692 */    MCD_OPC_Decode, 177, 2, 106, // Opcode: CLT_S_H
/* 5696 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 5708
/* 5700 */    MCD_OPC_CheckPredicate, 4, 114, 27, // Skip to: 12730
/* 5704 */    MCD_OPC_Decode, 178, 2, 107, // Opcode: CLT_S_W
/* 5708 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 5720
/* 5712 */    MCD_OPC_CheckPredicate, 4, 102, 27, // Skip to: 12730
/* 5716 */    MCD_OPC_Decode, 176, 2, 108, // Opcode: CLT_S_D
/* 5720 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 5732
/* 5724 */    MCD_OPC_CheckPredicate, 4, 90, 27, // Skip to: 12730
/* 5728 */    MCD_OPC_Decode, 179, 2, 105, // Opcode: CLT_U_B
/* 5732 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 5744
/* 5736 */    MCD_OPC_CheckPredicate, 4, 78, 27, // Skip to: 12730
/* 5740 */    MCD_OPC_Decode, 181, 2, 106, // Opcode: CLT_U_H
/* 5744 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 5756
/* 5748 */    MCD_OPC_CheckPredicate, 4, 66, 27, // Skip to: 12730
/* 5752 */    MCD_OPC_Decode, 182, 2, 107, // Opcode: CLT_U_W
/* 5756 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 5768
/* 5760 */    MCD_OPC_CheckPredicate, 4, 54, 27, // Skip to: 12730
/* 5764 */    MCD_OPC_Decode, 180, 2, 108, // Opcode: CLT_U_D
/* 5768 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 5780
/* 5772 */    MCD_OPC_CheckPredicate, 4, 42, 27, // Skip to: 12730
/* 5776 */    MCD_OPC_Decode, 157, 2, 105, // Opcode: CLE_S_B
/* 5780 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 5792
/* 5784 */    MCD_OPC_CheckPredicate, 4, 30, 27, // Skip to: 12730
/* 5788 */    MCD_OPC_Decode, 159, 2, 106, // Opcode: CLE_S_H
/* 5792 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 5804
/* 5796 */    MCD_OPC_CheckPredicate, 4, 18, 27, // Skip to: 12730
/* 5800 */    MCD_OPC_Decode, 160, 2, 107, // Opcode: CLE_S_W
/* 5804 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 5816
/* 5808 */    MCD_OPC_CheckPredicate, 4, 6, 27, // Skip to: 12730
/* 5812 */    MCD_OPC_Decode, 158, 2, 108, // Opcode: CLE_S_D
/* 5816 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 5828
/* 5820 */    MCD_OPC_CheckPredicate, 4, 250, 26, // Skip to: 12730
/* 5824 */    MCD_OPC_Decode, 161, 2, 105, // Opcode: CLE_U_B
/* 5828 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 5840
/* 5832 */    MCD_OPC_CheckPredicate, 4, 238, 26, // Skip to: 12730
/* 5836 */    MCD_OPC_Decode, 163, 2, 106, // Opcode: CLE_U_H
/* 5840 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 5852
/* 5844 */    MCD_OPC_CheckPredicate, 4, 226, 26, // Skip to: 12730
/* 5848 */    MCD_OPC_Decode, 164, 2, 107, // Opcode: CLE_U_W
/* 5852 */    MCD_OPC_FilterValue, 23, 218, 26, // Skip to: 12730
/* 5856 */    MCD_OPC_CheckPredicate, 4, 214, 26, // Skip to: 12730
/* 5860 */    MCD_OPC_Decode, 162, 2, 108, // Opcode: CLE_U_D
/* 5864 */    MCD_OPC_FilterValue, 16, 110, 1, // Skip to: 6234
/* 5868 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 5871 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 5882
/* 5875 */    MCD_OPC_CheckPredicate, 4, 195, 26, // Skip to: 12730
/* 5879 */    MCD_OPC_Decode, 58, 105, // Opcode: ADD_A_B
/* 5882 */    MCD_OPC_FilterValue, 1, 7, 0, // Skip to: 5893
/* 5886 */    MCD_OPC_CheckPredicate, 4, 184, 26, // Skip to: 12730
/* 5890 */    MCD_OPC_Decode, 60, 106, // Opcode: ADD_A_H
/* 5893 */    MCD_OPC_FilterValue, 2, 7, 0, // Skip to: 5904
/* 5897 */    MCD_OPC_CheckPredicate, 4, 173, 26, // Skip to: 12730
/* 5901 */    MCD_OPC_Decode, 61, 107, // Opcode: ADD_A_W
/* 5904 */    MCD_OPC_FilterValue, 3, 7, 0, // Skip to: 5915
/* 5908 */    MCD_OPC_CheckPredicate, 4, 162, 26, // Skip to: 12730
/* 5912 */    MCD_OPC_Decode, 59, 108, // Opcode: ADD_A_D
/* 5915 */    MCD_OPC_FilterValue, 4, 7, 0, // Skip to: 5926
/* 5919 */    MCD_OPC_CheckPredicate, 4, 151, 26, // Skip to: 12730
/* 5923 */    MCD_OPC_Decode, 31, 105, // Opcode: ADDS_A_B
/* 5926 */    MCD_OPC_FilterValue, 5, 7, 0, // Skip to: 5937
/* 5930 */    MCD_OPC_CheckPredicate, 4, 140, 26, // Skip to: 12730
/* 5934 */    MCD_OPC_Decode, 33, 106, // Opcode: ADDS_A_H
/* 5937 */    MCD_OPC_FilterValue, 6, 7, 0, // Skip to: 5948
/* 5941 */    MCD_OPC_CheckPredicate, 4, 129, 26, // Skip to: 12730
/* 5945 */    MCD_OPC_Decode, 34, 107, // Opcode: ADDS_A_W
/* 5948 */    MCD_OPC_FilterValue, 7, 7, 0, // Skip to: 5959
/* 5952 */    MCD_OPC_CheckPredicate, 4, 118, 26, // Skip to: 12730
/* 5956 */    MCD_OPC_Decode, 32, 108, // Opcode: ADDS_A_D
/* 5959 */    MCD_OPC_FilterValue, 8, 7, 0, // Skip to: 5970
/* 5963 */    MCD_OPC_CheckPredicate, 4, 107, 26, // Skip to: 12730
/* 5967 */    MCD_OPC_Decode, 35, 105, // Opcode: ADDS_S_B
/* 5970 */    MCD_OPC_FilterValue, 9, 7, 0, // Skip to: 5981
/* 5974 */    MCD_OPC_CheckPredicate, 4, 96, 26, // Skip to: 12730
/* 5978 */    MCD_OPC_Decode, 37, 106, // Opcode: ADDS_S_H
/* 5981 */    MCD_OPC_FilterValue, 10, 7, 0, // Skip to: 5992
/* 5985 */    MCD_OPC_CheckPredicate, 4, 85, 26, // Skip to: 12730
/* 5989 */    MCD_OPC_Decode, 38, 107, // Opcode: ADDS_S_W
/* 5992 */    MCD_OPC_FilterValue, 11, 7, 0, // Skip to: 6003
/* 5996 */    MCD_OPC_CheckPredicate, 4, 74, 26, // Skip to: 12730
/* 6000 */    MCD_OPC_Decode, 36, 108, // Opcode: ADDS_S_D
/* 6003 */    MCD_OPC_FilterValue, 12, 7, 0, // Skip to: 6014
/* 6007 */    MCD_OPC_CheckPredicate, 4, 63, 26, // Skip to: 12730
/* 6011 */    MCD_OPC_Decode, 39, 105, // Opcode: ADDS_U_B
/* 6014 */    MCD_OPC_FilterValue, 13, 7, 0, // Skip to: 6025
/* 6018 */    MCD_OPC_CheckPredicate, 4, 52, 26, // Skip to: 12730
/* 6022 */    MCD_OPC_Decode, 41, 106, // Opcode: ADDS_U_H
/* 6025 */    MCD_OPC_FilterValue, 14, 7, 0, // Skip to: 6036
/* 6029 */    MCD_OPC_CheckPredicate, 4, 41, 26, // Skip to: 12730
/* 6033 */    MCD_OPC_Decode, 42, 107, // Opcode: ADDS_U_W
/* 6036 */    MCD_OPC_FilterValue, 15, 7, 0, // Skip to: 6047
/* 6040 */    MCD_OPC_CheckPredicate, 4, 30, 26, // Skip to: 12730
/* 6044 */    MCD_OPC_Decode, 40, 108, // Opcode: ADDS_U_D
/* 6047 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 6059
/* 6051 */    MCD_OPC_CheckPredicate, 4, 19, 26, // Skip to: 12730
/* 6055 */    MCD_OPC_Decode, 131, 1, 105, // Opcode: AVE_S_B
/* 6059 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 6071
/* 6063 */    MCD_OPC_CheckPredicate, 4, 7, 26, // Skip to: 12730
/* 6067 */    MCD_OPC_Decode, 133, 1, 106, // Opcode: AVE_S_H
/* 6071 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 6083
/* 6075 */    MCD_OPC_CheckPredicate, 4, 251, 25, // Skip to: 12730
/* 6079 */    MCD_OPC_Decode, 134, 1, 107, // Opcode: AVE_S_W
/* 6083 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 6095
/* 6087 */    MCD_OPC_CheckPredicate, 4, 239, 25, // Skip to: 12730
/* 6091 */    MCD_OPC_Decode, 132, 1, 108, // Opcode: AVE_S_D
/* 6095 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 6107
/* 6099 */    MCD_OPC_CheckPredicate, 4, 227, 25, // Skip to: 12730
/* 6103 */    MCD_OPC_Decode, 135, 1, 105, // Opcode: AVE_U_B
/* 6107 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 6119
/* 6111 */    MCD_OPC_CheckPredicate, 4, 215, 25, // Skip to: 12730
/* 6115 */    MCD_OPC_Decode, 137, 1, 106, // Opcode: AVE_U_H
/* 6119 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 6131
/* 6123 */    MCD_OPC_CheckPredicate, 4, 203, 25, // Skip to: 12730
/* 6127 */    MCD_OPC_Decode, 138, 1, 107, // Opcode: AVE_U_W
/* 6131 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 6143
/* 6135 */    MCD_OPC_CheckPredicate, 4, 191, 25, // Skip to: 12730
/* 6139 */    MCD_OPC_Decode, 136, 1, 108, // Opcode: AVE_U_D
/* 6143 */    MCD_OPC_FilterValue, 24, 7, 0, // Skip to: 6154
/* 6147 */    MCD_OPC_CheckPredicate, 4, 179, 25, // Skip to: 12730
/* 6151 */    MCD_OPC_Decode, 123, 105, // Opcode: AVER_S_B
/* 6154 */    MCD_OPC_FilterValue, 25, 7, 0, // Skip to: 6165
/* 6158 */    MCD_OPC_CheckPredicate, 4, 168, 25, // Skip to: 12730
/* 6162 */    MCD_OPC_Decode, 125, 106, // Opcode: AVER_S_H
/* 6165 */    MCD_OPC_FilterValue, 26, 7, 0, // Skip to: 6176
/* 6169 */    MCD_OPC_CheckPredicate, 4, 157, 25, // Skip to: 12730
/* 6173 */    MCD_OPC_Decode, 126, 107, // Opcode: AVER_S_W
/* 6176 */    MCD_OPC_FilterValue, 27, 7, 0, // Skip to: 6187
/* 6180 */    MCD_OPC_CheckPredicate, 4, 146, 25, // Skip to: 12730
/* 6184 */    MCD_OPC_Decode, 124, 108, // Opcode: AVER_S_D
/* 6187 */    MCD_OPC_FilterValue, 28, 7, 0, // Skip to: 6198
/* 6191 */    MCD_OPC_CheckPredicate, 4, 135, 25, // Skip to: 12730
/* 6195 */    MCD_OPC_Decode, 127, 105, // Opcode: AVER_U_B
/* 6198 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 6210
/* 6202 */    MCD_OPC_CheckPredicate, 4, 124, 25, // Skip to: 12730
/* 6206 */    MCD_OPC_Decode, 129, 1, 106, // Opcode: AVER_U_H
/* 6210 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 6222
/* 6214 */    MCD_OPC_CheckPredicate, 4, 112, 25, // Skip to: 12730
/* 6218 */    MCD_OPC_Decode, 130, 1, 107, // Opcode: AVER_U_W
/* 6222 */    MCD_OPC_FilterValue, 31, 104, 25, // Skip to: 12730
/* 6226 */    MCD_OPC_CheckPredicate, 4, 100, 25, // Skip to: 12730
/* 6230 */    MCD_OPC_Decode, 128, 1, 108, // Opcode: AVER_U_D
/* 6234 */    MCD_OPC_FilterValue, 17, 27, 1, // Skip to: 6521
/* 6238 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 6241 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 6253
/* 6245 */    MCD_OPC_CheckPredicate, 4, 81, 25, // Skip to: 12730
/* 6249 */    MCD_OPC_Decode, 232, 9, 105, // Opcode: SUBS_S_B
/* 6253 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 6265
/* 6257 */    MCD_OPC_CheckPredicate, 4, 69, 25, // Skip to: 12730
/* 6261 */    MCD_OPC_Decode, 234, 9, 106, // Opcode: SUBS_S_H
/* 6265 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 6277
/* 6269 */    MCD_OPC_CheckPredicate, 4, 57, 25, // Skip to: 12730
/* 6273 */    MCD_OPC_Decode, 235, 9, 107, // Opcode: SUBS_S_W
/* 6277 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 6289
/* 6281 */    MCD_OPC_CheckPredicate, 4, 45, 25, // Skip to: 12730
/* 6285 */    MCD_OPC_Decode, 233, 9, 108, // Opcode: SUBS_S_D
/* 6289 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 6301
/* 6293 */    MCD_OPC_CheckPredicate, 4, 33, 25, // Skip to: 12730
/* 6297 */    MCD_OPC_Decode, 236, 9, 105, // Opcode: SUBS_U_B
/* 6301 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 6313
/* 6305 */    MCD_OPC_CheckPredicate, 4, 21, 25, // Skip to: 12730
/* 6309 */    MCD_OPC_Decode, 238, 9, 106, // Opcode: SUBS_U_H
/* 6313 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 6325
/* 6317 */    MCD_OPC_CheckPredicate, 4, 9, 25, // Skip to: 12730
/* 6321 */    MCD_OPC_Decode, 239, 9, 107, // Opcode: SUBS_U_W
/* 6325 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 6337
/* 6329 */    MCD_OPC_CheckPredicate, 4, 253, 24, // Skip to: 12730
/* 6333 */    MCD_OPC_Decode, 237, 9, 108, // Opcode: SUBS_U_D
/* 6337 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 6349
/* 6341 */    MCD_OPC_CheckPredicate, 4, 241, 24, // Skip to: 12730
/* 6345 */    MCD_OPC_Decode, 224, 9, 105, // Opcode: SUBSUS_U_B
/* 6349 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 6361
/* 6353 */    MCD_OPC_CheckPredicate, 4, 229, 24, // Skip to: 12730
/* 6357 */    MCD_OPC_Decode, 226, 9, 106, // Opcode: SUBSUS_U_H
/* 6361 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 6373
/* 6365 */    MCD_OPC_CheckPredicate, 4, 217, 24, // Skip to: 12730
/* 6369 */    MCD_OPC_Decode, 227, 9, 107, // Opcode: SUBSUS_U_W
/* 6373 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 6385
/* 6377 */    MCD_OPC_CheckPredicate, 4, 205, 24, // Skip to: 12730
/* 6381 */    MCD_OPC_Decode, 225, 9, 108, // Opcode: SUBSUS_U_D
/* 6385 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 6397
/* 6389 */    MCD_OPC_CheckPredicate, 4, 193, 24, // Skip to: 12730
/* 6393 */    MCD_OPC_Decode, 228, 9, 105, // Opcode: SUBSUU_S_B
/* 6397 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 6409
/* 6401 */    MCD_OPC_CheckPredicate, 4, 181, 24, // Skip to: 12730
/* 6405 */    MCD_OPC_Decode, 230, 9, 106, // Opcode: SUBSUU_S_H
/* 6409 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 6421
/* 6413 */    MCD_OPC_CheckPredicate, 4, 169, 24, // Skip to: 12730
/* 6417 */    MCD_OPC_Decode, 231, 9, 107, // Opcode: SUBSUU_S_W
/* 6421 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 6433
/* 6425 */    MCD_OPC_CheckPredicate, 4, 157, 24, // Skip to: 12730
/* 6429 */    MCD_OPC_Decode, 229, 9, 108, // Opcode: SUBSUU_S_D
/* 6433 */    MCD_OPC_FilterValue, 16, 7, 0, // Skip to: 6444
/* 6437 */    MCD_OPC_CheckPredicate, 4, 145, 24, // Skip to: 12730
/* 6441 */    MCD_OPC_Decode, 83, 105, // Opcode: ASUB_S_B
/* 6444 */    MCD_OPC_FilterValue, 17, 7, 0, // Skip to: 6455
/* 6448 */    MCD_OPC_CheckPredicate, 4, 134, 24, // Skip to: 12730
/* 6452 */    MCD_OPC_Decode, 85, 106, // Opcode: ASUB_S_H
/* 6455 */    MCD_OPC_FilterValue, 18, 7, 0, // Skip to: 6466
/* 6459 */    MCD_OPC_CheckPredicate, 4, 123, 24, // Skip to: 12730
/* 6463 */    MCD_OPC_Decode, 86, 107, // Opcode: ASUB_S_W
/* 6466 */    MCD_OPC_FilterValue, 19, 7, 0, // Skip to: 6477
/* 6470 */    MCD_OPC_CheckPredicate, 4, 112, 24, // Skip to: 12730
/* 6474 */    MCD_OPC_Decode, 84, 108, // Opcode: ASUB_S_D
/* 6477 */    MCD_OPC_FilterValue, 20, 7, 0, // Skip to: 6488
/* 6481 */    MCD_OPC_CheckPredicate, 4, 101, 24, // Skip to: 12730
/* 6485 */    MCD_OPC_Decode, 87, 105, // Opcode: ASUB_U_B
/* 6488 */    MCD_OPC_FilterValue, 21, 7, 0, // Skip to: 6499
/* 6492 */    MCD_OPC_CheckPredicate, 4, 90, 24, // Skip to: 12730
/* 6496 */    MCD_OPC_Decode, 89, 106, // Opcode: ASUB_U_H
/* 6499 */    MCD_OPC_FilterValue, 22, 7, 0, // Skip to: 6510
/* 6503 */    MCD_OPC_CheckPredicate, 4, 79, 24, // Skip to: 12730
/* 6507 */    MCD_OPC_Decode, 90, 107, // Opcode: ASUB_U_W
/* 6510 */    MCD_OPC_FilterValue, 23, 72, 24, // Skip to: 12730
/* 6514 */    MCD_OPC_CheckPredicate, 4, 68, 24, // Skip to: 12730
/* 6518 */    MCD_OPC_Decode, 88, 108, // Opcode: ASUB_U_D
/* 6521 */    MCD_OPC_FilterValue, 18, 83, 1, // Skip to: 6864
/* 6525 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 6528 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 6540
/* 6532 */    MCD_OPC_CheckPredicate, 4, 50, 24, // Skip to: 12730
/* 6536 */    MCD_OPC_Decode, 176, 7, 105, // Opcode: MULV_B
/* 6540 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 6552
/* 6544 */    MCD_OPC_CheckPredicate, 4, 38, 24, // Skip to: 12730
/* 6548 */    MCD_OPC_Decode, 178, 7, 106, // Opcode: MULV_H
/* 6552 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 6564
/* 6556 */    MCD_OPC_CheckPredicate, 4, 26, 24, // Skip to: 12730
/* 6560 */    MCD_OPC_Decode, 179, 7, 107, // Opcode: MULV_W
/* 6564 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 6576
/* 6568 */    MCD_OPC_CheckPredicate, 4, 14, 24, // Skip to: 12730
/* 6572 */    MCD_OPC_Decode, 177, 7, 108, // Opcode: MULV_D
/* 6576 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 6588
/* 6580 */    MCD_OPC_CheckPredicate, 4, 2, 24, // Skip to: 12730
/* 6584 */    MCD_OPC_Decode, 144, 6, 109, // Opcode: MADDV_B
/* 6588 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 6600
/* 6592 */    MCD_OPC_CheckPredicate, 4, 246, 23, // Skip to: 12730
/* 6596 */    MCD_OPC_Decode, 146, 6, 110, // Opcode: MADDV_H
/* 6600 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 6612
/* 6604 */    MCD_OPC_CheckPredicate, 4, 234, 23, // Skip to: 12730
/* 6608 */    MCD_OPC_Decode, 147, 6, 111, // Opcode: MADDV_W
/* 6612 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 6624
/* 6616 */    MCD_OPC_CheckPredicate, 4, 222, 23, // Skip to: 12730
/* 6620 */    MCD_OPC_Decode, 145, 6, 112, // Opcode: MADDV_D
/* 6624 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 6636
/* 6628 */    MCD_OPC_CheckPredicate, 4, 210, 23, // Skip to: 12730
/* 6632 */    MCD_OPC_Decode, 133, 7, 109, // Opcode: MSUBV_B
/* 6636 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 6648
/* 6640 */    MCD_OPC_CheckPredicate, 4, 198, 23, // Skip to: 12730
/* 6644 */    MCD_OPC_Decode, 135, 7, 110, // Opcode: MSUBV_H
/* 6648 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 6660
/* 6652 */    MCD_OPC_CheckPredicate, 4, 186, 23, // Skip to: 12730
/* 6656 */    MCD_OPC_Decode, 136, 7, 111, // Opcode: MSUBV_W
/* 6660 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 6672
/* 6664 */    MCD_OPC_CheckPredicate, 4, 174, 23, // Skip to: 12730
/* 6668 */    MCD_OPC_Decode, 134, 7, 112, // Opcode: MSUBV_D
/* 6672 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 6684
/* 6676 */    MCD_OPC_CheckPredicate, 4, 162, 23, // Skip to: 12730
/* 6680 */    MCD_OPC_Decode, 160, 3, 105, // Opcode: DIV_S_B
/* 6684 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 6696
/* 6688 */    MCD_OPC_CheckPredicate, 4, 150, 23, // Skip to: 12730
/* 6692 */    MCD_OPC_Decode, 162, 3, 106, // Opcode: DIV_S_H
/* 6696 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 6708
/* 6700 */    MCD_OPC_CheckPredicate, 4, 138, 23, // Skip to: 12730
/* 6704 */    MCD_OPC_Decode, 163, 3, 107, // Opcode: DIV_S_W
/* 6708 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 6720
/* 6712 */    MCD_OPC_CheckPredicate, 4, 126, 23, // Skip to: 12730
/* 6716 */    MCD_OPC_Decode, 161, 3, 108, // Opcode: DIV_S_D
/* 6720 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 6732
/* 6724 */    MCD_OPC_CheckPredicate, 4, 114, 23, // Skip to: 12730
/* 6728 */    MCD_OPC_Decode, 164, 3, 105, // Opcode: DIV_U_B
/* 6732 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 6744
/* 6736 */    MCD_OPC_CheckPredicate, 4, 102, 23, // Skip to: 12730
/* 6740 */    MCD_OPC_Decode, 166, 3, 106, // Opcode: DIV_U_H
/* 6744 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 6756
/* 6748 */    MCD_OPC_CheckPredicate, 4, 90, 23, // Skip to: 12730
/* 6752 */    MCD_OPC_Decode, 167, 3, 107, // Opcode: DIV_U_W
/* 6756 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 6768
/* 6760 */    MCD_OPC_CheckPredicate, 4, 78, 23, // Skip to: 12730
/* 6764 */    MCD_OPC_Decode, 165, 3, 108, // Opcode: DIV_U_D
/* 6768 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 6780
/* 6772 */    MCD_OPC_CheckPredicate, 4, 66, 23, // Skip to: 12730
/* 6776 */    MCD_OPC_Decode, 214, 6, 105, // Opcode: MOD_S_B
/* 6780 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 6792
/* 6784 */    MCD_OPC_CheckPredicate, 4, 54, 23, // Skip to: 12730
/* 6788 */    MCD_OPC_Decode, 216, 6, 106, // Opcode: MOD_S_H
/* 6792 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 6804
/* 6796 */    MCD_OPC_CheckPredicate, 4, 42, 23, // Skip to: 12730
/* 6800 */    MCD_OPC_Decode, 217, 6, 107, // Opcode: MOD_S_W
/* 6804 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 6816
/* 6808 */    MCD_OPC_CheckPredicate, 4, 30, 23, // Skip to: 12730
/* 6812 */    MCD_OPC_Decode, 215, 6, 108, // Opcode: MOD_S_D
/* 6816 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 6828
/* 6820 */    MCD_OPC_CheckPredicate, 4, 18, 23, // Skip to: 12730
/* 6824 */    MCD_OPC_Decode, 218, 6, 105, // Opcode: MOD_U_B
/* 6828 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 6840
/* 6832 */    MCD_OPC_CheckPredicate, 4, 6, 23, // Skip to: 12730
/* 6836 */    MCD_OPC_Decode, 220, 6, 106, // Opcode: MOD_U_H
/* 6840 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 6852
/* 6844 */    MCD_OPC_CheckPredicate, 4, 250, 22, // Skip to: 12730
/* 6848 */    MCD_OPC_Decode, 221, 6, 107, // Opcode: MOD_U_W
/* 6852 */    MCD_OPC_FilterValue, 31, 242, 22, // Skip to: 12730
/* 6856 */    MCD_OPC_CheckPredicate, 4, 238, 22, // Skip to: 12730
/* 6860 */    MCD_OPC_Decode, 219, 6, 108, // Opcode: MOD_U_D
/* 6864 */    MCD_OPC_FilterValue, 19, 219, 0, // Skip to: 7087
/* 6868 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 6871 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 6883
/* 6875 */    MCD_OPC_CheckPredicate, 4, 219, 22, // Skip to: 12730
/* 6879 */    MCD_OPC_Decode, 177, 3, 113, // Opcode: DOTP_S_H
/* 6883 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 6895
/* 6887 */    MCD_OPC_CheckPredicate, 4, 207, 22, // Skip to: 12730
/* 6891 */    MCD_OPC_Decode, 178, 3, 114, // Opcode: DOTP_S_W
/* 6895 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 6907
/* 6899 */    MCD_OPC_CheckPredicate, 4, 195, 22, // Skip to: 12730
/* 6903 */    MCD_OPC_Decode, 176, 3, 115, // Opcode: DOTP_S_D
/* 6907 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 6919
/* 6911 */    MCD_OPC_CheckPredicate, 4, 183, 22, // Skip to: 12730
/* 6915 */    MCD_OPC_Decode, 180, 3, 113, // Opcode: DOTP_U_H
/* 6919 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 6931
/* 6923 */    MCD_OPC_CheckPredicate, 4, 171, 22, // Skip to: 12730
/* 6927 */    MCD_OPC_Decode, 181, 3, 114, // Opcode: DOTP_U_W
/* 6931 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 6943
/* 6935 */    MCD_OPC_CheckPredicate, 4, 159, 22, // Skip to: 12730
/* 6939 */    MCD_OPC_Decode, 179, 3, 115, // Opcode: DOTP_U_D
/* 6943 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 6955
/* 6947 */    MCD_OPC_CheckPredicate, 4, 147, 22, // Skip to: 12730
/* 6951 */    MCD_OPC_Decode, 183, 3, 116, // Opcode: DPADD_S_H
/* 6955 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 6967
/* 6959 */    MCD_OPC_CheckPredicate, 4, 135, 22, // Skip to: 12730
/* 6963 */    MCD_OPC_Decode, 184, 3, 117, // Opcode: DPADD_S_W
/* 6967 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 6979
/* 6971 */    MCD_OPC_CheckPredicate, 4, 123, 22, // Skip to: 12730
/* 6975 */    MCD_OPC_Decode, 182, 3, 118, // Opcode: DPADD_S_D
/* 6979 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 6991
/* 6983 */    MCD_OPC_CheckPredicate, 4, 111, 22, // Skip to: 12730
/* 6987 */    MCD_OPC_Decode, 186, 3, 116, // Opcode: DPADD_U_H
/* 6991 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 7003
/* 6995 */    MCD_OPC_CheckPredicate, 4, 99, 22, // Skip to: 12730
/* 6999 */    MCD_OPC_Decode, 187, 3, 117, // Opcode: DPADD_U_W
/* 7003 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 7015
/* 7007 */    MCD_OPC_CheckPredicate, 4, 87, 22, // Skip to: 12730
/* 7011 */    MCD_OPC_Decode, 185, 3, 118, // Opcode: DPADD_U_D
/* 7015 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 7027
/* 7019 */    MCD_OPC_CheckPredicate, 4, 75, 22, // Skip to: 12730
/* 7023 */    MCD_OPC_Decode, 201, 3, 116, // Opcode: DPSUB_S_H
/* 7027 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 7039
/* 7031 */    MCD_OPC_CheckPredicate, 4, 63, 22, // Skip to: 12730
/* 7035 */    MCD_OPC_Decode, 202, 3, 117, // Opcode: DPSUB_S_W
/* 7039 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 7051
/* 7043 */    MCD_OPC_CheckPredicate, 4, 51, 22, // Skip to: 12730
/* 7047 */    MCD_OPC_Decode, 200, 3, 118, // Opcode: DPSUB_S_D
/* 7051 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 7063
/* 7055 */    MCD_OPC_CheckPredicate, 4, 39, 22, // Skip to: 12730
/* 7059 */    MCD_OPC_Decode, 204, 3, 116, // Opcode: DPSUB_U_H
/* 7063 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 7075
/* 7067 */    MCD_OPC_CheckPredicate, 4, 27, 22, // Skip to: 12730
/* 7071 */    MCD_OPC_Decode, 205, 3, 117, // Opcode: DPSUB_U_W
/* 7075 */    MCD_OPC_FilterValue, 23, 19, 22, // Skip to: 12730
/* 7079 */    MCD_OPC_CheckPredicate, 4, 15, 22, // Skip to: 12730
/* 7083 */    MCD_OPC_Decode, 203, 3, 118, // Opcode: DPSUB_U_D
/* 7087 */    MCD_OPC_FilterValue, 20, 131, 1, // Skip to: 7478
/* 7091 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 7094 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 7106
/* 7098 */    MCD_OPC_CheckPredicate, 4, 252, 21, // Skip to: 12730
/* 7102 */    MCD_OPC_Decode, 253, 8, 119, // Opcode: SLD_B
/* 7106 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 7118
/* 7110 */    MCD_OPC_CheckPredicate, 4, 240, 21, // Skip to: 12730
/* 7114 */    MCD_OPC_Decode, 255, 8, 120, // Opcode: SLD_H
/* 7118 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 7130
/* 7122 */    MCD_OPC_CheckPredicate, 4, 228, 21, // Skip to: 12730
/* 7126 */    MCD_OPC_Decode, 128, 9, 121, // Opcode: SLD_W
/* 7130 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 7142
/* 7134 */    MCD_OPC_CheckPredicate, 4, 216, 21, // Skip to: 12730
/* 7138 */    MCD_OPC_Decode, 254, 8, 122, // Opcode: SLD_D
/* 7142 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 7154
/* 7146 */    MCD_OPC_CheckPredicate, 4, 204, 21, // Skip to: 12730
/* 7150 */    MCD_OPC_Decode, 164, 9, 119, // Opcode: SPLAT_B
/* 7154 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 7166
/* 7158 */    MCD_OPC_CheckPredicate, 4, 192, 21, // Skip to: 12730
/* 7162 */    MCD_OPC_Decode, 166, 9, 120, // Opcode: SPLAT_H
/* 7166 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 7178
/* 7170 */    MCD_OPC_CheckPredicate, 4, 180, 21, // Skip to: 12730
/* 7174 */    MCD_OPC_Decode, 167, 9, 121, // Opcode: SPLAT_W
/* 7178 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 7190
/* 7182 */    MCD_OPC_CheckPredicate, 4, 168, 21, // Skip to: 12730
/* 7186 */    MCD_OPC_Decode, 165, 9, 122, // Opcode: SPLAT_D
/* 7190 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 7202
/* 7194 */    MCD_OPC_CheckPredicate, 4, 156, 21, // Skip to: 12730
/* 7198 */    MCD_OPC_Decode, 231, 7, 105, // Opcode: PCKEV_B
/* 7202 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 7214
/* 7206 */    MCD_OPC_CheckPredicate, 4, 144, 21, // Skip to: 12730
/* 7210 */    MCD_OPC_Decode, 233, 7, 106, // Opcode: PCKEV_H
/* 7214 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 7226
/* 7218 */    MCD_OPC_CheckPredicate, 4, 132, 21, // Skip to: 12730
/* 7222 */    MCD_OPC_Decode, 234, 7, 107, // Opcode: PCKEV_W
/* 7226 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 7238
/* 7230 */    MCD_OPC_CheckPredicate, 4, 120, 21, // Skip to: 12730
/* 7234 */    MCD_OPC_Decode, 232, 7, 108, // Opcode: PCKEV_D
/* 7238 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 7250
/* 7242 */    MCD_OPC_CheckPredicate, 4, 108, 21, // Skip to: 12730
/* 7246 */    MCD_OPC_Decode, 235, 7, 105, // Opcode: PCKOD_B
/* 7250 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 7262
/* 7254 */    MCD_OPC_CheckPredicate, 4, 96, 21, // Skip to: 12730
/* 7258 */    MCD_OPC_Decode, 237, 7, 106, // Opcode: PCKOD_H
/* 7262 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 7274
/* 7266 */    MCD_OPC_CheckPredicate, 4, 84, 21, // Skip to: 12730
/* 7270 */    MCD_OPC_Decode, 238, 7, 107, // Opcode: PCKOD_W
/* 7274 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 7286
/* 7278 */    MCD_OPC_CheckPredicate, 4, 72, 21, // Skip to: 12730
/* 7282 */    MCD_OPC_Decode, 236, 7, 108, // Opcode: PCKOD_D
/* 7286 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 7298
/* 7290 */    MCD_OPC_CheckPredicate, 4, 60, 21, // Skip to: 12730
/* 7294 */    MCD_OPC_Decode, 152, 5, 105, // Opcode: ILVL_B
/* 7298 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 7310
/* 7302 */    MCD_OPC_CheckPredicate, 4, 48, 21, // Skip to: 12730
/* 7306 */    MCD_OPC_Decode, 154, 5, 106, // Opcode: ILVL_H
/* 7310 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 7322
/* 7314 */    MCD_OPC_CheckPredicate, 4, 36, 21, // Skip to: 12730
/* 7318 */    MCD_OPC_Decode, 155, 5, 107, // Opcode: ILVL_W
/* 7322 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 7334
/* 7326 */    MCD_OPC_CheckPredicate, 4, 24, 21, // Skip to: 12730
/* 7330 */    MCD_OPC_Decode, 153, 5, 108, // Opcode: ILVL_D
/* 7334 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 7346
/* 7338 */    MCD_OPC_CheckPredicate, 4, 12, 21, // Skip to: 12730
/* 7342 */    MCD_OPC_Decode, 160, 5, 105, // Opcode: ILVR_B
/* 7346 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 7358
/* 7350 */    MCD_OPC_CheckPredicate, 4, 0, 21, // Skip to: 12730
/* 7354 */    MCD_OPC_Decode, 162, 5, 106, // Opcode: ILVR_H
/* 7358 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 7370
/* 7362 */    MCD_OPC_CheckPredicate, 4, 244, 20, // Skip to: 12730
/* 7366 */    MCD_OPC_Decode, 163, 5, 107, // Opcode: ILVR_W
/* 7370 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 7382
/* 7374 */    MCD_OPC_CheckPredicate, 4, 232, 20, // Skip to: 12730
/* 7378 */    MCD_OPC_Decode, 161, 5, 108, // Opcode: ILVR_D
/* 7382 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 7394
/* 7386 */    MCD_OPC_CheckPredicate, 4, 220, 20, // Skip to: 12730
/* 7390 */    MCD_OPC_Decode, 148, 5, 105, // Opcode: ILVEV_B
/* 7394 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 7406
/* 7398 */    MCD_OPC_CheckPredicate, 4, 208, 20, // Skip to: 12730
/* 7402 */    MCD_OPC_Decode, 150, 5, 106, // Opcode: ILVEV_H
/* 7406 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 7418
/* 7410 */    MCD_OPC_CheckPredicate, 4, 196, 20, // Skip to: 12730
/* 7414 */    MCD_OPC_Decode, 151, 5, 107, // Opcode: ILVEV_W
/* 7418 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 7430
/* 7422 */    MCD_OPC_CheckPredicate, 4, 184, 20, // Skip to: 12730
/* 7426 */    MCD_OPC_Decode, 149, 5, 108, // Opcode: ILVEV_D
/* 7430 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 7442
/* 7434 */    MCD_OPC_CheckPredicate, 4, 172, 20, // Skip to: 12730
/* 7438 */    MCD_OPC_Decode, 156, 5, 105, // Opcode: ILVOD_B
/* 7442 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 7454
/* 7446 */    MCD_OPC_CheckPredicate, 4, 160, 20, // Skip to: 12730
/* 7450 */    MCD_OPC_Decode, 158, 5, 106, // Opcode: ILVOD_H
/* 7454 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 7466
/* 7458 */    MCD_OPC_CheckPredicate, 4, 148, 20, // Skip to: 12730
/* 7462 */    MCD_OPC_Decode, 159, 5, 107, // Opcode: ILVOD_W
/* 7466 */    MCD_OPC_FilterValue, 31, 140, 20, // Skip to: 12730
/* 7470 */    MCD_OPC_CheckPredicate, 4, 136, 20, // Skip to: 12730
/* 7474 */    MCD_OPC_Decode, 157, 5, 108, // Opcode: ILVOD_D
/* 7478 */    MCD_OPC_FilterValue, 21, 35, 1, // Skip to: 7773
/* 7482 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 7485 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 7497
/* 7489 */    MCD_OPC_CheckPredicate, 4, 117, 20, // Skip to: 12730
/* 7493 */    MCD_OPC_Decode, 215, 10, 109, // Opcode: VSHF_B
/* 7497 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 7509
/* 7501 */    MCD_OPC_CheckPredicate, 4, 105, 20, // Skip to: 12730
/* 7505 */    MCD_OPC_Decode, 217, 10, 110, // Opcode: VSHF_H
/* 7509 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 7521
/* 7513 */    MCD_OPC_CheckPredicate, 4, 93, 20, // Skip to: 12730
/* 7517 */    MCD_OPC_Decode, 218, 10, 111, // Opcode: VSHF_W
/* 7521 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 7533
/* 7525 */    MCD_OPC_CheckPredicate, 4, 81, 20, // Skip to: 12730
/* 7529 */    MCD_OPC_Decode, 216, 10, 112, // Opcode: VSHF_D
/* 7533 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 7545
/* 7537 */    MCD_OPC_CheckPredicate, 4, 69, 20, // Skip to: 12730
/* 7541 */    MCD_OPC_Decode, 177, 9, 105, // Opcode: SRAR_B
/* 7545 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 7557
/* 7549 */    MCD_OPC_CheckPredicate, 4, 57, 20, // Skip to: 12730
/* 7553 */    MCD_OPC_Decode, 179, 9, 106, // Opcode: SRAR_H
/* 7557 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 7569
/* 7561 */    MCD_OPC_CheckPredicate, 4, 45, 20, // Skip to: 12730
/* 7565 */    MCD_OPC_Decode, 180, 9, 107, // Opcode: SRAR_W
/* 7569 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 7581
/* 7573 */    MCD_OPC_CheckPredicate, 4, 33, 20, // Skip to: 12730
/* 7577 */    MCD_OPC_Decode, 178, 9, 108, // Opcode: SRAR_D
/* 7581 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 7593
/* 7585 */    MCD_OPC_CheckPredicate, 4, 21, 20, // Skip to: 12730
/* 7589 */    MCD_OPC_Decode, 197, 9, 105, // Opcode: SRLR_B
/* 7593 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 7605
/* 7597 */    MCD_OPC_CheckPredicate, 4, 9, 20, // Skip to: 12730
/* 7601 */    MCD_OPC_Decode, 199, 9, 106, // Opcode: SRLR_H
/* 7605 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 7617
/* 7609 */    MCD_OPC_CheckPredicate, 4, 253, 19, // Skip to: 12730
/* 7613 */    MCD_OPC_Decode, 200, 9, 107, // Opcode: SRLR_W
/* 7617 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 7629
/* 7621 */    MCD_OPC_CheckPredicate, 4, 241, 19, // Skip to: 12730
/* 7625 */    MCD_OPC_Decode, 198, 9, 108, // Opcode: SRLR_D
/* 7629 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 7641
/* 7633 */    MCD_OPC_CheckPredicate, 4, 229, 19, // Skip to: 12730
/* 7637 */    MCD_OPC_Decode, 137, 5, 113, // Opcode: HADD_S_H
/* 7641 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 7653
/* 7645 */    MCD_OPC_CheckPredicate, 4, 217, 19, // Skip to: 12730
/* 7649 */    MCD_OPC_Decode, 138, 5, 114, // Opcode: HADD_S_W
/* 7653 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 7665
/* 7657 */    MCD_OPC_CheckPredicate, 4, 205, 19, // Skip to: 12730
/* 7661 */    MCD_OPC_Decode, 136, 5, 115, // Opcode: HADD_S_D
/* 7665 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 7677
/* 7669 */    MCD_OPC_CheckPredicate, 4, 193, 19, // Skip to: 12730
/* 7673 */    MCD_OPC_Decode, 140, 5, 113, // Opcode: HADD_U_H
/* 7677 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 7689
/* 7681 */    MCD_OPC_CheckPredicate, 4, 181, 19, // Skip to: 12730
/* 7685 */    MCD_OPC_Decode, 141, 5, 114, // Opcode: HADD_U_W
/* 7689 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 7701
/* 7693 */    MCD_OPC_CheckPredicate, 4, 169, 19, // Skip to: 12730
/* 7697 */    MCD_OPC_Decode, 139, 5, 115, // Opcode: HADD_U_D
/* 7701 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 7713
/* 7705 */    MCD_OPC_CheckPredicate, 4, 157, 19, // Skip to: 12730
/* 7709 */    MCD_OPC_Decode, 143, 5, 113, // Opcode: HSUB_S_H
/* 7713 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 7725
/* 7717 */    MCD_OPC_CheckPredicate, 4, 145, 19, // Skip to: 12730
/* 7721 */    MCD_OPC_Decode, 144, 5, 114, // Opcode: HSUB_S_W
/* 7725 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 7737
/* 7729 */    MCD_OPC_CheckPredicate, 4, 133, 19, // Skip to: 12730
/* 7733 */    MCD_OPC_Decode, 142, 5, 115, // Opcode: HSUB_S_D
/* 7737 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 7749
/* 7741 */    MCD_OPC_CheckPredicate, 4, 121, 19, // Skip to: 12730
/* 7745 */    MCD_OPC_Decode, 146, 5, 113, // Opcode: HSUB_U_H
/* 7749 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 7761
/* 7753 */    MCD_OPC_CheckPredicate, 4, 109, 19, // Skip to: 12730
/* 7757 */    MCD_OPC_Decode, 147, 5, 114, // Opcode: HSUB_U_W
/* 7761 */    MCD_OPC_FilterValue, 31, 101, 19, // Skip to: 12730
/* 7765 */    MCD_OPC_CheckPredicate, 4, 97, 19, // Skip to: 12730
/* 7769 */    MCD_OPC_Decode, 145, 5, 115, // Opcode: HSUB_U_D
/* 7773 */    MCD_OPC_FilterValue, 25, 162, 1, // Skip to: 8195
/* 7777 */    MCD_OPC_ExtractField, 20, 6,  // Inst{25-20} ...
/* 7780 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 7792
/* 7784 */    MCD_OPC_CheckPredicate, 4, 78, 19, // Skip to: 12730
/* 7788 */    MCD_OPC_Decode, 249, 8, 123, // Opcode: SLDI_B
/* 7792 */    MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 7810
/* 7796 */    MCD_OPC_CheckPredicate, 4, 66, 19, // Skip to: 12730
/* 7800 */    MCD_OPC_CheckField, 19, 1, 0, 60, 19, // Skip to: 12730
/* 7806 */    MCD_OPC_Decode, 251, 8, 124, // Opcode: SLDI_H
/* 7810 */    MCD_OPC_FilterValue, 3, 51, 0, // Skip to: 7865
/* 7814 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 7817 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 7829
/* 7821 */    MCD_OPC_CheckPredicate, 4, 41, 19, // Skip to: 12730
/* 7825 */    MCD_OPC_Decode, 252, 8, 125, // Opcode: SLDI_W
/* 7829 */    MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 7847
/* 7833 */    MCD_OPC_CheckPredicate, 4, 29, 19, // Skip to: 12730
/* 7837 */    MCD_OPC_CheckField, 17, 1, 0, 23, 19, // Skip to: 12730
/* 7843 */    MCD_OPC_Decode, 250, 8, 126, // Opcode: SLDI_D
/* 7847 */    MCD_OPC_FilterValue, 3, 15, 19, // Skip to: 12730
/* 7851 */    MCD_OPC_CheckPredicate, 4, 11, 19, // Skip to: 12730
/* 7855 */    MCD_OPC_CheckField, 16, 2, 2, 5, 19, // Skip to: 12730
/* 7861 */    MCD_OPC_Decode, 207, 2, 127, // Opcode: CTCMSA
/* 7865 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 7877
/* 7869 */    MCD_OPC_CheckPredicate, 4, 249, 18, // Skip to: 12730
/* 7873 */    MCD_OPC_Decode, 160, 9, 123, // Opcode: SPLATI_B
/* 7877 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 7895
/* 7881 */    MCD_OPC_CheckPredicate, 4, 237, 18, // Skip to: 12730
/* 7885 */    MCD_OPC_CheckField, 19, 1, 0, 231, 18, // Skip to: 12730
/* 7891 */    MCD_OPC_Decode, 162, 9, 124, // Opcode: SPLATI_H
/* 7895 */    MCD_OPC_FilterValue, 7, 52, 0, // Skip to: 7951
/* 7899 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 7902 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 7914
/* 7906 */    MCD_OPC_CheckPredicate, 4, 212, 18, // Skip to: 12730
/* 7910 */    MCD_OPC_Decode, 163, 9, 125, // Opcode: SPLATI_W
/* 7914 */    MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 7932
/* 7918 */    MCD_OPC_CheckPredicate, 4, 200, 18, // Skip to: 12730
/* 7922 */    MCD_OPC_CheckField, 17, 1, 0, 194, 18, // Skip to: 12730
/* 7928 */    MCD_OPC_Decode, 161, 9, 126, // Opcode: SPLATI_D
/* 7932 */    MCD_OPC_FilterValue, 3, 186, 18, // Skip to: 12730
/* 7936 */    MCD_OPC_CheckPredicate, 4, 182, 18, // Skip to: 12730
/* 7940 */    MCD_OPC_CheckField, 16, 2, 2, 176, 18, // Skip to: 12730
/* 7946 */    MCD_OPC_Decode, 148, 2, 128, 1, // Opcode: CFCMSA
/* 7951 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 7964
/* 7955 */    MCD_OPC_CheckPredicate, 4, 163, 18, // Skip to: 12730
/* 7959 */    MCD_OPC_Decode, 200, 2, 129, 1, // Opcode: COPY_S_B
/* 7964 */    MCD_OPC_FilterValue, 10, 15, 0, // Skip to: 7983
/* 7968 */    MCD_OPC_CheckPredicate, 4, 150, 18, // Skip to: 12730
/* 7972 */    MCD_OPC_CheckField, 19, 1, 0, 144, 18, // Skip to: 12730
/* 7978 */    MCD_OPC_Decode, 201, 2, 130, 1, // Opcode: COPY_S_H
/* 7983 */    MCD_OPC_FilterValue, 11, 35, 0, // Skip to: 8022
/* 7987 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 7990 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8003
/* 7994 */    MCD_OPC_CheckPredicate, 4, 124, 18, // Skip to: 12730
/* 7998 */    MCD_OPC_Decode, 202, 2, 131, 1, // Opcode: COPY_S_W
/* 8003 */    MCD_OPC_FilterValue, 3, 115, 18, // Skip to: 12730
/* 8007 */    MCD_OPC_CheckPredicate, 4, 111, 18, // Skip to: 12730
/* 8011 */    MCD_OPC_CheckField, 16, 2, 2, 105, 18, // Skip to: 12730
/* 8017 */    MCD_OPC_Decode, 222, 6, 132, 1, // Opcode: MOVE_V
/* 8022 */    MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 8035
/* 8026 */    MCD_OPC_CheckPredicate, 4, 92, 18, // Skip to: 12730
/* 8030 */    MCD_OPC_Decode, 203, 2, 129, 1, // Opcode: COPY_U_B
/* 8035 */    MCD_OPC_FilterValue, 14, 15, 0, // Skip to: 8054
/* 8039 */    MCD_OPC_CheckPredicate, 4, 79, 18, // Skip to: 12730
/* 8043 */    MCD_OPC_CheckField, 19, 1, 0, 73, 18, // Skip to: 12730
/* 8049 */    MCD_OPC_Decode, 204, 2, 130, 1, // Opcode: COPY_U_H
/* 8054 */    MCD_OPC_FilterValue, 15, 15, 0, // Skip to: 8073
/* 8058 */    MCD_OPC_CheckPredicate, 4, 60, 18, // Skip to: 12730
/* 8062 */    MCD_OPC_CheckField, 18, 2, 0, 54, 18, // Skip to: 12730
/* 8068 */    MCD_OPC_Decode, 205, 2, 131, 1, // Opcode: COPY_U_W
/* 8073 */    MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 8086
/* 8077 */    MCD_OPC_CheckPredicate, 4, 41, 18, // Skip to: 12730
/* 8081 */    MCD_OPC_Decode, 165, 5, 133, 1, // Opcode: INSERT_B
/* 8086 */    MCD_OPC_FilterValue, 18, 15, 0, // Skip to: 8105
/* 8090 */    MCD_OPC_CheckPredicate, 4, 28, 18, // Skip to: 12730
/* 8094 */    MCD_OPC_CheckField, 19, 1, 0, 22, 18, // Skip to: 12730
/* 8100 */    MCD_OPC_Decode, 168, 5, 134, 1, // Opcode: INSERT_H
/* 8105 */    MCD_OPC_FilterValue, 19, 15, 0, // Skip to: 8124
/* 8109 */    MCD_OPC_CheckPredicate, 4, 9, 18, // Skip to: 12730
/* 8113 */    MCD_OPC_CheckField, 18, 2, 0, 3, 18, // Skip to: 12730
/* 8119 */    MCD_OPC_Decode, 169, 5, 135, 1, // Opcode: INSERT_W
/* 8124 */    MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 8137
/* 8128 */    MCD_OPC_CheckPredicate, 4, 246, 17, // Skip to: 12730
/* 8132 */    MCD_OPC_Decode, 171, 5, 136, 1, // Opcode: INSVE_B
/* 8137 */    MCD_OPC_FilterValue, 22, 15, 0, // Skip to: 8156
/* 8141 */    MCD_OPC_CheckPredicate, 4, 233, 17, // Skip to: 12730
/* 8145 */    MCD_OPC_CheckField, 19, 1, 0, 227, 17, // Skip to: 12730
/* 8151 */    MCD_OPC_Decode, 173, 5, 137, 1, // Opcode: INSVE_H
/* 8156 */    MCD_OPC_FilterValue, 23, 218, 17, // Skip to: 12730
/* 8160 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 8163 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8176
/* 8167 */    MCD_OPC_CheckPredicate, 4, 207, 17, // Skip to: 12730
/* 8171 */    MCD_OPC_Decode, 174, 5, 138, 1, // Opcode: INSVE_W
/* 8176 */    MCD_OPC_FilterValue, 2, 198, 17, // Skip to: 12730
/* 8180 */    MCD_OPC_CheckPredicate, 4, 194, 17, // Skip to: 12730
/* 8184 */    MCD_OPC_CheckField, 17, 1, 0, 188, 17, // Skip to: 12730
/* 8190 */    MCD_OPC_Decode, 172, 5, 139, 1, // Opcode: INSVE_D
/* 8195 */    MCD_OPC_FilterValue, 26, 131, 1, // Skip to: 8586
/* 8199 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 8202 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 8214
/* 8206 */    MCD_OPC_CheckPredicate, 4, 168, 17, // Skip to: 12730
/* 8210 */    MCD_OPC_Decode, 131, 4, 107, // Opcode: FCAF_W
/* 8214 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 8226
/* 8218 */    MCD_OPC_CheckPredicate, 4, 156, 17, // Skip to: 12730
/* 8222 */    MCD_OPC_Decode, 130, 4, 108, // Opcode: FCAF_D
/* 8226 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 8238
/* 8230 */    MCD_OPC_CheckPredicate, 4, 144, 17, // Skip to: 12730
/* 8234 */    MCD_OPC_Decode, 156, 4, 107, // Opcode: FCUN_W
/* 8238 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 8250
/* 8242 */    MCD_OPC_CheckPredicate, 4, 132, 17, // Skip to: 12730
/* 8246 */    MCD_OPC_Decode, 155, 4, 108, // Opcode: FCUN_D
/* 8250 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 8262
/* 8254 */    MCD_OPC_CheckPredicate, 4, 120, 17, // Skip to: 12730
/* 8258 */    MCD_OPC_Decode, 133, 4, 107, // Opcode: FCEQ_W
/* 8262 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 8274
/* 8266 */    MCD_OPC_CheckPredicate, 4, 108, 17, // Skip to: 12730
/* 8270 */    MCD_OPC_Decode, 132, 4, 108, // Opcode: FCEQ_D
/* 8274 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 8286
/* 8278 */    MCD_OPC_CheckPredicate, 4, 96, 17, // Skip to: 12730
/* 8282 */    MCD_OPC_Decode, 148, 4, 107, // Opcode: FCUEQ_W
/* 8286 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 8298
/* 8290 */    MCD_OPC_CheckPredicate, 4, 84, 17, // Skip to: 12730
/* 8294 */    MCD_OPC_Decode, 147, 4, 108, // Opcode: FCUEQ_D
/* 8298 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 8310
/* 8302 */    MCD_OPC_CheckPredicate, 4, 72, 17, // Skip to: 12730
/* 8306 */    MCD_OPC_Decode, 139, 4, 107, // Opcode: FCLT_W
/* 8310 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 8322
/* 8314 */    MCD_OPC_CheckPredicate, 4, 60, 17, // Skip to: 12730
/* 8318 */    MCD_OPC_Decode, 138, 4, 108, // Opcode: FCLT_D
/* 8322 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 8334
/* 8326 */    MCD_OPC_CheckPredicate, 4, 48, 17, // Skip to: 12730
/* 8330 */    MCD_OPC_Decode, 152, 4, 107, // Opcode: FCULT_W
/* 8334 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 8346
/* 8338 */    MCD_OPC_CheckPredicate, 4, 36, 17, // Skip to: 12730
/* 8342 */    MCD_OPC_Decode, 151, 4, 108, // Opcode: FCULT_D
/* 8346 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 8358
/* 8350 */    MCD_OPC_CheckPredicate, 4, 24, 17, // Skip to: 12730
/* 8354 */    MCD_OPC_Decode, 137, 4, 107, // Opcode: FCLE_W
/* 8358 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 8370
/* 8362 */    MCD_OPC_CheckPredicate, 4, 12, 17, // Skip to: 12730
/* 8366 */    MCD_OPC_Decode, 136, 4, 108, // Opcode: FCLE_D
/* 8370 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 8382
/* 8374 */    MCD_OPC_CheckPredicate, 4, 0, 17, // Skip to: 12730
/* 8378 */    MCD_OPC_Decode, 150, 4, 107, // Opcode: FCULE_W
/* 8382 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 8394
/* 8386 */    MCD_OPC_CheckPredicate, 4, 244, 16, // Skip to: 12730
/* 8390 */    MCD_OPC_Decode, 149, 4, 108, // Opcode: FCULE_D
/* 8394 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 8406
/* 8398 */    MCD_OPC_CheckPredicate, 4, 232, 16, // Skip to: 12730
/* 8402 */    MCD_OPC_Decode, 222, 4, 107, // Opcode: FSAF_W
/* 8406 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 8418
/* 8410 */    MCD_OPC_CheckPredicate, 4, 220, 16, // Skip to: 12730
/* 8414 */    MCD_OPC_Decode, 221, 4, 108, // Opcode: FSAF_D
/* 8418 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 8430
/* 8422 */    MCD_OPC_CheckPredicate, 4, 208, 16, // Skip to: 12730
/* 8426 */    MCD_OPC_Decode, 252, 4, 107, // Opcode: FSUN_W
/* 8430 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 8442
/* 8434 */    MCD_OPC_CheckPredicate, 4, 196, 16, // Skip to: 12730
/* 8438 */    MCD_OPC_Decode, 251, 4, 108, // Opcode: FSUN_D
/* 8442 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 8454
/* 8446 */    MCD_OPC_CheckPredicate, 4, 184, 16, // Skip to: 12730
/* 8450 */    MCD_OPC_Decode, 224, 4, 107, // Opcode: FSEQ_W
/* 8454 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 8466
/* 8458 */    MCD_OPC_CheckPredicate, 4, 172, 16, // Skip to: 12730
/* 8462 */    MCD_OPC_Decode, 223, 4, 108, // Opcode: FSEQ_D
/* 8466 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 8478
/* 8470 */    MCD_OPC_CheckPredicate, 4, 160, 16, // Skip to: 12730
/* 8474 */    MCD_OPC_Decode, 244, 4, 107, // Opcode: FSUEQ_W
/* 8478 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 8490
/* 8482 */    MCD_OPC_CheckPredicate, 4, 148, 16, // Skip to: 12730
/* 8486 */    MCD_OPC_Decode, 243, 4, 108, // Opcode: FSUEQ_D
/* 8490 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 8502
/* 8494 */    MCD_OPC_CheckPredicate, 4, 136, 16, // Skip to: 12730
/* 8498 */    MCD_OPC_Decode, 228, 4, 107, // Opcode: FSLT_W
/* 8502 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 8514
/* 8506 */    MCD_OPC_CheckPredicate, 4, 124, 16, // Skip to: 12730
/* 8510 */    MCD_OPC_Decode, 227, 4, 108, // Opcode: FSLT_D
/* 8514 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 8526
/* 8518 */    MCD_OPC_CheckPredicate, 4, 112, 16, // Skip to: 12730
/* 8522 */    MCD_OPC_Decode, 248, 4, 107, // Opcode: FSULT_W
/* 8526 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 8538
/* 8530 */    MCD_OPC_CheckPredicate, 4, 100, 16, // Skip to: 12730
/* 8534 */    MCD_OPC_Decode, 247, 4, 108, // Opcode: FSULT_D
/* 8538 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 8550
/* 8542 */    MCD_OPC_CheckPredicate, 4, 88, 16, // Skip to: 12730
/* 8546 */    MCD_OPC_Decode, 226, 4, 107, // Opcode: FSLE_W
/* 8550 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 8562
/* 8554 */    MCD_OPC_CheckPredicate, 4, 76, 16, // Skip to: 12730
/* 8558 */    MCD_OPC_Decode, 225, 4, 108, // Opcode: FSLE_D
/* 8562 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 8574
/* 8566 */    MCD_OPC_CheckPredicate, 4, 64, 16, // Skip to: 12730
/* 8570 */    MCD_OPC_Decode, 246, 4, 107, // Opcode: FSULE_W
/* 8574 */    MCD_OPC_FilterValue, 31, 56, 16, // Skip to: 12730
/* 8578 */    MCD_OPC_CheckPredicate, 4, 52, 16, // Skip to: 12730
/* 8582 */    MCD_OPC_Decode, 245, 4, 108, // Opcode: FSULE_D
/* 8586 */    MCD_OPC_FilterValue, 27, 63, 1, // Skip to: 8909
/* 8590 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 8593 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 8605
/* 8597 */    MCD_OPC_CheckPredicate, 4, 33, 16, // Skip to: 12730
/* 8601 */    MCD_OPC_Decode, 129, 4, 107, // Opcode: FADD_W
/* 8605 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 8617
/* 8609 */    MCD_OPC_CheckPredicate, 4, 21, 16, // Skip to: 12730
/* 8613 */    MCD_OPC_Decode, 253, 3, 108, // Opcode: FADD_D
/* 8617 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 8629
/* 8621 */    MCD_OPC_CheckPredicate, 4, 9, 16, // Skip to: 12730
/* 8625 */    MCD_OPC_Decode, 242, 4, 107, // Opcode: FSUB_W
/* 8629 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 8641
/* 8633 */    MCD_OPC_CheckPredicate, 4, 253, 15, // Skip to: 12730
/* 8637 */    MCD_OPC_Decode, 238, 4, 108, // Opcode: FSUB_D
/* 8641 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 8653
/* 8645 */    MCD_OPC_CheckPredicate, 4, 241, 15, // Skip to: 12730
/* 8649 */    MCD_OPC_Decode, 211, 4, 107, // Opcode: FMUL_W
/* 8653 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 8665
/* 8657 */    MCD_OPC_CheckPredicate, 4, 229, 15, // Skip to: 12730
/* 8661 */    MCD_OPC_Decode, 207, 4, 108, // Opcode: FMUL_D
/* 8665 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 8677
/* 8669 */    MCD_OPC_CheckPredicate, 4, 217, 15, // Skip to: 12730
/* 8673 */    MCD_OPC_Decode, 161, 4, 107, // Opcode: FDIV_W
/* 8677 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 8689
/* 8681 */    MCD_OPC_CheckPredicate, 4, 205, 15, // Skip to: 12730
/* 8685 */    MCD_OPC_Decode, 157, 4, 108, // Opcode: FDIV_D
/* 8689 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 8701
/* 8693 */    MCD_OPC_CheckPredicate, 4, 193, 15, // Skip to: 12730
/* 8697 */    MCD_OPC_Decode, 193, 4, 111, // Opcode: FMADD_W
/* 8701 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 8713
/* 8705 */    MCD_OPC_CheckPredicate, 4, 181, 15, // Skip to: 12730
/* 8709 */    MCD_OPC_Decode, 192, 4, 112, // Opcode: FMADD_D
/* 8713 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 8725
/* 8717 */    MCD_OPC_CheckPredicate, 4, 169, 15, // Skip to: 12730
/* 8721 */    MCD_OPC_Decode, 206, 4, 111, // Opcode: FMSUB_W
/* 8725 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 8737
/* 8729 */    MCD_OPC_CheckPredicate, 4, 157, 15, // Skip to: 12730
/* 8733 */    MCD_OPC_Decode, 205, 4, 112, // Opcode: FMSUB_D
/* 8737 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 8749
/* 8741 */    MCD_OPC_CheckPredicate, 4, 145, 15, // Skip to: 12730
/* 8745 */    MCD_OPC_Decode, 166, 4, 107, // Opcode: FEXP2_W
/* 8749 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 8761
/* 8753 */    MCD_OPC_CheckPredicate, 4, 133, 15, // Skip to: 12730
/* 8757 */    MCD_OPC_Decode, 164, 4, 108, // Opcode: FEXP2_D
/* 8761 */    MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 8774
/* 8765 */    MCD_OPC_CheckPredicate, 4, 121, 15, // Skip to: 12730
/* 8769 */    MCD_OPC_Decode, 162, 4, 140, 1, // Opcode: FEXDO_H
/* 8774 */    MCD_OPC_FilterValue, 17, 9, 0, // Skip to: 8787
/* 8778 */    MCD_OPC_CheckPredicate, 4, 108, 15, // Skip to: 12730
/* 8782 */    MCD_OPC_Decode, 163, 4, 141, 1, // Opcode: FEXDO_W
/* 8787 */    MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 8800
/* 8791 */    MCD_OPC_CheckPredicate, 4, 95, 15, // Skip to: 12730
/* 8795 */    MCD_OPC_Decode, 129, 5, 140, 1, // Opcode: FTQ_H
/* 8800 */    MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 8813
/* 8804 */    MCD_OPC_CheckPredicate, 4, 82, 15, // Skip to: 12730
/* 8808 */    MCD_OPC_Decode, 130, 5, 141, 1, // Opcode: FTQ_W
/* 8813 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 8825
/* 8817 */    MCD_OPC_CheckPredicate, 4, 69, 15, // Skip to: 12730
/* 8821 */    MCD_OPC_Decode, 201, 4, 107, // Opcode: FMIN_W
/* 8825 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 8837
/* 8829 */    MCD_OPC_CheckPredicate, 4, 57, 15, // Skip to: 12730
/* 8833 */    MCD_OPC_Decode, 200, 4, 108, // Opcode: FMIN_D
/* 8837 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 8849
/* 8841 */    MCD_OPC_CheckPredicate, 4, 45, 15, // Skip to: 12730
/* 8845 */    MCD_OPC_Decode, 199, 4, 107, // Opcode: FMIN_A_W
/* 8849 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 8861
/* 8853 */    MCD_OPC_CheckPredicate, 4, 33, 15, // Skip to: 12730
/* 8857 */    MCD_OPC_Decode, 198, 4, 108, // Opcode: FMIN_A_D
/* 8861 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 8873
/* 8865 */    MCD_OPC_CheckPredicate, 4, 21, 15, // Skip to: 12730
/* 8869 */    MCD_OPC_Decode, 197, 4, 107, // Opcode: FMAX_W
/* 8873 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 8885
/* 8877 */    MCD_OPC_CheckPredicate, 4, 9, 15, // Skip to: 12730
/* 8881 */    MCD_OPC_Decode, 196, 4, 108, // Opcode: FMAX_D
/* 8885 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 8897
/* 8889 */    MCD_OPC_CheckPredicate, 4, 253, 14, // Skip to: 12730
/* 8893 */    MCD_OPC_Decode, 195, 4, 107, // Opcode: FMAX_A_W
/* 8897 */    MCD_OPC_FilterValue, 31, 245, 14, // Skip to: 12730
/* 8901 */    MCD_OPC_CheckPredicate, 4, 241, 14, // Skip to: 12730
/* 8905 */    MCD_OPC_Decode, 194, 4, 108, // Opcode: FMAX_A_D
/* 8909 */    MCD_OPC_FilterValue, 28, 35, 1, // Skip to: 9204
/* 8913 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 8916 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 8928
/* 8920 */    MCD_OPC_CheckPredicate, 4, 222, 14, // Skip to: 12730
/* 8924 */    MCD_OPC_Decode, 146, 4, 107, // Opcode: FCOR_W
/* 8928 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 8940
/* 8932 */    MCD_OPC_CheckPredicate, 4, 210, 14, // Skip to: 12730
/* 8936 */    MCD_OPC_Decode, 145, 4, 108, // Opcode: FCOR_D
/* 8940 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 8952
/* 8944 */    MCD_OPC_CheckPredicate, 4, 198, 14, // Skip to: 12730
/* 8948 */    MCD_OPC_Decode, 154, 4, 107, // Opcode: FCUNE_W
/* 8952 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 8964
/* 8956 */    MCD_OPC_CheckPredicate, 4, 186, 14, // Skip to: 12730
/* 8960 */    MCD_OPC_Decode, 153, 4, 108, // Opcode: FCUNE_D
/* 8964 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 8976
/* 8968 */    MCD_OPC_CheckPredicate, 4, 174, 14, // Skip to: 12730
/* 8972 */    MCD_OPC_Decode, 144, 4, 107, // Opcode: FCNE_W
/* 8976 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 8988
/* 8980 */    MCD_OPC_CheckPredicate, 4, 162, 14, // Skip to: 12730
/* 8984 */    MCD_OPC_Decode, 143, 4, 108, // Opcode: FCNE_D
/* 8988 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 9000
/* 8992 */    MCD_OPC_CheckPredicate, 4, 150, 14, // Skip to: 12730
/* 8996 */    MCD_OPC_Decode, 182, 7, 106, // Opcode: MUL_Q_H
/* 9000 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 9012
/* 9004 */    MCD_OPC_CheckPredicate, 4, 138, 14, // Skip to: 12730
/* 9008 */    MCD_OPC_Decode, 183, 7, 107, // Opcode: MUL_Q_W
/* 9012 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 9024
/* 9016 */    MCD_OPC_CheckPredicate, 4, 126, 14, // Skip to: 12730
/* 9020 */    MCD_OPC_Decode, 152, 6, 110, // Opcode: MADD_Q_H
/* 9024 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 9036
/* 9028 */    MCD_OPC_CheckPredicate, 4, 114, 14, // Skip to: 12730
/* 9032 */    MCD_OPC_Decode, 153, 6, 111, // Opcode: MADD_Q_W
/* 9036 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 9048
/* 9040 */    MCD_OPC_CheckPredicate, 4, 102, 14, // Skip to: 12730
/* 9044 */    MCD_OPC_Decode, 141, 7, 110, // Opcode: MSUB_Q_H
/* 9048 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 9060
/* 9052 */    MCD_OPC_CheckPredicate, 4, 90, 14, // Skip to: 12730
/* 9056 */    MCD_OPC_Decode, 142, 7, 111, // Opcode: MSUB_Q_W
/* 9060 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 9072
/* 9064 */    MCD_OPC_CheckPredicate, 4, 78, 14, // Skip to: 12730
/* 9068 */    MCD_OPC_Decode, 232, 4, 107, // Opcode: FSOR_W
/* 9072 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 9084
/* 9076 */    MCD_OPC_CheckPredicate, 4, 66, 14, // Skip to: 12730
/* 9080 */    MCD_OPC_Decode, 231, 4, 108, // Opcode: FSOR_D
/* 9084 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 9096
/* 9088 */    MCD_OPC_CheckPredicate, 4, 54, 14, // Skip to: 12730
/* 9092 */    MCD_OPC_Decode, 250, 4, 107, // Opcode: FSUNE_W
/* 9096 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 9108
/* 9100 */    MCD_OPC_CheckPredicate, 4, 42, 14, // Skip to: 12730
/* 9104 */    MCD_OPC_Decode, 249, 4, 108, // Opcode: FSUNE_D
/* 9108 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 9120
/* 9112 */    MCD_OPC_CheckPredicate, 4, 30, 14, // Skip to: 12730
/* 9116 */    MCD_OPC_Decode, 230, 4, 107, // Opcode: FSNE_W
/* 9120 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 9132
/* 9124 */    MCD_OPC_CheckPredicate, 4, 18, 14, // Skip to: 12730
/* 9128 */    MCD_OPC_Decode, 229, 4, 108, // Opcode: FSNE_D
/* 9132 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 9144
/* 9136 */    MCD_OPC_CheckPredicate, 4, 6, 14, // Skip to: 12730
/* 9140 */    MCD_OPC_Decode, 166, 7, 106, // Opcode: MULR_Q_H
/* 9144 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 9156
/* 9148 */    MCD_OPC_CheckPredicate, 4, 250, 13, // Skip to: 12730
/* 9152 */    MCD_OPC_Decode, 167, 7, 107, // Opcode: MULR_Q_W
/* 9156 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 9168
/* 9160 */    MCD_OPC_CheckPredicate, 4, 238, 13, // Skip to: 12730
/* 9164 */    MCD_OPC_Decode, 139, 6, 110, // Opcode: MADDR_Q_H
/* 9168 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 9180
/* 9172 */    MCD_OPC_CheckPredicate, 4, 226, 13, // Skip to: 12730
/* 9176 */    MCD_OPC_Decode, 140, 6, 111, // Opcode: MADDR_Q_W
/* 9180 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 9192
/* 9184 */    MCD_OPC_CheckPredicate, 4, 214, 13, // Skip to: 12730
/* 9188 */    MCD_OPC_Decode, 128, 7, 110, // Opcode: MSUBR_Q_H
/* 9192 */    MCD_OPC_FilterValue, 29, 206, 13, // Skip to: 12730
/* 9196 */    MCD_OPC_CheckPredicate, 4, 202, 13, // Skip to: 12730
/* 9200 */    MCD_OPC_Decode, 129, 7, 111, // Opcode: MSUBR_Q_W
/* 9204 */    MCD_OPC_FilterValue, 30, 199, 2, // Skip to: 9919
/* 9208 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 9211 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 9222
/* 9215 */    MCD_OPC_CheckPredicate, 4, 183, 13, // Skip to: 12730
/* 9219 */    MCD_OPC_Decode, 75, 105, // Opcode: AND_V
/* 9222 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 9234
/* 9226 */    MCD_OPC_CheckPredicate, 4, 172, 13, // Skip to: 12730
/* 9230 */    MCD_OPC_Decode, 222, 7, 105, // Opcode: OR_V
/* 9234 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 9246
/* 9238 */    MCD_OPC_CheckPredicate, 4, 160, 13, // Skip to: 12730
/* 9242 */    MCD_OPC_Decode, 212, 7, 105, // Opcode: NOR_V
/* 9246 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 9258
/* 9250 */    MCD_OPC_CheckPredicate, 4, 148, 13, // Skip to: 12730
/* 9254 */    MCD_OPC_Decode, 227, 10, 105, // Opcode: XOR_V
/* 9258 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 9270
/* 9262 */    MCD_OPC_CheckPredicate, 4, 136, 13, // Skip to: 12730
/* 9266 */    MCD_OPC_Decode, 198, 1, 109, // Opcode: BMNZ_V
/* 9270 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 9282
/* 9274 */    MCD_OPC_CheckPredicate, 4, 124, 13, // Skip to: 12730
/* 9278 */    MCD_OPC_Decode, 200, 1, 109, // Opcode: BMZ_V
/* 9282 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 9294
/* 9286 */    MCD_OPC_CheckPredicate, 4, 112, 13, // Skip to: 12730
/* 9290 */    MCD_OPC_Decode, 225, 1, 109, // Opcode: BSEL_V
/* 9294 */    MCD_OPC_FilterValue, 24, 198, 0, // Skip to: 9496
/* 9298 */    MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 9301 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 9314
/* 9305 */    MCD_OPC_CheckPredicate, 4, 93, 13, // Skip to: 12730
/* 9309 */    MCD_OPC_Decode, 180, 4, 142, 1, // Opcode: FILL_B
/* 9314 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 9327
/* 9318 */    MCD_OPC_CheckPredicate, 4, 80, 13, // Skip to: 12730
/* 9322 */    MCD_OPC_Decode, 183, 4, 143, 1, // Opcode: FILL_H
/* 9327 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 9340
/* 9331 */    MCD_OPC_CheckPredicate, 4, 67, 13, // Skip to: 12730
/* 9335 */    MCD_OPC_Decode, 184, 4, 144, 1, // Opcode: FILL_W
/* 9340 */    MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 9353
/* 9344 */    MCD_OPC_CheckPredicate, 4, 54, 13, // Skip to: 12730
/* 9348 */    MCD_OPC_Decode, 239, 7, 132, 1, // Opcode: PCNT_B
/* 9353 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 9366
/* 9357 */    MCD_OPC_CheckPredicate, 4, 41, 13, // Skip to: 12730
/* 9361 */    MCD_OPC_Decode, 241, 7, 145, 1, // Opcode: PCNT_H
/* 9366 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 9379
/* 9370 */    MCD_OPC_CheckPredicate, 4, 28, 13, // Skip to: 12730
/* 9374 */    MCD_OPC_Decode, 242, 7, 146, 1, // Opcode: PCNT_W
/* 9379 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 9392
/* 9383 */    MCD_OPC_CheckPredicate, 4, 15, 13, // Skip to: 12730
/* 9387 */    MCD_OPC_Decode, 240, 7, 147, 1, // Opcode: PCNT_D
/* 9392 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 9405
/* 9396 */    MCD_OPC_CheckPredicate, 4, 2, 13, // Skip to: 12730
/* 9400 */    MCD_OPC_Decode, 193, 7, 132, 1, // Opcode: NLOC_B
/* 9405 */    MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 9418
/* 9409 */    MCD_OPC_CheckPredicate, 4, 245, 12, // Skip to: 12730
/* 9413 */    MCD_OPC_Decode, 195, 7, 145, 1, // Opcode: NLOC_H
/* 9418 */    MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 9431
/* 9422 */    MCD_OPC_CheckPredicate, 4, 232, 12, // Skip to: 12730
/* 9426 */    MCD_OPC_Decode, 196, 7, 146, 1, // Opcode: NLOC_W
/* 9431 */    MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 9444
/* 9435 */    MCD_OPC_CheckPredicate, 4, 219, 12, // Skip to: 12730
/* 9439 */    MCD_OPC_Decode, 194, 7, 147, 1, // Opcode: NLOC_D
/* 9444 */    MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 9457
/* 9448 */    MCD_OPC_CheckPredicate, 4, 206, 12, // Skip to: 12730
/* 9452 */    MCD_OPC_Decode, 197, 7, 132, 1, // Opcode: NLZC_B
/* 9457 */    MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 9470
/* 9461 */    MCD_OPC_CheckPredicate, 4, 193, 12, // Skip to: 12730
/* 9465 */    MCD_OPC_Decode, 199, 7, 145, 1, // Opcode: NLZC_H
/* 9470 */    MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 9483
/* 9474 */    MCD_OPC_CheckPredicate, 4, 180, 12, // Skip to: 12730
/* 9478 */    MCD_OPC_Decode, 200, 7, 146, 1, // Opcode: NLZC_W
/* 9483 */    MCD_OPC_FilterValue, 15, 171, 12, // Skip to: 12730
/* 9487 */    MCD_OPC_CheckPredicate, 4, 167, 12, // Skip to: 12730
/* 9491 */    MCD_OPC_Decode, 198, 7, 147, 1, // Opcode: NLZC_D
/* 9496 */    MCD_OPC_FilterValue, 25, 158, 12, // Skip to: 12730
/* 9500 */    MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 9503 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 9516
/* 9507 */    MCD_OPC_CheckPredicate, 4, 147, 12, // Skip to: 12730
/* 9511 */    MCD_OPC_Decode, 135, 4, 146, 1, // Opcode: FCLASS_W
/* 9516 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 9529
/* 9520 */    MCD_OPC_CheckPredicate, 4, 134, 12, // Skip to: 12730
/* 9524 */    MCD_OPC_Decode, 134, 4, 147, 1, // Opcode: FCLASS_D
/* 9529 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 9542
/* 9533 */    MCD_OPC_CheckPredicate, 4, 121, 12, // Skip to: 12730
/* 9537 */    MCD_OPC_Decode, 132, 5, 146, 1, // Opcode: FTRUNC_S_W
/* 9542 */    MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 9555
/* 9546 */    MCD_OPC_CheckPredicate, 4, 108, 12, // Skip to: 12730
/* 9550 */    MCD_OPC_Decode, 131, 5, 147, 1, // Opcode: FTRUNC_S_D
/* 9555 */    MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 9568
/* 9559 */    MCD_OPC_CheckPredicate, 4, 95, 12, // Skip to: 12730
/* 9563 */    MCD_OPC_Decode, 134, 5, 146, 1, // Opcode: FTRUNC_U_W
/* 9568 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 9581
/* 9572 */    MCD_OPC_CheckPredicate, 4, 82, 12, // Skip to: 12730
/* 9576 */    MCD_OPC_Decode, 133, 5, 147, 1, // Opcode: FTRUNC_U_D
/* 9581 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 9594
/* 9585 */    MCD_OPC_CheckPredicate, 4, 69, 12, // Skip to: 12730
/* 9589 */    MCD_OPC_Decode, 237, 4, 146, 1, // Opcode: FSQRT_W
/* 9594 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 9607
/* 9598 */    MCD_OPC_CheckPredicate, 4, 56, 12, // Skip to: 12730
/* 9602 */    MCD_OPC_Decode, 233, 4, 147, 1, // Opcode: FSQRT_D
/* 9607 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 9620
/* 9611 */    MCD_OPC_CheckPredicate, 4, 43, 12, // Skip to: 12730
/* 9615 */    MCD_OPC_Decode, 220, 4, 146, 1, // Opcode: FRSQRT_W
/* 9620 */    MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 9633
/* 9624 */    MCD_OPC_CheckPredicate, 4, 30, 12, // Skip to: 12730
/* 9628 */    MCD_OPC_Decode, 219, 4, 147, 1, // Opcode: FRSQRT_D
/* 9633 */    MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 9646
/* 9637 */    MCD_OPC_CheckPredicate, 4, 17, 12, // Skip to: 12730
/* 9641 */    MCD_OPC_Decode, 216, 4, 146, 1, // Opcode: FRCP_W
/* 9646 */    MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 9659
/* 9650 */    MCD_OPC_CheckPredicate, 4, 4, 12, // Skip to: 12730
/* 9654 */    MCD_OPC_Decode, 215, 4, 147, 1, // Opcode: FRCP_D
/* 9659 */    MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 9672
/* 9663 */    MCD_OPC_CheckPredicate, 4, 247, 11, // Skip to: 12730
/* 9667 */    MCD_OPC_Decode, 218, 4, 146, 1, // Opcode: FRINT_W
/* 9672 */    MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 9685
/* 9676 */    MCD_OPC_CheckPredicate, 4, 234, 11, // Skip to: 12730
/* 9680 */    MCD_OPC_Decode, 217, 4, 147, 1, // Opcode: FRINT_D
/* 9685 */    MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 9698
/* 9689 */    MCD_OPC_CheckPredicate, 4, 221, 11, // Skip to: 12730
/* 9693 */    MCD_OPC_Decode, 186, 4, 146, 1, // Opcode: FLOG2_W
/* 9698 */    MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 9711
/* 9702 */    MCD_OPC_CheckPredicate, 4, 208, 11, // Skip to: 12730
/* 9706 */    MCD_OPC_Decode, 185, 4, 147, 1, // Opcode: FLOG2_D
/* 9711 */    MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 9724
/* 9715 */    MCD_OPC_CheckPredicate, 4, 195, 11, // Skip to: 12730
/* 9719 */    MCD_OPC_Decode, 169, 4, 148, 1, // Opcode: FEXUPL_W
/* 9724 */    MCD_OPC_FilterValue, 17, 9, 0, // Skip to: 9737
/* 9728 */    MCD_OPC_CheckPredicate, 4, 182, 11, // Skip to: 12730
/* 9732 */    MCD_OPC_Decode, 168, 4, 149, 1, // Opcode: FEXUPL_D
/* 9737 */    MCD_OPC_FilterValue, 18, 9, 0, // Skip to: 9750
/* 9741 */    MCD_OPC_CheckPredicate, 4, 169, 11, // Skip to: 12730
/* 9745 */    MCD_OPC_Decode, 171, 4, 148, 1, // Opcode: FEXUPR_W
/* 9750 */    MCD_OPC_FilterValue, 19, 9, 0, // Skip to: 9763
/* 9754 */    MCD_OPC_CheckPredicate, 4, 156, 11, // Skip to: 12730
/* 9758 */    MCD_OPC_Decode, 170, 4, 149, 1, // Opcode: FEXUPR_D
/* 9763 */    MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 9776
/* 9767 */    MCD_OPC_CheckPredicate, 4, 143, 11, // Skip to: 12730
/* 9771 */    MCD_OPC_Decode, 177, 4, 148, 1, // Opcode: FFQL_W
/* 9776 */    MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 9789
/* 9780 */    MCD_OPC_CheckPredicate, 4, 130, 11, // Skip to: 12730
/* 9784 */    MCD_OPC_Decode, 176, 4, 149, 1, // Opcode: FFQL_D
/* 9789 */    MCD_OPC_FilterValue, 22, 9, 0, // Skip to: 9802
/* 9793 */    MCD_OPC_CheckPredicate, 4, 117, 11, // Skip to: 12730
/* 9797 */    MCD_OPC_Decode, 179, 4, 148, 1, // Opcode: FFQR_W
/* 9802 */    MCD_OPC_FilterValue, 23, 9, 0, // Skip to: 9815
/* 9806 */    MCD_OPC_CheckPredicate, 4, 104, 11, // Skip to: 12730
/* 9810 */    MCD_OPC_Decode, 178, 4, 149, 1, // Opcode: FFQR_D
/* 9815 */    MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 9828
/* 9819 */    MCD_OPC_CheckPredicate, 4, 91, 11, // Skip to: 12730
/* 9823 */    MCD_OPC_Decode, 254, 4, 146, 1, // Opcode: FTINT_S_W
/* 9828 */    MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 9841
/* 9832 */    MCD_OPC_CheckPredicate, 4, 78, 11, // Skip to: 12730
/* 9836 */    MCD_OPC_Decode, 253, 4, 147, 1, // Opcode: FTINT_S_D
/* 9841 */    MCD_OPC_FilterValue, 26, 9, 0, // Skip to: 9854
/* 9845 */    MCD_OPC_CheckPredicate, 4, 65, 11, // Skip to: 12730
/* 9849 */    MCD_OPC_Decode, 128, 5, 146, 1, // Opcode: FTINT_U_W
/* 9854 */    MCD_OPC_FilterValue, 27, 9, 0, // Skip to: 9867
/* 9858 */    MCD_OPC_CheckPredicate, 4, 52, 11, // Skip to: 12730
/* 9862 */    MCD_OPC_Decode, 255, 4, 147, 1, // Opcode: FTINT_U_D
/* 9867 */    MCD_OPC_FilterValue, 28, 9, 0, // Skip to: 9880
/* 9871 */    MCD_OPC_CheckPredicate, 4, 39, 11, // Skip to: 12730
/* 9875 */    MCD_OPC_Decode, 173, 4, 146, 1, // Opcode: FFINT_S_W
/* 9880 */    MCD_OPC_FilterValue, 29, 9, 0, // Skip to: 9893
/* 9884 */    MCD_OPC_CheckPredicate, 4, 26, 11, // Skip to: 12730
/* 9888 */    MCD_OPC_Decode, 172, 4, 147, 1, // Opcode: FFINT_S_D
/* 9893 */    MCD_OPC_FilterValue, 30, 9, 0, // Skip to: 9906
/* 9897 */    MCD_OPC_CheckPredicate, 4, 13, 11, // Skip to: 12730
/* 9901 */    MCD_OPC_Decode, 175, 4, 146, 1, // Opcode: FFINT_U_W
/* 9906 */    MCD_OPC_FilterValue, 31, 4, 11, // Skip to: 12730
/* 9910 */    MCD_OPC_CheckPredicate, 4, 0, 11, // Skip to: 12730
/* 9914 */    MCD_OPC_Decode, 174, 4, 147, 1, // Opcode: FFINT_U_D
/* 9919 */    MCD_OPC_FilterValue, 32, 9, 0, // Skip to: 9932
/* 9923 */    MCD_OPC_CheckPredicate, 4, 243, 10, // Skip to: 12730
/* 9927 */    MCD_OPC_Decode, 212, 5, 150, 1, // Opcode: LD_B
/* 9932 */    MCD_OPC_FilterValue, 33, 9, 0, // Skip to: 9945
/* 9936 */    MCD_OPC_CheckPredicate, 4, 230, 10, // Skip to: 12730
/* 9940 */    MCD_OPC_Decode, 214, 5, 150, 1, // Opcode: LD_H
/* 9945 */    MCD_OPC_FilterValue, 34, 9, 0, // Skip to: 9958
/* 9949 */    MCD_OPC_CheckPredicate, 4, 217, 10, // Skip to: 12730
/* 9953 */    MCD_OPC_Decode, 215, 5, 150, 1, // Opcode: LD_W
/* 9958 */    MCD_OPC_FilterValue, 35, 9, 0, // Skip to: 9971
/* 9962 */    MCD_OPC_CheckPredicate, 4, 204, 10, // Skip to: 12730
/* 9966 */    MCD_OPC_Decode, 213, 5, 150, 1, // Opcode: LD_D
/* 9971 */    MCD_OPC_FilterValue, 36, 9, 0, // Skip to: 9984
/* 9975 */    MCD_OPC_CheckPredicate, 4, 191, 10, // Skip to: 12730
/* 9979 */    MCD_OPC_Decode, 212, 9, 150, 1, // Opcode: ST_B
/* 9984 */    MCD_OPC_FilterValue, 37, 9, 0, // Skip to: 9997
/* 9988 */    MCD_OPC_CheckPredicate, 4, 178, 10, // Skip to: 12730
/* 9992 */    MCD_OPC_Decode, 214, 9, 150, 1, // Opcode: ST_H
/* 9997 */    MCD_OPC_FilterValue, 38, 9, 0, // Skip to: 10010
/* 10001 */   MCD_OPC_CheckPredicate, 4, 165, 10, // Skip to: 12730
/* 10005 */   MCD_OPC_Decode, 215, 9, 150, 1, // Opcode: ST_W
/* 10010 */   MCD_OPC_FilterValue, 39, 156, 10, // Skip to: 12730
/* 10014 */   MCD_OPC_CheckPredicate, 4, 152, 10, // Skip to: 12730
/* 10018 */   MCD_OPC_Decode, 213, 9, 150, 1, // Opcode: ST_D
/* 10023 */   MCD_OPC_FilterValue, 31, 113, 9, // Skip to: 12444
/* 10027 */   MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10030 */   MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 10043
/* 10034 */   MCD_OPC_CheckPredicate, 3, 132, 10, // Skip to: 12730
/* 10038 */   MCD_OPC_Decode, 232, 3, 151, 1, // Opcode: EXT
/* 10043 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 10056
/* 10047 */   MCD_OPC_CheckPredicate, 3, 119, 10, // Skip to: 12730
/* 10051 */   MCD_OPC_Decode, 164, 5, 152, 1, // Opcode: INS
/* 10056 */   MCD_OPC_FilterValue, 10, 42, 0, // Skip to: 10102
/* 10060 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 10063 */   MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 10076
/* 10067 */   MCD_OPC_CheckPredicate, 5, 99, 10, // Skip to: 12730
/* 10071 */   MCD_OPC_Decode, 247, 5, 153, 1, // Opcode: LWX
/* 10076 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 10089
/* 10080 */   MCD_OPC_CheckPredicate, 5, 86, 10, // Skip to: 12730
/* 10084 */   MCD_OPC_Decode, 220, 5, 153, 1, // Opcode: LHX
/* 10089 */   MCD_OPC_FilterValue, 6, 77, 10, // Skip to: 12730
/* 10093 */   MCD_OPC_CheckPredicate, 5, 73, 10, // Skip to: 12730
/* 10097 */   MCD_OPC_Decode, 195, 5, 153, 1, // Opcode: LBUX
/* 10102 */   MCD_OPC_FilterValue, 12, 15, 0, // Skip to: 10121
/* 10106 */   MCD_OPC_CheckPredicate, 5, 60, 10, // Skip to: 12730
/* 10110 */   MCD_OPC_CheckField, 6, 10, 0, 54, 10, // Skip to: 12730
/* 10116 */   MCD_OPC_Decode, 170, 5, 154, 1, // Opcode: INSV
/* 10121 */   MCD_OPC_FilterValue, 16, 51, 1, // Skip to: 10432
/* 10125 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 10128 */   MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 10140
/* 10132 */   MCD_OPC_CheckPredicate, 5, 34, 10, // Skip to: 12730
/* 10136 */   MCD_OPC_Decode, 46, 155, 1, // Opcode: ADDU_QB
/* 10140 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 10153
/* 10144 */   MCD_OPC_CheckPredicate, 5, 22, 10, // Skip to: 12730
/* 10148 */   MCD_OPC_Decode, 243, 9, 155, 1, // Opcode: SUBU_QB
/* 10153 */   MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 10165
/* 10157 */   MCD_OPC_CheckPredicate, 5, 9, 10, // Skip to: 12730
/* 10161 */   MCD_OPC_Decode, 48, 155, 1, // Opcode: ADDU_S_QB
/* 10165 */   MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 10178
/* 10169 */   MCD_OPC_CheckPredicate, 5, 253, 9, // Skip to: 12730
/* 10173 */   MCD_OPC_Decode, 245, 9, 155, 1, // Opcode: SUBU_S_QB
/* 10178 */   MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 10191
/* 10182 */   MCD_OPC_CheckPredicate, 5, 240, 9, // Skip to: 12730
/* 10186 */   MCD_OPC_Decode, 160, 7, 155, 1, // Opcode: MULEU_S_PH_QBL
/* 10191 */   MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 10204
/* 10195 */   MCD_OPC_CheckPredicate, 5, 227, 9, // Skip to: 12730
/* 10199 */   MCD_OPC_Decode, 161, 7, 155, 1, // Opcode: MULEU_S_PH_QBR
/* 10204 */   MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 10216
/* 10208 */   MCD_OPC_CheckPredicate, 14, 214, 9, // Skip to: 12730
/* 10212 */   MCD_OPC_Decode, 45, 155, 1, // Opcode: ADDU_PH
/* 10216 */   MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 10229
/* 10220 */   MCD_OPC_CheckPredicate, 14, 202, 9, // Skip to: 12730
/* 10224 */   MCD_OPC_Decode, 242, 9, 155, 1, // Opcode: SUBU_PH
/* 10229 */   MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 10241
/* 10233 */   MCD_OPC_CheckPredicate, 5, 189, 9, // Skip to: 12730
/* 10237 */   MCD_OPC_Decode, 27, 155, 1, // Opcode: ADDQ_PH
/* 10241 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 10254
/* 10245 */   MCD_OPC_CheckPredicate, 5, 177, 9, // Skip to: 12730
/* 10249 */   MCD_OPC_Decode, 221, 9, 155, 1, // Opcode: SUBQ_PH
/* 10254 */   MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 10266
/* 10258 */   MCD_OPC_CheckPredicate, 14, 164, 9, // Skip to: 12730
/* 10262 */   MCD_OPC_Decode, 47, 155, 1, // Opcode: ADDU_S_PH
/* 10266 */   MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 10279
/* 10270 */   MCD_OPC_CheckPredicate, 14, 152, 9, // Skip to: 12730
/* 10274 */   MCD_OPC_Decode, 244, 9, 155, 1, // Opcode: SUBU_S_PH
/* 10279 */   MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 10291
/* 10283 */   MCD_OPC_CheckPredicate, 5, 139, 9, // Skip to: 12730
/* 10287 */   MCD_OPC_Decode, 28, 155, 1, // Opcode: ADDQ_S_PH
/* 10291 */   MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 10304
/* 10295 */   MCD_OPC_CheckPredicate, 5, 127, 9, // Skip to: 12730
/* 10299 */   MCD_OPC_Decode, 222, 9, 155, 1, // Opcode: SUBQ_S_PH
/* 10304 */   MCD_OPC_FilterValue, 16, 7, 0, // Skip to: 10315
/* 10308 */   MCD_OPC_CheckPredicate, 5, 114, 9, // Skip to: 12730
/* 10312 */   MCD_OPC_Decode, 30, 12, // Opcode: ADDSC
/* 10315 */   MCD_OPC_FilterValue, 17, 7, 0, // Skip to: 10326
/* 10319 */   MCD_OPC_CheckPredicate, 5, 103, 9, // Skip to: 12730
/* 10323 */   MCD_OPC_Decode, 57, 12, // Opcode: ADDWC
/* 10326 */   MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 10338
/* 10330 */   MCD_OPC_CheckPredicate, 5, 92, 9, // Skip to: 12730
/* 10334 */   MCD_OPC_Decode, 213, 6, 12, // Opcode: MODSUB
/* 10338 */   MCD_OPC_FilterValue, 20, 15, 0, // Skip to: 10357
/* 10342 */   MCD_OPC_CheckPredicate, 5, 80, 9, // Skip to: 12730
/* 10346 */   MCD_OPC_CheckField, 16, 5, 0, 74, 9, // Skip to: 12730
/* 10352 */   MCD_OPC_Decode, 167, 8, 156, 1, // Opcode: RADDU_W_QB
/* 10357 */   MCD_OPC_FilterValue, 22, 7, 0, // Skip to: 10368
/* 10361 */   MCD_OPC_CheckPredicate, 5, 61, 9, // Skip to: 12730
/* 10365 */   MCD_OPC_Decode, 29, 12, // Opcode: ADDQ_S_W
/* 10368 */   MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 10380
/* 10372 */   MCD_OPC_CheckPredicate, 5, 50, 9, // Skip to: 12730
/* 10376 */   MCD_OPC_Decode, 223, 9, 12, // Opcode: SUBQ_S_W
/* 10380 */   MCD_OPC_FilterValue, 28, 9, 0, // Skip to: 10393
/* 10384 */   MCD_OPC_CheckPredicate, 5, 38, 9, // Skip to: 12730
/* 10388 */   MCD_OPC_Decode, 158, 7, 157, 1, // Opcode: MULEQ_S_W_PHL
/* 10393 */   MCD_OPC_FilterValue, 29, 9, 0, // Skip to: 10406
/* 10397 */   MCD_OPC_CheckPredicate, 5, 25, 9, // Skip to: 12730
/* 10401 */   MCD_OPC_Decode, 159, 7, 157, 1, // Opcode: MULEQ_S_W_PHR
/* 10406 */   MCD_OPC_FilterValue, 30, 9, 0, // Skip to: 10419
/* 10410 */   MCD_OPC_CheckPredicate, 14, 12, 9, // Skip to: 12730
/* 10414 */   MCD_OPC_Decode, 164, 7, 155, 1, // Opcode: MULQ_S_PH
/* 10419 */   MCD_OPC_FilterValue, 31, 3, 9, // Skip to: 12730
/* 10423 */   MCD_OPC_CheckPredicate, 5, 255, 8, // Skip to: 12730
/* 10427 */   MCD_OPC_Decode, 162, 7, 155, 1, // Opcode: MULQ_RS_PH
/* 10432 */   MCD_OPC_FilterValue, 17, 69, 1, // Skip to: 10761
/* 10436 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 10439 */   MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 10458
/* 10443 */   MCD_OPC_CheckPredicate, 5, 235, 8, // Skip to: 12730
/* 10447 */   MCD_OPC_CheckField, 11, 5, 0, 229, 8, // Skip to: 12730
/* 10453 */   MCD_OPC_Decode, 191, 2, 158, 1, // Opcode: CMPU_EQ_QB
/* 10458 */   MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 10477
/* 10462 */   MCD_OPC_CheckPredicate, 5, 216, 8, // Skip to: 12730
/* 10466 */   MCD_OPC_CheckField, 11, 5, 0, 210, 8, // Skip to: 12730
/* 10472 */   MCD_OPC_Decode, 193, 2, 158, 1, // Opcode: CMPU_LT_QB
/* 10477 */   MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 10496
/* 10481 */   MCD_OPC_CheckPredicate, 5, 197, 8, // Skip to: 12730
/* 10485 */   MCD_OPC_CheckField, 11, 5, 0, 191, 8, // Skip to: 12730
/* 10491 */   MCD_OPC_Decode, 192, 2, 158, 1, // Opcode: CMPU_LE_QB
/* 10496 */   MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 10509
/* 10500 */   MCD_OPC_CheckPredicate, 5, 178, 8, // Skip to: 12730
/* 10504 */   MCD_OPC_Decode, 244, 7, 155, 1, // Opcode: PICK_QB
/* 10509 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 10522
/* 10513 */   MCD_OPC_CheckPredicate, 5, 165, 8, // Skip to: 12730
/* 10517 */   MCD_OPC_Decode, 188, 2, 157, 1, // Opcode: CMPGU_EQ_QB
/* 10522 */   MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 10535
/* 10526 */   MCD_OPC_CheckPredicate, 5, 152, 8, // Skip to: 12730
/* 10530 */   MCD_OPC_Decode, 190, 2, 157, 1, // Opcode: CMPGU_LT_QB
/* 10535 */   MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 10548
/* 10539 */   MCD_OPC_CheckPredicate, 5, 139, 8, // Skip to: 12730
/* 10543 */   MCD_OPC_Decode, 189, 2, 157, 1, // Opcode: CMPGU_LE_QB
/* 10548 */   MCD_OPC_FilterValue, 8, 15, 0, // Skip to: 10567
/* 10552 */   MCD_OPC_CheckPredicate, 5, 126, 8, // Skip to: 12730
/* 10556 */   MCD_OPC_CheckField, 11, 5, 0, 120, 8, // Skip to: 12730
/* 10562 */   MCD_OPC_Decode, 194, 2, 158, 1, // Opcode: CMP_EQ_PH
/* 10567 */   MCD_OPC_FilterValue, 9, 15, 0, // Skip to: 10586
/* 10571 */   MCD_OPC_CheckPredicate, 5, 107, 8, // Skip to: 12730
/* 10575 */   MCD_OPC_CheckField, 11, 5, 0, 101, 8, // Skip to: 12730
/* 10581 */   MCD_OPC_Decode, 196, 2, 158, 1, // Opcode: CMP_LT_PH
/* 10586 */   MCD_OPC_FilterValue, 10, 15, 0, // Skip to: 10605
/* 10590 */   MCD_OPC_CheckPredicate, 5, 88, 8, // Skip to: 12730
/* 10594 */   MCD_OPC_CheckField, 11, 5, 0, 82, 8, // Skip to: 12730
/* 10600 */   MCD_OPC_Decode, 195, 2, 158, 1, // Opcode: CMP_LE_PH
/* 10605 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 10618
/* 10609 */   MCD_OPC_CheckPredicate, 5, 69, 8, // Skip to: 12730
/* 10613 */   MCD_OPC_Decode, 243, 7, 155, 1, // Opcode: PICK_PH
/* 10618 */   MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 10631
/* 10622 */   MCD_OPC_CheckPredicate, 5, 56, 8, // Skip to: 12730
/* 10626 */   MCD_OPC_Decode, 129, 8, 155, 1, // Opcode: PRECRQ_QB_PH
/* 10631 */   MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 10644
/* 10635 */   MCD_OPC_CheckPredicate, 14, 43, 8, // Skip to: 12730
/* 10639 */   MCD_OPC_Decode, 131, 8, 155, 1, // Opcode: PRECR_QB_PH
/* 10644 */   MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 10657
/* 10648 */   MCD_OPC_CheckPredicate, 5, 30, 8, // Skip to: 12730
/* 10652 */   MCD_OPC_Decode, 230, 7, 155, 1, // Opcode: PACKRL_PH
/* 10657 */   MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 10670
/* 10661 */   MCD_OPC_CheckPredicate, 5, 17, 8, // Skip to: 12730
/* 10665 */   MCD_OPC_Decode, 255, 7, 155, 1, // Opcode: PRECRQU_S_QB_PH
/* 10670 */   MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 10683
/* 10674 */   MCD_OPC_CheckPredicate, 5, 4, 8, // Skip to: 12730
/* 10678 */   MCD_OPC_Decode, 128, 8, 159, 1, // Opcode: PRECRQ_PH_W
/* 10683 */   MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 10696
/* 10687 */   MCD_OPC_CheckPredicate, 5, 247, 7, // Skip to: 12730
/* 10691 */   MCD_OPC_Decode, 130, 8, 159, 1, // Opcode: PRECRQ_RS_PH_W
/* 10696 */   MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 10709
/* 10700 */   MCD_OPC_CheckPredicate, 14, 234, 7, // Skip to: 12730
/* 10704 */   MCD_OPC_Decode, 185, 2, 157, 1, // Opcode: CMPGDU_EQ_QB
/* 10709 */   MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 10722
/* 10713 */   MCD_OPC_CheckPredicate, 14, 221, 7, // Skip to: 12730
/* 10717 */   MCD_OPC_Decode, 187, 2, 157, 1, // Opcode: CMPGDU_LT_QB
/* 10722 */   MCD_OPC_FilterValue, 26, 9, 0, // Skip to: 10735
/* 10726 */   MCD_OPC_CheckPredicate, 14, 208, 7, // Skip to: 12730
/* 10730 */   MCD_OPC_Decode, 186, 2, 157, 1, // Opcode: CMPGDU_LE_QB
/* 10735 */   MCD_OPC_FilterValue, 30, 9, 0, // Skip to: 10748
/* 10739 */   MCD_OPC_CheckPredicate, 14, 195, 7, // Skip to: 12730
/* 10743 */   MCD_OPC_Decode, 132, 8, 160, 1, // Opcode: PRECR_SRA_PH_W
/* 10748 */   MCD_OPC_FilterValue, 31, 186, 7, // Skip to: 12730
/* 10752 */   MCD_OPC_CheckPredicate, 14, 182, 7, // Skip to: 12730
/* 10756 */   MCD_OPC_Decode, 133, 8, 160, 1, // Opcode: PRECR_SRA_R_PH_W
/* 10761 */   MCD_OPC_FilterValue, 18, 74, 1, // Skip to: 11095
/* 10765 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 10768 */   MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 10786
/* 10772 */   MCD_OPC_CheckPredicate, 14, 162, 7, // Skip to: 12730
/* 10776 */   MCD_OPC_CheckField, 21, 5, 0, 156, 7, // Skip to: 12730
/* 10782 */   MCD_OPC_Decode, 20, 161, 1, // Opcode: ABSQ_S_QB
/* 10786 */   MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 10799
/* 10790 */   MCD_OPC_CheckPredicate, 5, 144, 7, // Skip to: 12730
/* 10794 */   MCD_OPC_Decode, 174, 8, 162, 1, // Opcode: REPL_QB
/* 10799 */   MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 10818
/* 10803 */   MCD_OPC_CheckPredicate, 5, 131, 7, // Skip to: 12730
/* 10807 */   MCD_OPC_CheckField, 21, 5, 0, 125, 7, // Skip to: 12730
/* 10813 */   MCD_OPC_Decode, 172, 8, 163, 1, // Opcode: REPLV_QB
/* 10818 */   MCD_OPC_FilterValue, 4, 15, 0, // Skip to: 10837
/* 10822 */   MCD_OPC_CheckPredicate, 5, 112, 7, // Skip to: 12730
/* 10826 */   MCD_OPC_CheckField, 21, 5, 0, 106, 7, // Skip to: 12730
/* 10832 */   MCD_OPC_Decode, 245, 7, 161, 1, // Opcode: PRECEQU_PH_QBL
/* 10837 */   MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 10856
/* 10841 */   MCD_OPC_CheckPredicate, 5, 93, 7, // Skip to: 12730
/* 10845 */   MCD_OPC_CheckField, 21, 5, 0, 87, 7, // Skip to: 12730
/* 10851 */   MCD_OPC_Decode, 247, 7, 161, 1, // Opcode: PRECEQU_PH_QBR
/* 10856 */   MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 10875
/* 10860 */   MCD_OPC_CheckPredicate, 5, 74, 7, // Skip to: 12730
/* 10864 */   MCD_OPC_CheckField, 21, 5, 0, 68, 7, // Skip to: 12730
/* 10870 */   MCD_OPC_Decode, 246, 7, 161, 1, // Opcode: PRECEQU_PH_QBLA
/* 10875 */   MCD_OPC_FilterValue, 7, 15, 0, // Skip to: 10894
/* 10879 */   MCD_OPC_CheckPredicate, 5, 55, 7, // Skip to: 12730
/* 10883 */   MCD_OPC_CheckField, 21, 5, 0, 49, 7, // Skip to: 12730
/* 10889 */   MCD_OPC_Decode, 248, 7, 161, 1, // Opcode: PRECEQU_PH_QBRA
/* 10894 */   MCD_OPC_FilterValue, 9, 14, 0, // Skip to: 10912
/* 10898 */   MCD_OPC_CheckPredicate, 5, 36, 7, // Skip to: 12730
/* 10902 */   MCD_OPC_CheckField, 21, 5, 0, 30, 7, // Skip to: 12730
/* 10908 */   MCD_OPC_Decode, 19, 161, 1, // Opcode: ABSQ_S_PH
/* 10912 */   MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 10925
/* 10916 */   MCD_OPC_CheckPredicate, 5, 18, 7, // Skip to: 12730
/* 10920 */   MCD_OPC_Decode, 173, 8, 162, 1, // Opcode: REPL_PH
/* 10925 */   MCD_OPC_FilterValue, 11, 15, 0, // Skip to: 10944
/* 10929 */   MCD_OPC_CheckPredicate, 5, 5, 7, // Skip to: 12730
/* 10933 */   MCD_OPC_CheckField, 21, 5, 0, 255, 6, // Skip to: 12730
/* 10939 */   MCD_OPC_Decode, 171, 8, 163, 1, // Opcode: REPLV_PH
/* 10944 */   MCD_OPC_FilterValue, 12, 15, 0, // Skip to: 10963
/* 10948 */   MCD_OPC_CheckPredicate, 5, 242, 6, // Skip to: 12730
/* 10952 */   MCD_OPC_CheckField, 21, 5, 0, 236, 6, // Skip to: 12730
/* 10958 */   MCD_OPC_Decode, 249, 7, 164, 1, // Opcode: PRECEQ_W_PHL
/* 10963 */   MCD_OPC_FilterValue, 13, 15, 0, // Skip to: 10982
/* 10967 */   MCD_OPC_CheckPredicate, 5, 223, 6, // Skip to: 12730
/* 10971 */   MCD_OPC_CheckField, 21, 5, 0, 217, 6, // Skip to: 12730
/* 10977 */   MCD_OPC_Decode, 250, 7, 164, 1, // Opcode: PRECEQ_W_PHR
/* 10982 */   MCD_OPC_FilterValue, 17, 14, 0, // Skip to: 11000
/* 10986 */   MCD_OPC_CheckPredicate, 5, 204, 6, // Skip to: 12730
/* 10990 */   MCD_OPC_CheckField, 21, 5, 0, 198, 6, // Skip to: 12730
/* 10996 */   MCD_OPC_Decode, 21, 165, 1, // Opcode: ABSQ_S_W
/* 11000 */   MCD_OPC_FilterValue, 27, 15, 0, // Skip to: 11019
/* 11004 */   MCD_OPC_CheckPredicate, 5, 186, 6, // Skip to: 12730
/* 11008 */   MCD_OPC_CheckField, 21, 5, 0, 180, 6, // Skip to: 12730
/* 11014 */   MCD_OPC_Decode, 188, 1, 165, 1, // Opcode: BITREV
/* 11019 */   MCD_OPC_FilterValue, 28, 15, 0, // Skip to: 11038
/* 11023 */   MCD_OPC_CheckPredicate, 5, 167, 6, // Skip to: 12730
/* 11027 */   MCD_OPC_CheckField, 21, 5, 0, 161, 6, // Skip to: 12730
/* 11033 */   MCD_OPC_Decode, 251, 7, 161, 1, // Opcode: PRECEU_PH_QBL
/* 11038 */   MCD_OPC_FilterValue, 29, 15, 0, // Skip to: 11057
/* 11042 */   MCD_OPC_CheckPredicate, 5, 148, 6, // Skip to: 12730
/* 11046 */   MCD_OPC_CheckField, 21, 5, 0, 142, 6, // Skip to: 12730
/* 11052 */   MCD_OPC_Decode, 253, 7, 161, 1, // Opcode: PRECEU_PH_QBR
/* 11057 */   MCD_OPC_FilterValue, 30, 15, 0, // Skip to: 11076
/* 11061 */   MCD_OPC_CheckPredicate, 5, 129, 6, // Skip to: 12730
/* 11065 */   MCD_OPC_CheckField, 21, 5, 0, 123, 6, // Skip to: 12730
/* 11071 */   MCD_OPC_Decode, 252, 7, 161, 1, // Opcode: PRECEU_PH_QBLA
/* 11076 */   MCD_OPC_FilterValue, 31, 114, 6, // Skip to: 12730
/* 11080 */   MCD_OPC_CheckPredicate, 5, 110, 6, // Skip to: 12730
/* 11084 */   MCD_OPC_CheckField, 21, 5, 0, 104, 6, // Skip to: 12730
/* 11090 */   MCD_OPC_Decode, 254, 7, 161, 1, // Opcode: PRECEU_PH_QBRA
/* 11095 */   MCD_OPC_FilterValue, 19, 31, 1, // Skip to: 11386
/* 11099 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11102 */   MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 11115
/* 11106 */   MCD_OPC_CheckPredicate, 5, 84, 6, // Skip to: 12730
/* 11110 */   MCD_OPC_Decode, 231, 8, 166, 1, // Opcode: SHLL_QB
/* 11115 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 11128
/* 11119 */   MCD_OPC_CheckPredicate, 5, 71, 6, // Skip to: 12730
/* 11123 */   MCD_OPC_Decode, 247, 8, 166, 1, // Opcode: SHRL_QB
/* 11128 */   MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 11141
/* 11132 */   MCD_OPC_CheckPredicate, 5, 58, 6, // Skip to: 12730
/* 11136 */   MCD_OPC_Decode, 227, 8, 167, 1, // Opcode: SHLLV_QB
/* 11141 */   MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 11154
/* 11145 */   MCD_OPC_CheckPredicate, 5, 45, 6, // Skip to: 12730
/* 11149 */   MCD_OPC_Decode, 245, 8, 167, 1, // Opcode: SHRLV_QB
/* 11154 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 11167
/* 11158 */   MCD_OPC_CheckPredicate, 14, 32, 6, // Skip to: 12730
/* 11162 */   MCD_OPC_Decode, 240, 8, 166, 1, // Opcode: SHRA_QB
/* 11167 */   MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 11180
/* 11171 */   MCD_OPC_CheckPredicate, 14, 19, 6, // Skip to: 12730
/* 11175 */   MCD_OPC_Decode, 242, 8, 166, 1, // Opcode: SHRA_R_QB
/* 11180 */   MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 11193
/* 11184 */   MCD_OPC_CheckPredicate, 14, 6, 6, // Skip to: 12730
/* 11188 */   MCD_OPC_Decode, 235, 8, 167, 1, // Opcode: SHRAV_QB
/* 11193 */   MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 11206
/* 11197 */   MCD_OPC_CheckPredicate, 14, 249, 5, // Skip to: 12730
/* 11201 */   MCD_OPC_Decode, 237, 8, 167, 1, // Opcode: SHRAV_R_QB
/* 11206 */   MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 11219
/* 11210 */   MCD_OPC_CheckPredicate, 5, 236, 5, // Skip to: 12730
/* 11214 */   MCD_OPC_Decode, 230, 8, 166, 1, // Opcode: SHLL_PH
/* 11219 */   MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 11232
/* 11223 */   MCD_OPC_CheckPredicate, 5, 223, 5, // Skip to: 12730
/* 11227 */   MCD_OPC_Decode, 239, 8, 166, 1, // Opcode: SHRA_PH
/* 11232 */   MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 11245
/* 11236 */   MCD_OPC_CheckPredicate, 5, 210, 5, // Skip to: 12730
/* 11240 */   MCD_OPC_Decode, 226, 8, 167, 1, // Opcode: SHLLV_PH
/* 11245 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 11258
/* 11249 */   MCD_OPC_CheckPredicate, 5, 197, 5, // Skip to: 12730
/* 11253 */   MCD_OPC_Decode, 234, 8, 167, 1, // Opcode: SHRAV_PH
/* 11258 */   MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 11271
/* 11262 */   MCD_OPC_CheckPredicate, 5, 184, 5, // Skip to: 12730
/* 11266 */   MCD_OPC_Decode, 232, 8, 166, 1, // Opcode: SHLL_S_PH
/* 11271 */   MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 11284
/* 11275 */   MCD_OPC_CheckPredicate, 5, 171, 5, // Skip to: 12730
/* 11279 */   MCD_OPC_Decode, 241, 8, 166, 1, // Opcode: SHRA_R_PH
/* 11284 */   MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 11297
/* 11288 */   MCD_OPC_CheckPredicate, 5, 158, 5, // Skip to: 12730
/* 11292 */   MCD_OPC_Decode, 228, 8, 167, 1, // Opcode: SHLLV_S_PH
/* 11297 */   MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 11310
/* 11301 */   MCD_OPC_CheckPredicate, 5, 145, 5, // Skip to: 12730
/* 11305 */   MCD_OPC_Decode, 236, 8, 167, 1, // Opcode: SHRAV_R_PH
/* 11310 */   MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 11323
/* 11314 */   MCD_OPC_CheckPredicate, 5, 132, 5, // Skip to: 12730
/* 11318 */   MCD_OPC_Decode, 233, 8, 168, 1, // Opcode: SHLL_S_W
/* 11323 */   MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 11336
/* 11327 */   MCD_OPC_CheckPredicate, 5, 119, 5, // Skip to: 12730
/* 11331 */   MCD_OPC_Decode, 243, 8, 168, 1, // Opcode: SHRA_R_W
/* 11336 */   MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 11348
/* 11340 */   MCD_OPC_CheckPredicate, 5, 106, 5, // Skip to: 12730
/* 11344 */   MCD_OPC_Decode, 229, 8, 13, // Opcode: SHLLV_S_W
/* 11348 */   MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 11360
/* 11352 */   MCD_OPC_CheckPredicate, 5, 94, 5, // Skip to: 12730
/* 11356 */   MCD_OPC_Decode, 238, 8, 13, // Opcode: SHRAV_R_W
/* 11360 */   MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 11373
/* 11364 */   MCD_OPC_CheckPredicate, 14, 82, 5, // Skip to: 12730
/* 11368 */   MCD_OPC_Decode, 246, 8, 166, 1, // Opcode: SHRL_PH
/* 11373 */   MCD_OPC_FilterValue, 27, 73, 5, // Skip to: 12730
/* 11377 */   MCD_OPC_CheckPredicate, 14, 69, 5, // Skip to: 12730
/* 11381 */   MCD_OPC_Decode, 244, 8, 167, 1, // Opcode: SHRLV_PH
/* 11386 */   MCD_OPC_FilterValue, 24, 199, 0, // Skip to: 11589
/* 11390 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11393 */   MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 11405
/* 11397 */   MCD_OPC_CheckPredicate, 14, 49, 5, // Skip to: 12730
/* 11401 */   MCD_OPC_Decode, 43, 155, 1, // Opcode: ADDUH_QB
/* 11405 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 11418
/* 11409 */   MCD_OPC_CheckPredicate, 14, 37, 5, // Skip to: 12730
/* 11413 */   MCD_OPC_Decode, 240, 9, 155, 1, // Opcode: SUBUH_QB
/* 11418 */   MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 11430
/* 11422 */   MCD_OPC_CheckPredicate, 14, 24, 5, // Skip to: 12730
/* 11426 */   MCD_OPC_Decode, 44, 155, 1, // Opcode: ADDUH_R_QB
/* 11430 */   MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 11443
/* 11434 */   MCD_OPC_CheckPredicate, 14, 12, 5, // Skip to: 12730
/* 11438 */   MCD_OPC_Decode, 241, 9, 155, 1, // Opcode: SUBUH_R_QB
/* 11443 */   MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 11455
/* 11447 */   MCD_OPC_CheckPredicate, 14, 255, 4, // Skip to: 12730
/* 11451 */   MCD_OPC_Decode, 23, 155, 1, // Opcode: ADDQH_PH
/* 11455 */   MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 11468
/* 11459 */   MCD_OPC_CheckPredicate, 14, 243, 4, // Skip to: 12730
/* 11463 */   MCD_OPC_Decode, 217, 9, 155, 1, // Opcode: SUBQH_PH
/* 11468 */   MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 11480
/* 11472 */   MCD_OPC_CheckPredicate, 14, 230, 4, // Skip to: 12730
/* 11476 */   MCD_OPC_Decode, 24, 155, 1, // Opcode: ADDQH_R_PH
/* 11480 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 11493
/* 11484 */   MCD_OPC_CheckPredicate, 14, 218, 4, // Skip to: 12730
/* 11488 */   MCD_OPC_Decode, 218, 9, 155, 1, // Opcode: SUBQH_R_PH
/* 11493 */   MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 11506
/* 11497 */   MCD_OPC_CheckPredicate, 14, 205, 4, // Skip to: 12730
/* 11501 */   MCD_OPC_Decode, 181, 7, 155, 1, // Opcode: MUL_PH
/* 11506 */   MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 11519
/* 11510 */   MCD_OPC_CheckPredicate, 14, 192, 4, // Skip to: 12730
/* 11514 */   MCD_OPC_Decode, 184, 7, 155, 1, // Opcode: MUL_S_PH
/* 11519 */   MCD_OPC_FilterValue, 16, 7, 0, // Skip to: 11530
/* 11523 */   MCD_OPC_CheckPredicate, 14, 179, 4, // Skip to: 12730
/* 11527 */   MCD_OPC_Decode, 26, 12, // Opcode: ADDQH_W
/* 11530 */   MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 11542
/* 11534 */   MCD_OPC_CheckPredicate, 14, 168, 4, // Skip to: 12730
/* 11538 */   MCD_OPC_Decode, 220, 9, 12, // Opcode: SUBQH_W
/* 11542 */   MCD_OPC_FilterValue, 18, 7, 0, // Skip to: 11553
/* 11546 */   MCD_OPC_CheckPredicate, 14, 156, 4, // Skip to: 12730
/* 11550 */   MCD_OPC_Decode, 25, 12, // Opcode: ADDQH_R_W
/* 11553 */   MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 11565
/* 11557 */   MCD_OPC_CheckPredicate, 14, 145, 4, // Skip to: 12730
/* 11561 */   MCD_OPC_Decode, 219, 9, 12, // Opcode: SUBQH_R_W
/* 11565 */   MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 11577
/* 11569 */   MCD_OPC_CheckPredicate, 14, 133, 4, // Skip to: 12730
/* 11573 */   MCD_OPC_Decode, 165, 7, 12, // Opcode: MULQ_S_W
/* 11577 */   MCD_OPC_FilterValue, 23, 125, 4, // Skip to: 12730
/* 11581 */   MCD_OPC_CheckPredicate, 14, 121, 4, // Skip to: 12730
/* 11585 */   MCD_OPC_Decode, 163, 7, 12, // Opcode: MULQ_RS_W
/* 11589 */   MCD_OPC_FilterValue, 32, 60, 0, // Skip to: 11653
/* 11593 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11596 */   MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 11615
/* 11600 */   MCD_OPC_CheckPredicate, 15, 102, 4, // Skip to: 12730
/* 11604 */   MCD_OPC_CheckField, 21, 5, 0, 96, 4, // Skip to: 12730
/* 11610 */   MCD_OPC_Decode, 221, 10, 165, 1, // Opcode: WSBH
/* 11615 */   MCD_OPC_FilterValue, 16, 15, 0, // Skip to: 11634
/* 11619 */   MCD_OPC_CheckPredicate, 16, 83, 4, // Skip to: 12730
/* 11623 */   MCD_OPC_CheckField, 21, 5, 0, 77, 4, // Skip to: 12730
/* 11629 */   MCD_OPC_Decode, 213, 8, 165, 1, // Opcode: SEB
/* 11634 */   MCD_OPC_FilterValue, 24, 68, 4, // Skip to: 12730
/* 11638 */   MCD_OPC_CheckPredicate, 16, 64, 4, // Skip to: 12730
/* 11642 */   MCD_OPC_CheckField, 21, 5, 0, 58, 4, // Skip to: 12730
/* 11648 */   MCD_OPC_Decode, 216, 8, 165, 1, // Opcode: SEH
/* 11653 */   MCD_OPC_FilterValue, 48, 143, 1, // Skip to: 12056
/* 11657 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11660 */   MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 11678
/* 11664 */   MCD_OPC_CheckPredicate, 14, 38, 4, // Skip to: 12730
/* 11668 */   MCD_OPC_CheckField, 13, 3, 0, 32, 4, // Skip to: 12730
/* 11674 */   MCD_OPC_Decode, 195, 3, 84, // Opcode: DPA_W_PH
/* 11678 */   MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 11696
/* 11682 */   MCD_OPC_CheckPredicate, 14, 20, 4, // Skip to: 12730
/* 11686 */   MCD_OPC_CheckField, 13, 3, 0, 14, 4, // Skip to: 12730
/* 11692 */   MCD_OPC_Decode, 209, 3, 84, // Opcode: DPS_W_PH
/* 11696 */   MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 11714
/* 11700 */   MCD_OPC_CheckPredicate, 14, 2, 4, // Skip to: 12730
/* 11704 */   MCD_OPC_CheckField, 13, 3, 0, 252, 3, // Skip to: 12730
/* 11710 */   MCD_OPC_Decode, 169, 7, 84, // Opcode: MULSA_W_PH
/* 11714 */   MCD_OPC_FilterValue, 3, 14, 0, // Skip to: 11732
/* 11718 */   MCD_OPC_CheckPredicate, 5, 240, 3, // Skip to: 12730
/* 11722 */   MCD_OPC_CheckField, 13, 3, 0, 234, 3, // Skip to: 12730
/* 11728 */   MCD_OPC_Decode, 192, 3, 84, // Opcode: DPAU_H_QBL
/* 11732 */   MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 11750
/* 11736 */   MCD_OPC_CheckPredicate, 5, 222, 3, // Skip to: 12730
/* 11740 */   MCD_OPC_CheckField, 13, 3, 0, 216, 3, // Skip to: 12730
/* 11746 */   MCD_OPC_Decode, 191, 3, 84, // Opcode: DPAQ_S_W_PH
/* 11750 */   MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 11768
/* 11754 */   MCD_OPC_CheckPredicate, 5, 204, 3, // Skip to: 12730
/* 11758 */   MCD_OPC_CheckField, 13, 3, 0, 198, 3, // Skip to: 12730
/* 11764 */   MCD_OPC_Decode, 199, 3, 84, // Opcode: DPSQ_S_W_PH
/* 11768 */   MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 11786
/* 11772 */   MCD_OPC_CheckPredicate, 5, 186, 3, // Skip to: 12730
/* 11776 */   MCD_OPC_CheckField, 13, 3, 0, 180, 3, // Skip to: 12730
/* 11782 */   MCD_OPC_Decode, 168, 7, 84, // Opcode: MULSAQ_S_W_PH
/* 11786 */   MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 11804
/* 11790 */   MCD_OPC_CheckPredicate, 5, 168, 3, // Skip to: 12730
/* 11794 */   MCD_OPC_CheckField, 13, 3, 0, 162, 3, // Skip to: 12730
/* 11800 */   MCD_OPC_Decode, 193, 3, 84, // Opcode: DPAU_H_QBR
/* 11804 */   MCD_OPC_FilterValue, 8, 14, 0, // Skip to: 11822
/* 11808 */   MCD_OPC_CheckPredicate, 14, 150, 3, // Skip to: 12730
/* 11812 */   MCD_OPC_CheckField, 13, 3, 0, 144, 3, // Skip to: 12730
/* 11818 */   MCD_OPC_Decode, 194, 3, 84, // Opcode: DPAX_W_PH
/* 11822 */   MCD_OPC_FilterValue, 9, 14, 0, // Skip to: 11840
/* 11826 */   MCD_OPC_CheckPredicate, 14, 132, 3, // Skip to: 12730
/* 11830 */   MCD_OPC_CheckField, 13, 3, 0, 126, 3, // Skip to: 12730
/* 11836 */   MCD_OPC_Decode, 208, 3, 84, // Opcode: DPSX_W_PH
/* 11840 */   MCD_OPC_FilterValue, 11, 14, 0, // Skip to: 11858
/* 11844 */   MCD_OPC_CheckPredicate, 5, 114, 3, // Skip to: 12730
/* 11848 */   MCD_OPC_CheckField, 13, 3, 0, 108, 3, // Skip to: 12730
/* 11854 */   MCD_OPC_Decode, 206, 3, 84, // Opcode: DPSU_H_QBL
/* 11858 */   MCD_OPC_FilterValue, 12, 14, 0, // Skip to: 11876
/* 11862 */   MCD_OPC_CheckPredicate, 5, 96, 3, // Skip to: 12730
/* 11866 */   MCD_OPC_CheckField, 13, 3, 0, 90, 3, // Skip to: 12730
/* 11872 */   MCD_OPC_Decode, 190, 3, 84, // Opcode: DPAQ_SA_L_W
/* 11876 */   MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 11894
/* 11880 */   MCD_OPC_CheckPredicate, 5, 78, 3, // Skip to: 12730
/* 11884 */   MCD_OPC_CheckField, 13, 3, 0, 72, 3, // Skip to: 12730
/* 11890 */   MCD_OPC_Decode, 198, 3, 84, // Opcode: DPSQ_SA_L_W
/* 11894 */   MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 11912
/* 11898 */   MCD_OPC_CheckPredicate, 5, 60, 3, // Skip to: 12730
/* 11902 */   MCD_OPC_CheckField, 13, 3, 0, 54, 3, // Skip to: 12730
/* 11908 */   MCD_OPC_Decode, 207, 3, 84, // Opcode: DPSU_H_QBR
/* 11912 */   MCD_OPC_FilterValue, 16, 14, 0, // Skip to: 11930
/* 11916 */   MCD_OPC_CheckPredicate, 5, 42, 3, // Skip to: 12730
/* 11920 */   MCD_OPC_CheckField, 13, 3, 0, 36, 3, // Skip to: 12730
/* 11926 */   MCD_OPC_Decode, 155, 6, 84, // Opcode: MAQ_SA_W_PHL
/* 11930 */   MCD_OPC_FilterValue, 18, 14, 0, // Skip to: 11948
/* 11934 */   MCD_OPC_CheckPredicate, 5, 24, 3, // Skip to: 12730
/* 11938 */   MCD_OPC_CheckField, 13, 3, 0, 18, 3, // Skip to: 12730
/* 11944 */   MCD_OPC_Decode, 156, 6, 84, // Opcode: MAQ_SA_W_PHR
/* 11948 */   MCD_OPC_FilterValue, 20, 14, 0, // Skip to: 11966
/* 11952 */   MCD_OPC_CheckPredicate, 5, 6, 3, // Skip to: 12730
/* 11956 */   MCD_OPC_CheckField, 13, 3, 0, 0, 3, // Skip to: 12730
/* 11962 */   MCD_OPC_Decode, 157, 6, 84, // Opcode: MAQ_S_W_PHL
/* 11966 */   MCD_OPC_FilterValue, 22, 14, 0, // Skip to: 11984
/* 11970 */   MCD_OPC_CheckPredicate, 5, 244, 2, // Skip to: 12730
/* 11974 */   MCD_OPC_CheckField, 13, 3, 0, 238, 2, // Skip to: 12730
/* 11980 */   MCD_OPC_Decode, 158, 6, 84, // Opcode: MAQ_S_W_PHR
/* 11984 */   MCD_OPC_FilterValue, 24, 14, 0, // Skip to: 12002
/* 11988 */   MCD_OPC_CheckPredicate, 14, 226, 2, // Skip to: 12730
/* 11992 */   MCD_OPC_CheckField, 13, 3, 0, 220, 2, // Skip to: 12730
/* 11998 */   MCD_OPC_Decode, 189, 3, 84, // Opcode: DPAQX_S_W_PH
/* 12002 */   MCD_OPC_FilterValue, 25, 14, 0, // Skip to: 12020
/* 12006 */   MCD_OPC_CheckPredicate, 14, 208, 2, // Skip to: 12730
/* 12010 */   MCD_OPC_CheckField, 13, 3, 0, 202, 2, // Skip to: 12730
/* 12016 */   MCD_OPC_Decode, 197, 3, 84, // Opcode: DPSQX_S_W_PH
/* 12020 */   MCD_OPC_FilterValue, 26, 14, 0, // Skip to: 12038
/* 12024 */   MCD_OPC_CheckPredicate, 14, 190, 2, // Skip to: 12730
/* 12028 */   MCD_OPC_CheckField, 13, 3, 0, 184, 2, // Skip to: 12730
/* 12034 */   MCD_OPC_Decode, 188, 3, 84, // Opcode: DPAQX_SA_W_PH
/* 12038 */   MCD_OPC_FilterValue, 27, 176, 2, // Skip to: 12730
/* 12042 */   MCD_OPC_CheckPredicate, 14, 172, 2, // Skip to: 12730
/* 12046 */   MCD_OPC_CheckField, 13, 3, 0, 166, 2, // Skip to: 12730
/* 12052 */   MCD_OPC_Decode, 196, 3, 84, // Opcode: DPSQX_SA_W_PH
/* 12056 */   MCD_OPC_FilterValue, 49, 41, 0, // Skip to: 12101
/* 12060 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 12063 */   MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 12075
/* 12067 */   MCD_OPC_CheckPredicate, 14, 147, 2, // Skip to: 12730
/* 12071 */   MCD_OPC_Decode, 82, 169, 1, // Opcode: APPEND
/* 12075 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 12088
/* 12079 */   MCD_OPC_CheckPredicate, 14, 135, 2, // Skip to: 12730
/* 12083 */   MCD_OPC_Decode, 134, 8, 169, 1, // Opcode: PREPEND
/* 12088 */   MCD_OPC_FilterValue, 16, 126, 2, // Skip to: 12730
/* 12092 */   MCD_OPC_CheckPredicate, 14, 122, 2, // Skip to: 12730
/* 12096 */   MCD_OPC_Decode, 149, 1, 169, 1, // Opcode: BALIGN
/* 12101 */   MCD_OPC_FilterValue, 56, 58, 1, // Skip to: 12419
/* 12105 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 12108 */   MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 12127
/* 12112 */   MCD_OPC_CheckPredicate, 5, 102, 2, // Skip to: 12730
/* 12116 */   MCD_OPC_CheckField, 13, 3, 0, 96, 2, // Skip to: 12730
/* 12122 */   MCD_OPC_Decode, 244, 3, 170, 1, // Opcode: EXTR_W
/* 12127 */   MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 12146
/* 12131 */   MCD_OPC_CheckPredicate, 5, 83, 2, // Skip to: 12730
/* 12135 */   MCD_OPC_CheckField, 13, 3, 0, 77, 2, // Skip to: 12730
/* 12141 */   MCD_OPC_Decode, 240, 3, 171, 1, // Opcode: EXTRV_W
/* 12146 */   MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 12165
/* 12150 */   MCD_OPC_CheckPredicate, 5, 64, 2, // Skip to: 12730
/* 12154 */   MCD_OPC_CheckField, 13, 3, 0, 58, 2, // Skip to: 12730
/* 12160 */   MCD_OPC_Decode, 233, 3, 170, 1, // Opcode: EXTP
/* 12165 */   MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 12184
/* 12169 */   MCD_OPC_CheckPredicate, 5, 45, 2, // Skip to: 12730
/* 12173 */   MCD_OPC_CheckField, 13, 3, 0, 39, 2, // Skip to: 12730
/* 12179 */   MCD_OPC_Decode, 236, 3, 171, 1, // Opcode: EXTPV
/* 12184 */   MCD_OPC_FilterValue, 4, 15, 0, // Skip to: 12203
/* 12188 */   MCD_OPC_CheckPredicate, 5, 26, 2, // Skip to: 12730
/* 12192 */   MCD_OPC_CheckField, 13, 3, 0, 20, 2, // Skip to: 12730
/* 12198 */   MCD_OPC_Decode, 242, 3, 170, 1, // Opcode: EXTR_R_W
/* 12203 */   MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 12222
/* 12207 */   MCD_OPC_CheckPredicate, 5, 7, 2, // Skip to: 12730
/* 12211 */   MCD_OPC_CheckField, 13, 3, 0, 1, 2, // Skip to: 12730
/* 12217 */   MCD_OPC_Decode, 238, 3, 171, 1, // Opcode: EXTRV_R_W
/* 12222 */   MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 12241
/* 12226 */   MCD_OPC_CheckPredicate, 5, 244, 1, // Skip to: 12730
/* 12230 */   MCD_OPC_CheckField, 13, 3, 0, 238, 1, // Skip to: 12730
/* 12236 */   MCD_OPC_Decode, 241, 3, 170, 1, // Opcode: EXTR_RS_W
/* 12241 */   MCD_OPC_FilterValue, 7, 15, 0, // Skip to: 12260
/* 12245 */   MCD_OPC_CheckPredicate, 5, 225, 1, // Skip to: 12730
/* 12249 */   MCD_OPC_CheckField, 13, 3, 0, 219, 1, // Skip to: 12730
/* 12255 */   MCD_OPC_Decode, 237, 3, 171, 1, // Opcode: EXTRV_RS_W
/* 12260 */   MCD_OPC_FilterValue, 10, 15, 0, // Skip to: 12279
/* 12264 */   MCD_OPC_CheckPredicate, 5, 206, 1, // Skip to: 12730
/* 12268 */   MCD_OPC_CheckField, 13, 3, 0, 200, 1, // Skip to: 12730
/* 12274 */   MCD_OPC_Decode, 234, 3, 170, 1, // Opcode: EXTPDP
/* 12279 */   MCD_OPC_FilterValue, 11, 15, 0, // Skip to: 12298
/* 12283 */   MCD_OPC_CheckPredicate, 5, 187, 1, // Skip to: 12730
/* 12287 */   MCD_OPC_CheckField, 13, 3, 0, 181, 1, // Skip to: 12730
/* 12293 */   MCD_OPC_Decode, 235, 3, 171, 1, // Opcode: EXTPDPV
/* 12298 */   MCD_OPC_FilterValue, 14, 15, 0, // Skip to: 12317
/* 12302 */   MCD_OPC_CheckPredicate, 5, 168, 1, // Skip to: 12730
/* 12306 */   MCD_OPC_CheckField, 13, 3, 0, 162, 1, // Skip to: 12730
/* 12312 */   MCD_OPC_Decode, 243, 3, 170, 1, // Opcode: EXTR_S_H
/* 12317 */   MCD_OPC_FilterValue, 15, 15, 0, // Skip to: 12336
/* 12321 */   MCD_OPC_CheckPredicate, 5, 149, 1, // Skip to: 12730
/* 12325 */   MCD_OPC_CheckField, 13, 3, 0, 143, 1, // Skip to: 12730
/* 12331 */   MCD_OPC_Decode, 239, 3, 171, 1, // Opcode: EXTRV_S_H
/* 12336 */   MCD_OPC_FilterValue, 18, 9, 0, // Skip to: 12349
/* 12340 */   MCD_OPC_CheckPredicate, 5, 130, 1, // Skip to: 12730
/* 12344 */   MCD_OPC_Decode, 168, 8, 172, 1, // Opcode: RDDSP
/* 12349 */   MCD_OPC_FilterValue, 19, 9, 0, // Skip to: 12362
/* 12353 */   MCD_OPC_CheckPredicate, 5, 117, 1, // Skip to: 12730
/* 12357 */   MCD_OPC_Decode, 220, 10, 173, 1, // Opcode: WRDSP
/* 12362 */   MCD_OPC_FilterValue, 26, 15, 0, // Skip to: 12381
/* 12366 */   MCD_OPC_CheckPredicate, 5, 104, 1, // Skip to: 12730
/* 12370 */   MCD_OPC_CheckField, 13, 7, 0, 98, 1, // Skip to: 12730
/* 12376 */   MCD_OPC_Decode, 224, 8, 174, 1, // Opcode: SHILO
/* 12381 */   MCD_OPC_FilterValue, 27, 15, 0, // Skip to: 12400
/* 12385 */   MCD_OPC_CheckPredicate, 5, 85, 1, // Skip to: 12730
/* 12389 */   MCD_OPC_CheckField, 13, 8, 0, 79, 1, // Skip to: 12730
/* 12395 */   MCD_OPC_Decode, 225, 8, 175, 1, // Opcode: SHILOV
/* 12400 */   MCD_OPC_FilterValue, 31, 70, 1, // Skip to: 12730
/* 12404 */   MCD_OPC_CheckPredicate, 5, 66, 1, // Skip to: 12730
/* 12408 */   MCD_OPC_CheckField, 13, 8, 0, 60, 1, // Skip to: 12730
/* 12414 */   MCD_OPC_Decode, 152, 7, 175, 1, // Opcode: MTHLIP
/* 12419 */   MCD_OPC_FilterValue, 59, 51, 1, // Skip to: 12730
/* 12423 */   MCD_OPC_CheckPredicate, 2, 47, 1, // Skip to: 12730
/* 12427 */   MCD_OPC_CheckField, 21, 5, 0, 41, 1, // Skip to: 12730
/* 12433 */   MCD_OPC_CheckField, 6, 5, 0, 35, 1, // Skip to: 12730
/* 12439 */   MCD_OPC_Decode, 169, 8, 176, 1, // Opcode: RDHWR
/* 12444 */   MCD_OPC_FilterValue, 32, 9, 0, // Skip to: 12457
/* 12448 */   MCD_OPC_CheckPredicate, 2, 22, 1, // Skip to: 12730
/* 12452 */   MCD_OPC_Decode, 193, 5, 177, 1, // Opcode: LB
/* 12457 */   MCD_OPC_FilterValue, 33, 9, 0, // Skip to: 12470
/* 12461 */   MCD_OPC_CheckPredicate, 2, 9, 1, // Skip to: 12730
/* 12465 */   MCD_OPC_Decode, 218, 5, 177, 1, // Opcode: LH
/* 12470 */   MCD_OPC_FilterValue, 34, 9, 0, // Skip to: 12483
/* 12474 */   MCD_OPC_CheckPredicate, 2, 252, 0, // Skip to: 12730
/* 12478 */   MCD_OPC_Decode, 241, 5, 177, 1, // Opcode: LWL
/* 12483 */   MCD_OPC_FilterValue, 35, 9, 0, // Skip to: 12496
/* 12487 */   MCD_OPC_CheckPredicate, 2, 239, 0, // Skip to: 12730
/* 12491 */   MCD_OPC_Decode, 237, 5, 177, 1, // Opcode: LW
/* 12496 */   MCD_OPC_FilterValue, 36, 9, 0, // Skip to: 12509
/* 12500 */   MCD_OPC_CheckPredicate, 2, 226, 0, // Skip to: 12730
/* 12504 */   MCD_OPC_Decode, 197, 5, 177, 1, // Opcode: LBu
/* 12509 */   MCD_OPC_FilterValue, 37, 9, 0, // Skip to: 12522
/* 12513 */   MCD_OPC_CheckPredicate, 2, 213, 0, // Skip to: 12730
/* 12517 */   MCD_OPC_Decode, 222, 5, 177, 1, // Opcode: LHu
/* 12522 */   MCD_OPC_FilterValue, 38, 9, 0, // Skip to: 12535
/* 12526 */   MCD_OPC_CheckPredicate, 2, 200, 0, // Skip to: 12730
/* 12530 */   MCD_OPC_Decode, 244, 5, 177, 1, // Opcode: LWR
/* 12535 */   MCD_OPC_FilterValue, 40, 9, 0, // Skip to: 12548
/* 12539 */   MCD_OPC_CheckPredicate, 2, 187, 0, // Skip to: 12730
/* 12543 */   MCD_OPC_Decode, 198, 8, 177, 1, // Opcode: SB
/* 12548 */   MCD_OPC_FilterValue, 41, 9, 0, // Skip to: 12561
/* 12552 */   MCD_OPC_CheckPredicate, 2, 174, 0, // Skip to: 12730
/* 12556 */   MCD_OPC_Decode, 219, 8, 177, 1, // Opcode: SH
/* 12561 */   MCD_OPC_FilterValue, 42, 9, 0, // Skip to: 12574
/* 12565 */   MCD_OPC_CheckPredicate, 2, 161, 0, // Skip to: 12730
/* 12569 */   MCD_OPC_Decode, 135, 10, 177, 1, // Opcode: SWL
/* 12574 */   MCD_OPC_FilterValue, 43, 9, 0, // Skip to: 12587
/* 12578 */   MCD_OPC_CheckPredicate, 2, 148, 0, // Skip to: 12730
/* 12582 */   MCD_OPC_Decode, 131, 10, 177, 1, // Opcode: SW
/* 12587 */   MCD_OPC_FilterValue, 46, 9, 0, // Skip to: 12600
/* 12591 */   MCD_OPC_CheckPredicate, 2, 135, 0, // Skip to: 12730
/* 12595 */   MCD_OPC_Decode, 138, 10, 177, 1, // Opcode: SWR
/* 12600 */   MCD_OPC_FilterValue, 48, 9, 0, // Skip to: 12613
/* 12604 */   MCD_OPC_CheckPredicate, 2, 122, 0, // Skip to: 12730
/* 12608 */   MCD_OPC_Decode, 225, 5, 177, 1, // Opcode: LL
/* 12613 */   MCD_OPC_FilterValue, 49, 9, 0, // Skip to: 12626
/* 12617 */   MCD_OPC_CheckPredicate, 2, 109, 0, // Skip to: 12730
/* 12621 */   MCD_OPC_Decode, 239, 5, 178, 1, // Opcode: LWC1
/* 12626 */   MCD_OPC_FilterValue, 50, 9, 0, // Skip to: 12639
/* 12630 */   MCD_OPC_CheckPredicate, 2, 96, 0, // Skip to: 12730
/* 12634 */   MCD_OPC_Decode, 240, 5, 178, 1, // Opcode: LWC2
/* 12639 */   MCD_OPC_FilterValue, 53, 9, 0, // Skip to: 12652
/* 12643 */   MCD_OPC_CheckPredicate, 7, 83, 0, // Skip to: 12730
/* 12647 */   MCD_OPC_Decode, 201, 5, 178, 1, // Opcode: LDC1
/* 12652 */   MCD_OPC_FilterValue, 54, 9, 0, // Skip to: 12665
/* 12656 */   MCD_OPC_CheckPredicate, 2, 70, 0, // Skip to: 12730
/* 12660 */   MCD_OPC_Decode, 203, 5, 178, 1, // Opcode: LDC2
/* 12665 */   MCD_OPC_FilterValue, 56, 9, 0, // Skip to: 12678
/* 12669 */   MCD_OPC_CheckPredicate, 2, 57, 0, // Skip to: 12730
/* 12673 */   MCD_OPC_Decode, 201, 8, 177, 1, // Opcode: SC
/* 12678 */   MCD_OPC_FilterValue, 57, 9, 0, // Skip to: 12691
/* 12682 */   MCD_OPC_CheckPredicate, 2, 44, 0, // Skip to: 12730
/* 12686 */   MCD_OPC_Decode, 133, 10, 178, 1, // Opcode: SWC1
/* 12691 */   MCD_OPC_FilterValue, 58, 9, 0, // Skip to: 12704
/* 12695 */   MCD_OPC_CheckPredicate, 2, 31, 0, // Skip to: 12730
/* 12699 */   MCD_OPC_Decode, 134, 10, 178, 1, // Opcode: SWC2
/* 12704 */   MCD_OPC_FilterValue, 61, 9, 0, // Skip to: 12717
/* 12708 */   MCD_OPC_CheckPredicate, 7, 18, 0, // Skip to: 12730
/* 12712 */   MCD_OPC_Decode, 204, 8, 178, 1, // Opcode: SDC1
/* 12717 */   MCD_OPC_FilterValue, 62, 9, 0, // Skip to: 12730
/* 12721 */   MCD_OPC_CheckPredicate, 2, 5, 0, // Skip to: 12730
/* 12725 */   MCD_OPC_Decode, 206, 8, 178, 1, // Opcode: SDC2
/* 12730 */   MCD_OPC_Fail,
  0
};

static uint8_t DecoderTableMips6432[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 93, 1, // Skip to: 356
/* 7 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10 */      MCD_OPC_FilterValue, 20, 15, 0, // Skip to: 29
/* 14 */      MCD_OPC_CheckPredicate, 2, 6, 7, // Skip to: 1816
/* 18 */      MCD_OPC_CheckField, 6, 5, 0, 0, 7, // Skip to: 1816
/* 24 */      MCD_OPC_Decode, 219, 3, 179, 1, // Opcode: DSLLV
/* 29 */      MCD_OPC_FilterValue, 22, 29, 0, // Skip to: 62
/* 33 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 36 */      MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 49
/* 40 */      MCD_OPC_CheckPredicate, 2, 236, 6, // Skip to: 1816
/* 44 */      MCD_OPC_Decode, 225, 3, 179, 1, // Opcode: DSRLV
/* 49 */      MCD_OPC_FilterValue, 1, 227, 6, // Skip to: 1816
/* 53 */      MCD_OPC_CheckPredicate, 17, 223, 6, // Skip to: 1816
/* 57 */      MCD_OPC_Decode, 212, 3, 179, 1, // Opcode: DROTRV
/* 62 */      MCD_OPC_FilterValue, 23, 15, 0, // Skip to: 81
/* 66 */      MCD_OPC_CheckPredicate, 2, 210, 6, // Skip to: 1816
/* 70 */      MCD_OPC_CheckField, 6, 5, 0, 204, 6, // Skip to: 1816
/* 76 */      MCD_OPC_Decode, 222, 3, 179, 1, // Opcode: DSRAV
/* 81 */      MCD_OPC_FilterValue, 28, 15, 0, // Skip to: 100
/* 85 */      MCD_OPC_CheckPredicate, 2, 191, 6, // Skip to: 1816
/* 89 */      MCD_OPC_CheckField, 6, 10, 0, 185, 6, // Skip to: 1816
/* 95 */      MCD_OPC_Decode, 174, 3, 180, 1, // Opcode: DMULT
/* 100 */     MCD_OPC_FilterValue, 29, 15, 0, // Skip to: 119
/* 104 */     MCD_OPC_CheckPredicate, 2, 172, 6, // Skip to: 1816
/* 108 */     MCD_OPC_CheckField, 6, 10, 0, 166, 6, // Skip to: 1816
/* 114 */     MCD_OPC_Decode, 175, 3, 180, 1, // Opcode: DMULTu
/* 119 */     MCD_OPC_FilterValue, 30, 15, 0, // Skip to: 138
/* 123 */     MCD_OPC_CheckPredicate, 2, 153, 6, // Skip to: 1816
/* 127 */     MCD_OPC_CheckField, 6, 10, 0, 147, 6, // Skip to: 1816
/* 133 */     MCD_OPC_Decode, 214, 3, 180, 1, // Opcode: DSDIV
/* 138 */     MCD_OPC_FilterValue, 31, 15, 0, // Skip to: 157
/* 142 */     MCD_OPC_CheckPredicate, 2, 134, 6, // Skip to: 1816
/* 146 */     MCD_OPC_CheckField, 6, 10, 0, 128, 6, // Skip to: 1816
/* 152 */     MCD_OPC_Decode, 227, 3, 180, 1, // Opcode: DUDIV
/* 157 */     MCD_OPC_FilterValue, 44, 15, 0, // Skip to: 176
/* 161 */     MCD_OPC_CheckPredicate, 2, 115, 6, // Skip to: 1816
/* 165 */     MCD_OPC_CheckField, 6, 5, 0, 109, 6, // Skip to: 1816
/* 171 */     MCD_OPC_Decode, 146, 3, 181, 1, // Opcode: DADD
/* 176 */     MCD_OPC_FilterValue, 45, 15, 0, // Skip to: 195
/* 180 */     MCD_OPC_CheckPredicate, 2, 96, 6, // Skip to: 1816
/* 184 */     MCD_OPC_CheckField, 6, 5, 0, 90, 6, // Skip to: 1816
/* 190 */     MCD_OPC_Decode, 149, 3, 181, 1, // Opcode: DADDu
/* 195 */     MCD_OPC_FilterValue, 47, 15, 0, // Skip to: 214
/* 199 */     MCD_OPC_CheckPredicate, 2, 77, 6, // Skip to: 1816
/* 203 */     MCD_OPC_CheckField, 6, 5, 0, 71, 6, // Skip to: 1816
/* 209 */     MCD_OPC_Decode, 226, 3, 181, 1, // Opcode: DSUBu
/* 214 */     MCD_OPC_FilterValue, 56, 15, 0, // Skip to: 233
/* 218 */     MCD_OPC_CheckPredicate, 2, 58, 6, // Skip to: 1816
/* 222 */     MCD_OPC_CheckField, 21, 5, 0, 52, 6, // Skip to: 1816
/* 228 */     MCD_OPC_Decode, 216, 3, 182, 1, // Opcode: DSLL
/* 233 */     MCD_OPC_FilterValue, 58, 29, 0, // Skip to: 266
/* 237 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 240 */     MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 253
/* 244 */     MCD_OPC_CheckPredicate, 2, 32, 6, // Skip to: 1816
/* 248 */     MCD_OPC_Decode, 223, 3, 182, 1, // Opcode: DSRL
/* 253 */     MCD_OPC_FilterValue, 1, 23, 6, // Skip to: 1816
/* 257 */     MCD_OPC_CheckPredicate, 17, 19, 6, // Skip to: 1816
/* 261 */     MCD_OPC_Decode, 210, 3, 182, 1, // Opcode: DROTR
/* 266 */     MCD_OPC_FilterValue, 59, 15, 0, // Skip to: 285
/* 270 */     MCD_OPC_CheckPredicate, 2, 6, 6, // Skip to: 1816
/* 274 */     MCD_OPC_CheckField, 21, 5, 0, 0, 6, // Skip to: 1816
/* 280 */     MCD_OPC_Decode, 220, 3, 182, 1, // Opcode: DSRA
/* 285 */     MCD_OPC_FilterValue, 60, 15, 0, // Skip to: 304
/* 289 */     MCD_OPC_CheckPredicate, 2, 243, 5, // Skip to: 1816
/* 293 */     MCD_OPC_CheckField, 21, 5, 0, 237, 5, // Skip to: 1816
/* 299 */     MCD_OPC_Decode, 217, 3, 182, 1, // Opcode: DSLL32
/* 304 */     MCD_OPC_FilterValue, 62, 29, 0, // Skip to: 337
/* 308 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 311 */     MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 324
/* 315 */     MCD_OPC_CheckPredicate, 2, 217, 5, // Skip to: 1816
/* 319 */     MCD_OPC_Decode, 224, 3, 182, 1, // Opcode: DSRL32
/* 324 */     MCD_OPC_FilterValue, 1, 208, 5, // Skip to: 1816
/* 328 */     MCD_OPC_CheckPredicate, 17, 204, 5, // Skip to: 1816
/* 332 */     MCD_OPC_Decode, 211, 3, 182, 1, // Opcode: DROTR32
/* 337 */     MCD_OPC_FilterValue, 63, 195, 5, // Skip to: 1816
/* 341 */     MCD_OPC_CheckPredicate, 2, 191, 5, // Skip to: 1816
/* 345 */     MCD_OPC_CheckField, 21, 5, 0, 185, 5, // Skip to: 1816
/* 351 */     MCD_OPC_Decode, 221, 3, 182, 1, // Opcode: DSRA32
/* 356 */     MCD_OPC_FilterValue, 16, 41, 0, // Skip to: 401
/* 360 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 363 */     MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 382
/* 367 */     MCD_OPC_CheckPredicate, 18, 165, 5, // Skip to: 1816
/* 371 */     MCD_OPC_CheckField, 3, 8, 0, 159, 5, // Skip to: 1816
/* 377 */     MCD_OPC_Decode, 168, 3, 183, 1, // Opcode: DMFC0
/* 382 */     MCD_OPC_FilterValue, 5, 150, 5, // Skip to: 1816
/* 386 */     MCD_OPC_CheckPredicate, 18, 146, 5, // Skip to: 1816
/* 390 */     MCD_OPC_CheckField, 3, 8, 0, 140, 5, // Skip to: 1816
/* 396 */     MCD_OPC_Decode, 171, 3, 183, 1, // Opcode: DMTC0
/* 401 */     MCD_OPC_FilterValue, 17, 183, 3, // Skip to: 1356
/* 405 */     MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 408 */     MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 427
/* 412 */     MCD_OPC_CheckPredicate, 19, 120, 5, // Skip to: 1816
/* 416 */     MCD_OPC_CheckField, 21, 5, 17, 114, 5, // Skip to: 1816
/* 422 */     MCD_OPC_Decode, 255, 3, 184, 1, // Opcode: FADD_D64
/* 427 */     MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 446
/* 431 */     MCD_OPC_CheckPredicate, 19, 101, 5, // Skip to: 1816
/* 435 */     MCD_OPC_CheckField, 21, 5, 17, 95, 5, // Skip to: 1816
/* 441 */     MCD_OPC_Decode, 240, 4, 184, 1, // Opcode: FSUB_D64
/* 446 */     MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 465
/* 450 */     MCD_OPC_CheckPredicate, 19, 82, 5, // Skip to: 1816
/* 454 */     MCD_OPC_CheckField, 21, 5, 17, 76, 5, // Skip to: 1816
/* 460 */     MCD_OPC_Decode, 209, 4, 184, 1, // Opcode: FMUL_D64
/* 465 */     MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 484
/* 469 */     MCD_OPC_CheckPredicate, 19, 63, 5, // Skip to: 1816
/* 473 */     MCD_OPC_CheckField, 21, 5, 17, 57, 5, // Skip to: 1816
/* 479 */     MCD_OPC_Decode, 159, 4, 184, 1, // Opcode: FDIV_D64
/* 484 */     MCD_OPC_FilterValue, 4, 15, 0, // Skip to: 503
/* 488 */     MCD_OPC_CheckPredicate, 19, 44, 5, // Skip to: 1816
/* 492 */     MCD_OPC_CheckField, 16, 10, 160, 4, 37, 5, // Skip to: 1816
/* 499 */     MCD_OPC_Decode, 235, 4, 73, // Opcode: FSQRT_D64
/* 503 */     MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 522
/* 507 */     MCD_OPC_CheckPredicate, 6, 25, 5, // Skip to: 1816
/* 511 */     MCD_OPC_CheckField, 16, 10, 160, 4, 18, 5, // Skip to: 1816
/* 518 */     MCD_OPC_Decode, 250, 3, 73, // Opcode: FABS_D64
/* 522 */     MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 541
/* 526 */     MCD_OPC_CheckPredicate, 19, 6, 5, // Skip to: 1816
/* 530 */     MCD_OPC_CheckField, 16, 10, 160, 4, 255, 4, // Skip to: 1816
/* 537 */     MCD_OPC_Decode, 203, 4, 73, // Opcode: FMOV_D64
/* 541 */     MCD_OPC_FilterValue, 7, 15, 0, // Skip to: 560
/* 545 */     MCD_OPC_CheckPredicate, 6, 243, 4, // Skip to: 1816
/* 549 */     MCD_OPC_CheckField, 16, 10, 160, 4, 236, 4, // Skip to: 1816
/* 556 */     MCD_OPC_Decode, 213, 4, 73, // Opcode: FNEG_D64
/* 560 */     MCD_OPC_FilterValue, 8, 29, 0, // Skip to: 593
/* 564 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 567 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 580
/* 572 */     MCD_OPC_CheckPredicate, 19, 216, 4, // Skip to: 1816
/* 576 */     MCD_OPC_Decode, 182, 8, 66, // Opcode: ROUND_L_S
/* 580 */     MCD_OPC_FilterValue, 160, 4, 207, 4, // Skip to: 1816
/* 585 */     MCD_OPC_CheckPredicate, 19, 203, 4, // Skip to: 1816
/* 589 */     MCD_OPC_Decode, 181, 8, 73, // Opcode: ROUND_L_D64
/* 593 */     MCD_OPC_FilterValue, 9, 29, 0, // Skip to: 626
/* 597 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 600 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 613
/* 605 */     MCD_OPC_CheckPredicate, 19, 183, 4, // Skip to: 1816
/* 609 */     MCD_OPC_Decode, 208, 10, 66, // Opcode: TRUNC_L_S
/* 613 */     MCD_OPC_FilterValue, 160, 4, 174, 4, // Skip to: 1816
/* 618 */     MCD_OPC_CheckPredicate, 19, 170, 4, // Skip to: 1816
/* 622 */     MCD_OPC_Decode, 207, 10, 73, // Opcode: TRUNC_L_D64
/* 626 */     MCD_OPC_FilterValue, 10, 29, 0, // Skip to: 659
/* 630 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 633 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 646
/* 638 */     MCD_OPC_CheckPredicate, 19, 150, 4, // Skip to: 1816
/* 642 */     MCD_OPC_Decode, 135, 2, 66, // Opcode: CEIL_L_S
/* 646 */     MCD_OPC_FilterValue, 160, 4, 141, 4, // Skip to: 1816
/* 651 */     MCD_OPC_CheckPredicate, 19, 137, 4, // Skip to: 1816
/* 655 */     MCD_OPC_Decode, 134, 2, 73, // Opcode: CEIL_L_D64
/* 659 */     MCD_OPC_FilterValue, 11, 29, 0, // Skip to: 692
/* 663 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 666 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 679
/* 671 */     MCD_OPC_CheckPredicate, 19, 117, 4, // Skip to: 1816
/* 675 */     MCD_OPC_Decode, 188, 4, 66, // Opcode: FLOOR_L_S
/* 679 */     MCD_OPC_FilterValue, 160, 4, 108, 4, // Skip to: 1816
/* 684 */     MCD_OPC_CheckPredicate, 19, 104, 4, // Skip to: 1816
/* 688 */     MCD_OPC_Decode, 187, 4, 73, // Opcode: FLOOR_L_D64
/* 692 */     MCD_OPC_FilterValue, 12, 16, 0, // Skip to: 712
/* 696 */     MCD_OPC_CheckPredicate, 19, 92, 4, // Skip to: 1816
/* 700 */     MCD_OPC_CheckField, 16, 10, 160, 4, 85, 4, // Skip to: 1816
/* 707 */     MCD_OPC_Decode, 184, 8, 185, 1, // Opcode: ROUND_W_D64
/* 712 */     MCD_OPC_FilterValue, 13, 16, 0, // Skip to: 732
/* 716 */     MCD_OPC_CheckPredicate, 19, 72, 4, // Skip to: 1816
/* 720 */     MCD_OPC_CheckField, 16, 10, 160, 4, 65, 4, // Skip to: 1816
/* 727 */     MCD_OPC_Decode, 210, 10, 185, 1, // Opcode: TRUNC_W_D64
/* 732 */     MCD_OPC_FilterValue, 14, 16, 0, // Skip to: 752
/* 736 */     MCD_OPC_CheckPredicate, 19, 52, 4, // Skip to: 1816
/* 740 */     MCD_OPC_CheckField, 16, 10, 160, 4, 45, 4, // Skip to: 1816
/* 747 */     MCD_OPC_Decode, 137, 2, 185, 1, // Opcode: CEIL_W_D64
/* 752 */     MCD_OPC_FilterValue, 15, 16, 0, // Skip to: 772
/* 756 */     MCD_OPC_CheckPredicate, 19, 32, 4, // Skip to: 1816
/* 760 */     MCD_OPC_CheckField, 16, 10, 160, 4, 25, 4, // Skip to: 1816
/* 767 */     MCD_OPC_Decode, 190, 4, 185, 1, // Opcode: FLOOR_W_D64
/* 772 */     MCD_OPC_FilterValue, 17, 41, 0, // Skip to: 817
/* 776 */     MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 779 */     MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 798
/* 783 */     MCD_OPC_CheckPredicate, 19, 5, 4, // Skip to: 1816
/* 787 */     MCD_OPC_CheckField, 21, 5, 17, 255, 3, // Skip to: 1816
/* 793 */     MCD_OPC_Decode, 224, 6, 186, 1, // Opcode: MOVF_D64
/* 798 */     MCD_OPC_FilterValue, 1, 246, 3, // Skip to: 1816
/* 802 */     MCD_OPC_CheckPredicate, 19, 242, 3, // Skip to: 1816
/* 806 */     MCD_OPC_CheckField, 21, 5, 17, 236, 3, // Skip to: 1816
/* 812 */     MCD_OPC_Decode, 240, 6, 186, 1, // Opcode: MOVT_D64
/* 817 */     MCD_OPC_FilterValue, 18, 15, 0, // Skip to: 836
/* 821 */     MCD_OPC_CheckPredicate, 19, 223, 3, // Skip to: 1816
/* 825 */     MCD_OPC_CheckField, 21, 5, 17, 217, 3, // Skip to: 1816
/* 831 */     MCD_OPC_Decode, 250, 6, 187, 1, // Opcode: MOVZ_I_D64
/* 836 */     MCD_OPC_FilterValue, 19, 15, 0, // Skip to: 855
/* 840 */     MCD_OPC_CheckPredicate, 19, 204, 3, // Skip to: 1816
/* 844 */     MCD_OPC_CheckField, 21, 5, 17, 198, 3, // Skip to: 1816
/* 850 */     MCD_OPC_Decode, 234, 6, 187, 1, // Opcode: MOVN_I_D64
/* 855 */     MCD_OPC_FilterValue, 32, 31, 0, // Skip to: 890
/* 859 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 862 */     MCD_OPC_FilterValue, 160, 4, 9, 0, // Skip to: 876
/* 867 */     MCD_OPC_CheckPredicate, 19, 177, 3, // Skip to: 1816
/* 871 */     MCD_OPC_Decode, 216, 2, 185, 1, // Opcode: CVT_S_D64
/* 876 */     MCD_OPC_FilterValue, 160, 5, 167, 3, // Skip to: 1816
/* 881 */     MCD_OPC_CheckPredicate, 19, 163, 3, // Skip to: 1816
/* 885 */     MCD_OPC_Decode, 217, 2, 185, 1, // Opcode: CVT_S_L
/* 890 */     MCD_OPC_FilterValue, 33, 42, 0, // Skip to: 936
/* 894 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 897 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 910
/* 902 */     MCD_OPC_CheckPredicate, 19, 142, 3, // Skip to: 1816
/* 906 */     MCD_OPC_Decode, 211, 2, 66, // Opcode: CVT_D64_S
/* 910 */     MCD_OPC_FilterValue, 128, 5, 8, 0, // Skip to: 923
/* 915 */     MCD_OPC_CheckPredicate, 19, 129, 3, // Skip to: 1816
/* 919 */     MCD_OPC_Decode, 212, 2, 66, // Opcode: CVT_D64_W
/* 923 */     MCD_OPC_FilterValue, 160, 5, 120, 3, // Skip to: 1816
/* 928 */     MCD_OPC_CheckPredicate, 19, 116, 3, // Skip to: 1816
/* 932 */     MCD_OPC_Decode, 210, 2, 73, // Opcode: CVT_D64_L
/* 936 */     MCD_OPC_FilterValue, 36, 16, 0, // Skip to: 956
/* 940 */     MCD_OPC_CheckPredicate, 19, 104, 3, // Skip to: 1816
/* 944 */     MCD_OPC_CheckField, 16, 10, 160, 4, 97, 3, // Skip to: 1816
/* 951 */     MCD_OPC_Decode, 220, 2, 185, 1, // Opcode: CVT_W_D64
/* 956 */     MCD_OPC_FilterValue, 48, 21, 0, // Skip to: 981
/* 960 */     MCD_OPC_CheckPredicate, 19, 84, 3, // Skip to: 1816
/* 964 */     MCD_OPC_CheckField, 21, 5, 17, 78, 3, // Skip to: 1816
/* 970 */     MCD_OPC_CheckField, 6, 5, 0, 72, 3, // Skip to: 1816
/* 976 */     MCD_OPC_Decode, 226, 2, 188, 1, // Opcode: C_F_D64
/* 981 */     MCD_OPC_FilterValue, 49, 21, 0, // Skip to: 1006
/* 985 */     MCD_OPC_CheckPredicate, 19, 59, 3, // Skip to: 1816
/* 989 */     MCD_OPC_CheckField, 21, 5, 17, 53, 3, // Skip to: 1816
/* 995 */     MCD_OPC_CheckField, 6, 5, 0, 47, 3, // Skip to: 1816
/* 1001 */    MCD_OPC_Decode, 140, 3, 188, 1, // Opcode: C_UN_D64
/* 1006 */    MCD_OPC_FilterValue, 50, 21, 0, // Skip to: 1031
/* 1010 */    MCD_OPC_CheckPredicate, 19, 34, 3, // Skip to: 1816
/* 1014 */    MCD_OPC_CheckField, 21, 5, 17, 28, 3, // Skip to: 1816
/* 1020 */    MCD_OPC_CheckField, 6, 5, 0, 22, 3, // Skip to: 1816
/* 1026 */    MCD_OPC_Decode, 223, 2, 188, 1, // Opcode: C_EQ_D64
/* 1031 */    MCD_OPC_FilterValue, 51, 21, 0, // Skip to: 1056
/* 1035 */    MCD_OPC_CheckPredicate, 19, 9, 3, // Skip to: 1816
/* 1039 */    MCD_OPC_CheckField, 21, 5, 17, 3, 3, // Skip to: 1816
/* 1045 */    MCD_OPC_CheckField, 6, 5, 0, 253, 2, // Skip to: 1816
/* 1051 */    MCD_OPC_Decode, 131, 3, 188, 1, // Opcode: C_UEQ_D64
/* 1056 */    MCD_OPC_FilterValue, 52, 21, 0, // Skip to: 1081
/* 1060 */    MCD_OPC_CheckPredicate, 19, 240, 2, // Skip to: 1816
/* 1064 */    MCD_OPC_CheckField, 21, 5, 17, 234, 2, // Skip to: 1816
/* 1070 */    MCD_OPC_CheckField, 6, 5, 0, 228, 2, // Skip to: 1816
/* 1076 */    MCD_OPC_Decode, 250, 2, 188, 1, // Opcode: C_OLT_D64
/* 1081 */    MCD_OPC_FilterValue, 53, 21, 0, // Skip to: 1106
/* 1085 */    MCD_OPC_CheckPredicate, 19, 215, 2, // Skip to: 1816
/* 1089 */    MCD_OPC_CheckField, 21, 5, 17, 209, 2, // Skip to: 1816
/* 1095 */    MCD_OPC_CheckField, 6, 5, 0, 203, 2, // Skip to: 1816
/* 1101 */    MCD_OPC_Decode, 137, 3, 188, 1, // Opcode: C_ULT_D64
/* 1106 */    MCD_OPC_FilterValue, 54, 21, 0, // Skip to: 1131
/* 1110 */    MCD_OPC_CheckPredicate, 19, 190, 2, // Skip to: 1816
/* 1114 */    MCD_OPC_CheckField, 21, 5, 17, 184, 2, // Skip to: 1816
/* 1120 */    MCD_OPC_CheckField, 6, 5, 0, 178, 2, // Skip to: 1816
/* 1126 */    MCD_OPC_Decode, 247, 2, 188, 1, // Opcode: C_OLE_D64
/* 1131 */    MCD_OPC_FilterValue, 55, 21, 0, // Skip to: 1156
/* 1135 */    MCD_OPC_CheckPredicate, 19, 165, 2, // Skip to: 1816
/* 1139 */    MCD_OPC_CheckField, 21, 5, 17, 159, 2, // Skip to: 1816
/* 1145 */    MCD_OPC_CheckField, 6, 5, 0, 153, 2, // Skip to: 1816
/* 1151 */    MCD_OPC_Decode, 134, 3, 188, 1, // Opcode: C_ULE_D64
/* 1156 */    MCD_OPC_FilterValue, 56, 21, 0, // Skip to: 1181
/* 1160 */    MCD_OPC_CheckPredicate, 19, 140, 2, // Skip to: 1816
/* 1164 */    MCD_OPC_CheckField, 21, 5, 17, 134, 2, // Skip to: 1816
/* 1170 */    MCD_OPC_CheckField, 6, 5, 0, 128, 2, // Skip to: 1816
/* 1176 */    MCD_OPC_Decode, 128, 3, 188, 1, // Opcode: C_SF_D64
/* 1181 */    MCD_OPC_FilterValue, 57, 21, 0, // Skip to: 1206
/* 1185 */    MCD_OPC_CheckPredicate, 19, 115, 2, // Skip to: 1816
/* 1189 */    MCD_OPC_CheckField, 21, 5, 17, 109, 2, // Skip to: 1816
/* 1195 */    MCD_OPC_CheckField, 6, 5, 0, 103, 2, // Skip to: 1816
/* 1201 */    MCD_OPC_Decode, 238, 2, 188, 1, // Opcode: C_NGLE_D64
/* 1206 */    MCD_OPC_FilterValue, 58, 21, 0, // Skip to: 1231
/* 1210 */    MCD_OPC_CheckPredicate, 19, 90, 2, // Skip to: 1816
/* 1214 */    MCD_OPC_CheckField, 21, 5, 17, 84, 2, // Skip to: 1816
/* 1220 */    MCD_OPC_CheckField, 6, 5, 0, 78, 2, // Skip to: 1816
/* 1226 */    MCD_OPC_Decode, 253, 2, 188, 1, // Opcode: C_SEQ_D64
/* 1231 */    MCD_OPC_FilterValue, 59, 21, 0, // Skip to: 1256
/* 1235 */    MCD_OPC_CheckPredicate, 19, 65, 2, // Skip to: 1816
/* 1239 */    MCD_OPC_CheckField, 21, 5, 17, 59, 2, // Skip to: 1816
/* 1245 */    MCD_OPC_CheckField, 6, 5, 0, 53, 2, // Skip to: 1816
/* 1251 */    MCD_OPC_Decode, 241, 2, 188, 1, // Opcode: C_NGL_D64
/* 1256 */    MCD_OPC_FilterValue, 60, 21, 0, // Skip to: 1281
/* 1260 */    MCD_OPC_CheckPredicate, 19, 40, 2, // Skip to: 1816
/* 1264 */    MCD_OPC_CheckField, 21, 5, 17, 34, 2, // Skip to: 1816
/* 1270 */    MCD_OPC_CheckField, 6, 5, 0, 28, 2, // Skip to: 1816
/* 1276 */    MCD_OPC_Decode, 232, 2, 188, 1, // Opcode: C_LT_D64
/* 1281 */    MCD_OPC_FilterValue, 61, 21, 0, // Skip to: 1306
/* 1285 */    MCD_OPC_CheckPredicate, 19, 15, 2, // Skip to: 1816
/* 1289 */    MCD_OPC_CheckField, 21, 5, 17, 9, 2, // Skip to: 1816
/* 1295 */    MCD_OPC_CheckField, 6, 5, 0, 3, 2, // Skip to: 1816
/* 1301 */    MCD_OPC_Decode, 235, 2, 188, 1, // Opcode: C_NGE_D64
/* 1306 */    MCD_OPC_FilterValue, 62, 21, 0, // Skip to: 1331
/* 1310 */    MCD_OPC_CheckPredicate, 19, 246, 1, // Skip to: 1816
/* 1314 */    MCD_OPC_CheckField, 21, 5, 17, 240, 1, // Skip to: 1816
/* 1320 */    MCD_OPC_CheckField, 6, 5, 0, 234, 1, // Skip to: 1816
/* 1326 */    MCD_OPC_Decode, 229, 2, 188, 1, // Opcode: C_LE_D64
/* 1331 */    MCD_OPC_FilterValue, 63, 225, 1, // Skip to: 1816
/* 1335 */    MCD_OPC_CheckPredicate, 19, 221, 1, // Skip to: 1816
/* 1339 */    MCD_OPC_CheckField, 21, 5, 17, 215, 1, // Skip to: 1816
/* 1345 */    MCD_OPC_CheckField, 6, 5, 0, 209, 1, // Skip to: 1816
/* 1351 */    MCD_OPC_Decode, 244, 2, 188, 1, // Opcode: C_NGT_D64
/* 1356 */    MCD_OPC_FilterValue, 18, 41, 0, // Skip to: 1401
/* 1360 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1363 */    MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 1382
/* 1367 */    MCD_OPC_CheckPredicate, 18, 189, 1, // Skip to: 1816
/* 1371 */    MCD_OPC_CheckField, 3, 8, 0, 183, 1, // Skip to: 1816
/* 1377 */    MCD_OPC_Decode, 170, 3, 183, 1, // Opcode: DMFC2
/* 1382 */    MCD_OPC_FilterValue, 5, 174, 1, // Skip to: 1816
/* 1386 */    MCD_OPC_CheckPredicate, 18, 170, 1, // Skip to: 1816
/* 1390 */    MCD_OPC_CheckField, 3, 8, 0, 164, 1, // Skip to: 1816
/* 1396 */    MCD_OPC_Decode, 173, 3, 183, 1, // Opcode: DMTC2
/* 1401 */    MCD_OPC_FilterValue, 19, 79, 0, // Skip to: 1484
/* 1405 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1408 */    MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 1427
/* 1412 */    MCD_OPC_CheckPredicate, 20, 144, 1, // Skip to: 1816
/* 1416 */    MCD_OPC_CheckField, 11, 5, 0, 138, 1, // Skip to: 1816
/* 1422 */    MCD_OPC_Decode, 211, 5, 189, 1, // Opcode: LDXC164
/* 1427 */    MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 1446
/* 1431 */    MCD_OPC_CheckPredicate, 19, 125, 1, // Skip to: 1816
/* 1435 */    MCD_OPC_CheckField, 11, 5, 0, 119, 1, // Skip to: 1816
/* 1441 */    MCD_OPC_Decode, 233, 5, 189, 1, // Opcode: LUXC164
/* 1446 */    MCD_OPC_FilterValue, 9, 15, 0, // Skip to: 1465
/* 1450 */    MCD_OPC_CheckPredicate, 20, 106, 1, // Skip to: 1816
/* 1454 */    MCD_OPC_CheckField, 6, 5, 0, 100, 1, // Skip to: 1816
/* 1460 */    MCD_OPC_Decode, 212, 8, 190, 1, // Opcode: SDXC164
/* 1465 */    MCD_OPC_FilterValue, 13, 91, 1, // Skip to: 1816
/* 1469 */    MCD_OPC_CheckPredicate, 19, 87, 1, // Skip to: 1816
/* 1473 */    MCD_OPC_CheckField, 6, 5, 0, 81, 1, // Skip to: 1816
/* 1479 */    MCD_OPC_Decode, 130, 10, 190, 1, // Opcode: SUXC164
/* 1484 */    MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 1497
/* 1488 */    MCD_OPC_CheckPredicate, 2, 68, 1, // Skip to: 1816
/* 1492 */    MCD_OPC_Decode, 147, 3, 191, 1, // Opcode: DADDi
/* 1497 */    MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 1510
/* 1501 */    MCD_OPC_CheckPredicate, 2, 55, 1, // Skip to: 1816
/* 1505 */    MCD_OPC_Decode, 148, 3, 191, 1, // Opcode: DADDiu
/* 1510 */    MCD_OPC_FilterValue, 26, 9, 0, // Skip to: 1523
/* 1514 */    MCD_OPC_CheckPredicate, 2, 42, 1, // Skip to: 1816
/* 1518 */    MCD_OPC_Decode, 208, 5, 177, 1, // Opcode: LDL
/* 1523 */    MCD_OPC_FilterValue, 27, 9, 0, // Skip to: 1536
/* 1527 */    MCD_OPC_CheckPredicate, 2, 29, 1, // Skip to: 1816
/* 1531 */    MCD_OPC_Decode, 209, 5, 177, 1, // Opcode: LDR
/* 1536 */    MCD_OPC_FilterValue, 28, 29, 0, // Skip to: 1569
/* 1540 */    MCD_OPC_ExtractField, 0, 11,  // Inst{10-0} ...
/* 1543 */    MCD_OPC_FilterValue, 36, 9, 0, // Skip to: 1556
/* 1547 */    MCD_OPC_CheckPredicate, 13, 9, 1, // Skip to: 1816
/* 1551 */    MCD_OPC_Decode, 151, 3, 192, 1, // Opcode: DCLZ
/* 1556 */    MCD_OPC_FilterValue, 37, 0, 1, // Skip to: 1816
/* 1560 */    MCD_OPC_CheckPredicate, 13, 252, 0, // Skip to: 1816
/* 1564 */    MCD_OPC_Decode, 150, 3, 192, 1, // Opcode: DCLO
/* 1569 */    MCD_OPC_FilterValue, 31, 126, 0, // Skip to: 1699
/* 1573 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1576 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 1589
/* 1580 */    MCD_OPC_CheckPredicate, 3, 232, 0, // Skip to: 1816
/* 1584 */    MCD_OPC_Decode, 154, 3, 193, 1, // Opcode: DEXTM
/* 1589 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 1602
/* 1593 */    MCD_OPC_CheckPredicate, 3, 219, 0, // Skip to: 1816
/* 1597 */    MCD_OPC_Decode, 155, 3, 193, 1, // Opcode: DEXTU
/* 1602 */    MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 1615
/* 1606 */    MCD_OPC_CheckPredicate, 3, 206, 0, // Skip to: 1816
/* 1610 */    MCD_OPC_Decode, 153, 3, 193, 1, // Opcode: DEXT
/* 1615 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 1628
/* 1619 */    MCD_OPC_CheckPredicate, 3, 193, 0, // Skip to: 1816
/* 1623 */    MCD_OPC_Decode, 158, 3, 194, 1, // Opcode: DINSM
/* 1628 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 1641
/* 1632 */    MCD_OPC_CheckPredicate, 3, 180, 0, // Skip to: 1816
/* 1636 */    MCD_OPC_Decode, 159, 3, 194, 1, // Opcode: DINSU
/* 1641 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 1654
/* 1645 */    MCD_OPC_CheckPredicate, 3, 167, 0, // Skip to: 1816
/* 1649 */    MCD_OPC_Decode, 157, 3, 194, 1, // Opcode: DINS
/* 1654 */    MCD_OPC_FilterValue, 36, 158, 0, // Skip to: 1816
/* 1658 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 1661 */    MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 1680
/* 1665 */    MCD_OPC_CheckPredicate, 15, 147, 0, // Skip to: 1816
/* 1669 */    MCD_OPC_CheckField, 21, 5, 0, 141, 0, // Skip to: 1816
/* 1675 */    MCD_OPC_Decode, 213, 3, 195, 1, // Opcode: DSBH
/* 1680 */    MCD_OPC_FilterValue, 5, 132, 0, // Skip to: 1816
/* 1684 */    MCD_OPC_CheckPredicate, 15, 128, 0, // Skip to: 1816
/* 1688 */    MCD_OPC_CheckField, 21, 5, 0, 122, 0, // Skip to: 1816
/* 1694 */    MCD_OPC_Decode, 215, 3, 195, 1, // Opcode: DSHD
/* 1699 */    MCD_OPC_FilterValue, 39, 9, 0, // Skip to: 1712
/* 1703 */    MCD_OPC_CheckPredicate, 2, 109, 0, // Skip to: 1816
/* 1707 */    MCD_OPC_Decode, 250, 5, 177, 1, // Opcode: LWu
/* 1712 */    MCD_OPC_FilterValue, 44, 9, 0, // Skip to: 1725
/* 1716 */    MCD_OPC_CheckPredicate, 2, 96, 0, // Skip to: 1816
/* 1720 */    MCD_OPC_Decode, 209, 8, 177, 1, // Opcode: SDL
/* 1725 */    MCD_OPC_FilterValue, 45, 9, 0, // Skip to: 1738
/* 1729 */    MCD_OPC_CheckPredicate, 2, 83, 0, // Skip to: 1816
/* 1733 */    MCD_OPC_Decode, 210, 8, 177, 1, // Opcode: SDR
/* 1738 */    MCD_OPC_FilterValue, 52, 9, 0, // Skip to: 1751
/* 1742 */    MCD_OPC_CheckPredicate, 2, 70, 0, // Skip to: 1816
/* 1746 */    MCD_OPC_Decode, 226, 5, 177, 1, // Opcode: LLD
/* 1751 */    MCD_OPC_FilterValue, 53, 9, 0, // Skip to: 1764
/* 1755 */    MCD_OPC_CheckPredicate, 19, 57, 0, // Skip to: 1816
/* 1759 */    MCD_OPC_Decode, 202, 5, 178, 1, // Opcode: LDC164
/* 1764 */    MCD_OPC_FilterValue, 55, 9, 0, // Skip to: 1777
/* 1768 */    MCD_OPC_CheckPredicate, 2, 44, 0, // Skip to: 1816
/* 1772 */    MCD_OPC_Decode, 200, 5, 177, 1, // Opcode: LD
/* 1777 */    MCD_OPC_FilterValue, 60, 9, 0, // Skip to: 1790
/* 1781 */    MCD_OPC_CheckPredicate, 2, 31, 0, // Skip to: 1816
/* 1785 */    MCD_OPC_Decode, 202, 8, 177, 1, // Opcode: SCD
/* 1790 */    MCD_OPC_FilterValue, 61, 9, 0, // Skip to: 1803
/* 1794 */    MCD_OPC_CheckPredicate, 19, 18, 0, // Skip to: 1816
/* 1798 */    MCD_OPC_Decode, 205, 8, 178, 1, // Opcode: SDC164
/* 1803 */    MCD_OPC_FilterValue, 63, 9, 0, // Skip to: 1816
/* 1807 */    MCD_OPC_CheckPredicate, 2, 5, 0, // Skip to: 1816
/* 1811 */    MCD_OPC_Decode, 203, 8, 177, 1, // Opcode: SD
/* 1816 */    MCD_OPC_Fail,
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
    return (!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMicroMips));
  case 3:
    return ((Bits & Mips_FeatureMips32r2) && !(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMicroMips));
  case 4:
    return ((Bits & Mips_FeatureMSA));
  case 5:
    return ((Bits & Mips_FeatureDSP));
  case 6:
    return ((Bits & Mips_FeatureMips32) && !(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMicroMips));
  case 7:
    return (!(Bits & Mips_FeatureFP64Bit) && !(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMicroMips));
  case 8:
    return ((Bits & Mips_FeatureFPIdx) && !(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMicroMips));
  case 9:
    return ((Bits & Mips_FeatureFPIdx) && !(Bits & Mips_FeatureFP64Bit) && !(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMicroMips));
  case 10:
    return ((Bits & Mips_FeatureMips32r2) && !(Bits & Mips_FeatureFP64Bit) && !(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMicroMips));
  case 11:
    return ((Bits & Mips_FeatureMips32r2) && (Bits & Mips_FeatureMips32) && !(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMicroMips));
  case 12:
    return ((Bits & Mips_FeatureMips32r2) && !(Bits & Mips_FeatureFP64Bit) && (Bits & Mips_FeatureMips32) && !(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMicroMips));
  case 13:
    return ((Bits & Mips_FeatureBitCount) && !(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMicroMips));
  case 14:
    return ((Bits & Mips_FeatureDSPR2));
  case 15:
    return ((Bits & Mips_FeatureSwap) && !(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMicroMips));
  case 16:
    return ((Bits & Mips_FeatureSEInReg) && !(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMicroMips));
  case 17:
    return ((Bits & Mips_FeatureMips64r2) && !(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMicroMips));
  case 18:
    return ((Bits & Mips_FeatureMips64));
  case 19:
    return ((Bits & Mips_FeatureFP64Bit) && !(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMicroMips));
  case 20:
    return ((Bits & Mips_FeatureFPIdx) && (Bits & Mips_FeatureFP64Bit) && !(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMicroMips));
  }
}

static DecodeStatus decodeToMCInst(DecodeStatus S, unsigned Idx, uint32_t insn, MCInst *MI,
       uint64_t Address, MCRegisterInfo *Decoder)
{
  uint32_t tmp;

  switch (Idx) {
  default: //llvm_unreachable("Invalid index!");
  case 0:
    tmp = fieldFromInstruction(insn, 8, 3);
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 1:
    tmp = fieldFromInstruction(insn, 8, 3);
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 8, 3);
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 2:
    return S;
  case 3:
    tmp = 0;
    tmp |= (fieldFromInstruction(insn, 3, 2) << 3);
    tmp |= (fieldFromInstruction(insn, 5, 3) << 0);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 3);
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 4:
    tmp = fieldFromInstruction(insn, 0, 4);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 5:
    tmp = fieldFromInstruction(insn, 2, 3);
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 8, 3);
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 5, 3);
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 6:
    tmp = fieldFromInstruction(insn, 8, 3);
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 5, 3);
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 7:
    tmp = fieldFromInstruction(insn, 8, 3);
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 8, 3);
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 5, 3);
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 8:
    tmp = 0;
    tmp |= (fieldFromInstruction(insn, 0, 5) << 0);
    tmp |= (fieldFromInstruction(insn, 16, 5) << 11);
    tmp |= (fieldFromInstruction(insn, 21, 6) << 5);
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 9:
    tmp = fieldFromInstruction(insn, 5, 3);
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 10:
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 11:
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeInsSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 12:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 13:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 14:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 15:
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeExtSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 16:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 17:
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 18:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 19:
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 20:
    if (DecodeMemMMImm16(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 21:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    if (DecodeBranchTargetMM(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 22:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 23:
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 24:
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 13, 3);
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 25:
    if (DecodeMemMMImm12(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 26:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 27:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    if (DecodeBranchTargetMM(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 28:
    if (DecodeJumpTargetMM(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 29:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 30:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 18, 3);
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 31:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 2);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 32:
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 33:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 34:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 35:
    tmp = fieldFromInstruction(insn, 6, 20);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 36:
    tmp = fieldFromInstruction(insn, 16, 10);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    tmp = fieldFromInstruction(insn, 6, 10);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 37:
    tmp = fieldFromInstruction(insn, 6, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 38:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 39:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 2);
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 40:
    tmp = fieldFromInstruction(insn, 11, 2);
    if (DecodeHI32DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 41:
    tmp = fieldFromInstruction(insn, 11, 2);
    if (DecodeLO32DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 42:
    tmp = fieldFromInstruction(insn, 11, 2);
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 43:
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 10);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 44:
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 45:
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 46:
    tmp = fieldFromInstruction(insn, 0, 16);
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 47:
    if (DecodeJumpTarget(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 48:
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 49:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 50:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 3);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 51:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 52:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 53:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeCCRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 54:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGRH32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 55:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 56:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 57:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeCCRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 58:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGRH32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 59:
    tmp = fieldFromInstruction(insn, 18, 3);
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 60:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 61:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 62:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 63:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 18, 3);
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 64:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 65:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 66:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 67:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 68:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 69:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 70:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 71:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 18, 3);
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 72:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 73:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 74:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 75:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 76:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 77:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 78:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 79:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 80:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 81:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 82:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 83:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 84:
    tmp = fieldFromInstruction(insn, 11, 2);
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 2);
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 85:
    tmp = 0;
    tmp |= (fieldFromInstruction(insn, 11, 5) << 0);
    tmp |= (fieldFromInstruction(insn, 16, 5) << 0);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 86:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 8);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 87:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 8);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 88:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 8);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 89:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 8);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 90:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 91:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 92:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 93:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 94:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 6);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 95:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 4);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 96:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 3);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 97:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 6);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 98:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 99:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 4);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 100:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 3);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 101:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 10);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 102:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 10);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 103:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 10);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 104:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 10);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 105:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 106:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 107:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 108:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 109:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 110:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 111:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 112:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 113:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 114:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 115:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 116:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 117:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 118:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 119:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 120:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 121:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 122:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 123:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 4);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 124:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 3);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 125:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 2);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 126:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 1);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 127:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSACtrlRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 128:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSACtrlRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 129:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 4);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 130:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 3);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 131:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 2);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 132:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 133:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 4);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 134:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 3);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 135:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 2);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 136:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 4);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 137:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 3);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 138:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 2);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 139:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 1);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 140:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 141:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 142:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 143:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 144:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 145:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 146:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 147:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 148:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 149:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 150:
    if (DecodeMSA128Mem(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 151:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeExtSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 152:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeInsSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 153:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 154:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 155:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 156:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 157:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 158:
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 159:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 160:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 161:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 162:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 10);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 163:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 164:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 165:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 166:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 167:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 168:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 169:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 170:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 2);
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 171:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 2);
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 172:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 10);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 173:
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 10);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 174:
    tmp = fieldFromInstruction(insn, 11, 2);
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 20, 6);
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 2);
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 175:
    tmp = fieldFromInstruction(insn, 11, 2);
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 2);
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 176:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeHWRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 177:
    if (DecodeMem(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 178:
    if (DecodeFMem(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 179:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 180:
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 181:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 182:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 183:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 3);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 184:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 185:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 186:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 18, 3);
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 187:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 188:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 189:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 190:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 191:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 192:
    tmp = 0;
    tmp |= (fieldFromInstruction(insn, 11, 5) << 0);
    tmp |= (fieldFromInstruction(insn, 16, 5) << 0);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 193:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeExtSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 194:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeInsSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 195:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  }
}

static DecodeStatus decodeInstruction(uint8_t DecodeTable[], MCInst *MI,
  uint32_t insn, uint64_t Address, MCRegisterInfo *MRI, int mode)
{
  uint64_t Bits = Mips_getFeatureBits(mode);
  //printf(">>>> Bits: %llx\n", Bits);
  uint8_t *Ptr = DecodeTable;
  uint32_t CurFieldValue = 0;
  DecodeStatus S = MCDisassembler_Success;
  for (;;) {
    //unsigned Loc = Ptr - DecodeTable;
	//printf(">> Loc: %lu\n", Ptr - DecodeTable);
    switch (*Ptr) {
    default:
      //errs() << Loc << ": Unexpected decode table opcode!\n";
      return MCDisassembler_Fail;
    case MCD_OPC_ExtractField: {
	  //printf("::OPC_ExtractField\n");
      unsigned Start = *++Ptr;
      unsigned Len = *++Ptr;
      ++Ptr;
      CurFieldValue = fieldFromInstruction(insn, Start, Len);
      //DEBUG(dbgs() << Loc << ": OPC_ExtractField(" << Start << ", "
      //             << Len << "): " << CurFieldValue << "\n");
      break;
    }
    case MCD_OPC_FilterValue: {
	  //printf("::OPC_FilterValue\n");
      // Decode the field value.
      unsigned Len;
      uint32_t Val = decodeULEB128(++Ptr, &Len);
      Ptr += Len;
      // NumToSkip is a plain 16-bit integer.
      unsigned NumToSkip = *Ptr++;
      NumToSkip |= (*Ptr++) << 8;

      // Perform the filter operation.
      if (Val != CurFieldValue)
        Ptr += NumToSkip;
      //DEBUG(dbgs() << Loc << ": OPC_FilterValue(" << Val << ", " << NumToSkip
      //             << "): " << ((Val != CurFieldValue) ? "FAIL:" : "PASS:")
      //             << " continuing at " << (Ptr - DecodeTable) << "\n");

      break;
    }
    case MCD_OPC_CheckField: {
	  //printf("::OPC_CheckField\n");
      unsigned Start = *++Ptr;
      unsigned Len = *++Ptr;
      uint32_t FieldValue = fieldFromInstruction(insn, Start, Len);
      // Decode the field value.
      uint32_t ExpectedValue = decodeULEB128(++Ptr, &Len);
      Ptr += Len;
      // NumToSkip is a plain 16-bit integer.
      unsigned NumToSkip = *Ptr++;
      NumToSkip |= (*Ptr++) << 8;

      // If the actual and expected values don't match, skip.
      if (ExpectedValue != FieldValue)
        Ptr += NumToSkip;
      //DEBUG(dbgs() << Loc << ": OPC_CheckField(" << Start << ", "
      //             << Len << ", " << ExpectedValue << ", " << NumToSkip
      //             << "): FieldValue = " << FieldValue << ", ExpectedValue = "
      //             << ExpectedValue << ": "
      //             << ((ExpectedValue == FieldValue) ? "PASS\n" : "FAIL\n"));
      break;
    }
    case MCD_OPC_CheckPredicate: {
	  //printf("::OPC_CheckPredicate\n");
      unsigned Len;
      // Decode the Predicate Index value.
      unsigned PIdx = decodeULEB128(++Ptr, &Len);
      Ptr += Len;
      // NumToSkip is a plain 16-bit integer.
      unsigned NumToSkip = *Ptr++;
	  //printf(">>> NumToSkip 0: %u, Len: %u\n", NumToSkip, Len);
	  //printf(">>> Loc 000: %lu\n", Ptr - DecodeTable);
      NumToSkip |= (*Ptr++) << 8;
      // Check the predicate.
      bool Pred;
	  //printf(">>> NumToSkip: %u, PIdx: %u\n", NumToSkip, PIdx);
      if (!(Pred = checkDecoderPredicate(PIdx, Bits)))
        Ptr += NumToSkip;
      (void)Pred;
      //DEBUG(dbgs() << Loc << ": OPC_CheckPredicate(" << PIdx << "): "
      //      << (Pred ? "PASS\n" : "FAIL\n"));

      break;
    }
    case MCD_OPC_Decode: {
	  //printf("::OPC_Decode\n");
      unsigned Len;
      // Decode the Opcode value.
      unsigned Opc = decodeULEB128(++Ptr, &Len);
      Ptr += Len;
      unsigned DecodeIdx = decodeULEB128(Ptr, &Len);
      Ptr += Len;
      //printf("opcode: %u, decoder: %u\n", Opc, DecodeIdx);//DEBUG(dbgs() << Loc << ": OPC_Decode: opcode " << Opc
      //             << ", using decoder " << DecodeIdx << "\n" );
      //DEBUG(dbgs() << "----- DECODE SUCCESSFUL -----\n");

      MCInst_setOpcode(MI, Opc);
      return decodeToMCInst(S, DecodeIdx, insn, MI, Address, MRI);
    }
    case MCD_OPC_SoftFail: {
	  //printf("::OPC_SoftFail\n");
      // Decode the mask values.
      unsigned Len;
      uint32_t PositiveMask = decodeULEB128(++Ptr, &Len);
      Ptr += Len;
      uint32_t NegativeMask = decodeULEB128(Ptr, &Len);
      Ptr += Len;
      bool Fail = (insn & PositiveMask) || (~insn & NegativeMask);
      if (Fail)
        S = MCDisassembler_SoftFail;
      //DEBUG(dbgs() << Loc << ": OPC_SoftFail: " << (Fail ? "FAIL\n":"PASS\n"));
      break;
    }
    case MCD_OPC_Fail: {
	  //printf("::OPC_Fail\n");
      //DEBUG(dbgs() << Loc << ": OPC_Fail\n");
      return MCDisassembler_Fail;
    }
    }
  }
}

