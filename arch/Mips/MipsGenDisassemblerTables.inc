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
/* 3 */       MCD_OPC_FilterValue, 0, 139, 2, // Skip to: 658
/* 7 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10 */      MCD_OPC_FilterValue, 0, 51, 0, // Skip to: 65
/* 14 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 17 */      MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 29
/* 21 */      MCD_OPC_CheckPredicate, 1, 85, 4, // Skip to: 1134
/* 25 */      MCD_OPC_Decode, 145, 9, 10, // Opcode: SLL_MM
/* 29 */      MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 41
/* 33 */      MCD_OPC_CheckPredicate, 1, 73, 4, // Skip to: 1134
/* 37 */      MCD_OPC_Decode, 210, 9, 10, // Opcode: SRL_MM
/* 41 */      MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 53
/* 45 */      MCD_OPC_CheckPredicate, 1, 61, 4, // Skip to: 1134
/* 49 */      MCD_OPC_Decode, 190, 9, 10, // Opcode: SRA_MM
/* 53 */      MCD_OPC_FilterValue, 3, 53, 4, // Skip to: 1134
/* 57 */      MCD_OPC_CheckPredicate, 1, 49, 4, // Skip to: 1134
/* 61 */      MCD_OPC_Decode, 184, 8, 10, // Opcode: ROTR_MM
/* 65 */      MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 77
/* 69 */      MCD_OPC_CheckPredicate, 1, 37, 4, // Skip to: 1134
/* 73 */      MCD_OPC_Decode, 178, 5, 11, // Opcode: INS_MM
/* 77 */      MCD_OPC_FilterValue, 16, 180, 0, // Skip to: 261
/* 81 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 84 */      MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 96
/* 88 */      MCD_OPC_CheckPredicate, 1, 18, 4, // Skip to: 1134
/* 92 */      MCD_OPC_Decode, 141, 9, 12, // Opcode: SLLV_MM
/* 96 */      MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 108
/* 100 */     MCD_OPC_CheckPredicate, 1, 6, 4, // Skip to: 1134
/* 104 */     MCD_OPC_Decode, 206, 9, 12, // Opcode: SRLV_MM
/* 108 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 120
/* 112 */     MCD_OPC_CheckPredicate, 1, 250, 3, // Skip to: 1134
/* 116 */     MCD_OPC_Decode, 186, 9, 12, // Opcode: SRAV_MM
/* 120 */     MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 132
/* 124 */     MCD_OPC_CheckPredicate, 1, 238, 3, // Skip to: 1134
/* 128 */     MCD_OPC_Decode, 183, 8, 12, // Opcode: ROTRV_MM
/* 132 */     MCD_OPC_FilterValue, 4, 7, 0, // Skip to: 143
/* 136 */     MCD_OPC_CheckPredicate, 1, 226, 3, // Skip to: 1134
/* 140 */     MCD_OPC_Decode, 62, 13, // Opcode: ADD_MM
/* 143 */     MCD_OPC_FilterValue, 5, 7, 0, // Skip to: 154
/* 147 */     MCD_OPC_CheckPredicate, 1, 215, 3, // Skip to: 1134
/* 151 */     MCD_OPC_Decode, 68, 13, // Opcode: ADDu_MM
/* 154 */     MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 166
/* 158 */     MCD_OPC_CheckPredicate, 1, 204, 3, // Skip to: 1134
/* 162 */     MCD_OPC_Decode, 130, 10, 13, // Opcode: SUB_MM
/* 166 */     MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 178
/* 170 */     MCD_OPC_CheckPredicate, 1, 192, 3, // Skip to: 1134
/* 174 */     MCD_OPC_Decode, 132, 10, 13, // Opcode: SUBu_MM
/* 178 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 190
/* 182 */     MCD_OPC_CheckPredicate, 1, 180, 3, // Skip to: 1134
/* 186 */     MCD_OPC_Decode, 184, 7, 13, // Opcode: MUL_MM
/* 190 */     MCD_OPC_FilterValue, 9, 7, 0, // Skip to: 201
/* 194 */     MCD_OPC_CheckPredicate, 1, 168, 3, // Skip to: 1134
/* 198 */     MCD_OPC_Decode, 74, 13, // Opcode: AND_MM
/* 201 */     MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 213
/* 205 */     MCD_OPC_CheckPredicate, 1, 157, 3, // Skip to: 1134
/* 209 */     MCD_OPC_Decode, 225, 7, 13, // Opcode: OR_MM
/* 213 */     MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 225
/* 217 */     MCD_OPC_CheckPredicate, 1, 145, 3, // Skip to: 1134
/* 221 */     MCD_OPC_Decode, 215, 7, 13, // Opcode: NOR_MM
/* 225 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 237
/* 229 */     MCD_OPC_CheckPredicate, 1, 133, 3, // Skip to: 1134
/* 233 */     MCD_OPC_Decode, 240, 10, 13, // Opcode: XOR_MM
/* 237 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 249
/* 241 */     MCD_OPC_CheckPredicate, 1, 121, 3, // Skip to: 1134
/* 245 */     MCD_OPC_Decode, 149, 9, 13, // Opcode: SLT_MM
/* 249 */     MCD_OPC_FilterValue, 14, 113, 3, // Skip to: 1134
/* 253 */     MCD_OPC_CheckPredicate, 1, 109, 3, // Skip to: 1134
/* 257 */     MCD_OPC_Decode, 158, 9, 13, // Opcode: SLTu_MM
/* 261 */     MCD_OPC_FilterValue, 24, 27, 0, // Skip to: 292
/* 265 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 268 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 280
/* 272 */     MCD_OPC_CheckPredicate, 1, 90, 3, // Skip to: 1134
/* 276 */     MCD_OPC_Decode, 241, 6, 14, // Opcode: MOVN_I_MM
/* 280 */     MCD_OPC_FilterValue, 1, 82, 3, // Skip to: 1134
/* 284 */     MCD_OPC_CheckPredicate, 1, 78, 3, // Skip to: 1134
/* 288 */     MCD_OPC_Decode, 129, 7, 14, // Opcode: MOVZ_I_MM
/* 292 */     MCD_OPC_FilterValue, 44, 8, 0, // Skip to: 304
/* 296 */     MCD_OPC_CheckPredicate, 1, 66, 3, // Skip to: 1134
/* 300 */     MCD_OPC_Decode, 248, 3, 15, // Opcode: EXT_MM
/* 304 */     MCD_OPC_FilterValue, 60, 58, 3, // Skip to: 1134
/* 308 */     MCD_OPC_ExtractField, 6, 6,  // Inst{11-6} ...
/* 311 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 323
/* 315 */     MCD_OPC_CheckPredicate, 1, 47, 3, // Skip to: 1134
/* 319 */     MCD_OPC_Decode, 200, 10, 16, // Opcode: TEQ_MM
/* 323 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 335
/* 327 */     MCD_OPC_CheckPredicate, 1, 35, 3, // Skip to: 1134
/* 331 */     MCD_OPC_Decode, 208, 10, 16, // Opcode: TGE_MM
/* 335 */     MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 347
/* 339 */     MCD_OPC_CheckPredicate, 1, 23, 3, // Skip to: 1134
/* 343 */     MCD_OPC_Decode, 207, 10, 16, // Opcode: TGEU_MM
/* 347 */     MCD_OPC_FilterValue, 32, 8, 0, // Skip to: 359
/* 351 */     MCD_OPC_CheckPredicate, 1, 11, 3, // Skip to: 1134
/* 355 */     MCD_OPC_Decode, 215, 10, 16, // Opcode: TLT_MM
/* 359 */     MCD_OPC_FilterValue, 40, 8, 0, // Skip to: 371
/* 363 */     MCD_OPC_CheckPredicate, 1, 255, 2, // Skip to: 1134
/* 367 */     MCD_OPC_Decode, 214, 10, 16, // Opcode: TLTU_MM
/* 371 */     MCD_OPC_FilterValue, 44, 159, 0, // Skip to: 534
/* 375 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 378 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 390
/* 382 */     MCD_OPC_CheckPredicate, 1, 236, 2, // Skip to: 1134
/* 386 */     MCD_OPC_Decode, 219, 8, 17, // Opcode: SEB_MM
/* 390 */     MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 402
/* 394 */     MCD_OPC_CheckPredicate, 1, 224, 2, // Skip to: 1134
/* 398 */     MCD_OPC_Decode, 222, 8, 17, // Opcode: SEH_MM
/* 402 */     MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 414
/* 406 */     MCD_OPC_CheckPredicate, 1, 212, 2, // Skip to: 1134
/* 410 */     MCD_OPC_Decode, 169, 2, 17, // Opcode: CLO_MM
/* 414 */     MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 426
/* 418 */     MCD_OPC_CheckPredicate, 1, 200, 2, // Skip to: 1134
/* 422 */     MCD_OPC_Decode, 187, 2, 17, // Opcode: CLZ_MM
/* 426 */     MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 438
/* 430 */     MCD_OPC_CheckPredicate, 1, 188, 2, // Skip to: 1134
/* 434 */     MCD_OPC_Decode, 236, 10, 17, // Opcode: WSBH_MM
/* 438 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 450
/* 442 */     MCD_OPC_CheckPredicate, 1, 176, 2, // Skip to: 1134
/* 446 */     MCD_OPC_Decode, 177, 7, 18, // Opcode: MULT_MM
/* 450 */     MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 462
/* 454 */     MCD_OPC_CheckPredicate, 1, 164, 2, // Skip to: 1134
/* 458 */     MCD_OPC_Decode, 179, 7, 18, // Opcode: MULTu_MM
/* 462 */     MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 474
/* 466 */     MCD_OPC_CheckPredicate, 1, 152, 2, // Skip to: 1134
/* 470 */     MCD_OPC_Decode, 212, 8, 18, // Opcode: SDIV_MM
/* 474 */     MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 486
/* 478 */     MCD_OPC_CheckPredicate, 1, 140, 2, // Skip to: 1134
/* 482 */     MCD_OPC_Decode, 228, 10, 18, // Opcode: UDIV_MM
/* 486 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 498
/* 490 */     MCD_OPC_CheckPredicate, 1, 128, 2, // Skip to: 1134
/* 494 */     MCD_OPC_Decode, 155, 6, 18, // Opcode: MADD_MM
/* 498 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 510
/* 502 */     MCD_OPC_CheckPredicate, 1, 116, 2, // Skip to: 1134
/* 506 */     MCD_OPC_Decode, 147, 6, 18, // Opcode: MADDU_MM
/* 510 */     MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 522
/* 514 */     MCD_OPC_CheckPredicate, 1, 104, 2, // Skip to: 1134
/* 518 */     MCD_OPC_Decode, 144, 7, 18, // Opcode: MSUB_MM
/* 522 */     MCD_OPC_FilterValue, 15, 96, 2, // Skip to: 1134
/* 526 */     MCD_OPC_CheckPredicate, 1, 92, 2, // Skip to: 1134
/* 530 */     MCD_OPC_Decode, 136, 7, 18, // Opcode: MSUBU_MM
/* 534 */     MCD_OPC_FilterValue, 48, 8, 0, // Skip to: 546
/* 538 */     MCD_OPC_CheckPredicate, 1, 80, 2, // Skip to: 1134
/* 542 */     MCD_OPC_Decode, 219, 10, 16, // Opcode: TNE_MM
/* 546 */     MCD_OPC_FilterValue, 53, 75, 0, // Skip to: 625
/* 550 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 553 */     MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 571
/* 557 */     MCD_OPC_CheckPredicate, 1, 61, 2, // Skip to: 1134
/* 561 */     MCD_OPC_CheckField, 21, 5, 0, 55, 2, // Skip to: 1134
/* 567 */     MCD_OPC_Decode, 190, 6, 19, // Opcode: MFHI_MM
/* 571 */     MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 589
/* 575 */     MCD_OPC_CheckPredicate, 1, 43, 2, // Skip to: 1134
/* 579 */     MCD_OPC_CheckField, 21, 5, 0, 37, 2, // Skip to: 1134
/* 585 */     MCD_OPC_Decode, 194, 6, 19, // Opcode: MFLO_MM
/* 589 */     MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 607
/* 593 */     MCD_OPC_CheckPredicate, 1, 25, 2, // Skip to: 1134
/* 597 */     MCD_OPC_CheckField, 21, 5, 0, 19, 2, // Skip to: 1134
/* 603 */     MCD_OPC_Decode, 155, 7, 19, // Opcode: MTHI_MM
/* 607 */     MCD_OPC_FilterValue, 3, 11, 2, // Skip to: 1134
/* 611 */     MCD_OPC_CheckPredicate, 1, 7, 2, // Skip to: 1134
/* 615 */     MCD_OPC_CheckField, 21, 5, 0, 1, 2, // Skip to: 1134
/* 621 */     MCD_OPC_Decode, 160, 7, 19, // Opcode: MTLO_MM
/* 625 */     MCD_OPC_FilterValue, 60, 249, 1, // Skip to: 1134
/* 629 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 632 */     MCD_OPC_FilterValue, 0, 242, 1, // Skip to: 1134
/* 636 */     MCD_OPC_CheckPredicate, 1, 10, 0, // Skip to: 650
/* 640 */     MCD_OPC_CheckField, 21, 5, 0, 4, 0, // Skip to: 650
/* 646 */     MCD_OPC_Decode, 189, 5, 19, // Opcode: JR_MM
/* 650 */     MCD_OPC_CheckPredicate, 1, 224, 1, // Skip to: 1134
/* 654 */     MCD_OPC_Decode, 185, 5, 17, // Opcode: JALR_MM
/* 658 */     MCD_OPC_FilterValue, 4, 7, 0, // Skip to: 669
/* 662 */     MCD_OPC_CheckPredicate, 1, 212, 1, // Skip to: 1134
/* 666 */     MCD_OPC_Decode, 64, 20, // Opcode: ADDi_MM
/* 669 */     MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 681
/* 673 */     MCD_OPC_CheckPredicate, 1, 201, 1, // Skip to: 1134
/* 677 */     MCD_OPC_Decode, 203, 5, 21, // Opcode: LBu_MM
/* 681 */     MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 693
/* 685 */     MCD_OPC_CheckPredicate, 1, 189, 1, // Skip to: 1134
/* 689 */     MCD_OPC_Decode, 204, 8, 21, // Opcode: SB_MM
/* 693 */     MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 705
/* 697 */     MCD_OPC_CheckPredicate, 1, 177, 1, // Skip to: 1134
/* 701 */     MCD_OPC_Decode, 200, 5, 21, // Opcode: LB_MM
/* 705 */     MCD_OPC_FilterValue, 12, 7, 0, // Skip to: 716
/* 709 */     MCD_OPC_CheckPredicate, 1, 165, 1, // Skip to: 1134
/* 713 */     MCD_OPC_Decode, 66, 20, // Opcode: ADDiu_MM
/* 716 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 728
/* 720 */     MCD_OPC_CheckPredicate, 1, 154, 1, // Skip to: 1134
/* 724 */     MCD_OPC_Decode, 228, 5, 21, // Opcode: LHu_MM
/* 728 */     MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 740
/* 732 */     MCD_OPC_CheckPredicate, 1, 142, 1, // Skip to: 1134
/* 736 */     MCD_OPC_Decode, 252, 8, 21, // Opcode: SH_MM
/* 740 */     MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 752
/* 744 */     MCD_OPC_CheckPredicate, 1, 130, 1, // Skip to: 1134
/* 748 */     MCD_OPC_Decode, 225, 5, 21, // Opcode: LH_MM
/* 752 */     MCD_OPC_FilterValue, 16, 159, 0, // Skip to: 915
/* 756 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 759 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 771
/* 763 */     MCD_OPC_CheckPredicate, 1, 111, 1, // Skip to: 1134
/* 767 */     MCD_OPC_Decode, 196, 1, 22, // Opcode: BLTZ_MM
/* 771 */     MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 783
/* 775 */     MCD_OPC_CheckPredicate, 1, 99, 1, // Skip to: 1134
/* 779 */     MCD_OPC_Decode, 195, 1, 22, // Opcode: BLTZAL_MM
/* 783 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 795
/* 787 */     MCD_OPC_CheckPredicate, 1, 87, 1, // Skip to: 1134
/* 791 */     MCD_OPC_Decode, 168, 1, 22, // Opcode: BGEZ_MM
/* 795 */     MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 807
/* 799 */     MCD_OPC_CheckPredicate, 1, 75, 1, // Skip to: 1134
/* 803 */     MCD_OPC_Decode, 167, 1, 22, // Opcode: BGEZAL_MM
/* 807 */     MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 819
/* 811 */     MCD_OPC_CheckPredicate, 1, 63, 1, // Skip to: 1134
/* 815 */     MCD_OPC_Decode, 191, 1, 22, // Opcode: BLEZ_MM
/* 819 */     MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 831
/* 823 */     MCD_OPC_CheckPredicate, 1, 51, 1, // Skip to: 1134
/* 827 */     MCD_OPC_Decode, 171, 1, 22, // Opcode: BGTZ_MM
/* 831 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 843
/* 835 */     MCD_OPC_CheckPredicate, 1, 39, 1, // Skip to: 1134
/* 839 */     MCD_OPC_Decode, 212, 10, 23, // Opcode: TLTI_MM
/* 843 */     MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 855
/* 847 */     MCD_OPC_CheckPredicate, 1, 27, 1, // Skip to: 1134
/* 851 */     MCD_OPC_Decode, 205, 10, 23, // Opcode: TGEI_MM
/* 855 */     MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 867
/* 859 */     MCD_OPC_CheckPredicate, 1, 15, 1, // Skip to: 1134
/* 863 */     MCD_OPC_Decode, 211, 10, 23, // Opcode: TLTIU_MM
/* 867 */     MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 879
/* 871 */     MCD_OPC_CheckPredicate, 1, 3, 1, // Skip to: 1134
/* 875 */     MCD_OPC_Decode, 204, 10, 23, // Opcode: TGEIU_MM
/* 879 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 891
/* 883 */     MCD_OPC_CheckPredicate, 1, 247, 0, // Skip to: 1134
/* 887 */     MCD_OPC_Decode, 218, 10, 23, // Opcode: TNEI_MM
/* 891 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 903
/* 895 */     MCD_OPC_CheckPredicate, 1, 235, 0, // Skip to: 1134
/* 899 */     MCD_OPC_Decode, 240, 5, 23, // Opcode: LUi_MM
/* 903 */     MCD_OPC_FilterValue, 14, 227, 0, // Skip to: 1134
/* 907 */     MCD_OPC_CheckPredicate, 1, 223, 0, // Skip to: 1134
/* 911 */     MCD_OPC_Decode, 199, 10, 23, // Opcode: TEQI_MM
/* 915 */     MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 927
/* 919 */     MCD_OPC_CheckPredicate, 1, 211, 0, // Skip to: 1134
/* 923 */     MCD_OPC_Decode, 232, 7, 24, // Opcode: ORi_MM
/* 927 */     MCD_OPC_FilterValue, 21, 29, 0, // Skip to: 960
/* 931 */     MCD_OPC_ExtractField, 0, 13,  // Inst{12-0} ...
/* 934 */     MCD_OPC_FilterValue, 251, 2, 8, 0, // Skip to: 947
/* 939 */     MCD_OPC_CheckPredicate, 1, 191, 0, // Skip to: 1134
/* 943 */     MCD_OPC_Decode, 231, 6, 25, // Opcode: MOVF_I_MM
/* 947 */     MCD_OPC_FilterValue, 251, 18, 182, 0, // Skip to: 1134
/* 952 */     MCD_OPC_CheckPredicate, 1, 178, 0, // Skip to: 1134
/* 956 */     MCD_OPC_Decode, 247, 6, 25, // Opcode: MOVT_I_MM
/* 960 */     MCD_OPC_FilterValue, 24, 51, 0, // Skip to: 1015
/* 964 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 967 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 979
/* 971 */     MCD_OPC_CheckPredicate, 1, 159, 0, // Skip to: 1134
/* 975 */     MCD_OPC_Decode, 247, 5, 26, // Opcode: LWL_MM
/* 979 */     MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 991
/* 983 */     MCD_OPC_CheckPredicate, 1, 147, 0, // Skip to: 1134
/* 987 */     MCD_OPC_Decode, 250, 5, 26, // Opcode: LWR_MM
/* 991 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 1003
/* 995 */     MCD_OPC_CheckPredicate, 1, 135, 0, // Skip to: 1134
/* 999 */     MCD_OPC_Decode, 141, 10, 26, // Opcode: SWL_MM
/* 1003 */    MCD_OPC_FilterValue, 9, 127, 0, // Skip to: 1134
/* 1007 */    MCD_OPC_CheckPredicate, 1, 123, 0, // Skip to: 1134
/* 1011 */    MCD_OPC_Decode, 144, 10, 26, // Opcode: SWR_MM
/* 1015 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 1027
/* 1019 */    MCD_OPC_CheckPredicate, 1, 111, 0, // Skip to: 1134
/* 1023 */    MCD_OPC_Decode, 247, 10, 24, // Opcode: XORi_MM
/* 1027 */    MCD_OPC_FilterValue, 36, 8, 0, // Skip to: 1039
/* 1031 */    MCD_OPC_CheckPredicate, 1, 99, 0, // Skip to: 1134
/* 1035 */    MCD_OPC_Decode, 152, 9, 20, // Opcode: SLTi_MM
/* 1039 */    MCD_OPC_FilterValue, 37, 8, 0, // Skip to: 1051
/* 1043 */    MCD_OPC_CheckPredicate, 1, 87, 0, // Skip to: 1134
/* 1047 */    MCD_OPC_Decode, 163, 1, 27, // Opcode: BEQ_MM
/* 1051 */    MCD_OPC_FilterValue, 44, 8, 0, // Skip to: 1063
/* 1055 */    MCD_OPC_CheckPredicate, 1, 75, 0, // Skip to: 1134
/* 1059 */    MCD_OPC_Decode, 155, 9, 20, // Opcode: SLTiu_MM
/* 1063 */    MCD_OPC_FilterValue, 45, 8, 0, // Skip to: 1075
/* 1067 */    MCD_OPC_CheckPredicate, 1, 63, 0, // Skip to: 1134
/* 1071 */    MCD_OPC_Decode, 211, 1, 27, // Opcode: BNE_MM
/* 1075 */    MCD_OPC_FilterValue, 52, 7, 0, // Skip to: 1086
/* 1079 */    MCD_OPC_CheckPredicate, 1, 51, 0, // Skip to: 1134
/* 1083 */    MCD_OPC_Decode, 81, 24, // Opcode: ANDi_MM
/* 1086 */    MCD_OPC_FilterValue, 53, 8, 0, // Skip to: 1098
/* 1090 */    MCD_OPC_CheckPredicate, 1, 40, 0, // Skip to: 1134
/* 1094 */    MCD_OPC_Decode, 190, 5, 28, // Opcode: J_MM
/* 1098 */    MCD_OPC_FilterValue, 61, 8, 0, // Skip to: 1110
/* 1102 */    MCD_OPC_CheckPredicate, 1, 28, 0, // Skip to: 1134
/* 1106 */    MCD_OPC_Decode, 186, 5, 28, // Opcode: JAL_MM
/* 1110 */    MCD_OPC_FilterValue, 62, 8, 0, // Skip to: 1122
/* 1114 */    MCD_OPC_CheckPredicate, 1, 16, 0, // Skip to: 1134
/* 1118 */    MCD_OPC_Decode, 146, 10, 21, // Opcode: SW_MM
/* 1122 */    MCD_OPC_FilterValue, 63, 8, 0, // Skip to: 1134
/* 1126 */    MCD_OPC_CheckPredicate, 1, 4, 0, // Skip to: 1134
/* 1130 */    MCD_OPC_Decode, 253, 5, 21, // Opcode: LW_MM
/* 1134 */    MCD_OPC_Fail,
  0
};

static uint8_t DecoderTableMips32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 83, 3, // Skip to: 858
/* 7 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10 */      MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 28
/* 14 */      MCD_OPC_CheckPredicate, 2, 166, 49, // Skip to: 12728
/* 18 */      MCD_OPC_CheckField, 21, 5, 0, 160, 49, // Skip to: 12728
/* 24 */      MCD_OPC_Decode, 133, 9, 29, // Opcode: SLL
/* 28 */      MCD_OPC_FilterValue, 1, 39, 0, // Skip to: 71
/* 32 */      MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 35 */      MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 53
/* 39 */      MCD_OPC_CheckPredicate, 2, 141, 49, // Skip to: 12728
/* 43 */      MCD_OPC_CheckField, 6, 5, 0, 135, 49, // Skip to: 12728
/* 49 */      MCD_OPC_Decode, 229, 6, 30, // Opcode: MOVF_I
/* 53 */      MCD_OPC_FilterValue, 1, 127, 49, // Skip to: 12728
/* 57 */      MCD_OPC_CheckPredicate, 2, 123, 49, // Skip to: 12728
/* 61 */      MCD_OPC_CheckField, 6, 5, 0, 117, 49, // Skip to: 12728
/* 67 */      MCD_OPC_Decode, 245, 6, 30, // Opcode: MOVT_I
/* 71 */      MCD_OPC_FilterValue, 2, 27, 0, // Skip to: 102
/* 75 */      MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 78 */      MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 90
/* 82 */      MCD_OPC_CheckPredicate, 2, 98, 49, // Skip to: 12728
/* 86 */      MCD_OPC_Decode, 192, 9, 29, // Opcode: SRL
/* 90 */      MCD_OPC_FilterValue, 1, 90, 49, // Skip to: 12728
/* 94 */      MCD_OPC_CheckPredicate, 3, 86, 49, // Skip to: 12728
/* 98 */      MCD_OPC_Decode, 181, 8, 29, // Opcode: ROTR
/* 102 */     MCD_OPC_FilterValue, 3, 14, 0, // Skip to: 120
/* 106 */     MCD_OPC_CheckPredicate, 2, 74, 49, // Skip to: 12728
/* 110 */     MCD_OPC_CheckField, 21, 5, 0, 68, 49, // Skip to: 12728
/* 116 */     MCD_OPC_Decode, 172, 9, 29, // Opcode: SRA
/* 120 */     MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 138
/* 124 */     MCD_OPC_CheckPredicate, 2, 56, 49, // Skip to: 12728
/* 128 */     MCD_OPC_CheckField, 6, 5, 0, 50, 49, // Skip to: 12728
/* 134 */     MCD_OPC_Decode, 140, 9, 13, // Opcode: SLLV
/* 138 */     MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 156
/* 142 */     MCD_OPC_CheckPredicate, 4, 38, 49, // Skip to: 12728
/* 146 */     MCD_OPC_CheckField, 8, 3, 0, 32, 49, // Skip to: 12728
/* 152 */     MCD_OPC_Decode, 235, 5, 31, // Opcode: LSA
/* 156 */     MCD_OPC_FilterValue, 6, 27, 0, // Skip to: 187
/* 160 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 163 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 175
/* 167 */     MCD_OPC_CheckPredicate, 2, 13, 49, // Skip to: 12728
/* 171 */     MCD_OPC_Decode, 205, 9, 13, // Opcode: SRLV
/* 175 */     MCD_OPC_FilterValue, 1, 5, 49, // Skip to: 12728
/* 179 */     MCD_OPC_CheckPredicate, 3, 1, 49, // Skip to: 12728
/* 183 */     MCD_OPC_Decode, 182, 8, 13, // Opcode: ROTRV
/* 187 */     MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 205
/* 191 */     MCD_OPC_CheckPredicate, 2, 245, 48, // Skip to: 12728
/* 195 */     MCD_OPC_CheckField, 6, 5, 0, 239, 48, // Skip to: 12728
/* 201 */     MCD_OPC_Decode, 185, 9, 13, // Opcode: SRAV
/* 205 */     MCD_OPC_FilterValue, 8, 14, 0, // Skip to: 223
/* 209 */     MCD_OPC_CheckPredicate, 2, 227, 48, // Skip to: 12728
/* 213 */     MCD_OPC_CheckField, 6, 15, 0, 221, 48, // Skip to: 12728
/* 219 */     MCD_OPC_Decode, 187, 5, 32, // Opcode: JR
/* 223 */     MCD_OPC_FilterValue, 9, 20, 0, // Skip to: 247
/* 227 */     MCD_OPC_CheckPredicate, 2, 209, 48, // Skip to: 12728
/* 231 */     MCD_OPC_CheckField, 16, 5, 0, 203, 48, // Skip to: 12728
/* 237 */     MCD_OPC_CheckField, 6, 5, 0, 197, 48, // Skip to: 12728
/* 243 */     MCD_OPC_Decode, 181, 5, 33, // Opcode: JALR
/* 247 */     MCD_OPC_FilterValue, 10, 14, 0, // Skip to: 265
/* 251 */     MCD_OPC_CheckPredicate, 2, 185, 48, // Skip to: 12728
/* 255 */     MCD_OPC_CheckField, 6, 5, 0, 179, 48, // Skip to: 12728
/* 261 */     MCD_OPC_Decode, 255, 6, 34, // Opcode: MOVZ_I_I
/* 265 */     MCD_OPC_FilterValue, 11, 14, 0, // Skip to: 283
/* 269 */     MCD_OPC_CheckPredicate, 2, 167, 48, // Skip to: 12728
/* 273 */     MCD_OPC_CheckField, 6, 5, 0, 161, 48, // Skip to: 12728
/* 279 */     MCD_OPC_Decode, 239, 6, 34, // Opcode: MOVN_I_I
/* 283 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 295
/* 287 */     MCD_OPC_CheckPredicate, 2, 149, 48, // Skip to: 12728
/* 291 */     MCD_OPC_Decode, 148, 10, 35, // Opcode: SYSCALL
/* 295 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 307
/* 299 */     MCD_OPC_CheckPredicate, 2, 137, 48, // Skip to: 12728
/* 303 */     MCD_OPC_Decode, 219, 1, 36, // Opcode: BREAK
/* 307 */     MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 319
/* 311 */     MCD_OPC_CheckPredicate, 2, 125, 48, // Skip to: 12728
/* 315 */     MCD_OPC_Decode, 147, 10, 37, // Opcode: SYNC
/* 319 */     MCD_OPC_FilterValue, 16, 43, 0, // Skip to: 366
/* 323 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 326 */     MCD_OPC_FilterValue, 0, 110, 48, // Skip to: 12728
/* 330 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 333 */     MCD_OPC_FilterValue, 0, 103, 48, // Skip to: 12728
/* 337 */     MCD_OPC_ExtractField, 23, 3,  // Inst{25-23} ...
/* 340 */     MCD_OPC_FilterValue, 0, 96, 48, // Skip to: 12728
/* 344 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 358
/* 348 */     MCD_OPC_CheckField, 21, 2, 0, 4, 0, // Skip to: 358
/* 354 */     MCD_OPC_Decode, 187, 6, 38, // Opcode: MFHI
/* 358 */     MCD_OPC_CheckPredicate, 5, 78, 48, // Skip to: 12728
/* 362 */     MCD_OPC_Decode, 189, 6, 39, // Opcode: MFHI_DSP
/* 366 */     MCD_OPC_FilterValue, 17, 36, 0, // Skip to: 406
/* 370 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 373 */     MCD_OPC_FilterValue, 0, 63, 48, // Skip to: 12728
/* 377 */     MCD_OPC_ExtractField, 13, 8,  // Inst{20-13} ...
/* 380 */     MCD_OPC_FilterValue, 0, 56, 48, // Skip to: 12728
/* 384 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 398
/* 388 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 398
/* 394 */     MCD_OPC_Decode, 152, 7, 32, // Opcode: MTHI
/* 398 */     MCD_OPC_CheckPredicate, 5, 38, 48, // Skip to: 12728
/* 402 */     MCD_OPC_Decode, 154, 7, 40, // Opcode: MTHI_DSP
/* 406 */     MCD_OPC_FilterValue, 18, 43, 0, // Skip to: 453
/* 410 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 413 */     MCD_OPC_FilterValue, 0, 23, 48, // Skip to: 12728
/* 417 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 420 */     MCD_OPC_FilterValue, 0, 16, 48, // Skip to: 12728
/* 424 */     MCD_OPC_ExtractField, 23, 3,  // Inst{25-23} ...
/* 427 */     MCD_OPC_FilterValue, 0, 9, 48, // Skip to: 12728
/* 431 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 445
/* 435 */     MCD_OPC_CheckField, 21, 2, 0, 4, 0, // Skip to: 445
/* 441 */     MCD_OPC_Decode, 191, 6, 38, // Opcode: MFLO
/* 445 */     MCD_OPC_CheckPredicate, 5, 247, 47, // Skip to: 12728
/* 449 */     MCD_OPC_Decode, 193, 6, 39, // Opcode: MFLO_DSP
/* 453 */     MCD_OPC_FilterValue, 19, 36, 0, // Skip to: 493
/* 457 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 460 */     MCD_OPC_FilterValue, 0, 232, 47, // Skip to: 12728
/* 464 */     MCD_OPC_ExtractField, 13, 8,  // Inst{20-13} ...
/* 467 */     MCD_OPC_FilterValue, 0, 225, 47, // Skip to: 12728
/* 471 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 485
/* 475 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 485
/* 481 */     MCD_OPC_Decode, 157, 7, 32, // Opcode: MTLO
/* 485 */     MCD_OPC_CheckPredicate, 5, 207, 47, // Skip to: 12728
/* 489 */     MCD_OPC_Decode, 159, 7, 41, // Opcode: MTLO_DSP
/* 493 */     MCD_OPC_FilterValue, 24, 36, 0, // Skip to: 533
/* 497 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 500 */     MCD_OPC_FilterValue, 0, 192, 47, // Skip to: 12728
/* 504 */     MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 507 */     MCD_OPC_FilterValue, 0, 185, 47, // Skip to: 12728
/* 511 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 525
/* 515 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 525
/* 521 */     MCD_OPC_Decode, 174, 7, 17, // Opcode: MULT
/* 525 */     MCD_OPC_CheckPredicate, 5, 167, 47, // Skip to: 12728
/* 529 */     MCD_OPC_Decode, 176, 7, 42, // Opcode: MULT_DSP
/* 533 */     MCD_OPC_FilterValue, 25, 36, 0, // Skip to: 573
/* 537 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 540 */     MCD_OPC_FilterValue, 0, 152, 47, // Skip to: 12728
/* 544 */     MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 547 */     MCD_OPC_FilterValue, 0, 145, 47, // Skip to: 12728
/* 551 */     MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 565
/* 555 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 565
/* 561 */     MCD_OPC_Decode, 178, 7, 17, // Opcode: MULTu
/* 565 */     MCD_OPC_CheckPredicate, 5, 127, 47, // Skip to: 12728
/* 569 */     MCD_OPC_Decode, 175, 7, 42, // Opcode: MULTU_DSP
/* 573 */     MCD_OPC_FilterValue, 26, 14, 0, // Skip to: 591
/* 577 */     MCD_OPC_CheckPredicate, 2, 115, 47, // Skip to: 12728
/* 581 */     MCD_OPC_CheckField, 6, 10, 0, 109, 47, // Skip to: 12728
/* 587 */     MCD_OPC_Decode, 211, 8, 17, // Opcode: SDIV
/* 591 */     MCD_OPC_FilterValue, 27, 14, 0, // Skip to: 609
/* 595 */     MCD_OPC_CheckPredicate, 2, 97, 47, // Skip to: 12728
/* 599 */     MCD_OPC_CheckField, 6, 10, 0, 91, 47, // Skip to: 12728
/* 605 */     MCD_OPC_Decode, 227, 10, 17, // Opcode: UDIV
/* 609 */     MCD_OPC_FilterValue, 32, 13, 0, // Skip to: 626
/* 613 */     MCD_OPC_CheckPredicate, 2, 79, 47, // Skip to: 12728
/* 617 */     MCD_OPC_CheckField, 6, 5, 0, 73, 47, // Skip to: 12728
/* 623 */     MCD_OPC_Decode, 22, 12, // Opcode: ADD
/* 626 */     MCD_OPC_FilterValue, 33, 13, 0, // Skip to: 643
/* 630 */     MCD_OPC_CheckPredicate, 2, 62, 47, // Skip to: 12728
/* 634 */     MCD_OPC_CheckField, 6, 5, 0, 56, 47, // Skip to: 12728
/* 640 */     MCD_OPC_Decode, 67, 12, // Opcode: ADDu
/* 643 */     MCD_OPC_FilterValue, 34, 14, 0, // Skip to: 661
/* 647 */     MCD_OPC_CheckPredicate, 2, 45, 47, // Skip to: 12728
/* 651 */     MCD_OPC_CheckField, 6, 5, 0, 39, 47, // Skip to: 12728
/* 657 */     MCD_OPC_Decode, 220, 9, 12, // Opcode: SUB
/* 661 */     MCD_OPC_FilterValue, 35, 14, 0, // Skip to: 679
/* 665 */     MCD_OPC_CheckPredicate, 2, 27, 47, // Skip to: 12728
/* 669 */     MCD_OPC_CheckField, 6, 5, 0, 21, 47, // Skip to: 12728
/* 675 */     MCD_OPC_Decode, 131, 10, 12, // Opcode: SUBu
/* 679 */     MCD_OPC_FilterValue, 36, 13, 0, // Skip to: 696
/* 683 */     MCD_OPC_CheckPredicate, 2, 9, 47, // Skip to: 12728
/* 687 */     MCD_OPC_CheckField, 6, 5, 0, 3, 47, // Skip to: 12728
/* 693 */     MCD_OPC_Decode, 71, 12, // Opcode: AND
/* 696 */     MCD_OPC_FilterValue, 37, 14, 0, // Skip to: 714
/* 700 */     MCD_OPC_CheckPredicate, 2, 248, 46, // Skip to: 12728
/* 704 */     MCD_OPC_CheckField, 6, 5, 0, 242, 46, // Skip to: 12728
/* 710 */     MCD_OPC_Decode, 222, 7, 12, // Opcode: OR
/* 714 */     MCD_OPC_FilterValue, 38, 14, 0, // Skip to: 732
/* 718 */     MCD_OPC_CheckPredicate, 2, 230, 46, // Skip to: 12728
/* 722 */     MCD_OPC_CheckField, 6, 5, 0, 224, 46, // Skip to: 12728
/* 728 */     MCD_OPC_Decode, 237, 10, 12, // Opcode: XOR
/* 732 */     MCD_OPC_FilterValue, 39, 14, 0, // Skip to: 750
/* 736 */     MCD_OPC_CheckPredicate, 2, 212, 46, // Skip to: 12728
/* 740 */     MCD_OPC_CheckField, 6, 5, 0, 206, 46, // Skip to: 12728
/* 746 */     MCD_OPC_Decode, 212, 7, 12, // Opcode: NOR
/* 750 */     MCD_OPC_FilterValue, 42, 14, 0, // Skip to: 768
/* 754 */     MCD_OPC_CheckPredicate, 2, 194, 46, // Skip to: 12728
/* 758 */     MCD_OPC_CheckField, 6, 5, 0, 188, 46, // Skip to: 12728
/* 764 */     MCD_OPC_Decode, 147, 9, 12, // Opcode: SLT
/* 768 */     MCD_OPC_FilterValue, 43, 14, 0, // Skip to: 786
/* 772 */     MCD_OPC_CheckPredicate, 2, 176, 46, // Skip to: 12728
/* 776 */     MCD_OPC_CheckField, 6, 5, 0, 170, 46, // Skip to: 12728
/* 782 */     MCD_OPC_Decode, 156, 9, 12, // Opcode: SLTu
/* 786 */     MCD_OPC_FilterValue, 48, 8, 0, // Skip to: 798
/* 790 */     MCD_OPC_CheckPredicate, 2, 158, 46, // Skip to: 12728
/* 794 */     MCD_OPC_Decode, 201, 10, 43, // Opcode: TGE
/* 798 */     MCD_OPC_FilterValue, 49, 8, 0, // Skip to: 810
/* 802 */     MCD_OPC_CheckPredicate, 2, 146, 46, // Skip to: 12728
/* 806 */     MCD_OPC_Decode, 206, 10, 43, // Opcode: TGEU
/* 810 */     MCD_OPC_FilterValue, 50, 8, 0, // Skip to: 822
/* 814 */     MCD_OPC_CheckPredicate, 2, 134, 46, // Skip to: 12728
/* 818 */     MCD_OPC_Decode, 209, 10, 43, // Opcode: TLT
/* 822 */     MCD_OPC_FilterValue, 51, 8, 0, // Skip to: 834
/* 826 */     MCD_OPC_CheckPredicate, 2, 122, 46, // Skip to: 12728
/* 830 */     MCD_OPC_Decode, 213, 10, 43, // Opcode: TLTU
/* 834 */     MCD_OPC_FilterValue, 52, 8, 0, // Skip to: 846
/* 838 */     MCD_OPC_CheckPredicate, 2, 110, 46, // Skip to: 12728
/* 842 */     MCD_OPC_Decode, 197, 10, 43, // Opcode: TEQ
/* 846 */     MCD_OPC_FilterValue, 54, 102, 46, // Skip to: 12728
/* 850 */     MCD_OPC_CheckPredicate, 2, 98, 46, // Skip to: 12728
/* 854 */     MCD_OPC_Decode, 216, 10, 43, // Opcode: TNE
/* 858 */     MCD_OPC_FilterValue, 1, 141, 0, // Skip to: 1003
/* 862 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 865 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 877
/* 869 */     MCD_OPC_CheckPredicate, 2, 79, 46, // Skip to: 12728
/* 873 */     MCD_OPC_Decode, 192, 1, 44, // Opcode: BLTZ
/* 877 */     MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 889
/* 881 */     MCD_OPC_CheckPredicate, 2, 67, 46, // Skip to: 12728
/* 885 */     MCD_OPC_Decode, 164, 1, 44, // Opcode: BGEZ
/* 889 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 901
/* 893 */     MCD_OPC_CheckPredicate, 2, 55, 46, // Skip to: 12728
/* 897 */     MCD_OPC_Decode, 202, 10, 45, // Opcode: TGEI
/* 901 */     MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 913
/* 905 */     MCD_OPC_CheckPredicate, 2, 43, 46, // Skip to: 12728
/* 909 */     MCD_OPC_Decode, 203, 10, 45, // Opcode: TGEIU
/* 913 */     MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 925
/* 917 */     MCD_OPC_CheckPredicate, 2, 31, 46, // Skip to: 12728
/* 921 */     MCD_OPC_Decode, 210, 10, 45, // Opcode: TLTI
/* 925 */     MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 937
/* 929 */     MCD_OPC_CheckPredicate, 2, 19, 46, // Skip to: 12728
/* 933 */     MCD_OPC_Decode, 226, 10, 45, // Opcode: TTLTIU
/* 937 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 949
/* 941 */     MCD_OPC_CheckPredicate, 2, 7, 46, // Skip to: 12728
/* 945 */     MCD_OPC_Decode, 198, 10, 45, // Opcode: TEQI
/* 949 */     MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 961
/* 953 */     MCD_OPC_CheckPredicate, 2, 251, 45, // Skip to: 12728
/* 957 */     MCD_OPC_Decode, 217, 10, 45, // Opcode: TNEI
/* 961 */     MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 973
/* 965 */     MCD_OPC_CheckPredicate, 2, 239, 45, // Skip to: 12728
/* 969 */     MCD_OPC_Decode, 194, 1, 44, // Opcode: BLTZAL
/* 973 */     MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 985
/* 977 */     MCD_OPC_CheckPredicate, 2, 227, 45, // Skip to: 12728
/* 981 */     MCD_OPC_Decode, 166, 1, 44, // Opcode: BGEZAL
/* 985 */     MCD_OPC_FilterValue, 28, 219, 45, // Skip to: 12728
/* 989 */     MCD_OPC_CheckPredicate, 5, 215, 45, // Skip to: 12728
/* 993 */     MCD_OPC_CheckField, 21, 5, 0, 209, 45, // Skip to: 12728
/* 999 */     MCD_OPC_Decode, 217, 1, 46, // Opcode: BPOSGE32
/* 1003 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 1015
/* 1007 */    MCD_OPC_CheckPredicate, 6, 197, 45, // Skip to: 12728
/* 1011 */    MCD_OPC_Decode, 179, 5, 47, // Opcode: J
/* 1015 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 1027
/* 1019 */    MCD_OPC_CheckPredicate, 2, 185, 45, // Skip to: 12728
/* 1023 */    MCD_OPC_Decode, 180, 5, 47, // Opcode: JAL
/* 1027 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 1039
/* 1031 */    MCD_OPC_CheckPredicate, 2, 173, 45, // Skip to: 12728
/* 1035 */    MCD_OPC_Decode, 161, 1, 48, // Opcode: BEQ
/* 1039 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 1051
/* 1043 */    MCD_OPC_CheckPredicate, 2, 161, 45, // Skip to: 12728
/* 1047 */    MCD_OPC_Decode, 201, 1, 48, // Opcode: BNE
/* 1051 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 1069
/* 1055 */    MCD_OPC_CheckPredicate, 2, 149, 45, // Skip to: 12728
/* 1059 */    MCD_OPC_CheckField, 16, 5, 0, 143, 45, // Skip to: 12728
/* 1065 */    MCD_OPC_Decode, 189, 1, 44, // Opcode: BLEZ
/* 1069 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 1087
/* 1073 */    MCD_OPC_CheckPredicate, 2, 131, 45, // Skip to: 12728
/* 1077 */    MCD_OPC_CheckField, 16, 5, 0, 125, 45, // Skip to: 12728
/* 1083 */    MCD_OPC_Decode, 169, 1, 44, // Opcode: BGTZ
/* 1087 */    MCD_OPC_FilterValue, 8, 7, 0, // Skip to: 1098
/* 1091 */    MCD_OPC_CheckPredicate, 2, 113, 45, // Skip to: 12728
/* 1095 */    MCD_OPC_Decode, 63, 49, // Opcode: ADDi
/* 1098 */    MCD_OPC_FilterValue, 9, 7, 0, // Skip to: 1109
/* 1102 */    MCD_OPC_CheckPredicate, 2, 102, 45, // Skip to: 12728
/* 1106 */    MCD_OPC_Decode, 65, 49, // Opcode: ADDiu
/* 1109 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 1121
/* 1113 */    MCD_OPC_CheckPredicate, 2, 91, 45, // Skip to: 12728
/* 1117 */    MCD_OPC_Decode, 150, 9, 49, // Opcode: SLTi
/* 1121 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1133
/* 1125 */    MCD_OPC_CheckPredicate, 2, 79, 45, // Skip to: 12728
/* 1129 */    MCD_OPC_Decode, 153, 9, 49, // Opcode: SLTiu
/* 1133 */    MCD_OPC_FilterValue, 12, 7, 0, // Skip to: 1144
/* 1137 */    MCD_OPC_CheckPredicate, 2, 67, 45, // Skip to: 12728
/* 1141 */    MCD_OPC_Decode, 79, 50, // Opcode: ANDi
/* 1144 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 1156
/* 1148 */    MCD_OPC_CheckPredicate, 2, 56, 45, // Skip to: 12728
/* 1152 */    MCD_OPC_Decode, 230, 7, 50, // Opcode: ORi
/* 1156 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 1168
/* 1160 */    MCD_OPC_CheckPredicate, 2, 44, 45, // Skip to: 12728
/* 1164 */    MCD_OPC_Decode, 245, 10, 50, // Opcode: XORi
/* 1168 */    MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 1186
/* 1172 */    MCD_OPC_CheckPredicate, 2, 32, 45, // Skip to: 12728
/* 1176 */    MCD_OPC_CheckField, 21, 5, 0, 26, 45, // Skip to: 12728
/* 1182 */    MCD_OPC_Decode, 238, 5, 23, // Opcode: LUi
/* 1186 */    MCD_OPC_FilterValue, 16, 117, 0, // Skip to: 1307
/* 1190 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1193 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 1211
/* 1197 */    MCD_OPC_CheckPredicate, 2, 7, 45, // Skip to: 12728
/* 1201 */    MCD_OPC_CheckField, 3, 8, 0, 1, 45, // Skip to: 12728
/* 1207 */    MCD_OPC_Decode, 183, 6, 51, // Opcode: MFC0
/* 1211 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 1229
/* 1215 */    MCD_OPC_CheckPredicate, 2, 245, 44, // Skip to: 12728
/* 1219 */    MCD_OPC_CheckField, 3, 8, 0, 239, 44, // Skip to: 12728
/* 1225 */    MCD_OPC_Decode, 148, 7, 51, // Opcode: MTC0
/* 1229 */    MCD_OPC_FilterValue, 11, 31, 0, // Skip to: 1264
/* 1233 */    MCD_OPC_ExtractField, 0, 16,  // Inst{15-0} ...
/* 1236 */    MCD_OPC_FilterValue, 128, 192, 1, 8, 0, // Skip to: 1250
/* 1242 */    MCD_OPC_CheckPredicate, 2, 218, 44, // Skip to: 12728
/* 1246 */    MCD_OPC_Decode, 159, 3, 19, // Opcode: DI
/* 1250 */    MCD_OPC_FilterValue, 160, 192, 1, 208, 44, // Skip to: 12728
/* 1256 */    MCD_OPC_CheckPredicate, 2, 204, 44, // Skip to: 12728
/* 1260 */    MCD_OPC_Decode, 233, 3, 19, // Opcode: EI
/* 1264 */    MCD_OPC_FilterValue, 16, 196, 44, // Skip to: 12728
/* 1268 */    MCD_OPC_ExtractField, 0, 21,  // Inst{20-0} ...
/* 1271 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 1283
/* 1275 */    MCD_OPC_CheckPredicate, 2, 185, 44, // Skip to: 12728
/* 1279 */    MCD_OPC_Decode, 234, 3, 0, // Opcode: ERET
/* 1283 */    MCD_OPC_FilterValue, 31, 8, 0, // Skip to: 1295
/* 1287 */    MCD_OPC_CheckPredicate, 2, 173, 44, // Skip to: 12728
/* 1291 */    MCD_OPC_Decode, 155, 3, 0, // Opcode: DERET
/* 1295 */    MCD_OPC_FilterValue, 32, 165, 44, // Skip to: 12728
/* 1299 */    MCD_OPC_CheckPredicate, 2, 161, 44, // Skip to: 12728
/* 1303 */    MCD_OPC_Decode, 233, 10, 0, // Opcode: WAIT
/* 1307 */    MCD_OPC_FilterValue, 17, 253, 5, // Skip to: 2844
/* 1311 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1314 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 1332
/* 1318 */    MCD_OPC_CheckPredicate, 2, 142, 44, // Skip to: 12728
/* 1322 */    MCD_OPC_CheckField, 0, 11, 0, 136, 44, // Skip to: 12728
/* 1328 */    MCD_OPC_Decode, 184, 6, 52, // Opcode: MFC1
/* 1332 */    MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 1350
/* 1336 */    MCD_OPC_CheckPredicate, 2, 124, 44, // Skip to: 12728
/* 1340 */    MCD_OPC_CheckField, 0, 11, 0, 118, 44, // Skip to: 12728
/* 1346 */    MCD_OPC_Decode, 172, 3, 53, // Opcode: DMFC1
/* 1350 */    MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 1368
/* 1354 */    MCD_OPC_CheckPredicate, 2, 106, 44, // Skip to: 12728
/* 1358 */    MCD_OPC_CheckField, 0, 11, 0, 100, 44, // Skip to: 12728
/* 1364 */    MCD_OPC_Decode, 150, 2, 54, // Opcode: CFC1
/* 1368 */    MCD_OPC_FilterValue, 3, 14, 0, // Skip to: 1386
/* 1372 */    MCD_OPC_CheckPredicate, 2, 88, 44, // Skip to: 12728
/* 1376 */    MCD_OPC_CheckField, 0, 11, 0, 82, 44, // Skip to: 12728
/* 1382 */    MCD_OPC_Decode, 186, 6, 55, // Opcode: MFHC1
/* 1386 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 1404
/* 1390 */    MCD_OPC_CheckPredicate, 2, 70, 44, // Skip to: 12728
/* 1394 */    MCD_OPC_CheckField, 0, 11, 0, 64, 44, // Skip to: 12728
/* 1400 */    MCD_OPC_Decode, 149, 7, 56, // Opcode: MTC1
/* 1404 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 1422
/* 1408 */    MCD_OPC_CheckPredicate, 2, 52, 44, // Skip to: 12728
/* 1412 */    MCD_OPC_CheckField, 0, 11, 0, 46, 44, // Skip to: 12728
/* 1418 */    MCD_OPC_Decode, 175, 3, 57, // Opcode: DMTC1
/* 1422 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 1440
/* 1426 */    MCD_OPC_CheckPredicate, 2, 34, 44, // Skip to: 12728
/* 1430 */    MCD_OPC_CheckField, 0, 11, 0, 28, 44, // Skip to: 12728
/* 1436 */    MCD_OPC_Decode, 209, 2, 58, // Opcode: CTC1
/* 1440 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 1458
/* 1444 */    MCD_OPC_CheckPredicate, 2, 16, 44, // Skip to: 12728
/* 1448 */    MCD_OPC_CheckField, 0, 11, 0, 10, 44, // Skip to: 12728
/* 1454 */    MCD_OPC_Decode, 151, 7, 59, // Opcode: MTHC1
/* 1458 */    MCD_OPC_FilterValue, 8, 27, 0, // Skip to: 1489
/* 1462 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 1465 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1477
/* 1469 */    MCD_OPC_CheckPredicate, 2, 247, 43, // Skip to: 12728
/* 1473 */    MCD_OPC_Decode, 151, 1, 60, // Opcode: BC1F
/* 1477 */    MCD_OPC_FilterValue, 1, 239, 43, // Skip to: 12728
/* 1481 */    MCD_OPC_CheckPredicate, 2, 235, 43, // Skip to: 12728
/* 1485 */    MCD_OPC_Decode, 152, 1, 60, // Opcode: BC1T
/* 1489 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1501
/* 1493 */    MCD_OPC_CheckPredicate, 4, 223, 43, // Skip to: 12728
/* 1497 */    MCD_OPC_Decode, 238, 1, 61, // Opcode: BZ_V
/* 1501 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 1513
/* 1505 */    MCD_OPC_CheckPredicate, 4, 211, 43, // Skip to: 12728
/* 1509 */    MCD_OPC_Decode, 215, 1, 61, // Opcode: BNZ_V
/* 1513 */    MCD_OPC_FilterValue, 16, 80, 2, // Skip to: 2109
/* 1517 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1520 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1532
/* 1524 */    MCD_OPC_CheckPredicate, 2, 192, 43, // Skip to: 12728
/* 1528 */    MCD_OPC_Decode, 131, 4, 62, // Opcode: FADD_S
/* 1532 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 1544
/* 1536 */    MCD_OPC_CheckPredicate, 2, 180, 43, // Skip to: 12728
/* 1540 */    MCD_OPC_Decode, 244, 4, 62, // Opcode: FSUB_S
/* 1544 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 1556
/* 1548 */    MCD_OPC_CheckPredicate, 2, 168, 43, // Skip to: 12728
/* 1552 */    MCD_OPC_Decode, 213, 4, 62, // Opcode: FMUL_S
/* 1556 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 1568
/* 1560 */    MCD_OPC_CheckPredicate, 2, 156, 43, // Skip to: 12728
/* 1564 */    MCD_OPC_Decode, 163, 4, 62, // Opcode: FDIV_S
/* 1568 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 1586
/* 1572 */    MCD_OPC_CheckPredicate, 2, 144, 43, // Skip to: 12728
/* 1576 */    MCD_OPC_CheckField, 16, 5, 0, 138, 43, // Skip to: 12728
/* 1582 */    MCD_OPC_Decode, 239, 4, 63, // Opcode: FSQRT_S
/* 1586 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 1604
/* 1590 */    MCD_OPC_CheckPredicate, 6, 126, 43, // Skip to: 12728
/* 1594 */    MCD_OPC_CheckField, 16, 5, 0, 120, 43, // Skip to: 12728
/* 1600 */    MCD_OPC_Decode, 254, 3, 63, // Opcode: FABS_S
/* 1604 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 1622
/* 1608 */    MCD_OPC_CheckPredicate, 2, 108, 43, // Skip to: 12728
/* 1612 */    MCD_OPC_CheckField, 16, 5, 0, 102, 43, // Skip to: 12728
/* 1618 */    MCD_OPC_Decode, 207, 4, 63, // Opcode: FMOV_S
/* 1622 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 1640
/* 1626 */    MCD_OPC_CheckPredicate, 6, 90, 43, // Skip to: 12728
/* 1630 */    MCD_OPC_CheckField, 16, 5, 0, 84, 43, // Skip to: 12728
/* 1636 */    MCD_OPC_Decode, 217, 4, 63, // Opcode: FNEG_S
/* 1640 */    MCD_OPC_FilterValue, 12, 14, 0, // Skip to: 1658
/* 1644 */    MCD_OPC_CheckPredicate, 2, 72, 43, // Skip to: 12728
/* 1648 */    MCD_OPC_CheckField, 16, 5, 0, 66, 43, // Skip to: 12728
/* 1654 */    MCD_OPC_Decode, 189, 8, 63, // Opcode: ROUND_W_S
/* 1658 */    MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 1676
/* 1662 */    MCD_OPC_CheckPredicate, 2, 54, 43, // Skip to: 12728
/* 1666 */    MCD_OPC_CheckField, 16, 5, 0, 48, 43, // Skip to: 12728
/* 1672 */    MCD_OPC_Decode, 225, 10, 63, // Opcode: TRUNC_W_S
/* 1676 */    MCD_OPC_FilterValue, 14, 14, 0, // Skip to: 1694
/* 1680 */    MCD_OPC_CheckPredicate, 2, 36, 43, // Skip to: 12728
/* 1684 */    MCD_OPC_CheckField, 16, 5, 0, 30, 43, // Skip to: 12728
/* 1690 */    MCD_OPC_Decode, 141, 2, 63, // Opcode: CEIL_W_S
/* 1694 */    MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 1712
/* 1698 */    MCD_OPC_CheckPredicate, 2, 18, 43, // Skip to: 12728
/* 1702 */    MCD_OPC_CheckField, 16, 5, 0, 12, 43, // Skip to: 12728
/* 1708 */    MCD_OPC_Decode, 194, 4, 63, // Opcode: FLOOR_W_S
/* 1712 */    MCD_OPC_FilterValue, 17, 27, 0, // Skip to: 1743
/* 1716 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 1719 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1731
/* 1723 */    MCD_OPC_CheckPredicate, 2, 249, 42, // Skip to: 12728
/* 1727 */    MCD_OPC_Decode, 232, 6, 64, // Opcode: MOVF_S
/* 1731 */    MCD_OPC_FilterValue, 1, 241, 42, // Skip to: 12728
/* 1735 */    MCD_OPC_CheckPredicate, 2, 237, 42, // Skip to: 12728
/* 1739 */    MCD_OPC_Decode, 248, 6, 64, // Opcode: MOVT_S
/* 1743 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 1755
/* 1747 */    MCD_OPC_CheckPredicate, 2, 225, 42, // Skip to: 12728
/* 1751 */    MCD_OPC_Decode, 130, 7, 65, // Opcode: MOVZ_I_S
/* 1755 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 1767
/* 1759 */    MCD_OPC_CheckPredicate, 2, 213, 42, // Skip to: 12728
/* 1763 */    MCD_OPC_Decode, 242, 6, 65, // Opcode: MOVN_I_S
/* 1767 */    MCD_OPC_FilterValue, 33, 14, 0, // Skip to: 1785
/* 1771 */    MCD_OPC_CheckPredicate, 7, 201, 42, // Skip to: 12728
/* 1775 */    MCD_OPC_CheckField, 16, 5, 0, 195, 42, // Skip to: 12728
/* 1781 */    MCD_OPC_Decode, 211, 2, 66, // Opcode: CVT_D32_S
/* 1785 */    MCD_OPC_FilterValue, 36, 14, 0, // Skip to: 1803
/* 1789 */    MCD_OPC_CheckPredicate, 2, 183, 42, // Skip to: 12728
/* 1793 */    MCD_OPC_CheckField, 16, 5, 0, 177, 42, // Skip to: 12728
/* 1799 */    MCD_OPC_Decode, 224, 2, 63, // Opcode: CVT_W_S
/* 1803 */    MCD_OPC_FilterValue, 37, 14, 0, // Skip to: 1821
/* 1807 */    MCD_OPC_CheckPredicate, 2, 165, 42, // Skip to: 12728
/* 1811 */    MCD_OPC_CheckField, 16, 5, 0, 159, 42, // Skip to: 12728
/* 1817 */    MCD_OPC_Decode, 217, 2, 67, // Opcode: CVT_L_S
/* 1821 */    MCD_OPC_FilterValue, 48, 14, 0, // Skip to: 1839
/* 1825 */    MCD_OPC_CheckPredicate, 2, 147, 42, // Skip to: 12728
/* 1829 */    MCD_OPC_CheckField, 6, 5, 0, 141, 42, // Skip to: 12728
/* 1835 */    MCD_OPC_Decode, 230, 2, 68, // Opcode: C_F_S
/* 1839 */    MCD_OPC_FilterValue, 49, 14, 0, // Skip to: 1857
/* 1843 */    MCD_OPC_CheckPredicate, 2, 129, 42, // Skip to: 12728
/* 1847 */    MCD_OPC_CheckField, 6, 5, 0, 123, 42, // Skip to: 12728
/* 1853 */    MCD_OPC_Decode, 144, 3, 68, // Opcode: C_UN_S
/* 1857 */    MCD_OPC_FilterValue, 50, 14, 0, // Skip to: 1875
/* 1861 */    MCD_OPC_CheckPredicate, 2, 111, 42, // Skip to: 12728
/* 1865 */    MCD_OPC_CheckField, 6, 5, 0, 105, 42, // Skip to: 12728
/* 1871 */    MCD_OPC_Decode, 227, 2, 68, // Opcode: C_EQ_S
/* 1875 */    MCD_OPC_FilterValue, 51, 14, 0, // Skip to: 1893
/* 1879 */    MCD_OPC_CheckPredicate, 2, 93, 42, // Skip to: 12728
/* 1883 */    MCD_OPC_CheckField, 6, 5, 0, 87, 42, // Skip to: 12728
/* 1889 */    MCD_OPC_Decode, 135, 3, 68, // Opcode: C_UEQ_S
/* 1893 */    MCD_OPC_FilterValue, 52, 14, 0, // Skip to: 1911
/* 1897 */    MCD_OPC_CheckPredicate, 2, 75, 42, // Skip to: 12728
/* 1901 */    MCD_OPC_CheckField, 6, 5, 0, 69, 42, // Skip to: 12728
/* 1907 */    MCD_OPC_Decode, 254, 2, 68, // Opcode: C_OLT_S
/* 1911 */    MCD_OPC_FilterValue, 53, 14, 0, // Skip to: 1929
/* 1915 */    MCD_OPC_CheckPredicate, 2, 57, 42, // Skip to: 12728
/* 1919 */    MCD_OPC_CheckField, 6, 5, 0, 51, 42, // Skip to: 12728
/* 1925 */    MCD_OPC_Decode, 141, 3, 68, // Opcode: C_ULT_S
/* 1929 */    MCD_OPC_FilterValue, 54, 14, 0, // Skip to: 1947
/* 1933 */    MCD_OPC_CheckPredicate, 2, 39, 42, // Skip to: 12728
/* 1937 */    MCD_OPC_CheckField, 6, 5, 0, 33, 42, // Skip to: 12728
/* 1943 */    MCD_OPC_Decode, 251, 2, 68, // Opcode: C_OLE_S
/* 1947 */    MCD_OPC_FilterValue, 55, 14, 0, // Skip to: 1965
/* 1951 */    MCD_OPC_CheckPredicate, 2, 21, 42, // Skip to: 12728
/* 1955 */    MCD_OPC_CheckField, 6, 5, 0, 15, 42, // Skip to: 12728
/* 1961 */    MCD_OPC_Decode, 138, 3, 68, // Opcode: C_ULE_S
/* 1965 */    MCD_OPC_FilterValue, 56, 14, 0, // Skip to: 1983
/* 1969 */    MCD_OPC_CheckPredicate, 2, 3, 42, // Skip to: 12728
/* 1973 */    MCD_OPC_CheckField, 6, 5, 0, 253, 41, // Skip to: 12728
/* 1979 */    MCD_OPC_Decode, 132, 3, 68, // Opcode: C_SF_S
/* 1983 */    MCD_OPC_FilterValue, 57, 14, 0, // Skip to: 2001
/* 1987 */    MCD_OPC_CheckPredicate, 2, 241, 41, // Skip to: 12728
/* 1991 */    MCD_OPC_CheckField, 6, 5, 0, 235, 41, // Skip to: 12728
/* 1997 */    MCD_OPC_Decode, 242, 2, 68, // Opcode: C_NGLE_S
/* 2001 */    MCD_OPC_FilterValue, 58, 14, 0, // Skip to: 2019
/* 2005 */    MCD_OPC_CheckPredicate, 2, 223, 41, // Skip to: 12728
/* 2009 */    MCD_OPC_CheckField, 6, 5, 0, 217, 41, // Skip to: 12728
/* 2015 */    MCD_OPC_Decode, 129, 3, 68, // Opcode: C_SEQ_S
/* 2019 */    MCD_OPC_FilterValue, 59, 14, 0, // Skip to: 2037
/* 2023 */    MCD_OPC_CheckPredicate, 2, 205, 41, // Skip to: 12728
/* 2027 */    MCD_OPC_CheckField, 6, 5, 0, 199, 41, // Skip to: 12728
/* 2033 */    MCD_OPC_Decode, 245, 2, 68, // Opcode: C_NGL_S
/* 2037 */    MCD_OPC_FilterValue, 60, 14, 0, // Skip to: 2055
/* 2041 */    MCD_OPC_CheckPredicate, 2, 187, 41, // Skip to: 12728
/* 2045 */    MCD_OPC_CheckField, 6, 5, 0, 181, 41, // Skip to: 12728
/* 2051 */    MCD_OPC_Decode, 236, 2, 68, // Opcode: C_LT_S
/* 2055 */    MCD_OPC_FilterValue, 61, 14, 0, // Skip to: 2073
/* 2059 */    MCD_OPC_CheckPredicate, 2, 169, 41, // Skip to: 12728
/* 2063 */    MCD_OPC_CheckField, 6, 5, 0, 163, 41, // Skip to: 12728
/* 2069 */    MCD_OPC_Decode, 239, 2, 68, // Opcode: C_NGE_S
/* 2073 */    MCD_OPC_FilterValue, 62, 14, 0, // Skip to: 2091
/* 2077 */    MCD_OPC_CheckPredicate, 2, 151, 41, // Skip to: 12728
/* 2081 */    MCD_OPC_CheckField, 6, 5, 0, 145, 41, // Skip to: 12728
/* 2087 */    MCD_OPC_Decode, 233, 2, 68, // Opcode: C_LE_S
/* 2091 */    MCD_OPC_FilterValue, 63, 137, 41, // Skip to: 12728
/* 2095 */    MCD_OPC_CheckPredicate, 2, 133, 41, // Skip to: 12728
/* 2099 */    MCD_OPC_CheckField, 6, 5, 0, 127, 41, // Skip to: 12728
/* 2105 */    MCD_OPC_Decode, 248, 2, 68, // Opcode: C_NGT_S
/* 2109 */    MCD_OPC_FilterValue, 17, 80, 2, // Skip to: 2705
/* 2113 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 2116 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 2128
/* 2120 */    MCD_OPC_CheckPredicate, 7, 108, 41, // Skip to: 12728
/* 2124 */    MCD_OPC_Decode, 129, 4, 69, // Opcode: FADD_D32
/* 2128 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 2140
/* 2132 */    MCD_OPC_CheckPredicate, 7, 96, 41, // Skip to: 12728
/* 2136 */    MCD_OPC_Decode, 242, 4, 69, // Opcode: FSUB_D32
/* 2140 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 2152
/* 2144 */    MCD_OPC_CheckPredicate, 7, 84, 41, // Skip to: 12728
/* 2148 */    MCD_OPC_Decode, 211, 4, 69, // Opcode: FMUL_D32
/* 2152 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 2164
/* 2156 */    MCD_OPC_CheckPredicate, 7, 72, 41, // Skip to: 12728
/* 2160 */    MCD_OPC_Decode, 161, 4, 69, // Opcode: FDIV_D32
/* 2164 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 2182
/* 2168 */    MCD_OPC_CheckPredicate, 7, 60, 41, // Skip to: 12728
/* 2172 */    MCD_OPC_CheckField, 16, 5, 0, 54, 41, // Skip to: 12728
/* 2178 */    MCD_OPC_Decode, 237, 4, 70, // Opcode: FSQRT_D32
/* 2182 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 2200
/* 2186 */    MCD_OPC_CheckPredicate, 6, 42, 41, // Skip to: 12728
/* 2190 */    MCD_OPC_CheckField, 16, 5, 0, 36, 41, // Skip to: 12728
/* 2196 */    MCD_OPC_Decode, 252, 3, 70, // Opcode: FABS_D32
/* 2200 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 2218
/* 2204 */    MCD_OPC_CheckPredicate, 7, 24, 41, // Skip to: 12728
/* 2208 */    MCD_OPC_CheckField, 16, 5, 0, 18, 41, // Skip to: 12728
/* 2214 */    MCD_OPC_Decode, 205, 4, 70, // Opcode: FMOV_D32
/* 2218 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 2236
/* 2222 */    MCD_OPC_CheckPredicate, 6, 6, 41, // Skip to: 12728
/* 2226 */    MCD_OPC_CheckField, 16, 5, 0, 0, 41, // Skip to: 12728
/* 2232 */    MCD_OPC_Decode, 215, 4, 70, // Opcode: FNEG_D32
/* 2236 */    MCD_OPC_FilterValue, 12, 14, 0, // Skip to: 2254
/* 2240 */    MCD_OPC_CheckPredicate, 7, 244, 40, // Skip to: 12728
/* 2244 */    MCD_OPC_CheckField, 16, 5, 0, 238, 40, // Skip to: 12728
/* 2250 */    MCD_OPC_Decode, 187, 8, 71, // Opcode: ROUND_W_D32
/* 2254 */    MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 2272
/* 2258 */    MCD_OPC_CheckPredicate, 7, 226, 40, // Skip to: 12728
/* 2262 */    MCD_OPC_CheckField, 16, 5, 0, 220, 40, // Skip to: 12728
/* 2268 */    MCD_OPC_Decode, 223, 10, 71, // Opcode: TRUNC_W_D32
/* 2272 */    MCD_OPC_FilterValue, 14, 14, 0, // Skip to: 2290
/* 2276 */    MCD_OPC_CheckPredicate, 7, 208, 40, // Skip to: 12728
/* 2280 */    MCD_OPC_CheckField, 16, 5, 0, 202, 40, // Skip to: 12728
/* 2286 */    MCD_OPC_Decode, 139, 2, 71, // Opcode: CEIL_W_D32
/* 2290 */    MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 2308
/* 2294 */    MCD_OPC_CheckPredicate, 7, 190, 40, // Skip to: 12728
/* 2298 */    MCD_OPC_CheckField, 16, 5, 0, 184, 40, // Skip to: 12728
/* 2304 */    MCD_OPC_Decode, 192, 4, 71, // Opcode: FLOOR_W_D32
/* 2308 */    MCD_OPC_FilterValue, 17, 27, 0, // Skip to: 2339
/* 2312 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 2315 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 2327
/* 2319 */    MCD_OPC_CheckPredicate, 7, 165, 40, // Skip to: 12728
/* 2323 */    MCD_OPC_Decode, 227, 6, 72, // Opcode: MOVF_D32
/* 2327 */    MCD_OPC_FilterValue, 1, 157, 40, // Skip to: 12728
/* 2331 */    MCD_OPC_CheckPredicate, 7, 153, 40, // Skip to: 12728
/* 2335 */    MCD_OPC_Decode, 243, 6, 72, // Opcode: MOVT_D32
/* 2339 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 2351
/* 2343 */    MCD_OPC_CheckPredicate, 7, 141, 40, // Skip to: 12728
/* 2347 */    MCD_OPC_Decode, 253, 6, 73, // Opcode: MOVZ_I_D32
/* 2351 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 2363
/* 2355 */    MCD_OPC_CheckPredicate, 7, 129, 40, // Skip to: 12728
/* 2359 */    MCD_OPC_Decode, 237, 6, 73, // Opcode: MOVN_I_D32
/* 2363 */    MCD_OPC_FilterValue, 32, 14, 0, // Skip to: 2381
/* 2367 */    MCD_OPC_CheckPredicate, 7, 117, 40, // Skip to: 12728
/* 2371 */    MCD_OPC_CheckField, 16, 5, 0, 111, 40, // Skip to: 12728
/* 2377 */    MCD_OPC_Decode, 218, 2, 71, // Opcode: CVT_S_D32
/* 2381 */    MCD_OPC_FilterValue, 36, 14, 0, // Skip to: 2399
/* 2385 */    MCD_OPC_CheckPredicate, 7, 99, 40, // Skip to: 12728
/* 2389 */    MCD_OPC_CheckField, 16, 5, 0, 93, 40, // Skip to: 12728
/* 2395 */    MCD_OPC_Decode, 222, 2, 71, // Opcode: CVT_W_D32
/* 2399 */    MCD_OPC_FilterValue, 37, 14, 0, // Skip to: 2417
/* 2403 */    MCD_OPC_CheckPredicate, 2, 81, 40, // Skip to: 12728
/* 2407 */    MCD_OPC_CheckField, 16, 5, 0, 75, 40, // Skip to: 12728
/* 2413 */    MCD_OPC_Decode, 216, 2, 74, // Opcode: CVT_L_D64
/* 2417 */    MCD_OPC_FilterValue, 48, 14, 0, // Skip to: 2435
/* 2421 */    MCD_OPC_CheckPredicate, 7, 63, 40, // Skip to: 12728
/* 2425 */    MCD_OPC_CheckField, 6, 5, 0, 57, 40, // Skip to: 12728
/* 2431 */    MCD_OPC_Decode, 228, 2, 75, // Opcode: C_F_D32
/* 2435 */    MCD_OPC_FilterValue, 49, 14, 0, // Skip to: 2453
/* 2439 */    MCD_OPC_CheckPredicate, 7, 45, 40, // Skip to: 12728
/* 2443 */    MCD_OPC_CheckField, 6, 5, 0, 39, 40, // Skip to: 12728
/* 2449 */    MCD_OPC_Decode, 142, 3, 75, // Opcode: C_UN_D32
/* 2453 */    MCD_OPC_FilterValue, 50, 14, 0, // Skip to: 2471
/* 2457 */    MCD_OPC_CheckPredicate, 7, 27, 40, // Skip to: 12728
/* 2461 */    MCD_OPC_CheckField, 6, 5, 0, 21, 40, // Skip to: 12728
/* 2467 */    MCD_OPC_Decode, 225, 2, 75, // Opcode: C_EQ_D32
/* 2471 */    MCD_OPC_FilterValue, 51, 14, 0, // Skip to: 2489
/* 2475 */    MCD_OPC_CheckPredicate, 7, 9, 40, // Skip to: 12728
/* 2479 */    MCD_OPC_CheckField, 6, 5, 0, 3, 40, // Skip to: 12728
/* 2485 */    MCD_OPC_Decode, 133, 3, 75, // Opcode: C_UEQ_D32
/* 2489 */    MCD_OPC_FilterValue, 52, 14, 0, // Skip to: 2507
/* 2493 */    MCD_OPC_CheckPredicate, 7, 247, 39, // Skip to: 12728
/* 2497 */    MCD_OPC_CheckField, 6, 5, 0, 241, 39, // Skip to: 12728
/* 2503 */    MCD_OPC_Decode, 252, 2, 75, // Opcode: C_OLT_D32
/* 2507 */    MCD_OPC_FilterValue, 53, 14, 0, // Skip to: 2525
/* 2511 */    MCD_OPC_CheckPredicate, 7, 229, 39, // Skip to: 12728
/* 2515 */    MCD_OPC_CheckField, 6, 5, 0, 223, 39, // Skip to: 12728
/* 2521 */    MCD_OPC_Decode, 139, 3, 75, // Opcode: C_ULT_D32
/* 2525 */    MCD_OPC_FilterValue, 54, 14, 0, // Skip to: 2543
/* 2529 */    MCD_OPC_CheckPredicate, 7, 211, 39, // Skip to: 12728
/* 2533 */    MCD_OPC_CheckField, 6, 5, 0, 205, 39, // Skip to: 12728
/* 2539 */    MCD_OPC_Decode, 249, 2, 75, // Opcode: C_OLE_D32
/* 2543 */    MCD_OPC_FilterValue, 55, 14, 0, // Skip to: 2561
/* 2547 */    MCD_OPC_CheckPredicate, 7, 193, 39, // Skip to: 12728
/* 2551 */    MCD_OPC_CheckField, 6, 5, 0, 187, 39, // Skip to: 12728
/* 2557 */    MCD_OPC_Decode, 136, 3, 75, // Opcode: C_ULE_D32
/* 2561 */    MCD_OPC_FilterValue, 56, 14, 0, // Skip to: 2579
/* 2565 */    MCD_OPC_CheckPredicate, 7, 175, 39, // Skip to: 12728
/* 2569 */    MCD_OPC_CheckField, 6, 5, 0, 169, 39, // Skip to: 12728
/* 2575 */    MCD_OPC_Decode, 130, 3, 75, // Opcode: C_SF_D32
/* 2579 */    MCD_OPC_FilterValue, 57, 14, 0, // Skip to: 2597
/* 2583 */    MCD_OPC_CheckPredicate, 7, 157, 39, // Skip to: 12728
/* 2587 */    MCD_OPC_CheckField, 6, 5, 0, 151, 39, // Skip to: 12728
/* 2593 */    MCD_OPC_Decode, 240, 2, 75, // Opcode: C_NGLE_D32
/* 2597 */    MCD_OPC_FilterValue, 58, 14, 0, // Skip to: 2615
/* 2601 */    MCD_OPC_CheckPredicate, 7, 139, 39, // Skip to: 12728
/* 2605 */    MCD_OPC_CheckField, 6, 5, 0, 133, 39, // Skip to: 12728
/* 2611 */    MCD_OPC_Decode, 255, 2, 75, // Opcode: C_SEQ_D32
/* 2615 */    MCD_OPC_FilterValue, 59, 14, 0, // Skip to: 2633
/* 2619 */    MCD_OPC_CheckPredicate, 7, 121, 39, // Skip to: 12728
/* 2623 */    MCD_OPC_CheckField, 6, 5, 0, 115, 39, // Skip to: 12728
/* 2629 */    MCD_OPC_Decode, 243, 2, 75, // Opcode: C_NGL_D32
/* 2633 */    MCD_OPC_FilterValue, 60, 14, 0, // Skip to: 2651
/* 2637 */    MCD_OPC_CheckPredicate, 7, 103, 39, // Skip to: 12728
/* 2641 */    MCD_OPC_CheckField, 6, 5, 0, 97, 39, // Skip to: 12728
/* 2647 */    MCD_OPC_Decode, 234, 2, 75, // Opcode: C_LT_D32
/* 2651 */    MCD_OPC_FilterValue, 61, 14, 0, // Skip to: 2669
/* 2655 */    MCD_OPC_CheckPredicate, 7, 85, 39, // Skip to: 12728
/* 2659 */    MCD_OPC_CheckField, 6, 5, 0, 79, 39, // Skip to: 12728
/* 2665 */    MCD_OPC_Decode, 237, 2, 75, // Opcode: C_NGE_D32
/* 2669 */    MCD_OPC_FilterValue, 62, 14, 0, // Skip to: 2687
/* 2673 */    MCD_OPC_CheckPredicate, 7, 67, 39, // Skip to: 12728
/* 2677 */    MCD_OPC_CheckField, 6, 5, 0, 61, 39, // Skip to: 12728
/* 2683 */    MCD_OPC_Decode, 231, 2, 75, // Opcode: C_LE_D32
/* 2687 */    MCD_OPC_FilterValue, 63, 53, 39, // Skip to: 12728
/* 2691 */    MCD_OPC_CheckPredicate, 7, 49, 39, // Skip to: 12728
/* 2695 */    MCD_OPC_CheckField, 6, 5, 0, 43, 39, // Skip to: 12728
/* 2701 */    MCD_OPC_Decode, 246, 2, 75, // Opcode: C_NGT_D32
/* 2705 */    MCD_OPC_FilterValue, 20, 39, 0, // Skip to: 2748
/* 2709 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 2712 */    MCD_OPC_FilterValue, 32, 14, 0, // Skip to: 2730
/* 2716 */    MCD_OPC_CheckPredicate, 2, 24, 39, // Skip to: 12728
/* 2720 */    MCD_OPC_CheckField, 16, 5, 0, 18, 39, // Skip to: 12728
/* 2726 */    MCD_OPC_Decode, 221, 2, 63, // Opcode: CVT_S_W
/* 2730 */    MCD_OPC_FilterValue, 33, 10, 39, // Skip to: 12728
/* 2734 */    MCD_OPC_CheckPredicate, 7, 6, 39, // Skip to: 12728
/* 2738 */    MCD_OPC_CheckField, 16, 5, 0, 0, 39, // Skip to: 12728
/* 2744 */    MCD_OPC_Decode, 212, 2, 66, // Opcode: CVT_D32_W
/* 2748 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 2760
/* 2752 */    MCD_OPC_CheckPredicate, 4, 244, 38, // Skip to: 12728
/* 2756 */    MCD_OPC_Decode, 235, 1, 61, // Opcode: BZ_B
/* 2760 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 2772
/* 2764 */    MCD_OPC_CheckPredicate, 4, 232, 38, // Skip to: 12728
/* 2768 */    MCD_OPC_Decode, 237, 1, 76, // Opcode: BZ_H
/* 2772 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 2784
/* 2776 */    MCD_OPC_CheckPredicate, 4, 220, 38, // Skip to: 12728
/* 2780 */    MCD_OPC_Decode, 239, 1, 77, // Opcode: BZ_W
/* 2784 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 2796
/* 2788 */    MCD_OPC_CheckPredicate, 4, 208, 38, // Skip to: 12728
/* 2792 */    MCD_OPC_Decode, 236, 1, 78, // Opcode: BZ_D
/* 2796 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 2808
/* 2800 */    MCD_OPC_CheckPredicate, 4, 196, 38, // Skip to: 12728
/* 2804 */    MCD_OPC_Decode, 212, 1, 61, // Opcode: BNZ_B
/* 2808 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 2820
/* 2812 */    MCD_OPC_CheckPredicate, 4, 184, 38, // Skip to: 12728
/* 2816 */    MCD_OPC_Decode, 214, 1, 76, // Opcode: BNZ_H
/* 2820 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 2832
/* 2824 */    MCD_OPC_CheckPredicate, 4, 172, 38, // Skip to: 12728
/* 2828 */    MCD_OPC_Decode, 216, 1, 77, // Opcode: BNZ_W
/* 2832 */    MCD_OPC_FilterValue, 31, 164, 38, // Skip to: 12728
/* 2836 */    MCD_OPC_CheckPredicate, 4, 160, 38, // Skip to: 12728
/* 2840 */    MCD_OPC_Decode, 213, 1, 78, // Opcode: BNZ_D
/* 2844 */    MCD_OPC_FilterValue, 18, 39, 0, // Skip to: 2887
/* 2848 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 2851 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 2869
/* 2855 */    MCD_OPC_CheckPredicate, 2, 141, 38, // Skip to: 12728
/* 2859 */    MCD_OPC_CheckField, 3, 8, 0, 135, 38, // Skip to: 12728
/* 2865 */    MCD_OPC_Decode, 185, 6, 51, // Opcode: MFC2
/* 2869 */    MCD_OPC_FilterValue, 4, 127, 38, // Skip to: 12728
/* 2873 */    MCD_OPC_CheckPredicate, 2, 123, 38, // Skip to: 12728
/* 2877 */    MCD_OPC_CheckField, 3, 8, 0, 117, 38, // Skip to: 12728
/* 2883 */    MCD_OPC_Decode, 150, 7, 51, // Opcode: MTC2
/* 2887 */    MCD_OPC_FilterValue, 19, 207, 0, // Skip to: 3098
/* 2891 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 2894 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 2912
/* 2898 */    MCD_OPC_CheckPredicate, 8, 98, 38, // Skip to: 12728
/* 2902 */    MCD_OPC_CheckField, 11, 5, 0, 92, 38, // Skip to: 12728
/* 2908 */    MCD_OPC_Decode, 252, 5, 79, // Opcode: LWXC1
/* 2912 */    MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 2930
/* 2916 */    MCD_OPC_CheckPredicate, 9, 80, 38, // Skip to: 12728
/* 2920 */    MCD_OPC_CheckField, 11, 5, 0, 74, 38, // Skip to: 12728
/* 2926 */    MCD_OPC_Decode, 214, 5, 80, // Opcode: LDXC1
/* 2930 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 2948
/* 2934 */    MCD_OPC_CheckPredicate, 7, 62, 38, // Skip to: 12728
/* 2938 */    MCD_OPC_CheckField, 11, 5, 0, 56, 38, // Skip to: 12728
/* 2944 */    MCD_OPC_Decode, 236, 5, 80, // Opcode: LUXC1
/* 2948 */    MCD_OPC_FilterValue, 8, 14, 0, // Skip to: 2966
/* 2952 */    MCD_OPC_CheckPredicate, 8, 44, 38, // Skip to: 12728
/* 2956 */    MCD_OPC_CheckField, 6, 5, 0, 38, 38, // Skip to: 12728
/* 2962 */    MCD_OPC_Decode, 145, 10, 81, // Opcode: SWXC1
/* 2966 */    MCD_OPC_FilterValue, 9, 14, 0, // Skip to: 2984
/* 2970 */    MCD_OPC_CheckPredicate, 9, 26, 38, // Skip to: 12728
/* 2974 */    MCD_OPC_CheckField, 6, 5, 0, 20, 38, // Skip to: 12728
/* 2980 */    MCD_OPC_Decode, 215, 8, 82, // Opcode: SDXC1
/* 2984 */    MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 3002
/* 2988 */    MCD_OPC_CheckPredicate, 7, 8, 38, // Skip to: 12728
/* 2992 */    MCD_OPC_CheckField, 6, 5, 0, 2, 38, // Skip to: 12728
/* 2998 */    MCD_OPC_Decode, 133, 10, 82, // Opcode: SUXC1
/* 3002 */    MCD_OPC_FilterValue, 32, 8, 0, // Skip to: 3014
/* 3006 */    MCD_OPC_CheckPredicate, 3, 246, 37, // Skip to: 12728
/* 3010 */    MCD_OPC_Decode, 158, 6, 83, // Opcode: MADD_S
/* 3014 */    MCD_OPC_FilterValue, 33, 8, 0, // Skip to: 3026
/* 3018 */    MCD_OPC_CheckPredicate, 10, 234, 37, // Skip to: 12728
/* 3022 */    MCD_OPC_Decode, 152, 6, 84, // Opcode: MADD_D32
/* 3026 */    MCD_OPC_FilterValue, 40, 8, 0, // Skip to: 3038
/* 3030 */    MCD_OPC_CheckPredicate, 3, 222, 37, // Skip to: 12728
/* 3034 */    MCD_OPC_Decode, 147, 7, 83, // Opcode: MSUB_S
/* 3038 */    MCD_OPC_FilterValue, 41, 8, 0, // Skip to: 3050
/* 3042 */    MCD_OPC_CheckPredicate, 10, 210, 37, // Skip to: 12728
/* 3046 */    MCD_OPC_Decode, 141, 7, 84, // Opcode: MSUB_D32
/* 3050 */    MCD_OPC_FilterValue, 48, 8, 0, // Skip to: 3062
/* 3054 */    MCD_OPC_CheckPredicate, 11, 198, 37, // Skip to: 12728
/* 3058 */    MCD_OPC_Decode, 207, 7, 83, // Opcode: NMADD_S
/* 3062 */    MCD_OPC_FilterValue, 49, 8, 0, // Skip to: 3074
/* 3066 */    MCD_OPC_CheckPredicate, 12, 186, 37, // Skip to: 12728
/* 3070 */    MCD_OPC_Decode, 205, 7, 84, // Opcode: NMADD_D32
/* 3074 */    MCD_OPC_FilterValue, 56, 8, 0, // Skip to: 3086
/* 3078 */    MCD_OPC_CheckPredicate, 11, 174, 37, // Skip to: 12728
/* 3082 */    MCD_OPC_Decode, 210, 7, 83, // Opcode: NMSUB_S
/* 3086 */    MCD_OPC_FilterValue, 57, 166, 37, // Skip to: 12728
/* 3090 */    MCD_OPC_CheckPredicate, 12, 162, 37, // Skip to: 12728
/* 3094 */    MCD_OPC_Decode, 208, 7, 84, // Opcode: NMSUB_D32
/* 3098 */    MCD_OPC_FilterValue, 28, 171, 0, // Skip to: 3273
/* 3102 */    MCD_OPC_ExtractField, 0, 11,  // Inst{10-0} ...
/* 3105 */    MCD_OPC_FilterValue, 0, 29, 0, // Skip to: 3138
/* 3109 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3112 */    MCD_OPC_FilterValue, 0, 140, 37, // Skip to: 12728
/* 3116 */    MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 3130
/* 3120 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3130
/* 3126 */    MCD_OPC_Decode, 142, 6, 17, // Opcode: MADD
/* 3130 */    MCD_OPC_CheckPredicate, 5, 122, 37, // Skip to: 12728
/* 3134 */    MCD_OPC_Decode, 154, 6, 85, // Opcode: MADD_DSP
/* 3138 */    MCD_OPC_FilterValue, 1, 29, 0, // Skip to: 3171
/* 3142 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3145 */    MCD_OPC_FilterValue, 0, 107, 37, // Skip to: 12728
/* 3149 */    MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 3163
/* 3153 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3163
/* 3159 */    MCD_OPC_Decode, 145, 6, 17, // Opcode: MADDU
/* 3163 */    MCD_OPC_CheckPredicate, 5, 89, 37, // Skip to: 12728
/* 3167 */    MCD_OPC_Decode, 146, 6, 85, // Opcode: MADDU_DSP
/* 3171 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 3183
/* 3175 */    MCD_OPC_CheckPredicate, 2, 77, 37, // Skip to: 12728
/* 3179 */    MCD_OPC_Decode, 161, 7, 12, // Opcode: MUL
/* 3183 */    MCD_OPC_FilterValue, 4, 29, 0, // Skip to: 3216
/* 3187 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3190 */    MCD_OPC_FilterValue, 0, 62, 37, // Skip to: 12728
/* 3194 */    MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 3208
/* 3198 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3208
/* 3204 */    MCD_OPC_Decode, 131, 7, 17, // Opcode: MSUB
/* 3208 */    MCD_OPC_CheckPredicate, 5, 44, 37, // Skip to: 12728
/* 3212 */    MCD_OPC_Decode, 143, 7, 85, // Opcode: MSUB_DSP
/* 3216 */    MCD_OPC_FilterValue, 5, 29, 0, // Skip to: 3249
/* 3220 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3223 */    MCD_OPC_FilterValue, 0, 29, 37, // Skip to: 12728
/* 3227 */    MCD_OPC_CheckPredicate, 2, 10, 0, // Skip to: 3241
/* 3231 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3241
/* 3237 */    MCD_OPC_Decode, 134, 7, 17, // Opcode: MSUBU
/* 3241 */    MCD_OPC_CheckPredicate, 5, 11, 37, // Skip to: 12728
/* 3245 */    MCD_OPC_Decode, 135, 7, 85, // Opcode: MSUBU_DSP
/* 3249 */    MCD_OPC_FilterValue, 32, 8, 0, // Skip to: 3261
/* 3253 */    MCD_OPC_CheckPredicate, 13, 255, 36, // Skip to: 12728
/* 3257 */    MCD_OPC_Decode, 186, 2, 86, // Opcode: CLZ
/* 3261 */    MCD_OPC_FilterValue, 33, 247, 36, // Skip to: 12728
/* 3265 */    MCD_OPC_CheckPredicate, 13, 243, 36, // Skip to: 12728
/* 3269 */    MCD_OPC_Decode, 168, 2, 86, // Opcode: CLO
/* 3273 */    MCD_OPC_FilterValue, 30, 88, 26, // Skip to: 10021
/* 3277 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 3280 */    MCD_OPC_FilterValue, 0, 50, 0, // Skip to: 3334
/* 3284 */    MCD_OPC_ExtractField, 24, 2,  // Inst{25-24} ...
/* 3287 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 3298
/* 3291 */    MCD_OPC_CheckPredicate, 4, 217, 36, // Skip to: 12728
/* 3295 */    MCD_OPC_Decode, 73, 87, // Opcode: ANDI_B
/* 3298 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3310
/* 3302 */    MCD_OPC_CheckPredicate, 4, 206, 36, // Skip to: 12728
/* 3306 */    MCD_OPC_Decode, 224, 7, 87, // Opcode: ORI_B
/* 3310 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 3322
/* 3314 */    MCD_OPC_CheckPredicate, 4, 194, 36, // Skip to: 12728
/* 3318 */    MCD_OPC_Decode, 214, 7, 87, // Opcode: NORI_B
/* 3322 */    MCD_OPC_FilterValue, 3, 186, 36, // Skip to: 12728
/* 3326 */    MCD_OPC_CheckPredicate, 4, 182, 36, // Skip to: 12728
/* 3330 */    MCD_OPC_Decode, 239, 10, 87, // Opcode: XORI_B
/* 3334 */    MCD_OPC_FilterValue, 1, 39, 0, // Skip to: 3377
/* 3338 */    MCD_OPC_ExtractField, 24, 2,  // Inst{25-24} ...
/* 3341 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3353
/* 3345 */    MCD_OPC_CheckPredicate, 4, 163, 36, // Skip to: 12728
/* 3349 */    MCD_OPC_Decode, 197, 1, 88, // Opcode: BMNZI_B
/* 3353 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3365
/* 3357 */    MCD_OPC_CheckPredicate, 4, 151, 36, // Skip to: 12728
/* 3361 */    MCD_OPC_Decode, 199, 1, 88, // Opcode: BMZI_B
/* 3365 */    MCD_OPC_FilterValue, 2, 143, 36, // Skip to: 12728
/* 3369 */    MCD_OPC_CheckPredicate, 4, 139, 36, // Skip to: 12728
/* 3373 */    MCD_OPC_Decode, 220, 1, 88, // Opcode: BSELI_B
/* 3377 */    MCD_OPC_FilterValue, 2, 39, 0, // Skip to: 3420
/* 3381 */    MCD_OPC_ExtractField, 24, 2,  // Inst{25-24} ...
/* 3384 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3396
/* 3388 */    MCD_OPC_CheckPredicate, 4, 120, 36, // Skip to: 12728
/* 3392 */    MCD_OPC_Decode, 225, 8, 87, // Opcode: SHF_B
/* 3396 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3408
/* 3400 */    MCD_OPC_CheckPredicate, 4, 108, 36, // Skip to: 12728
/* 3404 */    MCD_OPC_Decode, 226, 8, 89, // Opcode: SHF_H
/* 3408 */    MCD_OPC_FilterValue, 2, 100, 36, // Skip to: 12728
/* 3412 */    MCD_OPC_CheckPredicate, 4, 96, 36, // Skip to: 12728
/* 3416 */    MCD_OPC_Decode, 227, 8, 90, // Opcode: SHF_W
/* 3420 */    MCD_OPC_FilterValue, 6, 31, 1, // Skip to: 3711
/* 3424 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 3427 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 3438
/* 3431 */    MCD_OPC_CheckPredicate, 4, 77, 36, // Skip to: 12728
/* 3435 */    MCD_OPC_Decode, 49, 91, // Opcode: ADDVI_B
/* 3438 */    MCD_OPC_FilterValue, 1, 7, 0, // Skip to: 3449
/* 3442 */    MCD_OPC_CheckPredicate, 4, 66, 36, // Skip to: 12728
/* 3446 */    MCD_OPC_Decode, 51, 92, // Opcode: ADDVI_H
/* 3449 */    MCD_OPC_FilterValue, 2, 7, 0, // Skip to: 3460
/* 3453 */    MCD_OPC_CheckPredicate, 4, 55, 36, // Skip to: 12728
/* 3457 */    MCD_OPC_Decode, 52, 93, // Opcode: ADDVI_W
/* 3460 */    MCD_OPC_FilterValue, 3, 7, 0, // Skip to: 3471
/* 3464 */    MCD_OPC_CheckPredicate, 4, 44, 36, // Skip to: 12728
/* 3468 */    MCD_OPC_Decode, 50, 94, // Opcode: ADDVI_D
/* 3471 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 3483
/* 3475 */    MCD_OPC_CheckPredicate, 4, 33, 36, // Skip to: 12728
/* 3479 */    MCD_OPC_Decode, 250, 9, 91, // Opcode: SUBVI_B
/* 3483 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 3495
/* 3487 */    MCD_OPC_CheckPredicate, 4, 21, 36, // Skip to: 12728
/* 3491 */    MCD_OPC_Decode, 252, 9, 92, // Opcode: SUBVI_H
/* 3495 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 3507
/* 3499 */    MCD_OPC_CheckPredicate, 4, 9, 36, // Skip to: 12728
/* 3503 */    MCD_OPC_Decode, 253, 9, 93, // Opcode: SUBVI_W
/* 3507 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 3519
/* 3511 */    MCD_OPC_CheckPredicate, 4, 253, 35, // Skip to: 12728
/* 3515 */    MCD_OPC_Decode, 251, 9, 94, // Opcode: SUBVI_D
/* 3519 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 3531
/* 3523 */    MCD_OPC_CheckPredicate, 4, 241, 35, // Skip to: 12728
/* 3527 */    MCD_OPC_Decode, 163, 6, 91, // Opcode: MAXI_S_B
/* 3531 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 3543
/* 3535 */    MCD_OPC_CheckPredicate, 4, 229, 35, // Skip to: 12728
/* 3539 */    MCD_OPC_Decode, 165, 6, 92, // Opcode: MAXI_S_H
/* 3543 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 3555
/* 3547 */    MCD_OPC_CheckPredicate, 4, 217, 35, // Skip to: 12728
/* 3551 */    MCD_OPC_Decode, 166, 6, 93, // Opcode: MAXI_S_W
/* 3555 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 3567
/* 3559 */    MCD_OPC_CheckPredicate, 4, 205, 35, // Skip to: 12728
/* 3563 */    MCD_OPC_Decode, 164, 6, 94, // Opcode: MAXI_S_D
/* 3567 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 3579
/* 3571 */    MCD_OPC_CheckPredicate, 4, 193, 35, // Skip to: 12728
/* 3575 */    MCD_OPC_Decode, 167, 6, 91, // Opcode: MAXI_U_B
/* 3579 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 3591
/* 3583 */    MCD_OPC_CheckPredicate, 4, 181, 35, // Skip to: 12728
/* 3587 */    MCD_OPC_Decode, 169, 6, 92, // Opcode: MAXI_U_H
/* 3591 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 3603
/* 3595 */    MCD_OPC_CheckPredicate, 4, 169, 35, // Skip to: 12728
/* 3599 */    MCD_OPC_Decode, 170, 6, 93, // Opcode: MAXI_U_W
/* 3603 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 3615
/* 3607 */    MCD_OPC_CheckPredicate, 4, 157, 35, // Skip to: 12728
/* 3611 */    MCD_OPC_Decode, 168, 6, 94, // Opcode: MAXI_U_D
/* 3615 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 3627
/* 3619 */    MCD_OPC_CheckPredicate, 4, 145, 35, // Skip to: 12728
/* 3623 */    MCD_OPC_Decode, 195, 6, 91, // Opcode: MINI_S_B
/* 3627 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 3639
/* 3631 */    MCD_OPC_CheckPredicate, 4, 133, 35, // Skip to: 12728
/* 3635 */    MCD_OPC_Decode, 197, 6, 92, // Opcode: MINI_S_H
/* 3639 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 3651
/* 3643 */    MCD_OPC_CheckPredicate, 4, 121, 35, // Skip to: 12728
/* 3647 */    MCD_OPC_Decode, 198, 6, 93, // Opcode: MINI_S_W
/* 3651 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 3663
/* 3655 */    MCD_OPC_CheckPredicate, 4, 109, 35, // Skip to: 12728
/* 3659 */    MCD_OPC_Decode, 196, 6, 94, // Opcode: MINI_S_D
/* 3663 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 3675
/* 3667 */    MCD_OPC_CheckPredicate, 4, 97, 35, // Skip to: 12728
/* 3671 */    MCD_OPC_Decode, 199, 6, 91, // Opcode: MINI_U_B
/* 3675 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 3687
/* 3679 */    MCD_OPC_CheckPredicate, 4, 85, 35, // Skip to: 12728
/* 3683 */    MCD_OPC_Decode, 201, 6, 92, // Opcode: MINI_U_H
/* 3687 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 3699
/* 3691 */    MCD_OPC_CheckPredicate, 4, 73, 35, // Skip to: 12728
/* 3695 */    MCD_OPC_Decode, 202, 6, 93, // Opcode: MINI_U_W
/* 3699 */    MCD_OPC_FilterValue, 23, 65, 35, // Skip to: 12728
/* 3703 */    MCD_OPC_CheckPredicate, 4, 61, 35, // Skip to: 12728
/* 3707 */    MCD_OPC_Decode, 200, 6, 94, // Opcode: MINI_U_D
/* 3711 */    MCD_OPC_FilterValue, 7, 35, 1, // Skip to: 4006
/* 3715 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 3718 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3730
/* 3722 */    MCD_OPC_CheckPredicate, 4, 42, 35, // Skip to: 12728
/* 3726 */    MCD_OPC_Decode, 142, 2, 91, // Opcode: CEQI_B
/* 3730 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3742
/* 3734 */    MCD_OPC_CheckPredicate, 4, 30, 35, // Skip to: 12728
/* 3738 */    MCD_OPC_Decode, 144, 2, 92, // Opcode: CEQI_H
/* 3742 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 3754
/* 3746 */    MCD_OPC_CheckPredicate, 4, 18, 35, // Skip to: 12728
/* 3750 */    MCD_OPC_Decode, 145, 2, 93, // Opcode: CEQI_W
/* 3754 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 3766
/* 3758 */    MCD_OPC_CheckPredicate, 4, 6, 35, // Skip to: 12728
/* 3762 */    MCD_OPC_Decode, 143, 2, 94, // Opcode: CEQI_D
/* 3766 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 3778
/* 3770 */    MCD_OPC_CheckPredicate, 4, 250, 34, // Skip to: 12728
/* 3774 */    MCD_OPC_Decode, 170, 2, 91, // Opcode: CLTI_S_B
/* 3778 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 3790
/* 3782 */    MCD_OPC_CheckPredicate, 4, 238, 34, // Skip to: 12728
/* 3786 */    MCD_OPC_Decode, 172, 2, 92, // Opcode: CLTI_S_H
/* 3790 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 3802
/* 3794 */    MCD_OPC_CheckPredicate, 4, 226, 34, // Skip to: 12728
/* 3798 */    MCD_OPC_Decode, 173, 2, 93, // Opcode: CLTI_S_W
/* 3802 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 3814
/* 3806 */    MCD_OPC_CheckPredicate, 4, 214, 34, // Skip to: 12728
/* 3810 */    MCD_OPC_Decode, 171, 2, 94, // Opcode: CLTI_S_D
/* 3814 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 3826
/* 3818 */    MCD_OPC_CheckPredicate, 4, 202, 34, // Skip to: 12728
/* 3822 */    MCD_OPC_Decode, 174, 2, 91, // Opcode: CLTI_U_B
/* 3826 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 3838
/* 3830 */    MCD_OPC_CheckPredicate, 4, 190, 34, // Skip to: 12728
/* 3834 */    MCD_OPC_Decode, 176, 2, 92, // Opcode: CLTI_U_H
/* 3838 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 3850
/* 3842 */    MCD_OPC_CheckPredicate, 4, 178, 34, // Skip to: 12728
/* 3846 */    MCD_OPC_Decode, 177, 2, 93, // Opcode: CLTI_U_W
/* 3850 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 3862
/* 3854 */    MCD_OPC_CheckPredicate, 4, 166, 34, // Skip to: 12728
/* 3858 */    MCD_OPC_Decode, 175, 2, 94, // Opcode: CLTI_U_D
/* 3862 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 3874
/* 3866 */    MCD_OPC_CheckPredicate, 4, 154, 34, // Skip to: 12728
/* 3870 */    MCD_OPC_Decode, 152, 2, 91, // Opcode: CLEI_S_B
/* 3874 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 3886
/* 3878 */    MCD_OPC_CheckPredicate, 4, 142, 34, // Skip to: 12728
/* 3882 */    MCD_OPC_Decode, 154, 2, 92, // Opcode: CLEI_S_H
/* 3886 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 3898
/* 3890 */    MCD_OPC_CheckPredicate, 4, 130, 34, // Skip to: 12728
/* 3894 */    MCD_OPC_Decode, 155, 2, 93, // Opcode: CLEI_S_W
/* 3898 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 3910
/* 3902 */    MCD_OPC_CheckPredicate, 4, 118, 34, // Skip to: 12728
/* 3906 */    MCD_OPC_Decode, 153, 2, 94, // Opcode: CLEI_S_D
/* 3910 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 3922
/* 3914 */    MCD_OPC_CheckPredicate, 4, 106, 34, // Skip to: 12728
/* 3918 */    MCD_OPC_Decode, 156, 2, 91, // Opcode: CLEI_U_B
/* 3922 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 3934
/* 3926 */    MCD_OPC_CheckPredicate, 4, 94, 34, // Skip to: 12728
/* 3930 */    MCD_OPC_Decode, 158, 2, 92, // Opcode: CLEI_U_H
/* 3934 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 3946
/* 3938 */    MCD_OPC_CheckPredicate, 4, 82, 34, // Skip to: 12728
/* 3942 */    MCD_OPC_Decode, 159, 2, 93, // Opcode: CLEI_U_W
/* 3946 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 3958
/* 3950 */    MCD_OPC_CheckPredicate, 4, 70, 34, // Skip to: 12728
/* 3954 */    MCD_OPC_Decode, 157, 2, 94, // Opcode: CLEI_U_D
/* 3958 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 3970
/* 3962 */    MCD_OPC_CheckPredicate, 4, 58, 34, // Skip to: 12728
/* 3966 */    MCD_OPC_Decode, 208, 5, 95, // Opcode: LDI_B
/* 3970 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 3982
/* 3974 */    MCD_OPC_CheckPredicate, 4, 46, 34, // Skip to: 12728
/* 3978 */    MCD_OPC_Decode, 210, 5, 96, // Opcode: LDI_H
/* 3982 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 3994
/* 3986 */    MCD_OPC_CheckPredicate, 4, 34, 34, // Skip to: 12728
/* 3990 */    MCD_OPC_Decode, 211, 5, 97, // Opcode: LDI_W
/* 3994 */    MCD_OPC_FilterValue, 27, 26, 34, // Skip to: 12728
/* 3998 */    MCD_OPC_CheckPredicate, 4, 22, 34, // Skip to: 12728
/* 4002 */    MCD_OPC_Decode, 209, 5, 98, // Opcode: LDI_D
/* 4006 */    MCD_OPC_FilterValue, 9, 35, 2, // Skip to: 4557
/* 4010 */    MCD_OPC_ExtractField, 22, 4,  // Inst{25-22} ...
/* 4013 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4025
/* 4017 */    MCD_OPC_CheckPredicate, 4, 3, 34, // Skip to: 12728
/* 4021 */    MCD_OPC_Decode, 137, 9, 99, // Opcode: SLLI_D
/* 4025 */    MCD_OPC_FilterValue, 1, 52, 0, // Skip to: 4081
/* 4029 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4032 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4044
/* 4036 */    MCD_OPC_CheckPredicate, 4, 240, 33, // Skip to: 12728
/* 4040 */    MCD_OPC_Decode, 139, 9, 93, // Opcode: SLLI_W
/* 4044 */    MCD_OPC_FilterValue, 1, 232, 33, // Skip to: 12728
/* 4048 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4051 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4063
/* 4055 */    MCD_OPC_CheckPredicate, 4, 221, 33, // Skip to: 12728
/* 4059 */    MCD_OPC_Decode, 138, 9, 100, // Opcode: SLLI_H
/* 4063 */    MCD_OPC_FilterValue, 1, 213, 33, // Skip to: 12728
/* 4067 */    MCD_OPC_CheckPredicate, 4, 209, 33, // Skip to: 12728
/* 4071 */    MCD_OPC_CheckField, 19, 1, 0, 203, 33, // Skip to: 12728
/* 4077 */    MCD_OPC_Decode, 136, 9, 101, // Opcode: SLLI_B
/* 4081 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 4093
/* 4085 */    MCD_OPC_CheckPredicate, 4, 191, 33, // Skip to: 12728
/* 4089 */    MCD_OPC_Decode, 174, 9, 99, // Opcode: SRAI_D
/* 4093 */    MCD_OPC_FilterValue, 3, 52, 0, // Skip to: 4149
/* 4097 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4100 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4112
/* 4104 */    MCD_OPC_CheckPredicate, 4, 172, 33, // Skip to: 12728
/* 4108 */    MCD_OPC_Decode, 176, 9, 93, // Opcode: SRAI_W
/* 4112 */    MCD_OPC_FilterValue, 1, 164, 33, // Skip to: 12728
/* 4116 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4119 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4131
/* 4123 */    MCD_OPC_CheckPredicate, 4, 153, 33, // Skip to: 12728
/* 4127 */    MCD_OPC_Decode, 175, 9, 100, // Opcode: SRAI_H
/* 4131 */    MCD_OPC_FilterValue, 1, 145, 33, // Skip to: 12728
/* 4135 */    MCD_OPC_CheckPredicate, 4, 141, 33, // Skip to: 12728
/* 4139 */    MCD_OPC_CheckField, 19, 1, 0, 135, 33, // Skip to: 12728
/* 4145 */    MCD_OPC_Decode, 173, 9, 101, // Opcode: SRAI_B
/* 4149 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 4161
/* 4153 */    MCD_OPC_CheckPredicate, 4, 123, 33, // Skip to: 12728
/* 4157 */    MCD_OPC_Decode, 194, 9, 99, // Opcode: SRLI_D
/* 4161 */    MCD_OPC_FilterValue, 5, 52, 0, // Skip to: 4217
/* 4165 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4168 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4180
/* 4172 */    MCD_OPC_CheckPredicate, 4, 104, 33, // Skip to: 12728
/* 4176 */    MCD_OPC_Decode, 196, 9, 93, // Opcode: SRLI_W
/* 4180 */    MCD_OPC_FilterValue, 1, 96, 33, // Skip to: 12728
/* 4184 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4187 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4199
/* 4191 */    MCD_OPC_CheckPredicate, 4, 85, 33, // Skip to: 12728
/* 4195 */    MCD_OPC_Decode, 195, 9, 100, // Opcode: SRLI_H
/* 4199 */    MCD_OPC_FilterValue, 1, 77, 33, // Skip to: 12728
/* 4203 */    MCD_OPC_CheckPredicate, 4, 73, 33, // Skip to: 12728
/* 4207 */    MCD_OPC_CheckField, 19, 1, 0, 67, 33, // Skip to: 12728
/* 4213 */    MCD_OPC_Decode, 193, 9, 101, // Opcode: SRLI_B
/* 4217 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 4229
/* 4221 */    MCD_OPC_CheckPredicate, 4, 55, 33, // Skip to: 12728
/* 4225 */    MCD_OPC_Decode, 154, 1, 99, // Opcode: BCLRI_D
/* 4229 */    MCD_OPC_FilterValue, 7, 52, 0, // Skip to: 4285
/* 4233 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4236 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4248
/* 4240 */    MCD_OPC_CheckPredicate, 4, 36, 33, // Skip to: 12728
/* 4244 */    MCD_OPC_Decode, 156, 1, 93, // Opcode: BCLRI_W
/* 4248 */    MCD_OPC_FilterValue, 1, 28, 33, // Skip to: 12728
/* 4252 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4255 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4267
/* 4259 */    MCD_OPC_CheckPredicate, 4, 17, 33, // Skip to: 12728
/* 4263 */    MCD_OPC_Decode, 155, 1, 100, // Opcode: BCLRI_H
/* 4267 */    MCD_OPC_FilterValue, 1, 9, 33, // Skip to: 12728
/* 4271 */    MCD_OPC_CheckPredicate, 4, 5, 33, // Skip to: 12728
/* 4275 */    MCD_OPC_CheckField, 19, 1, 0, 255, 32, // Skip to: 12728
/* 4281 */    MCD_OPC_Decode, 153, 1, 101, // Opcode: BCLRI_B
/* 4285 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 4297
/* 4289 */    MCD_OPC_CheckPredicate, 4, 243, 32, // Skip to: 12728
/* 4293 */    MCD_OPC_Decode, 228, 1, 99, // Opcode: BSETI_D
/* 4297 */    MCD_OPC_FilterValue, 9, 52, 0, // Skip to: 4353
/* 4301 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4304 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4316
/* 4308 */    MCD_OPC_CheckPredicate, 4, 224, 32, // Skip to: 12728
/* 4312 */    MCD_OPC_Decode, 230, 1, 93, // Opcode: BSETI_W
/* 4316 */    MCD_OPC_FilterValue, 1, 216, 32, // Skip to: 12728
/* 4320 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4323 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4335
/* 4327 */    MCD_OPC_CheckPredicate, 4, 205, 32, // Skip to: 12728
/* 4331 */    MCD_OPC_Decode, 229, 1, 100, // Opcode: BSETI_H
/* 4335 */    MCD_OPC_FilterValue, 1, 197, 32, // Skip to: 12728
/* 4339 */    MCD_OPC_CheckPredicate, 4, 193, 32, // Skip to: 12728
/* 4343 */    MCD_OPC_CheckField, 19, 1, 0, 187, 32, // Skip to: 12728
/* 4349 */    MCD_OPC_Decode, 227, 1, 101, // Opcode: BSETI_B
/* 4353 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 4365
/* 4357 */    MCD_OPC_CheckPredicate, 4, 175, 32, // Skip to: 12728
/* 4361 */    MCD_OPC_Decode, 204, 1, 99, // Opcode: BNEGI_D
/* 4365 */    MCD_OPC_FilterValue, 11, 52, 0, // Skip to: 4421
/* 4369 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4372 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4384
/* 4376 */    MCD_OPC_CheckPredicate, 4, 156, 32, // Skip to: 12728
/* 4380 */    MCD_OPC_Decode, 206, 1, 93, // Opcode: BNEGI_W
/* 4384 */    MCD_OPC_FilterValue, 1, 148, 32, // Skip to: 12728
/* 4388 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4391 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4403
/* 4395 */    MCD_OPC_CheckPredicate, 4, 137, 32, // Skip to: 12728
/* 4399 */    MCD_OPC_Decode, 205, 1, 100, // Opcode: BNEGI_H
/* 4403 */    MCD_OPC_FilterValue, 1, 129, 32, // Skip to: 12728
/* 4407 */    MCD_OPC_CheckPredicate, 4, 125, 32, // Skip to: 12728
/* 4411 */    MCD_OPC_CheckField, 19, 1, 0, 119, 32, // Skip to: 12728
/* 4417 */    MCD_OPC_Decode, 203, 1, 101, // Opcode: BNEGI_B
/* 4421 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 4433
/* 4425 */    MCD_OPC_CheckPredicate, 4, 107, 32, // Skip to: 12728
/* 4429 */    MCD_OPC_Decode, 173, 1, 102, // Opcode: BINSLI_D
/* 4433 */    MCD_OPC_FilterValue, 13, 52, 0, // Skip to: 4489
/* 4437 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4440 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4452
/* 4444 */    MCD_OPC_CheckPredicate, 4, 88, 32, // Skip to: 12728
/* 4448 */    MCD_OPC_Decode, 175, 1, 103, // Opcode: BINSLI_W
/* 4452 */    MCD_OPC_FilterValue, 1, 80, 32, // Skip to: 12728
/* 4456 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4459 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4471
/* 4463 */    MCD_OPC_CheckPredicate, 4, 69, 32, // Skip to: 12728
/* 4467 */    MCD_OPC_Decode, 174, 1, 104, // Opcode: BINSLI_H
/* 4471 */    MCD_OPC_FilterValue, 1, 61, 32, // Skip to: 12728
/* 4475 */    MCD_OPC_CheckPredicate, 4, 57, 32, // Skip to: 12728
/* 4479 */    MCD_OPC_CheckField, 19, 1, 0, 51, 32, // Skip to: 12728
/* 4485 */    MCD_OPC_Decode, 172, 1, 105, // Opcode: BINSLI_B
/* 4489 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 4501
/* 4493 */    MCD_OPC_CheckPredicate, 4, 39, 32, // Skip to: 12728
/* 4497 */    MCD_OPC_Decode, 181, 1, 102, // Opcode: BINSRI_D
/* 4501 */    MCD_OPC_FilterValue, 15, 31, 32, // Skip to: 12728
/* 4505 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4508 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4520
/* 4512 */    MCD_OPC_CheckPredicate, 4, 20, 32, // Skip to: 12728
/* 4516 */    MCD_OPC_Decode, 183, 1, 103, // Opcode: BINSRI_W
/* 4520 */    MCD_OPC_FilterValue, 1, 12, 32, // Skip to: 12728
/* 4524 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4527 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4539
/* 4531 */    MCD_OPC_CheckPredicate, 4, 1, 32, // Skip to: 12728
/* 4535 */    MCD_OPC_Decode, 182, 1, 104, // Opcode: BINSRI_H
/* 4539 */    MCD_OPC_FilterValue, 1, 249, 31, // Skip to: 12728
/* 4543 */    MCD_OPC_CheckPredicate, 4, 245, 31, // Skip to: 12728
/* 4547 */    MCD_OPC_CheckField, 19, 1, 0, 239, 31, // Skip to: 12728
/* 4553 */    MCD_OPC_Decode, 180, 1, 105, // Opcode: BINSRI_B
/* 4557 */    MCD_OPC_FilterValue, 10, 19, 1, // Skip to: 4836
/* 4561 */    MCD_OPC_ExtractField, 22, 4,  // Inst{25-22} ...
/* 4564 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4576
/* 4568 */    MCD_OPC_CheckPredicate, 4, 220, 31, // Skip to: 12728
/* 4572 */    MCD_OPC_Decode, 195, 8, 99, // Opcode: SAT_S_D
/* 4576 */    MCD_OPC_FilterValue, 1, 52, 0, // Skip to: 4632
/* 4580 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4583 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4595
/* 4587 */    MCD_OPC_CheckPredicate, 4, 201, 31, // Skip to: 12728
/* 4591 */    MCD_OPC_Decode, 197, 8, 93, // Opcode: SAT_S_W
/* 4595 */    MCD_OPC_FilterValue, 1, 193, 31, // Skip to: 12728
/* 4599 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4602 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4614
/* 4606 */    MCD_OPC_CheckPredicate, 4, 182, 31, // Skip to: 12728
/* 4610 */    MCD_OPC_Decode, 196, 8, 100, // Opcode: SAT_S_H
/* 4614 */    MCD_OPC_FilterValue, 1, 174, 31, // Skip to: 12728
/* 4618 */    MCD_OPC_CheckPredicate, 4, 170, 31, // Skip to: 12728
/* 4622 */    MCD_OPC_CheckField, 19, 1, 0, 164, 31, // Skip to: 12728
/* 4628 */    MCD_OPC_Decode, 194, 8, 101, // Opcode: SAT_S_B
/* 4632 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 4644
/* 4636 */    MCD_OPC_CheckPredicate, 4, 152, 31, // Skip to: 12728
/* 4640 */    MCD_OPC_Decode, 199, 8, 99, // Opcode: SAT_U_D
/* 4644 */    MCD_OPC_FilterValue, 3, 52, 0, // Skip to: 4700
/* 4648 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4651 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4663
/* 4655 */    MCD_OPC_CheckPredicate, 4, 133, 31, // Skip to: 12728
/* 4659 */    MCD_OPC_Decode, 201, 8, 93, // Opcode: SAT_U_W
/* 4663 */    MCD_OPC_FilterValue, 1, 125, 31, // Skip to: 12728
/* 4667 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4670 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4682
/* 4674 */    MCD_OPC_CheckPredicate, 4, 114, 31, // Skip to: 12728
/* 4678 */    MCD_OPC_Decode, 200, 8, 100, // Opcode: SAT_U_H
/* 4682 */    MCD_OPC_FilterValue, 1, 106, 31, // Skip to: 12728
/* 4686 */    MCD_OPC_CheckPredicate, 4, 102, 31, // Skip to: 12728
/* 4690 */    MCD_OPC_CheckField, 19, 1, 0, 96, 31, // Skip to: 12728
/* 4696 */    MCD_OPC_Decode, 198, 8, 101, // Opcode: SAT_U_B
/* 4700 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 4712
/* 4704 */    MCD_OPC_CheckPredicate, 4, 84, 31, // Skip to: 12728
/* 4708 */    MCD_OPC_Decode, 178, 9, 99, // Opcode: SRARI_D
/* 4712 */    MCD_OPC_FilterValue, 5, 52, 0, // Skip to: 4768
/* 4716 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4719 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4731
/* 4723 */    MCD_OPC_CheckPredicate, 4, 65, 31, // Skip to: 12728
/* 4727 */    MCD_OPC_Decode, 180, 9, 93, // Opcode: SRARI_W
/* 4731 */    MCD_OPC_FilterValue, 1, 57, 31, // Skip to: 12728
/* 4735 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4738 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4750
/* 4742 */    MCD_OPC_CheckPredicate, 4, 46, 31, // Skip to: 12728
/* 4746 */    MCD_OPC_Decode, 179, 9, 100, // Opcode: SRARI_H
/* 4750 */    MCD_OPC_FilterValue, 1, 38, 31, // Skip to: 12728
/* 4754 */    MCD_OPC_CheckPredicate, 4, 34, 31, // Skip to: 12728
/* 4758 */    MCD_OPC_CheckField, 19, 1, 0, 28, 31, // Skip to: 12728
/* 4764 */    MCD_OPC_Decode, 177, 9, 101, // Opcode: SRARI_B
/* 4768 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 4780
/* 4772 */    MCD_OPC_CheckPredicate, 4, 16, 31, // Skip to: 12728
/* 4776 */    MCD_OPC_Decode, 198, 9, 99, // Opcode: SRLRI_D
/* 4780 */    MCD_OPC_FilterValue, 7, 8, 31, // Skip to: 12728
/* 4784 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4787 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4799
/* 4791 */    MCD_OPC_CheckPredicate, 4, 253, 30, // Skip to: 12728
/* 4795 */    MCD_OPC_Decode, 200, 9, 93, // Opcode: SRLRI_W
/* 4799 */    MCD_OPC_FilterValue, 1, 245, 30, // Skip to: 12728
/* 4803 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4806 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4818
/* 4810 */    MCD_OPC_CheckPredicate, 4, 234, 30, // Skip to: 12728
/* 4814 */    MCD_OPC_Decode, 199, 9, 100, // Opcode: SRLRI_H
/* 4818 */    MCD_OPC_FilterValue, 1, 226, 30, // Skip to: 12728
/* 4822 */    MCD_OPC_CheckPredicate, 4, 222, 30, // Skip to: 12728
/* 4826 */    MCD_OPC_CheckField, 19, 1, 0, 216, 30, // Skip to: 12728
/* 4832 */    MCD_OPC_Decode, 197, 9, 101, // Opcode: SRLRI_B
/* 4836 */    MCD_OPC_FilterValue, 13, 131, 1, // Skip to: 5227
/* 4840 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 4843 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4855
/* 4847 */    MCD_OPC_CheckPredicate, 4, 197, 30, // Skip to: 12728
/* 4851 */    MCD_OPC_Decode, 142, 9, 106, // Opcode: SLL_B
/* 4855 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 4867
/* 4859 */    MCD_OPC_CheckPredicate, 4, 185, 30, // Skip to: 12728
/* 4863 */    MCD_OPC_Decode, 144, 9, 107, // Opcode: SLL_H
/* 4867 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 4879
/* 4871 */    MCD_OPC_CheckPredicate, 4, 173, 30, // Skip to: 12728
/* 4875 */    MCD_OPC_Decode, 146, 9, 108, // Opcode: SLL_W
/* 4879 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 4891
/* 4883 */    MCD_OPC_CheckPredicate, 4, 161, 30, // Skip to: 12728
/* 4887 */    MCD_OPC_Decode, 143, 9, 109, // Opcode: SLL_D
/* 4891 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 4903
/* 4895 */    MCD_OPC_CheckPredicate, 4, 149, 30, // Skip to: 12728
/* 4899 */    MCD_OPC_Decode, 187, 9, 106, // Opcode: SRA_B
/* 4903 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 4915
/* 4907 */    MCD_OPC_CheckPredicate, 4, 137, 30, // Skip to: 12728
/* 4911 */    MCD_OPC_Decode, 189, 9, 107, // Opcode: SRA_H
/* 4915 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 4927
/* 4919 */    MCD_OPC_CheckPredicate, 4, 125, 30, // Skip to: 12728
/* 4923 */    MCD_OPC_Decode, 191, 9, 108, // Opcode: SRA_W
/* 4927 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 4939
/* 4931 */    MCD_OPC_CheckPredicate, 4, 113, 30, // Skip to: 12728
/* 4935 */    MCD_OPC_Decode, 188, 9, 109, // Opcode: SRA_D
/* 4939 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 4951
/* 4943 */    MCD_OPC_CheckPredicate, 4, 101, 30, // Skip to: 12728
/* 4947 */    MCD_OPC_Decode, 207, 9, 106, // Opcode: SRL_B
/* 4951 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 4963
/* 4955 */    MCD_OPC_CheckPredicate, 4, 89, 30, // Skip to: 12728
/* 4959 */    MCD_OPC_Decode, 209, 9, 107, // Opcode: SRL_H
/* 4963 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 4975
/* 4967 */    MCD_OPC_CheckPredicate, 4, 77, 30, // Skip to: 12728
/* 4971 */    MCD_OPC_Decode, 211, 9, 108, // Opcode: SRL_W
/* 4975 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 4987
/* 4979 */    MCD_OPC_CheckPredicate, 4, 65, 30, // Skip to: 12728
/* 4983 */    MCD_OPC_Decode, 208, 9, 109, // Opcode: SRL_D
/* 4987 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 4999
/* 4991 */    MCD_OPC_CheckPredicate, 4, 53, 30, // Skip to: 12728
/* 4995 */    MCD_OPC_Decode, 157, 1, 106, // Opcode: BCLR_B
/* 4999 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 5011
/* 5003 */    MCD_OPC_CheckPredicate, 4, 41, 30, // Skip to: 12728
/* 5007 */    MCD_OPC_Decode, 159, 1, 107, // Opcode: BCLR_H
/* 5011 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 5023
/* 5015 */    MCD_OPC_CheckPredicate, 4, 29, 30, // Skip to: 12728
/* 5019 */    MCD_OPC_Decode, 160, 1, 108, // Opcode: BCLR_W
/* 5023 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 5035
/* 5027 */    MCD_OPC_CheckPredicate, 4, 17, 30, // Skip to: 12728
/* 5031 */    MCD_OPC_Decode, 158, 1, 109, // Opcode: BCLR_D
/* 5035 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 5047
/* 5039 */    MCD_OPC_CheckPredicate, 4, 5, 30, // Skip to: 12728
/* 5043 */    MCD_OPC_Decode, 231, 1, 106, // Opcode: BSET_B
/* 5047 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 5059
/* 5051 */    MCD_OPC_CheckPredicate, 4, 249, 29, // Skip to: 12728
/* 5055 */    MCD_OPC_Decode, 233, 1, 107, // Opcode: BSET_H
/* 5059 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 5071
/* 5063 */    MCD_OPC_CheckPredicate, 4, 237, 29, // Skip to: 12728
/* 5067 */    MCD_OPC_Decode, 234, 1, 108, // Opcode: BSET_W
/* 5071 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 5083
/* 5075 */    MCD_OPC_CheckPredicate, 4, 225, 29, // Skip to: 12728
/* 5079 */    MCD_OPC_Decode, 232, 1, 109, // Opcode: BSET_D
/* 5083 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 5095
/* 5087 */    MCD_OPC_CheckPredicate, 4, 213, 29, // Skip to: 12728
/* 5091 */    MCD_OPC_Decode, 207, 1, 106, // Opcode: BNEG_B
/* 5095 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 5107
/* 5099 */    MCD_OPC_CheckPredicate, 4, 201, 29, // Skip to: 12728
/* 5103 */    MCD_OPC_Decode, 209, 1, 107, // Opcode: BNEG_H
/* 5107 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 5119
/* 5111 */    MCD_OPC_CheckPredicate, 4, 189, 29, // Skip to: 12728
/* 5115 */    MCD_OPC_Decode, 210, 1, 108, // Opcode: BNEG_W
/* 5119 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 5131
/* 5123 */    MCD_OPC_CheckPredicate, 4, 177, 29, // Skip to: 12728
/* 5127 */    MCD_OPC_Decode, 208, 1, 109, // Opcode: BNEG_D
/* 5131 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 5143
/* 5135 */    MCD_OPC_CheckPredicate, 4, 165, 29, // Skip to: 12728
/* 5139 */    MCD_OPC_Decode, 176, 1, 110, // Opcode: BINSL_B
/* 5143 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 5155
/* 5147 */    MCD_OPC_CheckPredicate, 4, 153, 29, // Skip to: 12728
/* 5151 */    MCD_OPC_Decode, 178, 1, 111, // Opcode: BINSL_H
/* 5155 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 5167
/* 5159 */    MCD_OPC_CheckPredicate, 4, 141, 29, // Skip to: 12728
/* 5163 */    MCD_OPC_Decode, 179, 1, 112, // Opcode: BINSL_W
/* 5167 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 5179
/* 5171 */    MCD_OPC_CheckPredicate, 4, 129, 29, // Skip to: 12728
/* 5175 */    MCD_OPC_Decode, 177, 1, 113, // Opcode: BINSL_D
/* 5179 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 5191
/* 5183 */    MCD_OPC_CheckPredicate, 4, 117, 29, // Skip to: 12728
/* 5187 */    MCD_OPC_Decode, 184, 1, 110, // Opcode: BINSR_B
/* 5191 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 5203
/* 5195 */    MCD_OPC_CheckPredicate, 4, 105, 29, // Skip to: 12728
/* 5199 */    MCD_OPC_Decode, 186, 1, 111, // Opcode: BINSR_H
/* 5203 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 5215
/* 5207 */    MCD_OPC_CheckPredicate, 4, 93, 29, // Skip to: 12728
/* 5211 */    MCD_OPC_Decode, 187, 1, 112, // Opcode: BINSR_W
/* 5215 */    MCD_OPC_FilterValue, 31, 85, 29, // Skip to: 12728
/* 5219 */    MCD_OPC_CheckPredicate, 4, 81, 29, // Skip to: 12728
/* 5223 */    MCD_OPC_Decode, 185, 1, 113, // Opcode: BINSR_D
/* 5227 */    MCD_OPC_FilterValue, 14, 127, 1, // Skip to: 5614
/* 5231 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 5234 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 5245
/* 5238 */    MCD_OPC_CheckPredicate, 4, 62, 29, // Skip to: 12728
/* 5242 */    MCD_OPC_Decode, 53, 106, // Opcode: ADDV_B
/* 5245 */    MCD_OPC_FilterValue, 1, 7, 0, // Skip to: 5256
/* 5249 */    MCD_OPC_CheckPredicate, 4, 51, 29, // Skip to: 12728
/* 5253 */    MCD_OPC_Decode, 55, 107, // Opcode: ADDV_H
/* 5256 */    MCD_OPC_FilterValue, 2, 7, 0, // Skip to: 5267
/* 5260 */    MCD_OPC_CheckPredicate, 4, 40, 29, // Skip to: 12728
/* 5264 */    MCD_OPC_Decode, 56, 108, // Opcode: ADDV_W
/* 5267 */    MCD_OPC_FilterValue, 3, 7, 0, // Skip to: 5278
/* 5271 */    MCD_OPC_CheckPredicate, 4, 29, 29, // Skip to: 12728
/* 5275 */    MCD_OPC_Decode, 54, 109, // Opcode: ADDV_D
/* 5278 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 5290
/* 5282 */    MCD_OPC_CheckPredicate, 4, 18, 29, // Skip to: 12728
/* 5286 */    MCD_OPC_Decode, 254, 9, 106, // Opcode: SUBV_B
/* 5290 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 5302
/* 5294 */    MCD_OPC_CheckPredicate, 4, 6, 29, // Skip to: 12728
/* 5298 */    MCD_OPC_Decode, 128, 10, 107, // Opcode: SUBV_H
/* 5302 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 5314
/* 5306 */    MCD_OPC_CheckPredicate, 4, 250, 28, // Skip to: 12728
/* 5310 */    MCD_OPC_Decode, 129, 10, 108, // Opcode: SUBV_W
/* 5314 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 5326
/* 5318 */    MCD_OPC_CheckPredicate, 4, 238, 28, // Skip to: 12728
/* 5322 */    MCD_OPC_Decode, 255, 9, 109, // Opcode: SUBV_D
/* 5326 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 5338
/* 5330 */    MCD_OPC_CheckPredicate, 4, 226, 28, // Skip to: 12728
/* 5334 */    MCD_OPC_Decode, 175, 6, 106, // Opcode: MAX_S_B
/* 5338 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 5350
/* 5342 */    MCD_OPC_CheckPredicate, 4, 214, 28, // Skip to: 12728
/* 5346 */    MCD_OPC_Decode, 177, 6, 107, // Opcode: MAX_S_H
/* 5350 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 5362
/* 5354 */    MCD_OPC_CheckPredicate, 4, 202, 28, // Skip to: 12728
/* 5358 */    MCD_OPC_Decode, 178, 6, 108, // Opcode: MAX_S_W
/* 5362 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 5374
/* 5366 */    MCD_OPC_CheckPredicate, 4, 190, 28, // Skip to: 12728
/* 5370 */    MCD_OPC_Decode, 176, 6, 109, // Opcode: MAX_S_D
/* 5374 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 5386
/* 5378 */    MCD_OPC_CheckPredicate, 4, 178, 28, // Skip to: 12728
/* 5382 */    MCD_OPC_Decode, 179, 6, 106, // Opcode: MAX_U_B
/* 5386 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 5398
/* 5390 */    MCD_OPC_CheckPredicate, 4, 166, 28, // Skip to: 12728
/* 5394 */    MCD_OPC_Decode, 181, 6, 107, // Opcode: MAX_U_H
/* 5398 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 5410
/* 5402 */    MCD_OPC_CheckPredicate, 4, 154, 28, // Skip to: 12728
/* 5406 */    MCD_OPC_Decode, 182, 6, 108, // Opcode: MAX_U_W
/* 5410 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 5422
/* 5414 */    MCD_OPC_CheckPredicate, 4, 142, 28, // Skip to: 12728
/* 5418 */    MCD_OPC_Decode, 180, 6, 109, // Opcode: MAX_U_D
/* 5422 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 5434
/* 5426 */    MCD_OPC_CheckPredicate, 4, 130, 28, // Skip to: 12728
/* 5430 */    MCD_OPC_Decode, 207, 6, 106, // Opcode: MIN_S_B
/* 5434 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 5446
/* 5438 */    MCD_OPC_CheckPredicate, 4, 118, 28, // Skip to: 12728
/* 5442 */    MCD_OPC_Decode, 209, 6, 107, // Opcode: MIN_S_H
/* 5446 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 5458
/* 5450 */    MCD_OPC_CheckPredicate, 4, 106, 28, // Skip to: 12728
/* 5454 */    MCD_OPC_Decode, 210, 6, 108, // Opcode: MIN_S_W
/* 5458 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 5470
/* 5462 */    MCD_OPC_CheckPredicate, 4, 94, 28, // Skip to: 12728
/* 5466 */    MCD_OPC_Decode, 208, 6, 109, // Opcode: MIN_S_D
/* 5470 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 5482
/* 5474 */    MCD_OPC_CheckPredicate, 4, 82, 28, // Skip to: 12728
/* 5478 */    MCD_OPC_Decode, 211, 6, 106, // Opcode: MIN_U_B
/* 5482 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 5494
/* 5486 */    MCD_OPC_CheckPredicate, 4, 70, 28, // Skip to: 12728
/* 5490 */    MCD_OPC_Decode, 213, 6, 107, // Opcode: MIN_U_H
/* 5494 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 5506
/* 5498 */    MCD_OPC_CheckPredicate, 4, 58, 28, // Skip to: 12728
/* 5502 */    MCD_OPC_Decode, 214, 6, 108, // Opcode: MIN_U_W
/* 5506 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 5518
/* 5510 */    MCD_OPC_CheckPredicate, 4, 46, 28, // Skip to: 12728
/* 5514 */    MCD_OPC_Decode, 212, 6, 109, // Opcode: MIN_U_D
/* 5518 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 5530
/* 5522 */    MCD_OPC_CheckPredicate, 4, 34, 28, // Skip to: 12728
/* 5526 */    MCD_OPC_Decode, 171, 6, 106, // Opcode: MAX_A_B
/* 5530 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 5542
/* 5534 */    MCD_OPC_CheckPredicate, 4, 22, 28, // Skip to: 12728
/* 5538 */    MCD_OPC_Decode, 173, 6, 107, // Opcode: MAX_A_H
/* 5542 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 5554
/* 5546 */    MCD_OPC_CheckPredicate, 4, 10, 28, // Skip to: 12728
/* 5550 */    MCD_OPC_Decode, 174, 6, 108, // Opcode: MAX_A_W
/* 5554 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 5566
/* 5558 */    MCD_OPC_CheckPredicate, 4, 254, 27, // Skip to: 12728
/* 5562 */    MCD_OPC_Decode, 172, 6, 109, // Opcode: MAX_A_D
/* 5566 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 5578
/* 5570 */    MCD_OPC_CheckPredicate, 4, 242, 27, // Skip to: 12728
/* 5574 */    MCD_OPC_Decode, 203, 6, 106, // Opcode: MIN_A_B
/* 5578 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 5590
/* 5582 */    MCD_OPC_CheckPredicate, 4, 230, 27, // Skip to: 12728
/* 5586 */    MCD_OPC_Decode, 205, 6, 107, // Opcode: MIN_A_H
/* 5590 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 5602
/* 5594 */    MCD_OPC_CheckPredicate, 4, 218, 27, // Skip to: 12728
/* 5598 */    MCD_OPC_Decode, 206, 6, 108, // Opcode: MIN_A_W
/* 5602 */    MCD_OPC_FilterValue, 31, 210, 27, // Skip to: 12728
/* 5606 */    MCD_OPC_CheckPredicate, 4, 206, 27, // Skip to: 12728
/* 5610 */    MCD_OPC_Decode, 204, 6, 109, // Opcode: MIN_A_D
/* 5614 */    MCD_OPC_FilterValue, 15, 243, 0, // Skip to: 5861
/* 5618 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 5621 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5633
/* 5625 */    MCD_OPC_CheckPredicate, 4, 187, 27, // Skip to: 12728
/* 5629 */    MCD_OPC_Decode, 146, 2, 106, // Opcode: CEQ_B
/* 5633 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 5645
/* 5637 */    MCD_OPC_CheckPredicate, 4, 175, 27, // Skip to: 12728
/* 5641 */    MCD_OPC_Decode, 148, 2, 107, // Opcode: CEQ_H
/* 5645 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 5657
/* 5649 */    MCD_OPC_CheckPredicate, 4, 163, 27, // Skip to: 12728
/* 5653 */    MCD_OPC_Decode, 149, 2, 108, // Opcode: CEQ_W
/* 5657 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 5669
/* 5661 */    MCD_OPC_CheckPredicate, 4, 151, 27, // Skip to: 12728
/* 5665 */    MCD_OPC_Decode, 147, 2, 109, // Opcode: CEQ_D
/* 5669 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 5681
/* 5673 */    MCD_OPC_CheckPredicate, 4, 139, 27, // Skip to: 12728
/* 5677 */    MCD_OPC_Decode, 178, 2, 106, // Opcode: CLT_S_B
/* 5681 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 5693
/* 5685 */    MCD_OPC_CheckPredicate, 4, 127, 27, // Skip to: 12728
/* 5689 */    MCD_OPC_Decode, 180, 2, 107, // Opcode: CLT_S_H
/* 5693 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 5705
/* 5697 */    MCD_OPC_CheckPredicate, 4, 115, 27, // Skip to: 12728
/* 5701 */    MCD_OPC_Decode, 181, 2, 108, // Opcode: CLT_S_W
/* 5705 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 5717
/* 5709 */    MCD_OPC_CheckPredicate, 4, 103, 27, // Skip to: 12728
/* 5713 */    MCD_OPC_Decode, 179, 2, 109, // Opcode: CLT_S_D
/* 5717 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 5729
/* 5721 */    MCD_OPC_CheckPredicate, 4, 91, 27, // Skip to: 12728
/* 5725 */    MCD_OPC_Decode, 182, 2, 106, // Opcode: CLT_U_B
/* 5729 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 5741
/* 5733 */    MCD_OPC_CheckPredicate, 4, 79, 27, // Skip to: 12728
/* 5737 */    MCD_OPC_Decode, 184, 2, 107, // Opcode: CLT_U_H
/* 5741 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 5753
/* 5745 */    MCD_OPC_CheckPredicate, 4, 67, 27, // Skip to: 12728
/* 5749 */    MCD_OPC_Decode, 185, 2, 108, // Opcode: CLT_U_W
/* 5753 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 5765
/* 5757 */    MCD_OPC_CheckPredicate, 4, 55, 27, // Skip to: 12728
/* 5761 */    MCD_OPC_Decode, 183, 2, 109, // Opcode: CLT_U_D
/* 5765 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 5777
/* 5769 */    MCD_OPC_CheckPredicate, 4, 43, 27, // Skip to: 12728
/* 5773 */    MCD_OPC_Decode, 160, 2, 106, // Opcode: CLE_S_B
/* 5777 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 5789
/* 5781 */    MCD_OPC_CheckPredicate, 4, 31, 27, // Skip to: 12728
/* 5785 */    MCD_OPC_Decode, 162, 2, 107, // Opcode: CLE_S_H
/* 5789 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 5801
/* 5793 */    MCD_OPC_CheckPredicate, 4, 19, 27, // Skip to: 12728
/* 5797 */    MCD_OPC_Decode, 163, 2, 108, // Opcode: CLE_S_W
/* 5801 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 5813
/* 5805 */    MCD_OPC_CheckPredicate, 4, 7, 27, // Skip to: 12728
/* 5809 */    MCD_OPC_Decode, 161, 2, 109, // Opcode: CLE_S_D
/* 5813 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 5825
/* 5817 */    MCD_OPC_CheckPredicate, 4, 251, 26, // Skip to: 12728
/* 5821 */    MCD_OPC_Decode, 164, 2, 106, // Opcode: CLE_U_B
/* 5825 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 5837
/* 5829 */    MCD_OPC_CheckPredicate, 4, 239, 26, // Skip to: 12728
/* 5833 */    MCD_OPC_Decode, 166, 2, 107, // Opcode: CLE_U_H
/* 5837 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 5849
/* 5841 */    MCD_OPC_CheckPredicate, 4, 227, 26, // Skip to: 12728
/* 5845 */    MCD_OPC_Decode, 167, 2, 108, // Opcode: CLE_U_W
/* 5849 */    MCD_OPC_FilterValue, 23, 219, 26, // Skip to: 12728
/* 5853 */    MCD_OPC_CheckPredicate, 4, 215, 26, // Skip to: 12728
/* 5857 */    MCD_OPC_Decode, 165, 2, 109, // Opcode: CLE_U_D
/* 5861 */    MCD_OPC_FilterValue, 16, 110, 1, // Skip to: 6231
/* 5865 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 5868 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 5879
/* 5872 */    MCD_OPC_CheckPredicate, 4, 196, 26, // Skip to: 12728
/* 5876 */    MCD_OPC_Decode, 58, 106, // Opcode: ADD_A_B
/* 5879 */    MCD_OPC_FilterValue, 1, 7, 0, // Skip to: 5890
/* 5883 */    MCD_OPC_CheckPredicate, 4, 185, 26, // Skip to: 12728
/* 5887 */    MCD_OPC_Decode, 60, 107, // Opcode: ADD_A_H
/* 5890 */    MCD_OPC_FilterValue, 2, 7, 0, // Skip to: 5901
/* 5894 */    MCD_OPC_CheckPredicate, 4, 174, 26, // Skip to: 12728
/* 5898 */    MCD_OPC_Decode, 61, 108, // Opcode: ADD_A_W
/* 5901 */    MCD_OPC_FilterValue, 3, 7, 0, // Skip to: 5912
/* 5905 */    MCD_OPC_CheckPredicate, 4, 163, 26, // Skip to: 12728
/* 5909 */    MCD_OPC_Decode, 59, 109, // Opcode: ADD_A_D
/* 5912 */    MCD_OPC_FilterValue, 4, 7, 0, // Skip to: 5923
/* 5916 */    MCD_OPC_CheckPredicate, 4, 152, 26, // Skip to: 12728
/* 5920 */    MCD_OPC_Decode, 31, 106, // Opcode: ADDS_A_B
/* 5923 */    MCD_OPC_FilterValue, 5, 7, 0, // Skip to: 5934
/* 5927 */    MCD_OPC_CheckPredicate, 4, 141, 26, // Skip to: 12728
/* 5931 */    MCD_OPC_Decode, 33, 107, // Opcode: ADDS_A_H
/* 5934 */    MCD_OPC_FilterValue, 6, 7, 0, // Skip to: 5945
/* 5938 */    MCD_OPC_CheckPredicate, 4, 130, 26, // Skip to: 12728
/* 5942 */    MCD_OPC_Decode, 34, 108, // Opcode: ADDS_A_W
/* 5945 */    MCD_OPC_FilterValue, 7, 7, 0, // Skip to: 5956
/* 5949 */    MCD_OPC_CheckPredicate, 4, 119, 26, // Skip to: 12728
/* 5953 */    MCD_OPC_Decode, 32, 109, // Opcode: ADDS_A_D
/* 5956 */    MCD_OPC_FilterValue, 8, 7, 0, // Skip to: 5967
/* 5960 */    MCD_OPC_CheckPredicate, 4, 108, 26, // Skip to: 12728
/* 5964 */    MCD_OPC_Decode, 35, 106, // Opcode: ADDS_S_B
/* 5967 */    MCD_OPC_FilterValue, 9, 7, 0, // Skip to: 5978
/* 5971 */    MCD_OPC_CheckPredicate, 4, 97, 26, // Skip to: 12728
/* 5975 */    MCD_OPC_Decode, 37, 107, // Opcode: ADDS_S_H
/* 5978 */    MCD_OPC_FilterValue, 10, 7, 0, // Skip to: 5989
/* 5982 */    MCD_OPC_CheckPredicate, 4, 86, 26, // Skip to: 12728
/* 5986 */    MCD_OPC_Decode, 38, 108, // Opcode: ADDS_S_W
/* 5989 */    MCD_OPC_FilterValue, 11, 7, 0, // Skip to: 6000
/* 5993 */    MCD_OPC_CheckPredicate, 4, 75, 26, // Skip to: 12728
/* 5997 */    MCD_OPC_Decode, 36, 109, // Opcode: ADDS_S_D
/* 6000 */    MCD_OPC_FilterValue, 12, 7, 0, // Skip to: 6011
/* 6004 */    MCD_OPC_CheckPredicate, 4, 64, 26, // Skip to: 12728
/* 6008 */    MCD_OPC_Decode, 39, 106, // Opcode: ADDS_U_B
/* 6011 */    MCD_OPC_FilterValue, 13, 7, 0, // Skip to: 6022
/* 6015 */    MCD_OPC_CheckPredicate, 4, 53, 26, // Skip to: 12728
/* 6019 */    MCD_OPC_Decode, 41, 107, // Opcode: ADDS_U_H
/* 6022 */    MCD_OPC_FilterValue, 14, 7, 0, // Skip to: 6033
/* 6026 */    MCD_OPC_CheckPredicate, 4, 42, 26, // Skip to: 12728
/* 6030 */    MCD_OPC_Decode, 42, 108, // Opcode: ADDS_U_W
/* 6033 */    MCD_OPC_FilterValue, 15, 7, 0, // Skip to: 6044
/* 6037 */    MCD_OPC_CheckPredicate, 4, 31, 26, // Skip to: 12728
/* 6041 */    MCD_OPC_Decode, 40, 109, // Opcode: ADDS_U_D
/* 6044 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 6056
/* 6048 */    MCD_OPC_CheckPredicate, 4, 20, 26, // Skip to: 12728
/* 6052 */    MCD_OPC_Decode, 131, 1, 106, // Opcode: AVE_S_B
/* 6056 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 6068
/* 6060 */    MCD_OPC_CheckPredicate, 4, 8, 26, // Skip to: 12728
/* 6064 */    MCD_OPC_Decode, 133, 1, 107, // Opcode: AVE_S_H
/* 6068 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 6080
/* 6072 */    MCD_OPC_CheckPredicate, 4, 252, 25, // Skip to: 12728
/* 6076 */    MCD_OPC_Decode, 134, 1, 108, // Opcode: AVE_S_W
/* 6080 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 6092
/* 6084 */    MCD_OPC_CheckPredicate, 4, 240, 25, // Skip to: 12728
/* 6088 */    MCD_OPC_Decode, 132, 1, 109, // Opcode: AVE_S_D
/* 6092 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 6104
/* 6096 */    MCD_OPC_CheckPredicate, 4, 228, 25, // Skip to: 12728
/* 6100 */    MCD_OPC_Decode, 135, 1, 106, // Opcode: AVE_U_B
/* 6104 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 6116
/* 6108 */    MCD_OPC_CheckPredicate, 4, 216, 25, // Skip to: 12728
/* 6112 */    MCD_OPC_Decode, 137, 1, 107, // Opcode: AVE_U_H
/* 6116 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 6128
/* 6120 */    MCD_OPC_CheckPredicate, 4, 204, 25, // Skip to: 12728
/* 6124 */    MCD_OPC_Decode, 138, 1, 108, // Opcode: AVE_U_W
/* 6128 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 6140
/* 6132 */    MCD_OPC_CheckPredicate, 4, 192, 25, // Skip to: 12728
/* 6136 */    MCD_OPC_Decode, 136, 1, 109, // Opcode: AVE_U_D
/* 6140 */    MCD_OPC_FilterValue, 24, 7, 0, // Skip to: 6151
/* 6144 */    MCD_OPC_CheckPredicate, 4, 180, 25, // Skip to: 12728
/* 6148 */    MCD_OPC_Decode, 123, 106, // Opcode: AVER_S_B
/* 6151 */    MCD_OPC_FilterValue, 25, 7, 0, // Skip to: 6162
/* 6155 */    MCD_OPC_CheckPredicate, 4, 169, 25, // Skip to: 12728
/* 6159 */    MCD_OPC_Decode, 125, 107, // Opcode: AVER_S_H
/* 6162 */    MCD_OPC_FilterValue, 26, 7, 0, // Skip to: 6173
/* 6166 */    MCD_OPC_CheckPredicate, 4, 158, 25, // Skip to: 12728
/* 6170 */    MCD_OPC_Decode, 126, 108, // Opcode: AVER_S_W
/* 6173 */    MCD_OPC_FilterValue, 27, 7, 0, // Skip to: 6184
/* 6177 */    MCD_OPC_CheckPredicate, 4, 147, 25, // Skip to: 12728
/* 6181 */    MCD_OPC_Decode, 124, 109, // Opcode: AVER_S_D
/* 6184 */    MCD_OPC_FilterValue, 28, 7, 0, // Skip to: 6195
/* 6188 */    MCD_OPC_CheckPredicate, 4, 136, 25, // Skip to: 12728
/* 6192 */    MCD_OPC_Decode, 127, 106, // Opcode: AVER_U_B
/* 6195 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 6207
/* 6199 */    MCD_OPC_CheckPredicate, 4, 125, 25, // Skip to: 12728
/* 6203 */    MCD_OPC_Decode, 129, 1, 107, // Opcode: AVER_U_H
/* 6207 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 6219
/* 6211 */    MCD_OPC_CheckPredicate, 4, 113, 25, // Skip to: 12728
/* 6215 */    MCD_OPC_Decode, 130, 1, 108, // Opcode: AVER_U_W
/* 6219 */    MCD_OPC_FilterValue, 31, 105, 25, // Skip to: 12728
/* 6223 */    MCD_OPC_CheckPredicate, 4, 101, 25, // Skip to: 12728
/* 6227 */    MCD_OPC_Decode, 128, 1, 109, // Opcode: AVER_U_D
/* 6231 */    MCD_OPC_FilterValue, 17, 27, 1, // Skip to: 6518
/* 6235 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 6238 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 6250
/* 6242 */    MCD_OPC_CheckPredicate, 4, 82, 25, // Skip to: 12728
/* 6246 */    MCD_OPC_Decode, 236, 9, 106, // Opcode: SUBS_S_B
/* 6250 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 6262
/* 6254 */    MCD_OPC_CheckPredicate, 4, 70, 25, // Skip to: 12728
/* 6258 */    MCD_OPC_Decode, 238, 9, 107, // Opcode: SUBS_S_H
/* 6262 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 6274
/* 6266 */    MCD_OPC_CheckPredicate, 4, 58, 25, // Skip to: 12728
/* 6270 */    MCD_OPC_Decode, 239, 9, 108, // Opcode: SUBS_S_W
/* 6274 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 6286
/* 6278 */    MCD_OPC_CheckPredicate, 4, 46, 25, // Skip to: 12728
/* 6282 */    MCD_OPC_Decode, 237, 9, 109, // Opcode: SUBS_S_D
/* 6286 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 6298
/* 6290 */    MCD_OPC_CheckPredicate, 4, 34, 25, // Skip to: 12728
/* 6294 */    MCD_OPC_Decode, 240, 9, 106, // Opcode: SUBS_U_B
/* 6298 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 6310
/* 6302 */    MCD_OPC_CheckPredicate, 4, 22, 25, // Skip to: 12728
/* 6306 */    MCD_OPC_Decode, 242, 9, 107, // Opcode: SUBS_U_H
/* 6310 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 6322
/* 6314 */    MCD_OPC_CheckPredicate, 4, 10, 25, // Skip to: 12728
/* 6318 */    MCD_OPC_Decode, 243, 9, 108, // Opcode: SUBS_U_W
/* 6322 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 6334
/* 6326 */    MCD_OPC_CheckPredicate, 4, 254, 24, // Skip to: 12728
/* 6330 */    MCD_OPC_Decode, 241, 9, 109, // Opcode: SUBS_U_D
/* 6334 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 6346
/* 6338 */    MCD_OPC_CheckPredicate, 4, 242, 24, // Skip to: 12728
/* 6342 */    MCD_OPC_Decode, 228, 9, 106, // Opcode: SUBSUS_U_B
/* 6346 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 6358
/* 6350 */    MCD_OPC_CheckPredicate, 4, 230, 24, // Skip to: 12728
/* 6354 */    MCD_OPC_Decode, 230, 9, 107, // Opcode: SUBSUS_U_H
/* 6358 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 6370
/* 6362 */    MCD_OPC_CheckPredicate, 4, 218, 24, // Skip to: 12728
/* 6366 */    MCD_OPC_Decode, 231, 9, 108, // Opcode: SUBSUS_U_W
/* 6370 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 6382
/* 6374 */    MCD_OPC_CheckPredicate, 4, 206, 24, // Skip to: 12728
/* 6378 */    MCD_OPC_Decode, 229, 9, 109, // Opcode: SUBSUS_U_D
/* 6382 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 6394
/* 6386 */    MCD_OPC_CheckPredicate, 4, 194, 24, // Skip to: 12728
/* 6390 */    MCD_OPC_Decode, 232, 9, 106, // Opcode: SUBSUU_S_B
/* 6394 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 6406
/* 6398 */    MCD_OPC_CheckPredicate, 4, 182, 24, // Skip to: 12728
/* 6402 */    MCD_OPC_Decode, 234, 9, 107, // Opcode: SUBSUU_S_H
/* 6406 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 6418
/* 6410 */    MCD_OPC_CheckPredicate, 4, 170, 24, // Skip to: 12728
/* 6414 */    MCD_OPC_Decode, 235, 9, 108, // Opcode: SUBSUU_S_W
/* 6418 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 6430
/* 6422 */    MCD_OPC_CheckPredicate, 4, 158, 24, // Skip to: 12728
/* 6426 */    MCD_OPC_Decode, 233, 9, 109, // Opcode: SUBSUU_S_D
/* 6430 */    MCD_OPC_FilterValue, 16, 7, 0, // Skip to: 6441
/* 6434 */    MCD_OPC_CheckPredicate, 4, 146, 24, // Skip to: 12728
/* 6438 */    MCD_OPC_Decode, 83, 106, // Opcode: ASUB_S_B
/* 6441 */    MCD_OPC_FilterValue, 17, 7, 0, // Skip to: 6452
/* 6445 */    MCD_OPC_CheckPredicate, 4, 135, 24, // Skip to: 12728
/* 6449 */    MCD_OPC_Decode, 85, 107, // Opcode: ASUB_S_H
/* 6452 */    MCD_OPC_FilterValue, 18, 7, 0, // Skip to: 6463
/* 6456 */    MCD_OPC_CheckPredicate, 4, 124, 24, // Skip to: 12728
/* 6460 */    MCD_OPC_Decode, 86, 108, // Opcode: ASUB_S_W
/* 6463 */    MCD_OPC_FilterValue, 19, 7, 0, // Skip to: 6474
/* 6467 */    MCD_OPC_CheckPredicate, 4, 113, 24, // Skip to: 12728
/* 6471 */    MCD_OPC_Decode, 84, 109, // Opcode: ASUB_S_D
/* 6474 */    MCD_OPC_FilterValue, 20, 7, 0, // Skip to: 6485
/* 6478 */    MCD_OPC_CheckPredicate, 4, 102, 24, // Skip to: 12728
/* 6482 */    MCD_OPC_Decode, 87, 106, // Opcode: ASUB_U_B
/* 6485 */    MCD_OPC_FilterValue, 21, 7, 0, // Skip to: 6496
/* 6489 */    MCD_OPC_CheckPredicate, 4, 91, 24, // Skip to: 12728
/* 6493 */    MCD_OPC_Decode, 89, 107, // Opcode: ASUB_U_H
/* 6496 */    MCD_OPC_FilterValue, 22, 7, 0, // Skip to: 6507
/* 6500 */    MCD_OPC_CheckPredicate, 4, 80, 24, // Skip to: 12728
/* 6504 */    MCD_OPC_Decode, 90, 108, // Opcode: ASUB_U_W
/* 6507 */    MCD_OPC_FilterValue, 23, 73, 24, // Skip to: 12728
/* 6511 */    MCD_OPC_CheckPredicate, 4, 69, 24, // Skip to: 12728
/* 6515 */    MCD_OPC_Decode, 88, 109, // Opcode: ASUB_U_D
/* 6518 */    MCD_OPC_FilterValue, 18, 83, 1, // Skip to: 6861
/* 6522 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 6525 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 6537
/* 6529 */    MCD_OPC_CheckPredicate, 4, 51, 24, // Skip to: 12728
/* 6533 */    MCD_OPC_Decode, 180, 7, 106, // Opcode: MULV_B
/* 6537 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 6549
/* 6541 */    MCD_OPC_CheckPredicate, 4, 39, 24, // Skip to: 12728
/* 6545 */    MCD_OPC_Decode, 182, 7, 107, // Opcode: MULV_H
/* 6549 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 6561
/* 6553 */    MCD_OPC_CheckPredicate, 4, 27, 24, // Skip to: 12728
/* 6557 */    MCD_OPC_Decode, 183, 7, 108, // Opcode: MULV_W
/* 6561 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 6573
/* 6565 */    MCD_OPC_CheckPredicate, 4, 15, 24, // Skip to: 12728
/* 6569 */    MCD_OPC_Decode, 181, 7, 109, // Opcode: MULV_D
/* 6573 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 6585
/* 6577 */    MCD_OPC_CheckPredicate, 4, 3, 24, // Skip to: 12728
/* 6581 */    MCD_OPC_Decode, 148, 6, 110, // Opcode: MADDV_B
/* 6585 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 6597
/* 6589 */    MCD_OPC_CheckPredicate, 4, 247, 23, // Skip to: 12728
/* 6593 */    MCD_OPC_Decode, 150, 6, 111, // Opcode: MADDV_H
/* 6597 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 6609
/* 6601 */    MCD_OPC_CheckPredicate, 4, 235, 23, // Skip to: 12728
/* 6605 */    MCD_OPC_Decode, 151, 6, 112, // Opcode: MADDV_W
/* 6609 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 6621
/* 6613 */    MCD_OPC_CheckPredicate, 4, 223, 23, // Skip to: 12728
/* 6617 */    MCD_OPC_Decode, 149, 6, 113, // Opcode: MADDV_D
/* 6621 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 6633
/* 6625 */    MCD_OPC_CheckPredicate, 4, 211, 23, // Skip to: 12728
/* 6629 */    MCD_OPC_Decode, 137, 7, 110, // Opcode: MSUBV_B
/* 6633 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 6645
/* 6637 */    MCD_OPC_CheckPredicate, 4, 199, 23, // Skip to: 12728
/* 6641 */    MCD_OPC_Decode, 139, 7, 111, // Opcode: MSUBV_H
/* 6645 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 6657
/* 6649 */    MCD_OPC_CheckPredicate, 4, 187, 23, // Skip to: 12728
/* 6653 */    MCD_OPC_Decode, 140, 7, 112, // Opcode: MSUBV_W
/* 6657 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 6669
/* 6661 */    MCD_OPC_CheckPredicate, 4, 175, 23, // Skip to: 12728
/* 6665 */    MCD_OPC_Decode, 138, 7, 113, // Opcode: MSUBV_D
/* 6669 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 6681
/* 6673 */    MCD_OPC_CheckPredicate, 4, 163, 23, // Skip to: 12728
/* 6677 */    MCD_OPC_Decode, 163, 3, 106, // Opcode: DIV_S_B
/* 6681 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 6693
/* 6685 */    MCD_OPC_CheckPredicate, 4, 151, 23, // Skip to: 12728
/* 6689 */    MCD_OPC_Decode, 165, 3, 107, // Opcode: DIV_S_H
/* 6693 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 6705
/* 6697 */    MCD_OPC_CheckPredicate, 4, 139, 23, // Skip to: 12728
/* 6701 */    MCD_OPC_Decode, 166, 3, 108, // Opcode: DIV_S_W
/* 6705 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 6717
/* 6709 */    MCD_OPC_CheckPredicate, 4, 127, 23, // Skip to: 12728
/* 6713 */    MCD_OPC_Decode, 164, 3, 109, // Opcode: DIV_S_D
/* 6717 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 6729
/* 6721 */    MCD_OPC_CheckPredicate, 4, 115, 23, // Skip to: 12728
/* 6725 */    MCD_OPC_Decode, 167, 3, 106, // Opcode: DIV_U_B
/* 6729 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 6741
/* 6733 */    MCD_OPC_CheckPredicate, 4, 103, 23, // Skip to: 12728
/* 6737 */    MCD_OPC_Decode, 169, 3, 107, // Opcode: DIV_U_H
/* 6741 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 6753
/* 6745 */    MCD_OPC_CheckPredicate, 4, 91, 23, // Skip to: 12728
/* 6749 */    MCD_OPC_Decode, 170, 3, 108, // Opcode: DIV_U_W
/* 6753 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 6765
/* 6757 */    MCD_OPC_CheckPredicate, 4, 79, 23, // Skip to: 12728
/* 6761 */    MCD_OPC_Decode, 168, 3, 109, // Opcode: DIV_U_D
/* 6765 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 6777
/* 6769 */    MCD_OPC_CheckPredicate, 4, 67, 23, // Skip to: 12728
/* 6773 */    MCD_OPC_Decode, 218, 6, 106, // Opcode: MOD_S_B
/* 6777 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 6789
/* 6781 */    MCD_OPC_CheckPredicate, 4, 55, 23, // Skip to: 12728
/* 6785 */    MCD_OPC_Decode, 220, 6, 107, // Opcode: MOD_S_H
/* 6789 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 6801
/* 6793 */    MCD_OPC_CheckPredicate, 4, 43, 23, // Skip to: 12728
/* 6797 */    MCD_OPC_Decode, 221, 6, 108, // Opcode: MOD_S_W
/* 6801 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 6813
/* 6805 */    MCD_OPC_CheckPredicate, 4, 31, 23, // Skip to: 12728
/* 6809 */    MCD_OPC_Decode, 219, 6, 109, // Opcode: MOD_S_D
/* 6813 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 6825
/* 6817 */    MCD_OPC_CheckPredicate, 4, 19, 23, // Skip to: 12728
/* 6821 */    MCD_OPC_Decode, 222, 6, 106, // Opcode: MOD_U_B
/* 6825 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 6837
/* 6829 */    MCD_OPC_CheckPredicate, 4, 7, 23, // Skip to: 12728
/* 6833 */    MCD_OPC_Decode, 224, 6, 107, // Opcode: MOD_U_H
/* 6837 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 6849
/* 6841 */    MCD_OPC_CheckPredicate, 4, 251, 22, // Skip to: 12728
/* 6845 */    MCD_OPC_Decode, 225, 6, 108, // Opcode: MOD_U_W
/* 6849 */    MCD_OPC_FilterValue, 31, 243, 22, // Skip to: 12728
/* 6853 */    MCD_OPC_CheckPredicate, 4, 239, 22, // Skip to: 12728
/* 6857 */    MCD_OPC_Decode, 223, 6, 109, // Opcode: MOD_U_D
/* 6861 */    MCD_OPC_FilterValue, 19, 219, 0, // Skip to: 7084
/* 6865 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 6868 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 6880
/* 6872 */    MCD_OPC_CheckPredicate, 4, 220, 22, // Skip to: 12728
/* 6876 */    MCD_OPC_Decode, 180, 3, 114, // Opcode: DOTP_S_H
/* 6880 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 6892
/* 6884 */    MCD_OPC_CheckPredicate, 4, 208, 22, // Skip to: 12728
/* 6888 */    MCD_OPC_Decode, 181, 3, 115, // Opcode: DOTP_S_W
/* 6892 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 6904
/* 6896 */    MCD_OPC_CheckPredicate, 4, 196, 22, // Skip to: 12728
/* 6900 */    MCD_OPC_Decode, 179, 3, 116, // Opcode: DOTP_S_D
/* 6904 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 6916
/* 6908 */    MCD_OPC_CheckPredicate, 4, 184, 22, // Skip to: 12728
/* 6912 */    MCD_OPC_Decode, 183, 3, 114, // Opcode: DOTP_U_H
/* 6916 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 6928
/* 6920 */    MCD_OPC_CheckPredicate, 4, 172, 22, // Skip to: 12728
/* 6924 */    MCD_OPC_Decode, 184, 3, 115, // Opcode: DOTP_U_W
/* 6928 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 6940
/* 6932 */    MCD_OPC_CheckPredicate, 4, 160, 22, // Skip to: 12728
/* 6936 */    MCD_OPC_Decode, 182, 3, 116, // Opcode: DOTP_U_D
/* 6940 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 6952
/* 6944 */    MCD_OPC_CheckPredicate, 4, 148, 22, // Skip to: 12728
/* 6948 */    MCD_OPC_Decode, 186, 3, 117, // Opcode: DPADD_S_H
/* 6952 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 6964
/* 6956 */    MCD_OPC_CheckPredicate, 4, 136, 22, // Skip to: 12728
/* 6960 */    MCD_OPC_Decode, 187, 3, 118, // Opcode: DPADD_S_W
/* 6964 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 6976
/* 6968 */    MCD_OPC_CheckPredicate, 4, 124, 22, // Skip to: 12728
/* 6972 */    MCD_OPC_Decode, 185, 3, 119, // Opcode: DPADD_S_D
/* 6976 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 6988
/* 6980 */    MCD_OPC_CheckPredicate, 4, 112, 22, // Skip to: 12728
/* 6984 */    MCD_OPC_Decode, 189, 3, 117, // Opcode: DPADD_U_H
/* 6988 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 7000
/* 6992 */    MCD_OPC_CheckPredicate, 4, 100, 22, // Skip to: 12728
/* 6996 */    MCD_OPC_Decode, 190, 3, 118, // Opcode: DPADD_U_W
/* 7000 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 7012
/* 7004 */    MCD_OPC_CheckPredicate, 4, 88, 22, // Skip to: 12728
/* 7008 */    MCD_OPC_Decode, 188, 3, 119, // Opcode: DPADD_U_D
/* 7012 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 7024
/* 7016 */    MCD_OPC_CheckPredicate, 4, 76, 22, // Skip to: 12728
/* 7020 */    MCD_OPC_Decode, 204, 3, 117, // Opcode: DPSUB_S_H
/* 7024 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 7036
/* 7028 */    MCD_OPC_CheckPredicate, 4, 64, 22, // Skip to: 12728
/* 7032 */    MCD_OPC_Decode, 205, 3, 118, // Opcode: DPSUB_S_W
/* 7036 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 7048
/* 7040 */    MCD_OPC_CheckPredicate, 4, 52, 22, // Skip to: 12728
/* 7044 */    MCD_OPC_Decode, 203, 3, 119, // Opcode: DPSUB_S_D
/* 7048 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 7060
/* 7052 */    MCD_OPC_CheckPredicate, 4, 40, 22, // Skip to: 12728
/* 7056 */    MCD_OPC_Decode, 207, 3, 117, // Opcode: DPSUB_U_H
/* 7060 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 7072
/* 7064 */    MCD_OPC_CheckPredicate, 4, 28, 22, // Skip to: 12728
/* 7068 */    MCD_OPC_Decode, 208, 3, 118, // Opcode: DPSUB_U_W
/* 7072 */    MCD_OPC_FilterValue, 23, 20, 22, // Skip to: 12728
/* 7076 */    MCD_OPC_CheckPredicate, 4, 16, 22, // Skip to: 12728
/* 7080 */    MCD_OPC_Decode, 206, 3, 119, // Opcode: DPSUB_U_D
/* 7084 */    MCD_OPC_FilterValue, 20, 131, 1, // Skip to: 7475
/* 7088 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 7091 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 7103
/* 7095 */    MCD_OPC_CheckPredicate, 4, 253, 21, // Skip to: 12728
/* 7099 */    MCD_OPC_Decode, 129, 9, 120, // Opcode: SLD_B
/* 7103 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 7115
/* 7107 */    MCD_OPC_CheckPredicate, 4, 241, 21, // Skip to: 12728
/* 7111 */    MCD_OPC_Decode, 131, 9, 121, // Opcode: SLD_H
/* 7115 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 7127
/* 7119 */    MCD_OPC_CheckPredicate, 4, 229, 21, // Skip to: 12728
/* 7123 */    MCD_OPC_Decode, 132, 9, 122, // Opcode: SLD_W
/* 7127 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 7139
/* 7131 */    MCD_OPC_CheckPredicate, 4, 217, 21, // Skip to: 12728
/* 7135 */    MCD_OPC_Decode, 130, 9, 123, // Opcode: SLD_D
/* 7139 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 7151
/* 7143 */    MCD_OPC_CheckPredicate, 4, 205, 21, // Skip to: 12728
/* 7147 */    MCD_OPC_Decode, 168, 9, 120, // Opcode: SPLAT_B
/* 7151 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 7163
/* 7155 */    MCD_OPC_CheckPredicate, 4, 193, 21, // Skip to: 12728
/* 7159 */    MCD_OPC_Decode, 170, 9, 121, // Opcode: SPLAT_H
/* 7163 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 7175
/* 7167 */    MCD_OPC_CheckPredicate, 4, 181, 21, // Skip to: 12728
/* 7171 */    MCD_OPC_Decode, 171, 9, 122, // Opcode: SPLAT_W
/* 7175 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 7187
/* 7179 */    MCD_OPC_CheckPredicate, 4, 169, 21, // Skip to: 12728
/* 7183 */    MCD_OPC_Decode, 169, 9, 123, // Opcode: SPLAT_D
/* 7187 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 7199
/* 7191 */    MCD_OPC_CheckPredicate, 4, 157, 21, // Skip to: 12728
/* 7195 */    MCD_OPC_Decode, 235, 7, 106, // Opcode: PCKEV_B
/* 7199 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 7211
/* 7203 */    MCD_OPC_CheckPredicate, 4, 145, 21, // Skip to: 12728
/* 7207 */    MCD_OPC_Decode, 237, 7, 107, // Opcode: PCKEV_H
/* 7211 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 7223
/* 7215 */    MCD_OPC_CheckPredicate, 4, 133, 21, // Skip to: 12728
/* 7219 */    MCD_OPC_Decode, 238, 7, 108, // Opcode: PCKEV_W
/* 7223 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 7235
/* 7227 */    MCD_OPC_CheckPredicate, 4, 121, 21, // Skip to: 12728
/* 7231 */    MCD_OPC_Decode, 236, 7, 109, // Opcode: PCKEV_D
/* 7235 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 7247
/* 7239 */    MCD_OPC_CheckPredicate, 4, 109, 21, // Skip to: 12728
/* 7243 */    MCD_OPC_Decode, 239, 7, 106, // Opcode: PCKOD_B
/* 7247 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 7259
/* 7251 */    MCD_OPC_CheckPredicate, 4, 97, 21, // Skip to: 12728
/* 7255 */    MCD_OPC_Decode, 241, 7, 107, // Opcode: PCKOD_H
/* 7259 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 7271
/* 7263 */    MCD_OPC_CheckPredicate, 4, 85, 21, // Skip to: 12728
/* 7267 */    MCD_OPC_Decode, 242, 7, 108, // Opcode: PCKOD_W
/* 7271 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 7283
/* 7275 */    MCD_OPC_CheckPredicate, 4, 73, 21, // Skip to: 12728
/* 7279 */    MCD_OPC_Decode, 240, 7, 109, // Opcode: PCKOD_D
/* 7283 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 7295
/* 7287 */    MCD_OPC_CheckPredicate, 4, 61, 21, // Skip to: 12728
/* 7291 */    MCD_OPC_Decode, 155, 5, 106, // Opcode: ILVL_B
/* 7295 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 7307
/* 7299 */    MCD_OPC_CheckPredicate, 4, 49, 21, // Skip to: 12728
/* 7303 */    MCD_OPC_Decode, 157, 5, 107, // Opcode: ILVL_H
/* 7307 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 7319
/* 7311 */    MCD_OPC_CheckPredicate, 4, 37, 21, // Skip to: 12728
/* 7315 */    MCD_OPC_Decode, 158, 5, 108, // Opcode: ILVL_W
/* 7319 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 7331
/* 7323 */    MCD_OPC_CheckPredicate, 4, 25, 21, // Skip to: 12728
/* 7327 */    MCD_OPC_Decode, 156, 5, 109, // Opcode: ILVL_D
/* 7331 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 7343
/* 7335 */    MCD_OPC_CheckPredicate, 4, 13, 21, // Skip to: 12728
/* 7339 */    MCD_OPC_Decode, 163, 5, 106, // Opcode: ILVR_B
/* 7343 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 7355
/* 7347 */    MCD_OPC_CheckPredicate, 4, 1, 21, // Skip to: 12728
/* 7351 */    MCD_OPC_Decode, 165, 5, 107, // Opcode: ILVR_H
/* 7355 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 7367
/* 7359 */    MCD_OPC_CheckPredicate, 4, 245, 20, // Skip to: 12728
/* 7363 */    MCD_OPC_Decode, 166, 5, 108, // Opcode: ILVR_W
/* 7367 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 7379
/* 7371 */    MCD_OPC_CheckPredicate, 4, 233, 20, // Skip to: 12728
/* 7375 */    MCD_OPC_Decode, 164, 5, 109, // Opcode: ILVR_D
/* 7379 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 7391
/* 7383 */    MCD_OPC_CheckPredicate, 4, 221, 20, // Skip to: 12728
/* 7387 */    MCD_OPC_Decode, 151, 5, 106, // Opcode: ILVEV_B
/* 7391 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 7403
/* 7395 */    MCD_OPC_CheckPredicate, 4, 209, 20, // Skip to: 12728
/* 7399 */    MCD_OPC_Decode, 153, 5, 107, // Opcode: ILVEV_H
/* 7403 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 7415
/* 7407 */    MCD_OPC_CheckPredicate, 4, 197, 20, // Skip to: 12728
/* 7411 */    MCD_OPC_Decode, 154, 5, 108, // Opcode: ILVEV_W
/* 7415 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 7427
/* 7419 */    MCD_OPC_CheckPredicate, 4, 185, 20, // Skip to: 12728
/* 7423 */    MCD_OPC_Decode, 152, 5, 109, // Opcode: ILVEV_D
/* 7427 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 7439
/* 7431 */    MCD_OPC_CheckPredicate, 4, 173, 20, // Skip to: 12728
/* 7435 */    MCD_OPC_Decode, 159, 5, 106, // Opcode: ILVOD_B
/* 7439 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 7451
/* 7443 */    MCD_OPC_CheckPredicate, 4, 161, 20, // Skip to: 12728
/* 7447 */    MCD_OPC_Decode, 161, 5, 107, // Opcode: ILVOD_H
/* 7451 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 7463
/* 7455 */    MCD_OPC_CheckPredicate, 4, 149, 20, // Skip to: 12728
/* 7459 */    MCD_OPC_Decode, 162, 5, 108, // Opcode: ILVOD_W
/* 7463 */    MCD_OPC_FilterValue, 31, 141, 20, // Skip to: 12728
/* 7467 */    MCD_OPC_CheckPredicate, 4, 137, 20, // Skip to: 12728
/* 7471 */    MCD_OPC_Decode, 160, 5, 109, // Opcode: ILVOD_D
/* 7475 */    MCD_OPC_FilterValue, 21, 35, 1, // Skip to: 7770
/* 7479 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 7482 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 7494
/* 7486 */    MCD_OPC_CheckPredicate, 4, 118, 20, // Skip to: 12728
/* 7490 */    MCD_OPC_Decode, 229, 10, 110, // Opcode: VSHF_B
/* 7494 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 7506
/* 7498 */    MCD_OPC_CheckPredicate, 4, 106, 20, // Skip to: 12728
/* 7502 */    MCD_OPC_Decode, 231, 10, 111, // Opcode: VSHF_H
/* 7506 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 7518
/* 7510 */    MCD_OPC_CheckPredicate, 4, 94, 20, // Skip to: 12728
/* 7514 */    MCD_OPC_Decode, 232, 10, 112, // Opcode: VSHF_W
/* 7518 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 7530
/* 7522 */    MCD_OPC_CheckPredicate, 4, 82, 20, // Skip to: 12728
/* 7526 */    MCD_OPC_Decode, 230, 10, 113, // Opcode: VSHF_D
/* 7530 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 7542
/* 7534 */    MCD_OPC_CheckPredicate, 4, 70, 20, // Skip to: 12728
/* 7538 */    MCD_OPC_Decode, 181, 9, 106, // Opcode: SRAR_B
/* 7542 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 7554
/* 7546 */    MCD_OPC_CheckPredicate, 4, 58, 20, // Skip to: 12728
/* 7550 */    MCD_OPC_Decode, 183, 9, 107, // Opcode: SRAR_H
/* 7554 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 7566
/* 7558 */    MCD_OPC_CheckPredicate, 4, 46, 20, // Skip to: 12728
/* 7562 */    MCD_OPC_Decode, 184, 9, 108, // Opcode: SRAR_W
/* 7566 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 7578
/* 7570 */    MCD_OPC_CheckPredicate, 4, 34, 20, // Skip to: 12728
/* 7574 */    MCD_OPC_Decode, 182, 9, 109, // Opcode: SRAR_D
/* 7578 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 7590
/* 7582 */    MCD_OPC_CheckPredicate, 4, 22, 20, // Skip to: 12728
/* 7586 */    MCD_OPC_Decode, 201, 9, 106, // Opcode: SRLR_B
/* 7590 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 7602
/* 7594 */    MCD_OPC_CheckPredicate, 4, 10, 20, // Skip to: 12728
/* 7598 */    MCD_OPC_Decode, 203, 9, 107, // Opcode: SRLR_H
/* 7602 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 7614
/* 7606 */    MCD_OPC_CheckPredicate, 4, 254, 19, // Skip to: 12728
/* 7610 */    MCD_OPC_Decode, 204, 9, 108, // Opcode: SRLR_W
/* 7614 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 7626
/* 7618 */    MCD_OPC_CheckPredicate, 4, 242, 19, // Skip to: 12728
/* 7622 */    MCD_OPC_Decode, 202, 9, 109, // Opcode: SRLR_D
/* 7626 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 7638
/* 7630 */    MCD_OPC_CheckPredicate, 4, 230, 19, // Skip to: 12728
/* 7634 */    MCD_OPC_Decode, 140, 5, 114, // Opcode: HADD_S_H
/* 7638 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 7650
/* 7642 */    MCD_OPC_CheckPredicate, 4, 218, 19, // Skip to: 12728
/* 7646 */    MCD_OPC_Decode, 141, 5, 115, // Opcode: HADD_S_W
/* 7650 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 7662
/* 7654 */    MCD_OPC_CheckPredicate, 4, 206, 19, // Skip to: 12728
/* 7658 */    MCD_OPC_Decode, 139, 5, 116, // Opcode: HADD_S_D
/* 7662 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 7674
/* 7666 */    MCD_OPC_CheckPredicate, 4, 194, 19, // Skip to: 12728
/* 7670 */    MCD_OPC_Decode, 143, 5, 114, // Opcode: HADD_U_H
/* 7674 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 7686
/* 7678 */    MCD_OPC_CheckPredicate, 4, 182, 19, // Skip to: 12728
/* 7682 */    MCD_OPC_Decode, 144, 5, 115, // Opcode: HADD_U_W
/* 7686 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 7698
/* 7690 */    MCD_OPC_CheckPredicate, 4, 170, 19, // Skip to: 12728
/* 7694 */    MCD_OPC_Decode, 142, 5, 116, // Opcode: HADD_U_D
/* 7698 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 7710
/* 7702 */    MCD_OPC_CheckPredicate, 4, 158, 19, // Skip to: 12728
/* 7706 */    MCD_OPC_Decode, 146, 5, 114, // Opcode: HSUB_S_H
/* 7710 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 7722
/* 7714 */    MCD_OPC_CheckPredicate, 4, 146, 19, // Skip to: 12728
/* 7718 */    MCD_OPC_Decode, 147, 5, 115, // Opcode: HSUB_S_W
/* 7722 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 7734
/* 7726 */    MCD_OPC_CheckPredicate, 4, 134, 19, // Skip to: 12728
/* 7730 */    MCD_OPC_Decode, 145, 5, 116, // Opcode: HSUB_S_D
/* 7734 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 7746
/* 7738 */    MCD_OPC_CheckPredicate, 4, 122, 19, // Skip to: 12728
/* 7742 */    MCD_OPC_Decode, 149, 5, 114, // Opcode: HSUB_U_H
/* 7746 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 7758
/* 7750 */    MCD_OPC_CheckPredicate, 4, 110, 19, // Skip to: 12728
/* 7754 */    MCD_OPC_Decode, 150, 5, 115, // Opcode: HSUB_U_W
/* 7758 */    MCD_OPC_FilterValue, 31, 102, 19, // Skip to: 12728
/* 7762 */    MCD_OPC_CheckPredicate, 4, 98, 19, // Skip to: 12728
/* 7766 */    MCD_OPC_Decode, 148, 5, 116, // Opcode: HSUB_U_D
/* 7770 */    MCD_OPC_FilterValue, 25, 163, 1, // Skip to: 8193
/* 7774 */    MCD_OPC_ExtractField, 20, 6,  // Inst{25-20} ...
/* 7777 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 7789
/* 7781 */    MCD_OPC_CheckPredicate, 4, 79, 19, // Skip to: 12728
/* 7785 */    MCD_OPC_Decode, 253, 8, 124, // Opcode: SLDI_B
/* 7789 */    MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 7807
/* 7793 */    MCD_OPC_CheckPredicate, 4, 67, 19, // Skip to: 12728
/* 7797 */    MCD_OPC_CheckField, 19, 1, 0, 61, 19, // Skip to: 12728
/* 7803 */    MCD_OPC_Decode, 255, 8, 125, // Opcode: SLDI_H
/* 7807 */    MCD_OPC_FilterValue, 3, 52, 0, // Skip to: 7863
/* 7811 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 7814 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 7826
/* 7818 */    MCD_OPC_CheckPredicate, 4, 42, 19, // Skip to: 12728
/* 7822 */    MCD_OPC_Decode, 128, 9, 126, // Opcode: SLDI_W
/* 7826 */    MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 7844
/* 7830 */    MCD_OPC_CheckPredicate, 4, 30, 19, // Skip to: 12728
/* 7834 */    MCD_OPC_CheckField, 17, 1, 0, 24, 19, // Skip to: 12728
/* 7840 */    MCD_OPC_Decode, 254, 8, 127, // Opcode: SLDI_D
/* 7844 */    MCD_OPC_FilterValue, 3, 16, 19, // Skip to: 12728
/* 7848 */    MCD_OPC_CheckPredicate, 4, 12, 19, // Skip to: 12728
/* 7852 */    MCD_OPC_CheckField, 16, 2, 2, 6, 19, // Skip to: 12728
/* 7858 */    MCD_OPC_Decode, 210, 2, 128, 1, // Opcode: CTCMSA
/* 7863 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 7875
/* 7867 */    MCD_OPC_CheckPredicate, 4, 249, 18, // Skip to: 12728
/* 7871 */    MCD_OPC_Decode, 164, 9, 124, // Opcode: SPLATI_B
/* 7875 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 7893
/* 7879 */    MCD_OPC_CheckPredicate, 4, 237, 18, // Skip to: 12728
/* 7883 */    MCD_OPC_CheckField, 19, 1, 0, 231, 18, // Skip to: 12728
/* 7889 */    MCD_OPC_Decode, 166, 9, 125, // Opcode: SPLATI_H
/* 7893 */    MCD_OPC_FilterValue, 7, 52, 0, // Skip to: 7949
/* 7897 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 7900 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 7912
/* 7904 */    MCD_OPC_CheckPredicate, 4, 212, 18, // Skip to: 12728
/* 7908 */    MCD_OPC_Decode, 167, 9, 126, // Opcode: SPLATI_W
/* 7912 */    MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 7930
/* 7916 */    MCD_OPC_CheckPredicate, 4, 200, 18, // Skip to: 12728
/* 7920 */    MCD_OPC_CheckField, 17, 1, 0, 194, 18, // Skip to: 12728
/* 7926 */    MCD_OPC_Decode, 165, 9, 127, // Opcode: SPLATI_D
/* 7930 */    MCD_OPC_FilterValue, 3, 186, 18, // Skip to: 12728
/* 7934 */    MCD_OPC_CheckPredicate, 4, 182, 18, // Skip to: 12728
/* 7938 */    MCD_OPC_CheckField, 16, 2, 2, 176, 18, // Skip to: 12728
/* 7944 */    MCD_OPC_Decode, 151, 2, 129, 1, // Opcode: CFCMSA
/* 7949 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 7962
/* 7953 */    MCD_OPC_CheckPredicate, 4, 163, 18, // Skip to: 12728
/* 7957 */    MCD_OPC_Decode, 203, 2, 130, 1, // Opcode: COPY_S_B
/* 7962 */    MCD_OPC_FilterValue, 10, 15, 0, // Skip to: 7981
/* 7966 */    MCD_OPC_CheckPredicate, 4, 150, 18, // Skip to: 12728
/* 7970 */    MCD_OPC_CheckField, 19, 1, 0, 144, 18, // Skip to: 12728
/* 7976 */    MCD_OPC_Decode, 204, 2, 131, 1, // Opcode: COPY_S_H
/* 7981 */    MCD_OPC_FilterValue, 11, 35, 0, // Skip to: 8020
/* 7985 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 7988 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8001
/* 7992 */    MCD_OPC_CheckPredicate, 4, 124, 18, // Skip to: 12728
/* 7996 */    MCD_OPC_Decode, 205, 2, 132, 1, // Opcode: COPY_S_W
/* 8001 */    MCD_OPC_FilterValue, 3, 115, 18, // Skip to: 12728
/* 8005 */    MCD_OPC_CheckPredicate, 4, 111, 18, // Skip to: 12728
/* 8009 */    MCD_OPC_CheckField, 16, 2, 2, 105, 18, // Skip to: 12728
/* 8015 */    MCD_OPC_Decode, 226, 6, 133, 1, // Opcode: MOVE_V
/* 8020 */    MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 8033
/* 8024 */    MCD_OPC_CheckPredicate, 4, 92, 18, // Skip to: 12728
/* 8028 */    MCD_OPC_Decode, 206, 2, 130, 1, // Opcode: COPY_U_B
/* 8033 */    MCD_OPC_FilterValue, 14, 15, 0, // Skip to: 8052
/* 8037 */    MCD_OPC_CheckPredicate, 4, 79, 18, // Skip to: 12728
/* 8041 */    MCD_OPC_CheckField, 19, 1, 0, 73, 18, // Skip to: 12728
/* 8047 */    MCD_OPC_Decode, 207, 2, 131, 1, // Opcode: COPY_U_H
/* 8052 */    MCD_OPC_FilterValue, 15, 15, 0, // Skip to: 8071
/* 8056 */    MCD_OPC_CheckPredicate, 4, 60, 18, // Skip to: 12728
/* 8060 */    MCD_OPC_CheckField, 18, 2, 0, 54, 18, // Skip to: 12728
/* 8066 */    MCD_OPC_Decode, 208, 2, 132, 1, // Opcode: COPY_U_W
/* 8071 */    MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 8084
/* 8075 */    MCD_OPC_CheckPredicate, 4, 41, 18, // Skip to: 12728
/* 8079 */    MCD_OPC_Decode, 168, 5, 134, 1, // Opcode: INSERT_B
/* 8084 */    MCD_OPC_FilterValue, 18, 15, 0, // Skip to: 8103
/* 8088 */    MCD_OPC_CheckPredicate, 4, 28, 18, // Skip to: 12728
/* 8092 */    MCD_OPC_CheckField, 19, 1, 0, 22, 18, // Skip to: 12728
/* 8098 */    MCD_OPC_Decode, 171, 5, 135, 1, // Opcode: INSERT_H
/* 8103 */    MCD_OPC_FilterValue, 19, 15, 0, // Skip to: 8122
/* 8107 */    MCD_OPC_CheckPredicate, 4, 9, 18, // Skip to: 12728
/* 8111 */    MCD_OPC_CheckField, 18, 2, 0, 3, 18, // Skip to: 12728
/* 8117 */    MCD_OPC_Decode, 172, 5, 136, 1, // Opcode: INSERT_W
/* 8122 */    MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 8135
/* 8126 */    MCD_OPC_CheckPredicate, 4, 246, 17, // Skip to: 12728
/* 8130 */    MCD_OPC_Decode, 174, 5, 137, 1, // Opcode: INSVE_B
/* 8135 */    MCD_OPC_FilterValue, 22, 15, 0, // Skip to: 8154
/* 8139 */    MCD_OPC_CheckPredicate, 4, 233, 17, // Skip to: 12728
/* 8143 */    MCD_OPC_CheckField, 19, 1, 0, 227, 17, // Skip to: 12728
/* 8149 */    MCD_OPC_Decode, 176, 5, 138, 1, // Opcode: INSVE_H
/* 8154 */    MCD_OPC_FilterValue, 23, 218, 17, // Skip to: 12728
/* 8158 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 8161 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8174
/* 8165 */    MCD_OPC_CheckPredicate, 4, 207, 17, // Skip to: 12728
/* 8169 */    MCD_OPC_Decode, 177, 5, 139, 1, // Opcode: INSVE_W
/* 8174 */    MCD_OPC_FilterValue, 2, 198, 17, // Skip to: 12728
/* 8178 */    MCD_OPC_CheckPredicate, 4, 194, 17, // Skip to: 12728
/* 8182 */    MCD_OPC_CheckField, 17, 1, 0, 188, 17, // Skip to: 12728
/* 8188 */    MCD_OPC_Decode, 175, 5, 140, 1, // Opcode: INSVE_D
/* 8193 */    MCD_OPC_FilterValue, 26, 131, 1, // Skip to: 8584
/* 8197 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 8200 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 8212
/* 8204 */    MCD_OPC_CheckPredicate, 4, 168, 17, // Skip to: 12728
/* 8208 */    MCD_OPC_Decode, 134, 4, 108, // Opcode: FCAF_W
/* 8212 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 8224
/* 8216 */    MCD_OPC_CheckPredicate, 4, 156, 17, // Skip to: 12728
/* 8220 */    MCD_OPC_Decode, 133, 4, 109, // Opcode: FCAF_D
/* 8224 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 8236
/* 8228 */    MCD_OPC_CheckPredicate, 4, 144, 17, // Skip to: 12728
/* 8232 */    MCD_OPC_Decode, 159, 4, 108, // Opcode: FCUN_W
/* 8236 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 8248
/* 8240 */    MCD_OPC_CheckPredicate, 4, 132, 17, // Skip to: 12728
/* 8244 */    MCD_OPC_Decode, 158, 4, 109, // Opcode: FCUN_D
/* 8248 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 8260
/* 8252 */    MCD_OPC_CheckPredicate, 4, 120, 17, // Skip to: 12728
/* 8256 */    MCD_OPC_Decode, 136, 4, 108, // Opcode: FCEQ_W
/* 8260 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 8272
/* 8264 */    MCD_OPC_CheckPredicate, 4, 108, 17, // Skip to: 12728
/* 8268 */    MCD_OPC_Decode, 135, 4, 109, // Opcode: FCEQ_D
/* 8272 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 8284
/* 8276 */    MCD_OPC_CheckPredicate, 4, 96, 17, // Skip to: 12728
/* 8280 */    MCD_OPC_Decode, 151, 4, 108, // Opcode: FCUEQ_W
/* 8284 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 8296
/* 8288 */    MCD_OPC_CheckPredicate, 4, 84, 17, // Skip to: 12728
/* 8292 */    MCD_OPC_Decode, 150, 4, 109, // Opcode: FCUEQ_D
/* 8296 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 8308
/* 8300 */    MCD_OPC_CheckPredicate, 4, 72, 17, // Skip to: 12728
/* 8304 */    MCD_OPC_Decode, 142, 4, 108, // Opcode: FCLT_W
/* 8308 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 8320
/* 8312 */    MCD_OPC_CheckPredicate, 4, 60, 17, // Skip to: 12728
/* 8316 */    MCD_OPC_Decode, 141, 4, 109, // Opcode: FCLT_D
/* 8320 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 8332
/* 8324 */    MCD_OPC_CheckPredicate, 4, 48, 17, // Skip to: 12728
/* 8328 */    MCD_OPC_Decode, 155, 4, 108, // Opcode: FCULT_W
/* 8332 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 8344
/* 8336 */    MCD_OPC_CheckPredicate, 4, 36, 17, // Skip to: 12728
/* 8340 */    MCD_OPC_Decode, 154, 4, 109, // Opcode: FCULT_D
/* 8344 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 8356
/* 8348 */    MCD_OPC_CheckPredicate, 4, 24, 17, // Skip to: 12728
/* 8352 */    MCD_OPC_Decode, 140, 4, 108, // Opcode: FCLE_W
/* 8356 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 8368
/* 8360 */    MCD_OPC_CheckPredicate, 4, 12, 17, // Skip to: 12728
/* 8364 */    MCD_OPC_Decode, 139, 4, 109, // Opcode: FCLE_D
/* 8368 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 8380
/* 8372 */    MCD_OPC_CheckPredicate, 4, 0, 17, // Skip to: 12728
/* 8376 */    MCD_OPC_Decode, 153, 4, 108, // Opcode: FCULE_W
/* 8380 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 8392
/* 8384 */    MCD_OPC_CheckPredicate, 4, 244, 16, // Skip to: 12728
/* 8388 */    MCD_OPC_Decode, 152, 4, 109, // Opcode: FCULE_D
/* 8392 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 8404
/* 8396 */    MCD_OPC_CheckPredicate, 4, 232, 16, // Skip to: 12728
/* 8400 */    MCD_OPC_Decode, 225, 4, 108, // Opcode: FSAF_W
/* 8404 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 8416
/* 8408 */    MCD_OPC_CheckPredicate, 4, 220, 16, // Skip to: 12728
/* 8412 */    MCD_OPC_Decode, 224, 4, 109, // Opcode: FSAF_D
/* 8416 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 8428
/* 8420 */    MCD_OPC_CheckPredicate, 4, 208, 16, // Skip to: 12728
/* 8424 */    MCD_OPC_Decode, 255, 4, 108, // Opcode: FSUN_W
/* 8428 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 8440
/* 8432 */    MCD_OPC_CheckPredicate, 4, 196, 16, // Skip to: 12728
/* 8436 */    MCD_OPC_Decode, 254, 4, 109, // Opcode: FSUN_D
/* 8440 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 8452
/* 8444 */    MCD_OPC_CheckPredicate, 4, 184, 16, // Skip to: 12728
/* 8448 */    MCD_OPC_Decode, 227, 4, 108, // Opcode: FSEQ_W
/* 8452 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 8464
/* 8456 */    MCD_OPC_CheckPredicate, 4, 172, 16, // Skip to: 12728
/* 8460 */    MCD_OPC_Decode, 226, 4, 109, // Opcode: FSEQ_D
/* 8464 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 8476
/* 8468 */    MCD_OPC_CheckPredicate, 4, 160, 16, // Skip to: 12728
/* 8472 */    MCD_OPC_Decode, 247, 4, 108, // Opcode: FSUEQ_W
/* 8476 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 8488
/* 8480 */    MCD_OPC_CheckPredicate, 4, 148, 16, // Skip to: 12728
/* 8484 */    MCD_OPC_Decode, 246, 4, 109, // Opcode: FSUEQ_D
/* 8488 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 8500
/* 8492 */    MCD_OPC_CheckPredicate, 4, 136, 16, // Skip to: 12728
/* 8496 */    MCD_OPC_Decode, 231, 4, 108, // Opcode: FSLT_W
/* 8500 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 8512
/* 8504 */    MCD_OPC_CheckPredicate, 4, 124, 16, // Skip to: 12728
/* 8508 */    MCD_OPC_Decode, 230, 4, 109, // Opcode: FSLT_D
/* 8512 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 8524
/* 8516 */    MCD_OPC_CheckPredicate, 4, 112, 16, // Skip to: 12728
/* 8520 */    MCD_OPC_Decode, 251, 4, 108, // Opcode: FSULT_W
/* 8524 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 8536
/* 8528 */    MCD_OPC_CheckPredicate, 4, 100, 16, // Skip to: 12728
/* 8532 */    MCD_OPC_Decode, 250, 4, 109, // Opcode: FSULT_D
/* 8536 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 8548
/* 8540 */    MCD_OPC_CheckPredicate, 4, 88, 16, // Skip to: 12728
/* 8544 */    MCD_OPC_Decode, 229, 4, 108, // Opcode: FSLE_W
/* 8548 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 8560
/* 8552 */    MCD_OPC_CheckPredicate, 4, 76, 16, // Skip to: 12728
/* 8556 */    MCD_OPC_Decode, 228, 4, 109, // Opcode: FSLE_D
/* 8560 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 8572
/* 8564 */    MCD_OPC_CheckPredicate, 4, 64, 16, // Skip to: 12728
/* 8568 */    MCD_OPC_Decode, 249, 4, 108, // Opcode: FSULE_W
/* 8572 */    MCD_OPC_FilterValue, 31, 56, 16, // Skip to: 12728
/* 8576 */    MCD_OPC_CheckPredicate, 4, 52, 16, // Skip to: 12728
/* 8580 */    MCD_OPC_Decode, 248, 4, 109, // Opcode: FSULE_D
/* 8584 */    MCD_OPC_FilterValue, 27, 63, 1, // Skip to: 8907
/* 8588 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 8591 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 8603
/* 8595 */    MCD_OPC_CheckPredicate, 4, 33, 16, // Skip to: 12728
/* 8599 */    MCD_OPC_Decode, 132, 4, 108, // Opcode: FADD_W
/* 8603 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 8615
/* 8607 */    MCD_OPC_CheckPredicate, 4, 21, 16, // Skip to: 12728
/* 8611 */    MCD_OPC_Decode, 128, 4, 109, // Opcode: FADD_D
/* 8615 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 8627
/* 8619 */    MCD_OPC_CheckPredicate, 4, 9, 16, // Skip to: 12728
/* 8623 */    MCD_OPC_Decode, 245, 4, 108, // Opcode: FSUB_W
/* 8627 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 8639
/* 8631 */    MCD_OPC_CheckPredicate, 4, 253, 15, // Skip to: 12728
/* 8635 */    MCD_OPC_Decode, 241, 4, 109, // Opcode: FSUB_D
/* 8639 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 8651
/* 8643 */    MCD_OPC_CheckPredicate, 4, 241, 15, // Skip to: 12728
/* 8647 */    MCD_OPC_Decode, 214, 4, 108, // Opcode: FMUL_W
/* 8651 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 8663
/* 8655 */    MCD_OPC_CheckPredicate, 4, 229, 15, // Skip to: 12728
/* 8659 */    MCD_OPC_Decode, 210, 4, 109, // Opcode: FMUL_D
/* 8663 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 8675
/* 8667 */    MCD_OPC_CheckPredicate, 4, 217, 15, // Skip to: 12728
/* 8671 */    MCD_OPC_Decode, 164, 4, 108, // Opcode: FDIV_W
/* 8675 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 8687
/* 8679 */    MCD_OPC_CheckPredicate, 4, 205, 15, // Skip to: 12728
/* 8683 */    MCD_OPC_Decode, 160, 4, 109, // Opcode: FDIV_D
/* 8687 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 8699
/* 8691 */    MCD_OPC_CheckPredicate, 4, 193, 15, // Skip to: 12728
/* 8695 */    MCD_OPC_Decode, 196, 4, 112, // Opcode: FMADD_W
/* 8699 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 8711
/* 8703 */    MCD_OPC_CheckPredicate, 4, 181, 15, // Skip to: 12728
/* 8707 */    MCD_OPC_Decode, 195, 4, 113, // Opcode: FMADD_D
/* 8711 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 8723
/* 8715 */    MCD_OPC_CheckPredicate, 4, 169, 15, // Skip to: 12728
/* 8719 */    MCD_OPC_Decode, 209, 4, 112, // Opcode: FMSUB_W
/* 8723 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 8735
/* 8727 */    MCD_OPC_CheckPredicate, 4, 157, 15, // Skip to: 12728
/* 8731 */    MCD_OPC_Decode, 208, 4, 113, // Opcode: FMSUB_D
/* 8735 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 8747
/* 8739 */    MCD_OPC_CheckPredicate, 4, 145, 15, // Skip to: 12728
/* 8743 */    MCD_OPC_Decode, 169, 4, 108, // Opcode: FEXP2_W
/* 8747 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 8759
/* 8751 */    MCD_OPC_CheckPredicate, 4, 133, 15, // Skip to: 12728
/* 8755 */    MCD_OPC_Decode, 167, 4, 109, // Opcode: FEXP2_D
/* 8759 */    MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 8772
/* 8763 */    MCD_OPC_CheckPredicate, 4, 121, 15, // Skip to: 12728
/* 8767 */    MCD_OPC_Decode, 165, 4, 141, 1, // Opcode: FEXDO_H
/* 8772 */    MCD_OPC_FilterValue, 17, 9, 0, // Skip to: 8785
/* 8776 */    MCD_OPC_CheckPredicate, 4, 108, 15, // Skip to: 12728
/* 8780 */    MCD_OPC_Decode, 166, 4, 142, 1, // Opcode: FEXDO_W
/* 8785 */    MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 8798
/* 8789 */    MCD_OPC_CheckPredicate, 4, 95, 15, // Skip to: 12728
/* 8793 */    MCD_OPC_Decode, 132, 5, 141, 1, // Opcode: FTQ_H
/* 8798 */    MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 8811
/* 8802 */    MCD_OPC_CheckPredicate, 4, 82, 15, // Skip to: 12728
/* 8806 */    MCD_OPC_Decode, 133, 5, 142, 1, // Opcode: FTQ_W
/* 8811 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 8823
/* 8815 */    MCD_OPC_CheckPredicate, 4, 69, 15, // Skip to: 12728
/* 8819 */    MCD_OPC_Decode, 204, 4, 108, // Opcode: FMIN_W
/* 8823 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 8835
/* 8827 */    MCD_OPC_CheckPredicate, 4, 57, 15, // Skip to: 12728
/* 8831 */    MCD_OPC_Decode, 203, 4, 109, // Opcode: FMIN_D
/* 8835 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 8847
/* 8839 */    MCD_OPC_CheckPredicate, 4, 45, 15, // Skip to: 12728
/* 8843 */    MCD_OPC_Decode, 202, 4, 108, // Opcode: FMIN_A_W
/* 8847 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 8859
/* 8851 */    MCD_OPC_CheckPredicate, 4, 33, 15, // Skip to: 12728
/* 8855 */    MCD_OPC_Decode, 201, 4, 109, // Opcode: FMIN_A_D
/* 8859 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 8871
/* 8863 */    MCD_OPC_CheckPredicate, 4, 21, 15, // Skip to: 12728
/* 8867 */    MCD_OPC_Decode, 200, 4, 108, // Opcode: FMAX_W
/* 8871 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 8883
/* 8875 */    MCD_OPC_CheckPredicate, 4, 9, 15, // Skip to: 12728
/* 8879 */    MCD_OPC_Decode, 199, 4, 109, // Opcode: FMAX_D
/* 8883 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 8895
/* 8887 */    MCD_OPC_CheckPredicate, 4, 253, 14, // Skip to: 12728
/* 8891 */    MCD_OPC_Decode, 198, 4, 108, // Opcode: FMAX_A_W
/* 8895 */    MCD_OPC_FilterValue, 31, 245, 14, // Skip to: 12728
/* 8899 */    MCD_OPC_CheckPredicate, 4, 241, 14, // Skip to: 12728
/* 8903 */    MCD_OPC_Decode, 197, 4, 109, // Opcode: FMAX_A_D
/* 8907 */    MCD_OPC_FilterValue, 28, 35, 1, // Skip to: 9202
/* 8911 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 8914 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 8926
/* 8918 */    MCD_OPC_CheckPredicate, 4, 222, 14, // Skip to: 12728
/* 8922 */    MCD_OPC_Decode, 149, 4, 108, // Opcode: FCOR_W
/* 8926 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 8938
/* 8930 */    MCD_OPC_CheckPredicate, 4, 210, 14, // Skip to: 12728
/* 8934 */    MCD_OPC_Decode, 148, 4, 109, // Opcode: FCOR_D
/* 8938 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 8950
/* 8942 */    MCD_OPC_CheckPredicate, 4, 198, 14, // Skip to: 12728
/* 8946 */    MCD_OPC_Decode, 157, 4, 108, // Opcode: FCUNE_W
/* 8950 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 8962
/* 8954 */    MCD_OPC_CheckPredicate, 4, 186, 14, // Skip to: 12728
/* 8958 */    MCD_OPC_Decode, 156, 4, 109, // Opcode: FCUNE_D
/* 8962 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 8974
/* 8966 */    MCD_OPC_CheckPredicate, 4, 174, 14, // Skip to: 12728
/* 8970 */    MCD_OPC_Decode, 147, 4, 108, // Opcode: FCNE_W
/* 8974 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 8986
/* 8978 */    MCD_OPC_CheckPredicate, 4, 162, 14, // Skip to: 12728
/* 8982 */    MCD_OPC_Decode, 146, 4, 109, // Opcode: FCNE_D
/* 8986 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 8998
/* 8990 */    MCD_OPC_CheckPredicate, 4, 150, 14, // Skip to: 12728
/* 8994 */    MCD_OPC_Decode, 186, 7, 107, // Opcode: MUL_Q_H
/* 8998 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 9010
/* 9002 */    MCD_OPC_CheckPredicate, 4, 138, 14, // Skip to: 12728
/* 9006 */    MCD_OPC_Decode, 187, 7, 108, // Opcode: MUL_Q_W
/* 9010 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 9022
/* 9014 */    MCD_OPC_CheckPredicate, 4, 126, 14, // Skip to: 12728
/* 9018 */    MCD_OPC_Decode, 156, 6, 111, // Opcode: MADD_Q_H
/* 9022 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 9034
/* 9026 */    MCD_OPC_CheckPredicate, 4, 114, 14, // Skip to: 12728
/* 9030 */    MCD_OPC_Decode, 157, 6, 112, // Opcode: MADD_Q_W
/* 9034 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 9046
/* 9038 */    MCD_OPC_CheckPredicate, 4, 102, 14, // Skip to: 12728
/* 9042 */    MCD_OPC_Decode, 145, 7, 111, // Opcode: MSUB_Q_H
/* 9046 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 9058
/* 9050 */    MCD_OPC_CheckPredicate, 4, 90, 14, // Skip to: 12728
/* 9054 */    MCD_OPC_Decode, 146, 7, 112, // Opcode: MSUB_Q_W
/* 9058 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 9070
/* 9062 */    MCD_OPC_CheckPredicate, 4, 78, 14, // Skip to: 12728
/* 9066 */    MCD_OPC_Decode, 235, 4, 108, // Opcode: FSOR_W
/* 9070 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 9082
/* 9074 */    MCD_OPC_CheckPredicate, 4, 66, 14, // Skip to: 12728
/* 9078 */    MCD_OPC_Decode, 234, 4, 109, // Opcode: FSOR_D
/* 9082 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 9094
/* 9086 */    MCD_OPC_CheckPredicate, 4, 54, 14, // Skip to: 12728
/* 9090 */    MCD_OPC_Decode, 253, 4, 108, // Opcode: FSUNE_W
/* 9094 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 9106
/* 9098 */    MCD_OPC_CheckPredicate, 4, 42, 14, // Skip to: 12728
/* 9102 */    MCD_OPC_Decode, 252, 4, 109, // Opcode: FSUNE_D
/* 9106 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 9118
/* 9110 */    MCD_OPC_CheckPredicate, 4, 30, 14, // Skip to: 12728
/* 9114 */    MCD_OPC_Decode, 233, 4, 108, // Opcode: FSNE_W
/* 9118 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 9130
/* 9122 */    MCD_OPC_CheckPredicate, 4, 18, 14, // Skip to: 12728
/* 9126 */    MCD_OPC_Decode, 232, 4, 109, // Opcode: FSNE_D
/* 9130 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 9142
/* 9134 */    MCD_OPC_CheckPredicate, 4, 6, 14, // Skip to: 12728
/* 9138 */    MCD_OPC_Decode, 170, 7, 107, // Opcode: MULR_Q_H
/* 9142 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 9154
/* 9146 */    MCD_OPC_CheckPredicate, 4, 250, 13, // Skip to: 12728
/* 9150 */    MCD_OPC_Decode, 171, 7, 108, // Opcode: MULR_Q_W
/* 9154 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 9166
/* 9158 */    MCD_OPC_CheckPredicate, 4, 238, 13, // Skip to: 12728
/* 9162 */    MCD_OPC_Decode, 143, 6, 111, // Opcode: MADDR_Q_H
/* 9166 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 9178
/* 9170 */    MCD_OPC_CheckPredicate, 4, 226, 13, // Skip to: 12728
/* 9174 */    MCD_OPC_Decode, 144, 6, 112, // Opcode: MADDR_Q_W
/* 9178 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 9190
/* 9182 */    MCD_OPC_CheckPredicate, 4, 214, 13, // Skip to: 12728
/* 9186 */    MCD_OPC_Decode, 132, 7, 111, // Opcode: MSUBR_Q_H
/* 9190 */    MCD_OPC_FilterValue, 29, 206, 13, // Skip to: 12728
/* 9194 */    MCD_OPC_CheckPredicate, 4, 202, 13, // Skip to: 12728
/* 9198 */    MCD_OPC_Decode, 133, 7, 112, // Opcode: MSUBR_Q_W
/* 9202 */    MCD_OPC_FilterValue, 30, 199, 2, // Skip to: 9917
/* 9206 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 9209 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 9220
/* 9213 */    MCD_OPC_CheckPredicate, 4, 183, 13, // Skip to: 12728
/* 9217 */    MCD_OPC_Decode, 75, 106, // Opcode: AND_V
/* 9220 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 9232
/* 9224 */    MCD_OPC_CheckPredicate, 4, 172, 13, // Skip to: 12728
/* 9228 */    MCD_OPC_Decode, 226, 7, 106, // Opcode: OR_V
/* 9232 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 9244
/* 9236 */    MCD_OPC_CheckPredicate, 4, 160, 13, // Skip to: 12728
/* 9240 */    MCD_OPC_Decode, 216, 7, 106, // Opcode: NOR_V
/* 9244 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 9256
/* 9248 */    MCD_OPC_CheckPredicate, 4, 148, 13, // Skip to: 12728
/* 9252 */    MCD_OPC_Decode, 241, 10, 106, // Opcode: XOR_V
/* 9256 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 9268
/* 9260 */    MCD_OPC_CheckPredicate, 4, 136, 13, // Skip to: 12728
/* 9264 */    MCD_OPC_Decode, 198, 1, 110, // Opcode: BMNZ_V
/* 9268 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 9280
/* 9272 */    MCD_OPC_CheckPredicate, 4, 124, 13, // Skip to: 12728
/* 9276 */    MCD_OPC_Decode, 200, 1, 110, // Opcode: BMZ_V
/* 9280 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 9292
/* 9284 */    MCD_OPC_CheckPredicate, 4, 112, 13, // Skip to: 12728
/* 9288 */    MCD_OPC_Decode, 225, 1, 110, // Opcode: BSEL_V
/* 9292 */    MCD_OPC_FilterValue, 24, 198, 0, // Skip to: 9494
/* 9296 */    MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 9299 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 9312
/* 9303 */    MCD_OPC_CheckPredicate, 4, 93, 13, // Skip to: 12728
/* 9307 */    MCD_OPC_Decode, 183, 4, 143, 1, // Opcode: FILL_B
/* 9312 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 9325
/* 9316 */    MCD_OPC_CheckPredicate, 4, 80, 13, // Skip to: 12728
/* 9320 */    MCD_OPC_Decode, 186, 4, 144, 1, // Opcode: FILL_H
/* 9325 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 9338
/* 9329 */    MCD_OPC_CheckPredicate, 4, 67, 13, // Skip to: 12728
/* 9333 */    MCD_OPC_Decode, 187, 4, 145, 1, // Opcode: FILL_W
/* 9338 */    MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 9351
/* 9342 */    MCD_OPC_CheckPredicate, 4, 54, 13, // Skip to: 12728
/* 9346 */    MCD_OPC_Decode, 243, 7, 133, 1, // Opcode: PCNT_B
/* 9351 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 9364
/* 9355 */    MCD_OPC_CheckPredicate, 4, 41, 13, // Skip to: 12728
/* 9359 */    MCD_OPC_Decode, 245, 7, 146, 1, // Opcode: PCNT_H
/* 9364 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 9377
/* 9368 */    MCD_OPC_CheckPredicate, 4, 28, 13, // Skip to: 12728
/* 9372 */    MCD_OPC_Decode, 246, 7, 147, 1, // Opcode: PCNT_W
/* 9377 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 9390
/* 9381 */    MCD_OPC_CheckPredicate, 4, 15, 13, // Skip to: 12728
/* 9385 */    MCD_OPC_Decode, 244, 7, 148, 1, // Opcode: PCNT_D
/* 9390 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 9403
/* 9394 */    MCD_OPC_CheckPredicate, 4, 2, 13, // Skip to: 12728
/* 9398 */    MCD_OPC_Decode, 197, 7, 133, 1, // Opcode: NLOC_B
/* 9403 */    MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 9416
/* 9407 */    MCD_OPC_CheckPredicate, 4, 245, 12, // Skip to: 12728
/* 9411 */    MCD_OPC_Decode, 199, 7, 146, 1, // Opcode: NLOC_H
/* 9416 */    MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 9429
/* 9420 */    MCD_OPC_CheckPredicate, 4, 232, 12, // Skip to: 12728
/* 9424 */    MCD_OPC_Decode, 200, 7, 147, 1, // Opcode: NLOC_W
/* 9429 */    MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 9442
/* 9433 */    MCD_OPC_CheckPredicate, 4, 219, 12, // Skip to: 12728
/* 9437 */    MCD_OPC_Decode, 198, 7, 148, 1, // Opcode: NLOC_D
/* 9442 */    MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 9455
/* 9446 */    MCD_OPC_CheckPredicate, 4, 206, 12, // Skip to: 12728
/* 9450 */    MCD_OPC_Decode, 201, 7, 133, 1, // Opcode: NLZC_B
/* 9455 */    MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 9468
/* 9459 */    MCD_OPC_CheckPredicate, 4, 193, 12, // Skip to: 12728
/* 9463 */    MCD_OPC_Decode, 203, 7, 146, 1, // Opcode: NLZC_H
/* 9468 */    MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 9481
/* 9472 */    MCD_OPC_CheckPredicate, 4, 180, 12, // Skip to: 12728
/* 9476 */    MCD_OPC_Decode, 204, 7, 147, 1, // Opcode: NLZC_W
/* 9481 */    MCD_OPC_FilterValue, 15, 171, 12, // Skip to: 12728
/* 9485 */    MCD_OPC_CheckPredicate, 4, 167, 12, // Skip to: 12728
/* 9489 */    MCD_OPC_Decode, 202, 7, 148, 1, // Opcode: NLZC_D
/* 9494 */    MCD_OPC_FilterValue, 25, 158, 12, // Skip to: 12728
/* 9498 */    MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 9501 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 9514
/* 9505 */    MCD_OPC_CheckPredicate, 4, 147, 12, // Skip to: 12728
/* 9509 */    MCD_OPC_Decode, 138, 4, 147, 1, // Opcode: FCLASS_W
/* 9514 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 9527
/* 9518 */    MCD_OPC_CheckPredicate, 4, 134, 12, // Skip to: 12728
/* 9522 */    MCD_OPC_Decode, 137, 4, 148, 1, // Opcode: FCLASS_D
/* 9527 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 9540
/* 9531 */    MCD_OPC_CheckPredicate, 4, 121, 12, // Skip to: 12728
/* 9535 */    MCD_OPC_Decode, 135, 5, 147, 1, // Opcode: FTRUNC_S_W
/* 9540 */    MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 9553
/* 9544 */    MCD_OPC_CheckPredicate, 4, 108, 12, // Skip to: 12728
/* 9548 */    MCD_OPC_Decode, 134, 5, 148, 1, // Opcode: FTRUNC_S_D
/* 9553 */    MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 9566
/* 9557 */    MCD_OPC_CheckPredicate, 4, 95, 12, // Skip to: 12728
/* 9561 */    MCD_OPC_Decode, 137, 5, 147, 1, // Opcode: FTRUNC_U_W
/* 9566 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 9579
/* 9570 */    MCD_OPC_CheckPredicate, 4, 82, 12, // Skip to: 12728
/* 9574 */    MCD_OPC_Decode, 136, 5, 148, 1, // Opcode: FTRUNC_U_D
/* 9579 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 9592
/* 9583 */    MCD_OPC_CheckPredicate, 4, 69, 12, // Skip to: 12728
/* 9587 */    MCD_OPC_Decode, 240, 4, 147, 1, // Opcode: FSQRT_W
/* 9592 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 9605
/* 9596 */    MCD_OPC_CheckPredicate, 4, 56, 12, // Skip to: 12728
/* 9600 */    MCD_OPC_Decode, 236, 4, 148, 1, // Opcode: FSQRT_D
/* 9605 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 9618
/* 9609 */    MCD_OPC_CheckPredicate, 4, 43, 12, // Skip to: 12728
/* 9613 */    MCD_OPC_Decode, 223, 4, 147, 1, // Opcode: FRSQRT_W
/* 9618 */    MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 9631
/* 9622 */    MCD_OPC_CheckPredicate, 4, 30, 12, // Skip to: 12728
/* 9626 */    MCD_OPC_Decode, 222, 4, 148, 1, // Opcode: FRSQRT_D
/* 9631 */    MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 9644
/* 9635 */    MCD_OPC_CheckPredicate, 4, 17, 12, // Skip to: 12728
/* 9639 */    MCD_OPC_Decode, 219, 4, 147, 1, // Opcode: FRCP_W
/* 9644 */    MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 9657
/* 9648 */    MCD_OPC_CheckPredicate, 4, 4, 12, // Skip to: 12728
/* 9652 */    MCD_OPC_Decode, 218, 4, 148, 1, // Opcode: FRCP_D
/* 9657 */    MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 9670
/* 9661 */    MCD_OPC_CheckPredicate, 4, 247, 11, // Skip to: 12728
/* 9665 */    MCD_OPC_Decode, 221, 4, 147, 1, // Opcode: FRINT_W
/* 9670 */    MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 9683
/* 9674 */    MCD_OPC_CheckPredicate, 4, 234, 11, // Skip to: 12728
/* 9678 */    MCD_OPC_Decode, 220, 4, 148, 1, // Opcode: FRINT_D
/* 9683 */    MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 9696
/* 9687 */    MCD_OPC_CheckPredicate, 4, 221, 11, // Skip to: 12728
/* 9691 */    MCD_OPC_Decode, 189, 4, 147, 1, // Opcode: FLOG2_W
/* 9696 */    MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 9709
/* 9700 */    MCD_OPC_CheckPredicate, 4, 208, 11, // Skip to: 12728
/* 9704 */    MCD_OPC_Decode, 188, 4, 148, 1, // Opcode: FLOG2_D
/* 9709 */    MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 9722
/* 9713 */    MCD_OPC_CheckPredicate, 4, 195, 11, // Skip to: 12728
/* 9717 */    MCD_OPC_Decode, 172, 4, 149, 1, // Opcode: FEXUPL_W
/* 9722 */    MCD_OPC_FilterValue, 17, 9, 0, // Skip to: 9735
/* 9726 */    MCD_OPC_CheckPredicate, 4, 182, 11, // Skip to: 12728
/* 9730 */    MCD_OPC_Decode, 171, 4, 150, 1, // Opcode: FEXUPL_D
/* 9735 */    MCD_OPC_FilterValue, 18, 9, 0, // Skip to: 9748
/* 9739 */    MCD_OPC_CheckPredicate, 4, 169, 11, // Skip to: 12728
/* 9743 */    MCD_OPC_Decode, 174, 4, 149, 1, // Opcode: FEXUPR_W
/* 9748 */    MCD_OPC_FilterValue, 19, 9, 0, // Skip to: 9761
/* 9752 */    MCD_OPC_CheckPredicate, 4, 156, 11, // Skip to: 12728
/* 9756 */    MCD_OPC_Decode, 173, 4, 150, 1, // Opcode: FEXUPR_D
/* 9761 */    MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 9774
/* 9765 */    MCD_OPC_CheckPredicate, 4, 143, 11, // Skip to: 12728
/* 9769 */    MCD_OPC_Decode, 180, 4, 149, 1, // Opcode: FFQL_W
/* 9774 */    MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 9787
/* 9778 */    MCD_OPC_CheckPredicate, 4, 130, 11, // Skip to: 12728
/* 9782 */    MCD_OPC_Decode, 179, 4, 150, 1, // Opcode: FFQL_D
/* 9787 */    MCD_OPC_FilterValue, 22, 9, 0, // Skip to: 9800
/* 9791 */    MCD_OPC_CheckPredicate, 4, 117, 11, // Skip to: 12728
/* 9795 */    MCD_OPC_Decode, 182, 4, 149, 1, // Opcode: FFQR_W
/* 9800 */    MCD_OPC_FilterValue, 23, 9, 0, // Skip to: 9813
/* 9804 */    MCD_OPC_CheckPredicate, 4, 104, 11, // Skip to: 12728
/* 9808 */    MCD_OPC_Decode, 181, 4, 150, 1, // Opcode: FFQR_D
/* 9813 */    MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 9826
/* 9817 */    MCD_OPC_CheckPredicate, 4, 91, 11, // Skip to: 12728
/* 9821 */    MCD_OPC_Decode, 129, 5, 147, 1, // Opcode: FTINT_S_W
/* 9826 */    MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 9839
/* 9830 */    MCD_OPC_CheckPredicate, 4, 78, 11, // Skip to: 12728
/* 9834 */    MCD_OPC_Decode, 128, 5, 148, 1, // Opcode: FTINT_S_D
/* 9839 */    MCD_OPC_FilterValue, 26, 9, 0, // Skip to: 9852
/* 9843 */    MCD_OPC_CheckPredicate, 4, 65, 11, // Skip to: 12728
/* 9847 */    MCD_OPC_Decode, 131, 5, 147, 1, // Opcode: FTINT_U_W
/* 9852 */    MCD_OPC_FilterValue, 27, 9, 0, // Skip to: 9865
/* 9856 */    MCD_OPC_CheckPredicate, 4, 52, 11, // Skip to: 12728
/* 9860 */    MCD_OPC_Decode, 130, 5, 148, 1, // Opcode: FTINT_U_D
/* 9865 */    MCD_OPC_FilterValue, 28, 9, 0, // Skip to: 9878
/* 9869 */    MCD_OPC_CheckPredicate, 4, 39, 11, // Skip to: 12728
/* 9873 */    MCD_OPC_Decode, 176, 4, 147, 1, // Opcode: FFINT_S_W
/* 9878 */    MCD_OPC_FilterValue, 29, 9, 0, // Skip to: 9891
/* 9882 */    MCD_OPC_CheckPredicate, 4, 26, 11, // Skip to: 12728
/* 9886 */    MCD_OPC_Decode, 175, 4, 148, 1, // Opcode: FFINT_S_D
/* 9891 */    MCD_OPC_FilterValue, 30, 9, 0, // Skip to: 9904
/* 9895 */    MCD_OPC_CheckPredicate, 4, 13, 11, // Skip to: 12728
/* 9899 */    MCD_OPC_Decode, 178, 4, 147, 1, // Opcode: FFINT_U_W
/* 9904 */    MCD_OPC_FilterValue, 31, 4, 11, // Skip to: 12728
/* 9908 */    MCD_OPC_CheckPredicate, 4, 0, 11, // Skip to: 12728
/* 9912 */    MCD_OPC_Decode, 177, 4, 148, 1, // Opcode: FFINT_U_D
/* 9917 */    MCD_OPC_FilterValue, 32, 9, 0, // Skip to: 9930
/* 9921 */    MCD_OPC_CheckPredicate, 4, 243, 10, // Skip to: 12728
/* 9925 */    MCD_OPC_Decode, 216, 5, 151, 1, // Opcode: LD_B
/* 9930 */    MCD_OPC_FilterValue, 33, 9, 0, // Skip to: 9943
/* 9934 */    MCD_OPC_CheckPredicate, 4, 230, 10, // Skip to: 12728
/* 9938 */    MCD_OPC_Decode, 218, 5, 151, 1, // Opcode: LD_H
/* 9943 */    MCD_OPC_FilterValue, 34, 9, 0, // Skip to: 9956
/* 9947 */    MCD_OPC_CheckPredicate, 4, 217, 10, // Skip to: 12728
/* 9951 */    MCD_OPC_Decode, 219, 5, 151, 1, // Opcode: LD_W
/* 9956 */    MCD_OPC_FilterValue, 35, 9, 0, // Skip to: 9969
/* 9960 */    MCD_OPC_CheckPredicate, 4, 204, 10, // Skip to: 12728
/* 9964 */    MCD_OPC_Decode, 217, 5, 151, 1, // Opcode: LD_D
/* 9969 */    MCD_OPC_FilterValue, 36, 9, 0, // Skip to: 9982
/* 9973 */    MCD_OPC_CheckPredicate, 4, 191, 10, // Skip to: 12728
/* 9977 */    MCD_OPC_Decode, 216, 9, 151, 1, // Opcode: ST_B
/* 9982 */    MCD_OPC_FilterValue, 37, 9, 0, // Skip to: 9995
/* 9986 */    MCD_OPC_CheckPredicate, 4, 178, 10, // Skip to: 12728
/* 9990 */    MCD_OPC_Decode, 218, 9, 151, 1, // Opcode: ST_H
/* 9995 */    MCD_OPC_FilterValue, 38, 9, 0, // Skip to: 10008
/* 9999 */    MCD_OPC_CheckPredicate, 4, 165, 10, // Skip to: 12728
/* 10003 */   MCD_OPC_Decode, 219, 9, 151, 1, // Opcode: ST_W
/* 10008 */   MCD_OPC_FilterValue, 39, 156, 10, // Skip to: 12728
/* 10012 */   MCD_OPC_CheckPredicate, 4, 152, 10, // Skip to: 12728
/* 10016 */   MCD_OPC_Decode, 217, 9, 151, 1, // Opcode: ST_D
/* 10021 */   MCD_OPC_FilterValue, 31, 113, 9, // Skip to: 12442
/* 10025 */   MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10028 */   MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 10041
/* 10032 */   MCD_OPC_CheckPredicate, 3, 132, 10, // Skip to: 12728
/* 10036 */   MCD_OPC_Decode, 235, 3, 152, 1, // Opcode: EXT
/* 10041 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 10054
/* 10045 */   MCD_OPC_CheckPredicate, 3, 119, 10, // Skip to: 12728
/* 10049 */   MCD_OPC_Decode, 167, 5, 153, 1, // Opcode: INS
/* 10054 */   MCD_OPC_FilterValue, 10, 42, 0, // Skip to: 10100
/* 10058 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 10061 */   MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 10074
/* 10065 */   MCD_OPC_CheckPredicate, 5, 99, 10, // Skip to: 12728
/* 10069 */   MCD_OPC_Decode, 251, 5, 154, 1, // Opcode: LWX
/* 10074 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 10087
/* 10078 */   MCD_OPC_CheckPredicate, 5, 86, 10, // Skip to: 12728
/* 10082 */   MCD_OPC_Decode, 224, 5, 154, 1, // Opcode: LHX
/* 10087 */   MCD_OPC_FilterValue, 6, 77, 10, // Skip to: 12728
/* 10091 */   MCD_OPC_CheckPredicate, 5, 73, 10, // Skip to: 12728
/* 10095 */   MCD_OPC_Decode, 199, 5, 154, 1, // Opcode: LBUX
/* 10100 */   MCD_OPC_FilterValue, 12, 15, 0, // Skip to: 10119
/* 10104 */   MCD_OPC_CheckPredicate, 5, 60, 10, // Skip to: 12728
/* 10108 */   MCD_OPC_CheckField, 6, 10, 0, 54, 10, // Skip to: 12728
/* 10114 */   MCD_OPC_Decode, 173, 5, 155, 1, // Opcode: INSV
/* 10119 */   MCD_OPC_FilterValue, 16, 51, 1, // Skip to: 10430
/* 10123 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 10126 */   MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 10138
/* 10130 */   MCD_OPC_CheckPredicate, 5, 34, 10, // Skip to: 12728
/* 10134 */   MCD_OPC_Decode, 46, 156, 1, // Opcode: ADDU_QB
/* 10138 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 10151
/* 10142 */   MCD_OPC_CheckPredicate, 5, 22, 10, // Skip to: 12728
/* 10146 */   MCD_OPC_Decode, 247, 9, 156, 1, // Opcode: SUBU_QB
/* 10151 */   MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 10163
/* 10155 */   MCD_OPC_CheckPredicate, 5, 9, 10, // Skip to: 12728
/* 10159 */   MCD_OPC_Decode, 48, 156, 1, // Opcode: ADDU_S_QB
/* 10163 */   MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 10176
/* 10167 */   MCD_OPC_CheckPredicate, 5, 253, 9, // Skip to: 12728
/* 10171 */   MCD_OPC_Decode, 249, 9, 156, 1, // Opcode: SUBU_S_QB
/* 10176 */   MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 10189
/* 10180 */   MCD_OPC_CheckPredicate, 5, 240, 9, // Skip to: 12728
/* 10184 */   MCD_OPC_Decode, 164, 7, 156, 1, // Opcode: MULEU_S_PH_QBL
/* 10189 */   MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 10202
/* 10193 */   MCD_OPC_CheckPredicate, 5, 227, 9, // Skip to: 12728
/* 10197 */   MCD_OPC_Decode, 165, 7, 156, 1, // Opcode: MULEU_S_PH_QBR
/* 10202 */   MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 10214
/* 10206 */   MCD_OPC_CheckPredicate, 14, 214, 9, // Skip to: 12728
/* 10210 */   MCD_OPC_Decode, 45, 156, 1, // Opcode: ADDU_PH
/* 10214 */   MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 10227
/* 10218 */   MCD_OPC_CheckPredicate, 14, 202, 9, // Skip to: 12728
/* 10222 */   MCD_OPC_Decode, 246, 9, 156, 1, // Opcode: SUBU_PH
/* 10227 */   MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 10239
/* 10231 */   MCD_OPC_CheckPredicate, 5, 189, 9, // Skip to: 12728
/* 10235 */   MCD_OPC_Decode, 27, 156, 1, // Opcode: ADDQ_PH
/* 10239 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 10252
/* 10243 */   MCD_OPC_CheckPredicate, 5, 177, 9, // Skip to: 12728
/* 10247 */   MCD_OPC_Decode, 225, 9, 156, 1, // Opcode: SUBQ_PH
/* 10252 */   MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 10264
/* 10256 */   MCD_OPC_CheckPredicate, 14, 164, 9, // Skip to: 12728
/* 10260 */   MCD_OPC_Decode, 47, 156, 1, // Opcode: ADDU_S_PH
/* 10264 */   MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 10277
/* 10268 */   MCD_OPC_CheckPredicate, 14, 152, 9, // Skip to: 12728
/* 10272 */   MCD_OPC_Decode, 248, 9, 156, 1, // Opcode: SUBU_S_PH
/* 10277 */   MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 10289
/* 10281 */   MCD_OPC_CheckPredicate, 5, 139, 9, // Skip to: 12728
/* 10285 */   MCD_OPC_Decode, 28, 156, 1, // Opcode: ADDQ_S_PH
/* 10289 */   MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 10302
/* 10293 */   MCD_OPC_CheckPredicate, 5, 127, 9, // Skip to: 12728
/* 10297 */   MCD_OPC_Decode, 226, 9, 156, 1, // Opcode: SUBQ_S_PH
/* 10302 */   MCD_OPC_FilterValue, 16, 7, 0, // Skip to: 10313
/* 10306 */   MCD_OPC_CheckPredicate, 5, 114, 9, // Skip to: 12728
/* 10310 */   MCD_OPC_Decode, 30, 12, // Opcode: ADDSC
/* 10313 */   MCD_OPC_FilterValue, 17, 7, 0, // Skip to: 10324
/* 10317 */   MCD_OPC_CheckPredicate, 5, 103, 9, // Skip to: 12728
/* 10321 */   MCD_OPC_Decode, 57, 12, // Opcode: ADDWC
/* 10324 */   MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 10336
/* 10328 */   MCD_OPC_CheckPredicate, 5, 92, 9, // Skip to: 12728
/* 10332 */   MCD_OPC_Decode, 217, 6, 12, // Opcode: MODSUB
/* 10336 */   MCD_OPC_FilterValue, 20, 15, 0, // Skip to: 10355
/* 10340 */   MCD_OPC_CheckPredicate, 5, 80, 9, // Skip to: 12728
/* 10344 */   MCD_OPC_CheckField, 16, 5, 0, 74, 9, // Skip to: 12728
/* 10350 */   MCD_OPC_Decode, 171, 8, 157, 1, // Opcode: RADDU_W_QB
/* 10355 */   MCD_OPC_FilterValue, 22, 7, 0, // Skip to: 10366
/* 10359 */   MCD_OPC_CheckPredicate, 5, 61, 9, // Skip to: 12728
/* 10363 */   MCD_OPC_Decode, 29, 12, // Opcode: ADDQ_S_W
/* 10366 */   MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 10378
/* 10370 */   MCD_OPC_CheckPredicate, 5, 50, 9, // Skip to: 12728
/* 10374 */   MCD_OPC_Decode, 227, 9, 12, // Opcode: SUBQ_S_W
/* 10378 */   MCD_OPC_FilterValue, 28, 9, 0, // Skip to: 10391
/* 10382 */   MCD_OPC_CheckPredicate, 5, 38, 9, // Skip to: 12728
/* 10386 */   MCD_OPC_Decode, 162, 7, 158, 1, // Opcode: MULEQ_S_W_PHL
/* 10391 */   MCD_OPC_FilterValue, 29, 9, 0, // Skip to: 10404
/* 10395 */   MCD_OPC_CheckPredicate, 5, 25, 9, // Skip to: 12728
/* 10399 */   MCD_OPC_Decode, 163, 7, 158, 1, // Opcode: MULEQ_S_W_PHR
/* 10404 */   MCD_OPC_FilterValue, 30, 9, 0, // Skip to: 10417
/* 10408 */   MCD_OPC_CheckPredicate, 14, 12, 9, // Skip to: 12728
/* 10412 */   MCD_OPC_Decode, 168, 7, 156, 1, // Opcode: MULQ_S_PH
/* 10417 */   MCD_OPC_FilterValue, 31, 3, 9, // Skip to: 12728
/* 10421 */   MCD_OPC_CheckPredicate, 5, 255, 8, // Skip to: 12728
/* 10425 */   MCD_OPC_Decode, 166, 7, 156, 1, // Opcode: MULQ_RS_PH
/* 10430 */   MCD_OPC_FilterValue, 17, 69, 1, // Skip to: 10759
/* 10434 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 10437 */   MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 10456
/* 10441 */   MCD_OPC_CheckPredicate, 5, 235, 8, // Skip to: 12728
/* 10445 */   MCD_OPC_CheckField, 11, 5, 0, 229, 8, // Skip to: 12728
/* 10451 */   MCD_OPC_Decode, 194, 2, 159, 1, // Opcode: CMPU_EQ_QB
/* 10456 */   MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 10475
/* 10460 */   MCD_OPC_CheckPredicate, 5, 216, 8, // Skip to: 12728
/* 10464 */   MCD_OPC_CheckField, 11, 5, 0, 210, 8, // Skip to: 12728
/* 10470 */   MCD_OPC_Decode, 196, 2, 159, 1, // Opcode: CMPU_LT_QB
/* 10475 */   MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 10494
/* 10479 */   MCD_OPC_CheckPredicate, 5, 197, 8, // Skip to: 12728
/* 10483 */   MCD_OPC_CheckField, 11, 5, 0, 191, 8, // Skip to: 12728
/* 10489 */   MCD_OPC_Decode, 195, 2, 159, 1, // Opcode: CMPU_LE_QB
/* 10494 */   MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 10507
/* 10498 */   MCD_OPC_CheckPredicate, 5, 178, 8, // Skip to: 12728
/* 10502 */   MCD_OPC_Decode, 248, 7, 156, 1, // Opcode: PICK_QB
/* 10507 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 10520
/* 10511 */   MCD_OPC_CheckPredicate, 5, 165, 8, // Skip to: 12728
/* 10515 */   MCD_OPC_Decode, 191, 2, 158, 1, // Opcode: CMPGU_EQ_QB
/* 10520 */   MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 10533
/* 10524 */   MCD_OPC_CheckPredicate, 5, 152, 8, // Skip to: 12728
/* 10528 */   MCD_OPC_Decode, 193, 2, 158, 1, // Opcode: CMPGU_LT_QB
/* 10533 */   MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 10546
/* 10537 */   MCD_OPC_CheckPredicate, 5, 139, 8, // Skip to: 12728
/* 10541 */   MCD_OPC_Decode, 192, 2, 158, 1, // Opcode: CMPGU_LE_QB
/* 10546 */   MCD_OPC_FilterValue, 8, 15, 0, // Skip to: 10565
/* 10550 */   MCD_OPC_CheckPredicate, 5, 126, 8, // Skip to: 12728
/* 10554 */   MCD_OPC_CheckField, 11, 5, 0, 120, 8, // Skip to: 12728
/* 10560 */   MCD_OPC_Decode, 197, 2, 159, 1, // Opcode: CMP_EQ_PH
/* 10565 */   MCD_OPC_FilterValue, 9, 15, 0, // Skip to: 10584
/* 10569 */   MCD_OPC_CheckPredicate, 5, 107, 8, // Skip to: 12728
/* 10573 */   MCD_OPC_CheckField, 11, 5, 0, 101, 8, // Skip to: 12728
/* 10579 */   MCD_OPC_Decode, 199, 2, 159, 1, // Opcode: CMP_LT_PH
/* 10584 */   MCD_OPC_FilterValue, 10, 15, 0, // Skip to: 10603
/* 10588 */   MCD_OPC_CheckPredicate, 5, 88, 8, // Skip to: 12728
/* 10592 */   MCD_OPC_CheckField, 11, 5, 0, 82, 8, // Skip to: 12728
/* 10598 */   MCD_OPC_Decode, 198, 2, 159, 1, // Opcode: CMP_LE_PH
/* 10603 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 10616
/* 10607 */   MCD_OPC_CheckPredicate, 5, 69, 8, // Skip to: 12728
/* 10611 */   MCD_OPC_Decode, 247, 7, 156, 1, // Opcode: PICK_PH
/* 10616 */   MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 10629
/* 10620 */   MCD_OPC_CheckPredicate, 5, 56, 8, // Skip to: 12728
/* 10624 */   MCD_OPC_Decode, 133, 8, 156, 1, // Opcode: PRECRQ_QB_PH
/* 10629 */   MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 10642
/* 10633 */   MCD_OPC_CheckPredicate, 14, 43, 8, // Skip to: 12728
/* 10637 */   MCD_OPC_Decode, 135, 8, 156, 1, // Opcode: PRECR_QB_PH
/* 10642 */   MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 10655
/* 10646 */   MCD_OPC_CheckPredicate, 5, 30, 8, // Skip to: 12728
/* 10650 */   MCD_OPC_Decode, 234, 7, 156, 1, // Opcode: PACKRL_PH
/* 10655 */   MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 10668
/* 10659 */   MCD_OPC_CheckPredicate, 5, 17, 8, // Skip to: 12728
/* 10663 */   MCD_OPC_Decode, 131, 8, 156, 1, // Opcode: PRECRQU_S_QB_PH
/* 10668 */   MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 10681
/* 10672 */   MCD_OPC_CheckPredicate, 5, 4, 8, // Skip to: 12728
/* 10676 */   MCD_OPC_Decode, 132, 8, 160, 1, // Opcode: PRECRQ_PH_W
/* 10681 */   MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 10694
/* 10685 */   MCD_OPC_CheckPredicate, 5, 247, 7, // Skip to: 12728
/* 10689 */   MCD_OPC_Decode, 134, 8, 160, 1, // Opcode: PRECRQ_RS_PH_W
/* 10694 */   MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 10707
/* 10698 */   MCD_OPC_CheckPredicate, 14, 234, 7, // Skip to: 12728
/* 10702 */   MCD_OPC_Decode, 188, 2, 158, 1, // Opcode: CMPGDU_EQ_QB
/* 10707 */   MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 10720
/* 10711 */   MCD_OPC_CheckPredicate, 14, 221, 7, // Skip to: 12728
/* 10715 */   MCD_OPC_Decode, 190, 2, 158, 1, // Opcode: CMPGDU_LT_QB
/* 10720 */   MCD_OPC_FilterValue, 26, 9, 0, // Skip to: 10733
/* 10724 */   MCD_OPC_CheckPredicate, 14, 208, 7, // Skip to: 12728
/* 10728 */   MCD_OPC_Decode, 189, 2, 158, 1, // Opcode: CMPGDU_LE_QB
/* 10733 */   MCD_OPC_FilterValue, 30, 9, 0, // Skip to: 10746
/* 10737 */   MCD_OPC_CheckPredicate, 14, 195, 7, // Skip to: 12728
/* 10741 */   MCD_OPC_Decode, 136, 8, 161, 1, // Opcode: PRECR_SRA_PH_W
/* 10746 */   MCD_OPC_FilterValue, 31, 186, 7, // Skip to: 12728
/* 10750 */   MCD_OPC_CheckPredicate, 14, 182, 7, // Skip to: 12728
/* 10754 */   MCD_OPC_Decode, 137, 8, 161, 1, // Opcode: PRECR_SRA_R_PH_W
/* 10759 */   MCD_OPC_FilterValue, 18, 74, 1, // Skip to: 11093
/* 10763 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 10766 */   MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 10784
/* 10770 */   MCD_OPC_CheckPredicate, 14, 162, 7, // Skip to: 12728
/* 10774 */   MCD_OPC_CheckField, 21, 5, 0, 156, 7, // Skip to: 12728
/* 10780 */   MCD_OPC_Decode, 20, 162, 1, // Opcode: ABSQ_S_QB
/* 10784 */   MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 10797
/* 10788 */   MCD_OPC_CheckPredicate, 5, 144, 7, // Skip to: 12728
/* 10792 */   MCD_OPC_Decode, 178, 8, 163, 1, // Opcode: REPL_QB
/* 10797 */   MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 10816
/* 10801 */   MCD_OPC_CheckPredicate, 5, 131, 7, // Skip to: 12728
/* 10805 */   MCD_OPC_CheckField, 21, 5, 0, 125, 7, // Skip to: 12728
/* 10811 */   MCD_OPC_Decode, 176, 8, 164, 1, // Opcode: REPLV_QB
/* 10816 */   MCD_OPC_FilterValue, 4, 15, 0, // Skip to: 10835
/* 10820 */   MCD_OPC_CheckPredicate, 5, 112, 7, // Skip to: 12728
/* 10824 */   MCD_OPC_CheckField, 21, 5, 0, 106, 7, // Skip to: 12728
/* 10830 */   MCD_OPC_Decode, 249, 7, 162, 1, // Opcode: PRECEQU_PH_QBL
/* 10835 */   MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 10854
/* 10839 */   MCD_OPC_CheckPredicate, 5, 93, 7, // Skip to: 12728
/* 10843 */   MCD_OPC_CheckField, 21, 5, 0, 87, 7, // Skip to: 12728
/* 10849 */   MCD_OPC_Decode, 251, 7, 162, 1, // Opcode: PRECEQU_PH_QBR
/* 10854 */   MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 10873
/* 10858 */   MCD_OPC_CheckPredicate, 5, 74, 7, // Skip to: 12728
/* 10862 */   MCD_OPC_CheckField, 21, 5, 0, 68, 7, // Skip to: 12728
/* 10868 */   MCD_OPC_Decode, 250, 7, 162, 1, // Opcode: PRECEQU_PH_QBLA
/* 10873 */   MCD_OPC_FilterValue, 7, 15, 0, // Skip to: 10892
/* 10877 */   MCD_OPC_CheckPredicate, 5, 55, 7, // Skip to: 12728
/* 10881 */   MCD_OPC_CheckField, 21, 5, 0, 49, 7, // Skip to: 12728
/* 10887 */   MCD_OPC_Decode, 252, 7, 162, 1, // Opcode: PRECEQU_PH_QBRA
/* 10892 */   MCD_OPC_FilterValue, 9, 14, 0, // Skip to: 10910
/* 10896 */   MCD_OPC_CheckPredicate, 5, 36, 7, // Skip to: 12728
/* 10900 */   MCD_OPC_CheckField, 21, 5, 0, 30, 7, // Skip to: 12728
/* 10906 */   MCD_OPC_Decode, 19, 162, 1, // Opcode: ABSQ_S_PH
/* 10910 */   MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 10923
/* 10914 */   MCD_OPC_CheckPredicate, 5, 18, 7, // Skip to: 12728
/* 10918 */   MCD_OPC_Decode, 177, 8, 163, 1, // Opcode: REPL_PH
/* 10923 */   MCD_OPC_FilterValue, 11, 15, 0, // Skip to: 10942
/* 10927 */   MCD_OPC_CheckPredicate, 5, 5, 7, // Skip to: 12728
/* 10931 */   MCD_OPC_CheckField, 21, 5, 0, 255, 6, // Skip to: 12728
/* 10937 */   MCD_OPC_Decode, 175, 8, 164, 1, // Opcode: REPLV_PH
/* 10942 */   MCD_OPC_FilterValue, 12, 15, 0, // Skip to: 10961
/* 10946 */   MCD_OPC_CheckPredicate, 5, 242, 6, // Skip to: 12728
/* 10950 */   MCD_OPC_CheckField, 21, 5, 0, 236, 6, // Skip to: 12728
/* 10956 */   MCD_OPC_Decode, 253, 7, 165, 1, // Opcode: PRECEQ_W_PHL
/* 10961 */   MCD_OPC_FilterValue, 13, 15, 0, // Skip to: 10980
/* 10965 */   MCD_OPC_CheckPredicate, 5, 223, 6, // Skip to: 12728
/* 10969 */   MCD_OPC_CheckField, 21, 5, 0, 217, 6, // Skip to: 12728
/* 10975 */   MCD_OPC_Decode, 254, 7, 165, 1, // Opcode: PRECEQ_W_PHR
/* 10980 */   MCD_OPC_FilterValue, 17, 14, 0, // Skip to: 10998
/* 10984 */   MCD_OPC_CheckPredicate, 5, 204, 6, // Skip to: 12728
/* 10988 */   MCD_OPC_CheckField, 21, 5, 0, 198, 6, // Skip to: 12728
/* 10994 */   MCD_OPC_Decode, 21, 166, 1, // Opcode: ABSQ_S_W
/* 10998 */   MCD_OPC_FilterValue, 27, 15, 0, // Skip to: 11017
/* 11002 */   MCD_OPC_CheckPredicate, 5, 186, 6, // Skip to: 12728
/* 11006 */   MCD_OPC_CheckField, 21, 5, 0, 180, 6, // Skip to: 12728
/* 11012 */   MCD_OPC_Decode, 188, 1, 166, 1, // Opcode: BITREV
/* 11017 */   MCD_OPC_FilterValue, 28, 15, 0, // Skip to: 11036
/* 11021 */   MCD_OPC_CheckPredicate, 5, 167, 6, // Skip to: 12728
/* 11025 */   MCD_OPC_CheckField, 21, 5, 0, 161, 6, // Skip to: 12728
/* 11031 */   MCD_OPC_Decode, 255, 7, 162, 1, // Opcode: PRECEU_PH_QBL
/* 11036 */   MCD_OPC_FilterValue, 29, 15, 0, // Skip to: 11055
/* 11040 */   MCD_OPC_CheckPredicate, 5, 148, 6, // Skip to: 12728
/* 11044 */   MCD_OPC_CheckField, 21, 5, 0, 142, 6, // Skip to: 12728
/* 11050 */   MCD_OPC_Decode, 129, 8, 162, 1, // Opcode: PRECEU_PH_QBR
/* 11055 */   MCD_OPC_FilterValue, 30, 15, 0, // Skip to: 11074
/* 11059 */   MCD_OPC_CheckPredicate, 5, 129, 6, // Skip to: 12728
/* 11063 */   MCD_OPC_CheckField, 21, 5, 0, 123, 6, // Skip to: 12728
/* 11069 */   MCD_OPC_Decode, 128, 8, 162, 1, // Opcode: PRECEU_PH_QBLA
/* 11074 */   MCD_OPC_FilterValue, 31, 114, 6, // Skip to: 12728
/* 11078 */   MCD_OPC_CheckPredicate, 5, 110, 6, // Skip to: 12728
/* 11082 */   MCD_OPC_CheckField, 21, 5, 0, 104, 6, // Skip to: 12728
/* 11088 */   MCD_OPC_Decode, 130, 8, 162, 1, // Opcode: PRECEU_PH_QBRA
/* 11093 */   MCD_OPC_FilterValue, 19, 31, 1, // Skip to: 11384
/* 11097 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11100 */   MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 11113
/* 11104 */   MCD_OPC_CheckPredicate, 5, 84, 6, // Skip to: 12728
/* 11108 */   MCD_OPC_Decode, 235, 8, 167, 1, // Opcode: SHLL_QB
/* 11113 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 11126
/* 11117 */   MCD_OPC_CheckPredicate, 5, 71, 6, // Skip to: 12728
/* 11121 */   MCD_OPC_Decode, 251, 8, 167, 1, // Opcode: SHRL_QB
/* 11126 */   MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 11139
/* 11130 */   MCD_OPC_CheckPredicate, 5, 58, 6, // Skip to: 12728
/* 11134 */   MCD_OPC_Decode, 231, 8, 168, 1, // Opcode: SHLLV_QB
/* 11139 */   MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 11152
/* 11143 */   MCD_OPC_CheckPredicate, 5, 45, 6, // Skip to: 12728
/* 11147 */   MCD_OPC_Decode, 249, 8, 168, 1, // Opcode: SHRLV_QB
/* 11152 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 11165
/* 11156 */   MCD_OPC_CheckPredicate, 14, 32, 6, // Skip to: 12728
/* 11160 */   MCD_OPC_Decode, 244, 8, 167, 1, // Opcode: SHRA_QB
/* 11165 */   MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 11178
/* 11169 */   MCD_OPC_CheckPredicate, 14, 19, 6, // Skip to: 12728
/* 11173 */   MCD_OPC_Decode, 246, 8, 167, 1, // Opcode: SHRA_R_QB
/* 11178 */   MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 11191
/* 11182 */   MCD_OPC_CheckPredicate, 14, 6, 6, // Skip to: 12728
/* 11186 */   MCD_OPC_Decode, 239, 8, 168, 1, // Opcode: SHRAV_QB
/* 11191 */   MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 11204
/* 11195 */   MCD_OPC_CheckPredicate, 14, 249, 5, // Skip to: 12728
/* 11199 */   MCD_OPC_Decode, 241, 8, 168, 1, // Opcode: SHRAV_R_QB
/* 11204 */   MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 11217
/* 11208 */   MCD_OPC_CheckPredicate, 5, 236, 5, // Skip to: 12728
/* 11212 */   MCD_OPC_Decode, 234, 8, 167, 1, // Opcode: SHLL_PH
/* 11217 */   MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 11230
/* 11221 */   MCD_OPC_CheckPredicate, 5, 223, 5, // Skip to: 12728
/* 11225 */   MCD_OPC_Decode, 243, 8, 167, 1, // Opcode: SHRA_PH
/* 11230 */   MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 11243
/* 11234 */   MCD_OPC_CheckPredicate, 5, 210, 5, // Skip to: 12728
/* 11238 */   MCD_OPC_Decode, 230, 8, 168, 1, // Opcode: SHLLV_PH
/* 11243 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 11256
/* 11247 */   MCD_OPC_CheckPredicate, 5, 197, 5, // Skip to: 12728
/* 11251 */   MCD_OPC_Decode, 238, 8, 168, 1, // Opcode: SHRAV_PH
/* 11256 */   MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 11269
/* 11260 */   MCD_OPC_CheckPredicate, 5, 184, 5, // Skip to: 12728
/* 11264 */   MCD_OPC_Decode, 236, 8, 167, 1, // Opcode: SHLL_S_PH
/* 11269 */   MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 11282
/* 11273 */   MCD_OPC_CheckPredicate, 5, 171, 5, // Skip to: 12728
/* 11277 */   MCD_OPC_Decode, 245, 8, 167, 1, // Opcode: SHRA_R_PH
/* 11282 */   MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 11295
/* 11286 */   MCD_OPC_CheckPredicate, 5, 158, 5, // Skip to: 12728
/* 11290 */   MCD_OPC_Decode, 232, 8, 168, 1, // Opcode: SHLLV_S_PH
/* 11295 */   MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 11308
/* 11299 */   MCD_OPC_CheckPredicate, 5, 145, 5, // Skip to: 12728
/* 11303 */   MCD_OPC_Decode, 240, 8, 168, 1, // Opcode: SHRAV_R_PH
/* 11308 */   MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 11321
/* 11312 */   MCD_OPC_CheckPredicate, 5, 132, 5, // Skip to: 12728
/* 11316 */   MCD_OPC_Decode, 237, 8, 169, 1, // Opcode: SHLL_S_W
/* 11321 */   MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 11334
/* 11325 */   MCD_OPC_CheckPredicate, 5, 119, 5, // Skip to: 12728
/* 11329 */   MCD_OPC_Decode, 247, 8, 169, 1, // Opcode: SHRA_R_W
/* 11334 */   MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 11346
/* 11338 */   MCD_OPC_CheckPredicate, 5, 106, 5, // Skip to: 12728
/* 11342 */   MCD_OPC_Decode, 233, 8, 13, // Opcode: SHLLV_S_W
/* 11346 */   MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 11358
/* 11350 */   MCD_OPC_CheckPredicate, 5, 94, 5, // Skip to: 12728
/* 11354 */   MCD_OPC_Decode, 242, 8, 13, // Opcode: SHRAV_R_W
/* 11358 */   MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 11371
/* 11362 */   MCD_OPC_CheckPredicate, 14, 82, 5, // Skip to: 12728
/* 11366 */   MCD_OPC_Decode, 250, 8, 167, 1, // Opcode: SHRL_PH
/* 11371 */   MCD_OPC_FilterValue, 27, 73, 5, // Skip to: 12728
/* 11375 */   MCD_OPC_CheckPredicate, 14, 69, 5, // Skip to: 12728
/* 11379 */   MCD_OPC_Decode, 248, 8, 168, 1, // Opcode: SHRLV_PH
/* 11384 */   MCD_OPC_FilterValue, 24, 199, 0, // Skip to: 11587
/* 11388 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11391 */   MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 11403
/* 11395 */   MCD_OPC_CheckPredicate, 14, 49, 5, // Skip to: 12728
/* 11399 */   MCD_OPC_Decode, 43, 156, 1, // Opcode: ADDUH_QB
/* 11403 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 11416
/* 11407 */   MCD_OPC_CheckPredicate, 14, 37, 5, // Skip to: 12728
/* 11411 */   MCD_OPC_Decode, 244, 9, 156, 1, // Opcode: SUBUH_QB
/* 11416 */   MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 11428
/* 11420 */   MCD_OPC_CheckPredicate, 14, 24, 5, // Skip to: 12728
/* 11424 */   MCD_OPC_Decode, 44, 156, 1, // Opcode: ADDUH_R_QB
/* 11428 */   MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 11441
/* 11432 */   MCD_OPC_CheckPredicate, 14, 12, 5, // Skip to: 12728
/* 11436 */   MCD_OPC_Decode, 245, 9, 156, 1, // Opcode: SUBUH_R_QB
/* 11441 */   MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 11453
/* 11445 */   MCD_OPC_CheckPredicate, 14, 255, 4, // Skip to: 12728
/* 11449 */   MCD_OPC_Decode, 23, 156, 1, // Opcode: ADDQH_PH
/* 11453 */   MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 11466
/* 11457 */   MCD_OPC_CheckPredicate, 14, 243, 4, // Skip to: 12728
/* 11461 */   MCD_OPC_Decode, 221, 9, 156, 1, // Opcode: SUBQH_PH
/* 11466 */   MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 11478
/* 11470 */   MCD_OPC_CheckPredicate, 14, 230, 4, // Skip to: 12728
/* 11474 */   MCD_OPC_Decode, 24, 156, 1, // Opcode: ADDQH_R_PH
/* 11478 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 11491
/* 11482 */   MCD_OPC_CheckPredicate, 14, 218, 4, // Skip to: 12728
/* 11486 */   MCD_OPC_Decode, 222, 9, 156, 1, // Opcode: SUBQH_R_PH
/* 11491 */   MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 11504
/* 11495 */   MCD_OPC_CheckPredicate, 14, 205, 4, // Skip to: 12728
/* 11499 */   MCD_OPC_Decode, 185, 7, 156, 1, // Opcode: MUL_PH
/* 11504 */   MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 11517
/* 11508 */   MCD_OPC_CheckPredicate, 14, 192, 4, // Skip to: 12728
/* 11512 */   MCD_OPC_Decode, 188, 7, 156, 1, // Opcode: MUL_S_PH
/* 11517 */   MCD_OPC_FilterValue, 16, 7, 0, // Skip to: 11528
/* 11521 */   MCD_OPC_CheckPredicate, 14, 179, 4, // Skip to: 12728
/* 11525 */   MCD_OPC_Decode, 26, 12, // Opcode: ADDQH_W
/* 11528 */   MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 11540
/* 11532 */   MCD_OPC_CheckPredicate, 14, 168, 4, // Skip to: 12728
/* 11536 */   MCD_OPC_Decode, 224, 9, 12, // Opcode: SUBQH_W
/* 11540 */   MCD_OPC_FilterValue, 18, 7, 0, // Skip to: 11551
/* 11544 */   MCD_OPC_CheckPredicate, 14, 156, 4, // Skip to: 12728
/* 11548 */   MCD_OPC_Decode, 25, 12, // Opcode: ADDQH_R_W
/* 11551 */   MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 11563
/* 11555 */   MCD_OPC_CheckPredicate, 14, 145, 4, // Skip to: 12728
/* 11559 */   MCD_OPC_Decode, 223, 9, 12, // Opcode: SUBQH_R_W
/* 11563 */   MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 11575
/* 11567 */   MCD_OPC_CheckPredicate, 14, 133, 4, // Skip to: 12728
/* 11571 */   MCD_OPC_Decode, 169, 7, 12, // Opcode: MULQ_S_W
/* 11575 */   MCD_OPC_FilterValue, 23, 125, 4, // Skip to: 12728
/* 11579 */   MCD_OPC_CheckPredicate, 14, 121, 4, // Skip to: 12728
/* 11583 */   MCD_OPC_Decode, 167, 7, 12, // Opcode: MULQ_RS_W
/* 11587 */   MCD_OPC_FilterValue, 32, 60, 0, // Skip to: 11651
/* 11591 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11594 */   MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 11613
/* 11598 */   MCD_OPC_CheckPredicate, 15, 102, 4, // Skip to: 12728
/* 11602 */   MCD_OPC_CheckField, 21, 5, 0, 96, 4, // Skip to: 12728
/* 11608 */   MCD_OPC_Decode, 235, 10, 166, 1, // Opcode: WSBH
/* 11613 */   MCD_OPC_FilterValue, 16, 15, 0, // Skip to: 11632
/* 11617 */   MCD_OPC_CheckPredicate, 16, 83, 4, // Skip to: 12728
/* 11621 */   MCD_OPC_CheckField, 21, 5, 0, 77, 4, // Skip to: 12728
/* 11627 */   MCD_OPC_Decode, 217, 8, 166, 1, // Opcode: SEB
/* 11632 */   MCD_OPC_FilterValue, 24, 68, 4, // Skip to: 12728
/* 11636 */   MCD_OPC_CheckPredicate, 16, 64, 4, // Skip to: 12728
/* 11640 */   MCD_OPC_CheckField, 21, 5, 0, 58, 4, // Skip to: 12728
/* 11646 */   MCD_OPC_Decode, 220, 8, 166, 1, // Opcode: SEH
/* 11651 */   MCD_OPC_FilterValue, 48, 143, 1, // Skip to: 12054
/* 11655 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11658 */   MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 11676
/* 11662 */   MCD_OPC_CheckPredicate, 14, 38, 4, // Skip to: 12728
/* 11666 */   MCD_OPC_CheckField, 13, 3, 0, 32, 4, // Skip to: 12728
/* 11672 */   MCD_OPC_Decode, 198, 3, 85, // Opcode: DPA_W_PH
/* 11676 */   MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 11694
/* 11680 */   MCD_OPC_CheckPredicate, 14, 20, 4, // Skip to: 12728
/* 11684 */   MCD_OPC_CheckField, 13, 3, 0, 14, 4, // Skip to: 12728
/* 11690 */   MCD_OPC_Decode, 212, 3, 85, // Opcode: DPS_W_PH
/* 11694 */   MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 11712
/* 11698 */   MCD_OPC_CheckPredicate, 14, 2, 4, // Skip to: 12728
/* 11702 */   MCD_OPC_CheckField, 13, 3, 0, 252, 3, // Skip to: 12728
/* 11708 */   MCD_OPC_Decode, 173, 7, 85, // Opcode: MULSA_W_PH
/* 11712 */   MCD_OPC_FilterValue, 3, 14, 0, // Skip to: 11730
/* 11716 */   MCD_OPC_CheckPredicate, 5, 240, 3, // Skip to: 12728
/* 11720 */   MCD_OPC_CheckField, 13, 3, 0, 234, 3, // Skip to: 12728
/* 11726 */   MCD_OPC_Decode, 195, 3, 85, // Opcode: DPAU_H_QBL
/* 11730 */   MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 11748
/* 11734 */   MCD_OPC_CheckPredicate, 5, 222, 3, // Skip to: 12728
/* 11738 */   MCD_OPC_CheckField, 13, 3, 0, 216, 3, // Skip to: 12728
/* 11744 */   MCD_OPC_Decode, 194, 3, 85, // Opcode: DPAQ_S_W_PH
/* 11748 */   MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 11766
/* 11752 */   MCD_OPC_CheckPredicate, 5, 204, 3, // Skip to: 12728
/* 11756 */   MCD_OPC_CheckField, 13, 3, 0, 198, 3, // Skip to: 12728
/* 11762 */   MCD_OPC_Decode, 202, 3, 85, // Opcode: DPSQ_S_W_PH
/* 11766 */   MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 11784
/* 11770 */   MCD_OPC_CheckPredicate, 5, 186, 3, // Skip to: 12728
/* 11774 */   MCD_OPC_CheckField, 13, 3, 0, 180, 3, // Skip to: 12728
/* 11780 */   MCD_OPC_Decode, 172, 7, 85, // Opcode: MULSAQ_S_W_PH
/* 11784 */   MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 11802
/* 11788 */   MCD_OPC_CheckPredicate, 5, 168, 3, // Skip to: 12728
/* 11792 */   MCD_OPC_CheckField, 13, 3, 0, 162, 3, // Skip to: 12728
/* 11798 */   MCD_OPC_Decode, 196, 3, 85, // Opcode: DPAU_H_QBR
/* 11802 */   MCD_OPC_FilterValue, 8, 14, 0, // Skip to: 11820
/* 11806 */   MCD_OPC_CheckPredicate, 14, 150, 3, // Skip to: 12728
/* 11810 */   MCD_OPC_CheckField, 13, 3, 0, 144, 3, // Skip to: 12728
/* 11816 */   MCD_OPC_Decode, 197, 3, 85, // Opcode: DPAX_W_PH
/* 11820 */   MCD_OPC_FilterValue, 9, 14, 0, // Skip to: 11838
/* 11824 */   MCD_OPC_CheckPredicate, 14, 132, 3, // Skip to: 12728
/* 11828 */   MCD_OPC_CheckField, 13, 3, 0, 126, 3, // Skip to: 12728
/* 11834 */   MCD_OPC_Decode, 211, 3, 85, // Opcode: DPSX_W_PH
/* 11838 */   MCD_OPC_FilterValue, 11, 14, 0, // Skip to: 11856
/* 11842 */   MCD_OPC_CheckPredicate, 5, 114, 3, // Skip to: 12728
/* 11846 */   MCD_OPC_CheckField, 13, 3, 0, 108, 3, // Skip to: 12728
/* 11852 */   MCD_OPC_Decode, 209, 3, 85, // Opcode: DPSU_H_QBL
/* 11856 */   MCD_OPC_FilterValue, 12, 14, 0, // Skip to: 11874
/* 11860 */   MCD_OPC_CheckPredicate, 5, 96, 3, // Skip to: 12728
/* 11864 */   MCD_OPC_CheckField, 13, 3, 0, 90, 3, // Skip to: 12728
/* 11870 */   MCD_OPC_Decode, 193, 3, 85, // Opcode: DPAQ_SA_L_W
/* 11874 */   MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 11892
/* 11878 */   MCD_OPC_CheckPredicate, 5, 78, 3, // Skip to: 12728
/* 11882 */   MCD_OPC_CheckField, 13, 3, 0, 72, 3, // Skip to: 12728
/* 11888 */   MCD_OPC_Decode, 201, 3, 85, // Opcode: DPSQ_SA_L_W
/* 11892 */   MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 11910
/* 11896 */   MCD_OPC_CheckPredicate, 5, 60, 3, // Skip to: 12728
/* 11900 */   MCD_OPC_CheckField, 13, 3, 0, 54, 3, // Skip to: 12728
/* 11906 */   MCD_OPC_Decode, 210, 3, 85, // Opcode: DPSU_H_QBR
/* 11910 */   MCD_OPC_FilterValue, 16, 14, 0, // Skip to: 11928
/* 11914 */   MCD_OPC_CheckPredicate, 5, 42, 3, // Skip to: 12728
/* 11918 */   MCD_OPC_CheckField, 13, 3, 0, 36, 3, // Skip to: 12728
/* 11924 */   MCD_OPC_Decode, 159, 6, 85, // Opcode: MAQ_SA_W_PHL
/* 11928 */   MCD_OPC_FilterValue, 18, 14, 0, // Skip to: 11946
/* 11932 */   MCD_OPC_CheckPredicate, 5, 24, 3, // Skip to: 12728
/* 11936 */   MCD_OPC_CheckField, 13, 3, 0, 18, 3, // Skip to: 12728
/* 11942 */   MCD_OPC_Decode, 160, 6, 85, // Opcode: MAQ_SA_W_PHR
/* 11946 */   MCD_OPC_FilterValue, 20, 14, 0, // Skip to: 11964
/* 11950 */   MCD_OPC_CheckPredicate, 5, 6, 3, // Skip to: 12728
/* 11954 */   MCD_OPC_CheckField, 13, 3, 0, 0, 3, // Skip to: 12728
/* 11960 */   MCD_OPC_Decode, 161, 6, 85, // Opcode: MAQ_S_W_PHL
/* 11964 */   MCD_OPC_FilterValue, 22, 14, 0, // Skip to: 11982
/* 11968 */   MCD_OPC_CheckPredicate, 5, 244, 2, // Skip to: 12728
/* 11972 */   MCD_OPC_CheckField, 13, 3, 0, 238, 2, // Skip to: 12728
/* 11978 */   MCD_OPC_Decode, 162, 6, 85, // Opcode: MAQ_S_W_PHR
/* 11982 */   MCD_OPC_FilterValue, 24, 14, 0, // Skip to: 12000
/* 11986 */   MCD_OPC_CheckPredicate, 14, 226, 2, // Skip to: 12728
/* 11990 */   MCD_OPC_CheckField, 13, 3, 0, 220, 2, // Skip to: 12728
/* 11996 */   MCD_OPC_Decode, 192, 3, 85, // Opcode: DPAQX_S_W_PH
/* 12000 */   MCD_OPC_FilterValue, 25, 14, 0, // Skip to: 12018
/* 12004 */   MCD_OPC_CheckPredicate, 14, 208, 2, // Skip to: 12728
/* 12008 */   MCD_OPC_CheckField, 13, 3, 0, 202, 2, // Skip to: 12728
/* 12014 */   MCD_OPC_Decode, 200, 3, 85, // Opcode: DPSQX_S_W_PH
/* 12018 */   MCD_OPC_FilterValue, 26, 14, 0, // Skip to: 12036
/* 12022 */   MCD_OPC_CheckPredicate, 14, 190, 2, // Skip to: 12728
/* 12026 */   MCD_OPC_CheckField, 13, 3, 0, 184, 2, // Skip to: 12728
/* 12032 */   MCD_OPC_Decode, 191, 3, 85, // Opcode: DPAQX_SA_W_PH
/* 12036 */   MCD_OPC_FilterValue, 27, 176, 2, // Skip to: 12728
/* 12040 */   MCD_OPC_CheckPredicate, 14, 172, 2, // Skip to: 12728
/* 12044 */   MCD_OPC_CheckField, 13, 3, 0, 166, 2, // Skip to: 12728
/* 12050 */   MCD_OPC_Decode, 199, 3, 85, // Opcode: DPSQX_SA_W_PH
/* 12054 */   MCD_OPC_FilterValue, 49, 41, 0, // Skip to: 12099
/* 12058 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 12061 */   MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 12073
/* 12065 */   MCD_OPC_CheckPredicate, 14, 147, 2, // Skip to: 12728
/* 12069 */   MCD_OPC_Decode, 82, 170, 1, // Opcode: APPEND
/* 12073 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 12086
/* 12077 */   MCD_OPC_CheckPredicate, 14, 135, 2, // Skip to: 12728
/* 12081 */   MCD_OPC_Decode, 138, 8, 170, 1, // Opcode: PREPEND
/* 12086 */   MCD_OPC_FilterValue, 16, 126, 2, // Skip to: 12728
/* 12090 */   MCD_OPC_CheckPredicate, 14, 122, 2, // Skip to: 12728
/* 12094 */   MCD_OPC_Decode, 149, 1, 170, 1, // Opcode: BALIGN
/* 12099 */   MCD_OPC_FilterValue, 56, 58, 1, // Skip to: 12417
/* 12103 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 12106 */   MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 12125
/* 12110 */   MCD_OPC_CheckPredicate, 5, 102, 2, // Skip to: 12728
/* 12114 */   MCD_OPC_CheckField, 13, 3, 0, 96, 2, // Skip to: 12728
/* 12120 */   MCD_OPC_Decode, 247, 3, 171, 1, // Opcode: EXTR_W
/* 12125 */   MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 12144
/* 12129 */   MCD_OPC_CheckPredicate, 5, 83, 2, // Skip to: 12728
/* 12133 */   MCD_OPC_CheckField, 13, 3, 0, 77, 2, // Skip to: 12728
/* 12139 */   MCD_OPC_Decode, 243, 3, 172, 1, // Opcode: EXTRV_W
/* 12144 */   MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 12163
/* 12148 */   MCD_OPC_CheckPredicate, 5, 64, 2, // Skip to: 12728
/* 12152 */   MCD_OPC_CheckField, 13, 3, 0, 58, 2, // Skip to: 12728
/* 12158 */   MCD_OPC_Decode, 236, 3, 171, 1, // Opcode: EXTP
/* 12163 */   MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 12182
/* 12167 */   MCD_OPC_CheckPredicate, 5, 45, 2, // Skip to: 12728
/* 12171 */   MCD_OPC_CheckField, 13, 3, 0, 39, 2, // Skip to: 12728
/* 12177 */   MCD_OPC_Decode, 239, 3, 172, 1, // Opcode: EXTPV
/* 12182 */   MCD_OPC_FilterValue, 4, 15, 0, // Skip to: 12201
/* 12186 */   MCD_OPC_CheckPredicate, 5, 26, 2, // Skip to: 12728
/* 12190 */   MCD_OPC_CheckField, 13, 3, 0, 20, 2, // Skip to: 12728
/* 12196 */   MCD_OPC_Decode, 245, 3, 171, 1, // Opcode: EXTR_R_W
/* 12201 */   MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 12220
/* 12205 */   MCD_OPC_CheckPredicate, 5, 7, 2, // Skip to: 12728
/* 12209 */   MCD_OPC_CheckField, 13, 3, 0, 1, 2, // Skip to: 12728
/* 12215 */   MCD_OPC_Decode, 241, 3, 172, 1, // Opcode: EXTRV_R_W
/* 12220 */   MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 12239
/* 12224 */   MCD_OPC_CheckPredicate, 5, 244, 1, // Skip to: 12728
/* 12228 */   MCD_OPC_CheckField, 13, 3, 0, 238, 1, // Skip to: 12728
/* 12234 */   MCD_OPC_Decode, 244, 3, 171, 1, // Opcode: EXTR_RS_W
/* 12239 */   MCD_OPC_FilterValue, 7, 15, 0, // Skip to: 12258
/* 12243 */   MCD_OPC_CheckPredicate, 5, 225, 1, // Skip to: 12728
/* 12247 */   MCD_OPC_CheckField, 13, 3, 0, 219, 1, // Skip to: 12728
/* 12253 */   MCD_OPC_Decode, 240, 3, 172, 1, // Opcode: EXTRV_RS_W
/* 12258 */   MCD_OPC_FilterValue, 10, 15, 0, // Skip to: 12277
/* 12262 */   MCD_OPC_CheckPredicate, 5, 206, 1, // Skip to: 12728
/* 12266 */   MCD_OPC_CheckField, 13, 3, 0, 200, 1, // Skip to: 12728
/* 12272 */   MCD_OPC_Decode, 237, 3, 171, 1, // Opcode: EXTPDP
/* 12277 */   MCD_OPC_FilterValue, 11, 15, 0, // Skip to: 12296
/* 12281 */   MCD_OPC_CheckPredicate, 5, 187, 1, // Skip to: 12728
/* 12285 */   MCD_OPC_CheckField, 13, 3, 0, 181, 1, // Skip to: 12728
/* 12291 */   MCD_OPC_Decode, 238, 3, 172, 1, // Opcode: EXTPDPV
/* 12296 */   MCD_OPC_FilterValue, 14, 15, 0, // Skip to: 12315
/* 12300 */   MCD_OPC_CheckPredicate, 5, 168, 1, // Skip to: 12728
/* 12304 */   MCD_OPC_CheckField, 13, 3, 0, 162, 1, // Skip to: 12728
/* 12310 */   MCD_OPC_Decode, 246, 3, 171, 1, // Opcode: EXTR_S_H
/* 12315 */   MCD_OPC_FilterValue, 15, 15, 0, // Skip to: 12334
/* 12319 */   MCD_OPC_CheckPredicate, 5, 149, 1, // Skip to: 12728
/* 12323 */   MCD_OPC_CheckField, 13, 3, 0, 143, 1, // Skip to: 12728
/* 12329 */   MCD_OPC_Decode, 242, 3, 172, 1, // Opcode: EXTRV_S_H
/* 12334 */   MCD_OPC_FilterValue, 18, 9, 0, // Skip to: 12347
/* 12338 */   MCD_OPC_CheckPredicate, 5, 130, 1, // Skip to: 12728
/* 12342 */   MCD_OPC_Decode, 172, 8, 173, 1, // Opcode: RDDSP
/* 12347 */   MCD_OPC_FilterValue, 19, 9, 0, // Skip to: 12360
/* 12351 */   MCD_OPC_CheckPredicate, 5, 117, 1, // Skip to: 12728
/* 12355 */   MCD_OPC_Decode, 234, 10, 174, 1, // Opcode: WRDSP
/* 12360 */   MCD_OPC_FilterValue, 26, 15, 0, // Skip to: 12379
/* 12364 */   MCD_OPC_CheckPredicate, 5, 104, 1, // Skip to: 12728
/* 12368 */   MCD_OPC_CheckField, 13, 7, 0, 98, 1, // Skip to: 12728
/* 12374 */   MCD_OPC_Decode, 228, 8, 175, 1, // Opcode: SHILO
/* 12379 */   MCD_OPC_FilterValue, 27, 15, 0, // Skip to: 12398
/* 12383 */   MCD_OPC_CheckPredicate, 5, 85, 1, // Skip to: 12728
/* 12387 */   MCD_OPC_CheckField, 13, 8, 0, 79, 1, // Skip to: 12728
/* 12393 */   MCD_OPC_Decode, 229, 8, 176, 1, // Opcode: SHILOV
/* 12398 */   MCD_OPC_FilterValue, 31, 70, 1, // Skip to: 12728
/* 12402 */   MCD_OPC_CheckPredicate, 5, 66, 1, // Skip to: 12728
/* 12406 */   MCD_OPC_CheckField, 13, 8, 0, 60, 1, // Skip to: 12728
/* 12412 */   MCD_OPC_Decode, 156, 7, 176, 1, // Opcode: MTHLIP
/* 12417 */   MCD_OPC_FilterValue, 59, 51, 1, // Skip to: 12728
/* 12421 */   MCD_OPC_CheckPredicate, 2, 47, 1, // Skip to: 12728
/* 12425 */   MCD_OPC_CheckField, 21, 5, 0, 41, 1, // Skip to: 12728
/* 12431 */   MCD_OPC_CheckField, 6, 5, 0, 35, 1, // Skip to: 12728
/* 12437 */   MCD_OPC_Decode, 173, 8, 177, 1, // Opcode: RDHWR
/* 12442 */   MCD_OPC_FilterValue, 32, 9, 0, // Skip to: 12455
/* 12446 */   MCD_OPC_CheckPredicate, 2, 22, 1, // Skip to: 12728
/* 12450 */   MCD_OPC_Decode, 197, 5, 178, 1, // Opcode: LB
/* 12455 */   MCD_OPC_FilterValue, 33, 9, 0, // Skip to: 12468
/* 12459 */   MCD_OPC_CheckPredicate, 2, 9, 1, // Skip to: 12728
/* 12463 */   MCD_OPC_Decode, 222, 5, 178, 1, // Opcode: LH
/* 12468 */   MCD_OPC_FilterValue, 34, 9, 0, // Skip to: 12481
/* 12472 */   MCD_OPC_CheckPredicate, 17, 252, 0, // Skip to: 12728
/* 12476 */   MCD_OPC_Decode, 245, 5, 178, 1, // Opcode: LWL
/* 12481 */   MCD_OPC_FilterValue, 35, 9, 0, // Skip to: 12494
/* 12485 */   MCD_OPC_CheckPredicate, 2, 239, 0, // Skip to: 12728
/* 12489 */   MCD_OPC_Decode, 241, 5, 178, 1, // Opcode: LW
/* 12494 */   MCD_OPC_FilterValue, 36, 9, 0, // Skip to: 12507
/* 12498 */   MCD_OPC_CheckPredicate, 2, 226, 0, // Skip to: 12728
/* 12502 */   MCD_OPC_Decode, 201, 5, 178, 1, // Opcode: LBu
/* 12507 */   MCD_OPC_FilterValue, 37, 9, 0, // Skip to: 12520
/* 12511 */   MCD_OPC_CheckPredicate, 2, 213, 0, // Skip to: 12728
/* 12515 */   MCD_OPC_Decode, 226, 5, 178, 1, // Opcode: LHu
/* 12520 */   MCD_OPC_FilterValue, 38, 9, 0, // Skip to: 12533
/* 12524 */   MCD_OPC_CheckPredicate, 17, 200, 0, // Skip to: 12728
/* 12528 */   MCD_OPC_Decode, 248, 5, 178, 1, // Opcode: LWR
/* 12533 */   MCD_OPC_FilterValue, 40, 9, 0, // Skip to: 12546
/* 12537 */   MCD_OPC_CheckPredicate, 2, 187, 0, // Skip to: 12728
/* 12541 */   MCD_OPC_Decode, 202, 8, 178, 1, // Opcode: SB
/* 12546 */   MCD_OPC_FilterValue, 41, 9, 0, // Skip to: 12559
/* 12550 */   MCD_OPC_CheckPredicate, 2, 174, 0, // Skip to: 12728
/* 12554 */   MCD_OPC_Decode, 223, 8, 178, 1, // Opcode: SH
/* 12559 */   MCD_OPC_FilterValue, 42, 9, 0, // Skip to: 12572
/* 12563 */   MCD_OPC_CheckPredicate, 17, 161, 0, // Skip to: 12728
/* 12567 */   MCD_OPC_Decode, 139, 10, 178, 1, // Opcode: SWL
/* 12572 */   MCD_OPC_FilterValue, 43, 9, 0, // Skip to: 12585
/* 12576 */   MCD_OPC_CheckPredicate, 2, 148, 0, // Skip to: 12728
/* 12580 */   MCD_OPC_Decode, 135, 10, 178, 1, // Opcode: SW
/* 12585 */   MCD_OPC_FilterValue, 46, 9, 0, // Skip to: 12598
/* 12589 */   MCD_OPC_CheckPredicate, 17, 135, 0, // Skip to: 12728
/* 12593 */   MCD_OPC_Decode, 142, 10, 178, 1, // Opcode: SWR
/* 12598 */   MCD_OPC_FilterValue, 48, 9, 0, // Skip to: 12611
/* 12602 */   MCD_OPC_CheckPredicate, 2, 122, 0, // Skip to: 12728
/* 12606 */   MCD_OPC_Decode, 229, 5, 178, 1, // Opcode: LL
/* 12611 */   MCD_OPC_FilterValue, 49, 9, 0, // Skip to: 12624
/* 12615 */   MCD_OPC_CheckPredicate, 2, 109, 0, // Skip to: 12728
/* 12619 */   MCD_OPC_Decode, 243, 5, 179, 1, // Opcode: LWC1
/* 12624 */   MCD_OPC_FilterValue, 50, 9, 0, // Skip to: 12637
/* 12628 */   MCD_OPC_CheckPredicate, 2, 96, 0, // Skip to: 12728
/* 12632 */   MCD_OPC_Decode, 244, 5, 179, 1, // Opcode: LWC2
/* 12637 */   MCD_OPC_FilterValue, 53, 9, 0, // Skip to: 12650
/* 12641 */   MCD_OPC_CheckPredicate, 7, 83, 0, // Skip to: 12728
/* 12645 */   MCD_OPC_Decode, 205, 5, 179, 1, // Opcode: LDC1
/* 12650 */   MCD_OPC_FilterValue, 54, 9, 0, // Skip to: 12663
/* 12654 */   MCD_OPC_CheckPredicate, 2, 70, 0, // Skip to: 12728
/* 12658 */   MCD_OPC_Decode, 207, 5, 179, 1, // Opcode: LDC2
/* 12663 */   MCD_OPC_FilterValue, 56, 9, 0, // Skip to: 12676
/* 12667 */   MCD_OPC_CheckPredicate, 2, 57, 0, // Skip to: 12728
/* 12671 */   MCD_OPC_Decode, 205, 8, 178, 1, // Opcode: SC
/* 12676 */   MCD_OPC_FilterValue, 57, 9, 0, // Skip to: 12689
/* 12680 */   MCD_OPC_CheckPredicate, 2, 44, 0, // Skip to: 12728
/* 12684 */   MCD_OPC_Decode, 137, 10, 179, 1, // Opcode: SWC1
/* 12689 */   MCD_OPC_FilterValue, 58, 9, 0, // Skip to: 12702
/* 12693 */   MCD_OPC_CheckPredicate, 2, 31, 0, // Skip to: 12728
/* 12697 */   MCD_OPC_Decode, 138, 10, 179, 1, // Opcode: SWC2
/* 12702 */   MCD_OPC_FilterValue, 61, 9, 0, // Skip to: 12715
/* 12706 */   MCD_OPC_CheckPredicate, 7, 18, 0, // Skip to: 12728
/* 12710 */   MCD_OPC_Decode, 208, 8, 179, 1, // Opcode: SDC1
/* 12715 */   MCD_OPC_FilterValue, 62, 9, 0, // Skip to: 12728
/* 12719 */   MCD_OPC_CheckPredicate, 2, 5, 0, // Skip to: 12728
/* 12723 */   MCD_OPC_Decode, 210, 8, 179, 1, // Opcode: SDC2
/* 12728 */   MCD_OPC_Fail,
  0
};

static uint8_t DecoderTableMips6432[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 93, 1, // Skip to: 356
/* 7 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10 */      MCD_OPC_FilterValue, 20, 15, 0, // Skip to: 29
/* 14 */      MCD_OPC_CheckPredicate, 2, 6, 7, // Skip to: 1816
/* 18 */      MCD_OPC_CheckField, 6, 5, 0, 0, 7, // Skip to: 1816
/* 24 */      MCD_OPC_Decode, 222, 3, 180, 1, // Opcode: DSLLV
/* 29 */      MCD_OPC_FilterValue, 22, 29, 0, // Skip to: 62
/* 33 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 36 */      MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 49
/* 40 */      MCD_OPC_CheckPredicate, 2, 236, 6, // Skip to: 1816
/* 44 */      MCD_OPC_Decode, 228, 3, 180, 1, // Opcode: DSRLV
/* 49 */      MCD_OPC_FilterValue, 1, 227, 6, // Skip to: 1816
/* 53 */      MCD_OPC_CheckPredicate, 18, 223, 6, // Skip to: 1816
/* 57 */      MCD_OPC_Decode, 215, 3, 180, 1, // Opcode: DROTRV
/* 62 */      MCD_OPC_FilterValue, 23, 15, 0, // Skip to: 81
/* 66 */      MCD_OPC_CheckPredicate, 2, 210, 6, // Skip to: 1816
/* 70 */      MCD_OPC_CheckField, 6, 5, 0, 204, 6, // Skip to: 1816
/* 76 */      MCD_OPC_Decode, 225, 3, 180, 1, // Opcode: DSRAV
/* 81 */      MCD_OPC_FilterValue, 28, 15, 0, // Skip to: 100
/* 85 */      MCD_OPC_CheckPredicate, 2, 191, 6, // Skip to: 1816
/* 89 */      MCD_OPC_CheckField, 6, 10, 0, 185, 6, // Skip to: 1816
/* 95 */      MCD_OPC_Decode, 177, 3, 181, 1, // Opcode: DMULT
/* 100 */     MCD_OPC_FilterValue, 29, 15, 0, // Skip to: 119
/* 104 */     MCD_OPC_CheckPredicate, 2, 172, 6, // Skip to: 1816
/* 108 */     MCD_OPC_CheckField, 6, 10, 0, 166, 6, // Skip to: 1816
/* 114 */     MCD_OPC_Decode, 178, 3, 181, 1, // Opcode: DMULTu
/* 119 */     MCD_OPC_FilterValue, 30, 15, 0, // Skip to: 138
/* 123 */     MCD_OPC_CheckPredicate, 2, 153, 6, // Skip to: 1816
/* 127 */     MCD_OPC_CheckField, 6, 10, 0, 147, 6, // Skip to: 1816
/* 133 */     MCD_OPC_Decode, 217, 3, 181, 1, // Opcode: DSDIV
/* 138 */     MCD_OPC_FilterValue, 31, 15, 0, // Skip to: 157
/* 142 */     MCD_OPC_CheckPredicate, 2, 134, 6, // Skip to: 1816
/* 146 */     MCD_OPC_CheckField, 6, 10, 0, 128, 6, // Skip to: 1816
/* 152 */     MCD_OPC_Decode, 230, 3, 181, 1, // Opcode: DUDIV
/* 157 */     MCD_OPC_FilterValue, 44, 15, 0, // Skip to: 176
/* 161 */     MCD_OPC_CheckPredicate, 2, 115, 6, // Skip to: 1816
/* 165 */     MCD_OPC_CheckField, 6, 5, 0, 109, 6, // Skip to: 1816
/* 171 */     MCD_OPC_Decode, 149, 3, 182, 1, // Opcode: DADD
/* 176 */     MCD_OPC_FilterValue, 45, 15, 0, // Skip to: 195
/* 180 */     MCD_OPC_CheckPredicate, 2, 96, 6, // Skip to: 1816
/* 184 */     MCD_OPC_CheckField, 6, 5, 0, 90, 6, // Skip to: 1816
/* 190 */     MCD_OPC_Decode, 152, 3, 182, 1, // Opcode: DADDu
/* 195 */     MCD_OPC_FilterValue, 47, 15, 0, // Skip to: 214
/* 199 */     MCD_OPC_CheckPredicate, 2, 77, 6, // Skip to: 1816
/* 203 */     MCD_OPC_CheckField, 6, 5, 0, 71, 6, // Skip to: 1816
/* 209 */     MCD_OPC_Decode, 229, 3, 182, 1, // Opcode: DSUBu
/* 214 */     MCD_OPC_FilterValue, 56, 15, 0, // Skip to: 233
/* 218 */     MCD_OPC_CheckPredicate, 2, 58, 6, // Skip to: 1816
/* 222 */     MCD_OPC_CheckField, 21, 5, 0, 52, 6, // Skip to: 1816
/* 228 */     MCD_OPC_Decode, 219, 3, 183, 1, // Opcode: DSLL
/* 233 */     MCD_OPC_FilterValue, 58, 29, 0, // Skip to: 266
/* 237 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 240 */     MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 253
/* 244 */     MCD_OPC_CheckPredicate, 2, 32, 6, // Skip to: 1816
/* 248 */     MCD_OPC_Decode, 226, 3, 183, 1, // Opcode: DSRL
/* 253 */     MCD_OPC_FilterValue, 1, 23, 6, // Skip to: 1816
/* 257 */     MCD_OPC_CheckPredicate, 18, 19, 6, // Skip to: 1816
/* 261 */     MCD_OPC_Decode, 213, 3, 183, 1, // Opcode: DROTR
/* 266 */     MCD_OPC_FilterValue, 59, 15, 0, // Skip to: 285
/* 270 */     MCD_OPC_CheckPredicate, 2, 6, 6, // Skip to: 1816
/* 274 */     MCD_OPC_CheckField, 21, 5, 0, 0, 6, // Skip to: 1816
/* 280 */     MCD_OPC_Decode, 223, 3, 183, 1, // Opcode: DSRA
/* 285 */     MCD_OPC_FilterValue, 60, 15, 0, // Skip to: 304
/* 289 */     MCD_OPC_CheckPredicate, 2, 243, 5, // Skip to: 1816
/* 293 */     MCD_OPC_CheckField, 21, 5, 0, 237, 5, // Skip to: 1816
/* 299 */     MCD_OPC_Decode, 220, 3, 183, 1, // Opcode: DSLL32
/* 304 */     MCD_OPC_FilterValue, 62, 29, 0, // Skip to: 337
/* 308 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 311 */     MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 324
/* 315 */     MCD_OPC_CheckPredicate, 2, 217, 5, // Skip to: 1816
/* 319 */     MCD_OPC_Decode, 227, 3, 183, 1, // Opcode: DSRL32
/* 324 */     MCD_OPC_FilterValue, 1, 208, 5, // Skip to: 1816
/* 328 */     MCD_OPC_CheckPredicate, 18, 204, 5, // Skip to: 1816
/* 332 */     MCD_OPC_Decode, 214, 3, 183, 1, // Opcode: DROTR32
/* 337 */     MCD_OPC_FilterValue, 63, 195, 5, // Skip to: 1816
/* 341 */     MCD_OPC_CheckPredicate, 2, 191, 5, // Skip to: 1816
/* 345 */     MCD_OPC_CheckField, 21, 5, 0, 185, 5, // Skip to: 1816
/* 351 */     MCD_OPC_Decode, 224, 3, 183, 1, // Opcode: DSRA32
/* 356 */     MCD_OPC_FilterValue, 16, 41, 0, // Skip to: 401
/* 360 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 363 */     MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 382
/* 367 */     MCD_OPC_CheckPredicate, 19, 165, 5, // Skip to: 1816
/* 371 */     MCD_OPC_CheckField, 3, 8, 0, 159, 5, // Skip to: 1816
/* 377 */     MCD_OPC_Decode, 171, 3, 184, 1, // Opcode: DMFC0
/* 382 */     MCD_OPC_FilterValue, 5, 150, 5, // Skip to: 1816
/* 386 */     MCD_OPC_CheckPredicate, 19, 146, 5, // Skip to: 1816
/* 390 */     MCD_OPC_CheckField, 3, 8, 0, 140, 5, // Skip to: 1816
/* 396 */     MCD_OPC_Decode, 174, 3, 184, 1, // Opcode: DMTC0
/* 401 */     MCD_OPC_FilterValue, 17, 183, 3, // Skip to: 1356
/* 405 */     MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 408 */     MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 427
/* 412 */     MCD_OPC_CheckPredicate, 20, 120, 5, // Skip to: 1816
/* 416 */     MCD_OPC_CheckField, 21, 5, 17, 114, 5, // Skip to: 1816
/* 422 */     MCD_OPC_Decode, 130, 4, 185, 1, // Opcode: FADD_D64
/* 427 */     MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 446
/* 431 */     MCD_OPC_CheckPredicate, 20, 101, 5, // Skip to: 1816
/* 435 */     MCD_OPC_CheckField, 21, 5, 17, 95, 5, // Skip to: 1816
/* 441 */     MCD_OPC_Decode, 243, 4, 185, 1, // Opcode: FSUB_D64
/* 446 */     MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 465
/* 450 */     MCD_OPC_CheckPredicate, 20, 82, 5, // Skip to: 1816
/* 454 */     MCD_OPC_CheckField, 21, 5, 17, 76, 5, // Skip to: 1816
/* 460 */     MCD_OPC_Decode, 212, 4, 185, 1, // Opcode: FMUL_D64
/* 465 */     MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 484
/* 469 */     MCD_OPC_CheckPredicate, 20, 63, 5, // Skip to: 1816
/* 473 */     MCD_OPC_CheckField, 21, 5, 17, 57, 5, // Skip to: 1816
/* 479 */     MCD_OPC_Decode, 162, 4, 185, 1, // Opcode: FDIV_D64
/* 484 */     MCD_OPC_FilterValue, 4, 15, 0, // Skip to: 503
/* 488 */     MCD_OPC_CheckPredicate, 20, 44, 5, // Skip to: 1816
/* 492 */     MCD_OPC_CheckField, 16, 10, 160, 4, 37, 5, // Skip to: 1816
/* 499 */     MCD_OPC_Decode, 238, 4, 74, // Opcode: FSQRT_D64
/* 503 */     MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 522
/* 507 */     MCD_OPC_CheckPredicate, 6, 25, 5, // Skip to: 1816
/* 511 */     MCD_OPC_CheckField, 16, 10, 160, 4, 18, 5, // Skip to: 1816
/* 518 */     MCD_OPC_Decode, 253, 3, 74, // Opcode: FABS_D64
/* 522 */     MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 541
/* 526 */     MCD_OPC_CheckPredicate, 20, 6, 5, // Skip to: 1816
/* 530 */     MCD_OPC_CheckField, 16, 10, 160, 4, 255, 4, // Skip to: 1816
/* 537 */     MCD_OPC_Decode, 206, 4, 74, // Opcode: FMOV_D64
/* 541 */     MCD_OPC_FilterValue, 7, 15, 0, // Skip to: 560
/* 545 */     MCD_OPC_CheckPredicate, 6, 243, 4, // Skip to: 1816
/* 549 */     MCD_OPC_CheckField, 16, 10, 160, 4, 236, 4, // Skip to: 1816
/* 556 */     MCD_OPC_Decode, 216, 4, 74, // Opcode: FNEG_D64
/* 560 */     MCD_OPC_FilterValue, 8, 29, 0, // Skip to: 593
/* 564 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 567 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 580
/* 572 */     MCD_OPC_CheckPredicate, 20, 216, 4, // Skip to: 1816
/* 576 */     MCD_OPC_Decode, 186, 8, 67, // Opcode: ROUND_L_S
/* 580 */     MCD_OPC_FilterValue, 160, 4, 207, 4, // Skip to: 1816
/* 585 */     MCD_OPC_CheckPredicate, 20, 203, 4, // Skip to: 1816
/* 589 */     MCD_OPC_Decode, 185, 8, 74, // Opcode: ROUND_L_D64
/* 593 */     MCD_OPC_FilterValue, 9, 29, 0, // Skip to: 626
/* 597 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 600 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 613
/* 605 */     MCD_OPC_CheckPredicate, 20, 183, 4, // Skip to: 1816
/* 609 */     MCD_OPC_Decode, 222, 10, 67, // Opcode: TRUNC_L_S
/* 613 */     MCD_OPC_FilterValue, 160, 4, 174, 4, // Skip to: 1816
/* 618 */     MCD_OPC_CheckPredicate, 20, 170, 4, // Skip to: 1816
/* 622 */     MCD_OPC_Decode, 221, 10, 74, // Opcode: TRUNC_L_D64
/* 626 */     MCD_OPC_FilterValue, 10, 29, 0, // Skip to: 659
/* 630 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 633 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 646
/* 638 */     MCD_OPC_CheckPredicate, 20, 150, 4, // Skip to: 1816
/* 642 */     MCD_OPC_Decode, 138, 2, 67, // Opcode: CEIL_L_S
/* 646 */     MCD_OPC_FilterValue, 160, 4, 141, 4, // Skip to: 1816
/* 651 */     MCD_OPC_CheckPredicate, 20, 137, 4, // Skip to: 1816
/* 655 */     MCD_OPC_Decode, 137, 2, 74, // Opcode: CEIL_L_D64
/* 659 */     MCD_OPC_FilterValue, 11, 29, 0, // Skip to: 692
/* 663 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 666 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 679
/* 671 */     MCD_OPC_CheckPredicate, 20, 117, 4, // Skip to: 1816
/* 675 */     MCD_OPC_Decode, 191, 4, 67, // Opcode: FLOOR_L_S
/* 679 */     MCD_OPC_FilterValue, 160, 4, 108, 4, // Skip to: 1816
/* 684 */     MCD_OPC_CheckPredicate, 20, 104, 4, // Skip to: 1816
/* 688 */     MCD_OPC_Decode, 190, 4, 74, // Opcode: FLOOR_L_D64
/* 692 */     MCD_OPC_FilterValue, 12, 16, 0, // Skip to: 712
/* 696 */     MCD_OPC_CheckPredicate, 20, 92, 4, // Skip to: 1816
/* 700 */     MCD_OPC_CheckField, 16, 10, 160, 4, 85, 4, // Skip to: 1816
/* 707 */     MCD_OPC_Decode, 188, 8, 186, 1, // Opcode: ROUND_W_D64
/* 712 */     MCD_OPC_FilterValue, 13, 16, 0, // Skip to: 732
/* 716 */     MCD_OPC_CheckPredicate, 20, 72, 4, // Skip to: 1816
/* 720 */     MCD_OPC_CheckField, 16, 10, 160, 4, 65, 4, // Skip to: 1816
/* 727 */     MCD_OPC_Decode, 224, 10, 186, 1, // Opcode: TRUNC_W_D64
/* 732 */     MCD_OPC_FilterValue, 14, 16, 0, // Skip to: 752
/* 736 */     MCD_OPC_CheckPredicate, 20, 52, 4, // Skip to: 1816
/* 740 */     MCD_OPC_CheckField, 16, 10, 160, 4, 45, 4, // Skip to: 1816
/* 747 */     MCD_OPC_Decode, 140, 2, 186, 1, // Opcode: CEIL_W_D64
/* 752 */     MCD_OPC_FilterValue, 15, 16, 0, // Skip to: 772
/* 756 */     MCD_OPC_CheckPredicate, 20, 32, 4, // Skip to: 1816
/* 760 */     MCD_OPC_CheckField, 16, 10, 160, 4, 25, 4, // Skip to: 1816
/* 767 */     MCD_OPC_Decode, 193, 4, 186, 1, // Opcode: FLOOR_W_D64
/* 772 */     MCD_OPC_FilterValue, 17, 41, 0, // Skip to: 817
/* 776 */     MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 779 */     MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 798
/* 783 */     MCD_OPC_CheckPredicate, 20, 5, 4, // Skip to: 1816
/* 787 */     MCD_OPC_CheckField, 21, 5, 17, 255, 3, // Skip to: 1816
/* 793 */     MCD_OPC_Decode, 228, 6, 187, 1, // Opcode: MOVF_D64
/* 798 */     MCD_OPC_FilterValue, 1, 246, 3, // Skip to: 1816
/* 802 */     MCD_OPC_CheckPredicate, 20, 242, 3, // Skip to: 1816
/* 806 */     MCD_OPC_CheckField, 21, 5, 17, 236, 3, // Skip to: 1816
/* 812 */     MCD_OPC_Decode, 244, 6, 187, 1, // Opcode: MOVT_D64
/* 817 */     MCD_OPC_FilterValue, 18, 15, 0, // Skip to: 836
/* 821 */     MCD_OPC_CheckPredicate, 20, 223, 3, // Skip to: 1816
/* 825 */     MCD_OPC_CheckField, 21, 5, 17, 217, 3, // Skip to: 1816
/* 831 */     MCD_OPC_Decode, 254, 6, 188, 1, // Opcode: MOVZ_I_D64
/* 836 */     MCD_OPC_FilterValue, 19, 15, 0, // Skip to: 855
/* 840 */     MCD_OPC_CheckPredicate, 20, 204, 3, // Skip to: 1816
/* 844 */     MCD_OPC_CheckField, 21, 5, 17, 198, 3, // Skip to: 1816
/* 850 */     MCD_OPC_Decode, 238, 6, 188, 1, // Opcode: MOVN_I_D64
/* 855 */     MCD_OPC_FilterValue, 32, 31, 0, // Skip to: 890
/* 859 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 862 */     MCD_OPC_FilterValue, 160, 4, 9, 0, // Skip to: 876
/* 867 */     MCD_OPC_CheckPredicate, 20, 177, 3, // Skip to: 1816
/* 871 */     MCD_OPC_Decode, 219, 2, 186, 1, // Opcode: CVT_S_D64
/* 876 */     MCD_OPC_FilterValue, 160, 5, 167, 3, // Skip to: 1816
/* 881 */     MCD_OPC_CheckPredicate, 20, 163, 3, // Skip to: 1816
/* 885 */     MCD_OPC_Decode, 220, 2, 186, 1, // Opcode: CVT_S_L
/* 890 */     MCD_OPC_FilterValue, 33, 42, 0, // Skip to: 936
/* 894 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 897 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 910
/* 902 */     MCD_OPC_CheckPredicate, 20, 142, 3, // Skip to: 1816
/* 906 */     MCD_OPC_Decode, 214, 2, 67, // Opcode: CVT_D64_S
/* 910 */     MCD_OPC_FilterValue, 128, 5, 8, 0, // Skip to: 923
/* 915 */     MCD_OPC_CheckPredicate, 20, 129, 3, // Skip to: 1816
/* 919 */     MCD_OPC_Decode, 215, 2, 67, // Opcode: CVT_D64_W
/* 923 */     MCD_OPC_FilterValue, 160, 5, 120, 3, // Skip to: 1816
/* 928 */     MCD_OPC_CheckPredicate, 20, 116, 3, // Skip to: 1816
/* 932 */     MCD_OPC_Decode, 213, 2, 74, // Opcode: CVT_D64_L
/* 936 */     MCD_OPC_FilterValue, 36, 16, 0, // Skip to: 956
/* 940 */     MCD_OPC_CheckPredicate, 20, 104, 3, // Skip to: 1816
/* 944 */     MCD_OPC_CheckField, 16, 10, 160, 4, 97, 3, // Skip to: 1816
/* 951 */     MCD_OPC_Decode, 223, 2, 186, 1, // Opcode: CVT_W_D64
/* 956 */     MCD_OPC_FilterValue, 48, 21, 0, // Skip to: 981
/* 960 */     MCD_OPC_CheckPredicate, 20, 84, 3, // Skip to: 1816
/* 964 */     MCD_OPC_CheckField, 21, 5, 17, 78, 3, // Skip to: 1816
/* 970 */     MCD_OPC_CheckField, 6, 5, 0, 72, 3, // Skip to: 1816
/* 976 */     MCD_OPC_Decode, 229, 2, 189, 1, // Opcode: C_F_D64
/* 981 */     MCD_OPC_FilterValue, 49, 21, 0, // Skip to: 1006
/* 985 */     MCD_OPC_CheckPredicate, 20, 59, 3, // Skip to: 1816
/* 989 */     MCD_OPC_CheckField, 21, 5, 17, 53, 3, // Skip to: 1816
/* 995 */     MCD_OPC_CheckField, 6, 5, 0, 47, 3, // Skip to: 1816
/* 1001 */    MCD_OPC_Decode, 143, 3, 189, 1, // Opcode: C_UN_D64
/* 1006 */    MCD_OPC_FilterValue, 50, 21, 0, // Skip to: 1031
/* 1010 */    MCD_OPC_CheckPredicate, 20, 34, 3, // Skip to: 1816
/* 1014 */    MCD_OPC_CheckField, 21, 5, 17, 28, 3, // Skip to: 1816
/* 1020 */    MCD_OPC_CheckField, 6, 5, 0, 22, 3, // Skip to: 1816
/* 1026 */    MCD_OPC_Decode, 226, 2, 189, 1, // Opcode: C_EQ_D64
/* 1031 */    MCD_OPC_FilterValue, 51, 21, 0, // Skip to: 1056
/* 1035 */    MCD_OPC_CheckPredicate, 20, 9, 3, // Skip to: 1816
/* 1039 */    MCD_OPC_CheckField, 21, 5, 17, 3, 3, // Skip to: 1816
/* 1045 */    MCD_OPC_CheckField, 6, 5, 0, 253, 2, // Skip to: 1816
/* 1051 */    MCD_OPC_Decode, 134, 3, 189, 1, // Opcode: C_UEQ_D64
/* 1056 */    MCD_OPC_FilterValue, 52, 21, 0, // Skip to: 1081
/* 1060 */    MCD_OPC_CheckPredicate, 20, 240, 2, // Skip to: 1816
/* 1064 */    MCD_OPC_CheckField, 21, 5, 17, 234, 2, // Skip to: 1816
/* 1070 */    MCD_OPC_CheckField, 6, 5, 0, 228, 2, // Skip to: 1816
/* 1076 */    MCD_OPC_Decode, 253, 2, 189, 1, // Opcode: C_OLT_D64
/* 1081 */    MCD_OPC_FilterValue, 53, 21, 0, // Skip to: 1106
/* 1085 */    MCD_OPC_CheckPredicate, 20, 215, 2, // Skip to: 1816
/* 1089 */    MCD_OPC_CheckField, 21, 5, 17, 209, 2, // Skip to: 1816
/* 1095 */    MCD_OPC_CheckField, 6, 5, 0, 203, 2, // Skip to: 1816
/* 1101 */    MCD_OPC_Decode, 140, 3, 189, 1, // Opcode: C_ULT_D64
/* 1106 */    MCD_OPC_FilterValue, 54, 21, 0, // Skip to: 1131
/* 1110 */    MCD_OPC_CheckPredicate, 20, 190, 2, // Skip to: 1816
/* 1114 */    MCD_OPC_CheckField, 21, 5, 17, 184, 2, // Skip to: 1816
/* 1120 */    MCD_OPC_CheckField, 6, 5, 0, 178, 2, // Skip to: 1816
/* 1126 */    MCD_OPC_Decode, 250, 2, 189, 1, // Opcode: C_OLE_D64
/* 1131 */    MCD_OPC_FilterValue, 55, 21, 0, // Skip to: 1156
/* 1135 */    MCD_OPC_CheckPredicate, 20, 165, 2, // Skip to: 1816
/* 1139 */    MCD_OPC_CheckField, 21, 5, 17, 159, 2, // Skip to: 1816
/* 1145 */    MCD_OPC_CheckField, 6, 5, 0, 153, 2, // Skip to: 1816
/* 1151 */    MCD_OPC_Decode, 137, 3, 189, 1, // Opcode: C_ULE_D64
/* 1156 */    MCD_OPC_FilterValue, 56, 21, 0, // Skip to: 1181
/* 1160 */    MCD_OPC_CheckPredicate, 20, 140, 2, // Skip to: 1816
/* 1164 */    MCD_OPC_CheckField, 21, 5, 17, 134, 2, // Skip to: 1816
/* 1170 */    MCD_OPC_CheckField, 6, 5, 0, 128, 2, // Skip to: 1816
/* 1176 */    MCD_OPC_Decode, 131, 3, 189, 1, // Opcode: C_SF_D64
/* 1181 */    MCD_OPC_FilterValue, 57, 21, 0, // Skip to: 1206
/* 1185 */    MCD_OPC_CheckPredicate, 20, 115, 2, // Skip to: 1816
/* 1189 */    MCD_OPC_CheckField, 21, 5, 17, 109, 2, // Skip to: 1816
/* 1195 */    MCD_OPC_CheckField, 6, 5, 0, 103, 2, // Skip to: 1816
/* 1201 */    MCD_OPC_Decode, 241, 2, 189, 1, // Opcode: C_NGLE_D64
/* 1206 */    MCD_OPC_FilterValue, 58, 21, 0, // Skip to: 1231
/* 1210 */    MCD_OPC_CheckPredicate, 20, 90, 2, // Skip to: 1816
/* 1214 */    MCD_OPC_CheckField, 21, 5, 17, 84, 2, // Skip to: 1816
/* 1220 */    MCD_OPC_CheckField, 6, 5, 0, 78, 2, // Skip to: 1816
/* 1226 */    MCD_OPC_Decode, 128, 3, 189, 1, // Opcode: C_SEQ_D64
/* 1231 */    MCD_OPC_FilterValue, 59, 21, 0, // Skip to: 1256
/* 1235 */    MCD_OPC_CheckPredicate, 20, 65, 2, // Skip to: 1816
/* 1239 */    MCD_OPC_CheckField, 21, 5, 17, 59, 2, // Skip to: 1816
/* 1245 */    MCD_OPC_CheckField, 6, 5, 0, 53, 2, // Skip to: 1816
/* 1251 */    MCD_OPC_Decode, 244, 2, 189, 1, // Opcode: C_NGL_D64
/* 1256 */    MCD_OPC_FilterValue, 60, 21, 0, // Skip to: 1281
/* 1260 */    MCD_OPC_CheckPredicate, 20, 40, 2, // Skip to: 1816
/* 1264 */    MCD_OPC_CheckField, 21, 5, 17, 34, 2, // Skip to: 1816
/* 1270 */    MCD_OPC_CheckField, 6, 5, 0, 28, 2, // Skip to: 1816
/* 1276 */    MCD_OPC_Decode, 235, 2, 189, 1, // Opcode: C_LT_D64
/* 1281 */    MCD_OPC_FilterValue, 61, 21, 0, // Skip to: 1306
/* 1285 */    MCD_OPC_CheckPredicate, 20, 15, 2, // Skip to: 1816
/* 1289 */    MCD_OPC_CheckField, 21, 5, 17, 9, 2, // Skip to: 1816
/* 1295 */    MCD_OPC_CheckField, 6, 5, 0, 3, 2, // Skip to: 1816
/* 1301 */    MCD_OPC_Decode, 238, 2, 189, 1, // Opcode: C_NGE_D64
/* 1306 */    MCD_OPC_FilterValue, 62, 21, 0, // Skip to: 1331
/* 1310 */    MCD_OPC_CheckPredicate, 20, 246, 1, // Skip to: 1816
/* 1314 */    MCD_OPC_CheckField, 21, 5, 17, 240, 1, // Skip to: 1816
/* 1320 */    MCD_OPC_CheckField, 6, 5, 0, 234, 1, // Skip to: 1816
/* 1326 */    MCD_OPC_Decode, 232, 2, 189, 1, // Opcode: C_LE_D64
/* 1331 */    MCD_OPC_FilterValue, 63, 225, 1, // Skip to: 1816
/* 1335 */    MCD_OPC_CheckPredicate, 20, 221, 1, // Skip to: 1816
/* 1339 */    MCD_OPC_CheckField, 21, 5, 17, 215, 1, // Skip to: 1816
/* 1345 */    MCD_OPC_CheckField, 6, 5, 0, 209, 1, // Skip to: 1816
/* 1351 */    MCD_OPC_Decode, 247, 2, 189, 1, // Opcode: C_NGT_D64
/* 1356 */    MCD_OPC_FilterValue, 18, 41, 0, // Skip to: 1401
/* 1360 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1363 */    MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 1382
/* 1367 */    MCD_OPC_CheckPredicate, 19, 189, 1, // Skip to: 1816
/* 1371 */    MCD_OPC_CheckField, 3, 8, 0, 183, 1, // Skip to: 1816
/* 1377 */    MCD_OPC_Decode, 173, 3, 184, 1, // Opcode: DMFC2
/* 1382 */    MCD_OPC_FilterValue, 5, 174, 1, // Skip to: 1816
/* 1386 */    MCD_OPC_CheckPredicate, 19, 170, 1, // Skip to: 1816
/* 1390 */    MCD_OPC_CheckField, 3, 8, 0, 164, 1, // Skip to: 1816
/* 1396 */    MCD_OPC_Decode, 176, 3, 184, 1, // Opcode: DMTC2
/* 1401 */    MCD_OPC_FilterValue, 19, 79, 0, // Skip to: 1484
/* 1405 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1408 */    MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 1427
/* 1412 */    MCD_OPC_CheckPredicate, 21, 144, 1, // Skip to: 1816
/* 1416 */    MCD_OPC_CheckField, 11, 5, 0, 138, 1, // Skip to: 1816
/* 1422 */    MCD_OPC_Decode, 215, 5, 190, 1, // Opcode: LDXC164
/* 1427 */    MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 1446
/* 1431 */    MCD_OPC_CheckPredicate, 20, 125, 1, // Skip to: 1816
/* 1435 */    MCD_OPC_CheckField, 11, 5, 0, 119, 1, // Skip to: 1816
/* 1441 */    MCD_OPC_Decode, 237, 5, 190, 1, // Opcode: LUXC164
/* 1446 */    MCD_OPC_FilterValue, 9, 15, 0, // Skip to: 1465
/* 1450 */    MCD_OPC_CheckPredicate, 21, 106, 1, // Skip to: 1816
/* 1454 */    MCD_OPC_CheckField, 6, 5, 0, 100, 1, // Skip to: 1816
/* 1460 */    MCD_OPC_Decode, 216, 8, 191, 1, // Opcode: SDXC164
/* 1465 */    MCD_OPC_FilterValue, 13, 91, 1, // Skip to: 1816
/* 1469 */    MCD_OPC_CheckPredicate, 20, 87, 1, // Skip to: 1816
/* 1473 */    MCD_OPC_CheckField, 6, 5, 0, 81, 1, // Skip to: 1816
/* 1479 */    MCD_OPC_Decode, 134, 10, 191, 1, // Opcode: SUXC164
/* 1484 */    MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 1497
/* 1488 */    MCD_OPC_CheckPredicate, 2, 68, 1, // Skip to: 1816
/* 1492 */    MCD_OPC_Decode, 150, 3, 192, 1, // Opcode: DADDi
/* 1497 */    MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 1510
/* 1501 */    MCD_OPC_CheckPredicate, 2, 55, 1, // Skip to: 1816
/* 1505 */    MCD_OPC_Decode, 151, 3, 192, 1, // Opcode: DADDiu
/* 1510 */    MCD_OPC_FilterValue, 26, 9, 0, // Skip to: 1523
/* 1514 */    MCD_OPC_CheckPredicate, 2, 42, 1, // Skip to: 1816
/* 1518 */    MCD_OPC_Decode, 212, 5, 178, 1, // Opcode: LDL
/* 1523 */    MCD_OPC_FilterValue, 27, 9, 0, // Skip to: 1536
/* 1527 */    MCD_OPC_CheckPredicate, 2, 29, 1, // Skip to: 1816
/* 1531 */    MCD_OPC_Decode, 213, 5, 178, 1, // Opcode: LDR
/* 1536 */    MCD_OPC_FilterValue, 28, 29, 0, // Skip to: 1569
/* 1540 */    MCD_OPC_ExtractField, 0, 11,  // Inst{10-0} ...
/* 1543 */    MCD_OPC_FilterValue, 36, 9, 0, // Skip to: 1556
/* 1547 */    MCD_OPC_CheckPredicate, 13, 9, 1, // Skip to: 1816
/* 1551 */    MCD_OPC_Decode, 154, 3, 193, 1, // Opcode: DCLZ
/* 1556 */    MCD_OPC_FilterValue, 37, 0, 1, // Skip to: 1816
/* 1560 */    MCD_OPC_CheckPredicate, 13, 252, 0, // Skip to: 1816
/* 1564 */    MCD_OPC_Decode, 153, 3, 193, 1, // Opcode: DCLO
/* 1569 */    MCD_OPC_FilterValue, 31, 126, 0, // Skip to: 1699
/* 1573 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1576 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 1589
/* 1580 */    MCD_OPC_CheckPredicate, 3, 232, 0, // Skip to: 1816
/* 1584 */    MCD_OPC_Decode, 157, 3, 194, 1, // Opcode: DEXTM
/* 1589 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 1602
/* 1593 */    MCD_OPC_CheckPredicate, 3, 219, 0, // Skip to: 1816
/* 1597 */    MCD_OPC_Decode, 158, 3, 194, 1, // Opcode: DEXTU
/* 1602 */    MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 1615
/* 1606 */    MCD_OPC_CheckPredicate, 3, 206, 0, // Skip to: 1816
/* 1610 */    MCD_OPC_Decode, 156, 3, 194, 1, // Opcode: DEXT
/* 1615 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 1628
/* 1619 */    MCD_OPC_CheckPredicate, 3, 193, 0, // Skip to: 1816
/* 1623 */    MCD_OPC_Decode, 161, 3, 195, 1, // Opcode: DINSM
/* 1628 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 1641
/* 1632 */    MCD_OPC_CheckPredicate, 3, 180, 0, // Skip to: 1816
/* 1636 */    MCD_OPC_Decode, 162, 3, 195, 1, // Opcode: DINSU
/* 1641 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 1654
/* 1645 */    MCD_OPC_CheckPredicate, 3, 167, 0, // Skip to: 1816
/* 1649 */    MCD_OPC_Decode, 160, 3, 195, 1, // Opcode: DINS
/* 1654 */    MCD_OPC_FilterValue, 36, 158, 0, // Skip to: 1816
/* 1658 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 1661 */    MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 1680
/* 1665 */    MCD_OPC_CheckPredicate, 15, 147, 0, // Skip to: 1816
/* 1669 */    MCD_OPC_CheckField, 21, 5, 0, 141, 0, // Skip to: 1816
/* 1675 */    MCD_OPC_Decode, 216, 3, 196, 1, // Opcode: DSBH
/* 1680 */    MCD_OPC_FilterValue, 5, 132, 0, // Skip to: 1816
/* 1684 */    MCD_OPC_CheckPredicate, 15, 128, 0, // Skip to: 1816
/* 1688 */    MCD_OPC_CheckField, 21, 5, 0, 122, 0, // Skip to: 1816
/* 1694 */    MCD_OPC_Decode, 218, 3, 196, 1, // Opcode: DSHD
/* 1699 */    MCD_OPC_FilterValue, 39, 9, 0, // Skip to: 1712
/* 1703 */    MCD_OPC_CheckPredicate, 2, 109, 0, // Skip to: 1816
/* 1707 */    MCD_OPC_Decode, 254, 5, 178, 1, // Opcode: LWu
/* 1712 */    MCD_OPC_FilterValue, 44, 9, 0, // Skip to: 1725
/* 1716 */    MCD_OPC_CheckPredicate, 2, 96, 0, // Skip to: 1816
/* 1720 */    MCD_OPC_Decode, 213, 8, 178, 1, // Opcode: SDL
/* 1725 */    MCD_OPC_FilterValue, 45, 9, 0, // Skip to: 1738
/* 1729 */    MCD_OPC_CheckPredicate, 2, 83, 0, // Skip to: 1816
/* 1733 */    MCD_OPC_Decode, 214, 8, 178, 1, // Opcode: SDR
/* 1738 */    MCD_OPC_FilterValue, 52, 9, 0, // Skip to: 1751
/* 1742 */    MCD_OPC_CheckPredicate, 2, 70, 0, // Skip to: 1816
/* 1746 */    MCD_OPC_Decode, 230, 5, 178, 1, // Opcode: LLD
/* 1751 */    MCD_OPC_FilterValue, 53, 9, 0, // Skip to: 1764
/* 1755 */    MCD_OPC_CheckPredicate, 20, 57, 0, // Skip to: 1816
/* 1759 */    MCD_OPC_Decode, 206, 5, 179, 1, // Opcode: LDC164
/* 1764 */    MCD_OPC_FilterValue, 55, 9, 0, // Skip to: 1777
/* 1768 */    MCD_OPC_CheckPredicate, 2, 44, 0, // Skip to: 1816
/* 1772 */    MCD_OPC_Decode, 204, 5, 178, 1, // Opcode: LD
/* 1777 */    MCD_OPC_FilterValue, 60, 9, 0, // Skip to: 1790
/* 1781 */    MCD_OPC_CheckPredicate, 2, 31, 0, // Skip to: 1816
/* 1785 */    MCD_OPC_Decode, 206, 8, 178, 1, // Opcode: SCD
/* 1790 */    MCD_OPC_FilterValue, 61, 9, 0, // Skip to: 1803
/* 1794 */    MCD_OPC_CheckPredicate, 20, 18, 0, // Skip to: 1816
/* 1798 */    MCD_OPC_Decode, 209, 8, 179, 1, // Opcode: SDC164
/* 1803 */    MCD_OPC_FilterValue, 63, 9, 0, // Skip to: 1816
/* 1807 */    MCD_OPC_CheckPredicate, 2, 5, 0, // Skip to: 1816
/* 1811 */    MCD_OPC_Decode, 207, 8, 178, 1, // Opcode: SD
/* 1816 */    MCD_OPC_Fail,
  0
};

static bool checkDecoderPredicate(unsigned Idx, uint64_t Bits)
{
  //printf(">>-- Idx: %u\n", Idx);
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
    return ((Bits & Mips_FeatureFPIdx) && !(Bits & Mips_FeatureFP64Bit) && !(Bits & Mips_FeatureMips16));
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

static DecodeStatus decodeToMCInst(DecodeStatus S, unsigned Idx, uint32_t insn, MCInst *MI,
       uint64_t Address, MCRegisterInfo *Decoder)
{
  uint32_t tmp;

  switch (Idx) {
  default: // llvm_unreachable("Invalid index!");
  case 0:
    return S;
  case 1:
    tmp = fieldFromInstruction(insn, 8, 3);
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 2:
    tmp = fieldFromInstruction(insn, 8, 3);
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 8, 3);
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
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
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 12, 4);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
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
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 20:
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 21:
    if (DecodeMemMMImm16(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 22:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    if (DecodeBranchTargetMM(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 23:
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
    tmp = fieldFromInstruction(insn, 0, 16);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 25:
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 13, 3);
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 26:
    if (DecodeMemMMImm12(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
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
    if (DecodeLSAImm(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
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
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 50:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 51:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 3);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 52:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 53:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 54:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeCCRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 55:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGRH32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 56:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 57:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 58:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeCCRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 59:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGRH32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 60:
    tmp = fieldFromInstruction(insn, 18, 3);
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 61:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 62:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 63:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 64:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 18, 3);
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 65:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 66:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 67:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 68:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 69:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 70:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 71:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 72:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 18, 3);
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 73:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 74:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 75:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 76:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 77:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 78:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 79:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 80:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 81:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 82:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 83:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 84:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 85:
    tmp = fieldFromInstruction(insn, 11, 2);
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 2);
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 86:
    tmp = 0;
    tmp |= (fieldFromInstruction(insn, 11, 5) << 0);
    tmp |= (fieldFromInstruction(insn, 16, 5) << 0);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 87:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 8);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 88:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 8);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 89:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 8);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 90:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 8);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 91:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 92:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 93:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 94:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 95:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 10);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 96:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 10);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 97:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 10);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 98:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 10);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 99:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 6);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 100:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 4);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 101:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 3);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 102:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 6);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 103:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 104:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 4);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 105:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 3);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 106:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 107:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 108:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 109:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 110:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 111:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 112:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 113:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 114:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 115:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 116:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 117:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 118:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 119:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 120:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 121:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 122:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 123:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 124:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 4);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 125:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 3);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 126:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 2);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 127:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 1);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 128:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSACtrlRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 129:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSACtrlRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 130:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 4);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 131:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 3);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 132:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 2);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 133:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 134:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 4);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 135:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 3);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 136:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 2);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 137:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 4);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 138:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 3);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 139:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 2);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 140:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 1);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 141:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 142:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 143:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 144:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 145:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 146:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 147:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 148:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 149:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 150:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 151:
    if (DecodeMSA128Mem(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 152:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeExtSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 153:
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
  case 154:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 155:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 156:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 157:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 158:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 159:
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 160:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 161:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 162:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 163:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 10);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 164:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 165:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 166:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 167:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 168:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 169:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 170:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 171:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 2);
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 172:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 2);
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 173:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 10);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 174:
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 10);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 175:
    tmp = fieldFromInstruction(insn, 11, 2);
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 20, 6);
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 2);
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 176:
    tmp = fieldFromInstruction(insn, 11, 2);
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 2);
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 177:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeHWRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 178:
    if (DecodeMem(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 179:
    if (DecodeFMem(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 180:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 181:
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 182:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 183:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 184:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 3);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    return S;
  case 185:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 186:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 187:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 18, 3);
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 188:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 189:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 190:
    tmp = fieldFromInstruction(insn, 6, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 191:
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 192:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 0, 16);
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 193:
    tmp = 0;
    tmp |= (fieldFromInstruction(insn, 11, 5) << 0);
    tmp |= (fieldFromInstruction(insn, 16, 5) << 0);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 194:
    tmp = fieldFromInstruction(insn, 16, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 21, 5);
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    tmp = fieldFromInstruction(insn, 6, 5);
    MCInst_addOperand(MI, MCOperand_CreateImm(tmp));
    tmp = fieldFromInstruction(insn, 11, 5);
    if (DecodeExtSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail;
    return S;
  case 195:
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
  case 196:
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
  uint8_t *Ptr = DecodeTable;
  uint32_t CurFieldValue = 0;
  DecodeStatus S = MCDisassembler_Success;
  for (;;) {
    //printf(">>> Loc: %lx\n", Ptr - DecodeTable);
    switch (*Ptr) {
    default:
      return MCDisassembler_Fail;
    case MCD_OPC_ExtractField: {
      unsigned Start = *++Ptr;
      unsigned Len = *++Ptr;
      ++Ptr;
      CurFieldValue = fieldFromInstruction(insn, Start, Len);
      break;
    }
    case MCD_OPC_FilterValue: {
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

      break;
    }
    case MCD_OPC_CheckField: {
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
      break;
    }
    case MCD_OPC_CheckPredicate: {
      unsigned Len;
      // Decode the Predicate Index value.
      unsigned PIdx = decodeULEB128(++Ptr, &Len);
      Ptr += Len;
      // NumToSkip is a plain 16-bit integer.
      unsigned NumToSkip = *Ptr++;
      NumToSkip |= (*Ptr++) << 8;
      // Check the predicate.
      bool Pred;
      if (!(Pred = checkDecoderPredicate(PIdx, Bits)))
        Ptr += NumToSkip;
      (void)Pred;

      break;
    }
    case MCD_OPC_Decode: {
      unsigned Len;
      // Decode the Opcode value.
      unsigned Opc = decodeULEB128(++Ptr, &Len);
      Ptr += Len;
      unsigned DecodeIdx = decodeULEB128(Ptr, &Len);

      MCInst_setOpcode(MI, Opc);
      return decodeToMCInst(S, DecodeIdx, insn, MI, Address, MRI);
    }
    case MCD_OPC_SoftFail: {
      // Decode the mask values.
      unsigned Len;
      uint32_t PositiveMask = decodeULEB128(++Ptr, &Len);
      Ptr += Len;
      uint32_t NegativeMask = decodeULEB128(Ptr, &Len);
      Ptr += Len;
      bool Fail = (insn & PositiveMask) || (~insn & NegativeMask);
      if (Fail)
        S = MCDisassembler_SoftFail;

      break;
    }
    case MCD_OPC_Fail: {
      return MCDisassembler_Fail;
    }
    }
  }
}

