/* Capstone Disassembly Engine, https://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/*    Rot127 <unisono@quyllur.org> 2022-2023 */
/* Automatically generated file by Capstone's LLVM TableGen Disassembler Backend. */

/* LLVM-commit: 083d57d0731afc1746680d828bdfe2fa41f62a61 */
/* LLVM-tag: llvmorg-3.0.0-2-g083d57d0731a */

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

static const uint8_t DecoderTable32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 12
/* 8 */       MCD_OPC_Decode, 190, 2, 0, // Opcode: COND_BRANCH_I
/* 12 */      MCD_OPC_FilterValue, 8, 4, 0, 0, // Skip to: 21
/* 17 */      MCD_OPC_Decode, 144, 3, 1, // Opcode: LDA
/* 21 */      MCD_OPC_FilterValue, 9, 4, 0, 0, // Skip to: 30
/* 26 */      MCD_OPC_Decode, 145, 3, 1, // Opcode: LDAH
/* 30 */      MCD_OPC_FilterValue, 10, 4, 0, 0, // Skip to: 39
/* 35 */      MCD_OPC_Decode, 150, 3, 1, // Opcode: LDBU
/* 39 */      MCD_OPC_FilterValue, 11, 4, 0, 0, // Skip to: 48
/* 44 */      MCD_OPC_Decode, 157, 3, 1, // Opcode: LDQ_U
/* 48 */      MCD_OPC_FilterValue, 12, 4, 0, 0, // Skip to: 57
/* 53 */      MCD_OPC_Decode, 164, 3, 1, // Opcode: LDWU
/* 57 */      MCD_OPC_FilterValue, 13, 4, 0, 0, // Skip to: 66
/* 62 */      MCD_OPC_Decode, 233, 3, 1, // Opcode: STW
/* 66 */      MCD_OPC_FilterValue, 14, 4, 0, 0, // Skip to: 75
/* 71 */      MCD_OPC_Decode, 220, 3, 1, // Opcode: STB
/* 75 */      MCD_OPC_FilterValue, 15, 4, 0, 0, // Skip to: 84
/* 80 */      MCD_OPC_Decode, 227, 3, 1, // Opcode: STQ_U
/* 84 */      MCD_OPC_FilterValue, 16, 215, 1, 0, // Skip to: 560
/* 89 */      MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 92 */      MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 108
/* 97 */      MCD_OPC_CheckField, 13, 3, 0, 43, 10, 0, // Skip to: 2707
/* 104 */     MCD_OPC_Decode, 136, 2, 2, // Opcode: ADDLr
/* 108 */     MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 124
/* 113 */     MCD_OPC_CheckField, 13, 3, 0, 27, 10, 0, // Skip to: 2707
/* 120 */     MCD_OPC_Decode, 195, 3, 2, // Opcode: S4ADDLr
/* 124 */     MCD_OPC_FilterValue, 9, 11, 0, 0, // Skip to: 140
/* 129 */     MCD_OPC_CheckField, 13, 3, 0, 11, 10, 0, // Skip to: 2707
/* 136 */     MCD_OPC_Decode, 236, 3, 2, // Opcode: SUBLr
/* 140 */     MCD_OPC_FilterValue, 11, 11, 0, 0, // Skip to: 156
/* 145 */     MCD_OPC_CheckField, 13, 3, 0, 251, 9, 0, // Skip to: 2707
/* 152 */     MCD_OPC_Decode, 199, 3, 2, // Opcode: S4SUBLr
/* 156 */     MCD_OPC_FilterValue, 15, 11, 0, 0, // Skip to: 172
/* 161 */     MCD_OPC_CheckField, 13, 3, 0, 235, 9, 0, // Skip to: 2707
/* 168 */     MCD_OPC_Decode, 173, 2, 2, // Opcode: CMPBGE
/* 172 */     MCD_OPC_FilterValue, 18, 11, 0, 0, // Skip to: 188
/* 177 */     MCD_OPC_CheckField, 13, 3, 0, 219, 9, 0, // Skip to: 2707
/* 184 */     MCD_OPC_Decode, 203, 3, 2, // Opcode: S8ADDLr
/* 188 */     MCD_OPC_FilterValue, 27, 11, 0, 0, // Skip to: 204
/* 193 */     MCD_OPC_CheckField, 13, 3, 0, 203, 9, 0, // Skip to: 2707
/* 200 */     MCD_OPC_Decode, 207, 3, 2, // Opcode: S8SUBLr
/* 204 */     MCD_OPC_FilterValue, 29, 11, 0, 0, // Skip to: 220
/* 209 */     MCD_OPC_CheckField, 13, 3, 0, 187, 9, 0, // Skip to: 2707
/* 216 */     MCD_OPC_Decode, 187, 2, 2, // Opcode: CMPULT
/* 220 */     MCD_OPC_FilterValue, 32, 11, 0, 0, // Skip to: 236
/* 225 */     MCD_OPC_CheckField, 13, 3, 0, 171, 9, 0, // Skip to: 2707
/* 232 */     MCD_OPC_Decode, 138, 2, 2, // Opcode: ADDQr
/* 236 */     MCD_OPC_FilterValue, 34, 11, 0, 0, // Skip to: 252
/* 241 */     MCD_OPC_CheckField, 13, 3, 0, 155, 9, 0, // Skip to: 2707
/* 248 */     MCD_OPC_Decode, 197, 3, 2, // Opcode: S4ADDQr
/* 252 */     MCD_OPC_FilterValue, 41, 11, 0, 0, // Skip to: 268
/* 257 */     MCD_OPC_CheckField, 13, 3, 0, 139, 9, 0, // Skip to: 2707
/* 264 */     MCD_OPC_Decode, 238, 3, 2, // Opcode: SUBQr
/* 268 */     MCD_OPC_FilterValue, 43, 11, 0, 0, // Skip to: 284
/* 273 */     MCD_OPC_CheckField, 13, 3, 0, 123, 9, 0, // Skip to: 2707
/* 280 */     MCD_OPC_Decode, 201, 3, 2, // Opcode: S4SUBQr
/* 284 */     MCD_OPC_FilterValue, 45, 11, 0, 0, // Skip to: 300
/* 289 */     MCD_OPC_CheckField, 13, 3, 0, 107, 9, 0, // Skip to: 2707
/* 296 */     MCD_OPC_Decode, 175, 2, 2, // Opcode: CMPEQ
/* 300 */     MCD_OPC_FilterValue, 50, 11, 0, 0, // Skip to: 316
/* 305 */     MCD_OPC_CheckField, 13, 3, 0, 91, 9, 0, // Skip to: 2707
/* 312 */     MCD_OPC_Decode, 205, 3, 2, // Opcode: S8ADDQr
/* 316 */     MCD_OPC_FilterValue, 59, 11, 0, 0, // Skip to: 332
/* 321 */     MCD_OPC_CheckField, 13, 3, 0, 75, 9, 0, // Skip to: 2707
/* 328 */     MCD_OPC_Decode, 209, 3, 2, // Opcode: S8SUBQr
/* 332 */     MCD_OPC_FilterValue, 61, 11, 0, 0, // Skip to: 348
/* 337 */     MCD_OPC_CheckField, 13, 3, 0, 59, 9, 0, // Skip to: 2707
/* 344 */     MCD_OPC_Decode, 185, 2, 2, // Opcode: CMPULE
/* 348 */     MCD_OPC_FilterValue, 77, 11, 0, 0, // Skip to: 364
/* 353 */     MCD_OPC_CheckField, 13, 3, 0, 43, 9, 0, // Skip to: 2707
/* 360 */     MCD_OPC_Decode, 179, 2, 2, // Opcode: CMPLT
/* 364 */     MCD_OPC_FilterValue, 109, 11, 0, 0, // Skip to: 380
/* 369 */     MCD_OPC_CheckField, 13, 3, 0, 27, 9, 0, // Skip to: 2707
/* 376 */     MCD_OPC_Decode, 177, 2, 2, // Opcode: CMPLE
/* 380 */     MCD_OPC_FilterValue, 128, 1, 4, 0, 0, // Skip to: 390
/* 386 */     MCD_OPC_Decode, 135, 2, 3, // Opcode: ADDLi
/* 390 */     MCD_OPC_FilterValue, 130, 1, 4, 0, 0, // Skip to: 400
/* 396 */     MCD_OPC_Decode, 194, 3, 3, // Opcode: S4ADDLi
/* 400 */     MCD_OPC_FilterValue, 137, 1, 4, 0, 0, // Skip to: 410
/* 406 */     MCD_OPC_Decode, 235, 3, 3, // Opcode: SUBLi
/* 410 */     MCD_OPC_FilterValue, 139, 1, 4, 0, 0, // Skip to: 420
/* 416 */     MCD_OPC_Decode, 198, 3, 3, // Opcode: S4SUBLi
/* 420 */     MCD_OPC_FilterValue, 143, 1, 4, 0, 0, // Skip to: 430
/* 426 */     MCD_OPC_Decode, 174, 2, 3, // Opcode: CMPBGEi
/* 430 */     MCD_OPC_FilterValue, 146, 1, 4, 0, 0, // Skip to: 440
/* 436 */     MCD_OPC_Decode, 202, 3, 3, // Opcode: S8ADDLi
/* 440 */     MCD_OPC_FilterValue, 155, 1, 4, 0, 0, // Skip to: 450
/* 446 */     MCD_OPC_Decode, 206, 3, 3, // Opcode: S8SUBLi
/* 450 */     MCD_OPC_FilterValue, 157, 1, 4, 0, 0, // Skip to: 460
/* 456 */     MCD_OPC_Decode, 188, 2, 3, // Opcode: CMPULTi
/* 460 */     MCD_OPC_FilterValue, 160, 1, 4, 0, 0, // Skip to: 470
/* 466 */     MCD_OPC_Decode, 137, 2, 3, // Opcode: ADDQi
/* 470 */     MCD_OPC_FilterValue, 162, 1, 4, 0, 0, // Skip to: 480
/* 476 */     MCD_OPC_Decode, 196, 3, 3, // Opcode: S4ADDQi
/* 480 */     MCD_OPC_FilterValue, 169, 1, 4, 0, 0, // Skip to: 490
/* 486 */     MCD_OPC_Decode, 237, 3, 3, // Opcode: SUBQi
/* 490 */     MCD_OPC_FilterValue, 171, 1, 4, 0, 0, // Skip to: 500
/* 496 */     MCD_OPC_Decode, 200, 3, 3, // Opcode: S4SUBQi
/* 500 */     MCD_OPC_FilterValue, 173, 1, 4, 0, 0, // Skip to: 510
/* 506 */     MCD_OPC_Decode, 176, 2, 3, // Opcode: CMPEQi
/* 510 */     MCD_OPC_FilterValue, 178, 1, 4, 0, 0, // Skip to: 520
/* 516 */     MCD_OPC_Decode, 204, 3, 3, // Opcode: S8ADDQi
/* 520 */     MCD_OPC_FilterValue, 187, 1, 4, 0, 0, // Skip to: 530
/* 526 */     MCD_OPC_Decode, 208, 3, 3, // Opcode: S8SUBQi
/* 530 */     MCD_OPC_FilterValue, 189, 1, 4, 0, 0, // Skip to: 540
/* 536 */     MCD_OPC_Decode, 186, 2, 3, // Opcode: CMPULEi
/* 540 */     MCD_OPC_FilterValue, 205, 1, 4, 0, 0, // Skip to: 550
/* 546 */     MCD_OPC_Decode, 180, 2, 3, // Opcode: CMPLTi
/* 550 */     MCD_OPC_FilterValue, 237, 1, 103, 8, 0, // Skip to: 2707
/* 556 */     MCD_OPC_Decode, 178, 2, 3, // Opcode: CMPLEi
/* 560 */     MCD_OPC_FilterValue, 17, 111, 1, 0, // Skip to: 932
/* 565 */     MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 568 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 584
/* 573 */     MCD_OPC_CheckField, 13, 3, 0, 79, 8, 0, // Skip to: 2707
/* 580 */     MCD_OPC_Decode, 142, 2, 2, // Opcode: ANDr
/* 584 */     MCD_OPC_FilterValue, 8, 11, 0, 0, // Skip to: 600
/* 589 */     MCD_OPC_CheckField, 13, 3, 0, 63, 8, 0, // Skip to: 2707
/* 596 */     MCD_OPC_Decode, 147, 2, 2, // Opcode: BICr
/* 600 */     MCD_OPC_FilterValue, 20, 11, 0, 0, // Skip to: 616
/* 605 */     MCD_OPC_CheckField, 13, 3, 0, 47, 8, 0, // Skip to: 2707
/* 612 */     MCD_OPC_Decode, 166, 2, 4, // Opcode: CMOVLBSr
/* 616 */     MCD_OPC_FilterValue, 22, 11, 0, 0, // Skip to: 632
/* 621 */     MCD_OPC_CheckField, 13, 3, 0, 31, 8, 0, // Skip to: 2707
/* 628 */     MCD_OPC_Decode, 164, 2, 4, // Opcode: CMOVLBCr
/* 632 */     MCD_OPC_FilterValue, 32, 11, 0, 0, // Skip to: 648
/* 637 */     MCD_OPC_CheckField, 13, 3, 0, 15, 8, 0, // Skip to: 2707
/* 644 */     MCD_OPC_Decode, 149, 2, 2, // Opcode: BISr
/* 648 */     MCD_OPC_FilterValue, 36, 11, 0, 0, // Skip to: 664
/* 653 */     MCD_OPC_CheckField, 13, 3, 0, 255, 7, 0, // Skip to: 2707
/* 660 */     MCD_OPC_Decode, 158, 2, 4, // Opcode: CMOVEQr
/* 664 */     MCD_OPC_FilterValue, 38, 11, 0, 0, // Skip to: 680
/* 669 */     MCD_OPC_CheckField, 13, 3, 0, 239, 7, 0, // Skip to: 2707
/* 676 */     MCD_OPC_Decode, 172, 2, 4, // Opcode: CMOVNEr
/* 680 */     MCD_OPC_FilterValue, 40, 11, 0, 0, // Skip to: 696
/* 685 */     MCD_OPC_CheckField, 13, 3, 0, 223, 7, 0, // Skip to: 2707
/* 692 */     MCD_OPC_Decode, 188, 3, 2, // Opcode: ORNOTr
/* 696 */     MCD_OPC_FilterValue, 64, 11, 0, 0, // Skip to: 712
/* 701 */     MCD_OPC_CheckField, 13, 3, 0, 207, 7, 0, // Skip to: 2707
/* 708 */     MCD_OPC_Decode, 248, 3, 2, // Opcode: XORr
/* 712 */     MCD_OPC_FilterValue, 68, 11, 0, 0, // Skip to: 728
/* 717 */     MCD_OPC_CheckField, 13, 3, 0, 191, 7, 0, // Skip to: 2707
/* 724 */     MCD_OPC_Decode, 170, 2, 4, // Opcode: CMOVLTr
/* 728 */     MCD_OPC_FilterValue, 70, 11, 0, 0, // Skip to: 744
/* 733 */     MCD_OPC_CheckField, 13, 3, 0, 175, 7, 0, // Skip to: 2707
/* 740 */     MCD_OPC_Decode, 160, 2, 4, // Opcode: CMOVGEr
/* 744 */     MCD_OPC_FilterValue, 72, 11, 0, 0, // Skip to: 760
/* 749 */     MCD_OPC_CheckField, 13, 3, 0, 159, 7, 0, // Skip to: 2707
/* 756 */     MCD_OPC_Decode, 214, 2, 2, // Opcode: EQVr
/* 760 */     MCD_OPC_FilterValue, 100, 11, 0, 0, // Skip to: 776
/* 765 */     MCD_OPC_CheckField, 13, 3, 0, 143, 7, 0, // Skip to: 2707
/* 772 */     MCD_OPC_Decode, 168, 2, 4, // Opcode: CMOVLEr
/* 776 */     MCD_OPC_FilterValue, 102, 11, 0, 0, // Skip to: 792
/* 781 */     MCD_OPC_CheckField, 13, 3, 0, 127, 7, 0, // Skip to: 2707
/* 788 */     MCD_OPC_Decode, 162, 2, 4, // Opcode: CMOVGTr
/* 792 */     MCD_OPC_FilterValue, 128, 1, 4, 0, 0, // Skip to: 802
/* 798 */     MCD_OPC_Decode, 141, 2, 3, // Opcode: ANDi
/* 802 */     MCD_OPC_FilterValue, 136, 1, 4, 0, 0, // Skip to: 812
/* 808 */     MCD_OPC_Decode, 146, 2, 3, // Opcode: BICi
/* 812 */     MCD_OPC_FilterValue, 148, 1, 4, 0, 0, // Skip to: 822
/* 818 */     MCD_OPC_Decode, 165, 2, 5, // Opcode: CMOVLBSi
/* 822 */     MCD_OPC_FilterValue, 150, 1, 4, 0, 0, // Skip to: 832
/* 828 */     MCD_OPC_Decode, 163, 2, 5, // Opcode: CMOVLBCi
/* 832 */     MCD_OPC_FilterValue, 160, 1, 4, 0, 0, // Skip to: 842
/* 838 */     MCD_OPC_Decode, 148, 2, 3, // Opcode: BISi
/* 842 */     MCD_OPC_FilterValue, 164, 1, 4, 0, 0, // Skip to: 852
/* 848 */     MCD_OPC_Decode, 157, 2, 5, // Opcode: CMOVEQi
/* 852 */     MCD_OPC_FilterValue, 166, 1, 4, 0, 0, // Skip to: 862
/* 858 */     MCD_OPC_Decode, 171, 2, 5, // Opcode: CMOVNEi
/* 862 */     MCD_OPC_FilterValue, 168, 1, 4, 0, 0, // Skip to: 872
/* 868 */     MCD_OPC_Decode, 187, 3, 3, // Opcode: ORNOTi
/* 872 */     MCD_OPC_FilterValue, 192, 1, 4, 0, 0, // Skip to: 882
/* 878 */     MCD_OPC_Decode, 247, 3, 3, // Opcode: XORi
/* 882 */     MCD_OPC_FilterValue, 196, 1, 4, 0, 0, // Skip to: 892
/* 888 */     MCD_OPC_Decode, 169, 2, 5, // Opcode: CMOVLTi
/* 892 */     MCD_OPC_FilterValue, 198, 1, 4, 0, 0, // Skip to: 902
/* 898 */     MCD_OPC_Decode, 159, 2, 5, // Opcode: CMOVGEi
/* 902 */     MCD_OPC_FilterValue, 200, 1, 4, 0, 0, // Skip to: 912
/* 908 */     MCD_OPC_Decode, 213, 2, 3, // Opcode: EQVi
/* 912 */     MCD_OPC_FilterValue, 228, 1, 4, 0, 0, // Skip to: 922
/* 918 */     MCD_OPC_Decode, 167, 2, 5, // Opcode: CMOVLEi
/* 922 */     MCD_OPC_FilterValue, 230, 1, 243, 6, 0, // Skip to: 2707
/* 928 */     MCD_OPC_Decode, 161, 2, 5, // Opcode: CMOVGTi
/* 932 */     MCD_OPC_FilterValue, 18, 125, 2, 0, // Skip to: 1574
/* 937 */     MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 940 */     MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 956
/* 945 */     MCD_OPC_CheckField, 13, 3, 0, 219, 6, 0, // Skip to: 2707
/* 952 */     MCD_OPC_Decode, 167, 3, 2, // Opcode: MSKBL
/* 956 */     MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 972
/* 961 */     MCD_OPC_CheckField, 13, 3, 0, 203, 6, 0, // Skip to: 2707
/* 968 */     MCD_OPC_Decode, 216, 2, 2, // Opcode: EXTBL
/* 972 */     MCD_OPC_FilterValue, 11, 11, 0, 0, // Skip to: 988
/* 977 */     MCD_OPC_CheckField, 13, 3, 0, 187, 6, 0, // Skip to: 2707
/* 984 */     MCD_OPC_Decode, 252, 2, 2, // Opcode: INSBL
/* 988 */     MCD_OPC_FilterValue, 18, 11, 0, 0, // Skip to: 1004
/* 993 */     MCD_OPC_CheckField, 13, 3, 0, 171, 6, 0, // Skip to: 2707
/* 1000 */    MCD_OPC_Decode, 179, 3, 2, // Opcode: MSKWL
/* 1004 */    MCD_OPC_FilterValue, 22, 11, 0, 0, // Skip to: 1020
/* 1009 */    MCD_OPC_CheckField, 13, 3, 0, 155, 6, 0, // Skip to: 2707
/* 1016 */    MCD_OPC_Decode, 228, 2, 2, // Opcode: EXTWL
/* 1020 */    MCD_OPC_FilterValue, 27, 11, 0, 0, // Skip to: 1036
/* 1025 */    MCD_OPC_CheckField, 13, 3, 0, 139, 6, 0, // Skip to: 2707
/* 1032 */    MCD_OPC_Decode, 136, 3, 2, // Opcode: INSWL
/* 1036 */    MCD_OPC_FilterValue, 34, 11, 0, 0, // Skip to: 1052
/* 1041 */    MCD_OPC_CheckField, 13, 3, 0, 123, 6, 0, // Skip to: 2707
/* 1048 */    MCD_OPC_Decode, 171, 3, 2, // Opcode: MSKLL
/* 1052 */    MCD_OPC_FilterValue, 38, 11, 0, 0, // Skip to: 1068
/* 1057 */    MCD_OPC_CheckField, 13, 3, 0, 107, 6, 0, // Skip to: 2707
/* 1064 */    MCD_OPC_Decode, 220, 2, 2, // Opcode: EXTLL
/* 1068 */    MCD_OPC_FilterValue, 43, 11, 0, 0, // Skip to: 1084
/* 1073 */    MCD_OPC_CheckField, 13, 3, 0, 91, 6, 0, // Skip to: 2707
/* 1080 */    MCD_OPC_Decode, 128, 3, 2, // Opcode: INSLL
/* 1084 */    MCD_OPC_FilterValue, 50, 11, 0, 0, // Skip to: 1100
/* 1089 */    MCD_OPC_CheckField, 13, 3, 0, 75, 6, 0, // Skip to: 2707
/* 1096 */    MCD_OPC_Decode, 175, 3, 2, // Opcode: MSKQL
/* 1100 */    MCD_OPC_FilterValue, 52, 11, 0, 0, // Skip to: 1116
/* 1105 */    MCD_OPC_CheckField, 13, 3, 0, 59, 6, 0, // Skip to: 2707
/* 1112 */    MCD_OPC_Decode, 219, 3, 2, // Opcode: SRLr
/* 1116 */    MCD_OPC_FilterValue, 54, 11, 0, 0, // Skip to: 1132
/* 1121 */    MCD_OPC_CheckField, 13, 3, 0, 43, 6, 0, // Skip to: 2707
/* 1128 */    MCD_OPC_Decode, 224, 2, 2, // Opcode: EXTQL
/* 1132 */    MCD_OPC_FilterValue, 57, 11, 0, 0, // Skip to: 1148
/* 1137 */    MCD_OPC_CheckField, 13, 3, 0, 27, 6, 0, // Skip to: 2707
/* 1144 */    MCD_OPC_Decode, 213, 3, 2, // Opcode: SLr
/* 1148 */    MCD_OPC_FilterValue, 59, 11, 0, 0, // Skip to: 1164
/* 1153 */    MCD_OPC_CheckField, 13, 3, 0, 11, 6, 0, // Skip to: 2707
/* 1160 */    MCD_OPC_Decode, 132, 3, 2, // Opcode: INSQL
/* 1164 */    MCD_OPC_FilterValue, 60, 11, 0, 0, // Skip to: 1180
/* 1169 */    MCD_OPC_CheckField, 13, 3, 0, 251, 5, 0, // Skip to: 2707
/* 1176 */    MCD_OPC_Decode, 217, 3, 2, // Opcode: SRAr
/* 1180 */    MCD_OPC_FilterValue, 82, 11, 0, 0, // Skip to: 1196
/* 1185 */    MCD_OPC_CheckField, 13, 3, 0, 235, 5, 0, // Skip to: 2707
/* 1192 */    MCD_OPC_Decode, 177, 3, 2, // Opcode: MSKWH
/* 1196 */    MCD_OPC_FilterValue, 87, 11, 0, 0, // Skip to: 1212
/* 1201 */    MCD_OPC_CheckField, 13, 3, 0, 219, 5, 0, // Skip to: 2707
/* 1208 */    MCD_OPC_Decode, 134, 3, 2, // Opcode: INSWH
/* 1212 */    MCD_OPC_FilterValue, 90, 11, 0, 0, // Skip to: 1228
/* 1217 */    MCD_OPC_CheckField, 13, 3, 0, 203, 5, 0, // Skip to: 2707
/* 1224 */    MCD_OPC_Decode, 226, 2, 2, // Opcode: EXTWH
/* 1228 */    MCD_OPC_FilterValue, 98, 11, 0, 0, // Skip to: 1244
/* 1233 */    MCD_OPC_CheckField, 13, 3, 0, 187, 5, 0, // Skip to: 2707
/* 1240 */    MCD_OPC_Decode, 169, 3, 2, // Opcode: MSKLH
/* 1244 */    MCD_OPC_FilterValue, 103, 11, 0, 0, // Skip to: 1260
/* 1249 */    MCD_OPC_CheckField, 13, 3, 0, 171, 5, 0, // Skip to: 2707
/* 1256 */    MCD_OPC_Decode, 254, 2, 2, // Opcode: INSLH
/* 1260 */    MCD_OPC_FilterValue, 106, 11, 0, 0, // Skip to: 1276
/* 1265 */    MCD_OPC_CheckField, 13, 3, 0, 155, 5, 0, // Skip to: 2707
/* 1272 */    MCD_OPC_Decode, 218, 2, 2, // Opcode: EXTLH
/* 1276 */    MCD_OPC_FilterValue, 114, 11, 0, 0, // Skip to: 1292
/* 1281 */    MCD_OPC_CheckField, 13, 3, 0, 139, 5, 0, // Skip to: 2707
/* 1288 */    MCD_OPC_Decode, 173, 3, 2, // Opcode: MSKQH
/* 1292 */    MCD_OPC_FilterValue, 119, 11, 0, 0, // Skip to: 1308
/* 1297 */    MCD_OPC_CheckField, 13, 3, 0, 123, 5, 0, // Skip to: 2707
/* 1304 */    MCD_OPC_Decode, 130, 3, 2, // Opcode: INSQH
/* 1308 */    MCD_OPC_FilterValue, 122, 11, 0, 0, // Skip to: 1324
/* 1313 */    MCD_OPC_CheckField, 13, 3, 0, 107, 5, 0, // Skip to: 2707
/* 1320 */    MCD_OPC_Decode, 222, 2, 2, // Opcode: EXTQH
/* 1324 */    MCD_OPC_FilterValue, 130, 1, 4, 0, 0, // Skip to: 1334
/* 1330 */    MCD_OPC_Decode, 168, 3, 3, // Opcode: MSKBLi
/* 1334 */    MCD_OPC_FilterValue, 134, 1, 4, 0, 0, // Skip to: 1344
/* 1340 */    MCD_OPC_Decode, 217, 2, 3, // Opcode: EXTBLi
/* 1344 */    MCD_OPC_FilterValue, 139, 1, 4, 0, 0, // Skip to: 1354
/* 1350 */    MCD_OPC_Decode, 253, 2, 3, // Opcode: INSBLi
/* 1354 */    MCD_OPC_FilterValue, 146, 1, 4, 0, 0, // Skip to: 1364
/* 1360 */    MCD_OPC_Decode, 180, 3, 3, // Opcode: MSKWLi
/* 1364 */    MCD_OPC_FilterValue, 150, 1, 4, 0, 0, // Skip to: 1374
/* 1370 */    MCD_OPC_Decode, 229, 2, 3, // Opcode: EXTWLi
/* 1374 */    MCD_OPC_FilterValue, 155, 1, 4, 0, 0, // Skip to: 1384
/* 1380 */    MCD_OPC_Decode, 137, 3, 3, // Opcode: INSWLi
/* 1384 */    MCD_OPC_FilterValue, 162, 1, 4, 0, 0, // Skip to: 1394
/* 1390 */    MCD_OPC_Decode, 172, 3, 3, // Opcode: MSKLLi
/* 1394 */    MCD_OPC_FilterValue, 166, 1, 4, 0, 0, // Skip to: 1404
/* 1400 */    MCD_OPC_Decode, 221, 2, 3, // Opcode: EXTLLi
/* 1404 */    MCD_OPC_FilterValue, 171, 1, 4, 0, 0, // Skip to: 1414
/* 1410 */    MCD_OPC_Decode, 129, 3, 3, // Opcode: INSLLi
/* 1414 */    MCD_OPC_FilterValue, 177, 1, 4, 0, 0, // Skip to: 1424
/* 1420 */    MCD_OPC_Decode, 249, 3, 3, // Opcode: ZAPNOTi
/* 1424 */    MCD_OPC_FilterValue, 178, 1, 4, 0, 0, // Skip to: 1434
/* 1430 */    MCD_OPC_Decode, 176, 3, 3, // Opcode: MSKQLi
/* 1434 */    MCD_OPC_FilterValue, 180, 1, 4, 0, 0, // Skip to: 1444
/* 1440 */    MCD_OPC_Decode, 218, 3, 3, // Opcode: SRLi
/* 1444 */    MCD_OPC_FilterValue, 182, 1, 4, 0, 0, // Skip to: 1454
/* 1450 */    MCD_OPC_Decode, 225, 2, 3, // Opcode: EXTQLi
/* 1454 */    MCD_OPC_FilterValue, 185, 1, 4, 0, 0, // Skip to: 1464
/* 1460 */    MCD_OPC_Decode, 212, 3, 3, // Opcode: SLi
/* 1464 */    MCD_OPC_FilterValue, 187, 1, 4, 0, 0, // Skip to: 1474
/* 1470 */    MCD_OPC_Decode, 133, 3, 3, // Opcode: INSQLi
/* 1474 */    MCD_OPC_FilterValue, 188, 1, 4, 0, 0, // Skip to: 1484
/* 1480 */    MCD_OPC_Decode, 216, 3, 3, // Opcode: SRAi
/* 1484 */    MCD_OPC_FilterValue, 210, 1, 4, 0, 0, // Skip to: 1494
/* 1490 */    MCD_OPC_Decode, 178, 3, 3, // Opcode: MSKWHi
/* 1494 */    MCD_OPC_FilterValue, 215, 1, 4, 0, 0, // Skip to: 1504
/* 1500 */    MCD_OPC_Decode, 135, 3, 3, // Opcode: INSWHi
/* 1504 */    MCD_OPC_FilterValue, 218, 1, 4, 0, 0, // Skip to: 1514
/* 1510 */    MCD_OPC_Decode, 227, 2, 3, // Opcode: EXTWHi
/* 1514 */    MCD_OPC_FilterValue, 226, 1, 4, 0, 0, // Skip to: 1524
/* 1520 */    MCD_OPC_Decode, 170, 3, 3, // Opcode: MSKLHi
/* 1524 */    MCD_OPC_FilterValue, 231, 1, 4, 0, 0, // Skip to: 1534
/* 1530 */    MCD_OPC_Decode, 255, 2, 3, // Opcode: INSLHi
/* 1534 */    MCD_OPC_FilterValue, 234, 1, 4, 0, 0, // Skip to: 1544
/* 1540 */    MCD_OPC_Decode, 219, 2, 3, // Opcode: EXTLHi
/* 1544 */    MCD_OPC_FilterValue, 242, 1, 4, 0, 0, // Skip to: 1554
/* 1550 */    MCD_OPC_Decode, 174, 3, 3, // Opcode: MSKQHi
/* 1554 */    MCD_OPC_FilterValue, 247, 1, 4, 0, 0, // Skip to: 1564
/* 1560 */    MCD_OPC_Decode, 131, 3, 3, // Opcode: INSQHi
/* 1564 */    MCD_OPC_FilterValue, 250, 1, 113, 4, 0, // Skip to: 2707
/* 1570 */    MCD_OPC_Decode, 223, 2, 3, // Opcode: EXTQHi
/* 1574 */    MCD_OPC_FilterValue, 19, 81, 0, 0, // Skip to: 1660
/* 1579 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 1582 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1598
/* 1587 */    MCD_OPC_CheckField, 13, 3, 0, 89, 4, 0, // Skip to: 2707
/* 1594 */    MCD_OPC_Decode, 182, 3, 2, // Opcode: MULLr
/* 1598 */    MCD_OPC_FilterValue, 32, 11, 0, 0, // Skip to: 1614
/* 1603 */    MCD_OPC_CheckField, 13, 3, 0, 73, 4, 0, // Skip to: 2707
/* 1610 */    MCD_OPC_Decode, 184, 3, 2, // Opcode: MULQr
/* 1614 */    MCD_OPC_FilterValue, 48, 11, 0, 0, // Skip to: 1630
/* 1619 */    MCD_OPC_CheckField, 13, 3, 0, 57, 4, 0, // Skip to: 2707
/* 1626 */    MCD_OPC_Decode, 243, 3, 2, // Opcode: UMULHr
/* 1630 */    MCD_OPC_FilterValue, 128, 1, 4, 0, 0, // Skip to: 1640
/* 1636 */    MCD_OPC_Decode, 181, 3, 3, // Opcode: MULLi
/* 1640 */    MCD_OPC_FilterValue, 160, 1, 4, 0, 0, // Skip to: 1650
/* 1646 */    MCD_OPC_Decode, 183, 3, 3, // Opcode: MULQi
/* 1650 */    MCD_OPC_FilterValue, 176, 1, 27, 4, 0, // Skip to: 2707
/* 1656 */    MCD_OPC_Decode, 242, 3, 3, // Opcode: UMULHi
/* 1660 */    MCD_OPC_FilterValue, 20, 69, 0, 0, // Skip to: 1734
/* 1665 */    MCD_OPC_ExtractField, 5, 11,  // Inst{15-5} ...
/* 1668 */    MCD_OPC_FilterValue, 4, 11, 0, 0, // Skip to: 1684
/* 1673 */    MCD_OPC_CheckField, 16, 5, 31, 3, 4, 0, // Skip to: 2707
/* 1680 */    MCD_OPC_Decode, 138, 3, 6, // Opcode: ITOFS
/* 1684 */    MCD_OPC_FilterValue, 36, 11, 0, 0, // Skip to: 1700
/* 1689 */    MCD_OPC_CheckField, 16, 5, 31, 243, 3, 0, // Skip to: 2707
/* 1696 */    MCD_OPC_Decode, 139, 3, 7, // Opcode: ITOFT
/* 1700 */    MCD_OPC_FilterValue, 139, 11, 11, 0, 0, // Skip to: 1717
/* 1706 */    MCD_OPC_CheckField, 21, 5, 31, 226, 3, 0, // Skip to: 2707
/* 1713 */    MCD_OPC_Decode, 214, 3, 8, // Opcode: SQRTS
/* 1717 */    MCD_OPC_FilterValue, 171, 11, 216, 3, 0, // Skip to: 2707
/* 1723 */    MCD_OPC_CheckField, 21, 5, 31, 209, 3, 0, // Skip to: 2707
/* 1730 */    MCD_OPC_Decode, 215, 3, 9, // Opcode: SQRTT
/* 1734 */    MCD_OPC_FilterValue, 22, 208, 0, 0, // Skip to: 1947
/* 1739 */    MCD_OPC_ExtractField, 5, 11,  // Inst{15-5} ...
/* 1742 */    MCD_OPC_FilterValue, 175, 10, 11, 0, 0, // Skip to: 1759
/* 1748 */    MCD_OPC_CheckField, 21, 5, 31, 184, 3, 0, // Skip to: 2707
/* 1755 */    MCD_OPC_Decode, 208, 2, 9, // Opcode: CVTTQ
/* 1759 */    MCD_OPC_FilterValue, 128, 11, 4, 0, 0, // Skip to: 1769
/* 1765 */    MCD_OPC_Decode, 139, 2, 10, // Opcode: ADDS
/* 1769 */    MCD_OPC_FilterValue, 129, 11, 4, 0, 0, // Skip to: 1779
/* 1775 */    MCD_OPC_Decode, 239, 3, 10, // Opcode: SUBS
/* 1779 */    MCD_OPC_FilterValue, 130, 11, 4, 0, 0, // Skip to: 1789
/* 1785 */    MCD_OPC_Decode, 185, 3, 10, // Opcode: MULS
/* 1789 */    MCD_OPC_FilterValue, 131, 11, 4, 0, 0, // Skip to: 1799
/* 1795 */    MCD_OPC_Decode, 210, 2, 10, // Opcode: DIVS
/* 1799 */    MCD_OPC_FilterValue, 160, 11, 4, 0, 0, // Skip to: 1809
/* 1805 */    MCD_OPC_Decode, 140, 2, 11, // Opcode: ADDT
/* 1809 */    MCD_OPC_FilterValue, 161, 11, 4, 0, 0, // Skip to: 1819
/* 1815 */    MCD_OPC_Decode, 240, 3, 11, // Opcode: SUBT
/* 1819 */    MCD_OPC_FilterValue, 162, 11, 4, 0, 0, // Skip to: 1829
/* 1825 */    MCD_OPC_Decode, 186, 3, 11, // Opcode: MULT
/* 1829 */    MCD_OPC_FilterValue, 163, 11, 4, 0, 0, // Skip to: 1839
/* 1835 */    MCD_OPC_Decode, 211, 2, 11, // Opcode: DIVT
/* 1839 */    MCD_OPC_FilterValue, 164, 11, 4, 0, 0, // Skip to: 1849
/* 1845 */    MCD_OPC_Decode, 184, 2, 11, // Opcode: CMPTUN
/* 1849 */    MCD_OPC_FilterValue, 165, 11, 4, 0, 0, // Skip to: 1859
/* 1855 */    MCD_OPC_Decode, 181, 2, 11, // Opcode: CMPTEQ
/* 1859 */    MCD_OPC_FilterValue, 166, 11, 4, 0, 0, // Skip to: 1869
/* 1865 */    MCD_OPC_Decode, 183, 2, 11, // Opcode: CMPTLT
/* 1869 */    MCD_OPC_FilterValue, 167, 11, 4, 0, 0, // Skip to: 1879
/* 1875 */    MCD_OPC_Decode, 182, 2, 11, // Opcode: CMPTLE
/* 1879 */    MCD_OPC_FilterValue, 172, 13, 11, 0, 0, // Skip to: 1896
/* 1885 */    MCD_OPC_CheckField, 21, 5, 31, 47, 3, 0, // Skip to: 2707
/* 1892 */    MCD_OPC_Decode, 207, 2, 12, // Opcode: CVTST
/* 1896 */    MCD_OPC_FilterValue, 172, 15, 11, 0, 0, // Skip to: 1913
/* 1902 */    MCD_OPC_CheckField, 21, 5, 31, 30, 3, 0, // Skip to: 2707
/* 1909 */    MCD_OPC_Decode, 209, 2, 13, // Opcode: CVTTS
/* 1913 */    MCD_OPC_FilterValue, 188, 15, 11, 0, 0, // Skip to: 1930
/* 1919 */    MCD_OPC_CheckField, 21, 5, 31, 13, 3, 0, // Skip to: 2707
/* 1926 */    MCD_OPC_Decode, 205, 2, 13, // Opcode: CVTQS
/* 1930 */    MCD_OPC_FilterValue, 190, 15, 3, 3, 0, // Skip to: 2707
/* 1936 */    MCD_OPC_CheckField, 21, 5, 31, 252, 2, 0, // Skip to: 2707
/* 1943 */    MCD_OPC_Decode, 206, 2, 9, // Opcode: CVTQT
/* 1947 */    MCD_OPC_FilterValue, 23, 84, 0, 0, // Skip to: 2036
/* 1952 */    MCD_OPC_ExtractField, 5, 11,  // Inst{15-5} ...
/* 1955 */    MCD_OPC_FilterValue, 32, 4, 0, 0, // Skip to: 1964
/* 1960 */    MCD_OPC_Decode, 198, 2, 10, // Opcode: CPYSS
/* 1964 */    MCD_OPC_FilterValue, 33, 4, 0, 0, // Skip to: 1973
/* 1969 */    MCD_OPC_Decode, 196, 2, 11, // Opcode: CPYSNT
/* 1973 */    MCD_OPC_FilterValue, 34, 4, 0, 0, // Skip to: 1982
/* 1978 */    MCD_OPC_Decode, 191, 2, 10, // Opcode: CPYSES
/* 1982 */    MCD_OPC_FilterValue, 42, 4, 0, 0, // Skip to: 1991
/* 1987 */    MCD_OPC_Decode, 236, 2, 10, // Opcode: FCMOVEQS
/* 1991 */    MCD_OPC_FilterValue, 43, 4, 0, 0, // Skip to: 2000
/* 1996 */    MCD_OPC_Decode, 247, 2, 11, // Opcode: FCMOVNET
/* 2000 */    MCD_OPC_FilterValue, 44, 4, 0, 0, // Skip to: 2009
/* 2005 */    MCD_OPC_Decode, 244, 2, 10, // Opcode: FCMOVLTS
/* 2009 */    MCD_OPC_FilterValue, 45, 4, 0, 0, // Skip to: 2018
/* 2014 */    MCD_OPC_Decode, 238, 2, 10, // Opcode: FCMOVGES
/* 2018 */    MCD_OPC_FilterValue, 46, 4, 0, 0, // Skip to: 2027
/* 2023 */    MCD_OPC_Decode, 242, 2, 10, // Opcode: FCMOVLES
/* 2027 */    MCD_OPC_FilterValue, 47, 163, 2, 0, // Skip to: 2707
/* 2032 */    MCD_OPC_Decode, 240, 2, 10, // Opcode: FCMOVGTS
/* 2036 */    MCD_OPC_FilterValue, 24, 174, 0, 0, // Skip to: 2215
/* 2041 */    MCD_OPC_ExtractField, 0, 16,  // Inst{15-0} ...
/* 2044 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2060
/* 2049 */    MCD_OPC_CheckField, 16, 10, 0, 139, 2, 0, // Skip to: 2707
/* 2056 */    MCD_OPC_Decode, 241, 3, 14, // Opcode: TRAPB
/* 2060 */    MCD_OPC_FilterValue, 128, 8, 11, 0, 0, // Skip to: 2077
/* 2066 */    MCD_OPC_CheckField, 16, 10, 0, 122, 2, 0, // Skip to: 2707
/* 2073 */    MCD_OPC_Decode, 215, 2, 14, // Opcode: EXCB
/* 2077 */    MCD_OPC_FilterValue, 128, 128, 1, 11, 0, 0, // Skip to: 2095
/* 2084 */    MCD_OPC_CheckField, 16, 10, 0, 104, 2, 0, // Skip to: 2707
/* 2091 */    MCD_OPC_Decode, 166, 3, 14, // Opcode: MB
/* 2095 */    MCD_OPC_FilterValue, 128, 136, 1, 11, 0, 0, // Skip to: 2113
/* 2102 */    MCD_OPC_CheckField, 16, 10, 0, 86, 2, 0, // Skip to: 2707
/* 2109 */    MCD_OPC_Decode, 246, 3, 14, // Opcode: WMB
/* 2113 */    MCD_OPC_FilterValue, 128, 128, 2, 4, 0, 0, // Skip to: 2124
/* 2120 */    MCD_OPC_Decode, 248, 2, 15, // Opcode: FETCH
/* 2124 */    MCD_OPC_FilterValue, 128, 192, 2, 4, 0, 0, // Skip to: 2135
/* 2131 */    MCD_OPC_Decode, 249, 2, 15, // Opcode: FETCH_M
/* 2135 */    MCD_OPC_FilterValue, 128, 128, 3, 4, 0, 0, // Skip to: 2146
/* 2142 */    MCD_OPC_Decode, 192, 3, 15, // Opcode: RPCC
/* 2146 */    MCD_OPC_FilterValue, 128, 192, 3, 11, 0, 0, // Skip to: 2164
/* 2153 */    MCD_OPC_CheckField, 16, 5, 0, 35, 2, 0, // Skip to: 2707
/* 2160 */    MCD_OPC_Decode, 189, 3, 16, // Opcode: RC
/* 2164 */    MCD_OPC_FilterValue, 128, 208, 3, 4, 0, 0, // Skip to: 2175
/* 2171 */    MCD_OPC_Decode, 212, 2, 15, // Opcode: ECB
/* 2175 */    MCD_OPC_FilterValue, 128, 224, 3, 11, 0, 0, // Skip to: 2193
/* 2182 */    MCD_OPC_CheckField, 16, 5, 0, 6, 2, 0, // Skip to: 2707
/* 2189 */    MCD_OPC_Decode, 193, 3, 16, // Opcode: RS
/* 2193 */    MCD_OPC_FilterValue, 128, 240, 3, 4, 0, 0, // Skip to: 2204
/* 2200 */    MCD_OPC_Decode, 244, 3, 15, // Opcode: WH64
/* 2204 */    MCD_OPC_FilterValue, 128, 248, 3, 240, 1, 0, // Skip to: 2707
/* 2211 */    MCD_OPC_Decode, 245, 3, 15, // Opcode: WH64EN
/* 2215 */    MCD_OPC_FilterValue, 26, 101, 0, 0, // Skip to: 2321
/* 2220 */    MCD_OPC_ExtractField, 14, 2,  // Inst{15-14} ...
/* 2223 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 2246
/* 2228 */    MCD_OPC_CheckField, 21, 5, 31, 216, 1, 0, // Skip to: 2707
/* 2235 */    MCD_OPC_CheckField, 0, 14, 0, 209, 1, 0, // Skip to: 2707
/* 2242 */    MCD_OPC_Decode, 140, 3, 17, // Opcode: JMP
/* 2246 */    MCD_OPC_FilterValue, 1, 37, 0, 0, // Skip to: 2288
/* 2251 */    MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 2254 */    MCD_OPC_FilterValue, 251, 5, 11, 0, 0, // Skip to: 2271
/* 2260 */    MCD_OPC_CheckField, 0, 14, 0, 184, 1, 0, // Skip to: 2707
/* 2267 */    MCD_OPC_Decode, 143, 3, 14, // Opcode: JSRs
/* 2271 */    MCD_OPC_FilterValue, 219, 6, 174, 1, 0, // Skip to: 2707
/* 2277 */    MCD_OPC_CheckField, 0, 14, 0, 167, 1, 0, // Skip to: 2707
/* 2284 */    MCD_OPC_Decode, 141, 3, 14, // Opcode: JSR
/* 2288 */    MCD_OPC_FilterValue, 2, 19, 0, 0, // Skip to: 2312
/* 2293 */    MCD_OPC_CheckField, 16, 10, 250, 7, 150, 1, 0, // Skip to: 2707
/* 2301 */    MCD_OPC_CheckField, 0, 14, 1, 143, 1, 0, // Skip to: 2707
/* 2308 */    MCD_OPC_Decode, 190, 3, 14, // Opcode: RETDAG
/* 2312 */    MCD_OPC_FilterValue, 3, 134, 1, 0, // Skip to: 2707
/* 2317 */    MCD_OPC_Decode, 142, 3, 18, // Opcode: JSR_COROUTINE
/* 2321 */    MCD_OPC_FilterValue, 28, 115, 0, 0, // Skip to: 2441
/* 2326 */    MCD_OPC_ExtractField, 5, 11,  // Inst{15-5} ...
/* 2329 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2345
/* 2334 */    MCD_OPC_CheckField, 21, 5, 31, 110, 1, 0, // Skip to: 2707
/* 2341 */    MCD_OPC_Decode, 210, 3, 19, // Opcode: SEXTB
/* 2345 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 2361
/* 2350 */    MCD_OPC_CheckField, 21, 5, 31, 94, 1, 0, // Skip to: 2707
/* 2357 */    MCD_OPC_Decode, 211, 3, 19, // Opcode: SEXTW
/* 2361 */    MCD_OPC_FilterValue, 48, 11, 0, 0, // Skip to: 2377
/* 2366 */    MCD_OPC_CheckField, 21, 5, 31, 78, 1, 0, // Skip to: 2707
/* 2373 */    MCD_OPC_Decode, 203, 2, 19, // Opcode: CTPOP
/* 2377 */    MCD_OPC_FilterValue, 50, 11, 0, 0, // Skip to: 2393
/* 2382 */    MCD_OPC_CheckField, 21, 5, 31, 62, 1, 0, // Skip to: 2707
/* 2389 */    MCD_OPC_Decode, 202, 2, 19, // Opcode: CTLZ
/* 2393 */    MCD_OPC_FilterValue, 51, 11, 0, 0, // Skip to: 2409
/* 2398 */    MCD_OPC_CheckField, 21, 5, 31, 46, 1, 0, // Skip to: 2707
/* 2405 */    MCD_OPC_Decode, 204, 2, 19, // Opcode: CTTZ
/* 2409 */    MCD_OPC_FilterValue, 112, 11, 0, 0, // Skip to: 2425
/* 2414 */    MCD_OPC_CheckField, 16, 5, 31, 30, 1, 0, // Skip to: 2707
/* 2421 */    MCD_OPC_Decode, 251, 2, 20, // Opcode: FTOIT
/* 2425 */    MCD_OPC_FilterValue, 120, 21, 1, 0, // Skip to: 2707
/* 2430 */    MCD_OPC_CheckField, 16, 5, 31, 14, 1, 0, // Skip to: 2707
/* 2437 */    MCD_OPC_Decode, 250, 2, 21, // Opcode: FTOIS
/* 2441 */    MCD_OPC_FilterValue, 34, 4, 0, 0, // Skip to: 2450
/* 2446 */    MCD_OPC_Decode, 160, 3, 22, // Opcode: LDS
/* 2450 */    MCD_OPC_FilterValue, 35, 4, 0, 0, // Skip to: 2459
/* 2455 */    MCD_OPC_Decode, 162, 3, 23, // Opcode: LDT
/* 2459 */    MCD_OPC_FilterValue, 38, 4, 0, 0, // Skip to: 2468
/* 2464 */    MCD_OPC_Decode, 229, 3, 22, // Opcode: STS
/* 2468 */    MCD_OPC_FilterValue, 39, 4, 0, 0, // Skip to: 2477
/* 2473 */    MCD_OPC_Decode, 231, 3, 23, // Opcode: STT
/* 2477 */    MCD_OPC_FilterValue, 40, 4, 0, 0, // Skip to: 2486
/* 2482 */    MCD_OPC_Decode, 152, 3, 1, // Opcode: LDL
/* 2486 */    MCD_OPC_FilterValue, 41, 4, 0, 0, // Skip to: 2495
/* 2491 */    MCD_OPC_Decode, 155, 3, 1, // Opcode: LDQ
/* 2495 */    MCD_OPC_FilterValue, 42, 4, 0, 0, // Skip to: 2504
/* 2500 */    MCD_OPC_Decode, 153, 3, 1, // Opcode: LDL_L
/* 2504 */    MCD_OPC_FilterValue, 43, 4, 0, 0, // Skip to: 2513
/* 2509 */    MCD_OPC_Decode, 156, 3, 1, // Opcode: LDQ_L
/* 2513 */    MCD_OPC_FilterValue, 44, 4, 0, 0, // Skip to: 2522
/* 2518 */    MCD_OPC_Decode, 222, 3, 1, // Opcode: STL
/* 2522 */    MCD_OPC_FilterValue, 45, 4, 0, 0, // Skip to: 2531
/* 2527 */    MCD_OPC_Decode, 225, 3, 1, // Opcode: STQ
/* 2531 */    MCD_OPC_FilterValue, 46, 4, 0, 0, // Skip to: 2540
/* 2536 */    MCD_OPC_Decode, 223, 3, 24, // Opcode: STL_C
/* 2540 */    MCD_OPC_FilterValue, 47, 4, 0, 0, // Skip to: 2549
/* 2545 */    MCD_OPC_Decode, 226, 3, 24, // Opcode: STQ_C
/* 2549 */    MCD_OPC_FilterValue, 48, 11, 0, 0, // Skip to: 2565
/* 2554 */    MCD_OPC_CheckField, 21, 5, 31, 146, 0, 0, // Skip to: 2707
/* 2561 */    MCD_OPC_Decode, 155, 2, 25, // Opcode: BR
/* 2565 */    MCD_OPC_FilterValue, 49, 4, 0, 0, // Skip to: 2574
/* 2570 */    MCD_OPC_Decode, 230, 2, 26, // Opcode: FBEQ
/* 2574 */    MCD_OPC_FilterValue, 50, 4, 0, 0, // Skip to: 2583
/* 2579 */    MCD_OPC_Decode, 234, 2, 26, // Opcode: FBLT
/* 2583 */    MCD_OPC_FilterValue, 51, 4, 0, 0, // Skip to: 2592
/* 2588 */    MCD_OPC_Decode, 233, 2, 26, // Opcode: FBLE
/* 2592 */    MCD_OPC_FilterValue, 52, 11, 0, 0, // Skip to: 2608
/* 2597 */    MCD_OPC_CheckField, 21, 5, 26, 103, 0, 0, // Skip to: 2707
/* 2604 */    MCD_OPC_Decode, 156, 2, 25, // Opcode: BSR
/* 2608 */    MCD_OPC_FilterValue, 53, 4, 0, 0, // Skip to: 2617
/* 2613 */    MCD_OPC_Decode, 235, 2, 26, // Opcode: FBNE
/* 2617 */    MCD_OPC_FilterValue, 54, 4, 0, 0, // Skip to: 2626
/* 2622 */    MCD_OPC_Decode, 231, 2, 26, // Opcode: FBGE
/* 2626 */    MCD_OPC_FilterValue, 55, 4, 0, 0, // Skip to: 2635
/* 2631 */    MCD_OPC_Decode, 232, 2, 26, // Opcode: FBGT
/* 2635 */    MCD_OPC_FilterValue, 56, 4, 0, 0, // Skip to: 2644
/* 2640 */    MCD_OPC_Decode, 150, 2, 27, // Opcode: BLBC
/* 2644 */    MCD_OPC_FilterValue, 57, 4, 0, 0, // Skip to: 2653
/* 2649 */    MCD_OPC_Decode, 143, 2, 27, // Opcode: BEQ
/* 2653 */    MCD_OPC_FilterValue, 58, 4, 0, 0, // Skip to: 2662
/* 2658 */    MCD_OPC_Decode, 153, 2, 27, // Opcode: BLT
/* 2662 */    MCD_OPC_FilterValue, 59, 4, 0, 0, // Skip to: 2671
/* 2667 */    MCD_OPC_Decode, 152, 2, 27, // Opcode: BLE
/* 2671 */    MCD_OPC_FilterValue, 60, 4, 0, 0, // Skip to: 2680
/* 2676 */    MCD_OPC_Decode, 151, 2, 27, // Opcode: BLBS
/* 2680 */    MCD_OPC_FilterValue, 61, 4, 0, 0, // Skip to: 2689
/* 2685 */    MCD_OPC_Decode, 154, 2, 27, // Opcode: BNE
/* 2689 */    MCD_OPC_FilterValue, 62, 4, 0, 0, // Skip to: 2698
/* 2694 */    MCD_OPC_Decode, 144, 2, 27, // Opcode: BGE
/* 2698 */    MCD_OPC_FilterValue, 63, 4, 0, 0, // Skip to: 2707
/* 2703 */    MCD_OPC_Decode, 145, 2, 27, // Opcode: BGT
/* 2707 */    MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableCondBranchF32[] = {
/* 0 */       MCD_OPC_CheckField, 26, 6, 0, 4, 0, 0, // Skip to: 11
/* 7 */       MCD_OPC_Decode, 189, 2, 28, // Opcode: COND_BRANCH_F
/* 11 */      MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableCpys32[] = {
/* 0 */       MCD_OPC_ExtractField, 5, 11,  // Inst{15-5} ...
/* 3 */       MCD_OPC_FilterValue, 32, 11, 0, 0, // Skip to: 19
/* 8 */       MCD_OPC_CheckField, 26, 6, 23, 36, 0, 0, // Skip to: 51
/* 15 */      MCD_OPC_Decode, 199, 2, 29, // Opcode: CPYSSt
/* 19 */      MCD_OPC_FilterValue, 33, 11, 0, 0, // Skip to: 35
/* 24 */      MCD_OPC_CheckField, 26, 6, 23, 20, 0, 0, // Skip to: 51
/* 31 */      MCD_OPC_Decode, 195, 2, 29, // Opcode: CPYSNSt
/* 35 */      MCD_OPC_FilterValue, 34, 11, 0, 0, // Skip to: 51
/* 40 */      MCD_OPC_CheckField, 26, 6, 23, 4, 0, 0, // Skip to: 51
/* 47 */      MCD_OPC_Decode, 192, 2, 29, // Opcode: CPYSESt
/* 51 */      MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableCpysET32[] = {
/* 0 */       MCD_OPC_CheckField, 26, 6, 23, 11, 0, 0, // Skip to: 18
/* 7 */       MCD_OPC_CheckField, 5, 11, 34, 4, 0, 0, // Skip to: 18
/* 14 */      MCD_OPC_Decode, 193, 2, 11, // Opcode: CPYSET
/* 18 */      MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableCpysNS32[] = {
/* 0 */       MCD_OPC_CheckField, 26, 6, 23, 11, 0, 0, // Skip to: 18
/* 7 */       MCD_OPC_CheckField, 5, 11, 33, 4, 0, 0, // Skip to: 18
/* 14 */      MCD_OPC_Decode, 194, 2, 10, // Opcode: CPYSNS
/* 18 */      MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableCpysT32[] = {
/* 0 */       MCD_OPC_CheckField, 26, 6, 23, 11, 0, 0, // Skip to: 18
/* 7 */       MCD_OPC_CheckField, 5, 11, 32, 4, 0, 0, // Skip to: 18
/* 14 */      MCD_OPC_Decode, 200, 2, 11, // Opcode: CPYST
/* 18 */      MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableCpysTs32[] = {
/* 0 */       MCD_OPC_ExtractField, 5, 11,  // Inst{15-5} ...
/* 3 */       MCD_OPC_FilterValue, 32, 11, 0, 0, // Skip to: 19
/* 8 */       MCD_OPC_CheckField, 26, 6, 23, 20, 0, 0, // Skip to: 35
/* 15 */      MCD_OPC_Decode, 201, 2, 30, // Opcode: CPYSTs
/* 19 */      MCD_OPC_FilterValue, 33, 11, 0, 0, // Skip to: 35
/* 24 */      MCD_OPC_CheckField, 26, 6, 23, 4, 0, 0, // Skip to: 35
/* 31 */      MCD_OPC_Decode, 197, 2, 30, // Opcode: CPYSNTs
/* 35 */      MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableFcmov32[] = {
/* 0 */       MCD_OPC_ExtractField, 5, 11,  // Inst{15-5} ...
/* 3 */       MCD_OPC_FilterValue, 42, 11, 0, 0, // Skip to: 19
/* 8 */       MCD_OPC_CheckField, 26, 6, 23, 84, 0, 0, // Skip to: 99
/* 15 */      MCD_OPC_Decode, 237, 2, 11, // Opcode: FCMOVEQT
/* 19 */      MCD_OPC_FilterValue, 43, 11, 0, 0, // Skip to: 35
/* 24 */      MCD_OPC_CheckField, 26, 6, 23, 68, 0, 0, // Skip to: 99
/* 31 */      MCD_OPC_Decode, 246, 2, 10, // Opcode: FCMOVNES
/* 35 */      MCD_OPC_FilterValue, 44, 11, 0, 0, // Skip to: 51
/* 40 */      MCD_OPC_CheckField, 26, 6, 23, 52, 0, 0, // Skip to: 99
/* 47 */      MCD_OPC_Decode, 245, 2, 11, // Opcode: FCMOVLTT
/* 51 */      MCD_OPC_FilterValue, 45, 11, 0, 0, // Skip to: 67
/* 56 */      MCD_OPC_CheckField, 26, 6, 23, 36, 0, 0, // Skip to: 99
/* 63 */      MCD_OPC_Decode, 239, 2, 11, // Opcode: FCMOVGET
/* 67 */      MCD_OPC_FilterValue, 46, 11, 0, 0, // Skip to: 83
/* 72 */      MCD_OPC_CheckField, 26, 6, 23, 20, 0, 0, // Skip to: 99
/* 79 */      MCD_OPC_Decode, 243, 2, 11, // Opcode: FCMOVLET
/* 83 */      MCD_OPC_FilterValue, 47, 11, 0, 0, // Skip to: 99
/* 88 */      MCD_OPC_CheckField, 26, 6, 23, 4, 0, 0, // Skip to: 99
/* 95 */      MCD_OPC_Decode, 241, 2, 11, // Opcode: FCMOVGTT
/* 99 */      MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableLDg32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 8, 4, 0, 0, // Skip to: 12
/* 8 */       MCD_OPC_Decode, 148, 3, 1, // Opcode: LDAg
/* 12 */      MCD_OPC_FilterValue, 9, 4, 0, 0, // Skip to: 21
/* 17 */      MCD_OPC_Decode, 146, 3, 1, // Opcode: LDAHg
/* 21 */      MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableLDl32[] = {
/* 0 */       MCD_OPC_CheckField, 26, 6, 41, 4, 0, 0, // Skip to: 11
/* 7 */       MCD_OPC_Decode, 158, 3, 1, // Opcode: LDQl
/* 11 */      MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableLDr32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 8, 4, 0, 0, // Skip to: 12
/* 8 */       MCD_OPC_Decode, 149, 3, 1, // Opcode: LDAr
/* 12 */      MCD_OPC_FilterValue, 9, 4, 0, 0, // Skip to: 21
/* 17 */      MCD_OPC_Decode, 147, 3, 1, // Opcode: LDAHr
/* 21 */      MCD_OPC_FilterValue, 10, 4, 0, 0, // Skip to: 30
/* 26 */      MCD_OPC_Decode, 151, 3, 1, // Opcode: LDBUr
/* 30 */      MCD_OPC_FilterValue, 12, 4, 0, 0, // Skip to: 39
/* 35 */      MCD_OPC_Decode, 165, 3, 1, // Opcode: LDWUr
/* 39 */      MCD_OPC_FilterValue, 34, 4, 0, 0, // Skip to: 48
/* 44 */      MCD_OPC_Decode, 161, 3, 22, // Opcode: LDSr
/* 48 */      MCD_OPC_FilterValue, 35, 4, 0, 0, // Skip to: 57
/* 53 */      MCD_OPC_Decode, 163, 3, 23, // Opcode: LDTr
/* 57 */      MCD_OPC_FilterValue, 40, 4, 0, 0, // Skip to: 66
/* 62 */      MCD_OPC_Decode, 154, 3, 1, // Opcode: LDLr
/* 66 */      MCD_OPC_FilterValue, 41, 4, 0, 0, // Skip to: 75
/* 71 */      MCD_OPC_Decode, 159, 3, 1, // Opcode: LDQr
/* 75 */      MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableRet32[] = {
/* 0 */       MCD_OPC_CheckField, 0, 32, 129, 128, 234, 223, 6, 4, 0, 0, // Skip to: 15
/* 11 */      MCD_OPC_Decode, 191, 3, 14, // Opcode: RETDAGp
/* 15 */      MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableSTr32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 13, 4, 0, 0, // Skip to: 12
/* 8 */       MCD_OPC_Decode, 234, 3, 1, // Opcode: STWr
/* 12 */      MCD_OPC_FilterValue, 14, 4, 0, 0, // Skip to: 21
/* 17 */      MCD_OPC_Decode, 221, 3, 1, // Opcode: STBr
/* 21 */      MCD_OPC_FilterValue, 38, 4, 0, 0, // Skip to: 30
/* 26 */      MCD_OPC_Decode, 230, 3, 22, // Opcode: STSr
/* 30 */      MCD_OPC_FilterValue, 39, 4, 0, 0, // Skip to: 39
/* 35 */      MCD_OPC_Decode, 232, 3, 23, // Opcode: STTr
/* 39 */      MCD_OPC_FilterValue, 44, 4, 0, 0, // Skip to: 48
/* 44 */      MCD_OPC_Decode, 224, 3, 1, // Opcode: STLr
/* 48 */      MCD_OPC_FilterValue, 45, 4, 0, 0, // Skip to: 57
/* 53 */      MCD_OPC_Decode, 228, 3, 1, // Opcode: STQr
/* 57 */      MCD_OPC_Fail,
  0
};

static bool checkDecoderPredicate(MCInst *Inst, unsigned Idx) {
  /* llvm_unreachable("Invalid index!"); */
  return false;
}

#define DecodeToMCInst(fname, fieldname, InsnType) \
static DecodeStatus fname(DecodeStatus S, unsigned Idx, InsnType insn, MCInst *MI, \
		uint64_t Address, const void *Decoder, bool *DecodeComplete) \
{ \
  *DecodeComplete = true; \
  InsnType tmp; \
  switch (Idx) { \
  default: /* llvm_unreachable("Invalid index!"); */ \
  case 0: \
    tmp = fieldname(insn, 21, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 0, 21); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 1: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 2: \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 3: \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 13, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 4: \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 5: \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 13, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 6: \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 7: \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 8: \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 9: \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 10: \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 11: \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 12: \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 13: \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 14: \
    return S; \
  case 15: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 16: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 17: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 18: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 14); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 19: \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 20: \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 21: \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 22: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 23: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 24: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 25: \
    tmp = fieldname(insn, 0, 21); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 26: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 21); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 27: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 21); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 28: \
    tmp = fieldname(insn, 21, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 0, 21); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 29: \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 30: \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
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

FieldFromInstruction(fieldFromInstruction_4, uint32_t)
DecodeToMCInst(decodeToMCInst_4, fieldFromInstruction_4, uint32_t)
DecodeInstruction(decodeInstruction_4, fieldFromInstruction_4, decodeToMCInst_4, uint32_t)
