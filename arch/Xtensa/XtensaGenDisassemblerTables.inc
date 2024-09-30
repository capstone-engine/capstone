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

static const uint8_t DecoderTable24[] = {
/* 0 */       MCD_OPC_ExtractField, 0, 4,  // Inst{3-0} ...
/* 3 */       MCD_OPC_FilterValue, 0, 11, 3, 0, // Skip to: 787
/* 8 */       MCD_OPC_ExtractField, 17, 3,  // Inst{19-17} ...
/* 11 */      MCD_OPC_FilterValue, 0, 146, 2, 0, // Skip to: 674
/* 16 */      MCD_OPC_ExtractField, 21, 3,  // Inst{23-21} ...
/* 19 */      MCD_OPC_FilterValue, 0, 198, 0, 0, // Skip to: 222
/* 24 */      MCD_OPC_ExtractField, 16, 1,  // Inst{16} ...
/* 27 */      MCD_OPC_FilterValue, 0, 181, 0, 0, // Skip to: 213
/* 32 */      MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 35 */      MCD_OPC_FilterValue, 0, 164, 0, 0, // Skip to: 204
/* 40 */      MCD_OPC_ExtractField, 4, 4,  // Inst{7-4} ...
/* 43 */      MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 59
/* 48 */      MCD_OPC_CheckField, 8, 8, 32, 144, 4, 0, // Skip to: 1223
/* 55 */      MCD_OPC_Decode, 181, 2, 0, // Opcode: ISYNC
/* 59 */      MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 75
/* 64 */      MCD_OPC_CheckField, 8, 8, 32, 128, 4, 0, // Skip to: 1223
/* 71 */      MCD_OPC_Decode, 200, 2, 0, // Opcode: RSYNC
/* 75 */      MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 91
/* 80 */      MCD_OPC_CheckField, 8, 8, 32, 112, 4, 0, // Skip to: 1223
/* 87 */      MCD_OPC_Decode, 178, 2, 0, // Opcode: ESYNC
/* 91 */      MCD_OPC_FilterValue, 3, 11, 0, 0, // Skip to: 107
/* 96 */      MCD_OPC_CheckField, 8, 8, 32, 96, 4, 0, // Skip to: 1223
/* 103 */     MCD_OPC_Decode, 177, 2, 0, // Opcode: DSYNC
/* 107 */     MCD_OPC_FilterValue, 8, 11, 0, 0, // Skip to: 123
/* 112 */     MCD_OPC_CheckField, 8, 8, 0, 80, 4, 0, // Skip to: 1223
/* 119 */     MCD_OPC_Decode, 198, 2, 0, // Opcode: RET
/* 123 */     MCD_OPC_FilterValue, 10, 11, 0, 0, // Skip to: 139
/* 128 */     MCD_OPC_CheckField, 12, 4, 0, 64, 4, 0, // Skip to: 1223
/* 135 */     MCD_OPC_Decode, 183, 2, 1, // Opcode: JX
/* 139 */     MCD_OPC_FilterValue, 12, 28, 0, 0, // Skip to: 172
/* 144 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 147 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 156
/* 152 */     MCD_OPC_Decode, 176, 2, 1, // Opcode: CALLX0
/* 156 */     MCD_OPC_FilterValue, 2, 38, 4, 0, // Skip to: 1223
/* 161 */     MCD_OPC_CheckField, 8, 4, 0, 31, 4, 0, // Skip to: 1223
/* 168 */     MCD_OPC_Decode, 189, 2, 0, // Opcode: MEMW
/* 172 */     MCD_OPC_FilterValue, 13, 11, 0, 0, // Skip to: 188
/* 177 */     MCD_OPC_CheckField, 8, 8, 32, 15, 4, 0, // Skip to: 1223
/* 184 */     MCD_OPC_Decode, 180, 2, 0, // Opcode: EXTW
/* 188 */     MCD_OPC_FilterValue, 15, 6, 4, 0, // Skip to: 1223
/* 193 */     MCD_OPC_CheckField, 8, 8, 32, 255, 3, 0, // Skip to: 1223
/* 200 */     MCD_OPC_Decode, 196, 2, 0, // Opcode: NOP
/* 204 */     MCD_OPC_FilterValue, 1, 246, 3, 0, // Skip to: 1223
/* 209 */     MCD_OPC_Decode, 150, 2, 2, // Opcode: AND
/* 213 */     MCD_OPC_FilterValue, 1, 237, 3, 0, // Skip to: 1223
/* 218 */     MCD_OPC_Decode, 205, 2, 3, // Opcode: SLLI
/* 222 */     MCD_OPC_FilterValue, 1, 38, 0, 0, // Skip to: 265
/* 227 */     MCD_OPC_ExtractField, 16, 1,  // Inst{16} ...
/* 230 */     MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 256
/* 235 */     MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 238 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 247
/* 243 */     MCD_OPC_Decode, 197, 2, 2, // Opcode: OR
/* 247 */     MCD_OPC_FilterValue, 1, 203, 3, 0, // Skip to: 1223
/* 252 */     MCD_OPC_Decode, 220, 2, 2, // Opcode: XOR
/* 256 */     MCD_OPC_FilterValue, 1, 194, 3, 0, // Skip to: 1223
/* 261 */     MCD_OPC_Decode, 207, 2, 4, // Opcode: SRAI
/* 265 */     MCD_OPC_FilterValue, 2, 119, 0, 0, // Skip to: 389
/* 270 */     MCD_OPC_ExtractField, 16, 1,  // Inst{16} ...
/* 273 */     MCD_OPC_FilterValue, 0, 95, 0, 0, // Skip to: 373
/* 278 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 281 */     MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 304
/* 286 */     MCD_OPC_CheckField, 20, 1, 0, 162, 3, 0, // Skip to: 1223
/* 293 */     MCD_OPC_CheckField, 4, 4, 0, 155, 3, 0, // Skip to: 1223
/* 300 */     MCD_OPC_Decode, 214, 2, 1, // Opcode: SSR
/* 304 */     MCD_OPC_FilterValue, 1, 18, 0, 0, // Skip to: 327
/* 309 */     MCD_OPC_CheckField, 20, 1, 0, 139, 3, 0, // Skip to: 1223
/* 316 */     MCD_OPC_CheckField, 4, 4, 0, 132, 3, 0, // Skip to: 1223
/* 323 */     MCD_OPC_Decode, 213, 2, 1, // Opcode: SSL
/* 327 */     MCD_OPC_FilterValue, 2, 18, 0, 0, // Skip to: 350
/* 332 */     MCD_OPC_CheckField, 20, 1, 0, 116, 3, 0, // Skip to: 1223
/* 339 */     MCD_OPC_CheckField, 4, 4, 0, 109, 3, 0, // Skip to: 1223
/* 346 */     MCD_OPC_Decode, 211, 2, 1, // Opcode: SSA8L
/* 350 */     MCD_OPC_FilterValue, 4, 100, 3, 0, // Skip to: 1223
/* 355 */     MCD_OPC_CheckField, 20, 1, 0, 93, 3, 0, // Skip to: 1223
/* 362 */     MCD_OPC_CheckField, 5, 3, 0, 86, 3, 0, // Skip to: 1223
/* 369 */     MCD_OPC_Decode, 212, 2, 5, // Opcode: SSAI
/* 373 */     MCD_OPC_FilterValue, 1, 77, 3, 0, // Skip to: 1223
/* 378 */     MCD_OPC_CheckField, 20, 1, 0, 70, 3, 0, // Skip to: 1223
/* 385 */     MCD_OPC_Decode, 210, 2, 6, // Opcode: SRLI
/* 389 */     MCD_OPC_FilterValue, 3, 59, 0, 0, // Skip to: 453
/* 394 */     MCD_OPC_ExtractField, 16, 1,  // Inst{16} ...
/* 397 */     MCD_OPC_FilterValue, 0, 35, 0, 0, // Skip to: 437
/* 402 */     MCD_OPC_ExtractField, 8, 4,  // Inst{11-8} ...
/* 405 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 421
/* 410 */     MCD_OPC_CheckField, 20, 1, 0, 38, 3, 0, // Skip to: 1223
/* 417 */     MCD_OPC_Decode, 195, 2, 7, // Opcode: NEG
/* 421 */     MCD_OPC_FilterValue, 1, 29, 3, 0, // Skip to: 1223
/* 426 */     MCD_OPC_CheckField, 20, 1, 0, 22, 3, 0, // Skip to: 1223
/* 433 */     MCD_OPC_Decode, 143, 2, 7, // Opcode: ABS
/* 437 */     MCD_OPC_FilterValue, 1, 13, 3, 0, // Skip to: 1223
/* 442 */     MCD_OPC_CheckField, 20, 1, 0, 6, 3, 0, // Skip to: 1223
/* 449 */     MCD_OPC_Decode, 221, 2, 8, // Opcode: XSR
/* 453 */     MCD_OPC_FilterValue, 4, 62, 0, 0, // Skip to: 520
/* 458 */     MCD_OPC_ExtractField, 16, 1,  // Inst{16} ...
/* 461 */     MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 487
/* 466 */     MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 469 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 478
/* 474 */     MCD_OPC_Decode, 144, 2, 2, // Opcode: ADD
/* 478 */     MCD_OPC_FilterValue, 1, 228, 2, 0, // Skip to: 1223
/* 483 */     MCD_OPC_Decode, 147, 2, 2, // Opcode: ADDX2
/* 487 */     MCD_OPC_FilterValue, 1, 219, 2, 0, // Skip to: 1223
/* 492 */     MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 495 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 504
/* 500 */     MCD_OPC_Decode, 208, 2, 2, // Opcode: SRC
/* 504 */     MCD_OPC_FilterValue, 1, 202, 2, 0, // Skip to: 1223
/* 509 */     MCD_OPC_CheckField, 8, 4, 0, 195, 2, 0, // Skip to: 1223
/* 516 */     MCD_OPC_Decode, 209, 2, 7, // Opcode: SRL
/* 520 */     MCD_OPC_FilterValue, 5, 69, 0, 0, // Skip to: 594
/* 525 */     MCD_OPC_ExtractField, 16, 1,  // Inst{16} ...
/* 528 */     MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 554
/* 533 */     MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 536 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 545
/* 541 */     MCD_OPC_Decode, 148, 2, 2, // Opcode: ADDX4
/* 545 */     MCD_OPC_FilterValue, 1, 161, 2, 0, // Skip to: 1223
/* 550 */     MCD_OPC_Decode, 149, 2, 2, // Opcode: ADDX8
/* 554 */     MCD_OPC_FilterValue, 1, 152, 2, 0, // Skip to: 1223
/* 559 */     MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 562 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 578
/* 567 */     MCD_OPC_CheckField, 4, 4, 0, 137, 2, 0, // Skip to: 1223
/* 574 */     MCD_OPC_Decode, 204, 2, 9, // Opcode: SLL
/* 578 */     MCD_OPC_FilterValue, 1, 128, 2, 0, // Skip to: 1223
/* 583 */     MCD_OPC_CheckField, 8, 4, 0, 121, 2, 0, // Skip to: 1223
/* 590 */     MCD_OPC_Decode, 206, 2, 7, // Opcode: SRA
/* 594 */     MCD_OPC_FilterValue, 6, 35, 0, 0, // Skip to: 634
/* 599 */     MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 602 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 618
/* 607 */     MCD_OPC_CheckField, 16, 1, 0, 97, 2, 0, // Skip to: 1223
/* 614 */     MCD_OPC_Decode, 215, 2, 2, // Opcode: SUB
/* 618 */     MCD_OPC_FilterValue, 1, 88, 2, 0, // Skip to: 1223
/* 623 */     MCD_OPC_CheckField, 16, 1, 0, 81, 2, 0, // Skip to: 1223
/* 630 */     MCD_OPC_Decode, 216, 2, 2, // Opcode: SUBX2
/* 634 */     MCD_OPC_FilterValue, 7, 72, 2, 0, // Skip to: 1223
/* 639 */     MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 642 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 658
/* 647 */     MCD_OPC_CheckField, 16, 1, 0, 57, 2, 0, // Skip to: 1223
/* 654 */     MCD_OPC_Decode, 217, 2, 2, // Opcode: SUBX4
/* 658 */     MCD_OPC_FilterValue, 1, 48, 2, 0, // Skip to: 1223
/* 663 */     MCD_OPC_CheckField, 16, 1, 0, 41, 2, 0, // Skip to: 1223
/* 670 */     MCD_OPC_Decode, 218, 2, 2, // Opcode: SUBX8
/* 674 */     MCD_OPC_FilterValue, 1, 99, 0, 0, // Skip to: 778
/* 679 */     MCD_OPC_ExtractField, 20, 4,  // Inst{23-20} ...
/* 682 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 698
/* 687 */     MCD_OPC_CheckField, 16, 1, 1, 17, 2, 0, // Skip to: 1223
/* 694 */     MCD_OPC_Decode, 199, 2, 10, // Opcode: RSR
/* 698 */     MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 714
/* 703 */     MCD_OPC_CheckField, 16, 1, 1, 1, 2, 0, // Skip to: 1223
/* 710 */     MCD_OPC_Decode, 219, 2, 11, // Opcode: WSR
/* 714 */     MCD_OPC_FilterValue, 8, 11, 0, 0, // Skip to: 730
/* 719 */     MCD_OPC_CheckField, 16, 1, 1, 241, 1, 0, // Skip to: 1223
/* 726 */     MCD_OPC_Decode, 190, 2, 2, // Opcode: MOVEQZ
/* 730 */     MCD_OPC_FilterValue, 9, 11, 0, 0, // Skip to: 746
/* 735 */     MCD_OPC_CheckField, 16, 1, 1, 225, 1, 0, // Skip to: 1223
/* 742 */     MCD_OPC_Decode, 194, 2, 2, // Opcode: MOVNEZ
/* 746 */     MCD_OPC_FilterValue, 10, 11, 0, 0, // Skip to: 762
/* 751 */     MCD_OPC_CheckField, 16, 1, 1, 209, 1, 0, // Skip to: 1223
/* 758 */     MCD_OPC_Decode, 193, 2, 2, // Opcode: MOVLTZ
/* 762 */     MCD_OPC_FilterValue, 11, 200, 1, 0, // Skip to: 1223
/* 767 */     MCD_OPC_CheckField, 16, 1, 1, 193, 1, 0, // Skip to: 1223
/* 774 */     MCD_OPC_Decode, 191, 2, 2, // Opcode: MOVGEZ
/* 778 */     MCD_OPC_FilterValue, 2, 184, 1, 0, // Skip to: 1223
/* 783 */     MCD_OPC_Decode, 179, 2, 12, // Opcode: EXTUI
/* 787 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 796
/* 792 */     MCD_OPC_Decode, 187, 2, 13, // Opcode: L32R
/* 796 */     MCD_OPC_FilterValue, 2, 93, 0, 0, // Skip to: 894
/* 801 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 804 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 813
/* 809 */     MCD_OPC_Decode, 188, 2, 14, // Opcode: L8UI
/* 813 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 822
/* 818 */     MCD_OPC_Decode, 185, 2, 15, // Opcode: L16UI
/* 822 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 831
/* 827 */     MCD_OPC_Decode, 186, 2, 16, // Opcode: L32I
/* 831 */     MCD_OPC_FilterValue, 4, 4, 0, 0, // Skip to: 840
/* 836 */     MCD_OPC_Decode, 203, 2, 14, // Opcode: S8I
/* 840 */     MCD_OPC_FilterValue, 5, 4, 0, 0, // Skip to: 849
/* 845 */     MCD_OPC_Decode, 201, 2, 15, // Opcode: S16I
/* 849 */     MCD_OPC_FilterValue, 6, 4, 0, 0, // Skip to: 858
/* 854 */     MCD_OPC_Decode, 202, 2, 16, // Opcode: S32I
/* 858 */     MCD_OPC_FilterValue, 9, 4, 0, 0, // Skip to: 867
/* 863 */     MCD_OPC_Decode, 184, 2, 15, // Opcode: L16SI
/* 867 */     MCD_OPC_FilterValue, 10, 4, 0, 0, // Skip to: 876
/* 872 */     MCD_OPC_Decode, 192, 2, 17, // Opcode: MOVI
/* 876 */     MCD_OPC_FilterValue, 12, 4, 0, 0, // Skip to: 885
/* 881 */     MCD_OPC_Decode, 145, 2, 18, // Opcode: ADDI
/* 885 */     MCD_OPC_FilterValue, 13, 77, 1, 0, // Skip to: 1223
/* 890 */     MCD_OPC_Decode, 146, 2, 19, // Opcode: ADDMI
/* 894 */     MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 910
/* 899 */     MCD_OPC_CheckField, 4, 2, 0, 61, 1, 0, // Skip to: 1223
/* 906 */     MCD_OPC_Decode, 175, 2, 20, // Opcode: CALL0
/* 910 */     MCD_OPC_FilterValue, 6, 126, 0, 0, // Skip to: 1041
/* 915 */     MCD_OPC_ExtractField, 4, 2,  // Inst{5-4} ...
/* 918 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 927
/* 923 */     MCD_OPC_Decode, 182, 2, 21, // Opcode: J
/* 927 */     MCD_OPC_FilterValue, 1, 39, 0, 0, // Skip to: 971
/* 932 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 935 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 944
/* 940 */     MCD_OPC_Decode, 159, 2, 22, // Opcode: BEQZ
/* 944 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 953
/* 949 */     MCD_OPC_Decode, 173, 2, 22, // Opcode: BNEZ
/* 953 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 962
/* 958 */     MCD_OPC_Decode, 169, 2, 22, // Opcode: BLTZ
/* 962 */     MCD_OPC_FilterValue, 3, 0, 1, 0, // Skip to: 1223
/* 967 */     MCD_OPC_Decode, 164, 2, 22, // Opcode: BGEZ
/* 971 */     MCD_OPC_FilterValue, 2, 39, 0, 0, // Skip to: 1015
/* 976 */     MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 979 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 988
/* 984 */     MCD_OPC_Decode, 158, 2, 23, // Opcode: BEQI
/* 988 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 997
/* 993 */     MCD_OPC_Decode, 172, 2, 23, // Opcode: BNEI
/* 997 */     MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1006
/* 1002 */    MCD_OPC_Decode, 166, 2, 23, // Opcode: BLTI
/* 1006 */    MCD_OPC_FilterValue, 3, 212, 0, 0, // Skip to: 1223
/* 1011 */    MCD_OPC_Decode, 161, 2, 23, // Opcode: BGEI
/* 1015 */    MCD_OPC_FilterValue, 3, 203, 0, 0, // Skip to: 1223
/* 1020 */    MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 1023 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1032
/* 1028 */    MCD_OPC_Decode, 168, 2, 24, // Opcode: BLTUI
/* 1032 */    MCD_OPC_FilterValue, 3, 186, 0, 0, // Skip to: 1223
/* 1037 */    MCD_OPC_Decode, 163, 2, 24, // Opcode: BGEUI
/* 1041 */    MCD_OPC_FilterValue, 7, 177, 0, 0, // Skip to: 1223
/* 1046 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 1049 */    MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 1075
/* 1054 */    MCD_OPC_ExtractField, 12, 1,  // Inst{12} ...
/* 1057 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1066
/* 1062 */    MCD_OPC_Decode, 174, 2, 25, // Opcode: BNONE
/* 1066 */    MCD_OPC_FilterValue, 1, 152, 0, 0, // Skip to: 1223
/* 1071 */    MCD_OPC_Decode, 157, 2, 25, // Opcode: BEQ
/* 1075 */    MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 1101
/* 1080 */    MCD_OPC_ExtractField, 12, 1,  // Inst{12} ...
/* 1083 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1092
/* 1088 */    MCD_OPC_Decode, 165, 2, 25, // Opcode: BLT
/* 1092 */    MCD_OPC_FilterValue, 1, 126, 0, 0, // Skip to: 1223
/* 1097 */    MCD_OPC_Decode, 167, 2, 25, // Opcode: BLTU
/* 1101 */    MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 1127
/* 1106 */    MCD_OPC_ExtractField, 12, 1,  // Inst{12} ...
/* 1109 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1118
/* 1114 */    MCD_OPC_Decode, 151, 2, 25, // Opcode: BALL
/* 1118 */    MCD_OPC_FilterValue, 1, 100, 0, 0, // Skip to: 1223
/* 1123 */    MCD_OPC_Decode, 153, 2, 25, // Opcode: BBC
/* 1127 */    MCD_OPC_FilterValue, 3, 4, 0, 0, // Skip to: 1136
/* 1132 */    MCD_OPC_Decode, 154, 2, 26, // Opcode: BBCI
/* 1136 */    MCD_OPC_FilterValue, 4, 21, 0, 0, // Skip to: 1162
/* 1141 */    MCD_OPC_ExtractField, 12, 1,  // Inst{12} ...
/* 1144 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1153
/* 1149 */    MCD_OPC_Decode, 152, 2, 25, // Opcode: BANY
/* 1153 */    MCD_OPC_FilterValue, 1, 65, 0, 0, // Skip to: 1223
/* 1158 */    MCD_OPC_Decode, 171, 2, 25, // Opcode: BNE
/* 1162 */    MCD_OPC_FilterValue, 5, 21, 0, 0, // Skip to: 1188
/* 1167 */    MCD_OPC_ExtractField, 12, 1,  // Inst{12} ...
/* 1170 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1179
/* 1175 */    MCD_OPC_Decode, 160, 2, 25, // Opcode: BGE
/* 1179 */    MCD_OPC_FilterValue, 1, 39, 0, 0, // Skip to: 1223
/* 1184 */    MCD_OPC_Decode, 162, 2, 25, // Opcode: BGEU
/* 1188 */    MCD_OPC_FilterValue, 6, 21, 0, 0, // Skip to: 1214
/* 1193 */    MCD_OPC_ExtractField, 12, 1,  // Inst{12} ...
/* 1196 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1205
/* 1201 */    MCD_OPC_Decode, 170, 2, 25, // Opcode: BNALL
/* 1205 */    MCD_OPC_FilterValue, 1, 13, 0, 0, // Skip to: 1223
/* 1210 */    MCD_OPC_Decode, 155, 2, 25, // Opcode: BBS
/* 1214 */    MCD_OPC_FilterValue, 7, 4, 0, 0, // Skip to: 1223
/* 1219 */    MCD_OPC_Decode, 156, 2, 26, // Opcode: BBSI
/* 1223 */    MCD_OPC_Fail,
  0
};

static bool checkDecoderPredicate(MCInst *Inst, unsigned Idx) {
	llvm_unreachable("Invalid index!");
	return true;
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
    return S; \
  case 1: \
    tmp = fieldname(insn, 8, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 2: \
    tmp = fieldname(insn, 12, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 4, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 3: \
    tmp = fieldname(insn, 12, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 4, 4) << 0; \
    tmp |= fieldname(insn, 20, 1) << 4; \
    if (!Check(&S, decodeShimm1_31Operand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 4: \
    tmp = fieldname(insn, 12, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 4, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 8, 4) << 0; \
    tmp |= fieldname(insn, 20, 1) << 4; \
    if (!Check(&S, decodeUimm5Operand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 5: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 4, 1) << 4; \
    tmp |= fieldname(insn, 8, 4) << 0; \
    if (!Check(&S, decodeUimm5Operand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 6: \
    tmp = fieldname(insn, 12, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 4, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 4); \
    if (!Check(&S, decodeUimm4Operand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 7: \
    tmp = fieldname(insn, 12, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 4, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 8: \
    tmp = fieldname(insn, 4, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 8); \
    if (!Check(&S, DecodeSRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 4, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 8); \
    if (!Check(&S, DecodeSRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 9: \
    tmp = fieldname(insn, 12, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 10: \
    tmp = fieldname(insn, 4, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 8); \
    if (!Check(&S, DecodeSRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 11: \
    tmp = fieldname(insn, 8, 8); \
    if (!Check(&S, DecodeSRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 4, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 12: \
    tmp = fieldname(insn, 12, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 4, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 8, 4) << 0; \
    tmp |= fieldname(insn, 16, 1) << 4; \
    if (!Check(&S, decodeUimm5Operand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 20, 4); \
    if (!Check(&S, decodeImm1_16Operand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 13: \
    tmp = fieldname(insn, 4, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 16); \
    if (!Check(&S, decodeL32ROperand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 14: \
    tmp = fieldname(insn, 4, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 8, 4) << 0; \
    tmp |= fieldname(insn, 16, 8) << 4; \
    if (!Check(&S, decodeMem8Operand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 15: \
    tmp = fieldname(insn, 4, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 8, 4) << 0; \
    tmp |= fieldname(insn, 16, 8) << 4; \
    if (!Check(&S, decodeMem16Operand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 16: \
    tmp = fieldname(insn, 4, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 8, 4) << 0; \
    tmp |= fieldname(insn, 16, 8) << 4; \
    if (!Check(&S, decodeMem32Operand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 17: \
    tmp = fieldname(insn, 4, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 8, 4) << 8; \
    tmp |= fieldname(insn, 16, 8) << 0; \
    if (!Check(&S, decodeImm12Operand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 18: \
    tmp = fieldname(insn, 4, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 8); \
    if (!Check(&S, decodeImm8Operand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 19: \
    tmp = fieldname(insn, 4, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 8) << 8; \
    if (!Check(&S, decodeImm8_sh8Operand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 20: \
    tmp = fieldname(insn, 6, 18); \
    if (!Check(&S, decodeCallOperand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 21: \
    tmp = fieldname(insn, 6, 18); \
    if (!Check(&S, decodeJumpOperand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 22: \
    tmp = fieldname(insn, 8, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 12, 12); \
    if (!Check(&S, decodeBranchOperand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 23: \
    tmp = fieldname(insn, 8, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 12, 4); \
    if (!Check(&S, decodeB4constOperand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 8); \
    if (!Check(&S, decodeBranchOperand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 24: \
    tmp = fieldname(insn, 8, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 12, 4); \
    if (!Check(&S, decodeB4constuOperand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 8); \
    if (!Check(&S, decodeBranchOperand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 25: \
    tmp = fieldname(insn, 8, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 4, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 8); \
    if (!Check(&S, decodeBranchOperand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 26: \
    tmp = fieldname(insn, 8, 4); \
    if (!Check(&S, DecodeARRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 4, 4) << 0; \
    tmp |= fieldname(insn, 12, 1) << 4; \
    if (!Check(&S, decodeUimm5Operand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 8); \
    if (!Check(&S, decodeBranchOperand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
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

