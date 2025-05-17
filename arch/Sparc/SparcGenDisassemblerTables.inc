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

static const uint8_t DecoderTableSparc32[] = {
/* 0 */       MCD_OPC_ExtractField, 30, 2,  // Inst{31-30} ...
/* 3 */       MCD_OPC_FilterValue, 0, 172, 1, 0, // Skip to: 436
/* 8 */       MCD_OPC_ExtractField, 22, 3,  // Inst{24-22} ...
/* 11 */      MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 27
/* 16 */      MCD_OPC_CheckField, 25, 5, 0, 125, 29, 0, // Skip to: 7572
/* 23 */      MCD_OPC_Decode, 238, 5, 0, // Opcode: UNIMP
/* 27 */      MCD_OPC_FilterValue, 1, 127, 0, 0, // Skip to: 159
/* 32 */      MCD_OPC_ExtractField, 19, 3,  // Inst{21-19} ...
/* 35 */      MCD_OPC_FilterValue, 0, 31, 0, 0, // Skip to: 71
/* 40 */      MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 43 */      MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 57
/* 48 */      MCD_OPC_CheckPredicate, 0, 95, 29, 0, // Skip to: 7572
/* 53 */      MCD_OPC_Decode, 195, 2, 1, // Opcode: BPICCNT
/* 57 */      MCD_OPC_FilterValue, 1, 86, 29, 0, // Skip to: 7572
/* 62 */      MCD_OPC_CheckPredicate, 0, 81, 29, 0, // Skip to: 7572
/* 67 */      MCD_OPC_Decode, 194, 2, 1, // Opcode: BPICCANT
/* 71 */      MCD_OPC_FilterValue, 1, 31, 0, 0, // Skip to: 107
/* 76 */      MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 79 */      MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 93
/* 84 */      MCD_OPC_CheckPredicate, 0, 59, 29, 0, // Skip to: 7572
/* 89 */      MCD_OPC_Decode, 192, 2, 1, // Opcode: BPICC
/* 93 */      MCD_OPC_FilterValue, 1, 50, 29, 0, // Skip to: 7572
/* 98 */      MCD_OPC_CheckPredicate, 0, 45, 29, 0, // Skip to: 7572
/* 103 */     MCD_OPC_Decode, 193, 2, 1, // Opcode: BPICCA
/* 107 */     MCD_OPC_FilterValue, 4, 21, 0, 0, // Skip to: 133
/* 112 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 115 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 124
/* 120 */     MCD_OPC_Decode, 203, 2, 1, // Opcode: BPXCCNT
/* 124 */     MCD_OPC_FilterValue, 1, 19, 29, 0, // Skip to: 7572
/* 129 */     MCD_OPC_Decode, 202, 2, 1, // Opcode: BPXCCANT
/* 133 */     MCD_OPC_FilterValue, 5, 10, 29, 0, // Skip to: 7572
/* 138 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 141 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 150
/* 146 */     MCD_OPC_Decode, 200, 2, 1, // Opcode: BPXCC
/* 150 */     MCD_OPC_FilterValue, 1, 249, 28, 0, // Skip to: 7572
/* 155 */     MCD_OPC_Decode, 201, 2, 1, // Opcode: BPXCCA
/* 159 */     MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 185
/* 164 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 167 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 176
/* 172 */     MCD_OPC_Decode, 183, 2, 2, // Opcode: BCOND
/* 176 */     MCD_OPC_FilterValue, 1, 223, 28, 0, // Skip to: 7572
/* 181 */     MCD_OPC_Decode, 184, 2, 2, // Opcode: BCONDA
/* 185 */     MCD_OPC_FilterValue, 3, 55, 0, 0, // Skip to: 245
/* 190 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 193 */     MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 219
/* 198 */     MCD_OPC_ExtractField, 28, 2,  // Inst{29-28} ...
/* 201 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 210
/* 206 */     MCD_OPC_Decode, 199, 2, 3, // Opcode: BPRNT
/* 210 */     MCD_OPC_FilterValue, 2, 189, 28, 0, // Skip to: 7572
/* 215 */     MCD_OPC_Decode, 198, 2, 3, // Opcode: BPRANT
/* 219 */     MCD_OPC_FilterValue, 1, 180, 28, 0, // Skip to: 7572
/* 224 */     MCD_OPC_ExtractField, 28, 2,  // Inst{29-28} ...
/* 227 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 236
/* 232 */     MCD_OPC_Decode, 196, 2, 3, // Opcode: BPR
/* 236 */     MCD_OPC_FilterValue, 2, 163, 28, 0, // Skip to: 7572
/* 241 */     MCD_OPC_Decode, 197, 2, 3, // Opcode: BPRA
/* 245 */     MCD_OPC_FilterValue, 4, 22, 0, 0, // Skip to: 272
/* 250 */     MCD_OPC_CheckField, 25, 5, 0, 11, 0, 0, // Skip to: 268
/* 257 */     MCD_OPC_CheckField, 0, 22, 0, 4, 0, 0, // Skip to: 268
/* 264 */     MCD_OPC_Decode, 210, 4, 4, // Opcode: NOP
/* 268 */     MCD_OPC_Decode, 249, 4, 5, // Opcode: SETHIi
/* 272 */     MCD_OPC_FilterValue, 5, 107, 0, 0, // Skip to: 384
/* 277 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 280 */     MCD_OPC_FilterValue, 0, 31, 0, 0, // Skip to: 316
/* 285 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 288 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 302
/* 293 */     MCD_OPC_CheckPredicate, 0, 106, 28, 0, // Skip to: 7572
/* 298 */     MCD_OPC_Decode, 191, 2, 6, // Opcode: BPFCCNT
/* 302 */     MCD_OPC_FilterValue, 1, 97, 28, 0, // Skip to: 7572
/* 307 */     MCD_OPC_CheckPredicate, 0, 92, 28, 0, // Skip to: 7572
/* 312 */     MCD_OPC_Decode, 190, 2, 6, // Opcode: BPFCCANT
/* 316 */     MCD_OPC_FilterValue, 1, 83, 28, 0, // Skip to: 7572
/* 321 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 324 */     MCD_OPC_FilterValue, 0, 25, 0, 0, // Skip to: 354
/* 329 */     MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 345
/* 334 */     MCD_OPC_CheckField, 20, 2, 0, 4, 0, 0, // Skip to: 345
/* 341 */     MCD_OPC_Decode, 246, 2, 1, // Opcode: FBCOND_V9
/* 345 */     MCD_OPC_CheckPredicate, 0, 54, 28, 0, // Skip to: 7572
/* 350 */     MCD_OPC_Decode, 188, 2, 6, // Opcode: BPFCC
/* 354 */     MCD_OPC_FilterValue, 1, 45, 28, 0, // Skip to: 7572
/* 359 */     MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 375
/* 364 */     MCD_OPC_CheckField, 20, 2, 0, 4, 0, 0, // Skip to: 375
/* 371 */     MCD_OPC_Decode, 245, 2, 1, // Opcode: FBCONDA_V9
/* 375 */     MCD_OPC_CheckPredicate, 0, 24, 28, 0, // Skip to: 7572
/* 380 */     MCD_OPC_Decode, 189, 2, 6, // Opcode: BPFCCA
/* 384 */     MCD_OPC_FilterValue, 6, 21, 0, 0, // Skip to: 410
/* 389 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 392 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 401
/* 397 */     MCD_OPC_Decode, 243, 2, 2, // Opcode: FBCOND
/* 401 */     MCD_OPC_FilterValue, 1, 254, 27, 0, // Skip to: 7572
/* 406 */     MCD_OPC_Decode, 244, 2, 2, // Opcode: FBCONDA
/* 410 */     MCD_OPC_FilterValue, 7, 245, 27, 0, // Skip to: 7572
/* 415 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 418 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 427
/* 423 */     MCD_OPC_Decode, 212, 2, 2, // Opcode: CBCOND
/* 427 */     MCD_OPC_FilterValue, 1, 228, 27, 0, // Skip to: 7572
/* 432 */     MCD_OPC_Decode, 213, 2, 2, // Opcode: CBCONDA
/* 436 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 445
/* 441 */     MCD_OPC_Decode, 205, 2, 7, // Opcode: CALL
/* 445 */     MCD_OPC_FilterValue, 2, 176, 21, 0, // Skip to: 6002
/* 450 */     MCD_OPC_ExtractField, 19, 6,  // Inst{24-19} ...
/* 453 */     MCD_OPC_FilterValue, 0, 28, 0, 0, // Skip to: 486
/* 458 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 461 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 477
/* 466 */     MCD_OPC_CheckField, 5, 8, 0, 187, 27, 0, // Skip to: 7572
/* 473 */     MCD_OPC_Decode, 169, 2, 8, // Opcode: ADDrr
/* 477 */     MCD_OPC_FilterValue, 1, 178, 27, 0, // Skip to: 7572
/* 482 */     MCD_OPC_Decode, 168, 2, 9, // Opcode: ADDri
/* 486 */     MCD_OPC_FilterValue, 1, 28, 0, 0, // Skip to: 519
/* 491 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 494 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 510
/* 499 */     MCD_OPC_CheckField, 5, 8, 0, 154, 27, 0, // Skip to: 7572
/* 506 */     MCD_OPC_Decode, 179, 2, 8, // Opcode: ANDrr
/* 510 */     MCD_OPC_FilterValue, 1, 145, 27, 0, // Skip to: 7572
/* 515 */     MCD_OPC_Decode, 178, 2, 9, // Opcode: ANDri
/* 519 */     MCD_OPC_FilterValue, 2, 28, 0, 0, // Skip to: 552
/* 524 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 527 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 543
/* 532 */     MCD_OPC_CheckField, 5, 8, 0, 121, 27, 0, // Skip to: 7572
/* 539 */     MCD_OPC_Decode, 218, 4, 8, // Opcode: ORrr
/* 543 */     MCD_OPC_FilterValue, 1, 112, 27, 0, // Skip to: 7572
/* 548 */     MCD_OPC_Decode, 217, 4, 9, // Opcode: ORri
/* 552 */     MCD_OPC_FilterValue, 3, 28, 0, 0, // Skip to: 585
/* 557 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 560 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 576
/* 565 */     MCD_OPC_CheckField, 5, 8, 0, 88, 27, 0, // Skip to: 7572
/* 572 */     MCD_OPC_Decode, 141, 6, 8, // Opcode: XORrr
/* 576 */     MCD_OPC_FilterValue, 1, 79, 27, 0, // Skip to: 7572
/* 581 */     MCD_OPC_Decode, 140, 6, 9, // Opcode: XORri
/* 585 */     MCD_OPC_FilterValue, 4, 28, 0, 0, // Skip to: 618
/* 590 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 593 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 609
/* 598 */     MCD_OPC_CheckField, 5, 8, 0, 55, 27, 0, // Skip to: 7572
/* 605 */     MCD_OPC_Decode, 197, 5, 8, // Opcode: SUBrr
/* 609 */     MCD_OPC_FilterValue, 1, 46, 27, 0, // Skip to: 7572
/* 614 */     MCD_OPC_Decode, 196, 5, 9, // Opcode: SUBri
/* 618 */     MCD_OPC_FilterValue, 5, 28, 0, 0, // Skip to: 651
/* 623 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 626 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 642
/* 631 */     MCD_OPC_CheckField, 5, 8, 0, 22, 27, 0, // Skip to: 7572
/* 638 */     MCD_OPC_Decode, 177, 2, 8, // Opcode: ANDNrr
/* 642 */     MCD_OPC_FilterValue, 1, 13, 27, 0, // Skip to: 7572
/* 647 */     MCD_OPC_Decode, 176, 2, 9, // Opcode: ANDNri
/* 651 */     MCD_OPC_FilterValue, 6, 28, 0, 0, // Skip to: 684
/* 656 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 659 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 675
/* 664 */     MCD_OPC_CheckField, 5, 8, 0, 245, 26, 0, // Skip to: 7572
/* 671 */     MCD_OPC_Decode, 216, 4, 8, // Opcode: ORNrr
/* 675 */     MCD_OPC_FilterValue, 1, 236, 26, 0, // Skip to: 7572
/* 680 */     MCD_OPC_Decode, 215, 4, 9, // Opcode: ORNri
/* 684 */     MCD_OPC_FilterValue, 7, 28, 0, 0, // Skip to: 717
/* 689 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 692 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 708
/* 697 */     MCD_OPC_CheckField, 5, 8, 0, 212, 26, 0, // Skip to: 7572
/* 704 */     MCD_OPC_Decode, 137, 6, 8, // Opcode: XNORrr
/* 708 */     MCD_OPC_FilterValue, 1, 203, 26, 0, // Skip to: 7572
/* 713 */     MCD_OPC_Decode, 136, 6, 9, // Opcode: XNORri
/* 717 */     MCD_OPC_FilterValue, 8, 28, 0, 0, // Skip to: 750
/* 722 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 725 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 741
/* 730 */     MCD_OPC_CheckField, 5, 8, 0, 179, 26, 0, // Skip to: 7572
/* 737 */     MCD_OPC_Decode, 163, 2, 8, // Opcode: ADDCrr
/* 741 */     MCD_OPC_FilterValue, 1, 170, 26, 0, // Skip to: 7572
/* 746 */     MCD_OPC_Decode, 162, 2, 9, // Opcode: ADDCri
/* 750 */     MCD_OPC_FilterValue, 9, 28, 0, 0, // Skip to: 783
/* 755 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 758 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 774
/* 763 */     MCD_OPC_CheckField, 5, 8, 0, 146, 26, 0, // Skip to: 7572
/* 770 */     MCD_OPC_Decode, 209, 4, 10, // Opcode: MULXrr
/* 774 */     MCD_OPC_FilterValue, 1, 137, 26, 0, // Skip to: 7572
/* 779 */     MCD_OPC_Decode, 208, 4, 11, // Opcode: MULXri
/* 783 */     MCD_OPC_FilterValue, 10, 28, 0, 0, // Skip to: 816
/* 788 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 791 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 807
/* 796 */     MCD_OPC_CheckField, 5, 8, 0, 113, 26, 0, // Skip to: 7572
/* 803 */     MCD_OPC_Decode, 237, 5, 8, // Opcode: UMULrr
/* 807 */     MCD_OPC_FilterValue, 1, 104, 26, 0, // Skip to: 7572
/* 812 */     MCD_OPC_Decode, 236, 5, 9, // Opcode: UMULri
/* 816 */     MCD_OPC_FilterValue, 11, 28, 0, 0, // Skip to: 849
/* 821 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 824 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 840
/* 829 */     MCD_OPC_CheckField, 5, 8, 0, 80, 26, 0, // Skip to: 7572
/* 836 */     MCD_OPC_Decode, 134, 5, 8, // Opcode: SMULrr
/* 840 */     MCD_OPC_FilterValue, 1, 71, 26, 0, // Skip to: 7572
/* 845 */     MCD_OPC_Decode, 133, 5, 9, // Opcode: SMULri
/* 849 */     MCD_OPC_FilterValue, 12, 28, 0, 0, // Skip to: 882
/* 854 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 857 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 873
/* 862 */     MCD_OPC_CheckField, 5, 8, 0, 47, 26, 0, // Skip to: 7572
/* 869 */     MCD_OPC_Decode, 193, 5, 8, // Opcode: SUBCrr
/* 873 */     MCD_OPC_FilterValue, 1, 38, 26, 0, // Skip to: 7572
/* 878 */     MCD_OPC_Decode, 192, 5, 9, // Opcode: SUBCri
/* 882 */     MCD_OPC_FilterValue, 13, 28, 0, 0, // Skip to: 915
/* 887 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 890 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 906
/* 895 */     MCD_OPC_CheckField, 5, 8, 0, 14, 26, 0, // Skip to: 7572
/* 902 */     MCD_OPC_Decode, 228, 5, 10, // Opcode: UDIVXrr
/* 906 */     MCD_OPC_FilterValue, 1, 5, 26, 0, // Skip to: 7572
/* 911 */     MCD_OPC_Decode, 227, 5, 11, // Opcode: UDIVXri
/* 915 */     MCD_OPC_FilterValue, 14, 28, 0, 0, // Skip to: 948
/* 920 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 923 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 939
/* 928 */     MCD_OPC_CheckField, 5, 8, 0, 237, 25, 0, // Skip to: 7572
/* 935 */     MCD_OPC_Decode, 230, 5, 8, // Opcode: UDIVrr
/* 939 */     MCD_OPC_FilterValue, 1, 228, 25, 0, // Skip to: 7572
/* 944 */     MCD_OPC_Decode, 229, 5, 9, // Opcode: UDIVri
/* 948 */     MCD_OPC_FilterValue, 15, 28, 0, 0, // Skip to: 981
/* 953 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 956 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 972
/* 961 */     MCD_OPC_CheckField, 5, 8, 0, 204, 25, 0, // Skip to: 7572
/* 968 */     MCD_OPC_Decode, 248, 4, 8, // Opcode: SDIVrr
/* 972 */     MCD_OPC_FilterValue, 1, 195, 25, 0, // Skip to: 7572
/* 977 */     MCD_OPC_Decode, 247, 4, 9, // Opcode: SDIVri
/* 981 */     MCD_OPC_FilterValue, 16, 28, 0, 0, // Skip to: 1014
/* 986 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 989 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1005
/* 994 */     MCD_OPC_CheckField, 5, 8, 0, 171, 25, 0, // Skip to: 7572
/* 1001 */    MCD_OPC_Decode, 161, 2, 8, // Opcode: ADDCCrr
/* 1005 */    MCD_OPC_FilterValue, 1, 162, 25, 0, // Skip to: 7572
/* 1010 */    MCD_OPC_Decode, 160, 2, 9, // Opcode: ADDCCri
/* 1014 */    MCD_OPC_FilterValue, 17, 28, 0, 0, // Skip to: 1047
/* 1019 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1022 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1038
/* 1027 */    MCD_OPC_CheckField, 5, 8, 0, 138, 25, 0, // Skip to: 7572
/* 1034 */    MCD_OPC_Decode, 173, 2, 8, // Opcode: ANDCCrr
/* 1038 */    MCD_OPC_FilterValue, 1, 129, 25, 0, // Skip to: 7572
/* 1043 */    MCD_OPC_Decode, 172, 2, 9, // Opcode: ANDCCri
/* 1047 */    MCD_OPC_FilterValue, 18, 28, 0, 0, // Skip to: 1080
/* 1052 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1055 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1071
/* 1060 */    MCD_OPC_CheckField, 5, 8, 0, 105, 25, 0, // Skip to: 7572
/* 1067 */    MCD_OPC_Decode, 212, 4, 8, // Opcode: ORCCrr
/* 1071 */    MCD_OPC_FilterValue, 1, 96, 25, 0, // Skip to: 7572
/* 1076 */    MCD_OPC_Decode, 211, 4, 9, // Opcode: ORCCri
/* 1080 */    MCD_OPC_FilterValue, 19, 28, 0, 0, // Skip to: 1113
/* 1085 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1088 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1104
/* 1093 */    MCD_OPC_CheckField, 5, 8, 0, 72, 25, 0, // Skip to: 7572
/* 1100 */    MCD_OPC_Decode, 139, 6, 8, // Opcode: XORCCrr
/* 1104 */    MCD_OPC_FilterValue, 1, 63, 25, 0, // Skip to: 7572
/* 1109 */    MCD_OPC_Decode, 138, 6, 9, // Opcode: XORCCri
/* 1113 */    MCD_OPC_FilterValue, 20, 28, 0, 0, // Skip to: 1146
/* 1118 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1121 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1137
/* 1126 */    MCD_OPC_CheckField, 5, 8, 0, 39, 25, 0, // Skip to: 7572
/* 1133 */    MCD_OPC_Decode, 191, 5, 8, // Opcode: SUBCCrr
/* 1137 */    MCD_OPC_FilterValue, 1, 30, 25, 0, // Skip to: 7572
/* 1142 */    MCD_OPC_Decode, 190, 5, 9, // Opcode: SUBCCri
/* 1146 */    MCD_OPC_FilterValue, 21, 28, 0, 0, // Skip to: 1179
/* 1151 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1154 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1170
/* 1159 */    MCD_OPC_CheckField, 5, 8, 0, 6, 25, 0, // Skip to: 7572
/* 1166 */    MCD_OPC_Decode, 175, 2, 8, // Opcode: ANDNCCrr
/* 1170 */    MCD_OPC_FilterValue, 1, 253, 24, 0, // Skip to: 7572
/* 1175 */    MCD_OPC_Decode, 174, 2, 9, // Opcode: ANDNCCri
/* 1179 */    MCD_OPC_FilterValue, 22, 28, 0, 0, // Skip to: 1212
/* 1184 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1187 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1203
/* 1192 */    MCD_OPC_CheckField, 5, 8, 0, 229, 24, 0, // Skip to: 7572
/* 1199 */    MCD_OPC_Decode, 214, 4, 8, // Opcode: ORNCCrr
/* 1203 */    MCD_OPC_FilterValue, 1, 220, 24, 0, // Skip to: 7572
/* 1208 */    MCD_OPC_Decode, 213, 4, 9, // Opcode: ORNCCri
/* 1212 */    MCD_OPC_FilterValue, 23, 28, 0, 0, // Skip to: 1245
/* 1217 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1220 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1236
/* 1225 */    MCD_OPC_CheckField, 5, 8, 0, 196, 24, 0, // Skip to: 7572
/* 1232 */    MCD_OPC_Decode, 135, 6, 8, // Opcode: XNORCCrr
/* 1236 */    MCD_OPC_FilterValue, 1, 187, 24, 0, // Skip to: 7572
/* 1241 */    MCD_OPC_Decode, 134, 6, 9, // Opcode: XNORCCri
/* 1245 */    MCD_OPC_FilterValue, 24, 28, 0, 0, // Skip to: 1278
/* 1250 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1253 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1269
/* 1258 */    MCD_OPC_CheckField, 5, 8, 0, 163, 24, 0, // Skip to: 7572
/* 1265 */    MCD_OPC_Decode, 165, 2, 8, // Opcode: ADDErr
/* 1269 */    MCD_OPC_FilterValue, 1, 154, 24, 0, // Skip to: 7572
/* 1274 */    MCD_OPC_Decode, 164, 2, 9, // Opcode: ADDEri
/* 1278 */    MCD_OPC_FilterValue, 26, 28, 0, 0, // Skip to: 1311
/* 1283 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1286 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1302
/* 1291 */    MCD_OPC_CheckField, 5, 8, 0, 130, 24, 0, // Skip to: 7572
/* 1298 */    MCD_OPC_Decode, 234, 5, 8, // Opcode: UMULCCrr
/* 1302 */    MCD_OPC_FilterValue, 1, 121, 24, 0, // Skip to: 7572
/* 1307 */    MCD_OPC_Decode, 233, 5, 9, // Opcode: UMULCCri
/* 1311 */    MCD_OPC_FilterValue, 27, 28, 0, 0, // Skip to: 1344
/* 1316 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1319 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1335
/* 1324 */    MCD_OPC_CheckField, 5, 8, 0, 97, 24, 0, // Skip to: 7572
/* 1331 */    MCD_OPC_Decode, 132, 5, 8, // Opcode: SMULCCrr
/* 1335 */    MCD_OPC_FilterValue, 1, 88, 24, 0, // Skip to: 7572
/* 1340 */    MCD_OPC_Decode, 131, 5, 9, // Opcode: SMULCCri
/* 1344 */    MCD_OPC_FilterValue, 28, 28, 0, 0, // Skip to: 1377
/* 1349 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1352 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1368
/* 1357 */    MCD_OPC_CheckField, 5, 8, 0, 64, 24, 0, // Skip to: 7572
/* 1364 */    MCD_OPC_Decode, 195, 5, 8, // Opcode: SUBErr
/* 1368 */    MCD_OPC_FilterValue, 1, 55, 24, 0, // Skip to: 7572
/* 1373 */    MCD_OPC_Decode, 194, 5, 9, // Opcode: SUBEri
/* 1377 */    MCD_OPC_FilterValue, 30, 28, 0, 0, // Skip to: 1410
/* 1382 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1385 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1401
/* 1390 */    MCD_OPC_CheckField, 5, 8, 0, 31, 24, 0, // Skip to: 7572
/* 1397 */    MCD_OPC_Decode, 226, 5, 8, // Opcode: UDIVCCrr
/* 1401 */    MCD_OPC_FilterValue, 1, 22, 24, 0, // Skip to: 7572
/* 1406 */    MCD_OPC_Decode, 225, 5, 9, // Opcode: UDIVCCri
/* 1410 */    MCD_OPC_FilterValue, 31, 28, 0, 0, // Skip to: 1443
/* 1415 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1418 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1434
/* 1423 */    MCD_OPC_CheckField, 5, 8, 0, 254, 23, 0, // Skip to: 7572
/* 1430 */    MCD_OPC_Decode, 244, 4, 8, // Opcode: SDIVCCrr
/* 1434 */    MCD_OPC_FilterValue, 1, 245, 23, 0, // Skip to: 7572
/* 1439 */    MCD_OPC_Decode, 243, 4, 9, // Opcode: SDIVCCri
/* 1443 */    MCD_OPC_FilterValue, 32, 28, 0, 0, // Skip to: 1476
/* 1448 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1451 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1467
/* 1456 */    MCD_OPC_CheckField, 5, 8, 0, 221, 23, 0, // Skip to: 7572
/* 1463 */    MCD_OPC_Decode, 208, 5, 8, // Opcode: TADDCCrr
/* 1467 */    MCD_OPC_FilterValue, 1, 212, 23, 0, // Skip to: 7572
/* 1472 */    MCD_OPC_Decode, 207, 5, 9, // Opcode: TADDCCri
/* 1476 */    MCD_OPC_FilterValue, 33, 28, 0, 0, // Skip to: 1509
/* 1481 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1484 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1500
/* 1489 */    MCD_OPC_CheckField, 5, 8, 0, 188, 23, 0, // Skip to: 7572
/* 1496 */    MCD_OPC_Decode, 222, 5, 8, // Opcode: TSUBCCrr
/* 1500 */    MCD_OPC_FilterValue, 1, 179, 23, 0, // Skip to: 7572
/* 1505 */    MCD_OPC_Decode, 221, 5, 9, // Opcode: TSUBCCri
/* 1509 */    MCD_OPC_FilterValue, 34, 28, 0, 0, // Skip to: 1542
/* 1514 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1517 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1533
/* 1522 */    MCD_OPC_CheckField, 5, 8, 0, 155, 23, 0, // Skip to: 7572
/* 1529 */    MCD_OPC_Decode, 206, 5, 8, // Opcode: TADDCCTVrr
/* 1533 */    MCD_OPC_FilterValue, 1, 146, 23, 0, // Skip to: 7572
/* 1538 */    MCD_OPC_Decode, 205, 5, 9, // Opcode: TADDCCTVri
/* 1542 */    MCD_OPC_FilterValue, 35, 28, 0, 0, // Skip to: 1575
/* 1547 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1550 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1566
/* 1555 */    MCD_OPC_CheckField, 5, 8, 0, 122, 23, 0, // Skip to: 7572
/* 1562 */    MCD_OPC_Decode, 220, 5, 8, // Opcode: TSUBCCTVrr
/* 1566 */    MCD_OPC_FilterValue, 1, 113, 23, 0, // Skip to: 7572
/* 1571 */    MCD_OPC_Decode, 219, 5, 9, // Opcode: TSUBCCTVri
/* 1575 */    MCD_OPC_FilterValue, 36, 28, 0, 0, // Skip to: 1608
/* 1580 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1583 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1599
/* 1588 */    MCD_OPC_CheckField, 5, 8, 0, 89, 23, 0, // Skip to: 7572
/* 1595 */    MCD_OPC_Decode, 207, 4, 8, // Opcode: MULSCCrr
/* 1599 */    MCD_OPC_FilterValue, 1, 80, 23, 0, // Skip to: 7572
/* 1604 */    MCD_OPC_Decode, 206, 4, 9, // Opcode: MULSCCri
/* 1608 */    MCD_OPC_FilterValue, 37, 39, 0, 0, // Skip to: 1652
/* 1613 */    MCD_OPC_ExtractField, 12, 2,  // Inst{13-12} ...
/* 1616 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1625
/* 1621 */    MCD_OPC_Decode, 128, 5, 8, // Opcode: SLLrr
/* 1625 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1634
/* 1630 */    MCD_OPC_Decode, 254, 4, 12, // Opcode: SLLXrr
/* 1634 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1643
/* 1639 */    MCD_OPC_Decode, 255, 4, 13, // Opcode: SLLri
/* 1643 */    MCD_OPC_FilterValue, 3, 36, 23, 0, // Skip to: 7572
/* 1648 */    MCD_OPC_Decode, 253, 4, 14, // Opcode: SLLXri
/* 1652 */    MCD_OPC_FilterValue, 38, 39, 0, 0, // Skip to: 1696
/* 1657 */    MCD_OPC_ExtractField, 12, 2,  // Inst{13-12} ...
/* 1660 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1669
/* 1665 */    MCD_OPC_Decode, 142, 5, 8, // Opcode: SRLrr
/* 1669 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1678
/* 1674 */    MCD_OPC_Decode, 140, 5, 12, // Opcode: SRLXrr
/* 1678 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1687
/* 1683 */    MCD_OPC_Decode, 141, 5, 13, // Opcode: SRLri
/* 1687 */    MCD_OPC_FilterValue, 3, 248, 22, 0, // Skip to: 7572
/* 1692 */    MCD_OPC_Decode, 139, 5, 14, // Opcode: SRLXri
/* 1696 */    MCD_OPC_FilterValue, 39, 39, 0, 0, // Skip to: 1740
/* 1701 */    MCD_OPC_ExtractField, 12, 2,  // Inst{13-12} ...
/* 1704 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1713
/* 1709 */    MCD_OPC_Decode, 138, 5, 8, // Opcode: SRArr
/* 1713 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1722
/* 1718 */    MCD_OPC_Decode, 136, 5, 12, // Opcode: SRAXrr
/* 1722 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1731
/* 1727 */    MCD_OPC_Decode, 137, 5, 13, // Opcode: SRAri
/* 1731 */    MCD_OPC_FilterValue, 3, 204, 22, 0, // Skip to: 7572
/* 1736 */    MCD_OPC_Decode, 135, 5, 14, // Opcode: SRAXri
/* 1740 */    MCD_OPC_FilterValue, 40, 66, 0, 0, // Skip to: 1811
/* 1745 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1748 */    MCD_OPC_FilterValue, 0, 30, 0, 0, // Skip to: 1783
/* 1753 */    MCD_OPC_ExtractField, 0, 13,  // Inst{12-0} ...
/* 1756 */    MCD_OPC_FilterValue, 0, 179, 22, 0, // Skip to: 7572
/* 1761 */    MCD_OPC_CheckField, 25, 5, 0, 11, 0, 0, // Skip to: 1779
/* 1768 */    MCD_OPC_CheckField, 14, 5, 15, 4, 0, 0, // Skip to: 1779
/* 1775 */    MCD_OPC_Decode, 145, 5, 4, // Opcode: STBAR
/* 1779 */    MCD_OPC_Decode, 226, 4, 15, // Opcode: RDASR
/* 1783 */    MCD_OPC_FilterValue, 1, 152, 22, 0, // Skip to: 7572
/* 1788 */    MCD_OPC_CheckPredicate, 0, 147, 22, 0, // Skip to: 7572
/* 1793 */    MCD_OPC_CheckField, 25, 5, 0, 140, 22, 0, // Skip to: 7572
/* 1800 */    MCD_OPC_CheckField, 14, 5, 15, 133, 22, 0, // Skip to: 7572
/* 1807 */    MCD_OPC_Decode, 192, 4, 16, // Opcode: MEMBARi
/* 1811 */    MCD_OPC_FilterValue, 41, 11, 0, 0, // Skip to: 1827
/* 1816 */    MCD_OPC_CheckField, 0, 19, 0, 117, 22, 0, // Skip to: 7572
/* 1823 */    MCD_OPC_Decode, 229, 4, 17, // Opcode: RDPSR
/* 1827 */    MCD_OPC_FilterValue, 42, 43, 0, 0, // Skip to: 1875
/* 1832 */    MCD_OPC_ExtractField, 0, 14,  // Inst{13-0} ...
/* 1835 */    MCD_OPC_FilterValue, 0, 100, 22, 0, // Skip to: 7572
/* 1840 */    MCD_OPC_ExtractField, 14, 5,  // Inst{18-14} ...
/* 1843 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1852
/* 1848 */    MCD_OPC_Decode, 231, 4, 17, // Opcode: RDWIM
/* 1852 */    MCD_OPC_FilterValue, 15, 9, 0, 0, // Skip to: 1866
/* 1857 */    MCD_OPC_CheckPredicate, 0, 4, 0, 0, // Skip to: 1866
/* 1862 */    MCD_OPC_Decode, 227, 4, 17, // Opcode: RDFQ
/* 1866 */    MCD_OPC_CheckPredicate, 0, 69, 22, 0, // Skip to: 7572
/* 1871 */    MCD_OPC_Decode, 228, 4, 18, // Opcode: RDPR
/* 1875 */    MCD_OPC_FilterValue, 43, 28, 0, 0, // Skip to: 1908
/* 1880 */    MCD_OPC_ExtractField, 0, 19,  // Inst{18-0} ...
/* 1883 */    MCD_OPC_FilterValue, 0, 52, 22, 0, // Skip to: 7572
/* 1888 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 1904
/* 1893 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 1904
/* 1900 */    MCD_OPC_Decode, 153, 3, 4, // Opcode: FLUSHW
/* 1904 */    MCD_OPC_Decode, 230, 4, 17, // Opcode: RDTBR
/* 1908 */    MCD_OPC_FilterValue, 44, 141, 0, 0, // Skip to: 2054
/* 1913 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1916 */    MCD_OPC_FilterValue, 0, 64, 0, 0, // Skip to: 1985
/* 1921 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 1924 */    MCD_OPC_FilterValue, 0, 25, 0, 0, // Skip to: 1954
/* 1929 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 1945
/* 1934 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 1945
/* 1941 */    MCD_OPC_Decode, 195, 4, 19, // Opcode: MOVFCCrr
/* 1945 */    MCD_OPC_CheckPredicate, 0, 246, 21, 0, // Skip to: 7572
/* 1950 */    MCD_OPC_Decode, 249, 5, 20, // Opcode: V9MOVFCCrr
/* 1954 */    MCD_OPC_FilterValue, 1, 237, 21, 0, // Skip to: 7572
/* 1959 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 1962 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 1976
/* 1967 */    MCD_OPC_CheckPredicate, 0, 224, 21, 0, // Skip to: 7572
/* 1972 */    MCD_OPC_Decode, 197, 4, 19, // Opcode: MOVICCrr
/* 1976 */    MCD_OPC_FilterValue, 2, 215, 21, 0, // Skip to: 7572
/* 1981 */    MCD_OPC_Decode, 204, 4, 19, // Opcode: MOVXCCrr
/* 1985 */    MCD_OPC_FilterValue, 1, 206, 21, 0, // Skip to: 7572
/* 1990 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 1993 */    MCD_OPC_FilterValue, 0, 25, 0, 0, // Skip to: 2023
/* 1998 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 2014
/* 2003 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 2014
/* 2010 */    MCD_OPC_Decode, 194, 4, 21, // Opcode: MOVFCCri
/* 2014 */    MCD_OPC_CheckPredicate, 0, 177, 21, 0, // Skip to: 7572
/* 2019 */    MCD_OPC_Decode, 248, 5, 22, // Opcode: V9MOVFCCri
/* 2023 */    MCD_OPC_FilterValue, 1, 168, 21, 0, // Skip to: 7572
/* 2028 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 2031 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 2045
/* 2036 */    MCD_OPC_CheckPredicate, 0, 155, 21, 0, // Skip to: 7572
/* 2041 */    MCD_OPC_Decode, 196, 4, 21, // Opcode: MOVICCri
/* 2045 */    MCD_OPC_FilterValue, 2, 146, 21, 0, // Skip to: 7572
/* 2050 */    MCD_OPC_Decode, 203, 4, 21, // Opcode: MOVXCCri
/* 2054 */    MCD_OPC_FilterValue, 45, 28, 0, 0, // Skip to: 2087
/* 2059 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2062 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2078
/* 2067 */    MCD_OPC_CheckField, 5, 8, 0, 122, 21, 0, // Skip to: 7572
/* 2074 */    MCD_OPC_Decode, 246, 4, 10, // Opcode: SDIVXrr
/* 2078 */    MCD_OPC_FilterValue, 1, 113, 21, 0, // Skip to: 7572
/* 2083 */    MCD_OPC_Decode, 245, 4, 11, // Opcode: SDIVXri
/* 2087 */    MCD_OPC_FilterValue, 46, 16, 0, 0, // Skip to: 2108
/* 2092 */    MCD_OPC_CheckPredicate, 0, 99, 21, 0, // Skip to: 7572
/* 2097 */    MCD_OPC_CheckField, 5, 14, 0, 92, 21, 0, // Skip to: 7572
/* 2104 */    MCD_OPC_Decode, 221, 4, 23, // Opcode: POPCrr
/* 2108 */    MCD_OPC_FilterValue, 47, 28, 0, 0, // Skip to: 2141
/* 2113 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2116 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2132
/* 2121 */    MCD_OPC_CheckField, 5, 5, 0, 68, 21, 0, // Skip to: 7572
/* 2128 */    MCD_OPC_Decode, 199, 4, 24, // Opcode: MOVRrr
/* 2132 */    MCD_OPC_FilterValue, 1, 59, 21, 0, // Skip to: 7572
/* 2137 */    MCD_OPC_Decode, 198, 4, 25, // Opcode: MOVRri
/* 2141 */    MCD_OPC_FilterValue, 48, 51, 0, 0, // Skip to: 2197
/* 2146 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2149 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2165
/* 2154 */    MCD_OPC_CheckField, 5, 8, 0, 35, 21, 0, // Skip to: 7572
/* 2161 */    MCD_OPC_Decode, 251, 5, 26, // Opcode: WRASRrr
/* 2165 */    MCD_OPC_FilterValue, 1, 26, 21, 0, // Skip to: 7572
/* 2170 */    MCD_OPC_CheckPredicate, 0, 18, 0, 0, // Skip to: 2193
/* 2175 */    MCD_OPC_CheckField, 25, 5, 15, 11, 0, 0, // Skip to: 2193
/* 2182 */    MCD_OPC_CheckField, 14, 5, 0, 4, 0, 0, // Skip to: 2193
/* 2189 */    MCD_OPC_Decode, 252, 4, 27, // Opcode: SIR
/* 2193 */    MCD_OPC_Decode, 250, 5, 28, // Opcode: WRASRri
/* 2197 */    MCD_OPC_FilterValue, 49, 127, 0, 0, // Skip to: 2329
/* 2202 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2205 */    MCD_OPC_FilterValue, 0, 88, 0, 0, // Skip to: 2298
/* 2210 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 2213 */    MCD_OPC_FilterValue, 0, 35, 0, 0, // Skip to: 2253
/* 2218 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 2221 */    MCD_OPC_FilterValue, 0, 226, 20, 0, // Skip to: 7572
/* 2226 */    MCD_OPC_CheckPredicate, 0, 18, 0, 0, // Skip to: 2249
/* 2231 */    MCD_OPC_CheckField, 14, 5, 0, 11, 0, 0, // Skip to: 2249
/* 2238 */    MCD_OPC_CheckField, 0, 5, 0, 4, 0, 0, // Skip to: 2249
/* 2245 */    MCD_OPC_Decode, 240, 4, 4, // Opcode: SAVED
/* 2249 */    MCD_OPC_Decode, 255, 5, 29, // Opcode: WRPSRrr
/* 2253 */    MCD_OPC_FilterValue, 1, 194, 20, 0, // Skip to: 7572
/* 2258 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 2261 */    MCD_OPC_FilterValue, 0, 186, 20, 0, // Skip to: 7572
/* 2266 */    MCD_OPC_CheckPredicate, 0, 18, 0, 0, // Skip to: 2289
/* 2271 */    MCD_OPC_CheckField, 14, 5, 0, 11, 0, 0, // Skip to: 2289
/* 2278 */    MCD_OPC_CheckField, 0, 5, 0, 4, 0, 0, // Skip to: 2289
/* 2285 */    MCD_OPC_Decode, 232, 4, 4, // Opcode: RESTORED
/* 2289 */    MCD_OPC_CheckPredicate, 1, 158, 20, 0, // Skip to: 7572
/* 2294 */    MCD_OPC_Decode, 225, 4, 29, // Opcode: PWRPSRrr
/* 2298 */    MCD_OPC_FilterValue, 1, 149, 20, 0, // Skip to: 7572
/* 2303 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 2306 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2315
/* 2311 */    MCD_OPC_Decode, 254, 5, 30, // Opcode: WRPSRri
/* 2315 */    MCD_OPC_FilterValue, 1, 132, 20, 0, // Skip to: 7572
/* 2320 */    MCD_OPC_CheckPredicate, 1, 127, 20, 0, // Skip to: 7572
/* 2325 */    MCD_OPC_Decode, 224, 4, 30, // Opcode: PWRPSRri
/* 2329 */    MCD_OPC_FilterValue, 50, 61, 0, 0, // Skip to: 2395
/* 2334 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2337 */    MCD_OPC_FilterValue, 0, 28, 0, 0, // Skip to: 2370
/* 2342 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 2345 */    MCD_OPC_FilterValue, 0, 102, 20, 0, // Skip to: 7572
/* 2350 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 2361
/* 2357 */    MCD_OPC_Decode, 131, 6, 29, // Opcode: WRWIMrr
/* 2361 */    MCD_OPC_CheckPredicate, 0, 86, 20, 0, // Skip to: 7572
/* 2366 */    MCD_OPC_Decode, 253, 5, 31, // Opcode: WRPRrr
/* 2370 */    MCD_OPC_FilterValue, 1, 77, 20, 0, // Skip to: 7572
/* 2375 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 2386
/* 2382 */    MCD_OPC_Decode, 130, 6, 30, // Opcode: WRWIMri
/* 2386 */    MCD_OPC_CheckPredicate, 0, 61, 20, 0, // Skip to: 7572
/* 2391 */    MCD_OPC_Decode, 252, 5, 32, // Opcode: WRPRri
/* 2395 */    MCD_OPC_FilterValue, 51, 42, 0, 0, // Skip to: 2442
/* 2400 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2403 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 2426
/* 2408 */    MCD_OPC_CheckField, 25, 5, 0, 37, 20, 0, // Skip to: 7572
/* 2415 */    MCD_OPC_CheckField, 5, 8, 0, 30, 20, 0, // Skip to: 7572
/* 2422 */    MCD_OPC_Decode, 129, 6, 29, // Opcode: WRTBRrr
/* 2426 */    MCD_OPC_FilterValue, 1, 21, 20, 0, // Skip to: 7572
/* 2431 */    MCD_OPC_CheckField, 25, 5, 0, 14, 20, 0, // Skip to: 7572
/* 2438 */    MCD_OPC_Decode, 128, 6, 30, // Opcode: WRTBRri
/* 2442 */    MCD_OPC_FilterValue, 52, 43, 3, 0, // Skip to: 3258
/* 2447 */    MCD_OPC_ExtractField, 5, 9,  // Inst{13-5} ...
/* 2450 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 2466
/* 2455 */    MCD_OPC_CheckField, 14, 5, 0, 246, 19, 0, // Skip to: 7572
/* 2462 */    MCD_OPC_Decode, 168, 3, 33, // Opcode: FMOVS
/* 2466 */    MCD_OPC_FilterValue, 2, 16, 0, 0, // Skip to: 2487
/* 2471 */    MCD_OPC_CheckPredicate, 0, 232, 19, 0, // Skip to: 7572
/* 2476 */    MCD_OPC_CheckField, 14, 5, 0, 225, 19, 0, // Skip to: 7572
/* 2483 */    MCD_OPC_Decode, 157, 3, 34, // Opcode: FMOVD
/* 2487 */    MCD_OPC_FilterValue, 3, 16, 0, 0, // Skip to: 2508
/* 2492 */    MCD_OPC_CheckPredicate, 0, 211, 19, 0, // Skip to: 7572
/* 2497 */    MCD_OPC_CheckField, 14, 5, 0, 204, 19, 0, // Skip to: 7572
/* 2504 */    MCD_OPC_Decode, 161, 3, 35, // Opcode: FMOVQ
/* 2508 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 2524
/* 2513 */    MCD_OPC_CheckField, 14, 5, 0, 188, 19, 0, // Skip to: 7572
/* 2520 */    MCD_OPC_Decode, 188, 3, 33, // Opcode: FNEGS
/* 2524 */    MCD_OPC_FilterValue, 6, 16, 0, 0, // Skip to: 2545
/* 2529 */    MCD_OPC_CheckPredicate, 0, 174, 19, 0, // Skip to: 7572
/* 2534 */    MCD_OPC_CheckField, 14, 5, 0, 167, 19, 0, // Skip to: 7572
/* 2541 */    MCD_OPC_Decode, 186, 3, 34, // Opcode: FNEGD
/* 2545 */    MCD_OPC_FilterValue, 7, 16, 0, 0, // Skip to: 2566
/* 2550 */    MCD_OPC_CheckPredicate, 0, 153, 19, 0, // Skip to: 7572
/* 2555 */    MCD_OPC_CheckField, 14, 5, 0, 146, 19, 0, // Skip to: 7572
/* 2562 */    MCD_OPC_Decode, 187, 3, 35, // Opcode: FNEGQ
/* 2566 */    MCD_OPC_FilterValue, 9, 11, 0, 0, // Skip to: 2582
/* 2571 */    MCD_OPC_CheckField, 14, 5, 0, 130, 19, 0, // Skip to: 7572
/* 2578 */    MCD_OPC_Decode, 232, 2, 33, // Opcode: FABSS
/* 2582 */    MCD_OPC_FilterValue, 10, 16, 0, 0, // Skip to: 2603
/* 2587 */    MCD_OPC_CheckPredicate, 0, 116, 19, 0, // Skip to: 7572
/* 2592 */    MCD_OPC_CheckField, 14, 5, 0, 109, 19, 0, // Skip to: 7572
/* 2599 */    MCD_OPC_Decode, 230, 2, 34, // Opcode: FABSD
/* 2603 */    MCD_OPC_FilterValue, 11, 16, 0, 0, // Skip to: 2624
/* 2608 */    MCD_OPC_CheckPredicate, 0, 95, 19, 0, // Skip to: 7572
/* 2613 */    MCD_OPC_CheckField, 14, 5, 0, 88, 19, 0, // Skip to: 7572
/* 2620 */    MCD_OPC_Decode, 231, 2, 35, // Opcode: FABSQ
/* 2624 */    MCD_OPC_FilterValue, 41, 11, 0, 0, // Skip to: 2640
/* 2629 */    MCD_OPC_CheckField, 14, 5, 0, 72, 19, 0, // Skip to: 7572
/* 2636 */    MCD_OPC_Decode, 232, 3, 33, // Opcode: FSQRTS
/* 2640 */    MCD_OPC_FilterValue, 42, 11, 0, 0, // Skip to: 2656
/* 2645 */    MCD_OPC_CheckField, 14, 5, 0, 56, 19, 0, // Skip to: 7572
/* 2652 */    MCD_OPC_Decode, 230, 3, 34, // Opcode: FSQRTD
/* 2656 */    MCD_OPC_FilterValue, 43, 11, 0, 0, // Skip to: 2672
/* 2661 */    MCD_OPC_CheckField, 14, 5, 0, 40, 19, 0, // Skip to: 7572
/* 2668 */    MCD_OPC_Decode, 231, 3, 35, // Opcode: FSQRTQ
/* 2672 */    MCD_OPC_FilterValue, 65, 4, 0, 0, // Skip to: 2681
/* 2677 */    MCD_OPC_Decode, 235, 2, 36, // Opcode: FADDS
/* 2681 */    MCD_OPC_FilterValue, 66, 4, 0, 0, // Skip to: 2690
/* 2686 */    MCD_OPC_Decode, 233, 2, 37, // Opcode: FADDD
/* 2690 */    MCD_OPC_FilterValue, 67, 4, 0, 0, // Skip to: 2699
/* 2695 */    MCD_OPC_Decode, 234, 2, 38, // Opcode: FADDQ
/* 2699 */    MCD_OPC_FilterValue, 69, 4, 0, 0, // Skip to: 2708
/* 2704 */    MCD_OPC_Decode, 247, 3, 36, // Opcode: FSUBS
/* 2708 */    MCD_OPC_FilterValue, 70, 4, 0, 0, // Skip to: 2717
/* 2713 */    MCD_OPC_Decode, 245, 3, 37, // Opcode: FSUBD
/* 2717 */    MCD_OPC_FilterValue, 71, 4, 0, 0, // Skip to: 2726
/* 2722 */    MCD_OPC_Decode, 246, 3, 38, // Opcode: FSUBQ
/* 2726 */    MCD_OPC_FilterValue, 73, 4, 0, 0, // Skip to: 2735
/* 2731 */    MCD_OPC_Decode, 181, 3, 36, // Opcode: FMULS
/* 2735 */    MCD_OPC_FilterValue, 74, 4, 0, 0, // Skip to: 2744
/* 2740 */    MCD_OPC_Decode, 177, 3, 37, // Opcode: FMULD
/* 2744 */    MCD_OPC_FilterValue, 75, 4, 0, 0, // Skip to: 2753
/* 2749 */    MCD_OPC_Decode, 180, 3, 38, // Opcode: FMULQ
/* 2753 */    MCD_OPC_FilterValue, 77, 4, 0, 0, // Skip to: 2762
/* 2758 */    MCD_OPC_Decode, 136, 3, 36, // Opcode: FDIVS
/* 2762 */    MCD_OPC_FilterValue, 78, 4, 0, 0, // Skip to: 2771
/* 2767 */    MCD_OPC_Decode, 134, 3, 37, // Opcode: FDIVD
/* 2771 */    MCD_OPC_FilterValue, 79, 4, 0, 0, // Skip to: 2780
/* 2776 */    MCD_OPC_Decode, 135, 3, 38, // Opcode: FDIVQ
/* 2780 */    MCD_OPC_FilterValue, 81, 9, 0, 0, // Skip to: 2794
/* 2785 */    MCD_OPC_CheckPredicate, 2, 174, 18, 0, // Skip to: 7572
/* 2790 */    MCD_OPC_Decode, 183, 3, 37, // Opcode: FNADDS
/* 2794 */    MCD_OPC_FilterValue, 82, 9, 0, 0, // Skip to: 2808
/* 2799 */    MCD_OPC_CheckPredicate, 2, 160, 18, 0, // Skip to: 7572
/* 2804 */    MCD_OPC_Decode, 182, 3, 37, // Opcode: FNADDD
/* 2808 */    MCD_OPC_FilterValue, 89, 9, 0, 0, // Skip to: 2822
/* 2813 */    MCD_OPC_CheckPredicate, 2, 146, 18, 0, // Skip to: 7572
/* 2818 */    MCD_OPC_Decode, 192, 3, 37, // Opcode: FNMULS
/* 2822 */    MCD_OPC_FilterValue, 90, 9, 0, 0, // Skip to: 2836
/* 2827 */    MCD_OPC_CheckPredicate, 2, 132, 18, 0, // Skip to: 7572
/* 2832 */    MCD_OPC_Decode, 191, 3, 37, // Opcode: FNMULD
/* 2836 */    MCD_OPC_FilterValue, 97, 9, 0, 0, // Skip to: 2850
/* 2841 */    MCD_OPC_CheckPredicate, 2, 118, 18, 0, // Skip to: 7572
/* 2846 */    MCD_OPC_Decode, 144, 3, 37, // Opcode: FHADDS
/* 2850 */    MCD_OPC_FilterValue, 98, 9, 0, 0, // Skip to: 2864
/* 2855 */    MCD_OPC_CheckPredicate, 2, 104, 18, 0, // Skip to: 7572
/* 2860 */    MCD_OPC_Decode, 143, 3, 37, // Opcode: FHADDD
/* 2864 */    MCD_OPC_FilterValue, 101, 9, 0, 0, // Skip to: 2878
/* 2869 */    MCD_OPC_CheckPredicate, 2, 90, 18, 0, // Skip to: 7572
/* 2874 */    MCD_OPC_Decode, 146, 3, 37, // Opcode: FHSUBS
/* 2878 */    MCD_OPC_FilterValue, 102, 9, 0, 0, // Skip to: 2892
/* 2883 */    MCD_OPC_CheckPredicate, 2, 76, 18, 0, // Skip to: 7572
/* 2888 */    MCD_OPC_Decode, 145, 3, 37, // Opcode: FHSUBD
/* 2892 */    MCD_OPC_FilterValue, 105, 4, 0, 0, // Skip to: 2901
/* 2897 */    MCD_OPC_Decode, 229, 3, 39, // Opcode: FSMULD
/* 2901 */    MCD_OPC_FilterValue, 110, 4, 0, 0, // Skip to: 2910
/* 2906 */    MCD_OPC_Decode, 137, 3, 40, // Opcode: FDMULQ
/* 2910 */    MCD_OPC_FilterValue, 113, 9, 0, 0, // Skip to: 2924
/* 2915 */    MCD_OPC_CheckPredicate, 2, 44, 18, 0, // Skip to: 7572
/* 2920 */    MCD_OPC_Decode, 190, 3, 37, // Opcode: FNHADDS
/* 2924 */    MCD_OPC_FilterValue, 114, 9, 0, 0, // Skip to: 2938
/* 2929 */    MCD_OPC_CheckPredicate, 2, 30, 18, 0, // Skip to: 7572
/* 2934 */    MCD_OPC_Decode, 189, 3, 37, // Opcode: FNHADDD
/* 2938 */    MCD_OPC_FilterValue, 121, 9, 0, 0, // Skip to: 2952
/* 2943 */    MCD_OPC_CheckPredicate, 2, 16, 18, 0, // Skip to: 7572
/* 2948 */    MCD_OPC_Decode, 199, 3, 37, // Opcode: FNSMULD
/* 2952 */    MCD_OPC_FilterValue, 129, 1, 11, 0, 0, // Skip to: 2969
/* 2958 */    MCD_OPC_CheckField, 14, 5, 0, 255, 17, 0, // Skip to: 7572
/* 2965 */    MCD_OPC_Decode, 244, 3, 41, // Opcode: FSTOX
/* 2969 */    MCD_OPC_FilterValue, 130, 1, 11, 0, 0, // Skip to: 2986
/* 2975 */    MCD_OPC_CheckField, 14, 5, 0, 238, 17, 0, // Skip to: 7572
/* 2982 */    MCD_OPC_Decode, 141, 3, 34, // Opcode: FDTOX
/* 2986 */    MCD_OPC_FilterValue, 131, 1, 11, 0, 0, // Skip to: 3003
/* 2992 */    MCD_OPC_CheckField, 14, 5, 0, 221, 17, 0, // Skip to: 7572
/* 2999 */    MCD_OPC_Decode, 224, 3, 42, // Opcode: FQTOX
/* 3003 */    MCD_OPC_FilterValue, 132, 1, 11, 0, 0, // Skip to: 3020
/* 3009 */    MCD_OPC_CheckField, 14, 5, 0, 204, 17, 0, // Skip to: 7572
/* 3016 */    MCD_OPC_Decode, 254, 3, 43, // Opcode: FXTOS
/* 3020 */    MCD_OPC_FilterValue, 136, 1, 11, 0, 0, // Skip to: 3037
/* 3026 */    MCD_OPC_CheckField, 14, 5, 0, 187, 17, 0, // Skip to: 7572
/* 3033 */    MCD_OPC_Decode, 252, 3, 34, // Opcode: FXTOD
/* 3037 */    MCD_OPC_FilterValue, 140, 1, 11, 0, 0, // Skip to: 3054
/* 3043 */    MCD_OPC_CheckField, 14, 5, 0, 170, 17, 0, // Skip to: 7572
/* 3050 */    MCD_OPC_Decode, 253, 3, 44, // Opcode: FXTOQ
/* 3054 */    MCD_OPC_FilterValue, 196, 1, 11, 0, 0, // Skip to: 3071
/* 3060 */    MCD_OPC_CheckField, 14, 5, 0, 153, 17, 0, // Skip to: 7572
/* 3067 */    MCD_OPC_Decode, 149, 3, 33, // Opcode: FITOS
/* 3071 */    MCD_OPC_FilterValue, 198, 1, 11, 0, 0, // Skip to: 3088
/* 3077 */    MCD_OPC_CheckField, 14, 5, 0, 136, 17, 0, // Skip to: 7572
/* 3084 */    MCD_OPC_Decode, 140, 3, 43, // Opcode: FDTOS
/* 3088 */    MCD_OPC_FilterValue, 199, 1, 11, 0, 0, // Skip to: 3105
/* 3094 */    MCD_OPC_CheckField, 14, 5, 0, 119, 17, 0, // Skip to: 7572
/* 3101 */    MCD_OPC_Decode, 223, 3, 45, // Opcode: FQTOS
/* 3105 */    MCD_OPC_FilterValue, 200, 1, 11, 0, 0, // Skip to: 3122
/* 3111 */    MCD_OPC_CheckField, 14, 5, 0, 102, 17, 0, // Skip to: 7572
/* 3118 */    MCD_OPC_Decode, 147, 3, 41, // Opcode: FITOD
/* 3122 */    MCD_OPC_FilterValue, 201, 1, 11, 0, 0, // Skip to: 3139
/* 3128 */    MCD_OPC_CheckField, 14, 5, 0, 85, 17, 0, // Skip to: 7572
/* 3135 */    MCD_OPC_Decode, 241, 3, 41, // Opcode: FSTOD
/* 3139 */    MCD_OPC_FilterValue, 203, 1, 11, 0, 0, // Skip to: 3156
/* 3145 */    MCD_OPC_CheckField, 14, 5, 0, 68, 17, 0, // Skip to: 7572
/* 3152 */    MCD_OPC_Decode, 221, 3, 42, // Opcode: FQTOD
/* 3156 */    MCD_OPC_FilterValue, 204, 1, 11, 0, 0, // Skip to: 3173
/* 3162 */    MCD_OPC_CheckField, 14, 5, 0, 51, 17, 0, // Skip to: 7572
/* 3169 */    MCD_OPC_Decode, 148, 3, 46, // Opcode: FITOQ
/* 3173 */    MCD_OPC_FilterValue, 205, 1, 11, 0, 0, // Skip to: 3190
/* 3179 */    MCD_OPC_CheckField, 14, 5, 0, 34, 17, 0, // Skip to: 7572
/* 3186 */    MCD_OPC_Decode, 243, 3, 46, // Opcode: FSTOQ
/* 3190 */    MCD_OPC_FilterValue, 206, 1, 11, 0, 0, // Skip to: 3207
/* 3196 */    MCD_OPC_CheckField, 14, 5, 0, 17, 17, 0, // Skip to: 7572
/* 3203 */    MCD_OPC_Decode, 139, 3, 44, // Opcode: FDTOQ
/* 3207 */    MCD_OPC_FilterValue, 209, 1, 11, 0, 0, // Skip to: 3224
/* 3213 */    MCD_OPC_CheckField, 14, 5, 0, 0, 17, 0, // Skip to: 7572
/* 3220 */    MCD_OPC_Decode, 242, 3, 33, // Opcode: FSTOI
/* 3224 */    MCD_OPC_FilterValue, 210, 1, 11, 0, 0, // Skip to: 3241
/* 3230 */    MCD_OPC_CheckField, 14, 5, 0, 239, 16, 0, // Skip to: 7572
/* 3237 */    MCD_OPC_Decode, 138, 3, 43, // Opcode: FDTOI
/* 3241 */    MCD_OPC_FilterValue, 211, 1, 229, 16, 0, // Skip to: 7572
/* 3247 */    MCD_OPC_CheckField, 14, 5, 0, 222, 16, 0, // Skip to: 7572
/* 3254 */    MCD_OPC_Decode, 222, 3, 45, // Opcode: FQTOI
/* 3258 */    MCD_OPC_FilterValue, 53, 188, 1, 0, // Skip to: 3707
/* 3263 */    MCD_OPC_ExtractField, 5, 5,  // Inst{9-5} ...
/* 3266 */    MCD_OPC_FilterValue, 1, 94, 0, 0, // Skip to: 3365
/* 3271 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 3274 */    MCD_OPC_FilterValue, 0, 41, 0, 0, // Skip to: 3320
/* 3279 */    MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 3282 */    MCD_OPC_FilterValue, 0, 189, 16, 0, // Skip to: 7572
/* 3287 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 3290 */    MCD_OPC_FilterValue, 0, 181, 16, 0, // Skip to: 7572
/* 3295 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 3311
/* 3300 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 3311
/* 3307 */    MCD_OPC_Decode, 169, 3, 47, // Opcode: FMOVS_FCC
/* 3311 */    MCD_OPC_CheckPredicate, 0, 160, 16, 0, // Skip to: 7572
/* 3316 */    MCD_OPC_Decode, 247, 5, 48, // Opcode: V9FMOVS_FCC
/* 3320 */    MCD_OPC_FilterValue, 1, 151, 16, 0, // Skip to: 7572
/* 3325 */    MCD_OPC_ExtractField, 10, 3,  // Inst{12-10} ...
/* 3328 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 3349
/* 3333 */    MCD_OPC_CheckPredicate, 0, 138, 16, 0, // Skip to: 7572
/* 3338 */    MCD_OPC_CheckField, 18, 1, 0, 131, 16, 0, // Skip to: 7572
/* 3345 */    MCD_OPC_Decode, 170, 3, 47, // Opcode: FMOVS_ICC
/* 3349 */    MCD_OPC_FilterValue, 4, 122, 16, 0, // Skip to: 7572
/* 3354 */    MCD_OPC_CheckField, 18, 1, 0, 115, 16, 0, // Skip to: 7572
/* 3361 */    MCD_OPC_Decode, 171, 3, 47, // Opcode: FMOVS_XCC
/* 3365 */    MCD_OPC_FilterValue, 2, 94, 0, 0, // Skip to: 3464
/* 3370 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 3373 */    MCD_OPC_FilterValue, 0, 41, 0, 0, // Skip to: 3419
/* 3378 */    MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 3381 */    MCD_OPC_FilterValue, 0, 90, 16, 0, // Skip to: 7572
/* 3386 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 3389 */    MCD_OPC_FilterValue, 0, 82, 16, 0, // Skip to: 7572
/* 3394 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 3410
/* 3399 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 3410
/* 3406 */    MCD_OPC_Decode, 158, 3, 49, // Opcode: FMOVD_FCC
/* 3410 */    MCD_OPC_CheckPredicate, 0, 61, 16, 0, // Skip to: 7572
/* 3415 */    MCD_OPC_Decode, 245, 5, 50, // Opcode: V9FMOVD_FCC
/* 3419 */    MCD_OPC_FilterValue, 1, 52, 16, 0, // Skip to: 7572
/* 3424 */    MCD_OPC_ExtractField, 10, 3,  // Inst{12-10} ...
/* 3427 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 3448
/* 3432 */    MCD_OPC_CheckPredicate, 0, 39, 16, 0, // Skip to: 7572
/* 3437 */    MCD_OPC_CheckField, 18, 1, 0, 32, 16, 0, // Skip to: 7572
/* 3444 */    MCD_OPC_Decode, 159, 3, 49, // Opcode: FMOVD_ICC
/* 3448 */    MCD_OPC_FilterValue, 4, 23, 16, 0, // Skip to: 7572
/* 3453 */    MCD_OPC_CheckField, 18, 1, 0, 16, 16, 0, // Skip to: 7572
/* 3460 */    MCD_OPC_Decode, 160, 3, 49, // Opcode: FMOVD_XCC
/* 3464 */    MCD_OPC_FilterValue, 3, 94, 0, 0, // Skip to: 3563
/* 3469 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 3472 */    MCD_OPC_FilterValue, 0, 41, 0, 0, // Skip to: 3518
/* 3477 */    MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 3480 */    MCD_OPC_FilterValue, 0, 247, 15, 0, // Skip to: 7572
/* 3485 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 3488 */    MCD_OPC_FilterValue, 0, 239, 15, 0, // Skip to: 7572
/* 3493 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 3509
/* 3498 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 3509
/* 3505 */    MCD_OPC_Decode, 162, 3, 51, // Opcode: FMOVQ_FCC
/* 3509 */    MCD_OPC_CheckPredicate, 0, 218, 15, 0, // Skip to: 7572
/* 3514 */    MCD_OPC_Decode, 246, 5, 52, // Opcode: V9FMOVQ_FCC
/* 3518 */    MCD_OPC_FilterValue, 1, 209, 15, 0, // Skip to: 7572
/* 3523 */    MCD_OPC_ExtractField, 10, 3,  // Inst{12-10} ...
/* 3526 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 3547
/* 3531 */    MCD_OPC_CheckPredicate, 0, 196, 15, 0, // Skip to: 7572
/* 3536 */    MCD_OPC_CheckField, 18, 1, 0, 189, 15, 0, // Skip to: 7572
/* 3543 */    MCD_OPC_Decode, 163, 3, 51, // Opcode: FMOVQ_ICC
/* 3547 */    MCD_OPC_FilterValue, 4, 180, 15, 0, // Skip to: 7572
/* 3552 */    MCD_OPC_CheckField, 18, 1, 0, 173, 15, 0, // Skip to: 7572
/* 3559 */    MCD_OPC_Decode, 164, 3, 51, // Opcode: FMOVQ_XCC
/* 3563 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 3579
/* 3568 */    MCD_OPC_CheckField, 13, 1, 0, 157, 15, 0, // Skip to: 7572
/* 3575 */    MCD_OPC_Decode, 167, 3, 53, // Opcode: FMOVRS
/* 3579 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 3595
/* 3584 */    MCD_OPC_CheckField, 13, 1, 0, 141, 15, 0, // Skip to: 7572
/* 3591 */    MCD_OPC_Decode, 165, 3, 54, // Opcode: FMOVRD
/* 3595 */    MCD_OPC_FilterValue, 7, 11, 0, 0, // Skip to: 3611
/* 3600 */    MCD_OPC_CheckField, 13, 1, 0, 125, 15, 0, // Skip to: 7572
/* 3607 */    MCD_OPC_Decode, 166, 3, 55, // Opcode: FMOVRQ
/* 3611 */    MCD_OPC_FilterValue, 17, 11, 0, 0, // Skip to: 3627
/* 3616 */    MCD_OPC_CheckField, 10, 4, 2, 109, 15, 0, // Skip to: 7572
/* 3623 */    MCD_OPC_Decode, 244, 5, 56, // Opcode: V9FCMPS
/* 3627 */    MCD_OPC_FilterValue, 18, 11, 0, 0, // Skip to: 3643
/* 3632 */    MCD_OPC_CheckField, 10, 4, 2, 93, 15, 0, // Skip to: 7572
/* 3639 */    MCD_OPC_Decode, 239, 5, 57, // Opcode: V9FCMPD
/* 3643 */    MCD_OPC_FilterValue, 19, 11, 0, 0, // Skip to: 3659
/* 3648 */    MCD_OPC_CheckField, 10, 4, 2, 77, 15, 0, // Skip to: 7572
/* 3655 */    MCD_OPC_Decode, 243, 5, 58, // Opcode: V9FCMPQ
/* 3659 */    MCD_OPC_FilterValue, 21, 11, 0, 0, // Skip to: 3675
/* 3664 */    MCD_OPC_CheckField, 10, 4, 2, 61, 15, 0, // Skip to: 7572
/* 3671 */    MCD_OPC_Decode, 242, 5, 56, // Opcode: V9FCMPES
/* 3675 */    MCD_OPC_FilterValue, 22, 11, 0, 0, // Skip to: 3691
/* 3680 */    MCD_OPC_CheckField, 10, 4, 2, 45, 15, 0, // Skip to: 7572
/* 3687 */    MCD_OPC_Decode, 240, 5, 57, // Opcode: V9FCMPED
/* 3691 */    MCD_OPC_FilterValue, 23, 36, 15, 0, // Skip to: 7572
/* 3696 */    MCD_OPC_CheckField, 10, 4, 2, 29, 15, 0, // Skip to: 7572
/* 3703 */    MCD_OPC_Decode, 241, 5, 58, // Opcode: V9FCMPEQ
/* 3707 */    MCD_OPC_FilterValue, 54, 35, 7, 0, // Skip to: 5539
/* 3712 */    MCD_OPC_ExtractField, 5, 9,  // Inst{13-5} ...
/* 3715 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 3729
/* 3720 */    MCD_OPC_CheckPredicate, 3, 7, 15, 0, // Skip to: 7572
/* 3725 */    MCD_OPC_Decode, 226, 2, 10, // Opcode: EDGE8
/* 3729 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 3743
/* 3734 */    MCD_OPC_CheckPredicate, 4, 249, 14, 0, // Skip to: 7572
/* 3739 */    MCD_OPC_Decode, 229, 2, 10, // Opcode: EDGE8N
/* 3743 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 3757
/* 3748 */    MCD_OPC_CheckPredicate, 3, 235, 14, 0, // Skip to: 7572
/* 3753 */    MCD_OPC_Decode, 227, 2, 10, // Opcode: EDGE8L
/* 3757 */    MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 3771
/* 3762 */    MCD_OPC_CheckPredicate, 4, 221, 14, 0, // Skip to: 7572
/* 3767 */    MCD_OPC_Decode, 228, 2, 10, // Opcode: EDGE8LN
/* 3771 */    MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 3785
/* 3776 */    MCD_OPC_CheckPredicate, 3, 207, 14, 0, // Skip to: 7572
/* 3781 */    MCD_OPC_Decode, 218, 2, 10, // Opcode: EDGE16
/* 3785 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 3799
/* 3790 */    MCD_OPC_CheckPredicate, 4, 193, 14, 0, // Skip to: 7572
/* 3795 */    MCD_OPC_Decode, 221, 2, 10, // Opcode: EDGE16N
/* 3799 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 3813
/* 3804 */    MCD_OPC_CheckPredicate, 3, 179, 14, 0, // Skip to: 7572
/* 3809 */    MCD_OPC_Decode, 219, 2, 10, // Opcode: EDGE16L
/* 3813 */    MCD_OPC_FilterValue, 7, 9, 0, 0, // Skip to: 3827
/* 3818 */    MCD_OPC_CheckPredicate, 4, 165, 14, 0, // Skip to: 7572
/* 3823 */    MCD_OPC_Decode, 220, 2, 10, // Opcode: EDGE16LN
/* 3827 */    MCD_OPC_FilterValue, 8, 9, 0, 0, // Skip to: 3841
/* 3832 */    MCD_OPC_CheckPredicate, 3, 151, 14, 0, // Skip to: 7572
/* 3837 */    MCD_OPC_Decode, 222, 2, 10, // Opcode: EDGE32
/* 3841 */    MCD_OPC_FilterValue, 9, 9, 0, 0, // Skip to: 3855
/* 3846 */    MCD_OPC_CheckPredicate, 4, 137, 14, 0, // Skip to: 7572
/* 3851 */    MCD_OPC_Decode, 225, 2, 10, // Opcode: EDGE32N
/* 3855 */    MCD_OPC_FilterValue, 10, 9, 0, 0, // Skip to: 3869
/* 3860 */    MCD_OPC_CheckPredicate, 3, 123, 14, 0, // Skip to: 7572
/* 3865 */    MCD_OPC_Decode, 223, 2, 10, // Opcode: EDGE32L
/* 3869 */    MCD_OPC_FilterValue, 11, 9, 0, 0, // Skip to: 3883
/* 3874 */    MCD_OPC_CheckPredicate, 4, 109, 14, 0, // Skip to: 7572
/* 3879 */    MCD_OPC_Decode, 224, 2, 10, // Opcode: EDGE32LN
/* 3883 */    MCD_OPC_FilterValue, 16, 9, 0, 0, // Skip to: 3897
/* 3888 */    MCD_OPC_CheckPredicate, 3, 95, 14, 0, // Skip to: 7572
/* 3893 */    MCD_OPC_Decode, 182, 2, 10, // Opcode: ARRAY8
/* 3897 */    MCD_OPC_FilterValue, 17, 9, 0, 0, // Skip to: 3911
/* 3902 */    MCD_OPC_CheckPredicate, 2, 81, 14, 0, // Skip to: 7572
/* 3907 */    MCD_OPC_Decode, 166, 2, 10, // Opcode: ADDXC
/* 3911 */    MCD_OPC_FilterValue, 18, 9, 0, 0, // Skip to: 3925
/* 3916 */    MCD_OPC_CheckPredicate, 3, 67, 14, 0, // Skip to: 7572
/* 3921 */    MCD_OPC_Decode, 180, 2, 10, // Opcode: ARRAY16
/* 3925 */    MCD_OPC_FilterValue, 19, 9, 0, 0, // Skip to: 3939
/* 3930 */    MCD_OPC_CheckPredicate, 2, 53, 14, 0, // Skip to: 7572
/* 3935 */    MCD_OPC_Decode, 167, 2, 10, // Opcode: ADDXCCC
/* 3939 */    MCD_OPC_FilterValue, 20, 9, 0, 0, // Skip to: 3953
/* 3944 */    MCD_OPC_CheckPredicate, 3, 39, 14, 0, // Skip to: 7572
/* 3949 */    MCD_OPC_Decode, 181, 2, 10, // Opcode: ARRAY32
/* 3953 */    MCD_OPC_FilterValue, 22, 9, 0, 0, // Skip to: 3967
/* 3958 */    MCD_OPC_CheckPredicate, 2, 25, 14, 0, // Skip to: 7572
/* 3963 */    MCD_OPC_Decode, 235, 5, 10, // Opcode: UMULXHI
/* 3967 */    MCD_OPC_FilterValue, 23, 16, 0, 0, // Skip to: 3988
/* 3972 */    MCD_OPC_CheckPredicate, 2, 11, 14, 0, // Skip to: 7572
/* 3977 */    MCD_OPC_CheckField, 14, 5, 0, 4, 14, 0, // Skip to: 7572
/* 3984 */    MCD_OPC_Decode, 191, 4, 59, // Opcode: LZCNT
/* 3988 */    MCD_OPC_FilterValue, 24, 9, 0, 0, // Skip to: 4002
/* 3993 */    MCD_OPC_CheckPredicate, 3, 246, 13, 0, // Skip to: 7572
/* 3998 */    MCD_OPC_Decode, 170, 2, 10, // Opcode: ALIGNADDR
/* 4002 */    MCD_OPC_FilterValue, 25, 9, 0, 0, // Skip to: 4016
/* 4007 */    MCD_OPC_CheckPredicate, 4, 232, 13, 0, // Skip to: 7572
/* 4012 */    MCD_OPC_Decode, 187, 2, 10, // Opcode: BMASK
/* 4016 */    MCD_OPC_FilterValue, 26, 9, 0, 0, // Skip to: 4030
/* 4021 */    MCD_OPC_CheckPredicate, 3, 218, 13, 0, // Skip to: 7572
/* 4026 */    MCD_OPC_Decode, 171, 2, 10, // Opcode: ALIGNADDRL
/* 4030 */    MCD_OPC_FilterValue, 27, 23, 0, 0, // Skip to: 4058
/* 4035 */    MCD_OPC_CheckPredicate, 2, 204, 13, 0, // Skip to: 7572
/* 4040 */    MCD_OPC_CheckField, 25, 5, 0, 197, 13, 0, // Skip to: 7572
/* 4047 */    MCD_OPC_CheckField, 14, 5, 0, 190, 13, 0, // Skip to: 7572
/* 4054 */    MCD_OPC_Decode, 216, 2, 60, // Opcode: CMASK8
/* 4058 */    MCD_OPC_FilterValue, 28, 9, 0, 0, // Skip to: 4072
/* 4063 */    MCD_OPC_CheckPredicate, 4, 176, 13, 0, // Skip to: 7572
/* 4068 */    MCD_OPC_Decode, 204, 2, 37, // Opcode: BSHUFFLE
/* 4072 */    MCD_OPC_FilterValue, 29, 23, 0, 0, // Skip to: 4100
/* 4077 */    MCD_OPC_CheckPredicate, 2, 162, 13, 0, // Skip to: 7572
/* 4082 */    MCD_OPC_CheckField, 25, 5, 0, 155, 13, 0, // Skip to: 7572
/* 4089 */    MCD_OPC_CheckField, 14, 5, 0, 148, 13, 0, // Skip to: 7572
/* 4096 */    MCD_OPC_Decode, 214, 2, 60, // Opcode: CMASK16
/* 4100 */    MCD_OPC_FilterValue, 31, 23, 0, 0, // Skip to: 4128
/* 4105 */    MCD_OPC_CheckPredicate, 2, 134, 13, 0, // Skip to: 7572
/* 4110 */    MCD_OPC_CheckField, 25, 5, 0, 127, 13, 0, // Skip to: 7572
/* 4117 */    MCD_OPC_CheckField, 14, 5, 0, 120, 13, 0, // Skip to: 7572
/* 4124 */    MCD_OPC_Decode, 215, 2, 60, // Opcode: CMASK32
/* 4128 */    MCD_OPC_FilterValue, 32, 9, 0, 0, // Skip to: 4142
/* 4133 */    MCD_OPC_CheckPredicate, 3, 106, 13, 0, // Skip to: 7572
/* 4138 */    MCD_OPC_Decode, 254, 2, 61, // Opcode: FCMPLE16
/* 4142 */    MCD_OPC_FilterValue, 33, 9, 0, 0, // Skip to: 4156
/* 4147 */    MCD_OPC_CheckPredicate, 2, 92, 13, 0, // Skip to: 7572
/* 4152 */    MCD_OPC_Decode, 227, 3, 37, // Opcode: FSLL16
/* 4156 */    MCD_OPC_FilterValue, 34, 9, 0, 0, // Skip to: 4170
/* 4161 */    MCD_OPC_CheckPredicate, 3, 78, 13, 0, // Skip to: 7572
/* 4166 */    MCD_OPC_Decode, 128, 3, 61, // Opcode: FCMPNE16
/* 4170 */    MCD_OPC_FilterValue, 35, 9, 0, 0, // Skip to: 4184
/* 4175 */    MCD_OPC_CheckPredicate, 2, 64, 13, 0, // Skip to: 7572
/* 4180 */    MCD_OPC_Decode, 239, 3, 37, // Opcode: FSRL16
/* 4184 */    MCD_OPC_FilterValue, 36, 9, 0, 0, // Skip to: 4198
/* 4189 */    MCD_OPC_CheckPredicate, 3, 50, 13, 0, // Skip to: 7572
/* 4194 */    MCD_OPC_Decode, 255, 2, 61, // Opcode: FCMPLE32
/* 4198 */    MCD_OPC_FilterValue, 37, 9, 0, 0, // Skip to: 4212
/* 4203 */    MCD_OPC_CheckPredicate, 2, 36, 13, 0, // Skip to: 7572
/* 4208 */    MCD_OPC_Decode, 228, 3, 37, // Opcode: FSLL32
/* 4212 */    MCD_OPC_FilterValue, 38, 9, 0, 0, // Skip to: 4226
/* 4217 */    MCD_OPC_CheckPredicate, 3, 22, 13, 0, // Skip to: 7572
/* 4222 */    MCD_OPC_Decode, 129, 3, 61, // Opcode: FCMPNE32
/* 4226 */    MCD_OPC_FilterValue, 39, 9, 0, 0, // Skip to: 4240
/* 4231 */    MCD_OPC_CheckPredicate, 2, 8, 13, 0, // Skip to: 7572
/* 4236 */    MCD_OPC_Decode, 240, 3, 37, // Opcode: FSRL32
/* 4240 */    MCD_OPC_FilterValue, 40, 9, 0, 0, // Skip to: 4254
/* 4245 */    MCD_OPC_CheckPredicate, 3, 250, 12, 0, // Skip to: 7572
/* 4250 */    MCD_OPC_Decode, 252, 2, 61, // Opcode: FCMPGT16
/* 4254 */    MCD_OPC_FilterValue, 41, 9, 0, 0, // Skip to: 4268
/* 4259 */    MCD_OPC_CheckPredicate, 2, 236, 12, 0, // Skip to: 7572
/* 4264 */    MCD_OPC_Decode, 225, 3, 37, // Opcode: FSLAS16
/* 4268 */    MCD_OPC_FilterValue, 42, 9, 0, 0, // Skip to: 4282
/* 4273 */    MCD_OPC_CheckPredicate, 3, 222, 12, 0, // Skip to: 7572
/* 4278 */    MCD_OPC_Decode, 250, 2, 61, // Opcode: FCMPEQ16
/* 4282 */    MCD_OPC_FilterValue, 43, 9, 0, 0, // Skip to: 4296
/* 4287 */    MCD_OPC_CheckPredicate, 2, 208, 12, 0, // Skip to: 7572
/* 4292 */    MCD_OPC_Decode, 233, 3, 37, // Opcode: FSRA16
/* 4296 */    MCD_OPC_FilterValue, 44, 9, 0, 0, // Skip to: 4310
/* 4301 */    MCD_OPC_CheckPredicate, 3, 194, 12, 0, // Skip to: 7572
/* 4306 */    MCD_OPC_Decode, 253, 2, 61, // Opcode: FCMPGT32
/* 4310 */    MCD_OPC_FilterValue, 45, 9, 0, 0, // Skip to: 4324
/* 4315 */    MCD_OPC_CheckPredicate, 2, 180, 12, 0, // Skip to: 7572
/* 4320 */    MCD_OPC_Decode, 226, 3, 37, // Opcode: FSLAS32
/* 4324 */    MCD_OPC_FilterValue, 46, 9, 0, 0, // Skip to: 4338
/* 4329 */    MCD_OPC_CheckPredicate, 3, 166, 12, 0, // Skip to: 7572
/* 4334 */    MCD_OPC_Decode, 251, 2, 61, // Opcode: FCMPEQ32
/* 4338 */    MCD_OPC_FilterValue, 47, 9, 0, 0, // Skip to: 4352
/* 4343 */    MCD_OPC_CheckPredicate, 2, 152, 12, 0, // Skip to: 7572
/* 4348 */    MCD_OPC_Decode, 234, 3, 37, // Opcode: FSRA32
/* 4352 */    MCD_OPC_FilterValue, 49, 9, 0, 0, // Skip to: 4366
/* 4357 */    MCD_OPC_CheckPredicate, 3, 138, 12, 0, // Skip to: 7572
/* 4362 */    MCD_OPC_Decode, 174, 3, 37, // Opcode: FMUL8X16
/* 4366 */    MCD_OPC_FilterValue, 51, 9, 0, 0, // Skip to: 4380
/* 4371 */    MCD_OPC_CheckPredicate, 3, 124, 12, 0, // Skip to: 7572
/* 4376 */    MCD_OPC_Decode, 176, 3, 37, // Opcode: FMUL8X16AU
/* 4380 */    MCD_OPC_FilterValue, 53, 9, 0, 0, // Skip to: 4394
/* 4385 */    MCD_OPC_CheckPredicate, 3, 110, 12, 0, // Skip to: 7572
/* 4390 */    MCD_OPC_Decode, 175, 3, 37, // Opcode: FMUL8X16AL
/* 4394 */    MCD_OPC_FilterValue, 54, 9, 0, 0, // Skip to: 4408
/* 4399 */    MCD_OPC_CheckPredicate, 3, 96, 12, 0, // Skip to: 7572
/* 4404 */    MCD_OPC_Decode, 172, 3, 37, // Opcode: FMUL8SUX16
/* 4408 */    MCD_OPC_FilterValue, 55, 9, 0, 0, // Skip to: 4422
/* 4413 */    MCD_OPC_CheckPredicate, 3, 82, 12, 0, // Skip to: 7572
/* 4418 */    MCD_OPC_Decode, 173, 3, 37, // Opcode: FMUL8ULX16
/* 4422 */    MCD_OPC_FilterValue, 56, 9, 0, 0, // Skip to: 4436
/* 4427 */    MCD_OPC_CheckPredicate, 3, 68, 12, 0, // Skip to: 7572
/* 4432 */    MCD_OPC_Decode, 178, 3, 37, // Opcode: FMULD8SUX16
/* 4436 */    MCD_OPC_FilterValue, 57, 9, 0, 0, // Skip to: 4450
/* 4441 */    MCD_OPC_CheckPredicate, 3, 54, 12, 0, // Skip to: 7572
/* 4446 */    MCD_OPC_Decode, 179, 3, 37, // Opcode: FMULD8ULX16
/* 4450 */    MCD_OPC_FilterValue, 58, 9, 0, 0, // Skip to: 4464
/* 4455 */    MCD_OPC_CheckPredicate, 3, 40, 12, 0, // Skip to: 7572
/* 4460 */    MCD_OPC_Decode, 209, 3, 37, // Opcode: FPACK32
/* 4464 */    MCD_OPC_FilterValue, 59, 16, 0, 0, // Skip to: 4485
/* 4469 */    MCD_OPC_CheckPredicate, 3, 26, 12, 0, // Skip to: 7572
/* 4474 */    MCD_OPC_CheckField, 14, 5, 0, 19, 12, 0, // Skip to: 7572
/* 4481 */    MCD_OPC_Decode, 208, 3, 34, // Opcode: FPACK16
/* 4485 */    MCD_OPC_FilterValue, 61, 16, 0, 0, // Skip to: 4506
/* 4490 */    MCD_OPC_CheckPredicate, 3, 5, 12, 0, // Skip to: 7572
/* 4495 */    MCD_OPC_CheckField, 14, 5, 0, 254, 11, 0, // Skip to: 7572
/* 4502 */    MCD_OPC_Decode, 210, 3, 34, // Opcode: FPACKFIX
/* 4506 */    MCD_OPC_FilterValue, 62, 9, 0, 0, // Skip to: 4520
/* 4511 */    MCD_OPC_CheckPredicate, 3, 240, 11, 0, // Skip to: 7572
/* 4516 */    MCD_OPC_Decode, 219, 4, 37, // Opcode: PDIST
/* 4520 */    MCD_OPC_FilterValue, 63, 9, 0, 0, // Skip to: 4534
/* 4525 */    MCD_OPC_CheckPredicate, 2, 226, 11, 0, // Skip to: 7572
/* 4530 */    MCD_OPC_Decode, 220, 4, 37, // Opcode: PDISTN
/* 4534 */    MCD_OPC_FilterValue, 64, 9, 0, 0, // Skip to: 4548
/* 4539 */    MCD_OPC_CheckPredicate, 2, 212, 11, 0, // Skip to: 7572
/* 4544 */    MCD_OPC_Decode, 156, 3, 37, // Opcode: FMEAN16
/* 4548 */    MCD_OPC_FilterValue, 66, 9, 0, 0, // Skip to: 4562
/* 4553 */    MCD_OPC_CheckPredicate, 2, 198, 11, 0, // Skip to: 7572
/* 4558 */    MCD_OPC_Decode, 215, 3, 37, // Opcode: FPADD64
/* 4562 */    MCD_OPC_FilterValue, 68, 9, 0, 0, // Skip to: 4576
/* 4567 */    MCD_OPC_CheckPredicate, 2, 184, 11, 0, // Skip to: 7572
/* 4572 */    MCD_OPC_Decode, 247, 2, 37, // Opcode: FCHKSM16
/* 4576 */    MCD_OPC_FilterValue, 72, 9, 0, 0, // Skip to: 4590
/* 4581 */    MCD_OPC_CheckPredicate, 3, 170, 11, 0, // Skip to: 7572
/* 4586 */    MCD_OPC_Decode, 236, 2, 37, // Opcode: FALIGNADATA
/* 4590 */    MCD_OPC_FilterValue, 75, 9, 0, 0, // Skip to: 4604
/* 4595 */    MCD_OPC_CheckPredicate, 3, 156, 11, 0, // Skip to: 7572
/* 4600 */    MCD_OPC_Decode, 216, 3, 37, // Opcode: FPMERGE
/* 4604 */    MCD_OPC_FilterValue, 77, 16, 0, 0, // Skip to: 4625
/* 4609 */    MCD_OPC_CheckPredicate, 3, 142, 11, 0, // Skip to: 7572
/* 4614 */    MCD_OPC_CheckField, 14, 5, 0, 135, 11, 0, // Skip to: 7572
/* 4621 */    MCD_OPC_Decode, 142, 3, 34, // Opcode: FEXPAND
/* 4625 */    MCD_OPC_FilterValue, 80, 9, 0, 0, // Skip to: 4639
/* 4630 */    MCD_OPC_CheckPredicate, 3, 121, 11, 0, // Skip to: 7572
/* 4635 */    MCD_OPC_Decode, 211, 3, 37, // Opcode: FPADD16
/* 4639 */    MCD_OPC_FilterValue, 81, 9, 0, 0, // Skip to: 4653
/* 4644 */    MCD_OPC_CheckPredicate, 3, 107, 11, 0, // Skip to: 7572
/* 4649 */    MCD_OPC_Decode, 212, 3, 37, // Opcode: FPADD16S
/* 4653 */    MCD_OPC_FilterValue, 82, 9, 0, 0, // Skip to: 4667
/* 4658 */    MCD_OPC_CheckPredicate, 3, 93, 11, 0, // Skip to: 7572
/* 4663 */    MCD_OPC_Decode, 213, 3, 37, // Opcode: FPADD32
/* 4667 */    MCD_OPC_FilterValue, 83, 9, 0, 0, // Skip to: 4681
/* 4672 */    MCD_OPC_CheckPredicate, 3, 79, 11, 0, // Skip to: 7572
/* 4677 */    MCD_OPC_Decode, 214, 3, 37, // Opcode: FPADD32S
/* 4681 */    MCD_OPC_FilterValue, 84, 9, 0, 0, // Skip to: 4695
/* 4686 */    MCD_OPC_CheckPredicate, 3, 65, 11, 0, // Skip to: 7572
/* 4691 */    MCD_OPC_Decode, 217, 3, 37, // Opcode: FPSUB16
/* 4695 */    MCD_OPC_FilterValue, 85, 9, 0, 0, // Skip to: 4709
/* 4700 */    MCD_OPC_CheckPredicate, 3, 51, 11, 0, // Skip to: 7572
/* 4705 */    MCD_OPC_Decode, 218, 3, 37, // Opcode: FPSUB16S
/* 4709 */    MCD_OPC_FilterValue, 86, 9, 0, 0, // Skip to: 4723
/* 4714 */    MCD_OPC_CheckPredicate, 3, 37, 11, 0, // Skip to: 7572
/* 4719 */    MCD_OPC_Decode, 219, 3, 37, // Opcode: FPSUB32
/* 4723 */    MCD_OPC_FilterValue, 87, 9, 0, 0, // Skip to: 4737
/* 4728 */    MCD_OPC_CheckPredicate, 3, 23, 11, 0, // Skip to: 7572
/* 4733 */    MCD_OPC_Decode, 220, 3, 37, // Opcode: FPSUB32S
/* 4737 */    MCD_OPC_FilterValue, 96, 23, 0, 0, // Skip to: 4765
/* 4742 */    MCD_OPC_CheckPredicate, 3, 9, 11, 0, // Skip to: 7572
/* 4747 */    MCD_OPC_CheckField, 14, 5, 0, 2, 11, 0, // Skip to: 7572
/* 4754 */    MCD_OPC_CheckField, 0, 5, 0, 251, 10, 0, // Skip to: 7572
/* 4761 */    MCD_OPC_Decode, 255, 3, 62, // Opcode: FZERO
/* 4765 */    MCD_OPC_FilterValue, 97, 23, 0, 0, // Skip to: 4793
/* 4770 */    MCD_OPC_CheckPredicate, 3, 237, 10, 0, // Skip to: 7572
/* 4775 */    MCD_OPC_CheckField, 14, 5, 0, 230, 10, 0, // Skip to: 7572
/* 4782 */    MCD_OPC_CheckField, 0, 5, 0, 223, 10, 0, // Skip to: 7572
/* 4789 */    MCD_OPC_Decode, 128, 4, 63, // Opcode: FZEROS
/* 4793 */    MCD_OPC_FilterValue, 98, 9, 0, 0, // Skip to: 4807
/* 4798 */    MCD_OPC_CheckPredicate, 3, 209, 10, 0, // Skip to: 7572
/* 4803 */    MCD_OPC_Decode, 193, 3, 37, // Opcode: FNOR
/* 4807 */    MCD_OPC_FilterValue, 99, 9, 0, 0, // Skip to: 4821
/* 4812 */    MCD_OPC_CheckPredicate, 3, 195, 10, 0, // Skip to: 7572
/* 4817 */    MCD_OPC_Decode, 194, 3, 36, // Opcode: FNORS
/* 4821 */    MCD_OPC_FilterValue, 100, 9, 0, 0, // Skip to: 4835
/* 4826 */    MCD_OPC_CheckPredicate, 3, 181, 10, 0, // Skip to: 7572
/* 4831 */    MCD_OPC_Decode, 240, 2, 37, // Opcode: FANDNOT2
/* 4835 */    MCD_OPC_FilterValue, 101, 9, 0, 0, // Skip to: 4849
/* 4840 */    MCD_OPC_CheckPredicate, 3, 167, 10, 0, // Skip to: 7572
/* 4845 */    MCD_OPC_Decode, 241, 2, 36, // Opcode: FANDNOT2S
/* 4849 */    MCD_OPC_FilterValue, 102, 16, 0, 0, // Skip to: 4870
/* 4854 */    MCD_OPC_CheckPredicate, 3, 153, 10, 0, // Skip to: 7572
/* 4859 */    MCD_OPC_CheckField, 14, 5, 0, 146, 10, 0, // Skip to: 7572
/* 4866 */    MCD_OPC_Decode, 197, 3, 34, // Opcode: FNOT2
/* 4870 */    MCD_OPC_FilterValue, 103, 16, 0, 0, // Skip to: 4891
/* 4875 */    MCD_OPC_CheckPredicate, 3, 132, 10, 0, // Skip to: 7572
/* 4880 */    MCD_OPC_CheckField, 14, 5, 0, 125, 10, 0, // Skip to: 7572
/* 4887 */    MCD_OPC_Decode, 198, 3, 33, // Opcode: FNOT2S
/* 4891 */    MCD_OPC_FilterValue, 104, 9, 0, 0, // Skip to: 4905
/* 4896 */    MCD_OPC_CheckPredicate, 3, 111, 10, 0, // Skip to: 7572
/* 4901 */    MCD_OPC_Decode, 238, 2, 37, // Opcode: FANDNOT1
/* 4905 */    MCD_OPC_FilterValue, 105, 9, 0, 0, // Skip to: 4919
/* 4910 */    MCD_OPC_CheckPredicate, 3, 97, 10, 0, // Skip to: 7572
/* 4915 */    MCD_OPC_Decode, 239, 2, 36, // Opcode: FANDNOT1S
/* 4919 */    MCD_OPC_FilterValue, 106, 16, 0, 0, // Skip to: 4940
/* 4924 */    MCD_OPC_CheckPredicate, 3, 83, 10, 0, // Skip to: 7572
/* 4929 */    MCD_OPC_CheckField, 0, 5, 0, 76, 10, 0, // Skip to: 7572
/* 4936 */    MCD_OPC_Decode, 195, 3, 64, // Opcode: FNOT1
/* 4940 */    MCD_OPC_FilterValue, 107, 16, 0, 0, // Skip to: 4961
/* 4945 */    MCD_OPC_CheckPredicate, 3, 62, 10, 0, // Skip to: 7572
/* 4950 */    MCD_OPC_CheckField, 0, 5, 0, 55, 10, 0, // Skip to: 7572
/* 4957 */    MCD_OPC_Decode, 196, 3, 65, // Opcode: FNOT1S
/* 4961 */    MCD_OPC_FilterValue, 108, 9, 0, 0, // Skip to: 4975
/* 4966 */    MCD_OPC_CheckPredicate, 3, 41, 10, 0, // Skip to: 7572
/* 4971 */    MCD_OPC_Decode, 250, 3, 37, // Opcode: FXOR
/* 4975 */    MCD_OPC_FilterValue, 109, 9, 0, 0, // Skip to: 4989
/* 4980 */    MCD_OPC_CheckPredicate, 3, 27, 10, 0, // Skip to: 7572
/* 4985 */    MCD_OPC_Decode, 251, 3, 36, // Opcode: FXORS
/* 4989 */    MCD_OPC_FilterValue, 110, 9, 0, 0, // Skip to: 5003
/* 4994 */    MCD_OPC_CheckPredicate, 3, 13, 10, 0, // Skip to: 7572
/* 4999 */    MCD_OPC_Decode, 184, 3, 37, // Opcode: FNAND
/* 5003 */    MCD_OPC_FilterValue, 111, 9, 0, 0, // Skip to: 5017
/* 5008 */    MCD_OPC_CheckPredicate, 3, 255, 9, 0, // Skip to: 7572
/* 5013 */    MCD_OPC_Decode, 185, 3, 36, // Opcode: FNANDS
/* 5017 */    MCD_OPC_FilterValue, 112, 9, 0, 0, // Skip to: 5031
/* 5022 */    MCD_OPC_CheckPredicate, 3, 241, 9, 0, // Skip to: 7572
/* 5027 */    MCD_OPC_Decode, 237, 2, 37, // Opcode: FAND
/* 5031 */    MCD_OPC_FilterValue, 113, 9, 0, 0, // Skip to: 5045
/* 5036 */    MCD_OPC_CheckPredicate, 3, 227, 9, 0, // Skip to: 7572
/* 5041 */    MCD_OPC_Decode, 242, 2, 36, // Opcode: FANDS
/* 5045 */    MCD_OPC_FilterValue, 114, 9, 0, 0, // Skip to: 5059
/* 5050 */    MCD_OPC_CheckPredicate, 3, 213, 9, 0, // Skip to: 7572
/* 5055 */    MCD_OPC_Decode, 248, 3, 37, // Opcode: FXNOR
/* 5059 */    MCD_OPC_FilterValue, 115, 9, 0, 0, // Skip to: 5073
/* 5064 */    MCD_OPC_CheckPredicate, 3, 199, 9, 0, // Skip to: 7572
/* 5069 */    MCD_OPC_Decode, 249, 3, 36, // Opcode: FXNORS
/* 5073 */    MCD_OPC_FilterValue, 116, 16, 0, 0, // Skip to: 5094
/* 5078 */    MCD_OPC_CheckPredicate, 3, 185, 9, 0, // Skip to: 7572
/* 5083 */    MCD_OPC_CheckField, 0, 5, 0, 178, 9, 0, // Skip to: 7572
/* 5090 */    MCD_OPC_Decode, 235, 3, 64, // Opcode: FSRC1
/* 5094 */    MCD_OPC_FilterValue, 117, 16, 0, 0, // Skip to: 5115
/* 5099 */    MCD_OPC_CheckPredicate, 3, 164, 9, 0, // Skip to: 7572
/* 5104 */    MCD_OPC_CheckField, 0, 5, 0, 157, 9, 0, // Skip to: 7572
/* 5111 */    MCD_OPC_Decode, 236, 3, 65, // Opcode: FSRC1S
/* 5115 */    MCD_OPC_FilterValue, 118, 9, 0, 0, // Skip to: 5129
/* 5120 */    MCD_OPC_CheckPredicate, 3, 143, 9, 0, // Skip to: 7572
/* 5125 */    MCD_OPC_Decode, 205, 3, 37, // Opcode: FORNOT2
/* 5129 */    MCD_OPC_FilterValue, 119, 9, 0, 0, // Skip to: 5143
/* 5134 */    MCD_OPC_CheckPredicate, 3, 129, 9, 0, // Skip to: 7572
/* 5139 */    MCD_OPC_Decode, 206, 3, 36, // Opcode: FORNOT2S
/* 5143 */    MCD_OPC_FilterValue, 120, 16, 0, 0, // Skip to: 5164
/* 5148 */    MCD_OPC_CheckPredicate, 3, 115, 9, 0, // Skip to: 7572
/* 5153 */    MCD_OPC_CheckField, 14, 5, 0, 108, 9, 0, // Skip to: 7572
/* 5160 */    MCD_OPC_Decode, 237, 3, 34, // Opcode: FSRC2
/* 5164 */    MCD_OPC_FilterValue, 121, 16, 0, 0, // Skip to: 5185
/* 5169 */    MCD_OPC_CheckPredicate, 3, 94, 9, 0, // Skip to: 7572
/* 5174 */    MCD_OPC_CheckField, 14, 5, 0, 87, 9, 0, // Skip to: 7572
/* 5181 */    MCD_OPC_Decode, 238, 3, 33, // Opcode: FSRC2S
/* 5185 */    MCD_OPC_FilterValue, 122, 9, 0, 0, // Skip to: 5199
/* 5190 */    MCD_OPC_CheckPredicate, 3, 73, 9, 0, // Skip to: 7572
/* 5195 */    MCD_OPC_Decode, 203, 3, 37, // Opcode: FORNOT1
/* 5199 */    MCD_OPC_FilterValue, 123, 9, 0, 0, // Skip to: 5213
/* 5204 */    MCD_OPC_CheckPredicate, 3, 59, 9, 0, // Skip to: 7572
/* 5209 */    MCD_OPC_Decode, 204, 3, 36, // Opcode: FORNOT1S
/* 5213 */    MCD_OPC_FilterValue, 124, 9, 0, 0, // Skip to: 5227
/* 5218 */    MCD_OPC_CheckPredicate, 3, 45, 9, 0, // Skip to: 7572
/* 5223 */    MCD_OPC_Decode, 202, 3, 37, // Opcode: FOR
/* 5227 */    MCD_OPC_FilterValue, 125, 9, 0, 0, // Skip to: 5241
/* 5232 */    MCD_OPC_CheckPredicate, 3, 31, 9, 0, // Skip to: 7572
/* 5237 */    MCD_OPC_Decode, 207, 3, 36, // Opcode: FORS
/* 5241 */    MCD_OPC_FilterValue, 126, 23, 0, 0, // Skip to: 5269
/* 5246 */    MCD_OPC_CheckPredicate, 3, 17, 9, 0, // Skip to: 7572
/* 5251 */    MCD_OPC_CheckField, 14, 5, 0, 10, 9, 0, // Skip to: 7572
/* 5258 */    MCD_OPC_CheckField, 0, 5, 0, 3, 9, 0, // Skip to: 7572
/* 5265 */    MCD_OPC_Decode, 200, 3, 62, // Opcode: FONE
/* 5269 */    MCD_OPC_FilterValue, 127, 23, 0, 0, // Skip to: 5297
/* 5274 */    MCD_OPC_CheckPredicate, 3, 245, 8, 0, // Skip to: 7572
/* 5279 */    MCD_OPC_CheckField, 14, 5, 0, 238, 8, 0, // Skip to: 7572
/* 5286 */    MCD_OPC_CheckField, 0, 5, 0, 231, 8, 0, // Skip to: 7572
/* 5293 */    MCD_OPC_Decode, 201, 3, 63, // Opcode: FONES
/* 5297 */    MCD_OPC_FilterValue, 128, 1, 30, 0, 0, // Skip to: 5333
/* 5303 */    MCD_OPC_CheckPredicate, 3, 216, 8, 0, // Skip to: 7572
/* 5308 */    MCD_OPC_CheckField, 25, 5, 0, 209, 8, 0, // Skip to: 7572
/* 5315 */    MCD_OPC_CheckField, 14, 5, 0, 202, 8, 0, // Skip to: 7572
/* 5322 */    MCD_OPC_CheckField, 0, 5, 0, 195, 8, 0, // Skip to: 7572
/* 5329 */    MCD_OPC_Decode, 250, 4, 4, // Opcode: SHUTDOWN
/* 5333 */    MCD_OPC_FilterValue, 129, 1, 30, 0, 0, // Skip to: 5369
/* 5339 */    MCD_OPC_CheckPredicate, 4, 180, 8, 0, // Skip to: 7572
/* 5344 */    MCD_OPC_CheckField, 25, 5, 0, 173, 8, 0, // Skip to: 7572
/* 5351 */    MCD_OPC_CheckField, 14, 5, 0, 166, 8, 0, // Skip to: 7572
/* 5358 */    MCD_OPC_CheckField, 0, 5, 0, 159, 8, 0, // Skip to: 7572
/* 5365 */    MCD_OPC_Decode, 251, 4, 4, // Opcode: SIAM
/* 5369 */    MCD_OPC_FilterValue, 144, 2, 16, 0, 0, // Skip to: 5391
/* 5375 */    MCD_OPC_CheckPredicate, 2, 144, 8, 0, // Skip to: 7572
/* 5380 */    MCD_OPC_CheckField, 14, 5, 0, 137, 8, 0, // Skip to: 7572
/* 5387 */    MCD_OPC_Decode, 193, 4, 66, // Opcode: MOVDTOX
/* 5391 */    MCD_OPC_FilterValue, 145, 2, 16, 0, 0, // Skip to: 5413
/* 5397 */    MCD_OPC_CheckPredicate, 2, 122, 8, 0, // Skip to: 7572
/* 5402 */    MCD_OPC_CheckField, 14, 5, 0, 115, 8, 0, // Skip to: 7572
/* 5409 */    MCD_OPC_Decode, 201, 4, 66, // Opcode: MOVSTOUW
/* 5413 */    MCD_OPC_FilterValue, 147, 2, 16, 0, 0, // Skip to: 5435
/* 5419 */    MCD_OPC_CheckPredicate, 2, 100, 8, 0, // Skip to: 7572
/* 5424 */    MCD_OPC_CheckField, 14, 5, 0, 93, 8, 0, // Skip to: 7572
/* 5431 */    MCD_OPC_Decode, 200, 4, 66, // Opcode: MOVSTOSW
/* 5435 */    MCD_OPC_FilterValue, 149, 2, 9, 0, 0, // Skip to: 5450
/* 5441 */    MCD_OPC_CheckPredicate, 2, 78, 8, 0, // Skip to: 7572
/* 5446 */    MCD_OPC_Decode, 132, 6, 10, // Opcode: XMULX
/* 5450 */    MCD_OPC_FilterValue, 151, 2, 9, 0, 0, // Skip to: 5465
/* 5456 */    MCD_OPC_CheckPredicate, 2, 63, 8, 0, // Skip to: 7572
/* 5461 */    MCD_OPC_Decode, 133, 6, 10, // Opcode: XMULXHI
/* 5465 */    MCD_OPC_FilterValue, 152, 2, 16, 0, 0, // Skip to: 5487
/* 5471 */    MCD_OPC_CheckPredicate, 2, 48, 8, 0, // Skip to: 7572
/* 5476 */    MCD_OPC_CheckField, 14, 5, 0, 41, 8, 0, // Skip to: 7572
/* 5483 */    MCD_OPC_Decode, 205, 4, 67, // Opcode: MOVXTOD
/* 5487 */    MCD_OPC_FilterValue, 153, 2, 16, 0, 0, // Skip to: 5509
/* 5493 */    MCD_OPC_CheckPredicate, 2, 26, 8, 0, // Skip to: 7572
/* 5498 */    MCD_OPC_CheckField, 14, 5, 0, 19, 8, 0, // Skip to: 7572
/* 5505 */    MCD_OPC_Decode, 202, 4, 67, // Opcode: MOVWTOS
/* 5509 */    MCD_OPC_FilterValue, 209, 2, 9, 0, 0, // Skip to: 5524
/* 5515 */    MCD_OPC_CheckPredicate, 2, 4, 8, 0, // Skip to: 7572
/* 5520 */    MCD_OPC_Decode, 151, 3, 57, // Opcode: FLCMPS
/* 5524 */    MCD_OPC_FilterValue, 210, 2, 250, 7, 0, // Skip to: 7572
/* 5530 */    MCD_OPC_CheckPredicate, 2, 245, 7, 0, // Skip to: 7572
/* 5535 */    MCD_OPC_Decode, 150, 3, 57, // Opcode: FLCMPD
/* 5539 */    MCD_OPC_FilterValue, 56, 28, 0, 0, // Skip to: 5572
/* 5544 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5547 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 5563
/* 5552 */    MCD_OPC_CheckField, 5, 8, 0, 221, 7, 0, // Skip to: 7572
/* 5559 */    MCD_OPC_Decode, 132, 4, 68, // Opcode: JMPLrr
/* 5563 */    MCD_OPC_FilterValue, 1, 212, 7, 0, // Skip to: 7572
/* 5568 */    MCD_OPC_Decode, 131, 4, 69, // Opcode: JMPLri
/* 5572 */    MCD_OPC_FilterValue, 57, 42, 0, 0, // Skip to: 5619
/* 5577 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5580 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 5603
/* 5585 */    MCD_OPC_CheckField, 25, 5, 0, 188, 7, 0, // Skip to: 7572
/* 5592 */    MCD_OPC_CheckField, 5, 8, 0, 181, 7, 0, // Skip to: 7572
/* 5599 */    MCD_OPC_Decode, 239, 4, 70, // Opcode: RETTrr
/* 5603 */    MCD_OPC_FilterValue, 1, 172, 7, 0, // Skip to: 7572
/* 5608 */    MCD_OPC_CheckField, 25, 5, 0, 165, 7, 0, // Skip to: 7572
/* 5615 */    MCD_OPC_Decode, 238, 4, 71, // Opcode: RETTri
/* 5619 */    MCD_OPC_FilterValue, 58, 119, 0, 0, // Skip to: 5743
/* 5624 */    MCD_OPC_ExtractField, 8, 6,  // Inst{13-8} ...
/* 5627 */    MCD_OPC_FilterValue, 16, 18, 0, 0, // Skip to: 5650
/* 5632 */    MCD_OPC_CheckField, 29, 1, 0, 141, 7, 0, // Skip to: 7572
/* 5639 */    MCD_OPC_CheckField, 5, 3, 0, 134, 7, 0, // Skip to: 7572
/* 5646 */    MCD_OPC_Decode, 224, 5, 72, // Opcode: TXCCrr
/* 5650 */    MCD_OPC_FilterValue, 32, 72, 0, 0, // Skip to: 5727
/* 5655 */    MCD_OPC_ExtractField, 0, 8,  // Inst{7-0} ...
/* 5658 */    MCD_OPC_FilterValue, 1, 18, 0, 0, // Skip to: 5681
/* 5663 */    MCD_OPC_CheckField, 25, 5, 8, 110, 7, 0, // Skip to: 7572
/* 5670 */    MCD_OPC_CheckField, 14, 5, 0, 103, 7, 0, // Skip to: 7572
/* 5677 */    MCD_OPC_Decode, 202, 5, 4, // Opcode: TA1
/* 5681 */    MCD_OPC_FilterValue, 3, 18, 0, 0, // Skip to: 5704
/* 5686 */    MCD_OPC_CheckField, 25, 5, 8, 87, 7, 0, // Skip to: 7572
/* 5693 */    MCD_OPC_CheckField, 14, 5, 0, 80, 7, 0, // Skip to: 7572
/* 5700 */    MCD_OPC_Decode, 203, 5, 4, // Opcode: TA3
/* 5704 */    MCD_OPC_FilterValue, 5, 71, 7, 0, // Skip to: 7572
/* 5709 */    MCD_OPC_CheckField, 25, 5, 8, 64, 7, 0, // Skip to: 7572
/* 5716 */    MCD_OPC_CheckField, 14, 5, 0, 57, 7, 0, // Skip to: 7572
/* 5723 */    MCD_OPC_Decode, 204, 5, 4, // Opcode: TA5
/* 5727 */    MCD_OPC_FilterValue, 48, 48, 7, 0, // Skip to: 7572
/* 5732 */    MCD_OPC_CheckField, 29, 1, 0, 41, 7, 0, // Skip to: 7572
/* 5739 */    MCD_OPC_Decode, 223, 5, 73, // Opcode: TXCCri
/* 5743 */    MCD_OPC_FilterValue, 59, 62, 0, 0, // Skip to: 5810
/* 5748 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5751 */    MCD_OPC_FilterValue, 0, 38, 0, 0, // Skip to: 5794
/* 5756 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 5759 */    MCD_OPC_FilterValue, 0, 16, 7, 0, // Skip to: 7572
/* 5764 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 5767 */    MCD_OPC_FilterValue, 0, 8, 7, 0, // Skip to: 7572
/* 5772 */    MCD_OPC_CheckField, 14, 5, 0, 11, 0, 0, // Skip to: 5790
/* 5779 */    MCD_OPC_CheckField, 0, 5, 0, 4, 0, 0, // Skip to: 5790
/* 5786 */    MCD_OPC_Decode, 152, 3, 4, // Opcode: FLUSH
/* 5790 */    MCD_OPC_Decode, 155, 3, 70, // Opcode: FLUSHrr
/* 5794 */    MCD_OPC_FilterValue, 1, 237, 6, 0, // Skip to: 7572
/* 5799 */    MCD_OPC_CheckField, 25, 5, 0, 230, 6, 0, // Skip to: 7572
/* 5806 */    MCD_OPC_Decode, 154, 3, 71, // Opcode: FLUSHri
/* 5810 */    MCD_OPC_FilterValue, 60, 28, 0, 0, // Skip to: 5843
/* 5815 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5818 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 5834
/* 5823 */    MCD_OPC_CheckField, 5, 8, 0, 206, 6, 0, // Skip to: 7572
/* 5830 */    MCD_OPC_Decode, 242, 4, 8, // Opcode: SAVErr
/* 5834 */    MCD_OPC_FilterValue, 1, 197, 6, 0, // Skip to: 7572
/* 5839 */    MCD_OPC_Decode, 241, 4, 9, // Opcode: SAVEri
/* 5843 */    MCD_OPC_FilterValue, 61, 28, 0, 0, // Skip to: 5876
/* 5848 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5851 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 5867
/* 5856 */    MCD_OPC_CheckField, 5, 8, 0, 173, 6, 0, // Skip to: 7572
/* 5863 */    MCD_OPC_Decode, 234, 4, 8, // Opcode: RESTORErr
/* 5867 */    MCD_OPC_FilterValue, 1, 164, 6, 0, // Skip to: 7572
/* 5872 */    MCD_OPC_Decode, 233, 4, 9, // Opcode: RESTOREri
/* 5876 */    MCD_OPC_FilterValue, 62, 88, 0, 0, // Skip to: 5969
/* 5881 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5884 */    MCD_OPC_FilterValue, 0, 71, 0, 0, // Skip to: 5960
/* 5889 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 5892 */    MCD_OPC_FilterValue, 0, 139, 6, 0, // Skip to: 7572
/* 5897 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 5900 */    MCD_OPC_FilterValue, 0, 23, 0, 0, // Skip to: 5928
/* 5905 */    MCD_OPC_CheckPredicate, 0, 46, 0, 0, // Skip to: 5956
/* 5910 */    MCD_OPC_CheckField, 14, 5, 0, 39, 0, 0, // Skip to: 5956
/* 5917 */    MCD_OPC_CheckField, 0, 5, 0, 32, 0, 0, // Skip to: 5956
/* 5924 */    MCD_OPC_Decode, 217, 2, 4, // Opcode: DONE
/* 5928 */    MCD_OPC_FilterValue, 1, 23, 0, 0, // Skip to: 5956
/* 5933 */    MCD_OPC_CheckPredicate, 0, 18, 0, 0, // Skip to: 5956
/* 5938 */    MCD_OPC_CheckField, 14, 5, 0, 11, 0, 0, // Skip to: 5956
/* 5945 */    MCD_OPC_CheckField, 0, 5, 0, 4, 0, 0, // Skip to: 5956
/* 5952 */    MCD_OPC_Decode, 237, 4, 4, // Opcode: RETRY
/* 5956 */    MCD_OPC_Decode, 232, 5, 8, // Opcode: UMACrr
/* 5960 */    MCD_OPC_FilterValue, 1, 71, 6, 0, // Skip to: 7572
/* 5965 */    MCD_OPC_Decode, 231, 5, 9, // Opcode: UMACri
/* 5969 */    MCD_OPC_FilterValue, 63, 62, 6, 0, // Skip to: 7572
/* 5974 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5977 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 5993
/* 5982 */    MCD_OPC_CheckField, 5, 8, 0, 47, 6, 0, // Skip to: 7572
/* 5989 */    MCD_OPC_Decode, 130, 5, 8, // Opcode: SMACrr
/* 5993 */    MCD_OPC_FilterValue, 1, 38, 6, 0, // Skip to: 7572
/* 5998 */    MCD_OPC_Decode, 129, 5, 9, // Opcode: SMACri
/* 6002 */    MCD_OPC_FilterValue, 3, 29, 6, 0, // Skip to: 7572
/* 6007 */    MCD_OPC_ExtractField, 19, 6,  // Inst{24-19} ...
/* 6010 */    MCD_OPC_FilterValue, 0, 28, 0, 0, // Skip to: 6043
/* 6015 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6018 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6034
/* 6023 */    MCD_OPC_CheckField, 5, 8, 0, 6, 6, 0, // Skip to: 7572
/* 6030 */    MCD_OPC_Decode, 190, 4, 68, // Opcode: LDrr
/* 6034 */    MCD_OPC_FilterValue, 1, 253, 5, 0, // Skip to: 7572
/* 6039 */    MCD_OPC_Decode, 189, 4, 69, // Opcode: LDri
/* 6043 */    MCD_OPC_FilterValue, 1, 28, 0, 0, // Skip to: 6076
/* 6048 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6051 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6067
/* 6056 */    MCD_OPC_CheckField, 5, 8, 0, 229, 5, 0, // Skip to: 7572
/* 6063 */    MCD_OPC_Decode, 178, 4, 68, // Opcode: LDUBrr
/* 6067 */    MCD_OPC_FilterValue, 1, 220, 5, 0, // Skip to: 7572
/* 6072 */    MCD_OPC_Decode, 177, 4, 69, // Opcode: LDUBri
/* 6076 */    MCD_OPC_FilterValue, 2, 28, 0, 0, // Skip to: 6109
/* 6081 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6084 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6100
/* 6089 */    MCD_OPC_CheckField, 5, 8, 0, 196, 5, 0, // Skip to: 7572
/* 6096 */    MCD_OPC_Decode, 182, 4, 68, // Opcode: LDUHrr
/* 6100 */    MCD_OPC_FilterValue, 1, 187, 5, 0, // Skip to: 7572
/* 6105 */    MCD_OPC_Decode, 181, 4, 69, // Opcode: LDUHri
/* 6109 */    MCD_OPC_FilterValue, 3, 28, 0, 0, // Skip to: 6142
/* 6114 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6117 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6133
/* 6122 */    MCD_OPC_CheckField, 5, 8, 0, 163, 5, 0, // Skip to: 7572
/* 6129 */    MCD_OPC_Decode, 148, 4, 74, // Opcode: LDDrr
/* 6133 */    MCD_OPC_FilterValue, 1, 154, 5, 0, // Skip to: 7572
/* 6138 */    MCD_OPC_Decode, 147, 4, 75, // Opcode: LDDri
/* 6142 */    MCD_OPC_FilterValue, 4, 28, 0, 0, // Skip to: 6175
/* 6147 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6150 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6166
/* 6155 */    MCD_OPC_CheckField, 5, 8, 0, 130, 5, 0, // Skip to: 7572
/* 6162 */    MCD_OPC_Decode, 189, 5, 76, // Opcode: STrr
/* 6166 */    MCD_OPC_FilterValue, 1, 121, 5, 0, // Skip to: 7572
/* 6171 */    MCD_OPC_Decode, 188, 5, 77, // Opcode: STri
/* 6175 */    MCD_OPC_FilterValue, 5, 28, 0, 0, // Skip to: 6208
/* 6180 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6183 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6199
/* 6188 */    MCD_OPC_CheckField, 5, 8, 0, 97, 5, 0, // Skip to: 7572
/* 6195 */    MCD_OPC_Decode, 149, 5, 76, // Opcode: STBrr
/* 6199 */    MCD_OPC_FilterValue, 1, 88, 5, 0, // Skip to: 7572
/* 6204 */    MCD_OPC_Decode, 148, 5, 77, // Opcode: STBri
/* 6208 */    MCD_OPC_FilterValue, 6, 28, 0, 0, // Skip to: 6241
/* 6213 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6216 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6232
/* 6221 */    MCD_OPC_CheckField, 5, 8, 0, 64, 5, 0, // Skip to: 7572
/* 6228 */    MCD_OPC_Decode, 177, 5, 76, // Opcode: STHrr
/* 6232 */    MCD_OPC_FilterValue, 1, 55, 5, 0, // Skip to: 7572
/* 6237 */    MCD_OPC_Decode, 176, 5, 77, // Opcode: STHri
/* 6241 */    MCD_OPC_FilterValue, 7, 28, 0, 0, // Skip to: 6274
/* 6246 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6249 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6265
/* 6254 */    MCD_OPC_CheckField, 5, 8, 0, 31, 5, 0, // Skip to: 7572
/* 6261 */    MCD_OPC_Decode, 167, 5, 78, // Opcode: STDrr
/* 6265 */    MCD_OPC_FilterValue, 1, 22, 5, 0, // Skip to: 7572
/* 6270 */    MCD_OPC_Decode, 166, 5, 79, // Opcode: STDri
/* 6274 */    MCD_OPC_FilterValue, 8, 28, 0, 0, // Skip to: 6307
/* 6279 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6282 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6298
/* 6287 */    MCD_OPC_CheckField, 5, 8, 0, 254, 4, 0, // Skip to: 7572
/* 6294 */    MCD_OPC_Decode, 174, 4, 80, // Opcode: LDSWrr
/* 6298 */    MCD_OPC_FilterValue, 1, 245, 4, 0, // Skip to: 7572
/* 6303 */    MCD_OPC_Decode, 173, 4, 81, // Opcode: LDSWri
/* 6307 */    MCD_OPC_FilterValue, 9, 28, 0, 0, // Skip to: 6340
/* 6312 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6315 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6331
/* 6320 */    MCD_OPC_CheckField, 5, 8, 0, 221, 4, 0, // Skip to: 7572
/* 6327 */    MCD_OPC_Decode, 162, 4, 68, // Opcode: LDSBrr
/* 6331 */    MCD_OPC_FilterValue, 1, 212, 4, 0, // Skip to: 7572
/* 6336 */    MCD_OPC_Decode, 161, 4, 69, // Opcode: LDSBri
/* 6340 */    MCD_OPC_FilterValue, 10, 28, 0, 0, // Skip to: 6373
/* 6345 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6348 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6364
/* 6353 */    MCD_OPC_CheckField, 5, 8, 0, 188, 4, 0, // Skip to: 7572
/* 6360 */    MCD_OPC_Decode, 166, 4, 68, // Opcode: LDSHrr
/* 6364 */    MCD_OPC_FilterValue, 1, 179, 4, 0, // Skip to: 7572
/* 6369 */    MCD_OPC_Decode, 165, 4, 69, // Opcode: LDSHri
/* 6373 */    MCD_OPC_FilterValue, 11, 28, 0, 0, // Skip to: 6406
/* 6378 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6381 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6397
/* 6386 */    MCD_OPC_CheckField, 5, 8, 0, 155, 4, 0, // Skip to: 7572
/* 6393 */    MCD_OPC_Decode, 188, 4, 80, // Opcode: LDXrr
/* 6397 */    MCD_OPC_FilterValue, 1, 146, 4, 0, // Skip to: 7572
/* 6402 */    MCD_OPC_Decode, 187, 4, 81, // Opcode: LDXri
/* 6406 */    MCD_OPC_FilterValue, 13, 28, 0, 0, // Skip to: 6439
/* 6411 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6414 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6430
/* 6419 */    MCD_OPC_CheckField, 5, 8, 0, 122, 4, 0, // Skip to: 7572
/* 6426 */    MCD_OPC_Decode, 170, 4, 68, // Opcode: LDSTUBrr
/* 6430 */    MCD_OPC_FilterValue, 1, 113, 4, 0, // Skip to: 7572
/* 6435 */    MCD_OPC_Decode, 169, 4, 69, // Opcode: LDSTUBri
/* 6439 */    MCD_OPC_FilterValue, 14, 28, 0, 0, // Skip to: 6472
/* 6444 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6447 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6463
/* 6452 */    MCD_OPC_CheckField, 5, 8, 0, 89, 4, 0, // Skip to: 7572
/* 6459 */    MCD_OPC_Decode, 187, 5, 82, // Opcode: STXrr
/* 6463 */    MCD_OPC_FilterValue, 1, 80, 4, 0, // Skip to: 7572
/* 6468 */    MCD_OPC_Decode, 186, 5, 83, // Opcode: STXri
/* 6472 */    MCD_OPC_FilterValue, 15, 28, 0, 0, // Skip to: 6505
/* 6477 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6480 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6496
/* 6485 */    MCD_OPC_CheckField, 5, 8, 0, 56, 4, 0, // Skip to: 7572
/* 6492 */    MCD_OPC_Decode, 201, 5, 84, // Opcode: SWAPrr
/* 6496 */    MCD_OPC_FilterValue, 1, 47, 4, 0, // Skip to: 7572
/* 6501 */    MCD_OPC_Decode, 200, 5, 85, // Opcode: SWAPri
/* 6505 */    MCD_OPC_FilterValue, 16, 26, 0, 0, // Skip to: 6536
/* 6510 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6513 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6522
/* 6518 */    MCD_OPC_Decode, 134, 4, 86, // Opcode: LDArr
/* 6522 */    MCD_OPC_FilterValue, 1, 21, 4, 0, // Skip to: 7572
/* 6527 */    MCD_OPC_CheckPredicate, 0, 16, 4, 0, // Skip to: 7572
/* 6532 */    MCD_OPC_Decode, 133, 4, 69, // Opcode: LDAri
/* 6536 */    MCD_OPC_FilterValue, 17, 26, 0, 0, // Skip to: 6567
/* 6541 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6544 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6553
/* 6549 */    MCD_OPC_Decode, 176, 4, 86, // Opcode: LDUBArr
/* 6553 */    MCD_OPC_FilterValue, 1, 246, 3, 0, // Skip to: 7572
/* 6558 */    MCD_OPC_CheckPredicate, 0, 241, 3, 0, // Skip to: 7572
/* 6563 */    MCD_OPC_Decode, 175, 4, 69, // Opcode: LDUBAri
/* 6567 */    MCD_OPC_FilterValue, 18, 26, 0, 0, // Skip to: 6598
/* 6572 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6575 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6584
/* 6580 */    MCD_OPC_Decode, 180, 4, 86, // Opcode: LDUHArr
/* 6584 */    MCD_OPC_FilterValue, 1, 215, 3, 0, // Skip to: 7572
/* 6589 */    MCD_OPC_CheckPredicate, 0, 210, 3, 0, // Skip to: 7572
/* 6594 */    MCD_OPC_Decode, 179, 4, 69, // Opcode: LDUHAri
/* 6598 */    MCD_OPC_FilterValue, 19, 26, 0, 0, // Skip to: 6629
/* 6603 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6606 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6615
/* 6611 */    MCD_OPC_Decode, 140, 4, 87, // Opcode: LDDArr
/* 6615 */    MCD_OPC_FilterValue, 1, 184, 3, 0, // Skip to: 7572
/* 6620 */    MCD_OPC_CheckPredicate, 0, 179, 3, 0, // Skip to: 7572
/* 6625 */    MCD_OPC_Decode, 139, 4, 75, // Opcode: LDDAri
/* 6629 */    MCD_OPC_FilterValue, 20, 26, 0, 0, // Skip to: 6660
/* 6634 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6637 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6646
/* 6642 */    MCD_OPC_Decode, 144, 5, 88, // Opcode: STArr
/* 6646 */    MCD_OPC_FilterValue, 1, 153, 3, 0, // Skip to: 7572
/* 6651 */    MCD_OPC_CheckPredicate, 0, 148, 3, 0, // Skip to: 7572
/* 6656 */    MCD_OPC_Decode, 143, 5, 77, // Opcode: STAri
/* 6660 */    MCD_OPC_FilterValue, 21, 26, 0, 0, // Skip to: 6691
/* 6665 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6668 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6677
/* 6673 */    MCD_OPC_Decode, 147, 5, 88, // Opcode: STBArr
/* 6677 */    MCD_OPC_FilterValue, 1, 122, 3, 0, // Skip to: 7572
/* 6682 */    MCD_OPC_CheckPredicate, 0, 117, 3, 0, // Skip to: 7572
/* 6687 */    MCD_OPC_Decode, 146, 5, 77, // Opcode: STBAri
/* 6691 */    MCD_OPC_FilterValue, 22, 26, 0, 0, // Skip to: 6722
/* 6696 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6699 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6708
/* 6704 */    MCD_OPC_Decode, 175, 5, 88, // Opcode: STHArr
/* 6708 */    MCD_OPC_FilterValue, 1, 91, 3, 0, // Skip to: 7572
/* 6713 */    MCD_OPC_CheckPredicate, 0, 86, 3, 0, // Skip to: 7572
/* 6718 */    MCD_OPC_Decode, 174, 5, 77, // Opcode: STHAri
/* 6722 */    MCD_OPC_FilterValue, 23, 26, 0, 0, // Skip to: 6753
/* 6727 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6730 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6739
/* 6735 */    MCD_OPC_Decode, 155, 5, 89, // Opcode: STDArr
/* 6739 */    MCD_OPC_FilterValue, 1, 60, 3, 0, // Skip to: 7572
/* 6744 */    MCD_OPC_CheckPredicate, 0, 55, 3, 0, // Skip to: 7572
/* 6749 */    MCD_OPC_Decode, 154, 5, 79, // Opcode: STDAri
/* 6753 */    MCD_OPC_FilterValue, 24, 21, 0, 0, // Skip to: 6779
/* 6758 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6761 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6770
/* 6766 */    MCD_OPC_Decode, 172, 4, 90, // Opcode: LDSWArr
/* 6770 */    MCD_OPC_FilterValue, 1, 29, 3, 0, // Skip to: 7572
/* 6775 */    MCD_OPC_Decode, 171, 4, 81, // Opcode: LDSWAri
/* 6779 */    MCD_OPC_FilterValue, 25, 26, 0, 0, // Skip to: 6810
/* 6784 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6787 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6796
/* 6792 */    MCD_OPC_Decode, 160, 4, 86, // Opcode: LDSBArr
/* 6796 */    MCD_OPC_FilterValue, 1, 3, 3, 0, // Skip to: 7572
/* 6801 */    MCD_OPC_CheckPredicate, 0, 254, 2, 0, // Skip to: 7572
/* 6806 */    MCD_OPC_Decode, 159, 4, 69, // Opcode: LDSBAri
/* 6810 */    MCD_OPC_FilterValue, 26, 26, 0, 0, // Skip to: 6841
/* 6815 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6818 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6827
/* 6823 */    MCD_OPC_Decode, 164, 4, 86, // Opcode: LDSHArr
/* 6827 */    MCD_OPC_FilterValue, 1, 228, 2, 0, // Skip to: 7572
/* 6832 */    MCD_OPC_CheckPredicate, 0, 223, 2, 0, // Skip to: 7572
/* 6837 */    MCD_OPC_Decode, 163, 4, 69, // Opcode: LDSHAri
/* 6841 */    MCD_OPC_FilterValue, 27, 21, 0, 0, // Skip to: 6867
/* 6846 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6849 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6858
/* 6854 */    MCD_OPC_Decode, 184, 4, 90, // Opcode: LDXArr
/* 6858 */    MCD_OPC_FilterValue, 1, 197, 2, 0, // Skip to: 7572
/* 6863 */    MCD_OPC_Decode, 183, 4, 81, // Opcode: LDXAri
/* 6867 */    MCD_OPC_FilterValue, 29, 26, 0, 0, // Skip to: 6898
/* 6872 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6875 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6884
/* 6880 */    MCD_OPC_Decode, 168, 4, 86, // Opcode: LDSTUBArr
/* 6884 */    MCD_OPC_FilterValue, 1, 171, 2, 0, // Skip to: 7572
/* 6889 */    MCD_OPC_CheckPredicate, 0, 166, 2, 0, // Skip to: 7572
/* 6894 */    MCD_OPC_Decode, 167, 4, 69, // Opcode: LDSTUBAri
/* 6898 */    MCD_OPC_FilterValue, 30, 21, 0, 0, // Skip to: 6924
/* 6903 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6906 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6915
/* 6911 */    MCD_OPC_Decode, 183, 5, 91, // Opcode: STXArr
/* 6915 */    MCD_OPC_FilterValue, 1, 140, 2, 0, // Skip to: 7572
/* 6920 */    MCD_OPC_Decode, 182, 5, 83, // Opcode: STXAri
/* 6924 */    MCD_OPC_FilterValue, 31, 26, 0, 0, // Skip to: 6955
/* 6929 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6932 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6941
/* 6937 */    MCD_OPC_Decode, 199, 5, 92, // Opcode: SWAPArr
/* 6941 */    MCD_OPC_FilterValue, 1, 114, 2, 0, // Skip to: 7572
/* 6946 */    MCD_OPC_CheckPredicate, 0, 109, 2, 0, // Skip to: 7572
/* 6951 */    MCD_OPC_Decode, 198, 5, 85, // Opcode: SWAPAri
/* 6955 */    MCD_OPC_FilterValue, 32, 28, 0, 0, // Skip to: 6988
/* 6960 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6963 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6979
/* 6968 */    MCD_OPC_CheckField, 5, 8, 0, 85, 2, 0, // Skip to: 7572
/* 6975 */    MCD_OPC_Decode, 154, 4, 93, // Opcode: LDFrr
/* 6979 */    MCD_OPC_FilterValue, 1, 76, 2, 0, // Skip to: 7572
/* 6984 */    MCD_OPC_Decode, 153, 4, 94, // Opcode: LDFri
/* 6988 */    MCD_OPC_FilterValue, 33, 79, 0, 0, // Skip to: 7072
/* 6993 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6996 */    MCD_OPC_FilterValue, 0, 40, 0, 0, // Skip to: 7041
/* 7001 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 7004 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7020
/* 7009 */    MCD_OPC_CheckField, 5, 8, 0, 44, 2, 0, // Skip to: 7572
/* 7016 */    MCD_OPC_Decode, 152, 4, 70, // Opcode: LDFSRrr
/* 7020 */    MCD_OPC_FilterValue, 1, 35, 2, 0, // Skip to: 7572
/* 7025 */    MCD_OPC_CheckPredicate, 0, 30, 2, 0, // Skip to: 7572
/* 7030 */    MCD_OPC_CheckField, 5, 8, 0, 23, 2, 0, // Skip to: 7572
/* 7037 */    MCD_OPC_Decode, 186, 4, 70, // Opcode: LDXFSRrr
/* 7041 */    MCD_OPC_FilterValue, 1, 14, 2, 0, // Skip to: 7572
/* 7046 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 7049 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7058
/* 7054 */    MCD_OPC_Decode, 151, 4, 71, // Opcode: LDFSRri
/* 7058 */    MCD_OPC_FilterValue, 1, 253, 1, 0, // Skip to: 7572
/* 7063 */    MCD_OPC_CheckPredicate, 0, 248, 1, 0, // Skip to: 7572
/* 7068 */    MCD_OPC_Decode, 185, 4, 71, // Opcode: LDXFSRri
/* 7072 */    MCD_OPC_FilterValue, 35, 28, 0, 0, // Skip to: 7105
/* 7077 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7080 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7096
/* 7085 */    MCD_OPC_CheckField, 5, 8, 0, 224, 1, 0, // Skip to: 7572
/* 7092 */    MCD_OPC_Decode, 146, 4, 95, // Opcode: LDDFrr
/* 7096 */    MCD_OPC_FilterValue, 1, 215, 1, 0, // Skip to: 7572
/* 7101 */    MCD_OPC_Decode, 145, 4, 96, // Opcode: LDDFri
/* 7105 */    MCD_OPC_FilterValue, 36, 28, 0, 0, // Skip to: 7138
/* 7110 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7113 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7129
/* 7118 */    MCD_OPC_CheckField, 5, 8, 0, 191, 1, 0, // Skip to: 7572
/* 7125 */    MCD_OPC_Decode, 173, 5, 97, // Opcode: STFrr
/* 7129 */    MCD_OPC_FilterValue, 1, 182, 1, 0, // Skip to: 7572
/* 7134 */    MCD_OPC_Decode, 172, 5, 98, // Opcode: STFri
/* 7138 */    MCD_OPC_FilterValue, 37, 79, 0, 0, // Skip to: 7222
/* 7143 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7146 */    MCD_OPC_FilterValue, 0, 40, 0, 0, // Skip to: 7191
/* 7151 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 7154 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7170
/* 7159 */    MCD_OPC_CheckField, 5, 8, 0, 150, 1, 0, // Skip to: 7572
/* 7166 */    MCD_OPC_Decode, 171, 5, 70, // Opcode: STFSRrr
/* 7170 */    MCD_OPC_FilterValue, 1, 141, 1, 0, // Skip to: 7572
/* 7175 */    MCD_OPC_CheckPredicate, 0, 136, 1, 0, // Skip to: 7572
/* 7180 */    MCD_OPC_CheckField, 5, 8, 0, 129, 1, 0, // Skip to: 7572
/* 7187 */    MCD_OPC_Decode, 185, 5, 70, // Opcode: STXFSRrr
/* 7191 */    MCD_OPC_FilterValue, 1, 120, 1, 0, // Skip to: 7572
/* 7196 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 7199 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7208
/* 7204 */    MCD_OPC_Decode, 170, 5, 71, // Opcode: STFSRri
/* 7208 */    MCD_OPC_FilterValue, 1, 103, 1, 0, // Skip to: 7572
/* 7213 */    MCD_OPC_CheckPredicate, 0, 98, 1, 0, // Skip to: 7572
/* 7218 */    MCD_OPC_Decode, 184, 5, 71, // Opcode: STXFSRri
/* 7222 */    MCD_OPC_FilterValue, 38, 42, 0, 0, // Skip to: 7269
/* 7227 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7230 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 7253
/* 7235 */    MCD_OPC_CheckField, 25, 5, 0, 74, 1, 0, // Skip to: 7572
/* 7242 */    MCD_OPC_CheckField, 5, 8, 0, 67, 1, 0, // Skip to: 7572
/* 7249 */    MCD_OPC_Decode, 163, 5, 70, // Opcode: STDFQrr
/* 7253 */    MCD_OPC_FilterValue, 1, 58, 1, 0, // Skip to: 7572
/* 7258 */    MCD_OPC_CheckField, 25, 5, 0, 51, 1, 0, // Skip to: 7572
/* 7265 */    MCD_OPC_Decode, 162, 5, 71, // Opcode: STDFQri
/* 7269 */    MCD_OPC_FilterValue, 39, 28, 0, 0, // Skip to: 7302
/* 7274 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7277 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7293
/* 7282 */    MCD_OPC_CheckField, 5, 8, 0, 27, 1, 0, // Skip to: 7572
/* 7289 */    MCD_OPC_Decode, 165, 5, 99, // Opcode: STDFrr
/* 7293 */    MCD_OPC_FilterValue, 1, 18, 1, 0, // Skip to: 7572
/* 7298 */    MCD_OPC_Decode, 164, 5, 100, // Opcode: STDFri
/* 7302 */    MCD_OPC_FilterValue, 45, 38, 0, 0, // Skip to: 7345
/* 7307 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7310 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 7331
/* 7315 */    MCD_OPC_CheckPredicate, 0, 252, 0, 0, // Skip to: 7572
/* 7320 */    MCD_OPC_CheckField, 5, 8, 0, 245, 0, 0, // Skip to: 7572
/* 7327 */    MCD_OPC_Decode, 223, 4, 101, // Opcode: PREFETCHr
/* 7331 */    MCD_OPC_FilterValue, 1, 236, 0, 0, // Skip to: 7572
/* 7336 */    MCD_OPC_CheckPredicate, 0, 231, 0, 0, // Skip to: 7572
/* 7341 */    MCD_OPC_Decode, 222, 4, 102, // Opcode: PREFETCHi
/* 7345 */    MCD_OPC_FilterValue, 49, 42, 0, 0, // Skip to: 7392
/* 7350 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7353 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 7376
/* 7358 */    MCD_OPC_CheckField, 25, 5, 0, 207, 0, 0, // Skip to: 7572
/* 7365 */    MCD_OPC_CheckField, 5, 8, 0, 200, 0, 0, // Skip to: 7572
/* 7372 */    MCD_OPC_Decode, 136, 4, 70, // Opcode: LDCSRrr
/* 7376 */    MCD_OPC_FilterValue, 1, 191, 0, 0, // Skip to: 7572
/* 7381 */    MCD_OPC_CheckField, 25, 5, 0, 184, 0, 0, // Skip to: 7572
/* 7388 */    MCD_OPC_Decode, 135, 4, 71, // Opcode: LDCSRri
/* 7392 */    MCD_OPC_FilterValue, 53, 42, 0, 0, // Skip to: 7439
/* 7397 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7400 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 7423
/* 7405 */    MCD_OPC_CheckField, 25, 5, 0, 160, 0, 0, // Skip to: 7572
/* 7412 */    MCD_OPC_CheckField, 5, 8, 0, 153, 0, 0, // Skip to: 7572
/* 7419 */    MCD_OPC_Decode, 151, 5, 70, // Opcode: STCSRrr
/* 7423 */    MCD_OPC_FilterValue, 1, 144, 0, 0, // Skip to: 7572
/* 7428 */    MCD_OPC_CheckField, 25, 5, 0, 137, 0, 0, // Skip to: 7572
/* 7435 */    MCD_OPC_Decode, 150, 5, 71, // Opcode: STCSRri
/* 7439 */    MCD_OPC_FilterValue, 54, 42, 0, 0, // Skip to: 7486
/* 7444 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7447 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 7470
/* 7452 */    MCD_OPC_CheckField, 25, 5, 0, 113, 0, 0, // Skip to: 7572
/* 7459 */    MCD_OPC_CheckField, 5, 8, 0, 106, 0, 0, // Skip to: 7572
/* 7466 */    MCD_OPC_Decode, 157, 5, 70, // Opcode: STDCQrr
/* 7470 */    MCD_OPC_FilterValue, 1, 97, 0, 0, // Skip to: 7572
/* 7475 */    MCD_OPC_CheckField, 25, 5, 0, 90, 0, 0, // Skip to: 7572
/* 7482 */    MCD_OPC_Decode, 156, 5, 71, // Opcode: STDCQri
/* 7486 */    MCD_OPC_FilterValue, 60, 38, 0, 0, // Skip to: 7529
/* 7491 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7494 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 7508
/* 7499 */    MCD_OPC_CheckPredicate, 5, 68, 0, 0, // Skip to: 7572
/* 7504 */    MCD_OPC_Decode, 209, 2, 103, // Opcode: CASArr
/* 7508 */    MCD_OPC_FilterValue, 1, 59, 0, 0, // Skip to: 7572
/* 7513 */    MCD_OPC_CheckPredicate, 0, 54, 0, 0, // Skip to: 7572
/* 7518 */    MCD_OPC_CheckField, 5, 8, 0, 47, 0, 0, // Skip to: 7572
/* 7525 */    MCD_OPC_Decode, 208, 2, 104, // Opcode: CASAri
/* 7529 */    MCD_OPC_FilterValue, 62, 38, 0, 0, // Skip to: 7572
/* 7534 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7537 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 7551
/* 7542 */    MCD_OPC_CheckPredicate, 0, 25, 0, 0, // Skip to: 7572
/* 7547 */    MCD_OPC_Decode, 211, 2, 105, // Opcode: CASXArr
/* 7551 */    MCD_OPC_FilterValue, 1, 16, 0, 0, // Skip to: 7572
/* 7556 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 7572
/* 7561 */    MCD_OPC_CheckField, 5, 8, 0, 4, 0, 0, // Skip to: 7572
/* 7568 */    MCD_OPC_Decode, 210, 2, 106, // Opcode: CASXAri
/* 7572 */    MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableSparcV832[] = {
/* 0 */       MCD_OPC_ExtractField, 19, 6,  // Inst{24-19} ...
/* 3 */       MCD_OPC_FilterValue, 48, 42, 0, 0, // Skip to: 50
/* 8 */       MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 11 */      MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 34
/* 16 */      MCD_OPC_CheckField, 30, 2, 3, 215, 0, 0, // Skip to: 238
/* 23 */      MCD_OPC_CheckField, 5, 8, 0, 208, 0, 0, // Skip to: 238
/* 30 */      MCD_OPC_Decode, 138, 4, 107, // Opcode: LDCrr
/* 34 */      MCD_OPC_FilterValue, 1, 199, 0, 0, // Skip to: 238
/* 39 */      MCD_OPC_CheckField, 30, 2, 3, 192, 0, 0, // Skip to: 238
/* 46 */      MCD_OPC_Decode, 137, 4, 108, // Opcode: LDCri
/* 50 */      MCD_OPC_FilterValue, 51, 42, 0, 0, // Skip to: 97
/* 55 */      MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 58 */      MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 81
/* 63 */      MCD_OPC_CheckField, 30, 2, 3, 168, 0, 0, // Skip to: 238
/* 70 */      MCD_OPC_CheckField, 5, 8, 0, 161, 0, 0, // Skip to: 238
/* 77 */      MCD_OPC_Decode, 142, 4, 109, // Opcode: LDDCrr
/* 81 */      MCD_OPC_FilterValue, 1, 152, 0, 0, // Skip to: 238
/* 86 */      MCD_OPC_CheckField, 30, 2, 3, 145, 0, 0, // Skip to: 238
/* 93 */      MCD_OPC_Decode, 141, 4, 110, // Opcode: LDDCri
/* 97 */      MCD_OPC_FilterValue, 52, 42, 0, 0, // Skip to: 144
/* 102 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 105 */     MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 128
/* 110 */     MCD_OPC_CheckField, 30, 2, 3, 121, 0, 0, // Skip to: 238
/* 117 */     MCD_OPC_CheckField, 5, 8, 0, 114, 0, 0, // Skip to: 238
/* 124 */     MCD_OPC_Decode, 153, 5, 111, // Opcode: STCrr
/* 128 */     MCD_OPC_FilterValue, 1, 105, 0, 0, // Skip to: 238
/* 133 */     MCD_OPC_CheckField, 30, 2, 3, 98, 0, 0, // Skip to: 238
/* 140 */     MCD_OPC_Decode, 152, 5, 112, // Opcode: STCri
/* 144 */     MCD_OPC_FilterValue, 55, 42, 0, 0, // Skip to: 191
/* 149 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 152 */     MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 175
/* 157 */     MCD_OPC_CheckField, 30, 2, 3, 74, 0, 0, // Skip to: 238
/* 164 */     MCD_OPC_CheckField, 5, 8, 0, 67, 0, 0, // Skip to: 238
/* 171 */     MCD_OPC_Decode, 159, 5, 113, // Opcode: STDCrr
/* 175 */     MCD_OPC_FilterValue, 1, 58, 0, 0, // Skip to: 238
/* 180 */     MCD_OPC_CheckField, 30, 2, 3, 51, 0, 0, // Skip to: 238
/* 187 */     MCD_OPC_Decode, 158, 5, 114, // Opcode: STDCri
/* 191 */     MCD_OPC_FilterValue, 58, 42, 0, 0, // Skip to: 238
/* 196 */     MCD_OPC_ExtractField, 8, 6,  // Inst{13-8} ...
/* 199 */     MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 222
/* 204 */     MCD_OPC_CheckField, 29, 3, 4, 27, 0, 0, // Skip to: 238
/* 211 */     MCD_OPC_CheckField, 5, 3, 0, 20, 0, 0, // Skip to: 238
/* 218 */     MCD_OPC_Decode, 218, 5, 72, // Opcode: TRAPrr
/* 222 */     MCD_OPC_FilterValue, 32, 11, 0, 0, // Skip to: 238
/* 227 */     MCD_OPC_CheckField, 29, 3, 4, 4, 0, 0, // Skip to: 238
/* 234 */     MCD_OPC_Decode, 217, 5, 73, // Opcode: TRAPri
/* 238 */     MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableSparcV932[] = {
/* 0 */       MCD_OPC_ExtractField, 19, 6,  // Inst{24-19} ...
/* 3 */       MCD_OPC_FilterValue, 34, 52, 0, 0, // Skip to: 60
/* 8 */       MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 11 */      MCD_OPC_FilterValue, 0, 23, 0, 0, // Skip to: 39
/* 16 */      MCD_OPC_CheckPredicate, 0, 197, 1, 0, // Skip to: 474
/* 21 */      MCD_OPC_CheckField, 30, 2, 3, 190, 1, 0, // Skip to: 474
/* 28 */      MCD_OPC_CheckField, 5, 8, 0, 183, 1, 0, // Skip to: 474
/* 35 */      MCD_OPC_Decode, 158, 4, 115, // Opcode: LDQFrr
/* 39 */      MCD_OPC_FilterValue, 1, 174, 1, 0, // Skip to: 474
/* 44 */      MCD_OPC_CheckPredicate, 0, 169, 1, 0, // Skip to: 474
/* 49 */      MCD_OPC_CheckField, 30, 2, 3, 162, 1, 0, // Skip to: 474
/* 56 */      MCD_OPC_Decode, 157, 4, 116, // Opcode: LDQFri
/* 60 */      MCD_OPC_FilterValue, 38, 52, 0, 0, // Skip to: 117
/* 65 */      MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 68 */      MCD_OPC_FilterValue, 0, 23, 0, 0, // Skip to: 96
/* 73 */      MCD_OPC_CheckPredicate, 0, 140, 1, 0, // Skip to: 474
/* 78 */      MCD_OPC_CheckField, 30, 2, 3, 133, 1, 0, // Skip to: 474
/* 85 */      MCD_OPC_CheckField, 5, 8, 0, 126, 1, 0, // Skip to: 474
/* 92 */      MCD_OPC_Decode, 181, 5, 117, // Opcode: STQFrr
/* 96 */      MCD_OPC_FilterValue, 1, 117, 1, 0, // Skip to: 474
/* 101 */     MCD_OPC_CheckPredicate, 0, 112, 1, 0, // Skip to: 474
/* 106 */     MCD_OPC_CheckField, 30, 2, 3, 105, 1, 0, // Skip to: 474
/* 113 */     MCD_OPC_Decode, 180, 5, 118, // Opcode: STQFri
/* 117 */     MCD_OPC_FilterValue, 48, 45, 0, 0, // Skip to: 167
/* 122 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 125 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 146
/* 130 */     MCD_OPC_CheckPredicate, 0, 83, 1, 0, // Skip to: 474
/* 135 */     MCD_OPC_CheckField, 30, 2, 3, 76, 1, 0, // Skip to: 474
/* 142 */     MCD_OPC_Decode, 150, 4, 119, // Opcode: LDFArr
/* 146 */     MCD_OPC_FilterValue, 1, 67, 1, 0, // Skip to: 474
/* 151 */     MCD_OPC_CheckPredicate, 0, 62, 1, 0, // Skip to: 474
/* 156 */     MCD_OPC_CheckField, 30, 2, 3, 55, 1, 0, // Skip to: 474
/* 163 */     MCD_OPC_Decode, 149, 4, 94, // Opcode: LDFAri
/* 167 */     MCD_OPC_FilterValue, 50, 45, 0, 0, // Skip to: 217
/* 172 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 175 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 196
/* 180 */     MCD_OPC_CheckPredicate, 0, 33, 1, 0, // Skip to: 474
/* 185 */     MCD_OPC_CheckField, 30, 2, 3, 26, 1, 0, // Skip to: 474
/* 192 */     MCD_OPC_Decode, 156, 4, 120, // Opcode: LDQFArr
/* 196 */     MCD_OPC_FilterValue, 1, 17, 1, 0, // Skip to: 474
/* 201 */     MCD_OPC_CheckPredicate, 0, 12, 1, 0, // Skip to: 474
/* 206 */     MCD_OPC_CheckField, 30, 2, 3, 5, 1, 0, // Skip to: 474
/* 213 */     MCD_OPC_Decode, 155, 4, 116, // Opcode: LDQFAri
/* 217 */     MCD_OPC_FilterValue, 51, 45, 0, 0, // Skip to: 267
/* 222 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 225 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 246
/* 230 */     MCD_OPC_CheckPredicate, 0, 239, 0, 0, // Skip to: 474
/* 235 */     MCD_OPC_CheckField, 30, 2, 3, 232, 0, 0, // Skip to: 474
/* 242 */     MCD_OPC_Decode, 144, 4, 121, // Opcode: LDDFArr
/* 246 */     MCD_OPC_FilterValue, 1, 223, 0, 0, // Skip to: 474
/* 251 */     MCD_OPC_CheckPredicate, 0, 218, 0, 0, // Skip to: 474
/* 256 */     MCD_OPC_CheckField, 30, 2, 3, 211, 0, 0, // Skip to: 474
/* 263 */     MCD_OPC_Decode, 143, 4, 96, // Opcode: LDDFAri
/* 267 */     MCD_OPC_FilterValue, 52, 45, 0, 0, // Skip to: 317
/* 272 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 275 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 296
/* 280 */     MCD_OPC_CheckPredicate, 0, 189, 0, 0, // Skip to: 474
/* 285 */     MCD_OPC_CheckField, 30, 2, 3, 182, 0, 0, // Skip to: 474
/* 292 */     MCD_OPC_Decode, 169, 5, 122, // Opcode: STFArr
/* 296 */     MCD_OPC_FilterValue, 1, 173, 0, 0, // Skip to: 474
/* 301 */     MCD_OPC_CheckPredicate, 0, 168, 0, 0, // Skip to: 474
/* 306 */     MCD_OPC_CheckField, 30, 2, 3, 161, 0, 0, // Skip to: 474
/* 313 */     MCD_OPC_Decode, 168, 5, 98, // Opcode: STFAri
/* 317 */     MCD_OPC_FilterValue, 54, 45, 0, 0, // Skip to: 367
/* 322 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 325 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 346
/* 330 */     MCD_OPC_CheckPredicate, 0, 139, 0, 0, // Skip to: 474
/* 335 */     MCD_OPC_CheckField, 30, 2, 3, 132, 0, 0, // Skip to: 474
/* 342 */     MCD_OPC_Decode, 179, 5, 123, // Opcode: STQFArr
/* 346 */     MCD_OPC_FilterValue, 1, 123, 0, 0, // Skip to: 474
/* 351 */     MCD_OPC_CheckPredicate, 0, 118, 0, 0, // Skip to: 474
/* 356 */     MCD_OPC_CheckField, 30, 2, 3, 111, 0, 0, // Skip to: 474
/* 363 */     MCD_OPC_Decode, 178, 5, 118, // Opcode: STQFAri
/* 367 */     MCD_OPC_FilterValue, 55, 45, 0, 0, // Skip to: 417
/* 372 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 375 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 396
/* 380 */     MCD_OPC_CheckPredicate, 0, 89, 0, 0, // Skip to: 474
/* 385 */     MCD_OPC_CheckField, 30, 2, 3, 82, 0, 0, // Skip to: 474
/* 392 */     MCD_OPC_Decode, 161, 5, 124, // Opcode: STDFArr
/* 396 */     MCD_OPC_FilterValue, 1, 73, 0, 0, // Skip to: 474
/* 401 */     MCD_OPC_CheckPredicate, 0, 68, 0, 0, // Skip to: 474
/* 406 */     MCD_OPC_CheckField, 30, 2, 3, 61, 0, 0, // Skip to: 474
/* 413 */     MCD_OPC_Decode, 160, 5, 100, // Opcode: STDFAri
/* 417 */     MCD_OPC_FilterValue, 58, 52, 0, 0, // Skip to: 474
/* 422 */     MCD_OPC_ExtractField, 8, 6,  // Inst{13-8} ...
/* 425 */     MCD_OPC_FilterValue, 0, 23, 0, 0, // Skip to: 453
/* 430 */     MCD_OPC_CheckPredicate, 0, 39, 0, 0, // Skip to: 474
/* 435 */     MCD_OPC_CheckField, 29, 3, 4, 32, 0, 0, // Skip to: 474
/* 442 */     MCD_OPC_CheckField, 5, 3, 0, 25, 0, 0, // Skip to: 474
/* 449 */     MCD_OPC_Decode, 212, 5, 72, // Opcode: TICCrr
/* 453 */     MCD_OPC_FilterValue, 32, 16, 0, 0, // Skip to: 474
/* 458 */     MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 474
/* 463 */     MCD_OPC_CheckField, 29, 3, 4, 4, 0, 0, // Skip to: 474
/* 470 */     MCD_OPC_Decode, 211, 5, 73, // Opcode: TICCri
/* 474 */     MCD_OPC_Fail,
  0
};

static bool checkDecoderPredicate(MCInst *Inst, unsigned Idx) {
  switch (Idx) {
  default: CS_ASSERT_RET_VAL(0 && "Invalid index!", false);
  case 0:
    return (Sparc_getFeatureBits(Inst->csh->mode, Sparc_FeatureV9));
  case 1:
    return (Sparc_getFeatureBits(Inst->csh->mode, Sparc_FeaturePWRPSR));
  case 2:
    return (Sparc_getFeatureBits(Inst->csh->mode, Sparc_FeatureVIS3));
  case 3:
    return (Sparc_getFeatureBits(Inst->csh->mode, Sparc_FeatureVIS));
  case 4:
    return (Sparc_getFeatureBits(Inst->csh->mode, Sparc_FeatureVIS2));
  case 5:
    return (Sparc_getFeatureBits(Inst->csh->mode, Sparc_LeonCASA) || Sparc_getFeatureBits(Inst->csh->mode, Sparc_FeatureV9));
  }
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
    tmp = fieldname(insn, 0, 22); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 1: \
    tmp = fieldname(insn, 0, 19); \
    if (!Check(&S, DecodeDisp19(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 2: \
    tmp = fieldname(insn, 0, 22); \
    if (!Check(&S, DecodeDisp22(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 3: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 14) << 0; \
    tmp |= fieldname(insn, 20, 2) << 14; \
    if (!Check(&S, DecodeDisp16(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 4: \
    return S; \
  case 5: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 22); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 6: \
    tmp = fieldname(insn, 0, 19); \
    if (!Check(&S, DecodeDisp19(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 20, 2); \
    if (!Check(&S, DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 7: \
    tmp = fieldname(insn, 0, 30); \
    if (!Check(&S, DecodeCall(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 8: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 9: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    if (!Check(&S, DecodeSIMM13(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 10: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 11: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 12: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 13: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 6); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 14: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 6); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 15: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeASRRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 16: \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 17: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 18: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePRRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 19: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 20: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 2); \
    if (!Check(&S, DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 21: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 11); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 22: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 2); \
    if (!Check(&S, DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 11); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 23: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 24: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 10, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 25: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 10, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 26: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeASRRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 27: \
    tmp = fieldname(insn, 0, 13); \
    if (!Check(&S, DecodeSIMM13(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 28: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeASRRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    if (!Check(&S, DecodeSIMM13(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 29: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 30: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    if (!Check(&S, DecodeSIMM13(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 31: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodePRRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 32: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodePRRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    if (!Check(&S, DecodeSIMM13(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 33: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 34: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 35: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 36: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 37: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 38: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 39: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 40: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 41: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 42: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 43: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 44: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 45: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 46: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 47: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 48: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 2); \
    if (!Check(&S, DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 49: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 50: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 2); \
    if (!Check(&S, DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 51: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 52: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 2); \
    if (!Check(&S, DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 53: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 10, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 54: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 10, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 55: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 10, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 56: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 57: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 58: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 59: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 60: \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 61: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 62: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 63: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 64: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 65: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 66: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 67: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 68: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 69: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 70: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 71: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 72: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 73: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 74: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 75: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 76: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 77: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 78: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 79: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 80: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 81: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 82: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 83: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 84: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 85: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 86: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 87: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 88: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 89: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 90: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 91: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 92: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 93: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 94: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 95: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 96: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 97: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 98: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 99: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 100: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 101: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 102: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 103: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 104: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 105: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 106: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 107: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 108: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 109: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 110: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 111: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 112: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 113: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 114: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 115: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 116: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 117: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 118: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 119: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 120: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 121: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 122: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 123: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 124: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
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

FieldFromInstruction(fieldFromInstruction_4, uint32_t)
DecodeToMCInst(decodeToMCInst_4, fieldFromInstruction_4, uint32_t)
DecodeInstruction(decodeInstruction_4, fieldFromInstruction_4, decodeToMCInst_4, uint32_t)
