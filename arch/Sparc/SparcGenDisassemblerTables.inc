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
/* 3 */       MCD_OPC_FilterValue, 0, 183, 1, 0, // Skip to: 447
/* 8 */       MCD_OPC_ExtractField, 22, 3,  // Inst{24-22} ...
/* 11 */      MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 27
/* 16 */      MCD_OPC_CheckField, 25, 5, 0, 136, 29, 0, // Skip to: 7583
/* 23 */      MCD_OPC_Decode, 239, 5, 0, // Opcode: UNIMP
/* 27 */      MCD_OPC_FilterValue, 1, 127, 0, 0, // Skip to: 159
/* 32 */      MCD_OPC_ExtractField, 19, 3,  // Inst{21-19} ...
/* 35 */      MCD_OPC_FilterValue, 0, 31, 0, 0, // Skip to: 71
/* 40 */      MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 43 */      MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 57
/* 48 */      MCD_OPC_CheckPredicate, 0, 106, 29, 0, // Skip to: 7583
/* 53 */      MCD_OPC_Decode, 196, 2, 1, // Opcode: BPICCNT
/* 57 */      MCD_OPC_FilterValue, 1, 97, 29, 0, // Skip to: 7583
/* 62 */      MCD_OPC_CheckPredicate, 0, 92, 29, 0, // Skip to: 7583
/* 67 */      MCD_OPC_Decode, 195, 2, 1, // Opcode: BPICCANT
/* 71 */      MCD_OPC_FilterValue, 1, 31, 0, 0, // Skip to: 107
/* 76 */      MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 79 */      MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 93
/* 84 */      MCD_OPC_CheckPredicate, 0, 70, 29, 0, // Skip to: 7583
/* 89 */      MCD_OPC_Decode, 193, 2, 1, // Opcode: BPICC
/* 93 */      MCD_OPC_FilterValue, 1, 61, 29, 0, // Skip to: 7583
/* 98 */      MCD_OPC_CheckPredicate, 0, 56, 29, 0, // Skip to: 7583
/* 103 */     MCD_OPC_Decode, 194, 2, 1, // Opcode: BPICCA
/* 107 */     MCD_OPC_FilterValue, 4, 21, 0, 0, // Skip to: 133
/* 112 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 115 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 124
/* 120 */     MCD_OPC_Decode, 204, 2, 1, // Opcode: BPXCCNT
/* 124 */     MCD_OPC_FilterValue, 1, 30, 29, 0, // Skip to: 7583
/* 129 */     MCD_OPC_Decode, 203, 2, 1, // Opcode: BPXCCANT
/* 133 */     MCD_OPC_FilterValue, 5, 21, 29, 0, // Skip to: 7583
/* 138 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 141 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 150
/* 146 */     MCD_OPC_Decode, 201, 2, 1, // Opcode: BPXCC
/* 150 */     MCD_OPC_FilterValue, 1, 4, 29, 0, // Skip to: 7583
/* 155 */     MCD_OPC_Decode, 202, 2, 1, // Opcode: BPXCCA
/* 159 */     MCD_OPC_FilterValue, 2, 32, 0, 0, // Skip to: 196
/* 164 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 167 */     MCD_OPC_FilterValue, 0, 15, 0, 0, // Skip to: 187
/* 172 */     MCD_OPC_CheckField, 25, 4, 8, 4, 0, 0, // Skip to: 183
/* 179 */     MCD_OPC_Decode, 183, 2, 2, // Opcode: BA
/* 183 */     MCD_OPC_Decode, 184, 2, 3, // Opcode: BCOND
/* 187 */     MCD_OPC_FilterValue, 1, 223, 28, 0, // Skip to: 7583
/* 192 */     MCD_OPC_Decode, 185, 2, 3, // Opcode: BCONDA
/* 196 */     MCD_OPC_FilterValue, 3, 55, 0, 0, // Skip to: 256
/* 201 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 204 */     MCD_OPC_FilterValue, 0, 21, 0, 0, // Skip to: 230
/* 209 */     MCD_OPC_ExtractField, 28, 2,  // Inst{29-28} ...
/* 212 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 221
/* 217 */     MCD_OPC_Decode, 200, 2, 4, // Opcode: BPRNT
/* 221 */     MCD_OPC_FilterValue, 2, 189, 28, 0, // Skip to: 7583
/* 226 */     MCD_OPC_Decode, 199, 2, 4, // Opcode: BPRANT
/* 230 */     MCD_OPC_FilterValue, 1, 180, 28, 0, // Skip to: 7583
/* 235 */     MCD_OPC_ExtractField, 28, 2,  // Inst{29-28} ...
/* 238 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 247
/* 243 */     MCD_OPC_Decode, 197, 2, 4, // Opcode: BPR
/* 247 */     MCD_OPC_FilterValue, 2, 163, 28, 0, // Skip to: 7583
/* 252 */     MCD_OPC_Decode, 198, 2, 4, // Opcode: BPRA
/* 256 */     MCD_OPC_FilterValue, 4, 22, 0, 0, // Skip to: 283
/* 261 */     MCD_OPC_CheckField, 25, 5, 0, 11, 0, 0, // Skip to: 279
/* 268 */     MCD_OPC_CheckField, 0, 22, 0, 4, 0, 0, // Skip to: 279
/* 275 */     MCD_OPC_Decode, 211, 4, 5, // Opcode: NOP
/* 279 */     MCD_OPC_Decode, 250, 4, 6, // Opcode: SETHIi
/* 283 */     MCD_OPC_FilterValue, 5, 107, 0, 0, // Skip to: 395
/* 288 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 291 */     MCD_OPC_FilterValue, 0, 31, 0, 0, // Skip to: 327
/* 296 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 299 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 313
/* 304 */     MCD_OPC_CheckPredicate, 0, 106, 28, 0, // Skip to: 7583
/* 309 */     MCD_OPC_Decode, 192, 2, 7, // Opcode: BPFCCNT
/* 313 */     MCD_OPC_FilterValue, 1, 97, 28, 0, // Skip to: 7583
/* 318 */     MCD_OPC_CheckPredicate, 0, 92, 28, 0, // Skip to: 7583
/* 323 */     MCD_OPC_Decode, 191, 2, 7, // Opcode: BPFCCANT
/* 327 */     MCD_OPC_FilterValue, 1, 83, 28, 0, // Skip to: 7583
/* 332 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 335 */     MCD_OPC_FilterValue, 0, 25, 0, 0, // Skip to: 365
/* 340 */     MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 356
/* 345 */     MCD_OPC_CheckField, 20, 2, 0, 4, 0, 0, // Skip to: 356
/* 352 */     MCD_OPC_Decode, 247, 2, 1, // Opcode: FBCOND_V9
/* 356 */     MCD_OPC_CheckPredicate, 0, 54, 28, 0, // Skip to: 7583
/* 361 */     MCD_OPC_Decode, 189, 2, 7, // Opcode: BPFCC
/* 365 */     MCD_OPC_FilterValue, 1, 45, 28, 0, // Skip to: 7583
/* 370 */     MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 386
/* 375 */     MCD_OPC_CheckField, 20, 2, 0, 4, 0, 0, // Skip to: 386
/* 382 */     MCD_OPC_Decode, 246, 2, 1, // Opcode: FBCONDA_V9
/* 386 */     MCD_OPC_CheckPredicate, 0, 24, 28, 0, // Skip to: 7583
/* 391 */     MCD_OPC_Decode, 190, 2, 7, // Opcode: BPFCCA
/* 395 */     MCD_OPC_FilterValue, 6, 21, 0, 0, // Skip to: 421
/* 400 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 403 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 412
/* 408 */     MCD_OPC_Decode, 244, 2, 3, // Opcode: FBCOND
/* 412 */     MCD_OPC_FilterValue, 1, 254, 27, 0, // Skip to: 7583
/* 417 */     MCD_OPC_Decode, 245, 2, 3, // Opcode: FBCONDA
/* 421 */     MCD_OPC_FilterValue, 7, 245, 27, 0, // Skip to: 7583
/* 426 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 429 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 438
/* 434 */     MCD_OPC_Decode, 213, 2, 3, // Opcode: CBCOND
/* 438 */     MCD_OPC_FilterValue, 1, 228, 27, 0, // Skip to: 7583
/* 443 */     MCD_OPC_Decode, 214, 2, 3, // Opcode: CBCONDA
/* 447 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 456
/* 452 */     MCD_OPC_Decode, 206, 2, 8, // Opcode: CALL
/* 456 */     MCD_OPC_FilterValue, 2, 176, 21, 0, // Skip to: 6013
/* 461 */     MCD_OPC_ExtractField, 19, 6,  // Inst{24-19} ...
/* 464 */     MCD_OPC_FilterValue, 0, 28, 0, 0, // Skip to: 497
/* 469 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 472 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 488
/* 477 */     MCD_OPC_CheckField, 5, 8, 0, 187, 27, 0, // Skip to: 7583
/* 484 */     MCD_OPC_Decode, 169, 2, 9, // Opcode: ADDrr
/* 488 */     MCD_OPC_FilterValue, 1, 178, 27, 0, // Skip to: 7583
/* 493 */     MCD_OPC_Decode, 168, 2, 10, // Opcode: ADDri
/* 497 */     MCD_OPC_FilterValue, 1, 28, 0, 0, // Skip to: 530
/* 502 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 505 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 521
/* 510 */     MCD_OPC_CheckField, 5, 8, 0, 154, 27, 0, // Skip to: 7583
/* 517 */     MCD_OPC_Decode, 179, 2, 9, // Opcode: ANDrr
/* 521 */     MCD_OPC_FilterValue, 1, 145, 27, 0, // Skip to: 7583
/* 526 */     MCD_OPC_Decode, 178, 2, 10, // Opcode: ANDri
/* 530 */     MCD_OPC_FilterValue, 2, 28, 0, 0, // Skip to: 563
/* 535 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 538 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 554
/* 543 */     MCD_OPC_CheckField, 5, 8, 0, 121, 27, 0, // Skip to: 7583
/* 550 */     MCD_OPC_Decode, 219, 4, 9, // Opcode: ORrr
/* 554 */     MCD_OPC_FilterValue, 1, 112, 27, 0, // Skip to: 7583
/* 559 */     MCD_OPC_Decode, 218, 4, 10, // Opcode: ORri
/* 563 */     MCD_OPC_FilterValue, 3, 28, 0, 0, // Skip to: 596
/* 568 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 571 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 587
/* 576 */     MCD_OPC_CheckField, 5, 8, 0, 88, 27, 0, // Skip to: 7583
/* 583 */     MCD_OPC_Decode, 142, 6, 9, // Opcode: XORrr
/* 587 */     MCD_OPC_FilterValue, 1, 79, 27, 0, // Skip to: 7583
/* 592 */     MCD_OPC_Decode, 141, 6, 10, // Opcode: XORri
/* 596 */     MCD_OPC_FilterValue, 4, 28, 0, 0, // Skip to: 629
/* 601 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 604 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 620
/* 609 */     MCD_OPC_CheckField, 5, 8, 0, 55, 27, 0, // Skip to: 7583
/* 616 */     MCD_OPC_Decode, 198, 5, 9, // Opcode: SUBrr
/* 620 */     MCD_OPC_FilterValue, 1, 46, 27, 0, // Skip to: 7583
/* 625 */     MCD_OPC_Decode, 197, 5, 10, // Opcode: SUBri
/* 629 */     MCD_OPC_FilterValue, 5, 28, 0, 0, // Skip to: 662
/* 634 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 637 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 653
/* 642 */     MCD_OPC_CheckField, 5, 8, 0, 22, 27, 0, // Skip to: 7583
/* 649 */     MCD_OPC_Decode, 177, 2, 9, // Opcode: ANDNrr
/* 653 */     MCD_OPC_FilterValue, 1, 13, 27, 0, // Skip to: 7583
/* 658 */     MCD_OPC_Decode, 176, 2, 10, // Opcode: ANDNri
/* 662 */     MCD_OPC_FilterValue, 6, 28, 0, 0, // Skip to: 695
/* 667 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 670 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 686
/* 675 */     MCD_OPC_CheckField, 5, 8, 0, 245, 26, 0, // Skip to: 7583
/* 682 */     MCD_OPC_Decode, 217, 4, 9, // Opcode: ORNrr
/* 686 */     MCD_OPC_FilterValue, 1, 236, 26, 0, // Skip to: 7583
/* 691 */     MCD_OPC_Decode, 216, 4, 10, // Opcode: ORNri
/* 695 */     MCD_OPC_FilterValue, 7, 28, 0, 0, // Skip to: 728
/* 700 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 703 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 719
/* 708 */     MCD_OPC_CheckField, 5, 8, 0, 212, 26, 0, // Skip to: 7583
/* 715 */     MCD_OPC_Decode, 138, 6, 9, // Opcode: XNORrr
/* 719 */     MCD_OPC_FilterValue, 1, 203, 26, 0, // Skip to: 7583
/* 724 */     MCD_OPC_Decode, 137, 6, 10, // Opcode: XNORri
/* 728 */     MCD_OPC_FilterValue, 8, 28, 0, 0, // Skip to: 761
/* 733 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 736 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 752
/* 741 */     MCD_OPC_CheckField, 5, 8, 0, 179, 26, 0, // Skip to: 7583
/* 748 */     MCD_OPC_Decode, 163, 2, 9, // Opcode: ADDCrr
/* 752 */     MCD_OPC_FilterValue, 1, 170, 26, 0, // Skip to: 7583
/* 757 */     MCD_OPC_Decode, 162, 2, 10, // Opcode: ADDCri
/* 761 */     MCD_OPC_FilterValue, 9, 28, 0, 0, // Skip to: 794
/* 766 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 769 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 785
/* 774 */     MCD_OPC_CheckField, 5, 8, 0, 146, 26, 0, // Skip to: 7583
/* 781 */     MCD_OPC_Decode, 210, 4, 11, // Opcode: MULXrr
/* 785 */     MCD_OPC_FilterValue, 1, 137, 26, 0, // Skip to: 7583
/* 790 */     MCD_OPC_Decode, 209, 4, 12, // Opcode: MULXri
/* 794 */     MCD_OPC_FilterValue, 10, 28, 0, 0, // Skip to: 827
/* 799 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 802 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 818
/* 807 */     MCD_OPC_CheckField, 5, 8, 0, 113, 26, 0, // Skip to: 7583
/* 814 */     MCD_OPC_Decode, 238, 5, 9, // Opcode: UMULrr
/* 818 */     MCD_OPC_FilterValue, 1, 104, 26, 0, // Skip to: 7583
/* 823 */     MCD_OPC_Decode, 237, 5, 10, // Opcode: UMULri
/* 827 */     MCD_OPC_FilterValue, 11, 28, 0, 0, // Skip to: 860
/* 832 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 835 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 851
/* 840 */     MCD_OPC_CheckField, 5, 8, 0, 80, 26, 0, // Skip to: 7583
/* 847 */     MCD_OPC_Decode, 135, 5, 9, // Opcode: SMULrr
/* 851 */     MCD_OPC_FilterValue, 1, 71, 26, 0, // Skip to: 7583
/* 856 */     MCD_OPC_Decode, 134, 5, 10, // Opcode: SMULri
/* 860 */     MCD_OPC_FilterValue, 12, 28, 0, 0, // Skip to: 893
/* 865 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 868 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 884
/* 873 */     MCD_OPC_CheckField, 5, 8, 0, 47, 26, 0, // Skip to: 7583
/* 880 */     MCD_OPC_Decode, 194, 5, 9, // Opcode: SUBCrr
/* 884 */     MCD_OPC_FilterValue, 1, 38, 26, 0, // Skip to: 7583
/* 889 */     MCD_OPC_Decode, 193, 5, 10, // Opcode: SUBCri
/* 893 */     MCD_OPC_FilterValue, 13, 28, 0, 0, // Skip to: 926
/* 898 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 901 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 917
/* 906 */     MCD_OPC_CheckField, 5, 8, 0, 14, 26, 0, // Skip to: 7583
/* 913 */     MCD_OPC_Decode, 229, 5, 11, // Opcode: UDIVXrr
/* 917 */     MCD_OPC_FilterValue, 1, 5, 26, 0, // Skip to: 7583
/* 922 */     MCD_OPC_Decode, 228, 5, 12, // Opcode: UDIVXri
/* 926 */     MCD_OPC_FilterValue, 14, 28, 0, 0, // Skip to: 959
/* 931 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 934 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 950
/* 939 */     MCD_OPC_CheckField, 5, 8, 0, 237, 25, 0, // Skip to: 7583
/* 946 */     MCD_OPC_Decode, 231, 5, 9, // Opcode: UDIVrr
/* 950 */     MCD_OPC_FilterValue, 1, 228, 25, 0, // Skip to: 7583
/* 955 */     MCD_OPC_Decode, 230, 5, 10, // Opcode: UDIVri
/* 959 */     MCD_OPC_FilterValue, 15, 28, 0, 0, // Skip to: 992
/* 964 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 967 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 983
/* 972 */     MCD_OPC_CheckField, 5, 8, 0, 204, 25, 0, // Skip to: 7583
/* 979 */     MCD_OPC_Decode, 249, 4, 9, // Opcode: SDIVrr
/* 983 */     MCD_OPC_FilterValue, 1, 195, 25, 0, // Skip to: 7583
/* 988 */     MCD_OPC_Decode, 248, 4, 10, // Opcode: SDIVri
/* 992 */     MCD_OPC_FilterValue, 16, 28, 0, 0, // Skip to: 1025
/* 997 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1000 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1016
/* 1005 */    MCD_OPC_CheckField, 5, 8, 0, 171, 25, 0, // Skip to: 7583
/* 1012 */    MCD_OPC_Decode, 161, 2, 9, // Opcode: ADDCCrr
/* 1016 */    MCD_OPC_FilterValue, 1, 162, 25, 0, // Skip to: 7583
/* 1021 */    MCD_OPC_Decode, 160, 2, 10, // Opcode: ADDCCri
/* 1025 */    MCD_OPC_FilterValue, 17, 28, 0, 0, // Skip to: 1058
/* 1030 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1033 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1049
/* 1038 */    MCD_OPC_CheckField, 5, 8, 0, 138, 25, 0, // Skip to: 7583
/* 1045 */    MCD_OPC_Decode, 173, 2, 9, // Opcode: ANDCCrr
/* 1049 */    MCD_OPC_FilterValue, 1, 129, 25, 0, // Skip to: 7583
/* 1054 */    MCD_OPC_Decode, 172, 2, 10, // Opcode: ANDCCri
/* 1058 */    MCD_OPC_FilterValue, 18, 28, 0, 0, // Skip to: 1091
/* 1063 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1066 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1082
/* 1071 */    MCD_OPC_CheckField, 5, 8, 0, 105, 25, 0, // Skip to: 7583
/* 1078 */    MCD_OPC_Decode, 213, 4, 9, // Opcode: ORCCrr
/* 1082 */    MCD_OPC_FilterValue, 1, 96, 25, 0, // Skip to: 7583
/* 1087 */    MCD_OPC_Decode, 212, 4, 10, // Opcode: ORCCri
/* 1091 */    MCD_OPC_FilterValue, 19, 28, 0, 0, // Skip to: 1124
/* 1096 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1099 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1115
/* 1104 */    MCD_OPC_CheckField, 5, 8, 0, 72, 25, 0, // Skip to: 7583
/* 1111 */    MCD_OPC_Decode, 140, 6, 9, // Opcode: XORCCrr
/* 1115 */    MCD_OPC_FilterValue, 1, 63, 25, 0, // Skip to: 7583
/* 1120 */    MCD_OPC_Decode, 139, 6, 10, // Opcode: XORCCri
/* 1124 */    MCD_OPC_FilterValue, 20, 28, 0, 0, // Skip to: 1157
/* 1129 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1132 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1148
/* 1137 */    MCD_OPC_CheckField, 5, 8, 0, 39, 25, 0, // Skip to: 7583
/* 1144 */    MCD_OPC_Decode, 192, 5, 9, // Opcode: SUBCCrr
/* 1148 */    MCD_OPC_FilterValue, 1, 30, 25, 0, // Skip to: 7583
/* 1153 */    MCD_OPC_Decode, 191, 5, 10, // Opcode: SUBCCri
/* 1157 */    MCD_OPC_FilterValue, 21, 28, 0, 0, // Skip to: 1190
/* 1162 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1165 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1181
/* 1170 */    MCD_OPC_CheckField, 5, 8, 0, 6, 25, 0, // Skip to: 7583
/* 1177 */    MCD_OPC_Decode, 175, 2, 9, // Opcode: ANDNCCrr
/* 1181 */    MCD_OPC_FilterValue, 1, 253, 24, 0, // Skip to: 7583
/* 1186 */    MCD_OPC_Decode, 174, 2, 10, // Opcode: ANDNCCri
/* 1190 */    MCD_OPC_FilterValue, 22, 28, 0, 0, // Skip to: 1223
/* 1195 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1198 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1214
/* 1203 */    MCD_OPC_CheckField, 5, 8, 0, 229, 24, 0, // Skip to: 7583
/* 1210 */    MCD_OPC_Decode, 215, 4, 9, // Opcode: ORNCCrr
/* 1214 */    MCD_OPC_FilterValue, 1, 220, 24, 0, // Skip to: 7583
/* 1219 */    MCD_OPC_Decode, 214, 4, 10, // Opcode: ORNCCri
/* 1223 */    MCD_OPC_FilterValue, 23, 28, 0, 0, // Skip to: 1256
/* 1228 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1231 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1247
/* 1236 */    MCD_OPC_CheckField, 5, 8, 0, 196, 24, 0, // Skip to: 7583
/* 1243 */    MCD_OPC_Decode, 136, 6, 9, // Opcode: XNORCCrr
/* 1247 */    MCD_OPC_FilterValue, 1, 187, 24, 0, // Skip to: 7583
/* 1252 */    MCD_OPC_Decode, 135, 6, 10, // Opcode: XNORCCri
/* 1256 */    MCD_OPC_FilterValue, 24, 28, 0, 0, // Skip to: 1289
/* 1261 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1264 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1280
/* 1269 */    MCD_OPC_CheckField, 5, 8, 0, 163, 24, 0, // Skip to: 7583
/* 1276 */    MCD_OPC_Decode, 165, 2, 9, // Opcode: ADDErr
/* 1280 */    MCD_OPC_FilterValue, 1, 154, 24, 0, // Skip to: 7583
/* 1285 */    MCD_OPC_Decode, 164, 2, 10, // Opcode: ADDEri
/* 1289 */    MCD_OPC_FilterValue, 26, 28, 0, 0, // Skip to: 1322
/* 1294 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1297 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1313
/* 1302 */    MCD_OPC_CheckField, 5, 8, 0, 130, 24, 0, // Skip to: 7583
/* 1309 */    MCD_OPC_Decode, 235, 5, 9, // Opcode: UMULCCrr
/* 1313 */    MCD_OPC_FilterValue, 1, 121, 24, 0, // Skip to: 7583
/* 1318 */    MCD_OPC_Decode, 234, 5, 10, // Opcode: UMULCCri
/* 1322 */    MCD_OPC_FilterValue, 27, 28, 0, 0, // Skip to: 1355
/* 1327 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1330 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1346
/* 1335 */    MCD_OPC_CheckField, 5, 8, 0, 97, 24, 0, // Skip to: 7583
/* 1342 */    MCD_OPC_Decode, 133, 5, 9, // Opcode: SMULCCrr
/* 1346 */    MCD_OPC_FilterValue, 1, 88, 24, 0, // Skip to: 7583
/* 1351 */    MCD_OPC_Decode, 132, 5, 10, // Opcode: SMULCCri
/* 1355 */    MCD_OPC_FilterValue, 28, 28, 0, 0, // Skip to: 1388
/* 1360 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1363 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1379
/* 1368 */    MCD_OPC_CheckField, 5, 8, 0, 64, 24, 0, // Skip to: 7583
/* 1375 */    MCD_OPC_Decode, 196, 5, 9, // Opcode: SUBErr
/* 1379 */    MCD_OPC_FilterValue, 1, 55, 24, 0, // Skip to: 7583
/* 1384 */    MCD_OPC_Decode, 195, 5, 10, // Opcode: SUBEri
/* 1388 */    MCD_OPC_FilterValue, 30, 28, 0, 0, // Skip to: 1421
/* 1393 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1396 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1412
/* 1401 */    MCD_OPC_CheckField, 5, 8, 0, 31, 24, 0, // Skip to: 7583
/* 1408 */    MCD_OPC_Decode, 227, 5, 9, // Opcode: UDIVCCrr
/* 1412 */    MCD_OPC_FilterValue, 1, 22, 24, 0, // Skip to: 7583
/* 1417 */    MCD_OPC_Decode, 226, 5, 10, // Opcode: UDIVCCri
/* 1421 */    MCD_OPC_FilterValue, 31, 28, 0, 0, // Skip to: 1454
/* 1426 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1429 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1445
/* 1434 */    MCD_OPC_CheckField, 5, 8, 0, 254, 23, 0, // Skip to: 7583
/* 1441 */    MCD_OPC_Decode, 245, 4, 9, // Opcode: SDIVCCrr
/* 1445 */    MCD_OPC_FilterValue, 1, 245, 23, 0, // Skip to: 7583
/* 1450 */    MCD_OPC_Decode, 244, 4, 10, // Opcode: SDIVCCri
/* 1454 */    MCD_OPC_FilterValue, 32, 28, 0, 0, // Skip to: 1487
/* 1459 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1462 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1478
/* 1467 */    MCD_OPC_CheckField, 5, 8, 0, 221, 23, 0, // Skip to: 7583
/* 1474 */    MCD_OPC_Decode, 209, 5, 9, // Opcode: TADDCCrr
/* 1478 */    MCD_OPC_FilterValue, 1, 212, 23, 0, // Skip to: 7583
/* 1483 */    MCD_OPC_Decode, 208, 5, 10, // Opcode: TADDCCri
/* 1487 */    MCD_OPC_FilterValue, 33, 28, 0, 0, // Skip to: 1520
/* 1492 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1495 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1511
/* 1500 */    MCD_OPC_CheckField, 5, 8, 0, 188, 23, 0, // Skip to: 7583
/* 1507 */    MCD_OPC_Decode, 223, 5, 9, // Opcode: TSUBCCrr
/* 1511 */    MCD_OPC_FilterValue, 1, 179, 23, 0, // Skip to: 7583
/* 1516 */    MCD_OPC_Decode, 222, 5, 10, // Opcode: TSUBCCri
/* 1520 */    MCD_OPC_FilterValue, 34, 28, 0, 0, // Skip to: 1553
/* 1525 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1528 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1544
/* 1533 */    MCD_OPC_CheckField, 5, 8, 0, 155, 23, 0, // Skip to: 7583
/* 1540 */    MCD_OPC_Decode, 207, 5, 9, // Opcode: TADDCCTVrr
/* 1544 */    MCD_OPC_FilterValue, 1, 146, 23, 0, // Skip to: 7583
/* 1549 */    MCD_OPC_Decode, 206, 5, 10, // Opcode: TADDCCTVri
/* 1553 */    MCD_OPC_FilterValue, 35, 28, 0, 0, // Skip to: 1586
/* 1558 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1561 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1577
/* 1566 */    MCD_OPC_CheckField, 5, 8, 0, 122, 23, 0, // Skip to: 7583
/* 1573 */    MCD_OPC_Decode, 221, 5, 9, // Opcode: TSUBCCTVrr
/* 1577 */    MCD_OPC_FilterValue, 1, 113, 23, 0, // Skip to: 7583
/* 1582 */    MCD_OPC_Decode, 220, 5, 10, // Opcode: TSUBCCTVri
/* 1586 */    MCD_OPC_FilterValue, 36, 28, 0, 0, // Skip to: 1619
/* 1591 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1594 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1610
/* 1599 */    MCD_OPC_CheckField, 5, 8, 0, 89, 23, 0, // Skip to: 7583
/* 1606 */    MCD_OPC_Decode, 208, 4, 9, // Opcode: MULSCCrr
/* 1610 */    MCD_OPC_FilterValue, 1, 80, 23, 0, // Skip to: 7583
/* 1615 */    MCD_OPC_Decode, 207, 4, 10, // Opcode: MULSCCri
/* 1619 */    MCD_OPC_FilterValue, 37, 39, 0, 0, // Skip to: 1663
/* 1624 */    MCD_OPC_ExtractField, 12, 2,  // Inst{13-12} ...
/* 1627 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1636
/* 1632 */    MCD_OPC_Decode, 129, 5, 9, // Opcode: SLLrr
/* 1636 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1645
/* 1641 */    MCD_OPC_Decode, 255, 4, 13, // Opcode: SLLXrr
/* 1645 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1654
/* 1650 */    MCD_OPC_Decode, 128, 5, 14, // Opcode: SLLri
/* 1654 */    MCD_OPC_FilterValue, 3, 36, 23, 0, // Skip to: 7583
/* 1659 */    MCD_OPC_Decode, 254, 4, 15, // Opcode: SLLXri
/* 1663 */    MCD_OPC_FilterValue, 38, 39, 0, 0, // Skip to: 1707
/* 1668 */    MCD_OPC_ExtractField, 12, 2,  // Inst{13-12} ...
/* 1671 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1680
/* 1676 */    MCD_OPC_Decode, 143, 5, 9, // Opcode: SRLrr
/* 1680 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1689
/* 1685 */    MCD_OPC_Decode, 141, 5, 13, // Opcode: SRLXrr
/* 1689 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1698
/* 1694 */    MCD_OPC_Decode, 142, 5, 14, // Opcode: SRLri
/* 1698 */    MCD_OPC_FilterValue, 3, 248, 22, 0, // Skip to: 7583
/* 1703 */    MCD_OPC_Decode, 140, 5, 15, // Opcode: SRLXri
/* 1707 */    MCD_OPC_FilterValue, 39, 39, 0, 0, // Skip to: 1751
/* 1712 */    MCD_OPC_ExtractField, 12, 2,  // Inst{13-12} ...
/* 1715 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1724
/* 1720 */    MCD_OPC_Decode, 139, 5, 9, // Opcode: SRArr
/* 1724 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1733
/* 1729 */    MCD_OPC_Decode, 137, 5, 13, // Opcode: SRAXrr
/* 1733 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1742
/* 1738 */    MCD_OPC_Decode, 138, 5, 14, // Opcode: SRAri
/* 1742 */    MCD_OPC_FilterValue, 3, 204, 22, 0, // Skip to: 7583
/* 1747 */    MCD_OPC_Decode, 136, 5, 15, // Opcode: SRAXri
/* 1751 */    MCD_OPC_FilterValue, 40, 66, 0, 0, // Skip to: 1822
/* 1756 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1759 */    MCD_OPC_FilterValue, 0, 30, 0, 0, // Skip to: 1794
/* 1764 */    MCD_OPC_ExtractField, 0, 13,  // Inst{12-0} ...
/* 1767 */    MCD_OPC_FilterValue, 0, 179, 22, 0, // Skip to: 7583
/* 1772 */    MCD_OPC_CheckField, 25, 5, 0, 11, 0, 0, // Skip to: 1790
/* 1779 */    MCD_OPC_CheckField, 14, 5, 15, 4, 0, 0, // Skip to: 1790
/* 1786 */    MCD_OPC_Decode, 146, 5, 5, // Opcode: STBAR
/* 1790 */    MCD_OPC_Decode, 227, 4, 16, // Opcode: RDASR
/* 1794 */    MCD_OPC_FilterValue, 1, 152, 22, 0, // Skip to: 7583
/* 1799 */    MCD_OPC_CheckPredicate, 0, 147, 22, 0, // Skip to: 7583
/* 1804 */    MCD_OPC_CheckField, 25, 5, 0, 140, 22, 0, // Skip to: 7583
/* 1811 */    MCD_OPC_CheckField, 14, 5, 15, 133, 22, 0, // Skip to: 7583
/* 1818 */    MCD_OPC_Decode, 193, 4, 17, // Opcode: MEMBARi
/* 1822 */    MCD_OPC_FilterValue, 41, 11, 0, 0, // Skip to: 1838
/* 1827 */    MCD_OPC_CheckField, 0, 19, 0, 117, 22, 0, // Skip to: 7583
/* 1834 */    MCD_OPC_Decode, 230, 4, 18, // Opcode: RDPSR
/* 1838 */    MCD_OPC_FilterValue, 42, 43, 0, 0, // Skip to: 1886
/* 1843 */    MCD_OPC_ExtractField, 0, 14,  // Inst{13-0} ...
/* 1846 */    MCD_OPC_FilterValue, 0, 100, 22, 0, // Skip to: 7583
/* 1851 */    MCD_OPC_ExtractField, 14, 5,  // Inst{18-14} ...
/* 1854 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1863
/* 1859 */    MCD_OPC_Decode, 232, 4, 18, // Opcode: RDWIM
/* 1863 */    MCD_OPC_FilterValue, 15, 9, 0, 0, // Skip to: 1877
/* 1868 */    MCD_OPC_CheckPredicate, 0, 4, 0, 0, // Skip to: 1877
/* 1873 */    MCD_OPC_Decode, 228, 4, 18, // Opcode: RDFQ
/* 1877 */    MCD_OPC_CheckPredicate, 0, 69, 22, 0, // Skip to: 7583
/* 1882 */    MCD_OPC_Decode, 229, 4, 19, // Opcode: RDPR
/* 1886 */    MCD_OPC_FilterValue, 43, 28, 0, 0, // Skip to: 1919
/* 1891 */    MCD_OPC_ExtractField, 0, 19,  // Inst{18-0} ...
/* 1894 */    MCD_OPC_FilterValue, 0, 52, 22, 0, // Skip to: 7583
/* 1899 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 1915
/* 1904 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 1915
/* 1911 */    MCD_OPC_Decode, 154, 3, 5, // Opcode: FLUSHW
/* 1915 */    MCD_OPC_Decode, 231, 4, 18, // Opcode: RDTBR
/* 1919 */    MCD_OPC_FilterValue, 44, 141, 0, 0, // Skip to: 2065
/* 1924 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1927 */    MCD_OPC_FilterValue, 0, 64, 0, 0, // Skip to: 1996
/* 1932 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 1935 */    MCD_OPC_FilterValue, 0, 25, 0, 0, // Skip to: 1965
/* 1940 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 1956
/* 1945 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 1956
/* 1952 */    MCD_OPC_Decode, 196, 4, 20, // Opcode: MOVFCCrr
/* 1956 */    MCD_OPC_CheckPredicate, 0, 246, 21, 0, // Skip to: 7583
/* 1961 */    MCD_OPC_Decode, 250, 5, 21, // Opcode: V9MOVFCCrr
/* 1965 */    MCD_OPC_FilterValue, 1, 237, 21, 0, // Skip to: 7583
/* 1970 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 1973 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 1987
/* 1978 */    MCD_OPC_CheckPredicate, 0, 224, 21, 0, // Skip to: 7583
/* 1983 */    MCD_OPC_Decode, 198, 4, 20, // Opcode: MOVICCrr
/* 1987 */    MCD_OPC_FilterValue, 2, 215, 21, 0, // Skip to: 7583
/* 1992 */    MCD_OPC_Decode, 205, 4, 20, // Opcode: MOVXCCrr
/* 1996 */    MCD_OPC_FilterValue, 1, 206, 21, 0, // Skip to: 7583
/* 2001 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 2004 */    MCD_OPC_FilterValue, 0, 25, 0, 0, // Skip to: 2034
/* 2009 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 2025
/* 2014 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 2025
/* 2021 */    MCD_OPC_Decode, 195, 4, 22, // Opcode: MOVFCCri
/* 2025 */    MCD_OPC_CheckPredicate, 0, 177, 21, 0, // Skip to: 7583
/* 2030 */    MCD_OPC_Decode, 249, 5, 23, // Opcode: V9MOVFCCri
/* 2034 */    MCD_OPC_FilterValue, 1, 168, 21, 0, // Skip to: 7583
/* 2039 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 2042 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 2056
/* 2047 */    MCD_OPC_CheckPredicate, 0, 155, 21, 0, // Skip to: 7583
/* 2052 */    MCD_OPC_Decode, 197, 4, 22, // Opcode: MOVICCri
/* 2056 */    MCD_OPC_FilterValue, 2, 146, 21, 0, // Skip to: 7583
/* 2061 */    MCD_OPC_Decode, 204, 4, 22, // Opcode: MOVXCCri
/* 2065 */    MCD_OPC_FilterValue, 45, 28, 0, 0, // Skip to: 2098
/* 2070 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2073 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2089
/* 2078 */    MCD_OPC_CheckField, 5, 8, 0, 122, 21, 0, // Skip to: 7583
/* 2085 */    MCD_OPC_Decode, 247, 4, 11, // Opcode: SDIVXrr
/* 2089 */    MCD_OPC_FilterValue, 1, 113, 21, 0, // Skip to: 7583
/* 2094 */    MCD_OPC_Decode, 246, 4, 12, // Opcode: SDIVXri
/* 2098 */    MCD_OPC_FilterValue, 46, 16, 0, 0, // Skip to: 2119
/* 2103 */    MCD_OPC_CheckPredicate, 0, 99, 21, 0, // Skip to: 7583
/* 2108 */    MCD_OPC_CheckField, 5, 14, 0, 92, 21, 0, // Skip to: 7583
/* 2115 */    MCD_OPC_Decode, 222, 4, 24, // Opcode: POPCrr
/* 2119 */    MCD_OPC_FilterValue, 47, 28, 0, 0, // Skip to: 2152
/* 2124 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2127 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2143
/* 2132 */    MCD_OPC_CheckField, 5, 5, 0, 68, 21, 0, // Skip to: 7583
/* 2139 */    MCD_OPC_Decode, 200, 4, 25, // Opcode: MOVRrr
/* 2143 */    MCD_OPC_FilterValue, 1, 59, 21, 0, // Skip to: 7583
/* 2148 */    MCD_OPC_Decode, 199, 4, 26, // Opcode: MOVRri
/* 2152 */    MCD_OPC_FilterValue, 48, 51, 0, 0, // Skip to: 2208
/* 2157 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2160 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2176
/* 2165 */    MCD_OPC_CheckField, 5, 8, 0, 35, 21, 0, // Skip to: 7583
/* 2172 */    MCD_OPC_Decode, 252, 5, 27, // Opcode: WRASRrr
/* 2176 */    MCD_OPC_FilterValue, 1, 26, 21, 0, // Skip to: 7583
/* 2181 */    MCD_OPC_CheckPredicate, 0, 18, 0, 0, // Skip to: 2204
/* 2186 */    MCD_OPC_CheckField, 25, 5, 15, 11, 0, 0, // Skip to: 2204
/* 2193 */    MCD_OPC_CheckField, 14, 5, 0, 4, 0, 0, // Skip to: 2204
/* 2200 */    MCD_OPC_Decode, 253, 4, 28, // Opcode: SIR
/* 2204 */    MCD_OPC_Decode, 251, 5, 29, // Opcode: WRASRri
/* 2208 */    MCD_OPC_FilterValue, 49, 127, 0, 0, // Skip to: 2340
/* 2213 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2216 */    MCD_OPC_FilterValue, 0, 88, 0, 0, // Skip to: 2309
/* 2221 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 2224 */    MCD_OPC_FilterValue, 0, 35, 0, 0, // Skip to: 2264
/* 2229 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 2232 */    MCD_OPC_FilterValue, 0, 226, 20, 0, // Skip to: 7583
/* 2237 */    MCD_OPC_CheckPredicate, 0, 18, 0, 0, // Skip to: 2260
/* 2242 */    MCD_OPC_CheckField, 14, 5, 0, 11, 0, 0, // Skip to: 2260
/* 2249 */    MCD_OPC_CheckField, 0, 5, 0, 4, 0, 0, // Skip to: 2260
/* 2256 */    MCD_OPC_Decode, 241, 4, 5, // Opcode: SAVED
/* 2260 */    MCD_OPC_Decode, 128, 6, 30, // Opcode: WRPSRrr
/* 2264 */    MCD_OPC_FilterValue, 1, 194, 20, 0, // Skip to: 7583
/* 2269 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 2272 */    MCD_OPC_FilterValue, 0, 186, 20, 0, // Skip to: 7583
/* 2277 */    MCD_OPC_CheckPredicate, 0, 18, 0, 0, // Skip to: 2300
/* 2282 */    MCD_OPC_CheckField, 14, 5, 0, 11, 0, 0, // Skip to: 2300
/* 2289 */    MCD_OPC_CheckField, 0, 5, 0, 4, 0, 0, // Skip to: 2300
/* 2296 */    MCD_OPC_Decode, 233, 4, 5, // Opcode: RESTORED
/* 2300 */    MCD_OPC_CheckPredicate, 1, 158, 20, 0, // Skip to: 7583
/* 2305 */    MCD_OPC_Decode, 226, 4, 30, // Opcode: PWRPSRrr
/* 2309 */    MCD_OPC_FilterValue, 1, 149, 20, 0, // Skip to: 7583
/* 2314 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 2317 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2326
/* 2322 */    MCD_OPC_Decode, 255, 5, 31, // Opcode: WRPSRri
/* 2326 */    MCD_OPC_FilterValue, 1, 132, 20, 0, // Skip to: 7583
/* 2331 */    MCD_OPC_CheckPredicate, 1, 127, 20, 0, // Skip to: 7583
/* 2336 */    MCD_OPC_Decode, 225, 4, 31, // Opcode: PWRPSRri
/* 2340 */    MCD_OPC_FilterValue, 50, 61, 0, 0, // Skip to: 2406
/* 2345 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2348 */    MCD_OPC_FilterValue, 0, 28, 0, 0, // Skip to: 2381
/* 2353 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 2356 */    MCD_OPC_FilterValue, 0, 102, 20, 0, // Skip to: 7583
/* 2361 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 2372
/* 2368 */    MCD_OPC_Decode, 132, 6, 30, // Opcode: WRWIMrr
/* 2372 */    MCD_OPC_CheckPredicate, 0, 86, 20, 0, // Skip to: 7583
/* 2377 */    MCD_OPC_Decode, 254, 5, 32, // Opcode: WRPRrr
/* 2381 */    MCD_OPC_FilterValue, 1, 77, 20, 0, // Skip to: 7583
/* 2386 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 2397
/* 2393 */    MCD_OPC_Decode, 131, 6, 31, // Opcode: WRWIMri
/* 2397 */    MCD_OPC_CheckPredicate, 0, 61, 20, 0, // Skip to: 7583
/* 2402 */    MCD_OPC_Decode, 253, 5, 33, // Opcode: WRPRri
/* 2406 */    MCD_OPC_FilterValue, 51, 42, 0, 0, // Skip to: 2453
/* 2411 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2414 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 2437
/* 2419 */    MCD_OPC_CheckField, 25, 5, 0, 37, 20, 0, // Skip to: 7583
/* 2426 */    MCD_OPC_CheckField, 5, 8, 0, 30, 20, 0, // Skip to: 7583
/* 2433 */    MCD_OPC_Decode, 130, 6, 30, // Opcode: WRTBRrr
/* 2437 */    MCD_OPC_FilterValue, 1, 21, 20, 0, // Skip to: 7583
/* 2442 */    MCD_OPC_CheckField, 25, 5, 0, 14, 20, 0, // Skip to: 7583
/* 2449 */    MCD_OPC_Decode, 129, 6, 31, // Opcode: WRTBRri
/* 2453 */    MCD_OPC_FilterValue, 52, 43, 3, 0, // Skip to: 3269
/* 2458 */    MCD_OPC_ExtractField, 5, 9,  // Inst{13-5} ...
/* 2461 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 2477
/* 2466 */    MCD_OPC_CheckField, 14, 5, 0, 246, 19, 0, // Skip to: 7583
/* 2473 */    MCD_OPC_Decode, 169, 3, 34, // Opcode: FMOVS
/* 2477 */    MCD_OPC_FilterValue, 2, 16, 0, 0, // Skip to: 2498
/* 2482 */    MCD_OPC_CheckPredicate, 0, 232, 19, 0, // Skip to: 7583
/* 2487 */    MCD_OPC_CheckField, 14, 5, 0, 225, 19, 0, // Skip to: 7583
/* 2494 */    MCD_OPC_Decode, 158, 3, 35, // Opcode: FMOVD
/* 2498 */    MCD_OPC_FilterValue, 3, 16, 0, 0, // Skip to: 2519
/* 2503 */    MCD_OPC_CheckPredicate, 0, 211, 19, 0, // Skip to: 7583
/* 2508 */    MCD_OPC_CheckField, 14, 5, 0, 204, 19, 0, // Skip to: 7583
/* 2515 */    MCD_OPC_Decode, 162, 3, 36, // Opcode: FMOVQ
/* 2519 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 2535
/* 2524 */    MCD_OPC_CheckField, 14, 5, 0, 188, 19, 0, // Skip to: 7583
/* 2531 */    MCD_OPC_Decode, 189, 3, 34, // Opcode: FNEGS
/* 2535 */    MCD_OPC_FilterValue, 6, 16, 0, 0, // Skip to: 2556
/* 2540 */    MCD_OPC_CheckPredicate, 0, 174, 19, 0, // Skip to: 7583
/* 2545 */    MCD_OPC_CheckField, 14, 5, 0, 167, 19, 0, // Skip to: 7583
/* 2552 */    MCD_OPC_Decode, 187, 3, 35, // Opcode: FNEGD
/* 2556 */    MCD_OPC_FilterValue, 7, 16, 0, 0, // Skip to: 2577
/* 2561 */    MCD_OPC_CheckPredicate, 0, 153, 19, 0, // Skip to: 7583
/* 2566 */    MCD_OPC_CheckField, 14, 5, 0, 146, 19, 0, // Skip to: 7583
/* 2573 */    MCD_OPC_Decode, 188, 3, 36, // Opcode: FNEGQ
/* 2577 */    MCD_OPC_FilterValue, 9, 11, 0, 0, // Skip to: 2593
/* 2582 */    MCD_OPC_CheckField, 14, 5, 0, 130, 19, 0, // Skip to: 7583
/* 2589 */    MCD_OPC_Decode, 233, 2, 34, // Opcode: FABSS
/* 2593 */    MCD_OPC_FilterValue, 10, 16, 0, 0, // Skip to: 2614
/* 2598 */    MCD_OPC_CheckPredicate, 0, 116, 19, 0, // Skip to: 7583
/* 2603 */    MCD_OPC_CheckField, 14, 5, 0, 109, 19, 0, // Skip to: 7583
/* 2610 */    MCD_OPC_Decode, 231, 2, 35, // Opcode: FABSD
/* 2614 */    MCD_OPC_FilterValue, 11, 16, 0, 0, // Skip to: 2635
/* 2619 */    MCD_OPC_CheckPredicate, 0, 95, 19, 0, // Skip to: 7583
/* 2624 */    MCD_OPC_CheckField, 14, 5, 0, 88, 19, 0, // Skip to: 7583
/* 2631 */    MCD_OPC_Decode, 232, 2, 36, // Opcode: FABSQ
/* 2635 */    MCD_OPC_FilterValue, 41, 11, 0, 0, // Skip to: 2651
/* 2640 */    MCD_OPC_CheckField, 14, 5, 0, 72, 19, 0, // Skip to: 7583
/* 2647 */    MCD_OPC_Decode, 233, 3, 34, // Opcode: FSQRTS
/* 2651 */    MCD_OPC_FilterValue, 42, 11, 0, 0, // Skip to: 2667
/* 2656 */    MCD_OPC_CheckField, 14, 5, 0, 56, 19, 0, // Skip to: 7583
/* 2663 */    MCD_OPC_Decode, 231, 3, 35, // Opcode: FSQRTD
/* 2667 */    MCD_OPC_FilterValue, 43, 11, 0, 0, // Skip to: 2683
/* 2672 */    MCD_OPC_CheckField, 14, 5, 0, 40, 19, 0, // Skip to: 7583
/* 2679 */    MCD_OPC_Decode, 232, 3, 36, // Opcode: FSQRTQ
/* 2683 */    MCD_OPC_FilterValue, 65, 4, 0, 0, // Skip to: 2692
/* 2688 */    MCD_OPC_Decode, 236, 2, 37, // Opcode: FADDS
/* 2692 */    MCD_OPC_FilterValue, 66, 4, 0, 0, // Skip to: 2701
/* 2697 */    MCD_OPC_Decode, 234, 2, 38, // Opcode: FADDD
/* 2701 */    MCD_OPC_FilterValue, 67, 4, 0, 0, // Skip to: 2710
/* 2706 */    MCD_OPC_Decode, 235, 2, 39, // Opcode: FADDQ
/* 2710 */    MCD_OPC_FilterValue, 69, 4, 0, 0, // Skip to: 2719
/* 2715 */    MCD_OPC_Decode, 248, 3, 37, // Opcode: FSUBS
/* 2719 */    MCD_OPC_FilterValue, 70, 4, 0, 0, // Skip to: 2728
/* 2724 */    MCD_OPC_Decode, 246, 3, 38, // Opcode: FSUBD
/* 2728 */    MCD_OPC_FilterValue, 71, 4, 0, 0, // Skip to: 2737
/* 2733 */    MCD_OPC_Decode, 247, 3, 39, // Opcode: FSUBQ
/* 2737 */    MCD_OPC_FilterValue, 73, 4, 0, 0, // Skip to: 2746
/* 2742 */    MCD_OPC_Decode, 182, 3, 37, // Opcode: FMULS
/* 2746 */    MCD_OPC_FilterValue, 74, 4, 0, 0, // Skip to: 2755
/* 2751 */    MCD_OPC_Decode, 178, 3, 38, // Opcode: FMULD
/* 2755 */    MCD_OPC_FilterValue, 75, 4, 0, 0, // Skip to: 2764
/* 2760 */    MCD_OPC_Decode, 181, 3, 39, // Opcode: FMULQ
/* 2764 */    MCD_OPC_FilterValue, 77, 4, 0, 0, // Skip to: 2773
/* 2769 */    MCD_OPC_Decode, 137, 3, 37, // Opcode: FDIVS
/* 2773 */    MCD_OPC_FilterValue, 78, 4, 0, 0, // Skip to: 2782
/* 2778 */    MCD_OPC_Decode, 135, 3, 38, // Opcode: FDIVD
/* 2782 */    MCD_OPC_FilterValue, 79, 4, 0, 0, // Skip to: 2791
/* 2787 */    MCD_OPC_Decode, 136, 3, 39, // Opcode: FDIVQ
/* 2791 */    MCD_OPC_FilterValue, 81, 9, 0, 0, // Skip to: 2805
/* 2796 */    MCD_OPC_CheckPredicate, 2, 174, 18, 0, // Skip to: 7583
/* 2801 */    MCD_OPC_Decode, 184, 3, 38, // Opcode: FNADDS
/* 2805 */    MCD_OPC_FilterValue, 82, 9, 0, 0, // Skip to: 2819
/* 2810 */    MCD_OPC_CheckPredicate, 2, 160, 18, 0, // Skip to: 7583
/* 2815 */    MCD_OPC_Decode, 183, 3, 38, // Opcode: FNADDD
/* 2819 */    MCD_OPC_FilterValue, 89, 9, 0, 0, // Skip to: 2833
/* 2824 */    MCD_OPC_CheckPredicate, 2, 146, 18, 0, // Skip to: 7583
/* 2829 */    MCD_OPC_Decode, 193, 3, 38, // Opcode: FNMULS
/* 2833 */    MCD_OPC_FilterValue, 90, 9, 0, 0, // Skip to: 2847
/* 2838 */    MCD_OPC_CheckPredicate, 2, 132, 18, 0, // Skip to: 7583
/* 2843 */    MCD_OPC_Decode, 192, 3, 38, // Opcode: FNMULD
/* 2847 */    MCD_OPC_FilterValue, 97, 9, 0, 0, // Skip to: 2861
/* 2852 */    MCD_OPC_CheckPredicate, 2, 118, 18, 0, // Skip to: 7583
/* 2857 */    MCD_OPC_Decode, 145, 3, 38, // Opcode: FHADDS
/* 2861 */    MCD_OPC_FilterValue, 98, 9, 0, 0, // Skip to: 2875
/* 2866 */    MCD_OPC_CheckPredicate, 2, 104, 18, 0, // Skip to: 7583
/* 2871 */    MCD_OPC_Decode, 144, 3, 38, // Opcode: FHADDD
/* 2875 */    MCD_OPC_FilterValue, 101, 9, 0, 0, // Skip to: 2889
/* 2880 */    MCD_OPC_CheckPredicate, 2, 90, 18, 0, // Skip to: 7583
/* 2885 */    MCD_OPC_Decode, 147, 3, 38, // Opcode: FHSUBS
/* 2889 */    MCD_OPC_FilterValue, 102, 9, 0, 0, // Skip to: 2903
/* 2894 */    MCD_OPC_CheckPredicate, 2, 76, 18, 0, // Skip to: 7583
/* 2899 */    MCD_OPC_Decode, 146, 3, 38, // Opcode: FHSUBD
/* 2903 */    MCD_OPC_FilterValue, 105, 4, 0, 0, // Skip to: 2912
/* 2908 */    MCD_OPC_Decode, 230, 3, 40, // Opcode: FSMULD
/* 2912 */    MCD_OPC_FilterValue, 110, 4, 0, 0, // Skip to: 2921
/* 2917 */    MCD_OPC_Decode, 138, 3, 41, // Opcode: FDMULQ
/* 2921 */    MCD_OPC_FilterValue, 113, 9, 0, 0, // Skip to: 2935
/* 2926 */    MCD_OPC_CheckPredicate, 2, 44, 18, 0, // Skip to: 7583
/* 2931 */    MCD_OPC_Decode, 191, 3, 38, // Opcode: FNHADDS
/* 2935 */    MCD_OPC_FilterValue, 114, 9, 0, 0, // Skip to: 2949
/* 2940 */    MCD_OPC_CheckPredicate, 2, 30, 18, 0, // Skip to: 7583
/* 2945 */    MCD_OPC_Decode, 190, 3, 38, // Opcode: FNHADDD
/* 2949 */    MCD_OPC_FilterValue, 121, 9, 0, 0, // Skip to: 2963
/* 2954 */    MCD_OPC_CheckPredicate, 2, 16, 18, 0, // Skip to: 7583
/* 2959 */    MCD_OPC_Decode, 200, 3, 38, // Opcode: FNSMULD
/* 2963 */    MCD_OPC_FilterValue, 129, 1, 11, 0, 0, // Skip to: 2980
/* 2969 */    MCD_OPC_CheckField, 14, 5, 0, 255, 17, 0, // Skip to: 7583
/* 2976 */    MCD_OPC_Decode, 245, 3, 42, // Opcode: FSTOX
/* 2980 */    MCD_OPC_FilterValue, 130, 1, 11, 0, 0, // Skip to: 2997
/* 2986 */    MCD_OPC_CheckField, 14, 5, 0, 238, 17, 0, // Skip to: 7583
/* 2993 */    MCD_OPC_Decode, 142, 3, 35, // Opcode: FDTOX
/* 2997 */    MCD_OPC_FilterValue, 131, 1, 11, 0, 0, // Skip to: 3014
/* 3003 */    MCD_OPC_CheckField, 14, 5, 0, 221, 17, 0, // Skip to: 7583
/* 3010 */    MCD_OPC_Decode, 225, 3, 43, // Opcode: FQTOX
/* 3014 */    MCD_OPC_FilterValue, 132, 1, 11, 0, 0, // Skip to: 3031
/* 3020 */    MCD_OPC_CheckField, 14, 5, 0, 204, 17, 0, // Skip to: 7583
/* 3027 */    MCD_OPC_Decode, 255, 3, 44, // Opcode: FXTOS
/* 3031 */    MCD_OPC_FilterValue, 136, 1, 11, 0, 0, // Skip to: 3048
/* 3037 */    MCD_OPC_CheckField, 14, 5, 0, 187, 17, 0, // Skip to: 7583
/* 3044 */    MCD_OPC_Decode, 253, 3, 35, // Opcode: FXTOD
/* 3048 */    MCD_OPC_FilterValue, 140, 1, 11, 0, 0, // Skip to: 3065
/* 3054 */    MCD_OPC_CheckField, 14, 5, 0, 170, 17, 0, // Skip to: 7583
/* 3061 */    MCD_OPC_Decode, 254, 3, 45, // Opcode: FXTOQ
/* 3065 */    MCD_OPC_FilterValue, 196, 1, 11, 0, 0, // Skip to: 3082
/* 3071 */    MCD_OPC_CheckField, 14, 5, 0, 153, 17, 0, // Skip to: 7583
/* 3078 */    MCD_OPC_Decode, 150, 3, 34, // Opcode: FITOS
/* 3082 */    MCD_OPC_FilterValue, 198, 1, 11, 0, 0, // Skip to: 3099
/* 3088 */    MCD_OPC_CheckField, 14, 5, 0, 136, 17, 0, // Skip to: 7583
/* 3095 */    MCD_OPC_Decode, 141, 3, 44, // Opcode: FDTOS
/* 3099 */    MCD_OPC_FilterValue, 199, 1, 11, 0, 0, // Skip to: 3116
/* 3105 */    MCD_OPC_CheckField, 14, 5, 0, 119, 17, 0, // Skip to: 7583
/* 3112 */    MCD_OPC_Decode, 224, 3, 46, // Opcode: FQTOS
/* 3116 */    MCD_OPC_FilterValue, 200, 1, 11, 0, 0, // Skip to: 3133
/* 3122 */    MCD_OPC_CheckField, 14, 5, 0, 102, 17, 0, // Skip to: 7583
/* 3129 */    MCD_OPC_Decode, 148, 3, 42, // Opcode: FITOD
/* 3133 */    MCD_OPC_FilterValue, 201, 1, 11, 0, 0, // Skip to: 3150
/* 3139 */    MCD_OPC_CheckField, 14, 5, 0, 85, 17, 0, // Skip to: 7583
/* 3146 */    MCD_OPC_Decode, 242, 3, 42, // Opcode: FSTOD
/* 3150 */    MCD_OPC_FilterValue, 203, 1, 11, 0, 0, // Skip to: 3167
/* 3156 */    MCD_OPC_CheckField, 14, 5, 0, 68, 17, 0, // Skip to: 7583
/* 3163 */    MCD_OPC_Decode, 222, 3, 43, // Opcode: FQTOD
/* 3167 */    MCD_OPC_FilterValue, 204, 1, 11, 0, 0, // Skip to: 3184
/* 3173 */    MCD_OPC_CheckField, 14, 5, 0, 51, 17, 0, // Skip to: 7583
/* 3180 */    MCD_OPC_Decode, 149, 3, 47, // Opcode: FITOQ
/* 3184 */    MCD_OPC_FilterValue, 205, 1, 11, 0, 0, // Skip to: 3201
/* 3190 */    MCD_OPC_CheckField, 14, 5, 0, 34, 17, 0, // Skip to: 7583
/* 3197 */    MCD_OPC_Decode, 244, 3, 47, // Opcode: FSTOQ
/* 3201 */    MCD_OPC_FilterValue, 206, 1, 11, 0, 0, // Skip to: 3218
/* 3207 */    MCD_OPC_CheckField, 14, 5, 0, 17, 17, 0, // Skip to: 7583
/* 3214 */    MCD_OPC_Decode, 140, 3, 45, // Opcode: FDTOQ
/* 3218 */    MCD_OPC_FilterValue, 209, 1, 11, 0, 0, // Skip to: 3235
/* 3224 */    MCD_OPC_CheckField, 14, 5, 0, 0, 17, 0, // Skip to: 7583
/* 3231 */    MCD_OPC_Decode, 243, 3, 34, // Opcode: FSTOI
/* 3235 */    MCD_OPC_FilterValue, 210, 1, 11, 0, 0, // Skip to: 3252
/* 3241 */    MCD_OPC_CheckField, 14, 5, 0, 239, 16, 0, // Skip to: 7583
/* 3248 */    MCD_OPC_Decode, 139, 3, 44, // Opcode: FDTOI
/* 3252 */    MCD_OPC_FilterValue, 211, 1, 229, 16, 0, // Skip to: 7583
/* 3258 */    MCD_OPC_CheckField, 14, 5, 0, 222, 16, 0, // Skip to: 7583
/* 3265 */    MCD_OPC_Decode, 223, 3, 46, // Opcode: FQTOI
/* 3269 */    MCD_OPC_FilterValue, 53, 188, 1, 0, // Skip to: 3718
/* 3274 */    MCD_OPC_ExtractField, 5, 5,  // Inst{9-5} ...
/* 3277 */    MCD_OPC_FilterValue, 1, 94, 0, 0, // Skip to: 3376
/* 3282 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 3285 */    MCD_OPC_FilterValue, 0, 41, 0, 0, // Skip to: 3331
/* 3290 */    MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 3293 */    MCD_OPC_FilterValue, 0, 189, 16, 0, // Skip to: 7583
/* 3298 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 3301 */    MCD_OPC_FilterValue, 0, 181, 16, 0, // Skip to: 7583
/* 3306 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 3322
/* 3311 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 3322
/* 3318 */    MCD_OPC_Decode, 170, 3, 48, // Opcode: FMOVS_FCC
/* 3322 */    MCD_OPC_CheckPredicate, 0, 160, 16, 0, // Skip to: 7583
/* 3327 */    MCD_OPC_Decode, 248, 5, 49, // Opcode: V9FMOVS_FCC
/* 3331 */    MCD_OPC_FilterValue, 1, 151, 16, 0, // Skip to: 7583
/* 3336 */    MCD_OPC_ExtractField, 10, 3,  // Inst{12-10} ...
/* 3339 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 3360
/* 3344 */    MCD_OPC_CheckPredicate, 0, 138, 16, 0, // Skip to: 7583
/* 3349 */    MCD_OPC_CheckField, 18, 1, 0, 131, 16, 0, // Skip to: 7583
/* 3356 */    MCD_OPC_Decode, 171, 3, 48, // Opcode: FMOVS_ICC
/* 3360 */    MCD_OPC_FilterValue, 4, 122, 16, 0, // Skip to: 7583
/* 3365 */    MCD_OPC_CheckField, 18, 1, 0, 115, 16, 0, // Skip to: 7583
/* 3372 */    MCD_OPC_Decode, 172, 3, 48, // Opcode: FMOVS_XCC
/* 3376 */    MCD_OPC_FilterValue, 2, 94, 0, 0, // Skip to: 3475
/* 3381 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 3384 */    MCD_OPC_FilterValue, 0, 41, 0, 0, // Skip to: 3430
/* 3389 */    MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 3392 */    MCD_OPC_FilterValue, 0, 90, 16, 0, // Skip to: 7583
/* 3397 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 3400 */    MCD_OPC_FilterValue, 0, 82, 16, 0, // Skip to: 7583
/* 3405 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 3421
/* 3410 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 3421
/* 3417 */    MCD_OPC_Decode, 159, 3, 50, // Opcode: FMOVD_FCC
/* 3421 */    MCD_OPC_CheckPredicate, 0, 61, 16, 0, // Skip to: 7583
/* 3426 */    MCD_OPC_Decode, 246, 5, 51, // Opcode: V9FMOVD_FCC
/* 3430 */    MCD_OPC_FilterValue, 1, 52, 16, 0, // Skip to: 7583
/* 3435 */    MCD_OPC_ExtractField, 10, 3,  // Inst{12-10} ...
/* 3438 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 3459
/* 3443 */    MCD_OPC_CheckPredicate, 0, 39, 16, 0, // Skip to: 7583
/* 3448 */    MCD_OPC_CheckField, 18, 1, 0, 32, 16, 0, // Skip to: 7583
/* 3455 */    MCD_OPC_Decode, 160, 3, 50, // Opcode: FMOVD_ICC
/* 3459 */    MCD_OPC_FilterValue, 4, 23, 16, 0, // Skip to: 7583
/* 3464 */    MCD_OPC_CheckField, 18, 1, 0, 16, 16, 0, // Skip to: 7583
/* 3471 */    MCD_OPC_Decode, 161, 3, 50, // Opcode: FMOVD_XCC
/* 3475 */    MCD_OPC_FilterValue, 3, 94, 0, 0, // Skip to: 3574
/* 3480 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 3483 */    MCD_OPC_FilterValue, 0, 41, 0, 0, // Skip to: 3529
/* 3488 */    MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 3491 */    MCD_OPC_FilterValue, 0, 247, 15, 0, // Skip to: 7583
/* 3496 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 3499 */    MCD_OPC_FilterValue, 0, 239, 15, 0, // Skip to: 7583
/* 3504 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 3520
/* 3509 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 3520
/* 3516 */    MCD_OPC_Decode, 163, 3, 52, // Opcode: FMOVQ_FCC
/* 3520 */    MCD_OPC_CheckPredicate, 0, 218, 15, 0, // Skip to: 7583
/* 3525 */    MCD_OPC_Decode, 247, 5, 53, // Opcode: V9FMOVQ_FCC
/* 3529 */    MCD_OPC_FilterValue, 1, 209, 15, 0, // Skip to: 7583
/* 3534 */    MCD_OPC_ExtractField, 10, 3,  // Inst{12-10} ...
/* 3537 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 3558
/* 3542 */    MCD_OPC_CheckPredicate, 0, 196, 15, 0, // Skip to: 7583
/* 3547 */    MCD_OPC_CheckField, 18, 1, 0, 189, 15, 0, // Skip to: 7583
/* 3554 */    MCD_OPC_Decode, 164, 3, 52, // Opcode: FMOVQ_ICC
/* 3558 */    MCD_OPC_FilterValue, 4, 180, 15, 0, // Skip to: 7583
/* 3563 */    MCD_OPC_CheckField, 18, 1, 0, 173, 15, 0, // Skip to: 7583
/* 3570 */    MCD_OPC_Decode, 165, 3, 52, // Opcode: FMOVQ_XCC
/* 3574 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 3590
/* 3579 */    MCD_OPC_CheckField, 13, 1, 0, 157, 15, 0, // Skip to: 7583
/* 3586 */    MCD_OPC_Decode, 168, 3, 54, // Opcode: FMOVRS
/* 3590 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 3606
/* 3595 */    MCD_OPC_CheckField, 13, 1, 0, 141, 15, 0, // Skip to: 7583
/* 3602 */    MCD_OPC_Decode, 166, 3, 55, // Opcode: FMOVRD
/* 3606 */    MCD_OPC_FilterValue, 7, 11, 0, 0, // Skip to: 3622
/* 3611 */    MCD_OPC_CheckField, 13, 1, 0, 125, 15, 0, // Skip to: 7583
/* 3618 */    MCD_OPC_Decode, 167, 3, 56, // Opcode: FMOVRQ
/* 3622 */    MCD_OPC_FilterValue, 17, 11, 0, 0, // Skip to: 3638
/* 3627 */    MCD_OPC_CheckField, 10, 4, 2, 109, 15, 0, // Skip to: 7583
/* 3634 */    MCD_OPC_Decode, 245, 5, 57, // Opcode: V9FCMPS
/* 3638 */    MCD_OPC_FilterValue, 18, 11, 0, 0, // Skip to: 3654
/* 3643 */    MCD_OPC_CheckField, 10, 4, 2, 93, 15, 0, // Skip to: 7583
/* 3650 */    MCD_OPC_Decode, 240, 5, 58, // Opcode: V9FCMPD
/* 3654 */    MCD_OPC_FilterValue, 19, 11, 0, 0, // Skip to: 3670
/* 3659 */    MCD_OPC_CheckField, 10, 4, 2, 77, 15, 0, // Skip to: 7583
/* 3666 */    MCD_OPC_Decode, 244, 5, 59, // Opcode: V9FCMPQ
/* 3670 */    MCD_OPC_FilterValue, 21, 11, 0, 0, // Skip to: 3686
/* 3675 */    MCD_OPC_CheckField, 10, 4, 2, 61, 15, 0, // Skip to: 7583
/* 3682 */    MCD_OPC_Decode, 243, 5, 57, // Opcode: V9FCMPES
/* 3686 */    MCD_OPC_FilterValue, 22, 11, 0, 0, // Skip to: 3702
/* 3691 */    MCD_OPC_CheckField, 10, 4, 2, 45, 15, 0, // Skip to: 7583
/* 3698 */    MCD_OPC_Decode, 241, 5, 58, // Opcode: V9FCMPED
/* 3702 */    MCD_OPC_FilterValue, 23, 36, 15, 0, // Skip to: 7583
/* 3707 */    MCD_OPC_CheckField, 10, 4, 2, 29, 15, 0, // Skip to: 7583
/* 3714 */    MCD_OPC_Decode, 242, 5, 59, // Opcode: V9FCMPEQ
/* 3718 */    MCD_OPC_FilterValue, 54, 35, 7, 0, // Skip to: 5550
/* 3723 */    MCD_OPC_ExtractField, 5, 9,  // Inst{13-5} ...
/* 3726 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 3740
/* 3731 */    MCD_OPC_CheckPredicate, 3, 7, 15, 0, // Skip to: 7583
/* 3736 */    MCD_OPC_Decode, 227, 2, 11, // Opcode: EDGE8
/* 3740 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 3754
/* 3745 */    MCD_OPC_CheckPredicate, 4, 249, 14, 0, // Skip to: 7583
/* 3750 */    MCD_OPC_Decode, 230, 2, 11, // Opcode: EDGE8N
/* 3754 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 3768
/* 3759 */    MCD_OPC_CheckPredicate, 3, 235, 14, 0, // Skip to: 7583
/* 3764 */    MCD_OPC_Decode, 228, 2, 11, // Opcode: EDGE8L
/* 3768 */    MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 3782
/* 3773 */    MCD_OPC_CheckPredicate, 4, 221, 14, 0, // Skip to: 7583
/* 3778 */    MCD_OPC_Decode, 229, 2, 11, // Opcode: EDGE8LN
/* 3782 */    MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 3796
/* 3787 */    MCD_OPC_CheckPredicate, 3, 207, 14, 0, // Skip to: 7583
/* 3792 */    MCD_OPC_Decode, 219, 2, 11, // Opcode: EDGE16
/* 3796 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 3810
/* 3801 */    MCD_OPC_CheckPredicate, 4, 193, 14, 0, // Skip to: 7583
/* 3806 */    MCD_OPC_Decode, 222, 2, 11, // Opcode: EDGE16N
/* 3810 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 3824
/* 3815 */    MCD_OPC_CheckPredicate, 3, 179, 14, 0, // Skip to: 7583
/* 3820 */    MCD_OPC_Decode, 220, 2, 11, // Opcode: EDGE16L
/* 3824 */    MCD_OPC_FilterValue, 7, 9, 0, 0, // Skip to: 3838
/* 3829 */    MCD_OPC_CheckPredicate, 4, 165, 14, 0, // Skip to: 7583
/* 3834 */    MCD_OPC_Decode, 221, 2, 11, // Opcode: EDGE16LN
/* 3838 */    MCD_OPC_FilterValue, 8, 9, 0, 0, // Skip to: 3852
/* 3843 */    MCD_OPC_CheckPredicate, 3, 151, 14, 0, // Skip to: 7583
/* 3848 */    MCD_OPC_Decode, 223, 2, 11, // Opcode: EDGE32
/* 3852 */    MCD_OPC_FilterValue, 9, 9, 0, 0, // Skip to: 3866
/* 3857 */    MCD_OPC_CheckPredicate, 4, 137, 14, 0, // Skip to: 7583
/* 3862 */    MCD_OPC_Decode, 226, 2, 11, // Opcode: EDGE32N
/* 3866 */    MCD_OPC_FilterValue, 10, 9, 0, 0, // Skip to: 3880
/* 3871 */    MCD_OPC_CheckPredicate, 3, 123, 14, 0, // Skip to: 7583
/* 3876 */    MCD_OPC_Decode, 224, 2, 11, // Opcode: EDGE32L
/* 3880 */    MCD_OPC_FilterValue, 11, 9, 0, 0, // Skip to: 3894
/* 3885 */    MCD_OPC_CheckPredicate, 4, 109, 14, 0, // Skip to: 7583
/* 3890 */    MCD_OPC_Decode, 225, 2, 11, // Opcode: EDGE32LN
/* 3894 */    MCD_OPC_FilterValue, 16, 9, 0, 0, // Skip to: 3908
/* 3899 */    MCD_OPC_CheckPredicate, 3, 95, 14, 0, // Skip to: 7583
/* 3904 */    MCD_OPC_Decode, 182, 2, 11, // Opcode: ARRAY8
/* 3908 */    MCD_OPC_FilterValue, 17, 9, 0, 0, // Skip to: 3922
/* 3913 */    MCD_OPC_CheckPredicate, 2, 81, 14, 0, // Skip to: 7583
/* 3918 */    MCD_OPC_Decode, 166, 2, 11, // Opcode: ADDXC
/* 3922 */    MCD_OPC_FilterValue, 18, 9, 0, 0, // Skip to: 3936
/* 3927 */    MCD_OPC_CheckPredicate, 3, 67, 14, 0, // Skip to: 7583
/* 3932 */    MCD_OPC_Decode, 180, 2, 11, // Opcode: ARRAY16
/* 3936 */    MCD_OPC_FilterValue, 19, 9, 0, 0, // Skip to: 3950
/* 3941 */    MCD_OPC_CheckPredicate, 2, 53, 14, 0, // Skip to: 7583
/* 3946 */    MCD_OPC_Decode, 167, 2, 11, // Opcode: ADDXCCC
/* 3950 */    MCD_OPC_FilterValue, 20, 9, 0, 0, // Skip to: 3964
/* 3955 */    MCD_OPC_CheckPredicate, 3, 39, 14, 0, // Skip to: 7583
/* 3960 */    MCD_OPC_Decode, 181, 2, 11, // Opcode: ARRAY32
/* 3964 */    MCD_OPC_FilterValue, 22, 9, 0, 0, // Skip to: 3978
/* 3969 */    MCD_OPC_CheckPredicate, 2, 25, 14, 0, // Skip to: 7583
/* 3974 */    MCD_OPC_Decode, 236, 5, 11, // Opcode: UMULXHI
/* 3978 */    MCD_OPC_FilterValue, 23, 16, 0, 0, // Skip to: 3999
/* 3983 */    MCD_OPC_CheckPredicate, 2, 11, 14, 0, // Skip to: 7583
/* 3988 */    MCD_OPC_CheckField, 14, 5, 0, 4, 14, 0, // Skip to: 7583
/* 3995 */    MCD_OPC_Decode, 192, 4, 60, // Opcode: LZCNT
/* 3999 */    MCD_OPC_FilterValue, 24, 9, 0, 0, // Skip to: 4013
/* 4004 */    MCD_OPC_CheckPredicate, 3, 246, 13, 0, // Skip to: 7583
/* 4009 */    MCD_OPC_Decode, 170, 2, 11, // Opcode: ALIGNADDR
/* 4013 */    MCD_OPC_FilterValue, 25, 9, 0, 0, // Skip to: 4027
/* 4018 */    MCD_OPC_CheckPredicate, 4, 232, 13, 0, // Skip to: 7583
/* 4023 */    MCD_OPC_Decode, 188, 2, 11, // Opcode: BMASK
/* 4027 */    MCD_OPC_FilterValue, 26, 9, 0, 0, // Skip to: 4041
/* 4032 */    MCD_OPC_CheckPredicate, 3, 218, 13, 0, // Skip to: 7583
/* 4037 */    MCD_OPC_Decode, 171, 2, 11, // Opcode: ALIGNADDRL
/* 4041 */    MCD_OPC_FilterValue, 27, 23, 0, 0, // Skip to: 4069
/* 4046 */    MCD_OPC_CheckPredicate, 2, 204, 13, 0, // Skip to: 7583
/* 4051 */    MCD_OPC_CheckField, 25, 5, 0, 197, 13, 0, // Skip to: 7583
/* 4058 */    MCD_OPC_CheckField, 14, 5, 0, 190, 13, 0, // Skip to: 7583
/* 4065 */    MCD_OPC_Decode, 217, 2, 61, // Opcode: CMASK8
/* 4069 */    MCD_OPC_FilterValue, 28, 9, 0, 0, // Skip to: 4083
/* 4074 */    MCD_OPC_CheckPredicate, 4, 176, 13, 0, // Skip to: 7583
/* 4079 */    MCD_OPC_Decode, 205, 2, 38, // Opcode: BSHUFFLE
/* 4083 */    MCD_OPC_FilterValue, 29, 23, 0, 0, // Skip to: 4111
/* 4088 */    MCD_OPC_CheckPredicate, 2, 162, 13, 0, // Skip to: 7583
/* 4093 */    MCD_OPC_CheckField, 25, 5, 0, 155, 13, 0, // Skip to: 7583
/* 4100 */    MCD_OPC_CheckField, 14, 5, 0, 148, 13, 0, // Skip to: 7583
/* 4107 */    MCD_OPC_Decode, 215, 2, 61, // Opcode: CMASK16
/* 4111 */    MCD_OPC_FilterValue, 31, 23, 0, 0, // Skip to: 4139
/* 4116 */    MCD_OPC_CheckPredicate, 2, 134, 13, 0, // Skip to: 7583
/* 4121 */    MCD_OPC_CheckField, 25, 5, 0, 127, 13, 0, // Skip to: 7583
/* 4128 */    MCD_OPC_CheckField, 14, 5, 0, 120, 13, 0, // Skip to: 7583
/* 4135 */    MCD_OPC_Decode, 216, 2, 61, // Opcode: CMASK32
/* 4139 */    MCD_OPC_FilterValue, 32, 9, 0, 0, // Skip to: 4153
/* 4144 */    MCD_OPC_CheckPredicate, 3, 106, 13, 0, // Skip to: 7583
/* 4149 */    MCD_OPC_Decode, 255, 2, 62, // Opcode: FCMPLE16
/* 4153 */    MCD_OPC_FilterValue, 33, 9, 0, 0, // Skip to: 4167
/* 4158 */    MCD_OPC_CheckPredicate, 2, 92, 13, 0, // Skip to: 7583
/* 4163 */    MCD_OPC_Decode, 228, 3, 38, // Opcode: FSLL16
/* 4167 */    MCD_OPC_FilterValue, 34, 9, 0, 0, // Skip to: 4181
/* 4172 */    MCD_OPC_CheckPredicate, 3, 78, 13, 0, // Skip to: 7583
/* 4177 */    MCD_OPC_Decode, 129, 3, 62, // Opcode: FCMPNE16
/* 4181 */    MCD_OPC_FilterValue, 35, 9, 0, 0, // Skip to: 4195
/* 4186 */    MCD_OPC_CheckPredicate, 2, 64, 13, 0, // Skip to: 7583
/* 4191 */    MCD_OPC_Decode, 240, 3, 38, // Opcode: FSRL16
/* 4195 */    MCD_OPC_FilterValue, 36, 9, 0, 0, // Skip to: 4209
/* 4200 */    MCD_OPC_CheckPredicate, 3, 50, 13, 0, // Skip to: 7583
/* 4205 */    MCD_OPC_Decode, 128, 3, 62, // Opcode: FCMPLE32
/* 4209 */    MCD_OPC_FilterValue, 37, 9, 0, 0, // Skip to: 4223
/* 4214 */    MCD_OPC_CheckPredicate, 2, 36, 13, 0, // Skip to: 7583
/* 4219 */    MCD_OPC_Decode, 229, 3, 38, // Opcode: FSLL32
/* 4223 */    MCD_OPC_FilterValue, 38, 9, 0, 0, // Skip to: 4237
/* 4228 */    MCD_OPC_CheckPredicate, 3, 22, 13, 0, // Skip to: 7583
/* 4233 */    MCD_OPC_Decode, 130, 3, 62, // Opcode: FCMPNE32
/* 4237 */    MCD_OPC_FilterValue, 39, 9, 0, 0, // Skip to: 4251
/* 4242 */    MCD_OPC_CheckPredicate, 2, 8, 13, 0, // Skip to: 7583
/* 4247 */    MCD_OPC_Decode, 241, 3, 38, // Opcode: FSRL32
/* 4251 */    MCD_OPC_FilterValue, 40, 9, 0, 0, // Skip to: 4265
/* 4256 */    MCD_OPC_CheckPredicate, 3, 250, 12, 0, // Skip to: 7583
/* 4261 */    MCD_OPC_Decode, 253, 2, 62, // Opcode: FCMPGT16
/* 4265 */    MCD_OPC_FilterValue, 41, 9, 0, 0, // Skip to: 4279
/* 4270 */    MCD_OPC_CheckPredicate, 2, 236, 12, 0, // Skip to: 7583
/* 4275 */    MCD_OPC_Decode, 226, 3, 38, // Opcode: FSLAS16
/* 4279 */    MCD_OPC_FilterValue, 42, 9, 0, 0, // Skip to: 4293
/* 4284 */    MCD_OPC_CheckPredicate, 3, 222, 12, 0, // Skip to: 7583
/* 4289 */    MCD_OPC_Decode, 251, 2, 62, // Opcode: FCMPEQ16
/* 4293 */    MCD_OPC_FilterValue, 43, 9, 0, 0, // Skip to: 4307
/* 4298 */    MCD_OPC_CheckPredicate, 2, 208, 12, 0, // Skip to: 7583
/* 4303 */    MCD_OPC_Decode, 234, 3, 38, // Opcode: FSRA16
/* 4307 */    MCD_OPC_FilterValue, 44, 9, 0, 0, // Skip to: 4321
/* 4312 */    MCD_OPC_CheckPredicate, 3, 194, 12, 0, // Skip to: 7583
/* 4317 */    MCD_OPC_Decode, 254, 2, 62, // Opcode: FCMPGT32
/* 4321 */    MCD_OPC_FilterValue, 45, 9, 0, 0, // Skip to: 4335
/* 4326 */    MCD_OPC_CheckPredicate, 2, 180, 12, 0, // Skip to: 7583
/* 4331 */    MCD_OPC_Decode, 227, 3, 38, // Opcode: FSLAS32
/* 4335 */    MCD_OPC_FilterValue, 46, 9, 0, 0, // Skip to: 4349
/* 4340 */    MCD_OPC_CheckPredicate, 3, 166, 12, 0, // Skip to: 7583
/* 4345 */    MCD_OPC_Decode, 252, 2, 62, // Opcode: FCMPEQ32
/* 4349 */    MCD_OPC_FilterValue, 47, 9, 0, 0, // Skip to: 4363
/* 4354 */    MCD_OPC_CheckPredicate, 2, 152, 12, 0, // Skip to: 7583
/* 4359 */    MCD_OPC_Decode, 235, 3, 38, // Opcode: FSRA32
/* 4363 */    MCD_OPC_FilterValue, 49, 9, 0, 0, // Skip to: 4377
/* 4368 */    MCD_OPC_CheckPredicate, 3, 138, 12, 0, // Skip to: 7583
/* 4373 */    MCD_OPC_Decode, 175, 3, 38, // Opcode: FMUL8X16
/* 4377 */    MCD_OPC_FilterValue, 51, 9, 0, 0, // Skip to: 4391
/* 4382 */    MCD_OPC_CheckPredicate, 3, 124, 12, 0, // Skip to: 7583
/* 4387 */    MCD_OPC_Decode, 177, 3, 38, // Opcode: FMUL8X16AU
/* 4391 */    MCD_OPC_FilterValue, 53, 9, 0, 0, // Skip to: 4405
/* 4396 */    MCD_OPC_CheckPredicate, 3, 110, 12, 0, // Skip to: 7583
/* 4401 */    MCD_OPC_Decode, 176, 3, 38, // Opcode: FMUL8X16AL
/* 4405 */    MCD_OPC_FilterValue, 54, 9, 0, 0, // Skip to: 4419
/* 4410 */    MCD_OPC_CheckPredicate, 3, 96, 12, 0, // Skip to: 7583
/* 4415 */    MCD_OPC_Decode, 173, 3, 38, // Opcode: FMUL8SUX16
/* 4419 */    MCD_OPC_FilterValue, 55, 9, 0, 0, // Skip to: 4433
/* 4424 */    MCD_OPC_CheckPredicate, 3, 82, 12, 0, // Skip to: 7583
/* 4429 */    MCD_OPC_Decode, 174, 3, 38, // Opcode: FMUL8ULX16
/* 4433 */    MCD_OPC_FilterValue, 56, 9, 0, 0, // Skip to: 4447
/* 4438 */    MCD_OPC_CheckPredicate, 3, 68, 12, 0, // Skip to: 7583
/* 4443 */    MCD_OPC_Decode, 179, 3, 38, // Opcode: FMULD8SUX16
/* 4447 */    MCD_OPC_FilterValue, 57, 9, 0, 0, // Skip to: 4461
/* 4452 */    MCD_OPC_CheckPredicate, 3, 54, 12, 0, // Skip to: 7583
/* 4457 */    MCD_OPC_Decode, 180, 3, 38, // Opcode: FMULD8ULX16
/* 4461 */    MCD_OPC_FilterValue, 58, 9, 0, 0, // Skip to: 4475
/* 4466 */    MCD_OPC_CheckPredicate, 3, 40, 12, 0, // Skip to: 7583
/* 4471 */    MCD_OPC_Decode, 210, 3, 38, // Opcode: FPACK32
/* 4475 */    MCD_OPC_FilterValue, 59, 16, 0, 0, // Skip to: 4496
/* 4480 */    MCD_OPC_CheckPredicate, 3, 26, 12, 0, // Skip to: 7583
/* 4485 */    MCD_OPC_CheckField, 14, 5, 0, 19, 12, 0, // Skip to: 7583
/* 4492 */    MCD_OPC_Decode, 209, 3, 35, // Opcode: FPACK16
/* 4496 */    MCD_OPC_FilterValue, 61, 16, 0, 0, // Skip to: 4517
/* 4501 */    MCD_OPC_CheckPredicate, 3, 5, 12, 0, // Skip to: 7583
/* 4506 */    MCD_OPC_CheckField, 14, 5, 0, 254, 11, 0, // Skip to: 7583
/* 4513 */    MCD_OPC_Decode, 211, 3, 35, // Opcode: FPACKFIX
/* 4517 */    MCD_OPC_FilterValue, 62, 9, 0, 0, // Skip to: 4531
/* 4522 */    MCD_OPC_CheckPredicate, 3, 240, 11, 0, // Skip to: 7583
/* 4527 */    MCD_OPC_Decode, 220, 4, 38, // Opcode: PDIST
/* 4531 */    MCD_OPC_FilterValue, 63, 9, 0, 0, // Skip to: 4545
/* 4536 */    MCD_OPC_CheckPredicate, 2, 226, 11, 0, // Skip to: 7583
/* 4541 */    MCD_OPC_Decode, 221, 4, 38, // Opcode: PDISTN
/* 4545 */    MCD_OPC_FilterValue, 64, 9, 0, 0, // Skip to: 4559
/* 4550 */    MCD_OPC_CheckPredicate, 2, 212, 11, 0, // Skip to: 7583
/* 4555 */    MCD_OPC_Decode, 157, 3, 38, // Opcode: FMEAN16
/* 4559 */    MCD_OPC_FilterValue, 66, 9, 0, 0, // Skip to: 4573
/* 4564 */    MCD_OPC_CheckPredicate, 2, 198, 11, 0, // Skip to: 7583
/* 4569 */    MCD_OPC_Decode, 216, 3, 38, // Opcode: FPADD64
/* 4573 */    MCD_OPC_FilterValue, 68, 9, 0, 0, // Skip to: 4587
/* 4578 */    MCD_OPC_CheckPredicate, 2, 184, 11, 0, // Skip to: 7583
/* 4583 */    MCD_OPC_Decode, 248, 2, 38, // Opcode: FCHKSM16
/* 4587 */    MCD_OPC_FilterValue, 72, 9, 0, 0, // Skip to: 4601
/* 4592 */    MCD_OPC_CheckPredicate, 3, 170, 11, 0, // Skip to: 7583
/* 4597 */    MCD_OPC_Decode, 237, 2, 38, // Opcode: FALIGNADATA
/* 4601 */    MCD_OPC_FilterValue, 75, 9, 0, 0, // Skip to: 4615
/* 4606 */    MCD_OPC_CheckPredicate, 3, 156, 11, 0, // Skip to: 7583
/* 4611 */    MCD_OPC_Decode, 217, 3, 38, // Opcode: FPMERGE
/* 4615 */    MCD_OPC_FilterValue, 77, 16, 0, 0, // Skip to: 4636
/* 4620 */    MCD_OPC_CheckPredicate, 3, 142, 11, 0, // Skip to: 7583
/* 4625 */    MCD_OPC_CheckField, 14, 5, 0, 135, 11, 0, // Skip to: 7583
/* 4632 */    MCD_OPC_Decode, 143, 3, 35, // Opcode: FEXPAND
/* 4636 */    MCD_OPC_FilterValue, 80, 9, 0, 0, // Skip to: 4650
/* 4641 */    MCD_OPC_CheckPredicate, 3, 121, 11, 0, // Skip to: 7583
/* 4646 */    MCD_OPC_Decode, 212, 3, 38, // Opcode: FPADD16
/* 4650 */    MCD_OPC_FilterValue, 81, 9, 0, 0, // Skip to: 4664
/* 4655 */    MCD_OPC_CheckPredicate, 3, 107, 11, 0, // Skip to: 7583
/* 4660 */    MCD_OPC_Decode, 213, 3, 38, // Opcode: FPADD16S
/* 4664 */    MCD_OPC_FilterValue, 82, 9, 0, 0, // Skip to: 4678
/* 4669 */    MCD_OPC_CheckPredicate, 3, 93, 11, 0, // Skip to: 7583
/* 4674 */    MCD_OPC_Decode, 214, 3, 38, // Opcode: FPADD32
/* 4678 */    MCD_OPC_FilterValue, 83, 9, 0, 0, // Skip to: 4692
/* 4683 */    MCD_OPC_CheckPredicate, 3, 79, 11, 0, // Skip to: 7583
/* 4688 */    MCD_OPC_Decode, 215, 3, 38, // Opcode: FPADD32S
/* 4692 */    MCD_OPC_FilterValue, 84, 9, 0, 0, // Skip to: 4706
/* 4697 */    MCD_OPC_CheckPredicate, 3, 65, 11, 0, // Skip to: 7583
/* 4702 */    MCD_OPC_Decode, 218, 3, 38, // Opcode: FPSUB16
/* 4706 */    MCD_OPC_FilterValue, 85, 9, 0, 0, // Skip to: 4720
/* 4711 */    MCD_OPC_CheckPredicate, 3, 51, 11, 0, // Skip to: 7583
/* 4716 */    MCD_OPC_Decode, 219, 3, 38, // Opcode: FPSUB16S
/* 4720 */    MCD_OPC_FilterValue, 86, 9, 0, 0, // Skip to: 4734
/* 4725 */    MCD_OPC_CheckPredicate, 3, 37, 11, 0, // Skip to: 7583
/* 4730 */    MCD_OPC_Decode, 220, 3, 38, // Opcode: FPSUB32
/* 4734 */    MCD_OPC_FilterValue, 87, 9, 0, 0, // Skip to: 4748
/* 4739 */    MCD_OPC_CheckPredicate, 3, 23, 11, 0, // Skip to: 7583
/* 4744 */    MCD_OPC_Decode, 221, 3, 38, // Opcode: FPSUB32S
/* 4748 */    MCD_OPC_FilterValue, 96, 23, 0, 0, // Skip to: 4776
/* 4753 */    MCD_OPC_CheckPredicate, 3, 9, 11, 0, // Skip to: 7583
/* 4758 */    MCD_OPC_CheckField, 14, 5, 0, 2, 11, 0, // Skip to: 7583
/* 4765 */    MCD_OPC_CheckField, 0, 5, 0, 251, 10, 0, // Skip to: 7583
/* 4772 */    MCD_OPC_Decode, 128, 4, 63, // Opcode: FZERO
/* 4776 */    MCD_OPC_FilterValue, 97, 23, 0, 0, // Skip to: 4804
/* 4781 */    MCD_OPC_CheckPredicate, 3, 237, 10, 0, // Skip to: 7583
/* 4786 */    MCD_OPC_CheckField, 14, 5, 0, 230, 10, 0, // Skip to: 7583
/* 4793 */    MCD_OPC_CheckField, 0, 5, 0, 223, 10, 0, // Skip to: 7583
/* 4800 */    MCD_OPC_Decode, 129, 4, 64, // Opcode: FZEROS
/* 4804 */    MCD_OPC_FilterValue, 98, 9, 0, 0, // Skip to: 4818
/* 4809 */    MCD_OPC_CheckPredicate, 3, 209, 10, 0, // Skip to: 7583
/* 4814 */    MCD_OPC_Decode, 194, 3, 38, // Opcode: FNOR
/* 4818 */    MCD_OPC_FilterValue, 99, 9, 0, 0, // Skip to: 4832
/* 4823 */    MCD_OPC_CheckPredicate, 3, 195, 10, 0, // Skip to: 7583
/* 4828 */    MCD_OPC_Decode, 195, 3, 37, // Opcode: FNORS
/* 4832 */    MCD_OPC_FilterValue, 100, 9, 0, 0, // Skip to: 4846
/* 4837 */    MCD_OPC_CheckPredicate, 3, 181, 10, 0, // Skip to: 7583
/* 4842 */    MCD_OPC_Decode, 241, 2, 38, // Opcode: FANDNOT2
/* 4846 */    MCD_OPC_FilterValue, 101, 9, 0, 0, // Skip to: 4860
/* 4851 */    MCD_OPC_CheckPredicate, 3, 167, 10, 0, // Skip to: 7583
/* 4856 */    MCD_OPC_Decode, 242, 2, 37, // Opcode: FANDNOT2S
/* 4860 */    MCD_OPC_FilterValue, 102, 16, 0, 0, // Skip to: 4881
/* 4865 */    MCD_OPC_CheckPredicate, 3, 153, 10, 0, // Skip to: 7583
/* 4870 */    MCD_OPC_CheckField, 14, 5, 0, 146, 10, 0, // Skip to: 7583
/* 4877 */    MCD_OPC_Decode, 198, 3, 35, // Opcode: FNOT2
/* 4881 */    MCD_OPC_FilterValue, 103, 16, 0, 0, // Skip to: 4902
/* 4886 */    MCD_OPC_CheckPredicate, 3, 132, 10, 0, // Skip to: 7583
/* 4891 */    MCD_OPC_CheckField, 14, 5, 0, 125, 10, 0, // Skip to: 7583
/* 4898 */    MCD_OPC_Decode, 199, 3, 34, // Opcode: FNOT2S
/* 4902 */    MCD_OPC_FilterValue, 104, 9, 0, 0, // Skip to: 4916
/* 4907 */    MCD_OPC_CheckPredicate, 3, 111, 10, 0, // Skip to: 7583
/* 4912 */    MCD_OPC_Decode, 239, 2, 38, // Opcode: FANDNOT1
/* 4916 */    MCD_OPC_FilterValue, 105, 9, 0, 0, // Skip to: 4930
/* 4921 */    MCD_OPC_CheckPredicate, 3, 97, 10, 0, // Skip to: 7583
/* 4926 */    MCD_OPC_Decode, 240, 2, 37, // Opcode: FANDNOT1S
/* 4930 */    MCD_OPC_FilterValue, 106, 16, 0, 0, // Skip to: 4951
/* 4935 */    MCD_OPC_CheckPredicate, 3, 83, 10, 0, // Skip to: 7583
/* 4940 */    MCD_OPC_CheckField, 0, 5, 0, 76, 10, 0, // Skip to: 7583
/* 4947 */    MCD_OPC_Decode, 196, 3, 65, // Opcode: FNOT1
/* 4951 */    MCD_OPC_FilterValue, 107, 16, 0, 0, // Skip to: 4972
/* 4956 */    MCD_OPC_CheckPredicate, 3, 62, 10, 0, // Skip to: 7583
/* 4961 */    MCD_OPC_CheckField, 0, 5, 0, 55, 10, 0, // Skip to: 7583
/* 4968 */    MCD_OPC_Decode, 197, 3, 66, // Opcode: FNOT1S
/* 4972 */    MCD_OPC_FilterValue, 108, 9, 0, 0, // Skip to: 4986
/* 4977 */    MCD_OPC_CheckPredicate, 3, 41, 10, 0, // Skip to: 7583
/* 4982 */    MCD_OPC_Decode, 251, 3, 38, // Opcode: FXOR
/* 4986 */    MCD_OPC_FilterValue, 109, 9, 0, 0, // Skip to: 5000
/* 4991 */    MCD_OPC_CheckPredicate, 3, 27, 10, 0, // Skip to: 7583
/* 4996 */    MCD_OPC_Decode, 252, 3, 37, // Opcode: FXORS
/* 5000 */    MCD_OPC_FilterValue, 110, 9, 0, 0, // Skip to: 5014
/* 5005 */    MCD_OPC_CheckPredicate, 3, 13, 10, 0, // Skip to: 7583
/* 5010 */    MCD_OPC_Decode, 185, 3, 38, // Opcode: FNAND
/* 5014 */    MCD_OPC_FilterValue, 111, 9, 0, 0, // Skip to: 5028
/* 5019 */    MCD_OPC_CheckPredicate, 3, 255, 9, 0, // Skip to: 7583
/* 5024 */    MCD_OPC_Decode, 186, 3, 37, // Opcode: FNANDS
/* 5028 */    MCD_OPC_FilterValue, 112, 9, 0, 0, // Skip to: 5042
/* 5033 */    MCD_OPC_CheckPredicate, 3, 241, 9, 0, // Skip to: 7583
/* 5038 */    MCD_OPC_Decode, 238, 2, 38, // Opcode: FAND
/* 5042 */    MCD_OPC_FilterValue, 113, 9, 0, 0, // Skip to: 5056
/* 5047 */    MCD_OPC_CheckPredicate, 3, 227, 9, 0, // Skip to: 7583
/* 5052 */    MCD_OPC_Decode, 243, 2, 37, // Opcode: FANDS
/* 5056 */    MCD_OPC_FilterValue, 114, 9, 0, 0, // Skip to: 5070
/* 5061 */    MCD_OPC_CheckPredicate, 3, 213, 9, 0, // Skip to: 7583
/* 5066 */    MCD_OPC_Decode, 249, 3, 38, // Opcode: FXNOR
/* 5070 */    MCD_OPC_FilterValue, 115, 9, 0, 0, // Skip to: 5084
/* 5075 */    MCD_OPC_CheckPredicate, 3, 199, 9, 0, // Skip to: 7583
/* 5080 */    MCD_OPC_Decode, 250, 3, 37, // Opcode: FXNORS
/* 5084 */    MCD_OPC_FilterValue, 116, 16, 0, 0, // Skip to: 5105
/* 5089 */    MCD_OPC_CheckPredicate, 3, 185, 9, 0, // Skip to: 7583
/* 5094 */    MCD_OPC_CheckField, 0, 5, 0, 178, 9, 0, // Skip to: 7583
/* 5101 */    MCD_OPC_Decode, 236, 3, 65, // Opcode: FSRC1
/* 5105 */    MCD_OPC_FilterValue, 117, 16, 0, 0, // Skip to: 5126
/* 5110 */    MCD_OPC_CheckPredicate, 3, 164, 9, 0, // Skip to: 7583
/* 5115 */    MCD_OPC_CheckField, 0, 5, 0, 157, 9, 0, // Skip to: 7583
/* 5122 */    MCD_OPC_Decode, 237, 3, 66, // Opcode: FSRC1S
/* 5126 */    MCD_OPC_FilterValue, 118, 9, 0, 0, // Skip to: 5140
/* 5131 */    MCD_OPC_CheckPredicate, 3, 143, 9, 0, // Skip to: 7583
/* 5136 */    MCD_OPC_Decode, 206, 3, 38, // Opcode: FORNOT2
/* 5140 */    MCD_OPC_FilterValue, 119, 9, 0, 0, // Skip to: 5154
/* 5145 */    MCD_OPC_CheckPredicate, 3, 129, 9, 0, // Skip to: 7583
/* 5150 */    MCD_OPC_Decode, 207, 3, 37, // Opcode: FORNOT2S
/* 5154 */    MCD_OPC_FilterValue, 120, 16, 0, 0, // Skip to: 5175
/* 5159 */    MCD_OPC_CheckPredicate, 3, 115, 9, 0, // Skip to: 7583
/* 5164 */    MCD_OPC_CheckField, 14, 5, 0, 108, 9, 0, // Skip to: 7583
/* 5171 */    MCD_OPC_Decode, 238, 3, 35, // Opcode: FSRC2
/* 5175 */    MCD_OPC_FilterValue, 121, 16, 0, 0, // Skip to: 5196
/* 5180 */    MCD_OPC_CheckPredicate, 3, 94, 9, 0, // Skip to: 7583
/* 5185 */    MCD_OPC_CheckField, 14, 5, 0, 87, 9, 0, // Skip to: 7583
/* 5192 */    MCD_OPC_Decode, 239, 3, 34, // Opcode: FSRC2S
/* 5196 */    MCD_OPC_FilterValue, 122, 9, 0, 0, // Skip to: 5210
/* 5201 */    MCD_OPC_CheckPredicate, 3, 73, 9, 0, // Skip to: 7583
/* 5206 */    MCD_OPC_Decode, 204, 3, 38, // Opcode: FORNOT1
/* 5210 */    MCD_OPC_FilterValue, 123, 9, 0, 0, // Skip to: 5224
/* 5215 */    MCD_OPC_CheckPredicate, 3, 59, 9, 0, // Skip to: 7583
/* 5220 */    MCD_OPC_Decode, 205, 3, 37, // Opcode: FORNOT1S
/* 5224 */    MCD_OPC_FilterValue, 124, 9, 0, 0, // Skip to: 5238
/* 5229 */    MCD_OPC_CheckPredicate, 3, 45, 9, 0, // Skip to: 7583
/* 5234 */    MCD_OPC_Decode, 203, 3, 38, // Opcode: FOR
/* 5238 */    MCD_OPC_FilterValue, 125, 9, 0, 0, // Skip to: 5252
/* 5243 */    MCD_OPC_CheckPredicate, 3, 31, 9, 0, // Skip to: 7583
/* 5248 */    MCD_OPC_Decode, 208, 3, 37, // Opcode: FORS
/* 5252 */    MCD_OPC_FilterValue, 126, 23, 0, 0, // Skip to: 5280
/* 5257 */    MCD_OPC_CheckPredicate, 3, 17, 9, 0, // Skip to: 7583
/* 5262 */    MCD_OPC_CheckField, 14, 5, 0, 10, 9, 0, // Skip to: 7583
/* 5269 */    MCD_OPC_CheckField, 0, 5, 0, 3, 9, 0, // Skip to: 7583
/* 5276 */    MCD_OPC_Decode, 201, 3, 63, // Opcode: FONE
/* 5280 */    MCD_OPC_FilterValue, 127, 23, 0, 0, // Skip to: 5308
/* 5285 */    MCD_OPC_CheckPredicate, 3, 245, 8, 0, // Skip to: 7583
/* 5290 */    MCD_OPC_CheckField, 14, 5, 0, 238, 8, 0, // Skip to: 7583
/* 5297 */    MCD_OPC_CheckField, 0, 5, 0, 231, 8, 0, // Skip to: 7583
/* 5304 */    MCD_OPC_Decode, 202, 3, 64, // Opcode: FONES
/* 5308 */    MCD_OPC_FilterValue, 128, 1, 30, 0, 0, // Skip to: 5344
/* 5314 */    MCD_OPC_CheckPredicate, 3, 216, 8, 0, // Skip to: 7583
/* 5319 */    MCD_OPC_CheckField, 25, 5, 0, 209, 8, 0, // Skip to: 7583
/* 5326 */    MCD_OPC_CheckField, 14, 5, 0, 202, 8, 0, // Skip to: 7583
/* 5333 */    MCD_OPC_CheckField, 0, 5, 0, 195, 8, 0, // Skip to: 7583
/* 5340 */    MCD_OPC_Decode, 251, 4, 5, // Opcode: SHUTDOWN
/* 5344 */    MCD_OPC_FilterValue, 129, 1, 30, 0, 0, // Skip to: 5380
/* 5350 */    MCD_OPC_CheckPredicate, 4, 180, 8, 0, // Skip to: 7583
/* 5355 */    MCD_OPC_CheckField, 25, 5, 0, 173, 8, 0, // Skip to: 7583
/* 5362 */    MCD_OPC_CheckField, 14, 5, 0, 166, 8, 0, // Skip to: 7583
/* 5369 */    MCD_OPC_CheckField, 0, 5, 0, 159, 8, 0, // Skip to: 7583
/* 5376 */    MCD_OPC_Decode, 252, 4, 5, // Opcode: SIAM
/* 5380 */    MCD_OPC_FilterValue, 144, 2, 16, 0, 0, // Skip to: 5402
/* 5386 */    MCD_OPC_CheckPredicate, 2, 144, 8, 0, // Skip to: 7583
/* 5391 */    MCD_OPC_CheckField, 14, 5, 0, 137, 8, 0, // Skip to: 7583
/* 5398 */    MCD_OPC_Decode, 194, 4, 67, // Opcode: MOVDTOX
/* 5402 */    MCD_OPC_FilterValue, 145, 2, 16, 0, 0, // Skip to: 5424
/* 5408 */    MCD_OPC_CheckPredicate, 2, 122, 8, 0, // Skip to: 7583
/* 5413 */    MCD_OPC_CheckField, 14, 5, 0, 115, 8, 0, // Skip to: 7583
/* 5420 */    MCD_OPC_Decode, 202, 4, 67, // Opcode: MOVSTOUW
/* 5424 */    MCD_OPC_FilterValue, 147, 2, 16, 0, 0, // Skip to: 5446
/* 5430 */    MCD_OPC_CheckPredicate, 2, 100, 8, 0, // Skip to: 7583
/* 5435 */    MCD_OPC_CheckField, 14, 5, 0, 93, 8, 0, // Skip to: 7583
/* 5442 */    MCD_OPC_Decode, 201, 4, 67, // Opcode: MOVSTOSW
/* 5446 */    MCD_OPC_FilterValue, 149, 2, 9, 0, 0, // Skip to: 5461
/* 5452 */    MCD_OPC_CheckPredicate, 2, 78, 8, 0, // Skip to: 7583
/* 5457 */    MCD_OPC_Decode, 133, 6, 11, // Opcode: XMULX
/* 5461 */    MCD_OPC_FilterValue, 151, 2, 9, 0, 0, // Skip to: 5476
/* 5467 */    MCD_OPC_CheckPredicate, 2, 63, 8, 0, // Skip to: 7583
/* 5472 */    MCD_OPC_Decode, 134, 6, 11, // Opcode: XMULXHI
/* 5476 */    MCD_OPC_FilterValue, 152, 2, 16, 0, 0, // Skip to: 5498
/* 5482 */    MCD_OPC_CheckPredicate, 2, 48, 8, 0, // Skip to: 7583
/* 5487 */    MCD_OPC_CheckField, 14, 5, 0, 41, 8, 0, // Skip to: 7583
/* 5494 */    MCD_OPC_Decode, 206, 4, 68, // Opcode: MOVXTOD
/* 5498 */    MCD_OPC_FilterValue, 153, 2, 16, 0, 0, // Skip to: 5520
/* 5504 */    MCD_OPC_CheckPredicate, 2, 26, 8, 0, // Skip to: 7583
/* 5509 */    MCD_OPC_CheckField, 14, 5, 0, 19, 8, 0, // Skip to: 7583
/* 5516 */    MCD_OPC_Decode, 203, 4, 68, // Opcode: MOVWTOS
/* 5520 */    MCD_OPC_FilterValue, 209, 2, 9, 0, 0, // Skip to: 5535
/* 5526 */    MCD_OPC_CheckPredicate, 2, 4, 8, 0, // Skip to: 7583
/* 5531 */    MCD_OPC_Decode, 152, 3, 58, // Opcode: FLCMPS
/* 5535 */    MCD_OPC_FilterValue, 210, 2, 250, 7, 0, // Skip to: 7583
/* 5541 */    MCD_OPC_CheckPredicate, 2, 245, 7, 0, // Skip to: 7583
/* 5546 */    MCD_OPC_Decode, 151, 3, 58, // Opcode: FLCMPD
/* 5550 */    MCD_OPC_FilterValue, 56, 28, 0, 0, // Skip to: 5583
/* 5555 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5558 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 5574
/* 5563 */    MCD_OPC_CheckField, 5, 8, 0, 221, 7, 0, // Skip to: 7583
/* 5570 */    MCD_OPC_Decode, 133, 4, 69, // Opcode: JMPLrr
/* 5574 */    MCD_OPC_FilterValue, 1, 212, 7, 0, // Skip to: 7583
/* 5579 */    MCD_OPC_Decode, 132, 4, 70, // Opcode: JMPLri
/* 5583 */    MCD_OPC_FilterValue, 57, 42, 0, 0, // Skip to: 5630
/* 5588 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5591 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 5614
/* 5596 */    MCD_OPC_CheckField, 25, 5, 0, 188, 7, 0, // Skip to: 7583
/* 5603 */    MCD_OPC_CheckField, 5, 8, 0, 181, 7, 0, // Skip to: 7583
/* 5610 */    MCD_OPC_Decode, 240, 4, 71, // Opcode: RETTrr
/* 5614 */    MCD_OPC_FilterValue, 1, 172, 7, 0, // Skip to: 7583
/* 5619 */    MCD_OPC_CheckField, 25, 5, 0, 165, 7, 0, // Skip to: 7583
/* 5626 */    MCD_OPC_Decode, 239, 4, 72, // Opcode: RETTri
/* 5630 */    MCD_OPC_FilterValue, 58, 119, 0, 0, // Skip to: 5754
/* 5635 */    MCD_OPC_ExtractField, 8, 6,  // Inst{13-8} ...
/* 5638 */    MCD_OPC_FilterValue, 16, 18, 0, 0, // Skip to: 5661
/* 5643 */    MCD_OPC_CheckField, 29, 1, 0, 141, 7, 0, // Skip to: 7583
/* 5650 */    MCD_OPC_CheckField, 5, 3, 0, 134, 7, 0, // Skip to: 7583
/* 5657 */    MCD_OPC_Decode, 225, 5, 73, // Opcode: TXCCrr
/* 5661 */    MCD_OPC_FilterValue, 32, 72, 0, 0, // Skip to: 5738
/* 5666 */    MCD_OPC_ExtractField, 0, 8,  // Inst{7-0} ...
/* 5669 */    MCD_OPC_FilterValue, 1, 18, 0, 0, // Skip to: 5692
/* 5674 */    MCD_OPC_CheckField, 25, 5, 8, 110, 7, 0, // Skip to: 7583
/* 5681 */    MCD_OPC_CheckField, 14, 5, 0, 103, 7, 0, // Skip to: 7583
/* 5688 */    MCD_OPC_Decode, 203, 5, 5, // Opcode: TA1
/* 5692 */    MCD_OPC_FilterValue, 3, 18, 0, 0, // Skip to: 5715
/* 5697 */    MCD_OPC_CheckField, 25, 5, 8, 87, 7, 0, // Skip to: 7583
/* 5704 */    MCD_OPC_CheckField, 14, 5, 0, 80, 7, 0, // Skip to: 7583
/* 5711 */    MCD_OPC_Decode, 204, 5, 5, // Opcode: TA3
/* 5715 */    MCD_OPC_FilterValue, 5, 71, 7, 0, // Skip to: 7583
/* 5720 */    MCD_OPC_CheckField, 25, 5, 8, 64, 7, 0, // Skip to: 7583
/* 5727 */    MCD_OPC_CheckField, 14, 5, 0, 57, 7, 0, // Skip to: 7583
/* 5734 */    MCD_OPC_Decode, 205, 5, 5, // Opcode: TA5
/* 5738 */    MCD_OPC_FilterValue, 48, 48, 7, 0, // Skip to: 7583
/* 5743 */    MCD_OPC_CheckField, 29, 1, 0, 41, 7, 0, // Skip to: 7583
/* 5750 */    MCD_OPC_Decode, 224, 5, 74, // Opcode: TXCCri
/* 5754 */    MCD_OPC_FilterValue, 59, 62, 0, 0, // Skip to: 5821
/* 5759 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5762 */    MCD_OPC_FilterValue, 0, 38, 0, 0, // Skip to: 5805
/* 5767 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 5770 */    MCD_OPC_FilterValue, 0, 16, 7, 0, // Skip to: 7583
/* 5775 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 5778 */    MCD_OPC_FilterValue, 0, 8, 7, 0, // Skip to: 7583
/* 5783 */    MCD_OPC_CheckField, 14, 5, 0, 11, 0, 0, // Skip to: 5801
/* 5790 */    MCD_OPC_CheckField, 0, 5, 0, 4, 0, 0, // Skip to: 5801
/* 5797 */    MCD_OPC_Decode, 153, 3, 5, // Opcode: FLUSH
/* 5801 */    MCD_OPC_Decode, 156, 3, 71, // Opcode: FLUSHrr
/* 5805 */    MCD_OPC_FilterValue, 1, 237, 6, 0, // Skip to: 7583
/* 5810 */    MCD_OPC_CheckField, 25, 5, 0, 230, 6, 0, // Skip to: 7583
/* 5817 */    MCD_OPC_Decode, 155, 3, 72, // Opcode: FLUSHri
/* 5821 */    MCD_OPC_FilterValue, 60, 28, 0, 0, // Skip to: 5854
/* 5826 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5829 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 5845
/* 5834 */    MCD_OPC_CheckField, 5, 8, 0, 206, 6, 0, // Skip to: 7583
/* 5841 */    MCD_OPC_Decode, 243, 4, 9, // Opcode: SAVErr
/* 5845 */    MCD_OPC_FilterValue, 1, 197, 6, 0, // Skip to: 7583
/* 5850 */    MCD_OPC_Decode, 242, 4, 10, // Opcode: SAVEri
/* 5854 */    MCD_OPC_FilterValue, 61, 28, 0, 0, // Skip to: 5887
/* 5859 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5862 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 5878
/* 5867 */    MCD_OPC_CheckField, 5, 8, 0, 173, 6, 0, // Skip to: 7583
/* 5874 */    MCD_OPC_Decode, 235, 4, 9, // Opcode: RESTORErr
/* 5878 */    MCD_OPC_FilterValue, 1, 164, 6, 0, // Skip to: 7583
/* 5883 */    MCD_OPC_Decode, 234, 4, 10, // Opcode: RESTOREri
/* 5887 */    MCD_OPC_FilterValue, 62, 88, 0, 0, // Skip to: 5980
/* 5892 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5895 */    MCD_OPC_FilterValue, 0, 71, 0, 0, // Skip to: 5971
/* 5900 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 5903 */    MCD_OPC_FilterValue, 0, 139, 6, 0, // Skip to: 7583
/* 5908 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 5911 */    MCD_OPC_FilterValue, 0, 23, 0, 0, // Skip to: 5939
/* 5916 */    MCD_OPC_CheckPredicate, 0, 46, 0, 0, // Skip to: 5967
/* 5921 */    MCD_OPC_CheckField, 14, 5, 0, 39, 0, 0, // Skip to: 5967
/* 5928 */    MCD_OPC_CheckField, 0, 5, 0, 32, 0, 0, // Skip to: 5967
/* 5935 */    MCD_OPC_Decode, 218, 2, 5, // Opcode: DONE
/* 5939 */    MCD_OPC_FilterValue, 1, 23, 0, 0, // Skip to: 5967
/* 5944 */    MCD_OPC_CheckPredicate, 0, 18, 0, 0, // Skip to: 5967
/* 5949 */    MCD_OPC_CheckField, 14, 5, 0, 11, 0, 0, // Skip to: 5967
/* 5956 */    MCD_OPC_CheckField, 0, 5, 0, 4, 0, 0, // Skip to: 5967
/* 5963 */    MCD_OPC_Decode, 238, 4, 5, // Opcode: RETRY
/* 5967 */    MCD_OPC_Decode, 233, 5, 9, // Opcode: UMACrr
/* 5971 */    MCD_OPC_FilterValue, 1, 71, 6, 0, // Skip to: 7583
/* 5976 */    MCD_OPC_Decode, 232, 5, 10, // Opcode: UMACri
/* 5980 */    MCD_OPC_FilterValue, 63, 62, 6, 0, // Skip to: 7583
/* 5985 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5988 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6004
/* 5993 */    MCD_OPC_CheckField, 5, 8, 0, 47, 6, 0, // Skip to: 7583
/* 6000 */    MCD_OPC_Decode, 131, 5, 9, // Opcode: SMACrr
/* 6004 */    MCD_OPC_FilterValue, 1, 38, 6, 0, // Skip to: 7583
/* 6009 */    MCD_OPC_Decode, 130, 5, 10, // Opcode: SMACri
/* 6013 */    MCD_OPC_FilterValue, 3, 29, 6, 0, // Skip to: 7583
/* 6018 */    MCD_OPC_ExtractField, 19, 6,  // Inst{24-19} ...
/* 6021 */    MCD_OPC_FilterValue, 0, 28, 0, 0, // Skip to: 6054
/* 6026 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6029 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6045
/* 6034 */    MCD_OPC_CheckField, 5, 8, 0, 6, 6, 0, // Skip to: 7583
/* 6041 */    MCD_OPC_Decode, 191, 4, 69, // Opcode: LDrr
/* 6045 */    MCD_OPC_FilterValue, 1, 253, 5, 0, // Skip to: 7583
/* 6050 */    MCD_OPC_Decode, 190, 4, 70, // Opcode: LDri
/* 6054 */    MCD_OPC_FilterValue, 1, 28, 0, 0, // Skip to: 6087
/* 6059 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6062 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6078
/* 6067 */    MCD_OPC_CheckField, 5, 8, 0, 229, 5, 0, // Skip to: 7583
/* 6074 */    MCD_OPC_Decode, 179, 4, 69, // Opcode: LDUBrr
/* 6078 */    MCD_OPC_FilterValue, 1, 220, 5, 0, // Skip to: 7583
/* 6083 */    MCD_OPC_Decode, 178, 4, 70, // Opcode: LDUBri
/* 6087 */    MCD_OPC_FilterValue, 2, 28, 0, 0, // Skip to: 6120
/* 6092 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6095 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6111
/* 6100 */    MCD_OPC_CheckField, 5, 8, 0, 196, 5, 0, // Skip to: 7583
/* 6107 */    MCD_OPC_Decode, 183, 4, 69, // Opcode: LDUHrr
/* 6111 */    MCD_OPC_FilterValue, 1, 187, 5, 0, // Skip to: 7583
/* 6116 */    MCD_OPC_Decode, 182, 4, 70, // Opcode: LDUHri
/* 6120 */    MCD_OPC_FilterValue, 3, 28, 0, 0, // Skip to: 6153
/* 6125 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6128 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6144
/* 6133 */    MCD_OPC_CheckField, 5, 8, 0, 163, 5, 0, // Skip to: 7583
/* 6140 */    MCD_OPC_Decode, 149, 4, 75, // Opcode: LDDrr
/* 6144 */    MCD_OPC_FilterValue, 1, 154, 5, 0, // Skip to: 7583
/* 6149 */    MCD_OPC_Decode, 148, 4, 76, // Opcode: LDDri
/* 6153 */    MCD_OPC_FilterValue, 4, 28, 0, 0, // Skip to: 6186
/* 6158 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6161 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6177
/* 6166 */    MCD_OPC_CheckField, 5, 8, 0, 130, 5, 0, // Skip to: 7583
/* 6173 */    MCD_OPC_Decode, 190, 5, 77, // Opcode: STrr
/* 6177 */    MCD_OPC_FilterValue, 1, 121, 5, 0, // Skip to: 7583
/* 6182 */    MCD_OPC_Decode, 189, 5, 78, // Opcode: STri
/* 6186 */    MCD_OPC_FilterValue, 5, 28, 0, 0, // Skip to: 6219
/* 6191 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6194 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6210
/* 6199 */    MCD_OPC_CheckField, 5, 8, 0, 97, 5, 0, // Skip to: 7583
/* 6206 */    MCD_OPC_Decode, 150, 5, 77, // Opcode: STBrr
/* 6210 */    MCD_OPC_FilterValue, 1, 88, 5, 0, // Skip to: 7583
/* 6215 */    MCD_OPC_Decode, 149, 5, 78, // Opcode: STBri
/* 6219 */    MCD_OPC_FilterValue, 6, 28, 0, 0, // Skip to: 6252
/* 6224 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6227 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6243
/* 6232 */    MCD_OPC_CheckField, 5, 8, 0, 64, 5, 0, // Skip to: 7583
/* 6239 */    MCD_OPC_Decode, 178, 5, 77, // Opcode: STHrr
/* 6243 */    MCD_OPC_FilterValue, 1, 55, 5, 0, // Skip to: 7583
/* 6248 */    MCD_OPC_Decode, 177, 5, 78, // Opcode: STHri
/* 6252 */    MCD_OPC_FilterValue, 7, 28, 0, 0, // Skip to: 6285
/* 6257 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6260 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6276
/* 6265 */    MCD_OPC_CheckField, 5, 8, 0, 31, 5, 0, // Skip to: 7583
/* 6272 */    MCD_OPC_Decode, 168, 5, 79, // Opcode: STDrr
/* 6276 */    MCD_OPC_FilterValue, 1, 22, 5, 0, // Skip to: 7583
/* 6281 */    MCD_OPC_Decode, 167, 5, 80, // Opcode: STDri
/* 6285 */    MCD_OPC_FilterValue, 8, 28, 0, 0, // Skip to: 6318
/* 6290 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6293 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6309
/* 6298 */    MCD_OPC_CheckField, 5, 8, 0, 254, 4, 0, // Skip to: 7583
/* 6305 */    MCD_OPC_Decode, 175, 4, 81, // Opcode: LDSWrr
/* 6309 */    MCD_OPC_FilterValue, 1, 245, 4, 0, // Skip to: 7583
/* 6314 */    MCD_OPC_Decode, 174, 4, 82, // Opcode: LDSWri
/* 6318 */    MCD_OPC_FilterValue, 9, 28, 0, 0, // Skip to: 6351
/* 6323 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6326 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6342
/* 6331 */    MCD_OPC_CheckField, 5, 8, 0, 221, 4, 0, // Skip to: 7583
/* 6338 */    MCD_OPC_Decode, 163, 4, 69, // Opcode: LDSBrr
/* 6342 */    MCD_OPC_FilterValue, 1, 212, 4, 0, // Skip to: 7583
/* 6347 */    MCD_OPC_Decode, 162, 4, 70, // Opcode: LDSBri
/* 6351 */    MCD_OPC_FilterValue, 10, 28, 0, 0, // Skip to: 6384
/* 6356 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6359 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6375
/* 6364 */    MCD_OPC_CheckField, 5, 8, 0, 188, 4, 0, // Skip to: 7583
/* 6371 */    MCD_OPC_Decode, 167, 4, 69, // Opcode: LDSHrr
/* 6375 */    MCD_OPC_FilterValue, 1, 179, 4, 0, // Skip to: 7583
/* 6380 */    MCD_OPC_Decode, 166, 4, 70, // Opcode: LDSHri
/* 6384 */    MCD_OPC_FilterValue, 11, 28, 0, 0, // Skip to: 6417
/* 6389 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6392 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6408
/* 6397 */    MCD_OPC_CheckField, 5, 8, 0, 155, 4, 0, // Skip to: 7583
/* 6404 */    MCD_OPC_Decode, 189, 4, 81, // Opcode: LDXrr
/* 6408 */    MCD_OPC_FilterValue, 1, 146, 4, 0, // Skip to: 7583
/* 6413 */    MCD_OPC_Decode, 188, 4, 82, // Opcode: LDXri
/* 6417 */    MCD_OPC_FilterValue, 13, 28, 0, 0, // Skip to: 6450
/* 6422 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6425 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6441
/* 6430 */    MCD_OPC_CheckField, 5, 8, 0, 122, 4, 0, // Skip to: 7583
/* 6437 */    MCD_OPC_Decode, 171, 4, 69, // Opcode: LDSTUBrr
/* 6441 */    MCD_OPC_FilterValue, 1, 113, 4, 0, // Skip to: 7583
/* 6446 */    MCD_OPC_Decode, 170, 4, 70, // Opcode: LDSTUBri
/* 6450 */    MCD_OPC_FilterValue, 14, 28, 0, 0, // Skip to: 6483
/* 6455 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6458 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6474
/* 6463 */    MCD_OPC_CheckField, 5, 8, 0, 89, 4, 0, // Skip to: 7583
/* 6470 */    MCD_OPC_Decode, 188, 5, 83, // Opcode: STXrr
/* 6474 */    MCD_OPC_FilterValue, 1, 80, 4, 0, // Skip to: 7583
/* 6479 */    MCD_OPC_Decode, 187, 5, 84, // Opcode: STXri
/* 6483 */    MCD_OPC_FilterValue, 15, 28, 0, 0, // Skip to: 6516
/* 6488 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6491 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6507
/* 6496 */    MCD_OPC_CheckField, 5, 8, 0, 56, 4, 0, // Skip to: 7583
/* 6503 */    MCD_OPC_Decode, 202, 5, 85, // Opcode: SWAPrr
/* 6507 */    MCD_OPC_FilterValue, 1, 47, 4, 0, // Skip to: 7583
/* 6512 */    MCD_OPC_Decode, 201, 5, 86, // Opcode: SWAPri
/* 6516 */    MCD_OPC_FilterValue, 16, 26, 0, 0, // Skip to: 6547
/* 6521 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6524 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6533
/* 6529 */    MCD_OPC_Decode, 135, 4, 87, // Opcode: LDArr
/* 6533 */    MCD_OPC_FilterValue, 1, 21, 4, 0, // Skip to: 7583
/* 6538 */    MCD_OPC_CheckPredicate, 0, 16, 4, 0, // Skip to: 7583
/* 6543 */    MCD_OPC_Decode, 134, 4, 70, // Opcode: LDAri
/* 6547 */    MCD_OPC_FilterValue, 17, 26, 0, 0, // Skip to: 6578
/* 6552 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6555 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6564
/* 6560 */    MCD_OPC_Decode, 177, 4, 87, // Opcode: LDUBArr
/* 6564 */    MCD_OPC_FilterValue, 1, 246, 3, 0, // Skip to: 7583
/* 6569 */    MCD_OPC_CheckPredicate, 0, 241, 3, 0, // Skip to: 7583
/* 6574 */    MCD_OPC_Decode, 176, 4, 70, // Opcode: LDUBAri
/* 6578 */    MCD_OPC_FilterValue, 18, 26, 0, 0, // Skip to: 6609
/* 6583 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6586 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6595
/* 6591 */    MCD_OPC_Decode, 181, 4, 87, // Opcode: LDUHArr
/* 6595 */    MCD_OPC_FilterValue, 1, 215, 3, 0, // Skip to: 7583
/* 6600 */    MCD_OPC_CheckPredicate, 0, 210, 3, 0, // Skip to: 7583
/* 6605 */    MCD_OPC_Decode, 180, 4, 70, // Opcode: LDUHAri
/* 6609 */    MCD_OPC_FilterValue, 19, 26, 0, 0, // Skip to: 6640
/* 6614 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6617 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6626
/* 6622 */    MCD_OPC_Decode, 141, 4, 88, // Opcode: LDDArr
/* 6626 */    MCD_OPC_FilterValue, 1, 184, 3, 0, // Skip to: 7583
/* 6631 */    MCD_OPC_CheckPredicate, 0, 179, 3, 0, // Skip to: 7583
/* 6636 */    MCD_OPC_Decode, 140, 4, 76, // Opcode: LDDAri
/* 6640 */    MCD_OPC_FilterValue, 20, 26, 0, 0, // Skip to: 6671
/* 6645 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6648 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6657
/* 6653 */    MCD_OPC_Decode, 145, 5, 89, // Opcode: STArr
/* 6657 */    MCD_OPC_FilterValue, 1, 153, 3, 0, // Skip to: 7583
/* 6662 */    MCD_OPC_CheckPredicate, 0, 148, 3, 0, // Skip to: 7583
/* 6667 */    MCD_OPC_Decode, 144, 5, 78, // Opcode: STAri
/* 6671 */    MCD_OPC_FilterValue, 21, 26, 0, 0, // Skip to: 6702
/* 6676 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6679 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6688
/* 6684 */    MCD_OPC_Decode, 148, 5, 89, // Opcode: STBArr
/* 6688 */    MCD_OPC_FilterValue, 1, 122, 3, 0, // Skip to: 7583
/* 6693 */    MCD_OPC_CheckPredicate, 0, 117, 3, 0, // Skip to: 7583
/* 6698 */    MCD_OPC_Decode, 147, 5, 78, // Opcode: STBAri
/* 6702 */    MCD_OPC_FilterValue, 22, 26, 0, 0, // Skip to: 6733
/* 6707 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6710 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6719
/* 6715 */    MCD_OPC_Decode, 176, 5, 89, // Opcode: STHArr
/* 6719 */    MCD_OPC_FilterValue, 1, 91, 3, 0, // Skip to: 7583
/* 6724 */    MCD_OPC_CheckPredicate, 0, 86, 3, 0, // Skip to: 7583
/* 6729 */    MCD_OPC_Decode, 175, 5, 78, // Opcode: STHAri
/* 6733 */    MCD_OPC_FilterValue, 23, 26, 0, 0, // Skip to: 6764
/* 6738 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6741 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6750
/* 6746 */    MCD_OPC_Decode, 156, 5, 90, // Opcode: STDArr
/* 6750 */    MCD_OPC_FilterValue, 1, 60, 3, 0, // Skip to: 7583
/* 6755 */    MCD_OPC_CheckPredicate, 0, 55, 3, 0, // Skip to: 7583
/* 6760 */    MCD_OPC_Decode, 155, 5, 80, // Opcode: STDAri
/* 6764 */    MCD_OPC_FilterValue, 24, 21, 0, 0, // Skip to: 6790
/* 6769 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6772 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6781
/* 6777 */    MCD_OPC_Decode, 173, 4, 91, // Opcode: LDSWArr
/* 6781 */    MCD_OPC_FilterValue, 1, 29, 3, 0, // Skip to: 7583
/* 6786 */    MCD_OPC_Decode, 172, 4, 82, // Opcode: LDSWAri
/* 6790 */    MCD_OPC_FilterValue, 25, 26, 0, 0, // Skip to: 6821
/* 6795 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6798 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6807
/* 6803 */    MCD_OPC_Decode, 161, 4, 87, // Opcode: LDSBArr
/* 6807 */    MCD_OPC_FilterValue, 1, 3, 3, 0, // Skip to: 7583
/* 6812 */    MCD_OPC_CheckPredicate, 0, 254, 2, 0, // Skip to: 7583
/* 6817 */    MCD_OPC_Decode, 160, 4, 70, // Opcode: LDSBAri
/* 6821 */    MCD_OPC_FilterValue, 26, 26, 0, 0, // Skip to: 6852
/* 6826 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6829 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6838
/* 6834 */    MCD_OPC_Decode, 165, 4, 87, // Opcode: LDSHArr
/* 6838 */    MCD_OPC_FilterValue, 1, 228, 2, 0, // Skip to: 7583
/* 6843 */    MCD_OPC_CheckPredicate, 0, 223, 2, 0, // Skip to: 7583
/* 6848 */    MCD_OPC_Decode, 164, 4, 70, // Opcode: LDSHAri
/* 6852 */    MCD_OPC_FilterValue, 27, 21, 0, 0, // Skip to: 6878
/* 6857 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6860 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6869
/* 6865 */    MCD_OPC_Decode, 185, 4, 91, // Opcode: LDXArr
/* 6869 */    MCD_OPC_FilterValue, 1, 197, 2, 0, // Skip to: 7583
/* 6874 */    MCD_OPC_Decode, 184, 4, 82, // Opcode: LDXAri
/* 6878 */    MCD_OPC_FilterValue, 29, 26, 0, 0, // Skip to: 6909
/* 6883 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6886 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6895
/* 6891 */    MCD_OPC_Decode, 169, 4, 87, // Opcode: LDSTUBArr
/* 6895 */    MCD_OPC_FilterValue, 1, 171, 2, 0, // Skip to: 7583
/* 6900 */    MCD_OPC_CheckPredicate, 0, 166, 2, 0, // Skip to: 7583
/* 6905 */    MCD_OPC_Decode, 168, 4, 70, // Opcode: LDSTUBAri
/* 6909 */    MCD_OPC_FilterValue, 30, 21, 0, 0, // Skip to: 6935
/* 6914 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6917 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6926
/* 6922 */    MCD_OPC_Decode, 184, 5, 92, // Opcode: STXArr
/* 6926 */    MCD_OPC_FilterValue, 1, 140, 2, 0, // Skip to: 7583
/* 6931 */    MCD_OPC_Decode, 183, 5, 84, // Opcode: STXAri
/* 6935 */    MCD_OPC_FilterValue, 31, 26, 0, 0, // Skip to: 6966
/* 6940 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6943 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6952
/* 6948 */    MCD_OPC_Decode, 200, 5, 93, // Opcode: SWAPArr
/* 6952 */    MCD_OPC_FilterValue, 1, 114, 2, 0, // Skip to: 7583
/* 6957 */    MCD_OPC_CheckPredicate, 0, 109, 2, 0, // Skip to: 7583
/* 6962 */    MCD_OPC_Decode, 199, 5, 86, // Opcode: SWAPAri
/* 6966 */    MCD_OPC_FilterValue, 32, 28, 0, 0, // Skip to: 6999
/* 6971 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6974 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6990
/* 6979 */    MCD_OPC_CheckField, 5, 8, 0, 85, 2, 0, // Skip to: 7583
/* 6986 */    MCD_OPC_Decode, 155, 4, 94, // Opcode: LDFrr
/* 6990 */    MCD_OPC_FilterValue, 1, 76, 2, 0, // Skip to: 7583
/* 6995 */    MCD_OPC_Decode, 154, 4, 95, // Opcode: LDFri
/* 6999 */    MCD_OPC_FilterValue, 33, 79, 0, 0, // Skip to: 7083
/* 7004 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7007 */    MCD_OPC_FilterValue, 0, 40, 0, 0, // Skip to: 7052
/* 7012 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 7015 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7031
/* 7020 */    MCD_OPC_CheckField, 5, 8, 0, 44, 2, 0, // Skip to: 7583
/* 7027 */    MCD_OPC_Decode, 153, 4, 71, // Opcode: LDFSRrr
/* 7031 */    MCD_OPC_FilterValue, 1, 35, 2, 0, // Skip to: 7583
/* 7036 */    MCD_OPC_CheckPredicate, 0, 30, 2, 0, // Skip to: 7583
/* 7041 */    MCD_OPC_CheckField, 5, 8, 0, 23, 2, 0, // Skip to: 7583
/* 7048 */    MCD_OPC_Decode, 187, 4, 71, // Opcode: LDXFSRrr
/* 7052 */    MCD_OPC_FilterValue, 1, 14, 2, 0, // Skip to: 7583
/* 7057 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 7060 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7069
/* 7065 */    MCD_OPC_Decode, 152, 4, 72, // Opcode: LDFSRri
/* 7069 */    MCD_OPC_FilterValue, 1, 253, 1, 0, // Skip to: 7583
/* 7074 */    MCD_OPC_CheckPredicate, 0, 248, 1, 0, // Skip to: 7583
/* 7079 */    MCD_OPC_Decode, 186, 4, 72, // Opcode: LDXFSRri
/* 7083 */    MCD_OPC_FilterValue, 35, 28, 0, 0, // Skip to: 7116
/* 7088 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7091 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7107
/* 7096 */    MCD_OPC_CheckField, 5, 8, 0, 224, 1, 0, // Skip to: 7583
/* 7103 */    MCD_OPC_Decode, 147, 4, 96, // Opcode: LDDFrr
/* 7107 */    MCD_OPC_FilterValue, 1, 215, 1, 0, // Skip to: 7583
/* 7112 */    MCD_OPC_Decode, 146, 4, 97, // Opcode: LDDFri
/* 7116 */    MCD_OPC_FilterValue, 36, 28, 0, 0, // Skip to: 7149
/* 7121 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7124 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7140
/* 7129 */    MCD_OPC_CheckField, 5, 8, 0, 191, 1, 0, // Skip to: 7583
/* 7136 */    MCD_OPC_Decode, 174, 5, 98, // Opcode: STFrr
/* 7140 */    MCD_OPC_FilterValue, 1, 182, 1, 0, // Skip to: 7583
/* 7145 */    MCD_OPC_Decode, 173, 5, 99, // Opcode: STFri
/* 7149 */    MCD_OPC_FilterValue, 37, 79, 0, 0, // Skip to: 7233
/* 7154 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7157 */    MCD_OPC_FilterValue, 0, 40, 0, 0, // Skip to: 7202
/* 7162 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 7165 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7181
/* 7170 */    MCD_OPC_CheckField, 5, 8, 0, 150, 1, 0, // Skip to: 7583
/* 7177 */    MCD_OPC_Decode, 172, 5, 71, // Opcode: STFSRrr
/* 7181 */    MCD_OPC_FilterValue, 1, 141, 1, 0, // Skip to: 7583
/* 7186 */    MCD_OPC_CheckPredicate, 0, 136, 1, 0, // Skip to: 7583
/* 7191 */    MCD_OPC_CheckField, 5, 8, 0, 129, 1, 0, // Skip to: 7583
/* 7198 */    MCD_OPC_Decode, 186, 5, 71, // Opcode: STXFSRrr
/* 7202 */    MCD_OPC_FilterValue, 1, 120, 1, 0, // Skip to: 7583
/* 7207 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 7210 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7219
/* 7215 */    MCD_OPC_Decode, 171, 5, 72, // Opcode: STFSRri
/* 7219 */    MCD_OPC_FilterValue, 1, 103, 1, 0, // Skip to: 7583
/* 7224 */    MCD_OPC_CheckPredicate, 0, 98, 1, 0, // Skip to: 7583
/* 7229 */    MCD_OPC_Decode, 185, 5, 72, // Opcode: STXFSRri
/* 7233 */    MCD_OPC_FilterValue, 38, 42, 0, 0, // Skip to: 7280
/* 7238 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7241 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 7264
/* 7246 */    MCD_OPC_CheckField, 25, 5, 0, 74, 1, 0, // Skip to: 7583
/* 7253 */    MCD_OPC_CheckField, 5, 8, 0, 67, 1, 0, // Skip to: 7583
/* 7260 */    MCD_OPC_Decode, 164, 5, 71, // Opcode: STDFQrr
/* 7264 */    MCD_OPC_FilterValue, 1, 58, 1, 0, // Skip to: 7583
/* 7269 */    MCD_OPC_CheckField, 25, 5, 0, 51, 1, 0, // Skip to: 7583
/* 7276 */    MCD_OPC_Decode, 163, 5, 72, // Opcode: STDFQri
/* 7280 */    MCD_OPC_FilterValue, 39, 28, 0, 0, // Skip to: 7313
/* 7285 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7288 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7304
/* 7293 */    MCD_OPC_CheckField, 5, 8, 0, 27, 1, 0, // Skip to: 7583
/* 7300 */    MCD_OPC_Decode, 166, 5, 100, // Opcode: STDFrr
/* 7304 */    MCD_OPC_FilterValue, 1, 18, 1, 0, // Skip to: 7583
/* 7309 */    MCD_OPC_Decode, 165, 5, 101, // Opcode: STDFri
/* 7313 */    MCD_OPC_FilterValue, 45, 38, 0, 0, // Skip to: 7356
/* 7318 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7321 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 7342
/* 7326 */    MCD_OPC_CheckPredicate, 0, 252, 0, 0, // Skip to: 7583
/* 7331 */    MCD_OPC_CheckField, 5, 8, 0, 245, 0, 0, // Skip to: 7583
/* 7338 */    MCD_OPC_Decode, 224, 4, 102, // Opcode: PREFETCHr
/* 7342 */    MCD_OPC_FilterValue, 1, 236, 0, 0, // Skip to: 7583
/* 7347 */    MCD_OPC_CheckPredicate, 0, 231, 0, 0, // Skip to: 7583
/* 7352 */    MCD_OPC_Decode, 223, 4, 103, // Opcode: PREFETCHi
/* 7356 */    MCD_OPC_FilterValue, 49, 42, 0, 0, // Skip to: 7403
/* 7361 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7364 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 7387
/* 7369 */    MCD_OPC_CheckField, 25, 5, 0, 207, 0, 0, // Skip to: 7583
/* 7376 */    MCD_OPC_CheckField, 5, 8, 0, 200, 0, 0, // Skip to: 7583
/* 7383 */    MCD_OPC_Decode, 137, 4, 71, // Opcode: LDCSRrr
/* 7387 */    MCD_OPC_FilterValue, 1, 191, 0, 0, // Skip to: 7583
/* 7392 */    MCD_OPC_CheckField, 25, 5, 0, 184, 0, 0, // Skip to: 7583
/* 7399 */    MCD_OPC_Decode, 136, 4, 72, // Opcode: LDCSRri
/* 7403 */    MCD_OPC_FilterValue, 53, 42, 0, 0, // Skip to: 7450
/* 7408 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7411 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 7434
/* 7416 */    MCD_OPC_CheckField, 25, 5, 0, 160, 0, 0, // Skip to: 7583
/* 7423 */    MCD_OPC_CheckField, 5, 8, 0, 153, 0, 0, // Skip to: 7583
/* 7430 */    MCD_OPC_Decode, 152, 5, 71, // Opcode: STCSRrr
/* 7434 */    MCD_OPC_FilterValue, 1, 144, 0, 0, // Skip to: 7583
/* 7439 */    MCD_OPC_CheckField, 25, 5, 0, 137, 0, 0, // Skip to: 7583
/* 7446 */    MCD_OPC_Decode, 151, 5, 72, // Opcode: STCSRri
/* 7450 */    MCD_OPC_FilterValue, 54, 42, 0, 0, // Skip to: 7497
/* 7455 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7458 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 7481
/* 7463 */    MCD_OPC_CheckField, 25, 5, 0, 113, 0, 0, // Skip to: 7583
/* 7470 */    MCD_OPC_CheckField, 5, 8, 0, 106, 0, 0, // Skip to: 7583
/* 7477 */    MCD_OPC_Decode, 158, 5, 71, // Opcode: STDCQrr
/* 7481 */    MCD_OPC_FilterValue, 1, 97, 0, 0, // Skip to: 7583
/* 7486 */    MCD_OPC_CheckField, 25, 5, 0, 90, 0, 0, // Skip to: 7583
/* 7493 */    MCD_OPC_Decode, 157, 5, 72, // Opcode: STDCQri
/* 7497 */    MCD_OPC_FilterValue, 60, 38, 0, 0, // Skip to: 7540
/* 7502 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7505 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 7519
/* 7510 */    MCD_OPC_CheckPredicate, 5, 68, 0, 0, // Skip to: 7583
/* 7515 */    MCD_OPC_Decode, 210, 2, 104, // Opcode: CASArr
/* 7519 */    MCD_OPC_FilterValue, 1, 59, 0, 0, // Skip to: 7583
/* 7524 */    MCD_OPC_CheckPredicate, 0, 54, 0, 0, // Skip to: 7583
/* 7529 */    MCD_OPC_CheckField, 5, 8, 0, 47, 0, 0, // Skip to: 7583
/* 7536 */    MCD_OPC_Decode, 209, 2, 105, // Opcode: CASAri
/* 7540 */    MCD_OPC_FilterValue, 62, 38, 0, 0, // Skip to: 7583
/* 7545 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7548 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 7562
/* 7553 */    MCD_OPC_CheckPredicate, 0, 25, 0, 0, // Skip to: 7583
/* 7558 */    MCD_OPC_Decode, 212, 2, 106, // Opcode: CASXArr
/* 7562 */    MCD_OPC_FilterValue, 1, 16, 0, 0, // Skip to: 7583
/* 7567 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 7583
/* 7572 */    MCD_OPC_CheckField, 5, 8, 0, 4, 0, 0, // Skip to: 7583
/* 7579 */    MCD_OPC_Decode, 211, 2, 107, // Opcode: CASXAri
/* 7583 */    MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableSparcV832[] = {
/* 0 */       MCD_OPC_ExtractField, 19, 6,  // Inst{24-19} ...
/* 3 */       MCD_OPC_FilterValue, 48, 42, 0, 0, // Skip to: 50
/* 8 */       MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 11 */      MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 34
/* 16 */      MCD_OPC_CheckField, 30, 2, 3, 215, 0, 0, // Skip to: 238
/* 23 */      MCD_OPC_CheckField, 5, 8, 0, 208, 0, 0, // Skip to: 238
/* 30 */      MCD_OPC_Decode, 139, 4, 108, // Opcode: LDCrr
/* 34 */      MCD_OPC_FilterValue, 1, 199, 0, 0, // Skip to: 238
/* 39 */      MCD_OPC_CheckField, 30, 2, 3, 192, 0, 0, // Skip to: 238
/* 46 */      MCD_OPC_Decode, 138, 4, 109, // Opcode: LDCri
/* 50 */      MCD_OPC_FilterValue, 51, 42, 0, 0, // Skip to: 97
/* 55 */      MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 58 */      MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 81
/* 63 */      MCD_OPC_CheckField, 30, 2, 3, 168, 0, 0, // Skip to: 238
/* 70 */      MCD_OPC_CheckField, 5, 8, 0, 161, 0, 0, // Skip to: 238
/* 77 */      MCD_OPC_Decode, 143, 4, 110, // Opcode: LDDCrr
/* 81 */      MCD_OPC_FilterValue, 1, 152, 0, 0, // Skip to: 238
/* 86 */      MCD_OPC_CheckField, 30, 2, 3, 145, 0, 0, // Skip to: 238
/* 93 */      MCD_OPC_Decode, 142, 4, 111, // Opcode: LDDCri
/* 97 */      MCD_OPC_FilterValue, 52, 42, 0, 0, // Skip to: 144
/* 102 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 105 */     MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 128
/* 110 */     MCD_OPC_CheckField, 30, 2, 3, 121, 0, 0, // Skip to: 238
/* 117 */     MCD_OPC_CheckField, 5, 8, 0, 114, 0, 0, // Skip to: 238
/* 124 */     MCD_OPC_Decode, 154, 5, 112, // Opcode: STCrr
/* 128 */     MCD_OPC_FilterValue, 1, 105, 0, 0, // Skip to: 238
/* 133 */     MCD_OPC_CheckField, 30, 2, 3, 98, 0, 0, // Skip to: 238
/* 140 */     MCD_OPC_Decode, 153, 5, 113, // Opcode: STCri
/* 144 */     MCD_OPC_FilterValue, 55, 42, 0, 0, // Skip to: 191
/* 149 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 152 */     MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 175
/* 157 */     MCD_OPC_CheckField, 30, 2, 3, 74, 0, 0, // Skip to: 238
/* 164 */     MCD_OPC_CheckField, 5, 8, 0, 67, 0, 0, // Skip to: 238
/* 171 */     MCD_OPC_Decode, 160, 5, 114, // Opcode: STDCrr
/* 175 */     MCD_OPC_FilterValue, 1, 58, 0, 0, // Skip to: 238
/* 180 */     MCD_OPC_CheckField, 30, 2, 3, 51, 0, 0, // Skip to: 238
/* 187 */     MCD_OPC_Decode, 159, 5, 115, // Opcode: STDCri
/* 191 */     MCD_OPC_FilterValue, 58, 42, 0, 0, // Skip to: 238
/* 196 */     MCD_OPC_ExtractField, 8, 6,  // Inst{13-8} ...
/* 199 */     MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 222
/* 204 */     MCD_OPC_CheckField, 29, 3, 4, 27, 0, 0, // Skip to: 238
/* 211 */     MCD_OPC_CheckField, 5, 3, 0, 20, 0, 0, // Skip to: 238
/* 218 */     MCD_OPC_Decode, 219, 5, 73, // Opcode: TRAPrr
/* 222 */     MCD_OPC_FilterValue, 32, 11, 0, 0, // Skip to: 238
/* 227 */     MCD_OPC_CheckField, 29, 3, 4, 4, 0, 0, // Skip to: 238
/* 234 */     MCD_OPC_Decode, 218, 5, 74, // Opcode: TRAPri
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
/* 35 */      MCD_OPC_Decode, 159, 4, 116, // Opcode: LDQFrr
/* 39 */      MCD_OPC_FilterValue, 1, 174, 1, 0, // Skip to: 474
/* 44 */      MCD_OPC_CheckPredicate, 0, 169, 1, 0, // Skip to: 474
/* 49 */      MCD_OPC_CheckField, 30, 2, 3, 162, 1, 0, // Skip to: 474
/* 56 */      MCD_OPC_Decode, 158, 4, 117, // Opcode: LDQFri
/* 60 */      MCD_OPC_FilterValue, 38, 52, 0, 0, // Skip to: 117
/* 65 */      MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 68 */      MCD_OPC_FilterValue, 0, 23, 0, 0, // Skip to: 96
/* 73 */      MCD_OPC_CheckPredicate, 0, 140, 1, 0, // Skip to: 474
/* 78 */      MCD_OPC_CheckField, 30, 2, 3, 133, 1, 0, // Skip to: 474
/* 85 */      MCD_OPC_CheckField, 5, 8, 0, 126, 1, 0, // Skip to: 474
/* 92 */      MCD_OPC_Decode, 182, 5, 118, // Opcode: STQFrr
/* 96 */      MCD_OPC_FilterValue, 1, 117, 1, 0, // Skip to: 474
/* 101 */     MCD_OPC_CheckPredicate, 0, 112, 1, 0, // Skip to: 474
/* 106 */     MCD_OPC_CheckField, 30, 2, 3, 105, 1, 0, // Skip to: 474
/* 113 */     MCD_OPC_Decode, 181, 5, 119, // Opcode: STQFri
/* 117 */     MCD_OPC_FilterValue, 48, 45, 0, 0, // Skip to: 167
/* 122 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 125 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 146
/* 130 */     MCD_OPC_CheckPredicate, 0, 83, 1, 0, // Skip to: 474
/* 135 */     MCD_OPC_CheckField, 30, 2, 3, 76, 1, 0, // Skip to: 474
/* 142 */     MCD_OPC_Decode, 151, 4, 120, // Opcode: LDFArr
/* 146 */     MCD_OPC_FilterValue, 1, 67, 1, 0, // Skip to: 474
/* 151 */     MCD_OPC_CheckPredicate, 0, 62, 1, 0, // Skip to: 474
/* 156 */     MCD_OPC_CheckField, 30, 2, 3, 55, 1, 0, // Skip to: 474
/* 163 */     MCD_OPC_Decode, 150, 4, 95, // Opcode: LDFAri
/* 167 */     MCD_OPC_FilterValue, 50, 45, 0, 0, // Skip to: 217
/* 172 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 175 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 196
/* 180 */     MCD_OPC_CheckPredicate, 0, 33, 1, 0, // Skip to: 474
/* 185 */     MCD_OPC_CheckField, 30, 2, 3, 26, 1, 0, // Skip to: 474
/* 192 */     MCD_OPC_Decode, 157, 4, 121, // Opcode: LDQFArr
/* 196 */     MCD_OPC_FilterValue, 1, 17, 1, 0, // Skip to: 474
/* 201 */     MCD_OPC_CheckPredicate, 0, 12, 1, 0, // Skip to: 474
/* 206 */     MCD_OPC_CheckField, 30, 2, 3, 5, 1, 0, // Skip to: 474
/* 213 */     MCD_OPC_Decode, 156, 4, 117, // Opcode: LDQFAri
/* 217 */     MCD_OPC_FilterValue, 51, 45, 0, 0, // Skip to: 267
/* 222 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 225 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 246
/* 230 */     MCD_OPC_CheckPredicate, 0, 239, 0, 0, // Skip to: 474
/* 235 */     MCD_OPC_CheckField, 30, 2, 3, 232, 0, 0, // Skip to: 474
/* 242 */     MCD_OPC_Decode, 145, 4, 122, // Opcode: LDDFArr
/* 246 */     MCD_OPC_FilterValue, 1, 223, 0, 0, // Skip to: 474
/* 251 */     MCD_OPC_CheckPredicate, 0, 218, 0, 0, // Skip to: 474
/* 256 */     MCD_OPC_CheckField, 30, 2, 3, 211, 0, 0, // Skip to: 474
/* 263 */     MCD_OPC_Decode, 144, 4, 97, // Opcode: LDDFAri
/* 267 */     MCD_OPC_FilterValue, 52, 45, 0, 0, // Skip to: 317
/* 272 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 275 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 296
/* 280 */     MCD_OPC_CheckPredicate, 0, 189, 0, 0, // Skip to: 474
/* 285 */     MCD_OPC_CheckField, 30, 2, 3, 182, 0, 0, // Skip to: 474
/* 292 */     MCD_OPC_Decode, 170, 5, 123, // Opcode: STFArr
/* 296 */     MCD_OPC_FilterValue, 1, 173, 0, 0, // Skip to: 474
/* 301 */     MCD_OPC_CheckPredicate, 0, 168, 0, 0, // Skip to: 474
/* 306 */     MCD_OPC_CheckField, 30, 2, 3, 161, 0, 0, // Skip to: 474
/* 313 */     MCD_OPC_Decode, 169, 5, 99, // Opcode: STFAri
/* 317 */     MCD_OPC_FilterValue, 54, 45, 0, 0, // Skip to: 367
/* 322 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 325 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 346
/* 330 */     MCD_OPC_CheckPredicate, 0, 139, 0, 0, // Skip to: 474
/* 335 */     MCD_OPC_CheckField, 30, 2, 3, 132, 0, 0, // Skip to: 474
/* 342 */     MCD_OPC_Decode, 180, 5, 124, // Opcode: STQFArr
/* 346 */     MCD_OPC_FilterValue, 1, 123, 0, 0, // Skip to: 474
/* 351 */     MCD_OPC_CheckPredicate, 0, 118, 0, 0, // Skip to: 474
/* 356 */     MCD_OPC_CheckField, 30, 2, 3, 111, 0, 0, // Skip to: 474
/* 363 */     MCD_OPC_Decode, 179, 5, 119, // Opcode: STQFAri
/* 367 */     MCD_OPC_FilterValue, 55, 45, 0, 0, // Skip to: 417
/* 372 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 375 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 396
/* 380 */     MCD_OPC_CheckPredicate, 0, 89, 0, 0, // Skip to: 474
/* 385 */     MCD_OPC_CheckField, 30, 2, 3, 82, 0, 0, // Skip to: 474
/* 392 */     MCD_OPC_Decode, 162, 5, 125, // Opcode: STDFArr
/* 396 */     MCD_OPC_FilterValue, 1, 73, 0, 0, // Skip to: 474
/* 401 */     MCD_OPC_CheckPredicate, 0, 68, 0, 0, // Skip to: 474
/* 406 */     MCD_OPC_CheckField, 30, 2, 3, 61, 0, 0, // Skip to: 474
/* 413 */     MCD_OPC_Decode, 161, 5, 101, // Opcode: STDFAri
/* 417 */     MCD_OPC_FilterValue, 58, 52, 0, 0, // Skip to: 474
/* 422 */     MCD_OPC_ExtractField, 8, 6,  // Inst{13-8} ...
/* 425 */     MCD_OPC_FilterValue, 0, 23, 0, 0, // Skip to: 453
/* 430 */     MCD_OPC_CheckPredicate, 0, 39, 0, 0, // Skip to: 474
/* 435 */     MCD_OPC_CheckField, 29, 3, 4, 32, 0, 0, // Skip to: 474
/* 442 */     MCD_OPC_CheckField, 5, 3, 0, 25, 0, 0, // Skip to: 474
/* 449 */     MCD_OPC_Decode, 213, 5, 73, // Opcode: TICCrr
/* 453 */     MCD_OPC_FilterValue, 32, 16, 0, 0, // Skip to: 474
/* 458 */     MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 474
/* 463 */     MCD_OPC_CheckField, 29, 3, 4, 4, 0, 0, // Skip to: 474
/* 470 */     MCD_OPC_Decode, 212, 5, 74, // Opcode: TICCri
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
    return S; \
  case 3: \
    tmp = fieldname(insn, 0, 22); \
    if (!Check(&S, DecodeDisp22(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 4: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 14) << 0; \
    tmp |= fieldname(insn, 20, 2) << 14; \
    if (!Check(&S, DecodeDisp16(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 5: \
    return S; \
  case 6: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 22); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 7: \
    tmp = fieldname(insn, 0, 19); \
    if (!Check(&S, DecodeDisp19(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 20, 2); \
    if (!Check(&S, DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 8: \
    tmp = fieldname(insn, 0, 30); \
    if (!Check(&S, DecodeCall(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 9: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 10: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    if (!Check(&S, DecodeSIMM13(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 11: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 12: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 13: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 14: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 6); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 15: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 6); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 16: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeASRRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 17: \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 18: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 19: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePRRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 20: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
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
    tmp = fieldname(insn, 11, 2); \
    if (!Check(&S, DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 22: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
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
    tmp = fieldname(insn, 11, 2); \
    if (!Check(&S, DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 11); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 24: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 25: \
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
  case 26: \
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
  case 27: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeASRRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 28: \
    tmp = fieldname(insn, 0, 13); \
    if (!Check(&S, DecodeSIMM13(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 29: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeASRRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    if (!Check(&S, DecodeSIMM13(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 30: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 31: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    if (!Check(&S, DecodeSIMM13(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 32: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodePRRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 33: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodePRRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    if (!Check(&S, DecodeSIMM13(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 34: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 35: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 36: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 37: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 38: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 39: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 40: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 41: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 42: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 43: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 44: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 45: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 46: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 47: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 48: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 49: \
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
  case 50: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 51: \
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
  case 52: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 53: \
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
  case 54: \
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
  case 55: \
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
  case 56: \
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
  case 57: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 58: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 59: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 60: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 61: \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 62: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 63: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 64: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 65: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 66: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 67: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 68: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 69: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 70: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 71: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 72: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 73: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 74: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 75: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 76: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 77: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 78: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 79: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 80: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 81: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 82: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 83: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 84: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 85: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 86: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 87: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 88: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 89: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 90: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 91: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 92: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 93: \
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
  case 94: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 95: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 96: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 97: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 98: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 99: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 100: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 101: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 102: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 103: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
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
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 105: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
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
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 107: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 108: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 109: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 110: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 111: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 112: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 113: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 114: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 115: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 116: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 117: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 118: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 119: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 120: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 121: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 122: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 123: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 124: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 125: \
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
