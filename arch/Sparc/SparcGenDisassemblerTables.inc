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
/* 3 */       MCD_OPC_FilterValue, 0, 212, 1, 0, // Skip to: 476
/* 8 */       MCD_OPC_ExtractField, 22, 3,  // Inst{24-22} ...
/* 11 */      MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 27
/* 16 */      MCD_OPC_CheckField, 25, 5, 0, 114, 30, 0, // Skip to: 7817
/* 23 */      MCD_OPC_Decode, 238, 5, 0, // Opcode: UNIMP
/* 27 */      MCD_OPC_FilterValue, 1, 147, 0, 0, // Skip to: 179
/* 32 */      MCD_OPC_ExtractField, 19, 3,  // Inst{21-19} ...
/* 35 */      MCD_OPC_FilterValue, 0, 31, 0, 0, // Skip to: 71
/* 40 */      MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 43 */      MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 57
/* 48 */      MCD_OPC_CheckPredicate, 0, 84, 30, 0, // Skip to: 7817
/* 53 */      MCD_OPC_Decode, 195, 2, 1, // Opcode: BPICCNT
/* 57 */      MCD_OPC_FilterValue, 1, 75, 30, 0, // Skip to: 7817
/* 62 */      MCD_OPC_CheckPredicate, 0, 70, 30, 0, // Skip to: 7817
/* 67 */      MCD_OPC_Decode, 194, 2, 1, // Opcode: BPICCANT
/* 71 */      MCD_OPC_FilterValue, 1, 31, 0, 0, // Skip to: 107
/* 76 */      MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 79 */      MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 93
/* 84 */      MCD_OPC_CheckPredicate, 0, 48, 30, 0, // Skip to: 7817
/* 89 */      MCD_OPC_Decode, 192, 2, 1, // Opcode: BPICC
/* 93 */      MCD_OPC_FilterValue, 1, 39, 30, 0, // Skip to: 7817
/* 98 */      MCD_OPC_CheckPredicate, 0, 34, 30, 0, // Skip to: 7817
/* 103 */     MCD_OPC_Decode, 193, 2, 1, // Opcode: BPICCA
/* 107 */     MCD_OPC_FilterValue, 4, 31, 0, 0, // Skip to: 143
/* 112 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 115 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 129
/* 120 */     MCD_OPC_CheckPredicate, 0, 12, 30, 0, // Skip to: 7817
/* 125 */     MCD_OPC_Decode, 203, 2, 1, // Opcode: BPXCCNT
/* 129 */     MCD_OPC_FilterValue, 1, 3, 30, 0, // Skip to: 7817
/* 134 */     MCD_OPC_CheckPredicate, 0, 254, 29, 0, // Skip to: 7817
/* 139 */     MCD_OPC_Decode, 202, 2, 1, // Opcode: BPXCCANT
/* 143 */     MCD_OPC_FilterValue, 5, 245, 29, 0, // Skip to: 7817
/* 148 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 151 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 165
/* 156 */     MCD_OPC_CheckPredicate, 0, 232, 29, 0, // Skip to: 7817
/* 161 */     MCD_OPC_Decode, 200, 2, 1, // Opcode: BPXCC
/* 165 */     MCD_OPC_FilterValue, 1, 223, 29, 0, // Skip to: 7817
/* 170 */     MCD_OPC_CheckPredicate, 0, 218, 29, 0, // Skip to: 7817
/* 175 */     MCD_OPC_Decode, 201, 2, 1, // Opcode: BPXCCA
/* 179 */     MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 205
/* 184 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 187 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 196
/* 192 */     MCD_OPC_Decode, 183, 2, 2, // Opcode: BCOND
/* 196 */     MCD_OPC_FilterValue, 1, 192, 29, 0, // Skip to: 7817
/* 201 */     MCD_OPC_Decode, 184, 2, 2, // Opcode: BCONDA
/* 205 */     MCD_OPC_FilterValue, 3, 75, 0, 0, // Skip to: 285
/* 210 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 213 */     MCD_OPC_FilterValue, 0, 31, 0, 0, // Skip to: 249
/* 218 */     MCD_OPC_ExtractField, 28, 2,  // Inst{29-28} ...
/* 221 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 235
/* 226 */     MCD_OPC_CheckPredicate, 0, 162, 29, 0, // Skip to: 7817
/* 231 */     MCD_OPC_Decode, 199, 2, 3, // Opcode: BPRNT
/* 235 */     MCD_OPC_FilterValue, 2, 153, 29, 0, // Skip to: 7817
/* 240 */     MCD_OPC_CheckPredicate, 0, 148, 29, 0, // Skip to: 7817
/* 245 */     MCD_OPC_Decode, 198, 2, 3, // Opcode: BPRANT
/* 249 */     MCD_OPC_FilterValue, 1, 139, 29, 0, // Skip to: 7817
/* 254 */     MCD_OPC_ExtractField, 28, 2,  // Inst{29-28} ...
/* 257 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 271
/* 262 */     MCD_OPC_CheckPredicate, 0, 126, 29, 0, // Skip to: 7817
/* 267 */     MCD_OPC_Decode, 196, 2, 3, // Opcode: BPR
/* 271 */     MCD_OPC_FilterValue, 2, 117, 29, 0, // Skip to: 7817
/* 276 */     MCD_OPC_CheckPredicate, 0, 112, 29, 0, // Skip to: 7817
/* 281 */     MCD_OPC_Decode, 197, 2, 3, // Opcode: BPRA
/* 285 */     MCD_OPC_FilterValue, 4, 22, 0, 0, // Skip to: 312
/* 290 */     MCD_OPC_CheckField, 25, 5, 0, 11, 0, 0, // Skip to: 308
/* 297 */     MCD_OPC_CheckField, 0, 22, 0, 4, 0, 0, // Skip to: 308
/* 304 */     MCD_OPC_Decode, 210, 4, 4, // Opcode: NOP
/* 308 */     MCD_OPC_Decode, 249, 4, 5, // Opcode: SETHIi
/* 312 */     MCD_OPC_FilterValue, 5, 107, 0, 0, // Skip to: 424
/* 317 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 320 */     MCD_OPC_FilterValue, 0, 31, 0, 0, // Skip to: 356
/* 325 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 328 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 342
/* 333 */     MCD_OPC_CheckPredicate, 0, 55, 29, 0, // Skip to: 7817
/* 338 */     MCD_OPC_Decode, 191, 2, 6, // Opcode: BPFCCNT
/* 342 */     MCD_OPC_FilterValue, 1, 46, 29, 0, // Skip to: 7817
/* 347 */     MCD_OPC_CheckPredicate, 0, 41, 29, 0, // Skip to: 7817
/* 352 */     MCD_OPC_Decode, 190, 2, 6, // Opcode: BPFCCANT
/* 356 */     MCD_OPC_FilterValue, 1, 32, 29, 0, // Skip to: 7817
/* 361 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 364 */     MCD_OPC_FilterValue, 0, 25, 0, 0, // Skip to: 394
/* 369 */     MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 385
/* 374 */     MCD_OPC_CheckField, 20, 2, 0, 4, 0, 0, // Skip to: 385
/* 381 */     MCD_OPC_Decode, 246, 2, 1, // Opcode: FBCOND_V9
/* 385 */     MCD_OPC_CheckPredicate, 0, 3, 29, 0, // Skip to: 7817
/* 390 */     MCD_OPC_Decode, 188, 2, 6, // Opcode: BPFCC
/* 394 */     MCD_OPC_FilterValue, 1, 250, 28, 0, // Skip to: 7817
/* 399 */     MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 415
/* 404 */     MCD_OPC_CheckField, 20, 2, 0, 4, 0, 0, // Skip to: 415
/* 411 */     MCD_OPC_Decode, 245, 2, 1, // Opcode: FBCONDA_V9
/* 415 */     MCD_OPC_CheckPredicate, 0, 229, 28, 0, // Skip to: 7817
/* 420 */     MCD_OPC_Decode, 189, 2, 6, // Opcode: BPFCCA
/* 424 */     MCD_OPC_FilterValue, 6, 21, 0, 0, // Skip to: 450
/* 429 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 432 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 441
/* 437 */     MCD_OPC_Decode, 243, 2, 2, // Opcode: FBCOND
/* 441 */     MCD_OPC_FilterValue, 1, 203, 28, 0, // Skip to: 7817
/* 446 */     MCD_OPC_Decode, 244, 2, 2, // Opcode: FBCONDA
/* 450 */     MCD_OPC_FilterValue, 7, 194, 28, 0, // Skip to: 7817
/* 455 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 458 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 467
/* 463 */     MCD_OPC_Decode, 212, 2, 2, // Opcode: CBCOND
/* 467 */     MCD_OPC_FilterValue, 1, 177, 28, 0, // Skip to: 7817
/* 472 */     MCD_OPC_Decode, 213, 2, 2, // Opcode: CBCONDA
/* 476 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 485
/* 481 */     MCD_OPC_Decode, 205, 2, 7, // Opcode: CALL
/* 485 */     MCD_OPC_FilterValue, 2, 65, 22, 0, // Skip to: 6187
/* 490 */     MCD_OPC_ExtractField, 19, 6,  // Inst{24-19} ...
/* 493 */     MCD_OPC_FilterValue, 0, 28, 0, 0, // Skip to: 526
/* 498 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 501 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 517
/* 506 */     MCD_OPC_CheckField, 5, 8, 0, 136, 28, 0, // Skip to: 7817
/* 513 */     MCD_OPC_Decode, 169, 2, 8, // Opcode: ADDrr
/* 517 */     MCD_OPC_FilterValue, 1, 127, 28, 0, // Skip to: 7817
/* 522 */     MCD_OPC_Decode, 168, 2, 9, // Opcode: ADDri
/* 526 */     MCD_OPC_FilterValue, 1, 28, 0, 0, // Skip to: 559
/* 531 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 534 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 550
/* 539 */     MCD_OPC_CheckField, 5, 8, 0, 103, 28, 0, // Skip to: 7817
/* 546 */     MCD_OPC_Decode, 179, 2, 8, // Opcode: ANDrr
/* 550 */     MCD_OPC_FilterValue, 1, 94, 28, 0, // Skip to: 7817
/* 555 */     MCD_OPC_Decode, 178, 2, 9, // Opcode: ANDri
/* 559 */     MCD_OPC_FilterValue, 2, 28, 0, 0, // Skip to: 592
/* 564 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 567 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 583
/* 572 */     MCD_OPC_CheckField, 5, 8, 0, 70, 28, 0, // Skip to: 7817
/* 579 */     MCD_OPC_Decode, 218, 4, 8, // Opcode: ORrr
/* 583 */     MCD_OPC_FilterValue, 1, 61, 28, 0, // Skip to: 7817
/* 588 */     MCD_OPC_Decode, 217, 4, 9, // Opcode: ORri
/* 592 */     MCD_OPC_FilterValue, 3, 28, 0, 0, // Skip to: 625
/* 597 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 600 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 616
/* 605 */     MCD_OPC_CheckField, 5, 8, 0, 37, 28, 0, // Skip to: 7817
/* 612 */     MCD_OPC_Decode, 141, 6, 8, // Opcode: XORrr
/* 616 */     MCD_OPC_FilterValue, 1, 28, 28, 0, // Skip to: 7817
/* 621 */     MCD_OPC_Decode, 140, 6, 9, // Opcode: XORri
/* 625 */     MCD_OPC_FilterValue, 4, 28, 0, 0, // Skip to: 658
/* 630 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 633 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 649
/* 638 */     MCD_OPC_CheckField, 5, 8, 0, 4, 28, 0, // Skip to: 7817
/* 645 */     MCD_OPC_Decode, 197, 5, 8, // Opcode: SUBrr
/* 649 */     MCD_OPC_FilterValue, 1, 251, 27, 0, // Skip to: 7817
/* 654 */     MCD_OPC_Decode, 196, 5, 9, // Opcode: SUBri
/* 658 */     MCD_OPC_FilterValue, 5, 28, 0, 0, // Skip to: 691
/* 663 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 666 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 682
/* 671 */     MCD_OPC_CheckField, 5, 8, 0, 227, 27, 0, // Skip to: 7817
/* 678 */     MCD_OPC_Decode, 177, 2, 8, // Opcode: ANDNrr
/* 682 */     MCD_OPC_FilterValue, 1, 218, 27, 0, // Skip to: 7817
/* 687 */     MCD_OPC_Decode, 176, 2, 9, // Opcode: ANDNri
/* 691 */     MCD_OPC_FilterValue, 6, 28, 0, 0, // Skip to: 724
/* 696 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 699 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 715
/* 704 */     MCD_OPC_CheckField, 5, 8, 0, 194, 27, 0, // Skip to: 7817
/* 711 */     MCD_OPC_Decode, 216, 4, 8, // Opcode: ORNrr
/* 715 */     MCD_OPC_FilterValue, 1, 185, 27, 0, // Skip to: 7817
/* 720 */     MCD_OPC_Decode, 215, 4, 9, // Opcode: ORNri
/* 724 */     MCD_OPC_FilterValue, 7, 28, 0, 0, // Skip to: 757
/* 729 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 732 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 748
/* 737 */     MCD_OPC_CheckField, 5, 8, 0, 161, 27, 0, // Skip to: 7817
/* 744 */     MCD_OPC_Decode, 137, 6, 8, // Opcode: XNORrr
/* 748 */     MCD_OPC_FilterValue, 1, 152, 27, 0, // Skip to: 7817
/* 753 */     MCD_OPC_Decode, 136, 6, 9, // Opcode: XNORri
/* 757 */     MCD_OPC_FilterValue, 8, 28, 0, 0, // Skip to: 790
/* 762 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 765 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 781
/* 770 */     MCD_OPC_CheckField, 5, 8, 0, 128, 27, 0, // Skip to: 7817
/* 777 */     MCD_OPC_Decode, 163, 2, 8, // Opcode: ADDCrr
/* 781 */     MCD_OPC_FilterValue, 1, 119, 27, 0, // Skip to: 7817
/* 786 */     MCD_OPC_Decode, 162, 2, 9, // Opcode: ADDCri
/* 790 */     MCD_OPC_FilterValue, 9, 38, 0, 0, // Skip to: 833
/* 795 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 798 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 819
/* 803 */     MCD_OPC_CheckPredicate, 0, 97, 27, 0, // Skip to: 7817
/* 808 */     MCD_OPC_CheckField, 5, 8, 0, 90, 27, 0, // Skip to: 7817
/* 815 */     MCD_OPC_Decode, 209, 4, 10, // Opcode: MULXrr
/* 819 */     MCD_OPC_FilterValue, 1, 81, 27, 0, // Skip to: 7817
/* 824 */     MCD_OPC_CheckPredicate, 0, 76, 27, 0, // Skip to: 7817
/* 829 */     MCD_OPC_Decode, 208, 4, 11, // Opcode: MULXri
/* 833 */     MCD_OPC_FilterValue, 10, 28, 0, 0, // Skip to: 866
/* 838 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 841 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 857
/* 846 */     MCD_OPC_CheckField, 5, 8, 0, 52, 27, 0, // Skip to: 7817
/* 853 */     MCD_OPC_Decode, 237, 5, 8, // Opcode: UMULrr
/* 857 */     MCD_OPC_FilterValue, 1, 43, 27, 0, // Skip to: 7817
/* 862 */     MCD_OPC_Decode, 236, 5, 9, // Opcode: UMULri
/* 866 */     MCD_OPC_FilterValue, 11, 28, 0, 0, // Skip to: 899
/* 871 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 874 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 890
/* 879 */     MCD_OPC_CheckField, 5, 8, 0, 19, 27, 0, // Skip to: 7817
/* 886 */     MCD_OPC_Decode, 134, 5, 8, // Opcode: SMULrr
/* 890 */     MCD_OPC_FilterValue, 1, 10, 27, 0, // Skip to: 7817
/* 895 */     MCD_OPC_Decode, 133, 5, 9, // Opcode: SMULri
/* 899 */     MCD_OPC_FilterValue, 12, 28, 0, 0, // Skip to: 932
/* 904 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 907 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 923
/* 912 */     MCD_OPC_CheckField, 5, 8, 0, 242, 26, 0, // Skip to: 7817
/* 919 */     MCD_OPC_Decode, 193, 5, 8, // Opcode: SUBCrr
/* 923 */     MCD_OPC_FilterValue, 1, 233, 26, 0, // Skip to: 7817
/* 928 */     MCD_OPC_Decode, 192, 5, 9, // Opcode: SUBCri
/* 932 */     MCD_OPC_FilterValue, 13, 38, 0, 0, // Skip to: 975
/* 937 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 940 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 961
/* 945 */     MCD_OPC_CheckPredicate, 0, 211, 26, 0, // Skip to: 7817
/* 950 */     MCD_OPC_CheckField, 5, 8, 0, 204, 26, 0, // Skip to: 7817
/* 957 */     MCD_OPC_Decode, 228, 5, 10, // Opcode: UDIVXrr
/* 961 */     MCD_OPC_FilterValue, 1, 195, 26, 0, // Skip to: 7817
/* 966 */     MCD_OPC_CheckPredicate, 0, 190, 26, 0, // Skip to: 7817
/* 971 */     MCD_OPC_Decode, 227, 5, 11, // Opcode: UDIVXri
/* 975 */     MCD_OPC_FilterValue, 14, 28, 0, 0, // Skip to: 1008
/* 980 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 983 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 999
/* 988 */     MCD_OPC_CheckField, 5, 8, 0, 166, 26, 0, // Skip to: 7817
/* 995 */     MCD_OPC_Decode, 230, 5, 8, // Opcode: UDIVrr
/* 999 */     MCD_OPC_FilterValue, 1, 157, 26, 0, // Skip to: 7817
/* 1004 */    MCD_OPC_Decode, 229, 5, 9, // Opcode: UDIVri
/* 1008 */    MCD_OPC_FilterValue, 15, 28, 0, 0, // Skip to: 1041
/* 1013 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1016 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1032
/* 1021 */    MCD_OPC_CheckField, 5, 8, 0, 133, 26, 0, // Skip to: 7817
/* 1028 */    MCD_OPC_Decode, 248, 4, 8, // Opcode: SDIVrr
/* 1032 */    MCD_OPC_FilterValue, 1, 124, 26, 0, // Skip to: 7817
/* 1037 */    MCD_OPC_Decode, 247, 4, 9, // Opcode: SDIVri
/* 1041 */    MCD_OPC_FilterValue, 16, 28, 0, 0, // Skip to: 1074
/* 1046 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1049 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1065
/* 1054 */    MCD_OPC_CheckField, 5, 8, 0, 100, 26, 0, // Skip to: 7817
/* 1061 */    MCD_OPC_Decode, 161, 2, 8, // Opcode: ADDCCrr
/* 1065 */    MCD_OPC_FilterValue, 1, 91, 26, 0, // Skip to: 7817
/* 1070 */    MCD_OPC_Decode, 160, 2, 9, // Opcode: ADDCCri
/* 1074 */    MCD_OPC_FilterValue, 17, 28, 0, 0, // Skip to: 1107
/* 1079 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1082 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1098
/* 1087 */    MCD_OPC_CheckField, 5, 8, 0, 67, 26, 0, // Skip to: 7817
/* 1094 */    MCD_OPC_Decode, 173, 2, 8, // Opcode: ANDCCrr
/* 1098 */    MCD_OPC_FilterValue, 1, 58, 26, 0, // Skip to: 7817
/* 1103 */    MCD_OPC_Decode, 172, 2, 9, // Opcode: ANDCCri
/* 1107 */    MCD_OPC_FilterValue, 18, 28, 0, 0, // Skip to: 1140
/* 1112 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1115 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1131
/* 1120 */    MCD_OPC_CheckField, 5, 8, 0, 34, 26, 0, // Skip to: 7817
/* 1127 */    MCD_OPC_Decode, 212, 4, 8, // Opcode: ORCCrr
/* 1131 */    MCD_OPC_FilterValue, 1, 25, 26, 0, // Skip to: 7817
/* 1136 */    MCD_OPC_Decode, 211, 4, 9, // Opcode: ORCCri
/* 1140 */    MCD_OPC_FilterValue, 19, 28, 0, 0, // Skip to: 1173
/* 1145 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1148 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1164
/* 1153 */    MCD_OPC_CheckField, 5, 8, 0, 1, 26, 0, // Skip to: 7817
/* 1160 */    MCD_OPC_Decode, 139, 6, 8, // Opcode: XORCCrr
/* 1164 */    MCD_OPC_FilterValue, 1, 248, 25, 0, // Skip to: 7817
/* 1169 */    MCD_OPC_Decode, 138, 6, 9, // Opcode: XORCCri
/* 1173 */    MCD_OPC_FilterValue, 20, 28, 0, 0, // Skip to: 1206
/* 1178 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1181 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1197
/* 1186 */    MCD_OPC_CheckField, 5, 8, 0, 224, 25, 0, // Skip to: 7817
/* 1193 */    MCD_OPC_Decode, 191, 5, 8, // Opcode: SUBCCrr
/* 1197 */    MCD_OPC_FilterValue, 1, 215, 25, 0, // Skip to: 7817
/* 1202 */    MCD_OPC_Decode, 190, 5, 9, // Opcode: SUBCCri
/* 1206 */    MCD_OPC_FilterValue, 21, 28, 0, 0, // Skip to: 1239
/* 1211 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1214 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1230
/* 1219 */    MCD_OPC_CheckField, 5, 8, 0, 191, 25, 0, // Skip to: 7817
/* 1226 */    MCD_OPC_Decode, 175, 2, 8, // Opcode: ANDNCCrr
/* 1230 */    MCD_OPC_FilterValue, 1, 182, 25, 0, // Skip to: 7817
/* 1235 */    MCD_OPC_Decode, 174, 2, 9, // Opcode: ANDNCCri
/* 1239 */    MCD_OPC_FilterValue, 22, 28, 0, 0, // Skip to: 1272
/* 1244 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1247 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1263
/* 1252 */    MCD_OPC_CheckField, 5, 8, 0, 158, 25, 0, // Skip to: 7817
/* 1259 */    MCD_OPC_Decode, 214, 4, 8, // Opcode: ORNCCrr
/* 1263 */    MCD_OPC_FilterValue, 1, 149, 25, 0, // Skip to: 7817
/* 1268 */    MCD_OPC_Decode, 213, 4, 9, // Opcode: ORNCCri
/* 1272 */    MCD_OPC_FilterValue, 23, 28, 0, 0, // Skip to: 1305
/* 1277 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1280 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1296
/* 1285 */    MCD_OPC_CheckField, 5, 8, 0, 125, 25, 0, // Skip to: 7817
/* 1292 */    MCD_OPC_Decode, 135, 6, 8, // Opcode: XNORCCrr
/* 1296 */    MCD_OPC_FilterValue, 1, 116, 25, 0, // Skip to: 7817
/* 1301 */    MCD_OPC_Decode, 134, 6, 9, // Opcode: XNORCCri
/* 1305 */    MCD_OPC_FilterValue, 24, 28, 0, 0, // Skip to: 1338
/* 1310 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1313 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1329
/* 1318 */    MCD_OPC_CheckField, 5, 8, 0, 92, 25, 0, // Skip to: 7817
/* 1325 */    MCD_OPC_Decode, 165, 2, 8, // Opcode: ADDErr
/* 1329 */    MCD_OPC_FilterValue, 1, 83, 25, 0, // Skip to: 7817
/* 1334 */    MCD_OPC_Decode, 164, 2, 9, // Opcode: ADDEri
/* 1338 */    MCD_OPC_FilterValue, 26, 28, 0, 0, // Skip to: 1371
/* 1343 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1346 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1362
/* 1351 */    MCD_OPC_CheckField, 5, 8, 0, 59, 25, 0, // Skip to: 7817
/* 1358 */    MCD_OPC_Decode, 234, 5, 8, // Opcode: UMULCCrr
/* 1362 */    MCD_OPC_FilterValue, 1, 50, 25, 0, // Skip to: 7817
/* 1367 */    MCD_OPC_Decode, 233, 5, 9, // Opcode: UMULCCri
/* 1371 */    MCD_OPC_FilterValue, 27, 28, 0, 0, // Skip to: 1404
/* 1376 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1379 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1395
/* 1384 */    MCD_OPC_CheckField, 5, 8, 0, 26, 25, 0, // Skip to: 7817
/* 1391 */    MCD_OPC_Decode, 132, 5, 8, // Opcode: SMULCCrr
/* 1395 */    MCD_OPC_FilterValue, 1, 17, 25, 0, // Skip to: 7817
/* 1400 */    MCD_OPC_Decode, 131, 5, 9, // Opcode: SMULCCri
/* 1404 */    MCD_OPC_FilterValue, 28, 28, 0, 0, // Skip to: 1437
/* 1409 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1412 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1428
/* 1417 */    MCD_OPC_CheckField, 5, 8, 0, 249, 24, 0, // Skip to: 7817
/* 1424 */    MCD_OPC_Decode, 195, 5, 8, // Opcode: SUBErr
/* 1428 */    MCD_OPC_FilterValue, 1, 240, 24, 0, // Skip to: 7817
/* 1433 */    MCD_OPC_Decode, 194, 5, 9, // Opcode: SUBEri
/* 1437 */    MCD_OPC_FilterValue, 30, 28, 0, 0, // Skip to: 1470
/* 1442 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1445 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1461
/* 1450 */    MCD_OPC_CheckField, 5, 8, 0, 216, 24, 0, // Skip to: 7817
/* 1457 */    MCD_OPC_Decode, 226, 5, 8, // Opcode: UDIVCCrr
/* 1461 */    MCD_OPC_FilterValue, 1, 207, 24, 0, // Skip to: 7817
/* 1466 */    MCD_OPC_Decode, 225, 5, 9, // Opcode: UDIVCCri
/* 1470 */    MCD_OPC_FilterValue, 31, 28, 0, 0, // Skip to: 1503
/* 1475 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1478 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1494
/* 1483 */    MCD_OPC_CheckField, 5, 8, 0, 183, 24, 0, // Skip to: 7817
/* 1490 */    MCD_OPC_Decode, 244, 4, 8, // Opcode: SDIVCCrr
/* 1494 */    MCD_OPC_FilterValue, 1, 174, 24, 0, // Skip to: 7817
/* 1499 */    MCD_OPC_Decode, 243, 4, 9, // Opcode: SDIVCCri
/* 1503 */    MCD_OPC_FilterValue, 32, 28, 0, 0, // Skip to: 1536
/* 1508 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1511 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1527
/* 1516 */    MCD_OPC_CheckField, 5, 8, 0, 150, 24, 0, // Skip to: 7817
/* 1523 */    MCD_OPC_Decode, 208, 5, 8, // Opcode: TADDCCrr
/* 1527 */    MCD_OPC_FilterValue, 1, 141, 24, 0, // Skip to: 7817
/* 1532 */    MCD_OPC_Decode, 207, 5, 9, // Opcode: TADDCCri
/* 1536 */    MCD_OPC_FilterValue, 33, 28, 0, 0, // Skip to: 1569
/* 1541 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1544 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1560
/* 1549 */    MCD_OPC_CheckField, 5, 8, 0, 117, 24, 0, // Skip to: 7817
/* 1556 */    MCD_OPC_Decode, 222, 5, 8, // Opcode: TSUBCCrr
/* 1560 */    MCD_OPC_FilterValue, 1, 108, 24, 0, // Skip to: 7817
/* 1565 */    MCD_OPC_Decode, 221, 5, 9, // Opcode: TSUBCCri
/* 1569 */    MCD_OPC_FilterValue, 34, 28, 0, 0, // Skip to: 1602
/* 1574 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1577 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1593
/* 1582 */    MCD_OPC_CheckField, 5, 8, 0, 84, 24, 0, // Skip to: 7817
/* 1589 */    MCD_OPC_Decode, 206, 5, 8, // Opcode: TADDCCTVrr
/* 1593 */    MCD_OPC_FilterValue, 1, 75, 24, 0, // Skip to: 7817
/* 1598 */    MCD_OPC_Decode, 205, 5, 9, // Opcode: TADDCCTVri
/* 1602 */    MCD_OPC_FilterValue, 35, 28, 0, 0, // Skip to: 1635
/* 1607 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1610 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1626
/* 1615 */    MCD_OPC_CheckField, 5, 8, 0, 51, 24, 0, // Skip to: 7817
/* 1622 */    MCD_OPC_Decode, 220, 5, 8, // Opcode: TSUBCCTVrr
/* 1626 */    MCD_OPC_FilterValue, 1, 42, 24, 0, // Skip to: 7817
/* 1631 */    MCD_OPC_Decode, 219, 5, 9, // Opcode: TSUBCCTVri
/* 1635 */    MCD_OPC_FilterValue, 36, 28, 0, 0, // Skip to: 1668
/* 1640 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1643 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1659
/* 1648 */    MCD_OPC_CheckField, 5, 8, 0, 18, 24, 0, // Skip to: 7817
/* 1655 */    MCD_OPC_Decode, 207, 4, 8, // Opcode: MULSCCrr
/* 1659 */    MCD_OPC_FilterValue, 1, 9, 24, 0, // Skip to: 7817
/* 1664 */    MCD_OPC_Decode, 206, 4, 9, // Opcode: MULSCCri
/* 1668 */    MCD_OPC_FilterValue, 37, 49, 0, 0, // Skip to: 1722
/* 1673 */    MCD_OPC_ExtractField, 12, 2,  // Inst{13-12} ...
/* 1676 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1685
/* 1681 */    MCD_OPC_Decode, 128, 5, 8, // Opcode: SLLrr
/* 1685 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 1699
/* 1690 */    MCD_OPC_CheckPredicate, 0, 234, 23, 0, // Skip to: 7817
/* 1695 */    MCD_OPC_Decode, 254, 4, 12, // Opcode: SLLXrr
/* 1699 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1708
/* 1704 */    MCD_OPC_Decode, 255, 4, 13, // Opcode: SLLri
/* 1708 */    MCD_OPC_FilterValue, 3, 216, 23, 0, // Skip to: 7817
/* 1713 */    MCD_OPC_CheckPredicate, 0, 211, 23, 0, // Skip to: 7817
/* 1718 */    MCD_OPC_Decode, 253, 4, 14, // Opcode: SLLXri
/* 1722 */    MCD_OPC_FilterValue, 38, 49, 0, 0, // Skip to: 1776
/* 1727 */    MCD_OPC_ExtractField, 12, 2,  // Inst{13-12} ...
/* 1730 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1739
/* 1735 */    MCD_OPC_Decode, 142, 5, 8, // Opcode: SRLrr
/* 1739 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 1753
/* 1744 */    MCD_OPC_CheckPredicate, 0, 180, 23, 0, // Skip to: 7817
/* 1749 */    MCD_OPC_Decode, 140, 5, 12, // Opcode: SRLXrr
/* 1753 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1762
/* 1758 */    MCD_OPC_Decode, 141, 5, 13, // Opcode: SRLri
/* 1762 */    MCD_OPC_FilterValue, 3, 162, 23, 0, // Skip to: 7817
/* 1767 */    MCD_OPC_CheckPredicate, 0, 157, 23, 0, // Skip to: 7817
/* 1772 */    MCD_OPC_Decode, 139, 5, 14, // Opcode: SRLXri
/* 1776 */    MCD_OPC_FilterValue, 39, 49, 0, 0, // Skip to: 1830
/* 1781 */    MCD_OPC_ExtractField, 12, 2,  // Inst{13-12} ...
/* 1784 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1793
/* 1789 */    MCD_OPC_Decode, 138, 5, 8, // Opcode: SRArr
/* 1793 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 1807
/* 1798 */    MCD_OPC_CheckPredicate, 0, 126, 23, 0, // Skip to: 7817
/* 1803 */    MCD_OPC_Decode, 136, 5, 12, // Opcode: SRAXrr
/* 1807 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1816
/* 1812 */    MCD_OPC_Decode, 137, 5, 13, // Opcode: SRAri
/* 1816 */    MCD_OPC_FilterValue, 3, 108, 23, 0, // Skip to: 7817
/* 1821 */    MCD_OPC_CheckPredicate, 0, 103, 23, 0, // Skip to: 7817
/* 1826 */    MCD_OPC_Decode, 135, 5, 14, // Opcode: SRAXri
/* 1830 */    MCD_OPC_FilterValue, 40, 66, 0, 0, // Skip to: 1901
/* 1835 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1838 */    MCD_OPC_FilterValue, 0, 30, 0, 0, // Skip to: 1873
/* 1843 */    MCD_OPC_ExtractField, 0, 13,  // Inst{12-0} ...
/* 1846 */    MCD_OPC_FilterValue, 0, 78, 23, 0, // Skip to: 7817
/* 1851 */    MCD_OPC_CheckField, 25, 5, 0, 11, 0, 0, // Skip to: 1869
/* 1858 */    MCD_OPC_CheckField, 14, 5, 15, 4, 0, 0, // Skip to: 1869
/* 1865 */    MCD_OPC_Decode, 145, 5, 4, // Opcode: STBAR
/* 1869 */    MCD_OPC_Decode, 226, 4, 15, // Opcode: RDASR
/* 1873 */    MCD_OPC_FilterValue, 1, 51, 23, 0, // Skip to: 7817
/* 1878 */    MCD_OPC_CheckPredicate, 0, 46, 23, 0, // Skip to: 7817
/* 1883 */    MCD_OPC_CheckField, 25, 5, 0, 39, 23, 0, // Skip to: 7817
/* 1890 */    MCD_OPC_CheckField, 14, 5, 15, 32, 23, 0, // Skip to: 7817
/* 1897 */    MCD_OPC_Decode, 192, 4, 16, // Opcode: MEMBARi
/* 1901 */    MCD_OPC_FilterValue, 41, 11, 0, 0, // Skip to: 1917
/* 1906 */    MCD_OPC_CheckField, 0, 19, 0, 16, 23, 0, // Skip to: 7817
/* 1913 */    MCD_OPC_Decode, 229, 4, 17, // Opcode: RDPSR
/* 1917 */    MCD_OPC_FilterValue, 42, 43, 0, 0, // Skip to: 1965
/* 1922 */    MCD_OPC_ExtractField, 0, 14,  // Inst{13-0} ...
/* 1925 */    MCD_OPC_FilterValue, 0, 255, 22, 0, // Skip to: 7817
/* 1930 */    MCD_OPC_ExtractField, 14, 5,  // Inst{18-14} ...
/* 1933 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1942
/* 1938 */    MCD_OPC_Decode, 231, 4, 17, // Opcode: RDWIM
/* 1942 */    MCD_OPC_FilterValue, 15, 9, 0, 0, // Skip to: 1956
/* 1947 */    MCD_OPC_CheckPredicate, 0, 4, 0, 0, // Skip to: 1956
/* 1952 */    MCD_OPC_Decode, 227, 4, 17, // Opcode: RDFQ
/* 1956 */    MCD_OPC_CheckPredicate, 0, 224, 22, 0, // Skip to: 7817
/* 1961 */    MCD_OPC_Decode, 228, 4, 18, // Opcode: RDPR
/* 1965 */    MCD_OPC_FilterValue, 43, 28, 0, 0, // Skip to: 1998
/* 1970 */    MCD_OPC_ExtractField, 0, 19,  // Inst{18-0} ...
/* 1973 */    MCD_OPC_FilterValue, 0, 207, 22, 0, // Skip to: 7817
/* 1978 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 1994
/* 1983 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 1994
/* 1990 */    MCD_OPC_Decode, 153, 3, 4, // Opcode: FLUSHW
/* 1994 */    MCD_OPC_Decode, 230, 4, 17, // Opcode: RDTBR
/* 1998 */    MCD_OPC_FilterValue, 44, 151, 0, 0, // Skip to: 2154
/* 2003 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2006 */    MCD_OPC_FilterValue, 0, 69, 0, 0, // Skip to: 2080
/* 2011 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 2014 */    MCD_OPC_FilterValue, 0, 25, 0, 0, // Skip to: 2044
/* 2019 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 2035
/* 2024 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 2035
/* 2031 */    MCD_OPC_Decode, 195, 4, 19, // Opcode: MOVFCCrr
/* 2035 */    MCD_OPC_CheckPredicate, 0, 145, 22, 0, // Skip to: 7817
/* 2040 */    MCD_OPC_Decode, 249, 5, 20, // Opcode: V9MOVFCCrr
/* 2044 */    MCD_OPC_FilterValue, 1, 136, 22, 0, // Skip to: 7817
/* 2049 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 2052 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 2066
/* 2057 */    MCD_OPC_CheckPredicate, 0, 123, 22, 0, // Skip to: 7817
/* 2062 */    MCD_OPC_Decode, 197, 4, 19, // Opcode: MOVICCrr
/* 2066 */    MCD_OPC_FilterValue, 2, 114, 22, 0, // Skip to: 7817
/* 2071 */    MCD_OPC_CheckPredicate, 0, 109, 22, 0, // Skip to: 7817
/* 2076 */    MCD_OPC_Decode, 204, 4, 19, // Opcode: MOVXCCrr
/* 2080 */    MCD_OPC_FilterValue, 1, 100, 22, 0, // Skip to: 7817
/* 2085 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 2088 */    MCD_OPC_FilterValue, 0, 25, 0, 0, // Skip to: 2118
/* 2093 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 2109
/* 2098 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 2109
/* 2105 */    MCD_OPC_Decode, 194, 4, 21, // Opcode: MOVFCCri
/* 2109 */    MCD_OPC_CheckPredicate, 0, 71, 22, 0, // Skip to: 7817
/* 2114 */    MCD_OPC_Decode, 248, 5, 22, // Opcode: V9MOVFCCri
/* 2118 */    MCD_OPC_FilterValue, 1, 62, 22, 0, // Skip to: 7817
/* 2123 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 2126 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 2140
/* 2131 */    MCD_OPC_CheckPredicate, 0, 49, 22, 0, // Skip to: 7817
/* 2136 */    MCD_OPC_Decode, 196, 4, 21, // Opcode: MOVICCri
/* 2140 */    MCD_OPC_FilterValue, 2, 40, 22, 0, // Skip to: 7817
/* 2145 */    MCD_OPC_CheckPredicate, 0, 35, 22, 0, // Skip to: 7817
/* 2150 */    MCD_OPC_Decode, 203, 4, 21, // Opcode: MOVXCCri
/* 2154 */    MCD_OPC_FilterValue, 45, 38, 0, 0, // Skip to: 2197
/* 2159 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2162 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 2183
/* 2167 */    MCD_OPC_CheckPredicate, 0, 13, 22, 0, // Skip to: 7817
/* 2172 */    MCD_OPC_CheckField, 5, 8, 0, 6, 22, 0, // Skip to: 7817
/* 2179 */    MCD_OPC_Decode, 246, 4, 10, // Opcode: SDIVXrr
/* 2183 */    MCD_OPC_FilterValue, 1, 253, 21, 0, // Skip to: 7817
/* 2188 */    MCD_OPC_CheckPredicate, 0, 248, 21, 0, // Skip to: 7817
/* 2193 */    MCD_OPC_Decode, 245, 4, 11, // Opcode: SDIVXri
/* 2197 */    MCD_OPC_FilterValue, 46, 16, 0, 0, // Skip to: 2218
/* 2202 */    MCD_OPC_CheckPredicate, 0, 234, 21, 0, // Skip to: 7817
/* 2207 */    MCD_OPC_CheckField, 5, 14, 0, 227, 21, 0, // Skip to: 7817
/* 2214 */    MCD_OPC_Decode, 221, 4, 23, // Opcode: POPCrr
/* 2218 */    MCD_OPC_FilterValue, 47, 38, 0, 0, // Skip to: 2261
/* 2223 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2226 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 2247
/* 2231 */    MCD_OPC_CheckPredicate, 0, 205, 21, 0, // Skip to: 7817
/* 2236 */    MCD_OPC_CheckField, 5, 5, 0, 198, 21, 0, // Skip to: 7817
/* 2243 */    MCD_OPC_Decode, 199, 4, 24, // Opcode: MOVRrr
/* 2247 */    MCD_OPC_FilterValue, 1, 189, 21, 0, // Skip to: 7817
/* 2252 */    MCD_OPC_CheckPredicate, 0, 184, 21, 0, // Skip to: 7817
/* 2257 */    MCD_OPC_Decode, 198, 4, 25, // Opcode: MOVRri
/* 2261 */    MCD_OPC_FilterValue, 48, 51, 0, 0, // Skip to: 2317
/* 2266 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2269 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2285
/* 2274 */    MCD_OPC_CheckField, 5, 8, 0, 160, 21, 0, // Skip to: 7817
/* 2281 */    MCD_OPC_Decode, 251, 5, 26, // Opcode: WRASRrr
/* 2285 */    MCD_OPC_FilterValue, 1, 151, 21, 0, // Skip to: 7817
/* 2290 */    MCD_OPC_CheckPredicate, 0, 18, 0, 0, // Skip to: 2313
/* 2295 */    MCD_OPC_CheckField, 25, 5, 15, 11, 0, 0, // Skip to: 2313
/* 2302 */    MCD_OPC_CheckField, 14, 5, 0, 4, 0, 0, // Skip to: 2313
/* 2309 */    MCD_OPC_Decode, 252, 4, 27, // Opcode: SIR
/* 2313 */    MCD_OPC_Decode, 250, 5, 28, // Opcode: WRASRri
/* 2317 */    MCD_OPC_FilterValue, 49, 127, 0, 0, // Skip to: 2449
/* 2322 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2325 */    MCD_OPC_FilterValue, 0, 88, 0, 0, // Skip to: 2418
/* 2330 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 2333 */    MCD_OPC_FilterValue, 0, 35, 0, 0, // Skip to: 2373
/* 2338 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 2341 */    MCD_OPC_FilterValue, 0, 95, 21, 0, // Skip to: 7817
/* 2346 */    MCD_OPC_CheckPredicate, 0, 18, 0, 0, // Skip to: 2369
/* 2351 */    MCD_OPC_CheckField, 14, 5, 0, 11, 0, 0, // Skip to: 2369
/* 2358 */    MCD_OPC_CheckField, 0, 5, 0, 4, 0, 0, // Skip to: 2369
/* 2365 */    MCD_OPC_Decode, 240, 4, 4, // Opcode: SAVED
/* 2369 */    MCD_OPC_Decode, 255, 5, 29, // Opcode: WRPSRrr
/* 2373 */    MCD_OPC_FilterValue, 1, 63, 21, 0, // Skip to: 7817
/* 2378 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 2381 */    MCD_OPC_FilterValue, 0, 55, 21, 0, // Skip to: 7817
/* 2386 */    MCD_OPC_CheckPredicate, 0, 18, 0, 0, // Skip to: 2409
/* 2391 */    MCD_OPC_CheckField, 14, 5, 0, 11, 0, 0, // Skip to: 2409
/* 2398 */    MCD_OPC_CheckField, 0, 5, 0, 4, 0, 0, // Skip to: 2409
/* 2405 */    MCD_OPC_Decode, 232, 4, 4, // Opcode: RESTORED
/* 2409 */    MCD_OPC_CheckPredicate, 1, 27, 21, 0, // Skip to: 7817
/* 2414 */    MCD_OPC_Decode, 225, 4, 29, // Opcode: PWRPSRrr
/* 2418 */    MCD_OPC_FilterValue, 1, 18, 21, 0, // Skip to: 7817
/* 2423 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 2426 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2435
/* 2431 */    MCD_OPC_Decode, 254, 5, 30, // Opcode: WRPSRri
/* 2435 */    MCD_OPC_FilterValue, 1, 1, 21, 0, // Skip to: 7817
/* 2440 */    MCD_OPC_CheckPredicate, 1, 252, 20, 0, // Skip to: 7817
/* 2445 */    MCD_OPC_Decode, 224, 4, 30, // Opcode: PWRPSRri
/* 2449 */    MCD_OPC_FilterValue, 50, 61, 0, 0, // Skip to: 2515
/* 2454 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2457 */    MCD_OPC_FilterValue, 0, 28, 0, 0, // Skip to: 2490
/* 2462 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 2465 */    MCD_OPC_FilterValue, 0, 227, 20, 0, // Skip to: 7817
/* 2470 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 2481
/* 2477 */    MCD_OPC_Decode, 131, 6, 29, // Opcode: WRWIMrr
/* 2481 */    MCD_OPC_CheckPredicate, 0, 211, 20, 0, // Skip to: 7817
/* 2486 */    MCD_OPC_Decode, 253, 5, 31, // Opcode: WRPRrr
/* 2490 */    MCD_OPC_FilterValue, 1, 202, 20, 0, // Skip to: 7817
/* 2495 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 2506
/* 2502 */    MCD_OPC_Decode, 130, 6, 30, // Opcode: WRWIMri
/* 2506 */    MCD_OPC_CheckPredicate, 0, 186, 20, 0, // Skip to: 7817
/* 2511 */    MCD_OPC_Decode, 252, 5, 32, // Opcode: WRPRri
/* 2515 */    MCD_OPC_FilterValue, 51, 42, 0, 0, // Skip to: 2562
/* 2520 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2523 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 2546
/* 2528 */    MCD_OPC_CheckField, 25, 5, 0, 162, 20, 0, // Skip to: 7817
/* 2535 */    MCD_OPC_CheckField, 5, 8, 0, 155, 20, 0, // Skip to: 7817
/* 2542 */    MCD_OPC_Decode, 129, 6, 29, // Opcode: WRTBRrr
/* 2546 */    MCD_OPC_FilterValue, 1, 146, 20, 0, // Skip to: 7817
/* 2551 */    MCD_OPC_CheckField, 25, 5, 0, 139, 20, 0, // Skip to: 7817
/* 2558 */    MCD_OPC_Decode, 128, 6, 30, // Opcode: WRTBRri
/* 2562 */    MCD_OPC_FilterValue, 52, 73, 3, 0, // Skip to: 3408
/* 2567 */    MCD_OPC_ExtractField, 5, 9,  // Inst{13-5} ...
/* 2570 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 2586
/* 2575 */    MCD_OPC_CheckField, 14, 5, 0, 115, 20, 0, // Skip to: 7817
/* 2582 */    MCD_OPC_Decode, 168, 3, 33, // Opcode: FMOVS
/* 2586 */    MCD_OPC_FilterValue, 2, 16, 0, 0, // Skip to: 2607
/* 2591 */    MCD_OPC_CheckPredicate, 0, 101, 20, 0, // Skip to: 7817
/* 2596 */    MCD_OPC_CheckField, 14, 5, 0, 94, 20, 0, // Skip to: 7817
/* 2603 */    MCD_OPC_Decode, 157, 3, 34, // Opcode: FMOVD
/* 2607 */    MCD_OPC_FilterValue, 3, 16, 0, 0, // Skip to: 2628
/* 2612 */    MCD_OPC_CheckPredicate, 0, 80, 20, 0, // Skip to: 7817
/* 2617 */    MCD_OPC_CheckField, 14, 5, 0, 73, 20, 0, // Skip to: 7817
/* 2624 */    MCD_OPC_Decode, 161, 3, 35, // Opcode: FMOVQ
/* 2628 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 2644
/* 2633 */    MCD_OPC_CheckField, 14, 5, 0, 57, 20, 0, // Skip to: 7817
/* 2640 */    MCD_OPC_Decode, 188, 3, 33, // Opcode: FNEGS
/* 2644 */    MCD_OPC_FilterValue, 6, 16, 0, 0, // Skip to: 2665
/* 2649 */    MCD_OPC_CheckPredicate, 0, 43, 20, 0, // Skip to: 7817
/* 2654 */    MCD_OPC_CheckField, 14, 5, 0, 36, 20, 0, // Skip to: 7817
/* 2661 */    MCD_OPC_Decode, 186, 3, 34, // Opcode: FNEGD
/* 2665 */    MCD_OPC_FilterValue, 7, 16, 0, 0, // Skip to: 2686
/* 2670 */    MCD_OPC_CheckPredicate, 0, 22, 20, 0, // Skip to: 7817
/* 2675 */    MCD_OPC_CheckField, 14, 5, 0, 15, 20, 0, // Skip to: 7817
/* 2682 */    MCD_OPC_Decode, 187, 3, 35, // Opcode: FNEGQ
/* 2686 */    MCD_OPC_FilterValue, 9, 11, 0, 0, // Skip to: 2702
/* 2691 */    MCD_OPC_CheckField, 14, 5, 0, 255, 19, 0, // Skip to: 7817
/* 2698 */    MCD_OPC_Decode, 232, 2, 33, // Opcode: FABSS
/* 2702 */    MCD_OPC_FilterValue, 10, 16, 0, 0, // Skip to: 2723
/* 2707 */    MCD_OPC_CheckPredicate, 0, 241, 19, 0, // Skip to: 7817
/* 2712 */    MCD_OPC_CheckField, 14, 5, 0, 234, 19, 0, // Skip to: 7817
/* 2719 */    MCD_OPC_Decode, 230, 2, 34, // Opcode: FABSD
/* 2723 */    MCD_OPC_FilterValue, 11, 16, 0, 0, // Skip to: 2744
/* 2728 */    MCD_OPC_CheckPredicate, 0, 220, 19, 0, // Skip to: 7817
/* 2733 */    MCD_OPC_CheckField, 14, 5, 0, 213, 19, 0, // Skip to: 7817
/* 2740 */    MCD_OPC_Decode, 231, 2, 35, // Opcode: FABSQ
/* 2744 */    MCD_OPC_FilterValue, 41, 11, 0, 0, // Skip to: 2760
/* 2749 */    MCD_OPC_CheckField, 14, 5, 0, 197, 19, 0, // Skip to: 7817
/* 2756 */    MCD_OPC_Decode, 232, 3, 33, // Opcode: FSQRTS
/* 2760 */    MCD_OPC_FilterValue, 42, 11, 0, 0, // Skip to: 2776
/* 2765 */    MCD_OPC_CheckField, 14, 5, 0, 181, 19, 0, // Skip to: 7817
/* 2772 */    MCD_OPC_Decode, 230, 3, 34, // Opcode: FSQRTD
/* 2776 */    MCD_OPC_FilterValue, 43, 11, 0, 0, // Skip to: 2792
/* 2781 */    MCD_OPC_CheckField, 14, 5, 0, 165, 19, 0, // Skip to: 7817
/* 2788 */    MCD_OPC_Decode, 231, 3, 35, // Opcode: FSQRTQ
/* 2792 */    MCD_OPC_FilterValue, 65, 4, 0, 0, // Skip to: 2801
/* 2797 */    MCD_OPC_Decode, 235, 2, 36, // Opcode: FADDS
/* 2801 */    MCD_OPC_FilterValue, 66, 4, 0, 0, // Skip to: 2810
/* 2806 */    MCD_OPC_Decode, 233, 2, 37, // Opcode: FADDD
/* 2810 */    MCD_OPC_FilterValue, 67, 4, 0, 0, // Skip to: 2819
/* 2815 */    MCD_OPC_Decode, 234, 2, 38, // Opcode: FADDQ
/* 2819 */    MCD_OPC_FilterValue, 69, 4, 0, 0, // Skip to: 2828
/* 2824 */    MCD_OPC_Decode, 247, 3, 36, // Opcode: FSUBS
/* 2828 */    MCD_OPC_FilterValue, 70, 4, 0, 0, // Skip to: 2837
/* 2833 */    MCD_OPC_Decode, 245, 3, 37, // Opcode: FSUBD
/* 2837 */    MCD_OPC_FilterValue, 71, 4, 0, 0, // Skip to: 2846
/* 2842 */    MCD_OPC_Decode, 246, 3, 38, // Opcode: FSUBQ
/* 2846 */    MCD_OPC_FilterValue, 73, 4, 0, 0, // Skip to: 2855
/* 2851 */    MCD_OPC_Decode, 181, 3, 36, // Opcode: FMULS
/* 2855 */    MCD_OPC_FilterValue, 74, 4, 0, 0, // Skip to: 2864
/* 2860 */    MCD_OPC_Decode, 177, 3, 37, // Opcode: FMULD
/* 2864 */    MCD_OPC_FilterValue, 75, 4, 0, 0, // Skip to: 2873
/* 2869 */    MCD_OPC_Decode, 180, 3, 38, // Opcode: FMULQ
/* 2873 */    MCD_OPC_FilterValue, 77, 4, 0, 0, // Skip to: 2882
/* 2878 */    MCD_OPC_Decode, 136, 3, 36, // Opcode: FDIVS
/* 2882 */    MCD_OPC_FilterValue, 78, 4, 0, 0, // Skip to: 2891
/* 2887 */    MCD_OPC_Decode, 134, 3, 37, // Opcode: FDIVD
/* 2891 */    MCD_OPC_FilterValue, 79, 4, 0, 0, // Skip to: 2900
/* 2896 */    MCD_OPC_Decode, 135, 3, 38, // Opcode: FDIVQ
/* 2900 */    MCD_OPC_FilterValue, 81, 9, 0, 0, // Skip to: 2914
/* 2905 */    MCD_OPC_CheckPredicate, 2, 43, 19, 0, // Skip to: 7817
/* 2910 */    MCD_OPC_Decode, 183, 3, 36, // Opcode: FNADDS
/* 2914 */    MCD_OPC_FilterValue, 82, 9, 0, 0, // Skip to: 2928
/* 2919 */    MCD_OPC_CheckPredicate, 2, 29, 19, 0, // Skip to: 7817
/* 2924 */    MCD_OPC_Decode, 182, 3, 37, // Opcode: FNADDD
/* 2928 */    MCD_OPC_FilterValue, 89, 9, 0, 0, // Skip to: 2942
/* 2933 */    MCD_OPC_CheckPredicate, 2, 15, 19, 0, // Skip to: 7817
/* 2938 */    MCD_OPC_Decode, 192, 3, 36, // Opcode: FNMULS
/* 2942 */    MCD_OPC_FilterValue, 90, 9, 0, 0, // Skip to: 2956
/* 2947 */    MCD_OPC_CheckPredicate, 2, 1, 19, 0, // Skip to: 7817
/* 2952 */    MCD_OPC_Decode, 191, 3, 37, // Opcode: FNMULD
/* 2956 */    MCD_OPC_FilterValue, 97, 9, 0, 0, // Skip to: 2970
/* 2961 */    MCD_OPC_CheckPredicate, 2, 243, 18, 0, // Skip to: 7817
/* 2966 */    MCD_OPC_Decode, 144, 3, 36, // Opcode: FHADDS
/* 2970 */    MCD_OPC_FilterValue, 98, 9, 0, 0, // Skip to: 2984
/* 2975 */    MCD_OPC_CheckPredicate, 2, 229, 18, 0, // Skip to: 7817
/* 2980 */    MCD_OPC_Decode, 143, 3, 37, // Opcode: FHADDD
/* 2984 */    MCD_OPC_FilterValue, 101, 9, 0, 0, // Skip to: 2998
/* 2989 */    MCD_OPC_CheckPredicate, 2, 215, 18, 0, // Skip to: 7817
/* 2994 */    MCD_OPC_Decode, 146, 3, 36, // Opcode: FHSUBS
/* 2998 */    MCD_OPC_FilterValue, 102, 9, 0, 0, // Skip to: 3012
/* 3003 */    MCD_OPC_CheckPredicate, 2, 201, 18, 0, // Skip to: 7817
/* 3008 */    MCD_OPC_Decode, 145, 3, 37, // Opcode: FHSUBD
/* 3012 */    MCD_OPC_FilterValue, 105, 4, 0, 0, // Skip to: 3021
/* 3017 */    MCD_OPC_Decode, 229, 3, 39, // Opcode: FSMULD
/* 3021 */    MCD_OPC_FilterValue, 110, 4, 0, 0, // Skip to: 3030
/* 3026 */    MCD_OPC_Decode, 137, 3, 40, // Opcode: FDMULQ
/* 3030 */    MCD_OPC_FilterValue, 113, 9, 0, 0, // Skip to: 3044
/* 3035 */    MCD_OPC_CheckPredicate, 2, 169, 18, 0, // Skip to: 7817
/* 3040 */    MCD_OPC_Decode, 190, 3, 36, // Opcode: FNHADDS
/* 3044 */    MCD_OPC_FilterValue, 114, 9, 0, 0, // Skip to: 3058
/* 3049 */    MCD_OPC_CheckPredicate, 2, 155, 18, 0, // Skip to: 7817
/* 3054 */    MCD_OPC_Decode, 189, 3, 37, // Opcode: FNHADDD
/* 3058 */    MCD_OPC_FilterValue, 121, 9, 0, 0, // Skip to: 3072
/* 3063 */    MCD_OPC_CheckPredicate, 2, 141, 18, 0, // Skip to: 7817
/* 3068 */    MCD_OPC_Decode, 199, 3, 39, // Opcode: FNSMULD
/* 3072 */    MCD_OPC_FilterValue, 129, 1, 16, 0, 0, // Skip to: 3094
/* 3078 */    MCD_OPC_CheckPredicate, 0, 126, 18, 0, // Skip to: 7817
/* 3083 */    MCD_OPC_CheckField, 14, 5, 0, 119, 18, 0, // Skip to: 7817
/* 3090 */    MCD_OPC_Decode, 244, 3, 41, // Opcode: FSTOX
/* 3094 */    MCD_OPC_FilterValue, 130, 1, 16, 0, 0, // Skip to: 3116
/* 3100 */    MCD_OPC_CheckPredicate, 0, 104, 18, 0, // Skip to: 7817
/* 3105 */    MCD_OPC_CheckField, 14, 5, 0, 97, 18, 0, // Skip to: 7817
/* 3112 */    MCD_OPC_Decode, 141, 3, 34, // Opcode: FDTOX
/* 3116 */    MCD_OPC_FilterValue, 131, 1, 16, 0, 0, // Skip to: 3138
/* 3122 */    MCD_OPC_CheckPredicate, 0, 82, 18, 0, // Skip to: 7817
/* 3127 */    MCD_OPC_CheckField, 14, 5, 0, 75, 18, 0, // Skip to: 7817
/* 3134 */    MCD_OPC_Decode, 224, 3, 42, // Opcode: FQTOX
/* 3138 */    MCD_OPC_FilterValue, 132, 1, 16, 0, 0, // Skip to: 3160
/* 3144 */    MCD_OPC_CheckPredicate, 0, 60, 18, 0, // Skip to: 7817
/* 3149 */    MCD_OPC_CheckField, 14, 5, 0, 53, 18, 0, // Skip to: 7817
/* 3156 */    MCD_OPC_Decode, 254, 3, 43, // Opcode: FXTOS
/* 3160 */    MCD_OPC_FilterValue, 136, 1, 16, 0, 0, // Skip to: 3182
/* 3166 */    MCD_OPC_CheckPredicate, 0, 38, 18, 0, // Skip to: 7817
/* 3171 */    MCD_OPC_CheckField, 14, 5, 0, 31, 18, 0, // Skip to: 7817
/* 3178 */    MCD_OPC_Decode, 252, 3, 34, // Opcode: FXTOD
/* 3182 */    MCD_OPC_FilterValue, 140, 1, 16, 0, 0, // Skip to: 3204
/* 3188 */    MCD_OPC_CheckPredicate, 0, 16, 18, 0, // Skip to: 7817
/* 3193 */    MCD_OPC_CheckField, 14, 5, 0, 9, 18, 0, // Skip to: 7817
/* 3200 */    MCD_OPC_Decode, 253, 3, 44, // Opcode: FXTOQ
/* 3204 */    MCD_OPC_FilterValue, 196, 1, 11, 0, 0, // Skip to: 3221
/* 3210 */    MCD_OPC_CheckField, 14, 5, 0, 248, 17, 0, // Skip to: 7817
/* 3217 */    MCD_OPC_Decode, 149, 3, 33, // Opcode: FITOS
/* 3221 */    MCD_OPC_FilterValue, 198, 1, 11, 0, 0, // Skip to: 3238
/* 3227 */    MCD_OPC_CheckField, 14, 5, 0, 231, 17, 0, // Skip to: 7817
/* 3234 */    MCD_OPC_Decode, 140, 3, 43, // Opcode: FDTOS
/* 3238 */    MCD_OPC_FilterValue, 199, 1, 11, 0, 0, // Skip to: 3255
/* 3244 */    MCD_OPC_CheckField, 14, 5, 0, 214, 17, 0, // Skip to: 7817
/* 3251 */    MCD_OPC_Decode, 223, 3, 45, // Opcode: FQTOS
/* 3255 */    MCD_OPC_FilterValue, 200, 1, 11, 0, 0, // Skip to: 3272
/* 3261 */    MCD_OPC_CheckField, 14, 5, 0, 197, 17, 0, // Skip to: 7817
/* 3268 */    MCD_OPC_Decode, 147, 3, 41, // Opcode: FITOD
/* 3272 */    MCD_OPC_FilterValue, 201, 1, 11, 0, 0, // Skip to: 3289
/* 3278 */    MCD_OPC_CheckField, 14, 5, 0, 180, 17, 0, // Skip to: 7817
/* 3285 */    MCD_OPC_Decode, 241, 3, 41, // Opcode: FSTOD
/* 3289 */    MCD_OPC_FilterValue, 203, 1, 11, 0, 0, // Skip to: 3306
/* 3295 */    MCD_OPC_CheckField, 14, 5, 0, 163, 17, 0, // Skip to: 7817
/* 3302 */    MCD_OPC_Decode, 221, 3, 42, // Opcode: FQTOD
/* 3306 */    MCD_OPC_FilterValue, 204, 1, 11, 0, 0, // Skip to: 3323
/* 3312 */    MCD_OPC_CheckField, 14, 5, 0, 146, 17, 0, // Skip to: 7817
/* 3319 */    MCD_OPC_Decode, 148, 3, 46, // Opcode: FITOQ
/* 3323 */    MCD_OPC_FilterValue, 205, 1, 11, 0, 0, // Skip to: 3340
/* 3329 */    MCD_OPC_CheckField, 14, 5, 0, 129, 17, 0, // Skip to: 7817
/* 3336 */    MCD_OPC_Decode, 243, 3, 46, // Opcode: FSTOQ
/* 3340 */    MCD_OPC_FilterValue, 206, 1, 11, 0, 0, // Skip to: 3357
/* 3346 */    MCD_OPC_CheckField, 14, 5, 0, 112, 17, 0, // Skip to: 7817
/* 3353 */    MCD_OPC_Decode, 139, 3, 44, // Opcode: FDTOQ
/* 3357 */    MCD_OPC_FilterValue, 209, 1, 11, 0, 0, // Skip to: 3374
/* 3363 */    MCD_OPC_CheckField, 14, 5, 0, 95, 17, 0, // Skip to: 7817
/* 3370 */    MCD_OPC_Decode, 242, 3, 33, // Opcode: FSTOI
/* 3374 */    MCD_OPC_FilterValue, 210, 1, 11, 0, 0, // Skip to: 3391
/* 3380 */    MCD_OPC_CheckField, 14, 5, 0, 78, 17, 0, // Skip to: 7817
/* 3387 */    MCD_OPC_Decode, 138, 3, 43, // Opcode: FDTOI
/* 3391 */    MCD_OPC_FilterValue, 211, 1, 68, 17, 0, // Skip to: 7817
/* 3397 */    MCD_OPC_CheckField, 14, 5, 0, 61, 17, 0, // Skip to: 7817
/* 3404 */    MCD_OPC_Decode, 222, 3, 45, // Opcode: FQTOI
/* 3408 */    MCD_OPC_FilterValue, 53, 213, 1, 0, // Skip to: 3882
/* 3413 */    MCD_OPC_ExtractField, 5, 5,  // Inst{9-5} ...
/* 3416 */    MCD_OPC_FilterValue, 1, 99, 0, 0, // Skip to: 3520
/* 3421 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 3424 */    MCD_OPC_FilterValue, 0, 41, 0, 0, // Skip to: 3470
/* 3429 */    MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 3432 */    MCD_OPC_FilterValue, 0, 28, 17, 0, // Skip to: 7817
/* 3437 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 3440 */    MCD_OPC_FilterValue, 0, 20, 17, 0, // Skip to: 7817
/* 3445 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 3461
/* 3450 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 3461
/* 3457 */    MCD_OPC_Decode, 169, 3, 47, // Opcode: FMOVS_FCC
/* 3461 */    MCD_OPC_CheckPredicate, 0, 255, 16, 0, // Skip to: 7817
/* 3466 */    MCD_OPC_Decode, 247, 5, 48, // Opcode: V9FMOVS_FCC
/* 3470 */    MCD_OPC_FilterValue, 1, 246, 16, 0, // Skip to: 7817
/* 3475 */    MCD_OPC_ExtractField, 10, 3,  // Inst{12-10} ...
/* 3478 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 3499
/* 3483 */    MCD_OPC_CheckPredicate, 0, 233, 16, 0, // Skip to: 7817
/* 3488 */    MCD_OPC_CheckField, 18, 1, 0, 226, 16, 0, // Skip to: 7817
/* 3495 */    MCD_OPC_Decode, 170, 3, 47, // Opcode: FMOVS_ICC
/* 3499 */    MCD_OPC_FilterValue, 4, 217, 16, 0, // Skip to: 7817
/* 3504 */    MCD_OPC_CheckPredicate, 0, 212, 16, 0, // Skip to: 7817
/* 3509 */    MCD_OPC_CheckField, 18, 1, 0, 205, 16, 0, // Skip to: 7817
/* 3516 */    MCD_OPC_Decode, 171, 3, 47, // Opcode: FMOVS_XCC
/* 3520 */    MCD_OPC_FilterValue, 2, 99, 0, 0, // Skip to: 3624
/* 3525 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 3528 */    MCD_OPC_FilterValue, 0, 41, 0, 0, // Skip to: 3574
/* 3533 */    MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 3536 */    MCD_OPC_FilterValue, 0, 180, 16, 0, // Skip to: 7817
/* 3541 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 3544 */    MCD_OPC_FilterValue, 0, 172, 16, 0, // Skip to: 7817
/* 3549 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 3565
/* 3554 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 3565
/* 3561 */    MCD_OPC_Decode, 158, 3, 49, // Opcode: FMOVD_FCC
/* 3565 */    MCD_OPC_CheckPredicate, 0, 151, 16, 0, // Skip to: 7817
/* 3570 */    MCD_OPC_Decode, 245, 5, 50, // Opcode: V9FMOVD_FCC
/* 3574 */    MCD_OPC_FilterValue, 1, 142, 16, 0, // Skip to: 7817
/* 3579 */    MCD_OPC_ExtractField, 10, 3,  // Inst{12-10} ...
/* 3582 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 3603
/* 3587 */    MCD_OPC_CheckPredicate, 0, 129, 16, 0, // Skip to: 7817
/* 3592 */    MCD_OPC_CheckField, 18, 1, 0, 122, 16, 0, // Skip to: 7817
/* 3599 */    MCD_OPC_Decode, 159, 3, 49, // Opcode: FMOVD_ICC
/* 3603 */    MCD_OPC_FilterValue, 4, 113, 16, 0, // Skip to: 7817
/* 3608 */    MCD_OPC_CheckPredicate, 0, 108, 16, 0, // Skip to: 7817
/* 3613 */    MCD_OPC_CheckField, 18, 1, 0, 101, 16, 0, // Skip to: 7817
/* 3620 */    MCD_OPC_Decode, 160, 3, 49, // Opcode: FMOVD_XCC
/* 3624 */    MCD_OPC_FilterValue, 3, 99, 0, 0, // Skip to: 3728
/* 3629 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 3632 */    MCD_OPC_FilterValue, 0, 41, 0, 0, // Skip to: 3678
/* 3637 */    MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 3640 */    MCD_OPC_FilterValue, 0, 76, 16, 0, // Skip to: 7817
/* 3645 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 3648 */    MCD_OPC_FilterValue, 0, 68, 16, 0, // Skip to: 7817
/* 3653 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 3669
/* 3658 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 3669
/* 3665 */    MCD_OPC_Decode, 162, 3, 51, // Opcode: FMOVQ_FCC
/* 3669 */    MCD_OPC_CheckPredicate, 0, 47, 16, 0, // Skip to: 7817
/* 3674 */    MCD_OPC_Decode, 246, 5, 52, // Opcode: V9FMOVQ_FCC
/* 3678 */    MCD_OPC_FilterValue, 1, 38, 16, 0, // Skip to: 7817
/* 3683 */    MCD_OPC_ExtractField, 10, 3,  // Inst{12-10} ...
/* 3686 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 3707
/* 3691 */    MCD_OPC_CheckPredicate, 0, 25, 16, 0, // Skip to: 7817
/* 3696 */    MCD_OPC_CheckField, 18, 1, 0, 18, 16, 0, // Skip to: 7817
/* 3703 */    MCD_OPC_Decode, 163, 3, 51, // Opcode: FMOVQ_ICC
/* 3707 */    MCD_OPC_FilterValue, 4, 9, 16, 0, // Skip to: 7817
/* 3712 */    MCD_OPC_CheckPredicate, 0, 4, 16, 0, // Skip to: 7817
/* 3717 */    MCD_OPC_CheckField, 18, 1, 0, 253, 15, 0, // Skip to: 7817
/* 3724 */    MCD_OPC_Decode, 164, 3, 51, // Opcode: FMOVQ_XCC
/* 3728 */    MCD_OPC_FilterValue, 5, 16, 0, 0, // Skip to: 3749
/* 3733 */    MCD_OPC_CheckPredicate, 0, 239, 15, 0, // Skip to: 7817
/* 3738 */    MCD_OPC_CheckField, 13, 1, 0, 232, 15, 0, // Skip to: 7817
/* 3745 */    MCD_OPC_Decode, 167, 3, 53, // Opcode: FMOVRS
/* 3749 */    MCD_OPC_FilterValue, 6, 16, 0, 0, // Skip to: 3770
/* 3754 */    MCD_OPC_CheckPredicate, 0, 218, 15, 0, // Skip to: 7817
/* 3759 */    MCD_OPC_CheckField, 13, 1, 0, 211, 15, 0, // Skip to: 7817
/* 3766 */    MCD_OPC_Decode, 165, 3, 54, // Opcode: FMOVRD
/* 3770 */    MCD_OPC_FilterValue, 7, 11, 0, 0, // Skip to: 3786
/* 3775 */    MCD_OPC_CheckField, 13, 1, 0, 195, 15, 0, // Skip to: 7817
/* 3782 */    MCD_OPC_Decode, 166, 3, 55, // Opcode: FMOVRQ
/* 3786 */    MCD_OPC_FilterValue, 17, 11, 0, 0, // Skip to: 3802
/* 3791 */    MCD_OPC_CheckField, 10, 4, 2, 179, 15, 0, // Skip to: 7817
/* 3798 */    MCD_OPC_Decode, 244, 5, 56, // Opcode: V9FCMPS
/* 3802 */    MCD_OPC_FilterValue, 18, 11, 0, 0, // Skip to: 3818
/* 3807 */    MCD_OPC_CheckField, 10, 4, 2, 163, 15, 0, // Skip to: 7817
/* 3814 */    MCD_OPC_Decode, 239, 5, 57, // Opcode: V9FCMPD
/* 3818 */    MCD_OPC_FilterValue, 19, 11, 0, 0, // Skip to: 3834
/* 3823 */    MCD_OPC_CheckField, 10, 4, 2, 147, 15, 0, // Skip to: 7817
/* 3830 */    MCD_OPC_Decode, 243, 5, 58, // Opcode: V9FCMPQ
/* 3834 */    MCD_OPC_FilterValue, 21, 11, 0, 0, // Skip to: 3850
/* 3839 */    MCD_OPC_CheckField, 10, 4, 2, 131, 15, 0, // Skip to: 7817
/* 3846 */    MCD_OPC_Decode, 242, 5, 56, // Opcode: V9FCMPES
/* 3850 */    MCD_OPC_FilterValue, 22, 11, 0, 0, // Skip to: 3866
/* 3855 */    MCD_OPC_CheckField, 10, 4, 2, 115, 15, 0, // Skip to: 7817
/* 3862 */    MCD_OPC_Decode, 240, 5, 57, // Opcode: V9FCMPED
/* 3866 */    MCD_OPC_FilterValue, 23, 106, 15, 0, // Skip to: 7817
/* 3871 */    MCD_OPC_CheckField, 10, 4, 2, 99, 15, 0, // Skip to: 7817
/* 3878 */    MCD_OPC_Decode, 241, 5, 58, // Opcode: V9FCMPEQ
/* 3882 */    MCD_OPC_FilterValue, 54, 35, 7, 0, // Skip to: 5714
/* 3887 */    MCD_OPC_ExtractField, 5, 9,  // Inst{13-5} ...
/* 3890 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 3904
/* 3895 */    MCD_OPC_CheckPredicate, 3, 77, 15, 0, // Skip to: 7817
/* 3900 */    MCD_OPC_Decode, 226, 2, 10, // Opcode: EDGE8
/* 3904 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 3918
/* 3909 */    MCD_OPC_CheckPredicate, 4, 63, 15, 0, // Skip to: 7817
/* 3914 */    MCD_OPC_Decode, 229, 2, 10, // Opcode: EDGE8N
/* 3918 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 3932
/* 3923 */    MCD_OPC_CheckPredicate, 3, 49, 15, 0, // Skip to: 7817
/* 3928 */    MCD_OPC_Decode, 227, 2, 10, // Opcode: EDGE8L
/* 3932 */    MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 3946
/* 3937 */    MCD_OPC_CheckPredicate, 4, 35, 15, 0, // Skip to: 7817
/* 3942 */    MCD_OPC_Decode, 228, 2, 10, // Opcode: EDGE8LN
/* 3946 */    MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 3960
/* 3951 */    MCD_OPC_CheckPredicate, 3, 21, 15, 0, // Skip to: 7817
/* 3956 */    MCD_OPC_Decode, 218, 2, 10, // Opcode: EDGE16
/* 3960 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 3974
/* 3965 */    MCD_OPC_CheckPredicate, 4, 7, 15, 0, // Skip to: 7817
/* 3970 */    MCD_OPC_Decode, 221, 2, 10, // Opcode: EDGE16N
/* 3974 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 3988
/* 3979 */    MCD_OPC_CheckPredicate, 3, 249, 14, 0, // Skip to: 7817
/* 3984 */    MCD_OPC_Decode, 219, 2, 10, // Opcode: EDGE16L
/* 3988 */    MCD_OPC_FilterValue, 7, 9, 0, 0, // Skip to: 4002
/* 3993 */    MCD_OPC_CheckPredicate, 4, 235, 14, 0, // Skip to: 7817
/* 3998 */    MCD_OPC_Decode, 220, 2, 10, // Opcode: EDGE16LN
/* 4002 */    MCD_OPC_FilterValue, 8, 9, 0, 0, // Skip to: 4016
/* 4007 */    MCD_OPC_CheckPredicate, 3, 221, 14, 0, // Skip to: 7817
/* 4012 */    MCD_OPC_Decode, 222, 2, 10, // Opcode: EDGE32
/* 4016 */    MCD_OPC_FilterValue, 9, 9, 0, 0, // Skip to: 4030
/* 4021 */    MCD_OPC_CheckPredicate, 4, 207, 14, 0, // Skip to: 7817
/* 4026 */    MCD_OPC_Decode, 225, 2, 10, // Opcode: EDGE32N
/* 4030 */    MCD_OPC_FilterValue, 10, 9, 0, 0, // Skip to: 4044
/* 4035 */    MCD_OPC_CheckPredicate, 3, 193, 14, 0, // Skip to: 7817
/* 4040 */    MCD_OPC_Decode, 223, 2, 10, // Opcode: EDGE32L
/* 4044 */    MCD_OPC_FilterValue, 11, 9, 0, 0, // Skip to: 4058
/* 4049 */    MCD_OPC_CheckPredicate, 4, 179, 14, 0, // Skip to: 7817
/* 4054 */    MCD_OPC_Decode, 224, 2, 10, // Opcode: EDGE32LN
/* 4058 */    MCD_OPC_FilterValue, 16, 9, 0, 0, // Skip to: 4072
/* 4063 */    MCD_OPC_CheckPredicate, 3, 165, 14, 0, // Skip to: 7817
/* 4068 */    MCD_OPC_Decode, 182, 2, 10, // Opcode: ARRAY8
/* 4072 */    MCD_OPC_FilterValue, 17, 9, 0, 0, // Skip to: 4086
/* 4077 */    MCD_OPC_CheckPredicate, 2, 151, 14, 0, // Skip to: 7817
/* 4082 */    MCD_OPC_Decode, 166, 2, 10, // Opcode: ADDXC
/* 4086 */    MCD_OPC_FilterValue, 18, 9, 0, 0, // Skip to: 4100
/* 4091 */    MCD_OPC_CheckPredicate, 3, 137, 14, 0, // Skip to: 7817
/* 4096 */    MCD_OPC_Decode, 180, 2, 10, // Opcode: ARRAY16
/* 4100 */    MCD_OPC_FilterValue, 19, 9, 0, 0, // Skip to: 4114
/* 4105 */    MCD_OPC_CheckPredicate, 2, 123, 14, 0, // Skip to: 7817
/* 4110 */    MCD_OPC_Decode, 167, 2, 10, // Opcode: ADDXCCC
/* 4114 */    MCD_OPC_FilterValue, 20, 9, 0, 0, // Skip to: 4128
/* 4119 */    MCD_OPC_CheckPredicate, 3, 109, 14, 0, // Skip to: 7817
/* 4124 */    MCD_OPC_Decode, 181, 2, 10, // Opcode: ARRAY32
/* 4128 */    MCD_OPC_FilterValue, 22, 9, 0, 0, // Skip to: 4142
/* 4133 */    MCD_OPC_CheckPredicate, 2, 95, 14, 0, // Skip to: 7817
/* 4138 */    MCD_OPC_Decode, 235, 5, 10, // Opcode: UMULXHI
/* 4142 */    MCD_OPC_FilterValue, 23, 16, 0, 0, // Skip to: 4163
/* 4147 */    MCD_OPC_CheckPredicate, 2, 81, 14, 0, // Skip to: 7817
/* 4152 */    MCD_OPC_CheckField, 14, 5, 0, 74, 14, 0, // Skip to: 7817
/* 4159 */    MCD_OPC_Decode, 191, 4, 59, // Opcode: LZCNT
/* 4163 */    MCD_OPC_FilterValue, 24, 9, 0, 0, // Skip to: 4177
/* 4168 */    MCD_OPC_CheckPredicate, 3, 60, 14, 0, // Skip to: 7817
/* 4173 */    MCD_OPC_Decode, 170, 2, 10, // Opcode: ALIGNADDR
/* 4177 */    MCD_OPC_FilterValue, 25, 9, 0, 0, // Skip to: 4191
/* 4182 */    MCD_OPC_CheckPredicate, 4, 46, 14, 0, // Skip to: 7817
/* 4187 */    MCD_OPC_Decode, 187, 2, 10, // Opcode: BMASK
/* 4191 */    MCD_OPC_FilterValue, 26, 9, 0, 0, // Skip to: 4205
/* 4196 */    MCD_OPC_CheckPredicate, 3, 32, 14, 0, // Skip to: 7817
/* 4201 */    MCD_OPC_Decode, 171, 2, 10, // Opcode: ALIGNADDRL
/* 4205 */    MCD_OPC_FilterValue, 27, 23, 0, 0, // Skip to: 4233
/* 4210 */    MCD_OPC_CheckPredicate, 2, 18, 14, 0, // Skip to: 7817
/* 4215 */    MCD_OPC_CheckField, 25, 5, 0, 11, 14, 0, // Skip to: 7817
/* 4222 */    MCD_OPC_CheckField, 14, 5, 0, 4, 14, 0, // Skip to: 7817
/* 4229 */    MCD_OPC_Decode, 216, 2, 60, // Opcode: CMASK8
/* 4233 */    MCD_OPC_FilterValue, 29, 23, 0, 0, // Skip to: 4261
/* 4238 */    MCD_OPC_CheckPredicate, 2, 246, 13, 0, // Skip to: 7817
/* 4243 */    MCD_OPC_CheckField, 25, 5, 0, 239, 13, 0, // Skip to: 7817
/* 4250 */    MCD_OPC_CheckField, 14, 5, 0, 232, 13, 0, // Skip to: 7817
/* 4257 */    MCD_OPC_Decode, 214, 2, 60, // Opcode: CMASK16
/* 4261 */    MCD_OPC_FilterValue, 31, 23, 0, 0, // Skip to: 4289
/* 4266 */    MCD_OPC_CheckPredicate, 2, 218, 13, 0, // Skip to: 7817
/* 4271 */    MCD_OPC_CheckField, 25, 5, 0, 211, 13, 0, // Skip to: 7817
/* 4278 */    MCD_OPC_CheckField, 14, 5, 0, 204, 13, 0, // Skip to: 7817
/* 4285 */    MCD_OPC_Decode, 215, 2, 60, // Opcode: CMASK32
/* 4289 */    MCD_OPC_FilterValue, 32, 9, 0, 0, // Skip to: 4303
/* 4294 */    MCD_OPC_CheckPredicate, 3, 190, 13, 0, // Skip to: 7817
/* 4299 */    MCD_OPC_Decode, 254, 2, 61, // Opcode: FCMPLE16
/* 4303 */    MCD_OPC_FilterValue, 33, 9, 0, 0, // Skip to: 4317
/* 4308 */    MCD_OPC_CheckPredicate, 2, 176, 13, 0, // Skip to: 7817
/* 4313 */    MCD_OPC_Decode, 227, 3, 37, // Opcode: FSLL16
/* 4317 */    MCD_OPC_FilterValue, 34, 9, 0, 0, // Skip to: 4331
/* 4322 */    MCD_OPC_CheckPredicate, 3, 162, 13, 0, // Skip to: 7817
/* 4327 */    MCD_OPC_Decode, 128, 3, 61, // Opcode: FCMPNE16
/* 4331 */    MCD_OPC_FilterValue, 35, 9, 0, 0, // Skip to: 4345
/* 4336 */    MCD_OPC_CheckPredicate, 2, 148, 13, 0, // Skip to: 7817
/* 4341 */    MCD_OPC_Decode, 239, 3, 37, // Opcode: FSRL16
/* 4345 */    MCD_OPC_FilterValue, 36, 9, 0, 0, // Skip to: 4359
/* 4350 */    MCD_OPC_CheckPredicate, 3, 134, 13, 0, // Skip to: 7817
/* 4355 */    MCD_OPC_Decode, 255, 2, 61, // Opcode: FCMPLE32
/* 4359 */    MCD_OPC_FilterValue, 37, 9, 0, 0, // Skip to: 4373
/* 4364 */    MCD_OPC_CheckPredicate, 2, 120, 13, 0, // Skip to: 7817
/* 4369 */    MCD_OPC_Decode, 228, 3, 37, // Opcode: FSLL32
/* 4373 */    MCD_OPC_FilterValue, 38, 9, 0, 0, // Skip to: 4387
/* 4378 */    MCD_OPC_CheckPredicate, 3, 106, 13, 0, // Skip to: 7817
/* 4383 */    MCD_OPC_Decode, 129, 3, 61, // Opcode: FCMPNE32
/* 4387 */    MCD_OPC_FilterValue, 39, 9, 0, 0, // Skip to: 4401
/* 4392 */    MCD_OPC_CheckPredicate, 2, 92, 13, 0, // Skip to: 7817
/* 4397 */    MCD_OPC_Decode, 240, 3, 37, // Opcode: FSRL32
/* 4401 */    MCD_OPC_FilterValue, 40, 9, 0, 0, // Skip to: 4415
/* 4406 */    MCD_OPC_CheckPredicate, 3, 78, 13, 0, // Skip to: 7817
/* 4411 */    MCD_OPC_Decode, 252, 2, 61, // Opcode: FCMPGT16
/* 4415 */    MCD_OPC_FilterValue, 41, 9, 0, 0, // Skip to: 4429
/* 4420 */    MCD_OPC_CheckPredicate, 2, 64, 13, 0, // Skip to: 7817
/* 4425 */    MCD_OPC_Decode, 225, 3, 37, // Opcode: FSLAS16
/* 4429 */    MCD_OPC_FilterValue, 42, 9, 0, 0, // Skip to: 4443
/* 4434 */    MCD_OPC_CheckPredicate, 3, 50, 13, 0, // Skip to: 7817
/* 4439 */    MCD_OPC_Decode, 250, 2, 61, // Opcode: FCMPEQ16
/* 4443 */    MCD_OPC_FilterValue, 43, 9, 0, 0, // Skip to: 4457
/* 4448 */    MCD_OPC_CheckPredicate, 2, 36, 13, 0, // Skip to: 7817
/* 4453 */    MCD_OPC_Decode, 233, 3, 37, // Opcode: FSRA16
/* 4457 */    MCD_OPC_FilterValue, 44, 9, 0, 0, // Skip to: 4471
/* 4462 */    MCD_OPC_CheckPredicate, 3, 22, 13, 0, // Skip to: 7817
/* 4467 */    MCD_OPC_Decode, 253, 2, 61, // Opcode: FCMPGT32
/* 4471 */    MCD_OPC_FilterValue, 45, 9, 0, 0, // Skip to: 4485
/* 4476 */    MCD_OPC_CheckPredicate, 2, 8, 13, 0, // Skip to: 7817
/* 4481 */    MCD_OPC_Decode, 226, 3, 37, // Opcode: FSLAS32
/* 4485 */    MCD_OPC_FilterValue, 46, 9, 0, 0, // Skip to: 4499
/* 4490 */    MCD_OPC_CheckPredicate, 3, 250, 12, 0, // Skip to: 7817
/* 4495 */    MCD_OPC_Decode, 251, 2, 61, // Opcode: FCMPEQ32
/* 4499 */    MCD_OPC_FilterValue, 47, 9, 0, 0, // Skip to: 4513
/* 4504 */    MCD_OPC_CheckPredicate, 2, 236, 12, 0, // Skip to: 7817
/* 4509 */    MCD_OPC_Decode, 234, 3, 37, // Opcode: FSRA32
/* 4513 */    MCD_OPC_FilterValue, 49, 9, 0, 0, // Skip to: 4527
/* 4518 */    MCD_OPC_CheckPredicate, 3, 222, 12, 0, // Skip to: 7817
/* 4523 */    MCD_OPC_Decode, 174, 3, 62, // Opcode: FMUL8X16
/* 4527 */    MCD_OPC_FilterValue, 51, 9, 0, 0, // Skip to: 4541
/* 4532 */    MCD_OPC_CheckPredicate, 3, 208, 12, 0, // Skip to: 7817
/* 4537 */    MCD_OPC_Decode, 176, 3, 39, // Opcode: FMUL8X16AU
/* 4541 */    MCD_OPC_FilterValue, 53, 9, 0, 0, // Skip to: 4555
/* 4546 */    MCD_OPC_CheckPredicate, 3, 194, 12, 0, // Skip to: 7817
/* 4551 */    MCD_OPC_Decode, 175, 3, 39, // Opcode: FMUL8X16AL
/* 4555 */    MCD_OPC_FilterValue, 54, 9, 0, 0, // Skip to: 4569
/* 4560 */    MCD_OPC_CheckPredicate, 3, 180, 12, 0, // Skip to: 7817
/* 4565 */    MCD_OPC_Decode, 172, 3, 37, // Opcode: FMUL8SUX16
/* 4569 */    MCD_OPC_FilterValue, 55, 9, 0, 0, // Skip to: 4583
/* 4574 */    MCD_OPC_CheckPredicate, 3, 166, 12, 0, // Skip to: 7817
/* 4579 */    MCD_OPC_Decode, 173, 3, 37, // Opcode: FMUL8ULX16
/* 4583 */    MCD_OPC_FilterValue, 56, 9, 0, 0, // Skip to: 4597
/* 4588 */    MCD_OPC_CheckPredicate, 3, 152, 12, 0, // Skip to: 7817
/* 4593 */    MCD_OPC_Decode, 178, 3, 39, // Opcode: FMULD8SUX16
/* 4597 */    MCD_OPC_FilterValue, 57, 9, 0, 0, // Skip to: 4611
/* 4602 */    MCD_OPC_CheckPredicate, 3, 138, 12, 0, // Skip to: 7817
/* 4607 */    MCD_OPC_Decode, 179, 3, 39, // Opcode: FMULD8ULX16
/* 4611 */    MCD_OPC_FilterValue, 58, 9, 0, 0, // Skip to: 4625
/* 4616 */    MCD_OPC_CheckPredicate, 3, 124, 12, 0, // Skip to: 7817
/* 4621 */    MCD_OPC_Decode, 209, 3, 37, // Opcode: FPACK32
/* 4625 */    MCD_OPC_FilterValue, 59, 16, 0, 0, // Skip to: 4646
/* 4630 */    MCD_OPC_CheckPredicate, 3, 110, 12, 0, // Skip to: 7817
/* 4635 */    MCD_OPC_CheckField, 14, 5, 0, 103, 12, 0, // Skip to: 7817
/* 4642 */    MCD_OPC_Decode, 208, 3, 34, // Opcode: FPACK16
/* 4646 */    MCD_OPC_FilterValue, 61, 16, 0, 0, // Skip to: 4667
/* 4651 */    MCD_OPC_CheckPredicate, 3, 89, 12, 0, // Skip to: 7817
/* 4656 */    MCD_OPC_CheckField, 14, 5, 0, 82, 12, 0, // Skip to: 7817
/* 4663 */    MCD_OPC_Decode, 210, 3, 43, // Opcode: FPACKFIX
/* 4667 */    MCD_OPC_FilterValue, 62, 9, 0, 0, // Skip to: 4681
/* 4672 */    MCD_OPC_CheckPredicate, 3, 68, 12, 0, // Skip to: 7817
/* 4677 */    MCD_OPC_Decode, 219, 4, 37, // Opcode: PDIST
/* 4681 */    MCD_OPC_FilterValue, 63, 9, 0, 0, // Skip to: 4695
/* 4686 */    MCD_OPC_CheckPredicate, 2, 54, 12, 0, // Skip to: 7817
/* 4691 */    MCD_OPC_Decode, 220, 4, 61, // Opcode: PDISTN
/* 4695 */    MCD_OPC_FilterValue, 64, 9, 0, 0, // Skip to: 4709
/* 4700 */    MCD_OPC_CheckPredicate, 2, 40, 12, 0, // Skip to: 7817
/* 4705 */    MCD_OPC_Decode, 156, 3, 37, // Opcode: FMEAN16
/* 4709 */    MCD_OPC_FilterValue, 66, 9, 0, 0, // Skip to: 4723
/* 4714 */    MCD_OPC_CheckPredicate, 2, 26, 12, 0, // Skip to: 7817
/* 4719 */    MCD_OPC_Decode, 215, 3, 37, // Opcode: FPADD64
/* 4723 */    MCD_OPC_FilterValue, 68, 9, 0, 0, // Skip to: 4737
/* 4728 */    MCD_OPC_CheckPredicate, 2, 12, 12, 0, // Skip to: 7817
/* 4733 */    MCD_OPC_Decode, 247, 2, 37, // Opcode: FCHKSM16
/* 4737 */    MCD_OPC_FilterValue, 72, 9, 0, 0, // Skip to: 4751
/* 4742 */    MCD_OPC_CheckPredicate, 3, 254, 11, 0, // Skip to: 7817
/* 4747 */    MCD_OPC_Decode, 236, 2, 37, // Opcode: FALIGNADATA
/* 4751 */    MCD_OPC_FilterValue, 75, 9, 0, 0, // Skip to: 4765
/* 4756 */    MCD_OPC_CheckPredicate, 3, 240, 11, 0, // Skip to: 7817
/* 4761 */    MCD_OPC_Decode, 216, 3, 39, // Opcode: FPMERGE
/* 4765 */    MCD_OPC_FilterValue, 76, 9, 0, 0, // Skip to: 4779
/* 4770 */    MCD_OPC_CheckPredicate, 4, 226, 11, 0, // Skip to: 7817
/* 4775 */    MCD_OPC_Decode, 204, 2, 37, // Opcode: BSHUFFLE
/* 4779 */    MCD_OPC_FilterValue, 77, 16, 0, 0, // Skip to: 4800
/* 4784 */    MCD_OPC_CheckPredicate, 3, 212, 11, 0, // Skip to: 7817
/* 4789 */    MCD_OPC_CheckField, 14, 5, 0, 205, 11, 0, // Skip to: 7817
/* 4796 */    MCD_OPC_Decode, 142, 3, 41, // Opcode: FEXPAND
/* 4800 */    MCD_OPC_FilterValue, 80, 9, 0, 0, // Skip to: 4814
/* 4805 */    MCD_OPC_CheckPredicate, 3, 191, 11, 0, // Skip to: 7817
/* 4810 */    MCD_OPC_Decode, 211, 3, 37, // Opcode: FPADD16
/* 4814 */    MCD_OPC_FilterValue, 81, 9, 0, 0, // Skip to: 4828
/* 4819 */    MCD_OPC_CheckPredicate, 3, 177, 11, 0, // Skip to: 7817
/* 4824 */    MCD_OPC_Decode, 212, 3, 36, // Opcode: FPADD16S
/* 4828 */    MCD_OPC_FilterValue, 82, 9, 0, 0, // Skip to: 4842
/* 4833 */    MCD_OPC_CheckPredicate, 3, 163, 11, 0, // Skip to: 7817
/* 4838 */    MCD_OPC_Decode, 213, 3, 37, // Opcode: FPADD32
/* 4842 */    MCD_OPC_FilterValue, 83, 9, 0, 0, // Skip to: 4856
/* 4847 */    MCD_OPC_CheckPredicate, 3, 149, 11, 0, // Skip to: 7817
/* 4852 */    MCD_OPC_Decode, 214, 3, 36, // Opcode: FPADD32S
/* 4856 */    MCD_OPC_FilterValue, 84, 9, 0, 0, // Skip to: 4870
/* 4861 */    MCD_OPC_CheckPredicate, 3, 135, 11, 0, // Skip to: 7817
/* 4866 */    MCD_OPC_Decode, 217, 3, 37, // Opcode: FPSUB16
/* 4870 */    MCD_OPC_FilterValue, 85, 9, 0, 0, // Skip to: 4884
/* 4875 */    MCD_OPC_CheckPredicate, 3, 121, 11, 0, // Skip to: 7817
/* 4880 */    MCD_OPC_Decode, 218, 3, 36, // Opcode: FPSUB16S
/* 4884 */    MCD_OPC_FilterValue, 86, 9, 0, 0, // Skip to: 4898
/* 4889 */    MCD_OPC_CheckPredicate, 3, 107, 11, 0, // Skip to: 7817
/* 4894 */    MCD_OPC_Decode, 219, 3, 37, // Opcode: FPSUB32
/* 4898 */    MCD_OPC_FilterValue, 87, 9, 0, 0, // Skip to: 4912
/* 4903 */    MCD_OPC_CheckPredicate, 3, 93, 11, 0, // Skip to: 7817
/* 4908 */    MCD_OPC_Decode, 220, 3, 36, // Opcode: FPSUB32S
/* 4912 */    MCD_OPC_FilterValue, 96, 23, 0, 0, // Skip to: 4940
/* 4917 */    MCD_OPC_CheckPredicate, 3, 79, 11, 0, // Skip to: 7817
/* 4922 */    MCD_OPC_CheckField, 14, 5, 0, 72, 11, 0, // Skip to: 7817
/* 4929 */    MCD_OPC_CheckField, 0, 5, 0, 65, 11, 0, // Skip to: 7817
/* 4936 */    MCD_OPC_Decode, 255, 3, 63, // Opcode: FZERO
/* 4940 */    MCD_OPC_FilterValue, 97, 23, 0, 0, // Skip to: 4968
/* 4945 */    MCD_OPC_CheckPredicate, 3, 51, 11, 0, // Skip to: 7817
/* 4950 */    MCD_OPC_CheckField, 14, 5, 0, 44, 11, 0, // Skip to: 7817
/* 4957 */    MCD_OPC_CheckField, 0, 5, 0, 37, 11, 0, // Skip to: 7817
/* 4964 */    MCD_OPC_Decode, 128, 4, 64, // Opcode: FZEROS
/* 4968 */    MCD_OPC_FilterValue, 98, 9, 0, 0, // Skip to: 4982
/* 4973 */    MCD_OPC_CheckPredicate, 3, 23, 11, 0, // Skip to: 7817
/* 4978 */    MCD_OPC_Decode, 193, 3, 37, // Opcode: FNOR
/* 4982 */    MCD_OPC_FilterValue, 99, 9, 0, 0, // Skip to: 4996
/* 4987 */    MCD_OPC_CheckPredicate, 3, 9, 11, 0, // Skip to: 7817
/* 4992 */    MCD_OPC_Decode, 194, 3, 36, // Opcode: FNORS
/* 4996 */    MCD_OPC_FilterValue, 100, 9, 0, 0, // Skip to: 5010
/* 5001 */    MCD_OPC_CheckPredicate, 3, 251, 10, 0, // Skip to: 7817
/* 5006 */    MCD_OPC_Decode, 240, 2, 37, // Opcode: FANDNOT2
/* 5010 */    MCD_OPC_FilterValue, 101, 9, 0, 0, // Skip to: 5024
/* 5015 */    MCD_OPC_CheckPredicate, 3, 237, 10, 0, // Skip to: 7817
/* 5020 */    MCD_OPC_Decode, 241, 2, 36, // Opcode: FANDNOT2S
/* 5024 */    MCD_OPC_FilterValue, 102, 16, 0, 0, // Skip to: 5045
/* 5029 */    MCD_OPC_CheckPredicate, 3, 223, 10, 0, // Skip to: 7817
/* 5034 */    MCD_OPC_CheckField, 14, 5, 0, 216, 10, 0, // Skip to: 7817
/* 5041 */    MCD_OPC_Decode, 197, 3, 34, // Opcode: FNOT2
/* 5045 */    MCD_OPC_FilterValue, 103, 16, 0, 0, // Skip to: 5066
/* 5050 */    MCD_OPC_CheckPredicate, 3, 202, 10, 0, // Skip to: 7817
/* 5055 */    MCD_OPC_CheckField, 14, 5, 0, 195, 10, 0, // Skip to: 7817
/* 5062 */    MCD_OPC_Decode, 198, 3, 33, // Opcode: FNOT2S
/* 5066 */    MCD_OPC_FilterValue, 104, 9, 0, 0, // Skip to: 5080
/* 5071 */    MCD_OPC_CheckPredicate, 3, 181, 10, 0, // Skip to: 7817
/* 5076 */    MCD_OPC_Decode, 238, 2, 37, // Opcode: FANDNOT1
/* 5080 */    MCD_OPC_FilterValue, 105, 9, 0, 0, // Skip to: 5094
/* 5085 */    MCD_OPC_CheckPredicate, 3, 167, 10, 0, // Skip to: 7817
/* 5090 */    MCD_OPC_Decode, 239, 2, 36, // Opcode: FANDNOT1S
/* 5094 */    MCD_OPC_FilterValue, 106, 16, 0, 0, // Skip to: 5115
/* 5099 */    MCD_OPC_CheckPredicate, 3, 153, 10, 0, // Skip to: 7817
/* 5104 */    MCD_OPC_CheckField, 0, 5, 0, 146, 10, 0, // Skip to: 7817
/* 5111 */    MCD_OPC_Decode, 195, 3, 65, // Opcode: FNOT1
/* 5115 */    MCD_OPC_FilterValue, 107, 16, 0, 0, // Skip to: 5136
/* 5120 */    MCD_OPC_CheckPredicate, 3, 132, 10, 0, // Skip to: 7817
/* 5125 */    MCD_OPC_CheckField, 0, 5, 0, 125, 10, 0, // Skip to: 7817
/* 5132 */    MCD_OPC_Decode, 196, 3, 66, // Opcode: FNOT1S
/* 5136 */    MCD_OPC_FilterValue, 108, 9, 0, 0, // Skip to: 5150
/* 5141 */    MCD_OPC_CheckPredicate, 3, 111, 10, 0, // Skip to: 7817
/* 5146 */    MCD_OPC_Decode, 250, 3, 37, // Opcode: FXOR
/* 5150 */    MCD_OPC_FilterValue, 109, 9, 0, 0, // Skip to: 5164
/* 5155 */    MCD_OPC_CheckPredicate, 3, 97, 10, 0, // Skip to: 7817
/* 5160 */    MCD_OPC_Decode, 251, 3, 36, // Opcode: FXORS
/* 5164 */    MCD_OPC_FilterValue, 110, 9, 0, 0, // Skip to: 5178
/* 5169 */    MCD_OPC_CheckPredicate, 3, 83, 10, 0, // Skip to: 7817
/* 5174 */    MCD_OPC_Decode, 184, 3, 37, // Opcode: FNAND
/* 5178 */    MCD_OPC_FilterValue, 111, 9, 0, 0, // Skip to: 5192
/* 5183 */    MCD_OPC_CheckPredicate, 3, 69, 10, 0, // Skip to: 7817
/* 5188 */    MCD_OPC_Decode, 185, 3, 36, // Opcode: FNANDS
/* 5192 */    MCD_OPC_FilterValue, 112, 9, 0, 0, // Skip to: 5206
/* 5197 */    MCD_OPC_CheckPredicate, 3, 55, 10, 0, // Skip to: 7817
/* 5202 */    MCD_OPC_Decode, 237, 2, 37, // Opcode: FAND
/* 5206 */    MCD_OPC_FilterValue, 113, 9, 0, 0, // Skip to: 5220
/* 5211 */    MCD_OPC_CheckPredicate, 3, 41, 10, 0, // Skip to: 7817
/* 5216 */    MCD_OPC_Decode, 242, 2, 36, // Opcode: FANDS
/* 5220 */    MCD_OPC_FilterValue, 114, 9, 0, 0, // Skip to: 5234
/* 5225 */    MCD_OPC_CheckPredicate, 3, 27, 10, 0, // Skip to: 7817
/* 5230 */    MCD_OPC_Decode, 248, 3, 37, // Opcode: FXNOR
/* 5234 */    MCD_OPC_FilterValue, 115, 9, 0, 0, // Skip to: 5248
/* 5239 */    MCD_OPC_CheckPredicate, 3, 13, 10, 0, // Skip to: 7817
/* 5244 */    MCD_OPC_Decode, 249, 3, 36, // Opcode: FXNORS
/* 5248 */    MCD_OPC_FilterValue, 116, 16, 0, 0, // Skip to: 5269
/* 5253 */    MCD_OPC_CheckPredicate, 3, 255, 9, 0, // Skip to: 7817
/* 5258 */    MCD_OPC_CheckField, 0, 5, 0, 248, 9, 0, // Skip to: 7817
/* 5265 */    MCD_OPC_Decode, 235, 3, 65, // Opcode: FSRC1
/* 5269 */    MCD_OPC_FilterValue, 117, 16, 0, 0, // Skip to: 5290
/* 5274 */    MCD_OPC_CheckPredicate, 3, 234, 9, 0, // Skip to: 7817
/* 5279 */    MCD_OPC_CheckField, 0, 5, 0, 227, 9, 0, // Skip to: 7817
/* 5286 */    MCD_OPC_Decode, 236, 3, 66, // Opcode: FSRC1S
/* 5290 */    MCD_OPC_FilterValue, 118, 9, 0, 0, // Skip to: 5304
/* 5295 */    MCD_OPC_CheckPredicate, 3, 213, 9, 0, // Skip to: 7817
/* 5300 */    MCD_OPC_Decode, 205, 3, 37, // Opcode: FORNOT2
/* 5304 */    MCD_OPC_FilterValue, 119, 9, 0, 0, // Skip to: 5318
/* 5309 */    MCD_OPC_CheckPredicate, 3, 199, 9, 0, // Skip to: 7817
/* 5314 */    MCD_OPC_Decode, 206, 3, 36, // Opcode: FORNOT2S
/* 5318 */    MCD_OPC_FilterValue, 120, 16, 0, 0, // Skip to: 5339
/* 5323 */    MCD_OPC_CheckPredicate, 3, 185, 9, 0, // Skip to: 7817
/* 5328 */    MCD_OPC_CheckField, 14, 5, 0, 178, 9, 0, // Skip to: 7817
/* 5335 */    MCD_OPC_Decode, 237, 3, 34, // Opcode: FSRC2
/* 5339 */    MCD_OPC_FilterValue, 121, 16, 0, 0, // Skip to: 5360
/* 5344 */    MCD_OPC_CheckPredicate, 3, 164, 9, 0, // Skip to: 7817
/* 5349 */    MCD_OPC_CheckField, 14, 5, 0, 157, 9, 0, // Skip to: 7817
/* 5356 */    MCD_OPC_Decode, 238, 3, 33, // Opcode: FSRC2S
/* 5360 */    MCD_OPC_FilterValue, 122, 9, 0, 0, // Skip to: 5374
/* 5365 */    MCD_OPC_CheckPredicate, 3, 143, 9, 0, // Skip to: 7817
/* 5370 */    MCD_OPC_Decode, 203, 3, 37, // Opcode: FORNOT1
/* 5374 */    MCD_OPC_FilterValue, 123, 9, 0, 0, // Skip to: 5388
/* 5379 */    MCD_OPC_CheckPredicate, 3, 129, 9, 0, // Skip to: 7817
/* 5384 */    MCD_OPC_Decode, 204, 3, 36, // Opcode: FORNOT1S
/* 5388 */    MCD_OPC_FilterValue, 124, 9, 0, 0, // Skip to: 5402
/* 5393 */    MCD_OPC_CheckPredicate, 3, 115, 9, 0, // Skip to: 7817
/* 5398 */    MCD_OPC_Decode, 202, 3, 37, // Opcode: FOR
/* 5402 */    MCD_OPC_FilterValue, 125, 9, 0, 0, // Skip to: 5416
/* 5407 */    MCD_OPC_CheckPredicate, 3, 101, 9, 0, // Skip to: 7817
/* 5412 */    MCD_OPC_Decode, 207, 3, 36, // Opcode: FORS
/* 5416 */    MCD_OPC_FilterValue, 126, 23, 0, 0, // Skip to: 5444
/* 5421 */    MCD_OPC_CheckPredicate, 3, 87, 9, 0, // Skip to: 7817
/* 5426 */    MCD_OPC_CheckField, 14, 5, 0, 80, 9, 0, // Skip to: 7817
/* 5433 */    MCD_OPC_CheckField, 0, 5, 0, 73, 9, 0, // Skip to: 7817
/* 5440 */    MCD_OPC_Decode, 200, 3, 63, // Opcode: FONE
/* 5444 */    MCD_OPC_FilterValue, 127, 23, 0, 0, // Skip to: 5472
/* 5449 */    MCD_OPC_CheckPredicate, 3, 59, 9, 0, // Skip to: 7817
/* 5454 */    MCD_OPC_CheckField, 14, 5, 0, 52, 9, 0, // Skip to: 7817
/* 5461 */    MCD_OPC_CheckField, 0, 5, 0, 45, 9, 0, // Skip to: 7817
/* 5468 */    MCD_OPC_Decode, 201, 3, 64, // Opcode: FONES
/* 5472 */    MCD_OPC_FilterValue, 128, 1, 30, 0, 0, // Skip to: 5508
/* 5478 */    MCD_OPC_CheckPredicate, 3, 30, 9, 0, // Skip to: 7817
/* 5483 */    MCD_OPC_CheckField, 25, 5, 0, 23, 9, 0, // Skip to: 7817
/* 5490 */    MCD_OPC_CheckField, 14, 5, 0, 16, 9, 0, // Skip to: 7817
/* 5497 */    MCD_OPC_CheckField, 0, 5, 0, 9, 9, 0, // Skip to: 7817
/* 5504 */    MCD_OPC_Decode, 250, 4, 4, // Opcode: SHUTDOWN
/* 5508 */    MCD_OPC_FilterValue, 129, 1, 30, 0, 0, // Skip to: 5544
/* 5514 */    MCD_OPC_CheckPredicate, 4, 250, 8, 0, // Skip to: 7817
/* 5519 */    MCD_OPC_CheckField, 25, 5, 0, 243, 8, 0, // Skip to: 7817
/* 5526 */    MCD_OPC_CheckField, 14, 5, 0, 236, 8, 0, // Skip to: 7817
/* 5533 */    MCD_OPC_CheckField, 0, 5, 0, 229, 8, 0, // Skip to: 7817
/* 5540 */    MCD_OPC_Decode, 251, 4, 4, // Opcode: SIAM
/* 5544 */    MCD_OPC_FilterValue, 144, 2, 16, 0, 0, // Skip to: 5566
/* 5550 */    MCD_OPC_CheckPredicate, 2, 214, 8, 0, // Skip to: 7817
/* 5555 */    MCD_OPC_CheckField, 14, 5, 0, 207, 8, 0, // Skip to: 7817
/* 5562 */    MCD_OPC_Decode, 193, 4, 67, // Opcode: MOVDTOX
/* 5566 */    MCD_OPC_FilterValue, 145, 2, 16, 0, 0, // Skip to: 5588
/* 5572 */    MCD_OPC_CheckPredicate, 2, 192, 8, 0, // Skip to: 7817
/* 5577 */    MCD_OPC_CheckField, 14, 5, 0, 185, 8, 0, // Skip to: 7817
/* 5584 */    MCD_OPC_Decode, 201, 4, 68, // Opcode: MOVSTOUW
/* 5588 */    MCD_OPC_FilterValue, 147, 2, 16, 0, 0, // Skip to: 5610
/* 5594 */    MCD_OPC_CheckPredicate, 2, 170, 8, 0, // Skip to: 7817
/* 5599 */    MCD_OPC_CheckField, 14, 5, 0, 163, 8, 0, // Skip to: 7817
/* 5606 */    MCD_OPC_Decode, 200, 4, 68, // Opcode: MOVSTOSW
/* 5610 */    MCD_OPC_FilterValue, 149, 2, 9, 0, 0, // Skip to: 5625
/* 5616 */    MCD_OPC_CheckPredicate, 2, 148, 8, 0, // Skip to: 7817
/* 5621 */    MCD_OPC_Decode, 132, 6, 10, // Opcode: XMULX
/* 5625 */    MCD_OPC_FilterValue, 150, 2, 9, 0, 0, // Skip to: 5640
/* 5631 */    MCD_OPC_CheckPredicate, 2, 133, 8, 0, // Skip to: 7817
/* 5636 */    MCD_OPC_Decode, 133, 6, 10, // Opcode: XMULXHI
/* 5640 */    MCD_OPC_FilterValue, 152, 2, 16, 0, 0, // Skip to: 5662
/* 5646 */    MCD_OPC_CheckPredicate, 2, 118, 8, 0, // Skip to: 7817
/* 5651 */    MCD_OPC_CheckField, 14, 5, 0, 111, 8, 0, // Skip to: 7817
/* 5658 */    MCD_OPC_Decode, 205, 4, 69, // Opcode: MOVXTOD
/* 5662 */    MCD_OPC_FilterValue, 153, 2, 16, 0, 0, // Skip to: 5684
/* 5668 */    MCD_OPC_CheckPredicate, 2, 96, 8, 0, // Skip to: 7817
/* 5673 */    MCD_OPC_CheckField, 14, 5, 0, 89, 8, 0, // Skip to: 7817
/* 5680 */    MCD_OPC_Decode, 202, 4, 70, // Opcode: MOVWTOS
/* 5684 */    MCD_OPC_FilterValue, 209, 2, 9, 0, 0, // Skip to: 5699
/* 5690 */    MCD_OPC_CheckPredicate, 2, 74, 8, 0, // Skip to: 7817
/* 5695 */    MCD_OPC_Decode, 151, 3, 56, // Opcode: FLCMPS
/* 5699 */    MCD_OPC_FilterValue, 210, 2, 64, 8, 0, // Skip to: 7817
/* 5705 */    MCD_OPC_CheckPredicate, 2, 59, 8, 0, // Skip to: 7817
/* 5710 */    MCD_OPC_Decode, 150, 3, 57, // Opcode: FLCMPD
/* 5714 */    MCD_OPC_FilterValue, 56, 28, 0, 0, // Skip to: 5747
/* 5719 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5722 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 5738
/* 5727 */    MCD_OPC_CheckField, 5, 8, 0, 35, 8, 0, // Skip to: 7817
/* 5734 */    MCD_OPC_Decode, 132, 4, 71, // Opcode: JMPLrr
/* 5738 */    MCD_OPC_FilterValue, 1, 26, 8, 0, // Skip to: 7817
/* 5743 */    MCD_OPC_Decode, 131, 4, 72, // Opcode: JMPLri
/* 5747 */    MCD_OPC_FilterValue, 57, 42, 0, 0, // Skip to: 5794
/* 5752 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5755 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 5778
/* 5760 */    MCD_OPC_CheckField, 25, 5, 0, 2, 8, 0, // Skip to: 7817
/* 5767 */    MCD_OPC_CheckField, 5, 8, 0, 251, 7, 0, // Skip to: 7817
/* 5774 */    MCD_OPC_Decode, 239, 4, 73, // Opcode: RETTrr
/* 5778 */    MCD_OPC_FilterValue, 1, 242, 7, 0, // Skip to: 7817
/* 5783 */    MCD_OPC_CheckField, 25, 5, 0, 235, 7, 0, // Skip to: 7817
/* 5790 */    MCD_OPC_Decode, 238, 4, 74, // Opcode: RETTri
/* 5794 */    MCD_OPC_FilterValue, 58, 129, 0, 0, // Skip to: 5928
/* 5799 */    MCD_OPC_ExtractField, 8, 6,  // Inst{13-8} ...
/* 5802 */    MCD_OPC_FilterValue, 16, 23, 0, 0, // Skip to: 5830
/* 5807 */    MCD_OPC_CheckPredicate, 0, 213, 7, 0, // Skip to: 7817
/* 5812 */    MCD_OPC_CheckField, 29, 1, 0, 206, 7, 0, // Skip to: 7817
/* 5819 */    MCD_OPC_CheckField, 5, 3, 0, 199, 7, 0, // Skip to: 7817
/* 5826 */    MCD_OPC_Decode, 224, 5, 75, // Opcode: TXCCrr
/* 5830 */    MCD_OPC_FilterValue, 32, 72, 0, 0, // Skip to: 5907
/* 5835 */    MCD_OPC_ExtractField, 0, 8,  // Inst{7-0} ...
/* 5838 */    MCD_OPC_FilterValue, 1, 18, 0, 0, // Skip to: 5861
/* 5843 */    MCD_OPC_CheckField, 25, 5, 8, 175, 7, 0, // Skip to: 7817
/* 5850 */    MCD_OPC_CheckField, 14, 5, 0, 168, 7, 0, // Skip to: 7817
/* 5857 */    MCD_OPC_Decode, 202, 5, 4, // Opcode: TA1
/* 5861 */    MCD_OPC_FilterValue, 3, 18, 0, 0, // Skip to: 5884
/* 5866 */    MCD_OPC_CheckField, 25, 5, 8, 152, 7, 0, // Skip to: 7817
/* 5873 */    MCD_OPC_CheckField, 14, 5, 0, 145, 7, 0, // Skip to: 7817
/* 5880 */    MCD_OPC_Decode, 203, 5, 4, // Opcode: TA3
/* 5884 */    MCD_OPC_FilterValue, 5, 136, 7, 0, // Skip to: 7817
/* 5889 */    MCD_OPC_CheckField, 25, 5, 8, 129, 7, 0, // Skip to: 7817
/* 5896 */    MCD_OPC_CheckField, 14, 5, 0, 122, 7, 0, // Skip to: 7817
/* 5903 */    MCD_OPC_Decode, 204, 5, 4, // Opcode: TA5
/* 5907 */    MCD_OPC_FilterValue, 48, 113, 7, 0, // Skip to: 7817
/* 5912 */    MCD_OPC_CheckPredicate, 0, 108, 7, 0, // Skip to: 7817
/* 5917 */    MCD_OPC_CheckField, 29, 1, 0, 101, 7, 0, // Skip to: 7817
/* 5924 */    MCD_OPC_Decode, 223, 5, 76, // Opcode: TXCCri
/* 5928 */    MCD_OPC_FilterValue, 59, 62, 0, 0, // Skip to: 5995
/* 5933 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5936 */    MCD_OPC_FilterValue, 0, 38, 0, 0, // Skip to: 5979
/* 5941 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 5944 */    MCD_OPC_FilterValue, 0, 76, 7, 0, // Skip to: 7817
/* 5949 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 5952 */    MCD_OPC_FilterValue, 0, 68, 7, 0, // Skip to: 7817
/* 5957 */    MCD_OPC_CheckField, 14, 5, 0, 11, 0, 0, // Skip to: 5975
/* 5964 */    MCD_OPC_CheckField, 0, 5, 0, 4, 0, 0, // Skip to: 5975
/* 5971 */    MCD_OPC_Decode, 152, 3, 4, // Opcode: FLUSH
/* 5975 */    MCD_OPC_Decode, 155, 3, 73, // Opcode: FLUSHrr
/* 5979 */    MCD_OPC_FilterValue, 1, 41, 7, 0, // Skip to: 7817
/* 5984 */    MCD_OPC_CheckField, 25, 5, 0, 34, 7, 0, // Skip to: 7817
/* 5991 */    MCD_OPC_Decode, 154, 3, 74, // Opcode: FLUSHri
/* 5995 */    MCD_OPC_FilterValue, 60, 28, 0, 0, // Skip to: 6028
/* 6000 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6003 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6019
/* 6008 */    MCD_OPC_CheckField, 5, 8, 0, 10, 7, 0, // Skip to: 7817
/* 6015 */    MCD_OPC_Decode, 242, 4, 8, // Opcode: SAVErr
/* 6019 */    MCD_OPC_FilterValue, 1, 1, 7, 0, // Skip to: 7817
/* 6024 */    MCD_OPC_Decode, 241, 4, 9, // Opcode: SAVEri
/* 6028 */    MCD_OPC_FilterValue, 61, 28, 0, 0, // Skip to: 6061
/* 6033 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6036 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6052
/* 6041 */    MCD_OPC_CheckField, 5, 8, 0, 233, 6, 0, // Skip to: 7817
/* 6048 */    MCD_OPC_Decode, 234, 4, 8, // Opcode: RESTORErr
/* 6052 */    MCD_OPC_FilterValue, 1, 224, 6, 0, // Skip to: 7817
/* 6057 */    MCD_OPC_Decode, 233, 4, 9, // Opcode: RESTOREri
/* 6061 */    MCD_OPC_FilterValue, 62, 88, 0, 0, // Skip to: 6154
/* 6066 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6069 */    MCD_OPC_FilterValue, 0, 71, 0, 0, // Skip to: 6145
/* 6074 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 6077 */    MCD_OPC_FilterValue, 0, 199, 6, 0, // Skip to: 7817
/* 6082 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 6085 */    MCD_OPC_FilterValue, 0, 23, 0, 0, // Skip to: 6113
/* 6090 */    MCD_OPC_CheckPredicate, 0, 46, 0, 0, // Skip to: 6141
/* 6095 */    MCD_OPC_CheckField, 14, 5, 0, 39, 0, 0, // Skip to: 6141
/* 6102 */    MCD_OPC_CheckField, 0, 5, 0, 32, 0, 0, // Skip to: 6141
/* 6109 */    MCD_OPC_Decode, 217, 2, 4, // Opcode: DONE
/* 6113 */    MCD_OPC_FilterValue, 1, 23, 0, 0, // Skip to: 6141
/* 6118 */    MCD_OPC_CheckPredicate, 0, 18, 0, 0, // Skip to: 6141
/* 6123 */    MCD_OPC_CheckField, 14, 5, 0, 11, 0, 0, // Skip to: 6141
/* 6130 */    MCD_OPC_CheckField, 0, 5, 0, 4, 0, 0, // Skip to: 6141
/* 6137 */    MCD_OPC_Decode, 237, 4, 4, // Opcode: RETRY
/* 6141 */    MCD_OPC_Decode, 232, 5, 8, // Opcode: UMACrr
/* 6145 */    MCD_OPC_FilterValue, 1, 131, 6, 0, // Skip to: 7817
/* 6150 */    MCD_OPC_Decode, 231, 5, 9, // Opcode: UMACri
/* 6154 */    MCD_OPC_FilterValue, 63, 122, 6, 0, // Skip to: 7817
/* 6159 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6162 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6178
/* 6167 */    MCD_OPC_CheckField, 5, 8, 0, 107, 6, 0, // Skip to: 7817
/* 6174 */    MCD_OPC_Decode, 130, 5, 8, // Opcode: SMACrr
/* 6178 */    MCD_OPC_FilterValue, 1, 98, 6, 0, // Skip to: 7817
/* 6183 */    MCD_OPC_Decode, 129, 5, 9, // Opcode: SMACri
/* 6187 */    MCD_OPC_FilterValue, 3, 89, 6, 0, // Skip to: 7817
/* 6192 */    MCD_OPC_ExtractField, 19, 6,  // Inst{24-19} ...
/* 6195 */    MCD_OPC_FilterValue, 0, 28, 0, 0, // Skip to: 6228
/* 6200 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6203 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6219
/* 6208 */    MCD_OPC_CheckField, 5, 8, 0, 66, 6, 0, // Skip to: 7817
/* 6215 */    MCD_OPC_Decode, 190, 4, 71, // Opcode: LDrr
/* 6219 */    MCD_OPC_FilterValue, 1, 57, 6, 0, // Skip to: 7817
/* 6224 */    MCD_OPC_Decode, 189, 4, 72, // Opcode: LDri
/* 6228 */    MCD_OPC_FilterValue, 1, 28, 0, 0, // Skip to: 6261
/* 6233 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6236 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6252
/* 6241 */    MCD_OPC_CheckField, 5, 8, 0, 33, 6, 0, // Skip to: 7817
/* 6248 */    MCD_OPC_Decode, 178, 4, 71, // Opcode: LDUBrr
/* 6252 */    MCD_OPC_FilterValue, 1, 24, 6, 0, // Skip to: 7817
/* 6257 */    MCD_OPC_Decode, 177, 4, 72, // Opcode: LDUBri
/* 6261 */    MCD_OPC_FilterValue, 2, 28, 0, 0, // Skip to: 6294
/* 6266 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6269 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6285
/* 6274 */    MCD_OPC_CheckField, 5, 8, 0, 0, 6, 0, // Skip to: 7817
/* 6281 */    MCD_OPC_Decode, 182, 4, 71, // Opcode: LDUHrr
/* 6285 */    MCD_OPC_FilterValue, 1, 247, 5, 0, // Skip to: 7817
/* 6290 */    MCD_OPC_Decode, 181, 4, 72, // Opcode: LDUHri
/* 6294 */    MCD_OPC_FilterValue, 3, 28, 0, 0, // Skip to: 6327
/* 6299 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6302 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6318
/* 6307 */    MCD_OPC_CheckField, 5, 8, 0, 223, 5, 0, // Skip to: 7817
/* 6314 */    MCD_OPC_Decode, 148, 4, 77, // Opcode: LDDrr
/* 6318 */    MCD_OPC_FilterValue, 1, 214, 5, 0, // Skip to: 7817
/* 6323 */    MCD_OPC_Decode, 147, 4, 78, // Opcode: LDDri
/* 6327 */    MCD_OPC_FilterValue, 4, 28, 0, 0, // Skip to: 6360
/* 6332 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6335 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6351
/* 6340 */    MCD_OPC_CheckField, 5, 8, 0, 190, 5, 0, // Skip to: 7817
/* 6347 */    MCD_OPC_Decode, 189, 5, 79, // Opcode: STrr
/* 6351 */    MCD_OPC_FilterValue, 1, 181, 5, 0, // Skip to: 7817
/* 6356 */    MCD_OPC_Decode, 188, 5, 80, // Opcode: STri
/* 6360 */    MCD_OPC_FilterValue, 5, 28, 0, 0, // Skip to: 6393
/* 6365 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6368 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6384
/* 6373 */    MCD_OPC_CheckField, 5, 8, 0, 157, 5, 0, // Skip to: 7817
/* 6380 */    MCD_OPC_Decode, 149, 5, 79, // Opcode: STBrr
/* 6384 */    MCD_OPC_FilterValue, 1, 148, 5, 0, // Skip to: 7817
/* 6389 */    MCD_OPC_Decode, 148, 5, 80, // Opcode: STBri
/* 6393 */    MCD_OPC_FilterValue, 6, 28, 0, 0, // Skip to: 6426
/* 6398 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6401 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6417
/* 6406 */    MCD_OPC_CheckField, 5, 8, 0, 124, 5, 0, // Skip to: 7817
/* 6413 */    MCD_OPC_Decode, 177, 5, 79, // Opcode: STHrr
/* 6417 */    MCD_OPC_FilterValue, 1, 115, 5, 0, // Skip to: 7817
/* 6422 */    MCD_OPC_Decode, 176, 5, 80, // Opcode: STHri
/* 6426 */    MCD_OPC_FilterValue, 7, 28, 0, 0, // Skip to: 6459
/* 6431 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6434 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6450
/* 6439 */    MCD_OPC_CheckField, 5, 8, 0, 91, 5, 0, // Skip to: 7817
/* 6446 */    MCD_OPC_Decode, 167, 5, 81, // Opcode: STDrr
/* 6450 */    MCD_OPC_FilterValue, 1, 82, 5, 0, // Skip to: 7817
/* 6455 */    MCD_OPC_Decode, 166, 5, 82, // Opcode: STDri
/* 6459 */    MCD_OPC_FilterValue, 8, 38, 0, 0, // Skip to: 6502
/* 6464 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6467 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 6488
/* 6472 */    MCD_OPC_CheckPredicate, 0, 60, 5, 0, // Skip to: 7817
/* 6477 */    MCD_OPC_CheckField, 5, 8, 0, 53, 5, 0, // Skip to: 7817
/* 6484 */    MCD_OPC_Decode, 174, 4, 83, // Opcode: LDSWrr
/* 6488 */    MCD_OPC_FilterValue, 1, 44, 5, 0, // Skip to: 7817
/* 6493 */    MCD_OPC_CheckPredicate, 0, 39, 5, 0, // Skip to: 7817
/* 6498 */    MCD_OPC_Decode, 173, 4, 84, // Opcode: LDSWri
/* 6502 */    MCD_OPC_FilterValue, 9, 28, 0, 0, // Skip to: 6535
/* 6507 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6510 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6526
/* 6515 */    MCD_OPC_CheckField, 5, 8, 0, 15, 5, 0, // Skip to: 7817
/* 6522 */    MCD_OPC_Decode, 162, 4, 71, // Opcode: LDSBrr
/* 6526 */    MCD_OPC_FilterValue, 1, 6, 5, 0, // Skip to: 7817
/* 6531 */    MCD_OPC_Decode, 161, 4, 72, // Opcode: LDSBri
/* 6535 */    MCD_OPC_FilterValue, 10, 28, 0, 0, // Skip to: 6568
/* 6540 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6543 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6559
/* 6548 */    MCD_OPC_CheckField, 5, 8, 0, 238, 4, 0, // Skip to: 7817
/* 6555 */    MCD_OPC_Decode, 166, 4, 71, // Opcode: LDSHrr
/* 6559 */    MCD_OPC_FilterValue, 1, 229, 4, 0, // Skip to: 7817
/* 6564 */    MCD_OPC_Decode, 165, 4, 72, // Opcode: LDSHri
/* 6568 */    MCD_OPC_FilterValue, 11, 38, 0, 0, // Skip to: 6611
/* 6573 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6576 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 6597
/* 6581 */    MCD_OPC_CheckPredicate, 0, 207, 4, 0, // Skip to: 7817
/* 6586 */    MCD_OPC_CheckField, 5, 8, 0, 200, 4, 0, // Skip to: 7817
/* 6593 */    MCD_OPC_Decode, 188, 4, 83, // Opcode: LDXrr
/* 6597 */    MCD_OPC_FilterValue, 1, 191, 4, 0, // Skip to: 7817
/* 6602 */    MCD_OPC_CheckPredicate, 0, 186, 4, 0, // Skip to: 7817
/* 6607 */    MCD_OPC_Decode, 187, 4, 84, // Opcode: LDXri
/* 6611 */    MCD_OPC_FilterValue, 13, 28, 0, 0, // Skip to: 6644
/* 6616 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6619 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6635
/* 6624 */    MCD_OPC_CheckField, 5, 8, 0, 162, 4, 0, // Skip to: 7817
/* 6631 */    MCD_OPC_Decode, 170, 4, 71, // Opcode: LDSTUBrr
/* 6635 */    MCD_OPC_FilterValue, 1, 153, 4, 0, // Skip to: 7817
/* 6640 */    MCD_OPC_Decode, 169, 4, 72, // Opcode: LDSTUBri
/* 6644 */    MCD_OPC_FilterValue, 14, 38, 0, 0, // Skip to: 6687
/* 6649 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6652 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 6673
/* 6657 */    MCD_OPC_CheckPredicate, 0, 131, 4, 0, // Skip to: 7817
/* 6662 */    MCD_OPC_CheckField, 5, 8, 0, 124, 4, 0, // Skip to: 7817
/* 6669 */    MCD_OPC_Decode, 187, 5, 85, // Opcode: STXrr
/* 6673 */    MCD_OPC_FilterValue, 1, 115, 4, 0, // Skip to: 7817
/* 6678 */    MCD_OPC_CheckPredicate, 0, 110, 4, 0, // Skip to: 7817
/* 6683 */    MCD_OPC_Decode, 186, 5, 86, // Opcode: STXri
/* 6687 */    MCD_OPC_FilterValue, 15, 28, 0, 0, // Skip to: 6720
/* 6692 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6695 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6711
/* 6700 */    MCD_OPC_CheckField, 5, 8, 0, 86, 4, 0, // Skip to: 7817
/* 6707 */    MCD_OPC_Decode, 201, 5, 87, // Opcode: SWAPrr
/* 6711 */    MCD_OPC_FilterValue, 1, 77, 4, 0, // Skip to: 7817
/* 6716 */    MCD_OPC_Decode, 200, 5, 88, // Opcode: SWAPri
/* 6720 */    MCD_OPC_FilterValue, 16, 26, 0, 0, // Skip to: 6751
/* 6725 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6728 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6737
/* 6733 */    MCD_OPC_Decode, 134, 4, 89, // Opcode: LDArr
/* 6737 */    MCD_OPC_FilterValue, 1, 51, 4, 0, // Skip to: 7817
/* 6742 */    MCD_OPC_CheckPredicate, 0, 46, 4, 0, // Skip to: 7817
/* 6747 */    MCD_OPC_Decode, 133, 4, 72, // Opcode: LDAri
/* 6751 */    MCD_OPC_FilterValue, 17, 26, 0, 0, // Skip to: 6782
/* 6756 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6759 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6768
/* 6764 */    MCD_OPC_Decode, 176, 4, 89, // Opcode: LDUBArr
/* 6768 */    MCD_OPC_FilterValue, 1, 20, 4, 0, // Skip to: 7817
/* 6773 */    MCD_OPC_CheckPredicate, 0, 15, 4, 0, // Skip to: 7817
/* 6778 */    MCD_OPC_Decode, 175, 4, 72, // Opcode: LDUBAri
/* 6782 */    MCD_OPC_FilterValue, 18, 26, 0, 0, // Skip to: 6813
/* 6787 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6790 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6799
/* 6795 */    MCD_OPC_Decode, 180, 4, 89, // Opcode: LDUHArr
/* 6799 */    MCD_OPC_FilterValue, 1, 245, 3, 0, // Skip to: 7817
/* 6804 */    MCD_OPC_CheckPredicate, 0, 240, 3, 0, // Skip to: 7817
/* 6809 */    MCD_OPC_Decode, 179, 4, 72, // Opcode: LDUHAri
/* 6813 */    MCD_OPC_FilterValue, 19, 26, 0, 0, // Skip to: 6844
/* 6818 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6821 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6830
/* 6826 */    MCD_OPC_Decode, 140, 4, 90, // Opcode: LDDArr
/* 6830 */    MCD_OPC_FilterValue, 1, 214, 3, 0, // Skip to: 7817
/* 6835 */    MCD_OPC_CheckPredicate, 0, 209, 3, 0, // Skip to: 7817
/* 6840 */    MCD_OPC_Decode, 139, 4, 78, // Opcode: LDDAri
/* 6844 */    MCD_OPC_FilterValue, 20, 26, 0, 0, // Skip to: 6875
/* 6849 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6852 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6861
/* 6857 */    MCD_OPC_Decode, 144, 5, 91, // Opcode: STArr
/* 6861 */    MCD_OPC_FilterValue, 1, 183, 3, 0, // Skip to: 7817
/* 6866 */    MCD_OPC_CheckPredicate, 0, 178, 3, 0, // Skip to: 7817
/* 6871 */    MCD_OPC_Decode, 143, 5, 80, // Opcode: STAri
/* 6875 */    MCD_OPC_FilterValue, 21, 26, 0, 0, // Skip to: 6906
/* 6880 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6883 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6892
/* 6888 */    MCD_OPC_Decode, 147, 5, 91, // Opcode: STBArr
/* 6892 */    MCD_OPC_FilterValue, 1, 152, 3, 0, // Skip to: 7817
/* 6897 */    MCD_OPC_CheckPredicate, 0, 147, 3, 0, // Skip to: 7817
/* 6902 */    MCD_OPC_Decode, 146, 5, 80, // Opcode: STBAri
/* 6906 */    MCD_OPC_FilterValue, 22, 26, 0, 0, // Skip to: 6937
/* 6911 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6914 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6923
/* 6919 */    MCD_OPC_Decode, 175, 5, 91, // Opcode: STHArr
/* 6923 */    MCD_OPC_FilterValue, 1, 121, 3, 0, // Skip to: 7817
/* 6928 */    MCD_OPC_CheckPredicate, 0, 116, 3, 0, // Skip to: 7817
/* 6933 */    MCD_OPC_Decode, 174, 5, 80, // Opcode: STHAri
/* 6937 */    MCD_OPC_FilterValue, 23, 26, 0, 0, // Skip to: 6968
/* 6942 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6945 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 6954
/* 6950 */    MCD_OPC_Decode, 155, 5, 92, // Opcode: STDArr
/* 6954 */    MCD_OPC_FilterValue, 1, 90, 3, 0, // Skip to: 7817
/* 6959 */    MCD_OPC_CheckPredicate, 0, 85, 3, 0, // Skip to: 7817
/* 6964 */    MCD_OPC_Decode, 154, 5, 82, // Opcode: STDAri
/* 6968 */    MCD_OPC_FilterValue, 24, 31, 0, 0, // Skip to: 7004
/* 6973 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6976 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 6990
/* 6981 */    MCD_OPC_CheckPredicate, 0, 63, 3, 0, // Skip to: 7817
/* 6986 */    MCD_OPC_Decode, 172, 4, 93, // Opcode: LDSWArr
/* 6990 */    MCD_OPC_FilterValue, 1, 54, 3, 0, // Skip to: 7817
/* 6995 */    MCD_OPC_CheckPredicate, 0, 49, 3, 0, // Skip to: 7817
/* 7000 */    MCD_OPC_Decode, 171, 4, 84, // Opcode: LDSWAri
/* 7004 */    MCD_OPC_FilterValue, 25, 26, 0, 0, // Skip to: 7035
/* 7009 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7012 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7021
/* 7017 */    MCD_OPC_Decode, 160, 4, 89, // Opcode: LDSBArr
/* 7021 */    MCD_OPC_FilterValue, 1, 23, 3, 0, // Skip to: 7817
/* 7026 */    MCD_OPC_CheckPredicate, 0, 18, 3, 0, // Skip to: 7817
/* 7031 */    MCD_OPC_Decode, 159, 4, 72, // Opcode: LDSBAri
/* 7035 */    MCD_OPC_FilterValue, 26, 26, 0, 0, // Skip to: 7066
/* 7040 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7043 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7052
/* 7048 */    MCD_OPC_Decode, 164, 4, 89, // Opcode: LDSHArr
/* 7052 */    MCD_OPC_FilterValue, 1, 248, 2, 0, // Skip to: 7817
/* 7057 */    MCD_OPC_CheckPredicate, 0, 243, 2, 0, // Skip to: 7817
/* 7062 */    MCD_OPC_Decode, 163, 4, 72, // Opcode: LDSHAri
/* 7066 */    MCD_OPC_FilterValue, 27, 31, 0, 0, // Skip to: 7102
/* 7071 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7074 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 7088
/* 7079 */    MCD_OPC_CheckPredicate, 0, 221, 2, 0, // Skip to: 7817
/* 7084 */    MCD_OPC_Decode, 184, 4, 93, // Opcode: LDXArr
/* 7088 */    MCD_OPC_FilterValue, 1, 212, 2, 0, // Skip to: 7817
/* 7093 */    MCD_OPC_CheckPredicate, 0, 207, 2, 0, // Skip to: 7817
/* 7098 */    MCD_OPC_Decode, 183, 4, 84, // Opcode: LDXAri
/* 7102 */    MCD_OPC_FilterValue, 29, 26, 0, 0, // Skip to: 7133
/* 7107 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7110 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7119
/* 7115 */    MCD_OPC_Decode, 168, 4, 89, // Opcode: LDSTUBArr
/* 7119 */    MCD_OPC_FilterValue, 1, 181, 2, 0, // Skip to: 7817
/* 7124 */    MCD_OPC_CheckPredicate, 0, 176, 2, 0, // Skip to: 7817
/* 7129 */    MCD_OPC_Decode, 167, 4, 72, // Opcode: LDSTUBAri
/* 7133 */    MCD_OPC_FilterValue, 30, 31, 0, 0, // Skip to: 7169
/* 7138 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7141 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 7155
/* 7146 */    MCD_OPC_CheckPredicate, 0, 154, 2, 0, // Skip to: 7817
/* 7151 */    MCD_OPC_Decode, 183, 5, 94, // Opcode: STXArr
/* 7155 */    MCD_OPC_FilterValue, 1, 145, 2, 0, // Skip to: 7817
/* 7160 */    MCD_OPC_CheckPredicate, 0, 140, 2, 0, // Skip to: 7817
/* 7165 */    MCD_OPC_Decode, 182, 5, 86, // Opcode: STXAri
/* 7169 */    MCD_OPC_FilterValue, 31, 26, 0, 0, // Skip to: 7200
/* 7174 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7177 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7186
/* 7182 */    MCD_OPC_Decode, 199, 5, 95, // Opcode: SWAPArr
/* 7186 */    MCD_OPC_FilterValue, 1, 114, 2, 0, // Skip to: 7817
/* 7191 */    MCD_OPC_CheckPredicate, 0, 109, 2, 0, // Skip to: 7817
/* 7196 */    MCD_OPC_Decode, 198, 5, 88, // Opcode: SWAPAri
/* 7200 */    MCD_OPC_FilterValue, 32, 28, 0, 0, // Skip to: 7233
/* 7205 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7208 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7224
/* 7213 */    MCD_OPC_CheckField, 5, 8, 0, 85, 2, 0, // Skip to: 7817
/* 7220 */    MCD_OPC_Decode, 154, 4, 96, // Opcode: LDFrr
/* 7224 */    MCD_OPC_FilterValue, 1, 76, 2, 0, // Skip to: 7817
/* 7229 */    MCD_OPC_Decode, 153, 4, 97, // Opcode: LDFri
/* 7233 */    MCD_OPC_FilterValue, 33, 79, 0, 0, // Skip to: 7317
/* 7238 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7241 */    MCD_OPC_FilterValue, 0, 40, 0, 0, // Skip to: 7286
/* 7246 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 7249 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7265
/* 7254 */    MCD_OPC_CheckField, 5, 8, 0, 44, 2, 0, // Skip to: 7817
/* 7261 */    MCD_OPC_Decode, 152, 4, 73, // Opcode: LDFSRrr
/* 7265 */    MCD_OPC_FilterValue, 1, 35, 2, 0, // Skip to: 7817
/* 7270 */    MCD_OPC_CheckPredicate, 0, 30, 2, 0, // Skip to: 7817
/* 7275 */    MCD_OPC_CheckField, 5, 8, 0, 23, 2, 0, // Skip to: 7817
/* 7282 */    MCD_OPC_Decode, 186, 4, 73, // Opcode: LDXFSRrr
/* 7286 */    MCD_OPC_FilterValue, 1, 14, 2, 0, // Skip to: 7817
/* 7291 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 7294 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7303
/* 7299 */    MCD_OPC_Decode, 151, 4, 74, // Opcode: LDFSRri
/* 7303 */    MCD_OPC_FilterValue, 1, 253, 1, 0, // Skip to: 7817
/* 7308 */    MCD_OPC_CheckPredicate, 0, 248, 1, 0, // Skip to: 7817
/* 7313 */    MCD_OPC_Decode, 185, 4, 74, // Opcode: LDXFSRri
/* 7317 */    MCD_OPC_FilterValue, 35, 28, 0, 0, // Skip to: 7350
/* 7322 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7325 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7341
/* 7330 */    MCD_OPC_CheckField, 5, 8, 0, 224, 1, 0, // Skip to: 7817
/* 7337 */    MCD_OPC_Decode, 146, 4, 98, // Opcode: LDDFrr
/* 7341 */    MCD_OPC_FilterValue, 1, 215, 1, 0, // Skip to: 7817
/* 7346 */    MCD_OPC_Decode, 145, 4, 99, // Opcode: LDDFri
/* 7350 */    MCD_OPC_FilterValue, 36, 28, 0, 0, // Skip to: 7383
/* 7355 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7358 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7374
/* 7363 */    MCD_OPC_CheckField, 5, 8, 0, 191, 1, 0, // Skip to: 7817
/* 7370 */    MCD_OPC_Decode, 173, 5, 100, // Opcode: STFrr
/* 7374 */    MCD_OPC_FilterValue, 1, 182, 1, 0, // Skip to: 7817
/* 7379 */    MCD_OPC_Decode, 172, 5, 101, // Opcode: STFri
/* 7383 */    MCD_OPC_FilterValue, 37, 79, 0, 0, // Skip to: 7467
/* 7388 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7391 */    MCD_OPC_FilterValue, 0, 40, 0, 0, // Skip to: 7436
/* 7396 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 7399 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7415
/* 7404 */    MCD_OPC_CheckField, 5, 8, 0, 150, 1, 0, // Skip to: 7817
/* 7411 */    MCD_OPC_Decode, 171, 5, 73, // Opcode: STFSRrr
/* 7415 */    MCD_OPC_FilterValue, 1, 141, 1, 0, // Skip to: 7817
/* 7420 */    MCD_OPC_CheckPredicate, 0, 136, 1, 0, // Skip to: 7817
/* 7425 */    MCD_OPC_CheckField, 5, 8, 0, 129, 1, 0, // Skip to: 7817
/* 7432 */    MCD_OPC_Decode, 185, 5, 73, // Opcode: STXFSRrr
/* 7436 */    MCD_OPC_FilterValue, 1, 120, 1, 0, // Skip to: 7817
/* 7441 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 7444 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7453
/* 7449 */    MCD_OPC_Decode, 170, 5, 74, // Opcode: STFSRri
/* 7453 */    MCD_OPC_FilterValue, 1, 103, 1, 0, // Skip to: 7817
/* 7458 */    MCD_OPC_CheckPredicate, 0, 98, 1, 0, // Skip to: 7817
/* 7463 */    MCD_OPC_Decode, 184, 5, 74, // Opcode: STXFSRri
/* 7467 */    MCD_OPC_FilterValue, 38, 42, 0, 0, // Skip to: 7514
/* 7472 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7475 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 7498
/* 7480 */    MCD_OPC_CheckField, 25, 5, 0, 74, 1, 0, // Skip to: 7817
/* 7487 */    MCD_OPC_CheckField, 5, 8, 0, 67, 1, 0, // Skip to: 7817
/* 7494 */    MCD_OPC_Decode, 163, 5, 73, // Opcode: STDFQrr
/* 7498 */    MCD_OPC_FilterValue, 1, 58, 1, 0, // Skip to: 7817
/* 7503 */    MCD_OPC_CheckField, 25, 5, 0, 51, 1, 0, // Skip to: 7817
/* 7510 */    MCD_OPC_Decode, 162, 5, 74, // Opcode: STDFQri
/* 7514 */    MCD_OPC_FilterValue, 39, 28, 0, 0, // Skip to: 7547
/* 7519 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7522 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7538
/* 7527 */    MCD_OPC_CheckField, 5, 8, 0, 27, 1, 0, // Skip to: 7817
/* 7534 */    MCD_OPC_Decode, 165, 5, 102, // Opcode: STDFrr
/* 7538 */    MCD_OPC_FilterValue, 1, 18, 1, 0, // Skip to: 7817
/* 7543 */    MCD_OPC_Decode, 164, 5, 103, // Opcode: STDFri
/* 7547 */    MCD_OPC_FilterValue, 45, 38, 0, 0, // Skip to: 7590
/* 7552 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7555 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 7576
/* 7560 */    MCD_OPC_CheckPredicate, 0, 252, 0, 0, // Skip to: 7817
/* 7565 */    MCD_OPC_CheckField, 5, 8, 0, 245, 0, 0, // Skip to: 7817
/* 7572 */    MCD_OPC_Decode, 223, 4, 104, // Opcode: PREFETCHr
/* 7576 */    MCD_OPC_FilterValue, 1, 236, 0, 0, // Skip to: 7817
/* 7581 */    MCD_OPC_CheckPredicate, 0, 231, 0, 0, // Skip to: 7817
/* 7586 */    MCD_OPC_Decode, 222, 4, 105, // Opcode: PREFETCHi
/* 7590 */    MCD_OPC_FilterValue, 49, 42, 0, 0, // Skip to: 7637
/* 7595 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7598 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 7621
/* 7603 */    MCD_OPC_CheckField, 25, 5, 0, 207, 0, 0, // Skip to: 7817
/* 7610 */    MCD_OPC_CheckField, 5, 8, 0, 200, 0, 0, // Skip to: 7817
/* 7617 */    MCD_OPC_Decode, 136, 4, 73, // Opcode: LDCSRrr
/* 7621 */    MCD_OPC_FilterValue, 1, 191, 0, 0, // Skip to: 7817
/* 7626 */    MCD_OPC_CheckField, 25, 5, 0, 184, 0, 0, // Skip to: 7817
/* 7633 */    MCD_OPC_Decode, 135, 4, 74, // Opcode: LDCSRri
/* 7637 */    MCD_OPC_FilterValue, 53, 42, 0, 0, // Skip to: 7684
/* 7642 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7645 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 7668
/* 7650 */    MCD_OPC_CheckField, 25, 5, 0, 160, 0, 0, // Skip to: 7817
/* 7657 */    MCD_OPC_CheckField, 5, 8, 0, 153, 0, 0, // Skip to: 7817
/* 7664 */    MCD_OPC_Decode, 151, 5, 73, // Opcode: STCSRrr
/* 7668 */    MCD_OPC_FilterValue, 1, 144, 0, 0, // Skip to: 7817
/* 7673 */    MCD_OPC_CheckField, 25, 5, 0, 137, 0, 0, // Skip to: 7817
/* 7680 */    MCD_OPC_Decode, 150, 5, 74, // Opcode: STCSRri
/* 7684 */    MCD_OPC_FilterValue, 54, 42, 0, 0, // Skip to: 7731
/* 7689 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7692 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 7715
/* 7697 */    MCD_OPC_CheckField, 25, 5, 0, 113, 0, 0, // Skip to: 7817
/* 7704 */    MCD_OPC_CheckField, 5, 8, 0, 106, 0, 0, // Skip to: 7817
/* 7711 */    MCD_OPC_Decode, 157, 5, 73, // Opcode: STDCQrr
/* 7715 */    MCD_OPC_FilterValue, 1, 97, 0, 0, // Skip to: 7817
/* 7720 */    MCD_OPC_CheckField, 25, 5, 0, 90, 0, 0, // Skip to: 7817
/* 7727 */    MCD_OPC_Decode, 156, 5, 74, // Opcode: STDCQri
/* 7731 */    MCD_OPC_FilterValue, 60, 38, 0, 0, // Skip to: 7774
/* 7736 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7739 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 7753
/* 7744 */    MCD_OPC_CheckPredicate, 5, 68, 0, 0, // Skip to: 7817
/* 7749 */    MCD_OPC_Decode, 209, 2, 106, // Opcode: CASArr
/* 7753 */    MCD_OPC_FilterValue, 1, 59, 0, 0, // Skip to: 7817
/* 7758 */    MCD_OPC_CheckPredicate, 0, 54, 0, 0, // Skip to: 7817
/* 7763 */    MCD_OPC_CheckField, 5, 8, 0, 47, 0, 0, // Skip to: 7817
/* 7770 */    MCD_OPC_Decode, 208, 2, 107, // Opcode: CASAri
/* 7774 */    MCD_OPC_FilterValue, 62, 38, 0, 0, // Skip to: 7817
/* 7779 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7782 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 7796
/* 7787 */    MCD_OPC_CheckPredicate, 6, 25, 0, 0, // Skip to: 7817
/* 7792 */    MCD_OPC_Decode, 211, 2, 108, // Opcode: CASXArr
/* 7796 */    MCD_OPC_FilterValue, 1, 16, 0, 0, // Skip to: 7817
/* 7801 */    MCD_OPC_CheckPredicate, 6, 11, 0, 0, // Skip to: 7817
/* 7806 */    MCD_OPC_CheckField, 5, 8, 0, 4, 0, 0, // Skip to: 7817
/* 7813 */    MCD_OPC_Decode, 210, 2, 109, // Opcode: CASXAri
/* 7817 */    MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableSparcV832[] = {
/* 0 */       MCD_OPC_ExtractField, 19, 6,  // Inst{24-19} ...
/* 3 */       MCD_OPC_FilterValue, 48, 42, 0, 0, // Skip to: 50
/* 8 */       MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 11 */      MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 34
/* 16 */      MCD_OPC_CheckField, 30, 2, 3, 215, 0, 0, // Skip to: 238
/* 23 */      MCD_OPC_CheckField, 5, 8, 0, 208, 0, 0, // Skip to: 238
/* 30 */      MCD_OPC_Decode, 138, 4, 110, // Opcode: LDCrr
/* 34 */      MCD_OPC_FilterValue, 1, 199, 0, 0, // Skip to: 238
/* 39 */      MCD_OPC_CheckField, 30, 2, 3, 192, 0, 0, // Skip to: 238
/* 46 */      MCD_OPC_Decode, 137, 4, 111, // Opcode: LDCri
/* 50 */      MCD_OPC_FilterValue, 51, 42, 0, 0, // Skip to: 97
/* 55 */      MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 58 */      MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 81
/* 63 */      MCD_OPC_CheckField, 30, 2, 3, 168, 0, 0, // Skip to: 238
/* 70 */      MCD_OPC_CheckField, 5, 8, 0, 161, 0, 0, // Skip to: 238
/* 77 */      MCD_OPC_Decode, 142, 4, 112, // Opcode: LDDCrr
/* 81 */      MCD_OPC_FilterValue, 1, 152, 0, 0, // Skip to: 238
/* 86 */      MCD_OPC_CheckField, 30, 2, 3, 145, 0, 0, // Skip to: 238
/* 93 */      MCD_OPC_Decode, 141, 4, 113, // Opcode: LDDCri
/* 97 */      MCD_OPC_FilterValue, 52, 42, 0, 0, // Skip to: 144
/* 102 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 105 */     MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 128
/* 110 */     MCD_OPC_CheckField, 30, 2, 3, 121, 0, 0, // Skip to: 238
/* 117 */     MCD_OPC_CheckField, 5, 8, 0, 114, 0, 0, // Skip to: 238
/* 124 */     MCD_OPC_Decode, 153, 5, 114, // Opcode: STCrr
/* 128 */     MCD_OPC_FilterValue, 1, 105, 0, 0, // Skip to: 238
/* 133 */     MCD_OPC_CheckField, 30, 2, 3, 98, 0, 0, // Skip to: 238
/* 140 */     MCD_OPC_Decode, 152, 5, 115, // Opcode: STCri
/* 144 */     MCD_OPC_FilterValue, 55, 42, 0, 0, // Skip to: 191
/* 149 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 152 */     MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 175
/* 157 */     MCD_OPC_CheckField, 30, 2, 3, 74, 0, 0, // Skip to: 238
/* 164 */     MCD_OPC_CheckField, 5, 8, 0, 67, 0, 0, // Skip to: 238
/* 171 */     MCD_OPC_Decode, 159, 5, 116, // Opcode: STDCrr
/* 175 */     MCD_OPC_FilterValue, 1, 58, 0, 0, // Skip to: 238
/* 180 */     MCD_OPC_CheckField, 30, 2, 3, 51, 0, 0, // Skip to: 238
/* 187 */     MCD_OPC_Decode, 158, 5, 117, // Opcode: STDCri
/* 191 */     MCD_OPC_FilterValue, 58, 42, 0, 0, // Skip to: 238
/* 196 */     MCD_OPC_ExtractField, 8, 6,  // Inst{13-8} ...
/* 199 */     MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 222
/* 204 */     MCD_OPC_CheckField, 29, 3, 4, 27, 0, 0, // Skip to: 238
/* 211 */     MCD_OPC_CheckField, 5, 3, 0, 20, 0, 0, // Skip to: 238
/* 218 */     MCD_OPC_Decode, 218, 5, 75, // Opcode: TRAPrr
/* 222 */     MCD_OPC_FilterValue, 32, 11, 0, 0, // Skip to: 238
/* 227 */     MCD_OPC_CheckField, 29, 3, 4, 4, 0, 0, // Skip to: 238
/* 234 */     MCD_OPC_Decode, 217, 5, 76, // Opcode: TRAPri
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
/* 35 */      MCD_OPC_Decode, 158, 4, 118, // Opcode: LDQFrr
/* 39 */      MCD_OPC_FilterValue, 1, 174, 1, 0, // Skip to: 474
/* 44 */      MCD_OPC_CheckPredicate, 0, 169, 1, 0, // Skip to: 474
/* 49 */      MCD_OPC_CheckField, 30, 2, 3, 162, 1, 0, // Skip to: 474
/* 56 */      MCD_OPC_Decode, 157, 4, 119, // Opcode: LDQFri
/* 60 */      MCD_OPC_FilterValue, 38, 52, 0, 0, // Skip to: 117
/* 65 */      MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 68 */      MCD_OPC_FilterValue, 0, 23, 0, 0, // Skip to: 96
/* 73 */      MCD_OPC_CheckPredicate, 0, 140, 1, 0, // Skip to: 474
/* 78 */      MCD_OPC_CheckField, 30, 2, 3, 133, 1, 0, // Skip to: 474
/* 85 */      MCD_OPC_CheckField, 5, 8, 0, 126, 1, 0, // Skip to: 474
/* 92 */      MCD_OPC_Decode, 181, 5, 120, // Opcode: STQFrr
/* 96 */      MCD_OPC_FilterValue, 1, 117, 1, 0, // Skip to: 474
/* 101 */     MCD_OPC_CheckPredicate, 0, 112, 1, 0, // Skip to: 474
/* 106 */     MCD_OPC_CheckField, 30, 2, 3, 105, 1, 0, // Skip to: 474
/* 113 */     MCD_OPC_Decode, 180, 5, 121, // Opcode: STQFri
/* 117 */     MCD_OPC_FilterValue, 48, 45, 0, 0, // Skip to: 167
/* 122 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 125 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 146
/* 130 */     MCD_OPC_CheckPredicate, 0, 83, 1, 0, // Skip to: 474
/* 135 */     MCD_OPC_CheckField, 30, 2, 3, 76, 1, 0, // Skip to: 474
/* 142 */     MCD_OPC_Decode, 150, 4, 122, // Opcode: LDFArr
/* 146 */     MCD_OPC_FilterValue, 1, 67, 1, 0, // Skip to: 474
/* 151 */     MCD_OPC_CheckPredicate, 0, 62, 1, 0, // Skip to: 474
/* 156 */     MCD_OPC_CheckField, 30, 2, 3, 55, 1, 0, // Skip to: 474
/* 163 */     MCD_OPC_Decode, 149, 4, 97, // Opcode: LDFAri
/* 167 */     MCD_OPC_FilterValue, 50, 45, 0, 0, // Skip to: 217
/* 172 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 175 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 196
/* 180 */     MCD_OPC_CheckPredicate, 0, 33, 1, 0, // Skip to: 474
/* 185 */     MCD_OPC_CheckField, 30, 2, 3, 26, 1, 0, // Skip to: 474
/* 192 */     MCD_OPC_Decode, 156, 4, 123, // Opcode: LDQFArr
/* 196 */     MCD_OPC_FilterValue, 1, 17, 1, 0, // Skip to: 474
/* 201 */     MCD_OPC_CheckPredicate, 0, 12, 1, 0, // Skip to: 474
/* 206 */     MCD_OPC_CheckField, 30, 2, 3, 5, 1, 0, // Skip to: 474
/* 213 */     MCD_OPC_Decode, 155, 4, 119, // Opcode: LDQFAri
/* 217 */     MCD_OPC_FilterValue, 51, 45, 0, 0, // Skip to: 267
/* 222 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 225 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 246
/* 230 */     MCD_OPC_CheckPredicate, 0, 239, 0, 0, // Skip to: 474
/* 235 */     MCD_OPC_CheckField, 30, 2, 3, 232, 0, 0, // Skip to: 474
/* 242 */     MCD_OPC_Decode, 144, 4, 124, // Opcode: LDDFArr
/* 246 */     MCD_OPC_FilterValue, 1, 223, 0, 0, // Skip to: 474
/* 251 */     MCD_OPC_CheckPredicate, 0, 218, 0, 0, // Skip to: 474
/* 256 */     MCD_OPC_CheckField, 30, 2, 3, 211, 0, 0, // Skip to: 474
/* 263 */     MCD_OPC_Decode, 143, 4, 99, // Opcode: LDDFAri
/* 267 */     MCD_OPC_FilterValue, 52, 45, 0, 0, // Skip to: 317
/* 272 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 275 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 296
/* 280 */     MCD_OPC_CheckPredicate, 0, 189, 0, 0, // Skip to: 474
/* 285 */     MCD_OPC_CheckField, 30, 2, 3, 182, 0, 0, // Skip to: 474
/* 292 */     MCD_OPC_Decode, 169, 5, 125, // Opcode: STFArr
/* 296 */     MCD_OPC_FilterValue, 1, 173, 0, 0, // Skip to: 474
/* 301 */     MCD_OPC_CheckPredicate, 0, 168, 0, 0, // Skip to: 474
/* 306 */     MCD_OPC_CheckField, 30, 2, 3, 161, 0, 0, // Skip to: 474
/* 313 */     MCD_OPC_Decode, 168, 5, 101, // Opcode: STFAri
/* 317 */     MCD_OPC_FilterValue, 54, 45, 0, 0, // Skip to: 367
/* 322 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 325 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 346
/* 330 */     MCD_OPC_CheckPredicate, 0, 139, 0, 0, // Skip to: 474
/* 335 */     MCD_OPC_CheckField, 30, 2, 3, 132, 0, 0, // Skip to: 474
/* 342 */     MCD_OPC_Decode, 179, 5, 126, // Opcode: STQFArr
/* 346 */     MCD_OPC_FilterValue, 1, 123, 0, 0, // Skip to: 474
/* 351 */     MCD_OPC_CheckPredicate, 0, 118, 0, 0, // Skip to: 474
/* 356 */     MCD_OPC_CheckField, 30, 2, 3, 111, 0, 0, // Skip to: 474
/* 363 */     MCD_OPC_Decode, 178, 5, 121, // Opcode: STQFAri
/* 367 */     MCD_OPC_FilterValue, 55, 45, 0, 0, // Skip to: 417
/* 372 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 375 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 396
/* 380 */     MCD_OPC_CheckPredicate, 0, 89, 0, 0, // Skip to: 474
/* 385 */     MCD_OPC_CheckField, 30, 2, 3, 82, 0, 0, // Skip to: 474
/* 392 */     MCD_OPC_Decode, 161, 5, 127, // Opcode: STDFArr
/* 396 */     MCD_OPC_FilterValue, 1, 73, 0, 0, // Skip to: 474
/* 401 */     MCD_OPC_CheckPredicate, 0, 68, 0, 0, // Skip to: 474
/* 406 */     MCD_OPC_CheckField, 30, 2, 3, 61, 0, 0, // Skip to: 474
/* 413 */     MCD_OPC_Decode, 160, 5, 103, // Opcode: STDFAri
/* 417 */     MCD_OPC_FilterValue, 58, 52, 0, 0, // Skip to: 474
/* 422 */     MCD_OPC_ExtractField, 8, 6,  // Inst{13-8} ...
/* 425 */     MCD_OPC_FilterValue, 0, 23, 0, 0, // Skip to: 453
/* 430 */     MCD_OPC_CheckPredicate, 0, 39, 0, 0, // Skip to: 474
/* 435 */     MCD_OPC_CheckField, 29, 3, 4, 32, 0, 0, // Skip to: 474
/* 442 */     MCD_OPC_CheckField, 5, 3, 0, 25, 0, 0, // Skip to: 474
/* 449 */     MCD_OPC_Decode, 212, 5, 75, // Opcode: TICCrr
/* 453 */     MCD_OPC_FilterValue, 32, 16, 0, 0, // Skip to: 474
/* 458 */     MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 474
/* 463 */     MCD_OPC_CheckField, 29, 3, 4, 4, 0, 0, // Skip to: 474
/* 470 */     MCD_OPC_Decode, 211, 5, 76, // Opcode: TICCri
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
  case 6:
    return (Sparc_getFeatureBits(Inst->csh->mode, Sparc_FeatureV9) && Sparc_getFeatureBits(Inst->csh->mode, Sparc_FeatureV9));
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
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 63: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 64: \
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
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 69: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 70: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 71: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 72: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 73: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 74: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 75: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 76: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 77: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 78: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 79: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 80: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 81: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 82: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 83: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 84: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 85: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 86: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 87: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 88: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 89: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 90: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
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
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 92: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 93: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 94: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 95: \
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
  case 96: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 97: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 98: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 99: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 100: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 101: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 102: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 103: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 104: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 105: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 106: \
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
  case 107: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 108: \
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
  case 109: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 110: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 111: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 112: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 113: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 114: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 115: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 116: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 117: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeCoprocPairRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 118: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 119: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 120: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 121: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 122: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 123: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 124: \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 125: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 126: \
    tmp = fieldname(insn, 14, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodePointerLikeRegClass0(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 25, 5); \
    if (!Check(&S, DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 127: \
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
