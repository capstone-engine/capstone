/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* * Sparc Disassembler                                                         *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

/* Capstone Disassembly Engine */
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

static const uint8_t DecoderTableSparc32[] = {
/* 0 */       MCD_OPC_ExtractField, 30, 2,  // Inst{31-30} ...
/* 3 */       MCD_OPC_FilterValue, 0, 13, 2, // Skip to: 532
/* 7 */       MCD_OPC_ExtractField, 22, 3,  // Inst{24-22} ...
/* 10 */      MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 24
/* 14 */      MCD_OPC_CheckField, 25, 5, 0, 161, 22, // Skip to: 5813
/* 20 */      MCD_OPC_Decode, 209, 3, 0, // Opcode: UNIMP
/* 24 */      MCD_OPC_FilterValue, 1, 103, 0, // Skip to: 131
/* 28 */      MCD_OPC_ExtractField, 19, 3,  // Inst{21-19} ...
/* 31 */      MCD_OPC_FilterValue, 0, 25, 0, // Skip to: 60
/* 35 */      MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 38 */      MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 49
/* 42 */      MCD_OPC_CheckPredicate, 0, 135, 22, // Skip to: 5813
/* 46 */      MCD_OPC_Decode, 92, 1, // Opcode: BPICCNT
/* 49 */      MCD_OPC_FilterValue, 1, 128, 22, // Skip to: 5813
/* 53 */      MCD_OPC_CheckPredicate, 0, 124, 22, // Skip to: 5813
/* 57 */      MCD_OPC_Decode, 91, 1, // Opcode: BPICCANT
/* 60 */      MCD_OPC_FilterValue, 1, 25, 0, // Skip to: 89
/* 64 */      MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 67 */      MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 78
/* 71 */      MCD_OPC_CheckPredicate, 0, 106, 22, // Skip to: 5813
/* 75 */      MCD_OPC_Decode, 89, 1, // Opcode: BPICC
/* 78 */      MCD_OPC_FilterValue, 1, 99, 22, // Skip to: 5813
/* 82 */      MCD_OPC_CheckPredicate, 0, 95, 22, // Skip to: 5813
/* 86 */      MCD_OPC_Decode, 90, 1, // Opcode: BPICCA
/* 89 */      MCD_OPC_FilterValue, 4, 17, 0, // Skip to: 110
/* 93 */      MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 96 */      MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 103
/* 100 */     MCD_OPC_Decode, 108, 1, // Opcode: BPXCCNT
/* 103 */     MCD_OPC_FilterValue, 1, 74, 22, // Skip to: 5813
/* 107 */     MCD_OPC_Decode, 107, 1, // Opcode: BPXCCANT
/* 110 */     MCD_OPC_FilterValue, 5, 67, 22, // Skip to: 5813
/* 114 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 117 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 124
/* 121 */     MCD_OPC_Decode, 105, 1, // Opcode: BPXCC
/* 124 */     MCD_OPC_FilterValue, 1, 53, 22, // Skip to: 5813
/* 128 */     MCD_OPC_Decode, 106, 1, // Opcode: BPXCCA
/* 131 */     MCD_OPC_FilterValue, 2, 26, 0, // Skip to: 161
/* 135 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 138 */     MCD_OPC_FilterValue, 0, 12, 0, // Skip to: 154
/* 142 */     MCD_OPC_CheckField, 25, 4, 8, 3, 0, // Skip to: 151
/* 148 */     MCD_OPC_Decode, 71, 0, // Opcode: BA
/* 151 */     MCD_OPC_Decode, 72, 2, // Opcode: BCOND
/* 154 */     MCD_OPC_FilterValue, 1, 23, 22, // Skip to: 5813
/* 158 */     MCD_OPC_Decode, 73, 2, // Opcode: BCONDA
/* 161 */     MCD_OPC_FilterValue, 3, 255, 0, // Skip to: 420
/* 165 */     MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 168 */     MCD_OPC_FilterValue, 1, 17, 0, // Skip to: 189
/* 172 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 175 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 182
/* 179 */     MCD_OPC_Decode, 111, 3, // Opcode: BPZnapn
/* 182 */     MCD_OPC_FilterValue, 1, 251, 21, // Skip to: 5813
/* 186 */     MCD_OPC_Decode, 112, 3, // Opcode: BPZnapt
/* 189 */     MCD_OPC_FilterValue, 2, 17, 0, // Skip to: 210
/* 193 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 196 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 203
/* 200 */     MCD_OPC_Decode, 95, 3, // Opcode: BPLEZnapn
/* 203 */     MCD_OPC_FilterValue, 1, 230, 21, // Skip to: 5813
/* 207 */     MCD_OPC_Decode, 96, 3, // Opcode: BPLEZnapt
/* 210 */     MCD_OPC_FilterValue, 3, 17, 0, // Skip to: 231
/* 214 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 217 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 224
/* 221 */     MCD_OPC_Decode, 99, 3, // Opcode: BPLZnapn
/* 224 */     MCD_OPC_FilterValue, 1, 209, 21, // Skip to: 5813
/* 228 */     MCD_OPC_Decode, 100, 3, // Opcode: BPLZnapt
/* 231 */     MCD_OPC_FilterValue, 5, 17, 0, // Skip to: 252
/* 235 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 238 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 245
/* 242 */     MCD_OPC_Decode, 103, 3, // Opcode: BPNZnapn
/* 245 */     MCD_OPC_FilterValue, 1, 188, 21, // Skip to: 5813
/* 249 */     MCD_OPC_Decode, 104, 3, // Opcode: BPNZnapt
/* 252 */     MCD_OPC_FilterValue, 6, 17, 0, // Skip to: 273
/* 256 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 259 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 266
/* 263 */     MCD_OPC_Decode, 87, 3, // Opcode: BPGZnapn
/* 266 */     MCD_OPC_FilterValue, 1, 167, 21, // Skip to: 5813
/* 270 */     MCD_OPC_Decode, 88, 3, // Opcode: BPGZnapt
/* 273 */     MCD_OPC_FilterValue, 7, 17, 0, // Skip to: 294
/* 277 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 280 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 287
/* 284 */     MCD_OPC_Decode, 83, 3, // Opcode: BPGEZnapn
/* 287 */     MCD_OPC_FilterValue, 1, 146, 21, // Skip to: 5813
/* 291 */     MCD_OPC_Decode, 84, 3, // Opcode: BPGEZnapt
/* 294 */     MCD_OPC_FilterValue, 17, 17, 0, // Skip to: 315
/* 298 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 301 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 308
/* 305 */     MCD_OPC_Decode, 109, 3, // Opcode: BPZapn
/* 308 */     MCD_OPC_FilterValue, 1, 125, 21, // Skip to: 5813
/* 312 */     MCD_OPC_Decode, 110, 3, // Opcode: BPZapt
/* 315 */     MCD_OPC_FilterValue, 18, 17, 0, // Skip to: 336
/* 319 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 322 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 329
/* 326 */     MCD_OPC_Decode, 93, 3, // Opcode: BPLEZapn
/* 329 */     MCD_OPC_FilterValue, 1, 104, 21, // Skip to: 5813
/* 333 */     MCD_OPC_Decode, 94, 3, // Opcode: BPLEZapt
/* 336 */     MCD_OPC_FilterValue, 19, 17, 0, // Skip to: 357
/* 340 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 343 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 350
/* 347 */     MCD_OPC_Decode, 97, 3, // Opcode: BPLZapn
/* 350 */     MCD_OPC_FilterValue, 1, 83, 21, // Skip to: 5813
/* 354 */     MCD_OPC_Decode, 98, 3, // Opcode: BPLZapt
/* 357 */     MCD_OPC_FilterValue, 21, 17, 0, // Skip to: 378
/* 361 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 364 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 371
/* 368 */     MCD_OPC_Decode, 101, 3, // Opcode: BPNZapn
/* 371 */     MCD_OPC_FilterValue, 1, 62, 21, // Skip to: 5813
/* 375 */     MCD_OPC_Decode, 102, 3, // Opcode: BPNZapt
/* 378 */     MCD_OPC_FilterValue, 22, 17, 0, // Skip to: 399
/* 382 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 385 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 392
/* 389 */     MCD_OPC_Decode, 85, 3, // Opcode: BPGZapn
/* 392 */     MCD_OPC_FilterValue, 1, 41, 21, // Skip to: 5813
/* 396 */     MCD_OPC_Decode, 86, 3, // Opcode: BPGZapt
/* 399 */     MCD_OPC_FilterValue, 23, 34, 21, // Skip to: 5813
/* 403 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 406 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 413
/* 410 */     MCD_OPC_Decode, 81, 3, // Opcode: BPGEZapn
/* 413 */     MCD_OPC_FilterValue, 1, 20, 21, // Skip to: 5813
/* 417 */     MCD_OPC_Decode, 82, 3, // Opcode: BPGEZapt
/* 420 */     MCD_OPC_FilterValue, 4, 20, 0, // Skip to: 444
/* 424 */     MCD_OPC_CheckField, 25, 5, 0, 10, 0, // Skip to: 440
/* 430 */     MCD_OPC_CheckField, 0, 22, 0, 4, 0, // Skip to: 440
/* 436 */     MCD_OPC_Decode, 222, 2, 4, // Opcode: NOP
/* 440 */     MCD_OPC_Decode, 133, 3, 5, // Opcode: SETHIi
/* 444 */     MCD_OPC_FilterValue, 5, 61, 0, // Skip to: 509
/* 448 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 451 */     MCD_OPC_FilterValue, 0, 25, 0, // Skip to: 480
/* 455 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 458 */     MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 469
/* 462 */     MCD_OPC_CheckPredicate, 0, 227, 20, // Skip to: 5813
/* 466 */     MCD_OPC_Decode, 80, 6, // Opcode: BPFCCNT
/* 469 */     MCD_OPC_FilterValue, 1, 220, 20, // Skip to: 5813
/* 473 */     MCD_OPC_CheckPredicate, 0, 216, 20, // Skip to: 5813
/* 477 */     MCD_OPC_Decode, 79, 6, // Opcode: BPFCCANT
/* 480 */     MCD_OPC_FilterValue, 1, 209, 20, // Skip to: 5813
/* 484 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 487 */     MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 498
/* 491 */     MCD_OPC_CheckPredicate, 0, 198, 20, // Skip to: 5813
/* 495 */     MCD_OPC_Decode, 77, 6, // Opcode: BPFCC
/* 498 */     MCD_OPC_FilterValue, 1, 191, 20, // Skip to: 5813
/* 502 */     MCD_OPC_CheckPredicate, 0, 187, 20, // Skip to: 5813
/* 506 */     MCD_OPC_Decode, 78, 6, // Opcode: BPFCCA
/* 509 */     MCD_OPC_FilterValue, 6, 180, 20, // Skip to: 5813
/* 513 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 516 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 524
/* 520 */     MCD_OPC_Decode, 149, 1, 2, // Opcode: FBCOND
/* 524 */     MCD_OPC_FilterValue, 1, 165, 20, // Skip to: 5813
/* 528 */     MCD_OPC_Decode, 150, 1, 2, // Opcode: FBCONDA
/* 532 */     MCD_OPC_FilterValue, 1, 3, 0, // Skip to: 539
/* 536 */     MCD_OPC_Decode, 114, 7, // Opcode: CALL
/* 539 */     MCD_OPC_FilterValue, 2, 85, 18, // Skip to: 5236
/* 543 */     MCD_OPC_ExtractField, 19, 6,  // Inst{24-19} ...
/* 546 */     MCD_OPC_FilterValue, 0, 23, 0, // Skip to: 573
/* 550 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 553 */     MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 566
/* 557 */     MCD_OPC_CheckField, 5, 8, 0, 130, 20, // Skip to: 5813
/* 563 */     MCD_OPC_Decode, 31, 8, // Opcode: ADDrr
/* 566 */     MCD_OPC_FilterValue, 1, 123, 20, // Skip to: 5813
/* 570 */     MCD_OPC_Decode, 30, 9, // Opcode: ADDri
/* 573 */     MCD_OPC_FilterValue, 1, 23, 0, // Skip to: 600
/* 577 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 580 */     MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 593
/* 584 */     MCD_OPC_CheckField, 5, 8, 0, 103, 20, // Skip to: 5813
/* 590 */     MCD_OPC_Decode, 46, 8, // Opcode: ANDrr
/* 593 */     MCD_OPC_FilterValue, 1, 96, 20, // Skip to: 5813
/* 597 */     MCD_OPC_Decode, 45, 9, // Opcode: ANDri
/* 600 */     MCD_OPC_FilterValue, 2, 25, 0, // Skip to: 629
/* 604 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 607 */     MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 621
/* 611 */     MCD_OPC_CheckField, 5, 8, 0, 76, 20, // Skip to: 5813
/* 617 */     MCD_OPC_Decode, 233, 2, 8, // Opcode: ORrr
/* 621 */     MCD_OPC_FilterValue, 1, 68, 20, // Skip to: 5813
/* 625 */     MCD_OPC_Decode, 232, 2, 9, // Opcode: ORri
/* 629 */     MCD_OPC_FilterValue, 3, 25, 0, // Skip to: 658
/* 633 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 636 */     MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 650
/* 640 */     MCD_OPC_CheckField, 5, 8, 0, 47, 20, // Skip to: 5813
/* 646 */     MCD_OPC_Decode, 235, 3, 8, // Opcode: XORrr
/* 650 */     MCD_OPC_FilterValue, 1, 39, 20, // Skip to: 5813
/* 654 */     MCD_OPC_Decode, 234, 3, 9, // Opcode: XORri
/* 658 */     MCD_OPC_FilterValue, 4, 25, 0, // Skip to: 687
/* 662 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 665 */     MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 679
/* 669 */     MCD_OPC_CheckField, 5, 8, 0, 18, 20, // Skip to: 5813
/* 675 */     MCD_OPC_Decode, 176, 3, 8, // Opcode: SUBrr
/* 679 */     MCD_OPC_FilterValue, 1, 10, 20, // Skip to: 5813
/* 683 */     MCD_OPC_Decode, 175, 3, 9, // Opcode: SUBri
/* 687 */     MCD_OPC_FilterValue, 5, 23, 0, // Skip to: 714
/* 691 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 694 */     MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 707
/* 698 */     MCD_OPC_CheckField, 5, 8, 0, 245, 19, // Skip to: 5813
/* 704 */     MCD_OPC_Decode, 41, 8, // Opcode: ANDNrr
/* 707 */     MCD_OPC_FilterValue, 1, 238, 19, // Skip to: 5813
/* 711 */     MCD_OPC_Decode, 40, 9, // Opcode: ANDNri
/* 714 */     MCD_OPC_FilterValue, 6, 25, 0, // Skip to: 743
/* 718 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 721 */     MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 735
/* 725 */     MCD_OPC_CheckField, 5, 8, 0, 218, 19, // Skip to: 5813
/* 731 */     MCD_OPC_Decode, 228, 2, 8, // Opcode: ORNrr
/* 735 */     MCD_OPC_FilterValue, 1, 210, 19, // Skip to: 5813
/* 739 */     MCD_OPC_Decode, 227, 2, 9, // Opcode: ORNri
/* 743 */     MCD_OPC_FilterValue, 7, 25, 0, // Skip to: 772
/* 747 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 750 */     MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 764
/* 754 */     MCD_OPC_CheckField, 5, 8, 0, 189, 19, // Skip to: 5813
/* 760 */     MCD_OPC_Decode, 229, 3, 8, // Opcode: XNORrr
/* 764 */     MCD_OPC_FilterValue, 1, 181, 19, // Skip to: 5813
/* 768 */     MCD_OPC_Decode, 228, 3, 9, // Opcode: XNORri
/* 772 */     MCD_OPC_FilterValue, 8, 23, 0, // Skip to: 799
/* 776 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 779 */     MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 792
/* 783 */     MCD_OPC_CheckField, 5, 8, 0, 160, 19, // Skip to: 5813
/* 789 */     MCD_OPC_Decode, 23, 8, // Opcode: ADDCrr
/* 792 */     MCD_OPC_FilterValue, 1, 153, 19, // Skip to: 5813
/* 796 */     MCD_OPC_Decode, 22, 9, // Opcode: ADDCri
/* 799 */     MCD_OPC_FilterValue, 9, 25, 0, // Skip to: 828
/* 803 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 806 */     MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 820
/* 810 */     MCD_OPC_CheckField, 5, 8, 0, 133, 19, // Skip to: 5813
/* 816 */     MCD_OPC_Decode, 221, 2, 10, // Opcode: MULXrr
/* 820 */     MCD_OPC_FilterValue, 1, 125, 19, // Skip to: 5813
/* 824 */     MCD_OPC_Decode, 220, 2, 11, // Opcode: MULXri
/* 828 */     MCD_OPC_FilterValue, 10, 25, 0, // Skip to: 857
/* 832 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 835 */     MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 849
/* 839 */     MCD_OPC_CheckField, 5, 8, 0, 104, 19, // Skip to: 5813
/* 845 */     MCD_OPC_Decode, 208, 3, 8, // Opcode: UMULrr
/* 849 */     MCD_OPC_FilterValue, 1, 96, 19, // Skip to: 5813
/* 853 */     MCD_OPC_Decode, 207, 3, 9, // Opcode: UMULri
/* 857 */     MCD_OPC_FilterValue, 11, 25, 0, // Skip to: 886
/* 861 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 864 */     MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 878
/* 868 */     MCD_OPC_CheckField, 5, 8, 0, 75, 19, // Skip to: 5813
/* 874 */     MCD_OPC_Decode, 143, 3, 8, // Opcode: SMULrr
/* 878 */     MCD_OPC_FilterValue, 1, 67, 19, // Skip to: 5813
/* 882 */     MCD_OPC_Decode, 142, 3, 9, // Opcode: SMULri
/* 886 */     MCD_OPC_FilterValue, 12, 25, 0, // Skip to: 915
/* 890 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 893 */     MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 907
/* 897 */     MCD_OPC_CheckField, 5, 8, 0, 46, 19, // Skip to: 5813
/* 903 */     MCD_OPC_Decode, 170, 3, 8, // Opcode: SUBCrr
/* 907 */     MCD_OPC_FilterValue, 1, 38, 19, // Skip to: 5813
/* 911 */     MCD_OPC_Decode, 169, 3, 9, // Opcode: SUBCri
/* 915 */     MCD_OPC_FilterValue, 13, 25, 0, // Skip to: 944
/* 919 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 922 */     MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 936
/* 926 */     MCD_OPC_CheckField, 5, 8, 0, 17, 19, // Skip to: 5813
/* 932 */     MCD_OPC_Decode, 201, 3, 10, // Opcode: UDIVXrr
/* 936 */     MCD_OPC_FilterValue, 1, 9, 19, // Skip to: 5813
/* 940 */     MCD_OPC_Decode, 200, 3, 11, // Opcode: UDIVXri
/* 944 */     MCD_OPC_FilterValue, 14, 25, 0, // Skip to: 973
/* 948 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 951 */     MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 965
/* 955 */     MCD_OPC_CheckField, 5, 8, 0, 244, 18, // Skip to: 5813
/* 961 */     MCD_OPC_Decode, 203, 3, 8, // Opcode: UDIVrr
/* 965 */     MCD_OPC_FilterValue, 1, 236, 18, // Skip to: 5813
/* 969 */     MCD_OPC_Decode, 202, 3, 9, // Opcode: UDIVri
/* 973 */     MCD_OPC_FilterValue, 15, 25, 0, // Skip to: 1002
/* 977 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 980 */     MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 994
/* 984 */     MCD_OPC_CheckField, 5, 8, 0, 215, 18, // Skip to: 5813
/* 990 */     MCD_OPC_Decode, 251, 2, 8, // Opcode: SDIVrr
/* 994 */     MCD_OPC_FilterValue, 1, 207, 18, // Skip to: 5813
/* 998 */     MCD_OPC_Decode, 250, 2, 9, // Opcode: SDIVri
/* 1002 */    MCD_OPC_FilterValue, 16, 23, 0, // Skip to: 1029
/* 1006 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1009 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 1022
/* 1013 */    MCD_OPC_CheckField, 5, 8, 0, 186, 18, // Skip to: 5813
/* 1019 */    MCD_OPC_Decode, 21, 8, // Opcode: ADDCCrr
/* 1022 */    MCD_OPC_FilterValue, 1, 179, 18, // Skip to: 5813
/* 1026 */    MCD_OPC_Decode, 20, 9, // Opcode: ADDCCri
/* 1029 */    MCD_OPC_FilterValue, 17, 23, 0, // Skip to: 1056
/* 1033 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1036 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 1049
/* 1040 */    MCD_OPC_CheckField, 5, 8, 0, 159, 18, // Skip to: 5813
/* 1046 */    MCD_OPC_Decode, 37, 8, // Opcode: ANDCCrr
/* 1049 */    MCD_OPC_FilterValue, 1, 152, 18, // Skip to: 5813
/* 1053 */    MCD_OPC_Decode, 36, 9, // Opcode: ANDCCri
/* 1056 */    MCD_OPC_FilterValue, 18, 25, 0, // Skip to: 1085
/* 1060 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1063 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 1077
/* 1067 */    MCD_OPC_CheckField, 5, 8, 0, 132, 18, // Skip to: 5813
/* 1073 */    MCD_OPC_Decode, 224, 2, 8, // Opcode: ORCCrr
/* 1077 */    MCD_OPC_FilterValue, 1, 124, 18, // Skip to: 5813
/* 1081 */    MCD_OPC_Decode, 223, 2, 9, // Opcode: ORCCri
/* 1085 */    MCD_OPC_FilterValue, 19, 25, 0, // Skip to: 1114
/* 1089 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1092 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 1106
/* 1096 */    MCD_OPC_CheckField, 5, 8, 0, 103, 18, // Skip to: 5813
/* 1102 */    MCD_OPC_Decode, 231, 3, 8, // Opcode: XORCCrr
/* 1106 */    MCD_OPC_FilterValue, 1, 95, 18, // Skip to: 5813
/* 1110 */    MCD_OPC_Decode, 230, 3, 9, // Opcode: XORCCri
/* 1114 */    MCD_OPC_FilterValue, 20, 44, 0, // Skip to: 1162
/* 1118 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1121 */    MCD_OPC_FilterValue, 0, 20, 0, // Skip to: 1145
/* 1125 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 1128 */    MCD_OPC_FilterValue, 0, 73, 18, // Skip to: 5813
/* 1132 */    MCD_OPC_CheckField, 25, 5, 0, 3, 0, // Skip to: 1141
/* 1138 */    MCD_OPC_Decode, 123, 12, // Opcode: CMPrr
/* 1141 */    MCD_OPC_Decode, 168, 3, 8, // Opcode: SUBCCrr
/* 1145 */    MCD_OPC_FilterValue, 1, 56, 18, // Skip to: 5813
/* 1149 */    MCD_OPC_CheckField, 25, 5, 0, 3, 0, // Skip to: 1158
/* 1155 */    MCD_OPC_Decode, 122, 13, // Opcode: CMPri
/* 1158 */    MCD_OPC_Decode, 167, 3, 9, // Opcode: SUBCCri
/* 1162 */    MCD_OPC_FilterValue, 21, 23, 0, // Skip to: 1189
/* 1166 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1169 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 1182
/* 1173 */    MCD_OPC_CheckField, 5, 8, 0, 26, 18, // Skip to: 5813
/* 1179 */    MCD_OPC_Decode, 39, 8, // Opcode: ANDNCCrr
/* 1182 */    MCD_OPC_FilterValue, 1, 19, 18, // Skip to: 5813
/* 1186 */    MCD_OPC_Decode, 38, 9, // Opcode: ANDNCCri
/* 1189 */    MCD_OPC_FilterValue, 22, 25, 0, // Skip to: 1218
/* 1193 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1196 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 1210
/* 1200 */    MCD_OPC_CheckField, 5, 8, 0, 255, 17, // Skip to: 5813
/* 1206 */    MCD_OPC_Decode, 226, 2, 8, // Opcode: ORNCCrr
/* 1210 */    MCD_OPC_FilterValue, 1, 247, 17, // Skip to: 5813
/* 1214 */    MCD_OPC_Decode, 225, 2, 9, // Opcode: ORNCCri
/* 1218 */    MCD_OPC_FilterValue, 23, 25, 0, // Skip to: 1247
/* 1222 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1225 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 1239
/* 1229 */    MCD_OPC_CheckField, 5, 8, 0, 226, 17, // Skip to: 5813
/* 1235 */    MCD_OPC_Decode, 226, 3, 8, // Opcode: XNORCCrr
/* 1239 */    MCD_OPC_FilterValue, 1, 218, 17, // Skip to: 5813
/* 1243 */    MCD_OPC_Decode, 225, 3, 9, // Opcode: XNORCCri
/* 1247 */    MCD_OPC_FilterValue, 24, 23, 0, // Skip to: 1274
/* 1251 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1254 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 1267
/* 1258 */    MCD_OPC_CheckField, 5, 8, 0, 197, 17, // Skip to: 5813
/* 1264 */    MCD_OPC_Decode, 25, 8, // Opcode: ADDErr
/* 1267 */    MCD_OPC_FilterValue, 1, 190, 17, // Skip to: 5813
/* 1271 */    MCD_OPC_Decode, 24, 9, // Opcode: ADDEri
/* 1274 */    MCD_OPC_FilterValue, 26, 25, 0, // Skip to: 1303
/* 1278 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1281 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 1295
/* 1285 */    MCD_OPC_CheckField, 5, 8, 0, 170, 17, // Skip to: 5813
/* 1291 */    MCD_OPC_Decode, 205, 3, 8, // Opcode: UMULCCrr
/* 1295 */    MCD_OPC_FilterValue, 1, 162, 17, // Skip to: 5813
/* 1299 */    MCD_OPC_Decode, 204, 3, 9, // Opcode: UMULCCri
/* 1303 */    MCD_OPC_FilterValue, 27, 25, 0, // Skip to: 1332
/* 1307 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1310 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 1324
/* 1314 */    MCD_OPC_CheckField, 5, 8, 0, 141, 17, // Skip to: 5813
/* 1320 */    MCD_OPC_Decode, 141, 3, 8, // Opcode: SMULCCrr
/* 1324 */    MCD_OPC_FilterValue, 1, 133, 17, // Skip to: 5813
/* 1328 */    MCD_OPC_Decode, 140, 3, 9, // Opcode: SMULCCri
/* 1332 */    MCD_OPC_FilterValue, 28, 25, 0, // Skip to: 1361
/* 1336 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1339 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 1353
/* 1343 */    MCD_OPC_CheckField, 5, 8, 0, 112, 17, // Skip to: 5813
/* 1349 */    MCD_OPC_Decode, 172, 3, 8, // Opcode: SUBErr
/* 1353 */    MCD_OPC_FilterValue, 1, 104, 17, // Skip to: 5813
/* 1357 */    MCD_OPC_Decode, 171, 3, 9, // Opcode: SUBEri
/* 1361 */    MCD_OPC_FilterValue, 30, 25, 0, // Skip to: 1390
/* 1365 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1368 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 1382
/* 1372 */    MCD_OPC_CheckField, 5, 8, 0, 83, 17, // Skip to: 5813
/* 1378 */    MCD_OPC_Decode, 199, 3, 8, // Opcode: UDIVCCrr
/* 1382 */    MCD_OPC_FilterValue, 1, 75, 17, // Skip to: 5813
/* 1386 */    MCD_OPC_Decode, 198, 3, 9, // Opcode: UDIVCCri
/* 1390 */    MCD_OPC_FilterValue, 31, 25, 0, // Skip to: 1419
/* 1394 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1397 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 1411
/* 1401 */    MCD_OPC_CheckField, 5, 8, 0, 54, 17, // Skip to: 5813
/* 1407 */    MCD_OPC_Decode, 247, 2, 8, // Opcode: SDIVCCrr
/* 1411 */    MCD_OPC_FilterValue, 1, 46, 17, // Skip to: 5813
/* 1415 */    MCD_OPC_Decode, 246, 2, 9, // Opcode: SDIVCCri
/* 1419 */    MCD_OPC_FilterValue, 32, 25, 0, // Skip to: 1448
/* 1423 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1426 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 1440
/* 1430 */    MCD_OPC_CheckField, 5, 8, 0, 25, 17, // Skip to: 5813
/* 1436 */    MCD_OPC_Decode, 184, 3, 8, // Opcode: TADDCCrr
/* 1440 */    MCD_OPC_FilterValue, 1, 17, 17, // Skip to: 5813
/* 1444 */    MCD_OPC_Decode, 183, 3, 9, // Opcode: TADDCCri
/* 1448 */    MCD_OPC_FilterValue, 33, 25, 0, // Skip to: 1477
/* 1452 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1455 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 1469
/* 1459 */    MCD_OPC_CheckField, 5, 8, 0, 252, 16, // Skip to: 5813
/* 1465 */    MCD_OPC_Decode, 195, 3, 8, // Opcode: TSUBCCrr
/* 1469 */    MCD_OPC_FilterValue, 1, 244, 16, // Skip to: 5813
/* 1473 */    MCD_OPC_Decode, 194, 3, 9, // Opcode: TSUBCCri
/* 1477 */    MCD_OPC_FilterValue, 34, 25, 0, // Skip to: 1506
/* 1481 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1484 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 1498
/* 1488 */    MCD_OPC_CheckField, 5, 8, 0, 223, 16, // Skip to: 5813
/* 1494 */    MCD_OPC_Decode, 182, 3, 8, // Opcode: TADDCCTVrr
/* 1498 */    MCD_OPC_FilterValue, 1, 215, 16, // Skip to: 5813
/* 1502 */    MCD_OPC_Decode, 181, 3, 9, // Opcode: TADDCCTVri
/* 1506 */    MCD_OPC_FilterValue, 35, 25, 0, // Skip to: 1535
/* 1510 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1513 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 1527
/* 1517 */    MCD_OPC_CheckField, 5, 8, 0, 194, 16, // Skip to: 5813
/* 1523 */    MCD_OPC_Decode, 193, 3, 8, // Opcode: TSUBCCTVrr
/* 1527 */    MCD_OPC_FilterValue, 1, 186, 16, // Skip to: 5813
/* 1531 */    MCD_OPC_Decode, 192, 3, 9, // Opcode: TSUBCCTVri
/* 1535 */    MCD_OPC_FilterValue, 37, 50, 0, // Skip to: 1589
/* 1539 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1542 */    MCD_OPC_FilterValue, 0, 25, 0, // Skip to: 1571
/* 1546 */    MCD_OPC_ExtractField, 12, 1,  // Inst{12} ...
/* 1549 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 1563
/* 1553 */    MCD_OPC_CheckField, 5, 7, 0, 158, 16, // Skip to: 5813
/* 1559 */    MCD_OPC_Decode, 139, 3, 8, // Opcode: SLLrr
/* 1563 */    MCD_OPC_FilterValue, 1, 150, 16, // Skip to: 5813
/* 1567 */    MCD_OPC_Decode, 137, 3, 14, // Opcode: SLLXrr
/* 1571 */    MCD_OPC_FilterValue, 1, 142, 16, // Skip to: 5813
/* 1575 */    MCD_OPC_CheckField, 12, 1, 1, 4, 0, // Skip to: 1585
/* 1581 */    MCD_OPC_Decode, 136, 3, 15, // Opcode: SLLXri
/* 1585 */    MCD_OPC_Decode, 138, 3, 9, // Opcode: SLLri
/* 1589 */    MCD_OPC_FilterValue, 38, 50, 0, // Skip to: 1643
/* 1593 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1596 */    MCD_OPC_FilterValue, 0, 25, 0, // Skip to: 1625
/* 1600 */    MCD_OPC_ExtractField, 12, 1,  // Inst{12} ...
/* 1603 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 1617
/* 1607 */    MCD_OPC_CheckField, 5, 7, 0, 104, 16, // Skip to: 5813
/* 1613 */    MCD_OPC_Decode, 151, 3, 8, // Opcode: SRLrr
/* 1617 */    MCD_OPC_FilterValue, 1, 96, 16, // Skip to: 5813
/* 1621 */    MCD_OPC_Decode, 149, 3, 14, // Opcode: SRLXrr
/* 1625 */    MCD_OPC_FilterValue, 1, 88, 16, // Skip to: 5813
/* 1629 */    MCD_OPC_CheckField, 12, 1, 1, 4, 0, // Skip to: 1639
/* 1635 */    MCD_OPC_Decode, 148, 3, 15, // Opcode: SRLXri
/* 1639 */    MCD_OPC_Decode, 150, 3, 9, // Opcode: SRLri
/* 1643 */    MCD_OPC_FilterValue, 39, 50, 0, // Skip to: 1697
/* 1647 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1650 */    MCD_OPC_FilterValue, 0, 25, 0, // Skip to: 1679
/* 1654 */    MCD_OPC_ExtractField, 12, 1,  // Inst{12} ...
/* 1657 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 1671
/* 1661 */    MCD_OPC_CheckField, 5, 7, 0, 50, 16, // Skip to: 5813
/* 1667 */    MCD_OPC_Decode, 147, 3, 8, // Opcode: SRArr
/* 1671 */    MCD_OPC_FilterValue, 1, 42, 16, // Skip to: 5813
/* 1675 */    MCD_OPC_Decode, 145, 3, 14, // Opcode: SRAXrr
/* 1679 */    MCD_OPC_FilterValue, 1, 34, 16, // Skip to: 5813
/* 1683 */    MCD_OPC_CheckField, 12, 1, 1, 4, 0, // Skip to: 1693
/* 1689 */    MCD_OPC_Decode, 144, 3, 15, // Opcode: SRAXri
/* 1693 */    MCD_OPC_Decode, 146, 3, 9, // Opcode: SRAri
/* 1697 */    MCD_OPC_FilterValue, 40, 55, 0, // Skip to: 1756
/* 1701 */    MCD_OPC_ExtractField, 13, 6,  // Inst{18-13} ...
/* 1704 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 1718
/* 1708 */    MCD_OPC_CheckField, 0, 13, 0, 3, 16, // Skip to: 5813
/* 1714 */    MCD_OPC_Decode, 237, 2, 4, // Opcode: RDY
/* 1718 */    MCD_OPC_FilterValue, 30, 16, 0, // Skip to: 1738
/* 1722 */    MCD_OPC_CheckField, 25, 5, 0, 245, 15, // Skip to: 5813
/* 1728 */    MCD_OPC_CheckField, 0, 13, 0, 239, 15, // Skip to: 5813
/* 1734 */    MCD_OPC_Decode, 152, 3, 4, // Opcode: STBAR
/* 1738 */    MCD_OPC_FilterValue, 31, 231, 15, // Skip to: 5813
/* 1742 */    MCD_OPC_CheckPredicate, 0, 227, 15, // Skip to: 5813
/* 1746 */    MCD_OPC_CheckField, 25, 5, 0, 221, 15, // Skip to: 5813
/* 1752 */    MCD_OPC_Decode, 196, 2, 16, // Opcode: MEMBARi
/* 1756 */    MCD_OPC_FilterValue, 43, 20, 0, // Skip to: 1780
/* 1760 */    MCD_OPC_CheckPredicate, 0, 209, 15, // Skip to: 5813
/* 1764 */    MCD_OPC_CheckField, 25, 5, 0, 203, 15, // Skip to: 5813
/* 1770 */    MCD_OPC_CheckField, 0, 19, 0, 197, 15, // Skip to: 5813
/* 1776 */    MCD_OPC_Decode, 181, 1, 4, // Opcode: FLUSHW
/* 1780 */    MCD_OPC_FilterValue, 44, 123, 0, // Skip to: 1907
/* 1784 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1787 */    MCD_OPC_FilterValue, 0, 56, 0, // Skip to: 1847
/* 1791 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 1794 */    MCD_OPC_FilterValue, 0, 22, 0, // Skip to: 1820
/* 1798 */    MCD_OPC_CheckPredicate, 0, 10, 0, // Skip to: 1812
/* 1802 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 1812
/* 1808 */    MCD_OPC_Decode, 199, 2, 17, // Opcode: MOVFCCrr
/* 1812 */    MCD_OPC_CheckPredicate, 0, 157, 15, // Skip to: 5813
/* 1816 */    MCD_OPC_Decode, 220, 3, 18, // Opcode: V9MOVFCCrr
/* 1820 */    MCD_OPC_FilterValue, 1, 149, 15, // Skip to: 5813
/* 1824 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 1827 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1839
/* 1831 */    MCD_OPC_CheckPredicate, 0, 138, 15, // Skip to: 5813
/* 1835 */    MCD_OPC_Decode, 201, 2, 17, // Opcode: MOVICCrr
/* 1839 */    MCD_OPC_FilterValue, 2, 130, 15, // Skip to: 5813
/* 1843 */    MCD_OPC_Decode, 218, 2, 17, // Opcode: MOVXCCrr
/* 1847 */    MCD_OPC_FilterValue, 1, 122, 15, // Skip to: 5813
/* 1851 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 1854 */    MCD_OPC_FilterValue, 0, 22, 0, // Skip to: 1880
/* 1858 */    MCD_OPC_CheckPredicate, 0, 10, 0, // Skip to: 1872
/* 1862 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 1872
/* 1868 */    MCD_OPC_Decode, 198, 2, 19, // Opcode: MOVFCCri
/* 1872 */    MCD_OPC_CheckPredicate, 0, 97, 15, // Skip to: 5813
/* 1876 */    MCD_OPC_Decode, 219, 3, 20, // Opcode: V9MOVFCCri
/* 1880 */    MCD_OPC_FilterValue, 1, 89, 15, // Skip to: 5813
/* 1884 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 1887 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1899
/* 1891 */    MCD_OPC_CheckPredicate, 0, 78, 15, // Skip to: 5813
/* 1895 */    MCD_OPC_Decode, 200, 2, 19, // Opcode: MOVICCri
/* 1899 */    MCD_OPC_FilterValue, 2, 70, 15, // Skip to: 5813
/* 1903 */    MCD_OPC_Decode, 217, 2, 19, // Opcode: MOVXCCri
/* 1907 */    MCD_OPC_FilterValue, 45, 25, 0, // Skip to: 1936
/* 1911 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1914 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 1928
/* 1918 */    MCD_OPC_CheckField, 5, 8, 0, 49, 15, // Skip to: 5813
/* 1924 */    MCD_OPC_Decode, 249, 2, 10, // Opcode: SDIVXrr
/* 1928 */    MCD_OPC_FilterValue, 1, 41, 15, // Skip to: 5813
/* 1932 */    MCD_OPC_Decode, 248, 2, 11, // Opcode: SDIVXri
/* 1936 */    MCD_OPC_FilterValue, 46, 14, 0, // Skip to: 1954
/* 1940 */    MCD_OPC_CheckPredicate, 0, 29, 15, // Skip to: 5813
/* 1944 */    MCD_OPC_CheckField, 5, 14, 0, 23, 15, // Skip to: 5813
/* 1950 */    MCD_OPC_Decode, 236, 2, 21, // Opcode: POPCrr
/* 1954 */    MCD_OPC_FilterValue, 47, 135, 0, // Skip to: 2093
/* 1958 */    MCD_OPC_ExtractField, 10, 4,  // Inst{13-10} ...
/* 1961 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 1975
/* 1965 */    MCD_OPC_CheckField, 5, 5, 0, 2, 15, // Skip to: 5813
/* 1971 */    MCD_OPC_Decode, 213, 2, 14, // Opcode: MOVRRZrr
/* 1975 */    MCD_OPC_FilterValue, 2, 10, 0, // Skip to: 1989
/* 1979 */    MCD_OPC_CheckField, 5, 5, 0, 244, 14, // Skip to: 5813
/* 1985 */    MCD_OPC_Decode, 207, 2, 14, // Opcode: MOVRLEZrr
/* 1989 */    MCD_OPC_FilterValue, 3, 10, 0, // Skip to: 2003
/* 1993 */    MCD_OPC_CheckField, 5, 5, 0, 230, 14, // Skip to: 5813
/* 1999 */    MCD_OPC_Decode, 209, 2, 14, // Opcode: MOVRLZrr
/* 2003 */    MCD_OPC_FilterValue, 5, 10, 0, // Skip to: 2017
/* 2007 */    MCD_OPC_CheckField, 5, 5, 0, 216, 14, // Skip to: 5813
/* 2013 */    MCD_OPC_Decode, 211, 2, 14, // Opcode: MOVRNZrr
/* 2017 */    MCD_OPC_FilterValue, 6, 10, 0, // Skip to: 2031
/* 2021 */    MCD_OPC_CheckField, 5, 5, 0, 202, 14, // Skip to: 5813
/* 2027 */    MCD_OPC_Decode, 205, 2, 14, // Opcode: MOVRGZrr
/* 2031 */    MCD_OPC_FilterValue, 7, 10, 0, // Skip to: 2045
/* 2035 */    MCD_OPC_CheckField, 5, 5, 0, 188, 14, // Skip to: 5813
/* 2041 */    MCD_OPC_Decode, 203, 2, 14, // Opcode: MOVRGEZrr
/* 2045 */    MCD_OPC_FilterValue, 9, 4, 0, // Skip to: 2053
/* 2049 */    MCD_OPC_Decode, 212, 2, 22, // Opcode: MOVRRZri
/* 2053 */    MCD_OPC_FilterValue, 10, 4, 0, // Skip to: 2061
/* 2057 */    MCD_OPC_Decode, 206, 2, 22, // Opcode: MOVRLEZri
/* 2061 */    MCD_OPC_FilterValue, 11, 4, 0, // Skip to: 2069
/* 2065 */    MCD_OPC_Decode, 208, 2, 22, // Opcode: MOVRLZri
/* 2069 */    MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 2077
/* 2073 */    MCD_OPC_Decode, 210, 2, 22, // Opcode: MOVRNZri
/* 2077 */    MCD_OPC_FilterValue, 14, 4, 0, // Skip to: 2085
/* 2081 */    MCD_OPC_Decode, 204, 2, 22, // Opcode: MOVRGZri
/* 2085 */    MCD_OPC_FilterValue, 15, 140, 14, // Skip to: 5813
/* 2089 */    MCD_OPC_Decode, 202, 2, 22, // Opcode: MOVRGEZri
/* 2093 */    MCD_OPC_FilterValue, 48, 37, 0, // Skip to: 2134
/* 2097 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2100 */    MCD_OPC_FilterValue, 0, 16, 0, // Skip to: 2120
/* 2104 */    MCD_OPC_CheckField, 25, 5, 0, 119, 14, // Skip to: 5813
/* 2110 */    MCD_OPC_CheckField, 5, 8, 0, 113, 14, // Skip to: 5813
/* 2116 */    MCD_OPC_Decode, 222, 3, 12, // Opcode: WRYrr
/* 2120 */    MCD_OPC_FilterValue, 1, 105, 14, // Skip to: 5813
/* 2124 */    MCD_OPC_CheckField, 25, 5, 0, 99, 14, // Skip to: 5813
/* 2130 */    MCD_OPC_Decode, 221, 3, 13, // Opcode: WRYri
/* 2134 */    MCD_OPC_FilterValue, 52, 197, 2, // Skip to: 2847
/* 2138 */    MCD_OPC_ExtractField, 5, 9,  // Inst{13-5} ...
/* 2141 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 2155
/* 2145 */    MCD_OPC_CheckField, 14, 5, 0, 78, 14, // Skip to: 5813
/* 2151 */    MCD_OPC_Decode, 209, 1, 23, // Opcode: FMOVS
/* 2155 */    MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 2173
/* 2159 */    MCD_OPC_CheckPredicate, 0, 66, 14, // Skip to: 5813
/* 2163 */    MCD_OPC_CheckField, 14, 5, 0, 60, 14, // Skip to: 5813
/* 2169 */    MCD_OPC_Decode, 183, 1, 24, // Opcode: FMOVD
/* 2173 */    MCD_OPC_FilterValue, 3, 14, 0, // Skip to: 2191
/* 2177 */    MCD_OPC_CheckPredicate, 0, 48, 14, // Skip to: 5813
/* 2181 */    MCD_OPC_CheckField, 14, 5, 0, 42, 14, // Skip to: 5813
/* 2187 */    MCD_OPC_Decode, 187, 1, 25, // Opcode: FMOVQ
/* 2191 */    MCD_OPC_FilterValue, 5, 10, 0, // Skip to: 2205
/* 2195 */    MCD_OPC_CheckField, 14, 5, 0, 28, 14, // Skip to: 5813
/* 2201 */    MCD_OPC_Decode, 229, 1, 23, // Opcode: FNEGS
/* 2205 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 2223
/* 2209 */    MCD_OPC_CheckPredicate, 0, 16, 14, // Skip to: 5813
/* 2213 */    MCD_OPC_CheckField, 14, 5, 0, 10, 14, // Skip to: 5813
/* 2219 */    MCD_OPC_Decode, 227, 1, 24, // Opcode: FNEGD
/* 2223 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 2241
/* 2227 */    MCD_OPC_CheckPredicate, 0, 254, 13, // Skip to: 5813
/* 2231 */    MCD_OPC_CheckField, 14, 5, 0, 248, 13, // Skip to: 5813
/* 2237 */    MCD_OPC_Decode, 228, 1, 25, // Opcode: FNEGQ
/* 2241 */    MCD_OPC_FilterValue, 9, 10, 0, // Skip to: 2255
/* 2245 */    MCD_OPC_CheckField, 14, 5, 0, 234, 13, // Skip to: 5813
/* 2251 */    MCD_OPC_Decode, 138, 1, 23, // Opcode: FABSS
/* 2255 */    MCD_OPC_FilterValue, 10, 14, 0, // Skip to: 2273
/* 2259 */    MCD_OPC_CheckPredicate, 0, 222, 13, // Skip to: 5813
/* 2263 */    MCD_OPC_CheckField, 14, 5, 0, 216, 13, // Skip to: 5813
/* 2269 */    MCD_OPC_Decode, 136, 1, 24, // Opcode: FABSD
/* 2273 */    MCD_OPC_FilterValue, 11, 14, 0, // Skip to: 2291
/* 2277 */    MCD_OPC_CheckPredicate, 0, 204, 13, // Skip to: 5813
/* 2281 */    MCD_OPC_CheckField, 14, 5, 0, 198, 13, // Skip to: 5813
/* 2287 */    MCD_OPC_Decode, 137, 1, 25, // Opcode: FABSQ
/* 2291 */    MCD_OPC_FilterValue, 41, 10, 0, // Skip to: 2305
/* 2295 */    MCD_OPC_CheckField, 14, 5, 0, 184, 13, // Skip to: 5813
/* 2301 */    MCD_OPC_Decode, 145, 2, 23, // Opcode: FSQRTS
/* 2305 */    MCD_OPC_FilterValue, 42, 10, 0, // Skip to: 2319
/* 2309 */    MCD_OPC_CheckField, 14, 5, 0, 170, 13, // Skip to: 5813
/* 2315 */    MCD_OPC_Decode, 143, 2, 24, // Opcode: FSQRTD
/* 2319 */    MCD_OPC_FilterValue, 43, 10, 0, // Skip to: 2333
/* 2323 */    MCD_OPC_CheckField, 14, 5, 0, 156, 13, // Skip to: 5813
/* 2329 */    MCD_OPC_Decode, 144, 2, 25, // Opcode: FSQRTQ
/* 2333 */    MCD_OPC_FilterValue, 65, 4, 0, // Skip to: 2341
/* 2337 */    MCD_OPC_Decode, 141, 1, 26, // Opcode: FADDS
/* 2341 */    MCD_OPC_FilterValue, 66, 4, 0, // Skip to: 2349
/* 2345 */    MCD_OPC_Decode, 139, 1, 27, // Opcode: FADDD
/* 2349 */    MCD_OPC_FilterValue, 67, 4, 0, // Skip to: 2357
/* 2353 */    MCD_OPC_Decode, 140, 1, 28, // Opcode: FADDQ
/* 2357 */    MCD_OPC_FilterValue, 69, 4, 0, // Skip to: 2365
/* 2361 */    MCD_OPC_Decode, 160, 2, 26, // Opcode: FSUBS
/* 2365 */    MCD_OPC_FilterValue, 70, 4, 0, // Skip to: 2373
/* 2369 */    MCD_OPC_Decode, 158, 2, 27, // Opcode: FSUBD
/* 2373 */    MCD_OPC_FilterValue, 71, 4, 0, // Skip to: 2381
/* 2377 */    MCD_OPC_Decode, 159, 2, 28, // Opcode: FSUBQ
/* 2381 */    MCD_OPC_FilterValue, 73, 4, 0, // Skip to: 2389
/* 2385 */    MCD_OPC_Decode, 222, 1, 26, // Opcode: FMULS
/* 2389 */    MCD_OPC_FilterValue, 74, 4, 0, // Skip to: 2397
/* 2393 */    MCD_OPC_Decode, 218, 1, 27, // Opcode: FMULD
/* 2397 */    MCD_OPC_FilterValue, 75, 4, 0, // Skip to: 2405
/* 2401 */    MCD_OPC_Decode, 221, 1, 28, // Opcode: FMULQ
/* 2405 */    MCD_OPC_FilterValue, 77, 4, 0, // Skip to: 2413
/* 2409 */    MCD_OPC_Decode, 165, 1, 26, // Opcode: FDIVS
/* 2413 */    MCD_OPC_FilterValue, 78, 4, 0, // Skip to: 2421
/* 2417 */    MCD_OPC_Decode, 163, 1, 27, // Opcode: FDIVD
/* 2421 */    MCD_OPC_FilterValue, 79, 4, 0, // Skip to: 2429
/* 2425 */    MCD_OPC_Decode, 164, 1, 28, // Opcode: FDIVQ
/* 2429 */    MCD_OPC_FilterValue, 81, 8, 0, // Skip to: 2441
/* 2433 */    MCD_OPC_CheckPredicate, 1, 48, 13, // Skip to: 5813
/* 2437 */    MCD_OPC_Decode, 224, 1, 27, // Opcode: FNADDS
/* 2441 */    MCD_OPC_FilterValue, 82, 8, 0, // Skip to: 2453
/* 2445 */    MCD_OPC_CheckPredicate, 1, 36, 13, // Skip to: 5813
/* 2449 */    MCD_OPC_Decode, 223, 1, 27, // Opcode: FNADDD
/* 2453 */    MCD_OPC_FilterValue, 89, 8, 0, // Skip to: 2465
/* 2457 */    MCD_OPC_CheckPredicate, 1, 24, 13, // Skip to: 5813
/* 2461 */    MCD_OPC_Decode, 233, 1, 27, // Opcode: FNMULS
/* 2465 */    MCD_OPC_FilterValue, 90, 8, 0, // Skip to: 2477
/* 2469 */    MCD_OPC_CheckPredicate, 1, 12, 13, // Skip to: 5813
/* 2473 */    MCD_OPC_Decode, 232, 1, 27, // Opcode: FNMULD
/* 2477 */    MCD_OPC_FilterValue, 97, 8, 0, // Skip to: 2489
/* 2481 */    MCD_OPC_CheckPredicate, 1, 0, 13, // Skip to: 5813
/* 2485 */    MCD_OPC_Decode, 173, 1, 27, // Opcode: FHADDS
/* 2489 */    MCD_OPC_FilterValue, 98, 8, 0, // Skip to: 2501
/* 2493 */    MCD_OPC_CheckPredicate, 1, 244, 12, // Skip to: 5813
/* 2497 */    MCD_OPC_Decode, 172, 1, 27, // Opcode: FHADDD
/* 2501 */    MCD_OPC_FilterValue, 101, 8, 0, // Skip to: 2513
/* 2505 */    MCD_OPC_CheckPredicate, 1, 232, 12, // Skip to: 5813
/* 2509 */    MCD_OPC_Decode, 175, 1, 27, // Opcode: FHSUBS
/* 2513 */    MCD_OPC_FilterValue, 102, 8, 0, // Skip to: 2525
/* 2517 */    MCD_OPC_CheckPredicate, 1, 220, 12, // Skip to: 5813
/* 2521 */    MCD_OPC_Decode, 174, 1, 27, // Opcode: FHSUBD
/* 2525 */    MCD_OPC_FilterValue, 105, 4, 0, // Skip to: 2533
/* 2529 */    MCD_OPC_Decode, 142, 2, 29, // Opcode: FSMULD
/* 2533 */    MCD_OPC_FilterValue, 110, 4, 0, // Skip to: 2541
/* 2537 */    MCD_OPC_Decode, 166, 1, 30, // Opcode: FDMULQ
/* 2541 */    MCD_OPC_FilterValue, 113, 8, 0, // Skip to: 2553
/* 2545 */    MCD_OPC_CheckPredicate, 1, 192, 12, // Skip to: 5813
/* 2549 */    MCD_OPC_Decode, 231, 1, 27, // Opcode: FNHADDS
/* 2553 */    MCD_OPC_FilterValue, 114, 8, 0, // Skip to: 2565
/* 2557 */    MCD_OPC_CheckPredicate, 1, 180, 12, // Skip to: 5813
/* 2561 */    MCD_OPC_Decode, 230, 1, 27, // Opcode: FNHADDD
/* 2565 */    MCD_OPC_FilterValue, 121, 8, 0, // Skip to: 2577
/* 2569 */    MCD_OPC_CheckPredicate, 1, 168, 12, // Skip to: 5813
/* 2573 */    MCD_OPC_Decode, 240, 1, 27, // Opcode: FNSMULD
/* 2577 */    MCD_OPC_FilterValue, 129, 1, 10, 0, // Skip to: 2592
/* 2582 */    MCD_OPC_CheckField, 14, 5, 0, 153, 12, // Skip to: 5813
/* 2588 */    MCD_OPC_Decode, 157, 2, 31, // Opcode: FSTOX
/* 2592 */    MCD_OPC_FilterValue, 130, 1, 10, 0, // Skip to: 2607
/* 2597 */    MCD_OPC_CheckField, 14, 5, 0, 138, 12, // Skip to: 5813
/* 2603 */    MCD_OPC_Decode, 170, 1, 24, // Opcode: FDTOX
/* 2607 */    MCD_OPC_FilterValue, 131, 1, 10, 0, // Skip to: 2622
/* 2612 */    MCD_OPC_CheckField, 14, 5, 0, 123, 12, // Skip to: 5813
/* 2618 */    MCD_OPC_Decode, 137, 2, 32, // Opcode: FQTOX
/* 2622 */    MCD_OPC_FilterValue, 132, 1, 10, 0, // Skip to: 2637
/* 2627 */    MCD_OPC_CheckField, 14, 5, 0, 108, 12, // Skip to: 5813
/* 2633 */    MCD_OPC_Decode, 167, 2, 33, // Opcode: FXTOS
/* 2637 */    MCD_OPC_FilterValue, 136, 1, 10, 0, // Skip to: 2652
/* 2642 */    MCD_OPC_CheckField, 14, 5, 0, 93, 12, // Skip to: 5813
/* 2648 */    MCD_OPC_Decode, 165, 2, 24, // Opcode: FXTOD
/* 2652 */    MCD_OPC_FilterValue, 140, 1, 10, 0, // Skip to: 2667
/* 2657 */    MCD_OPC_CheckField, 14, 5, 0, 78, 12, // Skip to: 5813
/* 2663 */    MCD_OPC_Decode, 166, 2, 34, // Opcode: FXTOQ
/* 2667 */    MCD_OPC_FilterValue, 196, 1, 10, 0, // Skip to: 2682
/* 2672 */    MCD_OPC_CheckField, 14, 5, 0, 63, 12, // Skip to: 5813
/* 2678 */    MCD_OPC_Decode, 178, 1, 23, // Opcode: FITOS
/* 2682 */    MCD_OPC_FilterValue, 198, 1, 10, 0, // Skip to: 2697
/* 2687 */    MCD_OPC_CheckField, 14, 5, 0, 48, 12, // Skip to: 5813
/* 2693 */    MCD_OPC_Decode, 169, 1, 33, // Opcode: FDTOS
/* 2697 */    MCD_OPC_FilterValue, 199, 1, 10, 0, // Skip to: 2712
/* 2702 */    MCD_OPC_CheckField, 14, 5, 0, 33, 12, // Skip to: 5813
/* 2708 */    MCD_OPC_Decode, 136, 2, 35, // Opcode: FQTOS
/* 2712 */    MCD_OPC_FilterValue, 200, 1, 10, 0, // Skip to: 2727
/* 2717 */    MCD_OPC_CheckField, 14, 5, 0, 18, 12, // Skip to: 5813
/* 2723 */    MCD_OPC_Decode, 176, 1, 31, // Opcode: FITOD
/* 2727 */    MCD_OPC_FilterValue, 201, 1, 10, 0, // Skip to: 2742
/* 2732 */    MCD_OPC_CheckField, 14, 5, 0, 3, 12, // Skip to: 5813
/* 2738 */    MCD_OPC_Decode, 154, 2, 31, // Opcode: FSTOD
/* 2742 */    MCD_OPC_FilterValue, 203, 1, 10, 0, // Skip to: 2757
/* 2747 */    MCD_OPC_CheckField, 14, 5, 0, 244, 11, // Skip to: 5813
/* 2753 */    MCD_OPC_Decode, 134, 2, 32, // Opcode: FQTOD
/* 2757 */    MCD_OPC_FilterValue, 204, 1, 10, 0, // Skip to: 2772
/* 2762 */    MCD_OPC_CheckField, 14, 5, 0, 229, 11, // Skip to: 5813
/* 2768 */    MCD_OPC_Decode, 177, 1, 36, // Opcode: FITOQ
/* 2772 */    MCD_OPC_FilterValue, 205, 1, 10, 0, // Skip to: 2787
/* 2777 */    MCD_OPC_CheckField, 14, 5, 0, 214, 11, // Skip to: 5813
/* 2783 */    MCD_OPC_Decode, 156, 2, 36, // Opcode: FSTOQ
/* 2787 */    MCD_OPC_FilterValue, 206, 1, 10, 0, // Skip to: 2802
/* 2792 */    MCD_OPC_CheckField, 14, 5, 0, 199, 11, // Skip to: 5813
/* 2798 */    MCD_OPC_Decode, 168, 1, 34, // Opcode: FDTOQ
/* 2802 */    MCD_OPC_FilterValue, 209, 1, 10, 0, // Skip to: 2817
/* 2807 */    MCD_OPC_CheckField, 14, 5, 0, 184, 11, // Skip to: 5813
/* 2813 */    MCD_OPC_Decode, 155, 2, 23, // Opcode: FSTOI
/* 2817 */    MCD_OPC_FilterValue, 210, 1, 10, 0, // Skip to: 2832
/* 2822 */    MCD_OPC_CheckField, 14, 5, 0, 169, 11, // Skip to: 5813
/* 2828 */    MCD_OPC_Decode, 167, 1, 33, // Opcode: FDTOI
/* 2832 */    MCD_OPC_FilterValue, 211, 1, 160, 11, // Skip to: 5813
/* 2837 */    MCD_OPC_CheckField, 14, 5, 0, 154, 11, // Skip to: 5813
/* 2843 */    MCD_OPC_Decode, 135, 2, 35, // Opcode: FQTOI
/* 2847 */    MCD_OPC_FilterValue, 53, 70, 2, // Skip to: 3433
/* 2851 */    MCD_OPC_ExtractField, 5, 6,  // Inst{10-5} ...
/* 2854 */    MCD_OPC_FilterValue, 1, 75, 0, // Skip to: 2933
/* 2858 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2861 */    MCD_OPC_FilterValue, 0, 29, 0, // Skip to: 2894
/* 2865 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 2868 */    MCD_OPC_FilterValue, 0, 125, 11, // Skip to: 5813
/* 2872 */    MCD_OPC_CheckPredicate, 0, 10, 0, // Skip to: 2886
/* 2876 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 2886
/* 2882 */    MCD_OPC_Decode, 210, 1, 37, // Opcode: FMOVS_FCC
/* 2886 */    MCD_OPC_CheckPredicate, 0, 107, 11, // Skip to: 5813
/* 2890 */    MCD_OPC_Decode, 218, 3, 38, // Opcode: V9FMOVS_FCC
/* 2894 */    MCD_OPC_FilterValue, 1, 99, 11, // Skip to: 5813
/* 2898 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 2901 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 2919
/* 2905 */    MCD_OPC_CheckPredicate, 0, 88, 11, // Skip to: 5813
/* 2909 */    MCD_OPC_CheckField, 18, 1, 0, 82, 11, // Skip to: 5813
/* 2915 */    MCD_OPC_Decode, 211, 1, 37, // Opcode: FMOVS_ICC
/* 2919 */    MCD_OPC_FilterValue, 2, 74, 11, // Skip to: 5813
/* 2923 */    MCD_OPC_CheckField, 18, 1, 0, 68, 11, // Skip to: 5813
/* 2929 */    MCD_OPC_Decode, 212, 1, 37, // Opcode: FMOVS_XCC
/* 2933 */    MCD_OPC_FilterValue, 2, 75, 0, // Skip to: 3012
/* 2937 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2940 */    MCD_OPC_FilterValue, 0, 29, 0, // Skip to: 2973
/* 2944 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 2947 */    MCD_OPC_FilterValue, 0, 46, 11, // Skip to: 5813
/* 2951 */    MCD_OPC_CheckPredicate, 0, 10, 0, // Skip to: 2965
/* 2955 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 2965
/* 2961 */    MCD_OPC_Decode, 184, 1, 39, // Opcode: FMOVD_FCC
/* 2965 */    MCD_OPC_CheckPredicate, 0, 28, 11, // Skip to: 5813
/* 2969 */    MCD_OPC_Decode, 216, 3, 40, // Opcode: V9FMOVD_FCC
/* 2973 */    MCD_OPC_FilterValue, 1, 20, 11, // Skip to: 5813
/* 2977 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 2980 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 2998
/* 2984 */    MCD_OPC_CheckPredicate, 0, 9, 11, // Skip to: 5813
/* 2988 */    MCD_OPC_CheckField, 18, 1, 0, 3, 11, // Skip to: 5813
/* 2994 */    MCD_OPC_Decode, 185, 1, 39, // Opcode: FMOVD_ICC
/* 2998 */    MCD_OPC_FilterValue, 2, 251, 10, // Skip to: 5813
/* 3002 */    MCD_OPC_CheckField, 18, 1, 0, 245, 10, // Skip to: 5813
/* 3008 */    MCD_OPC_Decode, 186, 1, 39, // Opcode: FMOVD_XCC
/* 3012 */    MCD_OPC_FilterValue, 3, 75, 0, // Skip to: 3091
/* 3016 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 3019 */    MCD_OPC_FilterValue, 0, 29, 0, // Skip to: 3052
/* 3023 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 3026 */    MCD_OPC_FilterValue, 0, 223, 10, // Skip to: 5813
/* 3030 */    MCD_OPC_CheckPredicate, 0, 10, 0, // Skip to: 3044
/* 3034 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3044
/* 3040 */    MCD_OPC_Decode, 188, 1, 41, // Opcode: FMOVQ_FCC
/* 3044 */    MCD_OPC_CheckPredicate, 0, 205, 10, // Skip to: 5813
/* 3048 */    MCD_OPC_Decode, 217, 3, 42, // Opcode: V9FMOVQ_FCC
/* 3052 */    MCD_OPC_FilterValue, 1, 197, 10, // Skip to: 5813
/* 3056 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 3059 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 3077
/* 3063 */    MCD_OPC_CheckPredicate, 0, 186, 10, // Skip to: 5813
/* 3067 */    MCD_OPC_CheckField, 18, 1, 0, 180, 10, // Skip to: 5813
/* 3073 */    MCD_OPC_Decode, 189, 1, 41, // Opcode: FMOVQ_ICC
/* 3077 */    MCD_OPC_FilterValue, 2, 172, 10, // Skip to: 5813
/* 3081 */    MCD_OPC_CheckField, 18, 1, 0, 166, 10, // Skip to: 5813
/* 3087 */    MCD_OPC_Decode, 190, 1, 41, // Opcode: FMOVQ_XCC
/* 3091 */    MCD_OPC_FilterValue, 5, 27, 0, // Skip to: 3122
/* 3095 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 3098 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3110
/* 3102 */    MCD_OPC_CheckPredicate, 0, 147, 10, // Skip to: 5813
/* 3106 */    MCD_OPC_Decode, 199, 1, 43, // Opcode: FMOVRLEZS
/* 3110 */    MCD_OPC_FilterValue, 3, 139, 10, // Skip to: 5813
/* 3114 */    MCD_OPC_CheckPredicate, 0, 135, 10, // Skip to: 5813
/* 3118 */    MCD_OPC_Decode, 196, 1, 43, // Opcode: FMOVRGZS
/* 3122 */    MCD_OPC_FilterValue, 6, 27, 0, // Skip to: 3153
/* 3126 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 3129 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3141
/* 3133 */    MCD_OPC_CheckPredicate, 0, 116, 10, // Skip to: 5813
/* 3137 */    MCD_OPC_Decode, 197, 1, 43, // Opcode: FMOVRLEZD
/* 3141 */    MCD_OPC_FilterValue, 3, 108, 10, // Skip to: 5813
/* 3145 */    MCD_OPC_CheckPredicate, 0, 104, 10, // Skip to: 5813
/* 3149 */    MCD_OPC_Decode, 194, 1, 43, // Opcode: FMOVRGZD
/* 3153 */    MCD_OPC_FilterValue, 7, 27, 0, // Skip to: 3184
/* 3157 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 3160 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3172
/* 3164 */    MCD_OPC_CheckPredicate, 0, 85, 10, // Skip to: 5813
/* 3168 */    MCD_OPC_Decode, 198, 1, 43, // Opcode: FMOVRLEZQ
/* 3172 */    MCD_OPC_FilterValue, 3, 77, 10, // Skip to: 5813
/* 3176 */    MCD_OPC_CheckPredicate, 0, 73, 10, // Skip to: 5813
/* 3180 */    MCD_OPC_Decode, 195, 1, 43, // Opcode: FMOVRGZQ
/* 3184 */    MCD_OPC_FilterValue, 17, 10, 0, // Skip to: 3198
/* 3188 */    MCD_OPC_CheckField, 11, 3, 1, 59, 10, // Skip to: 5813
/* 3194 */    MCD_OPC_Decode, 215, 3, 44, // Opcode: V9FCMPS
/* 3198 */    MCD_OPC_FilterValue, 18, 10, 0, // Skip to: 3212
/* 3202 */    MCD_OPC_CheckField, 11, 3, 1, 45, 10, // Skip to: 5813
/* 3208 */    MCD_OPC_Decode, 210, 3, 45, // Opcode: V9FCMPD
/* 3212 */    MCD_OPC_FilterValue, 19, 10, 0, // Skip to: 3226
/* 3216 */    MCD_OPC_CheckField, 11, 3, 1, 31, 10, // Skip to: 5813
/* 3222 */    MCD_OPC_Decode, 214, 3, 46, // Opcode: V9FCMPQ
/* 3226 */    MCD_OPC_FilterValue, 21, 10, 0, // Skip to: 3240
/* 3230 */    MCD_OPC_CheckField, 11, 3, 1, 17, 10, // Skip to: 5813
/* 3236 */    MCD_OPC_Decode, 213, 3, 44, // Opcode: V9FCMPES
/* 3240 */    MCD_OPC_FilterValue, 22, 10, 0, // Skip to: 3254
/* 3244 */    MCD_OPC_CheckField, 11, 3, 1, 3, 10, // Skip to: 5813
/* 3250 */    MCD_OPC_Decode, 211, 3, 45, // Opcode: V9FCMPED
/* 3254 */    MCD_OPC_FilterValue, 23, 10, 0, // Skip to: 3268
/* 3258 */    MCD_OPC_CheckField, 11, 3, 1, 245, 9, // Skip to: 5813
/* 3264 */    MCD_OPC_Decode, 212, 3, 46, // Opcode: V9FCMPEQ
/* 3268 */    MCD_OPC_FilterValue, 37, 51, 0, // Skip to: 3323
/* 3272 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 3275 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3287
/* 3279 */    MCD_OPC_CheckPredicate, 0, 226, 9, // Skip to: 5813
/* 3283 */    MCD_OPC_Decode, 208, 1, 43, // Opcode: FMOVRZS
/* 3287 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3299
/* 3291 */    MCD_OPC_CheckPredicate, 0, 214, 9, // Skip to: 5813
/* 3295 */    MCD_OPC_Decode, 202, 1, 43, // Opcode: FMOVRLZS
/* 3299 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 3311
/* 3303 */    MCD_OPC_CheckPredicate, 0, 202, 9, // Skip to: 5813
/* 3307 */    MCD_OPC_Decode, 205, 1, 43, // Opcode: FMOVRNZS
/* 3311 */    MCD_OPC_FilterValue, 3, 194, 9, // Skip to: 5813
/* 3315 */    MCD_OPC_CheckPredicate, 0, 190, 9, // Skip to: 5813
/* 3319 */    MCD_OPC_Decode, 193, 1, 43, // Opcode: FMOVRGEZS
/* 3323 */    MCD_OPC_FilterValue, 38, 51, 0, // Skip to: 3378
/* 3327 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 3330 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3342
/* 3334 */    MCD_OPC_CheckPredicate, 0, 171, 9, // Skip to: 5813
/* 3338 */    MCD_OPC_Decode, 206, 1, 43, // Opcode: FMOVRZD
/* 3342 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3354
/* 3346 */    MCD_OPC_CheckPredicate, 0, 159, 9, // Skip to: 5813
/* 3350 */    MCD_OPC_Decode, 200, 1, 43, // Opcode: FMOVRLZD
/* 3354 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 3366
/* 3358 */    MCD_OPC_CheckPredicate, 0, 147, 9, // Skip to: 5813
/* 3362 */    MCD_OPC_Decode, 203, 1, 43, // Opcode: FMOVRNZD
/* 3366 */    MCD_OPC_FilterValue, 3, 139, 9, // Skip to: 5813
/* 3370 */    MCD_OPC_CheckPredicate, 0, 135, 9, // Skip to: 5813
/* 3374 */    MCD_OPC_Decode, 191, 1, 43, // Opcode: FMOVRGEZD
/* 3378 */    MCD_OPC_FilterValue, 39, 127, 9, // Skip to: 5813
/* 3382 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 3385 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3397
/* 3389 */    MCD_OPC_CheckPredicate, 0, 116, 9, // Skip to: 5813
/* 3393 */    MCD_OPC_Decode, 207, 1, 43, // Opcode: FMOVRZQ
/* 3397 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3409
/* 3401 */    MCD_OPC_CheckPredicate, 0, 104, 9, // Skip to: 5813
/* 3405 */    MCD_OPC_Decode, 201, 1, 43, // Opcode: FMOVRLZQ
/* 3409 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 3421
/* 3413 */    MCD_OPC_CheckPredicate, 0, 92, 9, // Skip to: 5813
/* 3417 */    MCD_OPC_Decode, 204, 1, 43, // Opcode: FMOVRNZQ
/* 3421 */    MCD_OPC_FilterValue, 3, 84, 9, // Skip to: 5813
/* 3425 */    MCD_OPC_CheckPredicate, 0, 80, 9, // Skip to: 5813
/* 3429 */    MCD_OPC_Decode, 192, 1, 43, // Opcode: FMOVRGEZQ
/* 3433 */    MCD_OPC_FilterValue, 54, 16, 6, // Skip to: 4989
/* 3437 */    MCD_OPC_ExtractField, 5, 9,  // Inst{13-5} ...
/* 3440 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3452
/* 3444 */    MCD_OPC_CheckPredicate, 2, 61, 9, // Skip to: 5813
/* 3448 */    MCD_OPC_Decode, 132, 1, 10, // Opcode: EDGE8
/* 3452 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3464
/* 3456 */    MCD_OPC_CheckPredicate, 3, 49, 9, // Skip to: 5813
/* 3460 */    MCD_OPC_Decode, 135, 1, 10, // Opcode: EDGE8N
/* 3464 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 3476
/* 3468 */    MCD_OPC_CheckPredicate, 2, 37, 9, // Skip to: 5813
/* 3472 */    MCD_OPC_Decode, 133, 1, 10, // Opcode: EDGE8L
/* 3476 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 3488
/* 3480 */    MCD_OPC_CheckPredicate, 3, 25, 9, // Skip to: 5813
/* 3484 */    MCD_OPC_Decode, 134, 1, 10, // Opcode: EDGE8LN
/* 3488 */    MCD_OPC_FilterValue, 4, 7, 0, // Skip to: 3499
/* 3492 */    MCD_OPC_CheckPredicate, 2, 13, 9, // Skip to: 5813
/* 3496 */    MCD_OPC_Decode, 124, 10, // Opcode: EDGE16
/* 3499 */    MCD_OPC_FilterValue, 5, 7, 0, // Skip to: 3510
/* 3503 */    MCD_OPC_CheckPredicate, 3, 2, 9, // Skip to: 5813
/* 3507 */    MCD_OPC_Decode, 127, 10, // Opcode: EDGE16N
/* 3510 */    MCD_OPC_FilterValue, 6, 7, 0, // Skip to: 3521
/* 3514 */    MCD_OPC_CheckPredicate, 2, 247, 8, // Skip to: 5813
/* 3518 */    MCD_OPC_Decode, 125, 10, // Opcode: EDGE16L
/* 3521 */    MCD_OPC_FilterValue, 7, 7, 0, // Skip to: 3532
/* 3525 */    MCD_OPC_CheckPredicate, 3, 236, 8, // Skip to: 5813
/* 3529 */    MCD_OPC_Decode, 126, 10, // Opcode: EDGE16LN
/* 3532 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 3544
/* 3536 */    MCD_OPC_CheckPredicate, 2, 225, 8, // Skip to: 5813
/* 3540 */    MCD_OPC_Decode, 128, 1, 10, // Opcode: EDGE32
/* 3544 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 3556
/* 3548 */    MCD_OPC_CheckPredicate, 3, 213, 8, // Skip to: 5813
/* 3552 */    MCD_OPC_Decode, 131, 1, 10, // Opcode: EDGE32N
/* 3556 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 3568
/* 3560 */    MCD_OPC_CheckPredicate, 2, 201, 8, // Skip to: 5813
/* 3564 */    MCD_OPC_Decode, 129, 1, 10, // Opcode: EDGE32L
/* 3568 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 3580
/* 3572 */    MCD_OPC_CheckPredicate, 3, 189, 8, // Skip to: 5813
/* 3576 */    MCD_OPC_Decode, 130, 1, 10, // Opcode: EDGE32LN
/* 3580 */    MCD_OPC_FilterValue, 16, 7, 0, // Skip to: 3591
/* 3584 */    MCD_OPC_CheckPredicate, 2, 177, 8, // Skip to: 5813
/* 3588 */    MCD_OPC_Decode, 49, 10, // Opcode: ARRAY8
/* 3591 */    MCD_OPC_FilterValue, 17, 7, 0, // Skip to: 3602
/* 3595 */    MCD_OPC_CheckPredicate, 1, 166, 8, // Skip to: 5813
/* 3599 */    MCD_OPC_Decode, 26, 10, // Opcode: ADDXC
/* 3602 */    MCD_OPC_FilterValue, 18, 7, 0, // Skip to: 3613
/* 3606 */    MCD_OPC_CheckPredicate, 2, 155, 8, // Skip to: 5813
/* 3610 */    MCD_OPC_Decode, 47, 10, // Opcode: ARRAY16
/* 3613 */    MCD_OPC_FilterValue, 19, 7, 0, // Skip to: 3624
/* 3617 */    MCD_OPC_CheckPredicate, 1, 144, 8, // Skip to: 5813
/* 3621 */    MCD_OPC_Decode, 27, 10, // Opcode: ADDXCCC
/* 3624 */    MCD_OPC_FilterValue, 20, 7, 0, // Skip to: 3635
/* 3628 */    MCD_OPC_CheckPredicate, 2, 133, 8, // Skip to: 5813
/* 3632 */    MCD_OPC_Decode, 48, 10, // Opcode: ARRAY32
/* 3635 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 3647
/* 3639 */    MCD_OPC_CheckPredicate, 1, 122, 8, // Skip to: 5813
/* 3643 */    MCD_OPC_Decode, 206, 3, 10, // Opcode: UMULXHI
/* 3647 */    MCD_OPC_FilterValue, 23, 14, 0, // Skip to: 3665
/* 3651 */    MCD_OPC_CheckPredicate, 1, 110, 8, // Skip to: 5813
/* 3655 */    MCD_OPC_CheckField, 14, 5, 0, 104, 8, // Skip to: 5813
/* 3661 */    MCD_OPC_Decode, 195, 2, 47, // Opcode: LZCNT
/* 3665 */    MCD_OPC_FilterValue, 24, 7, 0, // Skip to: 3676
/* 3669 */    MCD_OPC_CheckPredicate, 2, 92, 8, // Skip to: 5813
/* 3673 */    MCD_OPC_Decode, 34, 10, // Opcode: ALIGNADDR
/* 3676 */    MCD_OPC_FilterValue, 25, 7, 0, // Skip to: 3687
/* 3680 */    MCD_OPC_CheckPredicate, 3, 81, 8, // Skip to: 5813
/* 3684 */    MCD_OPC_Decode, 76, 10, // Opcode: BMASK
/* 3687 */    MCD_OPC_FilterValue, 26, 7, 0, // Skip to: 3698
/* 3691 */    MCD_OPC_CheckPredicate, 2, 70, 8, // Skip to: 5813
/* 3695 */    MCD_OPC_Decode, 35, 10, // Opcode: ALIGNADDRL
/* 3698 */    MCD_OPC_FilterValue, 27, 19, 0, // Skip to: 3721
/* 3702 */    MCD_OPC_CheckPredicate, 1, 59, 8, // Skip to: 5813
/* 3706 */    MCD_OPC_CheckField, 25, 5, 0, 53, 8, // Skip to: 5813
/* 3712 */    MCD_OPC_CheckField, 14, 5, 0, 47, 8, // Skip to: 5813
/* 3718 */    MCD_OPC_Decode, 121, 48, // Opcode: CMASK8
/* 3721 */    MCD_OPC_FilterValue, 28, 7, 0, // Skip to: 3732
/* 3725 */    MCD_OPC_CheckPredicate, 3, 36, 8, // Skip to: 5813
/* 3729 */    MCD_OPC_Decode, 113, 27, // Opcode: BSHUFFLE
/* 3732 */    MCD_OPC_FilterValue, 29, 19, 0, // Skip to: 3755
/* 3736 */    MCD_OPC_CheckPredicate, 1, 25, 8, // Skip to: 5813
/* 3740 */    MCD_OPC_CheckField, 25, 5, 0, 19, 8, // Skip to: 5813
/* 3746 */    MCD_OPC_CheckField, 14, 5, 0, 13, 8, // Skip to: 5813
/* 3752 */    MCD_OPC_Decode, 119, 48, // Opcode: CMASK16
/* 3755 */    MCD_OPC_FilterValue, 31, 19, 0, // Skip to: 3778
/* 3759 */    MCD_OPC_CheckPredicate, 1, 2, 8, // Skip to: 5813
/* 3763 */    MCD_OPC_CheckField, 25, 5, 0, 252, 7, // Skip to: 5813
/* 3769 */    MCD_OPC_CheckField, 14, 5, 0, 246, 7, // Skip to: 5813
/* 3775 */    MCD_OPC_Decode, 120, 48, // Opcode: CMASK32
/* 3778 */    MCD_OPC_FilterValue, 32, 8, 0, // Skip to: 3790
/* 3782 */    MCD_OPC_CheckPredicate, 2, 235, 7, // Skip to: 5813
/* 3786 */    MCD_OPC_Decode, 157, 1, 49, // Opcode: FCMPLE16
/* 3790 */    MCD_OPC_FilterValue, 33, 8, 0, // Skip to: 3802
/* 3794 */    MCD_OPC_CheckPredicate, 1, 223, 7, // Skip to: 5813
/* 3798 */    MCD_OPC_Decode, 140, 2, 27, // Opcode: FSLL16
/* 3802 */    MCD_OPC_FilterValue, 34, 8, 0, // Skip to: 3814
/* 3806 */    MCD_OPC_CheckPredicate, 2, 211, 7, // Skip to: 5813
/* 3810 */    MCD_OPC_Decode, 159, 1, 49, // Opcode: FCMPNE16
/* 3814 */    MCD_OPC_FilterValue, 35, 8, 0, // Skip to: 3826
/* 3818 */    MCD_OPC_CheckPredicate, 1, 199, 7, // Skip to: 5813
/* 3822 */    MCD_OPC_Decode, 152, 2, 27, // Opcode: FSRL16
/* 3826 */    MCD_OPC_FilterValue, 36, 8, 0, // Skip to: 3838
/* 3830 */    MCD_OPC_CheckPredicate, 2, 187, 7, // Skip to: 5813
/* 3834 */    MCD_OPC_Decode, 158, 1, 49, // Opcode: FCMPLE32
/* 3838 */    MCD_OPC_FilterValue, 37, 8, 0, // Skip to: 3850
/* 3842 */    MCD_OPC_CheckPredicate, 1, 175, 7, // Skip to: 5813
/* 3846 */    MCD_OPC_Decode, 141, 2, 27, // Opcode: FSLL32
/* 3850 */    MCD_OPC_FilterValue, 38, 8, 0, // Skip to: 3862
/* 3854 */    MCD_OPC_CheckPredicate, 2, 163, 7, // Skip to: 5813
/* 3858 */    MCD_OPC_Decode, 160, 1, 49, // Opcode: FCMPNE32
/* 3862 */    MCD_OPC_FilterValue, 39, 8, 0, // Skip to: 3874
/* 3866 */    MCD_OPC_CheckPredicate, 1, 151, 7, // Skip to: 5813
/* 3870 */    MCD_OPC_Decode, 153, 2, 27, // Opcode: FSRL32
/* 3874 */    MCD_OPC_FilterValue, 40, 8, 0, // Skip to: 3886
/* 3878 */    MCD_OPC_CheckPredicate, 2, 139, 7, // Skip to: 5813
/* 3882 */    MCD_OPC_Decode, 155, 1, 49, // Opcode: FCMPGT16
/* 3886 */    MCD_OPC_FilterValue, 41, 8, 0, // Skip to: 3898
/* 3890 */    MCD_OPC_CheckPredicate, 1, 127, 7, // Skip to: 5813
/* 3894 */    MCD_OPC_Decode, 138, 2, 27, // Opcode: FSLAS16
/* 3898 */    MCD_OPC_FilterValue, 42, 8, 0, // Skip to: 3910
/* 3902 */    MCD_OPC_CheckPredicate, 2, 115, 7, // Skip to: 5813
/* 3906 */    MCD_OPC_Decode, 153, 1, 49, // Opcode: FCMPEQ16
/* 3910 */    MCD_OPC_FilterValue, 43, 8, 0, // Skip to: 3922
/* 3914 */    MCD_OPC_CheckPredicate, 1, 103, 7, // Skip to: 5813
/* 3918 */    MCD_OPC_Decode, 146, 2, 27, // Opcode: FSRA16
/* 3922 */    MCD_OPC_FilterValue, 44, 8, 0, // Skip to: 3934
/* 3926 */    MCD_OPC_CheckPredicate, 2, 91, 7, // Skip to: 5813
/* 3930 */    MCD_OPC_Decode, 156, 1, 49, // Opcode: FCMPGT32
/* 3934 */    MCD_OPC_FilterValue, 45, 8, 0, // Skip to: 3946
/* 3938 */    MCD_OPC_CheckPredicate, 1, 79, 7, // Skip to: 5813
/* 3942 */    MCD_OPC_Decode, 139, 2, 27, // Opcode: FSLAS32
/* 3946 */    MCD_OPC_FilterValue, 46, 8, 0, // Skip to: 3958
/* 3950 */    MCD_OPC_CheckPredicate, 2, 67, 7, // Skip to: 5813
/* 3954 */    MCD_OPC_Decode, 154, 1, 49, // Opcode: FCMPEQ32
/* 3958 */    MCD_OPC_FilterValue, 47, 8, 0, // Skip to: 3970
/* 3962 */    MCD_OPC_CheckPredicate, 1, 55, 7, // Skip to: 5813
/* 3966 */    MCD_OPC_Decode, 147, 2, 27, // Opcode: FSRA32
/* 3970 */    MCD_OPC_FilterValue, 49, 8, 0, // Skip to: 3982
/* 3974 */    MCD_OPC_CheckPredicate, 2, 43, 7, // Skip to: 5813
/* 3978 */    MCD_OPC_Decode, 215, 1, 27, // Opcode: FMUL8X16
/* 3982 */    MCD_OPC_FilterValue, 51, 8, 0, // Skip to: 3994
/* 3986 */    MCD_OPC_CheckPredicate, 2, 31, 7, // Skip to: 5813
/* 3990 */    MCD_OPC_Decode, 217, 1, 27, // Opcode: FMUL8X16AU
/* 3994 */    MCD_OPC_FilterValue, 53, 8, 0, // Skip to: 4006
/* 3998 */    MCD_OPC_CheckPredicate, 2, 19, 7, // Skip to: 5813
/* 4002 */    MCD_OPC_Decode, 216, 1, 27, // Opcode: FMUL8X16AL
/* 4006 */    MCD_OPC_FilterValue, 54, 8, 0, // Skip to: 4018
/* 4010 */    MCD_OPC_CheckPredicate, 2, 7, 7, // Skip to: 5813
/* 4014 */    MCD_OPC_Decode, 213, 1, 27, // Opcode: FMUL8SUX16
/* 4018 */    MCD_OPC_FilterValue, 55, 8, 0, // Skip to: 4030
/* 4022 */    MCD_OPC_CheckPredicate, 2, 251, 6, // Skip to: 5813
/* 4026 */    MCD_OPC_Decode, 214, 1, 27, // Opcode: FMUL8ULX16
/* 4030 */    MCD_OPC_FilterValue, 56, 8, 0, // Skip to: 4042
/* 4034 */    MCD_OPC_CheckPredicate, 2, 239, 6, // Skip to: 5813
/* 4038 */    MCD_OPC_Decode, 219, 1, 27, // Opcode: FMULD8SUX16
/* 4042 */    MCD_OPC_FilterValue, 57, 8, 0, // Skip to: 4054
/* 4046 */    MCD_OPC_CheckPredicate, 2, 227, 6, // Skip to: 5813
/* 4050 */    MCD_OPC_Decode, 220, 1, 27, // Opcode: FMULD8ULX16
/* 4054 */    MCD_OPC_FilterValue, 58, 8, 0, // Skip to: 4066
/* 4058 */    MCD_OPC_CheckPredicate, 2, 215, 6, // Skip to: 5813
/* 4062 */    MCD_OPC_Decode, 250, 1, 27, // Opcode: FPACK32
/* 4066 */    MCD_OPC_FilterValue, 59, 14, 0, // Skip to: 4084
/* 4070 */    MCD_OPC_CheckPredicate, 2, 203, 6, // Skip to: 5813
/* 4074 */    MCD_OPC_CheckField, 14, 5, 0, 197, 6, // Skip to: 5813
/* 4080 */    MCD_OPC_Decode, 249, 1, 24, // Opcode: FPACK16
/* 4084 */    MCD_OPC_FilterValue, 61, 14, 0, // Skip to: 4102
/* 4088 */    MCD_OPC_CheckPredicate, 2, 185, 6, // Skip to: 5813
/* 4092 */    MCD_OPC_CheckField, 14, 5, 0, 179, 6, // Skip to: 5813
/* 4098 */    MCD_OPC_Decode, 251, 1, 24, // Opcode: FPACKFIX
/* 4102 */    MCD_OPC_FilterValue, 62, 8, 0, // Skip to: 4114
/* 4106 */    MCD_OPC_CheckPredicate, 2, 167, 6, // Skip to: 5813
/* 4110 */    MCD_OPC_Decode, 234, 2, 27, // Opcode: PDIST
/* 4114 */    MCD_OPC_FilterValue, 63, 8, 0, // Skip to: 4126
/* 4118 */    MCD_OPC_CheckPredicate, 1, 155, 6, // Skip to: 5813
/* 4122 */    MCD_OPC_Decode, 235, 2, 27, // Opcode: PDISTN
/* 4126 */    MCD_OPC_FilterValue, 64, 8, 0, // Skip to: 4138
/* 4130 */    MCD_OPC_CheckPredicate, 1, 143, 6, // Skip to: 5813
/* 4134 */    MCD_OPC_Decode, 182, 1, 27, // Opcode: FMEAN16
/* 4138 */    MCD_OPC_FilterValue, 66, 8, 0, // Skip to: 4150
/* 4142 */    MCD_OPC_CheckPredicate, 1, 131, 6, // Skip to: 5813
/* 4146 */    MCD_OPC_Decode, 128, 2, 27, // Opcode: FPADD64
/* 4150 */    MCD_OPC_FilterValue, 68, 8, 0, // Skip to: 4162
/* 4154 */    MCD_OPC_CheckPredicate, 1, 119, 6, // Skip to: 5813
/* 4158 */    MCD_OPC_Decode, 151, 1, 27, // Opcode: FCHKSM16
/* 4162 */    MCD_OPC_FilterValue, 72, 8, 0, // Skip to: 4174
/* 4166 */    MCD_OPC_CheckPredicate, 2, 107, 6, // Skip to: 5813
/* 4170 */    MCD_OPC_Decode, 142, 1, 27, // Opcode: FALIGNADATA
/* 4174 */    MCD_OPC_FilterValue, 75, 8, 0, // Skip to: 4186
/* 4178 */    MCD_OPC_CheckPredicate, 2, 95, 6, // Skip to: 5813
/* 4182 */    MCD_OPC_Decode, 129, 2, 27, // Opcode: FPMERGE
/* 4186 */    MCD_OPC_FilterValue, 77, 14, 0, // Skip to: 4204
/* 4190 */    MCD_OPC_CheckPredicate, 2, 83, 6, // Skip to: 5813
/* 4194 */    MCD_OPC_CheckField, 14, 5, 0, 77, 6, // Skip to: 5813
/* 4200 */    MCD_OPC_Decode, 171, 1, 24, // Opcode: FEXPAND
/* 4204 */    MCD_OPC_FilterValue, 80, 8, 0, // Skip to: 4216
/* 4208 */    MCD_OPC_CheckPredicate, 2, 65, 6, // Skip to: 5813
/* 4212 */    MCD_OPC_Decode, 252, 1, 27, // Opcode: FPADD16
/* 4216 */    MCD_OPC_FilterValue, 81, 8, 0, // Skip to: 4228
/* 4220 */    MCD_OPC_CheckPredicate, 2, 53, 6, // Skip to: 5813
/* 4224 */    MCD_OPC_Decode, 253, 1, 27, // Opcode: FPADD16S
/* 4228 */    MCD_OPC_FilterValue, 82, 8, 0, // Skip to: 4240
/* 4232 */    MCD_OPC_CheckPredicate, 2, 41, 6, // Skip to: 5813
/* 4236 */    MCD_OPC_Decode, 254, 1, 27, // Opcode: FPADD32
/* 4240 */    MCD_OPC_FilterValue, 83, 8, 0, // Skip to: 4252
/* 4244 */    MCD_OPC_CheckPredicate, 2, 29, 6, // Skip to: 5813
/* 4248 */    MCD_OPC_Decode, 255, 1, 27, // Opcode: FPADD32S
/* 4252 */    MCD_OPC_FilterValue, 84, 8, 0, // Skip to: 4264
/* 4256 */    MCD_OPC_CheckPredicate, 2, 17, 6, // Skip to: 5813
/* 4260 */    MCD_OPC_Decode, 130, 2, 27, // Opcode: FPSUB16
/* 4264 */    MCD_OPC_FilterValue, 85, 8, 0, // Skip to: 4276
/* 4268 */    MCD_OPC_CheckPredicate, 2, 5, 6, // Skip to: 5813
/* 4272 */    MCD_OPC_Decode, 131, 2, 27, // Opcode: FPSUB16S
/* 4276 */    MCD_OPC_FilterValue, 86, 8, 0, // Skip to: 4288
/* 4280 */    MCD_OPC_CheckPredicate, 2, 249, 5, // Skip to: 5813
/* 4284 */    MCD_OPC_Decode, 132, 2, 27, // Opcode: FPSUB32
/* 4288 */    MCD_OPC_FilterValue, 87, 8, 0, // Skip to: 4300
/* 4292 */    MCD_OPC_CheckPredicate, 2, 237, 5, // Skip to: 5813
/* 4296 */    MCD_OPC_Decode, 133, 2, 27, // Opcode: FPSUB32S
/* 4300 */    MCD_OPC_FilterValue, 96, 20, 0, // Skip to: 4324
/* 4304 */    MCD_OPC_CheckPredicate, 2, 225, 5, // Skip to: 5813
/* 4308 */    MCD_OPC_CheckField, 14, 5, 0, 219, 5, // Skip to: 5813
/* 4314 */    MCD_OPC_CheckField, 0, 5, 0, 213, 5, // Skip to: 5813
/* 4320 */    MCD_OPC_Decode, 168, 2, 50, // Opcode: FZERO
/* 4324 */    MCD_OPC_FilterValue, 97, 20, 0, // Skip to: 4348
/* 4328 */    MCD_OPC_CheckPredicate, 2, 201, 5, // Skip to: 5813
/* 4332 */    MCD_OPC_CheckField, 14, 5, 0, 195, 5, // Skip to: 5813
/* 4338 */    MCD_OPC_CheckField, 0, 5, 0, 189, 5, // Skip to: 5813
/* 4344 */    MCD_OPC_Decode, 169, 2, 51, // Opcode: FZEROS
/* 4348 */    MCD_OPC_FilterValue, 98, 8, 0, // Skip to: 4360
/* 4352 */    MCD_OPC_CheckPredicate, 2, 177, 5, // Skip to: 5813
/* 4356 */    MCD_OPC_Decode, 234, 1, 27, // Opcode: FNOR
/* 4360 */    MCD_OPC_FilterValue, 99, 8, 0, // Skip to: 4372
/* 4364 */    MCD_OPC_CheckPredicate, 2, 165, 5, // Skip to: 5813
/* 4368 */    MCD_OPC_Decode, 235, 1, 26, // Opcode: FNORS
/* 4372 */    MCD_OPC_FilterValue, 100, 8, 0, // Skip to: 4384
/* 4376 */    MCD_OPC_CheckPredicate, 2, 153, 5, // Skip to: 5813
/* 4380 */    MCD_OPC_Decode, 146, 1, 27, // Opcode: FANDNOT2
/* 4384 */    MCD_OPC_FilterValue, 101, 8, 0, // Skip to: 4396
/* 4388 */    MCD_OPC_CheckPredicate, 2, 141, 5, // Skip to: 5813
/* 4392 */    MCD_OPC_Decode, 147, 1, 26, // Opcode: FANDNOT2S
/* 4396 */    MCD_OPC_FilterValue, 102, 14, 0, // Skip to: 4414
/* 4400 */    MCD_OPC_CheckPredicate, 2, 129, 5, // Skip to: 5813
/* 4404 */    MCD_OPC_CheckField, 14, 5, 0, 123, 5, // Skip to: 5813
/* 4410 */    MCD_OPC_Decode, 238, 1, 24, // Opcode: FNOT2
/* 4414 */    MCD_OPC_FilterValue, 103, 14, 0, // Skip to: 4432
/* 4418 */    MCD_OPC_CheckPredicate, 2, 111, 5, // Skip to: 5813
/* 4422 */    MCD_OPC_CheckField, 14, 5, 0, 105, 5, // Skip to: 5813
/* 4428 */    MCD_OPC_Decode, 239, 1, 23, // Opcode: FNOT2S
/* 4432 */    MCD_OPC_FilterValue, 104, 8, 0, // Skip to: 4444
/* 4436 */    MCD_OPC_CheckPredicate, 2, 93, 5, // Skip to: 5813
/* 4440 */    MCD_OPC_Decode, 144, 1, 27, // Opcode: FANDNOT1
/* 4444 */    MCD_OPC_FilterValue, 105, 8, 0, // Skip to: 4456
/* 4448 */    MCD_OPC_CheckPredicate, 2, 81, 5, // Skip to: 5813
/* 4452 */    MCD_OPC_Decode, 145, 1, 26, // Opcode: FANDNOT1S
/* 4456 */    MCD_OPC_FilterValue, 106, 14, 0, // Skip to: 4474
/* 4460 */    MCD_OPC_CheckPredicate, 2, 69, 5, // Skip to: 5813
/* 4464 */    MCD_OPC_CheckField, 0, 5, 0, 63, 5, // Skip to: 5813
/* 4470 */    MCD_OPC_Decode, 236, 1, 52, // Opcode: FNOT1
/* 4474 */    MCD_OPC_FilterValue, 107, 14, 0, // Skip to: 4492
/* 4478 */    MCD_OPC_CheckPredicate, 2, 51, 5, // Skip to: 5813
/* 4482 */    MCD_OPC_CheckField, 0, 5, 0, 45, 5, // Skip to: 5813
/* 4488 */    MCD_OPC_Decode, 237, 1, 53, // Opcode: FNOT1S
/* 4492 */    MCD_OPC_FilterValue, 108, 8, 0, // Skip to: 4504
/* 4496 */    MCD_OPC_CheckPredicate, 2, 33, 5, // Skip to: 5813
/* 4500 */    MCD_OPC_Decode, 163, 2, 27, // Opcode: FXOR
/* 4504 */    MCD_OPC_FilterValue, 109, 8, 0, // Skip to: 4516
/* 4508 */    MCD_OPC_CheckPredicate, 2, 21, 5, // Skip to: 5813
/* 4512 */    MCD_OPC_Decode, 164, 2, 26, // Opcode: FXORS
/* 4516 */    MCD_OPC_FilterValue, 110, 8, 0, // Skip to: 4528
/* 4520 */    MCD_OPC_CheckPredicate, 2, 9, 5, // Skip to: 5813
/* 4524 */    MCD_OPC_Decode, 225, 1, 27, // Opcode: FNAND
/* 4528 */    MCD_OPC_FilterValue, 111, 8, 0, // Skip to: 4540
/* 4532 */    MCD_OPC_CheckPredicate, 2, 253, 4, // Skip to: 5813
/* 4536 */    MCD_OPC_Decode, 226, 1, 26, // Opcode: FNANDS
/* 4540 */    MCD_OPC_FilterValue, 112, 8, 0, // Skip to: 4552
/* 4544 */    MCD_OPC_CheckPredicate, 2, 241, 4, // Skip to: 5813
/* 4548 */    MCD_OPC_Decode, 143, 1, 27, // Opcode: FAND
/* 4552 */    MCD_OPC_FilterValue, 113, 8, 0, // Skip to: 4564
/* 4556 */    MCD_OPC_CheckPredicate, 2, 229, 4, // Skip to: 5813
/* 4560 */    MCD_OPC_Decode, 148, 1, 26, // Opcode: FANDS
/* 4564 */    MCD_OPC_FilterValue, 114, 8, 0, // Skip to: 4576
/* 4568 */    MCD_OPC_CheckPredicate, 2, 217, 4, // Skip to: 5813
/* 4572 */    MCD_OPC_Decode, 161, 2, 27, // Opcode: FXNOR
/* 4576 */    MCD_OPC_FilterValue, 115, 8, 0, // Skip to: 4588
/* 4580 */    MCD_OPC_CheckPredicate, 2, 205, 4, // Skip to: 5813
/* 4584 */    MCD_OPC_Decode, 162, 2, 26, // Opcode: FXNORS
/* 4588 */    MCD_OPC_FilterValue, 116, 14, 0, // Skip to: 4606
/* 4592 */    MCD_OPC_CheckPredicate, 2, 193, 4, // Skip to: 5813
/* 4596 */    MCD_OPC_CheckField, 0, 5, 0, 187, 4, // Skip to: 5813
/* 4602 */    MCD_OPC_Decode, 148, 2, 52, // Opcode: FSRC1
/* 4606 */    MCD_OPC_FilterValue, 117, 14, 0, // Skip to: 4624
/* 4610 */    MCD_OPC_CheckPredicate, 2, 175, 4, // Skip to: 5813
/* 4614 */    MCD_OPC_CheckField, 0, 5, 0, 169, 4, // Skip to: 5813
/* 4620 */    MCD_OPC_Decode, 149, 2, 53, // Opcode: FSRC1S
/* 4624 */    MCD_OPC_FilterValue, 118, 8, 0, // Skip to: 4636
/* 4628 */    MCD_OPC_CheckPredicate, 2, 157, 4, // Skip to: 5813
/* 4632 */    MCD_OPC_Decode, 246, 1, 27, // Opcode: FORNOT2
/* 4636 */    MCD_OPC_FilterValue, 119, 8, 0, // Skip to: 4648
/* 4640 */    MCD_OPC_CheckPredicate, 2, 145, 4, // Skip to: 5813
/* 4644 */    MCD_OPC_Decode, 247, 1, 26, // Opcode: FORNOT2S
/* 4648 */    MCD_OPC_FilterValue, 120, 14, 0, // Skip to: 4666
/* 4652 */    MCD_OPC_CheckPredicate, 2, 133, 4, // Skip to: 5813
/* 4656 */    MCD_OPC_CheckField, 14, 5, 0, 127, 4, // Skip to: 5813
/* 4662 */    MCD_OPC_Decode, 150, 2, 24, // Opcode: FSRC2
/* 4666 */    MCD_OPC_FilterValue, 121, 14, 0, // Skip to: 4684
/* 4670 */    MCD_OPC_CheckPredicate, 2, 115, 4, // Skip to: 5813
/* 4674 */    MCD_OPC_CheckField, 14, 5, 0, 109, 4, // Skip to: 5813
/* 4680 */    MCD_OPC_Decode, 151, 2, 23, // Opcode: FSRC2S
/* 4684 */    MCD_OPC_FilterValue, 122, 8, 0, // Skip to: 4696
/* 4688 */    MCD_OPC_CheckPredicate, 2, 97, 4, // Skip to: 5813
/* 4692 */    MCD_OPC_Decode, 244, 1, 27, // Opcode: FORNOT1
/* 4696 */    MCD_OPC_FilterValue, 123, 8, 0, // Skip to: 4708
/* 4700 */    MCD_OPC_CheckPredicate, 2, 85, 4, // Skip to: 5813
/* 4704 */    MCD_OPC_Decode, 245, 1, 26, // Opcode: FORNOT1S
/* 4708 */    MCD_OPC_FilterValue, 124, 8, 0, // Skip to: 4720
/* 4712 */    MCD_OPC_CheckPredicate, 2, 73, 4, // Skip to: 5813
/* 4716 */    MCD_OPC_Decode, 243, 1, 27, // Opcode: FOR
/* 4720 */    MCD_OPC_FilterValue, 125, 8, 0, // Skip to: 4732
/* 4724 */    MCD_OPC_CheckPredicate, 2, 61, 4, // Skip to: 5813
/* 4728 */    MCD_OPC_Decode, 248, 1, 26, // Opcode: FORS
/* 4732 */    MCD_OPC_FilterValue, 126, 20, 0, // Skip to: 4756
/* 4736 */    MCD_OPC_CheckPredicate, 2, 49, 4, // Skip to: 5813
/* 4740 */    MCD_OPC_CheckField, 14, 5, 0, 43, 4, // Skip to: 5813
/* 4746 */    MCD_OPC_CheckField, 0, 5, 0, 37, 4, // Skip to: 5813
/* 4752 */    MCD_OPC_Decode, 241, 1, 50, // Opcode: FONE
/* 4756 */    MCD_OPC_FilterValue, 127, 20, 0, // Skip to: 4780
/* 4760 */    MCD_OPC_CheckPredicate, 2, 25, 4, // Skip to: 5813
/* 4764 */    MCD_OPC_CheckField, 14, 5, 0, 19, 4, // Skip to: 5813
/* 4770 */    MCD_OPC_CheckField, 0, 5, 0, 13, 4, // Skip to: 5813
/* 4776 */    MCD_OPC_Decode, 242, 1, 51, // Opcode: FONES
/* 4780 */    MCD_OPC_FilterValue, 128, 1, 26, 0, // Skip to: 4811
/* 4785 */    MCD_OPC_CheckPredicate, 2, 0, 4, // Skip to: 5813
/* 4789 */    MCD_OPC_CheckField, 25, 5, 0, 250, 3, // Skip to: 5813
/* 4795 */    MCD_OPC_CheckField, 14, 5, 0, 244, 3, // Skip to: 5813
/* 4801 */    MCD_OPC_CheckField, 0, 5, 0, 238, 3, // Skip to: 5813
/* 4807 */    MCD_OPC_Decode, 134, 3, 4, // Opcode: SHUTDOWN
/* 4811 */    MCD_OPC_FilterValue, 129, 1, 26, 0, // Skip to: 4842
/* 4816 */    MCD_OPC_CheckPredicate, 3, 225, 3, // Skip to: 5813
/* 4820 */    MCD_OPC_CheckField, 25, 5, 0, 219, 3, // Skip to: 5813
/* 4826 */    MCD_OPC_CheckField, 14, 5, 0, 213, 3, // Skip to: 5813
/* 4832 */    MCD_OPC_CheckField, 0, 5, 0, 207, 3, // Skip to: 5813
/* 4838 */    MCD_OPC_Decode, 135, 3, 4, // Opcode: SIAM
/* 4842 */    MCD_OPC_FilterValue, 144, 2, 14, 0, // Skip to: 4861
/* 4847 */    MCD_OPC_CheckPredicate, 1, 194, 3, // Skip to: 5813
/* 4851 */    MCD_OPC_CheckField, 14, 5, 0, 188, 3, // Skip to: 5813
/* 4857 */    MCD_OPC_Decode, 197, 2, 54, // Opcode: MOVDTOX
/* 4861 */    MCD_OPC_FilterValue, 145, 2, 14, 0, // Skip to: 4880
/* 4866 */    MCD_OPC_CheckPredicate, 1, 175, 3, // Skip to: 5813
/* 4870 */    MCD_OPC_CheckField, 14, 5, 0, 169, 3, // Skip to: 5813
/* 4876 */    MCD_OPC_Decode, 215, 2, 54, // Opcode: MOVSTOUW
/* 4880 */    MCD_OPC_FilterValue, 147, 2, 14, 0, // Skip to: 4899
/* 4885 */    MCD_OPC_CheckPredicate, 1, 156, 3, // Skip to: 5813
/* 4889 */    MCD_OPC_CheckField, 14, 5, 0, 150, 3, // Skip to: 5813
/* 4895 */    MCD_OPC_Decode, 214, 2, 54, // Opcode: MOVSTOSW
/* 4899 */    MCD_OPC_FilterValue, 149, 2, 8, 0, // Skip to: 4912
/* 4904 */    MCD_OPC_CheckPredicate, 1, 137, 3, // Skip to: 5813
/* 4908 */    MCD_OPC_Decode, 223, 3, 10, // Opcode: XMULX
/* 4912 */    MCD_OPC_FilterValue, 151, 2, 8, 0, // Skip to: 4925
/* 4917 */    MCD_OPC_CheckPredicate, 1, 124, 3, // Skip to: 5813
/* 4921 */    MCD_OPC_Decode, 224, 3, 10, // Opcode: XMULXHI
/* 4925 */    MCD_OPC_FilterValue, 152, 2, 14, 0, // Skip to: 4944
/* 4930 */    MCD_OPC_CheckPredicate, 1, 111, 3, // Skip to: 5813
/* 4934 */    MCD_OPC_CheckField, 14, 5, 0, 105, 3, // Skip to: 5813
/* 4940 */    MCD_OPC_Decode, 219, 2, 55, // Opcode: MOVXTOD
/* 4944 */    MCD_OPC_FilterValue, 153, 2, 14, 0, // Skip to: 4963
/* 4949 */    MCD_OPC_CheckPredicate, 1, 92, 3, // Skip to: 5813
/* 4953 */    MCD_OPC_CheckField, 14, 5, 0, 86, 3, // Skip to: 5813
/* 4959 */    MCD_OPC_Decode, 216, 2, 55, // Opcode: MOVWTOS
/* 4963 */    MCD_OPC_FilterValue, 209, 2, 8, 0, // Skip to: 4976
/* 4968 */    MCD_OPC_CheckPredicate, 1, 73, 3, // Skip to: 5813
/* 4972 */    MCD_OPC_Decode, 180, 1, 45, // Opcode: FLCMPS
/* 4976 */    MCD_OPC_FilterValue, 210, 2, 64, 3, // Skip to: 5813
/* 4981 */    MCD_OPC_CheckPredicate, 1, 60, 3, // Skip to: 5813
/* 4985 */    MCD_OPC_Decode, 179, 1, 45, // Opcode: FLCMPD
/* 4989 */    MCD_OPC_FilterValue, 56, 25, 0, // Skip to: 5018
/* 4993 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 4996 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5010
/* 5000 */    MCD_OPC_CheckField, 5, 8, 0, 39, 3, // Skip to: 5813
/* 5006 */    MCD_OPC_Decode, 172, 2, 56, // Opcode: JMPLrr
/* 5010 */    MCD_OPC_FilterValue, 1, 31, 3, // Skip to: 5813
/* 5014 */    MCD_OPC_Decode, 171, 2, 56, // Opcode: JMPLri
/* 5018 */    MCD_OPC_FilterValue, 57, 37, 0, // Skip to: 5059
/* 5022 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5025 */    MCD_OPC_FilterValue, 0, 16, 0, // Skip to: 5045
/* 5029 */    MCD_OPC_CheckField, 25, 5, 0, 10, 3, // Skip to: 5813
/* 5035 */    MCD_OPC_CheckField, 5, 8, 0, 4, 3, // Skip to: 5813
/* 5041 */    MCD_OPC_Decode, 243, 2, 57, // Opcode: RETTrr
/* 5045 */    MCD_OPC_FilterValue, 1, 252, 2, // Skip to: 5813
/* 5049 */    MCD_OPC_CheckField, 25, 5, 0, 246, 2, // Skip to: 5813
/* 5055 */    MCD_OPC_Decode, 242, 2, 57, // Opcode: RETTri
/* 5059 */    MCD_OPC_FilterValue, 58, 115, 0, // Skip to: 5178
/* 5063 */    MCD_OPC_ExtractField, 8, 6,  // Inst{13-8} ...
/* 5066 */    MCD_OPC_FilterValue, 0, 16, 0, // Skip to: 5086
/* 5070 */    MCD_OPC_CheckField, 29, 1, 0, 225, 2, // Skip to: 5813
/* 5076 */    MCD_OPC_CheckField, 5, 3, 0, 219, 2, // Skip to: 5813
/* 5082 */    MCD_OPC_Decode, 186, 3, 58, // Opcode: TICCrr
/* 5086 */    MCD_OPC_FilterValue, 16, 16, 0, // Skip to: 5106
/* 5090 */    MCD_OPC_CheckField, 29, 1, 0, 205, 2, // Skip to: 5813
/* 5096 */    MCD_OPC_CheckField, 5, 3, 0, 199, 2, // Skip to: 5813
/* 5102 */    MCD_OPC_Decode, 197, 3, 58, // Opcode: TXCCrr
/* 5106 */    MCD_OPC_FilterValue, 32, 54, 0, // Skip to: 5164
/* 5110 */    MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 5113 */    MCD_OPC_FilterValue, 0, 184, 2, // Skip to: 5813
/* 5117 */    MCD_OPC_ExtractField, 0, 8,  // Inst{7-0} ...
/* 5120 */    MCD_OPC_FilterValue, 3, 16, 0, // Skip to: 5140
/* 5124 */    MCD_OPC_CheckField, 25, 4, 0, 30, 0, // Skip to: 5160
/* 5130 */    MCD_OPC_CheckField, 14, 5, 1, 24, 0, // Skip to: 5160
/* 5136 */    MCD_OPC_Decode, 179, 3, 4, // Opcode: TA3
/* 5140 */    MCD_OPC_FilterValue, 5, 16, 0, // Skip to: 5160
/* 5144 */    MCD_OPC_CheckField, 25, 4, 8, 10, 0, // Skip to: 5160
/* 5150 */    MCD_OPC_CheckField, 14, 5, 0, 4, 0, // Skip to: 5160
/* 5156 */    MCD_OPC_Decode, 180, 3, 4, // Opcode: TA5
/* 5160 */    MCD_OPC_Decode, 185, 3, 59, // Opcode: TICCri
/* 5164 */    MCD_OPC_FilterValue, 48, 133, 2, // Skip to: 5813
/* 5168 */    MCD_OPC_CheckField, 29, 1, 0, 127, 2, // Skip to: 5813
/* 5174 */    MCD_OPC_Decode, 196, 3, 59, // Opcode: TXCCri
/* 5178 */    MCD_OPC_FilterValue, 60, 25, 0, // Skip to: 5207
/* 5182 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5185 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5199
/* 5189 */    MCD_OPC_CheckField, 5, 8, 0, 106, 2, // Skip to: 5813
/* 5195 */    MCD_OPC_Decode, 245, 2, 8, // Opcode: SAVErr
/* 5199 */    MCD_OPC_FilterValue, 1, 98, 2, // Skip to: 5813
/* 5203 */    MCD_OPC_Decode, 244, 2, 9, // Opcode: SAVEri
/* 5207 */    MCD_OPC_FilterValue, 61, 90, 2, // Skip to: 5813
/* 5211 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5214 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5228
/* 5218 */    MCD_OPC_CheckField, 5, 8, 0, 77, 2, // Skip to: 5813
/* 5224 */    MCD_OPC_Decode, 239, 2, 8, // Opcode: RESTORErr
/* 5228 */    MCD_OPC_FilterValue, 1, 69, 2, // Skip to: 5813
/* 5232 */    MCD_OPC_Decode, 238, 2, 9, // Opcode: RESTOREri
/* 5236 */    MCD_OPC_FilterValue, 3, 61, 2, // Skip to: 5813
/* 5240 */    MCD_OPC_ExtractField, 19, 6,  // Inst{24-19} ...
/* 5243 */    MCD_OPC_FilterValue, 0, 25, 0, // Skip to: 5272
/* 5247 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5250 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5264
/* 5254 */    MCD_OPC_CheckField, 5, 8, 0, 41, 2, // Skip to: 5813
/* 5260 */    MCD_OPC_Decode, 192, 2, 60, // Opcode: LDrr
/* 5264 */    MCD_OPC_FilterValue, 1, 33, 2, // Skip to: 5813
/* 5268 */    MCD_OPC_Decode, 191, 2, 60, // Opcode: LDri
/* 5272 */    MCD_OPC_FilterValue, 1, 25, 0, // Skip to: 5301
/* 5276 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5279 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5293
/* 5283 */    MCD_OPC_CheckField, 5, 8, 0, 12, 2, // Skip to: 5813
/* 5289 */    MCD_OPC_Decode, 186, 2, 60, // Opcode: LDUBrr
/* 5293 */    MCD_OPC_FilterValue, 1, 4, 2, // Skip to: 5813
/* 5297 */    MCD_OPC_Decode, 185, 2, 60, // Opcode: LDUBri
/* 5301 */    MCD_OPC_FilterValue, 2, 25, 0, // Skip to: 5330
/* 5305 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5308 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5322
/* 5312 */    MCD_OPC_CheckField, 5, 8, 0, 239, 1, // Skip to: 5813
/* 5318 */    MCD_OPC_Decode, 188, 2, 60, // Opcode: LDUHrr
/* 5322 */    MCD_OPC_FilterValue, 1, 231, 1, // Skip to: 5813
/* 5326 */    MCD_OPC_Decode, 187, 2, 60, // Opcode: LDUHri
/* 5330 */    MCD_OPC_FilterValue, 4, 25, 0, // Skip to: 5359
/* 5334 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5337 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5351
/* 5341 */    MCD_OPC_CheckField, 5, 8, 0, 210, 1, // Skip to: 5813
/* 5347 */    MCD_OPC_Decode, 166, 3, 61, // Opcode: STrr
/* 5351 */    MCD_OPC_FilterValue, 1, 202, 1, // Skip to: 5813
/* 5355 */    MCD_OPC_Decode, 165, 3, 61, // Opcode: STri
/* 5359 */    MCD_OPC_FilterValue, 5, 25, 0, // Skip to: 5388
/* 5363 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5366 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5380
/* 5370 */    MCD_OPC_CheckField, 5, 8, 0, 181, 1, // Skip to: 5813
/* 5376 */    MCD_OPC_Decode, 154, 3, 61, // Opcode: STBrr
/* 5380 */    MCD_OPC_FilterValue, 1, 173, 1, // Skip to: 5813
/* 5384 */    MCD_OPC_Decode, 153, 3, 61, // Opcode: STBri
/* 5388 */    MCD_OPC_FilterValue, 6, 25, 0, // Skip to: 5417
/* 5392 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5395 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5409
/* 5399 */    MCD_OPC_CheckField, 5, 8, 0, 152, 1, // Skip to: 5813
/* 5405 */    MCD_OPC_Decode, 160, 3, 61, // Opcode: STHrr
/* 5409 */    MCD_OPC_FilterValue, 1, 144, 1, // Skip to: 5813
/* 5413 */    MCD_OPC_Decode, 159, 3, 61, // Opcode: STHri
/* 5417 */    MCD_OPC_FilterValue, 8, 25, 0, // Skip to: 5446
/* 5421 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5424 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5438
/* 5428 */    MCD_OPC_CheckField, 5, 8, 0, 123, 1, // Skip to: 5813
/* 5434 */    MCD_OPC_Decode, 184, 2, 60, // Opcode: LDSWrr
/* 5438 */    MCD_OPC_FilterValue, 1, 115, 1, // Skip to: 5813
/* 5442 */    MCD_OPC_Decode, 183, 2, 60, // Opcode: LDSWri
/* 5446 */    MCD_OPC_FilterValue, 9, 25, 0, // Skip to: 5475
/* 5450 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5453 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5467
/* 5457 */    MCD_OPC_CheckField, 5, 8, 0, 94, 1, // Skip to: 5813
/* 5463 */    MCD_OPC_Decode, 180, 2, 60, // Opcode: LDSBrr
/* 5467 */    MCD_OPC_FilterValue, 1, 86, 1, // Skip to: 5813
/* 5471 */    MCD_OPC_Decode, 179, 2, 60, // Opcode: LDSBri
/* 5475 */    MCD_OPC_FilterValue, 10, 25, 0, // Skip to: 5504
/* 5479 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5482 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5496
/* 5486 */    MCD_OPC_CheckField, 5, 8, 0, 65, 1, // Skip to: 5813
/* 5492 */    MCD_OPC_Decode, 182, 2, 60, // Opcode: LDSHrr
/* 5496 */    MCD_OPC_FilterValue, 1, 57, 1, // Skip to: 5813
/* 5500 */    MCD_OPC_Decode, 181, 2, 60, // Opcode: LDSHri
/* 5504 */    MCD_OPC_FilterValue, 11, 25, 0, // Skip to: 5533
/* 5508 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5511 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5525
/* 5515 */    MCD_OPC_CheckField, 5, 8, 0, 36, 1, // Skip to: 5813
/* 5521 */    MCD_OPC_Decode, 190, 2, 60, // Opcode: LDXrr
/* 5525 */    MCD_OPC_FilterValue, 1, 28, 1, // Skip to: 5813
/* 5529 */    MCD_OPC_Decode, 189, 2, 60, // Opcode: LDXri
/* 5533 */    MCD_OPC_FilterValue, 14, 25, 0, // Skip to: 5562
/* 5537 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5540 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5554
/* 5544 */    MCD_OPC_CheckField, 5, 8, 0, 7, 1, // Skip to: 5813
/* 5550 */    MCD_OPC_Decode, 164, 3, 61, // Opcode: STXrr
/* 5554 */    MCD_OPC_FilterValue, 1, 255, 0, // Skip to: 5813
/* 5558 */    MCD_OPC_Decode, 163, 3, 61, // Opcode: STXri
/* 5562 */    MCD_OPC_FilterValue, 15, 25, 0, // Skip to: 5591
/* 5566 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5569 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5583
/* 5573 */    MCD_OPC_CheckField, 5, 8, 0, 234, 0, // Skip to: 5813
/* 5579 */    MCD_OPC_Decode, 178, 3, 62, // Opcode: SWAPrr
/* 5583 */    MCD_OPC_FilterValue, 1, 226, 0, // Skip to: 5813
/* 5587 */    MCD_OPC_Decode, 177, 3, 62, // Opcode: SWAPri
/* 5591 */    MCD_OPC_FilterValue, 32, 25, 0, // Skip to: 5620
/* 5595 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5598 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5612
/* 5602 */    MCD_OPC_CheckField, 5, 8, 0, 205, 0, // Skip to: 5813
/* 5608 */    MCD_OPC_Decode, 176, 2, 63, // Opcode: LDFrr
/* 5612 */    MCD_OPC_FilterValue, 1, 197, 0, // Skip to: 5813
/* 5616 */    MCD_OPC_Decode, 175, 2, 63, // Opcode: LDFri
/* 5620 */    MCD_OPC_FilterValue, 34, 33, 0, // Skip to: 5657
/* 5624 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5627 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 5645
/* 5631 */    MCD_OPC_CheckPredicate, 0, 178, 0, // Skip to: 5813
/* 5635 */    MCD_OPC_CheckField, 5, 8, 0, 172, 0, // Skip to: 5813
/* 5641 */    MCD_OPC_Decode, 178, 2, 64, // Opcode: LDQFrr
/* 5645 */    MCD_OPC_FilterValue, 1, 164, 0, // Skip to: 5813
/* 5649 */    MCD_OPC_CheckPredicate, 0, 160, 0, // Skip to: 5813
/* 5653 */    MCD_OPC_Decode, 177, 2, 64, // Opcode: LDQFri
/* 5657 */    MCD_OPC_FilterValue, 35, 25, 0, // Skip to: 5686
/* 5661 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5664 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5678
/* 5668 */    MCD_OPC_CheckField, 5, 8, 0, 139, 0, // Skip to: 5813
/* 5674 */    MCD_OPC_Decode, 174, 2, 65, // Opcode: LDDFrr
/* 5678 */    MCD_OPC_FilterValue, 1, 131, 0, // Skip to: 5813
/* 5682 */    MCD_OPC_Decode, 173, 2, 65, // Opcode: LDDFri
/* 5686 */    MCD_OPC_FilterValue, 36, 25, 0, // Skip to: 5715
/* 5690 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5693 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5707
/* 5697 */    MCD_OPC_CheckField, 5, 8, 0, 110, 0, // Skip to: 5813
/* 5703 */    MCD_OPC_Decode, 158, 3, 66, // Opcode: STFrr
/* 5707 */    MCD_OPC_FilterValue, 1, 102, 0, // Skip to: 5813
/* 5711 */    MCD_OPC_Decode, 157, 3, 66, // Opcode: STFri
/* 5715 */    MCD_OPC_FilterValue, 38, 33, 0, // Skip to: 5752
/* 5719 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5722 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 5740
/* 5726 */    MCD_OPC_CheckPredicate, 0, 83, 0, // Skip to: 5813
/* 5730 */    MCD_OPC_CheckField, 5, 8, 0, 77, 0, // Skip to: 5813
/* 5736 */    MCD_OPC_Decode, 162, 3, 67, // Opcode: STQFrr
/* 5740 */    MCD_OPC_FilterValue, 1, 69, 0, // Skip to: 5813
/* 5744 */    MCD_OPC_CheckPredicate, 0, 65, 0, // Skip to: 5813
/* 5748 */    MCD_OPC_Decode, 161, 3, 67, // Opcode: STQFri
/* 5752 */    MCD_OPC_FilterValue, 39, 25, 0, // Skip to: 5781
/* 5756 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 5759 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5773
/* 5763 */    MCD_OPC_CheckField, 5, 8, 0, 44, 0, // Skip to: 5813
/* 5769 */    MCD_OPC_Decode, 156, 3, 68, // Opcode: STDFrr
/* 5773 */    MCD_OPC_FilterValue, 1, 36, 0, // Skip to: 5813
/* 5777 */    MCD_OPC_Decode, 155, 3, 68, // Opcode: STDFri
/* 5781 */    MCD_OPC_FilterValue, 60, 14, 0, // Skip to: 5799
/* 5785 */    MCD_OPC_CheckPredicate, 0, 24, 0, // Skip to: 5813
/* 5789 */    MCD_OPC_CheckField, 5, 9, 128, 1, 17, 0, // Skip to: 5813
/* 5796 */    MCD_OPC_Decode, 118, 69, // Opcode: CASrr
/* 5799 */    MCD_OPC_FilterValue, 62, 10, 0, // Skip to: 5813
/* 5803 */    MCD_OPC_CheckField, 5, 9, 128, 1, 3, 0, // Skip to: 5813
/* 5810 */    MCD_OPC_Decode, 117, 70, // Opcode: CASXrr
/* 5813 */    MCD_OPC_Fail,
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
    return getbool(Bits & Sparc_FeatureV9);
  case 1:
    return getbool(Bits & Sparc_FeatureVIS3);
  case 2:
    return getbool(Bits & Sparc_FeatureVIS);
  case 3:
    return getbool(Bits & Sparc_FeatureVIS2);
  }
}

#define DecodeToMCInst(fname,fieldname, InsnType) \
static DecodeStatus fname(DecodeStatus S, unsigned Idx, InsnType insn, MCInst *MI, \
                uint64_t Address, const void *Decoder) \
{ \
  InsnType tmp; \
  switch (Idx) { \
  default: \
  case 0: \
    tmp = fieldname(insn, 0, 22); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 1: \
    tmp = fieldname(insn, 0, 19); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 2: \
    tmp = fieldname(insn, 0, 22); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 3: \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 0, 14) << 0); \
    tmp |= (fieldname(insn, 20, 2) << 14); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 4: \
    return S; \
  case 5: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 22); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 6: \
    tmp = fieldname(insn, 0, 19); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 20, 2); \
    if (DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 7: \
    tmp = fieldname(insn, 0, 30); \
    if (DecodeCall(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 8: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 9: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 13); \
    if (DecodeSIMM13(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 10: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 11: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 13); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 12: \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 13: \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 13); \
    if (DecodeSIMM13(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 14: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 15: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 6); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 16: \
    tmp = fieldname(insn, 0, 13); \
    if (DecodeSIMM13(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 17: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 18: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 19: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 11); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 20: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 11); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 21: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 22: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 23: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 24: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 25: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 26: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 27: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 28: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 29: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 30: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 31: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 32: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 33: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 34: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 35: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 36: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 37: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 38: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 39: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 40: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 41: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 42: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 43: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 44: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 45: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 46: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 47: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 48: \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 49: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 50: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 51: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 52: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 53: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 54: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 55: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 56: \
    if (DecodeJMPL(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 57: \
    if (DecodeReturn(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 58: \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 25, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 59: \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 25, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 60: \
    if (DecodeLoadInt(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 61: \
    if (DecodeStoreInt(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 62: \
    if (DecodeSWAP(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 63: \
    if (DecodeLoadFP(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 64: \
    if (DecodeLoadQFP(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 65: \
    if (DecodeLoadDFP(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 66: \
    if (DecodeStoreFP(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 67: \
    if (DecodeStoreQFP(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 68: \
    if (DecodeStoreDFP(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 69: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 70: \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 14, 5); \
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 25, 5); \
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  } \
} 

#define DecodeInstruction(fname, fieldname, decoder, InsnType) \
static DecodeStatus fname(const uint8_t DecodeTable[], MCInst *MI, \
           InsnType insn, uint64_t Address, const MCRegisterInfo *MRI, int feature) \
{ \
  uint64_t Bits = getFeatureBits(feature); \
  const uint8_t *Ptr = DecodeTable; \
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

FieldFromInstruction(fieldFromInstruction_4, uint32_t)
DecodeToMCInst(decodeToMCInst_4, fieldFromInstruction_4, uint32_t)
DecodeInstruction(decodeInstruction_4, fieldFromInstruction_4, decodeToMCInst_4, uint32_t)
