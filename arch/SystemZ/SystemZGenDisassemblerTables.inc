/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* * SystemZ Disassembler                                                     *|
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

static uint8_t DecoderTable16[] = {
/* 0 */       MCD_OPC_ExtractField, 8, 8,  // Inst{15-8} ...
/* 3 */       MCD_OPC_FilterValue, 7, 127, 0, // Skip to: 134
/* 7 */       MCD_OPC_ExtractField, 4, 4,  // Inst{7-4} ...
/* 10 */      MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 18
/* 14 */      MCD_OPC_Decode, 241, 2, 0, // Opcode: AsmOBR
/* 18 */      MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 26
/* 22 */      MCD_OPC_Decode, 161, 1, 0, // Opcode: AsmHBR
/* 26 */      MCD_OPC_FilterValue, 3, 4, 0, // Skip to: 34
/* 30 */      MCD_OPC_Decode, 206, 2, 0, // Opcode: AsmNLEBR
/* 34 */      MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 42
/* 38 */      MCD_OPC_Decode, 147, 2, 0, // Opcode: AsmLBR
/* 42 */      MCD_OPC_FilterValue, 5, 4, 0, // Skip to: 50
/* 46 */      MCD_OPC_Decode, 188, 2, 0, // Opcode: AsmNHEBR
/* 50 */      MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 58
/* 54 */      MCD_OPC_Decode, 157, 2, 0, // Opcode: AsmLHBR
/* 58 */      MCD_OPC_FilterValue, 7, 4, 0, // Skip to: 66
/* 62 */      MCD_OPC_Decode, 178, 2, 0, // Opcode: AsmNEBR
/* 66 */      MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 74
/* 70 */      MCD_OPC_Decode, 152, 1, 0, // Opcode: AsmEBR
/* 74 */      MCD_OPC_FilterValue, 9, 4, 0, // Skip to: 82
/* 78 */      MCD_OPC_Decode, 215, 2, 0, // Opcode: AsmNLHBR
/* 82 */      MCD_OPC_FilterValue, 10, 4, 0, // Skip to: 90
/* 86 */      MCD_OPC_Decode, 162, 1, 0, // Opcode: AsmHEBR
/* 90 */      MCD_OPC_FilterValue, 11, 4, 0, // Skip to: 98
/* 94 */      MCD_OPC_Decode, 205, 2, 0, // Opcode: AsmNLBR
/* 98 */      MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 106
/* 102 */     MCD_OPC_Decode, 148, 2, 0, // Opcode: AsmLEBR
/* 106 */     MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 114
/* 110 */     MCD_OPC_Decode, 187, 2, 0, // Opcode: AsmNHBR
/* 114 */     MCD_OPC_FilterValue, 14, 4, 0, // Skip to: 122
/* 118 */     MCD_OPC_Decode, 232, 2, 0, // Opcode: AsmNOBR
/* 122 */     MCD_OPC_FilterValue, 15, 4, 0, // Skip to: 130
/* 126 */     MCD_OPC_Decode, 253, 2, 0, // Opcode: BR
/* 130 */     MCD_OPC_Decode, 141, 1, 1, // Opcode: AsmBCR
/* 134 */     MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 142
/* 138 */     MCD_OPC_Decode, 252, 2, 2, // Opcode: BASR
/* 142 */     MCD_OPC_FilterValue, 16, 4, 0, // Skip to: 150
/* 146 */     MCD_OPC_Decode, 138, 5, 3, // Opcode: LPR
/* 150 */     MCD_OPC_FilterValue, 17, 4, 0, // Skip to: 158
/* 154 */     MCD_OPC_Decode, 128, 5, 3, // Opcode: LNR
/* 158 */     MCD_OPC_FilterValue, 18, 4, 0, // Skip to: 166
/* 162 */     MCD_OPC_Decode, 156, 5, 3, // Opcode: LTR
/* 166 */     MCD_OPC_FilterValue, 19, 4, 0, // Skip to: 174
/* 170 */     MCD_OPC_Decode, 188, 4, 3, // Opcode: LCR
/* 174 */     MCD_OPC_FilterValue, 20, 4, 0, // Skip to: 182
/* 178 */     MCD_OPC_Decode, 235, 5, 4, // Opcode: NR
/* 182 */     MCD_OPC_FilterValue, 21, 4, 0, // Skip to: 190
/* 186 */     MCD_OPC_Decode, 207, 3, 3, // Opcode: CLR
/* 190 */     MCD_OPC_FilterValue, 22, 4, 0, // Skip to: 198
/* 194 */     MCD_OPC_Decode, 134, 6, 4, // Opcode: OR
/* 198 */     MCD_OPC_FilterValue, 23, 4, 0, // Skip to: 206
/* 202 */     MCD_OPC_Decode, 133, 7, 4, // Opcode: XR
/* 206 */     MCD_OPC_FilterValue, 24, 4, 0, // Skip to: 214
/* 210 */     MCD_OPC_Decode, 140, 5, 3, // Opcode: LR
/* 214 */     MCD_OPC_FilterValue, 25, 4, 0, // Skip to: 222
/* 218 */     MCD_OPC_Decode, 218, 3, 3, // Opcode: CR
/* 222 */     MCD_OPC_FilterValue, 26, 3, 0, // Skip to: 229
/* 226 */     MCD_OPC_Decode, 63, 4, // Opcode: AR
/* 229 */     MCD_OPC_FilterValue, 27, 4, 0, // Skip to: 237
/* 233 */     MCD_OPC_Decode, 189, 6, 4, // Opcode: SR
/* 237 */     MCD_OPC_FilterValue, 30, 3, 0, // Skip to: 244
/* 241 */     MCD_OPC_Decode, 60, 4, // Opcode: ALR
/* 244 */     MCD_OPC_FilterValue, 31, 4, 0, // Skip to: 252
/* 248 */     MCD_OPC_Decode, 181, 6, 4, // Opcode: SLR
/* 252 */     MCD_OPC_FilterValue, 40, 4, 0, // Skip to: 260
/* 256 */     MCD_OPC_Decode, 194, 4, 5, // Opcode: LDR
/* 260 */     MCD_OPC_FilterValue, 56, 4, 0, // Skip to: 268
/* 264 */     MCD_OPC_Decode, 199, 4, 6, // Opcode: LER
/* 268 */     MCD_OPC_Fail,
  0
};

static uint8_t DecoderTable32[] = {
/* 0 */       MCD_OPC_ExtractField, 24, 8,  // Inst{31-24} ...
/* 3 */       MCD_OPC_FilterValue, 64, 4, 0, // Skip to: 11
/* 7 */       MCD_OPC_Decode, 212, 6, 7, // Opcode: STH
/* 11 */      MCD_OPC_FilterValue, 65, 4, 0, // Skip to: 19
/* 15 */      MCD_OPC_Decode, 167, 4, 8, // Opcode: LA
/* 19 */      MCD_OPC_FilterValue, 66, 4, 0, // Skip to: 27
/* 23 */      MCD_OPC_Decode, 201, 6, 7, // Opcode: STC
/* 27 */      MCD_OPC_FilterValue, 67, 4, 0, // Skip to: 35
/* 31 */      MCD_OPC_Decode, 143, 4, 9, // Opcode: IC
/* 35 */      MCD_OPC_FilterValue, 72, 4, 0, // Skip to: 43
/* 39 */      MCD_OPC_Decode, 217, 4, 7, // Opcode: LH
/* 43 */      MCD_OPC_FilterValue, 73, 4, 0, // Skip to: 51
/* 47 */      MCD_OPC_Decode, 166, 3, 7, // Opcode: CH
/* 51 */      MCD_OPC_FilterValue, 74, 3, 0, // Skip to: 58
/* 55 */      MCD_OPC_Decode, 39, 10, // Opcode: AH
/* 58 */      MCD_OPC_FilterValue, 75, 4, 0, // Skip to: 66
/* 62 */      MCD_OPC_Decode, 164, 6, 10, // Opcode: SH
/* 66 */      MCD_OPC_FilterValue, 76, 4, 0, // Skip to: 74
/* 70 */      MCD_OPC_Decode, 180, 5, 10, // Opcode: MH
/* 74 */      MCD_OPC_FilterValue, 80, 4, 0, // Skip to: 82
/* 78 */      MCD_OPC_Decode, 199, 6, 7, // Opcode: ST
/* 82 */      MCD_OPC_FilterValue, 84, 4, 0, // Skip to: 90
/* 86 */      MCD_OPC_Decode, 211, 5, 10, // Opcode: N
/* 90 */      MCD_OPC_FilterValue, 85, 4, 0, // Skip to: 98
/* 94 */      MCD_OPC_Decode, 175, 3, 7, // Opcode: CL
/* 98 */      MCD_OPC_FilterValue, 86, 4, 0, // Skip to: 106
/* 102 */     MCD_OPC_Decode, 238, 5, 10, // Opcode: O
/* 106 */     MCD_OPC_FilterValue, 87, 4, 0, // Skip to: 114
/* 110 */     MCD_OPC_Decode, 247, 6, 10, // Opcode: X
/* 114 */     MCD_OPC_FilterValue, 88, 4, 0, // Skip to: 122
/* 118 */     MCD_OPC_Decode, 165, 4, 7, // Opcode: L
/* 122 */     MCD_OPC_FilterValue, 89, 4, 0, // Skip to: 130
/* 126 */     MCD_OPC_Decode, 132, 3, 7, // Opcode: C
/* 130 */     MCD_OPC_FilterValue, 90, 3, 0, // Skip to: 137
/* 134 */     MCD_OPC_Decode, 19, 10, // Opcode: A
/* 137 */     MCD_OPC_FilterValue, 91, 4, 0, // Skip to: 145
/* 141 */     MCD_OPC_Decode, 154, 6, 10, // Opcode: S
/* 145 */     MCD_OPC_FilterValue, 94, 3, 0, // Skip to: 152
/* 149 */     MCD_OPC_Decode, 46, 10, // Opcode: AL
/* 152 */     MCD_OPC_FilterValue, 95, 4, 0, // Skip to: 160
/* 156 */     MCD_OPC_Decode, 166, 6, 10, // Opcode: SL
/* 160 */     MCD_OPC_FilterValue, 96, 4, 0, // Skip to: 168
/* 164 */     MCD_OPC_Decode, 205, 6, 11, // Opcode: STD
/* 168 */     MCD_OPC_FilterValue, 104, 4, 0, // Skip to: 176
/* 172 */     MCD_OPC_Decode, 190, 4, 11, // Opcode: LD
/* 176 */     MCD_OPC_FilterValue, 112, 4, 0, // Skip to: 184
/* 180 */     MCD_OPC_Decode, 207, 6, 12, // Opcode: STE
/* 184 */     MCD_OPC_FilterValue, 113, 4, 0, // Skip to: 192
/* 188 */     MCD_OPC_Decode, 185, 5, 10, // Opcode: MS
/* 192 */     MCD_OPC_FilterValue, 120, 4, 0, // Skip to: 200
/* 196 */     MCD_OPC_Decode, 197, 4, 12, // Opcode: LE
/* 200 */     MCD_OPC_FilterValue, 136, 1, 10, 0, // Skip to: 215
/* 205 */     MCD_OPC_CheckField, 16, 4, 0, 194, 11, // Skip to: 3221
/* 211 */     MCD_OPC_Decode, 194, 6, 13, // Opcode: SRL
/* 215 */     MCD_OPC_FilterValue, 137, 1, 10, 0, // Skip to: 230
/* 220 */     MCD_OPC_CheckField, 16, 4, 0, 179, 11, // Skip to: 3221
/* 226 */     MCD_OPC_Decode, 178, 6, 13, // Opcode: SLL
/* 230 */     MCD_OPC_FilterValue, 138, 1, 10, 0, // Skip to: 245
/* 235 */     MCD_OPC_CheckField, 16, 4, 0, 164, 11, // Skip to: 3221
/* 241 */     MCD_OPC_Decode, 190, 6, 13, // Opcode: SRA
/* 245 */     MCD_OPC_FilterValue, 145, 1, 4, 0, // Skip to: 254
/* 250 */     MCD_OPC_Decode, 235, 6, 14, // Opcode: TM
/* 254 */     MCD_OPC_FilterValue, 146, 1, 4, 0, // Skip to: 263
/* 259 */     MCD_OPC_Decode, 204, 5, 14, // Opcode: MVI
/* 263 */     MCD_OPC_FilterValue, 148, 1, 4, 0, // Skip to: 272
/* 268 */     MCD_OPC_Decode, 218, 5, 14, // Opcode: NI
/* 272 */     MCD_OPC_FilterValue, 149, 1, 4, 0, // Skip to: 281
/* 277 */     MCD_OPC_Decode, 202, 3, 14, // Opcode: CLI
/* 281 */     MCD_OPC_FilterValue, 150, 1, 4, 0, // Skip to: 290
/* 286 */     MCD_OPC_Decode, 245, 5, 14, // Opcode: OI
/* 290 */     MCD_OPC_FilterValue, 151, 1, 4, 0, // Skip to: 299
/* 295 */     MCD_OPC_Decode, 254, 6, 14, // Opcode: XI
/* 299 */     MCD_OPC_FilterValue, 165, 1, 131, 0, // Skip to: 435
/* 304 */     MCD_OPC_ExtractField, 16, 4,  // Inst{19-16} ...
/* 307 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 315
/* 311 */     MCD_OPC_Decode, 150, 4, 15, // Opcode: IIHH
/* 315 */     MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 323
/* 319 */     MCD_OPC_Decode, 152, 4, 15, // Opcode: IIHL
/* 323 */     MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 331
/* 327 */     MCD_OPC_Decode, 157, 4, 16, // Opcode: IILH
/* 331 */     MCD_OPC_FilterValue, 3, 4, 0, // Skip to: 339
/* 335 */     MCD_OPC_Decode, 159, 4, 16, // Opcode: IILL
/* 339 */     MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 347
/* 343 */     MCD_OPC_Decode, 222, 5, 15, // Opcode: NIHH
/* 347 */     MCD_OPC_FilterValue, 5, 4, 0, // Skip to: 355
/* 351 */     MCD_OPC_Decode, 224, 5, 15, // Opcode: NIHL
/* 355 */     MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 363
/* 359 */     MCD_OPC_Decode, 229, 5, 16, // Opcode: NILH
/* 363 */     MCD_OPC_FilterValue, 7, 4, 0, // Skip to: 371
/* 367 */     MCD_OPC_Decode, 231, 5, 16, // Opcode: NILL
/* 371 */     MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 379
/* 375 */     MCD_OPC_Decode, 249, 5, 15, // Opcode: OIHH
/* 379 */     MCD_OPC_FilterValue, 9, 4, 0, // Skip to: 387
/* 383 */     MCD_OPC_Decode, 251, 5, 15, // Opcode: OIHL
/* 387 */     MCD_OPC_FilterValue, 10, 4, 0, // Skip to: 395
/* 391 */     MCD_OPC_Decode, 128, 6, 16, // Opcode: OILH
/* 395 */     MCD_OPC_FilterValue, 11, 4, 0, // Skip to: 403
/* 399 */     MCD_OPC_Decode, 130, 6, 16, // Opcode: OILL
/* 403 */     MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 411
/* 407 */     MCD_OPC_Decode, 245, 4, 17, // Opcode: LLIHH
/* 411 */     MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 419
/* 415 */     MCD_OPC_Decode, 246, 4, 17, // Opcode: LLIHL
/* 419 */     MCD_OPC_FilterValue, 14, 4, 0, // Skip to: 427
/* 423 */     MCD_OPC_Decode, 248, 4, 17, // Opcode: LLILH
/* 427 */     MCD_OPC_FilterValue, 15, 230, 10, // Skip to: 3221
/* 431 */     MCD_OPC_Decode, 249, 4, 17, // Opcode: LLILL
/* 435 */     MCD_OPC_FilterValue, 167, 1, 252, 0, // Skip to: 692
/* 440 */     MCD_OPC_ExtractField, 16, 4,  // Inst{19-16} ...
/* 443 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 451
/* 447 */     MCD_OPC_Decode, 241, 6, 18, // Opcode: TMLH
/* 451 */     MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 459
/* 455 */     MCD_OPC_Decode, 243, 6, 18, // Opcode: TMLL
/* 459 */     MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 467
/* 463 */     MCD_OPC_Decode, 236, 6, 19, // Opcode: TMHH
/* 467 */     MCD_OPC_FilterValue, 3, 4, 0, // Skip to: 475
/* 471 */     MCD_OPC_Decode, 238, 6, 19, // Opcode: TMHL
/* 475 */     MCD_OPC_FilterValue, 4, 127, 0, // Skip to: 606
/* 479 */     MCD_OPC_ExtractField, 20, 4,  // Inst{23-20} ...
/* 482 */     MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 490
/* 486 */     MCD_OPC_Decode, 242, 2, 20, // Opcode: AsmOJ
/* 490 */     MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 498
/* 494 */     MCD_OPC_Decode, 171, 1, 20, // Opcode: AsmHJ
/* 498 */     MCD_OPC_FilterValue, 3, 4, 0, // Skip to: 506
/* 502 */     MCD_OPC_Decode, 207, 2, 20, // Opcode: AsmNLEJ
/* 506 */     MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 514
/* 510 */     MCD_OPC_Decode, 166, 2, 20, // Opcode: AsmLJ
/* 514 */     MCD_OPC_FilterValue, 5, 4, 0, // Skip to: 522
/* 518 */     MCD_OPC_Decode, 189, 2, 20, // Opcode: AsmNHEJ
/* 522 */     MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 530
/* 526 */     MCD_OPC_Decode, 158, 2, 20, // Opcode: AsmLHJ
/* 530 */     MCD_OPC_FilterValue, 7, 4, 0, // Skip to: 538
/* 534 */     MCD_OPC_Decode, 179, 2, 20, // Opcode: AsmNEJ
/* 538 */     MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 546
/* 542 */     MCD_OPC_Decode, 153, 1, 20, // Opcode: AsmEJ
/* 546 */     MCD_OPC_FilterValue, 9, 4, 0, // Skip to: 554
/* 550 */     MCD_OPC_Decode, 216, 2, 20, // Opcode: AsmNLHJ
/* 554 */     MCD_OPC_FilterValue, 10, 4, 0, // Skip to: 562
/* 558 */     MCD_OPC_Decode, 163, 1, 20, // Opcode: AsmHEJ
/* 562 */     MCD_OPC_FilterValue, 11, 4, 0, // Skip to: 570
/* 566 */     MCD_OPC_Decode, 224, 2, 20, // Opcode: AsmNLJ
/* 570 */     MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 578
/* 574 */     MCD_OPC_Decode, 149, 2, 20, // Opcode: AsmLEJ
/* 578 */     MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 586
/* 582 */     MCD_OPC_Decode, 197, 2, 20, // Opcode: AsmNHJ
/* 586 */     MCD_OPC_FilterValue, 14, 4, 0, // Skip to: 594
/* 590 */     MCD_OPC_Decode, 233, 2, 20, // Opcode: AsmNOJ
/* 594 */     MCD_OPC_FilterValue, 15, 4, 0, // Skip to: 602
/* 598 */     MCD_OPC_Decode, 163, 4, 20, // Opcode: J
/* 602 */     MCD_OPC_Decode, 142, 1, 21, // Opcode: AsmBRC
/* 606 */     MCD_OPC_FilterValue, 5, 4, 0, // Skip to: 614
/* 610 */     MCD_OPC_Decode, 254, 2, 22, // Opcode: BRAS
/* 614 */     MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 622
/* 618 */     MCD_OPC_Decode, 130, 3, 23, // Opcode: BRCT
/* 622 */     MCD_OPC_FilterValue, 7, 4, 0, // Skip to: 630
/* 626 */     MCD_OPC_Decode, 131, 3, 24, // Opcode: BRCTG
/* 630 */     MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 638
/* 634 */     MCD_OPC_Decode, 219, 4, 25, // Opcode: LHI
/* 638 */     MCD_OPC_FilterValue, 9, 4, 0, // Skip to: 646
/* 642 */     MCD_OPC_Decode, 212, 4, 26, // Opcode: LGHI
/* 646 */     MCD_OPC_FilterValue, 10, 3, 0, // Skip to: 653
/* 650 */     MCD_OPC_Decode, 40, 27, // Opcode: AHI
/* 653 */     MCD_OPC_FilterValue, 11, 3, 0, // Skip to: 660
/* 657 */     MCD_OPC_Decode, 34, 28, // Opcode: AGHI
/* 660 */     MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 668
/* 664 */     MCD_OPC_Decode, 181, 5, 27, // Opcode: MHI
/* 668 */     MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 676
/* 672 */     MCD_OPC_Decode, 179, 5, 28, // Opcode: MGHI
/* 676 */     MCD_OPC_FilterValue, 14, 4, 0, // Skip to: 684
/* 680 */     MCD_OPC_Decode, 169, 3, 25, // Opcode: CHI
/* 684 */     MCD_OPC_FilterValue, 15, 229, 9, // Skip to: 3221
/* 688 */     MCD_OPC_Decode, 158, 3, 26, // Opcode: CGHI
/* 692 */     MCD_OPC_FilterValue, 178, 1, 68, 0, // Skip to: 765
/* 697 */     MCD_OPC_ExtractField, 8, 16,  // Inst{23-8} ...
/* 700 */     MCD_OPC_FilterValue, 128, 68, 10, 0, // Skip to: 715
/* 705 */     MCD_OPC_CheckField, 0, 4, 0, 206, 9, // Skip to: 3221
/* 711 */     MCD_OPC_Decode, 162, 4, 29, // Opcode: IPM
/* 715 */     MCD_OPC_FilterValue, 128, 158, 1, 4, 0, // Skip to: 725
/* 721 */     MCD_OPC_Decode, 135, 4, 30, // Opcode: EAR
/* 725 */     MCD_OPC_FilterValue, 128, 164, 1, 4, 0, // Skip to: 735
/* 731 */     MCD_OPC_Decode, 196, 5, 4, // Opcode: MSR
/* 735 */     MCD_OPC_FilterValue, 128, 170, 1, 4, 0, // Skip to: 745
/* 741 */     MCD_OPC_Decode, 206, 5, 31, // Opcode: MVST
/* 745 */     MCD_OPC_FilterValue, 128, 186, 1, 4, 0, // Skip to: 755
/* 751 */     MCD_OPC_Decode, 210, 3, 31, // Opcode: CLST
/* 755 */     MCD_OPC_FilterValue, 128, 188, 1, 156, 9, // Skip to: 3221
/* 761 */     MCD_OPC_Decode, 197, 6, 31, // Opcode: SRST
/* 765 */     MCD_OPC_FilterValue, 179, 1, 85, 4, // Skip to: 1879
/* 770 */     MCD_OPC_ExtractField, 16, 8,  // Inst{23-16} ...
/* 773 */     MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 787
/* 777 */     MCD_OPC_CheckField, 8, 8, 0, 134, 9, // Skip to: 3221
/* 783 */     MCD_OPC_Decode, 135, 5, 6, // Opcode: LPEBR
/* 787 */     MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 801
/* 791 */     MCD_OPC_CheckField, 8, 8, 0, 120, 9, // Skip to: 3221
/* 797 */     MCD_OPC_Decode, 253, 4, 6, // Opcode: LNEBR
/* 801 */     MCD_OPC_FilterValue, 2, 10, 0, // Skip to: 815
/* 805 */     MCD_OPC_CheckField, 8, 8, 0, 106, 9, // Skip to: 3221
/* 811 */     MCD_OPC_Decode, 150, 5, 6, // Opcode: LTEBR
/* 815 */     MCD_OPC_FilterValue, 3, 10, 0, // Skip to: 829
/* 819 */     MCD_OPC_CheckField, 8, 8, 0, 92, 9, // Skip to: 3221
/* 825 */     MCD_OPC_Decode, 185, 4, 6, // Opcode: LCEBR
/* 829 */     MCD_OPC_FilterValue, 4, 10, 0, // Skip to: 843
/* 833 */     MCD_OPC_CheckField, 8, 8, 0, 78, 9, // Skip to: 3221
/* 839 */     MCD_OPC_Decode, 192, 4, 32, // Opcode: LDEBR
/* 843 */     MCD_OPC_FilterValue, 5, 10, 0, // Skip to: 857
/* 847 */     MCD_OPC_CheckField, 8, 8, 0, 64, 9, // Skip to: 3221
/* 853 */     MCD_OPC_Decode, 161, 5, 33, // Opcode: LXDBR
/* 857 */     MCD_OPC_FilterValue, 6, 10, 0, // Skip to: 871
/* 861 */     MCD_OPC_CheckField, 8, 8, 0, 50, 9, // Skip to: 3221
/* 867 */     MCD_OPC_Decode, 163, 5, 34, // Opcode: LXEBR
/* 871 */     MCD_OPC_FilterValue, 7, 10, 0, // Skip to: 885
/* 875 */     MCD_OPC_CheckField, 8, 8, 0, 36, 9, // Skip to: 3221
/* 881 */     MCD_OPC_Decode, 210, 5, 35, // Opcode: MXDBR
/* 885 */     MCD_OPC_FilterValue, 9, 10, 0, // Skip to: 899
/* 889 */     MCD_OPC_CheckField, 8, 8, 0, 22, 9, // Skip to: 3221
/* 895 */     MCD_OPC_Decode, 140, 3, 6, // Opcode: CEBR
/* 899 */     MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 912
/* 903 */     MCD_OPC_CheckField, 8, 8, 0, 8, 9, // Skip to: 3221
/* 909 */     MCD_OPC_Decode, 26, 36, // Opcode: AEBR
/* 912 */     MCD_OPC_FilterValue, 11, 10, 0, // Skip to: 926
/* 916 */     MCD_OPC_CheckField, 8, 8, 0, 251, 8, // Skip to: 3221
/* 922 */     MCD_OPC_Decode, 158, 6, 36, // Opcode: SEBR
/* 926 */     MCD_OPC_FilterValue, 12, 10, 0, // Skip to: 940
/* 930 */     MCD_OPC_CheckField, 8, 8, 0, 237, 8, // Skip to: 3221
/* 936 */     MCD_OPC_Decode, 176, 5, 37, // Opcode: MDEBR
/* 940 */     MCD_OPC_FilterValue, 13, 10, 0, // Skip to: 954
/* 944 */     MCD_OPC_CheckField, 8, 8, 0, 223, 8, // Skip to: 3221
/* 950 */     MCD_OPC_Decode, 253, 3, 36, // Opcode: DEBR
/* 954 */     MCD_OPC_FilterValue, 14, 10, 0, // Skip to: 968
/* 958 */     MCD_OPC_CheckField, 8, 4, 0, 209, 8, // Skip to: 3221
/* 964 */     MCD_OPC_Decode, 172, 5, 38, // Opcode: MAEBR
/* 968 */     MCD_OPC_FilterValue, 15, 10, 0, // Skip to: 982
/* 972 */     MCD_OPC_CheckField, 8, 4, 0, 195, 8, // Skip to: 3221
/* 978 */     MCD_OPC_Decode, 189, 5, 38, // Opcode: MSEBR
/* 982 */     MCD_OPC_FilterValue, 16, 10, 0, // Skip to: 996
/* 986 */     MCD_OPC_CheckField, 8, 8, 0, 181, 8, // Skip to: 3221
/* 992 */     MCD_OPC_Decode, 134, 5, 5, // Opcode: LPDBR
/* 996 */     MCD_OPC_FilterValue, 17, 10, 0, // Skip to: 1010
/* 1000 */    MCD_OPC_CheckField, 8, 8, 0, 167, 8, // Skip to: 3221
/* 1006 */    MCD_OPC_Decode, 252, 4, 5, // Opcode: LNDBR
/* 1010 */    MCD_OPC_FilterValue, 18, 10, 0, // Skip to: 1024
/* 1014 */    MCD_OPC_CheckField, 8, 8, 0, 153, 8, // Skip to: 3221
/* 1020 */    MCD_OPC_Decode, 148, 5, 5, // Opcode: LTDBR
/* 1024 */    MCD_OPC_FilterValue, 19, 10, 0, // Skip to: 1038
/* 1028 */    MCD_OPC_CheckField, 8, 8, 0, 139, 8, // Skip to: 3221
/* 1034 */    MCD_OPC_Decode, 184, 4, 5, // Opcode: LCDBR
/* 1038 */    MCD_OPC_FilterValue, 20, 10, 0, // Skip to: 1052
/* 1042 */    MCD_OPC_CheckField, 8, 8, 0, 125, 8, // Skip to: 3221
/* 1048 */    MCD_OPC_Decode, 187, 6, 6, // Opcode: SQEBR
/* 1052 */    MCD_OPC_FilterValue, 21, 10, 0, // Skip to: 1066
/* 1056 */    MCD_OPC_CheckField, 8, 8, 0, 111, 8, // Skip to: 3221
/* 1062 */    MCD_OPC_Decode, 185, 6, 5, // Opcode: SQDBR
/* 1066 */    MCD_OPC_FilterValue, 22, 10, 0, // Skip to: 1080
/* 1070 */    MCD_OPC_CheckField, 8, 8, 0, 97, 8, // Skip to: 3221
/* 1076 */    MCD_OPC_Decode, 188, 6, 39, // Opcode: SQXBR
/* 1080 */    MCD_OPC_FilterValue, 23, 10, 0, // Skip to: 1094
/* 1084 */    MCD_OPC_CheckField, 8, 8, 0, 83, 8, // Skip to: 3221
/* 1090 */    MCD_OPC_Decode, 178, 5, 36, // Opcode: MEEBR
/* 1094 */    MCD_OPC_FilterValue, 25, 10, 0, // Skip to: 1108
/* 1098 */    MCD_OPC_CheckField, 8, 8, 0, 69, 8, // Skip to: 3221
/* 1104 */    MCD_OPC_Decode, 134, 3, 5, // Opcode: CDBR
/* 1108 */    MCD_OPC_FilterValue, 26, 9, 0, // Skip to: 1121
/* 1112 */    MCD_OPC_CheckField, 8, 8, 0, 55, 8, // Skip to: 3221
/* 1118 */    MCD_OPC_Decode, 21, 40, // Opcode: ADBR
/* 1121 */    MCD_OPC_FilterValue, 27, 10, 0, // Skip to: 1135
/* 1125 */    MCD_OPC_CheckField, 8, 8, 0, 42, 8, // Skip to: 3221
/* 1131 */    MCD_OPC_Decode, 156, 6, 40, // Opcode: SDBR
/* 1135 */    MCD_OPC_FilterValue, 28, 10, 0, // Skip to: 1149
/* 1139 */    MCD_OPC_CheckField, 8, 8, 0, 28, 8, // Skip to: 3221
/* 1145 */    MCD_OPC_Decode, 174, 5, 40, // Opcode: MDBR
/* 1149 */    MCD_OPC_FilterValue, 29, 10, 0, // Skip to: 1163
/* 1153 */    MCD_OPC_CheckField, 8, 8, 0, 14, 8, // Skip to: 3221
/* 1159 */    MCD_OPC_Decode, 251, 3, 40, // Opcode: DDBR
/* 1163 */    MCD_OPC_FilterValue, 30, 10, 0, // Skip to: 1177
/* 1167 */    MCD_OPC_CheckField, 8, 4, 0, 0, 8, // Skip to: 3221
/* 1173 */    MCD_OPC_Decode, 170, 5, 41, // Opcode: MADBR
/* 1177 */    MCD_OPC_FilterValue, 31, 10, 0, // Skip to: 1191
/* 1181 */    MCD_OPC_CheckField, 8, 4, 0, 242, 7, // Skip to: 3221
/* 1187 */    MCD_OPC_Decode, 187, 5, 41, // Opcode: MSDBR
/* 1191 */    MCD_OPC_FilterValue, 64, 10, 0, // Skip to: 1205
/* 1195 */    MCD_OPC_CheckField, 8, 8, 0, 228, 7, // Skip to: 3221
/* 1201 */    MCD_OPC_Decode, 139, 5, 39, // Opcode: LPXBR
/* 1205 */    MCD_OPC_FilterValue, 65, 10, 0, // Skip to: 1219
/* 1209 */    MCD_OPC_CheckField, 8, 8, 0, 214, 7, // Skip to: 3221
/* 1215 */    MCD_OPC_Decode, 129, 5, 39, // Opcode: LNXBR
/* 1219 */    MCD_OPC_FilterValue, 66, 10, 0, // Skip to: 1233
/* 1223 */    MCD_OPC_CheckField, 8, 8, 0, 200, 7, // Skip to: 3221
/* 1229 */    MCD_OPC_Decode, 157, 5, 39, // Opcode: LTXBR
/* 1233 */    MCD_OPC_FilterValue, 67, 10, 0, // Skip to: 1247
/* 1237 */    MCD_OPC_CheckField, 8, 8, 0, 186, 7, // Skip to: 3221
/* 1243 */    MCD_OPC_Decode, 189, 4, 39, // Opcode: LCXBR
/* 1247 */    MCD_OPC_FilterValue, 68, 10, 0, // Skip to: 1261
/* 1251 */    MCD_OPC_CheckField, 8, 8, 0, 172, 7, // Skip to: 3221
/* 1257 */    MCD_OPC_Decode, 198, 4, 42, // Opcode: LEDBR
/* 1261 */    MCD_OPC_FilterValue, 69, 10, 0, // Skip to: 1275
/* 1265 */    MCD_OPC_CheckField, 8, 8, 0, 158, 7, // Skip to: 3221
/* 1271 */    MCD_OPC_Decode, 195, 4, 39, // Opcode: LDXBR
/* 1275 */    MCD_OPC_FilterValue, 70, 10, 0, // Skip to: 1289
/* 1279 */    MCD_OPC_CheckField, 8, 8, 0, 144, 7, // Skip to: 3221
/* 1285 */    MCD_OPC_Decode, 200, 4, 39, // Opcode: LEXBR
/* 1289 */    MCD_OPC_FilterValue, 71, 18, 0, // Skip to: 1311
/* 1293 */    MCD_OPC_CheckField, 8, 4, 0, 4, 0, // Skip to: 1303
/* 1299 */    MCD_OPC_Decode, 140, 4, 43, // Opcode: FIXBR
/* 1303 */    MCD_OPC_CheckPredicate, 0, 122, 7, // Skip to: 3221
/* 1307 */    MCD_OPC_Decode, 141, 4, 44, // Opcode: FIXBRA
/* 1311 */    MCD_OPC_FilterValue, 73, 10, 0, // Skip to: 1325
/* 1315 */    MCD_OPC_CheckField, 8, 8, 0, 108, 7, // Skip to: 3221
/* 1321 */    MCD_OPC_Decode, 224, 3, 39, // Opcode: CXBR
/* 1325 */    MCD_OPC_FilterValue, 74, 10, 0, // Skip to: 1339
/* 1329 */    MCD_OPC_CheckField, 8, 8, 0, 94, 7, // Skip to: 3221
/* 1335 */    MCD_OPC_Decode, 139, 1, 45, // Opcode: AXBR
/* 1339 */    MCD_OPC_FilterValue, 75, 10, 0, // Skip to: 1353
/* 1343 */    MCD_OPC_CheckField, 8, 8, 0, 80, 7, // Skip to: 3221
/* 1349 */    MCD_OPC_Decode, 226, 6, 45, // Opcode: SXBR
/* 1353 */    MCD_OPC_FilterValue, 76, 10, 0, // Skip to: 1367
/* 1357 */    MCD_OPC_CheckField, 8, 8, 0, 66, 7, // Skip to: 3221
/* 1363 */    MCD_OPC_Decode, 208, 5, 45, // Opcode: MXBR
/* 1367 */    MCD_OPC_FilterValue, 77, 10, 0, // Skip to: 1381
/* 1371 */    MCD_OPC_CheckField, 8, 8, 0, 52, 7, // Skip to: 3221
/* 1377 */    MCD_OPC_Decode, 134, 4, 45, // Opcode: DXBR
/* 1381 */    MCD_OPC_FilterValue, 87, 18, 0, // Skip to: 1403
/* 1385 */    MCD_OPC_CheckField, 8, 4, 0, 4, 0, // Skip to: 1395
/* 1391 */    MCD_OPC_Decode, 138, 4, 46, // Opcode: FIEBR
/* 1395 */    MCD_OPC_CheckPredicate, 0, 30, 7, // Skip to: 3221
/* 1399 */    MCD_OPC_Decode, 139, 4, 47, // Opcode: FIEBRA
/* 1403 */    MCD_OPC_FilterValue, 95, 18, 0, // Skip to: 1425
/* 1407 */    MCD_OPC_CheckField, 8, 4, 0, 4, 0, // Skip to: 1417
/* 1413 */    MCD_OPC_Decode, 136, 4, 48, // Opcode: FIDBR
/* 1417 */    MCD_OPC_CheckPredicate, 0, 8, 7, // Skip to: 3221
/* 1421 */    MCD_OPC_Decode, 137, 4, 49, // Opcode: FIDBRA
/* 1425 */    MCD_OPC_FilterValue, 101, 10, 0, // Skip to: 1439
/* 1429 */    MCD_OPC_CheckField, 8, 8, 0, 250, 6, // Skip to: 3221
/* 1435 */    MCD_OPC_Decode, 164, 5, 39, // Opcode: LXR
/* 1439 */    MCD_OPC_FilterValue, 114, 10, 0, // Skip to: 1453
/* 1443 */    MCD_OPC_CheckField, 8, 4, 0, 236, 6, // Skip to: 3221
/* 1449 */    MCD_OPC_Decode, 214, 3, 50, // Opcode: CPSDRdd
/* 1453 */    MCD_OPC_FilterValue, 116, 16, 0, // Skip to: 1473
/* 1457 */    MCD_OPC_CheckField, 8, 8, 0, 222, 6, // Skip to: 3221
/* 1463 */    MCD_OPC_CheckField, 0, 4, 0, 216, 6, // Skip to: 3221
/* 1469 */    MCD_OPC_Decode, 167, 5, 51, // Opcode: LZER
/* 1473 */    MCD_OPC_FilterValue, 117, 16, 0, // Skip to: 1493
/* 1477 */    MCD_OPC_CheckField, 8, 8, 0, 202, 6, // Skip to: 3221
/* 1483 */    MCD_OPC_CheckField, 0, 4, 0, 196, 6, // Skip to: 3221
/* 1489 */    MCD_OPC_Decode, 166, 5, 52, // Opcode: LZDR
/* 1493 */    MCD_OPC_FilterValue, 118, 16, 0, // Skip to: 1513
/* 1497 */    MCD_OPC_CheckField, 8, 8, 0, 182, 6, // Skip to: 3221
/* 1503 */    MCD_OPC_CheckField, 0, 4, 0, 176, 6, // Skip to: 3221
/* 1509 */    MCD_OPC_Decode, 168, 5, 53, // Opcode: LZXR
/* 1513 */    MCD_OPC_FilterValue, 144, 1, 8, 0, // Skip to: 1526
/* 1518 */    MCD_OPC_CheckPredicate, 0, 163, 6, // Skip to: 3221
/* 1522 */    MCD_OPC_Decode, 143, 3, 54, // Opcode: CELFBR
/* 1526 */    MCD_OPC_FilterValue, 145, 1, 8, 0, // Skip to: 1539
/* 1531 */    MCD_OPC_CheckPredicate, 0, 150, 6, // Skip to: 3221
/* 1535 */    MCD_OPC_Decode, 137, 3, 55, // Opcode: CDLFBR
/* 1539 */    MCD_OPC_FilterValue, 146, 1, 8, 0, // Skip to: 1552
/* 1544 */    MCD_OPC_CheckPredicate, 0, 137, 6, // Skip to: 3221
/* 1548 */    MCD_OPC_Decode, 227, 3, 56, // Opcode: CXLFBR
/* 1552 */    MCD_OPC_FilterValue, 148, 1, 10, 0, // Skip to: 1567
/* 1557 */    MCD_OPC_CheckField, 8, 8, 0, 122, 6, // Skip to: 3221
/* 1563 */    MCD_OPC_Decode, 141, 3, 57, // Opcode: CEFBR
/* 1567 */    MCD_OPC_FilterValue, 149, 1, 10, 0, // Skip to: 1582
/* 1572 */    MCD_OPC_CheckField, 8, 8, 0, 107, 6, // Skip to: 3221
/* 1578 */    MCD_OPC_Decode, 135, 3, 58, // Opcode: CDFBR
/* 1582 */    MCD_OPC_FilterValue, 150, 1, 10, 0, // Skip to: 1597
/* 1587 */    MCD_OPC_CheckField, 8, 8, 0, 92, 6, // Skip to: 3221
/* 1593 */    MCD_OPC_Decode, 225, 3, 59, // Opcode: CXFBR
/* 1597 */    MCD_OPC_FilterValue, 152, 1, 10, 0, // Skip to: 1612
/* 1602 */    MCD_OPC_CheckField, 8, 4, 0, 77, 6, // Skip to: 3221
/* 1608 */    MCD_OPC_Decode, 146, 3, 60, // Opcode: CFEBR
/* 1612 */    MCD_OPC_FilterValue, 153, 1, 10, 0, // Skip to: 1627
/* 1617 */    MCD_OPC_CheckField, 8, 4, 0, 62, 6, // Skip to: 3221
/* 1623 */    MCD_OPC_Decode, 145, 3, 61, // Opcode: CFDBR
/* 1627 */    MCD_OPC_FilterValue, 154, 1, 10, 0, // Skip to: 1642
/* 1632 */    MCD_OPC_CheckField, 8, 4, 0, 47, 6, // Skip to: 3221
/* 1638 */    MCD_OPC_Decode, 149, 3, 62, // Opcode: CFXBR
/* 1642 */    MCD_OPC_FilterValue, 156, 1, 8, 0, // Skip to: 1655
/* 1647 */    MCD_OPC_CheckPredicate, 0, 34, 6, // Skip to: 3221
/* 1651 */    MCD_OPC_Decode, 180, 3, 63, // Opcode: CLFEBR
/* 1655 */    MCD_OPC_FilterValue, 157, 1, 8, 0, // Skip to: 1668
/* 1660 */    MCD_OPC_CheckPredicate, 0, 21, 6, // Skip to: 3221
/* 1664 */    MCD_OPC_Decode, 179, 3, 64, // Opcode: CLFDBR
/* 1668 */    MCD_OPC_FilterValue, 158, 1, 8, 0, // Skip to: 1681
/* 1673 */    MCD_OPC_CheckPredicate, 0, 8, 6, // Skip to: 3221
/* 1677 */    MCD_OPC_Decode, 184, 3, 65, // Opcode: CLFXBR
/* 1681 */    MCD_OPC_FilterValue, 160, 1, 8, 0, // Skip to: 1694
/* 1686 */    MCD_OPC_CheckPredicate, 0, 251, 5, // Skip to: 3221
/* 1690 */    MCD_OPC_Decode, 144, 3, 66, // Opcode: CELGBR
/* 1694 */    MCD_OPC_FilterValue, 161, 1, 8, 0, // Skip to: 1707
/* 1699 */    MCD_OPC_CheckPredicate, 0, 238, 5, // Skip to: 3221
/* 1703 */    MCD_OPC_Decode, 138, 3, 67, // Opcode: CDLGBR
/* 1707 */    MCD_OPC_FilterValue, 162, 1, 8, 0, // Skip to: 1720
/* 1712 */    MCD_OPC_CheckPredicate, 0, 225, 5, // Skip to: 3221
/* 1716 */    MCD_OPC_Decode, 228, 3, 68, // Opcode: CXLGBR
/* 1720 */    MCD_OPC_FilterValue, 164, 1, 10, 0, // Skip to: 1735
/* 1725 */    MCD_OPC_CheckField, 8, 8, 0, 210, 5, // Skip to: 3221
/* 1731 */    MCD_OPC_Decode, 142, 3, 69, // Opcode: CEGBR
/* 1735 */    MCD_OPC_FilterValue, 165, 1, 10, 0, // Skip to: 1750
/* 1740 */    MCD_OPC_CheckField, 8, 8, 0, 195, 5, // Skip to: 3221
/* 1746 */    MCD_OPC_Decode, 136, 3, 70, // Opcode: CDGBR
/* 1750 */    MCD_OPC_FilterValue, 166, 1, 10, 0, // Skip to: 1765
/* 1755 */    MCD_OPC_CheckField, 8, 8, 0, 180, 5, // Skip to: 3221
/* 1761 */    MCD_OPC_Decode, 226, 3, 71, // Opcode: CXGBR
/* 1765 */    MCD_OPC_FilterValue, 168, 1, 10, 0, // Skip to: 1780
/* 1770 */    MCD_OPC_CheckField, 8, 4, 0, 165, 5, // Skip to: 3221
/* 1776 */    MCD_OPC_Decode, 152, 3, 72, // Opcode: CGEBR
/* 1780 */    MCD_OPC_FilterValue, 169, 1, 10, 0, // Skip to: 1795
/* 1785 */    MCD_OPC_CheckField, 8, 4, 0, 150, 5, // Skip to: 3221
/* 1791 */    MCD_OPC_Decode, 151, 3, 73, // Opcode: CGDBR
/* 1795 */    MCD_OPC_FilterValue, 170, 1, 10, 0, // Skip to: 1810
/* 1800 */    MCD_OPC_CheckField, 8, 4, 0, 135, 5, // Skip to: 3221
/* 1806 */    MCD_OPC_Decode, 165, 3, 74, // Opcode: CGXBR
/* 1810 */    MCD_OPC_FilterValue, 172, 1, 8, 0, // Skip to: 1823
/* 1815 */    MCD_OPC_CheckPredicate, 0, 122, 5, // Skip to: 3221
/* 1819 */    MCD_OPC_Decode, 187, 3, 75, // Opcode: CLGEBR
/* 1823 */    MCD_OPC_FilterValue, 173, 1, 8, 0, // Skip to: 1836
/* 1828 */    MCD_OPC_CheckPredicate, 0, 109, 5, // Skip to: 3221
/* 1832 */    MCD_OPC_Decode, 186, 3, 76, // Opcode: CLGDBR
/* 1836 */    MCD_OPC_FilterValue, 174, 1, 8, 0, // Skip to: 1849
/* 1841 */    MCD_OPC_CheckPredicate, 0, 96, 5, // Skip to: 3221
/* 1845 */    MCD_OPC_Decode, 198, 3, 77, // Opcode: CLGXBR
/* 1849 */    MCD_OPC_FilterValue, 193, 1, 10, 0, // Skip to: 1864
/* 1854 */    MCD_OPC_CheckField, 8, 8, 0, 81, 5, // Skip to: 3221
/* 1860 */    MCD_OPC_Decode, 193, 4, 70, // Opcode: LDGR
/* 1864 */    MCD_OPC_FilterValue, 205, 1, 72, 5, // Skip to: 3221
/* 1869 */    MCD_OPC_CheckField, 8, 8, 0, 66, 5, // Skip to: 3221
/* 1875 */    MCD_OPC_Decode, 206, 4, 78, // Opcode: LGDR
/* 1879 */    MCD_OPC_FilterValue, 185, 1, 48, 5, // Skip to: 3212
/* 1884 */    MCD_OPC_ExtractField, 16, 8,  // Inst{23-16} ...
/* 1887 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 1901
/* 1891 */    MCD_OPC_CheckField, 8, 8, 0, 44, 5, // Skip to: 3221
/* 1897 */    MCD_OPC_Decode, 137, 5, 79, // Opcode: LPGR
/* 1901 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 1915
/* 1905 */    MCD_OPC_CheckField, 8, 8, 0, 30, 5, // Skip to: 3221
/* 1911 */    MCD_OPC_Decode, 255, 4, 79, // Opcode: LNGR
/* 1915 */    MCD_OPC_FilterValue, 2, 10, 0, // Skip to: 1929
/* 1919 */    MCD_OPC_CheckField, 8, 8, 0, 16, 5, // Skip to: 3221
/* 1925 */    MCD_OPC_Decode, 155, 5, 79, // Opcode: LTGR
/* 1929 */    MCD_OPC_FilterValue, 3, 10, 0, // Skip to: 1943
/* 1933 */    MCD_OPC_CheckField, 8, 8, 0, 2, 5, // Skip to: 3221
/* 1939 */    MCD_OPC_Decode, 187, 4, 79, // Opcode: LCGR
/* 1943 */    MCD_OPC_FilterValue, 4, 10, 0, // Skip to: 1957
/* 1947 */    MCD_OPC_CheckField, 8, 8, 0, 244, 4, // Skip to: 3221
/* 1953 */    MCD_OPC_Decode, 215, 4, 79, // Opcode: LGR
/* 1957 */    MCD_OPC_FilterValue, 6, 10, 0, // Skip to: 1971
/* 1961 */    MCD_OPC_CheckField, 8, 8, 0, 230, 4, // Skip to: 3221
/* 1967 */    MCD_OPC_Decode, 205, 4, 79, // Opcode: LGBR
/* 1971 */    MCD_OPC_FilterValue, 7, 10, 0, // Skip to: 1985
/* 1975 */    MCD_OPC_CheckField, 8, 8, 0, 216, 4, // Skip to: 3221
/* 1981 */    MCD_OPC_Decode, 213, 4, 79, // Opcode: LGHR
/* 1985 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 1998
/* 1989 */    MCD_OPC_CheckField, 8, 8, 0, 202, 4, // Skip to: 3221
/* 1995 */    MCD_OPC_Decode, 36, 80, // Opcode: AGR
/* 1998 */    MCD_OPC_FilterValue, 9, 10, 0, // Skip to: 2012
/* 2002 */    MCD_OPC_CheckField, 8, 8, 0, 189, 4, // Skip to: 3221
/* 2008 */    MCD_OPC_Decode, 162, 6, 80, // Opcode: SGR
/* 2012 */    MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 2025
/* 2016 */    MCD_OPC_CheckField, 8, 8, 0, 175, 4, // Skip to: 3221
/* 2022 */    MCD_OPC_Decode, 57, 80, // Opcode: ALGR
/* 2025 */    MCD_OPC_FilterValue, 11, 10, 0, // Skip to: 2039
/* 2029 */    MCD_OPC_CheckField, 8, 8, 0, 162, 4, // Skip to: 3221
/* 2035 */    MCD_OPC_Decode, 176, 6, 80, // Opcode: SLGR
/* 2039 */    MCD_OPC_FilterValue, 12, 10, 0, // Skip to: 2053
/* 2043 */    MCD_OPC_CheckField, 8, 8, 0, 148, 4, // Skip to: 3221
/* 2049 */    MCD_OPC_Decode, 195, 5, 80, // Opcode: MSGR
/* 2053 */    MCD_OPC_FilterValue, 13, 10, 0, // Skip to: 2067
/* 2057 */    MCD_OPC_CheckField, 8, 8, 0, 134, 4, // Skip to: 3221
/* 2063 */    MCD_OPC_Decode, 133, 4, 81, // Opcode: DSGR
/* 2067 */    MCD_OPC_FilterValue, 15, 10, 0, // Skip to: 2081
/* 2071 */    MCD_OPC_CheckField, 8, 8, 0, 120, 4, // Skip to: 3221
/* 2077 */    MCD_OPC_Decode, 145, 5, 79, // Opcode: LRVGR
/* 2081 */    MCD_OPC_FilterValue, 16, 10, 0, // Skip to: 2095
/* 2085 */    MCD_OPC_CheckField, 8, 8, 0, 106, 4, // Skip to: 3221
/* 2091 */    MCD_OPC_Decode, 136, 5, 82, // Opcode: LPGFR
/* 2095 */    MCD_OPC_FilterValue, 17, 10, 0, // Skip to: 2109
/* 2099 */    MCD_OPC_CheckField, 8, 8, 0, 92, 4, // Skip to: 3221
/* 2105 */    MCD_OPC_Decode, 254, 4, 82, // Opcode: LNGFR
/* 2109 */    MCD_OPC_FilterValue, 18, 10, 0, // Skip to: 2123
/* 2113 */    MCD_OPC_CheckField, 8, 8, 0, 78, 4, // Skip to: 3221
/* 2119 */    MCD_OPC_Decode, 154, 5, 79, // Opcode: LTGFR
/* 2123 */    MCD_OPC_FilterValue, 19, 10, 0, // Skip to: 2137
/* 2127 */    MCD_OPC_CheckField, 8, 8, 0, 64, 4, // Skip to: 3221
/* 2133 */    MCD_OPC_Decode, 186, 4, 82, // Opcode: LCGFR
/* 2137 */    MCD_OPC_FilterValue, 20, 10, 0, // Skip to: 2151
/* 2141 */    MCD_OPC_CheckField, 8, 8, 0, 50, 4, // Skip to: 3221
/* 2147 */    MCD_OPC_Decode, 209, 4, 82, // Opcode: LGFR
/* 2151 */    MCD_OPC_FilterValue, 22, 10, 0, // Skip to: 2165
/* 2155 */    MCD_OPC_CheckField, 8, 8, 0, 36, 4, // Skip to: 3221
/* 2161 */    MCD_OPC_Decode, 233, 4, 82, // Opcode: LLGFR
/* 2165 */    MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 2178
/* 2169 */    MCD_OPC_CheckField, 8, 8, 0, 22, 4, // Skip to: 3221
/* 2175 */    MCD_OPC_Decode, 33, 83, // Opcode: AGFR
/* 2178 */    MCD_OPC_FilterValue, 25, 10, 0, // Skip to: 2192
/* 2182 */    MCD_OPC_CheckField, 8, 8, 0, 9, 4, // Skip to: 3221
/* 2188 */    MCD_OPC_Decode, 161, 6, 83, // Opcode: SGFR
/* 2192 */    MCD_OPC_FilterValue, 26, 9, 0, // Skip to: 2205
/* 2196 */    MCD_OPC_CheckField, 8, 8, 0, 251, 3, // Skip to: 3221
/* 2202 */    MCD_OPC_Decode, 55, 83, // Opcode: ALGFR
/* 2205 */    MCD_OPC_FilterValue, 27, 10, 0, // Skip to: 2219
/* 2209 */    MCD_OPC_CheckField, 8, 8, 0, 238, 3, // Skip to: 3221
/* 2215 */    MCD_OPC_Decode, 175, 6, 83, // Opcode: SLGFR
/* 2219 */    MCD_OPC_FilterValue, 28, 10, 0, // Skip to: 2233
/* 2223 */    MCD_OPC_CheckField, 8, 8, 0, 224, 3, // Skip to: 3221
/* 2229 */    MCD_OPC_Decode, 194, 5, 83, // Opcode: MSGFR
/* 2233 */    MCD_OPC_FilterValue, 29, 10, 0, // Skip to: 2247
/* 2237 */    MCD_OPC_CheckField, 8, 8, 0, 210, 3, // Skip to: 3221
/* 2243 */    MCD_OPC_Decode, 132, 4, 84, // Opcode: DSGFR
/* 2247 */    MCD_OPC_FilterValue, 31, 10, 0, // Skip to: 2261
/* 2251 */    MCD_OPC_CheckField, 8, 8, 0, 196, 3, // Skip to: 3221
/* 2257 */    MCD_OPC_Decode, 146, 5, 3, // Opcode: LRVR
/* 2261 */    MCD_OPC_FilterValue, 32, 10, 0, // Skip to: 2275
/* 2265 */    MCD_OPC_CheckField, 8, 8, 0, 182, 3, // Skip to: 3221
/* 2271 */    MCD_OPC_Decode, 162, 3, 79, // Opcode: CGR
/* 2275 */    MCD_OPC_FilterValue, 33, 10, 0, // Skip to: 2289
/* 2279 */    MCD_OPC_CheckField, 8, 8, 0, 168, 3, // Skip to: 3221
/* 2285 */    MCD_OPC_Decode, 195, 3, 79, // Opcode: CLGR
/* 2289 */    MCD_OPC_FilterValue, 38, 10, 0, // Skip to: 2303
/* 2293 */    MCD_OPC_CheckField, 8, 8, 0, 154, 3, // Skip to: 3221
/* 2299 */    MCD_OPC_Decode, 183, 4, 3, // Opcode: LBR
/* 2303 */    MCD_OPC_FilterValue, 39, 10, 0, // Skip to: 2317
/* 2307 */    MCD_OPC_CheckField, 8, 8, 0, 140, 3, // Skip to: 3221
/* 2313 */    MCD_OPC_Decode, 222, 4, 3, // Opcode: LHR
/* 2317 */    MCD_OPC_FilterValue, 48, 10, 0, // Skip to: 2331
/* 2321 */    MCD_OPC_CheckField, 8, 8, 0, 126, 3, // Skip to: 3221
/* 2327 */    MCD_OPC_Decode, 155, 3, 82, // Opcode: CGFR
/* 2331 */    MCD_OPC_FilterValue, 49, 10, 0, // Skip to: 2345
/* 2335 */    MCD_OPC_CheckField, 8, 8, 0, 112, 3, // Skip to: 3221
/* 2341 */    MCD_OPC_Decode, 190, 3, 82, // Opcode: CLGFR
/* 2345 */    MCD_OPC_FilterValue, 128, 1, 10, 0, // Skip to: 2360
/* 2350 */    MCD_OPC_CheckField, 8, 8, 0, 97, 3, // Skip to: 3221
/* 2356 */    MCD_OPC_Decode, 216, 5, 80, // Opcode: NGR
/* 2360 */    MCD_OPC_FilterValue, 129, 1, 10, 0, // Skip to: 2375
/* 2365 */    MCD_OPC_CheckField, 8, 8, 0, 82, 3, // Skip to: 3221
/* 2371 */    MCD_OPC_Decode, 243, 5, 80, // Opcode: OGR
/* 2375 */    MCD_OPC_FilterValue, 130, 1, 10, 0, // Skip to: 2390
/* 2380 */    MCD_OPC_CheckField, 8, 8, 0, 67, 3, // Skip to: 3221
/* 2386 */    MCD_OPC_Decode, 252, 6, 80, // Opcode: XGR
/* 2390 */    MCD_OPC_FilterValue, 131, 1, 10, 0, // Skip to: 2405
/* 2395 */    MCD_OPC_CheckField, 8, 8, 0, 52, 3, // Skip to: 3221
/* 2401 */    MCD_OPC_Decode, 142, 4, 85, // Opcode: FLOGR
/* 2405 */    MCD_OPC_FilterValue, 132, 1, 10, 0, // Skip to: 2420
/* 2410 */    MCD_OPC_CheckField, 8, 8, 0, 37, 3, // Skip to: 3221
/* 2416 */    MCD_OPC_Decode, 231, 4, 79, // Opcode: LLGCR
/* 2420 */    MCD_OPC_FilterValue, 133, 1, 10, 0, // Skip to: 2435
/* 2425 */    MCD_OPC_CheckField, 8, 8, 0, 22, 3, // Skip to: 3221
/* 2431 */    MCD_OPC_Decode, 236, 4, 79, // Opcode: LLGHR
/* 2435 */    MCD_OPC_FilterValue, 134, 1, 10, 0, // Skip to: 2450
/* 2440 */    MCD_OPC_CheckField, 8, 8, 0, 7, 3, // Skip to: 3221
/* 2446 */    MCD_OPC_Decode, 184, 5, 81, // Opcode: MLGR
/* 2450 */    MCD_OPC_FilterValue, 135, 1, 10, 0, // Skip to: 2465
/* 2455 */    MCD_OPC_CheckField, 8, 8, 0, 248, 2, // Skip to: 3221
/* 2461 */    MCD_OPC_Decode, 128, 4, 81, // Opcode: DLGR
/* 2465 */    MCD_OPC_FilterValue, 136, 1, 9, 0, // Skip to: 2479
/* 2470 */    MCD_OPC_CheckField, 8, 8, 0, 233, 2, // Skip to: 3221
/* 2476 */    MCD_OPC_Decode, 49, 80, // Opcode: ALCGR
/* 2479 */    MCD_OPC_FilterValue, 137, 1, 10, 0, // Skip to: 2494
/* 2484 */    MCD_OPC_CheckField, 8, 8, 0, 219, 2, // Skip to: 3221
/* 2490 */    MCD_OPC_Decode, 172, 6, 80, // Opcode: SLGBR
/* 2494 */    MCD_OPC_FilterValue, 148, 1, 10, 0, // Skip to: 2509
/* 2499 */    MCD_OPC_CheckField, 8, 8, 0, 204, 2, // Skip to: 3221
/* 2505 */    MCD_OPC_Decode, 228, 4, 3, // Opcode: LLCR
/* 2509 */    MCD_OPC_FilterValue, 149, 1, 10, 0, // Skip to: 2524
/* 2514 */    MCD_OPC_CheckField, 8, 8, 0, 189, 2, // Skip to: 3221
/* 2520 */    MCD_OPC_Decode, 241, 4, 3, // Opcode: LLHR
/* 2524 */    MCD_OPC_FilterValue, 151, 1, 10, 0, // Skip to: 2539
/* 2529 */    MCD_OPC_CheckField, 8, 8, 0, 174, 2, // Skip to: 3221
/* 2535 */    MCD_OPC_Decode, 129, 4, 84, // Opcode: DLR
/* 2539 */    MCD_OPC_FilterValue, 152, 1, 9, 0, // Skip to: 2553
/* 2544 */    MCD_OPC_CheckField, 8, 8, 0, 159, 2, // Skip to: 3221
/* 2550 */    MCD_OPC_Decode, 50, 4, // Opcode: ALCR
/* 2553 */    MCD_OPC_FilterValue, 153, 1, 10, 0, // Skip to: 2568
/* 2558 */    MCD_OPC_CheckField, 8, 8, 0, 145, 2, // Skip to: 3221
/* 2564 */    MCD_OPC_Decode, 169, 6, 4, // Opcode: SLBR
/* 2568 */    MCD_OPC_FilterValue, 226, 1, 186, 0, // Skip to: 2759
/* 2573 */    MCD_OPC_ExtractField, 8, 4,  // Inst{11-8} ...
/* 2576 */    MCD_OPC_FilterValue, 0, 129, 2, // Skip to: 3221
/* 2580 */    MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 2583 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 2595
/* 2587 */    MCD_OPC_CheckPredicate, 1, 160, 0, // Skip to: 2751
/* 2591 */    MCD_OPC_Decode, 246, 2, 80, // Opcode: AsmOLOCGR
/* 2595 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 2607
/* 2599 */    MCD_OPC_CheckPredicate, 1, 148, 0, // Skip to: 2751
/* 2603 */    MCD_OPC_Decode, 175, 1, 80, // Opcode: AsmHLOCGR
/* 2607 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 2619
/* 2611 */    MCD_OPC_CheckPredicate, 1, 136, 0, // Skip to: 2751
/* 2615 */    MCD_OPC_Decode, 211, 2, 80, // Opcode: AsmNLELOCGR
/* 2619 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 2631
/* 2623 */    MCD_OPC_CheckPredicate, 1, 124, 0, // Skip to: 2751
/* 2627 */    MCD_OPC_Decode, 170, 2, 80, // Opcode: AsmLLOCGR
/* 2631 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 2643
/* 2635 */    MCD_OPC_CheckPredicate, 1, 112, 0, // Skip to: 2751
/* 2639 */    MCD_OPC_Decode, 193, 2, 80, // Opcode: AsmNHELOCGR
/* 2643 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 2655
/* 2647 */    MCD_OPC_CheckPredicate, 1, 100, 0, // Skip to: 2751
/* 2651 */    MCD_OPC_Decode, 162, 2, 80, // Opcode: AsmLHLOCGR
/* 2655 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 2667
/* 2659 */    MCD_OPC_CheckPredicate, 1, 88, 0, // Skip to: 2751
/* 2663 */    MCD_OPC_Decode, 183, 2, 80, // Opcode: AsmNELOCGR
/* 2667 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 2679
/* 2671 */    MCD_OPC_CheckPredicate, 1, 76, 0, // Skip to: 2751
/* 2675 */    MCD_OPC_Decode, 157, 1, 80, // Opcode: AsmELOCGR
/* 2679 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 2691
/* 2683 */    MCD_OPC_CheckPredicate, 1, 64, 0, // Skip to: 2751
/* 2687 */    MCD_OPC_Decode, 220, 2, 80, // Opcode: AsmNLHLOCGR
/* 2691 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 2703
/* 2695 */    MCD_OPC_CheckPredicate, 1, 52, 0, // Skip to: 2751
/* 2699 */    MCD_OPC_Decode, 167, 1, 80, // Opcode: AsmHELOCGR
/* 2703 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 2715
/* 2707 */    MCD_OPC_CheckPredicate, 1, 40, 0, // Skip to: 2751
/* 2711 */    MCD_OPC_Decode, 228, 2, 80, // Opcode: AsmNLLOCGR
/* 2715 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 2727
/* 2719 */    MCD_OPC_CheckPredicate, 1, 28, 0, // Skip to: 2751
/* 2723 */    MCD_OPC_Decode, 153, 2, 80, // Opcode: AsmLELOCGR
/* 2727 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 2739
/* 2731 */    MCD_OPC_CheckPredicate, 1, 16, 0, // Skip to: 2751
/* 2735 */    MCD_OPC_Decode, 201, 2, 80, // Opcode: AsmNHLOCGR
/* 2739 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 2751
/* 2743 */    MCD_OPC_CheckPredicate, 1, 4, 0, // Skip to: 2751
/* 2747 */    MCD_OPC_Decode, 237, 2, 80, // Opcode: AsmNOLOCGR
/* 2751 */    MCD_OPC_CheckPredicate, 1, 210, 1, // Skip to: 3221
/* 2755 */    MCD_OPC_Decode, 174, 2, 86, // Opcode: AsmLOCGR
/* 2759 */    MCD_OPC_FilterValue, 228, 1, 14, 0, // Skip to: 2778
/* 2764 */    MCD_OPC_CheckPredicate, 2, 197, 1, // Skip to: 3221
/* 2768 */    MCD_OPC_CheckField, 8, 4, 0, 191, 1, // Skip to: 3221
/* 2774 */    MCD_OPC_Decode, 217, 5, 87, // Opcode: NGRK
/* 2778 */    MCD_OPC_FilterValue, 230, 1, 14, 0, // Skip to: 2797
/* 2783 */    MCD_OPC_CheckPredicate, 2, 178, 1, // Skip to: 3221
/* 2787 */    MCD_OPC_CheckField, 8, 4, 0, 172, 1, // Skip to: 3221
/* 2793 */    MCD_OPC_Decode, 244, 5, 87, // Opcode: OGRK
/* 2797 */    MCD_OPC_FilterValue, 231, 1, 14, 0, // Skip to: 2816
/* 2802 */    MCD_OPC_CheckPredicate, 2, 159, 1, // Skip to: 3221
/* 2806 */    MCD_OPC_CheckField, 8, 4, 0, 153, 1, // Skip to: 3221
/* 2812 */    MCD_OPC_Decode, 253, 6, 87, // Opcode: XGRK
/* 2816 */    MCD_OPC_FilterValue, 232, 1, 13, 0, // Skip to: 2834
/* 2821 */    MCD_OPC_CheckPredicate, 2, 140, 1, // Skip to: 3221
/* 2825 */    MCD_OPC_CheckField, 8, 4, 0, 134, 1, // Skip to: 3221
/* 2831 */    MCD_OPC_Decode, 37, 87, // Opcode: AGRK
/* 2834 */    MCD_OPC_FilterValue, 233, 1, 14, 0, // Skip to: 2853
/* 2839 */    MCD_OPC_CheckPredicate, 2, 122, 1, // Skip to: 3221
/* 2843 */    MCD_OPC_CheckField, 8, 4, 0, 116, 1, // Skip to: 3221
/* 2849 */    MCD_OPC_Decode, 163, 6, 87, // Opcode: SGRK
/* 2853 */    MCD_OPC_FilterValue, 234, 1, 13, 0, // Skip to: 2871
/* 2858 */    MCD_OPC_CheckPredicate, 2, 103, 1, // Skip to: 3221
/* 2862 */    MCD_OPC_CheckField, 8, 4, 0, 97, 1, // Skip to: 3221
/* 2868 */    MCD_OPC_Decode, 58, 87, // Opcode: ALGRK
/* 2871 */    MCD_OPC_FilterValue, 235, 1, 14, 0, // Skip to: 2890
/* 2876 */    MCD_OPC_CheckPredicate, 2, 85, 1, // Skip to: 3221
/* 2880 */    MCD_OPC_CheckField, 8, 4, 0, 79, 1, // Skip to: 3221
/* 2886 */    MCD_OPC_Decode, 177, 6, 87, // Opcode: SLGRK
/* 2890 */    MCD_OPC_FilterValue, 242, 1, 186, 0, // Skip to: 3081
/* 2895 */    MCD_OPC_ExtractField, 8, 4,  // Inst{11-8} ...
/* 2898 */    MCD_OPC_FilterValue, 0, 63, 1, // Skip to: 3221
/* 2902 */    MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 2905 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 2917
/* 2909 */    MCD_OPC_CheckPredicate, 1, 160, 0, // Skip to: 3073
/* 2913 */    MCD_OPC_Decode, 247, 2, 4, // Opcode: AsmOLOCR
/* 2917 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 2929
/* 2921 */    MCD_OPC_CheckPredicate, 1, 148, 0, // Skip to: 3073
/* 2925 */    MCD_OPC_Decode, 176, 1, 4, // Opcode: AsmHLOCR
/* 2929 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 2941
/* 2933 */    MCD_OPC_CheckPredicate, 1, 136, 0, // Skip to: 3073
/* 2937 */    MCD_OPC_Decode, 212, 2, 4, // Opcode: AsmNLELOCR
/* 2941 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 2953
/* 2945 */    MCD_OPC_CheckPredicate, 1, 124, 0, // Skip to: 3073
/* 2949 */    MCD_OPC_Decode, 171, 2, 4, // Opcode: AsmLLOCR
/* 2953 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 2965
/* 2957 */    MCD_OPC_CheckPredicate, 1, 112, 0, // Skip to: 3073
/* 2961 */    MCD_OPC_Decode, 194, 2, 4, // Opcode: AsmNHELOCR
/* 2965 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 2977
/* 2969 */    MCD_OPC_CheckPredicate, 1, 100, 0, // Skip to: 3073
/* 2973 */    MCD_OPC_Decode, 163, 2, 4, // Opcode: AsmLHLOCR
/* 2977 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 2989
/* 2981 */    MCD_OPC_CheckPredicate, 1, 88, 0, // Skip to: 3073
/* 2985 */    MCD_OPC_Decode, 184, 2, 4, // Opcode: AsmNELOCR
/* 2989 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 3001
/* 2993 */    MCD_OPC_CheckPredicate, 1, 76, 0, // Skip to: 3073
/* 2997 */    MCD_OPC_Decode, 158, 1, 4, // Opcode: AsmELOCR
/* 3001 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 3013
/* 3005 */    MCD_OPC_CheckPredicate, 1, 64, 0, // Skip to: 3073
/* 3009 */    MCD_OPC_Decode, 221, 2, 4, // Opcode: AsmNLHLOCR
/* 3013 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 3025
/* 3017 */    MCD_OPC_CheckPredicate, 1, 52, 0, // Skip to: 3073
/* 3021 */    MCD_OPC_Decode, 168, 1, 4, // Opcode: AsmHELOCR
/* 3025 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 3037
/* 3029 */    MCD_OPC_CheckPredicate, 1, 40, 0, // Skip to: 3073
/* 3033 */    MCD_OPC_Decode, 229, 2, 4, // Opcode: AsmNLLOCR
/* 3037 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 3049
/* 3041 */    MCD_OPC_CheckPredicate, 1, 28, 0, // Skip to: 3073
/* 3045 */    MCD_OPC_Decode, 154, 2, 4, // Opcode: AsmLELOCR
/* 3049 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 3061
/* 3053 */    MCD_OPC_CheckPredicate, 1, 16, 0, // Skip to: 3073
/* 3057 */    MCD_OPC_Decode, 202, 2, 4, // Opcode: AsmNHLOCR
/* 3061 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 3073
/* 3065 */    MCD_OPC_CheckPredicate, 1, 4, 0, // Skip to: 3073
/* 3069 */    MCD_OPC_Decode, 238, 2, 4, // Opcode: AsmNOLOCR
/* 3073 */    MCD_OPC_CheckPredicate, 1, 144, 0, // Skip to: 3221
/* 3077 */    MCD_OPC_Decode, 175, 2, 88, // Opcode: AsmLOCR
/* 3081 */    MCD_OPC_FilterValue, 244, 1, 14, 0, // Skip to: 3100
/* 3086 */    MCD_OPC_CheckPredicate, 2, 131, 0, // Skip to: 3221
/* 3090 */    MCD_OPC_CheckField, 8, 4, 0, 125, 0, // Skip to: 3221
/* 3096 */    MCD_OPC_Decode, 236, 5, 89, // Opcode: NRK
/* 3100 */    MCD_OPC_FilterValue, 246, 1, 14, 0, // Skip to: 3119
/* 3105 */    MCD_OPC_CheckPredicate, 2, 112, 0, // Skip to: 3221
/* 3109 */    MCD_OPC_CheckField, 8, 4, 0, 106, 0, // Skip to: 3221
/* 3115 */    MCD_OPC_Decode, 135, 6, 89, // Opcode: ORK
/* 3119 */    MCD_OPC_FilterValue, 247, 1, 14, 0, // Skip to: 3138
/* 3124 */    MCD_OPC_CheckPredicate, 2, 93, 0, // Skip to: 3221
/* 3128 */    MCD_OPC_CheckField, 8, 4, 0, 87, 0, // Skip to: 3221
/* 3134 */    MCD_OPC_Decode, 134, 7, 89, // Opcode: XRK
/* 3138 */    MCD_OPC_FilterValue, 248, 1, 13, 0, // Skip to: 3156
/* 3143 */    MCD_OPC_CheckPredicate, 2, 74, 0, // Skip to: 3221
/* 3147 */    MCD_OPC_CheckField, 8, 4, 0, 68, 0, // Skip to: 3221
/* 3153 */    MCD_OPC_Decode, 64, 89, // Opcode: ARK
/* 3156 */    MCD_OPC_FilterValue, 249, 1, 14, 0, // Skip to: 3175
/* 3161 */    MCD_OPC_CheckPredicate, 2, 56, 0, // Skip to: 3221
/* 3165 */    MCD_OPC_CheckField, 8, 4, 0, 50, 0, // Skip to: 3221
/* 3171 */    MCD_OPC_Decode, 193, 6, 89, // Opcode: SRK
/* 3175 */    MCD_OPC_FilterValue, 250, 1, 13, 0, // Skip to: 3193
/* 3180 */    MCD_OPC_CheckPredicate, 2, 37, 0, // Skip to: 3221
/* 3184 */    MCD_OPC_CheckField, 8, 4, 0, 31, 0, // Skip to: 3221
/* 3190 */    MCD_OPC_Decode, 61, 89, // Opcode: ALRK
/* 3193 */    MCD_OPC_FilterValue, 251, 1, 23, 0, // Skip to: 3221
/* 3198 */    MCD_OPC_CheckPredicate, 2, 19, 0, // Skip to: 3221
/* 3202 */    MCD_OPC_CheckField, 8, 4, 0, 13, 0, // Skip to: 3221
/* 3208 */    MCD_OPC_Decode, 182, 6, 89, // Opcode: SLRK
/* 3212 */    MCD_OPC_FilterValue, 186, 1, 4, 0, // Skip to: 3221
/* 3217 */    MCD_OPC_Decode, 221, 3, 90, // Opcode: CS
/* 3221 */    MCD_OPC_Fail,
  0
};

static uint8_t DecoderTable48[] = {
/* 0 */       MCD_OPC_ExtractField, 40, 8,  // Inst{47-40} ...
/* 3 */       MCD_OPC_FilterValue, 192, 1, 238, 0, // Skip to: 246
/* 8 */       MCD_OPC_ExtractField, 32, 4,  // Inst{35-32} ...
/* 11 */      MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 19
/* 15 */      MCD_OPC_Decode, 176, 4, 91, // Opcode: LARL
/* 19 */      MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 27
/* 23 */      MCD_OPC_Decode, 208, 4, 92, // Opcode: LGFI
/* 27 */      MCD_OPC_FilterValue, 4, 127, 0, // Skip to: 158
/* 31 */      MCD_OPC_ExtractField, 36, 4,  // Inst{39-36} ...
/* 34 */      MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 42
/* 38 */      MCD_OPC_Decode, 243, 2, 93, // Opcode: AsmOJG
/* 42 */      MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 50
/* 46 */      MCD_OPC_Decode, 172, 1, 93, // Opcode: AsmHJG
/* 50 */      MCD_OPC_FilterValue, 3, 4, 0, // Skip to: 58
/* 54 */      MCD_OPC_Decode, 208, 2, 93, // Opcode: AsmNLEJG
/* 58 */      MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 66
/* 62 */      MCD_OPC_Decode, 167, 2, 93, // Opcode: AsmLJG
/* 66 */      MCD_OPC_FilterValue, 5, 4, 0, // Skip to: 74
/* 70 */      MCD_OPC_Decode, 190, 2, 93, // Opcode: AsmNHEJG
/* 74 */      MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 82
/* 78 */      MCD_OPC_Decode, 159, 2, 93, // Opcode: AsmLHJG
/* 82 */      MCD_OPC_FilterValue, 7, 4, 0, // Skip to: 90
/* 86 */      MCD_OPC_Decode, 180, 2, 93, // Opcode: AsmNEJG
/* 90 */      MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 98
/* 94 */      MCD_OPC_Decode, 154, 1, 93, // Opcode: AsmEJG
/* 98 */      MCD_OPC_FilterValue, 9, 4, 0, // Skip to: 106
/* 102 */     MCD_OPC_Decode, 217, 2, 93, // Opcode: AsmNLHJG
/* 106 */     MCD_OPC_FilterValue, 10, 4, 0, // Skip to: 114
/* 110 */     MCD_OPC_Decode, 164, 1, 93, // Opcode: AsmHEJG
/* 114 */     MCD_OPC_FilterValue, 11, 4, 0, // Skip to: 122
/* 118 */     MCD_OPC_Decode, 225, 2, 93, // Opcode: AsmNLJG
/* 122 */     MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 130
/* 126 */     MCD_OPC_Decode, 150, 2, 93, // Opcode: AsmLEJG
/* 130 */     MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 138
/* 134 */     MCD_OPC_Decode, 198, 2, 93, // Opcode: AsmNHJG
/* 138 */     MCD_OPC_FilterValue, 14, 4, 0, // Skip to: 146
/* 142 */     MCD_OPC_Decode, 234, 2, 93, // Opcode: AsmNOJG
/* 146 */     MCD_OPC_FilterValue, 15, 4, 0, // Skip to: 154
/* 150 */     MCD_OPC_Decode, 164, 4, 93, // Opcode: JG
/* 154 */     MCD_OPC_Decode, 143, 1, 94, // Opcode: AsmBRCL
/* 158 */     MCD_OPC_FilterValue, 5, 4, 0, // Skip to: 166
/* 162 */     MCD_OPC_Decode, 255, 2, 91, // Opcode: BRASL
/* 166 */     MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 174
/* 170 */     MCD_OPC_Decode, 128, 7, 95, // Opcode: XIHF
/* 174 */     MCD_OPC_FilterValue, 7, 4, 0, // Skip to: 182
/* 178 */     MCD_OPC_Decode, 130, 7, 96, // Opcode: XILF
/* 182 */     MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 190
/* 186 */     MCD_OPC_Decode, 148, 4, 97, // Opcode: IIHF
/* 190 */     MCD_OPC_FilterValue, 9, 4, 0, // Skip to: 198
/* 194 */     MCD_OPC_Decode, 155, 4, 98, // Opcode: IILF
/* 198 */     MCD_OPC_FilterValue, 10, 4, 0, // Skip to: 206
/* 202 */     MCD_OPC_Decode, 220, 5, 95, // Opcode: NIHF
/* 206 */     MCD_OPC_FilterValue, 11, 4, 0, // Skip to: 214
/* 210 */     MCD_OPC_Decode, 227, 5, 96, // Opcode: NILF
/* 214 */     MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 222
/* 218 */     MCD_OPC_Decode, 247, 5, 95, // Opcode: OIHF
/* 222 */     MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 230
/* 226 */     MCD_OPC_Decode, 254, 5, 96, // Opcode: OILF
/* 230 */     MCD_OPC_FilterValue, 14, 4, 0, // Skip to: 238
/* 234 */     MCD_OPC_Decode, 244, 4, 99, // Opcode: LLIHF
/* 238 */     MCD_OPC_FilterValue, 15, 213, 12, // Skip to: 3527
/* 242 */     MCD_OPC_Decode, 247, 4, 99, // Opcode: LLILF
/* 246 */     MCD_OPC_FilterValue, 194, 1, 95, 0, // Skip to: 346
/* 251 */     MCD_OPC_ExtractField, 32, 4,  // Inst{35-32} ...
/* 254 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 262
/* 258 */     MCD_OPC_Decode, 193, 5, 100, // Opcode: MSGFI
/* 262 */     MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 270
/* 266 */     MCD_OPC_Decode, 190, 5, 101, // Opcode: MSFI
/* 270 */     MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 278
/* 274 */     MCD_OPC_Decode, 174, 6, 102, // Opcode: SLGFI
/* 278 */     MCD_OPC_FilterValue, 5, 4, 0, // Skip to: 286
/* 282 */     MCD_OPC_Decode, 170, 6, 96, // Opcode: SLFI
/* 286 */     MCD_OPC_FilterValue, 8, 3, 0, // Skip to: 293
/* 290 */     MCD_OPC_Decode, 32, 100, // Opcode: AGFI
/* 293 */     MCD_OPC_FilterValue, 9, 3, 0, // Skip to: 300
/* 297 */     MCD_OPC_Decode, 28, 101, // Opcode: AFI
/* 300 */     MCD_OPC_FilterValue, 10, 3, 0, // Skip to: 307
/* 304 */     MCD_OPC_Decode, 54, 102, // Opcode: ALGFI
/* 307 */     MCD_OPC_FilterValue, 11, 3, 0, // Skip to: 314
/* 311 */     MCD_OPC_Decode, 51, 96, // Opcode: ALFI
/* 314 */     MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 322
/* 318 */     MCD_OPC_Decode, 154, 3, 92, // Opcode: CGFI
/* 322 */     MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 330
/* 326 */     MCD_OPC_Decode, 147, 3, 103, // Opcode: CFI
/* 330 */     MCD_OPC_FilterValue, 14, 4, 0, // Skip to: 338
/* 334 */     MCD_OPC_Decode, 189, 3, 99, // Opcode: CLGFI
/* 338 */     MCD_OPC_FilterValue, 15, 113, 12, // Skip to: 3527
/* 342 */     MCD_OPC_Decode, 182, 3, 98, // Opcode: CLFI
/* 346 */     MCD_OPC_FilterValue, 196, 1, 91, 0, // Skip to: 442
/* 351 */     MCD_OPC_ExtractField, 32, 4,  // Inst{35-32} ...
/* 354 */     MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 362
/* 358 */     MCD_OPC_Decode, 242, 4, 104, // Opcode: LLHRL
/* 362 */     MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 370
/* 366 */     MCD_OPC_Decode, 214, 4, 91, // Opcode: LGHRL
/* 370 */     MCD_OPC_FilterValue, 5, 4, 0, // Skip to: 378
/* 374 */     MCD_OPC_Decode, 223, 4, 104, // Opcode: LHRL
/* 378 */     MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 386
/* 382 */     MCD_OPC_Decode, 237, 4, 91, // Opcode: LLGHRL
/* 386 */     MCD_OPC_FilterValue, 7, 4, 0, // Skip to: 394
/* 390 */     MCD_OPC_Decode, 215, 6, 104, // Opcode: STHRL
/* 394 */     MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 402
/* 398 */     MCD_OPC_Decode, 216, 4, 91, // Opcode: LGRL
/* 402 */     MCD_OPC_FilterValue, 11, 4, 0, // Skip to: 410
/* 406 */     MCD_OPC_Decode, 211, 6, 91, // Opcode: STGRL
/* 410 */     MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 418
/* 414 */     MCD_OPC_Decode, 210, 4, 91, // Opcode: LGFRL
/* 418 */     MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 426
/* 422 */     MCD_OPC_Decode, 141, 5, 104, // Opcode: LRL
/* 426 */     MCD_OPC_FilterValue, 14, 4, 0, // Skip to: 434
/* 430 */     MCD_OPC_Decode, 234, 4, 91, // Opcode: LLGFRL
/* 434 */     MCD_OPC_FilterValue, 15, 17, 12, // Skip to: 3527
/* 438 */     MCD_OPC_Decode, 221, 6, 104, // Opcode: STRL
/* 442 */     MCD_OPC_FilterValue, 198, 1, 91, 0, // Skip to: 538
/* 447 */     MCD_OPC_ExtractField, 32, 4,  // Inst{35-32} ...
/* 450 */     MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 458
/* 454 */     MCD_OPC_Decode, 138, 6, 94, // Opcode: PFDRL
/* 458 */     MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 466
/* 462 */     MCD_OPC_Decode, 159, 3, 91, // Opcode: CGHRL
/* 466 */     MCD_OPC_FilterValue, 5, 4, 0, // Skip to: 474
/* 470 */     MCD_OPC_Decode, 170, 3, 104, // Opcode: CHRL
/* 474 */     MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 482
/* 478 */     MCD_OPC_Decode, 192, 3, 91, // Opcode: CLGHRL
/* 482 */     MCD_OPC_FilterValue, 7, 4, 0, // Skip to: 490
/* 486 */     MCD_OPC_Decode, 201, 3, 104, // Opcode: CLHRL
/* 490 */     MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 498
/* 494 */     MCD_OPC_Decode, 164, 3, 91, // Opcode: CGRL
/* 498 */     MCD_OPC_FilterValue, 10, 4, 0, // Skip to: 506
/* 502 */     MCD_OPC_Decode, 197, 3, 91, // Opcode: CLGRL
/* 506 */     MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 514
/* 510 */     MCD_OPC_Decode, 156, 3, 91, // Opcode: CGFRL
/* 514 */     MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 522
/* 518 */     MCD_OPC_Decode, 220, 3, 104, // Opcode: CRL
/* 522 */     MCD_OPC_FilterValue, 14, 4, 0, // Skip to: 530
/* 526 */     MCD_OPC_Decode, 191, 3, 91, // Opcode: CLGFRL
/* 530 */     MCD_OPC_FilterValue, 15, 177, 11, // Skip to: 3527
/* 534 */     MCD_OPC_Decode, 209, 3, 104, // Opcode: CLRL
/* 538 */     MCD_OPC_FilterValue, 204, 1, 38, 0, // Skip to: 581
/* 543 */     MCD_OPC_ExtractField, 32, 4,  // Inst{35-32} ...
/* 546 */     MCD_OPC_FilterValue, 8, 7, 0, // Skip to: 557
/* 550 */     MCD_OPC_CheckPredicate, 3, 157, 11, // Skip to: 3527
/* 554 */     MCD_OPC_Decode, 45, 105, // Opcode: AIH
/* 557 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 569
/* 561 */     MCD_OPC_CheckPredicate, 3, 146, 11, // Skip to: 3527
/* 565 */     MCD_OPC_Decode, 173, 3, 106, // Opcode: CIH
/* 569 */     MCD_OPC_FilterValue, 15, 138, 11, // Skip to: 3527
/* 573 */     MCD_OPC_CheckPredicate, 3, 134, 11, // Skip to: 3527
/* 577 */     MCD_OPC_Decode, 203, 3, 98, // Opcode: CLIH
/* 581 */     MCD_OPC_FilterValue, 210, 1, 4, 0, // Skip to: 590
/* 586 */     MCD_OPC_Decode, 198, 5, 107, // Opcode: MVC
/* 590 */     MCD_OPC_FilterValue, 212, 1, 4, 0, // Skip to: 599
/* 595 */     MCD_OPC_Decode, 212, 5, 107, // Opcode: NC
/* 599 */     MCD_OPC_FilterValue, 213, 1, 4, 0, // Skip to: 608
/* 604 */     MCD_OPC_Decode, 176, 3, 107, // Opcode: CLC
/* 608 */     MCD_OPC_FilterValue, 214, 1, 4, 0, // Skip to: 617
/* 613 */     MCD_OPC_Decode, 239, 5, 107, // Opcode: OC
/* 617 */     MCD_OPC_FilterValue, 215, 1, 4, 0, // Skip to: 626
/* 622 */     MCD_OPC_Decode, 248, 6, 107, // Opcode: XC
/* 626 */     MCD_OPC_FilterValue, 227, 1, 163, 2, // Skip to: 1306
/* 631 */     MCD_OPC_ExtractField, 0, 8,  // Inst{7-0} ...
/* 634 */     MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 642
/* 638 */     MCD_OPC_Decode, 152, 5, 108, // Opcode: LTG
/* 642 */     MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 650
/* 646 */     MCD_OPC_Decode, 203, 4, 108, // Opcode: LG
/* 650 */     MCD_OPC_FilterValue, 8, 3, 0, // Skip to: 657
/* 654 */     MCD_OPC_Decode, 30, 109, // Opcode: AG
/* 657 */     MCD_OPC_FilterValue, 9, 4, 0, // Skip to: 665
/* 661 */     MCD_OPC_Decode, 159, 6, 109, // Opcode: SG
/* 665 */     MCD_OPC_FilterValue, 10, 3, 0, // Skip to: 672
/* 669 */     MCD_OPC_Decode, 52, 109, // Opcode: ALG
/* 672 */     MCD_OPC_FilterValue, 11, 4, 0, // Skip to: 680
/* 676 */     MCD_OPC_Decode, 171, 6, 109, // Opcode: SLG
/* 680 */     MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 688
/* 684 */     MCD_OPC_Decode, 191, 5, 109, // Opcode: MSG
/* 688 */     MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 696
/* 692 */     MCD_OPC_Decode, 130, 4, 110, // Opcode: DSG
/* 696 */     MCD_OPC_FilterValue, 15, 4, 0, // Skip to: 704
/* 700 */     MCD_OPC_Decode, 144, 5, 108, // Opcode: LRVG
/* 704 */     MCD_OPC_FilterValue, 18, 4, 0, // Skip to: 712
/* 708 */     MCD_OPC_Decode, 147, 5, 111, // Opcode: LT
/* 712 */     MCD_OPC_FilterValue, 20, 4, 0, // Skip to: 720
/* 716 */     MCD_OPC_Decode, 207, 4, 108, // Opcode: LGF
/* 720 */     MCD_OPC_FilterValue, 21, 4, 0, // Skip to: 728
/* 724 */     MCD_OPC_Decode, 211, 4, 108, // Opcode: LGH
/* 728 */     MCD_OPC_FilterValue, 22, 4, 0, // Skip to: 736
/* 732 */     MCD_OPC_Decode, 232, 4, 108, // Opcode: LLGF
/* 736 */     MCD_OPC_FilterValue, 24, 3, 0, // Skip to: 743
/* 740 */     MCD_OPC_Decode, 31, 109, // Opcode: AGF
/* 743 */     MCD_OPC_FilterValue, 25, 4, 0, // Skip to: 751
/* 747 */     MCD_OPC_Decode, 160, 6, 109, // Opcode: SGF
/* 751 */     MCD_OPC_FilterValue, 26, 3, 0, // Skip to: 758
/* 755 */     MCD_OPC_Decode, 53, 109, // Opcode: ALGF
/* 758 */     MCD_OPC_FilterValue, 27, 4, 0, // Skip to: 766
/* 762 */     MCD_OPC_Decode, 173, 6, 109, // Opcode: SLGF
/* 766 */     MCD_OPC_FilterValue, 28, 4, 0, // Skip to: 774
/* 770 */     MCD_OPC_Decode, 192, 5, 109, // Opcode: MSGF
/* 774 */     MCD_OPC_FilterValue, 29, 4, 0, // Skip to: 782
/* 778 */     MCD_OPC_Decode, 131, 4, 110, // Opcode: DSGF
/* 782 */     MCD_OPC_FilterValue, 30, 4, 0, // Skip to: 790
/* 786 */     MCD_OPC_Decode, 143, 5, 111, // Opcode: LRV
/* 790 */     MCD_OPC_FilterValue, 32, 4, 0, // Skip to: 798
/* 794 */     MCD_OPC_Decode, 150, 3, 108, // Opcode: CG
/* 798 */     MCD_OPC_FilterValue, 33, 4, 0, // Skip to: 806
/* 802 */     MCD_OPC_Decode, 185, 3, 108, // Opcode: CLG
/* 806 */     MCD_OPC_FilterValue, 36, 4, 0, // Skip to: 814
/* 810 */     MCD_OPC_Decode, 210, 6, 108, // Opcode: STG
/* 814 */     MCD_OPC_FilterValue, 47, 4, 0, // Skip to: 822
/* 818 */     MCD_OPC_Decode, 223, 6, 108, // Opcode: STRVG
/* 822 */     MCD_OPC_FilterValue, 48, 4, 0, // Skip to: 830
/* 826 */     MCD_OPC_Decode, 153, 3, 108, // Opcode: CGF
/* 830 */     MCD_OPC_FilterValue, 49, 4, 0, // Skip to: 838
/* 834 */     MCD_OPC_Decode, 188, 3, 108, // Opcode: CLGF
/* 838 */     MCD_OPC_FilterValue, 50, 4, 0, // Skip to: 846
/* 842 */     MCD_OPC_Decode, 153, 5, 108, // Opcode: LTGF
/* 846 */     MCD_OPC_FilterValue, 52, 4, 0, // Skip to: 854
/* 850 */     MCD_OPC_Decode, 157, 3, 108, // Opcode: CGH
/* 854 */     MCD_OPC_FilterValue, 54, 4, 0, // Skip to: 862
/* 858 */     MCD_OPC_Decode, 137, 6, 112, // Opcode: PFD
/* 862 */     MCD_OPC_FilterValue, 62, 4, 0, // Skip to: 870
/* 866 */     MCD_OPC_Decode, 222, 6, 111, // Opcode: STRV
/* 870 */     MCD_OPC_FilterValue, 80, 4, 0, // Skip to: 878
/* 874 */     MCD_OPC_Decode, 225, 6, 111, // Opcode: STY
/* 878 */     MCD_OPC_FilterValue, 81, 4, 0, // Skip to: 886
/* 882 */     MCD_OPC_Decode, 197, 5, 113, // Opcode: MSY
/* 886 */     MCD_OPC_FilterValue, 84, 4, 0, // Skip to: 894
/* 890 */     MCD_OPC_Decode, 237, 5, 113, // Opcode: NY
/* 894 */     MCD_OPC_FilterValue, 85, 4, 0, // Skip to: 902
/* 898 */     MCD_OPC_Decode, 212, 3, 111, // Opcode: CLY
/* 902 */     MCD_OPC_FilterValue, 86, 4, 0, // Skip to: 910
/* 906 */     MCD_OPC_Decode, 136, 6, 113, // Opcode: OY
/* 910 */     MCD_OPC_FilterValue, 87, 4, 0, // Skip to: 918
/* 914 */     MCD_OPC_Decode, 135, 7, 113, // Opcode: XY
/* 918 */     MCD_OPC_FilterValue, 88, 4, 0, // Skip to: 926
/* 922 */     MCD_OPC_Decode, 165, 5, 111, // Opcode: LY
/* 926 */     MCD_OPC_FilterValue, 89, 4, 0, // Skip to: 934
/* 930 */     MCD_OPC_Decode, 229, 3, 111, // Opcode: CY
/* 934 */     MCD_OPC_FilterValue, 90, 4, 0, // Skip to: 942
/* 938 */     MCD_OPC_Decode, 140, 1, 113, // Opcode: AY
/* 942 */     MCD_OPC_FilterValue, 91, 4, 0, // Skip to: 950
/* 946 */     MCD_OPC_Decode, 227, 6, 113, // Opcode: SY
/* 950 */     MCD_OPC_FilterValue, 94, 3, 0, // Skip to: 957
/* 954 */     MCD_OPC_Decode, 62, 113, // Opcode: ALY
/* 957 */     MCD_OPC_FilterValue, 95, 4, 0, // Skip to: 965
/* 961 */     MCD_OPC_Decode, 183, 6, 113, // Opcode: SLY
/* 965 */     MCD_OPC_FilterValue, 112, 4, 0, // Skip to: 973
/* 969 */     MCD_OPC_Decode, 216, 6, 111, // Opcode: STHY
/* 973 */     MCD_OPC_FilterValue, 113, 4, 0, // Skip to: 981
/* 977 */     MCD_OPC_Decode, 179, 4, 108, // Opcode: LAY
/* 981 */     MCD_OPC_FilterValue, 114, 4, 0, // Skip to: 989
/* 985 */     MCD_OPC_Decode, 204, 6, 111, // Opcode: STCY
/* 989 */     MCD_OPC_FilterValue, 115, 4, 0, // Skip to: 997
/* 993 */     MCD_OPC_Decode, 146, 4, 109, // Opcode: ICY
/* 997 */     MCD_OPC_FilterValue, 118, 4, 0, // Skip to: 1005
/* 1001 */    MCD_OPC_Decode, 180, 4, 111, // Opcode: LB
/* 1005 */    MCD_OPC_FilterValue, 119, 4, 0, // Skip to: 1013
/* 1009 */    MCD_OPC_Decode, 204, 4, 108, // Opcode: LGB
/* 1013 */    MCD_OPC_FilterValue, 120, 4, 0, // Skip to: 1021
/* 1017 */    MCD_OPC_Decode, 224, 4, 111, // Opcode: LHY
/* 1021 */    MCD_OPC_FilterValue, 121, 4, 0, // Skip to: 1029
/* 1025 */    MCD_OPC_Decode, 172, 3, 111, // Opcode: CHY
/* 1029 */    MCD_OPC_FilterValue, 122, 3, 0, // Skip to: 1036
/* 1033 */    MCD_OPC_Decode, 44, 113, // Opcode: AHY
/* 1036 */    MCD_OPC_FilterValue, 123, 4, 0, // Skip to: 1044
/* 1040 */    MCD_OPC_Decode, 165, 6, 113, // Opcode: SHY
/* 1044 */    MCD_OPC_FilterValue, 124, 4, 0, // Skip to: 1052
/* 1048 */    MCD_OPC_Decode, 182, 5, 113, // Opcode: MHY
/* 1052 */    MCD_OPC_FilterValue, 128, 1, 4, 0, // Skip to: 1061
/* 1057 */    MCD_OPC_Decode, 215, 5, 109, // Opcode: NG
/* 1061 */    MCD_OPC_FilterValue, 129, 1, 4, 0, // Skip to: 1070
/* 1066 */    MCD_OPC_Decode, 242, 5, 109, // Opcode: OG
/* 1070 */    MCD_OPC_FilterValue, 130, 1, 4, 0, // Skip to: 1079
/* 1075 */    MCD_OPC_Decode, 251, 6, 109, // Opcode: XG
/* 1079 */    MCD_OPC_FilterValue, 134, 1, 4, 0, // Skip to: 1088
/* 1084 */    MCD_OPC_Decode, 183, 5, 110, // Opcode: MLG
/* 1088 */    MCD_OPC_FilterValue, 135, 1, 4, 0, // Skip to: 1097
/* 1093 */    MCD_OPC_Decode, 255, 3, 110, // Opcode: DLG
/* 1097 */    MCD_OPC_FilterValue, 136, 1, 3, 0, // Skip to: 1105
/* 1102 */    MCD_OPC_Decode, 48, 109, // Opcode: ALCG
/* 1105 */    MCD_OPC_FilterValue, 137, 1, 4, 0, // Skip to: 1114
/* 1110 */    MCD_OPC_Decode, 168, 6, 109, // Opcode: SLBG
/* 1114 */    MCD_OPC_FilterValue, 144, 1, 4, 0, // Skip to: 1123
/* 1119 */    MCD_OPC_Decode, 230, 4, 108, // Opcode: LLGC
/* 1123 */    MCD_OPC_FilterValue, 145, 1, 4, 0, // Skip to: 1132
/* 1128 */    MCD_OPC_Decode, 235, 4, 108, // Opcode: LLGH
/* 1132 */    MCD_OPC_FilterValue, 148, 1, 4, 0, // Skip to: 1141
/* 1137 */    MCD_OPC_Decode, 225, 4, 111, // Opcode: LLC
/* 1141 */    MCD_OPC_FilterValue, 149, 1, 4, 0, // Skip to: 1150
/* 1146 */    MCD_OPC_Decode, 238, 4, 111, // Opcode: LLH
/* 1150 */    MCD_OPC_FilterValue, 151, 1, 4, 0, // Skip to: 1159
/* 1155 */    MCD_OPC_Decode, 254, 3, 110, // Opcode: DL
/* 1159 */    MCD_OPC_FilterValue, 152, 1, 3, 0, // Skip to: 1167
/* 1164 */    MCD_OPC_Decode, 47, 113, // Opcode: ALC
/* 1167 */    MCD_OPC_FilterValue, 153, 1, 4, 0, // Skip to: 1176
/* 1172 */    MCD_OPC_Decode, 167, 6, 113, // Opcode: SLB
/* 1176 */    MCD_OPC_FilterValue, 192, 1, 8, 0, // Skip to: 1189
/* 1181 */    MCD_OPC_CheckPredicate, 3, 38, 9, // Skip to: 3527
/* 1185 */    MCD_OPC_Decode, 181, 4, 114, // Opcode: LBH
/* 1189 */    MCD_OPC_FilterValue, 194, 1, 8, 0, // Skip to: 1202
/* 1194 */    MCD_OPC_CheckPredicate, 3, 25, 9, // Skip to: 3527
/* 1198 */    MCD_OPC_Decode, 226, 4, 111, // Opcode: LLCH
/* 1202 */    MCD_OPC_FilterValue, 195, 1, 8, 0, // Skip to: 1215
/* 1207 */    MCD_OPC_CheckPredicate, 3, 12, 9, // Skip to: 3527
/* 1211 */    MCD_OPC_Decode, 202, 6, 114, // Opcode: STCH
/* 1215 */    MCD_OPC_FilterValue, 196, 1, 8, 0, // Skip to: 1228
/* 1220 */    MCD_OPC_CheckPredicate, 3, 255, 8, // Skip to: 3527
/* 1224 */    MCD_OPC_Decode, 218, 4, 114, // Opcode: LHH
/* 1228 */    MCD_OPC_FilterValue, 198, 1, 8, 0, // Skip to: 1241
/* 1233 */    MCD_OPC_CheckPredicate, 3, 242, 8, // Skip to: 3527
/* 1237 */    MCD_OPC_Decode, 239, 4, 111, // Opcode: LLHH
/* 1241 */    MCD_OPC_FilterValue, 199, 1, 8, 0, // Skip to: 1254
/* 1246 */    MCD_OPC_CheckPredicate, 3, 229, 8, // Skip to: 3527
/* 1250 */    MCD_OPC_Decode, 213, 6, 114, // Opcode: STHH
/* 1254 */    MCD_OPC_FilterValue, 202, 1, 8, 0, // Skip to: 1267
/* 1259 */    MCD_OPC_CheckPredicate, 3, 216, 8, // Skip to: 3527
/* 1263 */    MCD_OPC_Decode, 202, 4, 114, // Opcode: LFH
/* 1267 */    MCD_OPC_FilterValue, 203, 1, 8, 0, // Skip to: 1280
/* 1272 */    MCD_OPC_CheckPredicate, 3, 203, 8, // Skip to: 3527
/* 1276 */    MCD_OPC_Decode, 209, 6, 114, // Opcode: STFH
/* 1280 */    MCD_OPC_FilterValue, 205, 1, 8, 0, // Skip to: 1293
/* 1285 */    MCD_OPC_CheckPredicate, 3, 190, 8, // Skip to: 3527
/* 1289 */    MCD_OPC_Decode, 167, 3, 114, // Opcode: CHF
/* 1293 */    MCD_OPC_FilterValue, 207, 1, 181, 8, // Skip to: 3527
/* 1298 */    MCD_OPC_CheckPredicate, 3, 177, 8, // Skip to: 3527
/* 1302 */    MCD_OPC_Decode, 199, 3, 114, // Opcode: CLHF
/* 1306 */    MCD_OPC_FilterValue, 229, 1, 75, 0, // Skip to: 1386
/* 1311 */    MCD_OPC_ExtractField, 32, 8,  // Inst{39-32} ...
/* 1314 */    MCD_OPC_FilterValue, 68, 4, 0, // Skip to: 1322
/* 1318 */    MCD_OPC_Decode, 202, 5, 115, // Opcode: MVHHI
/* 1322 */    MCD_OPC_FilterValue, 72, 4, 0, // Skip to: 1330
/* 1326 */    MCD_OPC_Decode, 201, 5, 115, // Opcode: MVGHI
/* 1330 */    MCD_OPC_FilterValue, 76, 4, 0, // Skip to: 1338
/* 1334 */    MCD_OPC_Decode, 203, 5, 115, // Opcode: MVHI
/* 1338 */    MCD_OPC_FilterValue, 84, 4, 0, // Skip to: 1346
/* 1342 */    MCD_OPC_Decode, 168, 3, 115, // Opcode: CHHSI
/* 1346 */    MCD_OPC_FilterValue, 85, 4, 0, // Skip to: 1354
/* 1350 */    MCD_OPC_Decode, 200, 3, 116, // Opcode: CLHHSI
/* 1354 */    MCD_OPC_FilterValue, 88, 4, 0, // Skip to: 1362
/* 1358 */    MCD_OPC_Decode, 160, 3, 115, // Opcode: CGHSI
/* 1362 */    MCD_OPC_FilterValue, 89, 4, 0, // Skip to: 1370
/* 1366 */    MCD_OPC_Decode, 193, 3, 116, // Opcode: CLGHSI
/* 1370 */    MCD_OPC_FilterValue, 92, 4, 0, // Skip to: 1378
/* 1374 */    MCD_OPC_Decode, 171, 3, 115, // Opcode: CHSI
/* 1378 */    MCD_OPC_FilterValue, 93, 97, 8, // Skip to: 3527
/* 1382 */    MCD_OPC_Decode, 181, 3, 116, // Opcode: CLFHSI
/* 1386 */    MCD_OPC_FilterValue, 235, 1, 53, 4, // Skip to: 2468
/* 1391 */    MCD_OPC_ExtractField, 0, 8,  // Inst{7-0} ...
/* 1394 */    MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 1402
/* 1398 */    MCD_OPC_Decode, 250, 4, 117, // Opcode: LMG
/* 1402 */    MCD_OPC_FilterValue, 10, 4, 0, // Skip to: 1410
/* 1406 */    MCD_OPC_Decode, 191, 6, 118, // Opcode: SRAG
/* 1410 */    MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 1418
/* 1414 */    MCD_OPC_Decode, 195, 6, 118, // Opcode: SRLG
/* 1418 */    MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 1426
/* 1422 */    MCD_OPC_Decode, 179, 6, 118, // Opcode: SLLG
/* 1426 */    MCD_OPC_FilterValue, 20, 4, 0, // Skip to: 1434
/* 1430 */    MCD_OPC_Decode, 223, 3, 119, // Opcode: CSY
/* 1434 */    MCD_OPC_FilterValue, 28, 4, 0, // Skip to: 1442
/* 1438 */    MCD_OPC_Decode, 149, 6, 118, // Opcode: RLLG
/* 1442 */    MCD_OPC_FilterValue, 29, 4, 0, // Skip to: 1450
/* 1446 */    MCD_OPC_Decode, 148, 6, 120, // Opcode: RLL
/* 1450 */    MCD_OPC_FilterValue, 36, 4, 0, // Skip to: 1458
/* 1454 */    MCD_OPC_Decode, 217, 6, 117, // Opcode: STMG
/* 1458 */    MCD_OPC_FilterValue, 48, 4, 0, // Skip to: 1466
/* 1462 */    MCD_OPC_Decode, 222, 3, 121, // Opcode: CSG
/* 1466 */    MCD_OPC_FilterValue, 81, 4, 0, // Skip to: 1474
/* 1470 */    MCD_OPC_Decode, 246, 6, 122, // Opcode: TMY
/* 1474 */    MCD_OPC_FilterValue, 82, 4, 0, // Skip to: 1482
/* 1478 */    MCD_OPC_Decode, 205, 5, 122, // Opcode: MVIY
/* 1482 */    MCD_OPC_FilterValue, 84, 4, 0, // Skip to: 1490
/* 1486 */    MCD_OPC_Decode, 234, 5, 122, // Opcode: NIY
/* 1490 */    MCD_OPC_FilterValue, 85, 4, 0, // Skip to: 1498
/* 1494 */    MCD_OPC_Decode, 205, 3, 122, // Opcode: CLIY
/* 1498 */    MCD_OPC_FilterValue, 86, 4, 0, // Skip to: 1506
/* 1502 */    MCD_OPC_Decode, 133, 6, 122, // Opcode: OIY
/* 1506 */    MCD_OPC_FilterValue, 87, 4, 0, // Skip to: 1514
/* 1510 */    MCD_OPC_Decode, 132, 7, 122, // Opcode: XIY
/* 1514 */    MCD_OPC_FilterValue, 106, 3, 0, // Skip to: 1521
/* 1518 */    MCD_OPC_Decode, 65, 123, // Opcode: ASI
/* 1521 */    MCD_OPC_FilterValue, 122, 3, 0, // Skip to: 1528
/* 1525 */    MCD_OPC_Decode, 38, 123, // Opcode: AGSI
/* 1528 */    MCD_OPC_FilterValue, 220, 1, 8, 0, // Skip to: 1541
/* 1533 */    MCD_OPC_CheckPredicate, 2, 198, 7, // Skip to: 3527
/* 1537 */    MCD_OPC_Decode, 192, 6, 120, // Opcode: SRAK
/* 1541 */    MCD_OPC_FilterValue, 222, 1, 8, 0, // Skip to: 1554
/* 1546 */    MCD_OPC_CheckPredicate, 2, 185, 7, // Skip to: 3527
/* 1550 */    MCD_OPC_Decode, 196, 6, 120, // Opcode: SRLK
/* 1554 */    MCD_OPC_FilterValue, 223, 1, 8, 0, // Skip to: 1567
/* 1559 */    MCD_OPC_CheckPredicate, 2, 172, 7, // Skip to: 3527
/* 1563 */    MCD_OPC_Decode, 180, 6, 120, // Opcode: SLLK
/* 1567 */    MCD_OPC_FilterValue, 226, 1, 179, 0, // Skip to: 1751
/* 1572 */    MCD_OPC_ExtractField, 32, 4,  // Inst{35-32} ...
/* 1575 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 1587
/* 1579 */    MCD_OPC_CheckPredicate, 1, 160, 0, // Skip to: 1743
/* 1583 */    MCD_OPC_Decode, 245, 2, 124, // Opcode: AsmOLOCG
/* 1587 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 1599
/* 1591 */    MCD_OPC_CheckPredicate, 1, 148, 0, // Skip to: 1743
/* 1595 */    MCD_OPC_Decode, 174, 1, 124, // Opcode: AsmHLOCG
/* 1599 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 1611
/* 1603 */    MCD_OPC_CheckPredicate, 1, 136, 0, // Skip to: 1743
/* 1607 */    MCD_OPC_Decode, 210, 2, 124, // Opcode: AsmNLELOCG
/* 1611 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 1623
/* 1615 */    MCD_OPC_CheckPredicate, 1, 124, 0, // Skip to: 1743
/* 1619 */    MCD_OPC_Decode, 169, 2, 124, // Opcode: AsmLLOCG
/* 1623 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 1635
/* 1627 */    MCD_OPC_CheckPredicate, 1, 112, 0, // Skip to: 1743
/* 1631 */    MCD_OPC_Decode, 192, 2, 124, // Opcode: AsmNHELOCG
/* 1635 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 1647
/* 1639 */    MCD_OPC_CheckPredicate, 1, 100, 0, // Skip to: 1743
/* 1643 */    MCD_OPC_Decode, 161, 2, 124, // Opcode: AsmLHLOCG
/* 1647 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 1659
/* 1651 */    MCD_OPC_CheckPredicate, 1, 88, 0, // Skip to: 1743
/* 1655 */    MCD_OPC_Decode, 182, 2, 124, // Opcode: AsmNELOCG
/* 1659 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 1671
/* 1663 */    MCD_OPC_CheckPredicate, 1, 76, 0, // Skip to: 1743
/* 1667 */    MCD_OPC_Decode, 156, 1, 124, // Opcode: AsmELOCG
/* 1671 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 1683
/* 1675 */    MCD_OPC_CheckPredicate, 1, 64, 0, // Skip to: 1743
/* 1679 */    MCD_OPC_Decode, 219, 2, 124, // Opcode: AsmNLHLOCG
/* 1683 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 1695
/* 1687 */    MCD_OPC_CheckPredicate, 1, 52, 0, // Skip to: 1743
/* 1691 */    MCD_OPC_Decode, 166, 1, 124, // Opcode: AsmHELOCG
/* 1695 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1707
/* 1699 */    MCD_OPC_CheckPredicate, 1, 40, 0, // Skip to: 1743
/* 1703 */    MCD_OPC_Decode, 227, 2, 124, // Opcode: AsmNLLOCG
/* 1707 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 1719
/* 1711 */    MCD_OPC_CheckPredicate, 1, 28, 0, // Skip to: 1743
/* 1715 */    MCD_OPC_Decode, 152, 2, 124, // Opcode: AsmLELOCG
/* 1719 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 1731
/* 1723 */    MCD_OPC_CheckPredicate, 1, 16, 0, // Skip to: 1743
/* 1727 */    MCD_OPC_Decode, 200, 2, 124, // Opcode: AsmNHLOCG
/* 1731 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 1743
/* 1735 */    MCD_OPC_CheckPredicate, 1, 4, 0, // Skip to: 1743
/* 1739 */    MCD_OPC_Decode, 236, 2, 124, // Opcode: AsmNOLOCG
/* 1743 */    MCD_OPC_CheckPredicate, 1, 244, 6, // Skip to: 3527
/* 1747 */    MCD_OPC_Decode, 173, 2, 125, // Opcode: AsmLOCG
/* 1751 */    MCD_OPC_FilterValue, 227, 1, 179, 0, // Skip to: 1935
/* 1756 */    MCD_OPC_ExtractField, 32, 4,  // Inst{35-32} ...
/* 1759 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 1771
/* 1763 */    MCD_OPC_CheckPredicate, 1, 160, 0, // Skip to: 1927
/* 1767 */    MCD_OPC_Decode, 249, 2, 126, // Opcode: AsmOSTOCG
/* 1771 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 1783
/* 1775 */    MCD_OPC_CheckPredicate, 1, 148, 0, // Skip to: 1927
/* 1779 */    MCD_OPC_Decode, 178, 1, 126, // Opcode: AsmHSTOCG
/* 1783 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 1795
/* 1787 */    MCD_OPC_CheckPredicate, 1, 136, 0, // Skip to: 1927
/* 1791 */    MCD_OPC_Decode, 214, 2, 126, // Opcode: AsmNLESTOCG
/* 1795 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 1807
/* 1799 */    MCD_OPC_CheckPredicate, 1, 124, 0, // Skip to: 1927
/* 1803 */    MCD_OPC_Decode, 177, 2, 126, // Opcode: AsmLSTOCG
/* 1807 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 1819
/* 1811 */    MCD_OPC_CheckPredicate, 1, 112, 0, // Skip to: 1927
/* 1815 */    MCD_OPC_Decode, 196, 2, 126, // Opcode: AsmNHESTOCG
/* 1819 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 1831
/* 1823 */    MCD_OPC_CheckPredicate, 1, 100, 0, // Skip to: 1927
/* 1827 */    MCD_OPC_Decode, 165, 2, 126, // Opcode: AsmLHSTOCG
/* 1831 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 1843
/* 1835 */    MCD_OPC_CheckPredicate, 1, 88, 0, // Skip to: 1927
/* 1839 */    MCD_OPC_Decode, 186, 2, 126, // Opcode: AsmNESTOCG
/* 1843 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 1855
/* 1847 */    MCD_OPC_CheckPredicate, 1, 76, 0, // Skip to: 1927
/* 1851 */    MCD_OPC_Decode, 160, 1, 126, // Opcode: AsmESTOCG
/* 1855 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 1867
/* 1859 */    MCD_OPC_CheckPredicate, 1, 64, 0, // Skip to: 1927
/* 1863 */    MCD_OPC_Decode, 223, 2, 126, // Opcode: AsmNLHSTOCG
/* 1867 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 1879
/* 1871 */    MCD_OPC_CheckPredicate, 1, 52, 0, // Skip to: 1927
/* 1875 */    MCD_OPC_Decode, 170, 1, 126, // Opcode: AsmHESTOCG
/* 1879 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1891
/* 1883 */    MCD_OPC_CheckPredicate, 1, 40, 0, // Skip to: 1927
/* 1887 */    MCD_OPC_Decode, 231, 2, 126, // Opcode: AsmNLSTOCG
/* 1891 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 1903
/* 1895 */    MCD_OPC_CheckPredicate, 1, 28, 0, // Skip to: 1927
/* 1899 */    MCD_OPC_Decode, 156, 2, 126, // Opcode: AsmLESTOCG
/* 1903 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 1915
/* 1907 */    MCD_OPC_CheckPredicate, 1, 16, 0, // Skip to: 1927
/* 1911 */    MCD_OPC_Decode, 204, 2, 126, // Opcode: AsmNHSTOCG
/* 1915 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 1927
/* 1919 */    MCD_OPC_CheckPredicate, 1, 4, 0, // Skip to: 1927
/* 1923 */    MCD_OPC_Decode, 240, 2, 126, // Opcode: AsmNOSTOCG
/* 1927 */    MCD_OPC_CheckPredicate, 1, 60, 6, // Skip to: 3527
/* 1931 */    MCD_OPC_Decode, 251, 2, 127, // Opcode: AsmSTOCG
/* 1935 */    MCD_OPC_FilterValue, 228, 1, 8, 0, // Skip to: 1948
/* 1940 */    MCD_OPC_CheckPredicate, 4, 47, 6, // Skip to: 3527
/* 1944 */    MCD_OPC_Decode, 173, 4, 117, // Opcode: LANG
/* 1948 */    MCD_OPC_FilterValue, 230, 1, 8, 0, // Skip to: 1961
/* 1953 */    MCD_OPC_CheckPredicate, 4, 34, 6, // Skip to: 3527
/* 1957 */    MCD_OPC_Decode, 175, 4, 117, // Opcode: LAOG
/* 1961 */    MCD_OPC_FilterValue, 231, 1, 8, 0, // Skip to: 1974
/* 1966 */    MCD_OPC_CheckPredicate, 4, 21, 6, // Skip to: 3527
/* 1970 */    MCD_OPC_Decode, 178, 4, 117, // Opcode: LAXG
/* 1974 */    MCD_OPC_FilterValue, 232, 1, 8, 0, // Skip to: 1987
/* 1979 */    MCD_OPC_CheckPredicate, 4, 8, 6, // Skip to: 3527
/* 1983 */    MCD_OPC_Decode, 169, 4, 117, // Opcode: LAAG
/* 1987 */    MCD_OPC_FilterValue, 234, 1, 8, 0, // Skip to: 2000
/* 1992 */    MCD_OPC_CheckPredicate, 4, 251, 5, // Skip to: 3527
/* 1996 */    MCD_OPC_Decode, 171, 4, 117, // Opcode: LAALG
/* 2000 */    MCD_OPC_FilterValue, 242, 1, 194, 0, // Skip to: 2199
/* 2005 */    MCD_OPC_ExtractField, 32, 4,  // Inst{35-32} ...
/* 2008 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 2021
/* 2012 */    MCD_OPC_CheckPredicate, 1, 174, 0, // Skip to: 2190
/* 2016 */    MCD_OPC_Decode, 244, 2, 128, 1, // Opcode: AsmOLOC
/* 2021 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 2034
/* 2025 */    MCD_OPC_CheckPredicate, 1, 161, 0, // Skip to: 2190
/* 2029 */    MCD_OPC_Decode, 173, 1, 128, 1, // Opcode: AsmHLOC
/* 2034 */    MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 2047
/* 2038 */    MCD_OPC_CheckPredicate, 1, 148, 0, // Skip to: 2190
/* 2042 */    MCD_OPC_Decode, 209, 2, 128, 1, // Opcode: AsmNLELOC
/* 2047 */    MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 2060
/* 2051 */    MCD_OPC_CheckPredicate, 1, 135, 0, // Skip to: 2190
/* 2055 */    MCD_OPC_Decode, 168, 2, 128, 1, // Opcode: AsmLLOC
/* 2060 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 2073
/* 2064 */    MCD_OPC_CheckPredicate, 1, 122, 0, // Skip to: 2190
/* 2068 */    MCD_OPC_Decode, 191, 2, 128, 1, // Opcode: AsmNHELOC
/* 2073 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 2086
/* 2077 */    MCD_OPC_CheckPredicate, 1, 109, 0, // Skip to: 2190
/* 2081 */    MCD_OPC_Decode, 160, 2, 128, 1, // Opcode: AsmLHLOC
/* 2086 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 2099
/* 2090 */    MCD_OPC_CheckPredicate, 1, 96, 0, // Skip to: 2190
/* 2094 */    MCD_OPC_Decode, 181, 2, 128, 1, // Opcode: AsmNELOC
/* 2099 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 2112
/* 2103 */    MCD_OPC_CheckPredicate, 1, 83, 0, // Skip to: 2190
/* 2107 */    MCD_OPC_Decode, 155, 1, 128, 1, // Opcode: AsmELOC
/* 2112 */    MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 2125
/* 2116 */    MCD_OPC_CheckPredicate, 1, 70, 0, // Skip to: 2190
/* 2120 */    MCD_OPC_Decode, 218, 2, 128, 1, // Opcode: AsmNLHLOC
/* 2125 */    MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 2138
/* 2129 */    MCD_OPC_CheckPredicate, 1, 57, 0, // Skip to: 2190
/* 2133 */    MCD_OPC_Decode, 165, 1, 128, 1, // Opcode: AsmHELOC
/* 2138 */    MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 2151
/* 2142 */    MCD_OPC_CheckPredicate, 1, 44, 0, // Skip to: 2190
/* 2146 */    MCD_OPC_Decode, 226, 2, 128, 1, // Opcode: AsmNLLOC
/* 2151 */    MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 2164
/* 2155 */    MCD_OPC_CheckPredicate, 1, 31, 0, // Skip to: 2190
/* 2159 */    MCD_OPC_Decode, 151, 2, 128, 1, // Opcode: AsmLELOC
/* 2164 */    MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 2177
/* 2168 */    MCD_OPC_CheckPredicate, 1, 18, 0, // Skip to: 2190
/* 2172 */    MCD_OPC_Decode, 199, 2, 128, 1, // Opcode: AsmNHLOC
/* 2177 */    MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 2190
/* 2181 */    MCD_OPC_CheckPredicate, 1, 5, 0, // Skip to: 2190
/* 2185 */    MCD_OPC_Decode, 235, 2, 128, 1, // Opcode: AsmNOLOC
/* 2190 */    MCD_OPC_CheckPredicate, 1, 53, 5, // Skip to: 3527
/* 2194 */    MCD_OPC_Decode, 172, 2, 129, 1, // Opcode: AsmLOC
/* 2199 */    MCD_OPC_FilterValue, 243, 1, 194, 0, // Skip to: 2398
/* 2204 */    MCD_OPC_ExtractField, 32, 4,  // Inst{35-32} ...
/* 2207 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 2220
/* 2211 */    MCD_OPC_CheckPredicate, 1, 174, 0, // Skip to: 2389
/* 2215 */    MCD_OPC_Decode, 248, 2, 130, 1, // Opcode: AsmOSTOC
/* 2220 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 2233
/* 2224 */    MCD_OPC_CheckPredicate, 1, 161, 0, // Skip to: 2389
/* 2228 */    MCD_OPC_Decode, 177, 1, 130, 1, // Opcode: AsmHSTOC
/* 2233 */    MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 2246
/* 2237 */    MCD_OPC_CheckPredicate, 1, 148, 0, // Skip to: 2389
/* 2241 */    MCD_OPC_Decode, 213, 2, 130, 1, // Opcode: AsmNLESTOC
/* 2246 */    MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 2259
/* 2250 */    MCD_OPC_CheckPredicate, 1, 135, 0, // Skip to: 2389
/* 2254 */    MCD_OPC_Decode, 176, 2, 130, 1, // Opcode: AsmLSTOC
/* 2259 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 2272
/* 2263 */    MCD_OPC_CheckPredicate, 1, 122, 0, // Skip to: 2389
/* 2267 */    MCD_OPC_Decode, 195, 2, 130, 1, // Opcode: AsmNHESTOC
/* 2272 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 2285
/* 2276 */    MCD_OPC_CheckPredicate, 1, 109, 0, // Skip to: 2389
/* 2280 */    MCD_OPC_Decode, 164, 2, 130, 1, // Opcode: AsmLHSTOC
/* 2285 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 2298
/* 2289 */    MCD_OPC_CheckPredicate, 1, 96, 0, // Skip to: 2389
/* 2293 */    MCD_OPC_Decode, 185, 2, 130, 1, // Opcode: AsmNESTOC
/* 2298 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 2311
/* 2302 */    MCD_OPC_CheckPredicate, 1, 83, 0, // Skip to: 2389
/* 2306 */    MCD_OPC_Decode, 159, 1, 130, 1, // Opcode: AsmESTOC
/* 2311 */    MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 2324
/* 2315 */    MCD_OPC_CheckPredicate, 1, 70, 0, // Skip to: 2389
/* 2319 */    MCD_OPC_Decode, 222, 2, 130, 1, // Opcode: AsmNLHSTOC
/* 2324 */    MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 2337
/* 2328 */    MCD_OPC_CheckPredicate, 1, 57, 0, // Skip to: 2389
/* 2332 */    MCD_OPC_Decode, 169, 1, 130, 1, // Opcode: AsmHESTOC
/* 2337 */    MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 2350
/* 2341 */    MCD_OPC_CheckPredicate, 1, 44, 0, // Skip to: 2389
/* 2345 */    MCD_OPC_Decode, 230, 2, 130, 1, // Opcode: AsmNLSTOC
/* 2350 */    MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 2363
/* 2354 */    MCD_OPC_CheckPredicate, 1, 31, 0, // Skip to: 2389
/* 2358 */    MCD_OPC_Decode, 155, 2, 130, 1, // Opcode: AsmLESTOC
/* 2363 */    MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 2376
/* 2367 */    MCD_OPC_CheckPredicate, 1, 18, 0, // Skip to: 2389
/* 2371 */    MCD_OPC_Decode, 203, 2, 130, 1, // Opcode: AsmNHSTOC
/* 2376 */    MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 2389
/* 2380 */    MCD_OPC_CheckPredicate, 1, 5, 0, // Skip to: 2389
/* 2384 */    MCD_OPC_Decode, 239, 2, 130, 1, // Opcode: AsmNOSTOC
/* 2389 */    MCD_OPC_CheckPredicate, 1, 110, 4, // Skip to: 3527
/* 2393 */    MCD_OPC_Decode, 250, 2, 131, 1, // Opcode: AsmSTOC
/* 2398 */    MCD_OPC_FilterValue, 244, 1, 9, 0, // Skip to: 2412
/* 2403 */    MCD_OPC_CheckPredicate, 4, 96, 4, // Skip to: 3527
/* 2407 */    MCD_OPC_Decode, 172, 4, 132, 1, // Opcode: LAN
/* 2412 */    MCD_OPC_FilterValue, 246, 1, 9, 0, // Skip to: 2426
/* 2417 */    MCD_OPC_CheckPredicate, 4, 82, 4, // Skip to: 3527
/* 2421 */    MCD_OPC_Decode, 174, 4, 132, 1, // Opcode: LAO
/* 2426 */    MCD_OPC_FilterValue, 247, 1, 9, 0, // Skip to: 2440
/* 2431 */    MCD_OPC_CheckPredicate, 4, 68, 4, // Skip to: 3527
/* 2435 */    MCD_OPC_Decode, 177, 4, 132, 1, // Opcode: LAX
/* 2440 */    MCD_OPC_FilterValue, 248, 1, 9, 0, // Skip to: 2454
/* 2445 */    MCD_OPC_CheckPredicate, 4, 54, 4, // Skip to: 3527
/* 2449 */    MCD_OPC_Decode, 168, 4, 132, 1, // Opcode: LAA
/* 2454 */    MCD_OPC_FilterValue, 250, 1, 44, 4, // Skip to: 3527
/* 2459 */    MCD_OPC_CheckPredicate, 4, 40, 4, // Skip to: 3527
/* 2463 */    MCD_OPC_Decode, 170, 4, 132, 1, // Opcode: LAAL
/* 2468 */    MCD_OPC_FilterValue, 236, 1, 185, 2, // Skip to: 3170
/* 2473 */    MCD_OPC_ExtractField, 0, 8,  // Inst{7-0} ...
/* 2476 */    MCD_OPC_FilterValue, 81, 9, 0, // Skip to: 2489
/* 2480 */    MCD_OPC_CheckPredicate, 3, 19, 4, // Skip to: 3527
/* 2484 */    MCD_OPC_Decode, 144, 6, 133, 1, // Opcode: RISBLG
/* 2489 */    MCD_OPC_FilterValue, 84, 5, 0, // Skip to: 2498
/* 2493 */    MCD_OPC_Decode, 150, 6, 134, 1, // Opcode: RNSBG
/* 2498 */    MCD_OPC_FilterValue, 85, 5, 0, // Skip to: 2507
/* 2502 */    MCD_OPC_Decode, 139, 6, 134, 1, // Opcode: RISBG
/* 2507 */    MCD_OPC_FilterValue, 86, 5, 0, // Skip to: 2516
/* 2511 */    MCD_OPC_Decode, 151, 6, 134, 1, // Opcode: ROSBG
/* 2516 */    MCD_OPC_FilterValue, 87, 5, 0, // Skip to: 2525
/* 2520 */    MCD_OPC_Decode, 152, 6, 134, 1, // Opcode: RXSBG
/* 2525 */    MCD_OPC_FilterValue, 93, 9, 0, // Skip to: 2538
/* 2529 */    MCD_OPC_CheckPredicate, 3, 226, 3, // Skip to: 3527
/* 2533 */    MCD_OPC_Decode, 141, 6, 135, 1, // Opcode: RISBHG
/* 2538 */    MCD_OPC_FilterValue, 100, 69, 0, // Skip to: 2611
/* 2542 */    MCD_OPC_ExtractField, 8, 4,  // Inst{11-8} ...
/* 2545 */    MCD_OPC_FilterValue, 0, 210, 3, // Skip to: 3527
/* 2549 */    MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 2552 */    MCD_OPC_FilterValue, 2, 5, 0, // Skip to: 2561
/* 2556 */    MCD_OPC_Decode, 204, 1, 136, 1, // Opcode: AsmJHCGR
/* 2561 */    MCD_OPC_FilterValue, 4, 5, 0, // Skip to: 2570
/* 2565 */    MCD_OPC_Decode, 236, 1, 136, 1, // Opcode: AsmJLCGR
/* 2570 */    MCD_OPC_FilterValue, 6, 5, 0, // Skip to: 2579
/* 2574 */    MCD_OPC_Decode, 140, 2, 136, 1, // Opcode: AsmJLHCGR
/* 2579 */    MCD_OPC_FilterValue, 8, 5, 0, // Skip to: 2588
/* 2583 */    MCD_OPC_Decode, 188, 1, 136, 1, // Opcode: AsmJECGR
/* 2588 */    MCD_OPC_FilterValue, 10, 5, 0, // Skip to: 2597
/* 2592 */    MCD_OPC_Decode, 220, 1, 136, 1, // Opcode: AsmJHECGR
/* 2597 */    MCD_OPC_FilterValue, 12, 5, 0, // Skip to: 2606
/* 2601 */    MCD_OPC_Decode, 252, 1, 136, 1, // Opcode: AsmJLECGR
/* 2606 */    MCD_OPC_Decode, 145, 1, 137, 1, // Opcode: AsmCGRJ
/* 2611 */    MCD_OPC_FilterValue, 101, 69, 0, // Skip to: 2684
/* 2615 */    MCD_OPC_ExtractField, 8, 4,  // Inst{11-8} ...
/* 2618 */    MCD_OPC_FilterValue, 0, 137, 3, // Skip to: 3527
/* 2622 */    MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 2625 */    MCD_OPC_FilterValue, 2, 5, 0, // Skip to: 2634
/* 2629 */    MCD_OPC_Decode, 207, 1, 136, 1, // Opcode: AsmJHCLGR
/* 2634 */    MCD_OPC_FilterValue, 4, 5, 0, // Skip to: 2643
/* 2638 */    MCD_OPC_Decode, 239, 1, 136, 1, // Opcode: AsmJLCLGR
/* 2643 */    MCD_OPC_FilterValue, 6, 5, 0, // Skip to: 2652
/* 2647 */    MCD_OPC_Decode, 143, 2, 136, 1, // Opcode: AsmJLHCLGR
/* 2652 */    MCD_OPC_FilterValue, 8, 5, 0, // Skip to: 2661
/* 2656 */    MCD_OPC_Decode, 191, 1, 136, 1, // Opcode: AsmJECLGR
/* 2661 */    MCD_OPC_FilterValue, 10, 5, 0, // Skip to: 2670
/* 2665 */    MCD_OPC_Decode, 223, 1, 136, 1, // Opcode: AsmJHECLGR
/* 2670 */    MCD_OPC_FilterValue, 12, 5, 0, // Skip to: 2679
/* 2674 */    MCD_OPC_Decode, 255, 1, 136, 1, // Opcode: AsmJLECLGR
/* 2679 */    MCD_OPC_Decode, 148, 1, 137, 1, // Opcode: AsmCLGRJ
/* 2684 */    MCD_OPC_FilterValue, 118, 69, 0, // Skip to: 2757
/* 2688 */    MCD_OPC_ExtractField, 8, 4,  // Inst{11-8} ...
/* 2691 */    MCD_OPC_FilterValue, 0, 64, 3, // Skip to: 3527
/* 2695 */    MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 2698 */    MCD_OPC_FilterValue, 2, 5, 0, // Skip to: 2707
/* 2702 */    MCD_OPC_Decode, 210, 1, 138, 1, // Opcode: AsmJHCR
/* 2707 */    MCD_OPC_FilterValue, 4, 5, 0, // Skip to: 2716
/* 2711 */    MCD_OPC_Decode, 242, 1, 138, 1, // Opcode: AsmJLCR
/* 2716 */    MCD_OPC_FilterValue, 6, 5, 0, // Skip to: 2725
/* 2720 */    MCD_OPC_Decode, 146, 2, 138, 1, // Opcode: AsmJLHCR
/* 2725 */    MCD_OPC_FilterValue, 8, 5, 0, // Skip to: 2734
/* 2729 */    MCD_OPC_Decode, 194, 1, 138, 1, // Opcode: AsmJECR
/* 2734 */    MCD_OPC_FilterValue, 10, 5, 0, // Skip to: 2743
/* 2738 */    MCD_OPC_Decode, 226, 1, 138, 1, // Opcode: AsmJHECR
/* 2743 */    MCD_OPC_FilterValue, 12, 5, 0, // Skip to: 2752
/* 2747 */    MCD_OPC_Decode, 130, 2, 138, 1, // Opcode: AsmJLECR
/* 2752 */    MCD_OPC_Decode, 151, 1, 139, 1, // Opcode: AsmCRJ
/* 2757 */    MCD_OPC_FilterValue, 119, 69, 0, // Skip to: 2830
/* 2761 */    MCD_OPC_ExtractField, 8, 4,  // Inst{11-8} ...
/* 2764 */    MCD_OPC_FilterValue, 0, 247, 2, // Skip to: 3527
/* 2768 */    MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 2771 */    MCD_OPC_FilterValue, 2, 5, 0, // Skip to: 2780
/* 2775 */    MCD_OPC_Decode, 209, 1, 138, 1, // Opcode: AsmJHCLR
/* 2780 */    MCD_OPC_FilterValue, 4, 5, 0, // Skip to: 2789
/* 2784 */    MCD_OPC_Decode, 241, 1, 138, 1, // Opcode: AsmJLCLR
/* 2789 */    MCD_OPC_FilterValue, 6, 5, 0, // Skip to: 2798
/* 2793 */    MCD_OPC_Decode, 145, 2, 138, 1, // Opcode: AsmJLHCLR
/* 2798 */    MCD_OPC_FilterValue, 8, 5, 0, // Skip to: 2807
/* 2802 */    MCD_OPC_Decode, 193, 1, 138, 1, // Opcode: AsmJECLR
/* 2807 */    MCD_OPC_FilterValue, 10, 5, 0, // Skip to: 2816
/* 2811 */    MCD_OPC_Decode, 225, 1, 138, 1, // Opcode: AsmJHECLR
/* 2816 */    MCD_OPC_FilterValue, 12, 5, 0, // Skip to: 2825
/* 2820 */    MCD_OPC_Decode, 129, 2, 138, 1, // Opcode: AsmJLECLR
/* 2825 */    MCD_OPC_Decode, 150, 1, 139, 1, // Opcode: AsmCLRJ
/* 2830 */    MCD_OPC_FilterValue, 124, 62, 0, // Skip to: 2896
/* 2834 */    MCD_OPC_ExtractField, 32, 4,  // Inst{35-32} ...
/* 2837 */    MCD_OPC_FilterValue, 2, 5, 0, // Skip to: 2846
/* 2841 */    MCD_OPC_Decode, 203, 1, 140, 1, // Opcode: AsmJHCGI
/* 2846 */    MCD_OPC_FilterValue, 4, 5, 0, // Skip to: 2855
/* 2850 */    MCD_OPC_Decode, 235, 1, 140, 1, // Opcode: AsmJLCGI
/* 2855 */    MCD_OPC_FilterValue, 6, 5, 0, // Skip to: 2864
/* 2859 */    MCD_OPC_Decode, 139, 2, 140, 1, // Opcode: AsmJLHCGI
/* 2864 */    MCD_OPC_FilterValue, 8, 5, 0, // Skip to: 2873
/* 2868 */    MCD_OPC_Decode, 187, 1, 140, 1, // Opcode: AsmJECGI
/* 2873 */    MCD_OPC_FilterValue, 10, 5, 0, // Skip to: 2882
/* 2877 */    MCD_OPC_Decode, 219, 1, 140, 1, // Opcode: AsmJHECGI
/* 2882 */    MCD_OPC_FilterValue, 12, 5, 0, // Skip to: 2891
/* 2886 */    MCD_OPC_Decode, 251, 1, 140, 1, // Opcode: AsmJLECGI
/* 2891 */    MCD_OPC_Decode, 144, 1, 141, 1, // Opcode: AsmCGIJ
/* 2896 */    MCD_OPC_FilterValue, 125, 62, 0, // Skip to: 2962
/* 2900 */    MCD_OPC_ExtractField, 32, 4,  // Inst{35-32} ...
/* 2903 */    MCD_OPC_FilterValue, 2, 5, 0, // Skip to: 2912
/* 2907 */    MCD_OPC_Decode, 206, 1, 142, 1, // Opcode: AsmJHCLGI
/* 2912 */    MCD_OPC_FilterValue, 4, 5, 0, // Skip to: 2921
/* 2916 */    MCD_OPC_Decode, 238, 1, 142, 1, // Opcode: AsmJLCLGI
/* 2921 */    MCD_OPC_FilterValue, 6, 5, 0, // Skip to: 2930
/* 2925 */    MCD_OPC_Decode, 142, 2, 142, 1, // Opcode: AsmJLHCLGI
/* 2930 */    MCD_OPC_FilterValue, 8, 5, 0, // Skip to: 2939
/* 2934 */    MCD_OPC_Decode, 190, 1, 142, 1, // Opcode: AsmJECLGI
/* 2939 */    MCD_OPC_FilterValue, 10, 5, 0, // Skip to: 2948
/* 2943 */    MCD_OPC_Decode, 222, 1, 142, 1, // Opcode: AsmJHECLGI
/* 2948 */    MCD_OPC_FilterValue, 12, 5, 0, // Skip to: 2957
/* 2952 */    MCD_OPC_Decode, 254, 1, 142, 1, // Opcode: AsmJLECLGI
/* 2957 */    MCD_OPC_Decode, 147, 1, 143, 1, // Opcode: AsmCLGIJ
/* 2962 */    MCD_OPC_FilterValue, 126, 62, 0, // Skip to: 3028
/* 2966 */    MCD_OPC_ExtractField, 32, 4,  // Inst{35-32} ...
/* 2969 */    MCD_OPC_FilterValue, 2, 5, 0, // Skip to: 2978
/* 2973 */    MCD_OPC_Decode, 205, 1, 144, 1, // Opcode: AsmJHCI
/* 2978 */    MCD_OPC_FilterValue, 4, 5, 0, // Skip to: 2987
/* 2982 */    MCD_OPC_Decode, 237, 1, 144, 1, // Opcode: AsmJLCI
/* 2987 */    MCD_OPC_FilterValue, 6, 5, 0, // Skip to: 2996
/* 2991 */    MCD_OPC_Decode, 141, 2, 144, 1, // Opcode: AsmJLHCI
/* 2996 */    MCD_OPC_FilterValue, 8, 5, 0, // Skip to: 3005
/* 3000 */    MCD_OPC_Decode, 189, 1, 144, 1, // Opcode: AsmJECI
/* 3005 */    MCD_OPC_FilterValue, 10, 5, 0, // Skip to: 3014
/* 3009 */    MCD_OPC_Decode, 221, 1, 144, 1, // Opcode: AsmJHECI
/* 3014 */    MCD_OPC_FilterValue, 12, 5, 0, // Skip to: 3023
/* 3018 */    MCD_OPC_Decode, 253, 1, 144, 1, // Opcode: AsmJLECI
/* 3023 */    MCD_OPC_Decode, 146, 1, 145, 1, // Opcode: AsmCIJ
/* 3028 */    MCD_OPC_FilterValue, 127, 62, 0, // Skip to: 3094
/* 3032 */    MCD_OPC_ExtractField, 32, 4,  // Inst{35-32} ...
/* 3035 */    MCD_OPC_FilterValue, 2, 5, 0, // Skip to: 3044
/* 3039 */    MCD_OPC_Decode, 208, 1, 146, 1, // Opcode: AsmJHCLI
/* 3044 */    MCD_OPC_FilterValue, 4, 5, 0, // Skip to: 3053
/* 3048 */    MCD_OPC_Decode, 240, 1, 146, 1, // Opcode: AsmJLCLI
/* 3053 */    MCD_OPC_FilterValue, 6, 5, 0, // Skip to: 3062
/* 3057 */    MCD_OPC_Decode, 144, 2, 146, 1, // Opcode: AsmJLHCLI
/* 3062 */    MCD_OPC_FilterValue, 8, 5, 0, // Skip to: 3071
/* 3066 */    MCD_OPC_Decode, 192, 1, 146, 1, // Opcode: AsmJECLI
/* 3071 */    MCD_OPC_FilterValue, 10, 5, 0, // Skip to: 3080
/* 3075 */    MCD_OPC_Decode, 224, 1, 146, 1, // Opcode: AsmJHECLI
/* 3080 */    MCD_OPC_FilterValue, 12, 5, 0, // Skip to: 3089
/* 3084 */    MCD_OPC_Decode, 128, 2, 146, 1, // Opcode: AsmJLECLI
/* 3089 */    MCD_OPC_Decode, 149, 1, 147, 1, // Opcode: AsmCLIJ
/* 3094 */    MCD_OPC_FilterValue, 216, 1, 14, 0, // Skip to: 3113
/* 3099 */    MCD_OPC_CheckPredicate, 2, 168, 1, // Skip to: 3527
/* 3103 */    MCD_OPC_CheckField, 8, 8, 0, 162, 1, // Skip to: 3527
/* 3109 */    MCD_OPC_Decode, 41, 148, 1, // Opcode: AHIK
/* 3113 */    MCD_OPC_FilterValue, 217, 1, 14, 0, // Skip to: 3132
/* 3118 */    MCD_OPC_CheckPredicate, 2, 149, 1, // Skip to: 3527
/* 3122 */    MCD_OPC_CheckField, 8, 8, 0, 143, 1, // Skip to: 3527
/* 3128 */    MCD_OPC_Decode, 35, 149, 1, // Opcode: AGHIK
/* 3132 */    MCD_OPC_FilterValue, 218, 1, 14, 0, // Skip to: 3151
/* 3137 */    MCD_OPC_CheckPredicate, 2, 130, 1, // Skip to: 3527
/* 3141 */    MCD_OPC_CheckField, 8, 8, 0, 124, 1, // Skip to: 3527
/* 3147 */    MCD_OPC_Decode, 59, 148, 1, // Opcode: ALHSIK
/* 3151 */    MCD_OPC_FilterValue, 219, 1, 115, 1, // Skip to: 3527
/* 3156 */    MCD_OPC_CheckPredicate, 2, 111, 1, // Skip to: 3527
/* 3160 */    MCD_OPC_CheckField, 8, 8, 0, 105, 1, // Skip to: 3527
/* 3166 */    MCD_OPC_Decode, 56, 149, 1, // Opcode: ALGHSIK
/* 3170 */    MCD_OPC_FilterValue, 237, 1, 96, 1, // Skip to: 3527
/* 3175 */    MCD_OPC_ExtractField, 0, 8,  // Inst{7-0} ...
/* 3178 */    MCD_OPC_FilterValue, 4, 11, 0, // Skip to: 3193
/* 3182 */    MCD_OPC_CheckField, 8, 8, 0, 83, 1, // Skip to: 3527
/* 3188 */    MCD_OPC_Decode, 191, 4, 150, 1, // Opcode: LDEB
/* 3193 */    MCD_OPC_FilterValue, 5, 11, 0, // Skip to: 3208
/* 3197 */    MCD_OPC_CheckField, 8, 8, 0, 68, 1, // Skip to: 3527
/* 3203 */    MCD_OPC_Decode, 160, 5, 151, 1, // Opcode: LXDB
/* 3208 */    MCD_OPC_FilterValue, 6, 11, 0, // Skip to: 3223
/* 3212 */    MCD_OPC_CheckField, 8, 8, 0, 53, 1, // Skip to: 3527
/* 3218 */    MCD_OPC_Decode, 162, 5, 151, 1, // Opcode: LXEB
/* 3223 */    MCD_OPC_FilterValue, 7, 11, 0, // Skip to: 3238
/* 3227 */    MCD_OPC_CheckField, 8, 8, 0, 38, 1, // Skip to: 3527
/* 3233 */    MCD_OPC_Decode, 209, 5, 152, 1, // Opcode: MXDB
/* 3238 */    MCD_OPC_FilterValue, 9, 11, 0, // Skip to: 3253
/* 3242 */    MCD_OPC_CheckField, 8, 8, 0, 23, 1, // Skip to: 3527
/* 3248 */    MCD_OPC_Decode, 139, 3, 153, 1, // Opcode: CEB
/* 3253 */    MCD_OPC_FilterValue, 10, 10, 0, // Skip to: 3267
/* 3257 */    MCD_OPC_CheckField, 8, 8, 0, 8, 1, // Skip to: 3527
/* 3263 */    MCD_OPC_Decode, 25, 154, 1, // Opcode: AEB
/* 3267 */    MCD_OPC_FilterValue, 11, 11, 0, // Skip to: 3282
/* 3271 */    MCD_OPC_CheckField, 8, 8, 0, 250, 0, // Skip to: 3527
/* 3277 */    MCD_OPC_Decode, 157, 6, 154, 1, // Opcode: SEB
/* 3282 */    MCD_OPC_FilterValue, 12, 11, 0, // Skip to: 3297
/* 3286 */    MCD_OPC_CheckField, 8, 8, 0, 235, 0, // Skip to: 3527
/* 3292 */    MCD_OPC_Decode, 175, 5, 155, 1, // Opcode: MDEB
/* 3297 */    MCD_OPC_FilterValue, 13, 11, 0, // Skip to: 3312
/* 3301 */    MCD_OPC_CheckField, 8, 8, 0, 220, 0, // Skip to: 3527
/* 3307 */    MCD_OPC_Decode, 252, 3, 154, 1, // Opcode: DEB
/* 3312 */    MCD_OPC_FilterValue, 14, 11, 0, // Skip to: 3327
/* 3316 */    MCD_OPC_CheckField, 8, 4, 0, 205, 0, // Skip to: 3527
/* 3322 */    MCD_OPC_Decode, 171, 5, 156, 1, // Opcode: MAEB
/* 3327 */    MCD_OPC_FilterValue, 15, 11, 0, // Skip to: 3342
/* 3331 */    MCD_OPC_CheckField, 8, 4, 0, 190, 0, // Skip to: 3527
/* 3337 */    MCD_OPC_Decode, 188, 5, 156, 1, // Opcode: MSEB
/* 3342 */    MCD_OPC_FilterValue, 20, 11, 0, // Skip to: 3357
/* 3346 */    MCD_OPC_CheckField, 8, 8, 0, 175, 0, // Skip to: 3527
/* 3352 */    MCD_OPC_Decode, 186, 6, 153, 1, // Opcode: SQEB
/* 3357 */    MCD_OPC_FilterValue, 21, 11, 0, // Skip to: 3372
/* 3361 */    MCD_OPC_CheckField, 8, 8, 0, 160, 0, // Skip to: 3527
/* 3367 */    MCD_OPC_Decode, 184, 6, 150, 1, // Opcode: SQDB
/* 3372 */    MCD_OPC_FilterValue, 23, 11, 0, // Skip to: 3387
/* 3376 */    MCD_OPC_CheckField, 8, 8, 0, 145, 0, // Skip to: 3527
/* 3382 */    MCD_OPC_Decode, 177, 5, 154, 1, // Opcode: MEEB
/* 3387 */    MCD_OPC_FilterValue, 25, 11, 0, // Skip to: 3402
/* 3391 */    MCD_OPC_CheckField, 8, 8, 0, 130, 0, // Skip to: 3527
/* 3397 */    MCD_OPC_Decode, 133, 3, 150, 1, // Opcode: CDB
/* 3402 */    MCD_OPC_FilterValue, 26, 10, 0, // Skip to: 3416
/* 3406 */    MCD_OPC_CheckField, 8, 8, 0, 115, 0, // Skip to: 3527
/* 3412 */    MCD_OPC_Decode, 20, 155, 1, // Opcode: ADB
/* 3416 */    MCD_OPC_FilterValue, 27, 11, 0, // Skip to: 3431
/* 3420 */    MCD_OPC_CheckField, 8, 8, 0, 101, 0, // Skip to: 3527
/* 3426 */    MCD_OPC_Decode, 155, 6, 155, 1, // Opcode: SDB
/* 3431 */    MCD_OPC_FilterValue, 28, 11, 0, // Skip to: 3446
/* 3435 */    MCD_OPC_CheckField, 8, 8, 0, 86, 0, // Skip to: 3527
/* 3441 */    MCD_OPC_Decode, 173, 5, 155, 1, // Opcode: MDB
/* 3446 */    MCD_OPC_FilterValue, 29, 11, 0, // Skip to: 3461
/* 3450 */    MCD_OPC_CheckField, 8, 8, 0, 71, 0, // Skip to: 3527
/* 3456 */    MCD_OPC_Decode, 250, 3, 155, 1, // Opcode: DDB
/* 3461 */    MCD_OPC_FilterValue, 30, 11, 0, // Skip to: 3476
/* 3465 */    MCD_OPC_CheckField, 8, 4, 0, 56, 0, // Skip to: 3527
/* 3471 */    MCD_OPC_Decode, 169, 5, 157, 1, // Opcode: MADB
/* 3476 */    MCD_OPC_FilterValue, 31, 11, 0, // Skip to: 3491
/* 3480 */    MCD_OPC_CheckField, 8, 4, 0, 41, 0, // Skip to: 3527
/* 3486 */    MCD_OPC_Decode, 186, 5, 157, 1, // Opcode: MSDB
/* 3491 */    MCD_OPC_FilterValue, 100, 5, 0, // Skip to: 3500
/* 3495 */    MCD_OPC_Decode, 201, 4, 158, 1, // Opcode: LEY
/* 3500 */    MCD_OPC_FilterValue, 101, 5, 0, // Skip to: 3509
/* 3504 */    MCD_OPC_Decode, 196, 4, 159, 1, // Opcode: LDY
/* 3509 */    MCD_OPC_FilterValue, 102, 5, 0, // Skip to: 3518
/* 3513 */    MCD_OPC_Decode, 208, 6, 158, 1, // Opcode: STEY
/* 3518 */    MCD_OPC_FilterValue, 103, 5, 0, // Skip to: 3527
/* 3522 */    MCD_OPC_Decode, 206, 6, 159, 1, // Opcode: STDY
/* 3527 */    MCD_OPC_Fail,
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
    return getbool(Bits & SystemZ_FeatureFPExtension);
  case 1:
    return getbool(Bits & SystemZ_FeatureLoadStoreOnCond);
  case 2:
    return getbool(Bits & SystemZ_FeatureDistinctOps);
  case 3:
    return getbool(Bits & SystemZ_FeatureHighWord);
  case 4:
    return getbool(Bits & SystemZ_FeatureInterlockedAccess1);
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
    tmp = fieldname(insn, 0, 4); \
    if (DecodeADDR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 1: \
    tmp = fieldname(insn, 4, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 2: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeADDR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 3: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 4: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 5: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 6: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 7: \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 20); \
    if (decodeBDXAddr64Disp12Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 8: \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 20); \
    if (decodeBDXAddr64Disp12Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 9: \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 20); \
    if (decodeBDXAddr64Disp12Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 10: \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 20); \
    if (decodeBDXAddr64Disp12Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 11: \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 20); \
    if (decodeBDXAddr64Disp12Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 12: \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 20); \
    if (decodeBDXAddr64Disp12Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 13: \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeBDAddr32Disp12Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 14: \
    tmp = fieldname(insn, 0, 16); \
    if (decodeBDAddr64Disp12Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 8); \
    if (decodeU8ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 15: \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGRH32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGRH32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeU16ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 16: \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeU16ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 17: \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeU16ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 18: \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeU16ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 19: \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGRH32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeU16ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 20: \
    tmp = fieldname(insn, 0, 16); \
    if (decodePC16DBLOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 21: \
    tmp = fieldname(insn, 20, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodePC16DBLOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 22: \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodePC16DBLOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 23: \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodePC16DBLOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 24: \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodePC16DBLOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 25: \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeS16ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 26: \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeS16ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 27: \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeS16ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 28: \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeS16ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 29: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 30: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (decodeAccessRegOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 31: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 32: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 33: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 34: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 35: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 36: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 37: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 38: \
    tmp = fieldname(insn, 12, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 39: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 40: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 41: \
    tmp = fieldname(insn, 12, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 42: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 43: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 44: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 45: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 46: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 47: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 48: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 49: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 50: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 51: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 52: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 53: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 54: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 55: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 56: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 57: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 58: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 59: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 60: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 61: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 62: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 63: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 64: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 65: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 66: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 67: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 68: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 69: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 70: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 71: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 72: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 73: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 74: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 75: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 76: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 77: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 78: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 79: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 80: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 81: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 82: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 83: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 84: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 85: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 86: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 87: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 88: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 89: \
    tmp = fieldname(insn, 4, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 90: \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 20, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeBDAddr64Disp12Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 91: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 32); \
    if (decodePC32DBLOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 92: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 32); \
    if (decodeS32ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 93: \
    tmp = fieldname(insn, 0, 32); \
    if (decodePC32DBLOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 94: \
    tmp = fieldname(insn, 36, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 32); \
    if (decodePC32DBLOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 95: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGRH32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGRH32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 32); \
    if (decodeU32ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 96: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 32); \
    if (decodeU32ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 97: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGRH32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 32); \
    if (decodeU32ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 98: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 32); \
    if (decodeU32ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 99: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 32); \
    if (decodeU32ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 100: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 32); \
    if (decodeS32ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 101: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 32); \
    if (decodeS32ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 102: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 32); \
    if (decodeU32ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 103: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 32); \
    if (decodeS32ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 104: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 32); \
    if (decodePC32DBLOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 105: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGRH32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGRH32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 32); \
    if (decodeS32ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 106: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGRH32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 32); \
    if (decodeS32ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 107: \
    tmp = fieldname(insn, 16, 24); \
    if (decodeBDLAddr64Disp12Len8Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeBDAddr64Disp12Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 108: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 28); \
    if (decodeBDXAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 109: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 28); \
    if (decodeBDXAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 110: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 28); \
    if (decodeBDXAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 111: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 28); \
    if (decodeBDXAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 112: \
    tmp = fieldname(insn, 36, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 28); \
    if (decodeBDXAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 113: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 28); \
    if (decodeBDXAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 114: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGRH32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 28); \
    if (decodeBDXAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 115: \
    tmp = fieldname(insn, 16, 16); \
    if (decodeBDAddr64Disp12Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeS16ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 116: \
    tmp = fieldname(insn, 16, 16); \
    if (decodeBDAddr64Disp12Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeU16ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 117: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 24); \
    if (decodeBDAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 118: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 24); \
    if (decodeBDAddr32Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 119: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 24); \
    if (decodeBDAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 120: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 24); \
    if (decodeBDAddr32Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 121: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 24); \
    if (decodeBDAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 122: \
    tmp = fieldname(insn, 8, 24); \
    if (decodeBDAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 8); \
    if (decodeU8ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 123: \
    tmp = fieldname(insn, 8, 24); \
    if (decodeBDAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 8); \
    if (decodeS8ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 124: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 24); \
    if (decodeBDAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 125: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 24); \
    if (decodeBDAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 126: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 24); \
    if (decodeBDAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 127: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 24); \
    if (decodeBDAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 128: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 24); \
    if (decodeBDAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 129: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 24); \
    if (decodeBDAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 130: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 24); \
    if (decodeBDAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 131: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 24); \
    if (decodeBDAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 132: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 24); \
    if (decodeBDAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 133: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 24, 8); \
    if (decodeU8ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 8); \
    if (decodeU8ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 8); \
    if (decodeU6ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 134: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 24, 8); \
    if (decodeU8ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 8); \
    if (decodeU8ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 8); \
    if (decodeU6ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 135: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGRH32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGRH32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 24, 8); \
    if (decodeU8ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 8); \
    if (decodeU8ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 8); \
    if (decodeU6ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 136: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 16); \
    if (decodePC16DBLOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 137: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 16); \
    if (decodePC16DBLOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 138: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 16); \
    if (decodePC16DBLOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 139: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 16); \
    if (decodePC16DBLOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 140: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 8); \
    if (decodeS8ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 16); \
    if (decodePC16DBLOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 141: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 8); \
    if (decodeS8ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 16); \
    if (decodePC16DBLOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 142: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 8); \
    if (decodeU8ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 16); \
    if (decodePC16DBLOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 143: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 8); \
    if (decodeU8ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 16); \
    if (decodePC16DBLOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 144: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 8); \
    if (decodeS8ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 16); \
    if (decodePC16DBLOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 145: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 8); \
    if (decodeS8ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 16); \
    if (decodePC16DBLOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 146: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 8); \
    if (decodeU8ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 16); \
    if (decodePC16DBLOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 147: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 8); \
    if (decodeU8ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (decodeU4ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 16); \
    if (decodePC16DBLOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 148: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (DecodeGR32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 16); \
    if (decodeS16ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 149: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 32, 4); \
    if (DecodeGR64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 16); \
    if (decodeS16ImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 150: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 20); \
    if (decodeBDXAddr64Disp12Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 151: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 20); \
    if (decodeBDXAddr64Disp12Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 152: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeFP128BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 20); \
    if (decodeBDXAddr64Disp12Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 153: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 20); \
    if (decodeBDXAddr64Disp12Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 154: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 20); \
    if (decodeBDXAddr64Disp12Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 155: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 20); \
    if (decodeBDXAddr64Disp12Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 156: \
    tmp = fieldname(insn, 12, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 20); \
    if (decodeBDXAddr64Disp12Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 157: \
    tmp = fieldname(insn, 12, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 20); \
    if (decodeBDXAddr64Disp12Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 158: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeFP32BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 28); \
    if (decodeBDXAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 159: \
    tmp = fieldname(insn, 36, 4); \
    if (DecodeFP64BitRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 28); \
    if (decodeBDXAddr64Disp20Operand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
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
  unsigned Len, Start, NumToSkip, PIdx, Opc, DecodeIdx; \
  InsnType FieldValue, Val, PositiveMask, NegativeMask; \
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

FieldFromInstruction(fieldFromInstruction, uint64_t)
DecodeToMCInst(decodeToMCInst, fieldFromInstruction, uint64_t)
DecodeInstruction(decodeInstruction, fieldFromInstruction, decodeToMCInst, uint64_t)
