/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* * TriCore Disassembler                                                     *|
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
/* 0 */       MCD_OPC_ExtractField, 0, 8,  // Inst{7-0} ...
/* 3 */       MCD_OPC_FilterValue, 22, 3, 0, // Skip to: 10
/* 7 */       MCD_OPC_Decode, 55, 0, // Opcode: ANDsc
/* 10 */      MCD_OPC_FilterValue, 32, 4, 0, // Skip to: 18
/* 14 */      MCD_OPC_Decode, 136, 1, 0, // Opcode: SUB_Asc
/* 18 */      MCD_OPC_FilterValue, 38, 3, 0, // Skip to: 25
/* 22 */      MCD_OPC_Decode, 56, 1, // Opcode: ANDsrr
/* 25 */      MCD_OPC_FilterValue, 50, 3, 0, // Skip to: 32
/* 29 */      MCD_OPC_Decode, 123, 2, // Opcode: RSUBsr
/* 32 */      MCD_OPC_FilterValue, 64, 3, 0, // Skip to: 39
/* 36 */      MCD_OPC_Decode, 82, 1, // Opcode: MOV_AAsrr
/* 39 */      MCD_OPC_FilterValue, 66, 3, 0, // Skip to: 46
/* 43 */      MCD_OPC_Decode, 35, 1, // Opcode: ADDsrr
/* 46 */      MCD_OPC_FilterValue, 70, 3, 0, // Skip to: 53
/* 50 */      MCD_OPC_Decode, 100, 2, // Opcode: NOTsr
/* 53 */      MCD_OPC_FilterValue, 110, 3, 0, // Skip to: 60
/* 57 */      MCD_OPC_Decode, 68, 3, // Opcode: JZsb
/* 60 */      MCD_OPC_FilterValue, 118, 3, 0, // Skip to: 67
/* 64 */      MCD_OPC_Decode, 69, 4, // Opcode: JZsbr
/* 67 */      MCD_OPC_FilterValue, 130, 1, 3, 0, // Skip to: 75
/* 72 */      MCD_OPC_Decode, 89, 5, // Opcode: MOVsrc
/* 75 */      MCD_OPC_FilterValue, 150, 1, 3, 0, // Skip to: 83
/* 80 */      MCD_OPC_Decode, 118, 0, // Opcode: ORsc
/* 83 */      MCD_OPC_FilterValue, 166, 1, 3, 0, // Skip to: 91
/* 88 */      MCD_OPC_Decode, 119, 1, // Opcode: ORsrr
/* 91 */      MCD_OPC_FilterValue, 194, 1, 3, 0, // Skip to: 99
/* 96 */      MCD_OPC_Decode, 34, 5, // Opcode: ADDsrc
/* 99 */      MCD_OPC_FilterValue, 198, 1, 4, 0, // Skip to: 108
/* 104 */     MCD_OPC_Decode, 156, 1, 1, // Opcode: XORsrr
/* 108 */     MCD_OPC_FilterValue, 226, 1, 3, 0, // Skip to: 116
/* 113 */     MCD_OPC_Decode, 92, 1, // Opcode: MULsrr
/* 116 */     MCD_OPC_FilterValue, 238, 1, 3, 0, // Skip to: 124
/* 121 */     MCD_OPC_Decode, 66, 3, // Opcode: JNZsb
/* 124 */     MCD_OPC_FilterValue, 246, 1, 3, 0, // Skip to: 132
/* 129 */     MCD_OPC_Decode, 67, 4, // Opcode: JNZsbr
/* 132 */     MCD_OPC_Fail,
  0
};

static uint8_t DecoderTable32[] = {
/* 0 */       MCD_OPC_ExtractField, 0, 8,  // Inst{7-0} ...
/* 3 */       MCD_OPC_FilterValue, 1, 41, 0, // Skip to: 48
/* 7 */       MCD_OPC_ExtractField, 18, 10,  // Inst{27-18} ...
/* 10 */      MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 17
/* 14 */      MCD_OPC_Decode, 81, 6, // Opcode: MOV_AArr
/* 17 */      MCD_OPC_FilterValue, 4, 3, 0, // Skip to: 24
/* 21 */      MCD_OPC_Decode, 29, 6, // Opcode: ADD_Arr
/* 24 */      MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 32
/* 28 */      MCD_OPC_Decode, 135, 1, 6, // Opcode: SUB_Arr
/* 32 */      MCD_OPC_FilterValue, 176, 2, 3, 0, // Skip to: 40
/* 37 */      MCD_OPC_Decode, 84, 6, // Opcode: MOV_Drr
/* 40 */      MCD_OPC_FilterValue, 140, 3, 123, 3, // Skip to: 936
/* 45 */      MCD_OPC_Decode, 83, 6, // Opcode: MOV_Arr
/* 48 */      MCD_OPC_FilterValue, 9, 45, 0, // Skip to: 97
/* 52 */      MCD_OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 55 */      MCD_OPC_FilterValue, 32, 3, 0, // Skip to: 62
/* 59 */      MCD_OPC_Decode, 72, 7, // Opcode: LD_Bbo
/* 62 */      MCD_OPC_FilterValue, 33, 3, 0, // Skip to: 69
/* 66 */      MCD_OPC_Decode, 71, 7, // Opcode: LD_BUbo
/* 69 */      MCD_OPC_FilterValue, 34, 3, 0, // Skip to: 76
/* 73 */      MCD_OPC_Decode, 75, 7, // Opcode: LD_Hbo
/* 76 */      MCD_OPC_FilterValue, 35, 3, 0, // Skip to: 83
/* 80 */      MCD_OPC_Decode, 74, 7, // Opcode: LD_HUbo
/* 83 */      MCD_OPC_FilterValue, 36, 3, 0, // Skip to: 90
/* 87 */      MCD_OPC_Decode, 76, 7, // Opcode: LD_Wbo
/* 90 */      MCD_OPC_FilterValue, 37, 74, 3, // Skip to: 936
/* 94 */      MCD_OPC_Decode, 73, 7, // Opcode: LD_Dbo
/* 97 */      MCD_OPC_FilterValue, 11, 89, 1, // Skip to: 446
/* 101 */     MCD_OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 104 */     MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 117
/* 108 */     MCD_OPC_CheckField, 18, 3, 0, 54, 3, // Skip to: 936
/* 114 */     MCD_OPC_Decode, 33, 6, // Opcode: ADDrr
/* 117 */     MCD_OPC_FilterValue, 2, 17, 0, // Skip to: 138
/* 121 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 124 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 131
/* 128 */     MCD_OPC_Decode, 28, 6, // Opcode: ADDXrr
/* 131 */     MCD_OPC_FilterValue, 4, 33, 3, // Skip to: 936
/* 135 */     MCD_OPC_Decode, 25, 6, // Opcode: ADDCrr
/* 138 */     MCD_OPC_FilterValue, 4, 3, 0, // Skip to: 145
/* 142 */     MCD_OPC_Decode, 27, 8, // Opcode: ADDXrc
/* 145 */     MCD_OPC_FilterValue, 6, 19, 0, // Skip to: 168
/* 149 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 152 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 160
/* 156 */     MCD_OPC_Decode, 134, 1, 6, // Opcode: SUBXrr
/* 160 */     MCD_OPC_FilterValue, 4, 4, 3, // Skip to: 936
/* 164 */     MCD_OPC_Decode, 133, 1, 6, // Opcode: SUBCrr
/* 168 */     MCD_OPC_FilterValue, 8, 17, 0, // Skip to: 189
/* 172 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 175 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 182
/* 179 */     MCD_OPC_Decode, 61, 6, // Opcode: EQrr
/* 182 */     MCD_OPC_FilterValue, 4, 238, 2, // Skip to: 936
/* 186 */     MCD_OPC_Decode, 96, 6, // Opcode: NErr
/* 189 */     MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 202
/* 193 */     MCD_OPC_CheckField, 18, 3, 0, 225, 2, // Skip to: 936
/* 199 */     MCD_OPC_Decode, 79, 6, // Opcode: LTrr
/* 202 */     MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 215
/* 206 */     MCD_OPC_CheckField, 18, 3, 0, 212, 2, // Skip to: 936
/* 212 */     MCD_OPC_Decode, 64, 6, // Opcode: GErr
/* 215 */     MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 228
/* 219 */     MCD_OPC_CheckField, 18, 3, 0, 199, 2, // Skip to: 936
/* 225 */     MCD_OPC_Decode, 23, 6, // Opcode: ABS
/* 228 */     MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 241
/* 232 */     MCD_OPC_CheckField, 18, 3, 4, 186, 2, // Skip to: 936
/* 238 */     MCD_OPC_Decode, 88, 6, // Opcode: MOVrr
/* 241 */     MCD_OPC_FilterValue, 16, 17, 0, // Skip to: 262
/* 245 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 248 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 255
/* 252 */     MCD_OPC_Decode, 41, 6, // Opcode: AND_EQrr
/* 255 */     MCD_OPC_FilterValue, 4, 165, 2, // Skip to: 936
/* 259 */     MCD_OPC_Decode, 51, 6, // Opcode: AND_NErr
/* 262 */     MCD_OPC_FilterValue, 17, 17, 0, // Skip to: 283
/* 266 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 269 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 276
/* 273 */     MCD_OPC_Decode, 49, 6, // Opcode: AND_LTrr
/* 276 */     MCD_OPC_FilterValue, 4, 144, 2, // Skip to: 936
/* 280 */     MCD_OPC_Decode, 47, 6, // Opcode: AND_LT_Urr
/* 283 */     MCD_OPC_FilterValue, 18, 17, 0, // Skip to: 304
/* 287 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 290 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 297
/* 294 */     MCD_OPC_Decode, 45, 6, // Opcode: AND_GErr
/* 297 */     MCD_OPC_FilterValue, 4, 123, 2, // Skip to: 936
/* 301 */     MCD_OPC_Decode, 43, 6, // Opcode: AND_GE_Urr
/* 304 */     MCD_OPC_FilterValue, 19, 9, 0, // Skip to: 317
/* 308 */     MCD_OPC_CheckField, 18, 3, 4, 110, 2, // Skip to: 936
/* 314 */     MCD_OPC_Decode, 104, 6, // Opcode: OR_EQrr
/* 317 */     MCD_OPC_FilterValue, 20, 17, 0, // Skip to: 338
/* 321 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 324 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 331
/* 328 */     MCD_OPC_Decode, 114, 6, // Opcode: OR_NErr
/* 331 */     MCD_OPC_FilterValue, 4, 89, 2, // Skip to: 936
/* 335 */     MCD_OPC_Decode, 112, 6, // Opcode: OR_LTrr
/* 338 */     MCD_OPC_FilterValue, 21, 17, 0, // Skip to: 359
/* 342 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 345 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 352
/* 349 */     MCD_OPC_Decode, 110, 6, // Opcode: OR_LT_Urr
/* 352 */     MCD_OPC_FilterValue, 4, 68, 2, // Skip to: 936
/* 356 */     MCD_OPC_Decode, 108, 6, // Opcode: OR_GErr
/* 359 */     MCD_OPC_FilterValue, 22, 9, 0, // Skip to: 372
/* 363 */     MCD_OPC_CheckField, 18, 3, 0, 55, 2, // Skip to: 936
/* 369 */     MCD_OPC_Decode, 106, 6, // Opcode: OR_GE_Urr
/* 372 */     MCD_OPC_FilterValue, 23, 10, 0, // Skip to: 386
/* 376 */     MCD_OPC_CheckField, 18, 3, 4, 42, 2, // Skip to: 936
/* 382 */     MCD_OPC_Decode, 141, 1, 6, // Opcode: XOR_EQrr
/* 386 */     MCD_OPC_FilterValue, 24, 19, 0, // Skip to: 409
/* 390 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 393 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 401
/* 397 */     MCD_OPC_Decode, 151, 1, 6, // Opcode: XOR_NErr
/* 401 */     MCD_OPC_FilterValue, 4, 19, 2, // Skip to: 936
/* 405 */     MCD_OPC_Decode, 149, 1, 6, // Opcode: XOR_LTrr
/* 409 */     MCD_OPC_FilterValue, 25, 19, 0, // Skip to: 432
/* 413 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 416 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 424
/* 420 */     MCD_OPC_Decode, 147, 1, 6, // Opcode: XOR_LT_Urr
/* 424 */     MCD_OPC_FilterValue, 4, 252, 1, // Skip to: 936
/* 428 */     MCD_OPC_Decode, 145, 1, 6, // Opcode: XOR_GErr
/* 432 */     MCD_OPC_FilterValue, 26, 244, 1, // Skip to: 936
/* 436 */     MCD_OPC_CheckField, 18, 3, 0, 238, 1, // Skip to: 936
/* 442 */     MCD_OPC_Decode, 143, 1, 6, // Opcode: XOR_GE_Urr
/* 446 */     MCD_OPC_FilterValue, 15, 53, 0, // Skip to: 503
/* 450 */     MCD_OPC_ExtractField, 18, 10,  // Inst{27-18} ...
/* 453 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 460
/* 457 */     MCD_OPC_Decode, 127, 6, // Opcode: SHrr
/* 460 */     MCD_OPC_FilterValue, 4, 3, 0, // Skip to: 467
/* 464 */     MCD_OPC_Decode, 125, 6, // Opcode: SHArr
/* 467 */     MCD_OPC_FilterValue, 32, 3, 0, // Skip to: 474
/* 471 */     MCD_OPC_Decode, 54, 6, // Opcode: ANDrr
/* 474 */     MCD_OPC_FilterValue, 36, 3, 0, // Skip to: 481
/* 478 */     MCD_OPC_Decode, 94, 6, // Opcode: NANDrr
/* 481 */     MCD_OPC_FilterValue, 40, 3, 0, // Skip to: 488
/* 485 */     MCD_OPC_Decode, 117, 6, // Opcode: ORrr
/* 488 */     MCD_OPC_FilterValue, 44, 3, 0, // Skip to: 495
/* 492 */     MCD_OPC_Decode, 98, 6, // Opcode: NORrr
/* 495 */     MCD_OPC_FilterValue, 48, 181, 1, // Skip to: 936
/* 499 */     MCD_OPC_Decode, 155, 1, 6, // Opcode: XORrr
/* 503 */     MCD_OPC_FilterValue, 25, 3, 0, // Skip to: 510
/* 507 */     MCD_OPC_Decode, 77, 9, // Opcode: LD_Wbol
/* 510 */     MCD_OPC_FilterValue, 27, 3, 0, // Skip to: 517
/* 514 */     MCD_OPC_Decode, 26, 10, // Opcode: ADDIrlc
/* 517 */     MCD_OPC_FilterValue, 29, 3, 0, // Skip to: 524
/* 521 */     MCD_OPC_Decode, 70, 11, // Opcode: Jb
/* 524 */     MCD_OPC_FilterValue, 55, 9, 0, // Skip to: 537
/* 528 */     MCD_OPC_CheckField, 21, 2, 2, 146, 1, // Skip to: 936
/* 534 */     MCD_OPC_Decode, 62, 12, // Opcode: EXTRrrpw
/* 537 */     MCD_OPC_FilterValue, 59, 3, 0, // Skip to: 544
/* 541 */     MCD_OPC_Decode, 87, 10, // Opcode: MOVrlc
/* 544 */     MCD_OPC_FilterValue, 83, 9, 0, // Skip to: 557
/* 548 */     MCD_OPC_CheckField, 21, 7, 1, 126, 1, // Skip to: 936
/* 554 */     MCD_OPC_Decode, 90, 8, // Opcode: MULrc
/* 557 */     MCD_OPC_FilterValue, 109, 3, 0, // Skip to: 564
/* 561 */     MCD_OPC_Decode, 58, 11, // Opcode: CALLb
/* 564 */     MCD_OPC_FilterValue, 115, 9, 0, // Skip to: 577
/* 568 */     MCD_OPC_CheckField, 16, 12, 10, 106, 1, // Skip to: 936
/* 574 */     MCD_OPC_Decode, 91, 13, // Opcode: MULrr2
/* 577 */     MCD_OPC_FilterValue, 119, 9, 0, // Skip to: 590
/* 581 */     MCD_OPC_CheckField, 21, 2, 0, 93, 1, // Skip to: 936
/* 587 */     MCD_OPC_Decode, 59, 12, // Opcode: DEXTRrrpw
/* 590 */     MCD_OPC_FilterValue, 123, 3, 0, // Skip to: 597
/* 594 */     MCD_OPC_Decode, 80, 10, // Opcode: MOVHrlc
/* 597 */     MCD_OPC_FilterValue, 137, 1, 43, 0, // Skip to: 645
/* 602 */     MCD_OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 605 */     MCD_OPC_FilterValue, 32, 4, 0, // Skip to: 613
/* 609 */     MCD_OPC_Decode, 129, 1, 7, // Opcode: ST_Bbo
/* 613 */     MCD_OPC_FilterValue, 34, 4, 0, // Skip to: 621
/* 617 */     MCD_OPC_Decode, 131, 1, 7, // Opcode: ST_Hbo
/* 621 */     MCD_OPC_FilterValue, 36, 4, 0, // Skip to: 629
/* 625 */     MCD_OPC_Decode, 132, 1, 7, // Opcode: ST_Wbo
/* 629 */     MCD_OPC_FilterValue, 37, 4, 0, // Skip to: 637
/* 633 */     MCD_OPC_Decode, 130, 1, 7, // Opcode: ST_Dbo
/* 637 */     MCD_OPC_FilterValue, 38, 39, 1, // Skip to: 936
/* 641 */     MCD_OPC_Decode, 128, 1, 7, // Opcode: ST_Abo
/* 645 */     MCD_OPC_FilterValue, 139, 1, 184, 0, // Skip to: 834
/* 650 */     MCD_OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 653 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 660
/* 657 */     MCD_OPC_Decode, 32, 8, // Opcode: ADDrc
/* 660 */     MCD_OPC_FilterValue, 5, 3, 0, // Skip to: 667
/* 664 */     MCD_OPC_Decode, 24, 8, // Opcode: ADDCrc
/* 667 */     MCD_OPC_FilterValue, 8, 3, 0, // Skip to: 674
/* 671 */     MCD_OPC_Decode, 122, 8, // Opcode: RSUBrc
/* 674 */     MCD_OPC_FilterValue, 16, 3, 0, // Skip to: 681
/* 678 */     MCD_OPC_Decode, 60, 8, // Opcode: EQrc
/* 681 */     MCD_OPC_FilterValue, 17, 3, 0, // Skip to: 688
/* 685 */     MCD_OPC_Decode, 95, 8, // Opcode: NErc
/* 688 */     MCD_OPC_FilterValue, 18, 3, 0, // Skip to: 695
/* 692 */     MCD_OPC_Decode, 78, 8, // Opcode: LTrc
/* 695 */     MCD_OPC_FilterValue, 20, 3, 0, // Skip to: 702
/* 699 */     MCD_OPC_Decode, 63, 8, // Opcode: GErc
/* 702 */     MCD_OPC_FilterValue, 32, 3, 0, // Skip to: 709
/* 706 */     MCD_OPC_Decode, 40, 8, // Opcode: AND_EQrc
/* 709 */     MCD_OPC_FilterValue, 33, 3, 0, // Skip to: 716
/* 713 */     MCD_OPC_Decode, 50, 8, // Opcode: AND_NErc
/* 716 */     MCD_OPC_FilterValue, 34, 3, 0, // Skip to: 723
/* 720 */     MCD_OPC_Decode, 48, 8, // Opcode: AND_LTrc
/* 723 */     MCD_OPC_FilterValue, 35, 3, 0, // Skip to: 730
/* 727 */     MCD_OPC_Decode, 46, 8, // Opcode: AND_LT_Urc
/* 730 */     MCD_OPC_FilterValue, 36, 3, 0, // Skip to: 737
/* 734 */     MCD_OPC_Decode, 44, 8, // Opcode: AND_GErc
/* 737 */     MCD_OPC_FilterValue, 37, 3, 0, // Skip to: 744
/* 741 */     MCD_OPC_Decode, 42, 8, // Opcode: AND_GE_Urc
/* 744 */     MCD_OPC_FilterValue, 39, 3, 0, // Skip to: 751
/* 748 */     MCD_OPC_Decode, 103, 8, // Opcode: OR_EQrc
/* 751 */     MCD_OPC_FilterValue, 40, 3, 0, // Skip to: 758
/* 755 */     MCD_OPC_Decode, 113, 8, // Opcode: OR_NErc
/* 758 */     MCD_OPC_FilterValue, 41, 3, 0, // Skip to: 765
/* 762 */     MCD_OPC_Decode, 111, 8, // Opcode: OR_LTrc
/* 765 */     MCD_OPC_FilterValue, 42, 3, 0, // Skip to: 772
/* 769 */     MCD_OPC_Decode, 109, 8, // Opcode: OR_LT_Urc
/* 772 */     MCD_OPC_FilterValue, 43, 3, 0, // Skip to: 779
/* 776 */     MCD_OPC_Decode, 107, 8, // Opcode: OR_GErc
/* 779 */     MCD_OPC_FilterValue, 44, 3, 0, // Skip to: 786
/* 783 */     MCD_OPC_Decode, 105, 8, // Opcode: OR_GE_Urc
/* 786 */     MCD_OPC_FilterValue, 47, 4, 0, // Skip to: 794
/* 790 */     MCD_OPC_Decode, 140, 1, 8, // Opcode: XOR_EQrc
/* 794 */     MCD_OPC_FilterValue, 48, 4, 0, // Skip to: 802
/* 798 */     MCD_OPC_Decode, 150, 1, 8, // Opcode: XOR_NErc
/* 802 */     MCD_OPC_FilterValue, 49, 4, 0, // Skip to: 810
/* 806 */     MCD_OPC_Decode, 148, 1, 8, // Opcode: XOR_LTrc
/* 810 */     MCD_OPC_FilterValue, 50, 4, 0, // Skip to: 818
/* 814 */     MCD_OPC_Decode, 146, 1, 8, // Opcode: XOR_LT_Urc
/* 818 */     MCD_OPC_FilterValue, 51, 4, 0, // Skip to: 826
/* 822 */     MCD_OPC_Decode, 144, 1, 8, // Opcode: XOR_GErc
/* 826 */     MCD_OPC_FilterValue, 52, 106, 0, // Skip to: 936
/* 830 */     MCD_OPC_Decode, 142, 1, 8, // Opcode: XOR_GE_Urc
/* 834 */     MCD_OPC_FilterValue, 143, 1, 75, 0, // Skip to: 914
/* 839 */     MCD_OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 842 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 849
/* 846 */     MCD_OPC_Decode, 126, 8, // Opcode: SHrc
/* 849 */     MCD_OPC_FilterValue, 1, 3, 0, // Skip to: 856
/* 853 */     MCD_OPC_Decode, 124, 8, // Opcode: SHArc
/* 856 */     MCD_OPC_FilterValue, 8, 3, 0, // Skip to: 863
/* 860 */     MCD_OPC_Decode, 52, 8, // Opcode: ANDrc
/* 863 */     MCD_OPC_FilterValue, 9, 3, 0, // Skip to: 870
/* 867 */     MCD_OPC_Decode, 93, 8, // Opcode: NANDrc
/* 870 */     MCD_OPC_FilterValue, 10, 3, 0, // Skip to: 877
/* 874 */     MCD_OPC_Decode, 115, 8, // Opcode: ORrc
/* 877 */     MCD_OPC_FilterValue, 11, 3, 0, // Skip to: 884
/* 881 */     MCD_OPC_Decode, 97, 8, // Opcode: NORrc
/* 884 */     MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 892
/* 888 */     MCD_OPC_Decode, 152, 1, 8, // Opcode: XORrc
/* 892 */     MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 900
/* 896 */     MCD_OPC_Decode, 139, 1, 8, // Opcode: XNORrc
/* 900 */     MCD_OPC_FilterValue, 14, 3, 0, // Skip to: 907
/* 904 */     MCD_OPC_Decode, 38, 8, // Opcode: ANDNrc
/* 907 */     MCD_OPC_FilterValue, 15, 25, 0, // Skip to: 936
/* 911 */     MCD_OPC_Decode, 101, 8, // Opcode: ORNrc
/* 914 */     MCD_OPC_FilterValue, 183, 1, 9, 0, // Skip to: 928
/* 919 */     MCD_OPC_CheckField, 21, 2, 1, 11, 0, // Skip to: 936
/* 925 */     MCD_OPC_Decode, 65, 14, // Opcode: IMASKrcpw
/* 928 */     MCD_OPC_FilterValue, 187, 1, 3, 0, // Skip to: 936
/* 933 */     MCD_OPC_Decode, 85, 10, // Opcode: MOV_Urlc
/* 936 */     MCD_OPC_Fail,
  0
};

static bool checkDecoderPredicate(unsigned Idx, uint64_t Bits)
{
  return true;  //llvm_unreachable("Invalid index!");
}

#define DecodeToMCInst(fname,fieldname, InsnType) \
static DecodeStatus fname(DecodeStatus S, unsigned Idx, InsnType insn, MCInst *MI, \
                uint64_t Address, void *Decoder) \
{ \
  switch (Idx) { \
  default: \
  case 0: \
    if (DecodeSCInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 1: \
    if (DecodeSRRInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 2: \
    if (DecodeSRInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 3: \
    if (DecodeSBInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 4: \
    if (DecodeSBRInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 5: \
    if (DecodeSRCInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 6: \
    if (DecodeRRInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 7: \
    if (DecodeBOInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 8: \
    if (DecodeRCInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 9: \
    if (DecodeBOLInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 10: \
    if (DecodeRLCInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 11: \
    if (DecodeBInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 12: \
    if (DecodeRRPWInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 13: \
    if (DecodeRR2Instruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 14: \
    if (DecodeRCPWInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
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


FieldFromInstruction(fieldFromInstruction_2, uint16_t)
DecodeToMCInst(decodeToMCInst_2, fieldFromInstruction_2, uint16_t)
DecodeInstruction(decodeInstruction_2, fieldFromInstruction_2, decodeToMCInst_2, uint16_t)
FieldFromInstruction(fieldFromInstruction_4, uint32_t)
DecodeToMCInst(decodeToMCInst_4, fieldFromInstruction_4, uint32_t)
DecodeInstruction(decodeInstruction_4, fieldFromInstruction_4, decodeToMCInst_4, uint32_t)
