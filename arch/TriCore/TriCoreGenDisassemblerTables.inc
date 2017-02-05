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
/* 14 */      MCD_OPC_Decode, 222, 1, 0, // Opcode: SUB_Asc
/* 18 */      MCD_OPC_FilterValue, 38, 3, 0, // Skip to: 25
/* 22 */      MCD_OPC_Decode, 56, 1, // Opcode: ANDsrr
/* 25 */      MCD_OPC_FilterValue, 50, 4, 0, // Skip to: 33
/* 29 */      MCD_OPC_Decode, 172, 1, 2, // Opcode: RSUBsr
/* 33 */      MCD_OPC_FilterValue, 64, 4, 0, // Skip to: 41
/* 37 */      MCD_OPC_Decode, 131, 1, 1, // Opcode: MOV_AAsrr
/* 41 */      MCD_OPC_FilterValue, 66, 3, 0, // Skip to: 48
/* 45 */      MCD_OPC_Decode, 35, 1, // Opcode: ADDsrr
/* 48 */      MCD_OPC_FilterValue, 70, 4, 0, // Skip to: 56
/* 52 */      MCD_OPC_Decode, 149, 1, 2, // Opcode: NOTsr
/* 56 */      MCD_OPC_FilterValue, 110, 3, 0, // Skip to: 63
/* 60 */      MCD_OPC_Decode, 68, 3, // Opcode: JZsb
/* 63 */      MCD_OPC_FilterValue, 118, 3, 0, // Skip to: 70
/* 67 */      MCD_OPC_Decode, 69, 4, // Opcode: JZsbr
/* 70 */      MCD_OPC_FilterValue, 130, 1, 4, 0, // Skip to: 79
/* 75 */      MCD_OPC_Decode, 138, 1, 5, // Opcode: MOVsrc
/* 79 */      MCD_OPC_FilterValue, 150, 1, 4, 0, // Skip to: 88
/* 84 */      MCD_OPC_Decode, 167, 1, 0, // Opcode: ORsc
/* 88 */      MCD_OPC_FilterValue, 166, 1, 4, 0, // Skip to: 97
/* 93 */      MCD_OPC_Decode, 168, 1, 1, // Opcode: ORsrr
/* 97 */      MCD_OPC_FilterValue, 194, 1, 3, 0, // Skip to: 105
/* 102 */     MCD_OPC_Decode, 34, 5, // Opcode: ADDsrc
/* 105 */     MCD_OPC_FilterValue, 198, 1, 4, 0, // Skip to: 114
/* 110 */     MCD_OPC_Decode, 242, 1, 1, // Opcode: XORsrr
/* 114 */     MCD_OPC_FilterValue, 226, 1, 4, 0, // Skip to: 123
/* 119 */     MCD_OPC_Decode, 141, 1, 1, // Opcode: MULsrr
/* 123 */     MCD_OPC_FilterValue, 238, 1, 3, 0, // Skip to: 131
/* 128 */     MCD_OPC_Decode, 66, 3, // Opcode: JNZsb
/* 131 */     MCD_OPC_FilterValue, 246, 1, 3, 0, // Skip to: 139
/* 136 */     MCD_OPC_Decode, 67, 4, // Opcode: JNZsbr
/* 139 */     MCD_OPC_Fail,
  0
};

static uint8_t DecoderTable32[] = {
/* 0 */       MCD_OPC_ExtractField, 0, 8,  // Inst{7-0} ...
/* 3 */       MCD_OPC_FilterValue, 1, 44, 0, // Skip to: 51
/* 7 */       MCD_OPC_ExtractField, 18, 10,  // Inst{27-18} ...
/* 10 */      MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 18
/* 14 */      MCD_OPC_Decode, 130, 1, 6, // Opcode: MOV_AArr
/* 18 */      MCD_OPC_FilterValue, 4, 3, 0, // Skip to: 25
/* 22 */      MCD_OPC_Decode, 29, 6, // Opcode: ADD_Arr
/* 25 */      MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 33
/* 29 */      MCD_OPC_Decode, 221, 1, 6, // Opcode: SUB_Arr
/* 33 */      MCD_OPC_FilterValue, 176, 2, 4, 0, // Skip to: 42
/* 38 */      MCD_OPC_Decode, 133, 1, 6, // Opcode: MOV_Drr
/* 42 */      MCD_OPC_FilterValue, 140, 3, 86, 6, // Skip to: 1669
/* 47 */      MCD_OPC_Decode, 132, 1, 6, // Opcode: MOV_Arr
/* 51 */      MCD_OPC_FilterValue, 5, 31, 0, // Skip to: 86
/* 55 */      MCD_OPC_ExtractField, 26, 2,  // Inst{27-26} ...
/* 58 */      MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 65
/* 62 */      MCD_OPC_Decode, 84, 7, // Opcode: LD_Babs
/* 65 */      MCD_OPC_FilterValue, 1, 3, 0, // Skip to: 72
/* 69 */      MCD_OPC_Decode, 78, 7, // Opcode: LD_BUabs
/* 72 */      MCD_OPC_FilterValue, 2, 3, 0, // Skip to: 79
/* 76 */      MCD_OPC_Decode, 108, 7, // Opcode: LD_Habs
/* 79 */      MCD_OPC_FilterValue, 3, 50, 6, // Skip to: 1669
/* 83 */      MCD_OPC_Decode, 102, 7, // Opcode: LD_HUabs
/* 86 */      MCD_OPC_FilterValue, 9, 192, 0, // Skip to: 282
/* 90 */      MCD_OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 93 */      MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 100
/* 97 */      MCD_OPC_Decode, 88, 8, // Opcode: LD_Bpostincbo
/* 100 */     MCD_OPC_FilterValue, 1, 3, 0, // Skip to: 107
/* 104 */     MCD_OPC_Decode, 82, 8, // Opcode: LD_BUpostincbo
/* 107 */     MCD_OPC_FilterValue, 2, 3, 0, // Skip to: 114
/* 111 */     MCD_OPC_Decode, 112, 8, // Opcode: LD_Hpostincbo
/* 114 */     MCD_OPC_FilterValue, 3, 3, 0, // Skip to: 121
/* 118 */     MCD_OPC_Decode, 106, 8, // Opcode: LD_HUpostincbo
/* 121 */     MCD_OPC_FilterValue, 4, 3, 0, // Skip to: 128
/* 125 */     MCD_OPC_Decode, 125, 8, // Opcode: LD_Wpostincbo
/* 128 */     MCD_OPC_FilterValue, 5, 3, 0, // Skip to: 135
/* 132 */     MCD_OPC_Decode, 100, 8, // Opcode: LD_Dpostincbo
/* 135 */     MCD_OPC_FilterValue, 6, 3, 0, // Skip to: 142
/* 139 */     MCD_OPC_Decode, 76, 8, // Opcode: LD_Apostincbo
/* 142 */     MCD_OPC_FilterValue, 7, 3, 0, // Skip to: 149
/* 146 */     MCD_OPC_Decode, 94, 8, // Opcode: LD_DApostincbo
/* 149 */     MCD_OPC_FilterValue, 8, 3, 0, // Skip to: 156
/* 153 */     MCD_OPC_Decode, 118, 8, // Opcode: LD_Qpostincbo
/* 156 */     MCD_OPC_FilterValue, 16, 3, 0, // Skip to: 163
/* 160 */     MCD_OPC_Decode, 89, 8, // Opcode: LD_Bpreincbo
/* 163 */     MCD_OPC_FilterValue, 17, 3, 0, // Skip to: 170
/* 167 */     MCD_OPC_Decode, 83, 8, // Opcode: LD_BUpreincbo
/* 170 */     MCD_OPC_FilterValue, 18, 3, 0, // Skip to: 177
/* 174 */     MCD_OPC_Decode, 113, 8, // Opcode: LD_Hpreincbo
/* 177 */     MCD_OPC_FilterValue, 19, 3, 0, // Skip to: 184
/* 181 */     MCD_OPC_Decode, 107, 8, // Opcode: LD_HUpreincbo
/* 184 */     MCD_OPC_FilterValue, 20, 3, 0, // Skip to: 191
/* 188 */     MCD_OPC_Decode, 126, 8, // Opcode: LD_Wpreincbo
/* 191 */     MCD_OPC_FilterValue, 21, 3, 0, // Skip to: 198
/* 195 */     MCD_OPC_Decode, 101, 8, // Opcode: LD_Dpreincbo
/* 198 */     MCD_OPC_FilterValue, 22, 3, 0, // Skip to: 205
/* 202 */     MCD_OPC_Decode, 77, 8, // Opcode: LD_Apreincbo
/* 205 */     MCD_OPC_FilterValue, 23, 3, 0, // Skip to: 212
/* 209 */     MCD_OPC_Decode, 95, 8, // Opcode: LD_DApreincbo
/* 212 */     MCD_OPC_FilterValue, 24, 3, 0, // Skip to: 219
/* 216 */     MCD_OPC_Decode, 119, 8, // Opcode: LD_Qpreincbo
/* 219 */     MCD_OPC_FilterValue, 32, 3, 0, // Skip to: 226
/* 223 */     MCD_OPC_Decode, 86, 8, // Opcode: LD_Bbo
/* 226 */     MCD_OPC_FilterValue, 33, 3, 0, // Skip to: 233
/* 230 */     MCD_OPC_Decode, 80, 8, // Opcode: LD_BUbo
/* 233 */     MCD_OPC_FilterValue, 34, 3, 0, // Skip to: 240
/* 237 */     MCD_OPC_Decode, 110, 8, // Opcode: LD_Hbo
/* 240 */     MCD_OPC_FilterValue, 35, 3, 0, // Skip to: 247
/* 244 */     MCD_OPC_Decode, 104, 8, // Opcode: LD_HUbo
/* 247 */     MCD_OPC_FilterValue, 36, 3, 0, // Skip to: 254
/* 251 */     MCD_OPC_Decode, 122, 8, // Opcode: LD_Wbo
/* 254 */     MCD_OPC_FilterValue, 37, 3, 0, // Skip to: 261
/* 258 */     MCD_OPC_Decode, 98, 8, // Opcode: LD_Dbo
/* 261 */     MCD_OPC_FilterValue, 38, 3, 0, // Skip to: 268
/* 265 */     MCD_OPC_Decode, 73, 8, // Opcode: LD_Abo
/* 268 */     MCD_OPC_FilterValue, 39, 3, 0, // Skip to: 275
/* 272 */     MCD_OPC_Decode, 92, 8, // Opcode: LD_DAbo
/* 275 */     MCD_OPC_FilterValue, 40, 110, 5, // Skip to: 1669
/* 279 */     MCD_OPC_Decode, 116, 8, // Opcode: LD_Qbo
/* 282 */     MCD_OPC_FilterValue, 11, 98, 1, // Skip to: 640
/* 286 */     MCD_OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 289 */     MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 302
/* 293 */     MCD_OPC_CheckField, 18, 3, 0, 90, 5, // Skip to: 1669
/* 299 */     MCD_OPC_Decode, 33, 6, // Opcode: ADDrr
/* 302 */     MCD_OPC_FilterValue, 2, 17, 0, // Skip to: 323
/* 306 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 309 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 316
/* 313 */     MCD_OPC_Decode, 28, 6, // Opcode: ADDXrr
/* 316 */     MCD_OPC_FilterValue, 4, 69, 5, // Skip to: 1669
/* 320 */     MCD_OPC_Decode, 25, 6, // Opcode: ADDCrr
/* 323 */     MCD_OPC_FilterValue, 4, 3, 0, // Skip to: 330
/* 327 */     MCD_OPC_Decode, 27, 9, // Opcode: ADDXrc
/* 330 */     MCD_OPC_FilterValue, 6, 19, 0, // Skip to: 353
/* 334 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 337 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 345
/* 341 */     MCD_OPC_Decode, 220, 1, 6, // Opcode: SUBXrr
/* 345 */     MCD_OPC_FilterValue, 4, 40, 5, // Skip to: 1669
/* 349 */     MCD_OPC_Decode, 219, 1, 6, // Opcode: SUBCrr
/* 353 */     MCD_OPC_FilterValue, 8, 18, 0, // Skip to: 375
/* 357 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 360 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 367
/* 364 */     MCD_OPC_Decode, 61, 6, // Opcode: EQrr
/* 367 */     MCD_OPC_FilterValue, 4, 18, 5, // Skip to: 1669
/* 371 */     MCD_OPC_Decode, 145, 1, 6, // Opcode: NErr
/* 375 */     MCD_OPC_FilterValue, 9, 10, 0, // Skip to: 389
/* 379 */     MCD_OPC_CheckField, 18, 3, 0, 4, 5, // Skip to: 1669
/* 385 */     MCD_OPC_Decode, 128, 1, 6, // Opcode: LTrr
/* 389 */     MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 402
/* 393 */     MCD_OPC_CheckField, 18, 3, 0, 246, 4, // Skip to: 1669
/* 399 */     MCD_OPC_Decode, 64, 6, // Opcode: GErr
/* 402 */     MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 415
/* 406 */     MCD_OPC_CheckField, 18, 3, 0, 233, 4, // Skip to: 1669
/* 412 */     MCD_OPC_Decode, 23, 6, // Opcode: ABS
/* 415 */     MCD_OPC_FilterValue, 15, 10, 0, // Skip to: 429
/* 419 */     MCD_OPC_CheckField, 18, 3, 4, 220, 4, // Skip to: 1669
/* 425 */     MCD_OPC_Decode, 137, 1, 6, // Opcode: MOVrr
/* 429 */     MCD_OPC_FilterValue, 16, 17, 0, // Skip to: 450
/* 433 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 436 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 443
/* 440 */     MCD_OPC_Decode, 41, 6, // Opcode: AND_EQrr
/* 443 */     MCD_OPC_FilterValue, 4, 198, 4, // Skip to: 1669
/* 447 */     MCD_OPC_Decode, 51, 6, // Opcode: AND_NErr
/* 450 */     MCD_OPC_FilterValue, 17, 17, 0, // Skip to: 471
/* 454 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 457 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 464
/* 461 */     MCD_OPC_Decode, 49, 6, // Opcode: AND_LTrr
/* 464 */     MCD_OPC_FilterValue, 4, 177, 4, // Skip to: 1669
/* 468 */     MCD_OPC_Decode, 47, 6, // Opcode: AND_LT_Urr
/* 471 */     MCD_OPC_FilterValue, 18, 17, 0, // Skip to: 492
/* 475 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 478 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 485
/* 482 */     MCD_OPC_Decode, 45, 6, // Opcode: AND_GErr
/* 485 */     MCD_OPC_FilterValue, 4, 156, 4, // Skip to: 1669
/* 489 */     MCD_OPC_Decode, 43, 6, // Opcode: AND_GE_Urr
/* 492 */     MCD_OPC_FilterValue, 19, 10, 0, // Skip to: 506
/* 496 */     MCD_OPC_CheckField, 18, 3, 4, 143, 4, // Skip to: 1669
/* 502 */     MCD_OPC_Decode, 153, 1, 6, // Opcode: OR_EQrr
/* 506 */     MCD_OPC_FilterValue, 20, 19, 0, // Skip to: 529
/* 510 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 513 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 521
/* 517 */     MCD_OPC_Decode, 163, 1, 6, // Opcode: OR_NErr
/* 521 */     MCD_OPC_FilterValue, 4, 120, 4, // Skip to: 1669
/* 525 */     MCD_OPC_Decode, 161, 1, 6, // Opcode: OR_LTrr
/* 529 */     MCD_OPC_FilterValue, 21, 19, 0, // Skip to: 552
/* 533 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 536 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 544
/* 540 */     MCD_OPC_Decode, 159, 1, 6, // Opcode: OR_LT_Urr
/* 544 */     MCD_OPC_FilterValue, 4, 97, 4, // Skip to: 1669
/* 548 */     MCD_OPC_Decode, 157, 1, 6, // Opcode: OR_GErr
/* 552 */     MCD_OPC_FilterValue, 22, 10, 0, // Skip to: 566
/* 556 */     MCD_OPC_CheckField, 18, 3, 0, 83, 4, // Skip to: 1669
/* 562 */     MCD_OPC_Decode, 155, 1, 6, // Opcode: OR_GE_Urr
/* 566 */     MCD_OPC_FilterValue, 23, 10, 0, // Skip to: 580
/* 570 */     MCD_OPC_CheckField, 18, 3, 4, 69, 4, // Skip to: 1669
/* 576 */     MCD_OPC_Decode, 227, 1, 6, // Opcode: XOR_EQrr
/* 580 */     MCD_OPC_FilterValue, 24, 19, 0, // Skip to: 603
/* 584 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 587 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 595
/* 591 */     MCD_OPC_Decode, 237, 1, 6, // Opcode: XOR_NErr
/* 595 */     MCD_OPC_FilterValue, 4, 46, 4, // Skip to: 1669
/* 599 */     MCD_OPC_Decode, 235, 1, 6, // Opcode: XOR_LTrr
/* 603 */     MCD_OPC_FilterValue, 25, 19, 0, // Skip to: 626
/* 607 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 610 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 618
/* 614 */     MCD_OPC_Decode, 233, 1, 6, // Opcode: XOR_LT_Urr
/* 618 */     MCD_OPC_FilterValue, 4, 23, 4, // Skip to: 1669
/* 622 */     MCD_OPC_Decode, 231, 1, 6, // Opcode: XOR_GErr
/* 626 */     MCD_OPC_FilterValue, 26, 15, 4, // Skip to: 1669
/* 630 */     MCD_OPC_CheckField, 18, 3, 0, 9, 4, // Skip to: 1669
/* 636 */     MCD_OPC_Decode, 229, 1, 6, // Opcode: XOR_GE_Urr
/* 640 */     MCD_OPC_FilterValue, 15, 58, 0, // Skip to: 702
/* 644 */     MCD_OPC_ExtractField, 18, 10,  // Inst{27-18} ...
/* 647 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 655
/* 651 */     MCD_OPC_Decode, 176, 1, 6, // Opcode: SHrr
/* 655 */     MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 663
/* 659 */     MCD_OPC_Decode, 174, 1, 6, // Opcode: SHArr
/* 663 */     MCD_OPC_FilterValue, 32, 3, 0, // Skip to: 670
/* 667 */     MCD_OPC_Decode, 54, 6, // Opcode: ANDrr
/* 670 */     MCD_OPC_FilterValue, 36, 4, 0, // Skip to: 678
/* 674 */     MCD_OPC_Decode, 143, 1, 6, // Opcode: NANDrr
/* 678 */     MCD_OPC_FilterValue, 40, 4, 0, // Skip to: 686
/* 682 */     MCD_OPC_Decode, 166, 1, 6, // Opcode: ORrr
/* 686 */     MCD_OPC_FilterValue, 44, 4, 0, // Skip to: 694
/* 690 */     MCD_OPC_Decode, 147, 1, 6, // Opcode: NORrr
/* 694 */     MCD_OPC_FilterValue, 48, 203, 3, // Skip to: 1669
/* 698 */     MCD_OPC_Decode, 241, 1, 6, // Opcode: XORrr
/* 702 */     MCD_OPC_FilterValue, 25, 3, 0, // Skip to: 709
/* 706 */     MCD_OPC_Decode, 123, 10, // Opcode: LD_Wbol
/* 709 */     MCD_OPC_FilterValue, 27, 3, 0, // Skip to: 716
/* 713 */     MCD_OPC_Decode, 26, 11, // Opcode: ADDIrlc
/* 716 */     MCD_OPC_FilterValue, 29, 3, 0, // Skip to: 723
/* 720 */     MCD_OPC_Decode, 70, 12, // Opcode: Jb
/* 723 */     MCD_OPC_FilterValue, 37, 19, 0, // Skip to: 746
/* 727 */     MCD_OPC_ExtractField, 26, 2,  // Inst{27-26} ...
/* 730 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 738
/* 734 */     MCD_OPC_Decode, 183, 1, 7, // Opcode: ST_Babs
/* 738 */     MCD_OPC_FilterValue, 2, 159, 3, // Skip to: 1669
/* 742 */     MCD_OPC_Decode, 201, 1, 7, // Opcode: ST_Habs
/* 746 */     MCD_OPC_FilterValue, 41, 129, 0, // Skip to: 879
/* 750 */     MCD_OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 753 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 760
/* 757 */     MCD_OPC_Decode, 85, 8, // Opcode: LD_Bbitrevbo
/* 760 */     MCD_OPC_FilterValue, 1, 3, 0, // Skip to: 767
/* 764 */     MCD_OPC_Decode, 79, 8, // Opcode: LD_BUbitrevbo
/* 767 */     MCD_OPC_FilterValue, 2, 3, 0, // Skip to: 774
/* 771 */     MCD_OPC_Decode, 109, 8, // Opcode: LD_Hbitrevbo
/* 774 */     MCD_OPC_FilterValue, 3, 3, 0, // Skip to: 781
/* 778 */     MCD_OPC_Decode, 103, 8, // Opcode: LD_HUbitrevbo
/* 781 */     MCD_OPC_FilterValue, 4, 3, 0, // Skip to: 788
/* 785 */     MCD_OPC_Decode, 121, 8, // Opcode: LD_Wbitrevbo
/* 788 */     MCD_OPC_FilterValue, 5, 3, 0, // Skip to: 795
/* 792 */     MCD_OPC_Decode, 97, 8, // Opcode: LD_Dbitrevbo
/* 795 */     MCD_OPC_FilterValue, 6, 3, 0, // Skip to: 802
/* 799 */     MCD_OPC_Decode, 72, 8, // Opcode: LD_Abitrevbo
/* 802 */     MCD_OPC_FilterValue, 7, 3, 0, // Skip to: 809
/* 806 */     MCD_OPC_Decode, 91, 8, // Opcode: LD_DAbitrevbo
/* 809 */     MCD_OPC_FilterValue, 8, 3, 0, // Skip to: 816
/* 813 */     MCD_OPC_Decode, 115, 8, // Opcode: LD_Qbitrevbo
/* 816 */     MCD_OPC_FilterValue, 16, 3, 0, // Skip to: 823
/* 820 */     MCD_OPC_Decode, 87, 8, // Opcode: LD_Bcircbo
/* 823 */     MCD_OPC_FilterValue, 17, 3, 0, // Skip to: 830
/* 827 */     MCD_OPC_Decode, 81, 8, // Opcode: LD_BUcircbo
/* 830 */     MCD_OPC_FilterValue, 18, 3, 0, // Skip to: 837
/* 834 */     MCD_OPC_Decode, 111, 8, // Opcode: LD_Hcircbo
/* 837 */     MCD_OPC_FilterValue, 19, 3, 0, // Skip to: 844
/* 841 */     MCD_OPC_Decode, 105, 8, // Opcode: LD_HUcircbo
/* 844 */     MCD_OPC_FilterValue, 20, 3, 0, // Skip to: 851
/* 848 */     MCD_OPC_Decode, 124, 8, // Opcode: LD_Wcircbo
/* 851 */     MCD_OPC_FilterValue, 21, 3, 0, // Skip to: 858
/* 855 */     MCD_OPC_Decode, 99, 8, // Opcode: LD_Dcircbo
/* 858 */     MCD_OPC_FilterValue, 22, 3, 0, // Skip to: 865
/* 862 */     MCD_OPC_Decode, 75, 8, // Opcode: LD_Acircbo
/* 865 */     MCD_OPC_FilterValue, 23, 3, 0, // Skip to: 872
/* 869 */     MCD_OPC_Decode, 93, 8, // Opcode: LD_DAcircbo
/* 872 */     MCD_OPC_FilterValue, 24, 25, 3, // Skip to: 1669
/* 876 */     MCD_OPC_Decode, 117, 8, // Opcode: LD_Qcircbo
/* 879 */     MCD_OPC_FilterValue, 55, 9, 0, // Skip to: 892
/* 883 */     MCD_OPC_CheckField, 21, 2, 2, 12, 3, // Skip to: 1669
/* 889 */     MCD_OPC_Decode, 62, 13, // Opcode: EXTRrrpw
/* 892 */     MCD_OPC_FilterValue, 59, 4, 0, // Skip to: 900
/* 896 */     MCD_OPC_Decode, 136, 1, 11, // Opcode: MOVrlc
/* 900 */     MCD_OPC_FilterValue, 69, 9, 0, // Skip to: 913
/* 904 */     MCD_OPC_CheckField, 26, 2, 0, 247, 2, // Skip to: 1669
/* 910 */     MCD_OPC_Decode, 114, 7, // Opcode: LD_Qabs
/* 913 */     MCD_OPC_FilterValue, 83, 10, 0, // Skip to: 927
/* 917 */     MCD_OPC_CheckField, 21, 7, 1, 234, 2, // Skip to: 1669
/* 923 */     MCD_OPC_Decode, 139, 1, 9, // Opcode: MULrc
/* 927 */     MCD_OPC_FilterValue, 101, 10, 0, // Skip to: 941
/* 931 */     MCD_OPC_CheckField, 26, 2, 0, 220, 2, // Skip to: 1669
/* 937 */     MCD_OPC_Decode, 207, 1, 7, // Opcode: ST_Qabs
/* 941 */     MCD_OPC_FilterValue, 109, 3, 0, // Skip to: 948
/* 945 */     MCD_OPC_Decode, 58, 12, // Opcode: CALLb
/* 948 */     MCD_OPC_FilterValue, 115, 10, 0, // Skip to: 962
/* 952 */     MCD_OPC_CheckField, 16, 12, 10, 199, 2, // Skip to: 1669
/* 958 */     MCD_OPC_Decode, 140, 1, 14, // Opcode: MULrr2
/* 962 */     MCD_OPC_FilterValue, 119, 9, 0, // Skip to: 975
/* 966 */     MCD_OPC_CheckField, 21, 2, 0, 185, 2, // Skip to: 1669
/* 972 */     MCD_OPC_Decode, 59, 13, // Opcode: DEXTRrrpw
/* 975 */     MCD_OPC_FilterValue, 123, 4, 0, // Skip to: 983
/* 979 */     MCD_OPC_Decode, 129, 1, 11, // Opcode: MOVHrlc
/* 983 */     MCD_OPC_FilterValue, 133, 1, 31, 0, // Skip to: 1019
/* 988 */     MCD_OPC_ExtractField, 26, 2,  // Inst{27-26} ...
/* 991 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 998
/* 995 */     MCD_OPC_Decode, 120, 7, // Opcode: LD_Wabs
/* 998 */     MCD_OPC_FilterValue, 1, 3, 0, // Skip to: 1005
/* 1002 */    MCD_OPC_Decode, 96, 7, // Opcode: LD_Dabs
/* 1005 */    MCD_OPC_FilterValue, 2, 3, 0, // Skip to: 1012
/* 1009 */    MCD_OPC_Decode, 71, 7, // Opcode: LD_Aabs
/* 1012 */    MCD_OPC_FilterValue, 3, 141, 2, // Skip to: 1669
/* 1016 */    MCD_OPC_Decode, 90, 7, // Opcode: LD_DAabs
/* 1019 */    MCD_OPC_FilterValue, 137, 1, 171, 0, // Skip to: 1195
/* 1024 */    MCD_OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 1027 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 1035
/* 1031 */    MCD_OPC_Decode, 187, 1, 8, // Opcode: ST_Bpostincbo
/* 1035 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 1043
/* 1039 */    MCD_OPC_Decode, 205, 1, 8, // Opcode: ST_Hpostincbo
/* 1043 */    MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 1051
/* 1047 */    MCD_OPC_Decode, 217, 1, 8, // Opcode: ST_Wpostincbo
/* 1051 */    MCD_OPC_FilterValue, 5, 4, 0, // Skip to: 1059
/* 1055 */    MCD_OPC_Decode, 199, 1, 8, // Opcode: ST_Dpostincbo
/* 1059 */    MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 1067
/* 1063 */    MCD_OPC_Decode, 181, 1, 8, // Opcode: ST_Apostincbo
/* 1067 */    MCD_OPC_FilterValue, 7, 4, 0, // Skip to: 1075
/* 1071 */    MCD_OPC_Decode, 193, 1, 8, // Opcode: ST_DApostincbo
/* 1075 */    MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 1083
/* 1079 */    MCD_OPC_Decode, 211, 1, 8, // Opcode: ST_Qpostincbo
/* 1083 */    MCD_OPC_FilterValue, 16, 4, 0, // Skip to: 1091
/* 1087 */    MCD_OPC_Decode, 188, 1, 8, // Opcode: ST_Bpreincbo
/* 1091 */    MCD_OPC_FilterValue, 18, 4, 0, // Skip to: 1099
/* 1095 */    MCD_OPC_Decode, 206, 1, 8, // Opcode: ST_Hpreincbo
/* 1099 */    MCD_OPC_FilterValue, 20, 4, 0, // Skip to: 1107
/* 1103 */    MCD_OPC_Decode, 218, 1, 8, // Opcode: ST_Wpreincbo
/* 1107 */    MCD_OPC_FilterValue, 21, 4, 0, // Skip to: 1115
/* 1111 */    MCD_OPC_Decode, 200, 1, 8, // Opcode: ST_Dpreincbo
/* 1115 */    MCD_OPC_FilterValue, 22, 4, 0, // Skip to: 1123
/* 1119 */    MCD_OPC_Decode, 182, 1, 8, // Opcode: ST_Apreincbo
/* 1123 */    MCD_OPC_FilterValue, 23, 4, 0, // Skip to: 1131
/* 1127 */    MCD_OPC_Decode, 194, 1, 8, // Opcode: ST_DApreincbo
/* 1131 */    MCD_OPC_FilterValue, 24, 4, 0, // Skip to: 1139
/* 1135 */    MCD_OPC_Decode, 212, 1, 8, // Opcode: ST_Qpreincbo
/* 1139 */    MCD_OPC_FilterValue, 32, 4, 0, // Skip to: 1147
/* 1143 */    MCD_OPC_Decode, 185, 1, 8, // Opcode: ST_Bbo
/* 1147 */    MCD_OPC_FilterValue, 34, 4, 0, // Skip to: 1155
/* 1151 */    MCD_OPC_Decode, 203, 1, 8, // Opcode: ST_Hbo
/* 1155 */    MCD_OPC_FilterValue, 36, 4, 0, // Skip to: 1163
/* 1159 */    MCD_OPC_Decode, 215, 1, 8, // Opcode: ST_Wbo
/* 1163 */    MCD_OPC_FilterValue, 37, 4, 0, // Skip to: 1171
/* 1167 */    MCD_OPC_Decode, 197, 1, 8, // Opcode: ST_Dbo
/* 1171 */    MCD_OPC_FilterValue, 38, 4, 0, // Skip to: 1179
/* 1175 */    MCD_OPC_Decode, 179, 1, 8, // Opcode: ST_Abo
/* 1179 */    MCD_OPC_FilterValue, 39, 4, 0, // Skip to: 1187
/* 1183 */    MCD_OPC_Decode, 191, 1, 8, // Opcode: ST_DAbo
/* 1187 */    MCD_OPC_FilterValue, 40, 222, 1, // Skip to: 1669
/* 1191 */    MCD_OPC_Decode, 209, 1, 8, // Opcode: ST_Qbo
/* 1195 */    MCD_OPC_FilterValue, 139, 1, 192, 0, // Skip to: 1392
/* 1200 */    MCD_OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 1203 */    MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 1210
/* 1207 */    MCD_OPC_Decode, 32, 9, // Opcode: ADDrc
/* 1210 */    MCD_OPC_FilterValue, 5, 3, 0, // Skip to: 1217
/* 1214 */    MCD_OPC_Decode, 24, 9, // Opcode: ADDCrc
/* 1217 */    MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 1225
/* 1221 */    MCD_OPC_Decode, 171, 1, 9, // Opcode: RSUBrc
/* 1225 */    MCD_OPC_FilterValue, 16, 3, 0, // Skip to: 1232
/* 1229 */    MCD_OPC_Decode, 60, 9, // Opcode: EQrc
/* 1232 */    MCD_OPC_FilterValue, 17, 4, 0, // Skip to: 1240
/* 1236 */    MCD_OPC_Decode, 144, 1, 9, // Opcode: NErc
/* 1240 */    MCD_OPC_FilterValue, 18, 3, 0, // Skip to: 1247
/* 1244 */    MCD_OPC_Decode, 127, 9, // Opcode: LTrc
/* 1247 */    MCD_OPC_FilterValue, 20, 3, 0, // Skip to: 1254
/* 1251 */    MCD_OPC_Decode, 63, 9, // Opcode: GErc
/* 1254 */    MCD_OPC_FilterValue, 32, 3, 0, // Skip to: 1261
/* 1258 */    MCD_OPC_Decode, 40, 9, // Opcode: AND_EQrc
/* 1261 */    MCD_OPC_FilterValue, 33, 3, 0, // Skip to: 1268
/* 1265 */    MCD_OPC_Decode, 50, 9, // Opcode: AND_NErc
/* 1268 */    MCD_OPC_FilterValue, 34, 3, 0, // Skip to: 1275
/* 1272 */    MCD_OPC_Decode, 48, 9, // Opcode: AND_LTrc
/* 1275 */    MCD_OPC_FilterValue, 35, 3, 0, // Skip to: 1282
/* 1279 */    MCD_OPC_Decode, 46, 9, // Opcode: AND_LT_Urc
/* 1282 */    MCD_OPC_FilterValue, 36, 3, 0, // Skip to: 1289
/* 1286 */    MCD_OPC_Decode, 44, 9, // Opcode: AND_GErc
/* 1289 */    MCD_OPC_FilterValue, 37, 3, 0, // Skip to: 1296
/* 1293 */    MCD_OPC_Decode, 42, 9, // Opcode: AND_GE_Urc
/* 1296 */    MCD_OPC_FilterValue, 39, 4, 0, // Skip to: 1304
/* 1300 */    MCD_OPC_Decode, 152, 1, 9, // Opcode: OR_EQrc
/* 1304 */    MCD_OPC_FilterValue, 40, 4, 0, // Skip to: 1312
/* 1308 */    MCD_OPC_Decode, 162, 1, 9, // Opcode: OR_NErc
/* 1312 */    MCD_OPC_FilterValue, 41, 4, 0, // Skip to: 1320
/* 1316 */    MCD_OPC_Decode, 160, 1, 9, // Opcode: OR_LTrc
/* 1320 */    MCD_OPC_FilterValue, 42, 4, 0, // Skip to: 1328
/* 1324 */    MCD_OPC_Decode, 158, 1, 9, // Opcode: OR_LT_Urc
/* 1328 */    MCD_OPC_FilterValue, 43, 4, 0, // Skip to: 1336
/* 1332 */    MCD_OPC_Decode, 156, 1, 9, // Opcode: OR_GErc
/* 1336 */    MCD_OPC_FilterValue, 44, 4, 0, // Skip to: 1344
/* 1340 */    MCD_OPC_Decode, 154, 1, 9, // Opcode: OR_GE_Urc
/* 1344 */    MCD_OPC_FilterValue, 47, 4, 0, // Skip to: 1352
/* 1348 */    MCD_OPC_Decode, 226, 1, 9, // Opcode: XOR_EQrc
/* 1352 */    MCD_OPC_FilterValue, 48, 4, 0, // Skip to: 1360
/* 1356 */    MCD_OPC_Decode, 236, 1, 9, // Opcode: XOR_NErc
/* 1360 */    MCD_OPC_FilterValue, 49, 4, 0, // Skip to: 1368
/* 1364 */    MCD_OPC_Decode, 234, 1, 9, // Opcode: XOR_LTrc
/* 1368 */    MCD_OPC_FilterValue, 50, 4, 0, // Skip to: 1376
/* 1372 */    MCD_OPC_Decode, 232, 1, 9, // Opcode: XOR_LT_Urc
/* 1376 */    MCD_OPC_FilterValue, 51, 4, 0, // Skip to: 1384
/* 1380 */    MCD_OPC_Decode, 230, 1, 9, // Opcode: XOR_GErc
/* 1384 */    MCD_OPC_FilterValue, 52, 25, 1, // Skip to: 1669
/* 1388 */    MCD_OPC_Decode, 228, 1, 9, // Opcode: XOR_GE_Urc
/* 1392 */    MCD_OPC_FilterValue, 143, 1, 81, 0, // Skip to: 1478
/* 1397 */    MCD_OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 1400 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 1408
/* 1404 */    MCD_OPC_Decode, 175, 1, 9, // Opcode: SHrc
/* 1408 */    MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 1416
/* 1412 */    MCD_OPC_Decode, 173, 1, 9, // Opcode: SHArc
/* 1416 */    MCD_OPC_FilterValue, 8, 3, 0, // Skip to: 1423
/* 1420 */    MCD_OPC_Decode, 52, 9, // Opcode: ANDrc
/* 1423 */    MCD_OPC_FilterValue, 9, 4, 0, // Skip to: 1431
/* 1427 */    MCD_OPC_Decode, 142, 1, 9, // Opcode: NANDrc
/* 1431 */    MCD_OPC_FilterValue, 10, 4, 0, // Skip to: 1439
/* 1435 */    MCD_OPC_Decode, 164, 1, 9, // Opcode: ORrc
/* 1439 */    MCD_OPC_FilterValue, 11, 4, 0, // Skip to: 1447
/* 1443 */    MCD_OPC_Decode, 146, 1, 9, // Opcode: NORrc
/* 1447 */    MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 1455
/* 1451 */    MCD_OPC_Decode, 238, 1, 9, // Opcode: XORrc
/* 1455 */    MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 1463
/* 1459 */    MCD_OPC_Decode, 225, 1, 9, // Opcode: XNORrc
/* 1463 */    MCD_OPC_FilterValue, 14, 3, 0, // Skip to: 1470
/* 1467 */    MCD_OPC_Decode, 38, 9, // Opcode: ANDNrc
/* 1470 */    MCD_OPC_FilterValue, 15, 195, 0, // Skip to: 1669
/* 1474 */    MCD_OPC_Decode, 150, 1, 9, // Opcode: ORNrc
/* 1478 */    MCD_OPC_FilterValue, 153, 1, 3, 0, // Skip to: 1486
/* 1483 */    MCD_OPC_Decode, 74, 10, // Opcode: LD_Abol
/* 1486 */    MCD_OPC_FilterValue, 165, 1, 35, 0, // Skip to: 1526
/* 1491 */    MCD_OPC_ExtractField, 26, 2,  // Inst{27-26} ...
/* 1494 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 1502
/* 1498 */    MCD_OPC_Decode, 213, 1, 7, // Opcode: ST_Wabs
/* 1502 */    MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 1510
/* 1506 */    MCD_OPC_Decode, 195, 1, 7, // Opcode: ST_Dabs
/* 1510 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 1518
/* 1514 */    MCD_OPC_Decode, 177, 1, 7, // Opcode: ST_Aabs
/* 1518 */    MCD_OPC_FilterValue, 3, 147, 0, // Skip to: 1669
/* 1522 */    MCD_OPC_Decode, 189, 1, 7, // Opcode: ST_DAabs
/* 1526 */    MCD_OPC_FilterValue, 169, 1, 115, 0, // Skip to: 1646
/* 1531 */    MCD_OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 1534 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 1542
/* 1538 */    MCD_OPC_Decode, 184, 1, 8, // Opcode: ST_Bbitrevbo
/* 1542 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 1550
/* 1546 */    MCD_OPC_Decode, 202, 1, 8, // Opcode: ST_Hbitrevbo
/* 1550 */    MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 1558
/* 1554 */    MCD_OPC_Decode, 214, 1, 8, // Opcode: ST_Wbitrevbo
/* 1558 */    MCD_OPC_FilterValue, 5, 4, 0, // Skip to: 1566
/* 1562 */    MCD_OPC_Decode, 196, 1, 8, // Opcode: ST_Dbitrevbo
/* 1566 */    MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 1574
/* 1570 */    MCD_OPC_Decode, 178, 1, 8, // Opcode: ST_Abitrevbo
/* 1574 */    MCD_OPC_FilterValue, 7, 4, 0, // Skip to: 1582
/* 1578 */    MCD_OPC_Decode, 190, 1, 8, // Opcode: ST_DAbitrevbo
/* 1582 */    MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 1590
/* 1586 */    MCD_OPC_Decode, 208, 1, 8, // Opcode: ST_Qbitrevbo
/* 1590 */    MCD_OPC_FilterValue, 16, 4, 0, // Skip to: 1598
/* 1594 */    MCD_OPC_Decode, 186, 1, 8, // Opcode: ST_Bcircbo
/* 1598 */    MCD_OPC_FilterValue, 18, 4, 0, // Skip to: 1606
/* 1602 */    MCD_OPC_Decode, 204, 1, 8, // Opcode: ST_Hcircbo
/* 1606 */    MCD_OPC_FilterValue, 20, 4, 0, // Skip to: 1614
/* 1610 */    MCD_OPC_Decode, 216, 1, 8, // Opcode: ST_Wcircbo
/* 1614 */    MCD_OPC_FilterValue, 21, 4, 0, // Skip to: 1622
/* 1618 */    MCD_OPC_Decode, 198, 1, 8, // Opcode: ST_Dcircbo
/* 1622 */    MCD_OPC_FilterValue, 22, 4, 0, // Skip to: 1630
/* 1626 */    MCD_OPC_Decode, 180, 1, 8, // Opcode: ST_Acircbo
/* 1630 */    MCD_OPC_FilterValue, 23, 4, 0, // Skip to: 1638
/* 1634 */    MCD_OPC_Decode, 192, 1, 8, // Opcode: ST_DAcircbo
/* 1638 */    MCD_OPC_FilterValue, 24, 27, 0, // Skip to: 1669
/* 1642 */    MCD_OPC_Decode, 210, 1, 8, // Opcode: ST_Qcircbo
/* 1646 */    MCD_OPC_FilterValue, 183, 1, 9, 0, // Skip to: 1660
/* 1651 */    MCD_OPC_CheckField, 21, 2, 1, 12, 0, // Skip to: 1669
/* 1657 */    MCD_OPC_Decode, 65, 15, // Opcode: IMASKrcpw
/* 1660 */    MCD_OPC_FilterValue, 187, 1, 4, 0, // Skip to: 1669
/* 1665 */    MCD_OPC_Decode, 134, 1, 11, // Opcode: MOV_Urlc
/* 1669 */    MCD_OPC_Fail,
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
    if (DecodeABSInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 8: \
    if (DecodeBOInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 9: \
    if (DecodeRCInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 10: \
    if (DecodeBOLInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 11: \
    if (DecodeRLCInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 12: \
    if (DecodeBInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 13: \
    if (DecodeRRPWInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 14: \
    if (DecodeRR2Instruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 15: \
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
