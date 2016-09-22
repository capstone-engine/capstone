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
/* 7 */       MCD_OPC_Decode, 51, 0, // Opcode: ANDsc
/* 10 */      MCD_OPC_FilterValue, 32, 3, 0, // Skip to: 17
/* 14 */      MCD_OPC_Decode, 126, 0, // Opcode: SUBAsc
/* 17 */      MCD_OPC_FilterValue, 38, 3, 0, // Skip to: 24
/* 21 */      MCD_OPC_Decode, 52, 1, // Opcode: ANDsrr
/* 24 */      MCD_OPC_FilterValue, 50, 3, 0, // Skip to: 31
/* 28 */      MCD_OPC_Decode, 115, 2, // Opcode: RSUBsr
/* 31 */      MCD_OPC_FilterValue, 64, 3, 0, // Skip to: 38
/* 35 */      MCD_OPC_Decode, 77, 1, // Opcode: MOVAAsrr
/* 38 */      MCD_OPC_FilterValue, 66, 3, 0, // Skip to: 45
/* 42 */      MCD_OPC_Decode, 35, 1, // Opcode: ADDsrr
/* 45 */      MCD_OPC_FilterValue, 70, 3, 0, // Skip to: 52
/* 49 */      MCD_OPC_Decode, 96, 2, // Opcode: NOTsr
/* 52 */      MCD_OPC_FilterValue, 110, 3, 0, // Skip to: 59
/* 56 */      MCD_OPC_Decode, 64, 3, // Opcode: JZsb
/* 59 */      MCD_OPC_FilterValue, 118, 3, 0, // Skip to: 66
/* 63 */      MCD_OPC_Decode, 65, 4, // Opcode: JZsbr
/* 66 */      MCD_OPC_FilterValue, 130, 1, 3, 0, // Skip to: 74
/* 71 */      MCD_OPC_Decode, 85, 5, // Opcode: MOVsrc
/* 74 */      MCD_OPC_FilterValue, 150, 1, 3, 0, // Skip to: 82
/* 79 */      MCD_OPC_Decode, 110, 0, // Opcode: ORsc
/* 82 */      MCD_OPC_FilterValue, 166, 1, 3, 0, // Skip to: 90
/* 87 */      MCD_OPC_Decode, 111, 1, // Opcode: ORsrr
/* 90 */      MCD_OPC_FilterValue, 194, 1, 3, 0, // Skip to: 98
/* 95 */      MCD_OPC_Decode, 34, 5, // Opcode: ADDsrc
/* 98 */      MCD_OPC_FilterValue, 198, 1, 4, 0, // Skip to: 107
/* 103 */     MCD_OPC_Decode, 136, 1, 1, // Opcode: XORsrr
/* 107 */     MCD_OPC_FilterValue, 226, 1, 3, 0, // Skip to: 115
/* 112 */     MCD_OPC_Decode, 88, 1, // Opcode: MULsrr
/* 115 */     MCD_OPC_FilterValue, 238, 1, 3, 0, // Skip to: 123
/* 120 */     MCD_OPC_Decode, 62, 3, // Opcode: JNZsb
/* 123 */     MCD_OPC_FilterValue, 246, 1, 3, 0, // Skip to: 131
/* 128 */     MCD_OPC_Decode, 63, 4, // Opcode: JNZsbr
/* 131 */     MCD_OPC_Fail,
  0
};

static uint8_t DecoderTable32[] = {
/* 0 */       MCD_OPC_ExtractField, 0, 8,  // Inst{7-0} ...
/* 3 */       MCD_OPC_FilterValue, 1, 40, 0, // Skip to: 47
/* 7 */       MCD_OPC_ExtractField, 18, 10,  // Inst{27-18} ...
/* 10 */      MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 17
/* 14 */      MCD_OPC_Decode, 76, 6, // Opcode: MOVAArr
/* 17 */      MCD_OPC_FilterValue, 4, 3, 0, // Skip to: 24
/* 21 */      MCD_OPC_Decode, 24, 6, // Opcode: ADDArr
/* 24 */      MCD_OPC_FilterValue, 8, 3, 0, // Skip to: 31
/* 28 */      MCD_OPC_Decode, 125, 6, // Opcode: SUBArr
/* 31 */      MCD_OPC_FilterValue, 176, 2, 3, 0, // Skip to: 39
/* 36 */      MCD_OPC_Decode, 79, 6, // Opcode: MOVDrr
/* 39 */      MCD_OPC_FilterValue, 140, 3, 179, 2, // Skip to: 735
/* 44 */      MCD_OPC_Decode, 78, 6, // Opcode: MOVArr
/* 47 */      MCD_OPC_FilterValue, 9, 45, 0, // Skip to: 96
/* 51 */      MCD_OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 54 */      MCD_OPC_FilterValue, 32, 3, 0, // Skip to: 61
/* 58 */      MCD_OPC_Decode, 68, 7, // Opcode: LDBbo
/* 61 */      MCD_OPC_FilterValue, 33, 3, 0, // Skip to: 68
/* 65 */      MCD_OPC_Decode, 67, 7, // Opcode: LDBUbo
/* 68 */      MCD_OPC_FilterValue, 34, 3, 0, // Skip to: 75
/* 72 */      MCD_OPC_Decode, 71, 7, // Opcode: LDHbo
/* 75 */      MCD_OPC_FilterValue, 35, 3, 0, // Skip to: 82
/* 79 */      MCD_OPC_Decode, 70, 7, // Opcode: LDHUbo
/* 82 */      MCD_OPC_FilterValue, 36, 3, 0, // Skip to: 89
/* 86 */      MCD_OPC_Decode, 72, 7, // Opcode: LDWbo
/* 89 */      MCD_OPC_FilterValue, 37, 130, 2, // Skip to: 735
/* 93 */      MCD_OPC_Decode, 69, 7, // Opcode: LDDbo
/* 96 */      MCD_OPC_FilterValue, 11, 212, 0, // Skip to: 312
/* 100 */     MCD_OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 103 */     MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 116
/* 107 */     MCD_OPC_CheckField, 18, 3, 0, 110, 2, // Skip to: 735
/* 113 */     MCD_OPC_Decode, 33, 6, // Opcode: ADDrr
/* 116 */     MCD_OPC_FilterValue, 2, 17, 0, // Skip to: 137
/* 120 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 123 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 130
/* 127 */     MCD_OPC_Decode, 29, 6, // Opcode: ADDXrr
/* 130 */     MCD_OPC_FilterValue, 4, 89, 2, // Skip to: 735
/* 134 */     MCD_OPC_Decode, 26, 6, // Opcode: ADDCrr
/* 137 */     MCD_OPC_FilterValue, 4, 3, 0, // Skip to: 144
/* 141 */     MCD_OPC_Decode, 28, 8, // Opcode: ADDXrc
/* 144 */     MCD_OPC_FilterValue, 6, 18, 0, // Skip to: 166
/* 148 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 151 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 159
/* 155 */     MCD_OPC_Decode, 128, 1, 6, // Opcode: SUBXrr
/* 159 */     MCD_OPC_FilterValue, 4, 60, 2, // Skip to: 735
/* 163 */     MCD_OPC_Decode, 127, 6, // Opcode: SUBCrr
/* 166 */     MCD_OPC_FilterValue, 8, 17, 0, // Skip to: 187
/* 170 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 173 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 180
/* 177 */     MCD_OPC_Decode, 57, 6, // Opcode: EQrr
/* 180 */     MCD_OPC_FilterValue, 4, 39, 2, // Skip to: 735
/* 184 */     MCD_OPC_Decode, 92, 6, // Opcode: NErr
/* 187 */     MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 200
/* 191 */     MCD_OPC_CheckField, 18, 3, 0, 26, 2, // Skip to: 735
/* 197 */     MCD_OPC_Decode, 75, 6, // Opcode: LTrr
/* 200 */     MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 213
/* 204 */     MCD_OPC_CheckField, 18, 3, 0, 13, 2, // Skip to: 735
/* 210 */     MCD_OPC_Decode, 60, 6, // Opcode: GErr
/* 213 */     MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 226
/* 217 */     MCD_OPC_CheckField, 18, 3, 0, 0, 2, // Skip to: 735
/* 223 */     MCD_OPC_Decode, 23, 6, // Opcode: ABS
/* 226 */     MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 239
/* 230 */     MCD_OPC_CheckField, 18, 3, 4, 243, 1, // Skip to: 735
/* 236 */     MCD_OPC_Decode, 84, 6, // Opcode: MOVrr
/* 239 */     MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 252
/* 243 */     MCD_OPC_CheckField, 18, 3, 0, 230, 1, // Skip to: 735
/* 249 */     MCD_OPC_Decode, 41, 6, // Opcode: AND_EQrr
/* 252 */     MCD_OPC_FilterValue, 17, 9, 0, // Skip to: 265
/* 256 */     MCD_OPC_CheckField, 18, 3, 4, 217, 1, // Skip to: 735
/* 262 */     MCD_OPC_Decode, 46, 6, // Opcode: AND_LT_Urr
/* 265 */     MCD_OPC_FilterValue, 18, 9, 0, // Skip to: 278
/* 269 */     MCD_OPC_CheckField, 18, 3, 4, 204, 1, // Skip to: 735
/* 275 */     MCD_OPC_Decode, 43, 6, // Opcode: AND_GE_Urr
/* 278 */     MCD_OPC_FilterValue, 20, 17, 0, // Skip to: 299
/* 282 */     MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 285 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 292
/* 289 */     MCD_OPC_Decode, 106, 6, // Opcode: OR_NErr
/* 292 */     MCD_OPC_FilterValue, 4, 183, 1, // Skip to: 735
/* 296 */     MCD_OPC_Decode, 104, 6, // Opcode: OR_LTrr
/* 299 */     MCD_OPC_FilterValue, 21, 176, 1, // Skip to: 735
/* 303 */     MCD_OPC_CheckField, 18, 3, 4, 170, 1, // Skip to: 735
/* 309 */     MCD_OPC_Decode, 101, 6, // Opcode: OR_GErr
/* 312 */     MCD_OPC_FilterValue, 15, 53, 0, // Skip to: 369
/* 316 */     MCD_OPC_ExtractField, 18, 10,  // Inst{27-18} ...
/* 319 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 326
/* 323 */     MCD_OPC_Decode, 119, 6, // Opcode: SHrr
/* 326 */     MCD_OPC_FilterValue, 4, 3, 0, // Skip to: 333
/* 330 */     MCD_OPC_Decode, 117, 6, // Opcode: SHArr
/* 333 */     MCD_OPC_FilterValue, 32, 3, 0, // Skip to: 340
/* 337 */     MCD_OPC_Decode, 50, 6, // Opcode: ANDrr
/* 340 */     MCD_OPC_FilterValue, 36, 3, 0, // Skip to: 347
/* 344 */     MCD_OPC_Decode, 90, 6, // Opcode: NANDrr
/* 347 */     MCD_OPC_FilterValue, 40, 3, 0, // Skip to: 354
/* 351 */     MCD_OPC_Decode, 109, 6, // Opcode: ORrr
/* 354 */     MCD_OPC_FilterValue, 44, 3, 0, // Skip to: 361
/* 358 */     MCD_OPC_Decode, 94, 6, // Opcode: NORrr
/* 361 */     MCD_OPC_FilterValue, 48, 114, 1, // Skip to: 735
/* 365 */     MCD_OPC_Decode, 135, 1, 6, // Opcode: XORrr
/* 369 */     MCD_OPC_FilterValue, 25, 3, 0, // Skip to: 376
/* 373 */     MCD_OPC_Decode, 73, 9, // Opcode: LDWbol
/* 376 */     MCD_OPC_FilterValue, 27, 3, 0, // Skip to: 383
/* 380 */     MCD_OPC_Decode, 27, 10, // Opcode: ADDIrlc
/* 383 */     MCD_OPC_FilterValue, 29, 3, 0, // Skip to: 390
/* 387 */     MCD_OPC_Decode, 66, 11, // Opcode: Jb
/* 390 */     MCD_OPC_FilterValue, 55, 9, 0, // Skip to: 403
/* 394 */     MCD_OPC_CheckField, 21, 2, 2, 79, 1, // Skip to: 735
/* 400 */     MCD_OPC_Decode, 58, 12, // Opcode: EXTRrrpw
/* 403 */     MCD_OPC_FilterValue, 59, 3, 0, // Skip to: 410
/* 407 */     MCD_OPC_Decode, 83, 10, // Opcode: MOVrlc
/* 410 */     MCD_OPC_FilterValue, 83, 9, 0, // Skip to: 423
/* 414 */     MCD_OPC_CheckField, 21, 7, 1, 59, 1, // Skip to: 735
/* 420 */     MCD_OPC_Decode, 86, 8, // Opcode: MULrc
/* 423 */     MCD_OPC_FilterValue, 109, 3, 0, // Skip to: 430
/* 427 */     MCD_OPC_Decode, 54, 11, // Opcode: CALLb
/* 430 */     MCD_OPC_FilterValue, 115, 9, 0, // Skip to: 443
/* 434 */     MCD_OPC_CheckField, 16, 12, 10, 39, 1, // Skip to: 735
/* 440 */     MCD_OPC_Decode, 87, 13, // Opcode: MULrr2
/* 443 */     MCD_OPC_FilterValue, 119, 9, 0, // Skip to: 456
/* 447 */     MCD_OPC_CheckField, 21, 2, 0, 26, 1, // Skip to: 735
/* 453 */     MCD_OPC_Decode, 55, 12, // Opcode: DEXTRrrpw
/* 456 */     MCD_OPC_FilterValue, 123, 3, 0, // Skip to: 463
/* 460 */     MCD_OPC_Decode, 80, 10, // Opcode: MOVHrlc
/* 463 */     MCD_OPC_FilterValue, 137, 1, 38, 0, // Skip to: 506
/* 468 */     MCD_OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 471 */     MCD_OPC_FilterValue, 32, 3, 0, // Skip to: 478
/* 475 */     MCD_OPC_Decode, 121, 7, // Opcode: STBbo
/* 478 */     MCD_OPC_FilterValue, 34, 3, 0, // Skip to: 485
/* 482 */     MCD_OPC_Decode, 123, 7, // Opcode: STHbo
/* 485 */     MCD_OPC_FilterValue, 36, 3, 0, // Skip to: 492
/* 489 */     MCD_OPC_Decode, 124, 7, // Opcode: STWbo
/* 492 */     MCD_OPC_FilterValue, 37, 3, 0, // Skip to: 499
/* 496 */     MCD_OPC_Decode, 122, 7, // Opcode: STDbo
/* 499 */     MCD_OPC_FilterValue, 38, 232, 0, // Skip to: 735
/* 503 */     MCD_OPC_Decode, 120, 7, // Opcode: STAbo
/* 506 */     MCD_OPC_FilterValue, 139, 1, 122, 0, // Skip to: 633
/* 511 */     MCD_OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 514 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 521
/* 518 */     MCD_OPC_Decode, 32, 8, // Opcode: ADDrc
/* 521 */     MCD_OPC_FilterValue, 5, 3, 0, // Skip to: 528
/* 525 */     MCD_OPC_Decode, 25, 8, // Opcode: ADDCrc
/* 528 */     MCD_OPC_FilterValue, 8, 3, 0, // Skip to: 535
/* 532 */     MCD_OPC_Decode, 114, 8, // Opcode: RSUBrc
/* 535 */     MCD_OPC_FilterValue, 16, 3, 0, // Skip to: 542
/* 539 */     MCD_OPC_Decode, 56, 8, // Opcode: EQrc
/* 542 */     MCD_OPC_FilterValue, 17, 3, 0, // Skip to: 549
/* 546 */     MCD_OPC_Decode, 91, 8, // Opcode: NErc
/* 549 */     MCD_OPC_FilterValue, 18, 3, 0, // Skip to: 556
/* 553 */     MCD_OPC_Decode, 74, 8, // Opcode: LTrc
/* 556 */     MCD_OPC_FilterValue, 20, 3, 0, // Skip to: 563
/* 560 */     MCD_OPC_Decode, 59, 8, // Opcode: GErc
/* 563 */     MCD_OPC_FilterValue, 32, 3, 0, // Skip to: 570
/* 567 */     MCD_OPC_Decode, 40, 8, // Opcode: AND_EQrc
/* 570 */     MCD_OPC_FilterValue, 34, 3, 0, // Skip to: 577
/* 574 */     MCD_OPC_Decode, 47, 8, // Opcode: AND_LTrc
/* 577 */     MCD_OPC_FilterValue, 35, 3, 0, // Skip to: 584
/* 581 */     MCD_OPC_Decode, 45, 8, // Opcode: AND_LTUrc
/* 584 */     MCD_OPC_FilterValue, 36, 3, 0, // Skip to: 591
/* 588 */     MCD_OPC_Decode, 44, 8, // Opcode: AND_GErc
/* 591 */     MCD_OPC_FilterValue, 37, 3, 0, // Skip to: 598
/* 595 */     MCD_OPC_Decode, 42, 8, // Opcode: AND_GEUrc
/* 598 */     MCD_OPC_FilterValue, 40, 3, 0, // Skip to: 605
/* 602 */     MCD_OPC_Decode, 105, 8, // Opcode: OR_NErc
/* 605 */     MCD_OPC_FilterValue, 41, 3, 0, // Skip to: 612
/* 609 */     MCD_OPC_Decode, 103, 8, // Opcode: OR_LTrc
/* 612 */     MCD_OPC_FilterValue, 42, 3, 0, // Skip to: 619
/* 616 */     MCD_OPC_Decode, 102, 8, // Opcode: OR_LTUrc
/* 619 */     MCD_OPC_FilterValue, 43, 3, 0, // Skip to: 626
/* 623 */     MCD_OPC_Decode, 100, 8, // Opcode: OR_GErc
/* 626 */     MCD_OPC_FilterValue, 44, 105, 0, // Skip to: 735
/* 630 */     MCD_OPC_Decode, 99, 8, // Opcode: OR_GEUrc
/* 633 */     MCD_OPC_FilterValue, 143, 1, 75, 0, // Skip to: 713
/* 638 */     MCD_OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 641 */     MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 648
/* 645 */     MCD_OPC_Decode, 118, 8, // Opcode: SHrc
/* 648 */     MCD_OPC_FilterValue, 1, 3, 0, // Skip to: 655
/* 652 */     MCD_OPC_Decode, 116, 8, // Opcode: SHArc
/* 655 */     MCD_OPC_FilterValue, 8, 3, 0, // Skip to: 662
/* 659 */     MCD_OPC_Decode, 48, 8, // Opcode: ANDrc
/* 662 */     MCD_OPC_FilterValue, 9, 3, 0, // Skip to: 669
/* 666 */     MCD_OPC_Decode, 89, 8, // Opcode: NANDrc
/* 669 */     MCD_OPC_FilterValue, 10, 3, 0, // Skip to: 676
/* 673 */     MCD_OPC_Decode, 107, 8, // Opcode: ORrc
/* 676 */     MCD_OPC_FilterValue, 11, 3, 0, // Skip to: 683
/* 680 */     MCD_OPC_Decode, 93, 8, // Opcode: NORrc
/* 683 */     MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 691
/* 687 */     MCD_OPC_Decode, 132, 1, 8, // Opcode: XORrc
/* 691 */     MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 699
/* 695 */     MCD_OPC_Decode, 131, 1, 8, // Opcode: XNORrc
/* 699 */     MCD_OPC_FilterValue, 14, 3, 0, // Skip to: 706
/* 703 */     MCD_OPC_Decode, 38, 8, // Opcode: ANDNrc
/* 706 */     MCD_OPC_FilterValue, 15, 25, 0, // Skip to: 735
/* 710 */     MCD_OPC_Decode, 97, 8, // Opcode: ORNrc
/* 713 */     MCD_OPC_FilterValue, 183, 1, 9, 0, // Skip to: 727
/* 718 */     MCD_OPC_CheckField, 21, 2, 1, 11, 0, // Skip to: 735
/* 724 */     MCD_OPC_Decode, 61, 14, // Opcode: IMASKrcpw
/* 727 */     MCD_OPC_FilterValue, 187, 1, 3, 0, // Skip to: 735
/* 732 */     MCD_OPC_Decode, 81, 10, // Opcode: MOVUrlc
/* 735 */     MCD_OPC_Fail,
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
