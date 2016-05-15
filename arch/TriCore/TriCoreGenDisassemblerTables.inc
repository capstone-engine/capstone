/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|*  * TriCore Disassembler                                                    *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#include "../../MCInst.h"
#include "../../LEB128.h"

// Helper function for extracting fields from encoded instructions.
template<typename InsnType>
static InsnType fieldFromInstruction(InsnType insn, unsigned startBit,
                                     unsigned numBits) {
    assert(startBit + numBits <= (sizeof(InsnType)*8) &&
           "Instruction field out of bounds!");
    InsnType fieldMask;
    if (numBits == sizeof(InsnType)*8)
      fieldMask = (InsnType)(-1LL);
    else
      fieldMask = (((InsnType)1 << numBits) - 1) << startBit;
    return (insn & fieldMask) >> startBit;
}

static const uint8_t DecoderTable16[] = {
/* 0 */       MCD::OPC_ExtractField, 0, 8,  // Inst{7-0} ...
/* 3 */       MCD::OPC_FilterValue, 22, 3, 0, // Skip to: 10
/* 7 */       MCD::OPC_Decode, 51, 0, // Opcode: ANDsc
/* 10 */      MCD::OPC_FilterValue, 32, 3, 0, // Skip to: 17
/* 14 */      MCD::OPC_Decode, 123, 0, // Opcode: SUBAsc
/* 17 */      MCD::OPC_FilterValue, 38, 3, 0, // Skip to: 24
/* 21 */      MCD::OPC_Decode, 52, 1, // Opcode: ANDsrr
/* 24 */      MCD::OPC_FilterValue, 50, 3, 0, // Skip to: 31
/* 28 */      MCD::OPC_Decode, 112, 2, // Opcode: RSUBsr
/* 31 */      MCD::OPC_FilterValue, 64, 3, 0, // Skip to: 38
/* 35 */      MCD::OPC_Decode, 74, 1, // Opcode: MOVAAsrr
/* 38 */      MCD::OPC_FilterValue, 66, 3, 0, // Skip to: 45
/* 42 */      MCD::OPC_Decode, 35, 1, // Opcode: ADDsrr
/* 45 */      MCD::OPC_FilterValue, 70, 3, 0, // Skip to: 52
/* 49 */      MCD::OPC_Decode, 93, 2, // Opcode: NOTsr
/* 52 */      MCD::OPC_FilterValue, 118, 3, 0, // Skip to: 59
/* 56 */      MCD::OPC_Decode, 63, 3, // Opcode: JZsbr
/* 59 */      MCD::OPC_FilterValue, 130, 1, 3, 0, // Skip to: 67
/* 64 */      MCD::OPC_Decode, 82, 4, // Opcode: MOVsrc
/* 67 */      MCD::OPC_FilterValue, 150, 1, 3, 0, // Skip to: 75
/* 72 */      MCD::OPC_Decode, 107, 0, // Opcode: ORsc
/* 75 */      MCD::OPC_FilterValue, 166, 1, 3, 0, // Skip to: 83
/* 80 */      MCD::OPC_Decode, 108, 1, // Opcode: ORsrr
/* 83 */      MCD::OPC_FilterValue, 194, 1, 3, 0, // Skip to: 91
/* 88 */      MCD::OPC_Decode, 34, 4, // Opcode: ADDsrc
/* 91 */      MCD::OPC_FilterValue, 198, 1, 4, 0, // Skip to: 100
/* 96 */      MCD::OPC_Decode, 133, 1, 1, // Opcode: XORsrr
/* 100 */     MCD::OPC_FilterValue, 226, 1, 3, 0, // Skip to: 108
/* 105 */     MCD::OPC_Decode, 85, 1, // Opcode: MULsrr
/* 108 */     MCD::OPC_FilterValue, 246, 1, 3, 0, // Skip to: 116
/* 113 */     MCD::OPC_Decode, 62, 3, // Opcode: JNZsbr
/* 116 */     MCD::OPC_Fail,
  0
};

static const uint8_t DecoderTable32[] = {
/* 0 */       MCD::OPC_ExtractField, 0, 8,  // Inst{7-0} ...
/* 3 */       MCD::OPC_FilterValue, 1, 40, 0, // Skip to: 47
/* 7 */       MCD::OPC_ExtractField, 18, 10,  // Inst{27-18} ...
/* 10 */      MCD::OPC_FilterValue, 0, 3, 0, // Skip to: 17
/* 14 */      MCD::OPC_Decode, 73, 5, // Opcode: MOVAArr
/* 17 */      MCD::OPC_FilterValue, 4, 3, 0, // Skip to: 24
/* 21 */      MCD::OPC_Decode, 24, 5, // Opcode: ADDArr
/* 24 */      MCD::OPC_FilterValue, 8, 3, 0, // Skip to: 31
/* 28 */      MCD::OPC_Decode, 122, 5, // Opcode: SUBArr
/* 31 */      MCD::OPC_FilterValue, 176, 2, 3, 0, // Skip to: 39
/* 36 */      MCD::OPC_Decode, 76, 5, // Opcode: MOVDrr
/* 39 */      MCD::OPC_FilterValue, 140, 3, 171, 2, // Skip to: 727
/* 44 */      MCD::OPC_Decode, 75, 5, // Opcode: MOVArr
/* 47 */      MCD::OPC_FilterValue, 9, 38, 0, // Skip to: 89
/* 51 */      MCD::OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 54 */      MCD::OPC_FilterValue, 32, 3, 0, // Skip to: 61
/* 58 */      MCD::OPC_Decode, 66, 6, // Opcode: LDBbo
/* 61 */      MCD::OPC_FilterValue, 33, 3, 0, // Skip to: 68
/* 65 */      MCD::OPC_Decode, 65, 6, // Opcode: LDBUbo
/* 68 */      MCD::OPC_FilterValue, 34, 3, 0, // Skip to: 75
/* 72 */      MCD::OPC_Decode, 69, 6, // Opcode: LDHbo
/* 75 */      MCD::OPC_FilterValue, 35, 3, 0, // Skip to: 82
/* 79 */      MCD::OPC_Decode, 68, 6, // Opcode: LDHUbo
/* 82 */      MCD::OPC_FilterValue, 37, 129, 2, // Skip to: 727
/* 86 */      MCD::OPC_Decode, 67, 6, // Opcode: LDDbo
/* 89 */      MCD::OPC_FilterValue, 11, 211, 0, // Skip to: 304
/* 93 */      MCD::OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 96 */      MCD::OPC_FilterValue, 0, 9, 0, // Skip to: 109
/* 100 */     MCD::OPC_CheckField, 18, 3, 0, 109, 2, // Skip to: 727
/* 106 */     MCD::OPC_Decode, 33, 5, // Opcode: ADDrr
/* 109 */     MCD::OPC_FilterValue, 2, 17, 0, // Skip to: 130
/* 113 */     MCD::OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 116 */     MCD::OPC_FilterValue, 0, 3, 0, // Skip to: 123
/* 120 */     MCD::OPC_Decode, 29, 5, // Opcode: ADDXrr
/* 123 */     MCD::OPC_FilterValue, 4, 88, 2, // Skip to: 727
/* 127 */     MCD::OPC_Decode, 26, 5, // Opcode: ADDCrr
/* 130 */     MCD::OPC_FilterValue, 4, 3, 0, // Skip to: 137
/* 134 */     MCD::OPC_Decode, 28, 7, // Opcode: ADDXrc
/* 137 */     MCD::OPC_FilterValue, 6, 17, 0, // Skip to: 158
/* 141 */     MCD::OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 144 */     MCD::OPC_FilterValue, 0, 3, 0, // Skip to: 151
/* 148 */     MCD::OPC_Decode, 125, 5, // Opcode: SUBXrr
/* 151 */     MCD::OPC_FilterValue, 4, 60, 2, // Skip to: 727
/* 155 */     MCD::OPC_Decode, 124, 5, // Opcode: SUBCrr
/* 158 */     MCD::OPC_FilterValue, 8, 17, 0, // Skip to: 179
/* 162 */     MCD::OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 165 */     MCD::OPC_FilterValue, 0, 3, 0, // Skip to: 172
/* 169 */     MCD::OPC_Decode, 57, 5, // Opcode: EQrr
/* 172 */     MCD::OPC_FilterValue, 4, 39, 2, // Skip to: 727
/* 176 */     MCD::OPC_Decode, 89, 5, // Opcode: NErr
/* 179 */     MCD::OPC_FilterValue, 9, 9, 0, // Skip to: 192
/* 183 */     MCD::OPC_CheckField, 18, 3, 0, 26, 2, // Skip to: 727
/* 189 */     MCD::OPC_Decode, 72, 5, // Opcode: LTrr
/* 192 */     MCD::OPC_FilterValue, 10, 9, 0, // Skip to: 205
/* 196 */     MCD::OPC_CheckField, 18, 3, 0, 13, 2, // Skip to: 727
/* 202 */     MCD::OPC_Decode, 60, 5, // Opcode: GErr
/* 205 */     MCD::OPC_FilterValue, 14, 9, 0, // Skip to: 218
/* 209 */     MCD::OPC_CheckField, 18, 3, 0, 0, 2, // Skip to: 727
/* 215 */     MCD::OPC_Decode, 23, 5, // Opcode: ABS
/* 218 */     MCD::OPC_FilterValue, 15, 9, 0, // Skip to: 231
/* 222 */     MCD::OPC_CheckField, 18, 3, 4, 243, 1, // Skip to: 727
/* 228 */     MCD::OPC_Decode, 81, 5, // Opcode: MOVrr
/* 231 */     MCD::OPC_FilterValue, 16, 9, 0, // Skip to: 244
/* 235 */     MCD::OPC_CheckField, 18, 3, 0, 230, 1, // Skip to: 727
/* 241 */     MCD::OPC_Decode, 41, 5, // Opcode: AND_EQrr
/* 244 */     MCD::OPC_FilterValue, 17, 9, 0, // Skip to: 257
/* 248 */     MCD::OPC_CheckField, 18, 3, 4, 217, 1, // Skip to: 727
/* 254 */     MCD::OPC_Decode, 46, 5, // Opcode: AND_LT_Urr
/* 257 */     MCD::OPC_FilterValue, 18, 9, 0, // Skip to: 270
/* 261 */     MCD::OPC_CheckField, 18, 3, 4, 204, 1, // Skip to: 727
/* 267 */     MCD::OPC_Decode, 43, 5, // Opcode: AND_GE_Urr
/* 270 */     MCD::OPC_FilterValue, 20, 17, 0, // Skip to: 291
/* 274 */     MCD::OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 277 */     MCD::OPC_FilterValue, 0, 3, 0, // Skip to: 284
/* 281 */     MCD::OPC_Decode, 103, 5, // Opcode: OR_NErr
/* 284 */     MCD::OPC_FilterValue, 4, 183, 1, // Skip to: 727
/* 288 */     MCD::OPC_Decode, 101, 5, // Opcode: OR_LTrr
/* 291 */     MCD::OPC_FilterValue, 21, 176, 1, // Skip to: 727
/* 295 */     MCD::OPC_CheckField, 18, 3, 4, 170, 1, // Skip to: 727
/* 301 */     MCD::OPC_Decode, 98, 5, // Opcode: OR_GErr
/* 304 */     MCD::OPC_FilterValue, 15, 53, 0, // Skip to: 361
/* 308 */     MCD::OPC_ExtractField, 18, 10,  // Inst{27-18} ...
/* 311 */     MCD::OPC_FilterValue, 0, 3, 0, // Skip to: 318
/* 315 */     MCD::OPC_Decode, 116, 5, // Opcode: SHrr
/* 318 */     MCD::OPC_FilterValue, 4, 3, 0, // Skip to: 325
/* 322 */     MCD::OPC_Decode, 114, 5, // Opcode: SHArr
/* 325 */     MCD::OPC_FilterValue, 32, 3, 0, // Skip to: 332
/* 329 */     MCD::OPC_Decode, 50, 5, // Opcode: ANDrr
/* 332 */     MCD::OPC_FilterValue, 36, 3, 0, // Skip to: 339
/* 336 */     MCD::OPC_Decode, 87, 5, // Opcode: NANDrr
/* 339 */     MCD::OPC_FilterValue, 40, 3, 0, // Skip to: 346
/* 343 */     MCD::OPC_Decode, 106, 5, // Opcode: ORrr
/* 346 */     MCD::OPC_FilterValue, 44, 3, 0, // Skip to: 353
/* 350 */     MCD::OPC_Decode, 91, 5, // Opcode: NORrr
/* 353 */     MCD::OPC_FilterValue, 48, 114, 1, // Skip to: 727
/* 357 */     MCD::OPC_Decode, 132, 1, 5, // Opcode: XORrr
/* 361 */     MCD::OPC_FilterValue, 25, 3, 0, // Skip to: 368
/* 365 */     MCD::OPC_Decode, 70, 8, // Opcode: LDWbo
/* 368 */     MCD::OPC_FilterValue, 27, 3, 0, // Skip to: 375
/* 372 */     MCD::OPC_Decode, 27, 9, // Opcode: ADDIrlc
/* 375 */     MCD::OPC_FilterValue, 29, 3, 0, // Skip to: 382
/* 379 */     MCD::OPC_Decode, 64, 10, // Opcode: Jb
/* 382 */     MCD::OPC_FilterValue, 55, 9, 0, // Skip to: 395
/* 386 */     MCD::OPC_CheckField, 21, 2, 2, 79, 1, // Skip to: 727
/* 392 */     MCD::OPC_Decode, 58, 11, // Opcode: EXTRrrpw
/* 395 */     MCD::OPC_FilterValue, 59, 3, 0, // Skip to: 402
/* 399 */     MCD::OPC_Decode, 80, 9, // Opcode: MOVrlc
/* 402 */     MCD::OPC_FilterValue, 83, 9, 0, // Skip to: 415
/* 406 */     MCD::OPC_CheckField, 21, 7, 1, 59, 1, // Skip to: 727
/* 412 */     MCD::OPC_Decode, 83, 7, // Opcode: MULrc
/* 415 */     MCD::OPC_FilterValue, 109, 3, 0, // Skip to: 422
/* 419 */     MCD::OPC_Decode, 54, 10, // Opcode: CALLb
/* 422 */     MCD::OPC_FilterValue, 115, 9, 0, // Skip to: 435
/* 426 */     MCD::OPC_CheckField, 16, 12, 10, 39, 1, // Skip to: 727
/* 432 */     MCD::OPC_Decode, 84, 12, // Opcode: MULrr2
/* 435 */     MCD::OPC_FilterValue, 119, 9, 0, // Skip to: 448
/* 439 */     MCD::OPC_CheckField, 21, 2, 0, 26, 1, // Skip to: 727
/* 445 */     MCD::OPC_Decode, 55, 11, // Opcode: DEXTRrrpw
/* 448 */     MCD::OPC_FilterValue, 123, 3, 0, // Skip to: 455
/* 452 */     MCD::OPC_Decode, 77, 9, // Opcode: MOVHrlc
/* 455 */     MCD::OPC_FilterValue, 137, 1, 38, 0, // Skip to: 498
/* 460 */     MCD::OPC_ExtractField, 22, 6,  // Inst{27-22} ...
/* 463 */     MCD::OPC_FilterValue, 32, 3, 0, // Skip to: 470
/* 467 */     MCD::OPC_Decode, 118, 6, // Opcode: STBbo
/* 470 */     MCD::OPC_FilterValue, 34, 3, 0, // Skip to: 477
/* 474 */     MCD::OPC_Decode, 120, 6, // Opcode: STHbo
/* 477 */     MCD::OPC_FilterValue, 36, 3, 0, // Skip to: 484
/* 481 */     MCD::OPC_Decode, 121, 6, // Opcode: STWbo
/* 484 */     MCD::OPC_FilterValue, 37, 3, 0, // Skip to: 491
/* 488 */     MCD::OPC_Decode, 119, 6, // Opcode: STDbo
/* 491 */     MCD::OPC_FilterValue, 38, 232, 0, // Skip to: 727
/* 495 */     MCD::OPC_Decode, 117, 6, // Opcode: STAbo
/* 498 */     MCD::OPC_FilterValue, 139, 1, 122, 0, // Skip to: 625
/* 503 */     MCD::OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 506 */     MCD::OPC_FilterValue, 0, 3, 0, // Skip to: 513
/* 510 */     MCD::OPC_Decode, 32, 7, // Opcode: ADDrc
/* 513 */     MCD::OPC_FilterValue, 5, 3, 0, // Skip to: 520
/* 517 */     MCD::OPC_Decode, 25, 7, // Opcode: ADDCrc
/* 520 */     MCD::OPC_FilterValue, 8, 3, 0, // Skip to: 527
/* 524 */     MCD::OPC_Decode, 111, 7, // Opcode: RSUBrc
/* 527 */     MCD::OPC_FilterValue, 16, 3, 0, // Skip to: 534
/* 531 */     MCD::OPC_Decode, 56, 7, // Opcode: EQrc
/* 534 */     MCD::OPC_FilterValue, 17, 3, 0, // Skip to: 541
/* 538 */     MCD::OPC_Decode, 88, 7, // Opcode: NErc
/* 541 */     MCD::OPC_FilterValue, 18, 3, 0, // Skip to: 548
/* 545 */     MCD::OPC_Decode, 71, 7, // Opcode: LTrc
/* 548 */     MCD::OPC_FilterValue, 20, 3, 0, // Skip to: 555
/* 552 */     MCD::OPC_Decode, 59, 7, // Opcode: GErc
/* 555 */     MCD::OPC_FilterValue, 32, 3, 0, // Skip to: 562
/* 559 */     MCD::OPC_Decode, 40, 7, // Opcode: AND_EQrc
/* 562 */     MCD::OPC_FilterValue, 34, 3, 0, // Skip to: 569
/* 566 */     MCD::OPC_Decode, 47, 7, // Opcode: AND_LTrc
/* 569 */     MCD::OPC_FilterValue, 35, 3, 0, // Skip to: 576
/* 573 */     MCD::OPC_Decode, 45, 7, // Opcode: AND_LTUrc
/* 576 */     MCD::OPC_FilterValue, 36, 3, 0, // Skip to: 583
/* 580 */     MCD::OPC_Decode, 44, 7, // Opcode: AND_GErc
/* 583 */     MCD::OPC_FilterValue, 37, 3, 0, // Skip to: 590
/* 587 */     MCD::OPC_Decode, 42, 7, // Opcode: AND_GEUrc
/* 590 */     MCD::OPC_FilterValue, 40, 3, 0, // Skip to: 597
/* 594 */     MCD::OPC_Decode, 102, 7, // Opcode: OR_NErc
/* 597 */     MCD::OPC_FilterValue, 41, 3, 0, // Skip to: 604
/* 601 */     MCD::OPC_Decode, 100, 7, // Opcode: OR_LTrc
/* 604 */     MCD::OPC_FilterValue, 42, 3, 0, // Skip to: 611
/* 608 */     MCD::OPC_Decode, 99, 7, // Opcode: OR_LTUrc
/* 611 */     MCD::OPC_FilterValue, 43, 3, 0, // Skip to: 618
/* 615 */     MCD::OPC_Decode, 97, 7, // Opcode: OR_GErc
/* 618 */     MCD::OPC_FilterValue, 44, 105, 0, // Skip to: 727
/* 622 */     MCD::OPC_Decode, 96, 7, // Opcode: OR_GEUrc
/* 625 */     MCD::OPC_FilterValue, 143, 1, 75, 0, // Skip to: 705
/* 630 */     MCD::OPC_ExtractField, 21, 7,  // Inst{27-21} ...
/* 633 */     MCD::OPC_FilterValue, 0, 3, 0, // Skip to: 640
/* 637 */     MCD::OPC_Decode, 115, 7, // Opcode: SHrc
/* 640 */     MCD::OPC_FilterValue, 1, 3, 0, // Skip to: 647
/* 644 */     MCD::OPC_Decode, 113, 7, // Opcode: SHArc
/* 647 */     MCD::OPC_FilterValue, 8, 3, 0, // Skip to: 654
/* 651 */     MCD::OPC_Decode, 48, 7, // Opcode: ANDrc
/* 654 */     MCD::OPC_FilterValue, 9, 3, 0, // Skip to: 661
/* 658 */     MCD::OPC_Decode, 86, 7, // Opcode: NANDrc
/* 661 */     MCD::OPC_FilterValue, 10, 3, 0, // Skip to: 668
/* 665 */     MCD::OPC_Decode, 104, 7, // Opcode: ORrc
/* 668 */     MCD::OPC_FilterValue, 11, 3, 0, // Skip to: 675
/* 672 */     MCD::OPC_Decode, 90, 7, // Opcode: NORrc
/* 675 */     MCD::OPC_FilterValue, 12, 4, 0, // Skip to: 683
/* 679 */     MCD::OPC_Decode, 129, 1, 7, // Opcode: XORrc
/* 683 */     MCD::OPC_FilterValue, 13, 4, 0, // Skip to: 691
/* 687 */     MCD::OPC_Decode, 128, 1, 7, // Opcode: XNORrc
/* 691 */     MCD::OPC_FilterValue, 14, 3, 0, // Skip to: 698
/* 695 */     MCD::OPC_Decode, 38, 7, // Opcode: ANDNrc
/* 698 */     MCD::OPC_FilterValue, 15, 25, 0, // Skip to: 727
/* 702 */     MCD::OPC_Decode, 94, 7, // Opcode: ORNrc
/* 705 */     MCD::OPC_FilterValue, 183, 1, 9, 0, // Skip to: 719
/* 710 */     MCD::OPC_CheckField, 21, 2, 1, 11, 0, // Skip to: 727
/* 716 */     MCD::OPC_Decode, 61, 13, // Opcode: IMASKrcpw
/* 719 */     MCD::OPC_FilterValue, 187, 1, 3, 0, // Skip to: 727
/* 724 */     MCD::OPC_Decode, 78, 9, // Opcode: MOVUrlc
/* 727 */     MCD::OPC_Fail,
  0
};

static bool checkDecoderPredicate(unsigned Idx, const FeatureBitset& Bits) {
   return true;  //llvm_unreachable("Invalid index!");
}

#define DecodeToMCInst(fname,fieldname, InsnType) \
static DecodeStatus fname(DecodeStatus S, unsigned Idx, InsnType insn, MCInst *MI, \
                uint64_t Address, void *Decoder) \
{ \  
  InsnType tmp; \
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
    if (DecodeSBRInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 4: \
    if (DecodeSRCInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 5: \
    if (DecodeRRInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 6: \
    if (DecodeBOInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 7: \
    if (DecodeRCInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 8: \
    if (DecodeBOLInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 9: \
    if (DecodeRCLInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 10: \
    if (DecodeBInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 11: \
    if (DecodeRRPWInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 12: \
    if (DecodeRR2Instruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 13: \
    if (DecodeRCPWInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
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
